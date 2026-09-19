// S2-006 explicit state-changing command API (spec §5, §11).
// Every command passes the same gates, in this order:
//   1. capability check (role in workspace / authenticated grant) — BEFORE
//      any record lookup or payload read;
//   2. exact-args validation (contract schemas, canonicalArgsDigest,
//      cross-references);
//   3. idempotency lookup keyed by hash(actor + operation +
//      canonicalArgsDigest) over canonical-json-v1;
//   4. ONE atomic transaction writing the immutable record + audit + outbox;
//   5. unknown commit outcomes escalate to ReconciliationRequired — never a
//      blind retry.
// Pure computation (verify*) lives in api.mjs; temporary outputs of a
// calibration harness only become canonical once these commands accept them.
import {
  computeCanonicalArgsDigest,
  verifierValidators,
} from './api.mjs';
import { canonicalDigest } from './canonical-json.mjs';
import {
  AclDenied,
  ContractVersionUnknown,
  NeedsInput,
  ReconciliationRequired,
  StoreOutcomeUnknownError,
  VerifierError,
  VerifierPolicyBlock,
} from './errors.mjs';
import {
  BudgetExceeded,
  deriveIdempotencyKey,
  recordIdOf,
} from './store.mjs';
import {
  verifyDetailed as verifySignatureDetailed,
} from './signature.mjs';

export { BudgetExceeded, deriveIdempotencyKey };

// Minimal authority registry over the S2-006 role set (spec §3):
// candidate, label_custodian, annotator, adjudicator, evaluation_harness,
// reviewer. Server-enforced; a principal needs the role AND workspace.
//
// The registry is ALSO the trust anchor for provider grants (review P1-2):
// `issuedGrants` maps grantId -> { grant, grantDigest, issuer, signature }.
// A caller-supplied grant is NEVER trusted by schema-check alone; it must
// resolve from this registry (registerProviderGrant) and its issuer
// signature must verify at every use.
export function makeVerifierAuthorityRegistry(entries = []) {
  const registry = new Map();
  for (const entry of entries) {
    registry.set(entry.principal, {
      roles: new Set(entry.roles ?? []),
      workspaces: new Set(entry.workspaces ?? []),
    });
  }
  registry.issuedGrants = new Map();
  return registry;
}

// Provider grants are spend/authority decisions: only a reviewer may issue
// one, never the beneficiary itself (self-authored grants are the exact
// review vulnerability). The issuer signs the canonical grant digest with a
// custody key (offline HMAC-SHA256 via signature.mjs) using the
// annotation-set signature envelope (contracts/annotation-set.schema.json):
//   { scheme: 'hmac-sha256', keyRef, digest: <MAC hex>, verified, attestedBy }
function verifyGrantSignature(grant, signature, registry) {
  if (!signature || typeof signature !== 'object' || Array.isArray(signature)) return 'malformed_signature';
  const { scheme, verified, attestedBy } = signature;
  if (scheme !== 'hmac-sha256') return 'unknown_scheme';
  if (verified !== true) return 'attestation_not_verified';
  if (typeof attestedBy !== 'string' || attestedBy.length === 0) return 'malformed_signature';
  const digestBytes = canonicalDigest(grant);
  const options = { artifactOwnerPrincipal: grant.authenticatedPrincipal };
  if (registry) options.registry = registry;
  // signature.mjs verifies custody, digest binding and the MAC in constant
  // time over the contract envelope; self-attestation (issuer ===
  // beneficiary) is refused there as well.
  const verdict = verifySignatureDetailed(signature, attestedBy, digestBytes, options);
  return verdict.ok ? 'verified' : verdict.reason;
}

// Registers an issuer-signed provider grant in the authority registry.
// Fails closed on: unknown/non-reviewer issuer, issuer without authority in
// the grant workspace, self-authored grants, bad signature envelopes.
export function registerProviderGrant(authorities, { grant, issuer, signature, registry } = {}) {
  if (!(authorities instanceof Map) || !(authorities.issuedGrants instanceof Map)) {
    throw new NeedsInput('registerProviderGrant requires a makeVerifierAuthorityRegistry product');
  }
  verifierValidators().requireValid('semantic-provider-grant', grant);
  const entry = authorities.get(issuer);
  if (!entry || !entry.roles.has('reviewer')) {
    throw new AclDenied(`provider grant issuer ${String(issuer)} holds no reviewer authority`);
  }
  if (!entry.workspaces.has(grant.workspaceId)) {
    throw new AclDenied(`provider grant issuer ${issuer} holds no authority in workspace ${grant.workspaceId}`);
  }
  if (issuer === grant.authenticatedPrincipal) {
    throw new AclDenied(`provider grant ${grant.grantId} is self-authored: the beneficiary can never issue its own grant`);
  }
  const verdict = verifyGrantSignature(grant, signature, registry);
  if (verdict !== 'verified') {
    throw new AclDenied(`provider grant ${grant.grantId} signature rejected: ${verdict}`);
  }
  const grantDigest = canonicalDigest(grant);
  authorities.issuedGrants.set(grant.grantId, { grant, grantDigest, issuer, signature });
  return { grantId: grant.grantId, grantDigest, issuer, replayed: false };
}

// Use-time re-check of the stored issuer attestation (review P1-2b). The
// cryptographic MAC verification happened MANDATORILY at registration over
// the exact grant digest; the presented grant must hash to that same digest.
// When a key registry is supplied the MAC is re-verified too (key revocation
// defense); its absence never weakens the digest/issuer/expiry binding.
function verifyRegisteredGrantAtUse(registered, keyRegistry) {
  const signature = registered.signature;
  if (!signature || typeof signature !== 'object' || Array.isArray(signature)) return 'malformed_signature';
  if (signature.scheme !== 'hmac-sha256') return 'unknown_scheme';
  if (signature.verified !== true) return 'attestation_not_verified';
  if (signature.attestedBy !== registered.issuer) return 'issuer_mismatch';
  if (!keyRegistry) return 'verified';
  return verifyGrantSignature(registered.grant, signature, keyRegistry);
}

function requireRole(authorities, actor, roles, workspaceId) {
  const entry = authorities?.get(actor);
  const allowed = Array.isArray(roles) ? roles : [roles];
  if (!entry || !allowed.some((role) => entry.roles.has(role))) {
    throw new AclDenied(`actor ${actor} lacks required role (${allowed.join('|')})`);
  }
  if (workspaceId !== undefined && !entry.workspaces.has(workspaceId)) {
    throw new AclDenied(`actor ${actor} has no authority in workspace ${workspaceId}`);
  }
}

function requireContract(name, record) {
  const validators = verifierValidators();
  if (record?.contractVersion !== '1.0.0') {
    throw new ContractVersionUnknown(`${name} has unsupported contractVersion ${String(record?.contractVersion)}`);
  }
  return validators.requireValid(name, record);
}

async function publishThroughStore({ store, actor, workspaceId, operation, operationId, records, auditType, canonicalArgsDigest }) {
  // The capability gate has already run in the public command before any
  // lookup; this helper only performs the atomic idempotent transaction.
  if (!store || typeof store.publish !== 'function') {
    throw new NeedsInput('command requires a verifier store (InMemory or Postgres)');
  }
  if (typeof operationId !== 'string' || !/^op-[a-z0-9][a-z0-9-]{0,62}$/.test(operationId)) {
    throw new VerifierError('OPERATION_ID_INVALID', `bad operation id: ${operationId}`);
  }
  const idempotencyKey = deriveIdempotencyKey({ actor, operation, canonicalArgsDigest });
  try {
    const outcome = await store.publish({
      workspaceId,
      operationId,
      actor,
      operation,
      idempotencyKey,
      records,
      audit: {
        type: auditType,
        recordKind: records[records.length - 1].kind,
        recordId: null,
        payload: { operation, records: records.map(({ kind, record }) => ({ kind, id: recordIdOf(kind, record) })) },
      },
    });
    return { ...outcome, operationId, idempotencyKey };
  } catch (error) {
    if (error instanceof StoreOutcomeUnknownError) {
      throw new ReconciliationRequired(`commit outcome of ${operation} ${operationId} is unknown; escalate to reconciliation`, { cause: error.message });
    }
    throw error;
  }
}

// ---- publishVerificationResult ----------------------------------------------
// Publishes the immutable request + result pair in ONE transaction. The
// result is an advisory evaluation artifact: humanDecisionRequired is always
// true and it can never be recorded as a human ACCEPT_BOUNDED decision.
// inputAcls (review P1-3): descriptors of the evaluated upstream inputs
// ({ visibility: 'public'|'project'|'private', allowedPrincipalIds? }); the
// derived result inherits the STRICTEST of them as store-level metadata —
// never inside the contract payload.
const ACL_STRICTNESS = Object.freeze({ public: 0, project: 1, private: 2 });

export function inheritedAclOf(inputAcls) {
  if (inputAcls === undefined) {
    return { visibility: 'project', inherited: 'default_workspace' };
  }
  if (!Array.isArray(inputAcls) || inputAcls.length === 0) {
    throw new NeedsInput('inputAcls must be a non-empty array of { visibility, allowedPrincipalIds? }');
  }
  let visibility = 'public';
  const principals = new Set();
  for (const [index, input] of inputAcls.entries()) {
    if (!input || typeof input !== 'object' || !(input.visibility in ACL_STRICTNESS)) {
      throw new NeedsInput(`inputAcls[${index}].visibility must be one of public|project|private`);
    }
    if (ACL_STRICTNESS[input.visibility] > ACL_STRICTNESS[visibility]) visibility = input.visibility;
    if (input.visibility === 'private') {
      for (const principal of Array.isArray(input.allowedPrincipalIds) ? input.allowedPrincipalIds : []) {
        if (typeof principal === 'string' && principal.length > 0) principals.add(principal);
      }
    }
  }
  const acl = { visibility, inherited: 'strictest_of_inputs' };
  if (visibility === 'private') acl.allowedPrincipalIds = [...principals].sort();
  return acl;
}

export async function publishVerificationResult({ store, authorities, actor, request, result, operationId, inputAcls }) {
  requireRole(authorities, actor, ['evaluation_harness', 'reviewer'], request?.workspaceId);
  requireContract('semantic-verification-request', request);
  requireContract('semantic-verification-result', result);
  if (computeCanonicalArgsDigest(request) !== request.canonicalArgsDigest) {
    throw new VerifierPolicyBlock('exact-args gate: canonicalArgsDigest does not match the request payload');
  }
  if (result.requestRef !== request.requestId) {
    throw new VerifierPolicyBlock(`result.requestRef ${result.requestRef} does not bind request ${request.requestId}`);
  }
  if (result.inputDigests.artifactDigest !== request.artifact.digest) {
    throw new VerifierPolicyBlock('result.inputDigests.artifactDigest does not match the request artifact digest');
  }
  if (
    result.inputDigests.canonicalArgsDigest !== undefined &&
    result.inputDigests.canonicalArgsDigest !== request.canonicalArgsDigest
  ) {
    throw new VerifierPolicyBlock('result.inputDigests.canonicalArgsDigest does not match the request');
  }
  if (result.humanDecisionRequired !== true) {
    throw new VerifierPolicyBlock('a verifier verdict can never replace a human decision');
  }
  const acl = inheritedAclOf(inputAcls);
  return publishThroughStore({
    store,
    actor,
    workspaceId: request.workspaceId,
    operation: 'publishVerificationResult',
    operationId,
    records: [
      { kind: 'request', record: request, acl },
      { kind: 'result', record: result, acl },
    ],
    auditType: 'VERIFICATION_RESULT_PUBLISHED',
    canonicalArgsDigest: request.canonicalArgsDigest,
  });
}

// ---- publishCalibrationReport ------------------------------------------------
export async function publishCalibrationReport({ store, authorities, actor, report, operationId, workspaceId }) {
  requireRole(authorities, actor, ['evaluation_harness'], workspaceId);
  requireContract('calibration-report', report);
  const canonicalArgsDigest = canonicalDigest(report);
  return publishThroughStore({
    store,
    actor,
    workspaceId,
    operation: 'publishCalibrationReport',
    operationId,
    records: [{ kind: 'calibration_report', record: report }],
    auditType: 'CALIBRATION_REPORT_PUBLISHED',
    canonicalArgsDigest,
  });
}

// ---- publishAdjudication -----------------------------------------------------
// Only an authenticated adjudicator publishes; an annotator of the case can
// never adjudicate it, and the producer can never adjudicate anything
// (spec §3, probe R/I).
export async function publishAdjudication({ store, authorities, actor, adjudication, operationId, workspaceId }) {
  requireRole(authorities, actor, ['adjudicator'], workspaceId);
  requireContract('adjudication-record', adjudication);
  if (adjudication.adjudicatorIdentity.principalId !== actor) {
    throw new AclDenied('the publishing actor must be the adjudicator of record');
  }
  if (adjudication.adjudicatorIdentity.authenticated !== true) {
    throw new VerifierPolicyBlock('adjudication requires an authenticated adjudicator identity');
  }
  const annotators = new Set(adjudication.retainedRawLabels.map((label) => label.annotatorId));
  if (annotators.has(actor)) {
    throw new VerifierPolicyBlock('an annotator of the case can never adjudicate the same case');
  }
  if (annotators.has(adjudication.adjudicatorIdentity.principalId)) {
    throw new VerifierPolicyBlock('the adjudicator of record appears among the raw annotators');
  }
  const canonicalArgsDigest = canonicalDigest(adjudication);
  return publishThroughStore({
    store,
    actor,
    workspaceId,
    operation: 'publishAdjudication',
    operationId,
    records: [{ kind: 'adjudication', record: adjudication }],
    auditType: 'ADJUDICATION_PUBLISHED',
    canonicalArgsDigest,
  });
}

// ---- invalidateCalibration ---------------------------------------------------
// Drift, revoked labels or changed source revisions publish a typed
// invalidation event with a computable impact set and an explicit supersede
// link. History is never rewritten in place: the invalidated records stay.
export async function invalidateCalibration({ store, authorities, actor, event, operationId, workspaceId }) {
  requireRole(authorities, actor, ['reviewer', 'label_custodian'], workspaceId);
  requireContract('verifier-invalidation-event', event);
  if (!Array.isArray(event.affectedRecords) || event.affectedRecords.length === 0) {
    throw new VerifierPolicyBlock('invalidation requires a non-empty computable impact set');
  }
  const canonicalArgsDigest = canonicalDigest(event);
  return publishThroughStore({
    store,
    actor,
    workspaceId,
    operation: 'invalidateCalibration',
    operationId,
    records: [{ kind: 'invalidation', record: event }],
    auditType: 'CALIBRATION_INVALIDATED',
    canonicalArgsDigest,
  });
}

// ---- provider external calls (spec §9/§11) -----------------------------------
// The provider/model call itself is NEVER held inside a DB transaction:
// reserve happens atomically BEFORE the call (REQUEST_ACCEPTED), and
// RUN_FINALIZED commits the exact response digest + settlement afterwards.
// A crash/timeout/unknown outcome between the two transitions is escalated
// through finalizeExternalCall({ outcome: 'unknown' }) to
// RECONCILIATION_REQUIRED behind the fencing token — never a blind retry.

// Provider-grant authorization (spec §9/§10, review P1-2). A grant is
// accepted ONLY when ALL of the following hold:
//   (1) it is contract-valid and all three numeric budget fields are present
//       (NEEDS_INPUT before the call otherwise);
//   (2) it RESOLVES from the authority registry as an issuer-registered
//       grant with an identical canonical digest (unknown/tampered grants
//       are refused — schema-valid caller-supplied grants are never trusted);
//   (3) the issuer signature verifies over the exact canonical grant digest
//       at use time, and the issuer differs from the beneficiary;
//   (4) expiry is checked against the INJECTED deterministic clock — a
//       missing `now` is an error, never a silent skip;
//   (5) grant.authenticatedPrincipal === actor and grant.workspaceId equals
//       the operation's workspace.
function requireGrant({ authorities, actor, grant, workspaceId, now, keyRegistry }) {
  if (!grant) throw new NeedsInput('provider call requires a semantic-provider-grant');
  requireContract('semantic-provider-grant', grant);
  // Any missing numeric budget field is NEEDS_INPUT before the call (§9).
  for (const key of ['task', 'campaign', 'day']) {
    if (typeof grant.budget[key] !== 'number' || Number.isNaN(grant.budget[key])) {
      throw new NeedsInput(`provider grant budget.${key} is missing; refusing the provider call`);
    }
  }
  const issuedGrants = authorities?.issuedGrants;
  if (!(issuedGrants instanceof Map)) {
    throw new NeedsInput('provider call requires an authority registry with provider-grant issuers; refusing the call');
  }
  const registered = issuedGrants.get(grant.grantId);
  if (!registered) {
    throw new AclDenied(`provider grant ${grant.grantId} does not resolve from the authority registry: unknown or unregistered grant`);
  }
  if (registered.grantDigest !== canonicalDigest(grant)) {
    throw new VerifierPolicyBlock(`presented provider grant ${grant.grantId} differs from the registered grant`);
  }
  if (registered.issuer === grant.authenticatedPrincipal) {
    throw new AclDenied(`provider grant ${grant.grantId} is self-authored (issuer equals the beneficiary)`);
  }
  if (typeof now !== 'string' || now.length === 0) {
    throw new NeedsInput('provider call requires the injected deterministic `now` to verify grant expiry; absence is an error, never a skip');
  }
  if (String(grant.expiresAt) < String(now)) {
    throw new VerifierPolicyBlock(`provider grant ${grant.grantId} expired at ${grant.expiresAt}`);
  }
  if (grant.authenticatedPrincipal !== actor) {
    throw new AclDenied(`grant ${grant.grantId} names ${grant.authenticatedPrincipal}, not ${actor}`);
  }
  if (grant.workspaceId !== workspaceId) {
    throw new AclDenied(`grant ${grant.grantId} binds workspace ${grant.workspaceId}, not the requested workspace ${workspaceId}`);
  }
  if (grant.noTraining !== true || grant.noRetention !== true) {
    throw new VerifierPolicyBlock('provider grant must assert no-training and no-retention');
  }
  const useVerdict = verifyRegisteredGrantAtUse(registered, keyRegistry);
  if (useVerdict !== 'verified') {
    throw new AclDenied(`provider grant ${grant.grantId} signature rejected at use time: ${useVerdict}`);
  }
  return registered;
}

export async function reserveExternalCall({ store, authorities, actor, grant, callId, operationId, reservation, workspaceId, now, keyRegistry }) {
  requireRole(authorities, actor, ['evaluation_harness'], workspaceId);
  const registered = requireGrant({ authorities, actor, grant, workspaceId, now, keyRegistry });
  if (!store || typeof store.beginExternalCall !== 'function') {
    throw new NeedsInput('reserveExternalCall requires a verifier store with external-call support');
  }
  // The reservation FREEZES the grant binding (review P1-2c): grant digest,
  // workspace, tool, model, timeout, currency and budget travel with the
  // call, and finalize cannot substitute different values.
  const grantBinding = {
    grantDigest: registered.grantDigest,
    workspaceId: grant.workspaceId,
    tool: grant.tool,
    model: grant.modelAccess.modelId,
    modelVersion: grant.modelAccess.modelVersion,
    timeoutMs: grant.timeoutMs,
    currency: grant.currency,
    budget: grant.budget,
  };
  return store.beginExternalCall({
    callId,
    workspaceId,
    actor,
    grantRef: grant.grantId,
    operationId,
    reservation: { ...reservation, grantBinding },
  });
}

export async function acceptExternalCall({ store, actor, callId, fencingToken, workspaceId }) {
  if (!store || typeof store.acceptExternalCall !== 'function') {
    throw new NeedsInput('acceptExternalCall requires a verifier store with external-call support');
  }
  if (!Number.isInteger(fencingToken)) throw new NeedsInput('acceptExternalCall requires the fencing token from reserveExternalCall');
  if (typeof actor !== 'string' || actor.length === 0) {
    throw new NeedsInput('acceptExternalCall requires the acting principal; un-attributed transitions are refused');
  }
  return store.acceptExternalCall({ callId, fencingToken, actor, workspaceId });
}

export async function finalizeExternalCall({ store, actor, callId, fencingToken, responseDigest, settlement, outcome, reason, grant, workspaceId }) {
  if (!store || typeof store.finalizeExternalCall !== 'function' || typeof store.markExternalCallReconciliation !== 'function') {
    throw new NeedsInput('finalizeExternalCall requires a verifier store with external-call support');
  }
  if (!Number.isInteger(fencingToken)) throw new NeedsInput('finalizeExternalCall requires the fencing token from reserveExternalCall');
  if (typeof actor !== 'string' || actor.length === 0) {
    throw new NeedsInput('finalizeExternalCall requires the acting principal; un-attributed transitions are refused');
  }
  if (outcome === 'unknown') {
    // Crash/timeout/unknown provider outcome after REQUEST_ACCEPTED:
    // fenced escalation to reconciliation (probe S). Idempotent per fencing
    // token; a finalized call can never be dragged back.
    return store.markExternalCallReconciliation({ callId, fencingToken, actor, reason: reason ?? 'unknown provider outcome' });
  }
  return store.finalizeExternalCall({ callId, fencingToken, actor, workspaceId, grant, responseDigest, settlement });
}
