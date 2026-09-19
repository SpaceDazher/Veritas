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
import { deriveIdempotencyKey, recordIdOf } from './store.mjs';

export { deriveIdempotencyKey };

// Minimal authority registry over the S2-006 role set (spec §3):
// candidate, label_custodian, annotator, adjudicator, evaluation_harness,
// reviewer. Server-enforced; a principal needs the role AND workspace.
export function makeVerifierAuthorityRegistry(entries = []) {
  const registry = new Map();
  for (const entry of entries) {
    registry.set(entry.principal, {
      roles: new Set(entry.roles ?? []),
      workspaces: new Set(entry.workspaces ?? []),
    });
  }
  return registry;
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
export async function publishVerificationResult({ store, authorities, actor, request, result, operationId }) {
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
  return publishThroughStore({
    store,
    actor,
    workspaceId: request.workspaceId,
    operation: 'publishVerificationResult',
    operationId,
    records: [
      { kind: 'request', record: request },
      { kind: 'result', record: result },
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

function requireGrant({ actor, grant, now }) {
  if (!grant) throw new NeedsInput('provider call requires a semantic-provider-grant');
  requireContract('semantic-provider-grant', grant);
  // Any missing numeric budget field is NEEDS_INPUT before the call (§9).
  for (const key of ['task', 'campaign', 'day']) {
    if (typeof grant.budget[key] !== 'number' || Number.isNaN(grant.budget[key])) {
      throw new NeedsInput(`provider grant budget.${key} is missing; refusing the provider call`);
    }
  }
  if (grant.authenticatedPrincipal !== actor) {
    throw new AclDenied(`grant ${grant.grantId} names ${grant.authenticatedPrincipal}, not ${actor}`);
  }
  if (grant.noTraining !== true || grant.noRetention !== true) {
    throw new VerifierPolicyBlock('provider grant must assert no-training and no-retention');
  }
  if (typeof now === 'string' && String(grant.expiresAt) < String(now)) {
    throw new VerifierPolicyBlock(`provider grant ${grant.grantId} expired at ${grant.expiresAt}`);
  }
}

export async function reserveExternalCall({ store, authorities, actor, grant, callId, operationId, reservation, workspaceId, now }) {
  requireRole(authorities, actor, ['evaluation_harness'], workspaceId);
  requireGrant({ actor, grant, now });
  if (!store || typeof store.beginExternalCall !== 'function') {
    throw new NeedsInput('reserveExternalCall requires a verifier store with external-call support');
  }
  return store.beginExternalCall({
    callId,
    workspaceId,
    actor,
    grantRef: grant.grantId,
    operationId,
    reservation: { ...reservation, grantDigest: canonicalDigest(grant) },
  });
}

export async function acceptExternalCall({ store, actor, callId, fencingToken }) {
  if (!store || typeof store.acceptExternalCall !== 'function') {
    throw new NeedsInput('acceptExternalCall requires a verifier store with external-call support');
  }
  if (!Number.isInteger(fencingToken)) throw new NeedsInput('acceptExternalCall requires the fencing token from reserveExternalCall');
  void actor;
  return store.acceptExternalCall({ callId, fencingToken });
}

export async function finalizeExternalCall({ store, actor, callId, fencingToken, responseDigest, settlement, outcome, reason }) {
  if (!store || typeof store.finalizeExternalCall !== 'function' || typeof store.markExternalCallReconciliation !== 'function') {
    throw new NeedsInput('finalizeExternalCall requires a verifier store with external-call support');
  }
  if (!Number.isInteger(fencingToken)) throw new NeedsInput('finalizeExternalCall requires the fencing token from reserveExternalCall');
  void actor;
  if (outcome === 'unknown') {
    // Crash/timeout/unknown provider outcome after REQUEST_ACCEPTED:
    // fenced escalation to reconciliation (probe S). Idempotent per fencing
    // token; a finalized call can never be dragged back.
    return store.markExternalCallReconciliation({ callId, fencingToken, reason: reason ?? 'unknown provider outcome' });
  }
  return store.finalizeExternalCall({ callId, fencingToken, responseDigest, settlement });
}
