// S2-004 Claim Graph Store (memory implementation).
//
// Ownership and trust model (todo §2, §9):
// - every claim/edge record is immutable; corrections create a new revision
//   and a SUPERSEDES edge; lifecycle is a *projected* state derived from
//   review decisions and invalidation events, never a rewrite of content;
// - evidence_support, authorship, user_expert_trust, measured_calibration,
//   review_status and epistemic_type are separate fields and are never folded
//   into a single score anywhere in this module;
// - a producer can never review/accept their own claim;
// - every mutation carries an exact capability (role in the claim's
//   workspace), canonical arguments, an idempotency key and an atomic
//   commit: claim + edges + audit/outbox event are written together or
//   nothing is written at all;
// - replay of a committed operation returns the recorded outcome; an unknown
//   outcome leads to reconciliation, never a blind retry (probe J).
import {
  claimValidators,
  canonicalJson,
  canonicalDigestOfClaim,
  claimContentDigest,
  deterministicClaimId,
  deterministicId,
  sha256Hex,
  spanDigest,
  VeritasError,
} from './validation.mjs';

export const CLAIM_LIFECYCLE = Object.freeze([
  'PROPOSED', 'QUARANTINED', 'REVIEWED', 'ACCEPTED_BOUNDED', 'REJECTED', 'STALE', 'REVOKED', 'SUPERSEDED',
]);

export const VISIBILITY_SEVERITY = Object.freeze({ public: 1, project: 2, private: 3 });

export function makeAuthorityRegistry(entries = []) {
  const registry = new Map();
  for (const entry of entries) {
    registry.set(entry.principal, {
      roles: new Set(entry.roles ?? []),
      workspaces: new Set(entry.workspaces ?? []),
    });
  }
  return registry;
}

export function mostRestrictiveAcl(acls) {
  if (!Array.isArray(acls) || acls.length === 0) throw new VeritasError('ACL_EMPTY', 'cannot derive ACL from an empty set');
  let severity = -1;
  let visibility = 'private';
  for (const acl of acls) {
    if (VISIBILITY_SEVERITY[acl.visibility] > severity) {
      severity = VISIBILITY_SEVERITY[acl.visibility];
      visibility = acl.visibility;
    }
  }
  const derived = { visibility, workspace_id: acls[0].workspace_id, tenant_id: acls[0].tenant_id };
  if (visibility === 'project') {
    const sets = acls.filter((a) => a.visibility === 'project').map((a) => new Set(a.allowed_workspace_ids ?? []));
    derived.allowed_workspace_ids = sets.length
      ? [...sets.reduce((acc, s) => new Set([...acc].filter((x) => s.has(x))))]
      : [];
  }
  if (visibility === 'private') {
    const sets = acls.filter((a) => a.visibility === 'private').map((a) => new Set(a.allowed_principal_ids ?? []));
    derived.allowed_principal_ids = sets.length
      ? [...sets.reduce((acc, s) => new Set([...acc].filter((x) => s.has(x))))]
      : [];
  }
  return derived;
}

export function aclGrantsRead(acl, { workspaceId, principalId }) {
  switch (acl.visibility) {
    case 'public':
      return true;
    case 'project':
      return acl.workspace_id === workspaceId || (acl.allowed_workspace_ids ?? []).includes(workspaceId);
    case 'private':
      return (acl.allowed_principal_ids ?? []).includes(principalId);
    default:
      return false;
  }
}

export function createClaimGraphStore({ authorities, clock, segmentResolver, snapshotResolver } = {}) {
  const validators = claimValidators();
  const now = clock ?? (() => new Date().toISOString().replace(/(\.\d{3})\d*Z$/, '$1Z').replace(/\.\d+Z$/, '.000Z'));
  const can = (principal, role, workspaceId) => {
    const entry = authorities?.get(principal);
    if (!entry || !entry.roles.has(role)) return false;
    if (workspaceId === undefined) return true; // workspace-unbounded role (e.g. evaluator)
    return entry.workspaces.has(workspaceId);
  };

  // ---- immutable content ----
  const claims = new Map();        // claim_id -> Map(revision -> claim record)
  const evidenceEdges = new Map(); // edge_id -> edge record
  const claimEdges = new Map();    // edge_id -> edge record
  const expertProfiles = new Map();// expert_id -> { history: [profile...] }
  const lenses = new Map();        // lens_id -> { history: [lens...] }
  const calibrationRecords = new Map(); // calibration_id -> record
  // ---- projected state ----
  const claimState = new Map();    // claim_id -> { revision, lifecycle, staleReasons[], reviewed:bool, supersededBy }
  const reviewDecisions = new Map(); // decision_id -> decision
  const invalidationEvents = new Map(); // event_id -> event
  // ---- idempotency + audit ----
  const operationLedger = new Map(); // operationId -> { status, idempotencyKey, actor, inputDigest, outcome }
  const idempotencyIndex = new Map(); // idempotencyKey -> operationId
  const outbox = [];

  const audit = (operation, type, payload) => {
    const event = {
      event_id: deterministicId('aud', operation.operation_id, type, outbox.length),
      type,
      operation_id: operation.operation_id,
      actor: operation.actor,
      created_at: operation.now,
      payload_digest: sha256Hex(payload),
    };
    outbox.push(event);
    operation.events.push(event);
    return event;
  };

  function beginOperation({ operationId, actor, idempotencyKey, input }) {
    if (!/^op-[a-z0-9][a-z0-9-]{0,62}$/.test(operationId ?? '')) {
      throw new VeritasError('OPERATION_ID_INVALID', `bad operation id: ${operationId}`);
    }
    const inputDigest = sha256Hex(input ?? null);
    const ledgered = operationLedger.get(operationId);
    if (ledgered) {
      if (ledgered.inputDigest === inputDigest && ledgered.actor === actor) {
        // Idempotent replay of a committed operation returns the recorded
        // outcome; nothing is written twice.
        return { replay: true, status: ledgered.status, outcome: ledgered.outcome };
      }
      throw new VeritasError('IDEMPOTENCY_CONFLICT', `operation ${operationId} already exists with a different actor/input digest`);
    }
    if (idempotencyKey !== undefined && idempotencyKey !== null) {
      const mapped = idempotencyIndex.get(idempotencyKey);
      if (mapped && mapped !== operationId) {
        const other = operationLedger.get(mapped);
        if (other && (other.actor !== actor || other.inputDigest !== inputDigest)) {
          throw new VeritasError('IDEMPOTENCY_CONFLICT', `idempotency key ${idempotencyKey} already bound to operation ${mapped} with different actor/input digest`);
        }
      }
    }
    return {
      replay: false,
      operation: {
        operation_id: operationId,
        actor,
        idempotency_key: idempotencyKey ?? null,
        now: now(),
        events: [],
        written: [],
      },
      inputDigest,
    };
  }

  // every write between beginOperation and commit/rollback is undoable
  function activateWriteLog(operation) {
    activeWriteLog = operation.written;
  }

  function commitOperation(operation, inputDigest, outcome) {
    activeWriteLog = null;
    operationLedger.set(operation.operation_id, {
      status: 'COMMITTED',
      actor: operation.actor,
      idempotencyKey: operation.idempotency_key,
      inputDigest,
      outcome,
      auditEvents: operation.events.length,
    });
    if (operation.idempotency_key) idempotencyIndex.set(operation.idempotency_key, operation.operation_id);
    return outcome;
  }

  function rollbackOperation(operation) {
    // remove any records the failed operation had already written
    activeWriteLog = null;
    for (const undo of operation.written.reverse()) undo();
    operation.written.length = 0;
  }

  // write-log of the operation currently being applied; used to undo partial
  // writes when a later validation step fails (atomic all-or-nothing)
  let activeWriteLog = null;

  function trackWrite(undo) {
    if (activeWriteLog) activeWriteLog.push(undo);
  }

  function putClaimRecord(claim) {
    let revisions = claims.get(claim.claim_id);
    if (!revisions) {
      revisions = new Map();
      claims.set(claim.claim_id, revisions);
    }
    if (revisions.has(claim.revision)) {
      const existing = revisions.get(claim.revision);
      if (canonicalJson(existing) !== canonicalJson(claim)) {
        throw new VeritasError('CLAIM_REVISION_CONFLICT', `claim ${claim.claim_id}@${claim.revision} already exists with different content`);
      }
      return existing;
    }
    revisions.set(claim.revision, claim);
    trackWrite(() => revisions.delete(claim.revision));
    return claim;
  }

  function ensureClaimState(claimId) {
    let state = claimState.get(claimId);
    if (!state) {
      state = { revision: 0, lifecycle: 'PROPOSED', staleReasons: [], reviewed: false, terminalDecision: false, supersededBy: null, revisionLifecycle: new Map() };
      claimState.set(claimId, state);
    }
    return state;
  }

  function currentLifecycle(claimId) {
    const revisions = claims.get(claimId);
    if (!revisions || revisions.size === 0) return null;
    return ensureClaimState(claimId);
  }

  function claimWithState(claim) {
    const state = claimState.get(claim.claim_id);
    if (!state) return { ...claim };
    const revisionLifecycle = state.revisionLifecycle?.get(claim.revision);
    if (revisionLifecycle) return { ...claim, lifecycle: revisionLifecycle };
    if (state.revision !== claim.revision) return { ...claim };
    return { ...claim, lifecycle: state.lifecycle };
  }

  function latestRevision(claimId) {
    const revisions = claims.get(claimId);
    if (!revisions || revisions.size === 0) return null;
    return Math.max(...revisions.keys());
  }

  function getClaimRecord(claimId, revision) {
    const revisions = claims.get(claimId);
    if (!revisions) return null;
    const target = revision ?? latestRevision(claimId);
    return revisions.get(target) ?? null;
  }

  // ---- dependency graph over claims (for cycle detection + invalidation) ----
  function dependsOnEdges() {
    const edges = [];
    for (const edge of claimEdges.values()) {
      if (edge.relation === 'DEPENDS_ON' || edge.relation === 'TRANSLATES') edges.push(edge);
    }
    return edges;
  }

  function wouldCreateCycle(sourceClaimId, targetClaimId) {
    if (sourceClaimId === targetClaimId) return true;
    const adjacency = new Map();
    for (const edge of dependsOnEdges()) {
      if (!adjacency.has(edge.source_claim_id)) adjacency.set(edge.source_claim_id, new Set());
      adjacency.get(edge.source_claim_id).add(edge.target_claim_id);
    }
    const seen = new Set();
    const stack = [targetClaimId];
    while (stack.length) {
      const node = stack.pop();
      if (node === sourceClaimId) return true;
      if (seen.has(node)) continue;
      seen.add(node);
      for (const next of adjacency.get(node) ?? []) stack.push(next);
    }
    return false;
  }

  // ==========================================================================
  // proposeClaims
  // ==========================================================================
  function proposeClaims({ claims: claimInputs, actor, operationId, idempotencyKey }) {
    if (!Array.isArray(claimInputs) || claimInputs.length === 0) {
      throw new VeritasError('CLAIMS_EMPTY', 'proposeClaims requires at least one claim');
    }
    const begun = beginOperation({ operationId, actor, idempotencyKey, input: claimInputs });
    if (begun.replay) return begun.outcome;
    const { operation, inputDigest } = begun;
    activateWriteLog(operation);

    const proposed = [];
    for (const input of claimInputs) {
      const workspaceId = input.workspace_id;
      if (!can(actor, 'producer', workspaceId) && !can(actor, 'extractor', workspaceId)) {
        rollbackOperation(operation);
        throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} has no producer/extractor capability in workspace ${workspaceId}`);
      }
      const candidate = {
        qualifiers: [],
        assumptions: [],
        exclusions: [],
        supersedes_claim_id: null,
        supersedes_revision: null,
        ...input,
        lifecycle: input.lifecycle ?? 'PROPOSED',
      };
      if (!candidate.claim_id) {
        candidate.claim_id = deterministicClaimId({ workspaceId, contentDigest: claimContentDigest(candidate) });
      }
      if (!candidate.revision) candidate.revision = 1;
      if (!candidate.canonical_digest) {
        candidate.canonical_digest = canonicalDigestOfClaim(candidate);
      }
      validators.requireValid('claim', candidate);
      if (candidate.canonical_digest !== canonicalDigestOfClaim(candidate)) {
        rollbackOperation(operation);
        throw new VeritasError('DIGEST_MISMATCH', `canonical_digest mismatch for ${candidate.claim_id}`);
      }
      const record = putClaimRecord(candidate);
      const state = ensureClaimState(record.claim_id);
      if (record.revision > state.revision) {
        state.revision = record.revision;
        state.lifecycle = record.lifecycle;
      }
      audit(operation, 'CLAIM_PROPOSED', { claim_id: record.claim_id, revision: record.revision, epistemic_type: record.epistemic_type, lifecycle: state.lifecycle });
      proposed.push(claimWithState(record));
    }
    const outcome = { claims: proposed, operation_id: operationId, audit_events: operation.events.length };
    commitOperation(operation, inputDigest, outcome);
    return outcome;
  }

  // ==========================================================================
  // reviewClaim — authorized promotion gate (S1-011 semantics)
  // ==========================================================================
  function reviewClaim({ decision }) {
    validators.requireValid('claim-review-decision', decision);
    const record = getClaimRecord(decision.claim_id, decision.claim_revision);
    if (!record) {
      throw new VeritasError('CLAIM_NOT_FOUND', `claim ${decision.claim_id}@${decision.claim_revision} not found`);
    }
    // exact input binding: the decision binds the canonical digest of the
    // exact claim revision (probe K — forged records do not verify)
    if (record.canonical_digest !== decision.claim_digest) {
      throw new VeritasError('DECISION_BINDING_MISMATCH', 'decision claim_digest does not match the claim revision canonical digest');
    }
    const workspaceId = record.workspace_id;
    if (!can(decision.actor, 'reviewer', workspaceId)) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${decision.actor} has no reviewer capability in workspace ${workspaceId}`);
    }
    // producer cannot review/accept their own claim — even when holding the
    // reviewer role (todo §9)
    if (record.created_by === decision.actor) {
      throw new VeritasError('PRODUCER_SELF_REVIEW', `actor ${decision.actor} produced claim ${record.claim_id} and cannot review it`);
    }
    if (decision.expiry && decision.expiry < now()) {
      throw new VeritasError('DECISION_EXPIRED', 'review decision expiry is in the past');
    }
    // idempotent replay of the exact same decision returns the recorded
    // outcome; a different decision bound to the same decision id conflicts
    const existingDecision = reviewDecisions.get(decision.decision_id);
    if (existingDecision) {
      if (canonicalJson(existingDecision) === canonicalJson(decision)) {
        return claimWithState(record);
      }
      throw new VeritasError('IDEMPOTENCY_CONFLICT', `decision id ${decision.decision_id} already used with different content`);
    }
    const state = ensureClaimState(record.claim_id);
    if (state.terminalDecision) {
      throw new VeritasError('SINGLE_USE_APPROVAL', `claim ${record.claim_id}@${record.revision} already has a terminal review decision`);
    }
    const transition = {
      ACCEPT_BOUNDED: 'ACCEPTED_BOUNDED',
      REJECT: 'REJECTED',
      QUARANTINE: 'QUARANTINED',
      REQUEST_REVISION: 'REVIEWED',
    }[decision.decision];
    if (state.lifecycle === 'STALE' && decision.decision === 'ACCEPT_BOUNDED') {
      // re-review after invalidation is allowed: STALE -> re-verified
      state.staleReasons = [];
    }
    state.lifecycle = transition;
    state.reviewed = true;
    state.terminalDecision = decision.decision === 'ACCEPT_BOUNDED' || decision.decision === 'REJECT';
    reviewDecisions.set(decision.decision_id, decision);
    audit(
      { operation_id: `op-review-${decision.decision_id}`, actor: decision.actor, now: now(), events: [] },
      'CLAIM_REVIEWED',
      { claim_id: record.claim_id, revision: record.revision, decision: decision.decision, reason_codes: decision.reason_codes }
    );
    return claimWithState(record);
  }

  // ==========================================================================
  // Atomic extraction commit: proposed claims + evidence edges + audit are
  // written together or nothing is written at all (todo §4.9)
  // ==========================================================================
  function commitExtraction({ request, result, actor, operationId, idempotencyKey }) {
    if (!can(actor, 'extractor', request.workspace_id) && !can(actor, 'producer', request.workspace_id)) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} has no extractor capability in workspace ${request.workspace_id}`);
    }
    const input = { request, result };
    const begun = beginOperation({ operationId, actor, idempotencyKey, input });
    if (begun.replay) return begun.outcome;
    const { operation, inputDigest } = begun;
    activateWriteLog(operation);

    const claims = [];
    const edges = [];
    try {
      for (const proposed of result.proposed_claims) {
        const segment = resolveSegment(proposed.source_span.segment_id, proposed.segment_revision ?? 1);
        const segmentAcl = segment.acl ?? {
          visibility: 'project',
          workspace_id: request.workspace_id,
          tenant_id: segment.tenant_id ?? 'tn-default',
          allowed_workspace_ids: [],
          allowed_principal_ids: [],
        };
        const record = {
          qualifiers: [],
          assumptions: [],
          exclusions: [],
          supersedes_claim_id: null,
          supersedes_revision: null,
          ...proposed.claim,
          lifecycle: proposed.claim.lifecycle ?? proposed.lifecycle ?? 'PROPOSED',
          created_at: operation.now,
          created_by: actor,
        };
        if (!record.claim_id) {
          record.claim_id = deterministicClaimId({ workspaceId: request.workspace_id, contentDigest: claimContentDigest(record) });
        }
        if (!record.revision) record.revision = 1;
        if (!record.canonical_digest) record.canonical_digest = canonicalDigestOfClaim(record);
        validators.requireValid('claim', record);
        if (record.canonical_digest !== canonicalDigestOfClaim(record)) {
          throw new VeritasError('DIGEST_MISMATCH', `canonical_digest mismatch for ${record.claim_id}`);
        }
        const stored = putClaimRecord(record);
        const state = ensureClaimState(record.claim_id);
        if (record.revision > state.revision) {
          state.revision = record.revision;
          state.lifecycle = record.lifecycle;
        }
        claims.push(claimWithState(stored));

        const exactSpanDigest = spanDigest(segment.text, proposed.source_span.start, proposed.source_span.end);
        if (exactSpanDigest !== proposed.evidence_digest) {
          throw new VeritasError('SPAN_DIGEST_MISMATCH', `evidence digest does not match segment ${proposed.source_span.segment_id} span`);
        }
        const edge = {
          contractVersion: '1.0.0',
          edge_id: deterministicId('eed', record.claim_id, String(record.revision), segment.segment_id, String(proposed.source_span.start), String(proposed.source_span.end), exactSpanDigest.slice(0, 12)),
          claim_id: record.claim_id,
          claim_revision: record.revision,
          segment_id: segment.segment_id,
          segment_revision: segment.revision ?? 1,
          relation: 'SUPPORTS',
          span: { start: proposed.source_span.start, end: proposed.source_span.end },
          quote_digest: proposed.evidence_digest,
          entailment_status: 'ENTAILED',
          method: {
            name: request.extractor,
            version: request.extractor_version,
            config_digest: sha256Hex({ prompt_version: request.prompt_version, parameters: request.parameters, seed: request.seed ?? null }),
          },
          reviewer: null,
          source_family_id: proposed.source_family_id ?? `fam-${sha256Hex(segment.source_id ?? segment.segment_id).slice(0, 16)}`,
          upstream_snapshot_ids: [segment.snapshot_id],
          access_state: 'available',
          retention_state: 'active',
          created_at: operation.now,
          created_by: actor,
        };
        validators.requireValid('evidence-edge', edge);
        putEvidenceEdge(edge);
        edges.push(edge);
      }
    } catch (error) {
      rollbackOperation(operation);
      throw error;
    }
    audit(operation, 'CLAIM_EXTRACTION_COMMITTED', {
      request_id: request.request_id,
      claims: claims.length,
      edges: edges.length,
      abstentions: result.abstentions.length,
      status: result.status,
    });
    const outcome = { claims, edges, result, operation_id: operationId };
    commitOperation(operation, inputDigest, outcome);
    return outcome;
  }

  // ==========================================================================
  // reviseClaim — correction creates a new revision + SUPERSEDES edge
  // ==========================================================================
  function reviseClaim({ claimId, baseRevision, patch, actor, operationId, idempotencyKey }) {
    const base = getClaimRecord(claimId, baseRevision);
    if (!base) throw new VeritasError('CLAIM_NOT_FOUND', `claim ${claimId}@${baseRevision} not found`);
    if (!can(actor, 'producer', base.workspace_id)) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} has no producer capability in workspace ${base.workspace_id}`);
    }
    const input = { claimId, baseRevision, patch, actor };
    const begun = beginOperation({ operationId, actor, idempotencyKey, input });
    if (begun.replay) return begun.outcome;
    const { operation, inputDigest } = begun;
    activateWriteLog(operation);

    const nextRevision = base.revision + 1;
    const replacement = {
      ...base,
      ...patch,
      revision: nextRevision,
      supersedes_claim_id: base.claim_id,
      supersedes_revision: base.revision,
      lifecycle: 'PROPOSED',
      created_at: operation.now,
      created_by: actor,
    };
    replacement.canonical_digest = canonicalDigestOfClaim(replacement);
    validators.requireValid('claim', replacement);
    const record = putClaimRecord(replacement);
    const state = ensureClaimState(claimId);
    state.revisionLifecycle.set(base.revision, 'SUPERSEDED');
    state.revision = nextRevision;
    state.lifecycle = 'PROPOSED';
    state.reviewed = false;
    state.terminalDecision = false;
    audit(operation, 'CLAIM_REVISED', { claim_id: claimId, base_revision: baseRevision, revision: nextRevision });
    // SUPERSEDES edge (same claim, older revision -> newer revision)
    const edge = {
      contractVersion: '1.0.0',
      edge_id: deterministicId('ced', claimId, String(base.revision), claimId, String(nextRevision), 'SUPERSEDES'),
      source_claim_id: claimId,
      source_revision: base.revision,
      target_claim_id: claimId,
      target_revision: nextRevision,
      relation: 'SUPERSEDES',
      direction: 'forward',
      scope_intersection: {},
      provenance: { method: 'claim-revision', extractor: 'veritas-claim-store', extractor_version: '1.0.0' },
      creation_authority: actor,
      created_at: operation.now,
      created_by: actor,
    };
    putClaimEdge(edge);
    audit(operation, 'CLAIMS_LINKED', { edge_id: edge.edge_id, relation: 'SUPERSEDES' });
    const outcome = { claim: claimWithState(record), superseded_revision: base.revision, operation_id: operationId };
    commitOperation(operation, inputDigest, outcome);
    return outcome;
  }

  // ==========================================================================
  // Evidence edges
  // ==========================================================================
  function resolveSegment(segmentId, segmentRevision) {
    if (!segmentResolver) throw new VeritasError('SEGMENT_RESOLVER_MISSING', 'store requires a segment resolver to bind evidence');
    const segment = segmentResolver(segmentId, segmentRevision);
    if (!segment) throw new VeritasError('SEGMENT_NOT_FOUND', `segment ${segmentId}@${segmentRevision ?? '?'} not found`);
    return segment;
  }

  function linkEvidence({ edge: input, actor, operationId, idempotencyKey }) {
    const claim = getClaimRecord(input.claim_id, input.claim_revision);
    if (!claim) throw new VeritasError('CLAIM_NOT_FOUND', `claim ${input.claim_id}@${input.claim_revision} not found`);
    if (!can(actor, 'producer', claim.workspace_id) && !can(actor, 'extractor', claim.workspace_id)) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} has no producer/extractor capability in workspace ${claim.workspace_id}`);
    }
    const begun = beginOperation({ operationId, actor, idempotencyKey, input });
    if (begun.replay) return begun.outcome;
    const { operation, inputDigest } = begun;
    activateWriteLog(operation);

    const segment = resolveSegment(input.segment_id, input.segment_revision);
    const segmentAcl = segment.acl ?? {
      visibility: 'project',
      workspace_id: claim.workspace_id,
      tenant_id: claim.tenant_id,
      allowed_workspace_ids: [],
      allowed_principal_ids: [],
    };
    // derived ACL = most restrictive of all inputs (todo §5)
    const derivedAcl = mostRestrictiveAcl([claim.acl, segmentAcl]);
    // exact span binding: the quote digest must equal the digest of the exact
    // span bytes of the immutable segment (metric: span binding accuracy)
    if (segment.text === null || segment.text === undefined) {
      rollbackOperation(operation);
      throw new VeritasError('SPAN_UNBINDABLE', `segment ${input.segment_id} has no text payload`);
    }
    const actualSpanDigest = spanDigest(segment.text, input.span.start, input.span.end);
    if (actualSpanDigest !== input.quote_digest) {
      rollbackOperation(operation);
      throw new VeritasError('SPAN_DIGEST_MISMATCH', `quote_digest does not match segment ${input.segment_id} span [${input.span.start},${input.span.end})`);
    }
    // rebinding evidence to a reviewed claim revision requires a new revision
    // and a new decision (todo §5)
    const state = claimState.get(claim.claim_id);
    if (state && state.reviewed && input.claim_revision === state.revision) {
      rollbackOperation(operation);
      throw new VeritasError('EVIDENCE_REBIND_AFTER_REVIEW', `claim ${claim.claim_id}@${claim.claim_revision} is reviewed; binding evidence requires a new revision and a new decision`);
    }
    const edge = {
      ...input,
      acl: derivedAcl,
      created_at: operation.now,
      created_by: actor,
    };
    validators.requireValid('evidence-edge', { ...edge, acl: undefined });
    putEvidenceEdge(edge);
    audit(operation, 'EVIDENCE_LINKED', { edge_id: edge.edge_id, claim_id: edge.claim_id, segment_id: edge.segment_id, relation: edge.relation });
    const outcome = { edge, derived_acl: derivedAcl, operation_id: operationId };
    commitOperation(operation, inputDigest, outcome);
    return outcome;
  }

  function putEvidenceEdge(edge) {
    if (evidenceEdges.has(edge.edge_id)) {
      const existing = evidenceEdges.get(edge.edge_id);
      if (canonicalJson(existing) !== canonicalJson(edge)) {
        throw new VeritasError('EDGE_CONFLICT', `evidence edge ${edge.edge_id} already exists with different content`);
      }
      return existing;
    }
    evidenceEdges.set(edge.edge_id, edge);
    trackWrite(() => evidenceEdges.delete(edge.edge_id));
    return edge;
  }

  function putClaimEdge(edge) {
    if (claimEdges.has(edge.edge_id)) {
      const existing = claimEdges.get(edge.edge_id);
      if (canonicalJson(existing) !== canonicalJson(edge)) {
        throw new VeritasError('EDGE_CONFLICT', `claim edge ${edge.edge_id} already exists with different content`);
      }
      return existing;
    }
    claimEdges.set(edge.edge_id, edge);
    trackWrite(() => claimEdges.delete(edge.edge_id));
    return edge;
  }

  function listEvidenceMap(claimId, revision) {
    const target = revision ?? latestRevision(claimId);
    return [...evidenceEdges.values()].filter((e) => e.claim_id === claimId && e.claim_revision === target);
  }

  // ==========================================================================
  // Claim edges
  // ==========================================================================
  function linkClaims({ edge: input, actor, operationId, idempotencyKey }) {
    const source = getClaimRecord(input.source_claim_id, input.source_revision);
    const target = getClaimRecord(input.target_claim_id, input.target_revision);
    if (!source) throw new VeritasError('CLAIM_NOT_FOUND', `claim ${input.source_claim_id}@${input.source_revision} not found`);
    if (!target) throw new VeritasError('CLAIM_NOT_FOUND', `claim ${input.target_claim_id}@${input.target_revision} not found`);
    if (!can(actor, 'producer', source.workspace_id) && !can(actor, 'extractor', source.workspace_id)) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} has no producer/extractor capability in workspace ${source.workspace_id}`);
    }
    if (input.relation === 'SUPERSEDES' && input.source_claim_id !== input.target_claim_id) {
      throw new VeritasError('SUPERSEDES_SCOPE', 'SUPERSEDES edges must connect revisions of the same claim');
    }
    // cycles in DEPENDS_ON (and translation chains) are detected before commit
    if (input.relation === 'DEPENDS_ON' || input.relation === 'TRANSLATES') {
      if (wouldCreateCycle(input.source_claim_id, input.target_claim_id)) {
        throw new VeritasError('CYCLE_DETECTED', `adding ${input.relation} ${input.source_claim_id} -> ${input.target_claim_id} would create a cycle`);
      }
    }
    const begun = beginOperation({ operationId, actor, idempotencyKey, input });
    if (begun.replay) return begun.outcome;
    const { operation, inputDigest } = begun;
    activateWriteLog(operation);

    const derivedAcl = mostRestrictiveAcl([source.acl, target.acl]);
    const edge = {
      scope_intersection: {},
      ...input,
      acl: derivedAcl,
      created_at: operation.now,
      created_by: actor,
    };
    putClaimEdge(edge);
    validators.requireValid('claim-edge', { ...edge, acl: undefined });
    audit(operation, 'CLAIMS_LINKED', { edge_id: edge.edge_id, relation: edge.relation, source: edge.source_claim_id, target: edge.target_claim_id });
    const outcome = { edge, derived_acl: derivedAcl, operation_id: operationId };
    commitOperation(operation, inputDigest, outcome);
    return outcome;
  }

  function listClaimEdges(claimId) {
    return [...claimEdges.values()].filter((e) => e.source_claim_id === claimId || e.target_claim_id === claimId);
  }

  // ==========================================================================
  // Experts, lenses, calibration
  // ==========================================================================
  function upsertExpertProfile({ profile, actor }) {
    validators.requireValid('expert-profile', profile);
    if (profile.created_by !== actor && !can(actor, 'admin', profile.workspace_id ?? 'ws-*')) {
      // profile maintenance is an administrative act bound to its author
      if (profile.created_by !== actor) {
        throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} cannot maintain profile authored by ${profile.created_by}`);
      }
    }
    let entry = expertProfiles.get(profile.expert_id);
    if (!entry) {
      entry = { history: [] };
      expertProfiles.set(profile.expert_id, entry);
    }
    entry.history.push(profile);
    audit({ operation_id: `op-profile-${profile.expert_id}-${entry.history.length}`, actor, now: now(), events: [] }, 'EXPERT_PROFILE_UPSERTED', { expert_id: profile.expert_id, version: entry.history.length });
    return profile;
  }

  function getExpertProfile(expertId) {
    const entry = expertProfiles.get(expertId);
    return entry ? entry.history[entry.history.length - 1] : null;
  }

  function listProfileHistory(expertId) {
    return expertProfiles.get(expertId)?.history ?? [];
  }

  function setExpertLens({ lens, actor, operationId, idempotencyKey }) {
    validators.requireValid('expert-lens', lens);
    if (lens.issuer !== actor && !can(actor, 'admin', lens.owner_workspace_id)) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} cannot issue a lens in workspace ${lens.owner_workspace_id}`);
    }
    const begun = beginOperation({ operationId, actor, idempotencyKey, input: lens });
    if (begun.replay) return begun.outcome;
    const { operation, inputDigest } = begun;
    activateWriteLog(operation);
    let entry = lenses.get(lens.lens_id);
    if (!entry) {
      entry = { history: [] };
      lenses.set(lens.lens_id, entry);
    }
    entry.history.push(lens);
    audit(operation, 'EXPERT_LENS_SET', { lens_id: lens.lens_id, expert_id: lens.expert_id, weight: lens.weight });
    const outcome = { lens, operation_id: operationId };
    commitOperation(operation, inputDigest, outcome);
    return outcome;
  }

  function revokeExpertLens({ lensId, actor, reason, operationId }) {
    const entry = lenses.get(lensId);
    if (!entry) throw new VeritasError('LENS_NOT_FOUND', `lens ${lensId} not found`);
    const lens = entry.history[entry.history.length - 1];
    if (lens.issuer !== actor && lens.owner_principal_id !== actor && !can(actor, 'admin', lens.owner_workspace_id)) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} cannot revoke lens ${lensId}`);
    }
    if (lens.revoked_at) return { lens, alreadyRevoked: true };
    const revoked = {
      ...lens,
      revoked_at: now(),
      revocation_reason: reason ?? 'revoked',
    };
    validators.requireValid('expert-lens', revoked);
    entry.history.push(revoked);
    audit({ operation_id: operationId ?? `op-lens-revoke-${lensId}`, actor, now: now(), events: [] }, 'EXPERT_LENS_REVOKED', { lens_id: lensId, reason: revoked.revocation_reason });
    // revocation immediately ceases use in new decisions: listExpertLenses
    // only returns the non-revoked head; previously produced results keep
    // their provenance (lens_id is recorded there).
    return { lens: revoked, alreadyRevoked: false };
  }

  function listExpertLenses({ workspaceId, principalId, at }) {
    const active = [];
    for (const [lensId, entry] of lenses) {
      const head = entry.history[entry.history.length - 1];
      // isolation: a lens is visible ONLY to its owner workspace+principal
      if (head.owner_workspace_id !== workspaceId || head.owner_principal_id !== principalId) continue;
      if (head.revoked_at) continue;
      if (at && (head.valid_from > at || head.valid_until < at)) continue;
      active.push(head);
    }
    return active;
  }

  function lensById(lensId) {
    const entry = lenses.get(lensId);
    return entry ? entry.history[entry.history.length - 1] : null;
  }

  function upsertCalibrationRecord({ record, actor }) {
    validators.requireValid('calibration-record', record);
    // evaluator independence: the measuring actor must hold the evaluator
    // role (workspace-unbounded); producers and reviewers of the claims being
    // calibrated cannot self-certify semantic quality (probe K)
    if (!can(actor, 'evaluator')) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} has no evaluator capability`);
    }
    if (record.measured_by !== actor) {
      throw new VeritasError('CALIBRATION_BINDING_MISMATCH', 'calibration measured_by does not match the acting principal');
    }
    if (record.status === 'MEASURED' && record.numerator > record.denominator) {
      throw new VeritasError('CALIBRATION_INCONSISTENT', 'numerator exceeds denominator');
    }
    if (record.status === 'MEASURED' && record.missing_count + record.numerator > record.denominator) {
      throw new VeritasError('CALIBRATION_INCONSISTENT', 'numerator + missing exceeds denominator');
    }
    calibrationRecords.set(record.calibration_id, record);
    audit({ operation_id: `op-calibration-${record.calibration_id}`, actor, now: now(), events: [] }, 'CALIBRATION_RECORDED', { calibration_id: record.calibration_id, status: record.status });
    return record;
  }

  function getCalibrationRecord(calibrationId) {
    return calibrationRecords.get(calibrationId) ?? null;
  }

  // ==========================================================================
  // Invalidation (todo §5): tombstone/correction/retraction of a parent
  // transitively marks dependent outputs STALE until re-review; audit lineage
  // is preserved; access restriction hides payload but keeps the reason.
  // ==========================================================================
  function invalidateFromParent({ trigger, reason, actor, operationId }) {
    const input = { trigger, reason };
    const begun = beginOperation({ operationId, actor, idempotencyKey: undefined, input });
    if (begun.replay) return begun.outcome;
    const { operation, inputDigest } = begun;
    activateWriteLog(operation);
    // invalidation is triggered by the ingestion layer or an admin, never by
    // arbitrary content-driven actors
    if (actor !== 'system' && !can(actor, 'admin', 'ws-system') && !can(actor, 'system', 'ws-system')) {
      rollbackOperation(operation);
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} cannot trigger graph invalidation`);
    }

    const visited = new Set();
    const edgesTraversed = [];
    const affected = [];
    const queue = [];

    if (trigger.type.startsWith('source_snapshot') || trigger.type.startsWith('content_segment')) {
      for (const edge of evidenceEdges.values()) {
        const segmentMatches = edge.segment_id === trigger.id;
        if (segmentMatches) {
          queue.push({ kind: 'claim', id: edge.claim_id, revision: edge.claim_revision, via: edge.edge_id });
          edgesTraversed.push(edge.edge_id);
        }
      }
    } else if (trigger.type.startsWith('claim')) {
      queue.push({ kind: 'claim', id: trigger.id, revision: trigger.revision, via: 'trigger' });
    }

    while (queue.length) {
      const node = queue.shift();
      const key = `${node.kind}:${node.id}@${node.revision}`;
      if (visited.has(key)) continue;
      visited.add(key);
      if (node.kind === 'claim') {
        const record = getClaimRecord(node.id, node.revision);
        if (!record) continue;
        if (affected.some((a) => a.entity_id === node.id && a.entity_revision === node.revision)) continue;
        affected.push({ entity_type: 'claim', entity_id: node.id, entity_revision: node.revision, new_lifecycle: 'STALE' });
        const state = ensureClaimState(node.id);
        if (record.revision === state.revision) {
          state.lifecycle = 'STALE';
          state.staleReasons.push({ reason: reason.code, trigger: trigger.id, via: node.via });
        }
        // dependents: DEPENDS_ON / TRANSLATES edges pointing at this claim
        for (const edge of claimEdges.values()) {
          const pointsAt = (edge.target_claim_id === node.id && edge.target_revision === node.revision)
            || (edge.relation === 'TRANSLATES' && edge.source_claim_id === node.id);
          if (!pointsAt) continue;
          edgesTraversed.push(edge.edge_id);
          queue.push({ kind: 'claim', id: edge.relation === 'TRANSLATES' ? edge.target_claim_id : edge.source_claim_id, revision: edge.relation === 'TRANSLATES' ? edge.target_revision : edge.source_revision, via: edge.edge_id });
        }
        // claims evidenced by segments derived from this claim keep their own
        // evidence edges; evidence edges of stale claims are marked restricted
        for (const edge of evidenceEdges.values()) {
          if (edge.claim_id === node.id && edge.claim_revision === node.revision) {
            edgesTraversed.push(edge.edge_id);
            affected.push({ entity_type: 'evidence_edge', entity_id: edge.edge_id, entity_revision: 1, new_lifecycle: 'STALE' });
          }
        }
      }
    }

    const event = {
      contractVersion: '1.0.0',
      event_id: deterministicId('inv', trigger.id, String(trigger.revision), reason.code, operationId),
      trigger_type: trigger.type,
      trigger_id: trigger.id,
      trigger_revision: trigger.revision,
      affected_descendants: affected,
      reason,
      traversal_evidence: { method: 'bfs', visited_count: visited.size, edges_traversed: edgesTraversed },
      completion_state: 'COMPLETED',
      failed_descendants: [],
      created_at: operation.now,
      created_by: actor,
    };
    validators.requireValid('graph-invalidation-event', event);
    invalidationEvents.set(event.event_id, event);
    audit(operation, 'GRAPH_INVALIDATED', { event_id: event.event_id, trigger: trigger.id, affected: affected.length });
    const outcome = { event, operation_id: operationId };
    commitOperation(operation, inputDigest, outcome);
    return outcome;
  }

  function getInvalidationEvents(triggerId) {
    return [...invalidationEvents.values()].filter((e) => e.trigger_id === triggerId);
  }

  // ==========================================================================
  // Reconciliation: unknown outcome leads to reconciliation, not blind retry
  // ==========================================================================
  function reconcileOperation(operationId) {
    const ledgered = operationLedger.get(operationId);
    if (ledgered && ledgered.status === 'COMMITTED') {
      return { status: 'COMMITTED', outcome: ledgered.outcome, replayed: true };
    }
    return { status: 'RECONCILIATION_REQUIRED', replayed: false };
  }

  // ==========================================================================
  // Readers
  // ==========================================================================
  function getClaim(claimId, revision) {
    const record = getClaimRecord(claimId, revision);
    return record ? claimWithState(record) : null;
  }

  function listClaimHistory(claimId) {
    const revisions = claims.get(claimId);
    if (!revisions) return [];
    return [...revisions.keys()].sort((a, b) => a - b).map((r) => claimWithState(revisions.get(r)));
  }

  function listReviewDecisions(claimId) {
    return [...reviewDecisions.values()].filter((d) => d.claim_id === claimId);
  }

  function listOutbox() {
    return [...outbox];
  }

  function listCalibrationRecords() {
    return [...calibrationRecords.values()];
  }

  return {
    // required operations (todo §9)
    proposeClaims,
    reviewClaim,
    getClaim,
    listClaimHistory,
    linkEvidence,
    linkClaims,
    listEvidenceMap,
    setExpertLens,
    revokeExpertLens,
    invalidateFromParent,
    reconcileOperation,
    // additional required surface
    reviseClaim,
    listReviewDecisions,
    upsertExpertProfile,
    getExpertProfile,
    listProfileHistory,
    upsertCalibrationRecord,
    getCalibrationRecord,
    listCalibrationRecords,
    getInvalidationEvents,
    listExpertLenses,
    lensById,
    listOutbox,
    listClaimEdges,
    commitExtraction,
    // internals exposed for tests/diagnostics only
    __internals: {
      wouldCreateCycle,
      operationLedger,
      idempotencyIndex,
      claimState,
    },
  };
}
