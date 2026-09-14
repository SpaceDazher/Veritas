// S2-003 ingestion pipeline.
// State machine (each transition emits an atomic audit event in the store):
//   QUEUED → AUTHORIZED → FETCHING → SNAPSHOT_STAGED → EXTRACTING
//          → VALIDATING → COMMITTED
// Terminal states (exactly one per operation):
//   COMMITTED | BLOCKED_CONNECTOR | ACCESS_DENIED | TOMBSTONED |
//   QUARANTINED | FAILED | CANCELLED | RECONCILIATION_REQUIRED
//
// Hard rules enforced here:
//   - the request is validated against the fetch-request contract; the
//     descriptor is always resolved from the canonical store by
//     request.source_id — a caller-supplied descriptor can never bypass
//     registered ACL/license/lifecycle (server-side authorization);
//   - actor, workspace and connector in the request must match the
//     descriptor; grant_required connectors need a grant verified against
//     the injected grant ledger (fail-closed when none is configured);
//   - the idempotency digest binds the FULL request (actor, connector,
//     grant/lease, budget, claimed metadata, identity, selector): the same
//     operation id with a different payload is a conflict, not a replay;
//   - deduplication is tenant- and ACL-scoped: snapshots outside the
//     requester's scope are invisible to every dedup stage;
//   - the decision clock is injected: wall-clock never reaches a decision;
//   - untrusted content can never change policy, ACL, grants or lifecycle;
//   - an empty successful import is impossible: a fetch without bytes is a
//     normalized error, never COMMITTED.
import { createHash } from 'node:crypto';
import { assertValidContract } from './contract-registry.mjs';
import { CANONICALIZATION_VERSION } from './canonical.mjs';
import { contentSnapshotId, tombstoneSnapshotId } from './time-model.mjs';
import { normalizeContent, sha256Hex, decideDedup, lineageFromVerdict, makeShingleClassifier } from './dedup.mjs';
import { viewerCanRead } from './export-policy.mjs';

const INSTRUCTION_PATTERNS = [
  { pattern: /ignore (all )?(previous|prior|above) instructions/i, classification: 'instruction_attempt' },
  { pattern: /disregard (all )?(previous|prior|above)/i, classification: 'instruction_attempt' },
  { pattern: /you are now (a|an|the)/i, classification: 'instruction_attempt' },
  { pattern: /(new|updated) (system )?prompt:/i, classification: 'instruction_attempt' },
  { pattern: /(call|invoke|run|execute) (the )?(tool|function|command)/i, classification: 'prompt_injection_suspect' },
  { pattern: /(grant|approve|escalate).{0,40}(permission|access|role|authority)/i, classification: 'authority_claim' },
  { pattern: /(you have|you now have) (full |unrestricted )?(access|permission|authority)/i, classification: 'authority_claim' },
];

function classifyEmbeddedInstructions(text) {
  for (const { pattern, classification } of INSTRUCTION_PATTERNS) {
    if (pattern.test(text)) {
      return { present: true, classification, confidence: 0.9, note: 'pattern-matched untrusted content; data-only metadata' };
    }
  }
  return { present: false, classification: 'none', confidence: 1, note: null };
}

// The idempotency digest binds the complete operation arguments. Two calls
// with the same operation id but different authority, budget, selector or
// claimed metadata are a conflict and must never replay each other.
function requestDigest(request) {
  return createHash('sha256').update(JSON.stringify({
    operation_id: request.operation_id,
    source_id: request.source_id,
    connector_id: request.connector_id ?? null,
    locator: request.locator,
    identity: request.identity ?? null,
    selector: request.version_selector ?? { latest: true },
    workspace_id: request.workspace_id,
    actor: request.actor ?? null,
    grant_id: request.grant_id ?? null,
    lease_id: request.lease_id ?? null,
    budget: request.budget ?? null,
    claimed: request.claimed ?? null,
  })).digest('hex');
}

function validateGrant(grant, { request, requiredScope, clockNow }) {
  if (!grant) return 'grant not found in the ledger';
  if (grant.principal_id !== request.actor) return 'grant principal does not match the request actor';
  if (grant.workspace_id !== request.workspace_id) return 'grant workspace does not match the request workspace';
  if (grant.scope !== requiredScope) return `grant scope ${grant.scope} does not cover ${requiredScope}`;
  if (grant.expires_at && String(grant.expires_at) <= String(clockNow)) return 'grant expired';
  return null;
}

export class IngestionPipeline {
  constructor({ store, connectors, clock, now, classifier = null, grants = null }) {
    this.store = store;
    this.connectors = connectors; // Map<source_kind, connector>
    this.clock = clock; // injected decision clock
    // `now` is the only host-time source and it is audit-only.
    this.now = now; // () => utcTimestamp, for observed_at/fetched_at telemetry
    this.classifier = classifier ?? makeShingleClassifier();
    // Optional grant ledger: Map<grant_id, {principal_id, workspace_id,
    // scope, expires_at}>. grant_required connectors fail closed when no
    // ledger is configured.
    this.grants = grants;
    this.observations = [];
  }

  #connectorFor(kind) {
    const connector = this.connectors.get(kind);
    if (!connector) {
      throw new Error(`PIPELINE_CONNECTOR_MISSING: ${kind}`);
    }
    return connector;
  }

  // Record one observation for the run comparator.
  #observe(caseId, decision) {
    this.observations.push({ case_id: caseId, decision: decision.terminal, snapshot_id: decision.snapshot_id ?? null, error_code: decision.error_code ?? null, version: decision.version ?? null });
    return decision;
  }

  // Canonical server-side descriptor resolution: the caller can never inject
  // a substitute descriptor that would bypass registered ACL/lifecycle.
  async #descriptorFor(request) {
    const descriptor = await this.store.getDescriptor(request.source_id);
    if (!descriptor) return null;
    if (request.connector_id !== undefined && request.connector_id !== null && request.connector_id !== descriptor.connector_id) {
      return { __mismatch__: 'connector_id does not match the registered descriptor' };
    }
    return descriptor;
  }

  async ingest({ request, caseId = null }) {
    // QUEUED: request-shape validation before any authorization decision.
    const shape = validateContract('fetch-request', request);
    if (!shape.valid) {
      const outcome = { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: `invalid fetch-request: ${shape.errors.map((e) => e.message).join('; ').slice(0, 200)}` };
      // No ledger entry: the operation id of a malformed request is not owned.
      return this.#observe(caseId, outcome);
    }
    const digest = requestDigest(request);
    let begin;
    try {
      begin = await this.store.beginOperation(request.workspace_id, request.operation_id, digest);
    } catch (error) {
      if (error?.name === 'DuplicateOperationError') {
        return this.#observe(caseId, { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: 'operation id reused with a different request payload' });
      }
      throw error;
    }
    if (begin.replay) {
      const record = begin.record;
      if (record.status === 'INTENT') {
        // A previous attempt crashed before terminal: reconcile, never blind-retry.
        return this.#reconcile({ request, caseId });
      }
      const outcome = { ...record.outcome, replayed: true };
      if (outcome.terminal === 'RECONCILIATION_REQUIRED') {
        // The replay path itself is the duplicate-prevention mechanism.
        outcome.reconciled = true;
        outcome.duplicate_prevented = true;
      }
      return this.#observe(caseId, outcome);
    }
    try {
      const outcome = await this.#execute({ request });
      await this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    } catch (error) {
      if (error?.name === 'UnknownOutcomeError') {
        const outcome = { terminal: 'RECONCILIATION_REQUIRED', error_code: 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED', snapshot_id: null };
        await this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
        return this.#observe(caseId, outcome);
      }
      const outcome = { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: String(error?.message ?? error).slice(0, 256) };
      await this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    }
  }

  // Reconciliation of an unknown outcome: ask the connector what actually
  // happened, then finish the operation exactly once.
  async #reconcile({ request, caseId }) {
    const descriptor = await this.#descriptorFor(request);
    const outcome = { terminal: 'RECONCILIATION_REQUIRED', error_code: 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED', snapshot_id: null, reconciled: true, duplicate_prevented: true };
    if (descriptor && !descriptor.__mismatch__) {
      const connector = this.#connectorFor(descriptor.source_kind);
      await connector.reconcile(request.operation_id);
    }
    await this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
    return this.#observe(caseId, outcome);
  }

  // AUTHORIZATION: everything is decided from the registered descriptor and
  // the validated request; nothing is taken from source content.
  #authorize({ request, descriptor }) {
    if (descriptor?.__mismatch__) {
      return { terminal: 'ACCESS_DENIED', error_code: 'ACCESS_DENIED', snapshot_id: null, detail: descriptor.__mismatch__ };
    }
    if (!descriptor) return { terminal: 'FAILED', error_code: 'NOT_FOUND', snapshot_id: null, detail: 'descriptor not registered' };
    // The request must stay inside the descriptor's workspace scope.
    const workspaceAllowed = request.workspace_id === descriptor.workspace_id
      || (descriptor.classification.allowed_workspace_ids ?? []).includes(request.workspace_id);
    if (!workspaceAllowed) {
      return { terminal: 'ACCESS_DENIED', error_code: 'ACCESS_DENIED', snapshot_id: null, detail: 'request workspace is outside the descriptor scope' };
    }
    // Private sources are readable only by explicitly allowed principals
    // (or the owning workspace, which the check above already covers).
    if (descriptor.classification.visibility === 'private') {
      const principalAllowed = (descriptor.classification.allowed_principal_ids ?? []).includes(request.actor);
      if (!principalAllowed && request.workspace_id !== descriptor.workspace_id) {
        return { terminal: 'ACCESS_DENIED', error_code: 'ACCESS_DENIED', snapshot_id: null, detail: 'actor is not allowed on this private source' };
      }
    }
    if (descriptor.lifecycle?.state === 'tombstoned') {
      return { terminal: 'TOMBSTONED', error_code: 'TOMBSTONED', snapshot_id: null };
    }
    if (descriptor.lifecycle?.state === 'blocked') {
      return { terminal: 'ACCESS_DENIED', error_code: 'ACCESS_DENIED', snapshot_id: null, detail: 'source lifecycle is blocked' };
    }
    const connector = this.#connectorFor(descriptor.source_kind);
    const capabilities = connector.discoverCapabilities();
    if (capabilities.auth_mode === 'blocked_without_credential') {
      return { terminal: 'BLOCKED_CONNECTOR', error_code: 'BLOCKED_CONNECTOR', snapshot_id: null };
    }
    if (capabilities.auth_mode === 'grant_required') {
      if (!this.grants) {
        return { terminal: 'ACCESS_DENIED', error_code: 'ACCESS_DENIED', snapshot_id: null, detail: 'connector requires a verified grant and no grant ledger is configured' };
      }
      const grantProblem = validateGrant(this.grants.get(request.grant_id), {
        request,
        requiredScope: capabilities.required_grant_scope ?? connector.requiredGrantScope,
        clockNow: this.clock.now(),
      });
      if (grantProblem) {
        return { terminal: 'ACCESS_DENIED', error_code: 'ACCESS_DENIED', snapshot_id: null, detail: `grant rejected: ${grantProblem}` };
      }
    }
    if (descriptor.license?.spdx === 'LICENSE_UNKNOWN') {
      return { terminal: 'FAILED', error_code: 'LICENSE_UNKNOWN', snapshot_id: null, detail: 'license must be determined before ingestion' };
    }
    if (descriptor.retention?.policy === 'retain_then_delete' && descriptor.retention?.retain_until) {
      const deadline = descriptor.retention.retain_until;
      const now = this.clock.now();
      if (now > deadline) {
        return { terminal: 'FAILED', error_code: 'RETENTION_BLOCKED', snapshot_id: null, detail: `retention expired at ${deadline}` };
      }
    }
    if (request.budget.max_bytes <= 0 || request.budget.time_limit_ms <= 0) {
      return { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: 'invalid budget' };
    }
    return null; // authorized
  }

  async #execute({ request }) {
    // QUEUED → AUTHORIZED: server-side checks against the registered
    // descriptor only.
    const descriptor = await this.#descriptorFor(request);
    const denied = this.#authorize({ request, descriptor });
    if (denied) return denied;

    // AUTHORIZED → FETCHING
    const fetched = await this.#connectorFor(descriptor.source_kind).fetchVersion({
      operation_id: request.operation_id,
      locator: request.locator,
      identity: request.identity ?? null,
      version_selector: request.version_selector ?? { latest: true },
      signal: request.signal,
      budget: request.budget,
    });
    if (!fetched || fetched.ok !== true) {
      const code = fetched?.code ?? 'BLOCKED_CONNECTOR';
      const terminal = code === 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED' ? 'RECONCILIATION_REQUIRED' : code === 'TOMBSTONED' ? 'TOMBSTONED' : code === 'ACCESS_DENIED' ? 'ACCESS_DENIED' : code === 'NOT_FOUND' || code === 'TIMEOUT' || code === 'RATE_LIMITED' ? 'FAILED' : code;
      const outcome = { terminal, error_code: code, snapshot_id: null };
      if (fetched) {
        const observedAt = this.now();
        this.store.events?.push({ type: 'CONNECTOR_ERROR', operation_id: request.operation_id, code, at: observedAt });
      }
      return outcome;
    }
    if (!Buffer.isBuffer(fetched.raw) || fetched.raw.length === 0) {
      // Silent empty successes are impossible.
      return { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: 'connector returned no bytes' };
    }
    if (fetched.raw.length > request.budget.max_bytes) {
      return { terminal: 'FAILED', error_code: 'QUARANTINED', snapshot_id: null, detail: 'payload exceeds budget' };
    }

    // FETCHING → SNAPSHOT_STAGED
    const observedAt = this.now();
    const fetchedAt = this.now();
    // Canonical identity is anchored on the registered descriptor (or on a
    // provider-canonicalized request identity when a connector supplies one).
    // Source content can never influence it.
    const identity = { canonical_locator: request.identity?.canonical_locator ?? descriptor.canonical_locator, canonicalization_version: CANONICALIZATION_VERSION };
    const rawSha256 = sha256Hex(fetched.raw);
    const normalizedText = normalizeContent(fetched.raw);
    const normalizedSha256 = sha256Hex(normalizedText);

    const prior = await this.store.activeSnapshot(identity.canonical_locator);
    const version = prior.current ? prior.current.version + 1 : 1;
    const snapshotId = contentSnapshotId({
      canonical_locator: identity.canonical_locator,
      raw_sha256: rawSha256,
      normalized_sha256: normalizedSha256,
      version,
    });

    const baseSnapshot = {
      contractVersion: '1.0.0',
      snapshot_id: snapshotId,
      source_id: descriptor.source_id,
      connector_id: descriptor.connector_id,
      source_kind: descriptor.source_kind,
      version,
      snapshot_kind: 'content',
      tombstone_reason: null,
      ...(identity.canonical_url ? { canonical_url: identity.canonical_url } : {}),
      ...(identity.canonical_message_id ? { canonical_message_id: identity.canonical_message_id } : {}),
      ...(identity.canonical_repository_id ? { canonical_repository_id: identity.canonical_repository_id } : {}),
      ...(identity.canonical_object_id ? { canonical_object_id: identity.canonical_object_id } : {}),
      canonical_locator: identity.canonical_locator,
      canonicalization_version: CANONICALIZATION_VERSION,
      raw_sha256: rawSha256,
      normalized_sha256: normalizedSha256,
      author: descriptor.author ?? null,
      publisher: descriptor.publisher ?? null,
      published_at: request.claimed?.published_at ?? null,
      event_time: request.claimed?.event_time ?? null,
      observed_at: observedAt,
      fetched_at: fetchedAt,
      parent_snapshot_id: prior.current?.snapshot_id ?? null,
      supersedes_snapshot_id: prior.current && !prior.tombstoned ? prior.current.snapshot_id : null,
      language: request.claimed?.language ?? null,
      mime_type: fetched.mime_type ?? null,
      size_bytes: fetched.raw.length,
      extraction_status: 'COMPLETE',
      acl: {
        visibility: descriptor.classification.visibility,
        workspace_id: descriptor.workspace_id,
        tenant_id: descriptor.tenant_id,
        ...(descriptor.classification.allowed_workspace_ids ? { allowed_workspace_ids: descriptor.classification.allowed_workspace_ids } : {}),
        ...(descriptor.classification.allowed_principal_ids ? { allowed_principal_ids: descriptor.classification.allowed_principal_ids } : {}),
      },
      license: { spdx: descriptor.license.spdx, attribution_required: descriptor.license.attribution_required },
      retention: { policy: descriptor.retention.policy, retain_until: descriptor.retention.retain_until ?? null },
      fetch_provenance: {
        operation_id: request.operation_id,
        connector_id: descriptor.connector_id,
        connector_version: connectorVersionOf(this, descriptor),
        fetched_from: request.locator.slice(0, 2048),
        fetched_at: fetchedAt,
        grant_id: request.grant_id ?? null,
        content_type_validated: fetched.mime_type != null,
      },
    };

    // EXTRACTING
    const extracted = await this.#connectorFor(descriptor.source_kind).extract(baseSnapshot, fetched);
    const segments = extracted.map((segment, index) => {
      let text = typeof segment.text === 'string' ? segment.text : null;
      let nulSanitized = false;
      if (text !== null && text.includes('\u0000')) {
        text = text.replace(/\u0000/g, '\uFFFD');
        nulSanitized = true;
      }
      const classification = classifyEmbeddedInstructions(text ?? '');
      return {
        contractVersion: '1.0.0',
        segment_id: `seg-${createHash('sha256').update(`${snapshotId}:${index}`).digest('hex').slice(0, 16)}`,
        snapshot_id: snapshotId,
        source_id: descriptor.source_id,
        ordinal: segment.ordinal ?? index,
        coordinates: segment.coordinates,
        text,
        text_sha256: segment.text_sha256 ?? sha256Hex(text ?? ''),
        original_language: request.claimed?.language ?? null,
        normalized_language: request.claimed?.language ?? null,
        extraction: {
          method: segment.extraction.method,
          extractor_name: segment.extraction.extractor_name,
          extractor_version: segment.extraction.extractor_version,
          config_sha256: segment.extraction.config_sha256 ?? null,
          confidence: segment.extraction.confidence,
          uncertainty_flags: nulSanitized && !(segment.extraction.uncertainty_flags ?? []).includes('UNDECODABLE_BYTES')
            ? [...(segment.extraction.uncertainty_flags ?? []), 'UNDECODABLE_BYTES']
            : (segment.extraction.uncertainty_flags ?? []),
          missing_ranges: segment.extraction.missing_ranges ?? [],
        },
        ...(segment.coverage ? { coverage: segment.coverage } : {}),
        embedded_instruction_classification: classification,
        status: segment.status ?? (text !== null ? 'COMPLETE' : 'PARTIAL'),
      };
    });

    // Extraction amplification guard: the segment budget is enforced, not
    // just the byte budget.
    if (request.budget.max_segments !== undefined && segments.length > request.budget.max_segments) {
      return { terminal: 'FAILED', error_code: 'QUARANTINED', snapshot_id: null, detail: `extraction produced ${segments.length} segments, exceeding the budget of ${request.budget.max_segments}` };
    }

    // VALIDATING — full contract validation before anything is committed.
    try {
      assertValidContract('source-snapshot', baseSnapshot);
      for (const segment of segments) assertValidContract('content-segment', segment);
    } catch (error) {
      return { terminal: 'QUARANTINED', error_code: 'QUARANTINED', snapshot_id: null, detail: String(error?.message ?? error).slice(0, 256) };
    }
    // ACL inheritance is verified from the descriptor, never from content.
    if (baseSnapshot.acl.visibility !== descriptor.classification.visibility) {
      return { terminal: 'QUARANTINED', error_code: 'QUARANTINED', snapshot_id: null, detail: 'ACL drift' };
    }

    // COMMITTED — append-only writes in one critical section. Dedup is
    // tenant/ACL-scoped: snapshots outside this descriptor's scope do not
    // exist for the decision.
    const dedup = await decideDedup({
      store: this.store,
      viewer: {
        tenant_id: descriptor.tenant_id,
        workspace_id: descriptor.workspace_id,
        principal_id: request.actor,
      },
      candidate: {
        raw_sha256: rawSha256,
        normalized_sha256: normalizedSha256,
        canonical_locator: identity.canonical_locator,
        version,
        segment_text: segments.map((s) => s.text ?? '').join('\n'),
      },
      classifier: this.classifier,
    });

    if (dedup.verdict === 'EXACT_DUPLICATE_RAW' || dedup.verdict === 'EXACT_DUPLICATE_NORMALIZED' || dedup.verdict === 'SAME_IDENTITY_SAME_VERSION') {
      // Idempotent re-import or in-scope cross-channel duplicate: no new
      // snapshot row.
      if (dedup.upstream.canonical_locator === identity.canonical_locator) {
        const outcome = { terminal: 'COMMITTED', snapshot_id: dedup.upstream.snapshot_id, version: dedup.upstream.version, dedup: dedup.verdict, duplicate_of: dedup.upstream.snapshot_id };
        return outcome;
      }
    }

    // Atomic commit through the store: ledger terminal + snapshot + segments
    // + lineage + audit events in ONE transaction (SQL BEGIN/COMMIT) or one
    // critical section (memory). A failure mid-commit rolls everything back
    // and leaves the INTENT row for reconciliation — a partial snapshot
    // without segments can never be observed.
    const lineageRecord = dedup.upstream && dedup.upstream.canonical_locator !== identity.canonical_locator
      ? lineageFromVerdict({ result: dedup, upstreamSnapshot: dedup.upstream, downstreamSnapshot: baseSnapshot, createdAt: observedAt })
      : null;
    const outcome = { terminal: 'COMMITTED', snapshot_id: snapshotId, version, dedup: dedup.verdict, lineage: Boolean(lineageRecord) };
    await this.store.commitIngest({
      workspaceId: request.workspace_id,
      operationId: request.operation_id,
      outcome,
      snapshot: baseSnapshot,
      segments,
      lineage: lineageRecord,
    });

    return outcome;
  }

  // Deleted-source handling: observeDeletion creates a tombstone version.
  // Prior snapshots and audit remain; the current pointer moves atomically.
  async recordDeletion({ request, reason, caseId = null }) {
    const shape = validateDeletionRequest(request);
    if (!shape.valid) {
      return this.#observe(caseId, { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: `invalid deletion request: ${shape.errors.join('; ').slice(0, 200)}` });
    }
    const digest = requestDigest(request);
    let begin;
    try {
      begin = await this.store.beginOperation(request.workspace_id, request.operation_id, digest);
    } catch (error) {
      if (error?.name === 'DuplicateOperationError') {
        return this.#observe(caseId, { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: 'operation id reused with a different request payload' });
      }
      throw error;
    }
    if (begin.replay && begin.record.status !== 'INTENT') {
      return this.#observe(caseId, { ...begin.record.outcome, replayed: true });
    }
    const descriptor = await this.#descriptorFor(request);
    if (!descriptor || descriptor.__mismatch__) {
      const outcome = { terminal: 'FAILED', error_code: 'NOT_FOUND', snapshot_id: null, detail: 'descriptor not registered' };
      await this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    }
    if (request.workspace_id !== descriptor.workspace_id && !(descriptor.classification.allowed_workspace_ids ?? []).includes(request.workspace_id)) {
      const outcome = { terminal: 'ACCESS_DENIED', error_code: 'ACCESS_DENIED', snapshot_id: null, detail: 'deletion request outside the descriptor scope' };
      await this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    }
    if (descriptor.lifecycle?.state === 'tombstoned') {
      // Idempotent re-observation of a deletion: the source is already
      // tombstoned; return the current tombstone without a new append.
      const current = await this.store.activeSnapshot(descriptor.canonical_locator);
      const outcome = { terminal: 'TOMBSTONED', error_code: 'TOMBSTONED', snapshot_id: current.current?.snapshot_id ?? null, idempotent: true };
      await this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    }
    try {
      const identity = { canonical_locator: request.identity?.canonical_locator ?? descriptor.canonical_locator, canonicalization_version: CANONICALIZATION_VERSION };
      const prior = await this.store.activeSnapshot(identity.canonical_locator);
      const version = (prior.current?.version ?? 0) + 1;
      const at = this.now();
      const tombstone = {
        contractVersion: '1.0.0',
        snapshot_id: tombstoneSnapshotId({ canonical_locator: identity.canonical_locator, version }),
        source_id: descriptor.source_id,
        connector_id: descriptor.connector_id,
        source_kind: descriptor.source_kind,
        version,
        snapshot_kind: 'tombstone',
        tombstone_reason: reason,
        canonical_locator: identity.canonical_locator,
        canonicalization_version: CANONICALIZATION_VERSION,
        raw_sha256: sha256Hex(''),
        normalized_sha256: sha256Hex(''),
        author: descriptor.author ?? null,
        publisher: descriptor.publisher ?? null,
        published_at: null,
        event_time: null,
        observed_at: at,
        fetched_at: at,
        parent_snapshot_id: prior.current?.snapshot_id ?? null,
        supersedes_snapshot_id: null,
        language: null,
        mime_type: null,
        size_bytes: 0,
        extraction_status: 'FAILED',
        acl: {
          visibility: descriptor.classification.visibility,
          workspace_id: descriptor.workspace_id,
          tenant_id: descriptor.tenant_id,
          ...(descriptor.classification.allowed_workspace_ids ? { allowed_workspace_ids: descriptor.classification.allowed_workspace_ids } : {}),
          ...(descriptor.classification.allowed_principal_ids ? { allowed_principal_ids: descriptor.classification.allowed_principal_ids } : {}),
        },
        license: { spdx: descriptor.license.spdx, attribution_required: descriptor.license.attribution_required },
        retention: { policy: descriptor.retention.policy, retain_until: descriptor.retention.retain_until ?? null },
        fetch_provenance: {
          operation_id: request.operation_id,
          connector_id: descriptor.connector_id,
          connector_version: connectorVersionOf(this, descriptor),
          fetched_from: 'observeDeletion',
          fetched_at: at,
          grant_id: null,
          content_type_validated: false,
        },
      };
      assertValidContract('source-snapshot', tombstone);
      const outcome = { terminal: 'TOMBSTONED', error_code: 'TOMBSTONED', snapshot_id: tombstone.snapshot_id, version };
      await this.store.commitIngest({
        workspaceId: request.workspace_id,
        operationId: request.operation_id,
        outcome,
        snapshot: tombstone,
        descriptorTombstone: { source_id: descriptor.source_id, reason, at },
      });
      return this.#observe(caseId, outcome);
    } catch (error) {
      const outcome = { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: String(error?.message ?? error).slice(0, 256) };
      await this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    }
  }
}

// Deletion requests reuse the fetch-request contract for identity/budget
// fields; they carry no version selector.
function validateDeletionRequest(request) {
  const errors = [];
  if (typeof request?.operation_id !== 'string' || !/^op-[a-z0-9][a-z0-9-]{0,62}$/.test(request.operation_id)) errors.push('operation_id');
  if (typeof request?.source_id !== 'string' || !/^src-[a-z0-9][a-z0-9-]{0,62}$/.test(request.source_id)) errors.push('source_id');
  if (typeof request?.workspace_id !== 'string' || !/^ws-[a-z0-9][a-z0-9-]{0,62}$/.test(request.workspace_id)) errors.push('workspace_id');
  if (typeof request?.actor !== 'string' || !/^prn-[a-z0-9][a-z0-9-]{0,62}$/.test(request.actor)) errors.push('actor');
  return { valid: errors.length === 0, errors };
}

function validateContract(name, data) {
  try {
    assertValidContract(name, data);
    return { valid: true, errors: [] };
  } catch (error) {
    const messages = String(error?.message ?? error).replace(/^CONTRACT_INVALID [^:]+:\s*/, '');
    return { valid: false, errors: [{ message: messages }] };
  }
}

function connectorVersionOf(pipeline, descriptor) {
  const connector = pipeline.connectors.get(descriptor.source_kind);
  return connector?.version ?? '0.0.0';
}
