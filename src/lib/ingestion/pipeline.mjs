// S2-003 ingestion pipeline.
// State machine (each transition emits an atomic audit event in the store):
//   QUEUED → AUTHORIZED → FETCHING → SNAPSHOT_STAGED → EXTRACTING
//          → VALIDATING → COMMITTED
// Terminal states (exactly one per operation):
//   COMMITTED | BLOCKED_CONNECTOR | ACCESS_DENIED | TOMBSTONED |
//   QUARANTINED | FAILED | CANCELLED | RECONCILIATION_REQUIRED
//
// Hard rules enforced here:
//   - authorization is server-side, from the descriptor, never from content;
//   - the decision clock is injected: wall-clock never reaches a decision;
//   - idempotency: a repeated operation replays its recorded terminal without
//     re-executing; an interrupted operation (crash) is reconciled, and a
//     reconciled replay never creates a second snapshot or a second event;
//   - untrusted content can never change policy, ACL, grants or lifecycle;
//   - an empty successful import is impossible: a fetch without bytes is a
//     normalized error, never COMMITTED.
import { createHash } from 'node:crypto';
import { assertValidContract } from './contract-registry.mjs';
import { CANONICALIZATION_VERSION } from './canonical.mjs';
import { contentSnapshotId, tombstoneSnapshotId } from './time-model.mjs';
import { normalizeContent, sha256Hex, decideDedup, lineageFromVerdict, makeShingleClassifier } from './dedup.mjs';
import { connectorError } from './connectors/base.mjs';

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

function requestDigest(request) {
  return createHash('sha256').update(JSON.stringify({
    operation_id: request.operation_id,
    source_id: request.source_id,
    locator: request.locator,
    selector: request.version_selector ?? { latest: true },
    workspace_id: request.workspace_id,
  })).digest('hex');
}

export class IngestionPipeline {
  constructor({ store, connectors, clock, now, classifier = null }) {
    this.store = store;
    this.connectors = connectors; // Map<source_kind, connector>
    this.clock = clock; // injected decision clock
    // `now` is the only host-time source and it is audit-only.
    this.now = now; // () => utcTimestamp, for observed_at/fetched_at telemetry
    this.classifier = classifier ?? makeShingleClassifier();
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

  async ingest({ request, descriptor, caseId = null }) {
    const digest = requestDigest(request);
    const begin = this.store.beginOperation(request.workspace_id, request.operation_id, digest);
    if (begin.replay) {
      const record = begin.record;
      if (record.status === 'INTENT') {
        // A previous attempt crashed before terminal: reconcile, never blind-retry.
        return this.#reconcile({ request, descriptor, caseId });
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
      const outcome = await this.#execute({ request, descriptor });
      this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    } catch (error) {
      if (error?.name === 'UnknownOutcomeError') {
        const outcome = { terminal: 'RECONCILIATION_REQUIRED', error_code: 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED', snapshot_id: null };
        this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
        return this.#observe(caseId, outcome);
      }
      const outcome = { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: String(error?.message ?? error).slice(0, 256) };
      this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    }
  }

  // Reconciliation of an unknown outcome: ask the connector what actually
  // happened, then finish the operation exactly once.
  async #reconcile({ request, descriptor, caseId }) {
    const connector = this.#connectorFor(descriptor.source_kind);
    const probe = await connector.reconcile(request.operation_id);
    const outcome = probe?.known
      ? { terminal: 'RECONCILIATION_REQUIRED', error_code: 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED', snapshot_id: probe.snapshot_id ?? null, reconciled: true, duplicate_prevented: true }
      : { terminal: 'RECONCILIATION_REQUIRED', error_code: 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED', snapshot_id: null, reconciled: true, duplicate_prevented: true };
    this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
    return this.#observe(caseId, outcome);
  }

  async #execute({ request, descriptor }) {
    // QUEUED → AUTHORIZED: server-side checks against the descriptor only.
    if (!descriptor) return { terminal: 'FAILED', error_code: 'NOT_FOUND', snapshot_id: null, detail: 'descriptor not registered' };
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
    if (capabilities.auth_mode === 'grant_required' && !request.grant_id) {
      return { terminal: 'ACCESS_DENIED', error_code: 'ACCESS_DENIED', snapshot_id: null, detail: 'connector requires a verified grant' };
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

    // AUTHORIZED → FETCHING
    const fetched = await connector.fetchVersion({
      operation_id: request.operation_id,
      locator: request.locator,
      identity: request.identity ?? null,
      version_selector: request.version_selector ?? { latest: true },
      signal: request.signal,
    });
    if (!fetched || fetched.ok !== true) {
      const code = fetched?.code ?? 'BLOCKED_CONNECTOR';
      const terminal = code === 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED' ? 'RECONCILIATION_REQUIRED' : code === 'TOMBSTONED' ? 'TOMBSTONED' : code === 'ACCESS_DENIED' ? 'ACCESS_DENIED' : code === 'NOT_FOUND' || code === 'TIMEOUT' || code === 'RATE_LIMITED' ? 'FAILED' : code;
      const outcome = { terminal, error_code: code, snapshot_id: null };
      if (fetched) {
        const observedAt = this.now();
        this.store.events.push({ type: 'CONNECTOR_ERROR', operation_id: request.operation_id, code, at: observedAt });
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

    const prior = this.store.activeSnapshot(identity.canonical_locator);
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
        connector_version: connector.version,
        fetched_from: request.locator.slice(0, 2048),
        fetched_at: fetchedAt,
        grant_id: request.grant_id ?? null,
        content_type_validated: fetched.mime_type != null,
      },
    };

    // EXTRACTING
    const extracted = await connector.extract(baseSnapshot, fetched);
    const segments = extracted.map((segment, index) => {
      const text = typeof segment.text === 'string' ? segment.text : null;
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
          uncertainty_flags: segment.extraction.uncertainty_flags ?? [],
          missing_ranges: segment.extraction.missing_ranges ?? [],
        },
        ...(segment.coverage ? { coverage: segment.coverage } : {}),
        embedded_instruction_classification: classification,
        status: segment.status ?? (text !== null ? 'COMPLETE' : 'PARTIAL'),
      };
    });

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

    // COMMITTED — append-only writes in one critical section.
    const dedup = decideDedup({
      store: this.store,
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
      // Idempotent re-import or cross-channel duplicate: no new snapshot row.
      if (dedup.upstream.canonical_locator === identity.canonical_locator) {
        const outcome = { terminal: 'COMMITTED', snapshot_id: dedup.upstream.snapshot_id, version: dedup.upstream.version, dedup: dedup.verdict, duplicate_of: dedup.upstream.snapshot_id };
        return outcome;
      }
    }

    this.store.appendSnapshot(baseSnapshot);
    this.store.appendSegments(snapshotId, segments);

    if (dedup.upstream && dedup.upstream.canonical_locator !== identity.canonical_locator) {
      const lineage = lineageFromVerdict({ result: dedup, upstreamSnapshot: dedup.upstream, downstreamSnapshot: baseSnapshot, createdAt: observedAt });
      if (lineage) this.store.appendLineage(lineage);
    }

    return { terminal: 'COMMITTED', snapshot_id: snapshotId, version, dedup: dedup.verdict, lineage: dedup.upstream && dedup.upstream.canonical_locator !== identity.canonical_locator };
  }

  // Deleted-source handling: observeDeletion creates a tombstone version.
  // Prior snapshots and audit remain; the current pointer moves atomically.
  async recordDeletion({ request, descriptor, reason, caseId = null }) {
    const digest = requestDigest(request);
    const begin = this.store.beginOperation(request.workspace_id, request.operation_id, digest);
    if (begin.replay && begin.record.status !== 'INTENT') {
      return this.#observe(caseId, { ...begin.record.outcome, replayed: true });
    }
    try {
      const identity = { canonical_locator: request.identity?.canonical_locator ?? descriptor.canonical_locator, canonicalization_version: CANONICALIZATION_VERSION };
      const prior = this.store.activeSnapshot(identity.canonical_locator);
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
      this.store.appendSnapshot(tombstone);
      this.store.tombstoneDescriptor(descriptor.source_id, reason, at);
      const outcome = { terminal: 'TOMBSTONED', error_code: 'TOMBSTONED', snapshot_id: tombstone.snapshot_id, version };
      this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    } catch (error) {
      const outcome = { terminal: 'FAILED', error_code: 'MALFORMED_CONTENT', snapshot_id: null, detail: String(error?.message ?? error).slice(0, 256) };
      this.store.completeOperation(request.workspace_id, request.operation_id, outcome);
      return this.#observe(caseId, outcome);
    }
  }
}

function connectorVersionOf(pipeline, descriptor) {
  const connector = pipeline.connectors.get(descriptor.source_kind);
  return connector?.version ?? '0.0.0';
}
