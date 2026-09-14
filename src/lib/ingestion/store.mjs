// S2-003 canonical ingestion store.
// In-memory reference implementation of the append-only PostgreSQL model:
//   - snapshots and segments are immutable once written (append-only);
//   - corrections create new versions bound with SUPERSEDES;
//   - deletion creates a tombstone while preserving prior existence and audit;
//   - operation records form an idempotency ledger: intents are written
//     before side effects and terminals exactly once, so a crash replay can
//     reconcile instead of duplicating;
//   - every state transition emits an audit event in the same critical
//     section (mirrored by a single SQL transaction in migrations/0002).
import { createHash } from 'node:crypto';

export class SnapshotImmutabilityError extends Error {
  constructor(message) { super(message); this.name = 'SnapshotImmutabilityError'; }
}
export class DuplicateOperationError extends Error {
  constructor(message) { super(message); this.name = 'DuplicateOperationError'; }
}

function operationKey(workspaceId, operationId) {
  return `${workspaceId}:${operationId}`;
}

function digestOf(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

export class IngestionStore {
  constructor() {
    this.descriptors = new Map(); // source_id -> descriptor
    this.snapshots = new Map(); // snapshot_id -> snapshot (immutable)
    this.versionChain = new Map(); // canonical_locator -> [snapshot_id] in version order
    this.segments = new Map(); // snapshot_id -> [segment] (immutable)
    this.lineage = new Map(); // lineage_id -> lineage
    this.runs = new Map(); // run_id -> run
    this.events = []; // append-only audit log
    this.proposals = new Map(); // proposal_id -> proposal
    this.operations = new Map(); // operation_key -> ledger record
  }

  // --- descriptors -----------------------------------------------------------
  registerDescriptor(descriptor) {
    const existing = this.descriptors.get(descriptor.source_id);
    if (existing) {
      // Descriptors are configuration, not content: their revision is a new
      // append, never an in-place mutation of ACL/license history.
      this.events.push({ type: 'DESCRIPTOR_REAPPENDED', source_id: descriptor.source_id, at: descriptor.registered_at });
      this.descriptors.set(descriptor.source_id, descriptor);
      return descriptor;
    }
    this.descriptors.set(descriptor.source_id, descriptor);
    this.events.push({ type: 'DESCRIPTOR_REGISTERED', source_id: descriptor.source_id, at: descriptor.registered_at });
    return descriptor;
  }

  getDescriptor(sourceId) {
    return this.descriptors.get(sourceId) ?? null;
  }

  tombstoneDescriptor(sourceId, reason, at) {
    const descriptor = this.descriptors.get(sourceId);
    if (!descriptor) return null;
    const tombstoned = {
      ...descriptor,
      lifecycle: { state: 'tombstoned', reason, changed_at: at },
    };
    this.descriptors.set(sourceId, tombstoned);
    this.events.push({ type: 'DESCRIPTOR_TOMBSTONED', source_id: sourceId, reason, at });
    return tombstoned;
  }

  // --- snapshots ---------------------------------------------------------------
  appendSnapshot(snapshot) {
    const existing = this.snapshots.get(snapshot.snapshot_id);
    if (existing) {
      if (digestOf(existing) !== digestOf(snapshot)) {
        throw new SnapshotImmutabilityError(snapshot.snapshot_id);
      }
      return existing; // idempotent re-append of identical bytes
    }
    this.snapshots.set(snapshot.snapshot_id, Object.freeze({ ...snapshot }));
    const chain = this.versionChain.get(snapshot.canonical_locator) ?? [];
    chain.push(snapshot.snapshot_id);
    this.versionChain.set(snapshot.canonical_locator, chain);
    this.events.push({
      type: snapshot.snapshot_kind === 'tombstone' ? 'SNAPSHOT_TOMBSTONED' : 'SNAPSHOT_COMMITTED',
      snapshot_id: snapshot.snapshot_id,
      source_id: snapshot.source_id,
      version: snapshot.version,
      at: snapshot.fetched_at,
    });
    return this.snapshots.get(snapshot.snapshot_id);
  }

  getSnapshot(snapshotId) {
    return this.snapshots.get(snapshotId) ?? null;
  }

  versionChainFor(canonicalLocator) {
    return [...(this.versionChain.get(canonicalLocator) ?? [])];
  }

  currentSnapshot(canonicalLocator) {
    const chain = this.versionChain.get(canonicalLocator);
    if (!chain || chain.length === 0) return null;
    return this.snapshots.get(chain[chain.length - 1]) ?? null;
  }

  activeSnapshot(canonicalLocator) {
    const current = this.currentSnapshot(canonicalLocator);
    if (!current) return { current: null, active: null, tombstoned: false };
    if (current.snapshot_kind === 'tombstone') return { current: current, active: null, tombstoned: true };
    return { current, active: current, tombstoned: false };
  }

  appendSegments(snapshotId, segments) {
    if (this.segments.has(snapshotId)) {
      throw new SnapshotImmutabilityError(`segments already frozen for ${snapshotId}`);
    }
    this.segments.set(snapshotId, Object.freeze(segments.map((segment) => Object.freeze({ ...segment }))));
  }

  segmentsFor(snapshotId) {
    return this.segments.get(snapshotId) ?? [];
  }

  // --- lineage -------------------------------------------------------------
  appendLineage(lineage) {
    const existing = this.lineage.get(lineage.lineage_id);
    if (existing) {
      if (digestOf(existing) !== digestOf(lineage)) {
        throw new SnapshotImmutabilityError(lineage.lineage_id);
      }
      return existing;
    }
    this.lineage.set(lineage.lineage_id, Object.freeze({ ...lineage }));
    this.events.push({ type: 'LINEAGE_APPENDED', lineage_id: lineage.lineage_id, relation: lineage.relation, automated: lineage.automated, status: lineage.status, at: lineage.created_at });
    return this.lineage.get(lineage.lineage_id);
  }

  lineageFor(snapshotId) {
    return [...this.lineage.values()].filter((l) => l.upstream_snapshot_id === snapshotId || l.downstream_snapshot_id === snapshotId);
  }

  // --- idempotency ledger ------------------------------------------------------
  beginOperation(workspaceId, operationId, requestDigest) {
    const key = operationKey(workspaceId, operationId);
    const existing = this.operations.get(key);
    if (existing) {
      if (existing.request_digest !== requestDigest) {
        throw new DuplicateOperationError(`operation ${operationId} reused with a different request payload`);
      }
      return { replay: true, record: existing };
    }
    const record = { workspace_id: workspaceId, operation_id: operationId, request_digest: requestDigest, status: 'INTENT', outcome: null };
    this.operations.set(key, record);
    this.events.push({ type: 'OPERATION_INTENT', operation_id: operationId, workspace_id: workspaceId });
    return { replay: false, record };
  }

  completeOperation(workspaceId, operationId, outcome) {
    const key = operationKey(workspaceId, operationId);
    const record = this.operations.get(key);
    if (!record) throw new Error(`OPERATION_INTENT_MISSING: ${operationId}`);
    if (record.status !== 'INTENT') {
      if (digestOf(record.outcome) === digestOf(outcome)) return record;
      throw new DuplicateOperationError(`operation ${operationId} already completed`);
    }
    record.status = outcome.terminal;
    record.outcome = outcome;
    this.events.push({ type: 'OPERATION_COMPLETED', operation_id: operationId, terminal: outcome.terminal });
    return record;
  }

  getOperation(workspaceId, operationId) {
    return this.operations.get(operationKey(workspaceId, operationId)) ?? null;
  }

  // --- runs / proposals -----------------------------------------------------
  appendRun(run) {
    this.runs.set(run.run_id, Object.freeze({ ...run }));
    return run;
  }

  appendProposal(proposal) {
    if (this.proposals.has(proposal.proposal_id)) {
      throw new DuplicateOperationError(`proposal ${proposal.proposal_id} already exists`);
    }
    this.proposals.set(proposal.proposal_id, Object.freeze({ ...proposal }));
    return proposal;
  }

  // Hard-integrity counters (§13). The runner's run-local counters
  // (private leaks, authority expansions) are passed in as extras.
  async integritySummary({ outcomes = [], privateLeakCounter = 0, authorityExpansionCounter = 0 } = {}) {
    const contentSnapshots = [...this.snapshots.values()].filter((s) => s.snapshot_kind === 'content');
    const provenanceComplete = contentSnapshots.filter((s) => {
      const p = s.fetch_provenance ?? {};
      return Boolean(p.operation_id && p.connector_id && p.connector_version && p.fetched_from && p.fetched_at)
        && Boolean(s.acl?.visibility && s.license?.spdx && s.retention?.policy);
    }).length;
    const commitsPerSnapshot = new Map();
    for (const event of this.events) {
      if (event.type === 'SNAPSHOT_COMMITTED') {
        commitsPerSnapshot.set(event.snapshot_id, (commitsPerSnapshot.get(event.snapshot_id) ?? 0) + 1);
      }
    }
    const flaggedSegments = [...this.segments.values()].flat().filter((s) => s.embedded_instruction_classification?.present === true).length;
    let authorityDrift = authorityExpansionCounter;
    for (const descriptor of this.descriptors.values()) {
      if (descriptor.lifecycle?.state === 'tombstoned') continue;
      if (!descriptor.classification?.visibility) authorityDrift += 1;
    }
    return {
      snapshots_total: this.snapshots.size,
      provenance_complete_pct: contentSnapshots.length === 0 ? 0 : Math.round((provenanceComplete / contentSnapshots.length) * 100),
      committed_operations: [...this.operations.values()].filter((o) => o.status === 'COMMITTED').length,
      operations_stuck_intent: [...this.operations.values()].filter((o) => o.status === 'INTENT').length,
      duplicate_committed_snapshots: [...commitsPerSnapshot.values()].reduce((sum, n) => sum + (n > 1 ? n - 1 : 0), 0),
      committed_without_snapshot: outcomes.filter((o) => o.terminal === 'COMMITTED' && !o.snapshot_id).length,
      private_exports_leaked: privateLeakCounter,
      authority_expansions: authorityDrift,
      instruction_flagged_segments: flaggedSegments,
    };
  }

  decideProposal(proposalId, decision, at) {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) return null;
    const updated = { ...proposal, status: decision.status, reviewed_by: decision.reviewed_by, decision_reason: decision.decision_reason, decided_at: at };
    this.proposals.set(proposalId, Object.freeze(updated));
    return updated;
  }
}
