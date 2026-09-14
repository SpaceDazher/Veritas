// S2-003 PostgreSQL-backed ingestion store.
// Implements the same interface as the in-memory IngestionStore, but every
// mutation is a real SQL statement against the append-only schema of
// migrations/0002_source_ingestion.sql — including the idempotency ledger
// with its server-enforced INTENT -> terminal transition. Used by the
// DB-backed Run A / Run B replay (scripts/s2-003-db-replay.mjs).
import pg from 'pg';

export class SnapshotImmutabilityError extends Error {
  constructor(message) { super(message); this.name = 'SnapshotImmutabilityError'; }
}
export class DuplicateOperationError extends Error {
  constructor(message) { super(message); this.name = 'DuplicateOperationError'; }
}

const UNIQUE_VIOLATION = '23505';

export class PostgresIngestionStore {
  constructor(pool) {
    this.pool = pool;
    // Audit mirror for run comparators (the canonical copy lives in
    // ingestion_event, which is append-only in SQL).
    this.events = [];
  }

  async #one(sql, params = []) {
    const result = await this.pool.query(sql, params);
    return result.rows[0] ?? null;
  }

  // --- descriptors -----------------------------------------------------------
  async registerDescriptor(d) {
    await this.pool.query(
      `INSERT INTO source_descriptor(source_id, connector_id, source_kind, canonical_locator, display_locator,
         owner, author, publisher, workspace_id, tenant_id, classification, license, retention, lifecycle,
         registered_at, registered_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       ON CONFLICT (source_id) DO UPDATE SET lifecycle = EXCLUDED.lifecycle`,
      [d.source_id, d.connector_id, d.source_kind, d.canonical_locator, d.display_locator ?? '', d.owner,
        d.author ?? null, d.publisher ?? null, d.workspace_id, d.tenant_id, JSON.stringify(d.classification),
        JSON.stringify(d.license), JSON.stringify(d.retention), JSON.stringify(d.lifecycle), d.registered_at, d.registered_by],
    );
    this.events.push({ type: 'DESCRIPTOR_REGISTERED', source_id: d.source_id, at: d.registered_at });
    return d;
  }

  async getDescriptor(sourceId) {
    const row = await this.#one('SELECT * FROM source_descriptor WHERE source_id = $1', [sourceId]);
    if (!row) return null;
    return {
      ...row,
      classification: row.classification,
      license: row.license,
      retention: row.retention,
      lifecycle: row.lifecycle,
    };
  }

  async tombstoneDescriptor(sourceId, reason, at) {
    const current = await this.getDescriptor(sourceId);
    if (!current) return null;
    await this.pool.query(
      'UPDATE source_descriptor SET lifecycle = $2 WHERE source_id = $1',
      [sourceId, JSON.stringify({ state: 'tombstoned', reason, changed_at: at.toISOString ? at.toISOString() : String(at) })],
    );
    this.events.push({ type: 'DESCRIPTOR_TOMBSTONED', source_id: sourceId, reason, at: String(at) });
    return current;
  }

  // --- snapshots ---------------------------------------------------------------
  async appendSnapshot(snapshot) {
    const existing = await this.getSnapshot(snapshot.snapshot_id);
    if (existing) {
      if (existing.raw_sha256 !== snapshot.raw_sha256 || existing.normalized_sha256 !== snapshot.normalized_sha256) {
        throw new SnapshotImmutabilityError(snapshot.snapshot_id);
      }
      return existing; // identical re-append
    }
    await this.pool.query(
      `INSERT INTO source_snapshot(snapshot_id, source_id, connector_id, source_kind, version, snapshot_kind,
         tombstone_reason, canonical_url, canonical_message_id, canonical_repository_id, canonical_object_id,
         canonical_locator, canonicalization_version, raw_sha256, normalized_sha256, author, publisher,
         published_at, event_time, observed_at, fetched_at, parent_snapshot_id, supersedes_snapshot_id,
         language, mime_type, size_bytes, extraction_status, acl, license, retention, fetch_provenance)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)
       ON CONFLICT (snapshot_id) DO NOTHING`,
      [snapshot.snapshot_id, snapshot.source_id, snapshot.connector_id, snapshot.source_kind, snapshot.version,
        snapshot.snapshot_kind, snapshot.tombstone_reason, snapshot.canonical_url ?? null,
        snapshot.canonical_message_id ?? null, snapshot.canonical_repository_id ?? null,
        snapshot.canonical_object_id ?? null, snapshot.canonical_locator, snapshot.canonicalization_version,
        snapshot.raw_sha256, snapshot.normalized_sha256, snapshot.author ?? null, snapshot.publisher ?? null,
        snapshot.published_at ?? null, snapshot.event_time ?? null, snapshot.observed_at, snapshot.fetched_at,
        snapshot.parent_snapshot_id ?? null, snapshot.supersedes_snapshot_id ?? null, snapshot.language ?? null,
        snapshot.mime_type ?? null, snapshot.size_bytes, snapshot.extraction_status,
        JSON.stringify(snapshot.acl), JSON.stringify(snapshot.license), JSON.stringify(snapshot.retention),
        JSON.stringify(snapshot.fetch_provenance)],
    );
    this.events.push({
      type: snapshot.snapshot_kind === 'tombstone' ? 'SNAPSHOT_TOMBSTONED' : 'SNAPSHOT_COMMITTED',
      snapshot_id: snapshot.snapshot_id,
      source_id: snapshot.source_id,
      version: snapshot.version,
      at: String(snapshot.fetched_at),
    });
    return snapshot;
  }

  async getSnapshot(snapshotId) {
    const row = await this.#one('SELECT * FROM source_snapshot WHERE snapshot_id = $1', [snapshotId]);
    return row ?? null;
  }

  async activeSnapshot(canonicalLocator) {
    const row = await this.#one(
      'SELECT * FROM source_snapshot WHERE canonical_locator = $1 ORDER BY version DESC LIMIT 1',
      [canonicalLocator],
    );
    if (!row) return { current: null, active: null, tombstoned: false };
    if (row.snapshot_kind === 'tombstone') return { current: row, active: null, tombstoned: true };
    return { current: row, active: row, tombstoned: false };
  }

  async versionChainFor(canonicalLocator) {
    const rows = await this.pool.query(
      'SELECT snapshot_id FROM source_snapshot WHERE canonical_locator = $1 ORDER BY version ASC',
      [canonicalLocator],
    );
    return rows.rows.map((r) => r.snapshot_id);
  }

  async appendSegments(snapshotId, segments) {
    for (const segment of segments) {
      await this.pool.query(
        `INSERT INTO content_segment(segment_id, snapshot_id, source_id, ordinal, coordinates, text, text_sha256,
           original_language, normalized_language, extraction, coverage, embedded_instruction_classification, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         ON CONFLICT (segment_id) DO NOTHING`,
        [segment.segment_id, segment.snapshot_id, segment.source_id, segment.ordinal,
          JSON.stringify(segment.coordinates), segment.text ?? null, segment.text_sha256,
          segment.original_language ?? null, segment.normalized_language ?? null,
          JSON.stringify(segment.extraction), segment.coverage ? JSON.stringify(segment.coverage) : null,
          JSON.stringify(segment.embedded_instruction_classification), segment.status],
      );
    }
  }

  async segmentsFor(snapshotId) {
    const rows = await this.pool.query('SELECT * FROM content_segment WHERE snapshot_id = $1 ORDER BY ordinal ASC', [snapshotId]);
    return rows.rows;
  }

  // --- lineage -------------------------------------------------------------
  async appendLineage(lineage) {
    const existing = await this.#one('SELECT * FROM source_lineage WHERE lineage_id = $1', [lineage.lineage_id]);
    if (existing) return existing;
    await this.pool.query(
      `INSERT INTO source_lineage(lineage_id, relation, upstream_snapshot_id, downstream_snapshot_id, evidence,
         confidence, automated, status, confirmed_by, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [lineage.lineage_id, lineage.relation, lineage.upstream_snapshot_id, lineage.downstream_snapshot_id,
        JSON.stringify(lineage.evidence), lineage.confidence ?? null, lineage.automated, lineage.status,
        lineage.confirmed_by ?? null, lineage.created_at],
    );
    this.events.push({ type: 'LINEAGE_APPENDED', lineage_id: lineage.lineage_id, relation: lineage.relation, automated: lineage.automated, status: lineage.status, at: lineage.created_at });
    return lineage;
  }

  // --- idempotency ledger (server-enforced INTENT -> terminal) ---------------
  async beginOperation(workspaceId, operationId, requestDigest) {
    const inserted = await this.pool.query(
      `INSERT INTO ingestion_operation(workspace_id, operation_id, request_hash)
       VALUES ($1,$2,$3)
       ON CONFLICT (workspace_id, operation_id) DO NOTHING
       RETURNING status, outcome`,
      [workspaceId, operationId, requestDigest],
    );
    if (inserted.rows.length > 0) {
      // The INTENT row and its audit event are canonical, not memory-only.
      await this.pool.query(
        'INSERT INTO ingestion_event(operation_id, workspace_id, event_type, payload) VALUES ($1, $2, $3, $4)',
        [operationId, workspaceId, 'OPERATION_INTENT', JSON.stringify({ request_hash: requestDigest })],
      );
      this.events.push({ type: 'OPERATION_INTENT', operation_id: operationId, workspace_id: workspaceId });
      return { replay: false, record: { workspace_id: workspaceId, operation_id: operationId, request_digest: requestDigest, status: 'INTENT', outcome: null } };
    }
    const existing = await this.#one(
      'SELECT request_hash, status, outcome FROM ingestion_operation WHERE workspace_id = $1 AND operation_id = $2',
      [workspaceId, operationId],
    );
    if (existing.request_hash !== requestDigest) {
      throw new DuplicateOperationError(`operation ${operationId} reused with a different request payload`);
    }
    return { replay: true, record: { workspace_id: workspaceId, operation_id: operationId, request_digest: requestDigest, status: existing.status, outcome: existing.outcome } };
  }

  async completeOperation(workspaceId, operationId, outcome) {
    const updated = await this.pool.query(
      `UPDATE ingestion_operation SET status = $3, outcome = $4
       WHERE workspace_id = $1 AND operation_id = $2 AND status = 'INTENT'`,
      [workspaceId, operationId, outcome.terminal, JSON.stringify(outcome)],
    );
    if (updated.rowCount > 0) {
      this.events.push({ type: 'OPERATION_COMPLETED', operation_id: operationId, terminal: outcome.terminal });
      return { workspace_id: workspaceId, operation_id: operationId, status: outcome.terminal, outcome };
    }
    const existing = await this.#one(
      'SELECT status, outcome FROM ingestion_operation WHERE workspace_id = $1 AND operation_id = $2',
      [workspaceId, operationId],
    );
    if (existing && JSON.stringify(existing.outcome) === JSON.stringify(outcome)) {
      return { workspace_id: workspaceId, operation_id: operationId, status: existing.status, outcome: existing.outcome };
    }
    throw new DuplicateOperationError(`operation ${operationId} already completed with a different outcome`);
  }

  async getOperation(workspaceId, operationId) {
    const row = await this.#one(
      'SELECT workspace_id, operation_id, status, outcome FROM ingestion_operation WHERE workspace_id = $1 AND operation_id = $2',
      [workspaceId, operationId],
    );
    return row ?? null;
  }

  // --- runs ---------------------------------------------------------------
  async appendRun(run) {
    await this.pool.query(
      `INSERT INTO ingestion_run(run_id, executor_id, pid, nonce, output_root, frozen_inputs, environment, counts, started_at, finished_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [run.run_id, run.executor_id, run.pid ?? null, run.nonce, run.output_root,
        JSON.stringify(run.frozen_inputs), JSON.stringify(run.environment), JSON.stringify(run.counts),
        run.started_at ?? null, run.finished_at ?? null],
    );
    return run;
  }

  async allSnapshots() {
    const rows = await this.pool.query('SELECT * FROM source_snapshot');
    return rows.rows;
  }

  // Atomic commit: BEGIN; guarded ledger transition; snapshot; segments;
  // lineage; descriptor tombstone; ingestion_event rows; COMMIT. Any failure
  // rolls the whole block back and rethrows, leaving the INTENT row in place
  // for reconciliation — a partial commit is impossible.
  async commitIngest({ workspaceId, operationId, outcome, snapshot = null, segments = [], lineage = null, descriptorTombstone = null, events = [] }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const updated = await client.query(
        `UPDATE ingestion_operation SET status = $3, outcome = $4, completed_at = now()
         WHERE workspace_id = $1 AND operation_id = $2 AND status = 'INTENT'`,
        [workspaceId, operationId, outcome.terminal, JSON.stringify(outcome)],
      );
      if (updated.rowCount === 0) {
        const existing = await client.query(
          'SELECT status, outcome FROM ingestion_operation WHERE workspace_id = $1 AND operation_id = $2',
          [workspaceId, operationId],
        );
        const row = existing.rows[0];
        if (row && JSON.stringify(row.outcome) === JSON.stringify(outcome)) {
          await client.query('COMMIT');
          return { appendResult: null, record: { ...row, idempotent: true } };
        }
        throw new DuplicateOperationError(`operation ${operationId} is not in INTENT state`);
      }
      if (snapshot) {
        await client.query(
          `INSERT INTO source_snapshot(snapshot_id, source_id, connector_id, source_kind, version, snapshot_kind,
             tombstone_reason, canonical_url, canonical_message_id, canonical_repository_id, canonical_object_id,
             canonical_locator, canonicalization_version, raw_sha256, normalized_sha256, author, publisher,
             published_at, event_time, observed_at, fetched_at, parent_snapshot_id, supersedes_snapshot_id,
             language, mime_type, size_bytes, extraction_status, acl, license, retention, fetch_provenance)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)
           ON CONFLICT (snapshot_id) DO NOTHING`,
          [snapshot.snapshot_id, snapshot.source_id, snapshot.connector_id, snapshot.source_kind, snapshot.version,
            snapshot.snapshot_kind, snapshot.tombstone_reason ?? null, snapshot.canonical_url ?? null,
            snapshot.canonical_message_id ?? null, snapshot.canonical_repository_id ?? null,
            snapshot.canonical_object_id ?? null, snapshot.canonical_locator, snapshot.canonicalization_version,
            snapshot.raw_sha256, snapshot.normalized_sha256, snapshot.author ?? null, snapshot.publisher ?? null,
            snapshot.published_at ?? null, snapshot.event_time ?? null, snapshot.observed_at, snapshot.fetched_at,
            snapshot.parent_snapshot_id ?? null, snapshot.supersedes_snapshot_id ?? null, snapshot.language ?? null,
            snapshot.mime_type ?? null, snapshot.size_bytes, snapshot.extraction_status,
            JSON.stringify(snapshot.acl), JSON.stringify(snapshot.license), JSON.stringify(snapshot.retention),
            JSON.stringify(snapshot.fetch_provenance)],
        );
        await this.#insertEvent(client, {
          type: snapshot.snapshot_kind === 'tombstone' ? 'SNAPSHOT_TOMBSTONED' : 'SNAPSHOT_COMMITTED',
          operation_id: operationId,
          workspace_id: workspaceId,
          payload: { snapshot_id: snapshot.snapshot_id, source_id: snapshot.source_id, version: snapshot.version },
        });
      }
      for (const segment of segments) {
        await client.query(
          `INSERT INTO content_segment(segment_id, snapshot_id, source_id, ordinal, coordinates, text, text_sha256,
             original_language, normalized_language, extraction, coverage, embedded_instruction_classification, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
           ON CONFLICT (segment_id) DO NOTHING`,
          [segment.segment_id, segment.snapshot_id, segment.source_id, segment.ordinal,
            JSON.stringify(segment.coordinates), segment.text ?? null, segment.text_sha256,
            segment.original_language ?? null, segment.normalized_language ?? null,
            JSON.stringify(segment.extraction), segment.coverage ? JSON.stringify(segment.coverage) : null,
            JSON.stringify(segment.embedded_instruction_classification), segment.status],
        );
      }
      if (lineage) {
        await client.query(
          `INSERT INTO source_lineage(lineage_id, relation, upstream_snapshot_id, downstream_snapshot_id, evidence,
             confidence, automated, status, confirmed_by, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [lineage.lineage_id, lineage.relation, lineage.upstream_snapshot_id, lineage.downstream_snapshot_id,
            JSON.stringify(lineage.evidence), lineage.confidence ?? null, lineage.automated, lineage.status,
            lineage.confirmed_by ?? null, lineage.created_at],
        );
        await this.#insertEvent(client, {
          type: 'LINEAGE_APPENDED',
          operation_id: operationId,
          workspace_id: workspaceId,
          payload: { lineage_id: lineage.lineage_id, relation: lineage.relation, automated: lineage.automated, status: lineage.status },
        });
      }
      if (descriptorTombstone) {
        await client.query(
          'UPDATE source_descriptor SET lifecycle = $2 WHERE source_id = $1',
          [descriptorTombstone.source_id, JSON.stringify({ state: 'tombstoned', reason: descriptorTombstone.reason, changed_at: String(descriptorTombstone.at) })],
        );
        await this.#insertEvent(client, {
          type: 'DESCRIPTOR_TOMBSTONED',
          operation_id: operationId,
          workspace_id: workspaceId,
          payload: { source_id: descriptorTombstone.source_id, reason: descriptorTombstone.reason },
        });
      }
      await this.#insertEvent(client, {
        type: 'OPERATION_COMPLETED',
        operation_id: operationId,
        workspace_id: workspaceId,
        payload: { terminal: outcome.terminal },
      });
      await client.query('COMMIT');
      for (const event of events) this.events.push(event);
      this.events.push({ type: 'OPERATION_COMPLETED', operation_id: operationId, terminal: outcome.terminal });
      return { appendResult: snapshot, record: { workspace_id: workspaceId, operation_id: operationId, status: outcome.terminal, outcome } };
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch { /* connection already broken */ }
      throw error;
    } finally {
      client.release();
    }
  }

  async #insertEvent(client, { type, operation_id, workspace_id, payload }) {
    await client.query(
      'INSERT INTO ingestion_event(run_id, operation_id, workspace_id, event_type, payload) VALUES (NULL, $1, $2, $3, $4)',
      [operation_id, workspace_id, type, JSON.stringify(payload ?? null)],
    );
  }

  // --- integrity summary: computed by PostgreSQL -----------------------------
  async integritySummary({ outcomes = [], privateLeakCounter = 0, authorityExpansionCounter = 0 } = {}) {
    const stats = await this.#one(`SELECT
      (SELECT count(*)::int FROM source_snapshot WHERE snapshot_kind = 'content') AS content_snapshots,
      (SELECT count(*)::int FROM source_snapshot) AS snapshots_total,
      (SELECT count(*)::int FROM ingestion_operation WHERE status = 'COMMITTED') AS committed_operations,
      (SELECT count(*)::int FROM ingestion_operation WHERE status = 'INTENT') AS stuck_intent,
      (SELECT count(*)::int FROM content_segment WHERE embedded_instruction_classification->>'present' = 'true') AS flagged_segments`);
    const provenance = await this.#one(`SELECT count(*)::int AS complete FROM source_snapshot
      WHERE snapshot_kind = 'content'
        AND fetch_provenance->>'operation_id' IS NOT NULL
        AND fetch_provenance->>'connector_id' IS NOT NULL
        AND fetch_provenance->>'connector_version' IS NOT NULL
        AND fetch_provenance->>'fetched_from' IS NOT NULL
        AND fetch_provenance->>'fetched_at' IS NOT NULL
        AND acl->>'visibility' IS NOT NULL AND license->>'spdx' IS NOT NULL AND retention->>'policy' IS NOT NULL`);
    // duplicate committed snapshots: equal (canonical_locator, version) rows
    // cannot exist (UNIQUE constraint), so the counter is structurally zero;
    // the live query proves it from the actual table data.
    const duplicates = await this.#one(`SELECT count(*)::int AS dup FROM (
      SELECT snapshot_id FROM source_snapshot GROUP BY snapshot_id HAVING count(*) > 1) d`);
    let authorityDrift = authorityExpansionCounter;
    const descriptors = await this.pool.query('SELECT lifecycle, classification FROM source_descriptor');
    for (const row of descriptors.rows) {
      if (row.lifecycle?.state === 'tombstoned') continue;
      if (!row.classification?.visibility) authorityDrift += 1;
    }
    return {
      snapshots_total: stats.snapshots_total,
      provenance_complete_pct: stats.content_snapshots === 0 ? 0 : Math.round((provenance.complete / stats.content_snapshots) * 100),
      committed_operations: stats.committed_operations,
      operations_stuck_intent: stats.stuck_intent,
      duplicate_committed_snapshots: duplicates.dup,
      committed_without_snapshot: outcomes.filter((o) => o.terminal === 'COMMITTED' && !o.snapshot_id).length,
      private_exports_leaked: privateLeakCounter,
      authority_expansions: authorityDrift,
      instruction_flagged_segments: stats.flagged_segments,
    };
  }
}
