// S2-004 PostgreSQL-backed claim graph store.
// Implements the operation surface the corpus run and the DB replay need with
// the SAME fail-closed semantics as the memory store: schema-validated,
// digest-bound, atomic (single transaction per operation) and idempotent via
// the operation ledger. Immutable rows in claims/evidence_edges/claim_edges;
// lifecycle is projected through claim_state (migration 0004).
import {
  claimValidators,
  canonicalDigestOfClaim,
  claimContentDigest,
  deterministicClaimId,
  deterministicId,
  sha256Hex,
  spanDigest,
  VeritasError,
} from './validation.mjs';

export class PostgresClaimGraphStore {
  constructor(pool, { authorities, clock, segmentResolver, snapshotResolver } = {}) {
    this.pool = pool;
    this.validators = claimValidators();
    this.authorities = authorities;
    this.clock = clock ?? (() => new Date().toISOString().replace(/\.\d+Z$/, '.000Z'));
    this.segmentResolver = segmentResolver;
    this.snapshotResolver = snapshotResolver;
  }

  // The corpus attaches the case's immutable segments/snapshots before its
  // extraction so span/digest binding can be verified inside the transaction.
  attachSegments(segments, snapshots) {
    const segmentMap = new Map(segments.map((s) => [`${s.segment_id}@${s.revision ?? 1}`, s]));
    const snapshotMap = new Map(snapshots.map((s) => [s.snapshot_id, s]));
    this.segmentResolver = (id, rev) => segmentMap.get(`${id}@${rev ?? 1}`) ?? null;
    this.snapshotResolver = (id) => snapshotMap.get(id) ?? null;
  }

  can(principal, role, workspaceId) {
    const entry = this.authorities?.get(principal);
    if (!entry || !entry.roles.has(role)) return false;
    if (workspaceId === undefined) return true;
    return entry.workspaces.has(workspaceId);
  }

  async #one(client, sql, params = []) {
    const res = await client.query(sql, params);
    return res.rows[0] ?? null;
  }

  async beginOperation(client, { workspaceId, operationId, actor, idempotencyKey, input }) {
    const inputDigest = sha256Hex(input ?? null);
    const existing = await this.#one(
      client,
      'SELECT status, actor, input_digest FROM claim_operation_ledger WHERE workspace_id = $1 AND operation_id = $2',
      [workspaceId, operationId],
    );
    if (existing) {
      if (existing.actor === actor && existing.input_digest === inputDigest) {
        return { replay: true };
      }
      throw new VeritasError('IDEMPOTENCY_CONFLICT', `operation ${operationId} already exists with a different actor/input digest`);
    }
    void idempotencyKey;
    return { replay: false, inputDigest };
  }

  // ---- reads ----------------------------------------------------------------

  async getClaim(claimId, revision) {
    const row = await this.#one(
      this.pool,
      revision
        ? 'SELECT * FROM claims WHERE claim_id = $1 AND revision = $2'
        : 'SELECT * FROM claims WHERE claim_id = $1 ORDER BY revision DESC LIMIT 1',
      revision ? [claimId, revision] : [claimId],
    );
    if (!row) return null;
    const claim = this.#rowToClaim(row);
    // projected lifecycle overrides the record's original value
    const state = await this.#one(this.pool, 'SELECT revision, lifecycle FROM claim_state WHERE claim_id = $1', [claimId]);
    if (state && state.revision === claim.revision) claim.lifecycle = state.lifecycle;
    return claim;
  }

  async listClaimHistory(claimId) {
    const res = await this.pool.query('SELECT * FROM claims WHERE claim_id = $1 ORDER BY revision ASC', [claimId]);
    return res.rows.map((row) => this.#rowToClaim(row));
  }

  async listEvidenceMap(claimId, revision) {
    let target = revision;
    if (!target) {
      const row = await this.#one(this.pool, 'SELECT MAX(revision) AS r FROM claims WHERE claim_id = $1', [claimId]);
      target = row?.r;
    }
    if (!target) return [];
    const res = await this.pool.query(
      'SELECT * FROM evidence_edges WHERE claim_id = $1 AND claim_revision = $2 ORDER BY edge_id',
      [claimId, target],
    );
    return res.rows.map((row) => this.#evidenceRowToEdge(row));
  }

  async listClaimEdges(claimId) {
    const res = await this.pool.query(
      'SELECT * FROM claim_edges WHERE source_claim_id = $1 OR target_claim_id = $1 ORDER BY edge_id',
      [claimId],
    );
    return res.rows;
  }

  async listOutbox() {
    const res = await this.pool.query('SELECT * FROM claim_audit_outbox ORDER BY created_at ASC, event_id ASC');
    return res.rows;
  }

  #rowToClaim(row) {
    return {
      contractVersion: row.contract_version,
      claim_id: row.claim_id,
      revision: row.revision,
      workspace_id: row.workspace_id,
      tenant_id: row.tenant_id,
      acl: {
        visibility: row.acl_visibility,
        workspace_id: row.acl_workspace_id,
        tenant_id: row.acl_tenant_id,
        allowed_workspace_ids: row.acl_allowed_workspaces ?? [],
        allowed_principal_ids: row.acl_allowed_principals ?? [],
      },
      epistemic_type: row.epistemic_type,
      polarity: row.polarity,
      modality: row.modality,
      normalized_text: row.normalized_text,
      original_text: row.original_text,
      subject: row.subject,
      predicate: row.predicate,
      object: row.object,
      qualifiers: row.qualifiers ?? [],
      assumptions: row.assumptions ?? [],
      exclusions: row.exclusions ?? [],
      units: row.units,
      denominator: row.denominator,
      value_range: row.value_min === null && row.value_max === null ? null : { min: Number(row.value_min), max: Number(row.value_max) },
      population: row.population,
      geography: row.geography,
      period: row.period_start === undefined ? row.period_start : (row.period_start || row.period_end ? { start: row.period_start, end: row.period_end } : null),
      event_time: row.event_time,
      published_at: row.published_at,
      observed_at: row.observed_at,
      fetched_at: row.fetched_at,
      language: row.language,
      translation_status: row.translation_status,
      canonical_digest: row.canonical_digest,
      lifecycle: row.lifecycle,
      supersedes_claim_id: row.supersedes_claim_id,
      supersedes_revision: row.supersedes_revision,
      created_at: row.created_at,
      created_by: row.created_by,
    };
  }

  #evidenceRowToEdge(row) {
    return {
      contractVersion: row.contract_version,
      edge_id: row.edge_id,
      claim_id: row.claim_id,
      claim_revision: row.claim_revision,
      segment_id: row.segment_id,
      segment_revision: row.segment_revision,
      relation: row.relation,
      span: { start: row.span_start, end: row.span_end },
      quote_digest: row.quote_digest,
      entailment_status: row.entailment_status,
      method: { name: row.method_name, version: row.method_version, config_digest: row.method_config_digest },
      reviewer: row.reviewer,
      source_family_id: row.source_family_id,
      upstream_snapshot_ids: row.upstream_snapshot_ids ?? [],
      access_state: row.access_state,
      retention_state: row.retention_state,
      created_at: row.created_at,
      created_by: row.created_by,
    };
  }

  // ---- writes ----------------------------------------------------------------

  async #putClaim(client, claim) {
    await client.query(
      `INSERT INTO claims (
        claim_id, revision, workspace_id, tenant_id,
        acl_visibility, acl_workspace_id, acl_tenant_id, acl_allowed_workspaces, acl_allowed_principals,
        epistemic_type, polarity, modality, normalized_text, original_text,
        subject, predicate, object, qualifiers, assumptions, exclusions,
        units, denominator, value_min, value_max, population, geography, period_start, period_end,
        event_time, published_at, observed_at, fetched_at,
        language, translation_status, canonical_digest, lifecycle,
        supersedes_claim_id, supersedes_revision, created_at, created_by
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
        $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40
      ) ON CONFLICT (claim_id, revision) DO NOTHING`,
      [
        claim.claim_id, claim.revision, claim.workspace_id, claim.tenant_id,
        claim.acl.visibility, claim.acl.workspace_id, claim.acl.tenant_id,
        claim.acl.allowed_workspace_ids ?? [], claim.acl.allowed_principal_ids ?? [],
        claim.epistemic_type, claim.polarity, claim.modality ?? null,
        claim.normalized_text, claim.original_text,
        claim.subject, claim.predicate, claim.object,
        claim.qualifiers ?? [], claim.assumptions ?? [], claim.exclusions ?? [],
        claim.units ?? null, claim.denominator ?? null,
        claim.value_range?.min ?? null, claim.value_range?.max ?? null,
        claim.population ?? null, claim.geography ?? null,
        claim.period?.start ?? null, claim.period?.end ?? null,
        claim.event_time ?? null, claim.published_at ?? null,
        claim.observed_at ?? null, claim.fetched_at ?? null,
        claim.language, claim.translation_status, claim.canonical_digest,
        claim.lifecycle, claim.supersedes_claim_id ?? null, claim.supersedes_revision ?? null,
        claim.created_at, claim.created_by,
      ],
    );
    // immutability: if the row pre-existed it must be byte-identical content
    const existing = await this.#one(client, 'SELECT canonical_digest FROM claims WHERE claim_id = $1 AND revision = $2', [claim.claim_id, claim.revision]);
    if (existing && existing.canonical_digest !== claim.canonical_digest) {
      throw new VeritasError('CLAIM_REVISION_CONFLICT', `claim ${claim.claim_id}@${claim.revision} exists with different content`);
    }
  }

  async #upsertClaimState(client, claim) {
    await client.query(
      `INSERT INTO claim_state (claim_id, revision, lifecycle, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (claim_id) DO UPDATE SET
         revision = EXCLUDED.revision,
         lifecycle = EXCLUDED.lifecycle,
         updated_at = EXCLUDED.updated_at
       WHERE EXCLUDED.revision >= claim_state.revision`,
      [claim.claim_id, claim.revision, claim.lifecycle, this.clock()],
    );
  }

  async #putEvidenceEdge(client, edge) {
    await client.query(
      `INSERT INTO evidence_edges (
        edge_id, claim_id, claim_revision, segment_id, segment_revision, relation,
        span_start, span_end, quote_digest, entailment_status,
        method_name, method_version, method_config_digest, reviewer,
        source_family_id, upstream_snapshot_ids, access_state, retention_state,
        created_at, created_by
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
      ON CONFLICT (edge_id) DO NOTHING`,
      [
        edge.edge_id, edge.claim_id, edge.claim_revision, edge.segment_id, edge.segment_revision, edge.relation,
        edge.span.start, edge.span.end, edge.quote_digest, edge.entailment_status,
        edge.method.name, edge.method.version, edge.method.config_digest ?? null, edge.reviewer ?? null,
        edge.source_family_id, edge.upstream_snapshot_ids, edge.access_state, edge.retention_state,
        edge.created_at, edge.created_by,
      ],
    );
  }

  async #putOutbox(client, { eventId, type, operationId, actor, payload }) {
    await client.query(
      'INSERT INTO claim_audit_outbox (event_id, event_type, operation_id, actor, payload_digest) VALUES ($1,$2,$3,$4,$5)',
      [eventId, type, operationId, actor, sha256Hex(payload)],
    );
  }

  // Atomic extraction commit: claims + edges + state + audit in one transaction.
  async commitExtraction({ request, result, actor, operationId, idempotencyKey }) {
    if (!this.can(actor, 'extractor', request.workspace_id) && !this.can(actor, 'producer', request.workspace_id)) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} has no extractor capability in workspace ${request.workspace_id}`);
    }
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const begun = await this.beginOperation(client, { workspaceId: request.workspace_id, operationId, actor, idempotencyKey, input: { request, result } });
      if (begun.replay) {
        await client.query('ROLLBACK');
        const claims = [];
        for (const proposed of result.proposed_claims) {
          const claim = await this.getClaim(proposed.claim.claim_id ?? null);
          if (claim) claims.push(claim);
        }
        return { claims, edges: [], result, replayed: true };
      }
      const now = this.clock();
      const claims = [];
      const edges = [];
      for (const proposed of result.proposed_claims) {
        const segment = this.segmentResolver?.(proposed.source_span.segment_id, proposed.segment_revision ?? 1) ?? null;
        if (!segment) throw new VeritasError('SEGMENT_NOT_FOUND', `segment ${proposed.source_span.segment_id} not found`);
        if (segment.text === null || segment.text === undefined) throw new VeritasError('SPAN_UNBINDABLE', 'segment has no text');
        const exactSpanDigest = spanDigest(segment.text, proposed.source_span.start, proposed.source_span.end);
        if (exactSpanDigest !== proposed.evidence_digest) {
          throw new VeritasError('SPAN_DIGEST_MISMATCH', 'evidence digest does not match the segment span');
        }
        const record = {
          qualifiers: [], assumptions: [], exclusions: [],
          supersedes_claim_id: null, supersedes_revision: null,
          ...proposed.claim,
          lifecycle: proposed.claim.lifecycle ?? proposed.lifecycle ?? 'PROPOSED',
          created_at: now,
          created_by: actor,
        };
        if (!record.claim_id) {
          record.claim_id = deterministicClaimId({ workspaceId: request.workspace_id, contentDigest: claimContentDigest(record) });
        }
        if (!record.revision) record.revision = 1;
        if (!record.canonical_digest) record.canonical_digest = canonicalDigestOfClaim(record);
        this.validators.requireValid('claim', record);
        if (record.canonical_digest !== canonicalDigestOfClaim(record)) {
          throw new VeritasError('DIGEST_MISMATCH', `canonical_digest mismatch for ${record.claim_id}`);
        }
        await this.#putClaim(client, record);
        await this.#upsertClaimState(client, record);
        claims.push(record);

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
            config_digest: sha256Hex({ prompt_version: request.prompt_version, parameters: request.parameters }),
          },
          reviewer: null,
          source_family_id: `fam-${sha256Hex(segment.source_id ?? segment.segment_id).slice(0, 16)}`,
          upstream_snapshot_ids: [segment.snapshot_id],
          access_state: 'available',
          retention_state: 'active',
          created_at: now,
          created_by: actor,
        };
        this.validators.requireValid('evidence-edge', edge);
        await this.#putEvidenceEdge(client, edge);
        edges.push(edge);
      }
      const auditId = deterministicId('aud', operationId, 'CLAIM_EXTRACTION_COMMITTED');
      await this.#putOutbox(client, { eventId: auditId, type: 'CLAIM_EXTRACTION_COMMITTED', operationId, actor, payload: { request_id: request.request_id, claims: claims.length, status: result.status } });
      await client.query(
        `INSERT INTO claim_operation_ledger (workspace_id, operation_id, idempotency_key, actor, input_digest, status, outcome_digest)
         VALUES ($1,$2,$3,$4,$5,'COMMITTED',$6)
         ON CONFLICT (workspace_id, operation_id) DO NOTHING`,
        [request.workspace_id, operationId, idempotencyKey ?? null, actor, begun.inputDigest, sha256Hex({ claims: claims.length, status: result.status })],
      );
      await client.query('COMMIT');
      return { claims, edges, result, replayed: false };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  // Transitive invalidation over evidence edges and DEPENDS_ON/TRANSLATES
  // edges, computed from PostgreSQL rows and committed atomically.
  async invalidateFromParent({ trigger, reason, actor, operationId }) {
    if (actor !== 'prn-system' && !this.can(actor, 'admin', 'ws-system') && !this.can(actor, 'system', 'ws-system')) {
      throw new VeritasError('AUTHORITY_DENIED', `actor ${actor} cannot trigger graph invalidation`);
    }
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const visited = new Set();
      const edgesTraversed = [];
      const affected = [];
      const queue = [];
      if (trigger.type.startsWith('source_snapshot') || trigger.type.startsWith('content_segment') || trigger.type === 'retention_expiry' || trigger.type === 'access_restriction') {
        const res = await client.query('SELECT * FROM evidence_edges WHERE segment_id = $1', [trigger.id]);
        for (const edge of res.rows) {
          queue.push({ kind: 'claim', id: edge.claim_id, revision: edge.claim_revision, via: edge.edge_id });
          edgesTraversed.push(edge.edge_id);
        }
      } else if (trigger.type.startsWith('claim')) {
        queue.push({ kind: 'claim', id: trigger.id, revision: trigger.revision, via: 'trigger' });
      }
      while (queue.length) {
        const node = queue.shift();
        const key = `${node.id}@${node.revision}`;
        if (visited.has(key)) continue;
        visited.add(key);
        const claimRow = await this.#one(client, 'SELECT * FROM claims WHERE claim_id = $1 AND revision = $2', [node.id, node.revision]);
        if (!claimRow) continue;
        if (!affected.some((a) => a.entity_id === node.id && a.entity_revision === node.revision)) {
          affected.push({ entity_type: 'claim', entity_id: node.id, entity_revision: node.revision, new_lifecycle: 'STALE' });
        }
        await client.query(
          `INSERT INTO claim_state (claim_id, revision, lifecycle, stale_reasons, updated_at)
           VALUES ($1, $2, 'STALE', $3, $4)
           ON CONFLICT (claim_id) DO UPDATE SET lifecycle = 'STALE', stale_reasons = claim_state.stale_reasons || $3, updated_at = $4
           WHERE claim_state.revision <= $2`,
          [node.id, node.revision, JSON.stringify([{ reason: reason.code, trigger: trigger.id, via: node.via }]), this.clock()],
        );
        const depRes = await client.query(
          `SELECT * FROM claim_edges WHERE relation IN ('DEPENDS_ON','TRANSLATES')
           AND ((relation = 'DEPENDS_ON' AND target_claim_id = $1 AND target_revision = $2)
             OR (relation = 'TRANSLATES' AND source_claim_id = $1 AND source_revision = $2))`,
          [node.id, node.revision],
        );
        for (const edge of depRes.rows) {
          edgesTraversed.push(edge.edge_id);
          queue.push(edge.relation === 'TRANSLATES'
            ? { kind: 'claim', id: edge.target_claim_id, revision: edge.target_revision, via: edge.edge_id }
            : { kind: 'claim', id: edge.source_claim_id, revision: edge.source_revision, via: edge.edge_id });
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
        created_at: this.clock(),
        created_by: actor,
      };
      this.validators.requireValid('graph-invalidation-event', event);
      await client.query(
        `INSERT INTO graph_invalidation_events (
          event_id, trigger_type, trigger_id, trigger_revision, affected_descendants,
          reason_code, reason_description, traversal_method, traversal_visited, traversal_edges,
          completion_state, failed_descendants, created_at, created_by
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,'bfs',$8,$9,'COMPLETED','{}',$10,$11)`,
        [
          event.event_id, event.trigger_type, event.trigger_id, event.trigger_revision,
          JSON.stringify(event.affected_descendants), reason.code, reason.description,
          visited.size, edgesTraversed, event.created_at, actor,
        ],
      );
      await this.#putOutbox(client, { eventId: deterministicId('aud', operationId, 'GRAPH_INVALIDATED'), type: 'GRAPH_INVALIDATED', operationId, actor, payload: { event_id: event.event_id, affected: affected.length } });
      await client.query(
        `INSERT INTO claim_operation_ledger (workspace_id, operation_id, actor, input_digest, status)
         VALUES ('ws-system', $1, $2, $3, 'COMMITTED') ON CONFLICT (workspace_id, operation_id) DO NOTHING`,
        [operationId, actor, sha256Hex({ trigger, reason })],
      );
      await client.query('COMMIT');
      return { event, operation_id: operationId };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async reconcileOperation(workspaceId, operationId) {
    const row = await this.#one(this.pool, 'SELECT status FROM claim_operation_ledger WHERE workspace_id = $1 AND operation_id = $2', [workspaceId, operationId]);
    if (row?.status === 'COMMITTED') return { status: 'COMMITTED', replayed: true };
    return { status: 'RECONCILIATION_REQUIRED', replayed: false };
  }
}
