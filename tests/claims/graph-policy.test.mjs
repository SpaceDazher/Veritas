// S2-004 invalidation, expert lens and calibration tests (todo §5, §8):
// transitive STALE propagation, audit preservation, lens isolation and
// revocation, evaluator-independence of calibration records.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CLOCK, PRINCIPALS, makeClaim, makeDecision, makeSegment, makeSnapshot, makeStore,
  nextIdem, nextOp, sha256, testAuthorities,
} from './helpers.mjs';
import { applyExpertLenses, lensesPreservedCandidates } from '../../src/lib/claims/lens.mjs';
import { collapseSourceFamilies, proposeDuplicateCandidates } from '../../src/lib/claims/provenance.mjs';

describe('S2-004 invalidation', () => {
  function buildGraph() {
    const text = 'Wind and solar generated 22% of EU electricity in 2024.';
    const segment = makeSegment(text, { segment_id: 'seg-root', snapshot_id: 'snp-root' });
    const store = makeStore({ segments: [segment], snapshots: [makeSnapshot({ snapshot_id: 'snp-root' })] });
    const outcome = store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() });
    const claim = outcome.claims[0];
    store.linkEvidence({
      edge: {
        contractVersion: '1.0.0', edge_id: 'eed-root', claim_id: claim.claim_id, claim_revision: 1,
        segment_id: segment.segment_id, segment_revision: 1, relation: 'SUPPORTS',
        span: { start: 0, end: 20 }, quote_digest: sha256(text.slice(0, 20)),
        entailment_status: 'ENTAILED', method: { name: 'manual', version: '1.0.0' }, reviewer: null,
        source_family_id: 'fam-root', upstream_snapshot_ids: ['snp-root'],
        access_state: 'available', retention_state: 'active',
      },
      actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
    });
    // a dependent claim: depends_on the root claim
    const dependent = store.proposeClaims({
      claims: [makeClaim({ normalized_text: 'EU renewable share depends on the 22% baseline.', original_text: 'EU renewable share depends on the 22% baseline.', subject: 'EU renewable share' })],
      actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
    }).claims[0];
    store.linkClaims({
      edge: {
        contractVersion: '1.0.0', edge_id: 'ced-dep', source_claim_id: dependent.claim_id, source_revision: 1,
        target_claim_id: claim.claim_id, target_revision: 1, relation: 'DEPENDS_ON', direction: 'forward',
        scope_intersection: { population_overlap: true, geography_overlap: true, period_overlap: true, units_compatible: true },
        provenance: { method: 'manual', extractor: 'annotator', extractor_version: '1.0.0' },
        creation_authority: PRINCIPALS.producer,
      },
      actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
    });
    return { store, segment, claim, dependent };
  }

  test('segment tombstone transitively marks the claim and its dependents STALE', () => {
    const { store, segment, claim, dependent } = buildGraph();
    const outcome = store.invalidateFromParent({
      trigger: { type: 'content_segment_tombstone', id: segment.segment_id, revision: 1 },
      reason: { code: 'upstream_tombstoned', description: 'source deleted the page' },
      actor: PRINCIPALS.system,
      operationId: nextOp(),
    });
    assert.equal(outcome.event.completion_state, 'COMPLETED');
    const affected = outcome.event.affected_descendants.map((d) => d.entity_id);
    assert.ok(affected.includes(claim.claim_id), 'root claim stale');
    assert.ok(affected.includes(dependent.claim_id), 'dependent stale');
    assert.equal(store.getClaim(claim.claim_id).lifecycle, 'STALE');
    assert.equal(store.getClaim(dependent.claim_id).lifecycle, 'STALE');
    // traversal evidence recorded
    assert.ok(outcome.event.traversal_evidence.visited_count >= 2);
  });

  test('invalidation is authority-gated', () => {
    const { store, segment } = buildGraph();
    assert.throws(
      () => store.invalidateFromParent({
        trigger: { type: 'content_segment_tombstone', id: segment.segment_id, revision: 1 },
        reason: { code: 'upstream_tombstoned', description: 'x' },
        actor: PRINCIPALS.producer,
        operationId: nextOp(),
      }),
      (e) => e.code === 'AUTHORITY_DENIED',
    );
  });

  test('the audit trail survives invalidation and claims stay queryable', () => {
    const { store, segment, claim } = buildGraph();
    const before = store.listOutbox().length;
    store.invalidateFromParent({
      trigger: { type: 'content_segment_tombstone', id: segment.segment_id, revision: 1 },
      reason: { code: 'upstream_tombstoned', description: 'source deleted the page' },
      actor: PRINCIPALS.system,
      operationId: nextOp(),
    });
    // history + evidence still queryable: deletion hides payload, never lineage
    assert.equal(store.listClaimHistory(claim.claim_id).length, 1);
    assert.equal(store.listEvidenceMap(claim.claim_id).length, 1);
    assert.ok(store.listOutbox().length > before);
    assert.ok(store.getInvalidationEvents(segment.segment_id).length === 1);
  });

  test('re-review after invalidation restores acceptance with a fresh decision', () => {
    const { store, segment, claim } = buildGraph();
    store.invalidateFromParent({
      trigger: { type: 'content_segment_tombstone', id: segment.segment_id, revision: 1 },
      reason: { code: 'upstream_tombstoned', description: 'source deleted the page' },
      actor: PRINCIPALS.system,
      operationId: nextOp(),
    });
    assert.equal(store.getClaim(claim.claim_id).lifecycle, 'STALE');
    // the source is corrected: the claim is re-verified by a reviewer
    const reviewed = store.reviewClaim({ decision: makeDecision(store.getClaim(claim.claim_id), PRINCIPALS.reviewer, 'ACCEPT_BOUNDED') });
    assert.equal(reviewed.lifecycle, 'ACCEPTED_BOUNDED');
  });

  test('claim correction triggers STALE on dependents via SUPERSEDES-linked lineage', () => {
    const { store, claim, dependent } = buildGraph();
    store.reviseClaim({
      claimId: claim.claim_id, baseRevision: 1,
      patch: { normalized_text: 'Wind and solar generated 25% of EU electricity in 2024.', value_range: { min: 25, max: 25 } },
      actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
    });
    // old revision is superseded
    assert.equal(store.getClaim(claim.claim_id, 1).lifecycle, 'SUPERSEDED');
    assert.equal(store.getClaim(claim.claim_id, 2).lifecycle, 'PROPOSED');
    // dependent still points at revision 1; invalidating the old revision stales it
    const outcome = store.invalidateFromParent({
      trigger: { type: 'claim_correction', id: claim.claim_id, revision: 1 },
      reason: { code: 'upstream_corrected', description: 'baseline figure corrected' },
      actor: PRINCIPALS.system,
      operationId: nextOp(),
    });
    assert.ok(outcome.event.affected_descendants.some((d) => d.entity_id === dependent.claim_id));
    assert.equal(store.getClaim(dependent.claim_id).lifecycle, 'STALE');
  });
});

describe('S2-004 expert lenses', () => {
  function lens(overrides = {}) {
    return {
      contractVersion: '1.0.0',
      lens_id: 'len-iso-1',
      owner_workspace_id: 'ws-1',
      owner_principal_id: PRINCIPALS.user1,
      expert_id: 'exp-muller',
      domain: 'energy economics',
      task_class: 'fact_checking',
      weight: 0.9,
      valid_from: '2026-01-01T00:00:00.000Z',
      valid_until: '2027-01-01T00:00:00.000Z',
      rationale: 'recognized domain expert',
      issuer: PRINCIPALS.admin,
      revoked_at: null,
      revocation_reason: null,
      created_at: CLOCK(),
      ...overrides,
    };
  }

  test('lenses are isolated per owner: user2 never sees user1 lenses', () => {
    const store = makeStore();
    store.setExpertLens({ lens: lens(), actor: PRINCIPALS.admin, operationId: nextOp(), idempotencyKey: nextIdem() });
    assert.equal(store.listExpertLenses({ workspaceId: 'ws-1', principalId: PRINCIPALS.user1 }).length, 1);
    assert.equal(store.listExpertLenses({ workspaceId: 'ws-1', principalId: PRINCIPALS.user2 }).length, 0);
    assert.equal(store.listExpertLenses({ workspaceId: 'ws-2', principalId: PRINCIPALS.user1 }).length, 0);
  });

  test('revocation immediately stops new uses; a lens cannot be revoked by a stranger', () => {
    const store = makeStore();
    store.setExpertLens({ lens: lens(), actor: PRINCIPALS.admin, operationId: nextOp(), idempotencyKey: nextIdem() });
    assert.throws(
      () => store.revokeExpertLens({ lensId: 'len-iso-1', actor: PRINCIPALS.user2, reason: 'not mine' }),
      (e) => e.code === 'AUTHORITY_DENIED',
    );
    store.revokeExpertLens({ lensId: 'len-iso-1', actor: PRINCIPALS.admin, reason: 'conflict of interest' });
    assert.equal(store.listExpertLenses({ workspaceId: 'ws-1', principalId: PRINCIPALS.user1 }).length, 0);
    // prior results keep provenance through lensById
    assert.equal(store.lensById('len-iso-1').revocation_reason, 'conflict of interest');
  });

  test('lens weight re-ranks but never touches protected fields (probe F invariant)', () => {
    const candidates = [
      { claim_id: 'clm-a', base_rank: 1, epistemic_type: 'EXPERT_OPINION', evidence_family_count: 1, calibration: 'NOT_MEASURED', expert_id: 'exp-muller' },
      { claim_id: 'clm-b', base_rank: 1, epistemic_type: 'FACT_CLAIM', evidence_family_count: 4, calibration: 'NOT_MEASURED', expert_id: 'exp-other' },
    ];
    const ranked = applyExpertLenses({ candidates, lenses: [lens()], taskClass: 'fact_checking' });
    // the lens-backed expert's candidate moves up purely through adjusted rank
    assert.equal(ranked[0].claim_id, 'clm-a');
    assert.equal(ranked[0].adjusted_rank, 1.9);
    // but the evidence count, epistemic type and calibration are untouched
    assert.equal(ranked[0].evidence_family_count, 1);
    assert.equal(ranked[0].calibration, 'NOT_MEASURED');
    assert.equal(ranked[0].epistemic_type, 'EXPERT_OPINION');
    assert.ok(lensesPreservedCandidates(candidates, ranked));
  });

  test('expired or other-task lenses have no effect', () => {
    const candidates = [{ claim_id: 'clm-a', base_rank: 1, expert_id: 'exp-muller' }];
    const expired = lens({ valid_from: '2025-01-01T00:00:00.000Z', valid_until: '2025-12-01T00:00:00.000Z' });
    const ranked = applyExpertLenses({ candidates, lenses: [expired], taskClass: 'fact_checking' });
    assert.equal(ranked[0].adjusted_rank, 1);
    assert.equal(ranked[0].lens_influence.length, 0);
  });
});

describe('S2-004 calibration records', () => {
  function calibration(overrides = {}) {
    return {
      contractVersion: '1.0.0',
      calibration_id: 'cal-iso-1',
      corpus_version: '1.0.0',
      corpus_sha256: sha256('corpus'),
      outcome_definition: { metric: 'extraction_accuracy', threshold: 0.9, description: 'exact field match' },
      numerator: 90,
      denominator: 100,
      missing_count: 0,
      uncertainty: { method: 'wilson', confidence_interval: { lower: 0.83, upper: 0.94, confidence_level: 0.95 } },
      evaluator_independence: { independent_evaluators: 2, blind_to_producer: true, separate_processes: true },
      status: 'MEASURED',
      not_measured_reason: null,
      measured_at: CLOCK(),
      measured_by: PRINCIPALS.evaluator,
      ...overrides,
    };
  }

  test('only an evaluator may record calibration; binding must match the actor', () => {
    const store = makeStore();
    assert.throws(
      () => store.upsertCalibrationRecord({ record: calibration(), actor: PRINCIPALS.producer }),
      (e) => e.code === 'AUTHORITY_DENIED',
    );
    const forged = calibration({ measured_by: PRINCIPALS.producer });
    assert.throws(
      () => store.upsertCalibrationRecord({ record: forged, actor: PRINCIPALS.evaluator }),
      (e) => e.code === 'CALIBRATION_BINDING_MISMATCH',
    );
    const ok = store.upsertCalibrationRecord({ record: calibration(), actor: PRINCIPALS.evaluator });
    assert.equal(ok.status, 'MEASURED');
  });

  test('inconsistent numerators are rejected', () => {
    const store = makeStore();
    assert.throws(
      () => store.upsertCalibrationRecord({ record: calibration({ numerator: 120 }), actor: PRINCIPALS.evaluator }),
      (e) => e.code === 'CALIBRATION_INCONSISTENT',
    );
    assert.throws(
      () => store.upsertCalibrationRecord({ record: calibration({ numerator: 95, missing_count: 10 }), actor: PRINCIPALS.evaluator }),
      (e) => e.code === 'CALIBRATION_INCONSISTENT',
    );
  });

  test('a lens can never write a calibration field', () => {
    const store = makeStore();
    assert.throws(
      () => store.setExpertLens({
        lens: {
          contractVersion: '1.0.0', lens_id: 'len-cal-1', owner_workspace_id: 'ws-1', owner_principal_id: PRINCIPALS.user1,
          expert_id: 'exp-muller', domain: 'energy', task_class: 'fact_checking', weight: 0.5,
          valid_from: '2026-01-01T00:00:00.000Z', valid_until: '2027-01-01T00:00:00.000Z',
          rationale: 'x', issuer: PRINCIPALS.admin, revoked_at: null, revocation_reason: null, created_at: CLOCK(),
          calibration: 'MEASURED',
        },
        actor: PRINCIPALS.admin, operationId: nextOp(), idempotencyKey: nextIdem(),
      }),
      (e) => e.code === 'CONTRACT_REJECTED',
    );
  });
});

describe('S2-004 source family collapse', () => {
  test('ten reprints of one upstream collapse to one family; translations follow the root', () => {
    const snapshots = new Map([
      ['snp-upstream', { lineage_type: 'original', parent_snapshot_ids: [] }],
      ...Array.from({ length: 9 }, (_, i) => [`snp-reprint-${i}`, { lineage_type: 'syndication', parent_snapshot_ids: ['snp-upstream'] }]),
      ['snp-translation', { lineage_type: 'translation', parent_snapshot_ids: ['snp-upstream'] }],
      ['snp-unrelated', { lineage_type: 'original', parent_snapshot_ids: [] }],
    ]);
    const edges = [
      'snp-upstream', ...Array.from({ length: 9 }, (_, i) => `snp-reprint-${i}`), 'snp-translation', 'snp-unrelated',
    ].map((s, i) => ({ edge_id: `eed-${i}`, upstream_snapshot_ids: [s] }));
    const collapse = collapseSourceFamilies(edges, { snapshotResolver: (id) => snapshots.get(id) });
    assert.equal(collapse.raw_source_count, 12);
    assert.equal(collapse.collapsed_family_count, 2);
    assert.equal(collapse.unknown_lineage_count, 0);
    const rootFamily = collapse.members.find((m) => m.edge_id === 'eed-0').family_id;
    assert.ok(collapse.members.filter((m) => m.family_id === rootFamily).length === 11);
  });

  test('unknown lineage never counts as independent and never merges into a family', () => {
    const snapshots = new Map([
      ['snp-mystery-1', { lineage_type: 'unknown', parent_snapshot_ids: [] }],
      ['snp-mystery-2', { lineage_type: 'unknown', parent_snapshot_ids: [] }],
    ]);
    const edges = [
      { edge_id: 'eed-u1', upstream_snapshot_ids: ['snp-mystery-1'] },
      { edge_id: 'eed-u2', upstream_snapshot_ids: ['snp-mystery-2'] },
    ];
    const collapse = collapseSourceFamilies(edges, { snapshotResolver: (id) => snapshots.get(id) });
    assert.equal(collapse.unknown_lineage_count, 2);
    assert.equal(collapse.collapsed_family_count, 0);
    assert.notEqual(collapse.members[0].family_id, collapse.members[1].family_id);
  });

  test('near-duplicates are candidates for review, never auto-merged', () => {
    const claims = [
      { claim_id: 'clm-a', revision: 1, normalized_text: 'Solar grew by 22% in 2024.' },
      { claim_id: 'clm-b', revision: 1, normalized_text: 'Solar grew by 22% in 2024.' },
    ];
    const candidates = proposeDuplicateCandidates(claims);
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].relation, 'DUPLICATES_CANDIDATE');
    assert.equal(candidates[0].requires_review, true);
  });
});
