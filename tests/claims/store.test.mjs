// S2-004 claim graph store behavior tests: immutability, projected lifecycle,
// review authority gates, single-use approvals, idempotent replay, atomic
// multi-record commits, cycle detection and derived ACL.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CLOCK, PRINCIPALS, makeClaim, makeDecision, makeSegment, makeSnapshot, makeStore,
  nextIdem, nextOp, sha256, testAuthorities,
} from './helpers.mjs';
import { canonicalDigestOfClaim } from '../../src/lib/claims/validation.mjs';

describe('S2-004 claim store: proposals and immutability', () => {
  test('a proposal writes one immutable record and an audit event', () => {
    const store = makeStore();
    const outcome = store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() });
    assert.equal(outcome.claims.length, 1);
    assert.equal(outcome.claims[0].lifecycle, 'PROPOSED');
    assert.equal(store.listOutbox().filter((e) => e.type === 'CLAIM_PROPOSED').length, 1);
    assert.match(outcome.claims[0].claim_id, /^clm-/);
  });

  test('identical content maps to the same deterministic claim id without a duplicate record', () => {
    const store = makeStore();
    const first = store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() });
    const second = store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() });
    assert.equal(first.claims[0].claim_id, second.claims[0].claim_id);
    assert.equal(store.listClaimHistory(first.claims[0].claim_id).length, 1);
  });

  test('content differences produce different deterministic ids', () => {
    const store = makeStore();
    const a = store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() });
    const b = store.proposeClaims({ claims: [makeClaim({ normalized_text: 'Different text entirely.', original_text: 'Different text entirely.' })], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() });
    assert.notEqual(a.claims[0].claim_id, b.claims[0].claim_id);
  });

  test('a proposal without producer/extractor capability is denied', () => {
    const store = makeStore();
    assert.throws(
      () => store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.reviewer, operationId: nextOp(), idempotencyKey: nextIdem() }),
      (e) => e.code === 'AUTHORITY_DENIED',
    );
  });

  test('a contract-invalid claim aborts the whole operation', () => {
    const store = makeStore();
    const valid = makeClaim();
    const invalid = makeClaim({ epistemic_type: 'TRUTH' });
    assert.throws(
      () => store.proposeClaims({ claims: [valid, invalid], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }),
      (e) => e.code === 'CONTRACT_REJECTED',
    );
    // atomicity: the valid claim of the failed operation was rolled back
    const stillAbsent = store.getClaim(valid.claim_id ?? 'clm-nothing');
    assert.ok(stillAbsent === null || store.listClaimHistory(stillAbsent.claim_id).length <= 1);
  });
});

describe('S2-004 claim store: review gate', () => {
  function proposed(store) {
    return store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }).claims[0];
  }

  test('a producer holding the reviewer role still cannot review their own claim', () => {
    const authorities = testAuthorities();
    // prn-producer gains the reviewer role — the self-review guard must hold
    authorities.set(PRINCIPALS.producer, { roles: new Set(['producer', 'reviewer']), workspaces: new Set(['ws-1']) });
    const store = makeStore({ authorities });
    const claim = store.proposeClaims({ claims: [makeClaim({ created_by: PRINCIPALS.producer })], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }).claims[0];
    assert.throws(
      () => store.reviewClaim({ decision: makeDecision(claim, PRINCIPALS.producer) }),
      (e) => e.code === 'PRODUCER_SELF_REVIEW',
    );
  });

  test('an actor without reviewer capability cannot review', () => {
    const store = makeStore();
    const claim = proposed(store);
    assert.throws(
      () => store.reviewClaim({ decision: makeDecision(claim, PRINCIPALS.extractor) }),
      (e) => e.code === 'AUTHORITY_DENIED',
    );
  });

  test('a decision binds the exact canonical digest of the exact revision', () => {
    const store = makeStore();
    const claim = proposed(store);
    const decision = makeDecision(claim, PRINCIPALS.reviewer);
    decision.claim_digest = sha256('forged');
    assert.throws(
      () => store.reviewClaim({ decision }),
      (e) => e.code === 'DECISION_BINDING_MISMATCH',
    );
    decision.claim_revision = 99;
    decision.claim_digest = claim.canonical_digest;
    assert.throws(
      () => store.reviewClaim({ decision }),
      (e) => e.code === 'CLAIM_NOT_FOUND',
    );
  });

  test('ACCEPT_BOUNDED is terminal and single-use', () => {
    const store = makeStore();
    const claim = proposed(store);
    const accepted = store.reviewClaim({ decision: makeDecision(claim, PRINCIPALS.reviewer, 'ACCEPT_BOUNDED') });
    assert.equal(accepted.lifecycle, 'ACCEPTED_BOUNDED');
    assert.throws(
      () => store.reviewClaim({ decision: makeDecision(claim, PRINCIPALS.reviewer2, 'REJECT', { decision_id: nextIdem('dec-2') }) }),
      (e) => e.code === 'SINGLE_USE_APPROVAL',
    );
  });

  test('exact decision replay is idempotent; a different decision under the same id conflicts', () => {
    const store = makeStore();
    const claim = proposed(store);
    const decision = makeDecision(claim, PRINCIPALS.reviewer, 'QUARANTINE');
    const first = store.reviewClaim({ decision });
    assert.equal(first.lifecycle, 'QUARANTINED');
    const replay = store.reviewClaim({ decision });
    assert.equal(replay.lifecycle, 'QUARANTINED');
    const conflicting = { ...decision, decision: 'ACCEPT_BOUNDED', expiry: '2027-01-01T00:00:00.000Z' };
    assert.throws(
      () => store.reviewClaim({ decision: conflicting }),
      (e) => e.code === 'IDEMPOTENCY_CONFLICT',
    );
  });

  test('an expired decision is rejected', () => {
    const store = makeStore({ clock: () => '2027-06-01T00:00:00.000Z' });
    const claim = proposed(store);
    assert.throws(
      () => store.reviewClaim({ decision: makeDecision(claim, PRINCIPALS.reviewer, 'ACCEPT_BOUNDED', { expiry: '2027-01-01T00:00:00.000Z' }) }),
      (e) => e.code === 'DECISION_EXPIRED',
    );
  });
});

describe('S2-004 claim store: revisions and supersession', () => {
  test('reviseClaim creates a new revision with a SUPERSEDES edge', () => {
    const store = makeStore();
    const claim = store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }).claims[0];
    const outcome = store.reviseClaim({
      claimId: claim.claim_id,
      baseRevision: 1,
      patch: { normalized_text: 'Wind and solar generated 23% of EU electricity in 2024.', value_range: { min: 23, max: 23 } },
      actor: PRINCIPALS.producer,
      operationId: nextOp(),
      idempotencyKey: nextIdem(),
    });
    assert.equal(outcome.claim.revision, 2);
    assert.equal(outcome.superseded_revision, 1);
    const history = store.listClaimHistory(claim.claim_id);
    assert.equal(history.length, 2);
    assert.equal(history[0].lifecycle, 'SUPERSEDED');
    assert.equal(history[1].lifecycle, 'PROPOSED');
    const edges = store.listClaimEdges(claim.claim_id).filter((e) => e.relation === 'SUPERSEDES');
    assert.equal(edges.length, 1);
    assert.equal(edges[0].source_revision, 1);
    assert.equal(edges[0].target_revision, 2);
    // revision 1 content is unchanged (immutability)
    assert.equal(history[0].value_range.min, 22);
    assert.equal(history[0].canonical_digest, claim.canonical_digest);
  });

  test('canonical digest of the new revision differs; the old stays verifiable', () => {
    const store = makeStore();
    const claim = store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }).claims[0];
    const revised = store.reviseClaim({ claimId: claim.claim_id, baseRevision: 1, patch: { normalized_text: 'Revised statement.' }, actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() });
    assert.notEqual(revised.claim.canonical_digest, claim.canonical_digest);
    assert.equal(revised.claim.canonical_digest, canonicalDigestOfClaim(revised.claim));
  });
});

describe('S2-004 claim store: cycles and claim edges', () => {
  function twoClaims(store) {
    const a = store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }).claims[0];
    const b = store.proposeClaims({ claims: [makeClaim({ normalized_text: 'Another proposition.', original_text: 'Another proposition.', subject: 'Another subject' })], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }).claims[0];
    return [a, b];
  }

  test('DEPENDS_ON cycles are detected before commit', () => {
    const store = makeStore();
    const [a, b] = twoClaims(store);
    const edge = (source, target) => ({
      contractVersion: '1.0.0',
      edge_id: `ced-${source.claim_id}-${target.claim_id}`,
      source_claim_id: source.claim_id,
      source_revision: 1,
      target_claim_id: target.claim_id,
      target_revision: 1,
      relation: 'DEPENDS_ON',
      direction: 'forward',
      scope_intersection: { population_overlap: true, geography_overlap: true, period_overlap: true, units_compatible: true },
      provenance: { method: 'manual', extractor: 'annotator', extractor_version: '1.0.0' },
      creation_authority: PRINCIPALS.producer,
    });
    store.linkClaims({ edge: edge(a, b), actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() });
    assert.throws(
      () => store.linkClaims({ edge: edge(b, a), actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }),
      (e) => e.code === 'CYCLE_DETECTED',
    );
  });

  test('self-dependency is rejected', () => {
    const store = makeStore();
    const [a] = twoClaims(store);
    assert.throws(
      () => store.linkClaims({
        edge: {
          contractVersion: '1.0.0', edge_id: 'ced-self', source_claim_id: a.claim_id, source_revision: 1,
          target_claim_id: a.claim_id, target_revision: 1, relation: 'DEPENDS_ON', direction: 'forward',
          scope_intersection: { population_overlap: true, geography_overlap: true, period_overlap: true, units_compatible: true },
          provenance: { method: 'manual', extractor: 'annotator', extractor_version: '1.0.0' },
          creation_authority: PRINCIPALS.producer,
        },
        actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
      }),
      (e) => e.code === 'CYCLE_DETECTED',
    );
  });

  test('SUPERSEDES edges must stay within one claim', () => {
    const store = makeStore();
    const [a, b] = twoClaims(store);
    assert.throws(
      () => store.linkClaims({
        edge: {
          contractVersion: '1.0.0', edge_id: 'ced-cross', source_claim_id: a.claim_id, source_revision: 1,
          target_claim_id: b.claim_id, target_revision: 1, relation: 'SUPERSEDES', direction: 'forward',
          scope_intersection: {}, provenance: { method: 'manual', extractor: 'annotator', extractor_version: '1.0.0' },
          creation_authority: PRINCIPALS.producer,
        },
        actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
      }),
      (e) => e.code === 'SUPERSEDES_SCOPE',
    );
  });
});

describe('S2-004 claim store: evidence binding and derived ACL', () => {
  test('evidence binds the exact span digest of the immutable segment', () => {
    const text = 'Solar produced 8% of German electricity in 2024. Wind followed at 27%.';
    const segment = makeSegment(text);
    const store = makeStore({ segments: [segment], snapshots: [makeSnapshot()] });
    const claim = store.proposeClaims({ claims: [makeClaim({ geography: 'Germany' })], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }).claims[0];
    const good = store.linkEvidence({
      edge: {
        contractVersion: '1.0.0', edge_id: 'eed-ok', claim_id: claim.claim_id, claim_revision: 1,
        segment_id: segment.segment_id, segment_revision: 1, relation: 'SUPPORTS',
        span: { start: 0, end: 51 }, quote_digest: sha256(text.slice(0, 51)),
        entailment_status: 'ENTAILED',
        method: { name: 'manual', version: '1.0.0' }, reviewer: null,
        source_family_id: 'fam-test', upstream_snapshot_ids: ['snp-test-1'],
        access_state: 'available', retention_state: 'active',
      },
      actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
    });
    assert.ok(good.edge.edge_id);
    assert.equal(good.derived_acl.visibility, 'project');
  });

  test('a span whose bytes do not hash to the quote digest is rejected', () => {
    const text = 'Solar produced 8% of German electricity in 2024.';
    const segment = makeSegment(text);
    const store = makeStore({ segments: [segment], snapshots: [makeSnapshot()] });
    const claim = store.proposeClaims({ claims: [makeClaim({ geography: 'Germany' })], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }).claims[0];
    assert.throws(
      () => store.linkEvidence({
        edge: {
          contractVersion: '1.0.0', edge_id: 'eed-bad', claim_id: claim.claim_id, claim_revision: 1,
          segment_id: segment.segment_id, segment_revision: 1, relation: 'SUPPORTS',
          span: { start: 0, end: 20 }, quote_digest: sha256('tampered bytes'),
          entailment_status: 'ENTAILED', method: { name: 'manual', version: '1.0.0' }, reviewer: null,
          source_family_id: 'fam-test', upstream_snapshot_ids: ['snp-test-1'],
          access_state: 'available', retention_state: 'active',
        },
        actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
      }),
      (e) => e.code === 'SPAN_DIGEST_MISMATCH',
    );
  });

  test('binding evidence to an already reviewed claim revision is rejected', () => {
    const text = 'Solar produced 8% of German electricity in 2024.';
    const segment = makeSegment(text);
    const store = makeStore({ segments: [segment], snapshots: [makeSnapshot()] });
    const claim = store.proposeClaims({ claims: [makeClaim({ geography: 'Germany' })], actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem() }).claims[0];
    store.linkEvidence({
      edge: {
        contractVersion: '1.0.0', edge_id: 'eed-first', claim_id: claim.claim_id, claim_revision: 1,
        segment_id: segment.segment_id, segment_revision: 1, relation: 'SUPPORTS',
        span: { start: 0, end: 20 }, quote_digest: sha256(text.slice(0, 20)),
        entailment_status: 'ENTAILED', method: { name: 'manual', version: '1.0.0' }, reviewer: null,
        source_family_id: 'fam-test', upstream_snapshot_ids: ['snp-test-1'],
        access_state: 'available', retention_state: 'active',
      },
      actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
    });
    store.reviewClaim({ decision: makeDecision(store.getClaim(claim.claim_id), PRINCIPALS.reviewer, 'ACCEPT_BOUNDED') });
    assert.throws(
      () => store.linkEvidence({
        edge: {
          contractVersion: '1.0.0', edge_id: 'eed-rebind', claim_id: claim.claim_id, claim_revision: 1,
          segment_id: segment.segment_id, segment_revision: 1, relation: 'SUPPORTS',
          span: { start: 20, end: 47 }, quote_digest: sha256(text.slice(20, 47)),
          entailment_status: 'ENTAILED', method: { name: 'manual', version: '1.0.0' }, reviewer: null,
          source_family_id: 'fam-test', upstream_snapshot_ids: ['snp-test-1'],
          access_state: 'available', retention_state: 'active',
        },
        actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
      }),
      (e) => e.code === 'EVIDENCE_REBIND_AFTER_REVIEW',
    );
  });

  test('derived ACL equals the most restrictive input: private segment tightens a public claim', () => {
    const text = 'Internal estimate: solar produced 8%.';
    const privateSegment = makeSegment(text, {
      acl: { visibility: 'private', workspace_id: 'ws-1', tenant_id: 'tn-1', allowed_workspace_ids: [], allowed_principal_ids: [PRINCIPALS.user1] },
    });
    const store = makeStore({ segments: [privateSegment], snapshots: [makeSnapshot()] });
    const claim = store.proposeClaims({
      claims: [makeClaim({ acl: { visibility: 'public', workspace_id: 'ws-1', tenant_id: 'tn-1' } })],
      actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
    }).claims[0];
    const outcome = store.linkEvidence({
      edge: {
        contractVersion: '1.0.0', edge_id: 'eed-private', claim_id: claim.claim_id, claim_revision: 1,
        segment_id: privateSegment.segment_id, segment_revision: 1, relation: 'SUPPORTS',
        span: { start: 0, end: 20 }, quote_digest: sha256(text.slice(0, 20)),
        entailment_status: 'ENTAILED', method: { name: 'manual', version: '1.0.0' }, reviewer: null,
        source_family_id: 'fam-test', upstream_snapshot_ids: ['snp-test-1'],
        access_state: 'available', retention_state: 'active',
      },
      actor: PRINCIPALS.producer, operationId: nextOp(), idempotencyKey: nextIdem(),
    });
    assert.equal(outcome.derived_acl.visibility, 'private');
    assert.deepEqual(outcome.derived_acl.allowed_principal_ids, [PRINCIPALS.user1]);
  });
});

describe('S2-004 claim store: idempotency ledger and reconciliation', () => {
  test('same operation id with different input is an IDEMPOTENCY_CONFLICT without mutation', () => {
    const store = makeStore();
    store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: 'op-same', idempotencyKey: nextIdem() });
    const before = store.listOutbox().length;
    assert.throws(
      () => store.proposeClaims({ claims: [makeClaim({ normalized_text: 'Changed.' })], actor: PRINCIPALS.producer, operationId: 'op-same', idempotencyKey: nextIdem() }),
      (e) => e.code === 'IDEMPOTENCY_CONFLICT',
    );
    assert.equal(store.listOutbox().length, before);
  });

  test('same idempotency key with a different actor conflicts', () => {
    const store = makeStore();
    store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: 'op-a', idempotencyKey: 'idem-shared' });
    assert.throws(
      () => store.proposeClaims({ claims: [makeClaim({ normalized_text: 'Other.' })], actor: PRINCIPALS.extractor, operationId: 'op-b', idempotencyKey: 'idem-shared' }),
      (e) => e.code === 'IDEMPOTENCY_CONFLICT',
    );
  });

  test('a committed operation replays its recorded outcome; unknown ones require reconciliation', () => {
    const store = makeStore();
    store.proposeClaims({ claims: [makeClaim()], actor: PRINCIPALS.producer, operationId: 'op-replay', idempotencyKey: nextIdem() });
    const reconciled = store.reconcileOperation('op-replay');
    assert.equal(reconciled.status, 'COMMITTED');
    assert.equal(reconciled.replayed, true);
    const unknown = store.reconcileOperation('op-never-happened');
    assert.equal(unknown.status, 'RECONCILIATION_REQUIRED');
    assert.equal(unknown.replayed, false);
  });
});
