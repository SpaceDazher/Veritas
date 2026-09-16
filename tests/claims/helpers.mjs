// Shared builders for S2-004 claim graph tests.
import { createHash } from 'node:crypto';
import { createClaimGraphStore, makeAuthorityRegistry } from '../../src/lib/claims/store.mjs';

export const sha256 = (s) => createHash('sha256').update(s).digest('hex');

export const T0 = '2026-01-15T08:00:00.000Z';
export const CLOCK = () => T0;

export const PRINCIPALS = Object.freeze({
  producer: 'prn-producer',
  extractor: 'prn-extractor',
  reviewer: 'prn-reviewer',
  reviewer2: 'prn-reviewer-2',
  admin: 'prn-admin',
  evaluator: 'prn-evaluator',
  user1: 'prn-user-1',
  user2: 'prn-user-2',
  system: 'prn-system',
});

export function testAuthorities() {
  return makeAuthorityRegistry([
    { principal: PRINCIPALS.producer, roles: ['producer'], workspaces: ['ws-1'] },
    { principal: PRINCIPALS.extractor, roles: ['extractor'], workspaces: ['ws-1'] },
    { principal: PRINCIPALS.reviewer, roles: ['reviewer'], workspaces: ['ws-1'] },
    { principal: PRINCIPALS.reviewer2, roles: ['reviewer'], workspaces: ['ws-1'] },
    { principal: PRINCIPALS.admin, roles: ['admin'], workspaces: ['ws-1', 'ws-2', 'ws-system'] },
    { principal: PRINCIPALS.evaluator, roles: ['evaluator'], workspaces: ['ws-1'] },
    { principal: PRINCIPALS.system, roles: ['system'], workspaces: ['ws-system'] },
  ]);
}

export function makeClaim(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    claim_id: null,
    revision: 1,
    workspace_id: 'ws-1',
    tenant_id: 'tn-1',
    acl: { visibility: 'project', workspace_id: 'ws-1', tenant_id: 'tn-1', allowed_workspace_ids: [] },
    epistemic_type: 'FACT_CLAIM',
    polarity: 'affirmative',
    modality: 'indicative',
    normalized_text: 'Wind and solar generated 22% of EU electricity in 2024.',
    original_text: 'Wind and solar generated 22% of EU electricity in 2024.',
    subject: 'Wind and solar',
    predicate: 'generated',
    object: '22% of EU electricity in 2024',
    qualifiers: [],
    assumptions: [],
    exclusions: [],
    units: '%',
    denominator: 'of EU electricity',
    value_range: { min: 22, max: 22 },
    population: null,
    geography: 'EU',
    period: { start: '2024-01-01T00:00:00.000Z', end: '2024-12-31T23:59:59.999Z' },
    event_time: null,
    published_at: T0,
    observed_at: T0,
    fetched_at: T0,
    language: 'en',
    translation_status: 'original',
    created_at: T0,
    created_by: PRINCIPALS.producer,
    ...overrides,
  };
}

export function makeSegment(text, overrides = {}) {
  return {
    segment_id: 'seg-test-1',
    snapshot_id: 'snp-test-1',
    source_id: 'src-test-1',
    revision: 1,
    text,
    text_sha256: sha256(text),
    original_language: 'en',
    normalized_language: 'en',
    status: 'COMPLETE',
    embedded_instruction_classification: { present: false, classification: 'none', confidence: 1, note: null },
    acl: { visibility: 'project', workspace_id: 'ws-1', tenant_id: 'tn-1', allowed_workspace_ids: [], allowed_principal_ids: [] },
    ...overrides,
  };
}

export function makeSnapshot(overrides = {}) {
  return {
    snapshot_id: 'snp-test-1',
    published_at: T0,
    event_time: null,
    observed_at: T0,
    fetched_at: T0,
    ...overrides,
  };
}

export function makeStore({ authorities = testAuthorities(), clock = CLOCK, segments = [], snapshots = [] } = {}) {
  const segmentMap = new Map(segments.map((s) => [`${s.segment_id}@${s.revision ?? 1}`, s]));
  const snapshotMap = new Map(snapshots.map((s) => [s.snapshot_id, s]));
  return createClaimGraphStore({
    authorities,
    clock,
    segmentResolver: (id, revision) => segmentMap.get(`${id}@${revision ?? 1}`) ?? null,
    snapshotResolver: (id) => snapshotMap.get(id) ?? null,
  });
}

let opCounter = 0;
export function nextOp(prefix = 'op-test') {
  opCounter += 1;
  return `${prefix}-${String(opCounter).padStart(6, '0')}`;
}

let idemCounter = 0;
export function nextIdem(prefix = 'idem-test') {
  idemCounter += 1;
  return `${prefix}-${String(idemCounter).padStart(6, '0')}`;
}

export function makeDecision(claim, actor, decision = 'ACCEPT_BOUNDED', overrides = {}) {
  return {
    contractVersion: '1.0.0',
    decision_id: overrides.decision_id ?? nextIdem('dec'),
    claim_id: claim.claim_id,
    claim_revision: claim.revision,
    claim_digest: claim.canonical_digest,
    actor,
    decision,
    reason_codes: overrides.reason_codes ?? ['insufficient_evidence'],
    expiry: decision === 'ACCEPT_BOUNDED' ? '2027-01-01T00:00:00.000Z' : null,
    supersession: null,
    idempotency_key: overrides.idempotency_key ?? nextIdem('idem-dec'),
    created_at: T0,
    ...overrides,
  };
}
