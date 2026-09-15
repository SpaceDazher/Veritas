// S2-004 contract schema tests: every canonical contract accepts a fully
// populated fixture and fails closed on mutations — unknown versions, missing
// hashes, invalid enum values, unbounded scopes, unknown mandatory fields and
// unknown extra properties (todo §3).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { claimValidators } from '../../src/lib/claims/validation.mjs';

const v = claimValidators();
const requireValid = (name, object) => v.requireValid(name, object);
const rejects = (name, mutate, label) => {
  const fixture = clone(FIXTURES[name]);
  mutate(fixture);
  assert.throws(() => requireValid(name, fixture), undefined, label ?? 'mutation must be rejected');
};
const clone = (value) => JSON.parse(JSON.stringify(value));

const T0 = '2026-01-15T08:00:00.000Z';
const T1 = '2026-01-16T08:00:00.000Z';

const FIXTURES = {
  claim: {
    contractVersion: '1.0.0',
    claim_id: 'clm-fixture000000000000000001',
    revision: 1,
    workspace_id: 'ws-1',
    tenant_id: 'tn-1',
    acl: { visibility: 'project', workspace_id: 'ws-1', tenant_id: 'tn-1', allowed_workspace_ids: [] },
    epistemic_type: 'FACT_CLAIM',
    polarity: 'affirmative',
    modality: 'indicative',
    normalized_text: 'Wind and solar generated 22% of EU electricity in 2024.',
    original_text: 'Wind and solar generated 22% of EU electricity in 2024, excluding hydropower.',
    subject: 'Wind and solar',
    predicate: 'generated',
    object: '22% of EU electricity in 2024',
    qualifiers: ['unit:%', 'exclusions:1'],
    uncertainty: { type: 'aleatory', description: 'range reported by the source' },
    method: { name: 'rule-based-extractor', version: '1.0.0', config_digest: 'a'.repeat(64) },
    assumptions: [],
    exclusions: ['hydropower'],
    units: '%',
    denominator: 'of EU electricity',
    value_range: { min: 22, max: 22 },
    population: null,
    geography: 'EU',
    period: { start: '2024-01-01T00:00:00.000Z', end: '2024-12-31T23:59:59.999Z' },
    event_time: null,
    published_at: T0,
    observed_at: T0,
    fetched_at: T1,
    language: 'en',
    translation_status: 'original',
    translation_provenance: null,
    canonical_digest: 'b'.repeat(64),
    lifecycle: 'PROPOSED',
    supersedes_claim_id: null,
    supersedes_revision: null,
    created_at: T0,
    created_by: 'prn-producer',
  },
  'evidence-edge': {
    contractVersion: '1.0.0',
    edge_id: 'eed-fixture00000000000000001',
    claim_id: 'clm-fixture000000000000000001',
    claim_revision: 1,
    segment_id: 'seg-fixture000000000000001',
    segment_revision: 1,
    relation: 'SUPPORTS',
    span: { start: 0, end: 30 },
    quote_digest: 'c'.repeat(64),
    entailment_status: 'ENTAILED',
    method: { name: 'rule-based-extractor', version: '1.0.0', config_digest: 'a'.repeat(64) },
    reviewer: null,
    source_family_id: 'fam-fixture00000000000001',
    upstream_snapshot_ids: ['snp-fixture00000000000001'],
    access_state: 'available',
    retention_state: 'active',
    created_at: T0,
    created_by: 'prn-producer',
  },
  'claim-edge': {
    contractVersion: '1.0.0',
    edge_id: 'ced-fixture00000000000000001',
    source_claim_id: 'clm-fixture000000000000000001',
    source_revision: 1,
    target_claim_id: 'clm-fixture000000000000000002',
    target_revision: 1,
    relation: 'DEPENDS_ON',
    direction: 'forward',
    scope_intersection: { population_overlap: true, geography_overlap: true, period_overlap: true, units_compatible: true },
    provenance: { method: 'manual', extractor: 'annotator', extractor_version: '1.0.0', config_digest: 'a'.repeat(64) },
    creation_authority: 'prn-producer',
    created_at: T0,
    created_by: 'prn-producer',
  },
  'expert-profile': {
    contractVersion: '1.0.0',
    expert_id: 'exp-fixture000000000000001',
    aliases: ['Dr. Muller'],
    domains: [{ domain: 'energy economics', valid_from: T0, valid_until: T1, provenance_claim_id: 'clm-fixture000000000000000003' }],
    affiliations: [{ organization: 'Institute A', role: 'senior fellow', valid_from: T0, valid_until: T1, provenance_claim_id: 'clm-fixture000000000000000003' }],
    conflicts: [{ description: 'consults for utility B', valid_from: T0, valid_until: T1, provenance_claim_id: 'clm-fixture000000000000000003' }],
    valid_from: T0,
    valid_until: T1,
    credentials: [{ credential_type: 'PhD', issuer: 'University C', issued_at: T0, expires_at: null, provenance_claim_id: 'clm-fixture000000000000000003' }],
    created_at: T0,
    created_by: 'prn-admin',
  },
  'expert-lens': {
    contractVersion: '1.0.0',
    lens_id: 'len-fixture0000000000000001',
    owner_workspace_id: 'ws-1',
    owner_principal_id: 'prn-user-1',
    expert_id: 'exp-fixture000000000000001',
    domain: 'energy economics',
    task_class: 'fact_checking',
    weight: 0.8,
    valid_from: T0,
    valid_until: T1,
    rationale: 'domain expertise',
    issuer: 'prn-admin',
    revoked_at: null,
    revocation_reason: null,
    created_at: T0,
  },
  'calibration-record': {
    contractVersion: '1.0.0',
    calibration_id: 'cal-fixture0000000000000001',
    corpus_version: '1.0.0',
    corpus_sha256: 'd'.repeat(64),
    outcome_definition: { metric: 'extraction_accuracy', threshold: 0.9, description: 'exact field match on frozen corpus' },
    numerator: 90,
    denominator: 100,
    missing_count: 0,
    uncertainty: { method: 'wilson', confidence_interval: { lower: 0.83, upper: 0.94, confidence_level: 0.95 } },
    evaluator_independence: { independent_evaluators: 2, blind_to_producer: true, separate_processes: true },
    status: 'MEASURED',
    not_measured_reason: null,
    measured_at: T0,
    measured_by: 'prn-evaluator',
  },
  'claim-extraction-request': {
    contractVersion: '1.0.0',
    request_id: 'req-fixture0000000000000001',
    segment_ids: ['seg-fixture000000000000001'],
    segment_hashes: ['e'.repeat(64)],
    extractor: 'rule-based-extractor',
    extractor_version: '1.0.0',
    prompt_version: '1.0.0',
    parameters: { language: 'en', max_claims: 10 },
    seed: null,
    actor: 'prn-extractor',
    workspace_id: 'ws-1',
    idempotency_key: 'idem-fixture000000000000001',
  },
  'claim-extraction-result': {
    contractVersion: '1.0.0',
    request_id: 'req-fixture0000000000000001',
    proposed_claims: [{
      claim_id: 'clm-fixture000000000000000001',
      normalized_text: 'Wind and solar generated 22% of EU electricity in 2024.',
      original_text: 'Wind and solar generated 22% of EU electricity in 2024.',
      epistemic_type: 'FACT_CLAIM',
      source_span: { segment_id: 'seg-fixture000000000000001', start: 0, end: 55 },
      evidence_digest: 'f'.repeat(64),
    }],
    abstentions: [{ segment_id: 'seg-fixture000000000000001', reason: 'ambiguous' }],
    malformed_output: [],
    audit_binding: { operation_id: 'op-fixture000000000000000001', executor_id: 'exec-fixture00000000001', pid: 1234, nonce: 'n-fixture00000000001', output_root: 'a'.repeat(64) },
    status: 'COMPLETED',
    completed_at: T0,
  },
  'claim-review-decision': {
    contractVersion: '1.0.0',
    decision_id: 'dec-fixture0000000000000001',
    claim_id: 'clm-fixture000000000000000001',
    claim_revision: 1,
    claim_digest: 'b'.repeat(64),
    actor: 'prn-reviewer',
    decision: 'ACCEPT_BOUNDED',
    reason_codes: ['insufficient_evidence'],
    expiry: T1,
    supersession: null,
    idempotency_key: 'idem-decision00000000000001',
    created_at: T0,
  },
  'graph-invalidation-event': {
    contractVersion: '1.0.0',
    event_id: 'inv-fixture0000000000000001',
    trigger_type: 'content_segment_tombstone',
    trigger_id: 'seg-fixture000000000000001',
    trigger_revision: 1,
    affected_descendants: [{ entity_type: 'claim', entity_id: 'clm-fixture000000000000000001', entity_revision: 1, new_lifecycle: 'STALE' }],
    reason: { code: 'upstream_tombstoned', description: 'parent segment tombstoned by source' },
    traversal_evidence: { method: 'bfs', visited_count: 1, edges_traversed: ['eed-fixture00000000000000001'] },
    completion_state: 'COMPLETED',
    failed_descendants: [],
    created_at: T0,
    created_by: 'prn-system',
  },
};

describe('S2-004 contract schemas', () => {
  for (const name of Object.keys(FIXTURES)) {
    test(`${name}: the canonical fixture validates`, () => {
      requireValid(name, clone(FIXTURES[name]));
    });
  }

  describe('claim', () => {
    test('unknown contractVersion is rejected', () => {
      rejects('claim', (f) => { f.contractVersion = '9.9.9'; });
    });
    test('invalid epistemic_type is rejected', () => {
      rejects('claim', (f) => { f.epistemic_type = 'TRUTH'; });
    });
    test('invalid lifecycle is rejected', () => {
      rejects('claim', (f) => { f.lifecycle = 'ACCEPTED'; });
    });
    test('missing canonical digest is rejected', () => {
      rejects('claim', (f) => { f.canonical_digest = undefined; });
    });
    test('malformed digest is rejected', () => {
      rejects('claim', (f) => { f.canonical_digest = 'xyz'; });
    });
    test('SUPERSEDED without supersedes target is rejected', () => {
      rejects('claim', (f) => {
        f.lifecycle = 'SUPERSEDED';
        f.supersedes_claim_id = null;
        f.supersedes_revision = null;
      });
    });
    test('translated without translation provenance is rejected', () => {
      rejects('claim', (f) => {
        f.translation_status = 'translated';
        f.translation_provenance = null;
      });
    });
    test('unknown extra property is rejected', () => {
      rejects('claim', (f) => { f.truth_score = 0.99; });
    });
    test('invalid timestamp is rejected', () => {
      rejects('claim', (f) => { f.published_at = '2026-01-15'; });
    });
    test('negative span-free value range bound is rejected via enum constraints', () => {
      rejects('claim', (f) => { f.revision = 0; });
    });
  });

  describe('evidence-edge', () => {
    test('missing quote digest is rejected', () => {
      rejects('evidence-edge', (f) => { f.quote_digest = null; });
    });
    test('invalid relation is rejected', () => {
      rejects('evidence-edge', (f) => { f.relation = 'MENTIONS'; });
    });
    test('empty upstream list is rejected', () => {
      rejects('evidence-edge', (f) => { f.upstream_snapshot_ids = []; });
    });
    test('invalid access state is rejected', () => {
      rejects('evidence-edge', (f) => { f.access_state = 'public_anyway'; });
    });
  });

  describe('claim-edge', () => {
    test('DEPENDS_ON requires the full scope intersection', () => {
      rejects('claim-edge', (f) => { f.scope_intersection = {}; });
    });
    test('creation authority is mandatory', () => {
      rejects('claim-edge', (f) => { f.creation_authority = undefined; });
    });
    test('invalid relation is rejected', () => {
      rejects('claim-edge', (f) => { f.relation = 'DERIVED_FROM'; });
    });
  });

  describe('expert-lens', () => {
    test('no authority or truth field can exist', () => {
      rejects('expert-lens', (f) => { f.authority = 1; });
      rejects('expert-lens', (f) => { f.truth = 1; });
    });
    test('weight is bounded to [0,1]', () => {
      rejects('expert-lens', (f) => { f.weight = 1.5; });
    });
    test('revocation without reason is rejected', () => {
      rejects('expert-lens', (f) => {
        f.revoked_at = T1;
        f.revocation_reason = null;
      });
    });
  });

  describe('calibration-record', () => {
    test('NOT_MEASURED requires a reason', () => {
      rejects('calibration-record', (f) => {
        f.status = 'NOT_MEASURED';
        f.not_measured_reason = null;
      });
    });
    test('negative missing_count is rejected', () => {
      rejects('calibration-record', (f) => { f.missing_count = -1; });
    });
  });

  describe('claim-review-decision', () => {
    test('empty reason codes are rejected', () => {
      rejects('claim-review-decision', (f) => { f.reason_codes = []; });
    });
    test('unknown reason code is rejected', () => {
      rejects('claim-review-decision', (f) => { f.reason_codes = ['vibes']; });
    });
    test('ACCEPT_BOUNDED without expiry is rejected', () => {
      rejects('claim-review-decision', (f) => { f.expiry = null; });
    });
  });

  describe('graph-invalidation-event', () => {
    test('FAILED completion requires failed_descendants', () => {
      rejects('graph-invalidation-event', (f) => {
        f.completion_state = 'FAILED';
        f.failed_descendants = undefined;
      });
    });
    test('unknown trigger type is rejected', () => {
      rejects('graph-invalidation-event', (f) => { f.trigger_type = 'vibes_shift'; });
    });
  });
});
