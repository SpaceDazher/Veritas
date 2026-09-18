// S2-005 contract schema tests: every canonical contract accepts a fully
// populated fixture and fails closed on mutations — unknown versions, missing
// required fields, invalid enum values, bad digests and unknown extra
// properties (todo §2).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { synthesisValidators } from '../../src/lib/synthesis/validation.mjs';

const v = synthesisValidators();
const requireValid = (name, object) => v.requireValid(name, object);
const clone = (value) => JSON.parse(JSON.stringify(value));

const T0 = '2026-01-15T08:00:00.000Z';
const SHA = 'a'.repeat(64);

const FIXTURES = {
  'retrieval-request': {
    contractVersion: '1.0.0',
    request_id: 'req-s5-fixture-001',
    actor: 'prn-user-1',
    workspace_id: 'ws-corpus',
    query: { text: 'asthma incidence urban children', task_class: 'research', question_kind: 'local' },
    as_of: '2025-06-01T00:00:00.000Z',
    domains: ['epidemiology'],
    languages: ['en'],
    geography: null,
    time_window: null,
    source_policy: { allowed_source_families: [] },
    budget: { max_candidates: 100, max_operations: 50000, timeout_ms: 5000 },
    allowed_retrieval_modes: ['lexical', 'vector', 'fusion', 'graph'],
    mode: 'fusion',
    corpus_version: '1.0.0',
    index_version: '1.0.0',
    seed: 0,
  },
  'retrieval-hit': {
    contractVersion: '1.0.0',
    hit_id: 'hit-s5-fixture-001-abcdef0123456789-1',
    request_id: 'req-s5-fixture-001',
    mode: 'fusion',
    claim_id: 'clm-abcdef0123456789abcdef',
    claim_revision: 1,
    segment_id: 'seg-epi-1',
    segment_revision: 1,
    span: { start: 0, end: 76 },
    quote_digest: SHA,
    text_sha256: SHA,
    source_family_id: 'fam-epi-1',
    acl: { visibility: 'project', workspace_id: 'ws-corpus', tenant_id: 'tn-corpus', allowed_workspace_ids: [], allowed_principal_ids: [] },
    score: { total: 1.5, components: { primary: 1.5, lexical: 1, vector: 0.5, rerank: 0.2 }, normalized: 0.9 },
    rank: 1,
    included: true,
    reason: 'INCLUDED_RELEVANT',
  },
  'evidence-map': {
    contractVersion: '1.0.0',
    map_id: 'evm-abcdef0123456789',
    statement: 'Air pollution exposure increased asthma incidence by 18% among urban children in 2023.',
    entries: [
      {
        claim_id: 'clm-abcdef0123456789abcdef',
        claim_revision: 1,
        relation: 'supports',
        entailment_status: 'ENTAILS',
        entailment_method: 'token-coverage+number+polarity/1.0.0',
        evidence_edge_id: null,
        segment_id: 'seg-epi-1',
        span: { start: 0, end: 76 },
        quote_digest: SHA,
        source_family_id: 'fam-epi-1',
        domain: 'epidemiology',
      },
    ],
    unavailable_evidence: [],
    qualifiers: [],
    family_collapse: { families: [{ source_family_id: 'fam-epi-1', member_count: 1, lineage: 'DERIVED' }], collapsed_members: 0, independent_evidence_count: 1 },
    stale: { is_stale: false, invalidation_event_ids: [], stale_claim_ids: [], recomputed: false },
    status: 'FRESH',
  },
  'hypothesis-card': {
    contractVersion: '1.0.0',
    card_id: 'hyc-abcdef0123456789',
    card_type: 'HYPOTHESIS',
    type_promotion: null,
    originating_domains: ['epidemiology', 'urban_mobility'],
    nodes: [
      { claim_id: 'clm-abcdef0123456789abcdef', revision: 1, domain: 'epidemiology', role: 'source' },
      { claim_id: 'clm-bcdef0123456789abcdef0', revision: 1, domain: 'urban_mobility', role: 'target' },
    ],
    proposed_relation: { subject: 'air pollution exposure', predicate: 'increases', object: 'asthma incidence', relation_strength: 'CORRELATION_EVIDENCE', causal_assertion: null },
    temporal_ordering: { established: false, evidence_claim_ids: [], event_times: [] },
    mediators: [{ description: 'no supported mediator identified', claim_id: null, evidence_status: 'NOT_FOUND' }],
    confounders: [{ description: 'seasonal driver', status: 'UNRESOLVED', claim_id: null }],
    alternative_explanations: [],
    scope: { population: null, geography: null, period: null, units: null, domain_limits: ['frozen corpus scope only'] },
    assumptions: [],
    falsifiers: [{ description: 'a replicated contradicting finding', observable: 'contradicting claim' }],
    test_design: 'stratified paired comparison',
    counterevidence: [],
    novelty: { assessment: 'novel_to_selected_corpus', corpus: 'corpus/s2-005@1.0.0', search_horizon: 'frozen corpus + lock date', similar_prior_refs: [] },
    uncertainty: { author_confidence: null, expert_trust: null, measured_calibration: null, evidence_support: 2 },
    stale: { is_stale: false, invalidation_event_ids: [], stale_claim_ids: [] },
    status: 'FRESH',
  },
};

// retrieval-run and synthesis-result are assembled from the fixtures above.
FIXTURES['retrieval-run'] = {
  contractVersion: '1.0.0',
  run_id: 'run-s5-fixture-001',
  mode: 'fusion',
  request_id: 'req-s5-fixture-001',
  request_digest: SHA,
  query_hash: SHA,
  index_hash: SHA,
  model: { model_id: 'hashed-tfidf-256', model_version: '1.0.0', model_digest: null },
  seed: 0,
  config_hash: SHA,
  as_of: '2025-06-01T00:00:00.000Z',
  candidates_total: 3,
  hits: [clone(FIXTURES['retrieval-hit'])],
  excluded_count: { EXCLUDED_FAMILY_COLLAPSED: 1 },
  failures: [],
  abstentions: [],
  cost: { operations: 120, budget_max_operations: 50000, budget_exhausted: false },
  latency_ms: 3.2,
  execution: { executor_id: 'exec-s2-005-a', pid: 1234, nonce: 'n-a-55f41bab6f1b53bc', output_root_digest: SHA, clock: T0 },
  status: 'COMPLETED',
};
FIXTURES['synthesis-result'] = {
  contractVersion: '1.0.0',
  result_id: 'syn-abcdef0123456789',
  request_digest: SHA,
  input_versions: { contracts_version: '1.0.0', corpus_version: '1.0.0', index_version: '1.0.0', retrieval_model_version: '1.0.0', as_of: '2025-06-01T00:00:00.000Z' },
  evidence_maps: [clone(FIXTURES['evidence-map'])],
  hypothesis_cards: [clone(FIXTURES['hypothesis-card'])],
  competing_explanations: [{ description: 'correlation candidate', supporting_claim_ids: [], card_id: 'hyc-abcdef0123456789', status: 'LIVE' }],
  unresolved_contradictions: [],
  coverage: { questions_total: 1, answered: 1, abstained: 0, coverage_gaps: [] },
  abstentions: [],
  status: 'READY_FOR_REVIEW',
  reasons: ['all statements carry entailing evidence'],
  execution: { executor_id: 'exec-s2-005-a', pid: 1234, nonce: 'n-a-55f41bab6f1b53bc', clock: T0 },
  testedImplementationCommit: null,
};

const rejects = (name, mutate, label) => {
  const fixture = clone(FIXTURES[name]);
  mutate(fixture);
  assert.throws(() => requireValid(name, fixture), undefined, label ?? 'mutation must be rejected');
};

describe('S2-005 contract schemas', () => {
  for (const name of Object.keys(FIXTURES)) {
    test(`${name} accepts a fully populated fixture`, () => {
      requireValid(name, clone(FIXTURES[name]));
    });
  }

  test('unknown contract versions are rejected', () => {
    for (const name of Object.keys(FIXTURES)) rejects(name, (f) => { f.contractVersion = '2.0.0'; });
  });

  test('missing required fields are rejected', () => {
    rejects('retrieval-request', (f) => { delete f.as_of; });
    rejects('retrieval-request', (f) => { delete f.budget; });
    rejects('retrieval-hit', (f) => { delete f.span; });
    rejects('retrieval-hit', (f) => { delete f.quote_digest; });
    rejects('retrieval-run', (f) => { delete f.execution; });
    rejects('evidence-map', (f) => { delete f.entries; });
    rejects('hypothesis-card', (f) => { delete f.falsifiers; });
    rejects('hypothesis-card', (f) => { delete f.test_design; });
    rejects('synthesis-result', (f) => { delete f.status; });
    rejects('synthesis-result', (f) => { delete f.reasons; });
  });

  test('invalid enum values are rejected', () => {
    rejects('retrieval-request', (f) => { f.mode = 'semantic'; });
    rejects('retrieval-hit', (f) => { f.reason = 'BECAUSE'; });
    rejects('evidence-map', (f) => { f.entries[0].entailment_status = 'PROBABLY'; });
    rejects('hypothesis-card', (f) => { f.card_type = 'CAUSAL_PROOF'; });
    rejects('synthesis-result', (f) => { f.status = 'DONE'; });
  });

  test('mode membership in allowed_retrieval_modes is a runtime cross-field rule, not a schema matter', () => {
    // the schema cannot express set membership across fields; the engine
    // rejects it with MODE_NOT_ALLOWED (tested in retrieval.test.mjs)
    const request = clone(FIXTURES['retrieval-request']);
    request.allowed_retrieval_modes = ['lexical'];
    request.mode = 'graph';
    requireValid('retrieval-request', request);
  });

  test('single-domain hypothesis cards are rejected (cross-domain >= 2 required)', () => {
    rejects('hypothesis-card', (f) => { f.originating_domains = ['epidemiology']; });
  });

  test('digest pattern violations are rejected', () => {
    rejects('retrieval-hit', (f) => { f.quote_digest = 'not-a-digest'; });
    rejects('retrieval-run', (f) => { f.index_hash = 'xyz'; });
  });

  test('unknown extra properties are rejected', () => {
    rejects('retrieval-request', (f) => { f.secret_backdoor = true; });
    rejects('retrieval-hit', (f) => { f.truth_score = 0.9; });
    rejects('synthesis-result', (f) => { f.final_truth = 'yes'; });
  });

  test('hypothesis-card with a causal assertion but HYPOTHESIS type is not a schema matter but an engine rule', () => {
    // the schema allows causal_assertion boolean; the ENGINE (classifyRelation)
    // forbids it outside MECHANISM_CLAIM — tested in synthesis.test.mjs
    const card = clone(FIXTURES['hypothesis-card']);
    card.proposed_relation.causal_assertion = true;
    requireValid('hypothesis-card', card);
  });
});
