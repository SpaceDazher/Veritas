// S2-005 retrieval engine tests: determinism, ACL-before-scoring, as_of
// freeze, stale exclusion, family collapse, budget enforcement, mode gating
// and the leak audit (todo §3, §4, §6).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  tokenize,
  buildRetrievalIndex,
  scoreBM25,
  scoreVector,
  embed,
  reciprocalRankFusion,
  executeRetrievalRequest,
  auditRunForLeaks,
  RETRIEVAL_CONFIG,
} from '../../src/lib/synthesis/retrieval.mjs';

const ACL_PROJECT = { visibility: 'project', workspace_id: 'ws-corpus', tenant_id: 'tn-corpus', allowed_workspace_ids: [], allowed_principal_ids: [] };
const ACL_PRIVATE = { visibility: 'private', workspace_id: 'ws-corpus', tenant_id: 'tn-corpus', allowed_workspace_ids: [], allowed_principal_ids: ['prn-user-2'] };

function claim(claimId, text, overrides = {}) {
  return {
    claim_id: claimId,
    revision: 1,
    workspace_id: 'ws-corpus',
    tenant_id: 'tn-corpus',
    acl: ACL_PROJECT,
    epistemic_type: 'FACT_CLAIM',
    polarity: 'affirmative',
    normalized_text: text,
    original_text: text,
    lifecycle: 'PROPOSED',
    segment_id: `seg-${claimId}`,
    span: { start: 0, end: text.length },
    quote_digest: 'b'.repeat(64),
    source_family_id: `fam-${claimId}`,
    domain: 'epidemiology',
    published_at: '2024-01-01T09:00:00.000Z',
    ...overrides,
  };
}

const SCOPE = { workspaceId: 'ws-corpus', principalId: 'prn-user-1' };
const AS_OF = '2025-06-01T00:00:00.000Z';

const REQUEST = (overrides = {}) => ({
  contractVersion: '1.0.0',
  request_id: 'req-test-0001',
  actor: 'prn-user-1',
  workspace_id: 'ws-corpus',
  query: { text: 'asthma incidence urban children', task_class: 'research', question_kind: 'local' },
  as_of: AS_OF,
  domains: [],
  languages: ['en'],
  geography: null,
  time_window: null,
  source_policy: { allowed_source_families: [] },
  budget: { max_candidates: 100, max_operations: 50000, timeout_ms: 5000 },
  allowed_retrieval_modes: ['lexical', 'vector', 'fusion', 'graph'],
  mode: 'lexical',
  corpus_version: '1.0.0',
  index_version: '1.0.0',
  seed: 0,
  ...overrides,
});

describe('S2-005 retrieval: tokenizer', () => {
  test('tokenization is deterministic, lowercase, stopword-filtered', () => {
    assert.deepEqual(tokenize('The Air Pollution and the Asthma!'), ['air', 'pollution', 'asthma']);
  });
});

describe('S2-005 retrieval: ACL before scoring', () => {
  test('private nodes never enter the candidate set for a denied actor', () => {
    const claims = [
      claim('clm-a', 'Air pollution exposure increased asthma incidence by 18% among urban children in 2023.'),
      claim('clm-priv', 'Unpublished trial data showed 34% mortality reduction in a sealed cohort during 2023.', { acl: ACL_PRIVATE, domain: 'epidemiology' }),
    ];
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    assert.equal(index.N, 1);
    assert.equal(index.exclusions.EXCLUDED_ACL, 1);
    assert.ok(!index.entries.some((e) => e.claim_id === 'clm-priv'));
    // no embedding, no trace: the private vector must not exist either
    assert.equal(index.vectors.has('clm-priv'), false);
  });

  test('an allowed principal sees the private node', () => {
    const claims = [claim('clm-priv', 'sealed cohort mortality', { acl: ACL_PRIVATE })];
    const index = buildRetrievalIndex({ claims, scope: { workspaceId: 'ws-corpus', principalId: 'prn-user-2' }, asOf: AS_OF });
    assert.equal(index.N, 1);
  });
});

describe('S2-005 retrieval: as_of freeze and stale exclusion', () => {
  test('documents published after as_of are excluded with a visible count', () => {
    const claims = [
      claim('clm-now', 'asthma incidence now', { published_at: '2024-01-01T09:00:00.000Z' }),
      claim('clm-future', 'asthma incidence future', { published_at: '2026-02-01T09:00:00.000Z' }),
    ];
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    assert.equal(index.N, 1);
    assert.equal(index.exclusions.EXCLUDED_AS_OF, 1);
  });

  test('stale and superseded claims never enter new evidence retrieval', () => {
    const claims = [
      claim('clm-ok', 'asthma incidence fresh'),
      claim('clm-stale', 'asthma incidence stale', { lifecycle: 'STALE' }),
      claim('clm-sup', 'asthma incidence superseded', { lifecycle: 'SUPERSEDED' }),
    ];
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    assert.equal(index.N, 1);
    assert.equal(index.exclusions.EXCLUDED_STALE, 2);
  });
});

describe('S2-005 retrieval: scoring determinism', () => {
  const claims = [
    claim('clm-a', 'Air pollution exposure increased asthma incidence by 18% among urban children in 2023.'),
    claim('clm-b', 'Bike lane expansion increased cycling trips by 24% in Copenhagen during 2023.', { domain: 'urban_mobility' }),
    claim('clm-c', 'Flu vaccination coverage reached 61% of adults in 2023.'),
  ];

  test('BM25 ranks the lexically matching claim first with stable tie-breaks', () => {
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    const ranked = scoreBM25(index, tokenize('asthma incidence urban children'));
    assert.equal(ranked[0].claim_id, 'clm-a');
    const again = scoreBM25(index, tokenize('asthma incidence urban children'));
    assert.deepEqual(ranked, again);
  });

  test('hashed tf-idf vectors are deterministic and collide-free here', () => {
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    const v1 = embed(index, 'asthma incidence');
    const v2 = embed(index, 'asthma incidence');
    assert.deepEqual([...v1], [...v2]);
    const ranked = scoreVector(index, v1);
    assert.equal(ranked[0].claim_id, 'clm-a');
  });

  test('reciprocal rank fusion is order-deterministic', () => {
    const a = [{ claim_id: 'clm-a', score: 2 }, { claim_id: 'clm-b', score: 1 }];
    const b = [{ claim_id: 'clm-b', score: 2 }, { claim_id: 'clm-c', score: 1 }];
    assert.deepEqual(reciprocalRankFusion([a, b]), reciprocalRankFusion([a, b]));
  });

  test('index digest is a function of entries only', () => {
    const i1 = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    const i2 = buildRetrievalIndex({ claims: [...claims].reverse(), scope: SCOPE, asOf: AS_OF });
    assert.equal(i1.indexHash, i2.indexHash);
  });
});

describe('S2-005 retrieval: family collapse and request execution', () => {
  test('same-family candidates collapse to one included hit with visible reasons', () => {
    const claims = [
      claim('clm-r1', 'Sleep deprivation decreased memory performance by 21% in lab studies in 2023.', { source_family_id: 'fam-sleep' }),
      claim('clm-r2', 'Sleep deprivation decreased memory performance sharply in lab studies in 2023.', { source_family_id: 'fam-sleep' }),
    ];
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    const run = executeRetrievalRequest(REQUEST({ query: { text: 'sleep deprivation memory performance lab studies', task_class: 'research', question_kind: 'local' }, mode: 'lexical' }), { index });
    assert.equal(run.status, 'COMPLETED');
    const included = run.hits.filter((h) => h.included);
    const collapsed = run.hits.filter((h) => h.reason === 'EXCLUDED_FAMILY_COLLAPSED');
    assert.equal(included.length, 1);
    assert.equal(collapsed.length, 1);
    assert.equal(run.excludedCount.EXCLUDED_FAMILY_COLLAPSED, 1);
  });

  test('a mode outside allowed_retrieval_modes fails closed', () => {
    const claims = [claim('clm-a', 'asthma incidence urban children')];
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    const run = executeRetrievalRequest(REQUEST({ allowed_retrieval_modes: ['lexical'], mode: 'graph' }), { index });
    assert.equal(run.status, 'FAILED');
    assert.equal(run.failures[0].code, 'MODE_NOT_ALLOWED');
  });

  test('budget exhaustion abstains instead of answering partially', () => {
    const claims = [
      claim('clm-a', 'asthma incidence urban children air pollution exposure increased'),
      claim('clm-b', 'vaccination coverage adults reached'),
    ];
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    const run = executeRetrievalRequest(REQUEST({ budget: { max_candidates: 100, max_operations: 1, timeout_ms: 5000 }, mode: 'lexical' }), { index });
    assert.equal(run.status, 'ABSTAINED');
    assert.equal(run.abstentions[0].reason, 'BUDGET_EXHAUSTED');
    assert.equal(run.cost.budget_exhausted, true);
  });

  test('an empty-for-scope index abstains explicitly', () => {
    const claims = [claim('clm-priv', 'sealed cohort', { acl: ACL_PRIVATE })];
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    const run = executeRetrievalRequest(REQUEST(), { index });
    assert.equal(run.status, 'ABSTAINED');
    assert.equal(run.abstentions[0].reason, 'NO_CANDIDATES');
  });

  test('with execution provenance a contract-valid retrieval-run payload is produced', () => {
    const claims = [claim('clm-a', 'Air pollution exposure increased asthma incidence by 18% among urban children in 2023.')];
    const index = buildRetrievalIndex({ claims, scope: SCOPE, asOf: AS_OF });
    const run = executeRetrievalRequest(REQUEST(), {
      index,
      execution: { executor_id: 'exec-test', pid: process.pid, nonce: 'n-test-00000001', output_root_digest: 'c'.repeat(64), clock: '2026-01-15T08:00:00.000Z' },
    });
    assert.equal(run.status, 'COMPLETED');
    assert.equal(run.runPayload.status, 'COMPLETED');
    assert.equal(run.runPayload.hits.length, run.hits.length);
    assert.equal(run.runPayload.execution.executor_id, 'exec-test');
  });
});

describe('S2-005 retrieval: leak audit', () => {
  test('a smuggled private hit is detected and fails the audit', () => {
    const claims = [
      claim('clm-a', 'public claim'),
      claim('clm-priv', 'private claim', { acl: ACL_PRIVATE }),
    ];
    const audit = auditRunForLeaks({ hits: [{ claim_id: 'clm-priv' }], allClaims: claims, scope: SCOPE, asOf: AS_OF });
    assert.equal(audit.ok, false);
    assert.equal(audit.counters.private_hits, 1);
  });

  test('a future-published hit is detected', () => {
    const claims = [claim('clm-fut', 'future claim', { published_at: '2026-01-01T09:00:00.000Z' })];
    const audit = auditRunForLeaks({ hits: [{ claim_id: 'clm-fut' }], allClaims: claims, scope: SCOPE, asOf: AS_OF });
    assert.equal(audit.ok, false);
    assert.equal(audit.counters.future_hits, 1);
  });

  test('a clean hit list passes', () => {
    const claims = [claim('clm-a', 'public claim')];
    const audit = auditRunForLeaks({ hits: [{ claim_id: 'clm-a' }], allClaims: claims, scope: SCOPE, asOf: AS_OF });
    assert.equal(audit.ok, true);
  });
});

describe('S2-005 retrieval: frozen configuration', () => {
  test('the configuration constants are frozen', () => {
    assert.equal(RETRIEVAL_CONFIG.top_k, 10);
    assert.throws(() => { RETRIEVAL_CONFIG.top_k = 5; }, /readonly|Cannot assign/, 'config must be immutable');
  });
});
