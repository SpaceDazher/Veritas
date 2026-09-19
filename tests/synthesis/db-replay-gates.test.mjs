import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dbReplayIssues} from '../../scripts/s2-005-db-replay.mjs';

const run = (overrides = {}) => ({
  status: 'COMPLETED', caseCount: 55, decisionCounts: {PASS: 55},
  graphDigest: 'a'.repeat(64), executor_id: 'a', clock: '2026-01-01T00:00:00Z',
  dbPid: 1, integrity: Object.fromEntries([
    'private_leaks', 'unauthorized_hits', 'future_leaks', 'stale_hits',
    'provenance_substitutions', 'causal_overclaims', 'facts_from_analogy',
    'hidden_contradictions', 'silent_exclusions', 'duplicate_side_effects',
    'authority_expansions', 'type_promotions_without_review',
  ].map((key) => [key, 0])),
  decisions: Array.from({length: 55}, (_, i) => ({case_id: `case-${i}`, decision: 'PASS'})),
  ...overrides,
});

test('DB replay rejects two identically broken runs rather than treating agreement as success', () => {
  const a = run({decisionCounts: {ERROR: 55}, decisions: run().decisions.map((d) => ({...d, decision: 'ERROR'}))});
  const b = run({...a, executor_id: 'b', dbPid: 2, clock: '2026-02-01T00:00:00Z'});
  assert.match(dbReplayIssues(a, b).join(' '), /ERROR|not-pass/i);
});

test('DB replay rejects nonzero integrity counters in either run', () => {
  const a = run();
  const b = run({executor_id: 'b', dbPid: 2, clock: '2026-02-01T00:00:00Z', integrity: {...a.integrity, private_leaks: 1}});
  assert.match(dbReplayIssues(a, b).join(' '), /integrity/i);
});

test('DB replay accepts complete independent clean runs', () => {
  const a = run();
  const b = run({executor_id: 'b', dbPid: 2, clock: '2026-02-01T00:00:00Z'});
  assert.deepEqual(dbReplayIssues(a, b), []);
});
