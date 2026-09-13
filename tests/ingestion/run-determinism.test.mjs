// S2-003 cross-run determinism regression test.
// Guards against content-identity drift between corpus runs inside one
// process (the original defect lived in a pooled-buffer byteOffset race in a
// fixture fetchFn and produced different snapshot ids for identical bytes).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { runCorpus } from '../../scripts/s2-003-run.mjs';

describe('S2-003 corpus determinism (single process)', () => {
  test('five consecutive runs produce identical decisions and content identity', async () => {
    const first = await runCorpus({
      runId: 'det-0', executorId: 'det-exec', nonce: 'n-det000000000000',
      outputRoot: 'tmp/det-0', clockNow: '2026-01-15T08:00:00.000Z',
    });
    assert.equal(first.quarantined, false);
    const signature = (run) => JSON.stringify(run.observations.map((o) => [o.case_id, o.decision, o.terminals, o.snapshot_ids]));
    const baseline = signature(first);
    for (let i = 1; i < 5; i += 1) {
      const next = await runCorpus({
        runId: `det-${i}`, executorId: `det-exec-${i}`, nonce: `n-det${String(i).padStart(13, '0')}`,
        outputRoot: `tmp/det-${i}`, clockNow: i % 2 === 0 ? '2026-01-15T08:00:00.000Z' : '2026-09-09T09:09:09.000Z',
      });
      assert.equal(signature(next), baseline, `run det-${i} diverged`);
    }
  });
});
