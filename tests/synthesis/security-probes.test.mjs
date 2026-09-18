// S2-005 adversarial probes A–L: every probe must hold against the production
// retrieval/synthesis path (todo §8). Failures here are hard gate violations.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { runAllProbes, ALL_PROBES } from '../../src/lib/synthesis/probes.mjs';

describe('S2-005 adversarial probes A–L', () => {
  test('all twelve probes are defined', () => {
    assert.equal(ALL_PROBES.length, 12);
    assert.deepEqual(ALL_PROBES.map(([id]) => id), ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L']);
  });

  test('every probe passes fail-closed', async () => {
    const report = await runAllProbes();
    const failed = report.probes.filter((p) => !p.ok).map((p) => `${p.probe}: ${JSON.stringify(p.observed).slice(0, 160)}`);
    assert.deepEqual(report.failures, [], `probes failed: ${failed.join(' | ')}`);
    assert.equal(report.ok, true);
  });

  test('each probe reports its expected-vs-observed evidence', async () => {
    const report = await runAllProbes();
    for (const probe of report.probes) {
      assert.ok(probe.description, `${probe.probe} must describe itself`);
      assert.ok(probe.expected, `${probe.probe} must declare its expectation`);
      assert.ok(probe.observed !== undefined, `${probe.probe} must report observations`);
    }
  });
});
