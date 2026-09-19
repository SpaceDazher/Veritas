// S2-006 wave 3: adversarial security probes A–S (spec §12, §14 gate 8).
// Every probe must report ok:true (the attempted violation is correctly
// blocked or detected), the aggregate hard counters must be zero, and any
// offline-impossible surface must be explicitly NOT_RUN_* — never silent.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { PROBE_IDS, runAllSecurityProbes, runSecurityProbe } from '../../src/lib/verifier/probes.mjs';

// run once at module load (top-level await is fine in ESM, describe bodies
// must stay synchronous)
const suite = await runAllSecurityProbes();

describe('S2-006 security probes: orchestrator surface', () => {
  test('all probes A–S are registered exactly once', () => {
    assert.equal(PROBE_IDS.length, 19);
    assert.deepEqual(new Set(PROBE_IDS).size, 19);
    assert.deepEqual(PROBE_IDS[0], 'A');
    assert.deepEqual(PROBE_IDS[PROBE_IDS.length - 1], 'S');
  });

  test('unknown probe id is a typed error, never a silent skip', async () => {
    await assert.rejects(() => runSecurityProbe('Z'), (e) => e.code === 'PROBE_UNKNOWN');
  });
});

describe('S2-006 security probes: full A–S suite (spec §12)', () => {
  test('all 19 probes executed and report ok:true', () => {
    assert.equal(suite.probes.length, 19);
    const failed = suite.probes.filter((p) => p.ok !== true);
    assert.deepEqual(
      failed.map((p) => ({ id: p.id, expected: p.expected, observed: p.observed })),
      [],
      `failing probes: ${failed.map((p) => p.id).join(', ')}`,
    );
    for (const probe of suite.probes) {
      assert.equal(probe.ok, true, `probe ${probe.id} must pass`);
      assert.equal(typeof probe.name, 'string');
      assert.ok(probe.expected && typeof probe.expected === 'object');
      assert.ok(probe.observed && typeof probe.observed === 'object');
    }
  });

  test('hard counters are zero (spec §14 gate 8): attempts blocked, none actual', () => {
    assert.equal(suite.totals.attemptedViolations >= 19, true, 'every probe attempts at least one violation');
    assert.equal(suite.totals.actualViolations, 0);
    assert.equal(suite.hardCounters.total, 0);
    assert.equal(suite.hardCounters.unauthorizedLeakageEvents, 0);
    assert.equal(suite.hardCounters.lockedLabelAccessEvents, 0);
    assert.equal(suite.hardCounters.producerSelfReviewEvents, 0);
    assert.equal(suite.hardCounters.upstreamArtifactMutationEvents, 0);
    assert.equal(suite.hardCounters.unauthorizedSideEffectEvents, 0);
  });

  test('offline-impossible surfaces are explicitly NOT_RUN_*, never silent', () => {
    // the only offline-impossible half in A–S is the PostgreSQL crash/restart
    // replay of probe S; it must be declared, not hidden
    assert.ok(suite.notRun.some((n) => n.startsWith('NOT_RUN_DB')), 'probe S DB replay must be declared NOT_RUN_DB');
    for (const probe of suite.probes) {
      if (probe.notRun) {
        assert.ok(Array.isArray(probe.notRun) && probe.notRun.every((n) => n.startsWith('NOT_RUN_')));
      }
    }
  });

  // per-probe spot checks: each spec §12 scenario maps to its probe id
  for (const probe of suite.probes) {
    test(`probe ${probe.id}: ${probe.name}`, () => {
      assert.equal(probe.ok, true);
      assert.equal(probe.actualViolations, 0);
    });
  }
});
