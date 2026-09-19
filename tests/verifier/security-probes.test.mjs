// S2-006 wave 3: adversarial security probes A–S (spec §12, §14 gate 8).
// Every probe carries an HONEST status pass|failed|not_run (review P2-6):
// an attempted violation that is correctly blocked/detected is 'pass', a
// succeeded violation is 'failed', and an offline-impossible surface is
// 'not_run' — never silently green. Probe S is green ONLY through the
// PostgreSQL crash/restart phase of scripts/s2-006-db-replay.mjs; the
// aggregate hard counters must stay zero.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { PROBE_IDS, runAllSecurityProbes, runSecurityProbe } from '../../src/lib/verifier/probes.mjs';

// run once at module load (top-level await is fine in ESM, describe bodies
// must stay synchronous)
const suite = await runAllSecurityProbes();

// Deterministic fixtures of the DB crash/restart phase result (the shape the
// aggregator derives from evidence/s2-006-db-comparison.json crashPhase).
const GREEN_DB_CRASH_PHASE = Object.freeze({
  ok: true,
  status: 'PASS',
  source: 'evidence/s2-006-db-comparison.json crashPhase',
});
const RED_DB_CRASH_PHASE = Object.freeze({
  ok: false,
  status: 'FAIL',
  issues: ['crash-a:not-completed'],
  source: 'evidence/s2-006-db-comparison.json crashPhase',
});
const suiteDbGreen = await runAllSecurityProbes({ probeSDbCrashPhase: GREEN_DB_CRASH_PHASE });
const suiteDbRed = await runAllSecurityProbes({ probeSDbCrashPhase: RED_DB_CRASH_PHASE });

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

describe('S2-006 security probes: honest offline statuses (review P2-6)', () => {
  test('offline: 18 probes pass, probe S is honestly NOT_RUN_DB, zero failed', () => {
    assert.equal(suite.probes.length, 19);
    for (const probe of suite.probes) {
      assert.ok(['pass', 'failed', 'not_run'].includes(probe.status), `probe ${probe.id} must carry a status`);
      if (probe.id === 'S') {
        assert.equal(probe.status, 'not_run', 'probe S is NOT_RUN_DB without the DB crash phase');
        assert.equal(probe.ok, false, 'NOT_RUN_DB is not green');
        assert.ok((probe.notRun ?? []).some((n) => n.startsWith('NOT_RUN_DB')));
      } else {
        assert.equal(probe.status, 'pass', `probe ${probe.id} must pass offline`);
        assert.equal(probe.ok, true, `probe ${probe.id} must pass`);
      }
    }
    assert.equal(suite.totals.pass, 18);
    assert.equal(suite.totals.failed, 0);
    assert.equal(suite.totals.not_run, 1);
    assert.equal(suite.totals.ok, 18);
  });

  test('probe S turns green ONLY through a green DB crash/restart phase', () => {
    const s = suiteDbGreen.probes.find((p) => p.id === 'S');
    assert.equal(s.status, 'pass');
    assert.equal(s.ok, true);
    assert.equal(s.notRun, undefined);
    assert.equal(suiteDbGreen.totals.pass, 19);
    assert.equal(suiteDbGreen.totals.not_run, 0);
    assert.equal(suiteDbGreen.totals.failed, 0);
  });

  test('a red DB crash/restart phase FAILS probe S (never silently green)', () => {
    const s = suiteDbRed.probes.find((p) => p.id === 'S');
    assert.equal(s.status, 'failed');
    assert.equal(s.ok, false);
    assert.equal(suiteDbRed.totals.failed, 1);
  });

  test('hard counters are zero while green; a failed probe counts its actual violation', () => {
    for (const [name, s] of [['offline', suite], ['db-green', suiteDbGreen]]) {
      assert.equal(s.totals.attemptedViolations >= 19, true, `${name}: every probe attempts at least one violation`);
      assert.equal(s.totals.actualViolations, 0, name);
      assert.equal(s.hardCounters.total, 0, name);
      assert.equal(s.hardCounters.unauthorizedLeakageEvents, 0, name);
      assert.equal(s.hardCounters.lockedLabelAccessEvents, 0, name);
      assert.equal(s.hardCounters.producerSelfReviewEvents, 0, name);
      assert.equal(s.hardCounters.upstreamArtifactMutationEvents, 0, name);
      assert.equal(s.hardCounters.unauthorizedSideEffectEvents, 0, name);
    }
    // the red DB variant honestly reports the succeeded violation (never 0)
    assert.equal(suiteDbRed.hardCounters.unauthorizedSideEffectEvents, 1);
    assert.equal(suiteDbRed.totals.failed, 1);
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
      if (probe.id === 'S') {
        // offline run: honestly NOT_RUN_DB, the offline state machine still exercised
        assert.equal(probe.status, 'not_run');
        assert.equal(probe.actualViolations, 0);
      } else {
        assert.equal(probe.status, 'pass');
        assert.equal(probe.ok, true);
        assert.equal(probe.actualViolations, 0);
      }
    });
  }
});
