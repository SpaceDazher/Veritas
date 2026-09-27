// S2-002 phase 5 — independent replay measurement (Run A / Run B).
// RED-first suite for the frozen corpus runner and the comparison. The child
// runner executes the whole trial corpus in its own process with a distinct
// executor id, nonce base and output root; the comparison must show zero
// decision mismatches and every hard counter at zero.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runCorpus } from '../../scripts/s2-002-run.mjs';
import { compareRuns, HARD_COUNTER_TRIALS } from '../../scripts/verify-s2-002.mjs';

const REQUIRED_COUNTERS = [
  'cross_tenant_success',
  'authority_expansion',
  'fs_network_secret_escapes',
  'allow_after_revocation_commit',
  'missing_or_censored_trials',
];

function tempOutputRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 's2-002-corpusrun-'));
}

const RUN_A = await runCorpus({
  runId: 'run-a',
  executorId: 'exec-alpha-test',
  nonceBase: 'nb-alpha',
  outputRoot: tempOutputRoot(),
});
const RUN_B = await runCorpus({
  runId: 'run-b',
  executorId: 'exec-beta-test',
  nonceBase: 'nb-beta',
  outputRoot: tempOutputRoot(),
});

describe('S2-002 independent replay: corpus runner', () => {
  const runA = RUN_A;
  const runB = RUN_B;

  test('both runs execute the same frozen corpus with distinct provenance', () => {
    assert.equal(runA.summary.trialCount, runB.summary.trialCount);
    assert.ok(runA.summary.trialCount >= 250, `corpus too small: ${runA.summary.trialCount}`);
    assert.notEqual(runA.summary.executorId, runB.summary.executorId);
    assert.notEqual(runA.summary.nonceBase, runB.summary.nonceBase);
    assert.notEqual(runA.summary.outputRoot, runB.summary.outputRoot);
    assert.equal(runA.summary.corpusDigest, runB.summary.corpusDigest, 'corpus must be frozen across runs');
  });

  test('raw observations are complete: nothing missing or censored', () => {
    for (const run of [runA, runB]) {
      assert.equal(run.observations.length, run.summary.trialCount);
      for (const observation of run.observations) {
        assert.ok(observation.trialId, 'observation must reference its trial');
        assert.ok(['ALLOW', 'DENY', 'BLOCKED_SANDBOX'].includes(observation.decision), JSON.stringify(observation));
      }
    }
  });

  test('ACL matrix covers 20 principals over all workspaces', () => {
    const matrixTrials = runA.observations.filter((o) => o.kind === 'acl_matrix');
    const principals = new Set(matrixTrials.map((o) => o.principalId));
    assert.equal(principals.size, 20);
  });

  for (const counter of REQUIRED_COUNTERS) {
    test(`hard counter ${counter} is zero in both runs`, () => {
      assert.equal(runA.summary.counters[counter], 0, `run-a ${counter}`);
      assert.equal(runB.summary.counters[counter], 0, `run-b ${counter}`);
    });
  }

  test('revocation decision latency: at least 100 trials, max <= 5000 ms, in each run', () => {
    for (const run of [runA, runB]) {
      const stats = run.summary.revocationLatency;
      assert.ok(stats.trials >= 100, `trials ${stats.trials}`);
      assert.ok(stats.maxMs <= 5000, `max ${stats.maxMs}ms`);
      assert.ok(stats.allowAfterCommit === 0);
    }
  });

  test('the survivor count is honest: measured zero, or explicitly unmeasured', () => {
    // The cancellation control is Windows-only. On a host that cannot exercise
    // it the run must say so — decision BLOCKED_SANDBOX, survivors null,
    // notRun true — and the summary counter must be null rather than a
    // fabricated zero. Asserting "zero survivors" unconditionally is what
    // forced a declined measurement to masquerade as a safety failure.
    for (const run of [runA, runB]) {
      const trial = run.observations.find((o) => o.trialId === 'sandbox/cancellation-survivors');
      assert.ok(trial, 'the cancellation trial must be present in the observations');
      if (trial.notRun === true) {
        assert.equal(trial.decision, 'BLOCKED_SANDBOX', 'an unexercised control is blocked, not allowed or denied');
        assert.equal(trial.survivors, null, 'an unexercised control has no survivor count');
        assert.equal(trial.match, null, 'an unexercised control is neither a pass nor a mismatch');
        assert.deepEqual(trial.reasonCodes, ['SANDBOX_CONTROL_NOT_EXERCISED_ON_PLATFORM']);
        assert.equal(
          run.summary.counters.survivors_after_cancellation, null,
          'an unmeasured survivor count must be null, never 0',
        );
        continue;
      }
      assert.equal(trial.decision, 'ALLOW', 'expected behaviour (zero survivors) must be observed');
      assert.equal(trial.survivors, 0);
      assert.equal(run.summary.counters.survivors_after_cancellation, 0);
    }
  });

  test('an unexercised hard control is reported, counted and never a pass', () => {
    // The property that makes the run honest on a host that cannot measure:
    // the not-run control is VISIBLE in the record, it is COUNTED, and the
    // gate refuses to certify while it stands.
    const notRun = runA.observations.filter((o) => o.notRun === true);
    for (const observation of notRun) {
      assert.equal(observation.match, null);
      assert.ok(observation.trialId, 'a not-run control must still name its trial');
    }
    assert.equal(
      runA.summary.counters.not_run_controls, notRun.length,
      'not-run controls must be counted, so a skip is reported rather than hidden',
    );
    if (notRun.length > 0) {
      const comparison = compareRuns(runA.summary, runB.summary, runA.observations, runB.observations);
      assert.equal(comparison.ok, false, 'a run with an unexercised hard control must NOT pass the gate');
      assert.ok(
        comparison.counterViolations.some((v) => v.includes('hardControlNotRun=')),
        `the gate must name the unexercised control, got: ${JSON.stringify(comparison.counterViolations)}`,
      );
    }
  });

  // The negative-counter guard that used to be asserted here has moved to
  // PR #42, which owns issue #41 and carries a stricter form of it
  // (`Number.isInteger` as well as `value < 0`). Asserting it here would make
  // this suite a second, weaker copy of the control, and would fail again the
  // moment the two branches are reconciled.

  test('Run A vs Run B: identical decisions, and only honest violations remain', () => {
    const comparison = compareRuns(runA.summary, runB.summary, runA.observations, runB.observations);
    // The replay itself must be exact: every trial decided identically, and
    // the trial count must match what the oracle expects — the mismatch that
    // used to appear here (283 run vs 282 oracle) was the oracle being scoped
    // to Windows while the runner executed the link-escape trial on POSIX too.
    assert.equal(comparison.mismatchedDecisions, 0);
    assert.equal(comparison.comparedTrials, runA.summary.trialCount);

    // WHICH violations are permitted depends on WHICH controls this host
    // could not exercise, so both sets are derived from the run instead of
    // being asserted as a fixed list. The previous shape hard-coded
    // `expectedOracleViolations === []` while, two lines below, allowing
    // NOT_RUN_ON_THIS_PLATFORM entries — so a host that also failed to create
    // the junction (a Windows account without the privilege, a container
    // without CAP_SYS_ADMIN) failed this test for a reason that has nothing to
    // do with the property under test.
    const notRunIds = new Set(
      [...runA.observations, ...runB.observations].filter((o) => o.notRun === true).map((o) => o.trialId),
    );
    const expectedOracleViolations = [...notRunIds]
      .filter((id) => !HARD_COUNTER_TRIALS.has(id))
      .flatMap((id) => ['run-a', 'run-b'].map((run) => ({ run, trialId: id, reason: 'NOT_RUN_ON_THIS_PLATFORM' })));
    assert.deepEqual(
      comparison.expectedOracleViolations.map(({ run, trialId, reason }) => ({ run, trialId, reason })),
      expectedOracleViolations,
      'the only permitted oracle violations are the controls this platform declined to run',
    );

    // Every violation that remains must be NAMED as a not-run one, on the run
    // that declined it. Anything else is a real finding and must not be
    // waved through by this test.
    const survivors = comparison.counterViolations.filter(
      (violation) => !/^run-[ab]\/(hardControlNotRun=|survivors_after_cancellation=null)/.test(violation),
    );
    assert.deepEqual(survivors, [], `unexplained counter violations: ${JSON.stringify(survivors)}`);
    for (const [label, run] of [['run-a', runA], ['run-b', runB]]) {
      for (const id of new Set(run.observations.filter((o) => o.notRun === true).map((o) => o.trialId))) {
        if (HARD_COUNTER_TRIALS.has(id)) {
          assert.ok(
            comparison.counterViolations.includes(`${label}/hardControlNotRun=${id}`),
            `the unexercised hard control must block the gate under its own name: ${id}`,
          );
        }
      }
    }
  });

  test('runner persists raw observations and summary to the output root', () => {
    for (const run of [runA, runB]) {
      const obsPath = path.join(run.summary.outputRoot, 'observations.json');
      const sumPath = path.join(run.summary.outputRoot, 'summary.json');
      assert.ok(fs.existsSync(obsPath));
      assert.ok(fs.existsSync(sumPath));
      const persisted = JSON.parse(fs.readFileSync(obsPath, 'utf8'));
      assert.equal(persisted.length, run.summary.trialCount);
    }
  });
});

describe('S2-002 comparator is fail-closed', () => {
  const sumA = RUN_A.summary;
  const sumB = RUN_B.summary;
  const obsA = RUN_A.observations;
  const obsB = RUN_B.observations;

  test('empty runs are violations, never ok', () => {
    const comparison = compareRuns(sumA, sumB, [], []);
    assert.equal(comparison.ok, false);
    assert.ok(comparison.counterViolations.length > 0, 'empty runs must produce violations');
  });

  test('a self-consistent singleton cannot replace the exact frozen corpus', () => {
    const counters = Object.fromEntries(REQUIRED_COUNTERS.map((name) => [name, 0]));
    const forgedSummary = {
      ...sumA,
      trialCount: 1,
      corpusDigest: 'forged',
      counters,
      revocationLatency: { trials: 100, maxMs: 0, allowAfterCommit: 0 },
    };
    const forged = [{
      trialId: 'only-one-forged-cell',
      expected: 'ALLOW',
      decision: 'ALLOW',
      match: true,
    }];
    const comparison = compareRuns(forgedSummary, forgedSummary, forged, forged);
    assert.equal(comparison.ok, false);
    assert.ok(comparison.counterViolations.some((value) => value.includes('missingTrial')),
      comparison.counterViolations.join(','));
  });

  test('missing or NaN counters are violations, never silently passing', () => {
    const broken = {
      ...sumA,
      counters: { ...sumA.counters, authority_expansion: Number.NaN },
      revocationLatency: { ...sumA.revocationLatency, maxMs: Number.NaN },
    };
    const comparison = compareRuns(broken, sumB, obsA, obsB);
    assert.equal(comparison.ok, false);
    assert.ok(comparison.counterViolations.some((v) => v.includes('authority_expansion')), comparison.counterViolations);
    assert.ok(comparison.counterViolations.some((v) => v.includes('revocationMaxMs')), comparison.counterViolations);
  });

  test('decisions must match the frozen expected oracle, not just each other', () => {
    const tampered = obsA.map((o) =>
      o.trialId === 'acl/prn-agent-eve/ws-eve-private' ? { ...o, decision: 'ALLOW' } : o,
    );
    const comparison = compareRuns(sumA, sumB, tampered, obsB);
    assert.equal(comparison.ok, false, 'an expected-DENY cell allowed in BOTH runs must still fail');
    assert.ok(comparison.expectedOracleViolations.some((v) => v.run === 'run-a' && v.trialId === 'acl/prn-agent-eve/ws-eve-private'));
  });

  test('sandbox observations failing their match flag violate the oracle', () => {
    const tampered = obsA.map((o) =>
      o.trialId === 'sandbox/fs-traversal' ? { ...o, decision: 'ALLOW', match: false, observed: 'ALLOWED' } : o,
    );
    const comparison = compareRuns(sumA, sumB, tampered, obsB);
    assert.equal(comparison.ok, false);
    assert.ok(comparison.expectedOracleViolations.some((v) => v.run === 'run-a' && v.trialId === 'sandbox/fs-traversal'));
  });

  test('summary trialCount contradicting observations is a violation', () => {
    const broken = { ...sumA, trialCount: sumA.trialCount + 5 };
    const comparison = compareRuns(broken, sumB, obsA, obsB);
    assert.equal(comparison.ok, false);
    assert.ok(comparison.counterViolations.some((v) => v.includes('trialCount')));
  });
});
