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
import { compareRuns } from '../../scripts/verify-s2-002.mjs';

const REQUIRED_COUNTERS = [
  'cross_tenant_success',
  'authority_expansion',
  'fs_network_secret_escapes',
  'survivors_after_cancellation',
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

  test('survivors after cancellation are zero (observed on this platform)', () => {
    for (const run of [runA, runB]) {
      const trial = run.observations.find((o) => o.trialId === 'sandbox/cancellation-survivors');
      assert.ok(trial, 'cancellation trial must run');
      assert.equal(trial.decision, 'ALLOW', 'expected behaviour (zero survivors) must be observed');
      assert.equal(trial.survivors, 0);
    }
  });

  test('Run A vs Run B decision mismatch is zero', () => {
    const comparison = compareRuns(runA.summary, runB.summary, runA.observations, runB.observations);
    assert.equal(comparison.mismatchedDecisions, 0);
    assert.equal(comparison.comparedTrials, runA.summary.trialCount);
    assert.deepEqual(comparison.counterViolations, []);
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
