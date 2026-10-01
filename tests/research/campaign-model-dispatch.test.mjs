import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { modelTrialArgv, assertPinnedModelImage, runModelTrial } from '../../scripts/s2-008-campaign-adapter.mjs';
import { chargeFor, chargingStep, preflightCharge, DISPATCHABLE_MODEL_ARMS } from '../../scripts/s2-008-campaign-run.mjs';

const ROOT = path.resolve(import.meta.dirname, '../..');
const pin = JSON.parse(readFileSync(path.join(ROOT, 'evidence/s2-008-campaign/model-image-pin-v4.json'), 'utf8'));
const prereg = JSON.parse(readFileSync(path.join(ROOT, 'corpus/s2-008-campaign/preregistration.v4.in-force.json'), 'utf8'));
const MODEL = 'arm-model-zai-glm53flash';
const digest = pin.first;
const pinV7 = JSON.parse(readFileSync(path.join(ROOT, 'evidence/s2-008-campaign/model-image-pin-v7.json'), 'utf8'));
const preregV7 = JSON.parse(readFileSync(path.join(ROOT, 'corpus/s2-008-campaign/preregistration.v7.in-force.json'), 'utf8'));
const manifestV7 = JSON.parse(readFileSync(path.join(ROOT, 'corpus/s2-008-campaign/manifest.json'), 'utf8'));
manifestV7.preregistration = {file:'preregistration.v7.in-force.json',status:'IN_FORCE',preregistration_digest:preregV7.preregistration_digest};

test('model argv names the model arm, blind input, and signed v4 in-force document', () => {
  const argv = modelTrialArgv({ armId: MODEL, seed: 20260926, dryRun: true });
  assert.deepEqual(argv, [
    '/usr/local/bin/node',
    '/opt/veritas/scripts/s2-008-campaign-arm-model.mjs',
    '/opt/veritas/corpus/s2-008-campaign/cases/holdout.blind.json',
    '/tmp/model-out.json',
    MODEL,
    '/opt/veritas/corpus/s2-008-campaign/preregistration.v4.in-force.json',
    '20260926',
    '--dry-run',
  ]);
  assert.equal(modelTrialArgv({ armId: MODEL, seed: 20260926, dryRun: false, remainingTokens: 5000000 }).includes('--dry-run'), false);
});

test('each model launch checks local Id and Digest against v4 pin and signed commitment', () => {
  const inspect = () => ({ Id: digest.imageId, Digest: digest.digest, Architecture: digest.architecture });
  assert.deepEqual(assertPinnedModelImage({ pin, prereg, inspect }), {
    imageId: digest.imageId, digest: digest.digest, architecture: digest.architecture,
  });
  assert.throws(() => assertPinnedModelImage({
    pin, prereg,
    inspect: () => ({ Id: digest.imageId, Digest: 'sha256:' + '0'.repeat(64), Architecture: digest.architecture }),
  }), /ISOLATION_IMAGE_DIGEST_MISMATCH/);
  assert.throws(() => assertPinnedModelImage({
    pin, prereg: { ...prereg, executor: { ...prereg.executor, model_image: { ...prereg.executor.model_image, content_commitment: 'fake' } } }, inspect,
  }), /MODEL_CONTENT_COMMITMENT_MISMATCH/);
});

test('model branch runs the model image and carries its own token report and sidecar ref', async () => {
  let called = 0;
  const sidecars = [];
  const output = {
    arm_id: MODEL, outcome_class: 'DRY_RUN', dry_run: true,
    budget: { currency: 'tokens', spent_tokens: 0, unreconciled_spend: false },
    executor: { model_calls: 0 },
    predictions: [{ case_id: 'x', predicted: 'MINOR' }],
    container: { pid: 123, node_version: 'v22.0.0' },
  };
  const payload = Buffer.from(JSON.stringify(output)).toString('base64');
  const observation = {
    exitCode: 0, signal: null, timedOut: false,
    stdout: 'ADAPTER_OK arm=' + MODEL + ' seed=20260926 n=1 predictions=1 tokens=0 usd=0 dry_run=true pid=123 node=v22.0.0\n'
      + 'ADAPTER_JSON 1/1 ' + payload + '\nADAPTER_JSON_END ' + payload.length + '\n',
    stderr: '',
  };
  const result = await runModelTrial({
    armId: MODEL, seed: 20260926, timeoutMs: 180000, dryRun: true,
    pin, prereg, runLabel: 'v4-test', predictionsSink: (digestValue, body) => sidecars.push([digestValue, body]),
    inspect: () => ({ Id: digest.imageId, Digest: digest.digest, Architecture: digest.architecture }),
    executeDry: (invocation) => {
      called += 1;
      assert.equal(invocation.image, digest.imageId);
      assert.equal(invocation.podmanArgv.includes('--dry-run'), true);
      return observation;
    },
  });
  assert.equal(called, 1);
  assert.equal(result.ok, true);
  assert.equal(result.output.budget.spent_tokens, 0);
  assert.deepEqual(result.record.arm_report, output);
  assert.equal(sidecars.length, 1);
  assert.equal(result.record.predictions.digest, sidecars[0][0]);
  assert.equal(result.record.predictions.rows, 1);
});

test('token accounting is proved from the arm report for the enabled model arm', () => {
  assert.deepEqual([...DISPATCHABLE_MODEL_ARMS], [MODEL]);
  assert.equal(preflightCharge({ currency: 'tokens', armId: MODEL, dispatchableArms: [MODEL] }).refusal, undefined);
  assert.equal(preflightCharge({ currency: 'tokens', armId: 'arm-type-chore', dispatchableArms: [MODEL] }).units, 0);
  const own = { budget: { currency: 'tokens', spent_tokens: 10233, unreconciled_spend: false, measured_by: 'turn_end.usage.totalTokens' } };
  const charged = chargeFor({ currency: 'tokens', armId: MODEL, armOutput: own, dispatchableArms: [MODEL] });
  assert.equal(charged.units, 10233);
  assert.equal(charged.unit, 'EXECUTOR_REPORTED_TOKENS');
  const partial = chargingStep({
    currency: 'tokens', spentUnits: 0, grantedUnits: 5000000,
    armId: MODEL, dispatchableArms: [MODEL],
    armOutput: { budget: { currency: 'tokens', unreconciled_spend: true, spent_tokens: 6735 } },
  });
  assert.equal(partial.action, 'refuse');
  assert.match(partial.detail, /ARM_UNRECONCILED_SPEND/);
  assert.equal(partial.units, 6735);
  assert.equal(partial.lower_bound, true);
  assert.match(chargeFor({ currency: 'tokens', armId: MODEL, armOutput: { budget: { currency: 'tokens' } }, dispatchableArms: [MODEL] }).refusal, /ARM_REPORTED_NO_TOKENS/);
  assert.match(chargeFor({ currency: 'tokens', armId: MODEL, armOutput: { budget: { currency: 'dollars', spent_tokens: 1 } }, dispatchableArms: [MODEL] }).refusal, /ARM_BUDGET_NOT_IN_THIS_CURRENCY/);
});


test('v7 runner charges the model report, zero for regex controls, and keeps every seed separate', async () => {
  const { runV4Campaign } = await import('../../scripts/s2-008-campaign-run.mjs');
  const calls = [];
  const remainingCaps = [];
  const fakeResult = (armId, seed, tokens) => ({
    ok: true,
    output: {
      outcome_class: tokens === 0 ? 'DRY_RUN' : 'MEASURED',
      budget: { currency: 'tokens', spent_tokens: tokens, unreconciled_spend: false },
      executor: { model_calls: tokens === 0 ? 0 : 1 },
      predictions: [{ case_id: 'x', predicted: 'MINOR' }],
    },
    record: { image: pinV7.first.imageId, image_digest: pinV7.first.digest, exit_code: 0, output_digest: 'sample', predictions: { digest: 'sidecar', rows: 1, unparsed: 0 } },
  });
  const successor = preregV7;
  const successorPin = pinV7;
  const report = await runV4Campaign({
    label: 'test-dispatch',
    write: false,
    prereg: successor,
    manifest: manifestV7,
    modelPin: successorPin,
    dispatchableArms: [MODEL],
    resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
    now: () => Date.parse('2026-09-30T00:00:00.000Z'),
    runModel: async ({ armId, seed, remainingTokens }) => { calls.push([armId, seed]); remainingCaps.push(remainingTokens); return fakeResult(armId, seed, 10233); },
    runRegex: ({ armId, seed }) => { calls.push([armId, seed]); return fakeResult(armId, seed, 0); },
    buildRegex: () => ({ pin: { imageId: 'sha256:' + 'b'.repeat(64) } }),
  });
  assert.equal(calls.length, 9);
  assert.match(report.raw_run_id, /^s2-008c-v7-test-dispatch-/);
  assert.equal(typeof report.nonce, 'string');
  assert.match(report.base.commit_sha, /^[0-9a-f]{40}$/);
  assert.match(report.base.tree_sha, /^[0-9a-f]{40}$/);
  assert.equal(report.spent_units, 30699);
  assert.deepEqual(remainingCaps, [5000000, 4989767, 4979534]);
  assert.deepEqual(report.charges.map((row) => row.units), [10233, 10233, 10233, 0, 0, 0, 0, 0, 0]);
  assert.ok(report.charges.every((row) => row.unit === 'EXECUTOR_REPORTED_TOKENS'));
  assert.equal(report.trials[0].seeds.length, 3);
  assert.deepEqual(report.trials[0].seeds.map((row) => row.seed), preregV7.seed_rule.seeds);
  assert.equal(report.trials[0].seeds[0].predictions.digest, 'sidecar');
});

test('v7 runner refuses unknown or unreconciled model spend without starting another seed', async () => {
  const { runV4Campaign } = await import('../../scripts/s2-008-campaign-run.mjs');
  let calls = 0;
  const successor = preregV7;
  const successorPin = pinV7;
  const report = await runV4Campaign({
    label: 'test-refuse', write: false, prereg: successor,
    manifest: manifestV7,
    modelPin: successorPin, dispatchableArms: [MODEL],
    resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
    now: () => Date.parse('2026-09-30T00:00:00.000Z'),
    runModel: async () => { calls += 1; return { ok: false, output: { budget: { currency: 'tokens', spent_tokens: 0, unreconciled_spend: true } }, record: { exit_code: 10 } }; },
    runRegex: () => { throw new Error('regex launched after refusal'); },
    buildRegex: () => ({ pin: { imageId: 'sha256:' + 'b'.repeat(64) } }),
  });
  assert.equal(calls, 1);
  assert.equal(report.status, 'BLOCKED');
  assert.match(report.reason, /ARM_UNRECONCILED_SPEND/);
  assert.equal(report.spent_units, 0);
});


test('v7 runner preserves an unknown-spend model exception and stops before another seed', async () => {
  const { runV4Campaign } = await import('../../scripts/s2-008-campaign-run.mjs');
  let attempts = 0;
  const report = await runV4Campaign({
    label: 'exception-probe', arm: MODEL, write: false,
    prereg: preregV7, manifest: manifestV7, modelPin: pinV7,
    dispatchableArms: [MODEL],
    resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
    now: () => Date.parse('2026-09-30T00:00:00.000Z'),
    runModel: async () => { attempts += 1; throw new Error('upstream failure with unknown spend'); },
    runRegex: () => { throw new Error('regex should not run after model refusal'); },
    buildRegex: () => { throw new Error('regex should not build for model-only trial'); },
  });
  assert.equal(attempts, 1);
  assert.equal(report.status, 'BLOCKED');
  assert.equal(report.unreconciled_spend, true);
  assert.equal(report.spent_units, null);
  assert.equal(report.model_calls, null);
  assert.equal(report.unknown_model_attempts, null);
  assert.equal(report.launches, 0);
  assert.equal(report.unknown_launch_attempts, 1);
  assert.match(report.reason, /ARM_UNRECONCILED_SPEND/);
  assert.equal(report.trials.length, 1);
  assert.equal(report.trials[0].seeds.length, 1);
  assert.equal(report.trials[0].seeds[0].outcome_class, 'INFRA');
});

test('v5 runner refuses paid dispatch until the signed total timeout policy is resealed', async () => {
  const { runV4Campaign } = await import('../../scripts/s2-008-campaign-run.mjs');
  const v5 = JSON.parse(readFileSync(path.join(ROOT, 'corpus/s2-008-campaign/preregistration.v5.in-force.json')));
  const v5Pin = JSON.parse(readFileSync(path.join(ROOT, 'evidence/s2-008-campaign/model-image-pin-v5.json')));
  let attempts = 0;
  const report = await runV4Campaign({
    label: 'exception-probe', arm: MODEL, write: false,
    prereg: v5,
    manifest: { preregistration: { file: 'preregistration.v5.in-force.json',
      status: 'IN_FORCE', preregistration_digest: v5.preregistration_digest } },
    modelPin: v5Pin,
    runModel: async () => { attempts += 1; throw new Error('upstream failure with unknown spend'); },
    buildRegex: () => { throw new Error('regex should not build'); },
  });
  assert.equal(attempts, 0);
  assert.equal(report.status, 'BLOCKED');
  assert.equal(report.code, 'MODEL_TOTAL_TIMEOUT_RESEAL_REQUIRED');
  assert.equal(report.spent_units, 0);
  assert.equal(report.launches, 0);
  assert.match(report.reason, /MODEL_TOTAL_TIMEOUT_RESEAL_REQUIRED/);
  assert.deepEqual(report.trials, []);
});

test('model INFRA retains the own-arm stop and unknown-spend report in durable launch evidence', async () => {
  const output = {
    arm_id: MODEL, outcome_class: 'INFRA', dry_run: false,
    budget: { currency: 'tokens', spent_tokens: 0, unreconciled_spend: true },
    executor: { model_calls: 0, model_attempts: 1 },
    stop: { reason: 'MODEL_USAGE_NOT_REPORTED', unreconciled_spend: true, stopped_before_case: 'x' },
    predictions: [], container: { pid: 123, node_version: 'v22.0.0' },
  };
  const payload = Buffer.from(JSON.stringify(output)).toString('base64');
  const result = await runModelTrial({
    armId: MODEL, seed: 20260926, timeoutMs: 180000, dryRun: true,
    pin, prereg, runLabel: 'infra-retention', predictionsSink: () => {},
    inspect: () => ({ Id: digest.imageId, Digest: digest.digest, Architecture: digest.architecture }),
    executeDry: () => ({
      exitCode: 10, signal: null, timedOut: false,
      stdout: 'ADAPTER_OK arm=' + MODEL + ' seed=20260926 n=1 predictions=0 tokens=0 usd=0 dry_run=false pid=123 node=v22.0.0\n'
        + 'ADAPTER_JSON 1/1 ' + payload + '\nADAPTER_JSON_END ' + payload.length + '\n',
      stderr: '',
    }),
  });
  assert.equal(result.ok, false);
  const retained = JSON.parse(JSON.stringify(result.record)).arm_report;
  assert.deepEqual(retained, output);
  assert.equal(retained.stop.reason, 'MODEL_USAGE_NOT_REPORTED');
  assert.equal(retained.budget.unreconciled_spend, true);
});


test('v9 host runner retains confirmed partial tokens and calls as lower bounds', async () => {
  const { runV4Campaign } = await import('../../scripts/s2-008-campaign-run.mjs');
  let attempts = 0;
  const output = {
    arm_id: MODEL, outcome_class: 'INFRA', dry_run: false,
    budget: {
      currency: 'tokens', spent_tokens: 6735, usd_spent: 0,
      measured_by: 'pi final assistant usage', unreconciled_spend: true,
    },
    executor: { model_calls: 11, model_attempts: 12 },
    stop: {
      reason: 'MODEL_ENDPOINT_UNREACHABLE', unreconciled_spend: true,
      spent_tokens_confirmed: 6735,
    },
    predictions: [],
  };
  const report = await runV4Campaign({
    label: 'partial-spend', arm: MODEL, write: false,
    prereg: preregV7, manifest: manifestV7, modelPin: pinV7,
    dispatchableArms: [MODEL],
    resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
    now: () => Date.parse('2026-09-30T00:00:00.000Z'),
    runModel: async () => {
      attempts += 1;
      return { ok: false, output, record: { arm_report: output, exit_code: 10 } };
    },
    runRegex: () => { throw new Error('regex launched after unreconciled model spend'); },
    buildRegex: () => { throw new Error('regex built after unreconciled model spend'); },
  });
  assert.equal(attempts, 1);
  assert.equal(report.status, 'BLOCKED');
  assert.match(report.reason, /ARM_UNRECONCILED_SPEND/);
  assert.equal(report.unreconciled_spend, true);
  assert.equal(report.spent_units, 6735);
  assert.equal(report.spent_units_is_lower_bound, true);
  assert.equal(report.model_calls, 11);
  assert.equal(report.model_calls_is_lower_bound, true);
  assert.equal(report.unknown_model_attempts, 1);
  assert.equal(report.launches, 1);
  assert.equal(report.unknown_launch_attempts, 0);
  assert.equal(report.charges.length, 1);
  assert.equal(report.charges[0].units, 6735);
  assert.equal(report.charges[0].lower_bound, true);
});

test('an injected MEASURED success cannot bypass the unreconciled-spend launch stop', async () => {
  const { runV4Campaign } = await import('../../scripts/s2-008-campaign-run.mjs');
  let attempts = 0;
  const output = {
    outcome_class: 'MEASURED',
    budget: { currency: 'tokens', spent_tokens: 50, unreconciled_spend: true },
    executor: { model_calls: 2, model_attempts: 3 },
  };
  const report = await runV4Campaign({
    label: 'unreconciled-ok', arm: MODEL, write: false,
    prereg: preregV7, manifest: manifestV7, modelPin: pinV7,
    dispatchableArms: [MODEL],
    resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
    now: () => Date.parse('2026-09-30T00:00:00.000Z'),
    runModel: async () => { attempts += 1; return { ok: true, output, record: { arm_report: output } }; },
  });
  assert.equal(attempts, 1);
  assert.equal(report.status, 'BLOCKED');
  assert.equal(report.spent_units, 50);
  assert.equal(report.spent_units_is_lower_bound, true);
  assert.equal(report.model_calls, 2);
  assert.equal(report.model_calls_is_lower_bound, true);
  assert.equal(report.unknown_model_attempts, 1);
});

test('invalid usage and call counters stay unknown in blocked host reports', async () => {
  const { runV4Campaign } = await import('../../scripts/s2-008-campaign-run.mjs');
  for (const [label, output] of [
    ['invalid-counts', {
      outcome_class: 'INFRA',
      budget: { currency: 'tokens', spent_tokens: '6735', unreconciled_spend: true },
      executor: { model_calls: '11', model_attempts: 12 },
    }],
    ['missing-counts', {
      outcome_class: 'INFRA',
      budget: { currency: 'tokens', unreconciled_spend: true },
    }],
  ]) {
    const report = await runV4Campaign({
      label, arm: MODEL, write: false,
      prereg: preregV7, manifest: manifestV7, modelPin: pinV7,
      dispatchableArms: [MODEL],
      resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
      now: () => Date.parse('2026-09-30T00:00:00.000Z'),
      runModel: async () => ({ ok: false, output, record: { arm_report: output } }),
    });
    assert.equal(report.status, 'BLOCKED');
    assert.equal(report.spent_units, null);
    assert.equal(report.spent_units_is_lower_bound, false);
    assert.equal(report.model_calls, null);
    assert.equal(report.model_calls_is_lower_bound, false);
    assert.equal(report.unknown_model_attempts, null);
  }
});


test('positive unknown model attempts stop before another seed even when budget is marked reconciled', async () => {
  const { runV4Campaign } = await import('../../scripts/s2-008-campaign-run.mjs');
  let attempts = 0;
  const output = {
    outcome_class: 'MEASURED',
    budget: { currency: 'tokens', spent_tokens: 6735, unreconciled_spend: false },
    executor: { model_calls: 11, model_attempts: 12 },
  };
  const report = await runV4Campaign({
    label: 'attempt-mismatch', arm: MODEL, write: false,
    prereg: preregV7, manifest: manifestV7, modelPin: pinV7,
    dispatchableArms: [MODEL],
    resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
    now: () => Date.parse('2026-09-30T00:00:00.000Z'),
    runModel: async () => { attempts += 1; return { ok: true, output, record: { arm_report: output } }; },
  });
  assert.equal(attempts, 1);
  assert.equal(report.status, 'BLOCKED');
  assert.match(report.reason, /ARM_UNRECONCILED_MODEL_ATTEMPTS:1/);
  assert.equal(report.spent_units, 6735);
  assert.equal(report.spent_units_is_lower_bound, true);
  assert.equal(report.model_calls, 11);
  assert.equal(report.model_calls_is_lower_bound, true);
  assert.equal(report.unknown_model_attempts, 1);
});
