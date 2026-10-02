import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { modelImagePaths } from '../../scripts/s2-008-campaign-model-image.mjs';
import { modelTrialArgv } from '../../scripts/s2-008-campaign-adapter.mjs';
import { activeCampaignVersion, loadV4TrialPredictions, verifyV4FrozenTable } from '../../scripts/s2-008-campaign-evaluate.mjs';

const evidence = 'evidence/s2-008-campaign';
const reconciliation = JSON.parse(fs.readFileSync(evidence + '/reconciliation-v9-a.json', 'utf8'));
const receipt = JSON.parse(fs.readFileSync(evidence + '/provider-receipt-v9-a-attempt-12.json', 'utf8'));
const priorRunBytes = fs.readFileSync(evidence + '/run-v9-a.json');
const priorSidecarBytes = fs.readFileSync(reconciliation.prior_sidecar_file);
const baseBytes = fs.readFileSync('corpus/s2-008-campaign/preregistration.v9.in-force.json');
const base = JSON.parse(baseBytes);
const sourcePin = JSON.parse(fs.readFileSync(evidence + '/model-image-pin-v9-preseal.json', 'utf8'));
const table = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/frozen-table.v3.json'));

test('v10 is a separate run/image version over the in-force v9 base', () => {
  assert.deepEqual(modelImagePaths('v10', { preseal: true }), {
    tag: 'localhost/veritas-s2-008-model:v10',
    stagedPrereg: 'corpus/s2-008-campaign/preregistration.v9.in-force.json',
    pinFile: 'evidence/s2-008-campaign/model-image-pin-v10-preseal.json',
    schema: 's2-008-model-image-pin/10',
  });
  assert.equal(modelImagePaths('v10').pinFile, 'evidence/s2-008-campaign/model-image-pin-v10.json');
  const argv = modelTrialArgv({
    armId: base.trial_list[0].arm_id,
    seed: 20260926,
    remainingTokens: 5000000,
    preregRule: 's2-008-prereg-v10',
  });
  assert.equal(argv.includes('/opt/veritas/corpus/s2-008-campaign/preregistration.v10.in-force.json'), true);
  assert.equal(activeCampaignVersion({ preregistration: { file: 'preregistration.v10.in-force.json' } }), 'v10');
});

test('v10 requires the complete v9 A reconciliation, sidecar and provider receipt', async () => {
  const {
    assertV9AReconciliation,
    readV10ReconciliationInputs,
  } = await import('../../scripts/s2-008-campaign-v10-approval.mjs');
  const inputs = readV10ReconciliationInputs();
  const accepted = assertV9AReconciliation(inputs);
  assert.equal(accepted.ok, true);
  assert.equal(accepted.priorRunSha256, '5958cdead994c3474a0496cf3bd41b2e9a4de31b02cf82075ff67339ac135b20');
  assert.equal(accepted.priorSidecarSha256, '69910f08dbb5d60f1373b58400df8e62c49faf3799e8d0c435ffd2f3a830be63');
  assert.equal(accepted.canonicalDigest, canonicalDigest(reconciliation));
  assert.equal(accepted.receiptDigest, canonicalDigest(receipt));
  assert.equal(accepted.localTokens, 6735);
  assert.equal(accepted.providerReceiptTokens, 577);
  assert.equal(accepted.actualTokens, 7312);
  assert.equal(accepted.modelCalls, 12);

  assert.throws(() => assertV9AReconciliation({ ...inputs, reconciliation: null }), /V10_RECONCILIATION_MISSING/);
  assert.throws(() => assertV9AReconciliation({ ...inputs, priorRunBytes: Buffer.concat([priorRunBytes, Buffer.from('x')]) }), /V10_RECONCILIATION_PRIOR_RUN_HASH/);
  assert.throws(() => assertV9AReconciliation({ ...inputs, priorSidecarBytes: Buffer.concat([priorSidecarBytes, Buffer.from('x')]) }), /V10_RECONCILIATION_PRIOR_SIDECAR_HASH/);

  const wrongBase = structuredClone(reconciliation);
  wrongBase.preregistration_digest = '0'.repeat(64);
  assert.throws(() => assertV9AReconciliation({ ...inputs, reconciliation: wrongBase }), /V10_RECONCILIATION_PRIOR_BINDING/);
  const incomplete = structuredClone(reconciliation);
  incomplete.completeness.unfiltered = false;
  assert.throws(() => assertV9AReconciliation({ ...inputs, reconciliation: incomplete }), /V10_RECONCILIATION_COMPLETENESS/);
  const missingUsage = structuredClone(reconciliation);
  missingUsage.rows[0].input = null;
  assert.throws(() => assertV9AReconciliation({ ...inputs, reconciliation: missingUsage }), /V10_RECONCILIATION_ROW/);
  const duplicateId = structuredClone(reconciliation);
  duplicateId.rows[1].generation_id = duplicateId.rows[0].generation_id;
  assert.throws(() => assertV9AReconciliation({ ...inputs, reconciliation: duplicateId }), /V10_RECONCILIATION_GENERATION_ID/);
  const wrongTotal = structuredClone(reconciliation);
  wrongTotal.actual_tokens -= 1;
  assert.throws(() => assertV9AReconciliation({ ...inputs, reconciliation: wrongTotal }), /V10_RECONCILIATION_TOTALS/);
  const wrongReceipt = structuredClone(receipt);
  wrongReceipt.data.native_tokens_completion += 1;
  assert.throws(() => assertV9AReconciliation({ ...inputs, receipt: wrongReceipt }), /V10_RECONCILIATION_RECEIPT/);
  const missingReceiptUsage = structuredClone(receipt);
  missingReceiptUsage.data.native_tokens_prompt = null;
  assert.throws(() => assertV9AReconciliation({ ...inputs, receipt: missingReceiptUsage }), /V10_RECONCILIATION_RECEIPT/);
});

test('v10 draft accepts only its own preseal pin and keeps the frozen scope', async () => {
  const {
    assertV10PresealPin,
    createV10Draft,
    readV10MeasurementOnDisk,
    readV10ReconciliationInputs,
  } = await import('../../scripts/s2-008-campaign-v10-approval.mjs');
  const inputs = {
    base,
    baseBytes,
    pin: sourcePin,
    measurement: readV10MeasurementOnDisk(),
    ...readV10ReconciliationInputs(),
  };
  assert.throws(() => assertV10PresealPin({ pin: sourcePin, baseBytes }), /V10_PRESEAL_PIN/);
  assert.throws(() => createV10Draft(inputs), /V10_PRESEAL_PIN/);
});

test('v10 prediction loading retains the v9 correlation and accounting requirements', () => {
  const entry = { trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash' };
  const seed = 20260926;
  const holdoutCases = [{ case_id: 'synthetic-case', label: 'MINOR' }];
  const file = 'evidence/s2-008-campaign/predictions-v10-a-' + entry.trial_id + '-' + seed + '.json';
  const make = ({ generationId = 'gen-v10-test-001', predicted = 'MINOR', unparsed = 0, output = 4 } = {}) => {
    const body = {
      kind: 's2-008-campaign-predictions/1',
      run: 'a',
      arm_id: entry.arm_id,
      seed,
      unparsed,
      model_calls: 1,
      spent_tokens: 578,
      usd_spent: 0,
      outcome_class: 'MEASURED',
      rows: [{ case_id: 'synthetic-case', predicted }],
      accounting: {
        schema: 's2-008-model-accounting/1',
        policy: 'GENERATION_ID_REQUIRED',
        calls: 1,
        tokens: 578,
        prompt_tokens: 574,
        reported_cost_usd: 0,
        rows: [{
          case_id: 'synthetic-case',
          generation_id: generationId,
          correlation_status: 'CORRELATED',
          input: 432,
          output,
          cacheRead: 142,
          cacheWrite: 0,
          prompt_tokens: 574,
          prompt_token_basis: 'input+cacheRead+cacheWrite',
          totalTokens: 578,
          reported_cost_usd: 0,
          usage_components_consistent: output === 4,
          usage_component_issue: output === 4 ? null : 'TOKEN_COMPONENT_MISMATCH',
        }],
      },
    };
    return {
      body,
      trial: {
        trial_id: entry.trial_id,
        arm_id: entry.arm_id,
        seeds: [{ seed, predictions: { file, digest: canonicalDigest(body), rows: 1, unparsed } }],
      },
      readFile: () => JSON.stringify(body),
    };
  };
  const load = (fixture) => loadV4TrialPredictions({
    trial: fixture.trial,
    entry,
    runLabel: 'a',
    seeds: [seed],
    holdoutCases,
    readFile: fixture.readFile,
    root: '/tmp',
    version: 'v10',
  });

  const valid = load(make());
  assert.equal(valid.available, true);
  assert.deepEqual(valid.provider_generation_ids, ['gen-v10-test-001']);
  const missingId = load(make({ generationId: null }));
  assert.equal(missingId.available, false);
  assert.match(missingId.reason, /ACCOUNTING_GENERATION_ID_INVALID/);
  const inconsistentUsage = load(make({ output: 3 }));
  assert.equal(inconsistentUsage.available, false);
  assert.match(inconsistentUsage.reason, /ACCOUNTING_CASE_SET_MISMATCH/);

  const unparsed = make({ predicted: 'UNPARSED', unparsed: 1 });
  const unparsedLoaded = load(unparsed);
  assert.equal(unparsedLoaded.available, true);
  assert.equal(unparsedLoaded.per_seed[0].unparsed, 1);
  assert.equal(unparsedLoaded.per_seed[0].agreeing, 0);

  const differentlyPredictedA = load(make({ predicted: 'MINOR' }));
  const differentlyPredictedB = load(make({ predicted: 'MAJOR' }));
  assert.equal(differentlyPredictedA.available, true);
  assert.equal(differentlyPredictedB.available, true);
  assert.deepEqual(differentlyPredictedA.per_seed[0].agreement, [1]);
  assert.deepEqual(differentlyPredictedB.per_seed[0].agreement, [0]);
  assert.notDeepEqual(
    differentlyPredictedA.per_seed[0].agreement,
    differentlyPredictedB.per_seed[0].agreement,
    'different A/B sidecars are independently scored rather than rejected for inequality',
  );
});

test('v10 keeps the deterministic frozen-table agreement separate from human acceptance', () => {
  const manifest = {
    preregistration: { file: 'preregistration.v10.in-force.json' },
    frozen_table: { file: 'frozen-table.v3.json', digest: canonicalDigest(table) },
  };
  const verdict = verifyV4FrozenTable({ prereg: base, manifest, frozenTable: table });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.verdict, 'AGREES');
  assert.deepEqual(verdict.remarks, []);
  assert.equal(activeCampaignVersion(manifest), 'v10');
  assert.equal(base.approval.in_force, true);
});
