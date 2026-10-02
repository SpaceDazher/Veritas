import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { FROZEN_MEMBERS, preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import { assertPreregistration, preregistrationDigest as sharedPreregistrationDigest } from '../../src/lib/research/preregistration.mjs';
import { credentialEnvNameForPreregistration } from '../../scripts/s2-008-campaign-credential-env.mjs';
import { modelImagePaths } from '../../scripts/s2-008-campaign-model-image.mjs';
import { modelTrialArgv } from '../../scripts/s2-008-campaign-adapter.mjs';
import { childInvocationArgs, resolveProbePreregistrationPath } from '../../scripts/s2-008-campaign-probes.mjs';
import { activeCampaignVersion, evaluateV4Campaign, loadV4TrialPredictions, verifyV4FrozenTable } from '../../scripts/s2-008-campaign-evaluate.mjs';

const evidence = 'evidence/s2-008-campaign';
const reconciliation = JSON.parse(fs.readFileSync(evidence + '/reconciliation-v9-a.json', 'utf8'));
const receipt = JSON.parse(fs.readFileSync(evidence + '/provider-receipt-v9-a-attempt-12.json', 'utf8'));
const priorRunBytes = fs.readFileSync(evidence + '/run-v9-a.json');
const priorSidecarBytes = fs.readFileSync(reconciliation.prior_sidecar_file);
const baseBytes = fs.readFileSync('corpus/s2-008-campaign/preregistration.v9.in-force.json');
const base = JSON.parse(baseBytes);
const sourcePin = JSON.parse(fs.readFileSync(evidence + '/model-image-pin-v9-preseal.json', 'utf8'));
const table = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/frozen-table.v3.json'));

function makeV10PresealPin(stagedBytes) {
  const sources = {
    ...sourcePin.first.sources,
    prereg: createHash('sha256').update(stagedBytes).digest('hex'),
  };
  const covers = Object.keys(sources).filter((name) => name !== 'prereg').sort();
  const makeBuild = (previous) => ({
    ...previous,
    sources,
    source_digest: canonicalDigest(sources),
    content_commitment: canonicalDigest(Object.fromEntries(covers.map((name) => [name, sources[name]]))),
    content_commitment_covers: covers,
  });
  return {
    ...sourcePin,
    schema: 's2-008-model-image-pin/10',
    image_tag: 'localhost/veritas-s2-008-model:v10',
    first: makeBuild(sourcePin.first),
    second: makeBuild(sourcePin.second),
    commitment: { ...sourcePin.commitment, covers, excludes: ['prereg'] },
  };
}

const EVALUATION_CASE_ID = '16bb546d7b453454202c315c6106e3a56ec77444';

test('v10 preregistration is accepted by the shared digest and validation contract', () => {
  const prereg = structuredClone(base);
  prereg.rule = 's2-008-prereg-v10';
  prereg.preregistration_id = 'xpr-s2-008c-10';
  prereg.preregistration_digest = preregistrationDigest(prereg);
  assert.equal(sharedPreregistrationDigest(prereg), prereg.preregistration_digest);
  assert.equal(assertPreregistration(prereg), prereg);
});

test('v10 credential routing keeps the signed OpenRouter environment policy', () => {
  const prereg = structuredClone(base);
  prereg.rule = 's2-008-prereg-v10';
  prereg.preregistration_id = 'xpr-s2-008c-10';
  prereg.preregistration_digest = preregistrationDigest(prereg);
  assert.equal(credentialEnvNameForPreregistration(prereg), 'OPENROUTER_API_KEY');
});

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

test('v10 probe path reaches both probe children through the public resolver', () => {
  const root = '/tmp/veritas-probe-root';
  const selected = resolveProbePreregistrationPath('corpus/s2-008-campaign/preregistration.v10.in-force.json', root);
  assert.equal(selected, root + '/corpus/s2-008-campaign/preregistration.v10.in-force.json');
  assert.deepEqual(childInvocationArgs('crash', { preregPath: selected }), [
    'scripts/s2-008-campaign-probes.mjs', '--child', 'crash', '--prereg', selected,
  ]);
  assert.deepEqual(childInvocationArgs('restart', { preregPath: selected, stateFile: '/tmp/state.json', resultOut: '/tmp/result.json' }), [
    'scripts/s2-008-campaign-probes.mjs', '--child', 'restart',
    '--state', '/tmp/state.json', '--result-out', '/tmp/result.json', '--prereg', selected,
  ]);
});

test('probe path resolver keeps legacy default and rejects unsupported or escaping paths', () => {
  const root = '/tmp/veritas-probe-root';
  assert.equal(resolveProbePreregistrationPath(undefined, root), root + '/corpus/s2-008-campaign/preregistration.json');
  for (const requested of [
    'corpus/s2-008-campaign/preregistration.v11.in-force.json',
    'corpus/s2-008-campaign/preregistration.v100.in-force.json',
    '/etc/passwd',
    '../../etc/passwd',
  ]) {
    assert.throws(() => resolveProbePreregistrationPath(requested, root), /PROBE_PREREG_PATH_INVALID/);
  }
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
  const wrongLocalReceiptTime = structuredClone(reconciliation);
  wrongLocalReceiptTime.rows[0].receipt.created_at = '2000-01-01T00:00:00.000Z';
  assert.throws(() => assertV9AReconciliation({ ...inputs, reconciliation: wrongLocalReceiptTime }), /V10_RECONCILIATION_PROVIDER_EVENT/);
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

  const changedId = 'gen-1790862092-qxgqw1Rrl8DGvxXX6i2B';
  const alternateRequest = structuredClone(reconciliation);
  const alternateReceipt = structuredClone(receipt);
  const alternateRow = alternateRequest.rows.at(-1);
  alternateRow.generation_id = changedId;
  alternateRow.receipt.generation_id = changedId;
  alternateRow.receipt.data.id = changedId;
  alternateReceipt.generation_id = changedId;
  alternateReceipt.data.id = changedId;
  assert.throws(() => assertV9AReconciliation({
    ...inputs, reconciliation: alternateRequest, receipt: alternateReceipt,
  }), /V10_RECONCILIATION_PROVIDER_EVENT/);

  const outOfWindow = structuredClone(reconciliation);
  const outOfWindowReceipt = structuredClone(receipt);
  const stoppedRow = outOfWindow.rows.at(-1);
  stoppedRow.created_at = '2026-09-01T00:00:00.000Z';
  stoppedRow.receipt.created_at = stoppedRow.created_at;
  stoppedRow.receipt.data.created_at = stoppedRow.created_at;
  outOfWindowReceipt.data.created_at = stoppedRow.created_at;
  assert.throws(() => assertV9AReconciliation({
    ...inputs, reconciliation: outOfWindow, receipt: outOfWindowReceipt,
  }), /V10_RECONCILIATION_PROVIDER_EVENT/);

  const outOfOrder = structuredClone(reconciliation);
  [outOfOrder.rows[0], outOfOrder.rows[1]] = [outOfOrder.rows[1], outOfOrder.rows[0]];
  assert.throws(() => assertV9AReconciliation({ ...inputs, reconciliation: outOfOrder }), /V10_RECONCILIATION_PROVIDER_EVENT/);

  const wrongStoppedCase = structuredClone(reconciliation);
  wrongStoppedCase.rows.at(-1).case_id = '85f721b06317e335e560e5cf01f9235d970dfa74';
  wrongStoppedCase.missing_prediction_case_id = '85f721b06317e335e560e5cf01f9235d970dfa74';
  assert.throws(() => assertV9AReconciliation({ ...inputs, reconciliation: wrongStoppedCase }), /V10_RECONCILIATION_PROVIDER_EVENT/);

  const wrongGenerationTime = structuredClone(receipt);
  const wrongTimeRequest = structuredClone(reconciliation);
  wrongGenerationTime.data.generation_time = 180783;
  wrongTimeRequest.rows.at(-1).receipt.data.generation_time = 180783;
  assert.throws(() => assertV9AReconciliation({
    ...inputs, reconciliation: wrongTimeRequest, receipt: wrongGenerationTime,
  }), /V10_RECONCILIATION_PROVIDER_EVENT/);
});

test('v10 draft and approval bind the known v9 base and reject every frozen-member mutation', async () => {
  const {
    approveV10,
    assertV10PresealPin,
    createV10Draft,
    readV10MeasurementOnDisk,
    readV10ReconciliationInputs,
  } = await import('../../scripts/s2-008-campaign-v10-approval.mjs');
  const inputs = {
    base,
    baseBytes,
    pin: makeV10PresealPin(baseBytes),
    measurement: readV10MeasurementOnDisk(),
    ...readV10ReconciliationInputs(),
  };
  assert.throws(() => assertV10PresealPin({ pin: sourcePin, baseBytes }), /V10_PRESEAL_PIN/);
  const draft = createV10Draft(inputs);
  for (const member of FROZEN_MEMBERS) assert.deepEqual(draft[member], base[member], member);
  assert.equal(draft.restart_reconciliation.reconciled_campaign_tokens, 7312);
  assert.equal(draft.restart_reconciliation.reconciled_campaign_usd, 0);
  assert.equal(draft.executor.model_launch_timeout.per_model_call_timeout_ms, 180000);
  assert.equal(draft.budget_reservation.granted_units, 5000000);

  const approvalArgs = {
    ...inputs, table, principal: 'prn-daniil', label: 'Daniil', issuedAt: '2026-10-02T00:00:00.000Z',
  };
  const approved = approveV10({ ...approvalArgs, draft });
  assert.equal(approved.approval.status, 'APPROVED');
  assert.equal(approved.approval.in_force, false);
  for (const member of FROZEN_MEMBERS) {
    const moved = structuredClone(draft);
    const value = moved[member];
    if (Array.isArray(value)) moved[member] = [...value, 'mutation'];
    else if (value && typeof value === 'object') moved[member] = { ...value, test_mutation: true };
    else if (typeof value === 'number') moved[member] = value + 1;
    else moved[member] = String(value) + '-mutation';
    moved.preregistration_digest = preregistrationDigest(moved);
    assert.throws(() => approveV10({ ...approvalArgs, draft: moved }), new RegExp('APPROVAL_SCOPE_DRIFT:' + member));
  }

  const alteredBase = structuredClone(base);
  alteredBase.metric = { ...alteredBase.metric, name: alteredBase.metric.name + '-forged' };
  alteredBase.preregistration_digest = preregistrationDigest(alteredBase);
  const alteredBaseBytes = Buffer.from(JSON.stringify(alteredBase, null, 2) + '\n');
  assert.throws(() => createV10Draft({
    ...inputs,
    base: alteredBase,
    baseBytes: alteredBaseBytes,
    pin: makeV10PresealPin(alteredBaseBytes),
  }), /V10_BASE_NOT_IN_FORCE/);
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

function makeEvaluationFixture({ duplicateAcrossRuns = false, corruptSidecar = false, unparsedMismatch = false } = {}) {
  const seed = 20260926;
  const prereg = structuredClone(base);
  prereg.rule = 's2-008-prereg-v10';
  prereg.preregistration_id = 'xpr-s2-008c-10';
  prereg.holdout_access.case_count = 1;
  prereg.seed_rule.seeds = [seed];
  const frozenTable = structuredClone(table);
  frozenTable.n_holdout = 1;
  frozenTable.seeds = [seed];
  frozenTable.trial_list_digest = canonicalDigest(prereg.trial_list);
  prereg.expected_table_digest = canonicalDigest(frozenTable);
  prereg.preregistration_digest = preregistrationDigest(prereg);
  const manifest = {
    preregistration: {
      file: 'preregistration.v10.in-force.json',
      status: 'IN_FORCE',
      preregistration_digest: prereg.preregistration_digest,
    },
    frozen_table: { file: 'frozen-table.v3.json', digest: canonicalDigest(frozenTable) },
  };
  const campaignProbes = JSON.parse(fs.readFileSync(evidence + '/probes-v9.json', 'utf8'));
  campaignProbes.preregistration_digest = prereg.preregistration_digest;
  const securityControls = JSON.parse(fs.readFileSync(evidence + '/security-probes-v9.json', 'utf8'));
  const runBase = { commit_sha: campaignProbes.commit_sha, tree_sha: campaignProbes.tree_sha, worktree_dirty: false };
  securityControls.base = { ...securityControls.base, commit_sha: runBase.commit_sha, tree_sha: runBase.tree_sha };
  const sidecars = new Map();
  const runs = {};
  for (const label of ['a', 'b']) {
    const charges = [];
    const trials = [];
    let spentUnits = 0;
    let modelCalls = 0;
    for (const entry of prereg.trial_list) {
      const isModel = entry.arm_id === 'arm-model-zai-glm53flash';
      const predicted = label === 'a' ? 'MINOR' : 'MAJOR';
      const unparsed = unparsedMismatch && label === 'a' && isModel ? 0 : 0;
      const rows = [{ case_id: EVALUATION_CASE_ID, predicted: unparsedMismatch && label === 'a' && isModel ? 'UNPARSED' : predicted }];
      const generationId = duplicateAcrossRuns
        ? 'gen-v10-evaluation-duplicate'
        : 'gen-v10-evaluation-' + label;
      const body = {
        kind: 's2-008-campaign-predictions/1',
        run: label,
        arm_id: entry.arm_id,
        seed,
        unparsed,
        model_calls: isModel ? 1 : 0,
        spent_tokens: isModel ? 578 : 0,
        usd_spent: 0,
        rows,
      };
      if (isModel) {
        body.outcome_class = 'MEASURED';
        body.accounting = {
          schema: 's2-008-model-accounting/1',
          policy: 'GENERATION_ID_REQUIRED',
          calls: 1,
          tokens: 578,
          prompt_tokens: 574,
          reported_cost_usd: 0,
          rows: [{
            case_id: EVALUATION_CASE_ID,
            generation_id: generationId,
            correlation_status: 'CORRELATED',
            input: 432,
            output: 4,
            cacheRead: 142,
            cacheWrite: 0,
            prompt_tokens: 574,
            prompt_token_basis: 'input+cacheRead+cacheWrite',
            totalTokens: 578,
            reported_cost_usd: 0,
            usage_components_consistent: true,
            usage_component_issue: null,
          }],
        };
        spentUnits += 578;
        modelCalls += 1;
      }
      const file = 'evidence/s2-008-campaign/predictions-v10-' + label + '-' + entry.trial_id + '-' + seed + '.json';
      const ref = { file, digest: canonicalDigest(body), rows: 1, unparsed };
      const fullFile = path.join('/tmp', file);
      sidecars.set(fullFile, JSON.stringify(body));
      if (corruptSidecar && label === 'b' && isModel) {
        const changed = structuredClone(body);
        changed.rows[0].predicted = 'OUTSIDE_CLOSED_SET';
        sidecars.set(fullFile, JSON.stringify(changed));
      }
      const seedRow = { seed, predictions: ref };
      if (isModel) seedRow.outcome_class = 'MEASURED';
      trials.push({ trial_id: entry.trial_id, arm_id: entry.arm_id, seeds: [seedRow] });
      charges.push({ trial: entry.trial_id, seed, arm_id: entry.arm_id, units: isModel ? 578 : 0 });
    }
    runs[label] = {
      kind: 's2-008-campaign-v10-predictions/1',
      label,
      status: 'MEASURED',
      dry_run: false,
      raw_run_id: 'run-v10-' + label,
      nonce: 'nonce-v10-' + label,
      base: structuredClone(runBase),
      preregistration_digest: prereg.preregistration_digest,
      model_image_pin: { content_commitment: prereg.executor.model_image.content_commitment },
      reservation: { currency: 'tokens', granted_units: prereg.budget_reservation.granted_units },
      spent_units: spentUnits,
      model_calls: modelCalls,
      launches: charges.length,
      trials,
      charges,
    };
  }
  const bootstrap = ({ vectors, seeds, samples, confidence }) => ({
    record: { real_start: { proven: true } },
    output: {
      kind: 's2-008-campaign-bootstrap-output/1',
      samples,
      confidence,
      results: vectors.map((vector) => {
        const [trialId, seedText] = vector.trial_id.split('@');
        const seedValue = Number(seedText);
        return {
          trial_id: vector.trial_id,
          seed: seedValue,
          arm_id: vector.arm_id,
          samples,
          confidence,
          n: vector.agreement.length,
          method: 'PERCENTILE_BOOTSTRAP_WITH_MULTIPLICITY',
          observed_rate: vector.agreement.reduce((sum, value) => sum + value, 0) / vector.agreement.length,
          mean_matches_observed: true,
          lower: 0,
          upper: 1,
          ignored_trial_id: trialId,
        };
      }),
    },
  });
  return {
    prereg,
    manifest,
    frozenTable,
    runA: runs.a,
    runB: runs.b,
    holdoutCases: [{ case_id: EVALUATION_CASE_ID, label: 'MINOR' }],
    campaignProbes,
    securityControls,
    bootstrap,
    root: '/tmp',
    readFile: (file) => sidecars.get(file),
  };
}

test('v10 evaluation publishes deterministic agreement only after full scoring and leaves human review pending', () => {
  const result = evaluateV4Campaign(makeEvaluationFixture());
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(result.deterministic_evaluation, { verdict: 'AGREES', remarks: [] });
  assert.equal(result.prediction_source, 'IMMUTABLE_RUN_SIDECARS');
  assert.equal(result.verdict, 'PENDING_HUMAN_REVIEW');
  assert.equal(result.reproducibility.same_decision_digest, false);
});

test('v10 evaluation refuses a corrupted sidecar, unparsed-as-agreement, and duplicate A/B generation IDs', () => {
  const corrupted = evaluateV4Campaign(makeEvaluationFixture({ corruptSidecar: true }));
  assert.equal(corrupted.ok, false);
  assert.match(corrupted.reason, /V4_SIDECAR_DIGEST_MISMATCH/);
  assert.equal(Object.hasOwn(corrupted, 'deterministic_evaluation'), false);

  const unparsed = evaluateV4Campaign(makeEvaluationFixture({ unparsedMismatch: true }));
  assert.equal(unparsed.ok, false);
  assert.match(unparsed.reason, /V4_UNPARSED_COUNT_MISMATCH/);

  const duplicate = evaluateV4Campaign(makeEvaluationFixture({ duplicateAcrossRuns: true }));
  assert.equal(duplicate.ok, false);
  assert.equal(duplicate.reason, 'V10_GENERATION_ID_DUPLICATE');
});
