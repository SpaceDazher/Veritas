import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { assertPreregistration, preregistrationDigest } from '../../src/lib/research/preregistration.mjs';
import { FROZEN_MEMBERS } from '../../scripts/s2-008-campaign-approve.mjs';
import { credentialEnvNameForPreregistration } from '../../scripts/s2-008-campaign-credential-env.mjs';
import { modelImagePaths, modelImageVersionFromArgv, modelImagePolicyInputs, parseModelImageCliArgs, assertV13ModelCatalogFile } from '../../scripts/s2-008-campaign-model-image.mjs';
import { activeCampaignVersion } from '../../scripts/s2-008-campaign-evaluate.mjs';
import { parsePrepareMode } from '../../scripts/s2-008-campaign-prepare-cli.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { V13_MODEL_POLICY } from '../../scripts/s2-008-campaign-credential-env.mjs';
import { assertV13BaseBinding, assertV13PriorV12AReconciliation, approveV13, createV13Draft, readV13BaseInputs, readV13PriorV12AInputs } from '../../scripts/s2-008-campaign-v13-approval.mjs';
import { sealV13, assertV13ApprovalBinding, assertV13ManifestBinding } from '../../scripts/s2-008-campaign-seal-v13.mjs';
import { createV13PiModelsFile } from '../../scripts/s2-008-campaign-credential-env.mjs';
import { modelTrialArgv } from '../../scripts/s2-008-campaign-adapter.mjs';
import { campaignCliMode } from '../../scripts/s2-008-campaign-run.mjs';
import { validateProbePreregistration } from '../../scripts/s2-008-campaign-probes.mjs';
import { validateS2PaidReviewGenerationAccounting } from '../../scripts/s2-008-paid-review.mjs';

const v12 = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/preregistration.v12.in-force.json', 'utf8'));
const catalogFile = 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json';
const catalogBytes = fs.readFileSync(catalogFile);
const modelCatalogSha256 = createHash('sha256').update(catalogBytes).digest('hex');
const modelRegistration = Object.freeze({
  id: 'inclusionai/ling-3.1-flash',
  name: 'inclusionAI: Ling 3.1 Flash',
  api: 'openai-completions',
  baseUrl: 'https://openrouter.ai/api/v1',
  input: Object.freeze(['text']),
  contextWindow: 262144,
  maxTokens: 32768,
  reasoning: true,
});
function v13Candidate() {
  const prereg = structuredClone(v12);
  prereg.rule = 's2-008-prereg-v13';
  prereg.preregistration_id = 'xpr-s2-008c-13';
  prereg.status = 'DRAFT';
  prereg.approval = { ...prereg.approval, status: null, principal_id: null, label: null, issued_at: null, in_force: false };
  prereg.executor = {
    ...prereg.executor,
    provider: 'openrouter',
    model: 'inclusionai/ling-3.1-flash',
    credential_env_name: 'OPENROUTER_API_KEY',
    pi_model_registration: structuredClone(modelRegistration),
    pi_model_catalog_binding: {
      file: catalogFile,
      sha256: modelCatalogSha256,
      canonical_slug: 'inclusionai/ling-3.1-flash-20261002',
      prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY',
      cache_pricing: 'NOT_PROVIDED',
      client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE',
    },
  };
  prereg.budget_reservation = {
    ...prereg.budget_reservation,
    reservation_id: 'rsv-s2-008c-13',
    granted_units: 5000000,
    ceiling_scope: 'PER_RUN_A_OR_B',
    expires_at: '2026-10-12T00:00:00.000Z',
  };
  prereg.v12_prior_execution_reconciliation = {
    kind: 's2-008-v12-a-reconciliation/1',
    file: 'evidence/s2-008-campaign/reconciliation-v12-a.json',
    raw_sha256: '19dca90fb603749b012d11a68317dff36e3d688af28585c85479f1c48a364493',
    canonical_digest: '266a48545aa92838a3a3aed0548de05f196020a198fd2db61c2bbbff2b44f352',
    prior_run_id: 's2-008c-v12-a-92b479ad27f349728672',
    prior_run_sha256: '1e64d455a837c8e8c10e5fea1c606231908c134e8b58e0d3fe0bccacf16dbdf4',
    prior_sidecar_file: 'evidence/s2-008-campaign/predictions-v12-a-trl-s2-008c-01-20260926.json',
    prior_sidecar_sha256: '1db420961471ff82ebc41d68fe16c9460ce53a7f244dd242320ebc70af5e0740',
    preregistration_digest: 'be2e9cba4629e66d295c2527f6a1842f6282f6526efc10d63acfddec33e0c394',
    raw_unknown_attempts: 1,
    closed_unknown_attempts: 1,
    unreconciled_attempts: 0,
    scope: 'Only stopped v12 A; account-wide and earlier campaign totals are outside this reconciliation',
  };
  prereg.preregistration_digest = preregistrationDigest(prereg);
  return prereg;
}

test('v13 preregistration validates the exact Ling policy with full-body digest and frozen science unchanged', () => {
  const prereg = v13Candidate();
  assert.deepEqual(FROZEN_MEMBERS.map((key) => prereg[key]), FROZEN_MEMBERS.map((key) => v12[key]));
  assert.equal(prereg.executor.provider, 'openrouter');
  assert.equal(prereg.executor.model, 'inclusionai/ling-3.1-flash');
  assert.deepEqual(prereg.executor.pi_model_registration, modelRegistration);
  assert.equal(Object.hasOwn(prereg.executor.pi_model_registration, 'cost'), false);
  assert.equal(prereg.budget_reservation.granted_units, 5000000);
  assert.equal(prereg.budget_reservation.ceiling_scope, 'PER_RUN_A_OR_B');
  assert.equal(prereg.budget_reservation.expires_at, '2026-10-12T00:00:00.000Z');
  assert.notEqual(preregistrationDigest({ ...prereg, executor: { ...prereg.executor, model: 'other/model' } }), prereg.preregistration_digest);
  assert.equal(assertPreregistration(prereg), prereg);
});

test('v13 OpenRouter credential route accepts only the registered model policy', () => {
  assert.equal(credentialEnvNameForPreregistration(v13Candidate()), 'OPENROUTER_API_KEY');
  const wrong = v13Candidate();
  wrong.executor.model = 'inclusionai/other';
  wrong.preregistration_digest = preregistrationDigest(wrong);
  assert.throws(() => credentialEnvNameForPreregistration(wrong), /V13_MODEL_POLICY_INVALID/);
});

test('v13 model image routes use v12 as staged predecessor and require the pinned PI package input', () => {
  assert.deepEqual(modelImagePaths('v13', { preseal: true }), {
    tag: 'localhost/veritas-s2-008-model:v13',
    stagedPrereg: 'corpus/s2-008-campaign/preregistration.v12.in-force.json',
    pinFile: 'evidence/s2-008-campaign/model-image-pin-v13-preseal.json',
    schema: 's2-008-model-image-pin/13',
  });
  assert.equal(modelImagePaths('v13').pinFile, 'evidence/s2-008-campaign/model-image-pin-v13.json');
  assert.deepEqual(parseModelImageCliArgs(['node', 'builder', '--v13', '--preseal', '--pi-package-dir', '/recovered/pi']),
    { version: 'v13', preseal: true, packageRoot: '/recovered/pi' });
  assert.throws(() => parseModelImageCliArgs(['node', 'builder', '--v13', '--preseal']), /MODEL_PI_PACKAGE_SOURCE_REQUIRED/);
  assert.equal(modelImageVersionFromArgv(['node', 'builder', '--v13']), 'v13');
  assert.deepEqual(modelImagePolicyInputs('s2-008-model-image-pin/13').sourceNames,
    ['credential_env_policy', 'pi_launcher', 'pi_package_manifest', 'pi_runtime_tree', 'pi_shrinkwrap', 'provider_model_catalog', 'timeout_policy']);
  assert.throws(() => modelImagePolicyInputs('s2-008-model-image-pin/013'), /MODEL_IMAGE_VERSION_INVALID/);
});

test('active version and prepare seal routing recognize v13 without allowing malformed versions', () => {
  assert.equal(activeCampaignVersion({ preregistration: { file: 'preregistration.v13.in-force.json' } }), 'v13');
  assert.equal(parsePrepareMode(['--seal-v13']), 'seal-v13');
  assert.throws(() => parsePrepareMode(['--seal-v013']), /PREPARE_VERSION_INVALID/);
  assert.throws(() => parsePrepareMode(['--seal-v14']), /PREPARE_VERSION_INVALID/);
});

test('v13 model image preflight binds the exact public catalog bytes', () => {
  assert.equal(assertV13ModelCatalogFile(catalogFile), true);
  const temp = fs.mkdtempSync('/tmp/veritas-v13-catalog-test-');
  try {
    const changed = temp + '/catalog.json';
    fs.copyFileSync(catalogFile, changed);
    fs.appendFileSync(changed, ' ');
    assert.throws(() => assertV13ModelCatalogFile(changed), /V13_MODEL_CATALOG_ARTIFACT_INVALID/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('v13 catalog binding hashes the saved exact model descriptor rather than trusting a model-id string', () => {
  const prereg = v13Candidate();
  assert.equal(prereg.executor.pi_model_catalog_binding.sha256, modelCatalogSha256);
  const changed = structuredClone(prereg);
  changed.executor.pi_model_catalog_binding.sha256 = '0'.repeat(64);
  changed.preregistration_digest = preregistrationDigest(changed);
  assert.throws(() => assertPreregistration(changed), /V13_MODEL_CATALOG_BINDING_INVALID/);
});


function fakeV13Pin(baseBytes) {
  const sourceNames = modelImagePolicyInputs('s2-008-model-image-pin/13').sourceNames;
  const sources = Object.fromEntries([...sourceNames, 'prereg'].sort().map((name) => [
    name, name === 'prereg' ? createHash('sha256').update(baseBytes).digest('hex')
      : name === 'provider_model_catalog' ? V13_MODEL_POLICY.catalog_sha256 : 'a'.repeat(64),
  ]));
  const covers = Object.keys(sources).filter((name) => name !== 'prereg');
  const commitment = canonicalDigest(Object.fromEntries(covers.map((name) => [name, sources[name]])));
  const build = { imageId: 'sha256:offline-fixture', digest: 'sha256:offline-fixture',
    source_digest: canonicalDigest(sources), content_commitment: commitment,
    content_commitment_covers: covers, sources };
  return { schema: 's2-008-model-image-pin/13', identical: true, context_digest_stable: true,
    content_commitment_stable: true, commitment_excludes_preregistration: true,
    commitment: { covers, excludes: ['prereg'] }, first: structuredClone(build), second: structuredClone(build) };
}

function signedV13Fixture() {
  const baseInputs = readV13BaseInputs({ allowHistorical: true });
  const restartInputs = readV13PriorV12AInputs();
  const pin = fakeV13Pin(baseInputs.baseBytes);
  const draft = createV13Draft({ ...baseInputs, pin, restartInputs });
  const earliest = Math.max(Date.parse(baseInputs.base.approval.issued_at),
    Date.parse(restartInputs.reconciliation.created_at));
  const signed = approveV13({ ...baseInputs, draft, pin, restartInputs,
    principal: 'prn-s2007r-owner', label: 'Daniil',
    issuedAt: new Date(earliest + 1000).toISOString() });
  return { baseInputs, restartInputs, pin, draft, signed };
}

test('v13 lineage validators bind positive exact v12 base and v12-A bytes and reject byte drift', () => {
  const base = readV13BaseInputs({ allowHistorical: true });
  const restart = readV13PriorV12AInputs();
  assert.equal(assertV13BaseBinding(base).baseDigest, v12.preregistration_digest);
  assert.equal(assertV13PriorV12AReconciliation(restart).raw_unknown_attempts, 1);
  assert.throws(() => assertV13BaseBinding({ ...base, baseBytes: Buffer.concat([base.baseBytes, Buffer.from('\n')]) }),
    /V13_BASE_BINDING_INVALID/);
  assert.throws(() => assertV13PriorV12AReconciliation({ ...restart, runBytes: Buffer.concat([restart.runBytes, Buffer.from(' ')]) }),
    /V13_V12A_RAW_BINDING_INVALID/);
});

test('v13 approval and seal preserve the signed lineage and append one manifest successor', () => {
  const fixture = signedV13Fixture();
  const { baseInputs, restartInputs, pin, draft, signed } = fixture;
  assert.equal(signed.approval.principal_id, 'prn-s2007r-owner');
  assert.equal(signed.approval.label, 'Daniil');
  assert.equal(signed.approval.in_force, false);
  assert.deepEqual(FROZEN_MEMBERS.map((key) => signed[key]), FROZEN_MEMBERS.map((key) => v12[key]));
  const sealed = sealV13({ signed, draft, ...baseInputs, baseSupersession: baseInputs.supersession,
    baseSupersessionBytes: baseInputs.supersessionBytes, pin, restartInputs, ledger: baseInputs.ledger });
  assert.equal(sealed.prereg.approval.in_force, true);
  assert.equal(sealed.manifest.preregistration.file, 'preregistration.v13.in-force.json');
  assert.equal(sealed.manifest.supersession_history.at(-1).file, 'preregistration-v13-supersession.json');
  assert.equal(assertV13ManifestBinding({ prereg: sealed.prereg, base: baseInputs.base,
    manifest: sealed.manifest, supersession: sealed.supersession, table: baseInputs.table, ledger: baseInputs.ledger }).ok, true);
  assert.equal(validateProbePreregistration({ prereg: sealed.prereg, manifest: sealed.manifest }).ok, true);
  assert.throws(() => sealV13({ signed, draft, ...baseInputs, baseSupersession: baseInputs.supersession,
    baseSupersessionBytes: baseInputs.supersessionBytes, pin,
    restartInputs: { ...restartInputs, sidecarBytes: Buffer.concat([restartInputs.sidecarBytes, Buffer.from(' ')]) },
    ledger: baseInputs.ledger }), /V13_V12A_RAW_BINDING_INVALID/);
});

test('v13 sealed binding rejects approval metadata drift outside the signed scientific digest', () => {
  const { signed } = signedV13Fixture();
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assert.equal(assertV13ApprovalBinding({ signed, prereg, expected: signed }).ok, true);
  const changedAuthority = structuredClone(signed);
  changedAuthority.approval.authority = 'AUTOMATION';
  assert.throws(() => assertV13ApprovalBinding({ signed: changedAuthority, prereg, expected: signed }),
    /V13_APPROVAL_BINDING_MISMATCH/);
  const changedStatus = structuredClone(signed);
  changedStatus.status = 'DRAFT';
  assert.throws(() => assertV13ApprovalBinding({ signed: changedStatus, prereg, expected: signed }),
    /V13_APPROVAL_BINDING_MISMATCH/);
  const extraField = structuredClone(signed);
  extraField.approval.extra = 'unsigned';
  assert.throws(() => assertV13ApprovalBinding({ signed: extraField, prereg, expected: signed }),
    /V13_APPROVAL_BINDING_MISMATCH/);
  const changedInForce = structuredClone(prereg);
  changedInForce.approval.extra = 'unsigned';
  assert.throws(() => assertV13ApprovalBinding({ signed, prereg: changedInForce, expected: signed }),
    /V13_APPROVAL_BINDING_MISMATCH/);
});

test('v13 approval rejects a forged principal and an approval predating its reconciliation', () => {
  const fixture = signedV13Fixture();
  const { baseInputs, restartInputs, pin, draft } = fixture;
  const earliest = Math.max(Date.parse(baseInputs.base.approval.issued_at),
    Date.parse(restartInputs.reconciliation.created_at));
  const args = { ...baseInputs, draft, pin, restartInputs, label: 'Daniil' };
  assert.throws(() => approveV13({ ...args, principal: 'prn-forged',
    issuedAt: new Date(earliest + 1000).toISOString() }), /V13_APPROVAL_IDENTITY_INVALID/);
  assert.throws(() => approveV13({ ...args, principal: 'prn-s2007r-owner',
    issuedAt: new Date(earliest - 1).toISOString() }), /V13_APPROVAL_CHRONOLOGY_INVALID/);
});

test('v13 runtime routes resolve the exact Ling model and versioned image without widening v12 controls', () => {
  const prereg = v13Candidate();
  const models = createV13PiModelsFile(prereg.executor);
  assert.deepEqual(models.providers.openrouter.models, [modelRegistration]);
  assert.equal(models.providers.openrouter.apiKey, '$OPENROUTER_API_KEY');
  assert.equal(JSON.stringify(models).includes('sk-'), false);
  assert.deepEqual(modelTrialArgv({ armId: 'arm-model-zai-glm53flash', seed: 20260926,
    remainingTokens: 1000, preregRule: 's2-008-prereg-v13' }).slice(5, 6),
    ['/opt/veritas/corpus/s2-008-campaign/preregistration.v13.in-force.json']);
  assert.deepEqual(campaignCliMode({ v13: true }), { predictionRunner: true, requestedVersion: 13 });
  assert.deepEqual(campaignCliMode({}), { predictionRunner: false, requestedVersion: null });
});


function v13ReceiptEvidence() {
  const provider = 'InclusionAI Edge';
  const model = 'inclusionai/ling-3.1-flash';
  const createdAt = '2026-01-01T00:00:00.000Z';
  const epoch = Math.floor(Date.parse(createdAt) / 1000);
  const sidecars = [];
  const receipts = [];
  const rows = [];
  const seeds = [20260926, 20260927, 20260928];
  for (let index = 0; index < seeds.length; index += 1) {
    const id = 'gen-' + epoch + '-' + String(index + 1).padStart(16, 'A');
    const caseId = 'case-' + index;
    const local = {
      generation_id: id, case_id: caseId, input: 3, output: 2, cacheRead: 0, cacheWrite: 0,
      prompt_tokens: 3, totalTokens: 5, prompt_token_basis: 'input+cacheRead+cacheWrite',
      usage_components_consistent: true, reported_cost_usd: null,
    };
    sidecars.push({ kind: 's2-008-campaign-predictions/1', accounting: {
      policy: 'GENERATION_ID_REQUIRED', calls: 1, tokens: 5, rows: [local],
    } });
    receipts.push({ id, provider, model, created_at: createdAt, http_status: 200,
      native_prompt: 3, native_completion: 2, native_cached: 0, generation_time: 12,
      cancelled: false, finish_reason: 'stop', matches_local: true, total_cost: 0 });
    rows.push({ generation_id: id, provider, case_id: caseId, created_at: createdAt,
      input: 3, output: 2, cached: 0, total_tokens: 5, provider_reported_usd: 0 });
  }
  const report = {
    status: 'MEASURED', spent_units: 15, spent_units_is_lower_bound: false,
    unreconciled_spend: false, model_calls_is_lower_bound: false, model_calls: 3,
    unknown_model_attempts: 0, trials: seeds.map((seed) => ({ arm_id: 'arm-model-zai-glm53flash',
      seeds: [{ seed, launch: { arm_report: { executor: {
        model_attempts: 1, model_calls: 1, unknown_model_attempts: 0,
      } } } }],
    })),
  };
  const reconciliation = {
    status: 'RECONCILED', completeness_basis: 'KNOWN_ATTEMPTS_ALL_RECEIPTS',
    completeness: { basis: 'KNOWN_ATTEMPTS_ALL_RECEIPTS', all_local_attempts_accounted: true,
      unfiltered_account_ledger_claimed: false, confirmed_by: null },
    provider_rows_verified_via_api: true, completeness_verified_via_api: false,
    local_model_attempts: 3, locally_accounted_model_calls: 3, matching_requests: 3,
    unreconciled_attempts: 0, actual_tokens: 15, actual_usd: 0,
    provider: 'openrouter', model, rows,
  };
  return { report, sidecars, receipts: {
    status: 'KNOWN_GENERATIONS_MATCH', known_calls: 3, known_tokens: 15,
    unknown_attempts: 0, known_provider_usd: 0, receipts,
  }, reconciliation };
}

test('v13 paid-review receipts bind exact Ling model, provider report, response ids, native usage, and authoritative cost', () => {
  const evidence = v13ReceiptEvidence();
  assert.deepEqual(validateS2PaidReviewGenerationAccounting({ ...evidence, version: 13 }),
    { calls: 3, tokens: 15, usd: 0 });
  const wrongModel = structuredClone(evidence);
  wrongModel.receipts.receipts[0].model = 'stealth/space-bunny-alpha';
  assert.throws(() => validateS2PaidReviewGenerationAccounting({ ...wrongModel, version: 13 }));
  const wrongId = structuredClone(evidence);
  wrongId.receipts.receipts[0].id = 'gen-1767225600-BBBBBBBBBBBBBBBB';
  assert.throws(() => validateS2PaidReviewGenerationAccounting({ ...wrongId, version: 13 }));
  const wrongUsage = structuredClone(evidence);
  wrongUsage.receipts.receipts[0].native_completion = 99;
  assert.throws(() => validateS2PaidReviewGenerationAccounting({ ...wrongUsage, version: 13 }));
  const wrongProvider = structuredClone(evidence);
  wrongProvider.reconciliation.rows[0].provider = 'Different Provider';
  assert.throws(() => validateS2PaidReviewGenerationAccounting({ ...wrongProvider, version: 13 }));
  const missingCost = structuredClone(evidence);
  delete missingCost.receipts.receipts[0].total_cost;
  assert.throws(() => validateS2PaidReviewGenerationAccounting({ ...missingCost, version: 13 }));
});
