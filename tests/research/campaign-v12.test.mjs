import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { BASE_IMAGE } from '../../src/lib/isolation/image.mjs';
import { FROZEN_MEMBERS } from '../../scripts/s2-008-campaign-approve.mjs';
import { assertPreregistration, preregistrationDigest as sharedDigest } from '../../src/lib/research/preregistration.mjs';
import { preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import { credentialEnvNameForPreregistration } from '../../scripts/s2-008-campaign-credential-env.mjs';
import { parseArgs as parseApprovalArgs } from '../../scripts/s2-008-campaign-approve.mjs';
import { modelImagePaths, modelImagePolicyInputs, modelImageVersionFromArgv, parseModelImageCliArgs, modelDryRunTimeoutMs } from '../../scripts/s2-008-campaign-model-image.mjs';
import { modelTrialArgv, runModelTrial, assertPinnedModelImage, campaignImageContextDigest } from '../../scripts/s2-008-campaign-adapter.mjs';
import { activeCampaignVersion } from '../../scripts/s2-008-campaign-evaluate.mjs';
import { resolveProbePreregistrationPath } from '../../scripts/s2-008-campaign-probes.mjs';
import { parsePrepareMode, assertPrepareWriteAllowed } from '../../scripts/s2-008-campaign-prepare-cli.mjs';
import { createS2PaidReviewWorkflow, validateS2PaidReviewCapsuleSourceInputs } from '../../scripts/s2-008-paid-review.mjs';
import { runV4Campaign } from '../../scripts/s2-008-campaign-run.mjs';
import { createS2PaidReviewWorkflow as createS2PaidReviewWorkflowFactory } from '../../scripts/s2-008-paid-review-workflow.mjs';

const BASE_PATH = 'corpus/s2-008-campaign/preregistration.v11.in-force.json';
const baseBytes = fs.readFileSync(BASE_PATH);
const base = JSON.parse(baseBytes);
const table = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/frozen-table.v3.json', 'utf8'));
const ledger = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/source-ledger.v3.json', 'utf8'));
const activeManifest = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/manifest.json', 'utf8'));
const activeV12 = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/preregistration.v12.in-force.json', 'utf8'));
const activeV13 = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/preregistration.v13.in-force.json', 'utf8'));
const activeV14 = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/preregistration.v14.in-force.json', 'utf8'));
const activeV15 = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/preregistration.v15.in-force.json', 'utf8'));
const activeCurrentMatch = /^preregistration\.v(15|16|17|18)\.in-force\.json$/.exec(activeManifest?.preregistration?.file ?? '');
if (!activeCurrentMatch) throw new Error('TEST_ACTIVE_CAMPAIGN_VERSION_INVALID');
const activeCurrentVersion = Number(activeCurrentMatch[1]);
const activeCurrent = JSON.parse(fs.readFileSync(
  'corpus/s2-008-campaign/preregistration.v' + activeCurrentVersion + '.in-force.json', 'utf8'));
const v12Supersession = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/preregistration-v12-supersession.json', 'utf8'));
const v11SupersessionBytes = fs.readFileSync('corpus/s2-008-campaign/preregistration-v11-supersession.json');
const v11Supersession = JSON.parse(v11SupersessionBytes);
// Historical v11 predecessor fixture built from immutable v11 source inputs;
// the live manifest is v12 after seal and must not serve as this fixture.
const manifest = {
  preregistration: {
    file: 'preregistration.v11.in-force.json',
    status: 'IN_FORCE',
    preregistration_digest: base.preregistration_digest,
  },
  supersession: {
    file: 'preregistration-v11-supersession.json',
    supersession_id: v11Supersession.supersession_id,
    supersession_digest: v11Supersession.supersession_digest,
  },
  supersession_history: [{
    file: 'preregistration-v11-supersession.json',
    supersession_id: v11Supersession.supersession_id,
    supersession_digest: v11Supersession.supersession_digest,
  }],
  superseded_preregistration: {
    file: 'preregistration-v10-superseded.json',
    superseded_by: 'preregistration.v11.in-force.json',
  },
  frozen_table: { file: 'frozen-table.v3.json', digest: canonicalDigest(table) },
  source_ledger: { file: 'source-ledger.v3.json', entry_count: ledger.entries.length,
    last_anchor_digest: ledger.entries.at(-1).anchor_digest },
};
const historicalV12Manifest = {
  ...structuredClone(manifest),
  preregistration: {
    file: 'preregistration.v12.in-force.json',
    status: 'IN_FORCE',
    preregistration_digest: activeV12.preregistration_digest,
    sealed_before_first_trial: true,
  },
  supersession: {
    file: 'preregistration-v12-supersession.json',
    supersession_id: v12Supersession.supersession_id,
    supersession_digest: v12Supersession.supersession_digest,
  },
  supersession_history: [
    ...structuredClone(manifest.supersession_history),
    {
      file: 'preregistration-v12-supersession.json',
      supersession_id: v12Supersession.supersession_id,
      supersession_digest: v12Supersession.supersession_digest,
    },
  ],
  superseded_preregistration: {
    file: 'preregistration-v11-superseded.json',
    preregistration_digest: base.preregistration_digest,
    superseded_by: 'preregistration.v12.in-force.json',
  },
};

const v12Candidate = () => {
  const value = structuredClone(base);
  value.rule = 's2-008-prereg-v12';
  value.preregistration_id = 'xpr-s2-008c-12';
  value.budget_reservation = { ...value.budget_reservation, reservation_id: 'rsv-s2-008c-12', expires_at: '2026-10-12T00:00:00.000Z' };
  value.preregistration_digest = preregistrationDigest(value);
  return value;
};

test('canonical manifest tracks signed active v15/v16/v17/v18 across successor sealing', () => {
  assert.equal(activeManifest.preregistration.file, 'preregistration.v' + activeCurrentVersion + '.in-force.json');
  assert.equal(activeManifest.preregistration.status, 'IN_FORCE');
  assert.equal(activeManifest.preregistration.sealed_before_first_trial, true);
  assert.equal(activeManifest.preregistration.preregistration_digest, activeCurrent.preregistration_digest);
  assert.equal(activeCurrent.preregistration_digest, preregistrationDigest(activeCurrent));
  assert.equal(sharedDigest(activeCurrent), activeCurrent.preregistration_digest);
  assert.equal(activeCurrent.rule, 's2-008-prereg-v' + activeCurrentVersion);
  assert.equal(activeCurrent.status, 'APPROVED');
  assert.equal(activeCurrent.approval?.status, 'APPROVED');
  assert.equal(activeCurrent.approval?.in_force, true);
  assert.equal(activeV15.rule, 's2-008-prereg-v15');
  assert.equal(activeV15.approval?.in_force, true);
  assert.equal(activeV14.approval?.in_force, true);
  assert.equal(activeV13.rule, 's2-008-prereg-v13');
  assert.equal(activeV13.approval?.in_force, true);
  assert.equal(activeV12.rule, 's2-008-prereg-v12');
  assert.equal(activeV12.approval?.in_force, true);
  assert.equal(manifest.preregistration.file, 'preregistration.v11.in-force.json');
  assert.equal(manifest.preregistration.preregistration_digest, base.preregistration_digest);
  assert.equal(historicalV12Manifest.preregistration.file, 'preregistration.v12.in-force.json');
  assert.equal(historicalV12Manifest.preregistration.preregistration_digest, activeV12.preregistration_digest);
});

test('control image context digest preserves the existing literal recipe bytes', () => {
  const tick = String.fromCharCode(96);
  const recipe = [
    '# The S2-008 real-campaign adapter image. Read-only recipe: every',
    '# instruction is a literal or a digest, nothing is passed as a build arg.',
    '# There is no RUN step; the base image already carries the runtime.',
    '#',
    '# ' + tick + '--timestamp 0' + tick + ' is what makes the derived digest a function of CONTENT.',
    '# Without it buildah stamps each layer with the wall clock, two builds of',
    '# identical bytes get different digests, and the pin is a coincidence.',
    'FROM ' + BASE_IMAGE,
    'COPY opt/campaign /opt/campaign',
    'LABEL org.veritas.subject="S2-008-CAMPAIGN" org.veritas.label="acceptance" org.veritas.program="/opt/campaign/arm.mjs" org.veritas.base.digest="sha256:25330af3531fb5e23318554a0aa911125b6e91b1b777edf7655501d207c067a2"',
    '',
  ].join('\n');
  const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
  const expected = canonicalDigest({
    program_sha256: digest(fs.readFileSync('scripts/s2-008-campaign-arm.mjs')),
    blind_input_sha256: digest(fs.readFileSync('corpus/s2-008-campaign/cases/holdout.blind.json')),
    containerfile_sha256: digest(Buffer.from(recipe)),
  });
  assert.equal(campaignImageContextDigest(), expected);
});

test('v12 dry-run timeout uses the signed v6 policy and rejects policy drift', () => {
  assert.equal(modelDryRunTimeoutMs(activeV12), activeV12.executor.model_launch_timeout.total_container_timeout_ms);
  const mutated = structuredClone(activeV12);
  mutated.executor.model_launch_timeout.total_container_timeout_ms += 1;
  assert.throws(() => modelDryRunTimeoutMs(mutated), /V6_MODEL_TIMEOUT_POLICY_INVALID/);
});

test('v12 routes are strict and retain the v11 predecessor for preseal staging', async () => {
  const prereg = v12Candidate();
  assert.equal(sharedDigest(prereg), prereg.preregistration_digest);
  assert.equal(assertPreregistration(prereg), prereg);
  assert.deepEqual(modelImagePaths('v12', { preseal: true }), {
    tag: 'localhost/veritas-s2-008-model:v12',
    stagedPrereg: 'corpus/s2-008-campaign/preregistration.v11.in-force.json',
    pinFile: 'evidence/s2-008-campaign/model-image-pin-v12-preseal.json',
    schema: 's2-008-model-image-pin/12',
  });
  assert.equal(modelImagePaths('v12').pinFile, 'evidence/s2-008-campaign/model-image-pin-v12.json');
  assert.deepEqual(modelImagePolicyInputs('s2-008-model-image-pin/12').sourceNames,
    ['credential_env_policy', 'pi_launcher', 'pi_package_manifest', 'pi_runtime_tree', 'pi_shrinkwrap', 'timeout_policy']);
  assert.equal(modelImageVersionFromArgv(['node', 'builder', '--v12']), 'v12');
  const { spawnSync } = await import('node:child_process');
  const path = await import('node:path');
  const missingSource = spawnSync(process.execPath, [path.resolve('scripts/s2-008-campaign-model-image.mjs'), '--v12', '--preseal'],
    { cwd: process.cwd(), encoding: 'utf8' });
  assert.notEqual(missingSource.status, 0);
  assert.match(missingSource.stderr, /MODEL_PI_PACKAGE_SOURCE_REQUIRED/);
  assert.deepEqual(parseModelImageCliArgs(['node', 'builder', '--v12', '--preseal', '--pi-package-dir', '/recovered/pi']),
    { version: 'v12', preseal: true, packageRoot: '/recovered/pi' });
  assert.throws(() => parseModelImageCliArgs(['node', 'builder', '--v12', '--preseal']), /MODEL_PI_PACKAGE_SOURCE_REQUIRED/);
  assert.equal(credentialEnvNameForPreregistration(prereg), 'OPENROUTER_API_KEY');
  assert.equal(modelTrialArgv({ armId: prereg.trial_list[0].arm_id, seed: 20260926,
    remainingTokens: 5000000, preregRule: 's2-008-prereg-v12' })
    .includes('/opt/veritas/corpus/s2-008-campaign/preregistration.v12.in-force.json'), true);
  assert.equal(activeCampaignVersion({ preregistration: { file: 'preregistration.v12.in-force.json' } }), 'v12');
  assert.equal(resolveProbePreregistrationPath('corpus/s2-008-campaign/preregistration.v12.in-force.json', '/tmp/veritas-probe-root'),
    '/tmp/veritas-probe-root/corpus/s2-008-campaign/preregistration.v12.in-force.json');
  assert.equal(parsePrepareMode(['--seal-v12']), 'seal-v12');
  assert.throws(() => parsePrepareMode(['--seal-v12', '--check']), /PREPARE_MODE_INVALID/);
  assert.throws(() => parsePrepareMode(['--seal-v120']), /PREPARE_VERSION_INVALID/);
  assert.throws(() => modelImageVersionFromArgv(['node', 'builder', '--v120']), /MODEL_IMAGE_VERSION_INVALID/);
  assert.throws(() => modelImageVersionFromArgv(['node', 'builder', '--v11', '--v12']), /MODEL_IMAGE_VERSION_INVALID/);
  assert.equal(parseApprovalArgs(['--version', 'v12', '--principal', 'prn-s2007r-owner', '--label', 'test']).version, 'v12');
  assert.throws(() => parseApprovalArgs(['--version', 'v12', '--version', 'v12']), /APPROVE_VERSION_CONFLICT/);
  assert.throws(() => resolveProbePreregistrationPath('corpus/s2-008-campaign/preregistration.v120.in-force.json', '/tmp/veritas-probe-root'),
    /PROBE_PREREG_PATH_INVALID/);
  assert.throws(() => assertPrepareWriteAllowed({ preregistration: { status: 'IN_FORCE', file: 'preregistration.v12.in-force.json' } }),
    /VERSIONED_IN_FORCE_REFUSES_DEFAULT_WRITE/);
});

test('v12 lineage validator binds immutable v11 bytes, owner approval, supersession, and active manifest pointer', async () => {
  const v12 = await import('../../scripts/s2-008-campaign-v12-approval.mjs');
  assert.equal(typeof v12.assertV12BaseBinding, 'function');
  const args = { base, baseBytes, manifest, supersession: v11Supersession,
    supersessionBytes: v11SupersessionBytes, table };
  const result = v12.assertV12BaseBinding(args);
  assert.equal(result.baseDigest, '244a6801e4b1f6ea4bd71097fb70a768113b72f085d4899e876993627590bf4c');
  assert.equal(result.baseSha256, '63f9b66761263a056cd9f6c4d54c97e0c5b063d08c19a08dec3be611dfc04e5d');
  assert.equal(result.supersessionId, 'spr-6f5e296f15e53ae440c57ef5');
  assert.throws(() => v12.assertV12BaseBinding({ ...args, baseBytes: Buffer.concat([baseBytes, Buffer.from('x')]) }),
    /V12_BASE/);
  const changedSignature = structuredClone(base);
  changedSignature.approval.principal_id = 'prn-other-owner';
  assert.throws(() => v12.assertV12BaseBinding({ ...args, base: changedSignature }), /V12_BASE/);
  const changedManifest = structuredClone(manifest);
  changedManifest.preregistration.file = 'preregistration.v10.in-force.json';
  assert.throws(() => v12.assertV12BaseBinding({ ...args, manifest: changedManifest }), /V12_BASE/);
  const changedSupersession = structuredClone(v11Supersession);
  changedSupersession.supersession_id = 'spr-forged';
  assert.throws(() => v12.assertV12BaseBinding({ ...args, supersession: changedSupersession }), /V12_BASE/);
});

test('v12 revalidates the inherited v10 restart reconciliation against current raw evidence', async () => {
  const v12 = await import('../../scripts/s2-008-campaign-v12-approval.mjs');
  const v11 = await import('../../scripts/s2-008-campaign-v11-approval.mjs');
  assert.equal(typeof v12.assertV12RestartReconciliation, 'function');
  const prereg = v12Candidate();
  const inputs = v11.readV11ReconciliationInputs();
  const binding = v12.assertV12RestartReconciliation(prereg, inputs);
  assert.equal(binding.actualTokens, 15856);
  assert.equal(binding.priorRunSha256, prereg.restart_reconciliation.prior_run_sha256);

  const tamperedRaw = { ...inputs,
    reconciliationBytes: Buffer.concat([inputs.reconciliationBytes, Buffer.from(' ')]) };
  assert.throws(() => v12.assertV12RestartReconciliation(prereg, tamperedRaw),
    /V11_RECONCILIATION_OWNER_BYTES_INVALID/);
  const tamperedBinding = structuredClone(prereg);
  tamperedBinding.restart_reconciliation.prior_run_sha256 = 'a'.repeat(64);
  assert.throws(() => v12.assertV12RestartReconciliation(tamperedBinding, inputs),
    /V12_RESTART_RECONCILIATION_BINDING_MISMATCH/);
});

test('v11 execution scan is scoped, ignores unrelated generated records, and never claims provider completeness', async () => {
  const { inspectV11PriorExecutionEvidence } = await import('../../scripts/s2-008-campaign-v12-approval.mjs');
  const actual = inspectV11PriorExecutionEvidence();
  assert.equal(actual.status, 'NOT_FOUND_IN_INSPECTED_SCOPE');
  assert.equal(actual.provider_completeness_claimed, false);
  assert.equal(actual.actual_tokens, undefined);
  assert.match(actual.inspected_scope, /evidence[/]s2-008-campaign/);

  const root = fs.mkdtempSync('/tmp/veritas-v12-scan-');
  try {
    const directory = root + '/evidence/s2-008-campaign';
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(directory + '/run-v11-a.json', JSON.stringify({
      status: 'MEASURED', preregistration_digest: 'b3ae2a63-not-v11',
    }));
    const unrelated = inspectV11PriorExecutionEvidence({ repoRoot: root });
    assert.equal(unrelated.status, 'NOT_FOUND_IN_INSPECTED_SCOPE');
    assert.equal(unrelated.provider_completeness_claimed, false);

    fs.writeFileSync(directory + '/run-v11-b.json', JSON.stringify({
      status: 'INFRA', preregistration_digest: base.preregistration_digest,
      executor: { model_attempts: 1, model_calls: 0, unknown_model_attempts: 1 },
    }));
    const matching = inspectV11PriorExecutionEvidence({ repoRoot: root });
    assert.equal(matching.status, 'RECONCILIATION_REQUIRED');
    assert.equal(matching.provider_completeness_claimed, false);
    assert.deepEqual(matching.findings.map((row) => row.file), ['run-v11-b.json']);

    const malformedRoot = fs.mkdtempSync('/tmp/veritas-v12-malformed-scan-');
    try {
      const malformedDir = malformedRoot + '/evidence/s2-008-campaign';
      fs.mkdirSync(malformedDir, { recursive: true });
      fs.writeFileSync(malformedDir + '/run-v11-a.json', '{broken');
      assert.equal(inspectV11PriorExecutionEvidence({ repoRoot: malformedRoot }).status, 'RECONCILIATION_REQUIRED');
      fs.writeFileSync(malformedDir + '/run-v11-a.json', JSON.stringify({ status: 'BLOCKED' }));
      assert.equal(inspectV11PriorExecutionEvidence({ repoRoot: malformedRoot }).status, 'RECONCILIATION_REQUIRED');
      fs.unlinkSync(malformedDir + '/run-v11-a.json');
      fs.writeFileSync(malformedDir + '/campaign-v11-a-attempt-12.json', JSON.stringify({ status: 'BLOCKED' }));
      assert.equal(inspectV11PriorExecutionEvidence({ repoRoot: malformedRoot }).status, 'RECONCILIATION_REQUIRED');
    } finally { fs.rmSync(malformedRoot, { recursive: true, force: true }); }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('v12 draft requires a real v12 preseal pin and does not invent predecessor spend', async () => {
  const v12 = await import('../../scripts/s2-008-campaign-v12-approval.mjs');
  assert.equal(typeof v12.createV12Draft, 'function');
  const priorExecutionEvidence = v12.inspectV11PriorExecutionEvidence();
  assert.equal(priorExecutionEvidence.status, 'NOT_FOUND_IN_INSPECTED_SCOPE');
  assert.throws(() => v12.createV12Draft({ base, baseBytes, manifest, supersession: v11Supersession,
    supersessionBytes: v11SupersessionBytes, table, pin: null, priorExecutionEvidence }),
  /V12_PRESEAL_PIN_REQUIRED/);
});

function syntheticV12Pin(preregistrationBytes) {
  const sources = {
    prereg: createHash('sha256').update(preregistrationBytes).digest('hex'),
    credential_env_policy: '1'.repeat(64),
    pi_launcher: '2'.repeat(64),
    pi_package_manifest: '3'.repeat(64),
    pi_runtime_tree: '4'.repeat(64),
    pi_shrinkwrap: '5'.repeat(64),
    timeout_policy: '6'.repeat(64),
  };
  const covers = Object.keys(sources).filter((name) => name !== 'prereg').sort();
  const commitment = canonicalDigest(Object.fromEntries(covers.map((name) => [name, sources[name]])));
  const build = {
    sources,
    source_digest: canonicalDigest(sources),
    content_commitment: commitment,
    content_commitment_covers: covers,
    imageId: 'sha256:' + 'a'.repeat(64),
    digest: 'sha256:' + 'b'.repeat(64),
  };
  return {
    schema: 's2-008-model-image-pin/12', identical: true, context_digest_stable: true,
    content_commitment_stable: true, commitment_excludes_preregistration: true,
    first: structuredClone(build), second: structuredClone(build),
    commitment: { covers, excludes: ['prereg'] },
  };
}

test('v12 pure draft approval and seal preserve all frozen science and bind current manifest', async () => {
  const approvalModule = await import('../../scripts/s2-008-campaign-v12-approval.mjs');
  const sealModule = await import('../../scripts/s2-008-campaign-seal-v12.mjs');
  const inputs = { base, baseBytes, manifest, supersession: v11Supersession,
    supersessionBytes: v11SupersessionBytes, table };
  const pin = syntheticV12Pin(baseBytes);
  const priorExecutionEvidence = approvalModule.inspectV11PriorExecutionEvidence();
  const draft = approvalModule.createV12Draft({ ...inputs, pin, priorExecutionEvidence });
  for (const member of FROZEN_MEMBERS) {
    assert.equal(canonicalDigest(draft[member]), canonicalDigest(base[member]), member);
  }
  const signed = approvalModule.approveV12({ ...inputs, draft, pin, priorExecutionEvidence,
    principal: 'prn-s2007r-owner', label: 'fixture-only source test', issuedAt: '2026-10-05T12:00:00.000Z' });
  const sealed = sealModule.sealV12({ signed, draft, ...inputs, baseSupersession: v11Supersession,
    baseSupersessionBytes: v11SupersessionBytes, pin, priorExecutionEvidence, ledger });
  assert.equal(sealed.prereg.status, 'APPROVED');
  assert.equal(sealed.prereg.approval.in_force, true);
  assert.equal(sealed.manifest.preregistration.file, 'preregistration.v12.in-force.json');
  assert.equal(sealModule.assertV12ManifestBinding({ prereg: sealed.prereg, base,
    manifest: sealed.manifest, supersession: sealed.supersession, table, ledger }).ok, true);
  for (const member of FROZEN_MEMBERS) {
    const changed = structuredClone(draft);
    changed[member] = null;
    changed.preregistration_digest = preregistrationDigest(changed);
    assert.throws(() => approvalModule.approveV12({ ...inputs, draft: changed, pin, priorExecutionEvidence,
      principal: 'prn-s2007r-owner', label: 'fixture-only source test', issuedAt: '2026-10-05T12:00:00.000Z' }),
    new RegExp('APPROVAL_SCOPE_DRIFT|V12_TABLE_MISMATCH'));
  }
  const changedPin = syntheticV12Pin(baseBytes);
  changedPin.first.sources.pi_runtime_tree = 'f'.repeat(64);
  assert.throws(() => approvalModule.approveV12({ ...inputs, draft, pin: changedPin, priorExecutionEvidence,
    principal: 'prn-s2007r-owner', label: 'fixture-only source test', issuedAt: '2026-10-05T12:00:00.000Z' }), /V12_PRESEAL_PIN_INVALID/);
  assert.throws(() => approvalModule.approveV12({ ...inputs, baseBytes: Buffer.concat([baseBytes, Buffer.from('tamper')]),
    draft, pin, priorExecutionEvidence, principal: 'prn-s2007r-owner', label: 'fixture-only source test',
    issuedAt: '2026-10-05T12:00:00.000Z' }), /V12_BASE/);
  const badDigest = { ...draft, preregistration_digest: '0'.repeat(64) };
  assert.throws(() => approvalModule.approveV12({ ...inputs, draft: badDigest, pin, priorExecutionEvidence,
    principal: 'prn-s2007r-owner', label: 'fixture-only source test', issuedAt: '2026-10-05T12:00:00.000Z' }), /V12_DIGEST_MISMATCH/);
});

test('v12 capsule sources use the v12 preregistration path while preserving exact source bytes', async () => {
  const { buildV12ReviewCapsuleSourceInputs } = await import('../../scripts/s2-008-campaign-evaluate.mjs');
  assert.equal(typeof buildV12ReviewCapsuleSourceInputs, 'function');
  const paths = [
    'corpus/s2-008-campaign/preregistration.v12.in-force.json',
    'corpus/s2-008-campaign/manifest.json',
    'corpus/s2-008-campaign/frozen-table.v3.json',
    'corpus/s2-008-campaign/cases/holdout.blind.json',
    'scripts/s2-008-campaign-evaluate.mjs',
    'scripts/s2-008-campaign-bootstrap.mjs',
    'scripts/s2-008-campaign-adapter.mjs',
  ];
  const entries = paths.map((sourcePath, index) => ({ path: sourcePath, contents: Buffer.from('source-' + index) }));
  const inputs = buildV12ReviewCapsuleSourceInputs(entries);
  assert.equal(inputs[0].path, 'corpus/s2-008-campaign/preregistration.v12.in-force.json');
  assert.deepEqual(validateS2PaidReviewCapsuleSourceInputs(inputs, inputs, { version: 12 }), { ok: true });
  assert.deepEqual(validateS2PaidReviewCapsuleSourceInputs(inputs, inputs, { version: 11 }), { ok: false });
});

test('v12 adapter revalidates the sealed image pin before mocked dry dispatch', async () => {
  const pin = JSON.parse(fs.readFileSync('evidence/s2-008-campaign/model-image-pin-v12.json', 'utf8'));
  let inspections = 0;
  let dryExecutions = 0;
  const inspect = (imageId) => {
    inspections += 1;
    assert.equal(imageId, pin.first.imageId);
    return { Id: pin.first.imageId, Digest: pin.first.digest, Architecture: pin.first.architecture };
  };
  const armId = activeV12.trial_list[0].arm_id;
  const output = {
    arm_id: armId, outcome_class: 'DRY_RUN', dry_run: true,
    budget: { currency: 'tokens', spent_tokens: 0, unreconciled_spend: false },
    executor: { model_calls: 0 }, predictions: [{ case_id: 'fixture-case', predicted: 'MINOR' }],
    container: { pid: 123, node_version: 'v22.0.0' },
  };
  const payload = Buffer.from(JSON.stringify(output)).toString('base64');
  const observation = {
    exitCode: 0, signal: null, timedOut: false,
    stdout: 'ADAPTER_OK arm=' + armId + ' seed=20260926 n=1 predictions=1 tokens=0 usd=0 dry_run=true pid=123 node=v22.0.0\n'
      + 'ADAPTER_JSON 1/1 ' + payload + '\nADAPTER_JSON_END ' + payload.length + '\n',
    stderr: '',
  };
  const result = await runModelTrial({
    armId, seed: 20260926, timeoutMs: 180000, dryRun: true, pin, prereg: activeV12,
    runLabel: 'v12-adapter-fixture', inspect, predictionsSink: () => {},
    executePaid: () => { throw new Error('PAID_DISPATCH_FORBIDDEN_IN_TEST'); },
    executeDry: (invocation) => {
      dryExecutions += 1;
      assert.equal(invocation.image, pin.first.imageId);
      assert.equal(invocation.podmanArgv.includes('--dry-run'), true);
      assert.equal(invocation.podmanArgv.includes('/opt/veritas/corpus/s2-008-campaign/preregistration.v12.in-force.json'), true);
      return observation;
    },
  });
  assert.equal(inspections, 1);
  assert.equal(dryExecutions, 1);
  assert.equal(result.ok, true);
  assert.deepEqual(result.record.arm_report, output);
  assert.equal(result.record.predictions.rows, 1);
  assert.deepEqual(assertPinnedModelImage({ pin, prereg: activeV12, inspect: () => ({
    Id: pin.first.imageId, Digest: pin.first.digest, Architecture: pin.first.architecture,
  }) }), { imageId: pin.first.imageId, digest: pin.first.digest, architecture: pin.first.architecture });
});

test('v12 paid review discovers the active version and allocates distinct fixture task identities', async () => {
  const { inspectS2PaidReviewEvidence, buildS2PaidReviewTask } = await import('../../scripts/s2-008-paid-review.mjs');
  const root = fs.mkdtempSync('/tmp/veritas-v12-review-');
  try {
    const corpus = root + '/corpus/s2-008-campaign';
    fs.mkdirSync(corpus, { recursive: true });
    fs.mkdirSync(root + '/evidence/s2-008-campaign', { recursive: true });
    fs.writeFileSync(corpus + '/manifest.json', JSON.stringify({ preregistration: {
      file: 'preregistration.v12.in-force.json', status: 'IN_FORCE', sealed_before_first_trial: true,
    } }));
    const inspected = inspectS2PaidReviewEvidence(root);
    assert.equal(inspected.version, 12);
    assert.equal(inspected.ready, false);
    assert.ok(inspected.reasons.includes('ACTIVE_PREREGISTRATION_INVALID'));
    const task = buildS2PaidReviewTask({ version: 12, taskId: 'abt-s2-008-v12-fixture-000000000000',
      workspaceId: 'ws-s2-008-v12-fixture-000000000000', adapterId: 'adr-s2-008-v12-fixture-000000000000',
      ownerPrincipalId: 'prn-s2007r-owner', producerPrincipalId: 'prn-s2-008-evidence-importer',
      evidenceDigest: 'c'.repeat(64), imageId: 'sha256:' + 'd'.repeat(64),
      at: '2026-10-05T12:00:00.000Z', fixtureOnly: true });
    assert.equal(task.task_id, 'abt-s2-008-v12-fixture-000000000000');
    assert.equal(task.workspace_id, 'ws-s2-008-v12-fixture-000000000000');
    assert.match(task.title, /FIXTURE ONLY/);
    const workflow = createS2PaidReviewWorkflow({ pool: null, evidenceRoot: root, version: 12,
      inspectEvidence: () => ({ version: 12, ready: false }), buildTask: (value) => value,
      ownerPrincipalId: 'prn-s2007r-owner', producerPrincipalId: 'prn-s2-008-evidence-importer',
      stateRoot: root + '/state', replayJournal: () => ({ ok: true }), fixtureOnly: true,
      fixtureRoot: root, fixtureRecords: [{ path: 'fixture.json', sha256: 'e'.repeat(64) }] });
    assert.match(workflow.taskId, /^abt-s2-008-v12-fixture-[a-f0-9]{12}$/);
    assert.match(workflow.workspaceId, /^ws-s2-008-v12-fixture-[a-f0-9]{12}$/);
    assert.equal(workflow.version, 12);
    assert.equal(workflow.fixtureOnly, true);
    const snapshot = await workflow.status({ principalId: 'prn-s2007r-owner', taskId: workflow.taskId });
    assert.equal(snapshot.version, 12);
    assert.equal(snapshot.fixture_only, true);
    const mismatched = createS2PaidReviewWorkflowFactory({ pool: null, evidenceRoot: root, version: 12,
      inspectEvidence: () => ({ version: 11, ready: true }), buildTask: (value) => value,
      ownerPrincipalId: 'prn-s2007r-owner', producerPrincipalId: 'prn-s2-008-evidence-importer',
      stateRoot: root + '/mismatched-state', replayJournal: () => ({ ok: true }) });
    await assert.rejects(mismatched.status({ principalId: 'prn-s2007r-owner', taskId: mismatched.taskId }),
      /PAID_REVIEW_VERSION_UNSUPPORTED/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});


test('v12 comparison output is version-bound and rederived from every arm, seed, and case', async () => {
  const { deriveS2PaidReviewComparison, validateS2PaidReviewComparison } = await import('../../scripts/s2-008-paid-review.mjs');
  const trials = [
    { trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash' },
    { trial_id: 'trl-s2-008c-02', arm_id: 'arm-type-feat-fix' },
    { trial_id: 'trl-s2-008c-03', arm_id: 'arm-type-chore' },
  ];
  const seeds = [20260926, 20260927, 20260928];
  const holdoutCaseIds = Array.from({ length: 126 }, (_, index) => 'case-' + String(index).padStart(3, '0'));
  const rows = () => trials.flatMap((trial) => seeds.flatMap((seed) => holdoutCaseIds.map((case_id) => ({
    ...trial, seed, case_id, predicted: 'MINOR',
  }))));
  const input = { preregistrationDigest: 'c'.repeat(64), holdoutCaseIds,
    aPredictions: rows(), bPredictions: rows(), version: 12 };
  const comparison = deriveS2PaidReviewComparison(input);
  assert.equal(comparison.version, 12);
  assert.equal(validateS2PaidReviewComparison({ ...input, comparison }), true);
  assert.throws(() => validateS2PaidReviewComparison({ ...input, comparison, version: 11 }),
    (error) => error.code === 'PAID_REVIEW_COMPARISON_INVALID');
});

test('v12 mismatched independent control builds refuse before any model or control dispatch', async () => {
  const modelPin = JSON.parse(fs.readFileSync('evidence/s2-008-campaign/model-image-pin-v12.json', 'utf8'));
  let builds = 0;
  let dispatches = 0;
  const report = await runV4Campaign({
    label: 'a',
    dryRun: true,
    write: false,
    prereg: activeV12,
    manifest: historicalV12Manifest,
    modelPin,
    resolveBaseFn: () => ({ commit_sha: 'c'.repeat(40), tree_sha: 'd'.repeat(40), worktree_dirty: true }),
    buildRegex: () => {
      builds += 1;
      const suffix = String(builds).repeat(64);
      return {
        pin: { imageId: 'sha256:' + suffix, digest: 'sha256:' + 'e'.repeat(64), architecture: 'amd64' },
        context_digest: campaignImageContextDigest(),
        build_exit: 0,
      };
    },
    runModel: async () => { dispatches += 1; throw new Error('unexpected model dispatch'); },
    runRegex: async () => { dispatches += 1; throw new Error('unexpected control dispatch'); },
  });
  assert.equal(builds, 2);
  assert.equal(dispatches, 0);
  assert.equal(report.status, 'BLOCKED');
  assert.equal(report.code, 'CONTROL_IMAGE_PIN_INVALID');
  assert.equal(report.launches, 0);
  assert.deepEqual(report.trials, []);
});
