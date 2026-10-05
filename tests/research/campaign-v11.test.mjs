import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import { assertPreregistration, preregistrationDigest as sharedDigest } from '../../src/lib/research/preregistration.mjs';
import { credentialEnvNameForPreregistration } from '../../scripts/s2-008-campaign-credential-env.mjs';
import { modelImagePaths, modelImageVersionFromArgv } from '../../scripts/s2-008-campaign-model-image.mjs';
import { modelTrialArgv } from '../../scripts/s2-008-campaign-adapter.mjs';
import { activeCampaignVersion } from '../../scripts/s2-008-campaign-evaluate.mjs';
import { resolveProbePreregistrationPath } from '../../scripts/s2-008-campaign-probes.mjs';

const base = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/preregistration.v10.in-force.json', 'utf8'));
const evidence = 'evidence/s2-008-campaign';

function v11Candidate() {
  const prereg = structuredClone(base);
  prereg.rule = 's2-008-prereg-v11';
  prereg.preregistration_id = 'xpr-s2-008c-11';
  prereg.preregistration_digest = preregistrationDigest(prereg);
  return prereg;
}

test('v11 keeps the signed OpenRouter executor and canonical preregistration contract', () => {
  const prereg = v11Candidate();
  assert.equal(sharedDigest(prereg), prereg.preregistration_digest);
  assert.equal(assertPreregistration(prereg), prereg);
  assert.equal(credentialEnvNameForPreregistration(prereg), 'OPENROUTER_API_KEY');
  assert.deepEqual(modelImagePaths('v11', { preseal: true }), {
    tag: 'localhost/veritas-s2-008-model:v11',
    stagedPrereg: 'corpus/s2-008-campaign/preregistration.v10.in-force.json',
    pinFile: 'evidence/s2-008-campaign/model-image-pin-v11-preseal.json',
    schema: 's2-008-model-image-pin/11',
  });
  assert.equal(modelImagePaths('v11').pinFile, 'evidence/s2-008-campaign/model-image-pin-v11.json');
  assert.equal(modelTrialArgv({ armId: base.trial_list[0].arm_id, seed: 20260926,
    remainingTokens: 5000000, preregRule: 's2-008-prereg-v11' })
    .includes('/opt/veritas/corpus/s2-008-campaign/preregistration.v11.in-force.json'), true);
  assert.equal(activeCampaignVersion({ preregistration: { file: 'preregistration.v11.in-force.json' } }), 'v11');
  assert.equal(resolveProbePreregistrationPath('corpus/s2-008-campaign/preregistration.v11.in-force.json', '/tmp/veritas-probe-root'),
    '/tmp/veritas-probe-root/corpus/s2-008-campaign/preregistration.v11.in-force.json');
  for (const bad of ['v13', 'v110']) {
    assert.throws(() => modelImagePaths(bad), /MODEL_IMAGE_VERSION_INVALID/);
  }
  assert.equal(modelImageVersionFromArgv(['node', 'builder', '--v11']), 'v11');
  for (const bad of ['--v13', '--v110', '--v11junk', '--v11/../../v10', '--v11=foo']) {
    assert.throws(() => modelImageVersionFromArgv(['node', 'builder', bad]), /MODEL_IMAGE_VERSION_INVALID/);
  }
  assert.throws(() => modelImageVersionFromArgv(['node', 'builder', '--v10', '--v11']), /MODEL_IMAGE_VERSION_INVALID/);
  assert.throws(() => resolveProbePreregistrationPath('corpus/s2-008-campaign/preregistration.v110.in-force.json', '/tmp/veritas-probe-root'),
    /PROBE_PREREG_PATH_INVALID/);
});

test('v11 restart guard binds exact v10 A report, sidecar, owner reconciliation and receipts', async () => {
  const { assertV10AReconciliation, readV11ReconciliationInputs, overlapWithinPreviousCall } =
    await import('../../scripts/s2-008-campaign-v11-approval.mjs');
  const inputs = readV11ReconciliationInputs();
  const bound = assertV10AReconciliation(inputs);
  assert.equal(bound.priorRunSha256, '93bbedfad7f32919cbb100f2152646187ab57c80dc8689da5906e45d9bd451f1');
  assert.equal(bound.priorSidecarSha256, 'f44adbf7a50540bc1cc0a28e328edf2ede64e135ba04badcd2687aa060ae167c');
  assert.equal(bound.canonicalDigest, '5f391e89d66376d79da631d822acefb8081d01aa51e530f74afcab1734750d9b');
  assert.equal(bound.actualTokens, 15856);
  assert.equal(bound.actualUsd, 0);
  assert.equal(bound.providerCalls, 25);
  assert.equal(bound.localAttempts, 26);
  assert.equal(bound.unreconciledAttempts, 0);
  const lastKnown = inputs.knownReceipts.receipts.at(-1);
  assert.equal(overlapWithinPreviousCall(lastKnown, inputs.overlapReceipt.created_at), true);
  assert.equal(overlapWithinPreviousCall(lastKnown, '2026-10-02T07:00:29.000Z'), false);
  assert.equal(overlapWithinPreviousCall(lastKnown, '2026-10-02T07:00:20.000Z'), false);

  const changedRawRun = Buffer.concat([inputs.priorRunBytes, Buffer.from('x')]);
  assert.throws(() => assertV10AReconciliation({ ...inputs, priorRunBytes: changedRawRun }), /V11_RECONCILIATION/);
  const changedOwnerBytes = Buffer.concat([inputs.reconciliationBytes, Buffer.from('x')]);
  assert.throws(() => assertV10AReconciliation({ ...inputs, reconciliationBytes: changedOwnerBytes }), /V11_RECONCILIATION/);
  const changedReceiptBytes = Buffer.concat([inputs.knownReceiptBytes, Buffer.from('x')]);
  assert.throws(() => assertV10AReconciliation({ ...inputs, knownReceiptBytes: changedReceiptBytes }), /V11_RECONCILIATION/);

  const forged = structuredClone(inputs.reconciliation);
  forged.rows[0].input += 1;
  assert.throws(() => assertV10AReconciliation({ ...inputs, reconciliation: forged }), /V11_RECONCILIATION/);
  const forgedOverlap = structuredClone(inputs.overlapReceipt);
  forgedOverlap.id += '-forged';
  assert.throws(() => assertV10AReconciliation({ ...inputs, overlapReceipt: forgedOverlap }), /V11_RECONCILIATION/);
});

test('v11 safe failure diagnostics retain bounded evidence without raw events, prompts, or secrets', async () => {
  const { createSafeFailureDiagnostic } = await import('../../scripts/s2-008-campaign-arm-model.mjs');
  assert.equal(typeof createSafeFailureDiagnostic, 'function');
  const diag = createSafeFailureDiagnostic({
    startedAt: '2026-10-02T07:00:00.000Z',
    finishedAt: '2026-10-02T07:00:03.000Z',
    exitCode: 1,
    signal: null,
    stdout: '{"type":"agent_end","messages":[{"role":"assistant","responseId":"gen-1790000000-AbcdefghijklmnopQRST","stopReason":"error"}]}',
    stderr: 'OPENROUTER_API_KEY=SECRET_SENTINEL prompt=SUBJECT_SENTINEL',
    errorMessage: 'SECRET_SENTINEL SUBJECT_SENTINEL timeout detail',
    errorCode: 'ETIMEDOUT',
    stopReason: 'error',
    httpStatus: 429,
  });
  assert.equal(diag.schema, 's2-008-failure-diagnostic/1');
  assert.equal(diag.duration_ms, 3000);
  assert.equal(diag.error_category, 'TIMEOUT');
  assert.equal(diag.http_status, 429);
  assert.deepEqual(diag.generation_ids, ['gen-1790000000-AbcdefghijklmnopQRST']);
  const serialized = JSON.stringify(diag);
  for (const forbidden of ['OPENROUTER_API_KEY', 'SECRET_SENTINEL', 'SUBJECT_SENTINEL', 'agent_end', 'timeout detail']) {
    assert.equal(serialized.includes(forbidden), false, `diagnostic leaked ${forbidden}`);
  }
  assert.match(diag.stderr.sha256, /^[0-9a-f]{64}$/);
  assert.equal(diag.stderr.bytes > 0, true);
  assert.match(diag.error_message.sha256, /^[0-9a-f]{64}$/);

  const credentialShapedId = 'gen-sk-or-v1-' + 'b'.repeat(64);
  const credentialIdDiag = createSafeFailureDiagnostic({
    stdout: JSON.stringify({ type: 'agent_end', messages: [{ role: 'assistant', responseId: credentialShapedId }] }),
  });
  assert.deepEqual(credentialIdDiag.generation_ids, []);

  const providerPrefix = createSafeFailureDiagnostic({
    errorMessage: '429: OPENROUTER_API_KEY=SECRET_SENTINEL', errorCode: 'MODEL_PROVIDER_RESPONSE_ERROR',
  });
  assert.equal(providerPrefix.http_status, null);
  assert.deepEqual(providerPrefix.provider_reported_status_prefix, {
    status: 429, source: 'SDK_ERROR_MESSAGE_PREFIX',
  });
  const embeddedStatus = createSafeFailureDiagnostic({ errorMessage: 'detail contains 429 and SECRET_SENTINEL' });
  assert.equal(embeddedStatus.provider_reported_status_prefix, null);
  const oversizedSignal = createSafeFailureDiagnostic({ signal: 'SIG' + 'A'.repeat(100000) });
  assert.equal(oversizedSignal.cli_signal, null);
});

test('v11 arm records safe diagnostics for absent, zero, thrown, and billed error responses', async () => {
  const { ARM_ERRORS, callModel } = await import('../../scripts/s2-008-campaign-arm-model.mjs');
  const env = { OPENROUTER_API_KEY: 'TEST_CREDENTIAL_SENTINEL_LONG' };
  const call = (stdout, execFile = () => stdout) => callModel('SUBJECT_SENTINEL_DO_NOT_PUBLISH', {
    provider: 'openrouter', model: 'stealth/space-bunny-alpha', envName: 'OPENROUTER_API_KEY', env,
    dryRun: false, timeoutMs: 180000, captureFailureDiagnostics: true, execFile,
  });
  const event = (messages) => JSON.stringify({ type: 'agent_end', messages });
  const assistant = (responseId, usage, stopReason = 'stop') => ({
    role: 'assistant', responseId, stopReason, content: [{ type: 'text', text: 'MINOR' }], ...(usage ? { usage } : {}),
  });
  const usage = (totalTokens) => ({ input: totalTokens - 1, output: 1, cacheRead: 0, cacheWrite: 0,
    totalTokens, cost: { total: 0 } });

  for (const [name, stdout] of [
    ['missing', event([assistant('gen-1790000001-AbcdefghijklmnopQRST', null, 'error')])],
    ['zero', event([assistant('gen-1790000002-AbcdefghijklmnopQRST', usage(0), 'error')])],
  ]) {
    assert.throws(() => call(stdout), (error) => {
      assert.equal(error.message, ARM_ERRORS.NO_USAGE_REPORTED, name);
      assert.equal(error.confirmed_usage, undefined, name);
      assert.equal(error.failure_diagnostic.error_category, 'USAGE_NOT_REPORTED', name);
      assert.equal(error.failure_diagnostic.generation_ids.length, 1, name);
      return true;
    });
  }

  const thrown = Object.assign(new Error('TEST_CREDENTIAL_SENTINEL_LONG SUBJECT_SENTINEL'), {
    code: 'ETIMEDOUT', status: 127, signal: null,
    stdout: event([assistant('gen-1790000003-AbcdefghijklmnopQRST', null, 'error')]),
    stderr: 'TEST_CREDENTIAL_SENTINEL_LONG SUBJECT_SENTINEL',
  });
  assert.throws(() => call('', () => { throw thrown; }), (error) => {
    assert.equal(error.message, ARM_ERRORS.PROVIDER_UNREACHABLE);
    assert.equal(error.failure_diagnostic.error_category, 'TIMEOUT');
    assert.equal(error.failure_diagnostic.cli_exit_code, 127);
    assert.equal(error.failure_diagnostic.http_status, null);
    assert.equal(error.failure_diagnostic.generation_ids[0], 'gen-1790000003-AbcdefghijklmnopQRST');
    assert.equal(JSON.stringify(error.failure_diagnostic).includes('SUBJECT_SENTINEL'), false);
    return true;
  });

  const partialError = event([
    assistant('gen-1790000004-AbcdefghijklmnopQRST', usage(5)),
    assistant('gen-1790000005-AbcdefghijklmnopQRST', null, 'error'),
  ]);
  assert.throws(() => call(partialError), (error) => {
    assert.equal(error.confirmed_usage.totalTokens, 5);
    assert.equal(error.unreconciled_spend, true);
    assert.equal(error.accounting.correlation_status, 'UNAVAILABLE');
    assert.equal(error.failure_diagnostic.usage_status, 'PARTIAL');
    return true;
  });

  const billedError = event([
    assistant('gen-1790000006-AbcdefghijklmnopQRST', usage(3)),
    assistant('gen-1790000007-AbcdefghijklmnopQRST', usage(4), 'error'),
  ]);
  assert.throws(() => call(billedError), (error) => {
    assert.equal(error.failure_diagnostic.error_category, 'PROVIDER_RESPONSE_ERROR');
    assert.equal(error.confirmed_usage.totalTokens, 7);
    assert.deepEqual(error.failure_diagnostic.generation_ids, ['gen-1790000006-AbcdefghijklmnopQRST', 'gen-1790000007-AbcdefghijklmnopQRST']);
    assert.equal(error.accounting.correlation_status, 'UNAVAILABLE');
    assert.equal(error.accounting.totalTokens, 7);
    return true;
  });

  const credentialShapedSession = 'sk-or-v1-' + 'b'.repeat(64);
  const successfulWithSession = JSON.stringify({
    type: 'agent_end', session_id: credentialShapedSession,
    messages: [assistant('gen-1790000008-AbcdefghijklmnopQRST', usage(2))],
  });
  const success = call(successfulWithSession);
  assert.equal(success.usage.totalTokens, 2);
  assert.equal(Object.hasOwn(success.accounting, 'session_id'), false);
  assert.equal(JSON.stringify(success).includes(credentialShapedSession), false);

  const first = { ...assistant('gen-1790000009-AbcdefghijklmnopQRST', usage(5)), id: 'duplicate-local-id' };
  const second = { ...assistant('gen-1790000010-AbcdefghijklmnopQRST', usage(7)), id: 'duplicate-local-id' };
  const identicalDuplicate = event([first, structuredClone(first)]);
  assert.equal(call(identicalDuplicate).usage.totalTokens, 5);
  assert.throws(() => call(event([first, second])), (error) => {
    assert.equal(error.confirmed_usage.totalTokens, 12);
    assert.equal(error.unreconciled_spend, true);
    assert.equal(error.accounting.correlation_status, 'UNAVAILABLE');
    assert.equal(error.accounting.correlation_issue, 'CONTRADICTORY_DUPLICATE_MESSAGE_ID');
    assert.deepEqual(error.accounting.observed_generation_ids, ['gen-1790000009-AbcdefghijklmnopQRST', 'gen-1790000010-AbcdefghijklmnopQRST']);
    return true;
  });

  const repeatedGenerationA = { ...assistant('gen-1790000011-AbcdefghijklmnopQRST', usage(5)), id: 'local-a' };
  const repeatedGenerationB = { ...assistant('gen-1790000011-AbcdefghijklmnopQRST', usage(7)), id: 'local-b' };
  assert.throws(() => call(event([repeatedGenerationA, repeatedGenerationB])), (error) => {
    assert.equal(error.confirmed_usage.totalTokens, 5);
    assert.equal(error.unreconciled_spend, true);
    assert.equal(error.accounting.correlation_status, 'UNAVAILABLE');
    assert.equal(error.accounting.correlation_issue, 'CONTRADICTORY_DUPLICATE_GENERATION_ID');
    assert.deepEqual(error.accounting.observed_generation_ids, ['gen-1790000011-AbcdefghijklmnopQRST']);
    return true;
  });
});

test('v11 pure draft and seal bind v10 as predecessor and reject all frozen science mutations', async () => {
  const { createHash } = await import('node:crypto');
  const { createV11Draft, approveV11, readV11ReconciliationInputs } = await import('../../scripts/s2-008-campaign-v11-approval.mjs');
  const { assertV11ManifestBinding, sealV11 } = await import('../../scripts/s2-008-campaign-seal-v11.mjs');
  const { FROZEN_MEMBERS, preregistrationDigest: digest } = await import('../../scripts/s2-008-campaign-approve.mjs');
  const baseBytes = fs.readFileSync('corpus/s2-008-campaign/preregistration.v10.in-force.json');
  const pin = JSON.parse(fs.readFileSync('evidence/s2-008-campaign/model-image-pin-v10-preseal.json', 'utf8'));
  pin.schema = 's2-008-model-image-pin/11';
  pin.image_tag = 'localhost/veritas-s2-008-model:v11';
  const preregHash = createHash('sha256').update(baseBytes).digest('hex');
  let covers;
  for (const build of [pin.first, pin.second]) {
    build.sources = {
      ...build.sources,
      prereg: preregHash,
      pi_package_manifest: 'a'.repeat(64),
      pi_launcher: 'b'.repeat(64),
    };
    covers = Object.keys(build.sources).filter((name) => name !== 'prereg').sort();
    build.content_commitment = canonicalDigest(Object.fromEntries(covers.map((name) => [name, build.sources[name]])));
    build.content_commitment_covers = covers;
    build.source_digest = canonicalDigest(build.sources);
  }
  pin.commitment = { ...pin.commitment, covers, excludes: ['prereg'] };
  const inputs = readV11ReconciliationInputs();
  const table = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/frozen-table.v3.json', 'utf8'));
  const ledger = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/source-ledger.v3.json', 'utf8'));
  const manifest = structuredClone(JSON.parse(fs.readFileSync('corpus/s2-008-campaign/manifest.json', 'utf8')));
  // Keep this pure predecessor test stable after v11 becomes the live manifest.
  // The seal input is an in-memory v10 state, never a rewritten campaign file.
  manifest.preregistration = { ...manifest.preregistration, status: 'IN_FORCE',
    file: 'preregistration.v10.in-force.json', preregistration_digest: digest(base) };
  const measurement = base.budget_reservation.usd_reference.measurement;
  const draft = createV11Draft({ base, baseBytes, pin, measurement, ...inputs });
  assert.equal(draft.rule, 's2-008-prereg-v11');
  const approvalArgs = { base, baseBytes, pin, measurement, ...inputs, table,
    principal: 'prn-v11-test-review', label: 'in-memory guard fixture', issuedAt: '2026-10-02T00:00:00.000Z' };
  for (const member of FROZEN_MEMBERS) {
    const changed = structuredClone(draft);
    const value = changed[member];
    changed[member] = Array.isArray(value) ? [...value, 'TEST_SCOPE_MUTATION']
      : value && typeof value === 'object' ? { ...value, test_scope_mutation: true }
        : typeof value === 'string' ? value + '-TEST_SCOPE_MUTATION'
          : typeof value === 'number' ? value + 1 : !value;
    changed.preregistration_digest = digest(changed);
    assert.throws(() => approveV11({ ...approvalArgs, draft: changed }), new RegExp('APPROVAL_SCOPE_DRIFT:' + member));
  }
  const signed = approveV11({ ...approvalArgs, draft });
  const sealed = sealV11({ signed, draft, base, baseBytes, table, pin, measurement, ...inputs, manifest, ledger });
  assert.equal(sealed.manifest.preregistration.file, 'preregistration.v11.in-force.json');
  assert.equal(sealed.manifest.superseded_preregistration.file, 'preregistration-v10-superseded.json');
  assert.equal(assertV11ManifestBinding({
    prereg: sealed.prereg, base, manifest: sealed.manifest, supersession: sealed.supersession, table, ledger,
  }).ok, true);
});

test('v11 main preserves measured lower-bound spend and unknown attempts through host refusal', async () => {
  const { mkdtempSync, readFileSync, rmSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const path = await import('node:path');
  const { main, V11_FAILURE_DIAGNOSTICS_POLICY } = await import('../../scripts/s2-008-campaign-arm-model.mjs');
  const { chargingStep, DISPATCHABLE_MODEL_ARMS, runV4Campaign } = await import('../../scripts/s2-008-campaign-run.mjs');
  const temp = mkdtempSync(path.join(tmpdir(), 's2-008-v11-partial-'));
  try {
    const inputPath = path.join(temp, 'blind.json');
    const preregPath = path.join(temp, 'prereg.json');
    const outPath = path.join(temp, 'arm.json');
    const rows = Array.from({ length: base.holdout_access.case_count }, (_, index) => ({ case_id: 'fixture-' + index, subject: 'fixture subject' }));
    writeFileSync(inputPath, JSON.stringify(rows));
    const prereg = v11Candidate();
    prereg.failure_diagnostics_protocol = structuredClone(V11_FAILURE_DIAGNOSTICS_POLICY);
    prereg.preregistration_digest = preregistrationDigest(prereg);
    writeFileSync(preregPath, JSON.stringify(prereg));
    const mixedFailure = Object.assign(new Error('MODEL_ENDPOINT_UNREACHABLE'), {
      confirmed_usage: { input: 4, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 5, cost: { total: 0 } },
      accounting: { generation_id: null, correlation_status: 'UNAVAILABLE', correlation_issue: 'GENERATION_ID_MISSING',
        input: 4, output: 1, cacheRead: 0, cacheWrite: 0, prompt_tokens: 4,
        prompt_token_basis: 'input+cacheRead+cacheWrite', totalTokens: 5, reported_cost_usd: 0, usage_components_consistent: true },
      unreconciled_spend: true, failure_diagnostic: { schema: 's2-008-failure-diagnostic/1', error_category: 'TIMEOUT' },
    });
    const code = await main([inputPath, outPath, 'arm-model-zai-glm53flash', preregPath, '20260926', '--remaining-tokens', '5000000'],
      { OPENROUTER_API_KEY: 'TEST_ONLY_SECRET' }, {
        startBridge: () => ({ host: '127.0.0.1', port: 12345, stop() {} }),
        callModel: () => { throw mixedFailure; }, writeStdout: () => {},
      });
    assert.equal(code, 10);
    const arm = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(arm.budget.spent_tokens, 5);
    assert.equal(arm.budget.unreconciled_spend, true);
    assert.equal(arm.executor.model_calls, 1);
    assert.equal(arm.executor.model_attempts, 1);
    assert.equal(arm.executor.unknown_model_attempts, 1);
    assert.equal(arm.predictions.length, 0);
    assert.equal(arm.failure_diagnostics.length, 1);
    const reconciledLooking = structuredClone(arm);
    reconciledLooking.budget.unreconciled_spend = false;
    const step = chargingStep({ currency: 'tokens', spentUnits: 0, grantedUnits: 5000000,
      armOutput: reconciledLooking, armId: 'arm-model-zai-glm53flash', dispatchableArms: DISPATCHABLE_MODEL_ARMS });
    assert.equal(step.action, 'refuse');
    assert.equal(step.detail, 'ARM_UNRECONCILED_MODEL_ATTEMPTS:1');
    assert.equal(step.units, 5);
    assert.equal(step.lower_bound, true);
    const preregV7 = JSON.parse(readFileSync('corpus/s2-008-campaign/preregistration.v7.in-force.json', 'utf8'));
    const modelPinV7 = JSON.parse(readFileSync('evidence/s2-008-campaign/model-image-pin-v7.json', 'utf8'));
    const manifestV7 = JSON.parse(readFileSync('corpus/s2-008-campaign/manifest.json', 'utf8'));
    manifestV7.preregistration = { file: 'preregistration.v7.in-force.json', status: 'IN_FORCE', preregistration_digest: preregV7.preregistration_digest };
    let launches = 0;
    const report = await runV4Campaign({
      label: 'v11-partial', arm: 'arm-model-zai-glm53flash', write: false,
      prereg: preregV7, manifest: manifestV7, modelPin: modelPinV7, dispatchableArms: DISPATCHABLE_MODEL_ARMS,
      resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
      now: () => Date.parse('2026-10-02T00:00:00.000Z'),
      runModel: async () => { launches += 1; return { ok: true, output: arm, record: { arm_report: arm } }; },
    });
    assert.equal(launches, 1);
    assert.equal(report.status, 'BLOCKED');
    assert.equal(report.spent_units, 5);
    assert.equal(report.spent_units_is_lower_bound, true);
    assert.equal(report.model_calls, 1);
    assert.equal(report.model_calls_is_lower_bound, true);
    assert.equal(report.unknown_model_attempts, 1);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
test('model image CLI rejects unsupported and conflicting versions before invoking build', async () => {
  const { spawnSync } = await import('node:child_process');
  const path = await import('node:path');
  const script = path.resolve('scripts/s2-008-campaign-model-image.mjs');
  for (const flags of [['--v13'], ['--v110'], ['--v11junk'], ['--v11/../../v10'], ['--v11=foo'], ['--v10', '--v11']]) {
    const result = spawnSync(process.execPath, [script, ...flags], { cwd: process.cwd(), encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /MODEL_IMAGE_VERSION_INVALID/);
  }
});

test('strict campaign CLI helpers reject version and mode ambiguity before dispatch', async () => {
  const prepareCli = await import('../../scripts/s2-008-campaign-prepare-cli.mjs');
  assert.equal(prepareCli.parsePrepareMode([]), 'write');
  assert.equal(prepareCli.parsePrepareMode(['--check']), 'check');
  assert.equal(prepareCli.parsePrepareMode(['--seal-v11']), 'seal-v11');
  for (const args of [
    ['--seal-v13'], ['--seal-v110'], ['--seal-v011'], ['--seal-v11junk'], ['--seal-v11=foo'],
    ['--seal-v10', '--seal-v11'], ['--check', '--selftest'],
  ]) assert.throws(() => prepareCli.parsePrepareMode(args), /PREPARE_(?:VERSION|MODE)_INVALID/);
  for (let version = 2; version <= 12; version += 1) {
    assert.throws(() => prepareCli.assertPrepareWriteAllowed({
      preregistration: { file: 'preregistration.v' + version + '.in-force.json', status: 'IN_FORCE' },
    }), /VERSIONED_IN_FORCE_REFUSES_DEFAULT_WRITE/);
  }
  assert.equal(prepareCli.assertPrepareWriteAllowed({
    preregistration: { file: 'preregistration.json', status: 'IN_FORCE' },
  }), true);

  const approveModule = await import('../../scripts/s2-008-campaign-approve.mjs');
  assert.throws(() => approveModule.parseArgs(['--version', 'v11', '--version', 'v11']), /VERSION_CONFLICT/);
  assert.throws(() => approveModule.parseArgs(['--version', 'v10', '--version', 'v11']), /VERSION_CONFLICT/);
  assert.throws(() => approveModule.parseArgs(['--version', 'v13']), /VERSION_INVALID/);

  const runModule = await import('../../scripts/s2-008-campaign-run.mjs');
  assert.equal(runModule.campaignCliMode({ v11: true }).requestedVersion, 11);
  assert.equal(runModule.campaignCliMode({ arm: 'arm-model-zai-glm53flash', dryRun: true }).predictionRunner, true);
  for (const args of [
    { v13: true }, { v110: true }, { v11junk: true }, { v11: 'true' },
    { v10: true, v11: true }, { v11: true, v12: true },
  ]) assert.throws(() => runModule.campaignCliMode(args), /CAMPAIGN_VERSION_(?:INVALID|FLAGS_CONFLICT)/);
});


test('actual CLI refusals preserve the in-force manifest and never write approval output', async () => {
  const { spawnSync } = await import('node:child_process');
  const { mkdtempSync, rmSync, existsSync, readFileSync } = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const root = process.cwd();
  const manifestPath = path.join(root, 'corpus/s2-008-campaign/manifest.json');
  const manifestBefore = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBefore);
  const { assertPrepareWriteAllowed } = await import('../../scripts/s2-008-campaign-prepare-cli.mjs');
  assert.throws(() => assertPrepareWriteAllowed(manifest), /VERSIONED_IN_FORCE_REFUSES_DEFAULT_WRITE/);

  const prepareScript = path.join(root, 'scripts/s2-008-campaign-prepare.mjs');
  const rejectedPrepareModes = [
    ['--seal-v13'], ['--seal-v110'], ['--seal-v011'], ['--seal-v11junk'], ['--seal-v11=foo'],
    ['--seal-v10', '--seal-v11'], ['--check', '--selftest'],
  ];
  for (const flags of rejectedPrepareModes) {
    const result = spawnSync(process.execPath, [prepareScript, ...flags], { cwd: root, encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /PREPARE_(?:VERSION|MODE)_INVALID/);
    assert.deepEqual(readFileSync(manifestPath), manifestBefore);
  }
  const barePrepare = spawnSync(process.execPath, [prepareScript], { cwd: root, encoding: 'utf8' });
  assert.notEqual(barePrepare.status, 0);
  assert.match(barePrepare.stderr, /VERSIONED_IN_FORCE_REFUSES_DEFAULT_WRITE/);
  assert.deepEqual(readFileSync(manifestPath), manifestBefore);

  const temporary = mkdtempSync(path.join(os.tmpdir(), 's2-008-v11-approve-'));
  try {
    const out = path.join(temporary, 'must-not-exist.json');
    const approveScript = path.join(root, 'scripts/s2-008-campaign-approve.mjs');
    const approval = spawnSync(process.execPath, [
      approveScript, '--principal', 'prn-v11-test', '--label', 'guard test', '--out', out,
      '--version', 'v10', '--version', 'v11',
    ], { cwd: root, encoding: 'utf8' });
    assert.notEqual(approval.status, 0);
    assert.match(approval.stderr, /APPROVE_VERSION_CONFLICT/);
    assert.equal(existsSync(out), false);
    const repeatedApproval = spawnSync(process.execPath, [
      approveScript, '--principal', 'prn-v11-test', '--label', 'guard test', '--out', out,
      '--version', 'v11', '--version', 'v11',
    ], { cwd: root, encoding: 'utf8' });
    assert.notEqual(repeatedApproval.status, 0);
    assert.match(repeatedApproval.stderr, /APPROVE_VERSION_CONFLICT/);
    assert.equal(existsSync(out), false);

    const runScript = path.join(root, 'scripts/s2-008-campaign-run.mjs');
    for (const flags of [
      ['--v13'], ['--v110'], ['--v11junk'], ['--v11=foo'], ['--v11', 'false'],
      ['--v10', '--v11'], ['--v11', '--v12'],
    ]) {
      const result = spawnSync(process.execPath, [runScript, ...flags], { cwd: root, encoding: 'utf8' });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /CAMPAIGN_VERSION_(?:INVALID|FLAGS_CONFLICT)/);
      assert.equal(existsSync(out), false);
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
  assert.deepEqual(readFileSync(manifestPath), manifestBefore);
});


test('v11 successful calls with missing usage, correlation, or components retain unknown stop state', async () => {
  const { mkdtempSync, readFileSync, rmSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const path = await import('node:path');
  const { main, V11_FAILURE_DIAGNOSTICS_POLICY } = await import('../../scripts/s2-008-campaign-arm-model.mjs');
  const temp = mkdtempSync(path.join(tmpdir(), 's2-008-v11-unaccounted-'));
  try {
    const inputPath = path.join(temp, 'blind.json');
    const preregPath = path.join(temp, 'prereg.json');
    const rows = Array.from({ length: base.holdout_access.case_count }, (_, index) => ({ case_id: 'fixture-' + index, subject: 'fixture subject' }));
    writeFileSync(inputPath, JSON.stringify(rows));
    const prereg = v11Candidate();
    prereg.failure_diagnostics_protocol = structuredClone(V11_FAILURE_DIAGNOSTICS_POLICY);
    prereg.preregistration_digest = preregistrationDigest(prereg);
    writeFileSync(preregPath, JSON.stringify(prereg));
    const scenarios = [
      { name: 'missing-usage', result: { text: 'fixture', model_called: true } },
      { name: 'zero-usage', result: { text: 'fixture', model_called: true, usage: { totalTokens: 0, cost: { total: 0 } } } },
      { name: 'missing-correlation', result: {
        text: 'fixture', model_called: true,
        usage: { input: 4, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 5, cost: { total: 0 } },
        accounting: { generation_id: null, correlation_status: 'UNAVAILABLE', correlation_issue: 'GENERATION_ID_MISSING',
          input: 4, output: 1, cacheRead: 0, cacheWrite: 0, prompt_tokens: 4,
          prompt_token_basis: 'input+cacheRead+cacheWrite', totalTokens: 5, reported_cost_usd: 0, usage_components_consistent: true },
      } },
      { name: 'inconsistent-components', result: {
        text: 'fixture', model_called: true,
        usage: { input: 4, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 5, cost: { total: 0 } },
        accounting: { generation_id: 'gen-1790000012-AbcdefghijklmnopQRST', correlation_status: 'CORRELATED',
          input: 4, output: 1, cacheRead: 0, cacheWrite: 0, prompt_tokens: 4,
          prompt_token_basis: 'input+cacheRead+cacheWrite', totalTokens: 5, reported_cost_usd: 0,
          usage_components_consistent: false, usage_component_issue: 'TOKEN_COMPONENT_MISMATCH' },
      } },
    ];
    for (const [index, scenario] of scenarios.entries()) {
      const outPath = path.join(temp, scenario.name + '.json');
      const code = await main([inputPath, outPath, 'arm-model-zai-glm53flash', preregPath, '20260926', '--remaining-tokens', '5000000'],
        { OPENROUTER_API_KEY: 'TEST_ONLY_SECRET' }, {
          startBridge: () => ({ host: '127.0.0.1', port: 12345, stop() {} }),
          callModel: () => scenario.result, writeStdout: () => {},
        });
      assert.equal(code, 10);
      const arm = JSON.parse(readFileSync(outPath, 'utf8'));
      assert.equal(arm.budget.unreconciled_spend, true, scenario.name);
      assert.equal(arm.stop.unreconciled_spend, true, scenario.name);
      assert.equal(arm.executor.model_attempts, 1, scenario.name);
      assert.equal(arm.executor.unknown_model_attempts, 1, scenario.name);
      assert.equal(arm.predictions.length, 0, scenario.name);
      assert.equal(arm.stop.stopped_before_case, 'fixture-0', scenario.name);
      if (index < 2) assert.equal(arm.executor.model_calls, 0, scenario.name);
      else assert.equal(arm.executor.model_calls, 1, scenario.name);
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
