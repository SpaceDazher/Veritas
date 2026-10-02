import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import { assertPreregistration, preregistrationDigest as sharedDigest } from '../../src/lib/research/preregistration.mjs';
import { credentialEnvNameForPreregistration } from '../../scripts/s2-008-campaign-credential-env.mjs';
import { modelImagePaths } from '../../scripts/s2-008-campaign-model-image.mjs';
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
  for (const bad of ['v12', 'v110']) {
    assert.throws(() => modelImagePaths(bad), /MODEL_IMAGE_VERSION_INVALID/);
  }
  assert.throws(() => resolveProbePreregistrationPath('corpus/s2-008-campaign/preregistration.v110.in-force.json', '/tmp/veritas-probe-root'),
    /PROBE_PREREG_PATH_INVALID/);
});

test('v11 restart guard binds exact v10 A report, sidecar, owner reconciliation and receipts', async () => {
  const { assertV10AReconciliation, readV11ReconciliationInputs } =
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
});
