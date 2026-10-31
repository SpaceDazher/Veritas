import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';

const pacing = await import('../../scripts/s2-008-campaign-v14-pacing.mjs').catch(() => ({}));
const credentialPolicy = await import('../../scripts/s2-008-campaign-credential-env.mjs');
const V13_MODEL_POLICY = credentialPolicy.V13_MODEL_POLICY;
const V14_MODEL_POLICY = credentialPolicy.V14_MODEL_POLICY;
const V7_PI_SETTINGS = credentialPolicy.V7_PI_SETTINGS;
const paidReviewRoute = await import('../../scripts/s2-008-paid-review.mjs');
const modelImageRoute = await import('../../scripts/s2-008-campaign-model-image.mjs');
const validateS2PaidReviewGenerationAccounting = paidReviewRoute.validateS2PaidReviewGenerationAccounting;

test('v14 model-image dry run binds its timeout and interval to the staged in-force preregistration', () => {
  const timeout = pacing.createV14ModelTimeoutPolicy();
  assert.deepEqual(timeout.pi_argv_flags, ['--no-tools', '--no-extensions', '--no-skills']);
  const active = { rule: 's2-008-prereg-v14', executor: { model_launch_timeout: timeout } };
  assert.equal(modelImageRoute.modelDryRunTimeoutMs(active), 30540000);
  assert.equal(typeof modelImageRoute.modelDryRunArgv, 'function');
  const v14Args = modelImageRoute.modelDryRunArgv(active, modelImageRoute.modelImagePaths('v14'));
  assert.deepEqual(v14Args.slice(-3), ['--dry-run', '--min-start-interval-ms', '60000']);
  const v13Preseal = JSON.parse(fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../corpus/s2-008-campaign/preregistration.v13.in-force.json'), 'utf8'));
  assert.equal(modelImageRoute.modelDryRunTimeoutMs(v13Preseal), 22980000);
  const presealArgs = modelImageRoute.modelDryRunArgv(v13Preseal,
    modelImageRoute.modelImagePaths('v14', { preseal: true }));
  assert.deepEqual(presealArgs.slice(-1), ['--dry-run']);
  assert.equal(presealArgs.includes('--min-start-interval-ms'), false);
});

test('v14 pacing keeps at least 60 seconds between call starts', () => {
  assert.equal(typeof pacing.createV14StartPacer, 'function');
  let now = 100;
  const sleeps = [];
  const starts = [];
  const pacer = pacing.createV14StartPacer({
    minStartIntervalMs: 60000,
    now: () => now,
    sleep: (ms) => { sleeps.push(ms); now += ms; },
  });
  pacer.runSync(() => { starts.push(now); now += 3; });
  pacer.runSync(() => { starts.push(now); now += 2; });
  assert.deepEqual(starts, [100, 60100]);
  assert.deepEqual(sleeps, [59997]);
});

test('v14 pacing rejects non-integer intervals and avoids waiting after a stop or in dry run', () => {
  assert.equal(pacing.assertV14MinStartInterval(60000), 60000);
  for (const value of [0, -1, 1, 59999, 60000.5, 60001, Infinity, '60000', null]) {
    assert.throws(() => pacing.assertV14MinStartInterval(value));
  }
  let now = 0, calls = 0, allowed = false;
  const sleeps = [];
  const pacer = pacing.createV14StartPacer({ minStartIntervalMs: 60000,
    now: () => now, sleep: (ms) => { sleeps.push(ms); now += ms; } });
  assert.equal(pacer.runSync(() => { calls += 1; }, { shouldContinue: () => allowed }).proceeded, false);
  assert.deepEqual(sleeps, []);
  const dry = pacer.runSync(() => { calls += 1; }, { enabled: false });
  assert.equal(dry.proceeded, true);
  assert.equal(dry.called, false);
  assert.equal(calls, 0);
  assert.deepEqual(sleeps, []);
});

const routes = await Promise.all([
  import('../../scripts/s2-008-campaign-approve.mjs'),
  import('../../scripts/s2-008-campaign-prepare-cli.mjs'),
  import('../../scripts/s2-008-campaign-run.mjs'),
  import('../../scripts/s2-008-campaign-evaluate.mjs'),
  import('../../scripts/s2-008-campaign-model-image.mjs'),
  import('../../scripts/s2-008-campaign-adapter.mjs'),
  import('../../scripts/s2-008-campaign-credential-env.mjs'),
  import('../../scripts/s2-008-campaign-arm-model.mjs'),
  import('../../scripts/s2-008-campaign-probes.mjs'),
]);
const [approvalRoute, prepareRoute, runRoute, evalRoute, imageRoute, adapterRoute, credentialRoute, armRoute, probeRoute] = routes;

test('v14 version dispatch reaches image, approval, seal, run and evaluation entry points', () => {
  assert.deepEqual(imageRoute.modelImagePaths('v14', { preseal: true }), {
    tag: 'localhost/veritas-s2-008-model:v14',
    stagedPrereg: 'corpus/s2-008-campaign/preregistration.v13.in-force.json',
    pinFile: 'evidence/s2-008-campaign/model-image-pin-v14-preseal.json',
    schema: 's2-008-model-image-pin/14',
  });
  assert.equal(approvalRoute.parseArgs(['--version', 'v14', '--principal', 'prn-s2007r-owner', '--label', 'Daniil']).version, 'v14');
  assert.equal(prepareRoute.parsePrepareMode(['--seal-v14']), 'seal-v14');
  assert.equal(runRoute.campaignCliMode({ v14: true }).requestedVersion, 14);
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: 'preregistration.v14.in-force.json' } }), 'v14');
});

test('v14 arm argv pins the in-force document and the signed 60000ms interval', () => {
  const argv = adapterRoute.modelTrialArgv({ armId: 'arm-model-zai-glm53flash', seed: 20260926,
    remainingTokens: 4999999, preregRule: 's2-008-prereg-v14', minStartIntervalMs: 60000 });
  assert.ok(argv.includes('/opt/veritas/corpus/s2-008-campaign/preregistration.v14.in-force.json'));
  const index = argv.indexOf('--min-start-interval-ms');
  assert.notEqual(index, -1);
  assert.equal(argv[index + 1], '60000');
});

test('arm callModel applies pacing before actual PI calls, preserves usage, skips dry-run calls, and never retries a refusal', () => {
  let now = 100, calls = 0;
  const starts = [], sleeps = [];
  const pacer = pacing.createV14StartPacer({ minStartIntervalMs: 60000,
    now: () => now, sleep: (ms) => { sleeps.push(ms); now += ms; } });
  const output = JSON.stringify({ type: 'agent_end', messages: [{ role: 'assistant', id: 'billed-1',
    usage: { input: 3, output: 1, totalTokens: 4, cost: { total: 0.0001 } },
    content: [{ type: 'text', text: 'MINOR' }] }] });
  const options = { provider: 'openrouter', model: 'inclusionai/ling-3.1-flash',
    envName: 'OPENROUTER_API_KEY', env: { OPENROUTER_API_KEY: 'fixture-only-key' },
    dryRun: false, timeoutMs: 180000, pacer,
    execFile: () => { calls += 1; starts.push(now); now += 3; return output; } };
  assert.equal(armRoute.callModel('first', options).usage.totalTokens, 4);
  assert.equal(armRoute.callModel('second', options).usage.totalTokens, 4);
  assert.deepEqual(starts, [100, 60100]);
  assert.ok(starts[1] - starts[0] >= 60000);
  assert.deepEqual(sleeps, [59997]);

  const dry = armRoute.callModel('dry', { ...options, dryRun: true });
  assert.equal(dry.model_called, false);
  assert.equal(calls, 2);
  assert.deepEqual(sleeps, [59997]);

  let refusedCalls = 0;
  assert.throws(() => armRoute.callModel('refused', { ...options, pacer: null,
    execFile: () => { refusedCalls += 1; throw new Error('provider 429'); } }));
  assert.equal(refusedCalls, 1);
});

test('v14 container coordinator waits 60 seconds after completion, checks budget during wait, and skips dry runs', async () => {
  assert.equal(typeof pacing.createV14ContainerPacer, 'function');
  let now = 0, calls = 0, budgetAvailable = true;
  const starts = [], sleeps = [];
  const pacer = pacing.createV14ContainerPacer({ minStartIntervalMs: 60000,
    now: () => now, sleepAsync: async (ms) => { sleeps.push(ms); now += ms; } });
  const first = await pacer.run(async () => { calls += 1; starts.push(now); now += 200; return 'first'; });
  const second = await pacer.run(async () => { calls += 1; starts.push(now); return 'second'; },
    { shouldContinue: () => budgetAvailable });
  assert.deepEqual([first.value, second.value], ['first', 'second']);
  assert.deepEqual(starts, [0, 60200]);
  assert.deepEqual(sleeps, [60000]);
  budgetAvailable = false;
  const stopped = await pacer.run(async () => { calls += 1; }, { shouldContinue: () => budgetAvailable });
  assert.equal(stopped.proceeded, false);
  const dry = await pacer.run(async () => { calls += 1; }, { enabled: false });
  assert.equal(dry.called, false);
  assert.equal(calls, 2);
  assert.deepEqual(sleeps, [60000]);
  let expiryNow = 0, expiryOpen = true, expiryCalls = 0;
  const expiryPacer = pacing.createV14ContainerPacer({ minStartIntervalMs: 60000,
    now: () => expiryNow, sleepAsync: async (ms) => { expiryNow += ms; expiryOpen = false; } });
  await expiryPacer.run(async () => { expiryCalls += 1; });
  const expired = await expiryPacer.run(async () => { expiryCalls += 1; }, { shouldContinue: () => expiryOpen });
  assert.equal(expired.proceeded, false);
  assert.equal(expiryCalls, 1);
});

test('arm expiry during a 60-second call wait stops without a second attempt or unknown usage', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v14-arm-expiry-'));
  try {
    const inputPath = path.join(dir, 'input.json'), preregPath = path.join(dir, 'prereg.json'), outPath = path.join(dir, 'out.json');
    fs.writeFileSync(inputPath, JSON.stringify(Array.from({ length: 126 }, (_, i) => ({ case_id: `case-${i}`, subject: 'fixture' }))));
    const executor = {
      provider: V14_MODEL_POLICY.provider, model: V14_MODEL_POLICY.model,
      credential_env_name: V14_MODEL_POLICY.credential_env_name,
      credential_source: V14_MODEL_POLICY.credential_source,
      model_call_pacing: { min_start_interval_ms: 60000 },
      model_launch_timeout: pacing.createV14ModelTimeoutPolicy(),
      pi_settings: V7_PI_SETTINGS,
      pi_model_registration: V14_MODEL_POLICY.pi_model_registration,
      pi_model_catalog_binding: { file: 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json',
        sha256: V14_MODEL_POLICY.catalog_sha256, canonical_slug: V14_MODEL_POLICY.catalog_slug,
        prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY', cache_pricing: 'NOT_PROVIDED',
        client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE' },
    };
    const prereg = { rule: 's2-008-prereg-v14', status: 'APPROVED', preregistration_id: 'xpr-s2-008c-14',
      approval: { status: 'APPROVED', in_force: true, signed_digest_over: 'scientific body' },
      failure_diagnostics_protocol: armRoute.V11_FAILURE_DIAGNOSTICS_POLICY, executor,
      budget_reservation: { currency: 'tokens', granted_units: 5000000, expires_at: '1970-01-01T00:00:00.030Z', trial_timeout_ms: 30540000 } };
    const { approval, status, preregistration_digest: _digest, ...scientificBody } = prereg;
    prereg.preregistration_digest = canonicalDigest(scientificBody);
    fs.writeFileSync(preregPath, JSON.stringify(prereg));
    let now = 0, calls = 0;
    const pacer = pacing.createV14StartPacer({ minStartIntervalMs: 60000, now: () => now,
      sleep: (ms) => { now += ms; } });
    const exitCode = await armRoute.main([inputPath, outPath, 'arm-model-zai-glm53flash', preregPath, '20260926',
      '--remaining-tokens', '5000000', '--min-start-interval-ms', '60000'], { OPENROUTER_API_KEY: 'fixture-only-key' }, {
      startBridge: async () => ({ port: 18080, stop() {} }), pacer, wallNow: () => now,
      writeStdout() {},
      callModel: (_subject, options) => {
        const attempt = calls + 1;
        const paced = options.pacer.runSync(() => { calls += 1; now += 20; return attempt; }, { shouldContinue: options.shouldContinue });
        if (!paced.proceeded || !paced.called) throw new Error('V14_PACING_STOPPED_BEFORE_CALL');
        return { text: 'MINOR', model_called: true,
          usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { total: 0 } },
          accounting: { generation_id: `gen-${attempt}`, correlation_status: 'CORRELATED', correlation_issue: null,
            input: 1, output: 1, cacheRead: 0, cacheWrite: 0, prompt_tokens: 1,
            prompt_token_basis: 'input+cacheRead+cacheWrite', totalTokens: 2, reported_cost_usd: 0,
            usage_components_consistent: true } };
      },
    });
    const report = JSON.parse(fs.readFileSync(outPath, 'utf8'));
    assert.equal(exitCode, 10);
    assert.equal(calls, 1);
    assert.equal(report.stop.reason, 'BUDGET_RESERVATION_EXPIRED_BEFORE_MODEL_CALL');
    assert.equal(report.executor.model_attempts, 1);
    assert.equal(report.executor.model_calls, 1);
    assert.equal(report.executor.unknown_model_attempts, 0);
    assert.equal(report.budget.unreconciled_spend, false);
    assert.deepEqual(report.executor.model_call_pacing, { min_start_interval_ms: 60000,
      call_starts: 1, wait_count: 1, waited_ms: 59980 });
    assert.ok(report.container.argv_tail.includes('--min-start-interval-ms'));
    assert.ok(report.container.argv_tail.includes('60000'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('v14 credential route uses only explicit process environment and checks safe secret metadata fingerprints', async () => {
  const key = 'fixture-only-openrouter-key';
  let fallbackReads = 0;
  assert.throws(() => adapterRoute.modelCredentialValue({
    provider: 'openrouter', env: {}, allowAuthFallback: false,
    readAuth: () => { fallbackReads += 1; return JSON.stringify({ openrouter: { key } }); },
  }), /EXECUTOR_CREDENTIAL_ABSENT/);
  assert.equal(fallbackReads, 0);
  assert.equal(adapterRoute.modelCredentialValue({
    provider: 'openrouter', env: { OPENROUTER_API_KEY: key }, allowAuthFallback: false,
  }), key);

  const fingerprint = adapterRoute.credentialFingerprint(key);
  let forwarded = false;
  const request = { image: 'sha256:' + 'a'.repeat(64), argv: ['/usr/local/bin/node'], timeoutMs: 1000,
    provider: 'openrouter', envName: 'OPENROUTER_API_KEY', credentialEnv: { OPENROUTER_API_KEY: key },
    requireExplicitCredentialSource: true, credentialValue: key, credentialPresent: () => true,
    credentialMetadata: () => ({ present: true, fingerprint: '0000000000000000' }),
    startForwarder: async () => { forwarded = true; throw new Error('unexpected'); },
    execute: () => { forwarded = true; throw new Error('unexpected'); } };
  for (const metadata of [undefined, { present: true, fingerprint: null }, { present: true, fingerprint: 'bad' }]) {
    await assert.rejects(() => adapterRoute.executeModelWithCredential({ ...request, credentialMetadata: () => metadata }),
      /EXECUTOR_CREDENTIAL_(?:ABSENT|FINGERPRINT_UNAVAILABLE)/);
  }
  await assert.rejects(() => adapterRoute.executeModelWithCredential(request),
    /EXECUTOR_CREDENTIAL_FINGERPRINT_MISMATCH/);
  assert.equal(forwarded, false);

  const accepted = await adapterRoute.executeModelWithCredential({
    ...request, credentialMetadata: () => ({ present: true, fingerprint }),
    startForwarder: async (socketPath) => ({ socketPath, stop: async () => {} }),
    execute: (invocation) => {
      assert.equal(invocation.podmanArgv.some((arg) => arg.includes(key)), false);
      return { exitCode: 0, stdout: 'OK', stderr: '', image: invocation.image, axes: invocation.axes };
    },
  });
  assert.equal(accepted.observation.exitCode, 0);
  assert.equal(JSON.stringify(accepted).includes(key), false);
});

test('v14 timeout formula accounts for 126 call intervals at 180s plus 5m bridge margin', () => {
  const timeout = pacing.createV14ModelTimeoutPolicy();
  assert.equal(timeout.holdout_case_count, 126);
  assert.equal(timeout.per_model_call_timeout_ms, 180000);
  assert.equal(timeout.min_start_interval_ms, 60000);
  assert.equal(timeout.bridge_report_margin_ms, 300000);
  assert.equal(timeout.total_container_timeout_ms, 30540000);
  assert.equal(pacing.assertV14ModelTimeoutPolicy(timeout), timeout);
  assert.throws(() => pacing.assertV14ModelTimeoutPolicy({ ...timeout, total_container_timeout_ms: 30480000 }));
});

function paidEvidence(model) {
  const seeds = [20260926, 20260927, 20260928], provider = 'Novita';
  const createdAt = '2026-01-01T00:00:00.000Z', epoch = Math.floor(Date.parse(createdAt) / 1000);
  const sidecars = [], receipts = [], rows = [];
  for (let i = 0; i < seeds.length; i += 1) {
    const id = 'gen-' + epoch + '-' + String(i + 1).padStart(16, '0'), caseId = 'case-' + i;
    const local = { generation_id: id, case_id: caseId, input: 3, output: 2, cacheRead: 0, cacheWrite: 0,
      prompt_tokens: 3, totalTokens: 5, prompt_token_basis: 'input+cacheRead+cacheWrite',
      usage_components_consistent: true, reported_cost_usd: null };
    sidecars.push({ kind: 's2-008-campaign-predictions/1', accounting: {
      policy: 'GENERATION_ID_REQUIRED', calls: 1, tokens: 5, rows: [local] } });
    receipts.push({ id, provider, model, created_at: createdAt, http_status: 200, native_prompt: 3,
      native_completion: 2, native_cached: 0, generation_time: 12, cancelled: false,
      finish_reason: 'stop', matches_local: true, total_cost: 0 });
    rows.push({ generation_id: id, provider, case_id: caseId, created_at: createdAt, input: 3,
      output: 2, cached: 0, total_tokens: 5, provider_reported_usd: 0 });
  }
  const report = { status: 'MEASURED', spent_units: 15, spent_units_is_lower_bound: false,
    unreconciled_spend: false, model_calls_is_lower_bound: false, model_calls: 3, unknown_model_attempts: 0,
    trials: seeds.map((seed) => ({ arm_id: 'arm-model-zai-glm53flash',
      seeds: [{ seed, launch: { arm_report: { executor: { model_attempts: 1, model_calls: 1, unknown_model_attempts: 0 } } } }] })) };
  const reconciliation = { status: 'RECONCILED', completeness_basis: 'KNOWN_ATTEMPTS_ALL_RECEIPTS',
    completeness: { basis: 'KNOWN_ATTEMPTS_ALL_RECEIPTS', all_local_attempts_accounted: true,
      unfiltered_account_ledger_claimed: false, confirmed_by: null },
    provider_rows_verified_via_api: true, completeness_verified_via_api: false,
    local_model_attempts: 3, locally_accounted_model_calls: 3, matching_requests: 3,
    unreconciled_attempts: 0, actual_tokens: 15, actual_usd: 0, provider, model, rows };
  return { report, sidecars, reconciliation, receipts: { status: 'KNOWN_GENERATIONS_MATCH',
    known_calls: 3, known_tokens: 15, unknown_attempts: 0, known_provider_usd: 0, receipts } };
}

test('v14 paid review keeps the actual receipt model id and accepts only request id or signed catalog slug', () => {
  const prereg = { rule: 's2-008-prereg-v14', executor: {
    provider: 'openrouter', model: 'inclusionai/ling-3.1-flash',
    credential_env_name: 'OPENROUTER_API_KEY', credential_source: 'EXPLICIT_PROCESS_ENV_ONLY',
    pi_model_registration: { id: 'inclusionai/ling-3.1-flash', name: 'inclusionAI: Ling 3.1 Flash',
      api: 'openai-completions', baseUrl: 'https://openrouter.ai/api/v1', input: ['text'],
      contextWindow: 262144, maxTokens: 32768, reasoning: true },
    pi_model_catalog_binding: { file: 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json',
      sha256: V13_MODEL_POLICY.catalog_sha256, canonical_slug: 'inclusionai/ling-3.1-flash-20261002',
      prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY', cache_pricing: 'NOT_PROVIDED',
      client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE' },
    pi_settings: structuredClone(V7_PI_SETTINGS), model_call_pacing: { min_start_interval_ms: 60000 },
  } };
  for (const model of [prereg.executor.model, prereg.executor.pi_model_catalog_binding.canonical_slug]) {
    const evidence = paidEvidence(model);
    assert.deepEqual(validateS2PaidReviewGenerationAccounting({
      ...evidence, version: 14, prereg,
    }), { calls: 3, tokens: 15, usd: 0 });
    assert.equal(evidence.receipts.receipts[0].model, model);
  }
  assert.throws(() => validateS2PaidReviewGenerationAccounting({
    ...paidEvidence('inclusionai/ling-3.1-flash-other'), version: 14, prereg,
  }));
});



const v14Approval = await import('../../scripts/s2-008-campaign-v14-approval.mjs');
const sealRoute = await import('../../scripts/s2-008-campaign-seal-v14.mjs');
const campaignApproval = await import('../../scripts/s2-008-campaign-approve.mjs');

function v14PresealPinFixture(baseBytes) {
  const sha = (value) => createHash('sha256').update(value).digest('hex');
  const names = ['pi_runtime_tree','timeout_policy','credential_env_policy','pi_shrinkwrap',
    'pi_package_manifest','pi_launcher','provider_model_catalog','model_call_pacing_policy'];
  const sources = Object.fromEntries(names.map((name, index) => [name,
    name === 'provider_model_catalog' ? V14_MODEL_POLICY.catalog_sha256
      : name === 'model_call_pacing_policy' ? sha(fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../scripts/s2-008-campaign-v14-pacing.mjs')))
        : sha(Buffer.from('fixture-' + index))]));
  sources.prereg = sha(baseBytes);
  const covers = Object.keys(sources).filter((name) => name !== 'prereg').sort();
  const contentCommitment = canonicalDigest(Object.fromEntries(covers.map((name) => [name, sources[name]])));
  const first = { imageId: 'sha256:' + 'a'.repeat(64), digest: 'sha256:' + 'b'.repeat(64), sources,
    source_digest: canonicalDigest(sources), content_commitment: contentCommitment, content_commitment_covers: covers };
  const second = structuredClone(first);
  return { schema: 's2-008-model-image-pin/14', identical: true, context_digest_stable: true,
    content_commitment_stable: true, commitment_excludes_preregistration: true,
    commitment: { covers, excludes: ['prereg'] }, first, second };
}

test('paid-review inspector accepts the complete synthetic v14 in-force preregistration', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'v14-review-prereg-'));
  try {
    const inputs = v14Approval.readV14BaseInputs({ allowHistorical: true });
    const draft = v14Approval.createV14Draft({ ...inputs,
      pin: v14PresealPinFixture(inputs.baseBytes), restartInputs: v14Approval.readV14RestartInputs() });
    const prereg = { ...draft, status: 'APPROVED', approval: { ...draft.approval,
      status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: 'prn-s2007r-owner', label: 'Daniil',
      issued_at: '2026-10-06T15:00:00.000Z', in_force: true } };
    prereg.preregistration_digest = campaignApproval.preregistrationDigest(prereg);
    const corpus = path.join(root, 'corpus/s2-008-campaign');
    fs.mkdirSync(corpus, { recursive: true });
    fs.writeFileSync(path.join(corpus, 'preregistration.v14.in-force.json'), JSON.stringify(prereg));
    fs.writeFileSync(path.join(corpus, 'manifest.json'), JSON.stringify({ preregistration: {
      file: 'preregistration.v14.in-force.json', status: 'IN_FORCE', sealed_before_first_trial: true,
      preregistration_digest: prereg.preregistration_digest,
    } }));
    const inspected = paidReviewRoute.inspectS2PaidReviewEvidence(root);
    assert.equal(inspected.version, 14);
    assert.equal(inspected.reasons.includes('ACTIVE_PREREGISTRATION_INVALID'), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('v14 draft preserves all 15 frozen members and every frozen member tamper is detected', () => {
  const inputs = v14Approval.readV14BaseInputs({ allowHistorical: true });
  const restartInputs = v14Approval.readV14RestartInputs();
  const draft = v14Approval.createV14Draft({ ...inputs, pin: v14PresealPinFixture(inputs.baseBytes), restartInputs });
  assert.equal(campaignApproval.FROZEN_MEMBERS.length, 15);
  for (const member of campaignApproval.FROZEN_MEMBERS) {
    assert.deepEqual(draft[member], inputs.base[member], member);
    const changed = structuredClone(draft);
    changed[member] = draft[member] === null ? 'tampered' : null;
    assert.equal(campaignApproval.scopeDrift(inputs.base, changed, [member]).member, member);
  }
});

test('v14 probe validation binds signed policy, timeout, historical closure, path and output file', () => {
  const inputs = v14Approval.readV14BaseInputs({ allowHistorical: true });
  const draft = v14Approval.createV14Draft({ ...inputs, pin: v14PresealPinFixture(inputs.baseBytes),
    restartInputs: v14Approval.readV14RestartInputs() });
  const prereg = { ...draft, status: 'APPROVED', approval: { ...draft.approval,
    status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: 'prn-s2007r-owner', label: 'Daniil',
    issued_at: '2026-10-06T15:00:00.000Z', in_force: true } };
  prereg.preregistration_digest = campaignApproval.preregistrationDigest(prereg);
  const manifest = { preregistration: { file: 'preregistration.v14.in-force.json', status: 'IN_FORCE',
    preregistration_digest: prereg.preregistration_digest } };
  assert.deepEqual(probeRoute.validateProbePreregistration({ prereg, manifest }), {
    ok: true, digest: prereg.preregistration_digest, file: 'preregistration.v14.in-force.json' });
  assert.equal(probeRoute.resolveProbePreregistrationPath('corpus/s2-008-campaign/preregistration.v14.in-force.json'),
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..', 'corpus/s2-008-campaign/preregistration.v14.in-force.json'));
  assert.equal(probeRoute.defaultProbeOutputPath(prereg),
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..', 'evidence/s2-008-campaign/probes-v14.json'));
  const invalid = { ...prereg, executor: { ...prereg.executor, model_call_pacing: { min_start_interval_ms: 59999 } } };
  invalid.preregistration_digest = campaignApproval.preregistrationDigest(invalid);
  assert.equal(probeRoute.validateProbePreregistration({ prereg: invalid, manifest: {
    preregistration: { ...manifest.preregistration, preregistration_digest: invalid.preregistration_digest } } }).ok, false);
});

test('v14 draft and signed approval metadata reject extra fields in either copy', () => {
  const approvedAt = '2026-10-06T15:00:00.000Z';
  const validDraftApproval = { status: null, authority: 'HUMAN_OWNER', principal_id: null, label: null,
    issued_at: null, signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
    in_force: false, becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v14 records this digest and supersession in the corpus manifest' };
  assert.equal(v14Approval.assertV14DraftApprovalMetadata(validDraftApproval), true);
  const invalidValues = { status: 'APPROVED', authority: 'OTHER', principal_id: 'prn-s2007r-owner', label: 'Daniil',
    issued_at: approvedAt, signed_digest_over: 'other', in_force: true, becomes_in_force_when: 'other' };
  for (const [key, value] of Object.entries(invalidValues)) {
    assert.throws(() => v14Approval.assertV14DraftApprovalMetadata({ ...validDraftApproval, [key]: value }),
      /V14_APPROVAL_METADATA_INVALID/);
  }
  const draftApproval = { ...validDraftApproval, extra: true };
  assert.throws(() => v14Approval.approveV14({
    draft: { rule: 's2-008-prereg-v14', preregistration_id: 'xpr-s2-008c-14', status: 'DRAFT', approval: draftApproval },
    principal: 'prn-s2007r-owner', label: 'Daniil', issuedAt: approvedAt,
  }), /V14_APPROVAL_METADATA_INVALID/);

  const approval = { status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: 'prn-s2007r-owner',
    label: 'Daniil', issued_at: approvedAt,
    signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
    in_force: false,
    becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v14 records this digest and supersession in the corpus manifest',
    extra: true };
  const signed = { rule: 's2-008-prereg-v14', preregistration_id: 'xpr-s2-008c-14', status: 'APPROVED',
    test_scientific_member: 'bound', approval };
  signed.preregistration_digest = campaignApproval.preregistrationDigest(signed);
  const prereg = { ...signed, approval: { ...approval, in_force: true } };
  prereg.preregistration_digest = campaignApproval.preregistrationDigest(prereg);
  assert.throws(() => sealRoute.assertV14ApprovalBinding({ signed, prereg, expected: { approval } }),
    /V14_APPROVAL_BINDING_MISMATCH/);
});

test('v14 seal preflight rejects each stale target before writing', () => {
  assert.equal(sealRoute.V14_SEAL_TARGETS.length, 4);
  for (const staleTarget of sealRoute.V14_SEAL_TARGETS) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v14-seal-preflight-'));
    try {
      assert.equal(sealRoute.assertV14SealTargetsAbsent(dir), true);
      fs.writeFileSync(path.join(dir, staleTarget), '{}');
      assert.throws(() => sealRoute.assertV14SealTargetsAbsent(dir), /V14_SEAL_TARGET_EXISTS/);
      assert.deepEqual(fs.readdirSync(dir), [staleTarget]);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  }
});

test('evaluator and paid-review routing accept v14 and v15 capsule versions and source lists', () => {
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: 'preregistration.v14.in-force.json' } }), 'v14');
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: 'preregistration.v15.in-force.json' } }), 'v15');
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: 'preregistration.v16.in-force.json' } }), 'v16');
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: 'preregistration.v18.in-force.json' } }), null);
  const entries = evalRoute.V14_REVIEW_CAPSULE_SOURCE_PATHS.map((entryPath) => ({ path: entryPath, contents: Buffer.from(entryPath) }));
  const inputs = evalRoute.buildV14ReviewCapsuleSourceInputs(entries);
  assert.equal(inputs.length, evalRoute.V14_REVIEW_CAPSULE_SOURCE_PATHS.length);
  for (let i = 0; i < inputs.length; i += 1) {
    assert.equal(inputs[i].path, entries[i].path);
    assert.equal(inputs[i].bytes, entries[i].contents.length);
    assert.equal(inputs[i].sha256, createHash('sha256').update(entries[i].contents).digest('hex'));
  }
  assert.ok(inputs.some((row) => row.path === 'scripts/s2-008-campaign-v14-pacing.mjs'));
  assert.ok(inputs.some((row) => row.path === 'scripts/s2-008-campaign-v14-approval.mjs'));
  assert.deepEqual(paidReviewRoute.validateS2PaidReviewCapsuleSourceInputs(inputs, inputs, { version: 14 }), { ok: true });
  assert.deepEqual(paidReviewRoute.validateS2PaidReviewCapsuleSourceInputs(inputs, inputs, { version: 13 }), { ok: false });
  const changed = entries.map((entry) => ({ ...entry }));
  changed[0].path = 'corpus/s2-008-campaign/preregistration.v13.in-force.json';
  assert.throws(() => evalRoute.buildV14ReviewCapsuleSourceInputs(changed), /V14_REVIEW_CAPSULE_SOURCE_INPUTS_INVALID/);
});

test('v14 evaluation reservation is one-shot and sealed manifests retain the v13 lineage reader', () => {
  const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v14-sealed-manifest-'));
  const access = path.join(dir, 'access-once');
  try {
    assert.equal(evalRoute.reserveV14EvaluationAccessRoot(access), access);
    assert.throws(() => evalRoute.reserveV14EvaluationAccessRoot(access), /V14_HOLDOUT_ACCESS_ALREADY_RECORDED/);
    const sourceInputs = v14Approval.readV14RestartInputs();
    const baselineFiles = sourceInputs.baseline.value.files.map((row) => row.file);
    const required = [
      'corpus/s2-008-campaign/preregistration.v13.in-force.json',
      'corpus/s2-008-campaign/preregistration-v13-supersession.json',
      'corpus/s2-008-campaign/frozen-table.v3.json',
      'corpus/s2-008-campaign/source-ledger.v3.json',
      'corpus/s2-008-campaign/manifest.json',
      'evidence/s2-008-campaign/v13-immutable-baseline.json',
      'evidence/s2-008-campaign/reconciliation-v13-a-first-old-key-confirmed.json',
      'evidence/s2-008-campaign/reconciliation-v13-a-second-old-key-confirmed.json',
      'evidence/s2-008-campaign/v13-a-third-stopped/run-v13-a.json',
      'evidence/s2-008-campaign/v13-a-third-stopped/reconciliation.json',
      'evidence/s2-008-campaign/v13-a-third-stopped/predictions-v13-a-trl-s2-008c-01-20260926.json',
      'evidence/s2-008-campaign/v13-a-third-stopped/known-generation-receipts.json',
      'evidence/s2-008-campaign/v13-a-third-stopped/provider-receipts-api-recheck.json',
      'evidence/s2-008-campaign/v13-a-third-stopped/upstream-429-observation.json',
      'evidence/s2-008-campaign/reconciliation-v13-a.json',
      'evidence/s2-008-campaign/credential-attribution-correction-v13.json',
      ...baselineFiles,
    ];
    for (const relative of new Set(required)) {
      const target = path.join(dir, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(sourceRoot, relative), target);
    }
    const manifestPath = path.join(dir, 'corpus/s2-008-campaign/manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const supersession = JSON.parse(fs.readFileSync(path.join(dir, 'corpus/s2-008-campaign/preregistration-v13-supersession.json'), 'utf8'));
    manifest.supersession_history = Array.isArray(manifest.supersession_history) ? manifest.supersession_history : [];
    if (!manifest.supersession_history.some((row) => row.file === 'preregistration-v13-supersession.json')) {
      manifest.supersession_history.push({ file: 'preregistration-v13-supersession.json', supersession_digest: supersession.supersession_digest });
    }
    manifest.preregistration = { ...manifest.preregistration, file: 'preregistration.v14.in-force.json', status: 'IN_FORCE' };
    manifest.superseded_preregistration = { file: 'preregistration-v13-superseded.json',
      preregistration_digest: JSON.parse(fs.readFileSync(path.join(dir, 'corpus/s2-008-campaign/preregistration.v13.in-force.json'), 'utf8')).preregistration_digest,
      status: 'SUPERSEDED', superseded_by: 'preregistration.v14.in-force.json' };
    fs.writeFileSync(manifestPath, JSON.stringify(manifest));
    const historical = v14Approval.readV14BaseInputs({ repoRoot: dir, allowHistorical: true });
    assert.equal(historical.activeManifest.preregistration.file, 'preregistration.v14.in-force.json');
    assert.equal(historical.manifest.preregistration.file, 'preregistration.v13.in-force.json');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('v14 restart lineage binds the corrected 3-attempt closure without upgrading old or failed calls', () => {
  const { base } = v14Approval.readV14BaseInputs({ allowHistorical: true });
  const closure = v14Approval.assertV14RestartReconciliation(base, v14Approval.readV14RestartInputs());
  assert.equal(closure.third_attempt.local_attempts, 3);
  assert.equal(closure.third_attempt.successful_generations, 2);
  assert.equal(closure.third_attempt.failed_upstream_requests, 1);
  assert.equal(closure.third_attempt.owner_closed_unknown_attempts, 1);
  assert.equal(closure.third_attempt.known_tokens, 1586);
  assert.equal(closure.third_attempt.known_usd, 0);
  assert.equal(closure.third_attempt.third_failure_cost, null);
  assert.equal(closure.account_wide_completeness_claimed, false);
  assert.equal(closure.historical_old_key_reconciliations.length, 2);
  assert.equal(closure.superseded_incorrect_reconciliation_file, 'evidence/s2-008-campaign/reconciliation-v13-a.json');
});

test('v14 seals real v13 lineage and rejects missing or changed historical digest', () => {
  const inputs = v14Approval.readV14BaseInputs({ allowHistorical: true });
  const restartInputs = v14Approval.readV14RestartInputs();
  const pin = v14PresealPinFixture(inputs.baseBytes);
  const draft = v14Approval.createV14Draft({ ...inputs, pin, restartInputs });
  const signed = v14Approval.approveV14({ ...inputs, draft, pin, restartInputs,
    principal: 'prn-s2007r-owner', label: 'Daniil', issuedAt: '2026-10-06T15:00:00.000Z' });
  const result = sealRoute.sealV14({ ...inputs, signed, draft, pin, restartInputs,
    baseSupersession: inputs.supersession, baseSupersessionBytes: inputs.supersessionBytes });
  assert.equal(result.prereg.approval.in_force, true);
  const binding = { ...result, base: inputs.base, baseSupersession: inputs.supersession, table: inputs.table };
  assert.deepEqual(sealRoute.assertV14ManifestBinding(binding), { ok: true });
  for (const digest of [undefined, '0'.repeat(64)]) {
    const changed = structuredClone(result.manifest);
    const prior = changed.supersession_history.find(row => row.file === 'preregistration-v13-supersession.json');
    prior.supersession_digest = digest;
    assert.throws(() => sealRoute.assertV14ManifestBinding({ ...binding, manifest: changed }),
      /V14_MANIFEST_BINDING_MISMATCH/);
  }
  assert.throws(() => sealRoute.assertV14ManifestBinding({ ...binding, baseSupersession: undefined }),
    /V14_MANIFEST_BINDING_MISMATCH/);
});

test('v14 sealed runtime validates historical v13 before refusing an undeclared arm', async () => {
  const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const manifest = JSON.parse(fs.readFileSync(path.join(sourceRoot, 'corpus/s2-008-campaign/manifest.json'), 'utf8'));
  if (manifest.preregistration.file !== 'preregistration.v14.in-force.json') return;
  await assert.rejects(() => runRoute.runV4Campaign({
    dryRun: true, write: false, expectedVersion: 14, arm: 'not-preregistered',
  }), /CAMPAIGN_ARM_NOT_PREREGISTERED/);
});
