import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';

const pacing = await import('../../scripts/s2-008-campaign-v14-pacing.mjs').catch(() => ({}));
const credentialPolicy = await import('../../scripts/s2-008-campaign-credential-env.mjs');
const V13_MODEL_POLICY = credentialPolicy.V13_MODEL_POLICY;
const V14_MODEL_POLICY = credentialPolicy.V14_MODEL_POLICY;
const V7_PI_SETTINGS = credentialPolicy.V7_PI_SETTINGS;
const validateS2PaidReviewGenerationAccounting = (await import('../../scripts/s2-008-paid-review.mjs')).validateS2PaidReviewGenerationAccounting;

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
]);
const [approvalRoute, prepareRoute, runRoute, evalRoute, imageRoute, adapterRoute, credentialRoute, armRoute] = routes;

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

test('v14 restart lineage binds the corrected 3-attempt closure without upgrading old or failed calls', () => {
  const { base } = v14Approval.readV14BaseInputs();
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
