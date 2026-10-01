import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { FROZEN_MEMBERS, preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import { modelImagePaths } from '../../scripts/s2-008-campaign-model-image.mjs';
import { modelTrialArgv } from '../../scripts/s2-008-campaign-adapter.mjs';

const reconPath = 'evidence/s2-008-campaign/reconciliation-v8-a.json';
const runPath = 'evidence/s2-008-campaign/run-v8-a.json';
const basePath = 'corpus/s2-008-campaign/preregistration.v8.in-force.json';
const baseBytes = fs.readFileSync(basePath);
const base = JSON.parse(baseBytes);
const table = JSON.parse(fs.readFileSync('corpus/s2-008-campaign/frozen-table.v3.json'));
const reconciliation = JSON.parse(fs.readFileSync(reconPath));
const priorRunBytes = fs.readFileSync(runPath);
const sourcePin = JSON.parse(fs.readFileSync('evidence/s2-008-campaign/model-image-pin-v8-preseal.json'));
const measurement = {
  input: 10941, output: 3, cacheRead: 195, totalTokens: 11139,
  traceSha256: 'd'.repeat(64),
};

function pin9() {
  const sources = {
    ...sourcePin.first.sources,
    prereg: createHash('sha256').update(baseBytes).digest('hex'),
  };
  const covers = Object.keys(sources).filter((name) => name !== 'prereg').sort();
  const first = {
    ...sourcePin.first,
    sources,
    source_digest: canonicalDigest(sources),
    content_commitment: canonicalDigest(Object.fromEntries(covers.map((name) => [name, sources[name]]))),
    content_commitment_covers: covers,
  };
  return {
    ...sourcePin,
    schema: 's2-008-model-image-pin/9',
    image_tag: 'localhost/veritas-s2-008-model:v9',
    first,
    second: structuredClone(first),
    commitment: { covers, excludes: ['prereg'] },
  };
}

function createDraft(overrides = {}) {
  const { createV9Draft } = awaitableApproval;
  return createV9Draft({
    base, baseBytes, pin: pin9(), measurement, table,
    reconciliation, priorRunBytes,
    ...overrides,
  });
}
let awaitableApproval;

test('v9 has unique image pins and stages the signed v8 preregistration', () => {
  assert.deepEqual(modelImagePaths('v9', { preseal: true }), {
    tag: 'localhost/veritas-s2-008-model:v9',
    stagedPrereg: 'corpus/s2-008-campaign/preregistration.v8.in-force.json',
    pinFile: 'evidence/s2-008-campaign/model-image-pin-v9-preseal.json',
    schema: 's2-008-model-image-pin/9',
  });
  assert.equal(modelImagePaths('v9').pinFile, 'evidence/s2-008-campaign/model-image-pin-v9.json');
  const argv = modelTrialArgv({
    armId: base.trial_list[0].arm_id,
    seed: 20260926,
    remainingTokens: 5000000,
    preregRule: 's2-008-prereg-v9',
  });
  assert.ok(argv.includes('/opt/veritas/corpus/s2-008-campaign/preregistration.v9.in-force.json'));
  assert.deepEqual(argv.slice(-2), ['--remaining-tokens', '5000000']);
});

test('v9 guard validates the complete owner reconciliation and binds the preserved v8 A bytes', async () => {
  const { assertV8AReconciliation } = await import('../../scripts/s2-008-campaign-v9-approval.mjs');
  const accepted = assertV8AReconciliation({ reconciliation, priorRunBytes });
  assert.equal(accepted.ok, true);
  assert.equal(accepted.priorRunSha256, '57424275104d16799ac67ea554ee684f84ff62d89e52c083db3f773915a7df05');
  assert.equal(accepted.canonicalDigest, canonicalDigest(reconciliation));

  assert.throws(() => assertV8AReconciliation({ reconciliation: null, priorRunBytes }), /RECONCILIATION_MISSING/);
  const wrongHash = structuredClone(reconciliation);
  wrongHash.prior_run_sha256 = '0'.repeat(64);
  assert.throws(() => assertV8AReconciliation({ reconciliation: wrongHash, priorRunBytes }), /PRIOR_RUN_HASH/);
  const incomplete = structuredClone(reconciliation);
  incomplete.completeness.unfiltered = false;
  assert.throws(() => assertV8AReconciliation({ reconciliation: incomplete, priorRunBytes }), /COMPLETENESS/);
  const matching = structuredClone(reconciliation);
  matching.matching_requests = 1;
  assert.throws(() => assertV8AReconciliation({ reconciliation: matching, priorRunBytes }), /MATCHING_ACTIVITY/);
  const oldPrereq = structuredClone(reconciliation);
  oldPrereq.preregistration_digest = 'e'.repeat(64);
  assert.throws(() => assertV8AReconciliation({ reconciliation: oldPrereq, priorRunBytes }), /PREREG_BINDING/);
  const sessionDrift = structuredClone(reconciliation);
  sessionDrift.rows[0].session_id = 'different-session';
  assert.throws(() => assertV8AReconciliation({ reconciliation: sessionDrift, priorRunBytes }), /EXCLUDED_ROWS/);
});

test('v9 draft carries v8 science and cap with a digest-bound fresh-run reconciliation', async () => {
  awaitableApproval = await import('../../scripts/s2-008-campaign-v9-approval.mjs');
  const draft = createDraft();
  for (const member of FROZEN_MEMBERS) assert.deepEqual(draft[member], base[member], member);
  assert.equal(base.rule, 's2-008-prereg-v8');
  assert.equal(base.preregistration_digest, preregistrationDigest(base));
  assert.equal(draft.rule, 's2-008-prereg-v9');
  assert.equal(draft.preregistration_id, 'xpr-s2-008c-09');
  assert.equal(draft.supersession.supersedes, base.preregistration_id);
  assert.equal(draft.budget_reservation.reservation_id, 'rsv-s2-008c-09');
  assert.equal(draft.budget_reservation.granted_units, 5000000);
  assert.equal(draft.budget_reservation.ceiling_scope, 'PER_RUN_A_OR_B');
  assert.equal(draft.executor.model_image.built_image_pin, 'evidence/s2-008-campaign/model-image-pin-v9.json');
  assert.equal(draft.restart_reconciliation.canonical_digest, canonicalDigest(reconciliation));
  assert.equal(draft.restart_reconciliation.prior_run_sha256, reconciliation.prior_run_sha256);
  assert.equal(draft.recorded_before_first_trial.first_trial, 'NOT_STARTED');

  assert.throws(() => createDraft({ reconciliation: null }), /RECONCILIATION_MISSING/);
  assert.throws(() => createDraft({ base: JSON.parse(fs.readFileSync('corpus/s2-008-campaign/preregistration.v7.in-force.json')) }), /V9_BASE_NOT_IN_FORCE/);
});

test('a call reports provider correlation and the sidecar verifies per-case usage totals', async () => {
  const { callModel } = await import('../../scripts/s2-008-campaign-arm-model.mjs');
  const { persistPredictions } = await import('../../scripts/s2-008-campaign-adapter.mjs');
  const stdout = `${JSON.stringify({
    type: 'agent_end',
    sessionId: 'session-observed',
    messages: [{
      role: 'assistant',
      responseId: 'gen-observed-001',
      content: [{ type: 'text', text: 'MINOR' }],
      usage: { input: 432, output: 4, cacheRead: 142, cacheWrite: 0, totalTokens: 578, cost: { total: 0 } },
    }],
  })}\n`;
  const result = callModel('safe synthetic input', {
    provider: 'openrouter', model: 'stealth/space-bunny-alpha',
    envName: 'OPENROUTER_API_KEY', env: { OPENROUTER_API_KEY: 'test-only' },
    dryRun: false, timeoutMs: 1000, execFile: () => stdout,
  });
  assert.deepEqual(result.accounting, {
    generation_id: 'gen-observed-001', session_id: 'session-observed',
    correlation_status: 'CORRELATED', correlation_issue: null,
    input: 432, output: 4, cacheRead: 142, cacheWrite: 0,
    prompt_tokens: 574, prompt_token_basis: 'input+cacheRead+cacheWrite',
    totalTokens: 578, reported_cost_usd: 0,
  });

  const output = {
    predictions: [{ case_id: 'case-1', predicted: 'MINOR' }],
    accounting: [{ case_id: 'case-1', ...result.accounting }],
    executor: { model_calls: 1 },
    budget: { spent_tokens: 578, usd_spent: 0 },
    outcome_class: 'MEASURED',
  };
  let sidecar;
  const saved = persistPredictions({
    output, armId: 'arm-model-test', seed: 20260926, runLabel: 'v9-a',
    sink: (_digest, body) => { sidecar = body; },
  });
  assert.equal(saved.rows, 1);
  assert.equal(sidecar.accounting.calls, 1);
  assert.equal(sidecar.accounting.tokens, 578);
  assert.equal(sidecar.accounting.reported_cost_usd, 0);
  assert.equal(sidecar.accounting.rows[0].generation_id, 'gen-observed-001');
  assert.equal(sidecar.accounting.rows[0].prompt_tokens, 574);

  assert.throws(() => persistPredictions({
    output: { ...output, budget: { ...output.budget, spent_tokens: 579 } },
    armId: 'arm-model-test', seed: 20260926, runLabel: 'v9-a', sink: () => {},
  }), /ACCOUNTING_TOKEN_SUM/);
  assert.throws(() => persistPredictions({
    output: { ...output, executor: { model_calls: 2 } },
    armId: 'arm-model-test', seed: 20260926, runLabel: 'v9-a', sink: () => {},
  }), /ACCOUNTING_CALL_COUNT/);
});

test('v9 refuses correlation without erasing observed usage or guessing an ID', async () => {
  const { callModel } = await import('../../scripts/s2-008-campaign-arm-model.mjs');
  const stdout = `${JSON.stringify({
    type: 'agent_end',
    messages: [{
      role: 'assistant',
      content: [{ type: 'text', text: 'MINOR' }],
      usage: { input: 20, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 21, cost: { total: 0 } },
    }],
  })}\n`;
  const result = callModel('safe synthetic input', {
    provider: 'openrouter', model: 'stealth/space-bunny-alpha',
    envName: 'OPENROUTER_API_KEY', env: { OPENROUTER_API_KEY: 'test-only' },
    dryRun: false, timeoutMs: 1000, execFile: () => stdout,
  });
  assert.equal(result.usage.totalTokens, 21);
  assert.equal(result.accounting.generation_id, null);
  assert.equal(result.accounting.correlation_status, 'UNAVAILABLE');
  assert.equal(result.accounting.correlation_issue, 'GENERATION_ID_MISSING');
});
