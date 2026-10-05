import test from 'node:test';
import assert from 'node:assert/strict';
import { createA05ReviewServer, hashA05ReviewToken } from '../../scripts/a-mvp05-review.mjs';

const TOKEN = 'fixture-only-paid-review-action-token';
const OWNER = 'prn-s2007r-owner';
const TASK = 'abt-s2-008-v11-paid-review';
const DIGEST = 'a'.repeat(64);

test('fixture-only paid review uses the authenticated human start and snapshot decision protocol', async (t) => {
  const credential = {
    tokenHash: hashA05ReviewToken(TOKEN),
    principalId: OWNER,
    taskId: TASK,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    actions: ['view', 'start', 'approve', 'request_changes'],
  };
  let task = { state: 'PENDING', ready: true, revision: 1,
    producerPrincipalId: 'prn-s2-008-evidence-importer' };
  let starts = 0;
  let decisions = 0;
  const workflow = {
    async status() {
      return { ...task, artifactManifestDigest: DIGEST,
        expectedArtifactManifestDigest: DIGEST, currentArtifactManifestDigest: DIGEST };
    },
    async start({ principalId, taskId }) {
      assert.equal(principalId, OWNER);
      assert.equal(taskId, TASK);
      starts += 1;
      task = { ...task, state: 'IN_REVIEW', revision: 2 };
      return this.status();
    },
    async decide({ principalId, taskId, decision, observed }) {
      assert.equal(principalId, OWNER);
      assert.equal(taskId, TASK);
      assert.equal(decision, 'approve');
      assert.deepEqual(observed, { artifactManifestDigest: DIGEST, taskRevision: 2 });
      decisions += 1;
      task = { ...task, state: 'DONE', revision: 3 };
      return { ...(await this.status()), decisionReceipt: { actor: OWNER, fixture_test_only: true } };
    },
  };
  const server = createA05ReviewServer({ credential, workflow, presentation: 'paid-evidence-review' });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const origin = 'http://127.0.0.1:' + server.address().port;
  const headers = { authorization: 'Bearer ' + TOKEN };

  const page = await fetch(origin + '/');
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Одобрить/);
  const script = await fetch(origin + '/paid-review-app.js');
  assert.equal(script.status, 200);

  const stateResponse = await fetch(origin + '/api/state', { headers });
  assert.equal(stateResponse.status, 200);
  assert.equal((await stateResponse.json()).state, 'PENDING');
  const started = await fetch(origin + '/api/start', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(started.status, 200);
  assert.equal((await started.json()).state, 'IN_REVIEW');
  assert.equal(starts, 1);

  const decided = await fetch(origin + '/api/decision', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' },
    body: JSON.stringify({ decision: 'approve', reason: 'Reviewed the bound paid evidence snapshot.',
      observed_manifest_digest: DIGEST, expected_revision: 2 }),
  });
  assert.equal(decided.status, 200);
  const receipt = await decided.json();
  assert.equal(receipt.state, 'DONE');
  assert.equal(receipt.decisionReceipt.actor, OWNER);
  assert.equal(starts, 1);
  assert.equal(decisions, 1);
});

import * as paid from '../../scripts/s2-008-paid-review.mjs';
import { replayA05Journal } from '../../scripts/a-mvp05-runtime.mjs';

test('fixture-only successful checks require command, test summaries, and an observed zero exit', () => {
  const good = [
    'COMMAND: npm test',
    '> veritas-agent-board@0.1.0 test',
    '# pass 1914',
    '# fail 0',
    '# cancelled 0',
    '# skipped 8',
    'EXIT_STATUS=0',
  ].join('\n') + '\n';
  assert.equal(paid.verifyS2PaidReviewCheckLog('npm-test', good).summary.pass, 1914);
  assert.throws(() => paid.verifyS2PaidReviewCheckLog('npm-test', good.replace('EXIT_STATUS=0', 'EXIT_STATUS=1')),
    (error) => error.code === 'PAID_CHECK_LOG_INVALID');
  assert.throws(() => paid.verifyS2PaidReviewCheckLog('npm-test', good.replace('COMMAND: npm test', '')),
    (error) => error.code === 'PAID_CHECK_LOG_INVALID');
});

test('fixture-only campaign coverage includes all three frozen arms and all three seeds', () => {
  const holdoutCaseIds = Array.from({ length: 126 }, (_unused, index) => 'case-' + index);
  const trialList = [
    { trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash' },
    { trial_id: 'trl-s2-008c-02', arm_id: 'arm-type-feat-fix' },
    { trial_id: 'trl-s2-008c-03', arm_id: 'arm-type-chore' },
  ];
  const seeds = [20260926, 20260927, 20260928];
  const observed = trialList.flatMap((trial) => seeds.map((seed) => ({
    trial_id: trial.trial_id,
    arm_id: trial.arm_id,
    seed,
    caseIds: [...holdoutCaseIds],
    unparsed: 0,
  })));
  const result = paid.verifyS2PaidReviewCoverage({ trialList, seeds, holdoutCaseIds, observed });
  assert.deepEqual({ total: result.totalPredictions, model: result.modelPredictions, controls: result.controlPredictions },
    { total: 1134, model: 378, controls: 756 });
  assert.throws(() => paid.verifyS2PaidReviewCoverage({
    trialList: [trialList[2]], seeds, holdoutCaseIds,
    observed: observed.filter((row) => row.arm_id === 'arm-model-zai-glm53flash'),
  }), (error) => error.code === 'PAID_REVIEW_COVERAGE_INVALID');
});

test('fixture-only v11 reconciliation binds each receipt to the local generation and nonzero USD sum', () => {
  const createdAt = '2026-10-04T12:00:00.000Z';
  const timestamp = String(Math.floor(Date.parse(createdAt) / 1000));
  const generations = ['AbcdefghijklmnopQRST', 'BcdefghijklmnopQRSTU', 'CdefghijklmnopQRSTUV']
    .map((suffix) => 'gen-' + timestamp + '-' + suffix);
  const localRows = generations.map((generation, index) => ({
    case_id: 'case-' + (index + 1), generation_id: generation, correlation_status: 'CORRELATED',
    input: 432, output: 4, cacheRead: 142, cacheWrite: 0, prompt_tokens: 574,
    prompt_token_basis: 'input+cacheRead+cacheWrite', totalTokens: 578,
    reported_cost_usd: 0, usage_components_consistent: true,
  }));
  const sidecar = { kind: 's2-008-campaign-predictions/1', accounting: {
    schema: 's2-008-model-accounting/1', policy: 'GENERATION_ID_REQUIRED',
    calls: 3, tokens: 1734, prompt_tokens: 1722, reported_cost_usd: 0, rows: localRows } };
  const providerRows = generations.map((generation) => ({
    id: generation, http_status: 200, created_at: createdAt,
    model: 'stealth/space-bunny-alpha', provider: 'Stealth', native_prompt: 574,
    native_completion: 4, native_cached: 142, total_cost: 0.001,
    generation_time: 1200, cancelled: false, finish_reason: 'stop', matches_local: true,
  }));
  const reconciliation = {
    status: 'RECONCILED', completeness_basis: 'KNOWN_ATTEMPTS_ALL_RECEIPTS',
    completeness: { basis: 'KNOWN_ATTEMPTS_ALL_RECEIPTS', all_local_attempts_accounted: true,
      unfiltered_account_ledger_claimed: false, confirmed_by: null },
    provider_rows_verified_via_api: true, completeness_verified_via_api: false,
    matching_requests: 3, local_model_attempts: 3, locally_accounted_model_calls: 3,
    actual_tokens: 1734, actual_usd: 0.003, unreconciled_attempts: 0,
    rows: localRows.map((row) => ({
      generation_id: row.generation_id, case_id: row.case_id, created_at: createdAt,
      input: row.input, output: row.output, cached: row.cacheRead,
      total_tokens: row.totalTokens, provider_reported_usd: 0.001,
    })),
  };
  const receipts = { status: 'KNOWN_GENERATIONS_MATCH', known_calls: 3, known_tokens: 1734,
    known_provider_usd: 0.003, unknown_attempts: 0, receipts: providerRows };
  const report = {
    status: 'MEASURED', model_calls: 3, model_calls_is_lower_bound: false,
    unknown_model_attempts: 0, unreconciled_spend: false, spent_units: 1734,
    spent_units_is_lower_bound: false,
    trials: [{ trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash',
      seeds: [20260926, 20260927, 20260928].map((seed) => ({
        seed, launch: { arm_report: { executor: { model_attempts: 1, model_calls: 1, unknown_model_attempts: 0 } } },
      })),
    }],
  };
  const result = paid.validateS2PaidReviewGenerationAccounting({ report, sidecar, reconciliation, receipts });
  assert.deepEqual(result, { calls: 3, tokens: 1734, usd: 0.003 });
  const bad = structuredClone(reconciliation);
  bad.rows[0].cached = 141;
  assert.throws(() => paid.validateS2PaidReviewGenerationAccounting({ report, sidecar, reconciliation: bad, receipts }),
    (error) => error.code === 'V11_RECONCILIATION_LOCAL_PROVIDER_MISMATCH');
  const missingCost = structuredClone(receipts);
  delete missingCost.receipts[0].total_cost;
  assert.throws(() => paid.validateS2PaidReviewGenerationAccounting({ report, sidecar, reconciliation, receipts: missingCost }),
    (error) => error.code === 'V11_RECONCILIATION_LOCAL_PROVIDER_MISMATCH');
  const contradictoryAttempts = structuredClone(report);
  contradictoryAttempts.trials[0].seeds[0].launch.arm_report.executor.model_attempts = 2;
  assert.throws(() => paid.validateS2PaidReviewGenerationAccounting({ report: contradictoryAttempts, sidecar, reconciliation, receipts }),
    (error) => error.code === 'V11_RECONCILIATION_COMPLETENESS_INVALID');
});

test('fixture-only review task binds owner and distinct producer and the journal head', () => {
  const task = paid.buildS2PaidReviewTask({
    version: 11, taskId: TASK, workspaceId: 'ws-s2-008-v11-paid-review',
    evidenceDigest: DIGEST, imageId: 'sha256:' + 'b'.repeat(64),
    ownerPrincipalId: OWNER, producerPrincipalId: 'prn-s2-008-evidence-importer',
    adapterId: 'adr-s2-008-v11-importer', at: '2026-10-04T12:00:00.000Z',
  });
  assert.ok(task.acl.allowed_principal_ids.includes(OWNER));
  assert.ok(task.cost_limits.max_task_cost > 0, 'AgentBoard execution needs an explicit positive finite grant for the offline-only importer');
  assert.ok(task.acl.allowed_principal_ids.includes('prn-s2-008-evidence-importer'));
  assert.notEqual(task.acl.allowed_principal_ids[0], task.acl.allowed_principal_ids[1]);
  assert.equal(replayA05Journal(task, []).ok, true);
  assert.throws(() => replayA05Journal({ ...task, history_digest: 'sha256:' + '0'.repeat(64) }, []),
    (error) => error.code === 'JOURNAL_HEAD_INVALID');
});
