import test from 'node:test';
import assert from 'node:assert/strict';
import { createA05ReviewServer, hashA05ReviewToken } from '../../scripts/a-mvp05-review.mjs';
import * as paid from '../../scripts/s2-008-paid-review.mjs';
import { replayA05Journal } from '../../scripts/a-mvp05-runtime.mjs';
import { decisionIndependent, scoreRecordedPredictions, scoreV4Trial } from '../../scripts/s2-008-campaign-evaluate.mjs';
import * as evaluator from '../../scripts/s2-008-campaign-evaluate.mjs';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { contentCommitmentOf } from '../../scripts/s2-008-campaign-model-image.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { campaignImageContextDigest } from '../../scripts/s2-008-campaign-adapter.mjs';
import { buildInvocation } from '../../src/lib/isolation/launch.mjs';
import { SANDBOX_ISOLATION_EXECUTOR } from '../../src/lib/isolation/profile.mjs';

const TOKEN = 'fixture-only-paid-review-action-token';
const OWNER = 'prn-s2007r-owner';
const TASK = 'abt-s2-008-v11-fixture-012345abcdef';
const DIGEST = 'a'.repeat(64);

test('paid-review workflow accepts v14 through v16 while rejecting unsupported v17', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-paid-review-version-'));
  const options = {
    pool: null, evidenceRoot: root,
    inspectEvidence: () => ({ version: 14, ready: false }),
    buildTask: (value) => value,
    ownerPrincipalId: OWNER, producerPrincipalId: 'prn-s2-008-evidence-importer',
    stateRoot: path.join(root, 'state'), replayJournal: () => ({ ok: true }),
    fixtureOnly: true, fixtureRoot: root,
    fixtureRecords: [{ path: 'fixture.json', bytes: 0, sha256: '0'.repeat(64) }],
  };
  try {
    const workflow = paid.createS2PaidReviewWorkflow({ ...options, version: 14 });
    assert.equal(workflow.version, 14);
    assert.equal(workflow.fixtureOnly, true);
    const status = await workflow.status({ principalId: OWNER, taskId: workflow.taskId });
    assert.equal(status.version, 14);
    assert.equal(status.fixture_only, true);
    const v15Workflow = paid.createS2PaidReviewWorkflow({ ...options, version: 15 });
    assert.equal(v15Workflow.version, 15);
    const v15Status = await v15Workflow.status({ principalId: OWNER, taskId: v15Workflow.taskId });
    assert.equal(v15Status.version, 15);
    assert.equal(v15Status.fixture_only, true);
    const v16Workflow = paid.createS2PaidReviewWorkflow({ ...options, version: 16 });
    assert.equal(v16Workflow.version, 16);
    const v16Status = await v16Workflow.status({ principalId: OWNER, taskId: v16Workflow.taskId });
    assert.equal(v16Status.version, 16);
    assert.equal(v16Status.fixture_only, true);
    assert.throws(() => paid.createS2PaidReviewWorkflow({ ...options, version: 17 }),
      (error) => error.code === 'PAID_REVIEW_VERSION_UNSUPPORTED');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('v11 evaluator source-input producer matches the paid-review capsule consumer', () => {
  const paths = [
    'corpus/s2-008-campaign/preregistration.v11.in-force.json',
    'corpus/s2-008-campaign/manifest.json',
    'corpus/s2-008-campaign/frozen-table.v3.json',
    'corpus/s2-008-campaign/cases/holdout.blind.json',
    'scripts/s2-008-campaign-evaluate.mjs',
    'scripts/s2-008-campaign-bootstrap.mjs',
  ];
  const entries = paths.map((path, index) => ({ path, contents: Buffer.from('capsule-source-' + index) }));
  assert.equal(typeof evaluator.buildV11ReviewCapsuleSourceInputs, 'function');
  assert.equal(typeof paid.validateS2PaidReviewCapsuleSourceInputs, 'function');
  const emitted = evaluator.buildV11ReviewCapsuleSourceInputs(entries);
  assert.deepEqual(emitted, entries.map(({ path, contents }) => ({ path,
    bytes: contents.length, sha256: createHash('sha256').update(contents).digest('hex') })));
  assert.equal(paid.validateS2PaidReviewCapsuleSourceInputs(emitted, emitted).ok, true);
  const changed = structuredClone(emitted);
  changed[0].bytes += 1;
  assert.equal(paid.validateS2PaidReviewCapsuleSourceInputs(changed, emitted).ok, false);
});

test('v11 run readiness uses measured per-seed outcomes from the actual root report schema', () => {
  const report = {
    status: 'MEASURED', unreconciled_spend: false, spent_units_is_lower_bound: false,
    model_calls_is_lower_bound: false, unknown_model_attempts: 0,
    trials: [
      { trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash', seeds: [20260926, 20260927, 20260928] },
      { trial_id: 'trl-s2-008c-02', arm_id: 'arm-type-feat-fix', seeds: [20260926, 20260927, 20260928] },
      { trial_id: 'trl-s2-008c-03', arm_id: 'arm-type-chore', seeds: [20260926, 20260927, 20260928] },
    ].map((trial) => ({ ...trial, seeds: trial.seeds.map((seed) => ({ seed,
      outcome_class: 'MEASURED', launch: { exit_code: 0, signal: null, timed_out: false } })) })),
  };
  const input = { report, accounting: { modelRows: 378, controlRows: 756, rows: 1134 },
    reconciliation: { valid: true, unreconciledAttempts: 0 } };
  assert.equal(typeof paid.validateS2PaidReviewRunReadiness, 'function');
  assert.equal(paid.validateS2PaidReviewRunReadiness(input).ok, true,
    'the real root report has status but no root outcome_class; validated seed outcomes carry measurement status');
  const incompleteSeed = structuredClone(input);
  incompleteSeed.report.trials[1].seeds[2].outcome_class = 'INFRA';
  assert.equal(paid.validateS2PaidReviewRunReadiness(incompleteSeed).ok, false);
  const lowerBound = structuredClone(input);
  lowerBound.report.spent_units_is_lower_bound = true;
  assert.equal(paid.validateS2PaidReviewRunReadiness(lowerBound).ok, false);
});

test('v11 holdout access-root reservation is exclusive and durable before opening', () => {
  assert.equal(typeof evaluator.reserveV11EvaluationAccessRoot, 'function');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-v11-access-reservation-'));
  try {
    const accessRoot = path.join(root, 'v11-evaluation-access');
    assert.equal(evaluator.reserveV11EvaluationAccessRoot(accessRoot), accessRoot);
    assert.equal(fs.statSync(accessRoot).isDirectory(), true);
    assert.throws(() => evaluator.reserveV11EvaluationAccessRoot(accessRoot), /V11_HOLDOUT_ACCESS_ALREADY_RECORDED/);
    assert.equal(fs.statSync(accessRoot).isDirectory(), true, 'a failed second attempt cannot release the one-shot reservation');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('fixture-only review uses a distinct task and permits only the owner request-changes decision', async (t) => {
  const credential = {
    tokenHash: hashA05ReviewToken(TOKEN),
    principalId: OWNER,
    taskId: TASK,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    actions: ['view', 'start', 'request_changes'],
  };
  let task = { state: 'PENDING', ready: true, fixture_only: true, revision: 1,
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
      assert.equal(decision, 'request_changes');
      assert.deepEqual(observed, { artifactManifestDigest: DIGEST, taskRevision: 2 });
      decisions += 1;
      task = { ...task, state: 'BLOCKED', revision: 3 };
      return { ...(await this.status()), decisionReceipt: { actor: OWNER, fixture_only: true } };
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
  assert.equal((await stateResponse.json()).fixture_only, true);
  const started = await fetch(origin + '/api/start', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(started.status, 200);
  assert.equal((await started.json()).state, 'IN_REVIEW');
  assert.equal(starts, 1);

  const decided = await fetch(origin + '/api/decision', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' },
    body: JSON.stringify({ decision: 'request_changes', reason: 'Fixture only; verify exact snapshot binding.',
      observed_manifest_digest: DIGEST, expected_revision: 2 }),
  });
  assert.equal(decided.status, 200);
  const receipt = await decided.json();
  assert.equal(receipt.state, 'BLOCKED');
  assert.equal(receipt.decisionReceipt.actor, OWNER);
  assert.equal(receipt.decisionReceipt.fixture_only, true);

  const deniedApproval = await fetch(origin + '/api/decision', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' },
    body: JSON.stringify({ decision: 'approve', reason: 'Must never approve fixture.', observed_manifest_digest: DIGEST, expected_revision: 2 }),
  });
  assert.equal(deniedApproval.status, 403);
  assert.equal(starts, 1);
  assert.equal(decisions, 1);
});

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
  assert.deepEqual({ modelUnparsed: result.modelUnparsed, controlUnparsed: result.controlUnparsed },
    { modelUnparsed: 0, controlUnparsed: 0 });
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

test('paid review task binds owner, distinct producer, the small offline grant, and journal head', () => {
  const task = paid.buildS2PaidReviewTask({
    version: 11, taskId: 'abt-s2-008-v11-paid-review', workspaceId: 'ws-s2-008-v11-paid-review',
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


test('isolated historical-v12 evidence root stays not ready when its A/B records are absent', async () => {
  const evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-v12-review-missing-'));
  const sourceRoot = process.cwd();
  const copiedPaths = [
    'corpus/s2-008-campaign/preregistration.v12.in-force.json',
    'evidence/s2-008-campaign/reconciliation-v8-a.json',
    'evidence/s2-008-campaign/reconciliation-v9-a.json',
    'evidence/s2-008-campaign/reconciliation-v10-a.json',
    'evidence/s2-008-campaign/run-v10-a.json',
    'evidence/s2-008-campaign/stopped-v10-a.json',
  ];
  try {
    for (const relative of copiedPaths) {
      const target = path.join(evidenceRoot, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(sourceRoot, relative), target);
    }
    const historicalV12 = JSON.parse(fs.readFileSync(path.join(sourceRoot,
      'corpus/s2-008-campaign/preregistration.v12.in-force.json'), 'utf8'));
    const v12Supersession = JSON.parse(fs.readFileSync(path.join(sourceRoot,
      'corpus/s2-008-campaign/preregistration-v12-supersession.json'), 'utf8'));
    const historicalV12Manifest = {
      preregistration: {
        file: 'preregistration.v12.in-force.json',
        status: 'IN_FORCE',
        preregistration_digest: historicalV12.preregistration_digest,
        sealed_before_first_trial: true,
      },
      supersession: {
        file: 'preregistration-v12-supersession.json',
        supersession_id: v12Supersession.supersession_id,
        supersession_digest: v12Supersession.supersession_digest,
      },
    };
    fs.writeFileSync(path.join(evidenceRoot, 'corpus/s2-008-campaign/manifest.json'),
      JSON.stringify(historicalV12Manifest));
    const evidence = paid.inspectS2PaidReviewEvidence(evidenceRoot);
    assert.equal(evidence.version, 12);
    assert.equal(evidence.reasons.includes('ACTIVE_PREREGISTRATION_INVALID'), false);
    assert.equal(evidence.campaign.history.v10RestartReconciliationBinding.status, 'RECONCILED');
    assert.equal(evidence.ready, false);
    assert.equal(evidence.state, 'NOT_READY');
    assert.equal(evidence.reasons.includes('PAID_REVIEW_WORKFLOW_UNAVAILABLE'), false);
    assert.equal(evidence.reasons.includes('RUN_A_MISSING'), true);
    assert.equal(evidence.reasons.includes('RUN_B_MISSING'), true);
    assert.equal(evidence.campaign.history.priorKnownCampaignTokens, 23168);
    assert.equal(fs.existsSync(path.join(evidenceRoot, 'evidence/s2-008-campaign/run-v12-a.json')), false);
    assert.equal(fs.existsSync(path.join(evidenceRoot, 'evidence/s2-008-campaign/run-v12-b.json')), false);

    const workflow = paid.createS2PaidReviewWorkflow({
      pool: null, evidenceRoot, version: evidence.version, stateRoot: path.join(evidenceRoot, 'review-state'),
    });
    assert.equal(Object.isFrozen(workflow), true);
    const taskId = 'abt-s2-008-v12-paid-review';
    const view = await workflow.status({ principalId: OWNER, taskId });
    assert.equal(view.reviewSummary.campaign.version, evidence.version);
    assert.equal(view.importReport, null);
    await assert.rejects(workflow.start({ principalId: OWNER, taskId }),
      (error) => error.code === 'PAID_REVIEW_NOT_READY');
  } finally {
    fs.rmSync(evidenceRoot, { recursive: true, force: true });
  }
});


test('fixture-only verifier replays the existing bootstrap from all primary predictions', () => {
  const holdoutCases = Array.from({ length: 126 }, (_unused, index) => ({
    case_id: 'case-' + index, label: index < 63 ? 'MAJOR' : 'MINOR',
  }));
  const trials = [
    { trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash' },
    { trial_id: 'trl-s2-008c-02', arm_id: 'arm-type-feat-fix' },
    { trial_id: 'trl-s2-008c-03', arm_id: 'arm-type-chore' },
  ];
  const seeds = [20260926, 20260927, 20260928];
  const prereg = {
    seed_rule: { seeds, point_estimate: 'OBSERVED_RATE_SEED_INVARIANT' },
    noise_rule: { band: 0.02 },
    multiplicity_rule: { alpha: 0.05, confidence: 0.9833333333333333,
      family_size: 3, direction: 'two_sided', null_value: 0.5, bootstrap_samples: 200 },
  };
  const predictionRowsByArm = {};
  const runReports = {};
  const evaluation = {
    kind: 's2-008-campaign-v11-evaluation/1',
    verdict: 'PENDING_HUMAN_REVIEW',
    prediction_source: 'IMMUTABLE_RUN_SIDECARS',
    deterministic_evaluation: { verdict: 'AGREES', remarks: [] },
    table: { verdict: 'AGREES' },
    reproducibility: { same_base: true, distinct_raw_run_ids: true },
    runs: [],
  };
  const base = { commit_sha: 'c'.repeat(40), tree_sha: 'd'.repeat(40) };
  for (const arm of ['a', 'b']) {
    const rows = [];
    const vectors = [];
    const perSeedByTrial = new Map();
    for (const entry of trials) for (const seed of seeds) {
      const cell = holdoutCases.map((item, index) => {
        let predicted = item.label;
        if (arm === 'b' && entry.trial_id === trials[0].trial_id && index === 0) predicted = 'UNPARSED';
        return { trial_id: entry.trial_id, arm_id: entry.arm_id, seed,
          case_id: item.case_id, predicted };
      });
      const predictionDigest = canonicalDigest(cell);
      rows.push(...cell.map((row) => ({ ...row, prediction_digest: predictionDigest })));
      const score = scoreRecordedPredictions({
        rows: cell, labels: new Map(holdoutCases.map((item) => [item.case_id, item.label])),
        expectedIds: holdoutCases.map((item) => item.case_id),
      });
      const agreement = holdoutCases.map((item) => cell.find((row) => row.case_id === item.case_id)?.predicted === item.label ? 1 : 0);
      perSeedByTrial.set(entry.trial_id, [...(perSeedByTrial.get(entry.trial_id) ?? []), {
        seed, agreeing: score.agreeing, denominator: score.rows,
        observed: score.agreeing / score.rows, unparsed: score.unparsed,
        prediction_digest: predictionDigest,
      }]);
      vectors.push({ trial_id: entry.trial_id + '@' + seed, arm_id: entry.arm_id, agreement });
    }
    predictionRowsByArm[arm] = rows;
    const bootstrap = paid.runS2PaidReviewBootstrap({
      vectors, seeds, samples: prereg.multiplicity_rule.bootstrap_samples,
      confidence: prereg.multiplicity_rule.confidence,
    });
    const scoredTrials = trials.map((entry) => {
      const perSeed = perSeedByTrial.get(entry.trial_id);
      const bootstrapRows = perSeed.map((row) => {
        const result = bootstrap.results.find((item) => item.trial_id === entry.trial_id + '@' + row.seed
          && item.arm_id === entry.arm_id && item.seed === row.seed);
        return { ...result, trial_id: entry.trial_id };
      });
      const scored = scoreV4Trial({ entry, per_seed: perSeed, bootstrapRows, prereg });
      assert.equal(scored.ok, true);
      return scored;
    });
    const numerator = scoredTrials.reduce((sum, row) => sum + row.agreeing, 0);
    const denominator = scoredTrials.reduce((sum, row) => sum + row.denominator, 0);
    const interval = { lower: Math.min(...scoredTrials.map((row) => row.interval.lower)),
      upper: Math.max(...scoredTrials.map((row) => row.interval.upper)) };
    const decision = decisionIndependent({
      observed: numerator / denominator, lower: interval.lower, upper: interval.upper,
      noiseBand: prereg.noise_rule.band, alpha: prereg.multiplicity_rule.alpha,
      confidence: prereg.multiplicity_rule.confidence, familySize: prereg.multiplicity_rule.family_size,
      direction: prereg.multiplicity_rule.direction, nullValue: prereg.multiplicity_rule.null_value,
    });
    const projection = { trials: scoredTrials.map((row) => ({
      trial_id: row.trial_id, agreeing: row.agreeing, denominator: row.denominator,
      interval: row.interval, outcome: row.outcome,
    })), campaign: decision.decision };
    const rawRunId = 'run-' + arm;
    runReports[arm] = { raw_run_id: rawRunId, spent_units: 0, model_calls: 0, base, trials: [] };
    evaluation.runs.push({
      label: arm, raw_run_id: rawRunId, spent_units: 0, model_calls: 0, base,
      bootstrap: { record: { real_start: { proven: true } }, output_digest: canonicalDigest(bootstrap) },
      trials: scoredTrials,
      pooled: { numerator, denominator, observed: numerator / denominator, interval, decision },
      decision_digest: canonicalDigest(projection),
    });
  }
  evaluation.reproducibility.same_decision_digest =
    evaluation.runs[0].decision_digest === evaluation.runs[1].decision_digest;
  const input = { evaluation, runReports, predictionRowsByArm, holdoutCases, prereg, capsuleVerified: true };
  assert.equal(paid.validateS2PaidReviewEvaluation(input).ok, true,
    'A/B may differ; each evaluation is independently rederived from the primary sidecars');

  const alteredCount = structuredClone(input);
  alteredCount.evaluation.runs[0].trials[0].agreeing += 1;
  assert.equal(paid.validateS2PaidReviewEvaluation(alteredCount).ok, false);

  const alteredDecision = structuredClone(input);
  const recordedDecision = alteredDecision.evaluation.runs[1].trials[1].decision.decision;
  alteredDecision.evaluation.runs[1].trials[1].decision.decision = recordedDecision === 'POSITIVE' ? 'NEGATIVE' : 'POSITIVE';
  assert.notEqual(alteredDecision.evaluation.runs[1].trials[1].decision.decision, recordedDecision);
  assert.equal(paid.validateS2PaidReviewEvaluation(alteredDecision).ok, false);

  const unparsedDisagreement = structuredClone(input);
  unparsedDisagreement.predictionRowsByArm.a[0].predicted = 'UNPARSED';
  assert.equal(paid.validateS2PaidReviewEvaluation(unparsedDisagreement).ok, false);

  const forgedInterval = structuredClone(input);
  const forgedRun = forgedInterval.evaluation.runs[0];
  const changedTrial = forgedRun.trials[0];
  changedTrial.per_seed.forEach((row) => { row.interval = { lower: 0.99, upper: 0.99 }; });
  changedTrial.interval = { lower: 0.99, upper: 0.99, method: 'HULL_OF_ALL_SEED_INTERVALS' };
  const pooledLower = Math.min(...forgedRun.trials.map((row) => row.interval.lower));
  const pooledUpper = Math.max(...forgedRun.trials.map((row) => row.interval.upper));
  forgedRun.pooled.interval = { lower: pooledLower, upper: pooledUpper };
  const changedDecision = decisionIndependent({
    observed: forgedRun.pooled.observed, lower: pooledLower, upper: pooledUpper,
    noiseBand: prereg.noise_rule.band, alpha: prereg.multiplicity_rule.alpha,
    confidence: prereg.multiplicity_rule.confidence, familySize: prereg.multiplicity_rule.family_size,
    direction: prereg.multiplicity_rule.direction, nullValue: prereg.multiplicity_rule.null_value,
  });
  forgedRun.pooled.decision = changedDecision;
  const forgedProjection = { trials: forgedRun.trials.map((row) => ({
    trial_id: row.trial_id, agreeing: row.agreeing, denominator: row.denominator,
    interval: row.interval, outcome: row.outcome,
  })), campaign: changedDecision.decision };
  forgedRun.decision_digest = canonicalDigest(forgedProjection);
  forgedInterval.evaluation.reproducibility.same_decision_digest =
    forgedInterval.evaluation.runs[0].decision_digest === forgedInterval.evaluation.runs[1].decision_digest;
  assert.equal(forgedInterval.evaluation.deterministic_evaluation.verdict, 'AGREES');
  assert.equal(paid.validateS2PaidReviewEvaluation(forgedInterval).ok, false,
    'A coherent interval and decision rewrite still fails the bootstrap replay.');
});

test('fixture-only blind holdout index accepts the frozen integer commitment timestamps without reading labels', () => {
  const rows = Array.from({ length: 126 }, (_unused, index) => ({
    case_id: 'case-' + index,
    subject: 'fix: example ' + index,
    committed_at: 1790000000000 + index,
  }));
  const declared = rows.map((row) => row.case_id);
  assert.deepEqual(paid.validateS2PaidReviewBlindIndex(rows, declared), { ok: true, caseIds: declared });
  const malformed = structuredClone(rows);
  malformed[0].committed_at = '2026-10-05T00:00:00.000Z';
  assert.equal(paid.validateS2PaidReviewBlindIndex(malformed, declared).ok, false);
});


test('fixture-only v11 image pin rederives both build commitments and source bindings', () => {
  const sources = {
    arm: 'a'.repeat(64), blind: 'b'.repeat(64), prereg: 'c'.repeat(64), recipe: 'd'.repeat(64),
  };
  const commitment = contentCommitmentOf(sources);
  const first = {
    imageId: 'sha256:' + '1'.repeat(64), digest: 'sha256:' + '2'.repeat(64),
    source_digest: canonicalDigest(sources),
    content_commitment: commitment.digest, content_commitment_covers: commitment.covers, sources,
  };
  const pin = {
    schema: 's2-008-model-image-pin/11',
    commitment: { field: 'executor.model_image.content_commitment', covers: commitment.covers, excludes: ['prereg'] },
    first, second: structuredClone(first), identical: true, context_digest_stable: true,
    content_commitment_stable: true, commitment_excludes_preregistration: true,
  };
  assert.equal(paid.validateS2PaidReviewPin({
    pin, preregistrationSha256: sources.prereg, blindSha256: sources.blind,
  }).ok, true);
  const forged = structuredClone(pin);
  forged.first.sources.arm = 'e'.repeat(64);
  assert.equal(paid.validateS2PaidReviewPin({
    pin: forged, preregistrationSha256: sources.prereg, blindSha256: sources.blind,
  }).ok, false);
});

test('fixture-only dry-run refuses absent accounting fields instead of treating them as zero', () => {
  const preregistrationDigest = 'a'.repeat(64);
  const imagePin = { imageId: 'sha256:' + '1'.repeat(64), digest: 'sha256:' + '2'.repeat(64),
    content_commitment: '3'.repeat(64) };
  const dry = {
    status: 'DRY_RUN', dry_run: true, raw_run_id: 'dry-run-a', nonce: 'dry-nonce-a',
    preregistration_digest: preregistrationDigest,
    model_image_pin: imagePin, spent_units: 0, spent_units_is_lower_bound: false,
    unreconciled_spend: false, model_calls: 0, model_calls_is_lower_bound: false,
    unknown_model_attempts: 0, unknown_launch_attempts: 0, launches: 9,
    charges: Array.from({ length: 9 }, () => ({ units: 0 })),
    reservation: { currency: 'tokens', granted_units: 5000000 },
    base: { commit_sha: 'c'.repeat(40), tree_sha: 'd'.repeat(40) },
    trials: [
      { trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash' },
      { trial_id: 'trl-s2-008c-02', arm_id: 'arm-type-feat-fix' },
      { trial_id: 'trl-s2-008c-03', arm_id: 'arm-type-chore' },
    ].map((trial) => ({ ...trial, seeds: [20260926,20260927,20260928].map((seed) => ({
      seed, outcome_class: 'DRY_RUN', launch: {
        exit_code: 0, signal: null, timed_out: false, container_argv: ['run','--network=none'],
        image: imagePin.imageId, image_digest: imagePin.digest,
        arm_report: { dry_run: true, outcome_class: 'DRY_RUN', n_cases: 126,
          predictions: Array.from({ length: 126 }, (_unused, caseIndex) => ({ case_id: 'c' + caseIndex, predicted: 'MINOR' })),
          accounting: [], stop: null, executor: { model_calls: 0, model_attempts: 0, unknown_model_attempts: 0,
            provider: 'openrouter', model: 'stealth/space-bunny-alpha', credential_present: false, credential_in_argv: false, egress_route: null } },
      },
    })) })),
  };
  const input = { dry, preregistrationDigest, pin: imagePin, expectedBase: { commit: dry.base.commit_sha, tree: dry.base.tree_sha } };
  assert.equal(paid.validateS2PaidReviewDryRun(input).ok, true);
  const missingSpend = structuredClone(input);
  delete missingSpend.dry.spent_units;
  assert.equal(paid.validateS2PaidReviewDryRun(missingSpend).ok, false);
  const missingCalls = structuredClone(input);
  delete missingCalls.dry.model_calls;
  assert.equal(paid.validateS2PaidReviewDryRun(missingCalls).ok, false);
});


test('v12 dry-run validates deterministic controls from the separately double-built control pin', () => {
  const preregistrationDigest = 'a'.repeat(64);
  const modelPin = { imageId: 'sha256:' + '1'.repeat(64), digest: 'sha256:' + '2'.repeat(64), content_commitment: '3'.repeat(64) };
  const sourceBase = { commit_sha: 'c'.repeat(40), tree_sha: 'd'.repeat(40) };
  const samples = 2000;
  const timeoutMs = 180000;
  const caseIds = Array.from({ length: 126 }, (_unused, i) => 'case-' + i);
  const controlPin = {
    kind: 's2-008-campaign-control-image-pin/1',
    first: { imageId: 'sha256:' + '4'.repeat(64), digest: 'sha256:' + '5'.repeat(64), architecture: 'amd64', context_digest: campaignImageContextDigest(), build_exit: 0 },
    second: { imageId: 'sha256:' + '4'.repeat(64), digest: 'sha256:' + '5'.repeat(64), architecture: 'amd64', context_digest: campaignImageContextDigest(), build_exit: 0 },
    identical: true, context_digest_stable: true,
    source_base: sourceBase,
  };
  const controlRows = caseIds.map((case_id) => ({ case_id, predicted: 'MINOR' }));
  const dry = {
    status: 'DRY_RUN', dry_run: true, raw_run_id: 'v12-dry-run', nonce: 'v12-dry-nonce', label: 'clean-base',
    preregistration_digest: preregistrationDigest, model_image_pin: modelPin, control_image_pin: controlPin,
    spent_units: 0, spent_units_is_lower_bound: false, unreconciled_spend: false,
    model_calls: 0, model_calls_is_lower_bound: false, unknown_model_attempts: 0, unknown_launch_attempts: 0,
    launches: 9, charges: Array.from({ length: 9 }, () => ({ units: 0 })),
    reservation: { currency: 'tokens', granted_units: 5000000 }, base: sourceBase,
    trials: [
      { trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash' },
      { trial_id: 'trl-s2-008c-02', arm_id: 'arm-type-feat-fix' },
      { trial_id: 'trl-s2-008c-03', arm_id: 'arm-type-chore' },
    ].map((trial) => ({ ...trial, seeds: [20260926, 20260927, 20260928].map((seed) => {
      if (trial.arm_id === 'arm-model-zai-glm53flash') return {
        seed, outcome_class: 'DRY_RUN', launch: {
          exit_code: 0, signal: null, timed_out: false, container_argv: ['run', '--network=none'],
          image: modelPin.imageId, image_digest: modelPin.digest,
          arm_report: { dry_run: true, outcome_class: 'DRY_RUN', n_cases: 126, predictions: controlRows,
            accounting: [], stop: null, executor: { provider: 'openrouter', model: 'stealth/space-bunny-alpha',
              model_calls: 0, model_attempts: 0, unknown_model_attempts: 0,
              credential_present: false, credential_in_argv: false, egress_route: null } },
        },
      };
      const armReport = {
        kind: 's2-008-campaign-adapter-predict/1', arm_id: trial.arm_id, seed, n_cases: 126,
        predictions: controlRows,
        container: { node_version: 'v22.23.3', pid: 1, argv_tail: [trial.arm_id, String(seed)], cwd: '/work', labels_seen: false },
      };
      const invocation = buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
        image: controlPin.first.imageId,
        argv: ['/usr/local/bin/node', '/opt/campaign/arm.mjs', '/opt/campaign/holdout.blind.json',
          '/tmp/campaign-out.json', trial.arm_id, String(seed), String(samples)],
        timeoutMs,
        name: 's2-008-campaign-' + trial.arm_id + '-' + seed,
      });
      const sidecar = {
        kind: 's2-008-campaign-predictions/1', run: 'clean-base', arm_id: trial.arm_id, seed,
        unparsed: 0, model_calls: null, spent_tokens: null, usd_spent: null, outcome_class: null,
        rows: controlRows,
      };
      const outputDigest = canonicalDigest(armReport);
      return {
        seed, outcome_class: 'EXECUTED_CONTROL_DRY_RUN',
        predictions: { digest: canonicalDigest(sidecar), rows: 126, unparsed: 0, file: 'predictions-v12-clean-base-' + trial.trial_id + '-' + seed + '.json' },
        launch: {
          arm_id: trial.arm_id, seed, samples, podman: { executable: 'podman', argv_prefix: [] },
          container_argv: [...invocation.podmanArgv], image: controlPin.first.imageId, image_break_requested: false,
          axes: invocation.axes, exit_code: 0, signal: null, timed_out: false, stderr_excerpt: '', payload_chunks: 1,
          payload_error: null, banner: 'ADAPTER_OK arm=' + trial.arm_id + ' seed=' + seed + ' n=126 predictions=126 pid=1 node=v22.23.3',
          output_digest: outputDigest, predictions: { digest: canonicalDigest(sidecar), rows: 126, unparsed: 0 },
          real_start: { proven: true, separate_process: true, container_pid: 1, host_pid: 777,
            container_runtime_version: 'v22.23.3', pin_rechecked_by: 'src/lib/isolation/image.mjs#assertImageMatchesPin' },
          image_digest: controlPin.first.digest, arm_report: armReport,
          control_execution: { kind: 's2-008-campaign-control-execution/1',
            outcome_class: 'EXECUTED_CONTROL_DRY_RUN', output_digest: outputDigest,
            pin_digest: canonicalDigest(controlPin) },
        },
      };
    }) })),
  };
  const input = { version: 12, dry, preregistrationDigest, pin: modelPin,
    expectedBase: { commit: sourceBase.commit_sha, tree: sourceBase.tree_sha },
    controlPin, expectedCaseIds: caseIds, samples, timeoutMs };
  assert.equal(paid.validateS2PaidReviewDryRun(input).ok, true);
  const wrongControlImage = structuredClone(input);
  wrongControlImage.dry.trials[1].seeds[0].launch.image_digest = 'sha256:' + '9'.repeat(64);
  assert.equal(paid.validateS2PaidReviewDryRun(wrongControlImage).ok, false);
  const wrongControlSeed = structuredClone(input);
  const changedSeed = wrongControlSeed.dry.trials[1].seeds[0];
  changedSeed.seed = 20260927;
  changedSeed.launch.seed = 20260927;
  changedSeed.launch.arm_report.seed = 20260927;
  const changedOutputDigest = canonicalDigest(changedSeed.launch.arm_report);
  changedSeed.launch.output_digest = changedOutputDigest;
  changedSeed.launch.control_execution.output_digest = changedOutputDigest;
  const rehashedSidecar = {
    kind: 's2-008-campaign-predictions/1', run: 'clean-base',
    arm_id: changedSeed.launch.arm_report.arm_id, seed: changedSeed.seed,
    unparsed: 0, model_calls: null, spent_tokens: null, usd_spent: null, outcome_class: null,
    rows: changedSeed.launch.arm_report.predictions,
  };
  changedSeed.launch.predictions.digest = canonicalDigest(rehashedSidecar);
  changedSeed.predictions.digest = canonicalDigest(rehashedSidecar);
  assert.equal(paid.validateS2PaidReviewDryRun(wrongControlSeed).ok, false);
  const networkEnabled = structuredClone(input);
  networkEnabled.dry.trials[1].seeds[0].launch.axes.network.policy = 'allowlist';
  assert.equal(paid.validateS2PaidReviewDryRun(networkEnabled).ok, false);
  const missingOwnReport = structuredClone(input);
  delete missingOwnReport.dry.trials[1].seeds[0].launch.arm_report;
  assert.equal(paid.validateS2PaidReviewDryRun(missingOwnReport).ok, false);
  const forgedControlPin = structuredClone(input);
  forgedControlPin.controlPin = { ...forgedControlPin.controlPin, first: { ...forgedControlPin.controlPin.first, digest: 'sha256:' + '9'.repeat(64) } };
  assert.equal(paid.validateS2PaidReviewDryRun(forgedControlPin).ok, false);
});


test('v12 control pin artifact is bound to raw bytes, label, run identity, base, and double builds', () => {
  const base = { commit: 'c'.repeat(40), tree: 'd'.repeat(40) };
  const pin = {
    kind: 's2-008-campaign-control-image-pin/1',
    first: { imageId: 'sha256:' + '4'.repeat(64), digest: 'sha256:' + '5'.repeat(64),
      architecture: 'amd64', context_digest: campaignImageContextDigest(), build_exit: 0 },
    second: { imageId: 'sha256:' + '4'.repeat(64), digest: 'sha256:' + '5'.repeat(64),
      architecture: 'amd64', context_digest: campaignImageContextDigest(), build_exit: 0 },
    identical: true, context_digest_stable: true,
    source_base: { commit_sha: base.commit, tree_sha: base.tree },
  };
  const report = { raw_run_id: 's2-008c-v12-a-runsafe', nonce: 'nonce-safe', control_image_pin: pin };
  const artifact = {
    kind: 's2-008-campaign-control-image-pin-artifact/1',
    label: 'a',
    raw_run_id: report.raw_run_id,
    nonce: report.nonce,
    base: { commit_sha: base.commit, tree_sha: base.tree },
    control_image_pin: pin,
  };
  const bytes = Buffer.from(JSON.stringify(artifact) + '\n');
  const reference = {
    file: 'evidence/s2-008-campaign/control-image-pin-v12-a.json',
    bytes: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
  const input = { bytes, reference, report, label: 'a', expectedBase: base };
  assert.equal(paid.validateS2PaidReviewControlPinArtifact(input).ok, true);
  const changedBytes = Buffer.from(bytes);
  changedBytes[0] ^= 1;
  assert.equal(paid.validateS2PaidReviewControlPinArtifact({ ...input, bytes: changedBytes }).ok, false);
  assert.equal(paid.validateS2PaidReviewControlPinArtifact({ ...input,
    reference: { ...reference, file: 'evidence/s2-008-campaign/control-image-pin-v12-b.json' } }).ok, false);
  assert.equal(paid.validateS2PaidReviewControlPinArtifact({ ...input,
    report: { ...report, nonce: 'other-nonce' } }).ok, false);
});
