import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createServer as httpServer } from 'node:http';
import { createA05ReviewServer } from '../../scripts/a-mvp05-review.mjs';
import * as paid from '../../scripts/s2-008-paid-review.mjs';
import {
  createS2PaidReviewServer,
  createS2PaidReviewWorkflow,
  hashS2PaidReviewToken,
  inspectS2PaidReviewEvidence,
} from '../../scripts/s2-008-paid-review.mjs';

const TOKEN = 'fixture-only-paid-review-bearer-token';
const PRINCIPAL = 'prn-s2007r-owner';
const TASK = 'abt-s2-008-v11-paid-review';

function evidenceFixtureRoot(version = 11) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-paid-review-root-'));
  const dir = path.join(root, 'corpus', 's2-008-campaign');
  fs.mkdirSync(dir, { recursive: true });
  // A manifest-only fixture routes the test to v11 while the missing signed
  // preregistration guarantees this is never mistaken for campaign evidence.
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
    kind: 's2-008-campaign-corpus/1',
    preregistration: { file: 'preregistration.v' + version + '.in-force.json', status: 'IN_FORCE', sealed_before_first_trial: true },
  }));
  return root;
}

async function withServer(options, run) {
  const ownsRoot = !options.evidenceRoot;
  const evidenceRoot = options.evidenceRoot ?? evidenceFixtureRoot();
  const server = (options.serverFactory ?? createS2PaidReviewServer)({ ...options, evidenceRoot });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  try { await run(server, 'http://127.0.0.1:' + server.address().port); }
  finally {
    await new Promise((resolve) => server.close(resolve));
    if (ownsRoot) fs.rmSync(evidenceRoot, { recursive: true, force: true });
  }
}

function credential(actions = ['view']) {
  return {
    tokenHash: hashS2PaidReviewToken(TOKEN),
    principalId: PRINCIPAL,
    taskId: TASK,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    actions,
  };
}

function notReadyWorkflow() {
  return {
    async status() {
      return { state: 'PENDING', ready: false, reasons: ['RUN_A_UNKNOWN_SPEND', 'RUN_B_MISSING'] };
    },
    async start() { throw new Error('PAID_REVIEW_NOT_READY'); },
    async decide() { throw new Error('DECISION_NOT_AVAILABLE'); },
  };
}

test('immutable historical financial totals remain separate from the active campaign state', () => {
  const history = inspectS2PaidReviewEvidence().campaign.history;
  assert.equal(history.v10.status, 'RECONCILED');
  assert.equal(history.v10.tokens, 15_856);
  assert.equal(history.v10.usd, 0);
  assert.equal(history.v9.status, 'RECONCILED');
  assert.equal(history.v9.tokens, 7_312);
  assert.equal(history.v9.usd, 0);
  assert.equal(history.v8.tokens, 0);
  assert.equal(history.v7.status, 'UNKNOWN');
  assert.equal(history.authorizedDiagnosticTokens, 578);
  assert.equal(history.priorKnownCampaignTokens, 23_168);
});

test('the existing local review server still requires bearer authentication and rejects caller-supplied actor identity', async () => {
  let starts = 0;
  const service = notReadyWorkflow();
  service.start = async () => { starts += 1; throw new Error('PAID_REVIEW_NOT_READY'); };
  await withServer({ credential: credential(['start', 'approve']), workflow: service, serverFactory: createA05ReviewServer }, async (server, origin) => {
    const unauthenticated = await fetch(origin + '/api/state');
    assert.equal(unauthenticated.status, 401);

    const forgedStart = await fetch(origin + '/api/start', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + TOKEN, origin, 'content-type': 'application/json' },
      body: JSON.stringify({ principalId: 'prn-attacker', taskId: 'abt-attacker' }),
    });
    assert.equal(forgedStart.status, 400);
    assert.equal(starts, 0);
  });
});

test('the paid server binds its credential to the owner and exact scoped actions', () => {
  const evidenceRoot = evidenceFixtureRoot();
  const service = createS2PaidReviewWorkflow({ pool: null, evidenceRoot });
  assert.throws(
    () => createS2PaidReviewServer({
      credential: { ...credential(['approve','request_changes','start','view']), principalId: 'prn-attacker' },
      workflow: service, evidenceRoot,
    }),
    (error) => error.message === 'ACTOR_TASK_MISMATCH',
  );
  assert.throws(
    () => createS2PaidReviewServer({
      credential: credential(['view', 'approve']),
      workflow: service, evidenceRoot,
    }),
    (error) => error.message === 'REVIEW_CREDENTIAL_INVALID',
  );
});

test('the paid workflow refuses incomplete evidence before database or executor work', async () => {
  let databaseCalls = 0;
  const pool = { async query() { databaseCalls += 1; throw new Error('DB_SHOULD_NOT_BE_TOUCHED'); } };
  const evidenceRoot = evidenceFixtureRoot();
  const workflow = createS2PaidReviewWorkflow({ pool, evidenceRoot });
  try {
    await assert.rejects(
      workflow.start({ principalId: PRINCIPAL, taskId: TASK }),
      (error) => error.message === 'PAID_REVIEW_NOT_READY',
    );
    assert.equal(databaseCalls, 0);
  } finally { fs.rmSync(evidenceRoot, { recursive: true, force: true }); }
});

// Keep this import visible to the test runner: the paid server must be a separate
// factory while still using the same loopback-only review protocol.
assert.equal(typeof httpServer, 'function');

test('the active preregistration path is resolved only from the canonical manifest allowlist', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-paid-review-fixture-'));
  try {
    const dir = path.join(root, 'corpus', 's2-008-campaign');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
      kind: 's2-008-campaign-corpus/1',
      preregistration: { file: '../../outside.json', status: 'IN_FORCE', sealed_before_first_trial: true },
    }));
    const state = inspectS2PaidReviewEvidence(root);
    assert.equal(state.ready, false);
    assert.ok(state.reasons.includes('ACTIVE_PREREGISTRATION_PATH_INVALID'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('evidence reads reject parent-directory symlinks that escape the evidence root', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-paid-review-root-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-paid-review-outside-'));
  try {
    fs.mkdirSync(path.join(root, 'corpus'), { recursive: true });
    fs.writeFileSync(path.join(outside, 'manifest.json'), JSON.stringify({
      kind: 's2-008-campaign-corpus/1',
      preregistration: { file: 'preregistration.v10.in-force.json', status: 'IN_FORCE', sealed_before_first_trial: true },
    }));
    fs.symlinkSync(outside, path.join(root, 'corpus', 's2-008-campaign'), 'dir');
    const state = inspectS2PaidReviewEvidence(root);
    assert.ok(state.reasons.includes('EVIDENCE_PATH_INVALID'));
    assert.ok(!state.artifactManifest.some((entry) => entry.path === 'corpus/s2-008-campaign/manifest.json' && entry.sha256));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('the paid state endpoint reports an incomplete isolated v11 fixture without touching the database', async () => {
  const evidenceRoot = evidenceFixtureRoot();
  const workflow = createS2PaidReviewWorkflow({
    pool: { async query() { throw new Error('NO_DATABASE_READ'); } }, evidenceRoot,
  });
  try {
    await withServer({ credential: credential(['approve','request_changes','start','view']), workflow, evidenceRoot }, async (server, origin) => {
      const response = await fetch(origin + '/api/state', { headers: { authorization: 'Bearer ' + TOKEN } });
      assert.equal(response.status, 200);
      const state = await response.json();
      assert.equal(state.ready, false);
      assert.equal(state.version, 11);
      assert.ok(state.reasons.includes('ACTIVE_PREREGISTRATION_INVALID'));
      assert.equal(state.campaign.arms.a.status, 'NOT_RUN');
      assert.equal(state.campaign.arms.b.status, 'NOT_RUN');
    });
  } finally { fs.rmSync(evidenceRoot, { recursive: true, force: true }); }
});

test('view-only credentials cannot mutate even when a test workflow claims readiness', async () => {
  let starts = 0;
  let decisions = 0;
  const service = {
    async status() { return { state: 'NOT_READY', ready: false, revision: 1, fixture_only: true, reasons: ['EVIDENCE_MISSING'] }; },
    async start() { starts += 1; return { state: 'IN_REVIEW' }; },
    async decide() { decisions += 1; return { state: 'DONE' }; },
  };
  await withServer({ credential: credential(), workflow: service, serverFactory: createA05ReviewServer, presentation: 'paid-evidence-review' }, async (server, origin) => {
    const stateResponse = await fetch(origin + '/api/state', { headers: { authorization: 'Bearer ' + TOKEN } });
    assert.equal(stateResponse.status, 200);
    const state = await stateResponse.json();
    assert.equal(state.ready, false);
    assert.equal(state.ready, false);
    assert.equal(state.fixture_only, true);

    const startResponse = await fetch(origin + '/api/start', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + TOKEN, origin, 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(startResponse.status, 403);
    const decisionResponse = await fetch(origin + '/api/decision', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + TOKEN, origin, 'content-type': 'application/json' },
      body: JSON.stringify({ decision: 'approve', reason: 'fixture only', observed_manifest_digest: 'a'.repeat(64), expected_revision: 8 }),
    });
    assert.equal(decisionResponse.status, 403);
    assert.equal(starts, 0);
    assert.equal(decisions, 0);
  });
});

test('the existing local review server refuses stale revisions and changed evidence before a decision', async () => {
  let decisions = 0;
  const good = 'a'.repeat(64);
  const service = {
    async status() {
      return {
        state: 'IN_REVIEW', ready: true, revision: 8,
        producerPrincipalId: 'prn-s2-008-evidence-importer',
        artifactManifestDigest: good, expectedArtifactManifestDigest: good, currentArtifactManifestDigest: good,
      };
    },
    async start() { throw new Error('UNEXPECTED_START'); },
    async decide() { decisions += 1; return { state: 'DONE', fixture_test_only: true }; },
  };
  await withServer({ credential: credential(['approve']), workflow: service, serverFactory: createA05ReviewServer }, async (server, origin) => {
    const stale = await fetch(origin + '/api/decision', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + TOKEN, origin, 'content-type': 'application/json' },
      body: JSON.stringify({ decision: 'approve', reason: 'fixture only', observed_manifest_digest: good, expected_revision: 7 }),
    });
    assert.equal(stale.status, 409);
    assert.equal((await stale.json()).code, 'REVIEW_VERSION_CHANGED');
    assert.equal(decisions, 0);

    service.status = async () => ({
      state: 'IN_REVIEW', ready: true, revision: 8,
      producerPrincipalId: 'prn-s2-008-evidence-importer',
      artifactManifestDigest: good, expectedArtifactManifestDigest: good, currentArtifactManifestDigest: 'b'.repeat(64),
    });
    const changed = await fetch(origin + '/api/decision', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + TOKEN, origin, 'content-type': 'application/json' },
      body: JSON.stringify({ decision: 'approve', reason: 'fixture only', observed_manifest_digest: good, expected_revision: 8 }),
    });
    assert.equal(changed.status, 409);
    assert.equal((await changed.json()).code, 'ARTIFACT_CHANGED');
    assert.equal(decisions, 0);
  });
});

test('the paid server rejects an injected workflow that claims DONE', () => {
  const evidenceRoot = evidenceFixtureRoot();
  const workflow = {
    async status() { return { state: 'DONE', ready: true, revision: 8 }; },
    async start() { throw new Error('NO_START'); },
    async decide() { throw new Error('NO_DECISION'); },
  };
  assert.throws(() => createS2PaidReviewServer({
    credential: credential(['approve','request_changes','start','view']), workflow, evidenceRoot,
  }), (error) => error.code === 'PAID_REVIEW_WORKFLOW_INVALID');
});


test('fixture-only comparison rederives every arm, seed, and case while treating A/B equality as disclosure', () => {
  const trials = [
    { trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash' },
    { trial_id: 'trl-s2-008c-02', arm_id: 'arm-type-feat-fix' },
    { trial_id: 'trl-s2-008c-03', arm_id: 'arm-type-chore' },
  ];
  const seeds = [20260926, 20260927, 20260928];
  const holdoutCaseIds = Array.from({ length: 126 }, (_unused, index) => 'case-' + index);
  const predictions = (run) => trials.flatMap((trial) => seeds.flatMap((seed) => holdoutCaseIds.map((case_id, index) => {
    let predicted = 'MINOR';
    if (trial.arm_id === 'arm-model-zai-glm53flash' && seed === seeds[0] && index === 0) predicted = 'UNPARSED';
    if (run === 'b' && trial.arm_id === 'arm-model-zai-glm53flash' && seed === seeds[0] && index === 1) predicted = 'MAJOR';
    if (run === 'b' && trial.arm_id === 'arm-type-feat-fix' && seed === seeds[1] && index === 0) predicted = 'MAJOR';
    return { trial_id: trial.trial_id, arm_id: trial.arm_id, seed, case_id, predicted };
  })));
  const input = { preregistrationDigest: 'a'.repeat(64), holdoutCaseIds, aPredictions: predictions('a'), bPredictions: predictions('b') };
  const comparison = paid.deriveS2PaidReviewComparison(input);
  assert.equal(comparison.kind, 's2-008-campaign-comparison/1');
  assert.deepEqual(comparison.scope.predictions_per_run, { total: 1134, model: 378, controls: 756 });
  assert.equal(comparison.agreement.compared_predictions, 1134);
  assert.equal(comparison.agreement.equal_predictions, 1132);
  assert.equal(comparison.agreement.differing_predictions, 2);
  assert.equal(comparison.agreement.a_equals_b, false);
  assert.equal(comparison.agreement.criterion, 'DISCLOSURE_ONLY');
  assert.equal(comparison.agreement.by_trial.length, 3);
  assert.equal(comparison.agreement.by_seed.length, 3);
  assert.equal(paid.validateS2PaidReviewComparison({ ...input, comparison }), true);
  const altered = structuredClone(comparison);
  altered.agreement.equal_predictions = 1134;
  assert.throws(() => paid.validateS2PaidReviewComparison({ ...input, comparison: altered }),
    (error) => error.code === 'PAID_REVIEW_COMPARISON_INVALID');
  assert.throws(() => paid.deriveS2PaidReviewComparison({ ...input, bPredictions: input.bPredictions.slice(1) }),
    (error) => error.code === 'PAID_REVIEW_COMPARISON_INVALID');
});
