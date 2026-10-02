import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createServer as httpServer } from 'node:http';
import { createA05ReviewServer } from '../../scripts/a-mvp05-review.mjs';
import {
  createS2PaidReviewServer,
  createS2PaidReviewWorkflow,
  hashS2PaidReviewToken,
  inspectS2PaidReviewEvidence,
} from '../../scripts/s2-008-paid-review.mjs';

const TOKEN = 'fixture-only-paid-review-bearer-token';
const PRINCIPAL = 'prn-s2007r-owner';
const TASK = 'abt-s2-008-v10-paid-review';

async function withServer(options, run) {
  const server = (options.serverFactory ?? createS2PaidReviewServer)(options);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  try { await run(server, 'http://127.0.0.1:' + server.address().port); }
  finally { await new Promise((resolve) => server.close(resolve)); }
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

test('actual stopped A, missing B, and missing evaluation stay visibly not ready with prior spend separated', () => {
  const state = inspectS2PaidReviewEvidence();
  assert.equal(state.ready, false);
  assert.equal(state.workflow.mode, 'READ_ONLY');
  assert.equal(state.workflow.actionable, false);
  assert.ok(state.reasons.includes('PAID_REVIEW_WORKFLOW_UNAVAILABLE'));
  assert.equal(state.campaign.evaluationRecord.status, 'NOT_RUN');
  assert.equal(state.version, 10);
  assert.equal(state.campaign.arms.a.status, 'BLOCKED');
  assert.equal(state.campaign.arms.a.outcomeClass, 'INFRA');
  assert.equal(state.campaign.arms.a.rawUnknownAttempts, 1);
  assert.equal(state.campaign.arms.a.rawTokens, 15_856);
  assert.equal(state.campaign.arms.a.rawTokensAreLowerBound, true);
  assert.equal(state.campaign.arms.a.confirmedTokens, 15_856);
  assert.equal(state.campaign.arms.a.confirmedUsd, 0);
  assert.equal(state.campaign.arms.a.unreconciledAttempts, 0);
  assert.equal(state.campaign.arms.a.financialStatus, 'RECONCILED');
  assert.equal(state.campaign.arms.a.predictions, 25);
  assert.equal(state.campaign.arms.b.status, 'NOT_RUN');
  assert.ok(state.reasons.includes('RUN_A_INFRA'));
  assert.ok(state.reasons.includes('RUN_B_MISSING'));
  assert.ok(state.reasons.includes('EVALUATION_MISSING'));
  assert.ok(!state.reasons.includes('RUN_A_UNKNOWN_SPEND'));
  assert.equal(state.campaign.history.v10.tokens, 15_856);
  assert.equal(state.campaign.history.v9.tokens, 7_312);
  assert.equal(state.campaign.history.v8.tokens, 0);
  assert.equal(state.campaign.history.v7.status, 'UNKNOWN');
  assert.equal(state.campaign.history.authorizedDiagnosticTokens, 578);
  assert.equal(state.campaign.history.priorKnownCampaignTokens, 23_168);
  assert.equal(state.campaign.aggregate.confirmedTokens, 15_856);
  assert.equal(state.campaign.aggregate.complete, false);
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

test('the paid server binds its credential to the owner and view-only permission', () => {
  const service = { async status() { return { ready: false }; }, async start() {}, async decide() {} };
  assert.throws(
    () => createS2PaidReviewServer({
      credential: { ...credential(), principalId: 'prn-attacker' },
      workflow: service,
    }),
    (error) => error.message === 'ACTOR_TASK_MISMATCH',
  );
  assert.throws(
    () => createS2PaidReviewServer({
      credential: credential(['view', 'approve']),
      workflow: service,
    }),
    (error) => error.message === 'REVIEW_CREDENTIAL_INVALID',
  );
});

test('the paid workflow refuses incomplete evidence before database or executor work', async () => {
  let databaseCalls = 0;
  const pool = { async query() { databaseCalls += 1; throw new Error('DB_SHOULD_NOT_BE_TOUCHED'); } };
  const workflow = createS2PaidReviewWorkflow({ pool });
  await assert.rejects(
    workflow.start({ principalId: PRINCIPAL, taskId: TASK }),
    (error) => error.message === 'PAID_REVIEW_NOT_READY',
  );
  assert.equal(databaseCalls, 0);
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

test('the paid state endpoint exposes the evidence-derived current and historical accounting', async () => {
  const workflow = createS2PaidReviewWorkflow({ pool: { async query() { throw new Error('NO_DATABASE_READ'); } } });
  await withServer({ credential: credential(), workflow }, async (server, origin) => {
    const response = await fetch(origin + '/api/state', { headers: { authorization: 'Bearer ' + TOKEN } });
    assert.equal(response.status, 200);
    const state = await response.json();
    assert.equal(state.ready, false);
    assert.equal(state.campaign.arms.a.confirmedTokens, 15_856);
    assert.equal(state.campaign.arms.a.rawUnknownAttempts, 1);
    assert.equal(state.campaign.arms.a.unreconciledAttempts, 0);
    assert.equal(state.campaign.arms.b.status, 'NOT_RUN');
    assert.equal(state.campaign.history.v9.tokens, 7_312);
    assert.equal(state.campaign.history.authorizedDiagnosticTokens, 578);
  });
});

test('paid review is read-only even if an injected workflow claims evidence is ready', async () => {
  let starts = 0;
  let decisions = 0;
  const service = {
    async status() { return { state: 'IN_REVIEW', ready: true, revision: 8 }; },
    async start() { starts += 1; return { state: 'IN_REVIEW' }; },
    async decide() { decisions += 1; return { state: 'DONE' }; },
  };
  await withServer({ credential: credential(), workflow: service }, async (server, origin) => {
    const stateResponse = await fetch(origin + '/api/state', { headers: { authorization: 'Bearer ' + TOKEN } });
    assert.equal(stateResponse.status, 200);
    const state = await stateResponse.json();
    assert.equal(state.ready, false);
    assert.equal(state.workflow.mode, 'READ_ONLY');
    assert.equal(state.workflow.actionable, false);

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

test('the read-only paid endpoint never reports DONE from an injected workflow', async () => {
  const workflow = {
    async status() { return { state: 'DONE', ready: true, revision: 8 }; },
    async start() { throw new Error('NO_START'); },
    async decide() { throw new Error('NO_DECISION'); },
  };
  await withServer({ credential: credential(), workflow }, async (server, origin) => {
    const response = await fetch(origin + '/api/state', {
      headers: { authorization: 'Bearer ' + TOKEN },
    });
    assert.equal(response.status, 200);
    const state = await response.json();
    assert.equal(state.state, 'NOT_READY');
    assert.equal(state.ready, false);
    assert.equal(state.workflow.actionable, false);
  });
});
