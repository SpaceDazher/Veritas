import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as httpServer } from 'node:http';
import {
  createS2PaidReviewServer,
  createS2PaidReviewWorkflow,
  hashS2PaidReviewToken,
  inspectS2PaidReviewEvidence,
} from '../../scripts/s2-008-paid-review.mjs';

const TOKEN = 'fixture-only-paid-review-bearer-token';
const PRINCIPAL = 'prn-s2-008-daniil-reviewer';
const TASK = 'abt-s2-008-v10-paid-review';

async function withServer(options, run) {
  const server = createS2PaidReviewServer(options);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  try { await run(server, 'http://127.0.0.1:' + server.address().port); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

function credential() {
  return {
    tokenHash: hashS2PaidReviewToken(TOKEN),
    principalId: PRINCIPAL,
    taskId: TASK,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    actions: ['start', 'approve', 'request_changes'],
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
  assert.equal(state.campaign.arms.a.status, 'BLOCKED');
  assert.equal(state.campaign.arms.a.unknownAttempts, 1);
  assert.equal(state.campaign.arms.a.confirmedTokensLowerBound, 15_856);
  assert.equal(state.campaign.arms.b.status, 'NOT_RUN');
  assert.ok(state.reasons.includes('RUN_A_UNKNOWN_SPEND'));
  assert.ok(state.reasons.includes('RUN_B_MISSING'));
  assert.equal(state.history.v9.tokens, 7_312);
  assert.equal(state.history.v7.status, 'UNKNOWN');
});

test('paid review requires bearer authentication and rejects caller-supplied task or actor identity', async () => {
  let starts = 0;
  const service = notReadyWorkflow();
  service.start = async () => { starts += 1; throw new Error('PAID_REVIEW_NOT_READY'); };
  await withServer({ credential: credential(), workflow: service }, async (server, origin) => {
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
