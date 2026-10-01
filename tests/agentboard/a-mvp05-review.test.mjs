import test from 'node:test';
import assert from 'node:assert/strict';
import { createA05ReviewServer, hashA05ReviewToken } from '../../scripts/a-mvp05-review.mjs';

const TOKEN = 'test-only-a-mvp05-review-token';

async function withServer(options, run) {
  const server = createA05ReviewServer(options);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  try {
    await run({
      server,
      origin: 'http://127.0.0.1:' + server.address().port,
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function request(server, path, { method = 'GET', token, body, origin, host } = {}) {
  const url = 'http://127.0.0.1:' + server.address().port + path;
  const headers = {};
  if (token) headers.authorization = 'Bearer ' + token;
  if (origin) headers.origin = origin;
  if (host) headers.host = host;
  if (body !== undefined) headers['content-type'] = 'application/json';
  return fetch(url, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

function credential(overrides = {}) {
  return {
    tokenHash: hashA05ReviewToken(TOKEN),
    principalId: 'prn-a-mvp05-human-reviewer',
    taskId: 'abt-a-mvp05-review',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    actions: ['start', 'approve', 'request_changes'],
    ...overrides,
  };
}

test('review page is loopback-only, self-contained, and never embeds the bearer token', async () => {
  await withServer({ credential: credential(), workflow: {} }, async ({ server, origin }) => {
    const response = await request(server, '/');
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.match(response.headers.get('content-security-policy'), /connect-src 'self'/);
    const page = await response.text();
    assert.match(page, /Создать задачу и выполнить/);
    assert.match(page, /Принять/);
    assert.match(page, /Запросить изменения/);
    assert.doesNotMatch(page, new RegExp(TOKEN));
    assert.equal(new URL(origin).hostname, '127.0.0.1');
  });
});

test('state reads require the scoped bearer credential and same-origin loopback host', async () => {
  let reads = 0;
  const workflow = {
    async status({ principalId, taskId }) {
      reads += 1;
      return { state: 'PENDING', principalId, taskId };
    },
  };
  await withServer({ credential: credential(), workflow }, async ({ server, origin }) => {
    const unauthenticated = await request(server, '/api/state', { origin });
    assert.equal(unauthenticated.status, 401);
    assert.equal(reads, 0);

    const wrongOrigin = await request(server, '/api/state', {
      origin: 'https://attacker.invalid',
      token: TOKEN,
    });
    assert.equal(wrongOrigin.status, 403);
    assert.equal(reads, 0);

    const wrongHost = await request(server, '/api/state', {
      origin,
      token: TOKEN,
      host: 'attacker.invalid',
    });
    assert.equal(wrongHost.status, 403);
    assert.equal(reads, 0);

    const accepted = await request(server, '/api/state', { origin, token: TOKEN });
    assert.equal(accepted.status, 200);
    assert.deepEqual(await accepted.json(), {
      state: 'PENDING',
      principalId: 'prn-a-mvp05-human-reviewer',
      taskId: 'abt-a-mvp05-review',
    });
    assert.equal(reads, 1);
  });
});

test('start is an authenticated fixed operation; caller cannot choose identity or task', async () => {
  const calls = [];
  const workflow = {
    async start(input) {
      calls.push(input);
      return { state: 'IN_REVIEW', taskId: input.taskId };
    },
  };
  await withServer({ credential: credential(), workflow }, async ({ server, origin }) => {
    const response = await request(server, '/api/start', {
      method: 'POST',
      origin,
      token: TOKEN,
      body: { principal_id: 'prn-attacker', task_id: 'abt-other-task', actor_kind: 'human_owner' },
    });
    assert.equal(response.status, 400);
    assert.deepEqual(calls, []);

    const accepted = await request(server, '/api/start', {
      method: 'POST',
      origin,
      token: TOKEN,
      body: {},
    });
    assert.equal(accepted.status, 200);
    assert.deepEqual(calls, [{
      principalId: 'prn-a-mvp05-human-reviewer',
      taskId: 'abt-a-mvp05-review',
    }]);
  });
});

test('decision re-reads IN_REVIEW state, separates producer, and ignores client digests', async () => {
  const calls = [];
  const workflow = {
    async status() {
      return {
        state: 'IN_REVIEW',
        producerPrincipalId: 'prn-a-mvp05-worker',
        artifactManifestDigest: 'a'.repeat(64),
      };
    },
    async decide(input) {
      calls.push(input);
      return { state: input.decision === 'approve' ? 'DONE' : 'BLOCKED' };
    },
  };
  await withServer({ credential: credential(), workflow }, async ({ server, origin }) => {
    const response = await request(server, '/api/decision', {
      method: 'POST',
      origin,
      token: TOKEN,
      body: {
        decision: 'approve',
        reason: 'Reviewed fixture output and test log.',
        task_id: 'abt-attacker-task',
        principal_id: 'prn-a-mvp05-worker',
        manifest_digest: '0'.repeat(64),
      },
    });
    assert.equal(response.status, 400);
    assert.deepEqual(calls, []);

    const accepted = await request(server, '/api/decision', {
      method: 'POST',
      origin,
      token: TOKEN,
      body: { decision: 'approve', reason: 'Reviewed fixture output and test log.' },
    });
    assert.equal(accepted.status, 200);
    assert.deepEqual(calls, [{
      principalId: 'prn-a-mvp05-human-reviewer',
      taskId: 'abt-a-mvp05-review',
      decision: 'approve',
      reason: 'Reviewed fixture output and test log.',
      observed: {
        artifactManifestDigest: 'a'.repeat(64),
      },
    }]);
  });
});

test('expired credentials and producer self-review are refused before a decision write', async () => {
  let decisions = 0;
  const workflow = {
    async status() {
      return { state: 'IN_REVIEW', producerPrincipalId: 'prn-a-mvp05-human-reviewer' };
    },
    async decide() {
      decisions += 1;
    },
  };
  await withServer({
    credential: credential({ expiresAt: new Date(Date.now() - 1_000).toISOString() }),
    workflow,
  }, async ({ server, origin }) => {
    const response = await request(server, '/api/decision', {
      method: 'POST',
      origin,
      token: TOKEN,
      body: { decision: 'approve', reason: 'reviewed' },
    });
    assert.equal(response.status, 401);
    assert.equal(decisions, 0);
  });

  await withServer({ credential: credential(), workflow }, async ({ server, origin }) => {
    const response = await request(server, '/api/decision', {
      method: 'POST',
      origin,
      token: TOKEN,
      body: { decision: 'approve', reason: 'reviewed' },
    });
    assert.equal(response.status, 403);
    assert.equal(decisions, 0);
  });
});

test('a review decision is refused unless the canonical task is still IN_REVIEW', async () => {
  let decisions = 0;
  const workflow = {
    async status() {
      return { state: 'DONE', producerPrincipalId: 'prn-a-mvp05-worker' };
    },
    async decide() {
      decisions += 1;
    },
  };
  await withServer({ credential: credential(), workflow }, async ({ server, origin }) => {
    const response = await request(server, '/api/decision', {
      method: 'POST',
      origin,
      token: TOKEN,
      body: { decision: 'approve', reason: 'reviewed' },
    });
    assert.equal(response.status, 409);
    assert.equal(decisions, 0);
  });
});
