import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { createA05ReviewServer, hashA05ReviewToken } from '../../scripts/a-mvp05-review.mjs';

const TOKEN = 'test-only-a-mvp05-review-token';
const DIGEST = 'a'.repeat(64);
const REVISION = 7;

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
  if (host) {
    return new Promise((resolve, reject) => {
      const req = httpRequest(url, { method, headers }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({
            status: response.statusCode,
            headers: new Headers(response.headers),
            async json() { return JSON.parse(text); },
            async text() { return text; },
          });
        });
      });
      req.on('error', reject);
      if (body !== undefined) req.end(JSON.stringify(body));
      else req.end();
    });
  }
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

function defaultStatus(overrides = {}) {
  return {
    state: 'IN_REVIEW',
    producerPrincipalId: 'prn-a-mvp05-worker',
    artifactManifestDigest: DIGEST,
    expectedArtifactManifestDigest: DIGEST,
    currentArtifactManifestDigest: DIGEST,
    revision: REVISION,
    ...overrides,
  };
}

function workflow(overrides = {}) {
  return {
    async status() { return defaultStatus(); },
    async start(input) { return { state: 'PENDING', taskId: input.taskId }; },
    async decide(input) { return { state: input.decision === 'approve' ? 'DONE' : 'BLOCKED' }; },
    ...overrides,
  };
}

async function decide(server, origin, body) {
  return request(server, '/api/decision', {
    method: 'POST',
    origin,
    token: TOKEN,
    body,
  });
}

const exactViewedDecision = {
  decision: 'approve',
  reason: 'Reviewed fixture output and test log.',
  observed_manifest_digest: DIGEST,
  expected_revision: REVISION,
};

test('review page is loopback-only, self-contained, and never embeds the bearer token', async () => {
  await withServer({ credential: credential(), workflow: workflow() }, async ({ server, origin }) => {
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
  const service = workflow({
    async status({ principalId, taskId }) {
      reads += 1;
      return { state: 'PENDING', principalId, taskId };
    },
  });
  await withServer({ credential: credential(), workflow: service }, async ({ server, origin }) => {
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
  const service = workflow({
    async start(input) {
      calls.push(input);
      return { state: 'IN_REVIEW', taskId: input.taskId };
    },
  });
  await withServer({ credential: credential(), workflow: service }, async ({ server, origin }) => {
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

test('decision requires the exact displayed artifact digest and task revision', async () => {
  const calls = [];
  const service = workflow({
    async decide(input) {
      calls.push(input);
      return { state: 'DONE' };
    },
  });
  await withServer({ credential: credential(), workflow: service }, async ({ server, origin }) => {
    const missingBinding = await decide(server, origin, {
      decision: 'approve',
      reason: 'Reviewed the artifact.',
    });
    assert.equal(missingBinding.status, 400);

    const staleDigest = await decide(server, origin, {
      ...exactViewedDecision,
      observed_manifest_digest: '0'.repeat(64),
    });
    assert.equal(staleDigest.status, 409);

    const staleRevision = await decide(server, origin, {
      ...exactViewedDecision,
      expected_revision: REVISION - 1,
    });
    assert.equal(staleRevision.status, 409);
    assert.deepEqual(calls, []);
  });
});

test('decision is refused if current artifact bytes no longer match the manifest shown', async () => {
  let decisions = 0;
  const service = workflow({
    async status() {
      return defaultStatus({ currentArtifactManifestDigest: 'b'.repeat(64) });
    },
    async decide() {
      decisions += 1;
    },
  });
  await withServer({ credential: credential(), workflow: service }, async ({ server, origin }) => {
    const response = await decide(server, origin, exactViewedDecision);
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), { code: 'ARTIFACT_CHANGED' });
    assert.equal(decisions, 0);
  });
});

test('positive decision passes the observed digest and revision to the canonical workflow', async () => {
  const calls = [];
  const service = workflow({
    async decide(input) {
      calls.push(input);
      return { state: 'DONE' };
    },
  });
  await withServer({ credential: credential(), workflow: service }, async ({ server, origin }) => {
    const response = await decide(server, origin, exactViewedDecision);
    assert.equal(response.status, 200);
    assert.deepEqual(calls, [{
      principalId: 'prn-a-mvp05-human-reviewer',
      taskId: 'abt-a-mvp05-review',
      decision: 'approve',
      reason: 'Reviewed fixture output and test log.',
      observed: {
        artifactManifestDigest: DIGEST,
        taskRevision: REVISION,
      },
    }]);
  });
});

test('expired credentials and producer self-review are refused before a decision write', async () => {
  let decisions = 0;
  const service = workflow({
    async status() {
      return defaultStatus({ producerPrincipalId: 'prn-a-mvp05-human-reviewer' });
    },
    async decide() {
      decisions += 1;
    },
  });
  await withServer({
    credential: credential({ expiresAt: new Date(Date.now() - 1_000).toISOString() }),
    workflow: service,
  }, async ({ server, origin }) => {
    const response = await decide(server, origin, exactViewedDecision);
    assert.equal(response.status, 401);
    assert.equal(decisions, 0);
  });

  await withServer({ credential: credential(), workflow: service }, async ({ server, origin }) => {
    const response = await decide(server, origin, exactViewedDecision);
    assert.equal(response.status, 403);
    assert.equal(decisions, 0);
  });
});

test('a review decision is refused unless the canonical task is still IN_REVIEW', async () => {
  let decisions = 0;
  const service = workflow({
    async status() {
      return defaultStatus({ state: 'DONE' });
    },
    async decide() {
      decisions += 1;
    },
  });
  await withServer({ credential: credential(), workflow: service }, async ({ server, origin }) => {
    const response = await decide(server, origin, exactViewedDecision);
    assert.equal(response.status, 409);
    assert.equal(decisions, 0);
  });
});
