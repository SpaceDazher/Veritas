import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';

const MAX_BODY_BYTES = 4096;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{24,256}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const PRINCIPAL_PATTERN = /^prn-[a-z0-9][a-z0-9-]{0,62}$/;
const TASK_PATTERN = /^abt-[a-z0-9][a-z0-9-]{0,62}$/;
const ACTIONS = new Set(['start', 'approve', 'request_changes']);

const PAGE = [
  '<!doctype html>',
  '<html lang="ru">',
  '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
  '<title>A-MVP-05 · локальная проверка</title></head>',
  '<body>',
  '<main>',
  '<h1>A-MVP-05 · локальная проверка</h1>',
  '<p>Фиксированное задание: добавить строку в README изолированного репозитория и запустить его тест.</p>',
  '<p>Исполнитель — детерминированный локальный Node wrapper в Podman; вызовов модели и API нет.</p>',
  '<label for="token">Одноразовый ключ рецензента</label>',
  '<input id="token" type="password" autocomplete="off" spellcheck="false">',
  '<button id="open">Открыть задание</button>',
  '<pre id="status" aria-live="polite">Вставьте ключ, чтобы загрузить состояние.</pre>',
  '<button id="start" disabled>Создать задачу и выполнить</button>',
  '<label for="reason">Причина решения</label>',
  '<textarea id="reason" maxlength="500"></textarea>',
  '<button id="approve" disabled>Принять</button>',
  '<button id="changes" disabled>Запросить изменения</button>',
  '</main>',
  '<script src="/app.js" defer></script>',
  '</body>',
  '</html>',
].join('\n');

const APP = [
  "'use strict';",
  "const tokenInput = document.getElementById('token');",
  "const statusBox = document.getElementById('status');",
  "const startButton = document.getElementById('start');",
  "const approveButton = document.getElementById('approve');",
  "const changesButton = document.getElementById('changes');",
  "const reasonInput = document.getElementById('reason');",
  'let bearer = "";',
  'let currentState = null;',
  'let viewed = null;',
  'async function call(path, method, body) {',
  '  const headers = { authorization: "Bearer " + bearer };',
  '  if (body !== undefined) headers["content-type"] = "application/json";',
  '  const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store" });',
  '  const value = await response.json();',
  '  if (!response.ok) throw new Error(value.message || value.code || "request failed");',
  '  return value;',
  '}',
  'function show(value) { statusBox.textContent = JSON.stringify(value, null, 2); currentState = value.state || null; viewed = value;',
  '  startButton.disabled = currentState !== "PENDING";',
  '  approveButton.disabled = currentState !== "IN_REVIEW";',
  '  changesButton.disabled = currentState !== "IN_REVIEW";',
  '}',
  'document.getElementById("open").addEventListener("click", async () => {',
  '  bearer = tokenInput.value.trim(); tokenInput.value = "";',
  '  try { show(await call("/api/state", "GET")); } catch (error) { bearer = ""; statusBox.textContent = String(error.message); }',
  '});',
  'startButton.addEventListener("click", async () => {',
  '  startButton.disabled = true;',
  '  try { show(await call("/api/start", "POST", {})); } catch (error) { statusBox.textContent = String(error.message); }',
  '});',
  'async function decide(decision) {',
  '  approveButton.disabled = true; changesButton.disabled = true;',
  '  try { show(await call("/api/decision", "POST", { decision, reason: reasonInput.value.trim(), observed_manifest_digest: viewed.artifactManifestDigest, expected_revision: viewed.revision })); }',
  '  catch (error) { statusBox.textContent = String(error.message); }',
  '}',
  'approveButton.addEventListener("click", () => decide("approve"));',
  'changesButton.addEventListener("click", () => decide("request_changes"));',
].join('\n');

function credentialAction(credential, action) {
  return Array.isArray(credential.actions) && credential.actions.includes(action);
}

function jsonResponse(response, status, body) {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  });
  response.end(JSON.stringify(body));
}

function isLoopbackAddress(address) {
  return address === '127.0.0.1'
    || address === '::1'
    || address === '::ffff:127.0.0.1';
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function readJsonBody(request) {
  if (!String(request.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
    const error = new Error('JSON_REQUIRED');
    error.status = 415;
    throw error;
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      const error = new Error('BODY_TOO_LARGE');
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  let body;
  try {
    body = JSON.parse(text || '{}');
  } catch {
    const error = new Error('JSON_INVALID');
    error.status = 400;
    throw error;
  }
  if (!isPlainObject(body)) {
    const error = new Error('OBJECT_REQUIRED');
    error.status = 400;
    throw error;
  }
  return body;
}

function exactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === [...expected].sort()[index]);
}

function genericFailure(error) {
  const known = new Set(['JSON_REQUIRED', 'BODY_TOO_LARGE', 'JSON_INVALID', 'OBJECT_REQUIRED']);
  return {
    status: Number.isInteger(error?.status) ? error.status : 503,
    code: known.has(error?.message) ? error.message : 'A05_WORKFLOW_UNAVAILABLE',
  };
}

export function hashA05ReviewToken(token) {
  if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
    throw new TypeError('REVIEW_TOKEN_INVALID');
  }
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function createA05ReviewServer({ credential, workflow, now = () => new Date() } = {}) {
  if (!isPlainObject(credential)
      || !DIGEST_PATTERN.test(String(credential.tokenHash ?? ''))
      || !PRINCIPAL_PATTERN.test(String(credential.principalId ?? ''))
      || !TASK_PATTERN.test(String(credential.taskId ?? ''))
      || !Number.isFinite(Date.parse(credential.expiresAt))
      || !Array.isArray(credential.actions)
      || credential.actions.some((action) => !ACTIONS.has(action))) {
    throw new TypeError('REVIEW_CREDENTIAL_INVALID');
  }
  if (!isPlainObject(workflow)
      || typeof workflow.status !== 'function'
      || typeof workflow.start !== 'function'
      || typeof workflow.decide !== 'function') {
    throw new TypeError('REVIEW_WORKFLOW_INVALID');
  }
  if (typeof now !== 'function') throw new TypeError('REVIEW_CLOCK_INVALID');

  let server;
  server = createServer(async (request, response) => {
    const address = server.address();
    const expectedHost = '127.0.0.1:' + address.port;
    const expectedOrigin = 'http://' + expectedHost;

    const baseHeaders = {
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      'cross-origin-resource-policy': 'same-origin',
    };
    const respondText = (status, type, body) => {
      response.writeHead(status, { ...baseHeaders, 'content-type': type });
      response.end(body);
    };

    try {
      const target = request.url ?? '/';
      let path;
      try {
        if (!target.startsWith('/') || target.startsWith('//')) throw new Error('target');
        path = new URL(target, expectedOrigin);
      } catch {
        jsonResponse(response, 400, { code: 'REQUEST_TARGET_INVALID' });
        return;
      }
      if (request.socket.remoteAddress && !isLoopbackAddress(request.socket.remoteAddress)) {
        jsonResponse(response, 403, { code: 'LOOPBACK_ONLY' });
        return;
      }
      if (request.headers.host !== expectedHost) {
        jsonResponse(response, 403, { code: 'HOST_INVALID' });
        return;
      }
      if (path.search !== '') {
        jsonResponse(response, 400, { code: 'QUERY_NOT_ALLOWED' });
        return;
      }
      if (request.method === 'GET' && path.pathname === '/') {
        respondText(200, 'text/html; charset=utf-8', PAGE);
        return;
      }
      if (request.method === 'GET' && path.pathname === '/app.js') {
        respondText(200, 'text/javascript; charset=utf-8', APP);
        return;
      }

      const routes = new Set(['/api/state', '/api/start', '/api/decision']);
      if (!routes.has(path.pathname)) {
        jsonResponse(response, 404, { code: 'NOT_FOUND' });
        return;
      }
      if ((request.method !== 'GET' && request.headers.origin !== expectedOrigin)
          || (request.headers.origin !== undefined && request.headers.origin !== expectedOrigin)
          || (request.headers['sec-fetch-site'] !== undefined
              && !['same-origin', 'none'].includes(request.headers['sec-fetch-site']))) {
        jsonResponse(response, 403, { code: 'ORIGIN_INVALID' });
        return;
      }

      const auth = String(request.headers.authorization ?? '').match(/^Bearer ([A-Za-z0-9_-]{24,256})$/);
      if (!auth) {
        jsonResponse(response, 401, { code: 'AUTH_REQUIRED' });
        return;
      }
      let suppliedHash;
      try {
        suppliedHash = Buffer.from(hashA05ReviewToken(auth[1]), 'hex');
      } catch {
        jsonResponse(response, 401, { code: 'AUTH_REQUIRED' });
        return;
      }
      const expectedHash = Buffer.from(credential.tokenHash, 'hex');
      if (!timingSafeEqual(suppliedHash, expectedHash)) {
        jsonResponse(response, 401, { code: 'AUTH_REQUIRED' });
        return;
      }
      const instant = now();
      const instantMs = instant instanceof Date ? instant.getTime() : Date.parse(instant);
      if (!Number.isFinite(instantMs) || Date.parse(credential.expiresAt) <= instantMs) {
        jsonResponse(response, 401, { code: 'AUTH_EXPIRED' });
        return;
      }

      if (request.method === 'GET' && path.pathname === '/api/state') {
        if (!credentialAction(credential, 'start') && !credentialAction(credential, 'approve')) {
          jsonResponse(response, 403, { code: 'ACTION_FORBIDDEN' });
          return;
        }
        const status = await workflow.status({
          principalId: credential.principalId,
          taskId: credential.taskId,
        });
        jsonResponse(response, 200, status);
        return;
      }

      if (request.method !== 'POST') {
        jsonResponse(response, 405, { code: 'METHOD_NOT_ALLOWED' });
        return;
      }
      const body = await readJsonBody(request);
      if (path.pathname === '/api/start') {
        if (!credentialAction(credential, 'start')) {
          jsonResponse(response, 403, { code: 'ACTION_FORBIDDEN' });
          return;
        }
        if (!exactKeys(body, [])) {
          jsonResponse(response, 400, { code: 'START_ARGUMENTS_NOT_ALLOWED' });
          return;
        }
        const result = await workflow.start({
          principalId: credential.principalId,
          taskId: credential.taskId,
        });
        jsonResponse(response, 200, result);
        return;
      }

      if (!exactKeys(body, ['decision', 'reason', 'observed_manifest_digest', 'expected_revision'])
          || typeof body.observed_manifest_digest !== 'string'
          || !DIGEST_PATTERN.test(body.observed_manifest_digest)
          || !Number.isSafeInteger(body.expected_revision) || body.expected_revision < 1
          || !['approve', 'request_changes'].includes(body.decision)
          || typeof body.reason !== 'string'
          || body.reason.trim().length < 3
          || body.reason.trim().length > 500) {
        jsonResponse(response, 400, { code: 'DECISION_ARGUMENTS_INVALID' });
        return;
      }
      const action = body.decision === 'approve' ? 'approve' : 'request_changes';
      if (!credentialAction(credential, action)) {
        jsonResponse(response, 403, { code: 'ACTION_FORBIDDEN' });
        return;
      }
      const status = await workflow.status({
        principalId: credential.principalId,
        taskId: credential.taskId,
      });
      if (status?.state !== 'IN_REVIEW') {
        jsonResponse(response, 409, { code: 'TASK_NOT_IN_REVIEW' });
        return;
      }
      const producerPrincipalId = status.producerPrincipalId ?? status.producer_principal_id;
      if (typeof producerPrincipalId !== 'string' || producerPrincipalId === credential.principalId) {
        jsonResponse(response, 403, { code: 'PRODUCER_SELF_REVIEW_FORBIDDEN' });
        return;
      }
      if (typeof status.artifactManifestDigest !== 'string' || !DIGEST_PATTERN.test(status.artifactManifestDigest)) {
        jsonResponse(response, 409, { code: 'ARTIFACT_MANIFEST_UNAVAILABLE' });
        return;
      }
      if (body.observed_manifest_digest !== status.artifactManifestDigest
          || body.expected_revision !== status.revision) {
        jsonResponse(response, 409, { code: 'REVIEW_VERSION_CHANGED' });
        return;
      }
      if (status.expectedArtifactManifestDigest !== status.artifactManifestDigest
          || status.currentArtifactManifestDigest !== status.artifactManifestDigest) {
        jsonResponse(response, 409, { code: 'ARTIFACT_CHANGED' });
        return;
      }
      const result = await workflow.decide({
        principalId: credential.principalId,
        taskId: credential.taskId,
        decision: body.decision,
        reason: body.reason.trim(),
        observed: { artifactManifestDigest: body.observed_manifest_digest, taskRevision: body.expected_revision },
      });
      jsonResponse(response, 200, result);
    } catch (error) {
      const failure = genericFailure(error);
      jsonResponse(response, failure.status, { code: failure.code });
    }
  });
  return server;
}
