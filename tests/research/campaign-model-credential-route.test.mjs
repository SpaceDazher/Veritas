import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { existsSync, readFileSync, statSync } from 'node:fs';

import {
  executeModelWithCredential,
  startCampaignForwarder,
  modelCredentialValue,
} from '../../scripts/s2-008-campaign-adapter.mjs';

const HANDLE = 'sec-veritas-executor-credential';
const KEY = 'canary-model-credential-value';

test('paid launch waits for a listening forwarder, passes a 0600 env-file path and cleans it', async () => {
  let stopped = false;
  let forwarded = false;
  let envFilePath = null;
  const result = await executeModelWithCredential({
    image: 'sha256:' + 'a'.repeat(64),
    argv: ['/usr/local/bin/node', '/opt/veritas/scripts/s2-008-campaign-arm-model.mjs', '/input', '/out', 'arm-model-zai-glm53flash', '/prereg', '1'],
    timeoutMs: 1000,
    credentialValue: KEY,
    credentialPresent: () => true,
    startForwarder: async (socketPath) => {
      assert.equal(existsSync(socketPath), false);
      forwarded = true;
      return { socketPath, stop: async () => { stopped = true; } };
    },
    execute: (invocation) => {
      assert.equal(forwarded, true);
      assert.equal(stopped, false);
      const argv = invocation.podmanArgv;
      assert.ok(argv.includes('--network=none'));
      assert.ok(argv.includes('--secret'));
      assert.ok(argv.includes(HANDLE));
      const envIndex = argv.indexOf('--env-file');
      assert.ok(envIndex > 0);
      envFilePath = argv[envIndex + 1];
      assert.equal(statSync(envFilePath).mode & 0o777, 0o600);
      assert.equal(readFileSync(envFilePath, 'utf8'), 'ZAI_API_KEY=' + KEY + '\n');
      assert.equal(argv.some((arg) => arg.includes(KEY)), false);
      assert.ok(argv.some((arg) => arg.includes('dst=/run/egress.sock')));
      assert.equal(argv.includes('--api-key'), false);
      return { exitCode: 0, signal: null, timedOut: false, stdout: 'ADAPTER_OK', stderr: '', image: invocation.image, axes: invocation.axes };
    },
  });
  assert.equal(result.observation.exitCode, 0);
  assert.equal(result.leakScan.ok, true);
  assert.equal(result.detectorSelfCheckPassed, true);
  assert.deepEqual(result.leakScan.expectedToCarry, ['env']);
  assert.equal(stopped, true);
  assert.equal(existsSync(envFilePath), false);
  assert.equal(JSON.stringify(result).includes(KEY), false);
});

test('absent credential refuses before a model process and before the forwarder', async () => {
  let launched = false;
  await assert.rejects(() => executeModelWithCredential({
    image: 'sha256:' + 'a'.repeat(64),
    argv: ['/usr/local/bin/node'],
    credentialValue: '',
    credentialPresent: () => false,
    startForwarder: async () => { launched = true; throw new Error('unexpected'); },
    execute: () => { launched = true; throw new Error('unexpected'); },
  }), /EXECUTOR_CREDENTIAL_ABSENT/);
  assert.equal(launched, false);
});

test('a leaked value on stdout is detected and fails the launch', async () => {
  await assert.rejects(() => executeModelWithCredential({
    image: 'sha256:' + 'a'.repeat(64),
    argv: ['/usr/local/bin/node'],
    credentialValue: KEY,
    credentialPresent: () => true,
    startForwarder: async (socketPath) => ({ socketPath, stop: async () => {} }),
    execute: (invocation) => ({ exitCode: 0, stdout: KEY, stderr: '', image: invocation.image, axes: invocation.axes }),
  }), /SECRET_VALUE_DETECTED_IN_SURFACE/);
});

test('credential resolver reads configured JSON without exposing the value in a report', () => {
  const value = modelCredentialValue({
    env: {},
    readAuth: () => JSON.stringify({ 'zai-coding-cn': { key: KEY } }),
  });
  assert.equal(value, KEY);
  assert.equal(modelCredentialValue({ env: { ZAI_API_KEY: KEY }, readAuth: () => '' }), KEY);
  assert.throws(() => modelCredentialValue({ env: {}, readAuth: () => '{}' }), /EXECUTOR_CREDENTIAL_ABSENT/);
});

test('forwarder process confirms listening, refuses off-allowlist destination, then stops', async () => {
  const f = await startCampaignForwarder();
  try {
    assert.equal(existsSync(f.socketPath), true);
    const answer = await new Promise((resolve, reject) => {
      const socket = connect(f.socketPath);
      let head = '';
      const timer = setTimeout(() => reject(new Error('forwarder did not answer')), 3000);
      socket.on('connect', () => socket.write('CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n'));
      socket.on('data', (chunk) => { head += String(chunk); clearTimeout(timer); socket.destroy(); resolve(head); });
      socket.on('error', reject);
    });
    assert.match(answer, /EGRESS_NOT_ALLOWLISTED/);
  } finally {
    await f.stop();
  }
  assert.equal(existsSync(f.socketPath), false);
});


test('a launcher failure is sanitized so an exception cannot print the credential', async () => {
  await assert.rejects(() => executeModelWithCredential({
    image: 'sha256:' + 'a'.repeat(64),
    argv: ['/usr/local/bin/node'],
    credentialValue: KEY,
    credentialPresent: () => true,
    startForwarder: async (socketPath) => ({ socketPath, stop: async () => {} }),
    execute: () => { throw new Error('child failed with ' + KEY); },
  }), (error) => {
    assert.equal(String(error.message).includes(KEY), false);
    assert.match(String(error.message), /MODEL_EXECUTION_FAILED/);
    return true;
  });
});
