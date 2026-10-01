import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { callModel } from '../../scripts/s2-008-campaign-arm-model.mjs';
import { V7_PI_SETTINGS, assertV7ExecutorPolicy } from '../../scripts/s2-008-campaign-credential-env.mjs';
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

test('signed v7 runtime key name is the sole 0600 env-file binding', async () => {
  let envFilePath = null;
  const result = await executeModelWithCredential({
    image: 'sha256:' + 'a'.repeat(64),
    argv: ['/usr/local/bin/node', '/opt/veritas/scripts/s2-008-campaign-arm-model.mjs'],
    timeoutMs: 1000,
    envName: 'ZAI_CODING_CN_API_KEY',
    credentialValue: KEY,
    credentialPresent: () => true,
    startForwarder: async (socketPath) => ({ socketPath, stop: async () => {} }),
    execute: (invocation) => {
      const argv = invocation.podmanArgv;
      const envIndex = argv.indexOf('--env-file');
      envFilePath = argv[envIndex + 1];
      assert.equal(statSync(envFilePath).mode & 0o777, 0o600);
      assert.equal(readFileSync(envFilePath, 'utf8'), 'ZAI_CODING_CN_API_KEY=' + KEY + '\n');
      assert.equal(readFileSync(envFilePath, 'utf8').split('\n').filter(Boolean).length, 1);
      assert.equal(argv.some((arg) => arg.includes(KEY)), false);
      assert.equal(argv.includes('--api-key'), false);
      return { exitCode: 0, signal: null, timedOut: false, stdout: 'ADAPTER_OK', stderr: '', image: invocation.image, axes: invocation.axes };
    },
  });
  assert.equal(result.record.credential.env_name, 'ZAI_CODING_CN_API_KEY');
  assert.equal(JSON.stringify(result).includes(KEY), false);
  assert.equal(existsSync(envFilePath), false);
});

test('installed pi 0.99.1 resolves zai-coding-cn from the signed v7 key name offline', async (t) => {
  const modulePath = '/home/daniil/.local/lib/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/env-api-keys.js';
  if (!existsSync(modulePath)) {
    t.skip('the configured pi runtime is not installed on this host');
    return;
  }
  const { getEnvApiKey } = await import(pathToFileURL(modulePath).href);
  const sentinel = 'offline-contract-sentinel-key';
  assert.equal(getEnvApiKey('zai-coding-cn', { ZAI_CODING_CN_API_KEY: sentinel }), sentinel);
  assert.equal(getEnvApiKey('zai-coding-cn', { ZAI_API_KEY: sentinel }), undefined);
});

test('unknown signed credential env names refuse before secret lookup or process launch', async () => {
  let touched = false;
  await assert.rejects(() => executeModelWithCredential({
    image: 'sha256:' + 'a'.repeat(64), argv: ['/usr/local/bin/node'], timeoutMs: 1000,
    envName: 'PATH', credentialValue: KEY,
    credentialPresent: () => { touched = true; return true; },
    startForwarder: async () => { touched = true; throw new Error('unexpected'); },
    execute: () => { touched = true; throw new Error('unexpected'); },
  }), /MODEL_CREDENTIAL_ENV_NAME_INVALID/);
  assert.equal(touched, false);
});

test('signed v7 pi settings disable request retries/cache warming/compaction in a private config directory', () => {
  const settings = { ...V7_PI_SETTINGS };
  const envName = 'ZAI_CODING_CN_API_KEY';
  let configDir = null;
  let calls = 0;
  const result = callModel('subject', {
    provider: 'zai-coding-cn', model: 'glm-5.3-flash', envName,
    env: { [envName]: KEY, HTTPS_PROXY: 'http://127.0.0.1:43123' },
    dryRun: false, timeoutMs: 180000, piSettings: settings,
    execFile: (command, argv, options) => {
      calls += 1;
      assert.equal(command, 'pi');
      assert.ok(argv.includes('--no-tools'));
      assert.ok(argv.includes('--no-extensions'));
      assert.ok(argv.includes('--no-skills'));
      configDir = options.env.PI_CODING_AGENT_DIR;
      const settingsPath = path.join(configDir, 'settings.json');
      assert.equal(statSync(settingsPath).mode & 0o777, 0o600);
      assert.deepEqual(JSON.parse(readFileSync(settingsPath, 'utf8')), {
        retry: { enabled: false, maxRetries: 0, provider: { maxRetries: 0 } },
        cacheWarming: 'off', compaction: { enabled: false },
      });
      return JSON.stringify({ type: 'agent_end', messages: [{ role: 'assistant', id: 'billed-1',
        usage: { input: 3, output: 1, totalTokens: 4, cost: { total: 0.0001 } },
        content: [{ type: 'text', text: 'MINOR' }] }] });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.text, 'MINOR');
  assert.equal(result.usage.totalTokens, 4);
  assert.equal(existsSync(configDir), false);

  const invalid = structuredClone(settings);
  invalid.retry.enabled = true;
  assert.throws(() => assertV7ExecutorPolicy({
    provider: 'zai-coding-cn', credential_env_name: envName, pi_settings: invalid,
  }), /V7_CREDENTIAL_ENV_OR_RETRY_POLICY_INVALID/);
});

test('OpenRouter launch binds its signed provider to the forwarder and private env-file', async () => {
 let envFile;
 await executeModelWithCredential({
  image:'sha256:'+'a'.repeat(64),argv:['/usr/local/bin/node'],timeoutMs:1000,
  provider:'openrouter',envName:'OPENROUTER_API_KEY',credentialValue:KEY,credentialPresent:()=>true,
  startForwarder:async(socketPath,options)=>{
   assert.equal(options.provider,'openrouter');
   return {socketPath,stop:async()=>{}};
  },
  execute:invocation=>{
   envFile=invocation.podmanArgv[invocation.podmanArgv.indexOf('--env-file')+1];
   assert.equal(statSync(envFile).mode&0o777,0o600);
   assert.equal(readFileSync(envFile,'utf8'),'OPENROUTER_API_KEY='+KEY+'\n');
   assert.equal(invocation.podmanArgv.some(x=>x.includes(KEY)),false);
   return {exitCode:0,stdout:'OK',stderr:'',image:invocation.image,axes:invocation.axes};
  }
 });
 assert.equal(existsSync(envFile),false);
});
test('real OpenRouter forwarder refuses the former provider without contacting it', async () => {
 const f=await startCampaignForwarder({provider:'openrouter'});
 try {
  const answer=await new Promise((resolve,reject)=>{
   const socket=connect(f.socketPath);
   const timer=setTimeout(()=>{socket.destroy();reject(new Error('forwarder timeout'));},3000);
   socket.on('connect',()=>socket.write('CONNECT open.bigmodel.cn:443 HTTP/1.1\r\nHost: open.bigmodel.cn:443\r\n\r\n'));
   socket.on('data',chunk=>{clearTimeout(timer);socket.destroy();resolve(String(chunk));});
   socket.on('error',error=>{clearTimeout(timer);reject(error);});
  });
  assert.match(answer,/EGRESS_NOT_ALLOWLISTED/);
  assert.deepEqual(f.allowlist,[{host:'openrouter.ai',ports:[443]}]);
 } finally {await f.stop();}
});
