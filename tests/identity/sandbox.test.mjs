// S2-002 phase 3 — sandbox boundary adapters.
// RED-first suite for the three sandbox tiers. Filesystem canonicalization,
// junction/symlink escape detection, network policy, environment allowlist,
// secret redaction, process-tree cancellation and artifact outputs are all
// observed directly; a tier without proven kernel-level controls stays
// blocked instead of pretending to be a full sandbox.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createSandbox } from '../../src/lib/identity/sandbox.mjs';
import { SANDBOX_NO_EXEC, SANDBOX_LOCAL_RESTRICTED_BLOCKED } from '../../src/lib/identity/sandbox-profiles.mjs';

const NOW = '2026-09-12T12:00:00.000Z';
const IS_WINDOWS = process.platform === 'win32';

const SECRETS = {
  'sec-postgres-url': 'synthetic-db-secret-0123456789',
  'sec-token-a': 'tok_super_secret_value_0123456789',
};

function makeWorkspace() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-ws-'));
  fs.mkdirSync(path.join(root, 'data'), { recursive: true });
  fs.writeFileSync(path.join(root, 'data', 'file.txt'), 'inside');
  return root;
}

function makeSandbox(profile, roots, extra = {}) {
  return createSandbox({
    profile,
    workspaceRoots: roots,
    artifactRoot: path.join(roots[0], 'artifacts'),
    secrets: SECRETS,
    now: NOW,
    ...extra,
  });
}

describe('S2-002 sandbox: tier discipline', () => {
  test('NO_EXEC refuses execution before any process is spawned', async () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    assert.equal(sandbox.tier, 'NO_EXEC');
    assert.equal(sandbox.executionAllowed, false);
    const outcome = await sandbox.spawnProcess({ command: 'cmd.exe', args: ['/c', 'echo hi'], timeoutMs: 1000 });
    assert.equal(outcome.status, 'BLOCKED_SANDBOX');
    assert.ok(outcome.reasonCodes.includes('SBX_EXEC_FORBIDDEN'));
    assert.equal(outcome.pid, undefined, 'no process may be created');
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('LOCAL_RESTRICTED without kernel-level network evidence stays blocked', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_LOCAL_RESTRICTED_BLOCKED, [root]);
    assert.equal(sandbox.executionAllowed, false, 'no AppContainer/firewall boundary = no execution');
    assert.equal(sandbox.blockedReason, 'SBX_NO_KERNEL_NETWORK_BOUNDARY');
    fs.rmSync(root, { recursive: true, force: true });
  });
});

describe('S2-002 sandbox: filesystem boundary', () => {
  test('paths inside the workspace canonicalize', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    const resolved = sandbox.resolvePath('data/file.txt');
    assert.equal(fs.realpathSync(resolved), fs.realpathSync(path.join(root, 'data', 'file.txt')));
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('traversal outside the workspace is rejected', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    for (const attempt of [
      '../outside.txt',
      'data/../../outside.txt',
      'data\\..\\..\\outside.txt',
      'data/../../../../../../Windows/win.ini',
    ]) {
      assert.throws(() => sandbox.resolvePath(attempt), (error) => error.code === 'PATH_ESCAPE', attempt);
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('absolute paths outside allowed roots are rejected', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    for (const attempt of [
      'C:/Windows/System32/config.sys',
      path.join(os.tmpdir(), 'elsewhere.txt'),
    ]) {
      assert.throws(() => sandbox.resolvePath(attempt), (error) => error.code === 'ROOT_VIOLATION', attempt);
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('UNC and device paths are rejected', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    for (const attempt of [
      '//server/share/file.txt',
      '\\\\server\\share\\file.txt',
      '\\\\.\\C:\\evil',
      '\\\\?\\C:\\evil',
      'CON',
      'NUL',
      'COM1',
      'data/CON',
    ]) {
      assert.throws(() => sandbox.resolvePath(attempt), (error) => ['UNC_PATH', 'DEVICE_PATH'].includes(error.code), attempt);
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('junction escape out of the workspace is rejected', { skip: !IS_WINDOWS }, () => {
    const root = makeWorkspace();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-out-'));
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside content');
    const link = path.join(root, 'data', 'escape-junction');
    fs.symlinkSync(outside, link, 'junction');
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    assert.throws(() => sandbox.resolvePath('data/escape-junction/secret.txt'), (error) => error.code === 'LINK_ESCAPE');
    assert.throws(() => sandbox.resolvePath('data/escape-junction'), (error) => error.code === 'LINK_ESCAPE');
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  });

  test('symlink escape out of the workspace is rejected', () => {
    const root = makeWorkspace();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-out2-'));
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside content');
    const link = path.join(root, 'data', 'escape-link');
    try {
      fs.symlinkSync(path.join(outside, 'secret.txt'), link, 'file');
    } catch (error) {
      if (error.code === 'EPERM') {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(outside, { recursive: true, force: true });
        return; // privileged symlink; junction case above covers the class
      }
      throw error;
    }
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    assert.throws(() => sandbox.resolvePath('data/escape-link'), (error) => error.code === 'LINK_ESCAPE');
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  });
});

describe('S2-002 sandbox: network policy', () => {
  test('deny_all forbids every destination', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    assert.equal(sandbox.checkNetwork('registry.npmjs.org', 443).allowed, false);
    assert.equal(sandbox.checkNetwork('localhost', 5432).allowed, false);
    assert.equal(sandbox.checkNetwork('127.0.0.1', 8080).allowed, false);
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('allowlist profiles permit only exact host and port pairs', () => {
    const root = makeWorkspace();
    const profile = {
      ...SANDBOX_LOCAL_RESTRICTED_BLOCKED,
      network: { policy: 'allowlist', allowlist: [{ host: 'registry.npmjs.org', ports: [443] }] },
    };
    const sandbox = makeSandbox(profile, [root]);
    assert.equal(sandbox.checkNetwork('registry.npmjs.org', 443).allowed, true);
    assert.equal(sandbox.checkNetwork('registry.npmjs.org', 80).allowed, false);
    assert.equal(sandbox.checkNetwork('evil.example', 443).allowed, false);
    fs.rmSync(root, { recursive: true, force: true });
  });
});

describe('S2-002 sandbox: environment and secrets', () => {
  test('environment contains only allowlisted variables', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    const env = sandbox.buildEnvironment({ NODE_ENV: 'test', AWS_ACCESS_KEY_ID: 'leak' });
    assert.equal(env.NODE_ENV, 'test');
    assert.equal(env.AWS_ACCESS_KEY_ID, undefined);
    assert.equal(Object.keys(env).some((key) => !['NODE_ENV', 'VERITAS_SANDBOX_TIER', 'VERITAS_SANDBOX_PROFILE'].includes(key)), false,
      'environment must not leak unlisted variables');
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('secrets stay behind opaque handles and never appear in environment', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    const env = sandbox.buildEnvironment({});
    assert.equal(env.SEC_POSTGRES_URL, undefined);
    const serialized = JSON.stringify(env);
    for (const value of Object.values(SECRETS)) {
      assert.ok(!serialized.includes(value), 'secret value must not leak into environment');
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('redaction removes secret values from any log text', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    const line = `connecting with ${SECRETS['sec-postgres-url']} and ${SECRETS['sec-token-a']}`;
    const redacted = sandbox.redact(line);
    assert.ok(!redacted.includes('synthetic-db-secret-0123456789'));
    assert.ok(!redacted.includes('tok_super_secret_value'));
    assert.ok(redacted.includes('[REDACTED:sec-postgres-url]'));
    assert.ok(redacted.includes('[REDACTED:sec-token-a]'));
    fs.rmSync(root, { recursive: true, force: true });
  });
});

describe('S2-002 sandbox: process tree and cancellation', { skip: !IS_WINDOWS }, () => {
  test('cancellation kills the whole tree: no survivors', { timeout: 60000 }, async () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_LOCAL_RESTRICTED_BLOCKED, [root]);
    const { pid, done } = sandbox.startForControlProbe({
      command: 'cmd.exe',
      args: ['/d', '/s', '/c', 'ping -n 60 127.0.0.1 >nul'],
      timeoutMs: 60000,
    });
    assert.ok(pid > 0);
    assert.equal(sandbox.isAlive(pid), true);
    const cancel = await sandbox.cancel(pid);
    assert.equal(cancel.terminated, true);
    assert.equal(cancel.survivors, 0, `no process may survive cancellation: ${JSON.stringify(cancel)}`);
    assert.equal(sandbox.isAlive(pid), false);
    const outcome = await done;
    assert.equal(outcome.status, 'cancelled', 'cancel must yield a terminal cancelled outcome');
    assert.equal(outcome.terminated, true);
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('timeout produces a terminal outcome, never success', { timeout: 60000 }, async () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_LOCAL_RESTRICTED_BLOCKED, [root]);
    const outcome = await sandbox.spawnForControlProbe({
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 60000)'],
      timeoutMs: 700,
    });
    assert.equal(outcome.status, 'timeout');
    assert.equal(outcome.terminated, true);
    assert.equal(outcome.survivors, 0);
    assert.notEqual(outcome.status, 'success');
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('process count limits are enforced', { timeout: 60000 }, async () => {
    const root = makeWorkspace();
    const profile = { ...SANDBOX_LOCAL_RESTRICTED_BLOCKED, process: { ...SANDBOX_LOCAL_RESTRICTED_BLOCKED.process, max_processes: 1 } };
    const sandbox = makeSandbox(profile, [root]);
    const first = sandbox.startForControlProbe({
      command: 'cmd.exe',
      args: ['/d', '/s', '/c', 'ping -n 60 127.0.0.1 >nul'],
      timeoutMs: 20000,
    });
    assert.ok(first.pid > 0);
    await assert.rejects(
      () => sandbox.spawnForControlProbe({ command: 'cmd.exe', args: ['/d', '/s', '/c', 'echo second'], timeoutMs: 5000 }),
      (error) => error.code === 'LIMIT_PROCESSES',
    );
    await sandbox.cancel(first.pid);
    await first.done;
    fs.rmSync(root, { recursive: true, force: true });
  });
});

describe('S2-002 sandbox: artifact outputs', () => {
  test('outputs land in the artifact root with digest and provenance', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    const bytes = Buffer.from('deterministic output', 'utf8');
    const record = sandbox.writeOutput('result-1.txt', bytes);
    assert.equal(record.sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.equal(record.bytes, bytes.length);
    assert.ok(fs.realpathSync(record.path).startsWith(fs.realpathSync(path.join(root, 'artifacts'))));
    assert.equal(record.provenance.profileId, SANDBOX_NO_EXEC.profile_id);
    assert.equal(record.provenance.tier, 'NO_EXEC');
    assert.equal(record.provenance.createdAt, NOW);
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('output names cannot escape the artifact root', () => {
    const root = makeWorkspace();
    const sandbox = makeSandbox(SANDBOX_NO_EXEC, [root]);
    for (const bad of ['../escape.txt', 'a/b/../../../escape.txt', 'data\\evil.txt', 'CON']) {
      assert.throws(() => sandbox.writeOutput(bad, Buffer.from('x')), (error) => ['PATH_ESCAPE', 'ROOT_VIOLATION', 'DEVICE_PATH'].includes(error.code), bad);
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
});
