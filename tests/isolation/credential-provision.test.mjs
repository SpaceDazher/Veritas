// S2-002 #12 — the credential provisioning path, proved to leak nothing.
//
// The claim under test is the one A-MVP-04 was built on, carried forward to the
// point where a value must actually move: after `provision` runs, the value is
// in podman's secret store and nowhere else. The canary is planted by the test
// itself, and the detector has to still fire, because a detector that has never
// fired proves nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  PROVISION_ERRORS,
  parseArgs,
  provision,
  readCredential,
} from '../../scripts/veritas-credential-provision.mjs';
import { assertNoSecretLeak, fingerprint } from '../../src/lib/isolation/secrets.mjs';

const VALUE = 'zai-provision-canary-8b3d1f6a90c47e2d-not-a-real-key';
const HANDLE = 'sec-veritas-executor-credential';
const ENV_NAME = 'ZAI_API_KEY';

function withDir(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-prov-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A podman double that records every argv it was handed. */
function fakePodman(seen) {
  const calls = [];
  const impl = (args) => {
    calls.push([...args]);
    seen.push(...args);
    return { status: 0, stdout: `${args[0]}${args[1] ?? ''}\n`, stderr: '' };
  };
  impl.calls = calls;
  return impl;
}

test('the value never enters an argv: a value-shaped argument is refused outright', () => {
  // A script that merely declined to READ `--api-key x` would still have put the
  // value in the process list. Refusing the argument is the only safe behaviour.
  for (const argv of [
    ['--api-key', VALUE],
    [`--api-key=${VALUE}`],
    ['--token', VALUE],
    ['--password', VALUE],
    ['--bearer', VALUE],
    [VALUE],
  ]) {
    assert.throws(
      () => parseArgs(argv),
      (error) => String(error.message).startsWith(PROVISION_ERRORS.VALUE_IN_ARGV),
      `${JSON.stringify(argv[0])} was accepted`,
    );
  }
  // The supported invocations parse.
  const ok = parseArgs(['--handle', HANDLE, '--env-name', ENV_NAME, '--from-stdin']);
  assert.equal(ok.handle, HANDLE);
  assert.equal(ok.envName, ENV_NAME);
  assert.equal(ok.fromStdin, true);
});

test('the value is read from the source, with exactly one trailing newline removed', () => {
  withDir((dir) => {
    const file = path.join(dir, 'key.txt');
    writeFileSync(file, `${VALUE}\n`, { mode: 0o600 });
    assert.equal(readCredential({ fromFile: file }), VALUE, 'a trailing newline was not trimmed');
    assert.equal(readCredential({ fromStdin: true }, { stdin: `${VALUE}\n` }), VALUE);
    assert.equal(readCredential({}), '', 'no source produced a value instead of an empty string');
    // A value with an INTERNAL newline survives reading, and is then refused by
    // the spooler, which is the layer that knows it is about to write a line.
    writeFileSync(file, `${VALUE}\nSECOND=1\n`, { mode: 0o600 });
    assert.equal(readCredential({ fromFile: file }), `${VALUE}\nSECOND=1`);
  });
});

test('after provision the value is in the store and NOWHERE else on this host', () => {
  withDir((dir) => {
    const keyFile = path.join(dir, 'key.txt');
    writeFileSync(keyFile, `${VALUE}\n`, { mode: 0o600 });
    const seen = [];
    const podman = fakePodman(seen);
    const record = provision(
      { handle: HANDLE, envName: ENV_NAME, fromFile: keyFile, keepEnvFile: false },
      { podman, podmanArgv: ['--root', '/tmp/podman-root'], spoolDir: dir },
    );

    // 1. no podman argv carried it
    assert.equal(seen.join(' ').includes(VALUE), false, 'THE VALUE REACHED A PODMAN ARGUMENT');
    // 2. the record it prints carries no value
    const printed = JSON.stringify(record);
    assert.equal(printed.includes(VALUE), false, 'the printed record carries the value');
    // 3. the spool is gone: no env file, no spool file
    assert.deepEqual(
      readdirSync(dir).filter((n) => n.startsWith('.')),
      [],
      'a spool file survived the provisioning',
    );
    // 4. the fingerprint proves identity without being it
    assert.equal(record.fingerprint, fingerprint(VALUE), 'the fingerprint does not match the value');
    assert.equal(record.fingerprint.includes(VALUE), false);
    assert.equal(printed.includes('value_in_argv'), true, 'the record does not say the value stayed out of argv');
    // 5. and the detector, with the canary planted, agrees on every surface
    const surfaces = { argv: seen.join(' '), stdout: printed, record, env: '', stderr: '' };
    const scan = assertNoSecretLeak(surfaces, { value: VALUE });
    assert.equal(scan.ok, true, `a clean provision was reported as leaking: ${scan.leaks.join(',')}`);
    // 6. the detector still fires: plant the value and it must be found
    const planted = assertNoSecretLeak({ ...surfaces, stderr: `oops ${VALUE}` }, { value: VALUE });
    assert.equal(planted.ok, false, 'the detector did not fire on a planted value, so its silence means nothing');
    assert.ok(planted.leaks.includes('stderr'));
  });
});

test('a handle the profile does not declare is refused, and the store is never touched', () => {
  withDir((dir) => {
    const seen = [];
    const podman = fakePodman(seen);
    assert.throws(
      () => provision(
        { handle: 'sec-invented', envName: ENV_NAME, fromStdin: true },
        { podman, podmanArgv: [], spoolDir: dir, value: VALUE },
      ),
      (error) => String(error.message).startsWith(PROVISION_ERRORS.HANDLE_NOT_IN_PROFILE),
      'a credential on an undeclared handle reached the store',
    );
    assert.deepEqual(seen, [], 'the podman store was called for a refused handle');
  });
});

test('a missing source, an empty source, and a missing env name are refused', () => {
  withDir((dir) => {
    const podman = fakePodman([]);
    assert.throws(
      () => provision({ handle: HANDLE, fromFile: path.join(dir, 'absent'), envName: ENV_NAME }, { podman, spoolDir: dir }),
      (error) => String(error.message).startsWith(PROVISION_ERRORS.SOURCE_UNREADABLE),
    );
    assert.throws(
      () => provision({ handle: HANDLE, envName: ENV_NAME, fromStdin: true }, { podman, spoolDir: dir, value: 'short' }),
      (error) => String(error.message).startsWith(PROVISION_ERRORS.SOURCE_EMPTY),
    );
    assert.throws(
      () => provision({ handle: HANDLE, fromStdin: true }, { podman, spoolDir: dir, value: VALUE }),
      (error) => String(error.message).startsWith(PROVISION_ERRORS.ENV_NAME_REQUIRED),
    );
  });
});

test('the env file is kept ONLY when the run asked for it, and it is 0600', () => {
  withDir((dir) => {
    const podman = fakePodman([]);
    const record = provision(
      { handle: HANDLE, envName: ENV_NAME, fromStdin: true, keepEnvFile: true },
      { podman, podmanArgv: [], spoolDir: dir, value: VALUE },
    );
    assert.equal(record.env_file !== null, true, 'the run asked to keep the env file and did not get one');
    const body = readFileSync(record.env_file, 'utf8');
    assert.equal(body, `${ENV_NAME}=${VALUE}\n`, 'the kept env file is not one NAME=value line');
    // The caller owns the unlink, and the file is the value on disk until they do.
    rmSync(record.env_file, { force: true });
    assert.equal(existsSync(record.env_file), false);
  });
});

test('the default Podman launcher passes executable and argv in spawnSync order', () => {
  withDir((dir) => {
    const executable = path.join(dir, 'podman');
    writeFileSync(executable, '#!/bin/sh\nif [ "$1" = "secret" ]; then exit 0; fi\nexit 2\n', { mode: 0o755 });
    const previousPath = process.env.PATH;
    process.env.PATH = dir + ':' + previousPath;
    try {
      const record = provision({ handle: HANDLE, envName: ENV_NAME }, { value: VALUE, spoolDir: dir });
      assert.equal(record.store.created, true);
      assert.equal(record.value_in_argv, false);
    } finally {
      process.env.PATH = previousPath;
    }
  });
});
