// S2-002 — THE CREDENTIAL BRIDGE: an authenticated run, declared.
//
// A-MVP-04 proved that NO value reaches the executor: seven surfaces, a detector
// that plants a canary to prove it still fires, and a descriptor at
// /run/secrets/<handle>. A paid run cannot keep that property — pi reads its
// credential from the ENVIRONMENT, and a value on argv is exactly what A-MVP-04
// forbids — so this is the deliberate exception, and it is declared rather than
// the detector being switched off.
//
// Two properties carry the whole design and both are asserted here:
//
//   1. THE VALUE NEVER APPEARS IN AN ARGV. Delivery is podman's --env-file, a
//      PATH. `--env NAME=value` would put the value in the argv of podman on this
//      host, where `ps` can read it. Neither the value nor the name of the
//      variable the executor reads may appear in the argv.
//   2. THE EXECUTOR'S ENV IS THE ONE DECLARED SURFACE. Every other surface still
//      leaks if the value lands in it, and a caller that FORGETS to declare the
//      exception gets a FAIL — the safe direction, never a pass.
//
// The newline guard is not decoration: an env file is line-oriented, so a value
// containing a newline injects a second variable, and an attacker who chooses the
// value would choose the executor's environment.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  CREDENTIAL_ERRORS,
  assertCredentialEnvName,
  assertNoSecretLeak,
  credentialDeclaration,
  spoolCredentialEnvFile,
} from '../../src/lib/isolation/secrets.mjs';
import { EXECUTOR_IMAGE } from '../../src/lib/isolation/image.mjs';
import { buildInvocation, LAUNCH_ERRORS } from '../../src/lib/isolation/launch.mjs';
import { SANDBOX_ISOLATION_EXECUTOR } from '../../src/lib/isolation/profile.mjs';

const VALUE = 'zai-credential-canary-4f2b9c1d7e6a05b8-not-a-real-key';
const HANDLE = 'sec-veritas-executor-credential';
const ENV_NAME = 'ZAI_API_KEY';

function withSpool(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-cred-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The image reference the profile's pin expects: the derived content address. */
function pinnedImage() {
  return EXECUTOR_IMAGE;
}

test('the credential is delivered by a PATH: neither the value nor the variable name is in the argv', () => {
  withSpool((dir) => {
    const envFile = spoolCredentialEnvFile(HANDLE, ENV_NAME, VALUE, { spoolDir: dir });
    try {
      const invocation = buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
        image: pinnedImage(),
        argv: ['--version'],
        secretHandles: [HANDLE],
        credential: { handle: HANDLE, envFilePath: envFile.path },
      });
      const joined = invocation.argv.join(' ');
      assert.ok(joined.includes('--env-file'), 'the invocation does not pass an env file at all');
      assert.ok(!joined.includes(VALUE), 'THE VALUE IS IN THE ARGV, where ps can read it');
      assert.ok(!joined.includes(ENV_NAME), 'the variable name the executor reads is in the argv too');
      // The podman side of the argv, which is where a leak would actually land.
      const podmanArgv = invocation.argv.slice(invocation.argv.indexOf('run') + 1);
      assert.ok(!podmanArgv.includes(VALUE), 'the value reached the podman argv');
      assert.ok(!podmanArgv.some((a) => a.includes(VALUE)), 'the value reached a podman argument');
      // No --env NAME=value pair anywhere: the allowlist pairs are literals.
      for (let i = 0; i < podmanArgv.length; i += 1) {
        if (podmanArgv[i] !== '--env') continue;
        assert.ok(!String(podmanArgv[i + 1] ?? '').includes(VALUE), 'a --env pair carries the value');
      }
    } finally {
      envFile.unlink();
    }
  });
});

test('the env file is one line, 0600, and gone after unlink (twice, idempotently)', () => {
  withSpool((dir) => {
    const envFile = spoolCredentialEnvFile(HANDLE, ENV_NAME, VALUE, { spoolDir: dir });
    assert.equal(statSync(envFile.path).mode & 0o777, 0o600, 'the env file is readable by someone else');
    const body = readFileSync(envFile.path, 'utf8');
    assert.equal(body, `${ENV_NAME}=${VALUE}\n`, 'the env file is not exactly one NAME=value line');
    assert.equal(body.trim().split('\n').length, 1, 'the env file has more than one line');
    assert.equal(envFile.unlink(), true, 'the first unlink did not remove the file');
    assert.equal(existsSync(envFile.path), false, 'the value is still on disk after unlink');
    assert.equal(envFile.unlink(), true, 'the second unlink should be idempotent');
  });
});

test('a value that could inject a second variable is refused, not sanitised', () => {
  withSpool((dir) => {
    assert.throws(
      () => spoolCredentialEnvFile(HANDLE, ENV_NAME, `${VALUE}\nPI_HOME=/root`, { spoolDir: dir }),
      (error) => String(error.message).startsWith(CREDENTIAL_ERRORS.VALUE_INJECTED),
      'a value with a newline was written into a line-oriented file',
    );
    assert.throws(
      () => spoolCredentialEnvFile(HANDLE, ENV_NAME, `${VALUE}\rX=1`, { spoolDir: dir }),
      (error) => String(error.message).startsWith(CREDENTIAL_ERRORS.VALUE_INJECTED),
    );
    // Nothing was left behind by the refusal: an env file on disk is the leak.
    assert.deepEqual(readdirSync(dir), [], 'a refused credential left a file behind');
  });
});

test('a value too short to detect, or an env name that is not an identifier, is refused', () => {
  withSpool((dir) => {
    assert.throws(
      () => spoolCredentialEnvFile(HANDLE, ENV_NAME, 'short', { spoolDir: dir }),
      (error) => String(error.message).startsWith(CREDENTIAL_ERRORS.VALUE_INVALID),
    );
    for (const name of ['lower', '1BAD', 'HAS-DASH', 'HAS SPACE', '']) {
      assert.throws(
        () => assertCredentialEnvName(name),
        (error) => String(error.message).startsWith(CREDENTIAL_ERRORS.ENV_NAME_INVALID),
        `${JSON.stringify(name)} was accepted as an env name`,
      );
    }
    assert.equal(assertCredentialEnvName('ZAI_API_KEY_2'), 'ZAI_API_KEY_2');
  });
});

test('a credential with no DECLARED handle, or with no env file, is refused by the launcher', () => {
  const base = { image: pinnedImage(), argv: ['--version'] };
  assert.throws(
    () => buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
      ...base,
      credential: { handle: 'sec-not-declared', envFilePath: '/tmp/x.env' },
    }),
    (error) => String(error.message).includes(`${LAUNCH_ERRORS.ARGV_INVALID}:credential-handle-not-declared`),
    'a credential on an undeclared handle was accepted',
  );
  assert.throws(
    () => buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
      ...base,
      secretHandles: [HANDLE],
      credential: { handle: HANDLE },
    }),
    (error) => String(error.message).includes('credential-env-file-path-required'),
    'a credential with no env file path was accepted, which would put the value on the argv instead',
  );
});

test('WITHOUT a credential the invocation is byte-identical to the A-MVP-04 one: no --env-file appears', () => {
  // The default must not have moved. A paid run is opt-in, and the isolation
  // property A-MVP-04 measured is still the property when no credential is
  // declared.
  const invocation = buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
    image: pinnedImage(),
    argv: ['--version'],
    secretHandles: [HANDLE],
  });
  assert.ok(!invocation.argv.includes('--env-file'), 'a run that declared no credential still passes an env file');
  assert.ok(!invocation.argv.join(' ').includes(VALUE));
});

test('the executor env is the ONE declared surface; every other surface still leaks', () => {
  const surfaces = {
    argv: invocationArgv(),
    env: [`${ENV_NAME}=${VALUE}`, 'HOME=/tmp'],
    stdout: 'executor started',
    stderr: '',
    record: { status: 'PASS', axes: { network: { declared: 'deny_all' } } },
  };
  // Declared: exactly the env. Everything else is clean, so the run passes AND
  // the declaration is published, not inferred.
  const declared = assertNoSecretLeak(surfaces, { value: VALUE, expected: ['env'] });
  assert.equal(declared.ok, true, 'a clean run with the exception declared was reported as leaking');
  assert.deepEqual([...declared.expectedToCarry], ['env'], 'the declaration is not published with the result');

  // NOT declared: the same record now FAILS, which is the safe direction. A
  // caller that forgets the declaration does not get a pass.
  const forgotten = assertNoSecretLeak(surfaces, { value: VALUE });
  assert.equal(forgotten.ok, false, 'forgetting to declare the exception produced a PASS');
  assert.ok(forgotten.leaks.includes('env'), 'the undeclared env surface was not named as the leak');

  // Declared NARROWLY: allowing the env must not excuse anything else. This is
  // the property that stops the exception being widened until the detector is
  // decorative.
  const widened = assertNoSecretLeak(
    { ...surfaces, record: { note: `leaked ${VALUE}` } },
    { value: VALUE, expected: ['env'] },
  );
  assert.equal(widened.ok, false, 'declaring the env also excused the record');
  assert.ok(widened.leaks.includes('record'), 'the record leak was not reported');
  assert.ok(!widened.leaks.includes('env'), 'the declared env was reported as a leak');
  // And the same holds for the other clean-by-construction surfaces.
  for (const surface of ['argv', 'stdout', 'stderr']) {
    const leaked = assertNoSecretLeak(
      { ...surfaces, [surface]: `x ${VALUE} y` },
      { value: VALUE, expected: ['env'] },
    );
    assert.equal(leaked.ok, false, `${surface} was excused by an env-only declaration`);
    assert.ok(leaked.leaks.includes(surface), `the ${surface} leak was not named`);
  }

  // The declaration object publishes the mechanism, so a reader can see HOW the
  // value arrived and not just that it was allowed.
  const decl = credentialDeclaration({ envFile: { envName: ENV_NAME, path: '/tmp/.cred.env' }, surfaces: ['env'] });
  assert.equal(decl.env_name, ENV_NAME);
  assert.ok(decl.delivered_by.includes('--env-file'), 'the declaration does not say how the value was delivered');
});

function invocationArgv() {
  const invocation = buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
    image: pinnedImage(),
    argv: ['--version'],
    secretHandles: [HANDLE],
  });
  return invocation.argv.join(' ');
}
