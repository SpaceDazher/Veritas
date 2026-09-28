// S2-002 A-MVP-04 — the pure layer of the isolation profile.
//
// These tests need no container and no network. That is the point of the split:
// every rule in `src/lib/isolation/` is a function over a profile, so each one
// can be tested by asking what it does to a profile someone edited. A test that
// needed podman would pass or fail for reasons that have nothing to do with the
// rule, and a control that can only be exercised by an expensive live run is a
// control nobody runs.
//
// The tests that DO need a container are in `live-evidence.test.mjs`, and they
// read the record the live run produced rather than re-running it.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test, { describe } from 'node:test';

import {
  BASE_IMAGE,
  EXECUTOR_IMAGE_DIGEST,
  EXECUTOR_IMAGE_ID,
  EXECUTOR_TREE_FILES,
  EXECUTOR_TREE_SHA256,
  IMAGE_ERRORS,
  assertDigestPinned,
  assertImageMatchesPin,
  assertRealStart,
  digestOf,
  normalizeDigest,
  sha256,
} from '../../src/lib/isolation/image.mjs';
import {
  EXECUTABLE_TIERS,
  ISOLATION_EGRESS_ALLOWLIST,
  NON_EXECUTABLE_TIERS,
  PROFILE_ERRORS,
  SANDBOX_ISOLATION_EXECUTOR,
  assertExecutableProfile,
  assertNoWildcard,
  assertSecretHandleId,
  buildEnvironment,
  declaredSecretHandles,
  resolveEgress,
} from '../../src/lib/isolation/profile.mjs';
import { PODMAN_HOST, LAUNCH_ERRORS, assertGovernedRun, buildInvocation, validateArgv } from '../../src/lib/isolation/launch.mjs';
import { SECRET_ERRORS, assertHandleId, assertNoSecretLeak, fingerprint, secretMountPath } from '../../src/lib/isolation/secrets.mjs';
import { EGRESS_ERRORS, createEgressForwarder, parseConnectRequest } from '../../src/lib/isolation/egress.mjs';

const profile = SANDBOX_ISOLATION_EXECUTOR;
const code = (fn) => {
  try { fn(); return null; } catch (error) { return error.message; }
};

describe('image: a pin is a content address, never a tag', () => {
  test('a registry reference with a digest is accepted', () => {
    assert.equal(assertDigestPinned(BASE_IMAGE), BASE_IMAGE);
    assert.match(digestOf(BASE_IMAGE), /^sha256:[0-9a-f]{64}$/);
  });

  test('a bare digest is accepted and resolves to itself', () => {
    assert.equal(digestOf(EXECUTOR_IMAGE_ID), EXECUTOR_IMAGE_ID);
  });

  // The mutation this exists for: swap the digest for a tag and the pin is gone.
  for (const tag of [
    'docker.io/library/node:22-bookworm-slim',
    'docker.io/library/node:latest',
    'localhost/veritas-executor:isolated',
    'node',
  ]) {
    test(`a tag is refused: ${tag}`, () => {
      const message = code(() => assertDigestPinned(tag));
      assert.ok(message?.startsWith(IMAGE_ERRORS.NOT_DIGEST_PINNED), message);
    });
  }

  test('a short or malformed digest is refused rather than truncated into one', () => {
    for (const bad of ['node@sha256:abc', 'node@sha1:' + 'a'.repeat(40), '', null, 42, {}]) {
      assert.ok(code(() => assertDigestPinned(bad))?.startsWith(IMAGE_ERRORS.NOT_DIGEST_PINNED));
    }
  });

  // Podman answers `{{.Id}}` bare and `{{.Digest}}` prefixed on the same host.
  // Comparing raw strings reported a correct image as a mismatch, which is how a
  // gate teaches people to ignore it.
  test('normalizeDigest equates a bare hex id with its prefixed form', () => {
    const bare = EXECUTOR_IMAGE_ID.replace('sha256:', '');
    assert.equal(normalizeDigest(bare), EXECUTOR_IMAGE_ID);
    assert.equal(normalizeDigest(EXECUTOR_IMAGE_ID), EXECUTOR_IMAGE_ID);
    assert.equal(normalizeDigest(EXECUTOR_IMAGE_DIGEST), EXECUTOR_IMAGE_DIGEST);
    // And it does not invent agreement where there is none.
    assert.notEqual(normalizeDigest('a'.repeat(64)), EXECUTOR_IMAGE_ID);
    assert.equal(normalizeDigest('not-a-digest'), 'not-a-digest');
  });

  test('a matching inspect passes; each field alone is not enough', () => {
    const good = { Id: EXECUTOR_IMAGE_ID.replace('sha256:', ''), Digest: EXECUTOR_IMAGE_DIGEST, Architecture: 'amd64' };
    const checked = assertImageMatchesPin(good);
    assert.equal(checked.imageId, EXECUTOR_IMAGE_ID);
    assert.equal(checked.digest, EXECUTOR_IMAGE_DIGEST);

    assert.match(code(() => assertImageMatchesPin({ ...good, Id: 'b'.repeat(64) })), new RegExp(IMAGE_ERRORS.DIGEST_MISMATCH));
    assert.match(code(() => assertImageMatchesPin({ ...good, Digest: `sha256:${'c'.repeat(64)}` })), new RegExp(IMAGE_ERRORS.DIGEST_MISMATCH));
    assert.match(code(() => assertImageMatchesPin({ ...good, Architecture: 'arm64' })), new RegExp(IMAGE_ERRORS.DIGEST_MISMATCH));
  });

  test('an image that is not in the store is NOT_BUILT, not a pass', () => {
    for (const missing of [{}, { Id: '' }, { Digest: '' }, null, undefined]) {
      const message = code(() => assertImageMatchesPin(missing));
      assert.ok(message?.startsWith(IMAGE_ERRORS.NOT_BUILT), `${JSON.stringify(missing)} -> ${message}`);
    }
  });

  test('the executor tree digest is a constant next to the pin, not a free variable', () => {
    assert.match(EXECUTOR_TREE_SHA256, /^sha256:[0-9a-f]{64}$/);
    assert.equal(Number.isInteger(EXECUTOR_TREE_FILES), true);
    assert.ok(EXECUTOR_TREE_FILES > 1);
  });
});

describe('image: assertRealStart separates "ran" from "was permitted"', () => {
  const good = { exitCode: 0, signal: null, stdout: '0.87.1\n' };

  test('an observed zero exit with an executor-shaped version is a real start', () => {
    const proof = assertRealStart(good);
    assert.equal(proof.ok, true);
    assert.equal(proof.version, '0.87.1');
  });

  // `assert.ok(null === 0)` is false but `assert.ok(!null)` is true, and the
  // second is how a run that never started gets reported as a clean one. A null
  // exit is the case that must never pass. (0.0 is deliberately absent: in
  // JavaScript it IS the integer 0, so it belongs with the passing cases.)
  test('a null exit code is not a pass', () => {
    for (const exitCode of [null, undefined, '0', NaN, Infinity, -0.5, {}]) {
      const proof = assertRealStart({ ...good, exitCode });
      assert.equal(proof.ok, false, `exitCode ${String(exitCode)} must not pass`);
      assert.ok(proof.issues.some((i) => i.startsWith('exitCode:')));
    }
  });

  test('the integer 0 is the only exit status that passes', () => {
    assert.equal(assertRealStart({ ...good, exitCode: 0.0 }).ok, true);
    assert.equal(assertRealStart({ ...good, exitCode: -0 }).ok, true);
  });

  test('a non-zero exit is not a pass', () => {
    for (const exitCode of [1, 7, 125, 126, 137]) {
      assert.equal(assertRealStart({ ...good, exitCode }).ok, false);
    }
  });

  test('a signal is never a pass, even at exit 0', () => {
    assert.equal(assertRealStart({ ...good, signal: 'SIGKILL' }).ok, false);
  });

  // A launcher that printed the expected string while the image was broken would
  // satisfy the first two conditions. This is the one that catches it.
  test('stdout without an executor-shaped version is not a pass', () => {
    for (const stdout of ['', 'command not found', 'latest', 'v0.87.1', 'x'.repeat(40)]) {
      assert.equal(assertRealStart({ ...good, stdout }).ok, false, `stdout ${JSON.stringify(stdout)} must not pass`);
    }
  });

  test('the observed version is reported, not a constant', () => {
    assert.equal(assertRealStart({ ...good, stdout: '0.88.0\n' }).version, '0.88.0');
  });

  test('assertGovernedRun re-checks the pin, so an unpinned run proves nothing', () => {
    assert.throws(
      () => assertGovernedRun({ observation: good, pin: { Id: 'd'.repeat(64), Digest: EXECUTOR_IMAGE_DIGEST, Architecture: 'amd64' }, profile }),
      new RegExp(IMAGE_ERRORS.DIGEST_MISMATCH),
    );
    const ok = assertGovernedRun({ observation: good, pin: null, profile });
    assert.equal(ok.realStartProven, true);
  });
});

describe('profile: the four axes, deny by default', () => {
  test('the shipped profile is executable and carries no wildcard on any axis', () => {
    assert.equal(assertExecutableProfile(profile), true);
    assert.equal(assertNoWildcard(profile), true);
  });

  test('the shipped profile is LOCAL_RESTRICTED, not a floor tier', () => {
    assert.equal(profile.tier, 'LOCAL_RESTRICTED');
    assert.ok(EXECUTABLE_TIERS.includes(profile.tier));
    assert.ok(!NON_EXECUTABLE_TIERS.includes(profile.tier));
  });

  // A wildcard is a value, and a value is a leaf, so the scan has to reach leaves
  // through objects. The first version walked arrays only and missed
  // `[{host:'*'}]` entirely — the exact shape a network allowlist uses.
  test('a wildcard is refused at any depth on any axis', () => {
    const shapes = {
      'network allowlist host': { ...profile, network: { policy: 'allowlist', allowlist: [{ host: '*', ports: [443] }] } },
      'network allowlist nested port': { ...profile, network: { policy: 'allowlist', allowlist: [{ host: 'a.example', ports: [443] }, { host: 'b.example', ports: ['*'] }] } },
      'environment allowlist': { ...profile, environment: { ...profile.environment, allowlist: ['*'] } },
      'environment fixed value': { ...profile, environment: { ...profile.environment, fixed: { ...profile.environment.fixed, HOME: '*' } } },
      'filesystem roots': { ...profile, filesystem: { ...profile.filesystem, roots: ['/tmp', '*'] } },
      'secret handles': { ...profile, environment: { ...profile.environment, secret_handles: ['*'] } },
    };
    for (const [name, candidate] of Object.entries(shapes)) {
      const message = code(() => assertNoWildcard(candidate));
      assert.ok(message?.startsWith(PROFILE_ERRORS.WILDCARD_NOT_PERMITTED), `${name} -> ${message}`);
    }
  });

  test("'unrestricted' is refused as a network policy even though the contract permits it for HOST_UNISOLATED", () => {
    const message = code(() => assertNoWildcard({ ...profile, network: { policy: 'unrestricted', allowlist: [] } }));
    assert.ok(message?.startsWith(PROFILE_ERRORS.WILDCARD_NOT_PERMITTED), message);
  });

  // The tier the S2-007R record uses when a model-calling agent cannot run in
  // isolation. Accepting it here would be the silent substitution the handoff
  // forbids, so both floor tiers are refused by name.
  test('NO_EXEC and HOST_UNISOLATED are both refused by the launch gate', () => {
    for (const tier of NON_EXECUTABLE_TIERS) {
      const message = code(() => assertExecutableProfile({ ...profile, tier }));
      assert.ok(message?.startsWith(PROFILE_ERRORS.TIER_NOT_EXECUTABLE), `${tier} -> ${message}`);
    }
  });

  test('an unknown tier is refused too, not just the known-bad ones', () => {
    for (const tier of ['local_restricted', 'SANDBOX', '', null, undefined, 0]) {
      assert.ok(code(() => assertExecutableProfile({ ...profile, tier }))?.startsWith(PROFILE_ERRORS.TIER_NOT_EXECUTABLE));
    }
  });

  test('deny_all with a non-empty allowlist is refused, and allowlist with an empty one is refused', () => {
    const denyWithList = code(() => assertExecutableProfile({
      ...profile, network: { policy: 'deny_all', allowlist: ISOLATION_EGRESS_ALLOWLIST },
    }));
    assert.ok(denyWithList?.startsWith(PROFILE_ERRORS.PROFILE_MALFORMED), denyWithList);
    const emptyList = code(() => assertExecutableProfile({ ...profile, network: { policy: 'allowlist', allowlist: [] } }));
    assert.ok(emptyList?.startsWith(PROFILE_ERRORS.PROFILE_MALFORMED), emptyList);
  });

  test('a writable root filesystem is refused', () => {
    const message = code(() => assertExecutableProfile({
      ...profile, filesystem: { ...profile.filesystem, root_fs_read_only: false },
    }));
    assert.ok(message?.startsWith(PROFILE_ERRORS.PROFILE_MALFORMED), message);
  });

  test('a filesystem root that is relative or traverses is refused', () => {
    for (const root of ['tmp', '/tmp/../../etc', '/tmp/..', '', 'D:/workspaces']) {
      const message = code(() => assertExecutableProfile({ ...profile, filesystem: { ...profile.filesystem, roots: [root] } }));
      assert.ok(message?.startsWith(PROFILE_ERRORS.FS_ROOT_INVALID), `${root} -> ${message}`);
    }
  });

  test('an allowlist entry must name a real host and at least one real port', () => {
    const withAllowlist = (entry) => ({ ...profile, network: { policy: 'allowlist', allowlist: [entry] } });
    for (const entry of [{ host: 'not a host', ports: [443] }, { host: 'a.example', ports: [] }, { host: 'a.example', ports: [0] }, { host: 'a.example', ports: [70000] }, { host: 'a.example', ports: [443.5] }, { host: 'a.example' }]) {
      assert.ok(code(() => assertExecutableProfile(withAllowlist(entry)))?.startsWith(PROFILE_ERRORS.PROFILE_MALFORMED), JSON.stringify(entry));
    }
  });

  test('a secret handle must be a sec- identifier', () => {
    for (const bad of ['SEC-x', 'sec-', 'sec-UPPER', 'token-abc', '', null, 'sec-' + 'a'.repeat(80)]) {
      assert.ok(code(() => assertSecretHandleId(bad))?.startsWith(PROFILE_ERRORS.SECRET_HANDLE_INVALID), String(bad));
    }
    assert.equal(assertSecretHandleId('sec-ok-1'), 'sec-ok-1');
  });

  test('process ceilings must be positive integers', () => {
    for (const patch of [{ max_processes: 0 }, { max_processes: 1.5 }, { memory_mb: -1 }, { timeout_ms: '30000' }]) {
      assert.ok(code(() => assertExecutableProfile({ ...profile, process: { ...profile.process, ...patch } }))?.startsWith(PROFILE_ERRORS.PROFILE_MALFORMED), JSON.stringify(patch));
    }
  });
});

describe('profile: resolveEgress denies by default and names its reason', () => {
  test('deny_all refuses the allowlisted host too', () => {
    const decision = resolveEgress(profile, { host: 'open.bigmodel.cn', port: 443 });
    assert.equal(decision.allowed, false);
    assert.equal(decision.reason, 'DENY_ALL');
  });

  const allowProfile = { ...profile, network: { policy: 'allowlist', allowlist: ISOLATION_EGRESS_ALLOWLIST } };

  test('under allowlist, the named pair resolves and everything else does not', () => {
    assert.equal(resolveEgress(allowProfile, { host: 'open.bigmodel.cn', port: 443 }).allowed, true);
    for (const destination of [
      { host: 'open.bigmodel.cn', port: 22 },
      { host: 'open.bigmodel.cn', port: 8443 },
      { host: 'evil.example.com', port: 443 },
      { host: 'evil.example.com', port: 80 },
      { host: 'OPEN.BIGMODEL.CN', port: 443 },
      { host: 'open.bigmodel.cn.evil.example', port: 443 },
      { host: 'sub.open.bigmodel.cn', port: 443 },
    ]) {
      const decision = resolveEgress(allowProfile, destination);
      assert.equal(decision.allowed, false, `${destination.host}:${destination.port} must be refused`);
      assert.equal(decision.code, PROFILE_ERRORS.DESTINATION_NOT_ALLOWLISTED);
    }
  });

  test('the egress allowlist itself carries no wildcard and a real host', () => {
    assertNoWildcard({ ...profile, network: { policy: 'allowlist', allowlist: ISOLATION_EGRESS_ALLOWLIST } });
    for (const entry of ISOLATION_EGRESS_ALLOWLIST) {
      assert.notEqual(entry.host, '*');
      assert.ok(entry.ports.length > 0);
      for (const port of entry.ports) assert.ok(port >= 1 && port <= 65535);
    }
  });
});

describe('profile: the environment axis is built, not inherited', () => {
  test('the child env is exactly the allowlist, as literal pairs', () => {
    const pairs = buildEnvironment(profile);
    assert.deepEqual(pairs, ['HOME=/tmp', 'TMPDIR=/tmp', 'PI_HOME=/tmp/pi', 'NODE_ENV=production']);
    assert.equal(pairs.length, profile.environment.allowlist.length);
  });

  test('a name on the allowlist with no fixed value is refused rather than passed as empty', () => {
    const message = code(() => buildEnvironment({
      ...profile,
      environment: { ...profile.environment, allowlist: [...profile.environment.allowlist, 'MISSING'] },
    }));
    assert.ok(message?.startsWith(PROFILE_ERRORS.ENV_NOT_ALLOWLISTED), message);
  });

  test('a lowercase name is refused, so a secret cannot be smuggled in as a variable', () => {
    const message = code(() => assertExecutableProfile({
      ...profile,
      environment: { ...profile.environment, allowlist: ['api_key'], fixed: { api_key: 'x' } },
    }));
    assert.ok(message?.startsWith(PROFILE_ERRORS.PROFILE_MALFORMED), message);
  });

  test('the declared handles are the profile’s own, and only those', () => {
    assert.deepEqual([...declaredSecretHandles(profile)], [...profile.environment.secret_handles]);
    for (const handle of declaredSecretHandles(profile)) assertSecretHandleId(handle);
  });
});

describe('launch: the argv carries the profile and nothing else', () => {
  const request = { argv: ['node', '/opt/veritas-executor/dist/bundle/cli.js', '--version'], image: EXECUTOR_IMAGE_ID, secretHandles: profile.environment.secret_handles, workdir: '/tmp' };

  test('the four axes appear as flags, each from its own profile field', () => {
    const { podmanArgv, axes } = buildInvocation(profile, request);
    // Handles BOTH spellings: `--flag value` and `--flag=value`. A test helper
    // that only understood the first returned podmanArgv[0] for every `=` flag,
    // which is how `--ipc=none` was reported as `'run' !== 'none'` and the
    // assertion below would have been checking the wrong thing.
    const value = (name) => {
      const joined = podmanArgv.find((a) => a.startsWith(`${name}=`));
      if (joined !== undefined) return joined.slice(name.length + 1);
      const at = podmanArgv.indexOf(name);
      return at === -1 ? undefined : podmanArgv[at + 1];
    };
    const has = (name) => podmanArgv.includes(name) || podmanArgv.some((a) => a.startsWith(`${name}=`));
    // network
    assert.equal(value('--network'), 'none');
    assert.equal(axes.network.policy, 'deny_all');
    assert.equal(axes.network.egressSocket, null, 'a deny_all profile must not mount an egress socket');
    // filesystem
    assert.equal(has('--read-only'), true);
    assert.ok(podmanArgv.some((a) => a.startsWith('--tmpfs=/tmp:') && a.includes('noexec') && a.includes('nosuid') && a.includes('nodev')));
    assert.equal(axes.filesystem.rootFsReadOnly, true);
    // environment
    for (const pair of ['HOME=/tmp', 'TMPDIR=/tmp', 'PI_HOME=/tmp/pi', 'NODE_ENV=production']) {
      assert.ok(podmanArgv.includes(pair), pair);
    }
    assert.equal(axes.environment.inherited, false);
    assert.deepEqual(axes.environment.pairs, buildEnvironment(profile));
    // process
    assert.equal(value('--pids-limit'), '32');
    assert.equal(value('--memory'), '256m');
    assert.equal(value('--memory-swap'), '256m');
    assert.equal(value('--cpus'), '0.5');
    // the rest of the tier
    assert.equal(value('--cap-drop'), 'all');
    assert.equal(value('--security-opt'), 'no-new-privileges');
    assert.equal(value('--user'), '65534:65534');
    assert.equal(value('--ipc'), 'none');
    assert.equal(value('--log-driver'), 'none');
    assert.equal(has('--pull=never'), true);
    assert.equal(podmanArgv.includes('--rm'), true);
  });

  test('the image is a content address and the workload follows it', () => {
    const { podmanArgv } = buildInvocation(profile, request);
    const at = podmanArgv.indexOf(EXECUTOR_IMAGE_ID);
    assert.ok(at > 0);
    assert.deepEqual(podmanArgv.slice(at + 1), [...request.argv]);
    assert.doesNotThrow(() => assertDigestPinned(podmanArgv[at]));
  });

  test('a secret HANDLE is on the argv and no secret VALUE can be', () => {
    const { podmanArgv } = buildInvocation(profile, request);
    assert.equal(podmanArgv[podmanArgv.indexOf('--secret') + 1], profile.environment.secret_handles[0]);
    // Nothing in the podman argv looks like a credential: no key=, no token=, no
    // long opaque token, and no path that would carry a value.
    for (const argument of podmanArgv) {
      assert.doesNotMatch(argument, /=(sk-|key=|token=|password|bearer)/i, argument);
    }
  });
  test('an undeclared handle is refused: the profile is the authority on credentials', () => {
    for (const handle of ['sec-not-declared', 'sec-other-credential']) {
      const message = code(() => buildInvocation(profile, { ...request, secretHandles: [handle] }));
      assert.ok(message?.includes('handle-not-declared'), `${handle} -> ${message}`);
    }
  });

  test('a tag as the image is refused before anything is spawned', () => {
    const message = code(() => buildInvocation(profile, { ...request, image: 'localhost/veritas-executor:isolated' }));
    assert.ok(message?.startsWith(IMAGE_ERRORS.NOT_DIGEST_PINNED), message);
  });

  test('an allowlist profile REQUIRES the egress socket, so the axis cannot be half-wired', () => {
    const allowProfile = { ...profile, network: { policy: 'allowlist', allowlist: ISOLATION_EGRESS_ALLOWLIST } };
    const missing = code(() => buildInvocation(allowProfile, request));
    assert.ok(missing?.includes('egressSocketPath-required-for-allowlist'), missing);
    const { podmanArgv, axes } = buildInvocation(allowProfile, { ...request, egressSocketPath: '/tmp/eg.sock' });
    // The kernel still denies everything; the socket is the only exit.
    assert.equal(podmanArgv.includes('--network=none'), true);
    assert.ok(podmanArgv.includes('--mount'));
    assert.ok(podmanArgv.some((a) => a.includes('/tmp/eg.sock') && a.includes('dst=/run/egress.sock')));
    assert.equal(axes.network.egressSocket, '/tmp/eg.sock');
    // And a deny_all profile given a socket still does not get one.
    assert.equal(buildInvocation(profile, { ...request, egressSocketPath: '/tmp/eg.sock' }).axes.network.egressSocket, null);
  });

  test('a hostile argv is refused: empty, NUL-bearing, oversized, non-string, too long', () => {
    for (const argv of [[], ['a', 'b\0c'], [42], [''], new Array(65).fill('x'), ['x'.repeat(5000)]]) {
      assert.ok(code(() => validateArgv(argv))?.startsWith(LAUNCH_ERRORS.ARGV_INVALID), JSON.stringify(argv).slice(0, 40));
    }
  });

  test('the launcher is the measured host invocation, not a default', () => {
    assert.equal(PODMAN_HOST.executable, 'podman');
    assert.ok(PODMAN_HOST.argvPrefix.includes('--root'));
    assert.ok(PODMAN_HOST.argvPrefix.includes('--runtime'));
    const { argv } = buildInvocation(profile, request);
    assert.deepEqual(argv.slice(0, PODMAN_HOST.argvPrefix.length), [...PODMAN_HOST.argvPrefix]);
  });

  test('no process.env appears on the path that builds the child environment', () => {
    // A structural check, and the one that makes "the host environment is not
    // inherited" a fact about this code rather than a claim about a flag.
    //
    // COMMENTS ARE STRIPPED FIRST. The first version of this test read the file
    // raw and failed, because the module's own comment says "There is no
    // `...process.env` in this file" — the check was matching its own
    // documentation. A structural test that cannot distinguish prose from code
    // is a test that gets deleted the first time somebody improves a comment.
    const stripComments = (source) => source
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:])\/\/.*$/gm, '$1');
    for (const file of ['launch.mjs', 'profile.mjs']) {
      const source = stripComments(readFileSync(path.join(import.meta.dirname, '..', '..', 'src', 'lib', 'isolation', file), 'utf8'));
      assert.equal(/\bprocess\s*\.\s*env\b/.test(source), false, `${file} must not read process.env on the child-environment path`);
    }
  });
});

describe('secrets: a handle is a name and a value is what must not leak', () => {
  const handle = 'sec-veritas-executor-credential';
  const value = 'VERITAS_S2_002_NOT_A_REAL_SECRET_CANARY_9f3c1d7b4e2a6058';

  test('the mount path is derived from the handle and contains no value', () => {
    assert.equal(secretMountPath(handle), `/run/secrets/${handle}`);
    assert.equal(secretMountPath(handle).includes(value), false);
  });

  test('a handle that is not sec- prefixed is refused', () => {
    for (const bad of ['token-abc', 'SEC-abc', 'sec-', '', null]) {
      assert.ok(code(() => assertHandleId(bad))?.startsWith(SECRET_ERRORS.HANDLE_INVALID), String(bad));
    }
  });

  test('a clean surface reports no leak', () => {
    const result = assertNoSecretLeak({
      argv: 'podman run --secret sec-x node --version',
      env: '["HOME","PATH"]',
      stdout: '0.87.1',
      stderr: '',
      record: '{"status":"PASS"}',
    }, { value });
    assert.equal(result.ok, true);
    assert.deepEqual([...result.leaks], []);
  });

  // Every surface a launcher plausibly leaks through, planted one at a time. A
  // detector that only looks at stdout is a detector that misses a value in argv.
  test('the value is found in every surface it could plausibly reach', () => {
    for (const surface of ['argv', 'env', 'stdout', 'stderr', 'record']) {
      const result = assertNoSecretLeak({ [surface]: `prefix ${value} suffix` }, { value, required: ['argv', 'env', 'stdout', 'stderr', 'record'] });
      assert.equal(result.ok, false, `${surface} must be detected`);
      assert.ok(result.leaks.includes(surface), `${surface} -> ${[...result.leaks]}`);
    }
  });

  test('a nested surface is searched as JSON, so a value inside a field is found', () => {
    const result = assertNoSecretLeak({ record: { nested: { note: value } } }, { value, required: ['record'] });
    assert.equal(result.ok, false);
    assert.ok(result.leaks.includes('record'));
  });

  // A missing surface is a hole, not a pass. Without this the caller could omit
  // the one surface it was worried about and get a clean report.
  test('a required surface that was not supplied is itself a finding', () => {
    const result = assertNoSecretLeak({ stdout: 'clean' }, { value });
    assert.equal(result.ok, false);
    for (const missing of ['argv', 'env', 'stderr', 'record']) {
      assert.ok(result.leaks.includes(`${missing}:surface-not-supplied`), `${missing} -> ${[...result.leaks]}`);
    }
  });

  // A value too short to search for would match by accident and make the detector
  // report leaks everywhere, which is the same as reporting none.
  test('a value too short to detect is refused rather than searched for', () => {
    for (const short of ['', 'a', 'abc', '1234567']) {
      assert.ok(code(() => assertNoSecretLeak({ stdout: 'x' }, { value: short }))?.startsWith(SECRET_ERRORS.HANDLE_NOT_PROVIDED), String(short));
    }
  });

  test('the fingerprint identifies a value without being it, and is stable', () => {
    const printed = fingerprint(value);
    assert.match(printed, /^[0-9a-f]{16}$/);
    assert.equal(printed.includes(value), false);
    assert.equal(fingerprint(value), printed);
    assert.notEqual(fingerprint(`${value}x`), printed);
  });

  test('the secret form this host needs is recorded, because podman changed it', () => {
    // podman 4.9.3 refuses `id=…,src=…` and treats a bare `src=…` as a NAME; only
    // the store-backed name form works. The record names the form so a podman
    // upgrade does not change the semantics silently.
    assert.equal(SECRET_ERRORS.PODMAN_SECRET_FORM, 'podman-secret-store-name-only');
  });
});

describe('egress: the forwarder filters, and cannot be built into a pass-through', () => {  test('only the request line is parsed; a Host header does not make it malformed', () => {
    // The bug this pins: anchoring the regex to the end of the whole header block
    // refused every well-formed CONNECT, including the allowlisted one.
    for (const block of [
      'CONNECT open.bigmodel.cn:443 HTTP/1.1\r\nHost: open.bigmodel.cn:443\r\n\r\n',
      'CONNECT open.bigmodel.cn:443 HTTP/1.1\r\nHost: a.example:1\r\nProxy-Connection: keep-alive\r\n\r\n',
    ]) {
      const parsed = parseConnectRequest(block);
      assert.deepEqual(parsed && { host: parsed.host, port: parsed.port, method: parsed.method },
        { host: 'open.bigmodel.cn', port: 443, method: 'CONNECT' });
    }
  });

  test('a malformed request line yields null rather than a guess', () => {
    for (const block of [
      '', 'CONNECT\r\n', 'CONNECT open.bigmodel.cn HTTP/1.1\r\n\r\n',
      'CONNECT open.bigmodel.cn:0 HTTP/1.1\r\n\r\n', 'CONNECT open.bigmodel.cn:70000 HTTP/1.1\r\n\r\n',
      'CONNECT :443 HTTP/1.1\r\n\r\n', 'garbage\r\n\r\n',
    ]) {
      assert.equal(parseConnectRequest(block), null, JSON.stringify(block));
    }
  });

  test('the forwarder refuses to be constructed with a wildcard allowlist', () => {
    for (const allowlist of [[{ host: '*', ports: [443] }], [{ host: 'a.example', ports: [0] }], [], null, 'x']) {
      const message = code(() => createEgressForwarder({ allowlist, socketPath: '/tmp/never.sock' }));
      assert.ok(message?.startsWith(EGRESS_ERRORS.MALFORMED), JSON.stringify(allowlist));
    }
  });
});
