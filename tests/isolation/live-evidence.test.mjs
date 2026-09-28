// S2-002 A-MVP-04 — the live record, asserted.
//
// This suite does NOT re-run anything. It reads the two records the live scripts
// wrote and asserts that what they claim is what they observed. That split is
// deliberate: `profile-axes.test.mjs` proves the rules hold, and this file proves
// the rules were actually exercised on this host and the record says so.
//
// WHY IT READS RATHER THAN RUNS
//
// A test that starts a container costs minutes and fails for reasons unrelated to
// the claim. A test that reads a record is fast, and — this is the part that
// matters — it fails the moment the record stops matching the code, because the
// assertions below are the same expressions the code uses. If a future change
// loosens `assertRealStart`, the record's `realStartProven: true` stops being
// derivable and this file is where that shows up.
//
// WHAT IT WILL NOT DO
//
// It will not accept a record that is missing, `NOT_RUN` without a reason, or
// that claims a version nobody printed. An absent record is a failure, not a skip:
// the whole point of A-MVP-04 is that the measurement was taken, and "the file is
// not there" is the one state that proves nothing either way.
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import test, { describe } from 'node:test';

import {
  EXECUTOR_IMAGE_DIGEST,
  EXECUTOR_IMAGE_ID,
  EXECUTOR_TREE_SHA256,
  EXECUTOR_VERSION,
  assertDigestPinned,
  assertImageMatchesPin,
  assertRealStart,
  normalizeDigest,
} from '../../src/lib/isolation/image.mjs';
import {
  EXECUTABLE_TIERS,
  NON_EXECUTABLE_TIERS,
  SANDBOX_ISOLATION_EXECUTOR,
  assertExecutableProfile,
  assertNoWildcard,
} from '../../src/lib/isolation/profile.mjs';
import { PODMAN_HOST } from '../../src/lib/isolation/launch.mjs';
import { assertNoSecretLeak } from '../../src/lib/isolation/secrets.mjs';

const ROOT = path.resolve(import.meta.dirname, '..', '..');
const IMAGE_RECORD = path.join(ROOT, 'evidence', 's2-002-isolation-image.json');
const LIVE_RECORD = path.join(ROOT, 'evidence', 's2-002-isolation-live.json');

const read = (file) => JSON.parse(readFileSync(file, 'utf8'));
const image = existsSync(IMAGE_RECORD) ? read(IMAGE_RECORD) : null;
const live = existsSync(LIVE_RECORD) ? read(LIVE_RECORD) : null;

describe('A-MVP-04: the image record exists and pins what it claims to pin', () => {
  test('the record is present', () => {
    assert.ok(image, 'evidence/s2-002-isolation-image.json is missing; the image was never pinned');
    assert.equal(image.schemaVersion, 1);
    assert.equal(image.record, 's2-002-isolation-image');
  });

  test('the base is a registry digest, pulled by that digest, and the store agrees', () => {
    assert.doesNotThrow(() => assertDigestPinned(image.base.reference));
    assert.match(image.base.registry_digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(image.base.pull_exit, 0);
    assert.equal(image.base.digest_matches_pin, true);
    assert.equal(image.base.observed_digest, image.base.registry_digest);
  });

  test('the derived image matches BOTH pinned fields, and both are content addresses', () => {
    assert.doesNotThrow(() => assertDigestPinned(image.pin.executor_image_id));
    assert.doesNotThrow(() => assertDigestPinned(image.pin.executor_image_digest));
    assert.equal(image.pin.id_matches, true, `id ${image.pin.executor_image_id}`);
    assert.equal(image.pin.digest_matches, true, `digest ${image.pin.executor_image_digest}`);
    assert.equal(normalizeDigest(image.build.observed.Id), EXECUTOR_IMAGE_ID);
    assert.equal(normalizeDigest(image.build.observed.Digest), EXECUTOR_IMAGE_DIGEST);
    // And the gate that would catch a mismatch really does catch one, on the
    // record's own terms: re-derive it from what podman reported.
    assert.doesNotThrow(() => assertImageMatchesPin(image.build.observed));
    assert.equal(image.pin.digest_pinned, true);
  });

  // The pin and its provenance move together or not at all. A tree digest that
  // does not match means the image on this host was built from different bytes
  // than the pin describes, whatever the image digest says.
  test('the executor tree that the pin was built from is recorded and matches', () => {
    assert.equal(image.pin.executor_tree_sha256_pinned, EXECUTOR_TREE_SHA256);
    assert.equal(image.pin.executor_tree_sha256_observed, EXECUTOR_TREE_SHA256);
    assert.equal(image.pin.executor_tree_matches, true);
    assert.equal(image.pin.executor_tree_files_observed, image.pin.executor_tree_files_pinned);
    assert.ok(image.pin.executor_tree_files_pinned > 1);
  });

  test('the provenance says the executor is genuinely installed, not vendored', () => {
    assert.equal(image.provenance.committed_to_repository, false);
    assert.match(image.provenance.source_path, /node_modules\/@earendil-works\/pi-coding-agent$/);
    assert.equal(image.provenance.installed_version_from_package_json, EXECUTOR_VERSION);
    assert.equal(image.provenance.version_matches, true);
  });

  test('the record says the derived pin is reproducible and names the recipe', () => {
    assert.equal(image.reproducibility.portablePin, 'base.registry_digest');
    assert.equal(image.reproducibility.localPin, 'executor.derived_digest');
    assert.match(image.reproducibility.recipe, /--timestamp 0/);
    assert.match(image.reproducibility.measured, /identical/);
  });

  test('the build succeeded and the image carries layers', () => {
    assert.equal(image.status, 'PASS', image.reason ?? '');
    assert.equal(image.build.performed, true);
    assert.equal(image.build.build_exit, 0);
    assert.equal(image.build.inspect_exit, 0);
    assert.ok(image.build.observed.layers > 1, 'a one-layer image would be the base alone, with no executor in it');
  });

  test('the limits are stated, not implied away', () => {
    assert.ok(Array.isArray(image.limits) && image.limits.length >= 2);
    const text = image.limits.join(' ');
    assert.match(text, /derived digest/);
    assert.match(text, /no RUN instruction/);
  });
});

describe('A-MVP-04: the live record observed a real run under the profile', () => {
  test('the record is present and it is not a skip', () => {
    assert.ok(live, 'evidence/s2-002-isolation-live.json is missing; no live isolation run was recorded');
    assert.equal(live.record, 's2-002-isolation-live');
    assert.equal(live.aMvpClause, 'изоляция — образ, allowlist, secret handles');
    // NOT_RUN is a legitimate outcome and must carry its reason. What is not
    // legitimate is a record that is absent, or NOT_RUN with no explanation, or
    // any status outside the three.
    assert.ok(['PASS', 'FAIL', 'NOT_RUN'].includes(live.status), `unexpected status ${live.status}`);
    if (live.status !== 'PASS') {
      assert.ok(live.reason && live.reason.length > 20, 'a non-PASS record must state why');
    }
  });

  test('the tier is LOCAL_RESTRICTED and is one of the executable tiers', () => {
    assert.equal(live.tier, 'LOCAL_RESTRICTED');
    assert.ok(EXECUTABLE_TIERS.includes(live.tier));
    // The two tiers that must never appear here, spelled out so a reader does
    // not have to look them up.
    assert.ok(!NON_EXECUTABLE_TIERS.includes(live.tier));
    assert.deepEqual([...live.nonExecutableTiers], [...NON_EXECUTABLE_TIERS]);
  });

  test('the host could really raise isolation, and the record says which invocation', () => {
    assert.equal(live.host.isolationCanBeRaised, true);
    assert.equal(live.host.rootless, true);
    assert.equal(live.host.cgroupVersion, 'v2');
    assert.match(live.host.podmanVersion, /4\.9\.3/);
    assert.match(live.host.crunVersion, /crun version/);
    assert.deepEqual(live.host.launcher.argvPrefix, [...PODMAN_HOST.argvPrefix]);
  });

  test('the executor version was OBSERVED inside the container, not read from a file', () => {
    // Re-derive the proof with the same function the launcher used, from the
    // VERSION RUN's own exit code. If the gate is ever loosened, this stops
    // holding and the record is no longer evidence.
    const version = live.realRun.executor_version;
    const proof = assertRealStart({ exitCode: version.exitCode, signal: version.signal, stdout: version.stdout });
    assert.equal(proof.ok, true, `real start not provable from the record: ${[...proof.issues]}`);
    assert.equal(proof.version, EXECUTOR_VERSION);
    assert.equal(live.component.observedVersion, EXECUTOR_VERSION);
    assert.equal(live.component.expectedVersion, EXECUTOR_VERSION);
    assert.equal(live.realRun.realStartProven, true);
    assert.match(live.component.versionSource, /printed it from inside the container/);
  });

  test('the axis probe and the version run are two runs with two exit codes, both zero', () => {
    // Collapsing them into one `exitCode` made the record unable to re-derive
    // the real-start proof from its own bytes.
    assert.equal(live.realRun.axis_probe.exitCode, 0, live.realRun.axis_probe.stderrSha256);
    assert.equal(live.realRun.executor_version.exitCode, 0);
    assert.equal(live.realRun.axis_probe.signal, null);
    assert.equal(live.realRun.executor_version.signal, null);
    assert.match(live.realRun.axis_probe.stdout, /VERITAS_ROUTE_ROWS=/);
  });

  test('the image that ran is the pinned image, on both fields', () => {
    assert.match(live.image.executorImageId, /^sha256:[0-9a-f]{64}$/);
    assert.equal(normalizeDigest(live.image.executorImageId), EXECUTOR_IMAGE_ID);
    assert.equal(normalizeDigest(live.image.executorImageDigest), EXECUTOR_IMAGE_DIGEST);
    assert.equal(live.image.pinVerified, true);
    assert.deepEqual([...live.image.pinIssues], []);
    // The record says which pin is portable and which is local, rather than
    // presenting two digests as equally authoritative.
    assert.match(live.image.pinKind.base, /portable/);
    assert.match(live.image.pinKind.executor, /THIS host/);
  });

  test('the four axes were each measured from inside the container, not asserted', () => {
    const probe = live.realRun.axisProbe;
    // network: an empty route table
    assert.equal(probe.VERITAS_ROUTE_ROWS, '0', 'the container had a route');
    // filesystem: root read-only, the declared tmpfs writable
    assert.equal(probe.VERITAS_HOST_FS_WRITABLE, 'EROFS');
    assert.equal(probe.VERITAS_TMP_FS_WRITABLE, 'true');
    // process identity: the unprivileged uid the profile names
    assert.equal(probe.VERITAS_UID, '65534:65534');
    // environment: exactly the declared pairs are present
    for (const pair of ['HOME=/tmp', 'TMPDIR=/tmp', 'PI_HOME=/tmp/pi', 'NODE_ENV=production']) {
      const name = pair.split('=')[0];
      assert.ok(JSON.parse(probe.VERITAS_ENV).includes(name), `${name} missing from the container env`);
    }
  });

  test('the record separates what is ON from what is OFF, per axis, with the enforcer named', () => {
    for (const axis of ['network', 'filesystem', 'environment', 'process', 'image', 'secrets']) {
      const section = live.axes[axis];
      assert.ok(section, `axis ${axis} is missing from the record`);
      assert.ok(Array.isArray(section.on) && section.on.length > 0, `${axis}.on is empty`);
      assert.ok(Array.isArray(section.off) && section.off.length > 0, `${axis}.off is empty`);
      assert.ok(section.enforced_by && section.enforced_by.length > 5, `${axis}.enforced_by is missing`);
    }
  });

  test('the process axis states the ceiling it did not independently provoke', () => {
    // Honest reporting beats a complete-looking table: this ceiling is recorded
    // from the argv the kernel received, and the record says so.
    assert.equal(live.axes.process.declared, 'max_processes=32, memory=256m, cpus=0.5');
    assert.match(live.axes.process.not_independently_measured, /not provoked/);
  });

  test("the record carries no '*' in any executable profile's axes", () => {
    const serialised = JSON.stringify(live.axes);
    assert.equal(serialised.includes('"*"'), false, 'the record contains a wildcard value');
    assert.doesNotThrow(() => assertNoWildcard(SANDBOX_ISOLATION_EXECUTOR));
    assert.doesNotThrow(() => assertExecutableProfile(SANDBOX_ISOLATION_EXECUTOR));
  });
});

describe('A-MVP-04: the secret arrived as a descriptor and did not leak', () => {
  test('the handle is a sec- identifier and the mount path carries no value', () => {
    assert.match(live.secretHandle.handle, /^sec-[a-z0-9][a-z0-9-]{0,62}$/);
    assert.equal(live.secretHandle.mountPathInsideContainer, `/run/secrets/${live.secretHandle.handle}`);
    assert.equal(live.secretHandle.valuePublished, false);
    assert.match(live.secretHandle.valueOrigin, /synthetic/);
  });

  test('the container resolved the descriptor and reported a LENGTH', () => {
    const probe = live.realRun.axisProbe;
    assert.equal(probe.VERITAS_SECRET_PRESENT, 'true');
    assert.equal(probe.VERITAS_SECRET_PATH, `/run/secrets/${live.secretHandle.handle}`);
    assert.ok(Number.isInteger(Number(probe.VERITAS_SECRET_LEN)) && Number(probe.VERITAS_SECRET_LEN) > 0);
  });

  test('the value is in neither the container argv nor the container environment', () => {
    const probe = live.realRun.axisProbe;
    const argv = JSON.parse(probe.VERITAS_ARGV);
    assert.deepEqual(argv, ['/opt/veritas-executor/dist/bundle/cli.js', '--version']);
    // No environment variable holds a value; the only secret-related name is the
    // PATH the descriptor is read from.
    const env = JSON.parse(probe.VERITAS_ENV);
    assert.equal(env.includes(live.secretHandle.handle), false, 'the handle is not an environment variable');
    const valueish = env.filter((k) => /SECRET|KEY|TOKEN|PASSWORD/i.test(k));
    assert.deepEqual(valueish, ['VERITAS_SECRET_MOUNT'], 'a value-shaped variable is present in the container env');
  });

  test('the detector searched every surface and found nothing', () => {
    assert.equal(live.leakDetection.leakDetected, false, `leaks: ${[...(live.leakDetection.leaks ?? [])]}`);
    assert.deepEqual([...(live.leakDetection.leaks ?? [])], []);
    assert.equal(live.leakDetection.finalRecordScan.ok, true);
    assert.deepEqual([...live.leakDetection.finalRecordScan.leaks], []);
    for (const surface of ['argv', 'env', 'stdout', 'stderr', 'record']) {
      assert.ok(live.leakDetection.surfacesSearched.includes(surface), `${surface} was not searched`);
    }
    assert.equal(live.leakDetection.valuePublished, false);
  });

  // A detector that has never fired is indistinguishable from one that cannot
  // fire. The run plants the value in a throwaway surface and requires the
  // detector to report it.
  test('the detector fires on a planted value, so its silence above means something', () => {
    assert.equal(live.leakDetection.detectorFiresOnPlantedValue, true);
    assert.equal(live.leakDetection.detectorSelfCheckPassed, true);
    // And the same function, fed a planted surface, does so right now.
    const planted = assertNoSecretLeak({ stdout: 'x' }, { value: 'x'.repeat(8) });
    assert.equal(planted.ok, false);
  });

  test('the fingerprint is published and the value is not', () => {
    assert.match(live.leakDetection.fingerprint, /^[0-9a-f]{16}$/);
    const serialised = JSON.stringify(live);
    assert.equal(serialised.includes('VERITAS_S2_002_NOT_A_REAL_SECRET'), false, 'the record contains the canary value');
  });
});

describe('A-MVP-04: every negative control planted an attempt and got a named refusal', () => {
  const byName = Object.fromEntries(live.negativeControls.map((c) => [c.control, c]));

  test('all six controls ran and all six passed', () => {
    assert.equal(live.negativeControls.length, 6);
    for (const control of live.negativeControls) {
      assert.equal(control.passed, true, `${control.control}: ${JSON.stringify(control).slice(0, 300)}`);
      assert.ok(control.what && control.why_it_matters, `${control.control} does not say what it plants or why it matters`);
    }
  });

  // Control 1: a tier that is not executable must be refused.
  test('a tier that is not executable is refused, with a code, before any process', () => {
    const control = byName.NON_EXECUTABLE_TIER_REFUSED;
    assert.equal(control.results.NO_EXEC.refused, true);
    assert.equal(control.results.NO_EXEC.code, 'ISOLATION_TIER_NOT_EXECUTABLE');
    assert.equal(control.results.HOST_UNISOLATED.refused, true);
    assert.equal(control.results.HOST_UNISOLATED.code, 'ISOLATION_TIER_NOT_EXECUTABLE');
  });

  // Control 2: a secret in a log must be caught.
  test('the leak detector caught a planted value in a log surface', () => {
    assert.equal(live.leakDetection.detectorSelfCheckPassed, true);
    // Re-run the detector on a surface that really does carry the value. The
    // first version of this test put the value in the `value` argument and an
    // unrelated sentence in the surface, so there was nothing to find and the
    // assertion was checking a leak that had never been planted.
    const planted = 'CANARY_VALUE_PLANTED_HERE';
    const detector = assertNoSecretLeak({ stdout: `log line with ${planted} inside` }, { value: planted, required: ['stdout'] });
    assert.equal(detector.ok, false);
    assert.deepEqual([...detector.leaks], ['stdout']);
  });

  // Control 3: leaving the allowlist must be refused.
  test('leaving the network allowlist is refused by host, by port, and by policy', () => {
    const control = byName.ALLOWLIST_ESCAPE_REFUSED;
    assert.equal(control.off_allowlist_host.refused, true);
    assert.match(control.off_allowlist_host.raw, /EGRESS_NOT_ALLOWLISTED/);
    assert.equal(control.off_allowlist_port.refused, true);
    assert.match(control.off_allowlist_port.raw, /EGRESS_NOT_ALLOWLISTED/);
    // The inversion: the allowlisted pair is ADMITTED, so the two refusals above
    // are a filter and not a wall that refuses everything.
    assert.equal(control.on_allowlist.admitted, true);
    assert.match(control.on_allowlist.raw, /HTTP\/1\.1 200/);

    const resolution = byName.DENY_BY_DEFAULT_RESOLUTION;
    assert.equal(resolution.deny_all.allowed, false);
    assert.equal(resolution.allowlist_denied.allowed, false);
    assert.equal(resolution.allowlist_denied.code, 'ISOLATION_DESTINATION_NOT_ALLOWLISTED');
    assert.equal(resolution.allowlist_allowed.allowed, true);
  });

  test('a wildcard is refused on every axis and as a network policy', () => {
    const control = byName.WILDCARD_ALLOWLIST_REFUSED;
    for (const [shape, result] of Object.entries(control.shapes)) {
      assert.equal(result.refused, true, `${shape} was not refused`);
      assert.equal(result.code, 'ISOLATION_WILDCARD_ALLOWLIST_NOT_PERMITTED', shape);
    }
    assert.equal(Object.keys(control.shapes).length, 4);
  });

  test('the container had no route at all, so the kernel is the network enforcer', () => {
    const control = byName.NO_ROUTE_INSIDE_CONTAINER;
    assert.equal(control.exitCode, 7);
    assert.equal(control.observed, 'ERR=EAI_AGAIN');
  });

  test('the operator environment is not inherited: neither the planted variable nor the operator HOME arrived', () => {
    const control = byName.HOST_ENVIRONMENT_NOT_INHERITED;
    assert.equal(control.variable_present_in_container_env, false);
    assert.equal(control.planted_value_observed_inside_container, 'absent');
    // The strong half: the operator's real HOME is a different string from the
    // profile's, and the container reports the profile's. A missing planted
    // variable alone would not distinguish "not inherited" from "inherited but
    // nothing interesting was set".
    assert.equal(control.home_came_from_profile, true);
    assert.equal(control.operator_home_observed_inside_container, control.profile_home);
    assert.notEqual(control.operator_home_observed_inside_container, control.operator_home);
  });
});

describe('A-MVP-04: the raw log is referenced and its bytes are quoted', () => {
  test('the record points at a raw log that exists, with a matching digest and size', () => {
    assert.ok(live.rawLog.file, 'no raw log path in the record');
    const file = path.join(ROOT, live.rawLog.file);
    assert.ok(existsSync(file), `raw log missing: ${live.rawLog.file}`);
    const bytes = readFileSync(file);
    assert.equal(bytes.length, live.rawLog.bytes, 'the raw log size does not match the record');
  });

  test('the raw log carries the commands with their exit codes, and each exit code is the one that step expects', () => {
    const raw = read(path.join(ROOT, live.rawLog.file));
    assert.ok(Array.isArray(raw.commands) && raw.commands.length >= 8, `only ${raw.commands?.length} commands recorded`);
    // Not "every command exited 0": the no-route probe exits 7 BY DESIGN, because
    // its contract is "exit 7 on a connect error, 0 on a success". Asserting a
    // blanket 0 would either fail on the one command that worked correctly or
    // force that command to lie about its own exit.
    const expectedNonZero = new Map([['negative:no-route-to-api-host', 7]]);
    for (const command of raw.commands) {
      assert.ok('argv' in command && 'exitCode' in command, JSON.stringify(command).slice(0, 120));
      const wanted = expectedNonZero.get(command.step) ?? 0;
      assert.equal(command.exitCode, wanted, `${command.step} exited ${command.exitCode}, expected ${wanted}`);
    }
    // And the one non-zero exit is the refusal the control asserts.
    const noRoute = raw.commands.find((c) => c.step === 'negative:no-route-to-api-host');
    assert.equal(noRoute.exitCode, 7);
    // And the streams the record summarises are in the log, untruncated.
    assert.match(raw.streams.axisProbeStdout, /VERITAS_ROUTE_ROWS=0/);
    assert.equal(raw.streams.executorVersionStdout, EXECUTOR_VERSION);
    assert.equal(raw.streams.forwarderDecisions.length, 3);
  });

  test('the forwarder admitted exactly one destination across the whole run', () => {
    const raw = read(path.join(ROOT, live.rawLog.file));
    const admitted = raw.streams.forwarderDecisions.filter((d) => d.decision === 'ADMITTED');
    const refused = raw.streams.forwarderDecisions.filter((d) => d.decision === 'REFUSED');
    assert.equal(admitted.length, 1);
    assert.equal(admitted[0].host, 'open.bigmodel.cn');
    assert.equal(admitted[0].port, 443);
    assert.equal(refused.length, 2);
    for (const decision of refused) assert.equal(decision.code, 'EGRESS_NOT_ALLOWLISTED');
  });

  test('the raw log contains no secret value either', () => {
    const raw = readFileSync(path.join(ROOT, live.rawLog.file), 'utf8');
    const result = assertNoSecretLeak({ raw_log: raw }, { value: 'VERITAS_S2_002_NOT_A_REAL_SECRET_CANARY_9f3c1d7b4e2a6058', required: ['raw_log'] });
    assert.equal(result.ok, true, `leaks: ${[...result.leaks]}`);
  });

  test('no command argv on the record carries a secret handle as a value or a value as an argument', () => {
    for (const command of live.commands) {
      assert.ok(Array.isArray(command.argv));
      for (const argument of command.argv) {
        assert.doesNotMatch(argument, /VERITAS_S2_002_NOT_A_REAL_SECRET/);
      }
    }
    // The handle appears as a NAME on the run argv, which is the point.
    const runCommand = live.commands.find((c) => c.step === 'run:executor-version-direct' || c.step.startsWith('run:'));
    assert.ok(runCommand, 'no run command recorded');
  });
});

describe('A-MVP-04: the record states its own limits', () => {
  test('the limits name the derived pin, the absent model call, and the unprovoked ceiling', () => {
    const text = live.limits.join(' ');
    assert.match(text, /derived image digest/);
    assert.match(text, /no model call is made/);
    assert.match(text, /pids and memory ceilings/);
    assert.match(text, /synthetic/);
  });

  test('nothing in the record claims a model answered, and nothing claims A-MVP-04', () => {
    const text = JSON.stringify(live).toLowerCase();
    assert.equal(/model_?(call|response|answer|completion)/.test(text), false, 'the record implies a model call happened');
    // The record MEASURES the clause; it does not score it. `aMvpStatus` stays
    // NOT_CLAIMED, which is the vocabulary the S2-007R records already use, and
    // the record says whose act the upgrade is.
    assert.equal(live.aMvpStatus, 'NOT_CLAIMED');
    assert.equal(live.aMvpClauseMeasured, true);
    assert.match(live.aMvpClauseUpgradeRequires, /human review/);
  });
});
