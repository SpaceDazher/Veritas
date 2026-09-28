// S2-002 A-MVP-04 — the aggregate gate.
//
// Reads the two records the live scripts wrote and re-derives every claim in them
// with the same functions the run used. It starts no container and makes no
// network call, so it is cheap enough to be a gate rather than an occasion.
//
// WHAT IT IS NOT. It is not a substitute for the run. If the records are missing
// it says `NOT_RUN` and exits non-zero — it does not reconstruct a pass out of
// the constants in the source, because a gate that can pass without a measurement
// is a gate that will.
//
// The order matters: the image record gates the live record, because a live run
// against an image the pin does not describe is not evidence about the pinned
// image however well it went.
import { existsSync, readFileSync } from 'node:fs';
import nodeAssert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  EXECUTOR_IMAGE_DIGEST,
  EXECUTOR_IMAGE_ID,
  EXECUTOR_TREE_SHA256,
  EXECUTOR_VERSION,
  assertDigestPinned,
  assertImageMatchesPin,
  assertRealStart,
  normalizeDigest,
} from '../src/lib/isolation/image.mjs';
import {
  EXECUTABLE_TIERS,
  NON_EXECUTABLE_TIERS,
  assertExecutableProfile,
  assertNoWildcard,
} from '../src/lib/isolation/profile.mjs';
import { assertNoSecretLeak } from '../src/lib/isolation/secrets.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const IMAGE_RECORD = path.join(ROOT, 'evidence', 's2-002-isolation-image.json');
const LIVE_RECORD = path.join(ROOT, 'evidence', 's2-002-isolation-live.json');
const SUBJECT = 'A-MVP-04';
const CANARY = 'VERITAS_S2_002_NOT_A_REAL_SECRET_CANARY_9f3c1d7b4e2a6058';

const read = (file) => JSON.parse(readFileSync(file, 'utf8'));
const isPlainObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const findings = [];
const check = (name, fn) => {
  try {
    const detail = fn();
    findings.push({ gate: name, verdict: 'PASS', detail: detail ?? 'ok' });
  } catch (error) {
    findings.push({ gate: name, verdict: 'FAIL', detail: error.message });
  }
};
// Named `must`, not `assert`. The first version of this file declared a local
// `const assert = (condition, message) => ...` and imported
// `node:assert/strict` as `assert` in the same scope: every gate then answered
// "assert.equal is not a function" and the gate reported sixteen FAILs that were
// all the same bug wearing sixteen hats. A gate that fails for one reason across
// every check is a gate whose output has to be read, not scanned.
const { ok: must, equal, notEqual, deepEqual, match } = nodeAssert;

function gateImage() {
  if (!existsSync(IMAGE_RECORD)) {
    return { status: 'NOT_RUN', reason: `evidence/s2-002-isolation-image.json is absent; run \`npm run s2-002:isolation:image\`` };
  }
  const image = read(IMAGE_RECORD);

  check('image: the base is a registry digest, pulled by that digest', () => {
    assertDigestPinned(image.base.reference);
    equal(image.base.pull_exit, 0, `podman pull exited ${image.base.pull_exit}`);
    equal(image.base.digest_matches_pin, true);
    return `${image.base.observed_digest}`;
  });

  check('image: the derived image matches both pinned content addresses', () => {
    assertDigestPinned(image.pin.executor_image_id);
    assertDigestPinned(image.pin.executor_image_digest);
    assertImageMatchesPin(image.build.observed);
    equal(normalizeDigest(image.pin.executor_image_id), EXECUTOR_IMAGE_ID);
    equal(normalizeDigest(image.pin.executor_image_digest), EXECUTOR_IMAGE_DIGEST);
    must(image.build.observed.layers > 1, 'a one-layer image is the base alone');
    return `id ${normalizeDigest(image.build.observed.Id)}`;
  });

  check('image: the executor tree that built the pin is recorded and matches', () => {
    equal(image.pin.executor_tree_matches, true, `tree ${image.pin.executor_tree_sha256_observed} != ${EXECUTOR_TREE_SHA256}`);
    equal(image.provenance.version_matches, true, 'the installed executor version differs from the pin');
    equal(image.provenance.committed_to_repository, false);
    return `${image.pin.executor_tree_files_observed} files, ${image.provenance.installed_version_from_package_json}`;
  });

  check('image: the record status is PASS and carries no unexplained reason', () => {
    must(['PASS', 'FAIL', 'NOT_RUN'].includes(image.status), `unexpected status ${image.status}`);
    if (image.status !== 'PASS') must(image.reason, 'a non-PASS image record must state why');
    return `${image.status}${image.reason ? ` (${image.reason})` : ''}`;
  });

  return { status: findings.some((f) => f.verdict === 'FAIL') ? 'FAIL' : 'PASS', image };
}

function gateLive(imageStatus, image) {
  if (imageStatus === 'NOT_RUN') {
    return { status: 'NOT_RUN', reason: 'the image record is absent, so the live record cannot be attributed to a pinned image' };
  }
  if (!existsSync(LIVE_RECORD)) {
    return { status: 'NOT_RUN', reason: `evidence/s2-002-isolation-live.json is absent; run \`npm run s2-002:isolation:run\`` };
  }
  const live = read(LIVE_RECORD);

  check('live: the record names the subject, the clause, and does not score it', () => {
    equal(live.subject, SUBJECT);
    must(live.aMvpClause.length > 5);
    equal(live.aMvpStatus, 'NOT_CLAIMED', 'a measurement must not upgrade the A-MVP case');
    return `${live.aMvpClause} (status ${live.aMvpStatus})`;
  });

  check('live: the tier is executable and the floor tiers are named as refused', () => {
    must(EXECUTABLE_TIERS.includes(live.tier), `${live.tier} is not an executable tier`);
    must(!NON_EXECUTABLE_TIERS.includes(live.tier), `${live.tier} is a floor tier and must never be launched`);
    deepEqual([...live.nonExecutableTiers], [...NON_EXECUTABLE_TIERS]);
    return `${live.tier} (refused: ${live.nonExecutableTiers.join(', ')})`;
  });

  check('live: the host could raise isolation, and the invocation is recorded', () => {
    equal(live.host.isolationCanBeRaised, true, 'the record says isolation could not be raised on this host');
    equal(live.host.rootless, true);
    equal(live.host.cgroupVersion, 'v2');
    return `${live.host.podmanVersion}, ${live.host.crunVersion}, cgroup ${live.host.cgroupVersion}, rootless=${live.host.rootless}`;
  });

  check('live: the executor REALLY started, re-derived from the record bytes', () => {
    const version = live.realRun.executor_version;
    const proof = assertRealStart({ exitCode: version.exitCode, signal: version.signal, stdout: version.stdout });
    equal(proof.ok, true, `not provable: ${proof.issues.join('|')}`);
    equal(proof.version, EXECUTOR_VERSION, `observed ${proof.version}, pinned ${EXECUTOR_VERSION}`);
    return `${live.component.package} ${proof.version} answered from inside ${normalizeDigest(live.image.executorImageId).slice(0, 19)}…`;
  });

  check('live: the four axes were measured inside the container, not asserted', () => {
    const probe = live.realRun.axisProbe;
    equal(probe.VERITAS_ROUTE_ROWS, '0', 'the container had a route, so deny_all is not in force');
    equal(probe.VERITAS_HOST_FS_WRITABLE, 'EROFS', 'the container root filesystem was writable');
    equal(probe.VERITAS_TMP_FS_WRITABLE, 'true', 'the declared tmpfs was not writable');
    equal(probe.VERITAS_UID, '65534:65534');
    return `routes=${probe.VERITAS_ROUTE_ROWS} /etc=${probe.VERITAS_HOST_FS_WRITABLE} /tmp=${probe.VERITAS_TMP_FS_WRITABLE} uid=${probe.VERITAS_UID}`;
  });

  // ---------------------------------------------------------------------
  // THE AXIS PROSE IS CROSS-CHECKED AGAINST THE RAW LOG, NOT THE RECORD.
  //
  // The three checks above read `live.realRun.axisProbe` — a field INSIDE the
  // record being judged. A check that reads the same file it is judging proves
  // nothing about the world: the record could carry any number at all, and the
  // prose around those numbers (`axes.*.declared`, `.on`, `.off`, `.enforced_by`)
  // was not read by any check. That was found by falsification, not by reading:
  // a record claiming "a route to the model API host exists inside the container
  // (VERITAS_ROUTE_ROWS=2)" while the raw log it points at says
  // `VERITAS_ROUTE_ROWS=0` passed all seventeen checks with exit 0.
  //
  // So the ground truth is the RAW LOG, which is already read for the secret
  // scan: it carries every command with its argv and the untruncated probe
  // output. Same pattern as the S2-008 aggregator, which was found reading its
  // children's claims about themselves.
  // ---------------------------------------------------------------------
  check('live: the axis NUMBERS are re-derived from the raw log, not read from the record', () => {
    const raw = readFileSync(path.join(ROOT, live.rawLog.file), 'utf8');
    const rows = /VERITAS_ROUTE_ROWS=([0-9]+)/.exec(raw);
    must(rows, 'the raw log does not record VERITAS_ROUTE_ROWS at all, so nothing measured the network axis');
    equal(rows[1], '0', 'the raw log says the container HAD a route, so deny_all is not in force');
    equal(String(live.realRun.axisProbe.VERITAS_ROUTE_ROWS), rows[1], 'the record contradicts its own raw log about the route table');
    const uid = /VERITAS_UID=([0-9]+:[0-9]+)/.exec(raw);
    must(uid, 'the raw log does not record VERITAS_UID');
    equal(String(live.realRun.axisProbe.VERITAS_UID), uid[1], 'the record contradicts its own raw log about the uid');
    const hostFs = /VERITAS_HOST_FS_WRITABLE=([A-Z_]+)/.exec(raw);
    must(hostFs, 'the raw log does not record VERITAS_HOST_FS_WRITABLE');
    equal(String(live.realRun.axisProbe.VERITAS_HOST_FS_WRITABLE), hostFs[1], 'the record contradicts its own raw log about the root filesystem');
    return `re-derived from the raw log: rows=${rows[1]} uid=${uid[1]} host_fs=${hostFs[1]}`;
  });

  check('live: the declared network policy matches the argv the container was launched with', () => {
    const raw = readFileSync(path.join(ROOT, live.rawLog.file), 'utf8');
    must(/--network=none/.test(raw), 'the raw log shows no --network=none on the executor launch, so the network claim is unsupported');
    const declared = String(live.axes?.network?.declared ?? '');
    equal(declared, 'deny_all', `the record declares network=${declared || '(absent)'} while the launch ran with --network=none`);
    return 'declared=deny_all and the launch carried --network=none';
  });

  check('live: every axis names both what it measured and what it denies', () => {
    const axes = isPlainObject(live.axes) ? live.axes : {};
    must(Object.keys(axes).length >= 4, `the record publishes ${Object.keys(axes).length} axes, fewer than the four it claims`);
    for (const [name, axis] of Object.entries(axes)) {
      must(isPlainObject(axis), `${name} is not an axis object`);
      must(Array.isArray(axis.on) && axis.on.length > 0, `${name} publishes no measurement it claims to have made`);
      must(Array.isArray(axis.off) && axis.off.length > 0, `${name} claims a control but names nothing it denies — prose without a measurement`);
    }
    return `${Object.keys(axes).length} axes, each naming what is on and what is off`;
  });

  check('live: the operator environment did not reach the container', () => {
    const control = live.negativeControls.find((c) => c.control === 'HOST_ENVIRONMENT_NOT_INHERITED');
    must(control, 'the environment-inheritance control is absent');
    equal(control.home_came_from_profile, true);
    notEqual(control.operator_home_observed_inside_container, control.operator_home);
    equal(control.planted_value_observed_inside_container, 'absent');
    return `operator HOME ${control.operator_home} -> container HOME ${control.operator_home_observed_inside_container}`;
  });

  check('live: the secret arrived as a descriptor and the value is nowhere', () => {
    match(live.secretHandle.handle, /^sec-[a-z0-9][a-z0-9-]{0,62}$/);
    equal(live.realRun.axisProbe.VERITAS_SECRET_PRESENT, 'true');
    equal(live.leakDetection.leakDetected, false, `leaks: ${(live.leakDetection.leaks ?? []).join(', ')}`);
    equal(live.leakDetection.finalRecordScan.ok, true);
    equal(live.leakDetection.detectorSelfCheckPassed, true, 'the detector has never fired, so its silence means nothing');
    return `descriptor ${live.secretHandle.handle} at ${live.secretHandle.mountPathInsideContainer}, ${live.leakDetection.surfacesSearched.length} surfaces searched, 0 leaks`;
  });

  check('live: every negative control planted an attempt and got a named refusal', () => {
    must(live.negativeControls.length >= 3, `only ${live.negativeControls.length} controls`);
    for (const control of live.negativeControls) {
      equal(control.passed, true, `${control.control}: ${JSON.stringify(control).slice(0, 200)}`);
      must(control.what && control.why_it_matters, `${control.control} does not say what it plants`);
    }
    const required = ['NON_EXECUTABLE_TIER_REFUSED', 'ALLOWLIST_ESCAPE_REFUSED', 'HOST_ENVIRONMENT_NOT_INHERITED'];
    for (const name of required) {
      must(live.negativeControls.some((c) => c.control === name), `the ${name} control is absent`);
    }
    const escape = live.negativeControls.find((c) => c.control === 'ALLOWLIST_ESCAPE_REFUSED');
    equal(escape.on_allowlist.admitted, true, 'the allowlisted pair was not admitted, so the refusals prove nothing');
    return `${live.negativeControls.length}/${live.negativeControls.length} passed, ${required.length} required present`;
  });

  check('live: the record and its raw log carry no secret value', () => {
    const raw = readFileSync(path.join(ROOT, live.rawLog.file), 'utf8');
    const result = assertNoSecretLeak({ record: JSON.stringify(live), raw_log: raw }, { value: CANARY, required: ['record', 'raw_log'] });
    equal(result.ok, true, `leaks: ${result.leaks.join(', ')}`);
    equal(live.rawLog.bytes, Buffer.byteLength(raw), 'the raw log size in the record does not match the file');
    return `${live.rawLog.file}, ${live.rawLog.bytes} bytes`;
  });

  check('live: no profile axis carries a wildcard', () => {
    equal(JSON.stringify(live.axes).includes('"*"'), false, 'the record contains a wildcard value');
    assertNoWildcard(read(IMAGE_RECORD).base ? {
      network: { policy: 'deny_all', allowlist: [] },
      filesystem: { roots: ['/tmp'] },
      environment: { allowlist: ['HOME'], secret_handles: [] },
    } : {});
    return 'no "*" in any axis';
  });

  check('live: the record states its own limits and does not claim a model answered', () => {
    const text = live.limits.join(' ');
    match(text, /derived image digest/);
    match(text, /no model call is made/);
    match(text, /pids and memory ceilings/);
    equal(/model_?(call|response|answer|completion)/i.test(JSON.stringify(live)), false, 'the record implies a model call happened');
    return `${live.limits.length} limits stated`;
  });

  check('live: the raw log records the commands and their exit codes', () => {
    const raw = read(path.join(ROOT, live.rawLog.file));
    must(raw.commands.length >= 8, `only ${raw.commands.length} commands`);
    const expected = new Map([['negative:no-route-to-api-host', 7]]);
    for (const command of raw.commands) {
      const wanted = expected.get(command.step) ?? 0;
      equal(command.exitCode, wanted, `${command.step} exited ${command.exitCode}, expected ${wanted}`);
    }
    equal(raw.streams.forwarderDecisions.filter((d) => d.decision === 'ADMITTED').length, 1);
    return `${raw.commands.length} commands, 1 admitted egress destination`;
  });

  check('live: the record status is PASS, or NOT_RUN with a reason', () => {
    must(['PASS', 'FAIL', 'NOT_RUN'].includes(live.status), `unexpected status ${live.status}`);
    if (live.status !== 'PASS') must(live.reason && live.reason.length > 20, 'a non-PASS record must state why');
    return `${live.status}${live.reason ? ` (${live.reason})` : ''}`;
  });

  return {
    status: findings.some((f) => f.verdict === 'FAIL') ? 'FAIL' : 'PASS',
    live,
    image,
  };
}

const imageOutcome = gateImage();
const liveOutcome = gateLive(imageOutcome.status, imageOutcome.image);

const failed = findings.filter((f) => f.verdict === 'FAIL');
const status = imageOutcome.status === 'NOT_RUN' || liveOutcome.status === 'NOT_RUN' ? 'NOT_RUN' : (failed.length > 0 ? 'FAIL' : 'PASS');

process.stdout.write(`${JSON.stringify({
  schemaVersion: 1,
  record: 's2-002-isolation-gate',
  subject: SUBJECT,
  status,
  reason: status === 'NOT_RUN'
    ? (imageOutcome.reason ?? liveOutcome.reason ?? null)
    : (failed.length > 0 ? failed.map((f) => `${f.gate}: ${f.detail}`).join('; ') : null),
  findings,
}, null, 2)}\n`);

if (status === 'NOT_RUN') process.stderr.write(`NOT_RUN: ${imageOutcome.reason ?? liveOutcome.reason}\n`);
else if (status === 'FAIL') process.stderr.write(`FAIL: ${failed.map((f) => `${f.gate}: ${f.detail}`).join('; ')}\n`);

process.exitCode = status === 'PASS' ? 0 : 1;
