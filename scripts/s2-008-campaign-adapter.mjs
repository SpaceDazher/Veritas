// S2-008 REAL CAMPAIGN — the REAL ADAPTER.
//
// A trial's measurement is produced by a genuinely installed executor running
// inside the S2-002 A-MVP-04 digest-pinned isolation profile. This file is the
// adapter: it builds the content-pinned image the executor runs in, launches it
// through `src/lib/isolation/launch.mjs` (never a hand-rolled podman argv), and
// reports exactly what came back.
//
// THE PIN, AND WHY IT IS A PIN
//   FROM is the A-MVP-04 base REGISTRY digest, unchanged. The derived image is
//   built with `--timestamp 0`: buildah stamps layers with the wall clock by
//   default, so two builds of identical bytes get different digests and the
//   "pin" is a coincidence. Zeroing the timestamp makes the digest a function of
//   content, and `verifyImagePin` re-builds and requires the identical Id and
//   Digest — the same proof A-MVP-04 makes for its own image.
//
// THE ADAPTER IS AN ADAPTER, NOT A SHELL
//   `executeIsolated` requires exit 0 AND a real start (`assertRealStart`); a
//   podman that exited 0 without starting the executor is a refusal, not a pass.
//   The container's own PID and node version come back in its stdout and are
//   recorded, so a reader can see a process ran in there rather than take it on
//   trust.
//
// WHAT THE HOST NEVER DOES
//   It never computes a prediction and never reads a label on the adapter's
//   behalf. The container is handed the BLIND bytes; the label comparison is the
//   evaluator's, inside the one-shot sealed open, after the decision point.
//
// USAGE
//   node scripts/s2-008-campaign-adapter.mjs --arm <arm_id> --seed <n> [--samples n]
//                                              [--out <file>] [--verify-pin]
//                                              [--break-image]   # the INFRA probe

import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { BASE_IMAGE, assertDigestPinned, normalizeDigest } from '../src/lib/isolation/image.mjs';
import { SANDBOX_ISOLATION_EXECUTOR } from '../src/lib/isolation/profile.mjs';
import { buildInvocation, executeIsolated, PODMAN_HOST } from '../src/lib/isolation/launch.mjs';
import { assertImageMatchesPin } from '../src/lib/isolation/image.mjs';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CORPUS_DIR = path.join(REPO_ROOT, 'corpus/s2-008-campaign');
export const IMAGE_TAG = 'localhost/veritas-s2-008-campaign:acceptance';
export const BOOTSTRAP_IMAGE_TAG = 'localhost/veritas-s2-008-campaign-bootstrap:acceptance';
const ARM_PROGRAM = 'scripts/s2-008-campaign-arm.mjs';
const BOOTSTRAP_PROGRAM = 'scripts/s2-008-campaign-bootstrap.mjs';
const IN_CONTAINER_PROGRAM = '/opt/campaign/arm.mjs';
const IN_CONTAINER_INPUT = '/opt/campaign/holdout.blind.json';

/** The host environment podman needs on THIS host. Measured, not assumed:
 *  podman 4.9.3 here rejects its own default root/runroot/runtime, which is why
 *  launch.mjs carries the same three arguments in PODMAN_HOST. */
const PODMAN_ENV = Object.freeze({
  PATH: '/tmp/bin:/usr/bin:/bin',
  XDG_RUNTIME_DIR: '/tmp/xdg-rt',
  TMPDIR: '/tmp',
  HOME: '/home/daniil',
});

function podman(args, { extraEnv = {} } = {}) {
  const prefix = [...PODMAN_HOST.argvPrefix];
  return execFileSync('podman', [...prefix, ...args], {
    encoding: 'utf8',
    maxBuffer: 1 << 28,
    env: { ...PODMAN_ENV, ...extraEnv },
  }).trim();
}

function podmanTry(args) {
  const prefix = [...PODMAN_HOST.argvPrefix];
  const run = spawnSync('podman', [...prefix, ...args], { encoding: 'utf8', maxBuffer: 1 << 28, env: PODMAN_ENV });
  return { exitCode: Number.isInteger(run.status) ? run.status : null, stdout: String(run.stdout ?? ''), stderr: String(run.stderr ?? '') };
}

/** Build the content-pinned image. The context is staged from the committed
 *  bytes: the arm program and the sealed blind input, nothing else. */
export function buildImage({ label = 'acceptance' } = {}) {
  const context = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-campaign-build-'));
  const opt = path.join(context, 'opt', 'campaign');
  fs.mkdirSync(opt, { recursive: true });
  fs.copyFileSync(path.join(REPO_ROOT, ARM_PROGRAM), path.join(opt, 'arm.mjs'));
  fs.copyFileSync(path.join(CORPUS_DIR, 'cases/holdout.blind.json'), path.join(opt, 'holdout.blind.json'));
  const containerfile = [
    '# The S2-008 real-campaign adapter image. Read-only recipe: every',
    '# instruction is a literal or a digest, nothing is passed as a build arg.',
    '# There is no RUN step; the base image already carries the runtime.',
    '#',
    '# `--timestamp 0` is what makes the derived digest a function of CONTENT.',
    '# Without it buildah stamps each layer with the wall clock, two builds of',
    '# identical bytes get different digests, and the pin is a coincidence.',
    `FROM ${BASE_IMAGE}`,
    'COPY opt/campaign /opt/campaign',
    `LABEL org.veritas.subject="S2-008-CAMPAIGN" org.veritas.label="${label}" org.veritas.program="${IN_CONTAINER_PROGRAM}" org.veritas.base.digest="sha256:25330af3531fb5e23318554a0aa911125b6e91b1b777edf7655501d207c067a2"`,
    '',
  ].join('\n');
  const file = path.join(context, 'Containerfile.campaign');
  fs.writeFileSync(file, containerfile);

  const build = podmanTry(['build', '--timestamp', '0', '--pull=never', '-f', file, '-t', IMAGE_TAG, context]);
  if (build.exitCode !== 0) {
    throw new Error(`ADAPTER_IMAGE_BUILD_FAILED exit=${String(build.exitCode)}\n${build.stderr.slice(-1200)}`);
  }
  const inspect = podman(['inspect', '--format', '{{.Id}}|{{.Digest}}|{{.Architecture}}', IMAGE_TAG]).split('|');
  // `podman inspect` reports the local Id bare on this host and the A-MVP-04
  // constants spell it with the `sha256:` prefix, so the pin is NORMALISED
  // before it is checked: comparing the two spellings as strings would refuse a
  // correct image.
  const pin = { imageId: normalizeDigest(inspect[0]), digest: normalizeDigest(inspect[1]), architecture: inspect[2] };
  assertDigestPinned(pin.imageId);
  const contextDigest = canonicalDigest({
    program_sha256: sha256Of(path.join(REPO_ROOT, ARM_PROGRAM)),
    blind_input_sha256: sha256Of(path.join(CORPUS_DIR, 'cases/holdout.blind.json')),
    containerfile_sha256: sha256Of(file),
  });
  fs.rmSync(context, { recursive: true, force: true });
  return { pin, context_digest: contextDigest, build_exit: build.exitCode };
}

export function sha256Of(file) {
  return execFileSync('sha256sum', [file], { encoding: 'utf8' }).split(/\s+/)[0];
}

/** The pin is only a pin if a rebuild reproduces it. SAME content twice, so the
 *  label is held constant: varying it would vary the content and the check would
 *  prove nothing except that two different images differ. */
export function verifyImagePin() {
  const first = buildImage({ label: 'acceptance' });
  const second = buildImage({ label: 'acceptance' });
  return {
    first: first.pin,
    second: second.pin,
    identical: first.pin.imageId === second.pin.imageId && first.pin.digest === second.pin.digest,
    context_digest_stable: first.context_digest === second.context_digest,
    context_digest: first.context_digest,
    note: 'identical content built twice with --timestamp 0 must produce the identical image Id and Digest; anything else is a coincidence, not a pin',
  };
}

/** ONE trial measurement by the real installed executor.
 *  @returns {{ok: boolean, observation: object, output: object|null, record: object}} */
/**
 * PERSIST THE PER-CASE PREDICTIONS. Before this, a run record carried the arm's
 * aggregate count, its interval and a digest of the arm's output — and a digest
 * pins WHICH output without letting anyone re-score it. For a regex arm the
 * evaluator re-derives the predictions and checks the count, so a self-reported
 * number is not load-bearing. For a MODEL arm there is nothing to re-derive: the
 * only source of the predictions is the executor, so a count the executor reported
 * about itself is exactly the "record asserts itself" shape this repository has now
 * paid to remove three times. A third party must be able to take the predictions,
 * the corpus labels, and get the number themselves.
 *
 * They go to a SIDECAR rather than into the governed run record: 126 rows x 3 seeds
 * x 3 arms would bloat a record whose size other records pin. The binding runs the
 * other way — the record names the sidecar's digest — so a tampered prediction
 * file cannot be passed off as this run's.
 */
export function persistPredictions({ output, armId, seed, runLabel, sink }) {
  const rows = Array.isArray(output?.predictions) ? output.predictions : null;
  if (rows === null || typeof sink !== 'function' || runLabel === null || runLabel === undefined) return null;
  const body = {
    kind: 's2-008-campaign-predictions/1',
    run: String(runLabel),
    arm_id: armId,
    // The arm's own accounting beside the rows it produced, so a reader can see how
    // many answers were unusable without trusting the count.
    unparsed: rows.filter((row) => String(row?.predicted ?? '') === 'UNPARSED').length,
    model_calls: output?.executor?.model_calls ?? null,
    spent_tokens: output?.budget?.spent_tokens ?? null,
    usd_spent: output?.budget?.usd_spent ?? null,
    outcome_class: output?.outcome_class ?? null,
    rows: rows.map((row) => ({ case_id: String(row?.case_id ?? ''), predicted: String(row?.predicted ?? '') })),
  };
  const digest = canonicalDigest(body);
  sink(digest, body);
  return Object.freeze({ digest, rows: body.rows.length, unparsed: body.unparsed });
}

export function runTrial({ armId, seed, samples, timeoutMs, pin, breakImage = false, predictionsSink = null, runLabel = null }) {
  const image = breakImage
    // The INFRA probe: a digest that is syntactically a pin and is not on this
    // host. podman is told `--pull=never`, so the launch fails for real.
    ? 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    : pin.imageId;
  const invocation = buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
    image,
    argv: [
      '/usr/local/bin/node',
      IN_CONTAINER_PROGRAM,
      IN_CONTAINER_INPUT,
      // The container's own writable root. The root filesystem is read-only, so
      // this is the ONLY place the program may write, and the profile says so.
      '/tmp/campaign-out.json',
      armId,
      String(seed),
      String(samples),
    ],
    timeoutMs,
    name: `s2-008-campaign-${armId}-${seed}`,
  });
  const observation = executeIsolated(invocation);
  const lines = observation.stdout.split('\n');
  const banner = lines.find((entry) => entry.startsWith('ADAPTER_OK')) ?? null;
  // The payload arrives as numbered base64 chunks. The `n/total` in each chunk
  // header and the terminating length line are both checked, so a SHORT read is
  // a refusal rather than a JSON parse error that looks like corruption.
  const chunks = lines.filter((entry) => entry.startsWith('ADAPTER_JSON '));
  const endLine = lines.find((entry) => entry.startsWith('ADAPTER_JSON_END ')) ?? null;
  let output = null;
  let payloadError = null;
  try {
    if (chunks.length === 0) throw new Error('no payload chunks');
    const declared = chunks.map((entry) => /^ADAPTER_JSON (\d+)\/(\d+) (.*)$/.exec(entry)).map((match) => ({ index: Number(match[1]), total: Number(match[2]), body: match[3] }));
    const totals = [...new Set(declared.map((entry) => entry.total))];
    if (totals.length !== 1) throw new Error(`chunks disagree on their count: ${totals.join(',')}`);
    if (declared.length !== totals[0]) throw new Error(`${declared.length} chunks for a declared ${totals[0]}`);
    if (declared.some((entry, position) => entry.index !== position + 1)) throw new Error('chunk indices are not 1..n in order');
    const joined = declared.map((entry) => entry.body).join('');
    if (endLine === null) throw new Error('no ADAPTER_JSON_END line: the payload was cut short');
    if (Number(endLine.split(' ')[1]) !== joined.length) throw new Error(`payload is ${joined.length} chars, the container declared ${String(endLine.split(' ')[1])}`);
    output = JSON.parse(Buffer.from(joined, 'base64').toString('utf8'));
  } catch (error) {
    payloadError = String(error?.message ?? error);
  }
  const predictions = persistPredictions({ output, armId, seed, runLabel, sink: predictionsSink });
  return {
    ok: observation.exitCode === 0 && output !== null,
    observation,
    output,
    record: {
      arm_id: armId,
      seed,
      samples,
      podman: { executable: invocation.executable, argv_prefix: [...PODMAN_HOST.argvPrefix] },
      container_argv: [...invocation.podmanArgv],
      image: invocation.image,
      image_break_requested: breakImage,
      axes: invocation.axes,
      exit_code: observation.exitCode,
      signal: observation.signal,
      timed_out: observation.timedOut,
      stderr_excerpt: observation.stderr.slice(-400),
      banner,
      payload_chunks: chunks.length,
      payload_error: payloadError,
      output_digest: output === null ? null : canonicalDigest(output),
      // What a third party needs to re-score this seed without the executor. Null for an
      // arm that recorded no per-case rows — a fact the record states rather than
      // leaves to be inferred.
      predictions: predictions === null ? null : { digest: predictions.digest, rows: predictions.rows, unparsed: predictions.unparsed },
      // A run that did not start is not a run. Two independent predicates,
      // because the A-MVP-04 one does not apply to this program:
      //
      //   * `assertImageMatchesPin` IS the isolation tree's own check and is
      //     used verbatim: an observation of some other image says nothing
      //     about the pinned one.
      //   * `assertRealStart` is keyed to the STARTUP_PROBE — a version shape
      //     printed by the pi CLI, which is the executor A-MVP-04 pins. This
      //     campaign's adapter is a DIFFERENT installed program, so that probe
      //     is not applicable to it and forcing a version string out of the
      //     program to satisfy it would be gaming the detector. It is recorded
      //     as NOT_APPLICABLE with the reason, and the start is proved by the
      //     predicate below instead: exit 0, the container's own banner, a
      //     container PID that is not the host's, and a node version the
      //     container reported about itself.
      real_start: (() => {
        if (breakImage) return { proven: false, note: 'the INFRA probe names an image that is not on this host; no start is expected' };
        const issues = [];
        try { assertImageMatchesPin({ Id: invocation.image, Digest: pin.digest, Architecture: pin.architecture }, { imageId: pin.imageId, digest: pin.digest, architecture: pin.architecture }); }
        catch (error) { issues.push(`pin:${String(error?.message ?? error)}`); }
        if (observation.exitCode !== 0) issues.push(`exitCode:${String(observation.exitCode)}`);
        if (banner === null) issues.push('no_banner');
        const pidMatch = banner === null ? null : /pid=(\d+)/.exec(banner);
        if (pidMatch === null || Number(pidMatch[1]) < 1) issues.push('no_container_pid');
        if (banner !== null && !/node=v\d+\./.test(banner)) issues.push('no_container_runtime_version');
        if (output === null) issues.push('no_payload');
        if (output !== null && output.container?.pid !== Number(pidMatch?.[1] ?? -1)) issues.push('payload_pid_mismatch');
        return {
          proven: issues.length === 0,
          issues,
          container_pid: pidMatch === null ? null : Number(pidMatch[1]),
          host_pid: process.pid,
          separate_process: pidMatch !== null && Number(pidMatch[1]) !== process.pid,
          container_runtime_version: output?.container?.node_version ?? null,
          pin_rechecked_by: 'src/lib/isolation/image.mjs#assertImageMatchesPin',
          a_mvp_04_start_probe: 'NOT_APPLICABLE: assertRealStart keys on the pi CLI version shape that A-MVP-04 pins; this adapter is a different installed program and is not asked to impersonate that one',
        };
      })(),
    },
  };
}

/** The BOOTSTRAP image. It is built from the agreement vectors, so its digest is
 *  a function of the measurement it computes: a reader can tell which
 *  measurement an interval came from by the image alone. A separate image
 *  rather than a second program in the first, because the first must never hold
 *  a label and this one must. */
export function buildBootstrapImage({ agreementFile, samples, confidence }) {
  const context = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-campaign-bootstrap-'));
  const opt = path.join(context, 'opt', 'campaign');
  fs.mkdirSync(opt, { recursive: true });
  fs.copyFileSync(path.join(REPO_ROOT, BOOTSTRAP_PROGRAM), path.join(opt, 'bootstrap.mjs'));
  fs.copyFileSync(agreementFile, path.join(opt, 'agreement.json'));
  const containerfile = [
    '# The S2-008 campaign BOOTSTRAP image. Post-reveal, content-pinned: the',
    '# agreement vectors it resamples are COPYed in, so the image digest names',
    '# the measurement the interval belongs to.',
    `FROM ${BASE_IMAGE}`,
    'COPY opt/campaign /opt/campaign',
    `LABEL org.veritas.subject="S2-008-CAMPAIGN-BOOTSTRAP" org.veritas.program="/opt/campaign/bootstrap.mjs" org.veritas.samples="${String(samples)}" org.veritas.confidence="${String(confidence)}" org.veritas.base.digest="sha256:25330af3531fb5e23318554a0aa911125b6e91b1b777edf7655501d207c067a2"`,
    '',
  ].join('\n');
  const file = path.join(context, 'Containerfile.bootstrap');
  fs.writeFileSync(file, containerfile);
  const build = podmanTry(['build', '--timestamp', '0', '--pull=never', '-f', file, '-t', BOOTSTRAP_IMAGE_TAG, context]);
  if (build.exitCode !== 0) throw new Error(`BOOTSTRAP_IMAGE_BUILD_FAILED exit=${String(build.exitCode)}\n${build.stderr.slice(-1200)}`);
  const inspect = podman(['inspect', '--format', '{{.Id}}|{{.Digest}}|{{.Architecture}}', BOOTSTRAP_IMAGE_TAG]).split('|');
  const pin = { imageId: normalizeDigest(inspect[0]), digest: normalizeDigest(inspect[1]), architecture: inspect[2] };
  assertDigestPinned(pin.imageId);
  const out = {
    pin,
    context_digest: canonicalDigest({
      program_sha256: sha256Of(path.join(REPO_ROOT, BOOTSTRAP_PROGRAM)),
      agreement_sha256: sha256Of(agreementFile),
      containerfile_sha256: sha256Of(file),
    }),
  };
  fs.rmSync(context, { recursive: true, force: true });
  return out;
}

/** The one post-reveal launch. It never predicted anything, so it is handed the
 *  agreement vectors rather than the labels. */
export function runBootstrap({ agreementFile, samples, confidence, timeoutMs, pin, breakImage = false }) {
  const image = breakImage
    ? 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    : pin.imageId;
  const invocation = buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
    image,
    argv: ['/usr/local/bin/node', '/opt/campaign/bootstrap.mjs', '/opt/campaign/agreement.json', '/tmp/bootstrap-out.json'],
    timeoutMs,
    name: 's2-008-campaign-bootstrap',
  });
  const observation = executeIsolated(invocation);
  const lines = observation.stdout.split('\n');
  const banner = lines.find((entry) => entry.startsWith('BOOTSTRAP_OK')) ?? null;
  const chunks = lines.filter((entry) => entry.startsWith('ADAPTER_JSON '));
  const endLine = lines.find((entry) => entry.startsWith('ADAPTER_JSON_END ')) ?? null;
  let output = null;
  let payloadError = null;
  try {
    const declared = chunks.map((entry) => /^ADAPTER_JSON (\d+)\/(\d+) (.*)$/.exec(entry)).map((match) => ({ index: Number(match[1]), total: Number(match[2]), body: match[3] }));
    const totals = [...new Set(declared.map((entry) => entry.total))];
    if (totals.length !== 1) throw new Error(`chunks disagree on their count: ${totals.join(',')}`);
    if (declared.length !== totals[0]) throw new Error(`${declared.length} chunks for a declared ${String(totals[0])}`);
    if (declared.some((entry, position) => entry.index !== position + 1)) throw new Error('chunk indices are not 1..n in order');
    const joined = declared.map((entry) => entry.body).join('');
    if (endLine === null) throw new Error('no ADAPTER_JSON_END line: the payload was cut short');
    if (Number(endLine.split(' ')[1]) !== joined.length) throw new Error(`payload is ${String(joined.length)} chars, the container declared ${String(endLine.split(' ')[1])}`);
    output = JSON.parse(Buffer.from(joined, 'base64').toString('utf8'));
  } catch (error) {
    payloadError = String(error?.message ?? error);
  }
  return {
    ok: observation.exitCode === 0 && output !== null,
    observation,
    output,
    record: {
      role: 'bootstrap',
      podman: { executable: invocation.executable, argv_prefix: [...PODMAN_HOST.argvPrefix] },
      container_argv: [...invocation.podmanArgv],
      image: invocation.image,
      image_break_requested: breakImage,
      axes: invocation.axes,
      exit_code: observation.exitCode,
      timed_out: observation.timedOut,
      stderr_excerpt: observation.stderr.slice(-400),
      banner,
      payload_chunks: chunks.length,
      payload_error: payloadError,
      output_digest: output === null ? null : canonicalDigest(output),
      real_start: (() => {
        if (breakImage) return { proven: false, note: 'the INFRA probe names an image that is not on this host' };
        const issues = [];
        try { assertImageMatchesPin({ Id: invocation.image, Digest: pin.digest, Architecture: pin.architecture }, { imageId: pin.imageId, digest: pin.digest, architecture: pin.architecture }); }
        catch (error) { issues.push(`pin:${String(error?.message ?? error)}`); }
        if (observation.exitCode !== 0) issues.push(`exitCode:${String(observation.exitCode)}`);
        if (banner === null) issues.push('no_banner');
        const pidMatch = banner === null ? null : /pid=(\d+)/.exec(banner);
        if (pidMatch === null || Number(pidMatch[1]) < 1) issues.push('no_container_pid');
        if (output === null) issues.push('no_payload');
        return { proven: issues.length === 0, issues, container_pid: pidMatch === null ? null : Number(pidMatch[1]), host_pid: process.pid };
      })(),
    },
  };
}

function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2).replace(/[-_](\w)/g, (_m, c) => c.toUpperCase());
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) args[key] = true;
    else { args[key] = next; index += 1; }
  }
  return args;
}

const args = parseArgs(process.argv);
// Imported by the campaign driver, which needs the functions and not the
// banner; the CLI block only runs when this file IS the entry point.
const isEntry = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (!isEntry) {
  // imported as a library
} else if (args.verifyPin) {
  console.log(JSON.stringify(verifyImagePin(), null, 2));
} else if (args.arm) {
  const prereg = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'preregistration.json'), 'utf8'));
  const { pin } = buildImage();
  const result = runTrial({
    armId: String(args.arm),
    seed: Number(args.seed ?? prereg.seed_rule.seeds[0]),
    samples: Number(args.samples ?? prereg.noise_rule.bootstrap_samples),
    timeoutMs: Number(args.timeoutMs ?? prereg.budget_reservation.trial_timeout_ms),
    pin,
    breakImage: args.breakImage === true,
  });
  console.log(JSON.stringify({ ...result.record, ok: result.ok, output: result.output }, null, 2));
  if (!result.ok && !args.breakImage) process.exitCode = 1;
} else {
  console.log(JSON.stringify({ usage: 'node scripts/s2-008-campaign-adapter.mjs --arm <id> --seed <n> | --verify-pin | --break-image', podman_host: PODMAN_HOST, profile_id: SANDBOX_ISOLATION_EXECUTOR.profile_id }, null, 2));
}
