// S2-002 A-MVP-04 — the launch, and the proof that it happened.
//
// This module is the only place that turns a profile into a process. Its whole
// job is that nothing reaches a container except what the profile named, and
// that what came back is enough to say the container ran.
//
// FOUR AXES → FOUR SETS OF FLAGS, ONE FIELD EACH
//
//   network     `--network=none` for deny_all. For `allowlist`, still
//               `--network=none`, plus a bind-mounted forwarder socket: the
//               kernel grants nothing, the forwarder grants the named
//               destinations. A profile that names a host it does not get is
//               therefore impossible to express, which is the property that
//               makes the axis real rather than declared.
//   filesystem  `--read-only`, `--tmpfs` for the declared writable roots, and
//               `--mount` for each declared root. Not-listed is not-writable,
//               because the root itself is read-only.
//   environment `--env` for each name in the allowlist, all values literals
//               owned by the profile, and nothing else. There is no
//               `...process.env` in this file, and that absence is the
//               guarantee.
//   process     `--pids-limit`, `--memory`, `--memory-swap`, `--cpus` from the
//               profile's ceilings, and `timeout` from `process.timeout_ms`.
//
// The argv is a frozen array and there is no shell: `spawnSync` with
// `shell: false` and a non-string element is a TypeError rather than an
// injection.
import { spawnSync } from 'node:child_process';
import {
  CONTAINER_USER,
  assertExecutableProfile,
  assertSecretHandleId,
  buildEnvironment,
} from './profile.mjs';
import { assertDigestPinned, assertImageMatchesPin, assertRealStart } from './image.mjs';

export const LAUNCH_ERRORS = Object.freeze({
  ARGV_INVALID: 'ISOLATION_ARGV_INVALID',
  ARGV_TOO_LONG: 'ISOLATION_ARGV_TOO_LONG',
  EXIT_NOT_OBSERVED: 'ISOLATION_EXIT_NOT_OBSERVED',
  REAL_START_UNPROVEN: 'ISOLATION_REAL_START_UNPROVEN',
  PODMAN_STATUS_UNKNOWN: 'ISOLATION_PODMAN_STATUS_UNKNOWN',
});

const MAX_OUTPUT_BYTES = 128 * 1024;
const MAX_ARG_BYTES = 8 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * How podman is reached on this host.
 *
 * Measured, and deliberately NOT assumed: podman 4.9.3 on this host rejects its
 * own defaults (`Error: default OCI runtime "crun" not found: invalid argument`
 * for both crun and runc), so the working invocation is
 * `podman --root /tmp/podman-root --runroot /tmp/podman-runroot --runtime
 * /usr/bin/crun`. The path and those three arguments are configuration, and the
 * record stores what was actually used, so a run on a host with different
 * defaults reports different values instead of claiming the same ones.
 */
export const PODMAN_HOST = Object.freeze({
  executable: 'podman',
  argvPrefix: Object.freeze([
    '--root', '/tmp/podman-root',
    '--runroot', '/tmp/podman-runroot',
    '--runtime', '/usr/bin/crun',
  ]),
  boundary: 'WSL2_ROOTLESS_PODMAN_DIRECT',
  note: 'podman 4.9.3 rejects its default root/runroot/runtime on this host; the prefix above is the measured working invocation and is recorded, not assumed',
});

export function validateArgv(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.length > 64) {
    throw new Error(LAUNCH_ERRORS.ARGV_INVALID);
  }
  for (const [index, argument] of argv.entries()) {
    if (typeof argument !== 'string' || argument.length === 0
      || argument.includes('\0') || argument.length > 4096
      || (index === 0 && argument.length === 0)) {
      throw new Error(`${LAUNCH_ERRORS.ARGV_INVALID}:${index}`);
    }
  }
  const total = argv.reduce((sum, argument) => sum + Buffer.byteLength(argument), 0);
  if (total > MAX_ARG_BYTES) throw new Error(LAUNCH_ERRORS.ARGV_TOO_LONG);
  return Object.freeze([...argv]);
}

/**
 * Build the podman argv for one launch. Pure: it takes a profile, an argv and
 * the handles, and returns an object. Nothing here spawns, reads the clock or
 * touches the filesystem, so a test can assert on the exact flags without a
 * container, and a diff of the flags is a reviewable statement of what the
 * profile meant.
 *
 * @param {object} profile
 * @param {{argv: string[], image: string, secretHandles?: string[], egressSocketPath?: string|null,
 *          workdir?: string, name?: string, timeoutMs?: number}} request
 */
export function buildInvocation(profile, request) {
  assertExecutableProfile(profile);
  if (!request || typeof request !== 'object') throw new Error(`${LAUNCH_ERRORS.ARGV_INVALID}:request`);
  const image = assertDigestPinned(request.image);
  const argv = validateArgv(request.argv);
  const declared = new Set(profile.environment.secret_handles);
  const handles = request.secretHandles ?? [];
  for (const handle of handles) {
    assertSecretHandleId(handle);
    if (!declared.has(handle)) {
      // A handle the profile did not declare is refused here rather than being
      // mounted "just this once". The profile is the authority on which
      // credentials this tier may ever see.
      throw new Error(`${LAUNCH_ERRORS.ARGV_INVALID}:handle-not-declared:${handle}`);
    }
  }
  // The credential, if this run delivers one. A DECLARED handle is required: a
  // credential with no descriptor would put a value on this host with nothing on
  // record to say what it was, which is the leak A-MVP-04 was built to prevent.
  const credential = request.credential ?? null;
  if (credential !== null) {
    assertSecretHandleId(credential.handle);
    if (!declared.has(credential.handle)) {
      throw new Error(`${LAUNCH_ERRORS.ARGV_INVALID}:credential-handle-not-declared:${credential.handle}`);
    }
    if (typeof credential.envFilePath !== 'string' || credential.envFilePath.length === 0) {
      throw new Error(`${LAUNCH_ERRORS.ARGV_INVALID}:credential-env-file-path-required`);
    }
  }
  const credentialEnvFilePath = credential === null ? null : credential.envFilePath;

  const f = profile.filesystem;
  const p = profile.process;
  const networkPolicy = profile.network.policy;
  const egressSocketPath = networkPolicy === 'allowlist' ? request.egressSocketPath : null;
  if (networkPolicy === 'allowlist' && typeof egressSocketPath !== 'string') {
    throw new Error(`${LAUNCH_ERRORS.ARGV_INVALID}:egressSocketPath-required-for-allowlist`);
  }

  const podmanArgv = [
    'run', '--rm', '--pull=never',
    // --- network axis: the kernel grants nothing in both policies ---
    '--network=none',
    // --- filesystem axis: root read-only, declared tmpfs, declared mounts ---
    '--read-only',
    ...(f.writable_tmpfs ?? []).flatMap((root) => [
      `--tmpfs=${root}:rw,noexec,nosuid,nodev,size=16m`,
    ]),
    ...(request.workdir ? ['--workdir', request.workdir] : []),
    // --- process axis: ceilings from the profile, not descriptions ---
    '--pids-limit', String(p.max_processes),
    '--memory', `${p.memory_mb}m`,
    '--memory-swap', `${(p.memory_swap_mb ?? p.memory_mb)}m`,
    '--cpus', String((p.nano_cpus ?? 500_000_000) / 1e9),
    // --- environment axis: the allowlist, and nothing inherited ---
    ...buildEnvironment(profile).flatMap((pair) => ['--env', pair]),
    // --- the rest of the LOCAL_RESTRICTED controls ---
    '--cap-drop', 'all',
    '--security-opt', 'no-new-privileges',
    '--ipc=none',
    '--user', CONTAINER_USER,
    '--log-driver=none',
    // --- secret handles: names only, no values, no paths ---
    ...handles.flatMap((handle) => ['--secret', handle]),
    // --- the credential bridge: a PATH, never a NAME=VALUE pair. `--env NAME=value`
    // would put the value in the argv of podman on this host, where a process list
    // can read it; `--env-file` passes a path to a 0600 file the caller unlinks in a
    // finally. Neither the value nor the env NAME the executor reads is in the argv.
    ...(credentialEnvFilePath ? ['--env-file', credentialEnvFilePath] : []),
    // --- the allowlist's only exit, when the profile asked for one ---
    ...(egressSocketPath ? ['--mount', `type=bind,src=${egressSocketPath},dst=/run/egress.sock`] : []),
    ...(request.name ? ['--name', request.name] : []),
    image,
    ...argv,
  ];

  return Object.freeze({
    executable: PODMAN_HOST.executable,
    argv: Object.freeze([...PODMAN_HOST.argvPrefix, ...podmanArgv]),
    podmanArgv: Object.freeze(podmanArgv),
    image,
    timeoutMs: Number.isInteger(request.timeoutMs) ? request.timeoutMs : (p.timeout_ms ?? DEFAULT_TIMEOUT_MS),
    // Declared here so the record can state the axis without re-deriving it.
    axes: Object.freeze({
      network: Object.freeze({
        policy: networkPolicy,
        flag: '--network=none',
        allowlist: profile.network.allowlist.map((entry) => ({
          host: entry.host, ports: [...entry.ports],
        })),
        egressSocket: egressSocketPath,
      }),
      filesystem: Object.freeze({
        rootFsReadOnly: f.root_fs_read_only === true,
        writableTmpfs: [...(f.writable_tmpfs ?? [])],
        mounts: (request.workdir && request.workdir !== '/' ? [request.workdir] : []).concat(egressSocketPath ? ['/run/egress.sock'] : []),
        denyLinkEscape: f.deny_link_escape === true,
        denyTraversal: f.deny_traversal === true,
      }),
      environment: Object.freeze({
        inherited: false,
        allowlist: [...profile.environment.allowlist],
        pairs: buildEnvironment(profile),
        secretHandles: [...handles],
      }),
      process: Object.freeze({
        maxProcesses: p.max_processes,
        memoryMb: p.memory_mb,
        memorySwapMb: p.memory_swap_mb ?? p.memory_mb,
        nanoCpus: p.nano_cpus ?? 500_000_000,
        timeoutMs: Number.isInteger(request.timeoutMs) ? request.timeoutMs : (p.timeout_ms ?? DEFAULT_TIMEOUT_MS),
      }),
    }),
  });
}

/**
 * Spawn the invocation and report exactly what came back.
 *
 * `exitCode` is `null` when the process was signalled or never reported a
 * status, and it is passed through as `null` rather than being coerced to
 * something comparable. That distinction is the reason `assertRealStart` can
 * insist on `Number.isInteger` before it compares to 0: `assert.ok(null === 0)`
 * is false but `assert.ok(!null)` is true, and the second one is how a
 * never-started run gets reported as a clean one.
 */
export function executeIsolated(invocation, { spawnSyncImpl = spawnSync, env = undefined } = {}) {
  const run = spawnSyncImpl(invocation.executable, invocation.argv, {
    encoding: 'utf8',
    maxBuffer: MAX_OUTPUT_BYTES,
    timeout: invocation.timeoutMs,
    windowsHide: true,
    shell: false,
    // The child's OWN environment is the empty one podman was started with, so
    // nothing of this operator's session can reach the launcher. The container's
    // environment is then built from the profile inside `buildInvocation`.
    env: env ?? { PATH: '/usr/bin:/bin', HOME: '/tmp', XDG_RUNTIME_DIR: '/tmp/xdg-rt' },
  });
  const stdout = String(run?.stdout ?? '').slice(0, MAX_OUTPUT_BYTES);
  const stderr = String(run?.stderr ?? '').slice(0, MAX_OUTPUT_BYTES);
  return Object.freeze({
    exitCode: Number.isInteger(run?.status) ? run.status : null,
    signal: run?.signal ?? null,
    timedOut: run?.error?.code === 'ETIMEDOUT',
    errorCode: run?.error?.code ?? null,
    stdout,
    stderr,
    image: invocation.image,
    axes: invocation.axes,
  });
}

/**
 * The gate between "podman exited 0" and "the executor started".
 *
 * It also re-checks the pin, because an observation whose image is not the
 * pinned image says nothing about the pinned image, whatever its exit code.
 */
export function assertGovernedRun({ observation, pin, profile }) {
  assertExecutableProfile(profile);
  const proof = assertRealStart(observation);
  if (!proof.ok) {
    throw new Error(`${LAUNCH_ERRORS.REAL_START_UNPROVEN}:${proof.issues.join('|')}`);
  }
  if (pin) assertImageMatchesPin(pin);
  return Object.freeze({
    realStartProven: true,
    executorVersionObserved: proof.version,
    exitCode: observation.exitCode,
    signal: observation.signal,
  });
}
