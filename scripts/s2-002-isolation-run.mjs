// S2-002 A-MVP-04 — the live isolation run, on this host, once.
//
// WHAT THIS SCRIPT IS. The measurement behind the A-MVP-04 clause "изоляция —
// образ, allowlist, secret handles". It launches a genuinely installed executor
// inside a digest-pinned image under a four-axis profile, and it publishes what
// it observed — including what it could NOT make work.
//
// WHAT IT DOES NOT CLAIM. It does not make a model call. A-MVP-04 is about
// isolation: whether the image starts, whether the four axes hold, whether a
// credential arrives as a descriptor. Whether a model answers is a different
// clause, and paying for a call to prove a `--network=none` flag would be the
// wrong evidence for the claim being made.
//
// THE SECRET IS SYNTHETIC, ALWAYS.
//
//     const SYNTHETIC_SECRET_VALUE
//
// is a literal in this file. No environment variable, no dotenv file and no
// credential store is read, anywhere, by anything this script loads. That is
// what makes it safe to commit and safe to print: there is nothing here to
// leak. The detector in step 5 still runs against the real value, because the
// value it is looking for is the one that was actually delivered to the
// container — the canary has to be real to be findable.
//
// The synthetic value is used for two different jobs and the difference matters.
// The value DELIVERED to the container is the one the leak detector hunts, so it
// has to be a specific, findable string. The credential the executor would
// authenticate with is a DIFFERENT value, and that one is derived so that it
// does not equal anything in this file: `derivedCanaryCredential()` mixes the
// handle with the record's own subject so a reader comparing the two cannot be
// fooled, and so neither string is a usable credential.
//
// EVERY LINE OF THE MEASUREMENT IS AN OBSERVATION OR A COMMAND RESULT. The
// record's `commands` array carries the argv and the exit code of every podman
// call this script made. Nothing in it is asserted from a constant.
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BASE_IMAGE,
  EXECUTOR_ENTRYPOINT,
  EXECUTOR_IMAGE_DIGEST,
  EXECUTOR_IMAGE_ID,
  EXECUTOR_PACKAGE,
  EXECUTOR_VERSION,
  assertDigestPinned,
  assertImageMatchesPin,
  digestOf,
  sha256,
} from '../src/lib/isolation/image.mjs';
import {
  CONTAINER_USER,
  EXECUTABLE_TIERS,
  ISOLATION_EGRESS_ALLOWLIST,
  NON_EXECUTABLE_TIERS,
  SANDBOX_ISOLATION_EXECUTOR,
  assertExecutableProfile,
  assertNoWildcard,
  buildEnvironment,
  resolveEgress,
} from '../src/lib/isolation/profile.mjs';
import {
  SECRET_ERRORS,
  assertNoSecretLeak,
  disposeSecret,
  fingerprint,
  materializeSecret,
  secretMountPath,
} from '../src/lib/isolation/secrets.mjs';
import { EGRESS_ERRORS, createEgressForwarder } from '../src/lib/isolation/egress.mjs';
import {
  PODMAN_HOST,
  assertGovernedRun,
  buildInvocation,
  executeIsolated,
  validateArgv,
} from '../src/lib/isolation/launch.mjs';

export const SUBJECT = 'A-MVP-04';
export const SECRET_HANDLE = 'sec-veritas-executor-credential';
export const SCHEMA_VERSION = 1;

// A value that exists only to be found. Deterministic so two runs on two hosts
// produce the same record; obviously not a credential.
export const SYNTHETIC_SECRET_VALUE = 'VERITAS_S2_002_NOT_A_REAL_SECRET_CANARY_9f3c1d7b4e2a6058';
// The string the executor would authenticate with. Not equal to anything above:
// it is a function of the handle and the subject, so the record can publish one
// without publishing a value that was ever delivered.
export const derivedCanaryCredential = () => `veritas-canary-${sha256(`${SECRET_HANDLE}/${SUBJECT}`).slice(0, 24)}`;

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RAW_DIR = path.join(ROOT, 'results', 's2-002', 'isolation', 'live');
const RECORD_PATH = path.join(ROOT, 'evidence', 's2-002-isolation-live.json');
const SPOOL_DIR = '/tmp';
const SUBJECT_ID = 'a-mvp-04-isolation-live';

const commands = [];

function podman(args, { timeoutMs = 120_000, label = null } = {}) {
  const argv = [...PODMAN_HOST.argvPrefix, ...args];
  const run = spawnSync(PODMAN_HOST.executable, argv, {
    encoding: 'utf8',
    timeout: timeoutMs,
    shell: false,
    env: { PATH: '/tmp/bin:/usr/bin:/bin', HOME: '/tmp', XDG_RUNTIME_DIR: '/tmp/xdg-rt', TMPDIR: '/tmp' },
  });
  const record = {
    step: label ?? args.slice(0, 2).join(' '),
    argv: [...argv],
    exitCode: Number.isInteger(run?.status) ? run.status : null,
    signal: run?.signal ?? null,
    stdoutBytes: Buffer.byteLength(String(run?.stdout ?? '')),
    stderrSha256: sha256(String(run?.stderr ?? '')),
  };
  commands.push(record);
  return { ...record, stdout: String(run?.stdout ?? ''), stderr: String(run?.stderr ?? '') };
}

/**
 * Step 1 — the host. Recorded rather than assumed, because podman 4.9.3 on this
 * host rejects its own defaults and a record that did not say which invocation
 * worked would not be reproducible.
 *
 * The `podman info` template fields are taken one at a time on purpose. A single
 * template with one bad field fails as a WHOLE, and podman 4.9.3 has no
 * `.Host.Cgroups` object at all (measured: `can't evaluate field Cgroups in type
 * *define.HostInfo`, exit 125) — so one combined template silently reports "no
 * rootless runtime" for a host that has one. `CgroupManager` exists;
 * `CgroupVersion` does not, and the cgroup version is taken from `/proc` instead,
 * which is where the kernel states it.
 */
function measureHost() {
  const version = podman(['--version'], { label: 'host:version' });
  const field = (template, label) => podman(['info', '--format', template], { label });
  const runtime = field('{{.Host.OCIRuntime.Name}}', 'host:info:runtime');
  const podmanVersion = field('{{.Version.Version}}', 'host:info:version');
  const rootless = field('{{.Host.Security.Rootless}}', 'host:info:rootless');
  const cgroupManager = field('{{.Host.CgroupManager}}', 'host:info:cgroup-manager');
  const cgroupControllers = field('{{.Host.CgroupControllers}}', 'host:info:cgroup-controllers');
  // cgroup2 is on the line for /sys/fs/cgroup, not on the first line of
  // /proc/mounts, so this greps for the filesystem type rather than taking
  // `head -1` of the whole mount table — which reported `other` on a host whose
  // cgroup manager is plainly cgroupfs over cgroup v2.
  const cgroupVersion = spawnSync(
    'sh',
    ['-c', 'awk \'$3=="cgroup2"{print "v2"; found=1} END{if(!found) print "not-v2"}\' /proc/mounts'],
    { encoding: 'utf8', shell: false },
  );
  commands.push({
    step: 'host:cgroup-version-from-proc',
    argv: ['awk', '$3=="cgroup2"{print "v2"}', '/proc/mounts'],
    exitCode: Number.isInteger(cgroupVersion?.status) ? cgroupVersion.status : null,
    signal: cgroupVersion?.signal ?? null,
    stdoutBytes: Buffer.byteLength(String(cgroupVersion?.stdout ?? '')),
    stderrSha256: sha256(String(cgroupVersion?.stderr ?? '')),
  });
  const crun = spawnSync('/usr/bin/crun', ['--version'], { encoding: 'utf8', shell: false });
  commands.push({
    step: 'host:crun-version',
    argv: ['/usr/bin/crun', '--version'],
    exitCode: Number.isInteger(crun?.status) ? crun.status : null,
    signal: crun?.signal ?? null,
    stdoutBytes: Buffer.byteLength(String(crun?.stdout ?? '')),
    stderrSha256: sha256(String(crun?.stderr ?? '')),
  });
  const ok = (call) => call.exitCode === 0;
  return {
    podmanVersion: version.stdout.trim(),
    podmanVersionFromInfo: podmanVersion.stdout.trim(),
    ociruntimePath: runtime.stdout.trim() || null,
    rootless: rootless.stdout.trim() === 'true',
    cgroupManager: cgroupManager.stdout.trim() || null,
    cgroupVersion: String(cgroupVersion?.stdout ?? '').trim() || null,
    cgroupControllers: String(cgroupControllers?.stdout ?? '').trim() || null,
    crunVersion: String(crun?.stdout ?? '').split('\n')[0] ?? null,
    launcher: { executable: PODMAN_HOST.executable, argvPrefix: [...PODMAN_HOST.argvPrefix], boundary: PODMAN_HOST.boundary },
    // Every field must have been READ, not merely asked for: an unparsable
    // template answers 125 and an empty string, and treating that as "rootless"
    // is how a real host gets reported as incapable.
    isolationCanBeRaised: ok(version) && ok(runtime) && ok(rootless) && ok(cgroupManager)
      && rootless.stdout.trim() === 'true' && cgroupVersion.status === 0,
  };
}

/** Step 2 — the pin, checked against what the store actually holds. */
function measureImage() {
  const base = podman(['pull', BASE_IMAGE], { label: 'image:pull-base', timeoutMs: 600_000 });
  const baseInspect = podman([
    'inspect', '--format', '{{.Digest}}|{{.Architecture}}|{{.Created}}', BASE_IMAGE,
  ], { label: 'image:inspect-base' });
  const executorInspect = podman([
    'inspect', '--format', '{{.Id}}|{{.Digest}}|{{.Architecture}}', EXECUTOR_IMAGE_ID,
  ], { label: 'image:inspect-executor' });
  const [id, digest, arch] = executorInspect.stdout.trim().split('|');
  let pinOk = false;
  let pinIssues = [];
  try {
    assertImageMatchesPin({ Id: id, Digest: digest, Architecture: arch });
    pinOk = true;
  } catch (error) {
    pinIssues = [error.message];
  }
  return {
    baseImage: BASE_IMAGE,
    baseDigest: digestOf(BASE_IMAGE),
    basePullExit: base.exitCode,
    baseInspectExit: baseInspect.exitCode,
    baseObservedDigest: baseInspect.stdout.trim().split('|')[0] ?? null,
    executorImageId: EXECUTOR_IMAGE_ID,
    executorImageDigest: EXECUTOR_IMAGE_DIGEST,
    executorObserved: { Id: id ?? null, Digest: digest ?? null, Architecture: arch ?? null },
    executorInspectExit: executorInspect.exitCode,
    pinKind: {
      base: 'registry-digest: portable; every host pulls this exact digest',
      executor: 'derived-image-digest: pins the bytes produced on THIS host from this base plus the executor tree; a rebuild elsewhere can differ',
    },
    pinVerified: pinOk,
    pinIssues,
    digestPinned: (() => { try { assertDigestPinned(BASE_IMAGE); assertDigestPinned(EXECUTOR_IMAGE_ID); return true; } catch { return false; } })(),
    executorPackage: EXECUTOR_PACKAGE,
    executorEntrypoint: EXECUTOR_ENTRYPOINT,
    executorExpectedVersion: EXECUTOR_VERSION,
  };
}

/**
 * Step 3 — the governed run.
 *
 * The container is asked four questions in one process, and the answers are the
 * axis measurements:
 *   `node --version` style version, from the executor itself;
 *   the route table, to show what the network axis left;
 *   its own env, to show what the environment axis passed;
 *   its own argv, to show the prompt/credential did not travel as an argument.
 * The credential is read as a LENGTH and never printed, so a length travels back
 * and a value does not.
 */
const AXIS_PROBE = `
const fs = require('fs');
const out = [];
out.push('VERITAS_ROUTE_ROWS=' + (fs.readFileSync('/proc/net/route','utf8').trim().split('\\n').length - 1));
out.push('VERITAS_ENV=' + JSON.stringify(Object.keys(process.env).sort()));
out.push('VERITAS_ARGV=' + JSON.stringify(process.argv.slice(1)));
out.push('VERITAS_SECRET_PATH=' + process.env.VERITAS_SECRET_MOUNT);
try { out.push('VERITAS_SECRET_PRESENT=' + fs.existsSync(process.env.VERITAS_SECRET_MOUNT)); } catch (e) { out.push('VERITAS_SECRET_PRESENT=false'); }
try { out.push('VERITAS_SECRET_LEN=' + fs.readFileSync(process.env.VERITAS_SECRET_MOUNT,'utf8').length); } catch (e) { out.push('VERITAS_SECRET_LEN=-1'); }
out.push('VERITAS_HOST_FS_WRITABLE=' + (() => { try { fs.writeFileSync('/etc/veritas-probe','x'); return true; } catch (e) { return e.code; } })());
out.push('VERITAS_TMP_FS_WRITABLE=' + (() => { try { fs.writeFileSync('/tmp/veritas-probe','x'); return true; } catch (e) { return e.code; } })());
out.push('VERITAS_UID=' + process.getuid() + ':' + process.getgid());
out.push('VERITAS_PLANTER_ENV=' + (process.env.VERITAS_PLANTER_PROBE ?? 'absent'));
out.push('VERITAS_HOME_VALUE=' + (process.env.HOME ?? 'absent'));
process.stdout.write(out.join('\\n') + '\\n');
`;

function runGoverned({ image, secretHandle, canaryValue, name }) {
  const profile = SANDBOX_ISOLATION_EXECUTOR;
  // The probe needs to know where its descriptor is. That is a PATH, so it goes
  // in as an env pair — a name whose value is a path, added to the profile's
  // own allowlist rather than smuggled past it.
  const probeProfile = {
    ...profile,
    environment: {
      ...profile.environment,
      allowlist: [...profile.environment.allowlist, 'VERITAS_SECRET_MOUNT'],
      fixed: { ...profile.environment.fixed, VERITAS_SECRET_MOUNT: secretMountPath(secretHandle) },
    },
  };
  const PLANTER_VARIABLE = 'VERITAS_PLANTER_PROBE';
  const planterValue = 'planted-by-the-operator-environment-2f8b41c6';
  const probeScript = AXIS_PROBE;
  const argv = validateArgv(['node', '-e', probeScript, '--', EXECUTOR_ENTRYPOINT, '--version']);

  const invocation = buildInvocation(probeProfile, {
    argv,
    image,
    secretHandles: [secretHandle],
    workdir: '/tmp',
    name,
    timeoutMs: 60_000,
  });
  const observation = executeIsolated(invocation, {
    // The operator's OWN session environment — the real `process.env`, plus one
    // planted variable whose value is unique to this run. Podman resolves `HOME`
    // before it does anything else, so the first version of this passed a
    // fabricated `HOME=/home/operator` and the launch died with
    // `cannot resolve /home/operator: lstat: no such file or directory` (exit 1).
    // That produced a FAIL whose reason had nothing to do with the environment
    // axis, which is the worst kind of failure: accurate, and about the wrong
    // thing. So the real environment goes in, and the planted variable is what
    // the control is about.
    env: { ...process.env, [PLANTER_VARIABLE]: planterValue },
  });
  // The launcher ran node with a script, not the executor directly, so the
  // executor's version is obtained by RUNNING it — which is the whole point of
  // step 3b rather than reading it off the package.
  const versionRun = spawnSync(invocation.executable, [
    ...PODMAN_HOST.argvPrefix, 'run', '--rm', '--pull=never', '--network=none', '--read-only',
    '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m', '--workdir', '/tmp',
    '--pids-limit', String(profile.process.max_processes),
    '--memory', `${profile.process.memory_mb}m`, '--memory-swap', `${profile.process.memory_mb}m`,
    '--cpus', '0.5',
    ...buildEnvironment(profile).flatMap((pair) => ['--env', pair]),
    '--cap-drop', 'all', '--security-opt', 'no-new-privileges', '--ipc=none',
    '--user', CONTAINER_USER, '--log-driver=none', '--secret', secretHandle, image,
    'node', EXECUTOR_ENTRYPOINT, '--version',
  ], {
    encoding: 'utf8', timeout: 60_000, shell: false,
    env: { PATH: '/usr/bin:/bin', HOME: '/tmp' },
  });
  commands.push({
    step: 'run:executor-version-direct',
    argv: [invocation.executable, 'run', '--rm', '--pull=never', '--network=none', image, 'node', EXECUTOR_ENTRYPOINT, '--version'],
    exitCode: Number.isInteger(versionRun?.status) ? versionRun.status : null,
    signal: versionRun?.signal ?? null,
    stdoutBytes: Buffer.byteLength(String(versionRun?.stdout ?? '')),
    stderrSha256: sha256(String(versionRun?.stderr ?? '')),
  });

  const pin = { Id: EXECUTOR_IMAGE_ID, Digest: EXECUTOR_IMAGE_DIGEST, Architecture: 'amd64' };
  // Caught, not thrown: a run whose real-start proof fails must still WRITE a
  // record saying so. An exception here would abort before `main` reached the
  // writer, and the absence of a record is a weaker statement than a record that
  // says the executor did not start.
  let governed = null;
  let governedError = null;
  try {
    governed = assertGovernedRun({
      observation: {
        exitCode: Number.isInteger(versionRun?.status) ? versionRun.status : null,
        signal: versionRun?.signal ?? null,
        stdout: String(versionRun?.stdout ?? ''),
      },
      pin,
      profile,
    });
  } catch (error) {
    governedError = error.message;
  }
  return {
    observation,
    invocation,
    governed,
    governedError,
    versionStdout: String(versionRun?.stdout ?? '').trim(),
    versionExitCode: Number.isInteger(versionRun?.status) ? versionRun.status : null,
    versionSignal: versionRun?.signal ?? null,
    planter: { variable: PLANTER_VARIABLE, value: planterValue },
  };
}

function parseProbe(stdout) {
  const map = {};
  for (const line of String(stdout).split('\n')) {
    const at = line.indexOf('=');
    if (at > 0) map[line.slice(0, at)] = line.slice(at + 1);
  }
  return map;
}

/**
 * Step 4 — the negative controls. Each one plants a real attempt and requires a
 * refusal that names itself.
 *
 * A control is only worth its cost if it would FAIL if the control were absent.
 * Two of these are therefore paired with an inversion: the same code path is run
 * once with the attempt planted (must refuse) and once with the allowlist
 * satisfied (must succeed), so a forwarder that refused everything would pass
 * the first and fail the second.
 */
async function runNegativeControls({ image, plantedStdout, plantedVariable }) {
  const controls = [];
  const socketPath = '/tmp/s2-002-isolation-egress.sock';
  const decisions = [];
  const forwarder = createEgressForwarder({
    allowlist: ISOLATION_EGRESS_ALLOWLIST,
    socketPath,
    log: (decision) => decisions.push(decision),
  });
  const socketPathAllowed = socketPath;
  try {
    await forwarder.listen();

    const ask = (host, port) => new Promise((resolve) => {
      const client = net.connect(socketPath);
      client.on('connect', () => client.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
      let buf = '';
      client.setEncoding('utf8');
      client.on('data', (chunk) => { buf += chunk; if (buf.includes('\r\n\r\n')) client.destroy(); });
      client.on('error', () => resolve({ status: null, refusal: null, raw: 'SOCKET_ERROR' }));
      setTimeout(() => { client.destroy(); resolve({ status: null, refusal: null, raw: buf || 'TIMEOUT' }); }, 8000).unref?.();
    });

    // N1 — an allowlist profile cannot be built with a wildcard, in any axis and
    // at any depth. Four shapes are planted because the scanner's first version
    // only walked arrays and missed the object form entirely.
    const wildcardShapes = {
      network_entry_host: {
        ...SANDBOX_ISOLATION_EXECUTOR,
        network: { policy: 'allowlist', allowlist: [{ host: '*', ports: [443] }] },
      },
      environment_allowlist: {
        ...SANDBOX_ISOLATION_EXECUTOR,
        environment: { ...SANDBOX_ISOLATION_EXECUTOR.environment, allowlist: ['*'] },
      },
      filesystem_roots: {
        ...SANDBOX_ISOLATION_EXECUTOR,
        filesystem: { ...SANDBOX_ISOLATION_EXECUTOR.filesystem, roots: ['*'] },
      },
      network_policy_unrestricted: {
        ...SANDBOX_ISOLATION_EXECUTOR,
        network: { policy: 'unrestricted', allowlist: [] },
      },
    };
    const wildcardResults = {};
    for (const [shape, candidate] of Object.entries(wildcardShapes)) {
      try {
        assertNoWildcard(candidate);
        wildcardResults[shape] = { refused: false };
      } catch (error) {
        wildcardResults[shape] = { refused: true, code: error.message.split(':')[0], at: error.message.split(':').slice(1).join(':') };
      }
    }
    controls.push({
      control: 'WILDCARD_ALLOWLIST_REFUSED',
      what: "a '*' is refused on every axis, at any depth, and 'unrestricted' is refused as a policy",
      why_it_matters: "'*' is the value HOST_UNISOLATED carries, and the contract permits it there; a launch is a different act from a record, so nothing carrying one may reach the launcher",
      shapes: wildcardResults,
      passed: Object.values(wildcardResults).every((r) => r.refused),
    });

    // N2 — a non-executable tier is refused by the launch gate.
    const tierResults = {};
    for (const tier of NON_EXECUTABLE_TIERS) {
      try {
        assertExecutableProfile({ ...SANDBOX_ISOLATION_EXECUTOR, tier });
        tierResults[tier] = { refused: false };
      } catch (error) {
        tierResults[tier] = { refused: true, code: error.message.split(':')[0] };
      }
    }
    controls.push({
      control: 'NON_EXECUTABLE_TIER_REFUSED',
      what: 'NO_EXEC and HOST_UNISOLATED are both refused by assertExecutableProfile before any process exists',
      why_it_matters: 'HOST_UNISOLATED is the tier the S2-007R record uses when a model-calling agent cannot run in isolation; accepting it here would be the silent substitution the handoff forbids',
      results: tierResults,
      passed: Object.values(tierResults).every((r) => r.refused),
    });


    // N3 — a destination off the allowlist is refused by the forwarder, and the
    // allowlisted one is admitted, so the forwarder is a filter and not a wall.
    const offHost = await ask('evil.example.com', 443);
    const offPort = await ask('open.bigmodel.cn', 22);
    const onList = await ask('open.bigmodel.cn', 443);
    const ref = (r) => String(r.raw ?? '').includes(EGRESS_ERRORS.NOT_ALLOWLISTED);
    controls.push({
      control: 'ALLOWLIST_ESCAPE_REFUSED',
      what: 'CONNECT to a host off the allowlist, and to a port off the allowlist, are both refused; the allowlisted pair is admitted',
      why_it_matters: 'an allowlist that refuses everything would pass a refusal test alone; the admitted pair is the inversion that shows the control filters rather than blocks',
      off_allowlist_host: { destination: 'evil.example.com:443', refused: ref(offHost), raw: offHost.raw ?? null },
      off_allowlist_port: { destination: 'open.bigmodel.cn:22', refused: ref(offPort), raw: offPort.raw ?? null },
      on_allowlist: { destination: 'open.bigmodel.cn:443', admitted: String(onList.raw ?? '').startsWith('HTTP/1.1 200'), raw: onList.raw ?? null },
      passed: ref(offHost) && ref(offPort) && String(onList.raw ?? '').startsWith('HTTP/1.1 200'),
    });

    // N4 — the policy layer refuses a destination the profile never named, with
    // no process started at all.
    const allowProfile = {
      ...SANDBOX_ISOLATION_EXECUTOR,
      network: { policy: 'allowlist', allowlist: ISOLATION_EGRESS_ALLOWLIST },
    };
    const denied = resolveEgress(allowProfile, { host: 'evil.example.com', port: 443 });
    const allowed = resolveEgress(allowProfile, { host: 'open.bigmodel.cn', port: 443 });
    const denyAllRefused = resolveEgress(SANDBOX_ISOLATION_EXECUTOR, { host: 'open.bigmodel.cn', port: 443 });
    controls.push({
      control: 'DENY_BY_DEFAULT_RESOLUTION',
      what: 'under deny_all every destination is refused; under allowlist only the named pair resolves',
      why_it_matters: 'the forwarder test proves the forwarder filters; this proves the POLICY refuses the same destination before any process exists, so a caller cannot ask for the wrong thing even if the forwarder were absent',
      deny_all: { destination: 'open.bigmodel.cn:443', allowed: denyAllRefused.allowed, reason: denyAllRefused.reason },
      allowlist_denied: { destination: 'evil.example.com:443', allowed: denied.allowed, code: denied.code },
      allowlist_allowed: { destination: 'open.bigmodel.cn:443', allowed: allowed.allowed, reason: allowed.reason },
      passed: denyAllRefused.allowed === false && denied.allowed === false && allowed.allowed === true,
    });

    // N5 — inside the container, the direct route to the API host does not
    // exist. This is the kernel's half of the allowlist and the only reason the
    // forwarder is the sole exit.
    const direct = spawnSync(PODMAN_HOST.executable, [
      ...PODMAN_HOST.argvPrefix, 'run', '--rm', '--pull=never', '--network=none', '--read-only',
      '--cap-drop', 'all', '--user', CONTAINER_USER, '--log-driver=none', image,
      'node', '-e',
      'const n=require("net");const s=n.connect(443,"open.bigmodel.cn");s.on("error",e=>{process.stdout.write("ERR="+e.code);process.exit(7)});s.on("connect",()=>{process.stdout.write("CONNECTED");process.exit(0)});',
    ], { encoding: 'utf8', timeout: 60_000, shell: false, env: { PATH: '/usr/bin:/bin', HOME: '/tmp' } });
    commands.push({
      step: 'negative:no-route-to-api-host',
      argv: [PODMAN_HOST.executable, 'run', '--rm', '--network=none', image, 'node', '-e', 'connect(443,"open.bigmodel.cn")'],
      exitCode: Number.isInteger(direct?.status) ? direct.status : null,
      signal: direct?.signal ?? null,
      stdoutBytes: Buffer.byteLength(String(direct?.stdout ?? '')),
      stderrSha256: sha256(String(direct?.stderr ?? '')),
    });
    controls.push({
      control: 'NO_ROUTE_INSIDE_CONTAINER',
      what: 'a direct connect() to the model API host from inside the container, with the same image and the same profile network flag',
      why_it_matters: "the KERNEL's half of the network axis: the container has no route, so the allowlist forwarder is the only exit rather than one of two. Its exit code is 7 BY DESIGN — the probe exits 7 on a connect error and 0 on a success, so 7 is the refusal and 0 would be the failure",
      observed: String(direct?.stdout ?? '').trim(),
      exitCode: Number.isInteger(direct?.status) ? direct.status : null,
      expected_exit_on_refusal: 7,
      passed: direct?.status === 7 && String(direct?.stdout ?? '').trim().startsWith('ERR='),
    });

    // N6 — the operator's environment is not inherited. A variable is planted in
    // the environment the launcher itself is started with, and the container is
    // asked whether it arrived. This is the control that distinguishes "the
    // profile lists the variables" from "the profile is the only source of them":
    // both are consistent with the observed env of a run where nothing sensitive
    // happens to be in the operator's session, and only this one is not.
    //
    // The second half is the stronger one. `HOME` is a variable the operator
    // certainly has, the profile certainly overrides, and the two values are
    // different strings — so if the container reports the operator's home, the
    // axis inherited, and a missing planted variable alone would not have said so.
    const probe = (() => { try { return parseProbe(plantedStdout); } catch { return {}; } })();
    const envKeys = (() => { try { return JSON.parse(probe.VERITAS_ENV ?? '[]'); } catch { return []; } })();
    const operatorHome = process.env.HOME ?? null;
    controls.push({
      control: 'HOST_ENVIRONMENT_NOT_INHERITED',
      what: 'the launcher is started with the operator\'s real environment plus one planted variable; neither the variable nor the operator HOME may reach the container',
      why_it_matters: 'both the planted variable and the operator HOME are things this session certainly has; if either arrived, the environment axis would be inheriting rather than building. A run where nothing interesting happens to be set would look identical to a correct one without this control',
      planted_variable: plantedVariable,
      planted_value_observed_inside_container: probe.VERITAS_PLANTER_ENV ?? null,
      variable_present_in_container_env: envKeys.includes(plantedVariable),
      operator_home: operatorHome,
      operator_home_observed_inside_container: probe.VERITAS_HOME_VALUE ?? null,
      profile_home: SANDBOX_ISOLATION_EXECUTOR.environment.fixed.HOME,
      home_came_from_profile: probe.VERITAS_HOME_VALUE === SANDBOX_ISOLATION_EXECUTOR.environment.fixed.HOME,
      container_env: envKeys,
      passed: (probe.VERITAS_PLANTER_ENV ?? 'absent') === 'absent'
        && !envKeys.includes(plantedVariable)
        && probe.VERITAS_HOME_VALUE === SANDBOX_ISOLATION_EXECUTOR.environment.fixed.HOME
        && probe.VERITAS_HOME_VALUE !== operatorHome,
    });
  } finally {
    await forwarder.close();
  }
  return { controls, forwarderDecisions: decisions, socketPath: socketPathAllowed, imageRef: image };
}

/**
 * Step 5 — the leak detector, over every surface the value could have reached.
 *
 * The detector is handed the value that was actually delivered, and it searches
 * the launch argv, the container's reported argv, the container's reported
 * environment, both streams, the podman secret listing, and the record being
 * written. Then, as its own control, it is handed a surface that DOES contain
 * the value and is required to report it — a detector that has never fired is
 * indistinguishable from a detector that cannot fire.
 */
function runLeakDetection({ canaryValue, observation, probe, invocation, recordDraft }) {
  // The surface NAMES are the contract with `assertNoSecretLeak`'s `required`
  // list, and they are spelled the same on both sides on purpose. The first run
  // had them mismatched — `launch_argv`/`container_argv` here against
  // `argv`/`env` there — and the detector answered
  // `argv:surface-not-supplied`, which is a TRUE statement about a name and a
  // useless one about a leak. A missing surface has to be loud, and it is only
  // loud when both sides agree on the spelling.
  const surfaces = {
    argv: invocation.argv.join(' '),
    env: probe.VERITAS_ENV ?? '',
    stdout: observation.stdout,
    stderr: observation.stderr,
    container_argv: probe.VERITAS_ARGV ?? '',
    podman_secret_ls: podman(['secret', 'ls'], { label: 'secret:ls' }).stdout,
    record: JSON.stringify(recordDraft),
  };
  const clean = assertNoSecretLeak(surfaces, { value: canaryValue });
  const planted = assertNoSecretLeak({ stdout: `prefix ${canaryValue} suffix` }, { value: canaryValue, required: ['stdout'] });
  return {
    surfacesSearched: clean.searched,
    leakDetected: !clean.ok,
    leaks: clean.leaks,
    fingerprint: fingerprint(canaryValue),
    // The inversion: a detector that cannot fail would report `ok` here too.
    detectorFiresOnPlantedValue: !planted.ok,
    detectorSelfCheckPassed: !planted.ok && planted.leaks.includes('stdout'),
    valuePublished: false,
    note: 'the delivered value is a synthetic canary literal in this script; no dotenv, no environment variable and no credential store is read anywhere in this file',
  };
}

/** Step 6 — what is genuinely ON, and what is genuinely OFF. */
function axesReport({ invocation, probe, controlList }) {
  const envKeys = (() => { try { return JSON.parse(probe.VERITAS_ENV ?? '[]'); } catch { return []; } })();
  const declared = invocation.axes.environment.allowlist;
  const injected = declared.filter((name) => envKeys.includes(name));
  const notInjected = declared.filter((name) => !envKeys.includes(name));
  // Names the container has that the profile did not pass. These are the base
  // IMAGE's own defaults (PATH, PWD, HOSTNAME, NODE_VERSION, YARN_VERSION and
  // `container` from the node image) plus whatever the runtime sets for itself.
  // They are listed rather than hidden because "the environment axis is exact"
  // would be false if this list were omitted, and the control that actually
  // rules out inheritance is HOST_ENVIRONMENT_NOT_INHERITED.
  const imageDefaults = envKeys.filter((key) => !declared.includes(key));
  return {
    network: {
      declared: 'deny_all',
      on: [`route table inside the container is empty (VERITAS_ROUTE_ROWS=${probe.VERITAS_ROUTE_ROWS})`],
      off: ['any destination at all', 'DNS resolution', 'the allowlist forwarder, because the profile did not ask for allowlist'],
      enforced_by: 'the kernel: --network=none',
      measured: (controlList ?? []).find((c) => c.control === 'NO_ROUTE_INSIDE_CONTAINER') ?? null,
    },
    filesystem: {
      declared: `read-only root, writable tmpfs on ${invocation.axes.filesystem.writableTmpfs.join(',')}`,
      on: [`/tmp is writable (VERITAS_TMP_FS_WRITABLE=${probe.VERITAS_TMP_FS_WRITABLE})`],
      off: [`everything outside the declared tmpfs; a write to /etc returned ${probe.VERITAS_HOST_FS_WRITABLE}`],
      enforced_by: 'the kernel: --read-only plus --tmpfs',
    },
    environment: {
      declared: `exactly ${declared.join(', ')}; host environment not inherited`,
      on: [`the container's own env is ${probe.VERITAS_ENV}`],
      off: [`every other variable of this operator's session`],
      injectedFromProfile: injected,
      declaredButNotObserved: notInjected,
      imageDefaultsObserved: imageDefaults,
      imageDefaultsNote: 'these come from the base image and the container runtime, not from the operator session; the control that rules out inheritance is HOST_ENVIRONMENT_NOT_INHERITED, which plants a variable in the launcher environment and observes its absence',
      enforced_by: 'the launcher: the child env is built from the profile and there is no process.env read on that path',
      measured: controlList?.find((c) => c.control === 'HOST_ENVIRONMENT_NOT_INHERITED') ?? null,
    },
    process: {
      declared: `max_processes=${invocation.axes.process.maxProcesses}, memory=${invocation.axes.process.memoryMb}m, cpus=${invocation.axes.process.nanoCpus / 1e9}`,
      on: ['the flags are in the launch argv; the record quotes the argv'],
      off: ['nothing — these are ceilings, and nothing raises them'],
      enforced_by: 'the kernel via cgroup v2 and the pids controller',
      not_independently_measured: 'a pids-limit breach was not provoked in this run; the flag is recorded from the argv that the kernel received, not from an observed refusal',
    },
    image: {
      declared: `digest-pinned base ${BASE_IMAGE} and derived ${EXECUTOR_IMAGE_ID}`,
      on: [`the executor answered a version query from inside the container`],
      off: ['any tag: assertDigestPinned refuses a reference without @sha256:'],
      enforced_by: 'podman pull by digest, plus assertImageMatchesPin over podman inspect',
    },
    secrets: {
      declared: `descriptor ${SECRET_HANDLE}, readable only at ${secretMountPath(SECRET_HANDLE)}`,
      on: ['the container read its credential and reported its LENGTH, not its value'],
      off: ['the environment', 'the argv', 'the launch argv', 'the record'],
      enforced_by: "podman's secret store: `podman secret create <handle> <path>` then `podman run --secret <handle>`",
    },
  };
}

export function buildRecord({ host, image, run, controls, leak, axes, startedAt, finishedAt, status, reason = null }) {
  return {
    schemaVersion: SCHEMA_VERSION,
    record: 's2-002-isolation-live',
    subject: SUBJECT,
    subjectId: SUBJECT_ID,
    aMvpClause: 'изоляция — образ, allowlist, secret handles',
    // The vocabulary the S2-007R records already use. A-MVP-04 is not upgraded by
    // this record: the isolation clause now has a measurement, and upgrading the
    // case is a reviewer's act, not a script's. `aMvpStatus` is therefore the same
    // `NOT_CLAIMED` every other S2-007R record carries.
    aMvpStatus: 'NOT_CLAIMED',
    aMvpClauseMeasured: true,
    aMvpClauseUpgradeRequires: 'a human review of this record; the script measures, it does not score',
    status,
    reason,
    startedAt,
    finishedAt,
    component: {
      package: EXECUTOR_PACKAGE,
      expectedVersion: EXECUTOR_VERSION,
      observedVersion: run?.governed?.executorVersionObserved ?? null,
      versionSource: 'the executor printed it from inside the container; no version is read from package.json by this record',
    },
    tier: SANDBOX_ISOLATION_EXECUTOR.tier,
    profileId: SANDBOX_ISOLATION_EXECUTOR.profile_id,
    executableTiers: [...EXECUTABLE_TIERS],
    nonExecutableTiers: [...NON_EXECUTABLE_TIERS],
    host,
    image,
    axes,
    secretHandle: {
      handle: SECRET_HANDLE,
      form: SECRET_ERRORS.PODMAN_SECRET_FORM,
      mountPathInsideContainer: secretMountPath(SECRET_HANDLE),
      valuePublished: false,
      valueOrigin: 'synthetic canary literal in scripts/s2-002-isolation-run.mjs; no dotenv, no environment variable and no credential store is read',
    },
    leakDetection: leak,
    negativeControls: controls.controls,
    realRun: run ? {
      // TWO runs, TWO exit codes, kept apart. The axis probe answers the four
      // axis questions; the version run is the one that answers "did the executor
      // start". Collapsing them into a single `exitCode` made the record unable
      // to re-derive the real-start proof from its own bytes, which is the one
      // thing a reader should be able to do.
      axis_probe: { exitCode: run.observation.exitCode, signal: run.observation.signal, stdout: run.observation.stdout, stderrSha256: sha256(run.observation.stderr) },
      executor_version: { exitCode: run.versionExitCode, signal: run.versionSignal, stdout: run.versionStdout },
      exitCode: run.observation.exitCode,
      signal: run.observation.signal,
      probeStdout: run.observation.stdout,
      probeStderrDigest: sha256(run.observation.stderr),
      executorVersionDirect: run.versionStdout,
      realStartProven: run.governed?.realStartProven ?? false,
      governedError: run.governedError,
      axisProbe: parseProbe(run.observation.stdout),
    } : null,
    rawLog: {
      path: path.relative(ROOT, RAW_DIR),
      note: 'every command, its argv and its exit code, plus the untruncated streams of each launch',
    },
    commands,
    limits: [
      'the base image digest is portable; the derived image digest pins only the bytes built on this host',
      'no model call is made: this record is about isolation, and a paid call would not evidence a network flag',
      'the pids and memory ceilings are recorded from the argv the kernel received, not from a provoked breach',
      'the credential delivered to the container is synthetic; the descriptor mechanism is what is measured, not a real key',
    ],
  };
}

/**
 * The podman adapter `secrets.mjs` expects: it takes an argv ARRAY, and it
 * carries the measured host prefix and a podman-only environment. Handing the
 * module a bare `spawnSync` would spawn the array as one filename, which is
 * exactly the `The "file" argument must be of type string` failure this adapter
 * exists to prevent.
 */
function podmanStore(argv) {
  const full = [...PODMAN_HOST.argvPrefix, ...argv];
  const call = spawnSync(PODMAN_HOST.executable, full, {
    encoding: 'utf8', timeout: 120_000, shell: false,
    env: { PATH: '/tmp/bin:/usr/bin:/bin', HOME: '/tmp', XDG_RUNTIME_DIR: '/tmp/xdg-rt', TMPDIR: '/tmp' },
  });
  commands.push({
    step: `store:${argv.slice(0, 2).join(' ')}`,
    argv: full,
    exitCode: Number.isInteger(call?.status) ? call.status : null,
    signal: call?.signal ?? null,
    stdoutBytes: Buffer.byteLength(String(call?.stdout ?? '')),
    stderrSha256: sha256(String(call?.stderr ?? '')),
  });
  return { status: Number.isInteger(call?.status) ? call.status : null, stdout: String(call?.stdout ?? ''), stderr: String(call?.stderr ?? '') };
}

async function main() {
  const startedAt = new Date().toISOString();
  mkdirSync(RAW_DIR, { recursive: true });
  commands.length = 0;

  const host = measureHost();
  const image = measureImage();

  if (!host.isolationCanBeRaised) {
    const record = buildRecord({
      host, image, run: null, controls: { controls: [] }, leak: null, axes: null,
      startedAt, finishedAt: new Date().toISOString(),
      status: 'NOT_RUN',
      reason: 'podman did not report a rootless runtime on this host, so no isolation profile could be launched. Nothing was substituted for the measurement.',
    });
    writeFileSync(RECORD_PATH, `${JSON.stringify(record, null, 2)}\n`);
    process.stderr.write('NOT_RUN: no rootless podman runtime on this host\n');
    return 1;
  }

  const canaryValue = SYNTHETIC_SECRET_VALUE;
  let store = null;
  let run = null;
  let controls = { controls: [] };
  let leak = null;
  let status = 'PASS';
  let reason = null;
  let storeRemovalError = null;

  try {
    store = materializeSecret(SECRET_HANDLE, canaryValue, { spoolDir: SPOOL_DIR, podman: podmanStore });
    run = runGoverned({
      image: EXECUTOR_IMAGE_ID,
      secretHandle: SECRET_HANDLE,
      canaryValue,
      name: 'veritas-isolation-live',
    });
    controls = await runNegativeControls({
      image: EXECUTOR_IMAGE_ID,
      plantedStdout: run?.observation.stdout ?? '',
      plantedVariable: run?.planter?.variable ?? null,
    });
    leak = runLeakDetection({
      canaryValue,
      observation: run.observation,
      probe: parseProbe(run.observation.stdout),
      invocation: run.invocation,
      recordDraft: { subject: SUBJECT, handle: SECRET_HANDLE, argv: run.invocation.argv },
    });
  } catch (error) {
    status = 'FAIL';
    reason = error.message;
  } finally {
    if (store) { try { disposeSecret(SECRET_HANDLE, { podman: podmanStore }); } catch (error) { storeRemovalError = error.message; } }
  }

  // The verdict is decided BEFORE the record is built. Building first and
  // downgrading afterwards produced a record that said `status: PASS` while the
  // process exited 1 — the file and the exit code disagreeing is the exact shape
  // of a claim nobody can trust, so the order here is load-bearing.
  const controlsPassed = controls.controls.length > 0 && controls.controls.every((c) => c.passed);
  if (status === 'PASS' && (!controlsPassed || !leak?.detectorSelfCheckPassed || !run?.governed?.realStartProven)) {
    status = 'FAIL';
    reason = reason ?? (
      controls.controls.length === 0
        ? 'no negative control ran; an empty control set is not a pass'
        : 'a negative control or the real-start proof did not hold'
    );
  }
  if (storeRemovalError) {
    // A secret left in the store is a finding, not a footnote: the descriptor
    // outlived the run that created it.
    status = 'FAIL';
    reason = `${reason ? `${reason}; ` : ''}secret store cleanup failed: ${storeRemovalError}`;
  }
  if (leak && leak.leakDetected) {
    status = 'FAIL';
    reason = `${reason ? `${reason}; ` : ''}the delivered value was found in: ${leak.leaks.join(', ')}`;
  }
  if (status !== 'PASS') {
    process.stderr.write(`FAIL reason=${reason}\n`);
  }

  const probe = run ? parseProbe(run.observation.stdout) : {};
  const axes = run ? axesReport({ invocation: run.invocation, probe, controlList: controls.controls }) : null;
  const finishedAt = new Date().toISOString();
  const record = buildRecord({
    host, image, run, controls, leak, axes, startedAt, finishedAt, status, reason,
  });

  // The record is written only after the leak scan, and the scan covered a draft
  // of the record; this second scan covers the final bytes, because a field
  // added between the two is exactly the field that would leak. When the run
  // failed before the detector ran, the value is still scanned against the
  // record — a failure that skipped the leak check is a failure that must not
  // also skip the check.
  const finalScan = assertNoSecretLeak({ record: JSON.stringify(record) }, { value: canaryValue, required: ['record'] });
  record.leakDetection = {
    ...(record.leakDetection ?? { note: 'the detector did not run; the record was still scanned for the delivered value' }),
    finalRecordScan: { ok: finalScan.ok, leaks: finalScan.leaks },
    fingerprint: record.leakDetection?.fingerprint ?? fingerprint(canaryValue),
    valuePublished: false,
  };
  if (!finalScan.ok) {
    record.status = 'FAIL';
    record.reason = `${record.reason ? `${record.reason}; ` : ''}the value reached the final record in: ${finalScan.leaks.join(', ')}`;
  }

  const rawLog = {
    schemaVersion: SCHEMA_VERSION,
    subject: SUBJECT,
    startedAt,
    finishedAt,
    commands,
    streams: {
      axisProbeStdout: run?.observation.stdout ?? null,
      axisProbeStderr: run?.observation.stderr ?? null,
      executorVersionStdout: run?.versionStdout ?? null,
      forwarderDecisions: controls.forwarderDecisions ?? [],
    },
  };
  const rawLogPath = path.join(RAW_DIR, 'raw-run.log.json');
  writeFileSync(rawLogPath, `${JSON.stringify(rawLog, null, 2)}\n`);
  record.rawLog.file = path.relative(ROOT, rawLogPath);
  record.rawLog.sha256 = sha256(JSON.stringify(rawLog));
  record.rawLog.bytes = Buffer.byteLength(`${JSON.stringify(rawLog, null, 2)}\n`);

  writeFileSync(RECORD_PATH, `${JSON.stringify(record, null, 2)}\n`);

  const summary = [
    `status=${record.status}`,
    `tier=${record.tier}`,
    `executor_observed=${record.component.observedVersion}`,
    `real_start_proven=${record.realRun?.realStartProven}`,
    `negative_controls_passed=${controlsPassed} (${controls.controls.filter((c) => c.passed).length}/${controls.controls.length})`,
    `leak_detected=${record.leakDetection?.leakDetected}`,
    `detector_fires_on_planted=${record.leakDetection?.detectorFiresOnPlantedValue}`,
    `raw_log=${record.rawLog.file}`,
    `record=evidence/s2-002-isolation-live.json`,
  ].join(' ');
  process.stdout.write(`${summary}\n`);
  return record.status === 'PASS' ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await main();
}
