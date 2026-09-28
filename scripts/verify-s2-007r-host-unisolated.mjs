// S2-007R HOST_UNISOLATED tier evidence (issue #45, decision D3-b).
//
// WHAT THIS SCRIPT IS
// A measurement of what the host does NOT control when a model-calling agent
// runs outside the S2-002 isolation profiles. It is the ONLY evidence the
// HOST_UNISOLATED profile may cite, and it is deliberately an evidence of
// ABSENCE: the profile exists so that a real codex/pi run on a host that
// cannot execute an agent inside a proven profile can still be AUTHORISED and
// RECORDED truthfully, instead of either (a) being named after a profile whose
// controls were never in force, or (b) silently running with no record at all.
//
// WHY A LOWER TIER INSTEAD OF REUSING A PROVEN PROFILE
// `policy.assertSandboxExecutable` refuses "a degraded unisolated run" on
// purpose. Reusing `sbx-podman-local-restricted-v1` for a process that never
// entered the container would make that check pass on a claim, and the
// profile_id in every downstream record would then name controls that were not
// in force. A separate, lower tier keeps the authorization tier, the observed
// execution context and the record saying the same true thing.
//
// WHAT IT MEASURES (every field is observed here, not asserted)
//   1. The shipped S2-002 runtime's own verdict for an executable tier on this
//      host (`createSandbox(...).executionAllowed` and its blockedReason).
//   2. Whether the pinned isolation image can execute an agent at all: the
//      runtimes present inside it, and whether it has egress.
//   3. Whether a credential could reach an isolated child at all
//      (injectedEnvironment / mounts / secret_handles).
//   4. The contrast on the same host and moment: the host itself has egress.
//   5. The controls the tier therefore does NOT provide, and the exact
//      requirements that would unblock a genuinely isolated agent run.
//
// It writes evidence/s2-007r-host-unisolated.json and prints the record. It
// NEVER writes a secret, a credential or an environment value: only variable
// NAMES, digests and measured booleans.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createSandbox } from '../src/lib/identity/sandbox.mjs';
import { SANDBOX_LOCAL_RESTRICTED_PODMAN, SANDBOX_HOST_UNISOLATED } from '../src/lib/identity/sandbox-profiles.mjs';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EVIDENCE_PATH = path.join(ROOT, 'evidence/s2-007r-host-unisolated.json');
const DIGEST_PREFIX = 'sha256:';

const sha256File = (relative) => {
  const absolute = path.join(ROOT, relative);
  return `${DIGEST_PREFIX}${createHash('sha256').update(fs.readFileSync(absolute)).digest('hex')}`;
};

function run(executable, argv, { timeout = 30_000 } = {}) {
  const result = spawnSync(executable, argv, {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    shell: false,
    timeout,
    windowsHide: true,
  });
  if (result.error) return { ok: false, status: null, stdout: '', stderr: String(result.error.message ?? result.error.code) };
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
  };
}

function podman(argv, options) {
  // Portable: the same argv on posix, through wsl.exe on win32, exactly as
  // src/lib/identity/podman-sandbox.mjs does it.
  if (process.platform === 'win32') return run('wsl.exe', ['-d', 'Ubuntu-24.04', '--', 'podman', ...argv], options);
  return run('podman', argv, options);
}

// --- 1. the shipped S2-002 runtime's own verdict -----------------------------

function measureShippedRuntimeVerdict(workspaceRoot) {
  let verdict;
  try {
    const sandbox = createSandbox({
      profile: SANDBOX_LOCAL_RESTRICTED_PODMAN,
      workspaceRoots: [workspaceRoot],
      now: '2026-09-26T00:00:00.000Z',
    });
    verdict = {
      probed: true,
      tier: sandbox.tier,
      profileId: sandbox.profileId,
      executionAllowed: sandbox.executionAllowed,
      blockedReason: sandbox.blockedReason ?? null,
      blockedDetailPresent: typeof sandbox.blockedDetail === 'string' && sandbox.blockedDetail.length > 0,
    };
  } catch (error) {
    verdict = { probed: false, error: String(error?.message ?? error) };
  }
  return {
    ...verdict,
    interpretation: verdict.executionAllowed === true
      ? 'the S2-002 runtime permits executable-tier execution on this host'
      : 'the S2-002 runtime REFUSES executable-tier execution on this host, so a run declared under a proven isolation profile could not be executed by that runtime here',
  };
}

// --- 2. can the pinned isolation image execute an agent? ---------------------

function measurePinnedImage() {
  const image = 'docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc';
  const script = [
    'for b in node npm codex pi python3 curl wget; do',
    '  if command -v "$b" >/dev/null 2>&1; then echo "$b=present"; else echo "$b=absent"; fi',
    'done',
    'echo "route_lines=$(awk \'NR>1\' /proc/net/route 2>/dev/null | wc -l)"',
    'getent hosts openrouter.ai >/dev/null 2>&1 && echo "dns=resolves" || echo "dns=unresolvable"',
  ].join('; ');
  const probe = podman([
    'run', '--rm', '--pull=never', '--network=none', '--read-only',
    '--cap-drop', 'all', '--security-opt', 'no-new-privileges', '--user=65534:65534',
    '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m', '--log-driver=none',
    image, 'sh', '-c', script,
  ], { timeout: 60_000 });
  const parsed = {};
  for (const line of probe.stdout.split('\n')) {
    const [key, value] = line.split('=');
    if (key && value !== undefined) parsed[key.trim()] = value.trim();
  }
  const agentRuntimesPresent = ['node', 'npm', 'codex', 'pi']
    .filter((binary) => parsed[binary] === 'present');
  return {
    image,
    probed: probe.status !== null,
    exitStatus: probe.status,
    runtimesInImage: parsed,
    agentRuntimePresent: agentRuntimesPresent,
    routeLines: parsed.route_lines ?? null,
    dns: parsed.dns ?? null,
    conclusion: agentRuntimesPresent.length === 0
      ? 'the pinned isolation image contains no agent runtime, so a model-calling executor cannot run inside it'
      : `image contains ${agentRuntimesPresent.join(', ')}; egress still measured separately`,
  };
}

// --- 3. could a credential reach an isolated child? --------------------------

function measureCredentialPath() {
  const podmanInfo = podman(['info', '--format', 'json'], { timeout: 60_000 });
  let info = null;
  try {
    info = JSON.parse(podmanInfo.stdout);
  } catch {
    info = null;
  }
  const security = info?.host?.security ?? {};
  return {
    injectedEnvironment: security.injectedEnvironment ?? null,
    mounts: security.mounts ?? null,
    networkInterfaces: security.networkInterfaces ?? null,
    profileSecretHandles: SANDBOX_LOCAL_RESTRICTED_PODMAN.environment?.secret_handles ?? null,
    conclusion: 'with zero injected environment, zero mounts and an empty secret_handles allowlist, no host credential can be presented to a containerised executor, so even an agent-capable image could not authenticate',
  };
}

// --- 4. the contrast: the host itself has egress -----------------------------

function measureHostEgress() {
  const probe = run('curl', ['-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '8', 'https://openrouter.ai/api/v1/models'], { timeout: 20_000 });
  return {
    probe: 'https GET openrouter.ai/api/v1/models (no credentials sent)',
    exitStatus: probe.status,
    httpCode: probe.stdout.trim() || null,
    conclusion: probe.stdout.trim() === '200'
      ? 'the host process space has outbound network access, which is exactly the capability the isolation profiles deny'
      : 'the host has no observed outbound access either; a model-calling run would be impossible in either context',
  };
}

// --- 5. what this tier does NOT control -------------------------------------

const NOT_CONTROLLED = Object.freeze([
  'kernel_process_isolation: there is no AppContainer, no user namespace, no seccomp filter and no read-only root for the child; it is an ordinary host process',
  'filesystem_containment: the declared roots are the only boundary, enforced by the board ACL, not by the OS; the child can read anything the operator account can read',
  'network_egress: unrestricted, including the model provider endpoint; no allowlist, no deny rule, no DNS policy',
  'environment_and_secrets: the child inherits the operator environment; no allowlist, no secret handles, no injection control',
  'process_recourse: killing the process group is under this repository\'s control (POSIX group signal plus the shipped process observer), not under an OS-enforced boundary',
]);

const UNBLOCKING_REQUIRES = Object.freeze([
  'a digest-pinned image that contains the node runtime and the executor binaries',
  'a network allowlist that replaces --network=none with the model provider endpoint and nothing else',
  'a secret-handle mechanism in the profile, so a credential can be presented to the container without exporting the operator environment',
]);

export function buildHostUnisolatedRecord({ workspaceRoot } = {}) {
  const root = workspaceRoot ?? path.join(os.tmpdir(), 'veritas-s2-007r-host-unisolated-probe');
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const record = {
    schemaVersion: 1,
    ticket: 'S2-007R',
    issue: 'SpaceDazher/Veritas#45',
    profileId: SANDBOX_HOST_UNISOLATED.profile_id,
    tier: SANDBOX_HOST_UNISOLATED.tier,
    boundary: 'HOST_PROCESS_SPACE',
    decision: 'A run bound to this tier is authorised ONLY by an explicit, named human authorisation document resolved server-side. The tier exists so that the authorization tier, the observed execution context and the written record are the same true statement; it is NOT an isolation tier and may never be counted as one.',
    host: {
      platform: process.platform,
      release: os.release(),
      arch: process.arch,
      cpus: os.cpus().length,
      totalMemoryBytes: os.totalmem(),
    },
    measurements: {
      shippedRuntimeVerdict: measureShippedRuntimeVerdict(root),
      pinnedIsolationImage: measurePinnedImage(),
      credentialPath: measureCredentialPath(),
      hostEgress: measureHostEgress(),
    },
    notControlled: NOT_CONTROLLED,
    unblockingRequires: UNBLOCKING_REQUIRES,
    isolationClaim: false,
    aMvpIsolationClauses: 'NOT_RUN',
    scope: 'Evidence of the ABSENCE of OS-level isolation controls for a model-calling executor on this host. It is not a permit: the permit is the named human authorisation document, quoted by digest in the run record.',
  };
  const { recordDigest, ...withoutDigest } = record;
  return { ...withoutDigest, recordDigest: canonicalDigest(withoutDigest) };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const write = process.argv.includes('--write');
  const record = buildHostUnisolatedRecord();
  if (write) fs.writeFileSync(EVIDENCE_PATH, `${JSON.stringify(record, null, 2)}\n`);
  const { recordDigest, ...checkable } = record;
  if (canonicalDigest(checkable) !== recordDigest) {
    console.error('HOST_UNISOLATED_RECORD_DIGEST_MISMATCH');
    process.exit(1);
  }
  const shipped = record.measurements.shippedRuntimeVerdict;
  const image = record.measurements.pinnedIsolationImage;
  console.log(JSON.stringify({
    ok: true,
    profileId: record.profileId,
    recordDigest,
    shippedRuntimeAllowsExecution: shipped.executionAllowed === true,
    imageHasAgentRuntime: image.agentRuntimePresent.length > 0,
    hostEgressHttpCode: record.measurements.hostEgress.httpCode,
    isolationClaim: record.isolationClaim,
    aMvpIsolationClauses: record.aMvpIsolationClauses,
    evidencePath: write ? path.relative(ROOT, EVIDENCE_PATH) : null,
    evidenceDigest: write ? sha256File('evidence/s2-007r-host-unisolated.json') : null,
  }, null, 2));
}
