import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  PODMAN_DISTRO,
  PODMAN_IMAGE,
  PODMAN_PROFILE_ID,
  buildPodmanInvocation,
  executeAuthorizedPodmanTool,
  verifyPodmanEvidenceRecord,
} from '../src/lib/identity/podman-sandbox.mjs';
import { SANDBOX_LOCAL_RESTRICTED_PODMAN } from '../src/lib/identity/sandbox-profiles.mjs';
import { createPolicyEngine } from '../src/lib/identity/policy-engine.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EVIDENCE_PATH = path.join(ROOT, 'evidence/s2-002-podman-sandbox.json');

function run(executable, argv, { expected = 0, timeout = 30_000 } = {}) {
  const result = spawnSync(executable, argv, {
    encoding: 'utf8',
    maxBuffer: 256 * 1024,
    shell: false,
    timeout,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== expected) {
    throw new Error(`COMMAND_FAILED expected=${expected} actual=${result.status}: ${result.stderr}`);
  }
  return String(result.stdout ?? '').trim();
}

function wsl(argv, options) {
  return run('wsl.exe', ['-d', PODMAN_DISTRO, '--', ...argv], options);
}

function hardened(command, jobId, expected = 0) {
  const invocation = buildPodmanInvocation({ jobId, command });
  return run(invocation.executable, invocation.argv, { expected });
}

function observe() {
  const info = JSON.parse(wsl(['podman', 'info', '--format', 'json']));
  const imageDigest = wsl(['podman', 'image', 'inspect', PODMAN_IMAGE, '--format', '{{.Digest}}']);
  if (!PODMAN_IMAGE.endsWith(imageDigest)) throw new Error('PINNED_IMAGE_DIGEST_MISMATCH');

  const limitJob = 'evidence-limits';
  const limitInvocation = buildPodmanInvocation({ jobId: limitJob, command: ['sleep', '30'] });
  const imageIndex = limitInvocation.argv.indexOf(PODMAN_IMAGE);
  const detachedArgv = [...limitInvocation.argv];
  detachedArgv.splice(imageIndex, 0, '--detach');
  try {
    run(limitInvocation.executable, detachedArgv);
    const hostConfig = JSON.parse(wsl(['podman', 'inspect', limitInvocation.containerName, '--format', '{{json .HostConfig}}']));
    const capEff = hardened(['grep', 'CapEff:', '/proc/self/status'], 'evidence-cap').split(/\s+/)[1];
    const noNewPrivileges = Number(hardened(['grep', 'NoNewPrivs:', '/proc/self/status'], 'evidence-nnp').split(/\s+/)[1]);
    const seccompMode = Number(hardened(['grep', 'Seccomp:', '/proc/self/status'], 'evidence-seccomp').split(/\s+/)[1]);
    const authorizedSmoke = executeAuthorizedPodmanTool({
      policyEngine: createPolicyEngine({ now: '2026-09-12T12:00:00.000Z' }),
      request: {
        adapter: 'api',
        principalId: 'prn-platform-experimenter',
        action: 'tool.execute',
        workspaceId: 'ws-veritas-project',
        resource: { type: 'tool', id: 'tool:runner' },
        args: { tool_id: 'tool:runner', canonical_args: {} },
        lease: { leaseId: 'lse-experimenter-0005', fencingToken: 1 },
      },
      command: ['printf', 'VERITAS_SANDBOX_OK'],
      jobId: 'evidence-authorized-smoke',
    });
    if (authorizedSmoke.status !== 'success'
      || authorizedSmoke.stdout !== 'VERITAS_SANDBOX_OK'
      || authorizedSmoke.cleanupVerified !== true
      || authorizedSmoke.authorization?.decision !== 'ALLOW') {
      throw new Error('AUTHORIZED_PODMAN_SMOKE_FAILED');
    }
    return {
      schemaVersion: 1,
      profileId: PODMAN_PROFILE_ID,
      boundary: 'WSL2_ROOTLESS_PODMAN',
      distro: PODMAN_DISTRO,
      kernel: wsl(['uname', '-r']),
      podmanVersion: info.version.Version,
      ociRuntime: info.host.ociRuntime.name,
      image: PODMAN_IMAGE,
      rootless: info.host.security.rootless,
      cgroupVersion: info.host.cgroupVersion,
      cgroupControllers: [...info.host.cgroupControllers].sort(),
      controls: {
        uid: Number(hardened(['id', '-u'], 'evidence-uid')),
        capEff,
        rootFsReadOnly: hardened(['touch', '/root-should-fail'], 'evidence-rootfs', 1) === '',
        tmpfsWritable: hardened(['touch', '/tmp/ok'], 'evidence-tmp') === '',
        networkInterfaces: hardened(['ls', '/sys/class/net'], 'evidence-net').split(/\s+/).filter(Boolean).sort(),
        noNewPrivileges,
        seccompMode,
        mounts: hostConfig.Binds.length,
        injectedEnvironment: 0,
      },
      limits: {
        pids: hostConfig.PidsLimit,
        memoryBytes: hostConfig.Memory,
        nanoCpus: hostConfig.NanoCpus,
      },
      authorizedBackendSmoke: {
        decision: authorizedSmoke.authorization.decision,
        status: authorizedSmoke.status,
        exitCode: authorizedSmoke.exitCode,
        cleanupVerified: authorizedSmoke.cleanupVerified,
        stdoutSha256: authorizedSmoke.stdoutSha256,
      },
      scope: 'LOCAL_RESTRICTED',
      untrustedCodeEnabled: false,
      limitations: [
        'AppArmor and SELinux are unavailable inside this WSL2 distribution.',
        'Only network=none and images already pinned in the local rootless store are supported.',
        'No host filesystem mount, host environment variable or secret injection is supported.',
      ],
    };
  } finally {
    spawnSync('wsl.exe', [
      '-d', PODMAN_DISTRO, '--', 'podman', 'rm', '--force', '--time', '0', `veritas-${limitJob}`,
    ], { encoding: 'utf8', shell: false, timeout: 10_000, windowsHide: true });
  }
}

function canonical(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const observed = observe();
const observedValidation = verifyPodmanEvidenceRecord(observed);
if (!observedValidation.ok) throw new Error(`OBSERVED_CONTROLS_INVALID:${observedValidation.issues.join(',')}`);

if (process.argv.includes('--write')) {
  const serialized = canonical(observed);
  fs.writeFileSync(EVIDENCE_PATH, serialized);
  console.log(JSON.stringify({
    ok: true,
    mode: 'write',
    path: 'evidence/s2-002-podman-sandbox.json',
    sha256: createHash('sha256').update(serialized).digest('hex'),
    observed,
  }, null, 2));
  process.exit(0);
}

const bytes = fs.readFileSync(EVIDENCE_PATH);
const committed = JSON.parse(bytes.toString('utf8'));
const committedValidation = verifyPodmanEvidenceRecord(committed);
const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const issues = [
  ...committedValidation.issues,
  ...(JSON.stringify(committed) === JSON.stringify(observed) ? [] : ['observed-record-mismatch']),
  ...(SANDBOX_LOCAL_RESTRICTED_PODMAN.os_controls_evidence === digest ? [] : ['profile-evidence-digest-mismatch']),
];
console.log(JSON.stringify({ ok: issues.length === 0, digest, issues, observed }, null, 2));
process.exit(issues.length === 0 ? 0 : 1);
