import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  GVISOR_DISTRO,
  GVISOR_IMAGE,
  GVISOR_PROFILE_ID,
  GVISOR_RUNTIME_SHA256,
  GVISOR_VERSION,
  buildGvisorInvocation,
  executeAuthorizedGvisorTool,
  verifyGvisorEvidenceRecord,
} from '../src/lib/identity/gvisor-sandbox.mjs';
import { SANDBOX_UNTRUSTED_CODE_GVISOR } from '../src/lib/identity/sandbox-profiles.mjs';
import { createPolicyEngine } from '../src/lib/identity/policy-engine.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EVIDENCE_PATH = path.join(ROOT, 'evidence/s2-002-gvisor-sandbox.json');

function run(executable, argv, { expected = 0, timeout = 30000 } = {}) {
  const result = spawnSync(executable, argv, {
    encoding: 'utf8', maxBuffer: 512 * 1024, shell: false, timeout, windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== expected) throw new Error(`COMMAND_FAILED:${result.status}:${String(result.stderr).trim()}`);
  return String(result.stdout ?? '').trim();
}

function wslRoot(argv, options) {
  return run('wsl.exe', ['-d', GVISOR_DISTRO, '-u', 'root', '--', ...argv], options);
}

function hardened(command, jobId, expected = 0) {
  const invocation = buildGvisorInvocation({ jobId, command });
  return run(invocation.executable, invocation.argv, { expected, timeout: 60000 });
}

function parseStatusField(output, name) {
  const line = output.split(/\r?\n/).find((candidate) => candidate.startsWith(`${name}:`));
  return line?.split(/\s+/)[1] ?? '';
}

function parseNetworkInterfaces(output) {
  return output.split(/\r?\n/).slice(2).map((line) => line.split(':')[0].trim()).filter(Boolean).sort();
}

function observe() {
  const info = JSON.parse(wslRoot(['podman', 'info', '--format', 'json']));
  const imageDigest = wslRoot(['podman', 'image', 'inspect', GVISOR_IMAGE, '--format', '{{.Digest}}']);
  if (!GVISOR_IMAGE.endsWith(imageDigest)) throw new Error('PINNED_IMAGE_DIGEST_MISMATCH');
  const versionOutput = wslRoot(['/usr/bin/runsc', '--version']);
  const runtimeDigest = wslRoot(['sha256sum', '/usr/bin/runsc']).split(/\s+/)[0];
  if (!versionOutput.includes(GVISOR_VERSION) || runtimeDigest !== GVISOR_RUNTIME_SHA256) {
    throw new Error('GVISOR_BINARY_BINDING_MISMATCH');
  }

  const limitJob = 'gvisor-evidence-limits';
  const invocation = buildGvisorInvocation({ jobId: limitJob, command: ['sleep', '30'] });
  const imageIndex = invocation.argv.indexOf(GVISOR_IMAGE);
  const detachedArgv = [...invocation.argv];
  detachedArgv.splice(imageIndex, 0, '--detach');
  try {
    run(invocation.executable, detachedArgv, { timeout: 60000 });
    const hostConfig = JSON.parse(wslRoot(['podman', 'inspect', invocation.containerName, '--format', '{{json .HostConfig}}']));
    const runtime = wslRoot(['podman', 'inspect', invocation.containerName, '--format', '{{.OCIRuntime}}']);
    // The host has one explicitly reserved 65,536-ID range for rootful
    // auto-userns. Release the inspection container before executing the
    // independent probes so Podman can reuse that range fail-closed.
    wslRoot(['podman', 'rm', '--force', '--time', '0', invocation.containerName]);
    wslRoot(['podman', 'container', 'exists', invocation.containerName], { expected: 1 });
    const status = hardened(['cat', '/proc/self/status'], 'gvisor-evidence-status');
    const network = hardened(['cat', '/proc/net/dev'], 'gvisor-evidence-network');
    const boot = hardened(['dmesg'], 'gvisor-evidence-dmesg');
    const authorizedSmoke = executeAuthorizedGvisorTool({
      policyEngine: createPolicyEngine({ now: '2026-09-12T12:00:00.000Z' }),
      request: {
        adapter: 'api', principalId: 'prn-platform-experimenter',
        action: 'tool.execute.untrusted', workspaceId: 'ws-veritas-project',
        resource: { type: 'tool', id: 'tool:untrusted-runner' },
        args: {
          tool_id: 'tool:untrusted-runner',
          canonical_args: { argv: ['printf', 'VERITAS_GVISOR_OK'], timeout_ms: 30000 },
        },
        lease: { leaseId: 'lse-experimenter-untrusted-0009', fencingToken: 1 },
      },
      jobId: 'gvisor-authorized-smoke',
    });
    if (authorizedSmoke.status !== 'success' || authorizedSmoke.stdout !== 'VERITAS_GVISOR_OK'
      || authorizedSmoke.cleanupVerified !== true || authorizedSmoke.authorization?.decision !== 'ALLOW') {
      throw new Error('AUTHORIZED_GVISOR_SMOKE_FAILED');
    }
    const uidMap = hostConfig.IDMappings?.UidMap?.[0];
    return {
      schemaVersion: 1,
      profileId: GVISOR_PROFILE_ID,
      boundary: 'WSL2_ROOTFUL_PODMAN_GVISOR_SYSTRAP_AUTO_USERNS',
      distro: GVISOR_DISTRO,
      hostKernel: wslRoot(['uname', '-r']),
      podmanVersion: info.version.Version,
      podmanRootless: info.host.security.rootless,
      image: GVISOR_IMAGE,
      ociRuntime: runtime,
      gvisorVersion: GVISOR_VERSION,
      gvisorRuntimeSha256: runtimeDigest,
      gvisorPlatform: 'systrap',
      runtimeKernel: hardened(['uname', '-r'], 'gvisor-evidence-kernel'),
      gvisorBootMarker: boot.includes('Starting gVisor'),
      autoUserns: uidMap === '0:200000:65536',
      uidMap,
      controls: {
        uid: Number(hardened(['id', '-u'], 'gvisor-evidence-uid')),
        capEff: parseStatusField(status, 'CapEff'),
        rootFsReadOnlyConfigured: hostConfig.ReadonlyRootfs === true,
        rootFsReadOnly: hardened(['touch', '/root-should-fail'], 'gvisor-evidence-rootfs', 1) === '',
        tmpfsWritable: hardened(['touch', '/tmp/ok'], 'gvisor-evidence-tmp') === '',
        networkInterfaces: parseNetworkInterfaces(network),
        noNewPrivileges: Number(parseStatusField(status, 'NoNewPrivs')),
        seccompMode: Number(parseStatusField(status, 'Seccomp')),
        mounts: hostConfig.Binds.length,
        injectedEnvironment: 0,
      },
      limits: {
        pids: hostConfig.PidsLimit,
        memoryBytes: hostConfig.Memory,
        memorySwapBytes: hostConfig.MemorySwap,
        nanoCpus: hostConfig.NanoCpus,
      },
      authorizedBackendSmoke: {
        decision: authorizedSmoke.authorization.decision,
        status: authorizedSmoke.status,
        exitCode: authorizedSmoke.exitCode,
        cleanupVerified: authorizedSmoke.cleanupVerified,
        stdoutSha256: authorizedSmoke.stdoutSha256,
      },
      scope: 'UNTRUSTED_CODE',
      untrustedCodeEnabled: true,
      limitations: [],
    };
  } finally {
    spawnSync('wsl.exe', [
      '-d', GVISOR_DISTRO, '-u', 'root', '--', 'podman', 'rm', '--force', '--time', '0',
      invocation.containerName,
    ], { encoding: 'utf8', shell: false, timeout: 10000, windowsHide: true });
  }
}

const observed = observe();
const observedValidation = verifyGvisorEvidenceRecord(observed);
if (!observedValidation.ok) throw new Error(`OBSERVED_CONTROLS_INVALID:${observedValidation.issues.join(',')}`);

if (process.argv.includes('--write')) {
  const serialized = `${JSON.stringify(observed, null, 2)}\n`;
  fs.writeFileSync(EVIDENCE_PATH, serialized);
  console.log(JSON.stringify({
    ok: true, mode: 'write', path: 'evidence/s2-002-gvisor-sandbox.json',
    sha256: createHash('sha256').update(serialized).digest('hex'), observed,
  }, null, 2));
  process.exit(0);
}

const bytes = fs.readFileSync(EVIDENCE_PATH);
const committed = JSON.parse(bytes.toString('utf8'));
const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const issues = [
  ...verifyGvisorEvidenceRecord(committed).issues,
  ...(JSON.stringify(committed) === JSON.stringify(observed) ? [] : ['observed-record-mismatch']),
  ...(SANDBOX_UNTRUSTED_CODE_GVISOR.os_controls_evidence === digest ? [] : ['profile-evidence-digest-mismatch']),
];
console.log(JSON.stringify({ ok: issues.length === 0, digest, issues, observed }, null, 2));
process.exit(issues.length === 0 ? 0 : 1);
