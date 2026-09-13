// S2-002 UNTRUSTED_CODE execution backend.
//
// Windows launches a fixed rootful Podman command inside the named WSL2 VM.
// The workload runs behind gVisor's systrap userspace kernel and a separate
// Podman auto-userns mapping. Rootful Podman is used only so cgroup v2 limits
// remain enforced; every privileged launcher input is a host-owned constant.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { normalizePodmanCanonicalArgs } from './podman-sandbox.mjs';
import { SANDBOX_UNTRUSTED_CODE_GVISOR } from './sandbox-profiles.mjs';

export const GVISOR_DISTRO = 'Ubuntu-24.04';
export const GVISOR_IMAGE = 'docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc';
export const GVISOR_PROFILE_ID = 'sbx-gvisor-untrusted-v1';
export const GVISOR_RUNTIME = '/usr/bin/runsc';
export const GVISOR_VERSION = 'release-20260907.0';
export const GVISOR_RUNTIME_SHA256 = '3e0df2fa28f6ff5430b004f92573b81b75f442f78c780e0c85fdf6c2d572817a';

const REQUEST_KEYS = new Set(['jobId', 'command', 'timeoutMs']);
const MAX_OUTPUT_BYTES = 64 * 1024;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function normalizeRequest(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new TypeError('GVISOR_REQUEST_OBJECT_REQUIRED');
  }
  if (Object.keys(request).some((key) => !REQUEST_KEYS.has(key))) {
    throw new Error('GVISOR_REQUEST_UNKNOWN_FIELDS');
  }
  if (!/^[a-z0-9][a-z0-9-]{0,48}$/.test(request.jobId ?? '')) {
    throw new Error('GVISOR_JOB_ID_INVALID');
  }
  const canonical = normalizePodmanCanonicalArgs({
    argv: request.command,
    timeout_ms: request.timeoutMs,
  });
  return canonical;
}

export function buildGvisorInvocation(request) {
  const canonical = normalizeRequest(request);
  const containerName = `veritas-untrusted-${request.jobId}`;
  return Object.freeze({
    executable: 'wsl.exe',
    containerName,
    timeoutMs: canonical.timeoutMs,
    argv: Object.freeze([
      '-d', GVISOR_DISTRO, '-u', 'root', '--', 'podman', 'run',
      '--rm',
      `--name=${containerName}`,
      `--runtime=${GVISOR_RUNTIME}`,
      '--runtime-flag=platform=systrap',
      '--runtime-flag=network=none',
      '--runtime-flag=host-settings=enforce',
      '--runtime-flag=oci-seccomp',
      '--pull=never',
      '--network=none',
      '--read-only',
      '--cap-drop', 'all',
      '--security-opt', 'no-new-privileges',
      '--userns=auto:size=65536',
      '--pids-limit=32',
      '--memory=128m',
      '--memory-swap=128m',
      '--cpus=0.5',
      '--user=65534:65534',
      '--ipc=none',
      '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m',
      '--log-driver=none',
      GVISOR_IMAGE,
      ...canonical.command,
    ]),
  });
}

function minimalHostEnvironment(source = process.env) {
  const env = {};
  for (const key of ['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP']) {
    if (typeof source[key] === 'string') env[key] = source[key];
  }
  return env;
}

function bounded(value) {
  return String(value ?? '').slice(0, MAX_OUTPUT_BYTES);
}

export function executeGvisorCommand(request, { spawnSyncImpl = spawnSync } = {}) {
  const invocation = buildGvisorInvocation(request);
  const options = {
    encoding: 'utf8', env: minimalHostEnvironment(), maxBuffer: MAX_OUTPUT_BYTES,
    timeout: invocation.timeoutMs, windowsHide: true, shell: false,
  };
  const run = spawnSyncImpl(invocation.executable, invocation.argv, options);
  const cleanup = spawnSyncImpl(invocation.executable, [
    '-d', GVISOR_DISTRO, '-u', 'root', '--', 'podman', 'rm', '--force', '--time', '0',
    invocation.containerName,
  ], { ...options, timeout: 10_000 });
  const timedOut = run?.error?.code === 'ETIMEDOUT';
  const cleanupOk = cleanup?.status === 0 || /no such (?:container|object)/i.test(String(cleanup?.stderr ?? ''));
  let status = run?.status === 0 ? 'success' : 'error';
  if (timedOut) status = 'timeout';
  if (!cleanupOk) status = 'cleanup_failed';
  const stdout = bounded(run?.stdout);
  const stderr = bounded(run?.stderr);
  return Object.freeze({
    status,
    summary: status === 'success' ? 'gVisor sandbox command completed.' : `gVisor sandbox command terminated with ${status}.`,
    next_actions: status === 'success' ? [] : ['Inspect the bounded stderr digest; never blind-retry side effects.'],
    artifacts: [],
    exitCode: Number.isInteger(run?.status) ? run.status : null,
    signal: run?.signal ?? null,
    terminated: status !== 'success',
    cleanupVerified: cleanupOk,
    containerName: invocation.containerName,
    profileId: GVISOR_PROFILE_ID,
    image: GVISOR_IMAGE,
    stdout,
    stderr,
    stdoutSha256: sha256(stdout),
    stderrSha256: sha256(stderr),
  });
}

export function executeAuthorizedGvisorTool({ policyEngine, request, jobId, executeImpl = executeGvisorCommand }) {
  if (!policyEngine || typeof policyEngine.authorize !== 'function') throw new TypeError('POLICY_ENGINE_REQUIRED');
  if (request?.action !== 'tool.execute.untrusted') throw new Error('UNTRUSTED_TOOL_EXECUTE_ACTION_REQUIRED');
  const authorization = policyEngine.authorize(request);
  const context = authorization.document?.context;
  const bound = context?.sandbox_profile_id === GVISOR_PROFILE_ID
    && context?.os_controls_evidence === SANDBOX_UNTRUSTED_CODE_GVISOR.os_controls_evidence;
  if (authorization.decision !== 'ALLOW' || !bound) {
    return Object.freeze({
      status: 'not_authorized',
      summary: `Execution refused: ${authorization.decision}${bound ? '' : '/UNBOUND_SANDBOX'}.`,
      next_actions: ['Resolve exact authorization and gVisor evidence binding before retrying.'],
      artifacts: [], authorization, execution: null,
    });
  }
  let canonical;
  try {
    canonical = normalizePodmanCanonicalArgs(request.args?.canonical_args);
  } catch {
    return Object.freeze({
      status: 'not_authorized',
      summary: 'Execution refused: ALLOW/INVALID_CANONICAL_ARGS.',
      next_actions: ['Re-authorize exact canonical argv and timeout.'],
      artifacts: [], authorization, execution: null,
    });
  }
  const execution = executeImpl({ jobId, command: canonical.command, timeoutMs: canonical.timeoutMs });
  return Object.freeze({ ...execution, authorization, execution });
}

export function verifyGvisorEvidenceRecord(record) {
  const issues = [];
  if (!record || typeof record !== 'object') return { ok: false, issues: ['record:not-object'] };
  if (record.schemaVersion !== 1) issues.push('schemaVersion');
  if (record.profileId !== GVISOR_PROFILE_ID) issues.push('profileId');
  if (record.boundary !== 'WSL2_ROOTFUL_PODMAN_GVISOR_SYSTRAP_AUTO_USERNS') issues.push('boundary');
  if (record.distro !== GVISOR_DISTRO || record.image !== GVISOR_IMAGE) issues.push('hostBinding');
  if (record.gvisorVersion !== GVISOR_VERSION || record.gvisorRuntimeSha256 !== GVISOR_RUNTIME_SHA256) issues.push('gvisorBinary');
  if (record.ociRuntime !== GVISOR_RUNTIME || record.gvisorPlatform !== 'systrap') issues.push('runtimeBinding');
  if (record.runtimeKernel !== '4.19.0-gvisor' || record.gvisorBootMarker !== true) issues.push('userspaceKernel');
  if (record.podmanRootless !== false || record.autoUserns !== true || record.uidMap !== '0:200000:65536') issues.push('outerUserNamespace');
  if (record.controls?.uid !== 65534 || record.controls?.capEff !== '0000000000000000') issues.push('identity');
  if (record.controls?.rootFsReadOnlyConfigured !== true
    || record.controls?.rootFsReadOnly !== true || record.controls?.tmpfsWritable !== true) issues.push('filesystem');
  if (JSON.stringify(record.controls?.networkInterfaces) !== JSON.stringify(['lo'])) issues.push('network');
  if (record.controls?.noNewPrivileges !== 1 || record.controls?.seccompMode !== 2) issues.push('syscallControls');
  if (record.controls?.mounts !== 0 || record.controls?.injectedEnvironment !== 0) issues.push('hostInputs');
  if (record.limits?.pids !== 32 || record.limits?.memoryBytes !== 134217728
    || record.limits?.memorySwapBytes !== 134217728 || record.limits?.nanoCpus !== 500000000) issues.push('limits');
  if (record.authorizedBackendSmoke?.decision !== 'ALLOW'
    || record.authorizedBackendSmoke?.status !== 'success'
    || record.authorizedBackendSmoke?.exitCode !== 0
    || record.authorizedBackendSmoke?.cleanupVerified !== true
    || record.authorizedBackendSmoke?.stdoutSha256 !== sha256('VERITAS_GVISOR_OK')) issues.push('authorizedBackendSmoke');
  if (record.scope !== 'UNTRUSTED_CODE' || record.untrustedCodeEnabled !== true) issues.push('scope');
  return { ok: issues.length === 0, issues };
}
