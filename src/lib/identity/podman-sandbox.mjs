// S2-002 production-facing LOCAL_RESTRICTED execution backend.
//
// The host launches a rootless Podman container inside a named WSL2 distro.
// The image, distro and every isolation flag are host-owned constants. Callers
// may provide only a bounded argv vector and a validated job id; host mounts,
// environment injection, network access and alternate images are unsupported.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { SANDBOX_LOCAL_RESTRICTED_PODMAN } from './sandbox-profiles.mjs';

export const PODMAN_DISTRO = 'Ubuntu-24.04';
export const PODMAN_IMAGE = 'docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc';
export const PODMAN_PROFILE_ID = 'sbx-podman-local-restricted-v1';

const REQUEST_KEYS = new Set(['jobId', 'command', 'timeoutMs']);
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_OUTPUT_BYTES = 64 * 1024;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function validateRequest(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new TypeError('PODMAN_REQUEST_OBJECT_REQUIRED');
  }
  const unknown = Object.keys(request).filter((key) => !REQUEST_KEYS.has(key));
  if (unknown.length > 0) throw new Error(`PODMAN_REQUEST_UNKNOWN_FIELDS:${unknown.join(',')}`);
  if (!/^[a-z0-9][a-z0-9-]{0,48}$/.test(request.jobId ?? '')) {
    throw new Error('PODMAN_JOB_ID_INVALID');
  }
  if (!Array.isArray(request.command) || request.command.length === 0 || request.command.length > 128) {
    throw new Error('PODMAN_COMMAND_INVALID');
  }
  if (request.command.some((argument, index) => (
    typeof argument !== 'string'
    || argument.includes('\0')
    || argument.length > 4096
    || (index === 0 && argument.length === 0)
  ))) {
    throw new Error('PODMAN_COMMAND_INVALID');
  }
  const totalBytes = request.command.reduce((total, argument) => total + Buffer.byteLength(argument), 0);
  if (totalBytes > 16 * 1024) throw new Error('PODMAN_COMMAND_TOO_LARGE');
  const timeoutMs = request.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DEFAULT_TIMEOUT_MS) {
    throw new Error('PODMAN_TIMEOUT_INVALID');
  }
  return timeoutMs;
}

export function buildPodmanInvocation(request) {
  const timeoutMs = validateRequest(request);
  const containerName = `veritas-${request.jobId}`;
  return Object.freeze({
    executable: 'wsl.exe',
    containerName,
    timeoutMs,
    argv: Object.freeze([
      '-d', PODMAN_DISTRO, '--', 'podman', 'run',
      '--rm',
      `--name=${containerName}`,
      '--pull=never',
      '--network=none',
      '--read-only',
      '--cap-drop', 'all',
      '--security-opt', 'no-new-privileges',
      '--pids-limit=32',
      '--memory=128m',
      '--memory-swap=128m',
      '--cpus=0.5',
      '--user=65534:65534',
      '--ipc=none',
      '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m',
      '--log-driver=none',
      PODMAN_IMAGE,
      ...request.command,
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

export function executePodmanCommand(request, { spawnSyncImpl = spawnSync } = {}) {
  const invocation = buildPodmanInvocation(request);
  const options = {
    encoding: 'utf8',
    env: minimalHostEnvironment(),
    maxBuffer: MAX_OUTPUT_BYTES,
    timeout: invocation.timeoutMs,
    windowsHide: true,
    shell: false,
  };
  const run = spawnSyncImpl(invocation.executable, invocation.argv, options);
  const cleanupArgv = [
    '-d', PODMAN_DISTRO, '--', 'podman', 'rm', '--force', '--time', '0', invocation.containerName,
  ];
  const cleanup = spawnSyncImpl(invocation.executable, cleanupArgv, {
    ...options,
    timeout: 10_000,
  });
  const timedOut = run?.error?.code === 'ETIMEDOUT';
  const cleanupOk = cleanup?.status === 0 || /no such container/i.test(String(cleanup?.stderr ?? ''));
  let status = run?.status === 0 ? 'success' : 'error';
  if (timedOut) status = 'timeout';
  if (!cleanupOk) status = 'cleanup_failed';
  const stdout = bounded(run?.stdout);
  const stderr = bounded(run?.stderr);
  return Object.freeze({
    status,
    summary: status === 'success'
      ? 'Podman sandbox command completed.'
      : `Podman sandbox command terminated with ${status}.`,
    next_actions: status === 'success' ? [] : ['Inspect the bounded stderr digest and do not retry side effects blindly.'],
    artifacts: [],
    exitCode: Number.isInteger(run?.status) ? run.status : null,
    signal: run?.signal ?? null,
    terminated: status !== 'success',
    cleanupVerified: cleanupOk,
    containerName: invocation.containerName,
    profileId: PODMAN_PROFILE_ID,
    image: PODMAN_IMAGE,
    stdout,
    stderr,
    stdoutSha256: sha256(stdout),
    stderrSha256: sha256(stderr),
  });
}

export function executeAuthorizedPodmanTool({
  policyEngine,
  request,
  command,
  jobId,
  timeoutMs,
  executeImpl = executePodmanCommand,
}) {
  if (!policyEngine || typeof policyEngine.authorize !== 'function') {
    throw new TypeError('POLICY_ENGINE_REQUIRED');
  }
  if (request?.action !== 'tool.execute') throw new Error('TOOL_EXECUTE_ACTION_REQUIRED');
  const authorization = policyEngine.authorize(request);
  const context = authorization.document?.context;
  const boundToPodman = context?.sandbox_profile_id === PODMAN_PROFILE_ID
    && context?.os_controls_evidence === SANDBOX_LOCAL_RESTRICTED_PODMAN.os_controls_evidence;
  if (authorization.decision !== 'ALLOW' || !boundToPodman) {
    return Object.freeze({
      status: 'not_authorized',
      summary: `Execution refused: ${authorization.decision}${boundToPodman ? '' : '/UNBOUND_SANDBOX'}.`,
      next_actions: ['Resolve authorization, approval, lease or sandbox policy before retrying.'],
      artifacts: [],
      authorization,
      execution: null,
    });
  }
  const execution = executeImpl({ jobId, command, timeoutMs });
  return Object.freeze({ ...execution, authorization, execution });
}

export function verifyPodmanEvidenceRecord(record) {
  const issues = [];
  if (!record || typeof record !== 'object') return { ok: false, issues: ['record:not-object'] };
  if (record.schemaVersion !== 1) issues.push('schemaVersion');
  if (record.profileId !== PODMAN_PROFILE_ID) issues.push('profileId');
  if (record.boundary !== 'WSL2_ROOTLESS_PODMAN') issues.push('boundary');
  if (record.distro !== PODMAN_DISTRO) issues.push('distro');
  if (record.image !== PODMAN_IMAGE) issues.push('image');
  if (record.rootless !== true) issues.push('rootless');
  if (record.cgroupVersion !== 'v2') issues.push('cgroupVersion');
  for (const controller of ['cpu', 'memory', 'pids']) {
    if (!record.cgroupControllers?.includes(controller)) issues.push(`cgroup:${controller}`);
  }
  if (record.controls?.uid !== 65534) issues.push('uid');
  if (record.controls?.capEff !== '0000000000000000') issues.push('capEff');
  if (record.controls?.rootFsReadOnly !== true) issues.push('rootFsReadOnly');
  if (record.controls?.tmpfsWritable !== true) issues.push('tmpfsWritable');
  if (JSON.stringify(record.controls?.networkInterfaces) !== JSON.stringify(['lo'])) issues.push('networkInterfaces');
  if (record.controls?.noNewPrivileges !== 1) issues.push('noNewPrivileges');
  if (record.controls?.seccompMode !== 2) issues.push('seccompMode');
  if (record.controls?.mounts !== 0 || record.controls?.injectedEnvironment !== 0) issues.push('hostInputs');
  if (record.limits?.pids !== 32 || record.limits?.memoryBytes !== 134217728
    || record.limits?.nanoCpus !== 500000000) issues.push('limits');
  if (record.authorizedBackendSmoke?.decision !== 'ALLOW'
    || record.authorizedBackendSmoke?.status !== 'success'
    || record.authorizedBackendSmoke?.exitCode !== 0
    || record.authorizedBackendSmoke?.cleanupVerified !== true
    || record.authorizedBackendSmoke?.stdoutSha256 !== sha256('VERITAS_SANDBOX_OK')) {
    issues.push('authorizedBackendSmoke');
  }
  if (record.scope !== 'LOCAL_RESTRICTED') issues.push('scope');
  if (record.untrustedCodeEnabled !== false) issues.push('untrustedCodeEnabled');
  return { ok: issues.length === 0, issues };
}
