import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  PODMAN_IMAGE,
  buildPodmanInvocation,
  executeAuthorizedPodmanTool,
  executePodmanCommand,
  verifyPodmanEvidenceRecord,
} from '../../src/lib/identity/podman-sandbox.mjs';
import { SANDBOX_LOCAL_RESTRICTED_PODMAN } from '../../src/lib/identity/sandbox-profiles.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const EVIDENCE_PATH = path.join(ROOT, 'evidence/s2-002-podman-sandbox.json');

describe('S2-002 WSL2/rootless Podman sandbox contract', () => {
  test('builds one shell-free, pinned, deny-by-default invocation', () => {
    const invocation = buildPodmanInvocation({ jobId: 'job-001', command: ['printf', 'hello'] });
    assert.ok(invocation.executable.toLowerCase().endsWith('wsl.exe'));
    assert.deepEqual(invocation.argv.slice(0, 5), ['-d', 'Ubuntu-24.04', '--', 'podman', 'run']);
    assert.ok(invocation.argv.includes('--pull=never'));
    assert.ok(invocation.argv.includes('--network=none'));
    assert.ok(invocation.argv.includes('--read-only'));
    assert.deepEqual(invocation.argv.slice(invocation.argv.indexOf('--cap-drop') + 1, invocation.argv.indexOf('--cap-drop') + 2), ['all']);
    assert.ok(invocation.argv.includes('no-new-privileges'));
    assert.ok(invocation.argv.includes('--pids-limit=32'));
    assert.ok(invocation.argv.includes('--memory=128m'));
    assert.ok(invocation.argv.includes('--cpus=0.5'));
    assert.ok(invocation.argv.includes('--user=65534:65534'));
    assert.equal(invocation.argv.includes('--volume'), false);
    assert.equal(invocation.argv.includes('--env'), false);
    const imageIndex = invocation.argv.indexOf(PODMAN_IMAGE);
    assert.ok(imageIndex > 0);
    assert.deepEqual(invocation.argv.slice(imageIndex + 1), ['printf', 'hello']);
  });

  test('rejects alternate images, host mounts, invalid IDs and malformed command argv', () => {
    for (const request of [
      { jobId: 'job-1', command: ['id'], image: 'docker.io/library/ubuntu:latest' },
      { jobId: 'job-1', command: ['id'], volumes: ['D:/secrets:/secrets'] },
      { jobId: '../escape', command: ['id'] },
      { jobId: 'job-1', command: [] },
      { jobId: 'job-1', command: ['sh\0evil'] },
      { jobId: 'job-1', command: [42] },
    ]) {
      assert.throws(() => buildPodmanInvocation(request));
    }
  });

  test('execution returns deterministic harness observations and always performs exact cleanup', () => {
    const calls = [];
    const fake = (executable, argv, options) => {
      calls.push({ executable, argv, options });
      if (argv.includes('run')) return { status: 0, stdout: 'ok\n', stderr: '', signal: null };
      return { status: 0, stdout: '', stderr: '', signal: null };
    };
    const result = executePodmanCommand({ jobId: 'job-002', command: ['printf', 'ok'] }, { spawnSyncImpl: fake });
    assert.equal(result.status, 'success');
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, 'ok\n');
    assert.deepEqual(result.next_actions, []);
    assert.equal(calls.length, 2);
    assert.ok(calls[1].argv.includes('rm'));
    assert.ok(calls[1].argv.includes('veritas-job-002'));
    assert.equal(calls.every((call) => call.options.shell === false), true);
  });

  test('timeout is terminal, cleaned up and never reported as success', () => {
    const calls = [];
    const fake = (executable, argv, options) => {
      calls.push({ executable, argv, options });
      if (argv.includes('run')) {
        const error = new Error('timed out');
        error.code = 'ETIMEDOUT';
        return { status: null, stdout: '', stderr: '', signal: 'SIGTERM', error };
      }
      return { status: 0, stdout: '', stderr: '', signal: null };
    };
    const result = executePodmanCommand({ jobId: 'job-timeout', command: ['sleep', '60'], timeoutMs: 10 }, { spawnSyncImpl: fake });
    assert.equal(result.status, 'timeout');
    assert.equal(result.terminated, true);
    assert.notEqual(result.status, 'success');
    assert.ok(calls[1].argv.includes('rm'));
  });

  test('authorization denial never reaches Podman; allow executes through the fixed runner', () => {
    let executions = 0;
    const denied = executeAuthorizedPodmanTool({
      policyEngine: { authorize: () => ({ decision: 'DENY', reasonCodes: ['NO_ACCESS'] }) },
      request: { action: 'tool.execute' },
      command: ['id'],
      jobId: 'job-denied',
      executeImpl: () => { executions += 1; },
    });
    assert.equal(denied.status, 'not_authorized');
    assert.equal(executions, 0);

    const allowed = executeAuthorizedPodmanTool({
      policyEngine: { authorize: () => ({
        decision: 'ALLOW',
        reasonCodes: ['GRANT_VALID'],
        document: {
          context: {
            sandbox_profile_id: SANDBOX_LOCAL_RESTRICTED_PODMAN.profile_id,
            os_controls_evidence: SANDBOX_LOCAL_RESTRICTED_PODMAN.os_controls_evidence,
          },
        },
      }) },
      request: { action: 'tool.execute' },
      command: ['id'],
      jobId: 'job-allowed',
      executeImpl: () => { executions += 1; return { status: 'success', exitCode: 0 }; },
    });
    assert.equal(allowed.status, 'success');
    assert.equal(executions, 1);

    const unbound = executeAuthorizedPodmanTool({
      policyEngine: { authorize: () => ({ decision: 'ALLOW', reasonCodes: ['FORGED_ALLOW'], document: { context: {} } }) },
      request: { action: 'tool.execute' },
      command: ['id'],
      jobId: 'job-unbound',
      executeImpl: () => { executions += 1; return { status: 'success' }; },
    });
    assert.equal(unbound.status, 'not_authorized');
    assert.equal(executions, 1, 'an ALLOW without exact sandbox evidence must never execute');
  });

  test('tracked OS evidence is content-addressed by the registered profile', () => {
    const bytes = fs.readFileSync(EVIDENCE_PATH);
    const record = JSON.parse(bytes.toString('utf8'));
    const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    assert.equal(SANDBOX_LOCAL_RESTRICTED_PODMAN.os_controls_evidence, digest);
    assert.deepEqual(verifyPodmanEvidenceRecord(record), { ok: true, issues: [] });
  });
});
