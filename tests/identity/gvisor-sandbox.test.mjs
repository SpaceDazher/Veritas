import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  GVISOR_IMAGE,
  GVISOR_PROFILE_ID,
  buildGvisorInvocation,
  executeAuthorizedGvisorTool,
  verifyGvisorEvidenceRecord,
} from '../../src/lib/identity/gvisor-sandbox.mjs';
import { SANDBOX_UNTRUSTED_CODE_GVISOR } from '../../src/lib/identity/sandbox-profiles.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const EVIDENCE_PATH = path.join(ROOT, 'evidence/s2-002-gvisor-sandbox.json');

describe('S2-002 gVisor UNTRUSTED_CODE boundary', () => {
  test('builds a shell-free invocation with userspace kernel and auto user namespace', () => {
    const invocation = buildGvisorInvocation({ jobId: 'hostile-001', command: ['printf', 'safe'] });
    assert.ok(invocation.executable.toLowerCase().endsWith('wsl.exe'));
    assert.deepEqual(invocation.argv.slice(0, 7), ['-d', 'Ubuntu-24.04', '-u', 'root', '--', 'podman', 'run']);
    for (const required of [
      'run', '--runtime=/usr/bin/runsc', '--runtime-flag=platform=systrap',
      '--runtime-flag=network=none', '--runtime-flag=host-settings=enforce',
      '--runtime-flag=oci-seccomp', '--userns=auto:size=65536', '--pull=never',
      '--network=none', '--read-only', '--pids-limit=32', '--memory=128m',
      '--memory-swap=128m', '--cpus=0.5', '--user=65534:65534', '--ipc=none',
    ]) assert.ok(invocation.argv.includes(required), required);
    assert.equal(invocation.argv.includes('--volume'), false);
    assert.equal(invocation.argv.includes('--env'), false);
    const imageIndex = invocation.argv.indexOf(GVISOR_IMAGE);
    assert.ok(imageIndex > 0);
    assert.deepEqual(invocation.argv.slice(imageIndex + 1), ['printf', 'safe']);
  });

  test('does not execute without exact gVisor profile and evidence binding', () => {
    let executions = 0;
    const result = executeAuthorizedGvisorTool({
      policyEngine: { authorize: () => ({
        decision: 'ALLOW', document: { context: { sandbox_profile_id: 'forged' } },
      }) },
      request: { action: 'tool.execute.untrusted', args: { canonical_args: { argv: ['id'] } } },
      jobId: 'hostile-002',
      executeImpl: () => { executions += 1; },
    });
    assert.equal(result.status, 'not_authorized');
    assert.equal(executions, 0);
  });

  test('executes only the canonical argv authorized by policy', () => {
    let executed;
    const result = executeAuthorizedGvisorTool({
      policyEngine: { authorize: () => ({
        decision: 'ALLOW',
        document: { context: {
          sandbox_profile_id: GVISOR_PROFILE_ID,
          os_controls_evidence: SANDBOX_UNTRUSTED_CODE_GVISOR.os_controls_evidence,
        } },
      }) },
      request: {
        action: 'tool.execute.untrusted',
        args: { canonical_args: { argv: ['printf', 'AUTHORIZED'], timeout_ms: 4000 } },
      },
      command: ['id'],
      jobId: 'hostile-003',
      executeImpl: (request) => { executed = request; return { status: 'success', exitCode: 0 }; },
    });
    assert.equal(result.status, 'success');
    assert.deepEqual(executed, {
      jobId: 'hostile-003', command: ['printf', 'AUTHORIZED'], timeoutMs: 4000,
    });
  });

  test('tracked evidence is content-addressed and proves gVisor, not the host kernel', () => {
    const bytes = fs.readFileSync(EVIDENCE_PATH);
    const record = JSON.parse(bytes.toString('utf8'));
    const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    assert.equal(SANDBOX_UNTRUSTED_CODE_GVISOR.os_controls_evidence, digest);
    assert.equal(record.runtimeKernel, '4.19.0-gvisor');
    assert.equal(record.gvisorBootMarker, true);
    assert.equal(record.ociRuntime, '/usr/bin/runsc');
    assert.equal(record.gvisorPlatform, 'systrap');
    assert.equal(record.controls.rootFsReadOnlyConfigured, true);
    assert.equal(record.untrustedCodeEnabled, true);
    assert.deepEqual(verifyGvisorEvidenceRecord(record), { ok: true, issues: [] });
  });
});
