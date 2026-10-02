import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { snapshotA05Artifacts, replayA05Journal, buildA05Task, createA05Workflow } from '../../scripts/a-mvp05-runtime.mjs';

test('artifact snapshot measures bytes and refuses traversal, symlinks and duplicates', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'a05-artifact-'));
  try {
    fs.writeFileSync(path.join(root, 'README.md'), 'before\n');
    const before = snapshotA05Artifacts(root, ['README.md']);
    fs.writeFileSync(path.join(root, 'README.md'), 'after\n');
    assert.notDeepEqual(before, snapshotA05Artifacts(root, ['README.md']));
    assert.throws(() => snapshotA05Artifacts(root, ['../outside']), /ARTIFACT_PATH/);
    assert.throws(() => snapshotA05Artifacts(root, ['README.md', 'README.md']), /ARTIFACT_PATH/);
    fs.symlinkSync('README.md', path.join(root, 'link'));
    assert.throws(() => snapshotA05Artifacts(root, ['link']), /ARTIFACT/);
  } finally { fs.rmSync(root, { recursive: true }); }
});

test('journal replay derives state and revision, refuses gaps and modified payload', () => {
  const row = {
    transition_id: 'trn-test-1', from_state: 'BACKLOG', to_state: 'READY',
    revision: 2, payload: {}, payload_digest: canonicalDigest({}),
    brief_digest: 'a'.repeat(64), policy_digest: 'b'.repeat(64), manifest_digest: 'c'.repeat(64),
  };
  const task = {
    state: 'READY', revision: 2, history_digest: 'sha256:' + canonicalDigest(['trn-test-1']),
    brief_digest: 'sha256:' + row.brief_digest, policy_digest: 'sha256:' + row.policy_digest,
    manifest_digest: 'sha256:' + row.manifest_digest,
  };
  assert.equal(replayA05Journal(task, [row]).ok, true);
  assert.throws(() => replayA05Journal(task, [{ ...row, revision: 3 }]), /JOURNAL/);
  assert.throws(() => replayA05Journal(task, [{ ...row, payload: { forged: true } }]), /JOURNAL/);
  assert.throws(() => replayA05Journal({ ...task, state: 'DONE' }, [row]), /JOURNAL/);
});

test('journal replay refuses changed document bindings even if state matches', () => {
  const row = {
    transition_id: 'trn-test-1', from_state: 'BACKLOG', to_state: 'READY', revision: 2,
    payload: {}, payload_digest: canonicalDigest({}), brief_digest: 'a'.repeat(64),
    policy_digest: 'b'.repeat(64), manifest_digest: 'c'.repeat(64),
  };
  const task = { state: 'READY', revision: 2, history_digest: 'sha256:' + canonicalDigest(['trn-test-1']),
    brief_digest: 'sha256:' + '0'.repeat(64), policy_digest: 'sha256:' + row.policy_digest,
    manifest_digest: 'sha256:' + row.manifest_digest };
  assert.throws(() => replayA05Journal(task, [row]), /JOURNAL/);
});

test('local task is valid against frozen board contract before any store mutation', () => {
  const ticket = {
    taskId:'abt-a05-schema', workspaceId:'ws-a05-schema', principalId:'prn-a05-human', producerId:'prn-a05-worker',
    imageId:'sha256:'+'d'.repeat(64), baseline:[], runner_sha256:'e'.repeat(64),
    brief:{title:'Local change',runner:'Actual local Node wrapper',acceptance:'Existing tests pass'},
  };
  const registration = {declared_capabilities:['task.read','artifact.write'],declared_tools:['tool:fs.read']};
  const task = buildA05Task(ticket, registration, new Date().toISOString());
  assert.equal(task.workspace_ref.root_ref,'project');
  assert.equal(task.cost_limits.currency,'USD');
  assert.equal(task.acl.visibility,'personal');
});

test('separate workflow instances do not reuse durable audit IDs or a fixed epoch', () => {
  const a = createA05Workflow({ pool: {}, ticket: {} }).store;
  const b = createA05Workflow({ pool: {}, ticket: {} }).store;
  assert.notEqual(a.newId('audit'), b.newId('audit'));
  assert.ok(Math.abs(Date.now() - new Date(a.clock()).getTime()) < 2000);
});
