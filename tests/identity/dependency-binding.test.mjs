import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyDependencyBinding } from '../../scripts/verify-s2-002-dependencies.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RECORD = JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/s2-002-dependency-binding.json'), 'utf8'));

const clone = (value) => JSON.parse(JSON.stringify(value));

describe('S2-002 portable dependency gate', () => {
  test('the committed dependency record verifies from repository-relative/public bindings', () => {
    assert.deepEqual(verifyDependencyBinding(RECORD, ROOT), { ok: true, verified: 4, issues: [] });
  });

  test('absolute host paths are rejected', () => {
    const candidate = clone(RECORD);
    candidate.dependencies[1].evaluationRecordPath = 'D:/private/AgentOS/evaluation-record.json';
    const result = verifyDependencyBinding(candidate, ROOT);
    assert.equal(result.ok, false);
    assert.ok(result.issues.some((issue) => issue.includes('absolute-path')));
  });

  test('missing dependency, malformed digest and unpinned source fail closed', () => {
    const missing = clone(RECORD);
    missing.dependencies.pop();
    assert.equal(verifyDependencyBinding(missing, ROOT).ok, false);

    const digest = clone(RECORD);
    digest.dependencies[1].evaluationRecordSha256 = 'not-a-digest';
    assert.equal(verifyDependencyBinding(digest, ROOT).ok, false);

    const unpinned = clone(RECORD);
    unpinned.dependencies[1].sourceCommit = 'main';
    assert.equal(verifyDependencyBinding(unpinned, ROOT).ok, false);
  });

  test('clean-checkout verifies the root manifest before evidence-producing commands', () => {
    const source = fs.readFileSync(path.join(ROOT, 'scripts/verify-clean-checkout.mjs'), 'utf8');
    const manifest = source.indexOf("run('root-manifest'");
    assert.ok(manifest >= 0);
    for (const command of ["run('contracts'", "run('synthetic-smoke'", "run('public-artifacts'"]) {
      assert.ok(manifest < source.indexOf(command), `${command} must follow root-manifest verification`);
    }
  });
});
