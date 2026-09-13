// S2-003 dependency gate tests.
// The real gate must PASS against the repository; mutation tests prove it
// fails closed on unreachable commits, digest drift, unpinned branches and
// payload substitution. Git access is injected, so these tests never invoke
// git themselves (except through the injected stubs).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyDependencyBinding } from '../../scripts/verify-s2-003-dependencies.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RECORD = JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/s2-003-dependency-binding.json'), 'utf8'));

const clone = (value) => JSON.parse(JSON.stringify(value));
const MERGE = RECORD.s2_002.mergeCommit;
const CLOSURE = RECORD.s2_002.closureCommit;

// Deterministic in-memory Git standing in for the real repository.
function makeIo(overrides = {}) {
  const blobs = new Map(Object.entries(RECORD.s2_002.evidenceReadFromGitBytes));
  const io = {
    git(args) {
      const argv = args.join(' ');
      if (argv === 'rev-parse refs/remotes/origin/main') return overrides.main ?? MERGE;
      if (argv === `cat-file -e ${MERGE}^{commit}` || argv === `cat-file -e ${CLOSURE}^{commit}`) return '';
      if (argv.startsWith('merge-base --is-ancestor ')) {
        const commit = argv.split(' ')[2];
        if (overrides.unreachable === commit) throw new Error('not ancestor');
        return '';
      }
      if (argv.startsWith('rev-parse ')) {
        const ref = argv.slice('rev-parse '.length);
        if (blobs.has(ref.slice(CLOSURE.length + 1))) return blobs.get(ref.slice(CLOSURE.length + 1));
        throw new Error(`bad revision ${ref}`);
      }
      throw new Error(`unexpected git call: ${argv}`);
    },
    gitBytes(commit, repoPath) {
      if (overrides.gitBytes) return overrides.gitBytes(commit, repoPath);
      if (repoPath === 'evidence/frozen-manifest.json') {
        // minimal stand-in with verifiable sha256 recorded in the real record
        return Buffer.from('{}\n');
      }
      if (commit !== CLOSURE && commit !== MERGE) throw new Error(`bad commit ${commit}`);
      const file = path.join(ROOT, repoPath);
      return fs.readFileSync(file);
    },
    readWorkingTreeFile(rel) {
      return fs.readFileSync(path.join(ROOT, rel));
    },
  };
  return io;
}

describe('S2-003 dependency gate', () => {
  test('the committed binding record verifies against the real repository', () => {
    const result = verifyDependencyBinding(RECORD);
    assert.equal(result.ok, true, `issues: ${result.issues.join('; ')}`);
    assert.ok(result.checked >= 20);
    assert.deepEqual(result.issues, []);
  });

  test('origin/main drift from the S2-002 merge commit fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ main: '0'.repeat(40) }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('origin/main:not-at-s2-002-merge'));
  });

  test('an unreachable S2-002 commit fails closed, not as a warning', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ unreachable: CLOSURE }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('s2-002.closureCommit:unreachable-from-main'));
  });

  test('blob digest drift on S2-002 evidence fails closed', () => {
    const io = makeIo();
    const mutated = clone(RECORD);
    const firstEvidence = Object.keys(mutated.s2_002.evidenceReadFromGitBytes)[0];
    mutated.s2_002.evidenceReadFromGitBytes[firstEvidence] = '1'.repeat(40);
    const result = verifyDependencyBinding(mutated, io);
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes(`${firstEvidence}:blob-drift`));
  });

  test('a missing evidence file at the closure commit fails closed', () => {
    const mutated = clone(RECORD);
    mutated.s2_002.evidenceReadFromGitBytes['evidence/deleted-file.json'] = '2'.repeat(40);
    const result = verifyDependencyBinding(mutated, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('evidence/deleted-file.json:missing-at-closure-commit'));
  });

  test('frozen-manifest payload substitution fails closed', () => {
    const realFrozen = fs.readFileSync(path.join(ROOT, 'evidence/frozen-manifest.json'));
    const substituted = Buffer.from(JSON.stringify({
      ...JSON.parse(realFrozen.toString('utf8')),
      scope: 'TAMPERED',
    }));
    const io = makeIo({ gitBytes: (commit, repoPath) => (repoPath === 'evidence/frozen-manifest.json' ? substituted : fs.readFileSync(path.join(ROOT, repoPath))) });
    const result = verifyDependencyBinding(RECORD, io);
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('frozen-manifest:sha256-drift'));
  });

  test('S1-001 bound to a branch name or temp path instead of a commit SHA is rejected', () => {
    for (const pinned of ['main', 'research/tickets/tmp', '259d9af'.padEnd(40, 'g')]) {
      const mutated = clone(RECORD);
      mutated.s1_001.sourceRepository.pinnedCommit = pinned;
      const result = verifyDependencyBinding(mutated, makeIo());
      assert.equal(result.ok, false, `pinned=${pinned}`);
      assert.ok(result.issues.some((issue) => issue.startsWith('s1-001:')), `pinned=${pinned}`);
    }
  });

  test('S1-001 tracked evidence digest drift fails closed', () => {
    const mutated = clone(RECORD);
    mutated.s1_001.evaluationRecordSha256 = 'e'.repeat(64);
    const result = verifyDependencyBinding(mutated, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('s1-001:tracked-copy-digest-drift'));
  });

  test('a missing S1-001 dependency fails closed', () => {
    const mutated = clone(RECORD);
    mutated.s1_001.trackedCopy = 'evidence/external/s1-001/missing.json';
    const result = verifyDependencyBinding(mutated, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('s1-001:tracked-copy-missing'));
  });

  test('an incomplete digest (not full SHA-256) fails closed', () => {
    const mutated = clone(RECORD);
    mutated.s1_001.evaluationRecordSha256 = mutated.s1_001.evaluationRecordSha256.slice(0, 32);
    const result = verifyDependencyBinding(mutated, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('s1-001:invalid-record-digest'));
  });

  test('the gate never returns ok:true with outstanding issues', () => {
    const result = verifyDependencyBinding({}, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.length > 0);
  });
});
