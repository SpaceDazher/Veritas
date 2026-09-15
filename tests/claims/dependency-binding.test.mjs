// S2-004 dependency gate tests.
// The real gate must PASS against the repository; mutation tests prove it
// fails closed on unreachable commits, digest drift, unpinned branches,
// payload substitution, verdict mutation and identity collapse. Git access is
// injected, so mutation tests never invoke git themselves.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyDependencyBinding } from '../../scripts/verify-s2-004-dependencies.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RECORD = JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/s2-004-dependency-binding.json'), 'utf8'));

const clone = (value) => JSON.parse(JSON.stringify(value));
const CLOSURE = RECORD.s2_003.closureCommit;
const IMPL = RECORD.s2_003.implementationCommit;

// Deterministic in-memory Git standing in for the real repository.
function makeIo(overrides = {}) {
  const blobs = new Map([
    ...Object.entries(RECORD.s2_003.evidenceReadFromGitBytes ?? {}),
    ...Object.entries(RECORD.s2_003.contractSchemas ?? {}),
  ]);
  const workingTree = new Map([
    ...Object.entries(RECORD.stage1.bindings ?? {}).map(([, b]) => [b.trackedCopy, b]),
  ]);
  const io = {
    git(args) {
      const argv = args.join(' ');
      if (argv === 'rev-parse refs/remotes/origin/main') return overrides.main ?? RECORD.s2_003.canonicalBase;
      if (argv === `cat-file -e ${CLOSURE}^{commit}` || argv === `cat-file -e ${IMPL}^{commit}`) return '';
      if (argv.startsWith('merge-base --is-ancestor ')) {
        const commit = argv.split(' ')[2];
        if (overrides.unreachable === commit) throw new Error('not ancestor');
        return '';
      }
      if (argv.startsWith('rev-parse ')) {
        const ref = argv.slice('rev-parse '.length);
        if (ref.startsWith(`${CLOSURE}:`)) {
          const rel = ref.slice(CLOSURE.length + 1);
          if (overrides.blobDrift === rel) return '0'.repeat(40);
          if (blobs.has(rel)) return blobs.get(rel);
          throw new Error(`bad revision ${ref}`);
        }
        throw new Error(`bad revision ${ref}`);
      }
      throw new Error(`unexpected git call: ${argv}`);
    },
    gitBytes(commit, repoPath) {
      if (overrides.gitBytes) return overrides.gitBytes(commit, repoPath);
      if (commit !== CLOSURE) throw new Error(`bad commit ${commit}`);
      return fs.readFileSync(path.join(ROOT, repoPath));
    },
    readWorkingTreeFile(rel) {
      if (overrides.missingTrackedCopy === rel) throw new Error('ENOENT');
      const binding = workingTree.get(rel);
      if (binding && overrides.trackedCopyDigestDrift === rel) {
        return Buffer.from('{ "drifted": true }\n');
      }
      return fs.readFileSync(path.join(ROOT, rel));
    },
    archiveMode: false,
  };
  return io;
}

describe('S2-004 dependency gate', () => {
  test('the tracked binding record passes the real gate against this repository', () => {
    const result = verifyDependencyBinding(RECORD);
    assert.deepEqual(result.issues, []);
    assert.equal(result.ok, true);
    assert.ok(result.checked >= 30, `too few checks: ${result.checked}`);
  });

  test('origin/main not at the canonical S2-003 base is BLOCKED_DEPENDENCY', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ main: '4b4456a3acbe78371e2afcc75d81da59d2765b53' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('origin/main:not-at-s2-003-canonical-base'));
  });

  test('unreachable closure or implementation commit fails closed', () => {
    for (const commit of [CLOSURE, IMPL]) {
      const result = verifyDependencyBinding(RECORD, makeIo({ unreachable: commit }));
      assert.equal(result.ok, false);
      assert.ok(result.issues.some((i) => i.endsWith('Commit:unreachable-from-main')), commit);
    }
  });

  test('evidence blob drift at the closure commit fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ blobDrift: 'evidence/s2-003-comparison.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('evidence/s2-003-comparison.json:blob-drift'));
  });

  test('a comparison record with collapsed executor identities fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'evidence/s2-003-comparison.json') return fs.readFileSync(path.join(ROOT, repoPath));
        const comparison = JSON.parse(fs.readFileSync(path.join(ROOT, repoPath), 'utf8'));
        comparison.runParameters.run_b.executor = comparison.runParameters.run_a.executor;
        return Buffer.from(JSON.stringify(comparison, null, 2));
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('comparison:executor-identities-identical'));
  });

  test('a decision mismatch in the comparison record fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'evidence/s2-003-comparison.json') return fs.readFileSync(path.join(ROOT, repoPath));
        const comparison = JSON.parse(fs.readFileSync(path.join(ROOT, repoPath), 'utf8'));
        comparison.comparison.decisionMismatches = 3;
        return Buffer.from(JSON.stringify(comparison, null, 2));
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('comparison:decision-mismatches'));
  });

  test('an evaluation report without the PASS_WITH_LIMITS verdict fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'docs/decisions/S2-003-EVALUATION-REPORT.md') return fs.readFileSync(path.join(ROOT, repoPath));
        const report = fs.readFileSync(path.join(ROOT, repoPath), 'utf8');
        return Buffer.from(report.replace('## Verdict: PASS_WITH_LIMITS', '## Verdict: PASS'));
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('evaluation-report:no-pass-with-limits-verdict'));
  });

  test('a report with a dropped carried-limit marker fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'docs/decisions/S2-003-EVALUATION-REPORT.md') return fs.readFileSync(path.join(ROOT, repoPath));
        const report = fs.readFileSync(path.join(ROOT, repoPath), 'utf8');
        return Buffer.from(report.replace('OCR/ASR are fixture-level; no production extraction quality is claimed.', 'OCR/ASR quality is production-grade.'));
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.some((i) => i.startsWith('carried-limits:missing-marker')));
  });

  test('an unconditional PASS verdict is rejected even if limits markers remain', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'docs/decisions/S2-003-EVALUATION-REPORT.md') return fs.readFileSync(path.join(ROOT, repoPath));
        const report = fs.readFileSync(path.join(ROOT, repoPath), 'utf8');
        return Buffer.from(`${report}\n## Verdict: PASS\n`);
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('evaluation-report:unconditional-pass-forbidden'));
  });

  test('a contract schema blob pinned at the wrong digest fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ blobDrift: 'contracts/content-segment.schema.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('contracts/content-segment.schema.json:blob-drift'));
  });

  test('a Stage-1 binding pinned to a branch instead of a commit fails closed', () => {
    const record = clone(RECORD);
    record.stage1.sourceRepository.pinnedCommit = 'main';
    const result = verifyDependencyBinding(record, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('stage1:commit-not-pinned-to-sha'));
    assert.ok(result.issues.includes('stage1:branch-or-path-instead-of-commit'));
  });

  test('a drifted tracked Stage-1 evidence copy fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ trackedCopyDigestDrift: 'evidence/external/s1-011/evaluation-record.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('stage1.s1_011:tracked-copy-digest-drift'));
  });

  test('a missing tracked Stage-1 evidence copy fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ missingTrackedCopy: 'evidence/external/s1-012/evaluation-record.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('stage1.s1_012:tracked-copy-missing'));
  });

  test('payload substitution in a Stage-1 record fails closed', () => {
    const record = clone(RECORD);
    record.stage1.bindings.s1_003.expected.result = 'pass_with_limits';
    const result = verifyDependencyBinding(record, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('stage1.s1_003:result-drift'));
  });

  test('a missing required Stage-1 binding fails closed', () => {
    const record = clone(RECORD);
    delete record.stage1.bindings.s1_012;
    const result = verifyDependencyBinding(record, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('stage1.s1_012:missing-binding'));
  });

  test('a non-object record fails closed', () => {
    const result = verifyDependencyBinding(null, makeIo());
    assert.deepEqual(result, { ok: false, checked: 0, issues: ['record:not-object'] });
  });
});
