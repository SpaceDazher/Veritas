// S2-005 dependency gate tests.
// The real gate must PASS against the repository; mutation tests prove it
// fails closed on unreachable commits, digest drift, unpinned branches,
// payload substitution, verdict mutation, identity collapse, executable/main
// contract drift and unpinned consumer inputs. Git access is injected, so
// mutation tests never invoke git themselves.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyDependencyBinding } from '../../scripts/verify-s2-005-dependencies.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RECORD = JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/s2-005-dependency-binding.json'), 'utf8'));

const clone = (value) => JSON.parse(JSON.stringify(value));
const CLOSURE = RECORD.s2_004.closureCommit;
const IMPL = RECORD.s2_004.implementationCommit;
const BASE = RECORD.s2_004.canonicalBase;

// Deterministic in-memory Git standing in for the real repository.
function makeIo(overrides = {}) {
  const blobs = new Map([
    ...Object.entries(RECORD.s2_004.evidenceReadFromGitBytes ?? {}),
    ...Object.entries(RECORD.s2_004.contractSchemas ?? {}),
  ]);
  const workingTree = new Map([
    ...Object.entries(RECORD.stage1.bindings ?? {}).map(([, b]) => [b.trackedCopy, b]),
    ...Object.keys(RECORD.s2_004.contractSchemas ?? {}).map((rel) => [rel, null]),
  ]);
  const io = {
    git(args) {
      const argv = args.join(' ');
      if (argv === 'rev-parse refs/remotes/origin/main') return overrides.main ?? RECORD.s2_004.canonicalBase;
      if (argv === `cat-file -e ${CLOSURE}^{commit}` || argv === `cat-file -e ${IMPL}^{commit}` || argv === `cat-file -e ${BASE}^{commit}`) return '';
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
        if (ref.startsWith('refs/remotes/origin/main:')) {
          const rel = ref.slice('refs/remotes/origin/main:'.length);
          if (overrides.mainBlobDrift === rel) return 'f'.repeat(40);
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
      if (overrides.trackedCopyDigestDrift === rel) {
        return Buffer.from('{ "drifted": true }\n');
      }
      if (overrides.executableDrift === rel) {
        return Buffer.from('{ "contractVersion": { "const": "9.9.9" } }\n');
      }
      if (binding || fs.existsSync(path.join(ROOT, rel))) {
        return fs.readFileSync(path.join(ROOT, rel));
      }
      throw new Error('ENOENT');
    },
    archiveMode: false,
  };
  return io;
}

describe('S2-005 dependency gate', () => {
  const ARCHIVE = !fs.existsSync(path.join(ROOT, '.git'));

  test('the tracked binding record passes the real gate against this repository', () => {
    const result = verifyDependencyBinding(RECORD);
    if (ARCHIVE) {
      // git-archive checkouts have no .git: byte-level verification is
      // impossible there and the gate must fail closed (not silently pass).
      assert.equal(result.ok, false);
      assert.ok(result.issues.length > 0);
      return;
    }

    assert.deepEqual(result.issues, []);
    assert.equal(result.ok, true);
    assert.ok(result.checked >= 40, `too few checks: ${result.checked}`);
  });

  test('origin/main without the canonical S2-004 base in its history is BLOCKED_DEPENDENCY', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ unreachable: BASE }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.some((i) => i.endsWith('Commit:unreachable-from-main')));
  });

  test('unreachable closure or implementation commit fails closed', () => {
    for (const commit of [CLOSURE, IMPL]) {
      const result = verifyDependencyBinding(RECORD, makeIo({ unreachable: commit }));
      assert.equal(result.ok, false);
      assert.ok(result.issues.some((i) => i.endsWith('Commit:unreachable-from-main')), commit);
    }
  });

  test('evidence blob drift at the closure commit fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ blobDrift: 'evidence/s2-004-comparison.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('evidence/s2-004-comparison.json:blob-drift'));
  });

  test('a comparison record with collapsed executor identities fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'evidence/s2-004-comparison.json') return fs.readFileSync(path.join(ROOT, repoPath));
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
        if (repoPath !== 'evidence/s2-004-comparison.json') return fs.readFileSync(path.join(ROOT, repoPath));
        const comparison = JSON.parse(fs.readFileSync(path.join(ROOT, repoPath), 'utf8'));
        comparison.comparison.decisionMismatches = 3;
        return Buffer.from(JSON.stringify(comparison, null, 2));
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('comparison:decision-mismatches'));
  });

  test('a nonzero hard-gate integrity counter (stale survivor) fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'evidence/s2-004-comparison.json') return fs.readFileSync(path.join(ROOT, repoPath));
        const comparison = JSON.parse(fs.readFileSync(path.join(ROOT, repoPath), 'utf8'));
        comparison.integrity.run_a.stale_survivors = 2;
        comparison.integrity.run_b.stale_survivors = 2;
        return Buffer.from(JSON.stringify(comparison, null, 2));
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('comparison:stale-survivors'));
  });

  test('an evaluation report without the PASS_WITH_LIMITS verdict fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'docs/decisions/S2-004-EVALUATION-REPORT.md') return fs.readFileSync(path.join(ROOT, repoPath));
        const report = fs.readFileSync(path.join(ROOT, repoPath), 'utf8');
        return Buffer.from(report.replace('## Verdict: PASS_WITH_LIMITS', '## Verdict: BLOCKED'));
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('evaluation-report:no-pass-with-limits-verdict'));
  });

  test('a report with a dropped carried-limit marker fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'docs/decisions/S2-004-EVALUATION-REPORT.md') return fs.readFileSync(path.join(ROOT, repoPath));
        const report = fs.readFileSync(path.join(ROOT, repoPath), 'utf8');
        return Buffer.from(report.replace(
          'No causality from correlation, analogy or expert authority; a lens is\n  ranking-only.',
          'Causal conclusions are permitted when an expert lens agrees.'
        ));
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.some((i) => i.startsWith('carried-limits:missing-marker')));
  });

  test('an unconditional PASS verdict is rejected even if limits markers remain', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({
      gitBytes(commit, repoPath) {
        if (repoPath !== 'docs/decisions/S2-004-EVALUATION-REPORT.md') return fs.readFileSync(path.join(ROOT, repoPath));
        const report = fs.readFileSync(path.join(ROOT, repoPath), 'utf8');
        return Buffer.from(`${report}\n## Verdict: PASS\n`);
      },
    }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('evaluation-report:unconditional-pass-forbidden'));
  });

  test('a contract schema blob pinned at the wrong digest fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ blobDrift: 'contracts/claim.schema.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('contracts/claim.schema.json:blob-drift'));
  });

  test('a contract schema moved forward on origin/main after canonicalization fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ mainBlobDrift: 'contracts/claim.schema.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('contracts/claim.schema.json:main-drift'));
  });

  test('a drifted executable (working tree) contract version fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ executableDrift: 'contracts/evidence-edge.schema.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('contracts/evidence-edge.schema.json:executable-drift'));
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
    const result = verifyDependencyBinding(RECORD, makeIo({ trackedCopyDigestDrift: 'evidence/external/s1-007/evaluation-record.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('stage1.s1_007:tracked-copy-digest-drift'));
  });

  test('a missing tracked Stage-1 evidence copy fails closed', () => {
    const result = verifyDependencyBinding(RECORD, makeIo({ missingTrackedCopy: 'evidence/external/s1-009/evaluation-record.json' }));
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('stage1.s1_009:tracked-copy-missing'));
  });

  test('payload substitution in a Stage-1 record fails closed', () => {
    const record = clone(RECORD);
    record.stage1.bindings.s1_007.expected.result = 'pass';
    const result = verifyDependencyBinding(record, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('stage1.s1_007:result-drift'));
  });

  test('a missing required Stage-1 binding fails closed', () => {
    const record = clone(RECORD);
    delete record.stage1.bindings.s1_009;
    const result = verifyDependencyBinding(record, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('stage1.s1_009:missing-binding'));
  });

  test('a consumer input that is not pinned by blob digest fails closed', () => {
    const record = clone(RECORD);
    record.consumerInputs.inputs.accessRights = ['contracts/unpinned-acl.schema.json'];
    const result = verifyDependencyBinding(record, makeIo());
    assert.equal(result.ok, false);
    assert.ok(result.issues.some((i) => i.startsWith('consumer-inputs:unpinned-path')));
  });

  test('a non-object record fails closed', () => {
    const result = verifyDependencyBinding(null, makeIo());
    assert.deepEqual(result, { ok: false, checked: 0, issues: ['record:not-object'] });
  });
});
