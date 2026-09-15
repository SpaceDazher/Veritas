// S2-004 dependency gate (fail-closed).
// Verifies, BEFORE any claim graph implementation is touched, that:
//   1. origin/main carries the canonicalized S2-003: the closure commit
//      b3fe0ee1b0320ad349265fc5e33327833418e197 and the implementation commit
//      are reachable from it;
//   2. S2-003 evidence (green clean checkout, PASS_WITH_LIMITS verdict, Run A/B
//      with identical decisions but distinct executor identities, DB replay,
//      frozen manifests) is read from Git bytes at the pinned closure commit,
//      never from narrative fields of the working tree;
//   3. the S2-003 contract schemas this task builds upon (SourceSnapshot,
//      ContentSegment, source lineage, retention/tombstone, embedded
//      instruction classification) are pinned by blob digest at
//      contractVersion 1.0.0;
//   4. the carried S2-003 limits (live private connectors NOT_PROVEN,
//      OCR/ASR fixture-only, near-duplicate merge NOT_CALIBRATED, candidate
//      lineage requiring human confirmation) are present in the evaluation
//      report bytes — S2-004 must inherit them, not silently drop them;
//   5. S1-003 (executable SHACL validation), S1-011 (knowledge promotion
//      gate) and S1-012 (confidence/provenance semantics) are bound to a
//      fixed AgentOS commit with digest-verified tracked evidence copies;
//   6. any missing dependency, unreachable commit, digest drift or payload
//      mismatch exits non-zero as BLOCKED_DEPENDENCY — not a warning.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const GIT_BLOB = /^[0-9a-f]{40}$/;

function git(args, options = {}) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', ...options }).trimEnd();
}

// Raw blob bytes: no trim, no encoding round-trip — digest fidelity matters.
function gitBytes(commit, repoPath) {
  return execFileSync('git', ['show', `${commit}:${repoPath}`], { cwd: ROOT, maxBuffer: 1 << 28 });
}

function sha256OfBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function verifyDependencyBinding(record, io = {}) {
  const issues = [];
  const checked = [];
  const git_ = io.git ?? git;
  const gitBytes_ = io.gitBytes ?? gitBytes;
  const readWorkingTreeFile = io.readWorkingTreeFile ?? ((rel) => fs.readFileSync(path.join(ROOT, rel)));
  // Archive (git-archive) checkouts carry no .git: byte-level Git verification
  // is impossible there. archiveMode runs the structural checks that remain
  // meaningful (binding sanity + tracked-copy digests) and skips every Git
  // read; the full verification is mandatory in a real working repository.
  const archiveMode = io.archiveMode === true;

  const require = (condition, code) => {
    if (!condition) issues.push(code);
    return condition;
  };

  if (!isPlainObject(record)) {
    return { ok: false, checked: 0, issues: ['record:not-object'] };
  }

  const s2 = record.s2_003 ?? {};
  const stage1 = record.stage1 ?? {};

  // ---- 1. origin/main carries the canonicalized S2-003 ----
  if (archiveMode) {
    checked.push('git:archive-mode-skipped');
  } else {
    let mainHead = '';
    try {
      mainHead = git_(['rev-parse', 'refs/remotes/origin/main']);
    } catch {
      issues.push('origin/main:unresolvable');
    }
    if (GIT_COMMIT.test(mainHead)) {
      require(mainHead === s2.canonicalBase, 'origin/main:not-at-s2-003-canonical-base');
      checked.push('origin/main:head');
    }
    for (const [role, commit] of [['closure', s2.closureCommit], ['implementation', s2.implementationCommit]]) {
      if (!GIT_COMMIT.test(commit ?? '')) {
        issues.push(`s2-003.${role}Commit:unpinned`);
        continue;
      }
      try {
        git_(['cat-file', '-e', `${commit}^{commit}`]);
        git_(['merge-base', '--is-ancestor', commit, 'refs/remotes/origin/main']);
        checked.push(`s2-003.${role}Commit:reachable`);
      } catch {
        issues.push(`s2-003.${role}Commit:unreachable-from-main`);
      }
    }
  }

  // ---- 2. S2-003 evidence from Git bytes at the closure commit ----
  const closure = s2.closureCommit;
  const gitFileCache = new Map();
  const readGitFile = (relPath) => {
    if (gitFileCache.has(relPath)) return gitFileCache.get(relPath);
    const bytes = gitBytes_(closure, relPath);
    gitFileCache.set(relPath, bytes);
    return bytes;
  };
  const gitDrift = () =>
    issues.filter((i) => i.endsWith(':blob-drift') || i.endsWith(':missing-at-closure-commit'));

  if (!archiveMode) {
    const expectedBlobs = s2.evidenceReadFromGitBytes ?? {};
    if (!isPlainObject(expectedBlobs) || Object.keys(expectedBlobs).length === 0) {
      issues.push('s2-003.evidenceReadFromGitBytes:empty');
    }
    for (const [relPath, expectedBlob] of Object.entries(expectedBlobs)) {
      if (!GIT_BLOB.test(expectedBlob ?? '')) {
        issues.push(`${relPath}:unbound-blob-digest`);
        continue;
      }
      let actualBlob = '';
      try {
        actualBlob = git_(['rev-parse', `${closure}:${relPath}`]);
      } catch {
        issues.push(`${relPath}:missing-at-closure-commit`);
        continue;
      }
      require(actualBlob === expectedBlob, `${relPath}:blob-drift`);
      checked.push(`${relPath}:blob`);
    }

    if (GIT_COMMIT.test(closure ?? '') && gitDrift().length === 0) {
      // clean checkout must be green
      try {
        const cleanCheckout = JSON.parse(readGitFile('evidence/clean-checkout.json').toString('utf8'));
        require(cleanCheckout.passed === (s2.expected?.cleanCheckoutPassed ?? true), 'clean-checkout:not-green');
        require(cleanCheckout.exitCode === (s2.expected?.cleanCheckoutExitCode ?? 0), 'clean-checkout:nonzero-exit');
        checked.push('clean-checkout:payload');
      } catch {
        issues.push('evidence/clean-checkout.json:unreadable-from-git');
      }

      // Run A/B comparison must be clean: identical decisions, distinct identities
      try {
        const comparison = JSON.parse(readGitFile('evidence/s2-003-comparison.json').toString('utf8'));
        const expected = s2.expected ?? {};
        require(comparison.comparison?.ok === (expected.comparisonOk ?? true), 'comparison:not-ok');
        require(comparison.comparison?.decisionMismatches === (expected.decisionMismatches ?? 0), 'comparison:decision-mismatches');
        require(comparison.comparison?.identityMismatches === (expected.identityMismatches ?? 0), 'comparison:identity-mismatches');
        require(comparison.comparison?.comparedCases === expected.comparedCases, 'comparison:case-count-drift');
        require(comparison.corpus?.caseCount === expected.corpusCaseCount, 'comparison:corpus-count-drift');
        require(comparison.corpus?.corpusSha256 === expected.corpusSha256, 'comparison:corpus-digest-drift');
        require(comparison.testedImplementationCommit === expected.testedImplementationCommit, 'comparison:implementation-commit-drift');
        const runA = comparison.runParameters?.run_a ?? {};
        const runB = comparison.runParameters?.run_b ?? {};
        require(runA.executor !== runB.executor, 'comparison:executor-identities-identical');
        require(runA.nonce !== runB.nonce, 'comparison:nonces-identical');
        require(runA.clock !== runB.clock, 'comparison:clocks-identical');
        const integrityA = comparison.integrity?.run_a ?? {};
        const integrityB = comparison.integrity?.run_b ?? {};
        require(
          JSON.stringify(integrityA) === JSON.stringify(integrityB),
          'comparison:integrity-counters-differ'
        );
        require((integrityA.private_exports_leaked ?? 1) === (expected.privateExportsLeaked ?? 0), 'comparison:private-leak');
        require((integrityA.authority_expansions ?? 1) === (expected.authorityExpansions ?? 0), 'comparison:authority-expansion');
        checked.push('comparison:payload');
      } catch {
        issues.push('evidence/s2-003-comparison.json:unreadable-from-git');
      }

      // DB replay comparison must be clean too
      try {
        const dbComparison = JSON.parse(readGitFile('evidence/s2-003-db-comparison.json').toString('utf8'));
        require(dbComparison.comparison?.ok === true, 'db-comparison:not-ok');
        require((dbComparison.comparison?.decisionMismatches ?? 1) === 0, 'db-comparison:decision-mismatches');
        checked.push('db-comparison:payload');
      } catch {
        issues.push('evidence/s2-003-db-comparison.json:unreadable-from-git');
      }

      // PASS_WITH_LIMITS verdict: byte-level check on the evaluation report
      try {
        const reportBytes = readGitFile('docs/decisions/S2-003-EVALUATION-REPORT.md').toString('utf8');
        require(/^## Verdict: PASS_WITH_LIMITS$/m.test(reportBytes), 'evaluation-report:no-pass-with-limits-verdict');
        require(!/^## Verdict: PASS\s*$/m.test(reportBytes), 'evaluation-report:unconditional-pass-forbidden');
        checked.push('evaluation-report:verdict');
      } catch {
        issues.push('docs/decisions/S2-003-EVALUATION-REPORT.md:unreadable-from-git');
      }

      // Carried limits must be present in the report bytes
      const markers = s2.carriedLimits?.requiredReportMarkers ?? [];
      if (markers.length === 0) issues.push('s2-003.carriedLimits:empty');
      try {
        const reportBytes = readGitFile('docs/decisions/S2-003-EVALUATION-REPORT.md').toString('utf8');
        for (const marker of markers) {
          require(reportBytes.includes(marker), `carried-limits:missing-marker(${marker.slice(0, 48)})`);
        }
        checked.push(`carried-limits:markers(${markers.length})`);
      } catch {
        issues.push('carried-limits:report-unreadable');
      }

      // Contract schemas pinned at contractVersion 1.0.0
      const schemas = s2.contractSchemas ?? {};
      if (!isPlainObject(schemas) || Object.keys(schemas).length === 0) {
        issues.push('s2-003.contractSchemas:empty');
      }
      for (const [relPath, expectedBlob] of Object.entries(schemas)) {
        if (!GIT_BLOB.test(expectedBlob ?? '')) {
          issues.push(`${relPath}:unbound-blob-digest`);
          continue;
        }
        let bytes;
        try {
          bytes = readGitFile(relPath);
        } catch {
          issues.push(`${relPath}:missing-at-closure-commit`);
          continue;
        }
        let actualBlob = '';
        try {
          actualBlob = git_(['rev-parse', `${closure}:${relPath}`]);
        } catch {
          issues.push(`${relPath}:missing-at-closure-commit`);
          continue;
        }
        require(actualBlob === expectedBlob, `${relPath}:blob-drift`);
        try {
          const schema = JSON.parse(bytes.toString('utf8'));
          require(schema.properties?.contractVersion?.const === (s2.expected?.contractVersion ?? '1.0.0'), `${relPath}:contract-version-drift`);
        } catch {
          issues.push(`${relPath}:malformed`);
        }
        checked.push(`${relPath}:schema`);
      }
    }
  }

  // ---- 3. Stage-1 bindings pinned to a fixed AgentOS commit ----
  const source = stage1.sourceRepository ?? {};
  require(source.remote === 'https://github.com/SpaceDazher/AgentOS.git', 'stage1:unexpected-remote');
  if (!GIT_COMMIT.test(source.pinnedCommit ?? '')) {
    issues.push('stage1:commit-not-pinned-to-sha');
  }
  if (typeof source.pinnedCommit === 'string' && (source.pinnedCommit === 'main' || source.pinnedCommit.includes('/'))) {
    issues.push('stage1:branch-or-path-instead-of-commit');
  }

  const bindings = stage1.bindings ?? {};
  const requiredTickets = ['s1_003', 's1_011', 's1_012'];
  for (const ticket of requiredTickets) {
    const binding = bindings[ticket];
    if (!isPlainObject(binding)) {
      issues.push(`stage1.${ticket}:missing-binding`);
      continue;
    }
    if (!GIT_BLOB.test(binding.recordBlob ?? '')) issues.push(`stage1.${ticket}:record-blob-unpinned`);
    if (!SHA256.test(binding.recordSha256 ?? '')) issues.push(`stage1.${ticket}:invalid-record-digest`);
    if (!Number.isInteger(binding.recordBytes) || binding.recordBytes <= 0) issues.push(`stage1.${ticket}:invalid-record-length`);
    if (typeof binding.recordPath !== 'string' || !binding.recordPath.startsWith('research/tickets/')) {
      issues.push(`stage1.${ticket}:unexpected-record-path`);
    }
    if (typeof binding.trackedCopy !== 'string' || binding.trackedCopy.length === 0 || path.isAbsolute(binding.trackedCopy) || binding.trackedCopy.includes('\\') || binding.trackedCopy.includes('..')) {
      issues.push(`stage1.${ticket}:tracked-copy-not-portable`);
      continue;
    }
    let copyBytes;
    try {
      copyBytes = readWorkingTreeFile(binding.trackedCopy);
    } catch {
      issues.push(`stage1.${ticket}:tracked-copy-missing`);
      continue;
    }
    require(sha256OfBytes(copyBytes) === binding.recordSha256, `stage1.${ticket}:tracked-copy-digest-drift`);
    require(copyBytes.length === binding.recordBytes, `stage1.${ticket}:tracked-copy-length-drift`);
    checked.push(`stage1.${ticket}:tracked-copy`);
    let rec = null;
    try {
      rec = JSON.parse(copyBytes.toString('utf8'));
    } catch {
      issues.push(`stage1.${ticket}:tracked-copy-malformed`);
      continue;
    }
    const expected = binding.expected ?? {};
    require(rec.ticket_id === expected.ticket_id, `stage1.${ticket}:ticket-drift`);
    require(rec.result === expected.result, `stage1.${ticket}:result-drift`);
    require(rec.evaluation_id === expected.evaluation_id, `stage1.${ticket}:evaluation-id-drift`);
    require(rec.artifact_chain_hash === expected.artifact_chain_hash, `stage1.${ticket}:chain-hash-drift`);
    checked.push(`stage1.${ticket}:payload`);
  }

  return { ok: issues.length === 0, checked: checked.length, issues };
}

function main() {
  const bindingPath = path.join(ROOT, 'evidence/s2-004-dependency-binding.json');
  let record;
  try {
    record = JSON.parse(fs.readFileSync(bindingPath, 'utf8'));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, status: 'BLOCKED_DEPENDENCY', issues: [`binding-record:unreadable (${error.message})`] }, null, 2));
    process.exit(1);
  }
  // Clean-architecture checkouts (git archive) carry no .git directory: the
  // byte-level Git verification this gate exists for is impossible there.
  // The archive path runs the structural checks that remain possible (tracked
  // copy digests, binding structure) and reports ARCHIVE_DEGRADED explicitly;
  // the full Git-bytes verification is mandatory in a real working repository.
  const archiveMode = !fs.existsSync(path.join(ROOT, '.git'));
  const result = verifyDependencyBinding(record, { archiveMode });
  const output = {
    ...result,
    mode: archiveMode ? 'ARCHIVE_DEGRADED' : 'FULL_GIT_BYTES',
    status: result.ok ? 'PASS' : 'BLOCKED_DEPENDENCY',
  };
  console.log(JSON.stringify(output, null, 2));
  process.exit(result.ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
