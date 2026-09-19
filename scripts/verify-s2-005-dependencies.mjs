// S2-005 dependency gate (fail-closed).
// Verifies, BEFORE any retrieval or synthesis implementation is touched, that:
//   1. origin/main carries the canonicalized S2-004: the merge commit
//      7662face2091c1f591af2b586502beb4ea698e5e and the verified S2-004 head
//      f4122726c2926819066fa96255a9ab8aebea25fa are reachable from it;
//   2. S2-004 evidence (green clean checkout, PASS_WITH_LIMITS verdict, Run A/B
//      with identical decisions but distinct executor identities, PostgreSQL
//      replay, frozen manifests, zero ACL/authority/stale/duplicate-side-effect
//      counters) is read from Git bytes at the pinned closure commit, never
//      from narrative fields of the working tree;
//   3. the S2-004 contract schemas this task builds upon (claim revisions,
//      claim edges, exact evidence spans, graph invalidation/stale propagation,
//      expert lens ranking, server-side ACL authorization decisions, calibration
//      records) are pinned by blob digest at contractVersion 1.0.0, and the
//      executable (working tree) and origin/main versions of those schemas are
//      byte-identical to the pinned ones — no origin/main/record/executable
//      mismatch is tolerated;
//   4. the carried S2-004 limits (NOT_CALIBRATED semantics, no causality from
//      correlation/analogy/authority, ranking-only lenses, no claimed human
//      approval, carried S2-003 connector/OCR limits) are present in the
//      evaluation report bytes — S2-005 must inherit them, not silently drop
//      them;
//   5. S1-007 (retrieval and index isolation) and S1-009 (provider-neutral
//      delegation/adapter semantics) are bound to a fixed AgentOS commit with
//      digest-verified tracked evidence copies;
//   6. every declared consumer input (frozen corpora, access rights, time
//      model, S2-003/S2-004 limitations) is pinned by blob digest in this
//      record — an unpinned consumer input fails the gate;
//   7. any missing dependency, unreachable commit, digest drift, payload
//      mismatch, executable/main contract drift or unpinned consumer input
//      exits non-zero as BLOCKED_DEPENDENCY — not a warning.
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

// Git blob id computed without the object database: works even in archive
// checkouts, so the executable-contract check never degrades to a no-op.
function blobIdOfBytes(bytes) {
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
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
  // meaningful (binding sanity, tracked-copy digests, executable-contract
  // digests computed without the object database) and skips every Git read;
  // the full verification is mandatory in a real working repository.
  const archiveMode = io.archiveMode === true;

  const require = (condition, code) => {
    if (!condition) issues.push(code);
    return condition;
  };

  if (!isPlainObject(record)) {
    return { ok: false, checked: 0, issues: ['record:not-object'] };
  }

  const s2 = record.s2_004 ?? {};
  const stage1 = record.stage1 ?? {};

  // ---- 1. origin/main carries the canonicalized S2-004 ----
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
      checked.push('origin/main:head');
    }
    // §1: origin/main must CONTAIN the S2-004 canonicalization — the merge
    // base and the verified S2-004 head must be reachable ancestors; HEAD
    // equality is not required (later stages legitimately move main forward).
    for (const [role, commit] of [['canonicalBase', s2.canonicalBase], ['closure', s2.closureCommit], ['implementation', s2.implementationCommit]]) {
      if (!GIT_COMMIT.test(commit ?? '')) {
        issues.push(`s2-004.${role}Commit:unpinned`);
        continue;
      }
      try {
        git_(['cat-file', '-e', `${commit}^{commit}`]);
        git_(['merge-base', '--is-ancestor', commit, 'refs/remotes/origin/main']);
        checked.push(`s2-004.${role}Commit:reachable`);
      } catch {
        issues.push(`s2-004.${role}Commit:unreachable-from-main`);
      }
    }
  }

  // ---- 2. S2-004 evidence from Git bytes at the closure commit ----
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
      issues.push('s2-004.evidenceReadFromGitBytes:empty');
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

      // Run A/B comparison must be clean: identical decisions, distinct
      // identities, PASS_WITH_LIMITS verdict, hard gates green, zero
      // ACL/authority/type-promotion/stale/duplicate counters on both runs.
      try {
        const comparison = JSON.parse(readGitFile('evidence/s2-004-comparison.json').toString('utf8'));
        const expected = s2.expected ?? {};
        require(comparison.comparison?.ok === (expected.comparisonOk ?? true), 'comparison:not-ok');
        require((comparison.comparison?.decisionMismatches ?? 1) === (expected.decisionMismatches ?? 0), 'comparison:decision-mismatches');
        require(comparison.comparison?.comparedCases === expected.comparedCases, 'comparison:case-count-drift');
        require(comparison.corpus?.caseCount === expected.corpusCaseCount, 'comparison:corpus-count-drift');
        require(comparison.testedImplementationCommit === expected.testedImplementationCommit, 'comparison:implementation-commit-drift');
        require(comparison.verdict === (expected.comparisonVerdict ?? 'PASS_WITH_LIMITS'), 'comparison:verdict-drift');
        require(comparison.hardGates?.ok === (expected.hardGatesOk ?? true), 'comparison:hard-gates-violated');
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
        require((integrityA.acl_leaks ?? 1) === (expected.aclLeaks ?? 0), 'comparison:acl-leaks');
        require((integrityA.authority_expansions ?? 1) === (expected.authorityExpansions ?? 0), 'comparison:authority-expansion');
        require((integrityA.type_promotions_without_review ?? 1) === (expected.typePromotionsWithoutReview ?? 0), 'comparison:type-promotion-without-review');
        require((integrityA.stale_survivors ?? 1) === (expected.staleSurvivors ?? 0), 'comparison:stale-survivors');
        require((integrityA.duplicate_side_effects ?? 1) === (expected.duplicateSideEffects ?? 0), 'comparison:duplicate-side-effects');
        checked.push('comparison:payload');
      } catch {
        issues.push('evidence/s2-004-comparison.json:unreadable-from-git');
      }

      // PostgreSQL replay comparison must be clean too
      try {
        const dbComparison = JSON.parse(readGitFile('evidence/s2-004-db-comparison.json').toString('utf8'));
        require(dbComparison.comparison?.ok === (s2.expected?.dbComparisonOk ?? true), 'db-comparison:not-ok');
        require((dbComparison.comparison?.decisionMismatches ?? 1) === (s2.expected?.dbDecisionMismatches ?? 0), 'db-comparison:decision-mismatches');
        require(
          dbComparison.executors?.run_a !== dbComparison.executors?.run_b,
          'db-comparison:executor-identities-identical'
        );
        checked.push('db-comparison:payload');
      } catch {
        issues.push('evidence/s2-004-db-comparison.json:unreadable-from-git');
      }

      // PASS_WITH_LIMITS verdict: byte-level check on the evaluation report
      try {
        const reportBytes = readGitFile('docs/decisions/S2-004-EVALUATION-REPORT.md').toString('utf8');
        require(/^## Verdict: PASS_WITH_LIMITS$/m.test(reportBytes), 'evaluation-report:no-pass-with-limits-verdict');
        require(!/^## Verdict: PASS\s*$/m.test(reportBytes), 'evaluation-report:unconditional-pass-forbidden');
        checked.push('evaluation-report:verdict');
      } catch {
        issues.push('docs/decisions/S2-004-EVALUATION-REPORT.md:unreadable-from-git');
      }

      // Carried limits must be present in the report bytes
      const markers = s2.carriedLimits?.requiredReportMarkers ?? [];
      if (markers.length === 0) issues.push('s2-004.carriedLimits:empty');
      try {
        const reportBytes = readGitFile('docs/decisions/S2-004-EVALUATION-REPORT.md').toString('utf8');
        for (const marker of markers) {
          require(reportBytes.includes(marker), `carried-limits:missing-marker(${marker.slice(0, 48)})`);
        }
        checked.push(`carried-limits:markers(${markers.length})`);
      } catch {
        issues.push('carried-limits:report-unreadable');
      }
    }
  }

  // ---- 3. Contract schemas pinned, executable and main-consistent ----
  // §1.4: no mismatch between origin/main, this dependency record and the
  // executable (working tree) version of the contracts S2-005 builds upon.
  // The executable-contract digest is computed without the object database,
  // so this check also runs in archive mode and never degrades to a no-op.
  const schemas = s2.contractSchemas ?? {};
  if (!isPlainObject(schemas) || Object.keys(schemas).length === 0) {
    issues.push('s2-004.contractSchemas:empty');
  }
  for (const [relPath, expectedBlob] of Object.entries(schemas)) {
    if (!GIT_BLOB.test(expectedBlob ?? '')) {
      issues.push(`${relPath}:unbound-blob-digest`);
      continue;
    }
    let bytes = null;
    if (!archiveMode) {
      let actualBlob = '';
      try {
        actualBlob = git_(['rev-parse', `${closure}:${relPath}`]);
      } catch {
        issues.push(`${relPath}:missing-at-closure-commit`);
        continue;
      }
      require(actualBlob === expectedBlob, `${relPath}:blob-drift`);
      // origin/main must still carry the pinned schema bytes
      let mainBlob = '';
      try {
        mainBlob = git_(['rev-parse', `refs/remotes/origin/main:${relPath}`]);
      } catch {
        issues.push(`${relPath}:missing-at-main`);
      }
      if (mainBlob) {
        require(mainBlob === expectedBlob, `${relPath}:main-drift`);
        checked.push(`${relPath}:main-consistent`);
      }
      try {
        bytes = readGitFile(relPath);
      } catch {
        issues.push(`${relPath}:unreadable-from-git`);
        continue;
      }
    }
    // executable version: the working tree file the S2-005 implementation
    // will actually import must hash to the pinned blob id
    let workingBytes;
    try {
      workingBytes = readWorkingTreeFile(relPath);
    } catch {
      issues.push(`${relPath}:executable-missing`);
      continue;
    }
    require(blobIdOfBytes(workingBytes) === expectedBlob, `${relPath}:executable-drift`);
    checked.push(`${relPath}:executable-consistent`);
    if (bytes !== null) {
      try {
        const schema = JSON.parse(bytes.toString('utf8'));
        require(schema.properties?.contractVersion?.const === (s2.expected?.contractVersion ?? '1.0.0'), `${relPath}:contract-version-drift`);
      } catch {
        issues.push(`${relPath}:malformed`);
        continue;
      }
      checked.push(`${relPath}:schema`);
    }
  }

  // ---- 4. Stage-1 bindings pinned to a fixed AgentOS commit ----
  const source = stage1.sourceRepository ?? {};
  require(source.remote === 'https://github.com/SpaceDazher/AgentOS.git', 'stage1:unexpected-remote');
  if (!GIT_COMMIT.test(source.pinnedCommit ?? '')) {
    issues.push('stage1:commit-not-pinned-to-sha');
  }
  if (typeof source.pinnedCommit === 'string' && (source.pinnedCommit === 'main' || source.pinnedCommit.includes('/'))) {
    issues.push('stage1:branch-or-path-instead-of-commit');
  }

  const bindings = stage1.bindings ?? {};
  const requiredTickets = ['s1_007', 's1_009'];
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

  // ---- 5. Consumer inputs must be pinned ----
  // §1.3: frozen corpora, access rights, time model and the S2-003/S2-004
  // limitations must be available to the consumer as pinned artifacts — a
  // declared consumer input that is not pinned by blob digest fails closed.
  const consumerInputs = record.consumerInputs ?? {};
  const pinnedPaths = new Set([
    ...Object.keys(s2.evidenceReadFromGitBytes ?? {}),
    ...Object.keys(schemas),
  ]);
  const inputs = consumerInputs.inputs ?? {};
  if (!isPlainObject(inputs) || Object.keys(inputs).length === 0) {
    issues.push('consumer-inputs:empty');
  } else {
    for (const [need, paths] of Object.entries(inputs)) {
      if (!Array.isArray(paths) || paths.length === 0) {
        issues.push(`consumer-inputs:${need}:empty`);
        continue;
      }
      let needPinned = true;
      for (const relPath of paths) {
        if (typeof relPath !== 'string' || !pinnedPaths.has(relPath)) {
          issues.push(`consumer-inputs:unpinned-path(${relPath})`);
          needPinned = false;
        }
      }
      if (needPinned) checked.push(`consumer-inputs:${need}:pinned`);
    }
  }

  return { ok: issues.length === 0, checked: checked.length, issues };
}

function main() {
  const bindingPath = path.join(ROOT, 'evidence/s2-005-dependency-binding.json');
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
  // copy digests, executable-contract digests, consumer-input pinning) and
  // reports ARCHIVE_DEGRADED explicitly; the full Git-bytes verification is
  // mandatory in a real working repository.
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
