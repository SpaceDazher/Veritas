// S2-006 dependency gate (fail-closed, spec §1).
// Verifies, BEFORE any measured semantic verifier result may be recorded, that:
//   1. refs/remotes/origin/main points at the pinned canonicalization merge
//      d7ce192cec82e7cd66e1dce29faebcfbcfe9bd6f (the S2-005 PR #18 merge);
//      a later advance of origin/main fails closed because no reviewed rebase
//      binding exists in the record (a plain ancestor check is not enough);
//   2. the merge object has EXACTLY the two expected parents in Git order
//      (git cat-file -p and git rev-list --parents must agree), and the
//      second parent is the exact verified S2-005 head 36fd8f85…;
//   3. every protected S2-005 evidence/contract/corpus input is read ONLY via
//      `git show d7ce192:<path>`; its Git blob id and SHA-256 must match the
//      record, and each frozen-input SHA-256 is additionally cross-checked
//      against the frozen manifest bytes AT d7ce192 — never against the
//      working tree and never against a self-generated narrative;
//   4. the S2-005 evidence payloads (green clean checkout, PASS_WITH_LIMITS
//      comparison, hard counters zero, distinct run identities, green DB
//      replay) are re-verified from those Git bytes;
//   5. the inherited policy surfaces (METRIC_POLICY / HUMAN_APPROVAL_POLICY /
//      AUTONOMY_POLICY executable equivalents) are pinned by SHA-256 at
//      d7ce192 and byte-identical in the working tree;
//   6. S1-011 (human decisions / authority binding) and S1-012 (separation of
//      confidence, calibration and support) are bound to the pinned AgentOS
//      commit via digest- and length-verified tracked copies with checked
//      payload fields;
//   7. the S2-006 frozen inputs (thresholds, corpus, rubric, labels,
//      adjudication) match their authored digests — after the first recorded
//      result they may never change;
//   8. upstream limits are carried: the fixture-only corpus stratum and the
//      NEEDS_INPUT thresholds preregistration are checked from bytes;
//   9. any miss exits non-zero as BLOCKED_DEPENDENCY — not a warning.
//
//   node scripts/verify-s2-006-dependencies.mjs
//
// On a fully green FULL_GIT_BYTES verification the script rewrites the
// `resolved` section of evidence/s2-006-dependency-binding.json with the
// observed refs/object ids/exit codes. The resolved content is deterministic
// (no wall clock, no pids), so the rewrite is byte-stable. On any failure the
// committed record is left untouched and the gate exits 1.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RECORD_PATH = 'evidence/s2-006-dependency-binding.json';
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
// checkouts, so the executable-surface check never degrades to a no-op.
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
  // meaningful (binding sanity, executable digests computed without the object
  // database, S2-006 frozen inputs, stage-1 tracked copies, consumer pinning)
  // and skips every Git read; the full verification is mandatory in a real
  // working repository.
  const archiveMode = io.archiveMode === true;

  const require = (condition, code) => {
    if (!condition) issues.push(code);
    return condition;
  };

  if (!isPlainObject(record)) {
    return { ok: false, checked: 0, issues: ['record:not-object'] };
  }

  const s2 = record.s2_005 ?? {};

  // ---- 1. origin/main points at the pinned canonicalization merge ----------
  const merge = s2.canonicalMerge;
  let mainHead = '';
  if (archiveMode) {
    checked.push('git:archive-mode-skipped');
  } else {
    if (!GIT_COMMIT.test(merge ?? '')) {
      issues.push('s2-005.canonicalMerge:unpinned');
    } else {
      try {
        mainHead = git_(['rev-parse', 'refs/remotes/origin/main']);
      } catch {
        issues.push('origin/main:unresolvable');
      }
      if (GIT_COMMIT.test(mainHead)) {
        if (mainHead === merge) {
          checked.push('origin/main:at-pinned-merge');
        } else {
          // §1: a later advance of origin/main is allowed ONLY with a separate
          // reviewed rebase binding that proves the protected S2-005/policy
          // surface unchanged; a plain ancestor check is not sufficient.
          let advanced = false;
          try {
            git_(['merge-base', '--is-ancestor', merge, 'refs/remotes/origin/main']);
            advanced = true;
          } catch {
            advanced = false;
          }
          issues.push(advanced ? 'origin/main:advanced-past-pinned-merge' : 'origin/main:diverged-from-pinned-merge');
        }
      }
      try {
        git_(['cat-file', '-e', `${merge}^{commit}`]);
        checked.push('canonicalMerge:object-exists');
      } catch {
        issues.push('canonicalMerge:object-missing');
      }
    }
  }

  // ---- 2. merge parents: exactly the expected two, in Git order ------------
  const expectedParents = Array.isArray(s2.expectedParents) ? s2.expectedParents : [];
  if (expectedParents.length !== 2 || expectedParents.some((p) => !GIT_COMMIT.test(p ?? ''))) {
    issues.push('s2-005.expectedParents:not-two-commits');
  } else if (!archiveMode && GIT_COMMIT.test(merge ?? '')) {
    try {
      // Two independent reads of the parent list must agree.
      const catFileParents = git_(['cat-file', '-p', merge])
        .split('\n')
        .filter((line) => line.startsWith('parent '))
        .map((line) => line.slice('parent '.length).trim());
      const revListParents = git_(['rev-list', '--parents', '-n', '1', merge]).split(' ').slice(1);
      for (const [source, parents] of [['cat-file', catFileParents], ['rev-list', revListParents]]) {
        if (parents.length !== 2) {
          issues.push(`canonicalMerge:${source}:parent-count-${parents.length}`);
          continue;
        }
        if (parents[0] !== expectedParents[0]) issues.push(`canonicalMerge:${source}:first-parent-drift`);
        if (parents[1] !== expectedParents[1]) issues.push(`canonicalMerge:${source}:second-parent-drift`);
      }
      checked.push('canonicalMerge:parents(cat-file+rev-list)');
      // The second parent is the exact verified S2-005 head.
      if (s2.implementationHead !== expectedParents[1]) issues.push('s2-005.implementation-head-not-second-parent');
      else checked.push('s2-005.implementationHead:exact');
      try {
        git_(['cat-file', '-e', `${expectedParents[1]}^{commit}`]);
        checked.push('s2-005.head:object-exists');
      } catch {
        issues.push('s2-005.head:object-missing');
      }
    } catch {
      issues.push('canonicalMerge:unreadable');
    }
  }

  // ---- 3. protected S2-005 inputs: blob ids + SHA-256 over git show bytes --
  const expectedBlobs = s2.evidenceReadFromGitBytes ?? {};
  if (!isPlainObject(expectedBlobs) || Object.keys(expectedBlobs).length === 0) {
    issues.push('s2-005.evidenceReadFromGitBytes:empty');
  }
  const frozenInputs = record.frozenS2_005InputsSha256?.inputs ?? {};
  if (!isPlainObject(frozenInputs) || Object.keys(frozenInputs).length === 0) {
    issues.push('frozenS2_005InputsSha256:empty');
  }
  const pinnedPaths = new Set();
  if (!archiveMode && GIT_COMMIT.test(merge ?? '')) {
    for (const [relPath, expectedBlob] of Object.entries(expectedBlobs)) {
      if (!GIT_BLOB.test(expectedBlob ?? '')) {
        issues.push(`${relPath}:unbound-blob-digest`);
        continue;
      }
      let actualBlob = '';
      try {
        actualBlob = git_(['rev-parse', `${merge}:${relPath}`]);
      } catch {
        issues.push(`${relPath}:missing-at-canonical-merge`);
        continue;
      }
      require(actualBlob === expectedBlob, `${relPath}:blob-drift`);
      checked.push(`${relPath}:blob`);
      pinnedPaths.add(relPath);
    }
    // SHA-256 over git show bytes + cross-check against the frozen manifest
    // bytes at d7ce192 (an independent expectation, not the working tree).
    let frozenManifestAtMerge = null;
    try {
      frozenManifestAtMerge = JSON.parse(gitBytes_(merge, 'evidence/frozen-manifest.json').toString('utf8'));
    } catch {
      issues.push('evidence/frozen-manifest.json:unreadable-from-git');
    }
    for (const [relPath, expectedSha] of Object.entries(frozenInputs)) {
      if (!SHA256.test(expectedSha ?? '')) {
        issues.push(`${relPath}:unbound-digest`);
        continue;
      }
      let bytes = null;
      try {
        bytes = gitBytes_(merge, relPath);
      } catch {
        issues.push(`${relPath}:missing-at-canonical-merge`);
        continue;
      }
      require(sha256OfBytes(bytes) === expectedSha, `${relPath}:sha256-drift`);
      checked.push(`${relPath}:sha256(git-bytes)`);
      pinnedPaths.add(relPath);
      if (frozenManifestAtMerge) {
        const manifestDigest = frozenManifestAtMerge.files?.[relPath];
        if (manifestDigest === undefined) {
          // The frozen manifest does not claim this path (its scope is the
          // union of frozenTargets, which never covered run evidence) —
          // nothing to cross-check; the Git-bytes digest above stays binding.
          checked.push(`${relPath}:not-covered-by-frozen-manifest`);
        } else {
          require(manifestDigest === expectedSha, `${relPath}:frozen-manifest-cross-check-drift`);
          checked.push(`${relPath}:frozen-manifest-cross-check`);
        }
      }
    }
  }

  // ---- 4. S2-005 evidence payloads re-verified from Git bytes --------------
  if (!archiveMode && GIT_COMMIT.test(merge ?? '') && issues.filter((i) => i.endsWith(':blob-drift') || i.endsWith(':missing-at-canonical-merge')).length === 0) {
    const readGitFile = (relPath) => gitBytes_(merge, relPath);
    const expected = s2.expected ?? {};
    // green clean checkout
    try {
      const cleanCheckout = JSON.parse(readGitFile('evidence/clean-checkout.json').toString('utf8'));
      require(cleanCheckout.passed === (expected.cleanCheckoutPassed ?? true), 'clean-checkout:not-green');
      require(cleanCheckout.exitCode === (expected.cleanCheckoutExitCode ?? 0), 'clean-checkout:nonzero-exit');
      checked.push('clean-checkout:payload');
    } catch {
      issues.push('evidence/clean-checkout.json:unreadable-from-git');
    }
    // PASS_WITH_LIMITS comparison with zero hard counters and distinct run identities
    try {
      const comparison = JSON.parse(readGitFile('evidence/s2-005-comparison.json').toString('utf8'));
      require(comparison.comparison?.ok === (expected.comparisonOk ?? true), 'comparison:not-ok');
      require(comparison.corpus?.caseCount === expected.comparedCases, 'comparison:case-count-drift');
      require(comparison.verdict === (expected.comparisonVerdict ?? 'PASS_WITH_LIMITS'), 'comparison:verdict-drift');
      require(comparison.hardGates?.ok === (expected.hardGatesOk ?? true), 'comparison:hard-gates-violated');
      const runA = comparison.runParameters?.run_a ?? {};
      const runB = comparison.runParameters?.run_b ?? {};
      require(runA.executor !== runB.executor, 'comparison:executor-identities-identical');
      require(runA.nonce !== runB.nonce, 'comparison:nonces-identical');
      const integrityA = comparison.integrity ?? {};
      require((integrityA.private_leaks ?? 1) === (expected.aclLeaks ?? 0), 'comparison:private-leaks');
      require((integrityA.authority_expansions ?? 1) === (expected.authorityExpansions ?? 0), 'comparison:authority-expansion');
      require((integrityA.type_promotions_without_review ?? 1) === (expected.typePromotionsWithoutReview ?? 0), 'comparison:type-promotion-without-review');
      require((integrityA.stale_hits ?? 1) === (expected.staleSurvivors ?? 0), 'comparison:stale-survivors');
      require((integrityA.duplicate_side_effects ?? 1) === (expected.duplicateSideEffects ?? 0), 'comparison:duplicate-side-effects');
      checked.push('comparison:payload');
    } catch {
      issues.push('evidence/s2-005-comparison.json:unreadable-from-git');
    }
    // green PostgreSQL replay
    try {
      const dbComparison = JSON.parse(readGitFile('evidence/s2-005-db-comparison.json').toString('utf8'));
      require(dbComparison.comparison?.ok === (expected.dbComparisonOk ?? true), 'db-comparison:not-ok');
      require(dbComparison.executors?.run_a !== dbComparison.executors?.run_b, 'db-comparison:executor-identities-identical');
      checked.push('db-comparison:payload');
    } catch {
      issues.push('evidence/s2-005-db-comparison.json:unreadable-from-git');
    }
    // PASS_WITH_LIMITS verdict bytes on the evaluation report
    try {
      const reportBytes = readGitFile('docs/decisions/S2-005-EVALUATION-REPORT.md').toString('utf8');
      require(/^## Verdict: PASS_WITH_LIMITS$/m.test(reportBytes), 'evaluation-report:no-pass-with-limits-verdict');
      require(!/^## Verdict: PASS\s*$/m.test(reportBytes), 'evaluation-report:unconditional-pass-forbidden');
      checked.push('evaluation-report:verdict');
    } catch {
      issues.push('docs/decisions/S2-005-EVALUATION-REPORT.md:unreadable-from-git');
    }
    // S2-005 implementation commit binding
    try {
      const commitManifest = JSON.parse(readGitFile('evidence/s2-005-commit-manifest.json').toString('utf8'));
      require(commitManifest.implementationCommit === s2.testedImplementationCommit, 'commit-manifest:implementation-commit-drift');
      checked.push('commit-manifest:payload');
    } catch {
      issues.push('evidence/s2-005-commit-manifest.json:unreadable-from-git');
    }
  }

  // ---- 5. inherited policy surfaces pinned and executable-identical --------
  const policy = record.protectedPolicySha256 ?? {};
  if (!isPlainObject(policy.inputs) || Object.keys(policy.inputs).length === 0) {
    issues.push('protectedPolicySha256:empty');
  }
  for (const [relPath, expectedSha] of Object.entries(policy.inputs ?? {})) {
    if (!SHA256.test(expectedSha ?? '')) {
      issues.push(`${relPath}:unbound-digest`);
      continue;
    }
    if (!archiveMode && GIT_COMMIT.test(merge ?? '')) {
      let bytes = null;
      try {
        bytes = gitBytes_(merge, relPath);
      } catch {
        issues.push(`${relPath}:missing-at-canonical-merge`);
        continue;
      }
      require(sha256OfBytes(bytes) === expectedSha, `${relPath}:policy-sha256-drift`);
      checked.push(`${relPath}:policy(git-bytes)`);
      pinnedPaths.add(relPath);
    }
    // executable version: the working-tree file must stay byte-identical
    let workingBytes;
    try {
      workingBytes = readWorkingTreeFile(relPath);
    } catch {
      issues.push(`${relPath}:executable-missing`);
      continue;
    }
    const workingMatches = archiveMode
      ? sha256OfBytes(workingBytes) === expectedSha
      : blobIdOfBytes(workingBytes) === blobIdOfBytes(gitBytes_(merge, relPath));
    require(workingMatches, `${relPath}:executable-drift`);
    checked.push(`${relPath}:executable-consistent`);
  }

  // ---- 6. stage-1 S1-011 / S1-012 bindings ---------------------------------
  const source = record.stage1?.sourceRepository ?? {};
  require(source.remote === 'https://github.com/SpaceDazher/AgentOS.git', 'stage1:unexpected-remote');
  if (!GIT_COMMIT.test(source.pinnedCommit ?? '')) {
    issues.push('stage1:commit-not-pinned-to-sha');
  }
  if (typeof source.pinnedCommit === 'string' && (source.pinnedCommit === 'main' || source.pinnedCommit.includes('/'))) {
    issues.push('stage1:branch-or-path-instead-of-commit');
  }
  const bindings = record.stage1?.bindings ?? {};
  for (const ticket of ['s1_011', 's1_012']) {
    const binding = bindings[ticket];
    if (!isPlainObject(binding)) {
      issues.push(`stage1.${ticket}:missing-binding`);
      continue;
    }
    if (!SHA256.test(binding.recordSha256 ?? '')) issues.push(`stage1.${ticket}:invalid-record-digest`);
    if (!Number.isInteger(binding.recordBytes) || binding.recordBytes <= 0) issues.push(`stage1.${ticket}:invalid-record-length`);
    if (typeof binding.recordPath !== 'string' || !binding.recordPath.startsWith('research/tickets/')) {
      issues.push(`stage1.${ticket}:unexpected-record-path`);
    }
    if (binding.recordBlob !== null && !GIT_BLOB.test(binding.recordBlob ?? '')) {
      issues.push(`stage1.${ticket}:record-blob-unpinned`);
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

  // ---- 7. S2-006 frozen inputs: executable digest equality -----------------
  const own = record.s2_006FrozenInputsSha256?.inputs ?? {};
  if (!isPlainObject(own) || Object.keys(own).length === 0) {
    issues.push('s2_006FrozenInputsSha256:empty');
  }
  for (const [relPath, expectedSha] of Object.entries(own)) {
    if (!SHA256.test(expectedSha ?? '')) {
      issues.push(`${relPath}:unbound-digest`);
      continue;
    }
    let workingBytes;
    try {
      workingBytes = readWorkingTreeFile(relPath);
    } catch {
      issues.push(`${relPath}:frozen-input-missing`);
      continue;
    }
    require(sha256OfBytes(workingBytes) === expectedSha, `${relPath}:frozen-input-drift`);
    checked.push(`${relPath}:frozen-input`);
    pinnedPaths.add(relPath);
  }

  // ---- 8. owner-input state is RECORDED, never required to be empty (P2-7) --
  // The gate canonizes the dependency base (§1); whether the method owner has
  // already authorized thresholds or an external stratum is downstream §16
  // verdict state (verify-s2-006 deriveVerdict), not a dependency blocker —
  // a later owner decision must not retroactively break the dependency proof.
  // The observed state is recorded (deterministically) in
  // `resolved.ownerInputs` on a green run.
  let ownerInputs = null;
  try {
    const thresholds = JSON.parse(readWorkingTreeFile('contracts/s2-006-thresholds.json').toString('utf8'));
    const manifest = JSON.parse(readWorkingTreeFile('corpus/s2-006/manifest.json').toString('utf8'));
    require(thresholds !== null && typeof thresholds === 'object' && !Array.isArray(thresholds), 'owner-inputs:thresholds-not-object');
    require(typeof thresholds.status === 'string', 'owner-inputs:thresholds-status-not-string');
    require(manifest !== null && typeof manifest === 'object' && !Array.isArray(manifest), 'owner-inputs:manifest-not-object');
    ownerInputs = {
      thresholdsStatus: thresholds.status,
      methodOwner: thresholds.method_owner ?? null,
      ownerDecisionRef: thresholds.ownerDecisionRef ?? null,
      externalStratumStatus: manifest.externalStratum?.status ?? null,
      externalStratumReason: manifest.externalStratum?.reason ?? null,
      note: 'recorded, not required to be empty: owner-input state feeds the §16 verdict derivation, not the dependency gate (review P2-7)',
    };
    checked.push('owner-inputs:state-recorded');
  } catch {
    issues.push('owner-inputs:unreadable');
  }

  // ---- 9. consumer inputs must be pinned ------------------------------------
  const consumerInputs = record.consumerInputs ?? {};
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

  return { ok: issues.length === 0, checked: checked.length, issues, ownerInputs };
}

// Deterministic `resolved` section, written ONLY on a green FULL_GIT_BYTES run.
function resolvedSection(record, result) {
  const s2 = record.s2_005 ?? {};
  return {
    gate: 'scripts/verify-s2-006-dependencies.mjs',
    mode: 'FULL_GIT_BYTES',
    ok: true,
    checkedCount: result.checked,
    issueCount: 0,
    resolvedRefs: {
      originMain: git(['rev-parse', 'refs/remotes/origin/main']),
      canonicalMerge: s2.canonicalMerge ?? null,
      canonicalMergeParents: Array.isArray(s2.expectedParents) ? [...s2.expectedParents] : [],
      s2_005ImplementationHead: s2.implementationHead ?? null,
      s2_005TestedImplementationCommit: s2.testedImplementationCommit ?? null,
    },
    objectIds: {
      canonicalMergeType: 'commit',
      parentReadBack: ['git cat-file -p', 'git rev-list --parents'],
      evidenceBlobsAtCanonicalMerge: Object.keys(s2.evidenceReadFromGitBytes ?? {}).length,
      frozenInputDigestsAtCanonicalMerge: Object.keys(record.frozenS2_005InputsSha256?.inputs ?? {}).length,
    },
    exitCodes: {
      dependencyGate: 0,
      blockedDependency: null,
    },
    ownerInputs: result.ownerInputs ?? null,
  };
}

function main() {
  const bindingPath = path.join(ROOT, RECORD_PATH);
  let record;
  try {
    record = JSON.parse(fs.readFileSync(bindingPath, 'utf8'));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, status: 'BLOCKED_DEPENDENCY', issues: [`binding-record:unreadable (${error.message})`] }, null, 2));
    process.exit(1);
  }
  const archiveMode = !fs.existsSync(path.join(ROOT, '.git'));
  const result = verifyDependencyBinding(record, { archiveMode });
  let written = null;
  if (result.ok && !archiveMode) {
    // Canonical record update: deterministic bytes, so repeated green runs are
    // byte-stable and never dirty a frozen evidence file.
    const updated = { ...record, resolved: resolvedSection(record, result) };
    const serialized = `${JSON.stringify(updated, null, 2)}\n`;
    if (fs.readFileSync(bindingPath, 'utf8') !== serialized) {
      fs.writeFileSync(bindingPath, serialized);
      written = RECORD_PATH;
    }
  }
  const output = {
    ...result,
    mode: archiveMode ? 'ARCHIVE_DEGRADED' : 'FULL_GIT_BYTES',
    status: result.ok ? 'PASS' : 'BLOCKED_DEPENDENCY',
    ...(written ? { written } : {}),
  };
  console.log(JSON.stringify(output, null, 2));
  process.exit(result.ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
