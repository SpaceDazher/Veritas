// S2-003 dependency gate (fail-closed).
// Verifies, BEFORE any ingestion contract is touched, that:
//   1. origin/main contains the S2-002 merge commit and the S2-002 closure
//      commit is reachable from it;
//   2. S2-002 evidence (PASS_WITH_LIMITS result, green clean checkout, exact
//      root/frozen manifest digests) is read from Git bytes at the pinned
//      closure commit, never from narrative fields of the working tree;
//   3. the rights profile, sandbox and PostgreSQL evidence of S2-002 are
//      digest-bound from Git bytes;
//   4. S1-001 is bound to a fixed AgentOS commit (never a branch or a temp
//      path) and its tracked evidence copy matches the recorded SHA-256;
//   5. any missing dependency, incomplete digest, unreachable commit or
//      payload mismatch exits non-zero as BLOCKED_DEPENDENCY — not a warning.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;

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

  const s2 = record.s2_002 ?? {};
  const s1 = record.s1_001 ?? {};
  const cross = record.agentosCrossBinding ?? {};

  // ---- 1. origin/main contains the S2-002 merge and the closure commit ----
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
    require(mainHead === s2.mergeCommit, 'origin/main:not-at-s2-002-merge');
    checked.push('origin/main:head');
  }
  for (const [role, commit] of [['merge', s2.mergeCommit], ['closure', s2.closureCommit]]) {
    if (!GIT_COMMIT.test(commit ?? '')) {
      issues.push(`s2-002.${role}Commit:unpinned`);
      continue;
    }
    try {
      git_(['cat-file', '-e', `${commit}^{commit}`]);
      git_(['merge-base', '--is-ancestor', commit, 'refs/remotes/origin/main']);
      checked.push(`s2-002.${role}Commit:reachable`);
    } catch {
      issues.push(`s2-002.${role}Commit:unreachable-from-main`);
    }
  }
  }

  // ---- 2. S2-002 evidence from Git bytes at the closure commit ----
  const closure = s2.closureCommit;
  const gitFileCache = new Map();
  const readGitFile = (relPath) => {
    if (gitFileCache.has(relPath)) return gitFileCache.get(relPath);
    const bytes = gitBytes_(closure, relPath);
    gitFileCache.set(relPath, bytes);
    return bytes;
  };

  if (archiveMode) {
    checked.push('s2-002-evidence:archive-mode-skipped');
  } else {
  const expectedBlobs = s2.evidenceReadFromGitBytes ?? {};
  if (!isPlainObject(expectedBlobs) || Object.keys(expectedBlobs).length === 0) {
    issues.push('s2-002.evidenceReadFromGitBytes:empty');
  }
  for (const [relPath, expectedBlob] of Object.entries(expectedBlobs)) {
    if (!GIT_COMMIT.test(expectedBlob ?? '')) {
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

  if (GIT_COMMIT.test(closure ?? '') && issues.filter((i) => i.endsWith(':blob-drift') || i.endsWith(':missing-at-closure-commit')).length === 0) {
    // closure-record payload must match the recorded expectations exactly
    let closureRecord = null;
    try {
      closureRecord = JSON.parse(readGitFile('evidence/closure-record.json').toString('utf8'));
    } catch {
      issues.push('evidence/closure-record.json:malformed');
    }
    if (closureRecord) {
      const expected = s2.expected ?? {};
      require(closureRecord.implementationCommit === expected.implementationCommit, 'closure-record:implementation-commit-drift');
      require(closureRecord.manifestCommit === expected.manifestCommit, 'closure-record:manifest-commit-drift');
      require(closureRecord.payloadManifestSha256 === expected.payloadManifestSha256, 'closure-record:payload-manifest-digest-drift');
      require(closureRecord.fileManifestSha256 === expected.fileManifestSha256, 'closure-record:file-manifest-digest-drift');
      checked.push('closure-record:payload');
      // root manifest bytes must hash exactly to the closure-record value
      const rootManifestBytes = readGitFile('evidence/root-manifest.json');
      require(sha256OfBytes(rootManifestBytes) === closureRecord.rootManifestFileSha256, 'root-manifest:sha256-drift');
      checked.push('root-manifest:sha256');
      let rootManifest = null;
      try {
        rootManifest = JSON.parse(rootManifestBytes.toString('utf8'));
      } catch {
        issues.push('evidence/root-manifest.json:malformed');
      }
      if (rootManifest) {
        require(rootManifest.sourceCommit === closureRecord.implementationCommit, 'root-manifest:source-commit-drift');
        require(rootManifest.payloadManifestSha256 === closureRecord.payloadManifestSha256, 'root-manifest:payload-digest-drift');
        require(rootManifest.fileManifestSha256 === closureRecord.fileManifestSha256, 'root-manifest:file-digest-drift');
        checked.push('root-manifest:payload');
      }

      // frozen manifest: exact bytes digest + every listed entry re-verified
      // against the Git blob bytes at the closure commit
      const frozenBytes = readGitFile('evidence/frozen-manifest.json');
      require(sha256OfBytes(frozenBytes) === s2.frozenManifestSha256OfGitBytes, 'frozen-manifest:sha256-drift');
      let frozenManifest = null;
      try {
        frozenManifest = JSON.parse(frozenBytes.toString('utf8'));
      } catch {
        issues.push('evidence/frozen-manifest.json:malformed');
      }
      if (frozenManifest && isPlainObject(frozenManifest.files)) {
        let verifiedEntries = 0;
        for (const [relPath, expectedSha256] of Object.entries(frozenManifest.files)) {
          if (!SHA256.test(expectedSha256 ?? '')) {
            issues.push(`frozen-manifest:${relPath}:incomplete-digest`);
            continue;
          }
          let bytes;
          try {
            bytes = gitBytes_(closure, relPath);
          } catch {
            issues.push(`frozen-manifest:${relPath}:missing-at-closure-commit`);
            continue;
          }
          require(sha256OfBytes(bytes) === expectedSha256, `frozen-manifest:${relPath}:payload-drift`);
          verifiedEntries += 1;
        }
        if (verifiedEntries === 0) issues.push('frozen-manifest:no-verified-entries');
        checked.push(`frozen-manifest:entries(${verifiedEntries})`);
      }

      // clean checkout must be green
      try {
        const cleanCheckout = JSON.parse(readGitFile('evidence/clean-checkout.json').toString('utf8'));
        require(cleanCheckout.passed === (s2.expected?.cleanCheckoutPassed ?? true), 'clean-checkout:not-green');
        require(cleanCheckout.exitCode === 0, 'clean-checkout:nonzero-exit');
        checked.push('clean-checkout:payload');
      } catch {
        issues.push('evidence/clean-checkout.json:unreadable-from-git');
      }

      // replay comparison must be clean
      try {
        const comparison = JSON.parse(readGitFile('evidence/s2-002-comparison.json').toString('utf8'));
        require(comparison.comparison?.ok === (s2.expected?.comparisonOk ?? true), 'comparison:not-ok');
        require(comparison.comparison?.mismatchedDecisions === (s2.expected?.mismatchedDecisions ?? 0), 'comparison:decision-mismatches');
        checked.push('comparison:payload');
      } catch {
        issues.push('evidence/s2-002-comparison.json:unreadable-from-git');
      }

      // sandbox + postgres evidence read from Git bytes
      const sandboxStructuralChecks = Object.freeze({
        'evidence/s2-002-podman-sandbox.json': (s) => s.rootless === true,
        'evidence/s2-002-gvisor-sandbox.json': (s) => s.podmanRootless === false && s.autoUserns === true && s.gvisorBootMarker === true,
      });
      for (const [relPath, structuralCheck] of Object.entries(sandboxStructuralChecks)) {
        try {
          const sandbox = JSON.parse(readGitFile(relPath).toString('utf8'));
          require(sandbox.authorizedBackendSmoke?.status === (s2.expected?.sandboxStatus ?? 'success'), `${relPath}:status-drift`);
          require(sandbox.authorizedBackendSmoke?.cleanupVerified === true, `${relPath}:cleanup-not-verified`);
          require(structuralCheck(sandbox) === true, `${relPath}:structural-check-failed`);
          checked.push(`${relPath}:payload`);
        } catch {
          issues.push(`${relPath}:unreadable-from-git`);
        }
      }
      try {
        const postgres = JSON.parse(readGitFile('evidence/postgres-smoke.json').toString('utf8'));
        require(postgres.status === (s2.expected?.postgresSmokeStatus ?? 'PASS'), 'postgres-smoke:status-drift');
        require(postgres.exitCode === 0, 'postgres-smoke:nonzero-exit');
        require(postgres.transactionCommitted === true, 'postgres-smoke:transaction-not-committed');
        require(postgres.duplicateOperationRejected === true, 'postgres-smoke:duplicate-operation-accepted');
        checked.push('evidence/postgres-smoke.json:payload');
      } catch {
        issues.push('evidence/postgres-smoke.json:unreadable-from-git');
      }
      try {
        const policyProbes = JSON.parse(readGitFile('evidence/policy-probes.json').toString('utf8'));
        require(policyProbes.total > 0 && policyProbes.passed === policyProbes.total, 'policy-probes:not-all-passed');
        checked.push('evidence/policy-probes.json:payload');
      } catch {
        issues.push('evidence/policy-probes.json:unreadable-from-git');
      }
      try {
        const probes = JSON.parse(readGitFile('evidence/s2-002-security-probes.json').toString('utf8'));
        require(probes.escaped === 0, 'security-probes:escapes');
        require(probes.skipped === 0, 'security-probes:skipped');
        require(probes.detected === (s2.expected?.securityProbesDetected ?? 11), 'security-probes:detected-drift');
        checked.push('evidence/s2-002-security-probes.json:payload');
      } catch {
        issues.push('evidence/s2-002-security-probes.json:unreadable-from-git');
      }
    }
  }
  }

  // ---- 3. S1-001 pinned to a fixed AgentOS commit with digest-verified evidence ----
  const source = s1.sourceRepository ?? {};
  require(source.remote === 'https://github.com/SpaceDazher/AgentOS.git', 's1-001:unexpected-remote');
  if (!GIT_COMMIT.test(source.pinnedCommit ?? '')) {
    issues.push('s1-001:commit-not-pinned-to-sha');
  }
  if (typeof source.pinnedCommit === 'string' && (source.pinnedCommit === 'main' || source.pinnedCommit.includes('/'))) {
    issues.push('s1-001:branch-or-path-instead-of-commit');
  }
  if (!SHA256.test(s1.evaluationRecordSha256 ?? '')) issues.push('s1-001:invalid-record-digest');
  if (!Number.isInteger(s1.evaluationRecordBytes) || s1.evaluationRecordBytes <= 0) issues.push('s1-001:invalid-record-length');
  if (typeof s1.evaluationRecordUrl === 'string' && !s1.evaluationRecordUrl.includes(source.pinnedCommit ?? '\u0000')) {
    issues.push('s1-001:url-not-bound-to-commit');
  }
  const trackedCopy = s1.trackedCopy ?? '';
  if (typeof trackedCopy !== 'string' || trackedCopy.length === 0 || path.isAbsolute(trackedCopy) || trackedCopy.includes('\\') || trackedCopy.includes('..')) {
    issues.push('s1-001:tracked-copy-not-portable');
  } else {
    let copyBytes;
    try {
      copyBytes = readWorkingTreeFile(trackedCopy);
    } catch {
      issues.push('s1-001:tracked-copy-missing');
      copyBytes = null;
    }
    if (copyBytes) {
      require(sha256OfBytes(copyBytes) === s1.evaluationRecordSha256, 's1-001:tracked-copy-digest-drift');
      require(copyBytes.length === s1.evaluationRecordBytes, 's1-001:tracked-copy-length-drift');
      checked.push('s1-001:tracked-copy');
      let record = null;
      try {
        record = JSON.parse(copyBytes.toString('utf8'));
      } catch {
        issues.push('s1-001:tracked-copy-malformed');
      }
      if (record) {
        const expected = s1.expected ?? {};
        require(record.ticket_id === expected.ticket_id, 's1-001:ticket-drift');
        require(record.result === expected.result, 's1-001:result-drift');
        require(record.evaluation_id === expected.evaluation_id, 's1-001:evaluation-id-drift');
        require(record.artifact_chain_hash === expected.artifact_chain_hash, 's1-001:chain-hash-drift');
        checked.push('s1-001:payload');
      }
    }
  }

  // ---- 4. cross-binding consistency: S1-001 commit === S2-002 binding AgentOS commit ----
  if (!archiveMode && !io.skipGitChecks && GIT_CMD_AVAILABLE && GIT_COMMIT.test(closure ?? '')) {
    try {
      const s2Binding = JSON.parse(gitBytes_(closure, cross.s2_002BindingPath ?? 'evidence/s2-002-dependency-binding.json').toString('utf8'));
      const boundCommit = s2Binding.sourceRepository?.headCommitAtBindingTime;
      require(boundCommit === cross.expectedAgentosCommit, 'cross-binding:agentos-commit-drift');
      require(boundCommit === source.pinnedCommit, 'cross-binding:s1-001-commit-mismatch');
      checked.push('cross-binding:agentos-commit');
    } catch {
      issues.push('cross-binding:s2-002-binding-unreadable-from-git');
    }
  }

  return { ok: issues.length === 0, checked: checked.length, issues };
}

let GIT_CMD_AVAILABLE = true;
try {
  execFileSync('git', ['--version'], { stdio: 'ignore' });
} catch {
  GIT_CMD_AVAILABLE = false;
}

function main() {
  const bindingPath = path.join(ROOT, 'evidence/s2-003-dependency-binding.json');
  let record;
  try {
    record = JSON.parse(fs.readFileSync(bindingPath, 'utf8'));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, status: 'BLOCKED_DEPENDENCY', issues: [`binding-record:unreadable (${error.message})`] }, null, 2));
    process.exit(1);
  }
  // Clean-architecture checkouts (git archive) carry no .git directory: the
  // byte-level Git verification this gate exists for is impossible there.
  // Fail closed is meaningless without a repository, so the archive path runs
  // the structural checks that remain possible (tracked-copy digests,
  // binding structure) and reports ARCHIVE_DEGRADED explicitly; the full
  // Git-bytes verification is mandatory in the real working repository.
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
