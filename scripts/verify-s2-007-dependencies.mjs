// S2-007 dependency gate (issue #7 §1, fail-closed).
//
// Every S2-007 implementation result is downstream of a claim that the upstream
// S2-001/S2-002 surfaces are still the ones the board was specified against.
// A clean local test run, a matching branch name or a previous task's "PASS" in
// a report proves none of that. This gate therefore proves it from bytes:
//
//   1. refs/remotes/origin/main resolves to the recorded canonicalization
//      commit f590d37ea8e861431abf3f89f59e01a889ab903d (tree
//      c15ce47a35987c27a7610d4b8e8847b59f776924). The merge shape and the
//      upstream chain are CHECKED, not assumed: the commit's tree line and its
//      parents are read twice each (cat-file vs rev-parse), the parent list must
//      be exactly the recorded two in Git order, the first parent must be the
//      same commit the S2-006 record pins as its own canonicalization merge, and
//      the implementation base (HEAD) must descend from the pin. A later advance
//      of origin/main is refused, not absorbed: an ancestor check proves history,
//      not that the protected surface is unchanged.
//   2. The S2-001 product contract, the S2-002 policy/sandbox contracts and the
//      S2-002 evaluation evidence are read ONLY via `git show <commit>:<path>`.
//      Each Git blob id, SHA-256 and byte length must match the record, and the
//      digests are additionally cross-checked against independent expectations
//      read from those same Git bytes (evidence/frozen-manifest.json and
//      evidence/s2-002-comparison-integrity.json) — never against the working
//      tree and never against a self-generated narrative.
//   3. The S2-002 evidence PAYLOAD is re-verified from those bytes: green clean
//      checkout, every hard counter zero, green PostgreSQL replay, distinct run
//      identities, probes escaped/skipped zero.
//   4. `npm run verify:s2-002-dependencies`, `npm run verify:s2-002` and
//      `npm run manifest:check` are re-run as SUBPROCESSES and their real exit
//      codes recorded. `manifest:check` legitimately fails while the S2-007 file
//      inventory is still open, because the root manifest is regenerated once at
//      the very end; such an exit is recorded as REQUIRES_FINAL_MANIFEST with its
//      real exit code — never as green, and never as a dependency failure. Any
//      other non-zero exit is a real failure and blocks.
//   5. The internal sandbox gate must ALLOW exactly the requested profile, and
//      that ALLOW must be backed by the S2-002 OS-control evidence bytes. If it
//      does not, the LIVE run stays forbidden and this record says so.
//   6. S2-003/004/005 contribute EXPLICIT references to versioned artifacts
//      only: each reference must resolve at the pin, carry a pinned digest, and
//      name a version anchor that is a real ancestor commit. Their content may
//      not become a scheduler instruction, so the board tree must not name them.
//   7. S2-006E is NOT mandatory for the S2-007 core. If any verifier-derived
//      signal is admitted, only engineering properties are admitted; the official
//      S2-006 NEEDS_INPUT status and the absent independent semantic calibration
//      FORBID such a signal as an automatic Gate for DONE. The gate asserts
//      structurally (from the frozen transition table and the DONE guard) and
//      textually (by scanning the board tree) that no path reaches DONE from a
//      verifier signal.
//   8. The eight S2-007 contract schemas, the 0008 migration and the three frozen
//      modules are bound by SHA-256 at their own commit and must be byte-identical
//      in the working tree. They are read, never weakened, extended or
//      re-declared here.
//   9. A missing, drifted or unverifiable mandatory binding exits 1 as
//      BLOCKED_DEPENDENCY. It is never a warning, and no implementation result
//      may be recorded on top of a non-canonical branch.
//
//   node scripts/verify-s2-007-dependencies.mjs
//
// A dependency run must not be able to corrupt the evidence it verifies:
// the subprocess gates are sandboxed by a declared write allowlist, and any
// tracked canonical evidence they mutated is restored from the pinned commit and
// reported. On a fully green FULL_GIT_BYTES verification the `resolved` section
// of evidence/s2-007-dependency-binding.json is rewritten with the observed
// refs, gate statuses and exit codes; the content is deterministic (no wall
// clock, no durations, no pids), so the rewrite is byte-stable. On any failure
// the committed record is left untouched and the gate exits 1.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  PROVEN_SANDBOX_PROFILE_IDS,
  SANDBOX_PROFILES,
  TRANSITIONS,
  isExecutableSandboxProfile,
} from '../src/lib/agentboard/constants.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RECORD_PATH = 'evidence/s2-007-dependency-binding.json';
const BOARD_TREE = 'src/lib/agentboard';
const BOARD_SURFACE_TREES = ['src/lib/agentboard', 'src/app/api/agent-board'];
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const GIT_BLOB = /^[0-9a-f]{40}$/;
const APPROVAL_ACTOR_KINDS_ALLOWED = Object.freeze(['human_owner', 'human_reviewer', 'deterministic_gate']);
// Only the digest convention of the S2-006 canonical JSON may be reused from the
// verifier package. A verifier DECISION module must never enter the board.
const PERMITTED_VERIFIER_IMPORTS = Object.freeze(['../verifier/canonical-json.mjs']);
const RERUN_TIMEOUT_MS = Object.freeze({
  'verify-s2-002-dependencies': 300_000,
  'verify-s2-002': 900_000,
  'manifest-check': 300_000,
});

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
// checkouts, so an executable-surface check never degrades to a no-op.
function blobIdOfBytes(bytes) {
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function dottedPointer(root, pointer) {
  return String(pointer)
    .split('.')
    .reduce((node, key) => (isPlainObject(node) ? node[key] : undefined), root);
}

function listFilesRecursive(absDir) {
  let entries;
  try {
    entries = fs.readdirSync(absDir, { withFileTypes: true });
  } catch {
    return [];
  }
  const files = [];
  for (const entry of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const abs = path.join(absDir, entry.name);
    if (entry.isDirectory()) files.push(...listFilesRecursive(abs));
    else if (entry.isFile()) files.push(abs);
  }
  return files;
}

function tailOf(text, lines = 12) {
  if (typeof text !== 'string' || text.length === 0) return [];
  return text.trimEnd().split('\n').slice(-lines);
}

function findFunctionSource(text, name) {
  const start = text.search(new RegExp(`^(?:export\\s+)?function\\s+${name}\\s*\\(`, 'm'));
  if (start === -1) return null;
  const rest = text.slice(start + 1);
  const next = rest.search(/^(?:export\s+)?(?:async\s+)?function\s+[A-Za-z0-9_]+\s*\(|^(?:export\s+)?const\s+[A-Za-z0-9_]+\s*=/m);
  return next === -1 ? text.slice(start + 1) : text.slice(start + 1, start + 1 + next);
}

export function verifyDependencyBinding(record, io = {}) {
  const issues = [];
  const checked = [];
  const details = {};
  const deferred = [];
  const restored = [];
  const git_ = io.git ?? git;
  const gitBytes_ = io.gitBytes ?? gitBytes;
  const runRerunGate_ = io.runRerunGate ?? null;
  const readWorkingTreeFile = io.readWorkingTreeFile ?? ((rel) => fs.readFileSync(path.join(ROOT, rel)));

  const require = (condition, code) => {
    if (!condition) issues.push(code);
    return condition;
  };
  const ok = (code) => checked.push(code);

  if (!isPlainObject(record)) {
    return { ok: false, checked: 0, issues: ['record:not-object'], details, deferred, restored };
  }
  // An archive checkout has no object database, so nothing here can be proven
  // from origin/main. Unlike the S2-006 gate there is deliberately no degraded
  // mode: a dependency proof that cannot read Git bytes is not a dependency
  // proof, and S2-007 may not be built on one.
  if (io.archiveMode === true || !fs.existsSync(path.join(ROOT, '.git'))) {
    return {
      ok: false,
      checked: 0,
      issues: ['archive-mode:no-object-database'],
      details: { mode: 'UNVERIFIABLE_NO_OBJECT_DATABASE' },
      deferred,
      restored,
    };
  }

  const base = record.base ?? {};
  const commit = base.canonicalizationCommit;
  const tree = base.canonicalizationTree;

  // ---- 1. the base: pin, tree, merge shape, chain, ancestry -----------------
  if (!GIT_COMMIT.test(commit ?? '') || !GIT_COMMIT.test(tree ?? '')) {
    issues.push('base:canonicalization-not-pinned-to-commit-and-tree');
  } else {
    let mainHead = '';
    try {
      mainHead = git_(['rev-parse', base.ref]);
    } catch {
      issues.push('origin/main:unresolvable');
    }
    if (GIT_COMMIT.test(mainHead)) {
      if (mainHead === commit) {
        ok('origin/main:at-pinned-canonicalization-commit');
      } else {
        let advanced = false;
        try {
          git_(['merge-base', '--is-ancestor', commit, base.ref]);
          advanced = true;
        } catch {
          advanced = false;
        }
        // A plain ancestor check is NOT a bind: it would silently accept an
        // origin/main whose protected S2-001/S2-002 surface may have changed.
        issues.push(advanced ? 'origin/main:advanced-past-pinned-canonicalization' : 'origin/main:diverged-from-pinned-canonicalization');
      }
    }
    try {
      git_(['cat-file', '-e', `${commit}^{commit}`]);
      ok('canonicalizationCommit:object-exists');
    } catch {
      issues.push('canonicalizationCommit:object-missing');
    }
    // Tree: two independent reads of the same object must agree.
    let treeFromObject = '';
    let treeFromRevParse = '';
    try {
      treeFromObject = (git_(['cat-file', '-p', commit]).split('\n').find((line) => line.startsWith('tree ')) ?? '').slice('tree '.length).trim();
      treeFromRevParse = git_(['rev-parse', `${commit}^{tree}`]);
      require(GIT_COMMIT.test(treeFromObject) && treeFromObject === treeFromRevParse, 'canonicalizationCommit:tree-reads-disagree');
      require(treeFromObject === tree, 'canonicalizationCommit:tree-drift');
      ok('canonicalizationTree:cat-file+rev-parse');
    } catch {
      issues.push('canonicalizationCommit:tree-unreadable');
    }
    // Merge shape: exactly the recorded parents, in Git order, read twice.
    const expectedParents = Array.isArray(base.expectedParents) ? base.expectedParents : [];
    if (expectedParents.length !== 2 || expectedParents.some((p) => !GIT_COMMIT.test(p ?? ''))) {
      issues.push('base.expectedParents:not-two-pinned-commits');
    } else {
      let catFileParents = [];
      let revListParents = [];
      try {
        catFileParents = git_(['cat-file', '-p', commit])
          .split('\n')
          .filter((line) => line.startsWith('parent '))
          .map((line) => line.slice('parent '.length).trim());
        revListParents = git_(['rev-list', '--parents', '-n', '1', commit]).split(' ').slice(1);
      } catch {
        issues.push('canonicalizationCommit:parents-unreadable');
      }
      for (const [source, parents] of [['cat-file', catFileParents], ['rev-list', revListParents]]) {
        if (parents.length !== 2) {
          issues.push(`canonicalizationCommit:${source}:parent-count-${parents.length}`);
          continue;
        }
        if (parents[0] !== expectedParents[0]) issues.push(`canonicalizationCommit:${source}:first-parent-drift`);
        if (parents[1] !== expectedParents[1]) issues.push(`canonicalizationCommit:${source}:second-parent-drift`);
      }
      if (catFileParents.length === 2 && revListParents.length === 2) ok('canonicalizationCommit:parents(cat-file+rev-list)');
      for (const [index, parent] of expectedParents.entries()) {
        try {
          git_(['cat-file', '-e', `${parent}^{commit}`]);
          ok(`canonicalizationCommit:parent[${index}]:object-exists`);
        } catch {
          issues.push(`canonicalizationCommit:parent[${index}]:object-missing`);
        }
      }
    }
    // Upstream chain: the first parent must be the exact commit the S2-006
    // dependency record pins, read from the pinned bytes of that record.
    const anchor = base.upstreamChainAnchor ?? {};
    if (typeof anchor.path === 'string' && SHA256.test(anchor.sha256 ?? '')) {
      let anchorBytes = null;
      try {
        anchorBytes = gitBytes_(commit, anchor.path);
      } catch {
        issues.push('base.upstreamChainAnchor:unreadable-from-git');
      }
      if (anchorBytes) {
        if (sha256OfBytes(anchorBytes) !== anchor.sha256) {
          issues.push('base.upstreamChainAnchor:sha256-drift');
        } else {
          ok('base.upstreamChainAnchor:sha256(git-bytes)');
          let anchorRecord = null;
          try {
            anchorRecord = JSON.parse(anchorBytes.toString('utf8'));
          } catch {
            issues.push('base.upstreamChainAnchor:malformed');
          }
          if (anchorRecord) {
            const anchored = dottedPointer(anchorRecord, anchor.jsonPointer ?? '');
            require(anchored === anchor.expectedValue, 'base.upstreamChainAnchor:value-drift');
            require(anchored === expectedParents[0], 'base:first-parent-not-the-s2-006-canonical-merge');
            ok('upstream-chain:continuous');
          }
        }
      }
    } else {
      issues.push('base.upstreamChainAnchor:unbound');
    }
    // The implementation must sit on top of the pin, not beside it.
    if (GIT_COMMIT.test(base.implementationBaseCommit ?? '')) {
      let descends = false;
      try {
        git_(['merge-base', '--is-ancestor', commit, 'HEAD']);
        descends = true;
      } catch {
        descends = false;
      }
      if (!descends) issues.push('base:HEAD-does-not-descend-from-pinned-canonicalization');
      else ok('implementation-base:descends-from-canonicalization');
      let headCommit = '';
      try {
        headCommit = git_(['rev-parse', 'HEAD']);
      } catch {
        issues.push('base:HEAD-unresolvable');
      }
      details.base = {
        originMain: mainHead || null,
        canonicalizationCommit: commit,
        canonicalizationTree: treeFromRevParse || null,
        headCommit: headCommit || null,
        headDescendsFromCanonicalization: descends,
      };
    } else {
      issues.push('base.implementationBaseCommit:unpinned');
    }
  }

  // ---- 2. upstream canonicalization read ONLY from Git bytes ---------------
  const groups = record.upstreamCanonicalization ?? {};
  const crossChecks = record.independentCrossChecks ?? {};
  let frozenManifest = null;
  if (typeof crossChecks.frozenManifest?.path === 'string') {
    try {
      frozenManifest = JSON.parse(gitBytes_(commit, crossChecks.frozenManifest.path).toString('utf8'));
    } catch {
      issues.push('independentCrossChecks.frozenManifest:unreadable-from-git');
    }
  }
  const coveredGroups = new Set(Array.isArray(crossChecks.frozenManifest?.coveredGroups) ? crossChecks.frozenManifest.coveredGroups : []);
  for (const [groupName, paths] of Object.entries(isPlainObject(groups) ? groups : {})) {
    if (groupName === 'readRule' || !isPlainObject(paths)) continue;
    const entries = Object.entries(paths);
    if (entries.length === 0) issues.push(`upstreamCanonicalization.${groupName}:empty`);
    for (const [relPath, expected] of entries) {
      if (!isPlainObject(expected) || !GIT_BLOB.test(expected.blob ?? '') || !SHA256.test(expected.sha256 ?? '')) {
        issues.push(`${relPath}:unbound-blob-or-digest`);
        continue;
      }
      let actualBlob = '';
      try {
        actualBlob = git_(['rev-parse', `${commit}:${relPath}`]);
      } catch {
        issues.push(`${relPath}:missing-at-canonicalization-commit`);
        continue;
      }
      if (actualBlob !== expected.blob) {
        issues.push(`${relPath}:blob-drift`);
        continue;
      }
      ok(`${relPath}:blob`);
      let bytes = null;
      try {
        bytes = gitBytes_(commit, relPath);
      } catch {
        issues.push(`${relPath}:unreadable-from-git`);
        continue;
      }
      if (sha256OfBytes(bytes) !== expected.sha256) issues.push(`${relPath}:sha256-drift`);
      else ok(`${relPath}:sha256(git-bytes)`);
      if (Number.isInteger(expected.bytes) && bytes.length !== expected.bytes) issues.push(`${relPath}:length-drift`);
      // Independent expectation, when one exists. A missing coverage entry is
      // recorded, never silently treated as agreement.
      if (frozenManifest && coveredGroups.has(groupName)) {
        const manifestDigest = isPlainObject(frozenManifest.files) ? frozenManifest.files[relPath] : undefined;
        if (manifestDigest === undefined) ok(`${relPath}:not-covered-by-frozen-manifest`);
        else if (manifestDigest !== expected.sha256) issues.push(`${relPath}:frozen-manifest-cross-check-drift`);
        else ok(`${relPath}:frozen-manifest-cross-check`);
      }
    }
  }

  // Independent digests for the three S2-002 replay payloads, read from Git.
  if (typeof crossChecks.s2_002ComparisonIntegrity?.path === 'string') {
    let integrity = null;
    try {
      integrity = JSON.parse(gitBytes_(commit, crossChecks.s2_002ComparisonIntegrity.path).toString('utf8'));
    } catch {
      issues.push('independentCrossChecks.s2_002ComparisonIntegrity:unreadable-from-git');
    }
    const s2Evidence = groups.s2_002EvaluationEvidence ?? {};
    for (const relPath of Array.isArray(crossChecks.s2_002ComparisonIntegrity.covers) ? crossChecks.s2_002ComparisonIntegrity.covers : []) {
      const claimed = isPlainObject(integrity?.files) ? integrity.files[relPath] : undefined;
      const record_ = s2Evidence[relPath];
      if (!SHA256.test(claimed ?? '') || !isPlainObject(record_)) {
        issues.push(`${relPath}:comparison-integrity-cross-check-unavailable`);
        continue;
      }
      if (claimed !== record_.sha256) issues.push(`${relPath}:comparison-integrity-cross-check-drift`);
      else ok(`${relPath}:comparison-integrity-cross-check`);
    }
  }

  // ---- 3. the S2-002 evidence PAYLOAD, re-verified from those bytes --------
  const expected = record.s2_002EvidencePayload?.expected ?? {};
  const readGitJson = (relPath) => {
    const text = gitBytes_(commit, relPath).toString('utf8');
    return JSON.parse(text);
  };
  const hardCounters = isPlainObject(expected.hardCounters) ? expected.hardCounters : {};
  // green clean checkout
  try {
    const cleanCheckout = readGitJson('evidence/clean-checkout.json');
    require(cleanCheckout.passed === (expected.cleanCheckoutPassed ?? true), 'clean-checkout:not-green');
    require(cleanCheckout.exitCode === (expected.cleanCheckoutExitCode ?? 0), 'clean-checkout:nonzero-exit');
    if (expected.dbReplayGreen === true) {
      require(typeof cleanCheckout.databaseWorkspaceSmoke === 'string' && cleanCheckout.databaseWorkspaceSmoke.startsWith('PASS'), 'clean-checkout:database-workspace-smoke-not-green');
    }
    ok('s2-002-payload:clean-checkout');
  } catch (error) {
    issues.push(`clean-checkout-payload:unreadable-from-git (${error.message})`);
  }
  // green PostgreSQL replay
  try {
    const smoke = readGitJson('evidence/postgres-smoke.json');
    require(smoke.status === (expected.postgresSmokeStatus ?? 'PASS'), 'postgres-smoke:status-not-pass');
    require(smoke.exitCode === (expected.postgresSmokeExitCode ?? 0), 'postgres-smoke:nonzero-exit');
    if (expected.dbReplayGreen === true) {
      require(smoke.transactionCommitted === true, 'postgres-smoke:no-committed-transaction');
      require(smoke.duplicateOperationRejected === true, 'postgres-smoke:idempotency-not-enforced');
      require(smoke.cleanupVerified === true, 'postgres-smoke:cleanup-not-verified');
      require(smoke.hostPortExposedBeyondLoopback === false, 'postgres-smoke:port-exposed');
    }
    ok('s2-002-payload:postgres-replay');
  } catch (error) {
    issues.push(`postgres-smoke-payload:unreadable-from-git (${error.message})`);
  }
  // hard counters zero and distinct run identities
  const runSummaries = {};
  for (const role of ['a', 'b']) {
    const relPath = `evidence/s2-002-run-${role}.json`;
    try {
      const run = readGitJson(relPath);
      const summary = run.summary ?? {};
      runSummaries[role] = { summary, observationsDigest: run.observationsDigest ?? null };
      require(summary.trialCount === (expected.comparedTrials ?? summary.trialCount), `s2-002-run-${role}:trial-count-drift`);
      for (const [counter, limit] of Object.entries(hardCounters)) {
        require((summary.counters ?? {})[counter] === limit, `s2-002-run-${role}:hard-counter-${counter}-not-zero`);
      }
      const latency = summary.revocationLatency ?? {};
      require(latency.trials >= (expected.revocationMinTrialsPerRun ?? 0), `s2-002-run-${role}:too-few-revocation-trials`);
      require(latency.maxMs <= (expected.revocationMaxLatencyMs ?? Infinity), `s2-002-run-${role}:revocation-latency-over-budget`);
      require((latency.allowAfterCommit ?? 1) === (expected.revocationAllowAfterCommit ?? 0), `s2-002-run-${role}:allow-after-revocation-commit`);
      ok(`s2-002-payload:run-${role}-counters-zero`);
    } catch (error) {
      issues.push(`s2-002-run-${role}-payload:unreadable-from-git (${error.message})`);
    }
  }
  if (runSummaries.a && runSummaries.b) {
    const a = runSummaries.a;
    const b = runSummaries.b;
    const distinct = ['runId', 'executorId', 'nonceBase', 'outputRoot'].filter((key) => a.summary[key] !== b.summary[key]);
    if (expected.distinctRunIdentities === true) {
      require(distinct.length === 4, `s2-002-runs:identities-not-distinct (${distinct.join(',')})`);
      require(a.observationsDigest !== b.observationsDigest, 's2-002-runs:observation-digests-identical');
      require(a.summary.corpusDigest === b.summary.corpusDigest, 's2-002-runs:different-corpora');
      ok('s2-002-payload:distinct-run-identities');
    }
  }
  try {
    const comparison = readGitJson('evidence/s2-002-comparison.json');
    require(comparison.comparison?.ok === (expected.comparisonOk ?? true), 's2-002-comparison:not-ok');
    require(comparison.comparison?.mismatchedDecisions === (expected.mismatchedDecisions ?? 0), 's2-002-comparison:decision-mismatches');
    require(comparison.comparison?.comparedTrials === (expected.comparedTrials ?? 0), 's2-002-comparison:compared-trials-drift');
    require((comparison.comparison?.counterViolations ?? []).length === (expected.counterViolations ?? 0), 's2-002-comparison:counter-violations');
    require((comparison.comparison?.expectedOracleViolations ?? []).length === (expected.expectedOracleViolations ?? 0), 's2-002-comparison:oracle-violations');
    ok('s2-002-payload:comparison');
  } catch (error) {
    issues.push(`s2-002-comparison-payload:unreadable-from-git (${error.message})`);
  }
  try {
    const probes = readGitJson('evidence/s2-002-security-probes.json');
    require(probes.escaped === (expected.probesEscaped ?? 0), 's2-002-probes:escapes');
    require(probes.skipped === (expected.probesSkipped ?? 0), 's2-002-probes:skipped');
    ok('s2-002-payload:security-probes');
  } catch (error) {
    issues.push(`s2-002-probes-payload:unreadable-from-git (${error.message})`);
  }

  // ---- 4. the re-run gates: real subprocesses, real exit codes -------------
  const rerunStatuses = {};
  const protectedPaths = new Set();
  for (const entry of Array.isArray(record.reRunGates) ? record.reRunGates : []) {
    for (const relPath of Array.isArray(entry.mayWriteCanonicalEvidence) ? entry.mayWriteCanonicalEvidence : []) {
      protectedPaths.add(relPath);
    }
  }
  const before = new Map();
  for (const relPath of protectedPaths) {
    try {
      before.set(relPath, sha256OfBytes(readWorkingTreeFile(relPath)));
    } catch {
      before.set(relPath, null);
    }
  }
  for (const entry of Array.isArray(record.reRunGates) ? record.reRunGates : []) {
    const id = entry?.id;
    if (typeof id !== 'string' || typeof entry.command !== 'string') {
      issues.push('reRunGates:malformed-entry');
      continue;
    }
    // The subprocess is derived from the DECLARED command, never from the
    // record key: `npm run <script>` is exactly what the record promises will
    // be executed, so a typo in either place fails closed instead of quietly
    // running something else.
    const declared = entry.command.trim().split(/\s+/);
    if (declared.length !== 3 || declared[0] !== 'npm' || declared[1] !== 'run') {
      issues.push(`rerun.${id}:command-is-not-npm-run`);
      rerunStatuses[id] = { command: entry.command, exitCode: null, status: 'NOT_RUN' };
      continue;
    }
    if (runRerunGate_ === null) {
      issues.push(`rerun.${id}:not-run`);
      rerunStatuses[id] = { command: entry.command, exitCode: null, status: 'NOT_RUN' };
      continue;
    }
    const observed = runRerunGate_({ ...entry, npmScript: declared[2] }) ?? {};
    const combined = `${observed.stdout ?? ''}\n${observed.stderr ?? ''}`;
    const deferrable = Array.isArray(entry.deferrableStates) ? entry.deferrableStates : [];
    const signatures = Array.isArray(entry.staleManifestSignatures) ? entry.staleManifestSignatures : [];
    const deferrableHit = signatures.some((signature) => combined.includes(signature));
    let status;
    if (observed.timedOut === true) status = 'TIMED_OUT';
    else if (observed.exitCode === (entry.expectedExitCode ?? 0)) status = 'GREEN';
    else if (observed.exitCode !== 0 && deferrable.includes('REQUIRES_FINAL_MANIFEST') && deferrableHit) {
      // Honest middle state: the REAL exit code is kept and shown, the check is
      // neither green nor a dependency failure, and the obligation to
      // regenerate the root manifest at the end of the task is carried forward.
      status = 'REQUIRES_FINAL_MANIFEST';
      deferred.push({ id, command: entry.command, exitCode: observed.exitCode ?? null, reason: 'root manifest is regenerated once at the end of S2-007; the recorded exit code is the real one' });
    } else status = 'FAILED_NONZERO';
    rerunStatuses[id] = {
      command: entry.command,
      exitCode: observed.exitCode ?? null,
      signal: observed.signal ?? null,
      status,
    };
    if (status === 'GREEN') ok(`rerun.${id}:exit-0`);
    else if (status === 'REQUIRES_FINAL_MANIFEST') ok(`rerun.${id}:recorded-real-exit-code(${observed.exitCode ?? 'null'})`);
    else {
      issues.push(`rerun.${id}:${status.toLowerCase()}(exit=${observed.exitCode ?? 'null'})`);
      if (Array.isArray(observed.diagnostics)) rerunStatuses[id].diagnostics = observed.diagnostics;
      else rerunStatuses[id].stderrTail = tailOf(observed.stderr);
    }
  }
  // A dependency run must never be able to corrupt the evidence it verifies.
  for (const relPath of protectedPaths) {
    let now = null;
    try {
      now = sha256OfBytes(readWorkingTreeFile(relPath));
    } catch {
      now = null;
    }
    if (now === before.get(relPath)) continue;
    let tracked = false;
    try {
      git_(['ls-files', '--error-unmatch', '--', relPath]);
      tracked = true;
    } catch {
      tracked = false;
    }
    if (!tracked) {
      issues.push(`evidence-protection:${relPath}:untracked-mutation`);
      continue;
    }
    try {
      git_(['checkout', '--', relPath]);
      const after = sha256OfBytes(readWorkingTreeFile(relPath));
      if (after !== before.get(relPath)) issues.push(`evidence-protection:${relPath}:restore-failed`);
      else {
        restored.push(relPath);
        ok(`evidence-protection:${relPath}:restored-from-commit`);
      }
    } catch {
      issues.push(`evidence-protection:${relPath}:restore-error`);
    }
  }
  details.reRunGates = rerunStatuses;

  // ---- 5. the internal sandbox gate must ALLOW exactly the requested profile
  const sandbox = record.sandboxGate ?? {};
  const requestedProfileId = sandbox.requestedProfileId;
  let sandboxStatus = 'BLOCKED';
  if (typeof requestedProfileId !== 'string' || requestedProfileId.length === 0) {
    issues.push('sandboxGate.requestedProfileId:unpinned');
  } else {
    const profile = SANDBOX_PROFILES.find((candidate) => candidate.profile_id === requestedProfileId) ?? null;
    if (profile === null) {
      issues.push(`sandboxGate:profile-not-registered(${requestedProfileId})`);
    } else {
      const allows = isExecutableSandboxProfile(requestedProfileId) && PROVEN_SANDBOX_PROFILE_IDS.includes(requestedProfileId);
      if (!allows) issues.push(`sandboxGate:does-not-allow-requested-profile(${requestedProfileId})`);
      // The ALLOW must be backed by the S2-002 OS-control evidence bytes at the
      // pin, not by the profile's own claim about itself.
      const claimed = typeof profile.os_controls_evidence === 'string' ? profile.os_controls_evidence.replace(/^sha256:/, '') : '';
      let evidenceDigest = null;
      try {
        evidenceDigest = sha256OfBytes(gitBytes_(commit, sandbox.osControlsEvidencePath));
      } catch {
        issues.push('sandboxGate:os-controls-evidence-unreadable-from-git');
      }
      if (evidenceDigest !== null) {
        if (claimed !== evidenceDigest) issues.push('sandboxGate:os-controls-evidence-digest-drift');
        else ok('sandboxGate:os-controls-evidence-bound-to-git-bytes');
      }
      if (typeof sandbox.requestedTier === 'string' && profile.tier !== sandbox.requestedTier) {
        issues.push(`sandboxGate:tier-drift(${String(profile.tier)})`);
      }
      if (allows && claimed !== '' && evidenceDigest !== null && claimed === evidenceDigest) sandboxStatus = 'ALLOW';
      ok(`sandboxGate:${sandboxStatus.toLowerCase()}(${requestedProfileId})`);
    }
  }
  details.sandboxGate = {
    requestedProfileId: requestedProfileId ?? null,
    status: sandboxStatus,
    liveExecutionAllowed: sandboxStatus === 'ALLOW',
    note: sandbox.liveRunForbiddenWhenNotAllowed === true && sandboxStatus !== 'ALLOW'
      ? 'the internal sandbox gate does not allow the requested profile, so a live run stays forbidden'
      : null,
  };
  if (sandboxStatus !== 'ALLOW') issues.push('sandboxGate:live-run-forbidden');

  // ---- 6. S2-003/004/005: explicit references to versioned artifacts ------
  const references = record.upstreamVersionedArtifactReferences ?? {};
  const referencedPaths = [];
  for (const ticket of ['s2_003', 's2_004', 's2_005']) {
    const list = Array.isArray(references[ticket]) ? references[ticket] : [];
    if (list.length === 0) {
      issues.push(`upstreamVersionedArtifactReferences.${ticket}:empty`);
      continue;
    }
    for (const ref of list) {
      const relPath = ref?.path;
      if (typeof relPath !== 'string' || !GIT_BLOB.test(ref?.blob ?? '') || !SHA256.test(ref?.sha256 ?? '')) {
        issues.push(`reference(${ticket}):unbound-or-malformed`);
        continue;
      }
      referencedPaths.push(relPath);
      let actualBlob = '';
      try {
        actualBlob = git_(['rev-parse', `${commit}:${relPath}`]);
      } catch {
        issues.push(`reference(${ticket}):unresolvable(${relPath})`);
        continue;
      }
      if (actualBlob !== ref.blob) {
        issues.push(`reference(${ticket}):blob-drift(${relPath})`);
        continue;
      }
      let bytes = null;
      try {
        bytes = gitBytes_(commit, relPath);
      } catch {
        issues.push(`reference(${ticket}):unreadable(${relPath})`);
        continue;
      }
      if (sha256OfBytes(bytes) !== ref.sha256) issues.push(`reference(${ticket}):sha256-drift(${relPath})`);
      else ok(`reference(${ticket}):digest(${relPath})`);
      // The reference must resolve to a VERSIONED artifact.
      if (ref.kind === 'dependency-binding') {
        let parsed = null;
        try {
          parsed = JSON.parse(bytes.toString('utf8'));
        } catch {
          issues.push(`reference(${ticket}):malformed-binding(${relPath})`);
          continue;
        }
        const anchor = dottedPointer(parsed, ref.versionAnchor ?? '');
        if (!GIT_COMMIT.test(anchor ?? '')) {
          issues.push(`reference(${ticket}):version-anchor-not-a-commit(${relPath})`);
          continue;
        }
        try {
          git_(['cat-file', '-e', `${anchor}^{commit}`]);
          git_(['merge-base', '--is-ancestor', anchor, commit]);
          ok(`reference(${ticket}):version-anchor-is-ancestor(${relPath})`);
        } catch {
          issues.push(`reference(${ticket}):version-anchor-not-ancestor(${relPath})`);
        }
      } else if (ref.kind === 'schema') {
        let parsed = null;
        try {
          parsed = JSON.parse(bytes.toString('utf8'));
        } catch {
          issues.push(`reference(${ticket}):malformed-schema(${relPath})`);
          continue;
        }
        const id = typeof parsed.$id === 'string' ? parsed.$id : '';
        if (!id.endsWith(`/${path.basename(relPath)}`)) issues.push(`reference(${ticket}):schema-id-drift(${relPath})`);
        else ok(`reference(${ticket}):schema-id(${relPath})`);
      } else if (ref.kind === 'thresholds') {
        let parsed = null;
        try {
          parsed = JSON.parse(bytes.toString('utf8'));
        } catch {
          issues.push(`reference(${ticket}):malformed-thresholds(${relPath})`);
          continue;
        }
        if (!Number.isInteger(parsed.schemaVersion) || parsed.schemaVersion < 1) issues.push(`reference(${ticket}:thresholds-unversioned(${relPath})`);
        else ok(`reference(${ticket}):thresholds-versioned(${relPath})`);
      }
    }
  }
  // Their CONTENT may not become a scheduler instruction: the board must not
  // name these artifacts at all, so it cannot read them at runtime.
  const boardFiles = BOARD_SURFACE_TREES.flatMap((rel) => listFilesRecursive(path.join(ROOT, rel)));
  const referenceNeedles = referencedPaths.map((rel) => path.basename(rel).toLowerCase().replace(/\.[a-z]+$/, ''));
  for (const absFile of boardFiles) {
    let text = '';
    try {
      text = fs.readFileSync(absFile, 'utf8');
    } catch {
      continue;
    }
    const lower = text.toLowerCase();
    for (const needle of referenceNeedles) {
      if (needle.length > 0 && lower.includes(needle)) {
        issues.push(`scheduler-instruction-leak:${path.relative(ROOT, absFile)} names ${needle}`);
      }
    }
  }
  if (boardFiles.length > 0) ok('scheduler-instruction-leak:board-tree-scanned');

  // ---- 7. S2-006 / S2-006E: engineering properties only, never a DONE gate -
  const s2006e = record.s2_006e ?? {};
  if (s2006e.mandatoryForCore !== false) issues.push('s2_006e:mandatoryForCore-must-be-false');
  else ok('s2_006e:not-mandatory');
  const official = s2006e.officialStatusSource ?? {};
  if (typeof official.path === 'string' && SHA256.test(official.sha256 ?? '')) {
    let reportBytes = null;
    try {
      reportBytes = gitBytes_(commit, official.path);
    } catch {
      issues.push('s2_006e:official-status-unreadable-from-git');
    }
    if (reportBytes) {
      if (sha256OfBytes(reportBytes) !== official.sha256) issues.push('s2_006e:official-status-digest-drift');
      else ok('s2_006e:official-status-digest(git-bytes)');
      const text = reportBytes.toString('utf8');
      if (!new RegExp(`^${official.requiredVerdictHeading}$`, 'm').test(text)) issues.push('s2_006e:official-verdict-not-needs-input');
      if (new RegExp(`^${official.forbiddenVerdictHeading}\\s*$`, 'm').test(text)) issues.push('s2_006e:unconditional-pass-verdict-present');
      if (record.s2_006e?.officialStatus !== 'NEEDS_INPUT') issues.push('s2_006e:recorded-status-mismatch');
      else ok('s2_006e:official-status-NEEDS_INPUT');
    }
  } else {
    issues.push('s2_006e:official-status-unbound');
  }
  const closure = s2006e.engineeringClosure ?? {};
  if (typeof closure.path === 'string' && SHA256.test(closure.sha256 ?? '')) {
    let closureBytes = null;
    try {
      closureBytes = gitBytes_(commit, closure.path);
    } catch {
      issues.push('s2_006e:closure-unreadable-from-git');
    }
    if (closureBytes) {
      if (sha256OfBytes(closureBytes) !== closure.sha256) issues.push('s2_006e:closure-digest-drift');
      const text = closureBytes.toString('utf8');
      if (closure.doesNotRaiseVerdict === true && !text.includes('NEEDS_INPUT')) issues.push('s2_006e:closure-silently-raises-the-verdict');
      if (!text.includes(String(closure.status ?? ''))) issues.push('s2_006e:closure-status-drift');
      else ok('s2_006e:engineering-closure-does-not-raise-verdict');
    }
  } else {
    issues.push('s2_006e:closure-unbound');
  }

  // ---- 8. DONE may never be reachable from a verifier signal ---------------
  const assertion = record.doneReachabilityAssertion ?? {};
  const signalTokens = Array.isArray(assertion.verifierSignalTokens) ? assertion.verifierSignalTokens : [];
  const refusalMarkers = Array.isArray(assertion.refusalMarkers) ? assertion.refusalMarkers : [];
  const doneEdges = Object.entries(TRANSITIONS).filter(([, targets]) => Object.prototype.hasOwnProperty.call(targets, 'DONE'));
  if (doneEdges.length !== 1 || doneEdges[0][0] !== 'IN_REVIEW' || doneEdges[0][1].DONE !== 'guardInReviewToDone') {
    issues.push(`done-reachability:unexpected-incoming-edges(${doneEdges.map(([from]) => from).join('|') || 'none'})`);
  } else ok('done-reachability:single-incoming-edge(IN_REVIEW->DONE)');
  if (Object.keys(TRANSITIONS.DONE ?? {}).length !== 0) issues.push('done-reachability:DONE-has-outgoing-edges');
  else ok('done-reachability:DONE-terminal');

  const policyRelPath = `${BOARD_TREE}/policy.mjs`;
  let policySource = null;
  try {
    policySource = readWorkingTreeFile(policyRelPath).toString('utf8');
  } catch {
    issues.push('done-reachability:policy-module-unreadable');
  }
  if (policySource !== null) {
    const guard = findFunctionSource(policySource, 'guardInReviewToDone');
    if (guard === null) {
      issues.push('done-reachability:done-guard-not-found');
    } else {
      if (!guard.includes('assertHumanOnlyApproval')) issues.push('done-reachability:done-guard-does-not-require-human-approval');
      if (!guard.includes('assertNotSelfApproved')) issues.push('done-reachability:done-guard-does-not-refuse-self-approval');
      for (const token of signalTokens) {
        if (guard.toLowerCase().includes(token.toLowerCase())) issues.push(`done-reachability:done-guard-names-verifier-signal(${token})`);
      }
      if (!issues.some((code) => code.startsWith('done-reachability:done-guard'))) ok('done-reachability:done-guard-is-human-only');
    }
    const approvalSet = /APPROVAL_ACTOR_KINDS\s*=\s*new Set\(\[([^\]]*)\]\)/.exec(policySource);
    if (approvalSet === null) {
      issues.push('done-reachability:approval-actor-kinds-not-declared');
    } else {
      const kinds = [...approvalSet[1].matchAll(/'([^']+)'/g)].map((match) => match[1]);
      const forbidden = kinds.filter((kind) => !APPROVAL_ACTOR_KINDS_ALLOWED.includes(kind));
      if (forbidden.length > 0) issues.push(`done-reachability:non-human-approval-kind(${forbidden.join(',')})`);
      else ok('done-reachability:approval-actor-kinds-are-human-only');
    }
  }
  for (const absFile of boardFiles) {
    const relFile = path.relative(ROOT, absFile);
    let text = '';
    try {
      text = fs.readFileSync(absFile, 'utf8');
    } catch {
      continue;
    }
    for (const match of text.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)) {
      const specifier = match[1];
      if (!/verifier/.test(specifier)) continue;
      if (!PERMITTED_VERIFIER_IMPORTS.some((allowed) => specifier.endsWith(allowed))) {
        issues.push(`verifier-import-forbidden:${relFile} imports ${specifier}`);
      }
    }
    const lines = text.split('\n');
    for (const [index, line] of lines.entries()) {
      if (!line.includes('DONE')) continue;
      const lowerLine = line.toLowerCase();
      const named = signalTokens.filter((token) => lowerLine.includes(token.toLowerCase()));
      if (named.length === 0) continue;
      if (refusalMarkers.some((marker) => lowerLine.includes(marker.toLowerCase()))) continue;
      issues.push(`verifier-signal-reaches-DONE:${relFile}:${index + 1} (${named.join(',')})`);
    }
  }
  if (boardFiles.length > 0) ok('verifier-signal-reaches-DONE:board-tree-scanned');

  // ---- 9. the S2-007 frozen foundation, bound by SHA-256 -------------------
  const foundation = record.s2_007FrozenFoundation ?? {};
  const foundationCommit = foundation.commit;
  if (!GIT_COMMIT.test(foundationCommit ?? '')) {
    issues.push('s2_007FrozenFoundation.commit:unpinned');
  } else {
    // Issue #7 §2 names exactly eight wire shapes and one store migration.
    // A silent ninth schema, or a second migration, is a boundary change.
    const schemaPaths = Object.keys(isPlainObject(foundation.contractSchemas) ? foundation.contractSchemas : {});
    const migrationPaths = Object.keys(isPlainObject(foundation.migration) ? foundation.migration : {});
    if (schemaPaths.length !== 8) issues.push(`s2_007FrozenFoundation.contractSchemas:expected-8-got-${schemaPaths.length}`);
    else ok('s2_007FrozenFoundation.contractSchemas:exactly-8');
    if (migrationPaths.length !== 1) issues.push(`s2_007FrozenFoundation.migration:expected-1-got-${migrationPaths.length}`);
    else ok('s2_007FrozenFoundation.migration:exactly-1');
    for (const [groupName, paths] of Object.entries(foundation)) {
      if (!['contractSchemas', 'migration', 'frozenModules'].includes(groupName) || !isPlainObject(paths)) continue;
      if (Object.keys(paths).length === 0) issues.push(`s2_007FrozenFoundation.${groupName}:empty`);
      for (const [relPath, expected_] of Object.entries(paths)) {
        if (!isPlainObject(expected_) || !GIT_BLOB.test(expected_.blob ?? '') || !SHA256.test(expected_.sha256 ?? '')) {
          issues.push(`${relPath}:foundation-unbound`);
          continue;
        }
        let bytes = null;
        try {
          bytes = gitBytes_(foundationCommit, relPath);
        } catch {
          issues.push(`${relPath}:missing-at-foundation-commit`);
          continue;
        }
        if (blobIdOfBytes(bytes) !== expected_.blob) issues.push(`${relPath}:foundation-blob-drift`);
        if (sha256OfBytes(bytes) !== expected_.sha256) issues.push(`${relPath}:foundation-sha256-drift`);
        if (Number.isInteger(expected_.bytes) && bytes.length !== expected_.bytes) issues.push(`${relPath}:foundation-length-drift`);
        // The executable surface must stay byte-identical to the frozen commit.
        let working = null;
        try {
          working = readWorkingTreeFile(relPath);
        } catch {
          issues.push(`${relPath}:frozen-foundation-missing-in-working-tree`);
          continue;
        }
        if (sha256OfBytes(working) !== expected_.sha256) issues.push(`${relPath}:frozen-foundation-working-tree-drift`);
        else ok(`${relPath}:frozen-foundation(git-bytes+working-tree)`);
      }
    }
  }

  return {
    ok: issues.length === 0,
    checked: checked.length,
    issues,
    details,
    deferred,
    restored,
    boardFilesScanned: boardFiles.length,
  };
}

// A dependency re-run gate. The real implementation is used unless a test
// injects its own; the subprocess contract (real argv, real exit code, real
// signal, real stdout/stderr) is what makes the recorded status meaningful.
export function runSubprocessGate(entry) {
  const argv = ['run', '--silent', String(entry.npmScript ?? entry.id)];
  const timeout = RERUN_TIMEOUT_MS[entry.id] ?? 300_000;
  const result = spawnSync('npm', argv, {
    cwd: ROOT,
    encoding: 'utf8',
    timeout,
    maxBuffer: 1 << 28,
    windowsHide: true,
  });
  const stdout = result.stdout ?? '';
  const stderr = result.stderr ?? '';
  const timedOut = result.error?.code === 'ETIMEDOUT' || (result.signal === 'SIGTERM' && result.status === null);
  const observed = {
    command: entry.command,
    exitCode: typeof result.status === 'number' ? result.status : null,
    signal: result.signal ?? null,
    timedOut,
    stdout,
    stderr,
  };
  if (!timedOut && result.status !== 0) {
    // A bounded, structured diagnostic so the reason for a non-zero exit is
    // legible without dumping a whole run log into the gate output.
    let parsed = null;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      parsed = null;
    }
    const violations = parsed?.comparison?.counterViolations;
    if (Array.isArray(violations)) observed.diagnostics = violations.slice(0, 10);
    else if (Array.isArray(parsed?.issues)) observed.diagnostics = parsed.issues.slice(0, 10);
  }
  return observed;
}

// Deterministic `resolved` section, written ONLY on a green FULL_GIT_BYTES run.
function resolvedSection(record, result, rerun) {
  const sandbox = record.sandboxGate ?? {};
  return {
    gate: 'scripts/verify-s2-007-dependencies.mjs',
    mode: 'FULL_GIT_BYTES',
    ok: true,
    checkedCount: result.checked,
    issueCount: 0,
    resolvedRefs: {
      originMain: git(['rev-parse', 'refs/remotes/origin/main']),
      canonicalizationCommit: record.base?.canonicalizationCommit ?? null,
      canonicalizationTree: git(['rev-parse', `${record.base?.canonicalizationCommit}^{tree}`]),
      implementationBaseCommit: git(['rev-parse', 'HEAD']),
    },
    sandboxGate: {
      requestedProfileId: sandbox.requestedProfileId ?? null,
      status: result.details?.sandboxGate?.status ?? null,
      liveExecutionAllowed: result.details?.sandboxGate?.liveExecutionAllowed ?? null,
    },
    reRunGates: Object.fromEntries(
      Object.entries(rerun).map(([id, value]) => [id, { exitCode: value.exitCode, status: value.status }]),
    ),
    deferred: result.deferred.length === 0 ? null : result.deferred,
    restoredCanonicalEvidence: result.restored.length === 0 ? null : result.restored,
    writtenOnGreenRunOnly: true,
  };
}

async function main() {
  const bindingPath = path.join(ROOT, RECORD_PATH);
  let record;
  try {
    record = JSON.parse(fs.readFileSync(bindingPath, 'utf8'));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, status: 'BLOCKED_DEPENDENCY', issues: [`binding-record:unreadable (${error.message})`] }, null, 2));
    process.exit(1);
  }
  let result;
  try {
    result = verifyDependencyBinding(record, { runRerunGate: runSubprocessGate });
  } catch (error) {
    // An untyped throw out of the gate is a gate failure, never a green result.
    console.log(JSON.stringify({
      ok: false,
      status: 'BLOCKED_DEPENDENCY',
      mode: 'FULL_GIT_BYTES',
      issues: [`gate:untyped-failure (${error.message})`],
    }, null, 2));
    process.exit(1);
  }
  let written = null;
  if (result.ok) {
    // Canonical record update: deterministic bytes, so repeated green runs are
    // byte-stable and never dirty a frozen evidence file.
    const updated = { ...record, resolved: resolvedSection(record, result, result.details?.reRunGates ?? {}) };
    const serialized = `${JSON.stringify(updated, null, 2)}\n`;
    if (fs.readFileSync(bindingPath, 'utf8') !== serialized) {
      fs.writeFileSync(bindingPath, serialized);
      written = RECORD_PATH;
    }
  }
  const output = {
    ok: result.ok,
    status: result.ok ? 'PASS' : 'BLOCKED_DEPENDENCY',
    mode: 'FULL_GIT_BYTES',
    checked: result.checked,
    issues: result.issues,
    details: result.details,
    deferred: result.deferred,
    restoredCanonicalEvidence: result.restored,
    boardFilesScanned: result.boardFilesScanned,
    ...(written ? { written } : {}),
  };
  console.log(JSON.stringify(output, null, 2));
  process.exit(result.ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) await main();
