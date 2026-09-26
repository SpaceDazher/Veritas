// S2-002 process-cancellation verification, evidence revision 2 (issue #41).
//
// This stage is additive: it publishes NEW versioned evidence and never
// rewrites evidence/s2-002-run-a.json, s2-002-run-b.json,
// s2-002-comparison.json, s2-002-security-probes.json or any other historical
// record. It proves, on the host platform, that cancellation of a spawned
// process tree either (a) proves the whole tree terminated by re-observing the
// OS process table, or (b) returns a fail-closed blocked/unknown outcome. A
// zero-survivor success without a termination proof is a violation.
//
// Usage: node scripts/verify-s2-002-cancellation-v2.mjs [--write]
// Writes evidence/s2-002-cancellation-v2.json and
// evidence/s2-002-cancellation-v2-integrity.json; exits non-zero on any
// violation.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { createSandbox } from '../src/lib/identity/sandbox.mjs';
import { SANDBOX_LOCAL_RESTRICTED_BLOCKED } from '../src/lib/identity/sandbox-profiles.mjs';
import { DEFAULT_PROCESS_OBSERVER } from '../src/lib/identity/process-observer.mjs';
import { runCorpus } from './s2-002-run.mjs';
import { compareRuns } from './verify-s2-002.mjs';

const NOW = '2026-09-12T12:00:00.000Z';
const IS_WINDOWS = process.platform === 'win32';
const EVIDENCE_REVISION = 2;
const PROOF_VALUES = ['TERMINATED', 'SURVIVORS_REMAINING', 'UNVERIFIED'];

// Records produced before the #41 fix. This stage must never rewrite them: the
// new evidence is additive, so a post-fix claim can never overwrite the
// historical Windows replay that the defect was found against.
const HISTORICAL_EVIDENCE = Object.freeze([
  'evidence/s2-002-run-a.json',
  'evidence/s2-002-run-b.json',
  'evidence/s2-002-comparison.json',
  'evidence/s2-002-comparison-integrity.json',
  'evidence/s2-002-security-probes.json',
  'evidence/s2-002-podman-sandbox.json',
  'evidence/s2-002-gvisor-sandbox.json',
  'evidence/s2-002-dependency-binding.json',
]);

// The S2-002 hard gates are preserved unchanged. This record references them;
// it does not redefine or relax them.
const PRESERVED_HARD_GATES = Object.freeze({
  cross_tenant_success: 0,
  authority_expansion: 0,
  fs_network_secret_escapes: 0,
  survivors_after_cancellation: 0,
  allow_after_revocation_commit: 0,
  missing_or_censored_trials: 0,
});

const UNOBSERVABLE_REASON = 'SBX_NEGATIVE_CONTROL_NO_PROCESS_TABLE';

function unobservableObserver(id = 'negative-control:process-table-unavailable') {
  return Object.freeze({
    id,
    listDescendants: async () => ({ pids: [], observable: false, reason: UNOBSERVABLE_REASON }),
    listExisting: async (pids) => ({ alive: pids, observable: false, reason: UNOBSERVABLE_REASON }),
    identityFor: (pid) => String(pid),
  });
}

function tempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 's2-002-cancel-v2-'));
}

function sandboxFor(root, extra = {}) {
  return createSandbox({
    profile: { ...SANDBOX_LOCAL_RESTRICTED_BLOCKED, process: { ...SANDBOX_LOCAL_RESTRICTED_BLOCKED.process, max_processes: 8 } },
    workspaceRoots: [root],
    artifactRoot: path.join(root, 'artifacts'),
    secrets: {},
    now: NOW,
    ...extra,
  });
}

// A tree that leaves the child's process group, which is the shape a
// group-only or parent-only kill cannot reach: `start /b` on Windows,
// setsid(2) on POSIX. `pidFile` is written by the deepest process, so the
// harness observes a pid it did not create.
function escapingTree(root, { depth = 1, heartbeat = null } = {}) {
  const pidFile = path.join(root, 'tree.pid').split('\\').join('/');
  if (IS_WINDOWS) {
    return {
      command: 'cmd.exe',
      args: ['/d', '/s', '/c', 'start /b cmd /c ping -n 60 127.0.0.1 >nul & ping -n 60 127.0.0.1 >nul'],
      pidFile: null,
    };
  }
  let inner = `echo $$ > ${pidFile}; for i in 1 2 3 4 5 6 7 8 9 10 11 12; do sleep 5; done`;
  for (let level = 1; level < depth; level += 1) {
    inner = `/bin/sh -c ${JSON.stringify(inner)}`;
  }
  const beat = heartbeat ? `while true; do echo x >> ${heartbeat.split('\\').join('/')}; sleep 1; done & ` : '';
  return {
    command: '/bin/sh',
    args: ['-c', `${beat}setsid /bin/sh -c ${JSON.stringify(inner)} & sleep 60`],
    pidFile,
  };
}

async function readPids(file) {
  if (!file) return [];
  try {
    return fs.readFileSync(file, 'utf8')
      .split(/\s+/)
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value > 0);
  } catch {
    return [];
  }
}

async function waitForPids(file, attempts = 40) {
  let pids = [];
  for (let attempt = 0; attempt < attempts && pids.length === 0; attempt += 1) {
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 100));
    pids = await readPids(file);
  }
  return pids;
}

function proofOf(result) {
  return {
    proof: result.proof ?? null,
    terminated: result.terminated ?? null,
    survivors: result.survivors ?? null,
    remainingProcessIds: result.remainingProcessIds ?? [],
    trackedProcessIds: result.trackedProcessIds ?? [],
    reasonCodes: result.reasonCodes ?? [],
    observationSource: result.observationSource ?? null,
  };
}

function ok(caseId, checks, detail) {
  const passed = checks.every((check) => check === true);
  return { caseId, verdict: passed ? 'PASS' : 'FAIL', checks, detail };
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

// Compares each historical record against its committed digest. Any difference
// means a gate rewrote the pre-fix evidence, which violates the issue's
// "publish new evidence without rewriting historical evidence" rule.
//
// Two independent committed sources are accepted, because the gate also runs
// from a `git archive` export that has no .git directory:
//   - `git show HEAD:<path>`, the blob of record;
//   - the SHA-256 recorded in evidence/root-manifest.json, which is itself
//     bound to the implementation commit by the closure record.
function committedDigest(relative) {
  if (fs.existsSync(path.join('.git'))) {
    try {
      return { source: 'git:HEAD', sha256: sha256(execFileSync('git', ['show', `HEAD:${relative}`], { encoding: null, maxBuffer: 30 * 1024 * 1024 })) };
    } catch {
      // fall through to the manifest
    }
  }
  const rootManifestPath = 'evidence/root-manifest.json';
  if (!fs.existsSync(rootManifestPath)) return null;
  const manifest = JSON.parse(fs.readFileSync(rootManifestPath, 'utf8'));
  const entry = (manifest.files ?? []).find((file) => file.path === relative);
  return entry ? { source: 'root-manifest', sha256: entry.sha256 } : null;
}

function checkHistoricalEvidenceUntouched() {
  const records = [];
  for (const relative of HISTORICAL_EVIDENCE) {
    if (!fs.existsSync(relative)) {
      records.push({ path: relative, present: false, unchanged: false, sha256: null });
      continue;
    }
    const workingTree = sha256(fs.readFileSync(relative));
    const committed = committedDigest(relative);
    if (!committed) {
      records.push({ path: relative, present: true, unchanged: false, sha256: workingTree, reason: 'NO_COMMITTED_DIGEST' });
      continue;
    }
    records.push({ path: relative, present: true, unchanged: workingTree === committed.sha256, sha256: workingTree, source: committed.source });
  }
  const rewritten = records.filter((record) => record.unchanged !== true).map((record) => record.path);
  return ok('cancellation/historical-evidence-untouched', [rewritten.length === 0],
    `checked=${records.length}; source=${records[0]?.source ?? 'none'}; rewritten=${JSON.stringify(rewritten)}`);
}

// Case 1: the reported defect. A descendant in its own session, killed only if
// the tree is really discovered, reaped, and re-observed.
async function caseCancellationProvesTree() {
  const root = tempRoot();
  const sandbox = sandboxFor(root);
  const tree = escapingTree(root, { depth: 3, heartbeat: path.join(root, 'beat') });
  const { pid, done } = sandbox.startForControlProbe({ ...tree, timeoutMs: 60000 });
  const descendants = await waitForPids(tree.pidFile);
  const cancel = await sandbox.cancel(pid);
  const outcome = await done;
  // Independent ground truth: the pids the deepest process published.
  const alive = descendants.filter((value) => sandbox.isAlive(value));
  const beats = fs.existsSync(path.join(root, 'beat'))
    ? fs.readFileSync(path.join(root, 'beat'), 'utf8').trim().split('\n').filter(Boolean).length
    : 0;
  fs.rmSync(root, { recursive: true, force: true });
  return ok('cancellation/descendant-session-escape', [
    descendants.length > 0,
    cancel.proof === 'TERMINATED',
    cancel.terminated === true,
    cancel.survivors === 0,
    outcome.proof === 'TERMINATED',
    outcome.status === 'cancelled',
    outcome.survivors === 0,
    !sandbox.isAlive(pid),
    alive.length === 0,
    outcome.trackedProcessIds.length > descendants.length,
  ], `descendantsObserved=${descendants.length}; descendantHeartbeats=${beats}; ${JSON.stringify(proofOf(cancel))}; outcome.status=${outcome.status}`);
}

// Case 2: the same guarantee through the timeout path, without an explicit
// cancel() call.
async function caseTimeoutProvesTree() {
  const root = tempRoot();
  const sandbox = sandboxFor(root);
  const tree = escapingTree(root, { depth: 2 });
  const outcome = await sandbox.spawnForControlProbe({ ...tree, timeoutMs: 1500 });
  const descendants = await readPids(tree.pidFile);
  const alive = descendants.filter((value) => sandbox.isAlive(value));
  fs.rmSync(root, { recursive: true, force: true });
  return ok('cancellation/timeout-descendant-escape', [
    outcome.status === 'timeout',
    outcome.proof === 'TERMINATED',
    outcome.terminated === true,
    outcome.survivors === 0,
    outcome.status !== 'success',
    alive.length === 0,
  ], `status=${outcome.status}; ${JSON.stringify(proofOf(outcome))}; descendantAlive=${alive.length}`);
}

// Case 3 (negative control): the OS process table cannot be observed at all.
// The required outcome is fail-closed blocked/unknown. Reporting zero
// survivors here is exactly the #41 defect and must fail the gate.
async function caseNegativeControlNoProcessTable() {
  const root = tempRoot();
  const sandbox = sandboxFor(root, { processObserver: unobservableObserver() });
  const { pid, done } = sandbox.startForControlProbe({
    command: process.execPath,
    args: ['-e', 'setTimeout(() => {}, 30000)'],
    timeoutMs: 30000,
  });
  await new Promise((resolveTimer) => setTimeout(resolveTimer, 250));
  const cancel = await sandbox.cancel(pid);
  const outcome = await done;
  const checks = [
    cancel.proof === 'UNVERIFIED',
    cancel.terminated === false,
    cancel.survivors === null,
    cancel.reasonCodes.includes('SBX_PROCESS_OBSERVATION_UNAVAILABLE'),
    outcome.proof === 'UNVERIFIED',
    outcome.terminated === false,
    outcome.survivors === null,
    outcome.reasonCodes.includes('SBX_PROCESS_OBSERVATION_UNAVAILABLE'),
    sandbox.observationSource === 'negative-control:process-table-unavailable',
    sandbox.platformObserver === false,
  ];
  fs.rmSync(root, { recursive: true, force: true });
  return ok('cancellation/negative-control-no-process-table', checks,
    `cancel=${JSON.stringify(proofOf(cancel))}; outcome.survivors=${String(outcome.survivors)}`);
}

// Case 4 (negative control): descendant discovery fails while liveness still
// works. A tree of unknown shape can never be reported as fully terminated.
async function caseNegativeControlDescendantQueryFails() {
  const root = tempRoot();
  const platform = DEFAULT_PROCESS_OBSERVER;
  const halfBlind = Object.freeze({
    id: 'negative-control:descendant-query-unavailable',
    listDescendants: async () => ({ pids: [], observable: false, reason: UNOBSERVABLE_REASON }),
    listExisting: (pids, identities) => platform.listExisting(pids, identities),
    identityFor: (pid) => platform.identityFor(pid),
  });
  const sandbox = sandboxFor(root, { processObserver: halfBlind });
  const tree = escapingTree(root, { depth: 1 });
  const { pid, done } = sandbox.startForControlProbe({ ...tree, timeoutMs: 60000 });
  const descendants = await waitForPids(tree.pidFile);
  const cancel = await sandbox.cancel(pid);
  const outcome = await done;
  const checks = [
    descendants.length > 0,
    cancel.proof === 'UNVERIFIED',
    cancel.terminated === false,
    cancel.survivors === null,
    outcome.proof === 'UNVERIFIED',
    outcome.survivors === null,
  ];
  fs.rmSync(root, { recursive: true, force: true });
  return ok('cancellation/negative-control-descendant-query-fails', checks,
    `descendantsObserved=${descendants.length}; cancel=${JSON.stringify(proofOf(cancel))}`);
}

// Case 5: a recycled pid must never be signalled or counted as a survivor.
// Uses the real platform observer with a deliberately wrong starttime identity
// for a live pid, so the guard is exercised without killing an unrelated
// process.
async function caseRecycledPidIsNeverSignalled() {
  const result = await DEFAULT_PROCESS_OBSERVER.listExisting(
    [process.pid],
    { [process.pid]: `${process.pid}:1` },
  );
  const checks = [
    result.observable === true,
    Array.isArray(result.alive),
    Array.isArray(result.pidReused),
    !result.alive.includes(process.pid),
    result.pidReused.includes(process.pid),
    process.getuid !== undefined || process.platform === 'win32',
  ];
  return ok('cancellation/recycled-pid-not-signalled', checks,
    `observer=${DEFAULT_PROCESS_OBSERVER.id}; alive=${JSON.stringify(result.alive)}; pidReused=${JSON.stringify(result.pidReused)}`);
}

// The whole S2-002 hard-counter set, re-observed on this host after the fix.
// `npm run verify:s2-002` remains the process-separated authority; this
// records the same frozen corpus replayed in-process, so the post-fix result is
// published as new versioned evidence instead of overwriting the pre-fix run
// records.
async function caseFrozenCorpusHardCounters() {
  const runA = await runCorpus({
    runId: 'cancellation-v2-a',
    executorId: 'exec-cancel-v2-alpha',
    nonceBase: 'nb-cancel-v2-alpha',
    outputRoot: fs.mkdtempSync(path.join(os.tmpdir(), 's2-002-v2-a-')),
  });
  const runB = await runCorpus({
    runId: 'cancellation-v2-b',
    executorId: 'exec-cancel-v2-beta',
    nonceBase: 'nb-cancel-v2-beta',
    outputRoot: fs.mkdtempSync(path.join(os.tmpdir(), 's2-002-v2-b-')),
  });
  const comparison = compareRuns(runA.summary, runB.summary, runA.observations, runB.observations);
  for (const root of [runA.summary.outputRoot, runB.summary.outputRoot]) {
    fs.rmSync(root, { recursive: true, force: true });
  }
  const counters = runA.summary.counters;
  const checks = [
    comparison.ok === true,
    comparison.mismatchedDecisions === 0,
    comparison.counterViolations.length === 0,
    comparison.expectedOracleViolations.length === 0,
    runA.summary.corpusDigest === runB.summary.corpusDigest,
    ...Object.entries(PRESERVED_HARD_GATES).map(([counter, limit]) => {
      const value = counters[counter];
      return Number.isInteger(value) && value >= 0 && value <= limit;
    }),
    runB.summary.counters.survivors_after_cancellation === 0,
  ];
  return ok('cancellation/s2-002-frozen-corpus-hard-counters', checks,
    `inProcessReplay; comparedTrials=${comparison.comparedTrials}; corpusRevision=${runA.summary.corpusRevision}; ` +
    `corpusDigest=${runA.summary.corpusDigest.slice(0, 16)}; counters=${JSON.stringify(counters)}; ` +
    `counterViolations=${JSON.stringify(comparison.counterViolations)}`);
}

export async function runCancellationVerification() {
  const cases = [
    await caseCancellationProvesTree(),
    await caseTimeoutProvesTree(),
    await caseNegativeControlNoProcessTable(),
    await caseNegativeControlDescendantQueryFails(),
    await caseRecycledPidIsNeverSignalled(),
    await caseFrozenCorpusHardCounters(),
    checkHistoricalEvidenceUntouched(),
  ];
  const counters = {
    survivors_after_cancellation: cases
      .filter((c) => c.caseId === 'cancellation/descendant-session-escape' || c.caseId === 'cancellation/timeout-descendant-escape')
      .reduce((sum, c) => sum + (c.checks[3] === true ? 0 : 1), 0),
    false_zero_survivor_success: cases
      .filter((c) => c.caseId.startsWith('cancellation/negative-control'))
      .filter((c) => c.checks.some((check) => check === false))
      .length,
  };
  const okAll = cases.every((c) => c.verdict === 'PASS')
    && counters.survivors_after_cancellation === PRESERVED_HARD_GATES.survivors_after_cancellation
    && counters.false_zero_survivor_success === 0;
  return {
    evidence: {
      schemaVersion: 1,
      evidenceRevision: EVIDENCE_REVISION,
      supersedes: null,
      issue: 'SpaceDazher/Veritas#41',
      scope: 'Cross-platform process-tree cancellation proof: termination is either proven by re-observing the OS process table, or reported as a fail-closed blocked/unknown outcome.',
      generatedAt: NOW,
      policyVersion: 's2-002-policy-v5',
      corpusRevision: 2,
      platform: `${process.platform}/${process.arch} node ${process.version}`,
      observationSource: DEFAULT_PROCESS_OBSERVER.id,
      preservedHardGates: PRESERVED_HARD_GATES,
      historicalEvidence: HISTORICAL_EVIDENCE,
      counters,
      cases,
      verdict: okAll ? 'PASS' : 'FAIL',
      limitations: [
        'Proves the spawned-tree termination control of the in-process probe adapter on this host only; it is not a kernel containment boundary.',
        'Descendant discovery on POSIX reads /proc; on a host without /proc it falls back to ps, and if neither answers the outcome is UNVERIFIED rather than zero survivors.',
        'A Windows-only replay still does not establish the non-Windows property; both platforms must be observed independently.',
        'The adversarial A-K report evidence/s2-002-security-probes.json is the pre-fix record and is left untouched; npm run test:security-probes regenerates it in the working tree by design, so re-running it is an explicit separate act.',
      ],
    },
    ok: okAll,
  };
}

async function main() {
  const { evidence, ok: passed } = await runCancellationVerification();
  if (process.argv.includes('--write')) {
    const evidencePath = 'evidence/s2-002-cancellation-v2.json';
    const integrityPath = 'evidence/s2-002-cancellation-v2-integrity.json';
    fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
    const digest = createHash('sha256').update(fs.readFileSync(evidencePath)).digest('hex');
    fs.writeFileSync(integrityPath, `${JSON.stringify({
      schemaVersion: 1,
      evidenceRevision: EVIDENCE_REVISION,
      algorithm: 'SHA-256 raw file bytes',
      files: { [evidencePath]: digest },
      historicalEvidenceRewritten: false,
    }, null, 2)}\n`);
  }
  console.log(JSON.stringify({
    exitCode: passed ? 0 : 1,
    verdict: evidence.verdict,
    platform: evidence.platform,
    counters: evidence.counters,
    cases: evidence.cases.map((c) => ({ caseId: c.caseId, verdict: c.verdict })),
  }, null, 2));
  process.exit(passed ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
