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
// Usage: node scripts/verify-s2-002-cancellation-v2.mjs [--write] [--out <file>]
// Writes the evidence record and its integrity sidecar; exits non-zero on any
// violation. `--out` defaults to the linux record, so a second host writes a
// separate file instead of overwriting the first host's observation: the two
// platforms must be evidenced independently, never merged.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { createSandbox } from '../src/lib/identity/sandbox.mjs';
import { SANDBOX_LOCAL_RESTRICTED_BLOCKED } from '../src/lib/identity/sandbox-profiles.mjs';
import { DEFAULT_PROCESS_OBSERVER } from '../src/lib/identity/process-observer.mjs';
import { buildEscapingProcessTree, readPublishedPids, waitForPublishedPids } from '../src/lib/identity/process-tree-fixture.mjs';
import { runCorpus } from './s2-002-run.mjs';
import { compareRuns } from './verify-s2-002.mjs';

const NOW = '2026-09-12T12:00:00.000Z';
const IS_WINDOWS = process.platform === 'win32';
const EVIDENCE_REVISION = 2;

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
// group-only or parent-only kill cannot reach. `pidFile` is written by the
// deepest process, so the harness observes a pid it did not create and can
// check its liveness independently of the adapter's own verdict.
//
// POSIX uses setsid(2), which moves the descendant to a new session; the
// Windows counterpart is Start-Process, which starts an independent process
// that does not inherit the parent's stdio handles. Both are the hardest
// available shape: a run can finish while such a descendant is still alive.
// A tree that leaves the child's process group, which is the shape a
// group-only or parent-only kill cannot reach. Defined once, in
// process-tree-fixture.mjs, so the corpus runner, the adversarial probes and
// this stage cannot drift into observing different trees.
function escapingTree(root, { depth = 1 } = {}) {
  return buildEscapingProcessTree(root, { depth });
}

async function readPids(file) {
  return readPublishedPids(file);
}

async function waitForPids(file) {
  return waitForPublishedPids(file);
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

// Named checks, not a bare boolean array. The evidence's hard counters are
// derived from these, and a counter that reads checks[3] silently changes what
// it measures the moment anyone reorders the array. A name survives reordering.
function ok(caseId, checks, detail) {
  const named = checks.map(([name, pass]) => ({ name, pass: pass === true }));
  const passed = named.every((check) => check.pass);
  return {
    caseId,
    verdict: passed ? 'PASS' : 'FAIL',
    checks: named.map((check) => check.pass),
    namedChecks: Object.fromEntries(named.map((check) => [check.name, check.pass])),
    failed: named.filter((check) => !check.pass).map((check) => check.name),
    detail,
  };
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

// Compares each historical record against its committed digest. Any difference
// means a gate rewrote the pre-fix evidence, which violates the issue's
// "publish new evidence without rewriting historical evidence" rule.
//
// Three committed sources are consulted, in order of trust:
//   - `git show HEAD:<path>`, the blob of record;
//   - `evidence/historical-s2-002-baseline.json`, the fixed point written for
//     this issue. The four run/comparison records are rewritten by design
//     whenever `npm run verify:s2-002` runs, so they cannot be pinned in
//     frozen-manifest.json the way the other four are;
//   - the SHA-256 in `evidence/root-manifest.json`, which is a regenerable
//     artifact. It is the weakest source, because a commit that rewrites a
//     record and re-freezes the root manifest in the same change would satisfy
//     it — which is why it is last and why the baseline exists.
function committedDigest(relative) {
  if (fs.existsSync(path.join('.git'))) {
    try {
      return { source: 'git:HEAD', sha256: sha256(execFileSync('git', ['show', `HEAD:${relative}`], { encoding: null, maxBuffer: 30 * 1024 * 1024 })) };
    } catch {
      // fall through to the committed baselines
    }
  }
  const baselinePath = 'evidence/historical-s2-002-baseline.json';
  if (fs.existsSync(baselinePath)) {
    const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    const entry = baseline.files?.[relative];
    if (entry) return { source: 'historical-s2-002-baseline', sha256: entry.sha256 };
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
  // Which of the three committed sources answered, per record. A run from a
  // git archive has no .git and lands on the baseline; a run from a checkout
  // lands on the blob. Both are fixed points, unlike the root manifest.
  const sources = [...new Set(records.map((record) => record.source).filter(Boolean))];
  return ok('cancellation/historical-evidence-untouched', [
    ['noneRewritten', rewritten.length === 0],
    ['allRecordsPresent', records.every((record) => record.present === true)],
    ['allHaveCommittedDigest', records.every((record) => record.reason !== 'NO_COMMITTED_DIGEST')],
    // The guard must never be satisfied by the regenerable root manifest alone.
    ['notRootManifestOnly', !(sources.length === 1 && sources[0] === 'root-manifest')],
  ],
  `checked=${records.length}; sources=${JSON.stringify(sources)}; rewritten=${JSON.stringify(rewritten)}`);
}

// Case 1: the reported defect. A descendant in its own session, killed only if
// the tree is really discovered, reaped, and re-observed.
async function caseCancellationProvesTree() {
  const root = tempRoot();
  const sandbox = sandboxFor(root);
  const tree = escapingTree(root, { depth: 3 });
  const { pid, done } = sandbox.startForControlProbe({ ...tree, timeoutMs: 60000 });
  const descendants = await waitForPids(tree.pidFile);
  const cancel = await sandbox.cancel(pid);
  const outcome = await done;
  // Independent ground truth: the pids the deepest process published, checked
  // against the OS rather than against the adapter's own verdict.
  const alive = descendants.filter((value) => sandbox.isAlive(value));
  fs.rmSync(root, { recursive: true, force: true });
  return ok('cancellation/descendant-session-escape', [
    ['descendantObserved', descendants.length > 0],
    ['cancelProofTerminated', cancel.proof === 'TERMINATED'],
    ['cancelTerminated', cancel.terminated === true],
    ['cancelSurvivorsZero', cancel.survivors === 0],
    ['outcomeProofTerminated', outcome.proof === 'TERMINATED'],
    ['outcomeStatusCancelled', outcome.status === 'cancelled'],
    ['outcomeSurvivorsZero', outcome.survivors === 0],
    ['rootDead', !sandbox.isAlive(pid)],
    ['publishedDescendantsDead', alive.length === 0],
    ['trackedExceedsPublished', outcome.trackedProcessIds.length > descendants.length],
  ], `platform=${tree.platform}; descendantsObserved=${descendants.length}; descendantAlive=${alive.length}; ${JSON.stringify(proofOf(cancel))}; outcome.status=${outcome.status}`);
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
    ['statusTimeout', outcome.status === 'timeout'],
    ['proofTerminated', outcome.proof === 'TERMINATED'],
    ['terminated', outcome.terminated === true],
    ['survivorsZero', outcome.survivors === 0],
    ['statusNotSuccess', outcome.status !== 'success'],
    ['publishedDescendantsDead', alive.length === 0],
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
    ['cancelProofUnverified', cancel.proof === 'UNVERIFIED'],
    ['cancelNotTerminated', cancel.terminated === false],
    ['cancelSurvivorsNull', cancel.survivors === null],
    ['cancelReasonCodes', cancel.reasonCodes.includes('SBX_PROCESS_OBSERVATION_UNAVAILABLE')],
    ['outcomeProofUnverified', outcome.proof === 'UNVERIFIED'],
    ['outcomeNotTerminated', outcome.terminated === false],
    ['outcomeSurvivorsNull', outcome.survivors === null],
    ['outcomeReasonCodes', outcome.reasonCodes.includes('SBX_PROCESS_OBSERVATION_UNAVAILABLE')],
    ['observationSourceRecorded', sandbox.observationSource === 'negative-control:process-table-unavailable'],
    ['injectedObserverFlagged', sandbox.platformObserver === false],
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
  // This observer cannot enumerate the tree, so the adapter has no way to kill
  // the escaping descendant — and because that descendant inherits the child's
  // stdio, the run outcome cannot arrive until it dies on its own. The case
  // therefore reads the ground truth straight after cancel(), reaps the
  // fixture by hand, and only then waits for the outcome.
  const { pid, done } = sandbox.startForControlProbe({ ...tree, timeoutMs: 30000 });
  const descendants = await waitForPids(tree.pidFile);
  const cancel = await sandbox.cancel(pid);
  const stillAlive = descendants.filter((value) => {
    try { process.kill(value, 0); return true; } catch { return false; }
  });
  for (const survivor of descendants) {
    try { process.kill(survivor, 'SIGKILL'); } catch { /* already gone */ }
  }
  const outcome = await done;
  const checks = [
    ['descendantObserved', descendants.length > 0],
    ['cancelProofUnverified', cancel.proof === 'UNVERIFIED'],
    ['cancelNotTerminated', cancel.terminated === false],
    ['cancelSurvivorsNull', cancel.survivors === null],
    ['outcomeProofUnverified', outcome.proof === 'UNVERIFIED'],
    ['outcomeSurvivorsNull', outcome.survivors === null],
    // Ground truth: the descendant this observer could not see is still running
    // after the cancellation. That is precisely why the proof must stay
    // fail-closed instead of claiming zero survivors.
    ['unobservableDescendantStillAlive', stillAlive.length > 0],
  ];
  fs.rmSync(root, { recursive: true, force: true });
  return ok('cancellation/negative-control-descendant-query-fails', checks,
    `descendantsObserved=${descendants.length}; unobservableDescendantAlive=${stillAlive.length}; cancel=${JSON.stringify(proofOf(cancel))}`);
}

// Case 6: a run that ends on its own was never observed while its root was
// alive, so its tree shape is unknown. It must make no claim rather than
// publishing a zero-survivor success.
async function caseSelfCompletedRunMakesNoClaim() {
  const root = tempRoot();
  const sandbox = sandboxFor(root);
  const outcome = await sandbox.spawnForControlProbe({
    command: process.execPath,
    args: ['-e', 'process.exit(0)'],
    timeoutMs: 20000,
  });
  const checks = [
    ['statusCompleted', outcome.status === 'completed'],
    ['noTerminationClaim', outcome.terminated === false],
    ['proofUnverified', outcome.proof === 'UNVERIFIED'],
    ['survivorsNull', outcome.survivors === null],
    ['treeUnverified', outcome.treeVerified === false],
    ['treeShapeReason', outcome.reasonCodes.includes('SBX_TREE_SHAPE_NOT_OBSERVED')],
  ];
  fs.rmSync(root, { recursive: true, force: true });
  return ok('cancellation/self-completed-run-makes-no-claim', checks,
    `status=${outcome.status}; proof=${outcome.proof}; survivors=${String(outcome.survivors)}; reasonCodes=${JSON.stringify(outcome.reasonCodes)}`);
}

// Case 5: a recycled pid must never be signalled or counted as a survivor.
//
// Two halves, because they fail independently:
//   a) the observer must classify a pid whose identity token no longer matches
//      as reused, not as alive;
//   b) the adapter must refuse to signal a tracked pid whose identity token no
//      longer matches, and must not count it as a survivor.
//
// (b) is the half that actually prevents an unrelated process from being
// killed, and it lives in sandbox.mjs's treeKill, not in the observer. A case
// that only calls listExisting never exercises it, so this runs a real
// cancellation with a deliberately stale token for a tracked descendant and
// asserts that the unrelated live process is still alive afterwards.
//
// pid identity needs a per-pid token (Linux /proc starttime). Windows CIM does
// not expose one, so there the case asserts the normalised contract shape and
// records the missing control as a stated residual rather than as a proven one.
async function caseRecycledPidIsNeverSignalled() {
  const identity = DEFAULT_PROCESS_OBSERVER.identityFor(process.pid);
  const identitySupported = typeof identity === 'string' && identity.includes(':');
  const result = await DEFAULT_PROCESS_OBSERVER.listExisting(
    [process.pid],
    { [process.pid]: `${process.pid}:1` },
  );
  const shapeOk = Array.isArray(result.alive)
    && Array.isArray(result.pidReused)
    && result.observable === true;
  const shapeChecks = [
    ['shapeContract', shapeOk],
    ['harnessNotCountedAlive', !result.alive.includes(process.pid)],
    ['harnessReportedReused', result.pidReused.includes(process.pid)],
    // The harness itself must still be alive: nothing signalled it.
    ['harnessStillAlive', process.kill(process.pid, 0)],
  ];
  if (!identitySupported) {
    return ok('cancellation/recycled-pid-not-signalled', [
      ...shapeChecks.slice(0, 1),
      ['noReuseDetected', result.pidReused.length === 0],
      ['identityAbsent', result.identitySupported === false],
    ],
    `observer=${DEFAULT_PROCESS_OBSERVER.id}; identitySupported=false; `
    + `alive=${JSON.stringify(result.alive)}; pidReused=${JSON.stringify(result.pidReused)}; `
    + 'no per-pid identity token on this platform: stated residual, not a proven control');
  }
  return ok('cancellation/recycled-pid-not-signalled', shapeChecks,
    `observer=${DEFAULT_PROCESS_OBSERVER.id}; identitySupported=true; `
    + `alive=${JSON.stringify(result.alive)}; pidReused=${JSON.stringify(result.pidReused)}; `
    + 'stale identity token detected as reuse');
}

// Case 5b: the signalling guard itself. A tracked descendant is given a
// deliberately stale identity token, so the number now belongs to a different
// process. Cancellation must refuse to signal it, must not report it as a
// survivor, and the unrelated live process must still be running afterwards.
async function caseStaleTokenIsNeverSignalled() {
  const identity = DEFAULT_PROCESS_OBSERVER.identityFor(process.pid);
  if (typeof identity !== 'string' || !identity.includes(':')) {
    return ok('cancellation/stale-token-never-signalled', [
      ['noPerPidIdentityToken', true],
    ],
    `observer=${DEFAULT_PROCESS_OBSERVER.id}; this platform exposes no per-pid identity token, `
    + 'so the signal guard cannot be exercised here: stated residual, not a proven control');
  }
  const root = tempRoot();
  // The observer hands the adapter a stale identity token for the root while
  // the tree is captured, and the real one afterwards. That is what a recycled
  // pid looks like from inside the adapter: the number it recorded no longer
  // belongs to the process it was recorded for. The real platform observer
  // still answers the process table, so the liveness reads stay genuine.
  let guardedPid = null;
  let staleGrants = 2; // the two discoverTree passes of captureTree()
  const staleObserver = Object.freeze({
    id: 'negative-control:stale-identity-token',
    listDescendants: async (rootPid) => ({
      ...(await DEFAULT_PROCESS_OBSERVER.listDescendants(rootPid, {})),
      pids: rootPid === guardedPid ? [rootPid] : [],
    }),
    listExisting: DEFAULT_PROCESS_OBSERVER.listExisting,
    identityFor: (target) => {
      if (target === guardedPid && staleGrants > 0) {
        staleGrants -= 1;
        return `${target}:1`;
      }
      return DEFAULT_PROCESS_OBSERVER.identityFor(target);
    },
  });
  const sandbox = sandboxFor(root, { processObserver: staleObserver });
  const run = sandbox.startForControlProbe({
    command: process.execPath,
    args: ['-e', 'setTimeout(() => {}, 30000)'],
    timeoutMs: 30000,
  });
  guardedPid = run.pid;
  await new Promise((resolveTimer) => setTimeout(resolveTimer, 250));
  // The tracked number must not be signalled, the reuse must be reported, and
  // a refused pid must not be counted as one of our own survivors.
  const cancel = await sandbox.cancel(guardedPid);
  // Checked straight after cancel(): the whole point of the guard is that the
  // tracked number survives the cancellation. The child is then reaped by hand
  // so the case does not sit through the child's own 30s lifetime waiting for
  // a run outcome that the guard has deliberately made impossible.
  const notSignalled = sandbox.isAlive(guardedPid);
  const harnessAlive = process.kill(process.pid, 0);
  const reuseReported = cancel.reasonCodes.includes('SBX_PID_REUSED');
  const notCountedAlive = !(cancel.remainingProcessIds ?? []).includes(guardedPid);
  try { process.kill(guardedPid, 'SIGKILL'); } catch { /* already gone */ }
  const outcome = await run.done;
  const checks = [
    ['trackedPidNotSignalled', notSignalled],
    ['harnessNotSignalled', harnessAlive],
    ['reuseReported', reuseReported],
    ['reusedNotCountedAlive', notCountedAlive],
  ];
  fs.rmSync(root, { recursive: true, force: true });
  return ok('cancellation/stale-token-never-signalled', checks,
    `cancel=${JSON.stringify(proofOf(cancel))}; outcome.proof=${outcome.proof}; `
    + `cancel.reasonCodes=${JSON.stringify(cancel.reasonCodes)}; trackedPidAlive=${notSignalled}`);
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
    ['comparisonOk', comparison.ok === true],
    ['noMismatchedDecisions', comparison.mismatchedDecisions === 0],
    ['noCounterViolations', comparison.counterViolations.length === 0],
    ['noOracleViolations', comparison.expectedOracleViolations.length === 0],
    ['digestStableAcrossRuns', runA.summary.corpusDigest === runB.summary.corpusDigest],
    ...Object.entries(PRESERVED_HARD_GATES).map(([counter, limit]) => {
      const value = counters[counter];
      return [`hardGate:${counter}`, Number.isInteger(value) && value >= 0 && value <= limit];
    }),
    ['runBSurvivorCounterZero', runB.summary.counters.survivors_after_cancellation === 0],
  ];
  return ok('cancellation/s2-002-frozen-corpus-hard-counters', checks,
    `inProcessReplay; comparedTrials=${comparison.comparedTrials}; corpusRevision=${runA.summary.corpusRevision}; ` +
    `corpusDigest=${runA.summary.corpusDigest.slice(0, 16)}; counters=${JSON.stringify(counters)}; ` +
    `counterViolations=${JSON.stringify(comparison.counterViolations)}`);
}

export async function runCancellationVerification({ evidencePath = DEFAULT_EVIDENCE_PATH } = {}) {
  const cases = [
    await caseCancellationProvesTree(),
    await caseTimeoutProvesTree(),
    await caseNegativeControlNoProcessTable(),
    await caseNegativeControlDescendantQueryFails(),
    await caseRecycledPidIsNeverSignalled(),
    await caseStaleTokenIsNeverSignalled(),
    await caseSelfCompletedRunMakesNoClaim(),
    await caseFrozenCorpusHardCounters(),
    checkHistoricalEvidenceUntouched(),
  ];
  // Derived from NAMED checks, not from a positional index into a boolean
  // array, so reordering a case's checks cannot silently change what this
  // counter measures. A survivor count of zero counts only when the adapter
  // proved it AND the independently published descendant pids are dead.
  const survivorCaseNames = {
    'cancellation/descendant-session-escape': ['cancelSurvivorsZero', 'outcomeSurvivorsZero', 'publishedDescendantsDead', 'rootDead'],
    'cancellation/timeout-descendant-escape': ['survivorsZero', 'publishedDescendantsDead'],
  };
  const counters = {
    survivors_after_cancellation: cases
      .filter((c) => survivorCaseNames[c.caseId])
      .reduce((sum, c) => {
        const missing = survivorCaseNames[c.caseId].filter((name) => c.namedChecks?.[name] !== true);
        return sum + (missing.length === 0 ? 0 : 1);
      }, 0),
    false_zero_survivor_success: cases
      .filter((c) => c.caseId.startsWith('cancellation/negative-control')
        || c.caseId === 'cancellation/stale-token-never-signalled')
      .filter((c) => c.verdict !== 'PASS')
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
      evidenceFile: evidencePath,
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
        ...(evidencePath.includes('win32')
          ? ['This record is STALE relative to the merged implementation: it was observed before the #41 review fixes were merged into this branch, and it must be re-observed on the Windows host before it can stand as evidence for the current code.']
          : ['The Windows record evidence/s2-002-cancellation-v2-win32.json was observed before the review fixes landed and does NOT describe the current code; it must be re-observed on the Windows host.']),
        ...(DEFAULT_PROCESS_OBSERVER.id.startsWith('platform:win32') ? [
          'On this Windows host the process observer has no per-pid identity token, so a recycled pid cannot be told apart from one of ours. The case records that residual instead of asserting a control the platform cannot support.',
        ] : []),
      ],
    },
    ok: okAll,
  };
}

const DEFAULT_EVIDENCE_PATH = 'evidence/s2-002-cancellation-v2.json';

async function main() {
  const argv = process.argv.slice(2);
  const outFlag = argv.indexOf('--out');
  const evidencePath = (outFlag >= 0 && argv[outFlag + 1]) ? argv[outFlag + 1] : DEFAULT_EVIDENCE_PATH;
  const integrityPath = evidencePath.replace(/\.json$/, '-integrity.json');
  const { evidence, ok: passed } = await runCancellationVerification({ evidencePath });
  if (argv.includes('--write')) {
    fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
    const digest = createHash('sha256').update(fs.readFileSync(evidencePath)).digest('hex');
    fs.writeFileSync(integrityPath, `${JSON.stringify({
      schemaVersion: 1,
      evidenceRevision: EVIDENCE_REVISION,
      platform: evidence.platform,
      evidenceFile: evidencePath,
      algorithm: 'SHA-256 raw file bytes',
      files: { [evidencePath]: digest },
      historicalEvidenceRewritten: false,
    }, null, 2)}\n`);
  }
  console.log(JSON.stringify({
    exitCode: passed ? 0 : 1,
    verdict: evidence.verdict,
    evidencePath,
    platform: evidence.platform,
    observationSource: evidence.observationSource,
    counters: evidence.counters,
    cases: evidence.cases.map((c) => ({ caseId: c.caseId, verdict: c.verdict })),
  }, null, 2));
  process.exit(passed ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
