// S2-002 process-cancellation regression coverage for issue #41.
//
// The reported defect: on a non-Windows host, cancel() resolved
// { terminated: true, survivors: 0 } while a descendant of the spawned process
// was still running. Descendant enumeration was a stub that returned an empty
// list off Windows, the POSIX "tree kill" signalled only the direct child and
// then reported success unconditionally, and the corpus recorded an
// unobserved cancellation as survivors = -1, which passed a `value > 0` hard
// gate.
//
// Coverage here is platform-specific by construction: every live case spawns a
// real descendant that leaves the child's process group (`start /b` on
// Windows, setsid(2) on POSIX), because a group-only or parent-only kill
// provably cannot reach it. The negative controls pin the fail-closed
// behaviour for unavailable process observation.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createSandbox } from '../../src/lib/identity/sandbox.mjs';
import { SANDBOX_LOCAL_RESTRICTED_BLOCKED } from '../../src/lib/identity/sandbox-profiles.mjs';
import { DEFAULT_PROCESS_OBSERVER } from '../../src/lib/identity/process-observer.mjs';
import { buildEscapingProcessTree, readPublishedPids, waitForPublishedPids } from '../../src/lib/identity/process-tree-fixture.mjs';
import { runCancellationVerification } from '../../scripts/verify-s2-002-cancellation-v2.mjs';

const NOW = '2026-09-12T12:00:00.000Z';
const IS_WINDOWS = process.platform === 'win32';
const UNOBSERVABLE = 'SBX_NEGATIVE_CONTROL_NO_PROCESS_TABLE';

function makeWorkspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-cancel-'));
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

function unobservableObserver(id) {
  return {
    id,
    listDescendants: async () => ({ pids: [], observable: false, reason: UNOBSERVABLE }),
    listExisting: async (pids) => ({ alive: pids, observable: false, reason: UNOBSERVABLE }),
    identityFor: (pid) => String(pid),
  };
}

const readPids = readPublishedPids;
const waitForPids = waitForPublishedPids;

// Ground truth that does not go through the adapter: the OS process table.
const guardedAlive = (pid) => {
  try { process.kill(pid, 0); return true; } catch { return false; }
};

// The tree definition is shared with the frozen corpus runner, the adversarial
// probes and the verification stage, so all four observe the same shape.
function escapingTree(root, depth = 1) {
  return buildEscapingProcessTree(root, { depth });
}

describe('S2-002 #41: cancellation proves the whole spawned process tree', { timeout: 120000 }, () => {
  test('a descendant that leaves the process group is terminated and proven gone', async () => {
    const root = makeWorkspace();
    const sandbox = sandboxFor(root);
    const tree = escapingTree(root, 3);
    const { pid, done } = sandbox.startForControlProbe({ ...tree, timeoutMs: 60000 });
    const descendants = await waitForPids(tree.pidFile);
    assert.ok(descendants.length > 0, 'the trial must observe a real descendant, not a stubbed one');

    const cancel = await sandbox.cancel(pid);
    const outcome = await done;

    // The regression: a zero-survivor report is only acceptable with a proof.
    assert.equal(cancel.proof, 'TERMINATED', JSON.stringify(cancel));
    assert.equal(cancel.terminated, true);
    assert.equal(cancel.survivors, 0);
    assert.equal(cancel.treeVerified, true);
    assert.ok(cancel.reasonCodes.includes('SBX_TERMINATION_PROVEN'));
    assert.equal(outcome.proof, 'TERMINATED');
    assert.equal(outcome.status, 'cancelled');
    assert.equal(outcome.terminated, true);
    assert.equal(outcome.survivors, 0);
    // Independent ground truth: the pids published by the deepest process.
    for (const survivor of descendants) {
      assert.equal(sandbox.isAlive(survivor), false, `descendant ${survivor} survived cancellation`);
    }
    assert.equal(sandbox.isAlive(pid), false);
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('the timeout path proves the same tree property without an explicit cancel', async () => {
    const root = makeWorkspace();
    const sandbox = sandboxFor(root);
    const tree = escapingTree(root, 2);
    const outcome = await sandbox.spawnForControlProbe({ ...tree, timeoutMs: 1500 });
    const descendants = await readPids(tree.pidFile);
    assert.equal(outcome.status, 'timeout');
    assert.equal(outcome.proof, 'TERMINATED', JSON.stringify(outcome));
    assert.equal(outcome.terminated, true);
    assert.equal(outcome.survivors, 0);
    assert.notEqual(outcome.status, 'success');
    for (const survivor of descendants) {
      assert.equal(sandbox.isAlive(survivor), false, `descendant ${survivor} survived the timeout`);
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('a run that exits on its own makes no termination claim at all', async () => {
    const root = makeWorkspace();
    const sandbox = sandboxFor(root);
    const outcome = await sandbox.spawnForControlProbe({
      command: process.execPath,
      args: ['-e', 'process.exit(0)'],
      timeoutMs: 20000,
    });
    assert.equal(outcome.status, 'completed');
    assert.equal(outcome.terminated, false, 'a completed run is not a termination claim');
    // The root was already gone when the tree was observed, so the tree's
    // shape was never captured. "No survivors" would be a claim about data the
    // adapter never had, so the honest outcome is UNVERIFIED with no count.
    assert.equal(outcome.proof, 'UNVERIFIED', JSON.stringify(outcome));
    assert.equal(outcome.survivors, null);
    assert.equal(outcome.treeVerified, false);
    assert.ok(outcome.reasonCodes.includes('SBX_TREE_SHAPE_NOT_OBSERVED'), JSON.stringify(outcome.reasonCodes));
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('a descendant holding the child pipes keeps the run out of completed', async () => {
    const root = makeWorkspace();
    const sandbox = sandboxFor(root);
    const tree = escapingTree(root, 1);
    // The escaping descendant inherits stdout/stderr, so Node's `close` event
    // cannot fire while it lives. The run must therefore terminate as a
    // timeout with a proven, empty tree instead of claiming `completed`.
    const outcome = await sandbox.spawnForControlProbe({
      command: IS_WINDOWS ? 'cmd.exe' : '/bin/sh',
      args: IS_WINDOWS
        ? ['/d', '/s', '/c', 'start /b cmd /c ping -n 5 127.0.0.1 >nul & echo done']
        : ['-c', `setsid /bin/sh -c 'sleep 3' & echo done`],
      timeoutMs: 1200,
    });
    assert.notEqual(outcome.status, 'completed', 'a live descendant must block a completed verdict');
    assert.equal(outcome.proof, 'TERMINATED', JSON.stringify(outcome));
    assert.equal(outcome.survivors, 0);
    assert.equal(outcome.treeVerified, true);
    fs.rmSync(root, { recursive: true, force: true });
  });
});

describe('S2-002 #41: the tree edges are bounded by isolation', { timeout: 60000 }, () => {
  test('a root that is not isolated from this adapter fails the discovery closed', async () => {
    // A non-detached child shares this process's session and process group.
    // Expanding the tree by session or group there would sweep in every host
    // process that shares them — including this test runner — so the observer
    // must refuse rather than return a widened pid list.
    const child = spawn(IS_WINDOWS ? 'cmd.exe' : '/bin/sh',
      IS_WINDOWS ? ['/c', 'ping -n 30 127.0.0.1 >nul'] : ['-c', 'sleep 30'],
      { stdio: 'ignore', detached: false });
    try {
      await new Promise((resolve) => setTimeout(resolve, 300));
      const result = await DEFAULT_PROCESS_OBSERVER.listDescendants(child.pid, {});
      assert.equal(result.processGroupIsolated, false, JSON.stringify(result));
      assert.equal(result.observable, false, 'a non-isolated root must not yield a tree');
      assert.equal(result.reason, 'SBX_PROCESS_GROUP_NOT_ISOLATED');
      assert.deepEqual(result.pids, [], 'no pid may be returned from a non-isolated sweep');
      assert.equal(result.pids.includes(process.pid), false, 'the adapter must never see itself as a descendant');
    } finally {
      child.kill('SIGKILL');
    }
  });

  test('a sandbox on a non-isolated root reports UNVERIFIED, not a proven termination', async () => {
    const root = makeWorkspace();
    // The observer reports a root that is not isolated, whatever the real
    // process table says, so the adapter's own fail-closed path is what runs.
    const notIsolated = {
      id: 'negative-control:root-not-isolated',
      listDescendants: async () => ({
        pids: [process.pid],
        observable: true,
        rootPresent: true,
        processGroupIsolated: false,
        reason: 'SBX_PROCESS_GROUP_NOT_ISOLATED',
      }),
      listExisting: async () => ({ alive: [], observable: true, reason: null, pidReused: [] }),
      identityFor: (pid) => String(pid),
    };
    const sandbox = sandboxFor(root, { processObserver: notIsolated });
    const { pid, done } = sandbox.startForControlProbe({
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 30000)'],
      timeoutMs: 30000,
    });
    await new Promise((resolve) => setTimeout(resolve, 250));
    const cancel = await sandbox.cancel(pid);
    const outcome = await done;
    assert.equal(cancel.proof, 'UNVERIFIED', JSON.stringify(cancel));
    assert.equal(cancel.survivors, null);
    assert.ok(cancel.reasonCodes.includes('SBX_PROCESS_GROUP_NOT_ISOLATED'), JSON.stringify(cancel.reasonCodes));
    assert.equal(cancel.terminated, false);
    assert.equal(outcome.proof, 'UNVERIFIED');
    assert.equal(process.kill(process.pid, 0), true, 'the adapter must not have signalled itself');
    fs.rmSync(root, { recursive: true, force: true });
  });
});

describe('S2-002 #41: a vanished root still exposes the captured tree edges', { timeout: 60000 }, () => {
  test('captured session/pgroup edges re-discover a re-parented descendant', async () => {
    // terminateTree() kills the root before the settle loop starts, so a
    // parent walk from that pid can never find anything again. The sessions and
    // process groups captured while the root was alive are the only edge left,
    // and they were checked for isolation at capture time.
    const root = makeWorkspace();
    const pidFile = path.join(root, 'reparented.pid');
    // The inner script is written to a file rather than inlined: an inline
    // `$!` / `$1` would be expanded by the outer shell before the inner one
    // ever sees it, and the fixture would publish the wrong pid.
    const innerPath = path.join(root, 'inner.sh');
    fs.writeFileSync(innerPath, '#!/bin/sh\nsleep 0.2\nsetsid sleep 300 &\necho $! > "$1"\nsleep 30\n', { mode: 0o755 });
    const child = spawn('/bin/sh', ['-c', `setsid ${innerPath} ${pidFile} & sleep 30`], { stdio: 'ignore', detached: true });
    try {
      for (let i = 0; i < 60 && !fs.existsSync(pidFile); i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.ok(fs.existsSync(pidFile), 'the fixture must publish the descendant pid');
      const descendant = Number(fs.readFileSync(pidFile, 'utf8').trim());
      const captured = await DEFAULT_PROCESS_OBSERVER.listDescendants(child.pid, {});
      assert.equal(captured.rootPresent, true, 'the root is alive at capture time');
      assert.equal(captured.processGroupIsolated, true, 'the capture is only trusted because it was isolated');
      assert.ok(captured.pids.length > 0, 'a real tree must have been captured');

      // Kill only the root, exactly as terminateTree does, and let the
      // descendant be re-parented to init.
      child.kill('SIGKILL');
      await new Promise((resolve) => setTimeout(resolve, 300));

      const blind = await DEFAULT_PROCESS_OBSERVER.listDescendants(child.pid, {});
      assert.equal(blind.rootPresent, false);
      assert.deepEqual(blind.pids, [], 'a parent walk from a vanished root finds nothing');

      const known = { sessions: captured.sessions, processGroups: captured.processGroups };
      const swept = await DEFAULT_PROCESS_OBSERVER.listDescendants(child.pid, known);
      assert.equal(swept.sweptCapturedGroups, true, 'the captured edges must still sweep');
      assert.ok(swept.pids.length > 0, 'the settle loop must be able to re-discover the tree after the root dies');
      // The escapee the fixture actually published is the one that must come
      // back: it left the child's process group and was re-parented to init.
      assert.equal(guardedAlive(descendant), true, 'the published escapee must still be running at this point');
      assert.equal(swept.pids.includes(descendant), true,
        `the re-parented descendant ${descendant} must be re-discovered from the captured session, got ${JSON.stringify(swept.pids)}`);
      try { process.kill(descendant, 'SIGKILL'); } catch { /* already gone */ }
    } finally {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('S2-002 #41: unavailable process observation fails closed', { timeout: 120000 }, () => {
  test('a process table that cannot be read yields UNVERIFIED, not zero survivors', async () => {
    const root = makeWorkspace();
    const sandbox = sandboxFor(root, { processObserver: unobservableObserver('negative-control:process-table-unavailable') });
    const { pid, done } = sandbox.startForControlProbe({
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 30000)'],
      timeoutMs: 30000,
    });
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 250));
    const cancel = await sandbox.cancel(pid);
    const outcome = await done;

    assert.equal(cancel.proof, 'UNVERIFIED');
    assert.equal(cancel.terminated, false, 'an unobserved tree is never a proven termination');
    assert.equal(cancel.survivors, null, 'an unknown survivor count must be null, not 0');
    assert.equal(cancel.treeVerified, false);
    assert.ok(cancel.reasonCodes.includes('SBX_PROCESS_OBSERVATION_UNAVAILABLE'));
    assert.equal(outcome.proof, 'UNVERIFIED');
    assert.equal(outcome.survivors, null);
    assert.equal(outcome.terminated, false);
    assert.equal(sandbox.platformObserver, false, 'an injected observer must be visible in the sandbox record');
    assert.equal(sandbox.observationSource, 'negative-control:process-table-unavailable');
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('descendant discovery alone failing still fails the tree proof closed', async () => {
    const root = makeWorkspace();
    const halfBlind = {
      id: 'negative-control:descendant-query-unavailable',
      listDescendants: async () => ({ pids: [], observable: false, reason: UNOBSERVABLE }),
      listExisting: (pids, identities) => DEFAULT_PROCESS_OBSERVER.listExisting(pids, identities),
      identityFor: (pid) => DEFAULT_PROCESS_OBSERVER.identityFor(pid),
    };
    const sandbox = sandboxFor(root, { processObserver: halfBlind });
    const tree = escapingTree(root, 1);
    const { pid, done } = sandbox.startForControlProbe({ ...tree, timeoutMs: 30000 });
    const descendants = await waitForPids(tree.pidFile);
    const cancel = await sandbox.cancel(pid);
    // Checked before awaiting the run outcome: the escapee inherits the child's
    // stdio, so `done` cannot resolve until it dies on its own. The case is
    // about what the adapter claimed, and the claim is already made.
    const escaped = descendants.filter((survivor) => guardedAlive(survivor));
    // Reap the fixture by hand BEFORE waiting for the run outcome: the escapee
    // holds the child's stdio, so `done` would otherwise sit out its whole
    // remaining lifetime. The adapter still could not have killed it — that is
    // exactly the point of the control.
    for (const survivor of descendants) {
      try { process.kill(survivor, 'SIGKILL'); } catch { /* already gone */ }
    }
    const outcome = await done;
    // Liveness alone cannot prove a tree of unknown shape is gone.
    assert.equal(cancel.proof, 'UNVERIFIED');
    assert.equal(cancel.survivors, null);
    assert.equal(outcome.proof, 'UNVERIFIED');
    assert.equal(outcome.survivors, null);
    assert.ok(escaped.length > 0, 'the unobservable descendant must still be running, or the control proves nothing');
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('pid identity handling matches what this platform can actually prove', async () => {
    const identity = DEFAULT_PROCESS_OBSERVER.identityFor(process.pid);
    const identitySupported = typeof identity === 'string' && identity.includes(':');
    const result = await DEFAULT_PROCESS_OBSERVER.listExisting(
      [process.pid],
      { [process.pid]: `${process.pid}:1` },
    );
    // The shape is part of the contract on every platform.
    assert.equal(result.observable, true);
    assert.ok(Array.isArray(result.alive));
    assert.ok(Array.isArray(result.pidReused));
    if (!identitySupported) {
      // No per-pid identity token here: the control is absent, and the case
      // says so rather than asserting a guard that cannot run.
      assert.equal(result.identitySupported, false);
      assert.deepEqual(result.pidReused, []);
      return;
    }
    assert.equal(result.identitySupported, true);
    assert.equal(result.alive.includes(process.pid), false, 'a reused pid is not our process');
    assert.equal(result.pidReused.includes(process.pid), true);
    // The harness itself must still be alive: the guard prevented a signal.
    assert.equal(process.kill(process.pid, 0), true);
  });
});

// Runs the versioned verification once, inside a hook rather than at module
// scope. At module scope it ran before any test was registered, so a throw
// failed the whole file as a module-load error with no named failing subtest
// (the exact diagnosability problem Veritas#16 tracked), and
// --test-name-pattern could not skip the 60s of live process trees and corpus
// replay it performs.
let CANCELLATION = null;
before(async () => {
  CANCELLATION = await runCancellationVerification();
}, { timeout: 300000 });

describe('S2-002 #41: versioned cancellation evidence', () => {
  const evidence = () => CANCELLATION.evidence;
  const passed = () => CANCELLATION.ok;

  test('all cancellation cases pass and hard counters hold', () => {
    assert.equal(evidence().evidenceRevision, 2);
    assert.equal(evidence().issue, 'SpaceDazher/Veritas#41');
    assert.equal(evidence().counters.survivors_after_cancellation, 0, JSON.stringify(evidence().cases, null, 2));
    assert.equal(evidence().counters.false_zero_survivor_success, 0);
    assert.equal(passed(), true, JSON.stringify(evidence().cases.filter((c) => c.verdict !== 'PASS'), null, 2));
    for (const entry of evidence().cases) {
      assert.equal(entry.verdict, 'PASS', `${entry.caseId}: ${entry.detail}`);
      assert.ok(entry.namedChecks && Object.keys(entry.namedChecks).length > 0,
        `${entry.caseId} must name its checks, so a counter cannot read a positional index`);
      assert.ok(Object.values(entry.namedChecks).every((value) => typeof value === 'boolean'),
        'cases must assert booleans, never re-derive the guard inside the test');
      assert.ok(entry.detail && entry.detail.length > 0, `${entry.caseId} must record raw detail`);
    }
  });

  test('a failing named check is reported by name, not only by position', () => {
    // The hard counter used to read checks[3]. If it still did, renaming or
    // reordering a check would silently change what the counter measures; the
    // name is what makes the counter stable.
    const entry = evidence().cases.find((c) => c.caseId === 'cancellation/descendant-session-escape');
    assert.ok(entry.namedChecks.cancelSurvivorsZero === true, JSON.stringify(entry.namedChecks));
    assert.ok(entry.namedChecks.publishedDescendantsDead === true, JSON.stringify(entry.namedChecks));
    assert.deepEqual(entry.failed, []);
  });

  test('the preserved S2-002 hard gates are referenced, never redefined', () => {
    assert.deepEqual(evidence().preservedHardGates, {
      cross_tenant_success: 0,
      authority_expansion: 0,
      fs_network_secret_escapes: 0,
      survivors_after_cancellation: 0,
      allow_after_revocation_commit: 0,
      missing_or_censored_trials: 0,
    });
    // The new evidence only adds counters; it never loosens the frozen set.
    for (const gate of Object.keys(evidence().preservedHardGates)) {
      assert.ok(evidence().counters[gate] === undefined || evidence().counters[gate] === 0, gate);
    }
  });

  test('no cancellation case reports a zero-survivor success without a TERMINATED proof', () => {
    for (const entry of evidence().cases) {
      if (entry.caseId.startsWith('cancellation/negative-control')) {
        assert.ok(!entry.detail.includes('survivors=0'),
          `${entry.caseId} must not produce a zero-survivor success`);
        continue;
      }
      if (entry.caseId === 'cancellation/recycled-pid-not-signalled'
        || entry.caseId === 'cancellation/historical-evidence-untouched'
        || entry.caseId === 'cancellation/self-completed-run-makes-no-claim'
        || entry.caseId === 'cancellation/s2-002-frozen-corpus-hard-counters') {
        // Not cancellation cases: the pid-reuse guard, the evidence-integrity
        // check, the self-completed run and the corpus replay have no single
        // proven zero-survivor count to report.
        continue;
      }
      assert.ok(entry.detail.includes('"survivors":0'), `${entry.caseId} must report a counted zero`);
      assert.ok(entry.detail.includes('"proof":"TERMINATED"'), `${entry.caseId} must carry the proof`);
    }
  });

  test('the pre-fix evidence records are byte-identical to the committed blobs', () => {
    const entry = evidence().cases.find((c) => c.caseId === 'cancellation/historical-evidence-untouched');
    assert.ok(entry, 'the historical-evidence guard must run');
    assert.equal(entry.verdict, 'PASS', entry.detail);
    assert.ok(evidence().historicalEvidence.length >= 8);
    assert.ok(evidence().historicalEvidence.every((p) => p.startsWith('evidence/s2-002-')
      && !p.includes('cancellation-v2')), 'the new record must not list itself as historical');
  });

  test('the frozen S2-002 corpus replays clean on this host with the hardened counters', () => {    const entry = evidence().cases.find((c) => c.caseId === 'cancellation/s2-002-frozen-corpus-hard-counters');
    assert.ok(entry, 'the corpus replay must run');
    assert.equal(entry.verdict, 'PASS', entry.detail);
    // Every hard counter, including survivors_after_cancellation, at zero.
    for (const gate of Object.keys(evidence().preservedHardGates)) {
      assert.match(entry.detail, new RegExp(`"${gate}":0`), `${gate} must be zero on this host`);
    }
    assert.ok(entry.detail.includes('counterViolations=[]'), entry.detail);
  });
});

