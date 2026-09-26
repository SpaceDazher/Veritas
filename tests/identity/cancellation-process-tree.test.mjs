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
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createSandbox } from '../../src/lib/identity/sandbox.mjs';
import { SANDBOX_LOCAL_RESTRICTED_BLOCKED } from '../../src/lib/identity/sandbox-profiles.mjs';
import { DEFAULT_PROCESS_OBSERVER } from '../../src/lib/identity/process-observer.mjs';
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

async function readPids(file) {
  if (!file) return [];
  try {
    return fs.readFileSync(file, 'utf8').split(/\s+/).map(Number).filter((value) => Number.isInteger(value) && value > 0);
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

// depth 1 = the escaping descendant; depth 3 = root -> child -> grandchild ->
// great-grandchild, so the whole chain has to be discovered and reaped.
function escapingTree(root, depth = 1) {
  const pidFile = path.join(root, 'tree.pid').split('\\').join('/');
  if (IS_WINDOWS) {
    return {
      platform: 'win32',
      command: 'cmd.exe',
      args: ['/d', '/s', '/c', 'start /b cmd /c ping -n 60 127.0.0.1 >nul & ping -n 60 127.0.0.1 >nul'],
      pidFile: null,
    };
  }
  let inner = `echo $$ > ${pidFile}; for i in 1 2 3 4 5 6 7 8 9 10 11 12; do sleep 5; done`;
  for (let level = 1; level < depth; level += 1) inner = `/bin/sh -c ${JSON.stringify(inner)}`;
  return { platform: 'posix', command: '/bin/sh', args: ['-c', `setsid /bin/sh -c ${JSON.stringify(inner)} & sleep 60`], pidFile };
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

  test('a run that exits on its own is still observed, never assumed empty', async () => {
    const root = makeWorkspace();
    const sandbox = sandboxFor(root);
    const outcome = await sandbox.spawnForControlProbe({
      command: process.execPath,
      args: ['-e', 'process.exit(0)'],
      timeoutMs: 20000,
    });
    assert.equal(outcome.status, 'completed');
    assert.equal(outcome.terminated, false, 'a completed run is not a termination claim');
    assert.equal(outcome.proof, 'TERMINATED', JSON.stringify(outcome));
    assert.equal(outcome.survivors, 0);
    assert.equal(outcome.treeVerified, true, 'the tree was observed, not assumed');
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
    const { pid, done } = sandbox.startForControlProbe({ ...tree, timeoutMs: 60000 });
    const descendants = await waitForPids(tree.pidFile);
    assert.ok(descendants.length > 0, 'the control needs a real descendant to be meaningful');
    const cancel = await sandbox.cancel(pid);
    const outcome = await done;
    // Liveness alone cannot prove a tree of unknown shape is gone.
    assert.equal(cancel.proof, 'UNVERIFIED');
    assert.equal(cancel.survivors, null);
    assert.equal(outcome.proof, 'UNVERIFIED');
    assert.equal(outcome.survivors, null);
    for (const survivor of descendants) {
      try { process.kill(survivor, 'SIGKILL'); } catch { /* already gone */ }
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('a recycled pid is reported as reused and never counted as a survivor', async () => {
    const result = await DEFAULT_PROCESS_OBSERVER.listExisting(
      [process.pid],
      { [process.pid]: `${process.pid}:1` },
    );
    assert.equal(result.observable, true);
    assert.ok(Array.isArray(result.alive));
    assert.equal(result.alive.includes(process.pid), false, 'a reused pid is not our process');
    assert.equal(result.pidReused.includes(process.pid), true);
    // The harness itself must still be alive: the guard prevented a signal.
    assert.equal(process.kill(process.pid, 0), true);
  });
});

// Executed once at module scope: the live cancellation cases spawn real
// process trees, and the verdict is the object under test.
const CANCELLATION = await runCancellationVerification();

describe('S2-002 #41: versioned cancellation evidence', () => {
  const { evidence, ok: passed } = CANCELLATION;

  test('all cancellation cases pass and hard counters hold', () => {
    assert.equal(evidence.evidenceRevision, 2);
    assert.equal(evidence.issue, 'SpaceDazher/Veritas#41');
    assert.equal(evidence.counters.survivors_after_cancellation, 0, JSON.stringify(evidence.cases, null, 2));
    assert.equal(evidence.counters.false_zero_survivor_success, 0);
    assert.equal(passed, true, JSON.stringify(evidence.cases.filter((c) => c.verdict !== 'PASS'), null, 2));
    for (const entry of evidence.cases) {
      assert.equal(entry.verdict, 'PASS', `${entry.caseId}: ${entry.detail}`);
      assert.ok(entry.checks.every((check) => typeof check === 'boolean'),
        'cases must assert booleans, never re-derive the guard inside the test');
      assert.ok(entry.detail && entry.detail.length > 0, `${entry.caseId} must record raw detail`);
    }
  });

  test('the preserved S2-002 hard gates are referenced, never redefined', () => {
    assert.deepEqual(evidence.preservedHardGates, {
      cross_tenant_success: 0,
      authority_expansion: 0,
      fs_network_secret_escapes: 0,
      survivors_after_cancellation: 0,
      allow_after_revocation_commit: 0,
      missing_or_censored_trials: 0,
    });
    // The new evidence only adds counters; it never loosens the frozen set.
    for (const gate of Object.keys(evidence.preservedHardGates)) {
      assert.ok(evidence.counters[gate] === undefined || evidence.counters[gate] === 0, gate);
    }
  });

  test('no cancellation case reports a zero-survivor success without a TERMINATED proof', () => {
    for (const entry of evidence.cases) {
      if (entry.caseId.startsWith('cancellation/negative-control')) {
        assert.ok(!entry.detail.includes('survivors=0'),
          `${entry.caseId} must not produce a zero-survivor success`);
        continue;
      }
      if (entry.caseId === 'cancellation/recycled-pid-not-signalled'
        || entry.caseId === 'cancellation/historical-evidence-untouched'
        || entry.caseId === 'cancellation/s2-002-frozen-corpus-hard-counters') {
        // Not cancellation cases: the pid-reuse guard, the evidence-integrity
        // check and the corpus replay have no single survivor count to report.
        continue;
      }
      assert.ok(entry.detail.includes('"survivors":0'), `${entry.caseId} must report a counted zero`);
      assert.ok(entry.detail.includes('"proof":"TERMINATED"'), `${entry.caseId} must carry the proof`);
    }
  });

  test('the pre-fix evidence records are byte-identical to the committed blobs', () => {
    const entry = evidence.cases.find((c) => c.caseId === 'cancellation/historical-evidence-untouched');
    assert.ok(entry, 'the historical-evidence guard must run');
    assert.equal(entry.verdict, 'PASS', entry.detail);
    assert.ok(evidence.historicalEvidence.length >= 8);
    assert.ok(evidence.historicalEvidence.every((p) => p.startsWith('evidence/s2-002-')
      && !p.includes('cancellation-v2')), 'the new record must not list itself as historical');
  });

  test('the frozen S2-002 corpus replays clean on this host with the hardened counters', () => {
    const entry = evidence.cases.find((c) => c.caseId === 'cancellation/s2-002-frozen-corpus-hard-counters');
    assert.ok(entry, 'the corpus replay must run');
    assert.equal(entry.verdict, 'PASS', entry.detail);
    // Every hard counter, including survivors_after_cancellation, at zero.
    for (const gate of Object.keys(evidence.preservedHardGates)) {
      assert.match(entry.detail, new RegExp(`"${gate}":0`), `${gate} must be zero on this host`);
    }
    assert.ok(entry.detail.includes('counterViolations=[]'), entry.detail);
  });
});

