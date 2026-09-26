// S2-002 sandbox boundary adapter.
// Enforces the observable OS controls of a sandbox profile for local
// operations: filesystem canonicalization (traversal, UNC/device paths,
// junction/symlink escapes), deny-by-default network policy, environment
// allowlist, opaque secret handles with log redaction, process-tree
// cancellation, and artifact outputs with digest and provenance.
//
// Honesty boundary: a cwd + filtered env + tree kill is NOT a full sandbox.
// This in-process probe adapter never launches executable tiers. The separate
// evidence-bound Podman and gVisor bridges own agent-triggered execution.
// LOCAL_RESTRICTED execution is implemented separately by the evidence-bound
// rootless Podman bridge in podman-sandbox.mjs. startForControlProbe() and
// spawnForControlProbe() exist solely as a research instrument for the
// process-tree termination control.
//
// Termination is a PROVEN claim, never an assumed one (issue #41). The
// adapter terminates the whole spawned tree and then re-observes the OS
// process table. `terminated: true` is emitted only when observation was
// available and nothing of the tracked tree is left alive; an unavailable
// observer or a surviving pid yields a fail-closed UNVERIFIED/SURVIVORS
// outcome. A Windows-only replay never established this property for POSIX.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { DEFAULT_PROCESS_OBSERVER } from './process-observer.mjs';

const DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  ...Array.from({ length: 9 }, (_, i) => `COM${i + 1}`),
  ...Array.from({ length: 9 }, (_, i) => `LPT${i + 1}`),
]);

const BASE_ENV_KEYS = Object.freeze(['VERITAS_SANDBOX_TIER', 'VERITAS_SANDBOX_PROFILE']);
// OS variables a spawned console process needs merely to start on Windows.
// They are injected only into the internal probe runner environment, never
// exposed through buildEnvironment().
const OS_RUNTIME_ENV_KEYS = Object.freeze(['SystemRoot', 'TEMP', 'TMP', 'PATH', 'COMSPEC']);

const WPAT = (p) => p.split('\\').join('/');

function isDeviceSegment(segment) {
  const base = segment.split('.')[0].toUpperCase();
  return DEVICE_NAMES.has(base);
}

function stripDeviceName(name) {
  // A path that merely *contains* a device name in a segment is rejected
  // before any filesystem access (Windows would otherwise open the device).
  return name.split(/[\\/]/).some((segment) => segment.length > 0 && isDeviceSegment(segment));
}

function isAbsoluteish(name) {
  if (/^[a-zA-Z]:/.test(name)) return true;
  return name.startsWith('\\') || name.startsWith('/');
}

function looksLikeTraversal(name) {
  return name.split(/[\\/]/).includes('..');
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalInsideRoots(candidate, roots) {
  const canon = WPAT(candidate).toLowerCase();
  return roots.some((root) => {
    const canonRoot = WPAT(root).toLowerCase().replace(/\/+$/, '');
    return canon === canonRoot || canon.startsWith(`${canonRoot}/`);
  });
}

// Resolves the deepest existing ancestor and canonicalizes it, so junction
// and symlink escapes are detected even for not-yet-created files.
function realpathDeepest(target) {
  let current = path.resolve(target);
  const missing = [];
  while (!fs.existsSync(current)) {
    missing.unshift(path.basename(current));
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return { real: fs.realpathSync(current), missing };
}

export function createSandbox({ profile, workspaceRoots, artifactRoot, secrets = {}, now, processObserver }) {
  if (!profile || !profile.tier) throw new Error('SANDBOX_PROFILE_REQUIRED');
  if (!Array.isArray(workspaceRoots) || workspaceRoots.length === 0) {
    throw new Error('SANDBOX_ROOTS_REQUIRED');
  }
  if (typeof now !== 'string') throw new Error('SANDBOX_CLOCK_REQUIRED');
  const roots = workspaceRoots.map((root) => path.resolve(root));
  const rootRealPaths = roots.map((root) => fs.realpathSync(root));
  const artifactsDir = path.resolve(artifactRoot ?? path.join(roots[0], 'artifacts'));

  const tier = profile.tier;
  const executableTier = tier === 'LOCAL_RESTRICTED' || tier === 'UNTRUSTED_CODE';

  function verifyKernelNetworkBoundary() {
    // Honest probe: from Node.js on this platform we cannot create or verify
    // an AppContainer/network-isolation kernel boundary for a child process.
    // Until that changes, executable tiers remain blocked.
    return {
      supported: false,
      reason: 'SBX_NO_KERNEL_NETWORK_BOUNDARY',
      detail: 'No provable kernel-level network isolation for child processes on this platform; AppContainer/container evidence required.',
    };
  }

  const boundary = executableTier ? verifyKernelNetworkBoundary() : { supported: false, reason: 'SBX_TIER_FORBIDS_EXEC' };
  const executionAllowed = executableTier && boundary.supported === true;

  function assertRootsAllows(realPath) {
    if (!canonicalInsideRoots(realPath, rootRealPaths)) {
      const error = new Error(`path escapes workspace roots: ${realPath}`);
      error.code = 'LINK_ESCAPE';
      throw error;
    }
  }

  function resolvePath(name) {
    if (typeof name !== 'string' || name.length === 0) {
      const error = new Error('empty path');
      error.code = 'PATH_ESCAPE';
      throw error;
    }
    if (name.startsWith('\\\\') || name.startsWith('//')) {
      const error = new Error(`UNC path rejected: ${name}`);
      error.code = 'UNC_PATH';
      throw error;
    }
    if (isDeviceSegment(name)) {
      const error = new Error(`device path rejected: ${name}`);
      error.code = 'DEVICE_PATH';
      throw error;
    }
    if (stripDeviceName(name)) {
      const error = new Error(`device path rejected: ${name}`);
      error.code = 'DEVICE_PATH';
      throw error;
    }
    if (looksLikeTraversal(name)) {
      const error = new Error(`traversal rejected: ${name}`);
      error.code = 'PATH_ESCAPE';
      throw error;
    }
    let target;
    if (isAbsoluteish(name)) {
      target = path.resolve(name);
    } else {
      target = path.resolve(roots[0], name);
    }
    if (!canonicalInsideRoots(target, roots)) {
      const error = new Error(`absolute path outside allowed roots: ${name}`);
      error.code = 'ROOT_VIOLATION';
      throw error;
    }
    const { real, missing } = realpathDeepest(target);
    assertRootsAllows(real);
    const resolved = path.join(real, ...missing);
    assertRootsAllows(resolved);
    return resolved;
  }

  function checkNetwork(host, port) {
    if (profile.network.policy === 'deny_all') {
      return { allowed: false, reason: 'NETWORK_DENY_ALL' };
    }
    const target = profile.network.allowlist.find((entry) => entry.host === host);
    if (!target) return { allowed: false, reason: 'NETWORK_HOST_NOT_ALLOWLISTED' };
    if (!target.ports.includes(port)) return { allowed: false, reason: 'NETWORK_PORT_NOT_ALLOWLISTED' };
    return { allowed: true };
  }

  function buildEnvironment(overrides = {}) {
    const env = {};
    for (const key of BASE_ENV_KEYS) env[key] = key === 'VERITAS_SANDBOX_TIER' ? tier : profile.profile_id;
    for (const [key, value] of Object.entries(overrides)) {
      if (!profile.environment.allowlist.includes(key)) continue;
      if (typeof value !== 'string') {
        const error = new Error(`environment value for ${key} must be a string`);
        error.code = 'ENV_VALUE_INVALID';
        throw error;
      }
      env[key] = value;
    }
    return Object.freeze(env);
  }

  function redact(text) {
    let output = String(text);
    for (const [handle, value] of Object.entries(secrets)) {
      if (typeof value !== 'string' || value.length === 0) continue;
      while (output.includes(value)) {
        output = output.replace(value, `[REDACTED:${handle}]`);
      }
    }
    return output;
  }

  // ---- Process controls (research instrument; see module header) ----
  const activeProbes = new Map();
  // Pids whose 'close' event already fired. On Windows our own child handle
  // keeps OpenProcess succeeding for a terminated child, which makes
  // process.kill(pid, 0) unreliable for liveness of direct children.
  const exitSeen = new Set();

  // The observer is the only source of truth about what is still running. The
  // default is the host platform observer; an injected observer exists so the
  // fail-closed path (issue #41) can be exercised against a platform that
  // cannot report its process table. `observationSource` records which one
  // produced a proof, so an injected run can never be mistaken for a host
  // observation.
  const observer = processObserver ?? DEFAULT_PROCESS_OBSERVER;
  const observationSource = observer.id ?? 'injected:unknown';
  const isPlatformObserver = processObserver === undefined;

  function isAlive(pid) {
    if (exitSeen.has(pid)) return false;
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      return error.code === 'EPERM';
    }
  }

  // Descendants of the spawned tree. An observer that cannot answer is NOT an
  // empty tree: it reports observable:false and every caller fails closed.
  // `known` carries the sessions/process groups our own processes created, so
  // a re-discovery pass still sees a grandchild that was re-parented to init
  // when its parent died.
  async function discoverTree(pid, known = {}) {
    const result = await observer.listDescendants(pid, known);
    if (!result || result.observable !== true) {
      return {
        pids: [],
        identities: {},
        sessions: [],
        processGroups: [],
        processGroupIsolated: null,
        rootPresent: false,
        observable: false,
        reason: result?.reason ?? 'SBX_PROCESS_OBSERVATION_UNAVAILABLE',
      };
    }
    const identities = {};
    for (const candidate of result.pids) identities[candidate] = observer.identityFor(candidate);
    return {
      pids: [...new Set(result.pids)],
      identities,
      sessions: uniqueIds([...(known.sessions ?? []), ...(result.sessions ?? [])]),
      processGroups: uniqueIds([...(known.processGroups ?? []), ...(result.processGroups ?? [])]),
      processGroupIsolated: result.processGroupIsolated ?? null,
      // readable-but-absent is different from unreadable: an absent root means
      // the tree's shape is unknown, not that the tree was empty.
      rootPresent: result.rootPresent !== false,
      observable: true,
      reason: result.reason ?? null,
      processGroup: result.processGroup ?? null,
    };
  }

  // Liveness of a tracked pid set. Query failure is fail-closed: every
  // candidate is reported alive, because "could not look" is not "gone".
  async function observeExisting(pids, identities) {
    if (pids.length === 0) return { alive: [], observable: true, reason: null, pidReused: [] };
    const result = await observer.listExisting(pids, identities);
    if (!result || result.observable !== true) {
      return {
        alive: [...pids],
        observable: false,
        reason: result?.reason ?? 'SBX_PROCESS_OBSERVATION_UNAVAILABLE',
        pidReused: [],
      };
    }
    return {
      alive: result.alive,
      observable: true,
      reason: result.reason ?? null,
      pidReused: result.pidReused ?? [],
    };
  }

  // Terminate one tracked pid plus, on POSIX, its whole process group. A
  // reported group/pid kill is a signal request, never proof: only
  // observeExisting() can conclude that a process is gone.
  function treeKill(pid, identities = {}) {
    return new Promise((resolve) => {
      const identity = identities[pid];
      if (identity && observer.identityFor && observer.identityFor(pid) !== identity) {
        // The number now belongs to a different process; signalling it would
        // hit an unrelated pid.
        resolve({ signalled: false, reason: 'SBX_PID_REUSED' });
        return;
      }
      if (process.platform === 'win32') {
        const killer = spawn('taskkill', ['/T', '/F', '/PID', String(pid)], { windowsHide: true });
        killer.on('error', () => resolve({ signalled: false, reason: 'SBX_TASKKILL_UNAVAILABLE' }));
        killer.on('close', () => resolve({ signalled: true, reason: null }));
        return;
      }
      // POSIX: the probe child is spawned as a process-group leader, so the
      // negative pid addresses the group and reaches every descendant that did
      // not leave it with setsid(2).
      let groupSignalled = false;
      try {
        process.kill(-pid, 'SIGKILL');
        groupSignalled = true;
      } catch {
        groupSignalled = false;
      }
      let pidSignalled = false;
      try {
        process.kill(pid, 'SIGKILL');
        pidSignalled = true;
      } catch {
        pidSignalled = false;
      }
      resolve({
        signalled: groupSignalled || pidSignalled,
        reason: groupSignalled || pidSignalled ? null : 'SBX_SIGNAL_UNSUPPORTED',
      });
    });
  }

  function directKill(pid, childHandle = null) {
    try {
      if (childHandle?.pid === pid) return childHandle.kill('SIGKILL');
      process.kill(pid, 'SIGKILL');
      return true;
    } catch {
      return false;
    }
  }

  function trackPid(tracked, identities, pid) {
    if (!Number.isInteger(pid) || pid <= 0 || tracked.has(pid)) return;
    tracked.add(pid);
    identities[pid] ??= observer.identityFor(pid);
  }

  function uniqueIds(values) {
    return [...new Set(values.filter((value) => Number.isInteger(value) && value > 0))].sort((a, b) => a - b);
  }

  // Terminal proof for a tracked tree.
  //   TERMINATED            — observed, nothing of the tree is left alive
  //   SURVIVORS_REMAINING   — observed, at least one tracked pid is alive
  //   UNVERIFIED            — the process table could not be observed
  // `terminated` is true only for TERMINATED, so a blocked/unknown
  // observation can never be reported as successful termination.
  function terminationProof({ alive, observable, reason, trackedProcessIds, rounds, pidReused = [] }) {
    const reasonCodes = [];
    if (!observable) {
      reasonCodes.push('SBX_PROCESS_OBSERVATION_UNAVAILABLE', reason ?? 'SBX_PROCESS_OBSERVATION_UNAVAILABLE');
      return {
        proof: 'UNVERIFIED',
        terminated: false,
        treeVerified: false,
        survivors: null,
        remainingProcessIds: [],
        trackedProcessIds,
        rounds,
        pidReused,
        reasonCodes,
      };
    }
    if (alive.length > 0) {
      reasonCodes.push('SBX_SURVIVOR_PIDS_PRESENT');
      return {
        proof: 'SURVIVORS_REMAINING',
        terminated: false,
        treeVerified: true,
        survivors: alive.length,
        remainingProcessIds: alive,
        trackedProcessIds,
        rounds,
        pidReused,
        reasonCodes,
      };
    }
    if (pidReused.length > 0) reasonCodes.push('SBX_PID_REUSED');
    reasonCodes.push('SBX_TERMINATION_PROVEN');
    return {
      proof: 'TERMINATED',
      terminated: true,
      treeVerified: true,
      survivors: 0,
      remainingProcessIds: [],
      trackedProcessIds,
      rounds,
      pidReused,
      reasonCodes,
    };
  }

  // Capture the process tree before terminating the root. Once the parent
  // exits, descendants are re-parented and post-kill ppid enumeration can no
  // longer prove the original tree is gone. Kill deepest candidates
  // explicitly and retain their pids (with starttime identity) for the
  // terminal survivor proof.
  async function captureTree(pid) {
    const first = await discoverTree(pid);
    const tracked = new Set();
    const identities = { ...first.identities };
    trackPid(tracked, identities, pid);
    for (const descendant of first.pids) trackPid(tracked, identities, descendant);
    let observable = first.observable;
    // A readable process table with the root already gone cannot describe the
    // tree: descendants are re-parented to init and are no longer reachable
    // from it. Reporting an empty tree here would be the same false zero the
    // proof exists to prevent, so the shape counts as unobserved.
    let reason = first.reason;
    if (observable && !first.rootPresent) {
      observable = false;
      reason = 'SBX_TREE_SHAPE_NOT_OBSERVED';
    }
    let sessions = first.sessions;
    let processGroups = first.processGroups;
    if (observable) {
      // A second pass catches a descendant forked between the two reads.
      const second = await discoverTree(pid, { sessions, processGroups });
      if (second.observable) {
        for (const member of second.pids) trackPid(tracked, identities, member);
        sessions = second.sessions;
        processGroups = second.processGroups;
      } else {
        observable = false;
        reason = second.reason;
      }
    }
    return {
      tracked: [...tracked],
      identities,
      observable,
      reason,
      sessions,
      processGroups,
      processGroup: first.processGroup ?? null,
      processGroupIsolated: first.processGroupIsolated ?? null,
    };
  }

  // Terminates a just-cancelled tree and returns a terminal proof either way.
  // Each round re-discovers descendants (a process can fork while we signal),
  // re-observes every tracked pid, and re-signals whatever is still alive.
  async function settleTree(pid, captured) {
    const tracked = new Set(captured.tracked);
    const identityMap = { ...captured.identities };
    const known = { sessions: captured.sessions, processGroups: captured.processGroups };
    trackPid(tracked, identityMap, pid);
    const pidReused = new Set();
    let rounds = 0;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      rounds = attempt + 1;
      if (exitSeen.has(pid)) tracked.delete(pid);
      // A tree of unknown shape can never be reported as fully terminated:
      // the pids we would check are exactly the ones we could not enumerate.
      // A vanished root is expected here (the tree was just killed), so only
      // an unreadable table fails the proof closed; the tracked set captured
      // before the kill is what gets re-observed.
      const discovered = await discoverTree(pid, known);
      if (!discovered.observable) {
        const observedBlind = await observeExisting([...tracked], identityMap);
        return terminationProof({
          alive: observedBlind.alive,
          observable: false,
          reason: discovered.reason,
          trackedProcessIds: [...tracked],
          rounds,
          pidReused: [...pidReused],
        });
      }
      for (const descendant of discovered.pids) trackPid(tracked, identityMap, descendant);
      known.sessions = discovered.sessions;
      known.processGroups = discovered.processGroups;
      const observed = await observeExisting([...tracked], identityMap);
      for (const reused of observed.pidReused) pidReused.add(reused);
      if (!observed.observable) {
        return terminationProof({
          alive: observed.alive,
          observable: false,
          reason: observed.reason,
          trackedProcessIds: [...tracked],
          rounds,
          pidReused: [...pidReused],
        });
      }
      if (observed.alive.length === 0) {
        return terminationProof({
          alive: [],
          observable: true,
          reason: null,
          trackedProcessIds: [...tracked],
          rounds,
          pidReused: [...pidReused],
        });
      }
      for (const candidate of observed.alive) {
        directKill(candidate);
        await treeKill(candidate, identityMap);
      }
      await new Promise((resolveTimer) => setTimeout(resolveTimer, 100));
    }
    const observed = await observeExisting([...tracked], identityMap);
    return terminationProof({
      alive: observed.alive,
      observable: observed.observable,
      reason: observed.reason,
      trackedProcessIds: [...tracked],
      rounds,
      pidReused: [...pidReused],
    });
  }

  // Observation-only proof for a run that ended on its own (completed or
  // failed). Nothing is signalled here: a normal exit is not a cancellation,
  // but any surviving member of the tracked tree is still reported instead of
  // being rounded down to zero.
  async function verifyTree(pid) {
    const captured = await captureTree(pid);
    if (!captured.observable) {
      return {
        proof: terminationProof({
          alive: captured.tracked,
          observable: false,
          reason: captured.reason,
          trackedProcessIds: captured.tracked,
          rounds: 0,
        }),
        descendants: captured.tracked.filter((entry) => entry !== pid),
        captured,
      };
    }
    const tracked = new Set(captured.tracked);
    if (exitSeen.has(pid)) tracked.delete(pid);
    const observed = await observeExisting([...tracked], captured.identities);
    return {
      proof: terminationProof({
        alive: observed.alive,
        observable: observed.observable,
        reason: observed.reason,
        trackedProcessIds: [...tracked],
        rounds: 1,
        pidReused: observed.pidReused,
      }),
      descendants: captured.tracked.filter((entry) => entry !== pid),
      captured,
    };
  }

  async function terminateTree(pid, childHandle = null) {
    const captured = await captureTree(pid);
    // Ask the OS to terminate the tree while the root/parent relation still
    // exists. Killing the root handle first can hide a descendant that raced
    // the snapshot from a /T or group kill.
    await treeKill(pid, captured.identities);
    for (const descendant of captured.tracked.slice().reverse()) {
      if (descendant === pid) continue;
      directKill(descendant);
      await treeKill(descendant, captured.identities);
    }
    directKill(pid, childHandle);
    await treeKill(pid, captured.identities);
    const proof = await settleTree(pid, captured);
    return { proof, descendants: captured.tracked.filter((entry) => entry !== pid), captured };
  }

  function probeEnv() {
    const base = buildEnvironment({});
    const osVars = {};
    for (const key of OS_RUNTIME_ENV_KEYS) {
      if (typeof process.env[key] === 'string') osVars[key] = process.env[key];
    }
    return { ...osVars, ...base };
  }

  // POSIX children are spawned as process-group leaders (libuv setsid), so a
  // group-directed SIGKILL reaches every descendant that stays in the group.
  // Windows keeps detached:false because taskkill /T walks the parent chain
  // and a detached child would get its own console.
  const useProcessGroup = process.platform !== 'win32';

  function withinProcessLimit() {
    const max = profile.process?.max_processes ?? 1;
    return activeProbes.size < max;
  }

  function runProbe(request) {
    try {
      return runSettled(request).done;
    } catch (error) {
      return Promise.reject(error);
    }
  }

  function startForControlProbe(request) {
    const settled = runSettled(request);
    return { pid: settled.pid, done: settled.done };
  }

  function runSettled({ command, args, timeoutMs }) {
    if (!withinProcessLimit()) {
      const error = new Error(`process limit reached (${profile.process?.max_processes ?? 1})`);
      error.code = 'LIMIT_PROCESSES';
      throw error;
    }
    const started = Date.now();
    let settle;
    const done = new Promise((resolve, reject) => {
      settle = { resolve, reject };
    });
    let child;
    try {
      child = spawn(command, args, {
        cwd: roots[0],
        env: probeEnv(),
        detached: useProcessGroup,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      settle.reject(error);
      return { pid: -1, done };
    }
    const pid = child.pid;
    const record = {
      child,
      timeoutTimer: null,
      cancelled: false,
      timedOut: false,
      terminationPromise: null,
      trackedPids: [],
      identities: {},
      descendants: [],
    };
    activeProbes.set(pid, record);
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    child.stdout.on('data', (chunk) => { stdout = Buffer.concat([stdout, chunk]); });
    child.stderr.on('data', (chunk) => { stderr = Buffer.concat([stderr, chunk]); });

    const finish = async (status, exitCode) => {
      if (record.timeoutTimer) clearTimeout(record.timeoutTimer);
      activeProbes.delete(pid);
      // A cancellation or timeout already started the terminate-and-prove
      // sequence; a run that ended on its own is only observed, so a normal
      // exit never signals a pid it does not own.
      const termination = record.terminationPromise
        ? await record.terminationPromise
        : await verifyTree(pid);
      record.trackedPids = termination.captured.tracked;
      record.identities = termination.captured.identities;
      record.descendants = termination.descendants;
      const proof = termination.proof;
      settle.resolve({
        status,
        // `terminated` is a proven statement about the whole tracked tree,
        // not a restatement of the status string.
        terminated: proof.terminated && status !== 'completed',
        // Proof fields: `proof` is the machine-readable verdict, `survivors`
        // is a non-negative count or null when the tree could not be observed.
        proof: proof.proof,
        treeVerified: proof.treeVerified,
        survivors: proof.survivors,
        remainingProcessIds: proof.remainingProcessIds,
        trackedProcessIds: proof.trackedProcessIds,
        reasonCodes: proof.reasonCodes,
        observationSource,
        exitCode,
        pid,
        durationMs: Date.now() - started,
        stdoutDigest: sha256(redact(stdout.toString('utf8'))),
        stderrDigest: sha256(redact(stderr.toString('utf8'))),
        limits: profile.process ?? {},
        provenance: { profileId: profile.profile_id, tier, createdAt: now },
      });
    };

    child.on('error', (error) => {
      activeProbes.delete(pid);
      settle.reject(error);
    });
    child.on('close', (code) => {
      exitSeen.add(pid);
      if (record.timedOut) {
        finish('timeout', null);
        return;
      }
      if (record.cancelled) {
        finish('cancelled', null);
        return;
      }
      finish(code === 0 ? 'completed' : 'failed', code);
    });
    record.timeoutTimer = setTimeout(() => {
      record.timedOut = true;
      record.cancelled = true;
      record.terminationPromise ??= terminateTree(pid, child);
    }, timeoutMs);
    return { pid, done };
  }

  // Cancellation is fail-closed: the returned proof is TERMINATED only when
  // the whole tracked tree was re-observed as gone. Otherwise the caller sees
  // SURVIVORS_REMAINING (observed survivors) or UNVERIFIED (observation
  // unavailable, survivors: null) and `terminated` is false.
  async function cancel(pid) {
    const record = activeProbes.get(pid);
    if (record) record.cancelled = true;
    const termination = record?.terminationPromise ?? terminateTree(pid, record?.child ?? null);
    if (record) record.terminationPromise = termination;
    const { proof, descendants, captured } = await termination;
    if (record) {
      record.trackedPids = captured.tracked;
      record.identities = captured.identities;
      record.descendants = descendants;
    }
    return {
      pid,
      terminated: proof.terminated,
      proof: proof.proof,
      treeVerified: proof.treeVerified,
      survivors: proof.survivors,
      remainingProcessIds: proof.remainingProcessIds,
      trackedProcessIds: proof.trackedProcessIds,
      descendants,
      reasonCodes: proof.reasonCodes,
      observationSource,
    };
  }

  // Public execution path: blocked tiers never spawn anything.
  async function spawnProcess(request) {
    if (!executionAllowed) {
      return {
        status: 'BLOCKED_SANDBOX',
        terminated: true,
        proof: 'TERMINATED',
        survivors: 0,
        reasonCodes: ['SBX_EXEC_FORBIDDEN'],
        observationSource,
        blockedReason: executableTier ? boundary.reason : 'SBX_TIER_FORBIDS_EXEC',
      };
    }
    return runProbe(request);
  }

  function writeOutput(name, bytes) {
    if (typeof name !== 'string' || name.length === 0) {
      const error = new Error('empty output name');
      error.code = 'PATH_ESCAPE';
      throw error;
    }
    if (isDeviceSegment(name)) {
      const error = new Error(`device path rejected: ${name}`);
      error.code = 'DEVICE_PATH';
      throw error;
    }
    if (/[\\/:]|\.\./.test(name)) {
      const error = new Error(`output name must be a bare file name: ${name}`);
      error.code = 'PATH_ESCAPE';
      throw error;
    }
    const target = path.join(resolvePath(WPAT(path.relative(roots[0], artifactsDir))), name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, bytes);
    return Object.freeze({
      path: target,
      sha256: sha256(bytes),
      bytes: bytes.length,
      provenance: {
        profileId: profile.profile_id,
        tier,
        workspaceRoots: roots,
        createdAt: now,
      },
    });
  }

  return Object.freeze({
    tier,
    profileId: profile.profile_id,
    executionAllowed,
    observationSource,
    platformObserver: isPlatformObserver,
    blockedReason: executionAllowed ? null : (executableTier ? boundary.reason : 'SBX_TIER_FORBIDS_EXEC'),
    blockedDetail: executableTier ? boundary.detail : 'NO_EXEC permits contract/evidence operations only.',
    resolvePath,
    checkNetwork,
    buildEnvironment,
    redact,
    writeOutput,
    isAlive,
    spawnProcess,
    startForControlProbe,
    spawnForControlProbe: (request) => runProbe(request),
    cancel,
  });
}
