// S2-002 sandbox boundary adapter.
// Enforces the observable OS controls of a sandbox profile for local
// operations: filesystem canonicalization (traversal, UNC/device paths,
// junction/symlink escapes), deny-by-default network policy, environment
// allowlist, opaque secret handles with log redaction, process-tree
// cancellation, and artifact outputs with digest and provenance.
//
// Honesty boundary: a cwd + filtered env + tree kill is NOT a full sandbox.
// This Windows child-process adapter is not the executable sandbox: its
// This in-process probe adapter never launches executable tiers. The separate
// evidence-bound Podman and gVisor bridges own agent-triggered execution.
// LOCAL_RESTRICTED execution is implemented separately by the evidence-bound
// rootless Podman bridge in podman-sandbox.mjs. spawnForControlProbe() exists
// solely as a research instrument for the legacy tree-kill control.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  SNAPSHOT_SCRIPT,
  descendantsIn,
  parseProcessTable,
  queryUntilAnswered,
  settleUntilGone,
  SETTLE_BUDGET_MS,
} from './process-verdict.mjs';

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

export function createSandbox({ profile, workspaceRoots, artifactRoot, secrets = {}, now }) {
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
  // Counters for the process-table transport. Surfaced in every probe outcome
  // so that a survivor verdict can be told apart from an unverified one when
  // a clean-checkout run goes red (SpaceDazher/Veritas#16 recorded a flake
  // whose failing subtest was unrecoverable).
  const transport = { queries: 0, failedQueries: 0, settleSteps: 0, settleTimedOut: false, settleUnanswered: 0 };
  function transportSnapshot() {
    return { ...transport };
  }

  function isAlive(pid) {
    if (exitSeen.has(pid)) return false;
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      return error.code === 'EPERM';
    }
  }

  // One PowerShell/CIM round trip. Never throws: a transport failure is
  // reported as { answered: false } so the retry-and-fail-closed policy in
  // process-verdict.mjs decides what it means, instead of this adapter
  // silently equating "the query did not run" with "the process survived".
  function queryProcessTable(script) {
    return new Promise((resolve) => {
      if (process.platform !== 'win32') {
        resolve({ answered: false, reason: 'no_process_table_query_on_this_platform' });
        return;
      }
      transport.queries += 1;
      let child;
      try {
        child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true });
      } catch (error) {
        transport.failedQueries += 1;
        resolve({ answered: false, reason: `spawn_threw:${error?.code ?? error?.name ?? 'Error'}` });
        return;
      }
      let out = '';
      // A child that never produced a usable stdout stream must still settle
      // the promise: an unsettled verdict query would hang cancellation and
      // surface as a bare harness timeout with no detail.
      child.stdout?.on('data', (chunk) => { out += chunk; });
      child.on('error', (error) => {
        transport.failedQueries += 1;
        resolve({ answered: false, reason: `spawn_error:${error?.code ?? error?.name ?? 'Error'}` });
      });
      child.on('close', (code) => {
        if (code !== 0) {
          transport.failedQueries += 1;
          resolve({ answered: false, reason: `nonzero_exit:${code}` });
          return;
        }
        resolve({ answered: true, value: out });
      });
    });
  }

  // Descendant discovery fails soft: an unanswered query yields no
  // descendants, exactly as the previous three-try enumeration did, because
  // discovery only widens the set that is subsequently killed and re-checked
  // by pid. Liveness is the verdict and it never fails soft.
  async function listDescendants(pid) {
    if (process.platform !== 'win32') return [];
    const result = await queryUntilAnswered(() => queryProcessTable(SNAPSHOT_SCRIPT));
    if (!result.answered) return [];
    return descendantsIn(parseProcessTable(result.value), pid);
  }

  function treeKill(pid) {
    return new Promise((resolve) => {
      try {
        if (process.platform === 'win32') {
          const killer = spawn('taskkill', ['/T', '/F', '/PID', String(pid)], { windowsHide: true });
          killer.on('error', () => resolve(false));
          killer.on('close', () => resolve(true));
        } else {
          try {
            process.kill(-pid, 'SIGKILL');
          } catch {
            try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
          }
          resolve(true);
        }
      } catch {
        // Never leave the caller awaiting a kill that will not report back.
        resolve(false);
      }
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

  // Node's process.kill(pid, 0) is not an authoritative liveness probe on
  // Windows: a recently terminated process can remain open through a handle
  // long enough to be reported as alive. Query the OS process table for the
  // terminal cancellation proof instead.
  //
  // The query is WQL-filtered by ProcessId so only the candidate rows cross
  // the PowerShell/COM boundary, instead of marshalling every process on the
  // host into the shell and filtering it there. Candidates are validated as
  // positive integers before interpolation, so the filter carries no
  // caller-controlled text.
  //
  // A query that stays unanswered for the whole retry budget is fail-closed:
  // every candidate is reported as alive. "No survivors" is therefore only
  // ever reported when the OS actually said so.
  async function listExistingPids(pids) {
    const candidates = [...new Set(pids.filter((pid) => Number.isInteger(pid) && pid > 0))];
    if (candidates.length === 0) return [];
    if (process.platform !== 'win32') {
      return candidates.filter((pid) => isAlive(pid));
    }
    const filter = candidates.map((pid) => `ProcessId=${pid}`).join(' OR ');
    const script = `Get-CimInstance Win32_Process -Filter "${filter}" | ForEach-Object ProcessId`;
    const result = await queryUntilAnswered(() => queryProcessTable(script));
    if (!result.answered) return candidates;
    const alive = result.value
      .split(/\s+/)
      .map(Number)
      .filter((value) => Number.isInteger(value) && candidates.includes(value));
    return [...new Set(alive)];
  }

  async function survivorPids(pid, knownDescendants = []) {
    const discovered = await listDescendants(pid);
    const candidates = new Set([pid, ...knownDescendants, ...discovered]);
    return listExistingPids([...candidates]);
  }

  async function countSurvivors(pid, knownDescendants = []) {
    return (await survivorPids(pid, knownDescendants)).length;
  }

  // Settles a just-killed tree: re-observes until one process-table snapshot
  // reports nothing tracked alive, killing whatever the previous snapshot
  // still listed. Bounded by wall clock rather than by a fixed iteration
  // count, because a loaded host spends seconds per snapshot where an idle
  // one spends milliseconds, and a fixed count is what overran the test
  // budget. An unanswerable snapshot is fail-closed: every tracked pid counts
  // as alive and the loop keeps working instead of declaring success.
  async function settleTree(pid, knownDescendants = []) {
    const tracked = new Set([pid, ...knownDescendants]);
    const settled = await settleUntilGone({
      budgetMs: SETTLE_BUDGET_MS,
      observe: async () => {
        if (process.platform !== 'win32') {
          // No process-table query exists here, so liveness is whatever the
          // platform probe can see and descendant discovery stays empty. The
          // loop is still bounded, so this cannot hang a caller.
          const alive = [...tracked].filter((candidate) => isAlive(candidate));
          return { settled: alive.length === 0, answered: true, alive };
        }
        const result = await queryUntilAnswered(() => queryProcessTable(SNAPSHOT_SCRIPT));
        if (!result.answered) {
          return { settled: false, answered: false, alive: [...tracked], reason: result.lastFailure };
        }
        const entries = parseProcessTable(result.value);
        for (const descendant of descendantsIn(entries, pid)) tracked.add(descendant);
        const present = new Set(entries.map((entry) => entry.pid));
        const alive = [...tracked].filter((candidate) => present.has(candidate));
        return { settled: alive.length === 0, answered: true, alive };
      },
      terminate: async (alive) => {
        for (const candidate of alive) {
          directKill(candidate);
          await treeKill(candidate);
        }
      },
    });
    transport.settleSteps += settled.steps;
    transport.settleTimedOut = transport.settleTimedOut || settled.timedOut;
    transport.settleUnanswered += settled.unanswered;
    return { ...settled, tracked: [...tracked] };
  }

  // Capture the process tree before terminating the root. Once the parent
  // exits Windows may re-parent descendants, making post-kill enumeration
  // unable to prove that the original tree is gone. Kill deepest candidates
  // explicitly and retain their PIDs for the terminal survivor check.
  async function terminateTree(pid, childHandle = null) {
    const descendants = await listDescendants(pid);
    // Ask Windows to terminate the root while the parent/child relation
    // still exists. Killing the root handle first can re-parent a child that
    // raced the process-table snapshot and make /T unable to discover it.
    await treeKill(pid);
    for (const descendant of [...descendants].reverse()) {
      directKill(descendant);
      await treeKill(descendant);
    }
    directKill(pid, childHandle);
    await treeKill(pid);
    const settled = await settleTree(pid, descendants);
    // Anything the settle loop discovered and killed also belongs to the
    // original tree, so it joins the retained set the terminal check looks
    // at. Dropping it would let a re-parented pid that escaped this round be
    // reported as "no survivors".
    return [...new Set([...descendants, ...settled.tracked])];
  }

  function probeEnv() {
    const base = buildEnvironment({});
    const osVars = {};
    for (const key of OS_RUNTIME_ENV_KEYS) {
      if (typeof process.env[key] === 'string') osVars[key] = process.env[key];
    }
    return { ...osVars, ...base };
  }

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
        detached: false,
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
      knownDescendants: [],
      terminationPromise: null,
    };
    activeProbes.set(pid, record);
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    child.stdout.on('data', (chunk) => { stdout = Buffer.concat([stdout, chunk]); });
    child.stderr.on('data', (chunk) => { stderr = Buffer.concat([stderr, chunk]); });

    const finish = async (status, exitCode) => {
      if (record.timeoutTimer) clearTimeout(record.timeoutTimer);
      activeProbes.delete(pid);
      if (record.terminationPromise) {
        record.knownDescendants = await record.terminationPromise;
      }
      const remainingProcessIds = await survivorPids(pid, record.knownDescendants);
      settle.resolve({
        status,
        terminated: status !== 'completed',
        exitCode,
        pid,
        durationMs: Date.now() - started,
        survivors: remainingProcessIds.length,
        remainingProcessIds,
        processQueries: transportSnapshot(),
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
      activeProbes.delete(pid);
      finish(code === 0 ? 'completed' : 'failed', code);
    });
    record.timeoutTimer = setTimeout(() => {
      record.timedOut = true;
      record.cancelled = true;
      record.terminationPromise ??= terminateTree(pid, child);
    }, timeoutMs);
    return { pid, done };
  }

  async function cancel(pid) {
    const record = activeProbes.get(pid);
    if (record) record.cancelled = true;
    const termination = record?.terminationPromise ?? terminateTree(pid, record?.child ?? null);
    if (record) record.terminationPromise = termination;
    const descendants = await termination;
    if (record) record.knownDescendants = descendants;
    const remainingProcessIds = await survivorPids(pid, descendants);
    return {
      terminated: true,
      survivors: remainingProcessIds.length,
      remainingProcessIds,
      pid,
      // Distinguishes "the OS confirmed N processes are still alive" from
      // "the OS never answered within the retry budget" (fail-closed).
      processQueries: transportSnapshot(),
    };
  }

  // Public execution path: blocked tiers never spawn anything.
  async function spawnProcess(request) {
    if (!executionAllowed) {
      return {
        status: 'BLOCKED_SANDBOX',
        terminated: true,
        reasonCodes: ['SBX_EXEC_FORBIDDEN'],
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
    blockedReason: executionAllowed ? null : (executableTier ? boundary.reason : 'SBX_TIER_FORBIDS_EXEC'),
    blockedDetail: executableTier ? boundary.detail : 'NO_EXEC permits contract/evidence operations only.',
    resolvePath,
    checkNetwork,
    buildEnvironment,
    redact,
    writeOutput,
    isAlive,
    descendantPids: (pid) => listDescendants(pid),
    lastProcessQueries: transportSnapshot,
    spawnProcess,
    startForControlProbe,
    spawnForControlProbe: (request) => runProbe(request),
    cancel,
  });
}
