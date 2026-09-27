// S2-002 process observer — cross-platform, explicitly fallible.
//
// Honesty boundary (issue #41): "zero survivors" is a claim about the OS
// process table, not about the absence of data. Every query here returns
// { pids | alive, observable, reason }. A caller that receives
// observable:false MUST fail closed: the process tree is then UNVERIFIED and
// cancellation may not report a zero-survivor success.
//
// Platform coverage:
//   win32   - Win32_Process (CIM) for descendant and liveness queries.
//   linux   - /proc snapshot: ppid walk + process-group membership, and
//             starttime identity so a recycled pid is never mistaken for a
//             member of the spawned tree (and never signalled as one).
//   other   - `ps -A -o pid=,ppid=,pgid=` for the same two facts.
//   none    - observable:false, fail closed.
//
// This module only reads the process table and signals processes that the
// caller already spawned. It is not a containment boundary.
import fs from 'node:fs';
import { spawn } from 'node:child_process';

export const IS_WINDOWS = process.platform === 'win32';
const PROC_ROOT = '/proc';
const COMMAND_TIMEOUT_MS = 10000;

// Fields of /proc/<pid>/stat after the comm field: index N-3 == field N.
const STAT_FIELD = Object.freeze({ state: 0, ppid: 1, pgrp: 2, session: 3, starttime: 19 });

function uniquePids(values) {
  return [...new Set(values.filter((value) => Number.isInteger(value) && value > 0))].sort((a, b) => a - b);
}

// `ps`/CIM helpers ----------------------------------------------------------

function runCommand(command, args) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) {
      resolve({ ok: false, stdout: '', reason: error.code ?? 'SPAWN_FAILED' });
      return;
    }
    let stdout = '';
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      finish({ ok: false, stdout: '', reason: 'COMMAND_TIMEOUT' });
    }, COMMAND_TIMEOUT_MS);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.on('error', (error) => finish({ ok: false, stdout: '', reason: error.code ?? 'SPAWN_FAILED' }));
    child.on('close', (code) => finish(code === 0
      ? { ok: true, stdout, reason: null }
      : { ok: false, stdout, reason: `EXIT_${code}` }));
  });
}

async function windowsQuery(script) {
  const result = await runCommand('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);
  if (!result.ok) {
    return { stdout: '', observable: false, reason: `SBX_PROCESS_TABLE_QUERY_FAILED:${result.reason}` };
  }
  return { stdout: result.stdout, observable: true, reason: null };
}

// /proc ---------------------------------------------------------------------

function procAvailable() {
  try {
    return fs.statSync(PROC_ROOT).isDirectory();
  } catch {
    return false;
  }
}

function readProcStat(pid) {
  try {
    const raw = fs.readFileSync(`${PROC_ROOT}/${pid}/stat`, 'utf8');
    const tail = raw.slice(raw.lastIndexOf(')') + 2).split(' ');
    const state = tail[STAT_FIELD.state];
    const ppid = Number(tail[STAT_FIELD.ppid]);
    const pgrp = Number(tail[STAT_FIELD.pgrp]);
    const session = Number(tail[STAT_FIELD.session]);
    const starttime = tail[STAT_FIELD.starttime];
    if (!state || !Number.isInteger(ppid) || !Number.isInteger(pgrp) || !Number.isInteger(session) || !starttime) return null;
    return { pid, state, ppid, pgrp, session, starttime };
  } catch {
    return null;
  }
}

function procSnapshot() {
  const table = new Map();
  let entries;
  try {
    entries = fs.readdirSync(PROC_ROOT);
  } catch {
    return null;
  }
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    const record = readProcStat(Number(entry));
    if (record) table.set(record.pid, record);
  }
  return table.size > 0 ? table : null;
}

function childrenOf(table) {
  const byParent = new Map();
  for (const record of table.values()) {
    const siblings = byParent.get(record.ppid);
    if (siblings) siblings.push(record.pid);
    else byParent.set(record.ppid, [record.pid]);
  }
  return byParent;
}

function walkDescendants(table, rootPid) {
  const byParent = childrenOf(table);
  const found = [];
  const queue = [...(byParent.get(rootPid) ?? [])];
  const seen = new Set(queue);
  while (queue.length > 0) {
    const pid = queue.shift();
    found.push(pid);
    for (const child of byParent.get(pid) ?? []) {
      if (seen.has(child)) continue;
      seen.add(child);
      queue.push(child);
    }
  }
  return found;
}

// Every process in one of `sessions` / `processGroups`, excluding the adapter's
// own. This is the only edge that still reaches a descendant after its parent
// is gone: once the root exits, descendants are re-parented to init and a
// parent walk can no longer find them.
function sweepByGroup(table, sessions, processGroups, own, exclude) {
  const pids = [];
  for (const record of table.values()) {
    if (record.pid === exclude) continue;
    if (record.session === own.session || record.pgrp === own.pgrp) continue;
    if (sessions.has(record.session) || processGroups.has(record.pgrp)) pids.push(record.pid);
  }
  return pids;
}

function ownIdentity(table) {
  const self = table.get(process.pid);
  return { pgrp: self?.pgrp ?? null, session: self?.session ?? null };
}

async function psSnapshot() {
  const result = await runCommand('ps', ['-A', '-o', 'pid=,ppid=,pgid=,sid=']);
  if (!result.ok) return null;
  const table = new Map();
  for (const line of result.stdout.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4 || !/^\d+$/.test(parts[0])) continue;
    table.set(Number(parts[0]), {
      pid: Number(parts[0]),
      ppid: Number(parts[1]),
      pgrp: Number(parts[2]),
      session: Number(parts[3]),
    });
  }
  return table.size > 0 ? table : null;
}

function identityFor(table, pid) {
  const record = table?.get(pid);
  if (!record) return null;
  // starttime disambiguates a recycled pid; a null token on platforms that do
  // not expose it degrades to pid-only identity, exactly as before.
  return record.starttime ? `${pid}:${record.starttime}` : String(pid);
}

// A /proc table is a full scan (one synchronous readFileSync per host process),
// so it is memoised for SNAPSHOT_TTL_MS. Every query in one settle step then
// shares a single scan instead of re-reading the whole table per tracked pid —
// that turned a single cancellation into thousands of synchronous reads on a
// large host. The TTL is shorter than a settle poll, so a still-observing
// caller never reads a stale table for a whole step.
const SNAPSHOT_TTL_MS = 20;
let cachedProcTable = null;
let cachedProcAt = -Infinity;

function procTable() {
  const now = Date.now();
  if (cachedProcTable && now - cachedProcAt < SNAPSHOT_TTL_MS) return cachedProcTable;
  cachedProcTable = procSnapshot();
  cachedProcAt = now;
  return cachedProcTable;
}

function pidIdentity(pid) {
  if (IS_WINDOWS) return String(pid);
  return identityFor(procTable(), pid);
}

// One table read for a whole pid set, so asking for N identities costs one
// scan rather than N.
function pidIdentities(pids) {
  if (IS_WINDOWS) {
    const out = {};
    for (const pid of pids) out[pid] = String(pid);
    return out;
  }
  const table = procTable();
  const out = {};
  for (const pid of pids) out[pid] = identityFor(table, pid);
  return out;
}

// Public observer -----------------------------------------------------------

export function createProcessObserver({ platform = process.platform } = {}) {
  const isWindows = platform === 'win32';
  const id = `platform:${platform}`;

  // Descendants of the spawned tree, tracked three ways:
  //   1. a ppid walk from the root, which is the parent/child edge the OS
  //      keeps only while the parent is alive;
  //   2. every process in a session or process group that one of our own
  //      processes created with setsid(2) — this is the only way to still see
  //      a grandchild that was re-parented to init when its parent died, and
  //      it is what catches a descendant that deliberately left our process
  //      group;
  //   3. the root's own process-group members.
  // (2) and (3) are only used when the root is genuinely isolated from the
  // observer's own session and process group. When it is not, the only tree
  // edges left are ones that sweep in unrelated host processes — including,
  // on the default spawn path, this adapter's own process group — so the
  // query fails closed instead of widening the tree. See issue #41.
  async function posixTree(rootPid, table, known) {
    const own = ownIdentity(table);
    const knownSessions = new Set((known.sessions ?? []).filter((id) => id !== own.session));
    const knownGroups = new Set((known.processGroups ?? []).filter((id) => id !== own.pgrp));
    const root = table.get(rootPid);
    if (!root) {
      // The table is readable; the subject is not in it. That is not an empty
      // tree — the tree's shape is simply unknown, because a descendant
      // re-parented to init is no longer reachable from a pid that is gone.
      //
      // The sessions/process groups captured while the root WAS alive are the
      // one edge that still reaches the tree afterwards: they were checked for
      // isolation at capture time, so sweeping them here cannot reach an
      // unrelated host process. Without this, every settle round after the
      // kill discovered nothing at all.
      const pids = uniquePids(sweepByGroup(table, knownSessions, knownGroups, own, null));
      return {
        pids,
        observable: true,
        rootPresent: false,
        reason: 'SBX_ROOT_NOT_IN_PROCESS_TABLE',
        sessions: uniquePids([...knownSessions]),
        processGroups: uniquePids([...knownGroups]),
        processGroupIsolated: null,
        sweptCapturedGroups: pids.length > 0,
      };
    }
    const isolated = root.session !== own.session && root.pgrp !== own.pgrp;
    if (!isolated) {
      // Refused, and reported. A non-isolated root shares this adapter's
      // session and/or process group, so expanding by group would sweep in
      // every process on the host that shares it.
      return {
        pids: [],
        observable: false,
        rootPresent: true,
        reason: 'SBX_PROCESS_GROUP_NOT_ISOLATED',
        sessions: uniquePids([...knownSessions]),
        processGroups: uniquePids([...knownGroups]),
        processGroupIsolated: false,
        processGroup: root.pgrp,
      };
    }
    const discovered = walkDescendants(table, rootPid);
    const pids = new Set(discovered);
    const sessions = new Set(knownSessions);
    const processGroups = new Set(knownGroups);
    for (const pid of [rootPid, ...discovered]) {
      const record = table.get(pid);
      if (!record) continue;
      if (record.session !== own.session) sessions.add(record.session);
      if (record.pgrp !== own.pgrp) processGroups.add(record.pgrp);
    }
    for (const member of sweepByGroup(table, sessions, processGroups, own, rootPid)) pids.add(member);
    pids.delete(rootPid);
    return {
      pids: uniquePids([...pids]),
      observable: true,
      rootPresent: true,
      reason: null,
      sessions: uniquePids([...sessions]),
      processGroups: uniquePids([...processGroups]),
      processGroupIsolated: true,
      sweptCapturedGroups: true,
      processGroup: root.pgrp,
    };
  }

  async function listDescendants(rootPid, known = {}) {
    if (isWindows) {
      const literal = Number(rootPid);
      // One CIM snapshot answers both questions: which pids descend from the
      // root, and whether the root is still there at all. The root flag has to
      // be emitted separately, because the walk seeds its set with the root
      // pid — without it a vanished root is indistinguishable from a live one,
      // and a vanished root means the tree's shape is unknown, not empty.
      const script = `$p=@(${literal});$all=Get-CimInstance Win32_Process;` +
        `$root=@($all | Where-Object { [int]$_.ProcessId -eq ${literal} }).Count -gt 0;` +
        `foreach($i in (1..5)){$p=@($p + @($all | Where-Object { $p -contains $_.ParentProcessId } | ForEach-Object ProcessId | Select-Object -Unique))};` +
        `("ROOT=" + [int]$root + ";" + (($p | Select-Object -Unique) -join ' '))`;
      const result = await windowsQuery(script);
      // A failed CIM query is NOT an empty process tree.
      if (result.observable !== true) {
        return {
          pids: [], observable: false, rootPresent: false, reason: result.reason,
          platform, sessions: [], processGroups: [], processGroupIsolated: null,
        };
      }
      const rootPresent = /ROOT=1;/.test(result.stdout);
      const pidText = result.stdout.replace(/^.*?ROOT=[01];/, '');
      return {
        pids: uniquePids(pidText.split(/\s+/).map(Number)).filter((pid) => pid !== rootPid),
        observable: true,
        rootPresent,
        reason: rootPresent ? null : 'SBX_ROOT_NOT_IN_PROCESS_TABLE',
        platform,
        sessions: [],
        processGroups: [],
        processGroupIsolated: null,
      };
    }
    if (platform === 'linux' && procAvailable()) {
      const table = procTable();
      if (!table) return { pids: [], observable: false, rootPresent: false, reason: 'SBX_PROCFS_SNAPSHOT_EMPTY', platform };
      return { ...(await posixTree(rootPid, table, known)), platform };
    }
    const table = await psSnapshot();
    if (!table) return { pids: [], observable: false, rootPresent: false, reason: 'SBX_PS_QUERY_UNAVAILABLE', platform };
    return { ...(await posixTree(rootPid, table, known)), platform };
  }

  async function listExisting(pids, identities = {}) {
    const candidates = uniquePids(pids);
    if (candidates.length === 0) {
      return { alive: [], observable: true, reason: null, platform, pidReused: [], identitySupported: !isWindows };
    }
    if (isWindows) {
      const literal = candidates.join(',');
      const script = `$ids=@(${literal});` +
        `Get-CimInstance Win32_Process | Where-Object { $ids -contains [int]$_.ProcessId } | ` +
        `ForEach-Object ProcessId`;
      const result = await windowsQuery(script);
      // pidReused is always an array so callers can rely on the shape. On
      // Windows it is always empty: the CIM path carries no per-pid identity
      // token, so a recycled pid cannot be distinguished from ours. That
      // residual is stated in the evidence, not hidden behind a passing
      // assertion.
      return {
        alive: result.observable === true
          ? uniquePids(result.stdout.split(/\s+/).map(Number)).filter((pid) => candidates.includes(pid))
          : candidates,
        observable: result.observable,
        reason: result.reason,
        platform,
        pidReused: [],
        identitySupported: false,
      };
    }
    if (platform === 'linux' && procAvailable()) {
      const table = procTable();
      if (!table) return { alive: candidates, observable: false, reason: 'SBX_PROCFS_SNAPSHOT_EMPTY', platform, pidReused: [], identitySupported: true };
      const alive = [];
      const pidReused = [];
      for (const pid of candidates) {
        const record = table.get(pid);
        if (!record) continue; // gone
        const expected = identities[pid];
        // A pid whose starttime differs from the one captured for our tree is
        // a different process that reused the number: not our survivor, and
        // never a kill target.
        if (expected && record.starttime && !expected.endsWith(`:${record.starttime}`)) {
          pidReused.push(pid);
          continue;
        }
        alive.push(pid);
      }
      return { alive, observable: true, reason: null, platform, pidReused, identitySupported: true };
    }
    const alive = [];
    for (const pid of candidates) {
      try {
        process.kill(pid, 0);
        alive.push(pid);
      } catch (error) {
        // EPERM means the process exists but is not ours to signal.
        if (error.code !== 'ESRCH') alive.push(pid);
      }
    }
    return { alive, observable: true, reason: null, platform, pidReused: [], identitySupported: false };
  }

  return Object.freeze({
    id,
    platform,
    listDescendants,
    listExisting,
    identityFor: (pid) => pidIdentity(pid),
    identityForMany: (pids) => pidIdentities(pids),
  });
}

export const DEFAULT_PROCESS_OBSERVER = createProcessObserver();

