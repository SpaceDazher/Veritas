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

function uniqueIds(values) {
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
    return { pids: [], observable: false, reason: `SBX_PROCESS_TABLE_QUERY_FAILED:${result.reason}` };
  }
  const pids = uniquePids(result.stdout.split(/\s+/).map(Number));
  return { pids, observable: true, reason: null };
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

function groupMembers(table, rootPid) {
  const root = table.get(rootPid);
  if (!root) return [];
  return [...table.values()].filter((record) => record.pgrp === root.pgrp).map((record) => record.pid);
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

function pidIdentity(pid) {
  if (IS_WINDOWS) return String(pid);
  return identityFor(procSnapshot(), pid);
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
  // observer's own session and process group; otherwise they would sweep in
  // unrelated host processes, so they are refused and reported instead.
  async function posixTree(rootPid, table, known) {
    const root = table.get(rootPid);
    if (!root) {
      // The table is readable; the subject is not in it. That is not an empty
      // tree — the tree's shape is simply unknown, because a descendant
      // re-parented to init is no longer reachable from a pid that is gone.
      return { pids: [], observable: true, rootPresent: false, reason: 'SBX_ROOT_NOT_IN_PROCESS_TABLE', sessions: [], processGroups: [], processGroupIsolated: null };
    }
    const own = ownIdentity(table);
    const isolated = root.session !== own.session && root.pgrp !== own.pgrp;
    const byParent = childrenOf(table);
    const discovered = walkDescendants(table, rootPid);
    const pids = new Set(discovered);
    const sessions = new Set(known.sessions ?? []);
    const processGroups = new Set(known.processGroups ?? []);
    for (const pid of [rootPid, ...discovered]) {
      const record = table.get(pid);
      if (!record) continue;
      if (record.session !== own.session) sessions.add(record.session);
      if (record.pgrp !== own.pgrp) processGroups.add(record.pgrp);
    }
    if (isolated) {
      for (const record of table.values()) {
        if (record.pid === rootPid) continue;
        if (sessions.has(record.session) || processGroups.has(record.pgrp)) pids.add(record.pid);
      }
    } else {
      for (const pid of groupMembers(table, rootPid)) pids.add(pid);
    }
    pids.delete(rootPid);
    return {
      pids: uniquePids([...pids]),
      observable: true,
      rootPresent: true,
      reason: isolated ? null : 'SBX_PROCESS_GROUP_NOT_ISOLATED',
      sessions: uniqueIds([...sessions]),
      processGroups: uniqueIds([...processGroups]),
      processGroupIsolated: isolated,
      processGroup: root.pgrp,
    };
  }

  async function listDescendants(rootPid, known = {}) {
    if (isWindows) {
      const literal = Number(rootPid);
      const script = `$p=@(${literal});$all=Get-CimInstance Win32_Process;` +
        `foreach($i in (1..5)){$p=@($p + @($all | Where-Object { $p -contains $_.ParentProcessId } | ForEach-Object ProcessId | Select-Object -Unique))};` +
        `($p | Select-Object -Unique) -join ' '`;
      const result = await windowsQuery(script);
      // A failed CIM query is NOT an empty process tree.
      // rootPresent is assumed here: the CIM walk seeds the set with the root
      // pid, so the script cannot distinguish a vanished root. Cancellation
      // captures the tree while the root is alive, so this does not weaken the
      // cancellation proof; a self-completed run is not given a proof at all.
      return {
        ...result,
        pids: result.pids.filter((pid) => pid !== rootPid),
        platform,
        rootPresent: true,
        sessions: [],
        processGroups: [],
        processGroupIsolated: null,
      };
    }
    if (platform === 'linux' && procAvailable()) {
      const table = procSnapshot();
      if (!table) return { pids: [], observable: false, rootPresent: false, reason: 'SBX_PROCFS_SNAPSHOT_EMPTY', platform };
      return { ...(await posixTree(rootPid, table, known)), platform };
    }
    const table = await psSnapshot();
    if (!table) return { pids: [], observable: false, rootPresent: false, reason: 'SBX_PS_QUERY_UNAVAILABLE', platform };
    return { ...(await posixTree(rootPid, table, known)), platform };
  }

  async function listExisting(pids, identities = {}) {
    const candidates = uniquePids(pids);
    if (candidates.length === 0) return { alive: [], observable: true, reason: null, platform };
    if (isWindows) {      const literal = candidates.join(',');
      const script = `$ids=@(${literal});` +
        `Get-CimInstance Win32_Process | Where-Object { $ids -contains [int]$_.ProcessId } | ` +
        `ForEach-Object ProcessId`;
      const result = await windowsQuery(script);
      return { ...result, alive: result.pids.filter((pid) => candidates.includes(pid)), platform };
    }
    if (platform === 'linux' && procAvailable()) {
      const table = procSnapshot();
      if (!table) return { alive: candidates, observable: false, reason: 'SBX_PROCFS_SNAPSHOT_EMPTY', platform };
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
      return { alive, observable: true, reason: null, platform, pidReused };
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
    return { alive, observable: true, reason: null, platform };
  }

  return Object.freeze({
    id,
    platform,
    listDescendants,
    listExisting,
    identityFor: (pid) => pidIdentity(pid),
  });
}

export const DEFAULT_PROCESS_OBSERVER = createProcessObserver();

