// S2-002 — transport policy for the process-table survivor verdict.
//
// sandbox.mjs answers "is this process tree gone?" by shelling out to
// PowerShell/CIM. That query can fail for reasons that have nothing to do
// with the process tree: the spawn can fail, WMI can be contended, the shell
// can exit non-zero. The original adapter resolved such a failure as
// "every candidate is still alive", which is the correct fail-closed reading
// of *an unverified answer* — but it applied it to the FIRST transport
// hiccup, with no retry. Under clean-checkout load that turned a red
// identity/sandbox suite out of an answer the OS never managed to give
// (SpaceDazher/Veritas#16).
//
// The policy this module encodes:
//   * a verdict may only report "nothing alive" when the OS actually
//     answered, so the fail-closed reading is preserved;
//   * an unanswered query is retried within a wall-clock budget before that
//     fail-closed reading is taken, so a loaded host is not read as a
//     survivor;
//   * the settle loop is bounded by wall clock, not by a fixed iteration
//     count, because under load each iteration costs seconds rather than
//     milliseconds and a fixed count blew the test time budget.
//
// The helpers are platform-independent on purpose: the Windows host is the
// only place the live probes run, and the policy that made them flaky must
// therefore be testable everywhere.
export const QUERY_BUDGET_MS = 5000;
export const QUERY_MIN_ATTEMPTS = 3;
export const QUERY_BACKOFF_MS = 50;
// Hard ceiling on query attempts. A real clock plus QUERY_BUDGET_MS already
// bounds the loop; this only guards an injected sleep/clock that never
// advances, so a bug in the caller degrades into a bounded answer rather than
// a hung gate.
export const QUERY_MAX_ATTEMPTS = 200;
export const SETTLE_BUDGET_MS = 10000;
export const SETTLE_POLL_MS = 100;
export const SETTLE_MAX_STEPS = 64;
// A cancellation probe has to cancel a tree that exists. A fixed delay after
// spawn assumes the child has already created its own children; under load it
// has not, so the probe either reaps a one-process tree it then reports as a
// tree, or leaks the processes it never saw. Bounded in polls, because every
// poll costs a process-table query.
export const TREE_FORM_ATTEMPTS = 20;
export const TREE_FORM_POLL_MS = 100;

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Waits until `descendantPids(rootPid)` reports at least one descendant, so a
 * cancellation probe acts on a tree that actually exists.
 *
 * Returns `{ formed, seen, attempts }`. `formed: false` is a fail-closed
 * answer: the caller must not record the cancellation as a survivor check,
 * because there was no tree to reap.
 */
export async function awaitTree(descendantPids, rootPid, {
  attempts = TREE_FORM_ATTEMPTS,
  pollMs = TREE_FORM_POLL_MS,
  sleep = defaultSleep,
} = {}) {
  if (typeof descendantPids !== 'function') throw new Error('PROCESS_DESCENDANT_PROBE_REQUIRED');
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const seen = await descendantPids(rootPid);
    if (Array.isArray(seen) && seen.length > 0) return { formed: true, seen: seen.length, attempts: attempt + 1 };
    if (attempt + 1 < attempts) await sleep(pollMs);
  }
  return { formed: false, seen: 0, attempts };
}

// A whole-process-table snapshot rendered as "<pid> <ppid>" lines. One CIM
// enumeration answers both questions the settle loop asks — which pids are
// alive, and who descends from the root — from a single consistent view.
// Enumerating Win32_Process is the dominant cost of the Windows process
// adapter, so one pass per settle step instead of two is what keeps
// cancellation inside its time budget when the host is loaded.
export const SNAPSHOT_SCRIPT = 'Get-CimInstance Win32_Process | ForEach-Object { "$($_.ProcessId) $($_.ParentProcessId)" }';
// Five generations, matching the previous enumeration. Deeper trees are
// still killed by taskkill /T; only the pre-kill snapshot used for the
// terminal check is depth-limited.
export const DESCENDANT_DEPTH = 5;

export function parseProcessTable(text) {
  const entries = [];
  for (const line of String(text).split(/\r?\n/)) {
    const match = /^(\d{1,10})\s+(\d{1,10})$/.exec(line.trim());
    if (match) entries.push({ pid: Number(match[1]), parentPid: Number(match[2]) });
  }
  return entries;
}

export function descendantsIn(entries, rootPid) {
  const found = new Set();
  let frontier = [rootPid];
  for (let depth = 0; depth < DESCENDANT_DEPTH; depth += 1) {
    const next = [];
    for (const entry of entries) {
      if (entry.pid === rootPid || found.has(entry.pid)) continue;
      if (frontier.includes(entry.parentPid)) {
        found.add(entry.pid);
        next.push(entry.pid);
      }
    }
    if (next.length === 0) break;
    frontier = next;
  }
  return [...found];
}

/**
 * Runs `attempt` until it yields an answer the OS actually produced, or the
 * wall-clock budget expires. `attempt` must resolve to
 * `{ answered: true, value }` on success and `{ answered: false, reason }`
 * when the query itself failed; a throw is treated as a transport failure.
 *
 * Resolves to `{ answered, value, attempts, failures, lastFailure }`. The
 * caller decides what an unanswered verdict means; for the survivor check
 * that must remain fail-closed.
 */
export async function queryUntilAnswered(attempt, {
  budgetMs = QUERY_BUDGET_MS,
  minAttempts = QUERY_MIN_ATTEMPTS,
  maxAttempts = QUERY_MAX_ATTEMPTS,
  backoffMs = QUERY_BACKOFF_MS,
  sleep = defaultSleep,
  now = Date.now,
} = {}) {
  if (typeof attempt !== 'function') throw new Error('PROCESS_QUERY_REQUIRED');
  const deadline = now() + budgetMs;
  let attempts = 0;
  let lastReason = 'query_not_attempted';
  for (;;) {
    attempts += 1;
    let answer;
    try {
      answer = await attempt();
    } catch (error) {
      answer = { answered: false, reason: `query_threw:${error?.code ?? error?.name ?? 'Error'}` };
    }
    if (answer?.answered === true) {
      return { answered: true, value: answer.value, attempts, failures: attempts - 1, lastFailure: null };
    }
    lastReason = answer?.reason ?? 'unanswered';
    // The budget only starts to bite once the minimum attempt count is met:
    // a fast host gets a bounded number of tries even when budgetMs is small.
    if (attempts >= maxAttempts || (attempts >= minAttempts && now() >= deadline)) {
      return { answered: false, value: undefined, attempts, failures: attempts, lastFailure: lastReason };
    }
    await sleep(backoffMs * attempts);
  }
}

/**
 * Observes a just-killed process tree until the OS confirms nothing tracked
 * is alive, terminating whatever is still listed, bounded by wall clock and
 * by a hard step ceiling.
 *
 * `observe` must resolve to `{ settled, answered, alive }` where `settled` is
 * true only when the OS confirmed an empty alive set, and `terminate` is
 * called with the last observed alive set before the next observation. An
 * unanswered observation reports `answered: false` and every tracked pid as
 * alive, so the loop keeps working instead of declaring success.
 */
export async function settleUntilGone({
  observe,
  terminate,
  budgetMs = SETTLE_BUDGET_MS,
  pollMs = SETTLE_POLL_MS,
  maxSteps = SETTLE_MAX_STEPS,
  sleep = defaultSleep,
  now = Date.now,
} = {}) {
  if (typeof observe !== 'function') throw new Error('PROCESS_OBSERVER_REQUIRED');
  if (typeof terminate !== 'function') throw new Error('PROCESS_TERMINATOR_REQUIRED');
  const deadline = now() + budgetMs;
  let steps = 0;
  let unanswered = 0;
  let last = { settled: false, answered: false, alive: [] };
  let lastFailure = 'not_observed';
  for (;;) {
    steps += 1;
    let observation;
    try {
      observation = await observe();
    } catch (error) {
      observation = {
        settled: false,
        answered: false,
        alive: [],
        reason: `observer_threw:${error?.code ?? error?.name ?? 'Error'}`,
      };
    }
    if (observation?.settled === true) {
      return { settled: true, steps, unanswered, last, lastFailure: null, timedOut: false };
    }
    last = observation ?? { settled: false, answered: false, alive: [] };
    if (last.answered === false) {
      unanswered += 1;
      lastFailure = last.reason ?? 'unanswered';
    }
    if (steps >= maxSteps || now() >= deadline) {
      return { settled: false, steps, unanswered, last, lastFailure, timedOut: now() >= deadline };
    }
    await terminate(Array.isArray(last.alive) ? last.alive : []);
    await sleep(pollMs);
  }
}
