#!/usr/bin/env node
// S2-002 counter isolation diagnostic.
//
// PURPOSE
// A Windows run of the S2-002 corpus at commit 6a53358 reports
// `fs_network_secret_escapes = 1` and `survivors_after_cancellation = 1`, while
// the committed Windows evidence records 0 and 0. This tool isolates WHICH
// observation produces each non-zero counter, and whether that observation is
// new or was always there. It changes nothing: it refuses to write anywhere
// near evidence/ or results/, and it proves the canonical tree is byte-identical
// before and after.
//
//   node scripts/diagnose-s2-002-counters.mjs
//   node scripts/diagnose-s2-002-counters.mjs --ab            # also run the pre-change tree
//   VERITAS_DIAG_OUT=/tmp/x node scripts/diagnose-s2-002-counters.mjs
//
// What it prints
//   1. the oracle (trial count + digest) and whether it is the committed one;
//   2. every observation with match === false, in full, per run;
//   3. the cancellation trial's full record and how the counter was derived;
//   4. which sandbox controls were not exercised on this platform;
//   5. the counter table, with the contributing observation named for each
//      non-zero value;
//   6. for --ab: the same for the pre-change tree, so a host difference and a
//      code difference can be told apart.
//
// Exit 0 means the diagnostic ran; it is NOT a pass verdict. A non-zero hard
// counter is a finding to investigate, never a downgrade.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildExpectedCorpusOracle } from './s2-002-run.mjs';
import { createSandbox } from '../src/lib/identity/sandbox.mjs';
import { SANDBOX_LOCAL_RESTRICTED_BLOCKED } from '../src/lib/identity/sandbox-profiles.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const COMMITTED_ORACLE_DIGEST = 'a5a63dc0c53c29bcd10003a31179342bc1f3a2fbe0fb39b6c69dbb5ee3eeb7e0';

// The three files this ticket changed in the S2-002 surface. The --ab mode
// restores their PRE-change content into a throwaway copy of the tree so the
// same host can be measured both ways.
const CHANGED_FILES = Object.freeze([
  'src/lib/identity/sandbox.mjs',
  'scripts/s2-002-run.mjs',
  'scripts/verify-s2-002.mjs',
]);
const BASE_REF = '8f6254db1be3eb9a3c886ef41465314bf8e797c8';

const args = process.argv.slice(2);
const doAb = args.includes('--ab');
// --repeat N answers the question a single A/B run cannot: is a non-zero
// counter a persistent property of this host, or does it vary run to run? A
// counter that is always the same number is a deterministic defect; one that
// moves is timing-dependent, and the two need different fixes.
const repeatIndex = args.indexOf('--repeat');
const repeatCount = repeatIndex >= 0 ? Math.max(1, Number.parseInt(args[repeatIndex + 1] ?? '1', 10) || 1) : 1;
// --settle-sweep answers the question five identical repeats cannot: is the
// survivor a property of cancellation, or of how long the trial waits before it
// cancels? The S2-002 cancellation control waits a fixed 500 ms after starting
// the child. If the child chain has not materialised by then, an enumeration
// cannot see it, the kill misses it, and the trial reports a survivor - a
// property of the TRIAL, not of cancellation. Sweeping the wait separates them
// without touching the corpus, the evidence or the gate.
const doSweep = args.includes('--settle-sweep');
const numberAfter = (flag, fallback) => {
  const i = args.indexOf(flag);
  return i >= 0 ? Number.parseInt(args[i + 1] ?? String(fallback), 10) || fallback : fallback;
};
const sweepWaits = String(process.env.VERITAS_DIAG_WAITS ?? '250,500,1000,2000,4000')
  .split(',').map((v) => Number.parseInt(v.trim(), 10)).filter((v) => Number.isInteger(v) && v > 0);
const sweepRepeats = Math.max(1, numberAfter('--sweep-repeats', 3));
const OUT = process.env.VERITAS_DIAG_OUT
  ?? fs.mkdtempSync(path.join(os.tmpdir(), 's2-002-diag-'));

// Never inside the canonical directories, whatever the caller asks for.
const canonical = [path.join(ROOT, 'evidence'), path.join(ROOT, 'results')];
for (const dir of canonical) {
  if (path.resolve(OUT).startsWith(`${dir}${path.sep}`) || path.resolve(OUT) === dir) {
    console.error(`REFUSING: --out would write into ${dir}`);
    process.exit(2);
  }
}

function gitOut(...a) {
  return spawnSync('git', a, { cwd: ROOT, encoding: 'utf8', windowsHide: true });
}

/** SHA-256 of every canonical evidence/results file, so we can prove we did not touch it. */
function canonicalFingerprint() {
  const out = new Map();
  const files = gitOut('ls-files', 'evidence', 'results');
  if (files.status !== 0) return out;
  for (const rel of files.stdout.split('\n').filter(Boolean)) {
    try {
      out.set(rel, createHash('sha256').update(fs.readFileSync(path.join(ROOT, rel))).digest('hex'));
    } catch { /* a file may be absent in an archive; skip it */ }
  }
  return out;
}

function reportFingerprintChange(before, after) {
  const changed = [];
  for (const [file, sha] of after) if (before.get(file) !== sha) changed.push(file);
  for (const file of before.keys()) if (!after.has(file)) changed.push(file);
  if (changed.length > 0) {
    console.error(`\nCANONICAL EVIDENCE CHANGED (${changed.length}) — this diagnostic must never do that:`);
    for (const file of changed.slice(0, 20)) console.error(`  ${file}`);
    return false;
  }
  return true;
}

function runCorpus(label, cwd, runId) {
  const outputRoot = path.join(OUT, label);
  const result = spawnSync(process.execPath, [
    path.join(cwd, 'scripts', 's2-002-run.mjs'),
    '--run-id', runId,
    '--executor-id', `diag-${label}`,
    '--nonce-base', `nb-diag-${label}`,
    '--output-root', outputRoot,
  ], { cwd, encoding: 'utf8', windowsHide: true, timeout: 600000 });
  if (result.status !== 0) {
    console.error(`  corpus run "${label}" failed: ${String(result.stderr ?? '').split('\n')[0]}`);
    return null;
  }
  const observations = JSON.parse(fs.readFileSync(path.join(outputRoot, 'observations.json'), 'utf8'));
  const summary = JSON.parse(fs.readFileSync(path.join(outputRoot, 'summary.json'), 'utf8'));
  return { label, cwd, runId, outputRoot, observations, summary };
}

function describe(label, run) {
  const { observations, summary } = run;
  console.log(`\n${'='.repeat(78)}\n${label}\n${'='.repeat(78)}`);
  console.log(`  platform        : ${summary.platform ?? 'unknown'}`);
  console.log(`  trials executed : ${observations.length}`);
  console.log(`  oracle trials   : ${summary.oracleTrialCount ?? buildExpectedCorpusOracle().trialCount}`);

  // 1. every observation that did not match, in full — this is the whole point.
  const mismatches = observations.filter((o) => o.match === false);
  console.log(`\n  -- observations with match === false: ${mismatches.length} --`);
  for (const o of mismatches) {
    console.log(`     trialId   : ${o.trialId}`);
    console.log(`     kind      : ${o.kind}`);
    console.log(`     expected  : ${JSON.stringify(o.expected)}`);
    console.log(`     observed  : ${JSON.stringify(o.observed)}`);
    console.log(`     decision  : ${o.decision}`);
    console.log(`     reasonCodes: ${JSON.stringify(o.reasonCodes)}`);
    if ('survivors' in o) console.log(`     survivors : ${JSON.stringify(o.survivors)}`);
    console.log(`     full      : ${JSON.stringify(o)}`);
  }

  // 2. the not-run controls, so an honest skip is never read as a measurement.
  const notRun = observations.filter((o) => o.notRun === true);
  console.log(`\n  -- controls NOT exercised on this platform: ${notRun.length} --`);
  for (const o of notRun) {
    console.log(`     ${o.trialId}: observed=${JSON.stringify(o.observed)} decision=${o.decision} ` +
      `reasonCodes=${JSON.stringify(o.reasonCodes)} survivors=${JSON.stringify(o.survivors ?? null)}`);
  }

  // 3. the cancellation control in full, with how the counter came from it.
  const cancellation = observations.filter((o) => o.trialId === 'sandbox/cancellation-survivors');
  console.log(`\n  -- cancellation control --`);
  if (cancellation.length === 0) {
    console.log('     ABSENT from the run (it is pushed unconditionally, so this is itself a finding)');
  }
  for (const o of cancellation) console.log(`     ${JSON.stringify(o)}`);

  // 4. the counter table, each non-zero value traced to its observations.
  console.log(`\n  -- counters --`);
  for (const [name, value] of Object.entries(summary.counters ?? {})) {
    const flag = typeof value === 'number' ? (value > 0 ? '  <== NON-ZERO' : '') : (value === null ? '  (unmeasured)' : '');
    console.log(`     ${name.padEnd(32)} ${JSON.stringify(value)}${flag}`);
  }
  const escapeContributors = mismatches.filter((o) => o.kind === 'sandbox');
  console.log(`\n  fs_network_secret_escapes contributors (sandbox, match===false): ${escapeContributors.length}`);
  for (const o of escapeContributors) {
    console.log(`     ${o.trialId}: expected ${JSON.stringify(o.expected)} observed ${JSON.stringify(o.observed)}`);
  }
  return { label, counters: summary.counters ?? {}, mismatches: mismatches.map((o) => o.trialId), platform: summary.platform };
}

// ---------------------------------------------------------------------------

const fingerprintBefore = canonicalFingerprint();
console.log(`diagnostic output root: ${OUT}`);
console.log(`canonical evidence fingerprint: ${fingerprintBefore.size} files (must not change)`);

/**
 * One cancellation probe with a configurable settle wait, driving the PRODUCTION
 * adapter with the same child shape the S2-002 cancellation control uses.
 * Returns the survivor count and any survivor pids so the caller can reap them.
 */
/**
 * Kill everything this probe could have started, using sources independent of the
 * sandbox's own bookkeeping: the pids the child wrote for itself, the sandbox's
 * survivor list (advisory only), and — on Windows — a CIM query that is not the
 * module under test. Returns how many extra pids had to be reaped, which is
 * itself a datum: a non-zero count means the sandbox did not know about them.
 */
function reap(childPid, survivorIds, pidFile) {
  const extra = new Set();
  try {
    for (const line of fs.readFileSync(pidFile, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean)) {
      const pid = Number.parseInt(line, 10);
      if (Number.isInteger(pid) && pid > 0) extra.add(pid);
    }
  } catch { /* the child may never have written it */ }
  if (process.platform === 'win32') {
    // Cleanup-only enumeration, deliberately not the sandbox's implementation.
    const ps = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-Command',
      `(Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq ${childPid} }).ProcessId`,
    ], { encoding: 'utf8', windowsHide: true, timeout: 20000 });
    for (const line of String(ps.stdout ?? '').split(/\s+/).map((l) => l.trim()).filter(Boolean)) {
      const pid = Number.parseInt(line, 10);
      if (Number.isInteger(pid) && pid > 0) extra.add(pid);
    }
  }
  // Ground truth, measured independently of the sandbox: of the pids the child
  // reported, how many were STILL ALIVE after cancel? Comparing that against
  // `remainingProcessIds` would be wrong - a descendant that was enumerated and
  // killed is SUPPOSED to be absent from the survivor list. The honest question
  // is only whether anything survived.
  const isAlive = (pid) => {
    try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
  };
  const expected = [...extra].filter((pid) => Number.isInteger(pid) && pid > 0);
  const actuallyAlive = expected.filter(isAlive);
  const all = new Set([Number(childPid), ...survivorIds.map(Number), ...expected].filter((n) => Number.isInteger(n) && n > 0));
  for (const pid of all) {
    if (process.platform === 'win32') {
      spawnSync('taskkill', ['/T', '/F', '/PID', String(pid)], { windowsHide: true, timeout: 20000 });
    }
    try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
  }
  return {
    reaped: all.size,
    expectedChildren: expected.length,
    actuallyAliveAfterCancel: actuallyAlive.length,
    stillAlivePids: actuallyAlive,
  };
}

async function probeOnce(settleMs, workspaceRoot) {
  const sandbox = createSandbox({
    profile: { ...SANDBOX_LOCAL_RESTRICTED_BLOCKED, process: { ...SANDBOX_LOCAL_RESTRICTED_BLOCKED.process, max_processes: 8 } },
    workspaceRoots: [workspaceRoot],
    artifactRoot: path.join(workspaceRoot, 'artifacts'),
    secrets: {},
    now: '2026-09-25T00:00:00.000Z',
  });
  // The child records its own pids so the diagnostic can reap the tree
  // INDEPENDENTLY of the sandbox's own survivor list. Cleanup must never trust
  // the mechanism it is measuring: that list is exactly what is under test, and
  // by construction it can be incomplete.
  const pidFile = path.join(workspaceRoot, `pids-${settleMs}-${Date.now()}.txt`);
  const child = process.platform === 'win32'
    ? {
      command: 'cmd.exe',
      args: ['/d', '/s', '/c', `start /b cmd /c ping -n 60 127.0.0.1 >nul & ping -n 60 127.0.0.1 >nul & echo %cmdcmdline%`],
    }
    // POSIX equivalent: a backgrounded grandchild chain that outlives its parent,
    // each writing its own pid so cleanup does not depend on the sandbox.
    : {
      command: '/bin/sh',
      args: ['-c', `( sleep 120 & echo $! >> ${pidFile}; sleep 120 & echo $! >> ${pidFile}; wait )`],
    };
  let handle;
  try {
    handle = sandbox.startForControlProbe({ ...child, timeoutMs: 60000 });
  } catch (error) {
    return { ok: false, detail: String(error.message ?? error).slice(0, 120) };
  }
  await new Promise((r) => setTimeout(r, settleMs));
  let cancel;
  try {
    cancel = await Promise.race([
      sandbox.cancel(handle.pid),
      new Promise((r) => setTimeout(() => r({ timedOut: true }), 15000)),
    ]);
  } catch (error) {
    return { ok: false, detail: `cancel threw: ${String(error.message ?? error).slice(0, 120)}` };
  }
  if (cancel.timedOut === true) {
    return { ok: false, detail: 'cancel did not resolve within 15s' };
  }
  const survivors = Number(cancel.survivors ?? 0);
  const ids = Array.isArray(cancel.remainingProcessIds) ? cancel.remainingProcessIds.slice() : [];
  const reaped = reap(handle.pid, ids, pidFile);
  void handle.done;
  return {
    ok: true, survivors, ids, reaped, enumeration: cancel.enumeration ?? null, authoritative: cancel.authoritative ?? null,
  };
}

async function settleSweep() {
  console.log(`\n${'='.repeat(78)}\nSETTLE SWEEP — the same child, a different wait before cancel\n${'='.repeat(78)}`);
  const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 's2-002-sweep-'));
  const rows = [];
  try {
    for (const wait of sweepWaits) {
      const counts = [];
      const details = [];
      let lastReaped = { reaped: 0, extraBeyondSandboxList: 0 };
      for (let i = 0; i < sweepRepeats; i += 1) {
        const result = await probeOnce(wait, workspaceRoot);
        if (!result.ok) { details.push(`ERR:${result.detail}`); continue; }
        counts.push(result.survivors);
        details.push(`${result.enumeration ?? '?'} authoritative=${result.authoritative}`);
        if (result.survivors > 0 && i === 0) {
          details[details.length - 1] += ` leaked=${JSON.stringify(result.ids)}`;
        }
        lastReaped = result.reaped;
      }
      rows.push({ wait, counts, details, reaped: lastReaped });
    }
  } finally {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
  }
  console.log(`  wait(ms)   survivors per repeat      alive(indep)  enumeration`);
  for (const row of rows) {
    const alive = row.reaped?.actuallyAliveAfterCancel;
    console.log(`  ${String(row.wait).padStart(8)}   ${JSON.stringify(row.counts).padEnd(24)}  `
      + `${String(alive === undefined ? '?' : alive).padStart(12)}  ${row.details[0] ?? ''}`);
  }
  const worstAlive = Math.max(0, ...rows.map((r) => r.reaped?.actuallyAliveAfterCancel ?? 0));
  const worstReported = Math.max(0, ...rows.map((r) => Math.max(...(r.counts.length ? r.counts : [0]))));
  console.log(`\n  independently observed still-alive children (worst probe): ${worstAlive}`);
  console.log(`  survivors the sandbox reported      (worst probe): ${worstReported}`);
  if (worstAlive > worstReported) {
    console.log('    -> the sandbox UNDERCOUNTS survivors here. Its own count is not a proof, which is');
    console.log('       exactly what cancel()\'s authoritative:false declares.');
  } else {
    console.log('    -> the sandbox\'s own count matched what was independently observed alive.');
  }
  const nonZero = rows.filter((r) => r.counts.some((c) => c > 0));
  const zeroAtSomeWait = rows.some((r) => r.counts.every((c) => c === 0));
  console.log(`\n  waits leaving a survivor : ${nonZero.map((r) => r.wait).join(', ') || 'none'}`);
  console.log(`  waits with zero survivors : ${rows.filter((r) => r.counts.every((c) => c === 0)).map((r) => r.wait).join(', ') || 'none'}`);
  console.log('');
  if (nonZero.length === 0) {
    console.log('  VERDICT: no wait left a survivor on this host.');
  } else if (zeroAtSomeWait) {
    console.log('  VERDICT: the survivor depends on HOW LONG the trial waited. A longer wait finds');
    console.log('           nothing left, so the enumeration and the kill are correct and the fixed 500 ms');
    console.log('           settle in the S2-002 control is what misses the not-yet-materialised child.');
    console.log('           That is a property of the TRIAL, not of cancellation. Raising the settle is a');
    console.log('           change to the S2-002 control and belongs to that ticket; it is NOT a relaxation');
    console.log('           of the counter, and the hard counters keep failing until it is done honestly.');
  } else {
    console.log('  VERDICT: every wait left a survivor on this host. Cancellation does not reach the whole');
    console.log('           child chain here regardless of timing, which points at the host, not the settle.');
  }
  return rows;
}

const oracle = buildExpectedCorpusOracle();
console.log(`\noracle: ${oracle.trialCount} trials, digest ${oracle.digest}`);
console.log(`committed oracle digest: ${COMMITTED_ORACLE_DIGEST}`);
console.log(`oracle MATCHES the committed one: ${oracle.digest === COMMITTED_ORACLE_DIGEST ? 'yes' : 'NO — a finding'}`);

if (doSweep) {
  await settleSweep();
  if (!args.some((a) => a === '--repeat' || a === '--ab' || a === '--skip-corpus')) {
    const fingerprintAfterSweep = canonicalFingerprint();
    const intact = reportFingerprintChange(fingerprintBefore, fingerprintAfterSweep);
    console.log(`\ncanonical evidence unchanged by this diagnostic: ${intact ? 'YES' : 'NO'}`);
    process.exit(intact ? 0 : 1);
  }
}

const current = runCorpus('current', ROOT, 'diag-current');
if (current === null) {
  console.error('\nthe corpus run did not complete; nothing can be concluded');
  process.exit(1);
}
const results = [describe('CURRENT TREE (this commit)', current)];

if (repeatCount > 1) {
  // Distribution over N independent runs of the SAME tree on the SAME host.
  const series = [];
  for (let i = 0; i < repeatCount; i += 1) {
    const run = i === 0 ? current : runCorpus(`repeat-${i + 1}`, ROOT, `diag-repeat-${i + 1}`);
    if (run === null) continue;
    series.push({
      n: i + 1,
      escapes: run.summary.counters?.fs_network_secret_escapes ?? null,
      survivors: run.summary.counters?.survivors_after_cancellation ?? null,
      violations: run.summary.counters?.sandbox_control_violations ?? null,
      notRun: run.summary.counters?.not_run_controls ?? null,
      mismatched: run.observations.filter((o) => o.match === false).map((o) => `${o.trialId}=${o.observed}`),
    });
  }
  console.log(`\n${'='.repeat(78)}\nREPEAT ${series.length}x — same tree, same host\n${'='.repeat(78)}`);
  console.log('  run   escapes  survivors  violations  notRun  mismatched trials');
  for (const r of series) {
    console.log(`  ${String(r.n).padStart(3)}   ${String(r.escapes).padStart(7)}  ${String(r.survivors).padStart(9)}  `
      + `${String(r.violations).padStart(10)}  ${String(r.notRun).padStart(6)}  ${JSON.stringify(r.mismatched)}`);
  }
  const distinct = (key) => [...new Set(series.map((r) => JSON.stringify(r[key])))].sort();
  for (const key of ['escapes', 'survivors', 'violations']) {
    const values = distinct(key);
    const verdict = values.length === 1
      ? 'STABLE — a deterministic property of this host, not a timing artefact'
      : 'VARIES — timing-dependent; the committed evidence could have caught a lucky run';
    console.log(`\n  ${key.padEnd(10)} distinct values: ${values.join(', ')}\n             ${verdict}`);
  }
}

if (doAb) {
  // Build a throwaway copy of the tree with the three changed files restored to
  // their pre-change content, so the same host is measured both ways. The copy
  // is OUTSIDE the repository, so the canonical tree is never at risk.
  const abRoot = path.join(OUT, 'ab-tree');
  fs.rmSync(abRoot, { recursive: true, force: true });
  const tracked = gitOut('ls-files');
  for (const rel of tracked.stdout.split('\n').filter(Boolean)) {
    const dest = path.join(abRoot, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(ROOT, rel), dest);
  }
  let restored = 0;
  for (const rel of CHANGED_FILES) {
    const blob = gitOut('show', `${BASE_REF}:${rel}`);
    if (blob.status !== 0) {
      console.error(`  cannot read ${rel} at ${BASE_REF}: ${String(blob.stderr).split('\n')[0]}`);
      continue;
    }
    fs.writeFileSync(path.join(abRoot, rel), blob.stdout);
    restored += 1;
  }
  // The A/B copy needs its dependencies resolvable, or the runner cannot import
  // ajv/pg. Linking the installed tree is safe: the copy is outside the repo and
  // nothing is written through the link.
  const abModules = path.join(abRoot, 'node_modules');
  if (!fs.existsSync(abModules)) {
    try {
      fs.symlinkSync(path.join(ROOT, 'node_modules'), abModules, 'junction');
    } catch (error) {
      console.error(`  cannot link node_modules into the A/B tree: ${String(error.message).split('\n')[0]}`);
      console.error('  the A/B leg cannot run; the current-tree leg above is still complete');
    }
  }
  console.log(`\nA/B tree built at ${abRoot} (${restored}/${CHANGED_FILES.length} files restored to ${BASE_REF.slice(0, 7)})`);
  console.log(`node_modules resolvable: ${fs.existsSync(abModules) ? 'yes' : 'NO'}`);
  const ab = runCorpus('pre-change', abRoot, 'diag-pre-change');
  if (ab !== null) {
    results.push(describe(`PRE-CHANGE TREE (${BASE_REF.slice(0, 7)}) — same host`, ab));
  }
}

console.log(`\n${'='.repeat(78)}\nSIDE BY SIDE\n${'='.repeat(78)}`);
for (const [name, value] of results[0].counters ? Object.entries(results[0].counters) : []) {
  const other = results[1]?.counters?.[name];
  const verdict = other === undefined ? '—' : (JSON.stringify(value) === JSON.stringify(other) ? 'same' : 'DIFFERS');
  console.log(`  ${name.padEnd(32)} ${String(JSON.stringify(value)).padEnd(12)} pre-change=${String(JSON.stringify(other)).padEnd(12)} ${verdict}`);
}
console.log(`\n  mismatching trials, current : ${JSON.stringify(results[0].mismatches)}`);
if (results[1]) console.log(`  mismatching trials, pre-change: ${JSON.stringify(results[1].mismatches)}`);

const fingerprintAfter = canonicalFingerprint();
const intact = reportFingerprintChange(fingerprintBefore, fingerprintAfter);
console.log(`\ncanonical evidence unchanged by this diagnostic: ${intact ? 'YES' : 'NO'}`);
console.log('DIAGNOSTIC ONLY — this is not a pass verdict. A non-zero hard counter stays a finding.');
process.exit(intact ? 0 : 1);
