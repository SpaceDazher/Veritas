// S2-007 VERIFICATION AGGREGATOR (issue #7 §6; frozen module spec §4, §10).
//
// WHAT THIS SCRIPT IS NOT
// -----------------------
// It is not a wrapper that checks four exit codes. Exit code 0 from a gate that
// read a stale green file, wrote nothing and forgot to look at its own internal
// status is exactly the "fake green" this repository refuses to ship, so every
// mandatory gate here is judged on FOUR things at once:
//
//   1. the process really ran, in THIS invocation, and really exited 0;
//   2. the result artifact really exists AND is the bytes this invocation
//      produced (byte digest of the file == the digest the gate reported for
//      the file it just wrote), not a leftover from an earlier commit;
//   3. the artifact is FRESH: it is bound to the current HEAD commit (and to the
//      HEAD tree wherever the gate's frozen record format carries one), so a
//      record carried over from a previous commit cannot pass;
//   4. the artifact's INTERNAL status is the expected one: `hardGates.ok`,
//      `comparison.ok`, the internal `status`, the seven hard-gate counters and
//      the omit list. A file that merely EXISTS is never accepted.
//
// It also proves, on every run, that the gate set cannot be weakened:
//   * the frozen command set is compared against `package.json` and against a
//     second, literal copy of the mandatory gate ids, so deleting or renaming a
//     gate — or repointing an npm script at something weaker — is a defect;
//   * every evidence gate is re-classified against TAMPERED COPIES in a scratch
//     directory (stale commit, stale tree, non-zero counter, flipped
//     hardGates.ok, flipped comparison.ok, NOT_RUN_DB status, hand-written
//     "green" record, bytes that do not match the reported digest). If any
//     tampering is NOT detected, this run is REVISE and exits non-zero: a
//     checker that cannot see a doctored artifact is the defect.
//   * a mandatory gate that is skipped, or that reports NOT_RUN_DB, is proved
//     to flip the verdict to NOT_RUN instead of counting as a green replay.
//
// FRESHNESS MODEL (and its one documented asymmetry)
// HEAD commit equality is checked for every mandatory gate. HEAD tree equality
// is checked for every gate whose record carries a tree field (the security-probe
// gate does; the DB replay contract requires it to). The frozen
// `evidence/s2-007-dependency-binding.json` format has no HEAD-tree field, so
// for that ONE gate the commit binding is the anchor; it subsumes the tree for
// any committed change, and an UNCOMMITTED change is caught separately by the
// dirty-checkout check, which caps the verdict at PASS_WITH_LIMITS. A gate whose
// record carries no freshness anchor at all is NOT_RUN, never PASS: "I cannot
// prove it is fresh" is not "it is fine".
//
// DETERMINISM
// No wall clock in the record. The aggregator's own run id is a content address
// over (commit, tree, per-gate status, counter projection), so the same tree
// yields the same id and a changed tree cannot reuse the previous one.
//
// DESTRUCTION BOUNDARY
// This script writes exactly one file: `evidence/s2-007-summary.json`. It never
// edits another gate's evidence; the tamper matrix works on COPIES under
// `.bb/chats/<chat>/tmp/`.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
// The seven hard-gate counters come from the probe module itself, never from a
// second list written here: two lists would drift, and the drift would be a
// silently narrowed gate.
import { HARD_GATE_COUNTERS } from '../src/lib/agentboard/probes.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SUMMARY_RELATIVE = 'evidence/s2-007-summary.json';
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

// Exit codes of this aggregator. 0 means "the engineering boundary verified,
// with the limits named in the summary"; every other value means the ticket
// cannot be certified by this script and says so.
export const EXIT_VERIFIED = 0;
export const EXIT_NOT_VERIFIED = 1;

// ---------------------------------------------------------------------------
// The frozen gate set (issue #7 §6: verify:s2-007-dependencies, test:s2-007,
// test:s2-007-security-probes, verify:s2-007-db-replay, verify:s2-007).
// `script` is the EXACT package.json value; a changed value is a renamed gate.
// ---------------------------------------------------------------------------
export const EXPECTED_AGGREGATOR_SCRIPT = 'node scripts/verify-s2-007.mjs';
export const MANDATORY_GATE_IDS = Object.freeze(['dependencies', 'agentboard-tests', 'security-probes', 'db-replay']);

export const EXPECTED_GATES = Object.freeze([
  Object.freeze({
    id: 'dependencies',
    script: 'verify:s2-007-dependencies',
    scriptValue: 'node scripts/verify-s2-007-dependencies.mjs',
    command: 'npm run --silent verify:s2-007-dependencies',
    kind: 'json-stdout+file',
    entrypoint: 'scripts/verify-s2-007-dependencies.mjs',
    evidenceFiles: Object.freeze(['evidence/s2-007-dependency-binding.json']),
    // No tree field in the frozen record; see the FRESHNESS MODEL note above.
    commitPaths: Object.freeze(['resolved.resolvedRefs.implementationBaseCommit']),
    treePaths: Object.freeze([]),
    expectedStatus: 'PASS',
    carriesCounters: false,
    carriesComparison: false,
    timeoutMs: 1_800_000,
    contract: 'stdout JSON { ok:true, status:"PASS", mode:"FULL_GIT_BYTES" } + evidence/s2-007-dependency-binding.json whose resolved block was written by this run and is bound to the current HEAD commit',
  }),
  Object.freeze({
    id: 'agentboard-tests',
    script: 'test:s2-007',
    scriptValue: 'node --test --test-concurrency=1 "tests/agentboard/*.test.mjs"',
    command: 'npm run --silent test:s2-007',
    kind: 'subprocess-tap',
    entrypoint: 'tests/agentboard',
    evidenceFiles: Object.freeze([]),
    commitPaths: Object.freeze([]),
    treePaths: Object.freeze([]),
    expectedStatus: 'PASS',
    carriesCounters: false,
    carriesComparison: false,
    timeoutMs: 1_800_000,
    contract: 'node --test --test-concurrency=1 over tests/agentboard/*.test.mjs: exit 0, "# fail 0", a non-zero test count. This gate has no artifact by design, so its freshness is the fact that THIS aggregator spawned the process in THIS invocation and binds the output digest into this run id.',
  }),
  Object.freeze({
    id: 'security-probes',
    script: 'test:s2-007-security-probes',
    scriptValue: 'node scripts/s2-007-security-probes.mjs',
    command: 'npm run --silent test:s2-007-security-probes',
    kind: 'evidence-envelope',
    entrypoint: 'scripts/s2-007-security-probes.mjs',
    evidenceFiles: Object.freeze(['evidence/s2-007-security-probes.json']),
    commitPaths: Object.freeze(['commit']),
    treePaths: Object.freeze(['tree']),
    expectedStatus: 'PASS',
    carriesCounters: true,
    carriesComparison: false,
    timeoutMs: 1_800_000,
    // The gate binds its artifact only when it is asked to write it, and the
    // freshness contract below is "the bytes on disk are the bytes THIS
    // invocation produced". Both can only hold at once if the aggregator asks
    // for the write, which is exactly what the contract string names. Without
    // this the gate re-runs green, writes nothing, and the aggregator fails its
    // own freshness check on a stale file — a green run reported as FAIL.
    extraArgs: Object.freeze(['--write']),
    contract: 'scripts/s2-007-security-probes.mjs --write prints an envelope { status, ok, counters, hardGatesOk, evidenceFile, evidenceSha256, recordDigest, commit, tree } and writes the record it describes.',
  }),
  Object.freeze({
    id: 'db-replay',
    script: 'verify:s2-007-db-replay',
    scriptValue: 'node scripts/s2-007-db-replay.mjs',
    command: 'npm run --silent verify:s2-007-db-replay',
    kind: 'db-replay-report',
    entrypoint: 'scripts/s2-007-db-replay.mjs',
    // A small, DECLARED set of artifact names. Each candidate is still held to
    // the full freshness/status/digest contract, so accepting either name does
    // not weaken anything; what it avoids is this aggregator silently reading
    // nothing because the writer picked a different file name.
    evidenceFiles: Object.freeze(['evidence/s2-007-db-comparison.json', 'evidence/s2-007-db-replay.json']),
    // The DB replay record binds the tree under `git.commit_sha` / `git.tree_sha`
    // (the S2-006 record shape); the alternatives are listed so a future
    // flatter record still passes, and the requirement itself is unchanged: the
    // record must name THIS commit and THIS tree.
    commitPaths: Object.freeze(['commit', 'testedImplementationCommit', 'git.commit_sha']),
    treePaths: Object.freeze(['tree', 'git.tree_sha']),
    expectedStatus: 'PASS',
    carriesCounters: true,
    carriesComparison: true,
    timeoutMs: 1_800_000,
    contract: 'scripts/s2-007-db-replay.mjs prints its JSON report on stdout and writes the SAME report plus its exit code to the artifact; the aggregator requires the file to be deep-equal to {report, exitCode}, the report to carry { status:"PASS", ok:true, comparison.ok:true, hardGates.ok:true, crashPhase.ok:true, the seven zero counters } and the record to be bound to the current HEAD commit and tree.',
  }),
]);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
export function headIdentity(cwd = ROOT) {
  const one = (argv) => {
    try {
      return execFileSync('git', argv, { cwd, encoding: 'utf8' }).trim();
    } catch {
      return 'unavailable';
    }
  };
  return { commit: one(['rev-parse', 'HEAD']), tree: one(['rev-parse', 'HEAD^{tree}']) };
}

function gitLines(cwd, argv) {
  try {
    return execFileSync('git', argv, { cwd, encoding: 'utf8' }).split('\n').map((line) => line.trim()).filter((line) => line !== '');
  } catch {
    return [];
  }
}

/** Uncommitted work is not a HEAD tree, so it is detected separately and caps the verdict. */
export function workspaceState(cwd = ROOT) {
  const porcelain = gitLines(cwd, ['status', '--porcelain']);
  return {
    available: gitLines(cwd, ['rev-parse', '--git-dir']).length > 0,
    clean: porcelain.length === 0,
    changedPathCount: porcelain.length,
    changedPaths: porcelain.slice(0, 40).map((line) => line.slice(3)),
  };
}

export function sha256Of(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function readJsonFile(absolute) {
  try {
    return { bytes: fs.readFileSync(absolute), record: JSON.parse(fs.readFileSync(absolute, 'utf8')) };
  } catch {
    return { bytes: null, record: null };
  }
}

function at(record, dotPath) {
  return dotPath.split('.').reduce((value, key) => (value == null ? undefined : value[key]), record);
}

/**
 * A mandatory gate whose implementation file is not in this checkout is an
 * UNAVAILABLE mandatory tool, not a proven failure. Both are non-green, but the
 * distinction decides whether the ticket is REVISE (something is proven wrong)
 * or NOT_RUN (something is missing), and the issue asks for exactly that.
 */
function entrypointAbsent(gate) {
  return typeof gate.entrypoint === 'string' && !fs.existsSync(path.join(ROOT, gate.entrypoint));
}

function runProcess(command, { timeout, extraArgs = [] } = {}) {
  const usesShell = process.platform === 'win32' && NPM === 'npm.cmd';
  // `extraArgs` are handed to the GATE, never to npm: npm's own `--` separator
  // keeps `npm run verify:s2-007` and the gate it spawns distinguishable, and a
  // gate that must bind its artifact is invoked in exactly the mode its
  // contract string names (see the `security-probes` spec below).
  const passthrough = extraArgs.length > 0 ? ['--', ...extraArgs] : [];
  const result = spawnSync(
    usesShell ? 'cmd.exe' : NPM,
    usesShell
      ? ['/d', '/s', '/c', NPM, 'run', '--silent', command, ...passthrough]
      : ['run', '--silent', command, ...passthrough],
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 1 << 28, timeout, windowsHide: true },
  );
  return {
    exitCode: typeof result.status === 'number' ? result.status : null,
    signal: result.signal ?? null,
    timedOut: result.error?.code === 'ETIMEDOUT' || result.error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER',
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
  };
}

export function parseTapCounts(stdout) {
  const grab = (label) => {
    const match = stdout.match(new RegExp(`^# ${label} (\\d+)`, 'm'));
    return match ? Number(match[1]) : null;
  };
  return { tests: grab('tests'), pass: grab('pass'), fail: grab('fail'), skipped: grab('skipped') };
}

// ---------------------------------------------------------------------------
// The gate-set integrity check: no new result by renaming or repointing a gate
// ---------------------------------------------------------------------------
export function assertGateSetIntact({ packageScripts = {}, expectedGates = EXPECTED_GATES, mandatoryIds = MANDATORY_GATE_IDS, aggregatorScript = EXPECTED_AGGREGATOR_SCRIPT } = {}) {
  const issues = [];
  const expectedIds = expectedGates.map((gate) => gate.id);
  // (a) the expected set itself: a gate deleted from the source is a defect,
  //     so it is compared against a second literal list.
  if (JSON.stringify([...expectedIds].sort()) !== JSON.stringify([...mandatoryIds].sort())) {
    issues.push(`expected-gate-set:the frozen gate list is ${expectedIds.join(',')} but the mandatory set is ${mandatoryIds.join(',')} — a gate may not be removed from the aggregator`);
  }
  const seen = new Set();
  for (const id of expectedIds) {
    if (seen.has(id)) issues.push(`gate:${id}:duplicated`);
    seen.add(id);
  }
  // (b) the npm scripts: present, and byte-identical to the frozen command line.
  //     A different value is a repointed gate, which is exactly the "rename the
  //     gate to get a green status" move the ticket forbids.
  for (const gate of expectedGates) {
    const actual = packageScripts[gate.script];
    if (actual === undefined) issues.push(`script:${gate.script}:absent`);
    else if (actual !== gate.scriptValue) issues.push(`script:${gate.script}:repointed(${actual})`);
  }
  const aggregator = packageScripts['verify:s2-007'];
  if (aggregator === undefined) issues.push('script:verify:s2-007:absent');
  else if (aggregator !== aggregatorScript) issues.push(`script:verify:s2-007:repointed(${aggregator})`);
  return {
    ok: issues.length === 0,
    issues,
    expectedCommands: Object.fromEntries(expectedGates.map((gate) => [gate.id, gate.command])),
    observedCommands: Object.fromEntries(expectedGates.map((gate) => [gate.id, packageScripts[gate.script] ?? null])),
  };
}

// ---------------------------------------------------------------------------
// Classification of one gate
// ---------------------------------------------------------------------------

/**
 * The counter question of spec §4 for one record: are the seven counters
 * present AND exactly 0? A missing counter is a failure, not a pass — a gate
 * that stops reporting a counter must not look greener than one that reports a
 * finding.
 */
export function checkHardGateCounters(record, prefix = []) {
  const issues = [];
  const counters = {};
  for (const counter of HARD_GATE_COUNTERS) {
    const value = at(record, [...prefix, counter].join('.'));
    counters[counter] = typeof value === 'number' ? value : null;
    if (typeof value !== 'number') issues.push(`counter:${counter}:absent`);
    else if (value !== 0) issues.push(`counter:${counter}=${value}`);
  }
  return { ok: issues.length === 0, counters, issues };
}

/**
 * Classify a gate that produces an evidence artifact. Returns the acceptance
 * decision together with EVERY check it made, so the summary can show the
 * reasoning rather than a bare verdict.
 */
export function classifyEvidenceGate({ gate, envelope, run, bytes, record, head, before, relativeFile }) {
  const checks = [];
  const reasons = [];
  const freshnessBlock = () => ({
    evidenceFile: relativeFile ?? null,
    beforeSha256: before?.sha256 ?? null,
    afterSha256: bytes ? sha256Of(bytes) : null,
    rewritten: Boolean(bytes && before && before.sha256 !== sha256Of(bytes)),
    createdByThisRun: Boolean(bytes && before && before.sha256 !== sha256Of(bytes)),
    commitAnchor: head.commit,
    treeAnchor: head.tree,
  });
  const add = (id, ok, detail) => {
    checks.push({ check: id, ok, detail: detail === undefined ? null : String(detail).slice(0, 300) });
    if (!ok) reasons.push(`${id}${detail === undefined ? '' : `:${String(detail).slice(0, 200)}`}`);
    return ok;
  };
  const notRun = (id, detail) => {
    add(id, false, detail);
    return { status: 'NOT_RUN', reasons, checks, freshness: freshnessBlock() };
  };
  const fail = (id, detail) => {
    add(id, false, detail);
    return { status: 'FAIL', reasons, checks, freshness: freshnessBlock() };
  };

  // 1. the process really ran and really succeeded
  if (run.exitCode === null) return notRun('gate:process-did-not-report-an-exit-code', run.timedOut ? 'timed out' : 'killed by a signal');
  if (entrypointAbsent(gate)) return notRun('gate:implementation-absent', `${gate.entrypoint} is not in this checkout`);
  if (run.exitCode !== 0) return fail('gate:exit-code', `${run.exitCode}`);
  if (!bytes) return notRun('evidence:file-absent', relativeFile);
  if (!record) return fail('evidence:unparseable', relativeFile);
  if (!envelope) return notRun('evidence:no-envelope-from-the-gate', 'the gate printed no report, so this invocation cannot be bound to the artifact it wrote');

  // 2. the bytes on disk are the bytes this invocation produced
  add('freshness:byte-digest-matches-this-run',
    typeof envelope.evidenceSha256 === 'string' && envelope.evidenceSha256 === sha256Of(bytes),
    typeof envelope.evidenceSha256 === 'string' ? `file=${sha256Of(bytes).slice(0, 16)} reported=${envelope.evidenceSha256.slice(0, 16)}` : 'the gate reported no evidence digest');
  add('freshness:record-digest-matches-this-run',
    typeof envelope.recordDigest === 'string' && envelope.recordDigest === recordDigestOf(record),
    'the record content address must equal the one the gate reported');

  // 3. freshness: the record is bound to the CURRENT HEAD. Paths inside one
  //    anchor kind are ALTERNATIVES (a report may name the binding `commit` or
  //    `testedImplementationCommit`); the two kinds are not alternatives of each
  //    other, so a record with no tree field is caught by the tree anchor.
  const anchor = (kind, paths) => {
    if (paths.length === 0) return;
    const expected = kind === 'commit' ? head.commit : head.tree;
    const matched = paths.filter((dotPath) => at(record, dotPath) === expected);
    add(`freshness:${kind}-bound(${paths.join('|')})`, matched.length > 0,
      matched.length > 0 ? `via ${matched[0]}` : `${paths.map((dotPath) => `${dotPath}=${String(at(record, dotPath))}`).join(',')} != ${expected}`);
  };
  anchor('commit', gate.commitPaths);
  anchor('tree', gate.treePaths);
  if (gate.commitPaths.length === 0 && gate.treePaths.length === 0) {
    return notRun('freshness:no-anchor', `gate ${gate.id} carries no freshness anchor`);
  }

  // 4. the INTERNAL status, not the exit code
  const internalStatus = record.status ?? envelope.status ?? null;
  const notRunStatus = ['NOT_RUN', 'NOT_RUN_DB', 'NOT_MEASURED', 'NEEDS_INPUT'].includes(String(internalStatus));
  if (notRunStatus) {
    // A skip is never a pass. The check is recorded as FAILING so the reason
    // survives into the summary and the tamper matrix can see it.
    add('internal:status', false, `${internalStatus} != ${gate.expectedStatus}`);
    return { status: 'NOT_RUN', reasons, checks, freshness: freshnessBlock() };
  }
  add('internal:status', internalStatus === gate.expectedStatus, `${internalStatus} != ${gate.expectedStatus}`);
  // The record AND the gate's own report must both say ok. An OR here would let
  // a doctored record hide behind an untouched envelope, which is the exact
  // shape of artifact tampering the matrix below hunts for.
  if (record.ok !== undefined && envelope.ok !== undefined) add('internal:ok', record.ok === true && envelope.ok === true, `record.ok=${record.ok} envelope.ok=${envelope.ok}`);
  else if (record.ok !== undefined || envelope.ok !== undefined) add('internal:ok', (record.ok ?? envelope.ok) === true, `ok=${record.ok ?? envelope.ok}`);

  if (gate.carriesCounters) {
    add('hardGates:ok',
      record.hardGates?.ok === true && (envelope.hardGatesOk === undefined || envelope.hardGatesOk === true),
      `record.hardGates.ok=${record.hardGates?.ok} envelope.hardGatesOk=${envelope.hardGatesOk}`);
    const counters = checkHardGateCounters(record.counters ?? {});
    add('hardGates:counters-all-zero', counters.ok, counters.issues.join(','));
    if (record.hardGates?.counters) {
      const inner = checkHardGateCounters(record.hardGates.counters);
      add('hardGates:counters-agree-with-block', counters.ok && inner.ok, inner.issues.join(','));
    }
    const omits = record.omits ?? envelope.omits ?? [];
    add('honesty:no-unaccounted-omits', Array.isArray(omits) && omits.length === 0, `${Array.isArray(omits) ? omits.length : 'malformed'} omits`);
  }
  if (gate.carriesComparison) {
    add('comparison:ok', record.comparison?.ok === true, `comparison.ok=${record.comparison?.ok}`);
    if (record.crashPhase !== undefined) add('comparison:crash-phase-ok', record.crashPhase?.ok === true, `crashPhase.ok=${record.crashPhase?.ok}`);
  }

  const ok = reasons.length === 0;
  return { status: ok ? 'PASS' : 'FAIL', reasons, checks, counters: record.counters ?? null, freshness: freshnessBlock() };
}

/** The content address of a record, exactly as the gate computed it. */
export function recordDigestOf(record) {
  // The content address covers the WHOLE record except the address field
  // itself. `exitCode` is part of the record's meaning (`ok` is derived from
  // it), so excluding it would let a doctored exit code keep the same address;
  // the gate that produces the record and this aggregator's own summary both
  // digest everything-but-`recordDigest`, and the two have to agree or the
  // freshness check can never be satisfied by a truthful gate.
  const { recordDigest, ...rest } = record ?? {};
  return canonicalDigest(rest);
}

export function classifyJsonGate({ gate, run, bytes, record, head, before, relativeFile }) {
  const checks = [];
  const reasons = [];
  const tails = {
    stderrTail: String(run.stderr ?? '').slice(-1200) || null,
    stdoutTail: String(run.stdout ?? '').slice(-1200) || null,
  };
  const add = (id, ok, detail) => {
    checks.push({ check: id, ok, detail: detail === undefined ? null : String(detail).slice(0, 300) });
    if (!ok) reasons.push(`${id}${detail === undefined ? '' : `:${String(detail).slice(0, 200)}`}`);
  };
  const freshness = {
    evidenceFile: relativeFile ?? null,
    beforeSha256: before?.sha256 ?? null,
    afterSha256: bytes ? sha256Of(bytes) : null,
    rewritten: Boolean(bytes && before && before.sha256 !== sha256Of(bytes)),
    createdByThisRun: Boolean(bytes && before && before.sha256 !== sha256Of(bytes)),
    commitAnchor: head.commit,
    treeAnchor: head.tree,
  };
  if (run.exitCode === null) {
    add('gate:process-did-not-report-an-exit-code', false, run.timedOut ? 'timed out' : 'killed by a signal');
    return { status: 'NOT_RUN', reasons, checks, freshness, ...tails };
  }
  let report = null;
  try {
    report = JSON.parse(run.stdout);
  } catch {
    report = null;
  }
  if (entrypointAbsent(gate)) {
    add('gate:implementation-absent', false, `${gate.entrypoint} is not in this checkout`);
    return { status: 'NOT_RUN', reasons, checks, freshness, ...tails };
  }
  if (run.exitCode !== 0) {
    add('gate:exit-code', false, run.exitCode);
    // The gate's own words win over this script's guess: a dependency gate that
    // reports BLOCKED_DEPENDENCY is blocked, not "a failed check".
    if (report?.status === 'BLOCKED_DEPENDENCY') {
      add('internal:status', true, 'the gate reported BLOCKED_DEPENDENCY with its real exit code');
      return { status: 'BLOCKED_DEPENDENCY', reasons, checks, freshness, ...tails, reportedIssues: (report.issues ?? []).slice(0, 20) };
    }
    return { status: 'FAIL', reasons, checks, freshness, ...tails };
  }
  if (report === null) {
    add('internal:stdout-is-not-json', false, String(run.stdout).slice(0, 200));
    return { status: 'FAIL', reasons, checks, freshness, ...tails };
  }
  add('internal:ok', report.ok === true, `ok=${report.ok}`);
  add('internal:status', report.status === gate.expectedStatus, `${report.status} != ${gate.expectedStatus}`);
  if (report.mode !== undefined) add('internal:mode', report.mode === 'FULL_GIT_BYTES', `mode=${report.mode}`);
  if (!bytes) {
    add('evidence:file-absent', false, relativeFile);
    return { status: 'NOT_RUN', reasons, checks, freshness, ...tails };
  }
  if (!record) {
    add('evidence:unparseable', false, relativeFile);
    return { status: 'FAIL', reasons, checks, freshness, ...tails };
  }
  for (const dotPath of gate.commitPaths) {
    const value = at(record, dotPath);
    add(`freshness:commit-bound(${dotPath})`, value === head.commit, `${value} != ${head.commit}`);
  }
  for (const dotPath of gate.treePaths) {
    const value = at(record, dotPath);
    add(`freshness:tree-bound(${dotPath})`, value === head.tree, `${value} != ${head.tree}`);
  }
  add('freshness:resolved-block-written-by-this-run', record.resolved?.writtenOnGreenRunOnly === true, `writtenOnGreenRunOnly=${record.resolved?.writtenOnGreenRunOnly}`);
  const ok = reasons.length === 0;
  return { status: ok ? 'PASS' : 'FAIL', reasons, checks, freshness, ...tails };
}

export function classifyTapGate({ gate, run }) {
  const checks = [];
  const reasons = [];
  const add = (id, ok, detail) => {
    checks.push({ check: id, ok, detail: detail === undefined ? null : String(detail).slice(0, 300) });
    if (!ok) reasons.push(`${id}${detail === undefined ? '' : `:${String(detail).slice(0, 200)}`}`);
  };
  const tails = { stderrTail: String(run.stderr ?? '').slice(-1200) || null, stdoutTail: String(run.stdout ?? '').slice(-2000) || null };
  if (run.exitCode === null) {
    add('gate:process-did-not-report-an-exit-code', false, run.timedOut ? 'timed out' : 'killed by a signal');
    return { status: 'NOT_RUN', reasons, checks, freshness: { artifact: null, note: gate.contract }, ...tails };
  }
  if (entrypointAbsent(gate)) {
    add('gate:implementation-absent', false, `${gate.entrypoint} is not in this checkout`);
    return { status: 'NOT_RUN', reasons, checks, freshness: { artifact: null, note: gate.contract }, ...tails };
  }
  if (run.exitCode !== 0) {
    add('gate:exit-code', false, run.exitCode);
    return { status: 'FAIL', reasons, checks, freshness: { artifact: null, note: gate.contract }, ...tails };
  }
  const counts = parseTapCounts(run.stdout);
  add('internal:tap-summary-present', counts.tests !== null && counts.fail !== null, JSON.stringify(counts));
  add('internal:no-failing-tests', counts.fail === 0, `fail=${counts.fail}`);
  add('internal:tests-actually-ran', typeof counts.tests === 'number' && counts.tests > 0, `tests=${counts.tests}`);
  const ok = reasons.length === 0;
  return {
    status: ok ? 'PASS' : 'FAIL',
    reasons,
    checks,
    counts,
    freshness: {
      artifact: null,
      note: gate.contract,
      // This gate has no file: its freshness is structural. The aggregator
      // spawned the process itself in this invocation, and the digest of the
      // output it produced is bound into this run's id, so no pre-existing file
      // can stand in for it.
      boundToThisInvocation: true,
      stdoutSha256: createHash('sha256').update(run.stdout, 'utf8').digest('hex'),
    },
    ...tails,
  };
}

/**
 * The two-process DB replay gate. It reuses the S2-006 convention (issue §6
 * says the aggregator must not rely on the exit code alone): the gate prints
 * its report, writes that report plus its exit code, and the aggregator accepts
 * the file only when it is DEEP-EQUAL to `{report, exitCode}` of the process it
 * just ran, is bound to the current HEAD commit and tree, and its internal
 * status, comparison, hard gates and crash phase all say PASS.
 *
 * `NOT_RUN_DB` is explicitly NOT green: the issue states that skips and
 * NOT_RUN_DB on a mandatory DB gate are not a green replay.
 */
export function classifyDbReplayGate({ gate, run, bytes, record, head, before, relativeFile }) {
  const checks = [];
  const reasons = [];
  const tails = {
    stderrTail: String(run.stderr ?? '').slice(-1200) || null,
    stdoutTail: String(run.stdout ?? '').slice(-1500) || null,
  };
  const freshness = {
    evidenceFile: relativeFile ?? null,
    beforeSha256: before?.sha256 ?? null,
    afterSha256: bytes ? sha256Of(bytes) : null,
    rewritten: Boolean(bytes && before && before.sha256 !== sha256Of(bytes)),
    createdByThisRun: Boolean(bytes && before && before.sha256 !== sha256Of(bytes)),
    commitAnchor: head.commit,
    treeAnchor: head.tree,
    boundBy: 'the written file is deep-equal to {this run\'s stdout report, its exit code}',
  };
  const add = (id, ok, detail) => {
    checks.push({ check: id, ok, detail: detail === undefined ? null : String(detail).slice(0, 300) });
    if (!ok) reasons.push(`${id}${detail === undefined ? '' : `:${String(detail).slice(0, 200)}`}`);
  };
  const out = (status) => ({ status, reasons, checks, freshness, ...tails, counters: record?.hardGates?.counters ?? null });

  if (run.exitCode === null) {
    add('gate:process-did-not-report-an-exit-code', false, run.timedOut ? 'timed out' : 'killed by a signal');
    return out('NOT_RUN');
  }
  if (entrypointAbsent(gate)) {
    add('gate:implementation-absent', false, `${gate.entrypoint} is not in this checkout`);
    return out('NOT_RUN');
  }
  let observed = null;
  try {
    observed = JSON.parse(run.stdout);
  } catch {
    observed = null;
  }
  if (observed === null) {
    add('internal:stdout-is-not-json', false, String(run.stdout).slice(0, 200));
    return run.exitCode === 0 ? out('FAIL') : out('FAIL');
  }
  if (!bytes) {
    add('evidence:file-absent', false, relativeFile);
    return out('NOT_RUN');
  }
  if (!record) {
    add('evidence:unparseable', false, relativeFile);
    return out('FAIL');
  }
  add('freshness:file-is-this-runs-report',
    isDeepStrictEqual(record, { ...observed, exitCode: run.exitCode }),
    'the artifact must be exactly the report this process printed, plus its exit code');
  if (run.exitCode !== 0) {
    add('gate:exit-code', false, run.exitCode);
  }
  const anchor = (kind, paths) => {
    if (paths.length === 0) return;
    const expected = kind === 'commit' ? head.commit : head.tree;
    const matched = paths.filter((dotPath) => at(record, dotPath) === expected);
    add(`freshness:${kind}-bound(${paths.join('|')})`, matched.length > 0,
      matched.length > 0 ? `via ${matched[0]}` : `${paths.map((dotPath) => `${dotPath}=${String(at(record, dotPath))}`).join(',')} != ${expected}`);
  };
  anchor('commit', gate.commitPaths);
  anchor('tree', gate.treePaths);

  const internalStatus = record.status ?? observed.status ?? null;
  if (['NOT_RUN_DB', 'NOT_RUN', 'NEEDS_INPUT'].includes(String(internalStatus))) {
    add('internal:status', false, `${internalStatus} != ${gate.expectedStatus}`);
    return out('NOT_RUN');
  }
  add('internal:status', internalStatus === gate.expectedStatus, `${internalStatus} != ${gate.expectedStatus}`);
  add('internal:ok', record.ok === true && observed.ok === true, `record.ok=${record.ok} report.ok=${observed.ok}`);
  add('comparison:ok', record.comparison?.ok === true, `comparison.ok=${record.comparison?.ok}`);
  add('hardGates:ok', record.hardGates?.ok === true, `hardGates.ok=${record.hardGates?.ok}`);
  if (record.crashPhase !== undefined) add('comparison:crash-phase-ok', record.crashPhase?.ok === true, `crashPhase.ok=${record.crashPhase?.ok}`);
  const counters = checkHardGateCounters(record.hardGates?.counters ?? record.counters ?? {});
  add('hardGates:counters-all-zero', counters.ok, counters.issues.join(','));
  return out(reasons.length === 0 ? 'PASS' : 'FAIL');
}

// ---------------------------------------------------------------------------
// The tamper matrix: prove this aggregator rejects a doctored artifact
// ---------------------------------------------------------------------------
export const TAMPER_VARIANTS = Object.freeze([
  { id: 'stale-commit', requires: 'commitAnchor', kind: 'evidence-envelope', mutate: (record) => ({ ...record, commit: '0'.repeat(40) }), expect: 'freshness:commit-bound' },
  { id: 'stale-tree', requires: 'treeAnchor', kind: 'evidence-envelope', mutate: (record) => ({ ...record, tree: '0'.repeat(64) }), expect: 'freshness:tree-bound' },
  { id: 'counter-nonzero', requires: 'counters', kind: 'evidence-envelope', mutate: (record) => ({ ...record, counters: { ...(record.counters ?? {}), duplicateExternalEffects: 1 } }), expect: 'hardGates:counters-all-zero' },
  { id: 'hardgates-flipped', requires: 'hardGates', kind: 'evidence-envelope', mutate: (record) => ({ ...record, hardGates: { ...(record.hardGates ?? {}), ok: false } }), expect: 'hardGates:ok' },
  { id: 'comparison-flipped', requires: 'comparison', kind: 'evidence-envelope', mutate: (record) => ({ ...record, comparison: { ...(record.comparison ?? {}), ok: false } }), expect: 'comparison:ok' },
  { id: 'status-not-run-db', requires: 'any', kind: 'evidence-envelope', mutate: (record) => ({ ...record, status: 'NOT_RUN_DB', ok: false }), expect: 'internal:status' },
  { id: 'hand-written-green', requires: 'any', kind: 'evidence-envelope', mutate: () => ({ schemaVersion: 1, ticket: 'S2-007', status: 'PASS', ok: true, counters: Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0])), hardGates: { ok: true }, commit: 'x', tree: 'y' }), expect: 'freshness:byte-digest-matches-this-run' },
  { id: 'omits-hidden', requires: 'counters', kind: 'evidence-envelope', mutate: (record) => ({ ...record, omits: [{ probe: 'two_process_claim_race', code: 'NOT_RUN_DB' }] }), expect: 'honesty:no-unaccounted-omits' },
  // The DB replay artifact is bound by deep equality with the report the
  // process printed, so ANY edit to the file is the detection: the variants
  // below each prove that specific edit is caught.
  { id: 'db-stale-commit', requires: 'any', kind: 'db-replay-report', mutate: (record) => ({ ...record, git: { ...(record.git ?? {}), commit_sha: '0'.repeat(40) } }), expect: 'freshness:file-is-this-runs-report' },
  { id: 'db-stale-tree', requires: 'any', kind: 'db-replay-report', mutate: (record) => ({ ...record, git: { ...(record.git ?? {}), tree_sha: '0'.repeat(64) } }), expect: 'freshness:file-is-this-runs-report' },
  { id: 'db-counter-nonzero', requires: 'any', kind: 'db-replay-report', mutate: (record) => ({ ...record, hardGates: { ...(record.hardGates ?? {}), counters: { ...(record.hardGates?.counters ?? {}), falseApprovals: 1 } } }), expect: 'freshness:file-is-this-runs-report' },
  { id: 'db-status-not-run-db', requires: 'any', kind: 'db-replay-report', mutate: (record) => ({ ...record, status: 'NOT_RUN_DB', ok: false }), expect: 'internal:status' },
  { id: 'db-crash-phase-faked', requires: 'any', kind: 'db-replay-report', mutate: (record) => ({ ...record, crashPhase: { ok: true }, status: 'PASS', ok: true }), expect: 'freshness:file-is-this-runs-report' },
  // The dependency gate prints its report on stdout and writes the resolved
  // block to a file; the file is bound to HEAD through the implementation base
  // commit it names. A doctored binding must not be able to say "verified".
  { id: 'dep-stale-commit', requires: 'commitAnchor', kind: 'json-stdout+file', mutate: (record) => ({ ...record, resolved: { ...(record.resolved ?? {}), resolvedRefs: { ...(record.resolved?.resolvedRefs ?? {}), implementationBaseCommit: '0'.repeat(40) } } }), expect: 'freshness:commit-bound' },
  { id: 'dep-resolved-block-faked', requires: 'any', kind: 'json-stdout+file', mutate: (record) => ({ ...record, resolved: { ...(record.resolved ?? {}), writtenOnGreenRunOnly: false } }), expect: 'freshness:resolved-block-written-by-this-run' },
  { id: 'dep-hand-written-green', requires: 'any', kind: 'json-stdout+file', mutate: () => ({ schemaVersion: 1, ticket: 'S2-007', resolved: { ok: true, resolvedRefs: { implementationBaseCommit: 'x' } } }), expect: 'freshness:resolved-block-written-by-this-run' },
]);

/** The DB replay artifact is `{report, exitCode}`; the report is the artifact without it. */
export function stripExitCode(record) {
  const { exitCode, ...rest } = record ?? {};
  return rest;
}

/**
 * The stand-in "report a run printed" for the DB replay negative control.
 *
 * The DB replay artifact is accepted only by DEEP EQUALITY with the report the
 * process printed, so the only way to test that binding is to hand the
 * classifier a report. Using the real one would be the weaker test: when the
 * real gate is already red, every variant would "pass" for the wrong reason.
 * A forged green report is the STRONGER control — a doctored file must still be
 * rejected while a perfectly green, HEAD-bound report sits in stdout.
 */
export function forgedGreenDbReport(record, head) {
  return {
    ...(record ?? {}),
    status: 'PASS',
    ok: true,
    reason: null,
    stack: null,
    comparison: { ok: true, issues: [] },
    hardGates: { ok: true, counters: Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0])), violations: [] },
    crashPhase: { ok: true },
    git: { ...(record?.git ?? {}), commit_sha: head.commit, tree_sha: head.tree },
  };
}

/**
 * Re-classify every evidence gate against tampered COPIES. `expectedOutcome` is
 * what the classifier must answer: NOT green. A variant that comes back PASS is
 * a hole in the aggregator and fails the whole run.
 */
export function runTamperMatrix({ gates, head, scratchDir }) {
  const results = [];
  const skipped = [];
  for (const gate of gates) {
    const kind = gate.spec?.kind ?? null;
    const isEvidence = kind === 'evidence-envelope';
    const isDbReport = kind === 'db-replay-report';
    const isJsonReport = kind === 'json-stdout+file';
    if (!isEvidence && !isDbReport && !isJsonReport) {
      // Named, not implied: a gate shape with no artifact has nothing to
      // tamper with, and saying so is what keeps the matrix honest about its
      // own coverage.
      skipped.push(`${gate.id}: the ${kind ?? 'unknown'} gate shape writes no artifact, so there is nothing to doctor`);
      continue;
    }
    // The evidence shape needs BOTH halves of the binding (the envelope the
    // process printed and the file it wrote). The other two shapes bind the
    // file against the report on stdout instead, so requiring an envelope here
    // would have silently dropped the DB-replay and dependency gates out of
    // the matrix — a gate that stops being checked is a gate that stops being
    // a control.
    const missing = isEvidence
      ? (!gate.envelope ? 'the gate printed no report envelope' : null)
      : (!gate.record ? 'the gate produced no evidence artifact in this verification' : null);
    if (missing) {
      skipped.push(`${gate.id}: ${missing}`);
      continue;
    }
    if (isJsonReport && typeof gate.runStdout !== 'string') {
      skipped.push(`${gate.id}: the gate's stdout report was not captured, so no copy of it can be replayed against a doctored file`);
      continue;
    }
    // The BASELINE: the genuine, un-tampered file re-classified with the REAL
    // inputs. Only a gate whose genuine artifact this aggregator ACCEPTS can
    // demonstrate that a doctored copy flips it to rejected; when the genuine
    // artifact is already red (the common case in a failing run) the variants
    // are still executed and still must not pass, but they are reported as
    // non-strong rather than counted as a proven flip.
    //
    // The TAMPERED classification deliberately does NOT reuse those inputs: for
    // the DB replay shape it is handed a FORGED GREEN, HEAD-bound report, so
    // the doctored file has to be rejected while the most favourable report
    // anybody could print sits in stdout. That is strictly harder to pass than
    // replaying the real (possibly red) run.
    const classify = (bytes, record, { forged } = {}) => {
      if (isDbReport) {
        const observed = forged ? forgedGreenDbReport(gate.record, head) : stripExitCode(gate.record);
        return classifyDbReplayGate({
          gate: gate.spec,
          run: { exitCode: forged ? 0 : (gate.exitCode ?? 0), stdout: JSON.stringify(observed, null, 2), stderr: '' },
          bytes, record, head,
          before: { sha256: gate.freshness?.afterSha256 ?? null },
          relativeFile: gate.freshness?.evidenceFile ?? null,
        });
      }
      if (isJsonReport) {
        return classifyJsonGate({
          gate: gate.spec,
          run: { exitCode: 0, timedOut: false, stdout: gate.runStdout, stderr: '' },
          bytes, record, head,
          before: { sha256: gate.freshness?.afterSha256 ?? null },
          relativeFile: gate.freshness?.evidenceFile ?? null,
        });
      }
      return classifyEvidenceGate({
        gate: gate.spec,
        envelope: gate.envelope,
        run: { exitCode: 0, timedOut: false },
        bytes, record, head,
        before: { sha256: gate.freshness?.afterSha256 ?? null },
        relativeFile: gate.freshness?.evidenceFile ?? null,
      });
    };
    const baseline = classify(Buffer.from(`${JSON.stringify(gate.record, null, 2)}\n`, 'utf8'), gate.record);
    const capabilities = {
      commitAnchor: gate.spec.commitPaths.length > 0,
      treeAnchor: gate.spec.treePaths.length > 0,
      counters: gate.spec.carriesCounters === true,
      hardGates: gate.spec.carriesCounters === true,
      comparison: gate.spec.carriesComparison === true,
      any: true,
    };
    for (const variant of TAMPER_VARIANTS) {
      if (variant.kind !== gate.spec.kind) {
        skipped.push(`${gate.id}/${variant.id}: the variant targets the ${variant.kind} gate shape`);
        continue;
      }
      if (capabilities[variant.requires] !== true) {
        skipped.push(`${gate.id}/${variant.id}: the gate does not carry this field, so the variant is not applicable`);
        continue;
      }
      const tamperedRecord = variant.mutate(gate.record);
      const tamperedBytes = Buffer.from(`${JSON.stringify(tamperedRecord, null, 2)}\n`, 'utf8');
      const file = path.join(scratchDir, `${gate.id}--${variant.id}.json`);
      fs.mkdirSync(scratchDir, { recursive: true });
      fs.writeFileSync(file, tamperedBytes);
      const readBack = readJsonFile(file);
      const classified = classify(readBack.bytes, readBack.record, { forged: true });
      const detected = classified.status !== 'PASS' && classified.checks.some((check) => !check.ok && check.check.startsWith(variant.expect));
      results.push({
        gate: gate.id,
        variant: variant.id,
        expectedCheck: variant.expect,
        classifierStatus: classified.status,
        detected,
        // `strong` means the control proved what it exists to prove: the
        // genuine artifact was accepted and the doctored copy of it was not.
        baselineStatus: baseline.status,
        strong: detected && baseline.status === 'PASS',
        firstReason: classified.reasons[0] ?? null,
        scratchFile: path.relative(ROOT, file).split(path.sep).join('/'),
      });
    }
  }
  const undetected = results.filter((row) => !row.detected);
  return {
    ok: undetected.length === 0 && results.length > 0,
    checked: results.length,
    // How many of the controls were STRONG: a genuine artifact this aggregator
    // accepted, whose doctored copy it then rejected. Reported so a reader can
    // see how much of the matrix was a real proof and how much was only a
    // "still rejected" check on an already-red gate.
    strong: results.filter((row) => row.strong === true).length,
    undetected: undetected.map((row) => `${row.gate}/${row.variant}`),
    skipped,
    results,
  };
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/**
 * Outcome precedence, derived from the observations and never from a constant:
 *
 *   1. a critical defect (a hard-gate counter finding, a failed mandatory gate,
 *      a tampering that was NOT detected, a gate that was renamed or
 *      repointed, a tracked artifact of this ticket that still reports a
 *      failure)  -> REVISE
 *   2. the dependency gate is blocked                        -> BLOCKED_DEPENDENCY
 *   3. a mandatory gate could not run, or a mandatory probe was skipped /
 *      NOT_RUN_DB                                                  -> NOT_RUN
 *   4. every mandatory gate is green but not in a clean checkout -> PASS_WITH_LIMITS
 *   5. every mandatory gate is green in a clean checkout          -> COMPLETE_WITH_LIMITS
 *
 * The ceiling is COMPLETE_WITH_LIMITS and it is unreachable while any of the
 * above holds. `assuranceStatus` is a separate, deliberately narrow axis: no
 * engineering evidence in this repository can move it off NOT_MEASURED, because
 * a real adapter, a human review and an empirical semantic accuracy are not
 * things a synthetic or replay run can produce.
 */
export function deriveVerdict({ gates = [], gateCommands = null, counterSources = [], tamperChecks = null, selfChecks = null, checkout = null, observations = [] } = {}) {
  const defects = [];
  const blocked = [];
  const notRun = [];
  const byId = Object.fromEntries(gates.map((gate) => [gate.id, gate]));

  for (const source of counterSources) {
    if (source.bound !== true) continue;
    const findings = HARD_GATE_COUNTERS.filter((counter) => Number(source.counters?.[counter]) !== 0);
    if (source.allZero !== true && findings.length > 0) {
      defects.push(`hard-gate counters are not zero in ${source.source}: ${findings.map((counter) => `${counter}=${source.counters[counter]}`).join(', ')}`);
    }
  }

  for (const id of MANDATORY_GATE_IDS) {
    const gate = byId[id];
    if (!gate) {
      notRun.push(`mandatory gate ${id} was not evaluated`);
      continue;
    }
    if (gate.status === 'PASS') continue;
    const reason = `mandatory gate ${id} is ${gate.status}: ${(gate.reasons ?? []).slice(0, 3).join('; ') || 'no reason recorded'}`;
    if (gate.status === 'NOT_RUN') notRun.push(reason);
    else if (gate.status === 'BLOCKED_DEPENDENCY') blocked.push(reason);
    else defects.push(reason);
  }

  if (gateCommands && gateCommands.ok !== true) {
    const renamed = gateCommands.issues.filter((issue) => issue.includes('repointed') || issue.includes('removed') || issue.includes('duplicated'));
    if (renamed.length > 0) defects.push(`the mandatory gate set was altered: ${renamed.join('; ')}`);
    else notRun.push(`a mandatory npm script is absent: ${gateCommands.issues.join('; ')}`);
  }
  if (tamperChecks && tamperChecks.ok !== true) {
    defects.push(`the aggregator accepted a tampered artifact for: ${tamperChecks.undetected.join(', ')}`);
  }
  if (selfChecks && selfChecks.ok !== true) {
    defects.push(`the aggregator's own negative controls failed: ${(selfChecks.failures ?? []).join('; ')}`);
  }
  for (const observation of observations) {
    if (observation.blocksCompletion !== true) continue;
    defects.push(`${observation.name} is not refreshed for this tree and reports ${observation.status ?? 'an unknown status'}: ${observation.why}`);
  }

  const allGreen = MANDATORY_GATE_IDS.every((id) => byId[id]?.status === 'PASS');
  const clean = checkout?.clean === true;

  let engineeringStatus;
  if (defects.length > 0) {
    engineeringStatus = 'REVISE';
  } else if (blocked.length > 0) {
    engineeringStatus = 'BLOCKED_DEPENDENCY';
  } else if (notRun.length > 0) {
    engineeringStatus = 'NOT_RUN';
  } else if (allGreen && clean) {
    engineeringStatus = 'COMPLETE_WITH_LIMITS';
  } else if (allGreen) {
    engineeringStatus = 'PASS_WITH_LIMITS';
  } else {
    engineeringStatus = 'REVISE';
  }

  const verdictReasons = [...defects.map((r) => `[REVISE] ${r}`), ...blocked.map((r) => `[BLOCKED_DEPENDENCY] ${r}`), ...notRun.map((r) => `[NOT_RUN] ${r}`)];
  if (verdictReasons.length === 0) {
    verdictReasons.push(clean
      ? 'every mandatory engineering gate is PASS in this clean checkout and no critical defect was found; the ceiling is still COMPLETE_WITH_LIMITS, which is NOT an A-MVP PASS and NOT production readiness'
      : `every mandatory engineering gate is PASS, but the checkout is not clean (${checkout?.changedPathCount} changed paths), so COMPLETE_WITH_LIMITS is not claimed`);
  }
  return {
    engineeringStatus,
    assuranceStatus: 'NOT_MEASURED',
    assuranceCeiling: 'NOT_MEASURED is the honest status and no evidence produced by this ticket can move it: a real installed adapter, an authenticated human review and an empirical semantic accuracy are not derivable from a synthetic or replay run.',
    notInferred: ['real_adapter_execution', 'human_review', 'empirical_semantic_accuracy', 'A_MVP_PASS', 'production_readiness'],
    verdictReasons,
    buckets: { defects, blocked, notRun },
  };
}

/** exitCode for a verdict. Anything short of a fully green, clean-checkout run is non-zero. */
export function exitCodeForVerdict(verdict) {
  return verdict.engineeringStatus === 'COMPLETE_WITH_LIMITS' || verdict.engineeringStatus === 'PASS_WITH_LIMITS'
    ? EXIT_VERIFIED
    : EXIT_NOT_VERIFIED;
}

// ---------------------------------------------------------------------------
// Observations that are read, not re-run, and the A-MVP honesty block
// ---------------------------------------------------------------------------
function observationForComparison(record, head) {
  if (!record) {
    return { name: 'offline two-run comparison (evidence/s2-007-comparison.json)', present: false, bound: false, status: 'ABSENT', blocksCompletion: true, why: 'the artifact does not exist; run scripts/s2-007-run.mjs' };
  }
  const commit = record.commit ?? record.testedImplementationCommit ?? null;
  const bound = commit === head.commit && (record.tree === undefined || record.tree === head.tree);
  const ok = record.ok === true && (record.comparison?.ok ?? true) === true;
  const counters = record.hardGates?.counters ?? null;
  const counterFindings = counters ? HARD_GATE_COUNTERS.filter((counter) => Number(counters[counter]) !== 0) : [];
  return {
    name: 'offline two-run comparison (evidence/s2-007-comparison.json)',
    present: true,
    bound,
    boundTo: { commit, tree: record.tree ?? null },
    status: record.status ?? null,
    ok,
    counters,
    counterFindings,
    // A tracked artifact of THIS ticket that still reports a failure blocks
    // COMPLETE_WITH_LIMITS until it is regenerated against the current tree,
    // even when a fresh re-run says otherwise: an aggregator may not certify
    // over an evidence file that contradicts it.
    blocksCompletion: !ok || counterFindings.length > 0,
    why: ok && bound
      ? 'none'
      : `ok=${record.ok} status=${record.status} counterFindings=${counterFindings.join(',') || 'none'} commitBound=${bound} — regenerate with scripts/s2-007-run.mjs`,
  };
}

function aMvpBlock(head, gates) {
  let cases = [];
  try {
    const declared = JSON.parse(fs.readFileSync(path.join(ROOT, 'pilots/scenario-a/acceptance-cases.json'), 'utf8'));
    cases = (declared.cases ?? []).filter((row) => String(row.id).startsWith('A-MVP'));
  } catch {
    return { status: 'NOT_RUN', source: null, cases: [], note: 'pilots/scenario-a/acceptance-cases.json is unreadable, so no A-MVP case can be reported honestly' };
  }
  const probesGreen = gates.find((gate) => gate.id === 'security-probes')?.status === 'PASS';
  const dbGreen = gates.find((gate) => gate.id === 'db-replay')?.status === 'PASS';
  return {
    status: 'NOT_RUN',
    source: 'pilots/scenario-a/acceptance-cases.json (execution: NOT_RUN for every A-MVP case)',
    cases: cases.map((row) => ({
      id: row.id,
      execution: row.execution,
      expected: row.expected,
      engineeringEvidence: {
        'A-MVP-01': 'NOT_RUN: the veritas.adapter/1.0.0 interface and the NOT_RUN_REAL_ADAPTER probe are engineering evidence about the boundary, not two distinct installed executors',
        'A-MVP-02': 'NOT_RUN: no generic-CLI discovery run and no second approved agent exist on this host',
        'A-MVP-03': `NOT_RUN as an A-MVP case. The offline two-run comparison exercises the deterministic selection order${probesGreen ? ' and the probe suite is green' : ''}, but it drives a test transport, not an approved runtime`,
        'A-MVP-04': 'NOT_RUN: cancel/timeout/fence handling is proven against the boundary; process-group termination for the selected OS/sandbox is not proven here (S2-002 process-tree limits apply)',
        'A-MVP-05': 'NOT_RUN: no authenticated human performed a change→claim→execute→review→approve cycle in this verification',
        'A-MVP-06': `NOT_RUN as an A-MVP case. The two-process claim race ran for real on a disposable PostgreSQL in this verification (probe two_process_claim_race, security-probes gate ${probesGreen ? 'PASS' : 'NOT GREEN'}), but no real adapter executed the claim and no independent human observed it`,
        'A-MVP-07': `NOT_RUN as an A-MVP case. Idempotent dispatch and crash/restart recovery are covered by the probe families${dbGreen ? ' and a green DB replay' : ''}, against a disposable database and a scripted transport`,
      }[row.id] ?? 'NOT_RUN',
      whyNotClaimed: 'a real installed executor, an authenticated human reviewer and an authorized budget are prerequisites of every A-MVP case; none exists in this repository or on this host',
    })),
    note: 'A-MVP stays NOT_RUN. Engineering fixture/replay evidence never upgrades it (issue #7, spec rule 8).',
    headCommit: head.commit,
  };
}

// ---------------------------------------------------------------------------
// The criterion -> observation -> evidence matrix (issue #7 §6)
// ---------------------------------------------------------------------------
function buildMatrix({ gates, counterSources, tamperChecks, selfChecks, checkout, comparison, aMvp, verdict, gateCommands }) {
  const gate = (id) => gates.find((row) => row.id === id) ?? null;
  const statusOf = (id) => gate(id)?.status ?? 'NOT_EVALUATED';
  const exitOf = (id) => gate(id)?.exitCode ?? null;
  const row = (criterion, requirement, observation, evidence, status) => ({ criterion, requirement, observation, evidence, status });
  return [
    row('C1 dependency binding', 'issue §1: an upstream binding is verified before any implementation; a missing binding is BLOCKED_DEPENDENCY',
      `dependency gate ${statusOf('dependencies')} (exit ${exitOf('dependencies')}); the binding record is bound to HEAD commit ${checkout?.head?.commit ?? 'n/a'}`,
      'evidence/s2-007-dependency-binding.json', statusOf('dependencies')),
    row('C2 one authoritative contract', 'issue §2: wire shapes live only in contracts/*.schema.json and are validated only through contracts.mjs',
      'not re-measured by this aggregator: the contract registry, its schema set and the generated types are covered by the test gate and the dependency gate; the aggregator does not restate the schemas',
      'contracts/*.schema.json, src/lib/agentboard/contracts.mjs, tests/agentboard/contracts.test.mjs', statusOf('agentboard-tests')),
    row('C3 canonical board and rights', 'issue §3: nine states, only the allowed transitions, one lease, server-side actor re-check, idempotent writes, journal+outbox in one transaction',
      `test gate ${statusOf('agentboard-tests')} (exit ${exitOf('agentboard-tests')}) over transitions, ACL, idempotency, lease and recovery tests`,
      'tests/agentboard/*.test.mjs', statusOf('agentboard-tests')),
    row('C4 scheduler, leases, handoff', 'issue §4: deterministic selection, DB time, compare-and-swap, monotonic fence, idempotent outbox, no blind retry',
      `probe families concurrent_claim + idempotency_and_crash ${statusOf('security-probes')}; DB replay ${statusOf('db-replay')}`,
      'evidence/s2-007-security-probes.json, evidence/s2-007-comparison.json', statusOf('security-probes') === 'PASS' && statusOf('db-replay') === 'PASS' ? 'PASS' : 'LIMITED'),
    row('C5 mandatory negative probes', 'issue §5: six families through the production-facing path and seven hard gates at 0',
      `security-probe gate ${statusOf('security-probes')} (exit ${exitOf('security-probes')}); counters ${JSON.stringify(counterSources.find((source) => source.source === 'evidence/s2-007-security-probes.json')?.counters ?? {})}`,
      'evidence/s2-007-security-probes.json', statusOf('security-probes')),
    row('C6 two-process DB replay', 'issue §6: two process-separated executors on ephemeral PostgreSQL, canonical digests compared, hard gates and crash/restart phase; two identically wrong runs are not a PASS',
      `db-replay gate ${statusOf('db-replay')} (exit ${exitOf('db-replay')})`,
      'evidence/s2-007-db-comparison.json', statusOf('db-replay')),
    row('C7 freshness of the result', 'issue §6: the aggregator checks freshness, hardGates.ok, comparison.ok and the internal status, not only the exit code or an existing evidence file',
      `every evidence gate was re-run in this invocation and re-classified against ${tamperChecks?.checked ?? 0} tampered copies; undetected tampering: ${(tamperChecks?.undetected ?? []).join(', ') || 'none'}; ${tamperChecks?.strong ?? 0} of them were STRONG controls (a genuine artifact this aggregator accepted, whose doctored copy it rejected)${(tamperChecks?.strong ?? 0) === 0 ? ' — no strong control in this run, because every genuine artifact was already red, so the matrix proved "a doctored copy is still refused" and not "a flip from accepted to rejected"' : ''}`,
      'evidence/s2-007-summary.json (gates[].checks, tamperChecks)', tamperChecks?.ok === true ? 'PASS' : 'FAIL'),
    row('C8 no gate renaming', 'issue §6: a gate may not be renamed to obtain a green status',
      `the frozen command set is compared with package.json and with a second literal gate list: ${gateCommands?.ok === true ? 'intact' : `issues: ${(gateCommands?.issues ?? []).join('; ')}`}`,
      'evidence/s2-007-summary.json (gateCommands)', selfChecks?.gateSetOk === true ? 'PASS' : 'FAIL'),
    row('C9 honest A-MVP status', 'issue §6: NOT_RUN cases, real exit codes and residual limits are reported; no A-MVP or assurance claim is inferred',
      `A-MVP status ${aMvp.status}: ${aMvp.cases.length} cases, all execution NOT_RUN; assuranceStatus ${verdict.assuranceStatus}`,
      'pilots/scenario-a/acceptance-cases.json, evidence/s2-007-summary.json', 'PASS'),
    row('C10 tracked evidence consistency', 'issue §6: results are bound to commit/tree SHA and raw run IDs',
      `offline comparison artifact: status ${comparison.status}, bound=${comparison.bound}, ok=${comparison.ok}`,
      'evidence/s2-007-comparison.json', comparison.blocksCompletion === false ? 'PASS' : 'LIMITED'),
  ];
}

/**
 * A counter source is BOUND when its record is fresh — produced by this
 * invocation and tied to the current HEAD. It is deliberately NOT the same as
 * "the gate passed": a fresh record that reports a counter finding is the most
 * important source of truth there is, and losing it because the gate failed
 * would hide the very defect the gate exists to find.
 */
function freshnessSatisfied(gate) {
  if (!gate?.record) return false;
  const freshnessChecks = (gate.checks ?? []).filter((check) => check.check.startsWith('freshness:'));
  return freshnessChecks.length > 0 && freshnessChecks.every((check) => check.ok === true);
}

// ---------------------------------------------------------------------------
// The aggregation itself
// ---------------------------------------------------------------------------
export async function verifyS2_007(args = {}) {
  const startedFrom = { head: headIdentity(), workspace: workspaceState() };
  const packageScripts = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).scripts ?? {};
  const gateCommands = assertGateSetIntact({ packageScripts });

  const gates = [];
  const realExitCodes = {};
  for (const spec of EXPECTED_GATES) {
    const declared = packageScripts[spec.script];
    if (declared === undefined) {
      // A missing mandatory command is an unavailable mandatory tool, not a
      // silent skip: NOT_RUN, and the verdict cannot be COMPLETE_WITH_LIMITS.
      gates.push({
        id: spec.id, spec, status: 'NOT_RUN', exitCode: null, reasons: [`the mandatory npm script ${spec.script} is not declared in package.json`], checks: [], counters: null, freshness: { artifact: null, note: spec.contract },
      });
      realExitCodes[spec.command] = null;
      continue;
    }
    let relativeFile = spec.evidenceFiles[0] ?? null;
    const absoluteFile = relativeFile ? path.join(ROOT, relativeFile) : null;
    const before = absoluteFile && fs.existsSync(absoluteFile) ? { sha256: sha256Of(fs.readFileSync(absoluteFile)) } : null;
    const run = runProcess(spec.script, { timeout: spec.timeoutMs, extraArgs: spec.extraArgs ?? [] });
    realExitCodes[spec.command] = run.exitCode;
    const read = absoluteFile ? readJsonFile(absoluteFile) : { bytes: null, record: null };
    let classified;
    let envelope = null;
    if (spec.kind === 'evidence-envelope') {
      try {
        envelope = JSON.parse(run.stdout);
      } catch {
        envelope = null;
      }
      // The gate may have chosen the second declared artifact name.
      let usedRead = read;
      if (!read.bytes) {
        for (const candidate of spec.evidenceFiles.slice(1)) {
          const candidatePath = path.join(ROOT, candidate);
          if (fs.existsSync(candidatePath)) {
            usedRead = readJsonFile(candidatePath);
            relativeFile = candidate;
            break;
          }
        }
      }
      classified = classifyEvidenceGate({
        gate: spec, envelope, run, bytes: usedRead.bytes, record: usedRead.record, head: startedFrom.head, before,
        relativeFile: relativeFile ?? null,
      });
      gates.push({ id: spec.id, spec, exitCode: run.exitCode, status: classified.status, reasons: classified.reasons, checks: classified.checks, counters: classified.counters ?? null, freshness: { ...classified.freshness, evidenceFile: relativeFile }, record: usedRead.record, envelope, stderrTail: run.exitCode === 0 ? null : (String(run.stderr).slice(-1200) || null), stdoutTail: run.exitCode === 0 ? null : (String(run.stdout).slice(-1200) || null) });
      continue;
    }
    if (spec.kind === 'json-stdout+file') {
      classified = classifyJsonGate({ gate: spec, run, bytes: read.bytes, record: read.record, head: startedFrom.head, before, relativeFile });
      // The report the gate printed is kept so the tamper matrix can replay the
      // genuine report against a doctored copy of the file; it is a scratch
      // value, not a summary field.
      gates.push({
        id: spec.id, spec, exitCode: run.exitCode, status: classified.status, reasons: classified.reasons, checks: classified.checks,
        counters: classified.counters ?? null, freshness: classified.freshness, runStdout: run.stdout,
        stderrTail: classified.stderrTail, stdoutTail: classified.stdoutTail, reportedIssues: classified.reportedIssues ?? null,
      });
      continue;
    } else if (spec.kind === 'db-replay-report') {
      let usedRead = read;
      if (!read.bytes) {
        for (const candidate of spec.evidenceFiles.slice(1)) {
          const candidatePath = path.join(ROOT, candidate);
          if (fs.existsSync(candidatePath)) {
            usedRead = readJsonFile(candidatePath);
            relativeFile = candidate;
            break;
          }
        }
      }
      classified = classifyDbReplayGate({ gate: spec, run, bytes: usedRead.bytes, record: usedRead.record, head: startedFrom.head, before, relativeFile: relativeFile ?? null });
      gates.push({
        id: spec.id, spec, exitCode: run.exitCode, status: classified.status, reasons: classified.reasons, checks: classified.checks,
        counters: classified.counters ?? null, freshness: { ...classified.freshness, evidenceFile: relativeFile }, record: usedRead.record,
        stderrTail: classified.stderrTail, stdoutTail: classified.stdoutTail,
      });
      continue;
    } else {
      classified = classifyTapGate({ gate: spec, run });
    }
    gates.push({ id: spec.id, spec, exitCode: run.exitCode, status: classified.status, reasons: classified.reasons, checks: classified.checks, counts: classified.counts ?? null, freshness: classified.freshness, stderrTail: classified.stderrTail ?? null, stdoutTail: classified.stdoutTail ?? null, reportedIssues: classified.reportedIssues ?? null });
  }

  // ---- the seven counters, in every source of truth -----------------------
  const counterSources = [];
  const probesGate = gates.find((gate) => gate.id === 'security-probes');
  if (probesGate?.record?.counters) {
    const check = checkHardGateCounters(probesGate.record.counters);
    counterSources.push({ source: 'evidence/s2-007-security-probes.json', bound: freshnessSatisfied(probesGate), allZero: check.ok, counters: check.counters, issues: check.issues });
  }
  const dbGate = gates.find((gate) => gate.id === 'db-replay');
  const dbCounters = dbGate?.record?.hardGates?.counters ?? dbGate?.record?.counters ?? null;
  if (dbCounters) {
    const check = checkHardGateCounters(dbCounters);
    counterSources.push({ source: 'evidence/s2-007-db-comparison.json', bound: freshnessSatisfied(dbGate), allZero: check.ok, counters: check.counters, issues: check.issues });
  }
  const comparison = observationForComparison(readJsonFile(path.join(ROOT, 'evidence/s2-007-comparison.json')).record, startedFrom.head);
  if (comparison.counters) {
    const check = checkHardGateCounters(comparison.counters);
    counterSources.push({ source: 'evidence/s2-007-comparison.json', bound: comparison.bound === true, allZero: check.ok, counters: check.counters, issues: check.issues });
  }
  if (counterSources.length === 0) {
    counterSources.push({ source: 'none', bound: false, allZero: false, counters: null, issues: ['no mandatory gate produced a fresh counter block: the seven hard gates were not measured in this verification'] });
  }

  // ---- the aggregator's own negative controls ----------------------------
  // These run on EVERY invocation, not only in the unit test: an aggregator that
  // cannot prove it rejects a skip must not be allowed to certify a green run.
  // Each control is a full verdict derived through deriveVerdict, so a later
  // change to the precedence cannot silently disarm them.
  const scratchDir = path.join(ROOT, '.bb/chats/thr_8sxageuj7j/tmp', `s2-007-verify-${startedFrom.head.commit.slice(0, 12)}`);
  const tamperChecks = runTamperMatrix({ gates, head: startedFrom.head, scratchDir });
  const allGreenGates = MANDATORY_GATE_IDS.map((id) => ({ id, status: 'PASS', exitCode: 0, reasons: [] }));
  const zeroCounters = Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0]));
  const controlVerdict = (controlGates, extra = {}) => deriveVerdict({
    gates: controlGates,
    gateCommands: { ok: true },
    counterSources: [{ source: 'self-check', bound: true, allZero: true, counters: zeroCounters }],
    tamperChecks: { ok: true, checked: 1, undetected: [] },
    selfChecks: { ok: true, failures: [] },
    checkout: { clean: true },
    observations: [],
    ...extra,
  }).engineeringStatus;
  const negativeControls = {
    allGreenCleanCheckout: controlVerdict(allGreenGates),
    skippedMandatoryGate: controlVerdict(allGreenGates.map((row) => (row.id === 'security-probes' ? { ...row, status: 'NOT_RUN', reasons: ['self-check: a mandatory probe reported NOT_RUN_DB'] } : row))),
    notRunDbMandatoryGate: controlVerdict(allGreenGates.map((row) => (row.id === 'db-replay' ? { ...row, status: 'NOT_RUN', reasons: ['self-check: NOT_RUN_DB on the mandatory DB gate'] } : row))),
    blockedDependency: controlVerdict(allGreenGates.map((row) => (row.id === 'dependencies' ? { ...row, status: 'BLOCKED_DEPENDENCY', reasons: ['self-check'] } : row))),
    failedGate: controlVerdict(allGreenGates.map((row) => (row.id === 'db-replay' ? { ...row, status: 'FAIL', reasons: ['self-check'] } : row))),
    counterFinding: controlVerdict(allGreenGates, { counterSources: [{ source: 'self-check', bound: true, allZero: false, counters: { ...zeroCounters, falseApprovals: 1 } }] }),
    undetectedTampering: controlVerdict(allGreenGates, { tamperChecks: { ok: false, checked: 1, undetected: ['security-probes/stale-commit'] } }),
    renamedGate: controlVerdict(allGreenGates, { gateCommands: { ok: false, issues: ['script:verify:s2-007-db-replay:repointed(node scripts/other.mjs)'] } }),
    dirtyCheckout: controlVerdict(allGreenGates, { checkout: { clean: false, changedPathCount: 1 } }),
  };
  const selfChecks = {
    ok: negativeControls.allGreenCleanCheckout === 'COMPLETE_WITH_LIMITS'
      && negativeControls.skippedMandatoryGate === 'NOT_RUN'
      && negativeControls.notRunDbMandatoryGate === 'NOT_RUN'
      && negativeControls.blockedDependency === 'BLOCKED_DEPENDENCY'
      && negativeControls.failedGate === 'REVISE'
      && negativeControls.counterFinding === 'REVISE'
      && negativeControls.undetectedTampering === 'REVISE'
      && negativeControls.renamedGate === 'REVISE'
      && negativeControls.dirtyCheckout === 'PASS_WITH_LIMITS'
      && gateCommands.ok,
    failures: [
      ...(negativeControls.allGreenCleanCheckout === 'COMPLETE_WITH_LIMITS' ? [] : ['four green gates in a clean checkout did not produce COMPLETE_WITH_LIMITS']),
      ...(negativeControls.skippedMandatoryGate === 'NOT_RUN' ? [] : ['a skipped mandatory gate did not flip the verdict to NOT_RUN']),
      ...(negativeControls.notRunDbMandatoryGate === 'NOT_RUN' ? [] : ['NOT_RUN_DB on the mandatory DB gate did not flip the verdict to NOT_RUN']),
      ...(negativeControls.blockedDependency === 'BLOCKED_DEPENDENCY' ? [] : ['a blocked dependency gate did not flip the verdict to BLOCKED_DEPENDENCY']),
      ...(negativeControls.failedGate === 'REVISE' ? [] : ['a failed mandatory gate did not flip the verdict to REVISE']),
      ...(negativeControls.counterFinding === 'REVISE' ? [] : ['a non-zero hard-gate counter did not flip the verdict to REVISE']),
      ...(negativeControls.undetectedTampering === 'REVISE' ? [] : ['undetected evidence tampering did not flip the verdict to REVISE']),
      ...(negativeControls.renamedGate === 'REVISE' ? [] : ['a renamed mandatory gate did not flip the verdict to REVISE']),
      ...(negativeControls.dirtyCheckout === 'PASS_WITH_LIMITS' ? [] : ['a dirty checkout did not cap the verdict at PASS_WITH_LIMITS']),
      ...(gateCommands.ok ? [] : ['the frozen gate set does not match package.json']),
    ],
    negativeControls,
    gateSetOk: gateCommands.ok,
  };

  const aMvp = aMvpBlock(startedFrom.head, gates);
  const verdict = deriveVerdict({ gates, gateCommands, counterSources, tamperChecks, selfChecks, checkout: startedFrom.workspace, observations: [comparison] });
  const matrix = buildMatrix({ gates, counterSources, tamperChecks, selfChecks, checkout: { ...startedFrom.workspace, head: startedFrom.head }, comparison, aMvp, verdict, gateCommands });

  const summary = {
    schemaVersion: 1,
    ticket: 'S2-007',
    issue: 'SpaceDazher/Veritas#7',
    role: 'verification aggregator: freshness, internal status, the seven hard-gate counters, the tamper matrix and the derived verdict',
    gate: 'verify:s2-007',
    commit: startedFrom.head.commit,
    tree: startedFrom.head.tree,
    runId: `s2-007-verify-${canonicalDigest({
      commit: startedFrom.head.commit,
      tree: startedFrom.head.tree,
      gates: gates.map((row) => [row.id, row.status, row.exitCode]),
      counters: counterSources.map((row) => [row.source, row.counters]),
    }).slice(0, 24)}`,
    freshnessModel: 'Every mandatory gate is re-run by THIS process. An evidence artifact is accepted only when (a) the process exited 0, (b) the bytes on disk hash to the digest the gate reported for the file it just wrote, (c) the record content address matches, (d) the record is bound to the current HEAD commit and, where the record carries one, to the current HEAD tree, and (e) the internal status, hardGates.ok, comparison.ok and the seven counters say PASS. The frozen evidence/s2-007-dependency-binding.json format has no HEAD-tree field, so that gate is anchored on the HEAD commit, which subsumes the tree for any committed change; uncommitted changes are caught by the dirty-checkout check, which caps the verdict at PASS_WITH_LIMITS.',
    gateContracts: Object.fromEntries(EXPECTED_GATES.map((spec) => [spec.id, { command: spec.command, contract: spec.contract, evidenceFiles: spec.evidenceFiles }])),
    gates: Object.fromEntries(gates.map((row) => [row.id, {
      command: row.spec.command,
      status: row.status,
      expectedStatus: row.spec.expectedStatus,
      exitCode: row.exitCode,
      reasons: row.reasons,
      checks: row.checks,
      counts: row.counts ?? null,
      counters: row.counters ?? null,
      freshness: row.freshness,
      stderrTail: row.stderrTail ?? null,
      stdoutTail: row.stdoutTail ?? null,
      reportedIssues: row.reportedIssues ?? null,
    }])),
    realExitCodes,
    gateCommands,
    hardGates: {
      counters: Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0])),
      sources: counterSources,
      ok: counterSources.some((source) => source.bound) && counterSources.filter((source) => source.bound).every((source) => source.allZero),
    },
    tamperChecks,
    selfChecks,
    observations: [comparison],
    matrix,
    aMvp,
    engineeringStatus: verdict.engineeringStatus,
    assuranceStatus: verdict.assuranceStatus,
    assuranceCeiling: verdict.assuranceCeiling,
    notInferred: verdict.notInferred,
    verdictReasons: verdict.verdictReasons,
    verdictPrecedence: ['REVISE (critical defect) > BLOCKED_DEPENDENCY > NOT_RUN > PASS_WITH_LIMITS (green but dirty checkout) > COMPLETE_WITH_LIMITS'],
    checkout: startedFrom.workspace,
    finalAcceptance: {
      note: 'The final acceptance set of issue §6 is run by the owner at acceptance, not by this aggregator: this aggregator must not rebuild Next.js or run the whole suite while other work is in flight, and a result it did not observe may not be reported as observed.',
      commands: ['npm test', 'npm run typecheck', 'npm run lint', 'npm run build', 'npm run inventory:check', 'npm run manifest:check', 'npm run verify:clean-checkout', 'git diff --check'],
      statuses: Object.fromEntries(['npm test', 'npm run typecheck', 'npm run lint', 'npm run build', 'npm run inventory:check', 'npm run manifest:check', 'npm run verify:clean-checkout', 'git diff --check'].map((command) => [command, 'NOT_RUN_BY_THIS_AGGREGATOR'])),
    },
    residualLimitations: [
      'No real AgentOS/Codex/pi adapter is installed on this host: every execution-boundary observation comes from the veritas.adapter/1.0.0 test transport (NOT_RUN_REAL_ADAPTER).',
      'assuranceStatus is NOT_MEASURED: nothing here calibrates a semantic verifier, and the S2-006 official status stays NEEDS_INPUT.',
      'The database gate runs against a disposable PostgreSQL container, not a production instance: it validates transactions, fencing and recovery semantics, not operations.',
      'The metrics inside the offline run are engineering proxies over an injected clock; none is an empirical quality, cost or latency measurement.',
      'This aggregator certifies the engineering boundary described in issue #7 §2-§5. It is not an A-MVP PASS, not a SolutionPack sign-off and not production readiness.',
    ],
    rollback: {
      code: 'git revert the S2-007 commits, or reset the worktree to the recorded base commit; the live board is a disjoint agentboard_* namespace, so reverting removes the boundary without touching the public synthetic demo.',
      database: 'DROP the agentboard_* tables created by migrations/0008_agent_board.sql (agentboard_task, agentboard_acl, agentboard_lease, agentboard_adapter, agentboard_budget_grant, agentboard_budget_spend, agentboard_run, agentboard_execution_event, agentboard_transition, agentboard_audit, agentboard_outbox, agentboard_operation, agentboard_reconciliation) and the 0008 row in veritas_schema_migrations. The veritas_demo_* fixtures and migrations 0001-0007 are untouched by S2-007, so the public board keeps working.',
      evidence: 'delete evidence/s2-007-*.json; the gates are re-runnable from a clean checkout.',
      verification: 'npm run verify:s2-007 (the aggregator will report NOT_RUN/BLOCKED rather than green until every gate is green again).',
    },
  };
  summary.recordDigest = canonicalDigest({ ...summary, recordDigest: undefined });

  if (args['no-write'] !== 'true') {
    fs.mkdirSync(path.dirname(path.join(ROOT, SUMMARY_RELATIVE)), { recursive: true });
    fs.writeFileSync(path.join(ROOT, SUMMARY_RELATIVE), `${JSON.stringify(summary, null, 2)}\n`);
  }
  return { summary, exitCode: exitCodeForVerdict(verdict) };
}

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) args[argv[i].slice(2)] = argv[i + 1]?.startsWith('--') ? true : (argv[i + 1] ?? true);
  }
  return args;
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1]).split(path.sep).join('/')}`).href;
if (isMain) {
  const args = parseArgs(process.argv);
  let outcome;
  try {
    outcome = await verifyS2_007(args);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      ticket: 'S2-007',
      gate: 'verify:s2-007',
      engineeringStatus: 'REVISE',
      assuranceStatus: 'NOT_MEASURED',
      exitCode: EXIT_NOT_VERIFIED,
      verdictReasons: [`aggregator:untyped-failure:${String(error?.stack ?? error?.message ?? error).slice(0, 800)}`],
    }, null, 2)}\n`);
    process.exit(EXIT_NOT_VERIFIED);
  }
  const { summary } = outcome;
  console.log(JSON.stringify({
    engineeringStatus: summary.engineeringStatus,
    assuranceStatus: summary.assuranceStatus,
    exitCode: outcome.exitCode,
    runId: summary.runId,
    commit: summary.commit,
    tree: summary.tree,
    gates: Object.fromEntries(Object.entries(summary.gates).map(([id, row]) => [id, `${row.status} (exit ${row.exitCode})`])),
    realExitCodes: summary.realExitCodes,
    hardGatesOk: summary.hardGates.ok,
    tamperChecks: { ok: summary.tamperChecks.ok, checked: summary.tamperChecks.checked, undetected: summary.tamperChecks.undetected },
    selfChecks: summary.selfChecks,
    verdictReasons: summary.verdictReasons,
    evidence: SUMMARY_RELATIVE,
  }, null, 2));
  process.exit(outcome.exitCode);
}
