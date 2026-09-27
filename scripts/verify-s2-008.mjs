#!/usr/bin/env node
// S2-008 — THE VERIFICATION AGGREGATOR (issue SpaceDazher/Veritas#8, A2 + A3 +
// A4 + A5), in the shape of `scripts/verify-s2-006.mjs` and
// `scripts/verify-s2-007.mjs`.
//
// PIPELINE
//   1. dependency gate   — scripts/verify-s2-008-dependencies.mjs: the three
//                           frozen contract digests, the frozen targets, the five
//                           dependency bindings the issue records, module
//                           reachability and evidence presence, all read from
//                           Git bytes;
//   2. probes gate       — scripts/s2-008-security-probes.mjs: the six negative
//                           probes, the six negative controls and the six
//                           hard-gate counters;
//   3. cross-process run — scripts/s2-008-replay.mjs: two process-separated runs
//                           with different raw run ids and nonces, scored against
//                           the FROZEN expected-value table, plus the
//                           identical-wrong control, the crash/restart phase and
//                           the repeatability witness;
//   4. freshness         — the record on disk must be the report of THIS
//                           invocation and must be fresh. A historical green file
//                           is never authority: the aggregator spawns the replay
//                           itself, and a record that differs from the report it
//                           just produced is a FAILURE, not a rounding error;
//   5. summary + verdict — evidence/s2-008-summary.json, DERIVED from the fields
//                           the gates actually reported.
//
// THE STATUS VOCABULARY IS NOT COLLAPSED
// `PASS`, `FAIL`, `NOT_RUN` and `BLOCKED_DEPENDENCY` are four different answers.
// A NOT_RUN is never a pass and never a soft pass: "I could not check" and "I
// checked and it failed" are the two states a fake green is made of. Every gate
// keeps its own exit code (0 / 1 / 3) and the aggregator keeps them separate
// instead of averaging them into one number.
//
//   node scripts/verify-s2-008.mjs
//   node scripts/verify-s2-008.mjs --print-summary
//   S2_008_FRESHNESS_WINDOW_MS=0 node scripts/verify-s2-008.mjs   # prove the refusal
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { parseArgs, resolveBase } from './s2-008-run.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';
/** How old a replay record may be and still be called fresh. Env-overridable so
 *  the staleness refusal can be PROVEN with `--freshness-window-ms 0` instead of
 *  being asserted. */
const FRESHNESS_WINDOW_MS = Number(process.env.S2_008_FRESHNESS_WINDOW_MS ?? 6 * 60 * 60 * 1000);
const SUMMARY_RELATIVE = 'evidence/s2-008-summary.json';
const REPLAY_RELATIVE = 'evidence/s2-008-replay.json';
const HARNESS_RELATIVE = 'evidence/s2-008-harness.json';

/**
 * THE CROSS-RECORD AGREEMENT GATE (EV3).
 *
 * Two records name acceptance property A3: the harness's and the replay's.
 * Before, the aggregator spawned only the replay, so the two could contradict
 * each other and the summary reported both. The rule:
 *   * a harness A3 that declares `agreement_source:
 *     'TABLE_DERIVED_RUN_RECORDS'` is NOT a measurement, is reported as
 *     non-authoritative, and is NOT required to agree with the replay;
 *   * a harness A3 that claims to be a measurement MUST agree with the replay's
 *     A3 on the findings counts, or this is a defect;
 *   * a harness record with no A3 at all, while a replay record exists, is a
 *     defect: a property with two possible sources and one of them silent is how
 *     a contradiction survives.
 *
 * @param {object|null} harnessRecord `evidence/s2-008-harness.json`, or null.
 * @param {object|null} replayRecord `evidence/s2-008-replay.json`, or null.
 * @returns {{verdict: string, issues: ReadonlyArray<string>, note: string,
 *   harness_findings: object|null, replay_findings: object|null}}
 */
export function crossRecordAgreement(harnessRecord, replayRecord) {
  const issues = [];
  if (!isPlainObject(harnessRecord)) {
    return { verdict: 'NO_HARNESS_RECORD', issues: ['the harness record is unreadable, so its A3 cannot be cross-checked against the replay\'s'], note: 'the aggregator spawns the harness itself, so a missing record is a failed run, not an absent opinion', harness_findings: null, replay_findings: null };
  }
  const harnessA3 = (Array.isArray(harnessRecord.properties) ? harnessRecord.properties : []).find((property) => property?.id === 'A3');
  if (!isPlainObject(harnessA3)) {
    issues.push('the harness record names no A3 property');
  }
  const declaredMeasurement = isPlainObject(harnessA3) && harnessA3.agreement_source !== 'TABLE_DERIVED_RUN_RECORDS';
  const harnessFindings = isPlainObject(harnessA3) ? parseFindings(harnessA3.evidence) : null;
  const replayA3 = isPlainObject(replayRecord) && Array.isArray(replayRecord.properties)
    ? replayRecord.properties.find((property) => property?.id === 'A3') ?? null
    : null;
  const replayFindings = isPlainObject(replayA3) ? parseFindings(replayA3.evidence) : null;
  if (replayA3 === null) {
    issues.push('the replay record names no A3 property');
  }
  if (declaredMeasurement && harnessFindings !== null && replayFindings !== null
    && (harnessFindings.findingsA !== replayFindings.findingsA || harnessFindings.findingsB !== replayFindings.findingsB)) {
    issues.push(`the harness claims to MEASURE A3 (${harnessFindings.findingsA}/${harnessFindings.findingsB}) while the replay measured ${String(replayFindings.findingsA)}/${String(replayFindings.findingsB)}`);
  }
  if (declaredMeasurement && !harnessA3?.ok && !replayA3?.ok) {
    // Both failing is agreement; nothing to reconcile.
  }
  return {
    verdict: issues.length > 0 ? 'DISAGREEMENT' : (declaredMeasurement ? 'COMPARABLE' : 'NOT_COMPARABLE_DISCLOSED'),
    issues: Object.freeze(issues),
    note: declaredMeasurement
      ? 'the harness A3 declares itself a measurement and is compared with the replay\'s'
      : 'the harness A3 is built FROM the frozen table (agreement_source=TABLE_DERIVED_RUN_RECORDS), so its agreement count is definitional and the replay\'s A3 is the authoritative one',
    harness_findings: harnessFindings,
    replay_findings: replayFindings,
  };
}

/** `findingsA=0 findingsB=0` out of a property's evidence string. Bounded, and
 *  null when the string does not carry both numbers — a null is never read as
 *  zero. */
function parseFindings(evidence) {
  if (typeof evidence !== 'string') return null;
  const a = /findingsA=(\d+)/.exec(evidence);
  const b = /findingsB=(\d+)/.exec(evidence);
  if (a === null || b === null) return null;
  return { findingsA: Number(a[1]), findingsB: Number(b[1]) };
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function log(...parts) {
  process.stdout.write(`${parts.join(' ')}\n`);
}

/**
 * The LAST JSON value a gate printed. Every S2-008 gate prints a human-readable
 * block first and its JSON envelope last, so parsing the whole stdout as JSON
 * would report a syntax error for a gate that worked perfectly.
 * @param {string} stdout
 * @returns {object|null} The envelope, or null when there is none.
 */
export function parseLastJson(stdout) {
  const text = String(stdout ?? '');
  for (let index = text.lastIndexOf('{'); index !== -1; index = text.lastIndexOf('{', index - 1)) {
    const candidate = text.slice(index);
    try {
      const value = JSON.parse(candidate);
      if (value !== null && typeof value === 'object') return value;
    } catch {
      continue;
    }
  }
  return null;
}

function readJson(relativePath) {
  try {
    return JSON.parse(readFileSync(path.join(REPO_ROOT, relativePath), 'utf8'));
  } catch {
    return null;
  }
}

function runNode(script, scriptArgs = [], { timeout = 900_000 } = {}) {
  const result = spawnSync(process.execPath, [path.join(REPO_ROOT, script), ...scriptArgs], {
    cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout,
  });
  return {
    script,
    exitCode: typeof result.status === 'number' ? result.status : null,
    signal: result.signal ?? null,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    timedOut: result.error?.code === 'ETIMEDOUT',
  };
}

/**
 * THE FRESHNESS VERDICT, in the shape of `freshnessVerdict` in
 * `scripts/s2-007-db-replay.mjs:567`. A replay record is evidence about a TREE,
 * so it carries the commit, the tree, the raw run identities and the instant it
 * finished, and the aggregator can tell a fresh record from a stale one.
 *
 * The three rules that matter:
 *   * `stale-tree-sha` — the record's tree is not the tree this checkout is on;
 *   * `stale-run-timestamp` / `record-from-the-future` — the record is older than
 *     the window, or claims a finish instant that has not happened;
 *   * `green-with-nonzero-exit` — a record that says PASS and whose process
 *     exited non-zero. A green file written by a failing run is the exact shape
 *     of a fake green.
 */
export function freshnessVerdict({ record, headTreeSha, observedAtIso, windowMs = FRESHNESS_WINDOW_MS }) {
  const freshness = isPlainObject(record?.freshness) ? record.freshness : {};
  const startedAt = Date.parse(freshness.observed_at ?? '');
  const finishedAt = Date.parse(freshness.finished_at ?? '');
  const observedAt = Date.parse(observedAtIso ?? '');
  const issues = [];
  if (record?.base?.commit_sha === null || record?.base?.commit_sha === undefined) issues.push('missing-commit-sha');
  if (record?.base?.tree_sha !== headTreeSha) issues.push('stale-tree-sha');
  if (!Number.isFinite(startedAt)) issues.push('missing-run-timestamp');
  if (!Number.isFinite(finishedAt)) issues.push('missing-finish-timestamp');
  else if (Number.isFinite(startedAt) && finishedAt < startedAt) issues.push('run-timestamps-out-of-order');
  if (freshness.decides !== false) issues.push('freshness-block-claims-to-decide');
  if (Number.isFinite(observedAt) && Number.isFinite(finishedAt)) {
    freshness.age_ms = observedAt - finishedAt;
    if (observedAt < finishedAt) issues.push('record-from-the-future');
    if (observedAt - finishedAt > windowMs) issues.push('stale-run-timestamp');
  } else {
    issues.push('unverifiable-run-timestamp');
  }
  const rawIds = [record?.evidence?.a?.digest, record?.evidence?.b?.digest];
  if (!isPlainObject(record?.separation) || record.separation.ok !== true) issues.push('runs-not-process-separated');
  if (record?.separation?.raw_run_id?.a === record?.separation?.raw_run_id?.b) issues.push('run-ids-not-unique');
  if (rawIds.some((value) => typeof value !== 'string' || value.length === 0)) issues.push('run-artefact-digest-absent');
  // The record must CARRY its own exit code, and the pair must agree. The rule
  // was dead (EV5): `record.exitCode !== undefined` was a guard, the replay
  // never wrote the member, and `node -e "'exitCode' in
  // require('./evidence/s2-008-replay.json')"` answered false — so the one check
  // that catches "a green file written by a failing run" never ran.
  if (!Number.isInteger(record?.exitCode)) issues.push('exit-code-absent');
  else if (record?.overall === 'PASS' && record.exitCode !== 0) issues.push('green-with-nonzero-exit');
  else if (record?.overall !== 'PASS' && record.exitCode === 0) issues.push('non-green-with-zero-exit');
  return { ok: issues.length === 0, issues, age_ms: freshness.age_ms ?? null };
}

/**
 * THE AGGREGATOR CONTRACT: the report of THIS invocation and the record on disk
 * must be the same bytes, and the record must be fresh. A previous green file
 * can therefore never turn a current NOT_RUN or FAIL into a PASS.
 */
export function classifyCurrentReplay(executed, writtenEvidence, { headTreeSha = null, observedAtIso = null, windowMs = FRESHNESS_WINDOW_MS } = {}) {
  // THE STALE-GREEN REFUSAL. The child prints `REPLAY_EVIDENCE_SHA256 <hex>`, the
  // digest of the exact bytes it wrote. The bytes on disk are re-hashed HERE and
  // must match. A record that was not written by this invocation — a previous
  // green file, a hand-edited file, a re-run that failed before writing — cannot
  // be reported as this run's evidence, and comparing the file with ITSELF (the
  // tautology this replaced) would have made every stale file look current.
  const reported = /REPLAY_EVIDENCE_SHA256 ([0-9a-f]{64})/.exec(String(executed.stdout ?? ''));
  const onDisk = writtenEvidence === null ? null : readReplayBytes();
  const bytesMatch = reported !== null
    && onDisk !== null
    && createHash('sha256').update(onDisk).digest('hex') === reported[1];
  if (!bytesMatch) {
    return {
      gate: {
        status: 'FAIL',
        exitCode: executed.exitCode,
        source: 'current S2-008 replay',
        reason: reported === null
          ? 'the replay reported no evidence digest; its report cannot be matched against the record on disk'
          : `the record on disk is not the one this invocation wrote (reported ${reported[1].slice(0, 12)}, on disk ${onDisk === null ? 'absent' : createHash('sha256').update(onDisk).digest('hex').slice(0, 12)})`,
      },
      evidence: null,
    };
  }
  if (!recordCarriesRunIds(writtenEvidence)) {
    return {
      gate: { status: 'FAIL', exitCode: executed.exitCode, source: 'current S2-008 replay', reason: 'the replay record carries no run identities' },
      evidence: null,
    };
  }
  if (executed.exitCode !== 0) {
    return {
      gate: {
        status: executed.exitCode === 3 ? 'NOT_RUN' : 'FAIL',
        exitCode: executed.exitCode,
        source: 'current S2-008 replay',
        reason: `the replay process exited ${executed.exitCode} (${writtenEvidence.overall ?? 'unknown'})`,
      },
      evidence: writtenEvidence,
    };
  }
  const freshness = freshnessVerdict({
    record: writtenEvidence,
    headTreeSha: headTreeSha ?? writtenEvidence?.base?.tree_sha ?? null,
    observedAtIso,
    windowMs,
  });
  // S6 / EV2: THREE terms, not one. `overall === 'PASS'` already counts the
  // properties, the campaign verdict and the ledger shape (see the replay's
  // `overall_terms`), and each is re-read here from the record's own block so
  // this aggregator does not have to trust the summary it just read. A replay
  // whose `verdict` is FAIL, or whose `overall_terms` disagree with `overall`,
  // is a FAIL here even when it exits 0.
  const terms = isPlainObject(writtenEvidence.overall_terms) ? writtenEvidence.overall_terms : null;
  const greenReasons = [];
  if (writtenEvidence.overall !== 'PASS') greenReasons.push(`overall=${String(writtenEvidence.overall)}`);
  if (writtenEvidence.verdict !== 'PASS') greenReasons.push(`verdict=${String(writtenEvidence.verdict)}`);
  if (writtenEvidence.ledger_shape_ok !== true) {
    greenReasons.push(`ledger_shape_ok=${String(writtenEvidence.ledger_shape_ok)} findings=${String(writtenEvidence.overall_terms?.ledger_shape_findings ?? 'n/a')}`);
  }
  if (terms === null) greenReasons.push('overall_terms absent');
  else if (terms.verdict_is_pass !== true || terms.every_property_held !== true || terms.ledger_shape_matches_table !== true) {
    greenReasons.push(`overall_terms=${JSON.stringify(terms)}`);
  }
  if (!Array.isArray(writtenEvidence.properties)
    || !writtenEvidence.properties.every((property) => property.status === 'HELD')) {
    greenReasons.push('a property this replay owns did not hold');
  }
  if (greenReasons.length > 0) {
    return { gate: { status: 'FAIL', exitCode: 0, source: 'current S2-008 replay', reason: `the replay is not green: ${greenReasons.join('; ')}` }, evidence: writtenEvidence };
  }
  if (!freshness.ok) {
    return { gate: { status: 'FAIL', exitCode: 0, source: 'current S2-008 replay', stale: true, reason: `stale evidence: ${freshness.issues.join(',')}` }, evidence: null };
  }
  return { gate: { status: 'PASS', exitCode: 0, source: 'current S2-008 replay', fresh: true }, evidence: writtenEvidence };
}

function readReplayBytes() {
  try {
    return readFileSync(path.join(REPO_ROOT, REPLAY_RELATIVE));
  } catch {
    return null;
  }
}

function recordCarriesRunIds(record) {
  return isPlainObject(record?.separation)
    && typeof record?.separation?.raw_run_id?.a === 'string'
    && typeof record?.separation?.raw_run_id?.b === 'string';
}

/** The gate status, mapped from the child's exit code. Exit 3 is NOT_RUN and is
 *  never softened into a pass. */
function gateStatusFromExit(exitCode) {
  if (exitCode === 0) return 'PASS';
  if (exitCode === 3) return 'NOT_RUN';
  if (exitCode === 1) return 'FAIL';
  return `NOT_RUN_UNMAPPED_EXIT_${String(exitCode)}`;
}

export function verify(args = {}) {
  const observedAtIso = new Date().toISOString();
  const base = resolveBase();
  const gates = {};
  const notRun = [];
  const defects = [];

  // 1. the dependency gate
  const dependency = runNode('scripts/verify-s2-008-dependencies.mjs');
  const dependencyRecord = parseLastJson(dependency.stdout);
  gates.dependency = {
    // The dependency gate has its OWN status vocabulary
    // (`BLOCKED_DEPENDENCY`), and it is kept: a dependency that is not satisfied
    // is not a failed experiment, and collapsing the two would tell a reader
    // that a measurement was attempted and broke.
    status: typeof dependencyRecord?.status === 'string' ? dependencyRecord.status : gateStatusFromExit(dependency.exitCode),
    exitCode: dependency.exitCode,
    source: 'scripts/verify-s2-008-dependencies.mjs',
    issues: dependencyRecord?.issues ?? [],
    bindings: dependencyRecord?.bindings ?? null,
    track_files_tracked: dependencyRecord?.track_files_tracked ?? null,
  };
  if (dependency.exitCode === 3) notRun.push('NOT_RUN: the dependency gate could not run');
  else if (dependency.exitCode !== 0) defects.push(`dependency gate: ${gates.dependency.status} (${(dependencyRecord?.issues ?? []).join(', ')})`);

  // 2. the probes gate
  const probes = runNode('scripts/s2-008-security-probes.mjs', args.corpus === undefined ? [] : ['--corpus', String(args.corpus)]);
  const probesRecord = parseLastJson(probes.stdout);
  gates.probes = {
    status: gateStatusFromExit(probes.exitCode),
    exitCode: probes.exitCode,
    source: 'scripts/s2-008-security-probes.mjs',
    counters: probesRecord?.counters ?? null,
    totals: probesRecord?.totals ?? null,
    reasons: probesRecord?.reasons ?? null,
  };
  if (probes.exitCode === 3) notRun.push('NOT_RUN: a mandatory probe or control did not run');
  else if (probes.exitCode !== 0) defects.push(`probes gate: ${gates.probes.status} (${(probesRecord?.reasons ?? []).join(', ')})`);
  // The hard-gate counters, read from the gate's own report and never from a
  // file: a counter that moved is a failure whatever the rest says.
  const counters = isPlainObject(probesRecord?.counters) ? probesRecord.counters : null;
  if (counters !== null) {
    const moved = Object.entries(counters).filter(([, value]) => value !== 0).map(([name, value]) => `${name}=${value}`);
    if (moved.length > 0) defects.push(`hard-gate counters moved: ${moved.join(', ')}`);
  } else {
    notRun.push('NOT_RUN: the probes gate reported no counter map');
  }

  // 3. the cross-process replay, spawned BY THE AGGREGATOR
  const replayArgs = args.corpus === undefined ? [] : ['--corpus', String(args.corpus)];
  const replay = runNode('scripts/s2-008-replay.mjs', replayArgs);
  const replayRecord = readJson(REPLAY_RELATIVE);
  const classified = classifyCurrentReplay(replay, replayRecord, {
    headTreeSha: base.tree_sha,
    observedAtIso,
    windowMs: Number.isFinite(args.freshnessWindowMs) ? args.freshnessWindowMs : FRESHNESS_WINDOW_MS,
  });
  gates.replay = {
    status: classified.gate.status,
    exitCode: replay.exitCode,
    stale: classified.gate.stale ?? false,
    reason: classified.gate.reason ?? null,
    source: 'scripts/s2-008-replay.mjs',
    overall: classified.evidence?.overall ?? null,
    properties: (classified.evidence?.properties ?? []).map((property) => `${property.id}:${property.status ?? (property.ok ? 'HELD' : 'FAILED')}`),
    freshness: classified.evidence?.freshness ?? null,
  };
  if (classified.gate.status === 'NOT_RUN') notRun.push(`NOT_RUN: the cross-process replay (${classified.gate.reason})`);
  else if (classified.gate.status !== 'PASS') defects.push(`replay gate: ${classified.gate.status}${classified.gate.stale ? ' (stale evidence)' : ''} (${classified.gate.reason})`);

  // 3b. THE HARNESS, spawned BY THE AGGREGATOR, and the CROSS-RECORD
  //     AGREEMENT between its A3 and the replay's A3.
  //
  //     EV3: the harness was never spawned by this chain, so two records
  //     described the same acceptance property and contradicted each other with
  //     nothing to notice it — `harness.json` A3 `{"ok":true,"findings":"0/0"}`
  //     beside `replay.json` A3 `{"status":"FAILED","findings":3}`. The
  //     `agreement_source: 'TABLE_DERIVED_RUN_RECORDS'` string was a
  //     disclosure, not a guard. The cross-check below is the guard: the
  //     harness's A3 is either a MEASUREMENT and must agree with the replay's
  //     A3, or it declares itself table-derived and is reported as
  //     NON-AUTHORITATIVE — and a record that claims a measurement it did not
  //     make is a defect, not a nuance.
  const harness = runNode('scripts/s2-008-harness.mjs', args.corpus === undefined ? [] : ['--corpus', String(args.corpus), '--no-write']);
  const harnessRecord = readJson(HARNESS_RELATIVE);
  gates.harness = {
    status: gateStatusFromExit(harness.exitCode),
    exitCode: harness.exitCode,
    source: 'scripts/s2-008-harness.mjs',
    overall: harnessRecord?.overall ?? null,
    verdict: harnessRecord?.verdict ?? null,
    properties: (harnessRecord?.properties ?? []).map((property) => `${property.id}:${property.ok ? 'HELD' : 'FAILED'}`),
    reason: null,
  };
  if (harness.exitCode === 3) notRun.push('NOT_RUN: the harness could not run every property');
  else if (harness.exitCode !== 0) defects.push(`harness gate: ${gates.harness.status} (${harnessRecord?.overall ?? 'unknown'})`);
  const crossRecord = crossRecordAgreement(harnessRecord, classified.evidence);
  if (crossRecord.issues.length > 0) {
    defects.push(`harness/replay A3 disagreement: ${crossRecord.issues.join('; ')}`);
  } else if (crossRecord.verdict === 'NOT_COMPARABLE_DISCLOSED') {
    notRun.push(`NOT_RUN: the harness's A3 is table-derived, not a measurement (${crossRecord.note}); the authoritative A3 is the replay's`);
  }

  // 4. the derived verdict. The gate statuses are read, never averaged: one
  //    NOT_RUN is a NOT_RUN.
  const blocking = Object.entries(gates).filter(([, gate]) => gate.status === 'FAIL' || gate.status === 'BLOCKED_DEPENDENCY' || String(gate.status).startsWith('NOT_RUN_UNMAPPED'));
  const notRunGates = Object.entries(gates).filter(([, gate]) => gate.status === 'NOT_RUN' || String(gate.status).startsWith('NOT_RUN_UNMAPPED'));
  // EV5: THE STATUS IS NEVER PASS, AND THE SUMMARY SAYS WHY IN ONE PLACE.
  //
  // This used to compute a PASS and then push a disclaimer into `defects` while
  // also setting `ok: true` and `exitCode: 0` — a green summary that
  // contradicted its own defects. The two ticket-level preconditions are
  // therefore STATUS TERMS now, and each is a named NOT_RUN entry:
  //   * the campaign behind #45 is NOT_RUN, so this track's engineering result
  //     is not the ticket's verdict; and
  //   * the track's own files are untracked until delivery adds them, so nothing
  //     here is bound to a base a reader can check.
  // A reader of ONE file now sees a single consistent answer.
  const ticketPreconditions = [];
  if (gates.dependency.track_files_tracked === 0) {
    ticketPreconditions.push('the track\'s own files are untracked (git ls-files reports 0 of them), so no artefact of this track is bound to a base a reader can check; delivery owns git');
  }
  ticketPreconditions.push('the campaign behind #45 is NOT_RUN, so this deterministic track does not decide the ticket\'s own scope');
  for (const reason of ticketPreconditions) notRun.push(`NOT_RUN: ${reason}`);
  const status = blocking.length > 0 ? 'FAIL' : (notRunGates.length > 0 || notRun.length > 0 ? 'NOT_RUN' : 'PASS');
  const summary = {
    ticket: 'S2-008',
    gate: 'scripts/verify-s2-008.mjs',
    role: 'verification aggregator: dependency gate, probes gate, the cross-process replay it spawns itself, the freshness refusal, and the derived status',
    status,
    ok: status === 'PASS',
    exitCode: status === 'PASS' ? 0 : (status === 'NOT_RUN' ? 3 : 1),
    base,
    gates,
    defects,
    notRun,
    blockingGates: blocking.map(([id]) => id),
    notRunGates: notRunGates.map(([id]) => id),
    freshness: {
      observed_at: observedAtIso,
      window_ms: Number.isFinite(args.freshnessWindowMs) ? args.freshnessWindowMs : FRESHNESS_WINDOW_MS,
      head_tree_sha: base.tree_sha,
      replay_finished_at: classified.evidence?.freshness?.finished_at ?? null,
    },
    // The three statuses the track keeps apart, restated by this aggregator so a
    // reader of ONE file sees all of them.
    track_status: status === 'PASS' ? 'TRACK_PROPERTIES_HELD' : status,
    // Where the authoritative A3/A5 come from, so a reader never has to guess
    // between two records that name the same property.
    authoritative: {
      a3: 'evidence/s2-008-replay.json (the cross-process replay the aggregator spawned)',
      a5: 'evidence/s2-008-replay.json (the cross-process replay the aggregator spawned)',
      harness_a3_is: crossRecord.verdict === 'COMPARABLE' ? 'MEASUREMENT_AND_AGREES' : 'TABLE_DERIVED_NOT_A_MEASUREMENT',
      cross_record_agreement: crossRecord,
    },
    ticket_preconditions_not_met: ticketPreconditions,
    engineering_status: 'BLOCKED_DEPENDENCY',
    assurance_status: 'NOT_MEASURED',
    real_adapter_status: 'NOT_RUN_REAL_ADAPTER',
    a_mvp_status: 'NOT_RUN (A-MVP-01..07, behind #45)',
    note: 'engineeringStatus, assuranceStatus and the A-MVP rows are NOT derived from this gate and never are: a green deterministic track does not convert the ticket\'s own scope into done.',
    observedAtIso,
  };
  const outFile = path.join(REPO_ROOT, SUMMARY_RELATIVE);
  let written = null;
  // `--no-write` is honoured: a CHECK run of this aggregator must not mutate the
  // summary it is checking. Its three child gates are still spawned, because
  // their whole point is to produce a current report; the harness is spawned
  // with `--no-write` so the check leaves the evidence it inspects untouched.
  const noWrite = args.noWrite === true || args.no_write === true || args.nowrite === true;
  if (args.write !== false && !noWrite) {
    const body = `${JSON.stringify(summary, null, 2)}\n`;
    writeFileSync(outFile, body, 'utf8');
    written = { path: SUMMARY_RELATIVE, bytes: Buffer.byteLength(body) };
  }
  return { summary, written, replay, probes, dependency };
}

function main() {
  const args = parseArgs(process.argv);
  const numeric = args.freshnessWindowMs === undefined ? Number.NaN : Number(args.freshnessWindowMs);
  const { summary, written } = verify({
    ...args,
    freshnessWindowMs: Number.isFinite(numeric) ? numeric : undefined,
  });
  if (args.printSummary === true) {
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  } else {
    process.stdout.write(`${JSON.stringify({
      ticket: 'S2-008',
      gate: 'scripts/verify-s2-008.mjs',
      status: summary.status,
      ok: summary.ok,
      exitCode: summary.exitCode,
      gates: Object.fromEntries(Object.entries(summary.gates).map(([id, gate]) => [id, `${gate.status}(exit=${gate.exitCode})`])),
      blockingGates: summary.blockingGates,
      notRunGates: summary.notRunGates,
      defects: summary.defects,
      notRun: summary.notRun,
      ...(written ? { written } : {}),
    }, null, 2)}\n`);
  }
  process.exitCode = summary.exitCode;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      ticket: 'S2-008',
      gate: 'scripts/verify-s2-008.mjs',
      status: 'NOT_RUN',
      ok: false,
      exitCode: 3,
      code: String(error?.code ?? 'AGGREGATOR_ERROR'),
      error: String(error?.message ?? error).slice(0, 600),
      stack: String(error?.stack ?? '').split('\n').slice(0, 6),
    }, null, 2)}\n`);
    process.exitCode = 3;
  }
}
