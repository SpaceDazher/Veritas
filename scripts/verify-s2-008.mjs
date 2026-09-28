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
// A FIFTH KIND OF STATEMENT IS NOT A STATUS AT ALL. A `scopeNotes` entry says
// what this track does NOT decide — which gate owns a property, and which part
// of the ticket's scope is somebody else's campaign. It is recorded in the
// summary and in the printed output, and it is deliberately kept out of the
// status: a note is not an answer to "did a check this stage owns hold?", so a
// note that could decide a verdict would be a verdict fixed by a constant that
// is true on every run. See the three-way split at `deriveVerdict`.
//
// THE TRUST MODEL OF THIS FILE, IN ONE SENTENCE:
//   A RECORD THAT IS NOT BOUND TO THIS INVOCATION IS NOT THIS RUN'S EVIDENCE.
//
// Before this repair the aggregator read what its children SAID about
// themselves. `classifyCurrentReplay` re-hashed the replay record — but against
// the digest the REPLAY ITSELF printed, and the five pass terms were then read
// back out of that same record's own claims, so a stubbed replay that ran no
// trial, copied the previous honest file, refreshed two timestamps and printed
// the digest of what it wrote produced status PASS with `defects []`
// (reproduced, observed exit 0). The probes gate's `totals` were stored and
// never compared with anything, so a probes gate that ran nothing was
// indistinguishable from one that ran everything (reproduced, observed exit 0,
// published `probes_ran 0, controls_ran 0`). The harness record was read raw —
// no digest, no freshness, no exit-code agreement, no overall agreement — and a
// check run REWROTE it (reproduced twice, both observed exit 0). Partial
// untracking of the track was invisible (reproduced, observed exit 0, with 33
// untracked files named by the dependency gate itself).
//
// THE FIX, and it is five checks, all of them strengthening:
//   1. INVOCATION BINDING (G1). This aggregator mints ONE invocation id per run
//      (`randomBytes`, node:crypto), passes it to all three child gates as
//      `--invocation-id <id>`, and REFUSES a RUN-GATE record that does not carry
//      it, or whose tree is not the tree this checkout is on. (The dependency
//      gate is handed the same id and records it; it is not judged on it,
//      because it is the gate that OWNS the binding of its own record to the
//      base.) A record copied
//      from an earlier run cannot match, so the A3 stub dies here. WHERE the
//      binding can be required is stated rather than assumed: the REPLAY record
//      is written by a child this aggregator spawns in this run, so the id is
//      required of it in every mode, and the HARNESS record is required of it
//      only when this run asked the harness to write that record (a WRITE run);
//      on a CHECK run the harness is spawned with `--no-write`, the record on
//      disk is an EARLIER run's committed artefact by construction, and it is
//      judged for AGREEMENT with the process this run observed instead. Both
//      are published (`gates.*.invocation_id`, `head_tree_sha`,
//      `head_tree_sha_matches`), so a reader can see which run a record belongs
//      to without re-running anything.
//   2. THE HARNESS RECORD IS JUDGED LIKE THE REPLAY'S (G2): a digest THIS file
//      computes over the bytes it read, the invocation binding, and an
//      agreement check between the record's own claims and what this run
//      observed. A record whose `overall` is not PASS, whose property flags are
//      not all true, or whose recorded exit code disagrees with the exit code
//      the aggregator saw is a DEFECT — and a CHECK run is spawned with
//      `--no-write` by this file's own mode, so it can no longer overwrite the
//      record it is judging.
//   3. PROBE FLOORS (G3). The probes gate's counts are compared with the counts
//      the FROZEN probe list declares in `src/lib/research/probes.mjs` — read
//      from the CODE, never from the record. Fewer probes or fewer controls than
//      the code declares is a defect, and a counter map that reports none of the
//      declared counters is a defect, not a pass.
//   4. PROVABILITY OVER THE WHOLE TRACK (G4). The untracked and modified lists
//      the dependency gate already computes are copied into `gates.dependency`
//      and ANY entry in either is a blocking defect with the paths named. A
//      dependency gate that reports nothing is a defect too: "the gate said
//      nothing" is not "the gate found nothing". The one exemption is the
//      explicit set of records this chain's own children write in this run
//      (`CHAIN_WRITTEN_RECORDS`, published as `provability_exempt`), which is
//      the same ORDERING statement the dependency gate's `--chain-produced`
//      makes; a modified CORPUS file is not exempt.
//   5. G5, BOOTSTRAP ORDERING. This chain spawns the dependency gate BEFORE it
//      spawns the children that write `evidence/s2-008-replay.json` and
//      `evidence/s2-008-security-probes.json`, so that gate is told, with its
//      own `--chain-produced` flag, which records this run produces itself — and
//      the probes gate is spawned in this run's own mode, so the security-probes
//      record is one THIS RUN writes rather than one it has to find before it
//      starts. Without the flag the gate's standalone contract is
//      byte-for-byte unchanged.
//
// THE INVOCATION ID IS EXCLUDED FROM REPEATABILITY, ON PURPOSE, AND IT IS THE
// ONLY RANDOM VALUE ON THIS PATH. It decides nothing about the VERDICT of a
// measurement: it decides only WHETHER a record is the current run's, which is
// the same role the freshness observation plays, and for the same reason — a
// per-run identity cannot be a constant if it is to bind anything. Two runs of
// this aggregator on one tree therefore produce child records whose bytes
// differ in `invocation_id` and in nothing else that any verdict reads; the
// verdict itself stays a pure function of the record and the tree. That is why
// the id is published next to the other instants (`summary.invocation`) instead
// of being hidden in a record nobody diffs.
//
// THE STATED BOUNDARY, NOT A DEFECT (B-low, G6). The integrity gates read
// COMMITTED bytes — `scripts/generate-manifests.mjs` reads `git show HEAD:<file>`
// and `scripts/check-inventory.mjs` reads `git ls-files` — so a hand-edited
// `evidence/s2-008-summary.json` in the WORKING TREE is invisible to them until
// the next chain run rewrites it. That is not closed here and is not claimed to
// be, and the protection is named per SURFACE rather than in one breath: the
// corpus drift gate re-derives `tests/research/fixtures/**`, so it covers the
// working tree of the CORPUS and not of the summary, and what covers the
// summary is that nothing in this chain reads it back and that the next write
// run overwrites it. This aggregator's own reading of the child records is over
// the bytes on disk at judging time. The boundary is printed by every run
// (`boundaries`), so a reader never has to open the report to learn what this
// gate does not see.
//
//   node scripts/verify-s2-008.mjs
//   node scripts/verify-s2-008.mjs --print-summary
//   S2_008_FRESHNESS_WINDOW_MS=0 node scripts/verify-s2-008.mjs   # prove the refusal
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// The FLOORS are read from the frozen code and never from a record: the number
// of probes the probe list declares, and the number of controls the frozen
// control descriptors plus the named extra declare. This file may not edit
// `src/lib/research/**` and does not need to — importing the tables IS the
// reading of them, and it is what makes a record's own count checkable against
// something the record cannot choose.
import { EXPECTED_CONTROLS } from '../src/lib/research/expected-values.mjs';
import { EXTRA_CONTROL_IDS } from '../src/lib/research/negative-controls.mjs';
import { HARD_GATE_COUNTERS, PROBE_FAMILIES, PROBE_NAMES } from '../src/lib/research/probes.mjs';
// The digest the probes gate prints over the record it wrote, computed the same
// way here: `canonicalDigest` over the parsed bytes is the child's own function
// of the same document, so the comparison is between two readings of one file
// and not between a claim and a fact.
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';

import { parseArgs, resolveBase } from './s2-008-run.mjs';
// R-C: the campaign-decision rule is DEFINED ONCE, in the replay, and this
// aggregator CALLS it rather than re-typing the comparison. Four coupled sites
// is how `verdict_is_pass` came back; one definition is how it stays gone.
import { campaignDecisionAgreement, frozenCampaignDecision } from './s2-008-replay.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';
/** How old a replay record may be and still be called fresh. Env-overridable so
 *  the staleness refusal can be PROVEN with `--freshness-window-ms 0` instead of
 *  being asserted. */
const FRESHNESS_WINDOW_MS = Number(process.env.S2_008_FRESHNESS_WINDOW_MS ?? 6 * 60 * 60 * 1000);
const SUMMARY_RELATIVE = 'evidence/s2-008-summary.json';
const REPLAY_RELATIVE = 'evidence/s2-008-replay.json';
const HARNESS_RELATIVE = 'evidence/s2-008-harness.json';
const PROBES_RECORD_RELATIVE = 'evidence/s2-008-security-probes.json';
/** THE RECORDS THIS CHAIN'S CHILDREN WRITE, AFTER the dependency gate has run.
 *  Passed as that gate's `--chain-produced` (G5): it makes the FIRST run on a
 *  clean base green instead of red for a file the chain had not written yet, and
 *  it excludes them from REQUIRED only — they are still read and still reported.
 *  A frozen list, because a list read off the filesystem is a list that shrinks
 *  when the filesystem does.
 *
 *  `evidence/s2-008-security-probes.json` IS in it, and that is the last row
 *  G5 needed. It was the one record the chain could not produce — the probes
 *  gate is spawned by step 2, AFTER the dependency gate has run, and it was
 *  spawned without `--write`, so a base on which the record had never been
 *  produced was red on its FIRST run for a file the chain writes itself
 *  (reproduced, observed exit 1, defect
 *  `dependency gate: BLOCKED_DEPENDENCY
 *  (evidence-absent:evidence/s2-008-security-probes.json)`). It is written in
 *  this run's own mode now (see step 2), so the ordering statement is true
 *  rather than aspirational. */
const CHAIN_PRODUCED_RECORDS = Object.freeze([
  REPLAY_RELATIVE,
  'evidence/s2-008-run-a.json',
  'evidence/s2-008-run-b.json',
  'evidence/s2-008-probes.json',
  'evidence/s2-008-controls.json',
  'evidence/s2-008-comparison.json',
  HARNESS_RELATIVE,
  PROBES_RECORD_RELATIVE,
  // The dependency gate's OWN record: it writes that file itself, at step 1 of
  // this run, so it is the chain's business exactly like the others.
  'evidence/s2-008-dependency-binding.json',
]);
/** The same set, plus the summary THIS file writes. The summary is not in
 *  `--chain-produced` (the dependency gate's own frozen list does not accept it
 *  and would name a `chain-produced-unknown-path` issue), but it is written by
 *  this run, so the provability rule below does not report it as an uncommitted
 *  change either. A hand-edited summary in the working tree is the B-low
 *  boundary, and the next write run overwrites it — which is why the boundary
 *  says so rather than pretending the file cannot be edited. */
const CHAIN_WRITTEN_RECORDS = Object.freeze([...CHAIN_PRODUCED_RECORDS, SUMMARY_RELATIVE]);

/** The probes the FROZEN probe list declares, counted from the code: every
 *  family in `PROBE_FAMILIES` with every name `PROBE_NAMES` gives it. Six
 *  today; a record that reports fewer did not run the list. */
export const DECLARED_PROBE_COUNT = PROBE_FAMILIES
  .reduce((total, family) => total + (Array.isArray(PROBE_NAMES[family]) ? PROBE_NAMES[family].length : 0), 0);
/** The controls the frozen descriptors declare plus the ONE named extra the
 *  probes record itemises (`controls_extra_ids`). Seven today. */
export const DECLARED_CONTROL_COUNT = EXPECTED_CONTROLS.length + EXTRA_CONTROL_IDS.length;

/** The working-tree boundary (B-low), stated where every run prints it. It is a
 *  boundary and not a defect: nothing here can be false, and a statement that
 *  cannot be false must not decide anything. */
const WORKING_TREE_BOUNDARY = 'BOUNDARY (B-low, not closed): the integrity gates read COMMITTED bytes (scripts/generate-manifests.mjs uses `git show HEAD:<file>`, scripts/check-inventory.mjs uses `git ls-files`), so a hand-edited evidence/s2-008-summary.json in the WORKING TREE is invisible to `npm run manifest:check` and `npm run inventory:check` until the next chain run rewrites it. What covers the working tree is per SURFACE, and this one is not the corpus: the corpus drift gate (scripts/s2-008-build-corpus.mjs --check) re-derives tests/research/fixtures/**, so it covers the working tree of the CORPUS, not of the summary; the working-tree surface of the summary is covered by the fact that NOTHING in this chain reads it back (no gate, no property, no verdict term consumes evidence/s2-008-summary.json) and that the next write run overwrites it. That is a stated boundary, not a check, and it is stated here so a reader never has to open the report to learn it';

/** The invocation id: the one random value on this path, and the only one.
 *  16 bytes from `node:crypto`, minted once per `verify()` call, handed to both
 *  children as `--invocation-id <id>` and required back in their records. It is
 *  EXCLUDED FROM REPEATABILITY, exactly like the freshness observation, and for
 *  the same reason: a per-run identity is what binds a record to a run, and a
 *  constant could bind nothing. It decides no measurement. */
export function newInvocationId() {
  return randomBytes(16).toString('hex');
}

/**
 * The aggregator's own reading of the wall clock — and WHERE it reads it.
 *
 * The freshness rule compares a record's `finished_at` against the instant at
 * which the reader judged it, and this function exists to make that instant
 * mean what it says. It used to be sampled ONCE, at the top of `verify()`,
 * before the dependency gate, the probes gate and the cross-process replay had
 * run; the replay writes its record's `finished_at` after all of that, so every
 * record this aggregator judged was "from the future" and the chain reported
 * `replay gate: FAIL (stale evidence) (stale evidence: record-from-the-future)`
 * on a record the same process had just produced. The window was never the
 * problem and was NOT widened: the reading was taken before the thing it
 * measures existed.
 *
 * DETERMINISM, stated rather than hidden: this is a wall-clock read on the
 * aggregator's REPORTING path, and it decides nothing on its own — the record's
 * bytes are pinned by the digest its own child printed, and the decision terms
 * in `classifyCurrentReplay` are pure functions of the record and the head tree.
 * The two child records carry `freshness.decides: false` for exactly this
 * reason. The summary publishes every instant it sampled
 * (`started_at`, `replay_judged_at`, `harness_judged_at`, `observed_at`) so a
 * reader can see the order they were taken in.
 * @returns {string} An ISO-8601 UTC instant.
 */
function nowIso() {
  return new Date().toISOString();
}

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
 * THE INVOCATION BINDING (G1) — the check that makes "this run's evidence" mean
 * something.
 *
 * A record is bound to a run by TWO facts the run itself observed:
 *   * the TREE it was produced on, and
 *   * the INVOCATION ID this aggregator minted and handed the child as
 *     `--invocation-id <id>`.
 *
 * The tree is read from the member the ticket names, `head_tree_sha`, and falls
 * back to `base.tree_sha` — every S2-008 record already carries the tree in its
 * own `base` block, so the fallback is a real binding and not a hole: a record
 * whose tree is another tree is refused either way, and a record that carries
 * NEITHER member is refused. The invocation id has no fallback on purpose: it is
 * the one thing a record copied from an earlier run cannot reproduce, and the
 * A3 stub (a replay that ran nothing, copied the previous honest record,
 * refreshed two timestamps and printed the digest of what it wrote) is refused
 * here rather than explained in a report.
 *
 * `requireInvocationId` defaults to "an invocation id was supplied", so the unit
 * cases that classify a synthetic record with no invocation of their own keep
 * working; `verify()` ALWAYS supplies the id it minted, and the gate below is
 * only ever skipped by a caller that has no invocation to compare against. The
 * TREE binding follows the same switch, because it means the same thing: a
 * record the aggregator did not ask to be written (the harness record on a check
 * run) is not required to be this run's, and a record that IS this run's is.
 * @param {object|null} record
 * @param {{invocationId?: string|null, headTreeSha?: string|null,
 *   requireInvocationId?: boolean, requireTreeBinding?: boolean, label?: string}} options
 * @returns {string[]} The issues, empty when the record is bound to this run.
 */
export function invocationBindingIssues(record, {
  invocationId = null, headTreeSha = null, requireInvocationId = invocationId !== null, requireTreeBinding = requireInvocationId, label = 'child record',
} = {}) {
  const issues = [];
  if (!isPlainObject(record)) {
    issues.push(`${label}: the record is unreadable, so nothing in it can be bound to this invocation`);
    return issues;
  }
  const tree = typeof record.head_tree_sha === 'string' && record.head_tree_sha.length > 0
    ? record.head_tree_sha
    : (typeof record.base?.tree_sha === 'string' && record.base.tree_sha.length > 0 ? record.base.tree_sha : null);
  if (requireTreeBinding) {
    if (tree === null) {
      issues.push(`${label}: it names no tree at all (no head_tree_sha and no base.tree_sha), so it is bound to no base`);
    } else if (typeof headTreeSha === 'string' && headTreeSha.length > 0 && tree !== headTreeSha) {
      issues.push(`${label}: it is bound to tree ${tree.slice(0, 12)} while this checkout is on ${headTreeSha.slice(0, 12)}`);
    }
  }
  if (requireInvocationId) {
    const own = typeof record.invocation_id === 'string' ? record.invocation_id : null;
    if (own === null || own.length === 0) {
      issues.push(`${label}: it carries no invocation_id, so nothing binds it to the run that produced it — a record that is not bound to this invocation is not this run's evidence`);
    } else if (own !== invocationId) {
      issues.push(`${label}: it was written by invocation ${own.slice(0, 12)}, not by this one (${String(invocationId).slice(0, 12)})`);
    }
  }
  return issues;
}

/**
 * THE HARNESS RECORD'S AGREEMENT WITH WHAT THIS RUN OBSERVED (G2).
 *
 * The harness record was read raw before this repair: a record whose `overall`
 * was FAIL, whose A1..A5 flags were all false and whose A3 claimed to be a
 * MEASUREMENT was reported as a PASS gate with exit 0 (reproduced, observed exit
 * 0, published `overall FAIL` beside `A1:FAILED..A5:FAILED`). Three claims are
 * therefore compared with the observation, and each disagreement is a defect:
 *   * `overall` must be PASS — a record that reports its own run as failed is
 *     not evidence of a green one, whatever the process it came from did;
 *   * every property flag must be `true`, and the failing ids are named;
 *   * a recorded exit code must equal the exit code THIS run saw. The member is
 *     optional (the delivered harness record carries none) and its absence is
 *     PUBLISHED as `exit_code_recorded: null` rather than treated as agreement:
 *     a record that says nothing cannot contradict anything, and the live exit
 *     code is judged on its own either way.
 * @param {object|null} record
 * @param {number|null} observedExitCode
 * @returns {string[]} The disagreements, empty when the record agrees.
 */
export function harnessAgreementIssues(record, observedExitCode) {
  const issues = [];
  if (!isPlainObject(record)) {
    issues.push('the harness record is unreadable, so none of its claims can be compared with what this run observed');
    return issues;
  }
  if (record.overall !== 'PASS') {
    issues.push(`the harness record reports overall=${String(record.overall)} while the harness process exited ${String(observedExitCode)}`);
  }
  if (!Array.isArray(record.properties) || record.properties.length === 0) {
    issues.push('the harness record carries no acceptance property, so none of A1..A5 was observed');
  } else {
    const notHeld = record.properties
      .filter((property) => !isPlainObject(property) || property.ok !== true)
      .map((property) => String(property?.id ?? 'unidentified'));
    if (notHeld.length > 0) {
      issues.push(`the harness record reports ${notHeld.join(', ')} as NOT held, so the record on disk contradicts the harness process this run observed`);
    }
  }
  if (Number.isInteger(record.exitCode) && record.exitCode !== observedExitCode) {
    issues.push(`the harness record reports exitCode=${record.exitCode} while this run observed ${String(observedExitCode)}`);
  }
  if (record.overall === 'PASS' && observedExitCode !== 0) {
    issues.push(`the harness record is green while the harness process exited ${String(observedExitCode)}; a green record written by a failing run is the exact shape of a fake green`);
  }
  return issues;
}

/**
 * THE HARNESS RECORD, judged the way the replay's is (G2): a digest THIS file
 * computes over the bytes it read, the invocation binding, and the agreement
 * check above. The digest is deliberately NOT compared with a digest the child
 * printed: the replay's printed digest is kept because the replay's bytes are
 * written by the run itself and the comparison catches a record that is not the
 * one this run produced, but a record that carries its own digest proves
 * nothing about itself — it is published instead, as the aggregator's own
 * reading of the bytes it judged.
 * @param {{exitCode: number|null, stdout?: string}} executed The child result this run observed.
 * @param {{invocationId?: string|null, headTreeSha?: string|null, requireInvocationId?: boolean,
 *   requireReportedDigest?: boolean}} options
 * @returns {{gate: object, evidence: object|null, evidence_sha256: string|null, evidence_bytes: number}}
 */
export function classifyCurrentHarness(executed, {
  invocationId = null, headTreeSha = null, requireInvocationId = invocationId !== null, requireReportedDigest = requireInvocationId,
} = {}) {
  const bytes = readHarnessBytes();
  if (bytes === null) {
    return {
      gate: { status: 'FAIL', exitCode: executed.exitCode, source: 'current S2-008 harness', reason: 'the harness record is absent; this run read no bytes to judge' },
      evidence: null,
      evidence_sha256: null,
      evidence_bytes: 0,
    };
  }
  // THE AGGREGATOR'S OWN DIGEST over the bytes it read.
  const evidenceSha256 = createHash('sha256').update(bytes).digest('hex');
  let record = null;
  try {
    record = JSON.parse(bytes.toString('utf8'));
  } catch {
    return {
      gate: { status: 'FAIL', exitCode: executed.exitCode, source: 'current S2-008 harness', reason: `the harness record is not readable JSON (sha256 ${evidenceSha256.slice(0, 12)}, ${bytes.length} bytes)` },
      evidence: null,
      evidence_sha256: evidenceSha256,
      evidence_bytes: bytes.length,
    };
  }
  // THE BYTES THIS RUN WROTE, when the chain asked for them. The harness prints
  // `HARNESS_EVIDENCE_SHA256 <hex>` over the exact bytes it wrote, and the
  // aggregator re-hashes what is on disk: a child that wrote one record and
  // reported the digest of another is refused. This is the one comparison that
  // is NOT a tautology — and it is only possible when the chain told the child
  // to write, which is why it is not demanded of a `--no-write` run (the line
  // then says `NOT_ON_DISK`, truthfully).
  if (requireReportedDigest) {
    const reported = /HARNESS_EVIDENCE_SHA256 ([0-9a-f]{64})/.exec(String(executed.stdout ?? ''));
    if (reported === null) {
      return {
        gate: { status: 'FAIL', exitCode: executed.exitCode, source: 'current S2-008 harness', reason: 'the harness reported no evidence digest, so the record on disk cannot be matched against the run that produced it' },
        evidence: record,
        evidence_sha256: evidenceSha256,
        evidence_bytes: bytes.length,
      };
    }
    if (reported[1] !== evidenceSha256) {
      return {
        gate: { status: 'FAIL', exitCode: executed.exitCode, source: 'current S2-008 harness', reason: `the record on disk is not the one this invocation wrote (reported ${reported[1].slice(0, 12)}, on disk ${evidenceSha256.slice(0, 12)})` },
        evidence: record,
        evidence_sha256: evidenceSha256,
        evidence_bytes: bytes.length,
      };
    }
  }
  const issues = [
    ...invocationBindingIssues(record, { invocationId, headTreeSha, requireInvocationId, label: 'the harness record' }),
    ...harnessAgreementIssues(record, executed.exitCode),
  ];
  if (issues.length > 0) {
    return {
      gate: { status: 'FAIL', exitCode: executed.exitCode, source: 'current S2-008 harness', reason: issues.join('; ') },
      evidence: record,
      evidence_sha256: evidenceSha256,
      evidence_bytes: bytes.length,
    };
  }
  return {
    gate: { status: gateStatusFromExit(executed.exitCode), exitCode: executed.exitCode, source: 'current S2-008 harness', reason: null },
    evidence: record,
    evidence_sha256: evidenceSha256,
    evidence_bytes: bytes.length,
  };
}

/**
 * THE PROBE AND CONTROL FLOORS (G3) — the numbers come from the FROZEN CODE and
 * never from the record, which is the whole point: a record that reports its own
 * count can report any count.
 *
 * Three shapes are separated, because they are three different answers:
 *   * a DEFECT is a check this stage performed and that failed — fewer probes or
 *     fewer controls than the frozen lists declare, a counter map that carries
 *     none of the declared hard-gate counters (the A1a stub printed `{}` and
 *     exited 0), or a counter that moved;
 *   * a NOT_RUN is a check this stage could not make — no counter map, no totals
 *     block, no integer count. `notRun` is never softened into a pass and never
 *     sharpened into a failure;
 *   * the declared counts themselves are published by the caller (`gates.probes
 *     .floor`) so a reader sees where the floor came from.
 * @param {object|null} record The probes gate's own JSON envelope.
 * @returns {{defects: string[], notRun: string[], declared: {probes: number, controls: number}}}
 */
export function probeFloorIssues(record, {
  declaredProbes = DECLARED_PROBE_COUNT, declaredControls = DECLARED_CONTROL_COUNT, hardGateCounters = HARD_GATE_COUNTERS,
} = {}) {
  const defects = [];
  const notRun = [];
  const counters = isPlainObject(record?.counters) ? record.counters : null;
  if (counters === null) {
    notRun.push('NOT_RUN: the probes gate reported no counter map');
  } else {
    // An EMPTY counter map made `Object.values(counters).every((v) => v === 0)`
    // vacuously true, so a gate that measured nothing looked exactly like a gate
    // that measured six defences and found them all intact. The declared
    // counter names come from `src/lib/research/probes.mjs`, so the map must
    // carry them or it reports nothing.
    const missing = hardGateCounters.filter((name) => !(name in counters));
    if (missing.length > 0) {
      defects.push(`probes gate: the hard-gate counter map reports none of the ${hardGateCounters.length} counters the frozen probe list declares (missing ${missing.join(', ')}); a counter map that reports nothing is a check that did not happen, not a check that passed`);
    }
    const moved = Object.entries(counters).filter(([, value]) => value !== 0).map(([name, value]) => `${name}=${value}`);
    if (moved.length > 0) defects.push(`hard-gate counters moved: ${moved.join(', ')}`);
  }
  const totals = isPlainObject(record?.totals) ? record.totals : null;
  if (totals === null) {
    notRun.push('NOT_RUN: the probes gate reported no totals, so the number of probes and controls it actually ran is unknown');
  } else {
    if (!Number.isInteger(totals.probes_ran)) {
      notRun.push('NOT_RUN: the probes gate reported no integer count of the probes it ran');
    } else if (totals.probes_ran < declaredProbes) {
      defects.push(`probes gate: ${totals.probes_ran} of the ${declaredProbes} probes the frozen probe list declares (src/lib/research/probes.mjs) were run`);
    }
    if (!Number.isInteger(totals.controls_ran)) {
      notRun.push('NOT_RUN: the probes gate reported no integer count of the controls it ran');
    } else if (totals.controls_ran < declaredControls) {
      defects.push(`probes gate: ${totals.controls_ran} of the ${declaredControls} controls the frozen control list declares (EXPECTED_CONTROLS + EXTRA_CONTROL_IDS) were run`);
    }
  }
  return { defects, notRun, declared: { probes: declaredProbes, controls: declaredControls, hard_gate_counters: hardGateCounters.length } };
}

/**
 * THE SECURITY-PROBES RECORD, READ BY THE CHAIN THAT OWNS IT (G5).
 *
 * `evidence/s2-008-security-probes.json` is the one record the chain writes
 * itself and therefore the one record no gate can require of a base it has not
 * been written on: the dependency gate excludes it from REQUIRED (the same
 * ORDERING statement `--chain-produced` makes for the other records), so the
 * chain owns whether it is there, and owning a record means reading it. Three
 * shapes, three answers:
 *   * ABSENT, on any run. The chain judged a probes gate from its stdout and
 *     published `probes PASS(exit=0)` beside a base that holds no security-probes
 *     evidence at all. That is the green-with-a-disclaimer shape this file
 *     exists to remove, so absence is a defect and not a note. A CHECK run on
 *     such a base stays red: it may not refresh the record it is reporting on,
 *     and the next WRITE run is the one that produces it.
 *   * PRESENT and, on a WRITE run, REPORTED. The child prints the record's path
 *     and its canonical digest when it writes it; the aggregator computes the
 *     canonical digest of the bytes it read and the two must be equal. The
 *     child cannot be asked to vouch for a file it did not write, and this way
 *     it does not have to: the aggregator reads the file itself.
 *   * PRESENT on a CHECK run, unbound. The chain did not ask for that record in
 *     this run, so provenance is PUBLISHED (`record_is_this_run: false`) and not
 *     demanded — the same asymmetry the harness record is judged under (see 3b),
 *     and for the same reason.
 *
 * Exported so `tests/research/gate-semantics.test.mjs` can drive the refusal
 * without spawning the chain.
 * @param {object|null} reported The child gate's own JSON summary, as parsed.
 * @param {{requireWrittenByThisRun?: boolean, read?: () => Buffer|null}} [options]
 * @returns {{present: boolean, readable: boolean, sha256: string|null, bytes: number|null,
 *   canonical_digest: string|null, reported_path: string|null, reported_digest: string|null,
 *   digest_agrees: boolean|null, issues: string[]}}
 */
export function classifyProbesRecord(reported, { requireWrittenByThisRun = false, read = readProbesRecordBytes } = {}) {
  const issues = [];
  const reportedPath = typeof reported?.path === 'string' ? reported.path : null;
  const reportedDigest = typeof reported?.digest === 'string' ? reported.digest : null;
  const empty = {
    present: false, readable: false, sha256: null, bytes: null, canonical_digest: null,
    reported_path: reportedPath, reported_digest: reportedDigest, digest_agrees: null, issues,
  };
  let bytes = null;
  try {
    bytes = read();
  } catch {
    bytes = null;
  }
  if (bytes === null) {
    issues.push(`the security-probes record (${PROBES_RECORD_RELATIVE}) is absent, so this run publishes no security-probes evidence for a base a reader can check; the next WRITE run produces it`);
    return empty;
  }
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  let parsed = null;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    issues.push(`the security-probes record (${PROBES_RECORD_RELATIVE}) is not readable JSON (sha256 ${sha256.slice(0, 12)}, ${bytes.length} bytes), so nothing in it can be read as this run's evidence`);
    return { ...empty, present: true, sha256, bytes: bytes.length };
  }
  const canonical = canonicalDigest(parsed);
  if (requireWrittenByThisRun) {
    if (reportedPath !== PROBES_RECORD_RELATIVE) {
      issues.push(`the probes gate reported writing ${reportedPath === null ? 'no record' : `\`${reportedPath}\``} while this run asked for ${PROBES_RECORD_RELATIVE}, so the record this chain owns was not written`);
    }
    if (reportedDigest === null) {
      issues.push(`the probes gate reported no digest for the record it wrote, so the bytes on disk cannot be matched against the run that produced them`);
    } else if (reportedDigest !== canonical) {
      issues.push(`the record on disk is not the one the probes gate reported writing (reported ${reportedDigest.slice(0, 12)}, on disk ${canonical.slice(0, 12)})`);
    }
  }
  return {
    present: true,
    readable: true,
    sha256,
    bytes: bytes.length,
    canonical_digest: canonical,
    reported_path: reportedPath,
    reported_digest: reportedDigest,
    digest_agrees: reportedDigest === null ? null : reportedDigest === canonical,
    issues,
  };
}

/** The security-probes record's bytes, exactly as they are on disk. The
 *  aggregator hashes and parses these itself; it never accepts a digest the
 *  record states about itself. */
function readProbesRecordBytes() {
  try {
    return readFileSync(path.join(REPO_ROOT, PROBES_RECORD_RELATIVE));
  } catch {
    return null;
  }
}

/**
 * PROVABILITY OVER THE WHOLE TRACK (G4) — not its first file.
 *
 * `scripts/verify-s2-008-dependencies.mjs` already computes the whole picture
 * (`track_files_tracked`, `track_files_untracked`, `track_files_modified`) and
 * the aggregator copied NONE of the last two, so `git rm --cached -r
 * src/lib/research tests/research` — 24 of 57 files still tracked — left this
 * chain at exit 0 with `defects []` while the dependency gate's own record named
 * 33 untracked files (reproduced, observed exit 0). The rule:
 *   * ANY untracked or MODIFIED track file is a defect, with the paths named. A
 *     modified gate script is the same hole from the other side: the integrity
 *     gates read committed bytes, so an uncommitted edit to this file is
 *     invisible to them until it is committed;
 *   * a `null` is a defect TOO. "The dependency gate said nothing" is not "the
 *     dependency gate found nothing", and reading it as the latter is how a
 *     partially untracked track came through green;
 *   * a file the gate expected and could not ACCOUNT for at all (tracked,
 *     untracked and modified, none of it) is a defect, because the report does
 *     not then cover the whole set it declared;
 *   * the all-untracked case keeps its own, older defect in `deriveVerdict`
 *     (`track_files_tracked === 0`) and still fails exactly as it did.
 *
 * The shapes are the dependency gate's own (`scripts/verify-s2-008-dependencies.mjs`):
 * `track_files_expected` is the frozen SET of paths this track is made of,
 * `track_files_tracked` the `git ls-files` count, and `track_files_untracked` /
 * `track_files_modified` / `track_files_unaccounted` lists of paths.
 *
 * `chainProduced` is the narrow exemption, and it is the same ORDERING statement
 * the dependency gate's `--chain-produced` makes: the seven records this chain's
 * own children write in this same run are the chain's business, and a gate that
 * demanded they be tracked and clean BEFORE the chain has run would be the
 * bootstrap trap in a new dress (it is the same reason a clean base is green on
 * the FIRST run). Every other track file — every source, every test, every
 * script, the whole corpus — is still blocking, and a MODIFIED corpus file is
 * still a defect: the drift gate and this rule then say the same thing about the
 * same bytes, which is the point of having two of them.
 * @param {object|null} dependencyGate The aggregator's `gates.dependency`.
 * @param {{chainProduced?: ReadonlyArray<string>}} [options]
 * @returns {string[]} The defects, empty when the whole track is provable.
 */
export function trackProvabilityDefects(dependencyGate, { chainProduced = CHAIN_WRITTEN_RECORDS } = {}) {
  const gate = isPlainObject(dependencyGate) ? dependencyGate : {};
  const defects = [];
  // The paths are NAMED, up to a bound, with the remainder counted: a defect
  // that says "33 files" and shows none of them is a defect nobody can act on.
  const name = (list) => {
    const shown = list.slice(0, 24).map(String);
    return `${shown.join(', ')}${list.length > shown.length ? `, …and ${list.length - shown.length} more` : ''}`;
  };
  const tracked = gate.track_files_tracked;
  if (!Number.isInteger(tracked)) {
    defects.push(`provability: the dependency gate reported no count of this track's tracked files (track_files_tracked=${JSON.stringify(tracked ?? null)}), so no artefact of this track is bound to a base a reader can check; delivery owns git`);
  } else if (tracked === 0) {
    defects.push('provability: the track\'s own files are untracked (git ls-files reports 0 of them), so no artefact of this track is bound to a base a reader can check; delivery owns git');
  }
  if (!Array.isArray(gate.track_files_expected) || gate.track_files_expected.length === 0) {
    defects.push(`provability: the dependency gate named no expected set of files for this track (track_files_expected=${JSON.stringify(gate.track_files_expected ?? null)}), so its untracked and modified lists cannot be read as a statement about the WHOLE track`);
  }
  const exempt = new Set(chainProduced);
  for (const [key, what] of [['track_files_untracked', 'untracked'], ['track_files_modified', 'modified'], ['track_files_unaccounted', 'unaccounted-for']]) {
    const list = gate[key];
    if (list === undefined) continue;
    if (!Array.isArray(list)) {
      defects.push(`provability: the dependency gate reported no ${what} track files (${key}=${JSON.stringify(list ?? null)}); "the gate said nothing" is not "the gate found nothing"`);
      continue;
    }
    const reported = list.filter((entry) => !exempt.has(String(entry)));
    if (reported.length > 0) {
      defects.push(`provability: ${reported.length} ${what} file(s) of this track are not bound to a base a reader can check (${key}): ${name(reported)}`);
    }
  }
  return defects;
}

/**
 * The paths the provability rule above EXEMPTED, with the reason, published so
 * the exemption is visible instead of silent. Exempt means "this chain writes it
 * in this run", never "it does not matter".
 * @param {object|null} dependencyGate The aggregator's `gates.dependency`.
 * @param {{chainProduced?: ReadonlyArray<string>}} [options]
 * @returns {string[]}
 */
export function chainProducedExemptions(dependencyGate, { chainProduced = CHAIN_WRITTEN_RECORDS } = {}) {
  const gate = isPlainObject(dependencyGate) ? dependencyGate : {};
  const exempt = new Set(chainProduced);
  const seen = [];
  for (const key of ['track_files_untracked', 'track_files_modified', 'track_files_unaccounted']) {
    for (const entry of (Array.isArray(gate[key]) ? gate[key] : [])) {
      if (exempt.has(String(entry)) && !seen.includes(String(entry))) seen.push(String(entry));
    }
  }
  return seen;
}

/**
 * THE AGGREGATOR CONTRACT: the report of THIS invocation and the record on disk
 * must be the same bytes, the record must be bound to THIS invocation, and it
 * must be fresh. A previous green file can therefore never turn a current
 * NOT_RUN or FAIL into a PASS.
 */
export function classifyCurrentReplay(executed, writtenEvidence, {
  headTreeSha = null, observedAtIso = null, windowMs = FRESHNESS_WINDOW_MS, invocationId = null,
} = {}) {
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
  // G1, THE INVOCATION BINDING. The digest above proves the record on disk is
  // the file the child wrote THIS PROCESS — and a stub that writes the previous
  // honest record and prints the digest of what it wrote satisfies it exactly.
  // What a copied record cannot reproduce is the id this aggregator minted and
  // handed the child as `--invocation-id`, so that is what is required here. A
  // child that does not yet understand the flag writes no id, and a record with
  // no id is REFUSED: the safe direction is a red gate, never a green one.
  const bindingIssues = invocationBindingIssues(writtenEvidence, {
    invocationId, headTreeSha, label: 'the replay record',
  });
  if (bindingIssues.length > 0) {
    return {
      gate: { status: 'FAIL', exitCode: executed.exitCode, source: 'current S2-008 replay', reason: bindingIssues.join('; ') },
      evidence: writtenEvidence,
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
  // S6 / EV2, REPAIRED BY R-C: FIVE TERMS, not one, and the campaign VERDICT is
  // not among them. `overall === 'PASS'` already counts the properties, the
  // ledger shape and NOT_RUN (see the replay's `overall_terms`), and each is
  // re-read here from the record's own block so this aggregator does not have
  // to trust the summary it just read.
  //
  // Two terms were REMOVED and two were ADDED:
  //   * `verdict_is_pass` is gone. With eight synthetic cases the honest
  //     campaign answer is a null, and requiring ALLOW was unsatisfiable
  //     without tuning the fixtures until a fabricated effect looked
  //     legitimate. A NULL or UNMET campaign is an ANSWER, recorded as such;
  //   * the bare `verdict !== 'PASS'` refusal went with it, for the same
  //     reason and in the same commit — a record that reports its FAIL verdict
  //     and agrees with the table is the SUCCESS case, not a defect;
  //   * `decision_agrees_with_table`, `controls_all_flipped` and
  //     `not_run_zero` are the terms that carry the weight ALLOW used to.
  // The staleness, freshness, bytes, run-identity and property-status refusals
  // around this block are untouched, and a fabricated POSITIVE against the
  // frozen non-positive expectation is refused by the direct comparison below,
  // which reads the IN-CODE expectation and not the record's own claim.
  const terms = isPlainObject(writtenEvidence.overall_terms) ? writtenEvidence.overall_terms : null;
  const campaign = campaignDecisionAgreement({
    observed: writtenEvidence.observed_campaign_decision ?? writtenEvidence.comparison?.runs?.a?.decision ?? null,
    expected: frozenCampaignDecision(),
  });
  const greenReasons = [];
  if (writtenEvidence.overall !== 'PASS') greenReasons.push(`overall=${String(writtenEvidence.overall)}`);
  if (writtenEvidence.ledger_shape_ok !== true) {
    greenReasons.push(`ledger_shape_ok=${String(writtenEvidence.ledger_shape_ok)} findings=${String(writtenEvidence.overall_terms?.ledger_shape_findings ?? 'n/a')}`);
  }
  if (terms === null) greenReasons.push('overall_terms absent');
  else if (terms.decision_agrees_with_table !== true
    || terms.controls_all_flipped !== true
    || terms.every_property_held !== true
    || terms.ledger_shape_matches_table !== true
    || terms.not_run_zero !== true
    // F1: re-read HERE and not only in the child. `verdict_is_pass` is gone
    // because a null answer is an answer, and the term that replaced it must not
    // be a member only the child evaluates — a record whose own terms block
    // says an UNDECLARED comparator failure was raised is refused here, with
    // the findings named, whatever the child reported.
    || terms.comparator_failures_match_frozen_expectation !== true
    || (Array.isArray(terms.unexpected_comparator_findings) && terms.unexpected_comparator_findings.length > 0)) {
    greenReasons.push(`overall_terms=${JSON.stringify(terms)}`);
    for (const entry of (terms?.unexpected_comparator_findings ?? [])) {
      greenReasons.push(`undeclared comparator failure ${String(entry?.field)} observed=${String(entry?.observed)} expected=${String(entry?.expected)}`);
    }
  }
  if (!campaign.agrees) {
    for (const finding of campaign.findings) greenReasons.push(`${finding.code}:${String(finding.detail)}`);
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

/** The harness record's bytes, exactly as they are on disk. The aggregator
 *  hashes these itself (see `classifyCurrentHarness`); it never accepts a digest
 *  the record states about itself. */
function readHarnessBytes() {
  try {
    return readFileSync(path.join(REPO_ROOT, HARNESS_RELATIVE));
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
 *  never softened into a pass. Exported so the gate-semantics tests can drive
 *  the verdict cases with the SAME mapping a real run applies, rather than with
 *  a hand-typed status. */
export function gateStatusFromExit(exitCode) {
  if (exitCode === 0) return 'PASS';
  if (exitCode === 3) return 'NOT_RUN';
  if (exitCode === 1) return 'FAIL';
  return `NOT_RUN_UNMAPPED_EXIT_${String(exitCode)}`;
}

/**
 * THE SCOPE NOTES (F2) — the statements that are neither a defect nor a
 * gate-level NOT_RUN, because they answer a DIFFERENT question: not "did a
 * check this stage owns hold?" and not "could such a check be made?", but
 * "what does this track NOT decide, and whose answer is authoritative?".
 *
 *   * the A3-ownership note: the harness's A3 declares itself
 *     `TABLE_DERIVED_RUN_RECORDS`, so its agreement count is definitional and
 *     the replay's A3 is the measurement. This says WHICH GATE OWNS a
 *     property; both gates ran, and `crossRecordAgreement` already refused a
 *     harness A3 that claims a measurement it did not make; and
 *   * the #45 scope statement: the campaign behind issue #45 is NOT_RUN, so this
 *     deterministic track does not decide the ticket's own scope.
 *
 * They are RETURNED, not thrown away, and `verify` puts them in the summary's
 * `scopeNotes` and the printed output. What they no longer do is vote: they used
 * to be pushed into `notRun`, whose `length > 0` forces NOT_RUN, so a pair of
 * notes that are present on every single run made this aggregator report
 * `NOT_RUN` with an empty defect list and exit 3 forever, with all five gates
 * PASS. A note that is always true cannot be evidence about the run.
 * @param {{verdict: string, note: string}} crossRecord The result of
 *   `crossRecordAgreement` for this run.
 * @returns {string[]} The non-binding notes, in the order they are printed.
 */
export function ticketScopeNotes(crossRecord) {
  const notes = [];
  if (crossRecord?.verdict === 'NOT_COMPARABLE_DISCLOSED') {
    notes.push(`the harness's A3 is table-derived, not a measurement (${crossRecord.note}); the authoritative A3 is the replay's`);
  }
  notes.push('the campaign behind #45 is NOT_RUN, so this deterministic track does not decide the ticket\'s own scope');
  return notes;
}

/**
 * THE DERIVED VERDICT — F1, F2, F3, in ONE place, and exported so
 * `tests/research/gate-semantics.test.mjs` pins the decision with the same code
 * a real run executes rather than with a re-implementation of it.
 *
 * THREE KINDS OF STATEMENT, AND ONLY ONE OF THEM DECIDES (EV5, repaired):
 *
 *   1. BLOCKING DEFECTS — a check this stage DID perform and that failed, plus
 *      the ticket-level precondition that provability is a hard requirement of
 *      this repository. A blocking gate, a provability defect, or ANY entry in
 *      `defects` is `FAIL` (exit 1). The `defects` term is what this repair
 *      closed: `defects` was BUILT as the list of failed checks and then not
 *      read by the status, so a defect this file raised on its own — a
 *      harness/replay A3 disagreement, a refused child record, a track file that
 *      is untracked or modified — was printed beside `ok: true` and `exitCode: 0`
 *      whenever no gate's own status had flipped with it. A summary that lists a
 *      defect and reports a pass is the green-with-a-disclaimer shape this file
 *      exists to remove, and it was still reachable through the `defects` term
 *      alone. Nothing became more permissive: every run that reported a defect
 *      and no blocking gate was already wrong, and is now red.
 *   2. GATE-LEVEL NOT_RUNs — "I could not check": a gate that could not run, a
 *      mandatory probe or control that did not run, a cross-process replay that
 *      did not complete, a hard-gate counter map the probes gate did not report.
 *      Every one of them is `NOT_RUN` (exit 3) and none is ever a pass. Both
 *      `notRunGates` (the gates whose own status is NOT_RUN) and `notRun` (the
 *      named reasons) are read, because one gate-level NOT_RUN is reportable
 *      without that gate's own status flipping — the probes gate that exits 0
 *      and printed no counter map is the case that needs the second term, and
 *      dropping it would turn a check this stage could not make into a PASS.
 *   3. SCOPE NOTES — see `ticketScopeNotes`. They are recorded in the summary
 *      and in the printed output, and they CANNOT decide anything: a scope note
 *      is not an answer to the question the verdict asks. It never says whether
 *      a check this stage owns was performed or what it found — it says what
 *      the track does not decide — so a note that can veto is a gate whose
 *      verdict a constant decides, and a constant present on every run makes
 *      the gate permanently NOT_RUN while every gate it aggregates is PASS.
 *
 * F3, THE ONE PLACE THIS REPAIR IS STRICTER THAN THE FILE IT REPLACED: the
 * track's own files being untracked used to be a soft note. Provability is a
 * hard requirement here — an untracked track is bound to no base a reader can
 * check — so it is a blocking DEFECT now, and the aggregator goes RED (exit 1)
 * instead of yellow. Nothing else became stricter or more permissive: a gate
 * that could not run still yields `NOT_RUN` and exit 3, a failed gate is still
 * `FAIL` and exit 1, and a scope note still cannot fail a run.
 * @param {{gates?: object, defects?: string[], notRun?: string[], scopeNotes?: string[]}} input
 * @returns {{status: string, ok: boolean, exitCode: number, defects: string[],
 *   notRun: string[], scopeNotes: string[], blockingGates: string[],
 *   notRunGates: string[], provabilityDefects: string[]}}
 */
export function deriveVerdict({ gates = {}, defects = [], notRun = [], scopeNotes = [] } = {}) {
  // The gate statuses are read, never averaged: one NOT_RUN is a NOT_RUN.
  const blocking = Object.entries(gates).filter(([, gate]) => gate.status === 'FAIL' || gate.status === 'BLOCKED_DEPENDENCY' || String(gate.status).startsWith('NOT_RUN_UNMAPPED'));
  const notRunGates = Object.entries(gates).filter(([, gate]) => gate.status === 'NOT_RUN' || String(gate.status).startsWith('NOT_RUN_UNMAPPED'));
  // F3: the provability precondition, as a blocking defect. `git ls-files`
  // counts this track's own files; zero of them means no artefact here is bound
  // to a base, and the two integrity gates that would have noticed are green for
  // the wrong reason. Previously a note (and then a NOT_RUN entry); now RED.
  // The test is the strict `=== 0` and NOT `Number(x) === 0`: a dependency gate
  // that reported `null` (it said nothing) is not a gate that reported ZERO, and
  // a coercion would turn a missing report into a fabricated failure.
  const provabilityDefects = gates.dependency?.track_files_tracked === 0
    ? ['provability: the track\'s own files are untracked (git ls-files reports 0 of them), so no artefact of this track is bound to a base a reader can check; delivery owns git']
    : [];
  // F1: the status reads the GATE-LEVEL terms and the blocking defects, and
  // `notRun` now holds gate-level entries only — a scope note cannot reach it,
  // so the two notes that are present on every run can no longer decide this.
  // `defects.length > 0` decides as well, and that is the term this repair
  // closed: a defect this file raised with no gate status to back it used to be
  // printed beside `ok: true`.
  const status = blocking.length > 0 || provabilityDefects.length > 0 || defects.length > 0
    ? 'FAIL'
    : (notRunGates.length > 0 || notRun.length > 0 ? 'NOT_RUN' : 'PASS');
  return {
    status,
    ok: status === 'PASS',
    exitCode: status === 'PASS' ? 0 : (status === 'NOT_RUN' ? 3 : 1),
    defects: [...defects, ...provabilityDefects],
    notRun: [...notRun],
    scopeNotes: [...scopeNotes],
    blockingGates: blocking.map(([id]) => id),
    notRunGates: notRunGates.map(([id]) => id),
    provabilityDefects,
  };
}

export function verify(args = {}) {
  // The instant the run BEGAN, recorded so a reader can see how long the gate
  // took. It is deliberately NOT the instant the evidence is judged at: see
  // `nowIso` below.
  const startedAtIso = nowIso();
  const base = resolveBase();
  // THE INVOCATION ID (G1). One per run, minted here, handed to both child gates
  // as `--invocation-id <id>`, and required back in the records they write. It is
  // the only random value on this path and it is EXCLUDED FROM REPEATABILITY,
  // exactly like the freshness observation: it decides only whether a record is
  // the current run's, never what a measurement is. `verify({ invocationId })`
  // accepts one so a test can drive the refusal with a known id.
  const invocationId = typeof args.invocationId === 'string' && args.invocationId.length > 0
    ? args.invocationId
    : newInvocationId();
  // Whether this run is a CHECK. It is read HERE, before the first child is
  // spawned, because it decides how the harness is spawned (see 3b): a check run
  // must not rewrite the record it is about to judge, and a write run must
  // produce a record bound to THIS invocation or the binding is vacuous.
  const noWrite = args.noWrite === true || args.no_write === true || args.nowrite === true;
  const gates = {};
  const notRun = [];
  const defects = [];

  // 1. the dependency gate
  //
  // G5, BOOTSTRAP ORDERING. This gate runs BEFORE the aggregator spawns the
  // replay that writes `evidence/s2-008-replay.json`, while it listed that
  // record as REQUIRED — so the FIRST chain run on a clean base was red for the
  // existence of a file the chain had not written yet (reproduced: `rm -f
  // evidence/s2-008-replay.json` and the chain three times -> exit 1, defect
  // `evidence-absent:evidence/s2-008-replay.json`, then exit 0, exit 0). Not a
  // false green — the chain owns the records it writes and is what checks them —
  // but a gate whose FIRST answer is about ORDERING answers the wrong question.
  // `--chain-produced <paths>` is that gate's explicit flag for it: the listed
  // records are excluded from REQUIRED, still read, still reported with their
  // presence, and the chain owns them. WITHOUT the flag the gate's behaviour is
  // byte-for-byte what it was, so `npm run verify:s2-008-dependencies` keeps its
  // own contract. The list below is the set of records this chain's children
  // write AFTER this gate, and it is a CONSTANT rather than a set of whatever
  // happens to exist: a list assembled from the filesystem is a list that
  // shrinks when the filesystem does.
  const dependency = runNode('scripts/verify-s2-008-dependencies.mjs', [
    '--chain-produced', CHAIN_PRODUCED_RECORDS.join(','),
    '--invocation-id', invocationId,
  ]);
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
    // G4: the WHOLE track, not its first file. The dependency gate already
    // computes the untracked and modified lists; the aggregator copied neither,
    // so a PARTIALLY untracked track (24 of 57 files still tracked) came through
    // this chain at exit 0 with `defects []` while the dependency gate's own
    // record named 33 untracked files. All three counts are copied here and read
    // by `trackProvabilityDefects` below.
    track_files_expected: dependencyRecord?.track_files_expected ?? null,
    track_files_expected_count: dependencyRecord?.track_files_expected_count ?? null,
    track_files_unaccounted: dependencyRecord?.track_files_unaccounted ?? null,
    track_files_tracked: dependencyRecord?.track_files_tracked ?? null,
    track_files_untracked: dependencyRecord?.track_files_untracked ?? null,
    track_files_modified: dependencyRecord?.track_files_modified ?? null,
  };
  if (dependency.exitCode === 3) notRun.push('NOT_RUN: the dependency gate could not run');
  else if (dependency.exitCode !== 0) defects.push(`dependency gate: ${gates.dependency.status} (${(dependencyRecord?.issues ?? []).join(', ')})`);

  // 1b. THE CORPUS DRIFT GATE (F2 / F3).
  //
  //     `s2-008:check-corpus` was never part of this chain: `grep -n
  //     'check-corpus|build-corpus' scripts/verify-s2-008.mjs` had no match, so a
  //     manifest whose bytes moved in the WORKING TREE survived every gate here
  //     — the replay re-derives its own table digest, and the committed
  //     `preregistration.json` is what it reads, but nothing here asked whether
  //     the corpus the runs scored against is the corpus the fixture produces.
  //     Two digests were dead on this path (`manifest.case_digests` is now
  //     verified at read time in `dataset.mjs`, and the whole-manifest drift is
  //     checked here), and the exit-code vocabulary is the gate's own: 0 is
  //     PASS, 1 is a FAIL with the drifted file names in `drift`, and 2 is a
  //     refusal the builder raised before it could check (NOT_RUN, never a
  //     pass).
  const corpusCheck = runNode('scripts/s2-008-build-corpus.mjs', [
    '--check',
    ...(args.corpus === undefined ? [] : ['--out', String(args.corpus)]),
  ]);
  const corpusRecord = parseLastJson(corpusCheck.stdout);
  // The builder REFUSES (an uncaught throw) rather than reporting drift when the
  // frozen rule, the table or the supersession chain does not hold, and a
  // refusal exits 1 as well. Both are FAIL — a refusal is not a pass — but the
  // defect message has to name WHICH happened, so the two are told apart by
  // whether the builder managed to print its drift report.
  const corpusRefusal = corpusCheck.exitCode === 1 && corpusRecord === null
    ? `${corpusCheck.stderr.trim().split('\n')[0] ?? 'the builder raised before it could report'}`
    : null;
  gates.corpus = {
    status: corpusCheck.exitCode === 0 ? 'PASS' : (corpusCheck.exitCode === 1 ? 'FAIL' : 'NOT_RUN'),
    exitCode: corpusCheck.exitCode,
    source: 'scripts/s2-008-build-corpus.mjs --check',
    drift: corpusRecord?.drift ?? null,
    refusal: corpusRefusal,
    // WHY THIS GATE IS ABOUT THE WORKING TREE, stated because the root manifest
    // gate is not: `scripts/generate-manifests.mjs` reads its bytes with
    // `git show HEAD:<file>`, so `npm run manifest:check` validates the
    // committed inventory and cannot see an uncommitted edit (reproduction F3,
    // observed exit 0 on a tampered manifest). This gate re-derives from the
    // fixture on disk, so a tamper that is not yet committed is refused HERE.
    reads: 'the working tree, re-derived from tests/research/fixtures/**',
  };
  if (gates.corpus.status === 'NOT_RUN') notRun.push('NOT_RUN: the corpus drift check could not run');
  else if (gates.corpus.status === 'FAIL') {
    defects.push(corpusRefusal !== null
      ? `corpus gate: FAIL (${corpusRefusal})`
      : `corpus gate: FAIL (drift in ${(corpusRecord?.drift ?? ['unknown']).join(', ')}); the committed corpus no longer matches the frozen fixture`);
  }

  // 2. the probes gate
  //
  // G5, THE MODE FOLLOWS THIS RUN'S MODE, for the same reason the harness's
  // does (see 3b): a CHECK run must not rewrite a record it is about to judge,
  // and a WRITE run must produce the record the chain then owns. This gate used
  // to be spawned with no mode at all, and `scripts/s2-008-security-probes.mjs`
  // writes its record ONLY under `--write` — so that record was the one
  // REQUIRED record the chain could not produce, and a base on which it had
  // never been written was red on its FIRST run for a file the chain writes
  // itself (reproduced, observed exit 1, defect `dependency gate:
  // BLOCKED_DEPENDENCY (evidence-absent:evidence/s2-008-security-probes.json)`,
  // and the second and third runs exit 0). The fix is not a wider exemption: it
  // is that the chain writes the record.
  const probes = runNode('scripts/s2-008-security-probes.mjs', [
    ...(args.corpus === undefined ? [] : ['--corpus', String(args.corpus)]),
    ...(noWrite ? [] : ['--write']),
  ]);
  const probesRecord = parseLastJson(probes.stdout);
  // G3, THE FLOORS. The numbers the record reports are compared with the numbers
  // the FROZEN probe list and control list declare in the CODE. Before this, the
  // counters were checked for "every value is 0" (which an empty map satisfies
  // vacuously) and `totals` was stored and compared with nothing, so a probes
  // gate stub that ran no probe and no control, printed `{"counters":{},
  // "totals":{"probes_ran":0,"controls_ran":0}}` and exited 0 was a PASS gate
  // (reproduced, observed exit 0, and the summary published those zeroes).
  const floors = probeFloorIssues(probesRecord);
  // G5, THE RECORD THE CHAIN OWNS. `evidence/s2-008-security-probes.json` is in
  // `CHAIN_PRODUCED_RECORDS`, so the dependency gate no longer REQUIRES it and
  // the chain is what owns it. Owning a record means reading it, and the reading
  // is the aggregator's own: the bytes on disk, their sha256, and — on a WRITE
  // run, the one that produced them — the canonical digest the child reported
  // compared with the canonical digest the aggregator computes over the bytes it
  // read. A child that says it wrote one record and leaves another is refused.
  const probesFile = classifyProbesRecord(probesRecord, { requireWrittenByThisRun: !noWrite });
  // The GATE's own status is the aggregator's judgement of that gate, not a copy
  // of the child's exit code: a probes gate that ran nothing exits 0, and
  // publishing `PASS(exit=0)` beside a chain that is red over it would be the
  // green-with-a-disclaimer shape all over again. A failed floor is FAIL, an
  // unmade check is NOT_RUN, and neither is ever softened.
  const floorStatus = floors.defects.length > 0 ? 'FAIL' : (floors.notRun.length > 0 ? 'NOT_RUN' : null);
  gates.probes = {
    status: floorStatus ?? gateStatusFromExit(probes.exitCode),
    exitCode: probes.exitCode,
    source: 'scripts/s2-008-security-probes.mjs',
    counters: probesRecord?.counters ?? null,
    totals: probesRecord?.totals ?? null,
    reasons: probesRecord?.reasons ?? null,
    // WHY the status above is not the child's exit code, when it is not.
    floor_issues: [...floors.defects, ...floors.notRun],
    // G5: the record this chain owns, read by this file. `record_is_this_run`
    // is `false` on a check run — the chain spawned the gate with no `--write`,
    // so the file is an EARLIER run's committed artefact and is judged for
    // presence and readability, not for provenance.
    record_path: PROBES_RECORD_RELATIVE,
    record_present: probesFile.present,
    record_sha256: probesFile.sha256,
    record_bytes: probesFile.bytes,
    record_digest: probesFile.canonical_digest,
    record_digest_reported: probesFile.reported_digest,
    record_digest_agrees: probesFile.digest_agrees,
    record_is_this_run: !noWrite,
    record_issues: probesFile.issues,
    // Published so a reader sees WHERE the floor came from: a number out of the
    // record is not a floor, it is a claim.
    floor: {
      ...floors.declared,
      read_from: 'src/lib/research/probes.mjs (PROBE_FAMILIES, PROBE_NAMES, HARD_GATE_COUNTERS) and the frozen control list (EXPECTED_CONTROLS + EXTRA_CONTROL_IDS)',
      rule: 'fewer probes or fewer controls than the code declares is a defect; a counter map that reports none of the declared counters is a defect, not a pass',
    },
  };
  if (probes.exitCode === 3) notRun.push('NOT_RUN: a mandatory probe or control did not run');
  else if (probes.exitCode !== 0) defects.push(`probes gate: ${gates.probes.status} (${(probesRecord?.reasons ?? []).join(', ')})`);
  // The hard-gate counters and the probe/control FLOORS, read from the gate's
  // own report and compared against the code — never against the record.
  defects.push(...floors.defects);
  notRun.push(...floors.notRun);
  // G5, THE RECORD. Its issues are DEFECTS, and they decide the run (see
  // `deriveVerdict`) without being folded into `gates.probes.status`: that
  // status is the aggregator's reading of the CHILD, and a defect about the
  // file the child left on disk is a different statement. The two are printed
  // side by side on purpose — a reader sees the gate was green AND sees why the
  // chain was not.
  defects.push(...probesFile.issues.map((issue) => `probes record: ${issue}`));

  // 3. the cross-process replay, spawned BY THE AGGREGATOR, with THIS
  //    invocation's id (G1).
  const replayArgs = [
    ...(args.corpus === undefined ? [] : ['--corpus', String(args.corpus)]),
    '--invocation-id', invocationId,
  ];
  const replay = runNode('scripts/s2-008-replay.mjs', replayArgs);
  const replayRecord = readJson(REPLAY_RELATIVE);
  // The instant this record is JUDGED at, sampled AFTER the child returned (see
  // `nowIso`).
  const replayObservedAtIso = nowIso();
  const classified = classifyCurrentReplay(replay, replayRecord, {
    headTreeSha: base.tree_sha,
    observedAtIso: replayObservedAtIso,
    windowMs: Number.isFinite(args.freshnessWindowMs) ? args.freshnessWindowMs : FRESHNESS_WINDOW_MS,
    invocationId,
  });
  gates.replay = {
    status: classified.gate.status,
    exitCode: replay.exitCode,
    stale: classified.gate.stale ?? false,
    reason: classified.gate.reason ?? null,
    source: 'scripts/s2-008-replay.mjs',
    overall: classified.evidence?.overall ?? null,
    // G1, published: the id the record had to carry, and the tree it had to be
    // bound to. A reader can check both without re-running the chain.
    invocation_id: classified.evidence?.invocation_id ?? null,
    head_tree_sha: classified.evidence?.head_tree_sha ?? classified.evidence?.base?.tree_sha ?? null,
    // R-C: the campaign's ANSWER is reported next to the gate status, so a
    // reader of one file sees both. It decides nothing.
    campaign_verdict: classified.evidence?.verdict ?? null,
    expected_campaign_decision: classified.evidence?.expected_campaign_decision ?? null,
    observed_campaign_decision: classified.evidence?.observed_campaign_decision ?? null,
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
  //
  // G2, HOW THE HARNESS IS SPAWNED. The defect (F, reproduced twice) was that the
  // record was read raw AND that a CHECK run rewrote it: `--no-write` was passed
  // only when `--corpus` was, so `verify-s2-008.mjs --no-write` erased a marker a
  // reader had put into `evidence/s2-008-harness.json` (observed exit 0), while
  // the file's own comment said a check must not touch the evidence it inspects.
  // So the mode follows THIS run's mode:
  //   * a CHECK run (`--no-write`) spawns the harness with `--no-write`, and the
  //     record on disk is the COMMITTED artefact it is — an EARLIER run's record,
  //     by construction. It is judged for what an earlier record can still be
  //     judged for: it must AGREE with the process this run just observed (its
  //     `overall` PASS, every property flag true, a recorded exit code that
  //     agrees), and the invocation id and tree it names are PUBLISHED so a
  //     reader can see which run it belongs to. The id is NOT demanded of it: a
  //     record the chain did not ask to be written cannot name the chain's id,
  //     and demanding it anyway would make every check run red over a file the
  //     check is forbidden to refresh;
  //   * a WRITE run spawns the harness with `--write`, so the record on disk IS
  //     this run's, and then the invocation id, the tree AND the printed digest
  //     are all REQUIRED (G1). Without them the binding would be vacuous.
  // Either way the record is judged by `classifyCurrentHarness`: a digest THIS
  // file computes over the bytes it read, and the agreement check against the
  // exit code this run observed.
  const harness = runNode('scripts/s2-008-harness.mjs', [
    ...(args.corpus === undefined ? [] : ['--corpus', String(args.corpus)]),
    noWrite ? '--no-write' : '--write',
    '--invocation-id', invocationId,
  ]);
  // Sampled after the harness returned, for the same reason as the replay's.
  const harnessObservedAtIso = nowIso();
  const harnessClassified = classifyCurrentHarness(harness, {
    invocationId,
    headTreeSha: base.tree_sha,
    requireInvocationId: !noWrite,
    requireReportedDigest: !noWrite,
  });
  const harnessRecord = harnessClassified.evidence;
  gates.harness = {
    status: harnessClassified.gate.status,
    exitCode: harness.exitCode,
    source: 'scripts/s2-008-harness.mjs',
    observed_at: harnessObservedAtIso,
    // G2: the aggregator's OWN digest of the bytes it judged, and how the
    // record was bound. Neither is a claim the record makes about itself.
    evidence_sha256: harnessClassified.evidence_sha256,
    evidence_bytes: harnessClassified.evidence_bytes,
    // `false` on a check run: the chain spawned the harness with `--no-write`,
    // so the record it judged is an EARLIER run's committed record and is judged
    // for AGREEMENT with the process this run observed, not for provenance.
    record_is_this_run: !noWrite,
    invocation_id_required: !noWrite,
    invocation_id: harnessRecord?.invocation_id ?? null,
    head_tree_sha: harnessRecord?.head_tree_sha ?? harnessRecord?.base?.tree_sha ?? null,
    // REPORTED, not required, on a check run: the committed record names the
    // tree it was produced on, and a reader can see at a glance whether that is
    // this checkout's. Demanding it of a record the chain may not refresh would
    // make the gate red after every commit, which is the ordering trap G5 exists
    // to remove.
    head_tree_sha_matches: (harnessRecord?.head_tree_sha ?? harnessRecord?.base?.tree_sha ?? null) === base.tree_sha,
    exit_code_recorded: Number.isInteger(harnessRecord?.exitCode) ? harnessRecord.exitCode : null,
    overall: harnessRecord?.overall ?? null,
    // R-C, both gates: the campaign VERDICT is the honest answer and is
    // reported. It is not, and never was, the thing a green here means.
    verdict: harnessRecord?.verdict ?? null,
    expected_campaign_decision: harnessRecord?.expected_campaign_decision ?? null,
    observed_campaign_decision: harnessRecord?.observed_campaign_decision ?? null,
    decision_agrees_with_table: harnessRecord?.decision_agrees_with_table ?? null,
    properties: (harnessRecord?.properties ?? []).map((property) => `${property.id}:${property.ok ? 'HELD' : 'FAILED'}`),
    reason: harnessClassified.gate.reason ?? null,
  };
  if (gates.harness.status === 'NOT_RUN') notRun.push(`NOT_RUN: the harness could not run every property${gates.harness.reason === null ? '' : ` (${gates.harness.reason})`}`);
  else if (gates.harness.status !== 'PASS') defects.push(`harness gate: ${gates.harness.status} (${gates.harness.reason ?? harnessRecord?.overall ?? 'unknown'})`);
  const crossRecord = crossRecordAgreement(harnessRecord, classified.evidence);
  if (crossRecord.issues.length > 0) {
    defects.push(`harness/replay A3 disagreement: ${crossRecord.issues.join('; ')}`);
  }
  // F2: the two informational statements leave `notRun` and become
  // `scopeNotes` — recorded, printed, and unable to decide the verdict. They are
  // BUILT by `ticketScopeNotes` and DERIVED by `deriveVerdict`, which is what
  // tests/research/gate-semantics.test.mjs pins; nothing here re-types a note.
  const scopeNotes = ticketScopeNotes(crossRecord);
  // 4. THE DERIVED VERDICT: ONE STATUS, THREE KINDS OF STATEMENT, AND ONLY THE
  //    FIRST TWO DECIDE IT. The rule itself is `deriveVerdict` (exported, and
  //    pinned by tests/research/gate-semantics.test.mjs); this paragraph is the
  //    honest description of what it does.
  //
  //    EV5: THIS USED TO BE A GREEN SUMMARY THAT CONTRADICTED ITS OWN DEFECTS —
  //    it computed a PASS and then pushed a disclaimer into `defects` while
  //    also setting `ok: true` and `exitCode: 0`. The repair is a three-way
  //    split, because "a check failed", "a check could not be made" and "this
  //    track does not decide that" are three different claims, and only the
  //    first two are about this run's own work:
  //
  //      1. BLOCKING DEFECTS (`defects`, `blockingGates`) — a check this stage
  //         DID perform and that failed (a gate that exited 1, a drifted corpus,
  //         a moved hard-gate counter, a harness/replay A3 disagreement), plus
  //         the ticket-level precondition that PROVABILITY is a hard requirement
  //         of this repository. `FAIL`, exit 1.
  //      2. GATE-LEVEL NOT_RUNs (`notRun`, `notRunGates`) — "I could not
  //         check": the dependency gate that could not run, the corpus check
  //         that could not run, a mandatory probe or control that did not run,
  //         the cross-process replay that did not complete, the hard-gate
  //         counter map the probes gate did not report, the harness that could
  //         not run every property. `NOT_RUN`, exit 3, never a pass and never a
  //         soft pass: a gate that could not run still yields exit 3, and that
  //         path is unchanged by this repair.
  //      3. NON-BINDING SCOPE NOTES (`scopeNotes`) — statements about WHAT THIS
  //         TRACK DOES NOT DECIDE, never about a check it owns: which gate OWNS
  //         a property (the harness's A3 is table-derived, so the replay's A3 is
  //         the authoritative one) and the SCOPE of the ticket (the campaign
  //         behind #45 is NOT_RUN, so this deterministic track does not decide
  //         the ticket's own verdict). Recorded in the summary and in the
  //         printed output, and they decide NOTHING.
  //
  //    WHY A SCOPE NOTE MUST NOT BE ABLE TO DECIDE A VERDICT: it is not an
  //    answer to the question the verdict asks — it never says whether a check
  //    this stage owns was performed or what it found — so a note that votes is
  //    a veto, and a veto held by a statement that is true on EVERY run is a
  //    gate whose verdict is a constant. That is the bug this repair removes:
  //    the two notes named in (3) are present on every run of this track, so
  //    while they sat in `notRun` (whose `length > 0` forces NOT_RUN) the
  //    aggregator reported `status NOT_RUN`, `exit 3`, `blockingGates []`,
  //    `defects []` FOREVER, with all five gates PASS. Honest about scope is
  //    required; letting the scope decide is what made this gate meaningless.
  //
  //    F3, THE ONE PLACE THIS REPAIR IS STRICTER THAN THE FILE IT REPLACED:
  //    the third ticket-level precondition — "the track's own files are
  //    untracked (git ls-files reports 0 of them), so no artefact of this track
  //    is bound to a base a reader can check" — was a soft note here and is a
  //    blocking DEFECT now. Provability is a hard requirement of this
  //    repository, so an untracked track turns the gate RED (exit 1) rather than
  //    yellow. Nothing else changed direction: nothing became more permissive,
  //    and every other non-zero exit of this file is untouched.
  //
  //    G4, THE SAME RULE OVER THE WHOLE TRACK. `trackProvabilityDefects` is read
  //    here, from the dependency gate's own untracked and modified lists, and its
  //    defects go into `defects` — which now DECIDE (see `deriveVerdict`): a
  //    partially untracked track used to pass this chain at exit 0 with an empty
  //    defect list while the dependency gate named 33 untracked files.
  const trackDefects = trackProvabilityDefects(gates.dependency);
  const trackExempt = chainProducedExemptions(gates.dependency);
  defects.push(...trackDefects);
  const verdict = deriveVerdict({ gates, defects, notRun, scopeNotes });
  const status = verdict.status;
  // The instant this SUMMARY was produced, which is the gate's own observation
  // instant: the one both child records were judged against plus the run's own
  // end. Sampled here rather than at the top of the function, for the reason
  // `nowIso` states.
  const observedAtIso = nowIso();
  const summary = {
    ticket: 'S2-008',
    gate: 'scripts/verify-s2-008.mjs',
    role: 'verification aggregator: dependency gate, probes gate, the cross-process replay it spawns itself, the invocation binding, the freshness refusal, and the derived status',
    status,
    ok: verdict.ok,
    exitCode: verdict.exitCode,
    base,
    // G1: the invocation this run minted. Published, and declared EXCLUDED FROM
    // REPEATABILITY, so nobody reads the difference between two runs of one tree
    // as a change in the verdict: the id decides only whether a record is the
    // current run's.
    invocation: {
      id: invocationId,
      minted_by: 'scripts/verify-s2-008.mjs (node:crypto randomBytes, 16 bytes)',
      passed_to: ['scripts/s2-008-replay.mjs', 'scripts/s2-008-harness.mjs'],
      required_in: [REPLAY_RELATIVE, HARNESS_RELATIVE],
      required_when: noWrite ? 'a WRITE run: the record on disk is this run\'s, so it must carry the id; a CHECK run does not write it and judges the committed record by its TREE binding and its agreement with the observed process instead' : 'this WRITE run',
      excluded_from_repeatability: true,
      decides: false,
      note: 'the only random value on this path. It is not part of any decision about a measurement, and nothing else in the summary changes between two runs of one tree because of it',
    },
    // G6: the boundary this gate does NOT close, printed by every run. It is a
    // boundary and not a defect: a statement that cannot be false must not decide
    // anything, and the corpus drift gate is what covers the working tree.
    boundaries: [WORKING_TREE_BOUNDARY],
    // What the provability rule exempted, and why. An exemption that cannot be
    // seen in the record is a hole with a comment on it.
    provability_exempt: trackExempt.length === 0 ? [] : [{
      paths: trackExempt,
      reason: 'these are the records this chain\'s own children write in the same run, so the chain owns whether they are tracked and clean; every other file of the track is still blocking (a modified corpus file included)',
    }],
    gates,
    defects: verdict.defects,
    notRun: verdict.notRun,
    // F2: the non-binding statements, kept in the summary and in the printed
    // output. The honesty of the record is the point; their silence is not.
    scopeNotes: verdict.scopeNotes,
    blockingGates: verdict.blockingGates,
    notRunGates: verdict.notRunGates,
    freshness: {
      observed_at: observedAtIso,
      started_at: startedAtIso,
      replay_judged_at: replayObservedAtIso,
      harness_judged_at: harnessObservedAtIso,
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
    // F2/F3/G4: each ticket-level statement has ONE home. The provability
    // preconditions are unmet and are defects (so they are in `defects` above and
    // here); the #45 campaign statement is a scope note and is in `scopeNotes`.
    // This list therefore names only unmet preconditions this file treats as
    // defects, and is empty on a run whose whole track is tracked, committed and
    // unmodified.
    ticket_preconditions_not_met: [...verdict.provabilityDefects, ...trackDefects],
    engineering_status: 'BLOCKED_DEPENDENCY',
    assurance_status: 'NOT_MEASURED',
    real_adapter_status: 'NOT_RUN_REAL_ADAPTER',
    a_mvp_status: 'NOT_RUN (A-MVP-01..07, behind #45)',
    note: 'engineeringStatus, assuranceStatus and the A-MVP rows are NOT derived from this gate and never are: a green deterministic track does not convert the ticket\'s own scope into done.',
    observedAtIso,
    startedAtIso,
  };
  const outFile = path.join(REPO_ROOT, SUMMARY_RELATIVE);
  let written = null;
  // `--no-write` is honoured: a CHECK run of this aggregator must not mutate the
  // summary it is checking. Its three child gates are still spawned, because
  // their whole point is to produce a current report; the harness is spawned
  // with `--no-write` on a check run too (see 3b), so a check leaves BOTH the
  // summary and the harness record it is judging untouched.
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
      // G1: printed, so a reader can see WHICH invocation produced the child
      // records this run judged.
      invocation_id: summary.invocation.id,
      // F2: printed, so the notes are readable in the run's own output and not
      // only by opening the summary file.
      scopeNotes: summary.scopeNotes,
      // G6: the boundary is printed too. A gate that does not say what it cannot
      // see leaves a reader to guess, and this is the one thing here that is NOT
      // closed: the integrity gates read committed bytes, so a hand-edited
      // summary in the WORKING TREE is invisible to them until the next chain run
      // rewrites it, and the corpus drift gate is what covers that surface.
      boundaries: summary.boundaries,
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
