#!/usr/bin/env node
// S2-008 — THE CROSS-PROCESS REPLAY (issue SpaceDazher/Veritas#8, A3 + A5).
//
// THE TEMPLATE IS `scripts/s2-007-db-replay.mjs`, and this file is its shape for
// the research track: distinct run ids and nonces per process, a crash/restart
// phase, an EXPECTED-VALUE TABLE, and the rule that two identically wrong runs
// are not a pass.
//
// WHAT IT DOES, IN ORDER
//   0. purge the replay's own scratch, so a repeat replay on a permanent base
//      fails on the property and not on leftovers;
//   1. resolve the REAL base with read-only git;
//   2. SPAWN run A (`scripts/s2-008-run.mjs --label a --write`) and run B
//      (`--label b --write`) as two separate OS PROCESSES — not two awaited
//      calls, which are cooperative, not concurrent and not separate;
//   3. read the two evidence files the children were told to write, and
//      verify each against its own artefact digest (`assertArtefactBound`);
//   4. run the six negative controls and ATTACH the record to both runs BEFORE
//      the comparison, because the comparator's `negative_controls` gate reads
//      the evidence that was produced and an unmeasured control is a failure,
//      not a satisfied one;
//   5. `compareParallelTrack` against the FROZEN table. `digestsEqual` (A === B)
//      is REPORTED and is explicitly additional: two runs that agree can agree
//      on the same wrong answer;
//   6. the IDENTICAL-WRONG control: the same corruption in BOTH runs, so their
//      digests stay equal and the table is the only thing that can produce
//      findings. Both must produce them;
//   7. the crash/restart phase, as two more child processes: phase 1 kills
//      itself with SIGKILL between taking the reservation and the first trial,
//      phase 2 restarts on the SAME ledger and must open a RECONCILIATION, not
//      a retry and not a zero;
//   8. the repeatability proof: the two letters are two processes on one base,
//      so their decision projections must be equal (that is "same base ⇒ same
//      outcome" across process boundaries), and a third child runs the same
//      base twice in one process for the in-process witness;
//   9. write `evidence/s2-008-replay.json` and print the summary block.
//
// EXIT CODES
//   0  every property the replay owns held;
//   1  a property FAILED (a table disagreement, a control that did not flip, a
//      crash/restart that did not reconcile, a repeat that did not reproduce);
//   2  the replay could not be attempted (unreadable base, a child that could
//      not be spawned) — a crash, never a pass;
//   3  NOT_RUN: a child produced no runnable record, or a mandatory phase did
//      not run. "I could not check" and "I checked and it failed" are different
//      answers and are never collapsed.
//
// A NOTE ON THE WALL CLOCK AND ON THE INVOCATION ID
// Exactly two numbers in this record come from outside the frozen literals, and
// both are marked `decides: false`: `freshness.observed_at`, which exists so
// `verify-s2-008.mjs` can tell a fresh record from a stale one, and
// `invocation_id`, the per-chain-run id `scripts/verify-s2-008.mjs` generates
// and passes with `--invocation-id`. Both are excluded from the repeatability
// comparison BY NAME. Every instant the DECISION reads is a frozen literal
// inside the children, and the id decides only WHETHER the record on disk is
// this run's, never WHAT the campaign is.
//
//   node scripts/s2-008-replay.mjs
//   node scripts/s2-008-replay.mjs --corpus .bb/s2-008/selftest-corpus
//   node scripts/s2-008-replay.mjs --no-write
//   node scripts/s2-008-replay.mjs --invocation-id <hex>    (spawned by the chain)
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import {
  EXPECTED_CODES, EXPECTED_COMPARATOR_FAILURES, EXPECTED_CONTROLS, EXPECTED_COUNTERS,
  EXPECTED_LEDGER_SHAPE, EXPECTED_METRIC, EXPECTED_TRIAL_DECISIONS, assertTableFrozen,
  expectedTableDigest, unexpectedComparatorFailures,
} from '../src/lib/research/expected-values.mjs';
// A NAMESPACE import, on purpose. The frozen CAMPAIGN decision
// (`EXPECTED_CAMPAIGN`) is the R-C agreement target, and the two gates that read
// it (this replay, the harness) must not stop LOADING when the member is
// absent: a gate that crashes on import reports a crash, never a red gate. The
// absence is therefore a NAMED refusal — `frozenCampaignDecision()` returns
// null and `campaignDecisionAgreement` emits `EXPECTED_CAMPAIGN_ABSENT`, which
// is not agreement. Fail-closed, and the module still loads.
import * as expectedValues from '../src/lib/research/expected-values.mjs';
import { assertFrozenCampaignDerivable } from '../src/lib/research/campaign-expectation.mjs';
import {
  compareParallelTrack, injectCorruption, resolveCampaignVerdict,
} from '../src/lib/research/comparator.mjs';
import { expectedValueIssues } from '../src/lib/research/expected-values.mjs';
import { controlsFlipVerdict, runNegativeControls } from '../src/lib/research/negative-controls.mjs';
import { assertPreregistration, loadPreregistration } from '../src/lib/research/preregistration.mjs';
import { assertArtefactBound } from '../src/lib/research/runner.mjs';
import {
  COMMITTED_CORPUS_DIR, classifyCrashRestart, diffPaths, parseArgs, projectedDecision, resolveBase,
} from './s2-008-run.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RUN_SCRIPT = path.join(REPO_ROOT, 'scripts', 's2-008-run.mjs');
/** The replay's own scratch. Under `.bb/`, which `.gitignore` covers. */
const REPLAY_SCRATCH = path.join(REPO_ROOT, '.bb', 's2-008', 'replay');
/** The committed evidence file this replay writes. */
const OUT_RELATIVE = 'evidence/s2-008-replay.json';
/** The number of properties the replay owns. The aggregator adds its own; the
 *  two sets are never merged into one number. */
const OWNED_PROPERTIES = Object.freeze(['A3', 'A5']);

/** `--invocation-id <id>`: the chain's per-run id, recorded in the record so a
 *  reader can tell this run's record from a previous run's copy — the record a
 *  stub that copies the last honest record and refreshes two timestamps can
 *  never produce. A bare flag and a malformed value are a REFUSAL (the caller
 *  gets exit 2 and no record), not a default: a caller that asked to bind this
 *  record to an invocation and named nothing must not get a record that claims
 *  to be unbound.
 *
 *  It decides nothing. The table, the comparator, the properties, the NOT_RUN
 *  set and the exit code are computed exactly as they are without it.
 *
 *  @param {string[]} argv
 *  @returns {string|null} the id, or null when the caller passed none
 */
export function readInvocationId(argv = []) {
  for (let index = 2; index < argv.length; index += 1) {
    const token = String(argv[index] ?? '');
    const match = /^--invocation[-_]id(?:=(.*))?$/.exec(token);
    if (match === null) continue;
    const inline = match[1];
    const value = inline !== undefined ? inline : (String(argv[index + 1] ?? '').startsWith('--') ? '' : String(argv[index + 1] ?? ''));
    if (!/^[!-~]{1,200}$/.test(value)) {
      const error = new Error(`--invocation-id must be 1-200 printable non-space characters, got ${JSON.stringify(String(value).slice(0, 40))}`);
      error.code = 'REPLAY_INVOCATION_ID_INVALID';
      throw error;
    }
    return value;
  }
  return null;
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function log(...parts) {
  process.stdout.write(`${parts.join(' ')}\n`);
}

function rel(file) {
  return path.relative(REPO_ROOT, file);
}

/** The frozen table, in the shape `compareParallelTrack` reads. */
function expectedTable() {
  return {
    EXPECTED_TRIAL_DECISIONS,
    EXPECTED_CODES,
    EXPECTED_COUNTERS,
    EXPECTED_LEDGER_SHAPE,
    EXPECTED_METRIC,
    EXPECTED_CONTROLS,
    digest: expectedTableDigest(),
  };
}

/**
 * Spawn one child of the run script. A child is a real OS process: a real pid, a
 * real argv and a real exit status, which is the whole point of A3 — a nonce
 * minted from a pid in the same heap would be a nonce minted from a number this
 * process chose.
 */
function spawnRun({ label, args, corpusDir, write, out, extra = [] }) {
  const argv = [RUN_SCRIPT, '--label', label];
  if (corpusDir !== null) argv.push('--corpus', corpusDir);
  if (write === true) argv.push('--write');
  if (typeof out === 'string') argv.push('--out', out);
  argv.push(...extra);
  const result = spawnSync(process.execPath, argv, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 600_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  const exitCode = typeof result.status === 'number' ? result.status : null;
  return {
    label,
    argv: argv.map((entry) => (path.isAbsolute(entry) && entry.startsWith(REPO_ROOT) ? rel(entry) : entry)),
    pid: typeof result.pid === 'number' ? result.pid : null,
    exitCode,
    signal: result.signal ?? null,
    timedOut: result.error?.code === 'ETIMEDOUT',
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    exit_semantics: exitCode === 0 ? 'PASS' : (exitCode === 3 ? 'NOT_RUN' : (exitCode === 1 ? 'FAIL' : 'NOT_RUN_UNMAPPED')),
  };
}

/** Read an evidence file the child was told to write, and re-verify its own
 *  digest AND ITS OWN PID. A record that does not verify is a finding, never a
 *  formatting difference.
 *
 *  EV1: the digest alone is NOT a binding to a child. It re-derives the
 *  document's own `artefact_digest`, so an EDITED-and-RE-SEALED record passes
 *  it, and a record left over from an earlier run passes it too. The two
 *  children were spawned by THIS invocation and their pids are known, so the
 *  record's own `provenance.pid` is compared with the child that was told to
 *  write it. A record that does not name this child is not this invocation's
 *  evidence and is reported as such, whatever it says about itself.
 */
function readEvidence(relativePath, child = null) {
  const absolute = path.join(REPO_ROOT, relativePath);
  let document = null;
  try {
    document = JSON.parse(readFileSync(absolute, 'utf8'));
  } catch (error) {
    return { path: relativePath, readable: false, reason: String(error?.message ?? error).slice(0, 200), document: null, pid_bound: false, child_pid: null, record_pid: null };
  }
  let bound = false;
  let boundReason = null;
  try {
    assertArtefactBound(document);
    bound = true;
  } catch (error) {
    boundReason = String(error?.code ?? error?.message ?? error).slice(0, 200);
  }
  const recordPid = isPlainObject(document?.provenance) ? document.provenance.pid ?? null : null;
  const childPid = isPlainObject(child) ? child.pid ?? null : null;
  const pidBound = childPid !== null && recordPid !== null && Number(recordPid) === Number(childPid);
  return {
    path: relativePath,
    readable: true,
    artefact_bound: bound,
    artefact_bound_reason: boundReason,
    digest: document.artefact_digest ?? null,
    child_pid: childPid,
    record_pid: recordPid,
    pid_bound: pidBound,
    // WHY a record can fail this even when its own digest verifies.
    pid_binding_reason: childPid === null
      ? 'the child was not spawned, so no pid could be expected'
      : (recordPid === null
        ? 'the record names no provenance.pid, so it cannot be bound to the child that wrote it'
        : (pidBound ? null : `the record names pid ${String(recordPid)} while the child that was told to write it is pid ${String(childPid)}; the bytes on disk are not this invocation's run`)),
    document,
  };
}

/**
 * A ledger-shape check against the frozen `EXPECTED_LEDGER_SHAPE`, read from
 * the run record's own journal. The table declares the shape; nothing in the
 * track consumed it before, so the declaration had no teeth.
 *
 * EXPORTED (R-C): the ledger-shape gate term is one rule with one definition,
 * used by the replay over the real engine's journal and by the harness over its
 * own run journal. A second implementation would be a second opinion about the
 * same table, which is the exact shape of drift this table exists to catch.
 *
 * @param {object} runRecord A run record carrying `ledger.record_kinds`.
 * @returns {ReadonlyArray<object>} Empty when the journal matches the table.
 *   A run record with NO readable `record_kinds` reports all four kinds as
 *   `observed: 0`, never as a pass: an absent journal is a missing
 *   measurement, not a satisfied one.
 */
export function ledgerShapeIssues(runRecord) {
  const observed = Array.isArray(runRecord?.ledger?.record_kinds) ? runRecord.ledger.record_kinds : [];
  const issues = [];
  for (const row of EXPECTED_LEDGER_SHAPE) {
    const seen = observed.filter((kind) => kind === row.kind).length;
    if (seen !== row.count) {
      issues.push({ code: 'LEDGER_SHAPE_DIVERGES_FROM_TABLE', kind: row.kind, expected: row.count, observed: seen, note: row.note });
    }
  }
  return issues;
}

/**
 * The frozen CAMPAIGN decision the track is scored against, read from
 * `EXPECTED_CAMPAIGN` in src/lib/research/expected-values.mjs.
 * @returns {string|null} The declared decision, or null when the module
 *   publishes no campaign expectation. Null is NOT "anything agrees": it is the
 *   input to a named refusal.
 */
export function frozenCampaignDecision() {
  const declared = expectedValues.EXPECTED_CAMPAIGN;
  return isPlainObject(declared) && typeof declared.decision === 'string' && declared.decision !== ''
    ? declared.decision
    : null;
}

/**
 * R-C: THE GATE CHECKS AGREEMENT WITH THE FROZEN CAMPAIGN DECISION, NEVER
 * `ALLOW`.
 *
 * With eight synthetic cases the honest campaign answer is a null, so a
 * `verdict_is_pass` requirement is unsatisfiable without tuning the fixtures
 * until a fabricated effect looked legitimate. This is the one place the
 * condition is DEFINED, and all three gates (replay, harness, aggregator) call
 * it, so "four coupled sites" cannot drift apart again. A `POSITIVE` observed
 * against a non-positive frozen expectation is a refusal, not a pass: that is
 * the anti-goal, executed.
 *
 * @param {{observed?: string|null, expected?: string|null}} args
 * @returns {{expected: string|null, observed: string|null, agrees: boolean,
 *   findings: ReadonlyArray<object>}} `agrees` is true only when BOTH are
 *   strings and they are equal.
 */
export function campaignDecisionAgreement({ observed = null, expected = null } = {}) {
  const observedDecision = typeof observed === 'string' && observed !== '' ? observed : null;
  const expectedDecision = typeof expected === 'string' && expected !== '' ? expected : null;
  const findings = [];
  if (expectedDecision === null) {
    findings.push({
      code: 'EXPECTED_CAMPAIGN_ABSENT',
      field: 'expected_campaign_decision',
      expected: 'a frozen campaign decision in EXPECTED_CAMPAIGN',
      observed: expectedDecision,
      detail: 'src/lib/research/expected-values.mjs publishes no EXPECTED_CAMPAIGN, so the campaign decision has nothing to agree with; a gate with no expectation is not green',
    });
  } else if (observedDecision === null) {
    findings.push({
      code: 'CAMPAIGN_DECISION_ABSENT',
      field: 'observed_campaign_decision',
      expected: expectedDecision,
      observed: observedDecision,
      detail: 'the comparator produced no campaign decision, so nothing was measured to agree with',
    });
  } else if (observedDecision !== expectedDecision) {
    findings.push({
      code: 'CAMPAIGN_DECISION_DIVERGES_FROM_FROZEN_TABLE',
      field: 'observed_campaign_decision',
      expected: expectedDecision,
      observed: observedDecision,
      detail: `the campaign decided ${observedDecision} while the frozen expected-value table declares ${expectedDecision}; a decision the table does not declare is not a pass`,
    });
  }
  return Object.freeze({
    expected: expectedDecision,
    observed: observedDecision,
    agrees: findings.length === 0,
    findings: Object.freeze(findings),
  });
}

/** The identical-wrong control, run through the SAME comparator call on the
 *  SAME two runs: both receive the SAME corruption, so their digests stay equal
 *  and the table is the only thing that can produce findings. */
function identicalWrongControl({ runA, runB, prereg, base }) {
  const corrupt = (run) => {
    const injected = injectCorruption(run.trials, 'trial_status_skip');
    return { ...run, trials: injected.trials, corrupted: injected.corrupted };
  };
  const wrongA = corrupt(runA);
  const wrongB = corrupt(runB);
  const result = compareParallelTrack({ runA: wrongA, runB: wrongB, prereg, expected: expectedTable(), base });
  return {
    injected: wrongA.corrupted,
    findings_a: result.identicalWrongFindings.findings_a_count,
    findings_b: result.identicalWrongFindings.findings_b_count,
    digests_still_equal: result.identicalWrongFindings.digests_still_equal,
    both_non_empty: result.identicalWrongFindings.both_non_empty,
    conclusion: result.identicalWrongFindings.conclusion,
    note: 'A === B is reported as an additional condition only: the same corruption in both runs keeps their digests equal, so only the frozen table can produce findings here.',
  };
}

/** The clean, ALLOW trial the comparator-level controls mutate. The DELIVERED
 *  calibration of this track is NOT_MEASURED, and a NOT_MEASURED calibration
 *  makes every trial a VIOLATION by the comparator's own rule — a control whose
 *  "before" state is already a VIOLATION cannot demonstrate a flip. */
function controlTrial(prereg) {
  const seeds = Array.isArray(prereg?.seed_rule?.seeds) ? [...prereg.seed_rule.seeds] : [101, 202, 303, 404, 505];
  return {
    trial: 'trl-s2-008-control',
    status: 'RESOLVED',
    outcome: 'POSITIVE',
    metric: EXPECTED_METRIC.name,
    numerator: 7,
    denominator: 8,
    seedBinding: { seeds, source: 'PREREGISTERED', preregistered_seeds: seeds },
    holdoutBinding: {
      partition: 'HOLDOUT', read_at: '2026-01-01T01:00:00.000Z', decision_at: '2026-01-01T01:00:00.000Z', opened_before_decision_point: false, opens: 1, max_opens: 1,
    },
    budgetBinding: { reservation_id: 'rsv-s2-008-control', granted_units: 100, spent_units: 40, currency: 'UNITS' },
    evaluatorBinding: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    evaluator: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    calibration: {
      status: 'MEASURED',
      not_measured_reason: null,
      evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true },
    },
  };
}

async function replay(args = {}, argv = process.argv) {
  const corpusDir = typeof args.corpus === 'string' ? path.resolve(args.corpus) : COMMITTED_CORPUS_DIR;
  // THE INVOCATION BINDING, read first: a bad `--invocation-id` is refused
  // before a single child is spawned, so a refusal leaves no partial record.
  const invocationId = readInvocationId(argv);
  const evidenceEligible = corpusDir === COMMITTED_CORPUS_DIR;
  // The children ALWAYS write their record, because the replay has to read what
  // they produced: to the committed evidence path for the committed corpus, and
  // to this replay's own scratch for any other corpus (a self-test record that
  // `evidence/` cannot be talked into holding).
  // `--no-write`: neither the children nor this replay touch `evidence/`, so a
  // CHECK run cannot mutate the artefact it is checking. The record is still
  // produced and still printed; it simply is not written anywhere.
  const writeChildren = args.write !== false && args.noWrite !== true && args.no_write !== true;
  const base = resolveBase();
  const prereg = loadPreregistration(corpusDir);
  const tableDigest = assertTableFrozen(prereg);
  // R-B/R-C: the frozen CAMPAIGN decision is re-derived through the comparator's
  // own rule before the two children are spawned, and the derivation is printed
  // with the run log. A replay that compared a campaign against an expectation
  // the rule does not produce would be a green gate for a wrong question, so the
  // divergence is a refusal here rather than a finding three steps later.
  const frozenCampaign = assertFrozenCampaignDerivable();
  const observedAt = new Date().toISOString();

  // 0. Purge the replay's OWN scratch. The children purge their own roots too;
  //    this is the parent half of the same rule.
  rmSync(REPLAY_SCRATCH, { recursive: true, force: true });
  mkdirSync(REPLAY_SCRATCH, { recursive: true });

  log('# s2-008 cross-process replay');
  log(`config corpus=${rel(corpusDir)} evidence_eligible=${String(evidenceEligible)} write_evidence=${String(writeChildren && evidenceEligible)} table_digest=${tableDigest} metric=${EXPECTED_METRIC.name} noise_band=${String(EXPECTED_METRIC.noiseBand)}`);
  log(`base commit=${base.commit_sha} tree=${base.tree_sha} branch=${base.branch} track_tracked=${String(base.track_tracked)} tracked_files_of_this_track=${base.tracked_files_of_this_track}`);
  log(`invocation id=${String(invocationId)} bound=${String(invocationId !== null)} head_tree_sha=${base.tree_sha} decides=false excluded_from_repeatability=true`);
  log(`frozen campaign decision=${frozenCampaign.decision} reason=${String(frozenCampaign.decisionReason)} interval=${frozenCampaign.interval.lower}..${frozenCampaign.interval.upper} confidence=${String(frozenCampaign.confidence)} never_rejects=${String(frozenCampaign.rule_feasibility.never_rejects)}`);

  // 2. The two process-separated runs.
  // On the committed corpus the children write `evidence/s2-008-run-<letter>.json`
  // (their own default destination), which is where a reader looks for them. On
  // any other corpus they write into this replay's scratch, because a self-test
  // record must never be able to land in `evidence/`.
  const outA = evidenceEligible ? null : path.join(REPLAY_SCRATCH, 'run-a.json');
  const outB = evidenceEligible ? null : path.join(REPLAY_SCRATCH, 'run-b.json');
  const childA = spawnRun({ label: 'a', args, corpusDir, write: writeChildren, out: outA });
  log(`child a pid=${childA.pid} exit=${String(childA.exitCode)} signal=${String(childA.signal)}`);
  const childB = spawnRun({ label: 'b', args, corpusDir, write: writeChildren, out: outB });
  log(`child b pid=${childB.pid} exit=${String(childB.exitCode)} signal=${String(childB.signal)}`);

  const evidenceA = readEvidence(outA === null ? 'evidence/s2-008-run-a.json' : rel(outA), childA);
  const evidenceB = readEvidence(outB === null ? 'evidence/s2-008-run-b.json' : rel(outB), childB);
  log(`evidence a bound=${String(evidenceA.artefact_bound)} pid_bound=${String(evidenceA.pid_bound)} child_pid=${String(evidenceA.child_pid)} record_pid=${String(evidenceA.record_pid)} findings=${evidenceA.document?.table_finding_count ?? 'n/a'} digest=${evidenceA.digest ?? 'n/a'}`);
  log(`evidence b bound=${String(evidenceB.artefact_bound)} pid_bound=${String(evidenceB.pid_bound)} child_pid=${String(evidenceB.child_pid)} record_pid=${String(evidenceB.record_pid)} findings=${evidenceB.document?.table_finding_count ?? 'n/a'} digest=${evidenceB.digest ?? 'n/a'}`);

  const notRunEntries = [];
  const childrenRan = childA.exitCode !== null && childB.exitCode !== null;
  // EV1: PRODUCED MEANS "THIS CHILD WROTE IT". Before, `document !== null` was
  // enough: a child that died before writing left the PREVIOUS run's record on
  // disk, the record verified its own digest, and A3 scored it — a replay that
  // read a stale artefact and called it a measurement. Three conditions now
  // have to hold, and each names itself: the child exited zero, the record is
  // readable, and the record names the pid of the child that was told to write
  // it.
  const childProduced = [
    { letter: 'a', child: childA, evidence: evidenceA },
    { letter: 'b', child: childB, evidence: evidenceB },
  ].map((entry) => ({
    letter: entry.letter,
    path: entry.evidence.path,
    pid: entry.child.pid,
    exitCode: entry.child.exitCode,
    readable: entry.evidence.readable === true,
    pid_bound: entry.evidence.pid_bound === true,
    // "IT RAN AND REPORTED" is the question, not "it exited zero": a run that
    // honestly reports FAIL against the frozen table exits 1 and is still the
    // measurement. The codes that mean the child did NOT run are 2 (the script's
    // own crash code), a signal (SIGKILL), and no status at all.
    ran_to_a_report: [0, 1, 3].includes(entry.child.exitCode) && entry.child.signal === null,
    produced: [0, 1, 3].includes(entry.child.exitCode) && entry.child.signal === null
      && entry.evidence.readable === true && entry.evidence.pid_bound === true,
    pid_binding_reason: entry.evidence.pid_binding_reason ?? null,
    not_produced_reason: [0, 1, 3].includes(entry.child.exitCode) && entry.child.signal === null
      ? (entry.evidence.readable === true ? entry.evidence.pid_binding_reason : `the record is unreadable: ${entry.evidence.reason ?? 'no reason given'}`)
      : `the child exited ${String(entry.child.exitCode)}${entry.child.signal === null ? '' : ` on ${String(entry.child.signal)}`}; exit 2, a signal and an absent status all mean it never got as far as a report`,
  }));
  const recordsProduced = childProduced.every((entry) => entry.produced === true);
  for (const entry of childProduced) {
    if (entry.produced) continue;
    if (!entry.ran_to_a_report) {
      notRunEntries.push(`CHILD_${entry.letter.toUpperCase()}_DID_NOT_REPORT: the child that was told to write ${String(entry.path)} ${String(entry.not_produced_reason)}; the bytes on disk are not this invocation's run`);
    } else if (entry.pid_binding_reason !== null) {
      notRunEntries.push(`RUN_RECORD_NOT_BOUND_TO_CHILD:${entry.letter.toUpperCase()}: ${entry.pid_binding_reason}`);
    } else if (entry.readable !== true) {
      notRunEntries.push(`RUN_RECORD_ABSENT:${entry.letter.toUpperCase()}: ${String(entry.not_produced_reason)}`);
    }
  }
  // Nothing downstream may read a record this invocation did not produce. The
  // stale bytes are DROPPED here, not merely reported: a control, a comparison
  // and a repeatability witness that read them would be measuring the previous
  // run and calling it this one.
  for (const entry of childProduced) {
    if (entry.produced) continue;
    if (entry.letter === 'a') evidenceA.document = null;
    else evidenceB.document = null;
  }

  const separation = {
    fields: ['raw_run_id', 'nonce', 'executor_id', 'pid', 'output_root'],
    raw_run_id: { a: evidenceA.document?.provenance?.run_id ?? null, b: evidenceB.document?.provenance?.run_id ?? null },
    nonce: { a: evidenceA.document?.provenance?.nonce ?? null, b: evidenceB.document?.provenance?.nonce ?? null },
    executor_id: { a: evidenceA.document?.provenance?.executor_id ?? null, b: evidenceB.document?.provenance?.executor_id ?? null },
    pid: { a: evidenceA.document?.provenance?.pid ?? null, b: evidenceB.document?.provenance?.pid ?? null },
    output_root: { a: evidenceA.document?.output_root ?? null, b: evidenceB.document?.output_root ?? null },
    children_are_separate_processes: childA.pid !== null && childB.pid !== null && childA.pid !== childB.pid,
  };
  // A field that is ABSENT from both records cannot be "identical", and calling
  // it a collision would blame the runs for a field they never carried. Absent
  // fields are named and excluded from the check; present ones must differ.
  separation.fields_absent = separation.fields.filter((field) => separation[field].a === null && separation[field].b === null);
  separation.ok = separation.fields.some((field) => !separation.fields_absent.includes(field))
    && separation.fields
      .filter((field) => !separation.fields_absent.includes(field))
      .every((field) => separation[field].a !== separation[field].b);
  log(`A3 separation fields_distinct=${String(separation.ok)} separate_pids=${String(separation.children_are_separate_processes)}`);

  // 4. The six negative controls, attached to BOTH runs before the comparison.
  const trial = controlTrial(prereg);
  // A control that cannot be built is a NOT_RUN control, never a passing one.
  // `runNegativeControls` throws when its clean-run context has no trials, and
  // that throw is caught here so the replay keeps producing a record that says
  // which control could not run instead of dying.
  let controls = null;
  let controlsError = null;
  try {
    controls = runNegativeControls({
      trial,
      cleanRun: evidenceA.document ?? null,
      runA: evidenceA.document ?? null,
      runB: evidenceB.document ?? null,
      card: prereg.card,
    });
  } catch (error) {
    controlsError = { code: String(error?.code ?? 'CONTROL_CONTEXT_ERROR'), message: String(error?.message ?? error).slice(0, 300) };
    controls = {
      version: 's2-008-negative-controls-v1',
      controls: [],
      allFlipped: false,
      notRun: [{ id: 'all', reason: `CONTROL_CONTEXT_ABSENT: ${controlsError.code}` }],
      digest: null,
    };
  }
  const gate = controlsFlipVerdict(controls);
  log(`A2 controls allFlipped=${String(controls.allFlipped)} gate_ok=${String(gate.ok)} failures=${JSON.stringify(gate.failures ?? [])}`);
  const runA = evidenceA.document === null ? null : { ...evidenceA.document, controls: { allFlipped: controls.allFlipped, controls: controls.controls, notRun: controls.notRun } };
  const runB = evidenceB.document === null ? null : { ...evidenceB.document, controls: { allFlipped: controls.allFlipped, controls: controls.controls, notRun: controls.notRun } };

  // 5. The comparison against the FROZEN table.
  let comparison = null;
  let comparisonError = null;
  try {
    comparison = compareParallelTrack({ runA, runB, prereg, expected: expectedTable(), base });
  } catch (error) {
    comparisonError = { code: String(error?.code ?? 'COMPARISON_ERROR'), message: String(error?.message ?? error).slice(0, 300) };
  }
  if (comparison === null) {
    log(`A3 comparison REFUSED ${JSON.stringify(comparisonError)}`);
  } else {
    log(`A3 findingsA=${comparison.findingsA.length} findingsB=${comparison.findingsB.length} digestsEqual=${String(comparison.digestsEqual)} (A===B is ADDITIONAL, not the criterion)`);
    for (const finding of [...comparison.findingsA, ...comparison.findingsB].slice(0, 10)) {
      log(`A3 finding ${finding.field} expected=${JSON.stringify(finding.expected)} observed=${JSON.stringify(finding.observed)} code=${finding.code}`);
    }
  }

  // 6. The identical-wrong control.
  let identicalWrong = null;
  if (comparison !== null) {
    identicalWrong = identicalWrongControl({ runA, runB, prereg, base });
    log(`A3 identical_wrong findings_a=${identicalWrong.findings_a} findings_b=${identicalWrong.findings_b} digests_still_equal=${String(identicalWrong.digests_still_equal)}`);
  }

  // 7. The crash/restart phase, as two more child processes.
  const crashRoot = path.join(REPLAY_SCRATCH, 'crash');
  const crashOne = spawnRun({ label: 'crash', args, corpusDir, write: false, out: null, extra: ['--crash-phase', '1', '--root', crashRoot] });
  const crashedHard = crashOne.signal === 'SIGKILL' || crashOne.exitCode === 137;
  log(`crash phase1 pid=${crashOne.pid} exit=${String(crashOne.exitCode)} signal=${String(crashOne.signal)} killed=${String(crashedHard)} (a SIGKILL is the expected end; a clean exit would be a shutdown wearing a crash's name)`);
  const crashTwo = spawnRun({ label: 'crash', args, corpusDir, write: false, out: null, extra: ['--crash-phase', '2', '--root', crashRoot] });
  const crashDocument = parseLastJsonLine(crashTwo.stdout);
  const crashClassified = crashDocument === null ? null : classifyCrashRestart(crashDocument);
  log(`crash phase2 exit=${String(crashTwo.exitCode)} status=${crashClassified?.status ?? 'NOT_RUN'} reason=${crashClassified?.reason ?? 'no record'}`);
  if (crashDocument !== null) {
    log(`crash phase2 reconciliation=${crashDocument.reconciliation.reconciliation_id} decided=${String(crashDocument.reconciliation.decided)} trials_by_restart=${crashDocument.trials_executed_by_the_restart} retry_attempted=${String(crashDocument.retry_attempted)} implicit_zero=${String(crashDocument.implicit_zero)}`);
    log(`crash phase2 expired_reservation=${JSON.stringify(crashDocument.expired_reservation)}`);
  }
  const crashRestart = {
    phase1: { pid: crashOne.pid, exitCode: crashOne.exitCode, signal: crashOne.signal, killed: crashedHard },
    phase2: { pid: crashTwo.pid, exitCode: crashTwo.exitCode, document: crashDocument, classified: crashClassified },
    interrupted_trial_is_a_reconciliation: crashDocument !== null
      && isPlainObject(crashDocument.reconciliation)
      && crashDocument.reconciliation.decided === false
      && crashDocument.retry_attempted === false
      && crashDocument.implicit_zero === false,
  };

  // 8. Repeatability. Two facts, both named: the two letters are two PROCESSES
  //    on one base, and a third child ran the same base twice inside one
  //    process. A repeat run that reproduced only some of the time would be a
  //    flaky harness, so the in-process witness is run too.
  let repeatability = { cross_process: null, in_process: null, child: null };
  if (evidenceA.document !== null && evidenceB.document !== null) {
   try {
    // The SAME projection the in-process witness uses (`projectedDecision`:
    // the runner's allowlist, minus the per-execution settle key), so the
    // cross-process and in-process claims are made with one instrument.
    const projectionA = projectedDecision(evidenceA.document);
    const projectionB = projectedDecision(evidenceB.document);
    repeatability.cross_process = {
      projection: 'runner.mjs verdictProjection minus trials[].*settle_key (the key embeds the raw run id)',
      decision_projections_equal: canonicalDigest(projectionA) === canonicalDigest(projectionB),
      artefact_digests_differ: evidenceA.digest !== evidenceB.digest,
      differing_paths_after_masking: diffPaths(evidenceA.document, evidenceB.document).filter((entry) => !(
        entry.startsWith('provenance') || entry.startsWith('artefact_digest') || entry.startsWith('label')
        || entry.startsWith('decision_digest') || entry.startsWith('purge') || entry.startsWith('registry_root')
        || entry.startsWith('holdout_access') || entry === 'trials'
      )),
    };
    repeatability.cross_process.ok = repeatability.cross_process.decision_projections_equal
      && repeatability.cross_process.artefact_digests_differ;
    log(`A5 cross_process projections_equal=${String(repeatability.cross_process.decision_projections_equal)} artefact_digests_differ=${String(repeatability.cross_process.artefact_digests_differ)}`);
   } catch (error) {
     // A run that never executed has no decision projection. That is a NOT_RUN
     // for this witness, not a failure of it.
     repeatability.cross_process = {
       ok: false,
       reason: `PROJECTION_UNAVAILABLE: ${String(error?.code ?? 'RUN_RECORD_MALFORMED')}`,
       detail: 'at least one child produced a refusal record rather than an executed run',
     };
     log(`A5 cross_process NOT_RUN ${repeatability.cross_process.reason}`);
   }
  }
  const repeatChild = spawnRun({ label: 'r', args, corpusDir, write: false, out: null, extra: ['--repeat'] });
  log(`A5 repeat child pid=${repeatChild.pid} exit=${String(repeatChild.exitCode)}`);
  const repeatLines = parseJsonLines(repeatChild.stdout);
  repeatability.child = { exitCode: repeatChild.exitCode, attempts: repeatLines.length };
  repeatability.in_process = parseRepeatWitness(repeatChild.stdout);

  // The verdict, delegated to the comparator's own resolver.
  const verdict = comparison === null
    ? 'HUMAN_REVIEW'
    : resolveCampaignVerdict({ failures: comparison.failures, limits: comparison.limits, proofStatus: comparison.proofStatus });
  if (comparison !== null) {
    for (const entry of comparison.failures) log(`verdict failure ${entry.code} | ${entry.detail}`);
    for (const entry of comparison.limits) log(`verdict limit ${entry.code} | ${entry.detail}`);
  }
  log(`verdict ${verdict}`);

  // --- the properties this replay owns ---------------------------------------
  // Two executed runs are the PRECONDITION of A3 and of half of A5. A property
  // whose precondition is absent is NOT_RUN, never FAILED: "I could not run it"
  // and "I ran it and it did not hold" are different answers.
  const runsExecuted = recordsProduced
    && evidenceA.document.run_status === 'COMPLETED'
    && evidenceB.document.run_status === 'COMPLETED';
  // S5: THE LEDGER SHAPE, as a term of the decision and not as a member of the
  // record that nothing reads. `ledgerShapeIssues` compared the run's journal
  // against the frozen `EXPECTED_LEDGER_SHAPE` and its findings were written to
  // the record and then read by nobody: not by `properties`, not by `overall`,
  // not by the exit code. A real divergence — the delivered run's journal held
  // no ACCESS row at all — gated nothing.
  const ledgerShape = {
    a: evidenceA.document ? ledgerShapeIssues(evidenceA.document) : null,
    b: evidenceB.document ? ledgerShapeIssues(evidenceB.document) : null,
    expected: EXPECTED_LEDGER_SHAPE,
  };
  const ledgerShapeFindings = [...(ledgerShape.a ?? []), ...(ledgerShape.b ?? [])];
  const ledgerShapeOk = recordsProduced && ledgerShapeFindings.length === 0;
  const notRun = notRunEntries;
  if (!childrenRan) notRun.push('CHILD_NOT_SPAWNED');
  if (!recordsProduced) {
    notRun.push(`RUN_RECORD_ABSENT: a=${evidenceA.reason ?? 'no record'} b=${evidenceB.reason ?? 'no record'}`);
  } else if (!runsExecuted) {
    for (const [letter, evidence] of [['a', evidenceA], ['b', evidenceB]]) {
      if (evidence.document.run_status !== 'COMPLETED') {
        notRun.push(`RUN_${letter}_NOT_RUN: ${evidence.document.engine_error?.code ?? `run_status=${evidence.document.run_status}`}`);
      }
    }
  }
  if (crashDocument === null) notRun.push('CRASH_RESTART_NOT_RUN');
  if (repeatability.in_process === null) notRun.push('REPEAT_WITNESS_NOT_RUN');

  const tableFindingsA = evidenceA.document ? expectedValueIssues(evidenceA.document, 'a') : null;
  const properties = [
    {
      id: 'A3',
      statement: 'two process-separated runs with different ids and nonces agree with the FROZEN expected-value table; A === B is additional only',
      // EV1: the two records have to be the ones THIS invocation's children
      // wrote, before their agreement means anything. `recordsProduced` is the
      // conjunction of "the child exited zero", "the record is readable" and
      // "the record names that child's pid".
      ok: recordsProduced
        && separation.ok
        && separation.children_are_separate_processes
        && comparison !== null
        && comparison.findingsA.length === 0
        && comparison.findingsB.length === 0
        && (identicalWrong === null || identicalWrong.both_non_empty === true),
      evidence: `records_produced=${String(recordsProduced)} pid_bound_a=${String(evidenceA.pid_bound)} pid_bound_b=${String(evidenceB.pid_bound)} separation=${String(separation.ok)} separate_pids=${String(separation.children_are_separate_processes)} findingsA=${comparison?.findingsA.length ?? 'n/a'} findingsB=${comparison?.findingsB.length ?? 'n/a'} digestsEqual=${String(comparison?.digestsEqual ?? false)} identical_wrong_both_non_empty=${String(identicalWrong?.both_non_empty ?? false)}`,
    },
    {
      id: 'A5',
      statement: 'every artefact is bound to a commit SHA, a tree SHA and a raw run id, and survives a repeat run on the same base',
      // PR4: `crashClassified.status` is a TERM of A5, not a log line beside it.
      // The interrupted trial and the EXPIRED RESERVATION are the two halves the
      // ticket names, and the classification already decided both
      // (`classifyCrashRestart` in s2-008-run.mjs) — but its status was logged at
      // line 357 and read by nothing, while the property gated only
      // `interrupted_trial_is_a_reconciliation`, which is computed from the
      // reconciliation object rather than from the classification.
      ok: evidenceA.artefact_bound === true
        && evidenceB.artefact_bound === true
        && evidenceA.pid_bound === true
        && evidenceB.pid_bound === true
        && base.track_tracked
        && (repeatability.cross_process?.ok ?? false)
        && (repeatability.in_process?.equivalent ?? false)
        && crashRestart.interrupted_trial_is_a_reconciliation
        && crashClassified !== null
        && crashClassified.status === 'PASS',
      evidence: `bound_a=${String(evidenceA.artefact_bound)} bound_b=${String(evidenceB.artefact_bound)} pid_bound_a=${String(evidenceA.pid_bound)} pid_bound_b=${String(evidenceB.pid_bound)} track_tracked=${String(base.track_tracked)} cross_process=${String(repeatability.cross_process?.ok ?? false)} in_process_repeat=${String(repeatability.in_process?.equivalent ?? false)} reconciliation=${String(crashRestart.interrupted_trial_is_a_reconciliation)} crash_classified=${crashClassified?.status ?? 'NOT_RUN'} crash_classified_reason=${crashClassified?.reason ?? 'no classification'} expired_reservation=${crashDocument === null ? 'NOT_RUN' : String(crashDocument.expired_reservation?.outcome)}/${crashDocument === null ? 'n/a' : String(crashDocument.expired_reservation?.code)}`,
    },
  ];
  for (const property of properties) {
    log(`${property.id} ${property.ok ? 'HELD  ' : (runsExecuted ? 'FAILED' : 'NOT_RUN')} ${property.statement} | ${property.evidence}`);
  }

  for (const property of properties) {
    if (property.ok) property.status = 'HELD';
    else if (!runsExecuted) property.status = 'NOT_RUN';
    else property.status = 'FAILED';
    if (property.status === 'NOT_RUN' && !notRun.includes(`PROPERTY_${property.id}_NOT_RUN`)) {
      notRun.push(`PROPERTY_${property.id}_NOT_RUN: the two runs did not execute, so the property was not checked`);
    }
  }
  const held = properties.filter((property) => property.status === 'HELD').length;
  // EV2 / S6, REPAIRED BY R-C. `overall` COUNTS THE TERMS, AND THE VERDICT IS
  // NOT ONE OF THEM.
  //
  // It used to count ONE — the properties — while the campaign `verdict` was
  // computed three lines above, printed in the same RESULT line, and left out of
  // the decision, and the ledger shape was written to the record and read by
  // nobody. Then it was repaired the other way: the verdict became a TERM, and
  // `verdict_is_pass` made the gate unsatisfiable on a corpus whose honest
  // campaign answer is a null — an ALLOW was reachable only by tuning the
  // fixtures until a fabricated effect looked legitimate, which is the
  // anti-goal. The five decision terms below are the whole decision, each of
  // them a named fact, and the campaign DECISION is compared with the frozen
  // table rather than with a desired verdict. The verdict is still printed,
  // still written, and still visible in the record: a recorded OUTCOME beside
  // the pass condition, never a hidden one and never a term.
  const campaign = campaignDecisionAgreement({
    observed: comparison === null ? null : comparison.runs?.a?.decision ?? null,
    expected: frozenCampaignDecision(),
  });
  log(`campaign expected_decision=${String(campaign.expected)} observed_decision=${String(campaign.observed)} agrees=${String(campaign.agrees)} verdict=${verdict} (a recorded OUTCOME, not a gate term)`);
  for (const finding of campaign.findings) log(`campaign finding ${finding.code} | ${finding.detail}`);
  const controlsAllFlipped = controls !== null && controls.allFlipped === true && controls.notRun.length === 0;
  // F1: EVERY COMPARATOR FAILURE IS A DECISION TERM, or the ones the frozen
  // table does not declare are not. R-C's enumerated pass condition named table
  // divergence, moved counters, NOT_RUN and control flips, and a run record that
  // CARRIES a comparator failure which is none of those was recorded, printed
  // and gated by nothing — `best_seed_undisclosed` reproduces it end to end.
  //
  // The declaration lives in the table (`EXPECTED_COMPARATOR_FAILURES`, derived
  // from its own rows), so this term asks one question: is every failure the
  // comparator raised one the frozen table declares the honest campaign to
  // carry? An undeclared code, or a declared code raised a different number of
  // times, fails the term. The comparator is NOT weakened: it still raises
  // everything it raised before, and the honest campaign still carries its
  // `trial_violation` / `metric_not_measured` / `decision_unresolved` — those
  // are DECLARED, so the fail-closed record is still the green one.
  const unexpectedFailures = unexpectedComparatorFailures({
    failures: comparison?.failures ?? [],
    limits: comparison?.limits ?? [],
    runs: comparison === null ? 0 : 2,
  });
  for (const entry of unexpectedFailures) log(`unexpected comparator finding ${entry.code} ${entry.field} | ${entry.detail}`);
  const comparatorFailuresDeclared = unexpectedFailures.length === 0;
  const overallTerms = {
    every_property_held: held === properties.length,
    held,
    total: properties.length,
    expected_campaign_decision: campaign.expected,
    observed_campaign_decision: campaign.observed,
    decision_agrees_with_table: campaign.agrees,
    campaign_findings: campaign.findings.map((finding) => ({ code: finding.code, field: finding.field, expected: finding.expected, observed: finding.observed })),
    controls_all_flipped: controlsAllFlipped,
    controls_not_run: controls === null ? null : controls.notRun.length,
    comparator_failures_match_frozen_expectation: comparatorFailuresDeclared,
    unexpected_comparator_findings: unexpectedFailures.map((entry) => ({ code: entry.code, field: entry.field, expected: entry.expected, observed: entry.observed })),
    ledger_shape_matches_table: ledgerShapeOk,
    ledger_shape_findings: ledgerShapeFindings.length,
    not_run_zero: notRun.length === 0,
    not_run_count: notRun.length,
    // REPORTED, NOT A TERM. See the comment above.
    verdict,
  };
  const overall = notRun.length > 0
    ? 'NOT_RUN'
    : (overallTerms.every_property_held
      && overallTerms.decision_agrees_with_table
      && overallTerms.controls_all_flipped
      && overallTerms.comparator_failures_match_frozen_expectation
      && overallTerms.ledger_shape_matches_table
      ? 'PASS' : 'FAIL');
  // EV5: the exit code the process WILL exit with is part of the record. The
  // aggregator's `green-with-nonzero-exit` rule reads `record.exitCode`, and the
  // replay never wrote one, so the rule was dead code: `node -e "'exitCode' in
  // require('./evidence/s2-008-replay.json')"` answered false.
  const exitCode = overall === 'PASS' ? 0 : (overall === 'NOT_RUN' ? 3 : 1);
  log(`RESULT properties_held=${held}/${properties.length} not_run=${notRun.length} verdict=${verdict} overall=${overall}`);
  log(`RESULT overall_terms ${JSON.stringify(overallTerms)}`);
  if (notRun.length > 0) log(`RESULT not_run_entries=${JSON.stringify(notRun)}`);

  const finishedAt = new Date().toISOString();
  const record = {
    ticket: 'S2-008',
    kind: 'REPLAY',
    version: 's2-008-replay-v1',
    gate: 'scripts/s2-008-replay.mjs',
    owned_properties: [...OWNED_PROPERTIES],
    evidence_eligible: evidenceEligible,
    write_evidence: writeChildren && evidenceEligible,
    // THE INVOCATION BINDING, at the top level so the aggregator can read both
    // members without walking: `invocation_id` is the chain's per-run id (null
    // when a human started this replay), `head_tree_sha` the tree the record is
    // about. A record copied from an earlier run carries that run's id and
    // cannot match the id this run generated.
    invocation_id: invocationId,
    head_tree_sha: base.tree_sha,
    invocation: {
      invocation_id: invocationId,
      head_tree_sha: base.tree_sha,
      source: 'scripts/verify-s2-008.mjs generates one id per chain run and passes it with --invocation-id; a replay started by hand records null and says so',
      purpose: 'to tell this run\'s record from a copy of an earlier run\'s record — nothing else',
      decides: false,
      excluded_from_repeatability: true,
      excluded_fields: ['invocation_id', 'invocation.invocation_id'],
      note: 'the id is unique per aggregator run and carries no information about the campaign; the properties, the verdict and the exit code are computed exactly as they are without it',
    },
    base,
    corpus: { dir: rel(corpusDir), preregistration_digest: prereg.preregistration_digest ?? null, expected_table_digest: tableDigest },
    children: { a: { ...childA, stdout: undefined, stderr: childA.stderr.slice(-800) }, b: { ...childB, stdout: undefined, stderr: childB.stderr.slice(-800) } },
    evidence: {
      a: {
        path: evidenceA.path, artefact_bound: evidenceA.artefact_bound, digest: evidenceA.digest,
        readable: evidenceA.readable, child_pid: evidenceA.child_pid, record_pid: evidenceA.record_pid,
        pid_bound: evidenceA.pid_bound, pid_binding_reason: evidenceA.pid_binding_reason,
      },
      b: {
        path: evidenceB.path, artefact_bound: evidenceB.artefact_bound, digest: evidenceB.digest,
        readable: evidenceB.readable, child_pid: evidenceB.child_pid, record_pid: evidenceB.record_pid,
        pid_bound: evidenceB.pid_bound, pid_binding_reason: evidenceB.pid_binding_reason,
      },
    },
    separation,
    controls: { allFlipped: controls.allFlipped, gate, record: controls, notRun: controls.notRun, error: controlsError, attached_before_comparison: true },
    comparison,
    comparison_error: comparisonError,
    // R-C: the campaign decision beside the pass condition, so a reader of ONE
    // file sees both the answer and what the gate decided about it.
    campaign: {
      expected_decision: campaign.expected,
      observed_decision: campaign.observed,
      agrees_with_table: campaign.agrees,
      findings: campaign.findings,
      verdict,
      verdict_is_a_gate_term: false,
    },
    // F1: the comparator's own failure list, next to the terms that gate on it.
    comparator_failures: {
      declared_per_run: EXPECTED_COMPARATOR_FAILURES,
      observed_failures: comparison?.failures ?? [],
      observed_limits: comparison?.limits ?? [],
      unexpected: unexpectedFailures,
      is_a_gate_term: true,
    },
    expected_campaign_decision: campaign.expected,
    observed_campaign_decision: campaign.observed,
    decision_agrees_with_table: campaign.agrees,
    table_findings_a: tableFindingsA,
    ledger_shape: ledgerShape,
    ledger_shape_ok: ledgerShapeOk,
    identical_wrong: identicalWrong,
    crash_restart: crashRestart,
    repeatability,
    verdict,
    properties,
    // EV5: the exit code this invocation exits with, INSIDE the bytes it writes,
    // so the aggregator's `green-with-nonzero-exit` rule reads a real member
    // instead of being dead code.
    exitCode,
    overall,
    overall_terms: overallTerms,
    // EV1: which child produced which record, and by which test.
    child_binding: childProduced,
    not_run: notRun,
    harness_findings: {
      a: evidenceA.document?.harness_findings ?? null,
      b: evidenceB.document?.harness_findings ?? null,
    },
    // The ONLY wall-clock member in this record. It exists so the aggregator can
    // refuse a stale green file, it decides nothing, and the repeatability
    // comparison excludes it by name.
    freshness: {
      observed_at: observedAt,
      finished_at: finishedAt,
      source: 'wall_clock',
      decides: false,
      excluded_from_repeatability: true,
    },
    written: null,
  };
  const outFile = path.join(REPO_ROOT, typeof args.out === 'string' ? args.out : OUT_RELATIVE);
  const write = writeChildren && evidenceEligible;
  // The body is built in BOTH modes, so a check run can publish the digest of
  // the bytes it did NOT write. The aggregator reads `REPLAY_EVIDENCE_SHA256`
  // to tell "the record on disk is the one this invocation wrote" from "a
  // previous green file is lying there", and that question has to be answerable
  // when nothing was written — under `--no-write` the same digest is reported on
  // its own line as NOT_ON_DISK, never as a claim that it is on disk.
  const body = `${JSON.stringify(record, null, 2)}\n`;
  const bytesSha256 = createHash('sha256').update(body).digest('hex');
  if (writeChildren && evidenceEligible) {
    mkdirSync(path.dirname(outFile), { recursive: true });
    writeFileSync(outFile, body, 'utf8');
    // The digest of the EXACT BYTES written, printed so the aggregator can tell
    // "the record on disk is what this invocation wrote" from "a previous green
    // file is lying there". A digest of the in-memory object would not survive
    // the `written` member this very line adds.
    record.written = { path: rel(outFile), bytes: Buffer.byteLength(body), bytes_sha256: bytesSha256 };
    log(`wrote ${rel(outFile)} bytes=${Buffer.byteLength(body)} bytes_sha256=${bytesSha256}`);
    log(`REPLAY_EVIDENCE_SHA256 ${bytesSha256}`);
  } else {
    log(`not written to evidence/: evidence_eligible=${String(evidenceEligible)} (a non-committed corpus is never evidence)`);
    log(`REPLAY_EVIDENCE_SHA256_NOT_ON_DISK ${bytesSha256}`);
  }
  log(`RESULT exit_code=${exitCode}`);
  return { record, exitCode, comparison, controls, crashRestart, repeatability, properties, overall, notRun, separation, evidenceA, evidenceB, verdict };
}

/** The last JSON line of a child's stdout: the crash/restart record, which is
 *  printed after the human-readable block. */
function parseLastJsonLine(text) {
  const lines = String(text ?? '').trimEnd().split('\n');
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index].trim();
    if (!line.startsWith('{')) continue;
    try {
      return JSON.parse(line);
    } catch {
      continue;
    }
  }
  return null;
}

function parseJsonLines(text) {
  return String(text ?? '').split('\n').filter((line) => line.trim().startsWith('{')).map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  }).filter((value) => value !== null);
}

/** The in-process repeat witness, read back out of the child's summary block.
 *  The child is the authority on its own two attempts; this parses the lines it
 *  printed rather than re-deriving the comparison here. */
function parseRepeatWitness(text) {
  const body = String(text ?? '');
  const equivalent = /A5 repeat equivalent=(\w+)/.exec(body);
  const projections = /decision_projections_equal=(\w+)/.exec(body);
  const artefactDiffer = /artefact_digests_differ=(\w+)/.exec(body);
  if (equivalent === null) return null;
  return {
    equivalent: equivalent[1] === 'true',
    decision_projections_equal: projections === null ? null : projections[1] === 'true',
    artefact_digests_differ: artefactDiffer === null ? null : artefactDiffer[1] === 'true',
    source: 'scripts/s2-008-run.mjs --repeat (one process, two attempts, two raw run ids)',
  };
}

async function main() {
  const args = parseArgs(process.argv);
  const result = await replay(args, process.argv);
  process.exitCode = result.exitCode;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify({
      ticket: 'S2-008',
      gate: 'scripts/s2-008-replay.mjs',
      status: 'NOT_RUN',
      ok: false,
      exitCode: 2,
      code: String(error?.code ?? 'REPLAY_ERROR'),
      error: String(error?.message ?? error).slice(0, 600),
      stack: String(error?.stack ?? '').split('\n').slice(0, 6),
    }, null, 2)}\n`);
    process.exitCode = 2;
  });
}
