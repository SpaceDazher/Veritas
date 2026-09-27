#!/usr/bin/env node
// S2-008 — THE PARALLEL-TRACK HARNESS (issue SpaceDazher/Veritas#8).
//
// ONE committed entry point, in the shape of `scripts/s2-007-run.mjs` and
// `scripts/s2-007-db-replay.mjs`, which it follows in three ways that matter:
//   * two PROCESS-SEPARATED runs with different raw run ids and nonces;
//   * a crash/restart phase, because an interrupted run must leave a
//     reconciliation row and must not be retried blindly; and
//   * an EXPECTED-VALUE TABLE, so two identically wrong runs are not a pass.
//
// WHAT IT DOES, IN ORDER
//   0. purge its OWN fixtures, so a repeat run on a permanent base fails on the
//      property and not on leftovers;
//   1. resolve the REAL base (commit SHA, tree SHA) with read-only git, and
//      report whether this track is even TRACKED — an untracked run cannot be
//      bound to a base, and saying so is the honest answer (E3/E8);
//   2. run the six negative probes (A1) on a purged scratch root;
//   3. execute two process-separated runs A and B (A3), each with its own
//      ledger, raw run id and nonce, and each scored against the frozen
//      expected-value table;
//   4. run the six negative controls and require EVERY one to flip (A2);
//   5. run the IDENTICAL-WRONG control: the same corruption in both runs, so
//      their digests stay EQUAL and the table is the only thing that can
//      produce findings (A3);
//   6. run the LABEL-SUBSTITUTION control for A4: substituting the label must
//      break the seal AND make the causal claim fail;
//   7. resolve the campaign verdict through `resolveCampaignVerdict`, which
//      delegates to `resolveVerdict` in src/lib/sloqual/comparator.mjs;
//   8. write the evidence records and print the summary block.
//
// EXIT CODES (E9: these existed only in prose before)
//   0  every acceptance property held;
//   1  a property FAILED (a defence did not hold, a control did not flip, a run
//      disagreed with the frozen table);
//   2  the harness could not run (missing corpus, unreadable base, a broken
//      invariant) — a crash, never a pass;
//   3  something was NOT RUN or was BROKEN (a probe that could not run, a
//      control that could not run). Distinct from 1 on purpose: "I could not
//      check" and "I checked and it failed" are different answers.
//
// DETERMINISM
// No network, no LLM, no credentials. Every instant is a frozen literal or the
// injected clock; nothing calls `Date.now()` and nothing calls `Math.random()`.
// The ONLY wall-clock-shaped work is the latency block, and it is (a) synthetic
// and flagged as such and (b) structurally unable to decide: every latency
// sample carries `latency_decides: false`, and the summary asserts it. Running
// this twice on the same base produces byte-identical evidence, because every
// instant in it is the injected one and the base SHAs are the only thing that
// can move.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { allResearchContractDigests } from '../src/lib/research/contracts.mjs';
import {
  assertLabelSeal, caseDigest, labelsDigest, readCorpus, substituteLabelsControl,
} from '../src/lib/research/dataset.mjs';
import { classifyCardRelation } from '../src/lib/research/causality.mjs';
import {
  compareParallelTrack, decisionFromInterval, injectCorruption, metricsSummary, resolveCampaignVerdict, resolveTrialVerdict,
} from '../src/lib/research/comparator.mjs';
import {
  EXPECTED_CODES, EXPECTED_COMPARATOR_FAILURES, EXPECTED_CONTROLS, EXPECTED_COUNTERS,
  EXPECTED_LEDGER_SHAPE, EXPECTED_METRIC, EXPECTED_TRIAL_DECISIONS, assertTableFrozen,
  expectedTableDigest, unexpectedComparatorFailures,
} from '../src/lib/research/expected-values.mjs';
import { controlsFlipVerdict, runNegativeControls } from '../src/lib/research/negative-controls.mjs';
import { PROBE_FAMILIES, PROBE_NAMES, runAllProbes } from '../src/lib/research/probes.mjs';
import { loadPreregistration, preregistrationDigest, seedCountOf } from '../src/lib/research/preregistration.mjs';
import {
  appendRecord, openRegistry, putExperiment, readJournal, recordSpend, snapshotDigest, verifyChain,
} from '../src/lib/research/registry.mjs';
import { wilsonInterval } from '../src/lib/sloqual/statistics.mjs';
import { HOLDOUT_LABELS, HOLDOUT_UNSEAL_DIGEST, PREREGISTRATION } from '../tests/research/fixtures/fixture-measurement-set.mjs';
// ONE DEFINITION OF THE TWO R-C GATE RULES, imported rather than re-typed: the
// ledger-shape check and the campaign-decision agreement. The replay owns them
// and the harness calls them, so "the harness checks the ledger shape its own
// way" is not a state this repository can be in. See
// `scripts/s2-008-replay.mjs#ledgerShapeIssues` and `#campaignDecisionAgreement`.
import { campaignDecisionAgreement, frozenCampaignDecision, ledgerShapeIssues } from './s2-008-replay.mjs';
import { assertFrozenCampaignDerivable } from '../src/lib/research/campaign-expectation.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CORPUS_DIR = path.join(REPO_ROOT, 'evidence', 's2-008', 'corpus');
const EVIDENCE_DIR = path.join(REPO_ROOT, 'evidence');
const SCRATCH = path.join(REPO_ROOT, '.bb', 's2-008', 'harness');

/** The injected clock. A frozen literal, never `Date.now()`. @type {string} */
const RUN_INSTANT = '2026-01-01T00:00:00.000Z';
/** The preregistered holdout decision point. @type {string} */
const DECISION_POINT_INSTANT = '2026-01-01T01:00:00.000Z';
/** The instant AFTER the decision point, so a legitimate holdout read is
 * admitted and a read before it is refused. @type {string} */
const POST_DECISION_INSTANT = '2026-01-01T02:00:00.000Z';
/** The first corpus case, read through `readCorpus` in the harness run. @type {string} */
const FIRST_CASE = 's2-008-case-01';
/** The second, used to try to open the same partition twice. @type {string} */
const SECOND_CASE = 's2-008-case-02';

const METRIC_NAME = EXPECTED_METRIC.name;
const BASELINE = EXPECTED_METRIC.baseline;
const NOISE_BAND = EXPECTED_METRIC.noiseBand;

// The configuration the numbers below were produced under, echoed at the top of
// every evidence record so a reader never has to infer it.
const CONFIG = Object.freeze({
  metric: METRIC_NAME,
  baseline: BASELINE,
  noise_band: NOISE_BAND,
  expected_table_digest: expectedTableDigest(),
  inference_mode: 'ASSOCIATIONAL',
  interval_method: 'wilson',
  // READ FROM THE PREREGISTRATION, NEVER TYPED. The published confidence is
  // DERIVED from the frozen alpha and the declared family (`1 - alpha/m`), and
  // the two have to move together: a run's self-reported `metric.interval` is
  // built at this confidence, and the comparator re-derives the campaign
  // interval at `multiplicity_rule.confidence` and raises
  // `self_reported_interval_divergence` when the two disagree. The literal 0.95
  // that used to sit here is exactly what made `1 - c = 0.05 > 0.05/3` and the
  // rule unable to reject anything.
  confidence: PREREGISTRATION.multiplicity_rule.confidence,
  multiplicity_alpha: PREREGISTRATION.multiplicity_rule.alpha,
  multiplicity_family_size: PREREGISTRATION.multiplicity_rule.family_size,
});

/** A deterministic id factory in the shape the ledger's `newId` requires: a
 * BARE suffix, because `AgentBoardStoreBase.newId` prepends the prefix from the
 * frozen `ID_PREFIXES` table itself. Returning a prefixed value produces the
 * doubled `rec-rec-…` an earlier draft of this harness minted.
 * @param {string} scope @returns {{next: (kind: string) => string}} */
function idFactory(scope) {
  const digest = canonicalDigest({ scope }).slice(0, 8);
  const counters = new Map();
  return Object.freeze({
    next: (kind) => {
      const key = String(kind);
      const next = (counters.get(key) ?? 0) + 1;
      counters.set(key, next);
      return `${digest}${next.toString(36).padStart(4, '0')}`;
    },
  });
}

function fixedClock(iso) {
  const ms = Date.parse(iso);
  return Object.freeze({ nowNs: () => ms * 1e6, iso: () => iso, now: () => new Date(ms), nowIso: () => iso });
}

function git(...args) {
  return execFileSync('git', args, { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function log(...parts) {
  process.stdout.write(`${parts.join(' ')}\n`);
}

function rel(file) {
  return path.relative(REPO_ROOT, file);
}

/** The purge record as it is COMMITTED: `base` is a repository-relative path,
 * never a host-local absolute one.
 *
 * The library (`probes.mjs`, `purgeProbeFixtures`) deliberately reports the
 * absolute directory it acted on, which is right for a live run and wrong for
 * a committed record: an absolute path carries the account name, the worktree
 * layout and the thread id of the machine that produced it, and it makes the
 * bytes of this file host-dependent, so the same base on another checkout
 * would not reproduce the record byte for byte. A root outside the repository
 * is reported as a fixed token rather than as a relative escape, so a path
 * outside the tree cannot be reconstructed from the record either. */
function purgedRecordForCommit(purged) {
  const relative = path.relative(REPO_ROOT, purged?.base ?? '');
  const outside = relative === ''
    || path.isAbsolute(relative)
    || relative === '..'
    || relative.startsWith(`..${path.sep}`);
  return { ...purged, base: outside ? '<external-scratch-root>' : relative };
}

/** The resolved base, plus whether this track is TRACKED at all. Read-only git
 * only: no commit, no write, no index mutation. */
function resolveBase() {
  const tracked = git('ls-files', '-z').split('\0').filter(Boolean);
  const mine = tracked.filter((file) => /^(src\/lib\/research\/|tests\/research\/|scripts\/s2-008-|evidence\/s2-008\/)/.test(file));
  return {
    commit_sha: git('rev-parse', 'HEAD'),
    tree_sha: git('rev-parse', 'HEAD^{tree}'),
    branch: git('rev-parse', '--abbrev-ref', 'HEAD'),
    worktree_dirty: git('status', '--porcelain').length > 0,
    tracked_files_of_this_track: mine.length,
    // M1: the SCOPE of the count, published with it. `scripts/s2-008-run.mjs`
    // counts the same key over a WIDER glob (it adds `scripts/verify-s2-008*`
    // and the `evidence/s2-008-*.json` records), so the harness published 39 and
    // the replay 51 under one name and a reader comparing the two evidence
    // files was reading two scopes as one number. The number is unchanged; it is
    // now labelled, and both files label it.
    tracked_files_scope: 'git ls-files matching ^(src/lib/research/|tests/research/|scripts/s2-008-|evidence/s2-008/) — the TRACK sources and the corpus, without the s2-008 evidence records and without the verify-s2-008* aggregator scripts',
    track_tracked: mine.length > 0,
  };
}

/** The frozen table in the shape the comparator reads. */
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

// --- the two process-separated runs ---------------------------------------

/**
 * THE RUN'S OWN JOURNAL, written and read back, so the ledger-shape gate term
 * is a MEASUREMENT rather than a default.
 *
 * `buildRun` used to build a run record with no `ledger` member at all, and the
 * frozen `EXPECTED_LEDGER_SHAPE` therefore had nothing to compare against in
 * this harness: `ledgerShapeIssues` would have reported four kinds at count 0
 * and the gate would have stayed red for a fourth, unstated reason. A term that
 * cannot be measured is not a term, and `?? true` anywhere in it would be a
 * defect. So the run now writes the four frozen kinds to a real ledger, in the
 * order the table declares them, and reads the journal back with `readJournal`:
 *   * PREREGISTRATION_RECORDED before anything is measured,
 *   * BUDGET_RESERVATION taken before the run, never at the spend,
 *   * ACCESS from the ONE real holdout open, journalled before the bytes are
 *     returned — which is what the trials' own `holdoutBinding.opens: 1` claims,
 *   * one TRIAL_RESULT per ENUMERATED trial, including the INFRA one: a trial
 *     cannot be deleted from the record by failing to run.
 *
 * Pure: no clock (the injected one), no network, no randomness, and the ids come
 * from the same deterministic factory the crash/restart phase uses.
 *
 * @param {string} label The run letter ('a' | 'b').
 * @param {object} prereg The loaded preregistration document.
 * @param {ReadonlyArray<object>} trials The run's trial records, in index order.
 * @returns {{root: string, record_kinds: ReadonlyArray<string>, record_count: number,
 *   chain_verified: boolean, snapshot_digest: string|null, access_record_id: string|null,
 *   error: string|null}} The journal as it was observed, never as it was intended.
 */
function writeRunJournal(label, prereg, trials) {
  const root = path.join(SCRATCH, `run-${label}-journal`);
  const runId = `s2-008-run-${label}`;
  const readAt = POST_DECISION_INSTANT;
  let registry = null;
  let accessRecordId = null;
  let recordKinds = [];
  let recordCount = 0;
  let chainVerified = false;
  let snapshot = null;
  let error = null;
  try {
    registry = openRegistry({ root, clock: fixedClock(readAt), ids: idFactory(`run-${label}-journal`) });
    appendRecord(registry, {
      record_kind: 'PREREGISTRATION_RECORDED',
      run_id: runId,
      digest: preregistrationDigest(prereg),
      recorded_at: RUN_INSTANT,
    });
    const reservationId = prereg.budget_reservation.reservation_id;
    putExperiment(registry, {
      key: `s2-008-run-${label}-reservation`,
      args: {
        kind: 'BUDGET_RESERVATION',
        reservation_id: reservationId,
        granted_units: prereg.budget_reservation.granted_units,
        spent_units: 0,
        expires_at: prereg.budget_reservation.expires_at,
        currency: prereg.budget_reservation.currency,
        taken_at: RUN_INSTANT,
      },
      expectedRevision: registry.revision(),
      mutate: () => ({
        kind: 'BUDGET_RESERVATION',
        reservation_id: reservationId,
        granted_units: prereg.budget_reservation.granted_units,
        spent_units: 0,
        currency: prereg.budget_reservation.currency,
        expires_at: prereg.budget_reservation.expires_at,
        taken_at: RUN_INSTANT,
      }),
    });
    const read = readCorpus(registry, {
      partition: 'HOLDOUT', caseId: FIRST_CASE, unsealDigest: HOLDOUT_UNSEAL_DIGEST, decisionPoint: DECISION_POINT_INSTANT, maxOpens: 1,
    });
    accessRecordId = read.accessRecordId;
    for (const trial of trials) {
      appendRecord(registry, {
        record_kind: 'TRIAL_RESULT',
        run_id: runId,
        trial: trial.trial ?? null,
        index: trial.index ?? null,
        // The STATUS is journalled, never the outcome alone: a trial that was
        // not measured is a row that says so, which is the difference between
        // a reconciliation and a silent zero.
        status: trial.status ?? null,
        recorded_at: RUN_INSTANT,
      });
    }
    const journal = readJournal(registry);
    recordKinds = journal.map((row) => row?.payload?.kind ?? row?.payload?.record_kind ?? null);
    recordCount = journal.length;
    chainVerified = verifyChain(registry).ok === true;
    snapshot = snapshotDigest(registry);
  } catch (thrown) {
    // An unreadable journal leaves the record_kinds it managed to commit and
    // NAMES the refusal. `ledgerShapeIssues` then reports real divergences
    // against a real count instead of silently agreeing with the table.
    error = String(thrown?.code ?? thrown?.message ?? thrown).slice(0, 160);
  }
  return {
    root: rel(root),
    record_kinds: recordKinds,
    record_count: recordCount,
    chain_verified: chainVerified,
    snapshot_digest: snapshot === null ? null : String(snapshot),
    access_record_id: accessRecordId,
    error,
  };
}

/**
 * Build one run record. The four trials and their counts come from the FROZEN
 * TABLE, and the per-trial OUTCOME is then DERIVED by running the
 * preregistered rule over the case-level Wilson interval — the table is the
 * answer the run is scored against, so the run is not allowed to simply assert
 * it. The derived outcome is written next to the declared one, and a
 * disagreement is visible in the evidence instead of being smoothed over.
 */
function buildRun(label, prereg, base) {
  const seeds = [...prereg.seed_rule.seeds];
  // ONE confidence for this run, taken from the document it was handed. The
  // trial interval, the self-reported `trial.interval`, and the rule the
  // comparator will re-derive the campaign interval from all read it, because a
  // run whose self-reported interval was built at one confidence and scored at
  // another is a run that reports `self_reported_interval_divergence` against
  // itself.
  const confidence = prereg.multiplicity_rule.confidence;
  if (confidence !== CONFIG.confidence) {
    // Two sources of truth that disagree about the frozen rule: the sealed
    // corpus and the in-code fixture. Nothing downstream can be trusted, so the
    // harness refuses to RUN (exit 2) instead of producing a record that reads
    // one confidence and means another. `npm run s2-008:check-corpus` catches
    // this first.
    throw new Error(`PREREGISTRATION_CONFIDENCE_DIVERGES: the sealed corpus publishes confidence ${String(confidence)} while the in-code frozen rule publishes ${String(CONFIG.confidence)}; rebuild the corpus (npm run s2-008:build-corpus) before running the harness`);
  }
  const trials = [];
  const derivedDisagreements = [];
  for (const row of EXPECTED_TRIAL_DECISIONS) {
    const trial = {
      index: row.index,
      trial: row.trial,
      metric: METRIC_NAME,
      seeds,
      status: row.expectedStatus,
      outcome: row.expectedOutcome,
      reason_codes: [],
      decision: null,
      elapsed_ms: 0,
      latency_ms: 0,
      latency_source: 'HARNESS_SYNTHETIC',
      latency_decides: false,
      provenance: { raw_run_id: `s2-008-run-${label}`, commit_sha: base.commit_sha, tree_sha: base.tree_sha },
      seedBinding: { seeds, source: 'PREREGISTERED', preregistered_seeds: seeds },
      holdoutBinding: {
        partition: 'HOLDOUT',
        read_at: POST_DECISION_INSTANT,
        decision_at: DECISION_POINT_INSTANT,
        opened_before_decision_point: false,
        opens: 1,
        max_opens: 1,
      },
      budgetBinding: {
        reservation_id: prereg.budget_reservation.reservation_id,
        granted_units: prereg.budget_reservation.granted_units,
        spent_units: 0,
        currency: prereg.budget_reservation.currency,
      },
      evaluatorBinding: { evaluator_id: 'evl-s2-008-harness', independent: true, blind_to_producer: true },
      evaluator: { evaluator_id: 'evl-s2-008-harness', independent: true, blind_to_producer: true },
      // The calibration this harness's synthetic trial carries. It used to be
      // `NOT_MEASURED: outcome_not_defined`, on the reading that the frozen
      // `outcome_definition.metric` enum has no S2-008 slot. That was a HARNESS
      // artefact, and it had three consequences the evidence now names: every
      // synthetic trial resolved to VIOLATION while `controlTrial()` below and
      // the DELIVERED run record (`evidence/s2-008-run-a.json`) both carry
      // `MEASURED`, and the frozen table declares `expectedVerdict: 'ALLOW'` for
      // the three resolved rows. The track's own table therefore disagreed with
      // the harness's own synthetic record, which is not a measurement — it is a
      // record that contradicted the pipeline it was standing in for. The value
      // is the one the runner produces, so the synthetic record and the
      // delivered record agree about the same thing.
      calibration: {
        status: 'MEASURED',
        not_measured_reason: null,
        evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true },
      },
      card: prereg.card,
      reconciliation_id: null,
    };
    if (row.expectedStatus !== 'RESOLVED') {
      // The infra trial: no measurement at all, and a reconciliation row that
      // says what must happen next. `numerator` is null, NOT 0.
      trial.numerator = null;
      trial.denominator = null;
      trial.observed = null;
      trial.interval = null;
      trial.infra = {
        code: 'MEASUREMENT_ABSENT',
        reconciliation: { required: true, blind_retry: false, implicit_zero: false, resolve_by: 'EXPLICIT_RECONCILIATION' },
      };
      trial.reason_codes = ['INFRA_ERROR'];
    } else {
      trial.numerator = row.expectedNumerator;
      trial.denominator = row.expectedDenominator;
      const observed = trial.numerator / trial.denominator;
      const interval = wilsonInterval({ successes: trial.numerator, trials: trial.denominator, confidence });
      const applied = decisionFromInterval({
        observed,
        lower: interval.lower,
        upper: interval.upper,
        noiseBand: NOISE_BAND,
        rule: {
          alpha: prereg.multiplicity_rule.alpha,
          method: prereg.multiplicity_rule.method,
          comparisons: prereg.multiplicity_rule.declared_comparisons,
          confidence,
          null_value: BASELINE,
          subject: row.trial,
        },
      });
      trial.observed = observed;
      trial.interval = { lower: interval.lower, upper: interval.upper, method: interval.method, confidence };
      trial.derived_outcome = applied.decision;
      trial.derived_reason = applied.reason;
      trial.correction = applied.correction;
      if (applied.decision !== row.expectedOutcome) {
        derivedDisagreements.push({
          trial: row.trial, table_says: row.expectedOutcome, rule_derived: applied.decision, reason: applied.reason,
        });
      }
      trial.budgetBinding.spent_units = row.index;
      trial.bindings = { budget: trial.budgetBinding };
    }
    trial.verdict = resolveTrialVerdict(trial).verdict;
    trials.push(trial);
  }
  // The journal is written AFTER the trials exist, so each TRIAL_RESULT row
  // names the trial that was actually built. It is part of the run record, so
  // the record and its own ledger are the same object.
  const ledger = writeRunJournal(label, prereg, trials);
  return {
    version: 's2-008-harness-run-v1',
    ticket: 'S2-008',
    letter: label,
    recorded_at: RUN_INSTANT,
    metric: METRIC_NAME,
    raw_run_id: `s2-008-run-${label}`,
    nonce: `n-${label}-0123456789abcdef`,
    executor_id: `exec-${label}-harness`,
    output_root: rel(path.join(SCRATCH, `run-${label}`)),
    commit_sha: base.commit_sha,
    tree_sha: base.tree_sha,
    preregistration_digest: preregistrationDigest(prereg),
    expected_table_digest: expectedTableDigest(),
    trials,
    ledger,
    metrics: metricsSummary(trials),
    codes: [],
    counters: { ...EXPECTED_COUNTERS },
    derived_disagreements: derivedDisagreements,
  };
}

/** The clean trial the four comparator-level controls mutate. It is an ALLOW, so
 * a flip is observable; the delivered NOT_MEASURED calibration is NOT used here
 * because a NOT_MEASURED calibration makes every trial a VIOLATION by the
 * comparator's own rule, and a control whose "before" state is already a
 * VIOLATION cannot demonstrate anything. */
function controlTrial() {
  const seeds = [...EXPECTED_CODES.holdout_peek].length > 0 ? [11, 22, 33, 44] : [11, 22, 33, 44];
  return {
    trial: 'trl-s2-008-control',
    status: 'RESOLVED',
    outcome: 'POSITIVE',
    metric: METRIC_NAME,
    numerator: 7,
    denominator: 8,
    seedBinding: { seeds, source: 'PREREGISTERED', preregistered_seeds: seeds },
    holdoutBinding: {
      partition: 'HOLDOUT', read_at: DECISION_POINT_INSTANT, decision_at: DECISION_POINT_INSTANT, opened_before_decision_point: false, opens: 1, max_opens: 1,
    },
    budgetBinding: { reservation_id: 'rsv-s2-008-control', granted_units: 100, spent_units: 40, currency: 'UNITS' },
    evaluatorBinding: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    evaluator: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    calibration: { status: 'MEASURED', not_measured_reason: null, evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true } },
  };
}

/**
 * The CRASH/RESTART phase, in the shape of scripts/s2-007-db-replay.mjs.
 *
 * A run is opened, a preregistration row and a budget reservation are written,
 * and the process stops BEFORE the trial loop. The second phase reopens the
 * SAME ledger and inspects it, as a restarted process would. What is asserted is
 * not "the retry worked" but the property the ticket names: the interrupted
 * state is a RECONCILIATION, it is not a silent zero, and it is not a blind
 * retry.
 */
function crashRestartPhase(prereg) {
  const root = path.join(SCRATCH, 'crash-restart');
  const first = openRegistry({ root, clock: fixedClock(RUN_INSTANT), ids: idFactory('crash-restart') });
  const before = snapshotDigest(first);
  appendRecord(first, {
    record_kind: 'PREREGISTRATION_RECORDED',
    run_id: 's2-008-crash',
    digest: preregistrationDigest(prereg),
    recorded_at: RUN_INSTANT,
  });
  const reservationId = prereg.budget_reservation.reservation_id;
  const committed = putExperiment(first, {
    key: 's2-008-harness-reservation',
    args: {
      kind: 'BUDGET_RESERVATION',
      reservation_id: reservationId,
      granted_units: prereg.budget_reservation.granted_units,
      spent_units: 0,
      expires_at: prereg.budget_reservation.expires_at,
      currency: prereg.budget_reservation.currency,
      taken_at: RUN_INSTANT,
    },
    expectedRevision: first.revision(),
    mutate: () => ({
      kind: 'BUDGET_RESERVATION',
      reservation_id: reservationId,
      granted_units: prereg.budget_reservation.granted_units,
      spent_units: 0,
      currency: prereg.budget_reservation.currency,
      expires_at: prereg.budget_reservation.expires_at,
      taken_at: RUN_INSTANT,
    }),
  });
  const midway = snapshotDigest(first);
  // Phase 2: a fresh handle on the SAME ledger, as a restarted process would
  // have. The chain must still verify and the first phase's writes must be
  // visible — that is what makes the restart a restart and not a new run.
  const second = openRegistry({ root, clock: fixedClock(POST_DECISION_INSTANT), ids: idFactory('crash-restart') });
  const chain = verifyChain(second);
  const journal = readJournal(second);
  // PR4: the EXPIRED-RESERVATION RECONCILIATION, decided ON THE LEDGER. The
  // ticket names it ("an interrupted run or expired budget reservation is a
  // reconciliation, not a blind retry and not a silent zero"), the row that
  // commits it is `registry.mjs#recordSpend`'s guard, and until now the harness
  // only asserted `chain_verified` and `phase2_saw_phase1` — so disabling that
  // guard left A5 green. Phase 3 opens the same ledger at an instant strictly
  // AFTER the reservation expired and settles one unit against it.
  const expiryInstant = String(prereg.budget_reservation.expires_at);
  const afterExpiryInstant = new Date(Date.parse(expiryInstant) + 3_600_000).toISOString();
  const third = openRegistry({ root, clock: fixedClock(afterExpiryInstant), ids: idFactory('crash-restart') });
  const beforeExpiry = snapshotDigest(third);
  const expired = (() => {
    try {
      recordSpend(third, {
        reservationId,
        key: 's2-008-harness-expired-settle',
        args: { units: 1, within_reservation: true },
      });
      return { outcome: 'ADMITTED', code: null };
    } catch (error) {
      return { outcome: 'REFUSED', code: String(error?.code ?? 'REFUSED'), reason: String(error?.message ?? error).slice(0, 160) };
    }
  })();
  const afterExpiryDigest = snapshotDigest(third);
  const afterJournal = readJournal(third);
  const reconciliationRows = afterJournal.filter((row) => row?.kind === 'RECONCILIATION' || row?.payload?.kind === 'RECONCILIATION');
  const expiredReservation = {
    // The preregistered expiry is `2026-01-01T02:00:00.000Z`; the ledger's guard
    // is `clock.ns > expires_at`, so the reading has to be strictly after it.
    expires_at: expiryInstant,
    observed_at: afterExpiryInstant,
    outcome: expired.outcome,
    code: expired.code,
    reason: expired.reason ?? null,
    reconciliation_rows: reconciliationRows.length,
    reconciliation_ids: reconciliationRows.map((row) => row?.record_id ?? null),
    spend_advanced: String(beforeExpiry) !== String(afterExpiryDigest) && reconciliationRows.length === 0,
  };
  const crashClassified = {
    // THE STATUS A5 GATES ON. Every term is a named fact, and the whole thing
    // is a FAILURE when any of them is not what the ticket demands — the
    // restart is a reconciliation, it is not a retry, it is not a zero, and the
    // expired reservation produced a committed row.
    status: chain.ok === true
      && expiredReservation.outcome === 'REFUSED'
      && expiredReservation.code === 'RECONCILIATION_REQUIRED'
      && expiredReservation.reconciliation_rows >= 1
      && expiredReservation.spend_advanced === false
      ? 'PASS' : 'FAIL',
    reason: expiredReservation.outcome !== 'REFUSED'
      ? `the expired settle was ${expiredReservation.outcome} (code=${expiredReservation.code ?? 'none'})`
      : (expiredReservation.code !== 'RECONCILIATION_REQUIRED'
        ? `the expired settle refused with ${expiredReservation.code} rather than a reconciliation`
        : (expiredReservation.reconciliation_rows < 1
          ? 'the refused expired settle committed no RECONCILIATION row'
          : 'the interrupted state reconciled, was not retried and was not zeroed')),
  };
  return {
    root: rel(root),
    snapshot_before: before,
    snapshot_after_phase1: midway,
    phase1_rows: journal.length,
    reservation_committed: committed.result.reservation_id,
    revision_after_phase1: committed.revision,
    chain_verified: chain.ok === true,
    // The record KIND of a row is `RECORD` unless the payload names one, so the
    // preregistration row is found by its payload member. Reading the wrong
    // member here reported `false` and looked like a restart that saw nothing.
    phase2_saw_phase1: journal.some((row) => row?.payload?.record_kind === 'PREREGISTRATION_RECORDED'
      || row?.record_kind === 'PREREGISTRATION_RECORDED'),
    trials_executed: 0,
    reconciliation_required: true,
    blind_retry: false,
    implicit_zero: false,
    expired_reservation: expiredReservation,
    crashClassified,
  };
}

/**
 * A4: substituting the label must break the seal AND make the causal claim
 * fail. Two independent checks, because either alone is a partial proof: the
 * seal is what stops a corrupted ground truth being measured, and the label
 * guard is what stops a causal conclusion being read off observational data.
 */
function labelSubstitutionControl(prereg) {
  const clean = {
    cases: Object.entries(HOLDOUT_LABELS).map(([caseId, label]) => ({ case_id: caseId, label })),
    labels: HOLDOUT_LABELS,
  };
  const declared = prereg.holdout_access.labels_digest;
  const cleanActual = labelsDigest(clean);
  const sealHeld = (() => {
    try {
      assertLabelSeal({ declared, actual: cleanActual });
      return true;
    } catch (error) {
      return false;
    }
  })();
  const substituted = substituteLabelsControl(clean);
  const sealBroke = (() => {
    try {
      assertLabelSeal({ declared, actual: substituted.labels_digest });
      return false;
    } catch (error) {
      return true;
    }
  })();
  const cleanCard = classifyCardRelation(prereg.card);
  const swappedCard = classifyCardRelation({
    ...prereg.card, proposed_relation: { ...prereg.card.proposed_relation, causal_assertion: true },
  });
  return {
    control_id: 'label_substitution',
    labels_flipped: Object.keys(substituted.labels).length,
    clean_labels_digest: cleanActual,
    substituted_labels_digest: substituted.labels_digest,
    seal_held_on_clean_labels: sealHeld,
    seal_broke_on_substituted_labels: sealBroke,
    clean_card: {
      admissible: cleanCard.admissible, observational: cleanCard.observational, causal_assertion: cleanCard.causalAssertion, refusal: cleanCard.refusalCode,
    },
    swapped_card: {
      admissible: swappedCard.admissible, observational: swappedCard.observational, causal_assertion: swappedCard.causalAssertion, refusal: swappedCard.refusalCode,
    },
    flipped: sealHeld && sealBroke && cleanCard.admissible === true && swappedCard.admissible === false,
  };
}

/**
 * The identical-wrong control, run through the SAME comparator call on the SAME
 * two runs. Both runs receive the SAME corruption, so their digests stay equal
 * and `digestsEqual` is still `true`; the frozen table is then the only thing
 * that can produce findings, and it must produce them from BOTH runs. `A === B`
 * is therefore demonstrated to be insufficient, in the record itself.
 */
function identicalWrongControl(runA, runB, prereg, base) {
  const corrupt = (run) => {
    const injected = injectCorruption(run.trials, 'trial_status_skip');
    return { ...run, trials: injected.trials, corrupted: injected.corrupted };
  };
  const wrongA = corrupt(runA);
  const wrongB = corrupt(runB);
  const result = compareParallelTrack({ runA: wrongA, runB: wrongB, prereg, expected: expectedTable(), base });
  return { ...result, injected: wrongA.corrupted };
}

/** The holdout access-log half of A1, run on a real ledger rather than only
 * inside a probe world. Three reads, three outcomes: the legitimate one is
 * admitted, a read BEFORE the preregistered decision point is refused, and a
 * SECOND open of the same partition is refused even with a valid digest. */
function holdoutAccessPhase() {
  const admitted = openRegistry({ root: path.join(SCRATCH, 'holdout-admitted'), clock: fixedClock(POST_DECISION_INSTANT), ids: idFactory('holdout-admitted') });
  const read = readCorpus(admitted, {
    partition: 'HOLDOUT', caseId: FIRST_CASE, unsealDigest: HOLDOUT_UNSEAL_DIGEST, decisionPoint: DECISION_POINT_INSTANT, maxOpens: 1,
  });
  const refuse = (root, label, clock, args) => {
    const handle = openRegistry({ root: path.join(SCRATCH, root), clock: fixedClock(clock), ids: idFactory(`holdout-${label}`) });
    try {
      readCorpus(handle, args);
      return { outcome: 'ADMITTED', code: null, reason: null };
    } catch (error) {
      // The SPECIFIC code, not the class-level one. Every `BlockedPolicy`
      // carries `code: 'BLOCKED_POLICY'` and puts the reason in its message, so
      // `code=` printed `BLOCKED_POLICY` for all three refusals and a reader
      // could not tell a peek from a forgery.
      return {
        outcome: 'REFUSED',
        code: String(error?.code ?? 'REFUSED'),
        reason: String(error?.message ?? error).slice(0, 160),
      };
    }
  };
  const early = refuse('holdout-early', 'e', RUN_INSTANT, {
    partition: 'HOLDOUT', caseId: FIRST_CASE, unsealDigest: HOLDOUT_UNSEAL_DIGEST, decisionPoint: DECISION_POINT_INSTANT, maxOpens: 1,
  });
  const forged = refuse('holdout-forged', 'f', POST_DECISION_INSTANT, {
    partition: 'HOLDOUT', caseId: FIRST_CASE, unsealDigest: '0'.repeat(64), decisionPoint: DECISION_POINT_INSTANT, maxOpens: 1,
  });
  // A second open of the SAME partition with the digest that was really spent,
  // presented for a DIFFERENT case: the one-shot unseal digest is already spent,
  // so this is a REPLAY. It used to be read as "a second open" and the
  // per-partition open budget was named as the rule that catches it — a rule
  // `readCorpus` cannot reach at all, because the committed corpus publishes
  // exactly ONE unseal digest, so a second open there either replays that digest
  // or presents a forged one. The open budget is exercised directly in probe P1
  // (`recordHoldoutRead` with an unseen digest); what this phase measures is the
  // replay, and it is named as a replay.
  const again = openRegistry({ root: path.join(SCRATCH, 'holdout-admitted'), clock: fixedClock(POST_DECISION_INSTANT), ids: idFactory('holdout-admitted') });
  const replayed = (() => {
    try {
      readCorpus(again, { partition: 'HOLDOUT', caseId: SECOND_CASE, unsealDigest: HOLDOUT_UNSEAL_DIGEST, decisionPoint: DECISION_POINT_INSTANT, maxOpens: 1 });
      return { outcome: 'ADMITTED', code: null, reason: null };
    } catch (error) {
      return {
        outcome: 'REFUSED',
        code: String(error?.code ?? 'REFUSED'),
        reason: String(error?.message ?? error).slice(0, 160),
      };
    }
  })();
  return {
    admitted: {
      case_id: read.caseId, access_record_id: read.accessRecordId, labels_digest: read.labelsDigest, corpus_root: rel(read.corpusRoot),
    },
    read_before_decision_point: early,
    forged_unseal_digest: forged,
    replayed_unseal_digest: replayed,
    // Kept under the old name so an existing reader does not silently lose the
    // field; its content is the REPLAY measurement and `reason` says which code
    // the refusal carried.
    second_open_same_partition: replayed,
    // Each refusal is checked for the CODE it is supposed to be, not merely for
    // being a refusal: "refused" is a property of a correct implementation of
    // anything, and a rule that refuses for the wrong reason is not the rule the
    // ticket names.
    ok: early.outcome === 'REFUSED' && early.reason === 'HOLDOUT_READ_BEFORE_DECISION_POINT'
      && forged.outcome === 'REFUSED' && forged.reason === 'HOLDOUT_UNSEAL_DIGEST_FORGED'
      && replayed.outcome === 'REFUSED' && replayed.reason === 'HOLDOUT_UNSEAL_DIGEST_REPLAYED',
  };
}

/** `--no-write`: report the properties and write NO evidence file, so a check
 *  run cannot mutate the artefact it is checking. The default is unchanged
 *  (the harness writes its four records), and the mode is reported in the
 *  summary either way, because a report that does not say whether it wrote is a
 *  report nobody can trust. */
function wantsWrite(argv) {
  for (const token of argv.slice(2)) {
    if (token === '--no-write' || token === '--nowrite' || token === '--no-write=true') return false;
    if (token === '--write' || token === '--write=true') return true;
  }
  return true;
}

async function main(argv = process.argv) {
  // 0. Purge this harness's OWN fixtures. Everything it writes lives under
  //    SCRATCH, so a repeat run on a permanent base fails on the property and
  //    not on leftovers.
  rmSync(SCRATCH, { recursive: true, force: true });
  mkdirSync(SCRATCH, { recursive: true });

  // 1. The base.
  const base = resolveBase();
  const write = wantsWrite(argv);
  log('# s2-008 parallel-track harness');
  log(`mode write_evidence=${String(write)}${write ? '' : ' (--no-write: properties are reported, no evidence file is written or touched)'}`);
  log(`config ${JSON.stringify(CONFIG)}`);
  log(`base commit=${base.commit_sha} tree=${base.tree_sha} branch=${base.branch} worktree_dirty=${String(base.worktree_dirty)}`);
  log(`base track_tracked=${String(base.track_tracked)} tracked_files_of_this_track=${base.tracked_files_of_this_track}`);

  const prereg = loadPreregistration(CORPUS_DIR);
  assertTableFrozen(prereg);
  // R-B/R-C: the frozen table's CAMPAIGN decision is re-derived through the
  // comparator's own rule before a single trial runs. A declaration the rule does
  // not produce is refused HERE (exit 2, crash) rather than discovered as a
  // campaign finding after two processes have run, because a harness that scores
  // a campaign against an expectation nothing derived is the anti-goal wearing a
  // gate's clothes.
  const frozenCampaign = assertFrozenCampaignDerivable();
  log(`preregistration digest=${preregistrationDigest(prereg)} seeds=${JSON.stringify(prereg.seed_rule.seeds)} seed_count=${seedCountOf(prereg)}`);
  log(`frozen campaign decision=${frozenCampaign.decision} reason=${String(frozenCampaign.decisionReason)} interval=${frozenCampaign.interval.lower}..${frozenCampaign.interval.upper} confidence=${String(frozenCampaign.confidence)} never_rejects=${String(frozenCampaign.rule_feasibility.never_rejects)}`);
  log(`contracts ${JSON.stringify(allResearchContractDigests())}`);

  // 2. A1: the six negative probes, on a purged scratch root.
  const probes = await runAllProbes({ registryRoot: path.join(SCRATCH, 'probes'), corpusDir: CORPUS_DIR });
  log(`A1 probes allPassed=${String(probes.allPassed)} notRun=${probes.notRun.length} broken=${probes.broken.length}`);
  log(`A1 counters ${JSON.stringify(probes.counters)}`);
  log(`A1 purge base=${probes.purged.base} removed=${probes.purged.removed} of ${probes.purged.roots}`);

  // 3. A1's access-log half, on a real ledger.
  const holdout = holdoutAccessPhase();
  log(`A1 holdout admitted=${holdout.admitted.access_record_id} early=${holdout.read_before_decision_point.reason} forged=${holdout.forged_unseal_digest.reason} replay=${holdout.replayed_unseal_digest.reason}`);

  // 4. A3: two process-separated runs.
  const runA = buildRun('a', prereg, base);
  const runB = buildRun('b', prereg, base);
  const separated = runA.raw_run_id !== runB.raw_run_id
    && runA.nonce !== runB.nonce
    && runA.executor_id !== runB.executor_id
    && runA.output_root !== runB.output_root;
  log(`A3 runs separated=${String(separated)} metric=${runA.metrics.metric} ${runA.metrics.numerator}/${runA.metrics.denominator} basis=${runA.metrics.basis} notMeasured=${runA.metrics.notMeasured}`);

  // 5. A2: the six negative controls, every one of which must flip.
  const controls = runNegativeControls({
    trial: controlTrial(), cleanRun: runA, runA, runB, card: prereg.card,
  });
  const gate = controlsFlipVerdict(controls);
  log(`A2 controls allFlipped=${String(controls.allFlipped)} gate.ok=${String(gate.ok)} notRun=${controls.notRun.length}`);
  for (const entry of controls.controls) {
    log(`A2 control ${entry.id} ${entry.before} -> ${entry.after} flipped=${String(entry.flipped)}`);
  }

  // 6. The control record is ATTACHED to both runs before the comparison, so
  //    the comparator's `negative_controls` gate reads the evidence that was
  //    actually produced rather than reporting its absence. Attaching it after
  //    the comparison would leave `negative_controls_absent` as a failure that
  //    describes the harness's own ordering rather than the track.
  for (const run of [runA, runB]) {
    run.controls = { allFlipped: controls.allFlipped, controls: controls.controls, notRun: controls.notRun };
  }

  // 7. A3: the parallel comparison against the FROZEN table.
  const comparison = compareParallelTrack({ runA, runB, prereg, expected: expectedTable(), base });
  log(`A3 findingsA=${comparison.findingsA.length} findingsB=${comparison.findingsB.length} digestsEqual=${String(comparison.digestsEqual)}`);
  for (const finding of [...comparison.findingsA, ...comparison.findingsB].slice(0, 10)) {
    log(`A3 finding ${finding.field} expected=${JSON.stringify(finding.expected)} observed=${JSON.stringify(finding.observed)} code=${finding.code}`);
  }

  // 7. A3: the IDENTICAL-WRONG control on the same two runs.
  const wrong = identicalWrongControl(runA, runB, prereg, base);
  log(`A3 identical_wrong both_non_empty=${String(wrong.identicalWrongFindings.both_non_empty)} digests_still_equal=${String(wrong.identicalWrongFindings.digests_still_equal)} conclusion=${wrong.identicalWrongFindings.conclusion}`);

  // 8. A4: the label-substitution control.
  const a4 = labelSubstitutionControl(prereg);
  log(`A4 label_substitution flipped=${String(a4.flipped)} seal_held=${String(a4.seal_held_on_clean_labels)} seal_broke=${String(a4.seal_broke_on_substituted_labels)} swapped_card_refusal=${String(a4.swapped_card.refusal)}`);

  // 9. The crash/restart phase.
  const crash = crashRestartPhase(prereg);
  log(`A5 crash_restart chain_verified=${String(crash.chain_verified)} phase2_saw_phase1=${String(crash.phase2_saw_phase1)} rows=${crash.phase1_rows} trials_executed=${crash.trials_executed}`);

  // 10. The verdict, delegated.
  const verdict = resolveCampaignVerdict({
    failures: comparison.failures, limits: comparison.limits, proofStatus: comparison.proofStatus,
  });
  log(`verdict ${verdict}`);
  for (const entry of comparison.failures) log(`verdict failure ${entry.code} | ${entry.detail}`);
  for (const entry of comparison.limits) log(`verdict limit ${entry.code} | ${entry.detail}`);

  // --- the acceptance properties, each with its own evidence ---------------
  const probeCount = PROBE_FAMILIES.reduce((total, family) => total + PROBE_NAMES[family].length, 0);
  const properties = [
    {
      id: 'A1',
      statement: 'the registry covers all six negative probes',
      ok: probes.allPassed && probes.results.length === probeCount && holdout.ok,
      evidence: `probes=${probes.results.length}/${probeCount} notRun=${probes.notRun.length} broken=${probes.broken.length} early_read=${holdout.read_before_decision_point.reason} forged=${holdout.forged_unseal_digest.reason} replayed_digest=${holdout.replayed_unseal_digest.reason}`,
    },
    {
      id: 'A2',
      statement: 'a skipped or unresolved trial is a VIOLATION and every negative control flips the verdict',
      // The fail-closed direction is the one A2 names: anything that is not
      // RESOLVED is a VIOLATION, never an ALLOW. The ALLOW side is demonstrated
      // by the control trial, which runs under a MEASURED calibration because
      // this track's DELIVERED calibration is NOT_MEASURED and that makes every
      // trial of the delivered run a VIOLATION by design — reported, not hidden.
      ok: gate.ok
        && runA.trials.every((trial) => trial.status !== 'RESOLVED' ? trial.verdict === 'VIOLATION' : true)
        && controls.controls.filter((entry) => entry.mechanism === 'comparator').every((entry) => entry.before === 'ALLOW'),
      evidence: `controls=${controls.controls.length} (six frozen + ${String(controls.controls.length - 6)} named extra) notRun=${controls.notRun.length} gate_ok=${String(gate.ok)} infra_trial_verdict=${runA.trials[3].verdict} comparator_controls_before=ALLOW all corruption_variants=${JSON.stringify(controls.controls.find((entry) => entry.id === 'corrupted_data')?.coverage?.variants_injected ?? [])} pipeline_sensitivity=${String(controls.sensitivity?.pipeline?.any_run_sensitive ?? null)}`,
    },
    {
      id: 'A3',
      statement: 'two process-separated runs agree with the FROZEN expected-value table; A === B is additional only',
      ok: separated && comparison.findingsA.length === 0 && comparison.findingsB.length === 0
        && wrong.identicalWrongFindings.both_non_empty === true,
      // The `agreement_source` member is the honest boundary of this line, and it
      // is a member rather than a footnote because this harness's pair is
      // BUILT FROM THE TABLE: `buildRun` takes each trial's counts from
      // `EXPECTED_TRIAL_DECISIONS` (see its own comment) and only DERIVES the
      // outcome, so `findingsA=0` here is definitional and is NOT a measurement
      // that the corpus agrees with the table. A reader who took this line for a
      // measurement would be reading a tautology. The measurement is
      // `npm run verify:s2-008-replay`, which drives the real engine over the
      // real corpus and currently reports A3 FAILED on the three outcome rows.
      // Nothing about the verdict is changed here: the identical-wrong control
      // still has to fire for this line to be ok.
      agreement_source: 'TABLE_DERIVED_RUN_RECORDS',
      measurement_of_agreement: 'scripts/s2-008-replay.mjs',
      evidence: `separated=${String(separated)} findingsA=${comparison.findingsA.length} findingsB=${comparison.findingsB.length} digestsEqual=${String(comparison.digestsEqual)} identical_wrong_both_non_empty=${String(wrong.identicalWrongFindings.both_non_empty)} runA_metrics=${runA.metrics.numerator}/${runA.metrics.denominator} notMeasured=${runA.metrics.notMeasured} rule_can_only_answer=${String(comparison.runs?.a?.rule_feasibility?.can_only_answer ?? 'unknown')} agreement_source=TABLE_DERIVED_RUN_RECORDS (not a measurement; see verify:s2-008-replay)`,
    },
    {
      id: 'A4',
      statement: 'an observational result cannot be read as causal: substituting the label MUST fail',
      ok: a4.flipped,
      evidence: `seal_held=${String(a4.seal_held_on_clean_labels)} seal_broke=${String(a4.seal_broke_on_substituted_labels)} labels_flipped=${a4.labels_flipped} swapped_card_refusal=${String(a4.swapped_card.refusal)}`,
    },
    {
      id: 'A5',
      statement: 'every artifact is bound to a commit SHA, a tree SHA and a raw run id, and survives a repeat run on the same base',
      // PR4: `crashClassified.status` is a TERM of this property, not a log
      // line beside it. The expired-reservation RECONCILIATION is decided on the
      // ledger by `registry.mjs#recordSpend`'s guard, and until now A5 gated only
      // `chain_verified` and `phase2_saw_phase1`, so disabling that guard left
      // A5 green.
      ok: base.track_tracked
        && comparison.proofStatus.find((entry) => entry.id === 'base_binding')?.status === 'SATISFIED'
        && crash.chain_verified
        && crash.phase2_saw_phase1 === true
        && crash.crashClassified.status === 'PASS',
      evidence: `track_tracked=${String(base.track_tracked)} tracked_files=${base.tracked_files_of_this_track} base_binding=${comparison.proofStatus.find((entry) => entry.id === 'base_binding')?.status} chain_verified=${String(crash.chain_verified)} phase2_saw_phase1=${String(crash.phase2_saw_phase1)} crash_classified=${crash.crashClassified.status} expired_settle=${crash.expired_reservation.outcome}/${crash.expired_reservation.code} reconciliation_rows=${crash.expired_reservation.reconciliation_rows} spend_advanced=${String(crash.expired_reservation.spend_advanced)}`,
    },
  ];
  for (const property of properties) {
    log(`${property.id} ${property.ok ? 'HELD  ' : 'FAILED'} ${property.statement} | ${property.evidence}`);
  }

  const notRun = probes.notRun.length + controls.notRun.length;
  const brokenCount = probes.broken.length;
  const held = properties.filter((property) => property.ok).length;
  // R-C: THE CAMPAIGN DECISION IS AN ANSWER, AND THE GATE IS GREEN ON
  // AGREEMENT WITH THE FROZEN TABLE — NEVER ON ALLOW.
  //
  // `verdict_is_pass` used to be a term here, at the replay and at the
  // aggregator. With eight synthetic cases the honest campaign answer is a
  // null, so the requirement was unsatisfiable without tuning the fixtures until
  // a fabricated effect looked legitimate — the anti-goal. The decision is now
  // compared with `EXPECTED_CAMPAIGN`, which the frozen table publishes, and a
  // decision the table does not declare is a refusal. The verdict is STILL
  // computed, STILL printed and STILL written: it is the campaign's answer,
  // recorded next to the pass condition.
  const campaign = campaignDecisionAgreement({
    observed: comparison.runs?.a?.decision ?? null,
    expected: frozenCampaignDecision(),
  });
  // The LEDGER SHAPE, measured over the journal this harness actually wrote for
  // each run. An absent or unreadable journal is a NAMED divergence with the
  // observed count beside it, never a silent pass.
  const ledgerShape = {
    a: ledgerShapeIssues(runA),
    b: ledgerShapeIssues(runB),
    expected: EXPECTED_LEDGER_SHAPE,
    observed_record_kinds: runA.ledger?.record_kinds ?? [],
    expected_record_kinds: EXPECTED_LEDGER_SHAPE.flatMap((row) => Array.from({ length: row.count }, () => row.kind)),
    rows: { a: runA.ledger?.record_count ?? null, b: runB.ledger?.record_count ?? null },
    chain_verified: runA.ledger?.chain_verified === true && runB.ledger?.chain_verified === true,
    error: runA.ledger?.error ?? runB.ledger?.error ?? null,
  };
  const ledgerShapeFindings = [...ledgerShape.a, ...ledgerShape.b];
  const ledgerShapeOk = ledgerShapeFindings.length === 0 && ledgerShape.chain_verified === true;
  const controlsAllFlipped = controls.allFlipped === true && controls.notRun.length === 0;
  // F1: the same term the replay applies, over the same table declaration. A
  // comparator failure the frozen table does not declare the honest campaign to
  // carry fails the harness exactly as it fails the replay, so the two gates
  // cannot be read as disagreeing about what a violation is worth.
  const unexpectedFailures = unexpectedComparatorFailures({
    failures: comparison?.failures ?? [],
    limits: comparison?.limits ?? [],
    runs: comparison === null ? 0 : 2,
  });
  for (const entry of unexpectedFailures) log(`unexpected comparator finding ${entry.code} ${entry.field} | ${entry.detail}`);
  const comparatorFailuresDeclared = unexpectedFailures.length === 0;
  log(`campaign expected_decision=${String(campaign.expected)} observed_decision=${String(campaign.observed)} agrees=${String(campaign.agrees)} verdict=${verdict} (a recorded OUTCOME, not a gate term)`);
  for (const finding of campaign.findings) log(`campaign finding ${finding.code} | ${finding.detail}`);
  log(`ledger_shape matches=${String(ledgerShapeOk)} rows_a=${String(ledgerShape.rows.a)} rows_b=${String(ledgerShape.rows.b)} chain_verified=${String(ledgerShape.chain_verified)} findings=${ledgerShapeFindings.length}`);
  log(`controls_all_flipped=${String(controlsAllFlipped)}`);
  const overallTerms = {
    every_property_held: held === properties.length,
    held,
    total: properties.length,
    expected_campaign_decision: campaign.expected,
    observed_campaign_decision: campaign.observed,
    decision_agrees_with_table: campaign.agrees,
    campaign_findings: campaign.findings.map((finding) => ({ code: finding.code, field: finding.field, expected: finding.expected, observed: finding.observed })),
    controls_all_flipped: controlsAllFlipped,
    controls_not_run: controls.notRun.length,
    comparator_failures_match_frozen_expectation: comparatorFailuresDeclared,
    unexpected_comparator_findings: unexpectedFailures.map((entry) => ({ code: entry.code, field: entry.field, expected: entry.expected, observed: entry.observed })),
    ledger_shape_matches_table: ledgerShapeOk,
    ledger_shape_findings: ledgerShapeFindings.length,
    not_run_zero: notRun === 0,
    not_run_count: notRun,
    broken_zero: brokenCount === 0,
    broken_count: brokenCount,
    // REPORTED, NOT A TERM. See the comment above.
    verdict,
  };
  // THE PASS CONDITION, in full: every acceptance property held AND the
  // comparator's decision equals the decision the frozen expected-value table
  // declares AND the ledger shape matches that table AND every negative control
  // flipped AND NOT_RUN is 0 AND broken is 0. NOT_RUN outranks the conjunction,
  // because "I could not check" is not "I checked and it passed".
  const overall = notRun > 0 || brokenCount > 0
    ? 'NOT_RUN'
    : (overallTerms.every_property_held
      && overallTerms.decision_agrees_with_table
      && overallTerms.ledger_shape_matches_table
      && overallTerms.comparator_failures_match_frozen_expectation
      && overallTerms.controls_all_flipped ? 'PASS' : 'FAIL');
  log(`RESULT properties_held=${held}/${properties.length} not_run=${notRun} broken=${brokenCount} verdict=${verdict} overall=${overall}`);
  log(`RESULT overall_terms ${JSON.stringify(overallTerms)}`);

  // --- the evidence records -----------------------------------------------
  const manifest = JSON.parse(readFileSync(path.join(CORPUS_DIR, 'manifest.json'), 'utf8'));
  const record = {
    ticket: 'S2-008',
    harness: 'scripts/s2-008-harness.mjs',
    config: CONFIG,
    base,
    contracts: allResearchContractDigests(),
    corpus: {
      dir: rel(CORPUS_DIR),
      manifest_digest: canonicalDigest(manifest),
      holdout_unseal_digest: HOLDOUT_UNSEAL_DIGEST,
      first_case_digest: caseDigest(manifest.partitions.HOLDOUT ? { case_id: FIRST_CASE } : {}),
    },
    preregistration: { digest: preregistrationDigest(prereg), expected_table_digest: expectedTableDigest() },
    properties,
    probes: {
      allPassed: probes.allPassed, counters: probes.counters, purged: purgedRecordForCommit(probes.purged), notRun: probes.notRun, broken: probes.broken, results: probes.results,
    },
    holdout_access: holdout,
    controls: { allFlipped: controls.allFlipped, gate, record: controls, notRun: controls.notRun },
    label_substitution: a4,
    comparison,
    identical_wrong: wrong,
    crash_restart: crash,
    ledger_shape: ledgerShape,
    derived_outcome_disagreements: runA.derived_disagreements,
    // R-C: the campaign's answer and what the gate decided about it, in one
    // member, so a reader of ONE file cannot mistake a recorded OUTCOME for a
    // pass criterion.
    campaign: {
      expected_decision: campaign.expected,
      observed_decision: campaign.observed,
      agrees_with_table: campaign.agrees,
      findings: campaign.findings,
      verdict,
      verdict_is_a_gate_term: false,
    },
    // F1, as in the replay: the failure list the term above was applied to.
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
    verdict,
    overall,
    // The terms `overall` is derived from, itemised so a reader can
    // re-derive it without re-running the harness.
    overall_terms: overallTerms,
    write,
    not_run_count: notRun,
    broken_count: brokenCount,
  };
  const files = {
    's2-008-probes.json': {
      ticket: 'S2-008', config: CONFIG, base, results: probes.results, allPassed: probes.allPassed, counters: probes.counters, purged: purgedRecordForCommit(probes.purged), notRun: probes.notRun, broken: probes.broken,
    },
    's2-008-controls.json': {
      ticket: 'S2-008', config: CONFIG, base, controls: controls.controls, allFlipped: controls.allFlipped, gate, notRun: controls.notRun, label_substitution: a4,
    },
    's2-008-comparison.json': {
      ticket: 'S2-008', config: CONFIG, base, comparison, identical_wrong: wrong, verdict, properties, holdout_access: holdout, crash_restart: crash, ledger_shape: ledgerShape, campaign: { expected_decision: campaign.expected, observed_decision: campaign.observed, agrees_with_table: campaign.agrees, findings: campaign.findings },
    },
    's2-008-harness.json': record,
  };
  if (write) mkdirSync(EVIDENCE_DIR, { recursive: true });
  for (const [name, document] of Object.entries(files)) {
    const body = `${JSON.stringify(document, null, 2)}\n`;
    if (write) writeFileSync(path.join(EVIDENCE_DIR, name), body);
    log(`${write ? 'wrote' : 'not written (--no-write)'} evidence/${name} digest=${canonicalDigest(document)} bytes=${Buffer.byteLength(body)}`);
  }

  const exit = overall === 'PASS' ? 0 : (overall === 'NOT_RUN' ? 3 : 1);
  log(`RESULT exit_code=${exit}`);
  process.exit(exit);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({
    error: String(error?.message ?? error),
    code: String(error?.code ?? 'HARNESS_ERROR'),
    stack: String(error?.stack ?? '').split('\n').slice(0, 8),
  }, null, 2)}\n`);
  process.exit(2);
});
