// S2-008 REAL CAMPAIGN — the run. Drives the real adapter through the REUSED
// engine, and decides by the rule that was frozen before the adapter existed.
//
// WHAT IS REUSED AND NOT REWRITTEN
//   The registry (append-only, chained, idempotent, budget reservation,
//   fencing), the preregistration assertions, `readCorpus`'s one-shot sealed
//   open, `classifyTrialObservation`'s four-outcome precedence,
//   `resolveTrialVerdict`'s fail-closed bindings, `decisionFromInterval`'s
//   multiplicity correction and the provenance/binding helpers. `src/lib
//   /research/**` and `scripts/s2-008-*.mjs` are untouched; this file is the
//   campaign, not the machinery.
//
// THE ORDER, WHICH IS THE WHOLE POINT
//   1. purge the registry, so a repeat run fails on the property and not on its
//      own leftovers;
//   2. commit the PREREGISTRATION row and take the budget reservation;
//   3. prove the ordering from the JOURNAL, not from a clock;
//   4. Phase A — every (arm, seed) executed by the real installed executor,
//      BLIND: three arms x three seeds = nine real container launches, none of
//      which has ever seen a label;
//   5. Phase B — the decision point, and the holdout opened EXACTLY ONCE;
//   6. Phase C — agreement, the per-seed bootstrap, the HULLED interval, the
//      engine's classification, the per-trial verdict, the decision.
//   A label is revealed after every predictor has answered and before any
//   decision is read. That ordering is the experiment.
//
//   `--child` re-runs the whole thing in a fresh process against a fresh
//   registry, which is what makes the reproducibility claim a measurement.
//
// USAGE
//   node scripts/s2-008-campaign-run.mjs --label a --out evidence/<file>.json
//   node scripts/s2-008-campaign-run.mjs --label b --out evidence/<file>.json

import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import {
  openRegistry, appendRecord, recordSpend, readJournal, verifyChain,
  headDigest, snapshotDigest, putExperiment,
} from '../src/lib/research/registry.mjs';
import {
  assertPreregisteredBeforeRun, assertPreregistration, preregistrationDigest,
  assertBudgetReservation,
} from '../src/lib/research/preregistration.mjs';
import { readCorpus } from '../src/lib/research/dataset.mjs';
import {
  classifyTrialObservation, deriveProcessNonce, freezeProvenance, bindArtefact,
  writeArtefact, assertArtefactBound, verdictProjection, assertNoWallClockInVerdict,
  decisionDigest, reconciliationRow,
} from '../src/lib/research/runner.mjs';
import {
  resolveTrialVerdict, metricsSummary, latencyRecorded, bestSeedDisclosure,
  decisionFromInterval, resolveCampaignVerdict, ruleFeasibility,
} from '../src/lib/research/comparator.mjs';
import {
  TRIAL_STATUSES, RESEARCH_OUTCOMES, TRIAL_VERDICTS, RESEARCH_PARTITIONS,
} from '../src/lib/research/constants.mjs';
import { wilsonInterval } from '../src/lib/sloqual/statistics.mjs';
import { buildImage, runTrial, runModelTrial, buildBootstrapImage, runBootstrap, verifyImagePin } from './s2-008-campaign-adapter.mjs';
import { assertV6ModelTimeoutPolicy } from './s2-008-campaign-v6-timeout.mjs';
import { assertV8ExecutorPolicy, assertV7ExecutorPolicy } from './s2-008-campaign-credential-env.mjs';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CORPUS_DIR = path.join(REPO_ROOT, 'corpus/s2-008-campaign');
const DECISION_POINT = '2026-09-28T00:00:00.000Z';
const HOLDOUT_ACTOR_KIND = 'EVALUATOR';

/** The clock is INJECTED and FIXED. No wall clock reaches a decision, and a
 *  repeat run on the same base produces the same instants. */
function fixedClock(iso) {
  const ms = Date.parse(iso);
  return Object.freeze({
    nowNs: () => ms * 1e6, nowMs: () => ms, iso: () => iso,
    now: () => new Date(ms), nowIso: () => iso,
  });
}

/** The engine's dependency groups, resolved EXPLICITLY from the track's own
 *  modules. `resolveDeps` merges over `DEFAULT_DEPS`, and the point of the
 *  injection is that the engine uses the TRACK's functions and the TRACK's
 *  closed vocabulary rather than a private copy of either. */
function engineDeps() {
  return {
    constants: {
      TRIAL_STATUSES, RESEARCH_OUTCOMES, TRIAL_VERDICTS, RESEARCH_PARTITIONS,
    },
    comparator: {
      resolveTrialVerdict, metricsSummary, latencyRecorded, bestSeedDisclosure,
      decisionFromInterval, resolveCampaignVerdict,
    },
  };
}

/**
 * The bootstrap interval, EXACT, from the resample bitmasks the real adapter
 * produced.
 *
 * Each resample is a `ceil(n/8)`-byte bitmask saying which of the n cases it
 * drew. The resample's agreement rate is the agreement over the DRAWN cases,
 * divided by n — so every one of the `samples` rates is computable exactly, and
 * the interval is the percentile bootstrap interval over them. No Poisson-
 * binomial approximation, and nothing derived from the lossy per-case counts:
 * two different resample multisets can share the same counts and disagree on
 * every resample's agreement sum, so an interval computed from the counts
 * describes a distribution the adapter never drew.
 */
export function bootstrapIntervalFromMasks(masksBase64, stride, agreement, { confidence }) {
  const matrix = Buffer.from(masksBase64, 'base64');
  const n = agreement.length;
  const samples = Math.floor(matrix.length / stride);
  if (samples < 1) throw new Error(`RESAMPLE_MATRIX_EMPTY: ${String(samples)} resample(s) in ${String(matrix.length)} bytes`);
  if (samples * stride !== matrix.length) {
    throw new Error(`RESAMPLE_MATRIX_RAGGED: ${String(matrix.length)} bytes is not a whole number of ${String(stride)}-byte masks`);
  }
  const rates = new Array(samples);
  for (let draw = 0; draw < samples; draw += 1) {
    const offset = draw * stride;
    let sum = 0;
    for (let index = 0; index < n; index += 1) {
      if ((matrix[offset + (index >> 3)] & (1 << (index & 7))) !== 0) sum += agreement[index];
    }
    rates[draw] = sum / n;
  }
  const sorted = [...rates].sort((left, right) => left - right);
  const tail = (1 - confidence) / 2;
  // The empirical quantile, nearest-rank: it does not interpolate a rate the
  // run never produced.
  const quantile = (q) => {
    const position = Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1));
    return sorted[position];
  };
  return {
    lower: quantile(tail),
    upper: quantile(1 - tail),
    confidence,
    method: 'PERCENTILE_BOOTSTRAP_OVER_EXACT_RESAMPLE_BITMASKS',
    n,
    samples,
    resample_mean: rates.reduce((sum, value) => sum + value, 0) / rates.length,
    resample_min: sorted[0],
    resample_max: sorted[sorted.length - 1],
  };
}

function git(...parts) {
  return execFileSync('git', parts, { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
}

function resolveBase() {
  const tracked = git('ls-files', '-z').split('\0').filter(Boolean);
  const mine = tracked.filter((file) => /^(src\/lib\/research\/|src\/lib\/isolation\/|tests\/research\/|scripts\/s2-008-|scripts\/verify-s2-008|corpus\/s2-008-campaign\/|evidence\/s2-008)/.test(file));
  return {
    commit_sha: git('rev-parse', 'HEAD'),
    tree_sha: git('rev-parse', 'HEAD^{tree}'),
    branch: git('rev-parse', '--abbrev-ref', 'HEAD'),
    worktree_dirty: git('status', '--porcelain').length > 0,
    tracked_files_of_this_track: mine.length,
    track_tracked: mine.length > 0,
  };
}

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

/** `readJournal` returns ENVELOPES: `kind` is lifted to the top, but
 *  `preregistration_digest` and `run_id` stay in the payload. The ordering proof
 *  reads both at the row's TOP level, so the rows are projected — the same
 *  projection `src/lib/research/runner.mjs` does internally, and it adds
 *  nothing: every value is a member of the envelope or of its payload, so a row
 *  can never claim a digest the ledger does not hold. */
function projectJournalRows(rows) {
  return rows.map((row, position) => {
    const payload = row?.payload !== null && typeof row?.payload === 'object' && !Array.isArray(row.payload) ? row.payload : {};
    return {
      index: Number.isInteger(row.index) ? row.index : position,
      kind: row.kind,
      record_kind: typeof payload.record_kind === 'string' ? payload.record_kind : row.kind,
      preregistration_digest: payload.preregistration_digest ?? payload.prereg_digest ?? null,
      run_id: payload.run_id ?? payload.raw_run_id ?? null,
    };
  });
}

/** What this runner can OBSERVE happening, and therefore charge. A launch is a
 *  process; a token is a number the executor reports about that process. This
 *  runner can only see the first, and a reservation in any other currency stops
 *  the campaign before the first container rather than being charged in a unit
 *  that would make the ceiling look untouched. */
export const MEASURABLE = 'isolated_executor_launches';

/** Arms the adapter can actually run as the MODEL program. Empty until it can: the
  * refusal is the honest state, and filling this list is the work that enables
  * spending. A token charge is never taken on trust. */
export const DISPATCHABLE_MODEL_ARMS = Object.freeze(['arm-model-zai-glm53flash']);

/**
 * What each currency is actually MEASURED by, named so no reader has to infer it.
 * A launch is a process this runner can see starting. A token is a number the
 * executor reports about that process — the runner can only carry it, never
 * produce it, so a token charge is always a charge OF SOMETHING ELSE'S REPORT.
 */
export const MEASURED_BY = Object.freeze({
  isolated_executor_launches: 'LAUNCH_COUNT',
  tokens: 'EXECUTOR_REPORTED_TOKENS',
});

/**
 * ONE step of the launch loop, as a decision: charge, or stop, or refuse.
 *
 * The loop that spends money is the loop that was mis-wired once already, so the
 * arithmetic is extracted rather than left inline. A `spentUnits += 1` left in the
 * body of a token-denominated loop is exactly the bypass this work removes, and
 * inline it was invisible to the suite: reaching it needs a live corpus and a
 * container. Here both branches are readable.
 */
export function chargingStep({ currency, spentUnits, grantedUnits, armOutput = null, armId = null, dispatchableArms = [] }) {
  const plan = chargeFor({ currency, armOutput, armId, dispatchableArms });
  if (plan.refusal) return { action: 'refuse', code: 'CHARGE_NOT_MEASURABLE', detail: plan.refusal, spent_units: Number(spentUnits) ?? 0 };
  const spent = (Number(spentUnits) || 0) + plan.units;
  return {
    action: 'charge',
    units: plan.units,
    unit: plan.unit,
    source: plan.source,
    spent_units: spent,
    // The stop is decided from the post-charge number, so a charge that exactly
    // exhausts the ceiling ends the run rather than starting the next launch.
    stop: ceilingReached(spent, grantedUnits),
    granted_units: Number(grantedUnits),
  };
}

/** Local, because this file had none: `chargeFor` has to tell a reported budget
 *  object from a string that happens to have a `currency` member. Caught by the
 *  suite as a ReferenceError, which is the cheapest kind of bug to find. */
function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Whether the reservation is spent. Pure, because the stop must be observable:
 * the arm stops itself between CASES, and the run must not start the next LAUNCH
 * once the money is gone. `>=` and not `>`, so a charge that exactly exhausts the
 * ceiling stops rather than continuing to the next unit.
 */
export function ceilingReached(spent, granted) {
  const a = Number(spent);
  const b = Number(granted);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b <= 0) return false;
  return a >= b;
}

/**
 * The charge for one launch, in the reservation's own currency — or a refusal.
 *
 * The rule that matters: a currency may only be charged in units this runner can
 * name, and a token charge must be a number the ARM reported, taken from a named
 * field. Nothing here estimates, converts, or rounds. A run that cannot produce a
 * defensible number does not charge an invented one.
 *
 * Pure, so both branches are readable: an inline version was unreachable from a
 * test because the only path to it satisfied an earlier guard first.
 */
export function chargeFor({ currency, armOutput = null, armId = null, dispatchableArms = [] }) {
  const unit = MEASURED_BY[currency] ?? null;
  if (unit === null) {
    return { refusal: `RESERVATION_CURRENCY_NOT_MEASURABLE:${String(currency ?? '(none)')}` };
  }
  if (unit === 'LAUNCH_COUNT') {
    return { units: 1, unit, currency, source: 'a container launch this runner observed' };
  }
  // Regex controls make no model calls. Their token charge is exactly zero,
  // independently of how many containers were launched.
  if (armId === 'arm-type-feat-fix' || armId === 'arm-type-chore') {
    return { units: 0, unit, currency, source: 'regex control: no model call' };
  }
  // A token charge is the arm's own report, and only for an arm this runner can
  // actually dispatch to the model program — charging a program it never ran
  // would be counting someone else's number.
  if (!dispatchableArms.includes(armId)) {
    return { refusal: `TOKEN_ARMED_NOT_DISPATCHABLE:${String(armId)}` };
  }
  const reported = armOutput?.budget;
  if (!isPlainObject(reported) || String(reported.currency ?? '') !== currency) {
    return { refusal: `ARM_BUDGET_NOT_IN_THIS_CURRENCY:${String(armId)}:${String(reported?.currency ?? 'none')}` };
  }
  if (reported.unreconciled_spend === true) {
    return { refusal: `ARM_UNRECONCILED_SPEND:${String(armId)}` };
  }
  const spent = reported.spent_tokens;
  if (!Number.isInteger(spent) || spent < 0) {
    return { refusal: `ARM_REPORTED_NO_TOKENS:${String(armId)}:${String(spent ?? 'absent')}` };
  }
  return {
    units: spent,
    unit,
    currency,
    source: `the executor's own ${reported.measured_by ?? 'usage.totalTokens'}, as carried in the arm record's budget.spent_tokens`,
  };
}

/** A pre-launch check cannot ask an arm for output it has not produced yet. */
export function preflightCharge({ currency, armId, dispatchableArms = DISPATCHABLE_MODEL_ARMS } = {}) {
  if (currency === 'tokens') {
    if (armId === 'arm-type-feat-fix' || armId === 'arm-type-chore') {
      return { units: 0, unit: 'EXECUTOR_REPORTED_TOKENS', source: 'regex control: no model call' };
    }
    if (dispatchableArms.includes(armId)) {
      return { pending_report: true, unit: 'EXECUTOR_REPORTED_TOKENS' };
    }
    return { refusal: `TOKEN_ARMED_NOT_DISPATCHABLE:${String(armId)}` };
  }
  if (currency === MEASURABLE) return { units: 1, unit: 'LAUNCH_COUNT' };
  return { refusal: `RESERVATION_CURRENCY_NOT_MEASURABLE:${String(currency ?? '(none)')}` };
}

/**
 * The currency decision, as a pure function so a test can reach BOTH branches.
 * Returning null means "carry on"; anything else is the refusal the caller
 * records, prints and exits on. It was inline before, and the only way to observe
 * a refusal was to satisfy an earlier guard — so a mutation of the exit code, or
 * of the entry point's handling of the refusal, was invisible to the suite.
 */
export function currencyRefusal(reservationCurrency, { grantedUnits = null } = {}) {
  if (reservationCurrency === MEASURABLE) return null;
  return Object.freeze({
    status: 'BLOCKED',
    code: 'BUDGET_UNMEASURABLE',
    exitCode: 4,
    launches: 0,
    charged_units: 0,
    spent_units: 0,
    granted_units: grantedUnits,
    declared_currency: String(reservationCurrency ?? ''),
    measurable_currency: MEASURABLE,
    detail: `this runner charges ${MEASURABLE} and the reservation is denominated in ${String(reservationCurrency ?? '(none)')}; a launch is not a token, so nothing was launched and nothing was charged. A token-denominated campaign needs a runner that charges the executor's own usage.totalTokens.`,
  });
}

/** What the entry point prints and what status it leaves, for any run record. */
export function entryReportFor(record) {
  if (record?.status === 'BLOCKED') {
    return {
      exitCode: Number.isInteger(record.exitCode) ? record.exitCode : 4,
      report: {
        status: record.status,
        code: record.code,
        launches: record.launches ?? 0,
        charged_units: record.charged_units ?? 0,
        detail: record.detail,
      },
    };
  }
  return { exitCode: 0, report: null };
}

export function assertRunnerPreregInForce(prereg, manifest) {
  if (manifest?.preregistration?.status !== 'IN_FORCE' ||
      manifest.preregistration.file !== 'preregistration.json' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(prereg)) {
    throw new Error('CAMPAIGN_PREREGISTRATION_NOT_IN_FORCE');
  }
}

export async function runCampaign({ label = 'a', write = true, out = null, verifyPin = false } = {}) {
  const prereg = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'preregistration.json'), 'utf8'));
  const frozenTable = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'frozen-table.json'), 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'manifest.json'), 'utf8'));
  assertRunnerPreregInForce(prereg, manifest);

  // --- 0. the frozen document is admissible and self-consistent -------------
  assertPreregistration(prereg);
  const preregDigest = preregistrationDigest(prereg);
  const feasibility = ruleFeasibility({
    alpha: prereg.multiplicity_rule.alpha,
    confidence: prereg.multiplicity_rule.confidence,
    familySize: prereg.multiplicity_rule.family_size,
  });
  if (feasibility.never_rejects) {
    throw new Error(`FROZEN_RULE_NOT_SELF_CONSISTENT: ${JSON.stringify(feasibility)}`);
  }

  const base = resolveBase();
  const runId = `s2-008-campaign-${label}-${process.pid}`;
  const root = path.join(os.tmpdir(), `s2-008-campaign-registry-${label}`);
  // The purge comes FIRST, before anything this run writes. A run that
  // inherited a previous run's journal would be scored against rows it did not
  // write, and a repeat run on the same base has to fail on the property, not
  // on its own leftovers. The scratch root is removed outright, so there is
  // nothing to inherit.
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });

  const clock = fixedClock(DECISION_POINT);
  const registry = openRegistry({ root, clock, ids: idFactory(`${label}-${runId}`) });
  const provenance = freezeProvenance({
    commit: base.commit_sha, tree: base.tree_sha, runId, label,
    executorId: `exec-s2-008-campaign-${label}`,
    nonce: deriveProcessNonce({ label, runId, attempt: 0, pid: process.pid }),
    clock: DECISION_POINT, startedAt: DECISION_POINT,
  });

  // --- 1. the preregistration row and the budget reservation ---------------
  const reservationId = prereg.budget_reservation.reservation_id;
  // The row the ordering proof reads: `preregistration_digest` and `run_id` at
  // the TOP level, and the envelope's `kind` plus the payload's `record_kind`.
  appendRecord(registry, {
    kind: 'PREREGISTRATION',
    record_kind: 'PREREGISTRATION_RECORDED',
    run_id: runId,
    nonce: provenance.nonce,
    preregistration_digest: preregDigest,
    expected_table_digest: prereg.expected_table_digest ?? null,
    trial_count: prereg.trial_list.length,
    seed_count: prereg.seed_rule.seeds.length,
    inference_mode: prereg.inference_mode,
    recorded_at: DECISION_POINT,
  });
  assertBudgetReservation(prereg.budget_reservation, clock.nowNs());
  // The reservation is TAKEN through the registry's CAS write, so it is a row in
  // the chained ledger and not a field in a document: an unassigned budget is
  // not a zero.
  const reservationPayload = {
    kind: 'BUDGET_RESERVATION',
    reservation_id: reservationId,
    granted_units: prereg.budget_reservation.granted_units,
    spent_units: 0,
    currency: prereg.budget_reservation.currency,
    expires_at: prereg.budget_reservation.expires_at,
    preregistration_digest: preregDigest,
    run_id: runId,
    nonce: provenance.nonce,
  };
  putExperiment(registry, {
    key: canonicalDigest({ operation: 'OPEN_RESERVATION', ...reservationPayload }),
    args: { ...reservationPayload },
    expectedRevision: registry.revision(),
    mutate: () => ({ ...reservationPayload, taken_at: DECISION_POINT }),
  });
  const reservation = recordSpend(registry, {
    reservationId,
    key: `reserve:${reservationId}:${preregDigest}`,
    args: { granted_units: prereg.budget_reservation.granted_units, units: 0, currency: prereg.budget_reservation.currency, expires_at: prereg.budget_reservation.expires_at },
  });
  void reservation;
  // --- 2. ordering proved from the JOURNAL, not from a clock ---------------
  assertPreregisteredBeforeRun({ prereg, runId, journal: projectJournalRows(readJournal(registry)) });

  const rules = {
    alpha: prereg.multiplicity_rule.alpha,
    method: prereg.multiplicity_rule.method,
    confidence: prereg.multiplicity_rule.confidence,
    direction: prereg.multiplicity_rule.direction,
    null_value: prereg.multiplicity_rule.null_value,
    comparisons: prereg.multiplicity_rule.declared_comparisons.slice(),
  };
  const noiseBand = prereg.noise_rule.band;
  const timeoutMs = prereg.budget_reservation.trial_timeout_ms;
  const deps = engineDeps();

  // --- 2b. WHAT THIS RUNNER CAN MEASURE, checked BEFORE anything is launched ---
  //
  // This runner charges CONTAINER LAUNCHES: one unit per launch, because a
  // launch is the thing it can observe happening. A token-denominated campaign
  // is a different measurement, and the two are not interchangeable: the v1
  // attempt charged nothing at all, and a later variant would have charged ONE
  // TOKEN per launch against a 5,000,000-token ceiling — nine launches would read
  // as 9 tokens spent, which is a ceiling that looks untouched while the whole
  // amount went out. A budget that cannot be measured must REFUSE the run, not
  // acquire a unit size that flatters it.
  //
  // So: this runner declares what it can measure, and a reservation in any other
  // currency stops the campaign here — before the first container, so a refusal
  // costs nothing and leaves no half-spent ledger behind.
  const MEASURABLE_CURRENCY = MEASURABLE;
  // The arms this runner can dispatch to the MODEL program, and therefore the only
  // arms whose token spend it can carry. Until the adapter dispatches the model
  // arm, this is EMPTY on purpose: a token reservation then refuses every arm
  // rather than charging a number this runner never produced.
  const TOKEN_DISPATCHABLE_ARMS = DISPATCHABLE_MODEL_ARMS;
  let budgetStop = null;
  const reservationCurrency = String(prereg.budget_reservation.currency ?? '');
  const refusal = currencyRefusal(reservationCurrency, { grantedUnits: prereg.budget_reservation.granted_units });
  // A token reservation is only chargeable for arms this runner can dispatch to
  // the model program. Decided HERE, before any launch, so an undispatchable arm
  // costs nothing to find out.
  const dispatchableArms = TOKEN_DISPATCHABLE_ARMS;
  const armPlan = prereg.trial_list.map((entry) => ({
    trial: entry.trial_id,
    arm_id: entry.arm_id,
    plan: chargeFor({ currency: reservationCurrency, armId: entry.arm_id, dispatchableArms }),
  }));
  const unplannable = armPlan.filter((row) => row.plan.refusal);
  if (unplannable.length > 0) {
    const detail = `${unplannable.map((row) => `${row.trial}:${row.arm_id}:${row.plan.refusal}`).join('; ')}. Nothing was launched: a reservation may only be charged in a unit this runner can name, and a token charge must be a number the arm itself reported.`;
    appendRecord(registry, {
      kind: 'BUDGET_REFUSAL',
      record_kind: 'CHARGE_NOT_MEASURABLE',
      run_id: runId,
      reservation_id: reservationId,
      declared_currency: reservationCurrency,
      arms: unplannable.map((row) => ({ trial: row.trial, arm: row.arm_id, refusal: row.plan.refusal })),
      spent_units: 0,
      launches: 0,
      detail,
      at: DECISION_POINT,
    });
    process.stderr.write(`${detail}\n`);
    return { status: 'BLOCKED', code: 'CHARGE_NOT_MEASURABLE', exitCode: 4, launches: 0, charged_units: 0, spent_units: 0, detail };
  }
  if (refusal !== null) {
    appendRecord(registry, {
      kind: 'BUDGET_REFUSAL',
      record_kind: refusal.code,
      run_id: runId,
      reservation_id: reservationId,
      declared_currency: refusal.declared_currency,
      measurable_currency: refusal.measurable_currency,
      granted_units: refusal.granted_units,
      spent_units: 0,
      launches: 0,
      detail: refusal.detail,
      at: DECISION_POINT,
    });
    process.stderr.write(`${refusal.detail}\n`);
    return refusal;
  }

  // --- 3. PHASE A: every arm at every seed, by the REAL adapter, BLIND ----
  // Every launch is CHARGED against the reservation as it happens. A budget
  // that is only compared at the end is a number in a document, and the first
  // attempt made nine launches against a six-unit reservation without charging
  // any of them: the ledger said nothing and the record said `within_reservation`
  // by arithmetic nobody ran. Superseded, and the arithmetic is now real.
  const pin = buildImage();
  const executions = [];
  let spentUnits = 0;
  const charges = [];
  for (const entry of prereg.trial_list) {
    for (const seed of prereg.seed_rule.seeds) {
      const result = runTrial({
        armId: entry.arm_id, seed, samples: prereg.noise_rule.bootstrap_samples,
        timeoutMs, pin: pin.pin,
      });
      // The charge is decided AFTER the launch, because a token charge can only be
      // read out of what the arm reported. A refusal here is a STOP, not a fallback
      // to one unit: an unmeasurable launch is charged nothing and ends the run,
      // because a ledger that keeps going after it stopped accounting is exactly
      // how the v1 attempt went uncharged.
      const step = chargingStep({
        currency: reservationCurrency,
        spentUnits,
        grantedUnits: prereg.budget_reservation.granted_units,
        armOutput: result.output,
        armId: entry.arm_id,
        dispatchableArms: TOKEN_DISPATCHABLE_ARMS,
      });
      if (step.action === 'refuse') {
        appendRecord(registry, {
          kind: 'BUDGET_REFUSAL',
          record_kind: 'CHARGE_NOT_MEASURABLE',
          run_id: runId,
          reservation_id: reservationId,
          declared_currency: reservationCurrency,
          trial: entry.trial_id,
          arm: entry.arm_id,
          seed,
          spent_units: step.spent_units,
          launches: executions.length,
          detail: step.detail,
          at: DECISION_POINT,
        });
        process.stderr.write(`${step.detail}\n`);
        return { status: 'BLOCKED', code: step.code, exitCode: 4, launches: executions.length, charged_units: step.spent_units, spent_units: step.spent_units, detail: step.detail };
      }
      spentUnits = step.spent_units;
      const charge = recordSpend(registry, {
        reservationId,
        key: `launch:${reservationId}:${preregDigest}:${entry.trial_id}:${String(seed)}`,
        args: { reservation_id: reservationId, units: step.units, unit: step.unit, currency: reservationCurrency, source: step.source, trial: entry.trial_id, seed, at: DECISION_POINT },
      });
      // `replayed: false` is the ledger saying it CHARGED, and reporting that
      // as `outcome: false` reads like a failure. It is named here.
      charges.push({ trial: entry.trial_id, seed, units: step.units, unit: step.unit, source: step.source, replayed: charge?.replayed === true, settled: charge?.replayed !== true });
      // The ceiling is enforced HERE as well as inside the arm: the arm stops
      // between cases, and a run must not start the next launch once the money
      // is gone. The arm's own stop is recorded, not re-derived.
      if (step.stop) {
        budgetStop = { reason: 'BUDGET_EXHAUSTED', spent_units: spentUnits, granted_units: Number(prereg.budget_reservation.granted_units), after: { trial: entry.trial_id, seed } };
        break;
      }
      const row = {
        kind: 'TRIAL_EXECUTION',
        record_kind: 'TRIAL_EXECUTED',
        trial: entry.trial_id,
        raw_run_id: runId,
        nonce: provenance.nonce,
        at: DECISION_POINT,
        arm_id: entry.arm_id,
        seed,
        ok: result.ok,
        exit_code: result.record.exit_code,
        image: result.record.image,
        real_start_proven: result.record.real_start.proven,
        output_digest: result.record.output_digest,
        // A launch that produced nothing is recorded as producing nothing. It
        // is never a zero, and its row says so.
        produced_measurement: result.output !== null,
      };
      appendRecord(registry, row);
      executions.push({ entry, seed, result });
    }
  }

  // --- 4. PHASE B: the decision point, and the ONE sealed holdout open -----
  // `readCorpus` names ONE case, and that is the whole point: the open is
  // budgeted at one and the partition's labels come out of that single
  // journalled read. The case named here is the partition's first commit; the
  // returned `labels` map is the whole partition.
  const holdoutCases = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'cases/holdout.json'), 'utf8'));
  const holdoutIds = holdoutCases.map((row) => row.case_id);
  const blindDigest = canonicalDigest(JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'cases/holdout.blind.json'), 'utf8')));
  const access = readCorpus(registry, {
    partition: 'HOLDOUT',
    caseId: holdoutIds[0],
    unsealDigest: prereg.holdout_access.unseal_digest,
    corpusDir: CORPUS_DIR,
    decisionPoint: DECISION_POINT,
    maxOpens: prereg.holdout_access.max_opens,
    actorKind: HOLDOUT_ACTOR_KIND,
    releasedActorKinds: prereg.holdout_access.released_actor_kinds,
  });
  const labels = access.labels;

  // --- 4b. the agreement vectors, and the ONE post-reveal bootstrap launch --
  // The agreement vectors are written to a scratch file that becomes the input
  // of the bootstrap image, so the bootstrap's image digest is a function of
  // the measurement it resamples.
  const agreementVectors = [];
  for (const entry of prereg.trial_list) {
    const mine = executions.filter((item) => item.entry.trial_id === entry.trial_id && item.result.output !== null);
    if (mine.length === 0) continue;
    const byCase = mine[0].result.output.predictions.map((prediction) => ({
      case_id: prediction.case_id,
      agree: prediction.predicted === labels[prediction.case_id] ? 1 : 0,
    }));
    agreementVectors.push({ trial_id: entry.trial_id, arm_id: entry.arm_id, agreement: byCase.map((row) => row.agree) });
  }
  const agreementFile = path.join(root, 'agreement.json');
  fs.writeFileSync(agreementFile, JSON.stringify({
    vectors: agreementVectors,
    seeds: [...prereg.seed_rule.seeds],
    samples: prereg.noise_rule.bootstrap_samples,
    confidence: prereg.multiplicity_rule.confidence,
  }));
  const bootPin = agreementVectors.length === 0 ? null : buildBootstrapImage({
    agreementFile, samples: prereg.noise_rule.bootstrap_samples, confidence: prereg.multiplicity_rule.confidence,
  });
  let bootstrap = null;
  if (bootPin !== null) {
    const result = runBootstrap({
      agreementFile, samples: prereg.noise_rule.bootstrap_samples,
      confidence: prereg.multiplicity_rule.confidence, timeoutMs, pin: bootPin.pin,
    });
    spentUnits += 1;
    recordSpend(registry, {
      reservationId,
      key: `launch:${reservationId}:${preregDigest}:bootstrap`,
      args: { reservation_id: reservationId, units: 1, currency: prereg.budget_reservation.currency, trial: 'BOOTSTRAP', at: DECISION_POINT },
    });
    charges.push({ trial: 'BOOTSTRAP', seed: null, units: 1, unit: MEASURABLE_CURRENCY, launch_succeeded: result.ok, settled: true, note: 'a launch that fails is still charged: the unit is the launch, not the answer' });
    appendRecord(registry, {
      kind: 'TRIAL_EXECUTION', record_kind: 'BOOTSTRAP_EXECUTED', trial: 'BOOTSTRAP',
      raw_run_id: runId, nonce: provenance.nonce, at: DECISION_POINT,
      ok: result.ok, exit_code: result.record.exit_code, image: result.record.image,
      real_start_proven: result.record.real_start.proven, output_digest: result.record.output_digest,
      produced_measurement: result.output !== null,
    });
    bootstrap = result;
  }
  const bootstrapByArmSeed = new Map();
  for (const row of bootstrap?.output?.results ?? []) {
    bootstrapByArmSeed.set(`${row.trial_id}:${String(row.seed)}`, row);
  }

  // --- 5. PHASE C: score, classify, decide --------------------------------
  const evaluator = { evaluator_id: 'evl-s2-008-campaign-evaluator', independent: true, blind_to_producer: true };
  const calibration = {
    status: 'MEASURED', not_measured_reason: null,
    evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true },
  };
  const seedsBinding = { seeds: [...prereg.seed_rule.seeds], source: 'PREREGISTERED', preregistered_seeds: [...prereg.seed_rule.seeds] };
  const budgetBinding = {
    reservation_id: reservationId, granted_units: prereg.budget_reservation.granted_units,
    spent_units: spentUnits, currency: prereg.budget_reservation.currency,
    expires_at: prereg.budget_reservation.expires_at, within_reservation: spentUnits <= prereg.budget_reservation.granted_units,
  };
  const holdoutBinding = {
    partition: 'HOLDOUT', read_at: DECISION_POINT, decision_at: DECISION_POINT,
    opened_before_decision_point: false, opens: 1, max_opens: prereg.holdout_access.max_opens,
    labels_digest: access.labelsDigest, access_record_id: access.accessRecordId,
  };

  const trials = [];
  const reconciliations = [];
  for (const entry of prereg.trial_list) {
    const mine = executions.filter((item) => item.entry.trial_id === entry.trial_id);
    // A trial whose every launch produced nothing is an INFRA observation, and
    // the engine classifies it. It is NOT a zero and NOT a skip.
    const measuredSeeds = mine.filter((item) => item.result.output !== null);
    if (measuredSeeds.length === 0) {
      const observation = {
        infra: { code: 'ADAPTER_PRODUCED_NO_PAYLOAD', message: `every launch of ${entry.arm_id} returned no measurement; ${mine.length} launch(es) ran and none answered` },
        elapsed_ms: 0,
      };
      const classified = classifyTrialObservation(observation, { timeoutMs, deps, index: entry.index, trial: entry.trial_id, noiseBand, rule: { ...rules, subject: entry.trial_id } });
      reconciliations.push({ trial: entry.trial_id, kind: 'INFRA', classified });
      trials.push({ entry, seeds: [], classified, agreement: null, launches: mine.map((item) => item.result.record) });
      continue;
    }
    // Agreement per case, from the adapter's real predictions and the labels
    // this single open revealed.
    const perSeed = [];
    for (const item of measuredSeeds) {
      const out = item.result.output;
      const byCase = out.predictions.map((prediction) => ({
        case_id: prediction.case_id,
        agree: prediction.predicted === labels[prediction.case_id] ? 1 : 0,
      }));
      if (byCase.length !== holdoutIds.length || byCase.some((row) => labels[row.case_id] === undefined)) {
        throw new Error(`MEASUREMENT_OVER_A_DIFFERENT_PARTITION: ${String(entry.trial_id)} at seed ${String(item.seed)} scored ${byCase.length} case(s) against a holdout of ${holdoutIds.length}`);
      }
      const agreeing = byCase.reduce((sum, row) => sum + row.agree, 0);
      // The interval is the POST-REVEAL container's, over the full multiplicity
      // of every resample. It is not recomputed here: the host has no business
      // producing the distribution the decision rests on.
      const boot = bootstrapByArmSeed.get(`${entry.trial_id}:${String(item.seed)}`) ?? null;
      if (boot === null) {
        throw new Error(`BOOTSTRAP_ROW_ABSENT: no interval for ${String(entry.trial_id)} at seed ${String(item.seed)}`);
      }
      perSeed.push({
        seed: item.seed, agreeing, denominator: byCase.length, measured: agreeing / byCase.length,
        interval: {
          lower: boot.lower, upper: boot.upper, confidence: boot.confidence, method: boot.method,
          n: boot.n, samples: boot.samples, resample_mean: boot.resample_mean,
          resample_min: boot.min, resample_max: boot.max,
          sorted_rates_sha256: boot.sorted_rates_sha256,
        },
        mean_matches_observed: boot.mean_matches_observed,
        banner: item.result.record.banner,
        container_pid: item.result.record.real_start.container_pid,
        output_digest: item.result.record.output_digest,
      });
    }
    // The resample mean of a bootstrap of the data converges on the data's own
    // mean. A trial whose intervals do not sit around its own measured rate is
    // a broken interval, and it is refused here rather than published.
    for (const row of perSeed) {
      if (row.mean_matches_observed !== true) {
        throw new Error(`INTERVAL_DISJOINT_FROM_ITS_OWN_DATA: ${String(entry.trial_id)} at seed ${String(row.seed)} has a resample mean that is not the measured rate; the resampling is wrong`);
      }
    }
    // The FROZEN aggregation: the point estimate is the observed rate (which no
    // seed can move) and the interval is the HULL over every seed, so no seed
    // is ever chosen for being narrow and no seed is ever dropped.
    const measured = perSeed[0].measured;
    const lower = Math.min(...perSeed.map((row) => row.interval.lower));
    const upper = Math.max(...perSeed.map((row) => row.interval.upper));
    const hull = { lower, upper, method: 'HULL_OF_ALL_SEED_INTERVALS', seeds_used: perSeed.length, seeds_reported: perSeed.length, selected: null };
    // The analytic interval is carried beside it for the independent check; it
    // decides nothing.
    const analytic = wilsonInterval({ successes: perSeed[0].agreeing, trials: perSeed[0].denominator, confidence: prereg.multiplicity_rule.confidence });

    const observation = {
      measured, interval: hull, numerator: perSeed[0].agreeing, denominator: perSeed[0].denominator,
      elapsed_ms: 0,
      per_seed: perSeed, hull, analytic_wilson: analytic,
      bindings: { seed: seedsBinding, holdout: holdoutBinding, budget: budgetBinding, evaluator },
      evaluator, calibration,
    };
    const classified = classifyTrialObservation(observation, { timeoutMs, deps, index: entry.index, trial: entry.trial_id, noiseBand, rule: { ...rules, subject: entry.trial_id } });
    const trialRecord = {
      trial: entry.trial_id, index: entry.index, arm_id: entry.arm_id, metric: prereg.metric.name,
      status: classified.status, outcome: classified.outcome,
      numerator: perSeed[0].agreeing, denominator: perSeed[0].denominator,
      observed: classified.observed, interval: hull,
      reason_codes: classified.reason_codes,
      decision: classified.decision,
      seeds: [...prereg.seed_rule.seeds],
      // The four bindings, in the shape `verdictProjection` projects and
      // `resolveTrialVerdict` checks. The flat members are kept beside them so
      // either reader works.
      bindings: { seed: seedsBinding, holdout: holdoutBinding, budget: budgetBinding, evaluator },
      seedBinding: seedsBinding, holdoutBinding, budgetBinding, evaluatorBinding: evaluator,
      evaluator, calibration,
      per_seed: perSeed, analytic_wilson: analytic,
      launches: mine.map((item) => item.result.record),
    };
    const verdict = resolveTrialVerdict(trialRecord);
    trialRecord.verdict = verdict.verdict;
    trialRecord.verdict_reasons = [...verdict.reasons];
    trials.push({ entry, perSeed, classified, agreement: trialRecord, verdict, launches: trialRecord.launches });
    appendRecord(registry, {
      kind: 'TRIAL', record_kind: 'TRIAL_RESOLVED', campaign_id: prereg.preregistration_id,
      trial: entry.trial_id, raw_run_id: runId, at: DECISION_POINT,
      status: classified.status, outcome: classified.outcome,
      measured: classified.observed, interval: hull, seeds: [...prereg.seed_rule.seeds],
      verdict: verdict.verdict, verdict_reasons: [...verdict.reasons],
    });
  }

  // --- 6. the decision, and what decided nothing ---------------------------
  const metrics = metricsSummary(trials.map((item) => item.agreement ?? { metric: prereg.metric.name, status: item.classified.status, outcome: item.classified.outcome, trial: item.entry.trial_id }));
  const seedDisclosure = bestSeedDisclosure('report_every_seed', prereg.seed_rule.seeds);
  const latency = latencyRecorded(trials.map((item) => item.agreement ?? {}), prereg.noise_rule);

  const campaignRows = trials.filter((item) => item.agreement !== null);
  // The pooled aggregate is the family's own linear combination, and its
  // interval is the UNION of the family intervals: every convex combination of
  // the declared means lies inside the hull, so the hull is a CONSERVATIVE
  // interval for the pooled rate and not a claim about its own precision. The
  // width it ends up with is the between-arm heterogeneity, and that is the
  // honest number - a pooled interval narrower than the spread of its own
  // members would be a fiction.
  const pooled_interval_construction = 'UNION_OF_THE_DECLARED_FAMILY_INTERVALS (conservative for a linear combination of the family means)';
  // NO MEASURED ROW IS A NAMED ANSWER, NOT A CRASH. A campaign whose every
  // trial was INFRA has no pooled rate to score, and `decisionFromInterval`
  // refuses a non-finite `observed` by throwing - which, unhandled, is a stack
  // trace where the reader expects a verdict. The first run of this campaign
  // after a predictor defect hit exactly that, and the fix is to SAY the
  // campaign measured nothing rather than to divide by a denominator of zero.
  const campaignDecision = campaignRows.length === 0 || metrics.denominator === 0
    ? {
      decision: 'UNRESOLVED',
      reason: 'no_trial_resolved: the campaign measured nothing, so there is no rate to score and no interval to correct; this is not a null result and not a pass',
      measured_trials: 0,
      declared_trials: prereg.trial_list.length,
      numerator: metrics.numerator,
      denominator: metrics.denominator,
      correction: null,
      interval_construction: pooled_interval_construction,
    }
    : decisionFromInterval({
      observed: metrics.numerator / metrics.denominator,
      lower: Math.min(...campaignRows.map((item) => item.agreement.interval.lower)),
      upper: Math.max(...campaignRows.map((item) => item.agreement.interval.upper)),
      noiseBand,
      rule: { ...rules, subject_is_pooled_aggregate: true, subject: prereg.campaign_metric.name },
    });
  // `decisionFromInterval` returns a FROZEN object, so the construction note is
  // carried beside it rather than added to it.

  const violations = trials.filter((item) => item.verdict !== undefined && item.verdict.verdict !== 'ALLOW');
  const campaignVerdict = resolveCampaignVerdict({
    failures: violations.map((item) => ({ trial: item.entry.trial_id, reasons: item.verdict.reasons })),
    limits: [{ code: 'LATENCY_RECORDED_ONLY', detail: 'wall clock is measured as samples and decides nothing' }],
    proofStatus: [{ check: 'preregistration_before_first_trial', proved_by: 'REGISTRY_JOURNAL', ok: true }],
  });

  const record = {
    version: 's2-008-campaign-run/1',
    kind: 's2-008-campaign-run/1',
    ticket: 'S2-008',
    campaign: 'the real Veritas history, three preregistered message-feature arms',
    label: String(label),
    raw_run_id: runId,
    commit_sha: base.commit_sha,
    tree_sha: base.tree_sha,
    base,
    // The `run` block `verdictProjection` reads. Its status is the RUN's, not a
    // trial's: a campaign whose trials all resolved and whose reconciliation
    // rows are open is a run that completed.
    run: {
      version: 's2-008-campaign-run/1',
      label: String(label),
      status: reconciliations.length === 0 ? 'RUN_COMPLETED' : 'RUN_RECONCILIATION',
      started_at: DECISION_POINT,
      finished_at: DECISION_POINT,
      engine: {
        trial_count: prereg.trial_list.length,
        trial_timeout_ms: timeoutMs,
        trial_timeout_source: 'budget_reservation.trial_timeout_ms (preregistered, not chosen at run time)',
        units_per_trial: 1,
        sequential: true,
        retriable: false,
      },
    },
    provenance,
    adapter: {
      kind: 'real installed executor inside the S2-002 A-MVP-04 digest-pinned isolation profile',
      two_processes: 'the predictor runs blind and answers first; the evaluator opens the holdout once; the bootstrap runs afterwards in its own launch, because it needs the labels the predictor must never see',
      provider: 'generic_cli',
      adapter_kind: 'real',
      real_adapter_provenance: {
        status: 'REAL_ADAPTER_AVAILABLE',
        detail: `podman launched the content-pinned image ${pin.pin.imageId} (base ${'docker.io/library/node@sha256:25330af3531fb5e23318554a0aa911125b6e91b1b777edf7655501d207c067a2'}) with the four allowlist axes enforced; the container's own pid and node version came back in its stdout`,
      },
      NOT_A_MODEL_CALL: 'the executor is a deterministic installed program, not a model-calling agent; no model and no paid service is involved anywhere in this campaign',
      pin: pin.pin,
      pin_context_digest: pin.context_digest,
      bootstrap_pin: bootPin?.pin ?? null,
      bootstrap_pin_context_digest: bootPin?.context_digest ?? null,
      bootstrap_launch: bootstrap?.record ?? null,
      blind_input_digest: blindDigest,
      launches: executions.length,
    },
    preregistration: {
      digest: preregDigest,
      expected_table_digest: prereg.expected_table_digest ?? null,
      frozen_table: frozenTable,
      card_id: prereg.card_id,
      card_digest: prereg.card_digest,
      seed_count: prereg.seed_count,
      trial_count: prereg.trial_list.length,
      seeds: [...prereg.seed_rule.seeds],
      stopping_rule: prereg.stopping_rule,
      sequential_rule: prereg.sequential_rule,
      noise_rule: prereg.noise_rule,
      decision_rule: rules,
      inference_mode: prereg.inference_mode,
      budget: {
        reservation_id: reservationId, granted_units: prereg.budget_reservation.granted_units,
        spent_units: spentUnits, currency: prereg.budget_reservation.currency,
        unit_definition: prereg.budget_reservation.unit_definition,
        expires_at: prereg.budget_reservation.expires_at,
        within_reservation: spentUnits <= prereg.budget_reservation.granted_units,
        charges,
      },
    },
    ordering: {
      rule: 'every predictor answered before any label was revealed, and the holdout was opened exactly once',
      preregistration_row_index: readJournal(registry).findIndex((row) => row.kind === 'PREREGISTRATION'),
      first_trial_row_index: readJournal(registry).findIndex((row) => row.kind === 'TRIAL_EXECUTION'),
      access_row_index: readJournal(registry).findIndex((row) => row.kind === 'ACCESS'),
      access_rows: readJournal(registry).filter((row) => row.kind === 'ACCESS').length,
      proved_by: 'REGISTRY_JOURNAL_NOT_A_CLOCK',
      ordering_holds: (() => {
        const journal = readJournal(registry);
        const pre = journal.findIndex((row) => row.kind === 'PREREGISTRATION');
        const firstTrial = journal.findIndex((row) => row.kind === 'TRIAL_EXECUTION');
        const access = journal.findIndex((row) => row.kind === 'ACCESS');
        return pre >= 0 && firstTrial > pre && access > firstTrial;
      })(),
    },
    holdout: holdoutBinding,
    evaluator,
    calibration,
    trials: trials.map((item) => item.agreement ?? {
      trial: item.entry.trial_id, index: item.entry.index, arm_id: item.entry.arm_id,
      metric: prereg.metric.name, status: item.classified.status, outcome: item.classified.outcome,
      reason_codes: item.classified.reason_codes, seeds: [...prereg.seed_rule.seeds], observed: null,
      interval: null, decision: null,
      bindings: { seed: seedsBinding, holdout: holdoutBinding, budget: budgetBinding, evaluator },
      launches: item.launches,
    }),
    reconciliations,
    metrics,
    latency,
    seed_disclosure: seedDisclosure,
    campaign_decision: { ...campaignDecision, interval_construction: pooled_interval_construction },
    campaign_verdict: campaignVerdict,
    rule_feasibility: feasibility,
    registry: {
      root_is_scratch: true,
      chain_verified: verifyChain(registry),
      head_digest: headDigest(registry),
      snapshot_digest: snapshotDigest(registry),
      rows: readJournal(registry).map((row) => ({ kind: row.kind, trial: row.trial ?? null, at: row.at })),
    },
    codes: [],
    counters: {
      launches: executions.length,
      launches_producing_a_measurement: executions.filter((item) => item.result.output !== null).length,
      trials_resolved: trials.filter((item) => item.classified.status === 'RESOLVED').length,
      trials_unresolved: trials.filter((item) => item.classified.status === 'UNRESOLVED').length,
      trials_infra: trials.filter((item) => item.classified.status === 'INFRA_ERROR').length,
      trials_skipped: 0,
      reconciliations: reconciliations.length,
    },
  };

  // The decision digest is the digest of the verdict PROJECTION, and the
  // projection names no artefact member, so it can be computed from a throwaway
  // binding and then carried INSIDE the record. Binding last is what makes the
  // file verify: `assertArtefactBound` re-digests the whole body, so a digest
  // attached after the binding would be a digest of a document that no longer
  // exists.
  const probe = bindArtefact(record, provenance);
  const projection = assertNoWallClockInVerdict(probe);
  const artefact = bindArtefact({ ...record, decision_digest: decisionDigest(probe), verdict_projection: projection }, provenance);
  assertArtefactBound(artefact);

  if (write) {
    const target = out ?? path.join(REPO_ROOT, 'evidence/s2-008-campaign', `run-${label}.json`);
    writeArtefact(target, artefact, {});
  }
  return artefact;
}


/**
 * V4 prediction phase. The model is called while every input is blind; labels
 * are opened later by the independent evaluator. Each seed's exact rows are
 * written to a separate immutable sidecar and bound by its digest.
 */
export async function runV4Campaign({
  label = 'a', arm = null, seed = null, dryRun = false, write = true, out = null,
  prereg = null,
  manifest = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'manifest.json'), 'utf8')),
  modelPin = null,
  dispatchableArms = DISPATCHABLE_MODEL_ARMS, expectedVersion = null,
  runModel = runModelTrial, runRegex = runTrial, buildRegex = buildImage, resolveBaseFn = resolveBase, now = () => Date.now(),
} = {}) {
  const safeLabel = String(label);
  if (!/^[a-z0-9][a-z0-9-]{0,19}$/.test(safeLabel)) throw new Error('RUN_LABEL_INVALID');
  const activeFile = manifest?.preregistration?.file;
  if (!['preregistration.v4.in-force.json', 'preregistration.v5.in-force.json', 'preregistration.v6.in-force.json', 'preregistration.v7.in-force.json', 'preregistration.v8.in-force.json'].includes(activeFile)) {
    throw new Error('CAMPAIGN_PREREGISTRATION_NOT_IN_FORCE');
  }
  prereg = prereg ?? JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, activeFile), 'utf8'));
  const version = prereg.rule === 's2-008-prereg-v8' ? 8 : prereg.rule === 's2-008-prereg-v7' ? 7 : prereg.rule === 's2-008-prereg-v6' ? 6 : prereg.rule === 's2-008-prereg-v5' ? 5 : 4;
  if (expectedVersion !== null && expectedVersion !== version) throw new Error('ACTIVE_CAMPAIGN_VERSION_MISMATCH');
  const campaignKind = `s2-008-campaign-v${version}-predictions/1`;
  const base = resolveBaseFn();
  const runId = 's2-008c-v' + version + '-' + safeLabel + '-' + randomUUID().replaceAll('-', '').slice(0, 20);
  const nonce = deriveProcessNonce({ label: safeLabel, runId, attempt: 0, pid: process.pid });
  const expectedPreregFile = 'preregistration.v' + version + '.in-force.json';
  if (manifest?.preregistration?.file !== expectedPreregFile ||
      manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(prereg) ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      prereg.approval?.status !== 'APPROVED' || prereg.approval?.in_force !== true) {
    throw new Error('CAMPAIGN_PREREGISTRATION_NOT_IN_FORCE');
  }
  // The v4 image was built before the shared remaining-cap protocol existed.
  // Its arm would take a fresh 5m grant at every seed. Paid v4 is therefore
  // refused before building or launching anything; only a sealed successor
  // whose image contains the cap-aware arm may spend.
  if (!dryRun && !['s2-008-prereg-v7','s2-008-prereg-v8'].includes(prereg.rule)) {
    const code = version === 6 ? 'MODEL_CREDENTIAL_ENV_RESEAL_REQUIRED'
      : version === 5 ? 'MODEL_TOTAL_TIMEOUT_RESEAL_REQUIRED' : 'MODEL_CAP_RESEAL_REQUIRED';
    return {
      kind: campaignKind, status: 'BLOCKED', code,
      reason: code + ': only the v7 signed image binds the provider-specific credential name and finite retry policy',
      spent_units: 0, launches: 0, charges: [], trials: [],
      preregistration_digest: prereg.preregistration_digest,
    };
  }
  const productionPaidBackend = runModel === runModelTrial;
  if (!dryRun && productionPaidBackend && !['a', 'b'].includes(safeLabel)) {
    return { kind: campaignKind, status: 'BLOCKED', code: 'PAID_RUN_LABEL_INVALID', reason: 'production paid runs require the preregistered A or B label', spent_units: 0, launches: 0, charges: [], trials: [], preregistration_digest: prereg.preregistration_digest };
  }
  if (!dryRun && productionPaidBackend && !write) {
    return { kind: campaignKind, status: 'BLOCKED', code: 'PAID_RUN_EVIDENCE_REQUIRED', reason: 'production paid runs require durable report and prediction sidecars', spent_units: 0, launches: 0, charges: [], trials: [], preregistration_digest: prereg.preregistration_digest };
  }
  if (!dryRun && base?.worktree_dirty !== false) {
    return {
      kind: campaignKind, status: 'BLOCKED', code: 'DIRTY_SOURCE_BASE',
      reason: 'paid model launch refused because the source tree differs from the signed image and preregistration review state',
      spent_units: 0, launches: 0, charges: [], trials: [],
      preregistration_digest: prereg.preregistration_digest,
    };
  }
  if (['s2-008-prereg-v6','s2-008-prereg-v7','s2-008-prereg-v8'].includes(prereg.rule)) {
    assertV6ModelTimeoutPolicy(prereg.executor?.model_launch_timeout);
    if (prereg.holdout_access?.case_count !== 126) throw new Error('V6_MODEL_TIMEOUT_CASE_COUNT_MISMATCH');
  }
  if (prereg.rule === 's2-008-prereg-v8') assertV8ExecutorPolicy(prereg.executor);
  if (!dryRun && prereg.rule === 's2-008-prereg-v7') assertV7ExecutorPolicy(prereg.executor);
  const declaredPinPath = prereg.executor?.model_image?.built_image_pin;
  if (declaredPinPath !== 'evidence/s2-008-campaign/model-image-pin-v' + version + '.json') {
    throw new Error('MODEL_IMAGE_PIN_VERSION_MISMATCH');
  }
  const activeModelPin = modelPin ?? JSON.parse(fs.readFileSync(path.join(REPO_ROOT, declaredPinPath), 'utf8'));
  if (activeModelPin?.schema !== `s2-008-model-image-pin/${version}` ||
      activeModelPin.identical !== true ||
      activeModelPin.context_digest_stable !== true ||
      activeModelPin.content_commitment_stable !== true ||
      activeModelPin.first?.content_commitment !== prereg.executor?.model_image?.content_commitment) {
    return {
      kind: campaignKind, status: 'BLOCKED', code: 'MODEL_IMAGE_PIN_INVALID',
      reason: 'MODEL_IMAGE_PIN_INVALID: built image pin does not match the signed content commitment and version',
      spent_units: 0, launches: 0, charges: [], trials: [],
      preregistration_digest: prereg.preregistration_digest,
    };
  }
  const entries = arm === null ? prereg.trial_list : prereg.trial_list.filter((entry) => entry.arm_id === arm);
  if (entries.length === 0) throw new Error('CAMPAIGN_ARM_NOT_PREREGISTERED');
  const seeds = seed === null ? prereg.seed_rule.seeds : prereg.seed_rule.seeds.filter((value) => value === Number(seed));
  if (seeds.length === 0) throw new Error('CAMPAIGN_SEED_NOT_PREREGISTERED');
  if (write) {
    const reportTarget = out ?? path.join(REPO_ROOT, 'evidence/s2-008-campaign', `run-v${version}-${safeLabel}.json`);
    const planned = [reportTarget, ...entries.flatMap((entry) => seeds.map((currentSeed) =>
      path.join(REPO_ROOT, 'evidence/s2-008-campaign', `predictions-v${version}-${safeLabel}-${entry.trial_id}-${currentSeed}.json`)))];
    const collision = planned.find((target) => fs.existsSync(target));
    if (collision) return {
      kind: campaignKind, status: 'BLOCKED', code: 'CAMPAIGN_EVIDENCE_TARGET_EXISTS',
      reason: 'planned campaign report or prediction sidecar already exists; refusing before any arm launch',
      evidence_target: path.relative(REPO_ROOT, collision), spent_units: 0, launches: 0, charges: [], trials: [],
      preregistration_digest: prereg.preregistration_digest,
    };
  }
  const currency = prereg.budget_reservation.currency;
  const plan = entries.map((entry) => ({
    arm_id: entry.arm_id,
    charge: preflightCharge({ currency, armId: entry.arm_id, dispatchableArms }),
  }));
  const denied = plan.find((row) => row.charge.refusal);
  if (denied) return {
    kind: campaignKind, status: 'BLOCKED', code: 'CHARGE_NOT_MEASURABLE',
    reason: denied.charge.refusal, spent_units: 0, launches: 0, charges: [], trials: [],
    preregistration_digest: prereg.preregistration_digest,
  };

  const regexPin = entries.some((entry) => entry.arm_id !== 'arm-model-zai-glm53flash') ? buildRegex().pin : null;
  const trials = [];
  const charges = [];
  let spentUnits = 0;
  let launches = 0;
  let unknownLaunchAttempts = 0;
  let unreconciledSpend = false;
  let status = dryRun ? 'DRY_RUN' : 'MEASURED';
  let reason = null;
  let code = null;
  let modelCalls = 0;
  const granted = prereg.budget_reservation.granted_units;
  for (const entry of entries) {
    const perSeed = [];
    for (const currentSeed of seeds) {
      if (!dryRun && entry.arm_id === 'arm-model-zai-glm53flash' && version >= 6) {
        const expiresAt = Date.parse(prereg.budget_reservation?.expires_at ?? '');
        if (!Number.isFinite(expiresAt)) {
          status = 'BLOCKED'; code = 'BUDGET_RESERVATION_EXPIRY_INVALID';
          reason = 'v6 token reservation expiry is absent or invalid; no model launch was authorized';
          break;
        }
        let nowMs;
        try { nowMs = Number(now()); } catch { nowMs = Number.NaN; }
        if (!Number.isFinite(nowMs)) {
          status = 'BLOCKED'; code = 'BUDGET_RESERVATION_CLOCK_INVALID';
          reason = 'v6 token reservation authorization clock is invalid; no model launch was authorized';
          break;
        }
        if (nowMs >= expiresAt) {
          status = 'BLOCKED'; code = 'BUDGET_RESERVATION_EXPIRED';
          reason = 'v6 token reservation expired before this model launch';
          break;
        }
      }
      if (spentUnits >= granted) {
        status = 'BUDGET_STOPPED'; code = 'BUDGET_EXHAUSTED'; reason = 'recorded spend reached the preregistered ceiling';
        break;
      }
      let sidecarFile = null;
      const sink = write ? (digest, body) => {
        const relative = `evidence/s2-008-campaign/predictions-v${version}-${safeLabel}-${entry.trial_id}-${currentSeed}.json`;
        const absolute = path.join(REPO_ROOT, relative);
        fs.writeFileSync(absolute, `${JSON.stringify(body, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
        sidecarFile = relative;
        if (canonicalDigest(body) !== digest) throw new Error('PREDICTIONS_SIDECAR_DIGEST_MISMATCH');
      } : null;
      let result;
      try {
        result = entry.arm_id === 'arm-model-zai-glm53flash'
          ? await runModel({
            armId: entry.arm_id, seed: currentSeed,
            timeoutMs: version >= 6
              ? prereg.executor.model_launch_timeout.total_container_timeout_ms
              : prereg.budget_reservation.trial_timeout_ms,
            dryRun, pin: activeModelPin, prereg,
            remainingTokens: version >= 5 ? granted - spentUnits : undefined,
            predictionsSink: sink, runLabel: safeLabel,
          })
          : await runRegex({
            armId: entry.arm_id, seed: currentSeed,
            samples: prereg.noise_rule.bootstrap_samples,
            timeoutMs: prereg.budget_reservation.trial_timeout_ms,
            pin: regexPin, predictionsSink: sink, runLabel: safeLabel,
          });
      } catch {
        // An exception may occur after a provider request. No usage report
        // means the spend is unknown, so stop the campaign and publish it.
        const model = entry.arm_id === 'arm-model-zai-glm53flash';
        result = {
          ok: false, launch_unknown: true,
          output: {
            outcome_class: 'INFRA',
            budget: model ? { currency: 'tokens', spent_tokens: 0, unreconciled_spend: true } : null,
            stop: { reason: model ? 'MODEL_EXECUTION_UNRECONCILED' : 'CONTROL_EXECUTION_FAILED' },
          },
          record: {
            arm_id: entry.arm_id, seed: currentSeed,
            payload_error: model ? 'MODEL_EXECUTION_UNRECONCILED' : 'CONTROL_EXECUTION_FAILED',
            real_start: { proven: false },
          },
        };
      }
      if (result.launch_unknown) unknownLaunchAttempts += 1;
      else launches += 1;
      const step = chargingStep({
        currency, spentUnits, grantedUnits: granted,
        armOutput: result.output, armId: entry.arm_id, dispatchableArms,
      });
      if (step.action === 'refuse') {
        status = 'BLOCKED'; code = step.code; reason = step.detail;
        if (result.output?.budget?.unreconciled_spend === true) unreconciledSpend = true;
        perSeed.push({ seed: currentSeed, outcome_class: result.output?.outcome_class ?? 'NOT_RUN', predictions: result.record?.predictions ? { ...result.record.predictions, file: sidecarFile } : null, launch: result.record });
        break;
      }
      spentUnits = step.spent_units;
      charges.push({
        trial: entry.trial_id, arm_id: entry.arm_id, seed: currentSeed,
        units: step.units, unit: step.unit, source: step.source,
        spent_units_after: spentUnits,
      });
      modelCalls += Number(result.output?.executor?.model_calls ?? 0);
      perSeed.push({
        seed: currentSeed, outcome_class: result.output?.outcome_class ?? 'NOT_RUN',
        predictions: result.record?.predictions ? { ...result.record.predictions, file: sidecarFile } : null,
        launch: result.record,
      });
      if (result.output?.budget?.exhausted === true || step.stop) {
        status = 'BUDGET_STOPPED'; code = 'BUDGET_EXHAUSTED'; reason = 'arm or runner reached the preregistered ceiling';
        break;
      }
      if (!result.ok || result.output?.outcome_class === 'INFRA' || result.output?.outcome_class === 'NOT_RUN') {
        status = 'BLOCKED'; code = 'ARM_DID_NOT_COMPLETE'; reason = String(result.output?.stop?.reason ?? result.record?.payload_error ?? 'arm returned no complete measurement');
        break;
      }
    }
    trials.push({ trial_id: entry.trial_id, arm_id: entry.arm_id, seeds: perSeed });
    if (status === 'BLOCKED' || status === 'BUDGET_STOPPED') break;
  }
  const report = {
    kind: campaignKind, status, code, reason,
    label: safeLabel, dry_run: Boolean(dryRun),
    raw_run_id: runId, nonce, base,
    preregistration_digest: prereg.preregistration_digest,
    model_image_pin: { imageId: activeModelPin.first.imageId, digest: activeModelPin.first.digest, content_commitment: activeModelPin.first.content_commitment },
    reservation: { id: prereg.budget_reservation.reservation_id, currency, granted_units: granted },
    spent_units: spentUnits, unreconciled_spend: unreconciledSpend,
    model_calls: modelCalls, launches, unknown_launch_attempts: unknownLaunchAttempts, charges, trials,
  };
  if (write) {
    const target = out ?? path.join(REPO_ROOT, 'evidence/s2-008-campaign', `run-v${version}-${safeLabel}.json`);
    fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  }
  return report;
}

function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const equal = token.indexOf('=');
    if (equal >= 0) {
      const key = token.slice(2, equal).replace(/[-_](\w)/g, (_m, c) => c.toUpperCase());
      args[key] = token.slice(equal + 1);
      continue;
    }
    const key = token.slice(2).replace(/[-_](\w)/g, (_m, c) => c.toUpperCase());
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) args[key] = true;
    else { args[key] = next; index += 1; }
  }
  return args;
}

export function productionPaidRunRefusal({ dryRun = false, label = 'a', write = true } = {}) {
  if (dryRun) return null;
  if (write === false || write === 'false') return { code: 'PAID_RUN_EVIDENCE_REQUIRED', reason: 'production paid runs require durable report and prediction sidecars' };
  if (!['a', 'b'].includes(String(label))) return { code: 'PAID_RUN_LABEL_INVALID', reason: 'production paid runs require the preregistered A or B label' };
  return null;
}

export function campaignCliMode(args = {}) {
  const versions = ['v4', 'v5', 'v6', 'v7', 'v8'].filter((name) => args[name] === true);
  if (versions.length > 1) throw new Error('CAMPAIGN_VERSION_FLAGS_CONFLICT');
  const requestedVersion = versions.length === 0 ? null : Number(versions[0].slice(1));
  return Object.freeze({
    predictionRunner: requestedVersion !== null || Boolean(args.arm && args.dryRun),
    requestedVersion,
  });
}

const args = parseArgs(process.argv);
const cliMode = campaignCliMode(args);
const isEntry = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (!isEntry) {
  // Imported as a library (the independent evaluator imports the interval
  // helper); running a campaign is a decision, not a side effect of an import.
} else if (cliMode.predictionRunner) {
  const label = String(args.label ?? 'a');
  const refusal = productionPaidRunRefusal({ dryRun: args.dryRun === true, label, write: args.write });
  if (refusal) {
    console.log(JSON.stringify({ status: 'BLOCKED', ...refusal, spent_units: 0, launches: 0, charges: [], trials: [] }, null, 2));
    process.exitCode = 4;
  } else {
  const record = await runV4Campaign({
    label,
    expectedVersion: cliMode.requestedVersion,
    arm: typeof args.arm === 'string' ? args.arm : null,
    seed: typeof args.seed === 'string' ? Number(args.seed) : null,
    dryRun: args.dryRun === true,
    write: args.write === 'true' || (args.write !== 'false' && args.dryRun !== true),
    out: typeof args.out === 'string' ? args.out : null,
  });
  console.log(JSON.stringify(record, null, 2));
  if (record.status === 'BLOCKED' || record.status === 'BUDGET_STOPPED') process.exitCode = 4;
  }
} else if (args.verifyPin) {
  console.log(JSON.stringify(verifyImagePin(), null, 2));
} else {
  const record = await runCampaign({
    label: String(args.label ?? 'a'),
    write: args.write === true,
    out: typeof args.out === 'string' ? args.out : null,
  });
  // A refusal is a RESULT, and the entry point has to say so with a non-zero
  // status and nothing but the refusal. Without this the print below would
  // dereference fields a refused run never produced, and the operator would read
  // a TypeError instead of the reason the campaign did not start.
  const entry = entryReportFor(record);
  if (entry.report !== null) {
    console.log(JSON.stringify(entry.report, null, 2));
    process.exitCode = entry.exitCode;
  } else {
  console.log(JSON.stringify({
    raw_run_id: record.raw_run_id,
    commit_sha: record.commit_sha,
    tree_sha: record.tree_sha,
    decision_digest: record.decision_digest,
    adapter: { launches: record.adapter.launches, pin: record.adapter.pin.imageId, real_adapter_provenance: record.adapter.real_adapter_provenance.status },
    ordering: record.ordering,
    metrics: record.metrics,
    trials: record.trials.map((trial) => ({
      trial: trial.trial, arm: trial.arm_id, status: trial.status, outcome: trial.outcome,
      measured: trial.observed, interval: trial.interval ? { lower: trial.interval.lower, upper: trial.interval.upper, method: trial.interval.method } : null,
      reason: trial.decision?.reason ?? null, correction: trial.decision?.correction ? { pUpper: trial.decision.correction.pUpper, threshold: trial.decision.correction.threshold, rejected: trial.decision.correction.rejected, never_rejects: trial.decision.correction.never_rejects } : null,
      verdict: trial.verdict ?? null, seeds: trial.seeds?.length ?? 0,
    })),
    campaign_decision: record.campaign_decision,
    campaign_verdict: record.campaign_verdict,
    counters: record.counters,
    chain_verified: record.registry.chain_verified,
  }, null, 2));
  }
}
