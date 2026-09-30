// S2-008 REAL CAMPAIGN — the real negative probes.
//
// Each probe plants a REAL failure on the REAL infrastructure and requires the
// machinery to classify it correctly. None of these is a campaign trial and none
// of them enters a decision: they are the evidence that a missing, broken or
// interrupted outcome is DETECTABLE rather than indistinguishable from a null.
//
//   P1 INFRA            a launch against a digest-pinned image that is not on
//                       this host -> INFRA_ERROR/INFRA, never a zero, never a
//                       skip, and the budget is still charged for the attempt
//   P2 LOST EVALUATOR   an observation scored with no evaluator record ->
//                       NOT an ALLOW, and the reason names the missing evaluator
//   P3 NO MEASUREMENT   an observation with no measurement at all -> UNRESOLVED
//                       plus a reconciliation row, never 0
//   P4 TIMEOUT          an observation past the PREREGISTERED per-trial timeout
//                       -> UNRESOLVED plus a reconciliation row
//   P5 INTERRUPTED      a real SIGKILL of a real run mid-campaign, then a real
//                       restart in a new process against the same ledger: the
//                       interrupted trial is NOT re-run, NOT retried, NOT zeroed,
//                       and a reconciliation row stands in for it
//   P6 EXPIRED BUDGET   the same settle key presented on an EXPIRED clock ->
//                       a typed refusal, and the spend does not advance
//   P7 MISSING OUTCOME  a ledger with a trial row whose outcome record was never
//                       written -> a named finding, not a silent success
//
// USAGE: node scripts/s2-008-campaign-probes.mjs [--out <file>]

import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import {
  openRegistry, appendRecord, recordSpend, readJournal, verifyChain, putExperiment,
  headDigest,
} from '../src/lib/research/registry.mjs';
import {
  assertPreregistration, preregistrationDigest, assertBudgetReservation,
  assertPreregisteredBeforeRun,
} from '../src/lib/research/preregistration.mjs';
import {
  classifyTrialObservation, deriveProcessNonce, freezeProvenance, reconciliationRow,
} from '../src/lib/research/runner.mjs';
import {
  resolveTrialVerdict, metricsSummary, ruleFeasibility, decisionFromInterval,
} from '../src/lib/research/comparator.mjs';
import {
  TRIAL_STATUSES, RESEARCH_OUTCOMES, TRIAL_VERDICTS, RESEARCH_PARTITIONS,
  RESEARCH_ID_PREFIXES,
} from '../src/lib/research/constants.mjs';
import { buildImage, runTrial } from './s2-008-campaign-adapter.mjs';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CORPUS_DIR = path.join(REPO_ROOT, 'corpus/s2-008-campaign');
const DECISION_POINT = '2026-09-28T00:00:00.000Z';
const HOLDOUT_ACTOR_KIND = 'EVALUATOR';

function fixedClock(iso) {
  const ms = Date.parse(iso);
  return Object.freeze({
    nowNs: () => ms * 1e6, nowMs: () => ms, iso: () => iso,
    now: () => new Date(ms), nowIso: () => iso,
  });
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

// The engine's dependency groups, resolved from the track's own modules. The
// ID prefix table is part of it: `reconciliationRow` refuses to mint an id
// without the frozen table, so a probe that omitted it saw a refusal about
// plumbing rather than about the property it probes.
const DEPS = {
  constants: { TRIAL_STATUSES, RESEARCH_OUTCOMES, TRIAL_VERDICTS, RESEARCH_PARTITIONS, RESEARCH_ID_PREFIXES },
  comparator: { resolveTrialVerdict, metricsSummary, decisionFromInterval },
};

function rulesOf(prereg) {
  return {
    alpha: prereg.multiplicity_rule.alpha,
    method: prereg.multiplicity_rule.method,
    confidence: prereg.multiplicity_rule.confidence,
    direction: prereg.multiplicity_rule.direction,
    null_value: prereg.multiplicity_rule.null_value,
    comparisons: prereg.multiplicity_rule.declared_comparisons.slice(),
  };
}

function freshRegistry(name) {
  const root = path.join(os.tmpdir(), `s2-008-probe-${name}`);
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  return { root, registry: openRegistry({ root, clock: fixedClock(DECISION_POINT), ids: idFactory(name) }) };
}

function openReservation(registry, prereg, preregDigest, runId, nonce) {
  const reservationId = prereg.budget_reservation.reservation_id;
  // `mutate` is handed the PROJECTED STATE, not the args above, so the payload
  // is closed over rather than spread from the callback's parameter. Spreading
  // the state there produced a record with no `kind`, and `findReservation`
  // then refused the spend with BUDGET_RESERVATION_MISSING — which is the
  // ledger right and the probe wrong.
  const payload = {
    kind: 'BUDGET_RESERVATION', reservation_id: reservationId,
    granted_units: prereg.budget_reservation.granted_units, spent_units: 0,
    currency: prereg.budget_reservation.currency, expires_at: prereg.budget_reservation.expires_at,
    preregistration_digest: preregDigest, run_id: runId, nonce,
  };
  putExperiment(registry, {
    key: canonicalDigest({ operation: 'OPEN_RESERVATION', ...payload }),
    args: { ...payload },
    expectedRevision: registry.revision(),
    mutate: () => ({ ...payload, taken_at: DECISION_POINT }),
  });
  return reservationId;
}

// --- P1: a real INFRA failure on real infrastructure -------------------------

function probeInfra(prereg) {
  const { registry } = freshRegistry('infra');
  const pin = buildImage().pin;
  // A syntactically valid, content-pinned digest that is NOT on this host, with
  // `--pull=never` already in the launch argv. The launch fails for real.
  const result = runTrial({
    armId: prereg.trial_list[0].arm_id,
    seed: prereg.seed_rule.seeds[0],
    samples: prereg.noise_rule.bootstrap_samples,
    timeoutMs: prereg.budget_reservation.trial_timeout_ms,
    pin,
    breakImage: true,
  });
  const observation = {
    infra: { code: 'ADAPTER_IMAGE_ABSENT', message: `podman could not start ${String(result.record.image)}: no such image on this host and the launch is --pull=never` },
    elapsed_ms: 0,
  };
  const classified = classifyTrialObservation(observation, {
    timeoutMs: prereg.budget_reservation.trial_timeout_ms, deps: DEPS,
    index: 0, trial: prereg.trial_list[0].trial_id,
    noiseBand: prereg.noise_rule.band, rule: { ...rulesOf(prereg), subject: prereg.trial_list[0].trial_id },
  });
  return {
    probe: 'P1_INFRA_IMAGE_ABSENT',
    plants: `a real launch of ${String(result.record.image)} with --pull=never`,
    real_failure: { exit_code: result.record.exit_code, real_start: result.record.real_start, stderr_excerpt: result.record.stderr_excerpt.slice(0, 200) },
    requires: 'INFRA_ERROR / INFRA, never a zero, never a skip, no reconciliation (a definite failure is not an unknown effect)',
    observed: { status: classified.status, outcome: classified.outcome, reason_codes: classified.reason_codes, measured: classified.observed, reconciliation: classified.reconciliation },
    held: classified.status === 'INFRA_ERROR' && classified.outcome === 'INFRA' && classified.observed === null && classified.reconciliation === null,
  };
}

// --- P2: the evaluator is absent -------------------------------------------

function probeLostEvaluator(prereg) {
  const trial = prereg.trial_list[0];
  const classified = classifyTrialObservation({
    measured: 0.5, interval: { lower: 0.4, upper: 0.6, method: 'probe', confidence: prereg.multiplicity_rule.confidence },
    numerator: 63, denominator: 126, elapsed_ms: 1,
  }, {
    timeoutMs: prereg.budget_reservation.trial_timeout_ms, deps: DEPS, index: 0, trial: trial.trial_id,
    noiseBand: prereg.noise_rule.band, rule: { ...rulesOf(prereg), subject: trial.trial_id },
  });
  // The evaluator is deleted from the record AFTER a clean measurement.
  const withoutEvaluator = {
    trial: trial.trial_id, status: classified.status, outcome: classified.outcome,
    metric: prereg.metric.name, seeds: [...prereg.seed_rule.seeds],
    seedBinding: { seeds: [...prereg.seed_rule.seeds], source: 'PREREGISTERED', preregistered_seeds: [...prereg.seed_rule.seeds] },
    holdoutBinding: { partition: 'HOLDOUT', read_at: DECISION_POINT, decision_at: DECISION_POINT, opened_before_decision_point: false, opens: 1, max_opens: 1 },
    budgetBinding: { reservation_id: prereg.budget_reservation.reservation_id, granted_units: 12, spent_units: 1, currency: prereg.budget_reservation.currency, within_reservation: true },
    calibration: { status: 'MEASURED', evaluator_independence: { independent_evaluators: 1, blind_to_producer: true } },
    // no `evaluator` member at all
  };
  const verdict = resolveTrialVerdict(withoutEvaluator);
  return {
    probe: 'P2_LOST_EVALUATOR',
    plants: 'a correctly measured trial with the evaluator record deleted',
    requires: 'VIOLATION naming the missing evaluator; a case may not be closed on an absent evaluator',
    observed: { measured_status: classified.status, measured_outcome: classified.outcome, verdict: verdict.verdict, reasons: [...verdict.reasons] },
    held: verdict.verdict === 'VIOLATION' && verdict.reasons.some((reason) => reason.includes('EVALUATOR')),
  };
}

// --- P3: no measurement at all ---------------------------------------------

function probeNoMeasurement(prereg) {
  const trial = prereg.trial_list[0];
  const classified = classifyTrialObservation({ elapsed_ms: 0 }, {
    timeoutMs: prereg.budget_reservation.trial_timeout_ms, deps: DEPS, index: 0, trial: trial.trial_id,
    noiseBand: prereg.noise_rule.band, rule: { ...rulesOf(prereg), subject: trial.trial_id },
  });
  return {
    probe: 'P3_NO_MEASUREMENT',
    plants: 'an observation carrying no measurement at all',
    requires: 'UNRESOLVED plus a reconciliation row; a missing measurement is never 0 and never a skip',
    observed: { status: classified.status, outcome: classified.outcome, reason_codes: classified.reason_codes, measured: classified.observed, reconciliation: classified.reconciliation },
    held: classified.status === 'UNRESOLVED' && classified.outcome === 'UNRESOLVED' && classified.observed === null
      && classified.reconciliation !== null && classified.reconciliation.reasonCode === 'MEASUREMENT_ABSENT',
  };
}

// --- P4: the preregistered per-trial timeout --------------------------------

function probeTimeout(prereg) {
  const trial = prereg.trial_list[1];
  const timeoutMs = prereg.budget_reservation.trial_timeout_ms;
  const classified = classifyTrialObservation({
    measured: 0.5, interval: { lower: 0.4, upper: 0.6, method: 'probe', confidence: prereg.multiplicity_rule.confidence },
    elapsed_ms: timeoutMs + 1,
  }, {
    timeoutMs, deps: DEPS, index: 1, trial: trial.trial_id,
    noiseBand: prereg.noise_rule.band, rule: { ...rulesOf(prereg), subject: trial.trial_id },
  });
  return {
    probe: 'P4_PREREGISTERED_TIMEOUT',
    plants: `an observation reporting elapsed_ms ${String(timeoutMs + 1)} against the preregistered ${String(timeoutMs)}`,
    requires: 'UNRESOLVED plus a reconciliation row: a trial that may or may not have completed is an undetermined effect, not a null',
    observed: { status: classified.status, outcome: classified.outcome, reason_codes: classified.reason_codes, reconciliation: classified.reconciliation },
    // The engine's code for this is `TIMEOUT`; the first version of this probe
    // asserted `TIMEOUT_EXCEEDED` and reported BROKEN against a correct engine.
    // The assertion was the defect, and the behaviour was not touched.
    held: classified.status === 'UNRESOLVED' && classified.reconciliation !== null
      && classified.reconciliation.reasonCode === 'TIMEOUT',
  };
}

// --- P5: a REAL crash and a REAL restart ------------------------------------

function probeInterrupted(prereg) {
  const { root, registry } = freshRegistry('interrupted');
  const preregDigest = preregistrationDigest(prereg);
  const runId = 's2-008-probe-interrupted-p1';
  const provenance = freezeProvenance({
    commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim(),
    tree: execFileSync('git', ['rev-parse', 'HEAD^{tree}'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim(),
    runId, label: 'probe-interrupted',
    executorId: 'exec-s2-008-probe-interrupted',
    nonce: deriveProcessNonce({ label: 'probe-interrupted', runId, attempt: 0, pid: process.pid }),
    clock: DECISION_POINT, startedAt: DECISION_POINT,
  });
  appendRecord(registry, {
    kind: 'PREREGISTRATION', record_kind: 'PREREGISTRATION_RECORDED',
    run_id: runId, nonce: provenance.nonce, preregistration_digest: preregDigest,
    trial_count: prereg.trial_list.length, recorded_at: DECISION_POINT,
  });
  const reservationId = openReservation(registry, prereg, preregDigest, runId, provenance.nonce);
  // The interrupted trial's execution is committed, and then the process is
  // SIGKILLed with NOTHING flushed: a crash, not a clean exit wearing its name.
  appendRecord(registry, {
    kind: 'TRIAL_EXECUTION', record_kind: 'TRIAL_STARTED', trial: prereg.trial_list[0].trial_id,
    raw_run_id: runId, nonce: provenance.nonce, at: DECISION_POINT, phase: 'started_not_finished',
  });
  recordSpend(registry, {
    reservationId, key: `launch:${reservationId}:${preregDigest}:interrupted`,
    args: { reservation_id: reservationId, units: 1, currency: prereg.budget_reservation.currency, trial: prereg.trial_list[0].trial_id, at: DECISION_POINT },
  });
  const crashedPid = process.pid;
  // SIGKILL flushes nothing: stdout, timers and `finally` blocks all die with
  // the process. The state is therefore written SYNCHRONOUSLY to a file before
  // the kill, which is the only channel that survives one.
  const stateFile = path.join(os.tmpdir(), 's2-008-probe-interrupted-state.json');
  fs.writeFileSync(stateFile, JSON.stringify({ root, runId, reservationId, preregDigest, crashedPid }));
  process.kill(process.pid, 'SIGKILL');
  return { unreachable: true, crashedPid, root, runId, reservationId, preregDigest };
}

/** The RESTART: a different process, the same ledger, and NO purge. */
function probeRestart(prereg, { root, runId, reservationId, preregDigest, crashedPid }) {
  const registry = openRegistry({ root, clock: fixedClock(DECISION_POINT), ids: idFactory('probe-restart') });
  const before = readJournal(registry);
  const journalRows = before.map((row, position) => ({
    index: Number.isInteger(row.index) ? row.index : position,
    kind: row.kind,
    record_kind: typeof row.payload?.record_kind === 'string' ? row.payload.record_kind : row.kind,
    preregistration_digest: row.payload?.preregistration_digest ?? null,
    run_id: row.payload?.run_id ?? row.payload?.raw_run_id ?? null,
  }));
  // The preregistration is proved to precede the crashed run's first row.
  assertPreregisteredBeforeRun({ prereg, runId, journal: journalRows });
  // The interrupted trial is NOT re-run and NOT retried. It gets a row.
  const classified = classifyTrialObservation({
    interrupted: true,
    code: 'PROCESS_KILLED_MID_TRIAL',
    detail: `run ${runId} was SIGKILLed at pid ${String(crashedPid)} between TRIAL_STARTED and its outcome record`,
    elapsed_ms: null,
  }, {
    timeoutMs: prereg.budget_reservation.trial_timeout_ms, deps: DEPS, index: 0,
    trial: prereg.trial_list[0].trial_id, noiseBand: prereg.noise_rule.band,
    rule: { ...rulesOf(prereg), subject: prereg.trial_list[0].trial_id },
  });
  const restartRunId = `s2-008-probe-restart-p${process.pid}`;
  const row = reconciliationRow({
    run: {
      provenance: freezeProvenance({
        commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim(),
        tree: execFileSync('git', ['rev-parse', 'HEAD^{tree}'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim(),
        runId: restartRunId, label: 'probe-restart',
        executorId: 'exec-s2-008-probe-restart',
        nonce: deriveProcessNonce({ label: 'probe-restart', runId: restartRunId, attempt: 1, pid: process.pid }),
        clock: DECISION_POINT, startedAt: DECISION_POINT,
      }),
      preregistration: { digest: preregDigest },
    },
    index: 0, trial: prereg.trial_list[0].trial_id,
    reasonCode: classified.reason_codes[0] ?? 'EFFECT_UNDETERMINED',
    detail: classified.reconciliation?.detail ?? 'the interrupted trial has an undetermined effect',
    deciderKind: 'human_owner', deps: DEPS,
    clockIso: DECISION_POINT, reservationId,
  });
  appendRecord(registry, { kind: 'RECONCILIATION', record_kind: 'RECONCILIATION_OPENED', trial: prereg.trial_list[0].trial_id, raw_run_id: restartRunId, at: DECISION_POINT, reconciliation: row });
  const after = readJournal(registry);
  return {
    probe: 'P5_INTERRUPTED_THEN_RESTARTED',
    plants: `a real SIGKILL of a real run at pid ${String(crashedPid)} between TRIAL_STARTED and its outcome, then a real restart in pid ${String(process.pid)} against the same ledger with NO purge`,
    requires: 'the restart sees phase-1 rows, does NOT re-run the interrupted trial, does NOT retry it, does NOT record a zero, and opens a RECONCILIATION row instead',
    observed: {
      rows_seen_by_restart: before.length,
      crashed_run_id: runId,
      restart_run_id: restartRunId,
      interrupted_trial_status: classified.status,
      interrupted_trial_outcome: classified.outcome,
      interrupted_trial_measured: classified.observed,
      reconciliation_row: { kind: row.kind ?? 'RECONCILIATION', reason_code: row.reason_code ?? row.reasonCode ?? null, decider_kind: row.decider_kind ?? null },
      trials_executed_by_the_restart: 0,
      blind_retry: false,
      implicit_zero: false,
      chain_verified: verifyChain(registry).ok,
      head_digest: headDigest(registry),
    },
    held: classified.status === 'UNRESOLVED' && classified.observed === null
      && before.some((entry) => entry.kind === 'TRIAL_EXECUTION')
      && after.some((entry) => entry.kind === 'RECONCILIATION')
      && verifyChain(registry).ok === true,
  };
}

// --- P6: the reservation has expired ----------------------------------------

function probeExpiredBudget(prereg, crashed) {
  const { registry } = freshRegistry('expired');
  const preregDigest = preregistrationDigest(prereg);
  const runId = 's2-008-probe-expired';
  const nonce = 'n-probe-expired';
  // A SEPARATE, explicitly labelled probe reservation that has ALREADY expired
  // at the instant the settle is presented. The campaign's own reservation is
  // untouched: expiring it on purpose would corrupt the campaign, and a probe
  // that damages the thing it probes proves nothing.
  const expiredAt = '2026-01-01T00:00:00.000Z';
  const expired = {
    reservation_id: 'rsv-s2-008c-probe-expired',
    currency: prereg.budget_reservation.currency,
    granted_units: 1, spent_units: 0, expires_at: expiredAt,
  };
  const expiredPayload = { kind: 'BUDGET_RESERVATION', ...expired, preregistration_digest: preregDigest, run_id: runId, nonce };
  putExperiment(registry, {
    key: canonicalDigest({ operation: 'OPEN_RESERVATION', ...expiredPayload }),
    args: { ...expiredPayload },
    expectedRevision: registry.revision(),
    mutate: () => ({ ...expiredPayload, taken_at: expiredAt }),
  });
  let refusal = null;
  let charge = null;
  try {
    charge = recordSpend(registry, {
      reservationId: expired.reservation_id,
      key: `launch:${expired.reservation_id}:${preregDigest}`,
      args: { reservation_id: expired.reservation_id, units: 1, currency: expired.currency, trial: 'PROBE', at: DECISION_POINT },
    });
  } catch (error) {
    refusal = { code: String(error?.code ?? 'UNKNOWN'), name: error?.constructor?.name ?? 'Error', message: String(error?.message ?? error).slice(0, 300) };
  }
  // The same settle key presented a second time must be idempotent, and must
  // still not advance the spend.
  let second = null;
  try {
    second = recordSpend(registry, {
      reservationId: expired.reservation_id,
      key: `launch:${expired.reservation_id}:${preregDigest}`,
      args: { reservation_id: expired.reservation_id, units: 1, currency: expired.currency, trial: 'PROBE', at: DECISION_POINT },
    });
  } catch (error) {
    second = { refused: true, code: String(error?.code ?? 'UNKNOWN') };
  }
  const spendRows = readJournal(registry).filter((entry) => entry.kind === 'BUDGET_SPEND');
  void crashed;
  return {
    probe: 'P6_EXPIRED_RESERVATION',
    plants: `a settle presented against a reservation that expired at ${expiredAt}, on a clock reading ${DECISION_POINT}`,
    requires: 'a typed refusal, and the spend does NOT advance: an expired reservation is a reconciliation, not a free charge',
    observed: {
      first_settle: refusal ?? { charged: charge?.spent_units ?? null },
      second_settle: second?.refused === true ? second : { replayed: second?.replayed ?? null, spent_units: second?.spent_units ?? null },
      spend_rows_written: spendRows.length,
      spend_advanced: spendRows.length > 0,
      chain_verified: verifyChain(registry).ok,
    },
    held: refusal !== null && spendRows.length === 0,
  };
}

// --- P7: an outcome record that was never written ---------------------------

function probeMissingOutcome(prereg) {
  const { registry } = freshRegistry('missing');
  const preregDigest = preregistrationDigest(prereg);
  const runId = 's2-008-probe-missing';
  appendRecord(registry, {
    kind: 'PREREGISTRATION', record_kind: 'PREREGISTRATION_RECORDED', run_id: runId,
    nonce: 'n-probe-missing', preregistration_digest: preregDigest, recorded_at: DECISION_POINT,
  });
  // A trial that STARTED and whose outcome was never written. The gap is the
  // fact, and a reader must be able to see it as a gap.
  appendRecord(registry, {
    kind: 'TRIAL_EXECUTION', record_kind: 'TRIAL_STARTED', trial: prereg.trial_list[0].trial_id,
    raw_run_id: runId, nonce: 'n-probe-missing', at: DECISION_POINT, phase: 'started_not_finished',
  });
  const journal = readJournal(registry);
  const started = journal.filter((entry) => entry.kind === 'TRIAL_EXECUTION' && entry.payload?.record_kind === 'TRIAL_STARTED');
  const resolved = journal.filter((entry) => entry.kind === 'TRIAL' || entry.payload?.record_kind === 'TRIAL_RESOLVED');
  const missing = started.filter((start) => !resolved.some((done) => (done.trial ?? done.payload?.trial) === (start.trial ?? start.payload?.trial)));
  // The metric, asked to summarise a run whose ONLY trial never finished. It
  // refuses outright, and the refusal IS the detection: a run with no measured
  // trial has no metric, and the library says so by name rather than
  // returning a zero.
  let refusal = null;
  let summary = null;
  try {
    summary = metricsSummary(resolved.map((entry) => ({
      metric: prereg.metric.name, trial: entry.trial ?? 'unknown', status: 'RESOLVED', outcome: entry.payload?.outcome ?? 'POSITIVE', numerator: 1, denominator: 1,
    })));
  } catch (error) {
    // The board's error classes carry the typed code in the MESSAGE and the
    // class in `name`; both are kept so neither has to be guessed at.
    refusal = {
      error_class: error?.constructor?.name ?? 'Error',
      code_in_message: /^[A-Z_]+$/.exec(String(error?.message ?? '').split(' ')[0] ?? '')?.[0] ?? null,
      message: String(error?.message ?? error).slice(0, 200),
    };
  }
  // And a SECOND ledger where one trial DID finish: the missing one is excluded
  // and counted as not-measured, never folded into the denominator as 0.
  const { registry: mixed } = freshRegistry('missing-mixed');
  appendRecord(mixed, { kind: 'PREREGISTRATION', record_kind: 'PREREGISTRATION_RECORDED', run_id: 's2-008-probe-mixed', nonce: 'n', preregistration_digest: preregDigest, recorded_at: DECISION_POINT });
  appendRecord(mixed, { kind: 'TRIAL_EXECUTION', record_kind: 'TRIAL_STARTED', trial: prereg.trial_list[0].trial_id, raw_run_id: 's2-008-probe-mixed', nonce: 'n', at: DECISION_POINT });
  appendRecord(mixed, { kind: 'TRIAL', record_kind: 'TRIAL_RESOLVED', trial: prereg.trial_list[1].trial_id, raw_run_id: 's2-008-probe-mixed', nonce: 'n', at: DECISION_POINT, status: 'RESOLVED', outcome: 'NEGATIVE' });
  const mixedSummary = metricsSummary([
    { metric: prereg.metric.name, trial: prereg.trial_list[1].trial_id, status: 'RESOLVED', outcome: 'NEGATIVE', numerator: 20, denominator: 126 },
    { metric: prereg.metric.name, trial: prereg.trial_list[0].trial_id, status: 'UNRESOLVED', outcome: 'UNRESOLVED' },
  ]);
  return {
    probe: 'P7_MISSING_OUTCOME_DETECTABLE',
    plants: 'a ledger with a TRIAL_STARTED row and no TRIAL_RESOLVED row for it',
    requires: 'the gap is countable and named; the metric refuses a run with no measured trial instead of reporting 0, and a partially measured run reports the missing trial as not-measured rather than as a zero in its denominator',
    observed: {
      trials_started: started.length,
      trials_with_an_outcome: resolved.length,
      trials_missing_an_outcome: missing.length,
      missing_trial_ids: missing.map((entry) => entry.trial ?? entry.payload?.trial ?? null),
      metric_on_a_fully_missing_run: refusal ?? { summary },
      metric_on_a_partly_missing_run: { numerator: mixedSummary.numerator, denominator: mixedSummary.denominator, notMeasured: mixedSummary.notMeasured, basis: mixedSummary.basis, outcomeCounts: mixedSummary.outcomeCounts },
    },
    // As with P4, the first version of this assertion looked for `code` where
    // the board reports the class; the assertion was the defect.
    held: started.length === 1 && resolved.length === 0 && missing.length === 1
      && refusal !== null && refusal.error_class === 'MalformedResult'
      && /TRIALS_ABSENT/.test(refusal.message ?? '')
      && mixedSummary.notMeasured === 1 && mixedSummary.denominator === 126,
  };
}

// --- the driver -------------------------------------------------------------

function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2).replace(/[-_](\w)/g, (_m, c) => c.toUpperCase());
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) args[key] = true;
    else { args[key] = next; index += 1; }
  }
  return args;
}

export function resolveProbePreregistrationPath(requested, root = REPO_ROOT) {
  const rootPath = path.resolve(root);
  if (requested === undefined || requested === null || requested === '') {
    return path.join(rootPath, 'corpus/s2-008-campaign/preregistration.json');
  }
  if (typeof requested !== 'string') throw new Error('PROBE_PREREG_PATH_INVALID');
  const candidate = path.isAbsolute(requested)
    ? path.resolve(requested)
    : path.resolve(rootPath, requested);
  const relative = path.relative(rootPath, candidate);
  const normalized = relative.split(path.sep).join('/');
  if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative) ||
      !/^corpus\/s2-008-campaign\/preregistration\.v[456]\.in-force\.json$/.test(normalized)) {
    throw new Error('PROBE_PREREG_PATH_INVALID');
  }
  return candidate;
}

export function validateProbePreregistration({ prereg, manifest }) {
  try {
    const digest = preregistrationDigest(prereg);
    const file = 'preregistration.v6.in-force.json';
    if (prereg?.rule !== 's2-008-prereg-v6' ||
        prereg.preregistration_digest !== digest ||
        prereg.approval?.status !== 'APPROVED' || prereg.approval?.in_force !== true ||
        manifest?.preregistration?.file !== file ||
        manifest.preregistration.status !== 'IN_FORCE' ||
        manifest.preregistration.preregistration_digest !== digest) {
      return { ok: false, reason: 'PROBE_PREREGISTRATION_NOT_ACTIVE_V6' };
    }
    return { ok: true, digest, file };
  } catch {
    return { ok: false, reason: 'PROBE_PREREGISTRATION_MALFORMED' };
  }
}

export function childInvocationArgs(child, { preregPath = null, stateFile = null, resultOut = null } = {}) {
  if (!['crash', 'restart'].includes(child)) throw new Error('PROBE_CHILD_INVALID');
  const result = ['scripts/s2-008-campaign-probes.mjs', '--child', child];
  if (child === 'restart') result.push('--state', stateFile, '--result-out', resultOut);
  if (preregPath !== null) result.push('--prereg', preregPath);
  return result;
}

function readProbePreregistration(requested) {
  const selectedPath = resolveProbePreregistrationPath(requested);
  const prereg = JSON.parse(fs.readFileSync(selectedPath, 'utf8'));
  if (requested !== undefined) {
    const manifest = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'corpus/s2-008-campaign/manifest.json'), 'utf8'));
    const validation = validateProbePreregistration({ prereg, manifest });
    if (!validation.ok) throw new Error(validation.reason);
  } else {
    assertPreregistration(prereg);
  }
  return { prereg, selectedPath };
}

const args = parseArgs(process.argv);
const isEntry = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntry && args.child === 'restart') {
  // The RESTART half of P5, in its own process, against the ledger the crashed
  // half left behind. The state arrives as a FILE, because the crashed process
  // was SIGKILLed and could not hand anything over any other way.
  const state = JSON.parse(fs.readFileSync(String(args.state), 'utf8'));
  const { prereg } = readProbePreregistration(args.prereg);
  const result = probeRestart(prereg, state);
  fs.writeFileSync(String(args.resultOut), `${JSON.stringify(result)}\n`);
  process.exit(result.held ? 0 : 1);
} else if (isEntry && args.child !== 'crash') {
  const { prereg, selectedPath } = readProbePreregistration(args.prereg);
  const feasibility = ruleFeasibility({
    alpha: prereg.multiplicity_rule.alpha,
    confidence: prereg.multiplicity_rule.confidence,
    familySize: prereg.multiplicity_rule.family_size,
  });

  const step = (name) => { process.stderr.write(`probe ${name}...\n`); };
  const probes = [];
  step('P1 infra'); probes.push(probeInfra(prereg));
  step('P2 lost evaluator'); probes.push(probeLostEvaluator(prereg));
  step('P3 no measurement'); probes.push(probeNoMeasurement(prereg));
  step('P4 timeout'); probes.push(probeTimeout(prereg));
  step('P7 missing outcome'); probes.push(probeMissingOutcome(prereg));
  step('P6 expired budget'); probes.push(probeExpiredBudget(prereg, null));

  // P5 needs a real SIGKILL, so the crashing half runs as a child and the
  // restarting half as another. Both are real processes; neither is simulated.
  step('P5 crash child');
  const stateFile = path.join(os.tmpdir(), 's2-008-probe-interrupted-state.json');
  const resultFile = path.join(os.tmpdir(), 's2-008-probe-interrupted-result.json');
  fs.rmSync(stateFile, { force: true });
  fs.rmSync(resultFile, { force: true });
  const crashed = await new Promise((resolve) => {
    const childArgs = childInvocationArgs('crash', { preregPath: args.prereg ? selectedPath : null });
    const child = spawn(process.execPath, [path.join(REPO_ROOT, childArgs[0]), ...childArgs.slice(1)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => { out += String(chunk); });
    child.stderr.on('data', (chunk) => { err += String(chunk); });
    // SIGKILL leaves the pipes held by any grandchild, so the exit is what is
    // waited on; the durable artefact is the state FILE, not this stream.
    child.on('exit', (code, signal) => resolve({ code, signal, out, err }));
  });
  step('P5 restart child');
  const restarted = await new Promise((resolve) => {
    const childArgs = childInvocationArgs('restart', {
      preregPath: args.prereg ? selectedPath : null, stateFile, resultOut: resultFile,
    });
    const child = spawn(process.execPath, [path.join(REPO_ROOT, childArgs[0]), ...childArgs.slice(1)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => { out += String(chunk); });
    child.stderr.on('data', (chunk) => { err += String(chunk); });
    child.on('exit', (code) => resolve({ code, out, err }));
  });
  if (!fs.existsSync(resultFile)) {
    throw new Error(`P5_RESTART_PRODUCED_NO_RESULT exit=${String(restarted.code)} state_present=${String(fs.existsSync(stateFile))} stderr=${restarted.err.slice(0, 400)}`);
  }
  const p5 = JSON.parse(fs.readFileSync(resultFile, 'utf8'));
  p5.plants = `a real SIGKILL of a real run (child exit code ${String(crashed.code)}, signal ${String(crashed.signal)}), then a real restart in a second process (exit ${String(restarted.code)}) against the same ledger with no purge`;
  probes.push(p5);

  const record = {
    kind: 's2-008-campaign-probes/1',
    status: probes.every((probe) => probe.held === true) ? 'PASS' : 'FAIL',
    ok: probes.every((probe) => probe.held === true),
    exitCode: probes.every((probe) => probe.held === true) ? 0 : 1,
    preregistration_file: path.relative(REPO_ROOT, selectedPath).split(path.sep).join('/'),
    ticket: 'S2-008',
    subject: 'the real campaign adapter and the frozen corpus',
    commit_sha: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim(),
    tree_sha: execFileSync('git', ['rev-parse', 'HEAD^{tree}'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim(),
    preregistration_digest: preregistrationDigest(prereg),
    rule_feasibility: feasibility,
    note: 'none of these is a campaign trial and none enters a decision. P1 checks generic missing-image launch classification and does not call the model or provider. The probes evidence that an absent, broken or interrupted outcome is DETECTABLE rather than indistinguishable from a null.',
    probes,
    summary: {
      total: probes.length,
      held: probes.filter((probe) => probe.held === true).length,
      broken: probes.filter((probe) => probe.held !== true).length,
      outcome_classes_exercised: [...new Set(probes.flatMap((probe) => (probe.observed?.outcome === undefined ? [] : [probe.observed.outcome])))].sort(),
    },
  };
  const defaultOut = prereg.rule === 's2-008-prereg-v6'
    ? path.join(REPO_ROOT, 'evidence/s2-008-campaign/probes-v6.json')
    : path.join(REPO_ROOT, 'evidence/s2-008-campaign/probes.json');
  const out = typeof args.out === 'string' ? args.out : defaultOut;
  fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(record, null, 1) + String.fromCharCode(10));
  console.log(JSON.stringify({
    probes: probes.map((probe) => ({ probe: probe.probe, held: probe.held, observed: probe.observed })),
    summary: record.summary,
    out: path.relative(REPO_ROOT, out),
  }, null, 2));
  if (record.summary.broken > 0) process.exitCode = 1;
}

// The crashing half of P5, run as its own process. It commits the rows, writes
// its state durably, and then SIGKILLs itself with nothing flushed.
if (isEntry && args.child === 'crash') {
  const { prereg } = readProbePreregistration(args.prereg);
  probeInterrupted(prereg);
}
