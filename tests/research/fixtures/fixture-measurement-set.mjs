// The DETERMINISTIC MEASUREMENT SET: eight cases, four trials, two clean runs.
//
// WHAT THIS IS: a hand-authored observational case set and the per-case
// agreement LABEL each of the three measured trials observed, plus the one
// trial that is an INFRA failure. The labels are chosen so the campaign holds
// a known effect (7 of 8 cases agree), a known null (6 of 8, exactly the
// frozen baseline) and a known negative (5 of 8), pooling to 18 agreements over
// 24 cases — that is the "known effect, known null, known negative,
// infra-failure variant" the ticket asks for — and every interval is computed
// with the FROZEN `wilsonInterval` from `src/lib/sloqual/statistics.mjs`,
// never by a second statistics implementation here.
//
// WHY ALL VALUES ARE EXACT BINARY FRACTIONS
// A per-case agreement label is 0 or 1, so a trial's rate is k/8 and every
// value is a dyadic rational: represented exactly by IEEE-754 doubles, so no
// comparison in a test can turn on a rounding artefact, and the same bytes are
// produced on every host. A fixture built on 0.1 + 0.2 would be one whose
// "known" result depends on the rounding mode.
//
// WHY THE LABELS ARE BINARY AND WHY THE COUNTS ARE THE LINK
// The per-case observation is an agreement LABEL (did the case bind correctly:
// 1 or 0), so a trial reports an integer `numerator` over `denominator` 8.
// Those integers are the ONLY thing that links the hand-authored cases to the
// frozen table (`src/lib/research/expected-values.mjs` pins 7/8, 6/8 and 5/8),
// and `assertMeasurementAgreesWithTable` checks the link at IMPORT. An earlier
// version of this fixture used graded per-case RATES, which placed three
// bootstrap intervals neatly in three different regions but produced a mean of
// 5.125/8 on the negative trial — a numerator the frozen table does not accept.
// Every clean run therefore scored findings against the table, and an
// "expected_value_findings: NON_EMPTY" control had no clean state to flip
// FROM: a negative control whose "before" already fails proves nothing. The
// frozen table is the authority, so the data was rebuilt to match it.
//
// WHAT THE DESIGN IS, AND WHAT THE FROZEN RULE ACTUALLY DERIVES
// The corpus is DESIGNED so trial 1 sits above the frozen baseline, trial 2
// sits on it and trial 3 sits below it. That design is what the table pins.
//
// It is NOT what a 95% interval can resolve at this corpus size, and the
// fixture says so instead of hiding it: with eight cases the Wilson interval on
// 7/8 is [0.529, 0.978], on 6/8 [0.409, 0.929] and on 5/8 [0.306, 0.863] — all
// three straddle the frozen 0.75 baseline outside the 0.02 band, so
// `decisionFromInterval` derives UNRESOLVED for all three. Every trial record
// therefore carries BOTH `outcome` (the design the table scores) and
// `derived_outcome` + `derived_reason` (what the frozen rule derived from the
// interval computed here), and `FIXTURE_DERIVED_DISAGREEMENTS` names every
// trial where the two differ. `scripts/s2-008-harness.mjs` records the same
// disagreement in the run evidence; a fixture that hid it would be the one
// artefact in the track where an UNRESOLVED result was laundered into a
// designed one.
//
// WHAT THE NULL TRIAL IS NOT
// The null trial's POINT ESTIMATE is the frozen baseline itself: 6/8 = 0.75,
// not "a small positive effect that happens to look small". It is a null by
// construction rather than by a threshold applied after the fact.
//
// WHAT THE INFRA TRIAL IS NOT
// It is NOT a zero, NOT a skip and NOT a null. It produced no measurement at
// all: `samples: null`, `numerator: null`, `denominator: null`, and a
// reconciliation row that says what must happen next. `not_measured: true` sits
// next to the row precisely so that a consumer cannot read `numerator: 0` off
// it. The stopping rule calls for a reconciliation and forbids the blind
// retry.
//
// LATENCY
// `latency_ms` is a per-trial SYNTHETIC wall-clock sample, flagged as such in
// every record that carries it (`latency_source: FIXTURE_SYNTHETIC`,
// `latency_decides: false`). The ticket requires latency to be MEASURED but
// never to decide, so the fixture supplies one well-formed sample per trial —
// `latency_ms` is the only spelling `latencyRecorded` reads — while marking
// that it decides nothing. A harness that reports these numbers as a
// measurement has mislabelled its own evidence, which the flag makes visible.
//
// Serves: A2 (fail-closed comparator, a missing/unmeasured trial is a
// VIOLATION), A3 (the frozen table is scored by trial index), A4 (ground truth
// here is declared observational, so a causal label is visibly
// unsupported) and the ticket's "negative, null and infra results are kept as
// first-class outcomes".
import { wilsonInterval } from '../../../src/lib/sloqual/statistics.mjs';
import { RESEARCH_HARD_GATE_COUNTERS } from '../../../src/lib/research/constants.mjs';
import { EXPECTED_TRIAL_DECISIONS, expectedTableDigest } from '../../../src/lib/research/expected-values.mjs';
import { decisionFromInterval, metricsSummary } from '../../../src/lib/research/comparator.mjs';
import { fixtureDigest } from './fixture-digest.mjs';
import { FIXED_CLOCK, FIXED_INSTANT_ISO } from './fixture-fixed-clock.mjs';
import { ALLOWED_PROCESS_DIFFERENCES, RUN_LABELS, fixtureRunIdentity } from './fixture-run-identity.mjs';
import {
  BUDGET_RESERVATION,
  CALIBRATIONS,
  FROZEN_BASELINE,
  PREREGISTERED_METRIC,
  PREREGISTERED_SEEDS,
  PREREGISTERED_TRIALS,
  buildPreregistration,
  preregistrationFixtureDigest,
} from './fixture-preregistration.mjs';

/** The partition every fixture case lives in. @type {string} */
export const FIXTURE_PARTITION = 'HOLDOUT';

/**
 * The eight cases. `ground_truth_relation` is OBSERVATIONAL on every case, and
 * `observed_relation_strength` is the correlational label. This is the ground
 * truth a causal claim has to be measured against (A4), and it is why the
 * `label_substituted` variant can only be caught by a code guard: the schema
 * does not look at the data.
 *
 * `agreement_by_trial` is the per-case agreement LABEL (0 or 1) each measured
 * trial observed, and the counts are the frozen table's: 7 of 8 on trial 1,
 * 6 of 8 on trial 2, 5 of 8 on trial 3 (18 agreements pooled over 24 cases,
 * exactly the frozen baseline 0.75). The disagreement concentrates in the last
 * cases on purpose, so a case-level view of the corpus reads as a graded
 * difficulty rather than as noise.
 * @type {ReadonlyArray<Readonly<object>>}
 */
export const FIXTURE_CASES = Object.freeze([
  { case_id: 's2-008-case-01', ground_truth_relation: 'OBSERVATIONAL', observed_relation_strength: 'CORRELATION_EVIDENCE', agreement_label: 1, agreement_by_trial: { 'trl-s2-008-01': 1, 'trl-s2-008-02': 1, 'trl-s2-008-03': 1 } },
  { case_id: 's2-008-case-02', ground_truth_relation: 'OBSERVATIONAL', observed_relation_strength: 'CORRELATION_EVIDENCE', agreement_label: 1, agreement_by_trial: { 'trl-s2-008-01': 1, 'trl-s2-008-02': 1, 'trl-s2-008-03': 1 } },
  { case_id: 's2-008-case-03', ground_truth_relation: 'OBSERVATIONAL', observed_relation_strength: 'CORRELATION_EVIDENCE', agreement_label: 0, agreement_by_trial: { 'trl-s2-008-01': 1, 'trl-s2-008-02': 1, 'trl-s2-008-03': 1 } },
  { case_id: 's2-008-case-04', ground_truth_relation: 'OBSERVATIONAL', observed_relation_strength: 'CORRELATION_EVIDENCE', agreement_label: 1, agreement_by_trial: { 'trl-s2-008-01': 1, 'trl-s2-008-02': 1, 'trl-s2-008-03': 1 } },
  { case_id: 's2-008-case-05', ground_truth_relation: 'OBSERVATIONAL', observed_relation_strength: 'CORRELATION_EVIDENCE', agreement_label: 0, agreement_by_trial: { 'trl-s2-008-01': 1, 'trl-s2-008-02': 1, 'trl-s2-008-03': 1 } },
  { case_id: 's2-008-case-06', ground_truth_relation: 'OBSERVATIONAL', observed_relation_strength: 'CORRELATION_EVIDENCE', agreement_label: 1, agreement_by_trial: { 'trl-s2-008-01': 1, 'trl-s2-008-02': 1, 'trl-s2-008-03': 0 } },
  { case_id: 's2-008-case-07', ground_truth_relation: 'OBSERVATIONAL', observed_relation_strength: 'CORRELATION_EVIDENCE', agreement_label: 0, agreement_by_trial: { 'trl-s2-008-01': 1, 'trl-s2-008-02': 0, 'trl-s2-008-03': 0 } },
  { case_id: 's2-008-case-08', ground_truth_relation: 'OBSERVATIONAL', observed_relation_strength: 'CORRELATION_EVIDENCE', agreement_label: 1, agreement_by_trial: { 'trl-s2-008-01': 0, 'trl-s2-008-02': 0, 'trl-s2-008-03': 0 } },
].map((entry) => Object.freeze({ ...entry, partition: FIXTURE_PARTITION, agreement_by_trial: Object.freeze(entry.agreement_by_trial) })));

/**
 * The label vector of the holdout partition, in case order.
 * @type {ReadonlyArray<number>}
 */
export const HOLDOUT_LABEL_VECTOR = Object.freeze(FIXTURE_CASES.map((entry) => entry.agreement_label));

/**
 * The label MAP of the holdout partition: `case_id -> agreement_label`. This
 * is the shape `dataset.mjs` rebuilds from the committed corpus when it loads a
 * partition, so it — and NOT the vector above — is what the one-shot unseal
 * digest and the label seal are taken over. Digesting the vector instead would
 * give a second, order-sensitive spelling of the same labels, and the
 * committed corpus would then open on a digest the preregistration never named.
 * @type {Readonly<Record<string, number>>}
 */
export const HOLDOUT_LABELS = Object.freeze(Object.fromEntries(
  FIXTURE_CASES.map((entry) => [entry.case_id, entry.agreement_label]),
));

/** `sha256:<64 hex>` over the label map. The preregistered unseal digest. @type {string} */
export const HOLDOUT_UNSEAL_DIGEST = fixtureDigest(HOLDOUT_LABELS);

/** The preregistration this fixture set runs under, sealed with the digest above. @type {Readonly<object>} */
export const PREREGISTRATION = buildPreregistration({ holdoutUnsealDigest: HOLDOUT_UNSEAL_DIGEST });

/** The preregistration digest, recorded before trial one. @type {string} */
export const PREREGISTRATION_DIGEST = preregistrationFixtureDigest(PREREGISTRATION);

/** The preregistered noise band. @type {number} */
export const NOISE_BAND = PREREGISTRATION.noise_rule.band;

/** The preregistered baseline both intervals are compared against. @type {number} */
export const BASELINE = FROZEN_BASELINE.value;

/**
 * The frozen bootstrap parameters. Read by name so the interval below cannot
 * disagree with the preregistration about which seed produced it.
 * @type {{seed: number, resamples: number, percentile: number, confidence: number}}
 */
export const BOOTSTRAP = Object.freeze({
  seed: PREREGISTRATION.noise_rule.bootstrap_seed,
  resamples: PREREGISTRATION.noise_rule.bootstrap_samples,
  percentile: PREREGISTRATION.noise_rule.percentile,
  confidence: PREREGISTRATION.noise_rule.confidence,
});

// Synthetic latency samples, one per trial, in preregistered index order.
// Deterministic, positive, and never a verdict input. Marked `FIXTURE_SYNTHETIC`
// in every record that carries them.
const LATENCY_MS_SAMPLES = Object.freeze([12.5, 13.25, 11.75, 14]);

/**
 * The per-case agreement labels one measured trial observed, in `FIXTURE_CASES`
 * order.
 * @param {string} trial A member of the preregistered trial list.
 * @returns {ReadonlyArray<number>} One 0/1 label per case.
 * @throws {Error} `FIXTURE_TRIAL_UNKNOWN` for an unknown trial id.
 */
export function samplesForTrial(trial) {
  if (!FIXTURE_CASES.every((entry) => trial in entry.agreement_by_trial)) {
    throw new Error(`FIXTURE_TRIAL_UNKNOWN: ${String(trial)} has no per-case samples`);
  }
  return Object.freeze(FIXTURE_CASES.map((entry) => entry.agreement_by_trial[trial]));
}

/**
 * The Wilson score interval of one trial's agreement counts, computed by the
 * FROZEN statistics module at the preregistered confidence. The metric is a
 * proportion, so this is the interval a proportion gets; the bootstrap is
 * reserved for the latency block.
 * @param {string} trial A member of the preregistered trial list.
 * @returns {Readonly<object>} The interval plus every parameter that produced
 *   it, so a reader can re-derive it instead of trusting the number.
 */
export function intervalForTrial(trial) {
  const samples = samplesForTrial(trial);
  return Object.freeze(wilsonInterval({
    successes: samples.reduce((total, value) => total + value, 0),
    trials: samples.length,
    confidence: BOOTSTRAP.confidence,
  }));
}

/**
 * FIXTURE SELF-CHECK, NOT A VERDICT FUNCTION, AND NOT VACUOUS.
 *
 * It answers one yes/no question: "does the hand-authored per-case data
 * produce the agreement count the FROZEN TABLE pins for this trial?" It
 * returns a BOOLEAN and names no outcome. The outcome is named in exactly one
 * place in this repository — `decisionFromInterval` in
 * `src/lib/research/comparator.mjs` — and a second function that could name it
 * here would be a second decision layer, which is the silent divergence
 * `src/lib/agentboard/store.mjs:26-32` exists to prevent.
 *
 * It replaces a check that could not fail. The previous
 * `intervalAgreesWithRule(interval)` returned `true` for EVERY interval: the
 * POSITIVE branch, the NEGATIVE branch and the `lower <= band && upper >=
 * -band` NULL branch together cover the whole real line, so the
 * `FIXTURE_INTENT_MISMATCH` throw was unreachable and the "known effect, known
 * null, known negative" design was never actually verified. A self-check that
 * cannot fail is worse than none, because it reads like a guarantee.
 *
 * What replaced it is the check that CAN fail and that matters: the per-case
 * labels must sum to the table's `expectedNumerator` over `expectedDenominator`.
 * That is the actual link between authored data and the frozen expectation.
 * @param {string} trial A member of the preregistered trial list.
 * @returns {boolean} Whether the data and the frozen table agree.
 */
export function assertMeasurementAgreesWithTable(trial) {
  const row = EXPECTED_TRIAL_DECISIONS.find((entry) => entry.trial === trial);
  if (!row) throw new Error(`FIXTURE_TRIAL_UNKNOWN: ${String(trial)} has no row in the frozen table`);
  const samples = samplesForTrial(trial);
  const numerator = samples.reduce((total, value) => total + value, 0);
  if (samples.length !== row.expectedDenominator) {
    throw new Error(
      `FIXTURE_INTENT_MISMATCH: ${trial} observed ${String(samples.length)} cases while the frozen table pins ${String(row.expectedDenominator)}`,
    );
  }
  if (numerator !== row.expectedNumerator) {
    throw new Error(
      `FIXTURE_INTENT_MISMATCH: ${trial} observed ${String(numerator)} agreements while the frozen table pins ${String(row.expectedNumerator)}`,
    );
  }
  return true;
}

/**
 * What the FROZEN rule derives from the interval this fixture computed —
 * recorded, never asserted as the design.
 *
 * `decisionFromInterval` is the only place an outcome may be named, so the
 * fixture calls it and copies the answer out. With eight cases the 95% interval
 * cannot separate 7/8, 6/8 and 5/8 from the frozen baseline, so this returns
 * UNRESOLVED for all three measured trials: the honest reading of a corpus this
 * size, and the reason `FIXTURE_DERIVED_DISAGREEMENTS` is not empty.
 * @param {string} trial A member of the preregistered trial list.
 * @returns {Readonly<object>} `{trial, observed, lower, upper, derived_outcome, derived_reason}`.
 */
export function derivedDecisionFor(trial) {
  const interval = intervalForTrial(trial);
  const samples = samplesForTrial(trial);
  const observed = samples.reduce((total, value) => total + value, 0) / samples.length;
  const applied = decisionFromInterval({
    observed,
    lower: interval.lower,
    upper: interval.upper,
    noiseBand: NOISE_BAND,
    rule: {
      alpha: PREREGISTRATION.multiplicity_rule.alpha,
      method: PREREGISTRATION.multiplicity_rule.method,
      comparisons: PREREGISTRATION.multiplicity_rule.declared_comparisons,
      confidence: BOOTSTRAP.confidence,
      null_value: BASELINE,
      subject: trial,
    },
  });
  return Object.freeze({
    trial,
    observed,
    lower: interval.lower,
    upper: interval.upper,
    derived_outcome: applied.decision,
    derived_reason: applied.reason,
  });
}

/**
 * The reconciliation row an infra trial owes. Expiry and interruption produce
 * one of these and never a retry: P4's whole content is that an unknown
 * outcome is a decision for a human, not a second attempt.
 * @type {Readonly<object>}
 */
export const INFRA_RECONCILIATION = Object.freeze({
  required: true,
  kind: 'RECONCILIATION_REQUIRED',
  reason: 'EVALUATOR_PROCESS_ABORTED_BEFORE_MEASUREMENT',
  observed_at: FIXED_INSTANT_ISO,
  observed_by_clock: FIXED_CLOCK.source,
  resolution: 'AWAIT_AUTHORIZED_RECONCILIATION_DECISION',
  blind_retry: false,
  silent_zero: false,
  // Named, not implied: a reader must be able to see that the infra trial is
  // accounted for instead of quietly missing from the run.
  trial_accounted_for: true,
  row_digest: fixtureDigest({ trial: 'trl-s2-008-04', kind: 'RECONCILIATION_REQUIRED', reason: 'EVALUATOR_PROCESS_ABORTED_BEFORE_MEASUREMENT' }),
});

/**
 * One trial record, in the shape `expectedValueIssues`, `resolveTrialVerdict`
 * and `metricsSummary` read.
 *
 * The shape is NOT invented here. `DECISION_TRIAL_FIELDS` in
 * `src/lib/research/comparator.mjs` is the frozen list of the fields a decision
 * depends on (`trial, status, outcome, metric, numerator, denominator, seeds`),
 * `expectedValueIssues` scores `trial/status/outcome/numerator/denominator`
 * plus the per-trial `provenance` and `counters` blocks, and `scoreRun` reads
 * the four bindings, the `evaluator` and the `calibration`. A fixture record
 * that omitted one of those produced a run that was VIOLATION before the test
 * started, so every "the verdict flips" assertion was comparing two failures.
 *
 * All four bindings are present on a measured trial, and the calibration is
 * the MEASURED, independent one: `ALLOW` requires `RESOLVED` plus all four
 * bindings plus an independent evaluator, so a fixture that omitted one would
 * be asserting nothing. The delivered calibration of this track is honestly
 * NOT_MEASURED (`outcome_not_defined`); a test input is not a delivered
 * artefact, and the two must not be confused.
 * @param {Readonly<object>} entry An entry of `PREREGISTERED_TRIALS`.
 * @returns {Readonly<object>} The trial record.
 */
function buildTrial(entry) {
  const row = EXPECTED_TRIAL_DECISIONS.find((item) => item.trial === entry.trial);
  if (!row) throw new Error(`FIXTURE_TRIAL_UNKNOWN: ${String(entry.trial)} has no row in the frozen table`);
  const seeds = PREREGISTERED_SEEDS;
  const base = {
    index: entry.index,
    trial: entry.trial,
    partition: entry.partition,
    // The metric NAME is the frozen table's, and the trials DECLARE it: the
    // comparator refuses a run whose trials measure different metrics, and the
    // table refuses a run whose `metrics.metric` is not its own.
    metric: PREREGISTERED_METRIC.name,
    // `seeds` as a FLAT array on the trial, because that is the spelling both
    // the decision digest (`DECISION_TRIAL_FIELDS`) and `scoreRun` read. The
    // seed set is preregistered, so a trial cannot pick a better one (P2).
    seeds,
    // The design the FROZEN TABLE pins, and what this run recorded against it.
    designed_outcome: entry.designed_outcome,
    outcome: row.expectedOutcome,
    // The status the table pins, and the verdict the table pins for that
    // status. Both are DECLARED, not observed: a test is what asserts
    // `resolveTrialVerdict(trial).verdict === trial.verdict`, and a fixture
    // that called the comparator to fill in its own expectation would make that
    // assertion a tautology.
    status: row.expectedStatus,
    verdict: row.expectedVerdict,
    seedBinding: Object.freeze({
      present: true,
      preregistered: true,
      seeds,
      preregistered_seeds: seeds,
      seeds_digest: PREREGISTRATION.seeds_digest,
      source: 'PREREGISTERED',
      best_seed_selection: 'FORBIDDEN',
    }),
    holdoutBinding: Object.freeze({
      present: true,
      partition: FIXTURE_PARTITION,
      case_count: FIXTURE_CASES.length,
      labels_digest: HOLDOUT_UNSEAL_DIGEST,
      unseal_digest: HOLDOUT_UNSEAL_DIGEST,
      access_recorded: true,
      read_before_data: true,
      one_shot_used: false,
      // The one-shot open happened AT the preregistered decision point, never
      // before it: `holdoutBinding` is checked for exactly this, and a binding
      // that only said `present: true` proved nothing.
      opens: 1,
      max_opens: 1,
      read_at: FIXED_INSTANT_ISO,
      decision_at: FIXED_INSTANT_ISO,
      opened_before_decision_point: false,
    }),
    budgetBinding: Object.freeze({
      present: true,
      reservation_id: BUDGET_RESERVATION.reservation_id,
      granted_units: BUDGET_RESERVATION.granted_units,
      spent_units: entry.index + 1,
      currency: BUDGET_RESERVATION.currency,
      expires_at: BUDGET_RESERVATION.expires_at,
      clock_source: FIXED_CLOCK.source,
      within_reservation: true,
    }),
    evaluatorBinding: Object.freeze({
      present: true,
      evaluator_id: 'evl-s2-008-01',
      calibration_id: CALIBRATIONS.independent.calibration_id,
      independent: true,
      blind_to_producer: true,
      separate_process: true,
    }),
    // `evaluator` as its own member: the comparator reads it, and control
    // `missing_evaluator` deletes it. A record that carried the evaluator only
    // inside the binding could not lose it.
    evaluator: Object.freeze({
      evaluator_id: 'evl-s2-008-01',
      independent: true,
      blind_to_producer: true,
      separate_process: true,
    }),
    // The MEASURED, independent calibration. `resolveTrialVerdict` calls
    // `assertEvaluatorPresent(evaluator, calibration)`, so a trial without a
    // calibration is a VIOLATION no matter how satisfied its bindings look.
    calibration: CALIBRATIONS.independent,
    calibration_id: CALIBRATIONS.independent.calibration_id,
    latency_ms: LATENCY_MS_SAMPLES[entry.index],
    latency_source: 'FIXTURE_SYNTHETIC',
    latency_decides: false,
    reason_codes: [],
    reconciliation_id: null,
  };
  if (entry.designed_outcome === 'INFRA') {
    return Object.freeze({
      ...base,
      // An infra trial resolves to nothing, so it has no status a verdict could
      // read as a pass and no interval to compare.
      measured: false,
      not_measured: true,
      samples: null,
      numerator: null,
      denominator: null,
      observed: null,
      interval: null,
      derived_outcome: null,
      derived_reason: 'NO_MEASUREMENT_TO_DERIVE_FROM',
      reason_codes: ['INFRA_ERROR'],
      infra: Object.freeze({
        code: 'MEASUREMENT_ABSENT',
        reconciliation: INFRA_RECONCILIATION,
      }),
      reconciliation: INFRA_RECONCILIATION,
      // The anti-pattern, named: an unmeasured trial must never reach a
      // consumer as a number.
      numeric_value: null,
    });
  }
  assertMeasurementAgreesWithTable(entry.trial);
  const samples = samplesForTrial(entry.trial);
  const interval = intervalForTrial(entry.trial);
  const derived = derivedDecisionFor(entry.trial);
  return Object.freeze({
    ...base,
    measured: true,
    not_measured: false,
    samples,
    numerator: row.expectedNumerator,
    denominator: row.expectedDenominator,
    observed: derived.observed,
    interval: Object.freeze({
      lower: interval.lower,
      upper: interval.upper,
      method: interval.method,
      confidence: interval.confidence,
    }),
    // The frozen rule's own answer, next to the design. A reader who wants to
    // know what the interval decides does not have to re-run anything, and a
    // test can assert the two differ where they differ.
    derived_outcome: derived.derived_outcome,
    derived_reason: derived.derived_reason,
    decision: Object.freeze({
      metric: PREREGISTERED_METRIC.name,
      unit: PREREGISTERED_METRIC.unit,
      observed: derived.observed,
      lower: interval.lower,
      upper: interval.upper,
      method: interval.method,
      confidence: interval.confidence,
      sample_count: samples.length,
      frozen_baseline: BASELINE,
      noise_band: NOISE_BAND,
      // The same comparisons `decisionFromInterval` makes, precomputed so a
      // test can assert the arithmetic without re-deciding the outcome.
      delta_lower: interval.lower - BASELINE,
      delta_upper: interval.upper - BASELINE,
      interval_clears_noise: interval.lower - BASELINE > NOISE_BAND || interval.upper - BASELINE < -NOISE_BAND,
      interval_intersects_band: interval.lower - BASELINE <= NOISE_BAND && interval.upper - BASELINE >= -NOISE_BAND,
      inference_mode: 'ASSOCIATIONAL',
    }),
    reconciliation: null,
  });
}

/** The four trial records, in preregistered index order. @type {ReadonlyArray<Readonly<object>>} */
export const FIXTURE_TRIALS = Object.freeze(PREREGISTERED_TRIALS.map(buildTrial));

/**
 * Every trial where the frozen RULE derived an outcome other than the design
 * the frozen table pins. Published rather than hidden: with eight cases a 95%
 * interval cannot separate 7/8, 6/8 and 5/8 from the frozen baseline, and the
 * only honest thing a fixture can do with that fact is name it.
 * @type {ReadonlyArray<Readonly<object>>}
 */
export const FIXTURE_DERIVED_DISAGREEMENTS = Object.freeze(
  FIXTURE_TRIALS
    .filter((trial) => trial.derived_outcome !== null && trial.derived_outcome !== trial.outcome)
    .map((trial) => Object.freeze({
      trial: trial.trial,
      table_says: trial.outcome,
      rule_derived: trial.derived_outcome,
      reason: trial.derived_reason,
      corpus_cases: trial.denominator,
      corpus_limitation: 'eight cases cannot resolve a 0.02 noise band at 95% confidence; the disagreement is a property of the corpus, not of the rule',
    })),
);

/**
 * The hard-gate counters a CLEAN run ends at, READ from the track's frozen
 * `RESEARCH_HARD_GATE_COUNTERS` rather than written out here. This fixture used
 * to list NINE names, adding `corruptedControl`, `identicalWrong` and
 * `repeatRunDrift` to the six the track freezes. Those three are real
 * control-level gates (see `CONTROL_LEVEL_COUNTERS`) but they are NOT members
 * of the run's counter block, and putting them there gave a clean run a counter
 * set the frozen table does not know — a fixture carrying a second
 * vocabulary is how a wrong counter name survives review.
 * @type {ReadonlyArray<string>}
 */
export const FIXTURE_HARD_GATE_COUNTERS = Object.freeze([...RESEARCH_HARD_GATE_COUNTERS]);

/**
 * The control-level gates, which are NOT run counters and never appear in a
 * run's `counters` block. Kept as a separate, named list so a harness can
 * report them without a fixture having invented a seventh counter.
 * @type {ReadonlyArray<string>}
 */
export const CONTROL_LEVEL_COUNTERS = Object.freeze([
  'corruptedControl',
  'identicalWrong',
  'repeatRunDrift',
]);

/**
 * A zero-valued counter expectation over `names`.
 * @param {ReadonlyArray<string>} [names] Defaults to `FIXTURE_HARD_GATE_COUNTERS`.
 * @returns {Readonly<Record<string, number>>} Every counter at 0.
 * @throws {Error} `FIXTURE_COUNTER_UNKNOWN` for a name outside the frozen set.
 */
export function expectedCounters(names = FIXTURE_HARD_GATE_COUNTERS) {
  const out = {};
  for (const name of names) {
    if (!FIXTURE_HARD_GATE_COUNTERS.includes(name)) {
      throw new Error(`FIXTURE_COUNTER_UNKNOWN: ${String(name)} is not one of the frozen hard-gate counters`);
    }
    out[name] = 0;
  }
  return Object.freeze(out);
}

/**
 * Placeholder provenance. FROZEN-looking but deliberately obvious: a fixture
 * that minted a plausible SHA-1 would be a way to fake A5's binding, so these
 * are all-zero SHAs and every record that carries them sets
 * `provenance_is_placeholder: true`. A real commit SHA, tree SHA and raw run id
 * come from `scripts/s2-008-run.mjs --write` (W4), never from a fixture.
 * @type {{commit_sha: string, tree_sha: string, provenance_is_placeholder: true}}
 */
export const PLACEHOLDER_PROVENANCE = Object.freeze({
  commit_sha: '0000000000000000000000000000000000000000',
  tree_sha: '0000000000000000000000000000000000000000',
  provenance_is_placeholder: true,
});

/**
 * The ledger expectations of a CLEAN run, expressed as PROPERTIES rather than
 * as a record-kind table. W2 owns the record kinds and the journal format, so
 * listing kinds here would be a second, editable copy of the format; what a
 * fixture can honestly pin is that the chain held, nothing was overwritten and
 * a refused write changed no byte.
 * @type {Readonly<object>}
 */
export const CLEAN_LEDGER = Object.freeze({
  purged_before_run: true,
  purge_idempotent: true,
  sealed_before_first_trial: true,
  chain_intact: true,
  append_only: true,
  refused_writes_change_nothing: true,
  torn_tail_recovered: false,
  // A run's journal is not compared to a fixture here: the count depends on W2's
  // implementation and a fixture that pinned it would break every legitimate
  // change to the record set. `null` means "not pinned by the fixture", and it
  // is explicit rather than absent.
  pinned_record_count: null,
});

/**
 * The pooled case counts and their interval, computed from the trials rather
 * than written: 7 + 6 + 5 agreements over 3 x 8 cases, which is the frozen
 * 18/24 `POOLED_TRIAL_COUNTS` the table pins, and exactly the frozen baseline
 * 0.75. The infra trial contributes to NEITHER count: it is reported in
 * `notMeasured` and never as a zero.
 * @type {{successes: number, trials: number, notMeasured: number}}
 */
export const POOLED_COUNTS = Object.freeze({
  successes: FIXTURE_TRIALS.reduce(
    (total, trial) => total + (typeof trial.numerator === 'number' ? trial.numerator : 0),
    0,
  ),
  trials: FIXTURE_TRIALS.reduce(
    (total, trial) => total + (typeof trial.denominator === 'number' ? trial.denominator : 0),
    0,
  ),
  notMeasured: FIXTURE_TRIALS.filter((trial) => trial.status !== 'RESOLVED').length,
});

/** The Wilson interval over `POOLED_COUNTS`, from the frozen statistics module. @type {Readonly<object>} */
export const POOLED_INTERVAL = Object.freeze(wilsonInterval({
  successes: POOLED_COUNTS.successes,
  trials: POOLED_COUNTS.trials,
  confidence: PREREGISTRATION.noise_rule.confidence,
}));

/**
 * The six control ids, and the state a completed campaign reports for each.
 * One id list, so the fixture and the controls cannot disagree about how many
 * there are. The axis each control moves lives with its variant in
 * `fixture-corrupted-variants.mjs`.
 * @type {{allFlipped: true, controls: ReadonlyArray<Readonly<object>>}}
 */
export const CLEAN_CONTROLS = Object.freeze({
  allFlipped: true,
  controls: Object.freeze([
    'holdout_peek', 'seed_substitution', 'budget_opacity', 'label_substitution', 'missing_evaluator', 'corrupted_data',
  ].map((id) => Object.freeze({ id, flipped: true }))),
  notRun: Object.freeze([]),
});

/**
 * One CLEAN run record: the shape `expectedValueIssues(run, letter)` reads
 * (`trials, codes, counters, ledger, metrics`, plus the TOP-LEVEL `commit_sha`,
 * `tree_sha` and `raw_run_id`), with the two process-local identities of the
 * run's label.
 *
 * Runs A and B are built from the SAME builder, so they differ only in
 * `raw_run_id`, `nonce`, `executor_id` and `run_letter` — the named allowed
 * differences. That is what makes `A === B` hold for the right reason and what
 * the A3 identical-wrong control then defeats.
 *
 * WHY `metrics` IS COMPUTED, NOT WRITTEN
 * `metricsSummary` is the track's own aggregation, so the pooled counts cannot
 * drift from the trials they are pooled from. The previous version hand-wrote
 * `numerator: null, denominator: null` and an `aggregation` member the frozen
 * table does not know: the table scores `metrics.metric`, `metrics.basis`,
 * `metrics.numerator`, `metrics.denominator` and `metrics.notMeasured`, so a
 * clean run produced five findings on every single call and the whole
 * corruption-control design was measuring nothing. `metricsSummary(FIXTURE_TRIALS)`
 * yields 18/24 over `POOLED_TRIAL_COUNTS` with `notMeasured: 1`, which is what
 * the frozen table pins.
 * @param {string} label A member of `RUN_LABELS`.
 * @returns {Readonly<object>} The run record.
 * @throws {Error} `FIXTURE_LABEL_UNKNOWN` for a label outside `RUN_LABELS`.
 */
export function buildCleanRun(label) {
  const identity = fixtureRunIdentity(label);
  return Object.freeze({
    run_letter: label,
    version: 's2-008-fixture-run-v1',
    // A5: the binding fields are TOP LEVEL, because that is where the table and
    // the comparator read them. A run that carried them only inside a nested
    // `provenance` block was `RUN_PROVENANCE_UNBOUND` on every call.
    raw_run_id: identity.raw_run_id,
    commit_sha: PLACEHOLDER_PROVENANCE.commit_sha,
    tree_sha: PLACEHOLDER_PROVENANCE.tree_sha,
    nonce: identity.nonce,
    executor_id: identity.executor_id,
    output_root: `results/s2-008/fixtures/run-${label}`,
    preregistration_id: PREREGISTRATION.preregistration_id,
    preregistration_digest: PREREGISTRATION_DIGEST,
    // The table this run was scored against, sealed in the preregistration
    // before trial one and echoed here. The bare 64-hex form, because
    // `expectedValueIssues` compares it with `expectedTableDigest()` and treats
    // the `sha256:` wire form as a different table.
    expected_table_digest: expectedTableDigest(),
    // The campaign's own metric block, as a RECORD with its own interval: the
    // comparator reads `run.metric.interval` and compares it with the interval
    // its own counts give (`self_reported_interval_divergence`). A run that
    // reported a bare metric NAME skipped that check for want of a number.
    metric: Object.freeze({
      name: PREREGISTERED_METRIC.name,
      unit: PREREGISTERED_METRIC.unit,
      interval: Object.freeze(POOLED_INTERVAL),
    }),
    trials: FIXTURE_TRIALS,
    // A clean run emits no refusal code at all. A code here means something was
    // refused, and a clean run refuses nothing.
    codes: Object.freeze([]),
    counters: expectedCounters(),
    ledger: CLEAN_LEDGER,
    // The track's own aggregation over the trials above: pooled case counts,
    // `notMeasured` reported separately and never folded into a zero.
    metrics: Object.freeze({
      ...metricsSummary(FIXTURE_TRIALS),
      // Negative, null and infra outcomes are counted as themselves. None of
      // them is merged into another and none is a zero.
      outcome_counts: Object.freeze({ POSITIVE: 1, NULL: 1, NEGATIVE: 1, INFRA: 1 }),
      inference_mode: 'ASSOCIATIONAL',
    }),
    // The pooled counts the campaign reports, and the interval over them,
    // computed by the FROZEN statistics module from those same counts. Eight
    // cases are measured three times over: 7 + 6 + 5 agreements out of 24,
    // which is exactly the frozen baseline.
    pooled_counts: POOLED_COUNTS,
    // Every per-trial provenance block names the SAME execution as the run, so
    // `expectedValueIssues`'s `TRIAL_PROVENANCE_DIVERGES_FROM_TABLE` check has
    // a truth to confirm; the `forged_provenance` control moves exactly this.
    trial_provenance_digest: fixtureDigest({
      raw_run_id: identity.raw_run_id,
      commit_sha: PLACEHOLDER_PROVENANCE.commit_sha,
      tree_sha: PLACEHOLDER_PROVENANCE.tree_sha,
    }),
    provenance: Object.freeze({ ...PLACEHOLDER_PROVENANCE, run_label: label, recorded_at: FIXED_INSTANT_ISO }),
    // The campaign verdict this run is expected to resolve to. Declared here so
    // a test has one place to read it, and NOT computed by calling the
    // comparator: an expectation produced by the code under test is a tautology.
    expected_campaign_verdict: 'PASS',
    allowed_process_differences: ALLOWED_PROCESS_DIFFERENCES,
    // A2: the six controls, reported as the state a completed campaign reaches
    // — every one flipped. `scoreRun` reads this block and turns a missing or
    // un-flipped control into a FAILURE (S2-008-SD-05), so a clean fixture run
    // without it could never be scored clean, and each corrupted variant turns
    // exactly one entry to `flipped: false`. Declared, not observed: the
    // controls themselves are `src/lib/research/negative-controls.mjs`, and a
    // test is what asserts the declaration against them.
    controls: CLEAN_CONTROLS,
  });
}

// Attach the per-trial blocks the frozen table reads. Done here rather than
// inside `buildTrial` because they carry the RUN's identity, and a trial that
// carried its own identity could disagree with its run — which is exactly the
// `forged_provenance` control, so the clean state has to be the agreeing one.
const RUNS_WITH_TRIAL_PROVENANCE = Object.freeze(
  Object.fromEntries(RUN_LABELS.map((label) => {
    const run = buildCleanRun(label);
    const trials = FIXTURE_TRIALS.map((trial) => Object.freeze({
      ...trial,
      provenance: Object.freeze({
        raw_run_id: run.raw_run_id,
        commit_sha: run.commit_sha,
        tree_sha: run.tree_sha,
      }),
      counters: expectedCounters(),
    }));
    return [label, Object.freeze({ ...run, trials })];
  })),
);

/** The clean run records for both labels. @type {Readonly<Record<string, Readonly<object>>>} */
export const CLEAN_RUNS = RUNS_WITH_TRIAL_PROVENANCE;

/**
 * Build a run record whose `expected_table_digest` is filled in. Kept as a
 * function so a test can construct a run bound to a SPECIFIC table — including
 * the corrupted one — without editing this file.
 * @param {string} label A member of `RUN_LABELS`.
 * @param {string} tableDigest The digest of the table in force, bare 64-hex.
 * @returns {Readonly<object>} The run record.
 * @throws {Error} `FIXTURE_LABEL_UNKNOWN` for a label outside `RUN_LABELS`.
 */
export function buildRunBoundToTable(label, tableDigest) {
  return Object.freeze({ ...buildCleanRun(label), expected_table_digest: tableDigest });
}
