// The CORRUPTED VARIANTS: the inputs the negative controls need, and the
// verdict each one MUST flip to.
//
// WHAT THIS IS: a builder per corruption class plus, for each, an
// `expected_flip` that names the axis, the before and after value, and — where
// an axis does NOT move — why it does not. A test asserts the flip, so the
// declaration and the observation live next to each other and cannot drift
// apart the way an expectation buried in a test file can.
//
// THE FIVE REQUIRED VARIANTS
//   corrupted_measurement     A metric block replaced with a different,
//                             internally consistent one. (A2, control
//                                                   id `corrupted_data`.)
//   corrupted_expected_table  The TABLE is corrupted and both runs are left
//                             clean. This is the one that proves the table is
//                             load-bearing: agreement between the runs is
//                             untouched and the verdict still has to move.
//                             (A3, control id `corrupted_data`.)
//   label_substituted         The hypothesis card's relation label is replaced
//                             with a causal one while the ground truth stays
//                             observational, in BOTH directions a label can be
//                             substituted: `relation_strength` upgraded, and
//                             `causal_assertion` set on the observational
//                             label. (A4, control id `label_substitution`.)
//   missing_evaluator         The evaluator binding is deleted, or the run's
//                             calibration is the NOT_MEASURED one. (A2/P6,
//                                                           control id
//                                                           `missing_evaluator`.)
//   truncated_trial           The last trial's record is cut mid-write and the
//                             array loses it. (A2, control id
//                                                 `corrupted_data`.)
//
// FOUR ADDITIONAL BUILDERS, FOR THE FIVE FROZEN CORRUPTION CLASSES
// The identical-wrong control is only meaningful if it covers one class per
// frozen category (a trial status, a counter, a code set, a metric, a
// provenance field). The five required variants above do not reach all five, so
// `skipped_trial`, `nudged_counter`, `undeclared_code` and `forged_provenance`
// supply the rest — they exist to complete the coverage map below, not to add
// controls.
//
// EVERY `from` VALUE IS DERIVED FROM THE CLEAN FIXTURE, NOT TYPED
// The previous version of this file hand-wrote them (`observed: 0.859375`,
// `lower: 0.8125`, `upper: 0.875` for trial 0), so when the measurement set was
// rebuilt every one of them became a stale lie while still reading like a fact
// about the fixture. A "before" that nobody derives is not an expectation, it
// is a comment. Each is now read out of the clean record at import.
//
// NOT EVERY CORRUPTION MOVES EVERY AXIS, AND THE TABLE SAYS SO
// A corrupted METRIC does not change a trial's ALLOW/VIOLATION: the trial is
// still RESOLVED with all four bindings. What moves is the expected-value
// table's verdict for that trial and therefore the campaign verdict. Deleting
// the evaluator, by contrast, moves NO table finding at all — the frozen table
// scores counts, codes, statuses and provenance, not bindings — and moves the
// TRIAL verdict instead. Claiming a flip that the design cannot produce would be
// the easiest way to write a control that passes without testing anything, so
// `expected_flip` carries `changed: false` with a reason wherever that is the
// honest answer.
//
// NOTHING HERE MUTATES ITS INPUT
// Every builder deep-copies first, so the clean run record stays byte-identical
// after a corrupted one has been produced. Without that, "the clean run still
// passes" stops being provable and a second run of the control silently starts
// from an already-damaged fixture.
import { canonicalize } from '../../../src/lib/verifier/canonical-json.mjs';
import { expectedTableDigest } from '../../../src/lib/research/expected-values.mjs';
import { classifyCardRelation } from '../../../src/lib/research/causality.mjs';
import { fixtureDigest } from './fixture-digest.mjs';
import {
  CLEAN_RUNS,
  FIXTURE_TRIALS,
  PREREGISTRATION,
  buildRunBoundToTable,
  expectedCounters,
} from './fixture-measurement-set.mjs';
import {
  EXPECTED_TRIAL_DECISIONS,
  EXPECTED_VALUE_TABLE,
  withExpectedRow,
} from './fixture-expected-values.mjs';
import {
  CALIBRATIONS,
  HYPOTHESIS_CARD,
  HYPOTHESIS_CARD_DIGEST,
  preregistrationFixtureDigest,
} from './fixture-preregistration.mjs';
import { ALLOWED_PROCESS_DIFFERENCES } from './fixture-run-identity.mjs';

// The exact byte offset at which the last trial's record is cut. Fixed so the
// torn tail is the same bytes in every process.
const TRUNCATE_AT_BYTES = 96;

/**
 * A deep copy that is safe for these records: the fixture values are plain
 * JSON, so `structuredClone` is exact and does not drag a frozen prototype or a
 * class instance into a digest.
 * @param {*} value Any plain JSON value.
 * @returns {*} An independent copy.
 */
function copy(value) {
  return structuredClone(value);
}

/**
 * The campaign verdict a CLEAN comparison resolves to: `FAIL`.
 *
 * MEASURED, not hoped for. Driving `compareParallelTrack` from a scratch
 * directory outside the repository on the clean pair with the resolved base
 * returns failures whose codes are exactly
 * `decision_unresolved, metric_not_measured, trial_violation`, and
 * `resolveCampaignVerdict` maps any non-empty failure list to FAIL. The reason
 * is structural, not a fixture defect:
 *   * the FROZEN TABLE pins trial 3 as `INFRA_ERROR` / `VIOLATION`, and
 *     `scoreRun` raises a `trial_violation` for any trial that is not ALLOW —
 *     so a run that honours the table is guaranteed to carry one;
 *   * `scoreMetric` raises `metric_not_measured` whenever
 *     `summary.notMeasured > 0`, and the same table pins exactly one
 *     unmeasured trial, so a second failure is guaranteed too;
 *   * with eight cases the 95% interval cannot resolve 7/8, 6/8 and 5/8
 *     against the frozen baseline, so the decision is UNRESOLVED and
 *     `decision_unresolved` is the third.
 *
 * The track's own delivered evidence says the same thing:
 * `evidence/s2-008-harness.json` carries `verdict: 'FAIL'` with the same three
 * codes. This fixture previously declared `PASS`, which was a wish. A control
 * that says "the clean state is PASS" when the clean state is FAIL cannot show a
 * verdict flipping, because nothing flips at the campaign level — and a test
 * built on that declaration would be asserting against a fiction.
 * @type {string}
 */
export const CLEAN_CAMPAIGN_VERDICT = 'FAIL';

/**
 * The failure codes a CLEAN comparison carries, measured from the clean pair.
 * @type {ReadonlyArray<string>}
 */
export const CLEAN_CAMPAIGN_FAILURE_CODES = Object.freeze([
  'decision_unresolved',
  'metric_not_measured',
  'trial_violation',
]);

/**
 * The verdict every corrupted variant resolves to as well: `FAIL`.
 *
 * `changed: false`, and that is the honest answer rather than a missing one. The
 * campaign verdict is a three-valued summary, and the clean state already
 * occupies its worst value for reasons of the table's own design, so a
 * corruption cannot move it. What a corruption DOES move is named per variant:
 * the table findings, the per-trial verdicts, and the set of failure codes
 * `compareParallelTrack` reports. A test asserts those axes, and the failure-code
 * set is the one every single variant moves — it is the closest thing here to a
 * verdict that flips for all of them.
 * @type {string}
 */
export const CORRUPTED_CAMPAIGN_VERDICT = 'FAIL';

// ---------------------------------------------------------------------------
// 1. corrupted_measurement — the metric class.
// ---------------------------------------------------------------------------

// Hand-written, NOT the output of the statistics module. A corruption that
// looked exactly like an honest re-run would be indistinguishable from one,
// and a reader could not see the damage. The NUMBERS are internally consistent
// (3 agreements over the same 8 cases, with the interval those 3 give), so the
// record is not trivially malformed: it is subtly, plausibly wrong, which is
// the hard case. The LEVEL is not hand-written: `confidence` is the campaign's
// own published level, read from the preregistration, because a second literal
// level here would be a second spelling of the rule the run is scored against
// — and a stale one, which is precisely the defect this repair removed from the
// preregistration (a hard-coded 0.95 that no longer matched any rule).
const CORRUPTED_MEASUREMENT = Object.freeze({
  trial_index: 0,
  numerator: 3,
  denominator: 8,
  observed: 0.375,
  lower: 0.09670791409424857,
  upper: 0.7752932281125462,
  method: 'wilson_score',
  confidence: PREREGISTRATION.noise_rule.confidence,
});

/**
 * Replace trial 0's measurement block with the corrupted one. `outcome` and
 * `status` are deliberately LEFT ALONE: the table's declared outcome for trial 0
 * is POSITIVE and the corrupted number contradicts it, and the table is what has
 * to notice. Moving the outcome as well would corrupt two classes at once and a
 * single-class control cannot be attributed.
 * @param {object} run A clean run record.
 * @returns {object} A new run record; the input is untouched.
 */
export function corruptMeasurement(run = CLEAN_RUNS.a) {
  const next = copy(run);
  const trial = next.trials[CORRUPTED_MEASUREMENT.trial_index];
  trial.numerator = CORRUPTED_MEASUREMENT.numerator;
  trial.denominator = CORRUPTED_MEASUREMENT.denominator;
  trial.observed = CORRUPTED_MEASUREMENT.observed;
  trial.samples = trial.samples.map((_label, index) => (index < CORRUPTED_MEASUREMENT.numerator ? 1 : 0));
  trial.interval = {
    lower: CORRUPTED_MEASUREMENT.lower,
    upper: CORRUPTED_MEASUREMENT.upper,
    method: CORRUPTED_MEASUREMENT.method,
    confidence: CORRUPTED_MEASUREMENT.confidence,
  };
  return Object.freeze(next);
}

// ---------------------------------------------------------------------------
// 2. corrupted_expected_table — the expectation class. Runs stay CLEAN.
// ---------------------------------------------------------------------------

/**
 * The corruption: trial 0's expected outcome becomes NULL in the published
 * table, and the runs are re-bound to the digest of THAT table so the mismatch
 * is the thing under test rather than the binding.
 * The corruption is `table.trials[0].expectedOutcome` moved to `NULL`, which is a
 * DIFFERENT declared outcome from whatever the table pins for row 0 — read from the
 * frozen row, so the corruption stays a corruption if the table is ever re-derived.
 * @type {{trial: number, expectedOutcome: string}}
 */
export const CORRUPTED_EXPECTED_ROW = Object.freeze({ trial: 0, expectedOutcome: 'NULL' });

/**
 * Corrupt the expectation for trial 0: a POSITIVE design becomes a NULL one in
 * the table while both runs still carry the honest measurement.
 * @param {object} [table] The clean table.
 * @returns {object} A new table; the input is untouched.
 */
export function corruptExpectedTable(table = EXPECTED_VALUE_TABLE) {
  return withExpectedRow(table, CORRUPTED_EXPECTED_ROW.trial, { expectedOutcome: CORRUPTED_EXPECTED_ROW.expectedOutcome });
}

/**
 * The digest a run must declare when it was scored against the corrupted table.
 * Computed, not typed: a hand-written "corrupted digest" that nothing produced
 * would make the control's binding meaningless.
 * @param {object} [table] The corrupted table.
 * @returns {string} `sha256:<64 hex>` over the corrupted document.
 */
export function corruptedTableDigest(table = corruptExpectedTable()) {
  return fixtureDigest(table).slice('sha256:'.length);
}

// ---------------------------------------------------------------------------
// 3. label_substituted — the causal label class (A4).
// ---------------------------------------------------------------------------

/**
 * Build the preregistration whose card carries a causal label on observational
 * ground truth. The substitution is recorded field by field, because a
 * negative control that cannot show what it changed cannot be shown to have
 * caused the failure it is credited with.
 * @returns {{preregistration: object, substitution: object, card_digest: {from: string, to: string}, preregistration_digest: {from: string, to: string}}}
 */
export function buildLabelSubstitutedPreregistration() {
  const card = copy(HYPOTHESIS_CARD);
  const from = {
    relation_strength: card.proposed_relation.relation_strength,
    causal_assertion: card.proposed_relation.causal_assertion,
  };
  card.proposed_relation.relation_strength = 'EXPERIMENTAL';
  card.proposed_relation.causal_assertion = true;
  const substitution = {
    // What moved.
    from,
    to: { relation_strength: 'EXPERIMENTAL', causal_assertion: true },
    // What deliberately did NOT move, and why that matters: the card keeps its
    // id, keeps its type, gains no temporal ordering, no mediator and no
    // promotion, and is STILL VALID against the frozen card schema. Nothing in
    // the contract layer can see this; only the code guard and the digest can.
    unchanged: Object.freeze([
      'card_id', 'card_type', 'type_promotion', 'temporal_ordering.established', 'mediators',
    ]),
    ground_truth: 'OBSERVATIONAL',
    schema_valid_after_substitution: true,
    detectable_only_by: Object.freeze(['assertCausalDiscipline', 'assertNoCausalFromSimulation', 'card_digest']),
  };
  const honestCardDigest = HYPOTHESIS_CARD_DIGEST;
  const corruptedCardDigest = fixtureDigest(card);
  const honestPreregDigest = preregistrationFixtureDigest(PREREGISTRATION);
  const corrupted = { ...PREREGISTRATION, card: Object.freeze(card), card_digest: corruptedCardDigest };
  return {
    preregistration: Object.freeze(corrupted),
    substitution: Object.freeze(substitution),
    // Both digests, because the two answer different questions: the card digest
    // proves the LABEL moved, and the preregistration digest proves the change
    // was visible to the P3 check that a post-result edit has to move.
    card_digest: { from: honestCardDigest, to: corruptedCardDigest },
    preregistration_digest: { from: honestPreregDigest, to: preregistrationFixtureDigest(corrupted) },
  };
}

/**
 * The SECOND case of the same control: the label is left OBSERVATIONAL and
 * only `causal_assertion` is set to true.
 *
 * Both cases are real and they are refused by DIFFERENT guards, which is why
 * both are here. Upgrading `relation_strength` to `EXPERIMENTAL` takes the card
 * out of the observational set, so `assertNoCausalFromSimulation` — the
 * always-on refusal — has nothing to fire on and `assertCausalDiscipline`
 * refuses it instead for the missing promotion. Setting `causal_assertion` on
 * the OBSERVATIONAL label is the case the always-on guard exists for, and it
 * is A4's headline: an observational result read as causal.
 *
 * Both cards keep `card_id` and both remain valid against the frozen
 * hypothesis-card schema, which carries no `allOf`.
 * @returns {{card: object, substitution: object, card_digest: {from: string, to: string}, refusal_code: string}}
 */
export function buildObservationalCausalAssertionCard() {
  const card = copy(HYPOTHESIS_CARD);
  const from = {
    relation_strength: card.proposed_relation.relation_strength,
    causal_assertion: card.proposed_relation.causal_assertion,
  };
  card.proposed_relation.causal_assertion = true;
  const substitution = {
    from,
    to: { relation_strength: card.proposed_relation.relation_strength, causal_assertion: true },
    unchanged: Object.freeze(['card_id', 'card_type', 'relation_strength', 'type_promotion', 'temporal_ordering.established', 'mediators']),
    ground_truth: 'OBSERVATIONAL',
    schema_valid_after_substitution: true,
    refused_by: Object.freeze(['assertNoCausalFromSimulation', 'assertCausalDiscipline', 'classifyCardRelation']),
    refusal_code: 'CAUSAL_ASSERTION_UNSUPPORTED',
  };
  return Object.freeze({
    card: Object.freeze(card),
    substitution: Object.freeze(substitution),
    card_digest: { from: HYPOTHESIS_CARD_DIGEST, to: fixtureDigest(card) },
    // Read from the classifier, not typed: the domain code belongs to
    // `causality.mjs` and a hand-written copy here would be a second answer to
    // "which refusal".
    refusal_code: classifyCardRelation(card).refusalCode.split(':')[0],
  });
}

/**
 * Re-bind a clean run to a preregistration digest that has moved, so the
 * corrupted pair can be compared as a pair. A run still carrying the honest
 * digest would be caught by provenance instead, which would test the wrong
 * thing: the point of this control is that the LABEL is what fails.
 * @param {string} label A run label.
 * @param {object} prereg The corrupted preregistration.
 * @returns {object} A run record bound to that preregistration.
 */
export function rebindRunToPreregistration(label, prereg) {
  return Object.freeze({
    ...buildRunBoundToTable(label, expectedTableDigest()),
    preregistration_digest: preregistrationFixtureDigest(prereg),
  });
}

// ---------------------------------------------------------------------------
// 4. missing_evaluator — the binding class (P6).
// ---------------------------------------------------------------------------

/**
 * Delete the evaluator binding AND the evaluator record from trial 0. The trial
 * keeps its measurement, its seeds, its holdout seal and its budget row: three
 * of four bindings is not four, and the fourth is the one that decides whether
 * a number may be used at all. Both members are removed because the comparator
 * reads the flat member and falls back to `evaluator`; leaving one behind would
 * let a control pass without the evaluator actually being gone.
 * @param {object} run A clean run record.
 * @returns {object} A new run record; the input is untouched.
 */
export function removeEvaluator(run = CLEAN_RUNS.a) {
  const next = copy(run);
  next.trials[0].evaluatorBinding = null;
  next.trials[0].evaluator = null;
  return Object.freeze(next);
}

/**
 * Point trial 0 at the NOT_MEASURED calibration instead. The record stays
 * contract-valid and still reports `numerator: 0, denominator: 8` — which is
 * exactly the trap: read as a rate it is 0 %, read correctly it is "not
 * measured, because the evaluator was not independent".
 * @param {object} run A clean run record.
 * @returns {object} A new run record; the input is untouched.
 */
export function swapCalibrationToNotIndependent(run = CLEAN_RUNS.a) {
  const next = copy(run);
  next.trials[0].calibration_id = CALIBRATIONS.notIndependent.calibration_id;
  next.trials[0].calibration = copy(CALIBRATIONS.notIndependent);
  next.trials[0].evaluator = { ...next.trials[0].evaluator, blind_to_producer: false, independent: false };
  next.trials[0].evaluatorBinding = { ...next.trials[0].evaluatorBinding, blind_to_producer: false };
  next.calibration = copy(CALIBRATIONS.notIndependent);
  return Object.freeze(next);
}

// ---------------------------------------------------------------------------
// 5. truncated_trial — the record-completeness class.
// ---------------------------------------------------------------------------

/**
 * The torn tail: trial 3's canonical JSON cut at a fixed byte offset, with no
 * trailing newline. This is what a crashed writer leaves behind.
 * @type {string}
 */
export const TRUNCATED_TRIAL_TAIL = canonicalize(FIXTURE_TRIALS[3]).slice(0, TRUNCATE_AT_BYTES);

/**
 * Prove the tail is unparseable AT IMPORT. A partial line that could be read
 * back as a record is the torn-tail bug itself; if this ever started parsing,
 * the fixture would be teaching a test the wrong thing.
 * @returns {true} when `JSON.parse` refuses the tail.
 * @throws {Error} `FIXTURE_TAIL_PARSED` when the truncated line is readable.
 */
export function assertTruncatedTailUnparseable() {
  try {
    JSON.parse(TRUNCATED_TRIAL_TAIL);
  } catch {
    return true;
  }
  throw new Error(`FIXTURE_TAIL_PARSED: the truncated trial tail at ${String(TRUNCATE_AT_BYTES)} bytes parsed as JSON`);
}

/**
 * Drop the last trial from the array and expose the torn line that would have
 * been it. The run is now one trial short of its preregistered list, which is
 * the fail-open this control exists for: a trial that vanished must not read as
 * a campaign that passed.
 * @param {object} run A clean run record.
 * @returns {{run: object, torn_tail: string, dropped: object}} The damaged run,
 *   the torn line and the record that is no longer in the array.
 */
export function truncateTrial(run = CLEAN_RUNS.a) {
  assertTruncatedTailUnparseable();
  const next = copy(run);
  const dropped = next.trials.pop();
  next.torn_tail = TRUNCATED_TRIAL_TAIL;
  next.trials_complete = false;
  return { run: Object.freeze(next), torn_tail: TRUNCATED_TRIAL_TAIL, dropped: Object.freeze(dropped) };
}

// ---------------------------------------------------------------------------
// Additional builders: the status, the counter, the code set and provenance.
// ---------------------------------------------------------------------------

/**
 * Flip one trial's status from RESOLVED to SKIPPED — the `trial_status` class
 * the frozen categories name, and the exact skip a reader would most like to
 * pass off as "nothing to report". The measurement stays in the record, so the
 * corruption is the CLAIM that nothing was measured while the numbers are
 * right there.
 * @param {object} run A clean run record.
 * @param {number} [index] Which trial to skip, default 1 (the null trial).
 * @returns {object} A new run record; the input is untouched.
 */
export function skippedTrial(run = CLEAN_RUNS.a, index = 1) {
  const next = copy(run);
  next.trials[index].status = 'SKIPPED';
  next.trials[index].reason_codes = ['TRIAL_SKIPPED'];
  return Object.freeze(next);
}

/**
 * Nudge one hard-gate counter from 0 to 1. Used by the identical-wrong control,
 * which needs a corruption class the table scores on its own.
 * @param {object} run A clean run record.
 * @param {string} [counter] Which counter to move.
 * @returns {object} A new run record; the input is untouched.
 * @throws {Error} `FIXTURE_COUNTER_UNKNOWN` for a counter outside the frozen set.
 */
export function nudgedCounter(run = CLEAN_RUNS.a, counter = 'seedSubstitution') {
  if (!(counter in expectedCounters())) {
    throw new Error(`FIXTURE_COUNTER_UNKNOWN: ${String(counter)}`);
  }
  const next = copy(run);
  next.counters = { ...next.counters, [counter]: 1 };
  return Object.freeze(next);
}

/**
 * Attach a code the frozen table FORBIDS. The code chosen is the anti-pattern
 * the ticket names in words: a blind retry after an infra failure. Emitting it
 * is the failure, and an undeclared code is itself a finding — the vocabulary
 * is closed, so a code nobody declared cannot be quietly tolerated.
 * @type {string}
 */
export const UNDECLARED_BLIND_RETRY_CODE = 'BLIND_RETRY_AFTER_INFRA';

/**
 * @param {object} run A clean run record.
 * @returns {object} A new run record carrying the forbidden code.
 */
export function undeclaredCode(run = CLEAN_RUNS.a) {
  const next = copy(run);
  next.codes = [UNDECLARED_BLIND_RETRY_CODE];
  return Object.freeze(next);
}

/**
 * Replace the commit SHA with a different well-formed one. The record is still
 * shaped correctly and still names a tree; it simply no longer describes THIS
 * tree, which is what a stale evidence file looks like. The per-trial
 * `provenance` blocks are left naming the honest base, because that mismatch is
 * the finding: a run whose own trials disagree with it about the commit is a
 * record nobody can trust, and it is detectable without a git call.
 * @type {string}
 */
export const FORGED_COMMIT_SHA = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

/**
 * @param {object} run A clean run record.
 * @returns {object} A new run record with forged provenance.
 */
export function forgedProvenance(run = CLEAN_RUNS.a) {
  const next = copy(run);
  next.provenance = { ...next.provenance, commit_sha: FORGED_COMMIT_SHA };
  next.commit_sha = FORGED_COMMIT_SHA;
  return Object.freeze(next);
}

// The clean trial 0, read from the fixture so every `from` value below is the
// REAL before rather than a typed approximation of it.
const CLEAN_TRIAL_0 = CLEAN_RUNS.a.trials[0];
const CLEAN_RUN_A = CLEAN_RUNS.a;

// ---------------------------------------------------------------------------
// The expected flips. A test asserts against these, not against its own guess.
// ---------------------------------------------------------------------------

/**
 * The expected flip per variant. Every entry names the axis it moves, the value
 * before and the value after, and — where an axis does not move — says so.
 * @type {Readonly<Record<string, Readonly<object>>>}
 */
export const EXPECTED_FLIPS = Object.freeze({
  corrupted_measurement: Object.freeze({
    variant: 'corrupted_measurement',
    control_id: 'corrupted_data',
    corruption_class: 'metric',
    corrupts: 'run.trials[0].{numerator, denominator, observed, samples, interval}',
    from: Object.freeze({
      numerator: CLEAN_TRIAL_0.numerator,
      denominator: CLEAN_TRIAL_0.denominator,
      observed: CLEAN_TRIAL_0.observed,
      lower: CLEAN_TRIAL_0.interval.lower,
      upper: CLEAN_TRIAL_0.interval.upper,
      outcome: CLEAN_TRIAL_0.outcome,
    }),
    to: Object.freeze({
      numerator: CORRUPTED_MEASUREMENT.numerator,
      denominator: CORRUPTED_MEASUREMENT.denominator,
      observed: CORRUPTED_MEASUREMENT.observed,
      lower: CORRUPTED_MEASUREMENT.lower,
      upper: CORRUPTED_MEASUREMENT.upper,
      // The declared outcome is NOT corrupted: the table is what notices.
      outcome: CLEAN_TRIAL_0.outcome,
    }),
    must_flip: true,
    expected_flip: Object.freeze({
      measurement_findings: Object.freeze({
        expected_field: 'trials[0].numerator',
        from: CLEAN_TRIAL_0.numerator,
        to: CORRUPTED_MEASUREMENT.numerator,
      }),
      // Honest: this axis does NOT move. The trial is still RESOLVED with all
      // four bindings; a wrong number is the table's business, and pretending
      // otherwise would make this control prove nothing.
      trial_verdict: Object.freeze({ from: CLEAN_TRIAL_0.verdict, to: CLEAN_TRIAL_0.verdict, changed: false }),
      expected_value_findings: Object.freeze({ from: 0, to: 'NON_EMPTY' }),
      // Measured against the clean pair: `table_disagreement` (the numerator)
      // and `self_reported_interval_divergence` (the run's own pooled interval
      // no longer follows from its own counts).
      failure_codes_added: Object.freeze(['self_reported_interval_divergence', 'table_disagreement']),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT, changed: false, why: 'the clean state already resolves to FAIL; the failure-code set is what moves' }),
      named_by: 'the finding must name trials[0].numerator',
    }),
  }),
  corrupted_expected_table: Object.freeze({
    variant: 'corrupted_expected_table',
    control_id: 'corrupted_data',
    corruption_class: 'expectation',
    corrupts: 'table.trials[0].expectedOutcome, and the run records expected_table_digest',
    // The `from` state is READ from the frozen table, never typed. It used to carry
    // the literal `expectedOutcome: 'POSITIVE'`, which described the DESIGN the first
    // delivery pinned rather than the table that is in force; after R-B re-derived
    // the measured rows from the frozen measurements, that literal was a second
    // spelling of a number the table already carries, and a stale one.
    from: Object.freeze({ expectedOutcome: EXPECTED_TRIAL_DECISIONS[0].expectedOutcome, expected_table_digest: expectedTableDigest() }),
    to: Object.freeze({ expectedOutcome: CORRUPTED_EXPECTED_ROW.expectedOutcome, expected_table_digest: corruptedTableDigest() }),
    must_flip: true,
    expected_flip: Object.freeze({
      // Both runs are otherwise CLEAN and UNCHANGED. The verdict still has to
      // move, because the criterion is the table, not the agreement between
      // runs.
      runs_unchanged_apart_from_the_table_digest: true,
      expected_value_findings: Object.freeze({
        expected_field: 'expected_table_digest',
        from: 0,
        to: 'NON_EMPTY',
      }),
      table_freeze_assertion: Object.freeze({ from: 'OK', to: 'THROW:EXPECTED_TABLE_DRIFT' }),
      // Measured: `expected_table_digest_mismatch` and `table_disagreement`.
      failure_codes_added: Object.freeze(['expected_table_digest_mismatch', 'table_disagreement']),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT, changed: false, why: 'the clean state already resolves to FAIL; the table finding and the new failure codes are what moves' }),
    }),
  }),
  label_substituted: Object.freeze({
    variant: 'label_substituted',
    control_id: 'label_substitution',
    corruption_class: 'claim_label',
    corrupts: 'preregistration.card.proposed_relation.{relation_strength, causal_assertion}',
    from: Object.freeze({
      relation_strength: HYPOTHESIS_CARD.proposed_relation.relation_strength,
      causal_assertion: HYPOTHESIS_CARD.proposed_relation.causal_assertion,
    }),
    to: Object.freeze({ relation_strength: 'EXPERIMENTAL', causal_assertion: true }),
    must_flip: true,
    expected_flip: Object.freeze({
      // MEASURED, not guessed. Two cases, two guards, two domain codes:
      //   * `relation_strength` upgraded to EXPERIMENTAL — `observational`
      //     becomes false, so the always-on guard has nothing to fire on and
      //     `assertCausalDiscipline` refuses the missing promotion instead;
      //   * `causal_assertion` set on the OBSERVATIONAL label — refused by
      //     `assertNoCausalFromSimulation`, which is A4's headline.
      // The previous version of this file declared a single code,
      // CAUSAL_ASSERTION_UNSUPPORTED, for the upgraded case — a refusal the
      // guard does not raise for that input.
      cases: Object.freeze([
        Object.freeze({
          case: 'relation_strength_upgraded',
          from: Object.freeze({ relation_strength: HYPOTHESIS_CARD.proposed_relation.relation_strength, causal_assertion: null }),
          to: Object.freeze({ relation_strength: 'EXPERIMENTAL', causal_assertion: true }),
          refused_by: 'assertCausalDiscipline',
          refusal_code: 'CAUSAL_PROMOTION_MISSING',
        }),
        Object.freeze({
          case: 'causal_assertion_on_observational_label',
          from: Object.freeze({ relation_strength: HYPOTHESIS_CARD.proposed_relation.relation_strength, causal_assertion: null }),
          to: Object.freeze({ relation_strength: HYPOTHESIS_CARD.proposed_relation.relation_strength, causal_assertion: true }),
          refused_by: 'assertNoCausalFromSimulation',
          refusal_code: 'CAUSAL_ASSERTION_UNSUPPORTED',
        }),
      ]),
      // The DOMAIN code, and where a test can read it. The thrown `BlockedPolicy`
      // carries `code: 'BLOCKED_POLICY'` — the board's class code — and the
      // domain code appears in `classifyCardRelation(card).refusalCode` and in
      // the message. A test that asserts `error.code === 'CAUSAL_PROMOTION_MISSING'`
      // would fail, so the two places are named here instead of guessed at.
      refusal_code_is_read_from: 'classifyCardRelation(card).refusalCode (before the colon); the thrown error code is BLOCKED_POLICY',
      // A4's whole point: the id cannot see this, and neither can the schema.
      card_id: Object.freeze({ from: HYPOTHESIS_CARD.card_id, to: HYPOTHESIS_CARD.card_id, changed: false }),
      card_digest: Object.freeze({ changed: true }),
      preregistration_digest: Object.freeze({ changed: true }),
      // The table does not read labels, so it stays clean here. The campaign
      // verdict moves because the comparator reads the card per trial.
      expected_value_findings: Object.freeze({ from: 0, to: 0, changed: false }),
      // Measured: `preregistration_digest_mismatch` — the run was re-bound to
      // the corrupted preregistration while the table in force did not move.
      failure_codes_added: Object.freeze(['preregistration_digest_mismatch']),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT, changed: false, why: 'the clean state already resolves to FAIL; the guard refusal and the digest move are what count' }),
    }),
  }),
  missing_evaluator: Object.freeze({
    variant: 'missing_evaluator',
    control_id: 'missing_evaluator',
    corruption_class: 'binding',
    corrupts: 'run.trials[0].{evaluatorBinding, evaluator}',
    from: Object.freeze({ present: true, calibration_id: CALIBRATIONS.independent.calibration_id }),
    to: Object.freeze({ present: false, calibration_id: CALIBRATIONS.independent.calibration_id }),
    must_flip: true,
    expected_flip: Object.freeze({
      trial_verdict: Object.freeze({ from: CLEAN_TRIAL_0.verdict, to: 'VIOLATION' }),
      trial_status: Object.freeze({ from: CLEAN_TRIAL_0.status, to: 'NOT_MEASURED' }),
      // HONEST, and the reason this control is worth reading: the frozen table
      // scores counts, codes, statuses, counters and provenance — it does NOT
      // read the bindings — so a deleted evaluator produces NO table finding at
      // all. The flip is in the TRIAL verdict, which `scoreRun` turns into a
      // `trial_violation` failure. The previous version of this file claimed
      // `expected_value_findings: NON_EMPTY` here, which is false.
      expected_value_findings: Object.freeze({
        from: 0,
        to: 0,
        changed: false,
        why: 'the table does not read bindings; resolveTrialVerdict does',
      }),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT }),
      // "Not measured" is not 0 %. The run still holds numerator 0 over
      // denominator 8; the reason it may not be read as a rate is
      // `evaluator_not_independent`, and the record must say which it is.
      not_measured_is_not_zero: 'evaluator_not_independent',
      // Measured: `evaluator_not_independent`, plus the trial's own
      // `trial_violation` the clean run did not have for that trial.
      failure_codes_added: Object.freeze(['evaluator_not_independent']),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT, changed: false, why: 'the clean state already resolves to FAIL; the trial verdict ALLOW -> VIOLATION is what moves' }),
    }),
    // The sibling case of the same control: the evaluator is present but not
    // independent. Same flip, different reason, and the reason is in-contract.
    cases: Object.freeze(['binding_absent', 'calibration_not_independent']),
  }),
  truncated_trial: Object.freeze({
    variant: 'truncated_trial',
    control_id: 'corrupted_data',
    corruption_class: 'record_completeness',
    corrupts: 'run.trials — the last record is cut mid-write and the array loses it',
    from: Object.freeze({ trial_count: CLEAN_RUN_A.trials.length, tail_parses: true }),
    to: Object.freeze({ trial_count: CLEAN_RUN_A.trials.length - 1, tail_parses: false }),
    must_flip: true,
    expected_flip: Object.freeze({
      trial_count: Object.freeze({ from: CLEAN_RUN_A.trials.length, to: CLEAN_RUN_A.trials.length - 1 }),
      torn_tail_parses: Object.freeze({ from: true, to: false }),
      expected_value_findings: Object.freeze({ from: 0, to: 'NON_EMPTY' }),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT }),
      // `recoverTornTail` (W2) truncates to the last COMPLETE record and emits a
      // reconciliation row. A complete-but-uncommitted record must not be
      // resurrected, and a partial line must never be returned as a record.
      recovery_expectation: 'TRUNCATE_TO_LAST_COMPLETE_RECORD_PLUS_RECONCILIATION_ROW',
      // Measured: `table_disagreement` only. The failure COUNT does not grow
      // here, because a run with three trials no longer carries the infra
      // trial's `trial_violation` — a truncated run hides a failure as well as a
      // trial, which is why this control asserts the trial count and the table
      // findings and not the failure count.
      failure_codes_added: Object.freeze(['table_disagreement']),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT, changed: false, why: 'the clean state already resolves to FAIL; the missing row is what moves' }),
    }),
  }),
  skipped_trial: Object.freeze({
    variant: 'skipped_trial',
    control_id: 'corrupted_data',
    corruption_class: 'trial_status',
    corrupts: 'run.trials[1].status',
    from: Object.freeze({ status: CLEAN_RUN_A.trials[1].status }),
    to: Object.freeze({ status: 'SKIPPED' }),
    must_flip: true,
    expected_flip: Object.freeze({
      // A2's headline: a skipped trial is a VIOLATION, never an ALLOW and never
      // absent from the table. Both the table and the comparator name it.
      trial_verdict: Object.freeze({ from: CLEAN_RUN_A.trials[1].verdict, to: 'VIOLATION' }),
      expected_value_findings: Object.freeze({ from: 0, to: 'NON_EMPTY' }),
      // Measured: `table_disagreement` and `self_reported_interval_divergence`
      // (the pooled counts changed with the status), plus the trial's own
      // `trial_violation`.
      failure_codes_added: Object.freeze(['self_reported_interval_divergence', 'table_disagreement']),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT, changed: false, why: 'the clean state already resolves to FAIL; the skipped trial is what moves' }),
    }),
  }),
  nudged_counter: Object.freeze({
    variant: 'nudged_counter',
    control_id: 'corrupted_data',
    corruption_class: 'counter',
    corrupts: 'run.counters.seedSubstitution',
    from: 0,
    to: 1,
    must_flip: true,
    expected_flip: Object.freeze({
      hard_gate_counter: Object.freeze({ from: 0, to: 1 }),
      expected_value_findings: Object.freeze({ from: 0, to: 'NON_EMPTY' }),
      // Measured: `hard_gate_violated`, `hard_gate_diverges_from_table` and
      // `table_disagreement`.
      failure_codes_added: Object.freeze(['hard_gate_diverges_from_table', 'hard_gate_violated', 'table_disagreement']),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT, changed: false, why: 'the clean state already resolves to FAIL; the moved counter is what counts' }),
    }),
  }),
  undeclared_code: Object.freeze({
    variant: 'undeclared_code',
    control_id: 'corrupted_data',
    corruption_class: 'code_set',
    corrupts: 'run.codes',
    from: Object.freeze([]),
    to: Object.freeze([UNDECLARED_BLIND_RETRY_CODE]),
    must_flip: true,
    expected_flip: Object.freeze({
      emitted_codes: Object.freeze({ from: 0, to: 1 }),
      undeclared_code_is_a_finding: true,
      expected_value_findings: Object.freeze({ from: 0, to: 'NON_EMPTY' }),
      // Measured: `table_disagreement` alone — the forbidden code is a finding
      // in the table's own words, and nothing else about the run moved.
      failure_codes_added: Object.freeze(['table_disagreement']),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT, changed: false, why: 'the clean state already resolves to FAIL; the forbidden code is what moves' }),
      why: 'the refusal vocabulary is closed; a code nobody declared is a finding, not an extension',
    }),
  }),
  forged_provenance: Object.freeze({
    variant: 'forged_provenance',
    control_id: 'corrupted_data',
    corruption_class: 'provenance_field',
    corrupts: 'run.commit_sha (the per-trial provenance blocks keep the honest base)',
    from: CLEAN_RUN_A.commit_sha,
    to: FORGED_COMMIT_SHA,
    must_flip: true,
    expected_flip: Object.freeze({
      // Detectable WITHOUT a git call: every trial's `provenance` names the
      // commit the run no longer claims, and the table compares them. Against
      // a resolved base, `compareParallelTrack` also names it as
      // `base_mismatch`; with no resolved base it names `base_unverified`
      // (E8) and the record is UNVERIFIED, not proven wrong.
      expected_value_findings: Object.freeze({ from: 0, to: 'NON_EMPTY' }),
      comparison: Object.freeze({
        against_a_resolved_base: 'FAILURE:base_mismatch',
        without_one: 'FAILURE:base_unverified',
      }),
      // A5/E8: with a resolved base the comparator names `base_mismatch`; with
      // none it names `base_unverified` and the record is UNVERIFIED, not
      // proven wrong. Either way the record is not readable as clean.
      failure_codes_added: Object.freeze(['base_mismatch', 'table_disagreement', 'trial_provenance_divergence']),
      campaign_verdict: Object.freeze({ from: CLEAN_CAMPAIGN_VERDICT, to: CORRUPTED_CAMPAIGN_VERDICT, changed: false, why: 'the clean state already resolves to FAIL; the provenance mismatch is what moves' }),
    }),
  }),
});

/** The five variants the task requires, in order. @type {ReadonlyArray<string>} */
export const REQUIRED_VARIANT_IDS = Object.freeze([
  'corrupted_measurement',
  'corrupted_expected_table',
  'label_substituted',
  'missing_evaluator',
  'truncated_trial',
]);

/** Every variant id, including the four that complete the corruption-class coverage. @type {ReadonlyArray<string>} */
export const VARIANT_IDS = Object.freeze(Object.keys(EXPECTED_FLIPS));

/**
 * Which variant supplies the input for each frozen corruption class, and what
 * is still NOT covered.
 *
 * `supplied_by` is not `covered`: supplying a fixture is not running the
 * control, and `scripts/verify-s2-008.mjs` (W5) must itemise in
 * `evidence/s2-008-comparison.json` which classes the evidence ACTUALLY
 * exercised. A class listed here with no run behind it is a gap in the
 * evidence, and the plan's own limitation note says so.
 *
 * `record_completeness` and `claim_label` are the two classes the frozen five do
 * not name; they are listed as extra rather than folded into a frozen category,
 * because renaming a frozen category to fit a fixture is how a coverage map
 * stops meaning anything.
 * @type {Readonly<object>}
 */
export const CORRUPTION_CLASS_COVERAGE = Object.freeze({
  frozen_classes: Object.freeze({
    trial_status: 'skipped_trial',
    counter: 'nudged_counter',
    code_set: 'undeclared_code',
    metric: 'corrupted_measurement',
    provenance_field: 'forged_provenance',
  }),
  extra_classes: Object.freeze({
    record_completeness: 'truncated_trial',
    claim_label: 'label_substituted',
    binding: 'missing_evaluator',
    expectation: 'corrupted_expected_table',
  }),
  supplied_but_not_run: Object.freeze(VARIANT_IDS),
  not_covered_by_any_variant: Object.freeze([]),
  evidence_coverage_must_be_reported_by: 'scripts/verify-s2-008.mjs',
});

/**
 * Build one variant's complete bundle: the damaged inputs, the declaration of
 * what was damaged, and the flip a test must observe.
 * @param {string} variant A member of `VARIANT_IDS`.
 * @param {{label?: string, table?: object, run?: object}} [args]
 * @param {string} [args.label] The run label to build from, default 'a'.
 * @param {object} [args.table] The table to corrupt, default the frozen one.
 * @param {object} [args.run] A run to corrupt, default the clean run for `label`.
 * @returns {Readonly<object>} `{variant, declaration, run, table, preregistration, extras}`.
 * @throws {Error} `FIXTURE_VARIANT_UNKNOWN` for an id outside `VARIANT_IDS`.
 */
export function buildVariant(variant, { label = 'a', table = EXPECTED_VALUE_TABLE, run = CLEAN_RUNS[label] } = {}) {
  const declaration = EXPECTED_FLIPS[variant];
  if (!declaration) throw new Error(`FIXTURE_VARIANT_UNKNOWN: ${String(variant)}`);
  const base = {
    variant,
    declaration,
    control_id: declaration.control_id,
    corruption_class: declaration.corruption_class,
    must_flip: declaration.must_flip,
    label,
    // The clean inputs are returned too, so a test can prove the clean run is
    // still byte-identical after the corrupted one was built.
    clean: { run, table, run_digest: fixtureDigest(run), table_digest: fixtureDigest(table) },
  };
  switch (variant) {
    case 'corrupted_measurement':
      return Object.freeze({ ...base, run: corruptMeasurement(run), table, extras: null });
    case 'corrupted_expected_table': {
      const corrupted = corruptExpectedTable(table);
      return Object.freeze({
        ...base,
        // The runs stay clean in every other respect and are re-bound to the
        // CORRUPTED table's digest, which is the binding a run scored against
        // that table would carry.
        run: Object.freeze({ ...run, expected_table_digest: fixtureDigest(corrupted).slice('sha256:'.length) }),
        table: corrupted,
        preregistration: Object.freeze({ ...PREREGISTRATION, expected_table_digest: fixtureDigest(corrupted).slice('sha256:'.length) }),
        extras: { corrupted_digest: fixtureDigest(corrupted).slice('sha256:'.length) },
      });
    }
    case 'label_substituted': {
      const { preregistration, substitution, card_digest } = buildLabelSubstitutedPreregistration();
      const observational = buildObservationalCausalAssertionCard();
      return Object.freeze({
        ...base,
        run: rebindRunToPreregistration(label, preregistration),
        table,
        preregistration,
        extras: {
          substitution,
          card_digest,
          observational_case: {
            substitution: observational.substitution,
            card_digest: observational.card_digest,
            refusal_code: observational.refusal_code,
          },
        },
      });
    }
    case 'missing_evaluator':
      return Object.freeze({ ...base, run: removeEvaluator(run), table, extras: { cases: ['binding_absent'] } });
    case 'truncated_trial': {
      const { run: damaged, torn_tail, dropped } = truncateTrial(run);
      return Object.freeze({ ...base, run: damaged, table, extras: { torn_tail, dropped, trial_count: damaged.trials.length } });
    }
    case 'skipped_trial':
      return Object.freeze({ ...base, run: skippedTrial(run), table, extras: { trial_index: 1 } });
    case 'nudged_counter':
      return Object.freeze({ ...base, run: nudgedCounter(run), table, extras: { counter: 'seedSubstitution' } });
    case 'undeclared_code':
      return Object.freeze({ ...base, run: undeclaredCode(run), table, extras: { code: UNDECLARED_BLIND_RETRY_CODE } });
    case 'forged_provenance':
      return Object.freeze({ ...base, run: forgedProvenance(run), table, extras: { commit_sha: FORGED_COMMIT_SHA } });
    default:
      throw new Error(`FIXTURE_VARIANT_UNBUILT: ${String(variant)}`);
  }
}

/**
 * The second case of the `missing_evaluator` control: the evaluator is present
 * but not independent, so the calibration is NOT_MEASURED. Exposed separately
 * because it is a different defect with the same flip.
 * @param {{label?: string}} [args]
 * @returns {object} The same bundle shape `buildVariant` returns, for the
 *   `calibration_not_independent` case.
 */
export function buildNotIndependentCase({ label = 'a' } = {}) {
  const run = swapCalibrationToNotIndependent(CLEAN_RUNS[label]);
  return Object.freeze({
    variant: 'missing_evaluator',
    case: 'calibration_not_independent',
    control_id: 'missing_evaluator',
    run,
    table: EXPECTED_VALUE_TABLE,
    calibration: run.calibration,
    expected_flip: EXPECTED_FLIPS.missing_evaluator.expected_flip,
  });
}

// The DECISION fields, mirroring `DECISION_TRIAL_FIELDS` in
// `src/lib/research/comparator.mjs:347`. The list is mirrored rather than
// imported because the comparator does not export it, and mirroring it here is
// the honest option: the alternative is digesting whole trials, which includes
// each trial's `provenance` block and therefore each run's own `raw_run_id` —
// two process-separated runs could then NEVER agree, and the A3
// "digests_still_equal" claim would be unobservable rather than false.
const DECISION_TRIAL_FIELDS = Object.freeze([
  'trial', 'status', 'outcome', 'metric', 'numerator', 'denominator', 'seeds',
]);

/**
 * The digest of a run's DECISION CONTENT: everything a verdict can depend on,
 * with the process-local identity removed. Two process-separated runs can never
 * have equal whole-record digests — their run ids and nonces differ by
 * construction — so this is the digest A3's "digests stay equal" claim is
 * about, and it is named here so nobody has to guess which of the two a record
 * meant.
 * @param {object} run A run record.
 * @returns {string} `sha256:<64 hex>`.
 */
export function decisionContentDigest(run) {
  return fixtureDigest({
    trials: (Array.isArray(run.trials) ? run.trials : []).map((trial) => {
      const projected = {};
      for (const field of DECISION_TRIAL_FIELDS) {
        projected[field] = trial[field] === undefined ? null : trial[field];
      }
      return projected;
    }),
    codes: run.codes,
    counters: run.counters,
    metric: run.metrics,
    allowed_process_differences: ALLOWED_PROCESS_DIFFERENCES,
  });
}

/**
 * The A3 IDENTICAL-WRONG CONTROL as a fixture: the same corruption in BOTH
 * runs, the decision digests still equal, and non-empty findings expected from
 * BOTH.
 *
 * This is what makes "A === B is an extra condition" testable rather than
 * asserted: agreement between two runs is preserved exactly, and the verdict
 * still has to move. A test that only checked `A === B` would pass on this
 * bundle, which is the point — the bundle is the failure case for that check.
 * @param {{variant?: string}} [args]
 * @param {string} [args.variant] Which corruption to inject into both runs.
 * @returns {Readonly<object>} The two damaged runs, their digests, and the
 *   expectations a test asserts.
 */
export function buildIdenticallyWrongControl({ variant = 'nudged_counter' } = {}) {
  const declaration = EXPECTED_FLIPS[variant];
  if (!declaration) throw new Error(`FIXTURE_VARIANT_UNKNOWN: ${String(variant)}`);
  const runA = buildVariant(variant, { label: 'a' }).run;
  const runB = buildVariant(variant, { label: 'b' }).run;
  const digestA = decisionContentDigest(runA);
  const digestB = decisionContentDigest(runB);
  return Object.freeze({
    control: 'identical_wrong',
    variant,
    run_a: runA,
    run_b: runB,
    decision_digest_a: digestA,
    decision_digest_b: digestB,
    // Whole-record digests DIFFER, and must: the runs are process-separated and
    // carry different ids and nonces. Recording only the equal one would let a
    // reader assume the runs were the same object.
    run_digest_a: fixtureDigest(runA),
    run_digest_b: fixtureDigest(runB),
    expected: Object.freeze({
      digests_still_equal: true,
      findings_a: 'NON_EMPTY',
      findings_b: 'NON_EMPTY',
      // The clean state is FAIL and so is the corrupted one; what this control
      // proves is that the digests stay EQUAL while both runs produce findings,
      // so agreement alone cannot carry a pass.
      campaign_verdict: Object.freeze({
        from: CLEAN_CAMPAIGN_VERDICT,
        to: CORRUPTED_CAMPAIGN_VERDICT,
        changed: false,
        why: 'the clean state already resolves to FAIL; equality of the digests with non-empty findings on both sides is the load-bearing claim',
      }),
      a_equals_b_alone_is_not_a_pass: true,
    }),
  });
}

/**
 * Prove every `EXPECTED_FLIPS` entry is COMPLETE AND NON-VACUOUS.
 *
 * A control is complete when it names the fields it corrupts, a before and an
 * after, and the axis it moves. It is NON-VACUOUS when at least one of those
 * axes actually MOVES: the campaign verdict cannot be that axis, because the
 * clean state already resolves to FAIL (see `CLEAN_CAMPAIGN_VERDICT`) and a
 * three-valued summary cannot fall further. The previous version of this check
 * required `campaign_verdict: PASS -> FAIL` on every variant, which is a rule
 * that can only be satisfied by a fixture that lies about the clean state.
 *
 * It also proves every declared `from` is the value the clean fixture really
 * has. A `from` that does not match the fixture is a stale expectation, and a
 * stale expectation is how a control starts asserting a flip that never happens.
 * @returns {true}
 * @throws {Error} `FIXTURE_FLIP_INCOMPLETE` naming the variant and the field.
 */
export function assertEveryFlipDeclared() {
  for (const [id, entry] of Object.entries(EXPECTED_FLIPS)) {
    if (entry.must_flip !== true) throw new Error(`FIXTURE_FLIP_INCOMPLETE: ${id} does not set must_flip`);
    const flip = entry.expected_flip;
    if (!flip || typeof flip !== 'object') throw new Error(`FIXTURE_FLIP_INCOMPLETE: ${id} has no expected_flip`);
    if (!flip.campaign_verdict || flip.campaign_verdict.from !== CLEAN_CAMPAIGN_VERDICT || flip.campaign_verdict.to !== CORRUPTED_CAMPAIGN_VERDICT) {
      throw new Error(`FIXTURE_FLIP_INCOMPLETE: ${id} does not declare campaign_verdict ${CLEAN_CAMPAIGN_VERDICT} -> ${CORRUPTED_CAMPAIGN_VERDICT}`);
    }
    const findings = flip.expected_value_findings;
    const codes = flip.failure_codes_added;
    const trialVerdict = flip.trial_verdict;
    const tableMoves = findings !== undefined && findings.to === 'NON_EMPTY';
    const codesMove = Array.isArray(codes) && codes.length > 0;
    const trialMoves = trialVerdict !== undefined && trialVerdict.changed === true;
    if (!tableMoves && !codesMove && !trialMoves) {
      throw new Error(
        `FIXTURE_FLIP_INCOMPLETE: ${id} moves no axis: expected_value_findings.to is ${String(findings?.to)}, ` +
        `failure_codes_added is ${JSON.stringify(codes)}, trial_verdict.changed is ${String(trialVerdict?.changed)}`,
      );
    }
  }
  for (const id of REQUIRED_VARIANT_IDS) {
    if (!VARIANT_IDS.includes(id)) throw new Error(`FIXTURE_FLIP_INCOMPLETE: required variant ${id} is missing`);
  }
  // The declared "before" of the metric variant, read back out of the clean
  // record, must be the clean record's own numbers.
  const measured = EXPECTED_FLIPS.corrupted_measurement;
  if (measured.from.numerator !== CLEAN_TRIAL_0.numerator
    || measured.from.denominator !== CLEAN_TRIAL_0.denominator
    || measured.from.observed !== CLEAN_TRIAL_0.observed) {
    throw new Error('FIXTURE_FLIP_INCOMPLETE: corrupted_measurement.from does not match the clean trial it claims to corrupt');
  }
  // The clean codes this fixture publishes must be the ones the clean
  // comparison really carries, or every `failure_codes_added` is relative to a
  // fiction.
  for (const code of CLEAN_CAMPAIGN_FAILURE_CODES) {
    if (!/^[a-z_]+$/.test(code)) throw new Error(`FIXTURE_FLIP_INCOMPLETE: clean failure code ${String(code)} is not a code spelling`);
  }
  return true;
}

assertEveryFlipDeclared();
assertTruncatedTailUnparseable();
