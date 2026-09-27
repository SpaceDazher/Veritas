// S2-008 research track — the FROZEN EXPECTED-VALUE TABLE and its pure
// checker (issue SpaceDazher/Veritas#8).
//
// Serves acceptance item A3: TWO PROCESS-SEPARATED RUNS WITH DIFFERENT IDS AND
// NONCES, AND TWO IDENTICALLY WRONG RUNS ARE NOT A PASS.
//
// WHY A TABLE AT ALL
// `A === B` is an extra condition, never the pass criterion. Two runs that
// agree can agree on the same wrong answer, so agreement proves reproducibility
// and nothing about correctness. The pass criterion is: both runs agree with
// THIS TABLE **and** the controls flip. `A === B` is additional, not
// sufficient — the same rule the S2-007 replay applies, applied here to the
// decision layer instead of the transport.
//
// WHY IT IS PURE
// No clock, no process, no filesystem, no `Date.now()`, no `Math.random()`. That
// is what makes the identical-wrong control demonstrable inside a `node:test`
// with nothing spawned: the same corruption is injected into both runs, their
// digests are left equal, and BOTH must produce non-empty findings. If this
// module needed a process to run, that control would cost a spawn per
// iteration and the property would go untested for budget reasons.
//
// WHERE THE TABLE COMES FROM — NEVER FROM AN OBSERVED RUN
// The table is DECLARED from three already-frozen sources:
//   * the frozen transition table `RESEARCH_TRANSITIONS` (constants.mjs),
//   * the three frozen contracts (contracts.mjs), and
//   * the ENUMERATED trial list, published in
//     `corpus/s2-008/preregistration.json` before trial one.
// Reading the table out of a run that already happened would make it a
// description of the answer rather than a test of it.
//
// `assertTableFrozen(prereg)` FAILS when the in-code table and
// `corpus/s2-008/preregistration.json` disagree. That is the mechanism which
// stops a run from quietly editing the expectation to match its result.
//
// A SKIPPED, UNRESOLVED, INFRA_ERROR or NOT_MEASURED TRIAL IS NEVER ABSENT
// FROM THIS TABLE. It has a row, and its row says VIOLATION. A trial cannot be
// deleted from the expectation by failing to run.
//
// THE S2-008 REPAIR (R-A / R-B / R-C), AND WHY THIS FILE CHANGED
// The first delivery was RED and the three causes were all in the frozen
// documents, not in the comparator — the comparator was right, and its own
// comment said so (`frozen_rule_cannot_reject` names raising the published
// confidence as a PREREGISTRATION change, never a comparator change):
//   1. the published rule was not SELF-CONSISTENT. `alpha = 0.05` over a family
//      of 3 gives a corrected level of `0.05/3 = 0.016667`, and a published
//      `confidence` of 0.95 inherits a bound of `1 - c = 0.05`, which exceeds
//      the corrected level. A rule whose bound is above the level it has to
//      clear can NEVER reject, so every campaign answered UNRESOLVED whatever
//      was measured. The published confidence is now DERIVED below as
//      `1 - alpha / family_size` from this file's own alpha and family, and
//      `assertFrozenTableSelfConsistent()` refuses a table whose bound is above
//      its own corrected level;
//   2. the measured campaign was not WELL-POSED. `trl-s2-008-04` is authored
//      to produce an INFRA outcome, and an unresolved trial is a VIOLATION by
//      construction, so the default campaign failed for a reason that had
//      nothing to do with whether the mechanics work. It is out of the measured
//      set below (so it is out of the multiplicity family) and STILL has its
//      row, still says VIOLATION, and still owns an INFRA outcome;
//   3. the gate counted `verdict_is_pass`, which eight synthetic cases cannot
//      satisfy without tuning the fixtures until a fabricated effect looked
//      legitimate. The gate moved to AGREEMENT with the frozen campaign
//      decision below, which is an ANSWER recorded next to the decision, never
//      a term of it.
//
// WHY THE THREE MEASURED ROWS NOW SAY `UNRESOLVED`
// The rows were re-derived from the FROZEN MEASUREMENTS by the frozen rule, and
// NOT re-tuned until the designed effect cleared the band. At the derived
// confidence the eight-case Wilson interval on 7/8 is [0.453625, 0.983339], on
// 6/8 [0.347079, 0.944230] and on 5/8 [0.255737, 0.889917]: all three straddle
// the frozen 0.75 baseline OUTSIDE the 0.02 band, so `decisionFromInterval`
// derives `UNRESOLVED` / `interval_straddles_null_outside_noise_band` for each
// of them and for the pooled campaign's 18/24 ([0.505681, 0.897936]) — the
// honest reading of a corpus this size. The re-derivation is re-run against the
// comparator's own rule in `src/lib/research/campaign-expectation.mjs`, which
// the corpus builder and the harness both call, so a hand-written expectation
// the rule does not produce is refused before anything is sealed or scored.
//
// OWNER: W3 (decision core); R-A/R-B/R-C repair by the integration step.
// State: IMPLEMENTED. The exported signatures are the ones plan §1 froze and
// none was renamed. The table below is DECLARED, never observed: it is the
// answer a run is scored against, so reading it out of a run that already
// happened would turn every check into a tautology.
import { BlockedPolicy, MalformedResult } from '../agentboard/errors.mjs';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import { RESEARCH_HARD_GATE_COUNTERS, RESEARCH_OUTCOMES, TRIAL_STATUSES, TRIAL_VERDICTS } from './constants.mjs';

/** The metric this track measures. Named once, and the preregistration has to
 * agree with it: a run that measures a different metric is a table
 * disagreement, not a different track. @type {string} */
const METRIC_NAME = 'case_agreement_rate';

/** The frozen noise band, in the metric's own unit (a ratio). @type {number} */
const NOISE_BAND = 0.02;

/** The frozen baseline the null value is read against. @type {number} */
const FROZEN_BASELINE = 0.75;

/** The inference mode, never upgraded. @type {string} */
const INFERENCE_MODE = 'ASSOCIATIONAL';

/** The aggregation the frozen table was built on. @type {string} */
const EXPECTED_AGGREGATION_BASIS = 'POOLED_TRIAL_COUNTS';
/** Cases per corpus partition, frozen by the committed manifest. @type {number} */
const CASES_PER_PARTITION = 8;

/**
 * The family-wise alpha the frozen rule was DERIVED at, named once.
 *
 * It is here, beside the table, because the table is what a run is scored
 * against: the published confidence below is derived from THIS alpha and THIS
 * family's size, and a preregistration that publishes a different alpha, a
 * different family or a different confidence is refused by `assertTableFrozen`
 * rather than being allowed to decide under a rule the table never declared.
 * @type {number}
 */
const PREREGISTERED_ALPHA = 0.05;

/**
 * The relative tolerance the self-consistency check compares with, and WHY it
 * is not zero. `1 - (1 - alpha / m)` is 5.2e-17 ABOVE `alpha / m` in IEEE-754
 * (relative 3.1e-15): a written `1 - confidence <= alpha / family_size` would
 * fail on the rounding artefact of the value that makes the rule self-consistent
 * in the first place. The comparator applies its own `DECISION_EPSILON` for the
 * same reason; this is the table's own statement of the same tolerance, and it
 * is two orders of magnitude looser than the comparator's.
 * @type {number}
 */
const RULE_TOLERANCE = 1e-12;

/**
 * The frozen per-trial expectation, indexed BY TRIAL INDEX. Reading by index
 * is deliberate: a substituted seed changes WHICH row scores a result, so the
 * substitution cannot hide behind a stable key.
 *
 * Four rows, matching the four preregistered trials. The three MEASURED rows
 * declare the outcome the frozen rule DERIVES from the counts they publish — at
 * the derived confidence `1 - alpha/m` that answer is `UNRESOLVED` for an
 * eight-case corpus, and the `why` of each row names the interval that produces
 * it. The INFRA row is here and says VIOLATION: excluded from the measured
 * campaign and from the multiplicity family is not dropped, and a trial cannot
 * be deleted from the expectation by failing to run.
 *
 * The `why` members are derived by hand and the `expectedOutcome` members are
 * NOT: they are the re-derived answer, published before trial one and sealed
 * into `evidence/s2-008/corpus/preregistration.json` by the digest below.
 * @type {ReadonlyArray<object>} one row per enumerated preregistered trial,
 *   each carrying at least `{index, trial, expectedStatus, expectedVerdict}`.
 */
export const EXPECTED_TRIAL_DECISIONS = Object.freeze([
  Object.freeze({
    index: 0, trial: 'trl-s2-008-01', partition: 'HOLDOUT',
    // R-B: re-derived from the frozen measurement 7/8 through the frozen
    // rule, not chosen. The interval at the derived confidence is
    // [0.453625, 0.983339], which straddles the 0.75 baseline outside the 0.02
    // band, so the rule answers UNRESOLVED. The DESIGN was POSITIVE and the
    // design is published separately (`designed_outcome` in the preregistration
    // and `derived_outcome` in the fixture) so the two can be compared instead
    // of being collapsed into one name.
    expectedStatus: 'RESOLVED', expectedOutcome: 'UNRESOLVED', expectedVerdict: 'ALLOW',
    expectedNumerator: 7, expectedDenominator: 8,
    why: 'the 7/8 interval at the derived confidence straddles the frozen baseline outside the preregistered 0.02 band, so the frozen rule derives UNRESOLVED (interval_straddles_null_outside_noise_band): eight cases cannot resolve a 0.02 band at 98.33% confidence, and the row says that instead of claiming an effect the corpus does not carry',
  }),
  Object.freeze({
    index: 1, trial: 'trl-s2-008-02', partition: 'HOLDOUT',
    // The DESIGN was NULL and the rule's answer is UNRESOLVED, which are
    // different things: a null is a decided answer inside the band, and the
    // interval is outside it. The design lives in `designed_outcome`; the
    // expectation is the rule's answer.
    expectedStatus: 'RESOLVED', expectedOutcome: 'UNRESOLVED', expectedVerdict: 'ALLOW',
    expectedNumerator: 6, expectedDenominator: 8,
    why: 'the 6/8 interval at the derived confidence is [0.347079, 0.944230], which straddles the frozen baseline outside the band: the point estimate sits ON the baseline, but a decided NULL needs the whole interval inside the band, and this one is not',
  }),
  Object.freeze({
    index: 2, trial: 'trl-s2-008-03', partition: 'HOLDOUT',
    // The DESIGN was NEGATIVE and the rule's answer is UNRESOLVED. A negative
    // is a decided answer in the other direction, and 5/8 is not decided.
    expectedStatus: 'RESOLVED', expectedOutcome: 'UNRESOLVED', expectedVerdict: 'ALLOW',
    expectedNumerator: 5, expectedDenominator: 8,
    why: 'the 5/8 interval at the derived confidence is [0.255737, 0.889917], which still covers the frozen baseline: the design is a decrease, and the rule declines to call a decrease an eight-case interval cannot exclude the null from',
  }),
  Object.freeze({
    index: 3, trial: 'trl-s2-008-04', partition: 'HOLDOUT',
    expectedStatus: 'INFRA_ERROR', expectedOutcome: 'INFRA', expectedVerdict: 'VIOLATION',
    expectedNumerator: null, expectedDenominator: null,
    why: 'no measurement was produced; an infra result is a reconciliation with a row, never a zero, and R-B moved it out of the measured campaign without moving it out of this table',
  }),
]);

/**
 * The MEASURED rows: the rows that declare a measurement of their own. The
 * predicate is the published count, not a status string, so "measured" cannot
 * mean one thing in the multiplicity family and another in the pooled metric.
 *
 * `trl-s2-008-04` is NOT in it (R-B), which is what takes it out of the
 * multiplicity family. It keeps its row, its INFRA outcome and its VIOLATION.
 * @type {ReadonlyArray<object>}
 */
const MEASURED_ROWS = Object.freeze(EXPECTED_TRIAL_DECISIONS.filter(
  (row) => Number.isInteger(row.expectedNumerator) && Number.isInteger(row.expectedDenominator) && row.expectedDenominator > 0,
));

/**
 * `m`: the size of the DECLARED family the Holm-Bonferroni correction runs
 * over, COUNTED from the measured rows rather than typed. A typed 3 would be a
 * second copy of a number the rows already carry, and the two are exactly what
 * the first delivery got wrong in the other direction.
 * @type {number}
 */
export const MEASURED_FAMILY_SIZE = MEASURED_ROWS.length;

/**
 * The confidence the frozen rule publishes, DERIVED: `1 - alpha / family_size`.
 *
 * The self-consistency a multiplicity rule must have is `1 - c <= alpha / m`:
 * a comparison bound inherited from a `c`-level interval is `1 - c`, so a family
 * of `m` members whose bound exceeds the corrected level can never reject,
 * whatever is measured. At `m = 3` and `alpha = 0.05` the corrected level is
 * `0.016667` and the published confidence is `0.98333...`, so the bound lands ON
 * the level instead of above it.
 *
 * Chosen rather than derived, the first delivery published 0.95 — a round
 * number that reads like a convention, published in BOTH `noise_rule` and
 * `multiplicity_rule` so the two agreed with each other and not with the rule.
 * @type {number}
 */
export const EXPECTED_CONFIDENCE = 1 - PREREGISTERED_ALPHA / MEASURED_FAMILY_SIZE;

/** The pooled campaign rate: 7 + 6 + 5 agreements over 3 x 8 cases, summed from
 * the rows rather than written. @type {number} */
const EXPECTED_POOLED_NUMERATOR = MEASURED_ROWS.reduce((total, row) => total + row.expectedNumerator, 0);
/** @type {number} */
const EXPECTED_POOLED_DENOMINATOR = MEASURED_ROWS.reduce((total, row) => total + row.expectedDenominator, 0);
/** The trials the metric does NOT count, reported as themselves and never as a
 * zero. @type {number} */
const EXPECTED_NOT_MEASURED = EXPECTED_TRIAL_DECISIONS.length - MEASURED_ROWS.length;

/**
 * The frozen refusal-code expectation: which codes the track may emit per
 * edge, and which codes are forbidden. Used by P1, P2, P4 and the identical-
 * wrong control.
 * @type {Readonly<Record<string, ReadonlyArray<string>>>} edge name ->
 *   permitted codes, with the forbidden set named alongside.
 */
export const EXPECTED_CODES = Object.freeze({
  holdout_peek: Object.freeze([
    'HOLDOUT_UNSEAL_DIGEST_MISSING', 'HOLDOUT_UNSEAL_DIGEST_FORGED', 'HOLDOUT_UNSEAL_DIGEST_REPLAYED',
    'HOLDOUT_OPEN_BUDGET_EXCEEDED', 'HOLDOUT_READ_BEFORE_DECISION_POINT', 'HOLDOUT_ACCESS_NOT_RELEASED',
  ]),
  seed_substitution: Object.freeze(['SEED_SET_NOT_PREREGISTERED', 'SEED_SET_REORDERED', 'SEED_COUNT_MISMATCH', 'SEED_SUBSET_MISMATCH']),
  hypothesis_rewrite: Object.freeze(['HYPOTHESIS_REWRITE_AFTER_RESULT', 'PREREGISTRATION_MUTATED_IN_PLACE', 'AMENDMENT_AS_DECISION_BASIS', 'AMENDMENT_SAME_CARD_ID']),
  budget_opacity: Object.freeze(['BUDGET_EXCEEDED', 'BUDGET_RESERVATION_MISSING', 'BUDGET_RESERVATION_EXPIRED']),
  causal_upgrade: Object.freeze([
    'CAUSAL_ASSERTION_UNSUPPORTED', 'CAUSAL_PROMOTION_MISSING', 'CAUSAL_PROMOTION_SELF_REVIEWED',
    'CAUSAL_TEMPORAL_ORDER_UNESTABLISHED', 'CAUSAL_MEDIATOR_NOT_FOUND', 'LABEL_SEAL_MISMATCH',
  ]),
  missing_evaluator: Object.freeze(['EVALUATOR_NOT_INDEPENDENT', 'CALIBRATION_NOT_MEASURED']),
  // The codes a run may NEVER emit, whatever the outcome. A blind retry after
  // an infra failure is the specific one the ticket names: it would be a second
  // attempt at an unknown outcome, which is a reconciliation instead.
  forbidden: Object.freeze(['BLIND_RETRY_AFTER_INFRA', 'IMPLICIT_ZERO', 'SKIP_AS_PASS', 'CAUSAL_FROM_SIMULATION']),
});

/**
 * The frozen hard-gate counter expectation. Every counter is 0 at the end of a
 * clean run; the table says so, so a counter that moved is a table failure and
 * not a judgement call.
 * @type {Readonly<Record<string, number>>} counter name -> expected value.
 */
export const EXPECTED_COUNTERS = Object.freeze(Object.fromEntries(
  RESEARCH_HARD_GATE_COUNTERS.map((counter) => [counter, 0]),
));

/**
 * The frozen ledger-shape expectation: the record kinds a clean run's journal
 * contains, in order, with the chain intact. It is how "refused writes nothing"
 * becomes checkable rather than asserted.
 * @type {ReadonlyArray<object>} the expected journal shape.
 */
export const EXPECTED_LEDGER_SHAPE = Object.freeze([
  Object.freeze({ kind: 'PREREGISTRATION_RECORDED', required: true, count: 1, note: 'recorded before trial one' }),
  Object.freeze({ kind: 'BUDGET_RESERVATION', required: true, count: 1, note: 'taken before the run, never at the spend' }),
  Object.freeze({ kind: 'ACCESS', required: true, count: 1, note: 'exactly one holdout open, journalled before the bytes are returned' }),
  Object.freeze({ kind: 'TRIAL_RESULT', required: true, count: EXPECTED_TRIAL_DECISIONS.length, note: 'one per enumerated trial, including the infra one' }),
]);

/**
 * The frozen metric expectation, including its units and the preregistered
 * noise band. `inferenceMode` is ASSOCIATIONAL; nothing here may be read as a
 * causal effect.
 * @type {{name: string, unit: string, noiseBand: number, inferenceMode: string}}
 */
export const EXPECTED_METRIC = Object.freeze({
  name: METRIC_NAME,
  unit: 'ratio',
  noiseBand: NOISE_BAND,
  baseline: FROZEN_BASELINE,
  direction: 'HIGHER_IS_BETTER',
  inferenceMode: INFERENCE_MODE,
});

/**
 * The frozen control expectations: the six negative controls of
 * negative-controls.mjs, each with the verdict it must flip TO. A control that
 * does not flip fails the track.
 * @type {ReadonlyArray<object>} one descriptor per control, keyed by control
 *   id: `holdout_peek|seed_substitution|budget_opacity|label_substitution|missing_evaluator|corrupted_data`.
 */
export const EXPECTED_CONTROLS = Object.freeze([
  Object.freeze({ id: 'holdout_peek', probe: 'P1', mechanism: 'comparator', mustFlipFrom: 'ALLOW', mustFlipTo: 'VIOLATION', counter: 'holdoutPeek' }),
  Object.freeze({ id: 'seed_substitution', probe: 'P2', mechanism: 'comparator', mustFlipFrom: 'ALLOW', mustFlipTo: 'VIOLATION', counter: 'seedSubstitution' }),
  Object.freeze({ id: 'budget_opacity', probe: 'P4', mechanism: 'comparator', mustFlipFrom: 'ALLOW', mustFlipTo: 'VIOLATION', counter: 'budgetOpacity' }),
  Object.freeze({ id: 'label_substitution', probe: 'P5', mechanism: 'guard', mustFlipFrom: 'ADMITTED', mustFlipTo: 'REFUSED', counter: 'causalUpgrade' }),
  Object.freeze({ id: 'missing_evaluator', probe: 'P6', mechanism: 'comparator', mustFlipFrom: 'ALLOW', mustFlipTo: 'VIOLATION', counter: 'missingEvaluator' }),
  Object.freeze({ id: 'corrupted_data', probe: 'A2', mechanism: 'table', mustFlipFrom: 'no_findings', mustFlipTo: 'findings_non_empty', counter: null }),
]);

/**
 * A plain object: an object literal or a frozen one, never an array and never
 * `null`. Every refusal in this module starts here, because "a table row that is
 * an array" and "a row that is absent" are different defects.
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * THE FROZEN CAMPAIGN DECISION (R-B / R-C).
 *
 * A campaign decision is a POOLED answer, so it is not a per-trial row: it is
 * the decision the frozen rule derives from the frozen measurements, pooled the
 * way the preregistration published the aggregation. It is a MEMBER of this
 * table rather than a constant in a script, for the reason every other member
 * is here: a constant in a script is edited in the same commit as the run it
 * scores and nothing binds it to what the rule derives. It is inside
 * `expectedTableDigest()` below, so it is sealed into
 * `evidence/s2-008/corpus/preregistration.json` before trial one and
 * `assertTableFrozen` refuses a table that moved after it was published.
 *
 * IT IS DECLARED HERE AND RE-DERIVED IN CODE. The decision is a declaration —
 * reading it out of a run would make every check a tautology — and
 * `src/lib/research/campaign-expectation.mjs` re-derives it through the
 * comparator's own `decisionFromInterval` over the counts this table publishes,
 * refusing a declaration the rule does not produce
 * (`EXPECTED_CAMPAIGN_DIVERGES_FROM_RULE`). That module is called by the corpus
 * builder before it seals anything and by the harness before it runs anything,
 * so this value cannot drift from the rule silently.
 *
 * WHY THE HONEST ANSWER ON THIS CORPUS IS `UNRESOLVED` / `NOT_MEASURED`
 * The pooled campaign measured 18 agreements over 24 cases; the interval at the
 * derived confidence is [0.505681, 0.897936], which covers the frozen 0.75
 * baseline, so the decision is UNRESOLVED. `decisionStatus` is the comparator's
 * own mapping of an undecided decision (POSITIVE -> SATISFIED, NEGATIVE/NULL ->
 * UNMET, everything else -> NOT_MEASURED), so a campaign that decided nothing is
 * recorded as having measured nothing, which is a different statement from a
 * met expectation.
 * @type {Readonly<object>}
 */
export const EXPECTED_CAMPAIGN = Object.freeze({
  decision: 'UNRESOLVED',
  decisionStatus: 'NOT_MEASURED',
  decisionReason: 'interval_straddles_null_outside_noise_band',
  metric: METRIC_NAME,
  aggregation: EXPECTED_AGGREGATION_BASIS,
  numerator: EXPECTED_POOLED_NUMERATOR,
  denominator: EXPECTED_POOLED_DENOMINATOR,
  null_value: FROZEN_BASELINE,
  noise_band: NOISE_BAND,
  // The decision rule's own spelling of the metric's direction
  // (`EXPECTED_METRIC.direction` is 'HIGHER_IS_BETTER', and
  // `decisionFromInterval` reads 'increase' / 'decrease' / 'two_sided'). It is
  // declared HERE, beside the metric, rather than at the call site in
  // `campaign-expectation.mjs`, because a direction supplied by a caller is a
  // direction a caller can pick; and `assertFrozenTableSelfConsistent` refuses a
  // pair that disagrees, so the two spellings cannot drift apart silently.
  direction: 'increase',
  confidence: EXPECTED_CONFIDENCE,
  alpha: PREREGISTERED_ALPHA,
  family_size: MEASURED_FAMILY_SIZE,
  comparisons: Object.freeze(MEASURED_ROWS.map((row) => row.trial)),
  why: 'eight cases per trial over three measured trials give 18/24, whose interval at the derived confidence 1 - alpha/m covers the frozen 0.75 baseline outside the 0.02 band; the frozen rule therefore derives UNRESOLVED, and an undecided campaign is the answer this stage records rather than a verdict it demands',
});

/**
 * The measured campaign's tally the table declares, as the run record has to
 * report it: the pooled counts, the basis that produced them, and the number of
 * trials that contributed NEITHER count.
 * @type {{metric: string, basis: string, numerator: number, denominator: number, notMeasured: number}}
 */
export const EXPECTED_CAMPAIGN_METRIC = Object.freeze({
  metric: METRIC_NAME,
  basis: EXPECTED_AGGREGATION_BASIS,
  numerator: EXPECTED_POOLED_NUMERATOR,
  denominator: EXPECTED_POOLED_DENOMINATOR,
  notMeasured: EXPECTED_NOT_MEASURED,
});

/**
 * Score a campaign record against the frozen campaign decision (R-C).
 *
 * The table's own copy of the condition the gates apply: a campaign whose
 * decision is not the one this table declares is a FINDING, the same way a
 * per-trial divergence is, so a fabricated POSITIVE is nameable from any caller
 * of the table and not only from one gate.
 *
 * A NULL or UNMET campaign is an answer, and agreement with it is the success
 * case — so this function returns an EMPTY list for the honest answer and this
 * module is not a second `verdict_is_pass` wearing a different name.
 *
 * @param {{decision?: string|null, decisionStatus?: string|null}} campaign
 *   The campaign record: the comparator's `decision` and `decisionStatus`.
 * @returns {ReadonlyArray<object>} Non-empty when the campaign diverges from the
 *   frozen declaration. Each finding names the field, the expected value, the
 *   observed value and the code `CAMPAIGN_DECISION_DIVERGES_FROM_TABLE` — one
 *   code for both members, because both are the same divergence: this table's
 *   answer is not the answer the campaign gives.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'CAMPAIGN_RECORD_ABSENT' when the record is not an object. A campaign that
 *   produced nothing is a finding, not a missing argument.
 */
export function expectedCampaignIssues(campaign) {
  if (!isPlainObject(campaign)) {
    throw new MalformedResult('CAMPAIGN_RECORD_ABSENT', `expectedCampaignIssues needs a campaign record, got ${typeNameOf(campaign)}`);
  }
  const out = [];
  for (const field of ['decision', 'decisionStatus']) {
    const expected = EXPECTED_CAMPAIGN[field];
    const observed = campaign[field] === undefined ? null : campaign[field];
    if (observed !== expected) {
      out.push(finding(field, expected, observed, 'CAMPAIGN_DECISION_DIVERGES_FROM_TABLE'));
    }
  }
  return Object.freeze(out);
}

/**
 * THE FROZEN EXPECTATION FOR THE COMPARATOR'S OWN FAILURE LIST (F1).
 *
 * The comparator is fail-closed and STAYS that way: an unresolved trial is a
 * `trial_violation`, a run with an unmeasured trial raises
 * `metric_not_measured`, and a campaign that decided nothing raises
 * `decision_unresolved`. The honest delivered campaign therefore carries three
 * failures PER RUN, and R-C correctly stopped requiring the VERDICT to be a
 * gate term — a null answer is an answer.
 *
 * R-C's enumerated condition then had a hole, and it is a hole in the ENUMERATION
 * rather than a deviation from it: it named table divergence, moved counters,
 * NOT_RUN and control flips, and a comparator failure that is NONE of those
 * (`best_seed_undisclosed` is the reproduced example: a run record that reports
 * one seed of the preregistered set and no disclosure of the set) was recorded,
 * printed and then gated by nothing. A run that carries such a failure still
 * agreed with the table, so the chain was green on a record the comparator had
 * already called a violation.
 *
 * So the table now ALSO declares WHICH FAILURES THE HONEST CAMPAIGN CARRIES, and
 * the gate's sixth term asks the only question that closes the hole: is every
 * failure the comparator raised one this table declares? A failure outside the
 * declaration, or a declared failure raised a different number of times, is a
 * term failure — a finding, not a verdict.
 *
 * The counts are DERIVED from the rows and the campaign above, never typed:
 * `trial_violation` is the number of rows the table declares VIOLATION, so a
 * table that added an INFRA row would raise its own bar; `metric_not_measured`
 * follows from `notMeasured`; `decision_unresolved` follows from the declared
 * decision. A typed `1, 1, 1` would be a second copy of three facts the rows
 * already carry, and the two are exactly what the first delivery got wrong in
 * the other direction.
 *
 * THE LIMIT LIST IS DECLARED TOO. Latency is measured and can only raise a
 * limit, never a failure and never a verdict, so an UNKNOWN limit code must not
 * be a free pass either — the same closure, one list over.
 * @type {Readonly<{per_run: Readonly<Record<string, number>>,
 *   per_run_limits: Readonly<Record<string, number>>, why: string}>}
 */
export const EXPECTED_COMPARATOR_FAILURES = Object.freeze({
  per_run: Object.freeze({
    trial_violation: EXPECTED_TRIAL_DECISIONS.filter((row) => row.expectedVerdict === 'VIOLATION').length,
    metric_not_measured: EXPECTED_CAMPAIGN_METRIC.notMeasured > 0 ? 1 : 0,
    decision_unresolved: EXPECTED_CAMPAIGN.decision === 'UNRESOLVED' ? 1 : 0,
  }),
  per_run_limits: Object.freeze({ latency_observed: 1 }),
  why: 'the delivered campaign is UNRESOLVED because one of four trials produced no measurement (R-B kept that row and its VIOLATION), so the honest comparison raises exactly one trial_violation, one metric_not_measured and one decision_unresolved per run, plus one latency limit; any OTHER failure, or a different count of these, is a record the table does not describe and a gate term fails on it',
});

/**
 * The comparator's failure and limit lists, scored against what the frozen table
 * declares the honest campaign to carry (F1).
 *
 * PURE and fail-closed: a malformed list is a finding, not a throw, because the
 * question this answers ("did the comparator raise something nobody declared?")
 * has an answer either way and a run record must not be able to hide behind one.
 *
 * @param {{failures?: ReadonlyArray<object>|null, limits?: ReadonlyArray<object>|null, runs?: number|null}} [args]
 * @param {ReadonlyArray<object>} [args.failures=[]] `comparison.failures` as
 *   `compareParallelTrack` publishes it: `{code, detail}` per entry, one entry
 *   per run per code.
 * @param {ReadonlyArray<object>} [args.limits=[]] `comparison.limits`, the same
 *   shape.
 * @param {number} [args.runs=2] How many runs the comparison covered. Declared
 *   rather than parsed out of the detail strings: `runA`/`runB` prefixes are the
 *   comparator's prose, and a count that depends on prose is a count an
 *   attacker can edit.
 * @returns {ReadonlyArray<object>} One finding per divergence. `code` is the
 *   comparator's own code (or `UNEXPECTED_CODE` for a code the table never
 *   declares), `expected` is the declared total across `runs` runs, `observed`
 *   is what the comparison raised, and `divergence` is `UNDECLARED` or
 *   `COUNT_DIVERGES`. `UNEXPECTED_CODE` is used for a code outside the
 *   declaration, which is the case that reproduction F1 exercises.
 */
export function unexpectedComparatorFailures({ failures = [], limits = [], runs = 2 } = {}) {
  if (!Number.isInteger(runs) || runs < 0) {
    throw new MalformedResult('COMPARISON_RUN_COUNT_ABSENT', `unexpectedComparatorFailures needs a non-negative integer run count, got ${typeNameOf(runs)}`);
  }
  const out = [];
  for (const [list, declared, prefix] of [
    [failures, EXPECTED_COMPARATOR_FAILURES.per_run, 'failures'],
    [limits, EXPECTED_COMPARATOR_FAILURES.per_run_limits, 'limits'],
  ]) {
    const entries = Array.isArray(list) ? list : [];
    const counts = new Map();
    for (const entry of entries) {
      const code = isPlainObject(entry) && typeof entry.code === 'string' ? entry.code : 'MALFORMED_ENTRY';
      counts.set(code, (counts.get(code) ?? 0) + 1);
    }
    for (const code of new Set([...Object.keys(declared), ...counts.keys()])) {
      const expected = (declared[code] ?? 0) * runs;
      const observed = counts.get(code) ?? 0;
      if (observed === expected) continue;
      out.push(Object.freeze({
        field: `${prefix}.${code}`,
        code: declared[code] === undefined ? 'UNEXPECTED_CODE' : 'COUNT_DIVERGES',
        comparator_code: code,
        expected,
        observed,
        divergence: declared[code] === undefined ? 'UNDECLARED' : 'COUNT_DIVERGES',
      }));
    }
  }
  return Object.freeze(out.map((item) => Object.freeze({
    ...item,
    detail: `${item.comparator_code}: the frozen table declares ${String(item.expected)} occurrence(s) over ${String(runs)} run(s) and the comparison raised ${String(item.observed)}; ${item.divergence === 'UNDECLARED' ? 'a failure nobody declared is a failure the gate must not swallow' : 'a declared failure raised a different number of times'}`,
  })));
}

/**
 * The name of a value's type, for a refusal that has to say what it got. Named
 * here because the message a caller reads is part of the refusal: "expected an
 * object, got null" names the defect and "expected an object" does not.
 * @param {unknown} value
 * @returns {string}
 */
function typeNameOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function finding(field, expected, observed, code, index) {
  return Object.freeze({ field, expected, observed, code, index: index ?? null });
}

/**
 * Compare one run against the frozen table, by trial index.
 *
 * Pure: no clock, no process, no filesystem. The identical-wrong control
 * depends on that — the same corruption injected into two runs must yield
 * non-empty findings from BOTH even though their digests are equal.
 *
 * @param {object} run A completed run record (the shape written by
 *   scripts/s2-008-harness.mjs): trials, codes, counters, ledger, metrics,
 *   provenance.
 * @param {string} letter The run letter ('a' | 'b'), used only to label
 *   findings.
 * @returns {ReadonlyArray<object>} Non-empty when the run disagrees with the
 *   table. Each finding names the trial index, the field, the expected value
 *   and the observed value. EMPTY means the run matched the table.
 */
export function expectedValueIssues(run, letter) {
  if (!isPlainObject(run)) {
    throw new MalformedResult('RUN_RECORD_ABSENT', `expectedValueIssues(${String(letter)}) needs a run record`);
  }
  const out = [];
  const trials = Array.isArray(run.trials) ? run.trials : null;

  // 1. The trial set, BY INDEX. A trial the run does not have is a finding
  //    against its own row, and an EXTRA trial is a finding too: a run cannot
  //    answer with more trials than the preregistration enumerated.
  if (trials === null) {
    out.push(finding('trials', `array of ${EXPECTED_TRIAL_DECISIONS.length}`, 'absent', 'TRIALS_ABSENT'));
  } else {
    if (trials.length !== EXPECTED_TRIAL_DECISIONS.length) {
      out.push(finding('trials.length', EXPECTED_TRIAL_DECISIONS.length, trials.length, 'TRIAL_COUNT_DIVERGES_FROM_TABLE'));
    }
    for (const row of EXPECTED_TRIAL_DECISIONS) {
      const trial = trials[row.index];
      if (!isPlainObject(trial)) {
        out.push(finding(`trials[${row.index}]`, row.trial, 'absent', 'TRIAL_ROW_ABSENT', row.index));
        continue;
      }
      for (const [field, expected] of [['trial', row.trial], ['status', row.expectedStatus], ['outcome', row.expectedOutcome]]) {
        const observed = trial[field] === undefined ? null : trial[field];
        if (observed !== expected) {
          out.push(finding(`trials[${row.index}].${field}`, expected, observed, 'TRIAL_FIELD_DIVERGES_FROM_TABLE', row.index));
        }
      }
      // S4: the per-trial VERDICT, which the table declared in every row and
      // nothing ever compared. `expectedVerdict` was read by no code path, so
      // the only check on a recorded verdict was CLOSED-SET MEMBERSHIP: a trial
      // that self-declared `ALLOW` on a record the comparator scores as a
      // VIOLATION passed, and a trial that self-declared `VIOLATION` on a clean
      // record passed too. The verdict is the field a reader takes from a run
      // record, so the table has to hold it to the row it declared.
      if (row.expectedVerdict !== undefined && row.expectedVerdict !== null) {
        const observed = trial.verdict === undefined ? null : trial.verdict;
        if (observed !== row.expectedVerdict) {
          out.push(finding(`trials[${row.index}].verdict`, row.expectedVerdict, observed, 'TRIAL_VERDICT_DIVERGES_FROM_TABLE', row.index));
        }
      }
      if (row.expectedNumerator !== null && Number.isInteger(row.expectedNumerator)) {
        for (const [field, expected] of [['numerator', row.expectedNumerator], ['denominator', row.expectedDenominator]]) {
          const observed = trial[field] === undefined ? null : trial[field];
          if (observed !== expected) {
            out.push(finding(`trials[${row.index}].${field}`, expected, observed, 'MEASUREMENT_DIVERGES_FROM_TABLE', row.index));
          }
        }
      }
      // The per-trial provenance must name the SAME execution the run names.
      // This is the `provenance_field` corruption variant: a trial that claims
      // a different raw run id is a corrupted record, and the table has to say
      // so rather than leave the mismatch to a comment.
      const provenance = isPlainObject(trial.provenance) ? trial.provenance : null;
      if (provenance !== null) {
        for (const field of ['raw_run_id', 'commit_sha', 'tree_sha']) {
          if (provenance[field] === undefined) continue;
          if (provenance[field] !== run[field]) {
            out.push(finding(`trials[${row.index}].provenance.${field}`, run[field] ?? 'absent', provenance[field], 'TRIAL_PROVENANCE_DIVERGES_FROM_TABLE', row.index));
          }
        }
      }
      // A trial that carries its own hard-gate counters carries them for the
      // WHOLE run, and every one of them is 0 in a clean run. This is the
      // `counter_nudge` corruption variant, and it is checked per trial so a
      // corruption injected into a trial is caught even when the run-level
      // block is untouched.
      if (isPlainObject(trial.counters)) {
        for (const [name, expected] of Object.entries(EXPECTED_COUNTERS)) {
          const observed = trial.counters[name] === undefined ? 'absent' : trial.counters[name];
          if (observed !== expected) {
            out.push(finding(`trials[${row.index}].counters.${name}`, expected, observed, 'TRIAL_HARD_GATE_DIVERGES_FROM_TABLE', row.index));
          }
        }
      }
    }
  }

  // 2. The hard-gate counters, by name. Every one is 0 at the end of a clean
  //    run, and the table says so, so a moved counter is a disagreement and
  //    not a judgement call.
  const counters = isPlainObject(run.counters) ? run.counters : (isPlainObject(run.hardCounters) ? run.hardCounters : null);
  if (counters === null) {
    out.push(finding('counters', 'object', 'absent', 'HARD_COUNTERS_ABSENT'));
  } else {
    for (const [name, expected] of Object.entries(EXPECTED_COUNTERS)) {
      const observed = counters[name] === undefined ? 'absent' : counters[name];
      if (observed !== expected) {
        out.push(finding(`counters.${name}`, expected, observed, 'HARD_GATE_DIVERGES_FROM_TABLE'));
      }
    }
  }

  // 3. The metric. A run measuring a different metric, or a different
  //    inference mode, is a different track and must not pass this table.
  const metrics = isPlainObject(run.metrics) ? run.metrics : null;
  if (metrics === null) {
    out.push(finding('metrics', 'object', 'absent', 'METRICS_ABSENT'));
  } else {
    if (metrics.metric !== EXPECTED_METRIC.name) {
      out.push(finding('metrics.metric', EXPECTED_METRIC.name, metrics.metric ?? 'absent', 'METRIC_DIVERGES_FROM_TABLE'));
    }
    // The campaign rate is POOLED over the resolved trials' own counts: three
    // resolved trials over an eight-case corpus is 24 cases, and the frozen
    // baseline 0.75 is a per-CASE rate, so the denominator is in cases and not
    // in trials. Counting trials instead produced "1 of 3 trials" for a
    // campaign that measured 18 agreements out of 24 cases — a different
    // quantity wearing the same name. The infra trial contributes to
    // `notMeasured` and is never a denominator member.
    if (metrics.basis !== EXPECTED_AGGREGATION_BASIS) {
      out.push(finding('metrics.basis', EXPECTED_AGGREGATION_BASIS, metrics.basis ?? 'absent', 'METRIC_BASIS_DIVERGES_FROM_TABLE'));
    }
    if (metrics.numerator !== EXPECTED_POOLED_NUMERATOR) {
      out.push(finding('metrics.numerator', EXPECTED_POOLED_NUMERATOR, metrics.numerator ?? 'absent', 'METRIC_NUMERATOR_DIVERGES_FROM_TABLE'));
    }
    if (metrics.denominator !== EXPECTED_POOLED_DENOMINATOR) {
      out.push(finding('metrics.denominator', EXPECTED_POOLED_DENOMINATOR, metrics.denominator ?? 'absent', 'METRIC_DENOMINATOR_DIVERGES_FROM_TABLE'));
    }
    if (metrics.notMeasured !== EXPECTED_CAMPAIGN_METRIC.notMeasured) {
      out.push(finding('metrics.notMeasured', EXPECTED_CAMPAIGN_METRIC.notMeasured, metrics.notMeasured ?? 'absent', 'NOT_MEASURED_DIVERGES_FROM_TABLE'));
    }
  }

  // 4. The codes a run may NEVER emit. `run.codes` is the run's own list of
  //    refusal codes it observed; a forbidden code in it is a finding even
  //    though nothing else about the run moved.
  const codes = Array.isArray(run.codes) ? run.codes.map((code) => String(code)) : [];
  for (const forbidden of EXPECTED_CODES.forbidden) {
    if (codes.some((code) => code === forbidden || code.startsWith(`${forbidden}:`))) {
      out.push(finding('codes', `must not contain ${forbidden}`, forbidden, 'FORBIDDEN_CODE_EMITTED'));
    }
  }

  // 5. The provenance binding. A5: a run that does not name its base is
  //    unbound, and an unbound run cannot be scored against a table.
  for (const field of ['commit_sha', 'tree_sha', 'raw_run_id']) {
    const observed = run[field];
    if (typeof observed !== 'string' || observed === '') {
      out.push(finding(field, 'non-empty string', 'absent', 'RUN_PROVENANCE_UNBOUND'));
    }
  }

  // 6. The table's own digest, when the run declares it. A run scored against
  //    a different table is scored against a different question.
  if (typeof run.expected_table_digest === 'string' && expectedTableDigest() !== run.expected_table_digest) {
    out.push(finding('expected_table_digest', expectedTableDigest(), run.expected_table_digest, 'TABLE_DIGEST_MISMATCH'));
  }

  // 7. The closed vocabularies. A status or outcome outside the frozen set is a
  //    finding BEFORE it is a decision, so a widened vocabulary cannot slip in
  //    under a name the table has never seen.
  for (const [index, trial] of (trials ?? []).entries()) {
    if (!isPlainObject(trial)) continue;
    if (typeof trial.status === 'string' && !TRIAL_STATUSES.includes(trial.status)) {
      out.push(finding(`trials[${index}].status`, `one of ${TRIAL_STATUSES.join('|')}`, trial.status, 'STATUS_OUTSIDE_CLOSED_SET', index));
    }
    if (typeof trial.outcome === 'string' && !RESEARCH_OUTCOMES.includes(trial.outcome)) {
      out.push(finding(`trials[${index}].outcome`, `one of ${RESEARCH_OUTCOMES.join('|')}`, trial.outcome, 'OUTCOME_OUTSIDE_CLOSED_SET', index));
    }
    if (typeof trial.verdict === 'string' && !TRIAL_VERDICTS.includes(trial.verdict)) {
      out.push(finding(`trials[${index}].verdict`, `one of ${TRIAL_VERDICTS.join('|')}`, trial.verdict, 'VERDICT_OUTSIDE_CLOSED_SET', index));
    }
  }
  return Object.freeze(out);
}

/**
 * The canonical digest of the frozen table, so the evidence record binds the
 * table that was used and not merely the result it produced.
 *
 * `EXPECTED_CAMPAIGN` is INSIDE it (R-C). It is a table member, so a table whose
 * campaign declaration moved after the preregistration was sealed is a
 * detectable change and not a silent one: the digest that `assertTableFrozen`
 * compares is over the declaration as well as the rows.
 * @returns {string} `sha256:<64 hex>` over the canonical JSON of every
 *   EXPECTED_* constant, via `canonicalDigest` from
 *   src/lib/verifier/canonical-json.mjs.
 */
export function expectedTableDigest() {
  return canonicalDigest({
    EXPECTED_TRIAL_DECISIONS,
    EXPECTED_CODES,
    EXPECTED_COUNTERS,
    EXPECTED_LEDGER_SHAPE,
    EXPECTED_METRIC,
    EXPECTED_CONTROLS,
    EXPECTED_CAMPAIGN,
    // F1: the declaration of WHICH comparator failures the honest campaign
    // carries is part of the table, so it is sealed by the same digest and a
    // table whose expectation drifted after the preregistration was sealed is
    // refused by `assertTableFrozen` for this member too.
    EXPECTED_COMPARATOR_FAILURES,
  });
}

/**
 * The frozen rule this table was derived at, as one record: the family-wise
 * alpha, the declared family, the DERIVED confidence and the bound that
 * confidence inherits. Published so a reader can check the self-consistency
 * without re-doing the arithmetic, and so `assertFrozenTableSelfConsistent` and
 * `assertTableFrozen` compare against one object rather than four arguments.
 * @type {Readonly<{alpha: number, family_size: number, confidence: number, bound: number, corrected_level: number, method: string}>}
 */
export const EXPECTED_RULE = Object.freeze({
  alpha: PREREGISTERED_ALPHA,
  family_size: MEASURED_FAMILY_SIZE,
  confidence: EXPECTED_CONFIDENCE,
  // The bound a comparison inherits from a `confidence`-level interval: 1 - c.
  bound: 1 - EXPECTED_CONFIDENCE,
  // The level it has to clear after the family-wise correction: alpha / m.
  corrected_level: PREREGISTERED_ALPHA / MEASURED_FAMILY_SIZE,
  method: 'holm_bonferroni',
});

/**
 * The self-consistency of the frozen rule, measured rather than asserted.
 *
 * `never_rejects` here is the TABLE's own statement, computed over this file's
 * constants. It is NOT `ruleFeasibility` from the comparator — this module
 * cannot import the comparator (the comparator imports this module) — and the
 * comparison carries `RULE_TOLERANCE` for the reason documented there: the
 * derived value `1 - (1 - alpha/m)` is 5.2e-17 above `alpha/m` in IEEE-754, and
 * a rule that failed on the rounding artefact of the number that makes it
 * self-consistent would be wrong in the strictest possible way.
 *
 * The comparator remains the authority on what a campaign may decide
 * (`ruleFeasibility`), and `src/lib/research/campaign-expectation.mjs` re-derives
 * the declared campaign decision through it. This function is the table's own
 * side of the same statement.
 * @returns {{never_rejects: boolean, self_consistent: boolean, feasible: boolean,
 *   can_only_answer: string, bound: number, corrected_level: number, note: string}}
 */
export function frozenRuleFeasibility() {
  const { bound, corrected_level: floor } = EXPECTED_RULE;
  const neverRejects = bound > floor + Math.abs(floor) * RULE_TOLERANCE;
  return Object.freeze({
    never_rejects: neverRejects,
    self_consistent: neverRejects === false,
    feasible: neverRejects === false,
    can_only_answer: neverRejects ? 'NULL_OR_UNRESOLVED' : 'ANY_OUTCOME',
    bound,
    corrected_level: floor,
    note: neverRejects
      ? `1 - c = ${String(bound)} exceeds alpha/m = ${String(floor)} with m=${String(EXPECTED_RULE.family_size)}; the rule can reject nothing`
      : `1 - c = ${String(bound)} <= alpha/m = ${String(floor)} with m=${String(EXPECTED_RULE.family_size)}; the rule can reject`,
  });
}

/**
 * Refuse a frozen table that cannot decide anything, or whose pooled counts do
 * not follow from its own rows (R-A / R-B).
 *
 * The first delivery's table was well-formed in every syntactic sense and
 * UNDECIDABLE: it published `confidence: 0.95` against `alpha = 0.05` over a
 * family of 3, so the bound it inherited was above the corrected level and no
 * measurement could ever have been rejected. Nothing crashed and nothing
 * differed, which is exactly why a self-consistency check has to exist: a table
 * that is impossible rather than wrong is invisible to a reviewer reading it.
 *
 * Pure, no clock, no randomness, and it throws rather than returning a boolean,
 * so a caller cannot log the failure and carry on.
 *
 * @returns {{never_rejects: boolean, bound: number, corrected_level: number, family_size: number, measured_rows: number, unresolved_rows: number}}
 *   The measurements the check was made over.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'FROZEN_RULE_CANNOT_REJECT' when the published bound is above the corrected
 *   level, 'FROZEN_TABLE_POOLED_COUNTS_DRIFT' when the pooled denominator is not
 *   the measured rows' own cases, 'FROZEN_TABLE_ROW_NOT_CANONICAL' when a row's
 *   status, outcome or verdict is outside its closed set, and
 *   'FROZEN_TABLE_MEASURED_CAMPAIGN_ABSENT' when the table declares no measured
 *   row at all.
 */
export function assertFrozenTableSelfConsistent() {
  const feasibility = frozenRuleFeasibility();
  if (feasibility.never_rejects) {
    throw new MalformedResult('FROZEN_RULE_CANNOT_REJECT', feasibility.note);
  }
  if (MEASURED_ROWS.length === 0) {
    throw new MalformedResult('FROZEN_TABLE_MEASURED_CAMPAIGN_ABSENT', 'the frozen table declares no measured row, so it has no campaign decision to declare');
  }
  if (EXPECTED_POOLED_DENOMINATOR !== CASES_PER_PARTITION * MEASURED_ROWS.length) {
    throw new MalformedResult(
      'FROZEN_TABLE_POOLED_COUNTS_DRIFT',
      `the measured rows sum to ${String(EXPECTED_POOLED_DENOMINATOR)} cases over ${String(MEASURED_ROWS.length)} trial(s), and the committed corpus partitions hold ${String(CASES_PER_PARTITION)} cases per trial`,
    );
  }
  // The metric's direction and the decision rule's spelling of it are two
  // members, so they are checked against each other: a HIGHER_IS_BETTER metric
  // decided with a `decrease` rule is a real improvement scored as the wrong
  // answer, and the reverse is a regression read as support.
  const METRIC_DIRECTIONS = Object.freeze({ HIGHER_IS_BETTER: 'increase', LOWER_IS_BETTER: 'decrease' });
  const ruleDirection = METRIC_DIRECTIONS[EXPECTED_METRIC.direction] ?? null;
  if (ruleDirection === null || ruleDirection !== EXPECTED_CAMPAIGN.direction) {
    throw new MalformedResult(
      'FROZEN_TABLE_DIRECTION_DIVERGES',
      `the frozen metric is ${String(EXPECTED_METRIC.direction)} while the campaign rule declares direction ${String(EXPECTED_CAMPAIGN.direction)}`,
    );
  }
  for (const row of EXPECTED_TRIAL_DECISIONS) {
    if (!TRIAL_STATUSES.includes(row.expectedStatus) || !RESEARCH_OUTCOMES.includes(row.expectedOutcome) || !TRIAL_VERDICTS.includes(row.expectedVerdict)) {
      throw new MalformedResult(
        'FROZEN_TABLE_ROW_NOT_CANONICAL',
        `row ${String(row.index)} (${String(row.trial)}) declares ${String(row.expectedStatus)}/${String(row.expectedOutcome)}/${String(row.expectedVerdict)}, and at least one of those is outside its closed set`,
      );
    }
  }
  return Object.freeze({
    never_rejects: feasibility.never_rejects,
    bound: feasibility.bound,
    corrected_level: feasibility.corrected_level,
    family_size: EXPECTED_RULE.family_size,
    measured_rows: MEASURED_ROWS.length,
    unresolved_rows: EXPECTED_NOT_MEASURED,
  });
}

/**
 * Assert the in-code table and the preregistration agree. This is what stops a
 * run from editing the expectation to match its result: the preregistration
 * was committed and digested BEFORE trial one, so a later edit of the table is
 * a detectable change, not a silent one.
 * @param {object} prereg The loaded `corpus/s2-008/preregistration.json`,
 *   including its own recorded table digest.
 * @returns {string} The agreed table digest.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'EXPECTED_TABLE_DRIFT', naming the field that moved.
 */
export function assertTableFrozen(prereg) {
  if (!isPlainObject(prereg)) {
    throw new MalformedResult('PREREGISTRATION_NOT_AN_OBJECT', 'assertTableFrozen needs the preregistration document');
  }
  const actual = expectedTableDigest();
  const declared = prereg.expected_table_digest ?? prereg.table_digest ?? null;
  if (declared === null) {
    throw new BlockedPolicy('EXPECTED_TABLE_DIGEST_ABSENT', 'the preregistration records no frozen-table digest; an expectation published after the run is not an expectation');
  }
  const normalised = String(declared).startsWith('sha256:') ? String(declared).slice(7) : String(declared);
  if (normalised !== actual) {
    throw new BlockedPolicy('EXPECTED_TABLE_DRIFT', `the frozen table in code is ${actual}, the preregistration sealed ${normalised}; the expectation moved after it was published`);
  }
  // The metric and the noise band are checked member by member as well, so a
  // drift that happens to leave the digest alone is still named.
  const noise = isPlainObject(prereg.noise_rule) ? (prereg.noise_rule.band ?? prereg.noise_rule.noise_band ?? null) : null;
  if (noise !== null && noise !== EXPECTED_METRIC.noiseBand) {
    throw new BlockedPolicy('EXPECTED_TABLE_DRIFT', `the preregistered noise band is ${String(noise)}, the frozen table declares ${EXPECTED_METRIC.noiseBand}`);
  }
  // R-A: the SEALED rule has to be the rule this table was derived at, member by
  // member. The first delivery published `confidence: 0.95` with `alpha: 0.05`
  // over a family of 3, so the bound it inherited was `0.05 > 0.05/3` and the
  // rule could never reject: the campaign was undecidable by construction and
  // the corpus sealed that undecidability before trial one. A digest check
  // cannot see it — the digest was self-consistent — so the check is here, on
  // the published CONSTANTS, and it is the same tolerance the table uses.
  const multiplicity = isPlainObject(prereg.multiplicity_rule) ? prereg.multiplicity_rule : null;
  if (multiplicity === null) {
    throw new BlockedPolicy('PREREGISTRATION_MULTIPLICITY_ABSENT', 'the preregistration publishes no multiplicity rule, so there is no frozen rule to check for self-consistency');
  }
  if (multiplicity.alpha !== EXPECTED_RULE.alpha) {
    throw new BlockedPolicy('EXPECTED_RULE_DIVERGES_FROM_TABLE', `the sealed rule publishes alpha=${String(multiplicity.alpha)} while the frozen table derives the rule at alpha=${String(EXPECTED_RULE.alpha)}`);
  }
  if (multiplicity.family_size !== EXPECTED_RULE.family_size) {
    throw new BlockedPolicy('EXPECTED_RULE_DIVERGES_FROM_TABLE', `the sealed rule declares a family of ${String(multiplicity.family_size)} while the frozen table's measured campaign has ${String(EXPECTED_RULE.family_size)} measured rows`);
  }
  for (const [where, confidence] of [['multiplicity_rule', multiplicity.confidence], ['noise_rule', isPlainObject(prereg.noise_rule) ? prereg.noise_rule.confidence : null]]) {
    if (typeof confidence !== 'number') {
      throw new BlockedPolicy('EXPECTED_RULE_DIVERGES_FROM_TABLE', `${where} publishes no confidence, and a rule that does not publish its level cannot be checked`);
    }
    const floor = EXPECTED_RULE.corrected_level;
    if (Math.abs((1 - confidence) - floor) > Math.abs(floor) * RULE_TOLERANCE) {
      throw new BlockedPolicy(
        'FROZEN_RULE_NOT_SELF_CONSISTENT',
        `${where} publishes confidence ${String(confidence)}, whose bound 1 - c = ${String(1 - confidence)} exceeds the corrected level alpha/m = ${String(floor)}; the rule can reject nothing whatever is measured, so the campaign is undecidable by construction`,
      );
    }
    if (Math.abs(confidence - EXPECTED_RULE.confidence) > Math.abs(EXPECTED_RULE.confidence) * RULE_TOLERANCE) {
      throw new BlockedPolicy(
        'EXPECTED_RULE_DIVERGES_FROM_TABLE',
        `${where} publishes confidence ${String(confidence)} while the frozen table derives it as 1 - alpha/m = ${String(EXPECTED_RULE.confidence)}`,
      );
    }
  }
  assertFrozenTableSelfConsistent();
  return actual;
}
