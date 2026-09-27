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
// OWNER: W3 (decision core). Budget: part of W3's <= 800 lines.
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
/** The pooled campaign rate: 7 + 6 + 5 agreements over 3 x 8 cases. @type {number} */
const EXPECTED_POOLED_NUMERATOR = 18;
/** @type {number} */
const EXPECTED_POOLED_DENOMINATOR = CASES_PER_PARTITION * 3;

/**
 * The frozen per-trial expectation, indexed BY TRIAL INDEX. Reading by index
 * is deliberate: a substituted seed changes WHICH row scores a result, so the
 * substitution cannot hide behind a stable key.
 *
 * Four rows, matching the four preregistered trials. The INFRA row is here and
 * says VIOLATION: excluded from the multiplicity family is not dropped, and a
 * trial cannot be deleted from the expectation by failing to run.
 * @type {ReadonlyArray<object>} one row per enumerated preregistered trial,
 *   each carrying at least `{index, trial, expectedStatus, expectedVerdict}`.
 */
export const EXPECTED_TRIAL_DECISIONS = Object.freeze([
  Object.freeze({
    index: 0, trial: 'trl-s2-008-01', partition: 'HOLDOUT',
    expectedStatus: 'RESOLVED', expectedOutcome: 'POSITIVE', expectedVerdict: 'ALLOW',
    expectedNumerator: 7, expectedDenominator: 8,
    why: 'the whole interval clears the noise band in the preregistered direction',
  }),
  Object.freeze({
    index: 1, trial: 'trl-s2-008-02', partition: 'HOLDOUT',
    expectedStatus: 'RESOLVED', expectedOutcome: 'NULL', expectedVerdict: 'ALLOW',
    expectedNumerator: 6, expectedDenominator: 8,
    why: 'the interval lies inside the noise band: a real answer, not a negative one',
  }),
  Object.freeze({
    index: 2, trial: 'trl-s2-008-03', partition: 'HOLDOUT',
    expectedStatus: 'RESOLVED', expectedOutcome: 'NEGATIVE', expectedVerdict: 'ALLOW',
    expectedNumerator: 5, expectedDenominator: 8,
    why: 'a corrected significant effect in the other direction: first-class, never a pass',
  }),
  Object.freeze({
    index: 3, trial: 'trl-s2-008-04', partition: 'HOLDOUT',
    expectedStatus: 'INFRA_ERROR', expectedOutcome: 'INFRA', expectedVerdict: 'VIOLATION',
    expectedNumerator: null, expectedDenominator: null,
    why: 'no measurement was produced; an infra result is a reconciliation with a row, never a zero',
  }),
]);

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

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
    if (metrics.notMeasured !== 1) {
      out.push(finding('metrics.notMeasured', 1, metrics.notMeasured ?? 'absent', 'NOT_MEASURED_DIVERGES_FROM_TABLE'));
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
  return actual;
}
