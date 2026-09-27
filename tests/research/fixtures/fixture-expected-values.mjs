// The FROZEN EXPECTED-VALUE TABLE as the fixture set publishes it, and the
// argument a test hands to `compareParallelTrack` (A3).
//
// WHAT THIS IS
// Two things, and they are not the same thing:
//   1. `EXPECTED_VALUE_TABLE` — the DOCUMENT this fixture set publishes: what a
//      clean run A and a clean run B must contain, per TRIAL INDEX, per control,
//      per counter and per ledger property. It is DERIVED from the frozen table
//      and from the measurement set in this directory, so there is one authored
//      source (the frozen table's rows plus the per-case labels) and no second
//      hand-written copy of the same numbers.
//   2. `EXPECTED_TABLE_ARGUMENT` — the object `compareParallelTrack({..., expected})`
//      reads. `normaliseTable` looks for `EXPECTED_COUNTERS`,
//      `EXPECTED_TRIAL_DECISIONS`, `EXPECTED_CONTROLS`, `EXPECTED_METRIC` and
//      `digest`; the previous version of this file exported a document with
//      `trials`/`counters` keys, so a test that passed it got
//      `EXPECTED_TABLE_ABSENT` — "the frozen expected-value table was not
//      supplied; A === B is not a pass criterion" — and could not run the A3
//      path at all without importing the track's module by hand. A fixture that
//      cannot be handed to the function it exists to feed is half a fixture.
//
// WHAT THIS IS NOT
// It is not the authoritative table. The authoritative table is `EXPECTED_*` in
// `src/lib/research/expected-values.mjs` (W3), it is READ here, and it wins
// every disagreement. `assertFixtureTableMatchesFrozenTable()` is the check that
// proves it: it compares the derived document with the frozen constants field by
// field and throws at import on any difference, so a fixture edited to match a
// result is a load error, not a green test.
//
// WHY THE ROWS ARE INDEXED AND NOT KEYED BY TRIAL ID
// A substituted seed changes WHICH row scores a result (P2). Keyed by a stable
// id, a substitution could hide behind a row that still looks like itself;
// indexed, the substitution moves a different number and the table says so.
//
// WHY EVERY TRIAL HAS A ROW
// A trial cannot be deleted from the expectation by failing to run. The infra
// trial is in this table with a row that says VIOLATION, and so is every status
// that is not RESOLVED: absence is never the answer (A2).
//
// Serves: A2 (a skipped / unresolved / unmeasured trial is a VIOLATION),
// A3 (the table is the pass criterion; `A === B` is an extra condition) and
// the ticket's "negative, null and infra results are kept as first-class
// outcomes".
import {
  EXPECTED_CODES as FROZEN_CODES,
  EXPECTED_CONTROLS as FROZEN_CONTROLS,
  EXPECTED_COUNTERS as FROZEN_COUNTERS,
  EXPECTED_LEDGER_SHAPE as FROZEN_LEDGER_SHAPE,
  EXPECTED_METRIC as FROZEN_METRIC,
  EXPECTED_TRIAL_DECISIONS as FROZEN_TRIAL_DECISIONS,
  expectedTableDigest,
} from '../../../src/lib/research/expected-values.mjs';
import { fixtureDigest } from './fixture-digest.mjs';
import {
  CLEAN_LEDGER,
  CONTROL_LEVEL_COUNTERS,
  FIXTURE_DERIVED_DISAGREEMENTS,
  FIXTURE_HARD_GATE_COUNTERS,
  FIXTURE_TRIALS,
  POOLED_COUNTS,
  PREREGISTRATION,
  PREREGISTRATION_DIGEST,
  expectedCounters,
} from './fixture-measurement-set.mjs';
import { FIXED_INSTANT_ISO } from './fixture-fixed-clock.mjs';
import { RUN_IDENTITIES, RUN_LABELS } from './fixture-run-identity.mjs';

/**
 * The six control ids, closed. These are the ids written into
 * `evidence/s2-008-negative-controls.json`; a control outside this list is not
 * one of the six the track promises.
 * @type {ReadonlyArray<string>}
 */
export const CONTROL_IDS = Object.freeze([
  'holdout_peek',
  'seed_substitution',
  'budget_opacity',
  'label_substitution',
  'missing_evaluator',
  'corrupted_data',
]);

/**
 * The refusal codes each control may produce, and the codes NO run may ever
 * emit. This is the frozen table's `EXPECTED_CODES` verbatim, plus the
 * `clean_run` row the frozen table does not carry (a clean run emits nothing).
 *
 * WHY THE OLD BOARD-CODE CHECK WAS REMOVED, AND RECORDED HERE
 * The previous version of this file declared `{holdout_peek: ['BLOCKED_POLICY',
 * 'ACL_DENIED'], …}` and validated every name against the board's frozen
 * `ERROR_CODES`. Both halves were wrong for this track: `BLOCKED_POLICY` and
 * `ACL_DENIED` are BoardError CLASS codes, while the codes the track actually
 * emits on a refused peek are `HOLDOUT_UNSEAL_DIGEST_FORGED` and its siblings
 * (`src/lib/research/dataset.mjs:199`). The check therefore could never fire on
 * a real refusal, and it would have fired on the wrong names if the track ever
 * emitted them. A validation that is right about the wrong vocabulary is
 * decoration. The codes are now read from the frozen table, which is where the
 * vocabulary is decided.
 * @type {Readonly<Record<string, ReadonlyArray<string>>>}
 */
export const EXPECTED_CODES = Object.freeze({
  ...FROZEN_CODES,
  clean_run: Object.freeze([]),
});

/** The codes a run may never emit, whatever the outcome. @type {ReadonlyArray<string>} */
export const FORBIDDEN_CODES = FROZEN_CODES.forbidden;

/**
 * A clean run is asserted to emit none of the forbidden codes, which is a real
 * check rather than a comment: the `undeclared_code` control injects exactly
 * `BLIND_RETRY_AFTER_INFRA` — a member of the frozen forbidden set — so the
 * "before" state and the "after" state differ on a value both of them name.
 * @returns {boolean} `true` when the clean runs emit nothing.
 */
export function cleanRunEmitsNoForbiddenCode(run) {
  const codes = Array.isArray(run.codes) ? run.codes : [];
  return !codes.some((code) => FORBIDDEN_CODES.includes(String(code)));
}

/**
 * The per-control expectations, keyed by control id. The frozen descriptors
 * (`probe`, `mechanism`, `counter`, `mustFlipFrom`, `mustFlipTo`) are READ, not
 * re-declared; what this file adds is the artefact each control is written
 * into and the axis its flip has to reach. The exact before/after values live
 * with the variant in `fixture-corrupted-variants.mjs`, so there is one place
 * where a flip is declared rather than two that can disagree.
 * @type {ReadonlyArray<Readonly<object>>}
 */
export const EXPECTED_CONTROLS = Object.freeze(FROZEN_CONTROLS.map((control) => Object.freeze({
  ...control,
  artefact: `evidence/s2-008-negative-controls.json#${control.id}`,
  flips: {
    holdout_peek: 'the campaign verdict flips and the peek counter moves',
    seed_substitution: 'the table row for the substituted trial flips and the counter moves',
    budget_opacity: 'a BudgetExceeded refusal changes no byte, an expired reservation yields a reconciliation row',
    label_substitution: 'the causal guard throws and the campaign verdict flips',
    missing_evaluator: 'the trial verdict flips ALLOW to VIOLATION',
    corrupted_data: 'the campaign verdict flips and the corrupted field is NAMED',
  }[control.id],
})));

/**
 * One row per enumerated trial, indexed by position — the frozen rows plus the
 * reasons a reviewer can check the interval against. `expectedStatus`,
 * `expectedOutcome`, `expectedVerdict`, `expectedNumerator` and
 * `expectedDenominator` are READ from the frozen table; the derived block below
 * is what this fixture MEASURED and what the frozen rule DERIVED from it, and
 * the two are reported side by side so agreement is visible rather than assumed.
 * After the S2-008 repair the measured rows agree: the table declares the
 * outcome the rule derived (UNRESOLVED at 1 - alpha/m on an eight-case corpus),
 * and `FIXTURE_DERIVED_DISAGREEMENTS` is the record that would say otherwise.
 * @type {ReadonlyArray<Readonly<object>>}
 */
export const EXPECTED_TRIAL_DECISIONS = Object.freeze(FROZEN_TRIAL_DECISIONS.map((row) => {
  const trial = FIXTURE_TRIALS.find((item) => item.index === row.index);
  if (!trial) throw new Error(`FIXTURE_TABLE_ROW_UNMATCHED: the frozen table has a row at index ${String(row.index)} with no trial in the measurement set`);
  return Object.freeze({
    ...row,
    measured: trial.measured,
    not_measured: trial.not_measured,
    // What this fixture OBSERVED for the row, next to what the rule DERIVED
    // from the interval the same samples produce. Recorded because the
    // disagreement is a property of an eight-case corpus, and a reader who sees
    // only `expectedOutcome: 'POSITIVE'` would read it as a resolved result.
    observed_interval: trial.interval === null ? null : Object.freeze({
      observed: trial.observed,
      lower: trial.interval.lower,
      upper: trial.interval.upper,
      method: trial.interval.method,
    }),
    derived_outcome: trial.derived_outcome,
    derived_reason: trial.derived_reason,
    reason: {
      POSITIVE: 'the designed corpus sits above the frozen baseline: 7 of 8 cases agree',
      NULL: 'the designed corpus sits ON the frozen baseline: 6 of 8 cases agree, which is 0.75 exactly',
      NEGATIVE: 'the designed corpus sits below the frozen baseline: 5 of 8 cases agree',
      // The row every MEASURED trial now carries, and the reason is the frozen
      // rule's own answer rather than a comment about it: at the derived
      // confidence the eight-case interval straddles the frozen 0.75 baseline
      // OUTSIDE the 0.02 band, so `decisionFromInterval` returns
      // `interval_straddles_null_outside_noise_band` for 7/8, 6/8 and 5/8
      // alike (observed, exit 0). An eight-case corpus cannot resolve a 0.02
      // band at 98.33 % confidence, and the row says that instead of claiming an
      // effect the corpus does not carry.
      //
      // The key is derived from what the rule can answer, not typed for the
      // current table: with the key absent, every measured row published
      // `reason: undefined` after the re-derivation, which is a row that looks
      // explained and is not.
      UNRESOLVED: 'the eight-case interval straddles the frozen baseline outside the preregistered 0.02 band, so the frozen rule derives UNRESOLVED (interval_straddles_null_outside_noise_band) at the derived confidence 1 - alpha/family_size',
      INFRA: 'the trial produced no measurement; a reconciliation row is owed and no interval exists to compare',
    }[row.expectedOutcome],
    // Named so a test can assert the table was not edited to match a result.
    table_row_frozen_at: FIXED_INSTANT_ISO,
  });
}));

/**
 * The frozen metric expectation, READ from the table and extended with the
 * baseline the intervals are compared against. The pooled counts are named here
 * as well as in the runs, because "18 over 24" is the number a reader will want
 * and it must have exactly one home.
 * @type {Readonly<object>}
 */
export const EXPECTED_METRIC = Object.freeze({
  ...FROZEN_METRIC,
  baseline: PREREGISTRATION.frozen_baseline.value,
  pooled_counts: POOLED_COUNTS,
  pooled_basis: 'POOLED_TRIAL_COUNTS',
  not_measured_trials: POOLED_COUNTS.notMeasured,
});

/**
 * The frozen hard-gate counter expectation: every counter the TRACK freezes at
 * 0. `CONTROL_LEVEL_COUNTERS` (`corruptedControl`, `identicalWrong`,
 * `repeatRunDrift`) are gates over the control RECORD rather than members of a
 * run's counter block, and they are listed separately precisely so nobody adds
 * them to a run's `counters` and invents a seventh track counter.
 * @type {Readonly<Record<string, number>>}
 */
export const EXPECTED_COUNTERS = expectedCounters(FIXTURE_HARD_GATE_COUNTERS);

/**
 * The per-run expectations for the two process-separated runs. The two rows are
 * identical except for the process-local identity, which is the point of A3:
 * the runs must agree on everything a verdict depends on and differ only where
 * they are required to.
 * @type {Readonly<Record<string, Readonly<object>>>}
 */
export const EXPECTED_RUNS = Object.freeze(Object.fromEntries(RUN_LABELS.map((label) => {
  const identity = RUN_IDENTITIES[label];
  return [label, Object.freeze({
    run_letter: label,
    raw_run_id: identity.raw_run_id,
    nonce: identity.nonce,
    executor_id: identity.executor_id,
    // A === B is an EXTRA condition. The pass criterion is "both runs agree
    // with this table AND the controls flip"; agreement between two runs proves
    // reproducibility and nothing about correctness.
    digests_must_equal: true,
    agree_with_table: true,
    findings_must_be_empty: true,
  })];
})));

/**
 * The published document. What a harness prints and what a test reads; the
 * numbers in it are derived, and `assertFixtureTableMatchesFrozenTable` proves
 * the derivation still holds at import.
 * @type {Readonly<object>}
 */
export const EXPECTED_VALUE_TABLE = Object.freeze({
  version: 's2-008-fixture-expected-values-v2',
  // The authority: the digest of the track's frozen table, bare 64-hex, the
  // form `expectedValueIssues` and `normaliseTable` compare against.
  expected_table_digest: expectedTableDigest(),
  preregistration_id: PREREGISTRATION.preregistration_id,
  preregistration_digest: PREREGISTRATION_DIGEST,
  metric: EXPECTED_METRIC,
  trials: EXPECTED_TRIAL_DECISIONS,
  codes: EXPECTED_CODES,
  // Every hard-gate counter is 0 at the end of a clean run; the table says so,
  // so a counter that moved is a table failure and not a judgement call.
  counters: EXPECTED_COUNTERS,
  // The record kinds a clean journal contains are the frozen table's business
  // (`EXPECTED_LEDGER_SHAPE`), and the properties a run must show are the
  // fixture's (`CLEAN_LEDGER`). Both are published, neither is re-invented.
  ledger_shape: FROZEN_LEDGER_SHAPE,
  ledger: CLEAN_LEDGER,
  controls: EXPECTED_CONTROLS,
  control_level_counters_not_run_counters: CONTROL_LEVEL_COUNTERS,
  runs: EXPECTED_RUNS,
  assert_table_frozen: 'OK_while_the_derived_document_matches_the_frozen_table',
  // Published, not hidden: the design each trial was authored for, the outcome
  // the frozen table pins, and the decision the frozen rule derives from the
  // interval the same labels produce are three different things and all three
  // are named. The record is empty when the expectation was re-derived from the
  // measurements, and non-empty when they drift apart.
  derived_disagreements: FIXTURE_DERIVED_DISAGREEMENTS,
  latency: Object.freeze({ decides: false, source: 'FIXTURE_SYNTHETIC' }),
});

/**
 * The argument `compareParallelTrack({runA, runB, prereg, expected})` reads,
 * assembled from the FROZEN table's own exports plus the digest that binds it.
 *
 * `digest` is the bare 64-hex form. `expectedValueIssues` compares a run's
 * `expected_table_digest` with `expectedTableDigest()` and treats a `sha256:`
 * prefix as a different table, so a wire-form digest here would make every run
 * report `TABLE_DIGEST_MISMATCH`.
 * @type {Readonly<object>}
 */
export const EXPECTED_TABLE_ARGUMENT = Object.freeze({
  EXPECTED_TRIAL_DECISIONS: FROZEN_TRIAL_DECISIONS,
  EXPECTED_CODES: FROZEN_CODES,
  EXPECTED_COUNTERS: FROZEN_COUNTERS,
  EXPECTED_LEDGER_SHAPE: FROZEN_LEDGER_SHAPE,
  EXPECTED_METRIC: FROZEN_METRIC,
  EXPECTED_CONTROLS: FROZEN_CONTROLS,
  digest: expectedTableDigest(),
});

/**
 * The canonical digest of the PUBLISHED document, in wire form. The run records
 * carry the FROZEN table's digest, not this one; this digest exists so that a
 * test can prove the published document it handed around did not change, and it
 * is deliberately a different value from `expectedTableDigest()`.
 * @returns {string} `sha256:<64 hex>`.
 */
export function expectedTableFixtureDigest() {
  return fixtureDigest(EXPECTED_VALUE_TABLE);
}

/**
 * Prove the derived document still agrees with the frozen table, field by
 * field. This is the check that makes the derivation above safe: without it,
 * "derived" is a claim about how the file was written rather than a property of
 * the bytes, and a later edit of either side would go unnoticed.
 * @returns {true}
 * @throws {Error} `FIXTURE_TABLE_DIVERGES_FROM_FROZEN` naming the field.
 */
export function assertFixtureTableMatchesFrozenTable() {
  if (EXPECTED_VALUE_TABLE.expected_table_digest !== expectedTableDigest()) {
    throw new Error('FIXTURE_TABLE_DIVERGES_FROM_FROZEN: expected_table_digest');
  }
  for (const [index, row] of EXPECTED_TRIAL_DECISIONS.entries()) {
    const frozen = FROZEN_TRIAL_DECISIONS[index];
    for (const field of ['index', 'trial', 'expectedStatus', 'expectedOutcome', 'expectedVerdict', 'expectedNumerator', 'expectedDenominator']) {
      if (row[field] !== frozen[field]) {
        throw new Error(`FIXTURE_TABLE_DIVERGES_FROM_FROZEN: trials[${String(index)}].${field}`);
      }
    }
  }
  for (const control of EXPECTED_CONTROLS) {
    const frozen = FROZEN_CONTROLS.find((entry) => entry.id === control.id);
    if (!frozen) throw new Error(`FIXTURE_TABLE_DIVERGES_FROM_FROZEN: controls has no frozen row for ${String(control.id)}`);
    for (const field of ['probe', 'mechanism', 'counter', 'mustFlipFrom', 'mustFlipTo']) {
      if (control[field] !== frozen[field]) {
        throw new Error(`FIXTURE_TABLE_DIVERGES_FROM_FROZEN: controls.${String(control.id)}.${field}`);
      }
    }
  }
  for (const name of FIXTURE_HARD_GATE_COUNTERS) {
    if (EXPECTED_COUNTERS[name] !== FROZEN_COUNTERS[name]) {
      throw new Error(`FIXTURE_TABLE_DIVERGES_FROM_FROZEN: counters.${String(name)}`);
    }
  }
  if (EXPECTED_METRIC.name !== FROZEN_METRIC.name || EXPECTED_METRIC.noiseBand !== FROZEN_METRIC.noiseBand) {
    throw new Error('FIXTURE_TABLE_DIVERGES_FROM_FROZEN: metric');
  }
  return true;
}

/**
 * Return a COPY of `table` with one row replaced. The corruption the
 * `corrupted_expected_table` control needs.
 *
 * Never mutates: the clean table must stay byte-identical so that "the clean
 * comparison still passes" remains provable after the corrupted one has run
 * (the same reason `injectCorruption` in the comparator copies rather than
 * edits).
 * @param {object} table A table, normally `EXPECTED_VALUE_TABLE`.
 * @param {number} index The trial INDEX whose row is replaced.
 * @param {object} patch The fields to replace on that row.
 * @returns {object} A new table with the patched row; the input is untouched.
 * @throws {Error} `FIXTURE_TABLE_ROW_UNKNOWN` for an index with no row.
 */
export function withExpectedRow(table, index, patch) {
  if (!table.trials.some((row) => row.index === index)) {
    throw new Error(`FIXTURE_TABLE_ROW_UNKNOWN: no row with index ${String(index)}`);
  }
  const rows = table.trials.map((row) => (row.index === index ? Object.freeze({ ...row, ...patch }) : row));
  return Object.freeze({ ...table, trials: Object.freeze(rows) });
}

assertFixtureTableMatchesFrozenTable();
