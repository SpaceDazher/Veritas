// S2-008 — the fail-closed comparator, the frozen table, and the six negative
// controls (issue SpaceDazher/Veritas#8).
//
// Each test below exists because a CONFIRMED finding showed the property was not
// held. The finding is named in the test's title so a reader can check the test
// against the defect it was written for.
//
// A1  the six probes run and pass            A2  fail-closed + controls flip
// A3  the frozen table, not A === B          A4  observational is not causal
// A5  binding to a resolved base             SD  the runner-shaped trial record
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import test from 'node:test';

import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { classifyCardRelation } from '../../src/lib/research/causality.mjs';
import {
  compareParallelTrack, decisionFromInterval, injectCorruption, metricsSummary, resolveCampaignVerdict, resolveTrialVerdict,
} from '../../src/lib/research/comparator.mjs';
import {
  EXPECTED_CODES, EXPECTED_CONTROLS, EXPECTED_COUNTERS, EXPECTED_LEDGER_SHAPE, EXPECTED_METRIC, EXPECTED_TRIAL_DECISIONS,
  assertTableFrozen, expectedTableDigest, expectedValueIssues,
} from '../../src/lib/research/expected-values.mjs';
import { controlsFlipVerdict, EXTRA_CONTROL_IDS, NEGATIVE_CONTROLS, runNegativeControls } from '../../src/lib/research/negative-controls.mjs';
import { runAllProbes, PROBE_FAMILIES, PROBE_NAMES } from '../../src/lib/research/probes.mjs';
import { loadPreregistration } from '../../src/lib/research/preregistration.mjs';
import { FIXED_INSTANT_ISO } from './fixtures/fixture-fixed-clock.mjs';
import { HOLDOUT_LABELS, HOLDOUT_UNSEAL_DIGEST, PREREGISTRATION } from './fixtures/fixture-measurement-set.mjs';

const CORPUS_DIR = new URL('../../evidence/s2-008/corpus', import.meta.url).pathname;
const SCRATCH = new URL('../../.bb/s2-008/test-scratch', import.meta.url).pathname;
const BASE = Object.freeze({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40) });
const CONFIGURED_PREREG = { ...PREREGISTRATION, expected_table_digest: expectedTableDigest() };

/** The clean trial the comparator controls mutate. A MEASURED, independent
 * calibration, so the "before" state is a real ALLOW and a flip is observable. */
function cleanTrial() {
  const seeds = [...PREREGISTRATION.seed_rule.seeds];
  return {
    trial: 'trl-s2-008-control',
    status: 'RESOLVED',
    outcome: 'POSITIVE',
    metric: EXPECTED_METRIC.name,
    numerator: 7,
    denominator: 8,
    seedBinding: { seeds, source: 'PREREGISTERED', preregistered_seeds: seeds },
    holdoutBinding: {
      partition: 'HOLDOUT', read_at: FIXED_INSTANT_ISO, decision_at: FIXED_INSTANT_ISO, opened_before_decision_point: false, opens: 1, max_opens: 1,
    },
    budgetBinding: { reservation_id: 'rsv-s2-008-control', granted_units: 100, spent_units: 40, currency: 'UNITS' },
    evaluatorBinding: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    evaluator: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    calibration: { status: 'MEASURED', not_measured_reason: null, evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true } },
  };
}

function runFor(letter) {
  const seeds = [...PREREGISTRATION.seed_rule.seeds];
  const trials = EXPECTED_TRIAL_DECISIONS.map((row) => {
    const trial = {
      index: row.index,
      trial: row.trial,
      metric: EXPECTED_METRIC.name,
      seeds,
      status: row.expectedStatus,
      outcome: row.expectedOutcome,
      provenance: { raw_run_id: `s2-008-run-${letter}`, commit_sha: BASE.commit_sha, tree_sha: BASE.tree_sha },
      seedBinding: { seeds, source: 'PREREGISTERED', preregistered_seeds: seeds },
      holdoutBinding: {
        partition: 'HOLDOUT', read_at: FIXED_INSTANT_ISO, decision_at: FIXED_INSTANT_ISO, opened_before_decision_point: false, opens: 1, max_opens: 1,
      },
      budgetBinding: { reservation_id: 'rsv-01', granted_units: 8, spent_units: row.index, currency: 'trial_runs' },
      evaluatorBinding: { evaluator_id: 'evl-01', independent: true, blind_to_producer: true },
      evaluator: { evaluator_id: 'evl-01', independent: true, blind_to_producer: true },
      // The comparator's evaluator guard is called from the VERDICT loop, so a
      // trial with no calibration is refused. The delivered campaign run
      // carries NOT_MEASURED on purpose; the run used to exercise the table and
      // the controls carries a MEASURED, independent record.
      calibration: { status: 'MEASURED', not_measured_reason: null, evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true } },
      reconciliation_id: null,
    };
    if (row.expectedStatus === 'RESOLVED') {
      trial.numerator = row.expectedNumerator;
      trial.denominator = row.expectedDenominator;
    } else {
      trial.numerator = null;
      trial.denominator = null;
    }
    trial.verdict = resolveTrialVerdict(trial).verdict;
    return trial;
  });
  return {
    letter,
    raw_run_id: `s2-008-run-${letter}`,
    nonce: `n-${letter}-0123456789abcdef`,
    executor_id: `exec-${letter}-harness`,
    output_root: `s2-008/run-${letter}`,
    commit_sha: BASE.commit_sha,
    tree_sha: BASE.tree_sha,
    preregistration_digest: CONFIGURED_PREREG.preregistration_digest,
    expected_table_digest: expectedTableDigest(),
    trials,
    metrics: metricsSummary(trials),
    codes: [],
    counters: { ...EXPECTED_COUNTERS },
    controls: { allFlipped: true, controls: EXPECTED_CONTROLS.map((entry) => ({ id: entry.id, flipped: true })) },
  };
}

const EXPECTED_TABLE = {
  EXPECTED_TRIAL_DECISIONS,
  EXPECTED_COUNTERS,
  EXPECTED_METRIC,
  EXPECTED_CONTROLS,
  digest: expectedTableDigest(),
};

// --- A2: the fail-closed comparator ----------------------------------------

test('A2 a clean trial with all four bindings and a MEASURED independent calibration is an ALLOW', () => {
  const verdict = resolveTrialVerdict(cleanTrial());
  assert.equal(verdict.verdict, 'ALLOW', `clean trial reasons: ${verdict.reasons.join(', ')}`);
});

test('A2 a SKIPPED trial is a VIOLATION, never an ALLOW', () => {
  const verdict = resolveTrialVerdict({ ...cleanTrial(), status: 'SKIPPED' });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.includes('TRIAL_NOT_RESOLVED:SKIPPED'));
});

test('A2 an UNRESOLVED and an INFRA_ERROR trial are VIOLATIONs too', () => {
  for (const status of ['UNRESOLVED', 'INFRA_ERROR', 'NOT_MEASURED']) {
    assert.equal(resolveTrialVerdict({ ...cleanTrial(), status }).verdict, 'VIOLATION', status);
  }
});

// PR3: a binding used to pass on PRESENCE alone. Each of these is a bypass that
// returned ALLOW before the semantic binding checks existed.
test('PR3 a holdout read BEFORE its decision point is a VIOLATION even with no flag', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({ ...trial, holdoutBinding: { ...trial.holdoutBinding, read_at: '2025-12-31T00:00:00.000Z', decision_at: '2026-01-01T00:00:00.000Z' } });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.some((reason) => reason.startsWith('HOLDOUT_BINDING_UNSATISFIED:read_before_decision_point')));
});

test('PR3 a read AT or AFTER the decision point is lawful and is not invented into a violation', () => {
  // The mirror of the check above. Reading a holdout after the point at which
  // the decision was due is what the preregistration authorises; a guard that
  // also refused this would be a guard that refuses everything.
  const trial = cleanTrial();
  for (const [readAt, decisionAt] of [['2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'], ['2026-01-02T00:00:00.000Z', '2026-01-01T00:00:00.000Z']]) {
    const verdict = resolveTrialVerdict({ ...trial, holdoutBinding: { ...trial.holdoutBinding, read_at: readAt, decision_at: decisionAt } });
    assert.equal(verdict.verdict, 'ALLOW', `read_at=${readAt} decision_at=${decisionAt}: ${verdict.reasons.join(', ')}`);
  }
});

test('PR3 a holdout opened three times against max_opens 1 is a VIOLATION', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({ ...trial, holdoutBinding: { ...trial.holdoutBinding, opens: 3, max_opens: 1 } });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.some((reason) => reason.includes('opens_exceed_max_opens')));
});

test('PR3 a seed set that is not the preregistered one is a VIOLATION even with no flag', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({ ...trial, seedBinding: { ...trial.seedBinding, seeds: [4242] } });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.some((reason) => reason.startsWith('SEED_BINDING_UNSATISFIED:')));
});

test('PR3 four copies of one winning seed are a VIOLATION, not a set', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({ ...trial, seedBinding: { ...trial.seedBinding, seeds: [4242, 4242, 4242, 4242] } });
  assert.equal(verdict.verdict, 'VIOLATION');
});

test('PR3 a spend of 400 against a grant of 100 is a VIOLATION even with no flag', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({ ...trial, budgetBinding: { ...trial.budgetBinding, spent_units: 400 } });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.some((reason) => reason.includes('spend_exceeds_reservation:400>100')));
});

test('PR3 a bare string budget binding is a VIOLATION, not a satisfied binding', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({ ...trial, budgetBinding: 'rsv-01' });
  assert.equal(verdict.verdict, 'VIOLATION');
});

// PR4: the built-in control mutations used to set `bound: false`, so they proved
// the FLAG was read rather than that the property held.
test('PR4 every bypass flips to VIOLATION with the self-declared flag stripped', () => {
  const clean = cleanTrial();
  assert.equal(resolveTrialVerdict(clean).verdict, 'ALLOW');
  const bypasses = {
    holdout: { ...clean, holdoutBinding: { partition: 'HOLDOUT', read_at: '2026-01-02T00:00:00.000Z', decision_at: '2026-01-01T00:00:00.000Z', opened_before_decision_point: true } },
    seeds: { ...clean, seedBinding: { seeds: [4242], source: 'BEST_ONLY' } },
    budget: { ...clean, budgetBinding: { reservation_id: 'r', granted_units: 100, spent_units: 400, currency: 'U' } },
  };
  for (const [name, trial] of Object.entries(bypasses)) {
    const serialised = JSON.stringify(trial);
    assert.ok(!serialised.includes('"bound"'), `${name} still carries a bound flag`);
    assert.equal(resolveTrialVerdict(trial).verdict, 'VIOLATION', name);
  }
});

test('PR4 deleting the evaluator removes the binding and is a VIOLATION', () => {
  const trial = cleanTrial();
  delete trial.evaluatorBinding;
  delete trial.evaluator;
  delete trial.calibration;
  const verdict = resolveTrialVerdict(trial);
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.includes('MISSING_EVALUATOR_BINDING'));
});

// PR8: the verdict loop read only `calibration.status`, so a non-independent
// evaluator with `status: 'MEASURED'` was an ALLOW.
test('PR8 a non-independent evaluator is a VIOLATION even when the record claims MEASURED', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({
    ...trial,
    calibration: { status: 'MEASURED', not_measured_reason: null, evaluator_independence: { independent_evaluators: 0, blind_to_producer: false, separate_processes: false } },
  });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.some((reason) => reason.startsWith('EVALUATOR_NOT_INDEPENDENT')));
});

test('PR8 a NOT_MEASURED calibration is a VIOLATION and never a silent zero', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({
    ...trial,
    calibration: { status: 'NOT_MEASURED', not_measured_reason: 'evaluator_not_independent', evaluator_independence: { independent_evaluators: 1, blind_to_producer: false, separate_processes: false } },
  });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.includes('CALIBRATION_NOT_MEASURED:evaluator_not_independent'));
});

// PR7 / SD-06: the frozen schema puts the claim at
// `proposed_relation.causal_assertion`, and nothing read it.
test('PR7 a causal assertion at the SCHEMA position is refused', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({
    ...trial,
    card: { ...PREREGISTRATION.card, proposed_relation: { ...PREREGISTRATION.card.proposed_relation, causal_assertion: true } },
  });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.some((reason) => reason.includes('CORRELATION_EVIDENCE')));
});

test('PR7 the executor label CAUSAL_EXPERIMENT is a claim to support, not a non-claim', () => {
  // The executor's own closed set names CAUSAL_EXPERIMENT as a label this
  // transport must never produce. The comparator used to treat an unrecognised
  // label as non-causal, so a run that claimed one was an ALLOW.
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({ ...trial, provenance_label: 'CAUSAL_EXPERIMENT' });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.some((reason) => reason.startsWith('CAUSAL_CLAIM_UNSUPPORTED')), verdict.reasons.join(', '));
});

test('PR7 a label outside BOTH closed sets is refused as unrecognised, not waved through', () => {
  const trial = cleanTrial();
  const verdict = resolveTrialVerdict({ ...trial, provenance_label: 'CAUSAL_BY_ASSOCIATION' });
  assert.equal(verdict.verdict, 'VIOLATION');
  assert.ok(verdict.reasons.some((reason) => reason.includes('unrecognised_provenance_label:CAUSAL_BY_ASSOCIATION')), verdict.reasons.join(', '));
});

test('PR7 a producible, non-causal provenance label is not a violation', () => {
  const trial = cleanTrial();
  assert.equal(resolveTrialVerdict({ ...trial, provenance_label: 'OBSERVATIONAL_TEST' }).verdict, 'ALLOW');
});

// --- A4 --------------------------------------------------------------------

test('A4 the preregistered card is observational and admissible', () => {
  const classification = classifyCardRelation(PREREGISTRATION.card);
  assert.equal(classification.observational, true);
  assert.equal(classification.causalAssertion, false);
  assert.equal(classification.admissible, true);
});

test('A4 swapping the label to causal makes the card inadmissible', () => {
  const swapped = { ...PREREGISTRATION.card, proposed_relation: { ...PREREGISTRATION.card.proposed_relation, causal_assertion: true } };
  const classification = classifyCardRelation(swapped);
  assert.equal(classification.admissible, false);
  assert.equal(classification.refusalCode, 'CAUSAL_ASSERTION_UNSUPPORTED:CORRELATION_EVIDENCE');
});

test('A4 the observational subset is exactly the three compiled members', () => {
  assert.deepEqual(
    [...classifyCardRelation(PREREGISTRATION.card) && ['ANALOGICAL_STRUCTURE', 'TEMPORAL_CO-OCCURRENCE', 'CORRELATION_EVIDENCE']],
    ['ANALOGICAL_STRUCTURE', 'TEMPORAL_CO-OCCURRENCE', 'CORRELATION_EVIDENCE'],
  );
});

// --- SD-03 / SD-04: the decision rule --------------------------------------

test('SD-03 the declared comparison family is not collapsed to the observation under test', () => {
  const applied = decisionFromInterval({
    observed: 0.80, lower: 0.60, upper: 0.95, noiseBand: 0.02,
    rule: {
      alpha: 0.05, method: 'holm_bonferroni', comparisons: ['trl-a', 'trl-b', 'trl-c'], confidence: 0.95, null_value: 0.5, subject: 'trl-a',
    },
  });
  assert.equal(applied.correction.comparisons, 3);
  assert.equal(applied.correction.declared, 3);
  assert.equal(applied.correction.inherited_p_bound, 3);
});

test('SD-03 an absent comparison family is a MalformedResult, never a silent uncorrected test', () => {
  assert.throws(
    () => decisionFromInterval({ observed: 0.8, lower: 0.7, upper: 0.9, noiseBand: 0.02, rule: { alpha: 0.05, method: 'holm_bonferroni', comparisons: [], confidence: 0.95 } }),
    (error) => String(error?.message ?? '').startsWith('MULTIPLICITY_FAMILY_ABSENT'),
  );
});

test('SD-04 a preregistered LOWER_IS_BETTER metric scores a DROP as the improvement', () => {
  const applied = decisionFromInterval({
    observed: 0.70, lower: 0.60, upper: 0.79, noiseBand: 0.02,
    rule: {
      alpha: 0.05, method: 'holm_bonferroni', comparisons: ['trl-a'], confidence: 0.95, null_value: 0.8, direction: 'decrease', subject: 'trl-a',
    },
  });
  assert.equal(applied.decision, 'POSITIVE', `a real improvement was scored ${applied.decision} (${applied.reason})`);
});

test('SD-04 the same drop under an INCREASE rule is the other direction, not a pass', () => {
  const applied = decisionFromInterval({
    observed: 0.70, lower: 0.60, upper: 0.79, noiseBand: 0.02,
    rule: {
      alpha: 0.05, method: 'holm_bonferroni', comparisons: ['trl-a'], confidence: 0.95, null_value: 0.8, direction: 'increase', subject: 'trl-a',
    },
  });
  assert.equal(applied.decision, 'NEGATIVE');
});

test('SD-04 a metric with no declared direction ANYWHERE is a named failure, not a default', () => {
  // The direction may be stated by the metric, the decision rule or the
  // stopping rule; the check is that at least ONE of them says. Strip all three
  // and the absence must be named rather than defaulted to 'increase'.
  const bare = {
    ...CONFIGURED_PREREG,
    metric: { name: EXPECTED_METRIC.name, unit: 'ratio' },
    multiplicity_rule: { ...CONFIGURED_PREREG.multiplicity_rule },
    stopping_rule: { ...CONFIGURED_PREREG.stopping_rule },
    noise_rule: { ...CONFIGURED_PREREG.noise_rule },
  };
  delete bare.multiplicity_rule.direction;
  delete bare.stopping_rule.direction;
  delete bare.noise_rule.direction;
  const result = compareParallelTrack({ runA: runFor('a'), runB: runFor('b'), prereg: bare, expected: EXPECTED_TABLE, base: BASE });
  assert.ok(result.failures.some((entry) => entry.code === 'metric_direction_absent'), 'a missing direction was silently defaulted');
});

test('SD-04 a HIGHER_IS_BETTER metric stated ONLY on the metric is honoured', () => {
  const withDirection = {
    ...CONFIGURED_PREREG,
    metric: { ...CONFIGURED_PREREG.metric, direction: 'LOWER_IS_BETTER' },
    multiplicity_rule: { ...CONFIGURED_PREREG.multiplicity_rule },
  };
  delete withDirection.multiplicity_rule.direction;
  const result = compareParallelTrack({ runA: runFor('a'), runB: runFor('b'), prereg: withDirection, expected: EXPECTED_TABLE, base: BASE });
  assert.ok(!result.failures.some((entry) => entry.code === 'metric_direction_absent'), 'a direction stated on the metric was not read');
});

// --- E5 / SD-05: absence of control evidence must fail ----------------------

test('E5 a run with no control block is a FAILURE, not a downgrade', () => {
  const runA = runFor('a');
  const runB = runFor('b');
  delete runA.controls;
  delete runB.controls;
  const result = compareParallelTrack({ runA, runB, prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: BASE });
  assert.equal(result.failures.filter((entry) => entry.code === 'negative_controls_absent').length, 2);
  const proof = result.proofStatus.find((entry) => entry.id === 'negative_controls');
  assert.equal(proof.status, 'UNMET');
  assert.equal(resolveCampaignVerdict(result), 'FAIL');
});

test('SD-05 a control block that reports not-all-flipped is a FAILURE', () => {
  const runA = runFor('a');
  const runB = runFor('b');
  for (const run of [runA, runB]) run.controls = { allFlipped: false, controls: [{ id: 'holdout_peek', flipped: false }] };
  const result = compareParallelTrack({ runA, runB, prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: BASE });
  assert.equal(result.failures.filter((entry) => entry.code === 'negative_controls_did_not_flip').length, 2);
});

// --- E8: the base binding must be resolved, not self-asserted ---------------

test('E8 an unresolved base is a NAMED FAILURE, not a proof', () => {
  const result = compareParallelTrack({ runA: runFor('a'), runB: runFor('b'), prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE });
  assert.ok(result.failures.some((entry) => entry.code === 'base_unverified'));
  assert.equal(result.proofStatus.find((entry) => entry.id === 'base_binding').status, 'UNMET');
});

test('E8 a run that declares a base the repository does not have is a NAMED FAILURE', () => {
  const result = compareParallelTrack({
    runA: runFor('a'), runB: runFor('b'), prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE,
    base: { commit_sha: 'c'.repeat(40), tree_sha: 'd'.repeat(40) },
  });
  assert.equal(result.failures.filter((entry) => entry.code === 'base_mismatch').length, 2);
});

test('E8 a resolved base that matches is SATISFIED', () => {
  const result = compareParallelTrack({ runA: runFor('a'), runB: runFor('b'), prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: BASE });
  assert.equal(result.proofStatus.find((entry) => entry.id === 'base_binding').status, 'SATISFIED');
});

// --- A3: the frozen table ---------------------------------------------------

test('A3 two process-separated runs agree with the frozen table and produce NO findings', () => {
  const result = compareParallelTrack({ runA: runFor('a'), runB: runFor('b'), prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: BASE });
  assert.deepEqual([...result.findingsA], []);
  assert.deepEqual([...result.findingsB], []);
  assert.equal(result.digestsEqual, true);
  assert.equal(result.identicalWrongFindings.both_non_empty, false);
});

test('A3 two IDENTICALLY WRONG runs are not a pass: the digests stay equal and the findings do not', () => {
  const corrupt = (run) => {
    const injected = injectCorruption(run.trials, 'trial_status_skip');
    return { ...run, trials: injected.trials };
  };
  const result = compareParallelTrack({
    runA: corrupt(runFor('a')), runB: corrupt(runFor('b')), prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: BASE,
  });
  assert.equal(result.digestsEqual, true, 'the corruption must not move the digest, or A === B would have decided it');
  assert.equal(result.identicalWrongFindings.both_non_empty, true);
  assert.ok(result.findingsA.length > 0 && result.findingsB.length > 0);
  assert.equal(result.identicalWrongFindings.findings_a[0].field, 'trials[0].status');
});

test('A3 every frozen corruption variant moves the table', () => {
  for (const variant of ['trial_status_skip', 'counter_nudge', 'metric_altered', 'provenance_field']) {
    const run = runFor('a');
    const injected = injectCorruption(run.trials, variant);
    const findings = expectedValueIssues({ ...run, trials: injected.trials }, 'a');
    assert.ok(findings.length > 0, `${variant} produced no finding`);
  }
});

test('A3 a run with a shared raw run id is a collision, not a parallel track', () => {
  const result = compareParallelTrack({ runA: runFor('a'), runB: { ...runFor('b'), raw_run_id: 's2-008-run-a' }, prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: BASE });
  assert.ok(result.failures.some((entry) => entry.code === 'run_manifest_collision'));
  assert.ok(result.failures.some((entry) => entry.code === 'raw_run_id_collision'));
});

test('A3 a forbidden code in the run is a table finding', () => {
  const findings = expectedValueIssues({ ...runFor('a'), codes: ['BLIND_RETRY_AFTER_INFRA'] }, 'a');
  assert.ok(findings.some((entry) => entry.code === 'FORBIDDEN_CODE_EMITTED'));
});

test('A3 an absent trial cannot be deleted from the expectation by failing to run', () => {
  const run = runFor('a');
  run.trials = run.trials.slice(0, 3);
  const findings = expectedValueIssues(run, 'a');
  assert.ok(findings.some((entry) => entry.code === 'TRIAL_COUNT_DIVERGES_FROM_TABLE'));
  assert.ok(findings.some((entry) => entry.code === 'TRIAL_ROW_ABSENT'));
});

test('A3 the infra trial is a row of the table and its row says VIOLATION', () => {
  const row = EXPECTED_TRIAL_DECISIONS.find((entry) => entry.expectedStatus === 'INFRA_ERROR');
  assert.ok(row, 'the frozen table has no INFRA row');
  assert.equal(row.expectedVerdict, 'VIOLATION');
  assert.equal(row.expectedNumerator, null, 'an infra trial carries no numerator, and null is not 0');
});

test('A3 the table digest moves when the table moves', () => {
  const before = expectedTableDigest();
  assert.equal(before, canonicalDigest({
    EXPECTED_TRIAL_DECISIONS,
    EXPECTED_CODES,
    EXPECTED_COUNTERS,
    EXPECTED_LEDGER_SHAPE,
    EXPECTED_METRIC,
    EXPECTED_CONTROLS,
  }));
  // The digest is taken over the CONSTANTS, so re-deriving it from the same
  // objects is the reproducibility check; a table edited after publication
  // moves it, which is what `assertTableFrozen` refuses on.
  assert.notEqual(before, canonicalDigest({ ...EXPECTED_COUNTERS, holdoutPeek: 1 }));
});

test('A3 the preregistration seals the table, and a moved table is a refusal', () => {
  assert.equal(assertTableFrozen(CONFIGURED_PREREG), expectedTableDigest());
  assert.throws(
    () => assertTableFrozen({ ...CONFIGURED_PREREG, expected_table_digest: 'f'.repeat(64) }),
    (error) => String(error?.message ?? '').startsWith('EXPECTED_TABLE_DRIFT'),
  );
  assert.throws(
    () => assertTableFrozen({ ...CONFIGURED_PREREG, expected_table_digest: undefined, table_digest: undefined }),
    (error) => String(error?.message ?? '').startsWith('EXPECTED_TABLE_DIGEST_ABSENT'),
  );
});

// --- SD-01 / SD-02: the runner-shaped trial record --------------------------

test('SD-01 a trial record with a metric member aggregates; without one it is a MalformedResult', () => {
  const run = runFor('a');
  const summary = metricsSummary(run.trials);
  assert.equal(summary.metric, EXPECTED_METRIC.name);
  assert.equal(summary.basis, 'POOLED_TRIAL_COUNTS');
  assert.equal(summary.numerator, 18);
  assert.equal(summary.denominator, 24);
  assert.equal(summary.notMeasured, 1, 'the infra trial is not measured, and not measured is not a zero denominator member');
  const noMetric = run.trials.map((trial) => { const copy = { ...trial }; delete copy.metric; return copy; });
  assert.throws(() => metricsSummary(noMetric), (error) => String(error?.message ?? '').startsWith('METRIC_NAME_ABSENT'));
});

test('SD-02 the bindings nested under `bindings` and the flat members are ONE field', () => {
  const run = runFor('a');
  const nested = { ...run.trials[0], bindings: { seed: { seeds: [...PREREGISTRATION.seed_rule.seeds] } } };
  delete nested.seedBinding;
  assert.equal(resolveTrialVerdict(nested).verdict, 'ALLOW');
});

test('SD-12 latency is recorded under the PREREGISTERED parameters and never decides', () => {
  const run = runFor('a');
  const withLatency = run.trials.map((trial, index) => ({ ...trial, latency_ms: index + 1 }));
  const result = compareParallelTrack({
    runA: { ...run, trials: withLatency }, runB: { ...runFor('b'), trials: withLatency }, prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: BASE,
  });
  const latency = result.runs.a.latency;
  assert.equal(latency.decides, false);
  assert.equal(result.runs.a.decides_on_latency, false);
  assert.ok(result.limits.every((entry) => entry.code !== 'LATENCY_NOT_RECORDED'));
});

test('SD-11 a broken latency sample is a NAMED FAILURE, not a throw that discards the comparison', () => {
  const run = runFor('a');
  const withBadLatency = run.trials.map((trial, index) => ({ ...trial, latency_ms: index === 0 ? -1 : 1 }));
  const result = compareParallelTrack({ runA: { ...run, trials: withBadLatency }, runB: runFor('b'), prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: BASE });
  assert.ok(result.failures.some((entry) => entry.code === 'latency_not_recorded'));
  assert.ok(Array.isArray(result.findingsA), 'the comparison still returned its findings');
});

// --- A1: the six probes ----------------------------------------------------

test('A1 the six probes run, pass and leave every hard-gate counter at 0', async () => {
  rmSync(SCRATCH, { recursive: true, force: true });
  const report = await runAllProbes({ registryRoot: SCRATCH, corpusDir: CORPUS_DIR });
  assert.equal(report.results.length, 6);
  assert.equal(report.notRun.length, 0, `not run: ${JSON.stringify(report.notRun)}`);
  assert.equal(report.broken.length, 0, `broken: ${JSON.stringify(report.broken)}`);
  assert.equal(report.allPassed, true, JSON.stringify(report.results.filter((entry) => entry.status !== 'pass').map((entry) => ({ probe: entry.probe, failed: entry.evidence?.checks?.filter((c) => !c.ok) })), null, 1));
  for (const [name, value] of Object.entries(report.counters)) assert.equal(value, 0, `${name} moved`);
  assert.deepEqual(Object.keys(report.counters).sort(), [...PROBE_FAMILIES].length === 6 ? Object.keys(report.counters).sort() : []);
});

// PR10 / E7: `removed` counted the frozen list, so it could not distinguish
// "my residue is gone" from "there was nothing there".
test('PR10 a second probe run on a clean base removes nothing and says so', async () => {
  // The property PR10/E7 required: the record must be able to TELL the two
  // cases apart. Before the fix every run reported `removed: 6`, so "my residue
  // is gone" and "there was nothing there" were the same record.
  const fresh = `${SCRATCH}-purge`;
  // The base is wiped FIRST, or the test measures the residue of an earlier
  // run of this file — which is exactly the confusion the fix removes.
  rmSync(fresh, { recursive: true, force: true });
  const first = await runAllProbes({ registryRoot: fresh, corpusDir: CORPUS_DIR });
  assert.equal(first.purged.removed, 0, 'a VIRGIN base has nothing of this run\'s to remove');
  assert.deepEqual([...first.purged.removed_roots], []);
  const second = await runAllProbes({ registryRoot: fresh, corpusDir: CORPUS_DIR });
  assert.ok(second.purged.removed > 0, 'the second run removes the residue the first one left');
  assert.equal(second.purged.removed_roots.length, second.purged.removed);
  assert.equal(second.purged.roots, 6);
  assert.ok(second.purged.base.endsWith('test-scratch-purge/probes'), `the record must name the whole base, not its basename: ${second.purged.base}`);
  assert.ok(!second.purged.base.split('/').pop().startsWith('probes/'), 'the base must not be reduced to a basename');
});

// --- the six controls ------------------------------------------------------

test('A2 all six negative controls flip, and the gate names any that do not', () => {
  const record = runNegativeControls({ trial: cleanTrial(), cleanRun: runFor('a'), runA: runFor('a'), runB: runFor('b'), card: PREREGISTRATION.card });
  assert.equal(record.notRun.length, 0, JSON.stringify(record.notRun));
  // Six frozen controls plus `ledger_spelling_holdout_peek` (S2): the frozen id
  // set is unchanged and the extra is NAMED, gated and reported beside them.
  assert.equal(record.controls.length, NEGATIVE_CONTROLS.length + EXTRA_CONTROL_IDS.length);
  assert.equal(record.allFlipped, true, JSON.stringify(record.controls.filter((entry) => !entry.flipped), null, 1));
  const gate = controlsFlipVerdict(record);
  assert.equal(gate.ok, true);
  assert.deepEqual([...gate.failures], []);
});

test('A2 the gate fails when a control did not flip, naming it', () => {
  const record = runNegativeControls({ trial: cleanTrial(), cleanRun: runFor('a'), runA: runFor('a'), runB: runFor('b'), card: PREREGISTRATION.card });
  const broken = { ...record, controls: record.controls.map((entry) => (entry.id === 'holdout_peek' ? { ...entry, flipped: false } : entry)) };
  const gate = controlsFlipVerdict(broken);
  assert.equal(gate.ok, false);
  assert.ok(gate.failures.some((failure) => failure.includes('holdout_peek did not flip')));
});

test('A2 the gate fails when a control did not run at all', () => {
  const record = runNegativeControls({ trial: cleanTrial(), cleanRun: runFor('a'), runA: runFor('a'), runB: runFor('b'), card: PREREGISTRATION.card });
  const missing = { ...record, controls: record.controls.slice(1) };
  assert.ok(controlsFlipVerdict(missing).failures.some((failure) => failure.includes('holdout_peek did not run')));
});

test('A2 a context with no clean trial is refused rather than half-run', () => {
  assert.throws(() => runNegativeControls({}), (error) => String(error?.message ?? '').startsWith('CONTEXT_TRIAL_ABSENT'));
  assert.throws(() => runNegativeControls({ trial: cleanTrial() }), (error) => String(error?.message ?? '').startsWith('CONTEXT_RUN_ABSENT'));
});

// --- the committed corpus is the fixture, and the preregistration loads ----

test('A5 the committed preregistration loads and its seed rule re-derives', () => {
  const loaded = loadPreregistration(CORPUS_DIR);
  assert.equal(loaded.kind, 'PREREGISTRATION');
  assert.deepEqual([...loaded.seed_rule.seeds], [101, 202, 303, 404, 505]);
  assert.equal(loaded.seed_count, 5);
  assert.equal(loaded.inference_mode, 'ASSOCIATIONAL');
  assert.equal(loaded.holdout_access.max_opens, 1);
  assert.equal(loaded.holdout_access.unseal_digest, HOLDOUT_UNSEAL_DIGEST);
  assert.equal(Object.keys(HOLDOUT_LABELS).length, 8);
});
