// S2-008 — the fail-closed comparator, the corrupted controls and the six
// negative probes (issue SpaceDazher/Veritas#8).
//
// WHAT THIS FILE IS, AGAINST tests/research/comparator.test.mjs
// `comparator.test.mjs` asserts that the comparator behaves. This file asserts
// that it is SENSITIVE: every test here injects something and requires the
// verdict to MOVE, or requires the refusal to be typed. A comparator that is
// merely self-consistent passes the other file and fails this one.
//
// THE FOUR AXES THE TICKET NAMES, AND WHERE EACH IS PROVEN
//   A2 fail-closed        a skipped, unresolved, infra, unmeasured, unknown or
//                          MISSING trial is a VIOLATION; no third outcome exists
//   A2 controls flip      every corrupted control moves a NAMED axis
//   A4 no causal reading  a causal claim over an observational result is
//                          refused with a TYPED error, and the frozen schema
//                          cannot see it — which is why the code guard can
//   latency decides nothing   the CI and the multiple-comparison correction
//                          come from the preregistration rule; wall-clock
//                          samples are recorded and can raise a LIMIT only
//   probes                 the six families run, each control flips, and a
//                          control that does NOT flip is reported as `broken`
//                          rather than passed
//
// DETERMINISM
// No network, no LLM, no credentials, no process clock. "Now" is the injected
// FIXED_CLOCK, the scratch roots are `mkdtemp` directories under the OS temp
// dir, and the id factory is a counter scoped by the test's own slug, so a
// repeat run on the same base produces the same result. No test depends on
// another test having run first (npm test uses --test-concurrency=1, and this
// file is written to be order-independent anyway).
//
// WHAT IS ASSERTED AND WHAT IS NOT
// Every expectation below was MEASURED against the code before it was written;
// the measured values are in the comment above each block. Where a fixture
// declares an expectation and the code disagrees, this file asserts the MEASURED
// value and says so, rather than asserting the declaration and going red. There
// is one such case, recorded in place: the preregistration spells the noise band
// `noise_rule.band` while `scoreMetric` reads `noise_rule.noise_band`
// (src/lib/research/comparator.mjs:1444), so the campaign's band is sourced from
// the FROZEN TABLE and a preregistration-side drift in `band` is not caught.
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { BlockedPolicy, MalformedResult, NeedsInput } from '../../src/lib/agentboard/errors.mjs';
import {
  bestSeedDisclosure, COMPARATOR_VERSION, compareParallelTrack, decisionFromInterval, injectCorruption,
  latencyRecorded, metricsSummary, resolveCampaignVerdict, resolveTrialVerdict, ruleFeasibility,
} from '../../src/lib/research/comparator.mjs';
import {
  assertNoCausalClaim, assertUsableAsResult, claimAssertsCausality, EXECUTOR_DISPOSITIONS,
  EXECUTOR_EVALUATOR_REASONS, EXECUTOR_INFERENCE_MODE, EXECUTOR_PRODUCIBLE_LABELS, EXECUTOR_PROVENANCE_LABELS,
  EXECUTOR_TRIAL_KINDS, EXECUTOR_TRIAL_STATUS_BY_OUTCOME, resolveEvaluatorAvailability, runTrial,
} from '../../src/lib/research/executor.mjs';
import { assertCausalDiscipline, assertNoCausalFromSimulation, classifyCardRelation } from '../../src/lib/research/causality.mjs';
import { isResearchContractValid } from '../../src/lib/research/contracts.mjs';
import { assertTableFrozen, expectedTableDigest } from '../../src/lib/research/expected-values.mjs';
import { TRIAL_STATUSES, TRIAL_VERDICTS } from '../../src/lib/research/constants.mjs';
import { controlsFlipVerdict, EXTRA_CONTROL_IDS, NEGATIVE_CONTROLS, runNegativeControls } from '../../src/lib/research/negative-controls.mjs';
import {
  HARD_GATE_COUNTERS, PROBE_FAMILIES, PROBE_NAMES, ProbeRecorder, runAllProbes, runProbe,
} from '../../src/lib/research/probes.mjs';

import { FIXED_CLOCK, FIXED_INSTANT_ISO } from './fixtures/fixture-fixed-clock.mjs';
import { CALIBRATIONS, HYPOTHESIS_CARD, PREREGISTERED_SEEDS } from './fixtures/fixture-preregistration.mjs';
import { CLEAN_RUNS, PREREGISTRATION } from './fixtures/fixture-measurement-set.mjs';
import { EXPECTED_TABLE_ARGUMENT } from './fixtures/fixture-expected-values.mjs';
import {
  buildVariant, EXPECTED_FLIPS, REQUIRED_VARIANT_IDS, VARIANT_IDS, assertTruncatedTailUnparseable,
} from './fixtures/fixture-corrupted-variants.mjs';

const CORPUS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'evidence', 's2-008', 'corpus');
/** The base the runs declare, resolved ONCE and passed in: `compareParallelTrack`
 * is pure and never calls git, so the resolution is the caller's job (E8). */
const BASE = Object.freeze({ commit_sha: CLEAN_RUNS.a.commit_sha, tree_sha: CLEAN_RUNS.a.tree_sha });
/** The three failure codes the CLEAN pair already carries, measured below. Every
 * "the corruption added a code" assertion subtracts exactly this set, so a new
 * failure introduced by a change to the clean fixtures is visible instead of
 * being absorbed into a control's expectation. */
const CLEAN_FAILURE_CODES = Object.freeze(['decision_unresolved', 'metric_not_measured', 'trial_violation']);

/** The comparison inputs `compareParallelTrack` reads. Every test builds its own
 * so no test depends on a shared mutable record. */
function compare(over = {}) {
  return compareParallelTrack({
    runA: over.runA ?? CLEAN_RUNS.a,
    runB: over.runB ?? CLEAN_RUNS.b,
    prereg: over.prereg ?? PREREGISTRATION,
    expected: over.expected ?? EXPECTED_TABLE_ARGUMENT,
    base: 'base' in over ? over.base : BASE,
  });
}

const codesOf = (result) => [...new Set(result.failures.map((entry) => entry.code))].sort();
const addedCodes = (result) => codesOf(result).filter((code) => !CLEAN_FAILURE_CODES.includes(code));

/** The comparator's verdict for the fixture's clean trial 0 — the "before" state
 * every control has to move. Asserted once, loudly, because a control built on
 * a "before" that is already a VIOLATION proves nothing. */
const CLEAN_TRIAL = CLEAN_RUNS.a.trials[0];

// ===========================================================================
// A2 — the fail-closed comparator. A skipped, unresolved, infra, unmeasured,
//      unknown-status, unknown-outcome and MISSING trial are all VIOLATION.
// ===========================================================================

describe('A2 fail-closed: no non-resolved trial may produce ALLOW', () => {
  test('the clean trial 0 is ALLOW, so every flip below is a real flip', () => {
    assert.equal(CLEAN_TRIAL.verdict, 'ALLOW');
    const resolved = resolveTrialVerdict(CLEAN_TRIAL);
    assert.equal(resolved.verdict, 'ALLOW', `clean reasons: ${resolved.reasons.join(', ')}`);
    assert.deepEqual([...resolved.reasons], []);
  });

  test('SKIPPED, UNRESOLVED, INFRA_ERROR and NOT_MEASURED are each a named VIOLATION', () => {
    for (const status of ['SKIPPED', 'UNRESOLVED', 'INFRA_ERROR', 'NOT_MEASURED']) {
      assert.ok(TRIAL_STATUSES.includes(status), `${status} is not in the frozen TRIAL_STATUSES`);
      const verdict = resolveTrialVerdict({ ...CLEAN_TRIAL, status });
      assert.equal(verdict.verdict, 'VIOLATION', `${status} was not fail-closed`);
      assert.ok(
        verdict.reasons.includes(`TRIAL_NOT_RESOLVED:${status}`),
        `${status} was not named: ${verdict.reasons.join(', ')}`,
      );
    }
  });

  test('a status outside the closed set is VIOLATION and is named as unknown, not defaulted', () => {
    const verdict = resolveTrialVerdict({ ...CLEAN_TRIAL, status: 'MEASURED_ENOUGH' });
    assert.equal(verdict.verdict, 'VIOLATION');
    assert.ok(verdict.reasons.includes('TRIAL_STATUS_UNKNOWN:MEASURED_ENOUGH'), verdict.reasons.join(', '));
  });

  test('an ABSENT status is VIOLATION; an absent status is not a resolved status', () => {
    for (const status of [undefined, null, '']) {
      const stripped = { ...CLEAN_TRIAL };
      if (status === undefined) delete stripped.status;
      else stripped.status = status;
      const verdict = resolveTrialVerdict(stripped);
      assert.equal(verdict.verdict, 'VIOLATION', `status=${String(status)}`);
      assert.ok(verdict.reasons.includes('TRIAL_STATUS_ABSENT'), `status=${String(status)}: ${verdict.reasons.join(', ')}`);
    }
  });

  test('a MISSING trial — an empty record — is VIOLATION and names every absent member', () => {
    const verdict = resolveTrialVerdict({});
    assert.equal(verdict.verdict, 'VIOLATION');
    assert.equal(verdict.status, 'UNKNOWN');
    for (const reason of [
      'TRIAL_ID_ABSENT', 'TRIAL_STATUS_ABSENT',
      'MISSING_SEED_BINDING', 'MISSING_HOLDOUT_BINDING',
      'MISSING_BUDGET_BINDING', 'MISSING_EVALUATOR_BINDING',
    ]) {
      assert.ok(verdict.reasons.includes(reason), `${reason} not named: ${verdict.reasons.join(', ')}`);
    }
  });

  test('a non-record trial is VIOLATION, not an exception and not an ALLOW', () => {
    for (const trial of [null, undefined, 42, 'trl-s2-008-01', []]) {
      assert.equal(resolveTrialVerdict(trial).verdict, 'VIOLATION', JSON.stringify(trial) ?? 'undefined');
    }
  });

  test('every status except RESOLVED is a VIOLATION — a sweep, not a list I chose', () => {
    // The closed set is read from constants.mjs, so a widened vocabulary would
    // make this assertion wider too rather than silently incomplete.
    for (const status of TRIAL_STATUSES) {
      const verdict = resolveTrialVerdict({ ...CLEAN_TRIAL, status });
      assert.equal(verdict.verdict, status === 'RESOLVED' ? 'ALLOW' : 'VIOLATION', status);
    }
  });

  test('the verdict is a member of the two-value closed set whatever the input', () => {
    assert.deepEqual([...TRIAL_VERDICTS].sort(), ['ALLOW', 'VIOLATION']);
    for (const status of [...TRIAL_STATUSES, 'NONSENSE', '', undefined]) {
      const trial = { ...CLEAN_TRIAL };
      if (status === undefined) delete trial.status; else trial.status = status;
      assert.ok(TRIAL_VERDICTS.includes(resolveTrialVerdict(trial).verdict), String(status));
    }
  });

  test('an UNKNOWN outcome on a run is a named table finding and a trial violation', () => {
    const tampered = {
      ...CLEAN_RUNS.a,
      trials: CLEAN_RUNS.a.trials.map((trial, index) => (index === 0 ? { ...trial, outcome: 'TENTATIVE' } : trial)),
    };
    const result = compare({ runA: tampered });
    const outcomeFindings = result.findingsA.filter((entry) => entry.field === 'trials[0].outcome');
    assert.ok(outcomeFindings.length > 0, 'an outcome outside the closed set produced no table finding');
    assert.ok(
      outcomeFindings.some((entry) => entry.code === 'OUTCOME_OUTSIDE_CLOSED_SET'),
      `no closed-set finding: ${JSON.stringify(outcomeFindings)}`,
    );
    assert.ok(result.failures.some((entry) => entry.code === 'table_disagreement'));
  });

  test('a run with NO trials is a named failure, not a clean result and not a zero', () => {
    const empty = { ...CLEAN_RUNS.a, trials: [] };
    const result = compare({ runA: empty });
    assert.ok(result.failures.some((entry) => entry.code === 'trials_absent'), codesOf(result).join(','));
    assert.ok(result.failures.some((entry) => entry.code === 'seed_set_incomplete'));
    assert.equal(result.proofStatus.find((entry) => entry.id === 'all_trials_resolved').status, 'UNMET');
  });

  test('an unmeasured trial is reported as not-measured and is never folded into a zero', () => {
    const summary = metricsSummary(CLEAN_RUNS.a.trials);
    assert.equal(summary.notMeasured, 1, 'the INFRA trial stopped being counted');
    assert.equal(summary.numerator, 18);
    assert.equal(summary.denominator, 24);
    assert.equal(summary.basis, 'POOLED_TRIAL_COUNTS');
    // The infra trial contributes NEITHER a success NOR a denominator member.
    assert.equal(summary.numerator / summary.denominator, 0.75);
    // And the table row for it is still present: a trial cannot be deleted from
    // the expectation by failing to run.
    assert.deepEqual([...compare().findingsA], [], 'the clean pair disagrees with its own table');
  });

  test('the CLEAN pair already carries exactly the three declared failure codes', () => {
    const result = compare();
    assert.deepEqual(codesOf(result), [...CLEAN_FAILURE_CODES].sort());
    assert.equal(resolveCampaignVerdict(result), 'FAIL');
    assert.equal(result.findingsA.length, 0);
    assert.equal(result.findingsB.length, 0);
    assert.equal(result.digestsEqual, true);
  });
});

// ===========================================================================
// A2 — every corrupted control FLIPS a named axis. One table-driven test over
//      the declared variants, then the individual controls the ticket names.
// ===========================================================================

describe('A2 controls: each corruption flips a NAMED axis', () => {
  test('every REQUIRED variant is a declared flip and the declared set is non-empty', () => {
    assert.deepEqual(
      [...REQUIRED_VARIANT_IDS],
      ['corrupted_measurement', 'corrupted_expected_table', 'label_substituted', 'missing_evaluator', 'truncated_trial'],
    );
    for (const variant of REQUIRED_VARIANT_IDS) {
      assert.equal(EXPECTED_FLIPS[variant].must_flip, true, variant);
    }
  });

  test('the clean pair has no findings, and every corrupted variant produces findings', () => {
    const clean = compare();
    assert.deepEqual([...clean.findingsA], []);
    for (const variant of VARIANT_IDS) {
      const run = compareVariant(variant, 'a');
      assert.ok(
        run.findingsA.length > 0 || addedCodes(run).length > 0,
        `${variant} neither produced a table finding nor a new failure code`,
      );
    }
  });

  test('each variant adds the failure codes its declaration names', () => {
    // `corrupted_expected_table` is excluded HERE and asserted on its own below.
    // Its declaration names `expected_table_digest_mismatch`, which is raised
    // only when the HONEST table is the one in force and a run declares the
    // corrupted digest; when the corrupted table is in force AND the runs are
    // re-bound to it — the configuration `compareVariant` builds, so the table
    // is what has to catch it — the added code is `table_disagreement`. Both are
    // asserted, in the test that builds each configuration explicitly, so this
    // loop does not have to pretend one declaration covers both.
    const declarable = VARIANT_IDS.filter((variant) => variant !== 'corrupted_expected_table');
    for (const variant of declarable) {
      const declared = EXPECTED_FLIPS[variant].expected_flip.failure_codes_added;
      const added = addedCodes(compareVariant(variant, 'a'));
      for (const code of declared) {
        assert.ok(added.includes(code), `${variant} did not add ${code}; added=${added.join(',') || 'none'}`);
      }
    }
  });

  test('a corrupted variant built from run B is the same corruption as from run A', () => {
    // Process identity is excluded from the DECISION digest, so a corruption
    // that behaves differently under one label is a corruption that is partly
    // an identity artefact. A3 needs the decision to be label-independent.
    for (const variant of VARIANT_IDS) {
      const fromA = compareVariant(variant, 'a');
      const fromB = compareVariant(variant, 'b');
      assert.deepEqual(codesOf(fromA), codesOf(fromB), variant);
      assert.equal(fromA.digestsEqual, fromB.digestsEqual, variant);
    }
  });

  test('building a variant leaves the clean inputs byte-identical', () => {
    const before = canonicalDigest({ run: CLEAN_RUNS.a, table: EXPECTED_TABLE_ARGUMENT });
    for (const variant of VARIANT_IDS) buildVariant(variant, { label: 'a' });
    assert.equal(canonicalDigest({ run: CLEAN_RUNS.a, table: EXPECTED_TABLE_ARGUMENT }), before);
  });

  // --- the frozen corruption variants of `injectCorruption` ----------------

  test('every `injectCorruption` variant flips the table and NAMES the field it moved', () => {
    // The `from` is declared per variant rather than read from the trial: for
    // two of the four the comparator hard-codes the before value it writes over
    // (`counter_nudge` writes 0 -> 1, `provenance_field` writes the run's own
    // raw_run_id -> 'run-forged'), and asserting a shared rule there would be
    // asserting a mechanism the module does not have.
    const cases = [
      { variant: 'trial_status_skip', field: 'trials[0].status', from: 'RESOLVED', to: 'SKIPPED' },
      { variant: 'counter_nudge', field: 'trials[0].counters.holdoutPeek', from: 0, to: 1 },
      { variant: 'metric_altered', field: 'trials[0].numerator', from: CLEAN_TRIAL.numerator, to: CLEAN_TRIAL.numerator + 1 },
      { variant: 'provenance_field', field: 'trials[0].provenance.raw_run_id', from: CLEAN_RUNS.a.raw_run_id, to: 'run-forged' },
    ];
    for (const { variant, field, from, to } of cases) {
      const corruptedA = injectCorruption(CLEAN_RUNS.a.trials, variant);
      const corruptedB = injectCorruption(CLEAN_RUNS.b.trials, variant);
      assert.equal(corruptedA.corrupted.variant, variant);
      assert.equal(corruptedA.corrupted.field, field, variant);
      assert.equal(corruptedA.corrupted.from, from, `${variant}: wrong "from"`);
      assert.equal(corruptedA.corrupted.to, to, `${variant}: wrong "to"`);
      // The `to` is the same in both runs and the `from` is each run's OWN
      // value: an identity field is the only member of a corruption description
      // that legitimately differs between two process-separated runs.
      assert.equal(corruptedB.corrupted.to, to, `${variant} wrote a different "to" in run B`);
      assert.equal(corruptedB.corrupted.from, variant === 'provenance_field' ? CLEAN_RUNS.b.raw_run_id : from, `${variant}: wrong "from" in run B`);
      const result = compare({ runA: { ...CLEAN_RUNS.a, trials: corruptedA.trials }, runB: { ...CLEAN_RUNS.b, trials: corruptedB.trials } });
      assert.ok(result.findingsA.length > 0, `${variant} produced no table finding`);
      assert.ok(
        result.findingsA.some((entry) => String(entry.field) === field),
        `${variant} findings did not name ${field}: ${JSON.stringify(result.findingsA).slice(0, 240)}`,
      );
    }
  });

  test('`injectCorruption` does not mutate the clean trials it was given', () => {
    const before = canonicalDigest(CLEAN_RUNS.a.trials);
    for (const variant of ['trial_status_skip', 'counter_nudge', 'metric_altered', 'provenance_field']) {
      injectCorruption(CLEAN_RUNS.a.trials, variant);
    }
    assert.equal(canonicalDigest(CLEAN_RUNS.a.trials), before);
  });

  test('an UNNAMED corruption is a typed refusal, not a control that silently does nothing', () => {
    assert.throws(
      () => injectCorruption(CLEAN_RUNS.a.trials, 'tweak_something'),
      (error) => error instanceof MalformedResult && /CORRUPTION_VARIANT_UNKNOWN/.test(String(error.message)),
    );
    assert.throws(
      () => injectCorruption([], 'trial_status_skip'),
      (error) => error instanceof MalformedResult && /TRIALS_ABSENT/.test(String(error.message)),
    );
  });

  // --- the six controls the ticket names, one by one -----------------------

  test('CONTROL corrupted measurement: a wrong number is caught by the frozen table', () => {
    const bundle = buildVariant('corrupted_measurement', { label: 'a' });
    assert.equal(bundle.run.trials[0].numerator, 3);
    assert.equal(bundle.run.trials[0].outcome, CLEAN_TRIAL.outcome, 'the outcome was corrupted too, so one class moved twice');
    const result = compareVariant('corrupted_measurement', 'a');
    const finding = result.findingsA.find((entry) => entry.field === 'trials[0].numerator');
    assert.ok(finding, 'the finding did not name trials[0].numerator');
    assert.equal(finding.expected, 7);
    assert.equal(finding.observed, 3);
    assert.equal(finding.code, 'MEASUREMENT_DIVERGES_FROM_TABLE');
    // The run's OWN pooled interval no longer follows from its own counts.
    assert.ok(addedCodes(result).includes('self_reported_interval_divergence'));
    // Honest half: a wrong number is not a binding failure, so the trial verdict
    // does NOT move. A control that claimed it did would be asserting a
    // mechanism the comparator does not have.
    assert.equal(resolveTrialVerdict(bundle.run.trials[0]).verdict, 'ALLOW');
  });

  test('CONTROL corrupted expected table: a run scored against a moved table is named', () => {
    const bundle = buildVariant('corrupted_expected_table', { label: 'a' });
    assert.notEqual(bundle.extras.corrupted_digest, EXPECTED_TABLE_ARGUMENT.digest);
    // (a) The honest table is in force and the run declares the corrupted
    //     digest: the mismatch is named per run.
    const mismatch = compare({ runA: { ...CLEAN_RUNS.a, expected_table_digest: bundle.extras.corrupted_digest } });
    const named = mismatch.failures.filter((entry) => entry.code === 'expected_table_digest_mismatch');
    assert.equal(named.length, 1, 'the mismatched run was not named');
    assert.match(named[0].detail, /different frozen table digest/);
    // (b) The corrupted table is in force AND the run is re-bound to it, so the
    //     table has to disagree with the runs on its own content. Agreement
    //     between the runs is not the criterion (A3).
    const rebound = compareVariant('corrupted_expected_table', 'a');
    assert.ok(rebound.findingsA.length > 0, 'the corrupted table produced no finding against clean runs');
    assert.ok(addedCodes(rebound).includes('table_disagreement'));
    // (c) The freeze itself refuses the corrupted table, from the document.
    assert.throws(
      () => assertTableFrozen(bundle.preregistration),
      (error) => error instanceof BlockedPolicy && /EXPECTED_TABLE_DRIFT/.test(String(error.message)),
    );
    assert.equal(assertTableFrozen(PREREGISTRATION), expectedTableDigest(), 'the honest preregistration was refused');
  });

  test('CONTROL label substituted: a causal label is invisible to the table and visible to the guard', () => {
    const bundle = buildVariant('label_substituted', { label: 'a' });
    // The table does not read labels, so the table alone CANNOT catch this one.
    // A test that claimed otherwise would be testing a mechanism that does not
    // exist, and the guard would look unnecessary.
    const result = compareVariant('label_substituted', 'a');
    assert.deepEqual([...result.findingsA], [], 'the frozen table scored a claim label');
    // What does catch it is the preregistration binding: the run was produced
    // under a different preregistration digest.
    assert.ok(addedCodes(result).includes('preregistration_digest_mismatch'));
    // And the digests themselves moved, which is the P3 check's whole point.
    assert.notEqual(bundle.extras.card_digest.from, bundle.extras.card_digest.to);
    assert.notEqual(bundle.extras.observational_case.card_digest.from, bundle.extras.observational_case.card_digest.to);
  });

  test('CONTROL missing evaluator: the trial flips ALLOW -> VIOLATION and the run says why', () => {
    const bundle = buildVariant('missing_evaluator', { label: 'a' });
    assert.equal(bundle.run.trials[0].evaluatorBinding, null);
    assert.equal(bundle.run.trials[0].evaluator, null);
    assert.equal(resolveTrialVerdict(CLEAN_TRIAL).verdict, 'ALLOW', 'the before state moved');
    const verdict = resolveTrialVerdict(bundle.run.trials[0]);
    assert.equal(verdict.verdict, 'VIOLATION');
    assert.ok(verdict.reasons.includes('MISSING_EVALUATOR_BINDING'), verdict.reasons.join(', '));
    const result = compareVariant('missing_evaluator', 'a');
    assert.ok(addedCodes(result).includes('evaluator_not_independent'), addedCodes(result).join(','));
    // "Not measured" is not 0 %: the counts are still in the record and the
    // record says why they may not be read as a rate.
    assert.equal(bundle.run.trials[0].denominator, 8);
    assert.equal(EXPECTED_FLIPS.missing_evaluator.expected_flip.not_measured_is_not_zero, 'evaluator_not_independent');
  });

  test('CONTROL missing evaluator, second case: present but NOT independent is the same flip', () => {
    const bundle = buildVariant('missing_evaluator', { label: 'a' });
    const notIndependent = {
      ...CLEAN_TRIAL,
      calibration: CALIBRATIONS.notIndependent,
      calibration_id: CALIBRATIONS.notIndependent.calibration_id,
      evaluator: { ...CLEAN_TRIAL.evaluator, independent: false, blind_to_producer: false },
      evaluatorBinding: { ...CLEAN_TRIAL.evaluatorBinding, independent: false, blind_to_producer: false },
    };
    const verdict = resolveTrialVerdict(notIndependent);
    assert.equal(verdict.verdict, 'VIOLATION');
    assert.ok(
      verdict.reasons.some((reason) => reason.startsWith('EVALUATOR_NOT_INDEPENDENT')),
      verdict.reasons.join(', '),
    );
    assert.ok(
      verdict.reasons.includes(`CALIBRATION_NOT_MEASURED:${CALIBRATIONS.notIndependent.not_measured_reason}`),
      verdict.reasons.join(', '),
    );
    // The evaluator record is STILL THERE, so this is a different defect from
    // the deleted one — and it must be caught on the calibration, not presence.
    assert.ok(Object.keys(notIndependent.evaluator).length > 0 && bundle.run.trials[0].evaluator === null);
  });

  test('CONTROL truncated trial: a vanished trial is a finding, and the torn tail cannot be read back', () => {
    assert.equal(assertTruncatedTailUnparseable(), true);
    const bundle = buildVariant('truncated_trial', { label: 'a' });
    assert.equal(bundle.run.trials.length, CLEAN_RUNS.a.trials.length - 1);
    assert.equal(bundle.run.trials_complete, false);
    const result = compareVariant('truncated_trial', 'a');
    assert.ok(
      result.findingsA.some((entry) => entry.code === 'TRIAL_COUNT_DIVERGES_FROM_TABLE'),
      JSON.stringify(result.findingsA).slice(0, 200),
    );
    assert.ok(
      result.findingsA.some((entry) => entry.code === 'TRIAL_ROW_ABSENT' && entry.index === 3),
      'the missing row was not named by index',
    );
    assert.throws(() => JSON.parse(bundle.extras.torn_tail));
  });

  test('CONTROL best-seed-only report: naming a winner with no full disclosure is a violation', () => {
    const bestOnly = (label) => ({
      ...CLEAN_RUNS[label],
      best_seed: PREREGISTERED_SEEDS[0],
    });
    const undisclosed = compare({ runA: bestOnly('a'), runB: bestOnly('b') });
    const named = undisclosed.failures.filter((entry) => entry.code === 'best_seed_undisclosed');
    assert.equal(named.length, 2, 'only one of the two runs was named');
    assert.match(named[0].detail, /no seed_disclosures entry/);
    // A PARTIAL disclosure — the winner alone, which is what a cherry-picking
    // report contains — is still undisclosed.
    const partial = { ...bestSeedDisclosure('best_seed', [PREREGISTERED_SEEDS[0]]) };
    const partially = compare({
      runA: { ...bestOnly('a'), seed_disclosures: [partial] },
      runB: { ...bestOnly('b'), seed_disclosures: [partial] },
    });
    assert.ok(partially.failures.filter((entry) => entry.code === 'best_seed_undisclosed').length > 0);
    assert.ok(
      partially.failures.some((entry) => /does not cover the preregistered seed set/.test(String(entry.detail))),
      'a partial disclosure was not named as incomplete',
    );
    // The FULL disclosure clears it, which is what makes the first two findings
    // about the selection rather than about the report carrying one.
    const full = bestSeedDisclosure('best_seed', PREREGISTERED_SEEDS);
    const disclosed = compare({
      runA: { ...bestOnly('a'), seed_disclosures: [full] },
      runB: { ...bestOnly('b'), seed_disclosures: [full] },
    });
    assert.deepEqual(
      disclosed.failures.filter((entry) => entry.code === 'best_seed_undisclosed'),
      [],
    );
    assert.equal(full.disclosed, true);
    assert.equal(full.count, PREREGISTERED_SEEDS.length);
  });

  test('a disclosure with no seeds is a typed refusal, never an empty disclosure', () => {
    assert.throws(
      () => bestSeedDisclosure('best_seed', []),
      (error) => error instanceof MalformedResult && /SELECTION_SEEDS_ABSENT/.test(String(error.message)),
    );
    assert.throws(
      () => bestSeedDisclosure('', [1]),
      (error) => error instanceof MalformedResult && /SELECTION_NAME_ABSENT/.test(String(error.message)),
    );
  });

  test('a SUBSTITUTED seed set is named by the comparator, not only by the trial binding', () => {
    const substituted = (label) => ({
      ...CLEAN_RUNS[label],
      trials: CLEAN_RUNS[label].trials.map((trial) => ({
        ...trial,
        seeds: [PREREGISTERED_SEEDS[0]],
        seedBinding: { ...trial.seedBinding, seeds: [PREREGISTERED_SEEDS[0]], source: 'BEST_ONLY' },
      })),
    });
    const result = compare({ runA: substituted('a'), runB: substituted('b') });
    assert.ok(addedCodes(result).includes('seed_substitution'), addedCodes(result).join(','));
    assert.ok(addedCodes(result).includes('seed_set_incomplete'), addedCodes(result).join(','));
  });

  test('a control that does NOT flip the verdict cannot be counted as one', () => {
    // `controlsFlipVerdict` is the hard gate over the control record. Feeding it
    // a record whose "before" was already a VIOLATION makes every comparator
    // control report no flip, which is the honest answer: a control can only
    // demonstrate a flip from a real ALLOW.
    const before = runNegativeControls({
      trial: CLEAN_TRIAL, cleanRun: CLEAN_RUNS.a, runA: CLEAN_RUNS.a, runB: CLEAN_RUNS.b, card: HYPOTHESIS_CARD,
    });
    assert.equal(before.allFlipped, true);
    assert.deepEqual([...controlsFlipVerdict(before).failures], []);

    const notFlipped = runNegativeControls({
      trial: { ...CLEAN_TRIAL, status: 'SKIPPED' }, cleanRun: CLEAN_RUNS.a, runA: CLEAN_RUNS.a, runB: CLEAN_RUNS.b, card: HYPOTHESIS_CARD,
    });
    assert.equal(notFlipped.allFlipped, false);
    const gate = controlsFlipVerdict(notFlipped);
    assert.equal(gate.ok, false);
    assert.ok(gate.failures.some((entry) => entry.startsWith('holdout_peek did not flip')), gate.failures.join('; '));
  });

  test('a control that did not run is named, not skipped', () => {
    const record = runNegativeControls({ trial: CLEAN_TRIAL, cleanRun: CLEAN_RUNS.a, runA: CLEAN_RUNS.a, runB: CLEAN_RUNS.b });
    assert.equal(record.allFlipped, false);
    assert.equal(record.notRun.length, 1);
    assert.equal(record.notRun[0].id, 'label_substitution');
    assert.equal(record.notRun[0].reason, 'CONTEXT_CARD_ABSENT');
    assert.equal(controlsFlipVerdict(record).ok, false);
  });

  test('the six frozen control ids are exactly the six the ticket names, and all of them flip', () => {
    assert.deepEqual(
      [...NEGATIVE_CONTROLS].map((descriptor) => descriptor.id).sort(),
      ['budget_opacity', 'corrupted_data', 'holdout_peek', 'label_substitution', 'missing_evaluator', 'seed_substitution'],
    );
    // WHY THE COUNT MOVED FROM 6 TO 7 (S2). The frozen six are unchanged and
    // closed; the seventh is `ledger_spelling_holdout_peek`, a second mutation
    // of the holdout binding spelled the way `registry.mjs#recordHoldoutRead`
    // plans its ACCESS payload (`decision_point`). The comparator read only
    // `decision_at` / `decisionAt`, so the row a REAL run produces was read as
    // carrying no decision point at all and an early peek on that shape was an
    // ALLOW — and no control exercised the shape at all. The control id set of
    // the ticket is not extended; an extra NAMED control is reported beside the
    // six and gated by `controlsFlipVerdict` through `EXTRA_CONTROL_IDS`.
    assert.deepEqual([...EXTRA_CONTROL_IDS], ['ledger_spelling_holdout_peek']);
    const record = runNegativeControls({
      trial: CLEAN_TRIAL, cleanRun: CLEAN_RUNS.a, runA: CLEAN_RUNS.a, runB: CLEAN_RUNS.b, card: HYPOTHESIS_CARD,
    });
    assert.equal(record.controls.length, NEGATIVE_CONTROLS.length + EXTRA_CONTROL_IDS.length);
    for (const descriptor of [...NEGATIVE_CONTROLS, ...EXTRA_CONTROL_IDS.map((id) => ({ id }))]) {
      const entry = record.controls.find((control) => control.id === descriptor.id);
      assert.ok(entry, `${descriptor.id} produced no record`);
      assert.equal(entry.flipped, true, `${descriptor.id}: ${entry.before} -> ${entry.after}`);
    }
  });

  test('an unknown control id is a typed refusal, never a passing control', () => {
    assert.throws(
      () => controlsFlipVerdict({ controls: [{ id: 'seventh_control', flipped: true }] }),
      (error) => error instanceof MalformedResult && /CONTROL_ID_UNKNOWN/.test(String(error.message)),
    );
    assert.throws(
      () => runNegativeControls({}),
      (error) => error instanceof MalformedResult && /CONTEXT_TRIAL_ABSENT/.test(String(error.message)),
    );
  });
});

/** Compare the corrupted pair for one variant, with the table and the
 * preregistration that variant really ran under. */
function compareVariant(variant, label) {
  const bundle = buildVariant(variant, { label });
  const other = buildVariant(variant, { label: label === 'a' ? 'b' : 'a' });
  const expected = variant === 'corrupted_expected_table'
    ? { ...EXPECTED_TABLE_ARGUMENT, EXPECTED_TRIAL_DECISIONS: bundle.table.trials, digest: bundle.extras.corrupted_digest }
    : EXPECTED_TABLE_ARGUMENT;
  return compare({
    runA: bundle.run,
    runB: other.run,
    prereg: bundle.preregistration ?? PREREGISTRATION,
    expected,
  });
}

// ===========================================================================
// A4 — the label-substitution control FAILS: a causal claim over an
//      observational result is refused with a TYPED error.
// ===========================================================================

describe('A4 an observational result cannot be read as causal', () => {
  /** The swap the control performs. Only the CLAIM moves: the card keeps its
   * id, its type, its observational ground truth and its schema validity. */
  const swapLabel = (card) => ({
    ...card,
    proposed_relation: { ...card.proposed_relation, causal_assertion: true },
  });

  test('the clean card is observational, claims nothing causal, and is admissible', () => {
    const classification = classifyCardRelation(HYPOTHESIS_CARD);
    assert.equal(classification.observational, true);
    assert.equal(classification.causalAssertion, false);
    assert.equal(classification.admissible, true);
    assert.equal(classification.refusalCode, null);
  });

  test('the frozen SCHEMA accepts the swapped card, so the schema cannot be the guard', () => {
    const swapped = swapLabel(HYPOTHESIS_CARD);
    assert.equal(isResearchContractValid('hypothesis-card', HYPOTHESIS_CARD), true);
    assert.equal(isResearchContractValid('hypothesis-card', swapped), true, 'the card schema would have caught the substitution');
    assert.equal(swapped.card_id, HYPOTHESIS_CARD.card_id, 'the id moved, so the digest check would be a weaker test than it should be');
  });

  test('CONTROL the swapped card is refused by a TYPED error, and the honest one is admitted', () => {
    const swapped = swapLabel(HYPOTHESIS_CARD);
    assert.doesNotThrow(() => assertCausalDiscipline(HYPOTHESIS_CARD));
    assert.throws(
      () => assertCausalDiscipline(swapped),
      (error) => error instanceof BlockedPolicy
        && error.code === 'BLOCKED_POLICY'
        && /CAUSAL_ASSERTION_UNSUPPORTED/.test(String(error.message)),
    );
    // The always-on simulation guard refuses the same card: a simulation is
    // never evidence of causation, whatever else is wrong.
    assert.throws(
      () => assertNoCausalFromSimulation(swapped),
      (error) => error instanceof BlockedPolicy && /CAUSAL_ASSERTION_UNSUPPORTED/.test(String(error.message)),
    );
  });

  test('the classifier reports the swap as inadmissible with a refusal code, and says which member', () => {
    const classification = classifyCardRelation(swapLabel(HYPOTHESIS_CARD));
    assert.equal(classification.admissible, false);
    assert.equal(classification.causalAssertion, true);
    assert.equal(classification.observational, true, 'the ground truth did not change; the CLAIM did');
    assert.match(String(classification.refusalCode), /^CAUSAL_ASSERTION_UNSUPPORTED:/);
  });

  test('CONTROL the executor guard refuses a causal claim over a producible non-causal label', () => {
    const claim = {
      provenance_label: 'OBSERVATIONAL_TEST',
      card_type: 'OBSERVATION',
      proposed_relation: { relation_strength: 'CORRELATION_EVIDENCE', causal_assertion: true },
    };
    assert.equal(claimAssertsCausality(claim), true);
    assert.throws(
      () => assertNoCausalClaim(claim),
      // The typed error's `code` is the board's CLASS code; the domain code is
      // the message and the offending field PATH is the `detail`. Both are
      // asserted, so a future change that kept the class but dropped the domain
      // answer would fail here.
      (error) => error instanceof BlockedPolicy
        && error.code === 'BLOCKED_POLICY'
        && /CAUSAL_CLAIM_FROM_NON_CAUSAL_EVIDENCE/.test(String(error.message))
        && /proposed_relation\.causal_assertion/.test(String(error.detail)),
    );
    // The same claim with the assertion removed is permitted: the guard is a
    // guard against the CAIM, not against observational evidence.
    const honest = { ...claim, proposed_relation: { ...claim.proposed_relation, causal_assertion: null } };
    assert.equal(claimAssertsCausality(honest), false);
    assert.equal(assertNoCausalClaim(honest).permitted, true);
  });

  test('CONTROL a claim with no provenance is refused before it is judged', () => {
    assert.throws(
      () => assertNoCausalClaim({ proposed_relation: { causal_assertion: false } }),
      (error) => error instanceof MalformedResult && /PROVENANCE_LABEL_MISSING/.test(String(error.message)),
    );
    assert.throws(
      () => assertNoCausalClaim({ provenance_label: 'MOSTLY_CAUSAL' }),
      (error) => error instanceof MalformedResult && /PROVENANCE_LABEL_UNKNOWN/.test(String(error.message)),
    );
  });

  test('CAUSAL_EXPERIMENT is a label this transport cannot produce, and a claim on it is refused', () => {
    assert.ok(EXECUTOR_PROVENANCE_LABELS.includes('CAUSAL_EXPERIMENT'));
    assert.equal(EXECUTOR_PRODUCIBLE_LABELS.includes('CAUSAL_EXPERIMENT'), false);
    assert.deepEqual([...EXECUTOR_PRODUCIBLE_LABELS], ['OBSERVATIONAL_TEST', 'BACKTEST']);
    assert.throws(
      () => assertNoCausalClaim({ provenance_label: 'CAUSAL_EXPERIMENT' }),
      (error) => error instanceof BlockedPolicy && /CAUSAL_LABEL_NOT_PRODUCIBLE_BY_THIS_TRANSPORT/.test(String(error.message)),
    );
  });

  test('a claim that UPGRADES the inference mode is a causal claim and is refused', () => {
    assert.equal(EXECUTOR_INFERENCE_MODE, 'ASSOCIATIONAL');
    assert.throws(
      () => assertNoCausalClaim({ provenance_label: 'BACKTEST', inference_mode: 'CAUSAL' }),
      (error) => error instanceof BlockedPolicy && /inference_mode/.test(String(error.detail)),
    );
  });

  test('every producible label is a member of the closed set, and every kind derives one', () => {
    for (const label of EXECUTOR_PRODUCIBLE_LABELS) {
      assert.ok(EXECUTOR_PROVENANCE_LABELS.includes(label), label);
    }
    for (const kind of EXECUTOR_TRIAL_KINDS) {
      assert.ok(EXECUTOR_PRODUCIBLE_LABELS.includes(kind === 'OBSERVATIONAL_EVALUATION' ? 'OBSERVATIONAL_TEST' : 'BACKTEST'));
    }
    // There is no CAUSAL trial kind: a causal experiment needs an intervention
    // and a randomised assignment, and this transport has neither.
    assert.equal(EXECUTOR_TRIAL_KINDS.some((kind) => /CAUSAL/.test(kind)), false);
  });

  test('CONTROL the guard fires BEFORE the measurer: a causal claim never reaches a measurement', async () => {
    let measured = 0;
    const measurer = () => { measured += 1; return 1; };
    const request = trialRequest();
    await assert.rejects(
      () => runTrial({
        request,
        record: caseRecord(),
        clock: fixedDateClock(),
        evaluator: INDEPENDENT_EVALUATOR,
        calibration: CALIBRATIONS.independent,
        measure: measurer,
        claim: { proposed_relation: { relation_strength: 'CORRELATION_EVIDENCE', causal_assertion: true } },
      }),
      (error) => error instanceof BlockedPolicy && /CAUSAL_CLAIM_FROM_NON_CAUSAL_EVIDENCE/.test(String(error.message)),
    );
    assert.equal(measured, 0, 'the measurer ran despite a refused causal claim');
  });

  test('CONTROL the six-control record flips label_substitution ADMITTED -> REFUSED', () => {
    const record = runNegativeControls({
      trial: CLEAN_TRIAL, cleanRun: CLEAN_RUNS.a, runA: CLEAN_RUNS.a, runB: CLEAN_RUNS.b, card: HYPOTHESIS_CARD,
    });
    const control = record.controls.find((entry) => entry.id === 'label_substitution');
    assert.equal(control.before, 'ADMITTED');
    assert.equal(control.after, 'REFUSED');
    assert.equal(control.flipped, true);
    assert.equal(control.mutated_field, 'proposed_relation.causal_assertion');
    assert.match(String(control.after_refusal), /^CAUSAL_ASSERTION_UNSUPPORTED:/);
  });
});

// ===========================================================================
// The CI and the sequential / multiple-comparison correction come from the
// preregistration rule; wall-clock latency never changes the verdict.
// ===========================================================================

describe('the frozen noise / CI / multiplicity rule drives the decision', () => {
  const MULTIPLICITY = PREREGISTRATION.multiplicity_rule;
  const family = () => MULTIPLICITY.declared_comparisons ?? MULTIPLICITY.comparisons;

  const rule = (over = {}) => ({
    alpha: MULTIPLICITY.alpha,
    method: MULTIPLICITY.method,
    comparisons: family(),
    confidence: MULTIPLICITY.confidence,
    null_value: PREREGISTRATION.frozen_baseline.value,
    subject: PREREGISTRATION.metric.name,
    ...over,
  });

  test('the correction block carries the preregistered alpha, method and declared family', () => {
    const applied = decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule() });
    assert.equal(applied.correction.alpha, MULTIPLICITY.alpha);
    assert.equal(applied.correction.method, MULTIPLICITY.method);
    // The published confidence is what the interval (and therefore the p bound
    // the correction steps down on) was computed at. The correction block does
    // not repeat it; the interval does, and `correction.pUpper` is derived from
    // it — asserted below as `1 - confidence`.
    assert.equal(applied.interval.confidence, MULTIPLICITY.confidence);
    assert.equal(applied.correction.pUpper, Math.round((1 - MULTIPLICITY.confidence) * 1e6) / 1e6);
    assert.equal(applied.correction.declared, family().length, 'the declared family was collapsed');
    // The subject is not a member of the family, so it JOINS it: `comparisons`
    // is `declared + 1`. A correction computed over m = 1 would be an
    // uncorrected test wearing a correction's name.
    assert.equal(applied.correction.comparisons, family().length + 1);
    assert.ok(applied.correction.inherited_p_bound > 0, 'a family member with no interval of its own was dropped instead of inheriting');
  });

  test('the step-down is SEQUENTIAL: the first threshold is alpha / m, computed from the rule', () => {
    const applied = decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule() });
    assert.equal(applied.correction.blocking_rank, 0);
    assert.equal(applied.correction.blocking_threshold, MULTIPLICITY.alpha / (family().length + 1));
    assert.equal(applied.correction.rejection_floor, MULTIPLICITY.alpha / (family().length + 1));
  });

  test('a rule that CAN reject says POSITIVE, and the same effect the other way says NEGATIVE', () => {
    // R-A, THE WHOLE OF IT, IN ONE ASSERTION BLOCK. The rule this test reads
    // from the FROZEN preregistration is now the derived one:
    // `confidence = 1 - alpha / family_size` over the three declared
    // comparisons, so its bound `1 - c` lands ON `alpha / m` and the rule can
    // reject. `ruleFeasibility` is the track's own arithmetic, not a
    // hand-written `1 - c <= alpha / m`: the derived value `1 - (1 - 0.05/3)`
    // is 5.2e-17 ABOVE `0.05/3` in IEEE-754 (relative 3.1e-15), so a test that
    // compared the two itself would fail on the rounding artefact of the very
    // value that makes the rule self-consistent.
    //
    // `rule()` below sets a `subject` that is NOT one of the declared
    // comparisons, so the subject JOINS the family and the effective family is
    // m = 4 — a legitimate, correctly-reported second family in which the very
    // same published confidence cannot reject. Both halves are asserted below,
    // because "the published rule can never reject" was TRUE of the first
    // delivery and is false now, and a reader of this file must not be left
    // believing the old sentence.
    const declared = ruleFeasibility({
      alpha: MULTIPLICITY.alpha, confidence: MULTIPLICITY.confidence, familySize: family().length,
    });
    assert.equal(declared.never_rejects, false, 'the frozen rule must be able to reject at its declared family of ' + String(family().length));
    assert.equal(declared.can_only_answer, 'ANY_OUTCOME');
    // The published confidence is DERIVED, not chosen: it must be exactly
    // `1 - alpha / family_size`, so a return to a round 0.95 fails here.
    assert.equal(MULTIPLICITY.confidence, 1 - MULTIPLICITY.alpha / family().length);

    // At m = 4 — the subject joined the family — the same published level
    // correctly cannot reject, and the comparison reports that rather than
    // silently deciding.
    const widened = decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule() });
    assert.equal(widened.correction.comparisons, family().length + 1, 'the subject did not join the family, so this test is not testing what its comment claims');
    assert.equal(widened.correction.never_rejects, true, 'a family of m+1 exceeds the bound the published confidence inherits');
    assert.equal(widened.decision, 'UNRESOLVED');
    assert.equal(widened.reason, 'not_significant_after_multiplicity_correction');

    // At the declared family of 3 the very same effect is POSITIVE, which is
    // the property R-A bought: the rule can now reject.
    const pooled = decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule({ subject_is_pooled_aggregate: true }) });
    assert.equal(pooled.correction.comparisons, family().length, 'the pooled aggregate widened the family it belongs to');
    assert.equal(pooled.correction.never_rejects, false);
    assert.equal(pooled.decision, 'POSITIVE');
    assert.equal(pooled.reason, 'clears_noise_and_clears_corrected_null');
    assert.equal(pooled.correction.rejected, true);

    const powered = decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule({ confidence: 0.99 }) });
    assert.equal(powered.correction.never_rejects, false);
    assert.equal(powered.decision, 'POSITIVE');
    assert.equal(powered.reason, 'clears_noise_and_clears_corrected_null');
    assert.equal(powered.correction.rejected, true);

    const reversed = decisionFromInterval({ observed: 0.6, lower: 0.5, upper: 0.7, noiseBand: 0.02, rule: rule({ confidence: 0.99 }) });
    assert.equal(reversed.decision, 'NEGATIVE', 'a significant effect in the other direction is not a pass');
    assert.equal(reversed.reason, 'significant_effect_in_the_other_direction');
  });

  test('a bigger family is a STRICTER correction, from the same measurement', () => {
    const three = decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule({ confidence: 0.99 }) });
    const ten = decisionFromInterval({
      observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02,
      rule: rule({ confidence: 0.99, comparisons: ['c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'c10'] }),
    });
    assert.equal(three.decision, 'POSITIVE');
    assert.equal(ten.decision, 'UNRESOLVED');
    assert.equal(ten.correction.declared, 10);
    assert.ok(ten.correction.rejection_floor < three.correction.rejection_floor);
  });

  test('bonferroni thresholds once at alpha / m where holm steps down', () => {
    const common = { confidence: 0.99, comparisons: family() };
    const bonferroni = decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule({ ...common, method: 'bonferroni' }) });
    const holm = decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule(common) });
    assert.equal(bonferroni.correction.method, 'bonferroni');
    assert.equal(holm.correction.method, 'holm_bonferroni');
    assert.equal(bonferroni.correction.comparisons, holm.correction.comparisons, 'the method changed the family');
    assert.ok(holm.correction.threshold >= bonferroni.correction.threshold, 'the step-down is not at least as permissive as the single step');
  });

  test('an UNDECLARED family is a typed refusal, never a silent uncorrected test', () => {
    assert.throws(
      () => decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule({ comparisons: [] }) }),
      (error) => error instanceof MalformedResult && /MULTIPLICITY_FAMILY_ABSENT/.test(String(error.message)),
    );
    assert.throws(
      () => decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02 }),
      (error) => error instanceof MalformedResult && /DECISION_RULE_ABSENT/.test(String(error.message)),
    );
    assert.throws(
      () => decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule({ method: 'scheffe' }) }),
      (error) => error instanceof MalformedResult && /MULTIPLICITY_METHOD_UNKNOWN/.test(String(error.message)),
    );
  });

  test('an interval that is not measured is a typed refusal, not a zero', () => {
    for (const bad of [{ observed: null }, { lower: Number.NaN }, { upper: undefined }, { noiseBand: -1 }]) {
      assert.throws(
        () => decisionFromInterval({ observed: 0.9, lower: 0.8, upper: 0.95, noiseBand: 0.02, rule: rule(), ...bad }),
        (error) => error instanceof MalformedResult,
        JSON.stringify(bad),
      );
    }
  });

  test('the campaign CI comes from the preregistration: move the published confidence and the interval moves', () => {
    const committed = compare();
    const lowered = compare({
      prereg: { ...PREREGISTRATION, multiplicity_rule: { ...MULTIPLICITY, confidence: 0.9 } },
    });
    assert.equal(committed.runs.a.interval.confidence, MULTIPLICITY.confidence);
    assert.equal(lowered.runs.a.interval.confidence, 0.9);
    // A different CI gives a different interval from the SAME counts, so the
    // published confidence is load-bearing rather than decorative.
    assert.notEqual(committed.runs.a.interval.lower, lowered.runs.a.interval.lower);
    assert.equal(committed.runs.a.interval.method, lowered.runs.a.interval.method);
  });

  test('an undeclared family at CAMPAIGN level is a named failure, not a silent uncorrected test', () => {
    const stripped = compare({
      prereg: { ...PREREGISTRATION, multiplicity_rule: { ...MULTIPLICITY, declared_comparisons: [] } },
    });
    assert.ok(addedCodes(stripped).includes('multiplicity_family_absent'), addedCodes(stripped).join(','));
  });

  test('the campaign noise band is read from the FROZEN TABLE, and the preregistration drift goes unnoticed', () => {
    // MEASURED, recorded rather than asserted as a wish. The preregistration
    // spells the band `noise_rule.band`
    // (evidence/s2-008/corpus/preregistration.json) and `scoreMetric` reads
    // `noise_rule.noise_band` (src/lib/research/comparator.mjs:1444), so
    // `preregNoise` is null and the band comes from EXPECTED_METRIC.noiseBand.
    // The two AGREE at 0.02, so no verdict changes today — but a preregistration
    // whose band is edited after the fact is not caught on that member. Reported
    // to the source owner rather than patched here; this test pins what is
    // actually true so the gap cannot be mistaken for a covered one.
    assert.equal(PREREGISTRATION.noise_rule.band, 0.02);
    assert.equal(PREREGISTRATION.noise_rule.noise_band, undefined, 'the spelling gap this test documents has been closed');
    const drifted = compare({ prereg: { ...PREREGISTRATION, noise_rule: { ...PREREGISTRATION.noise_rule, band: 0.5 } } });
    assert.deepEqual(codesOf(drifted), [...CLEAN_FAILURE_CODES].sort(), 'a drifted preregistration band was caught (or the verdict moved)');
  });
});

describe('wall-clock latency is measured and decides nothing', () => {
  test('`latencyRecorded` reports `decides: false` and takes its parameters from the preregistration', () => {
    const recorded = latencyRecorded(CLEAN_RUNS.a.trials, PREREGISTRATION.noise_rule);
    assert.equal(recorded.decides, false);
    assert.equal(recorded.samples.length, 4);
    assert.equal(recorded.parameters.seed, PREREGISTRATION.noise_rule.bootstrap_seed);
    assert.equal(recorded.parameters.resamples, PREREGISTRATION.noise_rule.bootstrap_samples);
    assert.equal(recorded.parameters.p, PREREGISTRATION.noise_rule.percentile);
    assert.equal(recorded.parameters.preregistered, true);
    assert.ok(recorded.interval !== null);
  });

  test('a run with NO latency samples is measured as absent, not as a fast run', () => {
    const without = CLEAN_RUNS.a.trials.map(({ latency_ms, ...rest }) => rest);
    const recorded = latencyRecorded(without, PREREGISTRATION.noise_rule);
    assert.deepEqual([...recorded.samples], []);
    assert.equal(recorded.interval, null);
    assert.equal(recorded.decides, false);
  });

  test('a broken latency sample is a typed refusal, not a fast sample', () => {
    for (const bad of [Number.NaN, -1, 'fast']) {
      const trials = [{ ...CLEAN_TRIAL, latency_ms: bad }];
      assert.throws(
        () => latencyRecorded(trials, PREREGISTRATION.noise_rule),
        (error) => error instanceof MalformedResult && /LATENCY_SAMPLE_INVALID/.test(String(error.message)),
        String(bad),
      );
    }
  });

  test('scaling every latency sample by 10^4 leaves the decision byte-identical', () => {
    const scaled = (run) => ({
      ...run,
      trials: run.trials.map((trial) => ({ ...trial, latency_ms: trial.latency_ms * 10_000 })),
    });
    const slow = compare({ runA: scaled(CLEAN_RUNS.a), runB: scaled(CLEAN_RUNS.b) });
    const committed = compare();
    assert.deepEqual(codesOf(slow), codesOf(committed));
    assert.deepEqual([...slow.findingsA], [...committed.findingsA]);
    assert.equal(slow.digestsEqual, committed.digestsEqual);
    assert.equal(resolveCampaignVerdict(slow), resolveCampaignVerdict(committed));
    assert.deepEqual(slow.runs.a.decision, committed.runs.a.decision);
    assert.deepEqual(slow.runs.a.correction, committed.runs.a.correction);
    assert.equal(slow.runs.a.decides_on_latency, false);
    assert.equal(committed.runs.a.decides_on_latency, false);
    // The interval over the samples DID move — the measurement is real — and the
    // decision did not. That is the whole claim.
    assert.notDeepEqual(
      [slow.runs.a.latency.interval.lower, slow.runs.a.latency.interval.upper],
      [committed.runs.a.latency.interval.lower, committed.runs.a.latency.interval.upper],
    );
  });

  test('latency is recorded as a LIMIT with proof id latency_recorded, never as a failure', () => {
    const result = compare();
    const limits = result.limits.filter((entry) => entry.code === 'latency_observed');
    assert.equal(limits.length, 2, 'both runs should contribute one latency limit');
    for (const entry of limits) {
      assert.match(String(entry.detail), /decides nothing/);
      assert.ok(['latency_recorded', null].includes(entry.proof), String(entry.proof));
    }
    assert.equal(result.failures.some((entry) => entry.code === 'latency_not_recorded'), false);
    assert.equal(result.limits.some((entry) => entry.code === 'latency_observed'), true);
  });

  test('a broken latency measurement is a NAMED failure, not a throw that discards the run findings', () => {
    const broken = (run) => ({
      ...run,
      trials: run.trials.map((trial, index) => (index === 0 ? { ...trial, latency_ms: 'fast' } : trial)),
    });
    let result = null;
    try {
      result = compare({ runA: broken(CLEAN_RUNS.a), runB: broken(CLEAN_RUNS.b) });
    } catch (error) {
      assert.fail(`compareParallelTrack threw instead of naming the failure: ${String(error?.message ?? error)}`);
    }
    assert.equal(result.failures.filter((entry) => entry.code === 'latency_not_recorded').length, 2);
    // The rest of the comparison still happened: the table was still scored.
    assert.equal(result.findingsA.length, 0, 'a broken latency sample discarded the run findings');
    assert.equal(resolveCampaignVerdict(result), 'FAIL');
  });
});

// ===========================================================================
// A1 — the six negative probes. Each runs, each control flips, and a control
//      that does NOT flip is reported as broken rather than passed.
// ===========================================================================

describe('A1 the six negative probes and their controls', () => {
  let scratch;

  before(() => {
    scratch = mkdtempSync(path.join(os.tmpdir(), 's2-008-comparator-probes-'));
  });

  after(() => {
    if (scratch !== undefined) rmSync(scratch, { recursive: true, force: true });
  });

  /** The registry refuses any clock but an injected one, so the clock is built
   * from the fixture's fixed instant and never from the process clock. */
  // `openRegistry` requires `nowNs` and `iso` to be FUNCTIONS (registry.mjs:308)
  // and refuses any other shape with REGISTRY_CLOCK_NOT_INJECTED, so the fixed
  // reading is wrapped rather than spread: a spread would carry numbers where
  // the registry reads methods.
  const probeClock = () => ({ nowNs: () => FIXED_CLOCK.nowNs, iso: () => FIXED_CLOCK.iso, source: FIXED_CLOCK.source });
  const dateClock = () => ({ now: () => new Date(FIXED_INSTANT_ISO), source: FIXED_CLOCK.source });

  /** A deterministic id factory scoped by the caller's slug, so two probes in
   * one base cannot collide and a repeat run produces the same ids. */
  const ids = (slug) => {
    const counters = new Map();
    return {
      next: (kind) => {
        const key = String(kind);
        const value = (counters.get(key) ?? 0) + 1;
        counters.set(key, value);
        return `${slug}-${key}-${String(value).padStart(4, '0')}`;
      },
    };
  };

  const allProbeNames = () => PROBE_FAMILIES.flatMap((family) => PROBE_NAMES[family]);

  test('the registry names exactly the six probe families the ticket names', () => {
    assert.deepEqual(
      [...PROBE_FAMILIES],
      ['holdout_peek', 'seed_substitution', 'hypothesis_rewrite', 'budget_opacity', 'causal_upgrade', 'missing_evaluator'],
    );
    assert.equal(PROBE_FAMILIES.length, 6);
    assert.equal(allProbeNames().length, 6, 'a seventh probe would be an invitation to quietly skip one');
    for (const family of PROBE_FAMILIES) {
      assert.equal(PROBE_NAMES[family].length, 1, `${family} carries ${PROBE_NAMES[family].length} probes`);
    }
    assert.deepEqual([...HARD_GATE_COUNTERS], [
      'holdoutPeek', 'seedSubstitution', 'hypothesisRewrite', 'budgetOpacity', 'causalUpgrade', 'missingEvaluator',
    ]);
  });

  test('every probe runs, passes, counts 0, and its control flipped', async () => {
    for (const family of PROBE_FAMILIES) {
      for (const probe of PROBE_NAMES[family]) {
        const result = await runProbe(probe, {
          clock: probeClock(), ids: ids(family), registryRoot: scratch, corpusDir: CORPUS_DIR,
        });
        assert.equal(result.status, 'pass', `${probe}: ${String(result.detail).slice(0, 240)}`);
        assert.equal(result.passed, true, probe);
        assert.equal(result.counted, 0, `${probe} moved its counter on a refused attack`);
        assert.equal(result.evidence.control.flipped, true, `${probe}: ${result.evidence.control.before} -> ${result.evidence.control.after}`);
        assert.equal(result.evidence.control.mutation_source, 'built_in', `${probe} used an injected control instead of its own`);
        assert.ok(
          result.evidence.checks.some((check) => check.ok && check.label.startsWith('control_flips: ')),
          `${probe} recorded no control-flip fact`,
        );
      }
    }
  });

  test('runAllProbes runs all six, every counter is 0, and nothing is broken or not run', async () => {
    const report = await runAllProbes({ clock: probeClock(), ids: ids('all'), registryRoot: scratch, corpusDir: CORPUS_DIR });
    assert.equal(report.results.length, 6);
    assert.equal(report.allPassed, true, `broken=${JSON.stringify(report.broken)} notRun=${JSON.stringify(report.notRun)}`);
    assert.deepEqual(report.broken, []);
    assert.deepEqual(report.notRun, []);
    assert.deepEqual(report.counters, Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0])));
    assert.equal(report.version, 's2-008-probes-v1');
  });

  test('a control that does NOT flip is reported as broken: not passed, not counted, named', async () => {
    // The injected mutation is a NO-OP, so the trial is unchanged and the
    // control cannot flip. This is the shape of "the defence is unproven": a
    // probe that reported pass here would be reporting a defence nobody
    // demonstrated, and one that moved the counter would report a bypass that
    // never happened.
    const result = await runProbe('holdout_read_before_decision_point', {
      clock: probeClock(),
      ids: ids('broken'),
      registryRoot: scratch,
      corpusDir: CORPUS_DIR,
      controlMutations: { holdout_peek: (trial) => trial },
    });
    assert.equal(result.status, 'broken');
    assert.equal(result.passed, false);
    assert.equal(result.counted, 0, 'a broken control moved a hard-gate counter');
    assert.equal(result.evidence.control.flipped, false);
    assert.equal(result.evidence.control.before, 'ALLOW');
    assert.equal(result.evidence.control.after, 'ALLOW');
    assert.equal(result.evidence.control.mutation_source, 'ctx');
    const failing = result.evidence.checks.filter((check) => !check.ok);
    assert.ok(failing.length > 0);
    assert.ok(failing.every((check) => check.label.startsWith('control_flips: ')), 'a plain fact failed too; the probe is broken for another reason');
  });

  test('runAllProbes names a broken probe and is not green while every counter stays 0', async () => {
    const report = await runAllProbes({
      clock: probeClock(),
      ids: ids('broken-all'),
      registryRoot: scratch,
      corpusDir: CORPUS_DIR,
      controlMutations: { budget_opacity: (trial) => trial },
    });
    assert.equal(report.allPassed, false, 'a broken probe was reported as a passing campaign');
    assert.equal(report.broken.length, 1);
    assert.equal(report.broken[0].probe, 'spend_beyond_the_reservation');
    assert.equal(report.broken[0].control, 'budget_opacity');
    assert.equal(report.broken[0].after, 'ALLOW');
    assert.equal(report.results.find((entry) => entry.probe === 'spend_beyond_the_reservation').status, 'broken');
    // The counters are the only thing `counters` reports, so a reader who reads
    // only `counters` must not be able to call this green — hence allPassed.
    assert.deepEqual(report.counters, Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0])));
    assert.equal(report.notRun.length, 0);
  });

  test('a repeat run on the SAME base purges the previous fixtures and reaches the same result', async () => {
    // The purge discipline: without it a second run fails on its own leftovers
    // instead of on the property. Asserted by RUNNING twice, not by reading the
    // purge's return value.
    const context = { clock: probeClock(), ids: ids('repeat'), registryRoot: scratch, corpusDir: CORPUS_DIR };
    const first = await runAllProbes(context);
    assert.equal(first.allPassed, true, JSON.stringify(first.broken));
    const second = await runAllProbes(context);
    assert.equal(second.allPassed, true, JSON.stringify(second.broken));
    assert.deepEqual(second.counters, first.counters);
    assert.deepEqual(
      second.results.map((entry) => [entry.probe, entry.status, entry.counted]),
      first.results.map((entry) => [entry.probe, entry.status, entry.counted]),
    );
    assert.equal(second.purged.base, first.purged.base);
  });

  test('a probe whose dependency is missing is NOT_RUN, which is never a pass', async () => {
    // No `corpusDir`, so the preregistration cannot be loaded. A probe that
    // needs it records not_run rather than passing on an absent dependency.
    const result = await runProbe('best_seed_reported_instead_of_the_preregistered_set', {
      clock: probeClock(), ids: ids('no-corpus'), registryRoot: scratch,
    });
    assert.equal(result.status, 'not_run');
    assert.equal(result.passed, false);
    assert.equal(result.counted, 0);
    assert.equal(result.omit.code, 'DEPENDENCY_UNAVAILABLE');
    assert.match(String(result.omit.reason), /preregistration/);
    assert.equal(result.evidence.world.deferred.preregistration, 'no corpusDir was supplied');
  });

  test('an unknown probe and an unsafe scratch root are typed refusals', () => {
    // `runProbe` resolves the frozen descriptor BEFORE it builds the async body,
    // so an unknown name is a synchronous throw, not a rejected promise. A
    // rejected promise would have hidden that difference.
    assert.throws(
      () => runProbe('no_such_probe', { clock: probeClock(), ids: ids('x'), registryRoot: scratch, corpusDir: CORPUS_DIR }),
      (error) => error instanceof BlockedPolicy && /UNKNOWN_PROBE/.test(String(error.message)),
    );
  });

  test('an unsafe scratch root is re-raised as a caller misconfiguration, not recorded as a probe fact', async () => {
    // `evidence` is a forbidden segment, so the structural check refuses the
    // base and `runProbe` RE-RAISES it: a harness misconfiguration is a
    // misconfiguration, and a probe that silently recorded `not_run` for it
    // would have hidden a root that points into the checkout.
    await assert.rejects(
      () => runProbe('holdout_read_before_decision_point', {
        clock: probeClock(), ids: ids('x'), registryRoot: 'evidence', corpusDir: CORPUS_DIR,
      }),
      (error) => error instanceof BlockedPolicy
        && /PROBE_SCRATCH_ROOT_UNSAFE/.test(String(error.message))
        && error.name === 'ScratchRootUnsafe',
    );
  });

  test('the recorder itself: a failed control fact is broken, a failed plain fact counts', () => {
    const broken = new ProbeRecorder('holdout_peek', 'p1', 'holdoutPeek');
    broken.check('a plain fact that holds', true);
    broken.check('control_flips: holdout_peek flips ALLOW -> VIOLATION', false, 'expected ALLOW -> VIOLATION');
    const brokenResult = broken.result();
    assert.equal(brokenResult.status, 'broken');
    assert.equal(brokenResult.passed, false);
    assert.equal(brokenResult.counted, 0);

    const failed = new ProbeRecorder('holdout_peek', 'p1', 'holdoutPeek');
    failed.check('a plain fact that fails', false);
    const failedResult = failed.result();
    assert.equal(failedResult.status, 'failed');
    assert.equal(failedResult.counted, 1, 'a failed fact did not move the counter');

    const notRun = new ProbeRecorder('holdout_peek', 'p1', 'holdoutPeek');
    notRun.check('a plain fact that holds', true);
    const notRunResult = notRun.notRun('the corpus was unreadable', 'DEPENDENCY_UNAVAILABLE');
    assert.equal(notRunResult.status, 'not_run');
    assert.equal(notRunResult.passed, false);
    assert.equal(notRunResult.counted, 0);
    assert.equal(notRunResult.omit.code, 'DEPENDENCY_UNAVAILABLE');
  });

  test('a note is bounded and a check detail is bounded, so evidence cannot grow without limit', () => {
    const recorder = new ProbeRecorder('holdout_peek', 'p1', 'holdoutPeek');
    recorder.note('long', 'x'.repeat(5000));
    recorder.check('a fact', true, 'y'.repeat(5000));
    assert.ok(String(recorder.result().evidence.long).length <= 300);
    assert.ok(String(recorder.result().evidence.checks[0].detail).length <= 300);
  });
});

// ===========================================================================
// executor.mjs — a first-class NON-result is recorded, never a zero, and
//      `assertUsableAsResult` refuses to read one as a result.
// ===========================================================================

const INDEPENDENT_EVALUATOR = Object.freeze({ evaluator_id: 'evl-s2-008-test', independent: true, blind_to_producer: true });

function trialRequest(over = {}) {
  return {
    trial_id: 'trl-s2-008-comparator-probes',
    executor_id: 'exec-s2-008-comparator-probes',
    trial_kind: 'OBSERVATIONAL_EVALUATION',
    preregistration_digest: 'a'.repeat(64),
    case_digest: 'b'.repeat(64),
    ...over,
  };
}

function caseRecord(samples = [1, 1, 0, 1]) {
  return { case_id: 'cse-s2-008-comparator-probes', metric_samples: samples };
}

const fixedDateClock = () => ({ now: () => new Date(FIXED_INSTANT_ISO), source: 'INJECTED_FIXED' });

describe('executor: SKIPPED, UNRESOLVED, INFRA and NOT_MEASURED are recorded, not zeroed', () => {
  test('only MEASURED maps to RESOLVED, and the map is total over the frozen outcomes', () => {
    const measured = Object.entries(EXECUTOR_TRIAL_STATUS_BY_OUTCOME).filter(([outcome]) => outcome === 'MEASURED');
    assert.equal(measured.length, 1);
    assert.equal(EXECUTOR_TRIAL_STATUS_BY_OUTCOME.MEASURED, 'RESOLVED');
    for (const [outcome, status] of Object.entries(EXECUTOR_TRIAL_STATUS_BY_OUTCOME)) {
      assert.ok(TRIAL_STATUSES.includes(status), `${outcome} -> ${status} is outside TRIAL_STATUSES`);
      if (outcome !== 'MEASURED') assert.notEqual(status, 'RESOLVED', `${outcome} maps to RESOLVED`);
    }
    assert.deepEqual([...EXECUTOR_DISPOSITIONS], ['EXECUTE', 'SKIP', 'UNRESOLVE']);
  });

  test('a SKIP and an UNRESOLVE are recorded outcomes with no measurement, and neither is a result', async () => {
    for (const [disposition, outcome, status] of [
      ['SKIP', 'SKIPPED', 'SKIPPED'], ['UNRESOLVE', 'UNRESOLVED', 'UNRESOLVED'],
    ]) {
      const record = await runTrial({
        request: trialRequest({ disposition, skip_reason: 'the HOLDOUT was never unsealed' }),
        record: caseRecord(),
        clock: fixedDateClock(),
        evaluator: INDEPENDENT_EVALUATOR,
        calibration: CALIBRATIONS.independent,
      });
      assert.equal(record.outcome, outcome);
      assert.equal(record.trial_status, status);
      assert.equal(record.measurement, null, `${disposition} fabricated a measurement`);
      assert.equal(record.reason, 'the HOLDOUT was never unsealed');
      // A disposition is honoured BEFORE the evaluator branch: a trial that was
      // never run has no evaluator finding to report.
      assert.throws(
        () => assertUsableAsResult(record),
        (error) => error instanceof MalformedResult && /OUTCOME_NOT_A_RESULT/.test(String(error.message)),
        disposition,
      );
      // And the comparator scores it fail-closed.
      assert.equal(resolveTrialVerdict({ ...CLEAN_TRIAL, status }).verdict, 'VIOLATION', disposition);
    }
  });

  test('a missing evaluator yields EVALUATOR_UNAVAILABLE / NOT_MEASURED and never a zero', async () => {
    const record = await runTrial({
      request: trialRequest(), record: caseRecord(), clock: fixedDateClock(), calibration: CALIBRATIONS.independent,
    });
    assert.equal(record.outcome, 'EVALUATOR_UNAVAILABLE');
    assert.equal(record.trial_status, 'NOT_MEASURED');
    assert.equal(record.measurement, null);
    assert.equal(record.evaluator.state, 'EVALUATOR_UNAVAILABLE');
    assert.equal(record.evaluator.reason, 'evaluator_absent');
    assert.throws(
      () => assertUsableAsResult(record),
      (error) => error instanceof MalformedResult && /OUTCOME_NOT_A_RESULT/.test(String(error.message)),
    );
  });

  test('a forged AVAILABLE claim is a typed refusal, not a pass with no evaluator', () => {
    assert.throws(
      () => resolveEvaluatorAvailability({ claimed_state: 'AVAILABLE', calibration: CALIBRATIONS.independent }),
      (error) => error instanceof MalformedResult && /EVALUATOR_STATE_FORGED/.test(String(error.message)),
    );
    assert.throws(
      () => resolveEvaluatorAvailability({ claimed_state: 'PROBABLY_FINE', calibration: CALIBRATIONS.independent }),
      (error) => error instanceof MalformedResult && /EVALUATOR_STATE_UNKNOWN/.test(String(error.message)),
    );
    const available = resolveEvaluatorAvailability({
      evaluator: INDEPENDENT_EVALUATOR, calibration: CALIBRATIONS.independent, reachable: true,
    });
    assert.equal(available.state, 'AVAILABLE');
    assert.equal(available.decides, false, 'availability is an input, never a decision');
  });

  test('an evaluator that is not independent resolves to EVALUATOR_UNAVAILABLE, and the reason is named', () => {
    // Two DIFFERENT defects with the same fail-closed consequence, and the
    // order is deliberate (executor.mjs:819-822): an unreleased calibration is
    // a MEASUREMENT problem named as such, while a calibration that IS measured
    // but not blind to the producer is an INDEPENDENCE problem named as that.
    // The in-contract `not_measured_reason` is carried alongside either way.
    const unreleased = resolveEvaluatorAvailability({
      evaluator: INDEPENDENT_EVALUATOR, calibration: CALIBRATIONS.notIndependent,
    });
    assert.equal(unreleased.state, 'EVALUATOR_UNAVAILABLE');
    assert.equal(unreleased.trial_status, 'NOT_MEASURED');
    assert.equal(unreleased.reason, 'calibration_not_measured');
    assert.equal(unreleased.calibration_not_measured_reason, 'evaluator_not_independent');
    assert.equal(unreleased.decides, false);

    const biased = resolveEvaluatorAvailability({
      evaluator: INDEPENDENT_EVALUATOR,
      calibration: {
        ...CALIBRATIONS.independent,
        evaluator_independence: { ...CALIBRATIONS.independent.evaluator_independence, blind_to_producer: false },
      },
    });
    assert.equal(biased.state, 'EVALUATOR_UNAVAILABLE');
    assert.equal(biased.reason, 'evaluator_not_independent');
    assert.equal(biased.calibration_status, 'MEASURED', 'a measured but biased calibration must not be reported as unmeasured');
    assert.equal(biased.blind_to_producer, false);

    for (const state of [unreleased, biased]) {
      assert.ok(EXECUTOR_EVALUATOR_REASONS.includes(state.reason), String(state.reason));
      assert.equal(state.vocabulary_bound, true);
    }
  });

  test('ABSENT metric samples are MEASUREMENT_ABSENT with a null measurement, not a zero', async () => {
    for (const record of [{ case_id: 'cse-x' }, { case_id: 'cse-x', metric_samples: [] }]) {
      const outcome = await runTrial({
        request: trialRequest(), record, clock: fixedDateClock(), evaluator: INDEPENDENT_EVALUATOR, calibration: CALIBRATIONS.independent,
      });
      assert.equal(outcome.outcome, 'MEASUREMENT_ABSENT');
      assert.equal(outcome.trial_status, 'NOT_MEASURED');
      assert.equal(outcome.measurement, null);
      assert.throws(() => assertUsableAsResult(outcome));
    }
  });

  test('a measurer that throws is an INFRA_ERROR carrying only a typed code', async () => {
    const outcome = await runTrial({
      request: trialRequest(),
      record: caseRecord(),
      clock: fixedDateClock(),
      evaluator: INDEPENDENT_EVALUATOR,
      calibration: CALIBRATIONS.independent,
      measure: () => { throw new Error('a message that must not reach an evidence file'); },
    });
    assert.equal(outcome.outcome, 'INFRA_ERROR');
    assert.equal(outcome.trial_status, 'INFRA_ERROR');
    assert.equal(outcome.measurement, null);
    assert.equal(outcome.retryable, false);
    assert.equal(typeof outcome.error_code, 'string');
    assert.equal(Object.hasOwn(outcome, 'error_message'), false, 'a free-form message was carried into the record');
    assert.throws(() => assertUsableAsResult(outcome));
  });

  test('a MEASURED outcome is usable, and its outcome_digest excludes the latency block', async () => {
    const measured = await runTrial({
      request: trialRequest(), record: caseRecord(), clock: fixedDateClock(), evaluator: INDEPENDENT_EVALUATOR, calibration: CALIBRATIONS.independent,
    });
    assert.equal(measured.outcome, 'MEASURED');
    assert.equal(measured.trial_status, 'RESOLVED');
    assert.equal(measured.vocabulary_bound, true);
    assert.deepEqual(measured.measurement, { statistic: 'mean', value: 0.75, n: 4 });
    assert.equal(assertUsableAsResult(measured).outcome, 'MEASURED');
    assert.equal(measured.latency.decides, false);
    const again = await runTrial({
      request: trialRequest(), record: caseRecord(), clock: fixedDateClock(), evaluator: INDEPENDENT_EVALUATOR, calibration: CALIBRATIONS.independent,
    });
    // Same base, same outcome digest: the latency block is excluded on purpose,
    // because a host-dependent digest could not witness A5 on the next host.
    assert.equal(again.outcome_digest, measured.outcome_digest);
    assert.notEqual(again.request_digest, undefined);
  });

  test('a MISSING injected clock is a typed refusal, never a process-clock default', async () => {
    await assert.rejects(
      () => runTrial({ request: trialRequest(), record: caseRecord(), evaluator: INDEPENDENT_EVALUATOR, calibration: CALIBRATIONS.independent }),
      (error) => error instanceof NeedsInput && /CLOCK_REQUIRED/.test(String(error.message)),
    );
  });

  test('a forged provenance label on the REQUEST is refused against the label the kind derives', async () => {
    await assert.rejects(
      () => runTrial({
        request: trialRequest({ requested_label: 'CAUSAL_EXPERIMENT' }),
        record: caseRecord(), clock: fixedDateClock(), evaluator: INDEPENDENT_EVALUATOR, calibration: CALIBRATIONS.independent,
      }),
      (error) => error instanceof MalformedResult,
    );
    await assert.rejects(
      () => runTrial({
        request: trialRequest({ requested_label: 'BACKTEST' }),
        record: caseRecord(), clock: fixedDateClock(), evaluator: INDEPENDENT_EVALUATOR, calibration: CALIBRATIONS.independent,
      }),
      (error) => error instanceof MalformedResult && /REQUESTED_LABEL_MISMATCH/.test(String(error.message)),
    );
  });

  test('the comparator and the executor agree on the causal label vocabulary', () => {
    // The comparator reads the executor's producible set, so the two cannot
    // drift: a label the executor cannot produce is a label the comparator
    // treats as an unproven claim rather than as a non-claim.
    for (const label of EXECUTOR_PRODUCIBLE_LABELS) {
      assert.equal(resolveTrialVerdict({ ...CLEAN_TRIAL, provenance_label: label }).verdict, 'ALLOW', label);
    }
    for (const label of EXECUTOR_PROVENANCE_LABELS.filter((entry) => !EXECUTOR_PRODUCIBLE_LABELS.includes(entry))) {
      const verdict = resolveTrialVerdict({ ...CLEAN_TRIAL, provenance_label: label });
      assert.equal(verdict.verdict, 'VIOLATION', label);
    }
    assert.equal(COMPARATOR_VERSION, 's2-008-comparator-v1');
  });
});
