// A VALID PREREGISTRATION DOCUMENT plus the hypothesis card it covers.
//
// Serves: the ticket's "preregistration BEFORE the first run (hypothesis,
// metric, frozen baseline, seed count, stopping rule, budget reservation)" and
// negative probe P3 (rewriting a hypothesis after the result), plus the A3/A5
// binding `assertTableFrozen(prereg)` needs.
//
// WHY THE PREREGISTRATION IS NOT A CONTRACT DOCUMENT
// All three frozen schemas are `additionalProperties: false` and none of them
// has room for `seed_count`, `stopping_rule` or `budget_reservation`, and
// `contracts/` is a frozen target, so this document is a plain canonical-JSON
// object validated by `src/lib/research/preregistration.mjs` and NOT by a
// schema. Stating that here is deliberate: a reader who assumes a schema is
// behind this document will look for a validation that does not exist.
//
// WHAT THE CARD IS AND IS NOT
// The card below is valid against the FROZEN
// `contracts/hypothesis-card.schema.json` and is deliberately OBSERVATIONAL:
// `relation_strength: CORRELATION_EVIDENCE`, `causal_assertion: null`,
// `temporal_ordering.established: false`, `mediators: []`,
// `type_promotion: null`. That combination is the subject of A4: the card
// schema carries no `allOf`, so the SAME card with `causal_assertion: true`
// and `relation_strength: EXPERIMENTAL` is still schema-valid, and only
// `assertCausalDiscipline` / `assertNoCausalFromSimulation` in
// `src/lib/research/causality.mjs` can refuse it. The
// `label_substituted` variant in `fixture-corrupted-variants.mjs` is exactly
// that mutation, which is why this card keeps every causal field visibly
// empty rather than merely "unset".
//
// WHAT `designed_outcome` IS AND IS NOT
// `designed_outcome` is the fixture's DESIGN INTENT — the position each trial
// was AUTHORED to sit in relative to the frozen baseline. It is NOT an
// observation and it is not what the table scores: the table's
// `expectedOutcome` is the outcome `decisionFromInterval` DERIVES from the
// interval the frozen measurements produce. Both are published side by side
// (`derived_outcome` / `FIXTURE_DERIVED_DISAGREEMENTS` in
// `fixture-measurement-set.mjs`) rather than collapsed into one name, because
// collapsing them is how a fixture ends up asserting that whatever came out was
// expected.
//
// WITH EIGHT CASES THE RULE DERIVES `UNRESOLVED`, AND THAT IS THE ANSWER
// At the derived confidence the Wilson interval on 7/8 is [0.453625, 0.983339],
// on 6/8 [0.347079, 0.944230] and on 5/8 [0.255737, 0.889917], and the pooled
// campaign's 18/24 gives [0.505681, 0.897936] — all four straddle the frozen
// 0.75 baseline OUTSIDE the 0.02 band, so `decisionFromInterval` returns
// `UNRESOLVED` / `interval_straddles_null_outside_noise_band` for every one of
// them (observed, `node --input-type=module`, exit 0). The delivered table
// nevertheless scored the three measured rows as POSITIVE / NULL / NEGATIVE, so
// `FIXTURE_DERIVED_DISAGREEMENTS` was NOT empty and a clean run carried three
// `TRIAL_FIELD_DIVERGES_FROM_TABLE` findings. That disagreement was published
// rather than hidden, which is the only reason this repair was possible: the
// expectation and the frozen rule could be seen to disagree. The repair
// re-derived the EXPECTATION from the frozen measurements. It did NOT re-tune a
// measurement until a designed effect looked legitimate, and the campaign answer
// stayed UNRESOLVED.
//
// THE PUBLISHED CONFIDENCE IS DERIVED, NEVER CHOSEN
// `CORRECTED_CONFIDENCE = 1 - alpha / family_size`, written once and assigned to
// BOTH rules. It was a hard-coded 0.95 before, and a rule that publishes
// `1 - c = 0.05` against a corrected level of `alpha/m = 0.05/3 = 0.016667` can
// NEVER reject, whatever is measured: `ruleFeasibility` reported
// `never_rejects: true` and the comparator raised the limit
// `frozen_rule_cannot_reject` on every campaign. The comparator was right and
// its own comment said the fix is a PREREGISTRATION change; this file is the
// preregistration, so this is where it is fixed. The two members move TOGETHER
// on purpose: `scoreRun` reads `multiplicity_rule.confidence` for the interval
// it computes while the run record's self-reported `metric.interval` is built
// at `noise_rule.confidence`, and a disagreement between the two is the
// comparator's `self_reported_interval_divergence` finding. One derived
// constant, two assignments, no typed decimal.
//
// THE PUBLISHED FAMILY IS THE THREE DECLARED COMPARISONS — NOT `declared + subject`
// `family_size` is `PREREGISTERED_MEASURED_TRIALS.length` = 3, and the family's
// members are exactly those three trial ids. A unit-test call whose SUBJECT
// JOINS the family (as `tests/research/comparator-probes.test.mjs` does, so the
// subject is matched by id) legitimately widens the effective family to m = 4,
// where `1 - c = 0.016667 > 0.05/4 = 0.0125` and `never_rejects` is `true` AGAIN
// — correctly, because at m = 4 that rule really cannot reject. So
// `never_rejects: true` at m = 4 is not a regression and must not be "fixed" by
// touching those assertions: the fixture's own constants report
// `never_rejects: false` at m = 3 (see `RULE_FEASIBILITY` below), and the two
// numbers are about two different families.
//
// `RULE_FEASIBILITY` IS THE TRACK'S OWN ARITHMETIC, NOT A FIXTURE CLAIM
// It is `ruleFeasibility(...)` from `src/lib/research/comparator.mjs` called on
// this file's frozen constants, so a test asserts a boolean instead of
// re-deriving IEEE-754 by hand: `1 - (1 - 0.05/3)` is 5.2e-17 ABOVE `0.05/3`
// (relative 3.1e-15), and the comparator compares with its own `DECISION_EPSILON`
// tolerance. A hand-written `1 - confidence <= alpha / family_size` in a test
// fails on that rounding artefact; `RULE_FEASIBILITY.never_rejects` is the
// statement that means what it says.
//
// WHY THE METRIC IS NAMED `case_agreement_rate`
// It is the frozen table's `EXPECTED_METRIC.name`, read from
// `src/lib/research/expected-values.mjs` and re-exported here as
// `FROZEN_METRIC_NAME`. This fixture used to call the metric
// `span_binding_agreement`, which is a nicer name for a story and a wrong name
// for a record: `expectedValueIssues` scores `run.metrics.metric` against the
// frozen table's name and `scoreMetric` names a `metric_name_divergence`
// failure, so every clean fixture run produced a divergence it could not fix.
// A metric name is an identifier, and an identifier is one thing.
import { fixtureDigest } from './fixture-digest.mjs';
import { FIXED_INSTANT_ISO } from './fixture-fixed-clock.mjs';
import { ruleFeasibility } from '../../../src/lib/research/comparator.mjs';
import { PREREGISTRATION_RULE, preregistrationDigest } from '../../../src/lib/research/preregistration.mjs';
import { EXPECTED_METRIC as FROZEN_METRIC, expectedTableDigest } from '../../../src/lib/research/expected-values.mjs';

/** The document kind. Must equal `PREREGISTRATION_KIND`; a mismatch FAILS a test rather than being merged. @type {string} */
export const FIXTURE_PREREGISTRATION_KIND = 'PREREGISTRATION';

/**
 * The frozen rule string recorded with every fixture preregistration.
 *
 * RE-EXPORTED from the track rather than re-declared. The fixture used to carry
 * its own longer sentence for the same rule, so the document carried a `rule`
 * member the loader REFUSED at `PREREGISTRATION_RULE_MISMATCH` — the same class
 * of defect as SD-07, one level up: two spellings of one rule, and the
 * document matched neither. One rule string exists in this repository and it
 * lives in `src/lib/research/preregistration.mjs`.
 * @type {string}
 */
export const FIXTURE_PREREGISTRATION_RULE = PREREGISTRATION_RULE;

/**
 * The observational hypothesis card, valid against the frozen schema.
 * @type {Readonly<object>}
 */
export const HYPOTHESIS_CARD = Object.freeze({
  contractVersion: '1.0.0',
  card_id: 'hyc-s2-008-01',
  card_type: 'HYPOTHESIS',
  // No promotion happened. A producer may never promote its own card, and the
  // track never promotes anything: the card below stays a HYPOTHESIS.
  type_promotion: null,
  originating_domains: Object.freeze(['span-extraction', 'coherence-triage']),
  nodes: Object.freeze([
    Object.freeze({ claim_id: 'clm-s2-008-01', revision: 1, domain: 'coherence-triage', role: 'source' }),
    Object.freeze({ claim_id: 'clm-s2-008-02', revision: 1, domain: 'span-extraction', role: 'target' }),
  ]),
  proposed_relation: Object.freeze({
    subject: 'deterministic coherence triage filter',
    predicate: 'is associated with',
    object: 'span binding agreement on the holdout partition',
    // OBSERVATIONAL. `causal_assertion` is null, and the label above says
    // "is associated with" rather than "causes" — the prose and the enum agree,
    // so the card cannot be read as causal by skimming it.
    relation_strength: 'CORRELATION_EVIDENCE',
    causal_assertion: null,
  }),
  temporal_ordering: Object.freeze({ established: false, evidence_claim_ids: Object.freeze([]), event_times: Object.freeze([]) }),
  mediators: Object.freeze([]),
  confounders: Object.freeze([
    Object.freeze({
      description: 'cohort difficulty drifts between the dev partition and the holdout partition',
      status: 'IDENTIFIED',
      claim_id: 'clm-s2-008-02',
    }),
  ]),
  alternative_explanations: Object.freeze([
    Object.freeze({
      description: 'the filter changed which spans were labelled rather than which were bound',
      claim_id: null,
    }),
  ]),
  scope: Object.freeze({
    population: null,
    geography: null,
    period: null,
    units: 'span',
    domain_limits: Object.freeze([
      'the eight hand-authored fixture cases only; no production span stream was measured',
      'association only; no causal effect is claimed or measurable on this corpus',
    ]),
  }),
  assumptions: Object.freeze([
    'the holdout partition is exchangeable with the dev partition',
    'the evaluator is blind to the filter under test',
  ]),
  falsifiers: Object.freeze([
    Object.freeze({
      description: 'the holdout agreement interval lies inside the preregistered noise band',
      observable: 'holdout agreement interval against the frozen baseline 0.75 with a 0.02 band',
    }),
  ]),
  test_design:
    'One seeded percentile-bootstrap interval per enumerated trial over the eight fixture cases, compared against the frozen baseline 0.75 with a preregistered noise band of 0.02, Holm-Bonferroni over the three declared comparisons. Observational corpus; inference_mode ASSOCIATIONAL.',
  counterevidence: Object.freeze([
    Object.freeze({ claim_id: 'clm-s2-008-02', relation: 'bounds' }),
  ]),
  novelty: Object.freeze({
    assessment: 'NOT_ASSESSED',
    corpus: null,
    search_horizon: null,
    similar_prior_refs: Object.freeze([]),
  }),
  uncertainty: Object.freeze({
    author_confidence: null,
    expert_trust: null,
    measured_calibration: null,
    evidence_support: 0,
  }),
  stale: Object.freeze({ is_stale: false, invalidation_event_ids: Object.freeze([]), stale_claim_ids: Object.freeze([]) }),
  status: 'FRESH',
  created_at: FIXED_INSTANT_ISO,
  created_by: 's2-008-fixture-author',
});

/**
 * The canonical digest of the card. P3 rides on this: a post-result edit of
 * `test_design` keeps `card_id` and still satisfies the frozen schema, so only
 * a digest that COVERS `test_design` can catch the rewrite. A card digest that
 * covered only the id would have made the whole probe vacuous.
 * @type {string}
 */
export const HYPOTHESIS_CARD_DIGEST = fixtureDigest(HYPOTHESIS_CARD);

/**
 * The preregistered seed set. Frozen BEFORE the run, on every trial: because
 * the seeds are preregistered, "the best seed" is not a statistic the verdict
 * is allowed to use (P2).
 * @type {ReadonlyArray<number>}
 */
export const PREREGISTERED_SEEDS = Object.freeze([101, 202, 303, 404, 505]);

/** The frozen table's metric name, read from the track and re-exported. @type {string} */
export const FROZEN_METRIC_NAME = FROZEN_METRIC.name;

/**
 * The frozen metric. `inferenceMode` is ASSOCIATIONAL and is published here,
 * never upgraded: an observational corpus cannot support a causal claim, and
 * the field is in the preregistration precisely so that upgrading it would
 * move the preregistration digest.
 *
 * `name` is the frozen table's name and `noiseBand` is the frozen table's band;
 * both are READ from `src/lib/research/expected-values.mjs`, not re-declared.
 * Two spellings of one metric name is the same defect class as SD-07.
 * @type {{name: string, unit: string, direction: string, value_basis: string, noiseBand: number, inferenceMode: string}}
 */
export const PREREGISTERED_METRIC = Object.freeze({
  name: FROZEN_METRIC.name,
  unit: FROZEN_METRIC.unit,
  direction: FROZEN_METRIC.direction,
  value_basis: 'CASE_AGREEMENT_RATE',
  noiseBand: FROZEN_METRIC.noiseBand,
  inferenceMode: FROZEN_METRIC.inferenceMode,
});

/**
 * The frozen baseline the intervals are compared against. Preregistered, not
 * re-measured: a baseline read after the run is a baseline chosen to suit the
 * result.
 * @type {{value: number, source: string, corpus_partition: string, measured_by: string}}
 */
export const FROZEN_BASELINE = Object.freeze({
  value: 0.75,
  // The digest of the DEV partition this baseline was measured on. Required:
  // a baseline with no digest is a number a reader cannot trace to bytes, and a
  // baseline re-measured at analysis time is a baseline chosen to suit the
  // result. The value is the DYADIC fraction 6/8, exact in IEEE-754.
  baseline_digest: 'a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00',
  value_basis: 'CASE_AGREEMENT_RATE',
  source: 'FROZEN_DEV_PARTITION',
  corpus_partition: 'PRIMARY',
  measured_by: 's2-008-fixture-author',
});

/**
 * The budget reservation, live at `FIXED_CLOCK` and expiring two hours later —
 * i.e. ONE HOUR AFTER the preregistered decision point
 * (`2026-01-01T01:00:00.000Z`), not one hour after the clock.
 *
 * The earlier revision of this fixture expired AT the decision point, which made
 * the lawful window EMPTY: `lawfulWindow` (scripts/s2-008-run.mjs:202) requires
 * the holdout read to happen at or after `from` = the decision point AND the
 * reservation to still be live strictly before `until` = `expires_at`. With
 * `expires_at === from` no instant satisfies both, so every run carried the
 * harness finding `PREREGISTERED_RUN_WINDOW_EMPTY` — a reservation that cannot
 * be spent inside its own window is not a budget, it is a refusal. The
 * preregistered runway after the decision point is what makes the window
 * non-empty, and it is published HERE, before trial one, where a reader can
 * check it.
 *
 * `trial_timeout_ms` is the per-trial bound the engine reads
 * (`TRIAL_TIMEOUT_PATHS` in src/lib/research/runner.mjs:280). It is published
 * rather than defaulted because a timeout chosen at run time is not a timeout:
 * with none published, `trialTimeoutOf` refuses with
 * `TRIAL_TIMEOUT_NOT_PREREGISTERED` and no run can start at all.
 *
 * The value is deliberately FAR above any real trial: it is a bound on a stuck
 * trial, not a performance target. An elapsed time past it becomes an UNRESOLVED
 * trial, which the comparator scores as a VIOLATION rather than an absence
 * (fail-closed, A2) — so a bound tight enough to fire on a loaded host would let
 * the machine decide the verdict. One hour cannot. Latency is MEASURED and
 * recorded; the DECISION follows the frozen noise/CI rule in `noise_rule`, never
 * this number.
 * @type {{reservation_id: string, granted_units: number, spent_units: number, expires_at: string, currency: string, trial_timeout_ms: number}}
 */
export const BUDGET_RESERVATION = Object.freeze({
  reservation_id: 'rsv-s2-008-01',
  granted_units: 8,
  spent_units: 0,
  expires_at: '2026-01-01T02:00:00.000Z',
  currency: 'trial_runs',
  trial_timeout_ms: 3_600_000,
});

/**
 * The enumerated trial list, published before trial one. A trial cannot be
 * added, removed or re-ordered after a result: a change is an AMENDMENT with
 * its own id and digest, and the amendment may not be a decision basis.
 * @type {ReadonlyArray<Readonly<object>>}
 */
export const PREREGISTERED_TRIALS = Object.freeze([
  Object.freeze({ index: 0, trial: 'trl-s2-008-01', designed_outcome: 'POSITIVE', partition: 'HOLDOUT', stratum: 'all_cases' }),
  Object.freeze({ index: 1, trial: 'trl-s2-008-02', designed_outcome: 'NULL', partition: 'HOLDOUT', stratum: 'all_cases' }),
  Object.freeze({ index: 2, trial: 'trl-s2-008-03', designed_outcome: 'NEGATIVE', partition: 'HOLDOUT', stratum: 'all_cases' }),
  Object.freeze({ index: 3, trial: 'trl-s2-008-04', designed_outcome: 'INFRA', partition: 'HOLDOUT', stratum: 'all_cases' }),
]);
// Every trial reads the HOLDOUT partition. There is deliberately no case-level
// PRIMARY data in this fixture set: the dev partition enters only as the
// FROZEN baseline above, and a baseline that is re-measured at run time is a
// baseline chosen to suit the result.

/**
 * The MEASURED campaign: the preregistered trials that produce a measurement,
 * DERIVED from the trial list by the one predicate that says what "measured"
 * means here. The INFRA trial is not in it, and being out of the family is not
 * being dropped: it keeps its row in the frozen table, it keeps its
 * reconciliation row, and an unresolved trial is still scored as a VIOLATION.
 * The multiplicity correction runs over exactly these three ids.
 * @type {ReadonlyArray<Readonly<object>>}
 */
export const PREREGISTERED_MEASURED_TRIALS = Object.freeze(
  PREREGISTERED_TRIALS.filter((entry) => entry.designed_outcome !== 'INFRA'),
);

/**
 * The RECONCILIATION corpus: the enumerated trials that are NOT measured. INFRA
 * is already exercised there — P6's missing evaluator, the replay's
 * crash/restart phase and `INFRA_RECONCILIATION` — so an unmeasured trial
 * belongs with the other places an unmeasured trial is exercised rather than
 * inside the measured campaign it cannot contribute to.
 * @type {ReadonlyArray<Readonly<object>>}
 */
export const PREREGISTERED_RECONCILIATION_TRIALS = Object.freeze(
  PREREGISTERED_TRIALS.filter((entry) => entry.designed_outcome === 'INFRA'),
);

/**
 * The family-wise alpha the correction runs at. NAMED once, because the
 * corrected confidence below is derived FROM it and a second spelling of alpha
 * would let the two drift apart and produce exactly the undecidable rule this
 * file used to publish.
 * @type {number}
 */
export const PREREGISTRATION_ALPHA = 0.05;

/**
 * `m`: the size of the DECLARED family the Holm-Bonferroni correction runs over,
 * counted from the measured trials rather than typed. `assertMultiplicityRule`
 * refuses a `family_size` that disagrees with `declared_comparisons.length`, so
 * a typed 3 would be a third copy of a number the list already carries.
 * @type {number}
 */
export const MEASURED_FAMILY_SIZE = PREREGISTERED_MEASURED_TRIALS.length;

/**
 * The confidence the rule publishes, DERIVED: `1 - alpha / family_size`.
 *
 * The self-consistency a multiplicity rule must have is `1 - c <= alpha / m`: a
 * comparison bound inherited from a `c`-level interval is `1 - c`, so a family of
 * `m` members whose bound exceeds the corrected level can never reject, whatever
 * is measured. At `m = 3` and `alpha = 0.05` the corrected level is
 * `0.05/3 = 0.016667`, so the published confidence is `1 - 0.05/3 =
 * 0.98333...` and the bound lands ON the level rather than above it.
 *
 * Chosen rather than derived, the previous value was 0.95 — a round number that
 * reads like a convention and made the campaign undecidable by construction.
 * @type {number}
 */
export const CORRECTED_CONFIDENCE = 1 - PREREGISTRATION_ALPHA / MEASURED_FAMILY_SIZE;

/**
 * What the frozen rule COULD EVER DECIDE, computed by the track's own pure
 * helper over the constants above, so a test can assert the rule's feasibility
 * without re-doing the arithmetic (and without tripping over the 5.2e-17 by which
 * `1 - (1 - alpha/m)` sits above `alpha/m` in IEEE-754).
 * @type {{rejection_floor: number, max_p_bound: number, never_rejects: boolean, can_only_answer: string, feasible: boolean, note: string}}
 */
export const RULE_FEASIBILITY = Object.freeze(ruleFeasibility({
  alpha: PREREGISTRATION_ALPHA,
  confidence: CORRECTED_CONFIDENCE,
  familySize: MEASURED_FAMILY_SIZE,
}));

// --- the SUPERSEDED rule, preserved -----------------------------------------
//
// R-A: the pre-repair preregistration is preserved as a document of its own,
// with the reason and the digests of both states. Deleting it, or editing it in
// place, would leave the repair looking like a rule that was always able to
// reject — which is the specific dishonesty the supersession exists to prevent:
// nobody could afterwards read what the first delivery actually published.
//
// These three values are the WHOLE of the supersession's factual content. They
// are literals because they are HISTORY: 0.95 is what the first delivery
// published, and `9aad76e1...` is what `expectedTableDigest()` returned before
// the frozen table was re-derived. Neither is a claim about the rule in force.

/** The confidence the PRE-REPAIR preregistration published in BOTH rules. @type {number} */
export const SUPERSEDED_CONFIDENCE = 0.95;

/**
 * The frozen-table digest the pre-repair document sealed — the value
 * `npm run s2-008:check-corpus` reported (exit 0) and the value the committed
 * `evidence/s2-008/corpus/preregistration.json` carried before this repair.
 * @type {string}
 */
export const SUPERSEDED_EXPECTED_TABLE_DIGEST = '9aad76e1b0f8c6f55ac59548347278f1b4f7c3e5ea4d11a75d2fd1896c08af62';

/**
 * Why the pre-repair rule is superseded, in one line. It is a fact about the
 * published constants (`1 - 0.95 = 0.05 > 0.05/3`), and the redesign happened
 * BEFORE any new measurement of the synthetic corpus: the per-case labels are
 * the same eight cases with the same agreement values, and the only measurement
 * that changed is the INTERVAL those same labels are summarised at.
 *
 * It is kept inside `MAX_REASON` (240 characters, the bound
 * `createSupersession` enforces for the same reason `createAmendment` enforces
 * it: the text is hashed into a permanent, journalled document). A reason too
 * long for the bound is refused rather than truncated, because a truncated
 * reason is a reason that no longer says what it said.
 * @type {string}
 */
export const SUPERSESSION_REASON = 'the published confidence 0.95 gave 1 - c = 0.05 > alpha/m = 0.016667, so the rule could never reject; the confidence is now derived as 1 - alpha/family_size, and the redesign was made before any new measurement of the synthetic corpus';

/**
 * The corpus's own case digest, as a LITERAL (A3).
 *
 * The eight synthetic cases are the other half of what a wholesale rewrite of
 * this track would move, and this literal is what makes the ledger able to
 * notice: `scripts/s2-008-build-corpus.mjs` re-derives it and refuses a corpus
 * whose cases no longer hash to this. It is the digest
 * `evidence/s2-008/corpus/manifest.json` sealed as
 * `partitions.HOLDOUT.digest` in the FIRST delivery and in every one since — the
 * per-case agreement values were never re-tuned, only the interval they are
 * summarised at moved.
 * @type {string}
 */
export const FROZEN_CASES_DIGEST = '654631a483c581ee734caaea2ff052f18b18955aecd19c7cf25442f7fc143043';

/**
 * THE SUPERSESSION LEDGER OF THE FROZEN SOURCES (A3).
 *
 * Three entries, in order, each one a change to the pair
 * `(cases_digest, expected_table_digest)`:
 *
 *   0. THE FIRST DELIVERY. `9aad76e1…` is the table digest the pre-repair tree
 *      sealed, and it is the last state in which the multiplicity rule could
 *      reject nothing.
 *   1. THE R-A RULE REDESIGN. The confidence became `1 - alpha / m`, the INFRA
 *      trial left the multiplicity family (R-B) and the campaign expectation was
 *      added to the table (R-C) — so the table digest moved. No case changed:
 *      `cases_digest` is unchanged across all three entries, and that is the
 *      point of the anchor covering both.
 *   2. THE F1 DECLARATION. The table gained the declaration of WHICH comparator
 *      failures the honest campaign carries, so its digest moved again. No case
 *      and no measurement changed here either.
 *
 * WHY THE DIGESTS ARE LITERALS AND NOT COMPUTED HERE
 * A ledger entry that recomputed its anchor from the current sources would
 * re-anchor itself on every edit, and the chain would then be satisfied by any
 * rewrite — which is the gap the reproduction named. A literal is history: each
 * entry states the state that was true WHEN it was written, and
 * `assertSourceLedger` refuses a chain that does not end where the sources now
 * are. The price is the honest one: a future change to the frozen sources is
 * refused until an entry is appended here, with a reason. That is the design,
 * not a nuisance.
 * @type {ReadonlyArray<Readonly<{index: number, cases_digest: string, expected_table_digest: string, reason: string}>>}
 */
export const SUPERSESSION_LEDGER = Object.freeze([
  Object.freeze({
    index: 0,
    cases_digest: FROZEN_CASES_DIGEST,
    expected_table_digest: SUPERSEDED_EXPECTED_TABLE_DIGEST,
    reason: 'the first delivery: confidence 0.95 against alpha/m = 0.016667, a table without a campaign expectation, and the same eight cases',
  }),
  Object.freeze({
    index: 1,
    cases_digest: FROZEN_CASES_DIGEST,
    expected_table_digest: '02d4fb926b6737790b016ec28c1080745f7a0fb2f9581390f56c69a75acf9144',
    reason: 'R-A/R-B/R-C: the confidence is derived as 1 - alpha/m, the INFRA trial left the multiplicity family, and the table declares the campaign decision; the eight cases and their agreement values are byte-identical',
  }),
  Object.freeze({
    index: 2,
    cases_digest: FROZEN_CASES_DIGEST,
    expected_table_digest: '8062bc85f0252e6e48111b5dea3312ad698bca679da14eabd763510074207f63',
    reason: 'F1: the table also declares WHICH comparator failures the honest campaign carries, so an undeclared one is a gate term; no case and no measurement changed',
  }),
]);

/**
 * The holdout commitment: the one-shot unseal digest a holdout read must
 * present. Naming it in the preregistration is what makes a peek detectable —
 * a read with no matching digest is refused and counted (P1).
 * @type {{partition: string, one_shot: true, unseal_digest: string, case_count: number, reads_before_data: true}}
 * @see fixture-measurement-set.mjs for the label vector this seals.
 */
export const HOLDOUT_COMMITMENT = Object.freeze({
  partition: 'HOLDOUT',
  one_shot: true,
  // Computed by `fixture-measurement-set.mjs` over the fixture's own label
  // vector and injected here by `buildPreregistration()`; a placeholder here
  // would let a test pass against a digest that belongs to nothing.
  unseal_digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
  case_count: 8,
  reads_before_data: true,
});

/**
 * The calibration records the comparator reads. Two contract-valid documents:
 * an independent MEASURED one (which may allow a trial) and a NOT_MEASURED one
 * whose reason is `evaluator_not_independent` — an exact member of the frozen
 * `not_measured_reason` enum in
 * `contracts/calibration-record.schema.json` (P6). The second exists to prove
 * that "not measured" is NOT 0 % and NOT an ALLOW.
 *
 * The DELIVERED calibration record of this track is neither of these: the
 * frozen `outcome_definition.metric` enum has no S2-008 slot, so the track's
 * own record is `NOT_MEASURED` with `not_measured_reason: outcome_not_defined`
 * (plan §6). These two are TEST inputs for the comparator only.
 * @type {{independent: Readonly<object>, notIndependent: Readonly<object>}}
 */
export const CALIBRATIONS = Object.freeze({
  independent: Object.freeze({
    contractVersion: '1.0.0',
    calibration_id: 'cal-s2-008-independent',
    corpus_version: '2.8.0',
    corpus_sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00',
    outcome_definition: Object.freeze({
      metric: 'span_binding_accuracy',
      threshold: 0.75,
      description: 'share of fixture cases whose span binding matches the case ground truth',
    }),
    numerator: 6,
    denominator: 8,
    missing_count: 0,
    uncertainty: Object.freeze({
      method: 'bootstrap',
      confidence_interval: Object.freeze({ lower: 0.40625, upper: 0.953125, confidence_level: 0.95 }),
    }),
    // P6: an evaluator may decide only when it is independent AND blind to the
    // producer. `independent_evaluators >= 1` is also the schema's minimum, so
    // a record can never claim zero independent evaluators.
    evaluator_independence: Object.freeze({ independent_evaluators: 1, blind_to_producer: true, separate_processes: true }),
    status: 'MEASURED',
    not_measured_reason: null,
    measured_at: FIXED_INSTANT_ISO,
    measured_by: 'prn-s2-008-fixture-evaluator',
  }),
  notIndependent: Object.freeze({
    contractVersion: '1.0.0',
    calibration_id: 'cal-s2-008-not-independent',
    corpus_version: '2.8.0',
    corpus_sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00',
    outcome_definition: Object.freeze({
      metric: 'span_binding_accuracy',
      threshold: 0.75,
      description: 'share of fixture cases whose span binding matches the case ground truth',
    }),
    // A NOT_MEASURED record carries counts that are explicitly not a rate. The
    // numbers are the schema's legal minimum, not a measurement: reading them
    // as 0 / 8 = 0 % is precisely the conflation P6 exists to refuse.
    numerator: 0,
    denominator: 8,
    missing_count: 8,
    uncertainty: Object.freeze({
      method: 'wilson',
      confidence_interval: Object.freeze({ lower: 0, upper: 1, confidence_level: 0.95 }),
    }),
    evaluator_independence: Object.freeze({ independent_evaluators: 1, blind_to_producer: false, separate_processes: false }),
    status: 'NOT_MEASURED',
    not_measured_reason: 'evaluator_not_independent',
    measured_at: FIXED_INSTANT_ISO,
    measured_by: 'prn-s2-008-fixture-producer',
  }),
});

/**
 * Build the preregistration document.
 *
 * A function rather than a constant for exactly one reason: the holdout
 * commitment's `unseal_digest` is the digest of the fixture's own label map,
 * which lives in `fixture-measurement-set.mjs`. Hard-coding a digest here would
 * let the two drift apart and a test would pass against a seal that belongs to
 * nothing. The document is still deterministic: the same inputs produce
 * byte-identical bytes in every process.
 *
 * THE SHAPE IS `assertPreregistration`'s REQUIRED SHAPE, member for member.
 * This is the recorded correction behind finding S2-008-SD-07: the earlier
 * version of this builder emitted `seed_rule: 'PREREGISTERED_SET_ONLY'`,
 * `stopping_rule.type`, `stopping_rule.early_stop: 'NEVER'`,
 * `multiplicity_rule.comparison_list`, `trials`, `holdout` and a
 * `frozen_baseline` with no digest — so it was REFUSED at
 * `PREREGISTRATION_FIELD_INVALID` and no probe behind P1, P2, P4 or the
 * comparator had a preregistration to run against. The reason each member has
 * the name it has is in the "REQUIRED SHAPE" block of
 * `src/lib/research/preregistration.mjs`; nothing here is a second shape.
 *
 * @param {{holdoutUnsealDigest: string}} args
 * @param {string} args.holdoutUnsealDigest `sha256:<64 hex>` over the fixture
 *   label MAP (the form `dataset.mjs` recomputes from the committed corpus).
 * @returns {Readonly<object>} The preregistration document, self-sealed with
 *   `preregistration_digest` so the committed file is self-verifying at load.
 * @throws {Error} `FIXTURE_PREREGISTRATION_INPUT_INVALID` when the digest is not
 *   in wire form.
 */
export function buildPreregistration({ holdoutUnsealDigest } = {}) {
  return buildPreregistrationDocument({
    holdoutUnsealDigest,
    confidence: CORRECTED_CONFIDENCE,
    tableDigest: expectedTableDigest(),
  });
}

/**
 * The pre-repair preregistration, preserved whole.
 *
 * The same document builder as the rule in force, with the ONE published
 * confidence and the ONE frozen-table digest the first delivery carried, so the
 * two documents are the same SHAPE and differ only where the repair changed
 * something. `preregistrationDigest(...)` over this document is
 * `8fab7e83d472b7914b6e660dd956f6dc394589bcd4ab323162b6545dde7fe479` — the
 * value the committed corpus carried before the repair, and the proof that this
 * is a reconstruction of the first delivery rather than a new document that
 * happens to look old.
 *
 * It carries no `supersedes` pointer: `assertPreregistration` refuses a
 * preregistration that carries a result or a supersession pointer
 * (`RESULT_CARRYING_KEYS`), so the pointer lives in the supersession document
 * beside it, not inside the document it supersedes.
 *
 * @param {{holdoutUnsealDigest: string}} args The same input as the rule in force.
 * @returns {Readonly<object>} The superseded document, self-sealed.
 * @throws {Error} `FIXTURE_PREREGISTRATION_INPUT_INVALID` on a malformed digest.
 */
export function buildSupersededPreregistration({ holdoutUnsealDigest } = {}) {
  return buildPreregistrationDocument({
    holdoutUnsealDigest,
    confidence: SUPERSEDED_CONFIDENCE,
    tableDigest: SUPERSEDED_EXPECTED_TABLE_DIGEST,
  });
}

/**
 * The one document builder both published rules go through.
 *
 * PRIVATE ON PURPOSE: `confidence` is a parameter rather than a public option
 * because a caller-supplied confidence is a way to rebuild a rule that cannot
 * reject by accident. The two reachable documents are the two named builders
 * above, and both pass a value this file derives or freezes — never one a caller
 * chose.
 *
 * @param {{holdoutUnsealDigest: string, confidence: number, tableDigest: string}} args
 * @param {string} args.holdoutUnsealDigest `sha256:<64 hex>` over the label map.
 * @param {number} args.confidence The published confidence, derived or superseded.
 * @param {string} args.tableDigest The frozen-table digest this document seals.
 * @returns {Readonly<object>} A self-sealed preregistration document.
 * @throws {Error} `FIXTURE_PREREGISTRATION_INPUT_INVALID` when the digest is not
 *   in wire form.
 */
function buildPreregistrationDocument({ holdoutUnsealDigest, confidence, tableDigest }) {
  if (typeof holdoutUnsealDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(holdoutUnsealDigest)) {
    throw new Error(`FIXTURE_PREREGISTRATION_INPUT_INVALID: holdoutUnsealDigest must be sha256:<64 hex>, got ${String(holdoutUnsealDigest)}`);
  }
  const document = {
    kind: FIXTURE_PREREGISTRATION_KIND,
    preregistration_id: 'xpr-s2-008-01',
    rule: FIXTURE_PREREGISTRATION_RULE,
    // Recorded before trial one and covered by `preregistration_digest` below.
    // No wall-clock read happens here: the instant is the injected fixed one,
    // so a fixture can never claim it was preregistered "just now".
    recorded_at: FIXED_INSTANT_ISO,
    recorded_before_first_trial: Object.freeze({ first_trial: 'trl-s2-008-01', order_proved_by: 'REGISTRY_JOURNAL_NOT_A_CLOCK' }),
    card: HYPOTHESIS_CARD,
    card_id: HYPOTHESIS_CARD.card_id,
    card_digest: HYPOTHESIS_CARD_DIGEST,
    metric: PREREGISTERED_METRIC,
    frozen_baseline: FROZEN_BASELINE,
    // P2 in two fields: the SET is frozen as a rule `deriveSeedPlan` can
    // re-derive on its own, and selecting the best-scoring member of it is
    // forbidden, because "the best seed" is not a statistic the verdict may
    // use once the seeds are preregistered.
    seed_rule: Object.freeze({
      kind: 'FIXED_LIST',
      seeds: PREREGISTERED_SEEDS,
      source: 'PREREGISTERED',
      best_seed_selection: 'FORBIDDEN',
    }),
    seed_count: PREREGISTERED_SEEDS.length,
    seeds_digest: fixtureDigest(PREREGISTERED_SEEDS),
    stopping_rule: Object.freeze({
      kind: 'FIXED_TRIALS',
      max_trials: PREREGISTERED_TRIALS.length,
      // An explicit boolean, and FALSE under a fixed trial list: an early stop
      // that "stops when it looks good" is a peek with extra steps, so the
      // frozen rule refuses the edge rather than the run.
      early_stop: false,
      on_negative: 'RECORD_AND_CONTINUE',
      on_null: 'RECORD_AND_CONTINUE',
      on_infra: 'RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO',
    }),
    noise_rule: Object.freeze({
      band: PREREGISTERED_METRIC.noiseBand,
      // The SAME derived value `multiplicity_rule.confidence` carries. They move
      // together because `scoreRun` computes the campaign interval at the
      // multiplicity confidence while the run record's self-reported
      // `metric.interval` is built at this one; two spellings of the level make
      // the comparator report `self_reported_interval_divergence` against every
      // run.
      confidence,
      // The METRIC interval is a Wilson score interval over the per-case
      // agreement labels, because the metric is a proportion and the frozen
      // statistics module ships `wilsonInterval` for exactly that. The
      // bootstrap parameters below are for the LATENCY block, which is a
      // distribution of wall-clock samples and is recorded with
      // `decides: false`.
      //
      // Recording both methods under one rule, as the previous version did
      // (`percentile_bootstrap` for a proportion), is a rule that describes
      // nothing: a reader cannot re-derive the interval the run reported.
      method: 'wilson_score',
      latency_method: 'percentile_bootstrap',
      bootstrap_seed: 20260801,
      bootstrap_samples: 2000,
      // The LATENCY percentile. The metric's point estimate is the Wilson
      // point estimate, so this percentile has no say in any verdict
      // (SD-12: the parameters actually used are always reported back).
      percentile: 0.95,
      unit: PREREGISTERED_METRIC.unit,
      // The three rules, written down so `decisionFromInterval` reads them
      // instead of re-deciding what a band means. An interval that intersects
      // the band is NULL; it is never read as NEGATIVE.
      positive_rule: 'LOWER_MINUS_BASELINE_GT_BAND',
      negative_rule: 'UPPER_MINUS_BASELINE_LT_NEG_BAND',
      null_rule: 'INTERVAL_INTERSECTS_BAND',
      inference_mode: 'ASSOCIATIONAL',
    }),
    multiplicity_rule: Object.freeze({
      kind: 'HOLM_BONFERRONI',
      method: 'holm_bonferroni',
      alpha: PREREGISTRATION_ALPHA,
      // DERIVED, never chosen: `1 - alpha / family_size`. See
      // `CORRECTED_CONFIDENCE` above for why a published 0.95 made every
      // campaign undecidable.
      confidence,
      // R6: the correction runs over the DECLARED family of TRIAL IDS, and
      // every one of them is in `trial_list`. `assertMultiplicityRule` refuses
      // a comparison that is not a declared trial, so the family cannot be
      // "the comparisons that happened to be significant".
      declared_comparisons: Object.freeze(PREREGISTERED_MEASURED_TRIALS.map((entry) => entry.trial)),
      family_size: MEASURED_FAMILY_SIZE,
      // The direction the hypothesis expects, frozen HERE so the comparator
      // reads a preregistered direction rather than a default (finding
      // S2-008-SD-04: the direction was never in any document, so a real
      // improvement could be scored as the wrong answer).
      direction: 'increase',
      // The infra trial is excluded from the multiplicity family with a
      // reason, and the list is DERIVED from the reconciliation set rather than
      // typed, so the family and its complement cannot disagree. Excluded is not
      // dropped: it still has a table row and its row says VIOLATION.
      excluded: Object.freeze(PREREGISTERED_RECONCILIATION_TRIALS.map((entry) => Object.freeze({
        trial: entry.trial,
        reason: 'INFRA_OUTCOME_NO_INTERVAL_TO_CORRECT',
      }))),
    }),
    inference_mode: 'ASSOCIATIONAL',
    budget_reservation: BUDGET_RESERVATION,
    // The table this campaign will be scored against, SEALED HERE, before trial
    // one. `assertTableFrozen(prereg)` reads exactly this member, and refuses a
    // preregistration that carries no table digest with
    // EXPECTED_TABLE_DIGEST_ABSENT — "an expectation published after the run is
    // not an expectation". Without it every consumer had to bolt the digest on
    // by hand (the comparator test still does), and a fixture that only works
    // once a caller remembers a line is a fixture that is easy to get wrong.
    // It is NOT one of the twelve digest-projected members, so recording it
    // cannot change the preregistration digest it is published beside.
    expected_table_digest: tableDigest,
    holdout_access: Object.freeze({
      partition: 'HOLDOUT',
      one_shot: true,
      // P1's frozen rule, in the three members `assertHoldoutAccess` reads:
      // exactly one open, at a decision point named in advance (never "on
      // significance"), with the unseal digest and the sealed label digest
      // both fixed before trial one.
      max_opens: 1,
      decision_point: 'AFTER_DECLARED_TRIALS',
      unseal_digest: holdoutUnsealDigest,
      labels_digest: holdoutUnsealDigest,
      released_actor_kinds: Object.freeze(['EVALUATOR']),
      case_count: 8,
      reads_before_data: true,
    }),
    trial_list: Object.freeze(PREREGISTERED_TRIALS.map((entry) => Object.freeze({
      trial_id: entry.trial,
      index: entry.index,
      designed_outcome: entry.designed_outcome,
      partition: entry.partition,
      stratum: entry.stratum,
    }))),
    // The six fields the ticket enumerates are all present above; this block
    // exists so a reader (and a test) can see at a glance that none is missing,
    // without counting keys.
    required_fields_present: Object.freeze([
      'hypothesis', 'metric', 'frozen_baseline', 'seed_count', 'stopping_rule', 'budget_reservation',
    ]),
  };
  // The self-attestation is computed LAST and covers only the twelve
  // digest-projected members, so adding it cannot change the value it holds.
  // `assertPreregistration` re-derives it and refuses a mismatch, which makes
  // the committed `evidence/s2-008/corpus/preregistration.json` self-sealing.
  return Object.freeze({ ...document, preregistration_digest: preregistrationDigest(document) });
}

/**
 * The digest of the preregistration document. This is the value that must be
 * RECORDED BEFORE TRIAL ONE and that a post-result edit has to move: a
 * rewritten `test_design` keeps `card_id` and still satisfies the frozen card
 * schema, so this digest — which covers `card_digest` — is the only thing that
 * can catch the rewrite (P3).
 *
 * DELEGATES, it does not re-project. The earlier version of this function
 * spelled out ELEVEN members and omitted `budget_reservation`, so a post-result
 * budget edit was invisible to the fixture's own seal while the track's
 * twelve-member digest moved (finding S2-008-SD-08). A second projection of the
 * same rule is a second answer to "what is covered", and the two disagreed.
 * @param {object} prereg A document from `buildPreregistration`.
 * @returns {string} 64 lowercase hex characters, from the track's own
 *   `preregistrationDigest`.
 */
export function preregistrationFixtureDigest(prereg) {
  return preregistrationDigest(prereg);
}
