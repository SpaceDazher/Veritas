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
// `designed_outcome` is the fixture's DESIGN INTENT and it is the value the
// FROZEN TABLE carries in `expectedOutcome`
// (`src/lib/research/expected-values.mjs`). It is NOT an observation, and it is
// not derivable from the interval: with eight cases a 95% Wilson interval on
// 7/8, 6/8 and 5/8 all straddle the frozen baseline, so `decisionFromInterval`
// derives UNRESOLVED for all three (measured, see the `derived_outcome` and
// `derived_disagreements` blocks in `fixture-measurement-set.mjs`, which record
// that instead of hiding it). The fixture therefore pins TWO different things
// and names both: the DESIGN the table scores against, and the decision the
// frozen rule actually derives from the interval it computes. Collapsing them
// into one name is how a fixture ends up asserting that whatever came out was
// expected.
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
  if (typeof holdoutUnsealDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(holdoutUnsealDigest)) {
    throw new Error(`FIXTURE_PREREGISTRATION_INPUT_INVALID: holdoutUnsealDigest must be sha256:<64 hex>, got ${String(holdoutUnsealDigest)}`);
  }
  const measuredTrials = PREREGISTERED_TRIALS.filter((entry) => entry.designed_outcome !== 'INFRA');
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
      confidence: 0.95,
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
      alpha: 0.05,
      confidence: 0.95,
      // R6: the correction runs over the DECLARED family of TRIAL IDS, and
      // every one of them is in `trial_list`. `assertMultiplicityRule` refuses
      // a comparison that is not a declared trial, so the family cannot be
      // "the comparisons that happened to be significant".
      declared_comparisons: Object.freeze(measuredTrials.map((entry) => entry.trial)),
      family_size: measuredTrials.length,
      // The direction the hypothesis expects, frozen HERE so the comparator
      // reads a preregistered direction rather than a default (finding
      // S2-008-SD-04: the direction was never in any document, so a real
      // improvement could be scored as the wrong answer).
      direction: 'increase',
      // The infra trial is excluded from the multiplicity family with a
      // reason. Excluded is not dropped: it still has a table row and its row
      // says VIOLATION.
      excluded: Object.freeze([
        Object.freeze({ trial: 'trl-s2-008-04', reason: 'INFRA_OUTCOME_NO_INTERVAL_TO_CORRECT' }),
      ]),
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
    expected_table_digest: expectedTableDigest(),
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
