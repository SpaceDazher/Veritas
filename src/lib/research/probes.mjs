// S2-008 research track — the SIX NEGATIVE PROBES (issue SpaceDazher/Veritas#8).
//
// WHAT THIS MODULE IS: six attacks against the S2-008 research boundary, each
// paired with a negative control that MUST flip a verdict, plus the recorder
// that turns a probe into a fact. It is the only place in the track where a
// defence is deliberately attacked.
//
// WHAT IT IS NOT: it is not a second verdict layer, not a second validation
// path and not a test file. Every verdict inside a probe result is produced by
// `resolveTrialVerdict` (comparator.mjs) or by a refusal thrown by a guard in
// registry.mjs / dataset.mjs / causality.mjs / preregistration.mjs /
// contracts.mjs. This file decides nothing on its own; it records what those
// modules decided. A probe that computed its own verdict would keep passing
// after the real boundary was rewired, which is the exact failure this file
// exists to prevent.
//
// Serves A1 (all six negative probes are covered) and the fail-closed halves of
// A2, A4 and A5:
//
//   P1 peeking a holdout                      -> counter `holdoutPeek`
//   P2 substituting the best seed              -> counter `seedSubstitution`
//   P3 rewriting a hypothesis after the result -> counter `hypothesisRewrite`
//   P4 opaque budget                           -> counter `budgetOpacity`
//   P5 claiming causal proof from a simulation -> counter `causalUpgrade`
//   P6 a missing evaluator                     -> counter `missingEvaluator`
//
// A counter moves ONLY when the attack SUCCEEDED. Every counter must be 0 at
// the end of a clean run, and a non-zero counter is a failure, not a limit.
//
// FOUR STATES, NOT TWO. `result()` returns 'pass' | 'failed' | 'broken' |
// 'not_run'. 'failed' is a discovered bypass: the counter moves, a hard gate.
// 'broken' is a probe whose CONTROL did not flip the verdict: nothing got
// through, so the counter must NOT move, and the probe must not pass either —
// the defence is UNPROVEN, which is a different state from a proven defence.
// 'not_run' is a probe that could not run (missing dependency, absent fixture, a
// bundled fixture that fails its own frozen contract): never a pass, never
// counted, and the harness exits 3 rather than 0. A failed control-flip fact is
// recognised by the recorded label prefix `control_flips: ` (CONTROL_CHECK_PREFIX
// below), and that prefix sits in the evidence record, so a reader can see WHY a
// probe was called broken.
//
// EVERY PROBE DRIVES THE PUBLIC SURFACE. registry.mjs, dataset.mjs,
// causality.mjs, preregistration.mjs, comparator.mjs and contracts.mjs are the
// only modules a probe calls: no test-only shortcut into an implementation
// detail, no reaching into another worker's private helper.
//
// THE COORDINATION CONTRACT (read this before changing a sibling module). The
// interface index freezes sibling SIGNATURES, not the inner field names of a
// trial binding or of a bundled fixture, so each dependency lives in ONE place:
//   * FIXTURE_TRIAL — the minimal trial: `status` plus the four bindings named
//     in comparator.mjs's JSDoc. A caller may inject `ctx.trial`.
//   * CONTROL_MUTATIONS — the built-in control mutations, one per COMPARATOR
//     control id, each commented with the binding field it relies on. A caller
//     may inject `ctx.controlMutations[controlId]`, and the record then carries
//     `control_mutation_source: 'ctx'`, so an injected mutation can never
//     masquerade as the built-in one. If a comparator needs a different field
//     name this is the single place to change it — and the control MUST still
//     flip, or the probe reports 'broken'.
//   * FIXTURE_CARD / FIXTURE_CALIBRATION_* — bundled fixtures, each validated
//     against its FROZEN contract through `assertResearchContract` before any
//     probe uses it. A fixture that cannot pass its own contract yields
//     not_run, never a pass. A caller may inject `ctx.card` / `ctx.calibration`.
// P3 and P5 have NO trial-binding carrier in the frozen trial shape, so their
// controls are GUARD-level (`ADMITTED` -> `REFUSED`) and are built in the probe
// body; P1, P2, P4 and P6 are COMPARATOR-level (`ALLOW` -> `VIOLATION`). Both
// kinds are controls: one that does not flip is 'broken' either way.
//
// GATED vs RECORDED. `check` is a ticket property: every gated fact below is
// something the issue or the acceptance items state, so a failure is
// actionable. `note` is an observation, recorded and NOT gated, and every such
// observation is prefixed `observed_` so a reader sees at a glance what is not
// being asserted. Nothing that could hide a fail-open is left as a bare note.
//
// FIXTURES ARE PURGED BEFORE EVERY RUN. `purgeProbeFixtures` is this module's
// equivalent of the board's `purgeProbeFixtures` (src/lib/agentboard/probes.mjs:
// 172). It removes ONLY the six `<base>/<family>/<probe>` directories named in
// the frozen tables under a structurally checked base, and `createWorld` also
// calls the ledger's own idempotent `purgeRegistry`. A repeat run therefore
// fails on the property and not on its own leftovers: deterministic ids are what
// make the record comparable, and they are exactly what a leftover destroys.
//
// NO CLOCK, NO RANDOMNESS, NO NETWORK. `Date.now()`, `Math.random()` and an
// argument-less `new Date()` appear nowhere here; `Date.parse` is applied to a
// LITERAL instant, which parses and does not read a clock. The clock and the id
// factory are INJECTED, and the bundled defaults are a FIXED clock that never
// advances plus a slug-scoped counter, so ordering inside a probe is proved by
// the ledger's chain position and never by elapsed time.
//
// NO SECRETS. Refusal messages go through `redact` from
// src/lib/agentboard/errors.mjs and are bounded; the record names variable
// names and locations only.
//
// Owner: W4 (policy, probes, harness). Budget: part of W4's <= 1,100 lines.
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';

import { canonicalDigest, canonicalize } from '../verifier/canonical-json.mjs';
import { BlockedPolicy, isBoardError, redact } from '../agentboard/errors.mjs';
import { openRegistry, purgeRegistry, putExperiment, readJournal, recordHoldoutRead, recordSpend, snapshotDigest, verifyChain } from './registry.mjs';
import { readCorpus } from './dataset.mjs';
import { assertCausalDiscipline, assertNoCausalFromSimulation, classifyCardRelation } from './causality.mjs';
import { resolveTrialVerdict, assertEvaluatorPresent } from './comparator.mjs';
import {
  PREREGISTRATION_KIND, assertBudgetReservation, assertNoPostResultRewrite,
  assertAmendmentNotDecisionBasis, assertPreregistration, assertSeedSetFrozen,
  createAmendment, loadPreregistration, preregistrationDigest,
} from './preregistration.mjs';
import { assertResearchContract } from './contracts.mjs';

/**
 * The version string of the probe surface.
 * @type {string}
 */
export const PROBES_VERSION = 's2-008-probes-v1';

/**
 * The six mandatory probe families, in the frozen review order (P1..P6).
 * @type {ReadonlyArray<string>} exactly six members, one per P1..P6.
 */
export const PROBE_FAMILIES = Object.freeze([
  'holdout_peek', 'seed_substitution', 'hypothesis_rewrite',
  'budget_opacity', 'causal_upgrade', 'missing_evaluator',
]);

/**
 * The frozen probe name table: family -> the probe names inside it. Mirrors the
 * shape of `PROBE_NAMES` at src/lib/agentboard/probes.mjs:2541. Exactly SIX
 * probes in total, one per family, because the ticket names six and a seventh
 * name would be an invitation to quietly skip one of them.
 * @type {Readonly<Record<string, ReadonlyArray<string>>>}
 */
export const PROBE_NAMES = Object.freeze({
  holdout_peek: Object.freeze(['holdout_read_before_decision_point']),
  seed_substitution: Object.freeze(['best_seed_reported_instead_of_the_preregistered_set']),
  hypothesis_rewrite: Object.freeze(['test_design_edited_after_the_result']),
  budget_opacity: Object.freeze(['spend_beyond_the_reservation']),
  causal_upgrade: Object.freeze(['observational_label_swapped_to_causal']),
  missing_evaluator: Object.freeze(['evaluator_removed_between_reservation_and_comparison']),
});

/**
 * The hard-gate counters, one per probe edge. Every counter must be 0 at the
 * end of a clean run. Mirrors `HARD_GATE_COUNTERS` at
 * src/lib/agentboard/probes.mjs:99 in role and shape.
 * @type {ReadonlyArray<string>} ['holdoutPeek','seedSubstitution',
 *   'hypothesisRewrite','budgetOpacity','causalUpgrade','missingEvaluator']
 */
export const HARD_GATE_COUNTERS = Object.freeze([
  'holdoutPeek', 'seedSubstitution', 'hypothesisRewrite',
  'budgetOpacity', 'causalUpgrade', 'missingEvaluator',
]);

// --- private: the frozen instants, ids and the recognised label prefix ------

/** The fixed "now" every probe runs at. A literal, never a clock read. */
const PROBE_INSTANT = '2026-09-26T00:00:00.000Z';
/** Strictly after PROBE_INSTANT, and past the bundled reservation's expiry. */
const PROBE_LATER = '2026-09-27T00:00:00.000Z';
/** Strictly AFTER `PROBE_LATER`, which is what the ledger's own expiry guard
 *  reads: `recordSpend` refuses when `clock.ns > expires_at`, so a clock AT the
 *  expiry instant is still live and cannot demonstrate the reconciliation. */
const PROBE_AFTER_EXPIRY = '2026-09-28T00:00:00.000Z';
/** A digest no preregistration can name: a forged one-shot unseal digest, in
 * the ledger's BARE 64-hex form (recordHoldoutRead refuses anything else, so
 * the probe uses the stricter of the two spellings). */
const PROBE_FORGED_UNSEAL_DIGEST = '0'.repeat(64);
/** A second bare 64-hex digest, also naming nothing, used to reach the
 *  per-partition OPEN BUDGET without re-presenting a digest the ledger has
 *  already spent. */
const PROBE_SECOND_FORGED_UNSEAL_DIGEST = '1'.repeat(64);
/** The seed a cherry-picking report would name. The probe cannot know which
 * seed is actually best, and pretending to know would be the bug under test. */
const PROBE_BEST_SEED = 4242;
const PROBE_PREREGISTERED_SEEDS = Object.freeze([11, 22, 33, 44]);
/** The test_design a post-result rewrite installs. The card_id is unchanged. */
const PROBE_REWRITTEN_DESIGN = 'REWRITTEN AFTER THE RESULT: report the best seed only.';
/** The recognised prefix of a control-flip fact. See the header. */
const CONTROL_CHECK_PREFIX = 'control_flips: ';
/** The id prefix per record kind, taken from the frozen LOCAL vocabulary in
 * constants.mjs (RESEARCH_ID_PREFIXES). A probe never invents a prefix. */
const PROBE_PREFIX_KIND = Object.freeze({
  access: 'rec', audit: 'aud', reconciliation: 'rec', experiment: 'xpr',
  trial: 'trl', reservation: 'rsv', spend: 'rsc', comparison: 'cmp',
  card: 'hyc', amendment: 'amd',
});
/** What an unknown record `kind` falls back to. */
const PROBE_FALLBACK_PREFIX = 'xpr';
/** The default scratch parent, relative to the caller's cwd. */
// E2: the default scratch base is under `.bb/`, which `.gitignore` already
// covers, instead of `results/s2-008/`, which it does not. The old default
// wrote this track's own residue into an UNTRACKED directory, so it reappeared
// in `git status` on every run and could never be told apart from a
// deliberate artefact. The committed evidence of a run belongs in
// `evidence/s2-008/`, which is tracked; scratch belongs in neither.
const PROBE_DEFAULT_SCRATCH = path.join('.bb', 's2-008', 'probe-scratch');
/** A path segment the purge refuses to touch, whatever the caller passed. */
const PROBE_FORBIDDEN_SEGMENTS = Object.freeze([
  'contracts', 'src', 'evidence', 'scripts', 'tests', 'corpus', 'docs',
  'node_modules', '.git', '.next', 'public', 'patches', 'pilots',
]);

// --- private: the bundled fixtures (all validated before use) ---------------

/** The minimal trial: `status` plus the four bindings named in comparator.mjs.
 * This is the surface a control mutates, so a comparator that needs a fifth
 * field must be handed `ctx.trial` — and a control that then does not flip
 * reports 'broken', loudly. */
const FIXTURE_TRIAL = Object.freeze({
  trial: 'trl-s2-008-probe',
  status: 'RESOLVED',
  seedBinding: Object.freeze({
    seeds: PROBE_PREREGISTERED_SEEDS,
    seeds_digest: canonicalDigest({ seeds: PROBE_PREREGISTERED_SEEDS }),
    source: 'PREREGISTERED',
  }),
  holdoutBinding: Object.freeze({
    partition: 'HOLDOUT', read_at: PROBE_INSTANT, decision_at: PROBE_INSTANT,
    opened_before_decision_point: false,
  }),
  budgetBinding: Object.freeze({
    reservation_id: 'rsv-s2-008-probe', granted_units: 100, spent_units: 40, currency: 'UNITS',
  }),
  evaluatorBinding: Object.freeze({
    evaluator_id: 'evl-s2-008-probe', independent: true, blind_to_producer: true,
  }),
  outcome: 'POSITIVE',
  // A trial that `metricsSummary` can aggregate: the metric NAME is what the
  // aggregation refuses to do without (S2-008-SD-01), and the probes are the
  // one place a trial is built by hand rather than by the runner.
  metric: 'case_agreement_rate',
  numerator: 7,
  denominator: 8,
});

/** The bundled budget reservation, in the five-field shape preregistration.mjs
 * documents: live at PROBE_INSTANT, expired at PROBE_LATER. */
const FIXTURE_RESERVATION = Object.freeze({
  reservation_id: 'rsv-s2-008-probe',
  granted_units: 100,
  spent_units: 0,
  expires_at: PROBE_LATER,
  currency: 'UNITS',
});

/** A hypothesis card whose ground truth is OBSERVATIONAL and which claims no
 * causal relation. Validated against contracts/hypothesis-card.schema.json
 * before any probe touches it. */
const FIXTURE_CARD = Object.freeze({
  contractVersion: '1.0.0',
  card_id: 'hyc-s2-008-probe-observational',
  card_type: 'OBSERVATION',
  type_promotion: null,
  originating_domains: ['deterministic-harness', 'research-governance'],
  nodes: [
    { claim_id: 'clm-s2-008-source', revision: 1, domain: 'deterministic-harness', role: 'source' },
    { claim_id: 'clm-s2-008-target', revision: 1, domain: 'research-governance', role: 'target' },
  ],
  proposed_relation: {
    subject: 'the six negative probes',
    predicate: 'are recorded before',
    object: 'the campaign verdict is named',
    relation_strength: 'CORRELATION_EVIDENCE',
    causal_assertion: null,
  },
  confounders: [
    { description: 'probe fixtures left behind by an earlier run', status: 'RULED_OUT', claim_id: 'clm-s2-008-source' },
  ],
  alternative_explanations: [
    { description: 'the journal order coincides with the harness order by construction', claim_id: null },
  ],
  scope: {
    population: 'the S2-008 offline deterministic transport',
    geography: null, period: null, units: null,
    domain_limits: ['no real adapter is in scope: nothing here shows that a campaign improves a metric'],
  },
  assumptions: ['the registry journal is append-only'],
  falsifiers: [{ description: 'a probe that cannot run still reports pass', observable: 'the probe report status' }],
  test_design: 'PREREGISTERED: run all six probes on a purged registry root and compare the report field by field.',
  counterevidence: [{ claim_id: 'clm-s2-008-target', relation: 'bounds' }],
  novelty: { assessment: 'NOT_ASSESSED', corpus: null, search_horizon: null, similar_prior_refs: [] },
  uncertainty: { author_confidence: null, expert_trust: null, measured_calibration: null, evidence_support: 0 },
  stale: { is_stale: false, invalidation_event_ids: [], stale_claim_ids: [] },
  status: 'FRESH',
  created_at: PROBE_INSTANT,
  created_by: 's2-008-probes',
});

/** The calibration record, in the frozen shape, with `blind_to_producer` as the
 * only difference between the two bundled records. `status` is NOT_MEASURED
 * with `outcome_not_defined` on purpose: the closed S2-004 metric enum has no
 * S2-008 slot, and a fixture that pretended otherwise would be fabricating a
 * measurement this track never made. */
const bundledCalibration = (blind) => ({
  contractVersion: '1.0.0',
  calibration_id: 'cal-s2-008-probe',
  corpus_version: '0.0.0',
  corpus_sha256: '0'.repeat(64),
  outcome_definition: {
    metric: 'extraction_accuracy',
    threshold: 0.5,
    description: 'S2-008 probe fixture: the closed S2-004 metric enum has no S2-008 slot, so this record is NOT_MEASURED and decides nothing.',
  },
  numerator: 0,
  denominator: 1,
  missing_count: 0,
  uncertainty: { method: 'wilson', confidence_interval: { lower: 0, upper: 1, confidence_level: 0.95 } },
  evaluator_independence: { independent_evaluators: 1, blind_to_producer: blind, separate_processes: true },
  status: 'NOT_MEASURED',
  // BOTH records carry `outcome_not_defined`, and that is the correction behind
  // PR8 in this file's own fixture: the "independent" record claimed
  // `evaluator_not_independent` while declaring an independent, blind
  // evaluator, so the two fields contradicted each other and a genuinely
  // independent evaluator was scored as a VIOLATION for a reason that had
  // nothing to do with independence. `blind_to_producer` is the only member
  // that varies here, and it is the member `assertEvaluatorPresent` reads.
  not_measured_reason: 'outcome_not_defined',
  measured_at: PROBE_INSTANT,
  measured_by: 'prn-s2-008-probes',
});
// The independent evaluator record the `missing_evaluator` control deletes,
// attached to the fixture trial AFTER both are defined. Without it
// `assertEvaluatorPresent` refuses the CLEAN trial, every control's "before"
// state would be VIOLATION, and no flip could be observed.
const FIXTURE_EVALUATOR = Object.freeze({
  evaluator_id: 'evl-s2-008-probe', independent: true, blind_to_producer: true,
});
const FIXTURE_CALIBRATION_INDEPENDENT = Object.freeze(bundledCalibration(true));
const FIXTURE_CALIBRATION_NOT_INDEPENDENT = Object.freeze(bundledCalibration(false));

/**
 * The ONE calibration a probe trial may be ALLOW against: independent, blind to
 * the producer, and MEASURED.
 *
 * Why a MEASURED one has to exist at all, stated rather than hidden: this
 * track's OWN delivered calibration is NOT_MEASURED — the frozen
 * `outcome_definition.metric` enum has no S2-008 slot, and fabricating a slot
 * would be inventing a measurement — and a NOT_MEASURED calibration makes every
 * trial a VIOLATION by the comparator's own rule. That rule is correct and is
 * NOT weakened here. Instead the comparator CONTROLS run against a MEASURED,
 * independent record, because a control can only demonstrate a flip if its
 * "before" state is a real ALLOW, and the campaign verdict below still reports
 * NOT_MEASURED honestly. The two facts are separate and both are recorded.
 */
const FIXTURE_CALIBRATION_MEASURED = Object.freeze({
  ...bundledCalibration(true),
  status: 'MEASURED',
  not_measured_reason: null,
  numerator: 6,
  denominator: 8,
  missing_count: 0,
  uncertainty: Object.freeze({ method: 'wilson', confidence_interval: Object.freeze({ lower: 0.5, upper: 0.9, confidence_level: 0.95 }) }),
});

// The minimal trial, COMPLETE: `trialFor` spreads this and the two members
// below are added here rather than inside the frozen literal, because the
// calibration constants are declared after it.
const FIXTURE_TRIAL_COMPLETE = Object.freeze({
  ...FIXTURE_TRIAL,
  evaluator: FIXTURE_EVALUATOR,
  calibration: FIXTURE_CALIBRATION_MEASURED,
});

// --- private: the frozen probe descriptors ---------------------------------
//
// One descriptor per probe, carrying the six fields the ticket requires of a
// probe: id, subject, expectation, the control it injects, the finding it
// produces and the verdict it forces. `runProbe` writes the descriptor into
// every record, so no probe record can omit one of them by accident.

const PROBE_SPECS = Object.freeze({
  holdout_read_before_decision_point: Object.freeze({
    id: 'P1', family: 'holdout_peek', counter: 'holdoutPeek',
    subject: 'readCorpus + the ledger ACCESS record (dataset.mjs, registry.mjs)',
    expectation: 'a HOLDOUT read before the trial\'s decision point, or with a forged or replayed unseal digest, is refused by a typed policy refusal and returns no case data',
    verdict: 'VIOLATION',
    finding: 'the refusal code, whether any case data escaped the refusal, and the journal state around it',
    control: Object.freeze({
      id: 'holdout_peek', mechanism: 'comparator', injects: 'a trial that opened the HOLDOUT before its decision point',
      mustFlipFrom: 'ALLOW', mustFlipTo: 'VIOLATION',
    }),
  }),
  best_seed_reported_instead_of_the_preregistered_set: Object.freeze({
    id: 'P2', family: 'seed_substitution', counter: 'seedSubstitution',
    subject: 'assertSeedSetFrozen (preregistration.mjs) + the trial seed binding',
    expectation: 'a seed set that is not the preregistered one is refused on every trial, so "the best seed" is never a statistic the verdict may use',
    verdict: 'VIOLATION',
    finding: 'the refusal codes and which preregistration field the seed set was read from',
    control: Object.freeze({
      id: 'seed_substitution', mechanism: 'comparator', injects: 'a report whose seed binding names only the best seed',
      mustFlipFrom: 'ALLOW', mustFlipTo: 'VIOLATION',
    }),
  }),
  test_design_edited_after_the_result: Object.freeze({
    id: 'P3', family: 'hypothesis_rewrite', counter: 'hypothesisRewrite',
    subject: 'assertNoPostResultRewrite + preregistrationDigest + createAmendment (preregistration.mjs)',
    expectation: 'a test_design edited after a result is refused, even though the card_id is unchanged and the frozen schema still accepts the document; the lawful path is a new AMENDMENT that is itself refused as a decision basis',
    verdict: 'VIOLATION',
    finding: 'the moved digest, the refusal codes, and that the rewrite is still contract-valid with the same card_id',
    control: Object.freeze({
      id: 'post_result_rewrite', mechanism: 'guard', injects: 'a frozen preregistration mutated after run 1',
      mustFlipFrom: 'ADMITTED', mustFlipTo: 'REFUSED',
    }),
  }),
  spend_beyond_the_reservation: Object.freeze({
    id: 'P4', family: 'budget_opacity', counter: 'budgetOpacity',
    subject: 'assertBudgetReservation + recordSpend (preregistration.mjs, registry.mjs)',
    expectation: 'a spend beyond the reservation is BudgetExceeded and leaves the ledger byte-identical; an expired reservation is a ReconciliationRequired, never a zero and never a silent release',
    verdict: 'VIOLATION',
    finding: 'the refusal codes and whether a refused spend changed the snapshot digest',
    control: Object.freeze({
      id: 'budget_opacity', mechanism: 'comparator', injects: 'a run whose spend exceeds the reservation',
      mustFlipFrom: 'ALLOW', mustFlipTo: 'VIOLATION',
    }),
  }),
  observational_label_swapped_to_causal: Object.freeze({
    id: 'P5', family: 'causal_upgrade', counter: 'causalUpgrade',
    subject: 'assertCausalDiscipline + assertNoCausalFromSimulation + classifyCardRelation (causality.mjs, contracts.mjs)',
    expectation: 'an observational card whose label is swapped to causal is refused by a policy refusal while the un-swapped card is admitted; the refusal must be the label guard and not a schema rejection',
    verdict: 'VIOLATION',
    finding: 'the refusal code, the classification of the swapped card, and that both cards satisfy the frozen contract',
    control: Object.freeze({
      id: 'label_substitution', mechanism: 'guard', injects: 'an observational label swapped to causal',
      mustFlipFrom: 'ADMITTED', mustFlipTo: 'REFUSED',
    }),
  }),
  evaluator_removed_between_reservation_and_comparison: Object.freeze({
    id: 'P6', family: 'missing_evaluator', counter: 'missingEvaluator',
    subject: 'assertEvaluatorPresent (comparator.mjs) + the trial evaluator binding',
    expectation: 'an absent or non-independent evaluator is refused, and the resulting NOT_MEASURED trial is a VIOLATION — never ALLOW and never a silent zero',
    verdict: 'VIOLATION',
    finding: 'the refusal codes and the verdict the NOT_MEASURED trial resolved to',
    control: Object.freeze({
      id: 'missing_evaluator', mechanism: 'comparator', injects: 'the evaluator removed between reservation and comparison',
      mustFlipFrom: 'ALLOW', mustFlipTo: 'VIOLATION',
    }),
  }),
});

/** family + counter for a probe name, or a refusal for an unknown one. */
function specOf(probe) {
  const spec = PROBE_SPECS[probe];
  if (spec === undefined) {
    throw new BlockedPolicy('UNKNOWN_PROBE', `no frozen probe is named ${String(probe)}`);
  }
  return spec;
}

// --- private: the purge (this module's purgeProbeFixtures) ------------------

/** A purge target that failed the safety check. A subclass so `runProbe` can
 * tell a caller MISCONFIGURATION (re-raised, it is a harness error) apart from
 * a missing dependency (recorded as not_run). */
class ScratchRootUnsafe extends BlockedPolicy {
  constructor(base) {
    super('PROBE_SCRATCH_ROOT_UNSAFE', `refusing to purge ${base}`);
    this.name = 'ScratchRootUnsafe';
  }
}

/**
 * The scratch base every probe world lives under. `ctx.registryRoot` decides
 * where; nothing else does, and the path never reaches a digest or a verdict.
 * The structural check runs before anything is ever removed.
 */
function probeScratchBase(ctx) {
  const raw = typeof ctx?.registryRoot === 'string' && ctx.registryRoot !== '' ? ctx.registryRoot : PROBE_DEFAULT_SCRATCH;
  const base = path.resolve(path.resolve(process.cwd(), raw), 'probes');
  const segments = base.split(path.sep).filter((part) => part !== '');
  const cwd = path.resolve(process.cwd());
  if (base === path.parse(base).root
    || segments.length < 3
    || base === cwd
    || path.dirname(base) === cwd
    || cwd.startsWith(`${base}${path.sep}`)
    || segments.some((part) => PROBE_FORBIDDEN_SEGMENTS.includes(part))) {
    // The purge also refuses a base whose PARENT is the repository root, so no
    // caller can make this module create or remove a directory there: a probe
    // that wrote into the checkout would be a probe that edited the repo.
    throw new ScratchRootUnsafe(base);
  }
  return base;
}

/** `<base>/<family>/<probe>` for one probe. */
function probeWorldRoot(ctx, family, probe) {
  return path.join(probeScratchBase(ctx), family, probe);
}

/**
 * Remove this module's OWN fixtures before a run, and nothing else. Bounded to
 * the six frozen family/probe directories under a structurally checked base;
 * the board precedent is `purgeProbeFixtures` at
 * src/lib/agentboard/probes.mjs:172. Idempotent: a second call on a clean tree
 * removes nothing and reports `removed: 0`.
 * @param {object} ctx The shared context (only `registryRoot` is read).
 * @returns {{base: string, removed: number, roots: ReadonlyArray<string>}}
 */
function purgeProbeFixtures(ctx) {
  const base = probeScratchBase(ctx);
  const roots = [];
  const removed = [];
  for (const family of PROBE_FAMILIES) {
    for (const probe of PROBE_NAMES[family]) {
      const target = path.join(base, family, probe);
      const relative = `${family}/${probe}`;
      // PR10 / E7: `removed` counted the FROZEN LIST, not the removals, so a
      // second run on a clean tree reported the same `removed: 6` as a first
      // run on a dirty one and the record could not distinguish "my residue is
      // gone" from "there was nothing there". It is now the number of roots
      // that EXISTED, and the full base is reported instead of
      // `path.basename(base)` so the record names where the purge happened.
      if (existsSync(target)) {
        rmSync(target, { recursive: true, force: true });
        removed.push(relative);
      }
      roots.push(relative);
    }
  }
  return {
    base,
    removed: removed.length,
    removed_roots: Object.freeze(removed),
    roots: Object.freeze(roots),
  };
}

// --- private: the injected clock and id factory ---------------------------

/** A fixed clock that never advances. `Date.parse` parses a literal; it does
 * not read a clock.
 *
 * `nowNs`/`iso` are the ONLY shape the ledger accepts: `openRegistry` refuses
 * anything else with `REGISTRY_CLOCK_NOT_INJECTED` (registry.mjs:288), and a
 * probe handed such a clock reports `not_run` / `PROBE_ABORTED` rather than
 * quietly falling back to the process clock. `now`/`nowIso` are the board's
 * aliases, offered so a board-shaped caller can reuse this clock where those
 * members are read — they are NOT a second accepted registry shape, and an
 * earlier version of this comment claimed exactly that. */
function probeFixedClock(iso) {
  if (typeof iso !== 'string' || !Number.isFinite(Date.parse(iso))) {
    throw new BlockedPolicy('PROBE_CLOCK_INVALID', String(iso));
  }
  const ms = Date.parse(iso);
  return Object.freeze({
    nowNs: () => ms * 1e6,
    iso: () => iso,
    now: () => new Date(ms),
    nowIso: () => iso,
  });
}

/** A slug-scoped deterministic id factory: two probes never mint the same id.
 * The prefix comes from the frozen local vocabulary in constants.mjs
 * (RESEARCH_ID_PREFIXES); an unknown `kind` falls back to the experiment
 * prefix rather than inventing one. */
function probeIdFactory(slug) {
  const scope = canonicalDigest({ slug }).slice(0, 8);
  const counters = new Map();
  return Object.freeze({
    next: (kind) => {
      const key = String(kind);
      const next = (counters.get(key) ?? 0) + 1;
      counters.set(key, next);
      const prefix = PROBE_PREFIX_KIND[key] ?? PROBE_FALLBACK_PREFIX;
      return `${prefix}-p${scope}${next.toString(36).padStart(4, '0')}`;
    },
  });
}

/** A deterministic idempotency key. The key is consulted before any read of
 * state, so a replayed write writes nothing; that is the ledger's property, and
 * the probe only has to produce the same key twice. */
function probeKey(slug, step) {
  return canonicalDigest({ slug, step });
}

// --- private: small helpers ------------------------------------------------

/** A missing dependency is a STATE, not an exception: it becomes not_run with
 * this code, never a pass. */
class DependencyMissing extends Error {
  constructor(dependency, reason) {
    super(`${dependency}: ${reason}`);
    this.name = 'DependencyMissing';
    this.dependency = dependency;
    this.reason = reason;
  }
}

/** Require a world dependency, or fail the probe honestly. */
function need(value, name, reason = 'not available in this world') {
  if (value === null || value === undefined) throw new DependencyMissing(name, reason);
  return value;
}

/** A plain-object test, used where this module reads a corpus index rather than
 *  a frozen fixture. */
function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * An escaped throw that is NOT a decision.
 *
 * A sibling body that is still a skeleton raises `Error('NOT_IMPLEMENTED:
 * <name>')` and an absent export raises a TypeError. Neither is a refusal and
 * neither is a bypass, so both are a MISSING DEPENDENCY. This distinction is
 * load-bearing: a probe that scored a NOT_IMPLEMENTED throw as a failed check
 * would write `counted: 1` into the evidence for a bypass that never happened,
 * and one that scored it as a refusal would be reporting a guard nobody wrote.
 * The message is parsed for the name so the record says WHICH module is missing.
 */
function isImplementationGap(error) {
  if (isBoardError(error)) return false;
  const message = String(error?.message ?? '');
  return message.startsWith('NOT_IMPLEMENTED')
    || error instanceof TypeError
    || error instanceof ReferenceError;
}

/** A refusal, as a bounded and redacted record. */
function refusedOutcome(error) {
  if (isImplementationGap(error)) {
    const named = /^NOT_IMPLEMENTED:\s*([A-Za-z0-9_.$]+)/.exec(String(error?.message ?? ''));
    throw new DependencyMissing(
      named === null ? 'sibling export' : named[1],
      `${String(error?.name ?? 'Error')}: ${redact(String(error?.message ?? error)).slice(0, 160)}`,
    );
  }
  return {
    refused: true,
    code: isBoardError(error) ? error.code : null,
    typed: isBoardError(error),
    message: redact(String(error?.message ?? error)).slice(0, 200),
    value: null,
    // A refusal is only a refusal if nothing escaped it: a caller that returned
    // case data on a refused read HAS leaked.
    leaked: false,
  };
}

/** A returned value, with the leak flag the holdout property needs. */
function returnedOutcome(value) {
  return {
    refused: false,
    code: null,
    typed: false,
    message: null,
    value,
    leaked: value !== null && typeof value === 'object'
      && (value.case !== undefined || value.labels !== undefined),
  };
}

/** Run something expected to refuse, for a SYNCHRONOUS frozen signature. */
function outcomeOf(attempt) {
  try {
    return returnedOutcome(attempt());
  } catch (error) {
    return refusedOutcome(error);
  }
}

/** The same, for an attempt that may be async. Awaiting a plain value is a
 * no-op, so this is correct for a sync signature today and an async one
 * tomorrow instead of silently wrong in the second case. */
async function refusalOf(attempt) {
  try {
    return returnedOutcome(await attempt());
  } catch (error) {
    return refusedOutcome(error);
  }
}

/** "refused with a typed policy refusal" — the shape every A1..A5 guard uses. */
function policyRefused(outcome) {
  return outcome.refused && outcome.typed && outcome.code === 'BLOCKED_POLICY';
}

/** A typed refusal with one specific code. */
function refusedWith(outcome, code) {
  return outcome.refused && outcome.typed && outcome.code === code;
}

/**
 * A typed POLICY refusal with one specific code. Every member of
 * `BlockedPolicy` carries the class-level code `BLOCKED_POLICY` and puts the
 * specific code in its message, so `refusedWith` cannot distinguish
 * `HOLDOUT_UNSEAL_DIGEST_REPLAYED` from `HOLDOUT_READ_BEFORE_DECISION_POINT`.
 * The probes that assert a NAMED reason (PR5) read the message.
 */
function refusedWithPolicy(outcome, code) {
  return outcome.refused && outcome.typed && outcome.code === 'BLOCKED_POLICY'
    && String(outcome.message ?? '') === code;
}

/** A bounded, redacted reason string for a recorded refusal. */
function reasonOf(outcome) {
  return `${outcome.typed ? outcome.code : 'UNTHROWN'}: ${String(outcome.message ?? 'no message').slice(0, 160)}`;
}

/** A canonical deep copy. Cloning through the canonical form guarantees the
 * copy shares no reference with the original (a control that mutated the clean
 * fixture would invalidate the run behind it) and refuses a non-canonical
 * value instead of silently mangling it. */
function copyOf(value) {
  return JSON.parse(canonicalize(value));
}

/** Validate a bundled fixture against a FROZEN contract before any probe uses
 * it. A fixture that cannot pass its own contract yields not_run, never a
 * pass: this is the difference between a proven refusal and a lucky one. */
function assertFixture(contract, fixture) {
  const outcome = outcomeOf(() => assertResearchContract(contract, fixture));
  if (outcome.refused) {
    throw new DependencyMissing(contract, `the bundled fixture does not satisfy the frozen contract (${reasonOf(outcome)})`);
  }
  return outcome.value;
}

/** The trial a control mutates: the injected one, or the bundled minimal one. */
function trialFor(ctx) {
  const injected = ctx?.trial;
  return injected === undefined || injected === null ? copyOf(FIXTURE_TRIAL_COMPLETE) : copyOf(injected);
}

/** The comparator's own verdict for a trial, or a recorded refusal. A trial the
 * comparator refuses to score is NOT an ALLOW and NOT a VIOLATION: the control
 * then fails to flip and the probe reports 'broken'. */
async function comparatorVerdict(trial) {
  const outcome = await refusalOf(() => resolveTrialVerdict(trial));
  if (outcome.refused) return { verdict: null, reasons: [String(outcome.message)], code: outcome.code };
  const reasons = Array.isArray(outcome.value?.reasons) ? outcome.value.reasons.map((r) => String(r)) : [];
  return { verdict: outcome.value?.verdict === undefined ? null : String(outcome.value.verdict), reasons, code: null };
}

/**
 * The built-in COMPARATOR control mutations, one per control id, and the ONE
 * place that encodes how a control reaches the comparator. Each entry's comment
 * names the field it relies on. `ctx.controlMutations` may replace any of
 * them; the record then says which source was used.
 *
 * THE CONVENTION, CORRECTED (PR4)
 * These mutations used to state the violation TWICE: once semantically
 * (`spent_units`, `seeds`, `opened_before_decision_point`) and once by setting
 * `bound: false` — and the comparator read ONLY the flag, because a binding was
 * scored on presence plus a whitelist of self-declared booleans. The controls
 * therefore proved that the flag was read, not that the property held: with
 * `bound: false` stripped, holdout_peek, seed_substitution and budget_opacity
 * were all `ALLOW`. The flags are kept, because a binding that declares
 * `bound: false` IS unsatisfied and saying so is honest, but the SEMANTIC
 * content is what `BINDING_CHECKS` in comparator.mjs now reads, and the three
 * mutations below are exactly the content each checker looks for:
 *   * holdout_peek  -> `read_at` earlier than `decision_at`, and the flag;
 *   * seed_substitution -> a seed set that is not the preregistered one;
 *   * budget_opacity -> `spent_units` above `granted_units`.
 * `missing_evaluator` keeps deleting the binding, because deletion genuinely
 * fails the presence test and that is the property P6 asks for.
 */
const CONTROL_MUTATIONS = Object.freeze({
  // `holdoutBinding`: the read is admitted as happening BEFORE the decision.
  holdout_peek: (trial) => ({
    ...trial,
    holdoutBinding: {
      ...trial.holdoutBinding,
      partition: 'HOLDOUT',
      read_at: PROBE_INSTANT, decision_at: PROBE_LATER,
      opened_before_decision_point: true, opens: 1, max_opens: 1,
      bound: false, reason: 'HOLDOUT_OPENED_BEFORE_DECISION_POINT',
    },
  }),
  // `seedBinding`: the report names the best seed alone, not the frozen set.
  seed_substitution: (trial) => ({
    ...trial,
    seedBinding: {
      ...trial.seedBinding, seeds: [PROBE_BEST_SEED], source: 'BEST_ONLY',
      preregistered_seeds: [...PROBE_PREREGISTERED_SEEDS],
      seeds_digest: canonicalDigest({ seeds: [PROBE_BEST_SEED] }),
      bound: false, reason: 'SEED_SET_NOT_PREREGISTERED',
    },
  }),
  // `budgetBinding`: the spend is above the granted reservation.
  budget_opacity: (trial) => ({
    ...trial,
    budgetBinding: {
      ...trial.budgetBinding,
      reservation_id: 'rsv-s2-008-probe',
      granted_units: 100, spent_units: 400, currency: 'UNITS',
      bound: false, reason: 'SPEND_EXCEEDS_RESERVATION',
    },
  }),
  // `evaluatorBinding`: simply GONE — the ticket's P6 control verbatim.
  missing_evaluator: (trial) => {
    const copy = { ...trial };
    delete copy.evaluatorBinding;
    delete copy.evaluator;
    delete copy.calibration;
    return copy;
  },
});

/** The mutation to inject for a comparator control, and where it came from. */
function controlMutation(ctx, controlId) {
  const injected = ctx?.controlMutations?.[controlId];
  if (typeof injected === 'function') return { mutate: injected, source: 'ctx' };
  const mutate = CONTROL_MUTATIONS[controlId];
  if (typeof mutate !== 'function') {
    throw new DependencyMissing(`control:${controlId}`, 'no built-in control mutation exists for this control');
  }
  return { mutate, source: 'built_in' };
}

/** Whether a caller replaced a guard-level control's injection. */
function controlSource(ctx, controlId) {
  return typeof ctx?.controlMutations?.[controlId] === 'function' ? 'ctx' : 'built_in';
}

/**
 * Record the control block and the control-flip fact. `before` and `after` are
 * short state strings ('ALLOW'/'VIOLATION' for a comparator control,
 * 'ADMITTED'/'REFUSED' for a guard control). A control is a control only if it
 * flips, which is why the fact is recorded with the `control_flips: ` label
 * prefix `result()` looks for.
 */
function expectControlFlip(r, spec, { before, after, source, detail = '' }) {
  const control = spec.control;
  const flipped = before === control.mustFlipFrom && after === control.mustFlipTo;
  r.note('control', {
    id: control.id,
    mechanism: control.mechanism,
    injects: control.injects,
    mutation_source: source,
    before,
    after,
    must_flip_to: control.mustFlipTo,
    flipped,
  });
  r.check(
    `${CONTROL_CHECK_PREFIX}${control.id} flips ${before} -> ${after}`,
    flipped,
    detail === '' ? `expected ${control.mustFlipFrom} -> ${control.mustFlipTo}` : detail,
  );
  return flipped;
}

/** The COMPARATOR-level control: mutate one binding of a clean trial and
 * require the trial verdict to flip ALLOW -> VIOLATION. */
async function comparatorControl(r, ctx, spec) {
  const { mutate, source } = controlMutation(ctx, spec.control.id);
  const clean = trialFor(ctx);
  const before = await comparatorVerdict(clean);
  const after = await comparatorVerdict(mutate(copyOf(clean)));
  r.note('observed_baseline_trial', {
    trial: clean.trial, status: clean.status, verdict: before.verdict, reasons: before.reasons,
  });
  if (before.code !== null || after.code !== null) {
    r.note('observed_comparator_refusal', { before: before.code, after: after.code });
  }
  return expectControlFlip(r, spec, {
    before: before.verdict ?? `REFUSED:${before.code ?? 'UNKNOWN'}`,
    after: after.verdict ?? `REFUSED:${after.code ?? 'UNKNOWN'}`,
    source,
    detail: `reasons after injection: ${after.reasons.join('; ') || 'none named'}`,
  });
}

/** A bounded, redacted summary of the ledger — recorded, never gated. */
async function journalFact(registry) {
  const read = await refusalOf(() => readJournal(registry));
  const chain = await refusalOf(() => verifyChain(registry));
  return {
    readable: read.refused === false,
    records: read.refused === false && Array.isArray(read.value) ? read.value.length : null,
    chain_ok: chain.refused === false ? Boolean(chain.value?.ok) : null,
    first_refusal: read.refused ? reasonOf(read) : null,
  };
}

// --- public: the world -----------------------------------------------------

/**
 * A fresh, isolated world for ONE probe: a fresh registry root, a fresh
 * deterministic id factory, a fresh fixed clock and a dataset HANDLE. Nothing
 * is shared with any other probe and nothing is read from the process clock.
 * Every deterministic id is scoped by the run's label + step.
 *
 * `clock` and `ids` keep their frozen meaning. Four further OPTIONAL keys are
 * accepted, because a world is a fixture loader and none of them is a decision
 * input: `registryRoot` (the scratch base), `corpusDir` (where
 * `loadPreregistration` reads from), `caseId` (which PRIMARY case a probe reads
 * through `readCorpus`) and `seed` (the id-factory seed).
 *
 * @param {string} family A member of PROBE_FAMILIES.
 * @param {string} probe The probe name inside that family.
 * @param {{clock: object, ids: object, registryRoot?: string, corpusDir?: string,
 *   caseId?: string, seed?: number}} options
 * @param {object} [options.clock] The INJECTED fixed clock, which must supply
 *   `nowNs()` and `iso()` because `openRegistry` refuses any other shape
 *   (`REGISTRY_CLOCK_NOT_INJECTED` -> the probe reports `not_run`, never a
 *   process-clock default). `Date.now()` is never called by this module.
 *   Defaults to a FIXED clock at PROBE_INSTANT when absent, and the world
 *   records `clock_source` so a reader can tell.
 * @param {object} [options.ids] The deterministic id factory. Defaults to a
 *   slug-scoped counter, and the world records `id_source`.
 * @returns {{family: string, probe: string, registry: object, root: string,
 *   clock: object, ids: object, dataset: object, preregistration: object}}
 *   A world in which exactly one probe can act. `preregistration` is null and
 *   `deferred.preregistration` says why when the corpus is not readable yet, and
 *   a probe that needs it records not_run rather than passing. The object also
 *   carries `slug`, `key`, `purged`, `clock_source`, `id_source` and
 *   `deferred`: all evidence, none of them a decision input.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy} when the family or
 *   probe is not in the frozen tables, or the scratch root fails the safety check.
 */
export function createWorld(family, probe, { clock, ids, registryRoot, corpusDir, caseId, seed = 0 } = {}) {
  specOf(probe);
  if (!PROBE_FAMILIES.includes(family) || !PROBE_NAMES[family].includes(probe)) {
    throw new BlockedPolicy('UNKNOWN_PROBE_FAMILY', `${String(family)}/${String(probe)} is not a frozen family/probe pair`);
  }
  const ctx = { registryRoot, corpusDir, caseId };
  const root = probeWorldRoot(ctx, family, probe);
  mkdirSync(root, { recursive: true });
  const worldClock = clock ?? probeFixedClock(PROBE_INSTANT);
  const worldIds = ids ?? probeIdFactory(`${family}-${probe}-${String(seed)}`);
  const registry = openRegistry({ root, clock: worldClock, ids: worldIds });
  // The ledger's OWN idempotent purge, after the directory purge above: a
  // second purge is a no-op and leaves the snapshot digest unchanged.
  const purged = outcomeOf(() => purgeRegistry(registry));

  const world = {
    family,
    probe,
    registry,
    root,
    clock: worldClock,
    ids: worldIds,
    clock_source: clock === undefined ? 'probe_default_fixed' : 'injected',
    id_source: ids === undefined ? 'probe_default_slug_scoped' : 'injected',
    slug: `${family}-${probe}`,
    key: (step) => probeKey(`${family}-${probe}`, step),
    purged,
    dataset: { corpusDir: corpusDir ?? null, caseId: caseId ?? null, source: 'handle_only' },
    preregistration: null,
    deferred: purged.refused ? { purge: reasonOf(purged) } : {},
  };
  // The preregistration is loaded TOLERANTLY: a track whose corpus is not
  // written yet must still run and report honestly WHICH probes were not run
  // and why. It is never defaulted to a hand-built object.
  if (corpusDir === undefined || corpusDir === null) {
    world.deferred.preregistration = 'no corpusDir was supplied';
  } else {
    const loaded = outcomeOf(() => loadPreregistration(corpusDir));
    if (loaded.refused) {
      world.deferred.preregistration = reasonOf(loaded);
    } else {
      world.preregistration = loaded.value;
    }
  }
  return world;
}

/** Resolve the PRIMARY case id a probe reads: injected, else the first case id
 * in the corpus index file. Reading that file is to learn an ID and never to
 * read case CONTENT — the only supported way to read content is `readCorpus`,
 * and a probe that hand-assembled a dataset would bypass the access log. */
function resolveCaseId(ctx, world) {
  for (const candidate of [ctx?.caseId, world?.dataset?.caseId, ctx?.dataset?.caseId]) {
    if (typeof candidate === 'string' && candidate !== '') return { caseId: candidate, source: 'injected' };
  }
  const dir = ctx?.corpusDir ?? world?.dataset?.corpusDir ?? null;
  if (dir === null) return { caseId: null, source: 'none' };
  const outcome = outcomeOf(() => {
    const parsed = JSON.parse(readFileSync(path.join(dir, 'cases', 'dev.json'), 'utf8'));
    const cases = Array.isArray(parsed) ? parsed : (Array.isArray(parsed?.cases) ? parsed.cases : []);
    const first = cases[0] ?? null;
    return String(first?.case_id ?? first?.id ?? '');
  });
  if (outcome.refused || outcome.value === '') return { caseId: null, source: 'unreadable' };
  return { caseId: outcome.value, source: 'corpus_index' };
}

// --- the six probe bodies --------------------------------------------------
//
// Each body records facts through the recorder and returns `r.result()`. A body
// NEVER throws to signal a refusal: a refusal is a recorded fact, and a throw
// that aborts a probe would hide the counter move.

// P1 — peeking a holdout. Serves A1/P1 and the holdout half of A2.
async function probeHoldoutPeek(ctx, r) {
  const world = ctx.world;
  const registry = need(world.registry, 'registry.openRegistry');
  const { caseId, source } = resolveCaseId(ctx, world);
  r.note('observed_case_id_source', source);
  need(caseId, 'corpus:PRIMARY case id', 'no PRIMARY case id is available to read through readCorpus');
  const read = { partition: 'HOLDOUT', caseId, unsealDigest: PROBE_FORGED_UNSEAL_DIGEST };

  const forged = await refusalOf(() => readCorpus(registry, copyOf(read)));
  r.check('a HOLDOUT read presenting a forged unseal digest is refused by a typed policy refusal',
    policyRefused(forged), `code=${forged.code ?? 'none'} typed=${String(forged.typed)}`);
  r.check('a refused HOLDOUT read returns no case data', forged.leaked === false, `leaked=${String(forged.leaked)}`);

  // PR5: the REPLAY, on the digest that was really spent. Both reads above (and
  // before this line) presented `PROBE_FORGED_UNSEAL_DIGEST`, so
  // `readCorpus` refused them with HOLDOUT_UNSEAL_DIGEST_FORGED and
  // `recordHoldoutRead` was NEVER REACHED: the probe's "a replayed HOLDOUT read
  // is refused" was really a second statement about a FORGED digest, and the
  // committed evidence recorded `code=BLOCKED_POLICY` with no reason named. The
  // first read below uses the PREREGISTERED one-shot digest, so an ACCESS row is
  // committed; the second presents that same digest for a DIFFERENT trial, which
  // is the replay the ledger's own guard is there to catch, and the probe
  // asserts the NAMED reason.
  const access = need(world.preregistration?.holdout_access, 'preregistration.holdout_access', world.deferred.preregistration ?? 'the corpus publishes no holdout access block');
  const unsealDigest = need(access.unseal_digest, 'preregistration.holdout_access.unseal_digest', 'no one-shot unseal digest is published');
  const secondCaseId = await secondHoldoutCaseId(ctx, caseId);
  need(secondCaseId, 'corpus:HOLDOUT second case id', 'the HOLDOUT partition holds fewer than two cases, so a replay cannot be told from a second read');
  // The decision point is THIS WORLD'S OWN INSTANT, not a literal baked into
  // this file: a probe may be run under an INJECTED clock, and a hard-coded
  // decision point turns every legitimate read into an early one. The early
  // read is measured separately, below, against a point strictly in the future
  // of the same clock — so the rule is exercised without depending on which
  // clock the caller injected.
  const decisionPoint = world.clock.iso();
  const futureDecisionPoint = new Date(Date.parse(decisionPoint) + 3_600_000).toISOString();
  const early = await refusalOf(() => readCorpus(freshRegistry(ctx, 'holdout-early'), {
    partition: 'HOLDOUT', caseId, unsealDigest, decisionPoint: futureDecisionPoint, maxOpens: 1,
  }));
  r.check('a HOLDOUT read BEFORE the decision point is refused with HOLDOUT_READ_BEFORE_DECISION_POINT',
    refusedWithPolicy(early, 'HOLDOUT_READ_BEFORE_DECISION_POINT'), `code=${early.message ?? early.code ?? 'none'}`);
  const admittedHoldout = await refusalOf(() => readCorpus(registry, {
    partition: 'HOLDOUT', caseId, unsealDigest, decisionPoint, maxOpens: 1,
  }));
  r.check('a HOLDOUT read presenting the PREREGISTERED one-shot digest is admitted',
    admittedHoldout.refused === false, `code=${admittedHoldout.code ?? 'none'}`);

  const replayed = await refusalOf(() => readCorpus(registry, {
    partition: 'HOLDOUT', caseId: secondCaseId, unsealDigest, decisionPoint, maxOpens: 1,
  }));
  r.check('a replayed HOLDOUT read is refused with HOLDOUT_UNSEAL_DIGEST_REPLAYED',
    refusedWithPolicy(replayed, 'HOLDOUT_UNSEAL_DIGEST_REPLAYED'), `code=${replayed.message ?? replayed.code ?? 'none'}`);

  // The open budget. Through `readCorpus` it is NOT reachable: the committed
  // corpus has exactly ONE unseal digest, so a second open either replays the
  // digest (caught above) or presents a forged one (caught before the ledger is
  // reached). The rule is therefore exercised where it lives — on
  // `recordHoldoutRead` itself, with a digest the ledger has not seen — and the
  // unreachability through the dataset layer is recorded rather than left for a
  // reader to discover.
  const budgetExceeded = await refusalOf(() => recordHoldoutRead(registry, {
    trial: 'trl-s2-008-probe-second-open', unsealDigest: PROBE_SECOND_FORGED_UNSEAL_DIGEST, partition: 'HOLDOUT', decisionPoint, maxOpens: 1,
  }));
  r.check('a second open of the same partition is refused with HOLDOUT_OPEN_BUDGET_EXCEEDED',
    refusedWithPolicy(budgetExceeded, 'HOLDOUT_OPEN_BUDGET_EXCEEDED'), `code=${budgetExceeded.message ?? budgetExceeded.code ?? 'none'}`);
  const idempotentRetry = await refusalOf(() => readCorpus(registry, {
    partition: 'HOLDOUT', caseId, unsealDigest, decisionPoint, maxOpens: 1,
  }));
  r.check('re-presenting the same digest for the SAME trial is an idempotent replay, not a counted second open',
    idempotentRetry.refused === false, `code=${idempotentRetry.code ?? 'none'}`);
  r.note('observed_open_budget_reachability', {
    through_read_corpus: 'NOT_REACHABLE: the committed corpus publishes one unseal digest, so a second open through dataset.mjs either replays that digest or presents a forged one',
    through_record_holdout_read: 'REACHABLE and refused with HOLDOUT_OPEN_BUDGET_EXCEEDED',
  });

  // PR9: the actor-kind rule, which had no attack coverage at all. A read whose
  // actor kind the preregistration did NOT release is refused, and the same read
  // by a RELEASED actor kind is admitted — so the guard is shown to make a
  // distinction rather than to refuse everything. Each read needs its OWN
  // ledger: the unseal digest is one-shot, so a second world could not get past
  // the digest check and the actor rule would never be reached.
  const unreleased = await refusalOf(() => readCorpus(freshRegistry(ctx, 'actor-unreleased'), {
    partition: 'HOLDOUT', caseId, unsealDigest, decisionPoint, maxOpens: 1,
    actorKind: 'PRODUCER', releasedActorKinds: access.released_actor_kinds ?? null,
  }));
  r.check('a HOLDOUT read by an actor kind the preregistration did not release is refused with HOLDOUT_ACCESS_NOT_RELEASED',
    refusedWithPolicy(unreleased, 'HOLDOUT_ACCESS_NOT_RELEASED'), `code=${unreleased.message ?? unreleased.code ?? 'none'}`);
  const releasedKind = Array.isArray(access.released_actor_kinds) && access.released_actor_kinds.length > 0
    ? String(access.released_actor_kinds[0]) : null;
  if (releasedKind === null) {
    r.note('observed_actor_release_list', { released: null, reason: 'the preregistration releases no actor kind, so no released read can be demonstrated' });
  } else {
    const released = await refusalOf(() => readCorpus(freshRegistry(ctx, 'actor-released'), {
      partition: 'HOLDOUT', caseId, unsealDigest, decisionPoint, maxOpens: 1,
      actorKind: releasedKind, releasedActorKinds: access.released_actor_kinds,
    }));
    r.check('a HOLDOUT read by a RELEASED actor kind is admitted, so the rule is a decision and not a blanket refusal',
      released.refused === false, `actor=${releasedKind} code=${released.code ?? 'none'}`);
  }

  // The positive control: the reader is real, so the refusals above are
  // decisions about the HOLDOUT and not a blanket refusal of every read.
  const primary = await refusalOf(() => readCorpus(registry, { partition: 'PRIMARY', caseId }));
  r.check('the PRIMARY partition is readable without an unseal digest', primary.refused === false,
    `code=${primary.code ?? 'none'}`);
  r.note('observed_holdout_journal', await journalFact(registry));
  return comparatorControl(r, ctx, specOf(world.probe));
}

/** A second registry handle on a PROBE-LOCAL sub-root of this world's root, so
 *  a one-shot read can be exercised twice without the second attempt dying on
 *  the first one's digest. It is the same `openRegistry` the world used. */
function freshRegistry(ctx, label) {
  const world = ctx.world;
  const root = path.join(world.root, 'extra', label);
  mkdirSync(root, { recursive: true });
  return openRegistry({ root, clock: world.clock, ids: probeIdFactory(`${world.slug}-${label}`) });
}

/** The second case id of the HOLDOUT partition, read from the partition INDEX
 *  (case ids only, never case content). `null` when the partition holds one case
 *  or the file is unreadable, which the caller reports as not_run rather than
 *  passing. */
async function secondHoldoutCaseId(ctx, firstCaseId) {
  const dir = ctx?.corpusDir ?? ctx?.world?.dataset?.corpusDir ?? null;
  if (dir === null) return null;
  const outcome = await refusalOf(() => JSON.parse(readFileSync(path.join(dir, 'cases', 'holdout.json'), 'utf8')));
  if (outcome.refused) return null;
  const cases = Array.isArray(outcome.value) ? outcome.value : (Array.isArray(outcome.value?.cases) ? outcome.value.cases : []);
  const other = cases.find((entry) => isPlainObject(entry) && typeof entry.case_id === 'string' && entry.case_id !== firstCaseId);
  return isPlainObject(other) ? String(other.case_id) : null;
}

// P2 — substituting the best seed. Serves A1/P2.
async function probeSeedSubstitution(ctx, r) {
  const world = ctx.world;
  const prereg = need(world.preregistration, 'preregistration', world.deferred.preregistration ?? 'unavailable');
  // The seed set is read from the preregistration, and WHICH field it came
  // from is recorded: the interface freezes the preregistration's existence,
  // not the name of this member.
  const seeds = prereg.seeds ?? prereg.seed_rule?.seeds ?? null;
  r.note('observed_seed_field', prereg.seeds !== undefined ? 'seeds' : (prereg.seed_rule?.seeds !== undefined ? 'seed_rule.seeds' : 'none'));
  need(Array.isArray(seeds) && seeds.length > 0, 'preregistration.seeds', 'the preregistration carries no seed set to compare against');

  const admitted = await refusalOf(() => assertSeedSetFrozen(seeds, prereg));
  r.check('the preregistered seed set is admitted on every trial', admitted.refused === false, `code=${admitted.code ?? 'none'}`);

  const substituted = [...seeds.slice(0, -1), PROBE_BEST_SEED];
  const swapped = await refusalOf(() => assertSeedSetFrozen(substituted, prereg));
  r.check('a seed set with one seed substituted is refused by a typed policy refusal', policyRefused(swapped), `code=${swapped.code ?? 'none'}`);

  // The ticket's control verbatim: a report containing ONLY the best seed.
  const bestOnly = await refusalOf(() => assertSeedSetFrozen([PROBE_BEST_SEED], prereg));
  r.check('a report containing only the best seed is refused by a typed policy refusal', policyRefused(bestOnly), `code=${bestOnly.code ?? 'none'}`);
  return comparatorControl(r, ctx, specOf(world.probe));
}

// P3 — rewriting a hypothesis after the result. Serves A1/P3.
async function probeHypothesisRewrite(ctx, r) {
  const world = ctx.world;
  const spec = specOf(world.probe);
  const prereg = need(world.preregistration, 'preregistration', world.deferred.preregistration ?? 'unavailable');
  const card = ctx?.card ?? FIXTURE_CARD;
  const rewrittenCard = { ...copyOf(card), test_design: PROBE_REWRITTEN_DESIGN };
  // The load-bearing premise, gated: the rewrite keeps the card_id and is STILL
  // valid against the frozen schema, so nothing but the digest can catch it.
  assertFixture('hypothesis-card', card);
  assertFixture('hypothesis-card', rewrittenCard);
  r.check('a post-result test_design edit keeps the same card_id', rewrittenCard.card_id === card.card_id,
    `${String(rewrittenCard.card_id)} vs ${String(card.card_id)}`);

  const probeCard = { ...copyOf(prereg), card_digest: canonicalDigest(rewrittenCard) };
  if (Object.hasOwn(probeCard, 'card')) probeCard.card = rewrittenCard;
  if (Object.hasOwn(probeCard, 'test_design')) probeCard.test_design = PROBE_REWRITTEN_DESIGN;
  const moved = preregistrationDigest(probeCard) !== preregistrationDigest(prereg);
  r.check('the post-result rewrite moves the preregistration digest', moved === true, 'the digest is the only detector');

  const admitted = await refusalOf(() => assertPreregistration(prereg));
  r.check('the preregistration in force is complete', admitted.refused === false, `code=${admitted.code ?? 'none'}`);

  const unedited = await refusalOf(() => assertNoPostResultRewrite({ prereg, next: copyOf(prereg), resultRecorded: true }));
  r.check('an unedited preregistration is admitted as the decision basis after a result', unedited.refused === false, `code=${unedited.code ?? 'none'}`);

  const rewritten = await refusalOf(() => assertNoPostResultRewrite({ prereg, next: probeCard, resultRecorded: true }));
  r.check('a hypothesis edited after a result is refused by a typed policy refusal', policyRefused(rewritten), `code=${rewritten.code ?? 'none'}`);
  // Recorded, NOT gated: whether the guard keys on the RESULT or on any change
  // is a sibling module's decision, and this probe must not assert it.
  const beforeResult = await refusalOf(() => assertNoPostResultRewrite({ prereg, next: probeCard, resultRecorded: false }));
  r.note('observed_rewrite_before_any_result', { refused: beforeResult.refused, code: beforeResult.code });

  const amended = await refusalOf(() => createAmendment({ prereg, reason: 'a post-result design change is a new document, not an edit', newCardId: 'hyc-s2-008-probe-amended' }));
  r.check('the lawful path after a result is a new AMENDMENT document',
    amended.refused === false && typeof amended.value?.amendment_id === 'string'
    && typeof PREREGISTRATION_KIND === 'string' && String(amended.value?.kind) !== PREREGISTRATION_KIND,
    `kind=${String(amended.value?.kind)} code=${amended.code ?? 'none'}`);
  // A bare amendment is ADMITTED as a record of what changed — that is what it
  // is for, and `assertAmendmentNotDecisionBasis` is a closed-SHAPE check, so
  // the six-key document passes it by design. What must be refused is the same
  // amendment presented as an INPUT to a verdict, and the way a caller does
  // that is by adding the decision member. So the probe presents it that way.
  // (PR6: the probe used to pass the bare amendment and asserted a refusal,
  // which the guard correctly does not give; the assertion was wrong, not the
  // guard, and the guard's own JSDoc says the check is on the closed shape.)
  const asBasis = amended.refused === false
    ? await refusalOf(() => assertAmendmentNotDecisionBasis({ ...amended.value, verdict: 'POSITIVE' }, prereg))
    : { refused: true, code: 'NOT_CREATED', typed: false, message: 'the amendment was never created' };
  r.check('the amendment is refused when presented as a decision basis', policyRefused(asBasis), `code=${asBasis.code ?? 'none'}`);
  const journalledOnly = amended.refused === false
    ? await refusalOf(() => assertAmendmentNotDecisionBasis(amended.value, prereg))
    : { refused: true, code: 'NOT_CREATED', typed: false, message: 'the amendment was never created' };
  r.check('the same amendment is admitted when it is only journalled', journalledOnly.refused === false, `code=${journalledOnly.code ?? 'none'}`);
  const sameId = await refusalOf(() => createAmendment({ prereg, reason: 'an amendment that reuses the amended card id', newCardId: String(prereg.card_id ?? '') }));
  r.check('an amendment that reuses the amended card_id is refused', sameId.refused, `code=${sameId.code ?? 'none'}`);

  // The control: inject the rewritten preregistration and require the guard to
  // flip ADMITTED -> REFUSED. A caller may inject a different next-document.
  const injected = ctx?.controlMutations?.[spec.control.id];
  const mutated = typeof injected === 'function' ? injected(copyOf(prereg)) : probeCard;
  const control = await refusalOf(() => assertNoPostResultRewrite({ prereg, next: mutated, resultRecorded: true }));
  return expectControlFlip(r, spec, {
    before: 'ADMITTED',
    after: control.refused ? 'REFUSED' : 'ADMITTED',
    source: controlSource(ctx, spec.control.id),
    detail: `injected digest ${String(preregistrationDigest(mutated)).slice(0, 23)} code=${control.code ?? 'none'}`,
  });
}

// P4 — opaque budget. Serves A1/P4 and the reconciliation half of A5.
async function probeBudgetOpacity(ctx, r) {
  const world = ctx.world;
  const registry = need(world.registry, 'registry.openRegistry');
  const now = world.clock.nowNs();

  const live = await refusalOf(() => assertBudgetReservation(FIXTURE_RESERVATION, now));
  r.check('a live reservation covering the request is granted', live.refused === false, `code=${live.code ?? 'none'}`);

  const over = { ...FIXTURE_RESERVATION, spent_units: FIXTURE_RESERVATION.granted_units + 1 };
  const exceeded = await refusalOf(() => assertBudgetReservation(over, now));
  r.check('a spend beyond the reservation is refused as a budget refusal', refusedWith(exceeded, 'BUDGET_EXCEEDED'), `code=${exceeded.code ?? 'none'}`);

  // "or a reservation silently released": an expired reservation must be a
  // reconciliation with a row, never a zero and never a free pass.
  const expired = await refusalOf(() => assertBudgetReservation(FIXTURE_RESERVATION, PROBE_LATER));
  r.check('an expired reservation is a reconciliation, not a zero and not a grant',
    refusedWith(expired, 'RECONCILIATION_REQUIRED'), `code=${expired.code ?? 'none'}`);

  // The journal half: a refused settle must leave the ledger byte-identical. A
  // digest comparison against an EMPTY ledger would pass vacuously, so the
  // reservation and a within-limit settle are written first, and the row count
  // is gated. The reservation is a `BUDGET_RESERVATION` payload journalled
  // through `putExperiment`, which is the ordering the ticket demands: a
  // reservation BEFORE the run, not a budget that materialises at the spend.
  const reservation = {
    kind: 'BUDGET_RESERVATION',
    ...FIXTURE_RESERVATION,
    taken_at: PROBE_INSTANT,
  };
  const granted = await refusalOf(() => putExperiment(registry, {
    key: world.key('reserve'),
    args: reservation,
    expectedRevision: 0,
    // The returned object IS the journalled payload; the probe asserts the
    // LEDGER, so the state transition is the payload and not a state machine
    // this probe would be inventing.
    mutate: () => copyOf(reservation),
  }));
  r.check('a budget reservation is journalled before any spend', granted.refused === false, `code=${granted.code ?? 'none'}`);

  const settled = await refusalOf(() => recordSpend(registry, {
    reservationId: FIXTURE_RESERVATION.reservation_id, key: world.key('spend-within'), args: { units: 1, within_reservation: true },
  }));
  r.check('a settle within the reservation is journalled', settled.refused === false, `code=${settled.code ?? 'none'}`);
  const before = await journalFact(registry);
  r.check('the ledger holds a record before the refusal is measured', Number(before.records ?? 0) >= 1, `records=${String(before.records)}`);

  // "never a silent zero": a spend against a reservation that was never granted
  // is a refusal, not an unassigned budget of zero.
  const unassigned = await refusalOf(() => recordSpend(registry, {
    reservationId: 'rsv-s2-008-never-granted', key: world.key('spend-unassigned'), args: { units: 1 },
  }));
  r.check('a settle against a reservation that was never granted is refused, not a zero',
    refusedWith(unassigned, 'BUDGET_EXCEEDED'), `code=${unassigned.code ?? 'none'}`);

  const digestBefore = await refusalOf(() => snapshotDigest(registry));
  const refusedSpend = await refusalOf(() => recordSpend(registry, {
    reservationId: FIXTURE_RESERVATION.reservation_id, key: world.key('spend-over'), args: { units: FIXTURE_RESERVATION.granted_units + 1, within_reservation: false },
  }));
  r.check('a settle beyond the reservation is refused as a budget refusal', refusedWith(refusedSpend, 'BUDGET_EXCEEDED'), `code=${refusedSpend.code ?? 'none'}`);
  const digestAfter = await refusalOf(() => snapshotDigest(registry));
  r.check('a refused settle leaves the ledger byte-identical',
    digestBefore.value !== undefined && digestBefore.value === digestAfter.value,
    `${String(digestBefore.value).slice(0, 23)} vs ${String(digestAfter.value).slice(0, 23)}`);
  r.note('observed_refused_spend', { code: refusedSpend.code, journal_after: await journalFact(registry) });

  // PR4: the expired-reservation RECONCILIATION, measured on the LEDGER rather
  // than only through `assertBudgetReservation`. The row that commits it is
  // `registry.mjs#recordSpend`'s guard — `if (clock.ns > expiresAtNs)` — and no
  // probe reached it: `probes.mjs` asserted the PREREGISTRATION-PLANE guard
  // only, so disabling the ledger's own branch left every property green. The
  // clock has to be STRICTLY AFTER the expiry, because the guard compares with
  // `>`, so the probe opens a second handle on the SAME root at
  // PROBE_AFTER_EXPIRY and settles the reservation this run already granted.
  const afterExpiry = openRegistry({
    root: world.root,
    clock: probeFixedClock(PROBE_AFTER_EXPIRY),
    ids: probeIdFactory(`${world.slug}-after-expiry`),
  });
  const beforeExpiry = await journalFact(afterExpiry);
  const expiredSettle = await refusalOf(() => recordSpend(afterExpiry, {
    reservationId: FIXTURE_RESERVATION.reservation_id,
    key: world.key('spend-after-expiry'),
    args: { units: 1, within_reservation: true },
  }));
  r.check('a settle against an expired reservation is refused on the LEDGER as a reconciliation, not a grant',
    refusedWith(expiredSettle, 'RECONCILIATION_REQUIRED'),
    `code=${expiredSettle.message ?? expiredSettle.code ?? 'none'}`);
  const afterExpiryFact = await journalFact(afterExpiry);
  const journal = await refusalOf(() => readJournal(afterExpiry));
  const reconciliationRows = journal.refused === false && Array.isArray(journal.value)
    ? journal.value.filter((row) => row?.kind === 'RECONCILIATION' || row?.payload?.kind === 'RECONCILIATION')
    : [];
  r.check('the refused expired settle committed a RECONCILIATION row to the journal',
    reconciliationRows.length >= 1,
    `rows=${reconciliationRows.length} records_before=${String(beforeExpiry.records)} records_after=${String(afterExpiryFact.records)}`);
  r.check('the expired reservation was NOT released and NOT zeroed: the reconciliation is the only thing the refusal added',
    afterExpiryFact.records === (Number(beforeExpiry.records ?? 0) + reconciliationRows.length),
    `before=${String(beforeExpiry.records)} after=${String(afterExpiryFact.records)} reconciliation_rows=${reconciliationRows.length}`);
  r.note('observed_expired_reservation', {
    code: expiredSettle.message ?? null, reconciliation_rows: reconciliationRows.length,
    retry_attempted: false, implicit_zero: false,
  });
  return comparatorControl(r, ctx, specOf(world.probe));
}

// P5 — claiming causal proof from a simulation. Serves A1/P5 and ALL of A4.
async function probeCausalUpgrade(ctx, r) {
  const spec = specOf(ctx.world.probe);
  const card = copyOf(ctx?.card ?? FIXTURE_CARD);
  assertFixture('hypothesis-card', card);
  const swapped = { ...card, proposed_relation: { ...card.proposed_relation, causal_assertion: true } };
  // Gated: the swapped card is STILL contract-valid, so the refusal below is
  // attributable to the label guard and not to a schema rejection.
  assertFixture('hypothesis-card', swapped);
  r.check('a causal claim over observational ground truth is still valid against the frozen schema',
    swapped.proposed_relation.causal_assertion === true, 'the card schema has no allOf: the rule lives in code');

  const admitted = await refusalOf(() => assertCausalDiscipline(card));
  r.check('an observational card claiming no causal relation is admitted', admitted.refused === false, `code=${admitted.code ?? 'none'}`);

  const refused = await refusalOf(() => assertCausalDiscipline(swapped));
  r.check('a causal claim on observational ground truth is refused by a typed policy refusal', policyRefused(refused), `code=${refused.code ?? 'none'}`);

  const narrow = await refusalOf(() => assertNoCausalFromSimulation(swapped));
  r.check('the always-on simulation guard refuses the same card', policyRefused(narrow), `code=${narrow.code ?? 'none'}`);

  const classified = await refusalOf(() => classifyCardRelation(swapped));
  r.check('the classification reports the swapped card inadmissible with a refusal code',
    classified.refused === false && classified.value?.admissible === false && typeof classified.value?.refusalCode === 'string',
    `admissible=${String(classified.value?.admissible)} code=${String(classified.value?.refusalCode)}`);
  r.note('observed_classification', {
    relation_strength: card.proposed_relation.relation_strength, causal_assertion: true,
    refusal_code: classified.value?.refusalCode ?? null,
  });

  // PR7: the same claim put through `resolveTrialVerdict` — the ONE place a
  // trial verdict is named, and therefore the only place a causal claim reaches
  // a real ALLOW/VIOLATION. P5 calls the card-layer guards, which are not on
  // that path, so voiding `causalClaimRefusal` at comparator.mjs left every
  // property green. A RESOLVED trial with all four bindings PRESENT and a
  // causal claim over correlation evidence must be a VIOLATION, and the probe
  // asserts the NAMED reason.
  const causalTrial = await comparatorVerdict({
    ...trialFor(ctx),
    provenance_label: 'CAUSAL_PROOF',
    inference_mode: 'CAUSAL',
    relation_strength: 'CORRELATION_EVIDENCE',
  });
  r.check('a RESOLVED trial that CLAIMS causality over correlation evidence is a VIOLATION, never an ALLOW',
    causalTrial.verdict === 'VIOLATION'
      && causalTrial.reasons.some((reason) => reason.startsWith('CAUSAL_CLAIM_UNSUPPORTED:CORRELATION_EVIDENCE')),
    `verdict=${String(causalTrial.verdict)} reasons=${causalTrial.reasons.join('; ') || 'none named'}`);
  // S3: the same claim reached through a RENAMED member. A record that carries
  // the card as `hypothesis_card`, and names the label as `label`, must reach the
  // same refusal: a rename is not a defence, and the comparator must not be the
  // component a rename defeats.
  const renamedCard = { ...copyOf(ctx?.card ?? FIXTURE_CARD) };
  const renamedTrial = { ...trialFor(ctx), label: 'CAUSAL_PROOF', card: undefined, hypothesis_card: renamedCard };
  delete renamedTrial.card;
  const renamed = await comparatorVerdict(renamedTrial);
  r.check('the same causal claim under a RENAMED card member and a RENAMED label member is still a VIOLATION',
    renamed.verdict === 'VIOLATION'
      && renamed.reasons.some((reason) => reason.startsWith('CAUSAL_CLAIM_UNSUPPORTED')),
    `verdict=${String(renamed.verdict)} reasons=${renamed.reasons.join('; ') || 'none named'}`);

  return expectControlFlip(r, spec, {
    before: admitted.refused ? 'REFUSED' : 'ADMITTED',
    after: refused.refused ? 'REFUSED' : 'ADMITTED',
    source: controlSource(ctx, spec.control.id),
    detail: `label guard refusal code ${String(refused.code ?? 'none')}`,
  });
}

// P6 — a missing evaluator. Serves A1/P6 and the fail-closed half of A2.
async function probeMissingEvaluator(ctx, r) {
  const spec = specOf(ctx.world.probe);
  const independent = copyOf(ctx?.calibration ?? FIXTURE_CALIBRATION_INDEPENDENT);
  assertFixture('calibration-record', independent);
  const notIndependent = {
    ...independent,
    not_measured_reason: 'evaluator_not_independent',
    evaluator_independence: { ...independent.evaluator_independence, blind_to_producer: false },
  };
  assertFixture('calibration-record', notIndependent);
  const evaluator = { evaluator_id: 'evl-s2-008-probe', independent: true, blind_to_producer: true };

  const admitted = await refusalOf(() => assertEvaluatorPresent(evaluator, independent));
  r.check('an independent evaluator is admitted', admitted.refused === false, `code=${admitted.code ?? 'none'}`);

  const removed = await refusalOf(() => assertEvaluatorPresent(null, independent));
  r.check('an absent evaluator is refused by a typed policy refusal', policyRefused(removed), `code=${removed.code ?? 'none'}`);

  const biased = await refusalOf(() => assertEvaluatorPresent(evaluator, notIndependent));
  r.check('an evaluator that is not blind to the producer is refused by a typed policy refusal', policyRefused(biased), `code=${biased.code ?? 'none'}`);

  // A missing evaluator is NOT_MEASURED, and NOT_MEASURED is a VIOLATION: it
  // is never ALLOW and never a silent zero.
  const notMeasured = await comparatorVerdict({ ...trialFor(ctx), status: 'NOT_MEASURED' });
  r.check('a NOT_MEASURED trial resolves to VIOLATION, never ALLOW',
    notMeasured.verdict === 'VIOLATION', `verdict=${String(notMeasured.verdict)} reasons=${notMeasured.reasons.join('; ') || 'none named'}`);

  // PR2: a NON-INDEPENDENT evaluator put through `resolveTrialVerdict` — the one
  // place a trial verdict is named. Every one of the four bindings PRESENT, the
  // status RESOLVED, and a calibration that declares zero independent evaluators
  // and a producer-aware one: that is a VIOLATION, and the probe asserts the
  // NAMED reason. P6's three checks above call `assertEvaluatorPresent` directly,
  // so voiding the call INSIDE the verdict loop left every property green.
  const notIndependentVerdict = await comparatorVerdict({
    ...trialFor(ctx),
    calibration: {
      status: 'MEASURED',
      not_measured_reason: null,
      evaluator_independence: { independent_evaluators: 0, blind_to_producer: false, separate_processes: false },
    },
  });
  r.check('a trial whose calibration declares a non-independent evaluator is a VIOLATION, never an ALLOW',
    notIndependentVerdict.verdict === 'VIOLATION'
      && notIndependentVerdict.reasons.some((reason) => reason.startsWith('EVALUATOR_NOT_INDEPENDENT')),
    `verdict=${String(notIndependentVerdict.verdict)} reasons=${notIndependentVerdict.reasons.join('; ') || 'none named'}`);
  return comparatorControl(r, ctx, spec);
}

/** The probe body for a family, frozen per family so `runProbe` cannot pick a
 * body that does not belong to the probe it was asked for. */
const PROBE_BODIES = Object.freeze({
  holdout_peek: probeHoldoutPeek,
  seed_substitution: probeSeedSubstitution,
  hypothesis_rewrite: probeHypothesisRewrite,
  budget_opacity: probeBudgetOpacity,
  causal_upgrade: probeCausalUpgrade,
  missing_evaluator: probeMissingEvaluator,
});

// --- public: the two entry points ------------------------------------------

/**
 * Run ONE probe and return its recorder result. Probes are ASYNC because the
 * stored fixtures are file-backed; the decision path itself is synchronous and
 * pure.
 * @param {string} probe The probe name to run.
 * @param {object} ctx The world options (see createWorld) plus the shared
 *   corpus handle, the bundled-fixture overrides (`trial`, `card`,
 *   `calibration`) and the optional `controlMutations` a caller injects.
 * @returns {Promise<object>} The `ProbeRecorder.result()` shape:
 *   `{probe, family, status, passed, counter, counted, detail, evidence}`.
 *   `counted` is 1 only when the attack succeeded. A probe that could not run
 *   returns `status: 'not_run'` with an `omit` block and is never a pass; a
 *   probe whose control did not flip returns `status: 'broken'` and is not
 *   counted either.
 * @throws {Error} Only for a harness-level failure: an unknown probe name, or
 *   a scratch root that fails the purge safety check (a caller
 *   misconfiguration, which is raised rather than recorded as a probe fact). A
 *   probe BODY never throws to signal a refusal — a missing dependency or an
 *   unexpected raise is recorded as not_run, because a throw that aborts a
 *   probe hides the counter move and silently costs the other five probes
 *   their record.
 */
export function runProbe(probe, ctx) {
  const spec = specOf(probe);
  const recorder = new ProbeRecorder(spec.family, probe, spec.counter);
  recorder.note('id', spec.id);
  recorder.note('subject', spec.subject);
  recorder.note('expectation', spec.expectation);
  recorder.note('verdict_forced', spec.verdict);
  recorder.note('finding_produced', spec.finding);
  return (async () => {
    try {
      const world = createWorld(spec.family, probe, ctx ?? {});
      recorder.note('probes_version', PROBES_VERSION);
      recorder.note('world', {
        family: world.family, probe: world.probe, clock_source: world.clock_source,
        id_source: world.id_source, purge: world.purged.refused === false,
        purge_refusal: world.purged.refused ? reasonOf(world.purged) : null,
        deferred: world.deferred,
      });
      await PROBE_BODIES[spec.family]({ ...(ctx ?? {}), world }, recorder);
    } catch (error) {
      if (error instanceof ScratchRootUnsafe) throw error;
      const missing = error instanceof DependencyMissing;
      return recorder.notRun(
        missing
          ? `${error.dependency}: ${error.reason}`
          : `${String(error?.name ?? 'Error')}: ${redact(String(error?.message ?? error)).slice(0, 200)}`,
        missing ? 'DEPENDENCY_UNAVAILABLE' : 'PROBE_ABORTED',
      );
    }
    return recorder.result();
  })();
}

/**
 * Run all six families' probes in the frozen review order, purging this
 * module's own fixtures FIRST so a repeat run fails on the property and not on
 * its leftovers.
 * @param {object} ctx The shared context: `{clock, ids, registryRoot, corpusDir,
 *   caseId, trial, card, calibration, controlMutations}`. A fresh world per
 *   probe is created from it.
 * @returns {Promise<{version: string, purged: object, results: ReadonlyArray<object>,
 *   counters: Record<string, number>, allPassed: boolean, notRun: ReadonlyArray<object>,
 *   broken: ReadonlyArray<object>}>}
 *   `counters` is the hard-gate counter map; every value must be 0.
 *   `allPassed` is false if any probe failed OR any probe did not run OR any
 *   probe is broken. `notRun` and `broken` name the probes, so a caller that
 *   reads only `counters` cannot call a broken probe green: the individual
 *   `status` is 'broken', `allPassed` is already false, and a non-zero counter
 *   is the only thing `counters` reports. `purged` is the A5 evidence that this
 *   module's own fixtures were removed before the run.
 */
export async function runAllProbes(ctx) {
  const context = ctx ?? {};
  const purged = purgeProbeFixtures(context);
  const results = [];
  const counters = Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0]));
  for (const family of PROBE_FAMILIES) {
    for (const probe of PROBE_NAMES[family]) {
      const result = await runProbe(probe, context);
      results.push(result);
      if (Object.hasOwn(counters, result.counter)) counters[result.counter] += result.counted;
    }
  }
  const notRun = results.filter((entry) => entry.status === 'not_run')
    .map((entry) => ({ probe: entry.probe, family: entry.family, code: entry.omit?.code ?? 'NOT_RUN', reason: entry.omit?.reason ?? entry.detail }));
  const broken = results.filter((entry) => entry.status === 'broken')
    .map((entry) => ({
      probe: entry.probe, family: entry.family, control: entry.evidence?.control?.id ?? null,
      before: entry.evidence?.control?.before ?? null, after: entry.evidence?.control?.after ?? null,
    }));
  return {
    version: PROBES_VERSION,
    purged: { base: purged.base, removed: purged.removed, removed_roots: purged.removed_roots, roots: purged.roots.length },
    results,
    counters,
    allPassed: results.length === PROBE_FAMILIES.length && notRun.length === 0 && broken.length === 0
      && results.every((entry) => entry.passed),
    notRun,
    broken,
  };
}

// --- the probe result recorder ---------------------------------------------

/**
 * One probe's verdict. `check` records a boolean FACT, never an opinion:
 * `r.check('label', ok, detail)`. A probe passes only when every fact it
 * recorded is true. Counters move ONLY on success — a refused attack leaves
 * its counter at 0.
 *
 * Mirrors src/lib/agentboard/probes.mjs:343 (`check` / `note` / `notRun` /
 * `result`), with ONE documented addition: a failed control-flip fact (a label
 * carrying the `control_flips: ` prefix) yields `status: 'broken'` instead of
 * 'failed', because a control that does not flip means the defence is UNPROVEN,
 * not that the attack got through. Moving the counter there would report a
 * bypass that never happened; passing there would report a defence nobody
 * demonstrated.
 */
export class ProbeRecorder {
  /**
   * @param {string} family A member of PROBE_FAMILIES.
   * @param {string} probe The probe name.
   * @param {string} counter The hard-gate counter this probe owns.
   */
  constructor(family, probe, counter) {
    this.family = family;
    this.probe = probe;
    this.counter = counter;
    this.checks = [];
    this.facts = {};
    this.status = 'pass';
    this.detail = '';
  }

  /**
   * Record a boolean fact. A probe passes only when every fact is true.
   * @param {string} label The fact's short name.
   * @param {boolean} ok The fact.
   * @param {string} [detail=''] A bounded, secret-free elaboration.
   * @returns {boolean} `ok === true`, so a caller can branch on the recorded
   *   fact.
   */
  check(label, ok, detail = '') {
    const value = ok === true;
    this.checks.push({ label, ok: value, detail: String(detail).slice(0, 300) });
    if (!value && this.status === 'pass') this.status = 'failed';
    return value;
  }

  /**
   * Record a fact for the evidence record. Never a secret, never a whole-row
   * dump, never an unbounded string.
   * @param {string} key The fact's key.
   * @param {string|number|boolean|object} value The fact's value.
   * @returns {ProbeRecorder} this recorder, for chaining.
   */
  note(key, value) {
    this.facts[key] = typeof value === 'string' ? value.slice(0, 300) : value;
    return this;
  }

  /**
   * The probe could not run here. NOT_RUN is never a pass and never counts;
   * the harness exits 3 rather than 0.
   * @param {string} reason Why it could not run.
   * @param {string} [code='NOT_RUN'] The bounded reason code.
   * @returns {object} The `result()` shape with `status: 'not_run'` and an
   *   `omit` block naming the probe, family, code and reason.
   */
  notRun(reason, code = 'NOT_RUN') {
    this.status = 'not_run';
    this.detail = reason;
    this.omit = { probe: this.probe, family: this.family, code, reason };
    return this.result();
  }

  /**
   * The probe's record.
   * @returns {{probe: string, family: string, status: string, passed: boolean,
   *   counter: string, counted: number, detail: string, evidence: object}}
   *   `status` is 'pass' | 'failed' | 'broken' | 'not_run'. `counted` is 1 ONLY
   *   when the status is 'failed' — the counter moves when the attack succeeded,
   *   never when a control failed to flip.
   */
  result() {
    const controlBroken = this.checks.some((entry) => !entry.ok && entry.label.startsWith(CONTROL_CHECK_PREFIX));
    // Precedence: a probe that could not run at all stays not_run even if an
    // earlier fact was recorded as false; otherwise a failed control-flip fact
    // is 'broken' and only a real failed fact is 'failed'.
    const status = this.status === 'not_run' ? 'not_run' : (controlBroken ? 'broken' : this.status);
    return {
      probe: this.probe,
      family: this.family,
      status,
      passed: status === 'pass' && this.checks.every((entry) => entry.ok),
      counter: this.counter,
      // The counter moves ONLY when the attack succeeded (a failed probe).
      counted: status === 'failed' ? 1 : 0,
      detail: this.detail || this.checks.map((entry) => entry.label).join('; ').slice(0, 500),
      evidence: {
        probe: this.probe,
        family: this.family,
        counter: this.counter,
        status,
        checks: this.checks,
        ...(this.facts ?? {}),
      },
      ...(this.omit ? { omit: this.omit } : {}),
    };
  }
}
