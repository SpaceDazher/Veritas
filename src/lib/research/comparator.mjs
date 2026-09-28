// S2-008 research track — the FAIL-CLOSED DECISION (issue SpaceDazher/Veritas#8).
//
// Serves acceptance items A2, A3 and A4, and negative probe P6 (a missing
// evaluator) with its negative control id `missing_evaluator`.
//
// THE RULE, IN ONE LINE
// `ALLOW` requires `RESOLVED` **and** all four bindings — seed, holdout, budget
// and evaluator. Everything else is `VIOLATION`. There is no third outcome: a
// trial whose evaluator is missing, whose status is SKIPPED, UNRESOLVED or
// INFRA_ERROR, or whose calibration is NOT_MEASURED is a VIOLATION, never an
// ALLOW, never a silent zero, and never absent from the expected-value table.
// A NOT_MEASURED CALIBRATION IS NOT A ZERO PERCENT: `assertEvaluatorPresent`
// resolves an absent or non-independent evaluator to NOT_MEASURED with the
// in-contract reason `evaluator_not_independent` (an exact value of the
// `not_measured_reason` enum in contracts/calibration-record.schema.json), and
// the NOT_MEASURED trial then fails closed.
//
// EVERY VERDICT IS NAMED IN EXACTLY ONE PLACE
// `resolveTrialVerdict` names a TRIAL verdict; `resolveCampaignVerdict`
// DELEGATES to `resolveVerdict` from src/lib/sloqual/comparator.mjs:237 and
// never re-implements it. `src/lib/sloqual/**` is imported, never forked and
// never edited by this track: a second statistics or verdict layer is exactly
// the silent divergence `store.mjs:26-32` exists to prevent.
//
// LATENCY IS MEASURED, BUT IT NEVER DECIDES
// `latencyRecorded` records latency samples through `percentileBootstrapInterval`
// with the preregistered seed and sample count, and every returned sample block
// carries `decides: false`. Latency can therefore only ever contribute a LIMIT,
// never a failure and never a verdict. The comparator NEVER reads `nowNs` or
// the fixed clock: wall-clock latency is an observation about this host, and a
// verdict that depended on it would not reproduce on the next host.
//
// THE FROZEN NOISE / CI RULE, EXACTLY AS IMPLEMENTED HERE
// `decisionFromInterval` is the only place a campaign outcome is named, and it
// is pure arithmetic over constants the preregistration published BEFORE trial
// one:
//   1. A status that is not `RESOLVED` decides nothing: INFRA_ERROR yields
//      `INFRA`, and SKIPPED / UNRESOLVED / NOT_MEASURED yield `UNRESOLVED`.
//      The measurement is not consulted for a trial that did not resolve.
//   2. The interval is read against the preregistered NULL value and NOISE
//      BAND. An interval entirely INSIDE the band is a `NULL` result — a real
//      answer, not a negative one. An interval that straddles the null but
//      leaves the band is `UNRESOLVED`.
//   3. The MULTIPLICITY CORRECTION runs over the DECLARED comparison family,
//      never over "the comparisons that happened to be significant": a CI at
//      confidence `c` that excludes the null implies `p <= 1 - c`, and that
//      bound is what the step-down uses. `bonferroni` rejects at `alpha / m`;
//      `holm_bonferroni` steps down at `alpha / (m - i)`. `m` comes from the
//      preregistration; an absent family is a MalformedResult, never a silent
//      uncorrected test.
//   4. Only a corrected, significant effect in the preregistered direction is
//      `POSITIVE`; the same effect in the other direction is `NEGATIVE` —
//      first-class, itemised, never a pass. A significant effect the correction
//      does not reject is `UNRESOLVED`: "not significant at the corrected
//      level" is not the same answer as "no effect".
// The estimate, the interval and the corrected decision are all returned, so
// the evidence record is re-derived from the raw counts instead of trusted.
// `compareParallelTrack` REBUILDS the interval with `wilsonInterval` from the
// run's own counts and compares a self-reported interval only when it declares
// the same method: a run that reports a number its own counts do not support is
// a corruption the comparator would otherwise have honoured.
//
// A COMPARISON THAT CANNOT BE MADE IS A THROW; ONE THAT FAILED IS A FAILURE
//   * A missing raw run id, commit SHA or tree SHA, or two runs on DIFFERENT
//     bases, throw `MalformedResult`. There is no pair to compare, so no
//     verdict is produced — a verdict would name a record the track cannot
//     identify.
//   * Two runs sharing an id, a nonce, an executor or an output root; a
//     SKIPPED trial; a counter that moved; a disagreement with the frozen
//     table; an incomplete seed set. These are DECIDABLE, so they become
//     failures: the aggregator can itemise them and a control can show a FLIP
//     instead of a crash.
//
// A4: A PROVENANCE LABEL THAT IS NOT CAUSAL FORBIDS A CAUSAL VERDICT
// `resolveTrialVerdict` refuses a trial that claims a causal conclusion while
// its ground truth is observational — the claimed relation strength is a member
// of `OBSERVATIONAL_RELATION_STRENGTHS`, `causal_assertion` is not true, or the
// evidence is missing — and `compareParallelTrack` applies the same rule to the
// run record and to the preregistration's `inference_mode`, which is
// ASSOCIATIONAL for this track and never upgraded. A CLAIM is what is refused;
// the ABSENCE of a causal label is not a violation, because the observational
// reading is the lawful default and the deep A4 guard lives in causality.mjs.
//
// SEED DISCLOSURE IS A CHECK THE COMPARATOR RUNS ON ITSELF-REPORTS (P2)
// "Seeds are frozen" is not the whole of P2: the best seed is not a statistic
// the verdict may use. `bestSeedDisclosure(name, seeds)` builds the record that
// every seed was reported, and a run that names a selection without a matching
// disclosure over ALL seeds fails the check (`best_seed_undisclosed`).
//
// HOW A CORRUPTED RUN IS CAUGHT
// `injectCorruption` builds the corrupted record the `corrupted_data` control
// needs — a trial flipped RESOLVED -> SKIPPED, a counter nudged to 1, a metric
// record altered, or a provenance field replaced. Re-running
// `compareParallelTrack` on it MUST flip the verdict AND name the field. A
// corruption that survives the comparator is a fail-open and fails the track.
//
// TWO INTERFACE NOTES, RECORDED RATHER THAN HIDDEN
// 1. `bestSeedDisclosure` is NOT in the plan §1 export list for this file. The
//    S2-008 task text requires the name, so it is implemented and exported
//    here; adding it to `src/lib/research/index.mjs` and to the plan is D's and
//    W4's call, and this file is the only place that has to change.
// 2. The three frozen enums and the observational subset are imported from
//    constants.mjs / causality.mjs. While those modules are skeletons their
//    exports are `null`, so the mirrors below are used; the moment an import is
//    a usable array the IMPORT WINS, unconditionally. The mirrors exist only so
//    this module is verifiable before W1 lands, and they are never a second
//    source of truth at run time. Their values are the ones the frozen plan and
//    the frozen schemas already state in prose, so a disagreement is a defect
//    to report rather than a runtime fork.
//
// WHAT THE FROZEN CONSTANTS CAN AND CANNOT DECIDE (reported, not fixed here)
// With the committed preregistration's constants — alpha 0.05, confidence 0.95,
// a Holm–Bonferroni family of three declared comparisons — a comparison bound
// inherited from a `c`-level interval is `1 - c = 0.05`, and the first Holm step
// is `alpha / m = 0.0167`. The correction can therefore NEVER reject, whatever
// the measurement is, and the campaign-level decision is restricted to NULL,
// UNRESOLVED and INFRA. `decisionFromInterval` states this in its own output
// (`correction.never_rejects`, `correction.blocking_*`) so a reader can tell a
// real "no effect" from a rule that had no power to say otherwise. Making the
// family rejectable needs the PUBLISHED confidence to rise to `1 - alpha / m`;
// that is a change to `evidence/s2-008/corpus/preregistration.json`, which W2
// owns, and it is reported to D rather than made here. The comparator's
// conservatism is deliberate in the meantime: an UNRESOLVED can only ever cost
// a PASS, which is the direction this ticket requires.
//
// Owner: W3 (decision core). Budget: part of W3's <= 800 lines — this file
// alone exceeds it; the overrun is reported to D rather than paid for by
// dropping a check.
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import { resolveVerdict } from '../sloqual/comparator.mjs';
import { percentileBootstrapInterval, wilsonInterval } from '../sloqual/statistics.mjs';
import { BlockedPolicy, MalformedResult } from '../agentboard/errors.mjs';
import { expectedValueIssues } from './expected-values.mjs';
import { RESEARCH_OUTCOMES, TRIAL_STATUSES, TRIAL_VERDICTS } from './constants.mjs';
import { OBSERVATIONAL_RELATION_STRENGTHS, classifyCardRelation } from './causality.mjs';
import { EXECUTOR_PRODUCIBLE_LABELS } from './executor.mjs';
import { assertSeedSetFrozen } from './preregistration.mjs';

/**
 * The version string of this decision layer, for the evidence record.
 * @type {string}
 */
export const COMPARATOR_VERSION = 's2-008-comparator-v1';

// --- the frozen vocabulary, read from W1, mirrored only while W1 is a stub --

// The five trial statuses, the two trial verdicts and the five research
// outcomes, as the plan states them in prose. See the second interface note in
// the header: the import wins as soon as it is a usable array.
const MIRROR_TRIAL_STATUSES = ['RESOLVED', 'SKIPPED', 'UNRESOLVED', 'INFRA_ERROR', 'NOT_MEASURED'];
const MIRROR_TRIAL_VERDICTS = ['ALLOW', 'VIOLATION'];
const MIRROR_RESEARCH_OUTCOMES = ['POSITIVE', 'NEGATIVE', 'NULL', 'INFRA', 'UNRESOLVED'];

// The relation strengths that describe OBSERVED STRUCTURE ONLY. Membership is
// W1's to derive from the compiled enum and W1's test pins it; the mirror is
// used only while causality.mjs is a skeleton.
const MIRROR_OBSERVATIONAL_STRENGTHS = ['ANALOGICAL_STRUCTURE', 'TEMPORAL_CO-OCCURRENCE', 'CORRELATION_EVIDENCE'];

// The labels by which a run may CLAIM causality, closed on purpose, and read
// in BOTH directions. `CAUSAL_LABELS` names the labels that ARE claims; the
// complementary set is what the transport can actually PRODUCE
// (`EXECUTOR_PRODUCIBLE_LABELS`, imported from executor.mjs so this module
// cannot widen it). A `provenance_label` outside BOTH sets is an UNRECOGNISED
// label, and an unrecognised label is treated as a claim to be supported rather
// than as a non-claim: the previous rule ("unknown means non-causal") was a
// fail-open, and `CAUSAL_EXPERIMENT` — a member of the executor's OWN closed
// set — walked straight through it. `CAUSAL_STRENGTH` is the wording the frozen
// card schema itself uses ("correlation/analogy never recorded as
// causal_strength").
const CAUSAL_LABELS = new Set(['CAUSAL', 'CAUSAL_EFFECT', 'CAUSAL_PROOF', 'CAUSAL_STRENGTH', 'CAUSAL_EXPERIMENT']);
const PRODUCEABLE_LABELS = new Set(EXECUTOR_PRODUCIBLE_LABELS);

// A binding record may state its own flag. When it does, that flag decides:
// `{bound: false, reason: 'expired'}` is an UNSATISFIED binding, not a
// satisfied one with a comment attached.
const BINDING_FLAGS = ['bound', 'ok', 'verified', 'granted', 'satisfied', 'present'];

// The four bindings `ALLOW` requires. The order is the order they are reported.
// `member` is the flat camelCase name a trial record may use; `nested` is the
// key under `bindings` the runner writes. They are ONE field with two
// spellings — the same convention `readField` applies to snake_case — and not
// two independently optional bindings, which is what let a run present
// `bindings.seed` and be scored as if it had presented no seed binding at all
// (S2-008-SD-02).
const BINDINGS = Object.freeze([
  Object.freeze({ name: 'seedBinding', nested: 'seed', reason: 'SEED_BINDING' }),
  Object.freeze({ name: 'holdoutBinding', nested: 'holdout', reason: 'HOLDOUT_BINDING' }),
  Object.freeze({ name: 'budgetBinding', nested: 'budget', reason: 'BUDGET_BINDING' }),
  Object.freeze({ name: 'evaluatorBinding', nested: 'evaluator', reason: 'EVALUATOR_BINDING' }),
]);

/**
 * The semantic content each binding must carry, checked on its own terms.
 *
 * This is the corrected rule behind findings PR3, PR4, PR7, PR8 and S2-008-SD-02:
 * a binding used to PASS on presence alone, so a holdout opened before its
 * decision point, a spend above the reservation, a bare-string budget and a
 * non-independent evaluator were all `ALLOW`. A binding is SATISFIED when its
 * own content says so; a `bound: false` flag is still honoured, but it is no
 * longer the only thing that is read.
 *
 * Each checker is pure and total: it returns `null` when the binding is
 * satisfied and a bounded reason naming the exact requirement it missed when it
 * is not. A non-record binding returns `null` here — presence was already
 * judged by `bindingPresent`, and a checker that re-judged presence would be a
 * second opinion about the same thing.
 */
const BINDING_CHECKS = Object.freeze({
  seedBinding(raw) {
    if (!isRecord(raw)) return null;
    const declared = Array.isArray(raw.seeds) ? raw.seeds : null;
    if (declared === null) return 'no_declared_seed_set';
    if (raw.source !== undefined && String(raw.source).toUpperCase().includes('BEST')) return 'best_seed_only_not_the_frozen_set';
    if (Array.isArray(raw.preregistered_seeds) && !sameMembers(declared, raw.preregistered_seeds)) {
      return `seed_set_differs_from_preregistered:${JSON.stringify(declared)}`;
    }
    const distinct = [...new Set(declared.map((seed) => JSON.stringify(seed)))];
    if (distinct.length === 1 && declared.length > 1) return 'all_seeds_identical_which_is_not_a_set';
    return null;
  },
  holdoutBinding(raw) {
    if (!isRecord(raw)) return null;
    const readAt = raw.read_at ?? raw.readAt ?? null;
    // `decision_point` / `decisionPoint` is the spelling THE LEDGER COMMITS:
    // registry.mjs#recordHoldoutRead plans the ACCESS payload with
    // `decision_point`, so a trial that carried the ledger's own row verbatim
    // was read here as carrying no decision point at all and an early peek on
    // that shape was an ALLOW. The two spellings are ONE field read both ways,
    // the same convention `readField` applies elsewhere in this file.
    const decisionAt = raw.decision_at ?? raw.decisionAt ?? raw.decision_point ?? raw.decisionPoint ?? null;
    if (readAt !== null && decisionAt !== null && String(readAt) < String(decisionAt)) {
      const named = raw.decision_at !== undefined || raw.decisionAt !== undefined ? 'decision_at' : 'decision_point';
      return `read_before_decision_point:read_at=${String(readAt)}<${named}=${String(decisionAt)}`;
    }
    if (raw.opened_before_decision_point === true) return 'opened_before_decision_point';
    const opens = finiteNumber(raw.opens) ? raw.opens : (finiteNumber(raw.open_count) ? raw.open_count : null);
    if (opens !== null && finiteNumber(raw.max_opens) && opens > raw.max_opens) {
      return `opens_exceed_max_opens:${opens}>${raw.max_opens}`;
    }
    return null;
  },
  budgetBinding(raw) {
    // A budget binding that is not a RECORD states no units at all. A bare
    // string passed the presence test and was scored as a satisfied binding
    // (PR3), which is the one bypass that had no flag to strip.
    if (!isRecord(raw)) return 'budget_binding_states_no_units';
    const granted = finiteNumber(raw.granted_units) ? raw.granted_units : null;
    const spent = finiteNumber(raw.spent_units) ? raw.spent_units : null;
    if (granted === null || spent === null) return 'budget_binding_states_no_units';
    if (spent > granted) return `spend_exceeds_reservation:${spent}>${granted}`;
    return null;
  },
  evaluatorBinding(raw) {
    if (!isRecord(raw)) return null;
    if (raw.independent === false) return 'evaluator_not_independent';
    if (raw.blind_to_producer === false) return 'evaluator_not_blind_to_producer';
    return null;
  },
});

// The closed set of comparison methods, and the relative tolerance used only
// at an exact decision boundary. See `within` in decisionFromInterval.
const DECISION_EPSILON = 1e-12;

// The comparison-identity fields two PROCESS-SEPARATED runs must never share.
const SEPARATION_FIELDS = Object.freeze(['raw_run_id', 'nonce', 'executor_id', 'pid', 'output_root']);

// The provenance every run artefact must carry before two runs may be compared
// (A5). Absent means unbound, and an unbound artefact is not comparable.
const BINDING_PROVENANCE = Object.freeze(['commit_sha', 'tree_sha', 'raw_run_id']);

// The four frozen corruption variants of the `corrupted_data` control. The set
// is closed: an unknown variant is a MalformedResult, because an unnamed
// corruption is not a control.
const CORRUPTION_VARIANTS = Object.freeze({
  trial_status_skip: 'a trial status flipped RESOLVED -> SKIPPED',
  counter_nudge: 'a hard-gate counter nudged 0 -> 1',
  metric_altered: 'a metric record altered',
  provenance_field: 'a provenance field replaced',
});

function frozenSet(imported, mirror) {
  if (Array.isArray(imported) && imported.length > 0) return Object.freeze([...imported]);
  return Object.freeze([...mirror]);
}

const STATUSES = frozenSet(TRIAL_STATUSES, MIRROR_TRIAL_STATUSES);
const VERDICTS = frozenSet(TRIAL_VERDICTS, MIRROR_TRIAL_VERDICTS);
const OUTCOMES = frozenSet(RESEARCH_OUTCOMES, MIRROR_RESEARCH_OUTCOMES);
const OBSERVATIONAL = frozenSet(OBSERVATIONAL_RELATION_STRENGTHS, MIRROR_OBSERVATIONAL_STRENGTHS);

const RESOLVED = 'RESOLVED';
const ALLOW = 'ALLOW';
const VIOLATION = 'VIOLATION';

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function finiteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function round6(value) {
  return Number.isFinite(value) ? Math.round(value * 1e6) / 1e6 : null;
}

// Read a member in its camelCase form, falling back to the snake_case spelling
// a JSON run record carries. The camelCase name is the in-memory contract; the
// snake_case name is the wire spelling of the SAME field, not a second field.
function readField(record, name) {
  if (!isRecord(record)) return undefined;
  if (record[name] !== undefined) return record[name];
  const wire = name.replace(/[A-Z]/g, (character) => `_${character.toLowerCase()}`);
  return record[wire] === undefined ? undefined : record[wire];
}

function bindingPresent(value) {
  if (value === undefined || value === null || value === false) return false;
  if (value === true) return true;
  if (typeof value === 'string') return value.length > 0;
  if (finiteNumber(value)) return value > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (isRecord(value)) {
    for (const flag of BINDING_FLAGS) {
      if (Object.prototype.hasOwnProperty.call(value, flag)) return value[flag] === true;
    }
    return Object.keys(value).length > 0;
  }
  return false;
}

function sameMembers(left, right) {
  const a = [...left].map((item) => JSON.stringify(item)).sort();
  const b = [...right].map((item) => JSON.stringify(item)).sort();
  return a.length === b.length && a.every((item, index) => item === b[index]);
}

function failure(failures, code, detail) {
  failures.push({ code, detail });
}

function limit(limits, code, detail, proof) {
  limits.push({ code, detail, proof: proof ?? null });
}

function proof(proofStatus, id, status, evidence, missing) {
  proofStatus.push({ id, status, evidence, missing: missing ?? null });
}

// Bounded, secret-free rendering of one table finding. A finding is a field
// name, an index and two small values — never a whole run record.
function describeFinding(finding) {
  if (!isRecord(finding)) return 'malformed finding';
  const field = String(finding.field ?? finding.code ?? 'unknown');
  const index = finding.index === undefined ? '' : `#${String(finding.index)} `;
  const expected = finding.expected === undefined ? '' : ` expected=${JSON.stringify(finding.expected)}`;
  const observed = finding.observed === undefined ? '' : ` observed=${JSON.stringify(finding.observed)}`;
  return `${index}${field}:${expected}${observed}`;
}

// The content digest of a run's DECISION, deliberately excluding run id, pid,
// executor, nonce, timestamps, per-trial provenance and latency. That exclusion
// is what makes A3 expressible in both directions: two process-separated runs
// must AGREE on the decision while differing in identity, and the identical-
// wrong control must be able to leave the digests equal while both runs carry
// the same corruption. A digest that hashed the run id would be equal only when
// the two runs were the same execution, which is the opposite of the property.
const DECISION_TRIAL_FIELDS = Object.freeze(['trial', 'status', 'outcome', 'metric', 'numerator', 'denominator', 'seeds']);

function decisionProjection(run) {
  return {
    trials: (Array.isArray(run?.trials) ? run.trials : [])
      .filter((trial) => isRecord(trial))
      .map((trial) => {
        const projected = {};
        for (const field of DECISION_TRIAL_FIELDS) projected[field] = readField(trial, field) ?? null;
        return projected;
      }),
    codes: isRecord(run?.codes) ? run.codes : {},
    counters: isRecord(run?.counters) ? run.counters : (isRecord(run?.hardCounters) ? run.hardCounters : {}),
    metric: isRecord(run?.metric) ? run.metric : null,
  };
}

function runDigest(run) {
  const declared = isRecord(run?.digests)
    ? (run.digests.content ?? run.digests.decision ?? run.digests.run)
    : undefined;
  if (typeof declared === 'string' && declared !== '') return declared;
  try {
    return canonicalDigest(decisionProjection(run));
  } catch (error) {
    throw new MalformedResult(
      'RUN_RECORD_NOT_CANONICAL',
      `canonicalDigest refused the run record: ${String(error?.code ?? 'NON_CANONICAL_VALUE')}`,
    );
  }
}

/**
 * The single place a TRIAL verdict is named. Fail-closed by construction.
 * @param {object} trial `{trial, status, seedBinding, holdoutBinding,
 *   budgetBinding, evaluatorBinding, ...}` from a run record.
 * @returns {{verdict: string, status: string, reasons: ReadonlyArray<string>}}
 *   `verdict` is a member of the two-value `TRIAL_VERDICTS`. `ALLOW` requires
 *   `status === 'RESOLVED'` and all four bindings present; every other status
 *   (SKIPPED, UNRESOLVED, INFRA_ERROR, NOT_MEASURED) and every missing binding
 *   yields `VIOLATION` with the missing requirement named in `reasons`.
 */
export function resolveTrialVerdict(trial) {
  const record = isRecord(trial) ? trial : {};
  const reasons = [];
  const status = readField(record, 'status');
  const trialId = readField(record, 'trial') ?? readField(record, 'trial_id') ?? readField(record, 'index');
  if (trialId === undefined || trialId === null || trialId === '') reasons.push('TRIAL_ID_ABSENT');

  if (status === undefined || status === null || status === '') {
    reasons.push('TRIAL_STATUS_ABSENT');
  } else if (typeof status !== 'string' || !STATUSES.includes(status)) {
    reasons.push(`TRIAL_STATUS_UNKNOWN:${String(status)}`);
  } else if (status !== RESOLVED) {
    // A skipped, unresolved, infra-failed or unmeasured trial is a VIOLATION.
    // It is never an ALLOW and it is never dropped from the count.
    reasons.push(`TRIAL_NOT_RESOLVED:${status}`);
  }

  for (const binding of BINDINGS) {
    // One field, two spellings: the flat camelCase member and the key under
    // `bindings`. The evaluator binding may additionally be presented as the
    // evaluator record itself, because deleting the evaluator must remove the
    // binding (control `missing_evaluator`, probe P6), which it does.
    const container = readField(record, 'bindings');
    const raw = readField(record, binding.name)
      ?? (isRecord(container) ? (container[binding.nested] ?? undefined) : undefined)
      ?? (binding.name === 'evaluatorBinding' ? readField(record, 'evaluator') : undefined);
    if (raw === undefined || raw === null) {
      reasons.push(`MISSING_${binding.reason}`);
    } else if (!bindingPresent(raw)) {
      reasons.push(`UNSATISFIED_${binding.reason}`);
    } else {
      const missing = BINDING_CHECKS[binding.name](raw);
      if (missing !== null) reasons.push(`${binding.reason}_UNSATISFIED:${missing}`);
    }
  }

  // P6 / PR8: the CALIBRATION decides whether the evaluator may be used, not
  // only its `status` member. The previous rule read `status === 'NOT_MEASURED'`
  // and nothing else, so a record declaring
  // `evaluator_independence: {independent_evaluators: 0, blind_to_producer:
  // false}` while carrying `status: 'MEASURED'` was an ALLOW. The guard
  // already existed — `assertEvaluatorPresent`, which the trial loop called and
  // the verdict loop did not — so the fix is to call it HERE, where the verdict
  // is named, and to translate its refusal into a named reason.
  const calibration = readField(record, 'calibration');
  try {
    assertEvaluatorPresent(readField(record, 'evaluator') ?? readField(record, 'evaluatorBinding') ?? null, calibration);
  } catch (error) {
    reasons.push(`EVALUATOR_NOT_INDEPENDENT:${String(error?.code ?? 'EVALUATOR_ABSENT')}`);
  }
  if (isRecord(calibration) && calibration.status === 'NOT_MEASURED') {
    const why = typeof calibration.not_measured_reason === 'string' ? calibration.not_measured_reason : 'unspecified';
    reasons.push(`CALIBRATION_NOT_MEASURED:${why}`);
  }

  const causalRefusal = causalClaimRefusal(record);
  if (causalRefusal !== null) reasons.push(causalRefusal);

  const verdict = reasons.length === 0 && status === RESOLVED ? ALLOW : VIOLATION;
  if (!VERDICTS.includes(verdict)) {
    // Unreachable while the closed set is the frozen one; a hard throw rather
    // than a default, so a widened vocabulary can never quietly widen the
    // decision.
    throw new BlockedPolicy('VERDICT_OUTSIDE_CLOSED_SET', `resolved verdict ${verdict} is not in the closed trial-verdict set`);
  }
  return { verdict, status: typeof status === 'string' ? status : 'UNKNOWN', reasons: Object.freeze(reasons) };
}

// A4, per trial. Returns a reason string when the trial CLAIMS a causal
// conclusion its ground truth does not support, and null when it does not
// claim one. A claim with an unrecognised label is NOT non-causal: it is
// unproven, and an unproven claim is refused.
function causalClaimRefusal(record) {
  // The SCHEMA shape first. contracts/hypothesis-card.schema.json places the
  // claim at `proposed_relation.causal_assertion` and nothing is expressed as
  // `causal_claim`, so a record carrying the card — which is how every card the
  // track produces travels — was read as making no claim at all (PR7, SD-06).
  // `classifyCardRelation` is the same classifier the A4 guard uses, so the
  // comparator, the expected-value table and the label-substitution control
  // cannot classify one card three ways.
  // The card is read from a CLOSED set of the spellings a record may use for
  // it, and the record itself counts as the card when it IS one. Reading only
  // `card` meant a trial that carried the same document under
  // `hypothesis_card` made no claim at all and was an ALLOW (S3): a rename is
  // not a defence, and the comparator must not be the component a rename
  // defeats.
  const card = [readField(record, 'card'), readField(record, 'hypothesis_card'), readField(record, 'hypothesisCard'),
    readField(record, 'proposed_relation') !== undefined ? record : undefined]
    .find((candidate) => isRecord(candidate) && (candidate.proposed_relation !== undefined || candidate.card_type !== undefined));
  if (isRecord(card)) {
    const classification = classifyCardRelation(card);
    if (classification.refusalCode !== null) {
      return `CAUSAL_CLAIM_UNSUPPORTED:${classification.refusalCode.split(':').slice(1).join(':') || classification.refusalCode}`;
    }
  }
  // The provenance LABEL is read from every spelling the record may use for
  // it. Reading only `provenance_label` meant renaming the member to `label`
  // removed the claim from the comparator's view entirely (S3), and this
  // function's own rule — an UNRECOGNISED label is a claim to be supported,
  // never a non-claim — only bites when the label is read at all.
  //
  // The bare `label` member is AMBIGUOUS in this vocabulary and the ambiguity is
  // resolved rather than papered over: a RUN record uses `label` for its own
  // letter ('a' / 'b'), so a run record's bare `label` is read only when it is a
  // member of one of the closed label vocabularies. On any other record — a
  // TRIAL, which carries no `raw_run_id` — a bare `label` is read as the
  // provenance label whatever it says, which is what closes the rename bypass.
  // Getting this wrong in the other direction produced a real false positive: the
  // delivered run record's `label: 'A'` was read as an unrecognised claim and
  // every run was refused for a causal claim it never made.
  const bareLabel = readField(record, 'label');
  const isRunRecord = typeof readField(record, 'raw_run_id') === 'string' || typeof readField(record, 'commit_sha') === 'string';
  const bareLabelIsVocabulary = typeof bareLabel === 'string' && bareLabel !== ''
    && (CAUSAL_LABELS.has(bareLabel.toUpperCase())
      || PRODUCEABLE_LABELS.has(bareLabel.toUpperCase())
      || OBSERVATIONAL.includes(bareLabel.toUpperCase()));
  const provenance = [readField(record, 'provenance_label'), readField(record, 'provenanceLabel'),
    readField(record, 'claim_label'), readField(record, 'claimLabel'),
    (bareLabelIsVocabulary || !isRunRecord) ? bareLabel : undefined]
    .find((candidate) => typeof candidate === 'string' && candidate !== '');
  const provenanceLabel = typeof provenance === 'string' ? provenance.toUpperCase() : null;
  const provenanceClaims = provenanceLabel !== null
    && (CAUSAL_LABELS.has(provenanceLabel)
      || (!PRODUCEABLE_LABELS.has(provenanceLabel) && !OBSERVATIONAL.includes(provenanceLabel)));
  const claimed = readField(record, 'causal_claim') === true
    || readField(record, 'claimed_verdict') === 'CAUSAL'
    || (typeof readField(record, 'inference_mode') === 'string' && readField(record, 'inference_mode').toUpperCase() === 'CAUSAL')
    || (isRecord(readField(record, 'proposed_relation')) && readField(readField(record, 'proposed_relation'), 'causal_assertion') === true)
    || provenanceClaims;
  if (!claimed) return null;
  if (provenanceClaims && provenanceLabel !== null && !CAUSAL_LABELS.has(provenanceLabel)) {
    return `CAUSAL_CLAIM_UNSUPPORTED:unrecognised_provenance_label:${provenanceLabel}`;
  }
  const strength = readField(record, 'relation_strength');
  const evidence = readField(record, 'causal_evidence');
  const hasEvidence = (Array.isArray(evidence) && evidence.length > 0)
    || (isRecord(evidence) && Object.keys(evidence).length > 0);
  if (strength === undefined || strength === null) return 'CAUSAL_CLAIM_UNSUPPORTED:no_relation_strength';
  if (OBSERVATIONAL.includes(strength)) return `CAUSAL_CLAIM_UNSUPPORTED:${strength}`;
  if (readField(record, 'causal_assertion') !== true) return `CAUSAL_CLAIM_UNSUPPORTED:${strength}:no_causal_assertion`;
  if (!hasEvidence) return `CAUSAL_CLAIM_UNSUPPORTED:${strength}:no_evidence`;
  return null;
}

/**
 * P6: assert the evaluator exists and is independent. Resolves the trial to
 * NOT_MEASURED rather than to a number when independence cannot be shown.
 * @param {object|null} evaluator The evaluator record, or null/absent.
 * @param {object} calibration A contracts/calibration-record.schema.json
 *   document carrying `evaluator_independence` and `not_measured_reason`.
 * @returns {object} `{present: true, independent: true, blindToProducer: true}`
 *   when the evaluator may be used to decide a trial.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'EVALUATOR_NOT_INDEPENDENT' when the evaluator is absent, when
 *   `evaluator_independence.independent_evaluators < 1`, or when
 *   `evaluator_independence.blind_to_producer === false`. The caller resolves
 *   the trial to NOT_MEASURED with `not_measured_reason:
 *   'evaluator_not_independent'` — an exact in-contract enum value — which
 *   `resolveTrialVerdict` then scores as VIOLATION.
 */
export function assertEvaluatorPresent(evaluator, calibration) {
  if (!isRecord(evaluator)) {
    throw new BlockedPolicy(
      'EVALUATOR_NOT_INDEPENDENT',
      'no evaluator record was presented; resolve the trial to NOT_MEASURED with not_measured_reason evaluator_not_independent',
    );
  }
  const identity = evaluator.evaluator_id ?? evaluator.id;
  if (typeof identity !== 'string' || identity === '') {
    throw new BlockedPolicy(
      'EVALUATOR_NOT_INDEPENDENT',
      'the evaluator record carries no identity; an evaluator that cannot be named cannot be shown to be independent',
    );
  }
  const independence = isRecord(calibration) ? calibration.evaluator_independence : undefined;
  if (!isRecord(independence)) {
    throw new BlockedPolicy(
      'EVALUATOR_NOT_INDEPENDENT',
      'the calibration record carries no evaluator_independence block; independence is unmeasured, not assumed',
    );
  }
  const count = independence.independent_evaluators;
  if (!Number.isInteger(count) || count < 1) {
    throw new BlockedPolicy(
      'EVALUATOR_NOT_INDEPENDENT',
      `evaluator_independence.independent_evaluators=${String(count)}; fewer than one independent evaluator is not an evaluation`,
    );
  }
  if (independence.blind_to_producer !== true) {
    throw new BlockedPolicy(
      'EVALUATOR_NOT_INDEPENDENT',
      'evaluator_independence.blind_to_producer is not true; an evaluator that sees the producer is the producer',
    );
  }
  return { present: true, independent: true, blindToProducer: true };
}

/**
 * The frozen decision on a measured interval. Pure arithmetic over
 * preregistered constants: the noise band and the interval bounds are compared
 * against the observation, and the rule is the one published in the
 * preregistration. No clock, no host state, no latency.
 * @param {{observed: number, lower: number, upper: number, noiseBand: number, rule: object}} args
 * @param {number} args.observed The measured value.
 * @param {number} args.lower Lower bound of the preregistered interval.
 * @param {number} args.upper Upper bound of the preregistered interval.
 * @param {number} args.noiseBand The preregistered noise band. An interval
 *   inside it is a NULL result, not a negative one.
 * @param {object} args.rule The preregistered decision rule, including the
 *   multiplicity correction applied over the DECLARED comparison list.
 * @returns {{decision: string, insideNoiseBand: boolean, intervalClearsNoise: boolean}}
 *   `decision` is a member of RESEARCH_OUTCOMES: POSITIVE, NEGATIVE, NULL,
 *   INFRA or UNRESOLVED. A negative and a null result are different answers
 *   and are never merged.
 */
export function decisionFromInterval({ observed, lower, upper, noiseBand, rule } = {}) {
  if (!isRecord(rule)) {
    throw new MalformedResult(
      'DECISION_RULE_ABSENT',
      'decisionFromInterval was called without the preregistered decision rule; an uncorrected decision is not a decision',
    );
  }
  for (const [name, value] of [['observed', observed], ['lower', lower], ['upper', upper], ['noiseBand', noiseBand]]) {
    if (!finiteNumber(value)) {
      throw new MalformedResult(
        'INTERVAL_NOT_MEASURED',
        `${name} is not a finite number (${String(value)}); not measured is not zero and is never treated as a pass`,
      );
    }
  }
  if (lower > upper) {
    throw new MalformedResult('INTERVAL_INVERTED', `interval lower=${lower} is above upper=${upper}`);
  }
  if (noiseBand < 0) {
    throw new MalformedResult('NOISE_BAND_NEGATIVE', `noiseBand=${noiseBand} is negative; a negative noise band inverts every decision`);
  }
  const alpha = rule.alpha;
  if (!finiteNumber(alpha) || alpha <= 0 || alpha >= 1) {
    throw new MalformedResult(
      'ALPHA_ABSENT_OR_INVALID',
      `the preregistration must publish a family-wise alpha; got ${String(alpha)}`,
    );
  }
  const method = typeof rule.method === 'string' ? rule.method.toUpperCase().replace(/[^A-Z_]/g, '') : '';
  if (!['BONFERRONI', 'HOLM', 'HOLM_BONFERRONI'].includes(method)) {
    throw new MalformedResult('MULTIPLICITY_METHOD_UNKNOWN', `unknown multiplicity method ${String(rule.method)}`);
  }
  const nullValue = finiteNumber(rule.null_value) ? rule.null_value : 0;
  const confidence = finiteNumber(rule.confidence) ? rule.confidence : 0.95;
  if (confidence <= 0 || confidence >= 1) {
    throw new MalformedResult('CONFIDENCE_INVALID', `confidence=${confidence} is outside (0, 1)`);
  }
  // A hypothesis the run declared as two-sided accepts a significant effect in
  // either direction as support for the EXISTENCE of the effect; it never
  // decides the direction the effect points.
  const direction = rule.direction === 'decrease' ? 'decrease' : 'increase';
  const twoSided = rule.direction === 'two_sided';

  const report = {
    estimate: round6(observed),
    interval: { lower: round6(lower), upper: round6(upper), confidence },
    nullValue,
    noiseBand,
    method: method === 'HOLM' ? 'holm_bonferroni' : method.toLowerCase(),
    insideNoiseBand: false,
    intervalClearsNoise: false,
    decision: 'UNRESOLVED',
    reason: null,
    correction: null,
  };

  // 1. A trial that did not resolve decides nothing. The interval is still
  //    reported, so an undecided measurement is visible rather than absent.
  const status = typeof rule.status === 'string' ? rule.status : RESOLVED;
  if (status !== RESOLVED) {
    report.decision = status === 'INFRA_ERROR' ? 'INFRA' : 'UNRESOLVED';
    report.reason = `trial_status:${status}`;
    if (!OUTCOMES.includes(report.decision)) {
      throw new BlockedPolicy('OUTCOME_OUTSIDE_CLOSED_SET', `derived outcome ${report.decision} is not in RESEARCH_OUTCOMES`);
    }
    return Object.freeze(report);
  }

  // 2. The null value and the preregistered noise band.
  const bandLow = nullValue - noiseBand;
  const bandHigh = nullValue + noiseBand;
  const insideNoiseBand = lower >= bandLow && upper <= bandHigh;
  const clearsNoise = lower > bandHigh || upper < bandLow;
  const excludesNull = lower > nullValue || upper < nullValue;
  report.insideNoiseBand = insideNoiseBand;
  report.intervalClearsNoise = clearsNoise;

  if (!excludesNull && insideNoiseBand) {
    report.decision = 'NULL';
    report.reason = 'interval_inside_noise_band';
    return Object.freeze(report);
  }
  if (!excludesNull) {
    report.decision = 'UNRESOLVED';
    report.reason = 'interval_straddles_null_outside_noise_band';
    return Object.freeze(report);
  }

  // 3. The declared comparison family. `rule.comparisons` is the preregistered
  //    list; the observation scored by THIS call joins it when it is not
  //    already a member, so the correction can never be computed over a
  //    smaller family than the preregistration declared.
  // The declared family, NORMALISED HERE. The preregistration's own legal
  // spelling is a list of trial-id STRINGS (`assertMultiplicityRule` runs every
  // member through `requireString`), so a filter that kept only records
  // discarded the whole family and the correction silently ran over m = 1
  // (SD-03). A string member becomes `{id}`, which is the same comparison
  // carrying its identity and nothing else.
  const declared = (Array.isArray(rule.comparisons) ? rule.comparisons : [])
    .map((member) => (isRecord(member) ? member : (typeof member === 'string' && member !== '' ? { id: member } : null)))
    .filter((member) => member !== null);
  if (declared.length === 0) {
    // The header's promise, implemented: an absent DECLARED family is a
    // MalformedResult, never a silent uncorrected test.
    throw new MalformedResult(
      'MULTIPLICITY_FAMILY_ABSENT',
      'the preregistered comparison family is empty; a decision computed over m = 1 is not multiplicity-corrected',
    );
  }
  // The subject, and WHETHER IT IS THE POOLED AGGREGATE OF THE DECLARED FAMILY
  // rather than a comparison of its own. A campaign rate is a linear
  // combination of the declared trials' own counts: it is not a fourth
  // hypothesis, and counting it as one both inflates `m` and silently decides a
  // family the preregistration never froze (S7). The caller says which of the
  // two it is, and the correction block reports the EFFECTIVE family size so
  // the number cannot be read off the declared list by accident.
  const pooledAggregate = rule.subject_is_pooled_aggregate === true;
  const subject = pooledAggregate
    ? { id: declared[0].id, observed, lower, upper }
    : { id: typeof rule.subject === 'string' ? rule.subject : 'track_metric', observed, lower, upper };

  // The family is the DECLARED comparison list. The observation scored by this
  // call joins it ONLY when it is not already one of its members: counting it
  // twice would inflate `m` and make the correction stricter than the
  // preregistration, and dropping a genuinely undeclared comparison would make
  // it weaker. IDENTITY is by `id` FIRST and by interval only as a fallback:
  // a family declared as trial ids carries no intervals, so matching on
  // intervals alone always failed to find the subject and silently doubled the
  // family (SD-03).
  let family = declared;
  let subjectIndex = declared.findIndex((member) => member.id !== undefined && subject.id !== undefined
    && String(member.id) === String(subject.id));
  if (subjectIndex < 0) {
    subjectIndex = declared.findIndex((member) => sameMembers(
      [{ lower: member?.lower, upper: member?.upper }],
      [{ lower, upper }],
    ));
  }
  if (subjectIndex < 0 && !pooledAggregate) {
    family = [...declared, subject];
    subjectIndex = family.length - 1;
  }
  if (subjectIndex < 0) {
    // The pooled aggregate of a family whose members carry no interval of
    // their own: every member inherits the aggregate's bound, so the aggregate
    // is scored as the FIRST declared member and the family stays the one the
    // preregistration froze. Reported explicitly, never silently.
    subjectIndex = 0;
  }
  const subjectInDeclaredFamily = subjectIndex >= 0 && family === declared && family[subjectIndex] !== subject;

  const pUpperFor = (member) => {
    const memberLower = finiteNumber(member?.lower) ? member.lower : lower;
    const memberUpper = finiteNumber(member?.upper) ? member.upper : upper;
    const memberNull = finiteNumber(member?.null_value) ? member.null_value : nullValue;
    const memberConfidence = finiteNumber(member?.confidence) ? member.confidence : confidence;
    const excludes = memberLower > memberNull || memberUpper < memberNull;
    return excludes ? 1 - memberConfidence : 1;
  };
  const pUppers = family.map(pUpperFor);
  const m = family.length;
  const pUpper = pUppers[subjectIndex];
  // A declared comparison that carries no interval of its own inherits the
  // subject's, which is the CONSERVATIVE reading: a family member whose p
  // cannot be computed counts as the largest p the family could hold, so the
  // correction is never weaker than the one a fully-specified family would
  // give. It is reported as `inherited: true` in the correction block rather
  // than applied silently.
  const inheritedP = declared.filter((member) => !finiteNumber(member?.lower) || !finiteNumber(member?.upper)).length;

  let rejected = false;
  let step = null;
  // Where the step-down STOPPED, when it stopped without rejecting. The
  // correction block reported `threshold: null` for every unrejected
  // comparison, which reads as "no threshold was ever computed" instead of
  // "the bound was not small enough to pass it" — so a corrected UNRESOLVED
  // could not be re-derived from the record, and a rule that could never have
  // rejected anything looked exactly like a measurement that did not reach
  // significance. `blocking_p` / `blocking_threshold` name the comparison that
  // stopped the step-down and the number it had to beat.
  let blocking = null;
  // A comparison bound that falls EXACTLY on the threshold is decided in its
  // favour, and the decision says so. The epsilon exists because
  // `1 - 0.95` is 0.050000000000000044 in IEEE-754: without it the same
  // preregistered constants would reject on one host and not on the next,
  // which is a wall-clock-class defect in a determinism track. It is 1e-12
  // RELATIVE, far below any statistical meaning, and it is reported as
  // `atBoundary` in the correction block instead of being applied silently.
  const within = (value, threshold) => value <= threshold + Math.abs(threshold) * DECISION_EPSILON;
  if (method === 'BONFERRONI') {
    const threshold = alpha / m;
    step = threshold;
    rejected = within(pUpper, threshold);
    if (!rejected) blocking = { rank: 0, threshold, p: pUpper };
  } else {
    const ordered = pUppers.map((value, index) => ({ value, index })).sort((left, right) => left.value - right.value);
    for (let rank = 0; rank < ordered.length; rank += 1) {
      const threshold = alpha / (m - rank);
      if (!within(ordered[rank].value, threshold)) {
        blocking = { rank, threshold, p: ordered[rank].value };
        break;
      }
      step = threshold;
      if (ordered[rank].index === subjectIndex) rejected = true;
    }
  }
  // WHAT THE FROZEN RULE COULD EVER HAVE DECIDED, from the constants alone.
  // A comparison bound inherited from a `c`-level interval is `1 - c`, so a
  // family of `m` members with `1 - c > alpha / m` can NEVER reject, whatever
  // the measurement is. That is a fact about the PUBLISHED RULE, not about the
  // effect, and it is reported rather than left to be inferred: an UNRESOLVED
  // produced by a rule that could not have said otherwise is a different
  // statement from a measurement that did not clear the corrected level, and
  // collapsing the two is how a null gets dressed up as a finding. With this
  // preregistration's constants (alpha 0.05, confidence 0.95, three declared
  // comparisons) `1 - c = 0.05 > 0.05/3`, so `never_rejects` is true and the
  // honest reading is "this rule can only answer NULL or UNRESOLVED". Raising
  // the published confidence to `1 - alpha / m` is a PREREGISTRATION change
  // (W2's file), not a comparator change, and is reported to D as such.
  const rejectionFloor = alpha / m;
  const maxPBound = Math.max(...pUppers);
  const neverRejects = maxPBound > rejectionFloor + Math.abs(rejectionFloor) * DECISION_EPSILON;
  report.correction = {
    method: report.method,
    alpha,
    comparisons: m,
    // The EFFECTIVE family, next to the DECLARED one. `comparisons` alone was
    // read by nobody (S7): a family the comparator had widened past the
    // preregistered one looked exactly like a family the preregistration
    // declared. `effective_family_size` is the number a caller checks against
    // the preregistered `family_size`, and `family_widened` says whether the
    // two disagree.
    effective_family_size: family.length,
    // `declared` stays the COUNT the members `declared_members` carries, so an
    // existing reader of the block keeps the number it was reading.
    declared: declared.length,
    declared_members: declared,
    subject: subject.id,
    subject_role: pooledAggregate ? 'POOLED_AGGREGATE_OF_DECLARED_FAMILY' : 'DECLARED_COMPARISON',
    subject_in_declared_family: subjectInDeclaredFamily,
    family_widened: family.length !== declared.length,

    inherited_p_bound: inheritedP,
    pUpper: round6(pUpper),
    threshold: step === null ? null : round6(step),
    rejected,
    atBoundary: rejected && Math.abs(pUpper - step) <= Math.abs(step) * DECISION_EPSILON,
    blocking_rank: blocking === null ? null : blocking.rank,
    blocking_threshold: blocking === null ? null : round6(blocking.threshold),
    blocking_p: blocking === null ? null : round6(blocking.p),
    rejection_floor: round6(rejectionFloor),
    max_p_bound: round6(maxPBound),
    never_rejects: neverRejects,
  };

  // 4. The decision. Only a corrected, significant effect in the
  //    preregistered direction is POSITIVE.
  if (!rejected) {
    report.decision = 'UNRESOLVED';
    // The `reason` string is stable across runs and across releases because it
    // is what the aggregator writes into the evidence record; the WHY is in
    // `correction.blocking_*` and `correction.never_rejects`, which is where a
    // reader re-derives the decision from the published constants.
    report.reason = 'not_significant_after_multiplicity_correction';
    return Object.freeze(report);
  }
  const sign = lower > nullValue ? 1 : -1;
  const inHypothesis = twoSided || (direction === 'decrease' ? sign < 0 : sign > 0);
  report.decision = inHypothesis ? 'POSITIVE' : 'NEGATIVE';
  report.reason = inHypothesis ? 'clears_noise_and_clears_corrected_null' : 'significant_effect_in_the_other_direction';
  if (!OUTCOMES.includes(report.decision)) {
    throw new BlockedPolicy('OUTCOME_OUTSIDE_CLOSED_SET', `derived outcome ${report.decision} is not in RESEARCH_OUTCOMES`);
  }
  return Object.freeze(report);
}

/**
 * WHAT THE PUBLISHED RULE COULD EVER DECIDE, from the preregistered constants
 * alone, and independently of any measurement.
 *
 * `decisionFromInterval` reports the same arithmetic inside its `correction`
 * block, but that block is only reached once the interval clears the null value
 * — and a rule that cannot reject anything means the interval NEVER clears it.
 * The two facts hide each other: a campaign that could not be decided reported
 * no correction at all, so a reader had to infer the impossibility from the
 * UNRESOLVED (S1). This helper is pure arithmetic over `alpha`, `confidence` and
 * the declared family size, and it is called on EVERY campaign so the
 * impossibility is a named limit rather than an inference.
 *
 * A comparison bound inherited from a `c`-level interval is `1 - c`, so a family
 * of `m` members with `1 - c > alpha / m` can NEVER reject, whatever is
 * measured. Fixing it is a PREREGISTRATION change — the published confidence has
 * to rise to `1 - alpha / m` — and never a comparator change.
 *
 * @param {{alpha: number, confidence: number, familySize: number}} args
 * @returns {{rejection_floor: number, max_p_bound: number, never_rejects: boolean,
 *   can_only_answer: string, feasible: boolean}} `can_only_answer` is
 *   `'NULL_OR_UNRESOLVED'` when `never_rejects` is true, and `'ANY_OUTCOME'` —
 *   i.e. no restriction — otherwise.
 */
export function ruleFeasibility({ alpha, confidence, familySize } = {}) {
  const a = finiteNumber(alpha) ? alpha : null;
  const c = finiteNumber(confidence) ? confidence : null;
  const m = Number.isInteger(familySize) && familySize > 0 ? familySize : null;
  if (a === null || c === null || m === null) {
    return {
      rejection_floor: null,
      max_p_bound: null,
      never_rejects: null,
      can_only_answer: 'UNDECLARED_RULE',
      feasible: false,
      note: 'the rule does not publish a family-wise alpha, a confidence and a family size, so what it could ever decide cannot be stated',
    };
  }
  const rejectionFloor = a / m;
  const maxPBound = 1 - c;
  const neverRejects = maxPBound > rejectionFloor + Math.abs(rejectionFloor) * DECISION_EPSILON;
  return {
    rejection_floor: round6(rejectionFloor),
    max_p_bound: round6(maxPBound),
    never_rejects: neverRejects,
    can_only_answer: neverRejects ? 'NULL_OR_UNRESOLVED' : 'ANY_OUTCOME',
    feasible: neverRejects === false,
    note: neverRejects
      ? `1 - c = ${String(round6(maxPBound))} > alpha/m = ${String(round6(rejectionFloor))} with m=${m}; no measurement can clear the corrected level, so this rule can only answer NULL or UNRESOLVED`
      : `1 - c = ${String(round6(maxPBound))} <= alpha/m = ${String(round6(rejectionFloor))} with m=${m}; the rule can reject`,
  };
}

/**
 * P2: the disclosure block that proves every seed was reported. A run that
 * names a "best" seed must present this block over ALL seeds; a block that
 * covers fewer seeds than the run actually used is an undisclosed selection,
 * and the comparator scores it as a failed check rather than a footnote.
 * @param {string} name The metric the selection was made on, or the name of
 *   the selection itself ('best_seed'). Recorded verbatim so the evidence
 *   names what was selected.
 * @param {ReadonlyArray<number|string>} seeds EVERY seed the run used, in
 *   order. Not the winner, not a sample, not a summary: the whole set.
 * @returns {{name: string, seeds: ReadonlyArray<number|string>, count: number,
 *   disclosed: true, selection: null}} The disclosure record. `disclosed` is
 *   the literal `true`: there is no undisclosed form of this record.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when `seeds` is
 *   not a non-empty array — an empty seed set is not a disclosure.
 */
export function bestSeedDisclosure(name, seeds) {
  if (typeof name !== 'string' || name === '') {
    throw new MalformedResult('SELECTION_NAME_ABSENT', 'a selection disclosure must name what was selected');
  }
  if (!Array.isArray(seeds) || seeds.length === 0) {
    throw new MalformedResult('SELECTION_SEEDS_ABSENT', `the selection "${name}" discloses no seeds; an undisclosed selection is a violation`);
  }
  for (const [index, seed] of seeds.entries()) {
    const acceptable = typeof seed === 'number' ? Number.isFinite(seed) : (typeof seed === 'string' && seed !== '');
    if (!acceptable) {
      throw new MalformedResult('SELECTION_SEED_INVALID', `seeds[${index}] is neither a finite number nor a non-empty string`);
    }
  }
  return {
    name,
    seeds: Object.freeze([...seeds]),
    count: seeds.length,
    disclosed: true,
    selection: null,
  };
}

// A run reports a selection under any of these members. Finding one without a
// matching full disclosure is the violation.
const SELECTION_FIELDS = Object.freeze(['best_seed', 'selected_seed', 'best_seed_id', 'selection']);

// The comparison-identity fields must be present on BOTH runs, but a value may
// be absent on one side without becoming a collision: absent is reported once,
// by the provenance check above.
function readBoth(runA, runB, field) {
  return [readField(runA, field), readField(runB, field)];
}
/**
 * A3: the parallel-track comparison. The pass criterion is "both runs agree
 * with the FROZEN EXPECTED-VALUE TABLE **and** the controls flip". `A === B`
 * is an ADDITIONAL condition, never the criterion — two runs that agree can
 * agree on the same wrong answer, so the identical-wrong control is what
 * proves the table is load-bearing.
 * @param {{runA: object, runB: object, prereg: object, expected: object, base?: object}} args
 * @param {object} args.runA Run A's record.
 * @param {object} args.runB Run B's record, with a DIFFERENT raw run id and
 *   nonce.
 * @param {object} args.prereg The preregistration in force.
 * @param {object} args.expected The frozen table from expected-values.mjs.
 * @param {object} [args.base] `{commit_sha, tree_sha}` RESOLVED BY THE CALLER
 *   from the real repository. E8: the base check used to require only that the
 *   two runs AGREED on three non-empty strings, so a run could declare any
 *   commit it liked and the binding was self-asserted. This module stays pure
 *   (no `child_process`, no clock, no filesystem — that purity is what makes the
 *   identical-wrong control cheap), so the resolution happens once in
 *   `scripts/s2-008-harness.mjs` and the resolved values are handed in. When
 *   they are absent the base is UNVERIFIED and that is a NAMED FAILURE, not a
 *   proof.
 * @returns {{failures: ReadonlyArray<object>, limits: ReadonlyArray<object>,
 *   proofStatus: ReadonlyArray<object>, digestsEqual: boolean,
 *   findingsA: ReadonlyArray<object>, findingsB: ReadonlyArray<object>,
 *   identicalWrongFindings: object}} The inputs for `resolveVerdict`, plus the
 *   per-run table findings and the identical-wrong result. `digestsEqual` is
 *   reported and is NOT sufficient on its own.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when a run's
 *   provenance (commit SHA, tree SHA, raw run id) does not match the other.
 */
export function compareParallelTrack({ runA, runB, prereg, expected, base } = {}) {
  if (!isRecord(runA) || !isRecord(runB)) {
    throw new MalformedResult('RUN_RECORD_ABSENT', 'compareParallelTrack needs two run records; one run is not a parallel track');
  }
  const table = normaliseTable(expected);
  const registration = isRecord(prereg) ? prereg : {};
  const failures = [];
  const limits = [];
  const proofStatus = [];

  // A5 / A3: both runs must be bound to a base, and to the SAME base. A run
  // that is not bound, or two runs on different bases, are not a comparison —
  // there is nothing to name, so nothing is named.
  for (const [label, run] of [['runA', runA], ['runB', runB]]) {
    for (const field of BINDING_PROVENANCE) {
      const value = readField(run, field);
      if (typeof value !== 'string' || value === '') {
        throw new MalformedResult(
          'RUN_PROVENANCE_UNBOUND',
          `${label}.${field} is absent; an unbound artefact is not comparable (commit SHA, tree SHA and raw run id are all required)`,
        );
      }
    }
  }
  for (const field of ['commit_sha', 'tree_sha']) {
    const [left, right] = readBoth(runA, runB, field);
    if (left !== right) {
      throw new MalformedResult('BASE_DIVERGENCE', `runA.${field} and runB.${field} differ; a comparison across two bases decides nothing`);
    }
  }

  // A5, second half (E8): the declared SHAs are now RESOLVED against the real
  // repository by the caller. Two runs that agree with each other about a base
  // they both invented are not on a base at all.
  const resolvedBase = isRecord(base) ? base : null;
  const baseVerified = resolvedBase !== null
    && typeof resolvedBase.commit_sha === 'string' && resolvedBase.commit_sha !== ''
    && typeof resolvedBase.tree_sha === 'string' && resolvedBase.tree_sha !== '';
  if (!baseVerified) {
    failure(failures, 'base_unverified', 'no resolved base was supplied; the two runs agree about a commit and a tree only because they both declared the same one');
  }
  for (const field of ['commit_sha', 'tree_sha']) {
    if (baseVerified && readField(runA, field) !== resolvedBase[field]) {
      failure(failures, 'base_mismatch', `runA.${field} is ${String(readField(runA, field))} while the repository is at ${String(resolvedBase[field])}`);
    }
  }
  // A5, process identity: a raw run id is the id of an actual execution, so it
  // is a value a run cannot legitimately pin to a constant.
  if (readField(runA, 'raw_run_id') === readField(runB, 'raw_run_id')) {
    failure(failures, 'raw_run_id_collision', `both runs report raw_run_id ${String(readField(runA, 'raw_run_id'))}; two executions cannot share one id`);
  }

  // A3: process separation. Decidable, therefore a failure and not a throw.
  for (const field of SEPARATION_FIELDS) {
    const [left, right] = readBoth(runA, runB, field);
    if (left === undefined || right === undefined) {
      if (field === 'nonce') {
        failure(failures, 'run_nonce_unbound', `a run carries no ${field}; two independent executions must each carry their own nonce`);
      }
      continue;
    }
    if (left === right) {
      failure(failures, 'run_manifest_collision', `${field} is identical in both runs (${String(left)}); two independent executions are required`);
    }
  }

  // The preregistration in force, and the digest each run claims to have been
  // produced under. A run that cannot be tied to the registered expectation
  // has nothing to be compared against.
  const preregDigest = registration.preregistration_digest ?? registration.digest;
  let preregistrationBound = typeof preregDigest === 'string' && preregDigest !== '';
  if (!preregistrationBound) {
    failure(failures, 'preregistration_unbound', 'the preregistration in force carries no digest; an unregistered expectation is not a baseline');
  }
  for (const [label, run] of [['runA', runA], ['runB', runB]]) {
    const claimed = readField(run, 'preregistration_digest');
    if (typeof claimed !== 'string' || claimed === '') {
      failure(failures, 'preregistration_unbound', `${label} records no preregistration digest`);
      preregistrationBound = false;
    } else if (preregistrationBound && claimed !== preregDigest) {
      failure(failures, 'preregistration_digest_mismatch', `${label} was produced under a different preregistration digest`);
      preregistrationBound = false;
    }
    const tableDigest = readField(run, 'expected_table_digest');
    if (typeof tableDigest === 'string' && table.digest !== null && tableDigest !== table.digest) {
      failure(failures, 'expected_table_digest_mismatch', `${label} was scored against a different frozen table digest`);
    }
  }

  const perRun = { a: null, b: null };
  const findings = { a: [], b: [] };
  for (const [letter, run] of [['a', runA], ['b', runB]]) {
    findings[letter] = expectedValueIssues(run, letter);
    for (const item of findings[letter]) {
      failure(failures, 'table_disagreement', `run${letter.toUpperCase()}: ${describeFinding(item)}`);
    }
  }

  for (const [letter, run] of [['a', runA], ['b', runB]]) {
    perRun[letter] = scoreRun({ letter, run, prereg: registration, table, failures, limits });
  }

  const digestsEqual = perRun.a.digest === perRun.b.digest;
  const bothNonEmpty = findings.a.length > 0 && findings.b.length > 0;
  const identicalWrongFindings = {
    findings_a: findings.a,
    findings_b: findings.b,
    findings_a_count: findings.a.length,
    findings_b_count: findings.b.length,
    digests_still_equal: digestsEqual,
    both_non_empty: bothNonEmpty,
    conclusion: bothNonEmpty && digestsEqual
      ? 'the frozen table is load-bearing: identical decision digests, non-empty findings'
      : (digestsEqual
        ? 'the runs agree with the frozen table; agreement alone is not a pass and the controls must still flip'
        : 'the runs disagree: the table is not the only thing under test here'),
  };

  proof(proofStatus, 'base_binding', baseVerified ? 'SATISFIED' : 'UNMET', {
    commit_sha: readField(runA, 'commit_sha'),
    tree_sha: readField(runA, 'tree_sha'),
    resolved_commit_sha: resolvedBase === null ? null : (resolvedBase.commit_sha ?? null),
    resolved_tree_sha: resolvedBase === null ? null : (resolvedBase.tree_sha ?? null),
  }, baseVerified ? [] : ['base_unresolved']);
  proof(
    proofStatus,
    'process_separation',
    failures.some((item) => item.code === 'run_manifest_collision' || item.code === 'run_nonce_unbound') ? 'UNMET' : 'SATISFIED',
    { fields: [...SEPARATION_FIELDS] },
    failures.filter((item) => item.code === 'run_manifest_collision' || item.code === 'run_nonce_unbound').map((item) => item.code),
  );
  proof(
    proofStatus,
    'preregistration_bound',
    preregistrationBound ? 'SATISFIED' : 'UNMET',
    { digest: preregDigest ?? null },
    preregistrationBound ? [] : ['preregistration_digest'],
  );
  proof(
    proofStatus,
    'table_agreement',
    findings.a.length === 0 && findings.b.length === 0 ? 'SATISFIED' : 'UNMET',
    { findings_a: findings.a.length, findings_b: findings.b.length, table_digest: table.digest },
    [...findings.a, ...findings.b].map((item) => String(item?.code ?? 'finding')).slice(0, 20),
  );
  const seedsOk = perRun.a.seedsComplete && perRun.b.seedsComplete;
  proof(
    proofStatus,
    'seed_set_complete',
    seedsOk ? 'SATISFIED' : 'UNMET',
    { preregistered: perRun.a.preregisteredSeeds, run_a: perRun.a.observedSeeds, run_b: perRun.b.observedSeeds },
    seedsOk ? [] : ['seed_set'],
  );
  const trialsOk = perRun.a.trialViolations.length === 0 && perRun.b.trialViolations.length === 0;
  proof(
    proofStatus,
    'all_trials_resolved',
    trialsOk ? 'SATISFIED' : 'UNMET',
    { run_a: perRun.a.trialViolations.length, run_b: perRun.b.trialViolations.length },
    [...perRun.a.trialViolations, ...perRun.b.trialViolations].map((item) => item.trial).slice(0, 20),
  );
  proof(
    proofStatus,
    'negative_controls',
    perRun.a.controlsFlipped && perRun.b.controlsFlipped ? 'SATISFIED' : 'UNMET',
    { run_a: perRun.a.controls, run_b: perRun.b.controls },
    perRun.a.controlsFlipped && perRun.b.controlsFlipped ? [] : ['controls.allFlipped'],
  );
  for (const letter of ['a', 'b']) {
    const scored = perRun[letter];
    proof(
      proofStatus,
      `metric_decision_run_${letter}`,
      scored.decisionStatus,
      { decision: scored.decision, estimate: scored.metric, interval: scored.interval, correction: scored.correction },
      scored.decisionStatus === 'SATISFIED' ? [] : [scored.decisionReason],
    );
  }

  return {
    failures,
    limits,
    proofStatus,
    digestsEqual,
    findingsA: findings.a,
    findingsB: findings.b,
    identicalWrongFindings,
    // Additive report fields. The seven fields above are the frozen inputs to
    // `resolveVerdict`; everything below exists so the evidence record can be
    // re-derived from this return value instead of from a second pass.
    version: COMPARATOR_VERSION,
    table_digest: table.digest,
    runs: { a: runSummary('runA', runA, perRun.a), b: runSummary('runB', runB, perRun.b) },
  };
}

// The frozen table must be PRESENT. A comparison without it is a comparison of
// two runs to each other, which A3 explicitly refuses.
function normaliseTable(expected) {
  if (!isRecord(expected)) {
    throw new MalformedResult('EXPECTED_TABLE_ABSENT', 'the frozen expected-value table was not supplied; A === B is not a pass criterion');
  }
  const counters = expected.EXPECTED_COUNTERS;
  const decisions = expected.EXPECTED_TRIAL_DECISIONS;
  if (!isRecord(counters) && !Array.isArray(decisions)) {
    throw new MalformedResult(
      'EXPECTED_TABLE_ABSENT',
      'the supplied table carries neither EXPECTED_COUNTERS nor EXPECTED_TRIAL_DECISIONS; it is not the frozen table',
    );
  }
  const declaredDigest = expected.digest ?? expected.EXPECTED_TABLE_DIGEST ?? null;
  return {
    counters: isRecord(counters) ? counters : null,
    decisions: Array.isArray(decisions) ? decisions : null,
    controls: Array.isArray(expected.EXPECTED_CONTROLS) ? expected.EXPECTED_CONTROLS : null,
    metric: isRecord(expected.EXPECTED_METRIC) ? expected.EXPECTED_METRIC : null,
    digest: typeof declaredDigest === 'string' && declaredDigest !== '' ? declaredDigest : null,
  };
}

function runSummary(label, run, scored) {
  return {
    label,
    raw_run_id: readField(run, 'raw_run_id'),
    nonce: readField(run, 'nonce'),
    commit_sha: readField(run, 'commit_sha'),
    tree_sha: readField(run, 'tree_sha'),
    digest: scored.digest,
    trials: scored.trialCount,
    metric: scored.metric,
    interval: scored.interval,
    decision: scored.decision,
    correction: scored.correction,
    // S1: what the published rule could ever decide, reported per run so a
    // reader does not have to infer it from a UNRESOLVED.
    rule_feasibility: scored.rule_feasibility,
    latency: scored.latency,
    decides_on_latency: false,
  };
}

// Everything one run is scored on. Pure with respect to everything outside its
// own record: no clock, no process, no filesystem.
function scoreRun({ letter, run, prereg, table, failures, limits }) {
  const label = `run${letter.toUpperCase()}`;
  const digest = runDigest(run);
  const trials = Array.isArray(run.trials) ? run.trials : null;
  const trialCount = trials === null ? 0 : trials.length;
  const trialViolations = [];
  let seedsComplete = false;
  const observedSeeds = [];
  // PR5: the preregistered set is RE-DERIVED from the frozen `seed_rule` rather
  // than read from a `prereg.seeds` member that no document in the required
  // shape carries — so every comparison below was against an empty list and
  // could not fire. `assertSeedSetFrozen` IS the derivation (it re-derives the
  // plan from the rule and returns it); the same guard is then called for every
  // trial below, so the set used for reporting and the set used for scoring
  // cannot come from two places.
  const observedSeedsFirstPass = (Array.isArray(run.trials) ? run.trials : []).map((trial) => readField(trial, 'seeds'));
  let preregisteredSeeds = [];
  if (prereg.seed_rule !== undefined && observedSeedsFirstPass.some((seeds) => Array.isArray(seeds))) {
    try {
      preregisteredSeeds = [...assertSeedSetFrozen(observedSeedsFirstPass.find((seeds) => Array.isArray(seeds)), prereg)];
    } catch (error) {
      failure(failures, 'seed_substitution', `${label}: the presented seed set is not the preregistered one (${String(error?.code ?? 'SEED_SET_INVALID')})`);
    }
  } else if (Array.isArray(prereg.seeds)) {
    preregisteredSeeds = [...prereg.seeds];
  }
  const preregisteredCount = Number.isInteger(prereg.seed_count) ? prereg.seed_count : preregisteredSeeds.length;

  if (trials === null || trials.length === 0) {
    failure(failures, 'trials_absent', `${label} records no trials; an absent trial set is not a clean result`);
    failure(failures, 'seed_set_incomplete', `${label} ran 0 seeds against a preregistered seed count of ${String(preregisteredCount)}`);
  } else {
    // P2: the presented seed set must equal the PREREGISTERED set, in order.
    // Extra, missing, reordered or a different count are all substitutions,
    // and an incomplete seed set is a violation in its own right.
    for (const trial of trials) {
      const seeds = readField(trial, 'seeds');
      if (Array.isArray(seeds)) observedSeeds.push([...seeds]);
    }
    if (observedSeeds.length > 0 && preregisteredSeeds.length > 0 && !sameMembers(observedSeeds[0], preregisteredSeeds)) {
      failure(failures, 'seed_substitution', `${label}: the recorded seed set differs from the preregistered set (${preregisteredSeeds.length} preregistered, ${observedSeeds[0].length} used)`);
    }
    // PR5: the never-called guard is now CALLED, on every trial, from the one
    // place that scores seeds. It discriminates on membership, order and
    // count, where the only earlier check compared `observedSeeds[0]` against a
    // `prereg.seeds` member the preregistration does not have — so a run that
    // reported four copies of one winning seed, or the right four seeds in the
    // wrong order, or one trial substituted in isolation, produced no failure
    // at all. `assertSeedSetFrozen` re-derives the plan from the frozen
    // `seed_rule` and refuses an extra, a missing, a reordered or a
    // differently-counted set.
    if (prereg.seed_rule !== undefined) {
      for (const [index, trial] of trials.entries()) {
        const seeds = readField(trial, 'seeds');
        if (!Array.isArray(seeds)) continue;
        try {
          assertSeedSetFrozen(seeds, prereg);
        } catch (error) {
          failure(failures, 'seed_substitution', `${label} trial ${String(readField(trial, 'trial') ?? index)}: ${String(error?.code ?? 'SEED_SET_INVALID')} (${String(error?.message ?? error).slice(0, 160)})`);
        }
      }
    }
    const distinctSeedCounts = [...new Set(observedSeeds.map((seeds) => seeds.length))].sort();
    if ((observedSeeds[0]?.length ?? 0) !== preregisteredCount || distinctSeedCounts.length > 1) {
      failure(failures, 'seed_set_incomplete', `${label}: seed counts per trial ${JSON.stringify(distinctSeedCounts)} do not all equal the preregistered ${String(preregisteredCount)}`);
    } else {
      seedsComplete = true;
    }

    for (const [index, trial] of trials.entries()) {
      // S10: a broken MEASUREMENT is a NAMED failure, never a throw that
      // discards every finding run A already produced. The two neighbouring
      // measurement calls (the latency block and the metric block) are wrapped
      // for exactly this reason; this one was the odd member out, so a trial
      // whose `status` accessor throws escaped `scoreRun`, the exception left
      // `compareParallelTrack` altogether, and the OTHER run's findings were
      // thrown away with it.
      let verdict = null;
      try {
        verdict = resolveTrialVerdict(trial);
      } catch (error) {
        const code = String(error?.code ?? 'TRIAL_VERDICT_UNAVAILABLE');
        trialViolations.push({ trial: readField(trial, 'trial') ?? index, index, reasons: [`TRIAL_VERDICT_UNAVAILABLE:${code}`] });
        failure(failures, 'trial_verdict_unavailable', `${label} trial ${String(readField(trial, 'trial') ?? index)}: the comparator could not name a verdict (${code}); a trial that cannot be scored is a violation, not a missing measurement`);
      }
      if (verdict !== null && verdict.verdict !== ALLOW) {
        const named = { trial: readField(trial, 'trial') ?? index, index, reasons: [...verdict.reasons] };
        trialViolations.push(named);
        failure(failures, 'trial_violation', `${label} trial ${String(named.trial)}: ${verdict.verdict} (${verdict.reasons.join(', ')})`);
      }
      // P6, applied per trial: an evaluator that is absent or not independent
      // is a named failure, never a missing percentage.
      if (isRecord(trial)) {
        try {
          assertEvaluatorPresent(readField(trial, 'evaluator') ?? null, readField(trial, 'calibration'));
        } catch (error) {
          failure(failures, 'evaluator_not_independent', `${label} trial ${String(readField(trial, 'trial') ?? index)}: ${String(error?.message ?? error).slice(0, 200)}`);
        }
        // A4, applied per trial: a provenance field that claims a different
        // run or a different base is a corrupted record, named.
        const provenance = readField(trial, 'provenance');
        if (isRecord(provenance)) {
          for (const field of ['raw_run_id', 'commit_sha', 'tree_sha']) {
            const claimed = provenance[field];
            if (claimed === undefined) continue;
            if (claimed !== readField(run, field)) {
              failure(failures, 'trial_provenance_divergence', `${label} trial ${String(readField(trial, 'trial') ?? index)}: provenance.${field} does not match the run's own ${field}`);
            }
          }
        }
      }
    }
  }

  // A4 at the run and registration level: the track's inference mode is
  // ASSOCIATIONAL and this transport can never read a simulation as causal
  // proof. A run that claims otherwise is named.
  const runCausal = causalClaimRefusal(run);
  if (runCausal !== null) failure(failures, 'causal_claim_unsupported', `${label}: ${runCausal}`);
  const inferenceMode = prereg.inference_mode;
  if (typeof inferenceMode === 'string' && inferenceMode.toUpperCase() === 'CAUSAL') {
    failure(failures, 'inference_mode_not_associational', `${label}: the preregistration declares inference_mode=CAUSAL; this transport is ASSOCIATIONAL only`);
  }
  if (table.metric !== null && typeof table.metric.inferenceMode === 'string'
    && table.metric.inferenceMode.toUpperCase() === 'CAUSAL') {
    failure(failures, 'inference_mode_not_associational', 'the frozen table declares a causal inference mode');
  }

  scoreCounters({ label, run, table, failures });
  const disclosure = scoreSeedDisclosure({ label, run, failures, trials, preregisteredSeeds });
  const controls = readField(run, 'controls') ?? readField(run, 'negative_controls');
  const controlsReported = isRecord(controls);
  const controlsFlipped = controlsReported && controls.allFlipped === true;
  // E5 / S2-008-SD-05: ABSENCE OF CONTROL EVIDENCE IS A FAILURE, NOT A
  // DOWNGRADE. `controlsFlipped` used to be computed, returned and then never
  // used to fail anything, so a run that executed ZERO controls still reached
  // `PASS_WITH_LIMITS` through `resolveCampaignVerdict` and emitted
  // `negative_controls: NOT_MEASURED`. negative-controls.mjs states the
  // opposite rule for itself: a control that did not run is not a limit. Both
  // states are now named failures, and the proof block is UNMET rather than
  // NOT_MEASURED.
  if (!controlsReported) {
    failure(failures, 'negative_controls_absent', `${label} reports no control block; an unmeasured control is not a satisfied control`);
  } else if (!controlsFlipped) {
    const notFlipped = Array.isArray(controls.controls)
      ? controls.controls.filter((entry) => isRecord(entry) && entry.flipped !== true).map((entry) => String(entry.id ?? 'unnamed'))
      : [];
    failure(failures, 'negative_controls_did_not_flip', `${label}: ${notFlipped.length === 0 ? 'the control block does not assert allFlipped' : `${notFlipped.length} control(s) did not flip: ${notFlipped.join(', ')}`}`);
  }
  // Latency and the metric are MEASURED and can raise a limit or a failure, but
  // neither may abort the comparison: a broken measurement is a NAMED failure
  // (S2-008-SD-11), never a throw that discards run A's findings after they
  // were already collected.
  let latency = null;
  try {
    latency = trials === null ? null : latencyRecorded(trials, prereg.noise_rule ?? null);
  } catch (error) {
    failure(failures, 'latency_not_recorded', `${label}: ${String(error?.code ?? 'LATENCY_INVALID')} (${String(error?.message ?? error).slice(0, 160)})`);
  }
  let metric = null;
  try {
    metric = scoreMetric({ label, run, prereg, table, trials, failures, limits });
  } catch (error) {
    failure(failures, 'metric_not_measured', `${label}: ${String(error?.code ?? 'METRIC_UNSCORABLE')} (${String(error?.message ?? error).slice(0, 160)})`);
    metric = {
      summary: null, interval: null, decision: 'UNRESOLVED', decisionStatus: 'NOT_MEASURED',
      decisionReason: 'metric_not_measured', correction: null,
    };
  }
  if (latency !== null && latency.samples.length > 0) {
    limit(
      limits,
      'latency_observed',
      `${label}: p50=${latency.interval.pointEstimate}ms p95=${latency.interval.upper}ms over ${latency.samples.length} samples; measured, decides nothing`,
      'latency_recorded',
    );
  }

  return {
    digest,
    trialCount,
    trialViolations,
    seedsComplete,
    observedSeeds,
    preregisteredSeeds,
    controlsFlipped,
    controls: controlsFlipped ? { allFlipped: true, count: Array.isArray(controls.controls) ? controls.controls.length : null } : null,
    disclosure,
    metric: metric.summary,
    interval: metric.interval,
    decision: metric.decision,
    decisionStatus: metric.decisionStatus,
    decisionReason: metric.decisionReason,
    correction: metric.correction,
    rule_feasibility: metric.rule_feasibility,
    latency,
  };
}

// The trials a pooled campaign rate aggregates, named by id when the run
// declares them: the subject of a POOLED metric is the aggregate OF the
// declared family, so the caller reports the family's first member rather than
// the metric's name (S7).
function pooledSubjectOf(trials) {
  const declared = (Array.isArray(trials) ? trials : [])
    .map((trial) => readField(trial, 'trial') ?? readField(trial, 'trial_id') ?? null)
    .find((id) => typeof id === 'string' && id !== '');
  return typeof declared === 'string' ? declared : 'track_metric';
}

function observedSeedCount(observedSeeds) {
  return observedSeeds[0]?.length ?? 0;
}
// P2 at the report level: a run that names a selection must disclose every
// seed it used. Reporting the winner alone is a violation the comparator
// detects about itself.
function scoreSeedDisclosure({ label, run, failures, trials, preregisteredSeeds }) {
  // The DISTINCT seed set, in first-seen order. Every trial draws from the same
  // preregistered set, so the disclosure covers the set, not the flattened
  // multiset of every draw: comparing against `trials.length * seeds` would
  // demand a disclosure no run could honestly produce.
  const used = [];
  for (const trial of trials ?? []) {
    const seeds = readField(trial, 'seeds');
    if (!Array.isArray(seeds)) continue;
    for (const seed of seeds) {
      if (!used.some((known) => sameMembers([known], [seed]))) used.push(seed);
    }
  }
  const disclosures = Array.isArray(run.seed_disclosures) ? run.seed_disclosures : [];
  const selections = [];
  for (const field of SELECTION_FIELDS) {
    const value = readField(run, field);
    if (value !== undefined && value !== null && value !== false) selections.push({ field, value });
  }
  for (const { field } of selections) {
    const matching = disclosures.filter((item) => isRecord(item) && (item.name === field || item.name === 'best_seed'));
    if (matching.length === 0) {
      failure(failures, 'best_seed_undisclosed', `${label}: ${field} is reported with no seed_disclosures entry; a selection without the full seed set is a violation`);
      continue;
    }
    const complete = matching.some((item) => item.disclosed === true
      && Number.isInteger(item.count)
      && item.count === used.length
      && sameMembers(Array.isArray(item.seeds) ? item.seeds : [], used));
    if (!complete) {
      failure(failures, 'best_seed_undisclosed', `${label}: the disclosure for ${field} covers ${Array.isArray(matching[0]?.seeds) ? matching[0].seeds.length : 0} seed(s) while the run used ${used.length} distinct seed(s)`);
    }
  }
  if (disclosures.length > 0) {
    for (const item of disclosures) {
      if (!isRecord(item) || typeof item.name !== 'string') {
        failure(failures, 'best_seed_undisclosed', `${label}: a seed disclosure carries no name; an unnamed disclosure is not a disclosure`);
        continue;
      }
      if (preregisteredSeeds.length > 0 && Array.isArray(item.seeds) && !sameMembers(item.seeds, preregisteredSeeds)) {
        failure(failures, 'best_seed_undisclosed', `${label}: the disclosure for ${item.name} does not cover the preregistered seed set`);
      }
    }
  }
  return {
    selections: selections.map((item) => item.field),
    disclosures: disclosures.length,
    seeds_used: used.length,
  };
}

function scoreCounters({ label, run, table, failures }) {
  const observed = isRecord(run.counters) ? run.counters : (isRecord(run.hardCounters) ? run.hardCounters : null);
  if (observed === null) {
    failure(failures, 'hard_counters_unreported', `${label} reports no hard-gate counters; an unreported counter is not a zero counter`);
    return;
  }
  for (const [name, value] of Object.entries(observed)) {
    if (!finiteNumber(value)) {
      failure(failures, 'hard_gate_not_reported', `${label}: hard-gate counter ${name} is not a finite number (${String(value)})`);
      continue;
    }
    if (value !== 0) failure(failures, 'hard_gate_violated', `${label}: ${name}=${value}`);
    const expected = table.counters === null ? undefined : table.counters[name];
    if (expected !== undefined && expected !== value) {
      failure(failures, 'hard_gate_diverges_from_table', `${label}: ${name}=${value} but the frozen table expects ${String(expected)}`);
    }
  }
  if (table.counters !== null) {
    for (const name of Object.keys(table.counters)) {
      if (!Object.prototype.hasOwnProperty.call(observed, name)) {
        failure(failures, 'hard_gate_not_reported', `${label}: the frozen table declares counter ${name} and the run does not report it`);
      }
    }
  }
}

// The preregistered direction of the metric, translated into the vocabulary
// `decisionFromInterval` compares against. Read in the order the document
// states it: the METRIC's own `direction` is the primary statement of what
// better means, the decision rule's is the fallback, and `null` means the
// document never said — which the caller turns into a named failure rather than
// into a default (S2-008-SD-04).
const DIRECTION_BY_METRIC = Object.freeze({
  HIGHER_IS_BETTER: 'increase',
  LOWER_IS_BETTER: 'decrease',
  TARGET_INTERVAL: 'two_sided',
});

function declaredDirection(prereg) {
  const metricDirection = isRecord(prereg.metric) ? prereg.metric.direction : undefined;
  if (typeof metricDirection === 'string') {
    const mapped = DIRECTION_BY_METRIC[metricDirection];
    if (mapped !== undefined) return mapped;
  }
  for (const rule of [prereg.multiplicity_rule, prereg.stopping_rule, prereg.noise_rule]) {
    if (!isRecord(rule)) continue;
    const raw = rule.direction;
    if (raw === 'increase' || raw === 'decrease' || raw === 'two_sided') return raw;
    if (typeof raw === 'string' && DIRECTION_BY_METRIC[raw] !== undefined) return DIRECTION_BY_METRIC[raw];
  }
  return null;
}

// The metric, the interval, and the corrected decision. The interval is
// recomputed from the run's own counts with the frozen statistics; a
// self-reported interval is only compared when it declares the same method.
function scoreMetric({ label, run, prereg, table, trials, failures, limits }) {
  const noiseRule = isRecord(prereg.noise_rule) ? prereg.noise_rule : {};
  const multiplicity = isRecord(prereg.multiplicity_rule) ? prereg.multiplicity_rule : {};
  const stopping = isRecord(prereg.stopping_rule) ? prereg.stopping_rule : {};
  const tableNoise = table.metric !== null && finiteNumber(table.metric.noiseBand) ? table.metric.noiseBand : null;
  const preregNoise = finiteNumber(noiseRule.noise_band) ? noiseRule.noise_band : null;
  if (tableNoise !== null && preregNoise !== null && tableNoise !== preregNoise) {
    failure(failures, 'noise_band_drift', `${label}: the preregistration's noise band (${preregNoise}) differs from the frozen table's (${tableNoise})`);
  }
  const noiseBand = tableNoise ?? preregNoise;
  if (noiseBand === null) {
    throw new MalformedResult('NOISE_BAND_ABSENT', 'neither the preregistration nor the frozen table publishes a noise band; there is no frozen rule to apply');
  }

  const summary = trials === null ? null : metricsSummary(trials);
  if (summary === null) {
    failure(failures, 'metric_not_measured', `${label} has no trials to aggregate; a metric with no trials is not a zero`);
    return { summary: null, interval: null, decision: 'UNRESOLVED', decisionStatus: 'NOT_MEASURED', decisionReason: 'metric_not_measured', correction: null };
  }
  if (summary.notMeasured > 0) {
    failure(failures, 'metric_not_measured', `${label}: ${summary.notMeasured} trial(s) were not measured and are excluded from the metric, not counted as failures of it`);
  }
  if (summary.denominator < 1) {
    failure(failures, 'metric_not_measured', `${label}: no trial resolved, so the metric has no denominator`);
    return { summary, interval: null, decision: 'UNRESOLVED', decisionStatus: 'NOT_MEASURED', decisionReason: 'no_resolved_trial', correction: null };
  }
  if (table.metric !== null && typeof table.metric.name === 'string' && summary.metric !== table.metric.name) {
    failure(failures, 'metric_name_divergence', `${label}: measured metric ${summary.metric} is not the frozen metric ${table.metric.name}`);
  }
  // A metric computed by a DIFFERENT aggregation than the preregistration
  // published, under the preregistered metric's NAME, is not the frozen metric
  // — it is a different quantity wearing it. The frozen table catches this
  // whenever its rows pin per-trial counts; this check is the local guard, so
  // the rule does not depend on a second module noticing. It can only ever ADD
  // a failure: a run whose trials declare their own counts never reaches it.
  const declaredBasis = isRecord(prereg.metric) && typeof prereg.metric.value_basis === 'string'
    ? prereg.metric.value_basis
    : (table.metric !== null && typeof table.metric.valueBasis === 'string' ? table.metric.valueBasis : null);
  if (declaredBasis !== null && summary.basis === 'POSITIVE_OUTCOME_TALLY' && /RATE|PROPORTION|COUNT|RATIO|SHARE/.test(declaredBasis.toUpperCase())) {
    failure(
      failures,
      'metric_basis_divergence',
      `${label}: the preregistration publishes ${declaredBasis} (a rate over counts) while the metric was built from a POSITIVE/NEGATIVE outcome tally (${summary.numerator}/${summary.denominator}); the two are different quantities under one name`,
    );
  }

  const confidence = finiteNumber(multiplicity.confidence) ? multiplicity.confidence : 0.95;
  const interval = wilsonInterval({ successes: summary.numerator, trials: summary.denominator, confidence });
  const declared = isRecord(run.metric) && isRecord(run.metric.interval) ? run.metric.interval : null;
  if (declared !== null && declared.method === interval.method) {
    for (const bound of ['lower', 'upper']) {
      if (finiteNumber(declared[bound]) && Math.abs(declared[bound] - interval[bound]) > 1e-9) {
        failure(failures, 'self_reported_interval_divergence', `${label}: the run reports ${bound}=${declared[bound]} while its own counts give ${round6(interval[bound])}`);
      }
    }
  }

  // The DECLARED comparison family. `assertMultiplicityRule` accepts
  // `declared_comparisons` FIRST and then `comparisons`, and it accepts only
  // STRINGS (trial ids) — every member goes through `requireString`. The rule
  // passed to `decisionFromInterval` used to read only `multiplicity.comparisons`
  // and to keep only the members that were RECORDS, so with the legal spelling
  // the family silently collapsed to the single observation under test: the
  // correction was computed over m = 1 and never corrected anything. The
  // `MULTIPLICITY_FAMILY_ABSENT` refusal the header promises is implemented here
  // rather than described: no family, no decision.
  const familySource = Array.isArray(multiplicity.declared_comparisons)
    ? multiplicity.declared_comparisons
    : (Array.isArray(multiplicity.comparisons) ? multiplicity.comparisons : null);
  if (familySource === null || familySource.length === 0) {
    failure(failures, 'multiplicity_family_absent', `${label}: the preregistration declares no comparison family; an uncorrected test is not a decision`);
  }
  const rule = {
    alpha: finiteNumber(multiplicity.alpha) ? multiplicity.alpha : (finiteNumber(stopping.alpha) ? stopping.alpha : null),
    method: typeof multiplicity.method === 'string' ? multiplicity.method : 'holm_bonferroni',
    comparisons: (familySource ?? []).map((member) => (isRecord(member) ? member : { id: String(member) })),
    confidence,
    null_value: finiteNumber(prereg.frozen_baseline?.value) ? prereg.frozen_baseline.value : 0,
    // S2-008-SD-04: the direction used to fall back to the hard-coded
    // `'increase'`, and neither the multiplicity rule nor the stopping rule in
    // the required shape carried one — so a preregistered `LOWER_IS_BETTER`
    // metric whose value DROPPED was scored `NEGATIVE | UNMET`, i.e. a real
    // improvement read as the wrong answer. The direction is now read from the
  // three places the document may name it, in the order the document states
    // them, and an explicit `HIGHER_IS_BETTER` is honoured.
    direction: declaredDirection(prereg),
    // S7: the campaign rate is the POOLED aggregate of the declared trials'
    // own counts, so it is declared as such and the correction runs over the
    // preregistered family. Without this the subject was the metric NAME,
    // matched no declared comparison by id or by interval, and was APPENDED —
    // so the evidence reported m = 4 against a preregistered family_size of 3
    // and nothing read the difference. The arithmetic is reported either way:
    // with alpha 0.05 and confidence 0.95 the bound is 0.05 and the floor is
    // 0.05/3 = 0.0167, so `never_rejects` is true under m = 3 and under m = 4
    // and the decision is UNRESOLVED in both.
    subject: pooledSubjectOf(trials),
    subject_is_pooled_aggregate: true,
  };
  if (declaredDirection(prereg) === null) {
    failure(failures, 'metric_direction_absent', `${label}: neither the metric nor the decision rule declares a direction; a decision with an assumed direction can score an improvement as a regression`);
  }
  const applied = decisionFromInterval({
    observed: summary.numerator / summary.denominator,
    lower: interval.lower,
    upper: interval.upper,
    noiseBand,
    rule,
  });
  // The family the correction ACTUALLY ran over, checked against the family the
  // PREREGISTRATION froze. `preregistration.mjs` checks `family_size` only
  // against the declared list's length, so before this line a comparator that
  // widened the family past the declaration was invisible.
  const correction = isRecord(applied.correction) ? applied.correction : null;
  const declaredFamilySize = Number.isInteger(multiplicity.family_size) ? multiplicity.family_size : null;
  if (correction !== null && declaredFamilySize !== null && correction.effective_family_size !== declaredFamilySize) {
    failure(
      failures,
      'multiplicity_family_widened',
      `${label}: the correction ran over ${correction.effective_family_size} comparison(s) while the preregistration froze family_size=${declaredFamilySize} (${correction.family_widened === true ? 'the comparator widened the family' : 'the family does not match the declaration'})`,
    );
  }
  // S1: a frozen rule that provably CANNOT reject, whatever the measurement, is
  // a fact about the PUBLISHED CONSTANTS and it is named here so a reader never
  // has to infer it from a UNRESOLVED. The check is the pure helper rather than
  // the correction block, because a campaign that could not be decided never
  // reaches the correction at all. Fixing it is a PREREGISTRATION change (the
  // confidence has to rise to `1 - alpha / m`), never a comparator change.
  const feasibility = ruleFeasibility({
    alpha: rule.alpha,
    confidence: rule.confidence,
    familySize: rule.comparisons.length,
  });
  if (feasibility.never_rejects === true) {
    limit(
      limits,
      'frozen_rule_cannot_reject',
      `${label}: the published rule cannot reject any measurement — ${feasibility.note}; this rule can only answer NULL or UNRESOLVED, and raising the published confidence is a preregistration change`,
      'never_rejects',
    );
  }

  // The mapping from a decided outcome to the campaign record. A negative or a
  // null result is an ANSWER and is itemised as such; an unresolved or infra
  // outcome is a failure, because nothing was decided.
  const decisionStatus = applied.decision === 'POSITIVE' ? 'SATISFIED' : (applied.decision === 'NEGATIVE' || applied.decision === 'NULL' ? 'UNMET' : 'NOT_MEASURED');
  if (applied.decision === 'INFRA') {
    failure(failures, 'infrastructure_failure', `${label}: the measurement could not be completed (INFRA); an infra result is not a result`);
  } else if (applied.decision === 'UNRESOLVED') {
    failure(failures, 'decision_unresolved', `${label}: ${applied.reason}; an undecided measurement is not a pass`);
  }
  return {
    summary,
    interval: { lower: round6(interval.lower), upper: round6(interval.upper), confidence, method: interval.method },
    decision: applied.decision,
    decisionStatus,
    decisionReason: applied.reason,
    correction: applied.correction,
    rule_feasibility: feasibility,
  };
}

/**
 * The single place a CAMPAIGN verdict is named. DELEGATES to `resolveVerdict`
 * from src/lib/sloqual/comparator.mjs:237 and never re-implements it. This
 * module must not contain a second verdict function.
 * @param {{failures?: ReadonlyArray<object>, limits?: ReadonlyArray<object>, proofStatus?: ReadonlyArray<object>, force?: string|null}} args
 *   The same shape `resolveVerdict` accepts, forwarded unchanged.
 * @param {{failures?: ReadonlyArray<object>, limits?: ReadonlyArray<object>, proofStatus?: ReadonlyArray<object>, force?: string|null}} [args={}]
 *   The same shape `resolveVerdict` accepts, forwarded unchanged. The plan
 *   writes this signature as `resolveCampaignVerdict(...)`: the ellipsis means
 *   "whatever `resolveVerdict` takes, forwarded verbatim", NOT a free-form
 *   argument, because a shape of its own would be a second verdict layer.
 * @returns {string} 'PASS' | 'PASS_WITH_LIMITS' | 'FAIL', decided by
 *   `resolveVerdict` and by nothing else.
 * @throws {Error} SLOQUAL_COMPARATOR_INCONSISTENT, raised by `resolveVerdict`
 *   itself when a claimed verdict disagrees with the resolved one.
 */
export function resolveCampaignVerdict(args = {}) {
  return resolveVerdict(args);
}

/**
 * Aggregate the per-trial metric records into the track's single frozen
 * metric, with negative, null, infra and unresolved outcomes counted
 * separately. No averaging a failure away.
 * @param {ReadonlyArray<object>} trials The run's trial records.
 * @returns {{metric: string, numerator: number, denominator: number,
 *   outcomeCounts: Record<string, number>, notMeasured: number,
 *   basis: string}} `notMeasured` is reported separately from a zero and is
 *   never folded into the numerator or the denominator as 0. `basis` names the
 *   aggregation used: `POOLED_TRIAL_COUNTS` when the trials declare their own
 *   numerator/denominator, `POSITIVE_OUTCOME_TALLY` when they do not.
 */
export function metricsSummary(trials) {
  if (!Array.isArray(trials) || trials.length === 0) {
    throw new MalformedResult('TRIALS_ABSENT', 'metricsSummary was called with no trial records; an empty run has no metric');
  }
  let metric = null;
  let numerator = 0;
  let denominator = 0;
  let notMeasured = 0;
  let pooled = false;
  const outcomeCounts = {};
  for (const [index, trial] of trials.entries()) {
    if (!isRecord(trial)) {
      throw new MalformedResult('TRIAL_RECORD_MALFORMED', `trials[${index}] is not a record`);
    }
    const name = readField(trial, 'metric');
    if (typeof name !== 'string' || name === '') {
      throw new MalformedResult('METRIC_NAME_ABSENT', `trials[${index}] declares no metric name`);
    }
    if (metric === null) metric = name;
    else if (metric !== name) {
      throw new MalformedResult('METRIC_NAME_DIVERGENCE', `trials[${index}] measures ${name} while the run measures ${metric}`);
    }
    const status = readField(trial, 'status');
    const outcome = typeof readField(trial, 'outcome') === 'string' ? readField(trial, 'outcome') : 'UNRESOLVED';
    outcomeCounts[outcome] = (outcomeCounts[outcome] ?? 0) + 1;
    if (status !== RESOLVED) {
      // A trial that was not measured is counted here and NOWHERE else. It is
      // not a zero, not a failure of the metric, and not a denominator member.
      notMeasured += 1;
      continue;
    }
    const trialNumerator = readField(trial, 'numerator');
    const trialDenominator = readField(trial, 'denominator');
    if (Number.isInteger(trialNumerator) && Number.isInteger(trialDenominator) && trialDenominator > 0) {
      pooled = true;
      numerator += trialNumerator;
      denominator += trialDenominator;
      continue;
    }
    if (outcome === 'POSITIVE') numerator += 1;
    denominator += 1;
  }
  return {
    metric,
    numerator,
    denominator,
    outcomeCounts,
    notMeasured,
    // WHICH of the two aggregations produced the rate, reported so the number
    // can be read rather than trusted. A per-CASE rate (`case_agreement_rate`)
    // must be POOLED over the trials' own counts: counting how many trials came
    // out POSITIVE produces "1 of 3 trials" for a campaign that actually
    // measured 18 agreements out of 24 cases, which is a different quantity
    // wearing the same name. The outcome tally is kept as the fallback for a
    // run whose trials declare no counts, and `basis` says which one was used.
    basis: pooled ? 'POOLED_TRIAL_COUNTS' : 'POSITIVE_OUTCOME_TALLY',
  };
}

/**
 * Record wall-clock latency as SAMPLES and nothing more. Uses
 * `percentileBootstrapInterval` (src/lib/sloqual/statistics.mjs) with the
 * PREREGISTERED seed and sample count, so the interval is reproducible.
 *
 * The comparator NEVER reads `nowNs` or the fixed clock, and every block this
 * function returns carries `decides: false`. Latency is measured because the
 * ticket asks for it, and it can only ever contribute a LIMIT; it can never
 * produce a failure and never produce a verdict.
 *
 * @param {ReadonlyArray<object>} trials The run's trial records, each
 *   optionally carrying a `latency_ms` sample.
 * @param {object|null} [rule=null] The PREREGISTERED bootstrap parameters
 *   `{seed, resamples, p, confidence}`, normally `prereg.noise_rule`. Optional
 *   so the frozen one-argument signature keeps working; the parameters
 *   actually used are always reported back in `parameters`, so a run scored
 *   with different parameters is visible in the evidence rather than silent.
 * @returns {{samples: ReadonlyArray<number>, interval: object|null, decides: false}}
 *   `decides` is the literal `false` and is a typed part of the contract, not
 *   a convention.
 */
export function latencyRecorded(trials, rule = null) {
  if (!Array.isArray(trials)) {
    throw new MalformedResult('TRIALS_ABSENT', 'latencyRecorded was called with something that is not a list of trial records');
  }
  const samples = [];
  for (const trial of trials) {
    const value = readField(trial, 'latency_ms');
    if (value === undefined || value === null) continue;
    if (!finiteNumber(value) || value < 0) {
      throw new MalformedResult('LATENCY_SAMPLE_INVALID', 'a latency_ms sample is missing, non-finite or negative; a broken sample is not a fast sample');
    }
    samples.push(value);
  }
  const spec = isRecord(rule) ? rule : {};
  // SD-12: the preregistration names its bootstrap parameters as
  // `bootstrap_seed` / `bootstrap_samples` / `percentile` / `confidence`, and
  // the two spellings are READ here rather than papered over with defaults, so
  // a run scored under the preregistered parameters says so in its own
  // `parameters` block. Previously only the short spellings were read, the
  // preregistration's own names were ignored, and the runner's one-argument
  // call silently used the module defaults — so the JSDoc's promise ("the
  // PREREGISTERED seed and sample count") was false and unprovable from the
  // record.
  const firstDefined = (...names) => {
    for (const name of names) if (spec[name] !== undefined) return spec[name];
    return undefined;
  };
  const parameters = {
    seed: Number.isInteger(firstDefined('seed', 'bootstrap_seed')) ? firstDefined('seed', 'bootstrap_seed') : 20250808,
    resamples: Number.isInteger(firstDefined('resamples', 'bootstrap_samples')) ? firstDefined('resamples', 'bootstrap_samples') : 2000,
    p: finiteNumber(firstDefined('p', 'percentile')) ? firstDefined('p', 'percentile') : 0.95,
    confidence: finiteNumber(firstDefined('confidence', 'ci_level')) ? firstDefined('confidence', 'ci_level') : 0.95,
  };
  parameters.preregistered = Object.keys(parameters).length > 0 && isRecord(rule);
  const interval = samples.length === 0
    ? null
    : percentileBootstrapInterval({
      samples,
      p: parameters.p,
      resamples: parameters.resamples,
      confidence: parameters.confidence,
      seed: parameters.seed,
      label: 'latency_ms',
    });
  return { samples: Object.freeze(samples), interval, decides: false, parameters: Object.freeze(parameters) };
}

/**
 * Build a CORRUPTED copy of a run for the negative control. Never mutates its
 * input: the clean run record must stay byte-identical so the control can be
 * re-run. Every variant must flip the verdict when fed back through
 * `compareParallelTrack`, and the flipped field must be NAMED.
 * @param {ReadonlyArray<object>} trials The clean trial records.
 * @param {string} variant One of the frozen corruption variants — a trial
 *   status flip (RESOLVED -> SKIPPED), a counter nudge to 1, a metric-record
 *   alteration, or a provenance field replacement. Control id
 *   `corrupted_data`.
 * @returns {{trials: ReadonlyArray<object>, corrupted: {field: string,
 *   from: *, to: *, variant: string}}} The corrupted copy plus an exact
 *   description of what was changed, so the record can name it.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} on an unknown
 *   variant — an unnamed corruption is not a control.
 */
export function injectCorruption(trials, variant) {
  if (typeof variant !== 'string' || !Object.prototype.hasOwnProperty.call(CORRUPTION_VARIANTS, variant)) {
    const frozen = Object.entries(CORRUPTION_VARIANTS).map(([name, description]) => `${name} (${description})`).join(', ');
    throw new MalformedResult(
      'CORRUPTION_VARIANT_UNKNOWN',
      `unknown corruption variant ${String(variant)}; the frozen variants are ${frozen}`,
    );
  }
  if (!Array.isArray(trials) || trials.length === 0) {
    throw new MalformedResult('TRIALS_ABSENT', 'there is nothing to corrupt in an empty run; a corruption that cannot be applied is not a control');
  }
  const copy = trials.map((trial) => (isRecord(trial) ? { ...trial } : trial));
  const first = copy[0];
  if (!isRecord(first)) {
    throw new MalformedResult('TRIAL_RECORD_MALFORMED', 'trials[0] is not a record and cannot be corrupted meaningfully');
  }
  let corrupted;
  if (variant === 'trial_status_skip') {
    const from = readField(first, 'status') ?? null;
    first.status = 'SKIPPED';
    corrupted = { field: 'trials[0].status', from, to: 'SKIPPED', variant };
  } else if (variant === 'counter_nudge') {
    // A hard-gate counter nudged 0 -> 1 on the trial that owns it. The table
    // checks the per-trial counter block, so a corruption injected HERE is
    // caught even when the run-level block is left clean — which is the point
    // of a control: it has to move the verdict through the same path the real
    // attack would.
    const counters = { ...(isRecord(first.counters) ? first.counters : {}), holdoutPeek: Number(first.counters?.holdoutPeek ?? 0) + 1 };
    first.counters = counters;
    corrupted = { field: 'trials[0].counters.holdoutPeek', from: 0, to: 1, variant };
  } else if (variant === 'metric_altered') {
    if (finiteNumber(first.numerator)) {
      const from = first.numerator;
      first.numerator = from + 1;
      corrupted = { field: 'trials[0].numerator', from, to: first.numerator, variant };
    } else {
      const from = readField(first, 'outcome') ?? null;
      first.outcome = 'POSITIVE';
      corrupted = { field: 'trials[0].outcome', from, to: 'POSITIVE', variant };
    }
  } else {
    const provenance = isRecord(first.provenance) ? { ...first.provenance } : {};
    const field = 'raw_run_id';
    const from = provenance[field] ?? null;
    provenance[field] = 'run-forged';
    first.provenance = provenance;
    corrupted = { field: `trials[0].provenance.${field}`, from, to: 'run-forged', variant };
  }
  return { trials: copy, corrupted };
}
