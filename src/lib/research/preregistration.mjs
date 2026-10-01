// S2-008 research track — the PREREGISTRATION surface (issue SpaceDazher/Veritas#8).
//
// Serves A1, A2, A3 and A5; negative probes P1 (peeking a holdout), P2 (substituting
// the best seed), P3 (rewriting a hypothesis after the result), P4 (opaque budget).
//
// WHAT THIS IS / WHAT THIS IS NOT
// A run's decision surface is frozen BEFORE trial one, and every attempt to move it
// afterwards is refused: a plain canonical-JSON document plus pure guards over it.
// It is NOT the decision layer — comparator.mjs owns ALLOW/VIOLATION and this
// module only refuses to let a document reach it. It is NOT a second statistics
// layer: the noise band, the bootstrap seed and the sample count are frozen and
// digest-bound here, and src/lib/sloqual/statistics.mjs still computes every
// interval. It is NOT a second contract path: a hypothesis card is validated by
// contracts.mjs against the three frozen schemas. It is NOT a store — it writes
// nothing, so "recorded" here always means "the refusal carries a recordable
// payload and registry.mjs is the only thing that writes it".
//
// WHY IT IS NOT IN contracts/
// All three frozen schemas are `additionalProperties: false` and `contracts/` is a
// validate-contracts.mjs frozen target, so `seed_count`, `stopping_rule` and
// `budget_reservation` can live in neither. They live here, and the fact that this
// document is not a schema is recorded rather than worked around.
// `corpus/s2-008/preregistration.json` is the instance; this module is its only
// reader and its only writer.
//
// THE TWELVE DIGEST-COVERED FIELDS
// preregistrationDigest(prereg) = canonicalDigest({card_id, card_digest, metric,
// frozen_baseline, seed_rule, seed_count, seeds_digest, stopping_rule,
// budget_reservation, noise_rule, multiplicity_rule, inference_mode}) via
// canonicalDigest from src/lib/verifier/canonical-json.mjs — the reused digest
// convention, never a second one. RECORDED CORRECTION: the skeleton header said
// "the eleven named fields" (and, a paragraph earlier, "the six fields no schema
// can hold") while listing the plan's formula, which names TWELVE. The plan
// (s2-008-plan.md §1) is authoritative, and a digest surface is no place to carry a
// miscount of its own. WHAT THE PROJECTION CANNOT SEE: `trial_list`,
// `holdout_access` and an embedded `card` are outside it, which is why
// assertNoPostResultRewrite compares the WHOLE documents as well (see P3).
//
// P3: TWO FORGERIES, BOTH REFUSED
// A rewritten `test_design` keeps the same `card_id` and still satisfies
// contracts/hypothesis-card.schema.json, so neither the id nor the schema catches
// it — only a digest does. A forgery that also updates `card_digest` moves the
// twelve-field digest. One that leaves `card_digest` stale does not, and only the
// whole-document comparison sees it, because the edited `card` body is outside the
// projection. tests/research/preregistration.test.mjs must prove BOTH as
// mutations that throw; neither is a pass.
//
// THE AMENDMENT LAW
// A post-result edit is not an edit of the preregistration. The lawful path is
// createAmendment -> a new `AMENDMENT` document with its own `amendment_id`
// (prefix `amd-`), its own digest and `supersedes = preregistration_digest`,
// journalled. assertAmendmentNotDecisionBasis refuses an amendment as a decision
// input: it is a record of what changed, never a basis for the verdict that was
// reached before the change.
//
// P1: THE RULE IS FROZEN HERE, THE ONE-SHOT IS ENFORCED THERE
// assertPreregistration refuses to load a preregistration whose holdout rule is not
// exactly one-shot: `max_opens === 1`, a `decision_point` from a closed set (an "on
// significance" decision point has no way in), and the one-shot `unseal_digest` plus
// the sealed `labels_digest` present. The EXECUTABLE accounting — opened exactly
// once, only at the decision point, never re-opened — belongs to the two entry
// points the plan names for P1: dataset.mjs#readCorpus (which appends the ACCESS
// record before returning bytes) and registry.mjs#recordHoldoutRead (which counts
// opens and refuses a replay). This file's share is that the rule is frozen,
// validated and covered by the whole-document comparison, so it cannot be weakened
// after the fact: a preregistration that would authorise a peek does not load.
//
// P2: SEED SELECTION CANNOT DEPEND ON A RESULT
// The seed plan is a PURE function of the frozen `seed_rule` (`deriveSeedPlan`,
// module-private) and of nothing else: no clock, no file, no metric, no result.
// assertSeedSetFrozen re-derives it on every trial and refuses an extra, a missing,
// a reordered or a differently-counted set. Because the seeds are preregistered,
// "the best seed" is not a statistic the verdict may use, and expected-values.mjs
// indexes its table BY TRIAL INDEX, so a substitution changes which row scores the
// result.
//
// P4: THE BUDGET
// assertBudgetReservation reads an INJECTED clock, never Date.now(). Inside the
// reservation: granted. Beyond it: BudgetExceeded. EXPIRED: ReconciliationRequired,
// carrying a reconciliation row on `error.reconciliation`. Expiry is never a zero,
// never a silent skip and never a blind retry.
//
// DETERMINISM
// No Date.now(), no Math.random(), no argument-less new Date(), no network, no LLM,
// no credentials, no environment variable. The only I/O is `readFileSync` in
// loadPreregistration; the only clock is the injected one, and an ISO-8601 string is
// PARSED (Date.parse), never sampled. Same document + same clock => the same answer
// on every process and every repeat run, which is the property A5 rests on.
//
// DIGEST SPELLING
// canonicalDigest returns 64 BARE hex characters and this module returns it
// unchanged; a `sha256:`-prefixed spelling would be a second convention for one
// digest. Comparisons normalise the prefix (normaliseDigest), so a record written by
// a sibling that re-prefixes still compares equal. NOTE for this track's other
// workers: two sibling JSDoc blocks in this directory spell the reused digest
// `sha256:<64 hex>`, which does not describe what canonicalDigest returns.
//
// REQUIRED SHAPE of corpus/s2-008/preregistration.json (fail-closed; every refusal
// names the key it wanted):
//   kind                'PREREGISTRATION'
//   card_id             ^hyc-[a-z0-9][a-z0-9-]{0,62}$ (the frozen card_id pattern)
//   card_digest         64 hex, == canonicalDigest(card) when `card` is embedded
//   metric              { metric_id|name non-empty, direction in
//                         HIGHER_IS_BETTER|LOWER_IS_BETTER|TARGET_INTERVAL }
//   frozen_baseline     { baseline_digest|digest|source_digest 64 hex, plus
//                         value (finite number) or source (string) }
//   seed_rule           { kind in SEQUENTIAL|FIXED_LIST|HASH_FROM_LABEL plus the
//                         parameters that kind needs (see deriveSeedPlan) }
//   seed_count          positive integer == the derived plan's length
//   seeds_digest        64 hex == canonicalDigest(the derived plan)
//   trial_list          non-empty; each entry names a trial (a string, or an object
//                       carrying trial_id)
//   stopping_rule       { kind in FIXED_TRIALS|SEQUENTIAL_ALPHA_SPENDING,
//                         max_trials positive int == trial_list.length, early_stop an
//                         explicit boolean, and alpha_spending_method + alpha for
//                         the sequential kind }
//   budget_reservation  { reservation_id, currency non-empty, granted_units >= 1,
//                         spent_units >= 0 (absent = 0), expires_at = integer
//                         nanoseconds or an ISO-8601 UTC instant }
//   noise_rule          an object carrying at least one of
//                       band|noise_band|method|bootstrap_seed|bootstrap_samples|
//                       confidence|unit
//   multiplicity_rule   { kind in HOLM_BONFERRONI|NO_MULTIPLICITY_SINGLE_HYPOTHESIS,
//                         declared_comparisons|comparisons non-empty and every
//                         member present in trial_list, alpha in (0,1) }
//   inference_mode      'ASSOCIATIONAL' — the only admissible value of this track
//   holdout_access      { partition 'HOLDOUT', max_opens === 1, decision_point in
//                         AFTER_DECLARED_TRIALS|AFTER_ANALYSIS_FROZEN,
//                         unseal_digest 64 hex, labels_digest 64 hex }
// Optional and checked when present: `card` (must hash to `card_digest`),
// `preregistration_digest` (self-attestation, must match), `expected_table_digest`
// / `table_digest` (what W3's assertTableFrozen reads), `rule` (=== this file's
// PREREGISTRATION_RULE), `title`/`description`/`notes` (bounded free text; names and
// locations only, never a secret). A result-bearing key (results, verdict, findings,
// observed, ...) is REFUSED: a preregistration composed after a result is not a
// preregistration. HONEST LIMIT: a corpus file with no `preregistration_digest`
// self-attestation can be checked at load for INTERNAL consistency only; its tamper
// binding is the digest recorded in corpus/s2-008/manifest.json and in every run
// record. Adding the self-attestation makes the file self-sealing — recommended,
// not required, because requiring it would put a burden on a file this worker does
// not own.
//
// TWO INTERFACE GAPS REPORTED, NOT INVENTED (BLOCKED: to D)
//  1. NO PUBLIC SEED-PLAN DERIVATION. The ticket asks for an exported pure function
//     deriving the seed plan from the frozen rule; plan §1 froze eleven exports for
//     this file and none of them is it. The derivation is module-private
//     (`deriveSeedPlan`) and is reached through `assertSeedSetFrozen` and
//     `seedCountOf`; index.mjs must not export a name this file does not. A name
//     invented here would enter index.mjs and the evidence records and become
//     frozen by accident.
//  2. NO PUBLIC HOLDOUT-OPEN GUARD HERE. The one-shot / decision-point EXECUTION is
//     P1's two named entry points (dataset.mjs, registry.mjs), not this file. What
//     is not implemented here is not reported as implemented.
//
// Owner: W2. The exported signatures are frozen by plan §1: not renamed, not added
// to, not aliased. Every body below is implemented — there is no NOT_IMPLEMENTED
// path left in this file — and every refusal is a typed BoardError from
// src/lib/agentboard/errors.mjs, never a soft return value.
//
// SKELETON CONVENTION (kept): a function whose frozen signature destructures its
// parameter object carries a `= {}` default, so a zero-argument call reaches the
// same typed refusal instead of dying with a TypeError from the destructuring. The
// parameter SHAPE is unchanged for every real call.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  BlockedPolicy,
  BudgetExceeded,
  MalformedResult,
  NeedsInput,
  ReconciliationRequired,
  RevisionConflict,
  isBoardError,
  redact,
} from '../agentboard/errors.mjs';
import { assertCanonicalSafety, canonicalDigest, canonicalize } from '../verifier/canonical-json.mjs';

const PREREGISTRATION_FILE = 'preregistration.json';
const HEX64_RE = /^[0-9a-f]{64}$/;
const SHA256_SPELLING_RE = /^sha256:([0-9a-f]{64})$/;
const CARD_ID_RE = /^hyc-[a-z0-9][a-z0-9-]{0,62}$/;
const AMENDMENT_ID_RE = /^amd-[a-z0-9][a-z0-9-]{0,62}$/;
const RUN_ID_RE = /^[a-z0-9][a-z0-9._-]{0,199}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const MAX_SHORT = 128;
const MAX_TEXT = 512;
const MAX_REASON = 240;
const MAX_FREE_TEXT = 2048;
const HOLDOUT_PARTITION = 'HOLDOUT';

/** The plan's digest projection, in the plan's order. Twelve fields. */
const DIGEST_FIELDS = Object.freeze([
  'card_id', 'card_digest', 'metric', 'frozen_baseline', 'seed_rule', 'seed_count',
  'seeds_digest', 'stopping_rule', 'budget_reservation', 'noise_rule', 'multiplicity_rule',
  'inference_mode',
]);

/** The closed shape of an AMENDMENT. Any other key is a refusal (see below). */
const AMENDMENT_KEYS = Object.freeze([
  'kind', 'amendment_id', 'supersedes', 'card_id', 'reason', 'amendment_digest',
]);

/**
 * The closed key set of a SUPERSESSION document.
 *
 * A supersession is a THIRD document kind, not an amendment with a longer
 * reason: an amendment replaces a card, and this one replaces a RULE. The
 * distinction is what keeps the two apart in a reader's head, and the closed set
 * is what keeps a supersession from being used as a decision input (see
 * `assertSupersessionNotDecisionBasis`).
 * @type {ReadonlyArray<string>}
 */
const SUPERSESSION_KEYS = Object.freeze([
  'kind', 'supersession_id', 'supersedes', 'supersedes_confidence', 'supersedes_expected_table_digest',
  'replaced_by_confidence', 'replaced_by_expected_table_digest', 'reason', 'supersession_digest',
]);

/** `spr-<24 hex>`: derived from the content, so the same supersession always has the same id. @type {RegExp} */
const SUPERSESSION_ID_RE = /^spr-[0-9a-f]{24}$/;

/**
 * Keys that would mean the document carries a RESULT. A preregistration is frozen
 * before trial one, so a result in it can only have been put there after one
 * existed. Refused by name rather than ignored, so the composition error is visible
 * instead of silent. `supersedes`/`superseded_by` are here because a superseded
 * preregistration must not be presented as the one in force.
 */
const RESULT_CARRYING_KEYS = Object.freeze([
  'result', 'results', 'trial_result', 'trial_results', 'observed', 'observed_results',
  'measured', 'measured_results', 'findings', 'verdict', 'verdicts', 'outcome', 'outcomes',
  'summary', 'supersedes', 'superseded_by',
]);

const INFERENCE_MODES = Object.freeze(['ASSOCIATIONAL']);
const METRIC_DIRECTIONS = Object.freeze(['HIGHER_IS_BETTER', 'LOWER_IS_BETTER', 'TARGET_INTERVAL']);
const SEED_RULE_KINDS = Object.freeze(['SEQUENTIAL', 'FIXED_LIST', 'HASH_FROM_LABEL']);
const STOPPING_RULE_KINDS = Object.freeze(['FIXED_TRIALS', 'SEQUENTIAL_ALPHA_SPENDING']);
const ALPHA_SPENDING_METHODS = Object.freeze(['ALPHA_DIVESTING', 'LANE_EMMENS_DELTA', 'GROUP_SEQUENTIAL']);
const MULTIPLICITY_RULE_KINDS = Object.freeze(['HOLM_BONFERRONI', 'NO_MULTIPLICITY_SINGLE_HYPOTHESIS']);
const HOLDOUT_DECISION_POINTS = Object.freeze(['AFTER_DECLARED_TRIALS', 'AFTER_ANALYSIS_FROZEN']);
const NOISE_RULE_KEYS = Object.freeze([
  'band', 'noise_band', 'method', 'bootstrap_seed', 'bootstrap_samples', 'confidence', 'unit',
]);
/** Journal row kinds this module recognises when it proves ordering. */
const PREREGISTRATION_ROW_KINDS = Object.freeze(['PREREGISTRATION', 'PREREG', 'PREREGISTRATION_RECORD']);
const RESULT_ROW_KINDS = Object.freeze(['RESULT', 'TRIAL_RESULT', 'OUTCOME', 'OBSERVATION', 'MEASUREMENT']);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function typeName(value) {
  if (value === null) return 'null';
  return Array.isArray(value) ? 'array' : typeof value;
}

function malformed(code, detail) {
  return new MalformedResult(code, detail);
}

/** One spelling of one digest: a `sha256:` prefix is accepted and dropped. */
function normaliseDigest(value) {
  if (typeof value !== 'string') return null;
  if (HEX64_RE.test(value)) return value;
  const spelled = SHA256_SPELLING_RE.exec(value);
  return spelled ? spelled[1] : null;
}

function requireDigest(value, field) {
  const hex = normaliseDigest(value);
  if (hex === null) throw malformed('PREREGISTRATION_FIELD_INVALID', `${field} must be 64 lowercase hex characters`);
  return hex;
}

function requireObject(value, field) {
  if (!isPlainObject(value)) throw malformed('PREREGISTRATION_FIELD_INVALID', `${field} must be an object, got ${typeName(value)}`);
  return value;
}

function requireString(value, field, max = MAX_SHORT) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw malformed('PREREGISTRATION_FIELD_INVALID', `${field} must be a non-empty string, got ${typeName(value)}`);
  }
  const text = value.trim();
  if (text.length > max) throw malformed('PREREGISTRATION_FIELD_INVALID', `${field} exceeds ${max} characters`);
  return text;
}

function requireInteger(value, field, min) {
  if (!Number.isInteger(value) || value < min) {
    throw malformed('PREREGISTRATION_FIELD_INVALID', `${field} must be an integer >= ${min}, got ${typeName(value)}`);
  }
  return value;
}

function optionalInteger(value, field, min) {
  return value === undefined || value === null ? null : requireInteger(value, field, min);
}

function requireMember(value, allowed, field) {
  if (typeof value !== 'string' || !allowed.includes(value)) {
    throw malformed('PREREGISTRATION_FIELD_INVALID', `${field} must be one of ${allowed.join('|')}, got ${String(value)}`);
  }
  return value;
}

function firstPresentKey(source, keys) {
  for (const key of keys) {
    if (Object.hasOwn(source, key) && source[key] !== undefined && source[key] !== null) return key;
  }
  return null;
}

function freeText(value, field) {
  if (value === undefined || value === null) return;
  if (typeof value !== 'string' || value.length > MAX_FREE_TEXT) {
    throw malformed('PREREGISTRATION_FIELD_INVALID', `${field} must be a string of at most ${MAX_FREE_TEXT} characters`);
  }
}

/**
 * Nanoseconds from an injected clock reading. A string is PARSED, never sampled:
 * Date.parse is a pure function of its argument. This is the only time arithmetic
 * in the file and it never reads the process clock.
 *
 * A numeric reading is checked with `Number.isInteger`, NOT
 * `Number.isSafeInteger`: epoch nanoseconds (~1.8e18) are above 2^53, so a
 * safe-integer gate would refuse every real instant and force a caller into a
 * millisecond reading it does not have. The cost is stated rather than hidden —
 * above 2^53 a nanosecond reading quantises to ~256 ns, so no decision in this
 * file may turn on a difference finer than a microsecond. Every value the
 * deterministic harness injects is a small integer far below that.
 */
function clockToNs(reading, field) {
  if (typeof reading === 'number') {
    if (!Number.isInteger(reading) || reading < 0) throw new NeedsInput('CLOCK_INVALID', `${field} must be a non-negative integer of nanoseconds`);
    return reading;
  }
  if (typeof reading === 'string') {
    if (!ISO_RE.test(reading) || !Number.isFinite(Date.parse(reading))) throw new NeedsInput('CLOCK_INVALID', `${field} must be an ISO-8601 UTC instant`);
    return Date.parse(reading) * 1e6;
  }
  if (isPlainObject(reading)) {
    if (!Object.hasOwn(reading, 'nowNs')) throw new NeedsInput('CLOCK_INJECTION_REQUIRED', `${field} must carry nowNs`);
    return clockToNs(reading.nowNs, field);
  }
  throw new NeedsInput('CLOCK_INJECTION_REQUIRED', `${field} must be an injected clock reading: {nowNs}, integer nanoseconds, or an ISO-8601 string`);
}

/**
 * The reservation's shape, WITHOUT a clock: what a preregistration must publish
 * before a run exists. `expires_at` is integer NANOSECONDS or an ISO-8601 UTC
 * instant, and both are parsed, never sampled.
 */
function budgetShapeOf(reservation) {
  const value = requireObject(reservation, 'budget_reservation');
  const reservationId = requireString(value.reservation_id, 'budget_reservation.reservation_id');
  const currency = requireString(value.currency, 'budget_reservation.currency', 32);
  const grantedUnits = requireInteger(value.granted_units, 'budget_reservation.granted_units', 1);
  const spentUnits = optionalInteger(value.spent_units, 'budget_reservation.spent_units', 0) ?? 0;
  if (value.expires_at === undefined || value.expires_at === null) {
    throw malformed('PREREGISTRATION_FIELD_INVALID', 'budget_reservation.expires_at is required: a reservation with no expiry is an open-ended budget');
  }
  return { reservationId, currency, grantedUnits, spentUnits, expiresAt: clockToNs(value.expires_at, 'budget_reservation.expires_at') };
}

/**
 * The seed plan: a PURE function of the frozen rule. No clock, no file, no metric,
 * no result, no randomness — the whole point of P2. Given the same `seed_rule`
 * object it returns the same array on every process and every repeat run, and the
 * array's digest is what `seeds_digest` must equal.
 *
 *   SEQUENTIAL      {start, stride, count}  -> start + i * stride
 *   FIXED_LIST      {seeds}                 -> the frozen list, order significant
 *   HASH_FROM_LABEL {label, modulus, count} -> sha256(`${label}:${i}`) % modulus
 *
 * A modulo is not a uniform sampler. It does not need to be: the requirement is
 * determinism and a plan that cannot depend on a result, not uniformity.
 */
function deriveSeedPlan(rule) {
  const seedRule = requireObject(rule, 'seed_rule');
  const kind = requireMember(seedRule.kind, SEED_RULE_KINDS, 'seed_rule.kind');
  let seeds;
  if (kind === 'SEQUENTIAL') {
    const start = requireInteger(seedRule.start, 'seed_rule.start', 0);
    const stride = requireInteger(seedRule.stride, 'seed_rule.stride', 1);
    seeds = Array.from({ length: requireInteger(seedRule.count, 'seed_rule.count', 1) }, (_unused, i) => start + i * stride);
  } else if (kind === 'FIXED_LIST') {
    if (!Array.isArray(seedRule.seeds) || seedRule.seeds.length === 0) {
      throw malformed('PREREGISTRATION_FIELD_INVALID', 'seed_rule.seeds must be a non-empty array when kind is FIXED_LIST');
    }
    seeds = seedRule.seeds.map((seed, index) => {
      if (typeof seed === 'number' && Number.isFinite(seed)) return seed;
      if (typeof seed === 'string' && seed.length > 0 && seed.length <= MAX_SHORT) return seed;
      throw malformed('PREREGISTRATION_FIELD_INVALID', `seed_rule.seeds[${index}] must be a finite number or a non-empty string`);
    });
  } else {
    const label = requireString(seedRule.label, 'seed_rule.label');
    const modulus = requireInteger(seedRule.modulus, 'seed_rule.modulus', 2);
    const count = requireInteger(seedRule.count, 'seed_rule.count', 1);
    seeds = Array.from({ length: count }, (_unused, i) => Number.parseInt(canonicalDigest(`${label}:${i}`).slice(0, 8), 16) % modulus);
  }
  if (seedRule.modulus !== undefined && seedRule.modulus !== null && kind !== 'HASH_FROM_LABEL') {
    const modulus = requireInteger(seedRule.modulus, 'seed_rule.modulus', 1);
    seeds.forEach((seed, index) => {
      if (typeof seed === 'number' && seed >= modulus) throw malformed('PREREGISTRATION_FIELD_INVALID', `seed_rule.seeds[${index}] is outside modulus ${modulus}`);
    });
  }
  return seeds;
}

/** The preregistered seed plan, checked against `seed_count` and `seeds_digest`. */
function seedPlanOf(prereg) {
  const seeds = deriveSeedPlan(prereg.seed_rule);
  const count = requireInteger(prereg.seed_count, 'seed_count', 1);
  if (count !== seeds.length) throw malformed('SEED_COUNT_MISMATCH', `seed_count ${count} is not the derived plan's length ${seeds.length}`);
  const digest = requireDigest(prereg.seeds_digest, 'seeds_digest');
  const derived = canonicalDigest(seeds);
  if (digest !== derived) throw malformed('SEEDS_DIGEST_MISMATCH', `seeds_digest ${digest} does not match the rule-derived plan ${derived}`);
  return { seeds, count, digest };
}

/** The trial ids of the frozen trial list, in preregistered order. */
function trialIdsOf(prereg) {
  const list = prereg.trial_list;
  if (!Array.isArray(list) || list.length === 0) throw malformed('PREREGISTRATION_FIELD_INVALID', 'trial_list must be a non-empty array of the declared trials');
  return list.map((entry, index) => {
    if (typeof entry === 'string' && entry.trim().length > 0) return entry.trim();
    if (isPlainObject(entry)) {
      const key = firstPresentKey(entry, ['trial_id', 'id', 'comparison_id', 'comparison']);
      if (key !== null) return requireString(entry[key], `trial_list[${index}].${key}`);
    }
    throw malformed('PREREGISTRATION_FIELD_INVALID', `trial_list[${index}] must name a trial (a string, or an object carrying trial_id)`);
  });
}

/**
 * P1: the holdout access rule. EXACTLY one open, at a decision point named in
 * advance, with the unseal digest and the sealed label digest frozen. A rule that
 * would let a trial peek does not load. The one-shot EXECUTION lives in
 * dataset.mjs#readCorpus and registry.mjs#recordHoldoutRead — this is the frozen
 * rule those two read.
 */
function assertHoldoutAccess(prereg) {
  const access = requireObject(prereg.holdout_access, 'holdout_access');
  if (access.partition !== HOLDOUT_PARTITION) throw malformed('HOLDOUT_ACCESS_PARTITION_INVALID', `holdout_access.partition must be ${HOLDOUT_PARTITION}, got ${String(access.partition)}`);
  if (access.max_opens !== 1) throw malformed('HOLDOUT_ACCESS_NOT_ONE_SHOT', `holdout_access.max_opens must be exactly 1, got ${String(access.max_opens)}`);
  requireMember(access.decision_point, HOLDOUT_DECISION_POINTS, 'holdout_access.decision_point');
  requireDigest(access.unseal_digest, 'holdout_access.unseal_digest');
  requireDigest(access.labels_digest, 'holdout_access.labels_digest');
  if (access.released_actor_kinds !== undefined && access.released_actor_kinds !== null) {
    if (!Array.isArray(access.released_actor_kinds) || access.released_actor_kinds.length === 0) {
      throw malformed('HOLDOUT_ACCESS_RELEASES_INVALID', 'holdout_access.released_actor_kinds must be a non-empty array when present');
    }
    access.released_actor_kinds.forEach((actorKind, index) => requireString(actorKind, `holdout_access.released_actor_kinds[${index}]`));
  }
  return access;
}

/**
 * The stopping rule, published rather than chosen at analysis time. A rule that
 * stops "when it looks good" is not in the closed set, and under FIXED_TRIALS an
 * early stop is refused outright: an early stop under a fixed trial list is a peek
 * with extra steps.
 */
function assertStoppingRule(rule, trialIds) {
  const stopping = requireObject(rule, 'stopping_rule');
  const kind = requireMember(stopping.kind, STOPPING_RULE_KINDS, 'stopping_rule.kind');
  const maxTrials = requireInteger(stopping.max_trials, 'stopping_rule.max_trials', 1);
  if (typeof stopping.early_stop !== 'boolean') throw malformed('PREREGISTRATION_FIELD_INVALID', 'stopping_rule.early_stop must be an explicit boolean');
  if (trialIds !== null && maxTrials !== trialIds.length) {
    throw malformed('STOPPING_RULE_TRIAL_COUNT_MISMATCH', `stopping_rule.max_trials ${maxTrials} is not the declared trial count ${trialIds.length}`);
  }
  if (kind === 'FIXED_TRIALS') {
    if (stopping.early_stop !== false) throw malformed('STOPPING_RULE_EARLY_STOP_REFUSED', 'FIXED_TRIALS requires early_stop=false: an early stop under a fixed trial list is a peek');
    return stopping;
  }
  if (stopping.early_stop !== true) throw malformed('PREREGISTRATION_FIELD_INVALID', 'SEQUENTIAL_ALPHA_SPENDING requires early_stop=true, or the rule is FIXED_TRIALS');
  requireMember(stopping.alpha_spending_method, ALPHA_SPENDING_METHODS, 'stopping_rule.alpha_spending_method');
  const alpha = stopping.alpha;
  if (typeof alpha !== 'number' || !Number.isFinite(alpha) || alpha <= 0 || alpha >= 1) throw malformed('PREREGISTRATION_FIELD_INVALID', 'stopping_rule.alpha must be a finite number in (0,1)');
  return stopping;
}

function assertMetric(metric) {
  const value = requireObject(metric, 'metric');
  const idKey = firstPresentKey(value, ['metric_id', 'name']);
  if (idKey === null) throw malformed('PREREGISTRATION_FIELD_INVALID', 'metric must carry metric_id (or name)');
  requireString(value[idKey], `metric.${idKey}`);
  requireMember(value.direction, METRIC_DIRECTIONS, 'metric.direction');
  return value;
}

function assertFrozenBaseline(baseline) {
  const value = requireObject(baseline, 'frozen_baseline');
  const digestKey = firstPresentKey(value, ['baseline_digest', 'digest', 'source_digest']);
  if (digestKey === null) throw malformed('PREREGISTRATION_FIELD_INVALID', 'frozen_baseline must carry baseline_digest (or digest)');
  requireDigest(value[digestKey], `frozen_baseline.${digestKey}`);
  const valueKey = firstPresentKey(value, ['value', 'source', 'source_ref']);
  if (valueKey === null) throw malformed('PREREGISTRATION_FIELD_INVALID', 'frozen_baseline must carry value (number) or source (string)');
  if (valueKey === 'value') {
    if (typeof value.value !== 'number' || !Number.isFinite(value.value)) throw malformed('PREREGISTRATION_FIELD_INVALID', 'frozen_baseline.value must be a finite number');
  } else {
    requireString(value[valueKey], `frozen_baseline.${valueKey}`, MAX_TEXT);
  }
  return value;
}

function assertNoiseRule(noiseRule) {
  const value = requireObject(noiseRule, 'noise_rule');
  if (NOISE_RULE_KEYS.every((key) => value[key] === undefined)) {
    throw malformed('PREREGISTRATION_FIELD_INVALID', `noise_rule must carry at least one of ${NOISE_RULE_KEYS.join(', ')}`);
  }
  for (const key of ['band', 'noise_band', 'confidence']) {
    if (typeof value[key] === 'number' && (!Number.isFinite(value[key]) || value[key] < 0)) throw malformed('PREREGISTRATION_FIELD_INVALID', `noise_rule.${key} must be a finite number >= 0`);
  }
  if (value.bootstrap_seed !== undefined) requireInteger(value.bootstrap_seed, 'noise_rule.bootstrap_seed', 0);
  if (value.bootstrap_samples !== undefined) requireInteger(value.bootstrap_samples, 'noise_rule.bootstrap_samples', 1);
  if (typeof value.method === 'string' && value.method.trim().length > 0) requireString(value.method, 'noise_rule.method');
  return value;
}

/**
 * R6: the multiplicity correction runs over the DECLARED comparison list, and
 * every declared comparison must be a declared trial. A correction over a list
 * that contains no trial is a correction over nothing.
 */
function assertMultiplicityRule(rule, trialIds) {
  const value = requireObject(rule, 'multiplicity_rule');
  requireMember(value.kind, MULTIPLICITY_RULE_KINDS, 'multiplicity_rule.kind');
  const listKey = firstPresentKey(value, ['declared_comparisons', 'comparisons']);
  if (listKey === null) throw malformed('PREREGISTRATION_FIELD_INVALID', 'multiplicity_rule must carry declared_comparisons');
  if (!Array.isArray(value[listKey]) || value[listKey].length === 0) throw malformed('PREREGISTRATION_FIELD_INVALID', `multiplicity_rule.${listKey} must be a non-empty array`);
  const declared = value[listKey].map((comparison, index) => requireString(comparison, `multiplicity_rule.${listKey}[${index}]`, MAX_TEXT));
  const familySize = optionalInteger(value.family_size, 'multiplicity_rule.family_size', 1);
  if (familySize !== null && familySize !== declared.length) {
    throw malformed('PREREGISTRATION_FIELD_INVALID', `multiplicity_rule.family_size ${familySize} is not the declared comparison count ${declared.length}`);
  }
  if (trialIds !== null) {
    const declaredTrials = new Set(trialIds);
    const undeclared = declared.filter((comparison) => !declaredTrials.has(comparison));
    if (undeclared.length > 0) throw malformed('MULTIPLICITY_OVER_UNDECLARED_TRIALS', `declared comparisons absent from trial_list: ${undeclared.join(', ')}`);
  }
  if (typeof value.alpha !== 'number' || !Number.isFinite(value.alpha) || value.alpha <= 0 || value.alpha >= 1) {
    throw malformed('PREREGISTRATION_FIELD_INVALID', 'multiplicity_rule.alpha must be a finite number in (0,1)');
  }
  return value;
}

function canonicalOrNull(value) {
  // canonical-json-v1 strips undefined-valued object keys, so an undefined
  // member carries no canonical meaning and compares equal to an absent one.
  if (value === undefined) return null;
  try {
    return canonicalize(value);
  } catch (error) {
    // A value the reused gate refuses to serialise is not equal to any
    // canonical value, so it compares as CHANGED — which is the truth when the
    // other side is the frozen original. Without this the comparison below would
    // re-raise the gate's TypeError and a non-canonical PROPOSED document would
    // escape this module's closed taxonomy (see assertNoPostResultRewrite).
    if (error?.code === 'NON_CANONICAL_VALUE') return `NON_CANONICAL:${String(error.path ?? 'unknown')}`;
    throw error;
  }
}

/**
 * The keys whose canonical form differs between two documents, added or removed
 * included. This is the whole-document comparison the P3 refusal needs: the
 * plan's twelve-field projection cannot see an embedded `card`, `trial_list` or
 * `holdout_access`, and a forgery that leaves `card_digest` stale keeps the
 * published digest identical.
 */
function changedKeys(before, after) {
  const changed = [];
  for (const key of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
    const inBefore = Object.hasOwn(before, key);
    const inAfter = Object.hasOwn(after, key);
    if (inBefore !== inAfter || (inBefore && canonicalOrNull(before[key]) !== canonicalOrNull(after[key]))) changed.push(key);
  }
  return changed;
}

/** A whole-document digest, or null when the document is not representable. */
function wholeDigest(document) {
  try {
    return canonicalDigest(document);
  } catch (error) {
    if (isBoardError(error)) throw error;
    // Anything else from assertCanonicalSafety means the document cannot be
    // digested, which is itself a difference from the frozen original.
    return null;
  }
}

/** A refusal that carries the record of the attempt, so it can be journalled. */
function rejectedRewrite(code, ErrorClass, payload) {
  const error = new ErrorClass(code, canonicalize(payload));
  // The typed `detail` is bounded and redacted by BoardError; `rejection` is the
  // structured record the journal writer appends. Neither is written here: this
  // module has no side effects, so "recorded" always means "a caller writes it".
  error.rejection = payload;
  return error;
}

/** Order in the journal: the record's own `index` when it has one, else position. */
function rowIndex(row, position) {
  return Number.isInteger(row.index) && row.index >= 0 ? row.index : position;
}

function rowField(row, keys) {
  const key = firstPresentKey(row, keys);
  return key === null ? null : row[key];
}

/**
 * Ordering is proved by the journal, never by a wall clock. The preregistration
 * row for this digest must precede the run's first row and any result recorded
 * under this digest. A second run of the SAME preregistration stays legal: only a
 * preregistration row that comes AFTER them is refused, which is exactly a
 * preregistration written after the fact.
 */
function assertJournalOrdering(prereg, runId, digest, journal) {
  let preregIndex = -1;
  let firstResultIndex = -1;
  let firstRunIndex = -1;
  journal.forEach((row, position) => {
    if (!isPlainObject(row)) throw malformed('JOURNAL_ROW_MALFORMED', `row ${position} is ${typeName(row)}`);
    const kind = rowField(row, ['kind', 'record_kind']);
    const rowDigest = normaliseDigest(rowField(row, ['preregistration_digest', 'prereg_digest']));
    const index = rowIndex(row, position);
    if (preregIndex < 0 && kind !== null && PREREGISTRATION_ROW_KINDS.includes(kind) && rowDigest === digest) preregIndex = index;
    if (firstResultIndex < 0 && kind !== null && RESULT_ROW_KINDS.includes(kind) && rowDigest === digest) firstResultIndex = index;
    if (firstRunIndex < 0 && rowField(row, ['run_id', 'raw_run_id']) === runId) firstRunIndex = index;
  });
  if (preregIndex < 0) throw new BlockedPolicy('PREREGISTRATION_NOT_IN_JOURNAL', `no journal row records preregistration ${digest}`);
  if (firstRunIndex >= 0 && preregIndex > firstRunIndex) {
    throw new BlockedPolicy('PREREGISTRATION_AFTER_RESULT', `preregistration recorded at ${preregIndex}, run ${runId} began at ${firstRunIndex}`);
  }
  if (firstResultIndex >= 0 && preregIndex > firstResultIndex) {
    throw new BlockedPolicy('PREREGISTRATION_AFTER_RESULT', `preregistration recorded at ${preregIndex}, a result under it was recorded at ${firstResultIndex}`);
  }
}

/**
 * The document kind of a preregistration. A preregistration is never edited
 * after a result; it is superseded by an AMENDMENT.
 * @type {string}
 */
export const PREREGISTRATION_KIND = 'PREREGISTRATION';

/**
 * The document kind of a post-result amendment. A new kind, with its own id
 * and digest, carrying `supersedes = preregistration_digest`.
 * @type {string}
 */
export const AMENDMENT_KIND = 'AMENDMENT';

/**
 * The document kind of a SUPERSESSION: a frozen rule that was replaced before
 * any new measurement, with the reason and BOTH states' published values in it.
 *
 * WHY IT EXISTS (R-A, S2-008 repair). The first delivery of this track published
 * a rule that could not reject anything: `alpha = 0.05` with `confidence: 0.95`
 * over a family of 3 gives a bound of `0.05` against a corrected level of
 * `0.05/3 = 0.016667`, so no measurement could ever have been rejected. The fix
 * is a change to the PREREGISTRATION — the comparator says so in its own comment
 * on `frozen_rule_cannot_reject` — and a rule that is edited in place leaves
 * nobody able to read what was published the first time. So the superseded
 * document is preserved WHOLE, as a document of its own kind, beside the one in
 * force, and the reason travels with it.
 *
 * It is not an AMENDMENT: an amendment carries a new `card_id` and is refused as
 * a decision basis, while a supersession carries the published CONSTANTS of both
 * states and no card. It is not a RESULT either — `assertPreregistration` refuses
 * `supersedes` / `superseded_by` on a preregistration, so the pointer lives here
 * and never inside the document it points at.
 * @type {string}
 */
export const SUPERSESSION_KIND = 'SUPERSESSION';

/**
 * The frozen rule string of this surface, for the evidence record. Mirrors
 * `FREEZE_RULE` in src/lib/sloqual/contract.mjs:29: a document that declares
 * `rule` must declare THIS value.
 * @type {string}
 */
export const PREREGISTRATION_RULE = 's2-008-prereg-v1';

/**
 * The canonical digest of a preregistration, over the twelve named fields only,
 * computed with the reused `canonicalDigest` and returned as 64 bare hex.
 *
 * It is the only thing that detects a post-result rewrite that ALSO updates
 * `card_digest`, because a rewritten `test_design` keeps the same `card_id` and
 * still satisfies contracts/hypothesis-card.schema.json. A rewrite that does NOT
 * update `card_digest` is caught by the whole-document comparison inside
 * `assertNoPostResultRewrite`; neither forgery is a pass.
 *
 * @param {object} prereg A preregistration document.
 * @returns {string} 64 lowercase hex characters; identical for byte-identical
 *   canonical content over the twelve fields, different for any change to any of
 *   them, including `test_design` through `card_digest`.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when a
 *   digest-covered field is ABSENT. Hashing a partial projection would make a
 *   removed field invisible, which is the failure this digest exists to catch.
 *   Also 'PREREGISTRATION_NOT_AN_OBJECT' for a non-object and
 *   'PREREGISTRATION_NOT_CANONICAL' for a projection the reused
 *   canonical-json gate refuses to serialise: the gate's own TypeError is
 *   re-typed here so that EVERY refusal leaving this file is a BoardError, which
 *   is what the callers that journal a rejection rely on.
 */
export function preregistrationDigest(prereg) {
  if (!isPlainObject(prereg)) throw malformed('PREREGISTRATION_NOT_AN_OBJECT', `expected a preregistration object, got ${typeName(prereg)}`);
  if (['s2-008-prereg-v3', 's2-008-prereg-v4', 's2-008-prereg-v5', 's2-008-prereg-v6', 's2-008-prereg-v7', 's2-008-prereg-v8'].includes(prereg.rule)) {
    const { approval, status, preregistration_digest, ...body } = prereg;
    return canonicalDigest(body);
  }
  const projection = {};
  for (const field of DIGEST_FIELDS) {
    if (!Object.hasOwn(prereg, field) || prereg[field] === undefined) throw malformed('PREREGISTRATION_FIELD_MISSING', `digest-covered field absent: ${field}`);
    projection[field] = prereg[field];
  }
  try {
    return canonicalDigest(projection);
  } catch (error) {
    if (error?.code === 'NON_CANONICAL_VALUE') {
      throw malformed('PREREGISTRATION_NOT_CANONICAL', `NON_CANONICAL_VALUE: ${String(error.message).slice(0, 200)}`);
    }
    throw error;
  }
}

/**
 * Load `preregistration.json` from a corpus directory. The only supported way to
 * obtain a preregistration; a hand-built object assembled by a caller is not a
 * preregistration until it has been through this.
 * @param {string} dir Path of the corpus directory holding
 *   `preregistration.json` (in this track: `corpus/s2-008`).
 * @returns {object} The loaded preregistration document, unchanged.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'PREREGISTRATION_DIR_INVALID' when `dir` is not a path,
 *   'PREREGISTRATION_MISSING' when the file is absent or unreadable,
 *   'PREREGISTRATION_UNPARSEABLE' when it is not JSON, and whatever
 *   `assertPreregistration` refuses otherwise. A missing file is never an empty
 *   preregistration.
 */
export function loadPreregistration(dir) {
  if (typeof dir !== 'string' || dir.trim().length === 0) throw malformed('PREREGISTRATION_DIR_INVALID', `expected a corpus directory path, got ${typeName(dir)}`);
  const path = join(dir, PREREGISTRATION_FILE);
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    throw malformed('PREREGISTRATION_MISSING', `${path} is absent or unreadable`);
  }
  let document;
  try {
    document = JSON.parse(raw);
  } catch (error) {
    throw malformed('PREREGISTRATION_UNPARSEABLE', `${path}: ${String(error?.message ?? error).slice(0, 200)}`);
  }
  return assertPreregistration(document);
}

/**
 * Assert a preregistration is complete and internally consistent: the twelve
 * digest-covered fields present, the seed plan derivable and matching
 * `seed_count` and `seeds_digest`, the stopping rule a preregistered rule rather
 * than "stop when it looks good", the budget reservation positive, the declared
 * comparison list inside the declared trial list, the holdout access exactly
 * one-shot at a named decision point, and `inference_mode` published. The
 * required shape is documented in this file's header.
 *
 * This function is the reason a preregistration that would authorise a peek, a
 * best-seed search or a post-hoc comparison cannot even be loaded.
 *
 * @param {object} prereg The candidate preregistration.
 * @returns {object} The same document, unchanged, when it is admissible.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} on a missing or
 *   inconsistent field, naming the field, and 'PREREGISTRATION_NOT_CANONICAL'
 *   (the detail carries `NON_CANONICAL_VALUE` and the path) when the document
 *   cannot be canonically serialised at all.
 */
export function assertPreregistration(prereg) {
  if (!isPlainObject(prereg)) throw malformed('PREREGISTRATION_NOT_AN_OBJECT', `expected an object, got ${typeName(prereg)}`);
  // Canonically safe first: no undefined members, no NaN, no cycles, no non-plain
  // object. A document that cannot be digested cannot be sealed. The reused gate
  // throws a TypeError; it is re-typed into this boundary's closed taxonomy rather
  // than left to escape as a transport-shaped error.
  try {
    assertCanonicalSafety(prereg, 'prereg');
  } catch (error) {
    throw malformed('PREREGISTRATION_NOT_CANONICAL', `NON_CANONICAL_VALUE: ${String(error?.message ?? error).slice(0, 200)}`);
  }
  if (prereg.kind !== PREREGISTRATION_KIND) throw malformed('PREREGISTRATION_KIND_UNEXPECTED', `kind must be ${PREREGISTRATION_KIND}, got ${String(prereg.kind)}`);
  for (const key of RESULT_CARRYING_KEYS) {
    if (Object.hasOwn(prereg, key)) throw malformed('PREREGISTRATION_CARRIES_A_RESULT', `${key} carries a result; a preregistration is frozen before trial one`);
  }
  if (typeof prereg.card_id !== 'string' || !CARD_ID_RE.test(prereg.card_id)) throw malformed('PREREGISTRATION_FIELD_INVALID', `card_id must match ${CARD_ID_RE.source}`);
  requireDigest(prereg.card_digest, 'card_digest');
  assertMetric(prereg.metric);
  assertFrozenBaseline(prereg.frozen_baseline);
  seedPlanOf(prereg);
  const trialIds = trialIdsOf(prereg);
  assertStoppingRule(prereg.stopping_rule, trialIds);
  budgetShapeOf(prereg.budget_reservation);
  assertNoiseRule(prereg.noise_rule);
  assertMultiplicityRule(prereg.multiplicity_rule, trialIds);
  requireMember(prereg.inference_mode, INFERENCE_MODES, 'inference_mode');
  assertHoldoutAccess(prereg);
  if (['s2-008-prereg-v7','s2-008-prereg-v8'].includes(prereg.rule) &&
      (prereg.executor?.provider !== (prereg.rule === 's2-008-prereg-v8' ? 'openrouter' : 'zai-coding-cn') ||
       (prereg.rule === 's2-008-prereg-v8' && prereg.executor?.model !== 'stealth/space-bunny-alpha') ||
       prereg.executor?.credential_env_name !== (prereg.rule === 's2-008-prereg-v8' ? 'OPENROUTER_API_KEY' : 'ZAI_CODING_CN_API_KEY') ||
       prereg.executor?.pi_settings?.config_dir_env !== 'PI_CODING_AGENT_DIR' ||
       prereg.executor?.pi_settings?.retry?.enabled !== false ||
       prereg.executor?.pi_settings?.retry?.maxRetries !== 0 ||
       prereg.executor?.pi_settings?.retry?.provider?.maxRetries !== 0 ||
       prereg.executor?.pi_settings?.cacheWarming !== 'off' ||
       prereg.executor?.pi_settings?.compaction?.enabled !== false)) {
    throw malformed('PREREGISTRATION_EXECUTOR_POLICY_INVALID', 'v7/v8 require provider credential routing with disabled retries, cache warming, and compaction');
  }
  // Optional bindings, checked whenever they are present.
  if (prereg.card !== undefined && prereg.card !== null) {
    const card = requireObject(prereg.card, 'card');
    const cardDigest = requireDigest(prereg.card_digest, 'card_digest');
    const actual = canonicalDigest(card);
    if (actual !== cardDigest) throw malformed('CARD_DIGEST_MISMATCH', `card hashes to ${actual}, card_digest says ${cardDigest}`);
    if (card.card_id !== undefined && card.card_id !== prereg.card_id) throw malformed('CARD_ID_MISMATCH', `embedded card_id ${String(card.card_id)} is not the preregistered ${prereg.card_id}`);
  }
  const tableKey = firstPresentKey(prereg, ['expected_table_digest', 'table_digest']);
  if (tableKey !== null) requireDigest(prereg[tableKey], tableKey);
  if (prereg.rule !== undefined && prereg.rule !== null && ![PREREGISTRATION_RULE, 's2-008-prereg-v3', 's2-008-prereg-v4', 's2-008-prereg-v5', 's2-008-prereg-v6', 's2-008-prereg-v7', 's2-008-prereg-v8'].includes(prereg.rule)) {
    throw malformed('PREREGISTRATION_RULE_MISMATCH', `rule must be ${PREREGISTRATION_RULE}, got ${String(prereg.rule)}`);
  }
  for (const key of ['title', 'description', 'notes']) freeText(prereg[key], key);
  if (firstPresentKey(prereg, ['preregistration_digest']) !== null) {
    const declared = requireDigest(prereg.preregistration_digest, 'preregistration_digest');
    const actual = preregistrationDigest(prereg);
    if (declared !== actual) throw malformed('PREREGISTRATION_SEAL_MISMATCH', `recorded seal ${declared} does not match the document ${actual}`);
  }
  return prereg;
}

/**
 * Assert the preregistration was recorded before the run's first trial. Ordering
 * is proved by the registry journal, not by a wall clock: pass the journal rows
 * (as `registry.mjs#readJournal` returns them) and the preregistration row for
 * this digest must precede the run's first row and any result under it.
 *
 * WITHOUT `journal` this proves that the document is admissible, that it carries
 * no result (a document composed after a result is refused by
 * `assertPreregistration`), and that its optional self-attested seal still
 * matches. That is NOT the cross-process ordering proof, and a caller that needs
 * ordering must pass the journal. The optional `journal` key ADDS to the frozen
 * parameter object without changing it: `({prereg, runId})` behaves as before.
 *
 * @param {{prereg: object, runId: string, journal?: ReadonlyArray<object>}} args
 * @param {object} args.prereg The preregistration in force.
 * @param {string} args.runId The raw run id of the run about to start.
 * @param {ReadonlyArray<object>} [args.journal] Optional journal rows. A
 *   journal that is present but is NOT an array is REFUSED
 *   ('JOURNAL_MALFORMED'), never ignored.
 * @returns {object} `{prereg, runId, digest}` when the ordering holds.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'PREREGISTRATION_AFTER_RESULT' when the journal shows this preregistration
 *   recorded after the run's first row or after a result under it, and
 *   'PREREGISTRATION_NOT_IN_JOURNAL' when the journal has no row for this digest.
 * @throws {import('../agentboard/errors.mjs').NeedsInput} 'RUN_ID_INVALID',
 *   and 'JOURNAL_MALFORMED' when a `journal` is supplied and is not an array.
 */
export function assertPreregisteredBeforeRun({ prereg, runId, journal } = {}) {
  assertPreregistration(prereg);
  if (typeof runId !== 'string' || !RUN_ID_RE.test(runId)) throw new NeedsInput('RUN_ID_INVALID', `runId must match ${RUN_ID_RE.source}`);
  const digest = preregistrationDigest(prereg);
  // FIX (S2-008 W2 verification, 2nd dispatch): this used to be
  // `if (Array.isArray(journal))`, which is fail-OPEN — a caller that passed a
  // malformed journal (a string, a row object, anything not an array) silently
  // fell through to the weaker no-journal path and got a successful return. The
  // ordering proof then vanished with no refusal and no record, and A3's "the
  // preregistration is recorded before the run" would rest on a row list that
  // was never read. A journal that is PRESENT must be an array of rows; only
  // its ABSENCE selects the documented weaker path, which stays admissible
  // because `assertPreregistration` above has already proved the document
  // admissible and result-free.
  if (journal !== undefined && journal !== null) {
    if (!Array.isArray(journal)) throw new NeedsInput('JOURNAL_MALFORMED', `journal must be an array of rows when supplied, got ${typeName(journal)}; a malformed journal is refused, not ignored`);
    assertJournalOrdering(prereg, runId, digest, journal);
  }
  return { prereg, runId, digest };
}

/**
 * P2: the presented seed set must equal the PREREGISTERED seed set on EVERY trial.
 * Extra, missing, reordered or a different count are all substitutions. Because
 * the seeds are preregistered, "the best seed" is not a statistic the verdict may
 * use: the plan is re-derived here from the frozen rule on every call, and
 * expected-values.mjs indexes its table by trial index, so a substitution changes
 * which row scores the result.
 *
 * @param {ReadonlyArray<number|string>} seeds The seeds a trial actually used.
 * @param {object} prereg The preregistration in force.
 * @returns {ReadonlyArray<number|string>} The same seed array, unchanged, when it
 *   is the preregistered set.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'SEED_SUBSTITUTION:reordered' / ':substituted' / ':<count>' in the MESSAGE,
 *   with the per-index mismatches in `detail`.
 */
export function assertSeedSetFrozen(seeds, prereg) {
  if (!isPlainObject(prereg)) throw malformed('PREREGISTRATION_NOT_AN_OBJECT', `expected a preregistration object, got ${typeName(prereg)}`);
  if (!Array.isArray(seeds)) throw new NeedsInput('SEED_SET_MISSING', `seeds must be an array, got ${typeName(seeds)}`);
  const presented = [];
  seeds.forEach((seed, index) => {
    if (typeof seed === 'number' && Number.isFinite(seed)) presented.push(seed);
    else if (typeof seed === 'string' && seed.length > 0 && seed.length <= MAX_SHORT) presented.push(seed);
    else throw malformed('SEED_ELEMENT_INVALID', `seeds[${index}] must be a finite number or a non-empty string, got ${typeName(seed)}`);
  });
  const plan = seedPlanOf(prereg);
  if (presented.length !== plan.seeds.length) throw new BlockedPolicy(`SEED_SUBSTITUTION:count ${presented.length} vs ${plan.seeds.length}`, `presented ${presented.length} seeds, preregistered ${plan.seeds.length}`);
  const mismatches = [];
  presented.forEach((seed, index) => {
    if (seed !== plan.seeds[index]) mismatches.push({ index, presented: seed, preregistered: plan.seeds[index] });
  });
  if (mismatches.length > 0) {
    const sameSet = canonicalize([...presented].sort()) === canonicalize([...plan.seeds].sort());
    // The classification is in the MESSAGE, not only in the detail: the frozen
    // JSDoc promises the refusal names whether the set was extra, missing,
    // reordered or of a different count, and a reader must not have to open
    // `detail` to learn which of the four it is.
    const kind = sameSet ? 'reordered' : 'substituted';
    throw new BlockedPolicy(`SEED_SUBSTITUTION:${kind}`, canonicalize({ kind, mismatches, presented_digest: canonicalDigest(presented), preregistered_digest: plan.digest }));
  }
  return seeds;
}

/**
 * P3: refuse a post-result rewrite. Compares the preregistration digest in force
 * against the digest of the document now proposed as a decision basis, and
 * compares the WHOLE documents besides, because the plan's twelve-field
 * projection cannot see an embedded `card`, `trial_list` or `holdout_access`.
 *
 * `resultRecorded` is read fail-closed: an absent or non-boolean value is read as
 * `true`, because the safe direction is to assume a result exists. When no result
 * is recorded the document still may not move — a sealed preregistration has no
 * in-place edit path at all — so that refusal is a `RevisionConflict` and never
 * claims a result that does not exist.
 *
 * A document mutated IN PLACE is refused before any digest is compared: with the
 * same object reference on both sides the "before" value is already gone and every
 * comparison would trivially agree.
 *
 * The refusal is recorded, not merely thrown: `error.rejection` is the recordable
 * payload and `error.detail` its canonical form. This module has no side effects —
 * the journal writer (registry.mjs) is the only thing that appends the rejected
 * amendment, so the attempt is recorded once and cannot be dropped.
 *
 * @param {{prereg: object, next: object, resultRecorded: boolean}} args
 * @param {object} args.prereg The preregistration recorded before trial one.
 * @param {object} args.next The document now proposed as the decision basis.
 * @param {boolean} args.resultRecorded Whether a result has been recorded.
 * @returns {object} `{prereg, next, digest}` when nothing changed.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'HYPOTHESIS_REWRITE_AFTER_RESULT' when a result exists and the document
 *   moved — including a `test_design` edit that keeps the same `card_id` and
 *   still satisfies the frozen schema — and
 *   'PREREGISTRATION_MUTATED_IN_PLACE' when `next` IS `prereg`.
 * @throws {import('../agentboard/errors.mjs').RevisionConflict}
 *   'PREREGISTRATION_SEALED_MOVED' when no result is recorded and the document
 *   moved anyway.
 */
export function assertNoPostResultRewrite({ prereg, next, resultRecorded } = {}) {
  const base = assertPreregistration(prereg);
  if (!isPlainObject(next)) throw malformed('NEXT_DOCUMENT_NOT_AN_OBJECT', `expected the proposed document as an object, got ${typeName(next)}`);
  if (next === base) throw new BlockedPolicy('PREREGISTRATION_MUTATED_IN_PLACE', 'the same object was passed as both the frozen preregistration and the proposed document; the original bytes are already gone');
  const before = preregistrationDigest(base);
  let after = null;
  let nonCanonical = false;
  try {
    after = preregistrationDigest(next);
  } catch (error) {
    // A digest field that is absent or malformed in `next` is still a rewrite,
    // not a load failure: report it as one, naming the field.
    if (isBoardError(error)) {
      after = null;
    } else if (error?.code === 'NON_CANONICAL_VALUE') {
      // FIX (S2-008 W2 verification, 2nd dispatch): the reused canonical-json
      // gate throws a TypeError for a document it cannot serialise, and this
      // catch used to re-throw anything that was not a BoardError — so a
      // proposed document carrying a NaN, an undefined array member or a
      // circular reference left this function as a raw TypeError
      // (`isBoardError === false`) instead of a typed refusal. That broke the
      // module's own promise that every refusal is a BoardError, and it cost the
      // P3 record specifically: probes.mjs records `typed: isBoardError(error)`
      // and runner.mjs re-types a non-BoardError through `toBoardError`, so the
      // one attempt that MUST be recorded as HYPOTHESIS_REWRITE_AFTER_RESULT was
      // the one attempt that came back as an untyped transport error. It is still
      // a rewrite — an undigestable document cannot equal the frozen one — so it
      // is reported as one. Anything that is neither a BoardError nor the gate's
      // own code is a defect in THIS file and still propagates.
      after = null;
      nonCanonical = true;
    } else throw error;
  }
  const wholeBefore = canonicalDigest(base);
  const wholeAfter = wholeDigest(next);
  if (!nonCanonical && before === after && wholeBefore === wholeAfter) return { prereg, next, digest: before };
  const moved = changedKeys(base, next);
  const payload = {
    rule: PREREGISTRATION_RULE,
    digest_before: before,
    digest_after: after,
    whole_digest_before: wholeBefore,
    whole_digest_after: wholeAfter,
    moved_fields: moved,
    moved_digest_fields: moved.filter((key) => DIGEST_FIELDS.includes(key)),
    card_digest_stale: Object.hasOwn(next, 'card') && normaliseDigest(next.card_digest) !== wholeDigest(next.card),
    next_canonical: !nonCanonical,
    result_recorded: resultRecorded !== false,
    action: 'REJECTED_AMENDMENT_REQUIRED',
  };
  if (resultRecorded !== false) throw rejectedRewrite('HYPOTHESIS_REWRITE_AFTER_RESULT', BlockedPolicy, payload);
  throw rejectedRewrite('PREREGISTRATION_SEALED_MOVED', RevisionConflict, payload);
}

/**
 * The lawful path after a result: create a new AMENDMENT document. It has its own
 * `amendment_id` (prefix `amd-`), its own digest and
 * `supersedes = preregistration_digest`, and it is journalled. It is NEVER an edit
 * of the preregistration.
 *
 * The id and the digest are CONTENT-DERIVED, not random: two runs of the same base
 * produce byte-identical amendments, which is what A5's repeat-run witness needs,
 * and the ledger's idempotency treats an identical amendment as the same record
 * rather than inventing a second one. The cost is stated: two identical amendments
 * at different times are the same document, which is why `reason` is part of the
 * id's preimage.
 *
 * @param {{prereg: object, reason: string, newCardId: string}} args
 * @param {object} args.prereg The preregistration being amended.
 * @param {string} args.reason Why the amendment exists, in one bounded,
 *   secret-free line: names and locations only, no newlines, no credentials.
 * @param {string} args.newCardId The `card_id` (`hyc-…`) of the replacement card.
 *   A different id is required: the same id would make the rewrite undetectable,
 *   since `card_id` is what a reader compares first.
 * @returns {{kind: string, amendment_id: string, supersedes: string,
 *   card_id: string, reason: string, amendment_digest: string}} The amendment
 *   document, with exactly these six keys.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'AMENDMENT_SAME_CARD_ID' when `newCardId` equals the amended card's id.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when the reason or
 *   the new card id is absent, empty, over-long, multi-line, secret-shaped
 *   under the repository redaction list, or the wrong type.
 */
export function createAmendment({ prereg, reason, newCardId } = {}) {
  const base = assertPreregistration(prereg);
  if (typeof newCardId !== 'string' || !CARD_ID_RE.test(newCardId)) throw malformed('AMENDMENT_CARD_ID_INVALID', `newCardId must match ${CARD_ID_RE.source}`);
  if (newCardId === base.card_id) throw new BlockedPolicy('AMENDMENT_SAME_CARD_ID', `the replacement card must not reuse ${newCardId}: an edit under the same id is undetectable by construction`);
  if (typeof reason !== 'string') throw malformed('AMENDMENT_REASON_REQUIRED', `reason must be a string, got ${typeName(reason)}`);
  const bounded = reason.trim();
  if (bounded.length === 0) throw malformed('AMENDMENT_REASON_REQUIRED', 'reason must not be empty');
  if (bounded.length > MAX_REASON) throw malformed('AMENDMENT_REASON_TOO_LONG', `reason exceeds ${MAX_REASON} characters`);
  if (/[\r\n]/.test(bounded)) throw malformed('AMENDMENT_REASON_NOT_ONE_LINE', 'reason must be one line: an amendment record is a single bounded sentence');
  // FIX (S2-008 W2 verification, 2nd dispatch): a reason is free text that is
  // about to be hashed into a permanent, journalled document, and an amendment
  // record is the LAST place a credential should ever end up. The test is the
  // repository's own redaction list, not a second pattern set invented here:
  // `redact` is what every BoardError message and detail already passes
  // through, so "the reused redactor would rewrite this string" is exactly the
  // repository's definition of secret-shaped. The reason is REFUSED rather than
  // silently rewritten, because a redacted reason would still be hashed into the
  // amendment id and could read as a real, unredacted decision. A caller that
  // genuinely needs to name a credential's LOCATION writes the variable name
  // and where it lives, which is what the house rule asks for anyway. LIMIT,
  // stated rather than hidden: this is a shape test, not a scanner — a secret
  // that matches none of the seven patterns still passes, and this is defence
  // in depth, never a substitute for not passing a secret in.
  if (redact(bounded) !== bounded) throw malformed('AMENDMENT_REASON_SECRET_SHAPED', 'reason is secret-shaped under the repository redaction list; name the variable and its location instead');
  const body = { kind: AMENDMENT_KIND, card_id: newCardId, reason: bounded, supersedes: preregistrationDigest(base) };
  const amendment_id = `amd-${canonicalDigest(body).slice(0, 24)}`;
  return {
    kind: AMENDMENT_KIND,
    amendment_id,
    supersedes: body.supersedes,
    card_id: newCardId,
    reason: bounded,
    amendment_digest: canonicalDigest({ ...body, amendment_id }),
  };
}

/**
 * Refuse an amendment as a DECISION BASIS. An amendment is a record of what
 * changed; a verdict reached before the change may not be re-derived from the
 * document that changed it.
 *
 * The check is a closed-shape check, and that is the point: a decision input needs
 * fields this document does not have (a role, a verdict, a metric, a decision), so
 * ANY added key is the refusal. Pass the amendment document itself, not a wrapper.
 *
 * @param {object} amendment A document produced by createAmendment.
 * @param {object} prereg The preregistration the amendment supersedes.
 * @returns {object} The same amendment, unchanged, when it is NOT being used as
 *   the basis of a decision — that is, when it is only journalled.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'AMENDMENT_AS_DECISION_BASIS' when the amendment carries any key beyond its
 *   six, and 'AMENDMENT_SUPERSEDES_MISMATCH' when it does not react to this
 *   preregistration.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when the amendment
 *   is not an AMENDMENT, when its id or digest does not recompute, or when its card
 *   id is the amended one (the undetectable case).
 */
export function assertAmendmentNotDecisionBasis(amendment, prereg) {
  if (!isPlainObject(amendment)) throw malformed('AMENDMENT_NOT_AN_OBJECT', `expected an amendment object, got ${typeName(amendment)}`);
  if (amendment.kind !== AMENDMENT_KIND) throw malformed('AMENDMENT_KIND_UNEXPECTED', `kind must be ${AMENDMENT_KIND}, got ${String(amendment.kind)}`);
  const extra = Object.keys(amendment).filter((key) => !AMENDMENT_KEYS.includes(key)).sort();
  if (extra.length > 0) throw new BlockedPolicy('AMENDMENT_AS_DECISION_BASIS', `amendment carries ${extra.join(', ')}: an amendment is a record of what changed, never an input to a verdict`);
  if (typeof amendment.amendment_id !== 'string' || !AMENDMENT_ID_RE.test(amendment.amendment_id)) throw malformed('AMENDMENT_ID_INVALID', `amendment_id must match ${AMENDMENT_ID_RE.source}`);
  if (typeof amendment.card_id !== 'string' || !CARD_ID_RE.test(amendment.card_id)) throw malformed('AMENDMENT_CARD_ID_INVALID', `amendment card_id must match ${CARD_ID_RE.source}`);
  if (typeof amendment.reason !== 'string' || amendment.reason.trim().length === 0 || amendment.reason.length > MAX_REASON) {
    throw malformed('AMENDMENT_REASON_INVALID', `amendment reason must be one non-empty line of at most ${MAX_REASON} characters`);
  }
  const supersedes = requireDigest(amendment.supersedes, 'amendment.supersedes');
  const { kind, amendment_id: amendmentId, card_id: cardId, reason } = amendment;
  const recomputedId = `amd-${canonicalDigest({ kind, card_id: cardId, reason, supersedes }).slice(0, 24)}`;
  if (recomputedId !== amendmentId) throw malformed('AMENDMENT_ID_MISMATCH', `amendment_id ${amendmentId} does not match its content (${recomputedId})`);
  const recomputedDigest = canonicalDigest({ kind, card_id: cardId, reason, supersedes, amendment_id: amendmentId });
  if (requireDigest(amendment.amendment_digest, 'amendment.amendment_digest') !== recomputedDigest) {
    throw malformed('AMENDMENT_DIGEST_MISMATCH', `amendment_digest does not match its content (${recomputedDigest})`);
  }
  const base = assertPreregistration(prereg);
  if (cardId === base.card_id) throw malformed('AMENDMENT_SAME_CARD_ID', `an amendment must carry a NEW card id; ${cardId} is the amended one`);
  if (supersedes !== preregistrationDigest(base)) throw new BlockedPolicy('AMENDMENT_SUPERSEDES_MISMATCH', `amendment supersedes ${supersedes}, this preregistration is ${preregistrationDigest(base)}`);
  return amendment;
}

/**
 * Build the SUPERSESSION document for a frozen rule that was replaced before any
 * new measurement (R-A).
 *
 * The document preserves the superseded state in the two forms a reader needs to
 * check the claim that something changed: the superseded document's own digest
 * (`supersedes`, `preregistrationDigest` of the document in force before), and
 * the published constant that changed (`supersedes_confidence`), beside the one
 * that replaced it. The frozen-TABLE digests travel too, because the table is
 * sealed inside the preregistration and a re-derived rule moves it.
 *
 * `replacedBy` is REQUIRED, not optional. A supersession that names what it
 * replaced and nothing about what replaced it is a deletion with a reason
 * attached, and the whole point of the document kind is that the first delivery
 * stays readable.
 *
 * @param {{superseded: object, replacedBy: object, reason: string}} args
 * @param {object} args.superseded The preregistration that WAS in force, whole
 *   and unedited. It is validated as a preregistration, so a supersession can
 *   never point at a document that was not one.
 * @param {object} args.replacedBy The preregistration now in force, also
 *   validated. It must be a DIFFERENT document: a supersession of a
 *   preregistration by itself is a no-op with a digest on it.
 * @param {string} args.reason Why the rule was replaced, in one bounded,
 *   secret-free line. The same rules an amendment reason obeys, for the same
 *   reason: it is hashed into a permanent document.
 * @returns {{kind: string, supersession_id: string, supersedes: string,
 *   supersedes_confidence: number, supersedes_expected_table_digest: string,
 *   replaced_by_confidence: number, replaced_by_expected_table_digest: string,
 *   reason: string, supersession_digest: string}} The supersession document,
 *   with exactly these nine keys.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when either
 *   document is not an admissible preregistration, when the reason is absent,
 *   empty, over-long, multi-line or secret-shaped, or when the confidence /
 *   expected-table digest a document carries is unusable.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'SUPERSESSION_REPLACES_NOTHING' when the two documents are the same one, and
 *   'SUPERSESSION_CHANGES_NOTHING' when they are different documents that
 *   publish the same confidence and the same frozen-table digest — a
 *   supersession that records no change is a document that misleads.
 */
export function createSupersession({ superseded, replacedBy, reason } = {}) {
  const before = assertPreregistration(superseded);
  const after = assertPreregistration(replacedBy);
  const supersedes = preregistrationDigest(before);
  const replaces = preregistrationDigest(after);
  if (supersedes === replaces) {
    throw new BlockedPolicy('SUPERSESSION_REPLACES_NOTHING', `preregistration ${supersedes} supersedes itself; a rule that replaces nothing records nothing`);
  }
  if (typeof reason !== 'string') throw malformed('SUPERSESSION_REASON_REQUIRED', `reason must be a string, got ${typeName(reason)}`);
  const bounded = reason.trim();
  if (bounded.length === 0) throw malformed('SUPERSESSION_REASON_REQUIRED', 'reason must not be empty');
  if (bounded.length > MAX_REASON) throw malformed('SUPERSESSION_REASON_TOO_LONG', `reason exceeds ${MAX_REASON} characters`);
  if (/[\r\n]/.test(bounded)) throw malformed('SUPERSESSION_REASON_NOT_ONE_LINE', 'reason must be one line: a supersession record is a single bounded sentence');
  if (redact(bounded) !== bounded) throw malformed('SUPERSESSION_REASON_SECRET_SHAPED', 'reason is secret-shaped under the repository redaction list; name the variable and its location instead');
  const beforeConfidence = before.multiplicity_rule?.confidence;
  const afterConfidence = after.multiplicity_rule?.confidence;
  const beforeTableDigest = before.expected_table_digest ?? null;
  const afterTableDigest = after.expected_table_digest ?? null;
  if (!Number.isFinite(beforeConfidence) || !Number.isFinite(afterConfidence)) {
    throw malformed('SUPERSESSION_CONFIDENCE_ABSENT', 'a supersession needs both documents to publish a multiplicity confidence; a rule with no published level cannot be shown to have changed');
  }
  if (beforeTableDigest === null || afterTableDigest === null) {
    throw malformed('SUPERSESSION_TABLE_DIGEST_ABSENT', 'a supersession needs both documents to seal the frozen table; a table published after the run is not the table that ran');
  }
  if (beforeConfidence === afterConfidence && beforeTableDigest === afterTableDigest) {
    throw new BlockedPolicy('SUPERSESSION_CHANGES_NOTHING', `both documents publish confidence ${String(afterConfidence)} and table digest ${String(afterTableDigest)}; a supersession that records no change misleads the reader it exists for`);
  }
  const body = {
    kind: SUPERSESSION_KIND,
    supersedes,
    supersedes_confidence: beforeConfidence,
    supersedes_expected_table_digest: String(beforeTableDigest),
    replaced_by_confidence: afterConfidence,
    replaced_by_expected_table_digest: String(afterTableDigest),
    reason: bounded,
  };
  const supersession_id = `spr-${canonicalDigest(body).slice(0, 24)}`;
  return {
    kind: SUPERSESSION_KIND,
    supersession_id,
    supersedes: body.supersedes,
    supersedes_confidence: body.supersedes_confidence,
    supersedes_expected_table_digest: body.supersedes_expected_table_digest,
    replaced_by_confidence: body.replaced_by_confidence,
    replaced_by_expected_table_digest: body.replaced_by_expected_table_digest,
    reason: bounded,
    supersession_digest: canonicalDigest({ ...body, supersession_id }),
  };
}

/**
 * Assert a supersession document is internally consistent AND that the
 * preregistration it points at is the one it names.
 *
 * Three checks, all of them about a reader being able to trust the record: the
 * closed key set (a supersession is a record, never a decision input), the id
 * and digest recomputing from the content (an edited supersession with a
 * recomputed id is still an edited supersession, and the recomputation is what
 * makes that visible), and the two states being DISTINCT (a supersession whose
 * two states are the same document is a deletion wearing a digest).
 *
 * @param {object} supersession A document produced by `createSupersession`.
 * @param {object} superseded The superseded preregistration, whole.
 * @returns {object} The same document, unchanged.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'SUPERSESSION_AS_DECISION_BASIS' when the document carries a key beyond the
 *   closed set, and 'SUPERSESSION_SUPERSEDES_MISMATCH' when it does not name
 *   this preregistration.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when the document
 *   is not a SUPERSESSION, when its id or digest does not recompute, or when it
 *   names the same state twice.
 */
export function assertSupersession(supersession, superseded) {
  if (!isPlainObject(supersession)) throw malformed('SUPERSESSION_NOT_AN_OBJECT', `expected a supersession object, got ${typeName(supersession)}`);
  if (supersession.kind !== SUPERSESSION_KIND) throw malformed('SUPERSESSION_KIND_UNEXPECTED', `kind must be ${SUPERSESSION_KIND}, got ${String(supersession.kind)}`);
  const extra = Object.keys(supersession).filter((key) => !SUPERSESSION_KEYS.includes(key)).sort();
  if (extra.length > 0) throw new BlockedPolicy('SUPERSESSION_AS_DECISION_BASIS', `supersession carries ${extra.join(', ')}: a supersession is a record of what changed, never an input to a verdict`);
  if (typeof supersession.supersession_id !== 'string' || !SUPERSESSION_ID_RE.test(supersession.supersession_id)) {
    throw malformed('SUPERSESSION_ID_INVALID', `supersession_id must match ${SUPERSESSION_ID_RE.source}`);
  }
  if (typeof supersession.reason !== 'string' || supersession.reason.trim().length === 0 || supersession.reason.length > MAX_REASON) {
    throw malformed('SUPERSESSION_REASON_INVALID', `supersession reason must be one non-empty line of at most ${MAX_REASON} characters`);
  }
  const {
    kind, supersedes, supersedes_confidence: beforeConfidence, supersedes_expected_table_digest: beforeTable,
    replaced_by_confidence: afterConfidence, replaced_by_expected_table_digest: afterTable, reason, supersession_id: id,
  } = supersession;
  for (const name of ['supersedes', 'supersedes_expected_table_digest', 'replaced_by_expected_table_digest']) {
    requireDigest(supersession[name], `supersession.${name}`);
  }
  for (const [name, value] of [['supersedes_confidence', beforeConfidence], ['replaced_by_confidence', afterConfidence]]) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value >= 1) {
      throw malformed('SUPERSESSION_CONFIDENCE_INVALID', `${name} must be a confidence in (0, 1), got ${typeName(value)}`);
    }
  }
  if (beforeConfidence === afterConfidence && beforeTable === afterTable) {
    throw new BlockedPolicy('SUPERSESSION_CHANGES_NOTHING', `both states publish confidence ${String(afterConfidence)} and table digest ${String(afterTable)}`);
  }
  const body = {
    kind,
    supersedes,
    supersedes_confidence: beforeConfidence,
    supersedes_expected_table_digest: beforeTable,
    replaced_by_confidence: afterConfidence,
    replaced_by_expected_table_digest: afterTable,
    reason,
  };
  const recomputedId = `spr-${canonicalDigest(body).slice(0, 24)}`;
  if (recomputedId !== id) throw malformed('SUPERSESSION_ID_MISMATCH', `supersession_id ${id} does not match its content (${recomputedId})`);
  const recomputedDigest = canonicalDigest({ ...body, supersession_id: id });
  if (requireDigest(supersession.supersession_digest, 'supersession.supersession_digest') !== recomputedDigest) {
    throw malformed('SUPERSESSION_DIGEST_MISMATCH', `supersession_digest does not match its content (${recomputedDigest})`);
  }
  const base = assertPreregistration(superseded);
  if (supersedes !== preregistrationDigest(base)) {
    throw new BlockedPolicy('SUPERSESSION_SUPERSEDES_MISMATCH', `supersession names ${supersedes}, this preregistration is ${preregistrationDigest(base)}`);
  }
  return supersession;
}

/**
 * P4: budget opacity is refused by making the reservation explicit and checked
 * against an INJECTED clock. `Date.now()` is never called; an ISO-8601 `now` is
 * parsed, never sampled. Without an injected clock there is no budget decision at
 * all — the absence of a clock is `NeedsInput`, not a grant.
 *
 * `requested_units` is what this call asks to spend. When it is absent the call is
 * a LIVENESS check: it answers "is this reservation still alive and how much
 * headroom is left", and `remaining_units` is the headroom AFTER this call's
 * request, so a caller cannot read the return value as an authorisation to spend it.
 *
 * @param {object} reservation `{reservation_id, granted_units, spent_units,
 *   expires_at, currency}` plus an optional `requested_units`.
 * @param {{nowNs: number}|string|number} now The injected fixed clock reading:
 *   `{nowNs}`, a bare integer of nanoseconds, or an ISO-8601 UTC string.
 * @returns {{granted: true, remaining_units: number, reservation_id: string}}
 *   when the reservation is live and covers the request.
 * @throws {import('../agentboard/errors.mjs').BudgetExceeded} when the request
 *   exceeds the remaining reservation; the caller's `recordSpend` then writes
 *   nothing, so a refused spend leaves the journal byte-identical.
 * @throws {import('../agentboard/errors.mjs').ReconciliationRequired} when the
 *   reservation has EXPIRED, carrying `error.reconciliation` — a reconciliation
 *   row. Expiry is a reconciliation, never a zero, never a silent skip and never a
 *   blind retry.
 * @throws {import('../agentboard/errors.mjs').NeedsInput}
 *   'CLOCK_INJECTION_REQUIRED' when no injected clock is supplied.
 */
export function assertBudgetReservation(reservation, now) {
  if (!isPlainObject(reservation)) throw malformed('BUDGET_RESERVATION_MISSING', `expected a reservation object, got ${typeName(reservation)}`);
  const { reservationId, currency, grantedUnits, spentUnits, expiresAt } = budgetShapeOf(reservation);
  const requestedUnits = optionalInteger(reservation.requested_units, 'requested_units', 0) ?? 0;
  if (spentUnits > grantedUnits) throw new BudgetExceeded('BUDGET_EXCEEDED', `${spentUnits} units already spent of ${grantedUnits} granted on ${reservationId}`);
  const nowNs = clockToNs(now, 'now');
  if (nowNs >= expiresAt) {
    const error = new ReconciliationRequired('BUDGET_RESERVATION_EXPIRED', `${reservationId} expired at ${expiresAt}ns, observed ${nowNs}ns`);
    // The reconciliation row is produced here and WRITTEN by the caller's
    // `registry.mjs#recordSpend`. The `rec-` id belongs to the deterministic id
    // factory there; minting one here would need a nonce and would break the A5
    // repeat-run property, so the row carries the reservation instead.
    error.reconciliation = {
      reservation_id: reservationId,
      currency,
      granted_units: grantedUnits,
      spent_units: spentUnits,
      expires_at_ns: expiresAt,
      observed_now_ns: nowNs,
      reason: 'BUDGET_RESERVATION_EXPIRED',
      action: 'RECONCILE',
      retry: 'FORBIDDEN',
      zero_result: false,
    };
    throw error;
  }
  if (spentUnits + requestedUnits > grantedUnits) throw new BudgetExceeded('BUDGET_EXCEEDED', `${spentUnits} spent + ${requestedUnits} requested exceeds ${grantedUnits} granted on ${reservationId}`);
  return { granted: true, remaining_units: grantedUnits - spentUnits - requestedUnits, reservation_id: reservationId };
}

/**
 * The preregistered seed count. Read from the preregistration, never from the
 * seeds a run happened to use, and checked against the rule-derived plan.
 * @param {object} prereg The preregistration.
 * @returns {number} The preregistered `seed_count`.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when absent, or
 *   when it disagrees with the plan the frozen rule derives.
 */
export function seedCountOf(prereg) {
  if (!isPlainObject(prereg)) throw malformed('PREREGISTRATION_NOT_AN_OBJECT', `expected a preregistration object, got ${typeName(prereg)}`);
  return seedPlanOf(prereg).count;
}

/**
 * The preregistered stopping rule. Published, not chosen at analysis time, and
 * returned UNCHANGED (the same object) so a caller cannot mutate what it read.
 *
 * The noise band and the multiplicity correction are separate digest-covered
 * top-level fields (`noise_rule`, `multiplicity_rule`); this function returns the
 * rule itself, and `assertPreregistration` is what refuses a preregistration whose
 * stopping rule, noise rule and declared comparison list do not agree. A caller
 * that needs the whole decision surface reads the preregistration.
 *
 * @param {object} prereg The preregistration.
 * @returns {object} The `stopping_rule` as preregistered.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when absent, or
 *   when it is not a preregistered rule (an "on significance" rule has no way in,
 *   and an early stop under a fixed trial list is refused outright).
 */
export function stoppingRuleOf(prereg) {
  if (!isPlainObject(prereg)) throw malformed('PREREGISTRATION_NOT_AN_OBJECT', `expected a preregistration object, got ${typeName(prereg)}`);
  const trialIds = prereg.trial_list === undefined || prereg.trial_list === null ? null : trialIdsOf(prereg);
  return assertStoppingRule(prereg.stopping_rule, trialIds);
}

// --- THE SUPERSESSION LEDGER (A3) -------------------------------------------
//
// WHAT IT IS, AND WHY IT IS NOT A FOURTH DOCUMENT KIND
// A SUPERSESSION (above) records that a frozen RULE was replaced, with the two
// documents' published constants. It says nothing about the frozen MEASUREMENT
// SOURCES: the eight synthetic cases and the frozen expected-value table, which
// is where a real rewrite of a synthetic campaign would land. The ledger is the
// monotone, CHAINED record of those two digests, one entry per change, with the
// reason next to it — the same history a supersession records for the rule, at
// the level of the data.
//
// THE GAP IT CLOSES, IN THE WORDS THE REPRODUCTION USED
// `assertFrozenCampaignDerivable` accepts any SELF-CONSISTENT rewrite by
// construction: rewrite the fixture to 8/8, rewrite the table's rows to 8/8,
// rewrite `EXPECTED_CAMPAIGN` to what the rule then derives, re-seal, and the
// chain is green. That attack touches two sources and one seal, and the seal
// moves with them, so no in-corpus check can tell it from a legitimate
// supersession. What it could not do was APPEND here: the ledger's last entry
// carries the table digest and the cases digest as LITERALS, and a chain that
// does not end at the digests the current sources produce is refused. So the
// property this file can actually establish, and the one the report must claim,
// is exact:
//
//   AN UNRECORDED CHANGE OF THE FROZEN SOURCES IS REFUSED. A RECORDED ONE IS A
//   SUPERSESSION, which is what R-A asked for: a document kind of its own, with
//   a reason and both old digests. Immutability of a committed corpus is git's
//   job, and `npm run manifest:check` is the other half of it; this is the
//   third, and it is the one that runs inside the acceptance chain.
//
// IT IS NOT A DECISION BASIS
// `assertSourceLedger` returns the ledger for publication and takes no part in
// any verdict. The same closed-key rule the supersession obeys applies here: the
// ledger is a record of what changed, never an input to what is decided.

/** The document kind of a supersession ledger. @type {string} */
export const SOURCE_LEDGER_KIND = 'SUPERSESSION_LEDGER/1';

/** The closed key set of a ledger entry. @type {ReadonlyArray<string>} */
const SOURCE_LEDGER_ENTRY_KEYS = Object.freeze([
  'index', 'previous_anchor_digest', 'anchor_digest', 'cases_digest',
  'expected_table_digest', 'reason',
]);

/** The closed key set of a ledger. @type {ReadonlyArray<string>} */
const SOURCE_LEDGER_KEYS = Object.freeze(['kind', 'entries', 'entry_count', 'last_anchor_digest']);

/**
 * The anchor digest over the two frozen sources a rewrite would move: the
 * corpus's own cases and the frozen expected-value table. ONE digest over BOTH
 * because a change to either is the same event — the frozen synthetic
 * measurement moved — and two digests would let an attacker move one and leave
 * the other as a coincidence.
 *
 * @param {{cases_digest: string, expected_table_digest: string}} anchor
 * @returns {string} `sha256:<64 hex>` over the canonical form of the pair.
 */
export function sourceAnchorDigest({ cases_digest: casesDigest, expected_table_digest: tableDigest } = {}) {
  requireDigest(casesDigest, 'ledger.cases_digest');
  requireDigest(tableDigest, 'ledger.expected_table_digest');
  return canonicalDigest({ cases_digest: String(casesDigest), expected_table_digest: String(tableDigest) });
}

/**
 * Build a ledger entry for one change to the frozen sources.
 *
 * @param {{index?: number, previous?: object|null, cases_digest: string, expected_table_digest: string, reason: string}} args
 * @param {number} args.index The entry's position, 0-based and contiguous.
 * @param {object|null} args.previous The entry before this one, or null for the
 *   first. The chain is `previous_anchor_digest = previous.anchor_digest`, so an
 *   entry that is not appended after the one before it cannot be written.
 * @param {string} args.cases_digest The corpus cases' canonical digest, as a
 *   LITERAL of the change being recorded.
 * @param {string} args.expected_table_digest The frozen table's digest, as a
 *   literal of the change being recorded.
 * @param {string} args.reason Why, in one bounded secret-free line — the same
 *   rule a supersession reason obeys, for the same reason: the text is hashed
 *   into a permanent document.
 * @returns {Readonly<object>} The entry, frozen, with exactly the closed key set.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} on an unusable
 *   index, a missing or multi-line or secret-shaped reason, a previous entry
 *   that is not one, or an anchor whose digests do not recompute.
 */
export function createSourceLedgerEntry({ index = 0, previous = null, cases_digest: casesDigest, expected_table_digest: tableDigest, reason } = {}) {
  if (!Number.isInteger(index) || index < 0) throw malformed('LEDGER_INDEX_INVALID', `index must be a non-negative integer, got ${typeName(index)}`);
  if (index === 0 && previous !== null) throw malformed('LEDGER_FIRST_ENTRY_HAS_A_PARENT', 'the first ledger entry has no parent; a chain that starts in the middle records nothing about what came before');
  if (index > 0 && !isPlainObject(previous)) throw malformed('LEDGER_CHAIN_BROKEN', `entry ${index} needs the entry it follows; the ledger is a chain, not a list`);
  if (typeof reason !== 'string') throw malformed('LEDGER_REASON_REQUIRED', `reason must be a string, got ${typeName(reason)}`);
  const bounded = reason.trim();
  if (bounded.length === 0) throw malformed('LEDGER_REASON_REQUIRED', 'reason must not be empty');
  if (bounded.length > MAX_REASON) throw malformed('LEDGER_REASON_TOO_LONG', `reason exceeds ${MAX_REASON} characters`);
  if (/[\r\n]/.test(bounded)) throw malformed('LEDGER_REASON_NOT_ONE_LINE', 'reason must be one line: a ledger entry is a single bounded sentence');
  if (redact(bounded) !== bounded) throw malformed('LEDGER_REASON_SECRET_SHAPED', 'reason is secret-shaped under the repository redaction list; name the variable and its location instead');
  const anchor = sourceAnchorDigest({ cases_digest: casesDigest, expected_table_digest: tableDigest });
  const previousAnchor = index === 0 ? null : sourceAnchorDigest({
    cases_digest: previous.cases_digest,
    expected_table_digest: previous.expected_table_digest,
  });
  if (index > 0 && previousAnchor === anchor) {
    throw new BlockedPolicy('LEDGER_RECORDS_NO_CHANGE', `entry ${index} repeats the anchor of the entry it follows; an entry that records no change makes the count a lie`);
  }
  return Object.freeze({
    index,
    previous_anchor_digest: previousAnchor,
    anchor_digest: anchor,
    cases_digest: String(casesDigest),
    expected_table_digest: String(tableDigest),
    reason: bounded,
  });
}

/**
 * Assert a supersession ledger is a well-formed chain AND that it ENDS at the
 * digests the frozen sources actually produce right now.
 *
 * The last check is the one that matters, and it is the one that refuses the
 * wholesale-rewrite attack: a fixture or table whose bytes moved without an
 * appended entry is a `BlockedPolicy`, not a warning, and it is raised by the
 * corpus builder before anything is sealed and therefore before any run is
 * scored.
 *
 * @param {ReadonlyArray<object>} entries The ledger's entries, in order.
 * @param {{cases_digest: string, expected_table_digest: string}} current What the
 *   frozen sources hash to right now, as the caller re-derives them.
 * @returns {Readonly<{kind: string, entries: ReadonlyArray<object>, entry_count: number, last_anchor_digest: string, matches_current: true}>}
 *   The ledger, for publication.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} on a malformed
 *   chain: no entries, a non-contiguous index, a broken `previous_anchor_digest`
 *   link, an entry carrying a key outside the closed set, or a reason that is
 *   not one bounded line.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'FROZEN_SOURCES_CHANGED_WITHOUT_SUPERSESSION' when the chain's last anchor
 *   is not the digest the current sources produce.
 */
export function assertSourceLedger(entries, current) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw malformed('LEDGER_EMPTY', 'a supersession ledger with no entries records nothing; the first entry is the first delivery of the frozen sources');
  }
  const built = [];
  for (const [position, entry] of entries.entries()) {
    if (!isPlainObject(entry)) throw malformed('LEDGER_ENTRY_NOT_AN_OBJECT', `entry ${position} is ${typeName(entry)}`);
    const extra = Object.keys(entry).filter((key) => !SOURCE_LEDGER_ENTRY_KEYS.includes(key)).sort();
    if (extra.length > 0) throw new BlockedPolicy('LEDGER_AS_DECISION_BASIS', `ledger entry ${position} carries ${extra.join(', ')}: a ledger is a record of what changed, never an input to a verdict`);
    const rebuilt = createSourceLedgerEntry({
      index: position,
      previous: built[position - 1] ?? null,
      cases_digest: entry.cases_digest,
      expected_table_digest: entry.expected_table_digest,
      reason: entry.reason,
    });
    if (entry.index !== position) throw malformed('LEDGER_INDEX_DISCONTINUOUS', `entry ${position} declares index ${String(entry.index)}`);
    if (entry.anchor_digest !== rebuilt.anchor_digest) throw malformed('LEDGER_ANCHOR_MISMATCH', `entry ${position} anchors ${String(entry.anchor_digest)} but its digests hash to ${rebuilt.anchor_digest}`);
    if ((entry.previous_anchor_digest ?? null) !== rebuilt.previous_anchor_digest) {
      throw malformed('LEDGER_CHAIN_BROKEN', `entry ${position} names the previous anchor ${String(entry.previous_anchor_digest)} but the entry before it anchors ${String(rebuilt.previous_anchor_digest)}`);
    }
    built.push(rebuilt);
  }
  const observed = sourceAnchorDigest(current);
  const last = built[built.length - 1];
  if (last.anchor_digest !== observed) {
    throw new BlockedPolicy(
      'FROZEN_SOURCES_CHANGED_WITHOUT_SUPERSESSION',
      `the frozen sources now hash to ${observed} (cases ${String(current?.cases_digest)}, table ${String(current?.expected_table_digest)}) while the ledger's last of ${String(built.length)} entr${built.length === 1 ? 'y' : 'ies'} ends at ${last.anchor_digest} (cases ${last.cases_digest}, table ${last.expected_table_digest}); a change to the frozen synthetic corpus or to the frozen table is a supersession with a reason and both old digests, never a re-seal`,
    );
  }
  return Object.freeze({
    kind: SOURCE_LEDGER_KIND,
    entries: Object.freeze(built),
    entry_count: built.length,
    last_anchor_digest: observed,
    matches_current: true,
  });
}
