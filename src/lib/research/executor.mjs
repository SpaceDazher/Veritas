// S2-008 research track — the DETERMINISTIC TEST TRANSPORT (issue
// SpaceDazher/Veritas#8).
//
// WHAT THIS MODULE IS
// A transport that executes ONE trial from FROZEN inputs and returns a
// measurement plus a MANDATORY, machine-readable provenance label. Frozen
// inputs means: a caller-supplied frozen case record, the preregistration
// digest that froze it, and the case digest — all three are required, and a
// trial without them is refused rather than measured. The returned record is
// deep-frozen and digest-bound, and two runs over the same inputs and the same
// injected clock produce the same `outcome_digest` byte for byte; the clock
// itself is confined to the `latency` block and to nothing that is digested.
//
// Serves acceptance item A4 (a non-causal result cannot be read as causal), the
// P6 half of A2 (a missing or unreachable evaluator is an explicit
// EVALUATOR_UNAVAILABLE outcome, never a passing result), and the A5
// pre-condition (self-cleanup, so a repeat run on a permanent base starts
// clean instead of failing on its own leftovers).
//
// WHAT THIS MODULE IS NOT
//   * NOT a verdict layer. It measures; it never names ALLOW or VIOLATION.
//     `resolveTrialVerdict` and `resolveCampaignVerdict` in comparator.mjs are
//     the only places a verdict is named, and the POSITIVE/NEGATIVE/NULL
//     decision over the preregistered interval belongs to
//     `decisionFromInterval`. This module has no such function, and
//     `assertUsableAsResult` below is a PRECONDITION check that throws, not a
//     third verdict.
//   * NOT a second board transport. `createTestTransport`
//     (src/lib/agentboard/adapters.mjs:1578) models the S2-007 EXECUTION
//     boundary with a scripted event stream and implements the adapter
//     interface. A research TRIAL is not a board DISPATCH, this module does not
//     implement `assertAdapterInterface`, and it neither forks nor replaces the
//     board transport.
//   * NOT an adapter, an executor of LLM calls, or anything that touches the
//     network, a credential or a clock it did not receive. It performs no I/O
//     outside its own fixture directory and consults no clock but the injected
//     one.
//   * NOT a writer. It returns a record; `scripts/s2-008-run.mjs` (W4) and the
//     registry (W2) own every byte that lands on disk. This module never writes
//     an evidence file.
//   * NOT an id minter. `trial_id` and `executor_id` are supplied by the caller,
//     because the ledger owns identifiers (plan §2, W2). The only digest this
//     module mints is a `canonicalDigest` over canonical-json-v1, the ONE
//     digest convention of src/lib/verifier/canonical-json.mjs.
//
// WHY `CAUSAL_EXPERIMENT` CANNOT BE PRODUCED HERE, INSTEAD OF MERELY DISCOURAGED
// The ticket names three labels — OBSERVATIONAL_TEST, BACKTEST and
// CAUSAL_EXPERIMENT — and this transport can only ever produce the first two.
// That is a STRUCTURAL property here, held by four independent mechanisms, so
// the failure mode is not one missed check:
//
//   1. `EXECUTOR_TRIAL_KINDS` has no causal kind. The label is DERIVED from the
//      trial kind through `EXECUTOR_LABELS_BY_KIND`, a total map whose every
//      value is a member of `EXECUTOR_PRODUCIBLE_LABELS`. There is no branch
//      anywhere in this file that returns the third label.
//   2. `EXECUTOR_PRODUCIBLE_LABELS` is the allow-list a caller is checked
//      against, so `requested_label: 'CAUSAL_EXPERIMENT'` is refused on the way
//      IN with MalformedResult, before any evaluator or case is consulted.
//   3. `assertNoCausalClaim` refuses a causal claim whose evidence label is
//      non-causal (BlockedPolicy), and separately refuses ANY claim that
//      presents this transport as the source of a CAUSAL_EXPERIMENT.
//   4. Every returned record passes `assertOutcomeProvenance`, which re-derives
//      the label from the kind and refuses a record whose label does not match
//      — so a record that was relabelled after the fact (on disk, in a run
//      record, by a control) is refused too, not trusted.
//
// WHY THE DERIVATION IS ALSO TRUE (a deterministic offline transport cannot
// randomise treatment assignment, so there is nothing to be causal about)
//   A CAUSAL_EXPERIMENT would need an intervention and a randomised assignment
//   of units to it. This transport has none: no clock, no network, no
//   scheduler, no assignment, and a corpus whose partitions were declared in the
//   preregistration before the first run. Re-running it produces the same
//   numbers by construction. The transport is therefore structurally incapable
//   of an intervention even if a caller asked for one, which is why the refusal
//   is an allow-list refusal and not a policy judgement.
//
// A CAUSAL CLAIM IS REFUSED, NEVER ANNOTATED
// `assertNoCausalClaim` throws. It does not set a flag, does not warn, and does
// not return `admissible: false` for a caller to ignore. The two refusals are
// distinct on purpose:
//   * BlockedPolicy `CAUSAL_CLAIM_FROM_NON_CAUSAL_EVIDENCE` — the A4 / P5 case:
//     an observational or backtest label carrying a causal assertion. The
//     offending FIELD is named in the detail, so the control can assert on it.
//   * BlockedPolicy `CAUSAL_LABEL_NOT_PRODUCIBLE_BY_THIS_TRANSPORT` — a claim
//     that presents this transport as a causal experiment.
//   * MalformedResult `PROVENANCE_LABEL_UNKNOWN` / `PROVENANCE_LABEL_MISSING` —
//     the evidence's own provenance is absent or not a member of the closed
//     label set. A causal-claim check that does not know where the evidence
//     came from is not a check.
// Note what is deliberately NOT decisive: `card_type === 'MECHANISM_CLAIM'`
// alone. A mechanism card without `causal_assertion` is admissible under
// contracts/hypothesis-card.schema.json (the field is optional and may be
// null), and a guard that refused it would be over-reaching: a guard that
// refuses too much gets disabled, and a disabled guard is worse than none. This
// module guards the causal ASSERTION, and `card_type` is carried in the
// refusal detail instead.
//
// HOW THIS COMPOSES WITH causality.mjs (W1) WITHOUT FORKING IT
// W1's `assertCausalDiscipline` / `assertNoCausalFromSimulation` are the
// CARD-SIDE guards: they ask whether a card carries the evidence a causal
// assertion requires. This module is the TRANSPORT-SIDE guard: it asks whether
// the evidence this transport can produce is of a kind that could support the
// assertion at all. They are different questions and both are needed for A4.
// The transport-side guard is deliberately not an import of W1's functions, and
// that is a design boundary rather than a workaround: `causality.mjs` is
// implemented (no `NOT_IMPLEMENTED` body remains in it as of this revision), but
// its question is whether a CARD carries the evidence a causal assertion
// requires, while this one is whether the evidence this transport can PRODUCE
// could support an assertion at all. Importing the card-side guard here would
// let a transport-side refusal be satisfied by a well-formed card, which is
// precisely the substitution A4 must refuse: the card would still be
// observational. The probe order for P5 is `assertNoCausalClaim` (here) first,
// then `assertNoCausalFromSimulation` (W1) on the same card, and the record
// names both. The two vocabularies are not allowed to drift: `comparator.mjs`
// imports `classifyCardRelation` from W1 AND `EXECUTOR_PRODUCIBLE_LABELS` from
// this file, so one track reads the card classifier and the producible-label
// ceiling from their single owners.
//
// EVALUATOR AVAILABILITY IS AN OUTCOME, NOT AN EXCEPTION
// A missing or unreachable evaluator resolves to the explicit outcome
// EVALUATOR_UNAVAILABLE, which maps to the in-contract trial status
// NOT_MEASURED — an exact member of the frozen TRIAL_STATUSES, and the status
// the comparator scores as VIOLATION. The measurement in that record is `null`,
// never 0: "not measured" and "measured as zero" are different answers and this
// module never conflates them. Unavailability is NEVER raised as an error,
// because an exception a caller can catch and ignore is exactly how a missing
// evaluator turns into a passing result. A FORGED availability claim is a
// different matter and IS raised: presenting `state: 'AVAILABLE'` with no
// evaluator behind it is MalformedResult, not unavailability.
// Stated limit, not hidden: this transport is offline, so it cannot itself probe
// reachability. `reachable` is the caller's report. If an evaluator is
// unreachable and the caller does not say so, the injected `measure()` throws
// and the trial lands in INFRA_ERROR — which is still a non-passing, first-class
// outcome, never a pass.
//
// INFRA ERRORS ARE FIRST-CLASS OUTCOMES, GOVERNANCE REFUSALS PROPAGATE
// An exception raised by an injected `measure()` that is NOT a `BoardError`
// becomes an INFRA_ERROR outcome carrying the typed `error_code` (and never the
// message or the detail, which could carry a secret into an evidence file). A
// `BoardError` is NOT caught: a governance refusal must never be softened into
// a soft outcome, because a caught BlockedPolicy is a BlockedPolicy that
// somebody turned back into a number.
//
// A SKIPPED TRIAL IS A RECORDED OUTCOME, NOT AN ABSENT ROW
// The transport executes; it does not decide that a trial may be skipped. The
// layer that owns a partition (dataset.mjs, W2) is the one that knows a holdout
// was never unsealed, so it says so through `request.disposition` and the
// outcome is SKIPPED or UNRESOLVED with `measurement: null` and the caller's
// reason attached. Both are members of the closed `TRIAL_STATUSES` the
// comparator scores as VIOLATION, which is what "a skipped trial is a
// violation" means in practice: the row exists, it says why, and it cannot be
// read as a zero. Every member of `EXECUTOR_OUTCOMES` is reachable from
// `runTrial`; a declared outcome nothing can produce would be a fail-open
// waiting for the day someone needs it.
//
// LATENCY IS MEASURED AND CANNOT DECIDE
// `latency` is two clock readings from the INJECTED clock and carries the typed
// literal `decides: false`. It is deliberately EXCLUDED from `outcome_digest`,
// together with every timestamp: a digest that contained wall-clock values
// could not be reproduced on the next host, and an unreproducible digest cannot
// witness the A5 repeat-run property. Determinism is the harness's to prove
// (tests/research/harness.test.mjs, W5); what this module owes that proof is a
// digest that contains nothing host-dependent, and an `outcome_digest` that is
// equal across the two process-separated runs whenever the verdict is.
//
// THE TRIAL-STATUS VOCABULARY IS BOUND, AND THE BINDING IS CHECKED
// The trial statuses this module emits are named in
// `EXECUTOR_TRIAL_STATUS_BY_OUTCOME` and are bound to `TRIAL_STATUSES` from
// ./constants.mjs, which is now PUBLISHED:
// ['RESOLVED','SKIPPED','UNRESOLVED','INFRA_ERROR','NOT_MEASURED']. The binding
// is therefore no longer a deferred fact: it is asserted at import against the
// live ESM binding (see the invariant below), and every record reports it as
// `vocabulary_bound: true` rather than assuming it. The fail-closed half stays
// in place for a future divergence: an unbound status is never presented as
// usable, and `assertUsableAsResult` refuses one. The rule is unchanged by the
// sibling having landed — if the published set ever disagrees with the mapping
// below, the import aborts and the mapping is the defect, rather than the
// mismatch being reconciled at runtime in whichever direction runs first.
//
// SELF-CLEANUP, MIRRORING purgeProbeFixtures (src/lib/agentboard/probes.mjs:172)
// `purgeExecutorFixtures` removes THIS MODULE'S OWN namespace and nothing else:
// it is bounded to `<root>/executor-fixtures/<label>/`, so purging label `a`
// cannot delete label `b` — which matters because the A3 two-run track runs
// both labels on one machine. It refuses a filesystem root as the base, refuses
// a label that is not a bounded kebab/dot/dash token (the path-traversal
// guard), and UNLINKS a symlink instead of following it. It never creates the
// directory: a purge that creates state is not a purge, so the caller creates
// the namespace and the purge removes it. Idempotency is checkable, not
// self-certified: the report lists exactly what was removed, so a second call
// on the same state returns `present: false, removed: []`. Without this, a
// repeat run on a permanent base fails on its own leftovers instead of on the
// property under test.
//
// INTERFACE GAP — READ THIS BEFORE USING ANY NAME BELOW
// Plan §1 freezes eleven module interfaces and this file is not one of them;
// the interface index has no row for it. The export names below are therefore
// this module's OWN surface, not a frozen one, and they are NOT re-exported by
// src/lib/research/index.mjs (W4's barrel, which was written from the plan's
// eleven rows) — adding a name there would change a frozen surface, so it is
// not done unilaterally here.
// Reachability, stated precisely rather than claimed either way: the one export
// the track depends on IS wired in — `comparator.mjs:121` imports
// `EXECUTOR_PRODUCIBLE_LABELS` so the decision layer cannot widen the ceiling
// this file sets, which makes the ceiling load-bearing for A4. The rest is
// reachable by path only: no script, probe or committed test calls `runTrial`,
// `assertNoCausalClaim`, `assertUsableAsResult` or `purgeExecutorFixtures`, so
// `npm test` does not witness this file today. tests/research/ and scripts/
// belong to other workers, so that wiring is BLOCKED: to D and is NOT done
// here; what backs the file instead is the scratch check under this thread's
// own chat workspace, and this header is not allowed to imply a committed test
// that does not exist.
//
// Owner: the S2-008 executor worker. Budget: this file alone.
import { existsSync, lstatSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import {
  BlockedPolicy,
  MalformedResult,
  NeedsInput,
  isBoardError,
  toBoardError,
} from '../agentboard/errors.mjs';
import { TRIAL_STATUSES } from './constants.mjs';

// ---------------------------------------------------------------------------
// Frozen vocabulary
// ---------------------------------------------------------------------------

/**
 * The version of this transport, recorded in every outcome.
 * @type {string}
 */
export const EXECUTOR_VERSION = 's2-008-executor-v1';

/**
 * The three provenance labels the ticket names. This is the CLOSED label set:
 * a label outside it does not exist on this boundary, and
 * `assertProvenanceLabel` refuses it.
 * @type {ReadonlyArray<string>}
 */
export const EXECUTOR_PROVENANCE_LABELS = Object.freeze([
  'OBSERVATIONAL_TEST',
  'BACKTEST',
  'CAUSAL_EXPERIMENT',
]);

/**
 * The labels this transport is able to PRODUCE. CAUSAL_EXPERIMENT is
 * structurally absent, which is what makes "impossible, not merely
 * discouraged" checkable by membership rather than by reading a comment.
 * @type {ReadonlyArray<string>}
 */
export const EXECUTOR_PRODUCIBLE_LABELS = Object.freeze([
  'OBSERVATIONAL_TEST',
  'BACKTEST',
]);

/**
 * The trial kinds this transport accepts. There is no causal kind: a causal
 * experiment needs an intervention and a randomised assignment, and this
 * transport has neither.
 * @type {ReadonlyArray<string>}
 */
export const EXECUTOR_TRIAL_KINDS = Object.freeze([
  'OBSERVATIONAL_EVALUATION',
  'HOLDOUT_EVALUATION',
]);

/**
 * kind -> label. TOTAL over `EXECUTOR_TRIAL_KINDS` and total into
 * `EXECUTOR_PRODUCIBLE_LABELS`; both properties are asserted at import below,
 * so an edit that adds a kind without a producible label aborts the import
 * instead of shipping a causal branch.
 * @type {Readonly<Record<string, string>>}
 */
export const EXECUTOR_LABELS_BY_KIND = Object.freeze({
  OBSERVATIONAL_EVALUATION: 'OBSERVATIONAL_TEST',
  HOLDOUT_EVALUATION: 'BACKTEST',
});

/**
 * The transport's own EXECUTION outcomes, on a different axis from the track's
 * RESEARCH_OUTCOMES. `MEASURED` means a number came back; whether that number
 * is POSITIVE, NEGATIVE or NULL is `decisionFromInterval`'s question in
 * comparator.mjs and is never decided here. Conflating the two axes would let
 * an execution state be read as a scientific conclusion, which is the exact
 * confusion A4 exists to prevent.
 * @type {ReadonlyArray<string>}
 */
export const EXECUTOR_OUTCOMES = Object.freeze([
  'MEASURED',
  'EVALUATOR_UNAVAILABLE',
  'MEASUREMENT_ABSENT',
  'INFRA_ERROR',
  'UNRESOLVED',
  'SKIPPED',
]);

/**
 * What the CALLER told the transport to do with this trial. The transport
 * executes; it does not decide that a trial may be skipped. `SKIP` and
 * `UNRESOLVE` exist because the layer that owns a partition (dataset.mjs, W2)
 * can be the one that knows a holdout was never unsealed — and that trial must
 * be recorded as SKIPPED, a first-class outcome the comparator scores as
 * VIOLATION, rather than dropped or recorded as a zero. A declared outcome that
 * nothing can produce is a fail-open waiting to happen, so the vocabulary above
 * is closed over what this module can actually return.
 * @type {ReadonlyArray<string>}
 */
export const EXECUTOR_DISPOSITIONS = Object.freeze(['EXECUTE', 'SKIP', 'UNRESOLVE']);

/**
 * The frozen execution-outcome -> in-contract trial-status map. Every value is
 * a member of the track's closed `TRIAL_STATUSES`
 * (RESOLVED|SKIPPED|UNRESOLVED|INFRA_ERROR|NOT_MEASURED), and only `MEASURED`
 * maps to `RESOLVED`. EVALUATOR_UNAVAILABLE and MEASUREMENT_ABSENT both map to
 * NOT_MEASURED, which the comparator scores as VIOLATION — a missing evaluator
 * and a missing measurement are different reasons with the same fail-closed
 * consequence, and the reason is always carried alongside.
 * @type {Readonly<Record<string, string>>}
 */
export const EXECUTOR_TRIAL_STATUS_BY_OUTCOME = Object.freeze({
  MEASURED: 'RESOLVED',
  EVALUATOR_UNAVAILABLE: 'NOT_MEASURED',
  MEASUREMENT_ABSENT: 'NOT_MEASURED',
  INFRA_ERROR: 'INFRA_ERROR',
  UNRESOLVED: 'UNRESOLVED',
  SKIPPED: 'SKIPPED',
});

/**
 * The two evaluator-availability states. There is no third "assume it is
 * fine" state: `AVAILABLE` requires an evaluator record behind it.
 * @type {ReadonlyArray<string>}
 */
export const EXECUTOR_EVALUATOR_STATES = Object.freeze([
  'AVAILABLE',
  'EVALUATOR_UNAVAILABLE',
]);

/**
 * Why the evaluator is unavailable. `evaluator_not_independent` and
 * `calibration_not_measured` correspond to the in-contract
 * `not_measured_reason` enum of contracts/calibration-record.schema.json
 * (['no_valid_corpus','insufficient_samples','evaluator_not_independent',
 * 'outcome_not_defined']); the exact in-contract value is carried in
 * `calibration_not_measured_reason` so the record never invents an enum member.
 * @type {ReadonlyArray<string>}
 */
export const EXECUTOR_EVALUATOR_REASONS = Object.freeze([
  'evaluator_absent',
  'evaluator_unreachable',
  'evaluator_not_independent',
  'calibration_not_measured',
]);

/**
 * The track's own published inference mode (plan §6: "the track's own
 * `inference_mode` is ASSOCIATIONAL and is published in the
 * preregistration"). Any other inference mode in a claim is a causal claim.
 * @type {string}
 */
export const EXECUTOR_INFERENCE_MODE = 'ASSOCIATIONAL';

/**
 * The measurement statistics this transport can compute from a frozen case
 * record's `metric_samples`, with no domain knowledge of its own.
 * @type {ReadonlyArray<string>}
 */
export const EXECUTOR_STATISTICS = Object.freeze(['mean', 'sum', 'n']);

/**
 * The fixture namespace this module owns, under a caller-supplied root. One
 * label per subdirectory, so two runs on one machine cannot purge each other.
 * @type {string}
 */
export const EXECUTOR_FIXTURE_DIRNAME = 'executor-fixtures';

/**
 * The label shape accepted for a fixture namespace, as a source string so it
 * travels through canonical JSON and evidence like any other value. A caller
 * compiles it with `new RegExp(EXECUTOR_FIXTURE_LABEL_PATTERN)`; the transport
 * does the same, internally. The shape admits no `/`, no `\`, no `..` and no
 * leading dot, which is the path-traversal guard.
 * @type {string}
 */
export const EXECUTOR_FIXTURE_LABEL_PATTERN = '^[a-z0-9][a-z0-9._-]{0,63}$';

const LABEL_PATTERN = new RegExp(EXECUTOR_FIXTURE_LABEL_PATTERN);
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const MAX_IDENTIFIER = 128;
const MAX_DETAIL = 300;

// Import-time invariant. A vocabulary that cannot produce a label for every
// kind, or that names a label outside the producible set, is a defect in this
// file and must abort the import rather than be discovered by a probe.
for (const kind of EXECUTOR_TRIAL_KINDS) {
  const label = EXECUTOR_LABELS_BY_KIND[kind];
  if (!EXECUTOR_PRODUCIBLE_LABELS.includes(label)) {
    throw new Error(`EXECUTOR_VOCABULARY_INCONSISTENT:kind ${kind} maps to no producible label`);
  }
}
for (const outcome of EXECUTOR_OUTCOMES) {
  if (typeof EXECUTOR_TRIAL_STATUS_BY_OUTCOME[outcome] !== 'string') {
    throw new Error(`EXECUTOR_VOCABULARY_INCONSISTENT:outcome ${outcome} has no trial status`);
  }
}
// Same rule one level out, against the sibling's PUBLISHED vocabulary: a status
// this transport emits that the track does not define is a divergence that must
// abort here rather than travel as `vocabulary_bound: false` into every record
// until someone reads the flag. An unpublished vocabulary (the frozen-skeleton
// `null`) is not a divergence and does NOT throw — that state is already
// fail-closed, because `assertUsableAsResult` refuses an unbound outcome.
if (Array.isArray(TRIAL_STATUSES)) {
  for (const [outcome, status] of Object.entries(EXECUTOR_TRIAL_STATUS_BY_OUTCOME)) {
    if (!TRIAL_STATUSES.includes(status)) {
      throw new Error(
        `EXECUTOR_VOCABULARY_INCONSISTENT:outcome ${outcome} maps to '${status}', `
        + `which the published TRIAL_STATUSES [${TRIAL_STATUSES.join('|')}] does not contain`,
      );
    }
  }
}
if (EXECUTOR_LABELS_BY_KIND.CAUSAL_EXPERIMENT !== undefined) {
  throw new Error('EXECUTOR_VOCABULARY_INCONSISTENT:this transport must not map a causal kind');
}

// ---------------------------------------------------------------------------
// Local helpers (deliberately small, and deliberately not exported)
// ---------------------------------------------------------------------------

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return Object.freeze(value);
}

// The board's own `requireClock` (src/lib/agentboard/adapters.mjs:251) is
// private and exporting it would be an edit to a read-only file, so the same
// three-line contract is restated here rather than imported: an injected clock
// is mandatory and the process clock is never read. If the two ever disagree,
// this file's copy is the defect.
function requireInjectedClock(clock) {
  if (!isPlainObject(clock) || typeof clock.now !== 'function') {
    throw new NeedsInput(
      'CLOCK_REQUIRED',
      'an injected clock with now() -> Date is mandatory; the process clock is never read',
    );
  }
  return () => {
    const value = clock.now();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
      throw new NeedsInput('CLOCK_SHAPE', 'now() must return a valid Date');
    }
    return value;
  };
}

// canonicalDigest raises a TypeError (code NON_CANONICAL_VALUE) for a value it
// cannot represent — an undefined array member, a non-finite number, a Date, a
// cycle. An untyped TypeError escaping a transport is indistinguishable from a
// crash, so it is converted into a typed refusal that names the offending input.
function digestOf(value, label) {
  try {
    return canonicalDigest(value);
  } catch (error) {
    throw new MalformedResult(
      `CANONICAL_INPUT_UNSAFE:${label}`,
      String(error?.message ?? error).slice(0, MAX_DETAIL),
    );
  }
}

function requireIdentifier(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_IDENTIFIER) {
    throw new MalformedResult(
      `IDENTIFIER_INVALID:${label}`,
      `a non-empty string of at most ${MAX_IDENTIFIER} characters is required`,
    );
  }
  return value;
}

function requireDigest(value, label) {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new MalformedResult(
      `DIGEST_INVALID:${label}`,
      'a lowercase 64-character sha256 hex digest is required; a missing digest is not a wildcard',
    );
  }
  return value;
}

function boundedDetail(value) {
  return String(value).slice(0, MAX_DETAIL);
}

/** True when a status is a member of the track's closed TRIAL_STATUSES. */
function boundToTrackVocabulary(status) {
  return Array.isArray(TRIAL_STATUSES) && TRIAL_STATUSES.includes(status);
}

/**
 * Whether a status is bound to the track's frozen `TRIAL_STATUSES` vocabulary.
 *
 * @param {string} status An in-contract trial status, e.g. 'RESOLVED'.
 * @returns {boolean} True only when ./constants.mjs has published a non-empty
 *   `TRIAL_STATUSES` containing it. A false here is never treated as a pass:
 *   `assertUsableAsResult` refuses an unbound outcome, so an unbound status can
 *   only ever be a non-decision. The import is a live ESM binding, so this
 *   starts reporting true the moment W1 lands the vocabulary, with no restart
 *   of this module and no second copy of the enum.
 */
export function trackVocabularyBound(status) {
  return boundToTrackVocabulary(status);
}

// ---------------------------------------------------------------------------
// Provenance labels
// ---------------------------------------------------------------------------

/**
 * Whether a label is one this transport is able to produce.
 * @param {string} label A candidate provenance label.
 * @returns {boolean} Membership of `EXECUTOR_PRODUCIBLE_LABELS`. Pure.
 */
export function isProducibleLabel(label) {
  return EXECUTOR_PRODUCIBLE_LABELS.includes(label);
}

/**
 * The provenance label a trial kind is DERIVED to carry. The label is never
 * copied from the caller, so a caller cannot attach a label the kind does not
 * support.
 * @param {string} kind A member of `EXECUTOR_TRIAL_KINDS`.
 * @returns {string} A member of `EXECUTOR_PRODUCIBLE_LABELS`.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} on an unknown
 *   kind, including 'CAUSAL_EXPERIMENT': this transport has no causal kind, and
 *   the refusal says so instead of falling back to a default label.
 */
export function provenanceLabelForTrialKind(kind) {
  const label = isPlainObject(EXECUTOR_LABELS_BY_KIND) ? EXECUTOR_LABELS_BY_KIND[kind] : undefined;
  if (typeof label !== 'string') {
    throw new MalformedResult(
      'TRIAL_KIND_UNKNOWN',
      `'${boundedDetail(kind)}' is not an executable trial kind; this transport executes `
      + `${EXECUTOR_TRIAL_KINDS.join('|')} and cannot execute a causal experiment`,
    );
  }
  return assertProvenanceLabel(label);
}

/**
 * Assert a provenance label is one this transport may carry, and return it.
 * @param {string} label The label to check.
 * @param {Function} [ErrorClass] The typed class to throw; defaults to
 *   `MalformedResult` from ../agentboard/errors.mjs.
 * @returns {string} The same label, when it is producible.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'PROVENANCE_LABEL_NOT_PRODUCIBLE' for CAUSAL_EXPERIMENT and for any label
 *   outside the closed set — the ceiling of this transport, stated as a typed
 *   refusal rather than as a comment.
 */
export function assertProvenanceLabel(label, ErrorClass = MalformedResult) {
  if (!isProducibleLabel(label)) {
    throw new ErrorClass(
      'PROVENANCE_LABEL_NOT_PRODUCIBLE',
      `'${boundedDetail(label)}' is not a label this transport can produce; producible labels are `
      + `${EXECUTOR_PRODUCIBLE_LABELS.join('|')} and a causal experiment is not among them`,
    );
  }
  return label;
}

// ---------------------------------------------------------------------------
// The A4 causal-claim guard (transport side)
// ---------------------------------------------------------------------------

/**
 * The fields of a claim that assert causality, named as the contract names
 * them. Every entry is a real field of a real document, not a private flag:
 * `causal_assertion` is `proposed_relation.causal_assertion` of
 * contracts/hypothesis-card.schema.json (a free
 * `oneOf: [{type: boolean}, {type: null}]` that the frozen schema cannot
 * constrain), and `inference_mode` is the track's own published mode.
 * @param {object} claim The claim document.
 * @returns {ReadonlyArray<string>} The offending field paths, in a fixed order.
 *   Empty when the claim asserts no causality.
 */
export function causalClaimFields(claim) {
  if (!isPlainObject(claim)) return [];
  const fields = [];
  const relation = isPlainObject(claim.proposed_relation) ? claim.proposed_relation : null;
  if (claim.causal_assertion === true) fields.push('causal_assertion');
  if (relation !== null && relation.causal_assertion === true) fields.push('proposed_relation.causal_assertion');
  if (typeof claim.inference_mode === 'string' && claim.inference_mode !== EXECUTOR_INFERENCE_MODE) {
    fields.push('inference_mode');
  }
  return Object.freeze(fields);
}

/**
 * Whether a claim asserts causality. Pure, total, and cheap enough to use as a
 * predicate — but never as a substitute for `assertNoCausalClaim`, because a
 * boolean a caller may ignore is not a guard.
 * @param {object} claim A claim document, a hypothesis card, or any object
 *   carrying `causal_assertion`, `proposed_relation.causal_assertion` or
 *   `inference_mode`.
 * @returns {boolean} True when at least one causal field is asserted.
 */
export function claimAssertsCausality(claim) {
  return causalClaimFields(claim).length > 0;
}

/**
 * THE A4 GUARD, TRANSPORT SIDE: refuse a causal claim whose evidence this
 * transport produced. Throws; never annotates, never warns, never returns an
 * `admissible: false` a caller can forget to read.
 * @param {object} claim The claim to guard. Must carry the provenance of the
 *   evidence it rests on as `provenance_label` (a member of
 *   `EXECUTOR_PROVENANCE_LABELS`); a causal-claim check that does not know
 *   where the evidence came from is not a check.
 * @returns {object} A frozen `{permitted: true, asserted_fields: []}` when the
 *   claim asserts no causality. Anything else throws.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'CAUSAL_LABEL_NOT_PRODUCIBLE_BY_THIS_TRANSPORT' when the claim presents
 *   this transport as a CAUSAL_EXPERIMENT;
 *   'CAUSAL_CLAIM_FROM_NON_CAUSAL_EVIDENCE' when a non-causal label carries a
 *   causal assertion, with the offending field paths named in the detail. This
 *   second refusal IS acceptance item A4: an observational or backtest result
 *   cannot be read as causal, and the substituted label must fail.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'PROVENANCE_LABEL_MISSING' / 'PROVENANCE_LABEL_UNKNOWN' when the evidence's
 *   own provenance is absent or outside the closed label set.
 */
export function assertNoCausalClaim(claim) {
  if (!isPlainObject(claim)) {
    throw new MalformedResult('CLAIM_MALFORMED', 'a claim must be an object; a string is not a claim');
  }
  const label = claim.provenance_label;
  if (label === undefined || label === null) {
    throw new MalformedResult(
      'PROVENANCE_LABEL_MISSING',
      'the evidence provenance is required: a causal claim without knowing where the evidence came from is not a check',
    );
  }
  if (!EXECUTOR_PROVENANCE_LABELS.includes(label)) {
    throw new MalformedResult(
      'PROVENANCE_LABEL_UNKNOWN',
      `'${boundedDetail(label)}' is not a member of the closed provenance label set`,
    );
  }
  if (!isProducibleLabel(label)) {
    throw new BlockedPolicy(
      'CAUSAL_LABEL_NOT_PRODUCIBLE_BY_THIS_TRANSPORT',
      `this transport produces ${EXECUTOR_PRODUCIBLE_LABELS.join('|')} and never `
      + `${label}; the claim may not be sourced to it`,
    );
  }
  const fields = causalClaimFields(claim);
  if (fields.length > 0) {
    throw new BlockedPolicy(
      'CAUSAL_CLAIM_FROM_NON_CAUSAL_EVIDENCE',
      `evidence label '${label}' is non-causal and cannot support a causal claim; asserted by `
      + `${fields.join(', ')}; card_type '${boundedDetail(claim.card_type ?? 'UNSTATED')}' does not change this`,
    );
  }
  return Object.freeze({
    permitted: true,
    label,
    asserted_fields: Object.freeze([]),
  });
}

/**
 * The post-condition on a produced or re-read record: its provenance label must
 * be producible AND must equal the label its trial kind derives to. A record
 * whose label was changed after the fact is refused rather than trusted, which
 * is what makes the label-substitution control bite on a record read back from
 * disk, not only on a live call.
 * @param {object} outcome An outcome record, or anything carrying `trial_kind`
 *   and `provenance_label`.
 * @returns {object} The same record, unchanged, when the label is consistent.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'OUTCOME_PROVENANCE_MISMATCH' when the label does not match the derived
 *   one, and 'PROVENANCE_LABEL_NOT_PRODUCIBLE' (via
 *   `assertProvenanceLabel`) when it is CAUSAL_EXPERIMENT.
 */
export function assertOutcomeProvenance(outcome) {
  if (!isPlainObject(outcome)) {
    throw new MalformedResult('OUTCOME_MALFORMED', 'an outcome must be an object');
  }
  assertProvenanceLabel(outcome.provenance_label);
  const derived = provenanceLabelForTrialKind(outcome.trial_kind);
  if (outcome.provenance_label !== derived) {
    throw new MalformedResult(
      'OUTCOME_PROVENANCE_MISMATCH',
      `kind '${boundedDetail(outcome.trial_kind)}' derives '${derived}', the record claims `
      + `'${boundedDetail(outcome.provenance_label)}'`,
    );
  }
  return outcome;
}

// ---------------------------------------------------------------------------
// Evaluator availability (P6 / A2)
// ---------------------------------------------------------------------------

/**
 * The evaluator-availability state of a trial. An explicit state object, not a
 * boolean and not an exception: a missing or unreachable evaluator is an
 * OUTCOME that the comparator scores fail-closed, and a boolean would be one
 * `if` away from being the wrong answer.
 * @param {{evaluator?: object|null, calibration?: object|null,
 *   reachable?: boolean, claimed_state?: string}} args
 * @param {object|null} [args.evaluator] The evaluator record, or null/absent.
 * @param {object|null} [args.calibration] A
 *   contracts/calibration-record.schema.json document, or null/absent.
 * @param {boolean} [args.reachable] The caller's reachability report. This
 *   transport is offline and never probes reachability itself; an unreported
 *   unreachability surfaces as an INFRA_ERROR from the injected measure, which
 *   is still a non-passing outcome.
 * @param {string} [args.claimed_state] A state the caller asserts. The state is
 *   DERIVED from the evidence and the claim NEVER decides it, in either
 *   direction: an `AVAILABLE` claim with no evaluator behind it is forged and
 *   is REFUSED, because that is the one shape by which a missing evaluator
 *   could still be recorded as a passing result; the opposite claim (a caller
 *   asserting `EVALUATOR_UNAVAILABLE` while a well-formed evaluator is present)
 *   cannot manufacture a pass either, so it is not refused — but it is not
 *   silently dropped either. It is echoed as `claimed_state` with
 *   `claim_agrees`, so an evidence reader can SEE that a caller asserted
 *   something the evidence contradicts, instead of reading a derived state and
 *   never learning that the caller disagreed. The asymmetry is deliberate and
 *   one-directional: only a lie that could CREATE a pass is fatal.
 * @returns {object} A deep-frozen availability record. `state` is a member of
 *   `EXECUTOR_EVALUATOR_STATES`; when it is not `AVAILABLE`, `reason` is a
 *   member of `EXECUTOR_EVALUATOR_REASONS` and `trial_status` is the
 *   in-contract status the transport emits ('NOT_MEASURED'). Every record
 *   carries `decides: false`: availability is an INPUT to the comparator's
 *   decision and is never itself a decision. `claimed_state` is the caller's
 *   assertion echoed back (`null` when none was made) and `claim_agrees` says
 *   whether it matches the derived `state` (`null` when no claim was made);
 *   both are evidence about the CALLER and neither influences the state.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'EVALUATOR_STATE_UNKNOWN' for a state outside the closed two-value set,
 *   'EVALUATOR_STATE_FORGED' for `AVAILABLE` without an evaluator, and
 *   'IDENTIFIER_INVALID' for a present evaluator record with no usable
 *   identifier. Note what is NOT thrown: an absent, unreachable or
 *   non-independent evaluator. Those are outcomes, and turning them into
 *   exceptions is how a missing evaluator becomes a passing result.
 */
export function resolveEvaluatorAvailability({ evaluator, calibration, reachable, claimed_state: claimedState } = {}) {
  if (claimedState !== undefined && !EXECUTOR_EVALUATOR_STATES.includes(claimedState)) {
    throw new MalformedResult(
      'EVALUATOR_STATE_UNKNOWN',
      `'${boundedDetail(claimedState)}' is not a member of ${EXECUTOR_EVALUATOR_STATES.join('|')}`,
    );
  }
  const present = isPlainObject(evaluator);
  if (claimedState === 'AVAILABLE' && !present) {
    throw new MalformedResult(
      'EVALUATOR_STATE_FORGED',
      'availability was claimed with no evaluator record behind it; a claim of availability is not an evaluator',
    );
  }

  const independence = isPlainObject(calibration) && isPlainObject(calibration.evaluator_independence)
    ? calibration.evaluator_independence
    : null;
  const base = {
    state: 'EVALUATOR_UNAVAILABLE',
    reason: null,
    evaluator_id: present ? requireIdentifier(evaluator.evaluator_id ?? evaluator.id, 'evaluator.evaluator_id') : null,
    independent: independence !== null
      && Number.isInteger(independence.independent_evaluators)
      && independence.independent_evaluators >= 1,
    blind_to_producer: independence !== null && independence.blind_to_producer === true,
    calibration_status: isPlainObject(calibration) && typeof calibration.status === 'string' ? calibration.status : null,
    calibration_not_measured_reason: isPlainObject(calibration) && typeof calibration.not_measured_reason === 'string'
      ? calibration.not_measured_reason
      : null,
    vocabulary_bound: false,
    decides: false,
  };

  // The claim is attached last, on purpose: it can only be compared against a
  // state that has already been derived, and it is never fed back into the
  // derivation. `attachClaim` is a pure addition to the record shape — the
  // digested fields (`state`, `reason`) are untouched, so an evidence record
  // that carries the echo still digests identically to one that does not.
  const attachClaim = (record) => deepFreeze({
    ...record,
    claimed_state: claimedState === undefined ? null : claimedState,
    claim_agrees: claimedState === undefined ? null : claimedState === record.state,
  });

  const unavailable = (reason) => {
    const record = { ...base, reason, trial_status: 'NOT_MEASURED' };
    record.vocabulary_bound = boundToTrackVocabulary(record.trial_status);
    return attachClaim(record);
  };

  // First match wins, most specific first. The order is deliberate: an
  // unreleased calibration is a MEASUREMENT problem and is named as such,
  // while a calibration that IS measured but blind to the producer is an
  // INDEPENDENCE problem and is named as that.
  if (!present) return unavailable('evaluator_absent');
  if (reachable === false || evaluator.reachable === false) return unavailable('evaluator_unreachable');
  if (base.calibration_status !== 'MEASURED') return unavailable('calibration_not_measured');
  if (!recordIsIndependent(base)) return unavailable('evaluator_not_independent');

  const available = {
    ...base,
    state: 'AVAILABLE',
    reason: null,
    trial_status: 'RESOLVED',
  };
  available.vocabulary_bound = boundToTrackVocabulary(available.trial_status);
  return attachClaim(available);
}

function recordIsIndependent(record) {
  return record.independent === true && record.blind_to_producer === true;
}

// ---------------------------------------------------------------------------
// The transport
// ---------------------------------------------------------------------------

function computeStatistic(samples, statistic) {
  if (!Array.isArray(samples)) {
    throw new MalformedResult(
      'METRIC_SAMPLES_INVALID',
      `metric_samples must be an array of finite numbers, got ${Array.isArray(samples) ? 'array' : typeof samples}`,
    );
  }
  for (let index = 0; index < samples.length; index += 1) {
    if (typeof samples[index] !== 'number' || !Number.isFinite(samples[index])) {
      throw new MalformedResult(
        'METRIC_SAMPLES_INVALID',
        `metric_samples[${index}] is not a finite number`,
      );
    }
  }
  if (statistic === 'n') return { statistic: 'n', value: samples.length, n: samples.length };
  // Summation follows the array's own order, so the value is reproducible for
  // a fixed input on any host with the same IEEE-754 semantics.
  let total = 0;
  for (const sample of samples) total += sample;
  const value = statistic === 'sum' ? total : total / samples.length;
  if (!Number.isFinite(value)) {
    throw new MalformedResult('MEASUREMENT_NOT_FINITE', 'the computed statistic is not finite');
  }
  return { statistic, value, n: samples.length };
}

function normalizeMeasurement(raw) {
  if (typeof raw === 'number') {
    if (!Number.isFinite(raw)) {
      throw new MalformedResult('MEASUREMENT_NOT_FINITE', 'the measured value is not finite');
    }
    return { statistic: 'value', value: raw, n: 1 };
  }
  if (!isPlainObject(raw)) {
    throw new MalformedResult(
      'MEASUREMENT_SHAPE',
      'a measure() must return a finite number or {statistic, value, n}',
    );
  }
  if (typeof raw.value !== 'number' || !Number.isFinite(raw.value)) {
    throw new MalformedResult('MEASUREMENT_NOT_FINITE', 'measurement.value must be a finite number');
  }
  const n = raw.n === undefined ? 1 : raw.n;
  if (!Number.isInteger(n) || n < 1) {
    throw new MalformedResult('MEASUREMENT_SHAPE', 'measurement.n must be an integer of at least 1');
  }
  const named = typeof raw.statistic === 'string' && raw.statistic.length > 0 && raw.statistic.length <= 64;
  return { statistic: named ? raw.statistic : 'value', value: raw.value, n };
}

/**
 * Execute ONE trial from frozen inputs and return the measurement plus its
 * mandatory provenance label.
 *
 * The order of the checks is the design, not an accident:
 *   1. the injected clock is required (the process clock is never read);
 *   2. the request is validated and the label is DERIVED from the trial kind;
 *   3. a caller-presented `requested_label` is checked for producibility and
 *      then for agreement with the derived label;
 *   4. a presented causal claim is guarded BEFORE the evaluator is consulted,
 *      so a causal reading of a non-causal trial costs nothing and leaves no
 *      measurement behind;
 *   5. evaluator availability is resolved — an unavailable evaluator returns
 *      the EVALUATOR_UNAVAILABLE outcome without ever calling the measurer;
 *   6. the caller's disposition is honoured: SKIP / UNRESOLVE return those
 *      first-class outcomes with `measurement: null`, so a trial the dataset
 *      layer refused to run is RECORDED, never dropped and never a zero. A
 *      disposition is decided BEFORE the availability branch, because a trial
 *      that was not run has no evaluator finding to report;
 *   7. the measurement is taken, and its shape is checked rather than trusted;
 *   8. a governance `BoardError` from the measurer PROPAGATES, any other
 *      exception becomes an INFRA_ERROR outcome carrying only the typed code;
 *   9. the produced record passes the provenance post-condition and is frozen.
 *
 * @param {{
 *   request: object, record: object, clock: object,
 *   evaluator?: object|null, calibration?: object|null, reachable?: boolean,
 *   claimed_state?: string, measure?: Function, claim?: object|null
 * }} args
 * @param {object} args.request `{trial_id, executor_id, trial_kind,
 *   preregistration_digest, case_digest, statistic?, disposition?,
 *   requested_label?, skip_reason?}`. `trial_id` and `executor_id` are supplied
 *   by the caller: the ledger owns identifiers. `preregistration_digest` and
 *   `case_digest` are REQUIRED 64-hex digests — a trial is executed from frozen
 *   inputs, and "frozen" is a digest, not an intention.
 * @param {object} args.record The frozen case record. With no injected
 *   `measure`, the record must carry `metric_samples`, a non-empty array of
 *   finite numbers; without them the outcome is MEASUREMENT_ABSENT with
 *   `measurement: null`, never a fabricated number.
 * @param {object} args.clock REQUIRED injected clock `{now: () => Date}`.
 * @param {object|null} [args.evaluator] The evaluator record, or null.
 * @param {object|null} [args.calibration] The calibration record, or null.
 * @param {boolean} [args.reachable] The caller's reachability report.
 * @param {string} [args.claimed_state] A state the caller asserts, forwarded
 *   to `resolveEvaluatorAvailability` so that a forged `AVAILABLE` claim is a
 *   typed refusal HERE too, and not only when the availability resolver is
 *   called on its own. Ignoring such a key would be a small fail-open: the
 *   verdict would still come out right, but the lie would go unreported.
 * @param {Function} [args.measure] An injected PURE measurer
 *   `(record, request) => number | {statistic, value, n}`, sync or async. It is
 *   the only place domain knowledge enters; the transport owns nothing but the
 *   governance around it.
 * @param {object|null} [args.claim] A hypothesis card or claim to guard before
 *   the measurement is taken (see `assertNoCausalClaim`).
 * @returns {Promise<object>} A deep-frozen outcome record: `outcome`, the
 *   in-contract `trial_status`, `vocabulary_bound`, the deep-frozen `measurement`
 *   (or null), the `provenance_label` and `inference_mode`, the frozen
 *   `evaluator` availability, `inputs_digest`, `request_digest`, `record_digest`
 *   and `outcome_digest`, the `latency` block (`decides: false`) and `reason`.
 *   `outcome_digest` deliberately EXCLUDES every timestamp and the latency
 *   block, so it is reproducible across hosts and can witness A5.
 * @throws {import('../agentboard/errors.mjs').NeedsInput} CLOCK_REQUIRED /
 *   CLOCK_SHAPE; {import('../agentboard/errors.mjs').MalformedResult} for a
 *   malformed request, an unproducible or mismatched label, an unsafe canonical
 *   input or a malformed measurement;
 *   {import('../agentboard/errors.mjs').BlockedPolicy} for a causal claim over
 *   non-causal evidence. A governance refusal is never converted into an
 *   outcome: a caught BlockedPolicy is a refusal somebody turned back into a
 *   number.
 */
export async function runTrial({
  request, record, clock, evaluator, calibration, reachable, claimed_state: claimedState, measure, claim,
} = {}) {
  const now = requireInjectedClock(clock);

  if (!isPlainObject(request)) {
    throw new MalformedResult('REQUEST_MALFORMED', 'a trial request must be an object');
  }
  if (!isPlainObject(record)) {
    throw new MalformedResult(
      'CASE_RECORD_MISSING',
      'the frozen case record is required; a trial executed without its case is not a trial',
    );
  }
  const trialId = requireIdentifier(request.trial_id, 'request.trial_id');
  const executorId = requireIdentifier(request.executor_id, 'request.executor_id');
  const preregistrationDigest = requireDigest(request.preregistration_digest, 'request.preregistration_digest');
  const caseDigest = requireDigest(request.case_digest, 'request.case_digest');
  const statistic = request.statistic === undefined ? 'mean' : request.statistic;
  if (!EXECUTOR_STATISTICS.includes(statistic)) {
    throw new MalformedResult(
      'STATISTIC_UNKNOWN',
      `'${boundedDetail(statistic)}' is not a member of ${EXECUTOR_STATISTICS.join('|')}`,
    );
  }
  const disposition = request.disposition === undefined ? 'EXECUTE' : request.disposition;
  if (!EXECUTOR_DISPOSITIONS.includes(disposition)) {
    throw new MalformedResult(
      'DISPOSITION_UNKNOWN',
      `'${boundedDetail(disposition)}' is not a member of ${EXECUTOR_DISPOSITIONS.join('|')}`,
    );
  }

  // The label is derived here and nowhere else.
  const label = provenanceLabelForTrialKind(request.trial_kind);
  if (request.requested_label !== undefined) {
    assertProvenanceLabel(request.requested_label);
    if (request.requested_label !== label) {
      throw new MalformedResult(
        'REQUESTED_LABEL_MISMATCH',
        `kind '${boundedDetail(request.trial_kind)}' derives '${label}', the request asked for `
        + `'${boundedDetail(request.requested_label)}'`,
      );
    }
  }

  // The claim is guarded before anything is measured.
  let causalClaim = null;
  if (claim !== undefined && claim !== null) {
    const guarded = claim.provenance_label === undefined ? { ...claim, provenance_label: label } : claim;
    causalClaim = assertNoCausalClaim(guarded);
    if (guarded.provenance_label !== label) {
      throw new MalformedResult(
        'CLAIM_PROVENANCE_MISMATCH',
        `the trial derived '${label}' but the claim was sourced to '${boundedDetail(guarded.provenance_label)}'`,
      );
    }
  }

  const requestDigest = digestOf(request, 'request');
  const recordDigest = digestOf(record, 'record');
  const availability = resolveEvaluatorAvailability({ evaluator, calibration, reachable, claimed_state: claimedState });

  const core = {
    executor_version: EXECUTOR_VERSION,
    trial_id: trialId,
    executor_id: executorId,
    trial_kind: request.trial_kind,
    provenance_label: label,
    inference_mode: EXECUTOR_INFERENCE_MODE,
    preregistration_digest: preregistrationDigest,
    case_digest: caseDigest,
    request_digest: requestDigest,
    record_digest: recordDigest,
  };

  const startedAt = now();
  const settle = (outcome, measurement, reason, extra) => {
    const finishedAt = now();
    const trialStatus = EXECUTOR_TRIAL_STATUS_BY_OUTCOME[outcome];
    const fields = {
      ...core,
      outcome,
      trial_status: trialStatus,
      vocabulary_bound: boundToTrackVocabulary(trialStatus),
      measurement,
      evaluator: availability,
      reason,
      causal_claim: causalClaim,
      // Excluded from outcome_digest on purpose: a host-dependent digest could
      // not witness "same base => same outcome" on the next host.
      latency: {
        started_at: startedAt.toISOString(),
        finished_at: finishedAt.toISOString(),
        source: 'injected',
        decides: false,
      },
      ...(extra ?? {}),
    };
    fields.inputs_digest = canonicalDigest({
      request_digest: requestDigest, record_digest: recordDigest, trial_kind: core.trial_kind,
    });
    fields.outcome_digest = canonicalDigest({
      trial_id: trialId,
      executor_id: executorId,
      trial_kind: core.trial_kind,
      provenance_label: label,
      outcome,
      trial_status: trialStatus,
      measurement,
      evaluator_state: availability.state,
      evaluator_reason: availability.reason,
      preregistration_digest: preregistrationDigest,
      case_digest: caseDigest,
      request_digest: requestDigest,
      record_digest: recordDigest,
    });
    const outcomeRecord = assertOutcomeProvenance(fields);
    return deepFreeze(outcomeRecord);
  };

  // A trial the dataset layer refused to run is a RECORDED outcome, not an
  // absent row, and it is decided BEFORE the availability branch: the trial was
  // not run, so the evaluator was never needed and saying EVALUATOR_UNAVAILABLE
  // instead would hide the fact that actually mattered. `skip_reason` is the
  // caller's, carried verbatim (bounded) so the record says which rule refused
  // it. The availability record is still computed and still carried, and a
  // FORGED availability claim still throws above — a defect is a defect even
  // when the trial was not going to run.
  if (disposition === 'SKIP') {
    return settle('SKIPPED', null, boundedDetail(request.skip_reason ?? 'skipped_by_caller'));
  }
  if (disposition === 'UNRESOLVE') {
    return settle('UNRESOLVED', null, boundedDetail(request.skip_reason ?? 'unresolved_by_caller'));
  }
  if (availability.state !== 'AVAILABLE') {
    // No measurement, no zero, no measurer call. This is the P6 outcome.
    return settle('EVALUATOR_UNAVAILABLE', null, `evaluator_unavailable:${availability.reason}`, {
      measurement_absent_reason: availability.reason,
    });
  }

  // An ABSENCE of data is a state, not a defect. A PRESENT but invalid sample
  // array is the opposite and throws in the try below: an absence may not be
  // laundered into a number, and a corrupt array may not be laundered into an
  // absence.
  const samples = record.metric_samples;
  if (samples === undefined || (Array.isArray(samples) && samples.length === 0)) {
    const absent = samples === undefined ? 'metric_samples_absent' : 'metric_samples_empty';
    return settle('MEASUREMENT_ABSENT', null, absent, { measurement_absent_reason: absent });
  }

  let measurement = null;
  try {
    if (typeof measure === 'function') {
      measurement = normalizeMeasurement(await measure(record, request));
    } else {
      measurement = normalizeMeasurement(computeStatistic(samples, statistic));
    }
  } catch (error) {
    if (isBoardError(error)) throw error;
    const mapped = toBoardError(error);
    return settle('INFRA_ERROR', null, `infra_error:${mapped.code}`, {
      // Code and class only: a message or a detail could carry a secret into
      // an evidence file. Variable names and locations are enough to debug.
      error_code: mapped.code,
      error_name: mapped.name,
      retryable: false,
    });
  }

  return settle('MEASURED', measurement, null, { measurement_source: typeof measure === 'function' ? 'injected' : 'metric_samples' });
}

/**
 * The precondition for treating an outcome as a decision input at all.
 *
 * This is NOT a verdict and NOT a replacement for one: `resolveTrialVerdict`
 * and `resolveCampaignVerdict` in comparator.mjs remain the only places a
 * verdict is named. What this guard does is refuse the specific mistake A2 is
 * about — an EVALUATOR_UNAVAILABLE or INFRA_ERROR record being read as a
 * result — and it fails by THROWING, because a boolean is one `if` away from
 * being ignored.
 * @param {object} outcome An outcome record from `runTrial`.
 * @returns {object} The same record, unchanged, when it may be considered.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} naming the first
 *   unmet condition: a non-MEASURED outcome, a missing or non-finite
 *   measurement, an unavailable evaluator, a status that is not `RESOLVED`, a
 *   status not bound to the track's frozen `TRIAL_STATUSES`
 *   (`vocabulary_bound: false`), or a provenance label that does not match the
 *   trial kind (via `assertOutcomeProvenance`).
 */
export function assertUsableAsResult(outcome) {
  assertOutcomeProvenance(outcome);
  if (outcome.outcome !== 'MEASURED') {
    throw new MalformedResult(
      'OUTCOME_NOT_A_RESULT',
      `outcome '${boundedDetail(outcome.outcome)}' (reason ${boundedDetail(outcome.reason ?? 'none')}) `
      + 'is not a measurement and may never be read as a result',
    );
  }
  if (!isPlainObject(outcome.measurement)
    || typeof outcome.measurement.value !== 'number'
    || !Number.isFinite(outcome.measurement.value)
    || !Number.isInteger(outcome.measurement.n)
    || outcome.measurement.n < 1) {
    throw new MalformedResult('MEASUREMENT_ABSENT', 'a MEASURED outcome without a finite value and n >= 1 is malformed');
  }
  if (!isPlainObject(outcome.evaluator) || outcome.evaluator.state !== 'AVAILABLE') {
    throw new MalformedResult(
      'EVALUATOR_UNAVAILABLE',
      'a result produced without an available evaluator is not a result',
    );
  }
  if (outcome.trial_status !== 'RESOLVED') {
    throw new MalformedResult(
      'TRIAL_STATUS_NOT_RESOLVED',
      `trial_status '${boundedDetail(outcome.trial_status)}' is not RESOLVED`,
    );
  }
  if (outcome.vocabulary_bound !== true) {
    throw new MalformedResult(
      'TRIAL_VOCABULARY_UNBOUND',
      "the track's TRIAL_STATUSES vocabulary is not published yet, so this status is unproven here",
    );
  }
  return outcome;
}

// ---------------------------------------------------------------------------
// Self-cleanup (the purgeProbeFixtures precedent, bounded to this module)
// ---------------------------------------------------------------------------

/**
 * The absolute fixture namespace for one run label. The label is REQUIRED and
 * shape-checked: a default label would let two runs collide on one namespace,
 * which is the failure A3 turns into a run compared with itself.
 * @param {{root: string, label: string}} args
 * @param {string} args.root The caller-owned output root (e.g.
 *   `results/s2-008/run-a`). Never the filesystem root.
 * @param {string} args.label The run label (`a`, `b`, `repeat`), matching
 *   `EXECUTOR_FIXTURE_LABEL_PATTERN`.
 * @returns {string} `<root>/executor-fixtures/<label>`, resolved.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'FIXTURE_ROOT_MISSING', 'FIXTURE_ROOT_TOO_BROAD' (a filesystem root), or
 *   'FIXTURE_LABEL_INVALID' — the path-traversal guard, since a label
 *   containing `..` or a separator could name a directory outside the root.
 */
export function executorFixtureDir({ root, label } = {}) {
  if (typeof root !== 'string' || root.length === 0) {
    throw new MalformedResult('FIXTURE_ROOT_MISSING', 'a caller-supplied output root is required');
  }
  if (typeof label !== 'string' || !LABEL_PATTERN.test(label)) {
    throw new MalformedResult(
      'FIXTURE_LABEL_INVALID',
      `a run label must match ${EXECUTOR_FIXTURE_LABEL_PATTERN}; a label that could escape the root is refused`,
    );
  }
  const resolvedRoot = path.resolve(root);
  if (resolvedRoot === path.parse(resolvedRoot).root) {
    throw new MalformedResult('FIXTURE_ROOT_TOO_BROAD', 'a filesystem root is never a fixture root');
  }
  const dir = path.join(resolvedRoot, EXECUTOR_FIXTURE_DIRNAME, label);
  // Defence in depth: the dirname and the label are both constrained above, so
  // this is unreachable by construction. It stays because an unreachable guard
  // that silently stopped being unreachable would be a real deletion bug.
  if (!path.resolve(dir).startsWith(`${resolvedRoot}${path.sep}`)) {
    throw new MalformedResult('FIXTURE_DIR_ESCAPES_ROOT', 'the fixture namespace must stay under the root');
  }
  return dir;
}

/**
 * Remove THIS MODULE'S OWN fixture namespace and nothing else, so a repeat run
 * on a permanent base starts clean instead of failing on its own leftovers.
 *
 * Mirrors `purgeProbeFixtures` (src/lib/agentboard/probes.mjs:172) in role and
 * in its two independent guards:
 *   1. the removal is bounded to `<root>/executor-fixtures/<label>/`, so
 *      purging label `a` cannot delete label `b` — which matters, because the
 *      A3 two-run track runs both labels on one machine;
 *   2. a symlink is UNLINKED, never followed and never recursed into: a link
 *      INSIDE the namespace is removed as a link by `rmSync`, and a link at
 *      either level ABOVE it (`executor-fixtures/` or the label directory) is
 *      refused outright. Both are checked, because `lstat` does not follow the
 *      final component but does traverse the parents: guarding only the label
//      directory would let a symlinked `executor-fixtures/` be walked into and
//      purged from, which is exactly the "followed" case the guard exists for.
//      The caller's own `root` IS followed, by design — it is the root the
//      caller named, like `results/` itself.
 * The purge never CREATES the namespace: a purge that creates state is not a
 * purge. Idempotency is checkable rather than self-certified — the report names
 * every removed entry, so a second call on the same state returns
 * `present: false, removed: []`.
 * @param {{root: string, label: string, dryRun?: boolean}} args
 * @param {string} args.root The caller-owned output root.
 * @param {string} args.label The run label whose namespace is purged.
 * @param {boolean} [args.dryRun] Report what would be removed, remove nothing.
 * @returns {object} A frozen report `{dir, present, purged, dry_run, removed,
 *   removed_count, kept, other_labels}`. `kept` and `other_labels` list what
 *   was deliberately left alone, so the report is checkable against the tree
 *   instead of trusted.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} from
 *   `executorFixtureDir`, plus 'FIXTURE_DIR_SYMLINK' when the namespace itself
 *   is a link, 'FIXTURE_DIR_NOT_A_DIRECTORY' when a plain file occupies the
 *   namespace, and 'FIXTURE_DIR_UNREADABLE' when the directory cannot be
 *   listed. A refusal here leaves the tree exactly as it was.
 */
export function purgeExecutorFixtures({ root, label, dryRun = false } = {}) {
  const dir = executorFixtureDir({ root, label });
  const namespace = path.dirname(dir);
  for (const candidate of [namespace, dir]) {
    if (existsSync(candidate) && lstatSync(candidate).isSymbolicLink()) {
      throw new MalformedResult(
        'FIXTURE_DIR_SYMLINK',
        `${candidate} is a link; it is refused, not followed`,
      );
    }
  }
  if (!existsSync(dir)) {
    return deepFreeze({
      dir,
      present: false,
      purged: false,
      dry_run: dryRun === true,
      removed: Object.freeze([]),
      removed_count: 0,
      kept: Object.freeze([]),
      other_labels: Object.freeze(listFixtureLabels(root)),
    });
  }
  const stat = lstatSync(dir);
  if (!stat.isDirectory()) {
    throw new MalformedResult(
      'FIXTURE_DIR_NOT_A_DIRECTORY',
      'a plain file occupies the namespace; the purge refuses to unlink an unknown file',
    );
  }
  const removed = listDir(dir);
  const parent = path.dirname(dir);
  if (!dryRun) rmSync(dir, { recursive: true, force: true });
  return deepFreeze({
    dir,
    present: true,
    purged: !dryRun,
    dry_run: dryRun === true,
    removed: Object.freeze(removed),
    removed_count: removed.length,
    kept: Object.freeze(listDir(parent).filter((name) => name !== label)),
    other_labels: Object.freeze(listFixtureLabels(root)),
  });
}

// An OS-level listing failure is a typed refusal, never a silent empty list: a
// purge that reported "nothing there" when the directory was unreadable would
// be a lie the repeat run would then trust.
function listDir(dir) {
  try {
    return readdirSync(dir).sort();
  } catch (error) {
    throw new MalformedResult(
      'FIXTURE_DIR_UNREADABLE',
      `${error?.code ?? 'UNKNOWN'}: ${boundedDetail(error?.message ?? error)}`,
    );
  }
}

function listFixtureLabels(root) {
  const parent = path.join(path.resolve(root), EXECUTOR_FIXTURE_DIRNAME);
  if (!existsSync(parent)) return [];
  return listDir(parent).filter((name) => LABEL_PATTERN.test(name));
}
