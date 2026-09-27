// S2-008 research track — closed vocabulary (issue SpaceDazher/Veritas#8).
//
// Serves acceptance items A1, A2, A4 and A5. This module is the ONLY place the
// research vocabulary is written down. It contains no logic beyond the
// refusal-code map: a word that is not here does not exist on the research
// boundary, which is what makes "a skipped trial is a violation" a
// structural property instead of a convention.
//
// Reuses, never forks:
//   * `ID_PREFIXES` in src/lib/agentboard/constants.mjs:201 is FROZEN. The
//     research ledger uses its OWN `RESEARCH_ID_PREFIXES` table below and adds
//     nothing to it. A prefix that is not in either table is a bug, not an
//     extension.
//   * `RESEARCH_TRANSITIONS` mirrors the shape of the frozen
//     `TRANSITIONS` table at src/lib/agentboard/constants.mjs:40-74: a frozen
//     object of from -> to -> guardName, so the table and the guard set cannot
//     drift apart. The guard functions themselves live in policy.mjs (W4).
//   * `refusalClass(code)` maps a research refusal code onto the closed
//     `BoardError` class set of src/lib/agentboard/errors.mjs, so the error
//     taxonomy stays closed and every refusal is a typed boundary error.
//
// Owner: W1 (contracts & causality). Budget: part of W1's <= 700 lines.
// State: IMPLEMENTED. Every body below is written down; the exported
// signatures are the ones the judged plan §1 froze and none was renamed.
//
// The frozen expected-value table in expected-values.mjs, the fail-closed
// verdict in comparator.mjs and the six probes in probes.mjs are all written
// against the names below.
//
// WHY `refusalClass` MAPS ONTO `errorClassForCode` AND NOT A LOCAL TABLE
// src/lib/agentboard/errors.mjs already owns the code -> class map and keeps
// it closed (`ERROR_CODES` / `errorClassForCode`). A second table here would
// be a second, independently editable answer to "which class owns this code",
// and a code added to one map and not the other would escape as a generic
// Error. So the board's map is read, and an unmapped code is a STARTUP THROW
// (see the module-level assertion below), never a default.
import { ERROR_CODES, errorClassForCode } from '../agentboard/errors.mjs';

/**
 * The version string of the research boundary this module belongs to.
 * Frozen literal; changing it is a re-version of the whole track.
 * @type {string}
 */
export const RESEARCH_VERSION = 's2-008-research-v1';

/**
 * The closed set of research lifecycle states. Frozen, mirroring the style of
 * `BOARD_STATES`. A state not in this list has no edges and is never written.
 * @type {ReadonlyArray<string>}
 */
export const RESEARCH_STATES = Object.freeze([
  'DRAFT', 'PREREGISTERED', 'RESERVED', 'MEASURING', 'DECIDED', 'RECONCILIATION', 'ABANDONED',
]);

/**
 * from -> to -> guardName. Mirrors src/lib/agentboard/constants.mjs:40-74
 * edge for edge in shape: the value is the NAME of the guard function in
 * policy.mjs that authorizes the edge, never a boolean. Reading a guard that
 * does not exist is a startup throw, not a silently refused edge.
 * @type {Readonly<Record<string, Readonly<Record<string, string>>>>}
 */
export const RESEARCH_TRANSITIONS = Object.freeze({
  // The preregistration may only be frozen, never edited: the only edge out of
  // DRAFT is the sealing one.
  DRAFT: Object.freeze({ PREREGISTERED: 'guardSealPreregistration', ABANDONED: 'guardAbandon' }),
  // Once sealed, the decision surface is closed. The only way forward is the
  // budget reservation taken BEFORE the run; `guardReserveBudget` is the guard
  // that refuses a reservation taken after a result.
  PREREGISTERED: Object.freeze({ RESERVED: 'guardReserveBudget', ABANDONED: 'guardAbandon' }),
  // A reservation may be re-taken (a second, separately keyed reservation for
  // the same campaign is legal) but never silently extended.
  RESERVED: Object.freeze({ RESERVED: 'guardReserveBudget', MEASURING: 'guardBeginMeasurement', ABANDONED: 'guardAbandon' }),
  // Measurement is append-only. An interrupted run leaves a RECONCILIATION
  // row and takes the RECONCILIATION edge: never a blind retry, never a zero.
  MEASURING: Object.freeze({
    DECIDED: 'guardDecide',
    RECONCILIATION: 'guardReconcile',
    ABANDONED: 'guardAbandon',
  }),
  // DECIDED is terminal on the happy path; the only way out is an explicit
  // reconciliation, which is what an amendment-then-redecide would need.
  DECIDED: Object.freeze({ RECONCILIATION: 'guardReconcile' }),
  RECONCILIATION: Object.freeze({ MEASURING: 'guardResumeAfterReconciliation', ABANDONED: 'guardAbandon' }),
  ABANDONED: Object.freeze({}),
});

/**
 * The identifier prefixes this track owns. A local, documented extension:
 * `cmp- hyc- amd- xpr- trl- rsv- rsc- aud- rec-`.
 *
 * NOTHING here is added to the frozen `ID_PREFIXES`
 * (src/lib/agentboard/constants.mjs:201). The S2-007 store made the same
 * point for `aud- obx- rec-`: a local prefix table is how you add an
 * identifier without mutating a frozen vocabulary.
 * @type {Readonly<Record<string, string>>}
 */
export const RESEARCH_ID_PREFIXES = Object.freeze({
  campaign: 'cmp-',
  card: 'hyc-',
  amendment: 'amd-',
  preregistration: 'xpr-',
  trial: 'trl-',
  reservation: 'rsv-',
  result: 'rsc-',
  audit: 'aud-',
  reconciliation: 'rec-',
});

/**
 * The closed set of research outcomes. Negative, null, infra and unresolved
 * results are FIRST-CLASS outcomes: none of them may be dropped, and none of
 * them is a zero.
 * POSITIVE | NEGATIVE | NULL | INFRA | UNRESOLVED
 * @type {ReadonlyArray<string>}
 */
export const RESEARCH_OUTCOMES = Object.freeze(['POSITIVE', 'NEGATIVE', 'NULL', 'INFRA', 'UNRESOLVED']);

/**
 * The closed set of trial statuses. Five values, no escape hatch.
 * RESOLVED | SKIPPED | UNRESOLVED | INFRA_ERROR | NOT_MEASURED
 * Only RESOLVED may ever become ALLOW.
 * @type {ReadonlyArray<string>}
 */
export const TRIAL_STATUSES = Object.freeze(['RESOLVED', 'SKIPPED', 'UNRESOLVED', 'INFRA_ERROR', 'NOT_MEASURED']);

/**
 * The closed set of trial verdicts. TWO values, deliberately: there is no
 * 'UNKNOWN', no 'N/A' and no third value a caller could use to escape the
 * fail-closed decision.
 * @type {ReadonlyArray<string>}
 */
export const TRIAL_VERDICTS = Object.freeze(['ALLOW', 'VIOLATION']);

/**
 * The dataset partitions. PRIMARY is the development partition;
 * HOLDOUT is readable only through the access-logged path in dataset.mjs.
 * @type {ReadonlyArray<string>}
 */
export const RESEARCH_PARTITIONS = Object.freeze(['PRIMARY', 'HOLDOUT']);

/**
 * The hard-gate counters of the research track, one per negative probe edge.
 * Every counter must be 0 at the end of a run. Mirrors
 * `HARD_GATE_COUNTERS` in src/lib/agentboard/probes.mjs:99 in role and shape.
 * @type {ReadonlyArray<string>}
 */
export const RESEARCH_HARD_GATE_COUNTERS = Object.freeze([
  'holdoutPeek', 'seedSubstitution', 'hypothesisRewrite', 'budgetOpacity', 'causalUpgrade', 'missingEvaluator',
]);

/**
 * Map a research refusal code onto its closed BoardError class.
 *
 * A code with no class is a STARTUP THROW, not a default: an unmapped code
 * would otherwise escape as a generic Error and be indistinguishable from a
 * transport failure, which is precisely the silent divergence the closed
 * taxonomy exists to prevent.
 *
 * @param {string} code A member of the closed research refusal-code set
 *   (e.g. 'BLOCKED_POLICY', 'BUDGET_EXCEEDED', 'RECONCILIATION_REQUIRED',
 *   'REVISION_CONFLICT', 'MALFORMED_RESULT', 'UNKNOWN_OUTCOME',
 *   'IDEMPOTENCY_CONFLICT', 'TRANSITION_NOT_ALLOWED', 'NEEDS_INPUT').
 * @returns {Function} The `BoardError` subclass from
 *   src/lib/agentboard/errors.mjs that owns this code.
 * @throws {Error} At import/startup time if the code has no class; at call
 *   time if the code is not in the closed set.
 */
export function refusalClass(code) {
  if (typeof code !== 'string' || !ERROR_CODES.includes(code)) {
    throw new Error(`RESEARCH_REFUSAL_CODE_UNMAPPED:${String(code)}`);
  }
  return errorClassForCode(code);
}

// A code the track will ever throw that the board's closed set does not own is a
// defect in one of the two, and it is a STARTUP throw rather than a default: the
// alternative is a refusal that escapes as a generic Error and is
// indistinguishable from a transport failure. The set below is the track's own
// declared vocabulary; every name must resolve.
const RESEARCH_REFUSAL_CODES = Object.freeze([
  'BLOCKED_POLICY', 'BUDGET_EXCEEDED', 'RECONCILIATION_REQUIRED', 'REVISION_CONFLICT',
  'MALFORMED_RESULT', 'UNKNOWN_OUTCOME', 'IDEMPOTENCY_CONFLICT', 'TRANSITION_NOT_ALLOWED', 'NEEDS_INPUT',
]);
for (const code of RESEARCH_REFUSAL_CODES) {
  const resolved = refusalClass(code);
  if (typeof resolved !== 'function' || resolved.name === 'BoardError') {
    throw new Error(`RESEARCH_REFUSAL_CODE_UNMAPPED:${code}`);
  }
}

/**
 * Whether an edge of the research ledger is authorized at all. Pure: it reads
 * the frozen table, never a boolean copy of it, so a guard name that does not
 * exist in `RESEARCH_TRANSITIONS` cannot appear in a journal.
 * @param {string} from A member of RESEARCH_STATES.
 * @param {string} to A member of RESEARCH_STATES.
 * @returns {string|null} the guard name, or null when the edge is absent.
 */
export function researchGuardName(from, to) {
  return Object.prototype.hasOwnProperty.call(RESEARCH_TRANSITIONS, from)
    ? (RESEARCH_TRANSITIONS[from][to] ?? null)
    : null;
}
