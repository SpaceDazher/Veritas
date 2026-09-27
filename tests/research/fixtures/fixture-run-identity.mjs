// Deterministic run identities for the two process-separated runs (A3).
//
// WHAT THIS IS: the two run identities the A3 comparison needs, minted
// deterministically from the run LABEL, plus the closed list of fields a
// repeat run is allowed to differ in (A5).
//
// WHAT THIS IS NOT: these are not real run identities and nothing here may be
// read as one. A real record's `raw_run_id` comes from
// `scripts/s2-008-run.mjs` (W4) and its `commit_sha` / `tree_sha` from
// `freezeProvenance`; a fixture that minted a plausible-looking SHA-1 would be
// a way to fake provenance, so the SHA-1-shaped values below are obviously
// fake and flagged as such in the record (`provenance_is_placeholder: true`).
//
// WHY THE NONCE IS A FIXTURE VALUE AND NOT A SECRET
// The property under test is that the two runs carry DIFFERENT ids and
// DIFFERENT nonces — the anti-pattern being a run that reuses one identity
// twice, which would make A3 a run compared with itself. Guessing a nonce is
// not in scope, so this value has no security meaning and must never be
// copied into a place that expects one.
//
// Serves: A3 (two process-separated runs, distinct ids and nonces) and A5
// (a repeat run differs only in the named fields, each difference named).
import { fixtureDigest } from './fixture-digest.mjs';

/** The two run labels A3 requires. Closed: a third label is a new acceptance case. @type {ReadonlyArray<string>} */
export const RUN_LABELS = Object.freeze(['a', 'b']);

/**
 * The ONLY fields a repeat run may differ in (A5). Anything else that moves
 * between two runs on the same base is drift, and drift fails the track.
 * @type {ReadonlyArray<string>}
 */
export const ALLOWED_PROCESS_DIFFERENCES = Object.freeze([
  'raw_run_id',
  'nonce',
  'executor_id',
  'pid',
  'started_at',
  'finished_at',
]);

/** The prefix of the derived run id the aggregator writes into evidence. @type {string} */
export const DERIVED_RUN_ID_PREFIX = 's2-008-verify-';

// Per-label identity material. The nonce differs in its LOWEST hex digit, so
// "the two runs differ in their nonce" is readable in the source rather than
// provable only by digesting two strings that look alike.
const IDENTITY_MATERIAL = Object.freeze({
  a: Object.freeze({ raw_run_id: 'raw-s2-008-a', nonce: 'a1c0ffee00000001', executor_id: 'exe-s2-008-a' }),
  b: Object.freeze({ raw_run_id: 'raw-s2-008-b', nonce: 'a1c0ffee00000002', executor_id: 'exe-s2-008-b' }),
});

/**
 * The identity of one fixture run, derived from its label alone.
 * @param {string} label A member of `RUN_LABELS`.
 * @returns {{raw_run_id: string, nonce: string, executor_id: string, label: string}}
 * @throws {Error} `FIXTURE_LABEL_UNKNOWN` for any label outside `RUN_LABELS` —
 *   a typo must not silently mint a third identity that nothing compares.
 */
export function fixtureRunIdentity(label) {
  const material = IDENTITY_MATERIAL[label];
  if (!material) throw new Error(`FIXTURE_LABEL_UNKNOWN: ${String(label)}`);
  return Object.freeze({ ...material, label });
}

/** Both fixture identities, keyed by label. @type {Readonly<Record<string, object>>} */
export const RUN_IDENTITIES = Object.freeze(
  Object.fromEntries(RUN_LABELS.map((label) => [label, fixtureRunIdentity(label)])),
);

/**
 * Prove the identities really are process-separated: distinct raw run ids,
 * distinct nonces, distinct executors. Two in-process handles or a shared
 * nonce would collapse A3 into a self-comparison, so this is checked rather
 * than assumed.
 * @param {ReadonlyArray<string>} [labels] Defaults to `RUN_LABELS`.
 * @returns {true} when every field differs pairwise.
 * @throws {Error} `FIXTURE_IDENTITIES_NOT_SEPARATED`, naming the colliding field.
 */
export function assertRunIdentitiesSeparated(labels = RUN_LABELS) {
  for (const field of ['raw_run_id', 'nonce', 'executor_id']) {
    const seen = new Set(labels.map((label) => fixtureRunIdentity(label)[field]));
    if (seen.size !== labels.length) {
      throw new Error(`FIXTURE_IDENTITIES_NOT_SEPARATED: ${field} is shared by ${String(seen.size)} of ${String(labels.length)} runs`);
    }
  }
  return true;
}

/**
 * A deterministic id scoped by label AND step, which is what lets a repeat run
 * fail on the property instead of on its own leftovers: nothing this module
 * mints is global, so a second run cannot collide with the first one's ids.
 * @param {string} label A member of `RUN_LABELS`.
 * @param {string} step The step within the run, e.g. 'probe' or 'replay'.
 * @param {string} name What the id is for, e.g. 'seed-substitution'.
 * @returns {string} `<prefix>-<label>-<step>-<name>`.
 * @throws {Error} `FIXTURE_ID_SEGMENT_INVALID` when a segment is not
 *   `[a-z0-9][a-z0-9-]*`, which is also what keeps `..` and a path separator
 *   out of anything derived from a label.
 */
export function fixtureId(label, step, name) {
  const segment = /^[a-z0-9][a-z0-9-]{0,31}$/;
  for (const [field, value] of [['label', label], ['step', step], ['name', name]]) {
    if (typeof value !== 'string' || !segment.test(value)) {
      throw new Error(`FIXTURE_ID_SEGMENT_INVALID: ${field} must match ${segment.source}, got ${String(value)}`);
    }
  }
  return `fx-${label}-${step}-${name}`;
}

/**
 * The digest of one fixture run's identity block. Two runs that reused an
 * identity would produce the SAME digest here even if their records differed
 * elsewhere, which is why the identity block is digested separately from the
 * record.
 * @param {string} label A member of `RUN_LABELS`.
 * @returns {string} `sha256:<64 hex>` over the canonical identity, via the
 *   frozen convention in `fixture-digest.mjs`.
 */
export function runIdentityDigest(label) {
  return fixtureDigest(fixtureRunIdentity(label));
}

assertRunIdentitiesSeparated();
