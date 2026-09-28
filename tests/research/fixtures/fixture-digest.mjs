// The ONE digest convention the fixture set uses.
//
// WHAT THIS IS: a thin wrapper over `canonicalDigest` from
// `src/lib/verifier/canonical-json.mjs` — the frozen S2-006 canonicalisation
// and sha256, reused verbatim — that returns the WIRE form `sha256:<64 hex>`
// used by the Agent Board's `DIGEST_PATTERN`
// (src/lib/agentboard/constants.mjs:151).
//
// WHAT THIS IS NOT: it is not a second digest function. A fixture that
// hand-rolled JSON.stringify + sha256 would be a second, weaker convention:
// it would accept values `assertCanonicalSafety` rejects, and two digests over
// the same document that disagree is indistinguishable from a corrupted
// record. Every digest in tests/research/fixtures/ comes from here.
//
// A fixture digest answers "are these two documents the same document?", never
// "is this document correct?". The table in `expected-values.mjs` decides
// correctness; this file only makes the comparison reproducible.
import { canonicalDigest } from '../../../src/lib/verifier/canonical-json.mjs';

/** The digest prefix the Agent Board wire format uses. @type {string} */
export const DIGEST_PREFIX = 'sha256:';

/**
 * Canonical-JSON sha256 of `value`, in wire form.
 * @param {*} value Any canonical-safety-checkable value: plain objects, arrays,
 *   strings, finite numbers, booleans, null. A `Date`, a `Map`, `undefined`, a
 *   function or a non-finite number THROWS `NON_CANONICAL_VALUE` rather than
 *   being silently serialised — that refusal is the point of reusing the frozen
 *   canonicaliser.
 * @returns {string} `sha256:<64 lowercase hex>`.
 * @throws {TypeError} `NON_CANONICAL_VALUE` with the offending path.
 */
export function fixtureDigest(value) {
  return `${DIGEST_PREFIX}${canonicalDigest(value)}`;
}

/**
 * The bare 64-hex form, for a field typed as a stored CHAR(64) column.
 * @param {*} value The same value `fixtureDigest` accepts.
 * @returns {string} 64 lowercase hex characters, no prefix.
 */
export function fixtureStoredDigest(value) {
  return canonicalDigest(value);
}

/**
 * Assert two canonical values are byte-identical under the frozen convention.
 * @param {*} left A canonical-safety-checkable value.
 * @param {*} right A canonical-safety-checkable value.
 * @param {string} what What is being compared, named in the failure.
 * @returns {string} The shared wire digest.
 * @throws {Error} `FIXTURE_NOT_BYTE_IDENTICAL` naming `what` and both digests.
 */
export function assertFixtureByteIdentical(left, right, what) {
  const a = fixtureDigest(left);
  const b = fixtureDigest(right);
  if (a !== b) throw new Error(`FIXTURE_NOT_BYTE_IDENTICAL: ${what}: ${a} !== ${b}`);
  return a;
}
