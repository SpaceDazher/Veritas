// The parsing surface of the ONE S2-007R project.
//
// TASK T2: both functions are DOCUMENTED HERE AND NOT DEFINED. The task is to
// implement them to the contract below, and src/parse.test.js plus the oracle
// are the only things that decide whether the implementation is right. The
// contract is the whole specification; there is no hidden expectation.

/**
 * Split a comma-separated `key=value` list into a plain object.
 *
 * Contract:
 *   * segments are split on `,`; surrounding whitespace is trimmed off a key
 *     and off a value;
 *   * a segment with no `=` is IGNORED (and counted in `malformed`), not
 *     silently turned into a key with an empty value;
 *   * an empty input is an empty object;
 *   * a later duplicate key wins;
 *   * the result has a null prototype, so a segment named `__proto__` is an
 *     ordinary own property and cannot reach Object.prototype.
 */
export function parsePairs(text) {
  throw new Error('TASK_T2_NOT_IMPLEMENTED: parsePairs is documented in this file and is not defined');
}

/**
 * Render a `{key: value}` object back into the same `key=value,key=value` form.
 *
 * Contract:
 *   * keys are emitted in sorted order, so the rendering is deterministic;
 *   * a value containing `,` or `=` is percent-encoded (`%2C`, `%3D`) so the
 *     round trip `parsePairs(renderPairs(o))` deep-equals `o`;
 *   * an empty object renders as the empty string.
 */
export function renderPairs(object) {
  throw new Error('TASK_T2_NOT_IMPLEMENTED: renderPairs is documented in this file and is not defined');
}
