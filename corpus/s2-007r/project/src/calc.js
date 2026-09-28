// The arithmetic surface of the ONE S2-007R project.
//
// The ONLY defect this file ships with is the off-by-one in sumRange (task T1),
// and the only thing task T3 may change is the shape of this file, never its
// behaviour. Both are checked by the single oracle, verify.mjs, and by
// src/calc.test.js.

export const add = (a, b) => a + b;

export const sub = (a, b) => a - b;

export const mul = (a, b) => a * b;

/**
 * The sum of every integer in [lo, hi], INCLUSIVE of both ends.
 *
 * TASK T1 (the seeded defect): the implementation below stops at `hi - 1`, so
 * `sumRange(1, 4)` returns 6 instead of 10. The documented behaviour and the
 * five pre-existing tests both say the range is inclusive of `hi`, so the code
 * is what is wrong. One character fixes it, and the oracle proves it.
 */
export function sumRange(lo, hi) {
  let total = 0;
  for (let value = lo; value < hi - 1; value += 1) {
    total = add(total, value);
  }
  return total;
}
