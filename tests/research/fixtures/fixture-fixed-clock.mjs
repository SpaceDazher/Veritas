// The ONE clock every fixture in tests/research/fixtures/ reads.
//
// WHAT THIS IS: two literals — an injected instant and its nanosecond
// reading — plus a self-check that the two describe the same moment. Every
// fixture that needs "now" (a preregistration's recording time, a budget
// reservation's `expires_at`, a reconciliation row) imports it from here, so
// the whole fixture set describes ONE moment and a test can assert an instant
// by NAME instead of repeating a string literal in two places, where one copy
// could drift and the fixture would keep passing.
//
// WHAT THIS IS NOT: it is not a clock. It never advances, it never calls
// `Date.now()`, `Date.now`-equivalent (`performance.now`) or an argument-less
// `new Date()`, and nothing on the decision path may read it. The ticket says
// wall-clock latency is MEASURED but the decision follows the frozen noise/CI
// rule; a verdict that depended on when it was produced would not be
// reproducible on the next host, so the comparator never sees a clock at all
// (issue `SpaceDazher/Veritas#8`, A2 + the latency rule; see the header of
// `src/lib/research/comparator.mjs`).
//
// The single `Date.parse` below is a PARSE OF A LITERAL, not a reading of the
// process clock: it is what proves the two literals agree, and it returns the
// same value on every host forever.
//
// Serves: P4 (opaque budget) — an expired reservation is decided against an
// INJECTED reading, never against the wall clock, so "expired" is a fact about
// the fixture rather than a race.
import { assertCanonicalSafety } from '../../../src/lib/verifier/canonical-json.mjs';

// 2026-01-01T00:00:00.000Z. Written as a literal in BOTH forms on purpose: a
// fixture that derived one from the other would be testing its own arithmetic
// instead of agreeing with the test.
export const FIXED_INSTANT_ISO = '2026-01-01T00:00:00.000Z';
export const FIXED_CLOCK_NOW_NS = 1767225600000000000;

/**
 * The injected fixed clock. `source` is a typed part of the value: a record
 * that forgot to say where its reading came from is exactly the record whose
 * verdict a reader cannot reproduce.
 * @type {{nowNs: number, iso: string, source: string}}
 */
export const FIXED_CLOCK = Object.freeze({
  nowNs: FIXED_CLOCK_NOW_NS,
  iso: FIXED_INSTANT_ISO,
  source: 'INJECTED_FIXED',
});

/**
 * A deterministic later reading, derived by ADDITION from the fixed instant.
 * Deterministic arithmetic on a literal is not a clock: the same call returns
 * the same reading in every process on every host.
 * @param {number} offsetNs Nanoseconds to add. Must be a non-negative integer.
 * @returns {{nowNs: number, iso: string, source: string}} The same shape as
 *   `FIXED_CLOCK`, so a caller can pass either to the same parameter.
 * @throws {Error} `FIXTURE_CLOCK_INVALID` on a non-integer or negative offset.
 */
export function fixedClockAfterNs(offsetNs) {
  if (!Number.isInteger(offsetNs) || offsetNs < 0) {
    throw new Error(`FIXTURE_CLOCK_INVALID: offsetNs must be a non-negative integer, got ${String(offsetNs)}`);
  }
  const nowNs = FIXED_CLOCK_NOW_NS + offsetNs;
  return Object.freeze({ nowNs, iso: new Date(nowNs / 1e6).toISOString(), source: 'INJECTED_FIXED' });
}

/**
 * Prove the two literals describe the same instant. Called once at import by
 * this module, so an edit that breaks the pair fails at load rather than
 * producing a fixture that quietly measures a different moment.
 * @returns {true} when `Date.parse(FIXED_INSTANT_ISO) * 1e6 === FIXED_CLOCK_NOW_NS`.
 * @throws {Error} `FIXTURE_CLOCK_INCONSISTENT`, naming both readings.
 */
export function assertFixedClockConsistent() {
  const parsed = Date.parse(FIXED_INSTANT_ISO);
  if (!Number.isFinite(parsed) || parsed * 1e6 !== FIXED_CLOCK_NOW_NS) {
    throw new Error(
      `FIXTURE_CLOCK_INCONSISTENT: ${FIXED_INSTANT_ISO} parses to ${String(parsed * 1e6)} ns, ` +
      `but FIXED_CLOCK_NOW_NS is ${String(FIXED_CLOCK_NOW_NS)} ns`,
    );
  }
  return true;
}

assertFixedClockConsistent();
// The literals above are the whole module state; canonical-safety checking them
// at import is the cheap guard against a later edit smuggling a non-canonical
// value (undefined, NaN, a Date instance) into a digest computed from them.
assertCanonicalSafety(FIXED_CLOCK);
