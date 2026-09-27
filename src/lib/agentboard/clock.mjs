// The single injected-clock reader of the S2-007 boundary (issue #45).
//
// WHY IT MOVED OUT OF scheduler.mjs
// policy.mjs had to evaluate the authorisation window of an unisolated
// host-execution permit, and scheduler.mjs already imports policy.mjs, so the
// helper could not be imported back without a cycle. A second copy of the same
// instant parser in two files is exactly the "second, independently editable
// form" the boundary contract forbids, so the helper lives here and both
// modules read it from here. scheduler.mjs re-exports it, so every existing
// importer keeps working and its public surface does not change.
//
// THE RULE THIS ENFORCES
// No board decision may read the process clock. `Date.now()` and
// `new Date()` without an argument would make a replay, a lease expiry, a
// budget day key and an authorisation window depend on when the guard happened
// to run. The clock is therefore REQUIRED and injected; a missing, malformed or
// unparseable clock is a typed refusal, not a fallback to the wall clock.
import { BlockedPolicy } from './errors.mjs';

export const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export const CLOCK_VERSION = 's2-007-clock-v1';

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Normalise an injected clock into a strict ISO-8601 instant with
 * milliseconds. Accepts an ISO string, a Date, a function returning either, or
 * an object with a `now()` method (the board's clock shape). Everything else is
 * refused, and nothing is ever read from the process clock.
 */
export function toInjectedInstant(value, label = 'now') {
  let candidate = value;
  if (isPlainObject(candidate) && typeof candidate.now === 'function') candidate = candidate.now();
  if (typeof candidate === 'function') candidate = candidate();
  if (candidate instanceof Date) {
    if (Number.isNaN(candidate.getTime())) throw new BlockedPolicy(`INJECTED_CLOCK_INVALID:${label}`);
    return candidate.toISOString();
  }
  if (typeof candidate === 'string') {
    if (ISO_INSTANT.test(candidate)) return candidate;
    const parsed = new Date(candidate);
    if (Number.isNaN(parsed.getTime())) throw new BlockedPolicy(`INJECTED_CLOCK_INVALID:${label}`);
    return parsed.toISOString();
  }
  throw new BlockedPolicy(`INJECTED_CLOCK_MISSING:${label}`, 'the board never reads the process clock');
}

/** UTC calendar day of an injected instant — the budget `day_key`. */
export function dayKeyOf(instant) {
  return String(instant).slice(0, 10);
}
