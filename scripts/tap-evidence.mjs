// S2-002 — failure evidence extracted from a test runner's TAP stream.
//
// verify-clean-checkout.mjs stores only the last 1200 characters of a failing
// step's output. That is enough for the summary counters ("# pass 158 / #
// fail 1") and not enough for the failing subtest itself, which is why
// SpaceDazher/Veritas#16 could report "identity 158/159 twice" without being
// able to say which of the 159. The names are cheap to keep and small to
// store, so they are extracted from the full stream while it is in hand.

const NOT_OK = /^\s*not ok \d+ - (.+?)\s*$/;
// node:test prints the failing assertion block after a `not ok` line; the
// first indented non-empty line under it is the message, which is where a
// survivor count or an assertion detail shows up.
const ERROR_FIELD = /^\s+error: '(.*)'\s*$/;

/**
 * Returns the unique names of every failing test or suite in a TAP stream, in
 * the order they appear. Suite-level `not ok` lines are included because a
 * suite failure is what the tail usually ends on, and the subtest names it
 * aggregates are what actually identify the cause.
 */
export function failingTestNames(text) {
  const names = [];
  for (const line of String(text).split(/\r?\n/)) {
    const match = NOT_OK.exec(line);
    if (match && !names.includes(match[1])) names.push(match[1]);
  }
  return names;
}

/**
 * Returns the first error message reported after the first `not ok` line, or
 * null. This is the assertion detail the truncated tail most often loses.
 */
export function firstFailureMessage(text) {
  const lines = String(text).split(/\r?\n/);
  const start = lines.findIndex((line) => NOT_OK.test(line));
  if (start === -1) return null;
  for (const line of lines.slice(start + 1)) {
    if (NOT_OK.test(line)) return null;
    const match = ERROR_FIELD.exec(line);
    if (match) return match[1];
  }
  return null;
}

/**
 * The compact record written for a failing clean-checkout step: which tests
 * failed, the assertion message, and a tail of the output. Small enough to
 * keep in evidence/clean-checkout.json, specific enough to act on.
 *
 * The tail is returned even when no `not ok` line was found, because a step
 * that exits non-zero without one — a crash, a type error, a lint report — is
 * exactly the case where the tail is the only evidence there is.
 */
export function failureEvidence(text, { tailChars = 1200 } = {}) {
  const failingTests = failingTestNames(text);
  const message = firstFailureMessage(text);
  const tail = text.trim().slice(-tailChars);
  return {
    failingTests,
    ...(message ? { failureMessage: message } : {}),
    ...(tail ? { reason: tail } : {}),
  };
}
