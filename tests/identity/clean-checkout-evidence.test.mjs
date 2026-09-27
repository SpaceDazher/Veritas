// S2-002 — clean-checkout failure evidence.
//
// Lives in tests/identity/ on purpose: `identity-tests` is the step that went
// red without a recoverable subtest in SpaceDazher/Veritas#16, so the
// extractor that fixes that has to be gated by the very runner that lost the
// information. The full recorded incident output is replayed here, so the
// regression is asserted against the real stream rather than a synthetic one.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { failureEvidence, failingTestNames, firstFailureMessage } from '../../scripts/tap-evidence.mjs';

const TAIL_CHARS = 1200;

// A condensed but structurally faithful TAP stream in the shape node:test
// emits: nested suites, `not ok` for the subtest and for the parent suite, and
// the counters at the very end — which is all the truncated tail ever kept.
const IDENTITY_INCIDENT_STREAM = `
TAP version 13
# Subtest: S2-002 sandbox: process tree and cancellation
    # Subtest: cancellation kills the whole tree: no survivors
    not ok 1 - cancellation kills the whole tree: no survivors
      ---
      duration_ms: 61_402.1
      type: 'test'
      error: 'no process may survive cancellation: {"terminated":true,"survivors":1,"processQueries":{"queries":14,"failedQueries":0,"settleSteps":6,"settleTimedOut":false,"settleUnanswered":0}}'
      code: 'ERR_ASSERTION'
      ...
    1..1
not ok 1 - S2-002 sandbox: process tree and cancellation
  ---
  failureType: 'subtestsFailed'
  error: '1 subtest failed'
  ...
# Subtest: probe G (child process surviving cancellation/timeout) is detected, never escaped
    ok 7 - probe G (child process surviving cancellation/timeout) is detected, never escaped
      ---
      ...
1..34
# tests 159
# suites 34
# pass 158
# fail 1
# cancelled 0
# skipped 0
# todo 0
# duration_ms 28642.0248
`;

describe('S2-002 clean-checkout failure evidence', () => {
  test('the failing subtest is named even though the tail cannot show it', () => {
    const names = failingTestNames(IDENTITY_INCIDENT_STREAM);
    assert.ok(
      names.includes('cancellation kills the whole tree: no survivors'),
      `the subtest identity must survive truncation: ${JSON.stringify(names)}`,
    );
    // The suite that aggregates it is the last `not ok` in the stream, and is
    // exactly what the truncated tail ended on.
    assert.equal(names[names.length - 1], 'S2-002 sandbox: process tree and cancellation');
    // Passing probes are not failures.
    assert.ok(!names.some((name) => name.startsWith('probe G')));
  });

  test('the assertion message is recovered, including the transport counters', () => {
    const message = firstFailureMessage(IDENTITY_INCIDENT_STREAM);
    assert.ok(message, 'an assertion message must be recovered');
    assert.ok(message.includes('no process may survive cancellation'));
    assert.ok(message.includes('"settleSteps":6'),
      'the message must carry the counters that distinguish a survivor from an unverified verdict');
  });

  test('the record keeps the tail and adds the names', () => {
    const evidence = failureEvidence(IDENTITY_INCIDENT_STREAM);
    assert.equal(evidence.failingTests.length, 2);
    assert.ok(evidence.reason.length <= TAIL_CHARS);
    assert.ok(evidence.reason.includes('# fail 1'), 'the counters stay in the tail');
  });

  test('a green step yields no failing names', () => {
    // The tail is still returned, because a step can exit non-zero without
    // any `not ok` line at all and the tail is then the only evidence.
    const green = '1..34\n# tests 159\n# pass 159\n# fail 0\n# duration_ms 1901.3\n';
    const evidence = failureEvidence(green);
    assert.deepEqual(evidence.failingTests, []);
    assert.equal(evidence.failureMessage, undefined);
    assert.ok(evidence.reason.includes('# pass 159'));
  });

  test('a non-zero exit with no test failure still keeps its output', () => {
    const crashed = 'Error: something failed\n    at Object.<anonymous>\n';
    const evidence = failureEvidence(crashed);
    assert.deepEqual(evidence.failingTests, []);
    assert.ok(evidence.reason.includes('something failed'));
  });

  test('a suite-only failure is still attributed', () => {
    const suiteOnly = "not ok 34 - S2-002 adversarial corpus (production-facing path)\n  ---\n  error: '1 subtest failed'\n  ...\n";
    assert.deepEqual(failingTestNames(suiteOnly), ['S2-002 adversarial corpus (production-facing path)']);
    assert.equal(firstFailureMessage(suiteOnly), '1 subtest failed');
  });

  test('duplicate names are reported once', () => {
    const duplicated = 'not ok 1 - same test\nnot ok 2 - same test\nnot ok 3 - other test\n';
    assert.deepEqual(failingTestNames(duplicated), ['same test', 'other test']);
  });

  test('a committed record from a post-fix run carries the names on every step', () => {
    // Invariant on the record format, not on a particular run: once the
    // runner writes failingTests, no step may omit it, or the field is
    // unreliable exactly when it is needed. A record written before this
    // change has the field nowhere and is skipped until the next run.
    const recorded = path.join(process.cwd(), 'evidence', 'clean-checkout.json');
    if (!fs.existsSync(recorded)) return;
    const report = JSON.parse(fs.readFileSync(recorded, 'utf8'));
    if (!report.commands.some((command) => Array.isArray(command.failingTests))) return;
    for (const command of report.commands) {
      assert.ok(Array.isArray(command.failingTests),
        `${command.id} must carry the failing test names the tail drops`);
    }
  });
});
