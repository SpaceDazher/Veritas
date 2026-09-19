// S2-006 crash/restart replay gate (review P2-6, spec §11/§12 probe S):
// the coordinator of scripts/s2-006-db-replay.mjs must fail closed unless
// BOTH schemas show a first process that died after REQUEST_ACCEPTED
// (exit 70, no finalize) and a recovery process that reconciled over the
// fencing token with EXACTLY ONE settlement and zero duplicate ledger/outbox
// writes. Pure gate logic — no database required.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { crashPhaseIssues } from '../../scripts/s2-006-db-replay.mjs';

const greenRun = (suffix) => ({
  schemaVersion: 1,
  ticket: 'S2-006',
  status: 'COMPLETED',
  runId: `s2-006-db-crash-${suffix}`,
  executorId: `exec-db-s2006-crash-${suffix}`,
  recoveryPid: 4242 + (suffix === 'a' ? 1 : 2),
  crashFirstPid: 4342 + (suffix === 'a' ? 1 : 2),
  crashFirstExecutor: `exec-db-s2006-dies-${suffix}`,
  crashFirstExitCode: 70,
  diedAsDesigned: true,
  fencingToken: 2,
  checks: {
    crashedCallObservedInAcceptedState: true,
    staleFencingRefused: true,
    exactlyOneSettlement: true,
    duplicateFinalizeReplayed: true,
    finalizedCallNotDraggedBack: true,
  },
  counts: {
    outboxTotal: 9,
    ledgerTotal: 3,
    externalCallRows: 2,
    crashCallEvents: 3,
    crashCallFinalizedEvents: 1,
    crashCallSettlements: 1,
    duplicateOutboxIds: 0,
  },
  countsExpected: {
    outboxTotal: 9,
    ledgerTotal: 3,
    externalCallRows: 2,
    crashCallEvents: 3,
    crashCallFinalizedEvents: 1,
    crashCallSettlements: 1,
    duplicateOutboxIds: 0,
  },
  digest: 'd'.repeat(64),
});

describe('S2-006 crash/restart replay gate (review P2-6)', () => {
  test('two green crash/restart runs produce zero issues', () => {
    assert.deepEqual(crashPhaseIssues(greenRun('a'), greenRun('b')), []);
  });

  test('a first process that did not die as designed (exit != 70) fails the gate', () => {
    const a = { ...greenRun('a'), diedAsDesigned: false, crashFirstExitCode: 0 };
    const issues = crashPhaseIssues(a, greenRun('b'));
    assert.ok(issues.includes('crash-a:first-process-exit-0'), issues.join(','));
  });

  test('a recovery that settled twice (duplicate settlement) fails the gate', () => {
    const a = greenRun('a');
    a.checks = { ...a.checks, exactlyOneSettlement: false };
    a.counts = { ...a.counts, crashCallFinalizedEvents: 2 };
    const issues = crashPhaseIssues(a, greenRun('b'));
    assert.ok(issues.includes('crash-a:check-exactlyOneSettlement'), issues.join(','));
    assert.ok(issues.includes('crash-a:count-crashCallFinalizedEvents'), issues.join(','));
  });

  test('duplicate outbox events or an unrefused stale fencing token fail the gate', () => {
    const a = greenRun('a');
    a.counts = { ...a.counts, duplicateOutboxIds: 1 };
    const b = greenRun('b');
    b.checks = { ...b.checks, staleFencingRefused: false };
    const issues = crashPhaseIssues(a, b);
    assert.ok(issues.includes('crash-a:count-duplicateOutboxIds'), issues.join(','));
    assert.ok(issues.includes('crash-b:check-staleFencingRefused'), issues.join(','));
  });

  test('divergent digests or shared identities fail the gate (process separation)', () => {
    const b = { ...greenRun('b'), digest: 'e'.repeat(64), recoveryPid: greenRun('a').recoveryPid, executorId: greenRun('a').executorId };
    const issues = crashPhaseIssues(greenRun('a'), b);
    assert.ok(issues.includes('crash:digest-mismatch'), issues.join(','));
    assert.ok(issues.includes('crash:recovery-pid-identical'), issues.join(','));
    assert.ok(issues.includes('crash:executor-identical'), issues.join(','));
  });

  test('an errored recovery report fails the gate', () => {
    const a = { ...greenRun('a'), status: 'ERROR' };
    const issues = crashPhaseIssues(a, greenRun('b'));
    assert.ok(issues.includes('crash-a:not-completed'), issues.join(','));
  });
});
