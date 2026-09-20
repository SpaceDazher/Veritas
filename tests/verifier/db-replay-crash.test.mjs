// S2-006 crash/restart replay gate (review P2-6, spec §11/§12 probe S;
// fix2-D finding 5): the coordinator of scripts/s2-006-db-replay.mjs must
// fail closed unless BOTH schemas show the FULL production recovery
// sequence — a first process that died after REQUEST_ACCEPTED (exit 70, no
// finalize), a recovery process that OBSERVED the atomic
// RECONCILIATION_REQUIRED escalation (state + reason + exactly one outbox
// event), an AUTHORIZED reconciliation decision (reviewer-issued grant,
// actor-exact) whose resolution settled EXACTLY ONCE, and a refused blind
// retry against the reconciled call. A recovery that finalizes directly
// over ACCEPTED with pre-known digest/settlement never passes this gate.
//
// The offline tests below reproduce the production sequence on the
// InMemoryVerifierStore through the REAL command API (the identical state
// machine the PostgreSQL crash phase drives).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { crashPhaseIssues } from '../../scripts/s2-006-db-replay.mjs';
import { runSecurityProbe } from '../../src/lib/verifier/probes.mjs';

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
    reconciliationObserved: true,
    reconciliationReasonRecorded: true,
    reconciliationEventAtomicSingle: true,
    escalationReplayIdempotent: true,
    blindRetryRefused: true,
    reconciledCallNeverFinalized: true,
    unauthorizedDecisionRefused: true,
    reconciliationDecisionAuthorized: true,
    resolutionSettledExactlyOnce: true,
    duplicateResolutionReplayed: true,
  },
  counts: {
    outboxTotal: 12,
    ledgerTotal: 3,
    externalCallRows: 3,
    crashCallEvents: 3,
    crashCallReconciliationEvents: 1,
    crashCallFinalizedEvents: 0,
    operationFinalizedEvents: 1,
    operationSettledCalls: 1,
    duplicateOutboxIds: 0,
  },
  countsExpected: {
    outboxTotal: 12,
    ledgerTotal: 3,
    externalCallRows: 3,
    crashCallEvents: 3,
    crashCallReconciliationEvents: 1,
    crashCallFinalizedEvents: 0,
    operationFinalizedEvents: 1,
    operationSettledCalls: 1,
    duplicateOutboxIds: 0,
  },
  digest: 'd'.repeat(64),
});

describe('S2-006 crash/restart replay gate (review P2-6, fix2-D finding 5)', () => {
  test('two green crash/restart runs produce zero issues', () => {
    assert.deepEqual(crashPhaseIssues(greenRun('a'), greenRun('b')), []);
  });

  test('a first process that did not die as designed (exit != 70) fails the gate', () => {
    const a = { ...greenRun('a'), diedAsDesigned: false, crashFirstExitCode: 0 };
    const issues = crashPhaseIssues(a, greenRun('b'));
    assert.ok(issues.includes('crash-a:first-process-exit-0'), issues.join(','));
  });

  test('REGRESSION (finding 5): a direct finalize over ACCEPTED without observed reconciliation fails the gate', () => {
    // The pre-fix recovery shape: the second process skipped the
    // RECONCILIATION_REQUIRED escalation and finalized the ACCEPTED call
    // directly with a pre-known digest/settlement. Every such report must
    // fail the gate — the finding's production scenario, not just a
    // happy-path fixture mutation.
    const a = greenRun('a');
    a.checks = {
      ...a.checks,
      reconciliationObserved: false,
      reconciliationReasonRecorded: false,
      reconciliationEventAtomicSingle: false,
      blindRetryRefused: false,
      reconciledCallNeverFinalized: false,
    };
    a.counts = {
      ...a.counts,
      crashCallReconciliationEvents: 0,
      crashCallFinalizedEvents: 1,
    };
    const issues = crashPhaseIssues(a, greenRun('b'));
    for (const expected of [
      'crash-a:check-reconciliationObserved',
      'crash-a:check-reconciliationReasonRecorded',
      'crash-a:check-reconciliationEventAtomicSingle',
      'crash-a:check-blindRetryRefused',
      'crash-a:check-reconciledCallNeverFinalized',
      'crash-a:count-crashCallReconciliationEvents',
      'crash-a:count-crashCallFinalizedEvents',
    ]) {
      assert.ok(issues.includes(expected), `expected ${expected} in: ${issues.join(',')}`);
    }
  });

  test('an unresolved or unauthorized reconciliation resolution fails the gate', () => {
    const a = greenRun('a');
    a.checks = { ...a.checks, reconciliationDecisionAuthorized: false, unauthorizedDecisionRefused: false };
    const b = greenRun('b');
    b.checks = { ...b.checks, resolutionSettledExactlyOnce: false };
    b.counts = { ...b.counts, operationSettledCalls: 2, operationFinalizedEvents: 2 };
    const issues = crashPhaseIssues(a, b);
    assert.ok(issues.includes('crash-a:check-reconciliationDecisionAuthorized'), issues.join(','));
    assert.ok(issues.includes('crash-a:check-unauthorizedDecisionRefused'), issues.join(','));
    assert.ok(issues.includes('crash-b:check-resolutionSettledExactlyOnce'), issues.join(','));
    assert.ok(issues.includes('crash-b:count-operationSettledCalls'), issues.join(','));
    assert.ok(issues.includes('crash-b:count-operationFinalizedEvents'), issues.join(','));
  });

  test('a recovery that settled twice (duplicate settlement) fails the gate', () => {
    const a = greenRun('a');
    a.checks = { ...a.checks, duplicateResolutionReplayed: false };
    a.counts = { ...a.counts, duplicateOutboxIds: 1 };
    const issues = crashPhaseIssues(a, greenRun('b'));
    assert.ok(issues.includes('crash-a:check-duplicateResolutionReplayed'), issues.join(','));
    assert.ok(issues.includes('crash-a:count-duplicateOutboxIds'), issues.join(','));
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

// ---------------------------------------------------------------------------
// Offline reproduction of the EXACT production sequence (finding 5): the
// InMemory store + real command API drive ACCEPTED -> (unknown outcome) ->
// RECONCILIATION_REQUIRED observed -> authorized reconcile -> exactly one
// settlement -> blind retry refused. Probe S stays honestly NOT_RUN_DB
// offline, but its offline half must prove this sequence, never a direct
// finalize over ACCEPTED.
// ---------------------------------------------------------------------------
// run once at module load (describe bodies must stay synchronous)
const probeSOffline = await runSecurityProbe('S');

describe('S2-006 probe S offline state machine = production crash sequence (finding 5)', () => {
  const probeS = probeSOffline;

  test('probe S is honestly NOT_RUN_DB offline (never green by itself)', () => {
    assert.equal(probeS.status, 'not_run');
    assert.equal(probeS.ok, false);
    assert.ok((probeS.notRun ?? []).some((n) => n.startsWith('NOT_RUN_DB')));
  });

  test('offline half observed the atomic RECONCILIATION_REQUIRED escalation', () => {
    const o = probeS.observed;
    assert.equal(o.reservationCommitted, true);
    assert.equal(o.reconciledAfterCrash, true, 'the call must be observed in RECONCILIATION_REQUIRED');
    assert.equal(o.reconciliationReasonRecorded, true, 'the escalation reason must be recorded');
    assert.equal(o.reconciliationEventAtomicSingle, true, 'exactly one reconciliation outbox event');
    assert.equal(o.escalationReplayIdempotent, true, 'replaying the escalation writes no second event');
    assert.equal(o.callStateAfterCrash, 'RECONCILIATION_REQUIRED');
    assert.equal(o.settlementNull, true, 'the reconciled call carries no settlement');
  });

  test('offline half: blind retry and stale fencing are refused on the reconciled call', () => {
    const o = probeS.observed;
    assert.equal(o.staleFencingDenied, true);
    assert.equal(o.blindRetryRefused, true, 'finalize over a reconciled call must be refused');
    assert.equal(o.reconciledCallNeverFinalized, true);
    assert.equal(o.reconciliationReplayIdempotent, true);
    assert.equal(o.reservationReplayIdempotent, true, 're-reserve replays the reconciled call, never re-charges');
  });

  test('offline half: the resolution is an AUTHORIZED decision settling exactly once', () => {
    const o = probeS.observed;
    assert.equal(o.unauthorizedDecisionRefused, true, 'a non-named actor can never execute the decision');
    assert.equal(o.reconciliationAuthorized, true, 'the decision grant resolves (reviewer-issued, actor-exact)');
    assert.equal(o.resolutionSettledExactlyOnce, true, 'exactly one settlement for the operation');
    assert.equal(o.duplicateResolutionReplayed, true, 'a duplicate resolution replays without a second event');
    assert.equal(o.noDuplicateEvents, true, 'no duplicate ledger/outbox events for the operation');
  });
});
