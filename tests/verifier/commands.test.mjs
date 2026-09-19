// S2-006 wave 2A — offline tests for the explicit state-changing command API
// (spec §5, §11). Runs entirely on the InMemory store: capability gates,
// exact-args gates, idempotency (replay vs typed conflict), atomic
// record+ledger+outbox publication, unknown-commit reconciliation and the
// fenced external-call state machine. No network, no LLM, no DB.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import {
  computeCanonicalArgsDigest,
  verifyClaim,
} from '../../src/lib/verifier/api.mjs';
import {
  InMemoryVerifierStore,
  deriveIdempotencyKey,
} from '../../src/lib/verifier/store.mjs';
import {
  makeVerifierAuthorityRegistry,
  acceptExternalCall,
  finalizeExternalCall,
  invalidateCalibration,
  publishAdjudication,
  publishCalibrationReport,
  publishVerificationResult,
  reserveExternalCall,
} from '../../src/lib/verifier/commands.mjs';
import {
  AclDenied,
  ContractVersionUnknown,
  IdempotencyConflict,
  NeedsInput,
  ReconciliationRequired,
  VerifierError,
  VerifierPolicyBlock,
} from '../../src/lib/verifier/errors.mjs';

const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);
const HEX_C = 'c'.repeat(64);
const HEX_D = 'd'.repeat(64);
const AS_OF = '2026-03-22T00:00:00.000Z';

const AUTHORITIES = makeVerifierAuthorityRegistry([
  { principal: 'prn-evaluation-harness', roles: ['evaluation_harness'], workspaces: ['ws-verifier'] },
  { principal: 'prn-adjudicator', roles: ['adjudicator'], workspaces: ['ws-verifier'] },
  { principal: 'prn-annotator-1', roles: ['annotator'], workspaces: ['ws-verifier'] },
  { principal: 'prn-annotator-2', roles: ['annotator'], workspaces: ['ws-verifier'] },
  // Role reuse (probe R): one principal holding annotator AND adjudicator.
  { principal: 'prn-role-reuse', roles: ['annotator', 'adjudicator'], workspaces: ['ws-verifier'] },
  { principal: 'prn-reviewer', roles: ['reviewer'], workspaces: ['ws-verifier'] },
  { principal: 'prn-custodian', roles: ['label_custodian'], workspaces: ['ws-verifier'] },
]);

const PAYLOAD = {
  statement: 'Trial X reported a 12% reduction in systolic blood pressure versus placebo.',
  citations: [{ claimId: 'clm-src-0001', claimRevision: 1, segmentId: 'seg-0001' }],
};

function makeRequest(overrides = {}) {
  const base = {
    contractVersion: '1.0.0',
    requestId: 'svr-fixture-1',
    actor: 'prn-evaluation-harness',
    workspaceId: 'ws-verifier',
    artifact: { kind: 'claim', artifactId: 'clm-alpha-1', revision: 1, digest: canonicalDigest(PAYLOAD) },
    requestedChecks: ['citation_entailment'],
    asOf: AS_OF,
    aclGrantRef: 'cap-verifier.read',
    rubricVersion: '1.0.0',
    corpusVersion: '0.3.0',
    thresholdVersion: '1.0.0',
    idempotencyKey: 'idem-fixture-1',
    ...overrides,
  };
  base.canonicalArgsDigest = computeCanonicalArgsDigest(base);
  return base;
}

async function makeVerifiedResult(overrides = {}) {
  const request = makeRequest(overrides.request ?? {});
  const { result } = await verifyClaim(request, {
    checker: { check: () => ({ verdict: 'SUPPORTED', reasonCodes: [] }) },
    acl: { can: () => true },
    digests: { rubricDigest: HEX_A, corpusManifestDigest: HEX_B, thresholdsDigest: HEX_C },
    artifact: { kind: 'claim', artifactId: request.artifact.artifactId, revision: 1, payload: PAYLOAD },
  });
  return { request, result };
}

function makeGrant(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    grantId: 'grt-verifier-1',
    authenticatedPrincipal: 'prn-evaluation-harness',
    tool: 'semantic-verifier',
    workspaceId: 'ws-verifier',
    modelAccess: { modelId: 'offline-deterministic', modelVersion: '1.0.0', access: 'inference_only' },
    currency: 'none',
    timeoutMs: 30000,
    budget: { task: 0, campaign: 0, day: 0 },
    noTraining: true,
    noRetention: true,
    issuedAt: '2026-03-01T00:00:00.000Z',
    expiresAt: '2027-01-01T00:00:00.000Z',
    ...overrides,
  };
}

function makeAdjudication(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    adjudicationId: 'adj-fixture-1',
    caseId: 'case-fixture-1',
    annotationSetIds: ['ans-annot-1', 'ans-annot-2'],
    conflictingLabels: [
      { annotationSetId: 'ans-annot-1', annotatorId: 'prn-annotator-1', label: 'SUPPORTED', labelDigest: HEX_A },
      { annotationSetId: 'ans-annot-2', annotatorId: 'prn-annotator-2', label: 'CONTRADICTED', labelDigest: HEX_B },
    ],
    retainedRawLabels: [
      { annotationSetId: 'ans-annot-1', annotatorId: 'prn-annotator-1', label: 'SUPPORTED', labelDigest: HEX_A },
      { annotationSetId: 'ans-annot-2', annotatorId: 'prn-annotator-2', label: 'CONTRADICTED', labelDigest: HEX_B },
    ],
    decision: 'SUPPORTED',
    rationale: 'The cited span entails the statement with matching units and population.',
    adjudicatorIdentity: { principalId: 'prn-adjudicator', role: 'adjudicator', authenticated: true, attestationDigest: HEX_C },
    versions: { corpusVersion: '0.3.0', rubricDigest: HEX_A, annotationManifestDigest: HEX_B, thresholdsDigest: HEX_C },
    auditRef: { auditEntryId: 'aud-adj-fixture-1', auditDigest: HEX_D },
    createdAt: '2026-03-22T00:00:00.000Z',
    ...overrides,
  };
}

function makeInvalidationEvent(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    eventId: 'vinv-fixture-1',
    cause: 'rubric_drift',
    causeDetail: 'rubric 1.1.0 supersedes 1.0.0; calibration over corpus 0.3.0 is stale for new inputs',
    affectedRecords: [
      { recordKind: 'calibration_report', recordId: 'rep-fixture-1', recordDigest: HEX_A, resultingState: 'STALE' },
    ],
    supersedeLink: { supersededByKind: 'calibration_report', supersededById: 'rep-fixture-2', supersededByDigest: HEX_B },
    createdBy: 'prn-reviewer',
    createdAt: '2026-03-22T00:00:00.000Z',
    ...overrides,
  };
}

function makeReport(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    reportId: 'rep-fixture-1',
    corpusVersion: '0.3.0',
    rubricDigest: HEX_A,
    thresholdsDigest: HEX_C,
    metricRecords: [
      {
        name: 'citation_entailment_precision',
        numerator: 7,
        denominator: 10,
        missingCount: 0,
        value: 0.7,
        intervalMethod: 'wilson',
        interval: { lower: 0.4, upper: 0.9, confidenceLevel: 0.95 },
        status: 'MEASURED',
      },
      {
        name: 'causal_overclaim_rate',
        numerator: 0,
        denominator: 0,
        missingCount: 5,
        value: null,
        intervalMethod: 'none',
        interval: null,
        status: 'NOT_MEASURED',
        notMeasuredReason: 'insufficient_samples',
      },
    ],
    confusionMatrices: [
      { name: 'citation_entailment', truePositive: 7, falsePositive: 3, falseNegative: 2, trueNegative: 8, missing: 0 },
    ],
    slices: [
      { name: 'global_locked_test', stratum: 'global', caseCount: 20, metricNames: ['citation_entailment_precision'] },
    ],
    selectiveRisk: { risk: 0.2, coverage: 0.9, curve: [{ coverage: 0.9, risk: 0.2 }] },
    coverage: { denominator: 20, evaluated: 18, missing: 2, floor: 0.8 },
    thresholdDecision: { thresholdsDigest: HEX_C, status: 'APPLIED', ownerDecisionRef: HEX_D, appliedAt: '2026-03-20T00:00:00.000Z' },
    independenceTier: 'UNVERIFIED',
    limitations: ['synthetic-only corpus; no external-validity claim is made'],
    expiry: { at: '2026-06-01T00:00:00.000Z', cause: 'corpus_drift' },
    driftScope: ['rubric:1.0.0', 'corpus:0.3.0', 'thresholds:2026-03-20'],
    ...overrides,
  };
}

describe('S2-006 command API — publishVerificationResult', () => {
  test('publishes request+result atomically with one ledger entry and one outbox event', async () => {
    const store = new InMemoryVerifierStore();
    const { request, result } = await makeVerifiedResult();
    const outcome = await publishVerificationResult({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request, result, operationId: 'op-publish-1',
    });
    assert.equal(outcome.replayed, false);
    const ledger = store.listLedger();
    assert.equal(ledger.length, 1);
    assert.equal(ledger[0].status, 'COMMITTED');
    assert.equal(ledger[0].operation, 'publishVerificationResult');
    const outbox = store.listOutbox();
    assert.equal(outbox.length, 1);
    assert.equal(outbox[0].event_type, 'VERIFICATION_RESULT_PUBLISHED');
    assert.deepEqual(store.getRecord('result', result.resultId), result);
    assert.deepEqual(store.getRecord('request', request.requestId), request);
  });

  test('an identical republish replays the recorded outcome and writes nothing twice', async () => {
    const store = new InMemoryVerifierStore();
    const { request, result } = await makeVerifiedResult();
    const first = await publishVerificationResult({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request, result, operationId: 'op-publish-1',
    });
    const second = await publishVerificationResult({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request, result, operationId: 'op-publish-2',
    });
    assert.equal(second.replayed, true, 'same actor + operation + canonicalArgs must replay');
    assert.equal(second.outcomeDigest, first.outcomeDigest);
    assert.equal(store.listLedger().length, 1, 'idempotent replay adds no ledger rows');
    assert.equal(store.listOutbox().length, 1, 'idempotent replay adds no outbox events');
  });

  test('reusing the idempotency key with different arguments conflicts without mutation', async () => {
    const store = new InMemoryVerifierStore();
    const { request, result } = await makeVerifiedResult();
    await publishVerificationResult({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request, result, operationId: 'op-publish-1',
    });
    const mutatedResult = { ...result, status: 'INCOMPLETE' };
    await assert.rejects(
      publishVerificationResult({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request, result: mutatedResult, operationId: 'op-publish-2',
      }),
      IdempotencyConflict,
    );
    assert.equal(store.listLedger().length, 1, 'conflict leaves the ledger untouched');
    assert.equal(store.listOutbox().length, 1, 'conflict leaves the outbox untouched');
    assert.equal(store.getRecord('result', result.resultId).status, 'READY_FOR_HUMAN_REVIEW', 'original record untouched');
  });

  test('capability gate: only evaluation_harness/reviewer may publish', async () => {
    const store = new InMemoryVerifierStore();
    const { request, result } = await makeVerifiedResult();
    await assert.rejects(
      publishVerificationResult({
        store, authorities: AUTHORITIES, actor: 'prn-annotator-1', request, result, operationId: 'op-publish-3',
      }),
      AclDenied,
    );
    await assert.rejects(
      publishVerificationResult({
        store, authorities: AUTHORITIES, actor: 'prn-adjudicator', request, result, operationId: 'op-publish-4',
      }),
      AclDenied,
    );
    assert.equal(store.listLedger().length, 0);
    assert.equal(store.listOutbox().length, 0);
  });

  test('exact-args gate rejects tampered digests and unbound results before any write', async () => {
    const store = new InMemoryVerifierStore();
    const { request, result } = await makeVerifiedResult();
    const tamperedRequest = makeRequest();
    tamperedRequest.canonicalArgsDigest = HEX_D;
    await assert.rejects(
      publishVerificationResult({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request: tamperedRequest, result, operationId: 'op-publish-5',
      }),
      VerifierPolicyBlock,
    );
    const foreignResult = { ...result, requestRef: 'svr-other-request' };
    await assert.rejects(
      publishVerificationResult({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request, result: foreignResult, operationId: 'op-publish-6',
      }),
      VerifierPolicyBlock,
    );
    await assert.rejects(
      publishVerificationResult({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness',
        request: makeRequest({ contractVersion: '9.9.9' }), result, operationId: 'op-publish-7',
      }),
      (error) => error instanceof ContractVersionUnknown,
    );
    assert.equal(store.listLedger().length, 0, 'no partial writes from rejected commands');
  });

  test('unknown commit outcome escalates to reconciliation and a retry cannot bypass it', async () => {
    const store = new InMemoryVerifierStore();
    const { request, result } = await makeVerifiedResult();
    store.injectFault({ at: 'unknown-commit', once: true });
    await assert.rejects(
      publishVerificationResult({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request, result, operationId: 'op-crash-1',
      }),
      ReconciliationRequired,
    );
    assert.equal(store.listOutbox().length, 0, 'a crash before the outbox write leaves no audit event');
    const ledger = store.listLedger();
    assert.equal(ledger.length, 1);
    assert.equal(ledger[0].status, 'RECONCILIATION_REQUIRED');
    // Retry with the same key must NOT blindly re-execute.
    await assert.rejects(
      publishVerificationResult({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request, result, operationId: 'op-crash-2',
      }),
      ReconciliationRequired,
    );
    assert.equal(store.listLedger().length, 1, 'no duplicate ledger rows from the retry');
  });
});

describe('S2-006 command API — calibration and adjudication', () => {
  test('publishCalibrationReport stores the aggregate under the evaluation_harness role', async () => {
    const store = new InMemoryVerifierStore();
    const report = makeReport();
    const outcome = await publishCalibrationReport({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', report, operationId: 'op-cal-1', workspaceId: 'ws-verifier',
    });
    assert.equal(outcome.replayed, false);
    assert.deepEqual(store.getRecord('calibration_report', 'rep-fixture-1'), report);
    assert.deepEqual(store.listCalibrationReports({ corpusVersion: '0.3.0' }).map((r) => r.reportId), ['rep-fixture-1']);
    await assert.rejects(
      publishCalibrationReport({
        store, authorities: AUTHORITIES, actor: 'prn-annotator-1', report, operationId: 'op-cal-2', workspaceId: 'ws-verifier',
      }),
      AclDenied,
    );
  });

  test('publishAdjudication requires the authenticated adjudicator of record', async () => {
    const store = new InMemoryVerifierStore();
    const adjudication = makeAdjudication();
    await publishAdjudication({
      store, authorities: AUTHORITIES, actor: 'prn-adjudicator', adjudication, operationId: 'op-adj-1', workspaceId: 'ws-verifier',
    });
    assert.deepEqual(store.getRecord('adjudication', 'adj-fixture-1'), adjudication);

    await assert.rejects(
      publishAdjudication({
        store, authorities: AUTHORITIES, actor: 'prn-annotator-1', adjudication, operationId: 'op-adj-2', workspaceId: 'ws-verifier',
      }),
      AclDenied,
      'an annotator has no adjudicator role',
    );
    await assert.rejects(
      publishAdjudication({
        store, authorities: AUTHORITIES, actor: 'prn-reviewer',
        adjudication: makeAdjudication(), operationId: 'op-adj-3', workspaceId: 'ws-verifier',
      }),
      AclDenied,
      'the publishing actor must be the adjudicator of record',
    );
    await assert.rejects(
      publishAdjudication({
        store, authorities: AUTHORITIES, actor: 'prn-adjudicator',
        adjudication: makeAdjudication({
          adjudicatorIdentity: { principalId: 'prn-adjudicator', role: 'adjudicator', authenticated: false, attestationDigest: HEX_C },
        }),
        operationId: 'op-adj-4', workspaceId: 'ws-verifier',
      }),
      VerifierPolicyBlock,
      'unauthenticated adjudicator identity is a policy block',
    );
    await assert.rejects(
      publishAdjudication({
        store, authorities: AUTHORITIES, actor: 'prn-role-reuse',
        adjudication: makeAdjudication({
          adjudicationId: 'adj-conflict-1',
          adjudicatorIdentity: { principalId: 'prn-role-reuse', role: 'adjudicator', authenticated: true, attestationDigest: HEX_C },
          conflictingLabels: [
            { annotationSetId: 'ans-annot-1', annotatorId: 'prn-role-reuse', label: 'SUPPORTED', labelDigest: HEX_A },
            { annotationSetId: 'ans-annot-2', annotatorId: 'prn-annotator-2', label: 'CONTRADICTED', labelDigest: HEX_B },
          ],
          retainedRawLabels: [
            { annotationSetId: 'ans-annot-1', annotatorId: 'prn-role-reuse', label: 'SUPPORTED', labelDigest: HEX_A },
            { annotationSetId: 'ans-annot-2', annotatorId: 'prn-annotator-2', label: 'CONTRADICTED', labelDigest: HEX_B },
          ],
        }),
        operationId: 'op-adj-5', workspaceId: 'ws-verifier',
      }),
      VerifierPolicyBlock,
      'an annotator of the case can never adjudicate it even when the roles were reused (spec §3, probe R)',
    );
  });

  test('invalidateCalibration publishes the typed invalidation event with reviewer/custodian authority', async () => {
    const store = new InMemoryVerifierStore();
    const event = makeInvalidationEvent();
    await invalidateCalibration({
      store, authorities: AUTHORITIES, actor: 'prn-reviewer', event, operationId: 'op-inv-1', workspaceId: 'ws-verifier',
    });
    assert.deepEqual(store.getRecord('invalidation', 'vinv-fixture-1'), event);
    const outbox = store.listOutbox();
    assert.equal(outbox.length, 1);
    assert.equal(outbox[0].event_type, 'CALIBRATION_INVALIDATED');

    await invalidateCalibration({
      store, authorities: AUTHORITIES, actor: 'prn-custodian',
      event: makeInvalidationEvent({ eventId: 'vinv-fixture-2', cause: 'label_revoked' }),
      operationId: 'op-inv-2', workspaceId: 'ws-verifier',
    });
    assert.ok(store.getRecord('invalidation', 'vinv-fixture-2'));

    await assert.rejects(
      invalidateCalibration({
        store, authorities: AUTHORITIES, actor: 'prn-annotator-2', event, operationId: 'op-inv-3', workspaceId: 'ws-verifier',
      }),
      AclDenied,
    );
    await assert.rejects(
      invalidateCalibration({
        store, authorities: AUTHORITIES, actor: 'prn-reviewer',
        event: makeInvalidationEvent({ eventId: 'vinv-fixture-3', affectedRecords: [] }),
        operationId: 'op-inv-4', workspaceId: 'ws-verifier',
      }),
      VerifierError,
      'impact set must be non-empty and computable (schema or policy)',
    );
  });
});

describe('S2-006 command API — fenced external provider calls', () => {
  const RESERVATION = { model: 'offline-deterministic', items: 2 };

  test('deriveIdempotencyKey binds actor+operation+canonicalArgsDigest deterministically', () => {
    const key = deriveIdempotencyKey({ actor: 'prn-a', operation: 'op', canonicalArgsDigest: HEX_A });
    assert.equal(key, deriveIdempotencyKey({ actor: 'prn-a', operation: 'op', canonicalArgsDigest: HEX_A }));
    assert.notEqual(key, deriveIdempotencyKey({ actor: 'prn-b', operation: 'op', canonicalArgsDigest: HEX_A }));
    assert.notEqual(key, deriveIdempotencyKey({ actor: 'prn-a', operation: 'op', canonicalArgsDigest: HEX_B }));
    assert.throws(() => deriveIdempotencyKey({ actor: 'prn-a', operation: 'op', canonicalArgsDigest: 'nothex' }), NeedsInput);
  });

  test('reserve issues unique monotonic fencing tokens and validates the grant', async () => {
    const store = new InMemoryVerifierStore();
    const grant = makeGrant();
    const first = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-1', operationId: 'op-call-1', reservation: RESERVATION, workspaceId: 'ws-verifier',
    });
    assert.equal(first.state, 'RESERVED');
    assert.equal(first.fencingToken, 1);
    const second = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-2', operationId: 'op-call-2', reservation: RESERVATION, workspaceId: 'ws-verifier',
    });
    assert.equal(second.fencingToken, 2, 'fencing tokens are unique and monotonic');

    // Idempotent reservation of the same call.
    const replay = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-1', operationId: 'op-call-1', reservation: RESERVATION, workspaceId: 'ws-verifier',
    });
    assert.equal(replay.replayed, true);
    assert.equal(replay.fencingToken, 1);
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-1', operationId: 'op-call-1', reservation: { model: 'other' }, workspaceId: 'ws-verifier',
      }),
      IdempotencyConflict,
      'same call id with different reservation arguments conflicts',
    );

    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-annotator-1', grant, callId: 'call-3', operationId: 'op-call-3', reservation: {}, workspaceId: 'ws-verifier',
      }),
      AclDenied,
    );
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness',
        grant: makeGrant({ budget: { task: 5, campaign: 10, day: null } }),
        callId: 'call-4', operationId: 'op-call-4', reservation: {}, workspaceId: 'ws-verifier',
      }),
      NeedsInput,
      'a missing numeric budget field is NEEDS_INPUT before the call',
    );
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness',
        grant: makeGrant({ authenticatedPrincipal: 'prn-someone-else' }),
        callId: 'call-5', operationId: 'op-call-5', reservation: {}, workspaceId: 'ws-verifier',
      }),
      AclDenied,
    );
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant,
        callId: 'call-6', operationId: 'op-call-6', reservation: {}, workspaceId: 'ws-verifier',
        now: '2028-01-01T00:00:00.000Z',
      }),
      VerifierPolicyBlock,
      'an expired grant is a policy block',
    );
  });

  test('kill between ACCEPTED and FINALIZED escalates to reconciliation; retry is refused', async () => {
    const store = new InMemoryVerifierStore();
    const grant = makeGrant();
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-crash', operationId: 'op-crash-call', reservation: RESERVATION, workspaceId: 'ws-verifier',
    });
    await acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-crash', fencingToken: reserved.fencingToken });

    // The process dies after REQUEST_ACCEPTED; on restart the outcome is unknown.
    const reconciled = await finalizeExternalCall({
      store, actor: 'prn-evaluation-harness', callId: 'call-crash', fencingToken: reserved.fencingToken, outcome: 'unknown', reason: 'process killed after accept',
    });
    assert.equal(reconciled.state, 'RECONCILIATION_REQUIRED');
    const call = await store.readExternalCall('call-crash');
    assert.equal(call.state, 'RECONCILIATION_REQUIRED');
    assert.equal(call.response_digest, null, 'no fabricated response digest');
    assert.equal(call.settlement, null, 'no fabricated settlement');

    // A later success finalize must not silently resurrect the call.
    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-crash', fencingToken: reserved.fencingToken,
        responseDigest: HEX_A, settlement: { cost: 0 },
      }),
      ReconciliationRequired,
    );
    const events = store.listOutbox().filter((e) => e.record_id === 'call-crash').map((e) => e.event_type);
    assert.ok(events.includes('EXTERNAL_CALL_RECONCILIATION_REQUIRED'));
  });

  test('stale fencing tokens cannot mutate a call', async () => {
    const store = new InMemoryVerifierStore();
    const grant = makeGrant();
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-fence', operationId: 'op-fence', reservation: RESERVATION, workspaceId: 'ws-verifier',
    });
    await assert.rejects(
      acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-fence', fencingToken: reserved.fencingToken + 37 }),
      AclDenied,
    );
    const call = await store.readExternalCall('call-fence');
    assert.equal(call.state, 'RESERVED', 'fencing failure leaves no state change');
  });

  test('successful finalize is idempotent per fencing token and conflicts on different settlement', async () => {
    const store = new InMemoryVerifierStore();
    const grant = makeGrant();
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-ok', operationId: 'op-ok', reservation: RESERVATION, workspaceId: 'ws-verifier',
    });
    await acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-ok', fencingToken: reserved.fencingToken });

    const outboxBefore = store.listOutbox().length;
    const finalized = await finalizeExternalCall({
      store, actor: 'prn-evaluation-harness', callId: 'call-ok', fencingToken: reserved.fencingToken,
      responseDigest: HEX_A, settlement: { cost: 0, retries: 0 },
    });
    assert.equal(finalized.state, 'FINALIZED');

    const replay = await finalizeExternalCall({
      store, actor: 'prn-evaluation-harness', callId: 'call-ok', fencingToken: reserved.fencingToken,
      responseDigest: HEX_A, settlement: { cost: 0, retries: 0 },
    });
    assert.equal(replay.replayed, true, 'same fencing token + same exact outcome replays');
    assert.equal(store.listOutbox().length, outboxBefore + 1, 'no duplicate outbox events from the replay');

    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-ok', fencingToken: reserved.fencingToken,
        responseDigest: HEX_B, settlement: { cost: 0, retries: 0 },
      }),
      IdempotencyConflict,
      'a different response digest under the same fencing token conflicts',
    );

    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-ok', fencingToken: reserved.fencingToken, outcome: 'unknown',
      }),
      (error) => error instanceof VerifierError && error.code === 'INVALID_TRANSITION',
      'a finalized call can never be dragged back to reconciliation',
    );

    // RESERVED -> FINALIZED is not a legal transition.
    const second = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-skip', operationId: 'op-skip', reservation: RESERVATION, workspaceId: 'ws-verifier',
    });
    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-skip', fencingToken: second.fencingToken,
        responseDigest: HEX_A, settlement: {},
      }),
      (error) => error instanceof VerifierError && error.code === 'INVALID_TRANSITION',
    );
  });
});
