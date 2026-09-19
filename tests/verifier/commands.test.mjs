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
  registerProviderGrant,
  reserveExternalCall,
  BudgetExceeded,
} from '../../src/lib/verifier/commands.mjs';
import { registerKey, sign } from '../../src/lib/verifier/signature.mjs';
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

// ---- provider grant authorization fixtures (review P1-2) -------------------

// The grant issuer is a reviewer authority with signing custody (spec §3/§9:
// the beneficiary — here the evaluation harness — can never issue its own
// grant). The custody key material is test-only fixture material.
const GRANT_KEY_REF = 'kms://test/s2-006/grant-issuer-reviewer';
const GRANT_ISSUER = 'prn-reviewer';
const GRANT_BENEFICIARY_KEY_REF = 'kms://test/s2-006/grant-beneficiary-harness';
const GRANT_BENEFICIARY = 'prn-evaluation-harness';
const GRANT_KEY_REGISTRY = new Map();
registerKey({
  keyRef: GRANT_KEY_REF,
  secret: 's2-006-fixture-grant-issuer-key-01',
  custodian: GRANT_ISSUER,
  role: 'reviewer',
  registry: GRANT_KEY_REGISTRY,
});
registerKey({
  keyRef: GRANT_BENEFICIARY_KEY_REF,
  secret: 's2-006-fixture-grant-beneficiary-key-1',
  custodian: GRANT_BENEFICIARY,
  role: 'evaluation_harness',
  registry: GRANT_KEY_REGISTRY,
});
const NOW = '2026-03-22T00:00:00.000Z';

// annotation-set-style signature envelope (contracts/annotation-set.schema.json)
// — exactly what signature.mjs sign() emits since the schema-conformant
// envelope change: scheme 'hmac-sha256', MAC in `digest`, verified flag,
// attesting principal.
function grantSignature(grant, { keyRef = GRANT_KEY_REF, issuer = GRANT_ISSUER, macOverride = null } = {}) {
  const envelope = sign(issuer, keyRef, canonicalDigest(grant), { registry: GRANT_KEY_REGISTRY });
  return macOverride ? { ...envelope, digest: macOverride } : envelope;
}

// Registers a valid issuer-signed grant and returns it, ready for reserve.
function registeredGrant(authorities, overrides = {}, opts = {}) {
  const grant = makeGrant(overrides);
  registerProviderGrant(authorities, {
    grant,
    issuer: opts.issuer ?? GRANT_ISSUER,
    signature: grantSignature(grant, opts),
    registry: GRANT_KEY_REGISTRY,
  });
  return grant;
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
    assert.deepEqual(store.listCalibrationReports({ workspaceId: 'ws-verifier', corpusVersion: '0.3.0' }).map((r) => r.reportId), ['rep-fixture-1']);
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
    const grant = registeredGrant(AUTHORITIES);
    const first = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-1', operationId: 'op-call-1', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
    });
    assert.equal(first.state, 'RESERVED');
    assert.equal(first.fencingToken, 1);
    const second = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-2', operationId: 'op-call-2', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
    });
    assert.equal(second.fencingToken, 2, 'fencing tokens are unique and monotonic');

    // Idempotent reservation of the same call.
    const replay = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-1', operationId: 'op-call-1', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
    });
    assert.equal(replay.replayed, true);
    assert.equal(replay.fencingToken, 1);
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-1', operationId: 'op-call-1', reservation: { model: 'other' }, workspaceId: 'ws-verifier', now: NOW,
      }),
      IdempotencyConflict,
      'same call id with different reservation arguments conflicts',
    );

    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-annotator-1', grant, callId: 'call-3', operationId: 'op-call-3', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
      }),
      AclDenied,
    );
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness',
        grant: registeredGrant(AUTHORITIES, { grantId: 'grt-null-day', budget: { task: 5, campaign: 10, day: null } }),
        callId: 'call-4', operationId: 'op-call-4', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
      }),
      NeedsInput,
      'a missing numeric budget field is NEEDS_INPUT before the call',
    );
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness',
        grant: registeredGrant(AUTHORITIES, { grantId: 'grt-someone-else', authenticatedPrincipal: 'prn-someone-else' }),
        callId: 'call-5', operationId: 'op-call-5', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
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
    const grant = registeredGrant(AUTHORITIES);
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-crash', operationId: 'op-crash-call', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
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
    const grant = registeredGrant(AUTHORITIES);
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-fence', operationId: 'op-fence', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
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
    const grant = registeredGrant(AUTHORITIES);
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-ok', operationId: 'op-ok', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
    });
    await acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-ok', fencingToken: reserved.fencingToken });

    const outboxBefore = store.listOutbox().length;
    const finalized = await finalizeExternalCall({
      store, actor: 'prn-evaluation-harness', callId: 'call-ok', fencingToken: reserved.fencingToken,
      responseDigest: HEX_A, settlement: { amount: 0, retries: 0 },
    });
    assert.equal(finalized.state, 'FINALIZED');

    const replay = await finalizeExternalCall({
      store, actor: 'prn-evaluation-harness', callId: 'call-ok', fencingToken: reserved.fencingToken,
      responseDigest: HEX_A, settlement: { amount: 0, retries: 0 },
    });
    assert.equal(replay.replayed, true, 'same fencing token + same exact outcome replays');
    assert.equal(store.listOutbox().length, outboxBefore + 1, 'no duplicate outbox events from the replay');

    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-ok', fencingToken: reserved.fencingToken,
        responseDigest: HEX_B, settlement: { amount: 0, retries: 0 },
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
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant, callId: 'call-skip', operationId: 'op-skip', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
    });
    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-skip', fencingToken: second.fencingToken,
        responseDigest: HEX_A, settlement: { amount: 0 },
      }),
      (error) => error instanceof VerifierError && error.code === 'INVALID_TRANSITION',
    );
  });
});

describe('S2-006 provider-call authorization (review P1-2)', () => {
  const RESERVATION = { model: 'offline-deterministic', items: 2 };
  // Review reproduction: an expired, SELF-AUTHORED grant bound to ws-other
  // was accepted for a ws-a call. All three defects must now be refused.
  test('an expired self-authored grant for another workspace is refused in ws-verifier', async () => {
    const store = new InMemoryVerifierStore();
    const outboxBefore = store.listOutbox().length;

    // (1) expired grant, correctly registered and signed: still refused.
    const expired = registeredGrant(AUTHORITIES, { grantId: 'grt-expired-1', expiresAt: '2026-03-01T00:00:00.000Z' });
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant: expired,
        callId: 'call-expired', operationId: 'op-expired', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
      }),
      VerifierPolicyBlock,
    );

    // (2) missing `now` is an error, never a silent expiry skip.
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant: registeredGrant(AUTHORITIES, { grantId: 'grt-no-clock' }),
        callId: 'call-noclock', operationId: 'op-noclock', reservation: {}, workspaceId: 'ws-verifier',
      }),
      NeedsInput,
      'expiry verification is mandatory: the deterministic clock must be injected',
    );

    // (3) self-authored: the beneficiary cannot issue its own grant — even
    // with a cryptographically valid self-signature.
    const selfAuthored = makeGrant({ grantId: 'grt-self-authored' });
    assert.throws(
        () =>
          registerProviderGrant(AUTHORITIES, {
        grant: selfAuthored,
        issuer: GRANT_BENEFICIARY,
        signature: grantSignature(selfAuthored, { issuer: GRANT_BENEFICIARY, keyRef: GRANT_BENEFICIARY_KEY_REF }),
        registry: GRANT_KEY_REGISTRY,
      }),
      AclDenied,
      'self-authored grants are refused by construction',
    );
    // ...and a reviewer cannot issue a grant naming ITSELF beneficiary.
    const reviewerSelfGrant = makeGrant({ grantId: 'grt-reviewer-self', authenticatedPrincipal: GRANT_ISSUER });
    assert.throws(
        () =>
          registerProviderGrant(AUTHORITIES, {
        grant: reviewerSelfGrant,
        issuer: GRANT_ISSUER,
        signature: grantSignature(reviewerSelfGrant),
        registry: GRANT_KEY_REGISTRY,
      }),
      AclDenied,
      'issuer equals the named beneficiary',
    );

    // (4) workspace binding: a grant for ws-other cannot back a ws-verifier call.
    const multiWsAuthorities = makeVerifierAuthorityRegistry([
      { principal: 'prn-evaluation-harness', roles: ['evaluation_harness'], workspaces: ['ws-verifier', 'ws-other'] },
      { principal: 'prn-reviewer', roles: ['reviewer'], workspaces: ['ws-verifier', 'ws-other'] },
    ]);
    const foreignWsGrant = registeredGrant(multiWsAuthorities, { grantId: 'grt-ws-other', workspaceId: 'ws-other' });
    await assert.rejects(
      reserveExternalCall({
        store, authorities: multiWsAuthorities, actor: 'prn-evaluation-harness', grant: foreignWsGrant,
        callId: 'call-ws-other', operationId: 'op-ws-other', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
      }),
      AclDenied,
    );

    assert.equal(store.listOutbox().length, outboxBefore, 'no external-call events from refused reservations');
    assert.equal(store.listLedger().length, 0, 'no ledger mutation from refused reservations');
  });

  test('a caller-supplied grant that does not resolve from the authority registry is refused (unknown grant)', async () => {
    const store = new InMemoryVerifierStore();
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant: makeGrant({ grantId: 'grt-never-registered' }),
        callId: 'call-unregistered', operationId: 'op-unregistered', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
      }),
      AclDenied,
      'schema-valid but unregistered grants are never trusted',
    );
    assert.equal(await store.readExternalCall('call-unregistered'), null);
  });

  test('forged issuers and signature mismatches are refused before any state is created', async () => {
    const store = new InMemoryVerifierStore();

    // forged MAC under the reviewer keyRef
    assert.throws(
        () =>
          registerProviderGrant(AUTHORITIES, {
        grant: makeGrant({ grantId: 'grt-forged-mac' }),
        issuer: GRANT_ISSUER,
        signature: grantSignature(makeGrant({ grantId: 'grt-forged-mac' }), { macOverride: 'f'.repeat(64) }),
        registry: GRANT_KEY_REGISTRY,
      }),
      AclDenied,
    );
    // forged issuer: MAC made by the reviewer key but attested by someone else
    assert.throws(
        () =>
          registerProviderGrant(AUTHORITIES, {
        grant: makeGrant({ grantId: 'grt-forged-issuer' }),
        issuer: 'prn-annotator-1',
        signature: { scheme: 'hmac-sha256', keyRef: GRANT_KEY_REF, digest: grantSignature(makeGrant({ grantId: 'grt-forged-issuer' })).digest, verified: true, attestedBy: 'prn-annotator-1' },
        registry: GRANT_KEY_REGISTRY,
      }),
      AclDenied,
      'custodian mismatch: the key is not in the attesting principal custody',
    );
    // non-hmac-sha256 envelope is refused offline
    const wrongSchemeGrant = makeGrant({ grantId: 'grt-wrong-scheme' });
    assert.throws(
        () =>
          registerProviderGrant(AUTHORITIES, {
        grant: wrongSchemeGrant, issuer: GRANT_ISSUER,
        signature: { ...grantSignature(wrongSchemeGrant), scheme: 'ed25519' },
        registry: GRANT_KEY_REGISTRY,
      }),
      AclDenied,
    );
    // attestation not marked verified
    assert.throws(
        () =>
          registerProviderGrant(AUTHORITIES, {
        grant: makeGrant({ grantId: 'grt-unverified' }),
        issuer: GRANT_ISSUER,
        signature: { ...grantSignature(makeGrant({ grantId: 'grt-unverified' })), verified: false },
        registry: GRANT_KEY_REGISTRY,
      }),
      AclDenied,
    );
    // issuer without reviewer authority (signing with the reviewer key ref is impossible for them, so expect the custody refusal either way)
    assert.throws(
        () =>
          registerProviderGrant(AUTHORITIES, {
        grant: makeGrant({ grantId: 'grt-annotator-issued' }),
        issuer: 'prn-annotator-1',
        signature: grantSignature(makeGrant({ grantId: 'grt-annotator-issued' }), { issuer: 'prn-annotator-1', keyRef: GRANT_KEY_REF }),
        registry: GRANT_KEY_REGISTRY,
      }),
      AclDenied,
      'only reviewer authority may issue provider grants',
    );
    // a presented grant differing from the registered one is a policy block at use time
    const registered = registeredGrant(AUTHORITIES, { grantId: 'grt-tamper-target' });
    const tampered = { ...registered, timeoutMs: 1 };
    await assert.rejects(
      reserveExternalCall({
        store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant: tampered,
        callId: 'call-tampered', operationId: 'op-tampered', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
      }),
      VerifierPolicyBlock,
    );
    assert.equal(await store.readExternalCall('call-tampered'), null);
  });

  test('a foreign principal cannot accept or finalize the call (review scenario 2)', async () => {
    const store = new InMemoryVerifierStore();
    const grant = registeredGrant(AUTHORITIES);
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant,
      callId: 'call-foreign', operationId: 'op-foreign', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
    });
    await assert.rejects(
      acceptExternalCall({ store, actor: 'prn-annotator-1', callId: 'call-foreign', fencingToken: reserved.fencingToken }),
      AclDenied,
    );
    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-annotator-1', callId: 'call-foreign', fencingToken: reserved.fencingToken,
        responseDigest: HEX_A, settlement: { amount: 0 },
      }),
      AclDenied,
    );
    await assert.rejects(
      acceptExternalCall({ store, actor: undefined, callId: 'call-foreign', fencingToken: reserved.fencingToken }),
      NeedsInput,
      'actor is mandatory: un-attributed transitions break loudly',
    );
    const call = await store.readExternalCall('call-foreign');
    assert.equal(call.state, 'RESERVED', 'refused transitions mutate nothing');
    assert.equal(call.response_digest, null);
    assert.equal(call.settlement, null);
    const events = store.listOutbox().map((e) => e.event_type);
    assert.deepEqual(events, ['EXTERNAL_CALL_RESERVED'], 'no ACCEPTED/FINALIZED events leaked');
  });

  test('settlement above the remaining grant budget is BudgetExceeded and lands in reconciliation with no partial settlement (review scenario 3)', async () => {
    const store = new InMemoryVerifierStore();
    // Zero budget grant (the review scenario: settlement 999 at zero budget).
    const grant = registeredGrant(AUTHORITIES);
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant,
      callId: 'call-budget', operationId: 'op-budget', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
    });
    await acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-budget', fencingToken: reserved.fencingToken });
    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-budget', fencingToken: reserved.fencingToken,
        responseDigest: HEX_A, settlement: { amount: 999 },
      }),
      BudgetExceeded,
    );
    const call = await store.readExternalCall('call-budget');
    assert.equal(call.state, 'RECONCILIATION_REQUIRED', 'the outcome escalates to reconciliation');
    assert.equal(call.settlement, null, 'no partial settlement is recorded');
    assert.equal(call.response_digest, null);
    assert.ok(call.reconcile_reason.includes('budget'));

    // Uncertain billing: a settlement without a parseable non-negative
    // `amount` never silently counts as zero.
    const grant2 = registeredGrant(AUTHORITIES, { grantId: 'grt-uncertain' });
    const reserved2 = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant: grant2,
      callId: 'call-uncertain', operationId: 'op-uncertain', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
    });
    await acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-uncertain', fencingToken: reserved2.fencingToken });
    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-uncertain', fencingToken: reserved2.fencingToken,
        responseDigest: HEX_A, settlement: { charge: 999, currency: 'USD' },
      }),
      ReconciliationRequired,
      'unknown-billing-shape settlements escalate instead of passing as free',
    );
    const call2 = await store.readExternalCall('call-uncertain');
    assert.equal(call2.state, 'RECONCILIATION_REQUIRED');
    assert.equal(call2.settlement, null);
  });

  test('budget accounting accumulates per grant across calls; no-charge currency refuses positive amounts', async () => {
    const store = new InMemoryVerifierStore();
    const grant = registeredGrant(AUTHORITIES, { grantId: 'grt-budgeted', currency: 'USD', budget: { task: 5, campaign: 5, day: 5 } });
    const first = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant,
      callId: 'call-budget-1', operationId: 'op-budget-1', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
    });
    await acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-budget-1', fencingToken: first.fencingToken });
    const ok = await finalizeExternalCall({
      store, actor: 'prn-evaluation-harness', callId: 'call-budget-1', fencingToken: first.fencingToken,
      responseDigest: HEX_A, settlement: { amount: 3, currency: 'USD' },
    });
    assert.equal(ok.state, 'FINALIZED');

    // task scope: 3 + 3 > 5 -> BudgetExceeded
    const second = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant,
      callId: 'call-budget-2', operationId: 'op-budget-2', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
    });
    await acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-budget-2', fencingToken: second.fencingToken });
    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-budget-2', fencingToken: second.fencingToken,
        responseDigest: HEX_A, settlement: { amount: 3, currency: 'USD' },
      }),
      BudgetExceeded,
    );

    // a fresh zero-charge grant with currency 'none' refuses any positive amount
    const freeGrant = registeredGrant(AUTHORITIES, { grantId: 'grt-free' });
    const freeCall = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant: freeGrant,
      callId: 'call-free', operationId: 'op-free', reservation: {}, workspaceId: 'ws-verifier', now: NOW,
    });
    await acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-free', fencingToken: freeCall.fencingToken });
    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-free', fencingToken: freeCall.fencingToken,
        responseDigest: HEX_A, settlement: { amount: 1 },
      }),
      BudgetExceeded,
      'a no-charge grant settled a positive amount',
    );
  });

  test('finalize cannot substitute a grant different from the reservation-bound one', async () => {
    const store = new InMemoryVerifierStore();
    const grant = registeredGrant(AUTHORITIES, { grantId: 'grt-bound-a' });
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', grant,
      callId: 'call-bound', operationId: 'op-bound', reservation: RESERVATION, workspaceId: 'ws-verifier', now: NOW,
    });
    await acceptExternalCall({ store, actor: 'prn-evaluation-harness', callId: 'call-bound', fencingToken: reserved.fencingToken });
    const otherGrant = registeredGrant(AUTHORITIES, { grantId: 'grt-bound-b', budget: { task: 100, campaign: 100, day: 100 } });
    await assert.rejects(
      finalizeExternalCall({
        store, actor: 'prn-evaluation-harness', callId: 'call-bound', fencingToken: reserved.fencingToken,
        responseDigest: HEX_A, settlement: { amount: 0 }, grant: otherGrant,
      }),
      VerifierPolicyBlock,
      'the reservation froze grant A; finalize with grant B is refused',
    );
    const ok = await finalizeExternalCall({
      store, actor: 'prn-evaluation-harness', callId: 'call-bound', fencingToken: reserved.fencingToken,
      responseDigest: HEX_A, settlement: { amount: 0 }, grant,
    });
    assert.equal(ok.state, 'FINALIZED', 'the exact reservation-bound grant finalizes');
  });
});

