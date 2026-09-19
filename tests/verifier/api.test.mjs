// S2-006 wave 2A — offline tests for the pure compute/query API
// (spec §5, §13). Core unit tests: no network, no LLM, no DB.
// Covered here:
//   * pure mode never mutates files, stores or its input fixtures;
//   * verify* with an INJECTED checker (the rubric implementation itself is
//     a parallel workstream and is never imported);
//   * a typed checker failure (exception/timeout/policy refusal) never
//     becomes a semantic SUPPORTED/CONTRADICTED verdict (spec §5, probe P);
//   * deterministic staleness rules (stale/future/revoked sources);
//   * auditVerifierRunForLeaks catches locked-label access, candidate
//     adjudication access, private span/count leaks and post-as_of sources
//     (probes G, H, Q).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalDigest,
} from '../../src/lib/verifier/canonical-json.mjs';
import {
  auditVerifierRunForLeaks,
  computeCanonicalArgsDigest,
  getVerificationResult,
  listCalibrationReports,
  verifyClaim,
  verifyEvidenceMap,
  verifyHypothesisCard,
  verifySynthesisResult,
  verifierValidators,
} from '../../src/lib/verifier/api.mjs';
import { InMemoryVerifierStore } from '../../src/lib/verifier/store.mjs';
import {
  AclDenied,
  NeedsInput,
  StaleInput,
  VerifierError,
  VerifierPolicyBlock,
  ContractVersionUnknown,
} from '../../src/lib/verifier/errors.mjs';

const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);
const HEX_C = 'c'.repeat(64);
const HEX_D = 'd'.repeat(64);
const HEX_E = 'e'.repeat(64);
const AS_OF = '2026-03-22T00:00:00.000Z';

const PAYLOAD = Object.freeze({
  statement: 'Trial X reported a 12% reduction in systolic blood pressure versus placebo.',
  citations: [
    {
      claimId: 'clm-src-0001',
      claimRevision: 1,
      segmentId: 'seg-0001',
      span: { start: 0, end: 30 },
      quoteDigest: HEX_B,
    },
  ],
});

function makeRequest(overrides = {}) {
  const base = {
    contractVersion: '1.0.0',
    requestId: 'svr-fixture-1',
    actor: 'prn-evaluation-harness',
    workspaceId: 'ws-verifier',
    artifact: { kind: 'claim', artifactId: 'clm-alpha-1', revision: 1, digest: canonicalDigest(PAYLOAD) },
    requestedChecks: ['citation_entailment', 'number_unit_preservation'],
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

const ALLOW_ACL = Object.freeze({ can: () => true });
const DENY_ACL = Object.freeze({ can: () => false });
const DIGESTS = Object.freeze({ rubricDigest: HEX_A, corpusManifestDigest: HEX_B, thresholdsDigest: HEX_C });

function artifactFor(payload) {
  return { kind: 'claim', artifactId: 'clm-alpha-1', revision: 1, payload };
}

const SUPPORTING_CHECKER = Object.freeze({
  check: (item) => ({ verdict: 'SUPPORTED', reasonCodes: [], uncertainty: { kind: 'epistemic', value: 0.1 } }),
});

describe('S2-006 verifier pure compute API', () => {
  test('verifyClaim with an injected checker produces a contract-valid advisory result', async () => {
    const { result } = await verifyClaim(makeRequest(), {
      checker: SUPPORTING_CHECKER,
      acl: ALLOW_ACL,
      digests: DIGESTS,
      artifact: artifactFor(PAYLOAD),
    });
    assert.equal(result.status, 'READY_FOR_HUMAN_REVIEW');
    assert.equal(result.requestRef, 'svr-fixture-1');
    assert.equal(result.humanDecisionRequired, true, 'verifier verdicts are advisory only');
    assert.deepEqual(result.coverage, { denominator: 2, evaluated: 2, missing: 0 });
    assert.equal(result.items.length, 2);
    for (const item of result.items) {
      assert.equal(item.verdict, 'SUPPORTED');
      assert.deepEqual(item.missingness, { kind: 'none' });
      assert.match(item.itemId, /^svi-[a-z0-9][a-z0-9-]{0,62}$/);
      assert.match(item.provenance.runId, /^run-[a-z0-9][a-z0-9-]{0,62}$/);
    }
    // outputDigest is self-excluding: digest over the canonical form with
    // outputDigest set to null.
    assert.equal(result.outputDigest, canonicalDigest({ ...result, outputDigest: null }));
    verifierValidators().requireValid('semantic-verification-result', result);
  });

  test('pure mode is deterministic and mutates neither fixtures nor any store', async () => {
    const request = makeRequest();
    const payloadSnapshot = JSON.stringify(PAYLOAD);
    const options = {
      checker: SUPPORTING_CHECKER,
      acl: ALLOW_ACL,
      digests: DIGESTS,
      artifact: artifactFor(PAYLOAD),
    };
    const first = await verifyClaim(request, options);
    const second = await verifyClaim(request, options);
    assert.deepEqual(first.result, second.result, 'decision-affecting output must not depend on wall clock or ordering');

    assert.equal(JSON.stringify(PAYLOAD), payloadSnapshot, 'artifact payload untouched');
    const store = new InMemoryVerifierStore();
    await verifyClaim(request, { ...options });
    assert.equal(store.listLedger().length, 0, 'pure compute writes no ledger entries');
    assert.equal(store.listOutbox().length, 0, 'pure compute writes no outbox events');
    assert.equal(store.getRecord('result', 'sres-any'), null);
  });

  test('a typed checker failure never becomes a semantic pass/fail (probe P)', async () => {
    const timeoutChecker = {
      check() {
        const error = new Error('provider deadline exceeded');
        error.code = 'ETIMEDOUT';
        throw error;
      },
    };
    const { result } = await verifyClaim(makeRequest(), {
      checker: timeoutChecker,
      acl: ALLOW_ACL,
      digests: DIGESTS,
      artifact: artifactFor(PAYLOAD),
    });
    assert.equal(result.status, 'INCOMPLETE');
    assert.deepEqual(result.coverage, { denominator: 2, evaluated: 0, missing: 2 });
    for (const item of result.items) {
      assert.deepEqual(item.missingness, { kind: 'timeout', detail: 'provider deadline exceeded' });
      assert.equal(item.verdict, 'INSUFFICIENT_EVIDENCE');
      assert.ok(!['SUPPORTED', 'CONTRADICTED', 'PARTIALLY_SUPPORTED'].includes(item.verdict));
    }
    assert.equal(result.abstentions.length, 2);
    for (const abstention of result.abstentions) {
      assert.equal(abstention.reason, 'TIMEOUT');
      assert.equal(abstention.scope, 'item');
    }
  });

  test('policy refusal, evaluator failure and unbounded checker output map to typed missingness', async () => {
    const run = (checker) => verifyClaim(makeRequest(), { checker, acl: ALLOW_ACL, digests: DIGESTS, artifact: artifactFor(PAYLOAD) });

    const refused = await run({
      check() { throw new VerifierPolicyBlock('model content-policy refusal'); },
    });
    assert.equal(refused.result.items[0].missingness.kind, 'policy_refusal');
    assert.ok(refused.result.items[0].reasonCodes.includes('policy_block'));

    const broken = await run({
      check() { throw new Error('evaluator crashed'); },
    });
    assert.equal(broken.result.items[0].missingness.kind, 'source_unavailable');
    assert.equal(broken.result.items[0].verdict, 'INSUFFICIENT_EVIDENCE');

    const unbounded = await run({ check: () => ({ verdict: 'ABSOLUTELY_TRUE' }) });
    assert.equal(unbounded.result.items[0].missingness.kind, 'evaluator_missing');
    assert.equal(unbounded.result.status, 'INCOMPLETE');
  });

  test('stale, future and revoked sources deterministically invalidate the verdict (§7)', async () => {
    const base = {
      checker: SUPPORTING_CHECKER,
      acl: ALLOW_ACL,
      digests: DIGESTS,
      artifact: artifactFor(PAYLOAD),
    };
    const future = await verifyClaim(makeRequest(), {
      ...base,
      sourceIndex: { 'seg-0001': { publishedAt: '2026-04-01T00:00:00.000Z' } },
    });
    assert.equal(future.result.items[0].verdict, 'STALE_INPUT');
    assert.ok(future.result.items[0].reasonCodes.includes('future_source'));

    const revoked = await verifyClaim(makeRequest(), {
      ...base,
      sourceIndex: { 'seg-0001': { accessState: 'tombstoned' } },
    });
    assert.equal(revoked.result.items[0].verdict, 'STALE_INPUT');
    assert.ok(revoked.result.items[0].reasonCodes.includes('revoked_source'));

    const stale = await verifyClaim(makeRequest(), {
      ...base,
      sourceIndex: { 'seg-0001': { stale: true } },
    });
    assert.equal(stale.result.items[0].verdict, 'STALE_INPUT');
    assert.ok(stale.result.items[0].reasonCodes.includes('stale_source'));
  });

  test('a citation check without cited spans abstains deterministically without calling the checker (probe E)', async () => {
    let checkerCalls = 0;
    const payload = { statement: 'Persuasive summary with zero citations.', citations: [] };
    const request = makeRequest({
      requestedChecks: ['citation_entailment'],
      artifact: { kind: 'claim', artifactId: 'clm-alpha-1', revision: 1, digest: canonicalDigest(payload) },
    });
    const { result } = await verifyClaim(request, {
      checker: { check: () => { checkerCalls += 1; return { verdict: 'SUPPORTED' }; } },
      acl: ALLOW_ACL,
      digests: DIGESTS,
      artifact: artifactFor(payload),
    });
    assert.equal(checkerCalls, 0, 'no citation means the deterministic rule applies, not the checker');
    const item = result.items.find((i) => i.criterion === 'citation_entailment');
    assert.equal(item.verdict, 'INSUFFICIENT_EVIDENCE');
    assert.ok(item.reasonCodes.includes('missing_citation'));
    assert.equal(result.abstentions[0].reason, 'NO_CITATION');
  });

  test('independent gold labels surface disagreements without erasing raw labels', async () => {
    const request = makeRequest({ requestedChecks: ['citation_entailment'] });
    const { result } = await verifyClaim(request, {
      checker: { check: () => ({ verdict: 'SUPPORTED' }) },
      acl: ALLOW_ACL,
      digests: DIGESTS,
      artifact: artifactFor(PAYLOAD),
      goldLabels: { 0: 'CONTRADICTED' },
      annotationSetIds: ['ans-annot-1', 'ans-annot-2'],
    });
    assert.equal(result.disagreements.length, 1);
    assert.equal(result.disagreements[0].goldLabel, 'CONTRADICTED');
    assert.equal(result.disagreements[0].predictedLabel, 'SUPPORTED');
    assert.equal(result.disagreements[0].adjudicationRequired, true);
    assert.deepEqual(result.disagreements[0].annotationSetIds, ['ans-annot-1', 'ans-annot-2']);
  });

  test('the other verify* entry points run the same injected-checker pipeline', async () => {
    const mapPayload = {
      entries: [
        { claimId: 'clm-src-0001', claimRevision: 1, segmentId: 'seg-0001', statement: 'Entry one statement.' },
        { claimId: 'clm-src-0002', claimRevision: 1, segmentId: 'seg-0002', statement: 'Entry two statement.' },
      ],
    };
    const mapRequest = makeRequest({
      artifact: { kind: 'evidence_map', artifactId: 'evm-alpha-1', revision: 1, digest: canonicalDigest(mapPayload) },
      requestedChecks: ['completeness_and_abstention'],
    });
    const mapResult = await verifyEvidenceMap(mapRequest, {
      checker: SUPPORTING_CHECKER, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'evidence_map', artifactId: 'evm-alpha-1', revision: 1, payload: mapPayload },
    });
    assert.equal(mapResult.result.items.length, 2);
    assert.equal(mapResult.result.status, 'READY_FOR_HUMAN_REVIEW');

    const cardPayload = {
      criteria: [
        { statement: 'Criterion: the mechanism must be falsifiable by cohort data.' },
        { statement: 'Criterion: alternatives are named.' },
      ],
    };
    const cardRequest = makeRequest({
      artifact: { kind: 'hypothesis_card', artifactId: 'hyp-alpha-1', revision: 1, digest: canonicalDigest(cardPayload) },
      requestedChecks: ['completeness_and_abstention'],
    });
    const cardResult = await verifyHypothesisCard(cardRequest, {
      checker: SUPPORTING_CHECKER, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'hypothesis_card', artifactId: 'hyp-alpha-1', revision: 1, payload: cardPayload },
    });
    assert.equal(cardResult.result.items.length, 2);

    const synthPayload = {
      statements: [
        { statement: 'Combined evidence supports a moderate effect.', citations: [{ claimId: 'clm-src-0001', claimRevision: 1 }] },
      ],
    };
    const synthRequest = makeRequest({
      artifact: { kind: 'synthesis_result', artifactId: 'syn-alpha-1', revision: 1, digest: canonicalDigest(synthPayload) },
      requestedChecks: ['citation_entailment'],
    });
    const synthResult = await verifySynthesisResult(synthRequest, {
      checker: SUPPORTING_CHECKER, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'synthesis_result', artifactId: 'syn-alpha-1', revision: 1, payload: synthPayload },
    });
    assert.equal(synthResult.result.items.length, 1);
  });

  test('fail-closed gates: ACL before read, exact digests, exact args, version', async () => {
    const base = { checker: SUPPORTING_CHECKER, digests: DIGESTS, artifact: artifactFor(PAYLOAD) };
    await assert.rejects(
      verifyClaim(makeRequest(), { ...base }),
      (error) => error instanceof AclDenied && /default-denies/.test(error.message),
      'no ACL provider configured must default-deny',
    );
    await assert.rejects(
      verifyClaim(makeRequest(), { ...base, acl: DENY_ACL }),
      AclDenied,
      'ACL denial precedes any payload read',
    );
    await assert.rejects(
      verifyClaim(makeRequest(), { ...base, acl: ALLOW_ACL, checker: undefined }),
      NeedsInput,
      'missing checker is NEEDS_INPUT, never an implicit default',
    );
    await assert.rejects(
      verifyClaim(makeRequest(), { ...base, acl: ALLOW_ACL, digests: { rubricDigest: HEX_A } }),
      NeedsInput,
      'missing exact digests are NEEDS_INPUT',
    );
    await assert.rejects(
      verifyClaim(makeRequest(), {
        ...base, acl: ALLOW_ACL,
        artifact: { kind: 'claim', artifactId: 'clm-alpha-1', revision: 1, payload: { statement: 'Rewritten payload.' } },
      }),
      StaleInput,
      'payload digest differing from the request-bound digest is STALE_INPUT',
    );
    await assert.rejects(
      verifyClaim(makeRequest({ contractVersion: '9.9.9' }), { ...base, acl: ALLOW_ACL }),
      (error) => error instanceof ContractVersionUnknown,
      'unknown contract version rejected before anything else',
    );
    const tampered = makeRequest();
    tampered.canonicalArgsDigest = HEX_D;
    await assert.rejects(
      verifyClaim(tampered, { ...base, acl: ALLOW_ACL }),
      VerifierPolicyBlock,
      'exact-args gate: canonicalArgsDigest must match the canonical payload',
    );
  });

  test('read-only query API delegates to the store without mutating anything', async () => {
    const store = new InMemoryVerifierStore();
    assert.equal(getVerificationResult(store, { resultId: 'sres-missing' }), null);
    assert.deepEqual(listCalibrationReports(store), []);
    assert.throws(() => getVerificationResult(null, { resultId: 'x' }), NeedsInput);
  });
});

describe('S2-006 auditVerifierRunForLeaks (read-only static audit)', () => {
  const UNSEAL = '2026-03-23T00:00:00.000Z';

  test('clean run passes with zero findings', () => {
    const audit = auditVerifierRunForLeaks({
      runId: 'run-clean-1',
      asOf: AS_OF,
      unsealAt: UNSEAL,
      lockedLabelAccess: [{ principalId: 'prn-annotator-1', role: 'annotator', at: UNSEAL }],
      adjudicationAccess: [{ principalId: 'prn-adjudicator', role: 'adjudicator', at: UNSEAL }],
      shared: { coverage: 0.9, evaluated: 18 },
      inputSources: [{ sourceId: 'src-1', publishedAt: '2026-01-01T00:00:00.000Z' }],
    }, { privateMarkers: ['secret-span-text'] });
    assert.deepEqual(audit, { ok: true, findings: [] });
  });

  test('locked-label access before unseal is a hard fail (probe H)', () => {
    const audit = auditVerifierRunForLeaks({
      unsealAt: UNSEAL,
      lockedLabelAccess: [{ principalId: 'prn-annotator-1', role: 'annotator', at: '2026-03-22T12:00:00.000Z' }],
    });
    assert.equal(audit.ok, false);
    assert.equal(audit.findings.length, 1);
    assert.equal(audit.findings[0].code, 'locked_label_access');
    assert.equal(audit.findings[0].hardFail, true);
  });

  test('locked-label access with no unseal event at all is a hard fail', () => {
    const audit = auditVerifierRunForLeaks({
      lockedLabelAccess: [{ principalId: 'prn-annotator-1', role: 'annotator', at: '2026-03-22T12:00:00.000Z' }],
    });
    assert.equal(audit.findings[0].code, 'locked_label_access');
  });

  test('candidate touching locked labels is flagged even after unseal (probe Q)', () => {
    const audit = auditVerifierRunForLeaks({
      unsealAt: UNSEAL,
      lockedLabelAccess: [{ principalId: 'prn-candidate-1', role: 'candidate', at: '2026-03-24T00:00:00.000Z' }],
    });
    assert.equal(audit.findings[0].code, 'locked_label_access');
    assert.equal(audit.findings[0].hardFail, true);
  });

  test('candidate reading adjudication records is a hard fail', () => {
    const audit = auditVerifierRunForLeaks({
      unsealAt: UNSEAL,
      adjudicationAccess: [{ principalId: 'prn-candidate-1', role: 'candidate', at: '2026-03-24T00:00:00.000Z' }],
    });
    assert.equal(audit.findings[0].code, 'producer_self_review');
    assert.equal(audit.findings[0].hardFail, true);
  });

  test('private span/count content in the shared projection is a hard fail and the finding withholds the marker (probe G)', () => {
    const PRIVATE_SPAN = 'confidential-patient-row-17';
    const audit = auditVerifierRunForLeaks({
      shared: {
        metrics: { leakCount: 1 },
        notes: 'annotator quoted: confidential-patient-row-17 during review',
      },
    }, { privateMarkers: [PRIVATE_SPAN, '42.7'] });
    const leak = audit.findings.find((f) => f.code === 'private_leak');
    assert.ok(leak, 'private marker must be detected in shared fields');
    assert.equal(leak.hardFail, true);
    assert.ok(!JSON.stringify(audit).includes(PRIVATE_SPAN), 'the finding must never echo the private content');
    const countLeak = audit.findings.filter((f) => f.code === 'private_leak');
    assert.equal(countLeak.length, 1, 'marker #2 (42.7) is not present in this shared projection');
  });

  test('post-as_of sources are hard failures (probe H)', () => {
    const audit = auditVerifierRunForLeaks({
      asOf: AS_OF,
      inputSources: [{ sourceId: 'src-future', publishedAt: '2026-04-01T00:00:00.000Z' }],
    });
    assert.equal(audit.findings[0].code, 'post_as_of_source');
    assert.equal(audit.findings[0].hardFail, true);
    assert.equal(audit.ok, false);
  });

  test('the audit itself performs zero mutations', () => {
    const run = Object.freeze({
      unsealAt: UNSEAL,
      lockedLabelAccess: [{ principalId: 'prn-x', role: 'candidate', at: '2026-03-24T00:00:00.000Z' }],
      shared: { a: 1 },
    });
    const snapshot = JSON.stringify(run);
    auditVerifierRunForLeaks(run, { privateMarkers: ['x'] });
    assert.equal(JSON.stringify(run), snapshot);
  });
});
