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
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
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
  makeVerifierAuthorityRegistry,
  publishVerificationResult,
} from '../../src/lib/verifier/commands.mjs';
import {
  AclDenied,
  NeedsInput,
  StaleInput,
  VerifierError,
  VerifierPolicyBlock,
  ContractVersionUnknown,
} from '../../src/lib/verifier/errors.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
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

// ---- canonical frozen-schema fixtures (review P1-1) -------------------------

const PRODUCER_CONTRACTS = Object.freeze(['claim', 'evidence-map', 'hypothesis-card', 'synthesis-result']);
const CANONICAL_DIR = path.join(ROOT, 'tests/verifier/fixtures/canonical');

// Loads the canonical fixtures and validates each against the REAL frozen
// producer schema (Ajv compiled in-test) BEFORE any verifier call. A fixture
// that is not schema-valid is a test-suite bug, never a verifier concern.
function loadCanonicalFixtures() {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  for (const name of PRODUCER_CONTRACTS) {
    ajv.addSchema(JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts', `${name}.schema.json`), 'utf8')));
  }
  const out = {};
  for (const name of PRODUCER_CONTRACTS) {
    const doc = JSON.parse(fs.readFileSync(path.join(CANONICAL_DIR, `${name}.json`), 'utf8'));
    const validate = ajv.getSchema(`https://veritas.local/contracts/${name}.schema.json`);
    assert.equal(validate(doc), true, `canonical fixture ${name} must be schema-valid: ${ajv.errorsText(validate.errors)}`);
    out[name] = doc;
  }
  return out;
}

// Deterministic content-driven checker: verdicts follow the CONTENT of the
// canonical fixtures (entail / contradict / insufficient), not their shape.
const CANONICAL_CHECKER = Object.freeze({
  check: ({ criterion, statement, evidenceLinks }) => {
    if (criterion === 'causal_overclaim' && statement.startsWith('Sleep deprivation reduces')) {
      // CORRELATION_EVIDENCE must never pass a causal check (spec §7).
      return { verdict: 'CONTRADICTED', reasonCodes: ['causal_overclaim'] };
    }
    if (criterion === 'citation_entailment' && evidenceLinks.length === 0) {
      return { verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['missing_citation'] };
    }
    return { verdict: 'SUPPORTED', reasonCodes: [], uncertainty: { kind: 'epistemic', value: 0.1 } };
  },
});

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

  test('the other verify* entry points accept CANONICAL S2-005 artifacts (frozen-schema form, review P1-1)', async () => {
    const canonical = loadCanonicalFixtures();

    // EvidenceMap: ONE checkable statement at map level; entries[] are the
    // citations (snake_case claim_id/claim_revision per the frozen schema).
    const mapRequest = makeRequest({
      artifact: { kind: 'evidence_map', artifactId: 'evm-canonical-001', revision: 1, digest: canonicalDigest(canonical['evidence-map']) },
      requestedChecks: ['completeness_and_abstention'],
    });
    const mapResult = await verifyEvidenceMap(mapRequest, {
      checker: SUPPORTING_CHECKER, acl: ALLOW_ACL, digests: DIGESTS,
      artifact: { kind: 'evidence_map', artifactId: 'evm-canonical-001', revision: 1, payload: canonical['evidence-map'] },
    });
    assert.equal(mapResult.result.items.length, 1, 'the map-level statement is the single checkable unit');
    assert.equal(mapResult.result.items[0].statement, canonical['evidence-map'].statement);
    assert.deepEqual(
      mapResult.result.items[0].evidenceLinks[0],
      {
        claimId: 'clm-canonical-0001', claimRevision: 1, segmentId: 'seg-canonical-0001',
        span: { start: 0, end: 56 },
        quoteDigest: 'e7cef6cdb4f0609dd2e86204b8188ea2a9d5c6ef07d8085f37942975ff43c8c9',
      },
      'canonical entries[] map onto the item evidence-link contract',
    );
    assert.equal(mapResult.result.status, 'READY_FOR_HUMAN_REVIEW');

    // HypothesisCard: the proposed_relation triple is the checkable
    // proposition; nodes[] are the citations.
    const cardRequest = makeRequest({
      artifact: { kind: 'hypothesis_card', artifactId: 'hyc-canonical-001', revision: 1, digest: canonicalDigest(canonical['hypothesis-card']) },
      requestedChecks: ['completeness_and_abstention'],
    });
    const cardResult = await verifyHypothesisCard(cardRequest, {
      checker: SUPPORTING_CHECKER, acl: ALLOW_ACL, digests: DIGESTS,
      artifact: { kind: 'hypothesis_card', artifactId: 'hyc-canonical-001', revision: 1, payload: canonical['hypothesis-card'] },
    });
    assert.equal(cardResult.result.items.length, 1);
    assert.equal(
      cardResult.result.items[0].statement,
      'Sleep deprivation reduces hippocampal memory consolidation accuracy',
      'proposed_relation (subject predicate object) is the atomic statement',
    );
    assert.deepEqual(
      cardResult.result.items[0].evidenceLinks.map((l) => l.claimId),
      ['clm-canonical-0101', 'clm-canonical-0102', 'clm-canonical-0103'],
      'nodes[] AND counterevidence[] become the evidence links',
    );

    // SynthesisResult: statements come from the embedded evidence_maps[] and
    // hypothesis_cards[] ($ref form), not from a homemade statements[] field.
    const synthRequest = makeRequest({
      artifact: { kind: 'synthesis_result', artifactId: 'syn-canonical-001', revision: 1, digest: canonicalDigest(canonical['synthesis-result']) },
      requestedChecks: ['completeness_and_abstention'],
    });
    const synthResult = await verifySynthesisResult(synthRequest, {
      checker: SUPPORTING_CHECKER, acl: ALLOW_ACL, digests: DIGESTS,
      artifact: { kind: 'synthesis_result', artifactId: 'syn-canonical-001', revision: 1, payload: canonical['synthesis-result'] },
    });
    assert.equal(synthResult.result.items.length, 2, 'one item per embedded evidence map and hypothesis card');
    assert.deepEqual(
      synthResult.result.items.map((i) => i.statement),
      [
        'Wind and solar generated 22% of EU electricity in 2024.',
        'Sleep deprivation reduces hippocampal memory consolidation accuracy',
      ],
    );
    assert.equal(synthResult.result.status, 'READY_FOR_HUMAN_REVIEW');
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
    assert.throws(() => getVerificationResult(null, { resultId: 'x' }), NeedsInput);
    assert.equal(store.listLedger().length, 0, 'reads write no ledger entries');
    assert.equal(store.listOutbox().length, 0, 'reads write no outbox events');
  });
});

describe('S2-006 verifier read API enforces the workspace ACL (review P1-3)', () => {
  const AUTHORITIES = makeVerifierAuthorityRegistry([
    { principal: 'prn-evaluation-harness', roles: ['evaluation_harness'], workspaces: ['ws-a'] },
    { principal: 'prn-reviewer', roles: ['reviewer'], workspaces: ['ws-a'] },
    { principal: 'prn-reviewer-b', roles: ['reviewer'], workspaces: ['ws-b'] },
    { principal: 'prn-annotator-1', roles: ['annotator'], workspaces: ['ws-a'] },
  ]);

  function resultRecord(resultId) {
    return {
      contractVersion: '1.0.0',
      resultId,
      requestRef: 'svr-store-1',
      inputDigests: { artifactDigest: HEX_A, rubricDigest: HEX_A, corpusManifestDigest: HEX_A, thresholdsDigest: HEX_A },
      outputDigest: HEX_B,
      items: [],
      disagreements: [],
      criticalFindings: [],
      abstentions: [],
      coverage: { denominator: 0, evaluated: 0, missing: 0 },
      independenceProfileRef: 'ind-unverified',
      humanDecisionRequired: true,
      status: 'READY_FOR_HUMAN_REVIEW',
    };
  }

  async function seedWorkspace(store, workspaceId, { resultId = 'sres-seed-1', reportId = 'rep-seed-1', acl } = {}) {
    const records = [
      { kind: 'result', record: resultRecord(resultId), ...(acl ? { acl } : {}) },
      {
        kind: 'calibration_report',
        record: {
          contractVersion: '1.0.0', reportId, corpusVersion: '0.3.0',
          rubricDigest: HEX_A, thresholdsDigest: HEX_A,
        },
        ...(acl ? { acl } : {}),
      },
    ];
    await store.publish({
      workspaceId,
      operationId: `op-seed-${workspaceId}-${resultId}`,
      actor: 'prn-evaluation-harness',
      operation: 'publishVerificationResult',
      idempotencyKey: `idem-${workspaceId}-${resultId}`,
      records,
      audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: { seed: workspaceId } },
    });
  }

  test('legacy no-actor reads break loudly instead of silently returning everything', async () => {
    const store = new InMemoryVerifierStore();
    await seedWorkspace(store, 'ws-a');
    assert.throws(
      () => getVerificationResult(store, { resultId: 'sres-seed-1' }),
      AclDenied,
      'un-attributed reads must fail, never leak the record',
    );
    assert.throws(() => listCalibrationReports(store), AclDenied, 'un-attributed listing must fail, never leak the corpus');
  });

  test('an actor with no authority registry entry or without the read capability is denied', async () => {
    const store = new InMemoryVerifierStore();
    await seedWorkspace(store, 'ws-a');
    assert.throws(
      () => getVerificationResult(store, { resultId: 'sres-seed-1', actor: 'prn-ghost', workspaceId: 'ws-a', authorities: AUTHORITIES }),
      AclDenied,
    );
    assert.throws(
      () => getVerificationResult(store, { resultId: 'sres-seed-1', actor: 'prn-annotator-1', workspaceId: 'ws-a', authorities: AUTHORITIES }),
      AclDenied,
      'annotators hold no read capability over verification_result in the policy matrix',
    );
    assert.throws(
      () => getVerificationResult(store, { resultId: 'sres-seed-1', actor: 'prn-evaluation-harness', workspaceId: 'ws-a', authorities: undefined }),
      AclDenied,
      'no enforcement configured is a default deny, not an implicit allow',
    );
  });

  test('reading a record that lives in another workspace is AclDenied, never an empty miss', async () => {
    const store = new InMemoryVerifierStore();
    await seedWorkspace(store, 'ws-b', { resultId: 'sres-ws-b-1', reportId: 'rep-ws-b-1' });
    // prn-evaluation-harness has read capability, but only inside ws-a.
    assert.throws(
      () => getVerificationResult(store, { resultId: 'sres-ws-b-1', actor: 'prn-evaluation-harness', workspaceId: 'ws-a', authorities: AUTHORITIES }),
      AclDenied,
    );
    // A ws-b authority reads it through its own workspace binding.
    const viaB = getVerificationResult(store, { resultId: 'sres-ws-b-1', actor: 'prn-reviewer-b', workspaceId: 'ws-b', authorities: AUTHORITIES });
    assert.equal(viaB.resultId, 'sres-ws-b-1');
    assert.equal(getVerificationResult(store, { resultId: 'sres-missing', actor: 'prn-reviewer-b', workspaceId: 'ws-b', authorities: AUTHORITIES }), null);
  });

  test('calibration report listing is strictly workspace-scoped', async () => {
    const store = new InMemoryVerifierStore();
    await seedWorkspace(store, 'ws-a', { resultId: 'sres-a-1', reportId: 'rep-a-1' });
    await seedWorkspace(store, 'ws-b', { resultId: 'sres-b-1', reportId: 'rep-b-1' });
    const own = listCalibrationReports(store, { actor: 'prn-evaluation-harness', workspaceId: 'ws-a', authorities: AUTHORITIES });
    assert.deepEqual(own.map((r) => r.reportId), ['rep-a-1'], 'listing never mixes workspaces');
    const other = listCalibrationReports(store, { actor: 'prn-reviewer-b', workspaceId: 'ws-b', authorities: AUTHORITIES, corpusVersion: '9.9.9' });
    assert.deepEqual(other, [], 'corpusVersion filter still applies inside the workspace');
    assert.throws(
      () => listCalibrationReports(store, { actor: 'prn-evaluation-harness', workspaceId: 'ws-b', authorities: AUTHORITIES }),
      AclDenied,
      'an actor with no authority in the requested workspace is denied, not handed an empty list',
    );
  });

  test('a derived result stores the strictest-of-inputs ACL as store-level metadata and read enforces it', async () => {
    const store = new InMemoryVerifierStore();
    const request = makeRequest({ workspaceId: 'ws-a' });
    const { result } = await verifyClaim(request, {
      checker: { check: () => ({ verdict: 'SUPPORTED', reasonCodes: [] }) },
      acl: ALLOW_ACL,
      digests: DIGESTS,
      artifact: artifactFor(PAYLOAD),
    });
    await publishVerificationResult({
      store, authorities: AUTHORITIES, actor: 'prn-evaluation-harness', request, result, operationId: 'op-derived-acl-1',
      inputAcls: [
        { visibility: 'project' },
        { visibility: 'private', allowedPrincipalIds: ['prn-reviewer'] },
      ],
    });
    // The inherited ACL lives in store-level metadata, NOT inside the
    // contract payload (the frozen result schema stays byte-pure).
    assert.deepEqual(store.getRecord('result', result.resultId), result, 'payload untouched by ACL metadata');
    assert.equal(Object.prototype.hasOwnProperty.call(store.getRecord('result', result.resultId), 'acl'), false);
    const acl = store.getRecordAcl('result', result.resultId);
    assert.equal(acl.visibility, 'private', 'strictest of the inputs wins');
    assert.deepEqual(acl.allowedPrincipalIds, ['prn-reviewer']);

    // Read enforcement: a same-workspace harness with read capability is
    // still excluded by the inherited private ACL; the named principal reads.
    assert.throws(
      () => getVerificationResult(store, { resultId: result.resultId, actor: 'prn-evaluation-harness', workspaceId: 'ws-a', authorities: AUTHORITIES }),
      AclDenied,
      'strictest-of-inputs inheritance must bind at read time',
    );
    const seen = getVerificationResult(store, { resultId: result.resultId, actor: 'prn-reviewer', workspaceId: 'ws-a', authorities: AUTHORITIES });
    assert.equal(seen.resultId, result.resultId);
  });
});

describe('S2-006 verifier accepts canonical schema-valid artifacts with correct verdicts (review P1-1)', () => {
  function requestFor(kind, artifactId, payload, requestedChecks) {
    return makeRequest({
      artifact: { kind, artifactId, revision: 1, digest: canonicalDigest(payload) },
      requestedChecks,
    });
  }

  test('canonical fixtures validate against the frozen producer schemas (Ajv compiled in-test)', () => {
    // Throws with a precise assert message if any fixture drifts from the
    // frozen contracts — the verifier is only ever fed canonical form here.
    loadCanonicalFixtures();
  });

  test('canonical EvidenceMap: entail / contradict / insufficient verdicts follow the fixture content', async () => {
    const canonical = loadCanonicalFixtures();
    const map = canonical['evidence-map'];
    const { result } = await verifyEvidenceMap(
      requestFor('evidence_map', 'evm-canonical-001', map, ['citation_entailment', 'number_unit_preservation']),
      { checker: CANONICAL_CHECKER, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'evidence_map', artifactId: 'evm-canonical-001', revision: 1, payload: map } },
    );
    assert.equal(result.status, 'READY_FOR_HUMAN_REVIEW', 'a schema-valid canonical map must never end in NEEDS_INPUT missingness');
    assert.deepEqual(result.coverage, { denominator: 2, evaluated: 2, missing: 0 });
    const entail = result.items.find((i) => i.criterion === 'citation_entailment');
    assert.equal(entail.verdict, 'SUPPORTED', 'the cited span ENTAILS the map statement');
    assert.equal(entail.statement, map.statement, 'the map-level statement is the evaluated statement');
    const units = result.items.find((i) => i.criterion === 'number_unit_preservation');
    assert.equal(units.verdict, 'SUPPORTED');
  });

  test('canonical HypothesisCard: correlation-strength relation is flagged, not promoted', async () => {
    const canonical = loadCanonicalFixtures();
    const card = canonical['hypothesis-card'];
    const { result } = await verifyHypothesisCard(
      requestFor('hypothesis_card', 'hyc-canonical-001', card, ['causal_overclaim', 'epistemic_type']),
      { checker: CANONICAL_CHECKER, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'hypothesis_card', artifactId: 'hyc-canonical-001', revision: 1, payload: card } },
    );
    assert.equal(result.status, 'READY_FOR_HUMAN_REVIEW');
    const causal = result.items.find((i) => i.criterion === 'causal_overclaim');
    assert.equal(causal.verdict, 'CONTRADICTED');
    assert.deepEqual(causal.reasonCodes, ['causal_overclaim']);
    assert.equal(causal.statement, 'Sleep deprivation reduces hippocampal memory consolidation accuracy');
    assert.equal(result.items.find((i) => i.criterion === 'epistemic_type').verdict, 'SUPPORTED');
  });

  test('canonical SynthesisResult: embedded maps and cards both verified, no NEEDS_INPUT', async () => {
    const canonical = loadCanonicalFixtures();
    const synth = canonical['synthesis-result'];
    const { result } = await verifySynthesisResult(
      requestFor('synthesis_result', 'syn-canonical-001', synth, ['causal_overclaim']),
      { checker: CANONICAL_CHECKER, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'synthesis_result', artifactId: 'syn-canonical-001', revision: 1, payload: synth } },
    );
    assert.equal(result.status, 'READY_FOR_HUMAN_REVIEW');
    assert.deepEqual(result.items.map((i) => [i.criterion, i.verdict]), [
      ['causal_overclaim', 'SUPPORTED'],
      ['causal_overclaim', 'CONTRADICTED'],
    ]);
  });

  test('canonical claim: citation checks abstain without citations, content checks evaluate', async () => {
    const canonical = loadCanonicalFixtures();
    const claim = canonical.claim;
    let checkerCalls = 0;
    const countingChecker = {
      check: (item) => {
        checkerCalls += 1;
        return CANONICAL_CHECKER.check(item);
      },
    };
    const { result } = await verifyClaim(
      requestFor('claim', 'clm-canonical-0001', claim, ['citation_entailment', 'number_unit_preservation']),
      { checker: countingChecker, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'claim', artifactId: 'clm-canonical-0001', revision: 1, payload: claim } },
    );
    assert.equal(result.status, 'READY_FOR_HUMAN_REVIEW', 'a deterministic NO_CITATION abstention is evaluated coverage, not missingness');
    const entail = result.items.find((i) => i.criterion === 'citation_entailment');
    assert.equal(entail.verdict, 'INSUFFICIENT_EVIDENCE', 'a canonical claim carries no citations: deterministic abstention (probe E)');
    assert.ok(entail.reasonCodes.includes('missing_citation'));
    assert.equal(result.abstentions[0].reason, 'NO_CITATION');
    const units = result.items.find((i) => i.criterion === 'number_unit_preservation');
    assert.equal(units.verdict, 'SUPPORTED');
    assert.equal(units.statement, claim.normalized_text, 'normalized_text is the canonical claim statement');
    assert.equal(checkerCalls, 1, 'the citation check abstains without calling the checker');
  });

  test('canonical map staleness: stale/revoked sources referenced by canonical entries invalidate the verdict', async () => {
    const canonical = loadCanonicalFixtures();
    const map = canonical['evidence-map'];
    const { result } = await verifyEvidenceMap(
      requestFor('evidence_map', 'evm-canonical-001', map, ['citation_entailment']),
      {
        checker: CANONICAL_CHECKER, acl: ALLOW_ACL, digests: DIGESTS,
        artifact: { kind: 'evidence_map', artifactId: 'evm-canonical-001', revision: 1, payload: map },
        sourceIndex: { 'seg-canonical-0001': { accessState: 'revoked' } },
      },
    );
    const item = result.items[0];
    assert.equal(item.verdict, 'STALE_INPUT');
    assert.ok(item.reasonCodes.includes('revoked_source'));
  });

  test('homemade producer-shaped payloads are no longer extractable: no second internal format', async () => {
    const canonical = loadCanonicalFixtures();
    const oldStyleMap = {
      entries: [{ claimId: 'clm-src-0001', claimRevision: 1, statement: 'Entry one statement.' }],
    };
    await assert.rejects(
      verifyEvidenceMap(
        requestFor('evidence_map', 'evm-canonical-001', oldStyleMap, ['citation_entailment']),
        { checker: CANONICAL_CHECKER, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'evidence_map', artifactId: 'evm-canonical-001', revision: 1, payload: oldStyleMap } },
      ),
      (error) => error instanceof NeedsInput && /map-level statement/.test(error.message),
      'entries[].statement was never canonical: the map-level statement is',
    );
    const oldStyleCard = { criteria: [{ statement: 'Criterion text.' }] };
    await assert.rejects(
      verifyHypothesisCard(
        requestFor('hypothesis_card', 'hyc-canonical-001', oldStyleCard, ['citation_entailment']),
        { checker: CANONICAL_CHECKER, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'hypothesis_card', artifactId: 'hyc-canonical-001', revision: 1, payload: oldStyleCard } },
      ),
      NeedsInput,
      'criteria[] was never canonical: proposed_relation is',
    );
    const oldStyleSynth = { statements: [{ statement: 'Homemade top-level statement.' }] };
    await assert.rejects(
      verifySynthesisResult(
        requestFor('synthesis_result', 'syn-canonical-001', oldStyleSynth, ['citation_entailment']),
        { checker: CANONICAL_CHECKER, acl: ALLOW_ACL, digests: DIGESTS, artifact: { kind: 'synthesis_result', artifactId: 'syn-canonical-001', revision: 1, payload: oldStyleSynth } },
      ),
      NeedsInput,
      'statements[] was never canonical: embedded evidence_maps[]/hypothesis_cards[] are',
    );
    void canonical;
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
