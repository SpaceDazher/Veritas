// S2-006 wave 2B + review fix2-E: fail-closed comparator over two pre-sealed
// prediction sets (Run A / Run B, spec §9). Signature verification goes
// through ONE custody-aware core — signature.verifyDetailed — with a key
// REGISTRY (keyRef -> {secret, custodian, role}) built from the real fixture
// custody material (tests/verifier/fixtures/keys.json): a keyRef belongs to
// exactly one annotator principal, and a valid MAC under a foreign/unknown
// key is rejected. The retired single shared-secret parameter
// (annotationHmacKey) survives only as a @deprecated fixture-mode shim for
// legacy callers and fails closed on any keyRef observed under more than one
// annotator — the exact forgery the old interface accepted.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHmac } from 'node:crypto';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { evaluateScenario } from '../../src/lib/verifier/rubric.mjs';
import {
  compareRuns, annotationSetBindingDigest, labelEntryDigest, caseLabelsDigest,
  adjudicationAttestationDigest,
} from '../../src/lib/verifier/comparator.mjs';
import { registerKey, sign } from '../../src/lib/verifier/signature.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CORPUS = path.join(ROOT, 'corpus', 's2-006');
const FIXTURES = path.join(ROOT, 'tests', 'verifier', 'fixtures');
// The DEPRECATED shared fixture secret (legacy callers only — see fix2-E).
const DEPRECATED_SHARED_HMAC_KEY = 's2-006-fixture-hmac-key';

function loadFixtureKeys() {
  const registry = new Map();
  const fixtures = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'keys.json'), 'utf8'));
  for (const key of fixtures.keys) registerKey({ ...key, registry });
  return { registry, fixtures };
}

function loadCorpus() {
  const manifestBytes = fs.readFileSync(path.join(CORPUS, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  const rubricBytes = fs.readFileSync(path.join(CORPUS, 'rubric-v1.json'));
  const cases = manifest.cases.map((entry) => {
    const bytes = fs.readFileSync(path.join(CORPUS, 'cases', `${entry.caseId}.json`));
    const file = JSON.parse(bytes);
    const split = manifest.splitAssignments.find((a) => a.caseId === entry.caseId).split;
    return { caseId: entry.caseId, bytes, record: file.case, scenario: file.scenario, split };
  });
  const labelSets = {};
  for (const annotator of ['a', 'b']) {
    for (const set of JSON.parse(fs.readFileSync(path.join(CORPUS, 'labels', `annotator-${annotator}.json`), 'utf8'))) {
      labelSets[set.annotationSetId] = set;
    }
  }
  const adjudications = JSON.parse(fs.readFileSync(path.join(CORPUS, 'adjudication.json'), 'utf8'));
  const thresholdsDigest = canonicalDigest(JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts', 's2-006-thresholds.json'), 'utf8')));
  return { manifest, manifestBytes, rubricBytes, cases, labelSets, adjudications, thresholdsDigest };
}

function rubricPredictions(cases) {
  const predictions = {};
  for (const c of cases) {
    const r = evaluateScenario(c.scenario);
    predictions[c.caseId] = { verdict: r.verdict, reasonCodes: r.reasonCodes };
  }
  return predictions;
}

let nonceCounter = 0;
function runMeta(overrides = {}) {
  nonceCounter += 1;
  return {
    runId: `run-s2006-${nonceCounter}`,
    executorId: `exec-${nonceCounter}`,
    pid: 4000 + nonceCounter,
    nonce: `nonce-${nonceCounter}`,
    outputRoot: `D:/Project/AgentOS/.codex-work/verifier-out/run-${nonceCounter}`,
    implementationDigest: canonicalDigest({ module: 'rubric', version: '1.0.0' }),
    hardCounters: {
      unauthorizedLeakageEvents: 0, lockedLabelAccessEvents: 0,
      producerSelfReviewEvents: 0, upstreamArtifactMutationEvents: 0,
      unauthorizedSideEffectEvents: 0,
    },
    ...overrides,
  };
}

// Custody-valid adjudications for the registry path: the fixture corpus's
// opaque attestationDigest values predate the unified core, so the registry
// path re-attests the frozen records with the adjudicator's custody key
// (form: contracts/adjudication-record.schema.json adjudicatorIdentity).
function withSignedAdjudications(corpus, registry, { principalId = 'prn-adjudicator-1', keyRef = 'kms://test/s2-006/adjudicator-1' } = {}) {
  const adjudications = corpus.adjudications.map((rec) => ({
    ...rec,
    adjudicatorIdentity: sign(principalId, keyRef, adjudicationAttestationDigest(rec), { registry, form: 'adjudicator-identity' }),
  }));
  return { ...corpus, adjudications };
}

// Crafts a contract-shaped annotation-set envelope with an EXPLICITLY
// supplied secret and keyRef — the exact MAC construction of the shared
// signature core but WITHOUT its custody enforcement. This is what an
// attacker holding a leaked (or shared) key material can produce.
function forgeAnnotationSignature(set, { secret, keyRef, attestedBy }) {
  const binding = annotationSetBindingDigest(set);
  const digest = createHmac('sha256', secret)
    .update(['hmac-sha256', attestedBy, keyRef, binding].join('\u0000'), 'utf8')
    .digest('hex');
  return { scheme: 'hmac-sha256', keyRef, digest, verified: true, attestedBy };
}

const KEY_A = 'kms://fixture/s2-006/annotator/prn-annotator-a';
const KEY_B = 'kms://fixture/s2-006/annotator/prn-annotator-b';

describe('S2-006 comparator: green path over per-annotator custody keys (fix2-E)', () => {
  const { registry } = loadFixtureKeys();

  test('the custody registry binds each keyRef to exactly one annotator principal', () => {
    const a = registry.get(KEY_A);
    const b = registry.get(KEY_B);
    assert.ok(a && b, 'both frozen-corpus annotator keyRefs are registered');
    assert.equal(a.custodian, 'prn-annotator-a');
    assert.equal(b.custodian, 'prn-annotator-b');
    assert.notEqual(a.custodian, b.custodian, 'custody is per-principal, never shared');
    // the standalone test-namespace custody keys are FULLY distinct key material
    const testA = registry.get('kms://test/s2-006/annotator-a');
    const testB = registry.get('kms://test/s2-006/annotator-b');
    assert.notEqual(testA.secret, testB.secret, 'annotators can hold different secrets');
    assert.notEqual(testA.custodian, testB.custodian);
  });

  test('two process-separated runs of the deterministic candidate match (frozen corpus, real registry)', () => {
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus,
      signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, true, JSON.stringify(report.failures, null, 1));
    assert.deepEqual(report.failures, []);
  });

  test('the frozen corpus label signatures verify without re-signing (keyRefs match custody)', () => {
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.ok(report.failures.every((f) => f.code !== 'signature_rejected' && f.code !== 'signature_unverifiable'),
      JSON.stringify(report.failures));
  });

  test('the consensus gold covers all 45 cases with the three adjudicated disagreements', () => {
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(Object.keys(report.checks.consensusGold).length, 45);
    assert.equal(corpus.adjudications.length, 3);
    for (const rec of corpus.adjudications) {
      assert.equal(report.checks.consensusGold[rec.caseId], rec.decision);
    }
  });

  test('an explicit registry takes precedence over the deprecated shared-key parameter', () => {
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      annotationHmacKey: 'not-the-real-shared-key-at-all',
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, true, JSON.stringify(report.failures, null, 1));
  });

  test('the deprecated shared-secret path still verifies the frozen fixture corpus (legacy callers)', () => {
    const corpus = loadCorpus();
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, annotationHmacKey: DEPRECATED_SHARED_HMAC_KEY,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, true, JSON.stringify(report.failures, null, 1));
  });
});

describe('S2-006 comparator: principals are data, never code (review P1-4b)', () => {
  // Relabels the whole fixture corpus under RENAMED annotator principal ids:
  // entry annotators, label digest bindings, set-level annotatorId, freshly
  // signed contract envelopes and recomputed manifest label digests. Each
  // relabeled annotator gets its OWN custody key (different secret, matching
  // custodian). If the comparator still passes, no hardcoded principal id or
  // shared-secret assumption remains on its path.
  function relabelCorpus(corpus, rename) {
    const registry = relabelRegistry();
    const renameId = (id) => rename[id] ?? id;
    const labelSets = {};
    for (const set of Object.values(corpus.labelSets)) {
      const s = JSON.parse(JSON.stringify(set));
      s.annotatorId = renameId(s.annotatorId);
      for (const l of s.labels) {
        l.annotatorId = renameId(l.annotatorId);
        l.labelDigest = labelEntryDigest({ annotationSetId: s.annotationSetId, annotatorId: l.annotatorId, caseId: l.caseId, label: l.label, labeledAt: l.labeledAt });
      }
      s.signature = sign(s.annotatorId, `kms://test/relabel/${s.annotatorId}`, annotationSetBindingDigest(s), { registry });
      labelSets[s.annotationSetId] = s;
    }
    const adjudications = corpus.adjudications.map((rec) => ({
      ...rec,
      adjudicatorIdentity: sign('prn-adjudicator-1', 'kms://test/relabel/adjudicator', adjudicationAttestationDigest(rec), { registry, form: 'adjudicator-identity' }),
    }));
    const manifest = JSON.parse(JSON.stringify(corpus.manifest));
    for (const entry of manifest.cases) {
      const entries = Object.values(labelSets)
        .flatMap((s) => s.labels.filter((l) => l.caseId === entry.caseId))
        .sort((a, b) => a.annotatorId.localeCompare(b.annotatorId));
      entry.labelsSha256 = caseLabelsDigest(entry.caseId, entries);
    }
    return { ...corpus, manifest, labelSets, adjudications, registry };
  }

  test('a fully relabeled corpus (different principal ids, per-annotator keys) compares green', () => {
    const { registry, ...corpus } = relabelCorpus(loadCorpus(), {
      'prn-annotator-a': 'prn-reviewer-x',
      'prn-annotator-b': 'prn-reviewer-y',
    });
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus,
      signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, true, JSON.stringify(report.failures, null, 1));
    assert.equal(Object.keys(report.checks.consensusGold).length, 45);
  });

  test('expectedAnnotators pins the required annotator pair and fails closed on a mismatch', () => {
    const { registry, ...corpus } = relabelCorpus(loadCorpus(), {
      'prn-annotator-a': 'prn-reviewer-x',
      'prn-annotator-b': 'prn-reviewer-y',
    });
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, expectedAnnotators: ['prn-reviewer-x', 'prn-reviewer-z'], signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'annotator_set_mismatch'));
  });

  test('a single annotator set is not independent labeling: fail closed', () => {
    const corpus = withSignedAdjudications(loadCorpus(), loadFixtureKeys().registry);
    const single = {};
    for (const [id, set] of Object.entries(corpus.labelSets)) {
      if (set.annotatorId === 'prn-annotator-a') single[id] = set;
    }
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, labelSets: single, signatureKeyRegistry: loadFixtureKeys().registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'incomplete_case_set' && f.detail.includes('two distinct annotators')));
  });
});

function relabelRegistry() {
  const registry = new Map();
  registerKey({ keyRef: 'kms://test/relabel/prn-reviewer-x', custodian: 'prn-reviewer-x', role: 'annotator', secret: 's2-006-relabel-custody-reviewer-x-key', registry });
  registerKey({ keyRef: 'kms://test/relabel/prn-reviewer-y', custodian: 'prn-reviewer-y', role: 'annotator', secret: 's2-006-relabel-custody-reviewer-y-key', registry });
  registerKey({ keyRef: 'kms://test/relabel/adjudicator', custodian: 'prn-adjudicator-1', role: 'adjudicator', secret: 's2-006-relabel-custody-adjudicator-key', registry });
  return registry;
}

describe('S2-006 comparator: custody-aware signature core (finding 6, fix2-E)', () => {
  test('P1 regression: a valid MAC under annotator-a\'s key attesting annotator-b\'s set is REJECTED', () => {
    // Production forgery: annotator-b's set is signed with annotator-a's
    // key material (leaked or shared). The MAC is cryptographically valid;
    // the old comparator accepted it because it checked only
    // attestedBy === annotatorId and recomputed the MAC over ONE secret.
    // The custody-aware core must reject it: KEY_A is in custody of
    // prn-annotator-a, never prn-annotator-b.
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const victimId = Object.keys(corpus.labelSets).find((id) => corpus.labelSets[id].annotatorId === 'prn-annotator-b');
    const labelSets = {
      ...corpus.labelSets,
      [victimId]: {
        ...corpus.labelSets[victimId],
        signature: forgeAnnotationSignature(corpus.labelSets[victimId], {
          secret: registry.get(KEY_A).secret,
          keyRef: KEY_A,
          attestedBy: 'prn-annotator-b',
        }),
      },
    };
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, labelSets, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    const rejection = report.failures.find((f) => f.code === 'signature_rejected');
    assert.ok(rejection, JSON.stringify(report.failures));
    assert.ok(rejection.detail.includes(victimId), 'the forged set is named');
    assert.ok(rejection.detail.includes('custodian_mismatch'), 'the rejection reason is a custody mismatch');
  });

  test('P1 regression: the shared-secret path fails closed when one keyRef appears under two annotators', () => {
    // Same forgery under the DEPRECATED shared-secret parameter: the keyRef
    // of annotator-a is used to attest annotator-b's set with a valid MAC
    // over the shared fixture key. One custody key serving two principals is
    // refused regardless of MAC validity.
    const corpus = loadCorpus();
    const victimId = Object.keys(corpus.labelSets).find((id) => corpus.labelSets[id].annotatorId === 'prn-annotator-b');
    const labelSets = {
      ...corpus.labelSets,
      [victimId]: {
        ...corpus.labelSets[victimId],
        signature: forgeAnnotationSignature(corpus.labelSets[victimId], {
          secret: DEPRECATED_SHARED_HMAC_KEY,
          keyRef: KEY_A,
          attestedBy: 'prn-annotator-b',
        }),
      },
    };
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, labelSets, annotationHmacKey: DEPRECATED_SHARED_HMAC_KEY,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    const rejection = report.failures.find((f) => f.code === 'signature_rejected');
    assert.ok(rejection, JSON.stringify(report.failures));
    assert.ok(rejection.detail.includes('more than one annotator'));
  });

  test('an unknown keyRef is rejected even with a valid MAC (fail-closed custody lookup)', () => {
    // Registry WITHOUT annotator-b's keys: the MAC of b's frozen signature
    // would verify under the right secret, but the keyRef has no custody
    // entry — the unified core must refuse before any MAC check.
    const full = loadFixtureKeys().registry;
    const registry = new Map([...full].filter(([keyRef]) => keyRef !== KEY_B && keyRef !== 'kms://test/s2-006/annotator-b'));
    const corpus = withSignedAdjudications(loadCorpus(), full);
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    const rejection = report.failures.find((f) => f.code === 'signature_rejected');
    assert.ok(rejection, JSON.stringify(report.failures));
    assert.ok(rejection.detail.includes('unknown_key_ref'));
  });

  test('a tampered label fails the constant-time MAC check over the exact binding digest', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const sets = { ...corpus.labelSets };
    const victimId = Object.keys(sets).find((id) => sets[id].labels.some((l) => l.label !== 'SUPPORTED'));
    const victim = sets[victimId];
    sets[victimId] = {
      ...victim,
      labels: victim.labels.map((l) => (l.label !== 'SUPPORTED' && l.caseId === victim.labels.find((x) => x.label !== 'SUPPORTED').caseId
        ? { ...l, label: 'SUPPORTED' }
        : l)),
    };
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, labelSets: sets, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    const rejection = report.failures.find((f) => f.code === 'signature_rejected');
    assert.ok(rejection, JSON.stringify(report.failures));
    assert.ok(rejection.detail.includes('mac_forged'), 'rejection flows through signature.verifyDetailed');
  });

  test('an envelope with verified:false is rejected by the unified core (unverified_attestation)', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const victimId = Object.keys(corpus.labelSets).find((id) => corpus.labelSets[id].annotatorId === 'prn-annotator-a');
    const labelSets = {
      ...corpus.labelSets,
      [victimId]: { ...corpus.labelSets[victimId], signature: { ...corpus.labelSets[victimId].signature, verified: false } },
    };
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, labelSets, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    const rejection = report.failures.find((f) => f.code === 'signature_rejected');
    assert.ok(rejection, JSON.stringify(report.failures));
    assert.ok(rejection.detail.includes('unverified_attestation'));
  });

  test('a non-contract envelope shape stays signature_unverifiable', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const victimId = Object.keys(corpus.labelSets).find((id) => corpus.labelSets[id].annotatorId === 'prn-annotator-a');
    const labelSets = {
      ...corpus.labelSets,
      [victimId]: { ...corpus.labelSets[victimId], signature: { scheme: 'hmac-sha256', keyRef: KEY_A, digest: 'a'.repeat(64), verified: true, attestedBy: 'prn-annotator-a', extra: 1 } },
    };
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, labelSets, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'signature_unverifiable'));
  });

  test('no custody material at all fails closed (signature_key_unavailable)', () => {
    const corpus = loadCorpus();
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'signature_key_unavailable'));
  });

  test('a non-Map registry is a typed misuse, not a silent skip', () => {
    const corpus = loadCorpus();
    const predictions = rubricPredictions(corpus.cases);
    assert.throws(() => compareRuns({
      ...corpus, signatureKeyRegistry: { KEY_A: { secret: 'x' } },
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    }), /Map/);
  });
});

describe('S2-006 comparator: adjudicator identity is custody-verified (finding 6, fix2-E)', () => {
  test('the frozen opaque adjudication attestations do NOT pass the registry path', () => {
    const { registry } = loadFixtureKeys();
    const corpus = loadCorpus();
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    const rejection = report.failures.find((f) => f.code === 'signature_rejected');
    assert.ok(rejection, JSON.stringify(report.failures));
    assert.ok(rejection.detail.includes('mac_forged'), 'the opaque fixture digest is not a MAC over the attested content');
  });

  test('custody-signed adjudications verify through the same unified core', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, true, JSON.stringify(report.failures, null, 1));
  });

  test('a tampered adjudication breaks its attestation binding', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const adjudications = corpus.adjudications.map((rec, i) => (i === 0 ? { ...rec, rationale: `${rec.rationale} (tampered)` } : rec));
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, adjudications, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    const rejection = report.failures.find((f) => f.code === 'signature_rejected');
    assert.ok(rejection, JSON.stringify(report.failures));
    assert.ok(rejection.detail.includes('mac_forged'));
  });

  test('an adjudicator who is one of the annotators of record fails closed (self-review)', () => {
    const corpus = loadCorpus();
    const adjudications = corpus.adjudications.map((rec, i) => (i === 0
      ? { ...rec, adjudicatorIdentity: { principalId: 'prn-annotator-a', role: 'adjudicator', authenticated: true, attestationDigest: 'b'.repeat(64) } }
      : rec));
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, adjudications, annotationHmacKey: DEPRECATED_SHARED_HMAC_KEY,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'annotator_set_mismatch' && f.detail.includes('prn-annotator-a')));
  });

  test('an unauthenticated adjudicator identity is signature_unverifiable', () => {
    const corpus = loadCorpus();
    const adjudications = corpus.adjudications.map((rec, i) => (i === 0
      ? { ...rec, adjudicatorIdentity: { ...rec.adjudicatorIdentity, authenticated: false } }
      : rec));
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, adjudications, annotationHmacKey: DEPRECATED_SHARED_HMAC_KEY,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'signature_unverifiable'));
  });
});

describe('S2-006 comparator: fail-closed paths', () => {
  test('an incomplete sealed set fails even when both runs are identically incomplete', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const predictions = rubricPredictions(corpus.cases);
    delete predictions['case-s2006-45'];
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'incomplete_case_set' && f.detail.includes('case-s2006-45')));
  });

  test('a tampered case file breaks the manifest byte binding', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const victim = corpus.cases[0];
    const tampered = { ...victim, bytes: Buffer.from(`${victim.bytes.toString('utf8')}<!-- tampered -->\n`) };
    const report = compareRuns({
      ...corpus, cases: [tampered, ...corpus.cases.slice(1)],
      signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
      runB: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'digest_mismatch' && f.detail.includes(victim.caseId)));
  });

  test('a tampered manifest breaks the adjudication manifest binding', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const report = compareRuns({
      ...corpus, manifestBytes: Buffer.from(`${corpus.manifestBytes.toString('utf8')}{"drift":true}\n`),
      signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
      runB: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'digest_mismatch' && f.detail.includes('annotation manifest')));
  });

  test('probe L: two identically broken runs (100% ERROR) fail closed, never match', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const broken = Object.fromEntries(corpus.cases.map((c) => [c.caseId, { verdict: 'ERROR', reasonCodes: [] }]));
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions: broken },
      runB: { ...runMeta(), predictions: broken },
    });
    assert.equal(report.ok, false);
    const degenerate = report.failures.filter((f) => f.code === 'degenerate_run');
    assert.equal(degenerate.length, 2, 'both identically broken runs must be flagged');
    assert.deepEqual(report.failures, degenerate, 'no other failure class fires');
  });

  test('probe L: a uniform single-verdict prediction set is degenerate on its own', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const abstainAll = Object.fromEntries(corpus.cases.map((c) => [c.caseId, { verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['missing_citation'] }]));
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions: abstainAll },
      runB: { ...runMeta(), predictions: abstainAll },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.every((f) => f.code === 'degenerate_run'));
  });

  test('run divergence under the exact rule fails the comparison', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const a = rubricPredictions(corpus.cases);
    const b = { ...a, 'case-s2006-23': { verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['topic_overlap'] } };
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions: a },
      runB: { ...runMeta(), predictions: b },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'run_divergence'));
  });

  test('identical run-manifest digests are a collision, not two runs', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const predictions = rubricPredictions(corpus.cases);
    const meta = runMeta();
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...meta, predictions },
      runB: { ...meta, predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'run_manifest_collision'));
  });

  test('hard violation counters in a run manifest fail the comparison', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta({ hardCounters: { ...runMeta().hardCounters, lockedLabelAccessEvents: 1 } }), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'hard_violations' && f.detail.includes('runA')));
  });

  test('extra predictions for unknown cases fail the composition check', () => {
    const { registry } = loadFixtureKeys();
    const corpus = withSignedAdjudications(loadCorpus(), registry);
    const predictions = rubricPredictions(corpus.cases);
    predictions['case-unknown-999'] = { verdict: 'SUPPORTED', reasonCodes: [] };
    const report = compareRuns({
      ...corpus, signatureKeyRegistry: registry,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'incomplete_case_set' && f.detail.includes('case-unknown-999')));
  });
});
