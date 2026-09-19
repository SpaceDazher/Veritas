// S2-006 wave 2B: fail-closed comparator over two pre-sealed prediction sets
// (Run A / Run B, spec §9). Green path on identical complete sets; failure
// paths on incomplete composition, digest mismatch, degenerate distributions
// (the S2-005 ERROR:55 regression signature, including two identically broken
// runs), run divergence, manifest collisions and unavailable signature keys.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { evaluateScenario } from '../../src/lib/verifier/rubric.mjs';
import { compareRuns } from '../../src/lib/verifier/comparator.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CORPUS = path.join(ROOT, 'corpus', 's2-006');
const HMAC_KEY = 's2-006-fixture-hmac-key';

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

describe('S2-006 comparator: green path on two identical complete sealed sets', () => {
  const corpus = loadCorpus();
  const predictions = rubricPredictions(corpus.cases);
  const report = compareRuns({
    ...corpus,
    annotationHmacKey: HMAC_KEY,
    runA: { ...runMeta(), predictions },
    runB: { ...runMeta(), predictions },
  });

  test('two process-separated runs of the deterministic candidate match', () => {
    assert.equal(report.ok, true, JSON.stringify(report.failures, null, 1));
    assert.deepEqual(report.failures, []);
  });

  test('sealed prediction digests are equal; run-manifest digests are distinct', () => {
    assert.equal(report.checks.predictionDigests.runA, report.checks.predictionDigests.runB);
    assert.notEqual(report.checks.runManifestDigests.runA, report.checks.runManifestDigests.runB);
  });

  test('the consensus gold covers all 45 cases with the three adjudicated disagreements', () => {
    assert.equal(Object.keys(report.checks.consensusGold).length, 45);
    assert.equal(corpus.adjudications.length, 3);
    for (const rec of corpus.adjudications) {
      assert.equal(report.checks.consensusGold[rec.caseId], rec.decision);
    }
  });
});

describe('S2-006 comparator: fail-closed paths', () => {
  test('an incomplete sealed set fails even when both runs are identically incomplete', () => {
    const corpus = loadCorpus();
    const predictions = rubricPredictions(corpus.cases);
    delete predictions['case-s2006-45'];
    const report = compareRuns({
      ...corpus, annotationHmacKey: HMAC_KEY,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'incomplete_case_set' && f.detail.includes('case-s2006-45')));
  });

  test('a tampered case file breaks the manifest byte binding', () => {
    const corpus = loadCorpus();
    const victim = corpus.cases[0];
    const tampered = { ...victim, bytes: Buffer.from(`${victim.bytes.toString('utf8')}<!-- tampered -->\n`) };
    const report = compareRuns({
      ...corpus, cases: [tampered, ...corpus.cases.slice(1)],
      annotationHmacKey: HMAC_KEY,
      runA: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
      runB: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'digest_mismatch' && f.detail.includes(victim.caseId)));
  });

  test('a tampered manifest breaks the adjudication manifest binding', () => {
    const corpus = loadCorpus();
    const report = compareRuns({
      ...corpus, manifestBytes: Buffer.from(`${corpus.manifestBytes.toString('utf8')}{"drift":true}\n`),
      annotationHmacKey: HMAC_KEY,
      runA: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
      runB: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'digest_mismatch' && f.detail.includes('annotation manifest')));
  });

  test('a tampered label fails signature verification over the exact digest', () => {
    const corpus = loadCorpus();
    const sets = { ...corpus.labelSets };
    const victimId = Object.keys(sets).find((id) => sets[id].labels.some((l) => l.label !== 'SUPPORTED'));
    const victim = sets[victimId];
    sets[victimId] = {
      ...victim,
      labels: victim.labels.map((l) => (l.label !== 'SUPPORTED' && l.caseId === victim.labels.find((x) => x.label !== 'SUPPORTED').caseId
        ? { ...l, label: 'SUPPORTED' }
        : l)),
    };
    const report = compareRuns({
      ...corpus, labelSets: sets, annotationHmacKey: HMAC_KEY,
      runA: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
      runB: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'signature_invalid' || f.code === 'digest_mismatch'));
  });

  test('probe L: two identically broken runs (100% ERROR) fail closed, never match', () => {
    const corpus = loadCorpus();
    const broken = Object.fromEntries(corpus.cases.map((c) => [c.caseId, { verdict: 'ERROR', reasonCodes: [] }]));
    const report = compareRuns({
      ...corpus, annotationHmacKey: HMAC_KEY,
      runA: { ...runMeta(), predictions: broken },
      runB: { ...runMeta(), predictions: broken },
    });
    assert.equal(report.ok, false);
    const degenerate = report.failures.filter((f) => f.code === 'degenerate_run');
    assert.equal(degenerate.length, 2, 'both identically broken runs must be flagged');
  });

  test('probe L: a uniform single-verdict prediction set is degenerate on its own', () => {
    const corpus = loadCorpus();
    const abstainAll = Object.fromEntries(corpus.cases.map((c) => [c.caseId, { verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['missing_citation'] }]));
    const report = compareRuns({
      ...corpus, annotationHmacKey: HMAC_KEY,
      runA: { ...runMeta(), predictions: abstainAll },
      runB: { ...runMeta(), predictions: abstainAll },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.every((f) => f.code === 'degenerate_run'));
  });

  test('run divergence under the exact rule fails the comparison', () => {
    const corpus = loadCorpus();
    const a = rubricPredictions(corpus.cases);
    const b = { ...a, 'case-s2006-23': { verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['topic_overlap'] } };
    const report = compareRuns({
      ...corpus, annotationHmacKey: HMAC_KEY,
      runA: { ...runMeta(), predictions: a },
      runB: { ...runMeta(), predictions: b },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'run_divergence'));
  });

  test('identical run-manifest digests are a collision, not two runs', () => {
    const corpus = loadCorpus();
    const predictions = rubricPredictions(corpus.cases);
    const meta = runMeta();
    const report = compareRuns({
      ...corpus, annotationHmacKey: HMAC_KEY,
      runA: { ...meta, predictions },
      runB: { ...meta, predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'run_manifest_collision'));
  });

  test('probe Q: an unavailable signature key fails closed — the comparator never trusts the attestation', () => {
    const corpus = loadCorpus();
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, annotationHmacKey: null,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'signature_key_unavailable'));
  });

  test('hard violation counters in a run manifest fail the comparison', () => {
    const corpus = loadCorpus();
    const predictions = rubricPredictions(corpus.cases);
    const report = compareRuns({
      ...corpus, annotationHmacKey: HMAC_KEY,
      runA: { ...runMeta({ hardCounters: { ...runMeta().hardCounters, lockedLabelAccessEvents: 1 } }), predictions },
      runB: { ...runMeta(), predictions },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'hard_violations' && f.detail.includes('runA')));
  });

  test('extra predictions for unknown cases fail the composition check', () => {
    const corpus = loadCorpus();
    const predictions = rubricPredictions(corpus.cases);
    predictions['case-unknown-999'] = { verdict: 'SUPPORTED', reasonCodes: [] };
    const report = compareRuns({
      ...corpus, annotationHmacKey: HMAC_KEY,
      runA: { ...runMeta(), predictions },
      runB: { ...runMeta(), predictions: rubricPredictions(corpus.cases) },
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f) => f.code === 'incomplete_case_set' && f.detail.includes('case-unknown-999')));
  });
});
