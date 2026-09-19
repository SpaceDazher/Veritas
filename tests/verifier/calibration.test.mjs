// S2-006 wave 2B: calibration metrics on the frozen fixture cases (spec §8).
// Raw counts are re-derived with independent reference loops; NOT_MEASURED /
// NOT_APPLICABLE semantics, the coverage gate against abstain-all, and the
// lexicographic decision rule are exercised on test-authored thresholds —
// the in-repo thresholds preregistration stays untouched at NEEDS_INPUT.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateScenario } from '../../src/lib/verifier/rubric.mjs';
import { ruleBaselineEvaluate, producerBaselineEvaluate } from '../../src/lib/verifier/baselines.mjs';
import {
  computeMetrics,
  decideLexicographic,
  pairedBootstrapInterval,
  oneVsRestConfusion,
  wilsonInterval,
} from '../../src/lib/verifier/calibration.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CORPUS = path.join(ROOT, 'corpus', 's2-006');

// ---- frozen gold consensus from the corpus bytes -----------------------------

const manifest = JSON.parse(fs.readFileSync(path.join(CORPUS, 'manifest.json'), 'utf8'));
const cases = manifest.cases.map((entry) => {
  const file = JSON.parse(fs.readFileSync(path.join(CORPUS, 'cases', `${entry.caseId}.json`), 'utf8'));
  const split = manifest.splitAssignments.find((a) => a.caseId === entry.caseId).split;
  return { caseId: entry.caseId, split, scenario: file.scenario };
});
const annotators = { a: {}, b: {} };
for (const annotator of ['a', 'b']) {
  const sets = JSON.parse(fs.readFileSync(path.join(CORPUS, 'labels', `annotator-${annotator}.json`), 'utf8'));
  for (const set of sets) for (const l of set.labels) annotators[annotator][l.caseId] = l.label;
}
const adjudications = JSON.parse(fs.readFileSync(path.join(CORPUS, 'adjudication.json'), 'utf8'));
const gold = {};
for (const c of cases) {
  const disagreement = adjudications.find((r) => r.caseId === c.caseId);
  gold[c.caseId] = disagreement ? disagreement.decision : annotators.a[c.caseId];
}

const metricCases = cases.map((c) => ({ caseId: c.caseId, category: c.scenario.category, stratum: 'fixture' }));
const goldReasons = Object.fromEntries(cases.map((c) => [c.caseId, c.scenario.expected.reasonCodes]));

// ---- prediction sets ----------------------------------------------------------

const rubricPredictions = {};
const rulePredictions = {};
const producerPredictions = {};
for (const c of cases) {
  const r = evaluateScenario(c.scenario);
  rubricPredictions[c.caseId] = { verdict: r.verdict, reasonCodes: r.reasonCodes, missingnessKind: r.missingness.kind };
  const rule = ruleBaselineEvaluate(c.scenario);
  rulePredictions[c.caseId] = { verdict: rule.verdict, reasonCodes: rule.reasonCodes, missingnessKind: 'none' };
  const producer = producerBaselineEvaluate(c.scenario);
  producerPredictions[c.caseId] = { verdict: producer.verdict, reasonCodes: producer.reasonCodes, missingnessKind: 'none' };
}

const metricsFor = (predictions, extra = {}) => computeMetrics({
  cases: metricCases,
  gold,
  goldReasons,
  predictions,
  annotators,
  independence: { independent: false, reason: 'evaluator_not_independent' },
  ...extra,
});

const rubricMetrics = metricsFor(rubricPredictions);
const ruleMetrics = metricsFor(rulePredictions);
const producerMetrics = metricsFor(producerPredictions);

// test-only owner-authored thresholds (the repo preregistration stays null)
const authorThresholds = ({
  floor = 0.4, delta = 0.2, cl = 0.9, tie = 'latency_asc',
  soft, owner = 'a'.repeat(64), costKeys = false,
} = {}) => ({
  status: 'AUTHORED_IN_TEST_ONLY',
  ownerDecisionRef: owner,
  coverage_floor: { value: floor },
  non_inferiority_margin: { delta },
  confidence_level: { value: cl },
  tie_rule: { rule: tie },
  soft_thresholds: soft ?? {
    citation_entailment_f1: { metric: 'citation_entailment_f1', operator: '>=', value: 0.5 },
    stale_invalidation_recall: { metric: 'stale_invalidation_recall', operator: '>=', value: 0.5 },
    false_advisory_acceptance_rate: { metric: 'false_advisory_acceptance_rate', operator: '<=', value: 0.2 },
  },
  ...(costKeys ? { cost: costKeys } : {}),
});

describe('S2-006 raw counts and coverage on the fixture stratum', () => {
  test('denominator, evaluated, missing and abstention counts are exact', () => {
    assert.equal(rubricMetrics.coverage.denominator, 45);
    assert.equal(rubricMetrics.coverage.evaluated, 45);
    assert.equal(rubricMetrics.coverage.missing, 0);
    const abstains = cases.filter((c) => rubricPredictions[c.caseId].verdict === 'INSUFFICIENT_EVIDENCE').length;
    assert.equal(rubricMetrics.coverage.abstained, abstains);
    const cov = rubricMetrics.metricsByName.get('citation_coverage');
    assert.equal(cov.status, 'MEASURED');
    assert.equal(cov.numerator, 45 - abstains);
    assert.equal(cov.denominator, 45);
    assert.equal(cov.value, (45 - abstains) / 45);
  });

  test('one-vs-rest confusion counts match an independent reference loop', () => {
    const ref = { tp: 0, fp: 0, fn: 0, tn: 0 };
    for (const c of cases) {
      const g = gold[c.caseId] === 'SUPPORTED';
      const p = rubricPredictions[c.caseId].verdict === 'SUPPORTED';
      if (g && p) ref.tp += 1;
      else if (!g && p) ref.fp += 1;
      else if (g && !p) ref.fn += 1;
      else ref.tn += 1;
    }
    const m = oneVsRestConfusion('SUPPORTED', gold, rubricPredictions, metricCases.map((c) => c.caseId));
    assert.deepEqual({ tp: m.truePositive, fp: m.falsePositive, fn: m.falseNegative, tn: m.trueNegative }, ref);
    const prec = rubricMetrics.metricsByName.get('precision:SUPPORTED');
    assert.equal(prec.numerator, ref.tp);
    assert.equal(prec.denominator, ref.tp + ref.fp);
    assert.equal(prec.value, ref.tp / (ref.tp + ref.fp));
  });

  test('citation entailment F1 equals the value recomputed from class precision/recall', () => {
    const p = rubricMetrics.metricsByName.get('precision:SUPPORTED').value;
    const r = rubricMetrics.metricsByName.get('recall:SUPPORTED').value;
    const f1 = rubricMetrics.metricsByName.get('citation_entailment_f1');
    assert.equal(f1.status, 'MEASURED');
    assert.ok(Math.abs(f1.value - (2 * p * r) / (p + r)) < 1e-12);
  });

  test('stale/future/revoked invalidation recall: candidate 1.0, producer baseline 0.0', () => {
    const stale = cases.filter((c) => gold[c.caseId] === 'STALE_INPUT');
    assert.equal(stale.length, 6);
    const rec = rubricMetrics.metricsByName.get('stale_invalidation_recall');
    assert.equal(rec.numerator, 6);
    assert.equal(rec.denominator, 6);
    assert.equal(rec.value, 1);
    const prod = producerMetrics.metricsByName.get('stale_invalidation_recall');
    assert.equal(prod.value, 0); // the producer heuristic has no staleness concept
    assert.equal(prod.status, 'MEASURED');
  });

  test('drift-reason preservation recalls hit the exact reason codes for the rubric engine', () => {
    for (const name of [
      'number_unit_preservation_recall',
      'negation_preservation_recall',
      'modality_preservation_recall',
      'scope_binding_recall',
    ]) {
      const rec = rubricMetrics.metricsByName.get(name);
      assert.equal(rec.status, 'MEASURED', name);
      assert.equal(rec.value, 1, name);
      assert.ok(rec.denominator >= 1, name);
    }
  });

  test('contradiction vs scope-difference confusion is counted, not hidden', () => {
    const refDenom = cases.filter((c) => gold[c.caseId] === 'CONTRADICTED'
      || (gold[c.caseId] !== 'CONTRADICTED' && goldReasons[c.caseId].includes('scope_difference'))).length;
    const rec = rubricMetrics.metricsByName.get('contradiction_scope_confusion_rate');
    assert.equal(rec.denominator, refDenom);
    assert.equal(rec.numerator, 0);
    const recall = rubricMetrics.metricsByName.get('contradiction_recall');
    assert.equal(recall.value, 1);
    // the producer baseline truly discriminates contradictions via compareClaims
    assert.equal(producerMetrics.metricsByName.get('contradiction_recall').value, 1);
  });

  test('false advisory acceptance/rejection are exact for the rubric engine', () => {
    const faa = rubricMetrics.metricsByName.get('false_advisory_acceptance_rate');
    const far = rubricMetrics.metricsByName.get('false_advisory_rejection_rate');
    assert.equal(faa.numerator, 0);
    assert.equal(far.numerator, 0);
    assert.equal(faa.denominator, cases.filter((c) => gold[c.caseId] !== 'SUPPORTED').length);
    assert.equal(far.denominator, cases.filter((c) => gold[c.caseId] === 'SUPPORTED').length);
  });

  test('selective risk vs coverage: abstentions are excluded from risk and counted in coverage', () => {
    const abstained = new Set(cases.filter((c) => rubricPredictions[c.caseId].verdict === 'INSUFFICIENT_EVIDENCE').map((c) => c.caseId));
    const nonAbstain = cases.filter((c) => !abstained.has(c.caseId));
    assert.equal(rubricMetrics.selectiveRisk.coverage, nonAbstain.length / 45);
    const errors = nonAbstain.filter((c) => rubricPredictions[c.caseId].verdict !== gold[c.caseId]).length;
    assert.equal(rubricMetrics.selectiveRisk.risk, errors / nonAbstain.length);
    assert.ok(Array.isArray(rubricMetrics.selectiveRisk.curve) && rubricMetrics.selectiveRisk.curve.length >= 1);
  });

  test('Wilson intervals are deterministic and bounded', () => {
    const ci = wilsonInterval(6, 6, 0.95);
    assert.ok(ci.lower > 0.5 && ci.upper <= 1);
    assert.equal(ci.confidenceLevel, 0.95);
    assert.deepEqual(wilsonInterval(6, 6, 0.95), wilsonInterval(6, 6, 0.95));
  });
});

describe('S2-006 NOT_MEASURED / NOT_APPLICABLE semantics (never 0% or 100%)', () => {
  test('zero denominator -> NOT_MEASURED with reason, value null', () => {
    const subset = metricCases.filter((c) => c.category !== 'private');
    const m = computeMetrics({
      cases: subset, gold, goldReasons,
      predictions: Object.fromEntries(Object.entries(rubricPredictions).filter(([id]) => subset.some((c) => c.caseId === id))),
      annotators,
      independence: { independent: false, reason: 'evaluator_not_independent' },
    });
    const leak = m.metricsByName.get('unauthorized_leakage_rate');
    assert.equal(leak.status, 'NOT_MEASURED');
    assert.equal(leak.notMeasuredReason, 'insufficient_samples');
    assert.equal(leak.value, null);
    assert.equal(m.hardViolations.total, 0);
  });

  test('IAA on the fixture stratum is NOT_MEASURED / evaluator_not_independent (raw agreement kept for transparency)', () => {
    const iaa = rubricMetrics.iaa;
    assert.equal(iaa.status, 'NOT_MEASURED');
    assert.equal(iaa.notMeasuredReason, 'evaluator_not_independent');
    assert.equal(iaa.value, null);
    assert.equal(rubricMetrics.rawAnnotatorAgreement.total, 45);
    assert.equal(rubricMetrics.rawAnnotatorAgreement.agree, 42);
  });

  test('Brier/ECE are NOT_APPLICABLE: the offline verifier emits no probabilities', () => {
    for (const name of ['brier_score', 'expected_calibration_error']) {
      const rec = rubricMetrics.metricsByName.get(name);
      assert.equal(rec.status, 'NOT_APPLICABLE');
      assert.equal(rec.value, null);
    }
  });

  test('hard violation counters: private leakage is counted for the baselines and zero for the rubric engine', () => {
    assert.equal(rubricMetrics.hardViolations.total, 0);
    assert.equal(ruleMetrics.hardViolations.unauthorizedLeakageEvents, 2);
    assert.equal(producerMetrics.hardViolations.unauthorizedLeakageEvents, 2);
    const ruleLeak = ruleMetrics.metricsByName.get('unauthorized_leakage_rate');
    assert.equal(ruleLeak.status, 'MEASURED');
    assert.equal(ruleLeak.value, 1); // both private cases read: a hard violation, not a quality nit
  });
});

describe('S2-006 lexicographic decision rule (spec §8)', () => {
  test('un-authored thresholds (repo preregistration) -> NEEDS_INPUT, never implicit defaults', () => {
    const thresholds = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts', 's2-006-thresholds.json'), 'utf8'));
    const decision = decideLexicographic({
      systems: [{ systemId: 'rubric-candidate', metrics: rubricMetrics, isCandidate: true, cost: 1, latency: 1 }],
      thresholds,
    });
    assert.equal(decision.status, 'NEEDS_INPUT');
    assert.equal(decision.winner, null);
    assert.ok(decision.needsInputReasons.includes('missing_human_decision'));
    assert.ok(decision.needsInputReasons.includes('missing_thresholds'));
  });

  test('abstain-all cannot win: the coverage gate rejects it even with high raw precision', () => {
    const abstainPredictions = Object.fromEntries(cases.map((c) => [c.caseId, { verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['missing_citation'], missingnessKind: 'none' }]));
    const abstainMetrics = metricsFor(abstainPredictions);
    const decision = decideLexicographic({
      systems: [
        { systemId: 'abstain-all', metrics: abstainMetrics, cost: 0, latency: 0 },
        { systemId: 'rubric-candidate', metrics: rubricMetrics, isCandidate: true, cost: 1, latency: 1 },
      ],
      thresholds: authorThresholds(),
    });
    assert.equal(decision.perSystem['abstain-all'].eligible, false);
    assert.equal(decision.perSystem['abstain-all'].step, 'coverage_gate');
    assert.equal(decision.status, 'DECIDED');
    assert.equal(decision.winner, 'rubric-candidate');
  });

  test('hard violations dominate lexicographically: a leaking perfect verifier loses to a clean mediocre one', () => {
    const leaky = { ...rubricPredictions };
    for (const c of cases) if (c.scenario.category === 'private') leaky[c.caseId] = { verdict: 'SUPPORTED', reasonCodes: [], missingnessKind: 'none' };
    const leakyMetrics = metricsFor(leaky);
    assert.equal(leakyMetrics.hardViolations.total, 2);

    const mediocre = { ...rubricPredictions };
    for (const c of cases) {
      // three stale degradations: still passes the 0.5 stale-recall soft floor
      if (['case-s2006-35', 'case-s2006-36', 'case-s2006-37'].includes(c.caseId)) {
        mediocre[c.caseId] = { verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['topic_overlap'], missingnessKind: 'none' };
      }
    }
    const mediocreMetrics = metricsFor(mediocre);

    const decision = decideLexicographic({
      systems: [
        { systemId: 'leaky-perfect', metrics: leakyMetrics, isCandidate: true, cost: 1, latency: 1 },
        { systemId: 'clean-mediocre', metrics: mediocreMetrics, cost: 5, latency: 10 },
      ],
      thresholds: authorThresholds(),
    });
    assert.equal(decision.perSystem['leaky-perfect'].eligible, false);
    assert.equal(decision.perSystem['leaky-perfect'].step, 'hard_violations');
    assert.equal(decision.status, 'DECIDED');
    assert.equal(decision.winner, 'clean-mediocre');
  });

  test('cost decides among eligible non-inferior candidates before latency', () => {
    const decision = decideLexicographic({
      systems: [
        { systemId: 'rubric-candidate', metrics: rubricMetrics, isCandidate: true, cost: 10, latency: 5 },
        { systemId: 'slower-but-cheap', metrics: rubricMetrics, cost: 2, latency: 99 },
      ],
      thresholds: authorThresholds(),
    });
    assert.equal(decision.status, 'DECIDED');
    assert.equal(decision.winner, 'slower-but-cheap');
  });

  test('cost tie falls through to the frozen latency rule; absent tie rule -> HUMAN_REVIEW', () => {
    const systems = (latA, latB) => [
      { systemId: 'sys-a', metrics: rubricMetrics, isCandidate: true, cost: 2, latency: latA },
      { systemId: 'sys-b', metrics: rubricMetrics, cost: 2, latency: latB },
    ];
    const byLatency = decideLexicographic({ systems: systems(10, 5), thresholds: authorThresholds() });
    assert.equal(byLatency.status, 'DECIDED');
    assert.equal(byLatency.winner, 'sys-b');
    const noTieRule = decideLexicographic({ systems: systems(10, 5), thresholds: authorThresholds({ tie: null }) });
    assert.equal(noTieRule.status, 'HUMAN_REVIEW');
    assert.equal(noTieRule.winner, null);
  });

  test('paired non-inferiority uses a deterministic seeded bootstrap bound against -delta', () => {
    const worse = { ...rubricPredictions };
    // five strict degradations against gold on SUPPORTED cases
    let flipped = 0;
    for (const c of cases) {
      if (gold[c.caseId] === 'SUPPORTED' && flipped < 5) {
        worse[c.caseId] = { verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['topic_overlap'], missingnessKind: 'none' };
        flipped += 1;
      }
    }
    const worseMetrics = metricsFor(worse);
    const decision = decideLexicographic({
      systems: [
        { systemId: 'rubric-candidate', metrics: rubricMetrics, isCandidate: true, cost: 5, latency: 1 },
        { systemId: 'degraded', metrics: worseMetrics, cost: 1, latency: 1 },
      ],
      thresholds: authorThresholds({ delta: 0.05, floor: 0.4, soft: {
        citation_entailment_f1: { metric: 'citation_entailment_f1', operator: '>=', value: 0.3 },
        stale_invalidation_recall: { metric: 'stale_invalidation_recall', operator: '>=', value: 0.5 },
        false_advisory_acceptance_rate: { metric: 'false_advisory_acceptance_rate', operator: '<=', value: 0.2 },
      } }),
    });
    assert.equal(decision.perSystem['rubric-candidate'].eligible, true, JSON.stringify(decision.perSystem));
    assert.equal(decision.pairedIntervals.length, 1);
    const ci = decision.pairedIntervals[0];
    assert.equal(ci.candidate, 'rubric-candidate');
    assert.equal(ci.baseline, 'degraded');
    assert.ok(ci.interval.lower > -0.05, `lower=${ci.interval.lower}`);
    assert.ok(ci.interval.lower >= -1 && ci.interval.upper <= 1);
    assert.equal(decision.status, 'DECIDED');
    assert.equal(decision.winner, 'degraded'); // cost still decides among non-inferior candidates
  });

  test('paired bootstrap is deterministic for a fixed seed and sane in shape', () => {
    const diffs = cases.map((c) => (rubricPredictions[c.caseId].verdict === gold[c.caseId] ? 1 : 0));
    const a = pairedBootstrapInterval(diffs, { seed: 'fixed', confidenceLevel: 0.9, draws: 500 });
    const b = pairedBootstrapInterval(diffs, { seed: 'fixed', confidenceLevel: 0.9, draws: 500 });
    assert.deepEqual(a, b);
    assert.ok(a.lower <= a.upper);
    assert.ok(a.lower >= -1 && a.upper <= 1);
    const other = pairedBootstrapInterval(diffs, { seed: 'other', confidenceLevel: 0.9, draws: 500 });
    assert.equal(other.draws, 500);
  });
});
