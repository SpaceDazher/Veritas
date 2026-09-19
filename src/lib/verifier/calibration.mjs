// S2-006 calibration metrics and preregistered decision rule (spec §8).
//
// Semantics enforced here:
//   * every metric carries raw numerator/denominator/missingCount; a zero
//     denominator, invalid labels or violated independence yield status
//     NOT_MEASURED with a notMeasuredReason from the closed contract
//     vocabulary — never 0% or 100%;
//   * Brier/ECE are NOT_APPLICABLE unless the verifier emits probabilities
//     (the offline verifier emits none);
//   * the decision rule is lexicographic: (1) zero hard violations, (2)
//     quality+coverage with the lower bound of the paired bootstrap
//     confidence interval above -delta, (3) full cost among eligible
//     non-inferior candidates, (4) latency under the frozen tie rule, (5)
//     inconclusive -> HUMAN_REVIEW with no winner;
//   * every owner-owned numeric comes from the passed thresholds
//     preregistration; a null value yields NEEDS_INPUT, never an implicit
//     default. Abstain-all cannot win: coverage gate.
//   * threshold AUTHORITY (review P1-5): a non-null `ownerDecisionRef` string
//     is bookkeeping, never authority. Numerics become effective only through
//     resolveThresholdDecision(): a canonical immutable HumanDecision
//     (contracts/human-decision.schema.json) from the authenticated
//     owner=user, bound to the exact canonical-json digest of the thresholds
//     document, whose authority_binding.grantRef resolves from the verifier
//     authority registry as a reviewer-issued, signature-verified grant
//     (same mechanism as commands.mjs registerProviderGrant). A failed
//     resolution yields NEEDS_INPUT — never an implicit default.
//
// Deterministic: Wilson intervals and the seeded bootstrap use no wall clock
// and no randomness beyond the explicit seed. Contract validation uses the
// real JSON Schemas in contracts/ (the §3 whitelist explicitly allows
// contract validation); this module never imports producer semantics.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { canonicalDigest } from './canonical-json.mjs';
import { verifyDetailed as verifySignatureDetailed } from './signature.mjs';

export const METRIC_STATUSES = Object.freeze(['MEASURED', 'NOT_MEASURED', 'NEEDS_INPUT', 'NOT_APPLICABLE']);

// Closed notMeasuredReason vocabulary from calibration-record-v2 /
// calibration-report contracts.
export const NOT_MEASURED_REASONS = Object.freeze([
  'no_valid_corpus',
  'insufficient_samples',
  'evaluator_not_independent',
  'outcome_not_defined',
  'missing_thresholds',
  'missing_human_decision',
  'dependency_blocked',
]);

const VERDICT_LABELS = Object.freeze([
  'SUPPORTED', 'CONTRADICTED', 'PARTIALLY_SUPPORTED',
  'INSUFFICIENT_EVIDENCE', 'OUT_OF_SCOPE', 'STALE_INPUT', 'BLOCKED_POLICY',
]);

// ---- deterministic math ------------------------------------------------------

function mulberry32(seedValue) {
  let a = seedValue >>> 0;
  return function next() {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function seedFromString(seed) {
  const s = String(seed ?? 'seed');
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function quantile(sorted, q) {
  if (sorted.length === 0) return null;
  const pos = (sorted.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  if (base + 1 < sorted.length) return sorted[base] + rest * (sorted[base + 1] - sorted[base]);
  return sorted[base];
}

export function wilsonInterval(numerator, denominator, confidenceLevel = 0.95) {
  if (!(denominator >= 1)) return null;
  const z = inverseNormalCdf(1 - (1 - confidenceLevel) / 2);
  const p = numerator / denominator;
  const denom = 1 + (z * z) / denominator;
  const center = (p + (z * z) / (2 * denominator)) / denom;
  const spread = (z * Math.sqrt((p * (1 - p)) / denominator + (z * z) / (4 * denominator * denominator))) / denom;
  return { lower: Math.max(0, center - spread), upper: Math.min(1, center + spread), confidenceLevel };
}

// Acklam-style inverse normal CDF (deterministic, stdlib-only).
function inverseNormalCdf(p) {
  const a = [-39.6968302866538, 220.946098424521, -275.928510446969, 138.357751867269, -30.6647980661472, 2.50662827745924];
  const b = [-54.4760987982241, 161.585836858041, -155.698979859887, 66.8013118877197, -13.2806815528857];
  const c = [-7.78489400243029e-3, -0.322396458041136, -2.40075827716184, -2.54973253934373, 4.37466414146497, 2.93816398269878];
  const d = [7.78469570904146e-3, 0.32246712907004, 2.445134137143, 3.75440866190742];
  const pLow = 0.02425;
  if (p <= 0 || p >= 1) throw new RangeError('inverseNormalCdf requires 0 < p < 1');
  if (p < pLow) {
    const q = Math.sqrt(-2 * Math.log(p));
    return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
  }
  if (p <= 1 - pLow) {
    const q = p - 0.5;
    const r = q * q;
    return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q /
      (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1);
  }
  const q = Math.sqrt(-2 * Math.log(1 - p));
  return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
}

// Deterministic paired bootstrap over a diff vector (per-case values, frozen
// order). Returns a percentile confidence interval of the mean difference.
export function pairedBootstrapInterval(diffs, { seed, confidenceLevel = 0.95, draws = 2000 } = {}) {
  const values = diffs.map(Number);
  if (values.length === 0) return null;
  const rand = mulberry32(seedFromString(seed));
  const means = [];
  const n = values.length;
  for (let d = 0; d < draws; d += 1) {
    let sum = 0;
    for (let i = 0; i < n; i += 1) sum += values[Math.floor(rand() * n)];
    means.push(sum / n);
  }
  means.sort((x, y) => x - y);
  const alpha = 1 - confidenceLevel;
  return {
    lower: quantile(means, alpha / 2),
    upper: quantile(means, 1 - alpha / 2),
    confidenceLevel,
    draws,
    seed: String(seed),
  };
}

// ---- metric record construction ---------------------------------------------

function record(name, numerator, denominator, {
  missingCount = 0,
  intervalMethod = 'wilson',
  status,
  notMeasuredReason,
  confidenceLevel = 0.95,
  value = null,
  interval,
} = {}) {
  let finalStatus = status;
  let finalValue = value;
  let finalInterval = interval ?? null;
  if (finalStatus === undefined) {
    if (!(denominator >= 1)) {
      finalStatus = 'NOT_MEASURED';
    } else {
      finalStatus = 'MEASURED';
      finalValue = numerator / denominator;
      if (intervalMethod === 'wilson') finalInterval = wilsonInterval(numerator, denominator, confidenceLevel);
    }
  }
  const rec = {
    name,
    numerator,
    denominator,
    missingCount,
    value: finalValue,
    intervalMethod: finalStatus === 'MEASURED' ? intervalMethod : 'none',
    interval: finalInterval,
    status: finalStatus,
  };
  if (finalStatus === 'NOT_MEASURED' || finalStatus === 'NEEDS_INPUT') {
    // auto-NOT_MEASURED comes from an empty denominator: the closed-vocabulary
    // default is insufficient_samples; explicit call sites pass their own reason
    const reason = notMeasuredReason ?? (finalStatus === 'NOT_MEASURED' ? 'insufficient_samples' : undefined);
    if (!reason) throw new Error(`metric ${name}: ${finalStatus} requires notMeasuredReason`);
    rec.notMeasuredReason = reason;
  }
  return rec;
}

const f1Of = (p, r) => (p + r > 0 ? (2 * p * r) / (p + r) : 0);

// ---- confusion / agreement ----------------------------------------------------

export function oneVsRestConfusion(label, gold, predictions, caseIds) {
  let tp = 0; let fp = 0; let fn = 0; let tn = 0; let missing = 0;
  for (const id of caseIds) {
    const g = gold[id];
    const p = predictions[id]?.verdict ?? null;
    if (!g || !p) { missing += 1; continue; }
    const gHit = g === label;
    const pHit = p === label;
    if (gHit && pHit) tp += 1;
    else if (!gHit && pHit) fp += 1;
    else if (gHit && !pHit) fn += 1;
    else tn += 1;
  }
  return { name: `one_vs_rest:${label}`, truePositive: tp, falsePositive: fp, falseNegative: fn, trueNegative: tn, missing };
}

function rawAnnotatorAgreement(annotators, caseIds) {
  if (!annotators?.a || !annotators?.b) return null;
  let agree = 0; let total = 0;
  for (const id of caseIds) {
    const a = annotators.a[id];
    const b = annotators.b[id];
    if (!a || !b) continue;
    total += 1;
    if (a === b) agree += 1;
  }
  return { agree, total, rate: total > 0 ? agree / total : null };
}

// ---- full metric suite ---------------------------------------------------------

// cases: [{caseId, category, stratum}]
// gold: {caseId: verdictLabel}; goldReasons: {caseId: [reasonCode...]}
// predictions: {caseId: {verdict, reasonCodes, missingnessKind?}}
// annotators: {a: {caseId: label}, b: {caseId: label}} (raw blind labels)
// independence: {independent: boolean, reason?: notMeasuredReason}
export function computeMetrics({ cases, gold, goldReasons = {}, predictions, annotators = null, independence = { independent: false, reason: 'evaluator_not_independent' }, confidenceLevel = 0.95 }) {
  const caseIds = cases.map((c) => c.caseId);
  const denominator = caseIds.length;
  const records = [];
  const byId = new Map(cases.map((c) => [c.caseId, c]));

  const missingFor = (id) => {
    const p = predictions[id];
    if (!p || !p.verdict) return true;
    return ['evaluator_missing', 'timeout', 'budget_exhausted'].includes(p.missingnessKind);
  };
  const evaluatedIds = caseIds.filter((id) => !missingFor(id));
  const evaluated = evaluatedIds.length;
  const missing = denominator - evaluated;

  const correct = (id) => predictions[id]?.verdict != null && predictions[id].verdict === gold[id];
  const abstained = (id) => predictions[id]?.verdict === 'INSUFFICIENT_EVIDENCE';

  const isPrivate = (id) => byId.get(id)?.category === 'private';
  // a leak means private CONTENT shaped the output: any verdict that asserts
  // or denies the statement's substance could only be produced by reading the
  // span. Abstentions and access/staleness refusals are not content leaks.
  const LEAK_VERDICTS = new Set(['SUPPORTED', 'CONTRADICTED', 'PARTIALLY_SUPPORTED']);
  const leak = (id) => isPrivate(id) && evaluatedIds.includes(id) && LEAK_VERDICTS.has(predictions[id]?.verdict);

  const countWhere = (pred) => evaluatedIds.filter(pred).length;
  const sub = (pred) => evaluatedIds.filter(pred);

  // availability and citation coverage (coverage gate uses the non-abstention
  // share: precision without coverage is insufficient — abstain-all loses)
  const abstainIds = evaluatedIds.filter(abstained);
  records.push(record('decision_availability', evaluated, denominator, { missingCount: missing, confidenceLevel }));
  records.push(record('citation_coverage', evaluatedIds.length - abstainIds.length, denominator, { missingCount: missing, confidenceLevel }));
  records.push(record('abstention_rate', abstainIds.length, denominator, { missingCount: missing, confidenceLevel }));

  // per-class one-vs-rest + macro
  const confusions = VERDICT_LABELS.map((label) => oneVsRestConfusion(label, gold, predictions, caseIds));
  const classRates = {};
  for (const label of VERDICT_LABELS) {
    const tp = countWhere((id) => gold[id] === label && predictions[id]?.verdict === label);
    const tpfp = countWhere((id) => predictions[id]?.verdict === label);
    const tpfn = countWhere((id) => gold[id] === label);
    const precision = record(`precision:${label}`, tp, tpfp, {
      missingCount: missing, confidenceLevel,
      ...(tpfp === 0 ? { status: 'NOT_MEASURED', notMeasuredReason: 'insufficient_samples' } : {}),
    });
    const recall = record(`recall:${label}`, tp, tpfn, {
      missingCount: missing, confidenceLevel,
      ...(tpfn === 0 ? { status: 'NOT_MEASURED', notMeasuredReason: 'insufficient_samples' } : {}),
    });
    classRates[label] = {
      precision: precision.status === 'MEASURED' ? precision.value : null,
      recall: recall.status === 'MEASURED' ? recall.value : null,
      tp, tpfp, tpfn,
    };
    records.push(precision, recall);
  }
  const measuredLabels = VERDICT_LABELS.filter((l) => classRates[l].tpfp > 0 && classRates[l].tpfn > 0);
  if (measuredLabels.length > 0) {
    const mp = measuredLabels.reduce((acc, l) => acc + classRates[l].precision, 0) / measuredLabels.length;
    const mr = measuredLabels.reduce((acc, l) => acc + classRates[l].recall, 0) / measuredLabels.length;
    records.push(record('macro_precision', 0, 1, { value: mp, status: 'MEASURED', intervalMethod: 'none', interval: null, missingCount: missing }));
    records.push(record('macro_recall', 0, 1, { value: mr, status: 'MEASURED', intervalMethod: 'none', interval: null, missingCount: missing }));
    records.push(record('macro_f1', 0, 1, { value: f1Of(mp, mr), status: 'MEASURED', intervalMethod: 'none', interval: null, missingCount: missing }));
    const p = classRates.SUPPORTED;
    if (p.tpfp > 0 && p.tpfn > 0) {
      records.push(record('citation_entailment_f1', 0, 1, {
        value: f1Of(p.precision, p.recall), status: 'MEASURED', intervalMethod: 'none', interval: null, missingCount: missing,
      }));
    } else {
      records.push(record('citation_entailment_f1', 0, 0, { status: 'NOT_MEASURED', notMeasuredReason: 'insufficient_samples', missingCount: missing }));
    }
  } else {
    for (const name of ['macro_precision', 'macro_recall', 'macro_f1', 'citation_entailment_f1']) {
      records.push(record(name, 0, 0, { status: 'NOT_MEASURED', notMeasuredReason: 'insufficient_samples', missingCount: missing }));
    }
  }

  // drift-reason preservation recalls (exact reason code required)
  const driftReasonMetric = (reason, name) => {
    const goldIds = evaluatedIds.filter((id) => gold[id] === 'INSUFFICIENT_EVIDENCE' && (goldReasons[id] ?? []).includes(reason));
    const hits = goldIds.filter((id) => predictions[id]?.verdict === 'INSUFFICIENT_EVIDENCE' && (predictions[id].reasonCodes ?? []).includes(reason));
    return record(name, hits.length, goldIds.length, { missingCount: missing, confidenceLevel });
  };
  records.push(driftReasonMetric('number_unit_drift', 'number_unit_preservation_recall'));
  records.push(driftReasonMetric('negation_drift', 'negation_preservation_recall'));
  records.push(driftReasonMetric('modality_drift', 'modality_preservation_recall'));
  records.push(driftReasonMetric('scope_difference', 'scope_binding_recall'));

  // contradiction vs scope-difference confusion (probe C)
  const goldContradicted = evaluatedIds.filter((id) => gold[id] === 'CONTRADICTED');
  const goldScopeDiff = evaluatedIds.filter((id) => gold[id] !== 'CONTRADICTED' && (goldReasons[id] ?? []).includes('scope_difference'));
  records.push(record('contradiction_precision',
    goldContradicted.filter((id) => predictions[id]?.verdict === 'CONTRADICTED').length,
    evaluatedIds.filter((id) => predictions[id]?.verdict === 'CONTRADICTED').length,
    { missingCount: missing, confidenceLevel }));
  records.push(record('contradiction_recall',
    goldContradicted.filter((id) => predictions[id]?.verdict === 'CONTRADICTED').length,
    goldContradicted.length,
    { missingCount: missing, confidenceLevel }));
  const falseContradictions = goldScopeDiff.filter((id) => predictions[id]?.verdict === 'CONTRADICTED').length;
  const missedContradictions = goldContradicted.filter((id) => predictions[id]?.verdict !== 'CONTRADICTED').length;
  records.push(record('contradiction_scope_confusion_rate',
    falseContradictions + missedContradictions,
    goldScopeDiff.length + goldContradicted.length,
    { missingCount: missing, confidenceLevel }));

  // epistemic type / causal overclaim (probe D)
  const causalIds = evaluatedIds.filter((id) => byId.get(id)?.category === 'causal');
  records.push(record('epistemic_type_exact_match',
    causalIds.filter((id) => correct(id)).length, causalIds.length,
    { missingCount: missing, confidenceLevel }));
  const overclaimIds = evaluatedIds.filter((id) => (goldReasons[id] ?? []).includes('causal_overclaim'));
  records.push(record('causal_overclaim_miss_rate',
    overclaimIds.filter((id) => !(predictions[id]?.reasonCodes ?? []).includes('causal_overclaim')).length,
    overclaimIds.length,
    { missingCount: missing, confidenceLevel }));

  // evidence-family collapse recall (probe F)
  const familyIds = evaluatedIds.filter((id) => (goldReasons[id] ?? []).includes('family_collapse'));
  records.push(record('family_collapse_recall',
    familyIds.filter((id) => (predictions[id]?.reasonCodes ?? []).includes('family_collapse')).length,
    familyIds.length,
    { missingCount: missing, confidenceLevel }));

  // stale/future/revoked invalidation recall
  const staleIds = evaluatedIds.filter((id) => gold[id] === 'STALE_INPUT');
  records.push(record('stale_invalidation_recall',
    staleIds.filter((id) => predictions[id]?.verdict === 'STALE_INPUT').length,
    staleIds.length,
    { missingCount: missing, confidenceLevel }));

  // unauthorized private-content leakage (hard violation)
  const privateIds = evaluatedIds.filter(isPrivate);
  const leakIds = evaluatedIds.filter(leak);
  records.push(record('unauthorized_leakage_rate', leakIds.length, privateIds.length, {
    missingCount: missing,
    confidenceLevel,
    status: privateIds.length === 0 ? 'NOT_MEASURED' : undefined,
    notMeasuredReason: privateIds.length === 0 ? 'insufficient_samples' : undefined,
  }));

  // advisory acceptance / rejection errors
  const goldNotSupported = evaluatedIds.filter((id) => gold[id] !== 'SUPPORTED');
  const goldSupported = evaluatedIds.filter((id) => gold[id] === 'SUPPORTED');
  records.push(record('false_advisory_acceptance_rate',
    goldNotSupported.filter((id) => predictions[id]?.verdict === 'SUPPORTED').length,
    goldNotSupported.length,
    { missingCount: missing, confidenceLevel }));
  records.push(record('false_advisory_rejection_rate',
    goldSupported.filter((id) => predictions[id]?.verdict !== 'SUPPORTED').length,
    goldSupported.length,
    { missingCount: missing, confidenceLevel }));

  // selective risk vs coverage (risk = error rate among non-abstained)
  const nonAbstain = evaluatedIds.filter((id) => !abstained(id));
  const riskRec = record('selective_risk',
    nonAbstain.filter((id) => !correct(id)).length,
    nonAbstain.length,
    { missingCount: missing, confidenceLevel });
  records.push(riskRec);
  const overallRisk = denominator > 0 ? evaluatedIds.filter((id) => !correct(id)).length / Math.max(1, evaluatedIds.length) : null;
  const selectiveRisk = {
    risk: riskRec.status === 'MEASURED' ? riskRec.value : null,
    coverage: denominator > 0 ? nonAbstain.length / denominator : null,
    curve: [
      ...(overallRisk != null ? [{ coverage: evaluated / Math.max(1, denominator), risk: overallRisk }] : []),
      ...(riskRec.status === 'MEASURED' ? [{ coverage: denominator > 0 ? nonAbstain.length / denominator : 0, risk: riskRec.value }] : []),
    ],
  };

  // inter-annotator agreement: computed for transparency, but on a fixture
  // stratum (violated independence) it is NOT_MEASURED, never a percentage
  const agreement = rawAnnotatorAgreement(annotators, caseIds);
  const iaa = independence.independent && agreement && agreement.total > 0
    ? record('inter_annotator_agreement', agreement.agree, agreement.total, { confidenceLevel })
    : record('inter_annotator_agreement', agreement?.agree ?? 0, agreement?.total ?? 0, {
        status: 'NOT_MEASURED',
        notMeasuredReason: independence.reason ?? 'evaluator_not_independent',
      });
  records.push(iaa);

  // adjudication rate
  const adjudicatedIds = evaluatedIds.filter((id) => goldReasons[id]?.adjudicated === true || (annotators?.a && annotators?.b && annotators.a[id] !== annotators.b[id]));
  records.push(record('adjudication_rate', adjudicatedIds.length, denominator, { missingCount: missing, confidenceLevel }));

  // probability calibration: the offline verifier emits no probabilities
  records.push(record('brier_score', 0, 0, { status: 'NOT_APPLICABLE', intervalMethod: 'none' }));
  records.push(record('expected_calibration_error', 0, 0, { status: 'NOT_APPLICABLE', intervalMethod: 'none' }));

  // human intervention/time, latency, cost: not produced by the offline harness
  records.push(record('human_active_time', 0, 0, { status: 'NOT_MEASURED', notMeasuredReason: 'outcome_not_defined', missingCount: missing }));
  records.push(record('latency', 0, 0, { status: 'NOT_MEASURED', notMeasuredReason: 'outcome_not_defined', missingCount: missing }));
  records.push(record('actual_cost', 0, 0, { status: 'NOT_MEASURED', notMeasuredReason: 'outcome_not_defined', missingCount: missing }));

  // evidence-map completeness: no EvidenceMap inputs in the verifier harness
  records.push(record('evidence_map_completeness', 0, 0, { status: 'NOT_APPLICABLE', intervalMethod: 'none' }));

  const hardViolations = {
    unauthorizedLeakageEvents: leakIds.length,
    lockedLabelAccessEvents: 0,
    producerSelfReviewEvents: 0,
    upstreamArtifactMutationEvents: 0,
    unauthorizedSideEffectEvents: 0,
    get total() {
      return this.unauthorizedLeakageEvents + this.lockedLabelAccessEvents + this.producerSelfReviewEvents
        + this.upstreamArtifactMutationEvents + this.unauthorizedSideEffectEvents;
    },
  };

  const metricsByName = new Map(records.map((r) => [r.name, r]));
  return {
    metricRecords: records,
    metricsByName,
    confusionMatrices: confusions,
    coverage: { denominator, evaluated, missing, abstained: abstainIds.length },
    selectiveRisk,
    hardViolations,
    iaa,
    rawAnnotatorAgreement: agreement,
    leaks: leakIds,
    correctById: Object.fromEntries(caseIds.map((id) => [id, Boolean(correct(id))])),
  };
}

// ---- threshold-decision authority (review P1-5, spec §8) --------------------

export const THRESHOLDS_ARTIFACT_REF = 'contracts/s2-006-thresholds.json';

// The grant tool scope that certifies threshold authority. A reviewer-issued
// grant for this tool names exactly one authenticated principal; a borrowed
// provider/model grant is refused.
export const THRESHOLD_AUTHORITY_TOOL = 'threshold-authority';

// Producer-side identities can never own the thresholds decision (spec §3:
// the producer cannot review or authorize its own artifact).
const FORBIDDEN_AUTHORITY_ROLES = Object.freeze(['candidate', 'producer', 'verifier_operator']);

const CALIBRATION_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
let humanDecisionValidate = null;

// Fail-closed validation against the REAL contracts/human-decision.schema.json
// (draft 2020-12): the canonical immutable HumanDecision shape — closed
// properties, APPROVED requires a human actor, exact digest, timestamp and a
// server_authenticated_human authority binding.
function requireCanonicalHumanDecision(decision) {
  if (!humanDecisionValidate) {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    for (const name of ['needs-input', 'human-decision']) {
      const schema = JSON.parse(fs.readFileSync(path.join(CALIBRATION_ROOT, 'contracts', `${name}.schema.json`), 'utf8'));
      ajv.addSchema(schema, schema.$id);
    }
    humanDecisionValidate = ajv.getSchema('https://veritas.local/contracts/human-decision.schema.json');
  }
  const ok = humanDecisionValidate(decision) === true;
  return {
    ok,
    errors: ok ? [] : humanDecisionValidate.errors.map((e) => `${e.instancePath} ${e.message}`).join('; '),
  };
}

// Resolves the owner decision that authorizes a thresholds document.
// Returns { resolved: true, decisionDigest, ownerPrincipal, grantRef } or
// { resolved: false, reason } — a failed resolution is NEEDS_INPUT, never an
// implicit default. Every check reuses an existing mechanism: the JSON Schema,
// canonical-json digests and the signature.mjs MAC core over the authority
// registry's registered grant (the registerProviderGrant pattern).
export function resolveThresholdDecision(thresholdsDoc, decision, authorities, { keyRegistry = null } = {}) {
  const refused = (reason) => ({ resolved: false, reason });
  if (!thresholdsDoc || typeof thresholdsDoc !== 'object' || Array.isArray(thresholdsDoc)) {
    return refused('thresholds_document_malformed');
  }
  const schema = requireCanonicalHumanDecision(decision);
  if (!schema.ok) return refused(`decision_not_canonical_human_decision: ${schema.errors}`);
  if (decision.status !== 'APPROVED') return refused('decision_not_approved');
  // authenticated owner=user (spec §8: self-appointment by an agent or the
  // verifier is forbidden)
  if (decision.actor_type !== 'human' || decision.actor_id !== 'user') {
    return refused('decision_actor_not_owner_user');
  }
  if (decision.decision_scope !== 'research') return refused('decision_scope_not_research');
  if (decision.artifact_ref !== THRESHOLDS_ARTIFACT_REF) return refused('decision_artifact_ref_mismatch');
  // exact binding to THIS thresholds document over canonical-json
  if (decision.artifact_digest !== canonicalDigest(thresholdsDoc)) {
    return refused('decision_digest_mismatch');
  }
  const binding = decision.authority_binding;
  if (!binding || binding.bindingType !== 'server_authenticated_human') {
    return refused('authority_binding_missing');
  }
  // the certified principal must be a registered authority and never a
  // producer-side identity
  const entry = authorities instanceof Map ? authorities.get(binding.principalId) : undefined;
  const roles = [...(entry?.roles ?? [])];
  if (!entry || roles.length === 0) return refused('owner_principal_unregistered');
  if (roles.some((role) => FORBIDDEN_AUTHORITY_ROLES.includes(role))) {
    return refused('owner_principal_producer_side');
  }
  // the authority grant must RESOLVE from the registry (registered by an
  // issuer with a verified signature — the registerProviderGrant pattern);
  // schema-valid caller-supplied grants are never trusted
  const issuedGrants = authorities instanceof Map ? authorities.issuedGrants : null;
  if (!(issuedGrants instanceof Map)) return refused('authority_registry_without_issued_grants');
  const registered = issuedGrants.get(binding.grantRef);
  if (!registered) return refused('authority_grant_unregistered');
  if (registered.issuer === binding.principalId) return refused('authority_grant_self_issued');
  if (registered.grant?.authenticatedPrincipal !== binding.principalId) {
    return refused('authority_grant_principal_mismatch');
  }
  if (registered.grant?.tool !== THRESHOLD_AUTHORITY_TOOL) return refused('authority_grant_wrong_tool');
  const grantDigest = canonicalDigest(registered.grant ?? {});
  if (registered.grantDigest !== grantDigest) return refused('authority_grant_digest_mismatch');
  // signature envelope re-checked at use time; without a key registry the
  // digest/issuer binding above stays binding (same policy as commands.mjs)
  const sig = registered.signature;
  if (!sig || typeof sig !== 'object' || Array.isArray(sig)
    || sig.scheme !== 'hmac-sha256' || sig.verified !== true
    || sig.attestedBy !== registered.issuer) {
    return refused('authority_grant_signature_rejected: malformed or unverified envelope');
  }
  if (keyRegistry) {
    const verdict = verifySignatureDetailed(sig, registered.issuer, grantDigest, { registry: keyRegistry });
    if (!verdict.ok) return refused(`authority_grant_signature_rejected: ${verdict.reason}`);
  }
  // expiry against the decision's own deterministic timestamp (never wall clock)
  if (String(decision.timestamp) > String(registered.grant.expiresAt ?? '')) {
    return refused('authority_grant_expired_at_decision_time');
  }
  return {
    resolved: true,
    reason: 'verified',
    decisionDigest: canonicalDigest(decision),
    ownerPrincipal: binding.principalId,
    grantRef: binding.grantRef,
  };
}

// ---- lexicographic decision rule (spec §8) ----------------------------------

// thresholds: preregistration document (contracts/s2-006-thresholds.json shape
// or an owner-authored version with the same canonical field layout —
// soft_thresholds nested under `thresholds`). Any null owner-owned numeric
// yields NEEDS_INPUT — never an implicit default. Owner authority comes ONLY
// from a resolvable canonical HumanDecision (ownerDecision + authorities);
// a bare ownerDecisionRef string is bookkeeping, never authority.
export function decideLexicographic({
  systems, thresholds, seed = 's2-006-paired-bootstrap', confidenceLevel,
  ownerDecision = null, authorities = null, keyRegistry = null,
} = {}) {
  const needsInputReasons = new Set();
  const needsInputDetails = [];
  const perSystem = {};
  for (const s of systems) perSystem[s.systemId] = { eligible: true, step: 'start', reasons: [] };

  const reject = (id, step, reason) => {
    perSystem[id].eligible = false;
    perSystem[id].step = step;
    perSystem[id].reasons.push(reason);
  };

  // step 1: zero hard violations (preregistered by the spec; zero-tolerance,
  // no owner numeric required)
  for (const s of systems) {
    if ((s.metrics.hardViolations?.total ?? 0) > 0) reject(s.systemId, 'hard_violations', `hard_violations=${s.metrics.hardViolations.total}`);
  }
  const afterHard = systems.filter((s) => perSystem[s.systemId].eligible);
  if (afterHard.length === 0) {
    return { status: 'HUMAN_REVIEW', winner: null, perSystem, pairedIntervals: [], needsInputReasons: [], needsInputDetails: [] };
  }

  // owner-owned numerics: null -> NEEDS_INPUT (no implicit defaults). The
  // soft thresholds are read from the CANONICAL nested document path
  // (thresholds.soft_thresholds) — a top-level field is not part of the
  // contract shape and is never consulted (review P1-5b).
  const floor = thresholds?.coverage_floor?.value ?? null;
  const delta = thresholds?.non_inferiority_margin?.delta ?? null;
  const soft = thresholds?.thresholds?.soft_thresholds ?? {};
  const tieRule = thresholds?.tie_rule?.rule ?? null;
  const cl = confidenceLevel ?? thresholds?.confidence_level?.value ?? null;
  // Threshold AUTHORITY (review P1-5a): only a resolvable canonical immutable
  // HumanDecision from the authenticated owner=user counts. A non-null
  // ownerDecisionRef string is bookkeeping, never authority.
  if (ownerDecision && authorities) {
    const resolution = resolveThresholdDecision(thresholds, ownerDecision, authorities, { keyRegistry });
    if (!resolution.resolved) {
      needsInputReasons.add('missing_human_decision');
      needsInputDetails.push(`threshold_decision_not_resolved: ${resolution.reason}`);
    }
  } else if (thresholds?.ownerDecisionRef != null) {
    needsInputReasons.add('missing_human_decision');
    needsInputDetails.push(`ownerDecisionRef ${String(thresholds.ownerDecisionRef)} does not resolve to a verified immutable HumanDecision from authenticated owner=user; authority never comes from a bare reference`);
  } else {
    needsInputReasons.add('missing_human_decision');
    needsInputDetails.push('threshold_decision_missing: an immutable HumanDecision from authenticated owner=user bound to the exact thresholds digest is required before any owner-owned numeric applies');
  }
  if (floor == null || delta == null || cl == null) needsInputReasons.add('missing_thresholds');
  for (const key of Object.keys(soft)) {
    if (soft[key]?.value == null) needsInputReasons.add('missing_thresholds');
  }
  if (needsInputReasons.size > 0) {
    return { status: 'NEEDS_INPUT', winner: null, perSystem, pairedIntervals: [], needsInputReasons: [...needsInputReasons].sort(), needsInputDetails: [...needsInputDetails] };
  }

  // step 2a: coverage gate (abstain-all cannot win)
  for (const s of afterHard) {
    const cov = s.metrics.metricsByName.get('citation_coverage');
    const coverageValue = cov?.status === 'MEASURED' ? cov.value : null;
    if (coverageValue == null) reject(s.systemId, 'coverage_gate', 'coverage_not_measured');
    else if (coverageValue < floor) reject(s.systemId, 'coverage_gate', `coverage ${coverageValue.toFixed(3)} < floor ${floor}`);
  }

  // step 2b: soft quality thresholds
  for (const s of afterHard) {
    if (!perSystem[s.systemId].eligible) continue;
    for (const key of Object.keys(soft)) {
      const spec = soft[key];
      const rec = s.metrics.metricsByName.get(spec.metric);
      if (!rec || rec.status !== 'MEASURED') {
        reject(s.systemId, 'quality', `${spec.metric}_not_measured`);
        continue;
      }
      if (spec.operator === '>=' && !(rec.value >= spec.value)) reject(s.systemId, 'quality', `${spec.metric} ${rec.value.toFixed(3)} < ${spec.value}`);
      if (spec.operator === '<=' && !(rec.value <= spec.value)) reject(s.systemId, 'quality', `${spec.metric} ${rec.value.toFixed(3)} > ${spec.value}`);
    }
  }

  // step 2c: paired non-inferiority of the candidate against every other
  // surviving system: lower bound of the paired bootstrap CI > -delta
  const surviving = systems.filter((s) => perSystem[s.systemId].eligible);
  const candidate = surviving.find((s) => s.isCandidate) ?? surviving[0];
  const pairedIntervals = [];
  if (surviving.length > 1) {
    for (const other of surviving) {
      if (other.systemId === candidate.systemId) continue;
      const ids = Object.keys(candidate.metrics.correctById);
      const diffs = ids.map((id) => (candidate.metrics.correctById[id] ? 1 : 0) - (other.metrics.correctById[id] ? 1 : 0));
      const ci = pairedBootstrapInterval(diffs, { seed: `${seed}:${candidate.systemId}:${other.systemId}`, confidenceLevel: cl });
      pairedIntervals.push({ candidate: candidate.systemId, baseline: other.systemId, interval: ci });
      if (ci == null || !(ci.lower > -delta)) {
        reject(candidate.systemId, 'non_inferiority', `paired lower bound ${ci ? ci.lower.toFixed(3) : 'n/a'} <= -delta`);
      }
    }
  }

  // steps 3-4: full cost, then latency under the frozen tie rule
  const eligible = systems.filter((s) => perSystem[s.systemId].eligible);
  if (eligible.length === 0) {
    return { status: 'HUMAN_REVIEW', winner: null, perSystem, pairedIntervals, needsInputReasons: [], needsInputDetails: [] };
  }
  for (const s of eligible) {
    if (s.cost == null) needsInputReasons.add('cost_not_provided');
  }
  if (needsInputReasons.size > 0) {
    return { status: 'NEEDS_INPUT', winner: null, perSystem, pairedIntervals, needsInputReasons: [...needsInputReasons].sort(), needsInputDetails: [...needsInputDetails] };
  }
  let finalists = [...eligible].sort((a, b) => a.cost - b.cost);
  const bestCost = finalists[0].cost;
  finalists = finalists.filter((s) => s.cost === bestCost);
  if (finalists.length > 1) {
    if (tieRule !== 'latency_asc') {
      return { status: 'HUMAN_REVIEW', winner: null, perSystem, pairedIntervals, needsInputReasons: [], needsInputDetails: [] };
    }
    finalists.sort((a, b) => a.latency - b.latency);
    const bestLatency = finalists[0].latency;
    finalists = finalists.filter((s) => s.latency === bestLatency);
  }
  if (finalists.length !== 1) {
    return { status: 'HUMAN_REVIEW', winner: null, perSystem, pairedIntervals, needsInputReasons: [], needsInputDetails: [] };
  }
  return { status: 'DECIDED', winner: finalists[0].systemId, perSystem, pairedIntervals, needsInputReasons: [], needsInputDetails: [] };
}
