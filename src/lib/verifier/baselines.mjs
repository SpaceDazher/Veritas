// S2-006 baselines (spec §9). Two reference systems evaluated on the same
// frozen cases/splits as the candidate verifier:
//
//   1. baseline-rule-schema-v1 — deterministic rule/schema baseline. Naive
//      declared-field and raw string-overlap matching: it trusts the span
//      status field, counts raw content-token overlap, and ignores polarity,
//      quantities, units, modality, scope binding, ACL and causal markers.
//
//   2. baseline-producer-heuristic-v1 — adapter around the current
//      S2-004/S2-005 producer heuristic behavior. Per spec §9.2 this adapter
//      is the ONLY place where producer functions (entailmentOf from
//      src/lib/synthesis/synthesis.mjs, compareClaims from
//      src/lib/claims/contradiction.mjs) may be reused: the baseline is not
//      the candidate verifier, so the §3 module whitelist is not violated.
//      The candidate path (rubric.mjs, calibration.mjs, comparator.mjs)
//      never imports them.
//
// Both baselines return the same bounded verdict/reasonCodes shape as the
// rubric engine. They are advisory baselines, never acceptance decisions.
import { entailmentOf } from '../synthesis/synthesis.mjs';
import { compareClaims } from '../claims/contradiction.mjs';

export const BASELINE_RULE_ID = 'baseline-rule-schema-v1';
export const BASELINE_PRODUCER_ID = 'baseline-producer-heuristic-v1';

const naiveContentTokens = (text) =>
  String(text ?? '')
    .toLowerCase()
    .split(/[^a-zа-я0-9%]+/)
    .filter((t) => t.length > 2 && t !== 'the' && t !== 'and' && t !== 'for' && t !== 'with');

function naiveOverlap(statement, text) {
  const a = naiveContentTokens(statement);
  if (a.length === 0) return 0;
  const b = new Set(naiveContentTokens(text));
  let covered = 0;
  for (const t of a) if (b.has(t)) covered += 1;
  return covered / a.length;
}

function freshnessReason(status) {
  if (status === 'future') return 'future_source';
  if (status === 'revoked') return 'revoked_source';
  if (status === 'stale') return 'stale_source';
  return null;
}

// ---- baseline #1: deterministic rule/schema --------------------------------

export function ruleBaselineEvaluate(scenario) {
  const support = scenario.supportingSpans ?? [];
  const contradict = scenario.contradictingSpans ?? [];
  const all = [...support, ...contradict];

  if (all.length === 0) {
    return { systemId: BASELINE_RULE_ID, verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['missing_citation'] };
  }

  // schema-driven freshness: the declared status field is checked, its
  // semantics are not
  for (const s of all) {
    const reason = freshnessReason(s.status);
    if (reason) return { systemId: BASELINE_RULE_ID, verdict: 'STALE_INPUT', reasonCodes: [reason] };
  }

  // naive contradiction: any roughly similar contradicting span wins,
  // regardless of scope compatibility (probe C failure by design)
  for (const c of contradict) {
    if (c.unavailable || c.text == null) continue;
    if (naiveOverlap(scenario.statement, c.text) >= 0.4) {
      return { systemId: BASELINE_RULE_ID, verdict: 'CONTRADICTED', reasonCodes: [] };
    }
  }

  // naive support: raw overlap threshold; no polarity/quantity/unit/scope/
  // modality checks; private access is not honored (measured as leakage)
  const evaluable = support.filter((s) => !s.unavailable && s.text != null);
  if (evaluable.length === 0) {
    return { systemId: BASELINE_RULE_ID, verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['missing_citation'] };
  }
  const best = Math.max(...evaluable.map((s) => naiveOverlap(scenario.statement, s.text)));
  if (best >= 0.5) {
    return { systemId: BASELINE_RULE_ID, verdict: 'SUPPORTED', reasonCodes: [] };
  }
  return { systemId: BASELINE_RULE_ID, verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['topic_overlap'] };
}

// ---- baseline #2: producer heuristic adapter (spec §9.2) --------------------

export function producerBaselineEvaluate(scenario) {
  const support = scenario.supportingSpans ?? [];
  const contradict = scenario.contradictingSpans ?? [];
  const all = [...support, ...contradict];

  if (all.length === 0) {
    return { systemId: BASELINE_PRODUCER_ID, verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['missing_citation'] };
  }

  // The producer heuristic has no freshness, ACL or causal-basis concepts:
  // stale/future/revoked sources, private spans and correlation-as-mechanism
  // are evaluated as ordinary text (the differential this baseline exposes).

  // contradiction via compareClaims on the frozen structured claims
  for (const c of contradict) {
    if (c.unavailable || c.text == null || !scenario.statementStructured || !c.structured) continue;
    const comparison = compareClaims(
      { ...scenario.statementStructured, normalized_text: scenario.statement },
      { ...c.structured, normalized_text: c.text },
    );
    if (comparison.relation === 'CONTRADICTS') {
      return { systemId: BASELINE_PRODUCER_ID, verdict: 'CONTRADICTED', reasonCodes: [] };
    }
    // SCOPE_DIFFERENCE / INDEPENDENT: fall through to support evaluation
  }

  // support via entailmentOf (token coverage + numbers + polarity)
  const evaluable = support.filter((s) => !s.unavailable && s.text != null);
  if (evaluable.length === 0) {
    return { systemId: BASELINE_PRODUCER_ID, verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['missing_citation'] };
  }
  let best = null;
  for (const s of evaluable) {
    const e = entailmentOf(scenario.statement, s.text);
    if (e === 'ENTAILS') {
      best = { verdict: 'SUPPORTED', reasonCodes: [] };
      break;
    }
    if (e === 'PARTIALLY_ENTAILS' && !best) {
      best = { verdict: 'PARTIALLY_SUPPORTED', reasonCodes: ['topic_overlap'] };
    }
  }
  if (best) return { systemId: BASELINE_PRODUCER_ID, ...best };
  return { systemId: BASELINE_PRODUCER_ID, verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['topic_overlap'] };
}
