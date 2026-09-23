// S2-006 independent semantic verifier — deterministic offline rubric engine
// (spec §7). Implements the frozen rubric decision rules for a single
// verification item: exact-span entailment with polarity, quantity/unit,
// population, geography, period and modality preservation; contradiction
// only under compatible scope; evidence families by upstream lineage;
// causal status from predefined markers without mechanical promotion;
// corpus-bounded novelty; stale/future/revoked invalidation.
//
// Module whitelist (spec §3): Node stdlib only. This module MUST NOT import
// producer semantics (src/lib/synthesis/*, src/lib/claims/*) — those are
// reserved for the deterministic baseline adapter (baselines.mjs, spec §9.2).
// The engine never echoes span text: results carry families, statuses,
// levels and reason codes only, so private content cannot leak into a
// verification result (spec §10).

export const RUBRIC_ID = 'rub-s2006-semantic-v1';
export const RUBRIC_VERSION = '1.0.0';

export const VERDICTS = Object.freeze([
  'SUPPORTED',
  'CONTRADICTED',
  'PARTIALLY_SUPPORTED',
  'INSUFFICIENT_EVIDENCE',
  'OUT_OF_SCOPE',
  'STALE_INPUT',
  'BLOCKED_POLICY',
]);

export const REASON_CODES = Object.freeze([
  'topic_overlap',
  'number_unit_drift',
  'negation_drift',
  'modality_drift',
  'scope_difference',
  'missing_citation',
  'stale_source',
  'future_source',
  'revoked_source',
  'family_collapse',
  'causal_overclaim',
  'out_of_scope',
  'policy_block',
  'evaluator_missing',
  'other',
]);

// Novelty outcomes are closed by spec §7; a world-novelty claim is never one
// of them (probe O).
export const NOVELTY_VALUES = Object.freeze([
  'novel_to_selected_corpus',
  'similar_prior_found',
  'NOT_ASSESSED',
]);

// ---- deterministic text primitives -----------------------------------------

const STOPWORDS = new Set([
  // English function words
  'the', 'a', 'an', 'of', 'to', 'in', 'on', 'for', 'and', 'or', 'by', 'that',
  'this', 'with', 'from', 'at', 'as', 'is', 'are', 'was', 'were', 'be', 'been',
  'it', 'its', 'their', 'has', 'have', 'had', 'did', 'does', 'do', 'will',
  'compared', 'among', 'per', 'up', 'about', 'into', 'over',
  // reporting/confirmation verbs carry no checkable content
  'showed', 'shows', 'found', 'reported', 'reports', 'according', 'confirm',
  'confirms', 'stated', 'says', 'said',
  // Russian function words
  'и', 'в', 'на', 'с', 'по', 'за', 'к', 'у', 'о', 'из', 'для', 'это', 'как',
  'что', 'был', 'была', 'были', 'было', 'году', 'год',
]);

// Negation is checked separately and excluded from coverage tokens so a
// polarity flip is reported as negation_drift, not as a coverage gap.
const NEGATION_TOKENS = new Set([
  'not', 'no', 'never', 'none', 'cannot', 'without', 'neither', 'nor',
  'unchanged', 'fails', 'failed',
  'не', 'нет', 'никогда', 'без',
]);

const HEDGE_TOKENS = new Set([
  'may', 'might', 'could', 'suggests', 'suggest', 'appears', 'appear',
  'possibly', 'likely', 'unclear', 'approximately',
]);

// Mechanism/causal assertion markers for the statement (predefined by the
// rubric; correlation verbs are deliberately absent).
const MECHANISM_TOKENS = new Set([
  'causes', 'cause', 'caused', 'prevents', 'prevent', 'prevented',
  'proves', 'prove', 'proven', 'drives', 'driver', 'lowers', 'lower',
  'cures', 'cured',
]);

// Causal-basis markers (spec §7: predefined features, never correlation).
const INTERVENTIONAL_TOKENS = new Set([
  'randomized', 'randomised', 'controlled', 'trial', 'intervention',
  'experiment', 'experimental',
]);

const GEOGRAPHY_LEXICON = new Set([
  'stockholm', 'oslo', 'gothenburg', 'paris', 'finland', 'hungary', 'poland',
  'portugal', 'germany', 'kenya', 'curitiba', 'vaxholm',
]);

const POPULATION_LEXICON = new Set([
  'adults', 'children', 'seniors', 'nurses', 'patients', 'households',
  'students', 'buyers', 'men', 'women',
]);

const UNIT_CANONICAL = new Map(Object.entries({
  '%': '%', percent: '%', pct: '%',
  kg: 'kg', kgs: 'kg', kilogram: 'kg', kilograms: 'kg',
  mg: 'mg', milligram: 'mg', milligrams: 'mg',
  tonne: 'tonne', tonnes: 'tonne', ton: 'tonne', tons: 'tonne',
  km: 'km', kilometers: 'km', kilometres: 'km',
  mile: 'miles', miles: 'miles',
  hour: 'hours', hours: 'hours',
  week: 'weeks', weeks: 'weeks',
  month: 'months', months: 'months',
  day: 'days', days: 'days',
  year: 'years', years: 'years',
  mmhg: 'mmhg', eur: 'eur', usd: 'usd',
}));

// Unit is optional: every number is captured, with its unit when one is
// directly attached; a bare number (e.g. a year) is unitless.
const NUMBER_UNIT_RE = /(\d+(?:[.,]\d+)?)(?:\s*(pct|percent|kgs|kg|kilograms|kilogram|mg|milligrams|milligram|tonnes|tonne|tons|ton|kms|km|kilometers|kilometres|miles|mile|hours|hour|weeks|week|months|month|days|day|years|year|mmhg|eur|usd|%))?/gi;

function splitTokens(text) {
  return String(text ?? '')
    .toLowerCase()
    .split(/[^a-zа-я0-9%.]+/)
    .map((t) => t.replace(/^\.+|\.+$/g, '')) // sentence punctuation, not decimal points
    .filter((t) => t.length > 0);
}

// Light deterministic stemming (one suffix), identical on both sides of the
// comparison; exists only so inflection does not masquerade as drift.
function stem(token) {
  if (token.length >= 5 && token.endsWith('ing')) return token.slice(0, -3);
  if (token.length >= 5 && token.endsWith('ed')) return token.slice(0, -2);
  if (token.length >= 5 && token.endsWith('es')) return token.slice(0, -2);
  if (token.length >= 4 && token.endsWith('s')) return token.slice(0, -1);
  return token;
}

function contentTokens(text) {
  return splitTokens(text).filter((t) => !STOPWORDS.has(t) && !NEGATION_TOKENS.has(t));
}

function hasNegation(text) {
  return splitTokens(text).some((t) => NEGATION_TOKENS.has(t));
}

function hasHedge(text) {
  return splitTokens(text).some((t) => HEDGE_TOKENS.has(t));
}

// Quantity+unit pairs; a bare number is unitless. Conservative comparison:
// same numeric value AND canonically equal unit — no silent unit conversion.
function quantityUnitPairs(text) {
  const pairs = [];
  for (const m of String(text ?? '').matchAll(NUMBER_UNIT_RE)) {
    const unit = m[2] ? (UNIT_CANONICAL.get(m[2].toLowerCase()) ?? null) : null;
    pairs.push({ value: m[1].replace(',', '.'), unit });
  }
  return pairs;
}

function quantitiesSurvive(statementPairs, spanPairs) {
  for (const p of statementPairs) {
    const hit = spanPairs.find((q) => q.value === p.value);
    if (!hit) return false;
    if (p.unit !== hit.unit) return false; // unitless only matches unitless
  }
  return true;
}

function lexiconIn(tokens, lexicon) {
  const found = new Set();
  for (const t of tokens) {
    if (lexicon.has(t)) found.add(t);
    else if (lexicon.has(stem(t))) found.add(stem(t));
  }
  return found;
}

// Scope attributes of a statement, resolved through the frozen translation
// alignment when present (cross-lingual checks run on frozen alignments).
function scopeAttributes(text, alignment) {
  const tokens = splitTokens(text);
  const expanded = [...tokens];
  if (alignment) {
    for (const t of tokens) {
      const mapped = alignment.get(t);
      if (mapped) expanded.push(mapped);
    }
  }
  return {
    geography: lexiconIn(expanded, GEOGRAPHY_LEXICON),
    population: lexiconIn(expanded, POPULATION_LEXICON),
    years: new Set(tokens.filter((t) => /^(19|20)\d{2}$/.test(t))),
  };
}

// Disjoint explicit values are conflicts; a one-sided value is only a
// qualifier gap (never a conflict — spec §7).
function scopeRelation(a, b) {
  if (a.size > 0 && b.size > 0) {
    for (const v of a) if (b.has(v)) return 'match';
    return 'conflict';
  }
  if (a.size === 0 && b.size === 0) return 'match';
  return 'qualifier_gap';
}

function coverage(statementText, spanText, alignment) {
  const stmt = contentTokens(statementText);
  if (stmt.length === 0) return { coverage: 1, total: 0 };
  const spanSet = new Set(contentTokens(spanText).map(stem));
  let covered = 0;
  for (const t of stmt) {
    if (spanSet.has(stem(t))) {
      covered += 1;
      continue;
    }
    const mapped = alignment?.get(t);
    if (mapped && spanSet.has(stem(mapped))) covered += 1;
  }
  return { coverage: covered / stmt.length, total: stmt.length };
}

function translationMap(alignment) {
  if (!alignment) return null;
  const map = new Map();
  for (const pair of alignment) {
    if (Array.isArray(pair)) map.set(pair[0], pair[1]);
    else map.set(pair.statementTerm, pair.spanTerm);
  }
  return map;
}

// ---- evidence families ------------------------------------------------------

// All spans descending from one upstream family are ONE evidence family;
// unknown lineage never creates additional independence (spec §7).
export function collapseEvidenceFamilies(spans) {
  const families = new Set();
  for (const s of spans) {
    families.add(s?.sourceFamily ?? null);
  }
  families.delete(null); // unknown lineage is never a second independent family
  return { families: [...families].sort(), independentCount: families.size };
}

// ---- novelty (corpus-bounded only) ------------------------------------------

export function assessNovelty({ scope, priorArtInSelectedCorpus, corpusScopeProvided = true } = {}) {
  if (!corpusScopeProvided) return 'NOT_ASSESSED';
  if (scope === 'worldwide') return 'NOT_ASSESSED'; // world novelty is refused, never assessed
  if (scope === 'selected_corpus') {
    return priorArtInSelectedCorpus ? 'similar_prior_found' : 'novel_to_selected_corpus';
  }
  return 'NOT_ASSESSED';
}

// ---- single-span evaluation -------------------------------------------------

function evaluateSpan(statement, spanCtx, options) {
  const alignment = options.alignment;
  const mechanismClaim = options.mechanismClaim === true;

  if (spanCtx.unavailable || spanCtx.text == null) {
    return { ok: false, reason: 'missing_citation', unavailable: true, causalBasis: false };
  }
  const text = spanCtx.text;

  // 1. quantities and units (conservative, no conversion)
  if (!quantitiesSurvive(quantityUnitPairs(statement), quantityUnitPairs(text))) {
    return { ok: false, reason: 'number_unit_drift', causalBasis: false };
  }

  const cov = coverage(statement, text, alignment);

  // 2. polarity (only judged within the same proposition)
  if (cov.coverage >= 0.5 && hasNegation(statement) !== hasNegation(text)) {
    return { ok: false, reason: 'negation_drift', coverage: cov.coverage, causalBasis: false };
  }

  // 3. modality class (hedged vs assertive)
  if (cov.coverage >= 0.5 && hasHedge(statement) !== hasHedge(text)) {
    return { ok: false, reason: 'modality_drift', coverage: cov.coverage, causalBasis: false };
  }

  // 4. scope: disjoint explicit values are conflicts; one-sided values are
  // qualifier gaps (downgrade, never a conflict).
  const stmtScope = scopeAttributes(statement, alignment);
  const spanScope = scopeAttributes(text, null);
  let qualifierGap = false;
  for (const dim of ['geography', 'population', 'years']) {
    const rel = scopeRelation(stmtScope[dim], spanScope[dim]);
    if (rel === 'conflict') {
      return { ok: false, reason: 'scope_difference', coverage: cov.coverage, causalBasis: false };
    }
    if (rel === 'qualifier_gap') qualifierGap = true;
  }

  // 5. causal basis: predefined interventional markers only.
  const spanTokens = splitTokens(text);
  const causalBasis = mechanismClaim && spanTokens.some((t) => INTERVENTIONAL_TOKENS.has(t));

  if (cov.coverage < 0.5) {
    return { ok: false, reason: 'topic_overlap', coverage: cov.coverage, causalBasis };
  }
  const level = cov.coverage >= 1 ? 'full' : 'partial';
  const reason = qualifierGap ? 'scope_difference' : (level === 'partial' ? 'topic_overlap' : null);
  return { ok: true, level, reason, coverage: cov.coverage, causalBasis };
}

// ---- statement-level decision (ordered, deterministic) ----------------------

// Drift reason priority when no span supports the statement: the most
// specific mismatch wins, ties resolve by this fixed order.
const DRIFT_PRIORITY = [
  'number_unit_drift',
  'negation_drift',
  'modality_drift',
  'scope_difference',
  'topic_overlap',
  'missing_citation',
];

export function evaluateStatement(input) {
  const {
    statement,
    supportingSpans = [],
    contradictingSpans = [],
    asOf,
    mechanismClaim = false,
    claimsMultipleIndependentSources = false,
    noveltyClaim = null,
    translationAlignment = null,
  } = input;

  if (!statement || typeof statement !== 'string') {
    throw new TypeError('evaluateStatement: statement must be a non-empty string');
  }
  const alignment = translationMap(translationAlignment);
  const options = { alignment, mechanismClaim };

  const allSpans = [...supportingSpans, ...contradictingSpans];

  // 0. ACL gate: private spans are never read (spec §10). The engine never
  // echoes their text; the verdict depends only on the access flag.
  const publicSupport = supportingSpans.filter((s) => s.access !== 'private');
  const publicContradict = contradictingSpans.filter((s) => s.access !== 'private');
  if (allSpans.length > 0 && publicSupport.length === 0 && publicContradict.length === 0) {
    return {
      verdict: 'BLOCKED_POLICY',
      reasonCodes: ['policy_block'],
      missingness: { kind: 'policy_refusal' },
      evidenceFamilies: collapseEvidenceFamilies([]),
      noveltyAssessment: 'NOT_ASSESSED',
      spanOutcomes: allSpans.map((s) => ({ role: supportingSpans.includes(s) ? 'support' : 'contradict', access: s.access, status: s.status, sourceFamily: s.sourceFamily })),
      rubricId: RUBRIC_ID,
      rubricVersion: RUBRIC_VERSION,
    };
  }

  // 1. citation gate
  if (allSpans.length === 0) {
    return {
      verdict: 'INSUFFICIENT_EVIDENCE',
      reasonCodes: ['missing_citation'],
      missingness: { kind: 'none' },
      evidenceFamilies: collapseEvidenceFamilies([]),
      noveltyAssessment: assessNovelty(noveltyClaim ?? undefined),
      spanOutcomes: [],
      rubricId: RUBRIC_ID,
      rubricVersion: RUBRIC_VERSION,
    };
  }

  // 2. typed unavailability is not a semantic pass/fail (spec §5/probe P)
  const evaluableSupport = publicSupport.filter((s) => !s.unavailable && s.text != null);
  if (evaluableSupport.length === 0 && publicContradict.length === 0) {
    const anyUnavailable = publicSupport.some((s) => s.unavailable || s.text == null);
    return {
      verdict: 'INSUFFICIENT_EVIDENCE',
      reasonCodes: ['missing_citation'],
      missingness: { kind: anyUnavailable ? 'source_unavailable' : 'none' },
      evidenceFamilies: collapseEvidenceFamilies([]),
      noveltyAssessment: assessNovelty(noveltyClaim ?? undefined),
      spanOutcomes: publicSupport.map((s) => ({ role: 'support', access: s.access, status: s.status, sourceFamily: s.sourceFamily, unavailable: Boolean(s.unavailable || s.text == null) })),
      rubricId: RUBRIC_ID,
      rubricVersion: RUBRIC_VERSION,
    };
  }

  // 3. freshness gate: future > revoked > stale; a post-as_of source invalidates
  // the dependent verdict regardless of textual similarity (probe H).
  const freshness = (s) => {
    if (s.status === 'future' || (asOf && s.publishedAt && String(s.publishedAt) > String(asOf))) return 'future';
    if (s.status === 'revoked') return 'revoked';
    if (s.status === 'stale') return 'stale';
    return 'current';
  };
  const freshRank = { future: 0, revoked: 1, stale: 2, current: 9 };
  let worst = 'current';
  for (const s of allSpans) {
    const f = freshness(s);
    if (freshRank[f] < freshRank[worst]) worst = f;
  }
  if (worst !== 'current') {
    const reason = worst === 'future' ? 'future_source' : worst === 'revoked' ? 'revoked_source' : 'stale_source';
    return {
      verdict: 'STALE_INPUT',
      reasonCodes: [reason],
      missingness: { kind: 'none' },
      evidenceFamilies: collapseEvidenceFamilies(allSpans),
      noveltyAssessment: 'NOT_ASSESSED',
      spanOutcomes: allSpans.map((s) => ({ role: supportingSpans.includes(s) ? 'support' : 'contradict', access: s.access, status: freshness(s), sourceFamily: s.sourceFamily })),
      rubricId: RUBRIC_ID,
      rubricVersion: RUBRIC_VERSION,
    };
  }

  // 4. novelty gate: a world-novelty claim is out of scope, always (probe O).
  if (noveltyClaim && noveltyClaim.scope === 'worldwide') {
    return {
      verdict: 'OUT_OF_SCOPE',
      reasonCodes: ['out_of_scope'],
      missingness: { kind: 'none' },
      evidenceFamilies: collapseEvidenceFamilies(publicSupport),
      noveltyAssessment: assessNovelty(noveltyClaim),
      spanOutcomes: publicSupport.map((s) => ({ role: 'support', access: s.access, status: s.status, sourceFamily: s.sourceFamily })),
      rubricId: RUBRIC_ID,
      rubricVersion: RUBRIC_VERSION,
    };
  }

  // 5. contradiction: opposite polarity or disjoint quantities for the same
  // proposition under COMPATIBLE scope only (probe C); scope differences are
  // never contradictions.
  for (const contra of publicContradict) {
    if (contra.unavailable || contra.text == null) continue;
    const compatible =
      scopeRelation(scopeAttributes(statement, alignment).geography, scopeAttributes(contra.text, null).geography) !== 'conflict' &&
      scopeRelation(scopeAttributes(statement, alignment).population, scopeAttributes(contra.text, null).population) !== 'conflict' &&
      scopeRelation(scopeAttributes(statement, alignment).years, scopeAttributes(contra.text, null).years) !== 'conflict';
    if (!compatible) continue;
    const polarityFlip = hasNegation(statement) !== hasNegation(contra.text);
    const stmtQ = quantityUnitPairs(statement).filter((p) => !/^(19|20)\d{2}/.test(p.value));
    const contraQ = quantityUnitPairs(contra.text).filter((p) => !/^(19|20)\d{2}/.test(p.value));
    const disjointQuantities = stmtQ.length > 0 && contraQ.length > 0 &&
      !stmtQ.some((p) => contraQ.some((q) => q.value === p.value));
    if (polarityFlip || disjointQuantities) {
      return {
        verdict: 'CONTRADICTED',
        reasonCodes: [],
        missingness: { kind: 'none' },
        evidenceFamilies: collapseEvidenceFamilies([...publicSupport, contra]),
        noveltyAssessment: assessNovelty(noveltyClaim ?? undefined),
        spanOutcomes: [
          ...publicSupport.map((s) => ({ role: 'support', access: s.access, status: s.status, sourceFamily: s.sourceFamily })),
          { role: 'contradict', access: contra.access, status: contra.status, sourceFamily: contra.sourceFamily },
        ],
        rubricId: RUBRIC_ID,
        rubricVersion: RUBRIC_VERSION,
      };
    }
  }

  // 6. support path: best supporting span decides the base level.
  const outcomes = evaluableSupport.map((s) => ({ span: s, result: evaluateSpan(statement, s, options) }));
  if (outcomes.length === 0) {
    return {
      verdict: 'INSUFFICIENT_EVIDENCE',
      reasonCodes: ['missing_citation'],
      missingness: { kind: 'none' },
      evidenceFamilies: collapseEvidenceFamilies(publicContradict),
      noveltyAssessment: assessNovelty(noveltyClaim ?? undefined),
      spanOutcomes: publicSupport.map((s) => ({ role: 'support', access: s.access, status: s.status, sourceFamily: s.sourceFamily, unavailable: Boolean(s.unavailable || s.text == null) })),
      rubricId: RUBRIC_ID,
      rubricVersion: RUBRIC_VERSION,
    };
  }

  const full = outcomes.filter((o) => o.result.ok && o.result.level === 'full');
  const partial = outcomes.filter((o) => o.result.ok && o.result.level === 'partial');
  const failed = outcomes.filter((o) => !o.result.ok && !o.result.unavailable);

  let verdict;
  let reasonCodes = [];
  let best = null;
  if (full.length > 0) {
    verdict = 'SUPPORTED';
    best = full[0].result;
  } else if (partial.length > 0) {
    verdict = 'PARTIALLY_SUPPORTED';
    best = partial[0].result;
    reasonCodes = [best.reason ?? 'topic_overlap'];
  } else {
    verdict = 'INSUFFICIENT_EVIDENCE';
    const reasons = failed.map((o) => o.result.reason).filter(Boolean);
    reasons.sort((a, b) => DRIFT_PRIORITY.indexOf(a) - DRIFT_PRIORITY.indexOf(b));
    reasonCodes = [reasons[0] ?? 'topic_overlap'];
    best = failed[0]?.result ?? { causalBasis: false };
  }

  // 7. causal status: correlation/analogy never promotes to mechanism; the
  // presence of markers keeps the verdict advisory (spec §7, probe D).
  const anyCausalBasis = outcomes.some((o) => o.result.causalBasis);
  if (mechanismClaim && !anyCausalBasis) {
    if (verdict === 'SUPPORTED') {
      verdict = 'PARTIALLY_SUPPORTED';
      reasonCodes = ['causal_overclaim'];
    } else if (verdict === 'PARTIALLY_SUPPORTED') {
      reasonCodes = ['causal_overclaim'];
    } else {
      reasonCodes = [...new Set([...reasonCodes, 'causal_overclaim'])];
    }
  }

  // 8. evidence-family collapse: an independence claim over fewer families
  // than claimed downgrades support (probe F); unknown lineage never counts
  // as an independent family.
  const passingSpans = outcomes.filter((o) => o.result.ok).map((o) => o.span);
  const families = collapseEvidenceFamilies(passingSpans);
  if (claimsMultipleIndependentSources && passingSpans.length > 0 && families.independentCount < 2) {
    reasonCodes = [...new Set([...reasonCodes, 'family_collapse'])];
    if (verdict === 'SUPPORTED') verdict = 'PARTIALLY_SUPPORTED';
  }

  return {
    verdict,
    reasonCodes,
    missingness: { kind: 'none' },
    evidenceFamilies: families,
    noveltyAssessment: assessNovelty(noveltyClaim ?? undefined),
    spanOutcomes: outcomes.map((o) => ({
      role: 'support',
      access: o.span.access,
      status: o.span.status,
      sourceFamily: o.span.sourceFamily,
      level: o.result.ok ? o.result.level : null,
      ok: o.result.ok,
      reason: o.result.ok ? (o.result.reason ?? null) : o.result.reason,
    })),
    rubricId: RUBRIC_ID,
    rubricVersion: RUBRIC_VERSION,
  };
}

// Convenience wrapper over a frozen fixture scenario document.
export function evaluateScenario(scenario) {
  return evaluateStatement({
    statement: scenario.statement,
    supportingSpans: scenario.supportingSpans ?? [],
    contradictingSpans: scenario.contradictingSpans ?? [],
    asOf: scenario.asOf,
    mechanismClaim: scenario.mechanismClaim,
    claimsMultipleIndependentSources: scenario.claimsMultipleIndependentSources,
    noveltyClaim: scenario.noveltyClaim ?? null,
    translationAlignment: scenario.translationAlignment ?? null,
  });
}
