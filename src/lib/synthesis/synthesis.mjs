// S2-005 synthesis engine.
// Builds EvidenceMaps and HypothesisCards over retrieved claims from the
// frozen corpus under the S2-005 epistemic rules:
//   * every externally checkable statement carries an EvidenceMap; a citation
//     without entailment is not support (numbers and negation must survive)
//   * correlation, analogical structure, candidate mechanism and causal
//     assertion are separate: MECHANISM_CLAIM requires a supported mediator
//     AND established temporal ordering; correlation-only input yields a
//     HYPOTHESIS with recorded confounders — never a causal proof
//   * epistemic type is never auto-promoted (S1-011 rule inherited)
//   * novelty is scoped to the named frozen corpus and search horizon
//   * unavailable/access-denied evidence appears as an explicit gap
//   * contradictions are shown on both sides; expert disagreement produces
//     uncertainty, never a popularity vote (S2-004 lens semantics)
import { createHash } from 'node:crypto';
import { tokenize } from './retrieval.mjs';
import { synthesisValidators } from './validation.mjs';
import { compareClaims } from '../claims/contradiction.mjs';

const sha256 = (value) => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');

const NEGATION_TOKENS = new Set(['not', 'no', 'never', 'none', 'cannot', 'without', 'neither', 'nor']);
const HEDGE_TOKENS = new Set(['may', 'might', 'could', 'suggests', 'appears', 'possibly', 'likely', 'unclear']);

function numbersIn(text) {
  return String(text ?? '').match(/\d+(?:[.,]\d+)?%?/g) ?? [];
}

function hasNegation(text) {
  // checked on the raw lowercase text: 'not' is a stopword for retrieval
  // tokens but MUST survive the entailment polarity check
  return /\b(not|no|never|none|cannot|without|neither|nor)\b/i.test(String(text ?? ''));
}

// Deterministic entailment check between an output statement and a cited
// claim span. Numbers and negation must survive: a summary/translation that
// changes a number or a negation does not entail the citation (probe L).
export function entailmentOf(statement, claimText) {
  const statementTokens = tokenize(statement);
  const claimTokens = new Set(tokenize(claimText));
  if (statementTokens.length === 0 || claimTokens.size === 0) return 'NOT_ENTAILING';
  const covered = statementTokens.filter((t) => claimTokens.has(t));
  const coverage = covered.length / statementTokens.length;

  const statementNumbers = numbersIn(statement);
  if (statementNumbers.length > 0) {
    const claimNumbers = new Set(numbersIn(claimText));
    const numbersSurvive = statementNumbers.every((n) => claimNumbers.has(n));
    if (!numbersSurvive) return 'NOT_ENTAILING';
  }
  if (hasNegation(statement) !== hasNegation(claimText)) return 'NOT_ENTAILING';

  if (coverage >= 0.8) return 'ENTAILS';
  if (coverage >= 0.5) return 'PARTIALLY_ENTAILS';
  return 'NOT_ENTAILING';
}

// ---- evidence maps --------------------------------------------------------------

export function buildEvidenceMap({
  statement,
  supporting = [], // [{ claim, hit }]
  contradicting = [], // [{ claim, hit }]
  qualifying = [], // [{ claim, hit }]
  unavailable = [], // [{ what_is_missing, kind, required_for }]
  staleClaimIds = [],
  invalidationEventIds = [],
}) {
  const entries = [];
  for (const { claim, hit } of supporting) {
    const entailment = entailmentOf(statement, claim.normalized_text);
    entries.push({
      claim_id: claim.claim_id,
      claim_revision: claim.revision,
      relation: 'supports',
      entailment_status: entailment,
      entailment_method: 'token-coverage+number+polarity/1.0.0',
      evidence_edge_id: null,
      segment_id: hit?.segment_id ?? null,
      span: hit?.span ?? null,
      ...(hit?.quote_digest ? { quote_digest: hit.quote_digest } : {}),
      source_family_id: hit?.source_family_id ?? claim.source_family_id ?? null,
      domain: claim.domain ?? null,
    });
  }
  for (const { claim, hit } of contradicting) {
    entries.push({
      claim_id: claim.claim_id,
      claim_revision: claim.revision,
      relation: 'contradicts',
      entailment_status: entailmentOf(statement, claim.normalized_text),
      entailment_method: 'token-coverage+number+polarity/1.0.0',
      evidence_edge_id: null,
      segment_id: hit?.segment_id ?? null,
      span: hit?.span ?? null,
      ...(hit?.quote_digest ? { quote_digest: hit.quote_digest } : {}),
      source_family_id: hit?.source_family_id ?? claim.source_family_id ?? null,
      domain: claim.domain ?? null,
    });
  }
  for (const { claim, hit } of qualifying) {
    entries.push({
      claim_id: claim.claim_id,
      claim_revision: claim.revision,
      relation: 'qualifies',
      entailment_status: entailmentOf(statement, claim.normalized_text),
      entailment_method: 'token-coverage+number+polarity/1.0.0',
      evidence_edge_id: null,
      segment_id: hit?.segment_id ?? null,
      span: hit?.span ?? null,
      ...(hit?.quote_digest ? { quote_digest: hit.quote_digest } : {}),
      source_family_id: hit?.source_family_id ?? claim.source_family_id ?? null,
      domain: claim.domain ?? null,
    });
  }

  // family collapse: independent evidence = distinct source families
  const familyCounts = new Map();
  let collapsedMembers = 0;
  for (const entry of entries) {
    if (entry.relation !== 'supports') continue;
    const family = entry.source_family_id ?? `singleton:${entry.claim_id}`;
    familyCounts.set(family, (familyCounts.get(family) ?? 0) + 1);
  }
  for (const count of familyCounts.values()) collapsedMembers += count - 1;
  const families = [...familyCounts.entries()].map(([family, count]) => ({
    source_family_id: family.startsWith('singleton:') ? null : family,
    member_count: count,
    lineage: family.startsWith('singleton:') ? 'UNKNOWN' : 'DERIVED',
  }));

  const entailingCount = entries.filter((e) => e.relation === 'supports' && e.entailment_status === 'ENTAILS').length;
  const isStale = staleClaimIds.length > 0;
  // an explicit access/freeze gap makes the map partial: the answer covers
  // only the accessible slice of what was asked (todo §5: gaps are shown,
  // never silently dropped)
  const blockingGap = unavailable.some((u) => u.kind === 'ACCESS_DENIED' || u.kind === 'AFTER_AS_OF' || u.kind === 'REMOVED');
  const status = isStale ? 'STALE' : entailingCount === 0 || blockingGap ? 'INCOMPLETE' : 'FRESH';

  const map = {
    contractVersion: '1.0.0',
    map_id: `evm-${sha256(statement).slice(0, 16)}`,
    statement,
    entries,
    unavailable_evidence: unavailable,
    qualifiers: qualifying.map((q) => q.claim.normalized_text).slice(0, 8),
    family_collapse: {
      families,
      collapsed_members: collapsedMembers,
      independent_evidence_count: familyCounts.size,
    },
    stale: {
      is_stale: isStale,
      invalidation_event_ids: invalidationEventIds,
      stale_claim_ids: staleClaimIds,
      recomputed: false,
    },
    status,
  };
  return synthesisValidators().requireValid('evidence-map', map);
}

// ---- novelty ---------------------------------------------------------------------

// Novelty is measured ONLY against the named frozen corpus and search
// horizon: never "never discovered by anyone before".
export function assessNovelty({ subject, predicate, index, corpus = null, horizon = null, excludeClaimIds = [] }) {
  if (!index) return { assessment: 'NOT_ASSESSED' };
  const relationTokens = new Set([...tokenize(subject), ...tokenize(predicate)]);
  if (relationTokens.size === 0) return { assessment: 'NOT_ASSESSED' };
  const excluded = new Set(excludeClaimIds);
  const priors = [];
  for (const entry of index.entries) {
    if (excluded.has(entry.claim_id)) continue; // the card's own nodes are not priors of themselves
    const entryTokens = new Set(entry.tokens);
    const overlap = [...relationTokens].filter((t) => entryTokens.has(t)).length / relationTokens.size;
    if (overlap >= 0.6) {
      priors.push({ claim_id: entry.claim_id, similarity: overlap >= 0.8 ? 'SAME_RELATION' : 'SAME_STRUCTURE' });
    }
  }
  priors.sort((a, b) => (a.claim_id < b.claim_id ? -1 : 1));
  if (priors.length > 0) {
    return { assessment: 'similar_prior_found', corpus, search_horizon: horizon, similar_prior_refs: priors.slice(0, 10) };
  }
  return { assessment: 'novel_to_selected_corpus', corpus, search_horizon: horizon, similar_prior_refs: [] };
}

// ---- hypothesis cards -------------------------------------------------------------

// Causal discipline: the card type is derived from the strength of the
// evidence, never from the author's enthusiasm. A MECHANISM_CLAIM requires
// a SUPPORTED mediator and established temporal ordering; correlation-only
// input is a HYPOTHESIS with recorded confounders and a null causal
// assertion; an analogical structure alone is an ANALOGY.
export function classifyRelation({ relationStrength, mediatorStatus, temporalEstablished }) {
  if (relationStrength === 'ANALOGICAL_STRUCTURE' && mediatorStatus !== 'SUPPORTED' && !temporalEstablished) {
    return 'ANALOGY';
  }
  if (relationStrength === 'MEDIATED_PATHWAY' && mediatorStatus === 'SUPPORTED' && temporalEstablished) {
    return 'MECHANISM_CLAIM';
  }
  if (relationStrength === 'EXPERIMENTAL') {
    return mediatorStatus === 'SUPPORTED' && temporalEstablished ? 'MECHANISM_CLAIM' : 'HYPOTHESIS';
  }
  return 'HYPOTHESIS';
}

export function buildHypothesisCard({
  domains,
  nodes, // [{ claim, role }]
  relation, // { subject, predicate, object, relation_strength }
  mediators = [],
  confounders = [],
  alternatives = [],
  scope = { domain_limits: ['claims hold only within the frozen corpus scope'] },
  assumptions = [],
  falsifiers = [],
  testDesign,
  counterevidence = [],
  index = null,
  corpus = null,
  horizon = null,
  staleClaimIds = [],
  invalidationEventIds = [],
  createdBy = 'prn-synthesizer',
  createdAt = '2026-01-15T08:00:00.000Z',
}) {
  if (domains.length < 2) throw new Error('hypothesis card requires >= 2 originating domains');
  if (nodes.length < 2) throw new Error('hypothesis card requires >= 2 nodes');

  const mediatorStatus = mediators.length > 0 ? mediators[0].evidence_status : 'NOT_FOUND';
  const temporalEstablished = nodes.some((n) => n.role === 'mediator') || Boolean(relation.temporal_ordering_established);
  const cardType = classifyRelation({
    relationStrength: relation.relation_strength,
    mediatorStatus,
    temporalEstablished,
  });

  const causalAssertion = cardType === 'MECHANISM_CLAIM' ? true : null;
  if (relation.causal_assertion === true && causalAssertion !== true) {
    throw new Error('causal assertion requires MECHANISM_CLAIM evidence (mediator + temporal ordering)');
  }

  const novelty = assessNovelty({ subject: relation.subject, predicate: relation.predicate, index, corpus, horizon, excludeClaimIds: nodes.map((n) => n.claim.claim_id) });
  const evidenceSupport = new Set(nodes.map((n) => n.claim.source_family_id ?? n.claim.claim_id)).size;

  const card = {
    contractVersion: '1.0.0',
    card_id: `hyc-${sha256(`${domains.join('|')}|${relation.subject}|${relation.predicate}|${relation.object}`).slice(0, 16)}`,
    card_type: cardType,
    type_promotion: null,
    originating_domains: domains,
    nodes: nodes.map((n) => ({ claim_id: n.claim.claim_id, revision: n.claim.revision, domain: n.claim.domain, role: n.role })),
    proposed_relation: {
      subject: relation.subject,
      predicate: relation.predicate,
      object: relation.object,
      relation_strength: relation.relation_strength,
      causal_assertion: causalAssertion,
    },
    temporal_ordering: {
      established: temporalEstablished,
      evidence_claim_ids: nodes.filter((n) => n.role === 'mediator' || n.role === 'source').map((n) => n.claim.claim_id),
      event_times: nodes
        .filter((n) => n.claim.event_time || n.claim.published_at)
        .map((n) => ({ node: n.claim.claim_id, time: n.claim.event_time ?? n.claim.published_at })),
    },
    mediators: mediators.length > 0 ? mediators : [{ description: 'no supported mediator identified in the frozen corpus', claim_id: null, evidence_status: 'NOT_FOUND' }],
    confounders,
    alternative_explanations: alternatives,
    scope,
    assumptions,
    falsifiers: falsifiers.length > 0 ? falsifiers : [{ description: 'a replicated finding within the corpus scope that contradicts the proposed relation', observable: 'contradicting claim in the frozen corpus' }],
    test_design: testDesign,
    counterevidence,
    novelty,
    uncertainty: {
      author_confidence: null,
      expert_trust: null,
      measured_calibration: null,
      evidence_support: evidenceSupport,
    },
    stale: {
      is_stale: staleClaimIds.length > 0,
      invalidation_event_ids: invalidationEventIds,
      stale_claim_ids: staleClaimIds,
    },
    status: staleClaimIds.length > 0 ? 'STALE' : 'FRESH',
    created_at: createdAt,
    created_by: createdBy,
  };
  return synthesisValidators().requireValid('hypothesis-card', card);
}

// ---- cross-domain candidate detection ---------------------------------------------

// Deterministic structural pairing: claims from different domains whose
// predicate token sets overlap become candidate relations. Observed
// co-occurrence is recorded as correlation evidence at most.
export function detectCrossDomainCandidates(index, { minPredicateOverlap = 0.5 } = {}) {
  const byDomain = new Map();
  for (const entry of index.entries) {
    if (!entry.domain) continue;
    if (!byDomain.has(entry.domain)) byDomain.set(entry.domain, []);
    byDomain.get(entry.domain).push(entry);
  }
  const domains = [...byDomain.keys()].sort();
  const candidates = [];
  for (let i = 0; i < domains.length; i += 1) {
    for (let j = i + 1; j < domains.length; j += 1) {
      for (const a of byDomain.get(domains[i])) {
        for (const b of byDomain.get(domains[j])) {
          const aTokens = new Set(a.tokens);
          const bTokens = new Set(b.tokens);
          const shared = a.tokens.filter((t) => bTokens.has(t));
          const overlap = shared.length / Math.max(1, Math.min(aTokens.size, bTokens.size));
          if (overlap >= minPredicateOverlap) {
            candidates.push({
              domains: [domains[i], domains[j]],
              a: a.claim_id,
              b: b.claim_id,
              shared_tokens: shared.sort(),
              overlap: Number(overlap.toFixed(3)),
            });
          }
        }
      }
    }
  }
  candidates.sort((x, y) => (y.overlap - x.overlap) || (`${x.a}${x.b}` < `${y.a}${y.b}` ? -1 : 1));
  return candidates;
}

// ---- contradiction surfacing -------------------------------------------------------

export function surfaceContradictions(claims) {
  const contradictions = [];
  for (let i = 0; i < claims.length; i += 1) {
    for (let j = i + 1; j < claims.length; j += 1) {
      const relation = compareClaims(claims[i], claims[j]);
      if (relation.relation === 'CONTRADICTS') {
        contradictions.push({
          claim_a: claims[i].claim_id,
          claim_b: claims[j].claim_id,
          relation: 'CONTRADICTS',
          basis: relation.basis ?? null,
          handling: 'BOTH_SHOWN',
        });
      }
    }
  }
  return contradictions;
}

// ---- synthesis result --------------------------------------------------------------

export function synthesize({
  requestDigest,
  statements, // [{ statement, supporting, contradicting, qualifying, unavailable, staleClaimIds, invalidationEventIds }]
  hypothesisCards = [],
  claimsForContradictions = [],
  abstentions = [],
  coverageGaps = [],
  inputVersions,
  execution,
  testedImplementationCommit = null,
}) {
  const evidenceMaps = statements.map((s) => buildEvidenceMap(s));
  const unresolvedContradictions = surfaceContradictions(claimsForContradictions);

  const incompleteMaps = evidenceMaps.filter((m) => m.status === 'INCOMPLETE').length;
  const staleMaps = evidenceMaps.filter((m) => m.status === 'STALE').length;
  const totalStatements = statements.length;
  const answered = evidenceMaps.filter((m) => m.status === 'FRESH').length;

  // Expert-lens disagreement handling (probe G): when competing explanations
  // carry different lens-backed interpretations, both stay LIVE with explicit
  // disagreement conditions — no popularity or trust-weight vote.
  const competingExplanations = hypothesisCards.map((card) => ({
    description: `${card.card_type}: ${card.proposed_relation.subject} ${card.proposed_relation.predicate} ${card.proposed_relation.object} (${card.originating_domains.join(' + ')})`,
    supporting_claim_ids: card.nodes.map((n) => n.claim_id),
    card_id: card.card_id,
    status: card.status === 'STALE' ? 'WEAKENED' : 'LIVE',
    ...(card.confounders.length > 0 ? { disagreement_conditions: 'disagreement persists while confounders remain UNRESOLVED' } : {}),
  }));

  let status;
  const reasons = [];
  if (unresolvedContradictions.length > 0) {
    // a contradicted statement is not answerable as-is: both sides are shown
    // and the result stays INCOMPLETE — the contradiction is never hidden and
    // never resolved by popularity (todo §5.6, probe G)
    status = 'INCOMPLETE';
    reasons.push(`${unresolvedContradictions.length} unresolved contradiction(s) shown on both sides`);
  }
  if (staleMaps > 0) {
    status = 'INCOMPLETE';
    reasons.push(`${staleMaps} evidence map(s) STALE: upstream claims invalidated; recomputation or explicit abstention required`);
  }
  if (incompleteMaps > 0) {
    status = status === 'INCOMPLETE' ? status : 'INCOMPLETE';
    reasons.push(`${incompleteMaps} evidence map(s) without entailing support: statements are not proven by cited spans`);
  }
  if (abstentions.length > 0) {
    reasons.push(`${abstentions.length} abstention(s): ${[...new Set(abstentions.map((a) => a.reason))].join(', ')}`);
  }
  if (status !== 'INCOMPLETE' && answered === totalStatements && abstentions.length === 0) {
    status = 'READY_FOR_REVIEW';
    reasons.push('all statements carry entailing evidence; ready for independent review, not for unreviewed publication');
  }
  if (status === undefined) {
    status = 'INCOMPLETE';
    reasons.push('insufficient coverage for a complete synthesis');
  }

  const result = {
    contractVersion: '1.0.0',
    result_id: `syn-${requestDigest.slice(0, 16)}`,
    request_digest: requestDigest,
    input_versions: inputVersions,
    evidence_maps: evidenceMaps,
    hypothesis_cards: hypothesisCards,
    competing_explanations: competingExplanations,
    unresolved_contradictions: unresolvedContradictions,
    coverage: {
      questions_total: totalStatements,
      answered,
      abstained: abstentions.length,
      coverage_gaps: coverageGaps,
    },
    abstentions,
    status,
    reasons,
    execution,
    testedImplementationCommit,
  };
  return synthesisValidators().requireValid('synthesis-result', result);
}

export { sha256 };
