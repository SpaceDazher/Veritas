// S2-005 synthesis engine tests: entailment discipline (numbers, negation,
// units), EvidenceMap statuses and family collapse, hypothesis typing and
// causal discipline, novelty scoping, uncertainty separation and result
// statuses (todo §5, §6).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  entailmentOf,
  buildEvidenceMap,
  buildHypothesisCard,
  classifyRelation,
  assessNovelty,
  detectCrossDomainCandidates,
  synthesize,
} from '../../src/lib/synthesis/synthesis.mjs';
import { buildRetrievalIndex } from '../../src/lib/synthesis/retrieval.mjs';

const CLAIM_TEXT = 'Air pollution exposure increased asthma incidence by 18% among urban children in 2023.';

function claim(claimId, text, overrides = {}) {
  return {
    claim_id: claimId,
    revision: 1,
    workspace_id: 'ws-corpus',
    tenant_id: 'tn-corpus',
    acl: { visibility: 'project', workspace_id: 'ws-corpus', tenant_id: 'tn-corpus', allowed_workspace_ids: [], allowed_principal_ids: [] },
    epistemic_type: 'FACT_CLAIM',
    polarity: 'affirmative',
    normalized_text: text,
    original_text: text,
    lifecycle: 'PROPOSED',
    segment_id: `seg-${claimId}`,
    span: { start: 0, end: text.length },
    quote_digest: 'b'.repeat(64),
    source_family_id: `fam-${claimId}`,
    domain: 'epidemiology',
    published_at: '2024-01-01T09:00:00.000Z',
    subject: 'air pollution exposure',
    predicate: 'increased',
    object: 'asthma incidence',
    ...overrides,
  };
}

describe('S2-005 entailment discipline (probe L core)', () => {
  test('a faithful restatement entails', () => {
    assert.equal(entailmentOf(CLAIM_TEXT, CLAIM_TEXT), 'ENTAILS');
  });

  test('a changed number does not entail', () => {
    const drifted = CLAIM_TEXT.replace('18%', '50%');
    assert.equal(entailmentOf(drifted, CLAIM_TEXT), 'NOT_ENTAILING');
  });

  test('a dropped negation does not entail', () => {
    assert.equal(entailmentOf('Air pollution did not increase asthma incidence.', 'Air pollution increased asthma incidence.'), 'NOT_ENTAILING');
    assert.equal(entailmentOf('Air pollution increased asthma incidence.', 'Air pollution did not increase asthma incidence.'), 'NOT_ENTAILING');
  });

  test('a changed unit does not entail', () => {
    assert.equal(entailmentOf(CLAIM_TEXT.replace('18%', '18 points'), CLAIM_TEXT), 'NOT_ENTAILING');
  });
});

describe('S2-005 evidence maps', () => {
  test('an entailing support yields a FRESH map', () => {
    const map = buildEvidenceMap({ statement: CLAIM_TEXT, supporting: [{ claim: claim('clm-a', CLAIM_TEXT), hit: null }] });
    assert.equal(map.status, 'FRESH');
    assert.equal(map.entries[0].entailment_status, 'ENTAILS');
    assert.equal(map.family_collapse.independent_evidence_count, 1);
  });

  test('ten reprints of one upstream collapse to one family (probe F core)', () => {
    const reprints = Array.from({ length: 10 }, (_, i) => claim(`clm-r${i}`, `${['', 'Reuters reported that ', 'Analysts confirmed that '][i % 3]}${CLAIM_TEXT}`, { source_family_id: 'fam-one' }));
    const map = buildEvidenceMap({ statement: CLAIM_TEXT, supporting: reprints.map((c) => ({ claim: c, hit: null })) });
    assert.equal(map.family_collapse.independent_evidence_count, 1);
    assert.equal(map.family_collapse.collapsed_members, 9);
  });

  test('no entailing support yields an INCOMPLETE map', () => {
    const map = buildEvidenceMap({ statement: 'Quantum tunnelling explains enzyme catalysis.', supporting: [{ claim: claim('clm-a', CLAIM_TEXT), hit: null }] });
    assert.equal(map.status, 'INCOMPLETE');
  });

  test('an access gap makes the map INCOMPLETE even with entailing support', () => {
    const map = buildEvidenceMap({
      statement: CLAIM_TEXT,
      supporting: [{ claim: claim('clm-a', CLAIM_TEXT), hit: null }],
      unavailable: [{ what_is_missing: 'access-blocked evidence', kind: 'ACCESS_DENIED', required_for: 'complete answer' }],
    });
    assert.equal(map.status, 'INCOMPLETE');
  });

  test('stale inputs make the map STALE with propagation ids', () => {
    const map = buildEvidenceMap({
      statement: CLAIM_TEXT,
      supporting: [{ claim: claim('clm-a', CLAIM_TEXT), hit: null }],
      staleClaimIds: ['clm-a'],
      invalidationEventIds: ['evt-1'],
    });
    assert.equal(map.status, 'STALE');
    assert.deepEqual(map.stale.stale_claim_ids, ['clm-a']);
  });
});

describe('S2-005 hypothesis typing and causal discipline', () => {
  const nodes = [
    { claim: claim('clm-a', CLAIM_TEXT, { domain: 'epidemiology' }), role: 'source' },
    { claim: claim('clm-b', 'Bike lane expansion increased cycling trips by 24% in Copenhagen during 2023.', { domain: 'urban_mobility' }), role: 'target' },
  ];

  test('classification matrix: evidence strength determines the card type', () => {
    assert.equal(classifyRelation({ relationStrength: 'ANALOGICAL_STRUCTURE', mediatorStatus: 'NOT_FOUND', temporalEstablished: false }), 'ANALOGY');
    assert.equal(classifyRelation({ relationStrength: 'CORRELATION_EVIDENCE', mediatorStatus: 'NOT_FOUND', temporalEstablished: false }), 'HYPOTHESIS');
    assert.equal(classifyRelation({ relationStrength: 'TEMPORAL_CO-OCCURRENCE', mediatorStatus: 'NOT_FOUND', temporalEstablished: false }), 'HYPOTHESIS');
    assert.equal(classifyRelation({ relationStrength: 'MEDIATED_PATHWAY', mediatorStatus: 'PROPOSED', temporalEstablished: true }), 'HYPOTHESIS');
    assert.equal(classifyRelation({ relationStrength: 'MEDIATED_PATHWAY', mediatorStatus: 'SUPPORTED', temporalEstablished: true }), 'MECHANISM_CLAIM');
    assert.equal(classifyRelation({ relationStrength: 'EXPERIMENTAL', mediatorStatus: 'SUPPORTED', temporalEstablished: true }), 'MECHANISM_CLAIM');
    assert.equal(classifyRelation({ relationStrength: 'EXPERIMENTAL', mediatorStatus: 'NOT_FOUND', temporalEstablished: false }), 'HYPOTHESIS');
  });

  test('a causal assertion without MECHANISM_CLAIM evidence is rejected', () => {
    assert.throws(
      () => buildHypothesisCard({
        domains: ['epidemiology', 'urban_mobility'],
        nodes,
        relation: { subject: 'exposure', predicate: 'increases', object: 'incidence', relation_strength: 'CORRELATION_EVIDENCE', causal_assertion: true },
        testDesign: 'paired comparison',
      }),
      /causal assertion requires MECHANISM_CLAIM/,
    );
  });

  test('a mediated pathway with supported mediator and temporal ordering is a MECHANISM_CLAIM', () => {
    const card = buildHypothesisCard({
      domains: ['epidemiology', 'urban_mobility'],
      nodes: [...nodes, { claim: nodes[1].claim, role: 'mediator' }],
      relation: { subject: 'exposure', predicate: 'increases', object: 'incidence', relation_strength: 'MEDIATED_PATHWAY', causal_assertion: null },
      mediators: [{ description: 'mediator', claim_id: nodes[1].claim.claim_id, evidence_status: 'SUPPORTED' }],
      testDesign: 'paired comparison',
    });
    assert.equal(card.card_type, 'MECHANISM_CLAIM');
    assert.equal(card.proposed_relation.causal_assertion, true);
  });

  test('uncertainty fields stay separate; evidence support is family-collapsed count', () => {
    const card = buildHypothesisCard({
      domains: ['epidemiology', 'urban_mobility'],
      nodes,
      relation: { subject: 'exposure', predicate: 'increases', object: 'incidence', relation_strength: 'CORRELATION_EVIDENCE', causal_assertion: null },
      testDesign: 'paired comparison',
    });
    const u = card.uncertainty;
    assert.equal(u.author_confidence, null);
    assert.equal(u.expert_trust, null);
    assert.equal(u.measured_calibration, null);
    assert.equal(typeof u.evidence_support, 'number');
    // no derived truth score exists anywhere on the card
    assert.equal(JSON.stringify(card).includes('truth_score'), false);
  });

  test('every card carries falsifiers and a test design', () => {
    const card = buildHypothesisCard({
      domains: ['epidemiology', 'urban_mobility'],
      nodes,
      relation: { subject: 'exposure', predicate: 'increases', object: 'incidence', relation_strength: 'ANALOGICAL_STRUCTURE', causal_assertion: null },
      testDesign: 'paired comparison',
    });
    assert.ok(card.falsifiers.length >= 1);
    assert.equal(typeof card.test_design, 'string');
  });
});

describe('S2-005 novelty scoping', () => {
  test('novelty is measured only against the frozen corpus and horizon', () => {
    const index = buildRetrievalIndex({
      claims: [claim('clm-prior', 'Review studies showed congestion pricing cut asthma admissions by 9% in 2023.')],
      scope: { workspaceId: 'ws-corpus', principalId: 'prn-user-1' },
      asOf: '2025-06-01T00:00:00.000Z',
    });
    const prior = assessNovelty({ subject: 'congestion pricing', predicate: 'asthma admissions', index, corpus: 'corpus/s2-005@1.0.0', horizon: 'frozen corpus + lock date' });
    assert.equal(prior.assessment, 'similar_prior_found');
    assert.equal(prior.corpus, 'corpus/s2-005@1.0.0');
    const novel = assessNovelty({ subject: 'quantum coherence', predicate: 'photosynthetic efficiency', index, corpus: 'corpus/s2-005@1.0.0', horizon: 'frozen corpus + lock date' });
    assert.equal(novel.assessment, 'novel_to_selected_corpus');
  });

  test('no index means NOT_ASSESSED, never a novelty claim', () => {
    assert.equal(assessNovelty({ subject: 'x', predicate: 'y', index: null }).assessment, 'NOT_ASSESSED');
  });
});

describe('S2-005 cross-domain detection and result statuses', () => {
  test('structural candidates pair claims across domains only', () => {
    const index = buildRetrievalIndex({
      claims: [
        claim('clm-a', CLAIM_TEXT, { domain: 'epidemiology' }),
        claim('clm-b', 'Asthma incidence increased by 24% among urban cycling commuters in 2023.', { domain: 'urban_mobility' }),
        claim('clm-c', 'Asthma incidence increased by 31% among coastal fishing crews in 2023.', { domain: 'marine_ecology' }),
      ],
      scope: { workspaceId: 'ws-corpus', principalId: 'prn-user-1' },
      asOf: '2025-06-01T00:00:00.000Z',
    });
    const candidates = detectCrossDomainCandidates(index);
    assert.ok(candidates.length >= 1);
    for (const candidate of candidates) {
      assert.equal(candidate.domains[0] === candidate.domains[1], false);
    }
  });

  test('all-entailing statements with no gaps produce READY_FOR_REVIEW', () => {
    const result = synthesize({
      requestDigest: 'd'.repeat(64),
      statements: [{ statement: CLAIM_TEXT, supporting: [{ claim: claim('clm-a', CLAIM_TEXT), hit: null }], contradicting: [], qualifying: [], unavailable: [], staleClaimIds: [], invalidationEventIds: [] }],
      hypothesisCards: [],
      claimsForContradictions: [],
      abstentions: [],
      coverageGaps: [],
      inputVersions: { contracts_version: '1.0.0', corpus_version: '1.0.0', index_version: '1.0.0', retrieval_model_version: '1.0.0' },
      execution: { executor_id: 'test', pid: process.pid, nonce: 'n-test-00000002' },
    });
    assert.equal(result.status, 'READY_FOR_REVIEW');
  });

  test('abstentions and gaps force INCOMPLETE', () => {
    const result = synthesize({
      requestDigest: 'd'.repeat(64),
      statements: [],
      hypothesisCards: [],
      claimsForContradictions: [],
      abstentions: [{ reason: 'SOURCE_MISSING' }],
      coverageGaps: [{ query: 'q', reason: 'SOURCE_MISSING' }],
      inputVersions: { contracts_version: '1.0.0', corpus_version: '1.0.0', index_version: '1.0.0', retrieval_model_version: '1.0.0' },
      execution: { executor_id: 'test', pid: process.pid, nonce: 'n-test-00000003' },
    });
    assert.equal(result.status, 'INCOMPLETE');
    assert.equal(result.coverage.coverage_gaps[0].reason, 'SOURCE_MISSING');
  });
});
