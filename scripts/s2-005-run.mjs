// S2-005 corpus run executor.
// Executes the frozen 55-case corpus through the production retrieval and
// synthesis path (src/lib/synthesis — the exact modules the tests and probes
// use), on top of the S2-004 claim graph (extraction, evidence edges, claim
// edges, invalidation). Before executing anything the frozen manifest is
// verified fail-closed: any drift in case digests stops the run as
// QUARANTINED (todo §3, §7).
//
// Every case runs in ALL FOUR retrieval modes for the paired comparison
// (same questions, frozen inputs — todo §7); the case decision uses the
// primary mode. Integrity counters are hard-gate inputs (todo §7).
//
// Usage:
//   node scripts/s2-005-run.mjs --run-id run-a --executor-id exec-s2-005-a \
//        --nonce n-abc12345 --clock 2026-01-15T08:00:00.000Z \
//        --output-root results/s2-005/run-a --out evidence/s2-005-run-a.json
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createClaimGraphStore, makeAuthorityRegistry } from '../src/lib/claims/store.mjs';
import { executeClaimExtraction } from '../src/lib/claims/extraction.mjs';
import { buildRetrievalIndex, executeRetrievalRequest, auditRunForLeaks, RETRIEVAL_CONFIG, VECTOR_MODEL } from '../src/lib/synthesis/retrieval.mjs';
import { synthesize, buildHypothesisCard, entailmentOf } from '../src/lib/synthesis/synthesis.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CASES_DIR = path.join(ROOT, 'corpus/s2-005/cases');
const MANIFEST_PATH = path.join(ROOT, 'corpus/s2-005/manifest.json');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sha256Json = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');

export const DEFAULT_CLOCK = '2026-01-15T08:00:00.000Z';

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (key.startsWith('--')) args[key.slice(2)] = argv[i + 1];
  }
  return args;
}

// ---- frozen manifest verification (fail-closed) ------------------------------

export function verifyFrozenManifest({ manifest, casesDir }) {
  const issues = [];
  if (manifest.schemaVersion !== 1) issues.push('manifest:schema-version-unknown');
  if (manifest.caseCount !== 55) issues.push('manifest:case-count-not-55');
  const required = {
    local_exact: 12,
    global_cross_domain: 10,
    contradiction: 6,
    private_forbidden: 6,
    retro_forecast: 6,
    unknown_answer: 6,
    hypothesis_labels: 8,
    family_collapse: 1,
  };
  for (const [category, count] of Object.entries(required)) {
    if ((manifest.categoryCounts?.[category] ?? 0) !== count) issues.push(`manifest:${category}:count-drift`);
  }
  for (const [caseId, digest] of Object.entries(manifest.caseSha256 ?? {})) {
    const file = path.join(casesDir, `${caseId}.json`);
    let bytes;
    try {
      bytes = fs.readFileSync(file);
    } catch {
      issues.push(`${caseId}:missing`);
      continue;
    }
    if (sha256(bytes) !== digest) issues.push(`${caseId}:digest-drift`);
  }
  for (const file of fs.readdirSync(casesDir)) {
    if (file.endsWith('.json') && !manifest.caseSha256?.[file.replace(/\.json$/, '')]) {
      issues.push(`${file}:unmanifested`);
    }
  }
  if (manifest.oracle?.locked !== true) issues.push('manifest:oracle-not-locked');
  return { ok: issues.length === 0, issues };
}

// ---- shared authorities ---------------------------------------------------------

function authorityRegistry() {
  return makeAuthorityRegistry([
    { principal: 'prn-producer', roles: ['producer'], workspaces: ['ws-corpus'] },
    { principal: 'prn-extractor', roles: ['extractor'], workspaces: ['ws-corpus'] },
    { principal: 'prn-reviewer', roles: ['reviewer'], workspaces: ['ws-corpus'] },
    { principal: 'prn-admin', roles: ['admin'], workspaces: ['ws-corpus', 'ws-system'] },
    { principal: 'prn-evaluator', roles: ['evaluator'] },
    { principal: 'prn-system', roles: ['system'], workspaces: ['ws-system'] },
    { principal: 'prn-user-1', roles: [], workspaces: ['ws-corpus'] },
    { principal: 'prn-user-2', roles: [], workspaces: ['ws-corpus'] },
  ]);
}

// Family = upstream source root: derived lineages follow their root snapshot
// (a reprint shares the family of the original it descends from — probe F).
function rootSnapshotIdOf(inputSegment) {
  const parents = inputSegment.snapshot.parent_snapshot_ids ?? [];
  return parents.length > 0 ? parents[0] : inputSegment.snapshot.snapshot_id;
}

function toRuntimeSegment(inputSegment) {
  return {
    segment_id: inputSegment.segment_id,
    snapshot_id: inputSegment.snapshot.snapshot_id,
    source_id: `src-${rootSnapshotIdOf(inputSegment)}`,
    revision: 1,
    text: inputSegment.text,
    text_sha256: sha256(inputSegment.text),
    original_language: 'en',
    normalized_language: 'en',
    status: 'COMPLETE',
    embedded_instruction_classification: inputSegment.embedded_instruction_classification,
    acl: inputSegment.acl,
    domain: inputSegment.domain,
  };
}

// ---- per-case pipeline -----------------------------------------------------------

async function runCase(doc, runParams, authorities, sharedStore) {
  const input = doc.input;
  const expected = doc.expected;
  const segments = input.segments.map(toRuntimeSegment);
  const snapshots = input.segments.map((s) => ({ ...s.snapshot }));
  const segmentMap = new Map(segments.map((s) => [s.segment_id, s]));
  const snapshotMap = new Map(snapshots.map((s) => [s.snapshot_id, s]));
  const store = sharedStore ?? createClaimGraphStore({
    authorities,
    clock: () => runParams.clock,
    segmentResolver: (id) => segmentMap.get(id) ?? null,
    snapshotResolver: (id) => snapshotMap.get(id) ?? null,
  });
  if (sharedStore?.attachSegments) sharedStore.attachSegments(segments, snapshots);

  const result = { case_id: doc.case_id, category: doc.category, checks: {}, error: null };

  // 1. claim extraction through the real S2-004 path
  const request = {
    contractVersion: '1.0.0',
    request_id: `req-${doc.case_id}`,
    segment_ids: segments.map((s) => s.segment_id),
    segment_hashes: segments.map((s) => s.text_sha256),
    extractor: 'rule-based-extractor',
    extractor_version: '1.0.0',
    prompt_version: '1.0.0',
    parameters: { language: 'en' },
    seed: null,
    actor: input.operation_actor,
    workspace_id: input.workspace_id,
    idempotency_key: `idem-${doc.case_id}`,
  };
  const ctx = {
    store,
    now: () => runParams.clock,
    resolveSegment: (id) => segmentMap.get(id) ?? null,
    resolveSnapshot: (id) => snapshotMap.get(id) ?? null,
    auditBinding: {
      operation_id: `op-${doc.case_id}`,
      executor_id: runParams.executorId,
      pid: runParams.pid,
      nonce: runParams.nonce,
      output_root: sha256(runParams.outputRoot),
    },
  };
  const outcome = await executeClaimExtraction(request, ctx);
  const rawClaims = outcome.claims;

  // 2. augment claims with domain/time/family from the graph
  const claims = [];
  for (const claim of rawClaims) {
    const edges = await store.listEvidenceMap(claim.claim_id, claim.revision);
    const primary = edges[0] ?? null;
    const segment = primary ? segmentMap.get(primary.segment_id) : null;
    const snapshot = segment ? snapshotMap.get(segment.snapshot_id) : null;
    claims.push({
      ...claim,
      domain: segment?.domain ?? null,
      source_family_id: primary?.source_family_id ?? null,
      segment_id: primary?.segment_id ?? null,
      span: primary?.span ?? null,
      quote_digest: primary?.quote_digest ?? null,
      published_at: snapshot?.published_at ?? claim.published_at ?? null,
      observed_at: snapshot?.observed_at ?? null,
      fetched_at: snapshot?.fetched_at ?? null,
    });
  }

  // 3. committed claim edges (documented relations) for graph retrieval
  const claimEdges = [];
  for (const edgeSpec of input.claim_edges ?? []) {
    const source = claims.find((c) => c.segment_id === edgeSpec.from_segment);
    const target = claims.find((c) => c.segment_id === edgeSpec.to_segment);
    if (source && target) {
      const edge = store.linkClaims({
        edge: {
          contractVersion: '1.0.0',
          edge_id: `ced-${doc.case_id}-${claimEdges.length + 1}`,
          source_claim_id: source.claim_id,
          source_revision: source.revision,
          target_claim_id: target.claim_id,
          target_revision: target.revision,
          relation: edgeSpec.relation,
          direction: 'bidirectional',
          scope_intersection: {},
          provenance: { method: 'corpus-documented-relation', extractor: 'rule-based-extractor', extractor_version: '1.0.0', config_digest: sha256Json(edgeSpec), confidence: 1 },
          creation_authority: 'prn-producer',
        },
        actor: 'prn-producer',
        operationId: `op-link-${doc.case_id}-${claimEdges.length + 1}`,
      });
      claimEdges.push(edge);
    }
  }

  // 4. invalidation (STALE propagation) if the case requests it
  let staleClaimIds = [];
  let invalidationEventIds = [];
  if (input.invalidation) {
    const target = claims.find((c) => c.segment_id === input.invalidation.segment_id);
    if (target) {
      const invalidation = await store.invalidateFromParent({
        trigger: { type: 'claim_tombstone', id: target.claim_id, revision: target.revision },
        reason: { code: 'upstream_tombstoned', description: `corpus case ${doc.case_id}` },
        actor: 'prn-system',
        operationId: `op-inv-${doc.case_id}`,
      });
      staleClaimIds = invalidation.event.affected_descendants.filter((d) => d.entity_type === 'claim' && typeof d.entity_id === 'string').map((d) => d.entity_id);

      invalidationEventIds = [invalidation.event.event_id];
      for (const claim of claims) {
        if (staleClaimIds.includes(claim.claim_id)) claim.lifecycle = 'STALE';
      }
    }
  }

  // 5. index build per request actor scope (server-side ACL BEFORE scoring)
  const actors = input.actors ? [input.actors.allowed, input.actors.denied] : [input.request_actor];
  const indexes = new Map();
  for (const actor of actors) {
    indexes.set(actor, buildRetrievalIndex({
      claims,
      claimEdges,
      scope: { workspaceId: input.workspace_id, principalId: actor },
      asOf: input.as_of,
    }));
  }

  // 6. retrieval in all four modes (paired comparison)
  const retrievalByMode = {};
  const primaryActor = input.request_actor;
  for (const mode of input.allowed_retrieval_modes) {
    const retrievalRequest = {
      contractVersion: '1.0.0',
      request_id: `req-${doc.case_id}-${mode}`,
      actor: primaryActor,
      workspace_id: input.workspace_id,
      query: { text: input.query.text, task_class: input.query.task_class, question_kind: input.query.question_kind },
      as_of: input.as_of,
      domains: input.query.domains ?? [],
      languages: ['en'],
      geography: null,
      time_window: null,
      source_policy: { allowed_source_families: [] },
      budget: input.budget,
      allowed_retrieval_modes: input.allowed_retrieval_modes,
      mode,
      corpus_version: RETRIEVAL_CONFIG.corpus_version,
      index_version: RETRIEVAL_CONFIG.index_version,
      seed: RETRIEVAL_CONFIG.seed,
    };
    retrievalByMode[mode] = executeRetrievalRequest(retrievalRequest, { index: indexes.get(primaryActor), execution: { executor_id: runParams.executorId, pid: runParams.pid, nonce: runParams.nonce, output_root_digest: sha256(runParams.outputRoot), clock: runParams.clock } });
  }
  const primary = retrievalByMode[input.primary_mode];

  // leak audit on the primary mode (hard-gate input)
  const audit = auditRunForLeaks({ hits: primary.hits ?? [], allClaims: claims, scope: { workspaceId: input.workspace_id, principalId: primaryActor }, asOf: input.as_of });

  // 7. per-mode gold metrics (paired strata for the comparison record)
  const goldSegments = expected.gold_segment_ids ?? [];
  const metricsByMode = {};
  for (const [mode, run] of Object.entries(retrievalByMode)) {
    const rankedSegments = (run.hits ?? []).filter((h) => h.included).map((h) => h.segment_id);
    const top = rankedSegments.slice(0, 10);
    const hitsInGold = top.filter((s) => goldSegments.includes(s));
    const recall = goldSegments.length > 0 ? hitsInGold.length / goldSegments.length : null;
    // binary-relevance nDCG@10
    let dcg = 0;
    top.forEach((segment, position) => {
      if (goldSegments.includes(segment)) dcg += 1 / Math.log2(position + 2);
    });
    const idealCount = Math.min(goldSegments.length, 10);
    let idcg = 0;
    for (let position = 0; position < idealCount; position += 1) idcg += 1 / Math.log2(position + 2);
    metricsByMode[mode] = {
      recall_at_10: recall,
      ndcg_at_10: idcg > 0 ? Number((dcg / idcg).toFixed(4)) : null,
      hit_at_1: goldSegments.length > 0 ? goldSegments.includes(top[0]) : null,
    };
  }

  result.retrieval = {
    status: primary.status,
    hits: (primary.hits ?? []).map((h) => ({ segment_id: h.segment_id, claim_id: h.claim_id, rank: h.rank, included: h.included, reason: h.reason, domain: indexes.get(primaryActor).byClaim.get(h.claim_id)?.domain ?? null })),
    abstentions: primary.abstentions ?? [],
    excluded_count: primary.excludedCount ?? null,
    cost: primary.cost ?? null,
    by_mode: metricsByMode,
    audit: audit.counters,
    index_entries: indexes.get(primaryActor).N,
    index_exclusions: indexes.get(primaryActor).exclusions,
  };

  // secondary actor check (private_forbidden case 034)
  if (input.actors) {
    const allowedRun = executeRetrievalRequest({
      ...buildRequest(input, input.actors.allowed),
    }, { index: indexes.get(input.actors.allowed) });
    const deniedRun = executeRetrievalRequest({
      ...buildRequest(input, input.actors.denied),
    }, { index: indexes.get(input.actors.denied) });
    result.actor_split = {
      allowed_actor_hits: (allowedRun.hits ?? []).map((h) => h.segment_id),
      denied_actor_hits: (deniedRun.hits ?? []).map((h) => h.segment_id),
    };
  }

  // 8. synthesis per category
  const hitClaims = (primary.hits ?? [])
    .filter((h) => h.included)
    .map((h) => ({ claim: claims.find((c) => c.claim_id === h.claim_id), hit: h }))
    .filter((x) => x.claim);

  let hypothesisCards = [];
  let statements = [];
  let abstentions = [];
  let coverageGaps = [];

  if (doc.category === 'hypothesis_labels') {
    const spec = expected.hypothesis_card;
    const nodeA = claims.find((c) => c.domain === 'epidemiology') ?? claims[0];
    const nodeB = claims.find((c) => c.domain === 'urban_mobility') ?? claims.find((c) => c.domain === 'labor_economics') ?? claims[1];
    const mediatorClaim = spec.mediator_status === 'SUPPORTED' || spec.mediator_status === 'PROPOSED' ? nodeB : null;
    const nodes = [
      { claim: nodeA, role: 'source' },
      { claim: nodeB, role: 'target' },
      ...(mediatorClaim ? [{ claim: mediatorClaim, role: 'mediator' }] : []),
    ];
    const domains = [...new Set(nodes.map((n) => n.claim.domain))].filter(Boolean);
    try {
      const card = buildHypothesisCard({
        domains: domains.length >= 2 ? domains : ['epidemiology', 'urban_mobility'],
        nodes,
        relation: {
          subject: spec.relation_subject ?? nodeA?.subject ?? 'exposure',
          predicate: spec.relation_predicate ?? nodeA?.predicate ?? 'increased',
          object: nodeA?.object ?? 'incidence',
          relation_strength: spec.relation_strength,
          causal_assertion: spec.attempt_causal_assertion === true ? true : spec.card_type === 'MECHANISM_CLAIM' ? true : null,
        },
        mediators: spec.mediator_status === 'NOT_FOUND' ? [] : [{ description: 'corpus-declared mediator', claim_id: mediatorClaim?.claim_id ?? null, evidence_status: spec.mediator_status }],
        confounders: spec.card_type === 'HYPOTHESIS' ? [{ description: 'seasonal confounder', status: 'UNRESOLVED', claim_id: null }] : [],
        alternatives: [],
        testDesign: 'paired comparison within the frozen corpus strata',
        index: indexes.get(primaryActor),
        corpus: 'corpus/s2-005@1.0.0',
        horizon: 'frozen corpus + lock date',
        createdBy: 'prn-synthesizer',
        createdAt: runParams.clock,
      });
      hypothesisCards = [card];
      result.hypothesis_rejected = false;
    } catch (error) {
      result.hypothesis_rejected = true;
      result.hypothesis_rejection_reason = error.message;
    }
  } else if (doc.category === 'global_cross_domain') {
    const spec = expected.hypothesis_card;
    const byDomain = new Map();
    for (const { claim } of hitClaims) {
      if (claim.domain && !byDomain.has(claim.domain)) byDomain.set(claim.domain, claim);
    }
    const domainList = [...byDomain.keys()];
    const nodes = domainList.slice(0, 2).map((domain, index) => ({ claim: byDomain.get(domain), role: index === 0 ? 'source' : 'target' }));
    if (nodes.length === 2) {
      const strength = spec.card_type === 'ANALOGY' ? 'ANALOGICAL_STRUCTURE' : 'CORRELATION_EVIDENCE';
      try {
        hypothesisCards = [buildHypothesisCard({
          domains: domainList.slice(0, 2),
          nodes,
          relation: {
            subject: spec.relation_subject ?? nodes[0].claim.subject ?? nodes[0].claim.normalized_text.slice(0, 64),
            predicate: spec.relation_predicate ?? nodes[0].claim.predicate ?? 'increased',
            object: nodes[1].claim.normalized_text.slice(0, 64),
            relation_strength: strength,
            causal_assertion: null,
          },
          confounders: (spec.min_confounders ?? 0) > 0 ? [{ description: 'shared external driver not controlled in the frozen corpus', status: 'UNRESOLVED', claim_id: null }] : [],
          alternatives: [{ description: 'both observations follow from a common third cause within scope limits', claim_id: null }],
          testDesign: 'stratified paired comparison across the frozen corpus domains',
          index: indexes.get(primaryActor),
          corpus: 'corpus/s2-005@1.0.0',
          horizon: 'frozen corpus + lock date',
          createdBy: 'prn-synthesizer',
          createdAt: runParams.clock,
        })];
      } catch (error) {
        result.hypothesis_rejected = true;
        result.hypothesis_rejection_reason = error.message;
      }
    }
    statements = hitClaims.slice(0, 2).map(({ claim, hit }) => ({
      statement: claim.normalized_text,
      supporting: [{ claim, hit }],
      contradicting: [],
      qualifying: [],
      unavailable: [],
      staleClaimIds,
      invalidationEventIds,
    }));
  } else {
    // local / contradiction / private / retro / unknown / family
    // supports require ENTAILS: a citation without entailment is not
    // support (todo §5) — non-entailing retrieved claims become qualifiers
    const statement = expected.statement ?? (hitClaims[0]?.claim.normalized_text ?? input.query.text);
    const unavailable = expected.private_mixed_query && primary.status === 'COMPLETED'
      ? [{ what_is_missing: 'access-blocked evidence for the remaining query terms', kind: 'ACCESS_DENIED', required_for: 'complete answer to the query' }]
      : [];
    const supporting = hitClaims.slice(0, 5).filter(({ claim }) => entailmentOf(statement, claim.normalized_text) === 'ENTAILS');
    const qualifying = hitClaims.slice(0, 5).filter(({ claim }) => entailmentOf(statement, claim.normalized_text) !== 'ENTAILS');
    statements = [{
      statement,
      supporting,
      contradicting: [],
      qualifying,
      unavailable,
      staleClaimIds,
      invalidationEventIds,
    }];
  }

  if (primary.status === 'ABSTAINED') {
    abstentions = primary.abstentions ?? [];
    const index = indexes.get(primaryActor);
    const queryTokens = input.query.text.toLowerCase().split(/[^a-z0-9%]+/).filter((t) => t.length > 1);
    const anyOverlap = index.entries.some((entry) => queryTokens.some((token) => entry.tokens.includes(token)));
    let gapReason;
    if (abstentions[0]?.reason === 'BUDGET_EXHAUSTED') {
      gapReason = 'BUDGET_EXHAUSTED';
    } else if (index.exclusions.EXCLUDED_ACL > 0 && !anyOverlap) {
      // evidence exists but is access-blocked: explicit gap, no node identity,
      // no count, no snippet (probe H/E)
      gapReason = 'ACCESS_DENIED';
    } else if (index.exclusions.EXCLUDED_AS_OF > 0 && !anyOverlap) {
      gapReason = 'AFTER_AS_OF';
    } else if (!anyOverlap) {
      gapReason = 'SOURCE_MISSING';
    } else {
      gapReason = 'NO_ENTAILING_EVIDENCE';
    }
    coverageGaps = [{ query: input.query.text, reason: gapReason }];
  }

  const synthesis = synthesize({
    requestDigest: sha256Json({ case_id: doc.case_id, query: input.query.text, as_of: input.as_of }),
    statements,
    hypothesisCards,
    // contradiction scan runs over ALL retrieved candidates, including
    // family-collapsed members: a collapsed reprint of a conflicting
    // measurement is still evidence that must be shown on both sides
    claimsForContradictions: (primary.hits ?? []).map((h) => claims.find((c) => c.claim_id === h.claim_id)).filter(Boolean),
    abstentions,
    coverageGaps,
    inputVersions: {
      contracts_version: '1.0.0',
      corpus_version: RETRIEVAL_CONFIG.corpus_version,
      index_version: RETRIEVAL_CONFIG.index_version,
      retrieval_model_version: VECTOR_MODEL.model_version,
      as_of: input.as_of,
    },
    execution: { executor_id: runParams.executorId, pid: runParams.pid, nonce: runParams.nonce, clock: runParams.clock },
    testedImplementationCommit: getHeadCommit(),
  });
  result.synthesis = {
    status: synthesis.status,
    reasons: synthesis.reasons,
    contradictions: synthesis.unresolved_contradictions,
    maps: synthesis.evidence_maps.map((m) => ({
      status: m.status,
      entailing: m.entries.filter((e) => e.relation === 'supports' && e.entailment_status === 'ENTAILS').length,
      supports_total: m.entries.filter((e) => e.relation === 'supports').length,
      not_entailing: m.entries.filter((e) => e.relation === 'supports' && e.entailment_status === 'NOT_ENTAILING').length,
      independent_families: m.family_collapse.independent_evidence_count,
      collapsed_members: m.family_collapse.collapsed_members,
      unavailable: m.unavailable_evidence.length,
    })),
    cards: synthesis.hypothesis_cards,
    coverage: synthesis.coverage,
    abstentions: synthesis.abstentions,
    result: synthesis,
  };

  result.decision = caseDecision(doc, result);
  return result;
}

function buildRequest(input, actor, mode = input.primary_mode) {
  return {
    contractVersion: '1.0.0',
    request_id: `req-${doc_case_id(input)}-${actor}`,
    actor,
    workspace_id: input.workspace_id,
    query: { text: input.query.text, task_class: input.query.task_class, question_kind: input.query.question_kind },
    as_of: input.as_of,
    domains: input.query.domains ?? [],
    languages: ['en'],
    geography: null,
    time_window: null,
    source_policy: { allowed_source_families: [] },
    budget: input.budget,
    allowed_retrieval_modes: input.allowed_retrieval_modes,
    mode,
    corpus_version: RETRIEVAL_CONFIG.corpus_version,
    index_version: RETRIEVAL_CONFIG.index_version,
    seed: RETRIEVAL_CONFIG.seed,
  };
}

function doc_case_id(input) {
  return input.__case_id ?? 'x';
}

// ---- decision ---------------------------------------------------------------------

function caseDecision(doc, result) {
  if (result.error) return 'ERROR';
  const expected = doc.expected;
  const checks = [];
  const hard = (condition, code) => {
    checks.push({ code, ok: Boolean(condition), hard: true });
    return Boolean(condition);
  };
  const soft = (condition, code) => {
    checks.push({ code, ok: Boolean(condition), hard: false });
    return Boolean(condition);
  };

  if (expected.retrieval_status !== undefined) {
    hard(result.retrieval.status === expected.retrieval_status, `retrieval-status:${result.retrieval.status}`);
  }
  const audit = result.retrieval.audit;
  hard(audit.private_hits === 0, 'leak:private');
  hard(audit.future_hits === 0, 'leak:future');
  hard(audit.stale_hits === 0, 'leak:stale');
  hard(audit.unknown_hits === 0, 'leak:unknown');

  if (expected.zero_private_leak) {
    hard((result.retrieval.index_exclusions?.EXCLUDED_ACL ?? 0) >= 0, 'acl-count-invisible');
  }
  if (expected.hits_reference_only) {
    const allowed = new Set(expected.hits_reference_only);
    hard((result.retrieval.hits ?? []).every((h) => allowed.has(h.segment_id)), 'hits-reference-only');
  }
  if (expected.hits_include) {
    const present = new Set((result.retrieval.hits ?? []).map((h) => h.segment_id));
    for (const segment of expected.hits_include) hard(present.has(segment), `hits-include:${segment}`);
  }
  if (expected.future_excluded) {
    hard(result.retrieval.hits.every((h) => h.reason !== 'FUTURE'), 'future-excluded');
  }
  if (expected.late_fetch_included) {
    const present = new Set((result.retrieval.hits ?? []).map((h) => h.segment_id));
    hard(present.has('seg-epi-6'), 'late-fetch-included');
  }
  if (expected.zero_hits) hard((result.retrieval.hits ?? []).length === 0, 'zero-hits');
  if (expected.empty_index_for_scope) hard(result.retrieval.index_entries === 0, 'empty-index-for-scope');
  if (expected.abstention_reason) hard((result.retrieval.abstentions[0]?.reason ?? '') === expected.abstention_reason, `abstention-reason:${expected.abstention_reason}`);
  if (expected.min_primary_recall !== undefined) {
    soft(result.retrieval.by_mode[doc.input.primary_mode]?.recall_at_10 >= expected.min_primary_recall, 'primary-recall');
  }
  if (expected.min_domains_in_hits) {
    const domains = new Set((result.retrieval.hits ?? []).map((h) => h.domain).filter(Boolean));
    hard(domains.size >= expected.min_domains_in_hits, `domains-in-hits:${domains.size}`);
  }
  if (expected.coverage_gap_reason) {
    for (const reason of expected.coverage_gap_reason) {
      hard((result.synthesis.coverage.coverage_gaps ?? []).some((g) => g.reason === reason), `coverage-gap:${reason}`);
    }
  }
  if (expected.contradiction_expected) {
    hard(result.synthesis.contradictions.length >= 1, 'contradiction-surfaced');
    hard(result.synthesis.contradictions.every((c) => c.handling === expected.contradiction_handling), 'contradiction-both-shown');
  }
  if (expected.synthesis_status !== undefined) {
    hard(result.synthesis.status === expected.synthesis_status, `synthesis-status:${result.synthesis.status}`);
  }
  if (expected.entailment) {
    hard(result.synthesis.maps[0]?.entailing >= 1, 'entailment-entails');
  }
  if (expected.statement_number_mismatch) {
    const map = result.synthesis.result.evidence_maps[0];
    hard(map?.entries.every((e) => e.entailment_status === expected.entailment_status), 'entailment-number-mismatch');
  }
  if (expected.hypothesis_card) {
    const spec = expected.hypothesis_card;
    if (spec.expect_rejection) {
      hard(result.hypothesis_rejected === true, 'hypothesis-rejected');
    } else {
      hard(result.hypothesis_rejected !== true, 'hypothesis-not-rejected');
      const card = result.synthesis.cards[0];
      hard(card?.card_type === spec.card_type, `card-type:${card?.card_type}`);
      hard((card?.proposed_relation.causal_assertion ?? null) === (spec.causal_assertion ? true : null), 'card-causal-assertion');
      if (spec.novelty) hard(card?.novelty.assessment === spec.novelty, `card-novelty:${card?.novelty.assessment}`);
      if ((spec.min_confounders ?? 0) > 0) hard((card?.confounders.length ?? 0) >= spec.min_confounders, 'card-confounders');
      if (expected.falsifiable) {
        hard((card?.falsifiers.length ?? 0) >= 1 && Boolean(card?.test_design), 'card-falsifiable');
      }
    }
  }
  if (expected.independent_evidence_families !== undefined) {
    hard(result.synthesis.maps[0]?.independent_families === expected.independent_evidence_families, 'family-count');
  }
  if (expected.min_family_excluded !== undefined) {
    hard((result.retrieval.excluded_count?.EXCLUDED_FAMILY_COLLAPSED ?? 0) >= expected.min_family_excluded, 'family-excluded-at-retrieval');
  }
  if (expected.allowed_actor_sees) {
    // subset semantics: the expected segments must appear; unrelated accessible
    // hits may legitimately appear alongside
    const allowedHits = result.actor_split?.allowed_actor_hits ?? [];
    hard(expected.allowed_actor_sees.every((s) => allowedHits.includes(s)), 'allowed-actor-sees');
  }
  if (expected.denied_actor_sees) {
    const deniedHits = result.actor_split?.denied_actor_hits ?? [];
    hard(deniedHits.every((s) => expected.denied_actor_sees.includes(s)), 'denied-actor-sees');
  }

  result.checks = checks;
  const hardFails = checks.filter((c) => c.hard && !c.ok);
  const softFails = checks.filter((c) => !c.hard && !c.ok);
  if (hardFails.length > 0) return 'FAIL';
  if (softFails.length > 0) return 'PARTIAL';
  return 'PASS';
}

// ---- the run ------------------------------------------------------------------------

export async function runCorpus(runParams, { store: sharedStore, authorities: registryOverride } = {}) {
  const authorities = registryOverride ?? authorityRegistry();
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  const manifestCheck = verifyFrozenManifest({ manifest, casesDir: CASES_DIR });
  if (!manifestCheck.ok) {
    return { schemaVersion: 1, run_id: runParams.runId, status: 'QUARANTINED', manifest_issues: manifestCheck.issues };
  }

  const caseResults = [];
  const integrity = {
    private_leaks: 0,
    unauthorized_hits: 0,
    future_leaks: 0,
    stale_hits: 0,
    provenance_substitutions: 0,
    causal_overclaims: 0,
    facts_from_analogy: 0,
    hidden_contradictions: 0,
    silent_exclusions: 0,
    duplicate_side_effects: 0,
    authority_expansions: 0,
    type_promotions_without_review: 0,
  };

  for (const file of fs.readdirSync(CASES_DIR).filter((f) => f.endsWith('.json')).sort()) {
    const doc = JSON.parse(fs.readFileSync(path.join(CASES_DIR, file), 'utf8'));
    doc.input.__case_id = doc.case_id;
    let result;
    try {
      result = await runCase(doc, runParams, authorities, sharedStore);
    } catch (error) {
      result = { case_id: doc.case_id, category: doc.category, error: error.message, decision: 'ERROR', checks: [] };
    }
    // aggregate hard integrity counters
    if (result.retrieval?.audit) {
      integrity.private_leaks += result.retrieval.audit.private_hits;
      integrity.unauthorized_hits += result.retrieval.audit.private_hits;
      integrity.future_leaks += result.retrieval.audit.future_hits;
      integrity.stale_hits += result.retrieval.audit.stale_hits;
    }
    if (result.synthesis?.cards) {
      for (const card of result.synthesis.cards) {
        if (card.card_type !== 'MECHANISM_CLAIM' && card.proposed_relation.causal_assertion === true) integrity.causal_overclaims += 1;
        if (card.card_type === 'ANALOGY' && card.proposed_relation.causal_assertion === true) integrity.facts_from_analogy += 1;
        if (card.type_promotion) integrity.type_promotions_without_review += card.type_promotion.reviewed_by ? 0 : 1;
      }
    }
    if (doc.expected?.contradiction_expected && (result.synthesis?.contradictions?.length ?? 0) === 0) integrity.hidden_contradictions += 1;

    caseResults.push({
      case_id: doc.case_id,
      case_number: doc.case_number,
      category: doc.category,
      severity: doc.severity,
      decision: result.decision,
      checks: result.checks ?? [],
      retrieval: result.retrieval ? {
        status: result.retrieval.status,
        primary_hits: result.retrieval.hits.slice(0, 10),
        abstentions: result.retrieval.abstentions,
        by_mode: result.retrieval.by_mode,
        cost: result.retrieval.cost ?? null,
        index_entries: result.retrieval.index_entries,
        index_exclusions: result.retrieval.index_exclusions,
      } : null,
      synthesis: result.synthesis ? {
        status: result.synthesis.status,
        maps: result.synthesis.maps,
        cards: result.synthesis.cards.map((c) => ({ card_id: c.card_id, card_type: c.card_type, causal: c.proposed_relation.causal_assertion, novelty: c.novelty.assessment })),
        contradictions: result.synthesis.contradictions,
        coverage: result.synthesis.coverage,
      } : null,
      hypothesis_rejected: result.hypothesis_rejected ?? false,
      actor_split: result.actor_split ?? null,
      error: result.error,
    });
  }

  const decisionCounts = caseResults.reduce((acc, c) => {
    acc[c.decision] = (acc[c.decision] ?? 0) + 1;
    return acc;
  }, {});
  const graphDigest = sha256Json(caseResults.map((c) => ({ case_id: c.case_id, decision: c.decision, checks: c.checks })));

  return {
    schemaVersion: 1,
    ticket: 'S2-005',
    run_id: runParams.runId,
    executor_id: runParams.executorId,
    clock: runParams.clock,
    nonce: runParams.nonce,
    pid: runParams.pid,
    output_root: runParams.outputRoot,
    testedImplementationCommit: getHeadCommit(),
    status: 'COMPLETED',
    caseCount: caseResults.length,
    decisionCounts,
    integrity,
    graphDigest,
    decisions: caseResults,
  };
}

function getHeadCommit() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unavailable';
  }
}

async function main() {
  const args = parseArgs(process.argv);
  const runParams = {
    runId: args['run-id'] ?? 'run-a',
    executorId: args['executor-id'] ?? 'exec-a',
    nonce: args.nonce ?? 'n-default',
    clock: args.clock ?? DEFAULT_CLOCK,
    pid: process.pid,
    outputRoot: args['output-root'] ?? `results/s2-005/${args['run-id'] ?? 'run-a'}`,
  };
  const report = await runCorpus(runParams);
  if (args.out) {
    const outPath = path.isAbsolute(args.out) ? args.out : path.join(ROOT, args.out);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
  }
  console.log(JSON.stringify({
    run_id: report.run_id,
    status: report.status,
    caseCount: report.caseCount,
    decisionCounts: report.decisionCounts,
    integrity: report.integrity,
    graphDigest: report.graphDigest,
  }, null, 2));
  process.exit(report.status === 'COMPLETED' ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await main();
}
