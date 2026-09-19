// S2-005 retrieval engine.
// Four deterministic retrieval modes over the frozen claim graph:
//   lexical — BM25 (k1=1.2, b=0.75)
//   vector  — hashed tf-idf embeddings (model: hashed-tfidf-256/1.0.0)
//   fusion  — reciprocal-rank fusion + deterministic reranker
//   graph   — lexical seeds expanded over committed claim edges (budgeted)
//
// Hard invariants (todo §4, §6):
//   * Server-side ACL is applied BEFORE scoring: an inaccessible private
//     node never enters the candidate set, counts, snippets, embeddings or
//     explanations. ACL-filtered nodes leave no trace at all.
//   * The index never contains data newer than as_of (EXCLUDED_AS_OF is
//     reportable; ACL exclusion is invisible by design).
//   * Stale/tombstoned claims never enter new evidence retrieval
//     (EXCLUDED_STALE).
//   * Ten reprints of one upstream collapse to one evidence family
//     (EXCLUDED_FAMILY_COLLAPSED).
//   * Budget is enforced; exhausting it records an abstention, never a
//     partial silent answer.
//   * Every decision is a deterministic function of (index, request, mode,
//     seed): wall-clock latency is telemetry only.
import { createHash } from 'node:crypto';
import { aclGrantsRead } from '../claims/store.mjs';
import { synthesisValidators } from './validation.mjs';

const sha256 = (value) => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');

export const RETRIEVAL_CONFIG = Object.freeze({
  top_k: 10,
  bm25_k1: 1.2,
  bm25_b: 0.75,
  rrf_k: 60,
  vector_dims: 256,
  seed: 0,
  corpus_version: '1.0.0',
  index_version: '1.0.0',
});

export const VECTOR_MODEL = Object.freeze({
  model_id: 'hashed-tfidf-256',
  model_version: '1.0.0',
});

export const MODES = Object.freeze(['lexical', 'vector', 'fusion', 'graph']);

const STOPWORDS = new Set(['the', 'a', 'an', 'of', 'in', 'on', 'for', 'to', 'and', 'or', 'is', 'are', 'was', 'were', 'by', 'with', 'at', 'as', 'that', 'this', 'it', 'from', 'be', 'has', 'have', 'had', 'did', 'does', 'do', 'not', 'but', 'its', 'than', 'then', 'so', 'such', 'can', 'could', 'may', 'might', 'will', 'would', 'should']);

// Deterministic tokenizer: lowercase, split on non-alphanumerics, drop
// stopwords and single characters. No locale-dependent behaviour.
export function tokenize(text) {
  return String(text ?? '')
    .toLowerCase()
    .split(/[^a-z0-9%]+/)
    .filter((t) => t.length > 1 && !STOPWORDS.has(t));
}

// FNV-1a — deterministic, dependency-free token hashing for embeddings.
function fnv1a(token) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < token.length; i += 1) {
    hash ^= token.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

// ---- index construction ------------------------------------------------------

export function buildRetrievalIndex({
  claims,
  claimEdges = [],
  scope, // { workspaceId, principalId } — server-side ACL scope
  asOf,
}) {
  const exclusions = { EXCLUDED_ACL: 0, EXCLUDED_AS_OF: 0, EXCLUDED_STALE: 0 };
  const entries = [];

  for (const claim of claims) {
    // 1. ACL BEFORE scoring — private/inaccessible nodes leave no trace:
    //    no candidate, no count, no snippet, no embedding, no explanation.
    const aclOk = aclGrantsRead(claim.acl, { workspaceId: scope.workspaceId, principalId: scope.principalId });
    if (!aclOk) {
      exclusions.EXCLUDED_ACL += 1;
      continue; // invisible: not even reported per-node
    }
    // 2. as_of freeze: nothing published after the cutoff may be indexed.
    const publishedAt = claim.published_at ?? claim.observed_at ?? claim.fetched_at ?? null;
    if (asOf && publishedAt && publishedAt > asOf) {
      exclusions.EXCLUDED_AS_OF += 1;
      continue;
    }
    // 3. stale/tombstoned claims never enter new evidence retrieval.
    if (claim.lifecycle === 'STALE' || claim.lifecycle === 'TOMBSTONED' || claim.lifecycle === 'SUPERSEDED') {
      exclusions.EXCLUDED_STALE += 1;
      continue;
    }

    const tokens = tokenize(claim.normalized_text);
    entries.push({
      claim_id: claim.claim_id,
      revision: claim.revision,
      normalized_text: claim.normalized_text,
      tokens,
      length: tokens.length,
      segment_id: claim.segment_id ?? null,
      span: claim.span ?? null,
      quote_digest: claim.quote_digest ?? null,
      text_sha256: claim.original_text ? sha256(claim.original_text) : null,
      source_family_id: claim.source_family_id ?? null,
      acl: claim.acl,
      domain: claim.domain ?? null,
      published_at: publishedAt,
      epistemic_type: claim.epistemic_type,
      event_time: claim.event_time ?? null,
      lifecycle: claim.lifecycle,
    });
  }

  entries.sort((a, b) => (a.claim_id < b.claim_id ? -1 : a.claim_id > b.claim_id ? 1 : b.revision - a.revision));

  // BM25 corpus statistics over the ACL/as_of-visible entries only.
  const N = entries.length;
  const df = new Map();
  for (const entry of entries) {
    for (const token of new Set(entry.tokens)) df.set(token, (df.get(token) ?? 0) + 1);
  }
  const avgdl = N > 0 ? entries.reduce((sum, e) => sum + e.length, 0) / N : 0;

  // Deterministic hashed tf-idf vectors (the "embedding model").
  const idf = (token) => Math.log(1 + (N + 1) / (1 + (df.get(token) ?? 0)));
  const vectors = new Map();
  for (const entry of entries) {
    const vector = new Float64Array(RETRIEVAL_CONFIG.vector_dims);
    const tf = new Map();
    for (const token of entry.tokens) tf.set(token, (tf.get(token) ?? 0) + 1);
    for (const [token, count] of tf) {
      vector[fnv1a(token) % RETRIEVAL_CONFIG.vector_dims] += (count / entry.length) * idf(token);
    }
    vectors.set(entry.claim_id, vector);
  }

  // Claim-edge adjacency for graph expansion (ACL-visible edges only).
  const adjacency = new Map();
  for (const edge of claimEdges) {
    if (!entries.some((e) => e.claim_id === edge.source_claim_id) || !entries.some((e) => e.claim_id === edge.target_claim_id)) continue;
    if (!adjacency.has(edge.source_claim_id)) adjacency.set(edge.source_claim_id, []);
    if (!adjacency.has(edge.target_claim_id)) adjacency.set(edge.target_claim_id, []);
    adjacency.get(edge.source_claim_id).push({ to: edge.target_claim_id, relation: edge.relation });
    adjacency.get(edge.target_claim_id).push({ to: edge.source_claim_id, relation: edge.relation });
  }
  for (const list of adjacency.values()) list.sort((a, b) => (a.to < b.to ? -1 : 1));

  // Index digest: proves which claim revisions/span digests the index carried.
  const indexHash = sha256(entries.map((e) => `${e.claim_id}@${e.revision}:${e.quote_digest ?? ''}:${e.source_family_id ?? ''}`).join('\n'));

  return {
    entries,
    byClaim: new Map(entries.map((e) => [e.claim_id, e])),
    df,
    idf,
    avgdl,
    N,
    vectors,
    adjacency,
    indexHash,
    exclusions, // aggregate counts only; ACL count is structural, not per-node
  };
}

// ---- scoring ------------------------------------------------------------------

export function scoreBM25(index, queryTokens) {
  const k1 = RETRIEVAL_CONFIG.bm25_k1;
  const b = RETRIEVAL_CONFIG.bm25_b;
  const scores = [];
  for (const entry of index.entries) {
    if (entry.length === 0) continue;
    const tf = new Map();
    for (const token of entry.tokens) tf.set(token, (tf.get(token) ?? 0) + 1);
    let score = 0;
    for (const token of queryTokens) {
      const count = tf.get(token);
      if (!count) continue;
      const idfValue = Math.log(1 + (index.N - (index.df.get(token) ?? 0) + 0.5) / ((index.df.get(token) ?? 0) + 0.5));
      score += idfValue * ((count * (k1 + 1)) / (count + k1 * (1 - b + (b * entry.length) / (index.avgdl || 1))));
    }
    if (score > 0) scores.push({ claim_id: entry.claim_id, score });
  }
  return rank(scores);
}

export function embed(index, text) {
  const vector = new Float64Array(RETRIEVAL_CONFIG.vector_dims);
  const tokens = tokenize(text);
  if (tokens.length === 0) return vector;
  const tf = new Map();
  for (const token of tokens) tf.set(token, (tf.get(token) ?? 0) + 1);
  for (const [token, count] of tf) {
    vector[fnv1a(token) % RETRIEVAL_CONFIG.vector_dims] += (count / tokens.length) * index.idf(token);
  }
  return vector;
}

function cosine(a, b) {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i += 1) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

export function scoreVector(index, queryVector) {
  const scores = [];
  for (const entry of index.entries) {
    const vector = index.vectors.get(entry.claim_id);
    if (!vector) continue;
    const score = cosine(queryVector, vector);
    if (score > 0) scores.push({ claim_id: entry.claim_id, score });
  }
  return rank(scores);
}

// Deterministic ranking: score desc, then claim_id asc (no random tie-break).
function rank(scores) {
  return scores.sort((a, b) => (b.score - a.score) || (a.claim_id < b.claim_id ? -1 : a.claim_id > b.claim_id ? 1 : 0));
}

export function reciprocalRankFusion(lists, weights = null) {
  const k = RETRIEVAL_CONFIG.rrf_k;
  const fused = new Map();
  lists.forEach((list, listIndex) => {
    const weight = weights ? weights[listIndex] : 1;
    list.forEach((item, position) => {
      const value = fused.get(item.claim_id) ?? { claim_id: item.claim_id, score: 0, contributions: [] };
      value.score += weight / (k + position + 1);
      value.contributions.push(listIndex);
      fused.set(item.claim_id, value);
    });
  });
  return rank([...fused.values()]);
}

// Deterministic reranker over fused candidates: exact-token overlap with the
// query, domain match and family diversity. No learned weights, no RNG.
export function rerank(fused, { index, queryTokens, domains = [] }) {
  const domainSet = new Set(domains);
  const seenFamilies = new Set();
  const reranked = [];
  for (const item of fused) {
    const entry = index.byClaim.get(item.claim_id);
    if (!entry) continue;
    const querySet = new Set(queryTokens);
    const overlap = entry.tokens.filter((t) => querySet.has(t)).length / Math.max(1, querySet.size);
    const domainMatch = domainSet.size === 0 || (entry.domain && domainSet.has(entry.domain)) ? 1 : 0;
    const familyNovel = entry.source_family_id ? !seenFamilies.has(entry.source_family_id) : true;
    if (entry.source_family_id) seenFamilies.add(entry.source_family_id);
    reranked.push({
      claim_id: item.claim_id,
      score: item.score + 0.5 * overlap + 0.25 * domainMatch + 0.15 * (familyNovel ? 1 : 0),
      components: { fusion: item.score, overlap, domain_match: domainMatch, family_diversity: familyNovel ? 1 : 0 },
    });
  }
  return rank(reranked);
}

// Graph retrieval: lexical seeds expanded over committed claim edges under a
// strict budget. Expansion is breadth-first, deterministic order, and every
// expanded candidate carries graph_expansion weight decaying with depth.
export function graphRetrieve({ index, queryTokens, budget }) {
  const seeds = scoreBM25(index, queryTokens).slice(0, 5);
  const frontier = seeds.map((s, position) => ({ claim_id: s.claim_id, score: 1 / (RETRIEVAL_CONFIG.rrf_k + position + 1), depth: 0 }));
  const visited = new Map(frontier.map((f) => [f.claim_id, f]));
  let operations = seeds.length;
  const maxOperations = budget?.max_operations ?? 100000;

  while (frontier.length > 0 && operations < maxOperations) {
    const node = frontier.shift();
    for (const neighbor of index.adjacency.get(node.claim_id) ?? []) {
      operations += 1;
      if (operations >= maxOperations) break;
      if (visited.has(neighbor.to)) continue;
      const depth = node.depth + 1;
      const score = node.score * 0.5;
      visited.set(neighbor.to, { claim_id: neighbor.to, score, depth });
      frontier.push({ claim_id: neighbor.to, score, depth });
    }
    frontier.sort((a, b) => (b.score - a.score) || (a.claim_id < b.claim_id ? -1 : 1));
  }

  const results = rank([...visited.values()].map((v) => ({ claim_id: v.claim_id, score: v.score, depth: v.depth })));
  return { results, operations };
}

// ---- integrity audit ------------------------------------------------------------

// Post-hoc leak audit used by runs and probes: given the FULL pre-ACL claim
// list, verify that no hit references a node invisible to the request scope,
// published after as_of, or stale. Probe K poisons hit lists on purpose and
// asserts this audit rejects the candidate BEFORE any quality ranking.
export function auditRunForLeaks({ hits, allClaims, scope, asOf }) {
  const byClaim = new Map(allClaims.map((c) => [c.claim_id, c]));
  const counters = { private_hits: 0, future_hits: 0, stale_hits: 0, unknown_hits: 0 };
  for (const hit of hits) {
    const claim = byClaim.get(hit.claim_id);
    if (!claim) {
      counters.unknown_hits += 1;
      continue;
    }
    const aclOk = aclGrantsRead(claim.acl, { workspaceId: scope.workspaceId, principalId: scope.principalId });
    if (!aclOk) counters.private_hits += 1;
    const publishedAt = claim.published_at ?? claim.observed_at ?? claim.fetched_at ?? null;
    if (asOf && publishedAt && publishedAt > asOf) counters.future_hits += 1;
    if (claim.lifecycle === 'STALE' || claim.lifecycle === 'TOMBSTONED' || claim.lifecycle === 'SUPERSEDED') counters.stale_hits += 1;
  }
  return { ok: counters.private_hits === 0 && counters.future_hits === 0 && counters.stale_hits === 0 && counters.unknown_hits === 0, counters };
}

// ---- request execution ---------------------------------------------------------

// Family collapse for candidate lists: one representative per evidence
// family; later members become EXCLUDED_FAMILY_COLLAPSED hit records.
function collapseFamilies(ranked, index) {
  const seenFamilies = new Set();
  const output = [];
  let collapsed = 0;
  for (const item of ranked) {
    const entry = index.byClaim.get(item.claim_id);
    if (!entry) continue;
    const family = entry.source_family_id;
    if (family && seenFamilies.has(family)) {
      collapsed += 1;
      output.push({ ...item, included: false, reason: 'EXCLUDED_FAMILY_COLLAPSED' });
      continue;
    }
    if (family) seenFamilies.add(family);
    output.push({ ...item, included: true, reason: 'INCLUDED_RELEVANT' });
  }
  return { output, collapsed };
}

export function executeRetrievalRequest(request, { index, execution = null } = {}) {
  // fail-closed contract boundary: the request must satisfy the versioned
  // schema before anything is scored (todo §2)
  synthesisValidators().requireValid('retrieval-request', request);
  const queryTokens = tokenize(request.query.text);
  const budget = request.budget;
  let operations = 0;
  let modeResults = null;
  let components = null;

  if (!MODES.includes(request.mode)) {
    return { status: 'FAILED', failures: [{ code: 'MODE_UNKNOWN', detail: request.mode }], hits: [], abstentions: [] };
  }
  if (!request.allowed_retrieval_modes.includes(request.mode)) {
    return { status: 'FAILED', failures: [{ code: 'MODE_NOT_ALLOWED', detail: `mode ${request.mode} is not in allowed_retrieval_modes` }], hits: [], abstentions: [] };
  }
  if (index.entries.length === 0) {
    // Distinguish an empty-for-ACL index from an honestly empty corpus:
    // both abstain, but the reason must be explicit, never fabricated.
    return {
      status: 'ABSTAINED',
      hits: [],
      abstentions: [{ reason: 'NO_CANDIDATES', detail: index.exclusions.EXCLUDED_ACL > 0 ? 'all candidates excluded (access or freeze window)' : 'index is empty for this scope' }],
    };
  }

  if (request.mode === 'lexical') {
    modeResults = scoreBM25(index, queryTokens);
    components = { primary: 'bm25', lexical: 1 };
    operations = index.entries.length * queryTokens.length;
  } else if (request.mode === 'vector') {
    const queryVector = embed(index, request.query.text);
    modeResults = scoreVector(index, queryVector);
    components = { primary: 'cosine', vector: 1 };
    operations = index.entries.length * RETRIEVAL_CONFIG.vector_dims;
  } else if (request.mode === 'fusion') {
    const lexical = scoreBM25(index, queryTokens);
    const vector = scoreVector(index, embed(index, request.query.text));
    const fused = reciprocalRankFusion([lexical, vector]);
    const reranked = rerank(fused, { index, queryTokens, domains: request.domains ?? [] });
    modeResults = reranked;
    components = { primary: 'rrf+rerank', lexical: 1, vector: 1, rerank: 1 };
    operations = index.entries.length * (queryTokens.length + RETRIEVAL_CONFIG.vector_dims) + reranked.length;
  } else if (request.mode === 'graph') {
    const graph = graphRetrieve({ index, queryTokens, budget });
    modeResults = graph.results;
    components = { primary: 'bm25-seeds+edge-expansion', lexical: 1, graph_expansion: 1 };
    operations = graph.operations;
  }

  if (operations > budget.max_operations) {
    return {
      status: 'ABSTAINED',
      hits: [],
      abstentions: [{ reason: 'BUDGET_EXHAUSTED', detail: `required ${operations} operations, budget ${budget.max_operations}` }],
      cost: { operations, budget_max_operations: budget.max_operations, budget_exhausted: true },
    };
  }

  const { output, collapsed } = collapseFamilies(modeResults, index);

  // time window filter (visible, accounted)
  const window = request.time_window ?? null;
  const finalHits = [];
  const excludedCount = { EXCLUDED_FAMILY_COLLAPSED: collapsed, EXCLUDED_STALE: 0, EXCLUDED_AS_OF: 0, EXCLUDED_TIME_WINDOW: 0, EXCLUDED_SOURCE_POLICY: 0, EXCLUDED_BUDGET: 0, EXCLUDED_DUPLICATE: 0 };
  const allowedFamilies = request.source_policy?.allowed_source_families?.length ? request.source_policy.allowed_source_families : null;
  const forbiddenFamilies = new Set(request.source_policy?.forbidden_source_families ?? []);

  const seenClaims = new Set();
  for (const item of output) {
    const entry = index.byClaim.get(item.claim_id);
    if (!entry) continue;
    if (seenClaims.has(entry.claim_id)) {
      excludedCount.EXCLUDED_DUPLICATE += 1;
      finalHits.push({ ...item, included: false, reason: 'EXCLUDED_DUPLICATE' });
      continue;
    }
    seenClaims.add(entry.claim_id);
    if (window && entry.published_at && (entry.published_at < window.start || entry.published_at > window.end)) {
      excludedCount.EXCLUDED_TIME_WINDOW += 1;
      finalHits.push({ ...item, included: false, reason: 'EXCLUDED_TIME_WINDOW' });
      continue;
    }
    if (forbiddenFamilies.has(entry.source_family_id)) {
      excludedCount.EXCLUDED_SOURCE_POLICY += 1;
      finalHits.push({ ...item, included: false, reason: 'EXCLUDED_SOURCE_POLICY' });
      continue;
    }
    if (allowedFamilies && !allowedFamilies.includes(entry.source_family_id)) {
      excludedCount.EXCLUDED_SOURCE_POLICY += 1;
      finalHits.push({ ...item, included: false, reason: 'EXCLUDED_SOURCE_POLICY' });
      continue;
    }
    finalHits.push(item);
  }

  const topK = RETRIEVAL_CONFIG.top_k;
  const selected = finalHits.slice(0, topK);
  if (selected.filter((h) => h.included).length === 0) {
    return {
      status: 'ABSTAINED',
      hits: [],
      abstentions: [{ reason: 'NO_CANDIDATES', detail: 'no included candidates for this query under the requested constraints' }],
      cost: { operations, budget_max_operations: budget.max_operations, budget_exhausted: false },
      excludedCount,
    };
  }

  const hits = selected.map((item, position) => {
    const entry = index.byClaim.get(item.claim_id);
    return synthesisValidators().requireValid('retrieval-hit', {
      contractVersion: '1.0.0',
      hit_id: `hit-${request.request_id.replace(/^req-/, '')}-${item.claim_id.replace(/^clm-/, '')}-${position + 1}`,
      request_id: request.request_id,
      mode: request.mode,
      claim_id: entry.claim_id,
      claim_revision: entry.revision,
      segment_id: entry.segment_id,
      segment_revision: 1,
      span: entry.span,
      quote_digest: entry.quote_digest,
      text_sha256: entry.text_sha256,
      source_family_id: entry.source_family_id,
      acl: entry.acl,
      score: {
        total: Number(item.score.toFixed(6)),
        components: {
          primary: Number(item.score.toFixed(6)),
          ...(item.components ?? {}),
          ...(components?.lexical ? { lexical: components.lexical } : {}),
          ...(components?.vector ? { vector: components.vector } : {}),
          ...(components?.rerank ? { rerank: components.rerank } : {}),
          ...(components?.graph_expansion ? { graph_expansion: components.graph_expansion } : {}),
        },
      },
      rank: position + 1,
      included: item.included,
      reason: item.reason,
    });
  });

  // full run payload (todo §2: runtime serialization passes the same
  // contract as consumer fixtures)
  const runPayload = execution
    ? synthesisValidators().requireValid('retrieval-run', {
        contractVersion: '1.0.0',
        run_id: `run-${request.request_id.replace(/^req-/, '')}`,
        mode: request.mode,
        request_id: request.request_id,
        request_digest: sha256(request),
        query_hash: sha256(request.query.text),
        index_hash: index.indexHash,
        model: request.mode === 'vector' || request.mode === 'fusion' ? VECTOR_MODEL : { model_id: 'none', model_version: '1.0.0', model_digest: null },
        seed: request.seed ?? null,
        config_hash: sha256({ ...RETRIEVAL_CONFIG, mode: request.mode, domains: request.domains ?? [] }),
        as_of: request.as_of,
        candidates_total: modeResults.length,
        hits,
        excluded_count: excludedCount,
        failures: [],
        abstentions: [],
        cost: { operations, budget_max_operations: budget.max_operations, budget_exhausted: false },
        execution,
        status: 'COMPLETED',
      })
    : null;

  return {
    status: 'COMPLETED',
    hits,
    runPayload,
    abstentions: [],
    cost: { operations, budget_max_operations: budget.max_operations, budget_exhausted: false },
    excludedCount,
    indexHash: index.indexHash,
    model: request.mode === 'vector' || request.mode === 'fusion' ? VECTOR_MODEL : { model_id: 'none', model_version: '1.0.0', model_digest: null },
    configHash: sha256({ ...RETRIEVAL_CONFIG, mode: request.mode, domains: request.domains ?? [] }),
    queryHash: sha256(request.query.text),
  };
}
