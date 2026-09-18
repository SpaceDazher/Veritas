// S2-005 retrieval/synthesis contract TypeScript types.
// GENERATED from contracts/*.schema.json by scripts/generate-synthesis-types.mjs.
// Do not edit by hand: the JSON Schemas are the single source of truth and
// tests/synthesis/contracts.types.test.mjs fails if this file drifts.

// retrieval-request.schema.json (contractVersion 1.0.0)
export interface RetrievalRequest {
  contractVersion: "1.0.0";
  request_id: RequestId;
  actor: PrincipalId;
  workspace_id: WorkspaceId;
  query: {
    text: string;
    task_class?: "fact_checking" | "research" | "monitoring" | "exploration";
    question_kind?: "local" | "global";
  };
  as_of: IsoDateTime;
  domains?: Array<string>;
  languages?: Array<string>;
  geography?: string | null;
  time_window?: {
    start: IsoDateTime;
    end: IsoDateTime;
  } | null;
  source_policy?: {
    allowed_source_families: Array<string>;
    forbidden_source_families?: Array<string>;
  };
  budget: {
    max_candidates: number;
    max_operations: number;
    timeout_ms: number;
  };
  allowed_retrieval_modes: Array<"lexical" | "vector" | "fusion" | "graph">;
  mode: "lexical" | "vector" | "fusion" | "graph";
  corpus_version: string;
  index_version: string;
  seed?: number | null;
}
export type RetrievalRequestRequestId = string;
export type RetrievalRequestPrincipalId = string;
export type RetrievalRequestWorkspaceId = string;
export type RetrievalRequestIsoDateTime = string;

// retrieval-hit.schema.json (contractVersion 1.0.0)
export interface RetrievalHit {
  contractVersion: "1.0.0";
  hit_id: HitId;
  request_id: RequestId;
  mode: "lexical" | "vector" | "fusion" | "graph";
  claim_id: ClaimId;
  claim_revision: number;
  segment_id: string;
  segment_revision: number;
  span: {
    start: number;
    end: number;
  };
  quote_digest: Sha256Hex;
  text_sha256: Sha256Hex;
  source_family_id: string | null;
  acl: {
    visibility: "public" | "project" | "private";
    workspace_id: WorkspaceId;
    tenant_id: string;
    allowed_workspace_ids?: Array<WorkspaceId>;
    allowed_principal_ids?: Array<string>;
  };
  score: {
    total: number;
    components: {
      primary: number;
      lexical?: number;
      vector?: number;
      rerank?: number;
      domain_match?: number;
      family_diversity?: number;
      graph_expansion?: number;
    };
    normalized?: number;
  };
  rank: number;
  included: boolean;
  reason: "INCLUDED_RELEVANT" | "EXCLUDED_FAMILY_COLLAPSED" | "EXCLUDED_STALE" | "EXCLUDED_ACL" | "EXCLUDED_AS_OF" | "EXCLUDED_BUDGET" | "EXCLUDED_TIME_WINDOW" | "EXCLUDED_SOURCE_POLICY" | "EXCLUDED_DUPLICATE";
}
export type RetrievalHitHitId = string;
export type RetrievalHitRequestId = string;
export type RetrievalHitClaimId = string;
export type RetrievalHitWorkspaceId = string;
export type RetrievalHitSha256Hex = string;

// retrieval-run.schema.json (contractVersion 1.0.0)
export interface RetrievalRun {
  contractVersion: "1.0.0";
  run_id: string;
  mode: "lexical" | "vector" | "fusion" | "graph";
  request_id: RequestId;
  request_digest: Sha256Hex;
  query_hash: Sha256Hex;
  index_hash: Sha256Hex;
  model: {
    model_id: string;
    model_version: string;
    model_digest?: Sha256Hex | null;
  };
  seed: number | null;
  config_hash: Sha256Hex;
  as_of?: IsoDateTime;
  candidates_total: number;
  hits: Array<RetrievalHit>;
  excluded_count: Record<string, unknown>;
  failures: Array<{
    code: string;
    detail: string;
  }>;
  abstentions: Array<{
    reason: "NO_CANDIDATES" | "BUDGET_EXHAUSTED" | "NO_ENTAILING_EVIDENCE" | "SOURCE_UNAVAILABLE" | "ACCESS_DENIED";
    detail?: string;
  }>;
  cost: {
    operations: number;
    budget_max_operations: number;
    budget_exhausted?: boolean;
  };
  latency_ms?: number;
  execution: {
    executor_id: string;
    pid: number;
    nonce: string;
    output_root_digest: Sha256Hex;
    clock?: IsoDateTime;
  };
  status: "COMPLETED" | "ABSTAINED" | "FAILED";
}
export type RetrievalRunRequestId = string;
export type RetrievalRunSha256Hex = string;
export type RetrievalRunIsoDateTime = string;

// evidence-map.schema.json (contractVersion 1.0.0)
export interface EvidenceMap {
  contractVersion: "1.0.0";
  map_id: string;
  statement: string;
  entries: Array<{
    claim_id: string;
    claim_revision: number;
    relation: "supports" | "contradicts" | "qualifies";
    entailment_status: "ENTAILS" | "PARTIALLY_ENTAILS" | "NOT_ENTAILING";
    entailment_method?: string;
    evidence_edge_id?: string | null;
    segment_id?: string | null;
    span?: {
    start: number;
    end: number;
  } | null;
    quote_digest?: Sha256Hex;
    source_family_id?: string | null;
    domain?: string | null;
  }>;
  unavailable_evidence: Array<{
    what_is_missing: string;
    kind: "NOT_IN_CORPUS" | "ACCESS_DENIED" | "AFTER_AS_OF" | "REMOVED" | "UNKNOWN";
    required_for?: string;
  }>;
  qualifiers: Array<string>;
  family_collapse?: {
    families: Array<{
    source_family_id: string | null;
    member_count: number;
    lineage?: "ORIGINAL" | "DERIVED" | "UNKNOWN";
  }>;
    collapsed_members: number;
    independent_evidence_count?: number;
  };
  stale: {
    is_stale: boolean;
    invalidation_event_ids?: Array<string>;
    stale_claim_ids?: Array<string>;
    recomputed?: boolean;
  };
  status: "FRESH" | "STALE" | "INCOMPLETE";
  created_at?: IsoDateTime;
  created_by?: string;
}
export type EvidenceMapSha256Hex = string;
export type EvidenceMapIsoDateTime = string;

// hypothesis-card.schema.json (contractVersion 1.0.0)
export interface HypothesisCard {
  contractVersion: "1.0.0";
  card_id: string;
  card_type: "ANALOGY" | "HYPOTHESIS" | "OBSERVATION" | "MECHANISM_CLAIM";
  type_promotion?: {
    from_type: "ANALOGY" | "HYPOTHESIS" | "OBSERVATION";
    to_type: "HYPOTHESIS" | "MECHANISM_CLAIM";
    reviewed_by: string;
    basis: string;
    review_artifact?: string;
  } | null;
  originating_domains: Array<string>;
  nodes: Array<{
    claim_id: string;
    revision: number;
    domain: string;
    role: "source" | "target" | "mediator" | "context";
  }>;
  proposed_relation: {
    subject: string;
    predicate: string;
    object: string;
    relation_strength: "ANALOGICAL_STRUCTURE" | "TEMPORAL_CO-OCCURRENCE" | "CORRELATION_EVIDENCE" | "MEDIATED_PATHWAY" | "EXPERIMENTAL";
    causal_assertion?: boolean | null;
  };
  temporal_ordering?: {
    established: boolean;
    evidence_claim_ids?: Array<string>;
    event_times?: Array<{
    node: string;
    time: IsoDateTime;
  }>;
  };
  mediators?: Array<{
    description: string;
    claim_id?: string | null;
    evidence_status?: "SUPPORTED" | "PROPOSED" | "NOT_FOUND";
  }>;
  confounders: Array<{
    description: string;
    status: "IDENTIFIED" | "RULED_OUT" | "UNRESOLVED";
    claim_id?: string | null;
  }>;
  alternative_explanations: Array<{
    description: string;
    claim_id?: string | null;
  }>;
  scope: {
    population?: string | null;
    geography?: string | null;
    period?: {
    start: IsoDateTime;
    end: IsoDateTime;
  } | null;
    units?: string | null;
    domain_limits: Array<string>;
  };
  assumptions: Array<string>;
  falsifiers: Array<{
    description: string;
    observable?: string;
  }>;
  test_design: string;
  counterevidence: Array<{
    claim_id: string;
    relation: "contradicts" | "weakens" | "bounds";
  }>;
  novelty: {
    assessment: "novel_to_selected_corpus" | "similar_prior_found" | "NOT_ASSESSED";
    corpus?: string | null;
    search_horizon?: string | null;
    similar_prior_refs?: Array<{
    claim_id: string;
    similarity?: "SAME_RELATION" | "SAME_STRUCTURE" | "SAME_DOMAIN_PAIR";
  }>;
  };
  uncertainty: {
    author_confidence?: number | null;
    expert_trust?: number | null;
    measured_calibration?: number | null;
    evidence_support: number;
  };
  stale: {
    is_stale: boolean;
    invalidation_event_ids?: Array<string>;
    stale_claim_ids?: Array<string>;
  };
  status: "FRESH" | "STALE";
  created_at?: IsoDateTime;
  created_by?: string;
}
export type HypothesisCardIsoDateTime = string;

// synthesis-result.schema.json (contractVersion 1.0.0)
export interface SynthesisResult {
  contractVersion: "1.0.0";
  result_id: string;
  request_digest: Sha256Hex;
  input_versions: {
    contracts_version: string;
    corpus_version: string;
    index_version: string;
    retrieval_model_version: string;
    as_of?: IsoDateTime;
  };
  evidence_maps: Array<EvidenceMap>;
  hypothesis_cards: Array<HypothesisCard>;
  competing_explanations: Array<{
    description: string;
    supporting_claim_ids?: Array<string>;
    card_id?: string | null;
    status: "LIVE" | "WEAKENED" | "REFUTED" | "UNRESOLVED";
    disagreement_conditions?: string;
  }>;
  unresolved_contradictions: Array<{
    claim_a: string;
    claim_b: string;
    relation: "CONTRADICTS" | "SCOPE_DIFFERENCE" | "INCOMMENSURABLE";
    basis?: string;
    handling: "BOTH_SHOWN" | "DEFERRED_TO_VERIFIER" | "ABSTAIN";
  }>;
  coverage: {
    questions_total: number;
    answered: number;
    abstained: number;
    coverage_gaps?: Array<{
    query: string;
    reason: "NO_ENTAILING_EVIDENCE" | "SOURCE_MISSING" | "ACCESS_DENIED" | "AFTER_AS_OF" | "BUDGET_EXHAUSTED" | "NO_CANDIDATES";
  }>;
  };
  abstentions?: Array<{
    reason: "NO_ENTAILING_EVIDENCE" | "SOURCE_MISSING" | "ACCESS_DENIED" | "AFTER_AS_OF" | "BUDGET_EXHAUSTED" | "NO_CANDIDATES";
    detail?: string;
  }>;
  status: "READY_FOR_REVIEW" | "INCOMPLETE" | "BLOCKED";
  reasons: Array<string>;
  execution?: {
    executor_id: string;
    pid: number;
    nonce: string;
    clock?: IsoDateTime;
  };
  testedImplementationCommit?: string | null;
}
export type SynthesisResultSha256Hex = string;
export type SynthesisResultIsoDateTime = string;
