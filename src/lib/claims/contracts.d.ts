// S2-004 claim graph contract TypeScript types.
// GENERATED from contracts/*.schema.json by scripts/generate-claim-types.mjs.
// Do not edit by hand: the JSON Schemas are the single source of truth and
// tests/claims/contracts.types.test.mjs fails if this file drifts.

// claim.schema.json (contractVersion 1.0.0)
export interface Claim {
  contractVersion: "1.0.0";
  claim_id: ClaimClaimId;
  revision: number;
  workspace_id: ClaimWorkspaceId;
  tenant_id: ClaimTenantId;
  acl?: {
    visibility: "public" | "project" | "private";
    workspace_id: ClaimWorkspaceId;
    tenant_id: ClaimTenantId;
    allowed_workspace_ids?: Array<ClaimWorkspaceId>;
    allowed_principal_ids?: Array<ClaimPrincipalId>;
  };
  epistemic_type: "OBSERVATION" | "FACT_CLAIM" | "EXPERT_OPINION" | "HYPOTHESIS" | "FORECAST" | "ANALOGY" | "MECHANISM_CLAIM";
  polarity: "affirmative" | "negated";
  modality?: "indicative" | "possibility" | "necessity" | "conditional" | null;
  denominator?: string | null;
  translation_provenance?: {
    translator: string;
    translator_version: string;
    translator_config_digest?: ClaimSha256Hex;
    source_claim_id: ClaimClaimId;
  } | null;
  normalized_text: string;
  original_text: string;
  subject: string;
  predicate: string;
  object: string;
  qualifiers?: Array<string>;
  uncertainty?: {
    type?: "aleatory" | "epistemic" | "both";
    description?: string;
  };
  method?: {
    name?: string;
    version?: string;
    config_digest?: ClaimSha256Hex;
  };
  assumptions?: Array<string>;
  exclusions?: Array<string>;
  units: string | null;
  value_range: {
    min: number;
    max: number;
  } | null;
  population: string | null;
  geography: string | null;
  period: {
    start: ClaimUtcTimestamp | null;
    end: ClaimUtcTimestamp | null;
  } | null;
  event_time: ClaimUtcTimestamp | null;
  published_at: ClaimUtcTimestamp | null;
  observed_at: ClaimUtcTimestamp;
  fetched_at: ClaimUtcTimestamp;
  language: string;
  translation_status: "original" | "translated" | "translation_pending";
  canonical_digest: ClaimSha256Hex;
  lifecycle: "PROPOSED" | "QUARANTINED" | "REVIEWED" | "ACCEPTED_BOUNDED" | "REJECTED" | "STALE" | "REVOKED" | "SUPERSEDED";
  supersedes_claim_id?: ClaimClaimId | null;
  supersedes_revision?: number | null;
  created_at: ClaimUtcTimestamp;
  created_by: ClaimPrincipalId;
}
export type ClaimUtcTimestamp = string;
export type ClaimSha256Hex = string;
export type ClaimClaimId = string;
export type ClaimWorkspaceId = string;
export type ClaimTenantId = string;
export type ClaimPrincipalId = string;

// evidence-edge.schema.json (contractVersion 1.0.0)
export interface EvidenceEdge {
  contractVersion: "1.0.0";
  edge_id: EvidenceEdgeEdgeId;
  claim_id: EvidenceEdgeClaimId;
  claim_revision: number;
  segment_id: EvidenceEdgeSegmentId;
  segment_revision: number;
  relation: "SUPPORTS" | "CONTRADICTS" | "QUALIFIES" | "CONTEXTUALIZES" | "DERIVED_FROM";
  span: {
    start: number;
    end: number;
  };
  quote_digest: EvidenceEdgeSha256Hex;
  entailment_status: "ENTAILED" | "CONTRADICTED" | "NEUTRAL" | "UNKNOWN";
  method: {
    name: string;
    version: string;
    config_digest?: EvidenceEdgeSha256Hex;
  };
  reviewer: EvidenceEdgePrincipalId | null;
  source_family_id: string;
  upstream_snapshot_ids: Array<EvidenceEdgeSnapshotId>;
  access_state: "available" | "restricted" | "tombstoned" | "unknown";
  retention_state: "active" | "expired" | "deleted";
  created_at: EvidenceEdgeUtcTimestamp;
  created_by: EvidenceEdgePrincipalId;
}
export type EvidenceEdgeUtcTimestamp = string;
export type EvidenceEdgeSha256Hex = string;
export type EvidenceEdgeClaimId = string;
export type EvidenceEdgeSegmentId = string;
export type EvidenceEdgeSnapshotId = string;
export type EvidenceEdgePrincipalId = string;
export type EvidenceEdgeEdgeId = string;

// claim-edge.schema.json (contractVersion 1.0.0)
export interface ClaimEdge {
  contractVersion: "1.0.0";
  edge_id: ClaimEdgeEdgeId;
  source_claim_id: ClaimEdgeClaimId;
  source_revision: number;
  target_claim_id: ClaimEdgeClaimId;
  target_revision: number;
  relation: "SUPPORTS" | "CONTRADICTS" | "REFINES" | "GENERALIZES" | "SPECIALIZES" | "DEPENDS_ON" | "SUPERSEDES" | "TRANSLATES" | "DUPLICATES_CANDIDATE";
  direction: "forward" | "bidirectional";
  scope_intersection: {
    population_overlap?: boolean;
    geography_overlap?: boolean;
    period_overlap?: boolean;
    units_compatible?: boolean;
  };
  provenance: {
    method: string;
    extractor: string;
    extractor_version: string;
    config_digest?: ClaimEdgeSha256Hex;
    confidence?: number;
  };
  creation_authority: ClaimEdgePrincipalId;
  created_at: ClaimEdgeUtcTimestamp;
  created_by: ClaimEdgePrincipalId;
}
export type ClaimEdgeUtcTimestamp = string;
export type ClaimEdgeSha256Hex = string;
export type ClaimEdgeClaimId = string;
export type ClaimEdgePrincipalId = string;
export type ClaimEdgeEdgeId = string;

// expert-profile.schema.json (contractVersion 1.0.0)
export interface ExpertProfile {
  contractVersion: "1.0.0";
  expert_id: ExpertProfileExpertId;
  aliases: Array<string>;
  domains: Array<{
    domain: string;
    valid_from: ExpertProfileUtcTimestamp;
    valid_until: ExpertProfileUtcTimestamp;
    provenance_claim_id?: ExpertProfileClaimId;
  }>;
  affiliations: Array<{
    organization: string;
    role: string;
    valid_from: ExpertProfileUtcTimestamp;
    valid_until: ExpertProfileUtcTimestamp;
    provenance_claim_id?: ExpertProfileClaimId;
  }>;
  conflicts: Array<{
    description: string;
    valid_from: ExpertProfileUtcTimestamp;
    valid_until: ExpertProfileUtcTimestamp;
    provenance_claim_id?: ExpertProfileClaimId;
  }>;
  valid_from: ExpertProfileUtcTimestamp;
  valid_until: ExpertProfileUtcTimestamp;
  credentials: Array<{
    credential_type: string;
    issuer: string;
    issued_at: ExpertProfileUtcTimestamp;
    expires_at?: ExpertProfileUtcTimestamp | null;
    provenance_claim_id: ExpertProfileClaimId;
  }>;
  created_at: ExpertProfileUtcTimestamp;
  created_by: ExpertProfilePrincipalId;
}
export type ExpertProfileUtcTimestamp = string;
export type ExpertProfileExpertId = string;
export type ExpertProfileClaimId = string;
export type ExpertProfilePrincipalId = string;

// expert-lens.schema.json (contractVersion 1.0.0)
export interface ExpertLens {
  contractVersion: "1.0.0";
  lens_id: ExpertLensLensId;
  owner_workspace_id: ExpertLensWorkspaceId;
  owner_principal_id: ExpertLensPrincipalId;
  expert_id: ExpertLensExpertId;
  domain: string;
  task_class: "fact_checking" | "forecasting" | "mechanism_analysis" | "policy_review" | "risk_assessment" | "synthesis";
  weight: number;
  valid_from: ExpertLensUtcTimestamp;
  valid_until: ExpertLensUtcTimestamp;
  rationale: string;
  issuer: ExpertLensPrincipalId;
  revoked_at: ExpertLensUtcTimestamp | null;
  revocation_reason?: string | null;
  created_at: ExpertLensUtcTimestamp;
}
export type ExpertLensUtcTimestamp = string;
export type ExpertLensLensId = string;
export type ExpertLensWorkspaceId = string;
export type ExpertLensPrincipalId = string;
export type ExpertLensExpertId = string;

// calibration-record.schema.json (contractVersion 1.0.0)
export interface CalibrationRecord {
  contractVersion: "1.0.0";
  calibration_id: CalibrationRecordCalibrationId;
  corpus_version: string;
  corpus_sha256: CalibrationRecordSha256Hex;
  outcome_definition: {
    metric: "extraction_accuracy" | "span_binding_accuracy" | "epistemic_type_accuracy" | "qualifier_preservation" | "contradiction_precision" | "contradiction_recall" | "upstream_collapse_accuracy" | "stale_invalidation_recall";
    threshold: number;
    description: string;
  };
  numerator: number;
  denominator: number;
  missing_count: number;
  uncertainty: {
    method: "wilson" | "clopper_pearson" | "bootstrap";
    confidence_interval: {
      lower: number;
      upper: number;
      confidence_level: number;
    };
  };
  evaluator_independence: {
    independent_evaluators: number;
    blind_to_producer: boolean;
    separate_processes?: boolean;
  };
  status: "MEASURED" | "NOT_MEASURED";
  not_measured_reason?: "no_valid_corpus" | "insufficient_samples" | "evaluator_not_independent" | "outcome_not_defined" | null;
  measured_at: CalibrationRecordUtcTimestamp;
  measured_by: CalibrationRecordPrincipalId;
}
export type CalibrationRecordUtcTimestamp = string;
export type CalibrationRecordSha256Hex = string;
export type CalibrationRecordCalibrationId = string;
export type CalibrationRecordPrincipalId = string;

// claim-extraction-request.schema.json (contractVersion 1.0.0)
export interface ClaimExtractionRequest {
  contractVersion: "1.0.0";
  request_id: ClaimExtractionRequestRequestId;
  segment_ids: Array<ClaimExtractionRequestSegmentId>;
  segment_hashes: Array<ClaimExtractionRequestSha256Hex>;
  extractor: string;
  extractor_version: string;
  prompt_version: string;
  parameters: Record<string, unknown>;
  seed: string | null;
  actor: ClaimExtractionRequestPrincipalId;
  workspace_id: ClaimExtractionRequestWorkspaceId;
  idempotency_key: string;
}
export type ClaimExtractionRequestSha256Hex = string;
export type ClaimExtractionRequestSegmentId = string;
export type ClaimExtractionRequestPrincipalId = string;
export type ClaimExtractionRequestWorkspaceId = string;
export type ClaimExtractionRequestRequestId = string;

// claim-extraction-result.schema.json (contractVersion 1.0.0)
export interface ClaimExtractionResult {
  contractVersion: "1.0.0";
  request_id: ClaimExtractionResultRequestId;
  proposed_claims: Array<ClaimExtractionResultProposedClaim>;
  abstentions: Array<{
    segment_id: ClaimExtractionResultSegmentId;
    reason: "ambiguous" | "insufficient_context" | "contradictory_signals" | "policy_blocked";
  }>;
  malformed_output: Array<{
    raw_output: string;
    parse_error: string;
  }>;
  audit_binding: {
    operation_id: string;
    executor_id: string;
    pid: number;
    nonce: string;
    output_root: ClaimExtractionResultSha256Hex;
  };
  status: "COMPLETED" | "QUARANTINED" | "FAILED" | "RECONCILIATION_REQUIRED";
  reconciliation_reason?: string | null;
  completed_at: ClaimExtractionResultUtcTimestamp;
}
export type ClaimExtractionResultUtcTimestamp = string;
export type ClaimExtractionResultSha256Hex = string;
export type ClaimExtractionResultSegmentId = string;
export type ClaimExtractionResultRequestId = string;
export type ClaimExtractionResultProposedClaim = {
    claim_id: ClaimId;
    normalized_text: string;
    original_text: string;
    epistemic_type: "OBSERVATION" | "FACT_CLAIM" | "EXPERT_OPINION" | "HYPOTHESIS" | "FORECAST" | "ANALOGY" | "MECHANISM_CLAIM";
    source_span: {
      segment_id: SegmentId;
      start: number;
      end: number;
    };
    evidence_digest: Sha256Hex;
  };
export type ClaimExtractionResultClaimId = string;

// claim-review-decision.schema.json (contractVersion 1.0.0)
export interface ClaimReviewDecision {
  contractVersion: "1.0.0";
  decision_id: ClaimReviewDecisionDecisionId;
  claim_id: ClaimReviewDecisionClaimId;
  claim_revision: number;
  claim_digest: ClaimReviewDecisionSha256Hex;
  actor: ClaimReviewDecisionPrincipalId;
  decision: "ACCEPT_BOUNDED" | "REJECT" | "QUARANTINE" | "REQUEST_REVISION";
  reason_codes: Array<"insufficient_evidence" | "contradicted_by_sources" | "epistemic_type_mismatch" | "qualifier_lost" | "unit_mismatch" | "scope_violation" | "private_leak" | "authority_expansion" | "duplicate_claim" | "producer_self_review">;
  expiry: ClaimReviewDecisionUtcTimestamp | null;
  supersession?: {
    supersedes_claim_id: ClaimReviewDecisionClaimId;
    supersedes_revision: number;
  } | null;
  idempotency_key: string;
  created_at: ClaimReviewDecisionUtcTimestamp;
}
export type ClaimReviewDecisionUtcTimestamp = string;
export type ClaimReviewDecisionSha256Hex = string;
export type ClaimReviewDecisionClaimId = string;
export type ClaimReviewDecisionPrincipalId = string;
export type ClaimReviewDecisionDecisionId = string;

// graph-invalidation-event.schema.json (contractVersion 1.0.0)
export interface GraphInvalidationEvent {
  contractVersion: "1.0.0";
  event_id: GraphInvalidationEventEventId;
  trigger_type: "source_snapshot_tombstone" | "source_snapshot_correction" | "source_snapshot_retraction" | "content_segment_tombstone" | "content_segment_correction" | "claim_tombstone" | "claim_correction" | "claim_revocation" | "access_restriction" | "retention_expiry";
  trigger_id: string;
  trigger_revision: number;
  affected_descendants: Array<{
    entity_type: "claim" | "evidence_edge" | "claim_edge";
    entity_id: string;
    entity_revision: number;
    new_lifecycle: "STALE" | "REVOKED" | "QUARANTINED";
  }>;
  reason: {
    code: "upstream_tombstoned" | "upstream_corrected" | "upstream_retracted" | "access_revoked" | "retention_expired" | "manual_invalidation";
    description: string;
  };
  traversal_evidence: {
    method: "bfs" | "dfs" | "topological";
    visited_count: number;
    edges_traversed: Array<string>;
  };
  completion_state: "PENDING" | "IN_PROGRESS" | "COMPLETED" | "FAILED" | "PARTIAL";
  failed_descendants?: Array<string>;
  created_at: GraphInvalidationEventUtcTimestamp;
  created_by: GraphInvalidationEventPrincipalId;
}
export type GraphInvalidationEventUtcTimestamp = string;
export type GraphInvalidationEventEventId = string;
export type GraphInvalidationEventPrincipalId = string;
