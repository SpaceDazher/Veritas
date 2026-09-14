// S2-003 ingestion contract TypeScript types.
// GENERATED from contracts/*.schema.json by scripts/generate-ingestion-types.mjs.
// Do not edit by hand: the JSON Schemas are the single source of truth and
// tests/ingestion/contracts.types.test.mjs fails if this file drifts.

// source-descriptor.schema.json (contractVersion 1.0.0)
export interface SourceDescriptor {
  contractVersion: "1.0.0";
  source_id: SourceDescriptorSourceId;
  connector_id: SourceDescriptorConnectorId;
  source_kind: SourceDescriptorSourceKind;
  canonical_locator: string;
  display_locator: string;
  owner: SourceDescriptorPrincipalId;
  author?: string | null;
  publisher?: string | null;
  workspace_id: SourceDescriptorWorkspaceId;
  tenant_id: SourceDescriptorWorkspaceId;
  classification: {
    visibility: "public" | "project" | "private";
    allowed_workspace_ids?: Array<SourceDescriptorWorkspaceId>;
    allowed_principal_ids?: Array<SourceDescriptorPrincipalId>;
  };
  license: {
    spdx: string | "LICENSE_UNKNOWN";
    attribution_required: boolean;
  };
  retention: {
    policy: "keep_forever" | "retain_then_delete" | "delete_on_source_deletion";
    retain_until?: SourceDescriptorUtcTimestamp | null;
  };
  lifecycle: {
    state: "enabled" | "blocked" | "tombstoned";
    reason?: string | null;
    changed_at?: SourceDescriptorUtcTimestamp | null;
  };
  registered_at: SourceDescriptorUtcTimestamp;
  registered_by?: SourceDescriptorPrincipalId;
}
export type SourceDescriptorUtcTimestamp = string;
export type SourceDescriptorSourceId = string;
export type SourceDescriptorConnectorId = string;
export type SourceDescriptorPrincipalId = string;
export type SourceDescriptorWorkspaceId = string;
export type SourceDescriptorSourceKind = "markdown_obsidian" | "web_url" | "pdf" | "github" | "telegram" | "youtube" | "arxiv_huggingface" | "manual_export";

// connector-contract.schema.json (contractVersion 1.0.0)
export interface ConnectorContract {
  contractVersion: "1.0.0";
  connector_id: ConnectorContractConnectorId;
  connector_version: string;
  source_kind: ConnectorContractSourceKind;
  auth_mode: "none" | "grant_required" | "blocked_without_credential";
  required_grant_scope?: string | null;
  read_only: true;
  sandbox_profile_id?: string | null;
  capability_id?: string | null;
  operations: {
    discoverCapabilities: true;
    resolveDescriptor: true;
    fetchVersion: true;
    extract: true;
    reconcile: true;
    observeDeletion: true;
  };
  limits: {
    timeout_ms: number;
    max_attempts: number;
    max_bytes: number;
    rate_limit_per_minute?: number;
  };
  reconciliation: {
    supported: boolean;
    unknown_outcome_policy: "RECONCILIATION_REQUIRED" | "BLOCKED_CONNECTOR";
  };
  terminal_states: Array<"COMMITTED" | "BLOCKED_CONNECTOR" | "ACCESS_DENIED" | "TOMBSTONED" | "QUARANTINED" | "FAILED" | "CANCELLED" | "RECONCILIATION_REQUIRED">;
}
export type ConnectorContractConnectorId = string;
export type ConnectorContractSourceKind = "markdown_obsidian" | "web_url" | "pdf" | "github" | "telegram" | "youtube" | "arxiv_huggingface" | "manual_export";

// fetch-request.schema.json (contractVersion 1.0.0)
export interface FetchRequest {
  contractVersion: "1.0.0";
  operation_id: string;
  source_id: FetchRequestSourceId;
  connector_id: FetchRequestConnectorId;
  version_selector: {
    latest?: true;
    snapshot_id?: FetchRequestSnapshotId;
    upstream_version?: string;
  };
  actor: FetchRequestPrincipalId;
  locator: string;
  claimed?: null | {
    published_at?: FetchRequestUtcTimestamp | null;
    event_time?: FetchRequestUtcTimestamp | null;
    language?: string | null;
  };
  identity?: null | {
    canonical_locator?: string;
  };
  workspace_id: FetchRequestWorkspaceId;
  grant_id?: string | null;
  lease_id?: string | null;
  budget: {
    max_bytes: number;
    max_segments?: number;
    time_limit_ms: number;
  };
  requested_at: FetchRequestUtcTimestamp;
}
export type FetchRequestUtcTimestamp = string;
export type FetchRequestSourceId = string;
export type FetchRequestSnapshotId = string;
export type FetchRequestConnectorId = string;
export type FetchRequestPrincipalId = string;
export type FetchRequestWorkspaceId = string;

// source-snapshot.schema.json (contractVersion 1.0.0)
export interface SourceSnapshot {
  contractVersion: "1.0.0";
  snapshot_id: SourceSnapshotSnapshotId;
  source_id: SourceSnapshotSourceId;
  connector_id: SourceSnapshotConnectorId;
  source_kind: SourceSnapshotSourceKind;
  version: number;
  snapshot_kind: "content" | "tombstone";
  tombstone_reason?: string | null;
  canonical_url?: string | null;
  canonical_message_id?: string | null;
  canonical_repository_id?: string | null;
  canonical_object_id?: string | null;
  canonical_locator: string;
  canonicalization_version: string;
  raw_sha256: SourceSnapshotSha256Hex;
  normalized_sha256: SourceSnapshotSha256Hex;
  author?: string | null;
  publisher?: string | null;
  published_at?: SourceSnapshotUtcTimestamp | null;
  event_time?: SourceSnapshotUtcTimestamp | null;
  observed_at: SourceSnapshotUtcTimestamp;
  fetched_at: SourceSnapshotUtcTimestamp;
  parent_snapshot_id?: SourceSnapshotSnapshotId | null;
  supersedes_snapshot_id?: SourceSnapshotSnapshotId | null;
  language?: string | null;
  mime_type?: string | null;
  size_bytes: number;
  extraction_status: "COMPLETE" | "PARTIAL" | "FAILED" | "QUARANTINED";
  acl: {
    visibility: "public" | "project" | "private";
    workspace_id: SourceSnapshotWorkspaceId;
    tenant_id: SourceSnapshotWorkspaceId;
    allowed_workspace_ids?: Array<SourceSnapshotWorkspaceId>;
    allowed_principal_ids?: Array<SourceSnapshotPrincipalId>;
  };
  license: {
    spdx: string | "LICENSE_UNKNOWN";
    attribution_required: boolean;
  };
  retention: {
    policy: "keep_forever" | "retain_then_delete" | "delete_on_source_deletion";
    retain_until?: SourceSnapshotUtcTimestamp | null;
  };
  fetch_provenance: {
    operation_id: string;
    run_id?: string | null;
    connector_id: SourceSnapshotConnectorId;
    connector_version: string;
    fetched_from: string;
    fetched_at: SourceSnapshotUtcTimestamp;
    grant_id?: string | null;
    content_type_validated?: boolean;
  };
}
export type SourceSnapshotUtcTimestamp = string;
export type SourceSnapshotSha256Hex = string;
export type SourceSnapshotSourceId = string;
export type SourceSnapshotSnapshotId = string;
export type SourceSnapshotConnectorId = string;
export type SourceSnapshotPrincipalId = string;
export type SourceSnapshotWorkspaceId = string;
export type SourceSnapshotSourceKind = "markdown_obsidian" | "web_url" | "pdf" | "github" | "telegram" | "youtube" | "arxiv_huggingface" | "manual_export";

// content-segment.schema.json (contractVersion 1.0.0)
export interface ContentSegment {
  contractVersion: "1.0.0";
  segment_id: ContentSegmentSegmentId;
  snapshot_id: ContentSegmentSnapshotId;
  source_id: ContentSegmentSourceId;
  ordinal: number;
  coordinates: {
    page?: number;
    span?: {
      start: number;
      end: number;
    };
    line?: {
      start: number;
      end: number;
    };
    timecode?: {
      start_ms: number;
      end_ms: number;
    };
  };
  text?: string | null;
  text_sha256: ContentSegmentSha256Hex;
  original_language?: string | null;
  normalized_language?: string | null;
  extraction: {
    method: "native_text" | "parser" | "ocr" | "asr" | "manual_export";
    extractor_name: string;
    extractor_version: string;
    config_sha256?: ContentSegmentSha256Hex | null;
    confidence: number;
    uncertainty_flags?: Array<"LOW_CONFIDENCE" | "MISSING_RANGES" | "UNDECODABLE_BYTES" | "OCR_NOISY" | "ASR_NOISY" | "LANGUAGE_UNCERTAIN" | "TRUNCATED">;
    missing_ranges?: Array<{
    start: number;
    end: number;
  }>;
  };
  coverage?: {
    page_count?: number;
    line_count?: number;
    duration_ms?: number;
  };
  embedded_instruction_classification?: {
    present: boolean;
    classification: "none" | "instruction_attempt" | "prompt_injection_suspect" | "authority_claim";
    confidence?: number;
    note?: string | null;
  };
  status: "COMPLETE" | "PARTIAL" | "FAILED" | "QUARANTINED";
}
export type ContentSegmentSha256Hex = string;
export type ContentSegmentSegmentId = string;
export type ContentSegmentSnapshotId = string;
export type ContentSegmentSourceId = string;

// ingestion-run.schema.json (contractVersion 1.0.0)
export interface IngestionRun {
  contractVersion: "1.0.0";
  run_id: IngestionRunRunId;
  executor_id: string;
  pid?: number;
  nonce: string;
  output_root: string;
  frozen_inputs: {
    connector_contracts_sha256: IngestionRunSha256Hex;
    corpus_sha256: IngestionRunSha256Hex;
    policy_sha256: IngestionRunSha256Hex;
  };
  started_at?: IngestionRunUtcTimestamp | null;
  finished_at?: IngestionRunUtcTimestamp | null;
  environment: {
    commit: string;
    tree: string;
    node_version?: string | null;
    platform?: string | null;
  };
  counts: {
    total: number;
    COMMITTED?: number;
    BLOCKED_CONNECTOR?: number;
    ACCESS_DENIED?: number;
    TOMBSTONED?: number;
    QUARANTINED?: number;
    FAILED?: number;
    CANCELLED?: number;
    RECONCILIATION_REQUIRED?: number;
  };
  outcomes: Array<{
    operation_id: string;
    case_id?: string | null;
    terminal: "COMMITTED" | "BLOCKED_CONNECTOR" | "ACCESS_DENIED" | "TOMBSTONED" | "QUARANTINED" | "FAILED" | "CANCELLED" | "RECONCILIATION_REQUIRED";
    snapshot_id?: IngestionRunSnapshotId | null;
    error_code?: IngestionRunConnectorErrorCode | null;
    raw_observation_ref?: string | null;
  }>;
}
export type IngestionRunUtcTimestamp = string;
export type IngestionRunSha256Hex = string;
export type IngestionRunRunId = string;
export type IngestionRunSnapshotId = string;
export type IngestionRunConnectorErrorCode = "BLOCKED_CONNECTOR" | "ACCESS_DENIED" | "NOT_FOUND" | "TOMBSTONED" | "RATE_LIMITED" | "TIMEOUT" | "MALFORMED_CONTENT" | "UNSUPPORTED_FORMAT" | "LICENSE_UNKNOWN" | "RETENTION_BLOCKED" | "QUARANTINED" | "UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED";

// source-lineage.schema.json (contractVersion 1.0.0)
export interface SourceLineage {
  contractVersion: "1.0.0";
  lineage_id: string;
  relation: "exact_duplicate" | "mirror" | "translation" | "quotation" | "repost" | "derived";
  upstream_snapshot_id: SourceLineageSnapshotId;
  downstream_snapshot_id: SourceLineageSnapshotId;
  evidence: {
    method: "exact_raw_digest" | "exact_normalized_digest" | "canonical_identity" | "near_duplicate_classifier" | "manual";
    digest_sha256?: SourceLineageSha256Hex | null;
    detail?: string | null;
  };
  confidence?: number | null;
  automated: boolean;
  status: "candidate" | "confirmed";
  confirmed_by?: SourceLineagePrincipalId | null;
  created_at: SourceLineageUtcTimestamp;
}
export type SourceLineageUtcTimestamp = string;
export type SourceLineageSha256Hex = string;
export type SourceLineageSnapshotId = string;
export type SourceLineagePrincipalId = string;

// source-proposal.schema.json (contractVersion 1.0.0)
export interface SourceProposal {
  contractVersion: "1.0.0";
  proposal_id: string;
  proposer: SourceProposalPrincipalId;
  candidate_locator: string;
  proposed_source_kind: SourceProposalSourceKind;
  reason: string;
  expected_domain: string;
  uncertainty: {
    access_uncertain: boolean;
    license_uncertain: boolean;
    notes?: string | null;
  };
  status: "PROPOSED" | "REVIEW_REQUIRED" | "APPROVED" | "REJECTED";
  reviewed_by?: SourceProposalPrincipalId | null;
  decision_reason?: string | null;
  decided_at?: SourceProposalUtcTimestamp | null;
  created_at: SourceProposalUtcTimestamp;
}
export type SourceProposalUtcTimestamp = string;
export type SourceProposalPrincipalId = string;
export type SourceProposalSourceKind = "markdown_obsidian" | "web_url" | "pdf" | "github" | "telegram" | "youtube" | "arxiv_huggingface" | "manual_export";

// connector-error.schema.json (contractVersion 1.0.0)
export interface ConnectorError {
  contractVersion: "1.0.0";
  error_id: string;
  connector_id: ConnectorErrorConnectorId;
  source_id?: ConnectorErrorSourceId | null;
  operation_id: string;
  code: ConnectorErrorConnectorErrorCode;
  retryable: boolean;
  reconciliation_action: "none" | "retry_with_backoff" | "probe_source" | "manual_review" | "reconcile_operation";
  diagnostic: {
    redacted_detail: string;
    redaction_applied?: true;
    detail_sha256?: ConnectorErrorSha256Hex | null;
  };
  occurred_at: ConnectorErrorUtcTimestamp;
}
export type ConnectorErrorUtcTimestamp = string;
export type ConnectorErrorSha256Hex = string;
export type ConnectorErrorConnectorId = string;
export type ConnectorErrorSourceId = string;
export type ConnectorErrorConnectorErrorCode = "BLOCKED_CONNECTOR" | "ACCESS_DENIED" | "NOT_FOUND" | "TOMBSTONED" | "RATE_LIMITED" | "TIMEOUT" | "MALFORMED_CONTENT" | "UNSUPPORTED_FORMAT" | "LICENSE_UNKNOWN" | "RETENTION_BLOCKED" | "QUARANTINED" | "UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED";
