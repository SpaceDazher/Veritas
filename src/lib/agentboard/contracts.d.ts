// S2-007 Agent Board contract TypeScript types.
// GENERATED from contracts/*.schema.json by scripts/generate-board-types.mjs
// (including the transitive $ref closure over the upstream contract schemas).
// Do not edit by hand: the JSON Schemas are the single source of truth,
// src/lib/agentboard/contracts.mjs is the single validation surface, and
// tests/agentboard/contracts-drift.test.mjs fails if this file drifts.

// board-task.schema.json (contractVersion 1.0.0)
export interface BoardTask {
  contractVersion: "1.0.0";
  task_id: string;
  workspace_id: string;
  title: string;
  goal: string;
  description: string;
  acceptance_criteria: Array<string>;
  state: "BACKLOG" | "READY" | "CLAIMED" | "RUNNING" | "BLOCKED" | "IN_REVIEW" | "DONE" | "FAILED" | "CANCELLED";
  revision: number;
  priority: "HIGH" | "MEDIUM" | "LOW";
  dependencies: Array<string>;
  required_capabilities: Array<string>;
  allowed_tools: Array<string>;
  workspace_ref: BoardTaskWorkspaceRef;
  time_limits: {
    timeout_ms: number;
    max_runtime_ms: number;
    deadline: string | null;
  };
  cost_limits: {
    currency: "USD" | "EUR" | "GBP" | "RUB";
    max_task_cost: number;
    max_campaign_cost: number;
    max_day_cost: number;
  };
  acl: {
    visibility: "personal" | "project" | "shared";
    allowed_principal_ids: Array<string>;
  };
  brief_digest: BoardTaskDigest;
  policy_digest: BoardTaskDigest;
  manifest_digest: BoardTaskDigest;
  assigned_adapter_id: string | null;
  active_lease_id: string | null;
  fencing_token: number | null;
  attempts: number;
  artifacts: Array<{
    artifact_id: string;
    digest: BoardTaskDigest;
    media_type: string;
  }>;
  evidence_refs: Array<string>;
  block_reason: string | null;
  created_at: string;
  updated_at: string;
  history_digest: BoardTaskDigest;
}
export type BoardTaskDigest = string;
export type BoardTaskWorkspaceRef = {
    workspace_id: string;
    root_ref: string;
    isolation_profile_id: string;
    sandbox_profile_digest: BoardTaskDigest;
    read_only_paths: Array<string>;
  };

// board-transition.schema.json (contractVersion 1.0.0)
export interface BoardTransition {
  contractVersion: "1.0.0";
  transition_id: string;
  task_id: string;
  workspace_id: string;
  from_state: BoardTransitionState;
  to_state: BoardTransitionState;
  revision: number;
  actor: string;
  idempotency_key: string;
  reason: string;
  lease_id: string | null;
  fencing_token: number | null;
  brief_digest: BoardTransitionDigest;
  policy_digest: BoardTransitionDigest;
  manifest_digest: BoardTransitionDigest;
  occurred_at: string;
}
export type BoardTransitionState = "BACKLOG" | "READY" | "CLAIMED" | "RUNNING" | "BLOCKED" | "IN_REVIEW" | "DONE" | "FAILED" | "CANCELLED";
export type BoardTransitionDigest = string;

// adapter-registration.schema.json (contractVersion 1.0.0)
export interface AdapterRegistration {
  contractVersion: "1.0.0";
  adapter_id: string;
  adapter_interface: "veritas.adapter/1.0.0";
  provider: "codex" | "pi" | "claude_code" | "opencode" | "hermes" | "generic_cli" | "test";
  display_name: string;
  adapter_kind: "real" | "wrapper" | "test" | "unavailable";
  health: "healthy" | "degraded" | "unhealthy" | "unknown";
  workspace_id: string;
  principal_id: string;
  declared_capabilities: Array<string>;
  declared_tools: Array<string>;
  sandbox_profile_id: string;
  max_concurrency: number;
  real_adapter_provenance: {
    status: "NOT_RUN_REAL_ADAPTER" | "REAL_ADAPTER_AVAILABLE" | "REAL_ADAPTER_NOT_INSTALLED" | "REAL_ADAPTER_CREDENTIALS_MISSING";
    detail: string;
  };
  registered_at: string;
}

// dispatch-decision.schema.json (contractVersion 1.0.0)
export interface DispatchDecision {
  contractVersion: "1.0.0";
  decision_id: string;
  workspace_id: string;
  max_concurrency: number;
  selected_task_id: string | null;
  selected_adapter_id: string | null;
  selected_lease_id: string | null;
  selected_fencing_token: number | null;
  candidates: Array<{
    task_id: string;
    priority: "HIGH" | "MEDIUM" | "LOW";
    eligible: boolean;
    exclusion_reasons: Array<DispatchDecisionExclusion_reason>;
  }>;
  excluded: Array<{
    subject_kind: "task" | "adapter";
    subject_id: string;
    reasons: Array<DispatchDecisionExclusion_reason>;
  }>;
  reason: string;
  budget_snapshot: {
    currency: "USD" | "EUR" | "GBP" | "RUB";
    task_remaining: number;
    campaign_remaining: number;
    day_remaining: number;
    assigned: boolean;
  };
  decided_at: string;
}
export type DispatchDecisionExclusion_reason = "STATE_NOT_READY" | "DEPENDENCIES_OPEN" | "BRIEF_NOT_VALIDATED" | "CAPABILITY_MISMATCH" | "NO_HEALTHY_ADAPTER" | "BUDGET_NOT_ASSIGNED" | "BUDGET_EXHAUSTED" | "SANDBOX_NOT_PROVEN" | "CONCURRENCY_LIMIT_REACHED" | "ACTIVE_LEASE_EXISTS" | "ACL_DENIED" | "STALE_FENCE";

// execution-request.schema.json (contractVersion veritas.execution/1.0.0)
export interface ExecutionRequest {
  contract_version: "veritas.execution/1.0.0";
  request_id: string;
  idempotency_key: string;
  task_id: string;
  workspace_id: string;
  brief_digest: ExecutionRequestDigest;
  policy_digest: ExecutionRequestDigest;
  manifest_digest: ExecutionRequestDigest;
  principal_id: string;
  granted_scope: Array<"task.read" | "task.write" | "artifact.write" | "evidence.submit" | "checkpoint.write" | "budget.spend">;
  allowed_tools: Array<string>;
  workspace_ref: BoardTaskWorkspaceRef;
  budget_grant: {
    currency: "USD" | "EUR" | "GBP" | "RUB";
    task_limit: number;
    campaign_limit: number;
    day_limit: number;
    timeout_ms: number;
    granted_by: string;
    granted_at: string;
  };
  deadline: string | null;
  lease_id: string;
  fencing_token: number;
  adapter_id: string;
  issued_at: string;
  negotiated_capabilities?: Array<string>;
}
export type ExecutionRequestDigest = string;

// execution-event.schema.json (contractVersion veritas.execution/1.0.0)
export interface ExecutionEvent {
  contract_version: "veritas.execution/1.0.0";
  event_id: string;
  run_id: string;
  task_id: string;
  workspace_id: string;
  lease_id: string;
  fencing_token: number;
  sequence: number;
  event_type: "ACCEPTED" | "STARTED" | "PROGRESS" | "CHECKPOINT" | "ARTIFACT" | "COMPLETED" | "FAILED" | "CANCELLED" | "TIMED_OUT" | "UNKNOWN";
  payload: Record<string, unknown>;
  outcome: "SUCCEEDED" | "FAILED" | "CANCELLED" | "TIMEOUT" | "BLOCKED" | "RECONCILIATION_REQUIRED" | null;
  emitted_at: string;
}

// execution-result.schema.json (contractVersion veritas.execution/1.0.0)
export interface ExecutionResult {
  contract_version: "veritas.execution/1.0.0";
  run_id: string;
  task_id: string;
  workspace_id: string;
  lease_id: string;
  fencing_token: number;
  sequence: number;
  outcome: "SUCCEEDED" | "FAILED" | "CANCELLED" | "TIMEOUT" | "BLOCKED" | "RECONCILIATION_REQUIRED";
  checkpoints: Array<{
    checkpoint_id: string;
    sequence: number;
    brief_digest: string;
    workspace_digest: string;
    tool_digest: string;
    recorded_at: string;
  }>;
  artifact_hashes: Array<{
    artifact_id: string;
    digest: string;
    media_type: string;
  }>;
  measurements: {
    duration_ms: number;
    spend: number;
    currency: "USD" | "EUR" | "GBP" | "RUB";
    model_id: string | null;
    tool_calls: number;
  };
  error: BoardError | null;
  reconciliation_required: boolean;
  completed_at: string;
}

// board-error.schema.json (contractVersion 1.0.0)
export interface BoardError {
  contractVersion: "1.0.0";
  code: "AUTH_REQUIRED" | "CAPABILITY_MISMATCH" | "BUDGET_EXCEEDED" | "AGENT_UNAVAILABLE" | "TIMEOUT" | "CANCELLED" | "MALFORMED_RESULT" | "UNKNOWN_OUTCOME" | "RECONCILIATION_REQUIRED" | "PROVIDER_FAILURE" | "EMPTY_RESPONSE" | "ACL_DENIED" | "BLOCKED_POLICY" | "BLOCKED_SANDBOX" | "IDEMPOTENCY_CONFLICT" | "REVISION_CONFLICT" | "STALE_FENCE" | "CONTRACT_VERSION_UNKNOWN" | "TRANSITION_NOT_ALLOWED" | "NEEDS_INPUT" | "NOT_RUN_REAL_ADAPTER" | "NOT_RUN_DB";
  message: string;
  retryable: boolean;
  detail: string | null;
  occurred_at: string;
}
