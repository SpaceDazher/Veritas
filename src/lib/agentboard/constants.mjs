// S2-007 Agent Board constants (single source of truth).
// Every state, transition, error code, scope and policy limit used by the
// board lives here exactly once. The JSON Schemas in contracts/ describe the
// WIRE shape; this module describes the SEMANTIC machine (which transition is
// allowed, who may drive it, what it requires). Nothing else in src/lib/
// agentboard/ may re-declare a state list, a transition edge or an error code
// — a second editable form of the same truth is exactly what the boundary
// contract forbids.
import {
  SANDBOX_LOCAL_RESTRICTED_PODMAN,
  SANDBOX_UNTRUSTED_CODE_GVISOR,
  SANDBOX_LOCAL_RESTRICTED_BLOCKED,
  SANDBOX_NO_EXEC,
  SANDBOX_HOST_UNISOLATED,
} from '../identity/sandbox-profiles.mjs';

export const BOARD_CONTRACT_VERSION = '1.0.0';
export const EXECUTION_CONTRACT_VERSION = 'veritas.execution/1.0.0';
export const ADAPTER_INTERFACE_VERSION = 'veritas.adapter/1.0.0';
export const SCHEDULER_VERSION = 's2-007-scheduler-v1';
export const CANONICAL_JSON_VERSION = 'canonical-json-v1';
export const COMMAND_BOUNDARY_VERSION = 's2-007-command-v1';

// The bounded profile runs at most ONE active task (S2-001: one local
// scheduler, one running job). Raising it requires a new contract version.
export const MAX_CONCURRENT_TASKS = 1;
export const MAX_ADAPTER_CONCURRENCY = 1;

// The nine canonical S2-001 states, in evaluation order. Terminal states have
// no outgoing edges except the explicit requeue edges listed below.
export const BOARD_STATES = Object.freeze([
  'BACKLOG', 'READY', 'CLAIMED', 'RUNNING', 'BLOCKED', 'IN_REVIEW', 'DONE', 'FAILED', 'CANCELLED',
]);

export const PRIORITIES = Object.freeze(['HIGH', 'MEDIUM', 'LOW']);
export const PRIORITY_RANK = Object.freeze({ HIGH: 0, MEDIUM: 1, LOW: 2 });

// Transition table derived from docs/product/PRODUCT_CONTRACT.md §"Agent Board
// MVP contract". Each edge maps to the guard function name in policy.mjs that
// authorizes it, so the table and the guard set cannot drift apart.
export const TRANSITIONS = Object.freeze({
  // BACKLOG -> READY only after dependencies and the immutable brief validate.
  BACKLOG: Object.freeze({ READY: 'guardBacklogToReady', CANCELLED: 'guardCancel' }),
  // READY -> CLAIMED is the single-transaction unique active lease.
  READY: Object.freeze({ CLAIMED: 'guardReadyToClaimed', BLOCKED: 'guardBlock', CANCELLED: 'guardCancel' }),
  // CLAIMED -> READY is release/expiry and always requires side-effect
  // reconciliation first, never a blind retry.
  CLAIMED: Object.freeze({
    RUNNING: 'guardClaimedToRunning',
    READY: 'guardRelease',
    BLOCKED: 'guardBlock',
    CANCELLED: 'guardCancel',
  }),
  RUNNING: Object.freeze({
    IN_REVIEW: 'guardRunningToInReview',
    BLOCKED: 'guardBlock',
    FAILED: 'guardFail',
    CANCELLED: 'guardCancel',
    READY: 'guardRequeueAfterReconciliation',
  }),
  IN_REVIEW: Object.freeze({
    DONE: 'guardInReviewToDone',
    BLOCKED: 'guardBlock',
    FAILED: 'guardFail',
    CANCELLED: 'guardCancel',
    READY: 'guardRequeueAfterReconciliation',
  }),
  BLOCKED: Object.freeze({ READY: 'guardUnblock', CANCELLED: 'guardCancel' }),
  // FAILED is a known terminal failure; it may only be requeued explicitly or
  // cancelled. It is never silently promoted back into READY.
  FAILED: Object.freeze({ READY: 'guardRequeueAfterReconciliation', CANCELLED: 'guardCancel' }),
  // DONE and CANCELLED are terminal: no outgoing edges at all.
  DONE: Object.freeze({}),
  CANCELLED: Object.freeze({}),
});

export function isKnownState(state) {
  return BOARD_STATES.includes(state);
}

export function isTransitionAllowed(from, to) {
  return Object.prototype.hasOwnProperty.call(TRANSITIONS[from] ?? {}, to);
}

export function allowedTargets(from) {
  return Object.keys(TRANSITIONS[from] ?? {}).sort();
}

// Actor kinds that may drive a transition. `human` is the only kind that can
// reach DONE; the deterministic gate is a separate, explicitly authorized kind
// and an uncalibrated semantic verifier is never permitted to be it.
export const ACTOR_KINDS = Object.freeze([
  'human_owner', 'human_reviewer', 'deterministic_gate', 'adapter', 'scheduler', 'system',
]);

// Capabilities a caller may hold. These are the board-side scopes; the S2-002
// policy engine remains the single authorization point and this list never
// substitutes for it.
export const BOARD_CAPABILITIES = Object.freeze([
  'board.task.create',
  'board.task.read',
  'board.task.transition',
  'board.task.claim',
  'board.task.release',
  'board.execution.start',
  'board.execution.cancel',
  'board.result.collect',
  'board.evidence.submit',
  'board.review.approve',
  'board.review.challenge',
  'board.adapter.register',
  'board.budget.grant',
  'board.reconciliation.decide',
]);

// Execution scopes grantable inside a single ExecutionRequest.
export const EXECUTION_SCOPES = Object.freeze([
  'task.read', 'task.write', 'artifact.write', 'evidence.submit', 'checkpoint.write', 'budget.spend',
]);

// The closed typed error set. Codes are the contract value; classes live in
// errors.mjs and are mapped from these codes.
export const ERROR_CODES = Object.freeze([
  'AUTH_REQUIRED',
  'CAPABILITY_MISMATCH',
  'BUDGET_EXCEEDED',
  'AGENT_UNAVAILABLE',
  'TIMEOUT',
  'CANCELLED',
  'MALFORMED_RESULT',
  'UNKNOWN_OUTCOME',
  'RECONCILIATION_REQUIRED',
  'PROVIDER_FAILURE',
  'EMPTY_RESPONSE',
  'ACL_DENIED',
  'BLOCKED_POLICY',
  'BLOCKED_SANDBOX',
  'IDEMPOTENCY_CONFLICT',
  'REVISION_CONFLICT',
  'STALE_FENCE',
  'CONTRACT_VERSION_UNKNOWN',
  'TRANSITION_NOT_ALLOWED',
  'NEEDS_INPUT',
  'NOT_RUN_REAL_ADAPTER',
  'NOT_RUN_DB',
]);

// An error whose side effect is unknown is never safe to blind-retry: it
// requires observation or an authorized reconciliation decision.
export const NON_RETRYABLE_CODES = Object.freeze([
  'UNKNOWN_OUTCOME', 'RECONCILIATION_REQUIRED', 'STALE_FENCE', 'IDEMPOTENCY_CONFLICT',
  'REVISION_CONFLICT', 'MALFORMED_RESULT', 'TRANSITION_NOT_ALLOWED', 'CONTRACT_VERSION_UNKNOWN',
  'AUTH_REQUIRED', 'ACL_DENIED', 'CAPABILITY_MISMATCH',
]);

// Adapter interface required by S2-001. Every method is async and must reject
// with a typed error; returning undefined or a truthy value is not a contract
// satisfaction.
export const ADAPTER_METHODS = Object.freeze([
  'identify', 'capabilities', 'health', 'claim', 'start', 'status', 'checkpoint', 'cancel',
  'collect_result', 'release',
]);

// Sandbox profiles the board may bind a run to. S2-002 remains the single
// source of these profiles; the blocked variants are the fail-closed answers
// when the isolation profile cannot be proven for this OS/sandbox.
export const SANDBOX_PROFILES = Object.freeze([
  SANDBOX_LOCAL_RESTRICTED_PODMAN,
  SANDBOX_UNTRUSTED_CODE_GVISOR,
  SANDBOX_LOCAL_RESTRICTED_BLOCKED,
  SANDBOX_NO_EXEC,
  SANDBOX_HOST_UNISOLATED,
]);

// The two profiles whose OS controls are backed by measured S2-002 evidence.
// Every other registered profile is fail-closed for a live run: NO_EXEC is
// contract-valid but executes nothing, and the *_blocked profiles exist
// precisely because the tier could not be proven on this host.
export const PROVEN_SANDBOX_PROFILE_IDS = Object.freeze([
  SANDBOX_LOCAL_RESTRICTED_PODMAN.profile_id,
  SANDBOX_UNTRUSTED_CODE_GVISOR.profile_id,
]);

export function isExecutableSandboxProfile(profileId) {
  return PROVEN_SANDBOX_PROFILE_IDS.includes(profileId);
}

// The HOST_UNISOLATED floor tier (issue #45). It is deliberately NOT in
// PROVEN_SANDBOX_PROFILE_IDS: nothing about it is proven to be isolated, and
// `isExecutableSandboxProfile` must keep meaning "this tier has measured OS
// controls". A run may still be bound to it, but only through
// policy.assertLiveExecutionAuthorized, which demands a separate named human
// authorisation document that the server resolves and that no adapter, task or
// executor can supply. An A-MVP isolation clause may never be scored against it.
export const HOST_UNISOLATED_SANDBOX_PROFILE_IDS = Object.freeze([
  SANDBOX_HOST_UNISOLATED.profile_id,
]);

export function isHostUnisolatedSandboxProfile(profileId) {
  return HOST_UNISOLATED_SANDBOX_PROFILE_IDS.includes(profileId);
}

// What a live execution needs, before the run starts. An isolated tier with
// proven OS controls needs nothing extra. The host-unisolated floor needs a
// named human authorisation; everything else is refused exactly as before.
export const SANDBOX_TIERS = Object.freeze({
  ISOLATED: 'ISOLATED',
  HOST_UNISOLATED: 'HOST_UNISOLATED',
  BLOCKED: 'BLOCKED',
});

export function classifySandboxProfile(profileId) {
  if (isExecutableSandboxProfile(profileId)) return SANDBOX_TIERS.ISOLATED;
  if (isHostUnisolatedSandboxProfile(profileId)) return SANDBOX_TIERS.HOST_UNISOLATED;
  return SANDBOX_TIERS.BLOCKED;
}

// Digest conventions. `sha256:<64 hex>` on the wire; bare 64-hex when stored
// as a CHAR(64) column. Both directions must be lossless.
export const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
export const STORED_DIGEST_PATTERN = /^[0-9a-f]{64}$/;

export function toStoredDigest(digest) {
  if (typeof digest !== 'string' || !DIGEST_PATTERN.test(digest)) return null;
  return digest.slice('sha256:'.length);
}

export function toWireDigest(stored) {
  if (typeof stored !== 'string' || !STORED_DIGEST_PATTERN.test(stored)) return null;
  return `sha256:${stored}`;
}

export const ID_PREFIXES = Object.freeze({
  task: 'abt-',
  transition: 'trn-',
  adapter: 'adr-',
  lease: 'lse-',
  run: 'run-',
  event: 'eve-',
  result: 'res-',
  decision: 'dsc-',
  request: 'xer-',
  artifact: 'art-',
  evidence: 'evd-',
  checkpoint: 'chk-',
  operation: 'op-',
  grant: 'grt-',
  principal: 'prn-',
  workspace: 'ws-',
  sandbox: 'sbx-',
});
