// S2-007 typed Agent Board errors (issue §2, §4, §5).
// One class per closed error code. Three rules are absolute:
//
//  1. A failure NEVER degrades into a silent success. Every refusal on the
//     board, the execution boundary or the store throws a BoardError subclass
//     whose `code` is a member of ERROR_CODES.
//  2. An unknown external side effect is UNKNOWN_OUTCOME /
//     RECONCILIATION_REQUIRED and is marked non-retryable. It is never a blind
//     retry, and never a fabricated success.
//  3. `detail` is bounded and redacted. Secrets, raw tokens, private locators
//     and user data must never reach a message, an outbox row or a log.
import { ERROR_CODES, NON_RETRYABLE_CODES } from './constants.mjs';

const CODE_SET = new Set(ERROR_CODES);
const NON_RETRYABLE = new Set(NON_RETRYABLE_CODES);

const MAX_DETAIL = 2000;
const MAX_MESSAGE = 500;

// Bounded, secret-shaped redaction applied to every message and detail before
// it is stored or returned. This is defence in depth, not a substitute for
// never passing a secret in.
const REDACTIONS = Object.freeze([
  [/gh[pousr]_[A-Za-z0-9]{16,}/g, 'gh<redacted>'],
  [/\bgithub_pat_[A-Za-z0-9_]{16,}/g, 'github_pat<redacted>'],
  [/\bsk-[A-Za-z0-9_-]{16,}/g, 'sk<redacted>'],
  [/\b(?:api[_-]?key|token|secret|password|passwd|authorization)\b\s*[:=]\s*\S+/gi, 'credential<redacted>'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*/gi, 'Bearer <redacted>'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '<redacted-private-key>'],
  [/\/home\/[^\s"']+\/[^\s"']*(?:\.env|\.ssh|id_rsa|credentials)[^\s"']*/gi, '<redacted-private-locator>'],
]);

export function redact(value) {
  if (typeof value !== 'string') return value;
  let out = value;
  for (const [pattern, replacement] of REDACTIONS) out = out.replace(pattern, replacement);
  return out;
}

function bound(text, max) {
  const value = redact(String(text ?? ''));
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export class BoardError extends Error {
  constructor(code, message, detail = undefined) {
    super(bound(message ?? code, MAX_MESSAGE));
    if (!CODE_SET.has(code)) {
      // An unknown code is itself a defect: fail closed loudly rather than
      // letting a free-form string escape the closed enum.
      throw new Error(`BOARD_ERROR_CODE_UNKNOWN:${String(code)}`);
    }
    this.name = 'BoardError';
    this.code = code;
    this.retryable = !NON_RETRYABLE.has(code);
    if (detail !== undefined) this.detail = bound(detail, MAX_DETAIL);
  }

  toDocument(occurredAt) {
    return {
      contractVersion: '1.0.0',
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      detail: this.detail ?? null,
      occurred_at: occurredAt,
    };
  }
}

// --- mandatory boundary codes (issue §2) -----------------------------------

// No authenticated server-side principal, or a payload tried to assert one.
export class AuthRequired extends BoardError {
  constructor(message = 'AUTH_REQUIRED', detail = undefined) {
    super('AUTH_REQUIRED', message, detail);
    this.name = 'AuthRequired';
  }
}

// The adapter, its registration and the current grant do not agree on the
// capability set, the tool set or the workspace.
export class CapabilityMismatch extends BoardError {
  constructor(message = 'CAPABILITY_MISMATCH', detail = undefined) {
    super('CAPABILITY_MISMATCH', message, detail);
    this.name = 'CapabilityMismatch';
  }
}

// A numeric budget scope is exhausted or was never assigned. An unassigned
// budget is not zero and a free model is not an authorization.
export class BudgetExceeded extends BoardError {
  constructor(message = 'BUDGET_EXCEEDED', detail = undefined) {
    super('BUDGET_EXCEEDED', message, detail);
    this.name = 'BudgetExceeded';
  }
}

// No healthy registered adapter, or the executor is not installed.
export class AgentUnavailable extends BoardError {
  constructor(message = 'AGENT_UNAVAILABLE', detail = undefined) {
    super('AGENT_UNAVAILABLE', message, detail);
    this.name = 'AgentUnavailable';
  }
}

export class TimeoutError extends BoardError {
  constructor(message = 'TIMEOUT', detail = undefined) {
    super('TIMEOUT', message, detail);
    this.name = 'TimeoutError';
  }
}

export class Cancelled extends BoardError {
  constructor(message = 'CANCELLED', detail = undefined) {
    super('CANCELLED', message, detail);
    this.name = 'Cancelled';
  }
}

// The executor returned something that is not a contract-valid
// ExecutionResult / ExecutionEvent.
export class MalformedResult extends BoardError {
  constructor(message = 'MALFORMED_RESULT', detail = undefined) {
    super('MALFORMED_RESULT', message, detail);
    this.name = 'MalformedResult';
  }
}

// The external side effect happened but its outcome is unknown.
export class UnknownOutcome extends BoardError {
  constructor(message = 'UNKNOWN_OUTCOME', detail = undefined) {
    super('UNKNOWN_OUTCOME', message, detail);
    this.name = 'UnknownOutcome';
  }
}

// An unknown side effect is pending an authorized reconciliation decision.
export class ReconciliationRequired extends BoardError {
  constructor(message = 'RECONCILIATION_REQUIRED', detail = undefined) {
    super('RECONCILIATION_REQUIRED', message, detail);
    this.name = 'ReconciliationRequired';
  }
}

// --- fail-closed internal conditions ---------------------------------------

export class ProviderFailure extends BoardError {
  constructor(message = 'PROVIDER_FAILURE', detail = undefined) {
    super('PROVIDER_FAILURE', message, detail);
    this.name = 'ProviderFailure';
  }
}

export class EmptyResponse extends BoardError {
  constructor(message = 'EMPTY_RESPONSE', detail = undefined) {
    super('EMPTY_RESPONSE', message, detail);
    this.name = 'EmptyResponse';
  }
}

export class AclDenied extends BoardError {
  constructor(message = 'ACL_DENIED', detail = undefined) {
    super('ACL_DENIED', message, detail);
    this.name = 'AclDenied';
  }
}

export class BlockedPolicy extends BoardError {
  constructor(message = 'BLOCKED_POLICY', detail = undefined) {
    super('BLOCKED_POLICY', message, detail);
    this.name = 'BlockedPolicy';
  }
}

// The required isolation profile cannot be proven for this OS/sandbox. The
// live path stays blocked; it does not degrade to an unisolated run.
export class BlockedSandbox extends BoardError {
  constructor(message = 'BLOCKED_SANDBOX', detail = undefined) {
    super('BLOCKED_SANDBOX', message, detail);
    this.name = 'BlockedSandbox';
  }
}

export class IdempotencyConflict extends BoardError {
  constructor(message = 'IDEMPOTENCY_CONFLICT', detail = undefined) {
    super('IDEMPOTENCY_CONFLICT', message, detail);
    this.name = 'IdempotencyConflict';
  }
}

export class RevisionConflict extends BoardError {
  constructor(message = 'REVISION_CONFLICT', detail = undefined) {
    super('REVISION_CONFLICT', message, detail);
    this.name = 'RevisionConflict';
  }
}

// A callback, checkpoint or result arrived with a fence that is no longer the
// current one. It mutates nothing.
export class StaleFence extends BoardError {
  constructor(message = 'STALE_FENCE', detail = undefined) {
    super('STALE_FENCE', message, detail);
    this.name = 'StaleFence';
  }
}

export class ContractVersionUnknown extends BoardError {
  constructor(message = 'CONTRACT_VERSION_UNKNOWN', detail = undefined) {
    super('CONTRACT_VERSION_UNKNOWN', message, detail);
    this.name = 'ContractVersionUnknown';
  }
}

export class TransitionNotAllowed extends BoardError {
  constructor(message = 'TRANSITION_NOT_ALLOWED', detail = undefined) {
    super('TRANSITION_NOT_ALLOWED', message, detail);
    this.name = 'TransitionNotAllowed';
  }
}

export class NeedsInput extends BoardError {
  constructor(message = 'NEEDS_INPUT', detail = undefined) {
    super('NEEDS_INPUT', message, detail);
    this.name = 'NeedsInput';
  }
}

// No genuinely installed real adapter backed the run. This is the honest
// result and it is never upgraded by fixture or replay evidence.
export class NotRunRealAdapter extends BoardError {
  constructor(message = 'NOT_RUN_REAL_ADAPTER', detail = undefined) {
    super('NOT_RUN_REAL_ADAPTER', message, detail);
    this.name = 'NotRunRealAdapter';
  }
}

// PostgreSQL was required and unavailable. Never a silent skip.
export class NotRunDb extends BoardError {
  constructor(message = 'NOT_RUN_DB', detail = undefined) {
    super('NOT_RUN_DB', message, detail);
    this.name = 'NotRunDb';
  }
}

const BY_CODE = new Map(Object.entries({
  AUTH_REQUIRED: AuthRequired,
  CAPABILITY_MISMATCH: CapabilityMismatch,
  BUDGET_EXCEEDED: BudgetExceeded,
  AGENT_UNAVAILABLE: AgentUnavailable,
  TIMEOUT: TimeoutError,
  CANCELLED: Cancelled,
  MALFORMED_RESULT: MalformedResult,
  UNKNOWN_OUTCOME: UnknownOutcome,
  RECONCILIATION_REQUIRED: ReconciliationRequired,
  PROVIDER_FAILURE: ProviderFailure,
  EMPTY_RESPONSE: EmptyResponse,
  ACL_DENIED: AclDenied,
  BLOCKED_POLICY: BlockedPolicy,
  BLOCKED_SANDBOX: BlockedSandbox,
  IDEMPOTENCY_CONFLICT: IdempotencyConflict,
  REVISION_CONFLICT: RevisionConflict,
  STALE_FENCE: StaleFence,
  CONTRACT_VERSION_UNKNOWN: ContractVersionUnknown,
  TRANSITION_NOT_ALLOWED: TransitionNotAllowed,
  NEEDS_INPUT: NeedsInput,
  NOT_RUN_REAL_ADAPTER: NotRunRealAdapter,
  NOT_RUN_DB: NotRunDb,
}));

export function isBoardError(value) {
  return value instanceof BoardError;
}

// The ONLY sanctioned translation from a thrown value to a typed boundary
// error. An exception, a timeout or an unavailable executor NEVER becomes a
// success and NEVER becomes a semantic verdict. A crash between two writes is
// RECONCILIATION_REQUIRED, never a silent retry.
export function toBoardError(error, fallbackCode = 'PROVIDER_FAILURE') {
  if (isBoardError(error)) return error;
  if (error && (error.code === 'ETIMEDOUT' || error.name === 'TimeoutError' || error.timeout === true)) {
    return new TimeoutError('executor call timed out', String(error.message ?? '').slice(0, 400));
  }
  if (error && error.code === 'ECONNREFUSED') {
    return new AgentUnavailable('executor transport refused the connection', String(error.message ?? '').slice(0, 400));
  }
  if (error && error.code === 'STORE_OUTCOME_UNKNOWN') {
    return new ReconciliationRequired('store transaction outcome could not be confirmed', String(error.message ?? '').slice(0, 400));
  }
  const code = CODE_SET.has(fallbackCode) ? fallbackCode : 'PROVIDER_FAILURE';
  return new BoardError(code, String(error?.message ?? error ?? 'unexpected failure').slice(0, 400));
}

export function errorClassForCode(code) {
  return BY_CODE.get(code) ?? BoardError;
}

export { ERROR_CODES, NON_RETRYABLE_CODES };
