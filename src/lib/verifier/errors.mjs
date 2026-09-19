// S2-006 typed verifier errors (spec §5, §11).
// Every verifier failure is typed. The single most important rule: an
// exception, timeout or unavailable source NEVER maps into a semantic
// pass/fail — the only sanctioned translation is `missingnessForError`,
// which maps typed errors onto the closed `semantic-verification-item
// .missingness.kind` enum (evaluator_missing / timeout / policy_refusal /
// budget_exhausted / source_unavailable), never onto a verdict label.
// Unknown outcomes escalate to ReconciliationRequired, never blind retry.

export class VerifierError extends Error {
  constructor(code, message, detail = undefined) {
    super(message ?? code);
    this.name = 'VerifierError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

// A verifier-level policy gate refused the operation before/at evaluation
// (exact-args mismatch, annotator adjudicating their own case, expired
// grant, ...). Never a semantic verdict.
export class VerifierPolicyBlock extends VerifierError {
  constructor(message, detail = undefined) {
    super('BLOCKED_POLICY', message, detail);
    this.name = 'VerifierPolicyBlock';
  }
}

// ACL/grant/capability denial. Applied before any text/span read.
export class AclDenied extends VerifierError {
  constructor(message, detail = undefined) {
    super('ACL_DENIED', message, detail);
    this.name = 'AclDenied';
  }
}

// Idempotency key reuse with different canonical arguments, or a record
// id reused with different content. No mutation ever accompanies it.
export class IdempotencyConflict extends VerifierError {
  constructor(message, detail = undefined) {
    super('IDEMPOTENCY_CONFLICT', message, detail);
    this.name = 'IdempotencyConflict';
  }
}

// Unknown commit outcome, fencing failure on a reconciled call, or a retry
// against an operation already marked RECONCILIATION_REQUIRED.
export class ReconciliationRequired extends VerifierError {
  constructor(message, detail = undefined) {
    super('RECONCILIATION_REQUIRED', message, detail);
    this.name = 'ReconciliationRequired';
  }
}

// The exact upstream artifact revision/digest no longer matches what the
// request bound (source moved on); the caller must re-request, not re-use.
export class StaleInput extends VerifierError {
  constructor(message, detail = undefined) {
    super('STALE_INPUT', message, detail);
    this.name = 'StaleInput';
  }
}

// PostgreSQL store unavailable — the gate is NOT_RUN_DB + NEEDS_INPUT,
// never a silent skip (spec §11).
export class NotRunDb extends VerifierError {
  constructor(message, detail = undefined) {
    super('NOT_RUN_DB', message, detail);
    this.name = 'NotRunDb';
  }
}

// A mandatory input is missing (checker, digests, grant fields, store).
// Missing inputs become NEEDS_INPUT, never implicit defaults (spec §8).
export class NeedsInput extends VerifierError {
  constructor(message, detail = undefined) {
    super('NEEDS_INPUT', message, detail);
    this.name = 'NeedsInput';
  }
}

// Unknown or unsupported contract version — rejected before any read.
export class ContractVersionUnknown extends VerifierError {
  constructor(message, detail = undefined) {
    super('CONTRACT_VERSION_UNKNOWN', message, detail);
    this.name = 'ContractVersionUnknown';
  }
}

// Internal store signal: the transaction outcome could not be confirmed
// (simulated crash/lost ack). Commands translate this into
// ReconciliationRequired; it must never surface as a semantic verdict.
export class StoreOutcomeUnknownError extends VerifierError {
  constructor(message, detail = undefined) {
    super('STORE_OUTCOME_UNKNOWN', message, detail);
    this.name = 'StoreOutcomeUnknownError';
  }
}

function isTimeout(error) {
  return (
    error.code === 'ETIMEDOUT' ||
    error.code === 'TIMEOUT' ||
    error.name === 'TimeoutError' ||
    error.name === 'AbortError' ||
    error.timeout === true
  );
}

// The ONLY sanctioned mapping from a thrown error to a typed missingness
// record acceptable by the semantic-verification-item contract
// (missingness.kind enum). It never returns a verdict label: an error is an
// abstention with a typed missingness kind, not a semantic pass/fail
// (spec §5, probe P). Unknown errors map to source_unavailable, never to a
// semantic verdict.
export function missingnessForError(error) {
  if (!error || typeof error !== 'object') {
    return { kind: 'source_unavailable', detail: 'non-object error thrown by checker' };
  }
  let kind;
  if (error instanceof VerifierPolicyBlock) kind = 'policy_refusal';
  else if (error instanceof NeedsInput || error instanceof ContractVersionUnknown || error instanceof NotRunDb) kind = 'evaluator_missing';
  else if (isTimeout(error)) kind = 'timeout';
  else if (error.code === 'BUDGET_EXHAUSTED') kind = 'budget_exhausted';
  else kind = 'source_unavailable';
  const detail = String(error.message ?? '').slice(0, 512);
  return detail.length > 0 ? { kind, detail } : { kind };
}

// Reason code for the closed semantic-verification-item reasonCode enum that
// corresponds to a typed missingness kind.
export function reasonCodeForMissingness(kind) {
  switch (kind) {
    case 'policy_refusal':
      return 'policy_block';
    case 'evaluator_missing':
      return 'evaluator_missing';
    default:
      return 'other';
  }
}
