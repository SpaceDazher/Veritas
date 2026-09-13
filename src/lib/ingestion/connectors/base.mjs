// S2-003 connector base contract.
// Every adapter implements the same observable operations and may only
// produce the same normalized outcomes. A connector never receives rights
// from source content: text, frontmatter, HTML annotations, transcripts,
// README text, issue comments and model output are untrusted data and can
// never change policy, ACL, grants, sandbox profiles or tool availability.
export const CONNECTOR_OPERATIONS = Object.freeze([
  'discoverCapabilities',
  'resolveDescriptor',
  'fetchVersion',
  'extract',
  'reconcile',
  'observeDeletion',
]);

export const CONNECTOR_ERROR_CODES = Object.freeze([
  'BLOCKED_CONNECTOR',
  'ACCESS_DENIED',
  'NOT_FOUND',
  'TOMBSTONED',
  'RATE_LIMITED',
  'TIMEOUT',
  'MALFORMED_CONTENT',
  'UNSUPPORTED_FORMAT',
  'LICENSE_UNKNOWN',
  'RETENTION_BLOCKED',
  'QUARANTINED',
  'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED',
]);

// Raised when the true outcome cannot be observed (crash, cut connection).
// The pipeline must record RECONCILIATION_REQUIRED, never blind-retry.
export class UnknownOutcomeError extends Error {
  constructor(operationId, detail) {
    super(`UNKNOWN_OUTCOME: ${detail ?? 'connector outcome unobservable'}`);
    this.name = 'UnknownOutcomeError';
    this.operationId = operationId;
  }
}

export function connectorError(code, { operationId, connectorId, sourceId = null, retryable = false, reconciliationAction = 'manual_review', detail = '' }) {
  if (!CONNECTOR_ERROR_CODES.includes(code)) {
    throw new Error(`CONNECTOR_ERROR_CODE_INVALID: ${code}`);
  }
  if (code === 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED' && reconciliationAction === 'none') {
    reconciliationAction = 'reconcile_operation';
  }
  return {
    contractVersion: '1.0.0',
    error_id: `err-${sha256Short(`${operationId}:${code}:${detail}`)}`,
    connector_id: connectorId,
    source_id: sourceId,
    operation_id: operationId,
    code,
    retryable,
    reconciliation_action: code === 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED' ? 'reconcile_operation' : reconciliationAction,
    diagnostic: {
      redacted_detail: String(detail).slice(0, 2048) || code,
      redaction_applied: true,
      detail_sha256: null,
    },
    // occurred_at is stamped by the pipeline from the injected decision clock;
    // connectors are deterministic and clock-free.
    occurred_at: null,
  };
}

import { createHash } from 'node:crypto';
function sha256Short(text) {
  return createHash('sha256').update(text).digest('hex').slice(0, 16);
}

// Assertion helper: an adapter result must be one of the normalized shapes.
export function assertConnectorShape(result) {
  if (result === null || typeof result !== 'object') {
    throw new Error('CONNECTOR_RESULT_MALFORMED');
  }
  return result;
}
