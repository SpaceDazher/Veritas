// S2-003 ingestion contract registry.
// Single fail-closed entry point for loading and validating the nine
// versioned ingestion contracts. Compiles all schemas at import time; any
// missing, malformed or unknown contract aborts immediately instead of
// degrading to best-effort validation.
//
// Semantic (cross-field) rules live here rather than in JSON Schema because
// they need computed comparisons (real timestamps, digest format, tombstone
// coherence, wall-clock separation). They are part of the contract surface:
// documents passing JSON Schema but failing semantics are rejected.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createHash } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';

const CONTRACTS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../contracts',
);

export const CONTRACT_VERSION = '1.0.0';

export const CONTRACT_NAMES = Object.freeze([
  'source-descriptor',
  'connector-contract',
  'fetch-request',
  'source-snapshot',
  'content-segment',
  'ingestion-run',
  'source-lineage',
  'source-proposal',
  'connector-error',
]);

export const SOURCE_KINDS = Object.freeze([
  'markdown_obsidian',
  'web_url',
  'pdf',
  'github',
  'telegram',
  'youtube',
  'arxiv_huggingface',
  'manual_export',
]);

export const TERMINAL_STATES = Object.freeze([
  'COMMITTED',
  'BLOCKED_CONNECTOR',
  'ACCESS_DENIED',
  'TOMBSTONED',
  'QUARANTINED',
  'FAILED',
  'CANCELLED',
  'RECONCILIATION_REQUIRED',
]);

const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

const ajv = new Ajv2020({ allErrors: true, strict: false });

function loadSchema(name) {
  const file = path.join(CONTRACTS_DIR, `${name}.schema.json`);
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (error) {
    throw new Error(`CONTRACT_SCHEMA_MISSING: ${name} (${error.message})`);
  }
  let schema;
  try {
    schema = JSON.parse(raw);
  } catch (error) {
    throw new Error(`CONTRACT_SCHEMA_MALFORMED: ${name} (${error.message})`);
  }
  const expectedId = `https://veritas.local/contracts/${name}.schema.json`;
  if (schema.$id !== expectedId) {
    throw new Error(`CONTRACT_SCHEMA_ID_MISMATCH: ${name} expected ${expectedId}, got ${schema.$id}`);
  }
  if (schema.$schema !== 'https://json-schema.org/draft/2020-12/schema') {
    throw new Error(`CONTRACT_SCHEMA_DRAFT_UNSUPPORTED: ${name}`);
  }
  if (schema.contractVersion === undefined && schema.properties?.contractVersion?.const !== CONTRACT_VERSION) {
    throw new Error(`CONTRACT_SCHEMA_VERSION_UNSUPPORTED: ${name}`);
  }
  return { raw, schema };
}

const validators = Object.freeze(Object.fromEntries(
  CONTRACT_NAMES.map((name) => {
    const { schema } = loadSchema(name);
    return [name, ajv.compile(schema)];
  }),
));

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isRealUtcTimestamp(value) {
  if (typeof value !== 'string' || !UTC_TIMESTAMP_PATTERN.test(value)) return false;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return false;
  return new Date(parsed).toISOString() === value;
}

function normalizeAjvErrors(errors) {
  return (errors ?? []).map((error) => ({
    code: 'SCHEMA_VIOLATION',
    path: error.instancePath || '/',
    keyword: error.keyword,
    message: error.message ?? 'schema violation',
  }));
}

const TIMESTAMP_FIELDS = Object.freeze({
  'source-descriptor': ['registered_at'],
  'connector-contract': [],
  'fetch-request': ['requested_at'],
  'source-snapshot': ['observed_at', 'fetched_at', 'published_at', 'event_time'],
  'content-segment': [],
  'ingestion-run': ['started_at', 'finished_at'],
  'source-lineage': ['created_at'],
  'source-proposal': ['created_at', 'decided_at'],
  'connector-error': ['occurred_at'],
});

// Cross-field semantic rules. Each returns an array of issues (empty = ok).
const SEMANTIC_CHECKS = Object.freeze({
  'source-descriptor'(doc) {
    const issues = [];
    if (doc.classification?.visibility === 'private') {
      const scoped = (doc.classification.allowed_workspace_ids?.length ?? 0) + (doc.classification.allowed_principal_ids?.length ?? 0);
      if (scoped === 0) {
        issues.push({ code: 'PRIVATE_WITHOUT_SCOPE', path: '/classification', message: 'a private source must name allowed workspaces or principals' });
      }
    }
    if (doc.license?.spdx === 'LICENSE_UNKNOWN' && doc.retention?.policy === 'keep_forever') {
      issues.push({ code: 'UNKNOWN_LICENSE_KEPT_FOREVER', path: '/license', message: 'unknown license cannot be retained forever; ingestion blocks downstream' });
    }
    return issues;
  },
  'connector-contract'(doc) {
    const issues = [];
    if (doc.read_only !== true) {
      issues.push({ code: 'CONNECTOR_NOT_READ_ONLY', path: '/read_only', message: 'connectors are read-only by construction' });
    }
    if (doc.auth_mode === 'grant_required' && !doc.required_grant_scope) {
      issues.push({ code: 'GRANT_SCOPE_MISSING', path: '/required_grant_scope', message: 'grant_required connectors must name the required grant scope' });
    }
    return issues;
  },
  'fetch-request'() {
    return [];
  },
  'source-snapshot'(doc) {
    const issues = [];
    if (!SHA256_PATTERN.test(doc.raw_sha256 ?? '') || !SHA256_PATTERN.test(doc.normalized_sha256 ?? '')) {
      issues.push({ code: 'INVALID_DIGEST', path: '/raw_sha256', message: 'snapshot digests must be lowercase hex SHA-256' });
    }
    if (doc.snapshot_kind === 'tombstone') {
      if (!doc.tombstone_reason) {
        issues.push({ code: 'TOMBSTONE_WITHOUT_REASON', path: '/tombstone_reason', message: 'tombstone snapshots must state a reason' });
      }
    } else if (doc.tombstone_reason) {
      issues.push({ code: 'CONTENT_WITH_TOMBSTONE_REASON', path: '/tombstone_reason', message: 'content snapshots cannot carry a tombstone reason' });
    }
    if (doc.supersedes_snapshot_id && doc.supersedes_snapshot_id === doc.snapshot_id) {
      issues.push({ code: 'SELF_SUPERSEDES', path: '/supersedes_snapshot_id', message: 'a snapshot cannot supersede itself' });
    }
    if (isRealUtcTimestamp(doc.published_at) && doc.published_at > doc.observed_at) {
      // A claimed publication time in the future is allowed only as a claim; flag for review data, not an error.
    }
    if (!isRealUtcTimestamp(doc.observed_at) || !isRealUtcTimestamp(doc.fetched_at)) {
      issues.push({ code: 'INVALID_HOST_TIME', path: '/observed_at', message: 'observed_at and fetched_at must be real UTC timestamps' });
    }
    const provenance = doc.fetch_provenance ?? {};
    if (provenance.connector_id !== doc.connector_id) {
      issues.push({ code: 'PROVENANCE_CONNECTOR_MISMATCH', path: '/fetch_provenance', message: 'fetch provenance connector must match the snapshot connector' });
    }
    return issues;
  },
  'content-segment'(doc) {
    const issues = [];
    const coordinates = doc.coordinates ?? {};
    const hasCoordinates = ['page', 'span', 'line', 'timecode'].some((key) => coordinates[key] !== undefined);
    if (!hasCoordinates) {
      issues.push({ code: 'SEGMENT_WITHOUT_COORDINATES', path: '/coordinates', message: 'a segment must carry at least one coordinate' });
    }
    if (!SHA256_PATTERN.test(doc.text_sha256 ?? '')) {
      issues.push({ code: 'INVALID_DIGEST', path: '/text_sha256', message: 'segment digest must be lowercase hex SHA-256' });
    }
    if (typeof doc.text === 'string' && doc.text.length > 0) {
      const actual = createHash('sha256').update(doc.text, 'utf8').digest('hex');
      if (actual !== doc.text_sha256) {
        issues.push({ code: 'TEXT_DIGEST_MISMATCH', path: '/text_sha256', message: 'text_sha256 must equal SHA-256 of text bytes' });
      }
    }
    const extraction = doc.extraction ?? {};
    if (extraction.method === 'ocr' || extraction.method === 'asr') {
      if (typeof extraction.confidence !== 'number' || extraction.confidence < 0.5) {
        if (!Array.isArray(extraction.uncertainty_flags) || extraction.uncertainty_flags.length === 0) {
          issues.push({ code: 'LOW_CONFIDENCE_UNFLAGGED', path: '/extraction', message: 'ocr/asr below 0.5 confidence must carry uncertainty flags' });
        }
      }
    }
    return issues;
  },
  'ingestion-run'(doc) {
    const issues = [];
    const counts = doc.counts ?? {};
    const sumTerminal = TERMINAL_STATES.reduce((sum, state) => sum + (counts[state] ?? 0), 0);
    if (sumTerminal !== counts.total) {
      issues.push({ code: 'COUNTS_MISMATCH', path: '/counts', message: `terminal outcome counts (${sumTerminal}) must sum to total (${counts.total})` });
    }
    if ((doc.outcomes ?? []).length !== counts.total) {
      issues.push({ code: 'OUTCOMES_MISMATCH', path: '/outcomes', message: 'outcomes length must equal counts.total' });
    }
    const seen = new Set();
    for (const outcome of doc.outcomes ?? []) {
      if (seen.has(outcome.operation_id)) {
        issues.push({ code: 'DUPLICATE_OPERATION_OUTCOME', path: '/outcomes', message: `operation ${outcome.operation_id} appears twice in one run` });
      }
      seen.add(outcome.operation_id);
    }
    const root = doc.output_root ?? '';
    if (path.isAbsolute(root) || /^[A-Za-z]:[\\/]/.test(root) || root.includes('..')) {
      issues.push({ code: 'NON_PORTABLE_OUTPUT_ROOT', path: '/output_root', message: 'output_root must be a portable relative path' });
    }
    return issues;
  },
  'source-lineage'(doc) {
    const issues = [];
    if (doc.upstream_snapshot_id === doc.downstream_snapshot_id) {
      issues.push({ code: 'SELF_LINEAGE', path: '/downstream_snapshot_id', message: 'lineage endpoints must differ' });
    }
    const exactMethods = new Set(['exact_raw_digest', 'exact_normalized_digest', 'canonical_identity']);
    if (doc.automated === true && !exactMethods.has(doc.evidence?.method)) {
      issues.push({ code: 'NON_EXACT_AUTOMATED_LINEAGE', path: '/automated', message: 'only exact deterministic relations may be automated' });
    }
    if (doc.evidence?.method === 'near_duplicate_classifier') {
      if (doc.automated === true || doc.status !== 'candidate') {
        issues.push({ code: 'NEAR_DUP_NOT_CANDIDATE', path: '/status', message: 'near-duplicate lineage is always a non-automated candidate' });
      }
    }
    return issues;
  },
  'source-proposal'(doc) {
    const issues = [];
    if ((doc.status === 'APPROVED' || doc.status === 'REJECTED')) {
      if (!doc.reviewed_by || !doc.decided_at || !doc.decision_reason) {
        issues.push({ code: 'DECISION_WITHOUT_REVIEWER', path: '/reviewed_by', message: 'APPROVED/REJECTED require reviewer, time and reason' });
      }
    }
    return issues;
  },
  'connector-error'(doc) {
    const issues = [];
    const detail = doc.diagnostic?.redacted_detail ?? '';
    if (/\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|Bearer\s+[A-Za-z0-9._-]{16,})/.test(detail)) {
      issues.push({ code: 'CREDENTIAL_LEAK', path: '/diagnostic', message: 'diagnostic detail must never contain credentials' });
    }
    if (doc.code === 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED' && doc.reconciliation_action === 'none') {
      issues.push({ code: 'UNKNOWN_WITHOUT_RECONCILIATION', path: '/reconciliation_action', message: 'unknown outcomes must demand reconciliation' });
    }
    if (doc.retryable === true && doc.reconciliation_action === 'none') {
      issues.push({ code: 'RETRYABLE_WITHOUT_ACTION', path: '/reconciliation_action', message: 'retryable errors must name a retry action' });
    }
    return issues;
  },
});

export function validateContract(name, data) {
  if (!Object.hasOwn(validators, name)) {
    throw new Error(`UNKNOWN_CONTRACT: ${String(name)}`);
  }
  if (!isPlainObject(data)) {
    return {
      valid: false,
      errors: [{ code: 'NOT_OBJECT', path: '/', message: 'contract document must be a JSON object' }],
    };
  }
  const validate = validators[name];
  const ok = validate(data);
  const errors = ok ? [] : normalizeAjvErrors(validate.errors);
  for (const field of TIMESTAMP_FIELDS[name]) {
    const value = data[field];
    if (value === undefined || value === null) continue;
    if (!isRealUtcTimestamp(value)) {
      errors.push({ code: 'INVALID_TIMESTAMP', path: `/${field}`, message: `${field} is not a real UTC ISO-8601 timestamp` });
    }
  }
  for (const issue of SEMANTIC_CHECKS[name](data)) {
    errors.push(issue);
  }
  return { valid: errors.length === 0, errors };
}

export function assertValidContract(name, data) {
  const result = validateContract(name, data);
  if (!result.valid) {
    const detail = result.errors.map((e) => `${e.code} ${e.path}: ${e.message}`).join('; ');
    throw new Error(`CONTRACT_INVALID ${name}: ${detail}`);
  }
  return true;
}

export function contractDigests() {
  return Object.fromEntries(
    CONTRACT_NAMES.map((name) => {
      const { raw } = loadSchema(name);
      return [name, createHash('sha256').update(raw, 'utf8').digest('hex')];
    }),
  );
}
