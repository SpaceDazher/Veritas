// S2-002 identity/sandbox contract registry.
// Single fail-closed entry point for loading and validating the eight
// versioned identity and sandbox contracts. Compiles all schemas at import
// time; any missing, malformed or unknown contract aborts immediately
// instead of degrading to best-effort validation.
//
// Semantic (cross-field) rules live here rather than in JSON Schema because
// they need computed comparisons. They are part of the contract surface:
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
  'workspace',
  'principal',
  'role',
  'capability',
  'grant',
  'lease',
  'sandbox-profile',
  'authorization-decision',
]);

const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const TIMESTAMP_FIELDS = Object.freeze({
  workspace: [],
  principal: [],
  role: [],
  capability: [],
  grant: ['issued_at', 'expires_at', 'revoked_at'],
  lease: ['issued_at', 'expires_at', 'revoked_at'],
  'sandbox-profile': [],
  'authorization-decision': ['decided_at'],
});

const EXPIRY_MUST_FOLLOW_ISSUED = Object.freeze(['grant', 'lease']);

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

// Cross-field semantic rules. Each returns an array of issues (empty = ok).
const SEMANTIC_CHECKS = Object.freeze({
  workspace() {
    return [];
  },
  principal(doc) {
    const issues = [];
    if (doc.kind === 'personal_agent' && doc.delegated_by === doc.principal_id) {
      issues.push({ code: 'SELF_DELEGATION', path: '/delegated_by', message: 'a personal agent cannot delegate to itself' });
    }
    return issues;
  },
  role() {
    return [];
  },
  capability() {
    return [];
  },
  grant(doc) {
    const issues = [];
    if (doc.issuer === doc.principal_id) {
      issues.push({ code: 'SELF_ISSUED_GRANT', path: '/issuer', message: 'grant issuer must differ from the grantee principal' });
    }
    return issues;
  },
  lease() {
    return [];
  },
  'sandbox-profile'() {
    return [];
  },
  'authorization-decision'() {
    return [];
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
  if (EXPIRY_MUST_FOLLOW_ISSUED.includes(name)) {
    const issued = Date.parse(data.issued_at ?? '');
    const expires = Date.parse(data.expires_at ?? '');
    if (Number.isFinite(issued) && Number.isFinite(expires) && expires <= issued) {
      errors.push({ code: 'EXPIRES_BEFORE_ISSUED', path: '/expires_at', message: 'expires_at must be strictly after issued_at' });
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
