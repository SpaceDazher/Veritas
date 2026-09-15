// S2-004 claim graph validation + canonical digests.
// Fail-closed ajv validation of every contract object; unknown contract
// versions, missing hashes, invalid enum values, unbounded scopes and unknown
// mandatory fields are rejected here, before any store mutation is attempted.
// Canonical JSON: sorted keys, no whitespace — the single digest convention
// for claim content, evidence spans, operation inputs and audit payloads.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');

export const CLAIM_CONTRACTS = Object.freeze([
  'claim',
  'evidence-edge',
  'claim-edge',
  'expert-profile',
  'expert-lens',
  'calibration-record',
  'claim-extraction-request',
  'claim-extraction-result',
  'claim-review-decision',
  'graph-invalidation-event',
]);

// ---- canonical JSON + digests ----------------------------------------------

export function canonicalJson(value) {
  return JSON.stringify(stripUndefined(value));
}

// Deterministic deep removal of undefined-valued keys: ajv sees
// `{a: undefined}` as an unknown/invalid value, and canonical JSON must be
// identical to the JSON that gets stored and hashed.
export function stripUndefined(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(stripUndefined);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] !== undefined) out[key] = stripUndefined(value[key]);
  }
  return out;
}

export function sha256Hex(value) {
  const bytes = typeof value === 'string' || Buffer.isBuffer(value) ? value : Buffer.from(canonicalJson(value), 'utf8');
  return createHash('sha256').update(bytes).digest('hex');
}

export function claimContentDigest(claim) {
  // Digest over every semantic field EXCEPT claim_id: used to derive the
  // deterministic claim id before the canonical (id-inclusive) digest exists.
  return sha256Hex({
    contractVersion: claim.contractVersion,
    revision: claim.revision ?? 1,
    workspace_id: claim.workspace_id,
    tenant_id: claim.tenant_id,
    acl: claim.acl,
    epistemic_type: claim.epistemic_type,
    polarity: claim.polarity,
    modality: claim.modality ?? null,
    normalized_text: claim.normalized_text,
    original_text: claim.original_text,
    subject: claim.subject,
    predicate: claim.predicate,
    object: claim.object,
    qualifiers: claim.qualifiers ?? [],
    uncertainty: claim.uncertainty ?? null,
    method: claim.method ?? null,
    assumptions: claim.assumptions ?? [],
    exclusions: claim.exclusions ?? [],
    units: claim.units ?? null,
    denominator: claim.denominator ?? null,
    value_range: claim.value_range ?? null,
    population: claim.population ?? null,
    geography: claim.geography ?? null,
    period: claim.period ?? null,
    event_time: claim.event_time ?? null,
    published_at: claim.published_at ?? null,
    observed_at: claim.observed_at ?? null,
    fetched_at: claim.fetched_at ?? null,
    language: claim.language,
    translation_status: claim.translation_status,
    supersedes_claim_id: claim.supersedes_claim_id ?? null,
    supersedes_revision: claim.supersedes_revision ?? null,
  });
}

export function canonicalDigestOfClaim(claim) {
  // Digest covers every semantic field of the proposition, including the
  // claim id. Lifecycle, audit and bookkeeping fields are deliberately
  // excluded: a review decision must bind the content of a revision, never
  // its current status.
  return sha256Hex({ claim_id: claim.claim_id, content: claimContentDigest(claim) });
}

// Quote digest of the exact span bytes: the machine-checkable binding between
// a claim and the characters it was derived from.
export function spanDigest(text, start, end) {
  return sha256Hex(Buffer.from(String(text).slice(start, end), 'utf8'));
}

export function deterministicClaimId({ workspaceId, contentDigest }) {
  return `clm-${sha256Hex(`${workspaceId}\n${contentDigest}`).slice(0, 24)}`;
}

export function deterministicId(prefix, ...parts) {
  return `${prefix}-${sha256Hex(parts.join('\u0000')).slice(0, 24)}`;
}

// ---- schema validation ------------------------------------------------------

let validator = null;

export function claimValidators(io = {}) {
  if (validator && !io.reload) return validator;
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const schemas = {};
  for (const name of CLAIM_CONTRACTS) {
    const schemaPath = path.join(CONTRACTS_DIR, `${name}.schema.json`);
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    ajv.addSchema(schema, schema.$id);
    schemas[name] = schema;
  }
  const compiled = new Map();
  for (const name of CLAIM_CONTRACTS) {
    compiled.set(name, ajv.getSchema(`https://veritas.local/contracts/${name}.schema.json`));
  }
  validator = {
    schemas,
    validate(name, object) {
      const fn = compiled.get(name);
      if (!fn) throw new Error(`unknown contract: ${name}`);
      const ok = fn(object);
      return { ok, errors: ok ? [] : fn.errors.map((e) => `${e.instancePath} ${e.message}`).join('; ') };
    },
    // Fail-closed wrapper: throws on any invalid object. Undefined-valued
    // keys are stripped first so ajv sees exactly the stored JSON.
    requireValid(name, object) {
      const result = this.validate(name, stripUndefined(object));
      if (!result.ok) {
        const error = new Error(`contract ${name} rejected payload: ${result.errors}`);
        error.code = 'CONTRACT_REJECTED';
        error.contract = name;
        error.issues = result.errors;
        throw error;
      }
      return object;
    },
  };
  return validator;
}

export class VeritasError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = 'VeritasError';
    this.code = code;
  }
}
