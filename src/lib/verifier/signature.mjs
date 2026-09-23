// S2-006 offline signatures (spec §3).
//
// Every label set and adjudication is signed/attested by an authenticated
// subject over the EXACT digest of corpus+split+case+rubric+label bytes.
// The policy engine cryptographically verifies the signature and never
// trusts an `auth_ref`-style field.
//
// The envelope is parameterized by contract shape (review P1-4a): it is
// EXACTLY the `signature` block of contracts/annotation-set.schema.json
//
//   { scheme: 'hmac-sha256'|'ed25519', keyRef, digest, verified, attestedBy }
//
// or the `adjudicatorIdentity` block of contracts/adjudication-record.schema.json
//
//   { principalId, role: 'adjudicator', authenticated, attestationDigest }.
//
// There is no `mac` field (the contract forbids additional properties): the
// MAC itself IS the envelope `digest`/`attestationDigest`, and the binding
// digest it signs over (corpus+split+case+rubric+label bytes — semantics
// unchanged) is part of the MAC input:
//
//   mac = HMAC-SHA256(secret, scheme || 0x00 || subject || 0x00 || keyRef || 0x00 || digestBytes)
//
// This module implements the offline HMAC-SHA256 scheme (Ed25519 is
// contract-permitted but not implemented for the fixture corpus); keys live
// in the custody of NAMED SUBJECTS — never with the candidate or the
// verifier operator, whose registration is refused (fail-closed).
//
// Verification runs ONE core for both shapes and is constant-time over the
// MAC (timingSafeEqual); it rejects: self-attestation (signer == artifact
// owner), forged MACs, unknown key references, custodian/subject mismatch,
// unverified/authenticated:false gates, wrong scheme and envelope shapes
// that are not exactly one of the two contract forms.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { canonicalDigest } from './canonical-json.mjs';
import { AclDenied, NeedsInput, VerifierError } from './errors.mjs';

// Contract enum value of contracts/annotation-set.schema.json (#/properties/
// signature/properties/scheme). Replaces the legacy internal 'hmac-sha256-v1'.
export const SIGNATURE_SCHEME = 'hmac-sha256';

// The two contract shapes the envelope can be emitted/verified in.
export const SIGNATURE_ENVELOPE_FORMS = Object.freeze(['annotation-set', 'adjudicator-identity']);

const ANNOTATION_SET_SIGNATURE_KEYS = Object.freeze(['scheme', 'keyRef', 'digest', 'verified', 'attestedBy']);
const ADJUDICATOR_IDENTITY_KEYS = Object.freeze(['principalId', 'role', 'authenticated', 'attestationDigest']);

const HEX64 = /^[0-9a-f]{64}$/;
const MIN_SECRET_LENGTH = 16;

// Producer-side principals can never hold signing keys: a signature from
// the artifact producer or the verifier operator is self-attestation by
// construction (spec §3).
export const CUSTODY_FORBIDDEN_ROLES = Object.freeze([
  'candidate', 'producer', 'verifier_operator',
]);

// keyRef -> {secret, custodian, role}. Module-level registry configured by
// registerKey()/clearKeys(); sign()/verify() accept an explicit registry
// override for isolation in tests.
const REGISTRY = new Map();

function assertKeyRef(keyRef) {
  if (typeof keyRef !== 'string' || keyRef.length === 0 || keyRef.length > 256) {
    throw new NeedsInput('keyRef must be a non-empty string (max 256 chars)');
  }
}

function assertDigestBytes(digestBytes) {
  if (typeof digestBytes !== 'string' || !HEX64.test(digestBytes)) {
    throw new NeedsInput('digestBytes must be the exact sha256 hex digest being signed over');
  }
}

function assertSubject(subject) {
  if (typeof subject !== 'string' || subject.length === 0) {
    throw new NeedsInput('subject must be a non-empty authenticated principal id');
  }
}

// Registers a custody key. Idempotent for identical registrations; a
// conflicting re-registration is refused. Candidate/producer/verifier-
// operator custody is refused outright (spec §3).
export function registerKey({ keyRef, secret, custodian, role, registry = REGISTRY } = {}) {
  assertKeyRef(keyRef);
  if (typeof secret !== 'string' || secret.length < MIN_SECRET_LENGTH) {
    throw new NeedsInput(`secret must be at least ${MIN_SECRET_LENGTH} chars (fixtures are not secrets, but real custody material must not be trivial)`);
  }
  assertSubject(custodian);
  if (typeof role !== 'string' || role.length === 0) {
    throw new NeedsInput('custody role is required');
  }
  if (CUSTODY_FORBIDDEN_ROLES.includes(role)) {
    throw new AclDenied(`role ${role} can never hold signature custody (candidate/verifier-operator self-attestation is refused by construction)`);
  }
  const existing = registry.get(keyRef);
  if (existing) {
    if (existing.secret !== secret || existing.custodian !== custodian || existing.role !== role) {
      throw new VerifierError('KEY_CONFLICT', `keyRef ${keyRef} is already registered with different custody material`);
    }
    return { keyRef, custodian, role, replayed: true };
  }
  registry.set(keyRef, { secret, custodian, role });
  return { keyRef, custodian, role, replayed: false };
}

export function clearKeys(registry = REGISTRY) {
  registry.clear();
}

export function custodianOf(keyRef, registry = REGISTRY) {
  return registry.get(keyRef)?.custodian ?? null;
}

export function hasKey(keyRef, registry = REGISTRY) {
  return registry.has(keyRef);
}

// Exact binding digest over corpus+split+case+rubric+label bytes (spec §3).
// All fields required: an incomplete lineage is rejected, never defaulted.
export function bindingDigest(binding) {
  const { corpusVersion, split, caseId, rubricDigest, labelBytesDigest } = binding ?? {};
  if (typeof corpusVersion !== 'string' || corpusVersion.length === 0) {
    throw new NeedsInput('binding requires corpusVersion');
  }
  if (typeof split !== 'string' || split.length === 0) {
    throw new NeedsInput('binding requires split');
  }
  if (typeof caseId !== 'string' || caseId.length === 0) {
    throw new NeedsInput('binding requires caseId');
  }
  if (typeof rubricDigest !== 'string' || !HEX64.test(rubricDigest)) {
    throw new NeedsInput('binding requires the exact rubricDigest');
  }
  if (typeof labelBytesDigest !== 'string' || !HEX64.test(labelBytesDigest)) {
    throw new NeedsInput('binding requires the exact labelBytesDigest');
  }
  return canonicalDigest({ caseId, corpusVersion, labelBytesDigest, rubricDigest, split });
}

function macHex(secret, subject, keyRef, digestBytes) {
  return createHmac('sha256', secret)
    .update([SIGNATURE_SCHEME, subject, keyRef, digestBytes].join('\u0000'), 'utf8')
    .digest('hex');
}

function isExactShape(sig, keys) {
  return typeof sig === 'object' && sig !== null && !Array.isArray(sig)
    && keys.every((k) => Object.prototype.hasOwnProperty.call(sig, k))
    && Object.keys(sig).length === keys.length;
}

const isNonEmptyString = (v) => typeof v === 'string' && v.length > 0;

// One verifying core for both contract shapes. Returns a normalized view or
// null when the envelope is not exactly one of the two contract forms.
function decomposeEnvelope(sig) {
  if (isExactShape(sig, ANNOTATION_SET_SIGNATURE_KEYS)) {
    if (!isNonEmptyString(sig.keyRef) || !isNonEmptyString(sig.digest) || !isNonEmptyString(sig.attestedBy)) return null;
    return {
      form: 'annotation-set',
      scheme: sig.scheme,
      keyRef: sig.keyRef,
      mac: sig.digest,
      claimedSubject: sig.attestedBy,
      gate: sig.verified === true,
    };
  }
  if (isExactShape(sig, ADJUDICATOR_IDENTITY_KEYS)) {
    if (!isNonEmptyString(sig.principalId) || !isNonEmptyString(sig.attestationDigest) || sig.role !== 'adjudicator') return null;
    return {
      form: 'adjudicator-identity',
      // the adjudication-record form carries no scheme field; the core is
      // HMAC-SHA256 by construction
      scheme: SIGNATURE_SCHEME,
      keyRef: null, // resolved from options/registry: the form has no keyRef field
      mac: sig.attestationDigest,
      claimedSubject: sig.principalId,
      gate: sig.authenticated === true,
    };
  }
  return null;
}

// Resolves the single custody key held by the named subject (adjudicator-
// identity form has no keyRef field). Ambiguous or absent custody -> null.
function resolveCustodianKeyRef(registry, subject) {
  const matches = [...registry.entries()]
    .filter(([, key]) => key.custodian === subject)
    .map(([keyRef]) => keyRef);
  return matches.length === 1 ? matches[0] : null;
}

// Signs the exact digest as the named subject, using a key that MUST be in
// that subject's custody. Returns the contract-shaped envelope; `form`
// selects the contract shape (annotation-set signature block by default,
// adjudication-record adjudicatorIdentity block for adjudications).
export function sign(subject, keyRef, digestBytes, { registry = REGISTRY, form = 'annotation-set' } = {}) {
  assertSubject(subject);
  assertKeyRef(keyRef);
  assertDigestBytes(digestBytes);
  if (!SIGNATURE_ENVELOPE_FORMS.includes(form)) {
    throw new NeedsInput(`unknown signature envelope form: ${String(form)} (expected one of ${SIGNATURE_ENVELOPE_FORMS.join(', ')})`);
  }
  const key = registry.get(keyRef);
  if (!key) {
    throw new AclDenied(`unknown keyRef: ${keyRef} — no signing key in custody`);
  }
  if (key.custodian !== subject) {
    throw new AclDenied(`key ${keyRef} is in custody of ${key.custodian}, not ${subject}`);
  }
  const mac = macHex(key.secret, subject, keyRef, digestBytes);
  if (form === 'adjudicator-identity') {
    return { principalId: subject, role: 'adjudicator', authenticated: true, attestationDigest: mac };
  }
  return { scheme: SIGNATURE_SCHEME, keyRef, digest: mac, verified: true, attestedBy: subject };
}

// Detailed verdict with a typed reason; verify() is the boolean form.
// Options: { artifactOwnerPrincipal, registry, keyRef }. Structural checks
// run first (cheap, non-secret); the MAC itself is compared constant-time.
export function verifyDetailed(sig, subject, digestBytes, options = {}) {
  const { artifactOwnerPrincipal = null, registry = REGISTRY, keyRef: keyRefOption = null } = options;
  const refused = (reason) => ({ ok: false, reason });
  assertSubject(subject);
  const env = decomposeEnvelope(sig);
  if (!env) return refused('malformed_signature');
  if (env.scheme !== SIGNATURE_SCHEME) return refused('unknown_scheme');
  if (!env.gate) return refused('unverified_attestation');
  assertDigestBytes(digestBytes);
  const keyRef = env.keyRef ?? (typeof keyRefOption === 'string' && keyRefOption.length > 0 ? keyRefOption : resolveCustodianKeyRef(registry, env.claimedSubject));
  if (typeof keyRef !== 'string' || keyRef.length === 0) return refused('unknown_key_ref');
  const key = registry.get(keyRef);
  if (!key) return refused('unknown_key_ref');
  // the envelope must attest exactly the subject being verified, and that
  // subject must hold the key's custody
  if (env.claimedSubject !== subject || key.custodian !== subject) return refused('custodian_mismatch');
  // Self-attestation: the signer equals the artifact owner — the producer
  // attesting its own independence is refused before any MAC check.
  if (artifactOwnerPrincipal !== null && artifactOwnerPrincipal === subject) {
    return refused('self_attestation');
  }
  const expected = macHex(key.secret, subject, keyRef, digestBytes);
  const a = Buffer.from(env.mac, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  const equal = a.length === b.length && timingSafeEqual(a, b);
  return equal ? { ok: true, reason: 'verified' } : refused('mac_forged');
}

// Boolean verification (constant-time MAC comparison). Never throws for a
// rejected signature: rejection is `false`, misuse (bad argument types) is
// a typed NeedsInput.
export function verify(sig, subject, digestBytes, options) {
  try {
    return verifyDetailed(sig, subject, digestBytes, options).ok;
  } catch (error) {
    if (error instanceof NeedsInput) throw error;
    return false;
  }
}
