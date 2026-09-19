// S2-006 offline signatures (spec §3).
//
// Every label set and adjudication is signed/attested by an authenticated
// subject over the EXACT digest of corpus+split+case+rubric+label bytes.
// The policy engine cryptographically verifies the signature and never
// trusts an `auth_ref`-style field. This module implements the offline
// HMAC-SHA256 scheme (Ed25519 is contract-permitted but not required for
// the fixture corpus); keys live in the custody of NAMED SUBJECTS — never
// with the candidate or the verifier operator, whose registration is
// refused (fail-closed).
//
// Verification is constant-time over the MAC (timingSafeEqual) and rejects:
// self-attestation (signer == artifact owner), forged MACs, unknown key
// references, custodian/subject mismatch and subject/digest mismatches.
// Test keys are fixtures under tests/verifier/fixtures and are NOT secrets.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { canonicalDigest } from './canonical-json.mjs';
import { AclDenied, NeedsInput, VerifierError } from './errors.mjs';

export const SIGNATURE_SCHEME = 'hmac-sha256-v1';

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

// Signs the exact digest as the named subject, using a key that MUST be in
// that subject's custody. Returns the contract-shaped envelope:
// { scheme, keyRef, digest, mac }.
export function sign(subject, keyRef, digestBytes, { registry = REGISTRY } = {}) {
  assertSubject(subject);
  assertKeyRef(keyRef);
  assertDigestBytes(digestBytes);
  const key = registry.get(keyRef);
  if (!key) {
    throw new AclDenied(`unknown keyRef: ${keyRef} — no signing key in custody`);
  }
  if (key.custodian !== subject) {
    throw new AclDenied(`key ${keyRef} is in custody of ${key.custodian}, not ${subject}`);
  }
  return {
    scheme: SIGNATURE_SCHEME,
    keyRef,
    digest: digestBytes,
    mac: macHex(key.secret, subject, keyRef, digestBytes),
  };
}

// Detailed verdict with a typed reason; verify() is the boolean form.
// Options: { artifactOwnerPrincipal, registry }. Structural checks run
// first (cheap, non-secret); the MAC itself is compared constant-time.
export function verifyDetailed(sig, subject, digestBytes, options = {}) {
  const { artifactOwnerPrincipal = null, registry = REGISTRY } = options;
  const refused = (reason) => ({ ok: false, reason });
  assertSubject(subject);
  if (!sig || typeof sig !== 'object') return refused('malformed_signature');
  const { scheme, keyRef, digest, mac } = sig;
  if (typeof keyRef !== 'string' || typeof digest !== 'string' || typeof mac !== 'string') {
    return refused('malformed_signature');
  }
  if (scheme !== SIGNATURE_SCHEME) return refused('unknown_scheme');
  assertDigestBytes(digestBytes);
  const key = registry.get(keyRef);
  if (!key) return refused('unknown_key_ref');
  if (key.custodian !== subject) return refused('custodian_mismatch');
  if (digest !== digestBytes) return refused('digest_mismatch');
  // Self-attestation: the signer equals the artifact owner — the producer
  // attesting its own independence is refused before any MAC check.
  if (artifactOwnerPrincipal !== null && artifactOwnerPrincipal === subject) {
    return refused('self_attestation');
  }
  const expected = macHex(key.secret, subject, keyRef, digestBytes);
  const a = Buffer.from(mac, 'utf8');
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
