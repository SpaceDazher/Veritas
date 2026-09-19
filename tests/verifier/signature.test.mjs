// S2-006 wave 3: offline HMAC signature scheme (spec §3). Roundtrip,
// constant-time verification and every rejection class: forged MAC,
// self-attestation, unknown keyRef, subject/digest mismatch, custody
// violations (candidate/verifier-operator keys refused by construction),
// and binding-digest completeness.
import { describe, test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SIGNATURE_SCHEME,
  CUSTODY_FORBIDDEN_ROLES,
  registerKey,
  clearKeys,
  custodianOf,
  hasKey,
  bindingDigest,
  sign,
  verify,
  verifyDetailed,
} from '../../src/lib/verifier/signature.mjs';
import { AclDenied, NeedsInput } from '../../src/lib/verifier/errors.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FIXTURES = path.join(ROOT, 'tests', 'verifier', 'fixtures');

const DIGEST = 'a'.repeat(64);
const OTHER_DIGEST = 'b'.repeat(64);

function loadFixtureKeys() {
  const registry = new Map();
  const fixtures = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'keys.json'), 'utf8'));
  for (const key of fixtures.keys) registerKey({ ...key, registry });
  return { registry, fixtures };
}

describe('S2-006 signature scheme: fixture custody keys', () => {
  test('fixture keys register with distinct custodians and no producer-side custody', () => {
    const { registry, fixtures } = loadFixtureKeys();
    assert.equal(registry.size, fixtures.keys.length);
    for (const key of fixtures.keys) {
      assert.equal(custodianOf(key.keyRef, registry), key.custodian);
      assert.ok(hasKey(key.keyRef, registry));
      assert.ok(!CUSTODY_FORBIDDEN_ROLES.includes(key.role), `${key.role} must never hold custody`);
    }
  });

  test('candidate/verifier-operator custody is refused outright', () => {
    const { fixtures } = loadFixtureKeys();
    for (const forbidden of fixtures.forbidden) {
      assert.throws(
        () => registerKey({ ...forbidden }),
        AclDenied,
        `${forbidden.role} custody must be refused`,
      );
      assert.equal(hasKey(forbidden.keyRef), false);
    }
  });

  test('conflicting re-registration of a keyRef is refused; identical is idempotent', () => {
    const { registry } = loadFixtureKeys();
    const key = {
      keyRef: 'kms://test/s2-006/dup',
      custodian: 'prn-annotator-a',
      role: 'annotator',
      secret: 's2-006-fixture-dup-secret-0000001',
    };
    assert.equal(registerKey({ ...key, registry }).replayed, false);
    assert.equal(registerKey({ ...key, registry }).replayed, true);
    assert.throws(
      () => registerKey({ ...key, registry, secret: 's2-006-fixture-dup-secret-0000002' }),
      (e) => e.code === 'KEY_CONFLICT',
    );
  });
});

describe('S2-006 signature scheme: sign/verify roundtrip', () => {
  beforeEach(() => clearKeys());

  test('sign -> verify roundtrip over the exact binding digest', () => {
    const { registry } = loadFixtureKeys();
    const binding = {
      corpusVersion: '1.0.0',
      split: 'locked_test',
      caseId: 'case-s2006-11',
      rubricDigest: 'c'.repeat(64),
      labelBytesDigest: 'd'.repeat(64),
    };
    const digest = bindingDigest(binding);
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', digest, { registry });
    assert.deepEqual(Object.keys(sig).sort(), ['digest', 'keyRef', 'mac', 'scheme']);
    assert.equal(sig.scheme, SIGNATURE_SCHEME);
    assert.equal(sig.digest, digest);
    assert.equal(verify(sig, 'prn-annotator-a', digest, { registry }), true);
    assert.deepEqual(verifyDetailed(sig, 'prn-annotator-a', digest, { registry }), { ok: true, reason: 'verified' });
  });

  test('bindingDigest is deterministic and rejects incomplete lineage', () => {
    const full = {
      corpusVersion: '1.0.0', split: 'dev', caseId: 'case-s2006-01',
      rubricDigest: 'c'.repeat(64), labelBytesDigest: 'd'.repeat(64),
    };
    assert.equal(bindingDigest(full), bindingDigest({ ...full }));
    for (const missing of ['corpusVersion', 'split', 'caseId', 'rubricDigest', 'labelBytesDigest']) {
      const broken = { ...full };
      delete broken[missing];
      assert.throws(() => bindingDigest(broken), NeedsInput, `binding without ${missing} must be rejected`);
    }
  });

  test('signing with a key not in the subject custody is refused', () => {
    const { registry } = loadFixtureKeys();
    assert.throws(
      () => sign('prn-annotator-b', 'kms://test/s2-006/annotator-a', DIGEST, { registry }),
      AclDenied,
    );
    assert.throws(
      () => sign('prn-annotator-a', 'kms://test/s2-006/unknown', DIGEST, { registry }),
      AclDenied,
    );
  });
});

describe('S2-006 signature scheme: rejection classes', () => {
  beforeEach(() => clearKeys());

  test('forged mac -> false with reason mac_forged', () => {
    const { registry } = loadFixtureKeys();
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    const forged = { ...sig, mac: '0'.repeat(64) };
    assert.equal(verify(forged, 'prn-annotator-a', DIGEST, { registry }), false);
    // truncated and garbage MACs are equally rejected, never a crash
    assert.equal(verify({ ...sig, mac: 'deadbeef' }, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verifyDetailed(forged, 'prn-annotator-a', DIGEST, { registry }).reason, 'mac_forged');
  });

  test('self-attestation (signer == artifact owner) -> false', () => {
    const { registry } = loadFixtureKeys();
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    // even a cryptographically valid MAC from the artifact owner is refused:
    // the producer cannot attest its own independence
    assert.equal(
      verify(sig, 'prn-annotator-a', DIGEST, { registry, artifactOwnerPrincipal: 'prn-annotator-a' }),
      false,
    );
    assert.equal(
      verifyDetailed(sig, 'prn-annotator-a', DIGEST, { registry, artifactOwnerPrincipal: 'prn-annotator-a' }).reason,
      'self_attestation',
    );
    // a different owner binding verifies
    assert.equal(
      verify(sig, 'prn-annotator-a', DIGEST, { registry, artifactOwnerPrincipal: 'prn-producer-1' }),
      true,
    );
  });

  test('unknown keyRef -> false', () => {
    const { registry } = loadFixtureKeys();
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    assert.equal(verify({ ...sig, keyRef: 'kms://test/s2-006/ghost' }, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verify(sig, 'prn-annotator-a', DIGEST, { registry: new Map() }), false);
    assert.equal(verifyDetailed(sig, 'prn-annotator-a', DIGEST, { registry: new Map() }).reason, 'unknown_key_ref');
  });

  test('subject/digest mismatch -> false; custodian mismatch -> false', () => {
    const { registry } = loadFixtureKeys();
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    // digest mismatch: envelope claims one binding, verifier checks another
    assert.equal(verify(sig, 'prn-annotator-a', OTHER_DIGEST, { registry }), false);
    assert.equal(verifyDetailed(sig, 'prn-annotator-a', OTHER_DIGEST, { registry }).reason, 'digest_mismatch');
    // envelope digest field tampered relative to the digest being checked
    assert.equal(verify({ ...sig, digest: OTHER_DIGEST }, 'prn-annotator-a', DIGEST, { registry }), false);
    // subject/custodian mismatch: claiming another principal's identity
    assert.equal(verify(sig, 'prn-annotator-b', DIGEST, { registry }), false);
    assert.equal(verifyDetailed(sig, 'prn-annotator-b', DIGEST, { registry }).reason, 'custodian_mismatch');
  });

  test('unknown scheme and malformed envelopes -> false without throwing', () => {
    const { registry } = loadFixtureKeys();
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    assert.equal(verify({ ...sig, scheme: 'hmac-sha256' }, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verifyDetailed({ ...sig, scheme: 'hmac-sha256' }, 'prn-annotator-a', DIGEST, { registry }).reason, 'unknown_scheme');
    assert.equal(verify(null, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verify({}, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verify({ scheme: SIGNATURE_SCHEME, keyRef: 'k', digest: DIGEST, mac: 'm' }, 'prn-annotator-a', DIGEST, { registry }), false);
  });

  test('misuse (malformed subject/digest arguments) stays a typed NeedsInput', () => {
    const { registry } = loadFixtureKeys();
    assert.throws(() => verifyDetailed({}, '', DIGEST, { registry }), NeedsInput);
    const shaped = { scheme: SIGNATURE_SCHEME, keyRef: 'k', digest: DIGEST, mac: 'm' };
    assert.throws(() => verifyDetailed(shaped, 'prn-annotator-a', 'nothex', { registry }), NeedsInput);
    assert.throws(() => sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', 'short', { registry }), NeedsInput);
  });
});
