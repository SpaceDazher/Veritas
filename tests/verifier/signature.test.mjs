// S2-006 wave 3: offline HMAC signature scheme (spec §3). The envelope
// produced by sign()/consumed by verify() is EXACTLY the `signature` block
// of contracts/annotation-set.schema.json (scheme hmac-sha256|ed25519,
// keyRef, digest, verified, attestedBy — no `mac` field; the MAC IS the
// envelope `digest`, the binding digest it signs over lives inside the MAC
// input). The adjudication-record form (contracts/adjudication-record.schema.json
// `adjudicatorIdentity`) is supported through the same verifying core.
// Roundtrip, Ajv schema conformance (including the fixture corpus bytes),
// constant-time verification and every rejection class: forged MAC, self-
// attestation, unknown keyRef, subject/digest mismatch, custody violations
// (candidate/verifier-operator keys refused by construction), and binding-
// digest completeness.
import { describe, test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
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
import { annotationSetBindingDigest } from '../../src/lib/verifier/comparator.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { AclDenied, NeedsInput } from '../../src/lib/verifier/errors.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FIXTURES = path.join(ROOT, 'tests', 'verifier', 'fixtures');
const CORPUS = path.join(ROOT, 'corpus', 's2-006');
const CONTRACTS = path.join(ROOT, 'contracts');

const DIGEST = 'a'.repeat(64);
const OTHER_DIGEST = 'b'.repeat(64);
const HEX64 = (n) => n.toString(16).padStart(64, '0');
const TS = '2026-03-22T00:00:00.000Z';

function loadFixtureKeys() {
  const registry = new Map();
  const fixtures = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'keys.json'), 'utf8'));
  for (const key of fixtures.keys) registerKey({ ...key, registry });
  return { registry, fixtures };
}

function buildAjv(schemaName) {
  const schema = JSON.parse(fs.readFileSync(path.join(CONTRACTS, `${schemaName}.schema.json`), 'utf8'));
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  return ajv.compile(schema);
}

// Minimal annotation-set document that is valid against
// contracts/annotation-set.schema.json apart from the signature block,
// which comes verbatim from sign().
function annotationSetDocument(sig) {
  const labels = [{
    caseId: 'case-test-0001',
    label: 'SUPPORTED',
    labelDigest: canonicalDigest({ caseId: 'case-test-0001', label: 'SUPPORTED', labeledAt: TS }),
    annotatorId: 'prn-annotator-a',
    labeledAt: TS,
  }];
  return {
    contractVersion: '1.0.0',
    annotationSetId: 'ans-s2-006-test-fixture',
    corpusVersion: '1.0.0',
    frozenCaseIds: ['case-test-0001'],
    split: 'dev',
    blindAssignment: {
      producerIdentityHidden: true, producerVerdictHidden: true, predictionsHidden: true,
      thresholdsHidden: true, splitAssignmentHidden: true,
    },
    annotatorId: 'prn-annotator-a',
    annotatorRole: 'annotator',
    labels,
    timestamps: { frozenAt: TS, createdAt: TS },
    sourceDigest: HEX64(1),
    rubricDigest: HEX64(2),
    signature: sig,
  };
}

// Minimal adjudication record valid against contracts/adjudication-record.schema.json
// apart from the adjudicatorIdentity block, which comes verbatim from sign()
// in the adjudicator-identity form.
function adjudicationRecordDocument(identity) {
  const rawLabel = (setSuffix, annotatorId, label) => ({
    annotationSetId: `ans-s2-006-test-${setSuffix}`,
    annotatorId,
    label,
    labelDigest: canonicalDigest({ set: setSuffix, annotatorId, label }),
  });
  return {
    contractVersion: '1.0.0',
    adjudicationId: 'adj-s2-006-test-fixture',
    caseId: 'case-test-0001',
    annotationSetIds: ['ans-s2-006-test-x', 'ans-s2-006-test-y'],
    conflictingLabels: [rawLabel('x', 'prn-annotator-a', 'SUPPORTED'), rawLabel('y', 'prn-annotator-b', 'CONTRADICTED')],
    retainedRawLabels: [rawLabel('x', 'prn-annotator-a', 'SUPPORTED'), rawLabel('y', 'prn-annotator-b', 'CONTRADICTED')],
    decision: 'SUPPORTED',
    rationale: 'Test fixture adjudication rationale.',
    adjudicatorIdentity: identity,
    versions: {
      corpusVersion: '1.0.0', rubricDigest: HEX64(2), annotationManifestDigest: HEX64(3), thresholdsDigest: HEX64(4),
    },
    auditRef: { auditEntryId: 'audit-test-fixture', auditDigest: HEX64(5) },
    createdAt: TS,
  };
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

describe('S2-006 signature scheme: contract-shaped envelope', () => {
  beforeEach(() => clearKeys());

  test('sign emits the exact annotation-set contract signature block', () => {
    const { registry } = loadFixtureKeys();
    const digest = bindingDigest({
      corpusVersion: '1.0.0', split: 'locked_test', caseId: 'case-s2006-11',
      rubricDigest: 'c'.repeat(64), labelBytesDigest: 'd'.repeat(64),
    });
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', digest, { registry });
    assert.equal(SIGNATURE_SCHEME, 'hmac-sha256');
    assert.deepEqual(Object.keys(sig).sort(), ['attestedBy', 'digest', 'keyRef', 'scheme', 'verified']);
    assert.equal(sig.scheme, SIGNATURE_SCHEME);
    assert.equal(sig.verified, true);
    assert.equal(sig.attestedBy, 'prn-annotator-a');
    assert.match(sig.digest, /^[0-9a-f]{64}$/);
    assert.equal(sig.digest, sig.digest.toLowerCase());
    assert.equal(verify(sig, 'prn-annotator-a', digest, { registry }), true);
    assert.deepEqual(verifyDetailed(sig, 'prn-annotator-a', digest, { registry }), { ok: true, reason: 'verified' });
  });

  test('a signed annotation-set document validates against contracts/annotation-set.schema.json', () => {
    const { registry } = loadFixtureKeys();
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    const validate = buildAjv('annotation-set');
    const doc = annotationSetDocument(sig);
    const ok = validate(doc);
    assert.equal(ok, true, JSON.stringify(validate.errors, null, 1));
    // the legacy internal envelope (scheme hmac-sha256-v1 + mac field) must
    // stay invalid: the contract forbids `mac` and unknown scheme versions
    assert.equal(validate(annotationSetDocument({ ...sig, scheme: 'hmac-sha256-v1', mac: sig.digest, verified: undefined, attestedBy: undefined })), false);
  });

  test('sign supports the adjudication-record identity form through the same core', () => {
    const { registry } = loadFixtureKeys();
    const identity = sign('prn-adjudicator-1', 'kms://test/s2-006/adjudicator-1', DIGEST, { registry, form: 'adjudicator-identity' });
    assert.deepEqual(Object.keys(identity).sort(), ['attestationDigest', 'authenticated', 'principalId', 'role']);
    assert.equal(identity.role, 'adjudicator');
    assert.equal(identity.authenticated, true);
    assert.equal(identity.principalId, 'prn-adjudicator-1');
    const validate = buildAjv('adjudication-record');
    const doc = adjudicationRecordDocument(identity);
    const ok = validate(doc);
    assert.equal(ok, true, JSON.stringify(validate.errors, null, 1));
    // verify resolves the custody key by the named subject when the form
    // carries no keyRef
    assert.equal(verify(identity, 'prn-adjudicator-1', DIGEST, { registry }), true);
    assert.equal(verify(identity, 'prn-adjudicator-1', DIGEST, { registry, keyRef: 'kms://test/s2-006/adjudicator-1' }), true);
    assert.equal(verify(identity, 'prn-adjudicator-1', DIGEST, { registry: new Map() }), false);
  });

  test('unknown envelope form is a typed NeedsInput', () => {
    const { registry } = loadFixtureKeys();
    assert.throws(
      () => sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry, form: 'legacy-mac' }),
      NeedsInput,
    );
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
    const forged = { ...sig, digest: '0'.repeat(64) };
    assert.equal(verify(forged, 'prn-annotator-a', DIGEST, { registry }), false);
    // truncated and garbage MACs are equally rejected, never a crash
    assert.equal(verify({ ...sig, digest: 'deadbeef' }, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verifyDetailed(forged, 'prn-annotator-a', DIGEST, { registry }).reason, 'mac_forged');
  });

  test('digest mismatch (verifier checks another binding) -> false; the binding lives inside the MAC', () => {
    const { registry } = loadFixtureKeys();
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    assert.equal(verify(sig, 'prn-annotator-a', OTHER_DIGEST, { registry }), false);
    assert.equal(verifyDetailed(sig, 'prn-annotator-a', OTHER_DIGEST, { registry }).ok, false);
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

  test('subject/custodian mismatch -> false (claimed attestedBy and registry custodian both checked)', () => {
    const { registry } = loadFixtureKeys();
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    // claiming another principal's identity
    assert.equal(verify(sig, 'prn-annotator-b', DIGEST, { registry }), false);
    assert.equal(verifyDetailed(sig, 'prn-annotator-b', DIGEST, { registry }).reason, 'custodian_mismatch');
    // tampered attestedBy field
    assert.equal(verifyDetailed({ ...sig, attestedBy: 'prn-annotator-b' }, 'prn-annotator-a', DIGEST, { registry }).reason, 'custodian_mismatch');
  });

  test('unverified / wrong-scheme / malformed envelopes -> false without throwing', () => {
    const { registry } = loadFixtureKeys();
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    // ed25519 is contract-permitted but not implemented offline: refuse
    assert.equal(verify({ ...sig, scheme: 'ed25519' }, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verifyDetailed({ ...sig, scheme: 'ed25519' }, 'prn-annotator-a', DIGEST, { registry }).reason, 'unknown_scheme');
    // an envelope claiming verified:false is an unverified attestation
    assert.equal(verify({ ...sig, verified: false }, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verifyDetailed({ ...sig, verified: false }, 'prn-annotator-a', DIGEST, { registry }).reason, 'unverified_attestation');
    assert.equal(verify(null, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verify({}, 'prn-annotator-a', DIGEST, { registry }), false);
    // the legacy internal envelope (mac field) is contract-forbidden
    assert.equal(verify({ ...sig, mac: 'm' }, 'prn-annotator-a', DIGEST, { registry }), false);
    assert.equal(verifyDetailed({ ...sig, mac: 'm' }, 'prn-annotator-a', DIGEST, { registry }).reason, 'malformed_signature');
  });

  test('adjudicator-form gate: unauthenticated or wrong role is refused', () => {
    const { registry } = loadFixtureKeys();
    const identity = sign('prn-adjudicator-1', 'kms://test/s2-006/adjudicator-1', DIGEST, { registry, form: 'adjudicator-identity' });
    assert.equal(
      verifyDetailed({ ...identity, authenticated: false }, 'prn-adjudicator-1', DIGEST, { registry }).reason,
      'unverified_attestation',
    );
    // wrong role is a shape violation (the contract fixes role=adjudicator)
    assert.equal(
      verifyDetailed({ ...identity, role: 'annotator' }, 'prn-adjudicator-1', DIGEST, { registry }).reason,
      'malformed_signature',
    );
  });

  test('misuse (malformed subject/digest arguments) stays a typed NeedsInput', () => {
    const { registry } = loadFixtureKeys();
    assert.throws(() => verifyDetailed({}, '', DIGEST, { registry }), NeedsInput);
    const sig = sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', DIGEST, { registry });
    assert.throws(() => verifyDetailed(sig, 'prn-annotator-a', 'nothex', { registry }), NeedsInput);
    assert.throws(() => sign('prn-annotator-a', 'kms://test/s2-006/annotator-a', 'short', { registry }), NeedsInput);
  });
});

describe('S2-006 signature scheme: fixture corpus envelopes are contract-valid and verify', () => {
  const corpusSets = [
    ...JSON.parse(fs.readFileSync(path.join(CORPUS, 'labels', 'annotator-a.json'), 'utf8')),
    ...JSON.parse(fs.readFileSync(path.join(CORPUS, 'labels', 'annotator-b.json'), 'utf8')),
  ];
  const adjudications = JSON.parse(fs.readFileSync(path.join(CORPUS, 'adjudication.json'), 'utf8'));
  const CORPUS_SECRET = 's2-006-fixture-hmac-key';

  function corpusRegistry() {
    const registry = new Map();
    for (const set of corpusSets) {
      registerKey({ keyRef: set.signature.keyRef, custodian: set.annotatorId, role: 'annotator', secret: CORPUS_SECRET, registry });
    }
    return registry;
  }

  test('every fixture annotation set validates against contracts/annotation-set.schema.json', () => {
    const validate = buildAjv('annotation-set');
    for (const set of corpusSets) {
      const ok = validate(set);
      assert.equal(ok, true, `${set.annotationSetId}: ${JSON.stringify(validate.errors, null, 1)}`);
    }
  });

  test('every fixture annotation-set signature verifies over the exact binding digest', () => {
    const registry = corpusRegistry();
    for (const set of corpusSets) {
      assert.equal(
        verify(set.signature, set.annotatorId, annotationSetBindingDigest(set), { registry }),
        true,
        `${set.annotationSetId}: corpus signature must verify through the shared core`,
      );
    }
  });

  test('every fixture adjudication record validates against contracts/adjudication-record.schema.json', () => {
    const validate = buildAjv('adjudication-record');
    for (const rec of adjudications) {
      const ok = validate(rec);
      assert.equal(ok, true, `${rec.adjudicationId}: ${JSON.stringify(validate.errors, null, 1)}`);
    }
  });
});
