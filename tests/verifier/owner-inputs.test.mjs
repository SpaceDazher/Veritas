// S2-006 owner-input boundary: the submitted package is untrusted data;
// custody keys and authority grants arrive through a separate operator trust
// context. Under-sized synthetic fixtures can exercise validation but can
// never establish independent calibration.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import {
  makeVerifierAuthorityRegistry,
  registerProviderGrant,
} from '../../src/lib/verifier/commands.mjs';
import { registerKey, sign } from '../../src/lib/verifier/signature.mjs';
import {
  adjudicationAttestationDigest,
  loadOwnerExternalCorpus,
  loadOwnerInputs,
  loadOwnerTrustBundle,
} from '../../scripts/s2-006-run.mjs';
import { summarizeOwnerInputs } from '../../scripts/verify-s2-006.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FIXTURE_DIR = path.join(ROOT, 'tests', 'verifier', 'fixtures', 'owner-inputs');
const RUN_SCRIPT = path.join(ROOT, 'scripts', 's2-006-run.mjs');
const SHARED = 's2-006-fixture-hmac-key';
const REVIEWER = 'prn-owner-authority-reviewer';
const REVIEWER_KEY = 'kms://test/s2-006/owner-authority-reviewer';
const WORKSPACE = 'ws-s2-006-verifier';

function tmpCopy(mangle) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's2-006-owner-inputs-'));
  fs.cpSync(FIXTURE_DIR, dir, { recursive: true });
  if (mangle) mangle(dir);
  return dir;
}

function trustBundle() {
  const decision = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'threshold-decision.json'), 'utf8'));
  const keys = [
    { keyRef: 'kms://fixture/s2-006/owner-inputs/annotator-a', secret: SHARED, custodian: 'prn-owner-annotator-a', role: 'annotator' },
    { keyRef: 'kms://fixture/s2-006/owner-inputs/annotator-b', secret: SHARED, custodian: 'prn-owner-annotator-b', role: 'annotator' },
    { keyRef: 'kms://fixture/s2-006/owner-inputs/adjudicator/prn-owner-adjudicator-1', secret: SHARED, custodian: 'prn-owner-adjudicator-1', role: 'adjudicator' },
    { keyRef: REVIEWER_KEY, secret: 's2-006-owner-authority-reviewer-secret', custodian: REVIEWER, role: 'reviewer' },
  ];
  const principals = [
    { principal: decision.authority_binding.principalId, roles: ['method_owner'], workspaces: [WORKSPACE] },
    { principal: REVIEWER, roles: ['reviewer'], workspaces: [WORKSPACE] },
  ];
  const registry = new Map();
  for (const key of keys) registerKey({ ...key, registry });
  const grant = {
    contractVersion: '1.0.0',
    grantId: decision.authority_binding.grantRef,
    authenticatedPrincipal: decision.authority_binding.principalId,
    tool: 'threshold-authority',
    workspaceId: WORKSPACE,
    modelAccess: { modelId: 'none', modelVersion: '1.0.0', access: 'inference_only' },
    currency: 'none', timeoutMs: 30000,
    budget: { task: 0, campaign: 0, day: 0 },
    noTraining: true, noRetention: true,
    issuedAt: decision.timestamp,
    expiresAt: decision.authority_binding.expiresAt,
  };
  const signature = sign(REVIEWER, REVIEWER_KEY, canonicalDigest(grant), { registry });
  return {
    contractVersion: '1.0.0', bundleId: 'otb-owner-inputs-test', fixtureGrade: false,
    principals, keys, grants: [{ grant, issuer: REVIEWER, signature }],
  };
}

function trustedContext() {
  const bundle = trustBundle();
  const keyRegistry = new Map();
  for (const key of bundle.keys) registerKey({ ...key, registry: keyRegistry });
  const authorities = makeVerifierAuthorityRegistry(bundle.principals);
  for (const entry of bundle.grants) registerProviderGrant(authorities, { ...entry, registry: keyRegistry });
  return { keyRegistry, authorities, bundleId: bundle.bundleId, fixtureGrade: false };
}

function resignAdjudications(dir, context) {
  const target = path.join(dir, 'adjudication.json');
  const records = JSON.parse(fs.readFileSync(target, 'utf8')).map((record) => ({
    ...record,
    adjudicatorIdentity: sign(
      record.adjudicatorIdentity.principalId,
      'kms://fixture/s2-006/owner-inputs/adjudicator/prn-owner-adjudicator-1',
      adjudicationAttestationDigest(record),
      { registry: context.keyRegistry, form: 'adjudicator-identity' },
    ),
  }));
  fs.writeFileSync(target, `${JSON.stringify(records, null, 2)}\n`);
}

function runCli(args) {
  return spawnSync(process.execPath, [RUN_SCRIPT, ...args], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 120000,
  });
}

describe('S2-006 owner-input trust boundary', () => {
  test('an owner package cannot register its own keys or grants', () => {
    const loaded = loadOwnerInputs(FIXTURE_DIR);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((issue) => issue.includes('trusted owner context')), JSON.stringify(loaded.issues, null, 2));
  });

  test('a separate schema-valid trust bundle creates the runtime registries', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's2-006-owner-trust-'));
    const file = path.join(dir, 'trust.json');
    fs.writeFileSync(file, `${JSON.stringify(trustBundle(), null, 2)}\n`);
    const loaded = loadOwnerTrustBundle(file);
    assert.equal(loaded.ok, true, JSON.stringify(loaded.issues, null, 2));
    assert.ok(loaded.context.keyRegistry instanceof Map);
    assert.ok(loaded.context.authorities.issuedGrants.has('grt-owner-threshold-authority-001'));
  });

  test('even with valid external trust, six locked cases remain below the mandatory minimum', () => {
    const context = trustedContext();
    const dir = tmpCopy((copy) => resignAdjudications(copy, context));
    const loaded = loadOwnerInputs(dir, { trustedContext: context });
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((issue) => issue.includes('locked_test') && issue.includes('20')), JSON.stringify(loaded.issues, null, 2));
    assert.ok(!loaded.issues.some((issue) => issue.includes('trusted_owner_context_missing')), JSON.stringify(loaded.issues, null, 2));
  });

  test('fixture-grade trust is never promoted to independent calibration', () => {
    const context = trustedContext();
    context.fixtureGrade = true;
    const dir = tmpCopy((copy) => resignAdjudications(copy, context));
    const loaded = loadOwnerInputs(dir, { trustedContext: context });
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((issue) => issue.includes('fixture-grade')));
  });
});

describe('S2-006 owner package fail-closed validation', () => {
  test('a forged annotation signature is reported against the external registry', () => {
    const context = trustedContext();
    const dir = tmpCopy((copy) => {
      resignAdjudications(copy, context);
      const target = path.join(copy, 'annotation-sets', 'ans-owner-b.json');
      const set = JSON.parse(fs.readFileSync(target, 'utf8'));
      set.signature.digest = '0'.repeat(64);
      fs.writeFileSync(target, `${JSON.stringify(set, null, 2)}\n`);
    });
    const loaded = loadOwnerInputs(dir, { trustedContext: context });
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((issue) => issue.includes('signature rejected') && issue.includes('mac_forged')), JSON.stringify(loaded.issues, null, 2));
  });

  test('a manifest violation is rejected on the original submitted object', () => {
    const dir = tmpCopy((copy) => {
      const target = path.join(copy, 'external-manifest.json');
      const manifest = JSON.parse(fs.readFileSync(target, 'utf8'));
      manifest.externalStratum.status = 'SUBMITTED';
      fs.writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`);
    });
    const loaded = loadOwnerInputs(dir, { trustedContext: trustedContext() });
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((issue) => issue.includes('externalStratum.status')), JSON.stringify(loaded.issues, null, 2));
  });

  test('adjudication attestation binds auditRef as well as the decision content', () => {
    const record = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'adjudication.json'), 'utf8'))[0];
    const changed = { ...record, auditRef: { ...record.auditRef, auditDigest: 'f'.repeat(64) } };
    assert.notEqual(adjudicationAttestationDigest(record), adjudicationAttestationDigest(changed));
    const withoutIdentity = { ...record };
    delete withoutIdentity.adjudicatorIdentity;
    assert.equal(adjudicationAttestationDigest(record), adjudicationAttestationDigest(withoutIdentity));
  });
});

describe('S2-006 owner CLI and blinded child boundary', () => {
  test('--owner-inputs without --owner-trust fails closed', () => {
    const result = runCli(['--owner-inputs', FIXTURE_DIR]);
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes('--owner-trust'));
    assert.ok(result.stderr.includes('OWNER_INPUTS_REJECTED'));
  });

  test('trust anchors inside the untrusted package are refused before parsing', () => {
    const result = runCli(['--owner-inputs', FIXTURE_DIR, '--owner-trust', path.join(FIXTURE_DIR, 'thresholds.json')]);
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes('outside the untrusted owner-inputs directory'));
  });

  test('candidate-side loader reads manifest/cases but no label or adjudication material', () => {
    const corpus = loadOwnerExternalCorpus(FIXTURE_DIR);
    assert.equal(corpus.ok, true, JSON.stringify(corpus.issues, null, 2));
    assert.equal(corpus.cases.length, 6);
    assert.equal(corpus.labelSets, undefined);
    assert.equal(corpus.adjudications, undefined);
  });
});

describe('S2-006 owner summary semantics', () => {
  test('absence stays explicit and a validated record exposes its decision tier', () => {
    assert.deepEqual(summarizeOwnerInputs(null), { present: false, status: 'NOT_RUN_HUMAN_INPUTS' });
    const summary = summarizeOwnerInputs({
      ownerInputs: {
        manifest: { externalStratum: { status: 'MEASURED', reason: 'external' } },
        independence: { resolved: true, tier: 'INDEPENDENTLY_CALIBRATED' },
        thresholdDecision: { resolved: true },
      },
      pipeline: { comparatorOk: true, decision: { status: 'HUMAN_REVIEW' } },
      honesty: { signatureVerification: 'external registry' },
    });
    assert.equal(summary.present, true);
    assert.equal(summary.decisionStatus, 'HUMAN_REVIEW');
    assert.equal(summary.independence.tier, 'INDEPENDENTLY_CALIBRATED');
  });
});
