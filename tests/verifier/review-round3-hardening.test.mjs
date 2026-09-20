// S2-006 review round 3: security/authority regressions.
// These tests encode the externally observable guarantees, not the current
// implementation shape, so each finding has one fail-closed acceptance test.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

import { inheritedAclOf } from '../../src/lib/verifier/commands.mjs';
import { InMemoryVerifierStore } from '../../src/lib/verifier/store.mjs';
import { IdempotencyConflict } from '../../src/lib/verifier/errors.mjs';
import { loadOwnerInputs } from '../../scripts/s2-006-run.mjs';
import { deriveVerdict } from '../../scripts/verify-s2-006.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OWNER_FIXTURE = path.join(ROOT, 'tests', 'verifier', 'fixtures', 'owner-inputs');
const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);

function resultRecord(id = 'sres-review-r3') {
  return {
    contractVersion: '1.0.0',
    resultId: id,
    requestRef: 'svr-review-r3',
    inputDigests: {
      artifactDigest: HEX_A,
      rubricDigest: HEX_A,
      corpusManifestDigest: HEX_A,
      thresholdsDigest: HEX_A,
    },
    outputDigest: HEX_B,
    items: [], disagreements: [], criticalFindings: [], abstentions: [],
    coverage: { denominator: 0, evaluated: 0, missing: 0 },
    independenceProfileRef: 'ind-review-r3',
    humanDecisionRequired: true,
    status: 'READY_FOR_HUMAN_REVIEW',
  };
}

function publish(store, operationId, record, acl) {
  return store.publish({
    workspaceId: 'ws-verifier',
    operationId,
    actor: 'prn-evaluation-harness',
    operation: 'publishVerificationResult',
    idempotencyKey: `idem-${operationId}`,
    records: [{ kind: 'result', record, acl }],
    audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: { review: 3 } },
  });
}

describe('review round 3: strict ACL derivation and immutable metadata', () => {
  test('disjoint private inputs produce an empty allowlist, never their union', () => {
    assert.deepEqual(inheritedAclOf([
      { visibility: 'private', allowedPrincipalIds: ['prn-alice'] },
      { visibility: 'private', allowedPrincipalIds: ['prn-bob'] },
    ]), {
      visibility: 'private',
      inherited: 'strictest_of_inputs',
      allowedPrincipalIds: [],
    });
  });

  test('byte-identical republish with incompatible ACL fails atomically', async () => {
    const store = new InMemoryVerifierStore();
    const record = resultRecord();
    await publish(store, 'op-review-r3-public', record, {
      visibility: 'public', inherited: 'strictest_of_inputs',
    });
    await assert.rejects(
      publish(store, 'op-review-r3-private', record, {
        visibility: 'private', inherited: 'strictest_of_inputs', allowedPrincipalIds: ['prn-owner'],
      }),
      IdempotencyConflict,
    );
    assert.equal(store.listLedger().length, 1, 'conflicting ACL must not commit a second ledger operation');
    assert.deepEqual(store.getRecordAcl('result', record.resultId), {
      visibility: 'public', inherited: 'strictest_of_inputs',
    });
  });
});

describe('review round 3: owner package contract and authority boundary', () => {
  test('MEASURED is validated on the original manifest bytes by the versioned schema', () => {
    const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts', 'annotation-manifest.schema.json'), 'utf8'));
    const manifest = JSON.parse(fs.readFileSync(path.join(OWNER_FIXTURE, 'external-manifest.json'), 'utf8'));
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const validate = ajv.compile(schema);
    assert.equal(validate(manifest), true, JSON.stringify(validate.errors, null, 2));
  });

  test('package cannot mint its own trust and the six-case fixture cannot satisfy the external minimum', () => {
    const loaded = loadOwnerInputs(OWNER_FIXTURE);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((issue) => issue.includes('trusted owner context')),
      JSON.stringify(loaded.issues, null, 2));
    assert.ok(loaded.issues.some((issue) => issue.includes('locked_test') && issue.includes('20')),
      JSON.stringify(loaded.issues, null, 2));
  });
});

describe('review round 3: owner evidence drives the aggregate verdict', () => {
  test('validated owner HUMAN_REVIEW replaces fixture-only NEEDS_INPUT inputs', () => {
    const pass = { status: 'PASS' };
    const gates = {
      dependency: pass,
      types: { status: 'IN_SYNC' },
      testVerifier: pass,
      evidenceRun: { status: 'PASS', comparisonOk: true },
      probes: pass,
      dbReplay: pass,
    };
    const fixtureCalibration = {
      hardViolations: { total: 0 },
      independence: { status: 'NOT_MEASURED', tier: 'NOT_INDEPENDENT' },
      externalStratum: { status: 'NEEDS_INPUT' },
      decision: { status: 'NEEDS_INPUT', needsInputReasons: ['missing_human_decision', 'missing_thresholds'] },
    };
    const ownerInputs = {
      hardGates: { ok: true, violations: [] },
      ownerInputs: {
        manifest: { externalStratum: { status: 'MEASURED', reason: 'external corpus' } },
        independence: { resolved: true, tier: 'INDEPENDENTLY_CALIBRATED' },
        thresholdDecision: { resolved: true },
      },
      pipeline: {
        ok: true,
        comparatorOk: true,
        calibration: { hardViolations: { total: 0 } },
        decision: { status: 'HUMAN_REVIEW', needsInputReasons: [] },
      },
    };
    const result = deriveVerdict({ gates, calibration: fixtureCalibration, ownerInputs });
    assert.equal(result.verdict, 'HUMAN_REVIEW', JSON.stringify(result, null, 2));
    assert.deepEqual(result.needsInputPath, []);
  });
});

describe('review round 3: PostgreSQL serialization structure', () => {
  const storeSource = fs.readFileSync(path.join(ROOT, 'src', 'lib', 'verifier', 'store.mjs'), 'utf8');

  test('state transitions lock the call row before validating its current state', () => {
    assert.match(storeSource, /FROM verifier_external_call_run WHERE call_id = \$1 FOR UPDATE/);
  });

  test('task budget totals are keyed by grant and operation, not only by grant', () => {
    const migrationPath = path.join(ROOT, 'migrations', '0007_verifier_store_hardening.sql');
    assert.equal(fs.existsSync(migrationPath), true, 'hardening migration is required');
    const migration = fs.readFileSync(migrationPath, 'utf8');
    assert.match(migration, /PRIMARY KEY\s*\(grant_ref,\s*operation_id\)/i);
  });
});
