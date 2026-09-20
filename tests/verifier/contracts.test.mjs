// S2-006 wave 1: verifier contract surfaces. The JSON Schemas in contracts/
// are the single source of truth; canonical-json-v1 is the only digest
// convention for idempotency keys and verification arguments; the generated
// declaration file must cover the transitive $ref closure and fail closed on
// drift; and a verifier verdict can never masquerade as a human
// ACCEPT_BOUNDED decision (spec §4).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  CANONICAL_JSON_VERSION,
  canonicalize,
  canonicalDigest,
  assertCanonicalSafety,
} from '../../src/lib/verifier/canonical-json.mjs';
import {
  VERIFIER_CONTRACTS,
  resolveContractClosure,
  generateTypes,
} from '../../scripts/generate-verifier-types.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUT_FILE = path.join(ROOT, 'src/lib/verifier/contracts.d.ts');
const CONTRACTS_URL = (name) => `https://veritas.local/contracts/${name}.schema.json`;
const HEX64 = 'a'.repeat(64);
const HEX64_B = 'b'.repeat(64);
const TS = '2026-03-22T00:00:00.000Z';

function buildAjv() {
  const closure = resolveContractClosure();
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  for (const [name, schema] of closure) {
    ajv.addSchema(schema, schema.$id);
  }
  return { closure, ajv };
}

function numericLeaves(value, at = '$', out = []) {
  if (typeof value === 'number') out.push(at);
  else if (Array.isArray(value)) value.forEach((v, i) => numericLeaves(v, `${at}[${i}]`, out));
  else if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) numericLeaves(child, `${at}.${key}`, out);
  }
  return out;
}

// Ajv validate functions return a boolean and expose .errors on themselves.
// undefined members are stripped exactly like src/lib/claims/validation.mjs does.
function stripUndefined(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(stripUndefined);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] !== undefined) out[key] = stripUndefined(value[key]);
  }
  return out;
}

function validate(fn, payload) {
  const ok = fn(stripUndefined(payload)) === true;
  return { valid: ok, errors: ok ? [] : fn.errors.map((e) => `${e.instancePath} ${e.message}`).join('; ') };
}

function verifierItem(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    itemId: 'svi-0001',
    statement: 'The administered dose was 50 mg per day for 12 weeks.',
    spanRef: { quoteDigest: HEX64, start: 0, end: 42 },
    criterion: 'citation_entailment',
    goldLabel: null,
    predictedLabel: 'SUPPORTED',
    verdict: 'SUPPORTED',
    reasonCodes: [],
    evidenceLinks: [{ claimId: 'clm-0001', claimRevision: 1 }],
    missingness: { kind: 'none' },
    provenance: { runId: 'run-0001' },
    ...overrides,
  };
}

function verifierResult(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    resultId: 'sres-0001',
    requestRef: 'svr-0001',
    inputDigests: {
      artifactDigest: HEX64,
      rubricDigest: HEX64,
      corpusManifestDigest: HEX64,
      thresholdsDigest: HEX64,
    },
    outputDigest: HEX64_B,
    items: [verifierItem()],
    disagreements: [],
    criticalFindings: [],
    abstentions: [],
    coverage: { denominator: 1, evaluated: 1, missing: 0 },
    independenceProfileRef: 'ind-0001',
    status: 'READY_FOR_HUMAN_REVIEW',
    humanDecisionRequired: true,
    ...overrides,
  };
}

function calibrationRecordV1(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    calibration_id: 'cal-0001',
    corpus_version: '1.0.0',
    corpus_sha256: HEX64,
    outcome_definition: { metric: 'extraction_accuracy', threshold: 0.9, description: 'extraction accuracy on frozen corpus' },
    numerator: 8,
    denominator: 10,
    missing_count: 0,
    uncertainty: {
      method: 'wilson',
      confidence_interval: { lower: 0.5, upper: 0.95, confidence_level: 0.95 },
    },
    evaluator_independence: { independent_evaluators: 2, blind_to_producer: true },
    status: 'MEASURED',
    measured_at: TS,
    measured_by: 'prn-ticket-owner',
    ...overrides,
  };
}

function calibrationRecordV2(overrides = {}) {
  return {
    contractVersion: '2.0.0',
    calibration_id: 'cal-0002',
    corpus_version: '1.0.0',
    corpus_sha256: HEX64,
    outcome_definition: { metric: 'citation_entailment_precision', threshold: 0.9, description: 'citation entailment precision' },
    numerator: 0,
    denominator: 0,
    missing_count: 0,
    uncertainty: {
      method: 'wilson',
      confidence_interval: { lower: 0, upper: 1, confidence_level: 0.95 },
    },
    evaluator_independence: {
      artifact_producer: 's2-005 synthesis pipeline (commit d7ce192)',
      implementation_owner: 'unassigned',
      implementation_digest: HEX64,
      annotators: [],
      adjudicator: null,
      blindness: {
        producer_identity_hidden: false,
        producer_verdict_hidden: false,
        predictions_hidden: false,
        thresholds_hidden: false,
        split_assignment_hidden: false,
      },
      data_independence: false,
      model_independence: false,
      process_independence: false,
      locked_label_access: [],
    },
    status: 'NOT_MEASURED',
    not_measured_reason: 'evaluator_not_independent',
    measured_at: TS,
    measured_by: 'prn-ticket-owner',
    ...overrides,
  };
}

describe('S2-006 verifier contracts', () => {
  test('all 14 verifier schemas are valid draft-2020-12 contracts and compile fail-closed', () => {
    const { closure, ajv } = buildAjv();
    for (const name of VERIFIER_CONTRACTS) {
      assert.ok(closure.has(name), `closure missing ${name}`);
      const schema = closure.get(name);
      assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema', name);
      assert.equal(schema.$id, CONTRACTS_URL(name), name);
      assert.equal(schema.additionalProperties, false, `${name} must be closed`);
      const expectedVersion = name === 'calibration-record-v2' ? '2.0.0' : '1.0.0';
      assert.equal(schema.properties.contractVersion.const, expectedVersion, `${name} contractVersion`);
      const validate = ajv.getSchema(CONTRACTS_URL(name));
      assert.equal(typeof validate, 'function', `${name} did not compile`);
    }
    assert.equal(VERIFIER_CONTRACTS.length, 14);
  });

  test('generator resolves the transitive $ref closure beyond the verifier set', () => {
    const { closure } = buildAjv();
    // calibration-report links calibration-record v1 (upstream S2-004) and
    // calibration-record-v2; neither is listed in VERIFIER_CONTRACTS, so both
    // must arrive through transitive $ref resolution.
    assert.ok(closure.has('calibration-record'), 'transitive closure missing calibration-record v1');
    assert.ok(closure.has('calibration-record-v2'), 'transitive closure missing calibration-record-v2');
    assert.ok(closure.size > VERIFIER_CONTRACTS.length);
  });

  test('s2-006-thresholds.json is a NEEDS_INPUT preregistration with no numeric values', () => {
    const thresholds = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts/s2-006-thresholds.json'), 'utf8'));
    assert.equal(thresholds.status, 'NEEDS_INPUT');
    assert.equal(thresholds.ownerDecisionRef, null, 'no method owner has been appointed yet');
    for (const section of [
      'thresholds',
      'confidence_level',
      'non_inferiority_margin',
      'multiplicity',
      'tie_rule',
      'coverage_floor',
      'sample_size_rationale',
      'decision_rule',
    ]) {
      assert.ok(section in thresholds, `missing preregistration section: ${section}`);
    }
    // $.schemaVersion is structural file versioning (style of s2-005-thresholds.json);
    // every §8 decision value must be null.
    const offenders = numericLeaves(thresholds).filter((at) => at !== '$.schemaVersion');
    assert.deepEqual(offenders, [], 'no numeric decision value may be authored by the agent');
  });
});

describe('S2-006 canonical-json-v1', () => {
  test('version marker is canonical-json-v1', () => {
    assert.equal(CANONICAL_JSON_VERSION, 'canonical-json-v1');
  });

  test('key order does not affect the canonical form or digest (golden test)', () => {
    const one = { b: 1, a: { d: 4, c: [3, 1, 2] } };
    const two = { a: { c: [3, 1, 2], d: 4 }, b: 1 };
    assert.equal(canonicalize(one), canonicalize(two));
    assert.equal(canonicalize(one), '{"a":{"c":[3,1,2],"d":4},"b":1}');
    assert.equal(canonicalDigest(one), canonicalDigest(two));
    assert.equal(canonicalDigest(one), 'f5cbe07d6e83779e9ff08861cb9b56bef07bc77ac734147d4824560718205832');
  });

  test('arrays keep their order; undefined array members fail closed, undefined object keys are stripped', () => {
    assert.equal(canonicalize([3, 1, 2]), '[3,1,2]');
    assert.notEqual(canonicalize([1, 2, 3]), canonicalize([3, 2, 1]));
    assert.equal(canonicalize({ a: 1, z: undefined }), '{"a":1}');
    assert.throws(() => canonicalize([1, undefined]), /undefined member/);
  });

  test('assertCanonicalSafety rejects values that would not survive lossless canonicalization', () => {
    assert.throws(() => assertCanonicalSafety({ ok: NaN }));
    assert.throws(() => assertCanonicalSafety({ ok: Infinity }));
    assert.throws(() => assertCanonicalSafety([1, undefined]));
    assert.throws(() => assertCanonicalSafety({ fn: () => {} }));
    assert.throws(() => assertCanonicalSafety({ big: 1n }));
    assert.doesNotThrow(() => assertCanonicalSafety({ a: [1, 'x', null, { b: 2.5, c: false }] }));
    assert.throws(() => canonicalize([1, undefined]));
    assert.throws(() => canonicalDigest({ ok: NaN }));
  });
});

describe('S2-006 generated types', () => {
  test('contracts.d.ts declares every verifier contract and the transitive closure', () => {
    const source = fs.readFileSync(OUT_FILE, 'utf8');
    const expected = [...VERIFIER_CONTRACTS, 'calibration-record'];
    for (const name of expected) {
      const typeName = name.split('-').map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join('');
      assert.match(source, new RegExp(`export interface ${typeName}\\b`), `${typeName} interface missing`);
    }
  });

  test('--write is idempotent and the no-write drift check fails closed on tampering', () => {
    const original = fs.readFileSync(OUT_FILE, 'utf8');
    try {
      const write1 = spawnSync(process.execPath, ['scripts/generate-verifier-types.mjs', '--write'], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(write1.status, 0, write1.stderr);
      const written = fs.readFileSync(OUT_FILE, 'utf8');
      assert.equal(written, generateTypes(), '--write output must equal generateTypes()');
      const write2 = spawnSync(process.execPath, ['scripts/generate-verifier-types.mjs', '--write'], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(write2.status, 0, write2.stderr);
      assert.equal(fs.readFileSync(OUT_FILE, 'utf8'), written, '--write must be idempotent');

      const check = spawnSync(process.execPath, ['scripts/generate-verifier-types.mjs'], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(check.status, 0, check.stderr);

      fs.writeFileSync(OUT_FILE, `${written}\n// drift\n`);
      const drift = spawnSync(process.execPath, ['scripts/generate-verifier-types.mjs'], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(drift.status, 1, 'drift check must exit 1 on a stale declaration file');
      const repair = spawnSync(process.execPath, ['scripts/generate-verifier-types.mjs', '--write'], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(repair.status, 0, repair.stderr);
      assert.equal(fs.readFileSync(OUT_FILE, 'utf8'), written, '--write must repair drift to the exact canonical bytes');
    } finally {
      fs.writeFileSync(OUT_FILE, original);
    }
  });
});

describe('S2-006 calibration-record v1/v2 evolution', () => {
  const { ajv } = buildAjv();
  const v1 = ajv.getSchema(CONTRACTS_URL('calibration-record'));
  const v2 = ajv.getSchema(CONTRACTS_URL('calibration-record-v2'));

  test('historical v1 records remain valid under the untouched v1 schema', () => {
    assert.equal(typeof v1, 'function');
    assert.equal(validate(v1, calibrationRecordV1()).valid, true, validate(v1, calibrationRecordV1()).errors);
  });

  test('v2 accepts denominator 0 paired with NOT_MEASURED + reason', () => {
    const checked = validate(v2, calibrationRecordV2());
    assert.equal(checked.valid, true, checked.errors);
  });

  test('v2 rejects denominator 0 paired with MEASURED', () => {
    const record = calibrationRecordV2({
      status: 'MEASURED',
      not_measured_reason: undefined,
    });
    assert.equal(validate(v2, record).valid, false, 'MEASURED requires denominator >= 1');
  });

  test('v2 rejects v1 payloads and v1 rejects v2 payloads (explicit versioning)', () => {
    assert.equal(validate(v2, calibrationRecordV1()).valid, false);
    assert.equal(validate(v1, calibrationRecordV2({ status: 'MEASURED', denominator: 10, numerator: 9 })).valid, false);
  });

  test('v2 carries the richer evaluator independence axes from spec §3', () => {
    const schema = resolveContractClosure().get('calibration-record-v2');
    const required = schema.properties.evaluator_independence.required;
    for (const axis of [
      'artifact_producer',
      'implementation_owner',
      'implementation_digest',
      'annotators',
      'adjudicator',
      'blindness',
      'data_independence',
      'model_independence',
      'process_independence',
      'locked_label_access',
    ]) {
      assert.ok(required.includes(axis), `evaluator_independence missing axis ${axis}`);
    }
    assert.deepEqual(schema.properties.status.enum, ['MEASURED', 'NOT_MEASURED', 'NEEDS_INPUT', 'NOT_APPLICABLE']);
    assert.ok(schema.properties.not_measured_reason.oneOf[0].enum.includes('evaluator_not_independent'));
  });
});

describe('S2-006 verifier verdict vs human decision boundary', () => {
  const { ajv } = buildAjv();
  const item = ajv.getSchema(CONTRACTS_URL('semantic-verification-item'));
  const result = ajv.getSchema(CONTRACTS_URL('semantic-verification-result'));

  test('a well-formed verification item and result validate', () => {
    assert.equal(validate(item, verifierItem()).valid, true, validate(item, verifierItem()).errors);
    assert.equal(validate(result, verifierResult()).valid, true, validate(result, verifierResult()).errors);
  });

  test('the result schema cannot carry a human ACCEPT_BOUNDED decision', () => {
    // No such enum value exists on the bounded status.
    assert.equal(validate(result, verifierResult({ status: 'ACCEPT_BOUNDED' })).valid, false);
    // No such property exists at all: additionalProperties:false rejects it.
    assert.equal(validate(result, verifierResult({ humanDecision: 'ACCEPT_BOUNDED' })).valid, false);
    assert.equal(validate(result, verifierResult({ verdict: 'ACCEPT_BOUNDED' })).valid, false);
    // humanDecisionRequired is const true and mandatory.
    assert.equal(validate(result, verifierResult({ humanDecisionRequired: false })).valid, false);
    const missing = verifierResult();
    delete missing.humanDecisionRequired;
    assert.equal(validate(result, missing).valid, false);
  });

  test('item labels and reason codes are closed enums', () => {
    assert.equal(validate(item, verifierItem({ predictedLabel: 'ACCEPT_BOUNDED' })).valid, false);
    assert.equal(validate(item, verifierItem({ verdict: 'GLOBAL_TRUTH' })).valid, false);
    assert.equal(validate(item, verifierItem({ reasonCodes: ['made_up_reason'] })).valid, false);
    assert.equal(validate(item, verifierItem({ reasonCodes: ['topic_overlap', 'number_unit_drift'] })).valid, true);
  });
});
