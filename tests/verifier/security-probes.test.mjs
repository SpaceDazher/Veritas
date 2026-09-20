// S2-006 wave 3: adversarial security probes A–S (spec §12, §14 gate 8).
// Every probe carries an HONEST status pass|failed|not_run (review P2-6):
// an attempted violation that is correctly blocked/detected is 'pass', a
// succeeded violation is 'failed', and an offline-impossible surface is
// 'not_run' — never silently green. Probe S is green ONLY through the
// PostgreSQL crash/restart phase of scripts/s2-006-db-replay.mjs; the
// aggregate hard counters must stay zero.
//
// fix2-D finding: every artifact a probe feeds through api.verifyClaim is a
// schema-valid CANONICAL producer document (the frozen fixtures under
// tests/verifier/fixtures/canonical or a content-derived variant of one) —
// homemade { statement, citations } bodies are a frozen-contract violation
// and must never reach the verifier again.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import Ajv2020 from 'ajv/dist/2020.js';
import { PROBE_IDS, runAllSecurityProbes, runSecurityProbe } from '../../src/lib/verifier/probes.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

// The REAL frozen producer schemas are the source of truth (never a
// test-only shape): every canonical fixture the probes build on must
// validate against them before any probe runs.
const PRODUCER_CONTRACTS = Object.freeze(['claim', 'evidence-map', 'hypothesis-card', 'synthesis-result']);
const PRODUCER_AJV = (() => {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  for (const name of PRODUCER_CONTRACTS) {
    ajv.addSchema(JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts', `${name}.schema.json`), 'utf8')));
  }
  return ajv;
})();
for (const name of PRODUCER_CONTRACTS) {
  const doc = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/verifier/fixtures/canonical', `${name}.json`), 'utf8'));
  const validate = PRODUCER_AJV.getSchema(`https://veritas.local/contracts/${name}.schema.json`);
  assert.equal(
    validate(doc), true,
    `canonical fixture ${name} must be schema-valid: ${PRODUCER_AJV.errorsText(validate.errors)}`,
  );
}

// run once at module load (top-level await is fine in ESM, describe bodies
// must stay synchronous)
const suite = await runAllSecurityProbes();

// Deterministic fixtures of the DB crash/restart phase result (the shape the
// aggregator derives from evidence/s2-006-db-comparison.json crashPhase).
const GREEN_DB_CRASH_PHASE = Object.freeze({
  ok: true,
  status: 'PASS',
  source: 'evidence/s2-006-db-comparison.json crashPhase',
});
const RED_DB_CRASH_PHASE = Object.freeze({
  ok: false,
  status: 'FAIL',
  issues: ['crash-a:not-completed'],
  source: 'evidence/s2-006-db-comparison.json crashPhase',
});
const suiteDbGreen = await runAllSecurityProbes({ probeSDbCrashPhase: GREEN_DB_CRASH_PHASE });
const suiteDbRed = await runAllSecurityProbes({ probeSDbCrashPhase: RED_DB_CRASH_PHASE });

describe('S2-006 security probes: orchestrator surface', () => {
  test('all probes A–S are registered exactly once', () => {
    assert.equal(PROBE_IDS.length, 19);
    assert.deepEqual(new Set(PROBE_IDS).size, 19);
    assert.deepEqual(PROBE_IDS[0], 'A');
    assert.deepEqual(PROBE_IDS[PROBE_IDS.length - 1], 'S');
  });

  test('unknown probe id is a typed error, never a silent skip', async () => {
    await assert.rejects(() => runSecurityProbe('Z'), (e) => e.code === 'PROBE_UNKNOWN');
  });
});

describe('S2-006 security probes: honest offline statuses (review P2-6)', () => {
  test('offline: 18 probes pass, probe S is honestly NOT_RUN_DB, zero failed', () => {
    assert.equal(suite.probes.length, 19);
    for (const probe of suite.probes) {
      assert.ok(['pass', 'failed', 'not_run'].includes(probe.status), `probe ${probe.id} must carry a status`);
      if (probe.id === 'S') {
        assert.equal(probe.status, 'not_run', 'probe S is NOT_RUN_DB without the DB crash phase');
        assert.equal(probe.ok, false, 'NOT_RUN_DB is not green');
        assert.ok((probe.notRun ?? []).some((n) => n.startsWith('NOT_RUN_DB')));
      } else {
        assert.equal(probe.status, 'pass', `probe ${probe.id} must pass offline`);
        assert.equal(probe.ok, true, `probe ${probe.id} must pass`);
      }
    }
    assert.equal(suite.totals.pass, 18);
    assert.equal(suite.totals.failed, 0);
    assert.equal(suite.totals.not_run, 1);
    assert.equal(suite.totals.ok, 18);
  });

  test('probe S turns green ONLY through a green DB crash/restart phase', () => {
    const s = suiteDbGreen.probes.find((p) => p.id === 'S');
    assert.equal(s.status, 'pass');
    assert.equal(s.ok, true);
    assert.equal(s.notRun, undefined);
    assert.equal(suiteDbGreen.totals.pass, 19);
    assert.equal(suiteDbGreen.totals.not_run, 0);
    assert.equal(suiteDbGreen.totals.failed, 0);
  });

  test('a red DB crash/restart phase FAILS probe S (never silently green)', () => {
    const s = suiteDbRed.probes.find((p) => p.id === 'S');
    assert.equal(s.status, 'failed');
    assert.equal(s.ok, false);
    assert.equal(suiteDbRed.totals.failed, 1);
  });

  test('hard counters are zero while green; a failed probe counts its actual violation', () => {
    for (const [name, s] of [['offline', suite], ['db-green', suiteDbGreen]]) {
      assert.equal(s.totals.attemptedViolations >= 19, true, `${name}: every probe attempts at least one violation`);
      assert.equal(s.totals.actualViolations, 0, name);
      assert.equal(s.hardCounters.total, 0, name);
      assert.equal(s.hardCounters.unauthorizedLeakageEvents, 0, name);
      assert.equal(s.hardCounters.lockedLabelAccessEvents, 0, name);
      assert.equal(s.hardCounters.producerSelfReviewEvents, 0, name);
      assert.equal(s.hardCounters.upstreamArtifactMutationEvents, 0, name);
      assert.equal(s.hardCounters.unauthorizedSideEffectEvents, 0, name);
    }
    // the red DB variant honestly reports the succeeded violation (never 0)
    assert.equal(suiteDbRed.hardCounters.unauthorizedSideEffectEvents, 1);
    assert.equal(suiteDbRed.totals.failed, 1);
  });

  test('offline-impossible surfaces are explicitly NOT_RUN_*, never silent', () => {
    // the only offline-impossible half in A–S is the PostgreSQL crash/restart
    // replay of probe S; it must be declared, not hidden
    assert.ok(suite.notRun.some((n) => n.startsWith('NOT_RUN_DB')), 'probe S DB replay must be declared NOT_RUN_DB');
    for (const probe of suite.probes) {
      if (probe.notRun) {
        assert.ok(Array.isArray(probe.notRun) && probe.notRun.every((n) => n.startsWith('NOT_RUN_')));
      }
    }
  });

  // per-probe spot checks: each spec §12 scenario maps to its probe id
  for (const probe of suite.probes) {
    test(`probe ${probe.id}: ${probe.name}`, () => {
      if (probe.id === 'S') {
        // offline run: honestly NOT_RUN_DB, the offline state machine still exercised
        assert.equal(probe.status, 'not_run');
        assert.equal(probe.actualViolations, 0);
      } else {
        assert.equal(probe.status, 'pass');
        assert.equal(probe.ok, true);
        assert.equal(probe.actualViolations, 0);
      }
    });
  }
});

// REGRESSION (fix2-D): the artifact-level probes must run on CANONICAL
// producer documents. Before the fix the probes fed homemade
// { statement, citations } bodies, which fix2-C correctly rejects as
// ArtifactContractViolation — the suite could not even load. The observed
// surface now names the exact frozen fixture (or derived variant) every
// artifact-level probe is built on.
describe('S2-006 security probes: canonical producer payloads (fix2-D)', () => {
  test('artifact-level probes E, M, N, P, S declare canonical fixture payloads', async () => {
    const expectedPayloadSource = {
      E: 'canonical-fixture:claim',
      M: 'canonical-fixture:claim',
      N: 'canonical-fixture:evidence-map+hypothesis-card',
      P: 'canonical-fixture:evidence-map+synthesis-result',
      S: 'canonical-fixture:claim',
    };
    for (const [id, payloadSource] of Object.entries(expectedPayloadSource)) {
      const probe = await runSecurityProbe(id);
      assert.equal(probe.observed.payloadSource, payloadSource, `probe ${id} payload source`);
    }
  });

  test('derived probe variants stay schema-valid canonical documents (content mutations, not shape changes)', async () => {
    // probe E derives a persuasive variant of the canonical claim by
    // mutating normalized_text content — the mutation must stay a valid
    // claim document, and the citation check must still abstain
    // deterministically for BOTH the untouched fixture and the variant.
    const probeE = await runSecurityProbe('E');
    assert.equal(probeE.observed.payloadSource, 'canonical-fixture:claim');
    assert.equal(probeE.observed.canonicalFixtureVerdict, 'INSUFFICIENT_EVIDENCE');
    assert.equal(probeE.observed.derivedVariantVerdict, 'INSUFFICIENT_EVIDENCE');
    assert.equal(probeE.observed.abstention, 'NO_CITATION');
    assert.notEqual(probeE.observed.derivedVariantText, probeE.observed.canonicalFixtureText, 'the variant must be a real content mutation');
  });
});
