// S2-006 fix2-F (review finding 7): validated owner-inputs path.
//
// Regression coverage for the PRODUCTION scenario the first review round
// missed: the real pipeline could never leave NEEDS_INPUT on its own because
// the loader rejected any externalStratum.status except NEEDS_INPUT, labels
// were hardcoded to the fixture annotators, independence was always false and
// the owner threshold decision never reached calibration. These tests drive
// the real CLI and the real pipeline functions (comparator, calibration,
// decideLexicographic, verify-s2-006 summary propagation) over a committed
// owner-inputs fixture package (SYNTHETIC — see fixtures/owner-inputs/README.md)
// and fail closed on tampered packages.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  FIXTURE_ANNOTATION_HMAC_KEY,
  OWNER_EXTERNAL_STATUS_WHITELIST,
  adjudicationAttestationDigest,
  loadOwnerExternalCorpus,
  loadOwnerInputs,
  runOwnerInputsPipeline,
} from '../../scripts/s2-006-run.mjs';
import { summarizeOwnerInputs } from '../../scripts/verify-s2-006.mjs';
import { createHash } from 'node:crypto';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FIXTURE_DIR = path.join(ROOT, 'tests', 'verifier', 'fixtures', 'owner-inputs');
const RUN_SCRIPT = path.join(ROOT, 'scripts', 's2-006-run.mjs');

const sha256File = (p) => createHash('sha256').update(fs.readFileSync(p)).digest('hex');

function tmpCopy(mangle) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's2-006-owner-inputs-'));
  fs.cpSync(FIXTURE_DIR, dir, { recursive: true });
  if (mangle) mangle(dir);
  return dir;
}

function tmpEvidenceDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 's2-006-owner-evidence-'));
}

function runCli(extraArgs, evidenceDir) {
  const result = spawnSync(process.execPath, [
    RUN_SCRIPT,
    '--evidence-dir', evidenceDir,
    ...extraArgs,
  ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 120000 });
  let report = null;
  try { report = JSON.parse(result.stdout); } catch { report = null; }
  return { exitCode: result.status, stderr: result.stderr, report };
}

describe('S2-006 finding 7: well-formed owner-inputs package loads fail-closed and green', () => {
  const loaded = loadOwnerInputs(FIXTURE_DIR);

  test('the loader accepts the committed fixture package without any issue', () => {
    assert.equal(loaded.ok, true, JSON.stringify(loaded.issues, null, 1));
    assert.deepEqual(loaded.issues, []);
  });

  test('the external manifest white-listed status, thresholds and decision are resolved as data', () => {
    const pkg = loaded.package;
    assert.equal(pkg.manifest.manifestId, 'anmf-owner-inputs-fixture');
    assert.ok(OWNER_EXTERNAL_STATUS_WHITELIST.includes(pkg.manifest.externalStratum.status));
    assert.equal(pkg.manifest.externalStratum.status, 'MEASURED');
    assert.ok(pkg.manifest.externalStratum.reason.includes('SYNTHETIC'));
    assert.equal(pkg.thresholdsSource, 'owner-package');
    assert.equal(pkg.annotatorIds.length, 2);
    assert.deepEqual(pkg.annotatorIds, [...pkg.annotatorIds].sort());
    assert.equal(pkg.thresholdResolution.resolved, true);
    assert.equal(pkg.thresholdResolution.ownerPrincipal, 'prn-owner-method-owner-1');
  });

  test('the declared independence profile resolves to the independently-calibrated tier', () => {
    const pkg = loaded.package;
    assert.equal(pkg.independence.resolved, true);
    assert.equal(pkg.independence.tier, 'INDEPENDENTLY_CALIBRATED');
    assert.equal(pkg.adjudicatorIds, undefined); // not part of the package surface
    assert.ok(pkg.adjudicators.includes('prn-owner-adjudicator-1'));
  });
});

describe('S2-006 finding 7: the pipeline drives owner inputs to a verdict other than NEEDS_INPUT', () => {
  const pkg = loadOwnerInputs(FIXTURE_DIR).package;
  // review fix: redirect the evidence output — direct calls must not pollute
  // the canonical evidence/ directory (module default).
  const runPromise = runOwnerInputsPipeline({ pkg, evidenceDir: tmpEvidenceDir() });

  test('the fail-closed comparator accepts the two sealed owner runs', async () => {
    const run = await runPromise;
    assert.equal(run.ok, true, JSON.stringify(run.comparison?.failures ?? run, null, 1));
    assert.equal(run.comparison.ok, true);
    assert.equal(run.comparison.checks.predictionDigests.runA, run.comparison.checks.predictionDigests.runB);
    assert.notEqual(run.comparison.checks.runManifestDigests.runA, run.comparison.checks.runManifestDigests.runB);
  });

  test('calibration runs on the owner stratum with the declared independence', async () => {
    const run = await runPromise;
    assert.equal(run.metrics.coverage.denominator, 6);
    assert.equal(run.metrics.hardViolations.total, 0);
    assert.equal(run.metrics.metricsByName.get('inter_annotator_agreement').status, 'MEASURED');
  });

  test('the lexicographic decision rule resolves to HUMAN_REVIEW, not NEEDS_INPUT (ext-06 adjudication fails the authored f1 threshold)', async () => {
    const run = await runPromise;
    assert.notEqual(run.decision.status, 'NEEDS_INPUT');
    assert.equal(run.decision.status, 'HUMAN_REVIEW');
    assert.deepEqual(run.decision.needsInputReasons, []);
    assert.equal(run.metrics.metricsByName.get('citation_entailment_f1').value < 0.9, true);
  });
});

describe('S2-006 finding 7: CLI production scenario (--owner-inputs)', () => {
  test('the real run consumes the owner package end to end and records the owner evidence', () => {
    const evidenceDir = tmpEvidenceDir();
    const { stderr } = runCli(['--owner-inputs', FIXTURE_DIR], evidenceDir);
    // the owner block runs before the probe suite: the owner evidence must
    // exist and carry the resolved tiers regardless of any unrelated probe
    // outcome later in the run
    const record = JSON.parse(fs.readFileSync(path.join(evidenceDir, 's2-006-owner-inputs.json'), 'utf8'));
    assert.equal(record.ownerInputs.thresholdDecision.resolved, true);
    assert.equal(record.ownerInputs.manifest.externalStratum.status, 'MEASURED');
    assert.equal(record.ownerInputs.independence.tier, 'INDEPENDENTLY_CALIBRATED');
    assert.equal(record.pipeline.comparatorOk, true);
    assert.equal(record.pipeline.decision.status, 'HUMAN_REVIEW');
    assert.notEqual(record.pipeline.decision.status, 'NEEDS_INPUT');
    assert.ok(record.honesty.annotationHmacKey.includes('fixture'));
    assert.equal(record.pipeline.stage, 'complete');
    // the sealed owner prediction sets were written as run artifacts
    assert.ok(fs.existsSync(path.join(evidenceDir, 's2-006-owner-run-a.json')));
    assert.ok(fs.existsSync(path.join(evidenceDir, 's2-006-owner-run-b.json')));
    // the honest fixture stratum flow still ran alongside
    assert.ok(fs.existsSync(path.join(evidenceDir, 's2-006-calibration.json')));
    assert.ok(stderr.length === 0 || !stderr.includes('OWNER_INPUTS_REJECTED'));
  });

  test('without --owner-inputs the run stays the unchanged honest fixture flow', () => {
    const evidenceDir = tmpEvidenceDir();
    const { report } = runCli([], evidenceDir);
    assert.ok(fs.existsSync(path.join(evidenceDir, 's2-006-owner-inputs.json')) === false);
    assert.ok(fs.existsSync(path.join(evidenceDir, 's2-006-owner-run-a.json')) === false);
    if (report) assert.equal(report.ownerInputs, undefined);
  });

  test('a broken owner package refuses the run (OWNER_INPUTS_REJECTED, exit 1) — no silent fixture fallback', () => {
    const evidenceDir = tmpEvidenceDir();
    const broken = tmpCopy((d) => {
      const p = path.join(d, 'threshold-decision.json');
      const decision = JSON.parse(fs.readFileSync(p, 'utf8'));
      decision.artifact_digest = 'a'.repeat(64); // well-formed hex, wrong binding
      fs.writeFileSync(p, JSON.stringify(decision, null, 2));
    });
    const { exitCode, stderr } = runCli(['--owner-inputs', broken], evidenceDir);
    assert.equal(exitCode, 1);
    assert.ok(stderr.includes('OWNER_INPUTS_REJECTED'));
    assert.ok(stderr.includes('decision_digest_mismatch'));
    assert.ok(fs.existsSync(path.join(evidenceDir, 's2-006-owner-inputs.json')) === false);
  });
});

describe('S2-006 finding 7: tampered owner-inputs packages fail closed (no silent fixture fallback)', () => {
  test('a forged annotation-set signature is refused at load', () => {
    const dir = tmpCopy((d) => {
      const p = path.join(d, 'annotation-sets', 'ans-owner-b.json');
      const set = JSON.parse(fs.readFileSync(p, 'utf8'));
      set.signature.digest = '0'.repeat(64);
      fs.writeFileSync(p, JSON.stringify(set, null, 2));
    });
    const loaded = loadOwnerInputs(dir);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((i) => i.includes('signature')), JSON.stringify(loaded.issues, null, 1));
  });

  test('a status outside the loader white-list is refused', () => {
    const dir = tmpCopy((d) => {
      const p = path.join(d, 'external-manifest.json');
      const manifest = JSON.parse(fs.readFileSync(p, 'utf8'));
      manifest.externalStratum.status = 'SUBMITTED';
      fs.writeFileSync(p, JSON.stringify(manifest, null, 2));
    });
    const loaded = loadOwnerInputs(dir);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((i) => i.includes('externalStratum')), JSON.stringify(loaded.issues, null, 1));
  });

  test('a white-listed status without an explicit reason is refused', () => {
    const dir = tmpCopy((d) => {
      const p = path.join(d, 'external-manifest.json');
      const manifest = JSON.parse(fs.readFileSync(p, 'utf8'));
      manifest.externalStratum.reason = '   ';
      fs.writeFileSync(p, JSON.stringify(manifest, null, 2));
    });
    const loaded = loadOwnerInputs(dir);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((i) => i.includes('reason')), JSON.stringify(loaded.issues, null, 1));
  });

  test('a manifest that violates the frozen schema is refused', () => {
    const dir = tmpCopy((d) => {
      const p = path.join(d, 'external-manifest.json');
      const manifest = JSON.parse(fs.readFileSync(p, 'utf8'));
      delete manifest.frozenAt;
      fs.writeFileSync(p, JSON.stringify(manifest, null, 2));
    });
    const loaded = loadOwnerInputs(dir);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((i) => i.includes('external-manifest')), JSON.stringify(loaded.issues, null, 1));
  });

  test('a decision not binding to the exact thresholds digest is refused', () => {
    const dir = tmpCopy((d) => {
      const p = path.join(d, 'thresholds.json');
      const doc = JSON.parse(fs.readFileSync(p, 'utf8'));
      doc.coverage_floor.value = 0.55; // bytes and canonical digest drift; the decision still binds the old digest
      fs.writeFileSync(p, JSON.stringify(doc, null, 2));
    });
    const loaded = loadOwnerInputs(dir);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((i) => i.includes('decision_digest_mismatch')), JSON.stringify(loaded.issues, null, 1));
  });

  test('a missing owner-input file is a load refusal, never a fallback', () => {
    const dir = tmpCopy((d) => fs.rmSync(path.join(d, 'independence.json')));
    const loaded = loadOwnerInputs(dir);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((i) => i.includes('independence.json')), JSON.stringify(loaded.issues, null, 1));
  });

  test('a case file whose bytes drift from the manifest is refused', () => {
    const dir = tmpCopy((d) => {
      const p = path.join(d, 'cases', 'case-owner-ext-03.json');
      const file = JSON.parse(fs.readFileSync(p, 'utf8'));
      file.scenario.statement += ' (drifted)';
      fs.writeFileSync(p, JSON.stringify(file, null, 2));
    });
    const loaded = loadOwnerInputs(dir);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((i) => i.includes('case-owner-ext-03')), JSON.stringify(loaded.issues, null, 1));
  });

  test('a broken adjudicator attestation is refused', () => {
    const dir = tmpCopy((d) => {
      const p = path.join(d, 'adjudication.json');
      const records = JSON.parse(fs.readFileSync(p, 'utf8'));
      records[0].rationale += ' tampered after signing';
      fs.writeFileSync(p, JSON.stringify(records, null, 2));
    });
    const loaded = loadOwnerInputs(dir);
    assert.equal(loaded.ok, false);
    assert.ok(loaded.issues.some((i) => i.includes('adjudication') && i.includes('attestation')), JSON.stringify(loaded.issues, null, 1));
  });
});

describe('S2-006 finding 7: candidate blinding over the owner corpus', () => {
  test('the child-side loader reads the owner manifest and cases, never label material', () => {
    const corpus = loadOwnerExternalCorpus(FIXTURE_DIR);
    assert.equal(corpus.ok, true, JSON.stringify(corpus.issues, null, 1));
    assert.equal(corpus.cases.length, 6);
    assert.equal(corpus.stratum, 'external_owner_inputs');
    assert.equal(corpus.labelSets, undefined);
    assert.equal(corpus.adjudications, undefined);
    const frozenRubricSha = sha256File(path.join(ROOT, 'corpus', 's2-006', 'rubric-v1.json'));
    assert.equal(corpus.rubricDigest, frozenRubricSha);
  });
});

describe('S2-006 finding 7: aggregator summary propagation (deriveVerdict logic untouched)', () => {
  test('summarizeOwnerInputs reports absence as the honest NOT_RUN_HUMAN_INPUTS', () => {
    assert.deepEqual(summarizeOwnerInputs(null), { present: false, status: 'NOT_RUN_HUMAN_INPUTS' });
    assert.deepEqual(summarizeOwnerInputs(undefined), { present: false, status: 'NOT_RUN_HUMAN_INPUTS' });
  });

  test('summarizeOwnerInputs reports presence with resolved tiers', () => {
    const record = {
      ownerInputs: {
        manifest: { manifestId: 'anmf-owner-inputs-fixture', externalStratum: { status: 'MEASURED', reason: 'SYNTHETIC …' } },
        independence: { resolved: true, tier: 'INDEPENDENTLY_CALIBRATED' },
        thresholdDecision: { resolved: true, reason: 'verified', ownerPrincipal: 'prn-owner-method-owner-1' },
      },
      pipeline: { comparatorOk: true, decision: { status: 'HUMAN_REVIEW' } },
      honesty: { annotationHmacKey: 'fixture-key' },
    };
    const summary = summarizeOwnerInputs(record);
    assert.equal(summary.present, true);
    assert.equal(summary.status, 'OWNER_INPUTS_PRESENT');
    assert.equal(summary.externalStratum.status, 'MEASURED');
    assert.equal(summary.independence.tier, 'INDEPENDENTLY_CALIBRATED');
    assert.equal(summary.thresholdDecision.resolved, true);
    assert.equal(summary.decisionStatus, 'HUMAN_REVIEW');
    assert.equal(summary.comparatorOk, true);
  });

  test('the adjudicator attestation digest is a pure function of the record content', () => {
    const record = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'adjudication.json'), 'utf8'))[0];
    const a = adjudicationAttestationDigest(record);
    const withoutIdentity = { ...record };
    delete withoutIdentity.adjudicatorIdentity;
    delete withoutIdentity.auditRef;
    assert.equal(a, adjudicationAttestationDigest(withoutIdentity));
    assert.match(a, /^[0-9a-f]{64}$/);
  });
});

describe('S2-006 finding 7: fixture honesty invariants', () => {
  test('the fixture README declares the synthetic nature', () => {
    const readme = fs.readFileSync(path.join(FIXTURE_DIR, 'README.md'), 'utf8');
    assert.ok(readme.includes('SYNTHETIC'));
    assert.ok(readme.includes('NOT'));
    assert.ok(readme.includes('production'));
  });

  test('the externalStratum reason of the committed manifest carries the synthetic disclosure', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'external-manifest.json'), 'utf8'));
    assert.ok(manifest.externalStratum.reason.includes('SYNTHETIC'));
    assert.ok(manifest.externalStratum.reason.includes('NOT claimed'));
  });

  test('the fixture HMAC material is the public in-repo convention, not custody-grade', () => {
    assert.equal(FIXTURE_ANNOTATION_HMAC_KEY, 's2-006-fixture-hmac-key');
  });
});
