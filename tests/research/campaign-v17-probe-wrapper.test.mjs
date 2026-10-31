import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { PROBE_FAMILIES, PROBE_NAMES } from '../../src/lib/research/probes.mjs';
import { NEGATIVE_CONTROLS, EXTRA_CONTROL_IDS } from '../../src/lib/research/negative-controls.mjs';
import { RESEARCH_HARD_GATE_COUNTERS } from '../../src/lib/research/constants.mjs';
import * as evalRoute from '../../scripts/s2-008-campaign-evaluate.mjs';
import * as v18Approval from '../../scripts/s2-008-campaign-v18-approval.mjs';

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function v17ProbeInputs(repoRoot) {
  const prereg = JSON.parse(fs.readFileSync(path.join(repoRoot,
    'corpus/s2-008-campaign/preregistration.v17.in-force.json'), 'utf8'));
  const commit = execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const tree = execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim();
  const runA = { base: { commit_sha: commit, tree_sha: tree } };
  const runB = { base: { commit_sha: commit, tree_sha: tree } };
  const outcomes = ['MEASURED'];
  const campaignProbes = {
    kind: 's2-008-campaign-probes/1', status: 'PASS', ok: true, exitCode: 0,
    preregistration_digest: prereg.preregistration_digest,
    commit_sha: commit, tree_sha: tree,
    probes: ['P1_INFRA_IMAGE_ABSENT', 'P2_LOST_EVALUATOR', 'P3_NO_MEASUREMENT',
      'P4_PREREGISTERED_TIMEOUT', 'P5_INTERRUPTED_THEN_RESTARTED', 'P6_EXPIRED_RESERVATION',
      'P7_MISSING_OUTCOME_DETECTABLE'].map((probe) => ({ probe, held: true, observed: { outcome: 'MEASURED' } })),
    summary: { total: 7, held: 7, broken: 0, outcome_classes_exercised: outcomes },
  };
  const securityRows = PROBE_FAMILIES.flatMap((family) => PROBE_NAMES[family]
    .map((probe) => ({ family, probe, passed: true, status: 'pass' })));
  const notRun = [];
  const controlRows = [...NEGATIVE_CONTROLS.map((row) => row.id), ...EXTRA_CONTROL_IDS]
    .map((id) => ({ id, flipped: true }));
  const counters = Object.fromEntries(RESEARCH_HARD_GATE_COUNTERS.map((name) => [name, 0]));
  const securityControls = {
    base: { commit_sha: commit, tree_sha: tree },
    probes: { results: securityRows, notRun: [], broken: [] },
    controls: { records: controlRows, notRun,
      digest: canonicalDigest({ controls: controlRows, notRun }), allFlipped: true,
      gate: { ok: true, failures: [] } },
    hardGates: { counters, names: RESEARCH_HARD_GATE_COUNTERS, ok: true, moved: [] },
    totals: {
      families: PROBE_FAMILIES.length, probes: securityRows.length,
      probes_ran: securityRows.length, passed: securityRows.length,
      failed: 0, not_run: 0, broken: 0,
      controls_declared: NEGATIVE_CONTROLS.length,
      controls_extra_declared: EXTRA_CONTROL_IDS.length,
      controls_ran: controlRows.length, controls_flipped: controlRows.length,
      controls_unaccounted: [],
    },
    status: 'PASS', ok: true, exitCode: 0,
  };
  return { prereg, campaignProbes, securityControls, runA, runB };
}

test('v17 probe validator accepts valid v17 evidence and rejects a different preregistration version', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'v17-probe-wrapper-'));
  const repoRoot = path.join(workspace, 'repo');
  try {
    execFileSync('git', ['clone', '--quiet', '--shared', '--no-hardlinks', sourceRoot, repoRoot]);
    const historicalV17 = v18Approval.readV18BaseInputs({ repoRoot: sourceRoot, allowHistorical: true }).manifest;
    fs.writeFileSync(path.join(repoRoot, 'corpus/s2-008-campaign/manifest.json'),
      JSON.stringify(historicalV17, null, 2) + '\n');
    const inputs = v17ProbeInputs(repoRoot);
    const accepted = evalRoute.validateV17ProbeEvidence({ ...inputs, root: repoRoot });
    assert.equal(accepted.ok, true, JSON.stringify(accepted));
    assert.equal(accepted.status, 'PASS');

    const wrongVersion = JSON.parse(fs.readFileSync(path.join(repoRoot,
      'corpus/s2-008-campaign/preregistration-v16-superseded.json'), 'utf8'));
    const rejected = evalRoute.validateV17ProbeEvidence({ ...inputs, prereg: wrongVersion, root: repoRoot });
    assert.deepEqual(rejected, {
      ok: false, status: 'NOT_RUN', reason: 'V17_PREREGISTRATION_DIGEST_MISMATCH',
    });
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});
