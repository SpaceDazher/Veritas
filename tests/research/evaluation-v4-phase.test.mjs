import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { evaluateV4Campaign } from '../../scripts/s2-008-campaign-evaluate.mjs';

const corpus = path.resolve(import.meta.dirname, '../../corpus/s2-008-campaign');
const prereg = JSON.parse(fs.readFileSync(path.join(corpus, 'preregistration.v4.in-force.json')));
const manifestV5 = JSON.parse(fs.readFileSync(path.join(corpus, 'manifest.json')));
const manifest = structuredClone(manifestV5);
manifest.preregistration = { file: 'preregistration.v4.in-force.json',
  status: 'IN_FORCE', preregistration_digest: prereg.preregistration_digest };
const preregV5 = JSON.parse(fs.readFileSync(path.join(corpus, 'preregistration.v5.in-force.json')));
const frozenTable = JSON.parse(fs.readFileSync(path.join(corpus, 'frozen-table.v3.json')));
const holdoutCases = JSON.parse(fs.readFileSync(path.join(corpus, 'cases/holdout.json')));

function fixture(version = 'v4', selectedPrereg = prereg) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eval-v4-fixture-'));
  const runs = [];
  for (const label of ['a', 'b']) {
    const trials = [];
    const charges = [];
    let spent = 0;
    for (const entry of selectedPrereg.trial_list) {
      const seeds = [];
      for (const seed of selectedPrereg.seed_rule.seeds) {
        const model = entry.arm_id === 'arm-model-zai-glm53flash';
        const rows = holdoutCases.map((row) => ({ case_id: row.case_id, predicted: row.label }));
        const body = { kind: 's2-008-campaign-predictions/1', run: label, arm_id: entry.arm_id,
          seed, unparsed: 0, model_calls: model ? 126 : 0, spent_tokens: model ? 100 : 0,
          usd_spent: model ? 0.01 : 0, outcome_class: model ? 'MEASURED' : 'NOT_RUN', rows };
        const file = `evidence/s2-008-campaign/predictions-${version}-${label}-${entry.trial_id}-${seed}.json`;
        const absolute = path.join(root, file);
        fs.mkdirSync(path.dirname(absolute), { recursive: true });
        fs.writeFileSync(absolute, JSON.stringify(body));
        seeds.push({ seed, outcome_class: body.outcome_class,
          predictions: { file, digest: canonicalDigest(body), rows: rows.length, unparsed: 0 } });
        const units = model ? 100 : 0;
        spent += units;
        charges.push({ trial: entry.trial_id, arm_id: entry.arm_id, seed, units });
      }
      trials.push({ trial_id: entry.trial_id, arm_id: entry.arm_id, seeds });
    }
    runs.push({ kind: `s2-008-campaign-${version}-predictions/1`, status: 'MEASURED', label,
      dry_run: false, raw_run_id: `run-${label}`, nonce: `nonce-${label}`,
      base: { commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false },
      preregistration_digest: selectedPrereg.preregistration_digest,
      model_image_pin: { content_commitment: selectedPrereg.executor.model_image.content_commitment },
      reservation: { currency: 'tokens', granted_units: selectedPrereg.budget_reservation.granted_units },
      spent_units: spent, model_calls: 378, launches: charges.length, charges, trials });
  }
  const bootstrap = ({ vectors, seeds, samples, confidence }) => ({
    record: { real_start: { proven: true } },
    output: { kind: 's2-008-campaign-bootstrap-output/1', samples, confidence,
      results: vectors.flatMap((vector) => seeds.map((seed) => ({
        arm_id: vector.arm_id, trial_id: vector.trial_id, seed, samples,
        n: vector.agreement.length, observed_rate: 1, lower: 1, upper: 1,
        confidence, method: 'PERCENTILE_BOOTSTRAP_WITH_MULTIPLICITY',
        mean_matches_observed: true,
      }))) },
  });
  return { root, runA: runs[0], runB: runs[1], bootstrap };
}

test('v4 post-reveal phase scores both runs with isolated bootstrap and discloses repeat agreement', () => {
  const f = fixture();
  try {
    const result = evaluateV4Campaign({ ...f, prereg, manifest, frozenTable, holdoutCases });
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.table.verdict, 'AGREES');
    assert.equal(result.table.remarks.length, 0);
    assert.equal(result.probes.status, 'NOT_RUN');
    assert.equal(result.probes.total, 7);
    assert.equal(result.aggregate_spend.units, 600);
    assert.equal(result.runs.length, 2);
    assert.equal(result.runs[0].trials.length, prereg.trial_list.length);
    assert.equal(result.runs[0].trials[0].agreeing, holdoutCases.length);
    assert.equal(result.reproducibility.same_decision_digest, true);
    assert.equal(result.runs[0].pooled.decision.decision, 'POSITIVE');
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

test('v4 post-reveal phase refuses non-isolated bootstrap and changed seed rate', () => {
  const f = fixture();
  try {
    const noIsolation = evaluateV4Campaign({ ...f, prereg, manifest, frozenTable, holdoutCases,
      bootstrap: (input) => ({ ...f.bootstrap(input), record: { real_start: { proven: false } } }) });
    assert.match(noIsolation.reason, /BOOTSTRAP_ISOLATION/);
    const file = f.runA.trials[0].seeds[1].predictions.file;
    const body = JSON.parse(fs.readFileSync(path.join(f.root, file)));
    body.rows[0].predicted = body.rows[0].predicted === 'MAJOR' ? 'MINOR' : 'MAJOR';
    fs.writeFileSync(path.join(f.root, file), JSON.stringify(body));
    f.runA.trials[0].seeds[1].predictions.digest = canonicalDigest(body);
    const changed = evaluateV4Campaign({ ...f, prereg, manifest, frozenTable, holdoutCases });
    assert.match(changed.reason, /SEED_RATE_MOVED/);
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

test('v4 post-reveal phase binds immutable sidecar usage to charged tokens', () => {
  const f = fixture();
  try {
    const file = f.runA.trials[0].seeds[0].predictions.file;
    const body = JSON.parse(fs.readFileSync(path.join(f.root, file)));
    body.spent_tokens += 1;
    fs.writeFileSync(path.join(f.root, file), JSON.stringify(body));
    f.runA.trials[0].seeds[0].predictions.digest = canonicalDigest(body);
    const changed = evaluateV4Campaign({ ...f, prereg, manifest, frozenTable, holdoutCases });
    assert.equal(changed.reason, 'V4_SIDECAR_USAGE_MISMATCH');
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

test('v4 table tamper is refused before bootstrap and cannot claim an outcome', () => {
  const f = fixture();
  try {
    let launches = 0;
    const changed = structuredClone(frozenTable);
    changed.band += 0.01;
    const result = evaluateV4Campaign({ ...f, prereg, manifest, frozenTable: changed,
      holdoutCases, bootstrap: (input) => { launches += 1; return f.bootstrap(input); } });
    assert.equal(result.reason, 'V4_FROZEN_TABLE_DIGEST_MISMATCH');
    assert.equal(launches, 0);
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

test('active v5 manifest routes v5 prediction sidecars with the same frozen science', () => {
  const f = fixture('v5', preregV5);
  try {
    const result = evaluateV4Campaign({ ...f, prereg: preregV5, manifest: manifestV5,
      frozenTable, holdoutCases });
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.kind, 's2-008-campaign-v5-evaluation/1');
    assert.equal(result.table.verdict, 'AGREES');
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});
