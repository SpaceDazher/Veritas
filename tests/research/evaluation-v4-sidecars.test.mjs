import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { loadV4TrialPredictions } from '../../scripts/s2-008-campaign-evaluate.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';

const entry = { trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash' };
const seeds = [7, 8];
const cases = [
  { case_id: 'c1', label: 'MAJOR' },
  { case_id: 'c2', label: 'MINOR' },
];

function fixture(rowsBySeed = [
  [{ case_id: 'c1', predicted: 'MAJOR' }, { case_id: 'c2', predicted: 'UNPARSED' }],
  [{ case_id: 'c1', predicted: 'MINOR' }, { case_id: 'c2', predicted: 'MINOR' }],
]) {
  const root = mkdtempSync(path.join(tmpdir(), 'v4-sidecar-'));
  const sideDir = path.join(root, 'evidence/s2-008-campaign');
  mkdirSync(sideDir, { recursive: true });
  const refs = seeds.map((seed, i) => {
    const file = `evidence/s2-008-campaign/predictions-v4-a-${entry.trial_id}-${seed}.json`;
    const body = {
      kind: 's2-008-campaign-predictions/1', run: 'a', arm_id: entry.arm_id, seed,
      unparsed: rowsBySeed[i].filter((row) => row.predicted === 'UNPARSED').length,
      model_calls: 2, spent_tokens: 100, usd_spent: 0.01, outcome_class: 'MEASURED',
      rows: rowsBySeed[i],
    };
    writeFileSync(path.join(root, file), JSON.stringify(body));
    return { seed, predictions: { file, digest: canonicalDigest(body), rows: body.rows.length, unparsed: body.unparsed } };
  });
  return { root, trial: { trial_id: entry.trial_id, arm_id: entry.arm_id, seeds: refs }, refs };
}

test('v4 loader scores every seed independently; UNPARSED disagrees', () => {
  const f = fixture();
  try {
    const result = loadV4TrialPredictions({ trial: f.trial, entry, runLabel: 'a', seeds, holdoutCases: cases, root: f.root });
    assert.equal(result.available, true, result.reason);
    assert.deepEqual(result.per_seed.map((row) => row.agreeing), [1, 1]);
    assert.deepEqual(result.per_seed.map((row) => row.unparsed), [1, 0]);
    assert.equal(result.per_seed.length, 2);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('v4 loader refuses a tampered or missing immutable sidecar', () => {
  const f = fixture();
  try {
    const file = path.join(f.root, f.refs[0].predictions.file);
    const body = JSON.parse(readFileSync(file));
    body.rows[0].predicted = 'MINOR';
    writeFileSync(file, JSON.stringify(body));
    assert.match(loadV4TrialPredictions({ trial: f.trial, entry, runLabel: 'a', seeds, holdoutCases: cases, root: f.root }).reason, /DIGEST_MISMATCH/);
    rmSync(file);
    assert.match(loadV4TrialPredictions({ trial: f.trial, entry, runLabel: 'a', seeds, holdoutCases: cases, root: f.root }).reason, /SIDECAR_MISSING/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('v4 loader refuses wrong case sets and incomplete seed set', () => {
  const f = fixture([
    [{ case_id: 'c1', predicted: 'MAJOR' }, { case_id: 'alien', predicted: 'MINOR' }],
    [{ case_id: 'c1', predicted: 'MINOR' }, { case_id: 'c2', predicted: 'MINOR' }],
  ]);
  try {
    assert.match(loadV4TrialPredictions({ trial: f.trial, entry, runLabel: 'a', seeds, holdoutCases: cases, root: f.root }).reason, /CASE_SET/);
    assert.match(loadV4TrialPredictions({ trial: { ...f.trial, seeds: f.trial.seeds.slice(0, 1) }, entry, runLabel: 'a', seeds, holdoutCases: cases, root: f.root }).reason, /SEED_SET/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('v4 loader refuses wrong run identity and out-of-scope sidecar path', () => {
  const f = fixture();
  try {
    assert.match(loadV4TrialPredictions({ trial: f.trial, entry, runLabel: 'b', seeds, holdoutCases: cases, root: f.root }).reason, /SIDECAR_PATH/);
    const bad = structuredClone(f.trial);
    bad.seeds[0].predictions.file = '../outside.json';
    assert.match(loadV4TrialPredictions({ trial: bad, entry, runLabel: 'a', seeds, holdoutCases: cases, root: f.root }).reason, /SIDECAR_PATH/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});
