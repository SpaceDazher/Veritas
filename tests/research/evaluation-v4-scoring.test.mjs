import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { preflightV4Runs, scoreV4Trial } from '../../scripts/s2-008-campaign-evaluate.mjs';

const root = path.resolve(import.meta.dirname, '../../corpus/s2-008-campaign');
const prereg = JSON.parse(readFileSync(path.join(root, 'preregistration.v4.in-force.json')));
const manifest = structuredClone(JSON.parse(readFileSync(path.join(root, 'manifest.json'))));
manifest.preregistration = { file: 'preregistration.v4.in-force.json',
  status: 'IN_FORCE', preregistration_digest: prereg.preregistration_digest };
const trials = prereg.trial_list.map((entry) => ({
  trial_id: entry.trial_id, arm_id: entry.arm_id,
  seeds: prereg.seed_rule.seeds.map((seed) => ({
    seed, outcome_class: entry.arm_id === 'arm-model-zai-glm53flash' ? 'MEASURED' : 'NOT_RUN',
    predictions: { file: `evidence/s2-008-campaign/predictions-v4-a-${entry.trial_id}-${seed}.json`, digest: 'a'.repeat(64), rows: 126, unparsed: 0 },
  })),
}));
const charges = trials.flatMap((trial) => trial.seeds.map((row) => ({
  trial: trial.trial_id, arm_id: trial.arm_id, seed: row.seed,
  units: trial.arm_id === 'arm-model-zai-glm53flash' ? 100 : 0,
})));
function run(label) {
  const copied = structuredClone(trials);
  for (const trial of copied) for (const row of trial.seeds) row.predictions.file = row.predictions.file.replace('predictions-v4-a-', `predictions-v4-${label}-`);
  return {
    kind: 's2-008-campaign-v4-predictions/1', label, status: 'MEASURED', dry_run: false,
    preregistration_digest: prereg.preregistration_digest,
    raw_run_id: `run-${label}`, nonce: `nonce-${label}`,
    base: { commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false },
    model_image_pin: { content_commitment: prereg.executor.model_image.content_commitment },
    reservation: { id: prereg.budget_reservation.reservation_id, currency: 'tokens', granted_units: prereg.budget_reservation.granted_units },
    spent_units: 300, model_calls: 378, launches: 9, charges: structuredClone(charges), trials: copied,
  };
}

test('v4 preflight requires complete measured runs with distinct IDs and same clean base', () => {
  assert.equal(preflightV4Runs({ runA: run('a'), runB: run('b'), prereg, manifest }).ok, true);
  const dirty = run('b'); dirty.base.worktree_dirty = true;
  assert.match(preflightV4Runs({ runA: run('a'), runB: dirty, prereg, manifest }).reason, /DIRTY_BASE/);
  const duplicate = run('b'); duplicate.nonce = 'nonce-a';
  assert.match(preflightV4Runs({ runA: run('a'), runB: duplicate, prereg, manifest }).reason, /PROVENANCE/);
  const partial = run('a'); partial.trials[0].seeds.pop();
  assert.match(preflightV4Runs({ runA: partial, runB: run('b'), prereg, manifest }).reason, /INCOMPLETE/);
  const dry = run('a'); dry.dry_run = true;
  assert.match(preflightV4Runs({ runA: dry, runB: run('b'), prereg, manifest }).reason, /NOT_MEASURED/);
});

test('v4 trial refuses seed rates that violate the signed seed-invariant point estimate', () => {
  const entry = prereg.trial_list[0];
  const per_seed = prereg.seed_rule.seeds.map((seed, i) => ({ seed, agreeing: i === 1 ? 2 : 1, denominator: 3, observed: (i === 1 ? 2 : 1)/3, unparsed: 0 }));
  const bootstrapRows = per_seed.map((row) => ({ trial_id: entry.trial_id, seed: row.seed, lower: 0.1, upper: 0.9, observed_rate: row.observed, mean_matches_observed: true }));
  assert.match(scoreV4Trial({ entry, per_seed, bootstrapRows, prereg }).reason, /SEED_RATE_MOVED/);
});

test('v4 trial recomputes outcome from frozen constants when all seed rates agree', () => {
  const entry = prereg.trial_list[0];
  const per_seed = prereg.seed_rule.seeds.map((seed) => ({ seed, agreeing: 3, denominator: 3, observed: 1, unparsed: 0 }));
  const bootstrapRows = per_seed.map((row) => ({ trial_id: entry.trial_id, seed: row.seed, lower: 0.95, upper: 1, observed_rate: 1, mean_matches_observed: true }));
  const scored = scoreV4Trial({ entry, per_seed, bootstrapRows, prereg });
  assert.equal(scored.ok, true, scored.reason);
  assert.equal(scored.agreeing, 3);
  assert.equal(scored.outcome, 'POSITIVE');
});
