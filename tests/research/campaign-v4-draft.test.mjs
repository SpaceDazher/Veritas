import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const draft = JSON.parse(readFileSync(new URL('../../corpus/s2-008-campaign/preregistration.v4.draft.json', import.meta.url), 'utf8'));

test('v4 budget explanation counts only the model trial as paid work', () => {
  const modelTrials = draft.trial_list.filter((trial) => trial.arm_id === 'arm-model-zai-glm53flash');
  const calls = modelTrials.length * draft.seed_count * 126;
  assert.equal(calls, 378);
  assert.match(draft.budget_reservation.enumerated_work, /3 model runs x 126 holdout cases = 378 case calls/);
  assert.equal(draft.budget_reservation.usd_reference.plan.calls, calls);
});

test('v4 signs only a stable program commitment, without a stale built image digest', () => {
  assert.match(draft.executor.model_image.content_commitment, /^[a-f0-9]{64}$/);
  assert.equal('built_image_id' in draft.executor.model_image, false);
  assert.equal('built_image_digest' in draft.executor.model_image, false);
});
