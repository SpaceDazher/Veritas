import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { assertRecordedModelPin } from '../../scripts/s2-008-campaign-model-image.mjs';

const pin = JSON.parse(readFileSync(new URL('../../evidence/s2-008-campaign/model-image-pin-v4.json', import.meta.url), 'utf8'));

test('a stored model pin must match both rebuilt image Id, Digest and staged sources', () => {
  const current = {
    first: pin.first, second: pin.second,
    identical: true, context_digest_stable: true,
    content_commitment_stable: true, commitment_excludes_preregistration: true,
  };
  assert.doesNotThrow(() => assertRecordedModelPin(current, pin));
  const stale = structuredClone(pin);
  stale.first.digest = 'sha256:' + '0'.repeat(64);
  assert.throws(() => assertRecordedModelPin(current, stale), /MODEL_RECORDED_PIN_MISMATCH/);
  const changed = structuredClone(current);
  changed.first.sources.arm = '0'.repeat(64);
  assert.throws(() => assertRecordedModelPin(changed, pin), /MODEL_RECORDED_PIN_MISMATCH/);
});
