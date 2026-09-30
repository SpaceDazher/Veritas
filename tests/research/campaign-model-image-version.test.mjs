import { test } from 'node:test';
import assert from 'node:assert/strict';
import { modelImagePaths } from '../../scripts/s2-008-campaign-model-image.mjs';

test('v5 preseal uses v4 document only to establish the acyclic content commitment', () => {
  const preseal = modelImagePaths('v5', { preseal: true });
  const sealed = modelImagePaths('v5');
  assert.equal(preseal.tag, sealed.tag);
  assert.equal(preseal.stagedPrereg, 'corpus/s2-008-campaign/preregistration.v4.in-force.json');
  assert.equal(sealed.stagedPrereg, 'corpus/s2-008-campaign/preregistration.v5.in-force.json');
  assert.equal(preseal.pinFile, 'evidence/s2-008-campaign/model-image-pin-v5-preseal.json');
  assert.equal(sealed.pinFile, 'evidence/s2-008-campaign/model-image-pin-v5.json');
  assert.equal(preseal.schema, 's2-008-model-image-pin/5');
  assert.throws(() => modelImagePaths('v4', { preseal: true }), /MODEL_PRESEAL_VERSION_INVALID/);
});

test('v6 preseal stages the active v5 document and publishes a versioned v6 pin', () => {
  const preseal = modelImagePaths('v6', { preseal: true });
  const sealed = modelImagePaths('v6');
  assert.equal(preseal.tag, sealed.tag);
  assert.equal(preseal.stagedPrereg, 'corpus/s2-008-campaign/preregistration.v5.in-force.json');
  assert.equal(sealed.stagedPrereg, 'corpus/s2-008-campaign/preregistration.v6.in-force.json');
  assert.equal(preseal.pinFile, 'evidence/s2-008-campaign/model-image-pin-v6-preseal.json');
  assert.equal(sealed.pinFile, 'evidence/s2-008-campaign/model-image-pin-v6.json');
  assert.equal(preseal.schema, 's2-008-model-image-pin/6');
  assert.equal(modelImagePaths('v5', { preseal: true }).stagedPrereg, 'corpus/s2-008-campaign/preregistration.v4.in-force.json');
});

test('v7 preseal starts from signed v6 and uses a distinct versioned pin', () => {
  const preseal = modelImagePaths('v7', { preseal: true });
  const sealed = modelImagePaths('v7');
  assert.equal(preseal.tag, sealed.tag);
  assert.equal(preseal.stagedPrereg, 'corpus/s2-008-campaign/preregistration.v6.in-force.json');
  assert.equal(sealed.stagedPrereg, 'corpus/s2-008-campaign/preregistration.v7.in-force.json');
  assert.equal(preseal.pinFile, 'evidence/s2-008-campaign/model-image-pin-v7-preseal.json');
  assert.equal(sealed.pinFile, 'evidence/s2-008-campaign/model-image-pin-v7.json');
  assert.equal(preseal.schema, 's2-008-model-image-pin/7');
});
