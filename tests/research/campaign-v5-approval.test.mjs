import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { createV5Draft, approveV5 } from '../../scripts/s2-008-campaign-v5-approval.mjs';
import { preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import { assertPreregistration } from '../../src/lib/research/preregistration.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const baseBytes = fs.readFileSync(path.join(root, 'corpus/s2-008-campaign/preregistration.v4.in-force.json'));
const base = JSON.parse(baseBytes);
const oldPin = JSON.parse(fs.readFileSync(path.join(root, 'evidence/s2-008-campaign/model-image-pin-v4.json')));
const table = JSON.parse(fs.readFileSync(path.join(root, 'corpus/s2-008-campaign/frozen-table.v3.json')));
const sources = { ...oldPin.first.sources, arm: 'f'.repeat(64) };
const covers = Object.keys(sources).filter((key) => key !== 'prereg').sort();
const commitment = canonicalDigest(Object.fromEntries(covers.map((key) => [key, sources[key]])));
const first = { ...oldPin.first, sources, source_digest: canonicalDigest(sources), content_commitment: commitment, content_commitment_covers: covers };
const pin = { ...oldPin, schema: 's2-008-model-image-pin/5', first, second: structuredClone(first),
  commitment: { ...oldPin.commitment, covers } };

test('v5 draft keeps frozen science and states owner-approved per-run ceiling', () => {
  const draft = createV5Draft({ base, baseBytes, pin });
  assert.equal(draft.rule, 's2-008-prereg-v5');
  assert.equal(draft.approval.status, null);
  assert.equal(draft.executor.model_image.content_commitment, commitment);
  assert.equal(draft.budget_reservation.granted_units, 5_000_000);
  assert.equal(draft.budget_reservation.ceiling_scope, 'PER_RUN_A_OR_B');
  const signed = approveV5({ draft, base, baseBytes, table, pin, principal: 'prn-s2007r-owner', label: 'Daniil (repository owner)' });
  assert.equal(signed.approval.status, 'APPROVED');
  assert.equal(signed.approval.in_force, false);
  assert.doesNotThrow(() => assertPreregistration(signed));
});

test('v5 approval rejects science edits and a changed model commitment', () => {
  const draft = createV5Draft({ base, baseBytes, pin });
  const moved = structuredClone(draft);
  moved.seed_rule.seeds[0] += 1;
  moved.preregistration_digest = preregistrationDigest(moved);
  assert.throws(() => approveV5({ draft: moved, base, baseBytes, table, pin, principal: 'prn-s2007r-owner', label: 'Daniil' }), /APPROVAL_SCOPE_DRIFT:seed_rule/);
  const fake = structuredClone(draft);
  fake.executor.model_image.content_commitment = '0'.repeat(64);
  fake.preregistration_digest = preregistrationDigest(fake);
  assert.throws(() => approveV5({ draft: fake, base, baseBytes, table, pin, principal: 'prn-s2007r-owner', label: 'Daniil' }), /V5_PIN_MISMATCH/);
});
