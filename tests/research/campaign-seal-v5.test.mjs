import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { sealV5 } from '../../scripts/s2-008-campaign-seal-v5.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const corpus = path.join(root, 'corpus/s2-008-campaign');
const read = (name) => JSON.parse(fs.readFileSync(path.join(corpus, name)));
const input = () => ({
  signed: read('preregistration.v5.approved.json'),
  draft: read('preregistration.v5.draft.json'),
  base: read('preregistration.v4.in-force.json'),
  baseBytes: fs.readFileSync(path.join(corpus, 'preregistration.v4.in-force.json')),
  table: read('frozen-table.v3.json'),
  pin: JSON.parse(fs.readFileSync(path.join(root, 'evidence/s2-008-campaign/model-image-pin-v5-preseal.json'))),
  manifest: (() => {
    const active = read('manifest.json');
    const base = read('preregistration.v4.in-force.json');
    const previous = active.supersession_history.at(-2);
    return { ...active,
      preregistration: { file: 'preregistration.v4.in-force.json', status: 'IN_FORCE',
        preregistration_digest: base.preregistration_digest },
      supersession_history: active.supersession_history.slice(0, -1),
      supersession: previous,
    };
  })(),
  ledger: read('source-ledger.v3.json'),
});

test('v5 seal records a content supersession without changing source ledger or scientific members', () => {
  const before = input();
  const after = sealV5(before);
  assert.equal(after.prereg.approval.in_force, true);
  assert.equal(after.manifest.preregistration.file, 'preregistration.v5.in-force.json');
  assert.equal(after.manifest.superseded_preregistration.preregistration_digest, before.base.preregistration_digest);
  assert.equal(after.ledger.entries.length, before.ledger.entries.length);
  assert.equal(after.supersession.supersedes, before.base.preregistration_digest);
});

test('v5 seal refuses an unapproved or altered document', () => {
  const unsigned = input();
  unsigned.signed.approval.status = null;
  assert.throws(() => sealV5(unsigned), /V5_NOT_APPROVED/);
  const moved = input();
  moved.signed.metric.name = 'other';
  assert.throws(() => sealV5(moved), /V5_DIGEST_MISMATCH/);
});
