import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { approveV4 } from '../../scripts/s2-008-campaign-approve.mjs';
import { sealV4, checkV4OnDisk } from '../../scripts/s2-008-campaign-seal-v4.mjs';
import { createContentSupersession, assertContentSupersession } from '../../src/lib/research/content-supersession.mjs';
import { assertSourceLedger } from '../../src/lib/research/index.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';

const dir = path.resolve(import.meta.dirname, '../../corpus/s2-008-campaign');
const read = (name) => JSON.parse(readFileSync(path.join(dir, name), 'utf8'));
const base = read('preregistration.v3.in-force.json');
const draft = read('preregistration.v4.draft.json');
const table = read('frozen-table.v3.json');
const pin = JSON.parse(readFileSync(path.resolve(dir, '../../evidence/s2-008-campaign/model-image-pin-v4.json'), 'utf8'));
const activeManifest = read('manifest.json');
const manifest = structuredClone(activeManifest);
manifest.preregistration = {
  file: 'preregistration.v3.in-force.json',
  preregistration_digest: base.preregistration_digest,
  status: 'IN_FORCE',
  sealed_before_first_trial: true,
};
manifest.superseded_preregistration = {
  file: 'preregistration-v1-superseded.json',
  preregistration_digest: read('preregistration-v1-superseded.json').preregistration_digest,
  status: 'SUPERSEDED',
  superseded_by: 'preregistration.v3.in-force.json',
};
manifest.supersession = structuredClone(activeManifest.supersession_history[0]);
delete manifest.supersession_history;
const ledger = read('source-ledger.v3.json');
const clone = (v) => structuredClone(v);

test('v4 approval binds content change to v3 and keeps frozen table and trial list', () => {
  const signed = approveV4({ draft, base, table, pin, principal: 'prn-owner', label: 'Daniil', issuedAt: '2026-09-29T00:00:00.000Z' });
  assert.equal(signed.approval.in_force, false);
  assert.equal(signed.expected_table_digest, base.expected_table_digest);
  assert.equal(canonicalDigest(signed.trial_list), canonicalDigest(base.trial_list));
  assert.match(signed.approval.becomes_in_force_when, /--seal-v4/);
  const drift = clone(draft);
  drift.trial_list[1].arm_id = 'different';
  assert.throws(() => approveV4({ draft: drift, base, table, pin, principal: 'p', label: 'l' }), /SCOPE_DRIFT/);
  const wrongBase = clone(base);
  wrongBase.preregistration_digest = '0'.repeat(64);
  assert.throws(() => approveV4({ draft, base: wrongBase, table, pin, principal: 'p', label: 'l' }), /BASE_MISMATCH/);
});

test('content-only supersession binds both preregistration digests when table and confidence stay fixed', () => {
  const signed = approveV4({ draft, base, table, pin, principal: 'p', label: 'l' });
  const inForce = { ...signed, approval: { ...signed.approval, in_force: true } };
  const record = createContentSupersession({ superseded: base, replacedBy: inForce, reason: 'model image content changed' });
  assert.equal(record.supersedes, base.preregistration_digest);
  assert.equal(record.replaced_by_preregistration_digest, inForce.preregistration_digest);
  assert.doesNotThrow(() => assertContentSupersession(record, base, inForce));
  const wrong = clone(record);
  wrong.replaced_by_preregistration_digest = '0'.repeat(64);
  assert.throws(() => assertContentSupersession(wrong, base, inForce), /MISMATCH/);
  const moved = clone(inForce);
  moved.trial_list[1].arm_id = 'another-arm';
  moved.preregistration_digest = canonicalDigest((({ approval, status, preregistration_digest, ...body }) => body)(moved));
  assert.throws(() => createContentSupersession({ superseded: base, replacedBy: moved, reason: 'changed' }), /RULE_MOVED/);
});

test('v4 seal preserves v3 history and the valid unchanged source ledger', () => {
  const signed = approveV4({ draft, base, table, pin, principal: 'p', label: 'l' });
  const result = sealV4({ signed, draft, base, table, pin, manifest, ledger });
  assert.equal(signed.approval.in_force, false);
  assert.equal(result.prereg.approval.in_force, true);
  assert.equal(result.manifest.preregistration.preregistration_digest, signed.preregistration_digest);
  assert.equal(result.manifest.supersession_history.length, 2);
  assert.equal(result.manifest.supersession_history[0].supersession_digest, manifest.supersession.supersession_digest);
  assert.doesNotThrow(() => assertContentSupersession(result.supersession, base, result.prereg));
  assert.doesNotThrow(() => assertSourceLedger(result.ledger.entries, {
    cases_digest: result.ledger.entries.at(-1).cases_digest,
    expected_table_digest: canonicalDigest(table),
  }));
  assert.equal(result.manifest.source_ledger.entry_count, ledger.entries.length);
});

test('v4 seal rejects unsigned, edited and stale documents', () => {
  const signed = approveV4({ draft, base, table, pin, principal: 'p', label: 'l' });
  const call = (patch) => sealV4({ signed, draft, base, table, pin, manifest, ledger, ...patch });
  assert.throws(() => call({ signed: draft }), /NOT_APPROVED/);
  const edited = clone(signed);
  edited.executor.model_image.content_commitment = '0'.repeat(64);
  assert.throws(() => call({ signed: edited }), /PIN_MISMATCH|DIGEST_MISMATCH/);
  const stale = clone(manifest);
  stale.preregistration.preregistration_digest = '0'.repeat(64);
  assert.throws(() => call({ manifest: stale }), /BASE_MISMATCH/);
});

test('v4 approval and seal refuse a stale or unverified model image pin', () => {
  const wrongPin = clone(pin);
  wrongPin.first.content_commitment = '0'.repeat(64);
  assert.throws(() => approveV4({ draft, base, table, pin: wrongPin, principal: 'p', label: 'l' }), /V4_PIN_MISMATCH/);
  const unverified = clone(pin);
  unverified.identical = false;
  assert.throws(() => approveV4({ draft, base, table, pin: unverified, principal: 'p', label: 'l' }), /V4_PIN_NOT_USABLE/);
  const signed = approveV4({ draft, base, table, pin, principal: 'p', label: 'l' });
  assert.throws(() => sealV4({ signed, draft, base, table, pin: wrongPin, manifest, ledger }), /V4_PIN_MISMATCH/);
});

test('v4 approval refuses duplicate, reordered or extra supersession claims', () => {
  const duplicate = clone(draft);
  duplicate.supersession.unchanged.push(duplicate.supersession.unchanged[0]);
  assert.throws(() => approveV4({ draft: duplicate, base, table, pin, principal: 'p', label: 'l' }), /V4_SUPERSESSION_SCOPE_MISMATCH/);
  const extra = clone(draft);
  extra.supersession.second_supersession = 'unreviewed';
  assert.throws(() => approveV4({ draft: extra, base, table, pin, principal: 'p', label: 'l' }), /V4_SUPERSESSION_SCOPE_MISMATCH/);
  const altered = clone(draft);
  altered.supersession.unchanged[0] = 'executor';
  assert.throws(() => approveV4({ draft: altered, base, table, pin, principal: 'p', label: 'l' }), /V4_SUPERSESSION_SCOPE_MISMATCH/);
});

test('the actual sealed v4 remains bound on disk', () => {
  const checked = checkV4OnDisk();
  assert.equal(checked.ok, true);
  assert.equal(checked.preregistration_digest, read('preregistration.v4.in-force.json').preregistration_digest);
});
