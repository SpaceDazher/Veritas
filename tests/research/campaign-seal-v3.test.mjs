import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { approveV3 } from '../../scripts/s2-008-campaign-approve.mjs';
import { sealV3 } from '../../scripts/s2-008-campaign-seal-v3.mjs';
import { assertRunnerPreregInForce } from '../../scripts/s2-008-campaign-run.mjs';
import { assertPreregistration, assertSourceLedger, assertSupersession, preregistrationDigest } from '../../src/lib/research/index.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';

const dir = path.resolve(import.meta.dirname, '../../corpus/s2-008-campaign');
const load = (name) => JSON.parse(readFileSync(path.join(dir, name), 'utf8'));
const base = load('preregistration.json');
const draft = load('preregistration.v3.draft.json');
const table = load('frozen-table.v3.json');
const manifest = { ...load('manifest.json'), preregistration: { file: 'preregistration.json', status: 'IN_FORCE', preregistration_digest: base.preregistration_digest } };
const ledger = load('source-ledger.json');
const clone = (value) => structuredClone(value);

test('v3 signature binds one explicit model substitution and rejects extra scientific drift', () => {
  const signed = approveV3({ draft, base, table, principal: 'prn-s2007r-owner', label: 'Daniil', issuedAt: '2026-09-29T00:00:00.000Z' });
  assert.equal(signed.approval.in_force, false);
  assert.equal(signed.approval.principal_id, 'prn-s2007r-owner');
  const changed = clone(draft);
  changed.trial_list[1].arm_id = 'another-arm';
  assert.throws(() => approveV3({ draft: changed, base, table, principal: 'p', label: 'l' }), /V3_SCOPE_DRIFT/);
  const moved = clone(draft);
  moved.metric.noiseBand += 0.01;
  assert.throws(() => approveV3({ draft: moved, base, table, principal: 'p', label: 'l' }), /APPROVAL_SCOPE_DRIFT/);
});

test('seal v3 binds the signed digest, supersedes v1 and appends a valid source ledger entry', () => {
  const signed = approveV3({ draft, base, table, principal: 'prn-s2007r-owner', label: 'Daniil', issuedAt: '2026-09-29T00:00:00.000Z' });
  const result = sealV3({ signed, draft, base, table, manifest, ledger });
  assert.equal(signed.approval.in_force, false);
  assert.equal(result.prereg.approval.in_force, true);
  assert.equal(result.manifest.preregistration.preregistration_digest, signed.preregistration_digest);
  assert.equal(preregistrationDigest(result.prereg), signed.preregistration_digest);
  assert.doesNotThrow(() => assertPreregistration(result.prereg));
  assert.equal(result.manifest.superseded_preregistration.preregistration_digest, base.preregistration_digest);
  assert.doesNotThrow(() => assertSupersession(result.supersession, base));
  assert.doesNotThrow(() => assertSourceLedger(result.ledger.entries, {
    cases_digest: result.ledger.entries.at(-1).cases_digest,
    expected_table_digest: canonicalDigest(table),
  }));
  assert.equal(result.manifest.source_ledger.entry_count, ledger.entries.length + 1);
});

test('seal refuses tampering, stale base and an unsigned document without writing', () => {
  const signed = approveV3({ draft, base, table, principal: 'p', label: 'l' });
  const call = (patch) => sealV3({ signed, draft, base, table, manifest, ledger, ...patch });
  const tampered = clone(signed);
  tampered.budget_reservation.granted_units += 1;
  assert.throws(() => call({ signed: tampered }), /DIGEST_MISMATCH/);
  const unsigned = clone(draft);
  assert.throws(() => call({ signed: unsigned }), /NOT_APPROVED/);
  const stale = clone(manifest);
  stale.preregistration.preregistration_digest = '0'.repeat(64);
  assert.throws(() => call({ manifest: stale }), /BASE_MISMATCH/);
});

test('the legacy campaign runner refuses once v3 is the manifest authority', () => {
  const current = load('manifest.json');
  assert.throws(() => assertRunnerPreregInForce(base, current), /CAMPAIGN_PREREGISTRATION_NOT_IN_FORCE/);
  assert.doesNotThrow(() => assertRunnerPreregInForce(base, manifest));
});
