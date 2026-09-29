import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import {
  assertPreregistration, assertSourceLedger, assertSupersession,
  createSourceLedgerEntry, createSupersession, preregistrationDigest,
} from '../src/lib/research/index.mjs';
import { approveV3, scientificBody } from './s2-008-campaign-approve.mjs';

const DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../corpus/s2-008-campaign');
const REASON = 'v3 replaces the trial 01 regex predictor with the model under a 5000000-token cap; trials 02 and 03 remain controls, and the metric, baseline, band, seeds and decision rule remain fixed';

export function sealV3({ signed, draft, base, table, manifest, ledger }) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || !signed.approval?.principal_id) {
    throw new Error('V3_NOT_APPROVED');
  }
  if (signed.approval.in_force !== false) throw new Error('V3_ALREADY_IN_FORCE');
  if (signed.preregistration_digest !== canonicalDigest(scientificBody(signed))) throw new Error('V3_DIGEST_MISMATCH');
  if (canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft))) throw new Error('V3_DRAFT_MISMATCH');
  if (manifest?.preregistration?.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(base) ||
      base.preregistration_digest !== preregistrationDigest(base)) throw new Error('V3_BASE_MISMATCH');
  if (signed.expected_table_digest !== canonicalDigest(table)) throw new Error('V3_TABLE_MISMATCH');
  const expected = approveV3({ draft, base, table, principal: signed.approval.principal_id, label: signed.approval.label, issuedAt: signed.approval.issued_at });
  if (expected.preregistration_digest !== signed.preregistration_digest) throw new Error('V3_SIGNATURE_SCOPE_MISMATCH');

  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertPreregistration(prereg);
  const supersession = createSupersession({ superseded: base, replacedBy: prereg, reason: REASON });
  assertSupersession(supersession, base);

  if (!Array.isArray(ledger?.entries) || ledger.entries.length === 0) throw new Error('V3_LEDGER_ABSENT');
  const previous = ledger.entries.at(-1);
  const casesDigest = previous.cases_digest;
  const tableDigest = canonicalDigest(table);
  const next = createSourceLedgerEntry({
    index: ledger.entries.length, previous, cases_digest: casesDigest,
    expected_table_digest: tableDigest, reason: REASON,
  });
  const entries = [...ledger.entries, next];
  assertSourceLedger(entries, { cases_digest: casesDigest, expected_table_digest: tableDigest });
  const newLedger = { ...ledger, entries };
  const newManifest = structuredClone(manifest);
  newManifest.preregistration = {
    file: 'preregistration.v3.in-force.json',
    preregistration_digest: signed.preregistration_digest,
    status: 'IN_FORCE',
    sealed_before_first_trial: true,
  };
  newManifest.superseded_preregistration = {
    file: 'preregistration-v1-superseded.json',
    preregistration_digest: base.preregistration_digest,
    status: 'SUPERSEDED',
    superseded_by: 'preregistration.v3.in-force.json',
  };
  newManifest.supersession = {
    file: 'preregistration-v3-supersession.json',
    supersession_id: supersession.supersession_id,
    supersession_digest: supersession.supersession_digest,
    reason: REASON,
  };
  newManifest.frozen_table = { file: 'frozen-table.v3.json', digest: tableDigest };
  newManifest.source_ledger = {
    file: 'source-ledger.v3.json',
    entry_count: entries.length,
    last_anchor_digest: next.anchor_digest,
  };
  return { prereg, supersession, ledger: newLedger, manifest: newManifest };
}

export function checkV3OnDisk() {
  const signed = read('preregistration.v3.approved.json');
  const inForce = read('preregistration.v3.in-force.json');
  const base = read('preregistration-v1-superseded.json');
  const table = read('frozen-table.v3.json');
  const manifest = read('manifest.json');
  const ledger = read('source-ledger.v3.json');
  const supersession = read('preregistration-v3-supersession.json');
  const draft = read('preregistration.v3.draft.json');
  const expected = approveV3({ draft, base, table, principal: signed.approval?.principal_id, label: signed.approval?.label, issuedAt: signed.approval?.issued_at });
  if (expected.preregistration_digest !== signed.preregistration_digest) throw new Error('V3_SIGNATURE_SCOPE_MISMATCH');
  if (signed.approval?.in_force !== false || inForce.approval?.in_force !== true ||
      signed.preregistration_digest !== inForce.preregistration_digest ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(inForce))) throw new Error('V3_APPROVAL_BINDING_MISMATCH');
  assertPreregistration(inForce);
  assertSupersession(supersession, base);
  if (supersession.replaced_by_expected_table_digest !== canonicalDigest(table)) throw new Error('V3_TABLE_BINDING_MISMATCH');
  const last = ledger.entries.at(-1);
  assertSourceLedger(ledger.entries, { cases_digest: last.cases_digest, expected_table_digest: canonicalDigest(table) });
  if (manifest.preregistration?.file !== 'preregistration.v3.in-force.json' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(inForce) ||
      manifest.superseded_preregistration?.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.supersession_digest !== supersession.supersession_digest ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger.last_anchor_digest !== last.anchor_digest) throw new Error('V3_MANIFEST_BINDING_MISMATCH');
  return { ok: true, preregistration_digest: preregistrationDigest(inForce), supersession_id: supersession.supersession_id, ledger_entries: ledger.entries.length };
}

function read(name) { return JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8')); }
function write(name, value) {
  fs.writeFileSync(path.join(DIR, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
}
export function sealOnDisk() {
  const result = sealV3({
    signed: read('preregistration.v3.approved.json'),
    draft: read('preregistration.v3.draft.json'),
    base: read('preregistration.json'),
    table: read('frozen-table.v3.json'),
    manifest: read('manifest.json'),
    ledger: read('source-ledger.json'),
  });
  // All new artefacts are written before the manifest switches to v3.
  write('preregistration.v3.in-force.json', result.prereg);
  write('preregistration-v1-superseded.json', read('preregistration.json'));
  write('preregistration-v3-supersession.json', result.supersession);
  write('source-ledger.v3.json', result.ledger);
  const next = path.join(DIR, 'manifest.v3.next.json');
  fs.writeFileSync(next, JSON.stringify(result.manifest, null, 1) + '\n', { flag: 'wx' });
  fs.renameSync(next, path.join(DIR, 'manifest.json'));
  return { preregistration_digest: result.prereg.preregistration_digest, supersession_id: result.supersession.supersession_id, in_force: true };
}
