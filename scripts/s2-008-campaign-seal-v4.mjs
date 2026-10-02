import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import {
  assertPreregistration, assertSourceLedger,
  preregistrationDigest,
} from '../src/lib/research/index.mjs';
import {
  createContentSupersession, assertContentSupersession,
} from '../src/lib/research/content-supersession.mjs';
import { approveV4, assertV4Pin, scientificBody } from './s2-008-campaign-approve.mjs';

const DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../corpus/s2-008-campaign');
const REASON = 'v4 replaces the model image content commitment while preserving the v3 trial list, frozen table and decision rule';

export function sealV4({ signed, draft, base, table, pin, manifest, ledger }) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || !signed.approval?.principal_id) {
    throw new Error('V4_NOT_APPROVED');
  }
  if (signed.approval.in_force !== false) throw new Error('V4_ALREADY_IN_FORCE');
  assertV4Pin(signed, pin);
  if (signed.preregistration_digest !== canonicalDigest(scientificBody(signed))) throw new Error('V4_DIGEST_MISMATCH');
  if (canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft))) throw new Error('V4_DRAFT_MISMATCH');
  if (manifest?.preregistration?.status !== 'IN_FORCE' ||
      manifest.preregistration.file !== 'preregistration.v3.in-force.json' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(base) ||
      base.preregistration_digest !== preregistrationDigest(base)) throw new Error('V4_BASE_MISMATCH');
  if (signed.expected_table_digest !== canonicalDigest(table) ||
      base.expected_table_digest !== canonicalDigest(table) ||
      manifest.frozen_table?.digest !== canonicalDigest(table)) throw new Error('V4_TABLE_MISMATCH');
  const expected = approveV4({
    draft, base, table, pin, principal: signed.approval.principal_id,
    label: signed.approval.label, issuedAt: signed.approval.issued_at,
  });
  if (expected.preregistration_digest !== signed.preregistration_digest) throw new Error('V4_SIGNATURE_SCOPE_MISMATCH');

  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertPreregistration(prereg);
  const supersession = createContentSupersession({ superseded: base, replacedBy: prereg, reason: REASON });
  assertContentSupersession(supersession, base, prereg);

  if (!Array.isArray(ledger?.entries) || ledger.entries.length === 0 ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1).anchor_digest) {
    throw new Error('V4_LEDGER_BASE_MISMATCH');
  }
  const tableDigest = canonicalDigest(table);
  const casesDigest = ledger.entries.at(-1).cases_digest;
  assertSourceLedger(ledger.entries, { cases_digest: casesDigest, expected_table_digest: tableDigest });
  // Source bytes and the frozen table did not move. The source ledger must not
  // grow a fictitious change entry; retain its already verified chain.
  const entries = ledger.entries;
  const newManifest = structuredClone(manifest);
  const v3History = Array.isArray(manifest.supersession_history)
    ? manifest.supersession_history
    : [manifest.supersession];
  if (!v3History.every((row) => row?.supersession_digest && row?.file)) throw new Error('V4_HISTORY_ABSENT');
  newManifest.supersession_history = [
    ...v3History,
    { file: 'preregistration-v4-supersession.json',
      supersession_id: supersession.supersession_id,
      supersession_digest: supersession.supersession_digest,
      reason: REASON },
  ];
  newManifest.preregistration = {
    file: 'preregistration.v4.in-force.json',
    preregistration_digest: signed.preregistration_digest,
    status: 'IN_FORCE', sealed_before_first_trial: true,
  };
  newManifest.superseded_preregistration = {
    file: 'preregistration-v3-superseded.json',
    preregistration_digest: base.preregistration_digest,
    status: 'SUPERSEDED', superseded_by: 'preregistration.v4.in-force.json',
  };
  newManifest.supersession = newManifest.supersession_history.at(-1);
  newManifest.frozen_table = { file: 'frozen-table.v3.json', digest: tableDigest };
  newManifest.source_ledger = structuredClone(manifest.source_ledger);
  return { prereg, supersession, ledger: { ...ledger, entries }, manifest: newManifest };
}

function read(name) { return JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8')); }
function readPin() { return JSON.parse(fs.readFileSync(path.resolve(DIR, '../../evidence/s2-008-campaign/model-image-pin-v4.json'), 'utf8')); }
function write(name, value) {
  fs.writeFileSync(path.join(DIR, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
}

export function checkV4OnDisk() {
  const signed = read('preregistration.v4.approved.json');
  const prereg = read('preregistration.v4.in-force.json');
  const base = read('preregistration-v3-superseded.json');
  const table = read('frozen-table.v3.json');
  const draft = read('preregistration.v4.draft.json');
  const manifest = read('manifest.json');
  const ledger = read('source-ledger.v3.json');
  const supersession = read('preregistration-v4-supersession.json');
  const pin = readPin();
  assertV4Pin(prereg, pin);
  const expected = approveV4({
    draft, base, table, pin, principal: signed.approval?.principal_id,
    label: signed.approval?.label, issuedAt: signed.approval?.issued_at,
  });
  if (signed.approval?.in_force !== false || prereg.approval?.in_force !== true ||
      expected.preregistration_digest !== signed.preregistration_digest ||
      signed.preregistration_digest !== prereg.preregistration_digest ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(prereg))) {
    throw new Error('V4_APPROVAL_BINDING_MISMATCH');
  }
  assertPreregistration(prereg);
  assertContentSupersession(supersession, base, prereg);
  const last = ledger.entries.at(-1);
  assertSourceLedger(ledger.entries, { cases_digest: last.cases_digest, expected_table_digest: canonicalDigest(table) });
  const activeV4 = manifest.preregistration?.file === 'preregistration.v4.in-force.json' &&
    manifest.preregistration.preregistration_digest === preregistrationDigest(prereg) &&
    manifest.superseded_preregistration?.preregistration_digest === preregistrationDigest(base) &&
    manifest.supersession?.supersession_digest === supersession.supersession_digest;
  const archivedV4 = manifest.supersession_history?.some((row) =>
    row.file === 'preregistration-v4-supersession.json' &&
    row.supersession_id === supersession.supersession_id &&
    row.supersession_digest === supersession.supersession_digest);
  if ((!activeV4 && !archivedV4) ||
      manifest.source_ledger?.last_anchor_digest !== last.anchor_digest ||
      manifest.source_ledger.entry_count !== ledger.entries.length ||
      manifest.frozen_table?.digest !== canonicalDigest(table)) throw new Error('V4_MANIFEST_BINDING_MISMATCH');
  return { ok: true, preregistration_digest: prereg.preregistration_digest, supersession_id: supersession.supersession_id, ledger_entries: ledger.entries.length };
}

export function sealOnDisk() {
  const result = sealV4({
    signed: read('preregistration.v4.approved.json'),
    draft: read('preregistration.v4.draft.json'),
    base: read('preregistration.v3.in-force.json'),
    table: read('frozen-table.v3.json'),
    pin: readPin(),
    manifest: read('manifest.json'),
    ledger: read('source-ledger.v3.json'),
  });
  write('preregistration.v4.in-force.json', result.prereg);
  write('preregistration-v3-superseded.json', read('preregistration.v3.in-force.json'));
  write('preregistration-v4-supersession.json', result.supersession);
  const next = path.join(DIR, 'manifest.v4.next.json');
  fs.writeFileSync(next, JSON.stringify(result.manifest, null, 1) + '\n', { flag: 'wx' });
  fs.renameSync(next, path.join(DIR, 'manifest.json'));
  return { preregistration_digest: result.prereg.preregistration_digest, supersession_id: result.supersession.supersession_id, in_force: true };
}
