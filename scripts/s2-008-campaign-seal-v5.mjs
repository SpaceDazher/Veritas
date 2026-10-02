import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, assertSourceLedger, preregistrationDigest } from '../src/lib/research/index.mjs';
import { createContentSupersession, assertContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { approveV5, assertV5PresealPin } from './s2-008-campaign-v5-approval.mjs';
import { scientificBody } from './s2-008-campaign-approve.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, 'corpus/s2-008-campaign');
const REASON = 'v5 replaces the model image with a shared remaining-token cap across seeds while preserving the frozen science and the per-run ceiling';
const read = (name) => JSON.parse(fs.readFileSync(path.join(DIR, name)));
const bytes = (name) => fs.readFileSync(path.join(DIR, name));
const readPin = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/s2-008-campaign', name)));
const write = (name, value) => fs.writeFileSync(path.join(DIR, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });

export function sealV5({ signed, draft, base, baseBytes, table, pin, manifest, ledger }) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || !signed.approval?.principal_id) {
    throw new Error('V5_NOT_APPROVED');
  }
  if (signed.approval.in_force !== false) throw new Error('V5_ALREADY_IN_FORCE');
  if (signed.preregistration_digest !== preregistrationDigest(signed)) throw new Error('V5_DIGEST_MISMATCH');
  if (canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft))) throw new Error('V5_DRAFT_MISMATCH');
  if (manifest?.preregistration?.status !== 'IN_FORCE' ||
      manifest.preregistration.file !== 'preregistration.v4.in-force.json' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(base) ||
      base.preregistration_digest !== preregistrationDigest(base)) throw new Error('V5_BASE_MISMATCH');
  if (signed.expected_table_digest !== canonicalDigest(table) ||
      base.expected_table_digest !== canonicalDigest(table) ||
      manifest.frozen_table?.digest !== canonicalDigest(table)) throw new Error('V5_TABLE_MISMATCH');
  assertV5PresealPin({ pin, baseBytes, commitment: signed.executor?.model_image?.content_commitment });
  const expected = approveV5({
    draft, base, baseBytes, table, pin,
    principal: signed.approval.principal_id, label: signed.approval.label,
    issuedAt: signed.approval.issued_at,
  });
  if (expected.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expected.approval) !== canonicalDigest(signed.approval)) {
    throw new Error('V5_SIGNATURE_SCOPE_MISMATCH');
  }
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertPreregistration(prereg);
  const supersession = createContentSupersession({ superseded: base, replacedBy: prereg, reason: REASON });
  assertContentSupersession(supersession, base, prereg);
  if (!Array.isArray(ledger?.entries) || ledger.entries.length === 0 ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1).anchor_digest) {
    throw new Error('V5_LEDGER_BASE_MISMATCH');
  }
  const tableDigest = canonicalDigest(table);
  assertSourceLedger(ledger.entries, {
    cases_digest: ledger.entries.at(-1).cases_digest,
    expected_table_digest: tableDigest,
  });
  const history = manifest.supersession_history;
  if (!Array.isArray(history) || history.length === 0 ||
      history.at(-1)?.supersession_digest !== manifest.supersession?.supersession_digest) {
    throw new Error('V5_HISTORY_MISMATCH');
  }
  const nextManifest = structuredClone(manifest);
  nextManifest.supersession_history = [
    ...history,
    { file: 'preregistration-v5-supersession.json',
      supersession_id: supersession.supersession_id,
      supersession_digest: supersession.supersession_digest,
      reason: REASON },
  ];
  nextManifest.supersession = nextManifest.supersession_history.at(-1);
  nextManifest.preregistration = {
    file: 'preregistration.v5.in-force.json',
    preregistration_digest: prereg.preregistration_digest,
    status: 'IN_FORCE', sealed_before_first_trial: true,
  };
  nextManifest.superseded_preregistration = {
    file: 'preregistration-v4-superseded.json',
    preregistration_digest: base.preregistration_digest,
    status: 'SUPERSEDED', superseded_by: 'preregistration.v5.in-force.json',
  };
  nextManifest.frozen_table = { file: 'frozen-table.v3.json', digest: tableDigest };
  nextManifest.source_ledger = structuredClone(manifest.source_ledger);
  return { prereg, supersession, ledger: { ...ledger, entries: ledger.entries }, manifest: nextManifest };
}

export function sealV5OnDisk() {
  const result = sealV5({
    signed: read('preregistration.v5.approved.json'),
    draft: read('preregistration.v5.draft.json'),
    base: read('preregistration.v4.in-force.json'),
    baseBytes: bytes('preregistration.v4.in-force.json'),
    table: read('frozen-table.v3.json'),
    pin: readPin('model-image-pin-v5-preseal.json'),
    manifest: read('manifest.json'),
    ledger: read('source-ledger.v3.json'),
  });
  write('preregistration.v5.in-force.json', result.prereg);
  write('preregistration-v4-superseded.json', read('preregistration.v4.in-force.json'));
  write('preregistration-v5-supersession.json', result.supersession);
  const temp = path.join(DIR, 'manifest.v5.next.json');
  fs.writeFileSync(temp, JSON.stringify(result.manifest, null, 2) + '\n', { flag: 'wx' });
  fs.renameSync(temp, path.join(DIR, 'manifest.json'));
  return { in_force: true, preregistration_digest: result.prereg.preregistration_digest,
    supersession_id: result.supersession.supersession_id };
}

export function checkV5OnDisk() {
  const prereg = read('preregistration.v5.in-force.json');
  const signed = read('preregistration.v5.approved.json');
  const draft = read('preregistration.v5.draft.json');
  const base = read('preregistration-v4-superseded.json');
  const baseBytes = bytes('preregistration-v4-superseded.json');
  const table = read('frozen-table.v3.json');
  const ledger = read('source-ledger.v3.json');
  const manifest = read('manifest.json');
  const supersession = read('preregistration-v5-supersession.json');
  const presealPin = readPin('model-image-pin-v5-preseal.json');
  const finalPin = readPin('model-image-pin-v5.json');
  const expected = approveV5({
    draft, base, baseBytes, table, pin: presealPin,
    principal: signed.approval?.principal_id, label: signed.approval?.label,
    issuedAt: signed.approval?.issued_at,
  });
  if (signed.approval?.in_force !== false || prereg.approval?.in_force !== true ||
      expected.preregistration_digest !== signed.preregistration_digest ||
      signed.preregistration_digest !== prereg.preregistration_digest ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(prereg))) {
    throw new Error('V5_APPROVAL_BINDING_MISMATCH');
  }
  assertPreregistration(prereg);
  assertContentSupersession(supersession, base, prereg);
  const preseal = assertV5PresealPin({
    pin: presealPin, baseBytes, commitment: prereg.executor.model_image.content_commitment,
  });
  const final = assertV5PresealPin({
    pin: finalPin, baseBytes: bytes('preregistration.v5.in-force.json'),
    commitment: prereg.executor.model_image.content_commitment,
  });
  if (preseal.commitment !== final.commitment) throw new Error('V5_CONTENT_COMMITMENT_MOVED');
  assertSourceLedger(ledger.entries, {
    cases_digest: ledger.entries.at(-1).cases_digest, expected_table_digest: canonicalDigest(table),
  });
  if (manifest.preregistration?.file !== 'preregistration.v5.in-force.json' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(prereg) ||
      manifest.superseded_preregistration?.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.supersession_digest !== supersession.supersession_digest ||
      manifest.supersession_history?.at(-1)?.supersession_digest !== supersession.supersession_digest ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1).anchor_digest ||
      manifest.source_ledger.entry_count !== ledger.entries.length ||
      manifest.frozen_table?.digest !== canonicalDigest(table)) {
    throw new Error('V5_MANIFEST_BINDING_MISMATCH');
  }
  return { ok: true, preregistration_digest: prereg.preregistration_digest,
    supersession_id: supersession.supersession_id, content_commitment: final.commitment };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  console.log(JSON.stringify(process.argv.includes('--check') ? checkV5OnDisk() : sealV5OnDisk(), null, 2));
}
