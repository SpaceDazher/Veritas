import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, assertSourceLedger, preregistrationDigest } from '../src/lib/research/index.mjs';
import { createContentSupersession, assertContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { approveV8, assertV8PresealPin, readV8MeasurementOnDisk } from './s2-008-campaign-v8-approval.mjs';
import { scientificBody } from './s2-008-campaign-approve.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, 'corpus/s2-008-campaign');
const REASON = 'v8 replaces the executor with OpenRouter stealth/space-bunny-alpha while preserving frozen science and the 5,000,000-token ceiling per A/B run';
const read = (name) => JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8'));
const bytes = (name) => fs.readFileSync(path.join(DIR, name));
const readPin = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/s2-008-campaign', name), 'utf8'));
const write = (name, value) => fs.writeFileSync(path.join(DIR, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o644 });

export function assertV8ManifestBinding({ prereg, base, manifest, supersession, table, ledger }) {
  if (prereg?.rule !== 's2-008-prereg-v8' || prereg.approval?.in_force !== true ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      manifest?.preregistration?.file !== 'preregistration.v8.in-force.json' ||
      manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== prereg.preregistration_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v7-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.supersession_digest !== supersession?.supersession_digest ||
      manifest.supersession_history?.at(-1)?.supersession_digest !== supersession?.supersession_digest ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger?.entries?.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger?.entries?.at(-1)?.anchor_digest) {
    throw new Error('V8_MANIFEST_BINDING_MISMATCH');
  }
  assertContentSupersession(supersession, base, prereg);
  assertSourceLedger(ledger.entries, {
    cases_digest: ledger.entries.at(-1).cases_digest,
    expected_table_digest: canonicalDigest(table),
  });
  return { ok: true };
}

export function sealV8({ signed, draft, base, baseBytes, table, pin, measurement, manifest, ledger }) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || !signed.approval?.principal_id) {
    throw new Error('V8_NOT_APPROVED');
  }
  if (signed.approval.in_force !== false) throw new Error('V8_ALREADY_IN_FORCE');
  if (signed.preregistration_digest !== preregistrationDigest(signed)) throw new Error('V8_DIGEST_MISMATCH');
  if (canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft))) throw new Error('V8_DRAFT_MISMATCH');
  if (manifest?.preregistration?.status !== 'IN_FORCE' ||
      manifest.preregistration.file !== 'preregistration.v7.in-force.json' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(base) ||
      base.preregistration_digest !== preregistrationDigest(base)) throw new Error('V8_BASE_MISMATCH');
  if (signed.expected_table_digest !== canonicalDigest(table) ||
      base.expected_table_digest !== canonicalDigest(table) ||
      manifest.frozen_table?.digest !== canonicalDigest(table)) throw new Error('V8_TABLE_MISMATCH');
  assertV8PresealPin({ pin, baseBytes, commitment: signed.executor?.model_image?.content_commitment });
  const expected = approveV8({
    draft, base, baseBytes, table, pin, measurement,
    principal: signed.approval.principal_id, label: signed.approval.label,
    issuedAt: signed.approval.issued_at,
  });
  if (expected.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expected.approval) !== canonicalDigest(signed.approval)) {
    throw new Error('V8_SIGNATURE_SCOPE_MISMATCH');
  }
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertPreregistration(prereg);
  const supersession = createContentSupersession({ superseded: base, replacedBy: prereg, reason: REASON });
  assertContentSupersession(supersession, base, prereg);
  if (!Array.isArray(ledger?.entries) || ledger.entries.length === 0 ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1).anchor_digest) {
    throw new Error('V8_LEDGER_BASE_MISMATCH');
  }
  const tableDigest = canonicalDigest(table);
  assertSourceLedger(ledger.entries, {
    cases_digest: ledger.entries.at(-1).cases_digest,
    expected_table_digest: tableDigest,
  });
  const history = manifest.supersession_history;
  if (!Array.isArray(history) || history.length === 0 ||
      history.at(-1)?.supersession_digest !== manifest.supersession?.supersession_digest) {
    throw new Error('V8_HISTORY_MISMATCH');
  }
  const nextManifest = structuredClone(manifest);
  nextManifest.supersession_history = [
    ...history,
    {
      file: 'preregistration-v8-supersession.json',
      supersession_id: supersession.supersession_id,
      supersession_digest: supersession.supersession_digest,
      reason: REASON,
    },
  ];
  nextManifest.supersession = nextManifest.supersession_history.at(-1);
  nextManifest.preregistration = {
    file: 'preregistration.v8.in-force.json',
    preregistration_digest: prereg.preregistration_digest,
    status: 'IN_FORCE', sealed_before_first_trial: true,
  };
  nextManifest.superseded_preregistration = {
    file: 'preregistration-v7-superseded.json',
    preregistration_digest: base.preregistration_digest,
    status: 'SUPERSEDED', superseded_by: 'preregistration.v8.in-force.json',
  };
  nextManifest.frozen_table = { file: 'frozen-table.v3.json', digest: tableDigest };
  nextManifest.source_ledger = structuredClone(manifest.source_ledger);
  return { prereg, supersession, ledger: { ...ledger, entries: ledger.entries }, manifest: nextManifest };
}

export function sealV8OnDisk() {
  const result = sealV8({
    signed: read('preregistration.v8.approved.json'),
    draft: read('preregistration.v8.draft.json'),
    measurement: readV8MeasurementOnDisk(),
    base: read('preregistration.v7.in-force.json'),
    baseBytes: bytes('preregistration.v7.in-force.json'),
    table: read('frozen-table.v3.json'),
    pin: readPin('model-image-pin-v8-preseal.json'),
    manifest: read('manifest.json'),
    ledger: read('source-ledger.v3.json'),
  });
  write('preregistration.v8.in-force.json', result.prereg);
  write('preregistration-v7-superseded.json', read('preregistration.v7.in-force.json'));
  write('preregistration-v8-supersession.json', result.supersession);
  const temp = path.join(DIR, 'manifest.v8.next.json');
  fs.writeFileSync(temp, JSON.stringify(result.manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  fs.renameSync(temp, path.join(DIR, 'manifest.json'));
  return {
    in_force: true,
    preregistration_digest: result.prereg.preregistration_digest,
    supersession_id: result.supersession.supersession_id,
  };
}

export function checkV8OnDisk() {
  const prereg = read('preregistration.v8.in-force.json');
  const signed = read('preregistration.v8.approved.json');
  const draft = read('preregistration.v8.draft.json');
  const base = read('preregistration-v7-superseded.json');
  const baseBytes = bytes('preregistration-v7-superseded.json');
  const table = read('frozen-table.v3.json');
  const ledger = read('source-ledger.v3.json');
  const manifest = read('manifest.json');
  const supersession = read('preregistration-v8-supersession.json');
  const presealPin = readPin('model-image-pin-v8-preseal.json');
  const finalPin = readPin('model-image-pin-v8.json');
  const expected = approveV8({
    draft, base, baseBytes, table, pin: presealPin, measurement: readV8MeasurementOnDisk({requireTrace:false}),
    principal: signed.approval?.principal_id, label: signed.approval?.label,
    issuedAt: signed.approval?.issued_at,
  });
  if (signed.approval?.in_force !== false || prereg.approval?.in_force !== true ||
      expected.preregistration_digest !== signed.preregistration_digest ||
      signed.preregistration_digest !== prereg.preregistration_digest ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(prereg))) {
    throw new Error('V8_APPROVAL_BINDING_MISMATCH');
  }
  assertPreregistration(prereg);
  assertContentSupersession(supersession, base, prereg);
  const preseal = assertV8PresealPin({
    pin: presealPin, baseBytes, commitment: prereg.executor.model_image.content_commitment,
  });
  const final = assertV8PresealPin({
    pin: finalPin, baseBytes: bytes('preregistration.v8.in-force.json'),
    commitment: prereg.executor.model_image.content_commitment,
  });
  if (preseal.commitment !== final.commitment) throw new Error('V8_CONTENT_COMMITMENT_MOVED');
  assertSourceLedger(ledger.entries, {
    cases_digest: ledger.entries.at(-1).cases_digest,
    expected_table_digest: canonicalDigest(table),
  });
  if (manifest.preregistration?.file !== 'preregistration.v8.in-force.json' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(prereg) ||
      manifest.superseded_preregistration?.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.supersession_digest !== supersession.supersession_digest ||
      manifest.supersession_history?.at(-1)?.supersession_digest !== supersession.supersession_digest ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1).anchor_digest ||
      manifest.source_ledger.entry_count !== ledger.entries.length ||
      manifest.frozen_table?.digest !== canonicalDigest(table)) {
    throw new Error('V8_MANIFEST_BINDING_MISMATCH');
  }
  return {
    ok: true, preregistration_digest: prereg.preregistration_digest,
    supersession_id: supersession.supersession_id, content_commitment: final.commitment,
  };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  console.log(JSON.stringify(process.argv.includes('--check') ? checkV8OnDisk() : sealV8OnDisk(), null, 2));
}
