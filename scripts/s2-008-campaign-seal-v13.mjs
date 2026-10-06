import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, assertSourceLedger, preregistrationDigest } from '../src/lib/research/index.mjs';
import { createContentSupersession, assertContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { approveV13, assertV13BaseBinding, assertV13PresealPin, assertV13PriorV12AReconciliation, readV13BaseInputs, readV13PriorV12AInputs } from './s2-008-campaign-v13-approval.mjs';
import { scientificBody } from './s2-008-campaign-approve.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, 'corpus/s2-008-campaign');
const EVIDENCE_DIR = path.join(ROOT, 'evidence/s2-008-campaign');
const OWNER = 'prn-s2007r-owner';
const REASON = 'v13 selects the owner-approved Ling model and exact Pi catalog registration while preserving frozen science, v12 financial closure and the independent per-run A/B token ceilings';
const read = (name) => JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8'));
const bytes = (name) => fs.readFileSync(path.join(DIR, name));
const readPin = (name) => JSON.parse(fs.readFileSync(path.join(EVIDENCE_DIR, name), 'utf8'));
const write = (name, value) => fs.writeFileSync(path.join(DIR, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o644 });

export function assertV13ManifestBinding({ prereg, base, manifest, supersession, table, ledger }) {
  const v12History = manifest?.supersession_history?.find((entry) =>
    entry.file === 'preregistration-v12-supersession.json' &&
    entry.supersession_id === 'spr-f547ffdb1b1ffaa2ce5764a8' &&
    entry.supersession_digest === '10ae574d3d6dc17ee6da958821545f34c5c0e8ad760e7a6fe843c8968bf4996f');
  if (!prereg || prereg.rule !== 's2-008-prereg-v13' ||
      prereg.approval?.in_force !== true ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      manifest?.preregistration?.file !== 'preregistration.v13.in-force.json' ||
      manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== prereg.preregistration_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v12-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.file !== 'preregistration-v13-supersession.json' ||
      manifest.supersession?.supersession_digest !== supersession?.supersession_digest ||
      manifest.supersession_history?.at(-1)?.supersession_digest !== supersession?.supersession_digest ||
      !v12History ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger?.entries?.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger?.entries?.at(-1)?.anchor_digest) {
    throw new Error('V13_MANIFEST_BINDING_MISMATCH');
  }
  assertContentSupersession(supersession, base, prereg);
  assertSourceLedger(ledger.entries, {
    cases_digest: ledger.entries.at(-1).cases_digest,
    expected_table_digest: canonicalDigest(table),
  });
  return { ok: true };
}

export function assertV13ApprovalBinding({ signed, prereg, expected }) {
  const expectedSealedApproval = { ...signed?.approval, in_force: true };
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' ||
      signed.approval?.principal_id !== OWNER || signed.approval?.label !== 'Daniil' ||
      signed.approval?.in_force !== false || prereg?.status !== 'APPROVED' ||
      prereg.approval?.in_force !== true ||
      canonicalDigest(expected?.approval ?? null) !== canonicalDigest(signed.approval ?? null) ||
      canonicalDigest(prereg.approval ?? null) !== canonicalDigest(expectedSealedApproval) ||
      signed.preregistration_digest !== preregistrationDigest(signed) ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      signed.preregistration_digest !== prereg.preregistration_digest ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(prereg))) {
    throw new Error('V13_APPROVAL_BINDING_MISMATCH');
  }
  return { ok: true };
}

export function sealV13({
  signed, draft, base, baseBytes, manifest, baseSupersession, baseSupersessionBytes,
  table, pin, restartInputs = readV13PriorV12AInputs(), ledger,
}) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || signed.approval?.principal_id !== OWNER ||
      signed.approval?.label !== 'Daniil') {
    throw new Error('V13_NOT_APPROVED');
  }
  if (signed.approval.in_force !== false) throw new Error('V13_ALREADY_IN_FORCE');
  if (signed.preregistration_digest !== preregistrationDigest(signed) ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft))) {
    throw new Error('V13_DRAFT_MISMATCH');
  }
  const lineage = assertV13BaseBinding({
    base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes: baseSupersessionBytes, table, ledger,
  });
  const prior = assertV13PriorV12AReconciliation(restartInputs);
  if (canonicalDigest(signed.v12_prior_execution_reconciliation) !== canonicalDigest(prior) ||
      signed.supersession?.superseded_digest !== lineage.baseDigest) {
    throw new Error('V13_PRIOR_BINDING_MISMATCH');
  }
  assertV13PresealPin({ pin, baseBytes, commitment: signed.executor?.model_image?.content_commitment });
  const expected = approveV13({
    draft, base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes: baseSupersessionBytes, table, ledger, pin, restartInputs,
    principal: signed.approval.principal_id, label: signed.approval.label,
    issuedAt: signed.approval.issued_at,
  });
  if (expected.preregistration_digest !== signed.preregistration_digest) {
    throw new Error('V13_SIGNATURE_SCOPE_MISMATCH');
  }
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertV13ApprovalBinding({ signed, prereg, expected });
  assertPreregistration(prereg);
  const supersession = createContentSupersession({ superseded: base, replacedBy: prereg, reason: REASON });
  assertContentSupersession(supersession, base, prereg);
  if (!Array.isArray(ledger?.entries) || ledger.entries.length === 0 ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1).anchor_digest) {
    throw new Error('V13_LEDGER_BASE_MISMATCH');
  }
  assertSourceLedger(ledger.entries, {
    cases_digest: ledger.entries.at(-1).cases_digest,
    expected_table_digest: canonicalDigest(table),
  });
  const history = manifest.supersession_history;
  if (!Array.isArray(history) || history.length === 0 ||
      history.at(-1)?.supersession_digest !== manifest.supersession?.supersession_digest) {
    throw new Error('V13_HISTORY_MISMATCH');
  }
  const nextManifest = structuredClone(manifest);
  nextManifest.supersession_history = [
    ...history,
    {
      file: 'preregistration-v13-supersession.json',
      supersession_id: supersession.supersession_id,
      supersession_digest: supersession.supersession_digest,
      reason: REASON,
    },
  ];
  nextManifest.supersession = nextManifest.supersession_history.at(-1);
  nextManifest.preregistration = {
    file: 'preregistration.v13.in-force.json',
    preregistration_digest: prereg.preregistration_digest,
    status: 'IN_FORCE', sealed_before_first_trial: true,
  };
  nextManifest.superseded_preregistration = {
    file: 'preregistration-v12-superseded.json',
    preregistration_digest: base.preregistration_digest,
    status: 'SUPERSEDED', superseded_by: 'preregistration.v13.in-force.json',
  };
  nextManifest.frozen_table = { file: 'frozen-table.v3.json', digest: canonicalDigest(table) };
  nextManifest.source_ledger = structuredClone(manifest.source_ledger);
  const result = { prereg, supersession, ledger: { ...ledger, entries: ledger.entries }, manifest: nextManifest };
  assertV13ManifestBinding({ prereg, base, manifest: nextManifest, supersession, table, ledger });
  return result;
}

export function sealV13OnDisk() {
  const inputs = readV13BaseInputs();
  const restartInputs = readV13PriorV12AInputs();
  const signed = read('preregistration.v13.approved.json');
  const draft = read('preregistration.v13.draft.json');
  const pin = readPin('model-image-pin-v13-preseal.json');
  const result = sealV13({
    signed, draft, ...inputs, baseSupersession: inputs.supersession,
    baseSupersessionBytes: inputs.supersessionBytes, pin, restartInputs,
    ledger: read('source-ledger.v3.json'),
  });
  write('preregistration.v13.in-force.json', result.prereg);
  fs.writeFileSync(path.join(DIR, 'preregistration-v12-superseded.json'), inputs.baseBytes, { flag: 'wx', mode: 0o644 });
  write('preregistration-v13-supersession.json', result.supersession);
  const temp = path.join(DIR, 'manifest.v13.next.json');
  fs.writeFileSync(temp, JSON.stringify(result.manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  fs.renameSync(temp, path.join(DIR, 'manifest.json'));
  return { in_force: true, preregistration_digest: result.prereg.preregistration_digest,
    supersession_id: result.supersession.supersession_id };
}

export function checkV13OnDisk() {
  const prereg = read('preregistration.v13.in-force.json');
  const signed = read('preregistration.v13.approved.json');
  const draft = read('preregistration.v13.draft.json');
  const baseInputs = readV13BaseInputs({ allowHistorical: true });
  const { base, manifest, table, ledger, supersession: baseSupersession, supersessionBytes: baseSupersessionBytes } = baseInputs;
  const baseCopy = bytes('preregistration-v12-superseded.json');
  const supersession = read('preregistration-v13-supersession.json');
  const presealPin = readPin('model-image-pin-v13-preseal.json');
  const finalPin = readPin('model-image-pin-v13.json');
  const restartInputs = readV13PriorV12AInputs();
  if (!baseCopy.equals(baseInputs.baseBytes)) throw new Error('V13_BASE_BYTES_NOT_PRESERVED');
  const approval = approveV13({
    draft, base, baseBytes: baseInputs.baseBytes, manifest,
    supersession: baseSupersession, supersessionBytes: baseSupersessionBytes,
    table, ledger, pin: presealPin, restartInputs,
    principal: signed.approval?.principal_id, label: signed.approval?.label,
    issuedAt: signed.approval?.issued_at,
  });
  if (approval.preregistration_digest !== signed.preregistration_digest) {
    throw new Error('V13_APPROVAL_BINDING_MISMATCH');
  }
  assertV13ApprovalBinding({ signed, prereg, expected: approval });
  const preseal = assertV13PresealPin({
    pin: presealPin, baseBytes: baseInputs.baseBytes, commitment: prereg.executor.model_image.content_commitment,
  });
  const final = assertV13PresealPin({
    pin: finalPin, baseBytes: bytes('preregistration.v13.in-force.json'),
    commitment: prereg.executor.model_image.content_commitment,
  });
  if (preseal.commitment !== final.commitment) throw new Error('V13_CONTENT_COMMITMENT_MOVED');
  assertV13ManifestBinding({ prereg, base, manifest: baseInputs.activeManifest, supersession, table, ledger });
  return { ok: true, preregistration_digest: prereg.preregistration_digest,
    supersession_id: supersession.supersession_id, content_commitment: final.commitment };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  process.stdout.write(JSON.stringify(process.argv.includes('--check') ? checkV13OnDisk() : sealV13OnDisk(), null, 2) + '\n');
}
