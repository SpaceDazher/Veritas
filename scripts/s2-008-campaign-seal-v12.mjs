import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, assertSourceLedger, preregistrationDigest } from '../src/lib/research/index.mjs';
import { createContentSupersession, assertContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { approveV12, assertV12BaseBinding, assertV12PresealPin, assertV12PriorExecutionEvidence, inspectV11PriorExecutionEvidence, readV12BaseInputs } from './s2-008-campaign-v12-approval.mjs';
import { scientificBody } from './s2-008-campaign-approve.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, 'corpus/s2-008-campaign');
const REASON = 'v12 is a distinct successor to the signed v11 preregistration with a fresh reservation expiry and image pin; frozen science, provider, model, package and per-run ceiling remain unchanged';
const read = (name) => JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8'));
const bytes = (name) => fs.readFileSync(path.join(DIR, name));
const readPin = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/s2-008-campaign', name), 'utf8'));
const write = (name, value) => fs.writeFileSync(path.join(DIR, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o644 });

export function assertV12ManifestBinding({ prereg, base, manifest, supersession, table, ledger }) {
  const v11History = manifest?.supersession_history?.find((entry) =>
    entry.file === 'preregistration-v11-supersession.json' &&
    entry.supersession_id === 'spr-6f5e296f15e53ae440c57ef5' &&
    entry.supersession_digest === '39d04daa7e700305740fb3597fe8ec4cfb3fde4bcffd834ad0130de3c7b4b713');
  if (!prereg || prereg.rule !== 's2-008-prereg-v12' ||
      prereg.approval?.in_force !== true ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      manifest?.preregistration?.file !== 'preregistration.v12.in-force.json' ||
      manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== prereg.preregistration_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v11-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.supersession_digest !== supersession?.supersession_digest ||
      manifest.supersession_history?.at(-1)?.supersession_digest !== supersession?.supersession_digest ||
      !v11History ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger?.entries?.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger?.entries?.at(-1)?.anchor_digest) {
    throw new Error('V12_MANIFEST_BINDING_MISMATCH');
  }
  assertContentSupersession(supersession, base, prereg);
  assertSourceLedger(ledger.entries, {
    cases_digest: ledger.entries.at(-1).cases_digest,
    expected_table_digest: canonicalDigest(table),
  });
  return { ok: true };
}

export function sealV12({
  signed, draft, base, baseBytes, manifest, baseSupersession, baseSupersessionBytes,
  table, pin, priorExecutionEvidence, ledger,
}) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || !signed.approval?.principal_id) {
    throw new Error('V12_NOT_APPROVED');
  }
  if (signed.approval.in_force !== false) throw new Error('V12_ALREADY_IN_FORCE');
  if (signed.preregistration_digest !== preregistrationDigest(signed) ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft))) {
    throw new Error('V12_DRAFT_MISMATCH');
  }
  const lineage = assertV12BaseBinding({
    base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes: baseSupersessionBytes, table,
  });
  assertV12PresealPin({ pin, baseBytes, commitment: signed.executor?.model_image?.content_commitment });
  const prior = assertV12PriorExecutionEvidence(priorExecutionEvidence);
  if (signed.v11_prior_execution_evidence?.scan_digest !== canonicalDigest(prior) ||
      signed.v11_prior_execution_evidence?.base_preregistration_digest !== lineage.baseDigest) {
    throw new Error('V12_PRIOR_EVIDENCE_BINDING_MISMATCH');
  }
  const expected = approveV12({
    draft, base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes: baseSupersessionBytes, table, pin,
    priorExecutionEvidence: prior, principal: signed.approval.principal_id,
    label: signed.approval.label, issuedAt: signed.approval.issued_at,
  });
  if (expected.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expected.approval) !== canonicalDigest(signed.approval)) {
    throw new Error('V12_SIGNATURE_SCOPE_MISMATCH');
  }
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertPreregistration(prereg);
  const supersession = createContentSupersession({ superseded: base, replacedBy: prereg, reason: REASON });
  assertContentSupersession(supersession, base, prereg);
  if (!Array.isArray(ledger?.entries) || ledger.entries.length === 0 ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1).anchor_digest) {
    throw new Error('V12_LEDGER_BASE_MISMATCH');
  }
  assertSourceLedger(ledger.entries, {
    cases_digest: ledger.entries.at(-1).cases_digest,
    expected_table_digest: canonicalDigest(table),
  });
  const history = manifest.supersession_history;
  if (!Array.isArray(history) || history.length === 0 ||
      history.at(-1)?.supersession_digest !== manifest.supersession?.supersession_digest) {
    throw new Error('V12_HISTORY_MISMATCH');
  }
  const nextManifest = structuredClone(manifest);
  nextManifest.supersession_history = [
    ...history,
    {
      file: 'preregistration-v12-supersession.json',
      supersession_id: supersession.supersession_id,
      supersession_digest: supersession.supersession_digest,
      reason: REASON,
    },
  ];
  nextManifest.supersession = nextManifest.supersession_history.at(-1);
  nextManifest.preregistration = {
    file: 'preregistration.v12.in-force.json',
    preregistration_digest: prereg.preregistration_digest,
    status: 'IN_FORCE', sealed_before_first_trial: true,
  };
  nextManifest.superseded_preregistration = {
    file: 'preregistration-v11-superseded.json',
    preregistration_digest: base.preregistration_digest,
    status: 'SUPERSEDED', superseded_by: 'preregistration.v12.in-force.json',
  };
  nextManifest.frozen_table = { file: 'frozen-table.v3.json', digest: canonicalDigest(table) };
  nextManifest.source_ledger = structuredClone(manifest.source_ledger);
  return { prereg, supersession, ledger: { ...ledger, entries: ledger.entries }, manifest: nextManifest };
}

export function sealV12OnDisk() {
  const inputs = readV12BaseInputs();
  const priorExecutionEvidence = inspectV11PriorExecutionEvidence();
  const signed = read('preregistration.v12.approved.json');
  const draft = read('preregistration.v12.draft.json');
  const pin = readPin('model-image-pin-v12-preseal.json');
  const result = sealV12({
    signed, draft, ...inputs, baseSupersession: inputs.supersession,
    baseSupersessionBytes: inputs.supersessionBytes, pin, priorExecutionEvidence,
    ledger: read('source-ledger.v3.json'),
  });
  write('preregistration.v12.in-force.json', result.prereg);
  fs.writeFileSync(path.join(DIR, 'preregistration-v11-superseded.json'), inputs.baseBytes, { flag: 'wx', mode: 0o644 });
  write('preregistration-v12-supersession.json', result.supersession);
  const temp = path.join(DIR, 'manifest.v12.next.json');
  fs.writeFileSync(temp, JSON.stringify(result.manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  fs.renameSync(temp, path.join(DIR, 'manifest.json'));
  return { in_force: true, preregistration_digest: result.prereg.preregistration_digest,
    supersession_id: result.supersession.supersession_id };
}

export function checkV12OnDisk() {
  const prereg = read('preregistration.v12.in-force.json');
  const signed = read('preregistration.v12.approved.json');
  const draft = read('preregistration.v12.draft.json');
  const base = read('preregistration-v11-superseded.json');
  const baseBytes = bytes('preregistration-v11-superseded.json');
  const table = read('frozen-table.v3.json');
  const ledger = read('source-ledger.v3.json');
  const manifest = read('manifest.json');
  const supersession = read('preregistration-v12-supersession.json');
  const baseSupersession = read('preregistration-v11-supersession.json');
  const baseSupersessionBytes = bytes('preregistration-v11-supersession.json');
  const presealPin = readPin('model-image-pin-v12-preseal.json');
  const finalPin = readPin('model-image-pin-v12.json');
  const priorExecutionEvidence = inspectV11PriorExecutionEvidence();
  const baseManifest = {
    ...manifest,
    preregistration: { file: 'preregistration.v11.in-force.json', status: 'IN_FORCE', preregistration_digest: base.preregistration_digest },
    supersession: manifest.supersession_history.find((entry) => entry.file === 'preregistration-v11-supersession.json'),
    supersession_history: manifest.supersession_history.slice(0, -1),
    superseded_preregistration: {
      file: 'preregistration-v10-superseded.json',
      preregistration_digest: '580b3fadd655d396662efe21757f0473b830211ef42ae93f230df0445379ae22',
      status: 'SUPERSEDED', superseded_by: 'preregistration.v11.in-force.json',
    },
  };
  const approval = approveV12({
    draft, base, baseBytes, manifest: baseManifest, supersession: baseSupersession,
    supersessionBytes: baseSupersessionBytes, table, pin: presealPin, priorExecutionEvidence,
    principal: signed.approval?.principal_id, label: signed.approval?.label,
    issuedAt: signed.approval?.issued_at,
  });
  if (signed.approval?.in_force !== false || prereg.approval?.in_force !== true ||
      approval.preregistration_digest !== signed.preregistration_digest ||
      signed.preregistration_digest !== prereg.preregistration_digest ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(prereg))) {
    throw new Error('V12_APPROVAL_BINDING_MISMATCH');
  }
  const preseal = assertV12PresealPin({
    pin: presealPin, baseBytes, commitment: prereg.executor.model_image.content_commitment,
  });
  const final = assertV12PresealPin({
    pin: finalPin, baseBytes: bytes('preregistration.v12.in-force.json'),
    commitment: prereg.executor.model_image.content_commitment,
  });
  if (preseal.commitment !== final.commitment) throw new Error('V12_CONTENT_COMMITMENT_MOVED');
  assertV12ManifestBinding({ prereg, base, manifest, supersession, table, ledger });
  return { ok: true, preregistration_digest: prereg.preregistration_digest,
    supersession_id: supersession.supersession_id, content_commitment: final.commitment };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  process.stdout.write(JSON.stringify(process.argv.includes('--check') ? checkV12OnDisk() : sealV12OnDisk(), null, 2) + '\n');
}
