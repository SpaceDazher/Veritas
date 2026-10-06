import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, assertSourceLedger, preregistrationDigest } from '../src/lib/research/index.mjs';
import { createContentSupersession, assertContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { scientificBody } from './s2-008-campaign-approve.mjs';
import { approveV14, assertV14BaseBinding, assertV14PresealPin, assertV14RestartReconciliation,
  readV14BaseInputs, readV14RestartInputs } from './s2-008-campaign-v14-approval.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, 'corpus/s2-008-campaign');
const EVIDENCE = path.join(ROOT, 'evidence/s2-008-campaign');
const OWNER = 'prn-s2007r-owner';
const REASON = 'v14 binds the signed 60-second model call-start interval and explicit credential source after the v13 upstream 429, with frozen science and independent A/B ceilings preserved.';
const read = (name) => JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8'));
const bytes = (name) => fs.readFileSync(path.join(DIR, name));
const pin = (name) => JSON.parse(fs.readFileSync(path.join(EVIDENCE, name), 'utf8'));
const write = (name, value) => fs.writeFileSync(path.join(DIR, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o644 });

export function assertV14ApprovalBinding({ signed, prereg, expected }) {
  const signedApproval = { status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: OWNER, label: 'Daniil',
    issued_at: signed?.approval?.issued_at,
    signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
    in_force: false,
    becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v14 records this digest and supersession in the corpus manifest' };
  const sealedApproval = { ...signedApproval, in_force: true };
  if (!signed?.approval || Object.keys(signed.approval).sort().join(',') !== Object.keys(signedApproval).sort().join(',') ||
      !prereg?.approval || Object.keys(prereg.approval).sort().join(',') !== Object.keys(sealedApproval).sort().join(',') ||
      canonicalDigest(signed.approval) !== canonicalDigest(signedApproval) ||
      canonicalDigest(expected?.approval ?? null) !== canonicalDigest(signedApproval) ||
      canonicalDigest(prereg.approval) !== canonicalDigest(sealedApproval) ||
      signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || signed.approval?.principal_id !== OWNER ||
      signed.approval?.label !== 'Daniil' || signed.approval?.in_force !== false ||
      prereg?.status !== 'APPROVED' || prereg.approval?.in_force !== true ||
      canonicalDigest(prereg.approval ?? null) !== canonicalDigest(sealedApproval) ||
      signed.preregistration_digest !== preregistrationDigest(signed) ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      signed.preregistration_digest !== prereg.preregistration_digest ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(prereg))) {
    throw new Error('V14_APPROVAL_BINDING_MISMATCH');
  }
  return { ok: true };
}

export function assertV14ManifestBinding({ prereg, base, baseSupersession, manifest, supersession, table, ledger }) {
  const history = manifest?.supersession_history;
  const priorV13 = Array.isArray(history) ? history.find((entry) =>
    entry.file === 'preregistration-v13-supersession.json' &&
    typeof baseSupersession?.supersession_digest === 'string' &&
    entry.supersession_digest === baseSupersession.supersession_digest) : null;
  if (!prereg || prereg.rule !== 's2-008-prereg-v14' || prereg.approval?.in_force !== true ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      manifest?.preregistration?.file !== 'preregistration.v14.in-force.json' ||
      manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== prereg.preregistration_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v13-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.file !== 'preregistration-v14-supersession.json' ||
      manifest.supersession?.supersession_digest !== supersession?.supersession_digest ||
      history?.at(-1)?.file !== 'preregistration-v14-supersession.json' ||
      history.at(-1).supersession_digest !== supersession?.supersession_digest || !priorV13 ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger?.entries?.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger?.entries?.at(-1)?.anchor_digest) {
    throw new Error('V14_MANIFEST_BINDING_MISMATCH');
  }
  assertContentSupersession(supersession, base, prereg);
  assertSourceLedger(ledger.entries, { cases_digest: ledger.entries.at(-1)?.cases_digest,
    expected_table_digest: canonicalDigest(table) });
  return { ok: true };
}

export function sealV14({ signed, draft, base, baseBytes, manifest, baseSupersession, baseSupersessionBytes,
  table, pin: presealPin, restartInputs = readV14RestartInputs(), ledger }) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || signed.approval?.principal_id !== OWNER ||
      signed.approval?.label !== 'Daniil') throw new Error('V14_NOT_APPROVED');
  if (signed.approval.in_force !== false) throw new Error('V14_ALREADY_IN_FORCE');
  if (signed.preregistration_digest !== preregistrationDigest(signed) ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft))) throw new Error('V14_DRAFT_MISMATCH');

  const lineage = assertV14BaseBinding({ base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes: baseSupersessionBytes, table, ledger });
  const prior = assertV14RestartReconciliation(base, restartInputs);
  if (canonicalDigest(signed.v13_restart_reconciliation) !== canonicalDigest(prior) ||
      signed.supersession?.superseded_digest !== lineage.baseDigest) throw new Error('V14_PRIOR_BINDING_MISMATCH');
  assertV14PresealPin({ pin: presealPin, baseBytes, commitment: signed.executor?.model_image?.content_commitment });
  const expected = approveV14({ draft, base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes: baseSupersessionBytes, table, ledger, pin: presealPin, restartInputs,
    principal: signed.approval.principal_id, label: signed.approval.label, issuedAt: signed.approval.issued_at });
  if (expected.preregistration_digest !== signed.preregistration_digest) throw new Error('V14_SIGNATURE_SCOPE_MISMATCH');

  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertV14ApprovalBinding({ signed, prereg, expected });
  assertPreregistration(prereg);
  const supersession = createContentSupersession({ superseded: base, replacedBy: prereg, reason: REASON });
  assertContentSupersession(supersession, base, prereg);
  if (!Array.isArray(ledger?.entries) || ledger.entries.length === 0 ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1).anchor_digest) {
    throw new Error('V14_LEDGER_BASE_MISMATCH');
  }
  assertSourceLedger(ledger.entries, { cases_digest: ledger.entries.at(-1).cases_digest,
    expected_table_digest: canonicalDigest(table) });
  const history = manifest.supersession_history;
  if (!Array.isArray(history) || history.at(-1)?.supersession_digest !== manifest.supersession?.supersession_digest) {
    throw new Error('V14_HISTORY_MISMATCH');
  }
  const nextManifest = structuredClone(manifest);
  nextManifest.supersession_history = [...history, {
    file: 'preregistration-v14-supersession.json',
    supersession_id: supersession.supersession_id,
    supersession_digest: supersession.supersession_digest,
    reason: REASON,
  }];
  nextManifest.supersession = nextManifest.supersession_history.at(-1);
  nextManifest.preregistration = { file: 'preregistration.v14.in-force.json',
    preregistration_digest: prereg.preregistration_digest, status: 'IN_FORCE', sealed_before_first_trial: true };
  nextManifest.superseded_preregistration = { file: 'preregistration-v13-superseded.json',
    preregistration_digest: base.preregistration_digest, status: 'SUPERSEDED',
    superseded_by: 'preregistration.v14.in-force.json' };
  nextManifest.frozen_table = { file: 'frozen-table.v3.json', digest: canonicalDigest(table) };
  nextManifest.source_ledger = structuredClone(manifest.source_ledger);
  const result = { prereg, supersession, ledger: { ...ledger, entries: ledger.entries }, manifest: nextManifest };
  assertV14ManifestBinding({ prereg, base, baseSupersession, manifest: nextManifest, supersession, table, ledger });
  return result;
}

export const V14_SEAL_TARGETS = Object.freeze(['preregistration.v14.in-force.json',
  'preregistration-v13-superseded.json', 'preregistration-v14-supersession.json', 'manifest.v14.next.json']);

export function assertV14SealTargetsAbsent(dir = DIR) {
  const targets = V14_SEAL_TARGETS;
  for (const name of targets) {
    try { fs.lstatSync(path.join(dir, name)); }
    catch (error) { if (error?.code === 'ENOENT') continue; throw error; }
    throw new Error('V14_SEAL_TARGET_EXISTS');
  }
  return true;
}

export function sealV14OnDisk() {
  assertV14SealTargetsAbsent();
  const inputs = readV14BaseInputs(), restartInputs = readV14RestartInputs();
  const result = sealV14({ signed: read('preregistration.v14.approved.json'),
    draft: read('preregistration.v14.draft.json'), ...inputs,
    baseSupersession: inputs.supersession, baseSupersessionBytes: inputs.supersessionBytes,
    pin: pin('model-image-pin-v14-preseal.json'), restartInputs, ledger: read('source-ledger.v3.json') });
  write('preregistration.v14.in-force.json', result.prereg);
  fs.writeFileSync(path.join(DIR, 'preregistration-v13-superseded.json'), inputs.baseBytes, { flag: 'wx', mode: 0o644 });
  write('preregistration-v14-supersession.json', result.supersession);
  const temp = path.join(DIR, 'manifest.v14.next.json');
  fs.writeFileSync(temp, JSON.stringify(result.manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  fs.renameSync(temp, path.join(DIR, 'manifest.json'));
  return { in_force: true, preregistration_digest: result.prereg.preregistration_digest,
    supersession_id: result.supersession.supersession_id };
}

export function checkV14OnDisk() {
  const prereg = read('preregistration.v14.in-force.json'), signed = read('preregistration.v14.approved.json');
  const draft = read('preregistration.v14.draft.json'), baseInputs = readV14BaseInputs({ allowHistorical: true });
  const { base, baseBytes, activeManifest, table, ledger } = baseInputs;
  const baseCopy = bytes('preregistration-v13-superseded.json');
  const supersession = read('preregistration-v14-supersession.json');
  const presealPin = pin('model-image-pin-v14-preseal.json'), finalPin = pin('model-image-pin-v14.json');
  const restartInputs = readV14RestartInputs();
  if (!baseCopy.equals(baseBytes)) throw new Error('V14_BASE_BYTES_NOT_PRESERVED');
  const expected = approveV14({ draft, base, baseBytes, manifest: baseInputs.manifest,
    supersession: baseInputs.supersession, supersessionBytes: baseInputs.supersessionBytes, table, ledger,
    pin: presealPin, restartInputs, principal: signed.approval?.principal_id,
    label: signed.approval?.label, issuedAt: signed.approval?.issued_at });
  assertV14ApprovalBinding({ signed, prereg, expected });
  const preseal = assertV14PresealPin({ pin: presealPin, baseBytes,
    commitment: prereg.executor.model_image.content_commitment });
  const final = assertV14PresealPin({ pin: finalPin, baseBytes: bytes('preregistration.v14.in-force.json'),
    commitment: prereg.executor.model_image.content_commitment });
  if (preseal.commitment !== final.commitment) throw new Error('V14_CONTENT_COMMITMENT_MOVED');
  assertV14ManifestBinding({ prereg, base, baseSupersession: baseInputs.supersession, manifest: activeManifest, supersession, table, ledger });
  return { ok: true, preregistration_digest: prereg.preregistration_digest,
    supersession_id: supersession.supersession_id, content_commitment: final.commitment };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.stdout.write(JSON.stringify(process.argv.includes('--check') ? checkV14OnDisk() : sealV14OnDisk(), null, 2) + '\n');
