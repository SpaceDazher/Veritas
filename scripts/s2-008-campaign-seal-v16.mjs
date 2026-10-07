import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, preregistrationDigest } from '../src/lib/research/index.mjs';
import { createContentSupersession, assertContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { scientificBody } from './s2-008-campaign-approve.mjs';
import { approveV16, assertV16BaseBinding, assertV16PresealPin, assertV16PriorExecutionReconciliation,
  readV16BaseInputs, readV16PriorExecutionInputs } from './s2-008-campaign-v16-approval.mjs';

const OWNER = 'prn-s2007r-owner';
const REASON = 'v16 binds the delegated free Poolside Laguna model, a Poolside-only OpenRouter route with fallbacks disabled, its catalog listing, explicit process credential, 60-second pacing and preserved v15 unknown-outcome closure while keeping frozen science unchanged.';
export function assertV16ManifestBinding({ prereg, base, manifest, supersession, table, ledger } = {}) {
  const history = manifest?.supersession_history;
  const priorV15 = Array.isArray(history)
    ? history.find((entry) => entry.file === 'preregistration-v15-supersession.json') : null;
  if (!prereg || prereg.rule !== 's2-008-prereg-v16' || prereg.approval?.in_force !== true ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      manifest?.preregistration?.file !== 'preregistration.v16.in-force.json' ||
      manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== prereg.preregistration_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v15-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.file !== 'preregistration-v16-supersession.json' ||
      manifest.supersession?.supersession_digest !== supersession?.supersession_digest ||
      history?.at(-1)?.file !== 'preregistration-v16-supersession.json' ||
      history.at(-1).supersession_digest !== supersession?.supersession_digest ||
      priorV15?.supersession_digest !== prereg.v15_prior_execution_reconciliation?.prior_supersession_digest ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger?.entries?.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger?.entries?.at(-1)?.anchor_digest) {
    throw new Error('V16_MANIFEST_BINDING_INVALID');
  }
  assertContentSupersession(supersession, base, prereg);
  return { ok: true };
}
export function sealV16({ signed, draft, base, baseBytes, manifest, supersession: baseSupersession,
  supersessionBytes, table, pin, restartInputs = readV16PriorExecutionInputs(), ledger } = {}) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || signed.approval?.principal_id !== OWNER ||
      signed.approval?.label !== 'Daniil' || signed.approval.in_force !== false) throw new Error('V16_NOT_APPROVED');
  if (signed.preregistration_digest !== preregistrationDigest(signed) ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft))) throw new Error('V16_DRAFT_MISMATCH');
  const lineage = assertV16BaseBinding({ base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes, table, ledger });
  const prior = assertV16PriorExecutionReconciliation(base, restartInputs);
  if (canonicalDigest(signed.v15_prior_execution_reconciliation) !== canonicalDigest(prior) ||
      signed.supersession?.superseded_digest !== lineage.baseDigest) throw new Error('V16_PRIOR_BINDING_MISMATCH');
  assertV16PresealPin({ pin, baseBytes, commitment: signed.executor?.model_image?.content_commitment });
  const expected = approveV16({ draft, base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes, table, ledger, pin, restartInputs,
    principal: signed.approval.principal_id, label: signed.approval.label, issuedAt: signed.approval.issued_at });
  if (expected.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expected.approval) !== canonicalDigest(signed.approval)) throw new Error('V16_SIGNATURE_SCOPE_MISMATCH');
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertPreregistration(prereg);
  const nextSupersession = createContentSupersession({ superseded: base, replacedBy: prereg, reason: REASON });
  assertContentSupersession(nextSupersession, base, prereg);
  const nextManifest = structuredClone(manifest);
  const history = Array.isArray(nextManifest.supersession_history) ? nextManifest.supersession_history : [];
  nextManifest.supersession_history = [...history, {
    file: 'preregistration-v16-supersession.json',
    supersession_id: nextSupersession.supersession_id,
    supersession_digest: nextSupersession.supersession_digest,
    reason: REASON,
  }];
  nextManifest.supersession = nextManifest.supersession_history.at(-1);
  nextManifest.preregistration = { file: 'preregistration.v16.in-force.json',
    preregistration_digest: prereg.preregistration_digest, status: 'IN_FORCE', sealed_before_first_trial: true };
  nextManifest.superseded_preregistration = { file: 'preregistration-v15-superseded.json',
    preregistration_digest: base.preregistration_digest, status: 'SUPERSEDED',
    superseded_by: 'preregistration.v16.in-force.json' };
  nextManifest.frozen_table = { file: 'frozen-table.v3.json', digest: canonicalDigest(table) };
  const result = { prereg, supersession: nextSupersession, ledger: { ...ledger, entries: ledger.entries }, manifest: nextManifest };
  assertV16ManifestBinding({ prereg, base, manifest: nextManifest, supersession: nextSupersession, table, ledger });
  return result;
}


const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, 'corpus/s2-008-campaign');
const EVIDENCE = path.join(ROOT, 'evidence/s2-008-campaign');
const read = (name) => JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8'));
const bytes = (name) => fs.readFileSync(path.join(DIR, name));
const pin = (name) => JSON.parse(fs.readFileSync(path.join(EVIDENCE, name), 'utf8'));
const write = (name, value) => fs.writeFileSync(path.join(DIR, name), JSON.stringify(value, null, 2) + '\n',
  { flag: 'wx', mode: 0o644 });

export const V16_SEAL_TARGETS = Object.freeze(['preregistration.v16.in-force.json',
  'preregistration-v15-superseded.json', 'preregistration-v16-supersession.json', 'manifest.v16.next.json']);

export function assertV16SealTargetsAbsent(dir = DIR) {
  for (const name of V16_SEAL_TARGETS) {
    try { fs.lstatSync(path.join(dir, name)); }
    catch (error) { if (error?.code === 'ENOENT') continue; throw error; }
    throw new Error('V16_SEAL_TARGET_EXISTS');
  }
  return true;
}

export function sealV16OnDisk() {
  assertV16SealTargetsAbsent();
  const inputs = readV16BaseInputs(), restartInputs = readV16PriorExecutionInputs();
  const result = sealV16({ signed: read('preregistration.v16.approved.json'),
    draft: read('preregistration.v16.draft.json'), ...inputs,
    pin: pin('model-image-pin-v16-preseal.json'), restartInputs, ledger: read('source-ledger.v3.json') });
  write('preregistration.v16.in-force.json', result.prereg);
  fs.writeFileSync(path.join(DIR, 'preregistration-v15-superseded.json'), inputs.baseBytes,
    { flag: 'wx', mode: 0o644 });
  write('preregistration-v16-supersession.json', result.supersession);
  const temp = path.join(DIR, 'manifest.v16.next.json');
  fs.writeFileSync(temp, JSON.stringify(result.manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  fs.renameSync(temp, path.join(DIR, 'manifest.json'));
  return { in_force: true, preregistration_digest: result.prereg.preregistration_digest,
    supersession_id: result.supersession.supersession_id };
}

export function checkV16OnDisk(repoRoot = ROOT) {
  const corpusDir = path.join(repoRoot, 'corpus/s2-008-campaign');
  const evidenceDir = path.join(repoRoot, 'evidence/s2-008-campaign');
  const readRoot = (name) => JSON.parse(fs.readFileSync(path.join(corpusDir, name), 'utf8'));
  const readBytes = (name) => fs.readFileSync(path.join(corpusDir, name));
  const readPin = (name) => JSON.parse(fs.readFileSync(path.join(evidenceDir, name), 'utf8'));
  const prereg = readRoot('preregistration.v16.in-force.json');
  const signed = readRoot('preregistration.v16.approved.json');
  const draft = readRoot('preregistration.v16.draft.json');
  const inputs = readV16BaseInputs({ repoRoot, allowHistorical: true });
  const { base, baseBytes, activeManifest, table, ledger } = inputs;
  const preserved = readBytes('preregistration-v15-superseded.json');
  const supersession = readRoot('preregistration-v16-supersession.json');
  const presealPin = readPin('model-image-pin-v16-preseal.json');
  const finalPin = readPin('model-image-pin-v16.json');
  const restartInputs = readV16PriorExecutionInputs({ repoRoot });
  if (!preserved.equals(baseBytes)) throw new Error('V16_BASE_BYTES_NOT_PRESERVED');
  const expected = approveV16({ draft, ...inputs, pin: presealPin, restartInputs,
    principal: signed.approval?.principal_id, label: signed.approval?.label,
    issuedAt: signed.approval?.issued_at });
  if (expected.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expected.approval) !== canonicalDigest(signed.approval)) {
    throw new Error('V16_APPROVAL_BINDING_MISMATCH');
  }
  const preseal = assertV16PresealPin({ pin: presealPin, baseBytes,
    commitment: prereg.executor.model_image.content_commitment });
  const final = assertV16PresealPin({ pin: finalPin, baseBytes: readBytes('preregistration.v16.in-force.json'),
    commitment: prereg.executor.model_image.content_commitment });
  if (preseal.commitment !== final.commitment) throw new Error('V16_CONTENT_COMMITMENT_MOVED');
  assertV16ManifestBinding({ prereg, base, manifest: activeManifest, supersession, table, ledger });
  return { ok: true, preregistration_digest: prereg.preregistration_digest,
    supersession_id: supersession.supersession_id, content_commitment: final.commitment };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.stdout.write(JSON.stringify(process.argv.includes('--check') ? checkV16OnDisk() : sealV16OnDisk(), null, 2) + '\n');
