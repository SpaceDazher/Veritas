import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, preregistrationDigest } from '../src/lib/research/index.mjs';
import { createContentSupersession, assertContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { scientificBody } from './s2-008-campaign-approve.mjs';
import { approveV15, assertV15BaseBinding, assertV15PresealPin, assertV15PriorExecutionReconciliation,
  readV15BaseInputs, readV15PriorExecutionInputs } from './s2-008-campaign-v15-approval.mjs';

const OWNER = 'prn-s2007r-owner';
const REASON = 'v15 binds the free Gemma model selected under owner delegation, its zero-priced current provider descriptor, explicit process credential, 60-second pacing and preserved v14 request-outcome closure while keeping the frozen experiment unchanged.';
export function assertV15ManifestBinding({ prereg, base, manifest, supersession, table, ledger } = {}) {
  const history = manifest?.supersession_history;
  const priorV14 = Array.isArray(history)
    ? history.find((entry) => entry.file === 'preregistration-v14-supersession.json') : null;
  if (!prereg || prereg.rule !== 's2-008-prereg-v15' || prereg.approval?.in_force !== true ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      manifest?.preregistration?.file !== 'preregistration.v15.in-force.json' ||
      manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== prereg.preregistration_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v14-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.file !== 'preregistration-v15-supersession.json' ||
      manifest.supersession?.supersession_digest !== supersession?.supersession_digest ||
      history?.at(-1)?.file !== 'preregistration-v15-supersession.json' ||
      history.at(-1).supersession_digest !== supersession?.supersession_digest ||
      priorV14?.supersession_digest !== prereg.v14_prior_execution_reconciliation?.prior_supersession_digest ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger?.entries?.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger?.entries?.at(-1)?.anchor_digest) {
    throw new Error('V15_MANIFEST_BINDING_INVALID');
  }
  assertContentSupersession(supersession, base, prereg);
  return { ok: true };
}
export function sealV15({ signed, draft, base, baseBytes, manifest, supersession: baseSupersession,
  supersessionBytes, table, pin, restartInputs = readV15PriorExecutionInputs(), ledger } = {}) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || signed.approval?.principal_id !== OWNER ||
      signed.approval?.label !== 'Daniil' || signed.approval.in_force !== false) throw new Error('V15_NOT_APPROVED');
  if (signed.preregistration_digest !== preregistrationDigest(signed) ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft))) throw new Error('V15_DRAFT_MISMATCH');
  const lineage = assertV15BaseBinding({ base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes, table, ledger });
  const prior = assertV15PriorExecutionReconciliation(base, restartInputs);
  if (canonicalDigest(signed.v14_prior_execution_reconciliation) !== canonicalDigest(prior) ||
      signed.supersession?.superseded_digest !== lineage.baseDigest) throw new Error('V15_PRIOR_BINDING_MISMATCH');
  assertV15PresealPin({ pin, baseBytes, commitment: signed.executor?.model_image?.content_commitment });
  const expected = approveV15({ draft, base, baseBytes, manifest, supersession: baseSupersession,
    supersessionBytes, table, ledger, pin, restartInputs,
    principal: signed.approval.principal_id, label: signed.approval.label, issuedAt: signed.approval.issued_at });
  if (expected.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expected.approval) !== canonicalDigest(signed.approval)) throw new Error('V15_SIGNATURE_SCOPE_MISMATCH');
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertPreregistration(prereg);
  const nextSupersession = createContentSupersession({ superseded: base, replacedBy: prereg, reason: REASON });
  assertContentSupersession(nextSupersession, base, prereg);
  const nextManifest = structuredClone(manifest);
  const history = Array.isArray(nextManifest.supersession_history) ? nextManifest.supersession_history : [];
  nextManifest.supersession_history = [...history, {
    file: 'preregistration-v15-supersession.json',
    supersession_id: nextSupersession.supersession_id,
    supersession_digest: nextSupersession.supersession_digest,
    reason: REASON,
  }];
  nextManifest.supersession = nextManifest.supersession_history.at(-1);
  nextManifest.preregistration = { file: 'preregistration.v15.in-force.json',
    preregistration_digest: prereg.preregistration_digest, status: 'IN_FORCE', sealed_before_first_trial: true };
  nextManifest.superseded_preregistration = { file: 'preregistration-v14-superseded.json',
    preregistration_digest: base.preregistration_digest, status: 'SUPERSEDED',
    superseded_by: 'preregistration.v15.in-force.json' };
  nextManifest.frozen_table = { file: 'frozen-table.v3.json', digest: canonicalDigest(table) };
  const result = { prereg, supersession: nextSupersession, ledger: { ...ledger, entries: ledger.entries }, manifest: nextManifest };
  assertV15ManifestBinding({ prereg, base, manifest: nextManifest, supersession: nextSupersession, table, ledger });
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

export const V15_SEAL_TARGETS = Object.freeze(['preregistration.v15.in-force.json',
  'preregistration-v14-superseded.json', 'preregistration-v15-supersession.json', 'manifest.v15.next.json']);

export function assertV15SealTargetsAbsent(dir = DIR) {
  for (const name of V15_SEAL_TARGETS) {
    try { fs.lstatSync(path.join(dir, name)); }
    catch (error) { if (error?.code === 'ENOENT') continue; throw error; }
    throw new Error('V15_SEAL_TARGET_EXISTS');
  }
  return true;
}

export function sealV15OnDisk() {
  assertV15SealTargetsAbsent();
  const inputs = readV15BaseInputs(), restartInputs = readV15PriorExecutionInputs();
  const result = sealV15({ signed: read('preregistration.v15.approved.json'),
    draft: read('preregistration.v15.draft.json'), ...inputs,
    pin: pin('model-image-pin-v15-preseal.json'), restartInputs, ledger: read('source-ledger.v3.json') });
  write('preregistration.v15.in-force.json', result.prereg);
  fs.writeFileSync(path.join(DIR, 'preregistration-v14-superseded.json'), inputs.baseBytes,
    { flag: 'wx', mode: 0o644 });
  write('preregistration-v15-supersession.json', result.supersession);
  const temp = path.join(DIR, 'manifest.v15.next.json');
  fs.writeFileSync(temp, JSON.stringify(result.manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  fs.renameSync(temp, path.join(DIR, 'manifest.json'));
  return { in_force: true, preregistration_digest: result.prereg.preregistration_digest,
    supersession_id: result.supersession.supersession_id };
}

export function checkV15OnDisk(repoRoot = ROOT) {
  const corpusDir = path.join(repoRoot, 'corpus/s2-008-campaign');
  const evidenceDir = path.join(repoRoot, 'evidence/s2-008-campaign');
  const readRoot = (name) => JSON.parse(fs.readFileSync(path.join(corpusDir, name), 'utf8'));
  const readBytes = (name) => fs.readFileSync(path.join(corpusDir, name));
  const readPin = (name) => JSON.parse(fs.readFileSync(path.join(evidenceDir, name), 'utf8'));
  const prereg = readRoot('preregistration.v15.in-force.json');
  const signed = readRoot('preregistration.v15.approved.json');
  const draft = readRoot('preregistration.v15.draft.json');
  const inputs = readV15BaseInputs({ repoRoot, allowHistorical: true });
  const { base, baseBytes, activeManifest, table, ledger } = inputs;
  const preserved = readBytes('preregistration-v14-superseded.json');
  const supersession = readRoot('preregistration-v15-supersession.json');
  const presealPin = readPin('model-image-pin-v15-preseal.json');
  const finalPin = readPin('model-image-pin-v15.json');
  const restartInputs = readV15PriorExecutionInputs({ repoRoot });
  if (!preserved.equals(baseBytes)) throw new Error('V15_BASE_BYTES_NOT_PRESERVED');
  const expected = approveV15({ draft, ...inputs, pin: presealPin, restartInputs,
    principal: signed.approval?.principal_id, label: signed.approval?.label,
    issuedAt: signed.approval?.issued_at });
  if (expected.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expected.approval) !== canonicalDigest(signed.approval)) {
    throw new Error('V15_APPROVAL_BINDING_MISMATCH');
  }
  const preseal = assertV15PresealPin({ pin: presealPin, baseBytes,
    commitment: prereg.executor.model_image.content_commitment });
  const final = assertV15PresealPin({ pin: finalPin, baseBytes: readBytes('preregistration.v15.in-force.json'),
    commitment: prereg.executor.model_image.content_commitment });
  if (preseal.commitment !== final.commitment) throw new Error('V15_CONTENT_COMMITMENT_MOVED');
  assertV15ManifestBinding({ prereg, base, manifest: activeManifest, supersession, table, ledger });
  return { ok: true, preregistration_digest: prereg.preregistration_digest,
    supersession_id: supersession.supersession_id, content_commitment: final.commitment };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.stdout.write(JSON.stringify(process.argv.includes('--check') ? checkV15OnDisk() : sealV15OnDisk(), null, 2) + '\n');
