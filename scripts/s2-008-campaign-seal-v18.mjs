import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, preregistrationDigest } from '../src/lib/research/index.mjs';
import { assertContentSupersession, createContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { scientificBody } from './s2-008-campaign-approve.mjs';
import { approveV18, assertV18BaseBinding, assertV18PresealPin, assertV18PriorExecutionReconciliation,
  readV18BaseInputs, readV18PriorExecutionInputs } from './s2-008-campaign-v18-approval.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = 'prn-s2007r-owner';
export const V18_SUPERSESSION_REASON = 'Owner-authorized v18 recovery: preserve frozen science, bind all classified v17 stopped evidence, permit one new A and only a fully measured, receipts-reconciled B.';
export const V18_SEAL_TARGETS = Object.freeze(['preregistration.v18.in-force.json',
  'preregistration-v17-superseded.json', 'preregistration-v18-supersession.json', 'manifest.v18.next.json']);
const read = (root, name) => fs.readFileSync(path.join(root, 'corpus/s2-008-campaign', name));
const parse = (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8'));
const writeNew = (root, name, value) => fs.writeFileSync(path.join(root, 'corpus/s2-008-campaign', name),
  JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o644 });

export function assertV18SealTargetsAbsent(dir = path.join(ROOT, 'corpus/s2-008-campaign')) {
  for (const name of V18_SEAL_TARGETS) {
    try { fs.lstatSync(path.join(dir, name)); }
    catch (error) { if (error?.code === 'ENOENT') continue; throw error; }
    throw new Error('V18_SEAL_TARGET_EXISTS');
  }
  return true;
}

export function assertV18ManifestBinding({ prereg, base, manifest, supersession, table, ledger } = {}) {
  const history = manifest?.supersession_history;
  const tail = history?.at(-1);
  if (!prereg || prereg.rule !== 's2-008-prereg-v18' || prereg.approval?.in_force !== true ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      manifest?.preregistration?.file !== 'preregistration.v18.in-force.json' ||
      manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== prereg.preregistration_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v17-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== preregistrationDigest(base) ||
      manifest.supersession?.file !== 'preregistration-v18-supersession.json' ||
      manifest.supersession?.supersession_digest !== supersession?.supersession_digest ||
      tail?.file !== 'preregistration-v18-supersession.json' || tail.supersession_digest !== supersession?.supersession_digest ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger?.entries?.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger?.entries?.at(-1)?.anchor_digest) throw new Error('V18_MANIFEST_BINDING_INVALID');
  assertContentSupersession(supersession, base, prereg);
  return { ok: true };
}

export function sealV18({ signed, draft, base, baseBytes, manifest, supersession: priorSupersession,
  supersessionBytes, table, pin, restartInputs = readV18PriorExecutionInputs(), ledger, repoRoot = ROOT } = {}) {
  if (signed?.status !== 'APPROVED' || signed.approval?.status !== 'APPROVED' ||
      signed.approval?.authority !== 'HUMAN_OWNER' || signed.approval?.principal_id !== OWNER ||
      signed.approval?.label !== 'Daniil' || signed.approval.in_force !== false) throw new Error('V18_NOT_APPROVED');
  if (signed.preregistration_digest !== preregistrationDigest(signed)) throw new Error('V18_DRAFT_MISMATCH');
  const lineage = assertV18BaseBinding({ base, baseBytes, manifest, supersession: priorSupersession,
    supersessionBytes, table, ledger, repoRoot });
  const predecessor = assertV18PriorExecutionReconciliation(restartInputs);
  if (canonicalDigest(signed.v17_prior_execution_reconciliation) !== canonicalDigest(predecessor) ||
      signed.supersession?.superseded_digest !== lineage.baseDigest) throw new Error('V18_PRIOR_BINDING_MISMATCH');
  assertV18PresealPin({ pin, baseBytes, commitment: signed.executor?.model_image?.content_commitment });
  const expected = approveV18({ draft, base, baseBytes, manifest, supersession: priorSupersession,
    supersessionBytes, table, ledger, pin, restartInputs, principal: signed.approval.principal_id,
    label: signed.approval.label, issuedAt: signed.approval.issued_at, repoRoot });
  if (expected.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expected.approval) !== canonicalDigest(signed.approval)) throw new Error('V18_SIGNATURE_SCOPE_MISMATCH');
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  assertPreregistration(prereg);
  const nextSupersession = createContentSupersession({ superseded: base, replacedBy: prereg, reason: V18_SUPERSESSION_REASON });
  assertContentSupersession(nextSupersession, base, prereg);
  const nextManifest = structuredClone(manifest);
  const history = Array.isArray(nextManifest.supersession_history) ? nextManifest.supersession_history : [];
  nextManifest.supersession_history = [...history, { file: 'preregistration-v18-supersession.json',
    supersession_id: nextSupersession.supersession_id, supersession_digest: nextSupersession.supersession_digest,
    reason: V18_SUPERSESSION_REASON }];
  nextManifest.supersession = nextManifest.supersession_history.at(-1);
  nextManifest.preregistration = { file: 'preregistration.v18.in-force.json',
    preregistration_digest: prereg.preregistration_digest, status: 'IN_FORCE', sealed_before_first_trial: true };
  nextManifest.superseded_preregistration = { file: 'preregistration-v17-superseded.json',
    preregistration_digest: base.preregistration_digest, status: 'SUPERSEDED',
    superseded_by: 'preregistration.v18.in-force.json' };
  nextManifest.frozen_table = { file: 'frozen-table.v3.json', digest: canonicalDigest(table) };
  const result = { prereg, supersession: nextSupersession, manifest: nextManifest, ledger: { ...ledger, entries: ledger.entries } };
  assertV18ManifestBinding({ prereg, base, manifest: nextManifest, supersession: nextSupersession, table, ledger });
  return result;
}

export function sealV18OnDisk(repoRoot = ROOT) {
  const dir = path.join(repoRoot, 'corpus/s2-008-campaign');
  assertV18SealTargetsAbsent(dir);
  const inputs = readV18BaseInputs({ repoRoot });
  const restartInputs = readV18PriorExecutionInputs({ repoRoot });
  const result = sealV18({ signed: parse(read(repoRoot, 'preregistration.v18.approved.json')),
    draft: parse(read(repoRoot, 'preregistration.v18.draft.json')), ...inputs,
    pin: JSON.parse(fs.readFileSync(path.join(repoRoot, 'evidence/s2-008-campaign/model-image-pin-v18-preseal.json'), 'utf8')),
    restartInputs, ledger: JSON.parse(read(repoRoot, 'source-ledger.v3.json').toString('utf8')), repoRoot });
  writeNew(repoRoot, 'preregistration.v18.in-force.json', result.prereg);
  fs.writeFileSync(path.join(dir, 'preregistration-v17-superseded.json'), inputs.baseBytes, { flag: 'wx', mode: 0o644 });
  writeNew(repoRoot, 'preregistration-v18-supersession.json', result.supersession);
  const temp = path.join(dir, 'manifest.v18.next.json');
  fs.writeFileSync(temp, JSON.stringify(result.manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  fs.renameSync(temp, path.join(dir, 'manifest.json'));
  return { in_force: true, preregistration_digest: result.prereg.preregistration_digest,
    supersession_id: result.supersession.supersession_id };
}

export function assertV18SuccessorOnDisk(repoRoot = ROOT) {
  const inputs = readV18BaseInputs({ repoRoot, allowHistorical: true });
  const restartInputs = readV18PriorExecutionInputs({ repoRoot });
  const dir = path.join(repoRoot, 'corpus/s2-008-campaign'), evidence = path.join(repoRoot, 'evidence/s2-008-campaign');
  const preregBytes = fs.readFileSync(path.join(dir, 'preregistration.v18.in-force.json'));
  const prereg = parse(preregBytes), signed = JSON.parse(fs.readFileSync(path.join(dir, 'preregistration.v18.approved.json'), 'utf8'));
  const draft = JSON.parse(fs.readFileSync(path.join(dir, 'preregistration.v18.draft.json'), 'utf8'));
  const supersession = JSON.parse(fs.readFileSync(path.join(dir, 'preregistration-v18-supersession.json'), 'utf8'));
  const preseal = JSON.parse(fs.readFileSync(path.join(evidence, 'model-image-pin-v18-preseal.json'), 'utf8'));
  const finalPin = JSON.parse(fs.readFileSync(path.join(evidence, 'model-image-pin-v18.json'), 'utf8'));
  const expectedSigned = approveV18({ draft, ...inputs, pin: preseal, restartInputs,
    principal: signed.approval?.principal_id, label: signed.approval?.label, issuedAt: signed.approval?.issued_at, repoRoot });
  if (expectedSigned.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expectedSigned.approval) !== canonicalDigest(signed.approval) ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      canonicalDigest(scientificBody(prereg)) !== canonicalDigest(scientificBody(signed)) || prereg.approval?.in_force !== true) {
    throw new Error('V18_SIGNATURE_BINDING_INVALID');
  }
  const first = assertV18PresealPin({ pin: preseal, baseBytes: inputs.baseBytes,
    commitment: prereg.executor?.model_image?.content_commitment });
  const final = assertV18PresealPin({ pin: finalPin, baseBytes: preregBytes,
    commitment: prereg.executor?.model_image?.content_commitment });
  if (first.commitment !== final.commitment) throw new Error('V18_CONTENT_COMMITMENT_MOVED');
  const expected = sealV18({ signed, draft, ...inputs, pin: preseal, restartInputs,
    ledger: inputs.ledger, repoRoot });
  if (canonicalDigest(expected.supersession) !== canonicalDigest(supersession) ||
      canonicalDigest(expected.manifest) !== canonicalDigest(inputs.activeManifest) ||
      canonicalDigest(expected.prereg) !== canonicalDigest(prereg)) throw new Error('V18_ACTIVE_MANIFEST_BINDING_INVALID');
  assertContentSupersession(supersession, inputs.base, prereg);
  return { ok: true, preregistration_digest: prereg.preregistration_digest,
    supersession_id: supersession.supersession_id, content_commitment: final.commitment };
}

export function checkV18OnDisk(repoRoot = ROOT) { return assertV18SuccessorOnDisk(repoRoot); }
export function historicalV17ManifestForV18(repoRoot, manifest) {
  const actual = JSON.parse(fs.readFileSync(path.join(repoRoot, 'corpus/s2-008-campaign/manifest.json'), 'utf8'));
  if (canonicalDigest(actual) !== canonicalDigest(manifest)) throw new Error('V18_ACTIVE_MANIFEST_INPUT_MISMATCH');
  assertV18SuccessorOnDisk(repoRoot);
  return readV18BaseInputs({ repoRoot, allowHistorical: true }).manifest;
}
