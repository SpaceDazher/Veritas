import { historicalV16ManifestForV17 } from './s2-008-campaign-v17-approval.mjs';
import { historicalV16ManifestForV18 } from './s2-008-campaign-seal-v18.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { assertPreregistration, assertSourceLedger } from '../src/lib/research/index.mjs';
import { FROZEN_MEMBERS, preregistrationDigest, scopeDrift, scientificBody } from './s2-008-campaign-approve.mjs';
import { V14_MODEL_POLICY, V7_PI_SETTINGS, assertV14ExecutorPolicy } from './s2-008-campaign-credential-env.mjs';
import { assertVersionedPresealPin } from './s2-008-campaign-v6-approval.mjs';
import { assertV14ModelTimeoutPolicy, createV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = 'prn-s2007r-owner', BASE_FILE = 'preregistration.v13.in-force.json';
const BASE_SHA = '80da47105d3ec77a707c867fcb5fc29ae564ace482eea2d7fb868d609ac995cd';
const BASELINE_FILE = 'evidence/s2-008-campaign/v13-immutable-baseline.json';
const BASELINE_SHA = '56f8f82ab9a83298487490aaf94ec5bc54e5040064b668283103a24ec4042739';
const THIRD_RUN = 'evidence/s2-008-campaign/v13-a-third-stopped/run-v13-a.json';
const THIRD_RUN_SHA = '9b48f3de8e6e275f38e7c5eb2d5c9d05647671303a5c1effdfb9cd264e10b13a';
const THIRD_RECON = 'evidence/s2-008-campaign/v13-a-third-stopped/reconciliation.json';
const THIRD_RECON_SHA = '9c1c75d83c3952af147aed141c5fbd3c556815c8b81c97b7f2535a3b6d5bee81';
const SIDECAR = 'evidence/s2-008-campaign/v13-a-third-stopped/predictions-v13-a-trl-s2-008c-01-20260926.json';
const SIDECAR_SHA = 'db370f2cb50497ddd22458a30c4d84e403a4ab1bbe99e44ca9df43885997664b';
const KNOWN = 'evidence/s2-008-campaign/v13-a-third-stopped/known-generation-receipts.json';
const KNOWN_SHA = '3717dac69409ebb9d290aa6965c35aae64b97b1b5cf732d05e59e3d0aa3f0e0c';
const RECHECK = 'evidence/s2-008-campaign/v13-a-third-stopped/provider-receipts-api-recheck.json';
const RECHECK_SHA = 'd421ff258c084eb9f9716bf98bf2648b9d93d4dab748650f41124ae9fcbb1412';
const UPSTREAM = 'evidence/s2-008-campaign/v13-a-third-stopped/upstream-429-observation.json';
const UPSTREAM_SHA = 'a19a7af72919780e4602261555aa16a025af1fca4e128a9f80d61a9f5ccdeebd';
const WRONG = 'evidence/s2-008-campaign/reconciliation-v13-a.json';
const WRONG_SHA = '770396c10afd2e0e0e6ad70729e207da41ec7dbbaafa33b7db07d2de09d52fe7';
const CORRECTION = 'evidence/s2-008-campaign/credential-attribution-correction-v13.json';
const CORRECTION_SHA = '47de529c0b72bdba18568080c157324d730f7cb42b394ff5482776616026c09c';
const EXPIRY = '2026-10-12T00:00:00.000Z';

const APPROVAL_DIGEST_SCOPE = 'the scientific body: every member except approval, status and preregistration_digest';
const DRAFT_SEAL_TEXT = 'scripts/s2-008-campaign-prepare.mjs --seal-v14 records this digest and supersession in the corpus manifest';
const APPROVAL_KEYS = Object.freeze(['authority','becomes_in_force_when','in_force','issued_at','label','principal_id','signed_digest_over','status']);
const hasExactApprovalKeys = (value) => value && typeof value === 'object' &&
  Object.keys(value).sort().join(',') === [...APPROVAL_KEYS].sort().join(',');
export function assertV14DraftApprovalMetadata(approval) {
  if (!hasExactApprovalKeys(approval) || approval.status !== null || approval.authority !== 'HUMAN_OWNER' ||
      approval.principal_id !== null || approval.label !== null || approval.issued_at !== null ||
      approval.signed_digest_over !== APPROVAL_DIGEST_SCOPE || approval.in_force !== false ||
      approval.becomes_in_force_when !== DRAFT_SEAL_TEXT) throw new Error('V14_APPROVAL_METADATA_INVALID');
  return true;
}

const EXPECTED_BASELINE = [
  ['corpus/s2-008-campaign/preregistration.v13.approved.json','3357b412d0811ea089c8350773533e1784859c0950b91c713a702b1f095ff5aa',25380],
  ['corpus/s2-008-campaign/preregistration.v13.in-force.json',BASE_SHA,25379],
  ['corpus/s2-008-campaign/preregistration-v13-supersession.json','c40fd6e8e84b9c84c01d74dc366c0326353d0c6abbf3b7f8df4c78947e0aa03e',691],
  ['evidence/s2-008-campaign/model-image-pin-v13.json','6f655d3336dbe73c0eacc0d967743008741aadc5f84851c4545003a0558ad45f',5077],
  ['evidence/s2-008-campaign/run-v13-a.json','44b4c2af8ff3d12b5295572d7ffa5a8bf0ec951e815b35d1ff49eaa6eb1ccf11',13174],
  ['evidence/s2-008-campaign/reconciliation-v13-a-first-old-key-confirmed.json','ee24a8b777c347623dab78e0828899fe8974cbdab7fe1287d79f5ba9bd31ac6f',2983],
  ['evidence/s2-008-campaign/reconciliation-v13-a-second-old-key-confirmed.json','80a45812ee995dc9f962100830a4f1a75cd410b1904a241ce1484ac3a16765e9',3004],
  ['evidence/s2-008-campaign/v13-a-second-stopped/run-v13-a.json','be85ff414cb86ba06b9ab9a83fa2643b35038cc0bd8de740fa858aefd2128bd0',13174],
  [THIRD_RUN,THIRD_RUN_SHA,15139], [THIRD_RECON,THIRD_RECON_SHA,3876], [UPSTREAM,UPSTREAM_SHA,1139],
];
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const parse = (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8'));
const safeRead = (root, name) => {
  const realRoot = fs.realpathSync(root), full = path.resolve(realRoot, name);
  if (!full.startsWith(realRoot + path.sep)) throw new Error('V14_INPUT_PATH_INVALID');
  const stat = fs.lstatSync(full);
  if (!stat.isFile() || stat.isSymbolicLink() || fs.realpathSync(full) !== full) throw new Error('V14_INPUT_FILE_UNSAFE');
  return fs.readFileSync(full);
};


function assertV16ActiveSuccessor(repoRoot, manifest) {
  const v15Bytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v15-superseded.json');
  const v16Bytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration.v16.in-force.json');
  const supersessionBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v16-supersession.json');
  if (sha(v15Bytes) !== 'fb9496773cd4acafb0fad4e5c860ae6208dea977c919115ffe89d148d141c348') {
    throw new Error('V16_HISTORICAL_V15_BYTES_INVALID');
  }
  const v15 = parse(v15Bytes), v16 = parse(v16Bytes), supersession = parse(supersessionBytes);
  assertPreregistration(v15);
  assertPreregistration(v16);
  if (v15.preregistration_digest !== '84e15b1b1276c548ad6486fd65a03782f0b9d463cef802d6dcd608accf744268' ||
      v16.rule !== 's2-008-prereg-v16' || v16.preregistration_id !== 'xpr-s2-008c-16' ||
      v16.status !== 'APPROVED' || v16.approval?.status !== 'APPROVED' ||
      v16.approval?.authority !== 'HUMAN_OWNER' || v16.approval?.principal_id !== 'prn-s2007r-owner' ||
      v16.approval?.label !== 'Daniil' || v16.approval?.in_force !== true ||
      v16.approval?.signed_digest_over !== 'the scientific body: every member except approval, status and preregistration_digest' ||
      v16.preregistration_digest !== preregistrationDigest(v16) ||
      manifest?.preregistration?.file !== 'preregistration.v16.in-force.json' ||
      manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== v16.preregistration_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v15-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== v15.preregistration_digest) {
    throw new Error('V16_HISTORICAL_ACTIVE_BINDING_INVALID');
  }
  assertContentSupersession(supersession, v15, v16);
  const tail = { file: 'preregistration-v16-supersession.json',
    supersession_id: supersession.supersession_id,
    supersession_digest: supersession.supersession_digest,
    reason: supersession.reason };
  if (canonicalDigest(manifest.supersession_history?.at(-1) ?? null) !== canonicalDigest(tail) ||
      canonicalDigest(manifest.supersession ?? null) !== canonicalDigest(tail)) {
    throw new Error('V16_HISTORICAL_SUPERSESSION_MANIFEST_INVALID');
  }
}

function historicalV13Manifest(manifest, base, supersession) {
  if (manifest?.preregistration?.file === BASE_FILE && manifest.preregistration.status === 'IN_FORCE') return manifest;
  const isV14 = manifest?.preregistration?.file === 'preregistration.v14.in-force.json';
  const isV15 = manifest?.preregistration?.file === 'preregistration.v15.in-force.json';
  const isV16 = manifest?.preregistration?.file === 'preregistration.v16.in-force.json';
  if ((!isV14 && !isV15 && !isV16) || manifest.preregistration.status !== 'IN_FORCE') {
    throw new Error('V14_BASE_MANIFEST_INVALID');
  }
  const history = manifest.supersession_history;
  const index = Array.isArray(history) ? history.findIndex((item) =>
    item.file === 'preregistration-v13-supersession.json' &&
    item.supersession_digest === supersession?.supersession_digest) : -1;
  const successor = history?.[index + 1];
  const successorV15 = history?.[index + 2];
  const successorV16 = history?.[index + 3];
  const expectedNext = (isV15 || isV16)
    ? successor?.file === 'preregistration-v14-supersession.json' &&
      successor?.supersession_digest === 'c9e53c0cf3a0834136b22be61bb41936998d4a78e76f95cc2d3ec6b05a74b9a9'
    : true;
  const expectedV15 = !isV16 || (successorV15?.file === 'preregistration-v15-supersession.json' &&
    successorV15?.supersession_digest === '4387b8d444737a41dbc2738115e55fb0c3a8cf6177cbcd1b4f3629d1cc0c9218');
  const expectedV16 = !isV16 || (successorV16?.file === 'preregistration-v16-supersession.json' &&
    history?.at(-1)?.file === 'preregistration-v16-supersession.json' &&
    history.at(-1)?.supersession_digest === manifest.supersession?.supersession_digest &&
    manifest.superseded_preregistration?.preregistration_digest === '84e15b1b1276c548ad6486fd65a03782f0b9d463cef802d6dcd608accf744268');
  if (index < 0 || !expectedNext || !expectedV15 || !expectedV16 ||
      manifest.superseded_preregistration?.file !== (isV16 ? 'preregistration-v15-superseded.json'
        : isV15 ? 'preregistration-v14-superseded.json' : 'preregistration-v13-superseded.json') ||
      (isV16 && manifest.superseded_preregistration.preregistration_digest !== '84e15b1b1276c548ad6486fd65a03782f0b9d463cef802d6dcd608accf744268') ||
      (isV14 && manifest.superseded_preregistration.preregistration_digest !== base.preregistration_digest)) {
    throw new Error('V14_BASE_MANIFEST_INVALID');
  }
  return {
    ...manifest,
    preregistration: { file: BASE_FILE, status: 'IN_FORCE', preregistration_digest: base.preregistration_digest },
    supersession: history[index], supersession_history: history.slice(0, index + 1),
    superseded_preregistration: { file: 'preregistration-v12-superseded.json',
      preregistration_digest: base.supersession?.superseded_digest, status: 'SUPERSEDED', superseded_by: BASE_FILE },
  };
}

export function readV14BaseInputs({ repoRoot = ROOT, allowHistorical = false } = {}) {
  const baseBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/' + BASE_FILE);
  if (sha(baseBytes) !== BASE_SHA) throw new Error('V14_BASE_BYTES_INVALID');
  const base = parse(baseBytes);
  const activeManifest = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/manifest.json'));
  const historicalManifestView = allowHistorical && activeManifest.preregistration?.file === 'preregistration.v18.in-force.json'
    ? historicalV16ManifestForV18(repoRoot, activeManifest)
    : allowHistorical && activeManifest.preregistration?.file === 'preregistration.v17.in-force.json'
      ? historicalV16ManifestForV17(repoRoot, activeManifest) : activeManifest;
  if (historicalManifestView.preregistration?.file === 'preregistration.v16.in-force.json') assertV16ActiveSuccessor(repoRoot, historicalManifestView);
  if (!allowHistorical && historicalManifestView.preregistration?.file !== BASE_FILE) throw new Error('V14_BASE_NOT_CURRENT');
  const supersessionBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v13-supersession.json');
  const supersession = parse(supersessionBytes);
  const manifest = historicalV13Manifest(historicalManifestView, base, supersession);
  const table = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/frozen-table.v3.json'));
  const ledger = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/source-ledger.v3.json'));
  return { base, baseBytes, manifest, activeManifest, supersession, supersessionBytes, table, ledger };
}

export function readV14RestartInputs({ repoRoot = ROOT } = {}) {
  const readJson = (name) => { const bytes = safeRead(repoRoot, name); return { bytes, value: parse(bytes) }; };
  return {
    repoRoot,
    baseline: readJson(BASELINE_FILE),
    firstOldKey: readJson('evidence/s2-008-campaign/reconciliation-v13-a-first-old-key-confirmed.json'),
    secondOldKey: readJson('evidence/s2-008-campaign/reconciliation-v13-a-second-old-key-confirmed.json'),
    thirdRun: readJson(THIRD_RUN), thirdReconciliation: readJson(THIRD_RECON),
    thirdSidecar: readJson(SIDECAR), knownReceipts: readJson(KNOWN), apiRecheck: readJson(RECHECK),
    upstreamObservation: readJson(UPSTREAM), wrongReconciliation: readJson(WRONG),
    attributionCorrection: readJson(CORRECTION),
  };
}

function assertBaseline(inputs) {
  const baseline = inputs.baseline.value, bytes = inputs.baseline.bytes;
  if (sha(bytes) !== BASELINE_SHA || baseline?.head !== 'c8654c381e5dfb9937e8c3826792428568d08c99' ||
      !Array.isArray(baseline.files) || baseline.files.length !== EXPECTED_BASELINE.length) {
    throw new Error('V14_IMMUTABLE_BASELINE_INVALID');
  }
  for (let i = 0; i < EXPECTED_BASELINE.length; i += 1) {
    const [file, digest, size] = EXPECTED_BASELINE[i], entry = baseline.files[i];
    if (entry?.file !== file || entry.sha256 !== digest || entry.bytes !== size) throw new Error('V14_IMMUTABLE_BASELINE_INVALID');
    const raw = safeRead(inputs.repoRoot ?? ROOT, file);
    if (raw.length !== size || sha(raw) !== digest) throw new Error('V14_IMMUTABLE_BASELINE_INPUT_CHANGED');
  }
}

function assertOldKeyClosure(value, bytes, expectedSha, baseDigest) {
  if (sha(bytes) !== expectedSha || value?.kind !== 's2-008-v13-stopped-a-owner-reconciliation/1' ||
      value.status !== 'RECONCILED' || value.preregistration_digest !== baseDigest ||
      value.provider !== 'openrouter' || value.model !== V14_MODEL_POLICY.model ||
      value.provider_key?.fingerprint !== '63ba91bbeb808e17' ||
      value.method !== 'OWNER_CONFIRMED_EMPTY_INTERVAL' ||
      value.local_model_attempts !== 1 || value.locally_accounted_model_calls !== 0 ||
      value.matching_requests !== 0 || value.raw_unknown_attempts !== 1 ||
      value.closed_unknown_attempts !== 1 || value.unreconciled_attempts !== 0 ||
      value.actual_tokens !== 0 || value.actual_usd !== 0 ||
      value.completeness?.complete !== true ||
      value.completeness?.confirmed_by !== 'Daniil' || value.completeness?.principal_id !== OWNER ||
      !Array.isArray(value.rows) || value.rows.length !== 0) throw new Error('V14_OLD_KEY_CLOSURE_INVALID');
}

export function assertV14RestartReconciliation(base, inputs = readV14RestartInputs()) {
  if (!base || base.rule !== 's2-008-prereg-v13' || base.preregistration_digest !== preregistrationDigest(base)) {
    throw new Error('V14_RESTART_BASE_INVALID');
  }
  assertBaseline(inputs);
  const digest = base.preregistration_digest;
  assertOldKeyClosure(inputs.firstOldKey.value, inputs.firstOldKey.bytes,
    'ee24a8b777c347623dab78e0828899fe8974cbdab7fe1287d79f5ba9bd31ac6f', digest);
  assertOldKeyClosure(inputs.secondOldKey.value, inputs.secondOldKey.bytes,
    '80a45812ee995dc9f962100830a4f1a75cd410b1904a241ce1484ac3a16765e9', digest);

  const run = inputs.thirdRun.value, recon = inputs.thirdReconciliation.value;
  const sidecar = inputs.thirdSidecar.value, known = inputs.knownReceipts.value;
  const recheck = inputs.apiRecheck.value, observation = inputs.upstreamObservation.value;
  if (sha(inputs.thirdRun.bytes) !== THIRD_RUN_SHA || sha(inputs.thirdReconciliation.bytes) !== THIRD_RECON_SHA ||
      sha(inputs.thirdSidecar.bytes) !== SIDECAR_SHA || sha(inputs.knownReceipts.bytes) !== KNOWN_SHA ||
      sha(inputs.apiRecheck.bytes) !== RECHECK_SHA || sha(inputs.upstreamObservation.bytes) !== UPSTREAM_SHA) {
    throw new Error('V14_THIRD_ATTEMPT_BYTES_INVALID');
  }
  if (run?.kind !== 's2-008-campaign-v13-predictions/1' || run.status !== 'BLOCKED' ||
      run.label !== 'a' || run.raw_run_id !== 's2-008c-v13-a-9e07aa239f9543298675' ||
      run.preregistration_digest !== digest || run.model_calls !== 2 ||
      run.unknown_model_attempts !== 1 || run.unreconciled_spend !== true) throw new Error('V14_THIRD_RUN_INVALID');
  if (recon?.kind !== 's2-008-v13-stopped-a-reconciliation/1' || recon.status !== 'RECONCILED' ||
      recon.prior_run_id !== run.raw_run_id || recon.prior_run_sha256 !== THIRD_RUN_SHA ||
      recon.preregistration_digest !== digest || recon.provider !== 'openrouter' ||
      recon.requested_model !== V14_MODEL_POLICY.model || recon.resolved_model !== V14_MODEL_POLICY.catalog_slug ||
      recon.provider_key?.fingerprint !== '8f7ea446a8707bea' ||
      recon.local_model_attempts !== 3 || recon.locally_accounted_model_calls !== 2 ||
      recon.matching_requests !== 2 || recon.raw_unknown_attempts !== 1 ||
      recon.closed_unknown_attempts !== 1 || recon.unreconciled_attempts !== 0 ||
      recon.actual_tokens !== 1586 || recon.actual_usd !== 0 ||
      recon.completeness?.complete !== true || recon.completeness?.unfiltered !== true ||
      recon.completeness?.includes_errors_and_cancellations !== true ||
      recon.completeness?.confirmed_by !== 'Daniil' || recon.completeness?.principal_id !== OWNER ||
      recon.provider_rows_verified_via_api !== true || recon.completeness_verified_via_api !== false ||
      !Array.isArray(recon.rows) || recon.rows.length !== 2) throw new Error('V14_THIRD_RECONCILIATION_INVALID');
  if (sidecar?.kind !== 's2-008-campaign-predictions/1' || sidecar.arm_id !== 'arm-model-zai-glm53flash' ||
      sidecar.seed !== 20260926 || sidecar.model_calls !== 2 || sidecar.spent_tokens !== 1586 ||
      sidecar.accounting?.policy !== 'GENERATION_ID_REQUIRED' || sidecar.accounting?.calls !== 2 ||
      sidecar.accounting?.tokens !== 1586 || sidecar.accounting?.rows?.length !== 2) throw new Error('V14_THIRD_SIDECAR_INVALID');
  if (known?.kind !== 's2-008-v13-known-generation-receipts/1' || known.raw_run_id !== run.raw_run_id ||
      known.raw_run_sha256 !== THIRD_RUN_SHA || known.provider !== 'openrouter' ||
      known.model !== V14_MODEL_POLICY.model || known.unknown_attempts_not_closed !== 1 ||
      !Array.isArray(known.rows) || known.rows.length !== 2 || known.rows.some((row) => row.http_status !== 404)) {
    throw new Error('V14_PRIOR_RECEIPT_LOOKUP_INVALID');
  }
  if (!Array.isArray(recheck.rows) || canonicalDigest(recheck.rows) !== canonicalDigest(recon.rows) ||
      recheck.rows.length !== 2 || recheck.rows.some((row) => row.http_status !== 200 ||
        row.provider_name !== 'Novita' || row.model !== V14_MODEL_POLICY.catalog_slug || row.total_cost !== 0 ||
        !Number.isSafeInteger(row.native_tokens_prompt) || !Number.isSafeInteger(row.native_tokens_completion) ||
        !Number.isSafeInteger(row.native_tokens_cached)) ||
      recheck.rows.reduce((sum, row) => sum + row.native_tokens_prompt + row.native_tokens_completion, 0) !== 1586) {
    throw new Error('V14_API_RECEIPT_RECHECK_INVALID');
  }
  const receiptIds = new Set(recheck.rows.map((row) => row.id));
  const localIds = new Set(sidecar.accounting.rows.map((row) => row.generation_id));
  if (receiptIds.size !== 2 || [...receiptIds].some((id) => !localIds.has(id)) ||
      known.rows.some((row) => !receiptIds.has(row.id))) throw new Error('V14_API_RECEIPT_IDS_INVALID');

  const failed = observation?.upstream_request, lookup = observation?.generation_api_lookup;
  if (observation?.kind !== 's2-008-v13-upstream-failure-observation/1' || observation.raw_run_id !== run.raw_run_id ||
      failed?.generation_id !== 'gen-1791296028-YhoZZaxE3YaBb6RMSa72' ||
      failed?.provider_name !== 'Novita' || failed?.model !== V14_MODEL_POLICY.catalog_slug ||
      failed?.status !== 429 || failed?.attempts !== 1 || failed?.failed_attempts !== 1 ||
      failed?.fallback_latency_ms !== 0 || failed?.total_latency_ms !== 266 ||
      lookup?.id !== failed.generation_id || lookup.http_status !== 404 || receiptIds.has(failed.generation_id) ||
      observation.clarification !== 'Two successful Generations plus one failed Upstream Request. Previous owner-confirmed two-row Generations view does not mean only two upstream requests. Raw run and previous reconciliation preserved; this observation supplements their provenance.') {
    throw new Error('V14_UPSTREAM_FAILURE_OBSERVATION_INVALID');
  }
  if (sha(inputs.wrongReconciliation.bytes) !== WRONG_SHA ||
      inputs.wrongReconciliation.value?.kind !== 's2-008-v13-a-reconciliation/1' ||
      sha(inputs.attributionCorrection.bytes) !== CORRECTION_SHA ||
      inputs.attributionCorrection.value?.kind !== 's2-008-v13-credential-attribution-correction/1' ||
      inputs.attributionCorrection.value?.status !== 'RECONCILIATION_REQUIRED' ||
      inputs.attributionCorrection.value?.invalidates?.sha256 !== WRONG_SHA ||
      inputs.attributionCorrection.value?.replacement_credential_fingerprint !== '8f7ea446a8707bea' ||
      inputs.attributionCorrection.value?.selected_credential_fingerprint !== '63ba91bbeb808e17' ||
      inputs.attributionCorrection.value?.raw_reports_unchanged !== true) throw new Error('V14_CREDENTIAL_CORRECTION_EVIDENCE_INVALID');

  const latestEvidenceTimes = [recon.created_at, inputs.attributionCorrection.value?.recorded_at,
    observation.recorded_at].map((value) => Date.parse(value ?? ''));
  if (latestEvidenceTimes.some((value) => !Number.isFinite(value))) throw new Error('V14_LINEAGE_CHRONOLOGY_INVALID');
  const latestBoundEvidenceAt = new Date(Math.max(...latestEvidenceTimes)).toISOString();
  return Object.freeze({
    kind: 's2-008-v14-v13-restart-closure/1',
    base_preregistration_digest: digest,
    latest_bound_evidence_at: latestBoundEvidenceAt,
    immutable_baseline_file: BASELINE_FILE,
    immutable_baseline_sha256: BASELINE_SHA,
    historical_old_key_reconciliations: [
      { file: 'evidence/s2-008-campaign/reconciliation-v13-a-first-old-key-confirmed.json',
        sha256: 'ee24a8b777c347623dab78e0828899fe8974cbdab7fe1287d79f5ba9bd31ac6f' },
      { file: 'evidence/s2-008-campaign/reconciliation-v13-a-second-old-key-confirmed.json',
        sha256: '80a45812ee995dc9f962100830a4f1a75cd410b1904a241ce1484ac3a16765e9' },
    ],
    third_attempt: {
      run_file: THIRD_RUN, run_sha256: THIRD_RUN_SHA,
      reconciliation_file: THIRD_RECON, reconciliation_sha256: THIRD_RECON_SHA,
      sidecar_file: SIDECAR, sidecar_sha256: SIDECAR_SHA,
      known_receipts_file: KNOWN, known_receipts_sha256: KNOWN_SHA,
      api_receipt_recheck_file: RECHECK, api_receipt_recheck_sha256: RECHECK_SHA,
      upstream_observation_file: UPSTREAM, upstream_observation_sha256: UPSTREAM_SHA,
      local_attempts: 3, successful_generations: 2, failed_upstream_requests: 1,
      owner_closed_unknown_attempts: 1, unreconciled_attempts: 0,
      known_tokens: 1586, known_usd: 0, third_failure_cost: null,
    },
    credential_attribution_correction_file: CORRECTION,
    credential_attribution_correction_sha256: CORRECTION_SHA,
    superseded_incorrect_reconciliation_file: WRONG,
    superseded_incorrect_reconciliation_sha256: WRONG_SHA,
    account_wide_completeness_claimed: false,
  });
}

export function assertV14BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger } = {}) {
  if (!base || !Buffer.isBuffer(baseBytes) || !manifest || !supersession ||
      !Buffer.isBuffer(supersessionBytes) || !table || !Array.isArray(ledger?.entries)) throw new Error('V14_BASE_INPUTS_MISSING');
  const digest = base.preregistration_digest;
  const expectedBaseApproval = { status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: OWNER,
    label: 'Daniil', issued_at: base.approval?.issued_at,
    signed_digest_over: APPROVAL_DIGEST_SCOPE, in_force: true,
    becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v13 records this digest and supersession in the corpus manifest' };
  if (sha(baseBytes) !== BASE_SHA || base.rule !== 's2-008-prereg-v13' ||
      base.preregistration_id !== 'xpr-s2-008c-13' || digest !== preregistrationDigest(base) ||
      base.status !== 'APPROVED' || canonicalDigest(base.approval) !== canonicalDigest(expectedBaseApproval) ||
      !Number.isFinite(Date.parse(base.approval?.issued_at ?? '')) ||
      base.budget_reservation?.granted_units !== 5000000 ||
      base.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      base.budget_reservation?.expires_at !== EXPIRY) throw new Error('V14_BASE_BINDING_INVALID');
  assertPreregistration(base);
  assertV14ExecutorPolicy({ ...base.executor, credential_source: V14_MODEL_POLICY.credential_source,
    model_call_pacing: { min_start_interval_ms: V14_MODEL_POLICY.min_start_interval_ms } });
  if (sha(supersessionBytes) !== 'c40fd6e8e84b9c84c01d74dc366c0326353d0c6abbf3b7f8df4c78947e0aa03e' ||
      supersession.kind !== 'SUPERSESSION' ||
      manifest.preregistration?.file !== BASE_FILE || manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== digest ||
      manifest.supersession?.file !== 'preregistration-v13-supersession.json' ||
      manifest.supersession.supersession_digest !== supersession.supersession_digest ||
      manifest.supersession_history?.at(-1)?.file !== 'preregistration-v13-supersession.json' ||
      manifest.supersession_history.at(-1).supersession_digest !== supersession.supersession_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v12-superseded.json' ||
      manifest.frozen_table?.digest !== canonicalDigest(table) || base.expected_table_digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1)?.anchor_digest) throw new Error('V14_BASE_MANIFEST_INVALID');
  assertSourceLedger(ledger.entries, { cases_digest: ledger.entries.at(-1)?.cases_digest,
    expected_table_digest: canonicalDigest(table) });
  return Object.freeze({ baseDigest: digest, tableDigest: canonicalDigest(table),
    supersessionDigest: supersession.supersession_digest, ledgerDigest: canonicalDigest(ledger) });
}

export function assertV14PresealPin({ pin, baseBytes, commitment = null } = {}) {
  const result = assertVersionedPresealPin({ pin, baseBytes, commitment, version: 14,
    requiredSources: ['pi_runtime_tree','timeout_policy','credential_env_policy','pi_shrinkwrap',
      'pi_package_manifest','pi_launcher','provider_model_catalog','model_call_pacing_policy'] });
  if (pin.first.sources.provider_model_catalog !== V14_MODEL_POLICY.catalog_sha256 ||
      pin.first.sources.model_call_pacing_policy === undefined) throw new Error('V14_MODEL_POLICY_PIN_INVALID');
  return result;
}

export function createV14Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV14RestartInputs() }) {
  const lineage = assertV14BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV14RestartReconciliation(base, restartInputs);
  if (!pin) throw new Error('V14_PRESEAL_PIN_REQUIRED');
  const { commitment, covers } = assertV14PresealPin({ pin, baseBytes });
  const timeout = assertV14ModelTimeoutPolicy(createV14ModelTimeoutPolicy());
  const executor = {
    ...base.executor, provider: V14_MODEL_POLICY.provider, model: V14_MODEL_POLICY.model,
    credential_env_name: V14_MODEL_POLICY.credential_env_name,
    credential_source: V14_MODEL_POLICY.credential_source,
    model_call_pacing: { min_start_interval_ms: V14_MODEL_POLICY.min_start_interval_ms },
    model_launch_timeout: timeout,
    pi_model_registration: structuredClone(V14_MODEL_POLICY.pi_model_registration),
    pi_model_catalog_binding: { file: 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json',
      sha256: V14_MODEL_POLICY.catalog_sha256, canonical_slug: V14_MODEL_POLICY.catalog_slug,
      prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY', cache_pricing: 'NOT_PROVIDED',
      client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE' },
    pi_settings: structuredClone(V7_PI_SETTINGS),
    model_image: { ...base.executor.model_image, content_commitment: commitment, covers, excludes: ['prereg'],
      built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v14.json',
      built_image_pin_reason: 'v14 binds Ling registration, catalog, explicit env credential and 60-second call pacing while preserving v13 science and A/B ceilings' },
  };
  assertV14ExecutorPolicy(executor);
  const draft = {
    ...base, rule: 's2-008-prereg-v14', preregistration_id: 'xpr-s2-008c-14', executor,
    budget_reservation: { ...base.budget_reservation, reservation_id: 'rsv-s2-008c-14',
      granted_units: 5000000, ceiling_scope: 'PER_RUN_A_OR_B', expires_at: EXPIRY },
    v13_restart_reconciliation: prior,
    supersession: { supersedes: base.preregistration_id, superseded_digest: lineage.baseDigest,
      scope: 'v14 call-start pacing and credential source; preserve exact frozen science, model identity, catalog, independent A/B ceilings, expiry and reconciled v13 history',
      reason: 'Add signed 60-second minimum spacing between model call starts after the v13 upstream 429, with provider retries disabled and v13 history closed.',
      unchanged: [...FROZEN_MEMBERS] },
    recorded_before_first_trial: { first_trial: 'NOT_STARTED',
      proof: 'Exact v13 in-force bytes, eleven immutable baseline inputs, both old-key closures, two successful provider generations, separate failed upstream request and owner closure bind before any v14 trial.' },
    status: 'DRAFT',
    approval: { status: null, authority: 'HUMAN_OWNER', principal_id: null, label: null, issued_at: null,
      signed_digest_over: APPROVAL_DIGEST_SCOPE, in_force: false, becomes_in_force_when: DRAFT_SEAL_TEXT },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertPreregistration(draft);
  if (draft.v13_restart_reconciliation?.base_preregistration_digest !== lineage.baseDigest ||
      draft.budget_reservation.granted_units !== base.budget_reservation.granted_units ||
      draft.budget_reservation.expires_at !== base.budget_reservation.expires_at) throw new Error('V14_PRIOR_BINDING_MISMATCH');
  return draft;
}

export function approveV14({ draft, base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV14RestartInputs(), principal, label, issuedAt }) {
  if (principal !== OWNER || label !== 'Daniil' || typeof issuedAt !== 'string' ||
      !Number.isFinite(Date.parse(issuedAt)) || Date.parse(issuedAt) >= Date.parse(EXPIRY)) throw new Error('V14_APPROVAL_IDENTITY_INVALID');
  if (draft?.rule !== 's2-008-prereg-v14' || draft.preregistration_id !== 'xpr-s2-008c-14') throw new Error('V14_VERSION_MISMATCH');
  if (draft.status !== 'DRAFT' || draft.approval?.status !== null) throw new Error('V14_ALREADY_SIGNED');
  assertV14DraftApprovalMetadata(draft.approval);
  if (draft.preregistration_digest !== preregistrationDigest(draft)) throw new Error('V14_DIGEST_MISMATCH');
  const lineage = assertV14BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV14RestartReconciliation(base, restartInputs);
  const latestEvidenceTime = Date.parse(prior.latest_bound_evidence_at);
  const earliest = Math.max(Date.parse(base.approval.issued_at), latestEvidenceTime);
  if (!Number.isFinite(earliest) || Date.parse(issuedAt) < earliest) throw new Error('V14_APPROVAL_CHRONOLOGY_INVALID');
  if (canonicalDigest(draft.v13_restart_reconciliation) !== canonicalDigest(prior) ||
      draft.supersession?.superseded_digest !== lineage.baseDigest ||
      draft.expected_table_digest !== canonicalDigest(table)) throw new Error('V14_PRIOR_BINDING_MISMATCH');
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertV14PresealPin({ pin, baseBytes, commitment: draft.executor?.model_image?.content_commitment });
  const expected = createV14Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin, restartInputs });
  if (canonicalDigest(scientificBody(expected)) !== canonicalDigest(scientificBody(draft))) throw new Error('V14_SCOPE_MISMATCH');
  const signed = { ...scientificBody(draft), status: 'APPROVED', approval: { ...draft.approval,
    status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: principal, label, issued_at: issuedAt, in_force: false } };
  return Object.freeze({ ...signed, preregistration_digest: preregistrationDigest(signed) });
}
