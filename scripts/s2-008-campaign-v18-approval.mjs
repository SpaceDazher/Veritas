import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, preregistrationDigest } from '../src/lib/research/index.mjs';
import { assertContentSupersession, createContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { FROZEN_MEMBERS, scopeDrift, scientificBody } from './s2-008-campaign-approve.mjs';
import { V7_PI_SETTINGS } from './s2-008-campaign-credential-env.mjs';
import { assertVersionedPresealPin } from './s2-008-campaign-v6-approval.mjs';
import { createV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';
import { assertV17SuccessorOnDisk, V17_SUPERSESSION_REASON } from './s2-008-campaign-v17-approval.mjs';
import { V17_MODEL_POLICY } from './s2-008-campaign-v17-policy.mjs';
import { V18_MODEL_POLICY, assertV18ModelCatalogFiles, assertV18ExecutorPolicy, assertV18PreregistrationPolicy } from './s2-008-campaign-v18-policy.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = 'prn-s2007r-owner';
const BASE_DIGEST = '8a2df9a2c37751098a28706bddf71dcff5b58656886baabceff2712b2798742f';
const BASE_FILE = 'corpus/s2-008-campaign/preregistration.v17.in-force.json';
const BASE_NAME = 'preregistration.v17.in-force.json';
const EXPIRY = '2026-11-07T00:00:00.000Z';
const DIGEST_SCOPE = 'the scientific body: every member except approval, status and preregistration_digest';
const SEAL_TEXT = 'scripts/s2-008-campaign-prepare.mjs --seal-v18 records this digest and supersession in the corpus manifest';
const OWNER_STATEMENT = '\u0414\u0430, \u043e\u0442\u0434\u0435\u043b\u044c\u043d\u044b\u0439 \u043d\u043e\u0432\u044b\u0439 A \u043f\u043e \u043d\u043e\u0432\u043e\u043c\u0443 \u043f\u0440\u043e\u0442\u043e\u043a\u043e\u043b\u0443';
const STOPPED = 'evidence/s2-008-campaign/v17-a-stopped/';
export const V18_PRIOR_EXECUTION_FILES = Object.freeze([
  ['controlPin', STOPPED + 'control-image-pin-v17-a.json', 1296, '1874c8ba659c28c9b687d73b84b33a1ab5f86186290153419aceca6884d222e1'],
  ['partialAccounting', STOPPED + 'partial-accounting.json', 4904, '44bbfa20ca6dcb02004be3ed9f4b1b486bde3620d2ffdfb4b401382c021a0c58'],
  ['predictions', STOPPED + 'predictions-v17-a-trl-s2-008c-01-20260926.json', 6241, '0b9d5cc7d1c874fe5fbf240f1acb3a6d6603704ddf9ed4952f0d0bfc77041cd9'],
  ['receipt01', STOPPED + 'receipt-gen-1793462712-6lomKmXRaHbYZVDMPkVM.json', 2169, '35d15e86858f27bd66b3023a74c15628c691df507c4a10e95d121c87ed1bf4e9'],
  ['receipt02', STOPPED + 'receipt-gen-1793462774-xa7gar6aOjZvKJa8yWg3.json', 2169, 'c22874b6236cdbf68284d0c64e2bcb71db81b88e547869937b96b8738447fbd7'],
  ['receipt03', STOPPED + 'receipt-gen-1793462832-ZtEpuhojLUk42yHHkHc2.json', 2173, '312e2bbbb4e8f1d7f742be3ccad5751737dcf1371e4427a236548297e8ca982c'],
  ['receipt04', STOPPED + 'receipt-gen-1793462892-wa7UIMr4xG4ab7w0Btf5.json', 2171, '3a56e09c21e98878e245ef78611f9250f99436bdeadb351715348a406c92734e'],
  ['receipt05', STOPPED + 'receipt-gen-1793462952-QJFT6TdtM75kPuvFQ8lx.json', 2171, 'f25d878d5f8eda51a65fc5f3e99382fa13ecd8e154c7cc9db04d6a99b6783eb3'],
  ['receipt06', STOPPED + 'receipt-gen-1793463012-9SRDqNLWGfBBBMrl3pXZ.json', 2173, '52c7d807539115c25a54b0a55a4d0e6888d8c6dc8ccbabbf06b1e45fd52959c4'],
  ['receipt07', STOPPED + 'receipt-gen-1793463076-m70F1gJNfQyZvTNB84as.json', 2170, '03fac0844b860762bc40a34866bc54f6db6e6fb996df3056df4ab1c48ae2c2b2'],
  ['receipt08', STOPPED + 'receipt-gen-1793463132-MdxojDUo8V9BtGlZdqYg.json', 2169, '00902ae9576f4e36fcdcd44f29f98f4b26769fb9a91a177b1a8436846b2fa189'],
  ['receipt09', STOPPED + 'receipt-gen-1793463195-6uxQQFWYZX191Zn9zkuF.json', 2169, '1e4bf55310f952faa8cccbb4aa70bc408604978bf321980167fa81377ddd88ce'],
  ['receipt10', STOPPED + 'receipt-gen-1793463252-COJnaIbfT8Xjc5jK0jwg.json', 2168, 'b77e4fff52390c7917e0df11bb62dee144fc7cdc8ebee3a3b87ac59eeb216e5c'],
  ['reconciliation', STOPPED + 'request-outcome-reconciliation.json', 1912, 'cafc6ad2c55f55dc6271ba4a2b38bd37738fd81d6cd98ca7df598078a79b3b08'],
  ['run', STOPPED + 'run-v17-a.json', 23781, '2aa18416cdb8cd42c5800d872c6c7b95c42ef5694b1955e117a8a559fe7aa31c'],
  ['status', STOPPED + 'status.json', 961, '17f5a20808e54a3ad857f29a7d0dee9991fecb727b77b3c455139ac04446500a'],
]);
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const parse = (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8'));
const rows = () => V18_PRIOR_EXECUTION_FILES.map(([, file, bytes, sha256]) => ({ file, bytes, sha256 }));
export const V18_RECOVERY_EVIDENCE_DIGEST = canonicalDigest(rows());

function safeRead(root, relative) {
  const realRoot = fs.realpathSync(root), full = path.resolve(realRoot, relative);
  if (!full.startsWith(realRoot + path.sep)) throw new Error('V18_INPUT_PATH_INVALID');
  const stat = fs.lstatSync(full);
  if (!stat.isFile() || stat.isSymbolicLink() || fs.realpathSync(full) !== full) throw new Error('V18_INPUT_FILE_UNSAFE');
  return fs.readFileSync(full);
}
function v17ManifestView(active, base) {
  if (active?.preregistration?.file === BASE_NAME && active.preregistration.status === 'IN_FORCE') return active;
  const history = active?.supersession_history;
  const index = Array.isArray(history) ? history.findIndex((row) => row.file === 'preregistration-v17-supersession.json') : -1;
  if (active?.preregistration?.file !== 'preregistration.v18.in-force.json' || index < 0) throw new Error('V18_BASE_MANIFEST_INVALID');
  return { ...active,
    preregistration: { file: BASE_NAME, status: 'IN_FORCE', preregistration_digest: base.preregistration_digest, sealed_before_first_trial: true },
    supersession: history[index], supersession_history: history.slice(0, index + 1),
    superseded_preregistration: { file: 'preregistration-v16-superseded.json',
      preregistration_digest: base.v16_prior_execution_reconciliation?.base_preregistration_digest,
      status: 'SUPERSEDED', superseded_by: BASE_NAME },
  };
}

export function readV18BaseInputs({ repoRoot = ROOT, allowHistorical = false } = {}) {
  const baseBytes = safeRead(repoRoot, BASE_FILE), base = parse(baseBytes);
  const activeManifest = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/manifest.json'));
  if (!allowHistorical && activeManifest.preregistration?.file !== BASE_NAME) throw new Error('V18_BASE_NOT_CURRENT');
  if (activeManifest.preregistration?.file === BASE_NAME) assertV17SuccessorOnDisk(repoRoot);
  const manifest = v17ManifestView(activeManifest, base);
  const supersessionBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v17-supersession.json');
  const supersession = parse(supersessionBytes);
  const table = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/frozen-table.v3.json'));
  const ledger = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/source-ledger.v3.json'));
  const v16Bytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v16-superseded.json');
  if (hash(baseBytes) !== '376b0704df7ae4920ab7341c01ba70128f98677d5ef9334c59380fa9c5b85e07' ||
      base.rule !== 's2-008-prereg-v17' || base.preregistration_id !== 'xpr-s2-008c-17' ||
      base.status !== 'APPROVED' || base.approval?.status !== 'APPROVED' ||
      base.approval?.authority !== 'HUMAN_OWNER' || base.approval?.principal_id !== OWNER ||
      base.approval?.label !== 'Daniil' || base.approval?.in_force !== true ||
      base.preregistration_digest !== BASE_DIGEST || base.preregistration_digest !== preregistrationDigest(base) ||
      manifest.preregistration?.preregistration_digest !== BASE_DIGEST ||
      manifest.supersession?.file !== 'preregistration-v17-supersession.json' ||
      manifest.supersession.supersession_digest !== supersession.supersession_digest ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger.entries?.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries?.at(-1)?.anchor_digest) {
    throw new Error('V18_BASE_BINDING_INVALID');
  }
  assertPreregistration(base);
  assertV18ModelCatalogFiles(path.join(repoRoot, V18_MODEL_POLICY.catalog_file),
    path.join(repoRoot, V18_MODEL_POLICY.endpoint_catalog_file), path.join(repoRoot, V18_MODEL_POLICY.catalog_response_file));
  assertContentSupersession(supersession, parse(v16Bytes), base);
  return { repoRoot, base, baseBytes, manifest, activeManifest, supersession, supersessionBytes, table, ledger };
}

export function readV18PriorExecutionInputs({ repoRoot = ROOT } = {}) {
  const directory = path.join(repoRoot, 'evidence/s2-008-campaign/v17-a-stopped');
  const names = V18_PRIOR_EXECUTION_FILES.map(([, file]) => path.basename(file)).sort();
  if (canonicalDigest(fs.readdirSync(directory).sort()) !== canonicalDigest(names)) throw new Error('V18_PRIOR_EXECUTION_ARTIFACT_SET_INVALID');
  const inputs = { repoRoot, artifacts: [] };
  for (const [key, file, expectedBytes, expectedSha] of V18_PRIOR_EXECUTION_FILES) {
    const bytes = safeRead(repoRoot, file);
    if (bytes.length !== expectedBytes || hash(bytes) !== expectedSha) throw new Error('V18_PRIOR_EXECUTION_ARTIFACT_BINDING_INVALID');
    const item = { file, bytes, sha256: expectedSha, value: parse(bytes) };
    inputs[key] = item;
    inputs.artifacts.push(item);
  }
  return inputs;
}

export function assertV18PriorExecutionReconciliation(inputs = readV18PriorExecutionInputs()) {
  if (!inputs || !Array.isArray(inputs.artifacts) || inputs.artifacts.length !== V18_PRIOR_EXECUTION_FILES.length) {
    throw new Error('V18_PRIOR_EXECUTION_ARTIFACT_BINDING_INVALID');
  }
  for (const [key, file, expectedBytes, expectedSha] of V18_PRIOR_EXECUTION_FILES) {
    const item = inputs[key];
    if (item?.file !== file || !Buffer.isBuffer(item.bytes) || item.bytes.length !== expectedBytes ||
        hash(item.bytes) !== expectedSha || item.sha256 !== expectedSha ||
        canonicalDigest(item.value ?? null) !== canonicalDigest(parse(item.bytes))) {
      throw new Error('V18_PRIOR_EXECUTION_ARTIFACT_BINDING_INVALID');
    }
  }
  const run = inputs.run.value, closure = inputs.reconciliation.value;
  const accounting = inputs.partialAccounting.value, status = inputs.status.value;
  const prediction = inputs.predictions.value;
  const runId = 's2-008c-v17-a-3bfe162cc5774fa38a3a';
  if (run?.raw_run_id !== runId || run.status !== 'BLOCKED' || run.code !== 'CHARGE_NOT_MEASURABLE' ||
      run.preregistration_digest !== BASE_DIGEST || run.model_calls !== 10 || run.unknown_model_attempts !== 1 ||
      run.spent_units !== 11677 || run.spent_units_is_lower_bound !== true || run.unreconciled_spend !== true ||
      closure?.kind !== 's2-008-v17-request-outcome-reconciliation/1' ||
      closure.status !== 'REQUEST_OUTCOMES_CLASSIFIED_FINANCE_INCOMPLETE' || closure.raw_run_id !== runId ||
      closure.preregistration_digest !== BASE_DIGEST || closure.raw_run_sha256 !== inputs.run.sha256 ||
      closure.local_model_attempts !== 11 || closure.successful_generations !== 10 ||
      closure.known_tokens_lower_bound !== 11677 || closure.known_provider_usd_lower_bound !== 0 ||
      closure.classified_unknown_attempts !== 1 || closure.unclassified_attempts !== 0 ||
      closure.failed_generation_id !== null || closure.failed_request_tokens_confirmed !== null ||
      closure.failed_request_usd_confirmed !== null || closure.total_tokens_confirmed !== null ||
      closure.total_usd_confirmed !== null || closure.financial_reconciliation_complete !== false ||
      closure.raw_unreconciled_spend_preserved !== true || closure.no_cost_claim_for_failed_request !== true ||
      closure.account_wide_completeness_claimed !== false || closure.retry_performed !== false ||
      closure.B !== 'NOT_RUN' || closure.A_MVP_05 !== 'NOT_RUN_HUMAN_REVIEW_REQUIRED' ||
      closure.completeness?.complete !== true || closure.completeness.unfiltered !== true ||
      closure.completeness.includes_errors_and_cancellations !== true ||
      closure.completeness.basis !== 'DIRECT_OWNER_UNFILTERED_MINUTE_ATTESTATION' ||
      closure.completeness.confirmed_by !== 'Daniil' ||
      closure.completeness.UTC_interval?.[0] !== '2026-10-31T16:15:00Z' ||
      closure.completeness.UTC_interval?.[1] !== '2026-10-31T16:15:59Z' || closure.known_rows_verified_via_api !== true ||
      accounting?.kind !== 's2-008-v17-stopped-partial-accounting/1' || accounting.raw_run_id !== runId ||
      accounting.raw_run_sha256 !== inputs.run.sha256 || accounting.known_local_calls !== 10 ||
      accounting.known_receipts_verified !== 10 || accounting.local_tokens_lower_bound !== 11677 ||
      accounting.known_provider_usd !== 0 || accounting.financially_reconciled !== false ||
      accounting.receipts?.length !== 10 || accounting.B !== 'NOT_RUN' || accounting.independent_evaluation !== 'NOT_RUN' ||
      prediction?.accounting?.calls !== 10 || prediction.accounting.tokens !== 11677 ||
      status?.result?.raw_run_id !== runId || status.result.model_calls !== 10 ||
      status.result.unknown_model_attempts !== 1 || status.result.spent_units !== 11677 ||
      status.result.unreconciled_spend !== true) throw new Error('V18_PRIOR_EXECUTION_RECONCILIATION_INVALID');

  const receipts = V18_PRIOR_EXECUTION_FILES.filter(([key]) => key.startsWith('receipt')).map(([key]) => inputs[key].value);
  let tokens = 0;
  for (const ref of accounting.receipts) {
    const receipt = receipts.find((row) => row.body?.data?.id === ref.generation_id);
    if (!receipt || ref.api_http_status !== 200 || ref.matches_local !== true || receipt.http_status !== 200 ||
        receipt.lookup_error !== null || receipt.body.data.provider_name !== 'Nvidia' ||
        receipt.body.data.model !== V17_MODEL_POLICY.endpoint_slug ||
        receipt.body.data.native_tokens_prompt !== ref.native_prompt ||
        receipt.body.data.native_tokens_completion !== ref.native_completion ||
        receipt.body.data.native_tokens_cached !== ref.native_cached || receipt.body.data.total_cost !== ref.total_cost) {
      throw new Error('V18_PRIOR_EXECUTION_RECEIPT_BINDING_INVALID');
    }
    tokens += ref.native_prompt + ref.native_completion;
  }
  const controlPin = inputs.controlPin.value;
  const runRef = run.control_image_pin_artifact;
  if (tokens !== 11677 || runRef?.file !== 'evidence/s2-008-campaign/control-image-pin-v17-a.json' ||
      runRef.bytes !== inputs.controlPin.bytes.length || runRef.sha256 !== inputs.controlPin.sha256 ||
      canonicalDigest(run.control_image_pin) !== canonicalDigest(controlPin.control_image_pin)) {
    throw new Error('V18_PRIOR_EXECUTION_ARTIFACT_LINK_INVALID');
  }
  return Object.freeze({
    kind: 's2-008-v18-predecessor-outcome-binding/1', prior_raw_run_id: runId,
    prior_preregistration_digest: BASE_DIGEST, prior_raw_run_sha256: inputs.run.sha256,
    prior_closure_sha256: inputs.reconciliation.sha256,
    prior_partial_accounting_sha256: inputs.partialAccounting.sha256,
    disposition: 'RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO', prior_outcome: 'INFRA',
    known_model_calls: 10, known_tokens_lower_bound: 11677, known_provider_usd_lower_bound: 0,
    classified_unknown_attempts: 1, unclassified_attempts: 0, failed_generation_id: null,
    failed_request_tokens_confirmed: null, failed_request_usd_confirmed: null,
    total_tokens_confirmed: null, total_usd_confirmed: null,
    financial_reconciliation_complete: false, raw_unreconciled_spend_preserved: true,
    retry_performed: false, account_wide_completeness_claimed: false,
    owner_completeness_attestation: structuredClone(closure.completeness), immutable_artifacts: rows(),
  });
}

export function assertV18PresealPin({ pin, baseBytes, commitment = null } = {}) {
  const result = assertVersionedPresealPin({ pin, baseBytes, commitment, version: 18,
    requiredSources: ['pi_runtime_tree','timeout_policy','credential_env_policy','pi_shrinkwrap','pi_package_manifest',
      'pi_launcher','provider_model_catalog','provider_model_catalog_response','provider_model_endpoint_catalog',
      'v17_model_policy','v18_model_policy','v18_approval_policy','v18_seal_policy','v18_predecessor_evidence','model_call_pacing_policy'] });
  if (pin.first.sources.provider_model_catalog !== V17_MODEL_POLICY.catalog_sha256 ||
      pin.first.sources.provider_model_catalog_response !== V17_MODEL_POLICY.catalog_response_sha256 ||
      pin.first.sources.provider_model_endpoint_catalog !== V17_MODEL_POLICY.endpoint_catalog_sha256 ||
      pin.first.sources.v18_predecessor_evidence !== V18_RECOVERY_EVIDENCE_DIGEST) throw new Error('V18_MODEL_POLICY_PIN_INVALID');
  return result;
}

export function assertV18BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, repoRoot = ROOT } = {}) {
  if (!Buffer.isBuffer(baseBytes) || !base || !manifest || !supersession || !Buffer.isBuffer(supersessionBytes) ||
      !table || !Array.isArray(ledger?.entries) || hash(baseBytes) !== '376b0704df7ae4920ab7341c01ba70128f98677d5ef9334c59380fa9c5b85e07' ||
      canonicalDigest(base) !== canonicalDigest(parse(baseBytes)) || base.preregistration_digest !== BASE_DIGEST ||
      base.preregistration_digest !== preregistrationDigest(base) || base.rule !== 's2-008-prereg-v17' ||
      base.status !== 'APPROVED' || base.approval?.in_force !== true) throw new Error('V18_BASE_BINDING_INVALID');
  const currentManifest = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/manifest.json'));
  if (currentManifest.preregistration?.file === BASE_FILE) assertV17SuccessorOnDisk(repoRoot);
  if (manifest.preregistration?.file !== BASE_NAME || manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== BASE_DIGEST ||
      manifest.supersession?.file !== 'preregistration-v17-supersession.json' ||
      manifest.supersession.supersession_digest !== supersession.supersession_digest ||
      manifest.supersession_history?.at(-1)?.supersession_digest !== supersession.supersession_digest ||
      manifest.frozen_table?.digest !== canonicalDigest(table) || manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1)?.anchor_digest ||
      supersession.kind !== 'SUPERSESSION' || supersession.replaced_by_preregistration_digest !== BASE_DIGEST ||
      canonicalDigest(supersession) !== canonicalDigest(parse(supersessionBytes))) throw new Error('V18_BASE_BINDING_INVALID');
  assertContentSupersession(supersession, parse(safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v16-superseded.json')), base);
  return { baseDigest: BASE_DIGEST, tableDigest: canonicalDigest(table), ledgerDigest: canonicalDigest(ledger) };
}

function recoveryAuthorization(predecessor, issuedAt = null) {
  return { kind: 's2-008-v18-authorized-recovery/1',
    authorization_status: 'OWNER_APPROVAL_BINDS_TO_SIGNED_PREREGISTRATION',
    authorization_basis: { source: 'EXPLICIT_HUMAN_OWNER_APPROVAL', statement: OWNER_STATEMENT },
    predecessor: structuredClone(predecessor),
    authorization_scope: { protocol_version: 18, maximum_new_a_runs: 1, maximum_new_b_runs: 1,
      maximum_total_new_runs: 2, b_condition: 'A_FULLY_MEASURED_AND_RECEIPTS_RECONCILED',
      same_run_retry_permitted: false, on_infra: 'RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO',
      automatic_next_version_permitted: false },
    owner_approval: { authority: 'HUMAN_OWNER', principal_id: issuedAt ? OWNER : null,
      label: issuedAt ? 'Daniil' : null, issued_at: issuedAt, in_force: Boolean(issuedAt) },
  };
}

export function assertV18RecoveryAuthorization(prereg, predecessor = assertV18PriorExecutionReconciliation()) {
  if (prereg?.rule !== 's2-008-prereg-v18' || prereg.preregistration_id !== 'xpr-s2-008c-18' ||
      canonicalDigest(prereg.recovery_authorization ?? null) !== canonicalDigest(recoveryAuthorization(predecessor, prereg.approval?.issued_at)) ||
      prereg.recovery_authorization?.owner_approval?.principal_id !== OWNER ||
      prereg.recovery_authorization?.owner_approval?.label !== 'Daniil' ||
      prereg.recovery_authorization?.owner_approval?.in_force !== true ||
      prereg.approval?.principal_id !== OWNER || prereg.approval?.label !== 'Daniil' ||
      prereg.approval?.in_force !== true || prereg.preregistration_digest !== preregistrationDigest(prereg)) {
    throw new Error('V18_RECOVERY_AUTHORIZATION_INVALID');
  }
  return true;
}

export function createV18Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger,
  pin, repoRoot = ROOT, restartInputs = readV18PriorExecutionInputs({ repoRoot }) } = {}) {
  const lineage = assertV18BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, repoRoot });
  const predecessor = assertV18PriorExecutionReconciliation(restartInputs);
  if (!pin) throw new Error('V18_PRESEAL_PIN_REQUIRED');
  const { commitment, covers } = assertV18PresealPin({ pin, baseBytes });
  assertV18ModelCatalogFiles(path.join(repoRoot, V18_MODEL_POLICY.catalog_file),
    path.join(repoRoot, V18_MODEL_POLICY.endpoint_catalog_file), path.join(repoRoot, V18_MODEL_POLICY.catalog_response_file));
  const executor = { ...structuredClone(base.executor), model_call_pacing: { min_start_interval_ms: 60000 },
    model_launch_timeout: createV14ModelTimeoutPolicy(), pi_settings: structuredClone(V7_PI_SETTINGS),
    pi_model_registration: structuredClone(V18_MODEL_POLICY.pi_model_registration),
    model_image: { ...base.executor.model_image, content_commitment: commitment, covers, excludes: ['prereg'],
      built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v18.json',
      built_image_pin_reason: 'v18 binds one owner-authorized A and one conditional B after classified v17 INFRA while preserving frozen science.' } };
  assertV18ExecutorPolicy(executor);
  const draft = { ...base, rule: 's2-008-prereg-v18', preregistration_id: 'xpr-s2-008c-18', executor,
    budget_reservation: { ...base.budget_reservation, reservation_id: 'rsv-s2-008c-18',
      granted_units: 5000000, ceiling_scope: 'PER_RUN_A_OR_B', expires_at: EXPIRY },
    v17_prior_execution_reconciliation: predecessor,
    recovery_authorization: recoveryAuthorization(predecessor),
    supersession: { supersedes: base.preregistration_id, superseded_digest: lineage.baseDigest,
      scope: 'Preserve all 15 frozen science fields; authorize exactly one fresh v18 A after classified v17 INFRA and at most one B after fully measured, receipts-reconciled A.',
      reason: 'The owner-authorized v18 successor binds every immutable v17 stopped artifact and preserves unknown historical totals as null.',
      unchanged: [...FROZEN_MEMBERS] },
    recorded_before_first_trial: { first_trial: 'NOT_STARTED',
      proof: 'The v17 signed predecessor, outcome closure, raw report and all stopped artifacts are hash-bound before any v18 trial.' },
    status: 'DRAFT', approval: { status: null, authority: 'HUMAN_OWNER', principal_id: null, label: null,
      issued_at: null, signed_digest_over: DIGEST_SCOPE, in_force: false, becomes_in_force_when: SEAL_TEXT } };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  for (const member of FROZEN_MEMBERS) if (canonicalDigest(draft[member] ?? null) !== canonicalDigest(base[member] ?? null)) {
    throw new Error('V18_SCIENCE_SCOPE_DRIFT:' + member);
  }
  assertPreregistration(draft);
  assertV18PreregistrationPolicy(draft);
  return draft;
}

export function approveV18({ draft, base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV18PriorExecutionInputs(), principal, label, issuedAt, repoRoot = ROOT } = {}) {
  if (principal !== OWNER || label !== 'Daniil' || typeof issuedAt !== 'string' ||
      !Number.isFinite(Date.parse(issuedAt)) || Date.parse(issuedAt) >= Date.parse(EXPIRY)) throw new Error('V18_APPROVAL_IDENTITY_INVALID');
  if (draft?.rule !== 's2-008-prereg-v18' || draft.preregistration_id !== 'xpr-s2-008c-18') throw new Error('V18_VERSION_MISMATCH');
  if (draft.status !== 'DRAFT' || draft.approval?.status !== null || draft.approval.authority !== 'HUMAN_OWNER' ||
      draft.approval.principal_id !== null || draft.approval.label !== null || draft.approval.issued_at !== null ||
      draft.approval.signed_digest_over !== DIGEST_SCOPE || draft.approval.in_force !== false ||
      draft.approval.becomes_in_force_when !== SEAL_TEXT ||
      Object.keys(draft.approval).sort().join(',') !== 'authority,becomes_in_force_when,in_force,issued_at,label,principal_id,signed_digest_over,status') {
    throw new Error('V18_APPROVAL_METADATA_INVALID');
  }
  assertV18PreregistrationPolicy(draft);
  if (draft.preregistration_digest !== preregistrationDigest(draft)) throw new Error('V18_DIGEST_MISMATCH');
  const lineage = assertV18BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, repoRoot });
  const predecessor = assertV18PriorExecutionReconciliation(restartInputs);
  if (canonicalDigest(draft.v17_prior_execution_reconciliation) !== canonicalDigest(predecessor) ||
      canonicalDigest(draft.recovery_authorization) !== canonicalDigest(recoveryAuthorization(predecessor)) ||
      draft.supersession?.superseded_digest !== lineage.baseDigest || draft.expected_table_digest !== canonicalDigest(table)) {
    throw new Error('V18_PRIOR_BINDING_MISMATCH');
  }
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertV18PresealPin({ pin, baseBytes, commitment: draft.executor?.model_image?.content_commitment });
  const expected = createV18Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin, restartInputs, repoRoot });
  if (canonicalDigest(scientificBody(expected)) !== canonicalDigest(scientificBody(draft))) throw new Error('V18_SCOPE_MISMATCH');
  const signed = { ...scientificBody(draft), status: 'APPROVED', approval: { ...draft.approval,
    status: 'APPROVED', principal_id: principal, label, issued_at: issuedAt } };
  signed.recovery_authorization = recoveryAuthorization(predecessor, issuedAt);
  signed.preregistration_digest = preregistrationDigest(signed);
  return Object.freeze(signed);
}

const defaultState = path.join(os.userInfo().homedir, '.local/state/veritas/s2-008-v18-authorization');
function authFile(stateDir, digest, label) {
  if (!['a', 'b'].includes(label)) throw new Error('V18_RUN_AUTHORIZATION_LABEL_INVALID');
  if (!/^[a-f0-9]{64}$/.test(digest ?? '')) throw new Error('V18_RUN_AUTHORIZATION_DIGEST_INVALID');
  return path.join(path.resolve(stateDir ?? defaultState), digest + '-' + label + '.json');
}
function syncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function currentBase(repoRoot) {
  return { commit: execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    tree: execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim() };
}
export function reserveV18RunAuthorization({ prereg, label, runId, stateDir, dryRun = false, repoRoot = ROOT } = {}) {
  assertV18PreregistrationPolicy(prereg);
  if (prereg.approval?.in_force !== true || prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      prereg.recovery_authorization?.authorization_status !== 'OWNER_APPROVAL_BINDS_TO_SIGNED_PREREGISTRATION' ||
      prereg.recovery_authorization?.owner_approval?.principal_id !== OWNER ||
      prereg.recovery_authorization?.owner_approval?.in_force !== true ||
      prereg.recovery_authorization.authorization_scope?.maximum_new_a_runs !== 1 ||
      prereg.recovery_authorization.authorization_scope?.maximum_new_b_runs !== 1) throw new Error('V18_RUN_AUTHORIZATION_INVALID');
  if (dryRun) return { consumed: false, reason: 'DRY_RUN' };
  if (typeof runId !== 'string' || !new RegExp('^s2-008c-v18-' + label + '-[A-Za-z0-9-]{1,50}$').test(runId)) {
    throw new Error('V18_RUN_AUTHORIZATION_RUN_ID_INVALID');
  }
  const file = authFile(stateDir, prereg.preregistration_digest, label);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const record = { kind: 's2-008-v18-run-authorization-reservation/1', preregistration_digest: prereg.preregistration_digest,
    label, run_id: runId, reserved_at: new Date().toISOString(), source_base: currentBase(repoRoot), completion: null };
  try {
    const fd = fs.openSync(file, 'wx', 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(record) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    syncDirectory(path.dirname(file));
  } catch (error) { if (error?.code === 'EEXIST') throw new Error('V18_RUN_AUTHORIZATION_ALREADY_CONSUMED'); throw error; }
  return { consumed: true, file, record };
}

export function completeV18RunAuthorization({ prereg, label, runId, stateDir, reportPath, evidenceRoot, repoRoot = ROOT } = {}) {
  const file = authFile(stateDir, prereg?.preregistration_digest, label);
  const current = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (current.run_id !== runId || current.label !== label || current.completion !== null ||
      current.preregistration_digest !== prereg.preregistration_digest) throw new Error('V18_RUN_AUTHORIZATION_RESERVATION_INVALID');
  const reportBytes = fs.readFileSync(reportPath), report = parse(reportBytes);
  const completion = { kind: 's2-008-v18-run-authorization-completion/1', run_id: runId, label,
    preregistration_digest: prereg.preregistration_digest, report_path: fs.realpathSync(reportPath),
    report_sha256: hash(reportBytes), report_bytes: reportBytes.length, report_status: report.status,
    unknown_model_attempts: report.unknown_model_attempts, evidence_root: fs.realpathSync(evidenceRoot),
    base: { commit: report.base?.commit_sha, tree: report.base?.tree_sha }, raw_run_id: report.raw_run_id,
    completed_at: new Date().toISOString() };
  const temp = file + '.next-' + process.pid + '-' + randomBytes(6).toString('hex');
  const fd = fs.openSync(temp, 'wx', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify({ ...current, completion }) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temp, file);
  syncDirectory(path.dirname(file));
  return completion;
}

function readExternal(root, relative) {
  const realRoot = fs.realpathSync(root), full = path.resolve(realRoot, relative);
  if (!full.startsWith(realRoot + path.sep)) throw new Error('V18_A_EVIDENCE_PATH_INVALID');
  const stat = fs.lstatSync(full);
  if (!stat.isFile() || stat.isSymbolicLink() || fs.realpathSync(full) !== full) throw new Error('V18_A_EVIDENCE_FILE_UNSAFE');
  return fs.readFileSync(full);
}
export async function assertV18BEligibility({ repoRoot = ROOT, prereg, stateDir, aEvidenceRoot = null } = {}) {
  let reservation;
  try { reservation = JSON.parse(fs.readFileSync(authFile(stateDir, prereg?.preregistration_digest, 'a'), 'utf8')); }
  catch { throw new Error('V18_B_REQUIRES_RECONCILED_A'); }
  const done = reservation.completion;
  if (!done || done.kind !== 's2-008-v18-run-authorization-completion/1' || done.label !== 'a' ||
      done.preregistration_digest !== prereg.preregistration_digest || reservation.source_base?.commit !== currentBase(repoRoot).commit ||
      reservation.source_base?.tree !== currentBase(repoRoot).tree) throw new Error('V18_B_REQUIRES_RECONCILED_A');
  const root = fs.realpathSync(aEvidenceRoot ?? done.evidence_root);
  if (root !== done.evidence_root) throw new Error('V18_A_EVIDENCE_ROOT_MISMATCH');
  const reportBytes = fs.readFileSync(done.report_path);
  if (reportBytes.length !== done.report_bytes || hash(reportBytes) !== done.report_sha256) throw new Error('V18_A_REPORT_BINDING_INVALID');
  const report = parse(reportBytes);
  const paid = await import('./s2-008-paid-review.mjs');
  const validated = paid.validateV18CompletedAForRecovery({ report, reportBytes, prereg, evidenceRoot: root, repoRoot });
  if (!validated.ok || validated.raw_run_id !== done.raw_run_id || validated.report_sha256 !== done.report_sha256) {
    throw new Error('V18_B_REQUIRES_RECONCILED_A');
  }
  return { ...validated, evidence_root: root };
}
