import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertContentSupersession, createContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { assertPreregistration, assertSourceLedger, preregistrationDigest } from '../src/lib/research/index.mjs';
import { FROZEN_MEMBERS, scopeDrift, scientificBody } from './s2-008-campaign-approve.mjs';
import { V7_PI_SETTINGS } from './s2-008-campaign-credential-env.mjs';
import { assertV16PreregistrationPolicy } from './s2-008-campaign-v16-policy.mjs';
import { assertVersionedPresealPin } from './s2-008-campaign-v6-approval.mjs';
import { assertV14ModelTimeoutPolicy, createV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';
import { V17_MODEL_POLICY, assertV17ExecutorPolicy, assertV17ModelCatalogFiles, assertV17PreregistrationPolicy } from './s2-008-campaign-v17-policy.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = 'prn-s2007r-owner', BASE_FILE = 'preregistration.v16.in-force.json';
const BASE_SHA = 'e43d221b17ef3be95e68eb67f07ca422ec97fe5f8b325bb020eacd6d05e57077';
const V16_SUPERSESSION_SHA = '3bc72148941d4a722581e348478b3ecb4b177181355dac2d0327321d149cb7e8';
const V16_SUPERSESSION_DIGEST = 'e61b9f4a2d1b611d312f5e6f23a6d2765218d982aadb931ca06023d342395c9c';
const APPROVAL_DIGEST_SCOPE = 'the scientific body: every member except approval, status and preregistration_digest';
const DRAFT_SEAL_TEXT = 'scripts/s2-008-campaign-prepare.mjs --seal-v17 records this digest and supersession in the corpus manifest';
const BASE_EXPIRY = '2026-10-12T00:00:00.000Z';
const EXPIRY = '2026-11-07T00:00:00.000Z';
export const V17_SUPERSESSION_REASON = 'v17 binds the free NVIDIA Nemotron 3.5 Lightning model, NVIDIA-only OpenRouter routing with fallbacks disabled, the exact raw model catalog and endpoint listing, explicit process credential, 60-second pacing, preserved v16 unknown-outcome closure, and renewed A/B expiry while keeping frozen science unchanged.';
const PRIOR_FILES = Object.freeze({
  run: ['evidence/s2-008-campaign/v16-a-stopped/run-v16-a.json', 'c58eb4f72d3f42ace21aac31592cee6c668b5c8f5d675fb9564a01b7c0fe8280'],
  reconciliation: ['evidence/s2-008-campaign/v16-a-stopped/request-outcome-reconciliation.json', '5b295ee12198d1b453bbe3f0061acbc9fadf565d36b4ef4e8f7fbf63dac38da3'],
  ownerAttestation: ['evidence/s2-008-campaign/v16-a-stopped/owner-completeness-attestation.json', 'd9882dbb65c1f642fbc089237040bd105a21f157408054898aee19ff0048b807'],
  upstreamObservation: ['evidence/s2-008-campaign/v16-a-stopped/upstream-429-observation.json', '0a4e9589d44cd1f6858c2257140a3a1125b760004eabf2a32d0eb578ad737b28'],
  upstreamBinding: ['evidence/s2-008-campaign/v16-a-stopped/upstream-429-binding.json', '59d2d6302668c511863084450256b23f0a774765c2d5507b02860af709cecc5a'],
  generationLookup: ['evidence/s2-008-campaign/v16-a-stopped/generation-lookup.json', '714ed1084039e1f6ac5ac88ae552251523f13e6dd7c6abdd33ec0ab54e596190'],
  predictions: ['evidence/s2-008-campaign/v16-a-stopped/predictions-v16-a-trl-s2-008c-01-20260926.json', '1db420961471ff82ebc41d68fe16c9460ce53a7f244dd242320ebc70af5e0740'],
  status: ['evidence/s2-008-campaign/v16-a-stopped/status.json', 'ca255935baf454aea6ebf325de2336d23e3dc6526f7aab45390c625e01834163'],
  controlPin: ['evidence/s2-008-campaign/v16-a-stopped/control-image-pin-v16-a.json', 'b276faeaf4abdb44dbdd70b3c53e6e850fa6c1461ce4dbad9cdb8cefebcc75bc'],
  ownerAuthorization: ['evidence/s2-008-campaign/v16-a-stopped/owner-execution-authorization.json', 'c4c751651da981cce1f2d12ad63a77adee4ef1332b574419f8404b060aa92bd2'],
  providerObservationFiles: ['evidence/s2-008-campaign/v16-a-stopped/provider-observation-files.json', '48b30cfe548335a239cfac1e14539aa3a81890a050aa3b1d57f88e1a99cbd090'],
  credentialCheck: ['evidence/s2-008-campaign/v16-a-stopped/credential-check.json', '6417048d4a5b0fc4e577986bd50a894f1a90b1f4842a45757752237e27afae8e'],
  reconciliationRequired: ['evidence/s2-008-campaign/v16-a-stopped/reconciliation-required.json', '07fa38734f9cca02e4fe6289674af259cda2169c2cb4ac7a91565132af2c0ffe'],
  filesManifest: ['evidence/s2-008-campaign/v16-a-stopped/files.json', '8ba910dfecdee529fce78c802dcd3151c8af2bafdb442735a2abb3d498f87f97'],
});
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const parse = (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8'));
const safeRead = (root, name) => {
  const realRoot = fs.realpathSync(root), full = path.resolve(realRoot, name);
  if (!full.startsWith(realRoot + path.sep)) throw new Error('V17_INPUT_PATH_INVALID');
  const stat = fs.lstatSync(full);
  if (!stat.isFile() || stat.isSymbolicLink() || fs.realpathSync(full) !== full) throw new Error('V17_INPUT_FILE_UNSAFE');
  return fs.readFileSync(full);
};
function normalizeV16Manifest(manifest, base, supersession, { repoRoot = ROOT, baseBytes } = {}) {
  if (manifest?.preregistration?.file === BASE_FILE && manifest.preregistration.status === 'IN_FORCE') return manifest;
  if (manifest?.preregistration?.file !== 'preregistration.v17.in-force.json' ||
      manifest.preregistration.status !== 'IN_FORCE') throw new Error('V17_BASE_MANIFEST_INVALID');
  const v17Bytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration.v17.in-force.json');
  const v17 = parse(v17Bytes);
  const v17SupersessionBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v17-supersession.json');
  const v17Supersession = parse(v17SupersessionBytes);
  const preservedV16 = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v16-superseded.json');
  const history = manifest.supersession_history;
  const v16Index = Array.isArray(history) ? history.findIndex((entry) =>
    entry.file === 'preregistration-v16-supersession.json' &&
    entry.supersession_digest === supersession?.supersession_digest) : -1;
  const currentTail = { file: 'preregistration-v17-supersession.json',
    supersession_id: v17Supersession.supersession_id,
    supersession_digest: v17Supersession.supersession_digest,
    reason: v17Supersession.reason };
  if (!Buffer.isBuffer(baseBytes) || !preservedV16.equals(baseBytes) ||
      v17.rule !== 's2-008-prereg-v17' || v17.preregistration_id !== 'xpr-s2-008c-17' ||
      v17.status !== 'APPROVED' || v17.approval?.status !== 'APPROVED' ||
      v17.approval?.authority !== 'HUMAN_OWNER' || v17.approval?.principal_id !== OWNER ||
      v17.approval?.label !== 'Daniil' || v17.approval?.in_force !== true ||
      v17.approval?.signed_digest_over !== APPROVAL_DIGEST_SCOPE ||
      v17.preregistration_digest !== preregistrationDigest(v17) ||
      manifest.preregistration.preregistration_digest !== v17.preregistration_digest ||
      manifest.supersession?.file !== 'preregistration-v17-supersession.json' ||
      manifest.supersession.supersession_digest !== v17Supersession.supersession_digest ||
      canonicalDigest(history?.at(-1) ?? null) !== canonicalDigest(currentTail) ||
      canonicalDigest(manifest.supersession ?? null) !== canonicalDigest(currentTail) ||
      manifest.superseded_preregistration?.file !== 'preregistration-v16-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== base.preregistration_digest ||
      v16Index < 0 || history[v16Index + 1]?.file !== 'preregistration-v17-supersession.json' ||
      history[v16Index + 1]?.supersession_digest !== v17Supersession.supersession_digest) {
    throw new Error('V17_BASE_MANIFEST_INVALID');
  }
  assertPreregistration(v17);
  assertContentSupersession(v17Supersession, base, v17);
  return { ...manifest,
    preregistration: { file: BASE_FILE, status: 'IN_FORCE', preregistration_digest: base.preregistration_digest },
    supersession: history[v16Index], supersession_history: history.slice(0, v16Index + 1),
    superseded_preregistration: { file: 'preregistration-v15-superseded.json',
      preregistration_digest: supersession.supersedes, status: 'SUPERSEDED', superseded_by: BASE_FILE },
  };
}
export function readV17BaseInputs({ repoRoot = ROOT, allowHistorical = false } = {}) {
  const baseBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/' + BASE_FILE);
  if (sha(baseBytes) !== BASE_SHA) throw new Error('V17_BASE_BYTES_INVALID');
  const base = parse(baseBytes);
  const activeManifest = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/manifest.json'));
  if (!allowHistorical && activeManifest.preregistration?.file !== BASE_FILE) throw new Error('V17_BASE_NOT_CURRENT');
  const supersessionBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v16-supersession.json');
  const supersession = parse(supersessionBytes);
  const manifest = normalizeV16Manifest(activeManifest, base, supersession, { repoRoot, baseBytes });
  const table = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/frozen-table.v3.json'));
  const ledger = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/source-ledger.v3.json'));
  return { repoRoot, base, baseBytes, manifest, activeManifest, supersession, supersessionBytes, table, ledger };
}
function expectedPriorClosure(baseDigest) {
  return Object.freeze({
    kind: 's2-008-v17-v16-prior-request-outcome-closure/1', status: 'REQUEST_OUTCOMES_RECONCILED',
    base_preregistration_digest: baseDigest, raw_run_id: 's2-008c-v16-a-6610a7c4fae8418dace6',
    raw_run_sha256: PRIOR_FILES.run[1], reconciliation_sha256: PRIOR_FILES.reconciliation[1],
    owner_attestation_sha256: PRIOR_FILES.ownerAttestation[1], upstream_observation_sha256: PRIOR_FILES.upstreamObservation[1],
    upstream_binding_sha256: PRIOR_FILES.upstreamBinding[1], generation_lookup_sha256: PRIOR_FILES.generationLookup[1],
    predictions_sha256: PRIOR_FILES.predictions[1], status_sha256: PRIOR_FILES.status[1],
    control_pin_sha256: PRIOR_FILES.controlPin[1], owner_authorization_sha256: PRIOR_FILES.ownerAuthorization[1],
    provider_observation_files_sha256: PRIOR_FILES.providerObservationFiles[1],
    credential_check_sha256: PRIOR_FILES.credentialCheck[1],
    reconciliation_required_sha256: PRIOR_FILES.reconciliationRequired[1], files_manifest_sha256: PRIOR_FILES.filesManifest[1],
    prior_supersession_digest: V16_SUPERSESSION_DIGEST, local_attempts: 1, successful_generations: 0,
    failed_upstream_requests: 1, classified_unknown_attempts: 1, unclassified_attempts: 0,
    known_tokens_lower_bound: 0, known_usd_lower_bound: 0, failed_request_tokens_confirmed: null,
    failed_request_usd_confirmed: null, total_tokens_confirmed: null, total_usd_confirmed: null,
    no_cost_claim_for_failed_request: true, raw_report_unreconciled_spend: true, account_wide_completeness_claimed: false,
    owner_statement: '\u0414\u0430, \u043f\u043e\u043b\u043d\u044b\u0439 \u0441\u043f\u0438\u0441\u043e\u043a; \u0442\u043e\u043b\u044c\u043a\u043e \u044d\u0442\u043e\u0442 429',
    failure_generation_id: 'gen-1791385538-Kv8guCF6fgfxeioKvMfY',
    failure_provider: 'Poolside', failure_model: 'poolside/laguna-s-2.1-20260720',
    failure_variant: 'free', failure_http_status: 429, failure_total_latency_ms: 126,
    failure_attempts: 1, failure_fallback_latency_ms: 0, failure_generation_api_http_status: 404,
    latest_bound_evidence_at: '2026-10-07T15:05:39.699336+00:00',
  });
}
export function readV17PriorExecutionInputs({ repoRoot = ROOT } = {}) {
  const inputs = { repoRoot };
  for (const [key, [file, expectedSha]] of Object.entries(PRIOR_FILES)) {
    const bytes = safeRead(repoRoot, file);
    if (sha(bytes) !== expectedSha) throw new Error('V17_PRIOR_EXECUTION_RAW_INPUT_MISMATCH');
    inputs[key] = { file, bytes, value: parse(bytes) };
  }
  inputs.expectedClosure = expectedPriorClosure('bd230c0856930cab13372473bdb9e59dbf3d667fdbd1493e2119dc2c378d36b0');
  return inputs;
}
export function assertV17BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger } = {}) {
  if (!base || !Buffer.isBuffer(baseBytes) || !manifest || !supersession || !Buffer.isBuffer(supersessionBytes) ||
      !table || !Array.isArray(ledger?.entries)) throw new Error('V17_BASE_INPUTS_MISSING');
  const digest = base.preregistration_digest;
  const expectedApproval = { status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: OWNER, label: 'Daniil',
    issued_at: base.approval?.issued_at, signed_digest_over: APPROVAL_DIGEST_SCOPE, in_force: true,
    becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v16 records this digest and supersession in the corpus manifest' };
  if (sha(baseBytes) !== BASE_SHA || canonicalDigest(base) !== canonicalDigest(parse(baseBytes)) ||
      base.rule !== 's2-008-prereg-v16' || base.preregistration_id !== 'xpr-s2-008c-16' ||
      digest !== 'bd230c0856930cab13372473bdb9e59dbf3d667fdbd1493e2119dc2c378d36b0' ||
      digest !== preregistrationDigest(base) || base.status !== 'APPROVED' ||
      canonicalDigest(base.approval) !== canonicalDigest(expectedApproval) ||
      !Number.isFinite(Date.parse(base.approval?.issued_at ?? '')) ||
      base.budget_reservation?.granted_units !== 5000000 || base.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      base.budget_reservation?.expires_at !== BASE_EXPIRY) throw new Error('V17_BASE_BINDING_INVALID');
  assertPreregistration(base);
  assertV16PreregistrationPolicy(base);
  assertV14ModelTimeoutPolicy(base.executor?.model_launch_timeout);
  if (sha(supersessionBytes) !== V16_SUPERSESSION_SHA ||
      canonicalDigest(supersession) !== canonicalDigest(parse(supersessionBytes)) ||
      supersession.kind !== 'SUPERSESSION' || supersession.supersedes !== '84e15b1b1276c548ad6486fd65a03782f0b9d463cef802d6dcd608accf744268' ||
      supersession.replaced_by_preregistration_digest !== digest || supersession.supersession_digest !== V16_SUPERSESSION_DIGEST ||
      manifest.preregistration?.file !== BASE_FILE || manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== digest ||
      manifest.supersession?.file !== 'preregistration-v16-supersession.json' ||
      manifest.supersession.supersession_digest !== supersession.supersession_digest ||
      manifest.supersession_history?.at(-1)?.file !== 'preregistration-v16-supersession.json' ||
      manifest.supersession_history.at(-1).supersession_digest !== supersession.supersession_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v15-superseded.json' ||
      manifest.superseded_preregistration?.preregistration_digest !== supersession.supersedes ||
      manifest.frozen_table?.digest !== canonicalDigest(table) || base.expected_table_digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1)?.anchor_digest) throw new Error('V17_BASE_SUPERSESSION_INVALID');
  assertSourceLedger(ledger.entries, { cases_digest: ledger.entries.at(-1)?.cases_digest, expected_table_digest: canonicalDigest(table) });
  return Object.freeze({ baseDigest: digest, supersessionDigest: supersession.supersession_digest,
    tableDigest: canonicalDigest(table), ledgerDigest: canonicalDigest(ledger) });
}

export function assertV17PriorExecutionReconciliation(base, inputs = readV17PriorExecutionInputs()) {
  const digest = base?.preregistration_digest;
  if (!base || base.rule !== 's2-008-prereg-v16' || digest !== preregistrationDigest(base)) {
    throw new Error('V17_PRIOR_EXECUTION_BASE_INVALID');
  }
  for (const [key, [file, expectedSha]] of Object.entries(PRIOR_FILES)) {
    const item = inputs?.[key];
    if (item?.file !== file || !Buffer.isBuffer(item.bytes) || sha(item.bytes) !== expectedSha) {
      throw new Error('V17_PRIOR_EXECUTION_RAW_INPUT_MISMATCH');
    }
    if (canonicalDigest(item.value ?? null) !== canonicalDigest(parse(item.bytes))) {
      throw new Error(key === 'reconciliation' ? 'V17_PRIOR_EXECUTION_RECONCILIATION_INVALID'
        : 'V17_PRIOR_EXECUTION_RAW_INPUT_MISMATCH');
    }
  }
  const run = inputs.run.value, recon = inputs.reconciliation.value, owner = inputs.ownerAttestation.value;
  const upstream = inputs.upstreamObservation.value, binding = inputs.upstreamBinding.value;
  const lookup = inputs.generationLookup.value, status = inputs.status.value, predictions = inputs.predictions.value;
  const failedId = 'gen-1791385538-Kv8guCF6fgfxeioKvMfY';
  const statement = '\u0414\u0430, \u043f\u043e\u043b\u043d\u044b\u0439 \u0441\u043f\u0438\u0441\u043e\u043a; \u0442\u043e\u043b\u044c\u043a\u043e \u044d\u0442\u043e\u0442 429';
  if (run?.status !== 'BLOCKED' || run.raw_run_id !== 's2-008c-v16-a-6610a7c4fae8418dace6' ||
      run.preregistration_digest !== digest || run.model_calls !== 0 || run.unknown_model_attempts !== 1 ||
      run.unreconciled_spend !== true || run.spent_units !== 0 || run.spent_units_is_lower_bound !== true ||
      recon?.status !== 'REQUEST_OUTCOMES_RECONCILED' || recon.raw_run_id !== run.raw_run_id ||
      recon.preregistration_digest !== digest || recon.local_model_attempts !== 1 ||
      recon.successful_generations !== 0 || recon.failed_upstream_requests !== 1 ||
      recon.classified_unknown_attempts !== 1 || recon.unclassified_attempts !== 0 ||
      recon.known_tokens_lower_bound !== 0 || recon.known_provider_usd_lower_bound !== 0 ||
      recon.failed_request_tokens_confirmed !== null || recon.failed_request_usd_confirmed !== null ||
      recon.total_tokens_confirmed !== null || recon.total_usd_confirmed !== null ||
      recon.financial_reconciliation_complete !== false || recon.raw_unreconciled_spend_preserved !== true ||
      recon.no_cost_claim_for_failed_request !== true || recon.account_wide_completeness_claimed !== false ||
      recon.provider_rows_verified_via_api !== false || recon.retry_performed !== false || recon.B !== 'NOT_RUN' ||
      recon.completeness?.complete !== true || recon.completeness?.unfiltered !== true ||
      recon.completeness?.includes_errors_and_cancellations !== true ||
      recon.completeness?.basis !== 'DIRECT_OWNER_UNFILTERED_MINUTE_ATTESTATION' ||
      recon.completeness?.statement !== statement || owner?.source !== 'direct_user_question_reply' ||
      owner.actor_label !== 'Daniil' || owner.statement !== statement || owner.complete !== true ||
      owner.unfiltered !== true || owner.includes_errors_and_cancellations !== true ||
      owner.generations_empty !== true || owner.only_upstream_request !== failedId ||
      owner.key_name !== 'testVeritas' ||
      canonicalDigest(owner.UTC_interval) !== canonicalDigest(['2026-10-07T15:05:00Z', '2026-10-07T15:05:59Z']) ||
      upstream?.status !== 429 || upstream.generation_id !== failedId ||
      upstream.provider !== 'Poolside' || upstream.model !== 'poolside/laguna-s-2.1-20260720' ||
      upstream.variant !== 'free' || upstream.total_latency_ms !== 126 || upstream.attempts !== 1 ||
      upstream.failed_attempts !== 1 || upstream.fallback_latency_ms !== 0 ||
      upstream.generation_api_http_status !== 404 || upstream.failed_request_tokens_confirmed !== null ||
      upstream.failed_request_usd_confirmed !== null || upstream.complete_window_attestation !== null ||
      upstream.retry_performed !== false || binding?.generation_id !== failedId ||
      binding.raw_run_id !== run.raw_run_id || binding.inside_attempt_window !== true ||
      binding.provider !== 'Poolside' || binding.model !== 'poolside/laguna-s-2.1-20260720' ||
      binding.variant !== 'free' || binding.http_status_owner_observed !== 429 ||
      binding.attempts_owner_observed !== 1 || binding.fallback_latency_ms_owner_observed !== 0 ||
      binding.generation_api_http_status !== 404 || binding.retry_performed !== false ||
      binding.raw_unreconciled_spend_preserved !== true || binding.B !== 'NOT_RUN' ||
      lookup?.generation_id !== failedId || lookup.generation_api_http_status !== 404 ||
      lookup.failed_request_tokens_confirmed !== null || lookup.failed_request_usd_confirmed !== null ||
      status?.result?.status !== 'BLOCKED' || status.result.code !== 'CHARGE_NOT_MEASURABLE' ||
      status.result.unknown_model_attempts !== 1 || status.result.model_calls !== 0 ||
      status.result.spent_units !== 0 || status.result.unreconciled_spend !== true ||
      predictions?.accounting?.calls !== 0 || predictions?.accounting?.tokens !== 0) {
    throw new Error('V17_PRIOR_EXECUTION_RECONCILIATION_INVALID');
  }
  const expected = expectedPriorClosure(digest);
  if (inputs.expectedClosure && canonicalDigest(inputs.expectedClosure) !== canonicalDigest(expected)) {
    throw new Error('V17_PRIOR_EXECUTION_RECONCILIATION_INVALID');
  }
  return expected;
}
export function assertV17PresealPin({ pin, baseBytes, commitment = null } = {}) {
  const result = assertVersionedPresealPin({ pin, baseBytes, commitment, version: 17,
    requiredSources: ['pi_runtime_tree','timeout_policy','credential_env_policy','pi_shrinkwrap','pi_package_manifest',
      'pi_launcher','provider_model_catalog','provider_model_catalog_response','provider_model_endpoint_catalog','v17_model_policy','model_call_pacing_policy'] });
  if (pin.first.sources.provider_model_catalog !== V17_MODEL_POLICY.catalog_sha256 ||
      pin.first.sources.provider_model_catalog_response !== V17_MODEL_POLICY.catalog_response_sha256 ||
      pin.first.sources.provider_model_endpoint_catalog !== V17_MODEL_POLICY.endpoint_catalog_sha256) throw new Error('V17_MODEL_POLICY_PIN_INVALID');
  return result;
}
export function createV17Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin, repoRoot = ROOT,
  restartInputs = readV17PriorExecutionInputs({ repoRoot }) }) {
  const lineage = assertV17BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV17PriorExecutionReconciliation(base, restartInputs);
  assertV17ModelCatalogFiles(path.join(repoRoot, V17_MODEL_POLICY.catalog_file),
    path.join(repoRoot, V17_MODEL_POLICY.endpoint_catalog_file), path.join(repoRoot, V17_MODEL_POLICY.catalog_response_file));
  if (!pin) throw new Error('V17_PRESEAL_PIN_REQUIRED');
  const { commitment, covers } = assertV17PresealPin({ pin, baseBytes });
  const executor = {
    ...base.executor, provider: V17_MODEL_POLICY.provider, model: V17_MODEL_POLICY.model,
    credential_env_name: V17_MODEL_POLICY.credential_env_name, credential_source: V17_MODEL_POLICY.credential_source,
    model_call_pacing: { min_start_interval_ms: V17_MODEL_POLICY.min_start_interval_ms },
    model_launch_timeout: createV14ModelTimeoutPolicy(),
    pi_model_registration: structuredClone(V17_MODEL_POLICY.pi_model_registration),
    pi_model_catalog_binding: {
      file: V17_MODEL_POLICY.catalog_file, sha256: V17_MODEL_POLICY.catalog_sha256,
      endpoint_file: V17_MODEL_POLICY.endpoint_catalog_file, endpoint_sha256: V17_MODEL_POLICY.endpoint_catalog_sha256,
      response_file: V17_MODEL_POLICY.catalog_response_file, response_sha256: V17_MODEL_POLICY.catalog_response_sha256,
      canonical_slug: V17_MODEL_POLICY.catalog_slug, endpoint_slug: V17_MODEL_POLICY.endpoint_slug, prompt_price: '0', completion_price: '0',
      prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY', cache_pricing: 'NOT_PROVIDED',
      client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE',
    },
    pi_settings: structuredClone(V7_PI_SETTINGS),
    model_image: { ...base.executor.model_image, content_commitment: commitment, covers, excludes: ['prereg'],
      built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v17.json',
      built_image_pin_reason: 'v17 binds the delegated free NVIDIA Nemotron 3.5 Lightning model, an NVIDIA-only OpenRouter route with fallbacks disabled, its listed zero prices, explicit process credential, 60-second pacing, and the v16 unknown-outcome closure while preserving frozen science and separate A/B ceilings' },
  };
  assertV17ExecutorPolicy(executor);
  const draft = { ...base, rule: 's2-008-prereg-v17', preregistration_id: 'xpr-s2-008c-17', executor,
    budget_reservation: { ...base.budget_reservation,
      usd_reference: { ...base.budget_reservation.usd_reference,
        why_null: 'No Nvidia provider invoice is asserted; the zero-listed catalog price is not an invoice, and provider generation receipts remain authoritative.',
        projection: { ...base.budget_reservation.usd_reference?.projection,
          reason: 'The historical token observation is not a Nvidia campaign projection. Zero-listed prices and client estimates do not establish measured provider cost; actual generation receipts are authoritative.' } },
      reservation_id: 'rsv-s2-008c-17',
      granted_units: 5000000, ceiling_scope: 'PER_RUN_A_OR_B', expires_at: EXPIRY },
    v16_prior_execution_reconciliation: prior,
    supersession: { supersedes: base.preregistration_id, superseded_digest: lineage.baseDigest,
      scope: 'free NVIDIA Nemotron 3.5 Lightning model selected under owner delegation and provider catalog binding; preserve frozen science, three trials, pacing, no retries, independent A/B ceilings, expiry and v16 request outcomes',
      reason: 'Continue the frozen campaign with the free NVIDIA Nemotron 3.5 Lightning model selected under owner delegation and preserve unknown v16 failed-request cost and token values as null.',
      unchanged: [...FROZEN_MEMBERS] },
    recorded_before_first_trial: { first_trial: 'NOT_STARTED',
      proof: 'Exact v16 in-force bytes and separate supersession, raw request-outcome closure, delegated free-model selection, provider descriptor, zero listed prices, retry-off policy, and image commitment bind before any v17 trial.' },
    status: 'DRAFT',
    approval: { status: null, authority: 'HUMAN_OWNER', principal_id: null, label: null, issued_at: null,
      signed_digest_over: APPROVAL_DIGEST_SCOPE, in_force: false, becomes_in_force_when: DRAFT_SEAL_TEXT },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertPreregistration(draft);
  assertV17PreregistrationPolicy(draft);
  if (draft.v16_prior_execution_reconciliation.base_preregistration_digest !== lineage.baseDigest ||
      draft.budget_reservation.granted_units !== base.budget_reservation.granted_units ||
      draft.budget_reservation.expires_at !== EXPIRY) throw new Error('V17_PRIOR_BINDING_MISMATCH');
  return draft;
}
export function approveV17({ draft, base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV17PriorExecutionInputs(), principal, label, issuedAt }) {
  if (principal !== OWNER || label !== 'Daniil' || typeof issuedAt !== 'string' ||
      !Number.isFinite(Date.parse(issuedAt)) || Date.parse(issuedAt) >= Date.parse(EXPIRY)) throw new Error('V17_APPROVAL_IDENTITY_INVALID');
  if (draft?.rule !== 's2-008-prereg-v17' || draft.preregistration_id !== 'xpr-s2-008c-17') throw new Error('V17_VERSION_MISMATCH');
  const approval = draft.approval;
  if (draft.status !== 'DRAFT' || approval?.status !== null ||
      Object.keys(approval ?? {}).sort().join(',') !== 'authority,becomes_in_force_when,in_force,issued_at,label,principal_id,signed_digest_over,status' ||
      approval.authority !== 'HUMAN_OWNER' || approval.principal_id !== null || approval.label !== null ||
      approval.issued_at !== null || approval.signed_digest_over !== APPROVAL_DIGEST_SCOPE || approval.in_force !== false ||
      approval.becomes_in_force_when !== DRAFT_SEAL_TEXT) throw new Error('V17_APPROVAL_METADATA_INVALID');
  assertV17PreregistrationPolicy(draft);
  if (draft.preregistration_digest !== preregistrationDigest(draft)) throw new Error('V17_DIGEST_MISMATCH');
  const lineage = assertV17BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV17PriorExecutionReconciliation(base, restartInputs);
  if (Date.parse(issuedAt) < Date.parse(prior.latest_bound_evidence_at) ||
      canonicalDigest(draft.v16_prior_execution_reconciliation) !== canonicalDigest(prior) ||
      draft.supersession?.superseded_digest !== lineage.baseDigest || draft.expected_table_digest !== canonicalDigest(table)) {
    throw new Error('V17_PRIOR_BINDING_MISMATCH');
  }
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertV17PresealPin({ pin, baseBytes, commitment: draft.executor?.model_image?.content_commitment });
  const expected = createV17Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin, restartInputs });
  if (canonicalDigest(scientificBody(expected)) !== canonicalDigest(scientificBody(draft))) throw new Error('V17_SCOPE_MISMATCH');
  const signed = { ...scientificBody(draft), status: 'APPROVED', approval: { ...approval,
    status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: principal, label, issued_at: issuedAt, in_force: false } };
  return Object.freeze({ ...signed, preregistration_digest: preregistrationDigest(signed) });
}

export function assertV17SuccessorOnDisk(repoRoot = ROOT) {
  const corpus = 'corpus/s2-008-campaign/';
  const evidence = 'evidence/s2-008-campaign/';
  const readBytes = (name) => safeRead(repoRoot, corpus + name);
  const readEvidence = (name) => JSON.parse(safeRead(repoRoot, evidence + name).toString('utf8'));
  const inputs = readV17BaseInputs({ repoRoot, allowHistorical: true });
  const restartInputs = readV17PriorExecutionInputs({ repoRoot });
  const preregBytes = readBytes('preregistration.v17.in-force.json');
  const prereg = parse(preregBytes);
  const signed = parse(readBytes('preregistration.v17.approved.json'));
  const draft = parse(readBytes('preregistration.v17.draft.json'));
  const supersession = parse(readBytes('preregistration-v17-supersession.json'));
  const presealPin = readEvidence('model-image-pin-v17-preseal.json');
  const finalPin = readEvidence('model-image-pin-v17.json');
  if (!readBytes('preregistration-v16-superseded.json').equals(inputs.baseBytes)) {
    throw new Error('V17_BASE_BYTES_NOT_PRESERVED');
  }
  assertV17ModelCatalogFiles(path.join(repoRoot, V17_MODEL_POLICY.catalog_file),
    path.join(repoRoot, V17_MODEL_POLICY.endpoint_catalog_file),
    path.join(repoRoot, V17_MODEL_POLICY.catalog_response_file));
  const expectedSigned = approveV17({ draft, ...inputs, pin: presealPin, restartInputs,
    principal: signed.approval?.principal_id, label: signed.approval?.label,
    issuedAt: signed.approval?.issued_at });
  if (expectedSigned.preregistration_digest !== signed.preregistration_digest ||
      canonicalDigest(expectedSigned.approval) !== canonicalDigest(signed.approval) ||
      canonicalDigest(scientificBody(signed)) !== canonicalDigest(scientificBody(draft)) ||
      prereg.preregistration_digest !== preregistrationDigest(prereg) ||
      canonicalDigest(scientificBody(prereg)) !== canonicalDigest(scientificBody(signed)) ||
      prereg.approval?.in_force !== true) throw new Error('V17_SIGNATURE_BINDING_INVALID');
  const preseal = assertV17PresealPin({ pin: presealPin, baseBytes: inputs.baseBytes,
    commitment: prereg.executor?.model_image?.content_commitment });
  const final = assertV17PresealPin({ pin: finalPin, baseBytes: preregBytes,
    commitment: prereg.executor?.model_image?.content_commitment });
  if (preseal.commitment !== final.commitment) throw new Error('V17_CONTENT_COMMITMENT_MOVED');
  const expectedSupersession = createContentSupersession({ superseded: inputs.base, replacedBy: prereg,
    reason: V17_SUPERSESSION_REASON });
  if (canonicalDigest(expectedSupersession) !== canonicalDigest(supersession)) {
    throw new Error('V17_SUPERSESSION_BINDING_INVALID');
  }
  const activeManifest = inputs.activeManifest;
  const tail = { file: 'preregistration-v17-supersession.json',
    supersession_id: supersession.supersession_id,
    supersession_digest: supersession.supersession_digest,
    reason: supersession.reason };
  if (activeManifest.preregistration?.file !== 'preregistration.v17.in-force.json' ||
      activeManifest.preregistration.status !== 'IN_FORCE' ||
      activeManifest.preregistration.preregistration_digest !== prereg.preregistration_digest ||
      activeManifest.supersession?.file !== tail.file ||
      canonicalDigest(activeManifest.supersession) !== canonicalDigest(tail) ||
      canonicalDigest(activeManifest.supersession_history?.at(-1) ?? null) !== canonicalDigest(tail) ||
      activeManifest.superseded_preregistration?.file !== 'preregistration-v16-superseded.json' ||
      activeManifest.superseded_preregistration.preregistration_digest !== inputs.base.preregistration_digest ||
      activeManifest.frozen_table?.digest !== canonicalDigest(inputs.table) ||
      activeManifest.source_ledger?.entry_count !== inputs.ledger.entries.length ||
      activeManifest.source_ledger?.last_anchor_digest !== inputs.ledger.entries.at(-1)?.anchor_digest) {
    throw new Error('V17_ACTIVE_MANIFEST_BINDING_INVALID');
  }
  assertContentSupersession(supersession, inputs.base, prereg);
  return { ok: true, preregistration_digest: prereg.preregistration_digest,
    supersession_id: supersession.supersession_id, content_commitment: final.commitment };
}

export { PRIOR_FILES as V17_PRIOR_EXECUTION_FILES };


/** Supply old validators an authentic v16 view only after verifying the active successor. */
export function historicalV16ManifestForV17(repoRoot, manifest) {
  const actual = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/manifest.json'));
  if (canonicalDigest(actual) !== canonicalDigest(manifest)) throw new Error('V17_ACTIVE_MANIFEST_INPUT_MISMATCH');
  assertV17SuccessorOnDisk(repoRoot);
  return readV17BaseInputs({ repoRoot, allowHistorical: true }).manifest;
}
