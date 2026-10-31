import { historicalV16ManifestForV17 } from './s2-008-campaign-v17-approval.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, assertSourceLedger, preregistrationDigest } from '../src/lib/research/index.mjs';
import { FROZEN_MEMBERS, scopeDrift, scientificBody } from './s2-008-campaign-approve.mjs';
import { V7_PI_SETTINGS } from './s2-008-campaign-credential-env.mjs';
import { assertV15PreregistrationPolicy } from './s2-008-campaign-v15-policy.mjs';
import { assertVersionedPresealPin } from './s2-008-campaign-v6-approval.mjs';
import { assertV14ModelTimeoutPolicy, createV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';
import { V16_MODEL_POLICY, assertV16ExecutorPolicy, assertV16ModelCatalogFiles, assertV16PreregistrationPolicy } from './s2-008-campaign-v16-policy.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = 'prn-s2007r-owner', BASE_FILE = 'preregistration.v15.in-force.json';
const BASE_SHA = 'fb9496773cd4acafb0fad4e5c860ae6208dea977c919115ffe89d148d141c348';
const V15_SUPERSESSION_SHA = '584d74cfcef703aa02626c0fc4de259c671a6109482bf0d3f46cd6d454ae1368';
const V15_SUPERSESSION_DIGEST = '4387b8d444737a41dbc2738115e55fb0c3a8cf6177cbcd1b4f3629d1cc0c9218';
const APPROVAL_DIGEST_SCOPE = 'the scientific body: every member except approval, status and preregistration_digest';
const DRAFT_SEAL_TEXT = 'scripts/s2-008-campaign-prepare.mjs --seal-v16 records this digest and supersession in the corpus manifest';
const EXPIRY = '2026-10-12T00:00:00.000Z';
const PRIOR_FILES = Object.freeze({
  run: ['evidence/s2-008-campaign/v15-a-stopped/run-v15-a.json', 'f86c2f8404ef8fe5d943abc7fe71aa68ba59646b03ff8a5890b1d7b7ad478563'],
  reconciliation: ['evidence/s2-008-campaign/v15-a-stopped/request-outcome-reconciliation.json', '85b87e560f4fbd6b386bd348cf8b17029532216681bbf7f2a7b7dd66e8b82b07'],
  ownerAttestation: ['evidence/s2-008-campaign/v15-a-stopped/owner-completeness-attestation.json', '39174498b8eb4be6a36faabffb6e04204e44deb3d6c3dbefca0bd556c23ff574'],
  upstreamObservation: ['evidence/s2-008-campaign/v15-a-stopped/upstream-429-observation.json', 'fa6bd861dbb3895fd8c9686e21973418c031b7bf2212632b806e607b51c6ae9c'],
  upstreamBinding: ['evidence/s2-008-campaign/v15-a-stopped/upstream-429-binding.json', '95b8698e9609f07da5d6100a726633075f7df33ac0c5e09456ea63b0cabb3eee'],
  generationLookup: ['evidence/s2-008-campaign/v15-a-stopped/generation-lookup.json', '9aa86229b05166895dbbc6660c85952be0b10d3e717a66fbcfd34311c236e9a1'],
  predictions: ['evidence/s2-008-campaign/v15-a-stopped/predictions-v15-a-trl-s2-008c-01-20260926.json', '1db420961471ff82ebc41d68fe16c9460ce53a7f244dd242320ebc70af5e0740'],
  status: ['evidence/s2-008-campaign/v15-a-stopped/status.json', 'ec42a930fec0cfc7eda65d93f24d8fea41c46c476a956f7b612753c86774fea0'],
  keyQuota: ['evidence/s2-008-campaign/v15-a-stopped/key-quota-observation.json', '6094dc4085db696dca8e4d55cc5657130a726ccdfbbd2d6638721902da892a49'],
});
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const parse = (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8'));
const safeRead = (root, name) => {
  const realRoot = fs.realpathSync(root), full = path.resolve(realRoot, name);
  if (!full.startsWith(realRoot + path.sep)) throw new Error('V16_INPUT_PATH_INVALID');
  const stat = fs.lstatSync(full);
  if (!stat.isFile() || stat.isSymbolicLink() || fs.realpathSync(full) !== full) throw new Error('V16_INPUT_FILE_UNSAFE');
  return fs.readFileSync(full);
};
function normalizeV15Manifest(manifest, base, supersession) {
  if (manifest?.preregistration?.file === BASE_FILE && manifest.preregistration.status === 'IN_FORCE') return manifest;
  if (manifest?.preregistration?.file !== 'preregistration.v16.in-force.json' || manifest.preregistration.status !== 'IN_FORCE') {
    throw new Error('V16_BASE_MANIFEST_INVALID');
  }
  const history = manifest.supersession_history;
  const index = Array.isArray(history) ? history.findIndex((entry) =>
    entry.file === 'preregistration-v15-supersession.json' && entry.supersession_digest === supersession?.supersession_digest) : -1;
  if (index < 0 || manifest.superseded_preregistration?.file !== 'preregistration-v15-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== base.preregistration_digest) {
    throw new Error('V16_BASE_MANIFEST_INVALID');
  }
  return { ...manifest,
    preregistration: { file: BASE_FILE, status: 'IN_FORCE', preregistration_digest: base.preregistration_digest },
    supersession: history[index], supersession_history: history.slice(0, index + 1),
    superseded_preregistration: { file: 'preregistration-v14-superseded.json',
      preregistration_digest: supersession.supersedes, status: 'SUPERSEDED', superseded_by: BASE_FILE },
  };
}
export function readV16BaseInputs({ repoRoot = ROOT, allowHistorical = false } = {}) {
  const baseBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/' + BASE_FILE);
  if (sha(baseBytes) !== BASE_SHA) throw new Error('V16_BASE_BYTES_INVALID');
  const base = parse(baseBytes);
  const activeManifest = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/manifest.json'));
  const historicalManifestView = allowHistorical && activeManifest.preregistration?.file === 'preregistration.v17.in-force.json'
    ? historicalV16ManifestForV17(repoRoot, activeManifest) : activeManifest;
  if (!allowHistorical && historicalManifestView.preregistration?.file !== BASE_FILE) throw new Error('V16_BASE_NOT_CURRENT');
  const supersessionBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v15-supersession.json');
  const supersession = parse(supersessionBytes);
  const manifest = normalizeV15Manifest(historicalManifestView, base, supersession);
  const table = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/frozen-table.v3.json'));
  const ledger = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/source-ledger.v3.json'));
  return { repoRoot, base, baseBytes, manifest, activeManifest, supersession, supersessionBytes, table, ledger };
}
function expectedPriorClosure(baseDigest) {
  return Object.freeze({
    kind: 's2-008-v16-v15-prior-request-outcome-closure/1', status: 'REQUEST_OUTCOMES_RECONCILED',
    base_preregistration_digest: baseDigest, raw_run_id: 's2-008c-v15-a-2f7449f1c8a34f73bbbd',
    raw_run_sha256: PRIOR_FILES.run[1], reconciliation_sha256: PRIOR_FILES.reconciliation[1],
    owner_attestation_sha256: PRIOR_FILES.ownerAttestation[1], upstream_observation_sha256: PRIOR_FILES.upstreamObservation[1],
    upstream_binding_sha256: PRIOR_FILES.upstreamBinding[1], generation_lookup_sha256: PRIOR_FILES.generationLookup[1],
    predictions_sha256: PRIOR_FILES.predictions[1], status_sha256: PRIOR_FILES.status[1], key_quota_sha256: PRIOR_FILES.keyQuota[1],
    prior_supersession_digest: V15_SUPERSESSION_DIGEST, local_attempts: 1, successful_generations: 0,
    failed_upstream_requests: 1, classified_unknown_attempts: 1, unclassified_attempts: 0,
    known_tokens_lower_bound: 0, known_usd_lower_bound: 0, failed_request_tokens_confirmed: null,
    failed_request_usd_confirmed: null, total_tokens_confirmed: null, total_usd_confirmed: null,
    no_cost_claim_for_failed_request: true, raw_report_unreconciled_spend: true, account_wide_completeness_claimed: false,
    owner_statement: '\u0414\u0430, Generations \u043f\u0443\u0441\u0442\u043e; \u0435\u0434\u0438\u043d\u0441\u0442\u0432\u0435\u043d\u043d\u0430\u044f \u0437\u0430\u043f\u0438\u0441\u044c \u2014 \u044d\u0442\u043e\u0442 429',
    failure_generation_id: 'gen-1791370937-0Ten4t5o0cYcyazZ5LAu', failure_provider: 'Google AI Studio',
    failure_model: 'google/gemma-4-31b-it-20260402', failure_variant: 'free', failure_http_status: 429,
    failure_total_latency_ms: 107, failure_attempts: 1, failure_fallback_latency_ms: 0,
    failure_generation_api_http_status: 404, latest_bound_evidence_at: '2026-10-07T11:14:06.637850+00:00',
  });
}
export function readV16PriorExecutionInputs({ repoRoot = ROOT } = {}) {
  const inputs = { repoRoot };
  for (const [key, [file, expectedSha]] of Object.entries(PRIOR_FILES)) {
    const bytes = safeRead(repoRoot, file);
    if (sha(bytes) !== expectedSha) throw new Error('V16_PRIOR_EXECUTION_RAW_INPUT_MISMATCH');
    inputs[key] = { file, bytes, value: parse(bytes) };
  }
  inputs.expectedClosure = expectedPriorClosure('84e15b1b1276c548ad6486fd65a03782f0b9d463cef802d6dcd608accf744268');
  return inputs;
}
export function assertV16BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger } = {}) {
  if (!base || !Buffer.isBuffer(baseBytes) || !manifest || !supersession || !Buffer.isBuffer(supersessionBytes) ||
      !table || !Array.isArray(ledger?.entries)) throw new Error('V16_BASE_INPUTS_MISSING');
  const digest = base.preregistration_digest;
  const expectedApproval = { status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: OWNER, label: 'Daniil',
    issued_at: base.approval?.issued_at, signed_digest_over: APPROVAL_DIGEST_SCOPE, in_force: true,
    becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v15 records this digest and supersession in the corpus manifest' };
  if (sha(baseBytes) !== BASE_SHA || canonicalDigest(base) !== canonicalDigest(parse(baseBytes)) ||
      base.rule !== 's2-008-prereg-v15' || base.preregistration_id !== 'xpr-s2-008c-15' ||
      digest !== '84e15b1b1276c548ad6486fd65a03782f0b9d463cef802d6dcd608accf744268' ||
      digest !== preregistrationDigest(base) || base.status !== 'APPROVED' ||
      canonicalDigest(base.approval) !== canonicalDigest(expectedApproval) ||
      !Number.isFinite(Date.parse(base.approval?.issued_at ?? '')) ||
      base.budget_reservation?.granted_units !== 5000000 || base.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      base.budget_reservation?.expires_at !== EXPIRY) throw new Error('V16_BASE_BINDING_INVALID');
  assertPreregistration(base);
  assertV15PreregistrationPolicy(base);
  assertV14ModelTimeoutPolicy(base.executor?.model_launch_timeout);
  if (sha(supersessionBytes) !== V15_SUPERSESSION_SHA ||
      canonicalDigest(supersession) !== canonicalDigest(parse(supersessionBytes)) ||
      supersession.kind !== 'SUPERSESSION' || supersession.supersedes !== '2f44f017e1b133e91eaad92d49c60bf8d14b39cdea846394724918d2a14fb547' ||
      supersession.replaced_by_preregistration_digest !== digest || supersession.supersession_digest !== V15_SUPERSESSION_DIGEST ||
      manifest.preregistration?.file !== BASE_FILE || manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== digest ||
      manifest.supersession?.file !== 'preregistration-v15-supersession.json' ||
      manifest.supersession.supersession_digest !== supersession.supersession_digest ||
      manifest.supersession_history?.at(-1)?.file !== 'preregistration-v15-supersession.json' ||
      manifest.supersession_history.at(-1).supersession_digest !== supersession.supersession_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v14-superseded.json' ||
      manifest.superseded_preregistration?.preregistration_digest !== supersession.supersedes ||
      manifest.frozen_table?.digest !== canonicalDigest(table) || base.expected_table_digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1)?.anchor_digest) throw new Error('V16_BASE_SUPERSESSION_INVALID');
  assertSourceLedger(ledger.entries, { cases_digest: ledger.entries.at(-1)?.cases_digest, expected_table_digest: canonicalDigest(table) });
  return Object.freeze({ baseDigest: digest, supersessionDigest: supersession.supersession_digest,
    tableDigest: canonicalDigest(table), ledgerDigest: canonicalDigest(ledger) });
}

export function assertV16PriorExecutionReconciliation(base, inputs = readV16PriorExecutionInputs()) {
  const digest = base?.preregistration_digest;
  if (!base || base.rule !== 's2-008-prereg-v15' || digest !== preregistrationDigest(base)) {
    throw new Error('V16_PRIOR_EXECUTION_BASE_INVALID');
  }
  for (const [key, [file, expectedSha]] of Object.entries(PRIOR_FILES)) {
    const item = inputs?.[key];
    if (item?.file !== file || !Buffer.isBuffer(item.bytes) || sha(item.bytes) !== expectedSha) throw new Error('V16_PRIOR_EXECUTION_RAW_INPUT_MISMATCH');
    if (canonicalDigest(item.value ?? null) !== canonicalDigest(parse(item.bytes))) {
      throw new Error(key === 'reconciliation' ? 'V16_PRIOR_EXECUTION_RECONCILIATION_INVALID' : 'V16_PRIOR_EXECUTION_RAW_INPUT_MISMATCH');
    }
  }
  const run = inputs.run.value, recon = inputs.reconciliation.value, owner = inputs.ownerAttestation.value;
  const upstream = inputs.upstreamObservation.value, binding = inputs.upstreamBinding.value;
  const lookup = inputs.generationLookup.value, status = inputs.status.value, predictions = inputs.predictions.value;
  if (run?.status !== 'BLOCKED' || run.raw_run_id !== 's2-008c-v15-a-2f7449f1c8a34f73bbbd' ||
      run.preregistration_digest !== digest || run.model_calls !== 0 || run.unknown_model_attempts !== 1 ||
      run.unreconciled_spend !== true || run.spent_units !== 0 || run.spent_units_is_lower_bound !== true ||
      recon?.status !== 'REQUEST_OUTCOMES_RECONCILED' || recon.raw_run_id !== run.raw_run_id ||
      run.preregistration_digest !== digest ||
      recon.local_model_attempts !== 1 || recon.successful_generations !== 0 || recon.failed_upstream_requests !== 1 ||
      recon.classified_unknown_attempts !== 1 || recon.unclassified_attempts !== 0 ||
      recon.known_tokens_lower_bound !== 0 || recon.known_provider_usd_lower_bound !== 0 ||
      recon.failed_request_tokens_confirmed !== null || recon.failed_request_usd_confirmed !== null ||
      recon.total_tokens_confirmed !== null || recon.total_usd_confirmed !== null ||
      recon.no_cost_claim_for_failed_request !== true || recon.raw_unreconciled_spend_preserved !== true ||
      recon.account_wide_completeness_claimed !== false || recon.financial_reconciliation_complete !== false ||
      recon.completeness?.complete !== true || recon.completeness?.unfiltered !== true ||
      recon.completeness?.includes_errors_and_cancellations !== true ||
      recon.completeness?.statement !== owner.statement || owner.complete !== true || owner.unfiltered !== true ||
      owner.includes_errors_and_cancellations !== true || owner.generations_empty !== true ||
      owner.only_upstream_request !== recon.failed_generation_id ||
      upstream?.status !== 429 || upstream.generation_id !== recon.failed_generation_id ||
      upstream.provider !== 'Google AI Studio' || upstream.model !== 'google/gemma-4-31b-it-20260402' ||
      upstream.variant !== 'free' || upstream.total_latency_ms !== 107 || upstream.attempts !== 1 ||
      upstream.failed_attempts !== 1 || upstream.fallback_latency_ms !== 0 ||
      upstream.generation_api_http_status !== 404 || upstream.failed_request_tokens_confirmed !== null ||
      upstream.failed_request_usd_confirmed !== null || upstream.complete_window_attestation !== null ||
      binding?.generation_id !== recon.failed_generation_id || binding.retry_performed !== false ||
      binding.raw_unreconciled_spend_preserved !== true || binding.B !== 'NOT_RUN' ||
      lookup?.generation_id !== recon.failed_generation_id || lookup.generation_api_http_status !== 404 ||
      lookup.failed_request_tokens_confirmed !== null || lookup.failed_request_usd_confirmed !== null ||
      status?.result?.status !== 'BLOCKED' || status.result.unknown_model_attempts !== 1 ||
      predictions?.accounting?.calls !== 0 || predictions?.accounting?.tokens !== 0) {
    throw new Error('V16_PRIOR_EXECUTION_RECONCILIATION_INVALID');
  }
  const expected = expectedPriorClosure(digest);
  if (inputs.expectedClosure && canonicalDigest(inputs.expectedClosure) !== canonicalDigest(expected)) throw new Error('V16_PRIOR_EXECUTION_RECONCILIATION_INVALID');
  return expected;
}

export function assertV16PresealPin({ pin, baseBytes, commitment = null } = {}) {
  const result = assertVersionedPresealPin({ pin, baseBytes, commitment, version: 16,
    requiredSources: ['pi_runtime_tree','timeout_policy','credential_env_policy','pi_shrinkwrap','pi_package_manifest',
      'pi_launcher','provider_model_catalog','provider_model_catalog_response','provider_model_endpoint_catalog','v16_model_policy','model_call_pacing_policy'] });
  if (pin.first.sources.provider_model_catalog !== V16_MODEL_POLICY.catalog_sha256 ||
      pin.first.sources.provider_model_catalog_response !== V16_MODEL_POLICY.catalog_response_sha256 ||
      pin.first.sources.provider_model_endpoint_catalog !== V16_MODEL_POLICY.endpoint_catalog_sha256) throw new Error('V16_MODEL_POLICY_PIN_INVALID');
  return result;
}
export function createV16Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV16PriorExecutionInputs() }) {
  const lineage = assertV16BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV16PriorExecutionReconciliation(base, restartInputs);
  assertV16ModelCatalogFiles();
  if (!pin) throw new Error('V16_PRESEAL_PIN_REQUIRED');
  const { commitment, covers } = assertV16PresealPin({ pin, baseBytes });
  const executor = {
    ...base.executor, provider: V16_MODEL_POLICY.provider, model: V16_MODEL_POLICY.model,
    credential_env_name: V16_MODEL_POLICY.credential_env_name, credential_source: V16_MODEL_POLICY.credential_source,
    model_call_pacing: { min_start_interval_ms: V16_MODEL_POLICY.min_start_interval_ms },
    model_launch_timeout: createV14ModelTimeoutPolicy(),
    pi_model_registration: structuredClone(V16_MODEL_POLICY.pi_model_registration),
    pi_model_catalog_binding: {
      file: V16_MODEL_POLICY.catalog_file, sha256: V16_MODEL_POLICY.catalog_sha256,
      endpoint_file: V16_MODEL_POLICY.endpoint_catalog_file, endpoint_sha256: V16_MODEL_POLICY.endpoint_catalog_sha256,
      response_file: V16_MODEL_POLICY.catalog_response_file, response_sha256: V16_MODEL_POLICY.catalog_response_sha256,
      canonical_slug: V16_MODEL_POLICY.catalog_slug, endpoint_slug: V16_MODEL_POLICY.endpoint_slug, prompt_price: '0', completion_price: '0',
      prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY', cache_pricing: 'NOT_PROVIDED',
      client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE',
    },
    pi_settings: structuredClone(V7_PI_SETTINGS),
    model_image: { ...base.executor.model_image, content_commitment: commitment, covers, excludes: ['prereg'],
      built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v16.json',
      built_image_pin_reason: 'v16 binds the delegated free Poolside Laguna model, a Poolside-only OpenRouter route with fallbacks disabled, its listed zero prices, explicit process credential, 60-second pacing, and the v15 unknown-outcome closure while preserving frozen science and separate A/B ceilings' },
  };
  assertV16ExecutorPolicy(executor);
  const draft = { ...base, rule: 's2-008-prereg-v16', preregistration_id: 'xpr-s2-008c-16', executor,
    budget_reservation: { ...base.budget_reservation,
      usd_reference: { ...base.budget_reservation.usd_reference,
        why_null: 'No Poolside provider invoice is asserted; the zero-listed catalog price is not an invoice, and provider generation receipts remain authoritative.',
        projection: { ...base.budget_reservation.usd_reference?.projection,
          reason: 'The retained token observation and zero-listed Poolside prices do not establish a Poolside invoice or measured provider cost.' } },
      reservation_id: 'rsv-s2-008c-16',
      granted_units: 5000000, ceiling_scope: 'PER_RUN_A_OR_B', expires_at: EXPIRY },
    v15_prior_execution_reconciliation: prior,
    supersession: { supersedes: base.preregistration_id, superseded_digest: lineage.baseDigest,
      scope: 'free Poolside Laguna model selected under owner delegation and provider catalog binding; preserve frozen science, three trials, pacing, no retries, independent A/B ceilings, expiry and v15 request outcomes',
      reason: 'Continue the frozen campaign with the free Poolside Laguna model selected under owner delegation and preserve unknown v15 failed-request cost and token values as null.',
      unchanged: [...FROZEN_MEMBERS] },
    recorded_before_first_trial: { first_trial: 'NOT_STARTED',
      proof: 'Exact v15 in-force bytes and separate supersession, raw request-outcome closure, delegated free-model selection, provider descriptor, zero listed prices, retry-off policy, and image commitment bind before any v16 trial.' },
    status: 'DRAFT',
    approval: { status: null, authority: 'HUMAN_OWNER', principal_id: null, label: null, issued_at: null,
      signed_digest_over: APPROVAL_DIGEST_SCOPE, in_force: false, becomes_in_force_when: DRAFT_SEAL_TEXT },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertPreregistration(draft);
  assertV16PreregistrationPolicy(draft);
  if (draft.v15_prior_execution_reconciliation.base_preregistration_digest !== lineage.baseDigest ||
      draft.budget_reservation.granted_units !== base.budget_reservation.granted_units ||
      draft.budget_reservation.expires_at !== base.budget_reservation.expires_at) throw new Error('V16_PRIOR_BINDING_MISMATCH');
  return draft;
}
export function approveV16({ draft, base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV16PriorExecutionInputs(), principal, label, issuedAt }) {
  if (principal !== OWNER || label !== 'Daniil' || typeof issuedAt !== 'string' ||
      !Number.isFinite(Date.parse(issuedAt)) || Date.parse(issuedAt) >= Date.parse(EXPIRY)) throw new Error('V16_APPROVAL_IDENTITY_INVALID');
  if (draft?.rule !== 's2-008-prereg-v16' || draft.preregistration_id !== 'xpr-s2-008c-16') throw new Error('V16_VERSION_MISMATCH');
  const approval = draft.approval;
  if (draft.status !== 'DRAFT' || approval?.status !== null ||
      Object.keys(approval ?? {}).sort().join(',') !== 'authority,becomes_in_force_when,in_force,issued_at,label,principal_id,signed_digest_over,status' ||
      approval.authority !== 'HUMAN_OWNER' || approval.principal_id !== null || approval.label !== null ||
      approval.issued_at !== null || approval.signed_digest_over !== APPROVAL_DIGEST_SCOPE || approval.in_force !== false ||
      approval.becomes_in_force_when !== DRAFT_SEAL_TEXT) throw new Error('V16_APPROVAL_METADATA_INVALID');
  assertV16PreregistrationPolicy(draft);
  if (draft.preregistration_digest !== preregistrationDigest(draft)) throw new Error('V16_DIGEST_MISMATCH');
  const lineage = assertV16BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV16PriorExecutionReconciliation(base, restartInputs);
  if (Date.parse(issuedAt) < Date.parse(prior.latest_bound_evidence_at) ||
      canonicalDigest(draft.v15_prior_execution_reconciliation) !== canonicalDigest(prior) ||
      draft.supersession?.superseded_digest !== lineage.baseDigest || draft.expected_table_digest !== canonicalDigest(table)) {
    throw new Error('V16_PRIOR_BINDING_MISMATCH');
  }
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertV16PresealPin({ pin, baseBytes, commitment: draft.executor?.model_image?.content_commitment });
  const expected = createV16Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin, restartInputs });
  if (canonicalDigest(scientificBody(expected)) !== canonicalDigest(scientificBody(draft))) throw new Error('V16_SCOPE_MISMATCH');
  const signed = { ...scientificBody(draft), status: 'APPROVED', approval: { ...approval,
    status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: principal, label, issued_at: issuedAt, in_force: false } };
  return Object.freeze({ ...signed, preregistration_digest: preregistrationDigest(signed) });
}
export { PRIOR_FILES as V16_PRIOR_EXECUTION_FILES };
