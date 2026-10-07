import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertContentSupersession } from '../src/lib/research/content-supersession.mjs';
import { assertPreregistration, assertSourceLedger, preregistrationDigest } from '../src/lib/research/index.mjs';
import { FROZEN_MEMBERS, scopeDrift, scientificBody } from './s2-008-campaign-approve.mjs';
import { V7_PI_SETTINGS, V14_MODEL_POLICY, assertV14ExecutorPolicy } from './s2-008-campaign-credential-env.mjs';
import { assertVersionedPresealPin } from './s2-008-campaign-v6-approval.mjs';
import { assertV14ModelTimeoutPolicy, createV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';
import { V15_MODEL_POLICY, assertV15ExecutorPolicy, assertV15ModelCatalogFiles, assertV15PreregistrationPolicy } from './s2-008-campaign-v15-policy.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = 'prn-s2007r-owner', BASE_FILE = 'preregistration.v14.in-force.json';
const BASE_SHA = '77fabbe9ef92c8dbc281a78f7242fa6ce8f42031b8a4642783a2e3869c3d40bc';
const V14_SUPERSESSION_SHA = '4330a5ba0a429e9f8ea151773758ef29c3af75bd1c92c293ca3749371e65c13e';
const V14_SUPERSESSION_DIGEST = 'c9e53c0cf3a0834136b22be61bb41936998d4a78e76f95cc2d3ec6b05a74b9a9';
const APPROVAL_DIGEST_SCOPE = 'the scientific body: every member except approval, status and preregistration_digest';
const DRAFT_SEAL_TEXT = 'scripts/s2-008-campaign-prepare.mjs --seal-v15 records this digest and supersession in the corpus manifest';
const EXPIRY = '2026-10-12T00:00:00.000Z';
const PRIOR_FILES = Object.freeze({
  run: ['evidence/s2-008-campaign/v14-a-stopped/run-v14-a.json', 'f9fecbafd1eedf7dcfc3a953151d922033bfde970d14258b4db325d78975502b'],
  predictions: ['evidence/s2-008-campaign/v14-a-stopped/predictions-v14-a-trl-s2-008c-01-20260926.json', '324ac55ab50ef30ddaf0d051a9427a5f9007666fe2a775ecd8a1eddb91a00204'],
  knownReceipts: ['evidence/s2-008-campaign/v14-a-stopped/known-generation-receipts.json', 'de91fd4f776055fb8e174fa07cbd6911af8ccff952b65108f48d719084dd7931'],
  upstreamObservation: ['evidence/s2-008-campaign/v14-a-stopped/upstream-429-observation.json', '032187c8a473d1a2b050f4ba171fab2b25fd93749645490ffdf64bbb2327def3'],
  ownerList: ['evidence/s2-008-campaign/v14-a-stopped/owner-successful-list-observation.json', 'e91df3ae3812c05d53e583b2ee4359b7c78e6badeb379ca72ffb4af88d5ff617'],
  reconciliation: ['evidence/s2-008-campaign/v14-a-stopped/reconciliation.json', 'd6969fc66cef0da71f9cc35f50d6eef6c685cdf349fd871758002b9ce35b42c9'],
  keyQuota: ['evidence/s2-008-campaign/v14-a-stopped/key-quota-observation.json', '044d8c5161b7b0b096595947c08700904424cc76e2f9930a6b117355ebac81f3'],
  files: ['evidence/s2-008-campaign/v14-a-stopped/files.json', '5f1c13b24c56d4375ac475b3ffc6f8e5066609926d74e97aadfb1fbbad626358'],
});
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const parse = (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8'));
const safeRead = (root, name) => {
  const realRoot = fs.realpathSync(root), full = path.resolve(realRoot, name);
  if (!full.startsWith(realRoot + path.sep)) throw new Error('V15_INPUT_PATH_INVALID');
  const stat = fs.lstatSync(full);
  if (!stat.isFile() || stat.isSymbolicLink() || fs.realpathSync(full) !== full) throw new Error('V15_INPUT_FILE_UNSAFE');
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

function normalizeV14Manifest(manifest, base, supersession) {
  if (manifest?.preregistration?.file === BASE_FILE && manifest.preregistration.status === 'IN_FORCE') return manifest;
  const activeV15 = manifest?.preregistration?.file === 'preregistration.v15.in-force.json';
  const activeV16 = manifest?.preregistration?.file === 'preregistration.v16.in-force.json';
  if ((!activeV15 && !activeV16) || manifest.preregistration.status !== 'IN_FORCE') {
    throw new Error('V15_BASE_MANIFEST_INVALID');
  }
  const history = manifest.supersession_history;
  const index = Array.isArray(history) ? history.findIndex((entry) =>
    entry.file === 'preregistration-v14-supersession.json' && entry.supersession_digest === supersession?.supersession_digest) : -1;
  const v15Successor = history?.[index + 1];
  const v16Successor = history?.[index + 2];
  const activeV16Chain = !activeV16 || (
    v15Successor?.file === 'preregistration-v15-supersession.json' &&
    v15Successor?.supersession_digest === '4387b8d444737a41dbc2738115e55fb0c3a8cf6177cbcd1b4f3629d1cc0c9218' &&
    v16Successor?.file === 'preregistration-v16-supersession.json' &&
    history?.at(-1)?.file === 'preregistration-v16-supersession.json' &&
    history.at(-1)?.supersession_digest === manifest.supersession?.supersession_digest &&
    manifest.superseded_preregistration?.preregistration_digest === '84e15b1b1276c548ad6486fd65a03782f0b9d463cef802d6dcd608accf744268'
  );
  if (index < 0 || !activeV16Chain ||
      manifest.superseded_preregistration?.file !== (activeV16 ? 'preregistration-v15-superseded.json' : 'preregistration-v14-superseded.json') ||
      manifest.superseded_preregistration.preregistration_digest !== (activeV16 ? '84e15b1b1276c548ad6486fd65a03782f0b9d463cef802d6dcd608accf744268' : base.preregistration_digest)) {
    throw new Error('V15_BASE_MANIFEST_INVALID');
  }
  return {
    ...manifest,
    preregistration: { file: BASE_FILE, status: 'IN_FORCE', preregistration_digest: base.preregistration_digest },
    supersession: history[index], supersession_history: history.slice(0, index + 1),
    superseded_preregistration: { file: 'preregistration-v13-superseded.json',
      preregistration_digest: supersession.supersedes, status: 'SUPERSEDED', superseded_by: BASE_FILE },
  };
}
export function readV15BaseInputs({ repoRoot = ROOT, allowHistorical = false } = {}) {
  const baseBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/' + BASE_FILE);
  if (sha(baseBytes) !== BASE_SHA) throw new Error('V15_BASE_BYTES_INVALID');
  const base = parse(baseBytes);
  const activeManifest = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/manifest.json'));
  if (activeManifest.preregistration?.file === 'preregistration.v16.in-force.json') assertV16ActiveSuccessor(repoRoot, activeManifest);
  if (!allowHistorical && activeManifest.preregistration?.file !== BASE_FILE) throw new Error('V15_BASE_NOT_CURRENT');
  const supersessionBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/preregistration-v14-supersession.json');
  const supersession = parse(supersessionBytes);
  const manifest = normalizeV14Manifest(activeManifest, base, supersession);
  const table = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/frozen-table.v3.json'));
  const ledger = parse(safeRead(repoRoot, 'corpus/s2-008-campaign/source-ledger.v3.json'));
  return { repoRoot, base, baseBytes, manifest, activeManifest, supersession, supersessionBytes, table, ledger };
}
function expectedPriorClosure(baseDigest) {
  return Object.freeze({
    kind: 's2-008-v15-v14-prior-request-outcome-closure/1', status: 'REQUEST_OUTCOMES_RECONCILED',
    base_preregistration_digest: baseDigest, raw_run_id: 's2-008c-v14-a-6081b00e762f4fed8029',
    raw_run_sha256: PRIOR_FILES.run[1], reconciliation_sha256: PRIOR_FILES.reconciliation[1],
    prior_supersession_digest: V14_SUPERSESSION_DIGEST, local_attempts: 33, successful_generations: 32,
    failed_upstream_requests: 1, known_tokens: 33246, known_usd: 0,
    failed_request_tokens_confirmed: null, failed_request_usd_confirmed: null,
    total_tokens_confirmed: null, total_usd_confirmed: null, raw_report_unreconciled_spend: true,
    owner_statement: '\u042d\u0442\u043e \u0432\u0441\u0435 \u0431\u043e\u043b\u044c\u0448\u0435 \u043d\u0435\u0442',
    account_wide_completeness_claimed: false, failure_generation_id: 'gen-1791320426-Czrswj5nXxDzTpuQHNXU',
    failure_provider: 'Novita', failure_http_status: 429, failure_total_latency_ms: 186,
    failure_attempts: 1, failure_fallback_latency_ms: 0, failure_generation_api_http_status: 404,
    known_receipts_sha256: PRIOR_FILES.knownReceipts[1], upstream_observation_sha256: PRIOR_FILES.upstreamObservation[1],
    owner_successful_list_sha256: PRIOR_FILES.ownerList[1], key_quota_observation_sha256: PRIOR_FILES.keyQuota[1],
    latest_bound_evidence_at: '2026-10-07T08:58:57.000Z',
  });
}
export function readV15PriorExecutionInputs({ repoRoot = ROOT } = {}) {
  const inputs = { repoRoot };
  for (const [key, [file, expectedSha]] of Object.entries(PRIOR_FILES)) {
    const bytes = safeRead(repoRoot, file);
    if (sha(bytes) !== expectedSha) throw new Error('V15_PRIOR_EXECUTION_RAW_INPUT_MISMATCH');
    inputs[key] = { file, bytes, value: parse(bytes) };
  }
  inputs.expectedClosure = expectedPriorClosure('2f44f017e1b133e91eaad92d49c60bf8d14b39cdea846394724918d2a14fb547');
  return inputs;
}
export function assertV15BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger } = {}) {
  if (!base || !Buffer.isBuffer(baseBytes) || !manifest || !supersession || !Buffer.isBuffer(supersessionBytes) ||
      !table || !Array.isArray(ledger?.entries)) throw new Error('V15_BASE_INPUTS_MISSING');
  const digest = base.preregistration_digest;
  const expectedApproval = { status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: OWNER,
    label: 'Daniil', issued_at: base.approval?.issued_at,
    signed_digest_over: APPROVAL_DIGEST_SCOPE, in_force: true,
    becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v14 records this digest and supersession in the corpus manifest' };
  if (sha(baseBytes) !== BASE_SHA || canonicalDigest(base) !== canonicalDigest(parse(baseBytes)) || base.rule !== 's2-008-prereg-v14' || base.preregistration_id !== 'xpr-s2-008c-14' ||
      digest !== '2f44f017e1b133e91eaad92d49c60bf8d14b39cdea846394724918d2a14fb547' ||
      digest !== preregistrationDigest(base) || base.status !== 'APPROVED' ||
      canonicalDigest(base.approval) !== canonicalDigest(expectedApproval) ||
      !Number.isFinite(Date.parse(base.approval?.issued_at ?? '')) ||
      base.budget_reservation?.granted_units !== 5000000 || base.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      base.budget_reservation?.expires_at !== EXPIRY) throw new Error('V15_BASE_BINDING_INVALID');
  assertPreregistration(base);
  assertV14ExecutorPolicy({ ...base.executor, credential_source: V14_MODEL_POLICY.credential_source,
    model_call_pacing: { min_start_interval_ms: 60000 } });
  assertV14ModelTimeoutPolicy(base.executor?.model_launch_timeout);
  if (sha(supersessionBytes) !== V14_SUPERSESSION_SHA || canonicalDigest(supersession) !== canonicalDigest(parse(supersessionBytes)) || supersession.kind !== 'SUPERSESSION' ||
      supersession.replaced_by_preregistration_digest !== digest ||
      supersession.supersession_digest !== V14_SUPERSESSION_DIGEST ||
      manifest.preregistration?.file !== BASE_FILE || manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== digest ||
      manifest.supersession?.file !== 'preregistration-v14-supersession.json' ||
      manifest.supersession.supersession_digest !== supersession.supersession_digest ||
      manifest.supersession_history?.at(-1)?.file !== 'preregistration-v14-supersession.json' ||
      manifest.supersession_history.at(-1).supersession_digest !== supersession.supersession_digest ||
      manifest.superseded_preregistration?.file !== 'preregistration-v13-superseded.json' ||
      manifest.superseded_preregistration?.preregistration_digest !== supersession.supersedes ||
      manifest.frozen_table?.digest !== canonicalDigest(table) || base.expected_table_digest !== canonicalDigest(table) ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1)?.anchor_digest) throw new Error('V15_BASE_SUPERSESSION_INVALID');
  assertSourceLedger(ledger.entries, { cases_digest: ledger.entries.at(-1)?.cases_digest, expected_table_digest: canonicalDigest(table) });
  return Object.freeze({ baseDigest: digest, supersessionDigest: supersession.supersession_digest,
    tableDigest: canonicalDigest(table), ledgerDigest: canonicalDigest(ledger) });
}
export function assertV15PriorExecutionReconciliation(base, inputs = readV15PriorExecutionInputs()) {
  const digest = base?.preregistration_digest;
  if (!base || base.rule !== 's2-008-prereg-v14' || digest !== preregistrationDigest(base)) {
    throw new Error('V15_PRIOR_EXECUTION_BASE_INVALID');
  }
  for (const [key, [file, expectedSha]] of Object.entries(PRIOR_FILES)) {
    const item = inputs?.[key];
    if (item?.file !== file || !Buffer.isBuffer(item.bytes) || sha(item.bytes) !== expectedSha) throw new Error('V15_PRIOR_EXECUTION_RAW_INPUT_MISMATCH');
    if (canonicalDigest(item.value ?? null) !== canonicalDigest(parse(item.bytes))) {
      throw new Error(key === 'reconciliation' ? 'V15_PRIOR_EXECUTION_RECONCILIATION_INVALID' : 'V15_PRIOR_EXECUTION_RAW_INPUT_MISMATCH');
    }
  }
  const run = inputs.run.value, recon = inputs.reconciliation.value;
  const known = inputs.knownReceipts.value, upstream = inputs.upstreamObservation.value;
  if (run?.status !== 'BLOCKED' || run.raw_run_id !== 's2-008c-v14-a-6081b00e762f4fed8029' ||
      run.preregistration_digest !== digest || run.model_calls !== 32 || run.unknown_model_attempts !== 1 ||
      run.unreconciled_spend !== true || recon?.status !== 'REQUEST_OUTCOMES_RECONCILED' ||
      recon.prior_run_id !== run.raw_run_id || recon.prior_run_sha256 !== PRIOR_FILES.run[1] ||
      recon.preregistration_digest !== digest || recon.local_model_attempts !== 33 ||
      recon.successful_generations !== 32 || recon.failed_upstream_requests !== 1 ||
      recon.known_tokens !== 33246 || recon.known_provider_usd !== 0 ||
      recon.failed_request_tokens_confirmed !== null || recon.failed_request_usd_confirmed !== null ||
      recon.total_tokens_confirmed !== null || recon.total_usd_confirmed !== null ||
      recon.no_cost_claim_for_failed_request !== true || recon.raw_unreconciled_spend_preserved !== true ||
      recon.account_wide_completeness_claimed !== false || recon.classified_unknown_attempts !== 1 || recon.unclassified_attempts !== 0 || recon.completeness?.complete !== true || recon.completeness?.unfiltered !== true || recon.completeness?.includes_errors_and_cancellations !== true || recon.completeness?.statement !== 'Это все больше нет' || known?.status !== 'KNOWN_GENERATIONS_MATCH' ||
      known.known_calls !== 32 || known.known_tokens !== 33246 || known.known_provider_usd !== 0 ||
      known.local_attempts !== 33 || known.unknown_attempts !== 1 || known.unreconciled_spend !== true ||
      known.account_wide_completeness_claimed !== false || !Array.isArray(known.receipts) || known.receipts.length !== 32 ||
      upstream?.status !== 429 || upstream.generation_id !== 'gen-1791320426-Czrswj5nXxDzTpuQHNXU' ||
      upstream.provider !== 'Novita' || upstream.total_latency_ms !== 186 || upstream.attempts !== 1 ||
      upstream.failed_attempts !== 1 || upstream.fallback_latency_ms !== 0 ||
      upstream.generation_api_http_status !== 404 || upstream.failed_request_cost_confirmed !== null ||
      upstream.unknown_attempts_closed !== 0 || upstream.ledger_completeness_confirmed !== false || upstream.raw_run_preserved !== true) {
    throw new Error('V15_PRIOR_EXECUTION_RECONCILIATION_INVALID');
  }
  const expected = expectedPriorClosure(digest);
  if (inputs.expectedClosure && canonicalDigest(inputs.expectedClosure) !== canonicalDigest(expected)) {
    throw new Error('V15_PRIOR_EXECUTION_RECONCILIATION_INVALID');
  }
  return expected;
}
export function assertV15PresealPin({ pin, baseBytes, commitment = null } = {}) {
  const result = assertVersionedPresealPin({ pin, baseBytes, commitment, version: 15,
    requiredSources: ['pi_runtime_tree','timeout_policy','credential_env_policy','pi_shrinkwrap','pi_package_manifest',
      'pi_launcher','provider_model_catalog','provider_model_endpoint_catalog','model_call_pacing_policy'] });
  if (pin.first.sources.provider_model_catalog !== V15_MODEL_POLICY.catalog_sha256 ||
      pin.first.sources.provider_model_endpoint_catalog !== V15_MODEL_POLICY.endpoint_catalog_sha256) throw new Error('V15_MODEL_POLICY_PIN_INVALID');
  return result;
}
export function createV15Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV15PriorExecutionInputs() }) {
  const lineage = assertV15BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV15PriorExecutionReconciliation(base, restartInputs);
  assertV15ModelCatalogFiles();
  if (!pin) throw new Error('V15_PRESEAL_PIN_REQUIRED');
  const { commitment, covers } = assertV15PresealPin({ pin, baseBytes });
  const executor = {
    ...base.executor, provider: V15_MODEL_POLICY.provider, model: V15_MODEL_POLICY.model,
    credential_env_name: V15_MODEL_POLICY.credential_env_name, credential_source: V15_MODEL_POLICY.credential_source,
    model_call_pacing: { min_start_interval_ms: V15_MODEL_POLICY.min_start_interval_ms },
    model_launch_timeout: createV14ModelTimeoutPolicy(),
    pi_model_registration: structuredClone(V15_MODEL_POLICY.pi_model_registration),
    pi_model_catalog_binding: {
      file: V15_MODEL_POLICY.catalog_file, sha256: V15_MODEL_POLICY.catalog_sha256,
      endpoint_file: V15_MODEL_POLICY.endpoint_catalog_file, endpoint_sha256: V15_MODEL_POLICY.endpoint_catalog_sha256,
      canonical_slug: V15_MODEL_POLICY.catalog_slug, prompt_price: '0', completion_price: '0',
      prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY', cache_pricing: 'NOT_PROVIDED',
      client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE',
    },
    pi_settings: structuredClone(V7_PI_SETTINGS),
    model_image: { ...base.executor.model_image, content_commitment: commitment, covers, excludes: ['prereg'],
      built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v15.json',
      built_image_pin_reason: 'v15 binds the free Gemma model selected under owner delegation, its zero-priced provider endpoint, explicit process credential, 60-second pacing and v14 request-outcome closure while preserving frozen science and separate A/B ceilings' },
  };
  assertV15ExecutorPolicy(executor);
  const draft = { ...base, rule: 's2-008-prereg-v15', preregistration_id: 'xpr-s2-008c-15', executor,
    budget_reservation: { ...base.budget_reservation,
      usd_reference: { ...base.budget_reservation.usd_reference,
        why_null: 'No Google AI Studio provider invoice is asserted; the zero-listed catalog price is not an invoice, and provider generation receipts remain authoritative.',
        projection: { ...base.budget_reservation.usd_reference?.projection,
          reason: 'The retained token observation and zero-listed Gemma prices do not establish a Google AI Studio invoice or measured provider cost.' } },
      reservation_id: 'rsv-s2-008c-15',
      granted_units: 5000000, ceiling_scope: 'PER_RUN_A_OR_B', expires_at: EXPIRY },
    v14_prior_execution_reconciliation: prior,
    supersession: { supersedes: base.preregistration_id, superseded_digest: lineage.baseDigest,
      scope: 'free Gemma model selected under owner delegation and provider catalog binding; preserve frozen science, three trials, pacing, no retries, independent A/B ceilings, expiry and v14 request outcomes',
      reason: 'Continue the frozen campaign with the free Gemma model selected under owner delegation and preserve unknown v14 failed-request cost and token values as null.',
      unchanged: [...FROZEN_MEMBERS] },
    recorded_before_first_trial: { first_trial: 'NOT_STARTED',
      proof: 'Exact v14 in-force bytes and separate supersession, raw request outcome evidence, delegated free-model selection, provider descriptor, zero listed prices, retry-off policy, and image commitment bind before any v15 trial.' },
    status: 'DRAFT',
    approval: { status: null, authority: 'HUMAN_OWNER', principal_id: null, label: null, issued_at: null,
      signed_digest_over: APPROVAL_DIGEST_SCOPE, in_force: false, becomes_in_force_when: DRAFT_SEAL_TEXT },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertPreregistration(draft);
  assertV15PreregistrationPolicy(draft);
  if (draft.v14_prior_execution_reconciliation.base_preregistration_digest !== lineage.baseDigest ||
      draft.budget_reservation.granted_units !== base.budget_reservation.granted_units ||
      draft.budget_reservation.expires_at !== base.budget_reservation.expires_at) throw new Error('V15_PRIOR_BINDING_MISMATCH');
  return draft;
}
export function approveV15({ draft, base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV15PriorExecutionInputs(), principal, label, issuedAt }) {
  if (principal !== OWNER || label !== 'Daniil' || typeof issuedAt !== 'string' ||
      !Number.isFinite(Date.parse(issuedAt)) || Date.parse(issuedAt) >= Date.parse(EXPIRY)) throw new Error('V15_APPROVAL_IDENTITY_INVALID');
  if (draft?.rule !== 's2-008-prereg-v15' || draft.preregistration_id !== 'xpr-s2-008c-15') throw new Error('V15_VERSION_MISMATCH');
  const approval = draft.approval;
  if (draft.status !== 'DRAFT' || approval?.status !== null ||
      Object.keys(approval ?? {}).sort().join(',') !== 'authority,becomes_in_force_when,in_force,issued_at,label,principal_id,signed_digest_over,status' ||
      approval.authority !== 'HUMAN_OWNER' || approval.principal_id !== null || approval.label !== null ||
      approval.issued_at !== null || approval.signed_digest_over !== APPROVAL_DIGEST_SCOPE || approval.in_force !== false ||
      approval.becomes_in_force_when !== DRAFT_SEAL_TEXT) throw new Error('V15_APPROVAL_METADATA_INVALID');
  assertV15PreregistrationPolicy(draft);
  if (draft.preregistration_digest !== preregistrationDigest(draft)) throw new Error('V15_DIGEST_MISMATCH');
  const lineage = assertV15BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV15PriorExecutionReconciliation(base, restartInputs);
  if (Date.parse(issuedAt) < Date.parse(prior.latest_bound_evidence_at) ||
      canonicalDigest(draft.v14_prior_execution_reconciliation) !== canonicalDigest(prior) ||
      draft.supersession?.superseded_digest !== lineage.baseDigest || draft.expected_table_digest !== canonicalDigest(table)) {
    throw new Error('V15_PRIOR_BINDING_MISMATCH');
  }
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertV15PresealPin({ pin, baseBytes, commitment: draft.executor?.model_image?.content_commitment });
  const expected = createV15Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin, restartInputs });
  if (canonicalDigest(scientificBody(expected)) !== canonicalDigest(scientificBody(draft))) throw new Error('V15_SCOPE_MISMATCH');
  const signed = { ...scientificBody(draft), status: 'APPROVED', approval: { ...approval,
    status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: principal, label, issued_at: issuedAt, in_force: false } };
  return Object.freeze({ ...signed, preregistration_digest: preregistrationDigest(signed) });
}
export { PRIOR_FILES as V15_PRIOR_EXECUTION_FILES };
