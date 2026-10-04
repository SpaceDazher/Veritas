import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { FROZEN_MEMBERS, preregistrationDigest, scientificBody, scopeDrift } from './s2-008-campaign-approve.mjs';
import { assertVersionedPresealPin } from './s2-008-campaign-v6-approval.mjs';
import { assertV6ModelTimeoutPolicy } from './s2-008-campaign-v6-timeout.mjs';
import { V8_EXECUTOR_POLICY, V7_PI_SETTINGS, assertV8ExecutorPolicy } from './s2-008-campaign-credential-env.mjs';
import { V11_FAILURE_DIAGNOSTICS_POLICY } from './s2-008-campaign-arm-model.mjs';

export { approvalIdentityFromArgv } from './s2-008-campaign-v7-approval.mjs';

const V10_A_RUN_ID = 's2-008c-v10-a-bc03d54342da48479bb2';
const V10_A_RUN_SHA256 = '93bbedfad7f32919cbb100f2152646187ab57c80dc8689da5906e45d9bd451f1';
const V10_A_SIDECAR_SHA256 = 'f44adbf7a50540bc1cc0a28e328edf2ede64e135ba04badcd2687aa060ae167c';
const V10_RECONCILIATION_SHA256 = '147c934d81524761c9f5d973e985d23c25abaa3a7ab29fa970c886ed16b664d0';
const V10_RECONCILIATION_DIGEST = '5f391e89d66376d79da631d822acefb8081d01aa51e530f74afcab1734750d9b';
const V10_KNOWN_RECEIPTS_SHA256 = '103a4a3b1fa2317c5f8c82386bc4826e60241f67077fda726e170f32507306a9';
const V10_OVERLAP_RECEIPT_SHA256 = 'a7927ecb8053a4807e0143ec09050e97e808d6890a8cecfebce5eb916ea91f52';
const V10_PREREG_DIGEST = '580b3fadd655d396662efe21757f0473b830211ef42ae93f230df0445379ae22';
const V10_SIDECAR_FILE = 'evidence/s2-008-campaign/predictions-v10-a-trl-s2-008c-01-20260926.json';
const V10_RECONCILIATION_FILE = 'evidence/s2-008-campaign/reconciliation-v10-a.json';
const V10_KNOWN_RECEIPTS_FILE = 'evidence/s2-008-campaign/provider-receipts-v10-a-known.json';
const V10_OVERLAP_RECEIPT_FILE = 'evidence/s2-008-campaign/provider-receipt-v10-a-overlap.json';
const RECONCILIATION_PATH = new URL('../' + V10_RECONCILIATION_FILE, import.meta.url);
const KNOWN_RECEIPTS_PATH = new URL('../' + V10_KNOWN_RECEIPTS_FILE, import.meta.url);
const OVERLAP_RECEIPT_PATH = new URL('../' + V10_OVERLAP_RECEIPT_FILE, import.meta.url);
const PRIOR_RUN_PATH = new URL('../evidence/s2-008-campaign/run-v10-a.json', import.meta.url);
const PRIOR_SIDECAR_PATH = new URL('../' + V10_SIDECAR_FILE, import.meta.url);
const BASE_PATH = new URL('../corpus/s2-008-campaign/preregistration.v10.in-force.json', import.meta.url);
const EXPECTED_INTERVAL = Object.freeze({ from: '2026-10-02T07:00:00.000Z', to_exclusive: '2026-10-02T07:01:00.000Z' });
const isCount = (value) => Number.isSafeInteger(value) && value >= 0;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const parseBytes = (value) => JSON.parse(Buffer.from(value).toString('utf8'));
const isUtcTimestamp = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value) && Number.isFinite(Date.parse(value));

export function overlapWithinPreviousCall(lastKnownReceipt, overlapCreatedAt) {
  if (!isUtcTimestamp(lastKnownReceipt?.created_at) || !isUtcTimestamp(overlapCreatedAt) ||
      !Number.isSafeInteger(lastKnownReceipt?.generation_time) || lastKnownReceipt.generation_time <= 0) return false;
  const start = Date.parse(lastKnownReceipt.created_at);
  const overlap = Date.parse(overlapCreatedAt);
  return overlap >= start && overlap < start + lastKnownReceipt.generation_time;
}


export function readV11ReconciliationInputs() {
  const reconciliationBytes = fs.readFileSync(RECONCILIATION_PATH);
  const knownReceiptBytes = fs.readFileSync(KNOWN_RECEIPTS_PATH);
  const overlapReceiptBytes = fs.readFileSync(OVERLAP_RECEIPT_PATH);
  return {
    reconciliation: parseBytes(reconciliationBytes), reconciliationBytes,
    knownReceipts: parseBytes(knownReceiptBytes), knownReceiptBytes,
    overlapReceipt: parseBytes(overlapReceiptBytes), overlapReceiptBytes,
    priorRunBytes: fs.readFileSync(PRIOR_RUN_PATH), priorSidecarBytes: fs.readFileSync(PRIOR_SIDECAR_PATH),
  };
}

export function readV11MeasurementOnDisk() {
  const base = JSON.parse(fs.readFileSync(BASE_PATH, 'utf8'));
  const measurement = base?.budget_reservation?.usd_reference?.measurement;
  if (!measurement || !['input', 'output', 'cacheRead', 'totalTokens'].every((key) => isCount(measurement[key])) ||
      measurement.totalTokens <= 0 || !/^[0-9a-f]{64}$/.test(measurement.traceSha256 || '')) throw new Error('V11_MEASUREMENT_INVALID');
  return structuredClone(measurement);
}

export function assertV11PresealPin(args) {
  return assertVersionedPresealPin({ ...args, version: 11,
    requiredSources: ['pi_runtime_tree', 'timeout_policy', 'credential_env_policy'] });
}

export function assertV10AReconciliation({
  reconciliation, reconciliationBytes, knownReceipts, knownReceiptBytes,
  overlapReceipt, overlapReceiptBytes, priorRunBytes, priorSidecarBytes,
} = {}) {
  if (!reconciliation || !reconciliationBytes || !knownReceipts || !knownReceiptBytes || !overlapReceipt ||
      !overlapReceiptBytes || priorRunBytes === undefined || priorSidecarBytes === undefined) throw new Error('V11_RECONCILIATION_MISSING');
  if (sha256(reconciliationBytes) !== V10_RECONCILIATION_SHA256 ||
      canonicalDigest(reconciliation) !== V10_RECONCILIATION_DIGEST ||
      canonicalDigest(parseBytes(reconciliationBytes)) !== V10_RECONCILIATION_DIGEST) throw new Error('V11_RECONCILIATION_OWNER_BYTES_INVALID');
  if (sha256(knownReceiptBytes) !== V10_KNOWN_RECEIPTS_SHA256 ||
      canonicalDigest(knownReceipts) !== canonicalDigest(parseBytes(knownReceiptBytes))) throw new Error('V11_RECONCILIATION_RECEIPTS_BYTES_INVALID');
  if (sha256(overlapReceiptBytes) !== V10_OVERLAP_RECEIPT_SHA256 ||
      canonicalDigest(overlapReceipt) !== canonicalDigest(parseBytes(overlapReceiptBytes))) throw new Error('V11_RECONCILIATION_OVERLAP_BYTES_INVALID');
  const runSha256 = sha256(priorRunBytes);
  const sidecarSha256 = sha256(priorSidecarBytes);
  if (runSha256 !== V10_A_RUN_SHA256 || sidecarSha256 !== V10_A_SIDECAR_SHA256 ||
      reconciliation.prior_run_sha256 !== runSha256 || reconciliation.prior_sidecar_sha256 !== sidecarSha256 ||
      reconciliation.prior_sidecar_file !== V10_SIDECAR_FILE) throw new Error('V11_RECONCILIATION_PRIOR_HASH_INVALID');
  const run = parseBytes(priorRunBytes);
  const sidecar = parseBytes(priorSidecarBytes);
  if (reconciliation.prior_run_id !== V10_A_RUN_ID || reconciliation.preregistration_digest !== V10_PREREG_DIGEST ||
      run?.kind !== 's2-008-campaign-v10-predictions/1' || run.status !== 'BLOCKED' || run.raw_run_id !== V10_A_RUN_ID ||
      run.preregistration_digest !== V10_PREREG_DIGEST || run.model_calls !== 25 || run.unknown_model_attempts !== 1 ||
      run.spent_units !== 15856 || run.spent_units_is_lower_bound !== true || run.model_calls_is_lower_bound !== true ||
      run.unreconciled_spend !== true || sidecar?.kind !== 's2-008-campaign-predictions/1' || sidecar.run !== 'a' ||
      sidecar.arm_id !== 'arm-model-zai-glm53flash' || sidecar.seed !== 20260926 || sidecar.outcome_class !== 'INFRA' ||
      sidecar.model_calls !== 25 || sidecar.spent_tokens !== 15856 || sidecar.usd_spent !== 0 || sidecar.rows?.length !== 25) {
    throw new Error('V11_RECONCILIATION_PRIOR_RUN_INVALID');
  }
  if (reconciliation.kind !== 's2-008-v10-a-reconciliation/1' || reconciliation.status !== 'RECONCILED' ||
      reconciliation.provider !== 'openrouter' || reconciliation.model !== 'stealth/space-bunny-alpha' ||
      canonicalDigest(reconciliation.interval) !== canonicalDigest(EXPECTED_INTERVAL) ||
      reconciliation.prior_report_retained_unchanged !== true || reconciliation.provider_rows_verified_via_api !== true ||
      reconciliation.completeness_verified_via_api !== false) throw new Error('V11_RECONCILIATION_IDENTITY_INVALID');
  const completeness = reconciliation.completeness;
  if (completeness?.confirmed_by !== 'Daniil' || completeness.complete !== true || completeness.unfiltered !== true ||
      completeness.includes_errors_and_cancellations !== true || completeness.statement !== 'Да, полный список без фильтров' ||
      completeness.source !== 'Direct owner reply in this conversation') throw new Error('V11_RECONCILIATION_COMPLETENESS_INVALID');
  const owner = reconciliation.owner_confirmed_minute;
  if (owner?.total_records !== 10 || owner.matching_known_records !== 9 || owner.excluded_records !== 1 ||
      owner.matching_generation_ids?.length !== 9 || reconciliation.b?.status !== 'NOT_RUN' ||
      reconciliation.b?.model_attempts !== 0 || reconciliation.b?.tokens !== 0) throw new Error('V11_RECONCILIATION_OWNER_LEDGER_INVALID');
  const known = knownReceipts;
  if (known?.kind !== 's2-008-v10-a-known-generations/1' || known.status !== 'KNOWN_GENERATIONS_MATCH' ||
      known.run_id !== V10_A_RUN_ID || known.known_calls !== 25 || known.known_tokens !== 15856 ||
      known.known_provider_usd !== 0 || known.unknown_attempts !== 1 || known.receipts?.length !== 25 ||
      reconciliation.rows?.length !== 25 || sidecar.accounting?.schema !== 's2-008-model-accounting/1' ||
      sidecar.accounting.policy !== 'GENERATION_ID_REQUIRED' || sidecar.accounting.calls !== 25 ||
      sidecar.accounting.tokens !== 15856 || sidecar.accounting.rows?.length !== 25) throw new Error('V11_RECONCILIATION_ROWS_INVALID');

  const receiptById = new Map();
  for (const receipt of known.receipts) {
    if (typeof receipt?.id !== 'string' || !/^gen-\d{10}-[A-Za-z0-9]{20}$/.test(receipt.id) || receiptById.has(receipt.id) ||
        receipt.http_status !== 200 || receipt.model !== 'stealth/space-bunny-alpha' || receipt.provider !== 'Stealth' ||
        ![receipt.native_prompt, receipt.native_completion, receipt.native_cached].every(isCount) ||
        !Number.isFinite(receipt.total_cost) || receipt.total_cost < 0 || receipt.cancelled !== false ||
        receipt.finish_reason !== 'stop' || receipt.matches_local !== true ||
        !isUtcTimestamp(receipt.created_at)) {
      throw new Error('V11_RECONCILIATION_PROVIDER_RECEIPT_INVALID');
    }
    receiptById.set(receipt.id, receipt);
  }
  const accountById = new Map();
  const accountCases = new Set();
  let localTokens = 0;
  let localUsd = 0;
  let promptTokens = 0;
  for (const row of sidecar.accounting.rows) {
    if (typeof row?.case_id !== 'string' || accountCases.has(row.case_id) || typeof row.generation_id !== 'string' || !/^gen-\d{10}-[A-Za-z0-9]{20}$/.test(row.generation_id) ||
        accountById.has(row.generation_id) || row.correlation_status !== 'CORRELATED' || row.usage_components_consistent !== true ||
        ![row.input, row.output, row.cacheRead, row.cacheWrite, row.prompt_tokens, row.totalTokens].every(isCount) ||
        row.prompt_tokens !== row.input + row.cacheRead + row.cacheWrite || row.totalTokens !== row.prompt_tokens + row.output ||
        row.prompt_token_basis !== 'input+cacheRead+cacheWrite' || !Number.isFinite(row.reported_cost_usd) || row.reported_cost_usd < 0) {
      throw new Error('V11_RECONCILIATION_LOCAL_ACCOUNTING_INVALID');
    }
    accountCases.add(row.case_id);
    accountById.set(row.generation_id, row);
    localTokens += row.totalTokens;
    localUsd += row.reported_cost_usd;
    promptTokens += row.prompt_tokens;
  }
  const predictionCases = new Set();
  for (const prediction of sidecar.rows) {
    if (typeof prediction?.case_id !== 'string' || predictionCases.has(prediction.case_id)) throw new Error('V11_RECONCILIATION_PREDICTION_CASES_INVALID');
    predictionCases.add(prediction.case_id);
  }
  if (predictionCases.size !== accountCases.size || [...accountCases].some((id) => !predictionCases.has(id))) throw new Error('V11_RECONCILIATION_PREDICTION_CASES_INVALID');

  const ids = new Set();
  const cases = new Set();
  let providerTokens = 0;
  let providerUsd = 0;
  let inOwnerMinute = 0;
  let beforeOwnerMinute = 0;
  const ownerIds = new Set(owner.matching_generation_ids);
  const from = Date.parse(EXPECTED_INTERVAL.from);
  const to = Date.parse(EXPECTED_INTERVAL.to_exclusive);
  for (const row of reconciliation.rows) {
    if (typeof row?.generation_id !== 'string' || !/^gen-\d{10}-[A-Za-z0-9]{20}$/.test(row.generation_id) || ids.has(row.generation_id) ||
        typeof row.case_id !== 'string' || cases.has(row.case_id) || row.source_verified_via_api !== true ||
        row.local_usage_observed !== true || row.prediction_recorded !== true ||
        ![row.input, row.output, row.cached, row.total_tokens].every(isCount) || row.total_tokens !== row.input + row.output ||
        !Number.isFinite(row.provider_reported_usd) || row.provider_reported_usd < 0) throw new Error('V11_RECONCILIATION_ROW_INVALID');
    const time = Date.parse(row.created_at);
    if (!isUtcTimestamp(row.created_at) || time >= to) throw new Error('V11_RECONCILIATION_PROVIDER_TIME_INVALID');
    if (time >= from) { inOwnerMinute += 1; if (!ownerIds.has(row.generation_id)) throw new Error('V11_RECONCILIATION_OWNER_ROWS_INVALID'); }
    else beforeOwnerMinute += 1;
    ids.add(row.generation_id);
    cases.add(row.case_id);
    const receipt = receiptById.get(row.generation_id);
    const local = accountById.get(row.generation_id);
    if (!receipt || !local || local.case_id !== row.case_id || receipt.created_at !== row.created_at ||
        receipt.native_prompt !== row.input || receipt.native_completion !== row.output || receipt.native_cached !== row.cached ||
        receipt.total_cost !== row.provider_reported_usd || row.input !== local.prompt_tokens || row.output !== local.output ||
        row.cached !== local.cacheRead || row.total_tokens !== local.totalTokens || row.provider_reported_usd !== local.reported_cost_usd) {
      throw new Error('V11_RECONCILIATION_LOCAL_PROVIDER_MISMATCH');
    }
    providerTokens += receipt.native_prompt + receipt.native_completion;
    providerUsd += receipt.total_cost;
  }
  if (ids.size !== 25 || receiptById.size !== 25 || accountById.size !== 25 || inOwnerMinute !== 9 || beforeOwnerMinute !== 16 ||
      ownerIds.size !== 9 || [...ownerIds].some((id) => !ids.has(id))) throw new Error('V11_RECONCILIATION_ID_SET_INVALID');
  const overlap = reconciliation.excluded_rows?.[0];
  const lastKnownReceipt = known.receipts.at(-1);
  if (reconciliation.excluded_rows?.length !== 1 || overlap?.receipt_file !== V10_OVERLAP_RECEIPT_FILE ||
      overlap.receipt_sha256 !== V10_OVERLAP_RECEIPT_SHA256 || overlap.generation_id !== overlapReceipt.id ||
      overlap.created_at !== overlapReceipt.created_at || overlap.native_prompt !== overlapReceipt.native_prompt ||
      overlap.native_completion !== overlapReceipt.native_completion || overlap.finish_reason !== overlapReceipt.finish_reason ||
      overlapReceipt.kind !== 's2-008-v10-a-overlapping-generation/1' || overlapReceipt.http_status !== 200 ||
      overlapReceipt.id !== 'gen-1790924425-AX7ftss7HWmZpRnpRnSV' || overlapReceipt.created_at !== '2026-10-02T07:00:25.518Z' ||
      overlapReceipt.model !== 'stealth/space-bunny-alpha' || overlapReceipt.native_completion !== 575 ||
      overlapReceipt.finish_reason !== 'tool_calls' || overlapReceipt.cancelled !== false || ownerIds.has(overlapReceipt.id) || ids.has(overlapReceipt.id) ||
      owner.matching_generation_ids.at(-1) !== lastKnownReceipt?.id ||
      overlap.owner_supplied_session_id !== '01a0eb96-2f40-7218-9208-e487ecd0f829' ||
      overlap.session_id_verified_via_api !== false ||
      overlap.reason !== 'Starts before the preceding synchronous campaign call can have returned its first response according to provider timing; tool_calls and large prompt also disagree with campaign no-tools short-case configuration.' ||
      !overlapWithinPreviousCall(lastKnownReceipt, overlapReceipt.created_at)) {
    throw new Error('V11_RECONCILIATION_OVERLAP_INVALID');
  }
  const aggregate = reconciliation.aggregate;
  if (localTokens !== 15856 || localUsd !== 0 || promptTokens !== sidecar.accounting.prompt_tokens ||
      providerTokens !== 15856 || providerUsd !== 0 || reconciliation.matching_requests !== 25 ||
      reconciliation.actual_tokens !== 15856 || reconciliation.actual_usd !== 0 || reconciliation.locally_accounted_model_calls !== 25 ||
      reconciliation.local_model_attempts !== 26 || reconciliation.predictions_recorded !== 25 ||
      reconciliation.predictions_expected !== 378 || reconciliation.unreconciled_attempts !== 0 ||
      reconciliation.campaign_outcome_class !== 'INFRA' || aggregate?.earlier_v9_campaign_tokens !== 7312 ||
      aggregate.v9_plus_v10_campaign_tokens !== 23168 || aggregate.separate_diagnostic_tokens !== 578 ||
      aggregate.campaigns_plus_diagnostic_tokens !== 23746) throw new Error('V11_RECONCILIATION_TOTALS_INVALID');
  return Object.freeze({
    ok: true, kind: reconciliation.kind, canonicalDigest: V10_RECONCILIATION_DIGEST,
    reconciliationSha256: V10_RECONCILIATION_SHA256, knownReceiptSha256: V10_KNOWN_RECEIPTS_SHA256,
    overlapReceiptSha256: V10_OVERLAP_RECEIPT_SHA256, priorRunId: V10_A_RUN_ID,
    priorRunSha256: runSha256, priorSidecarSha256: sidecarSha256, preregistrationDigest: V10_PREREG_DIGEST,
    localTokens, providerTokens, actualTokens: providerTokens, actualUsd: providerUsd,
    providerCalls: reconciliation.matching_requests, localAttempts: reconciliation.local_model_attempts,
    unreconciledAttempts: reconciliation.unreconciled_attempts,
    priorV9Tokens: aggregate.earlier_v9_campaign_tokens,
    aggregatePriorTokens: aggregate.v9_plus_v10_campaign_tokens,
    diagnosticTokens: aggregate.separate_diagnostic_tokens,
    aggregateIncludingDiagnostics: aggregate.campaigns_plus_diagnostic_tokens,
  });
}


export function createV11Draft({
  base, baseBytes, pin, measurement, reconciliation, reconciliationBytes, knownReceipts, knownReceiptBytes,
  overlapReceipt, overlapReceiptBytes, priorRunBytes, priorSidecarBytes,
}) {
  if (base?.rule !== 's2-008-prereg-v10' ||
      base.preregistration_id !== 'xpr-s2-008c-10' ||
      base.preregistration_digest !== V10_PREREG_DIGEST ||
      base.approval?.in_force !== true ||
      base.preregistration_digest !== preregistrationDigest(base)) {
    throw new Error('V11_BASE_NOT_IN_FORCE');
  }
  const reconciliationBinding = assertV10AReconciliation({
    reconciliation, reconciliationBytes, knownReceipts, knownReceiptBytes,
    overlapReceipt, overlapReceiptBytes, priorRunBytes, priorSidecarBytes,
  });
  const { commitment, covers } = assertV11PresealPin({ pin, baseBytes });
  if (!measurement ||
      !['input', 'output', 'cacheRead', 'totalTokens'].every((key) =>
        isCount(measurement[key])) ||
      measurement.totalTokens <= 0 ||
      !/^[0-9a-f]{64}$/.test(measurement.traceSha256 || '')) {
    throw new Error('V11_MEASUREMENT_INVALID');
  }
  assertV6ModelTimeoutPolicy(base.executor?.model_launch_timeout);
  assertV8ExecutorPolicy(base.executor);

  const calls = base.holdout_access.case_count * base.seed_count;
  const projected = calls * measurement.totalTokens;
  if (!Number.isSafeInteger(projected) || projected > base.budget_reservation.granted_units) {
    throw new Error('V11_PROJECTION_EXCEEDS_CEILING');
  }

  const draft = {
    ...base,
    rule: 's2-008-prereg-v11',
    preregistration_id: 'xpr-s2-008c-11',
    executor: {
      ...base.executor,
      ...V8_EXECUTOR_POLICY,
      pi_settings: structuredClone(V7_PI_SETTINGS),
      model_image: {
        ...base.executor.model_image,
        content_commitment: commitment,
        covers,
        excludes: ['prereg'],
        built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v11.json',
        built_image_pin_reason: 'v11 image pin binds this signed OpenRouter document while preserving the v10 executor, provider, model and timeout controls',
      },
    },
    budget_reservation: {
      ...base.budget_reservation,
      reservation_id: 'rsv-s2-008c-11',
      usd_reference: {
        ...base.budget_reservation.usd_reference,
        confirmed_usd: null,
        confirmed_usd_status: 'NOT_VERIFIED',
        why_null: 'Client cost.total=0 is not an independently verified provider price.',
        measurement: structuredClone(measurement),
        measurement_basis: 'Inherited signed v9 host measurement; no new provider call is made for this reference.',
        projection: {
          calls,
          cases_per_seed: base.holdout_access.case_count,
          seeds: base.seed_count,
          tokens_per_call: measurement.totalTokens,
          tokens_estimate: projected,
          status: 'PROJECTION_NOT_MEASUREMENT',
          caveat: 'Container configuration is not measured by this host trace. Actual usage is charged during execution; the unchanged per-run ceiling applies independently to A and B.',
        },
        ceiling_scope: 'PER_RUN_A_OR_B',
        aggregate_spend: 'Report A+B separately; reconciled v10 A historical spend is reported separately; prior v9 A and its diagnostic remain separate history.',
      },
    },
    accounting_protocol: {
      schema: 's2-008-model-accounting/1',
      generation_id: 'one unique observed assistant responseId for each v11 model call',
      usage_fields: ['input', 'output', 'cacheRead', 'cacheWrite', 'totalTokens', 'reported_cost_usd'],
      prompt_token_basis: 'input+cacheRead+cacheWrite',
      cost_basis: 'executor-reported estimate; provider invoice not independently verified',
      partial_output: 'per-case records become durable only after the isolated process returns; host power loss can leave only confirmed spend and an unknown attempt',
    },
    failure_diagnostics_protocol: structuredClone(V11_FAILURE_DIAGNOSTICS_POLICY),
    restart_reconciliation: {
      kind: reconciliationBinding.kind,
      file: V10_RECONCILIATION_FILE,
      raw_sha256: reconciliationBinding.reconciliationSha256,
      canonical_digest: reconciliationBinding.canonicalDigest,
      known_receipts_file: V10_KNOWN_RECEIPTS_FILE,
      known_receipts_sha256: reconciliationBinding.knownReceiptSha256,
      overlap_receipt_file: V10_OVERLAP_RECEIPT_FILE,
      overlap_receipt_sha256: reconciliationBinding.overlapReceiptSha256,
      prior_run_id: reconciliationBinding.priorRunId,
      prior_run_sha256: reconciliationBinding.priorRunSha256,
      prior_sidecar_file: V10_SIDECAR_FILE,
      prior_sidecar_sha256: reconciliationBinding.priorSidecarSha256,
      preregistration_digest: reconciliationBinding.preregistrationDigest,
      reconciled_campaign_tokens: reconciliationBinding.actualTokens,
      reconciled_campaign_usd: reconciliationBinding.actualUsd,
      provider_calls: reconciliationBinding.providerCalls,
      local_attempts: reconciliationBinding.localAttempts,
      unreconciled_attempts: reconciliationBinding.unreconciledAttempts,
      prior_v9_campaign_tokens: reconciliationBinding.priorV9Tokens,
      aggregate_prior_campaign_tokens: reconciliationBinding.aggregatePriorTokens,
      separate_v9_diagnostic_tokens: reconciliationBinding.diagnosticTokens,
      aggregate_campaign_and_diagnostic_tokens: reconciliationBinding.aggregateIncludingDiagnostics,
      prior_reconciliation: structuredClone(base.restart_reconciliation),
    },
    supersession: {
      supersedes: base.preregistration_id,
      superseded_digest: base.preregistration_digest,
      scope: 'fresh run identity, diagnostics, and v10 financial reconciliation; frozen science, executor policy and 5M ceiling per A/B unchanged',
      reason: 'v11 starts separate clean A/B copies after v10 A financial spend is reconciled; provider, model, controls and frozen science remain unchanged',
      unchanged: [...FROZEN_MEMBERS],
    },
    recorded_before_first_trial: {
      first_trial: 'NOT_STARTED',
      proof: 'The stopped v10 A remains INFRA with 25 predictions from 26 local attempts. Its 25 provider requests, 15,856 tokens and USD 0 are bound to the owner-confirmed complete ledger; v10 B was never run. v11 starts separate clean A/B copies.',
    },
    status: 'DRAFT',
    approval: {
      status: null,
      authority: 'HUMAN_OWNER',
      principal_id: null,
      label: null,
      issued_at: null,
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: false,
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v11 records this digest and supersession in the corpus manifest',
    },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  return draft;
}

export function approveV11({
  draft, base, baseBytes, pin, measurement, reconciliation, reconciliationBytes, knownReceipts, knownReceiptBytes,
  overlapReceipt, overlapReceiptBytes, priorRunBytes, priorSidecarBytes,
  table, principal, label, issuedAt,
}) {
  if (typeof principal !== 'string' ||
      !/^prn-[a-z0-9-]+$/.test(principal) ||
      typeof label !== 'string' ||
      !label.trim() ||
      typeof issuedAt !== 'string' ||
      !Number.isFinite(Date.parse(issuedAt))) {
    throw new Error('V11_APPROVAL_IDENTITY_MISSING');
  }
  if (draft?.rule !== 's2-008-prereg-v11' ||
      draft.preregistration_id !== 'xpr-s2-008c-11') {
    throw new Error('V11_VERSION_MISMATCH');
  }
  const reconciliationBinding = assertV10AReconciliation({
    reconciliation, reconciliationBytes, knownReceipts, knownReceiptBytes,
    overlapReceipt, overlapReceiptBytes, priorRunBytes, priorSidecarBytes,
  });
  if (draft.restart_reconciliation?.canonical_digest !== reconciliationBinding.canonicalDigest ||
      draft.restart_reconciliation?.raw_sha256 !== reconciliationBinding.reconciliationSha256 ||
      draft.restart_reconciliation?.known_receipts_sha256 !== reconciliationBinding.knownReceiptSha256 ||
      draft.restart_reconciliation?.overlap_receipt_sha256 !== reconciliationBinding.overlapReceiptSha256 ||
      draft.restart_reconciliation?.prior_run_sha256 !== reconciliationBinding.priorRunSha256 ||
      draft.restart_reconciliation?.prior_sidecar_sha256 !== reconciliationBinding.priorSidecarSha256) {
    throw new Error('V11_RECONCILIATION_BINDING_MISMATCH');
  }
  if (draft.status !== 'DRAFT' || draft.approval?.status !== null) {
    throw new Error('V11_ALREADY_SIGNED');
  }
  if (draft.preregistration_digest !== preregistrationDigest(draft)) {
    throw new Error('V11_DIGEST_MISMATCH');
  }
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  if (draft.expected_table_digest !== canonicalDigest(table)) {
    throw new Error('V11_TABLE_MISMATCH');
  }
  assertV6ModelTimeoutPolicy(draft.executor?.model_launch_timeout);
  assertV8ExecutorPolicy(draft.executor);
  const expected = createV11Draft({
    base, baseBytes, pin, measurement, reconciliation, reconciliationBytes, knownReceipts, knownReceiptBytes,
  overlapReceipt, overlapReceiptBytes, priorRunBytes, priorSidecarBytes,
  });
  if (canonicalDigest(scientificBody(expected)) !== canonicalDigest(scientificBody(draft))) {
    throw new Error('V11_SCOPE_MISMATCH');
  }
  const signed = {
    ...scientificBody(draft),
    status: 'APPROVED',
    approval: {
      ...draft.approval,
      status: 'APPROVED',
      authority: 'HUMAN_OWNER',
      principal_id: principal,
      label,
      issued_at: issuedAt,
      in_force: false,
    },
  };
  return Object.freeze({ ...signed, preregistration_digest: preregistrationDigest(signed) });
}