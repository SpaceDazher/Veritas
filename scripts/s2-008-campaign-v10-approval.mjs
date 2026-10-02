import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { FROZEN_MEMBERS, preregistrationDigest, scientificBody, scopeDrift } from './s2-008-campaign-approve.mjs';
import { assertVersionedPresealPin } from './s2-008-campaign-v6-approval.mjs';
import { assertV6ModelTimeoutPolicy } from './s2-008-campaign-v6-timeout.mjs';
import { V8_EXECUTOR_POLICY, V7_PI_SETTINGS, assertV8ExecutorPolicy } from './s2-008-campaign-credential-env.mjs';

export { approvalIdentityFromArgv } from './s2-008-campaign-v7-approval.mjs';

const V9_A_RUN_ID = 's2-008c-v9-a-0c58e56c389b4622a70a';
const V9_A_RUN_SHA256 = '5958cdead994c3474a0496cf3bd41b2e9a4de31b02cf82075ff67339ac135b20';
const V9_A_SIDECAR_SHA256 = '69910f08dbb5d60f1373b58400df8e62c49faf3799e8d0c435ffd2f3a830be63';
const V9_PREREG_DIGEST = '6b20bdf8eaa70debcb3ce67ce949caec46fb0f1784c08afcfaeb8381f0c8299d';
const V9_SIDECAR_FILE = 'evidence/s2-008-campaign/predictions-v9-a-trl-s2-008c-01-20260926.json';
const RECONCILIATION_PATH = new URL('../evidence/s2-008-campaign/reconciliation-v9-a.json', import.meta.url);
const PROVIDER_RECEIPT_PATH = new URL('../evidence/s2-008-campaign/provider-receipt-v9-a-attempt-12.json', import.meta.url);
const PRIOR_RUN_PATH = new URL('../evidence/s2-008-campaign/run-v9-a.json', import.meta.url);
const PRIOR_SIDECAR_PATH = new URL('../' + V9_SIDECAR_FILE, import.meta.url);
const BASE_PATH = new URL('../corpus/s2-008-campaign/preregistration.v9.in-force.json', import.meta.url);
const EXPECTED_INTERVAL = Object.freeze({
  from: '2026-10-01T13:41:00.000Z',
  to_exclusive: '2026-10-01T13:45:00.000Z',
});
const EXPECTED_RECONCILIATION_SCOPE =
  'Only stopped v9 A. Earlier v7 spend and unrelated coding sessions are outside this reconciliation.';
const EXPECTED_NEW_RUN_POLICY =
  'A separate signed successor with fresh clean A/B copies of the same tested commit; retain stopped v9 A and do not retry its identity.';
const isCount = (value) => Number.isSafeInteger(value) && value >= 0;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const parseBytes = (value) => JSON.parse(Buffer.from(value).toString('utf8'));

export function readV10ReconciliationInputs() {
  return {
    reconciliation: JSON.parse(fs.readFileSync(RECONCILIATION_PATH, 'utf8')),
    receipt: JSON.parse(fs.readFileSync(PROVIDER_RECEIPT_PATH, 'utf8')),
    priorRunBytes: fs.readFileSync(PRIOR_RUN_PATH),
    priorSidecarBytes: fs.readFileSync(PRIOR_SIDECAR_PATH),
  };
}

export function readV10MeasurementOnDisk() {
  const base = JSON.parse(fs.readFileSync(BASE_PATH, 'utf8'));
  const measurement = base?.budget_reservation?.usd_reference?.measurement;
  if (!measurement || !['input', 'output', 'cacheRead', 'totalTokens'].every((key) =>
    isCount(measurement[key])) || measurement.totalTokens <= 0 ||
    !/^[0-9a-f]{64}$/.test(measurement.traceSha256 || '')) {
    throw new Error('V10_MEASUREMENT_INVALID');
  }
  return structuredClone(measurement);
}

export function assertV10PresealPin(args) {
  return assertVersionedPresealPin({
    ...args,
    version: 10,
    requiredSources: ['pi_runtime_tree', 'timeout_policy', 'credential_env_policy'],
  });
}

export function assertV9AReconciliation({
  reconciliation, receipt, priorRunBytes, priorSidecarBytes,
} = {}) {
  if (!reconciliation || !receipt || priorRunBytes === undefined || priorSidecarBytes === undefined) {
    throw new Error('V10_RECONCILIATION_MISSING');
  }

  const runSha256 = sha256(priorRunBytes);
  if (runSha256 !== V9_A_RUN_SHA256 || reconciliation.prior_run_sha256 !== runSha256) {
    throw new Error('V10_RECONCILIATION_PRIOR_RUN_HASH_MISMATCH');
  }
  const sidecarSha256 = sha256(priorSidecarBytes);
  if (sidecarSha256 !== V9_A_SIDECAR_SHA256 || reconciliation.prior_sidecar_sha256 !== sidecarSha256 ||
      reconciliation.prior_sidecar_file !== V9_SIDECAR_FILE) {
    throw new Error('V10_RECONCILIATION_PRIOR_SIDECAR_HASH_MISMATCH');
  }

  const priorRun = parseBytes(priorRunBytes);
  const priorSidecar = parseBytes(priorSidecarBytes);
  if (reconciliation.prior_run_id !== V9_A_RUN_ID ||
      reconciliation.preregistration_digest !== V9_PREREG_DIGEST ||
      priorRun?.kind !== 's2-008-campaign-v9-predictions/1' ||
      priorRun.status !== 'BLOCKED' ||
      priorRun.raw_run_id !== V9_A_RUN_ID ||
      priorRun.preregistration_digest !== V9_PREREG_DIGEST ||
      priorRun.unreconciled_spend !== true) {
    throw new Error('V10_RECONCILIATION_PRIOR_BINDING_INVALID');
  }
  if (priorSidecar?.kind !== 's2-008-campaign-predictions/1' ||
      priorSidecar.run !== 'a' ||
      priorSidecar.arm_id !== 'arm-model-zai-glm53flash' ||
      priorSidecar.seed !== 20260926 ||
      priorSidecar.outcome_class !== 'INFRA' ||
      priorSidecar.model_calls !== 11 ||
      priorSidecar.spent_tokens !== 6735 ||
      priorSidecar.usd_spent !== 0 ||
      !Array.isArray(priorSidecar.rows) || priorSidecar.rows.length !== 11) {
    throw new Error('V10_RECONCILIATION_PRIOR_SIDECAR_INVALID');
  }

  if (reconciliation.kind !== 's2-008-v9-a-reconciliation/1' ||
      reconciliation.status !== 'RECONCILED' ||
      reconciliation.method !== 'OWNER_CONFIRMED_COMPLETE_PROVIDER_LOG_AND_GENERATION_API' ||
      reconciliation.provider !== 'openrouter' ||
      reconciliation.model !== 'stealth/space-bunny-alpha' ||
      canonicalDigest(reconciliation.interval) !== canonicalDigest(EXPECTED_INTERVAL) ||
      reconciliation.scope !== EXPECTED_RECONCILIATION_SCOPE ||
      reconciliation.new_run_policy !== EXPECTED_NEW_RUN_POLICY ||
      reconciliation.provider_rows_verified_via_api !== true ||
      reconciliation.completeness_verified_via_api !== false) {
    throw new Error('V10_RECONCILIATION_IDENTITY_INVALID');
  }
  const completeness = reconciliation.completeness;
  if (completeness?.confirmed_by !== 'Daniil' ||
      completeness.complete !== true ||
      completeness.unfiltered !== true ||
      completeness.includes_errors_and_cancellations !== true ||
      completeness.statement !== 'Да, полный список без фильтров' ||
      completeness.source !== 'Authenticated owner reply in this conversation') {
    throw new Error('V10_RECONCILIATION_COMPLETENESS_INVALID');
  }

  if (receipt?.kind !== 's2-008-v9-provider-generation-receipt/1' ||
      receipt.http_status !== 200 ||
      receipt.source !== 'https://openrouter.ai/api/v1/generation' ||
      !receipt.data ||
      receipt.data.id !== receipt.generation_id ||
      receipt.data.model !== 'stealth/space-bunny-alpha' ||
      receipt.data.finish_reason !== 'stop' ||
      !isCount(receipt.data.native_tokens_prompt) ||
      !isCount(receipt.data.native_tokens_completion) ||
      !isCount(receipt.data.native_tokens_cached) ||
      !Number.isFinite(receipt.data.total_cost) ||
      receipt.data.total_cost < 0) {
    throw new Error('V10_RECONCILIATION_RECEIPT_INVALID');
  }

  const rows = reconciliation.rows;
  if (!Array.isArray(rows) || rows.length !== 12) {
    throw new Error('V10_RECONCILIATION_ROWS_INVALID');
  }
  const generationIds = new Set();
  const localRows = [];
  const providerOnlyRows = [];
  let allTokens = 0;
  let allUsd = 0;
  for (const row of rows) {
    if (typeof row?.generation_id !== 'string' ||
        !/^gen-[A-Za-z0-9-]+$/.test(row.generation_id) ||
        generationIds.has(row.generation_id)) {
      throw new Error('V10_RECONCILIATION_GENERATION_ID_INVALID');
    }
    generationIds.add(row.generation_id);
    if (![row.input, row.output, row.cached, row.total_tokens].every(isCount) ||
        row.total_tokens !== row.input + row.output ||
        !Number.isFinite(row.provider_reported_usd) ||
        row.provider_reported_usd < 0 ||
        row.source_verified_via_api !== true) {
      throw new Error('V10_RECONCILIATION_ROW_INVALID');
    }
    allTokens += row.total_tokens;
    allUsd += row.provider_reported_usd;
    if (row.local_usage_observed === true) {
      if (row.prediction_recorded !== true ||
          row.receipt?.kind !== 'veritas-openrouter-generation-receipt/1' ||
          row.receipt.source !== 'GET /api/v1/generation' ||
          row.receipt.source_verified_via_api !== true ||
          row.receipt.generation_id !== row.generation_id ||
          row.receipt.model !== 'stealth/space-bunny-alpha' ||
          row.receipt.finish_reason !== 'stop' ||
          ![row.receipt.native_tokens_prompt, row.receipt.native_tokens_completion,
            row.receipt.native_tokens_cached].every(isCount) ||
          row.receipt.native_tokens_prompt !== row.input ||
          row.receipt.native_tokens_completion !== row.output ||
          row.receipt.native_tokens_cached !== row.cached ||
          row.receipt.provider_reported_usd !== row.provider_reported_usd) {
        throw new Error('V10_RECONCILIATION_ROW_INVALID');
      }
      localRows.push(row);
    } else if (row.local_usage_observed === false && row.prediction_recorded === false) {
      providerOnlyRows.push(row);
    } else {
      throw new Error('V10_RECONCILIATION_ROW_INVALID');
    }
  }

  const accounting = priorSidecar.accounting;
  if (accounting?.schema !== 's2-008-model-accounting/1' ||
      accounting.policy !== 'GENERATION_ID_REQUIRED' ||
      !Array.isArray(accounting.rows) ||
      accounting.rows.length !== 11 ||
      accounting.calls !== 11 ||
      accounting.tokens !== 6735 ||
      priorSidecar.accounting.calls !== priorSidecar.model_calls ||
      priorSidecar.accounting.tokens !== priorSidecar.spent_tokens ||
      !Number.isSafeInteger(accounting.prompt_tokens) ||
      !Number.isFinite(accounting.reported_cost_usd) ||
      accounting.reported_cost_usd !== priorSidecar.usd_spent ||
      localRows.length !== 11 ||
      providerOnlyRows.length !== 1) {
    throw new Error('V10_RECONCILIATION_LOCAL_ACCOUNTING_INVALID');
  }

  const sideRows = new Map();
  const sideCaseIds = new Set();
  let localTokens = 0;
  let localUsd = 0;
  let localPromptTokens = 0;
  for (const row of accounting.rows) {
    if (typeof row?.case_id !== 'string' ||
        sideCaseIds.has(row.case_id) ||
        typeof row.generation_id !== 'string' ||
        row.correlation_status !== 'CORRELATED' ||
        row.usage_components_consistent !== true ||
        ![row.input, row.output, row.cacheRead, row.cacheWrite, row.prompt_tokens,
          row.totalTokens].every(isCount) ||
        row.prompt_tokens !== row.input + row.cacheRead + row.cacheWrite ||
        row.prompt_token_basis !== 'input+cacheRead+cacheWrite' ||
        row.totalTokens !== row.prompt_tokens + row.output ||
        !Number.isFinite(row.reported_cost_usd) ||
        row.reported_cost_usd < 0 ||
        sideRows.has(row.generation_id)) {
      throw new Error('V10_RECONCILIATION_LOCAL_ACCOUNTING_INVALID');
    }
    sideCaseIds.add(row.case_id);
    sideRows.set(row.generation_id, row);
    localTokens += row.totalTokens;
    localPromptTokens += row.prompt_tokens;
    localUsd += row.reported_cost_usd;
  }

  const predictionCaseIds = new Set();
  for (const prediction of priorSidecar.rows) {
    if (typeof prediction?.case_id !== 'string' || predictionCaseIds.has(prediction.case_id)) {
      throw new Error('V10_RECONCILIATION_LOCAL_ACCOUNTING_INVALID');
    }
    predictionCaseIds.add(prediction.case_id);
  }
  if (predictionCaseIds.size !== sideCaseIds.size ||
      Array.from(sideCaseIds).some((caseId) => !predictionCaseIds.has(caseId))) {
    throw new Error('V10_RECONCILIATION_LOCAL_ACCOUNTING_INVALID');
  }

  for (const row of localRows) {
    const side = sideRows.get(row.generation_id);
    if (!side ||
        side.case_id !== row.case_id ||
        row.input !== side.prompt_tokens ||
        row.output !== side.output ||
        row.cached !== side.cacheRead ||
        row.total_tokens !== side.totalTokens ||
        row.provider_reported_usd !== side.reported_cost_usd) {
      throw new Error('V10_RECONCILIATION_LOCAL_ACCOUNTING_INVALID');
    }
  }

  const providerOnly = providerOnlyRows[0];
  const externalData = receipt.data;
  if (!providerOnly.receipt ||
      providerOnly.generation_id !== receipt.generation_id ||
      providerOnly.receipt.generation_id !== receipt.generation_id ||
      providerOnly.receipt.http_status !== 200 ||
      providerOnly.receipt.source !== receipt.source ||
      canonicalDigest(providerOnly.receipt.data) !== canonicalDigest(externalData) ||
      providerOnly.input !== externalData.native_tokens_prompt ||
      providerOnly.output !== externalData.native_tokens_completion ||
      providerOnly.cached !== externalData.native_tokens_cached ||
      providerOnly.total_tokens !== externalData.native_tokens_prompt + externalData.native_tokens_completion ||
      providerOnly.provider_reported_usd !== externalData.total_cost ||
      providerOnly.receipt.data.id !== receipt.generation_id) {
    throw new Error('V10_RECONCILIATION_RECEIPT_INVALID');
  }

  const providerReceiptTokens = externalData.native_tokens_prompt + externalData.native_tokens_completion;
  if (localTokens !== 6735 ||
      localPromptTokens !== accounting.prompt_tokens ||
      localUsd !== accounting.reported_cost_usd ||
      allTokens !== 7312 ||
      allUsd !== 0 ||
      providerReceiptTokens !== 577 ||
      reconciliation.matching_requests !== 12 ||
      reconciliation.actual_tokens !== allTokens ||
      reconciliation.actual_usd !== allUsd ||
      reconciliation.locally_accounted_model_calls !== 11 ||
      reconciliation.local_model_attempts !== 12 ||
      reconciliation.predictions_recorded !== 11 ||
      reconciliation.predictions_expected !== 378 ||
      reconciliation.unreconciled_attempts !== 0 ||
      reconciliation.aggregate_campaign_and_diagnostic_tokens !== 7890 ||
      reconciliation.diagnostic_separate?.model_calls !== 1 ||
      reconciliation.diagnostic_separate?.tokens !== 578 ||
      reconciliation.diagnostic_separate?.provider_reported_usd !== 0 ||
      typeof reconciliation.diagnostic_separate?.generation_id !== 'string' ||
      generationIds.has(reconciliation.diagnostic_separate.generation_id)) {
    throw new Error('V10_RECONCILIATION_TOTALS_INVALID');
  }

  return Object.freeze({
    ok: true,
    kind: reconciliation.kind,
    canonicalDigest: canonicalDigest(reconciliation),
    receiptDigest: canonicalDigest(receipt),
    priorRunId: V9_A_RUN_ID,
    priorRunSha256: runSha256,
    priorSidecarSha256: sidecarSha256,
    preregistrationDigest: V9_PREREG_DIGEST,
    localTokens,
    providerReceiptTokens,
    actualTokens: allTokens,
    actualUsd: allUsd,
    modelCalls: reconciliation.matching_requests,
  });
}

export function createV10Draft({
  base, baseBytes, pin, measurement, reconciliation, receipt, priorRunBytes, priorSidecarBytes,
}) {
  if (base?.rule !== 's2-008-prereg-v9' ||
      base.preregistration_id !== 'xpr-s2-008c-09' ||
      base.approval?.in_force !== true ||
      base.preregistration_digest !== preregistrationDigest(base)) {
    throw new Error('V10_BASE_NOT_IN_FORCE');
  }
  const reconciliationBinding = assertV9AReconciliation({
    reconciliation, receipt, priorRunBytes, priorSidecarBytes,
  });
  const { commitment, covers } = assertV10PresealPin({ pin, baseBytes });
  if (!measurement ||
      !['input', 'output', 'cacheRead', 'totalTokens'].every((key) =>
        isCount(measurement[key])) ||
      measurement.totalTokens <= 0 ||
      !/^[0-9a-f]{64}$/.test(measurement.traceSha256 || '')) {
    throw new Error('V10_MEASUREMENT_INVALID');
  }
  assertV6ModelTimeoutPolicy(base.executor?.model_launch_timeout);
  assertV8ExecutorPolicy(base.executor);

  const calls = base.holdout_access.case_count * base.seed_count;
  const projected = calls * measurement.totalTokens;
  if (!Number.isSafeInteger(projected) || projected > base.budget_reservation.granted_units) {
    throw new Error('V10_PROJECTION_EXCEEDS_CEILING');
  }

  const draft = {
    ...base,
    rule: 's2-008-prereg-v10',
    preregistration_id: 'xpr-s2-008c-10',
    executor: {
      ...base.executor,
      ...V8_EXECUTOR_POLICY,
      pi_settings: structuredClone(V7_PI_SETTINGS),
      model_image: {
        ...base.executor.model_image,
        content_commitment: commitment,
        covers,
        excludes: ['prereg'],
        built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v10.json',
        built_image_pin_reason: 'v10 image pin binds this signed OpenRouter document while preserving the v9 executor, provider, model and timeout controls',
      },
    },
    budget_reservation: {
      ...base.budget_reservation,
      reservation_id: 'rsv-s2-008c-10',
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
        aggregate_spend: 'Report A+B separately; reconciled v9 A historical spend is reported separately.',
      },
    },
    accounting_protocol: {
      schema: 's2-008-model-accounting/1',
      generation_id: 'one unique observed assistant responseId for each v10 model call',
      usage_fields: ['input', 'output', 'cacheRead', 'cacheWrite', 'totalTokens', 'reported_cost_usd'],
      prompt_token_basis: 'input+cacheRead+cacheWrite',
      cost_basis: 'executor-reported estimate; provider invoice not independently verified',
      partial_output: 'per-case records become durable only after the isolated process returns; host power loss can leave only confirmed spend and an unknown attempt',
    },
    restart_reconciliation: {
      kind: reconciliationBinding.kind,
      file: 'evidence/s2-008-campaign/reconciliation-v9-a.json',
      canonical_digest: reconciliationBinding.canonicalDigest,
      receipt_file: 'evidence/s2-008-campaign/provider-receipt-v9-a-attempt-12.json',
      receipt_digest: reconciliationBinding.receiptDigest,
      prior_run_id: reconciliationBinding.priorRunId,
      prior_run_sha256: reconciliationBinding.priorRunSha256,
      prior_sidecar_file: V9_SIDECAR_FILE,
      prior_sidecar_sha256: reconciliationBinding.priorSidecarSha256,
      preregistration_digest: reconciliationBinding.preregistrationDigest,
      reconciled_campaign_tokens: reconciliationBinding.actualTokens,
      reconciled_campaign_usd: reconciliationBinding.actualUsd,
      locally_accounted_tokens: reconciliationBinding.localTokens,
      provider_receipt_tokens: reconciliationBinding.providerReceiptTokens,
      model_calls: reconciliationBinding.modelCalls,
    },
    supersession: {
      supersedes: base.preregistration_id,
      superseded_digest: base.preregistration_digest,
      scope: 'fresh run identity and reconciliation binding; frozen science, executor policy and 5M ceiling per A/B unchanged',
      reason: 'v10 starts separate clean A/B copies after v9 A spend is reconciled; provider, model, controls and frozen science remain unchanged',
      unchanged: [...FROZEN_MEMBERS],
    },
    recorded_before_first_trial: {
      first_trial: 'NOT_STARTED',
      proof: 'The stopped v9 A remains INFRA with 11 predictions from 12 reconciled calls, 7,312 tokens and USD 0. The twelfth attempt is bound to its independently verified provider receipt; v9 B was never run. v10 starts separate clean A/B copies.',
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
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v10 records this digest and supersession in the corpus manifest',
    },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  return draft;
}

export function approveV10({
  draft, base, baseBytes, pin, measurement, reconciliation, receipt, priorRunBytes, priorSidecarBytes,
  table, principal, label, issuedAt,
}) {
  if (typeof principal !== 'string' ||
      !/^prn-[a-z0-9-]+$/.test(principal) ||
      typeof label !== 'string' ||
      !label.trim() ||
      typeof issuedAt !== 'string' ||
      !Number.isFinite(Date.parse(issuedAt))) {
    throw new Error('V10_APPROVAL_IDENTITY_MISSING');
  }
  if (draft?.rule !== 's2-008-prereg-v10' ||
      draft.preregistration_id !== 'xpr-s2-008c-10') {
    throw new Error('V10_VERSION_MISMATCH');
  }
  const reconciliationBinding = assertV9AReconciliation({
    reconciliation, receipt, priorRunBytes, priorSidecarBytes,
  });
  if (draft.restart_reconciliation?.canonical_digest !== reconciliationBinding.canonicalDigest ||
      draft.restart_reconciliation?.receipt_digest !== reconciliationBinding.receiptDigest) {
    throw new Error('V10_RECONCILIATION_BINDING_MISMATCH');
  }
  if (draft.status !== 'DRAFT' || draft.approval?.status !== null) {
    throw new Error('V10_ALREADY_SIGNED');
  }
  if (draft.preregistration_digest !== preregistrationDigest(draft)) {
    throw new Error('V10_DIGEST_MISMATCH');
  }
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  if (draft.expected_table_digest !== canonicalDigest(table)) {
    throw new Error('V10_TABLE_MISMATCH');
  }
  assertV6ModelTimeoutPolicy(draft.executor?.model_launch_timeout);
  assertV8ExecutorPolicy(draft.executor);
  const expected = createV10Draft({
    base, baseBytes, pin, measurement, reconciliation, receipt, priorRunBytes, priorSidecarBytes,
  });
  if (canonicalDigest(scientificBody(expected)) !== canonicalDigest(scientificBody(draft))) {
    throw new Error('V10_SCOPE_MISMATCH');
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