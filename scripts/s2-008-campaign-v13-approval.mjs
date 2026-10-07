import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, assertSourceLedger } from '../src/lib/research/index.mjs';
import { assertV12RestartReconciliation } from './s2-008-campaign-v12-approval.mjs';
import { assertVersionedPresealPin } from './s2-008-campaign-v6-approval.mjs';
import { assertV6ModelTimeoutPolicy } from './s2-008-campaign-v6-timeout.mjs';
import { FROZEN_MEMBERS, preregistrationDigest, scopeDrift, scientificBody } from './s2-008-campaign-approve.mjs';
import { V13_MODEL_POLICY, V7_PI_SETTINGS, assertV13ExecutorPolicy } from './s2-008-campaign-credential-env.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = 'prn-s2007r-owner';
const BASE_FILE = 'preregistration.v12.in-force.json';
const BASE_DIGEST = 'be2e9cba4629e66d295c2527f6a1842f6282f6526efc10d63acfddec33e0c394';
const BASE_SHA256 = 'c95504d3ff40a11d82c42811e5cc8d2feac027ddb9012c9357ffb8bb34b80018';
const BASE_SUPERSESSION_FILE = 'preregistration-v12-supersession.json';
const BASE_SUPERSESSION_ID = 'spr-f547ffdb1b1ffaa2ce5764a8';
const BASE_SUPERSESSION_DIGEST = '10ae574d3d6dc17ee6da958821545f34c5c0e8ad760e7a6fe843c8968bf4996f';
const BASE_SUPERSESSION_SHA256 = '91c42439b9caeed9ad648b617cc273f97d1fa86ad0a4807f9a6cc2290de9259d';
const BASE_V11_DIGEST = '244a6801e4b1f6ea4bd71097fb70a768113b72f085d4899e876993627590bf4c';
const TABLE_DIGEST = '2e89457f3ad158508c69099e4187e4a045802a8b8a984248b07926236f231bf2';
const V13_EXPIRY = '2026-10-12T00:00:00.000Z';
const A = Object.freeze({
  reconFile: 'evidence/s2-008-campaign/reconciliation-v12-a.json',
  reconSha: '19dca90fb603749b012d11a68317dff36e3d688af28585c85479f1c48a364493',
  reconDigest: '266a48545aa92838a3a3aed0548de05f196020a198fd2db61c2bbbff2b44f352',
  runId: 's2-008c-v12-a-92b479ad27f349728672',
  runFile: 'evidence/s2-008-campaign/run-v12-a.json',
  runSha: '1e64d455a837c8e8c10e5fea1c606231908c134e8b58e0d3fe0bccacf16dbdf4',
  sidecarFile: 'evidence/s2-008-campaign/predictions-v12-a-trl-s2-008c-01-20260926.json',
  sidecarSha: '1db420961471ff82ebc41d68fe16c9460ce53a7f244dd242320ebc70af5e0740',
});
const OWNER_INTERVAL = { from: '2026-10-05T19:34:00.000Z', to_exclusive: '2026-10-05T19:35:00.000Z' };
const DIAGNOSTIC = {
  case_id: 'c7427f4fc7aa6d5f43e9306c1bc8c7fabd82597d', schema: 's2-008-failure-diagnostic/1',
  started_at: '2026-10-05T19:34:52.577Z', finished_at: '2026-10-05T19:34:53.853Z', duration_ms: 1276,
  cli_exit_code: null, cli_signal: null, stop_reason: 'error', error_category: 'PROVIDER_RESPONSE_ERROR',
  http_status: null, provider_reported_status_prefix: { status: 404, source: 'SDK_ERROR_MESSAGE_PREFIX' },
  usage_status: 'ZERO', generation_ids: [], generation_ids_truncated: false,
  stdout: { sha256: '5305fd3eaa5d05dea595d566d569ea64871b664a51daba875ed16bde0adac8fb', bytes: 8471 },
  stderr: { sha256: null, bytes: null },
  error_message: { sha256: 'c30ba227450653ef43ebf154776073007d1c5de727eefe9bef4c842ebc6b8a7f', bytes: 79 },
};
const sha = (value) => createHash('sha256').update(value).digest('hex');
const parse = (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8'));
const bytesOk = (value) => Buffer.isBuffer(value);
const safeRead = (root, name) => {
  const realRoot = fs.realpathSync(root), full = path.resolve(realRoot, name);
  if (!full.startsWith(realRoot + path.sep)) throw new Error('V13_INPUT_PATH_INVALID');
  const stat = fs.lstatSync(full);
  if (!stat.isFile() || stat.isSymbolicLink() || fs.realpathSync(full) !== full) throw new Error('V13_INPUT_FILE_UNSAFE');
  return fs.readFileSync(full);
};

export function historicalV12BaseManifest(manifest, base) {
  if (manifest?.preregistration?.file === BASE_FILE) return manifest;
  const isV13 = manifest?.preregistration?.file === 'preregistration.v13.in-force.json';
  const isV14 = manifest?.preregistration?.file === 'preregistration.v14.in-force.json';
  const isV15 = manifest?.preregistration?.file === 'preregistration.v15.in-force.json';
  if ((!isV13 && !isV14 && !isV15) || manifest.preregistration.status !== 'IN_FORCE') {
    throw new Error('V13_BASE_MANIFEST_INVALID');
  }
  const h = manifest.supersession_history;
  const i = Array.isArray(h) ? h.findIndex((x) => x.file === BASE_SUPERSESSION_FILE &&
    x.supersession_id === BASE_SUPERSESSION_ID && x.supersession_digest === BASE_SUPERSESSION_DIGEST) : -1;
  const v13 = h?.[i + 1];
  const v14 = h?.[i + 2];
  const chainOk = (!isV14 && !isV15) || (v13?.file === 'preregistration-v13-supersession.json' &&
    v13?.supersession_digest === 'cc47b268ecc5e9c1766b44a226a7104d13770d0acbdb0519368e96b272c15f55');
  const v14ChainOk = !isV15 || (v14?.file === 'preregistration-v14-supersession.json' &&
    v14?.supersession_digest === 'c9e53c0cf3a0834136b22be61bb41936998d4a78e76f95cc2d3ec6b05a74b9a9');
  if (i < 0 || !chainOk || !v14ChainOk ||
      manifest.superseded_preregistration?.file !== (isV15 ? 'preregistration-v14-superseded.json'
        : isV14 ? 'preregistration-v13-superseded.json' : 'preregistration-v12-superseded.json') ||
      (isV13 && manifest.superseded_preregistration.preregistration_digest !== BASE_DIGEST)) {
    throw new Error('V13_BASE_MANIFEST_INVALID');
  }
  return {
    ...manifest,
    preregistration: { file: BASE_FILE, status: 'IN_FORCE', preregistration_digest: base.preregistration_digest },
    supersession: h[i], supersession_history: h.slice(0, i + 1),
    superseded_preregistration: { file: 'preregistration-v11-superseded.json',
      preregistration_digest: BASE_V11_DIGEST, status: 'SUPERSEDED', superseded_by: BASE_FILE },
  };
}

export function readV13BaseInputs({ repoRoot = ROOT, allowHistorical = false } = {}) {
  const baseBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/' + BASE_FILE);
  const supersessionBytes = safeRead(repoRoot, 'corpus/s2-008-campaign/' + BASE_SUPERSESSION_FILE);
  const activeManifest = JSON.parse(safeRead(repoRoot, 'corpus/s2-008-campaign/manifest.json'));
  const base = parse(baseBytes), table = JSON.parse(safeRead(repoRoot, 'corpus/s2-008-campaign/frozen-table.v3.json'));
  const ledger = JSON.parse(safeRead(repoRoot, 'corpus/s2-008-campaign/source-ledger.v3.json'));
  const supersession = parse(supersessionBytes);
  if (activeManifest.preregistration?.file !== BASE_FILE && !allowHistorical) throw new Error('V13_BASE_NOT_CURRENT');
  return { base, baseBytes, manifest: historicalV12BaseManifest(activeManifest, base),
    activeManifest, supersession, supersessionBytes, table, ledger };
}

export function readV13PriorV12AInputs({ repoRoot = ROOT } = {}) {
  const reconciliationBytes = safeRead(repoRoot, A.reconFile);
  const runBytes = safeRead(repoRoot, A.runFile);
  const sidecarBytes = safeRead(repoRoot, A.sidecarFile);
  return { reconciliationBytes, runBytes, sidecarBytes,
    reconciliation: parse(reconciliationBytes), run: parse(runBytes), sidecar: parse(sidecarBytes) };
}

export function assertV13BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger } = {}) {
  if (!base || !bytesOk(baseBytes) || !manifest || !supersession || !bytesOk(supersessionBytes) || !table || !ledger?.entries) {
    throw new Error('V13_BASE_INPUTS_MISSING');
  }
  let parsedBase, parsedSupersession;
  try { parsedBase = parse(baseBytes); parsedSupersession = parse(supersessionBytes); }
  catch { throw new Error('V13_BASE_BYTES_INVALID'); }
  if (sha(baseBytes) !== BASE_SHA256 || canonicalDigest(parsedBase) !== canonicalDigest(base) ||
      base.rule !== 's2-008-prereg-v12' || base.preregistration_id !== 'xpr-s2-008c-12' ||
      base.preregistration_digest !== BASE_DIGEST || base.preregistration_digest !== preregistrationDigest(base) ||
      base.status !== 'APPROVED' || base.approval?.status !== 'APPROVED' ||
      base.approval?.authority !== 'HUMAN_OWNER' || base.approval?.principal_id !== OWNER ||
      base.approval?.in_force !== true || !Number.isFinite(Date.parse(base.approval?.issued_at ?? '')) ||
      base.budget_reservation?.granted_units !== 5000000 || base.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      base.budget_reservation?.expires_at !== V13_EXPIRY) throw new Error('V13_BASE_BINDING_INVALID');
  assertPreregistration(base);
  assertV12RestartReconciliation(base);
  if (sha(supersessionBytes) !== BASE_SUPERSESSION_SHA256 ||
      canonicalDigest(parsedSupersession) !== canonicalDigest(supersession) ||
      supersession.kind !== 'SUPERSESSION' || supersession.supersession_id !== BASE_SUPERSESSION_ID ||
      supersession.supersession_digest !== BASE_SUPERSESSION_DIGEST || supersession.supersedes !== BASE_V11_DIGEST ||
      supersession.replaced_by_preregistration_digest !== BASE_DIGEST ||
      supersession.expected_table_digest !== TABLE_DIGEST || canonicalDigest(table) !== TABLE_DIGEST) {
    throw new Error('V13_BASE_SUPERSESSION_INVALID');
  }
  const h = manifest.supersession_history;
  if (manifest.preregistration?.file !== BASE_FILE || manifest.preregistration.status !== 'IN_FORCE' ||
      manifest.preregistration.preregistration_digest !== BASE_DIGEST ||
      manifest.supersession?.file !== BASE_SUPERSESSION_FILE ||
      manifest.supersession.supersession_id !== BASE_SUPERSESSION_ID ||
      manifest.supersession.supersession_digest !== BASE_SUPERSESSION_DIGEST ||
      h?.at(-1)?.file !== BASE_SUPERSESSION_FILE || h.at(-1)?.supersession_id !== BASE_SUPERSESSION_ID ||
      h.at(-1)?.supersession_digest !== BASE_SUPERSESSION_DIGEST ||
      manifest.superseded_preregistration?.file !== 'preregistration-v11-superseded.json' ||
      manifest.superseded_preregistration.preregistration_digest !== BASE_V11_DIGEST ||
      manifest.superseded_preregistration.superseded_by !== BASE_FILE ||
      manifest.frozen_table?.digest !== TABLE_DIGEST || base.expected_table_digest !== TABLE_DIGEST ||
      manifest.source_ledger?.entry_count !== ledger.entries.length ||
      manifest.source_ledger?.last_anchor_digest !== ledger.entries.at(-1)?.anchor_digest) {
    throw new Error('V13_BASE_MANIFEST_INVALID');
  }
  assertSourceLedger(ledger.entries, { cases_digest: ledger.entries.at(-1)?.cases_digest, expected_table_digest: TABLE_DIGEST });
  return Object.freeze({ baseDigest: BASE_DIGEST, baseSha256: BASE_SHA256,
    supersessionId: BASE_SUPERSESSION_ID, supersessionDigest: BASE_SUPERSESSION_DIGEST,
    supersessionSha256: BASE_SUPERSESSION_SHA256, tableDigest: TABLE_DIGEST, ledgerDigest: canonicalDigest(ledger) });
}

export function assertV13PriorV12AReconciliation({ reconciliation, reconciliationBytes, run, runBytes, sidecar, sidecarBytes } = {}) {
  if (!reconciliation || !bytesOk(reconciliationBytes) || !run || !bytesOk(runBytes) || !sidecar || !bytesOk(sidecarBytes)) {
    throw new Error('V13_V12A_INPUTS_MISSING');
  }
  let rawRecon, rawRun, rawSidecar;
  try { rawRecon = parse(reconciliationBytes); rawRun = parse(runBytes); rawSidecar = parse(sidecarBytes); }
  catch { throw new Error('V13_V12A_BYTES_INVALID'); }
  if (canonicalDigest(rawRecon) !== canonicalDigest(reconciliation) || canonicalDigest(rawRun) !== canonicalDigest(run) ||
      canonicalDigest(rawSidecar) !== canonicalDigest(sidecar)) throw new Error('V13_V12A_OBJECT_BYTES_MISMATCH');
  if (sha(reconciliationBytes) !== A.reconSha || canonicalDigest(reconciliation) !== A.reconDigest ||
      sha(runBytes) !== A.runSha || sha(sidecarBytes) !== A.sidecarSha) throw new Error('V13_V12A_RAW_BINDING_INVALID');
  const r = reconciliation;
  if (r.kind !== 's2-008-v12-a-reconciliation/1' || r.status !== 'RECONCILED' ||
      r.prior_run_id !== A.runId || r.prior_run_sha256 !== A.runSha ||
      r.prior_sidecar_file !== A.sidecarFile || r.prior_sidecar_sha256 !== A.sidecarSha ||
      r.preregistration_digest !== BASE_DIGEST || r.method !== 'OWNER_CONFIRMED_EMPTY_INTERVAL' ||
      r.completeness_basis !== 'OWNER_CONFIRMED_EMPTY_INTERVAL' || r.provider !== 'openrouter' ||
      r.model !== 'stealth/space-bunny-alpha' ||
      r.interval?.from !== OWNER_INTERVAL.from || r.interval?.to_exclusive !== OWNER_INTERVAL.to_exclusive ||
      r.interval?.timezone !== 'America/Chicago' || r.interval?.local_date !== '2026-10-05' ||
      r.interval?.local_minute !== '14:34' ||
      r.completeness?.confirmed_by !== 'Daniil' || r.completeness?.principal_id !== OWNER ||
      r.completeness?.complete !== true || r.completeness?.unfiltered !== true ||
      r.completeness?.includes_errors_and_cancellations !== true ||
      r.completeness_verified_via_api !== false || r.provider_rows_verified_via_api !== false ||
      r.matching_requests !== 0 || r.local_model_attempts !== 1 || r.locally_accounted_model_calls !== 0 ||
      r.actual_tokens !== 0 || r.actual_usd !== 0 || r.unreconciled_attempts !== 0 ||
      r.raw_unknown_attempts !== 1 || r.closed_unknown_attempts !== 1 || !Array.isArray(r.rows) || r.rows.length !== 0 ||
      r.campaign_outcome_class !== 'INFRA' || r.predictions_recorded !== 0 || r.predictions_expected !== 378 ||
      r.prior_report_retained_unchanged !== true || r.b?.status !== 'NOT_RUN' ||
      r.scientific_evaluation?.status !== 'NOT_RUN' || r.human_paid_review?.status !== 'NOT_RUN' ||
      r.scope !== 'Only stopped v12 A; account-wide and earlier campaign totals are outside this reconciliation.' ||
      canonicalDigest(r.failure_diagnostic) !== canonicalDigest(DIAGNOSTIC)) throw new Error('V13_V12A_RECONCILIATION_INVALID');
  if (run.kind !== 's2-008-campaign-v12-predictions/1' || run.status !== 'BLOCKED' ||
      run.code !== 'CHARGE_NOT_MEASURABLE' || run.raw_run_id !== A.runId ||
      run.preregistration_digest !== BASE_DIGEST || run.spent_units !== 0 ||
      run.spent_units_is_lower_bound !== true || run.unreconciled_spend !== true ||
      run.model_calls !== 0 || run.model_calls_is_lower_bound !== true || run.unknown_model_attempts !== 1 ||
      run.trials?.length !== 1 || run.trials[0]?.arm_id !== 'arm-model-zai-glm53flash' ||
      run.trials[0]?.seeds?.length !== 1 || run.trials[0].seeds[0]?.seed !== 20260926 ||
      run.trials[0].seeds[0]?.outcome_class !== 'INFRA' || run.trials[0].seeds[0]?.predictions?.rows !== 0) {
    throw new Error('V13_V12A_RUN_INVALID');
  }
  const launch = run.trials[0].seeds[0].launch, arm = launch?.arm_report, start = launch?.real_start;
  if (!launch || launch.exit_code !== 10 || launch.signal !== null || launch.timed_out !== false ||
      start?.proven !== false || start.container_pid !== 1 || !Number.isSafeInteger(start.host_pid) ||
      start.host_pid <= 0 || start.separate_process !== true || start.container_runtime_version !== 'v22.23.3' ||
      start.pin_rechecked_by !== 'assertPinnedModelImage' || arm?.outcome_class !== 'INFRA' ||
      !Array.isArray(arm?.predictions) || arm.predictions.length !== 0 ||
      arm.failure_diagnostics?.length !== 1 || canonicalDigest(arm.failure_diagnostics[0]) !== canonicalDigest(DIAGNOSTIC)) {
    throw new Error('V13_V12A_DIAGNOSTIC_INVALID');
  }
  if (sidecar.kind !== 's2-008-campaign-predictions/1' || sidecar.arm_id !== 'arm-model-zai-glm53flash' ||
      sidecar.seed !== 20260926 || sidecar.outcome_class !== 'INFRA' ||
      sidecar.accounting?.schema !== 's2-008-model-accounting/1' ||
      sidecar.accounting?.policy !== 'GENERATION_ID_REQUIRED' || sidecar.accounting?.calls !== 0 ||
      sidecar.accounting?.tokens !== 0 || sidecar.accounting?.prompt_tokens !== 0 ||
      sidecar.accounting?.reported_cost_usd !== 0 || sidecar.accounting?.rows?.length !== 0 ||
      sidecar.model_calls !== 0 || sidecar.spent_tokens !== 0 || sidecar.usd_spent !== 0 ||
      !Array.isArray(sidecar.rows) || sidecar.rows.length !== 0) {
    throw new Error('V13_V12A_SIDECAR_INVALID');
  }
  return Object.freeze({
    kind: 's2-008-v12-a-reconciliation/1', file: A.reconFile, raw_sha256: A.reconSha,
    canonical_digest: A.reconDigest, prior_run_id: A.runId, prior_run_sha256: A.runSha,
    prior_sidecar_file: A.sidecarFile, prior_sidecar_sha256: A.sidecarSha,
    preregistration_digest: BASE_DIGEST, raw_unknown_attempts: 1, closed_unknown_attempts: 1,
    unreconciled_attempts: 0, scope: 'Only stopped v12 A; account-wide and earlier campaign totals are outside this reconciliation',
  });
}

export function assertV13RestartReconciliation(base, inputs = readV13PriorV12AInputs()) {
  assertV12RestartReconciliation(base);
  return assertV13PriorV12AReconciliation(inputs);
}

export function assertV13PresealPin({ pin, baseBytes, commitment = null }) {
  const result = assertVersionedPresealPin({ pin, baseBytes, commitment, version: 13,
    requiredSources: ['pi_runtime_tree','timeout_policy','credential_env_policy','pi_shrinkwrap',
      'pi_package_manifest','pi_launcher','provider_model_catalog'] });
  if (pin.first.sources.provider_model_catalog !== V13_MODEL_POLICY.catalog_sha256) {
    throw new Error('V13_MODEL_CATALOG_PIN_INVALID');
  }
  return result;
}

export function createV13Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV13PriorV12AInputs() }) {
  const lineage = assertV13BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV13RestartReconciliation(base, restartInputs);
  if (!pin) throw new Error('V13_PRESEAL_PIN_REQUIRED');
  const { commitment, covers } = assertV13PresealPin({ pin, baseBytes });
  assertV6ModelTimeoutPolicy(base.executor?.model_launch_timeout);
  const executor = {
    ...base.executor, provider: V13_MODEL_POLICY.provider, model: V13_MODEL_POLICY.model,
    credential_env_name: V13_MODEL_POLICY.credential_env_name,
    pi_model_registration: structuredClone(V13_MODEL_POLICY.pi_model_registration),
    pi_model_catalog_binding: { file: 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json',
      sha256: V13_MODEL_POLICY.catalog_sha256, canonical_slug: V13_MODEL_POLICY.catalog_slug,
      prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY', cache_pricing: 'NOT_PROVIDED',
      client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE' },
    pi_settings: structuredClone(V7_PI_SETTINGS),
    model_image: { ...base.executor.model_image, content_commitment: commitment, covers, excludes: ['prereg'],
      built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v13.json',
      built_image_pin_reason: 'v13 binds the exact Ling PI model descriptor and staged catalog in a new image while preserving all frozen scientific members and per-leg token ceiling' },
  };
  assertV13ExecutorPolicy(executor);
  const oldRef = base.budget_reservation?.usd_reference ?? {};
  const draft = {
    ...base, rule: 's2-008-prereg-v13', preregistration_id: 'xpr-s2-008c-13', executor,
    budget_reservation: { ...base.budget_reservation, reservation_id: 'rsv-s2-008c-13',
      granted_units: 5000000, ceiling_scope: 'PER_RUN_A_OR_B', expires_at: V13_EXPIRY,
      usd_reference: { confirmed_usd: null, confirmed_usd_status: 'NOT_VERIFIED',
        why_null: 'No Ling provider invoice is asserted by this draft; provider generation receipts remain authoritative.',
        predecessor_reference: { model: base.executor.model, status: 'UNMEASURED_FOR_SELECTED_MODEL',
          measurement: oldRef.measurement ?? null, measurement_basis: oldRef.measurement_basis ?? null },
        projection: { status: 'NOT_PROJECTED_FOR_SELECTED_MODEL',
          reason: 'The retained token observation and provider list price do not provide a Ling cost estimate.' },
        ceiling_scope: 'PER_RUN_A_OR_B' } },
    accounting_protocol: { ...structuredClone(base.accounting_protocol),
      generation_id: 'one unique observed assistant responseId for each Ling model call',
      provider_usage: 'retain per-case native usage and reconcile against OpenRouter generation receipts; PI cost is an estimate only' },
    v12_prior_execution_reconciliation: prior,
    supersession: { supersedes: base.preregistration_id, superseded_digest: base.preregistration_digest,
      scope: 'new v13 identity and exact Ling registration/image; preserve v12 financial closure and v10 restart reconciliation, all frozen science, timeout, egress and per-run ceiling',
      reason: 'v13 changes the selected OpenRouter model and its PI catalog registration while preserving the frozen scientific members, trial list and independent 5,000,000-token A/B ceilings',
      unchanged: [...FROZEN_MEMBERS] },
    recorded_before_first_trial: { first_trial: 'NOT_STARTED',
      proof: 'Exact signed v12 bytes, manifest, v10 restart reconciliation and separately closed v12-A failure are bound before any v13 trial; v12-A scope makes no account-wide completeness claim.' },
    status: 'DRAFT',
    approval: { status: null, authority: 'HUMAN_OWNER', principal_id: null, label: null, issued_at: null,
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: false, becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v13 records this digest and supersession in the corpus manifest' },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertPreregistration(draft);
  if (draft.v12_prior_execution_reconciliation?.raw_sha256 !== A.reconSha ||
      draft.supersession?.superseded_digest !== lineage.baseDigest) throw new Error('V13_PRIOR_BINDING_MISMATCH');
  return draft;
}

export function approveV13({ draft, base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin,
  restartInputs = readV13PriorV12AInputs(), principal, label, issuedAt }) {
  if (principal !== OWNER || label !== 'Daniil' || typeof issuedAt !== 'string' ||
      !Number.isFinite(Date.parse(issuedAt)) || Date.parse(issuedAt) >= Date.parse(V13_EXPIRY)) {
    throw new Error('V13_APPROVAL_IDENTITY_INVALID');
  }
  if (draft?.rule !== 's2-008-prereg-v13' || draft.preregistration_id !== 'xpr-s2-008c-13') throw new Error('V13_VERSION_MISMATCH');
  if (draft.status !== 'DRAFT' || draft.approval?.status !== null) throw new Error('V13_ALREADY_SIGNED');
  if (draft.preregistration_digest !== preregistrationDigest(draft)) throw new Error('V13_DIGEST_MISMATCH');
  const lineage = assertV13BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger });
  const prior = assertV13RestartReconciliation(base, restartInputs);
  const earliestApproval = Math.max(Date.parse(base.approval.issued_at), Date.parse(restartInputs.reconciliation.created_at));
  if (!Number.isFinite(earliestApproval) || Date.parse(issuedAt) < earliestApproval) throw new Error('V13_APPROVAL_CHRONOLOGY_INVALID');
  if (canonicalDigest(draft.v12_prior_execution_reconciliation) !== canonicalDigest(prior) ||
      draft.supersession?.superseded_digest !== lineage.baseDigest || draft.expected_table_digest !== canonicalDigest(table)) {
    throw new Error('V13_PRIOR_BINDING_MISMATCH');
  }
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertV13PresealPin({ pin, baseBytes, commitment: draft.executor?.model_image?.content_commitment });
  const expected = createV13Draft({ base, baseBytes, manifest, supersession, supersessionBytes, table, ledger, pin, restartInputs });
  if (canonicalDigest(scientificBody(expected)) !== canonicalDigest(scientificBody(draft))) throw new Error('V13_SCOPE_MISMATCH');
  const signed = { ...scientificBody(draft), status: 'APPROVED', approval: { ...draft.approval,
    status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: principal, label, issued_at: issuedAt, in_force: false } };
  return Object.freeze({ ...signed, preregistration_digest: preregistrationDigest(signed) });
}
