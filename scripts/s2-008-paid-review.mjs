import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, preregistrationDigest } from '../src/lib/research/preregistration.mjs';
import { createA05ReviewServer, hashA05ReviewToken } from './a-mvp05-review.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const STATE = path.join(os.homedir(), '.local/state/veritas/s2-008-paid-review');
const OWNER = 'prn-s2007r-owner';
const PRODUCER = 'prn-s2-008-evidence-importer';
const TOKEN_RE = /^[A-Za-z0-9_-]{24,256}$/;
const DIGEST_RE = /^[0-9a-f]{64}$/;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const addReason = (list, reason) => { if (!list.includes(reason)) list.push(reason); };
const fail = (code) => { const error = new Error(code); error.code = code; throw error; };

function readerFor(root, reasons) {
  let realRoot;
  try { realRoot = fs.realpathSync(root); }
  catch { addReason(reasons, 'EVIDENCE_ROOT_UNAVAILABLE'); return { json: () => null, text: () => null, records: () => [] }; }
  const seen = new Map();
  const insideRoot = (target) => target === realRoot || target.startsWith(realRoot + path.sep);
  function read(relative, allow, required = true) {
    if (typeof relative !== 'string' || !allow.test(relative) || path.posix.normalize(relative) !== relative || relative.startsWith('/')) {
      if (required) addReason(reasons, 'EVIDENCE_PATH_INVALID');
      return null;
    }
    if (seen.has(relative)) return seen.get(relative).value;
    const absolute = path.resolve(realRoot, relative);
    if (!insideRoot(absolute)) {
      if (required) addReason(reasons, 'EVIDENCE_PATH_INVALID');
      return null;
    }
    let value = null;
    let entry;
    let fd;
    try {
      const parent = fs.realpathSync(path.dirname(absolute));
      if (!insideRoot(parent)) {
        entry = { path: relative, invalid: true };
        if (required) addReason(reasons, 'EVIDENCE_PATH_INVALID');
        seen.set(relative, { entry, value: null });
        return null;
      }
      const target = path.join(parent, path.basename(absolute));
      const stat = fs.lstatSync(target);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error('invalid');
      fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      const openedPath = fs.realpathSync('/proc/self/fd/' + fd);
      const openedStat = fs.fstatSync(fd);
      if (!insideRoot(openedPath) || !openedStat.isFile() || openedStat.nlink !== 1
          || openedStat.dev !== stat.dev || openedStat.ino !== stat.ino) {
        entry = { path: relative, invalid: true };
        if (required) addReason(reasons, 'EVIDENCE_PATH_INVALID');
        seen.set(relative, { entry, value: null });
        return null;
      }
      const bytes = fs.readFileSync(fd);
      entry = { path: relative, bytes: bytes.length, sha256: hash(bytes) };
      value = { bytes, text: bytes.toString('utf8'), sha256: entry.sha256 };
    } catch {
      entry = { path: relative, missing: true };
      if (required) addReason(reasons, 'EVIDENCE_FILE_MISSING');
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
    seen.set(relative, { entry, value });
    return value;
  }
  function json(relative, allow, required = true) {
    const value = read(relative, allow, required);
    if (!value) return null;
    try { return JSON.parse(value.text); }
    catch { addReason(reasons, 'EVIDENCE_JSON_INVALID'); return null; }
  }
  return {
    json,
    text: read,
    records: () => [...seen.values()].map((row) => row.entry).sort((a, b) => a.path.localeCompare(b.path)),
  };
}

function verifyRunSidecars(reader, report, version, arm, holdoutCount, sharedIds, reasons) {
  let rows = 0;
  let unparsed = 0;
  let calls = 0;
  let tokens = 0;
  const predictions = new Map();
  const accountingIds = new Set();
  const trials = Array.isArray(report?.trials) ? report.trials : [];
  if (!trials.length) addReason(reasons, 'RUN_TRIALS_MISSING');
  for (const trial of trials) {
    if (typeof trial?.trial_id !== 'string' || typeof trial?.arm_id !== 'string' || !Array.isArray(trial.seeds)) {
      addReason(reasons, 'RUN_TRIALS_INVALID');
      continue;
    }
    for (const seed of trial.seeds) {
      const ref = seed?.predictions?.file;
      const expectedPath = 'evidence/s2-008-campaign/predictions-v' + version + '-' + arm + '-';
      if (typeof ref !== 'string' || !ref.startsWith(expectedPath) || !/^[A-Za-z0-9._-]+\.json$/.test(ref.slice(expectedPath.length))) {
        addReason(reasons, 'RUN_SIDECAR_PATH_INVALID');
        continue;
      }
      const sidecar = reader.json(ref, new RegExp('^evidence/s2-008-campaign/predictions-v' + version + '-' + arm + '-[A-Za-z0-9._-]+\\.json$'));
      if (!sidecar) continue;
      if (sidecar.kind !== 's2-008-campaign-predictions/1'
          || sidecar.run !== arm
          || sidecar.arm_id !== trial.arm_id
          || sidecar.seed !== seed.seed
          || canonicalDigest(sidecar) !== seed.predictions?.digest
          || !Array.isArray(sidecar.rows)
          || sidecar.rows.length !== seed.predictions?.rows) {
        addReason(reasons, 'RUN_SIDECAR_BINDING_INVALID');
        continue;
      }
      rows += sidecar.rows.length;
      unparsed += sidecar.rows.filter((row) => row?.predicted === 'UNPARSED').length;
      for (const row of sidecar.rows) {
        if (typeof row?.case_id !== 'string' || typeof row?.predicted !== 'string') {
          addReason(reasons, 'PREDICTION_ROW_INVALID');
          continue;
        }
        predictions.set(String(seed.seed) + ':' + row.case_id, row.predicted);
      }
      const accounting = sidecar.accounting;
      if (trial.arm_id === 'arm-model-zai-glm53flash') {
        if (!accounting || accounting.policy !== 'GENERATION_ID_REQUIRED' || !Array.isArray(accounting.rows)) {
          addReason(reasons, 'MODEL_ACCOUNTING_MISSING');
          continue;
        }
        calls += accounting.rows.length;
        for (const item of accounting.rows) {
          const id = item?.generation_id;
          const prompt = Number(item?.input) + Number(item?.cacheRead) + Number(item?.cacheWrite);
          if (typeof id !== 'string' || id.length < 8 || sharedIds.has(id)
              || !Number.isSafeInteger(item?.totalTokens)
              || item.totalTokens !== prompt + Number(item?.output)
              || item.prompt_token_basis !== 'input+cacheRead+cacheWrite'
              || item.usage_components_consistent !== true) {
            addReason(reasons, 'MODEL_ACCOUNTING_INVALID');
            continue;
          }
          sharedIds.add(id);
          accountingIds.add(id);
          tokens += item.totalTokens;
        }
        if (accounting.calls !== accounting.rows.length
            || accounting.tokens !== accounting.rows.reduce((sum, item) => sum + Number(item.totalTokens || 0), 0)) {
          addReason(reasons, 'MODEL_ACCOUNTING_SUM_INVALID');
        }
      }
    }
  }
  if (rows > 0 && rows > holdoutCount * 3) addReason(reasons, 'PREDICTION_COUNT_INVALID');
  return { rows, unparsed, calls, tokens, predictions, accountingIds };
}

function basePair(value) {
  return {
    commit: value?.commit_sha ?? value?.base?.commit_sha ?? null,
    tree: value?.tree_sha ?? value?.base?.tree_sha ?? null,
  };
}

function validateReconciliationFile(reader, report, version, arm, preregDigest, accounting, sidecarRefs, reasons, sharedIds) {
  const rel = 'evidence/s2-008-campaign/reconciliation-v' + version + '-' + arm + '.json';
  const reconciliation = reader.json(rel, new RegExp('^evidence/s2-008-campaign/reconciliation-v' + version + '-' + arm + '\\.json$'));
  if (!reconciliation) return { valid: false, tokens: null, usd: null, unreconciledAttempts: null };
  const reportFile = reader.text('evidence/s2-008-campaign/run-v' + version + '-' + arm + '.json',
    new RegExp('^evidence/s2-008-campaign/run-v' + version + '-' + arm + '\\.json$'));
  const receiptRef = reconciliation.known_receipts_file;
  const receiptPrefix = 'evidence/s2-008-campaign/provider-receipts-v' + version + '-' + arm + '-';
  const receiptPathOk = typeof receiptRef === 'string' && receiptRef.startsWith(receiptPrefix)
    && /^[A-Za-z0-9._-]+\.json$/.test(receiptRef.slice(receiptPrefix.length));
  const receipts = receiptPathOk
    ? reader.json(receiptRef, new RegExp('^evidence/s2-008-campaign/provider-receipts-v' + version + '-' + arm + '-[A-Za-z0-9._-]+\\.json$'))
    : null;
  const receiptBytes = receiptPathOk
    ? reader.text(receiptRef, new RegExp('^evidence/s2-008-campaign/provider-receipts-v' + version + '-' + arm + '-[A-Za-z0-9._-]+\\.json$'))
    : null;
  const rows = Array.isArray(reconciliation.rows) ? reconciliation.rows : [];
  const receiptRows = Array.isArray(receipts?.receipts) ? receipts.receipts : [];
  const ids = new Set();
  let tokens = 0;
  let usd = 0;
  for (const row of rows) {
    const id = row?.generation_id;
    const total = Number(row?.total_tokens);
    const cost = Number(row?.provider_reported_usd);
    if (typeof id !== 'string' || ids.has(id) || !Number.isSafeInteger(total) || !Number.isFinite(cost)) {
      addReason(reasons, 'RECONCILIATION_ROWS_INVALID');
      continue;
    }
    ids.add(id);
    tokens += total;
    usd += cost;
  }
  const receiptIds = new Set(receiptRows.map((row) => row?.id));
  const oneSidecar = sidecarRefs.length === 1;
  const valid = reconciliation.kind === 's2-008-v' + version + '-' + arm + '-reconciliation/1'
    && reconciliation.status === 'RECONCILED'
    && reconciliation.preregistration_digest === preregDigest
    && reconciliation.prior_run_id === report.raw_run_id
    && reconciliation.prior_run_sha256 === reportFile?.sha256
    && (oneSidecar
      ? reconciliation.prior_sidecar_file === sidecarRefs[0].path
        && reconciliation.prior_sidecar_sha256 === sidecarRefs[0].sha256
      : Array.isArray(reconciliation.sidecars)
        && reconciliation.sidecars.length === sidecarRefs.length
        && sidecarRefs.every((ref) => reconciliation.sidecars.some((row) => row.file === ref.path && row.sha256 === ref.sha256)))
    && reconciliation.provider === 'openrouter'
    && reconciliation.model === 'stealth/space-bunny-alpha'
    && reconciliation.completeness?.complete === true
    && reconciliation.completeness?.unfiltered === true
    && reconciliation.completeness?.includes_errors_and_cancellations === true
    && reconciliation.completeness?.confirmed_by === 'Daniil'
    && reconciliation.provider_rows_verified_via_api === true
    && reconciliation.completeness_verified_via_api === false
    && reconciliation.unreconciled_attempts === 0
    && reconciliation.matching_requests === accounting.calls
    && reconciliation.actual_tokens === accounting.tokens
    && reconciliation.actual_usd === 0
    && rows.length === accounting.calls
    && receiptRows.length === accounting.calls
    && receiptBytes?.sha256 === reconciliation.known_receipts_sha256
    && receipts?.run_id === report.raw_run_id
    && receipts?.known_calls === accounting.calls
    && receipts?.known_tokens === accounting.tokens
    && receipts?.known_provider_usd === 0
    && receipts?.status === 'KNOWN_GENERATIONS_MATCH'
    && tokens === accounting.tokens
    && usd === 0
    && ids.size === receiptIds.size
    && [...ids].every((id) => receiptIds.has(id))
    && [...ids].every((id) => accounting.accountingIds.has(id))
    && [...ids].every((id) => !sharedIds.has(id) || accounting.accountingIds.has(id));
  if (!valid) addReason(reasons, 'RUN_' + arm.toUpperCase() + '_RECONCILIATION_INVALID');
  return {
    valid,
    tokens: valid ? reconciliation.actual_tokens : null,
    usd: valid ? reconciliation.actual_usd : null,
    unreconciledAttempts: reconciliation.unreconciled_attempts ?? null,
    rawUnknownAttempts: report.unknown_model_attempts ?? null,
    runWasLowerBound: report.spent_units_is_lower_bound === true,
  };
}

function validateHistorical(rootReader, rel, version) {
  const reasons = [];
  const file = rootReader.json(rel, new RegExp('^evidence/s2-008-campaign/reconciliation-v' + version + '-a\\.json$'));
  const record = rootReader.text(rel, new RegExp('^evidence/s2-008-campaign/reconciliation-v' + version + '-a\\.json$'));
  if (!file || !record || file.status !== 'RECONCILED' || file.actual_usd !== 0
      || !Number.isSafeInteger(file.actual_tokens) || file.prior_run_id == null) {
    return { status: 'UNKNOWN', tokens: null, usd: null };
  }
  if (version === 10) {
    const runRel = 'evidence/s2-008-campaign/run-v10-a.json';
    const runText = rootReader.text(runRel, /^evidence\/s2-008-campaign\/run-v10-a\.json$/);
    const stopped = rootReader.json('evidence/s2-008-campaign/stopped-v10-a.json', /^evidence\/s2-008-campaign\/stopped-v10-a\.json$/);
    if (!runText || file.prior_run_sha256 !== runText.sha256 || stopped?.raw_run_sha256 !== runText.sha256) {
      return { status: 'UNKNOWN', tokens: null, usd: null };
    }
    return { status: 'RECONCILED', tokens: file.actual_tokens, usd: file.actual_usd };
  }
  return { status: 'RECONCILED', tokens: file.actual_tokens, usd: file.actual_usd };
}

export function inspectS2PaidReviewEvidence(root = ROOT) {
  const reasons = [];
  const reader = readerFor(root, reasons);
  const manifestPath = 'corpus/s2-008-campaign/manifest.json';
  const manifest = reader.json(manifestPath, /^corpus\/s2-008-campaign\/manifest\.json$/);
  const versionMatch = manifest?.preregistration?.file?.match(/^preregistration\.v(10|11)\.in-force\.json$/);
  const version = versionMatch ? Number(versionMatch[1]) : null;
  if (!versionMatch) addReason(reasons, 'ACTIVE_PREREGISTRATION_PATH_INVALID');
  if (manifest?.preregistration?.status !== 'IN_FORCE'
      || manifest?.preregistration?.sealed_before_first_trial !== true) addReason(reasons, 'ACTIVE_PREREGISTRATION_NOT_IN_FORCE');

  const preregPath = version ? 'corpus/s2-008-campaign/preregistration.v' + version + '.in-force.json' : null;
  const prereg = preregPath ? reader.json(preregPath, /^corpus\/s2-008-campaign\/preregistration\.v(?:10|11)\.in-force\.json$/) : null;
  let digest = null;
  let preregValid = false;
  if (prereg && version) {
    try {
      assertPreregistration(prereg);
      const { approval, status, preregistration_digest: storedDigest, ...body } = prereg;
      digest = canonicalDigest(body);
      preregValid = prereg.rule === 's2-008-prereg-v' + version
        && prereg.preregistration_id === 'xpr-s2-008c-' + String(version).padStart(2, '0')
        && prereg.status === 'APPROVED'
        && approval?.status === 'APPROVED'
        && approval?.authority === 'HUMAN_OWNER'
        && approval?.principal_id === OWNER
        && approval?.in_force === true
        && approval?.signed_digest_over === 'the scientific body: every member except approval, status and preregistration_digest'
        && storedDigest === digest
        && preregistrationDigest(prereg) === digest
        && manifest?.preregistration?.file === 'preregistration.v' + version + '.in-force.json'
        && manifest?.preregistration?.preregistration_digest === digest
        && prereg.executor?.provider === 'openrouter'
        && prereg.executor?.model === 'stealth/space-bunny-alpha'
        && prereg.executor?.model_launch_timeout?.per_model_call_timeout_ms === 180000
        && prereg.executor?.model_launch_timeout?.pi_argv_flags?.includes('--no-tools')
        && prereg.executor?.pi_settings?.retry?.enabled === false
        && prereg.executor?.pi_settings?.retry?.maxRetries === 0
        && prereg.executor?.pi_settings?.cacheWarming === 'off'
        && prereg.executor?.pi_settings?.compaction?.enabled === false;
    } catch {
      preregValid = false;
    }
  }
  if (!preregValid) addReason(reasons, 'ACTIVE_PREREGISTRATION_INVALID');

  const filePattern = /^evidence\/s2-008-campaign\/[A-Za-z0-9._/-]+\.(?:json|log)$/;
  let historyV9 = validateHistorical(reader, 'evidence/s2-008-campaign/reconciliation-v9-a.json', 9);
  if (version === 10 && prereg) {
    const restart = prereg.restart_reconciliation;
    const v9Path = 'evidence/s2-008-campaign/reconciliation-v9-a.json';
    const v9 = reader.json(v9Path, /^evidence\/s2-008-campaign\/reconciliation-v9-a\.json$/);
    const v9Bytes = reader.text(v9Path, /^evidence\/s2-008-campaign\/reconciliation-v9-a\.json$/);
    const v9Run = reader.text('evidence/s2-008-campaign/run-v9-a.json', /^evidence\/s2-008-campaign\/run-v9-a\.json$/);
    const v9SidecarPath = v9?.prior_sidecar_file;
    const v9Sidecar = typeof v9SidecarPath === 'string'
      ? reader.text(v9SidecarPath, /^evidence\/s2-008-campaign\/predictions-v9-a-[A-Za-z0-9._-]+\.json$/) : null;
    const receiptPath = restart?.receipt_file;
    const receipt = typeof receiptPath === 'string'
      ? reader.json(receiptPath, /^evidence\/s2-008-campaign\/provider-receipt-v9-a-attempt-12\.json$/) : null;
    const good = v9 && v9Bytes && v9Run && v9Sidecar && receipt
      && canonicalDigest(v9) === restart?.canonical_digest
      && v9.prior_run_sha256 === v9Run.sha256
      && v9.prior_run_id === restart?.prior_run_id
      && v9.prior_sidecar_sha256 === v9Sidecar.sha256
      && v9.prior_sidecar_file === restart?.prior_sidecar_file
      && v9.preregistration_digest === restart?.preregistration_digest
      && v9.actual_tokens === restart?.reconciled_campaign_tokens
      && v9.actual_usd === restart?.reconciled_campaign_usd
      && canonicalDigest(receipt) === restart?.receipt_digest
      && v9.status === 'RECONCILED';
    historyV9 = good ? { status: 'RECONCILED', tokens: v9.actual_tokens, usd: v9.actual_usd } : { status: 'UNKNOWN', tokens: null, usd: null };
  }
  const historyV10 = validateHistorical(reader, 'evidence/s2-008-campaign/reconciliation-v10-a.json', 10);
  const historyV8 = validateHistorical(reader, 'evidence/s2-008-campaign/reconciliation-v8-a.json', 8);
  reader.text('evidence/s2-008-campaign/operational-block-v7.json', /^evidence\/s2-008-campaign\/operational-block-v7\.json$/, false);

  const stopped = reader.json('evidence/s2-008-campaign/stopped-v10-a.json', /^evidence\/s2-008-campaign\/stopped-v10-a\.json$/);
  const diagnosticTokens = Number.isSafeInteger(stopped?.earlier_authorized_diagnostic_tokens)
    ? stopped.earlier_authorized_diagnostic_tokens : null;

  const campaign = {
    version,
    provider: preregValid ? prereg.executor.provider : null,
    model: preregValid ? prereg.executor.model : null,
    perArmTokenCap: 5000000,
    arms: {
      a: { status: 'NOT_RUN', outcomeClass: null, predictions: 0, expectedPredictions: 378, unparsed: null,
        rawUnknownAttempts: null, rawTokens: null, rawTokensAreLowerBound: false,
        confirmedTokens: null, confirmedUsd: null, unreconciledAttempts: null, financialStatus: 'UNKNOWN' },
      b: { status: 'NOT_RUN', outcomeClass: null, predictions: 0, expectedPredictions: 378, unparsed: null,
        rawUnknownAttempts: null, rawTokens: null, rawTokensAreLowerBound: false,
        confirmedTokens: null, confirmedUsd: null, unreconciledAttempts: null, financialStatus: 'UNKNOWN' },
    },
    evaluationRecord: { status: 'NOT_RUN', recordedVerdict: null, recordedRemarks: null,
      linkage: 'NOT_VALIDATED', independentScoringValidation: 'UNAVAILABLE' },
    aEqualsB: null,
    aggregate: { confirmedTokens: null, complete: false, equalityIsDisclosureOnly: true },
    history: {
      v10: historyV10,
      v9: historyV9,
      v8: historyV8,
      v7: { status: 'UNKNOWN', tokens: null },
      authorizedDiagnosticTokens: diagnosticTokens,
      priorKnownCampaignTokens: historyV10.status === 'RECONCILED' && historyV9.status === 'RECONCILED'
        ? historyV10.tokens + historyV9.tokens : null,
    },
  };

  const baseNames = [
    manifestPath,
    ...(preregPath ? [preregPath] : []),
    'evidence/s2-008-campaign/model-image-pin-v' + (version ?? 10) + '.json',
    'evidence/s2-008-campaign/probes-v' + (version ?? 10) + '.json',
    'evidence/s2-008-campaign/security-probes-v' + (version ?? 10) + '.json',
    'evidence/s2-008-campaign/dry-run-v' + (version ?? 10) + '-clean-base.json',
    'evidence/s2-008-campaign/run-v' + (version ?? 10) + '-a.json',
    'evidence/s2-008-campaign/run-v' + (version ?? 10) + '-b.json',
    'evidence/s2-008-campaign/reconciliation-v' + (version ?? 10) + '-a.json',
    'evidence/s2-008-campaign/reconciliation-v' + (version ?? 10) + '-b.json',
    'evidence/s2-008-campaign/evaluation-v' + (version ?? 10) + '.json',
    'evidence/s2-008-campaign/comparison-v' + (version ?? 10) + '.json',
    ...['npm-test', 'test-research', 'test-s2-008', 'test-s2-002-isolation', 'lint', 'typecheck', 'verify-s2-008']
      .map((name) => 'evidence/s2-008-campaign/v' + (version ?? 10) + '-checks/' + name + '.log'),
  ];
  for (const rel of baseNames) {
    const isCorpus = rel.startsWith('corpus/');
    const allow = isCorpus ? /^corpus\/s2-008-campaign\/[A-Za-z0-9._-]+\.json$/ : filePattern;
    const captured = reader.text(rel, allow, false);
    if (!captured && rel.includes('-checks/')) addReason(reasons, 'VERIFICATION_EVIDENCE_MISSING');
  }

  const pinPath = 'evidence/s2-008-campaign/model-image-pin-v' + (version ?? 10) + '.json';
  const pin = reader.json(pinPath, /^evidence\/s2-008-campaign\/model-image-pin-v(?:10|11)\.json$/);
  const pinOk = pin?.schema === 's2-008-model-image-pin/' + version
    && prereg?.executor?.model_image?.built_image_pin === pinPath
    && typeof pin.first?.imageId === 'string' && pin.first.imageId === pin.second?.imageId
    && pin.first.digest === pin.second?.digest
    && pin.first.content_commitment === pin.second?.content_commitment
    && pin.first.content_commitment === prereg?.executor?.model_image?.content_commitment
    && /^sha256:[0-9a-f]{64}$/.test(pin.first.digest);
  if (!pinOk) addReason(reasons, 'MODEL_IMAGE_PIN_INVALID');

  const probes = reader.json('evidence/s2-008-campaign/probes-v' + (version ?? 10) + '.json', /^evidence\/s2-008-campaign\/probes-v(?:10|11)\.json$/);
  const security = reader.json('evidence/s2-008-campaign/security-probes-v' + (version ?? 10) + '.json', /^evidence\/s2-008-campaign\/security-probes-v(?:10|11)\.json$/);
  const dry = reader.json('evidence/s2-008-campaign/dry-run-v' + (version ?? 10) + '-clean-base.json', /^evidence\/s2-008-campaign\/dry-run-v(?:10|11)-clean-base\.json$/);
  const base = basePair(probes);
  const securityBase = basePair(security);
  const dryBase = basePair(dry);
  if (probes?.status !== 'PASS' || probes?.ok !== true || probes?.exitCode !== 0
      || probes?.preregistration_file !== preregPath || probes?.preregistration_digest !== digest
      || security?.status !== 'PASS' || security?.ok !== true || security?.exitCode !== 0
      || !base.commit || !base.tree || securityBase.commit !== base.commit || securityBase.tree !== base.tree
      || dryBase.commit !== base.commit || dryBase.tree !== base.tree
      || (dry?.model_calls ?? dry?.modelCalls) !== 0
      || (dry?.spent_tokens ?? dry?.tokens ?? 0) !== 0) addReason(reasons, 'PROBE_OR_DRY_RUN_INVALID');

  const sharedIds = new Set();
  const armReconciliations = {};
  const armSidecars = {};
  for (const arm of ['a', 'b']) {
    const rel = 'evidence/s2-008-campaign/run-v' + (version ?? 10) + '-' + arm + '.json';
    const report = reader.json(rel, new RegExp('^evidence/s2-008-campaign/run-v' + (version ?? 10) + '-' + arm + '\\.json$'), false);
    if (!report) {
      campaign.arms[arm].status = 'NOT_RUN';
      addReason(reasons, 'RUN_' + arm.toUpperCase() + '_MISSING');
      continue;
    }
    const baseRun = basePair(report);
    const reportPin = report.model_image_pin ?? report.image_pin ?? {};
    if (report.label !== arm || report.preregistration_digest !== digest
        || reportPin.imageId !== pin?.first?.imageId
        || reportPin.digest !== pin?.first?.digest
        || baseRun.commit !== base.commit || baseRun.tree !== base.tree
        || report.reservation?.granted_units !== 5000000) {
      addReason(reasons, 'RUN_' + arm.toUpperCase() + '_BINDING_INVALID');
    }
    const sidecarRefs = [];
    const originalText = reader.text(rel, new RegExp('^evidence/s2-008-campaign/run-v' + (version ?? 10) + '-' + arm + '\\.json$'));
    const accounting = verifyRunSidecars(reader, report, version ?? 10, arm, 126, sharedIds, reasons);
    for (const trial of report.trials ?? []) for (const seed of trial.seeds ?? []) {
      const ref = seed?.predictions?.file;
      if (typeof ref === 'string') {
        const value = reader.text(ref, new RegExp('^evidence/s2-008-campaign/predictions-v' + (version ?? 10) + '-' + arm + '-[A-Za-z0-9._-]+\\.json$'), false);
        if (value) sidecarRefs.push({ path: ref, sha256: value.sha256 });
      }
    }
    armSidecars[arm] = accounting;
    const recon = validateReconciliationFile(reader, report, version ?? 10, arm, digest, accounting, sidecarRefs, reasons, sharedIds);
    armReconciliations[arm] = recon;
    if (arm === 'a' && version === 10) campaign.history.v10 = { status: recon.valid ? 'RECONCILED' : 'UNKNOWN', tokens: recon.tokens, usd: recon.usd, unreconciledAttempts: recon.unreconciledAttempts, rawUnknownAttempts: recon.rawUnknownAttempts };
    const expected = 126 * 3;
    const measured = report.status === 'MEASURED' && report.unreconciled_spend !== true
      && report.spent_units_is_lower_bound !== true && report.unknown_model_attempts === 0
      && accounting.rows === expected && accounting.calls > 0
      && recon.valid && recon.unreconciledAttempts === 0;
    campaign.arms[arm] = {
      status: report.status === 'MEASURED' ? 'MEASURED' : report.status === 'BLOCKED' ? 'BLOCKED' : 'INVALID',
      outcomeClass: report.outcome_class ?? report.trials?.[0]?.seeds?.[0]?.outcome_class ?? null,
      predictions: accounting.rows,
      expectedPredictions: expected,
      unparsed: accounting.unparsed,
      rawUnknownAttempts: report.unknown_model_attempts ?? null,
      rawTokens: report.spent_units ?? null,
      rawTokensAreLowerBound: report.spent_units_is_lower_bound === true,
      confirmedTokens: recon.valid ? recon.tokens : null,
      confirmedUsd: recon.valid ? recon.usd : null,
      unreconciledAttempts: recon.valid ? recon.unreconciledAttempts : (report.unknown_model_attempts ?? null),
      financialStatus: recon.valid ? 'RECONCILED' : 'UNKNOWN',
    };
    if (report.status !== 'MEASURED' || campaign.arms[arm].outcomeClass !== 'MEASURED') addReason(reasons, 'RUN_' + arm.toUpperCase() + '_INFRA');
    if (accounting.rows !== expected || !measured) addReason(reasons, 'RUN_' + arm.toUpperCase() + '_INCOMPLETE');
  }

  const evaluationPath = 'evidence/s2-008-campaign/evaluation-v' + (version ?? 10) + '.json';
  const comparisonPath = 'evidence/s2-008-campaign/comparison-v' + (version ?? 10) + '.json';
  const evaluation = reader.json(evaluationPath, /^evidence\/s2-008-campaign\/evaluation-v(?:10|11)\.json$/, false);
  const comparison = reader.json(comparisonPath, /^evidence\/s2-008-campaign\/comparison-v(?:10|11)\.json$/, false);
  if (!evaluation) addReason(reasons, 'EVALUATION_MISSING');
  else {
    const linked = Array.isArray(evaluation.runs) && evaluation.runs.length === 2
      && ['a', 'b'].every((arm) => evaluation.runs.some((row) => row.label === arm
        && row.raw_run_id === reader.json('evidence/s2-008-campaign/run-v' + version + '-' + arm + '.json',
          new RegExp('^evidence/s2-008-campaign/run-v' + version + '-' + arm + '\\.json$'), false)?.raw_run_id));
    if (!linked || evaluation.preregistration_digest !== digest
        || evaluation.verdict !== 'PENDING_HUMAN_REVIEW'
        || evaluation.prediction_source !== 'IMMUTABLE_RUN_SIDECARS'
        || evaluation.deterministic_evaluation?.verdict !== 'AGREES'
        || !Array.isArray(evaluation.deterministic_evaluation?.remarks)
        || evaluation.deterministic_evaluation.remarks.length !== 0
        || evaluation.table?.verdict !== 'AGREES') addReason(reasons, 'EVALUATION_INVALID');
    else campaign.evaluationRecord = {
      status: 'RECORDED_LINKED',
      recordedVerdict: evaluation.deterministic_evaluation.verdict,
      recordedRemarks: evaluation.deterministic_evaluation.remarks,
      linkage: 'PREREGISTRATION_AND_RUN_IDS_MATCH',
      independentScoringValidation: 'UNAVAILABLE',
    };
  }
  if (!comparison) addReason(reasons, 'COMPARISON_MISSING');
  else if (comparison.preregistration_digest !== digest) addReason(reasons, 'COMPARISON_BINDING_INVALID');

  const a = campaign.arms.a;
  const b = campaign.arms.b;
  if (a.predictions === a.expectedPredictions && b.predictions === b.expectedPredictions) {
    const left = armSidecars.a?.predictions ?? new Map();
    const right = armSidecars.b?.predictions ?? new Map();
    campaign.aEqualsB = left.size === right.size && [...left].every(([key, value]) => right.get(key) === value);
  }
  if (a.confirmedTokens !== null && b.confirmedTokens !== null) {
    campaign.aggregate = { confirmedTokens: a.confirmedTokens + b.confirmedTokens, complete: true, equalityIsDisclosureOnly: true };
  } else {
    const known = [a.confirmedTokens, b.confirmedTokens].filter((value) => Number.isSafeInteger(value));
    campaign.aggregate = { confirmedTokens: known.length ? known.reduce((sum, value) => sum + value, 0) : null,
      complete: false, equalityIsDisclosureOnly: true };
  }
  addReason(reasons, 'PAID_REVIEW_WORKFLOW_UNAVAILABLE');
  const records = reader.records();
  const artifactManifestDigest = canonicalDigest(records);
  return {
    ready: false,
    state: 'NOT_READY',
    workflow: { mode: 'READ_ONLY', actionable: false },
    version,
    reasons,
    campaign,
    artifactManifest: records,
    artifactManifestDigest,
    expectedArtifactManifestDigest: artifactManifestDigest,
    currentArtifactManifestDigest: artifactManifestDigest,
    reviewSummary: campaign,
  };
}

export function hashS2PaidReviewToken(token) {
  return hashA05ReviewToken(token);
}

export function createS2PaidReviewServer(options = {}) {
  const evidence = inspectS2PaidReviewEvidence(options.evidenceRoot ?? ROOT);
  const expectedTask = evidence.version ? 'abt-s2-008-v' + evidence.version + '-paid-review' : null;
  if (!options.credential || options.credential.principalId !== OWNER || options.credential.taskId !== expectedTask) {
    fail('ACTOR_TASK_MISMATCH');
  }
  const workflow = options.workflow;
  if (!workflow || typeof workflow.status !== 'function') fail('PAID_REVIEW_WORKFLOW_UNAVAILABLE');
  const readOnlyWorkflow = {
    async status(args) {
      const status = await workflow.status(args);
      const reasons = Array.isArray(status?.reasons) ? [...status.reasons] : [];
      addReason(reasons, 'PAID_REVIEW_WORKFLOW_UNAVAILABLE');
      return {
        ...status,
        ready: false,
        state: 'NOT_READY',
        reasons,
        workflow: { mode: 'READ_ONLY', actionable: false },
      };
    },
    async start() { fail('PAID_REVIEW_NOT_READY'); },
    async decide() { fail('DECISION_NOT_AVAILABLE'); },
  };
  return createA05ReviewServer({ ...options, workflow: readOnlyWorkflow, presentation: 'paid-campaign' });
}

export function createS2PaidReviewWorkflow({ pool, evidenceRoot = ROOT } = {}) {
  async function status({ principalId, taskId }) {
    const evidence = inspectS2PaidReviewEvidence(evidenceRoot);
    const expectedTask = evidence.version ? 'abt-s2-008-v' + evidence.version + '-paid-review' : null;
    if (principalId !== OWNER || taskId !== expectedTask) fail('ACTOR_TASK_MISMATCH');
    return {
      ...evidence,
      revision: 1,
      taskId: expectedTask,
      producerPrincipalId: PRODUCER,
      databaseJournal: 'NOT_CREATED_UNTIL_EVIDENCE_READY',
    };
  }
  async function start({ principalId, taskId }) {
    const evidence = inspectS2PaidReviewEvidence(evidenceRoot);
    const expectedTask = evidence.version ? 'abt-s2-008-v' + evidence.version + '-paid-review' : null;
    if (principalId !== OWNER || taskId !== expectedTask) fail('ACTOR_TASK_MISMATCH');
    if (!evidence.ready) fail('PAID_REVIEW_NOT_READY');
    if (!pool) fail('PAID_REVIEW_WORKFLOW_UNAVAILABLE');
    // The current versioned evidence has no validated local import-task contract.
    // Keep the paid review fail-closed until that contract is supplied and reviewed.
    fail('PAID_REVIEW_WORKFLOW_UNAVAILABLE');
  }
  async function decide() {
    fail('DECISION_NOT_AVAILABLE');
  }
  return { status, start, decide };
}

function privateRead(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) || stat.uid !== process.getuid()) fail('PRIVATE_FILE_INVALID');
  return fs.readFileSync(file, 'utf8');
}
function save(file, value, immutable = false) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: immutable ? 'wx' : 'w' });
  if (immutable) fs.chmodSync(file, 0o400);
}
async function main() {
  const mode = process.argv[2];
  if (!['--inspect', '--init', '--serve'].includes(mode) || process.argv.length !== 3) fail('USAGE_S2_PAID_REVIEW');
  const evidence = inspectS2PaidReviewEvidence();
  if (mode === '--inspect') {
    console.log(JSON.stringify({ ready: evidence.ready, version: evidence.version, reasons: evidence.reasons, campaign: evidence.campaign, artifactManifestDigest: evidence.artifactManifestDigest }, null, 2));
    return;
  }
  if (!evidence.version) fail('ACTIVE_PREREGISTRATION_INVALID');
  const dir = path.join(STATE, 'v' + evidence.version);
  const credentialPath = path.join(dir, 'reviewer.private.json');
  if (mode === '--serve') {
    let credential;
    try { credential = JSON.parse(privateRead(credentialPath)); }
    catch { fail('PRIVATE_CREDENTIAL_UNAVAILABLE'); }
    const server = createS2PaidReviewServer({
      credential,
      workflow: createS2PaidReviewWorkflow({ evidenceRoot: ROOT }),
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(8787, '127.0.0.1', resolve);
    });
    console.log(JSON.stringify({ state: 'READ_ONLY', url: 'http://127.0.0.1:8787', version: evidence.version }));
    return;
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tokenPath = path.join(dir, 'reviewer.private.token');
  if (!fs.existsSync(credentialPath)) {
    const token = randomBytes(32).toString('base64url');
    fs.writeFileSync(tokenPath, token, { mode: 0o600, flag: 'wx' });
    save(credentialPath, { tokenHash: hashS2PaidReviewToken(token), principalId: OWNER,
      taskId: 'abt-s2-008-v' + evidence.version + '-paid-review',
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      actions: ['view'] }, true);
  }
  console.log(JSON.stringify({ state: 'READ_ONLY', ready: false, version: evidence.version, reasons: evidence.reasons, token_file: tokenPath, credential_file: credentialPath }));
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(JSON.stringify({ code: error.code ?? error.message ?? 'PAID_REVIEW_FAILED' }));
    process.exitCode = 1;
  });
}
