import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { assertPreregistration, preregistrationDigest } from '../src/lib/research/preregistration.mjs';
import { PostgresAgentBoardStore } from '../src/lib/agentboard/store.mjs';
import { assertBoardContract } from '../src/lib/agentboard/contracts.mjs';
import { execute } from '../src/lib/agentboard/commands.mjs';
import { PODMAN_HOST } from '../src/lib/isolation/launch.mjs';
import { BASE_IMAGE } from '../src/lib/isolation/image.mjs';
import { replayA05Journal, setupA05Database } from './a-mvp05-runtime.mjs';
import { createA05ReviewServer, hashA05ReviewToken } from './a-mvp05-review.mjs';
import { decisionIndependent, scoreRecordedPredictions, scoreV4Trial, validateV11ProbeEvidence, validateV12ProbeEvidence, validateV13ProbeEvidence, validateV14ProbeEvidence, validateV15ProbeEvidence, V14_REVIEW_CAPSULE_SOURCE_PATHS, V15_REVIEW_CAPSULE_SOURCE_PATHS, buildV15ReviewCapsuleSourceInputs, verifyV4FrozenTable } from './s2-008-campaign-evaluate.mjs';
import { contentCommitmentOf } from './s2-008-campaign-model-image.mjs';
import { validateControlImagePinEvidence, validateControlExecution } from './s2-008-campaign-adapter.mjs';
import { openRegistry, readJournal, verifyChain } from '../src/lib/research/registry.mjs';
import { createS2PaidReviewWorkflow as createPaidWorkflow, isTrustedS2PaidReviewWorkflow } from './s2-008-paid-review-workflow.mjs';
import { assertV12PriorExecutionEvidence, assertV12RestartReconciliation, inspectV11PriorExecutionEvidence } from './s2-008-campaign-v12-approval.mjs';
import { V13_MODEL_POLICY, V14_MODEL_POLICY, assertV13ExecutorPolicy, assertV14ExecutorPolicy } from './s2-008-campaign-credential-env.mjs';
import { assertV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';
import { assertV14RestartReconciliation, readV14BaseInputs, readV14RestartInputs } from './s2-008-campaign-v14-approval.mjs';
import { assertV14PresealPin } from './s2-008-campaign-v14-approval.mjs';
import { V15_MODEL_POLICY, assertV15ExecutorPolicy, assertV15PreregistrationPolicy } from './s2-008-campaign-v15-policy.mjs';
import { assertV15PresealPin } from './s2-008-campaign-v15-approval.mjs';
import { checkV15OnDisk } from './s2-008-campaign-seal-v15.mjs';
import { assertV13PresealPin, assertV13RestartReconciliation, readV13BaseInputs, readV13PriorV12AInputs } from './s2-008-campaign-v13-approval.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BOOTSTRAP_SCRIPT = path.join(ROOT, 'scripts/s2-008-campaign-bootstrap.mjs');
const STATE = path.join(os.homedir(), '.local/state/veritas/s2-008-paid-review');
const OWNER = 'prn-s2007r-owner';
const PRODUCER = 'prn-s2-008-evidence-importer';
const TOKEN_RE = /^[A-Za-z0-9_-]{24,256}$/;
const DIGEST_RE = /^[0-9a-f]{64}$/;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const addReason = (list, reason) => { if (!list.includes(reason)) list.push(reason); };
const fail = (code) => { const error = new Error(code); error.code = code; throw error; };
const V11_MODEL_ARM = 'arm-model-zai-glm53flash';
const V11_TRIALS = Object.freeze([
  Object.freeze({ trial_id: 'trl-s2-008c-01', arm_id: 'arm-model-zai-glm53flash' }),
  Object.freeze({ trial_id: 'trl-s2-008c-02', arm_id: 'arm-type-feat-fix' }),
  Object.freeze({ trial_id: 'trl-s2-008c-03', arm_id: 'arm-type-chore' }),
]);
const V11_SEEDS = Object.freeze([20260926, 20260927, 20260928]);
const V11_CAPSULE_SOURCE_PATHS = Object.freeze([
  'corpus/s2-008-campaign/preregistration.v11.in-force.json',
  'corpus/s2-008-campaign/manifest.json',
  'corpus/s2-008-campaign/frozen-table.v3.json',
  'corpus/s2-008-campaign/cases/holdout.blind.json',
  'scripts/s2-008-campaign-evaluate.mjs',
  'scripts/s2-008-campaign-bootstrap.mjs',
]);
const capsuleSourcePaths = (version) => {
  if (version === 14) return [...V14_REVIEW_CAPSULE_SOURCE_PATHS];
  if (version === 15) return [...V15_REVIEW_CAPSULE_SOURCE_PATHS];
  const paths = V11_CAPSULE_SOURCE_PATHS.map((value) =>
    version >= 12 && value === 'corpus/s2-008-campaign/preregistration.v11.in-force.json'
      ? 'corpus/s2-008-campaign/preregistration.v' + version + '.in-force.json' : value);
  if (version === 11) return paths;
  const withAdapter = [...paths, 'scripts/s2-008-campaign-adapter.mjs'];
  return version === 12 ? withAdapter : [...withAdapter,
    'scripts/s2-008-campaign-arm-model.mjs',
    'scripts/s2-008-campaign-credential-env.mjs',
    'scripts/s2-008-campaign-model-image.mjs',
    'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json'];
};
const isCapsuleVersion = (version) => version === 11 || version === 12 || version === 13 || version === 14 || version === 15;
const isControlPinVersion = (version) => version === 12 || version === 13 || version === 14 || version === 15;
const CONTROL_RAW_KEYS = Object.freeze([
  'arm_id', 'seed', 'samples', 'podman', 'container_argv', 'image', 'image_break_requested',
  'axes', 'exit_code', 'signal', 'timed_out', 'stderr_excerpt', 'banner', 'payload_chunks',
  'payload_error', 'output_digest', 'predictions', 'real_start',
]);
const CONTROL_WRAPPER_KEYS = Object.freeze([...CONTROL_RAW_KEYS, 'image_digest', 'arm_report', 'control_execution']);

export function validateS2PaidReviewControlPinEvidence(pin, expectedBase) {
  return validateControlImagePinEvidence(pin, expectedBase);
}


function validV12ControlCell({ report, trial, seed, pin, caseIds, expectedOutcome, samples, timeoutMs, sidecar = null }) {
  try {
    const launch = seed?.launch;
    if (!launch || Object.keys(launch).sort().join(',') !== [...CONTROL_WRAPPER_KEYS].sort().join(',')
        || launch.arm_report === null || !launch.control_execution
        || launch.image !== pin?.first?.imageId || launch.image_digest !== pin?.first?.digest
        || launch.control_execution.kind !== 's2-008-campaign-control-execution/1'
        || launch.control_execution.outcome_class !== expectedOutcome
        || launch.control_execution.pin_digest !== canonicalDigest(pin)
        || launch.control_execution.output_digest !== canonicalDigest(launch.arm_report)
        || launch.output_digest !== canonicalDigest(launch.arm_report)
        || seed.outcome_class !== expectedOutcome
        || seed.predictions?.digest !== launch.predictions?.digest
        || seed.predictions?.rows !== 126 || seed.predictions?.unparsed !== 0) return false;
    const raw = Object.fromEntries(CONTROL_RAW_KEYS.map((key) => [key, launch[key]]));
    if (!validateControlExecution({ ok: true, output: launch.arm_report, record: raw }, {
      armId: trial.arm_id, seed: seed.seed, samples, timeoutMs,
      runLabel: report.label, caseIds,
      imageId: pin.first.imageId, imageDigest: pin.first.digest,
    })) return false;
    if (sidecar !== null) {
      if (sidecar.kind !== 's2-008-campaign-predictions/1' || sidecar.run !== report.label
          || sidecar.arm_id !== trial.arm_id || sidecar.seed !== seed.seed
          || sidecar.unparsed !== 0 || sidecar.model_calls !== null
          || sidecar.spent_tokens !== null || sidecar.usd_spent !== null || sidecar.outcome_class !== null
          || canonicalDigest(sidecar.rows) !== canonicalDigest(launch.arm_report.predictions)
          || canonicalDigest(sidecar) !== seed.predictions.digest) return false;
    }
    return true;
  } catch { return false; }
}


export function validateS2PaidReviewCapsuleSourceInputs(capsuleInputs, sourceInputs, { version = 11 } = {}) {
  try {
    const paths = capsuleSourcePaths(version);
    if (!isCapsuleVersion(version) || !Array.isArray(capsuleInputs) || !Array.isArray(sourceInputs)
        || capsuleInputs.length !== paths.length || sourceInputs.length !== paths.length
        || canonicalDigest(capsuleInputs) !== canonicalDigest(sourceInputs)) return { ok: false };
    for (let index = 0; index < paths.length; index += 1) {
      for (const row of [capsuleInputs[index], sourceInputs[index]]) {
        if (!row || Object.keys(row).sort().join(',') !== 'bytes,path,sha256'
            || row.path !== paths[index]
            || !Number.isSafeInteger(row.bytes) || row.bytes < 1
            || !DIGEST_RE.test(row.sha256 ?? '')) return { ok: false };
      }
    }
    return { ok: true };
  } catch { return { ok: false }; }
}

export function validateS2PaidReviewRunReadiness({ report, accounting, reconciliation, version = 11, controlPin = null, caseIds = [], samples, timeoutMs } = {}) {
  try {
    if (!report || report.status !== 'MEASURED' || report.unreconciled_spend !== false
        || report.spent_units_is_lower_bound !== false || report.model_calls_is_lower_bound !== false
        || report.unknown_model_attempts !== 0 || !Array.isArray(report.trials)
        || report.trials.length !== V11_TRIALS.length) return { ok: false };
    if (isControlPinVersion(version) && (!validateS2PaidReviewControlPinEvidence(controlPin, basePair(report))
        || canonicalDigest(report.control_image_pin) !== canonicalDigest(controlPin))) return { ok: false };
    for (let index = 0; index < V11_TRIALS.length; index += 1) {
      const expected = V11_TRIALS[index];
      const trial = report.trials[index];
      if (trial?.trial_id !== expected.trial_id || trial?.arm_id !== expected.arm_id
          || !Array.isArray(trial.seeds) || trial.seeds.length !== V11_SEEDS.length) return { ok: false };
      for (let seedIndex = 0; seedIndex < V11_SEEDS.length; seedIndex += 1) {
        const row = trial.seeds[seedIndex];
        const expectedOutcome = isControlPinVersion(version) && expected.arm_id !== V11_MODEL_ARM ? 'MEASURED_CONTROL' : 'MEASURED';
        if (row?.seed !== V11_SEEDS[seedIndex] || row.outcome_class !== expectedOutcome
            || row.launch?.exit_code !== 0 || row.launch?.signal !== null
            || row.launch?.timed_out !== false) return { ok: false };
        if (isControlPinVersion(version) && expected.arm_id !== V11_MODEL_ARM
            && !validV12ControlCell({ report, trial, seed: row, pin: controlPin, caseIds, samples, timeoutMs,
              expectedOutcome: 'MEASURED_CONTROL' })) return { ok: false };
      }
    }
    if (accounting?.modelRows !== 378 || accounting?.controlRows !== 756 || accounting?.rows !== 1134
        || reconciliation?.valid !== true || reconciliation.unreconciledAttempts !== 0
        || (isControlPinVersion(version) && accounting?.controlExecutions !== 6)) return { ok: false };
    if (version === 14) {
      const modelContainers = report.trials.filter((row) => row.arm_id === V11_MODEL_ARM)
        .reduce((sum, row) => sum + row.seeds.length, 0);
      const pacing = report.model_call_pacing;
      if (!pacing || pacing.min_start_interval_ms !== 60000 || pacing.container_starts !== modelContainers
          || pacing.wait_count !== Math.max(0, modelContainers - 1)
          || pacing.waited_ms < Math.max(0, modelContainers - 1) * 60000) return { ok: false };
      for (const trial of report.trials.filter((row) => row.arm_id === V11_MODEL_ARM)) for (const seed of trial.seeds) {
        const modelPacing = seed.launch?.arm_report?.executor?.model_call_pacing;
        if (!modelPacing || modelPacing.min_start_interval_ms !== 60000
            || modelPacing.call_starts !== seed.launch.arm_report.executor.model_calls
            || modelPacing.wait_count !== Math.max(0, modelPacing.call_starts - 1)
            || !Number.isSafeInteger(modelPacing.waited_ms) || modelPacing.waited_ms < 0) return { ok: false };
      }
    }
    return { ok: true };
  } catch { return { ok: false }; }
}
const PAID_CHECK_COMMANDS = Object.freeze({
  'npm-test': 'npm test',
  'test-research': 'npm run test:research',
  'test-s2-008': 'npm run test:s2-008',
  'test-s2-002-isolation': 'npm run test:s2-002-isolation',
  lint: 'npm run lint',
  typecheck: 'npm run typecheck',
  'verify-s2-008': 'npm run verify:s2-008',
});

export function verifyS2PaidReviewCheckLog(name, text) {
  const command = PAID_CHECK_COMMANDS[name];
  if (typeof command !== 'string' || typeof text !== 'string' || text.length > 16 * 1024 * 1024) fail('PAID_CHECK_LOG_INVALID');
  const lines = text.split(/\r?\n/);
  const nonempty = lines.filter((line) => line.length > 0);
  const exits = lines.filter((line) => /^EXIT_STATUS=/.test(line));
  if (nonempty[0] !== 'COMMAND: ' + command || exits.length !== 1 || nonempty.at(-1) !== 'EXIT_STATUS=0') {
    fail('PAID_CHECK_LOG_INVALID');
  }
  const result = { command, exitStatus: 0, summary: null };
  if (['npm-test', 'test-research', 'test-s2-008', 'test-s2-002-isolation'].includes(name)) {
    const summary = {};
    for (const field of ['pass', 'fail', 'cancelled', 'skipped']) {
      const matches = [...text.matchAll(new RegExp('^# ' + field + ' ([0-9]+)$', 'gm'))];
      if (matches.length !== 1) fail('PAID_CHECK_LOG_INVALID');
      summary[field] = Number(matches[0][1]);
    }
    if (!Number.isSafeInteger(summary.pass) || summary.pass < 1 || summary.fail !== 0
        || summary.cancelled !== 0 || !Number.isSafeInteger(summary.skipped)
        || /\bnot ok \d+\b/.test(text)) fail('PAID_CHECK_LOG_INVALID');
    result.summary = summary;
  } else if (name === 'verify-s2-008') {
    const start = text.indexOf('\n{');
    const end = text.lastIndexOf('\nEXIT_STATUS=0');
    if (start < 0 || end <= start) fail('PAID_CHECK_LOG_INVALID');
    let report;
    try { report = JSON.parse(text.slice(start + 1, end).trim()); }
    catch { fail('PAID_CHECK_LOG_INVALID'); }
    const gates = report?.gates;
    if (report?.ok !== true || report?.status !== 'PASS'
        || !gates || ['dependency', 'corpus', 'probes', 'replay', 'harness']
          .some((gate) => typeof gates[gate] !== 'string' || !/^PASS\(exit=0\)$/.test(gates[gate]))) {
      fail('PAID_CHECK_LOG_INVALID');
    }
    result.summary = { verifierStatus: report.status, gates: Object.keys(gates).length };
  }
  return result;
}

export function verifyS2PaidReviewCoverage({ trialList, seeds, holdoutCaseIds, observed } = {}) {
  if (!Array.isArray(trialList) || !Array.isArray(seeds) || !Array.isArray(holdoutCaseIds)
      || !Array.isArray(observed) || trialList.length !== V11_TRIALS.length
      || seeds.length !== V11_SEEDS.length || holdoutCaseIds.length !== 126
      || new Set(holdoutCaseIds).size !== 126
      || holdoutCaseIds.some((id) => typeof id !== 'string' || id.length < 1 || id.length > 200)
      || canonicalDigest(trialList.map(({ trial_id, arm_id }) => ({ trial_id, arm_id }))) !== canonicalDigest(V11_TRIALS)
      || canonicalDigest(seeds) !== canonicalDigest(V11_SEEDS)) fail('PAID_REVIEW_COVERAGE_INVALID');
  const expectedCases = new Set(holdoutCaseIds);
  const byCell = new Map();
  for (const cell of observed) {
    const key = [cell?.trial_id, cell?.arm_id, cell?.seed].join(':');
    if (byCell.has(key) || !Array.isArray(cell?.caseIds) || cell.caseIds.length !== 126
        || new Set(cell.caseIds).size !== 126 || cell.caseIds.some((id) => !expectedCases.has(id))
        || [...expectedCases].some((id) => !cell.caseIds.includes(id))
        || !Number.isSafeInteger(cell.unparsed) || cell.unparsed < 0
        || !V11_TRIALS.some((row) => row.trial_id === cell.trial_id && row.arm_id === cell.arm_id)
        || !V11_SEEDS.includes(cell.seed)) fail('PAID_REVIEW_COVERAGE_INVALID');
    byCell.set(key, cell);
  }
  if (byCell.size !== V11_TRIALS.length * V11_SEEDS.length) fail('PAID_REVIEW_COVERAGE_INVALID');
  for (const trial of V11_TRIALS) for (const seed of V11_SEEDS) {
    if (!byCell.has([trial.trial_id, trial.arm_id, seed].join(':'))) fail('PAID_REVIEW_COVERAGE_INVALID');
  }
  const model = V11_TRIALS.find((trial) => trial.arm_id === V11_MODEL_ARM);
  const modelUnparsed = V11_SEEDS.reduce((sum, seed) =>
    sum + byCell.get([model.trial_id, model.arm_id, seed].join(':')).unparsed, 0);
  const controlUnparsed = V11_TRIALS.filter((trial) => trial.arm_id !== V11_MODEL_ARM)
    .reduce((sum, trial) => sum + V11_SEEDS.reduce((inner, seed) =>
      inner + byCell.get([trial.trial_id, trial.arm_id, seed].join(':')).unparsed, 0), 0);
  return { totalPredictions: 1134, modelPredictions: 378, controlPredictions: 756,
    modelUnparsed, controlUnparsed, cells: byCell.size };
}

export function deriveS2PaidReviewComparison({
  preregistrationDigest, holdoutCaseIds, aPredictions, bPredictions, version = 11,
} = {}) {
  if (!isCapsuleVersion(version) || typeof preregistrationDigest !== 'string' || !DIGEST_RE.test(preregistrationDigest)
      || !Array.isArray(holdoutCaseIds) || holdoutCaseIds.length !== 126
      || new Set(holdoutCaseIds).size !== 126
      || holdoutCaseIds.some((id) => typeof id !== 'string' || id.length < 1 || id.length > 200)
      || !Array.isArray(aPredictions) || !Array.isArray(bPredictions)) {
    fail('PAID_REVIEW_COMPARISON_INVALID');
  }
  const expectedCount = V11_TRIALS.length * V11_SEEDS.length * holdoutCaseIds.length;
  function normalize(rows) {
    if (rows.length !== expectedCount) fail('PAID_REVIEW_COMPARISON_INVALID');
    const byKey = new Map();
    for (const row of rows) {
      if (!row || typeof row !== 'object'
          || Object.keys(row).sort().join(',') !== 'arm_id,case_id,predicted,seed,trial_id'
          || typeof row.trial_id !== 'string' || typeof row.arm_id !== 'string'
          || !V11_SEEDS.includes(row.seed) || typeof row.case_id !== 'string'
          || !['MAJOR', 'MINOR', 'UNPARSED'].includes(row.predicted)) {
        fail('PAID_REVIEW_COMPARISON_INVALID');
      }
      const key = JSON.stringify([row.trial_id, row.arm_id, row.seed, row.case_id]);
      if (byKey.has(key)) fail('PAID_REVIEW_COMPARISON_INVALID');
      byKey.set(key, row.predicted);
    }
    const ordered = [];
    for (const trial of V11_TRIALS) {
      for (const seed of V11_SEEDS) {
        for (const caseId of holdoutCaseIds) {
          const key = JSON.stringify([trial.trial_id, trial.arm_id, seed, caseId]);
          const predicted = byKey.get(key);
          if (predicted === undefined) fail('PAID_REVIEW_COMPARISON_INVALID');
          ordered.push({ trial_id: trial.trial_id, arm_id: trial.arm_id, seed, case_id: caseId, predicted });
        }
      }
    }
    if (byKey.size !== expectedCount) fail('PAID_REVIEW_COMPARISON_INVALID');
    return ordered;
  }
  const a = normalize(aPredictions);
  const b = normalize(bPredictions);
  const aMap = new Map(a.map((row) => [JSON.stringify([row.trial_id, row.arm_id, row.seed, row.case_id]), row.predicted]));
  const bMap = new Map(b.map((row) => [JSON.stringify([row.trial_id, row.arm_id, row.seed, row.case_id]), row.predicted]));
  const trialStats = V11_TRIALS.map((trial) => ({
    trial_id: trial.trial_id,
    arm_id: trial.arm_id,
    arm_kind: trial.arm_id === V11_MODEL_ARM ? 'MODEL' : 'CONTROL',
    compared_predictions: 0,
    equal_predictions: 0,
    differing_predictions: 0,
    a_unparsed: 0,
    b_unparsed: 0,
  }));
  const seedStats = V11_SEEDS.map((seed) => ({
    seed,
    compared_predictions: 0,
    equal_predictions: 0,
    differing_predictions: 0,
    a_unparsed: 0,
    b_unparsed: 0,
  }));
  let equal = 0;
  let differing = 0;
  let aUnparsed = 0;
  let bUnparsed = 0;
  for (const trial of V11_TRIALS) {
    const trialRow = trialStats.find((row) => row.trial_id === trial.trial_id);
    for (const seed of V11_SEEDS) {
      const seedRow = seedStats.find((row) => row.seed === seed);
      for (const caseId of holdoutCaseIds) {
        const key = JSON.stringify([trial.trial_id, trial.arm_id, seed, caseId]);
        const left = aMap.get(key);
        const right = bMap.get(key);
        trialRow.compared_predictions += 1;
        seedRow.compared_predictions += 1;
        if (left === right) { equal += 1; trialRow.equal_predictions += 1; seedRow.equal_predictions += 1; }
        else { differing += 1; trialRow.differing_predictions += 1; seedRow.differing_predictions += 1; }
        if (left === 'UNPARSED') { aUnparsed += 1; trialRow.a_unparsed += 1; seedRow.a_unparsed += 1; }
        if (right === 'UNPARSED') { bUnparsed += 1; trialRow.b_unparsed += 1; seedRow.b_unparsed += 1; }
      }
    }
  }
  return {
    kind: 's2-008-campaign-comparison/1',
    version,
    preregistration_digest: preregistrationDigest,
    prediction_source: 'IMMUTABLE_RUN_SIDECARS',
    scope: {
      trials: V11_TRIALS,
      seeds: V11_SEEDS,
      holdout_case_count: holdoutCaseIds.length,
      predictions_per_run: { total: 1134, model: 378, controls: 756 },
    },
    runs: {
      a: { predictions: a.length, model_predictions: 378, control_predictions: 756,
        unparsed: aUnparsed, prediction_map_digest: canonicalDigest(a) },
      b: { predictions: b.length, model_predictions: 378, control_predictions: 756,
        unparsed: bUnparsed, prediction_map_digest: canonicalDigest(b) },
    },
    agreement: {
      compared_predictions: expectedCount,
      equal_predictions: equal,
      differing_predictions: differing,
      a_unparsed: aUnparsed,
      b_unparsed: bUnparsed,
      a_equals_b: differing === 0,
      criterion: 'DISCLOSURE_ONLY',
      by_trial: trialStats.map((row) => ({ ...row, a_equals_b: row.differing_predictions === 0 })),
      by_seed: seedStats.map((row) => ({ ...row, a_equals_b: row.differing_predictions === 0 })),
    },
  };
}

export function validateS2PaidReviewComparison({
  comparison, preregistrationDigest, holdoutCaseIds, aPredictions, bPredictions, version = 11,
} = {}) {
  const expected = deriveS2PaidReviewComparison({ preregistrationDigest, holdoutCaseIds, aPredictions, bPredictions, version });
  if (!comparison || canonicalDigest(comparison) !== canonicalDigest(expected)) fail('PAID_REVIEW_COMPARISON_INVALID');
  return true;
}

function sameUsd(left, right) {
  return Number.isFinite(left) && Number.isFinite(right)
    && Math.abs(left - right) <= Math.max(1, Math.abs(left), Math.abs(right)) * 1e-12;
}
function canonicalInstant(value) {
  if (typeof value !== 'string') return false;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.toISOString() === value;
}

export function replayS2PaidReviewAccessFiles({ files, journalSha256, version = 11 } = {}) {
  if (!isCapsuleVersion(version)) return { ok: false };
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-review-access-replay-'));
  const registryRoot = path.join(rootDir, 'v' + version + '-evaluation-access');
  const names = ['registry.json', 'journal.ndjson', 'head.json', 'operations.ndjson'];
  const expectedPaths = names.map((name) => 'evidence/s2-008-campaign/v' + version + '-evaluation-access/' + name);
  try {
    if (!Array.isArray(files) || files.length !== names.length
        || files.some((file, index) => file?.path !== expectedPaths[index]
          || !Buffer.isBuffer(file.contents) || file.contents.length !== file.bytes
          || hash(file.contents) !== file.sha256)) return { ok: false };
    fs.mkdirSync(registryRoot, { mode: 0o700 });
    for (let index = 0; index < names.length; index += 1) {
      fs.writeFileSync(path.join(registryRoot, names[index]), files[index].contents, { flag: 'wx', mode: 0o600 });
    }
    const milliseconds = Date.parse('2026-10-05T00:00:00.000Z');
    let nextId = 0;
    const clock = { nowNs: () => milliseconds * 1e6, nowMs: () => milliseconds,
      iso: () => new Date(milliseconds).toISOString(), now: () => new Date(milliseconds),
      nowIso: () => new Date(milliseconds).toISOString() };
    const registry = openRegistry({ root: registryRoot, clock, ids: { next: () => 'review-' + (++nextId) } });
    const verification = verifyChain(registry);
    const rows = readJournal(registry);
    const journal = files.find((file) => file.path.endsWith('/journal.ndjson'));
    if (!verification.ok || verification.headBound !== true || verification.recordCount !== 1
        || verification.length !== 1 || verification.markers?.ok !== true || rows.length !== 1
        || journal?.sha256 !== journalSha256) return { ok: false };
    return { ok: true, rows, journalSha256, chain: verification };
  } catch {
    return { ok: false };
  } finally {
    fs.rmSync(rootDir, { recursive: true, force: true });
  }
}

export function validateS2PaidReviewBlindIndex(rows, declaredIds) {
  if (!Array.isArray(rows) || rows.length !== 126 || !Array.isArray(declaredIds) || declaredIds.length !== 126) {
    return { ok: false, caseIds: [] };
  }
  const caseIds = [];
  for (const row of rows) {
    if (!row || Object.keys(row).sort().join(',') !== 'case_id,committed_at,subject'
        || typeof row.case_id !== 'string' || row.case_id.length < 1 || row.case_id.length > 200
        || !Number.isSafeInteger(row.committed_at) || row.committed_at < 0
        || typeof row.subject !== 'string' || row.subject.length > 2000) return { ok: false, caseIds: [] };
    caseIds.push(row.case_id);
  }
  if (new Set(caseIds).size !== 126 || new Set(declaredIds).size !== 126
      || declaredIds.some((id) => typeof id !== 'string')
      || canonicalDigest([...caseIds].sort()) !== canonicalDigest([...declaredIds].sort())) {
    return { ok: false, caseIds: [] };
  }
  return { ok: true, caseIds };
}

export function validateS2PaidReviewPin({ pin, preregistrationSha256, blindSha256, version = 11 } = {}) {
  try {
    const first = pin?.first;
    const second = pin?.second;
    const hash = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
    const prefixed = (value) => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
    if (!isCapsuleVersion(version) || pin?.schema !== 's2-008-model-image-pin/' + version || pin.identical !== true
        || pin.context_digest_stable !== true || pin.content_commitment_stable !== true
        || pin.commitment_excludes_preregistration !== true
        || pin.commitment?.field !== 'executor.model_image.content_commitment'
        || canonicalDigest(pin.commitment?.excludes) !== canonicalDigest(['prereg'])
        || !first || !second || !prefixed(first.imageId) || !prefixed(first.digest)
        || first.imageId !== second.imageId || first.digest !== second.digest
        || !first.sources || typeof first.sources !== 'object' || Array.isArray(first.sources)
        || !second.sources || typeof second.sources !== 'object' || Array.isArray(second.sources)
        || canonicalDigest(first.sources) !== canonicalDigest(second.sources)
        || !hash(first.source_digest) || first.source_digest !== canonicalDigest(first.sources)
        || second.source_digest !== first.source_digest
        || !hash(first.content_commitment) || first.content_commitment !== second.content_commitment
        || first.content_commitment !== contentCommitmentOf(first.sources).digest
        || !hash(second.content_commitment) || second.content_commitment !== contentCommitmentOf(second.sources).digest
        || !Array.isArray(first.content_commitment_covers)
        || !Array.isArray(second.content_commitment_covers)
        || canonicalDigest(first.content_commitment_covers) !== canonicalDigest(contentCommitmentOf(first.sources).covers)
        || canonicalDigest(second.content_commitment_covers) !== canonicalDigest(contentCommitmentOf(second.sources).covers)
        || canonicalDigest(pin.commitment?.covers) !== canonicalDigest(contentCommitmentOf(first.sources).covers)
        || !Object.values(first.sources).every(hash)
        || first.sources.prereg !== preregistrationSha256
        || first.sources.blind !== blindSha256
        || ([14, 15].includes(version) && !hash(first.sources.model_call_pacing_policy))) return { ok: false };
    return { ok: true, contentCommitment: first.content_commitment, sourceDigest: first.source_digest };
  } catch {
    return { ok: false };
  }
}

export function validateS2PaidReviewDryRun({ dry, preregistrationDigest, pin, expectedBase, version = 11, controlPin = null, expectedCaseIds = [], samples, timeoutMs } = {}) {
  try {
    const first = pin?.first ?? pin;
    if (!dry || dry.status !== 'DRY_RUN' || dry.dry_run !== true
        || dry.preregistration_digest !== preregistrationDigest
        || !dry.model_image_pin || dry.model_image_pin.imageId !== first?.imageId
        || dry.model_image_pin.digest !== first?.digest
        || dry.model_image_pin.content_commitment !== first?.content_commitment
        || !Number.isSafeInteger(dry.spent_units) || dry.spent_units !== 0
        || dry.spent_units_is_lower_bound !== false || dry.unreconciled_spend !== false
        || !Number.isSafeInteger(dry.model_calls) || dry.model_calls !== 0
        || dry.model_calls_is_lower_bound !== false
        || !Number.isSafeInteger(dry.unknown_model_attempts) || dry.unknown_model_attempts !== 0
        || !Number.isSafeInteger(dry.unknown_launch_attempts) || dry.unknown_launch_attempts !== 0
        || dry.launches !== 9 || dry.reservation?.currency !== 'tokens'
        || dry.reservation?.granted_units !== 5000000 || !Array.isArray(dry.charges)
        || dry.charges.length !== 9 || dry.charges.some((row) => row?.units !== 0)
        || typeof dry.raw_run_id !== 'string' || !dry.raw_run_id
        || typeof dry.nonce !== 'string' || !dry.nonce
        || !expectedBase?.commit || !expectedBase?.tree
        || dry.base?.commit_sha !== expectedBase.commit || dry.base?.tree_sha !== expectedBase.tree
        || !Array.isArray(dry.trials) || dry.trials.length !== V11_TRIALS.length) return { ok: false };
    if (isControlPinVersion(version) && (!validateS2PaidReviewControlPinEvidence(controlPin, expectedBase)
        || canonicalDigest(dry.control_image_pin) !== canonicalDigest(controlPin))) return { ok: false };
    for (let index = 0; index < V11_TRIALS.length; index += 1) {
      const expected = V11_TRIALS[index];
      const trial = dry.trials[index];
      if (trial?.trial_id !== expected.trial_id || trial?.arm_id !== expected.arm_id
          || !Array.isArray(trial.seeds) || trial.seeds.length !== V11_SEEDS.length) return { ok: false };
      for (let seedIndex = 0; seedIndex < V11_SEEDS.length; seedIndex += 1) {
        const seed = trial.seeds[seedIndex];
        if (seed?.seed !== V11_SEEDS[seedIndex]) return { ok: false };
        if (isControlPinVersion(version) && expected.arm_id !== V11_MODEL_ARM) {
          if (!validV12ControlCell({ report: dry, trial: expected, seed, pin: controlPin,
            caseIds: expectedCaseIds, samples, timeoutMs, expectedOutcome: 'EXECUTED_CONTROL_DRY_RUN' })) return { ok: false };
          continue;
        }
        const launch = seed?.launch;
        const arm = launch?.arm_report;
        const executor = arm?.executor;
        if (seed?.seed !== V11_SEEDS[seedIndex] || seed.outcome_class !== 'DRY_RUN'
            || !launch || launch.exit_code !== 0 || launch.signal !== null || launch.timed_out !== false
            || !Array.isArray(launch.container_argv) || !launch.container_argv.includes('--network=none')
            || launch.image !== first.imageId || launch.image_digest !== first.digest
            || !arm || arm.dry_run !== true || arm.outcome_class !== 'DRY_RUN'
            || arm.n_cases !== 126 || !Array.isArray(arm.predictions) || arm.predictions.length !== 126
            || !Array.isArray(arm.accounting) || arm.accounting.length !== 0
            || arm.stop !== null
            || ([14, 15].includes(version) && (executor?.model_call_pacing?.min_start_interval_ms !== 60000
              || executor.model_call_pacing.call_starts !== 0 || executor.model_call_pacing.wait_count !== 0
              || executor.model_call_pacing.waited_ms !== 0))) return { ok: false };
        if (expected.arm_id === V11_MODEL_ARM) {
          if (!executor || executor.provider !== 'openrouter' || executor.model !== (version === 15 ? V15_MODEL_POLICY.model : version === 14 ? V14_MODEL_POLICY.model : version === 13 ? V13_MODEL_POLICY.model : 'stealth/space-bunny-alpha')
              || executor.model_calls !== 0 || executor.model_attempts !== 0
              || executor.unknown_model_attempts !== 0 || executor.credential_present !== false
              || executor.credential_in_argv !== false || executor.egress_route !== null) return { ok: false };
        } else if (executor && (executor.model_calls !== 0 || executor.model_attempts !== 0
            || executor.unknown_model_attempts !== 0)) return { ok: false };
      }
    }
    return { ok: true, launches: dry.launches, modelCalls: dry.model_calls, spentTokens: dry.spent_units };
  } catch {
    return { ok: false };
  }
}

export function validateS2PaidReviewReviewCapsule({
  capsule, evaluation, prereg, declaredCaseIds, runReports, runReportSha256,
  sidecarRefs, sourceInputs, accessJournal, accessJournalSha256, registryFiles, registryReplay, version = 11,
} = {}) {
  try {
    if (!isCapsuleVersion(version) || !capsule || Object.keys(capsule).sort().join(',') !== 'access,case_ids,digest,kind,labels,labels_digest,preregistration_digest,runs,source_inputs'
        || capsule.kind !== 's2-008-campaign-review-capsule/1'
        || typeof capsule.digest !== 'string' || !DIGEST_RE.test(capsule.digest)) return { ok: false };
    const { digest, ...body } = capsule;
    if (canonicalDigest(body) !== digest || !prereg || capsule.preregistration_digest !== prereg.preregistration_digest
        || canonicalDigest(capsule.case_ids) !== canonicalDigest(declaredCaseIds)
        || !Array.isArray(capsule.labels) || capsule.labels.length !== 126
        || new Set(capsule.labels.map((row) => row?.case_id)).size !== 126
        || capsule.labels.some((row, index) => !row || Object.keys(row).sort().join(',') !== 'case_id,label'
          || row.case_id !== declaredCaseIds[index] || !['MAJOR', 'MINOR'].includes(row.label))) return { ok: false };
    const labels = Object.fromEntries(capsule.labels.map((row) => [row.case_id, row.label]));
    const sealedLabelsDigest = String(prereg.holdout_access?.labels_digest ?? '').replace(/^sha256:/, '');
    if (!DIGEST_RE.test(sealedLabelsDigest) || capsule.labels_digest !== canonicalDigest(labels)
        || capsule.labels_digest !== sealedLabelsDigest || prereg.holdout_access?.partition !== 'HOLDOUT'
        || prereg.holdout_access?.case_count !== 126 || prereg.holdout_access?.max_opens !== 1
        || prereg.holdout_access?.one_shot !== true) return { ok: false };
    if (!validateS2PaidReviewCapsuleSourceInputs(capsule.source_inputs, sourceInputs, { version }).ok) return { ok: false };
    if (!Array.isArray(capsule.runs) || capsule.runs.length !== 2
        || canonicalDigest(capsule.runs.map((row) => row?.label)) !== canonicalDigest(['a', 'b'])) return { ok: false };
    for (const arm of ['a', 'b']) {
      const run = runReports?.[arm];
      const capsuleRun = capsule.runs.find((row) => row.label === arm);
      if (!run || !capsuleRun || capsuleRun.raw_run_id !== run.raw_run_id
          || capsuleRun.report_sha256 !== runReportSha256?.[arm]
          || !DIGEST_RE.test(capsuleRun.report_sha256 ?? '')
          || !Array.isArray(capsuleRun.sidecars) || capsuleRun.sidecars.length !== 9
          || canonicalDigest(capsuleRun.sidecars) !== canonicalDigest(sidecarRefs?.[arm])) return { ok: false };
    }
    const access = capsule.access;
    const journalPath = 'evidence/s2-008-campaign/v' + version + '-evaluation-access/journal.ndjson';
    const expectedRegistryPaths = [
      'evidence/s2-008-campaign/v' + version + '-evaluation-access/registry.json',
      journalPath,
      'evidence/s2-008-campaign/v' + version + '-evaluation-access/head.json',
      'evidence/s2-008-campaign/v' + version + '-evaluation-access/operations.ndjson',
    ];
    if (!access || Object.keys(access).sort().join(',') !== 'actor_kind,journal_digest,journal_sha256,one_shot,partition,path,registry_files,rows'
        || access.path !== journalPath || access.rows !== 1 || access.actor_kind !== 'EVALUATOR'
        || access.partition !== 'HOLDOUT' || access.one_shot !== true
        || !Array.isArray(access.registry_files) || access.registry_files.length !== expectedRegistryPaths.length
        || access.registry_files.some((row, index) => row?.path !== expectedRegistryPaths[index]
          || !Number.isSafeInteger(row?.bytes) || row.bytes < 0 || !DIGEST_RE.test(row?.sha256 ?? ''))
        || canonicalDigest(access.registry_files) !== canonicalDigest(registryFiles)
        || canonicalDigest(access.registry_files) !== canonicalDigest(evaluation?.holdout_one_shot?.registry_files)
        || registryReplay?.ok !== true || registryReplay.journalSha256 !== access.journal_sha256
        || !Array.isArray(registryReplay.rows) || canonicalDigest(registryReplay.rows) !== canonicalDigest(accessJournal)
        || evaluation?.holdout_one_shot?.access_rows !== 1
        || evaluation.holdout_one_shot.registry !== 'evidence/s2-008-campaign/v' + version + '-evaluation-access'
        || evaluation.holdout_one_shot.decision_point !== accessJournal?.[0]?.payload?.decision_point
        || evaluation.holdout_one_shot.journal_digest !== access.journal_digest
        || evaluation.holdout_one_shot.journal_sha256 !== access.journal_sha256
        || !DIGEST_RE.test(access.journal_digest ?? '')
        || access.journal_sha256 !== accessJournalSha256 || !DIGEST_RE.test(accessJournalSha256 ?? '')
        || access.registry_files[1]?.sha256 !== access.journal_sha256
        || !Array.isArray(accessJournal) || accessJournal.length !== 1
        || canonicalDigest(accessJournal) !== access.journal_digest) return { ok: false };
    const row = accessJournal[0];
    const payload = row?.payload;
    if (row?.kind !== 'ACCESS' || !payload || payload.partition !== 'HOLDOUT'
        || payload.actor_kind !== 'EVALUATOR' || payload.trial !== declaredCaseIds[0]
        || payload.case_id !== declaredCaseIds[0] || payload.max_opens !== 1
        || payload.unseal_digest !== String(prereg.holdout_access?.unseal_digest ?? '').replace(/^sha256:/, '')
        || canonicalDigest(payload.released_actor_kinds) !== canonicalDigest(prereg.holdout_access?.released_actor_kinds)
        || !canonicalInstant(payload.decision_point) || !canonicalInstant(payload.read_at)
        || payload.read_at !== payload.decision_point || row.created_at !== payload.read_at) return { ok: false };
    return { ok: true, holdoutCases: capsule.labels.map((row) => ({ ...row })), capsuleDigest: digest };
  } catch {
    return { ok: false };
  }
}

export function runS2PaidReviewBootstrap({ vectors, seeds, samples, confidence } = {}) {
  if (!Array.isArray(vectors) || vectors.length !== 9 || !Array.isArray(seeds) || seeds.length !== 3
      || !Number.isSafeInteger(samples) || samples < 1 || !(typeof confidence === 'number' && confidence > 0 && confidence < 1)) {
    fail('PAID_REVIEW_BOOTSTRAP_INPUT_INVALID');
  }
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-paid-review-bootstrap-'));
  try {
    const inputPath = path.join(workspace, 'input.json');
    const outputPath = path.join(workspace, 'output.json');
    fs.writeFileSync(inputPath, JSON.stringify({ vectors, seeds, samples, confidence }), { flag: 'wx', mode: 0o600 });
    const result = spawnSync(process.execPath, [BOOTSTRAP_SCRIPT, inputPath, outputPath], {
      cwd: ROOT, encoding: 'utf8', timeout: 120000, maxBuffer: 2 * 1024 * 1024,
      env: { PATH: '/usr/bin:/bin' },
    });
    if (result.error || result.status !== 0 || result.signal !== null) fail('PAID_REVIEW_BOOTSTRAP_REPLAY_FAILED');
    const stat = fs.lstatSync(outputPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 8 * 1024 * 1024) fail('PAID_REVIEW_BOOTSTRAP_REPLAY_FAILED');
    const output = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
    if (output?.kind !== 's2-008-campaign-bootstrap-output/1' || output.samples !== samples
        || output.confidence !== confidence || !Array.isArray(output.results)
        || output.results.length !== vectors.length * seeds.length) fail('PAID_REVIEW_BOOTSTRAP_REPLAY_FAILED');
    return output;
  } catch (error) {
    if (error?.code?.startsWith('PAID_REVIEW_')) throw error;
    fail('PAID_REVIEW_BOOTSTRAP_REPLAY_FAILED');
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
}

export function validateS2PaidReviewEvaluation({
  evaluation, runReports, predictionRowsByArm, holdoutCases, prereg, manifest, frozenTable, capsuleVerified = false,
} = {}) {
  try {
    if (!capsuleVerified || !evaluation || evaluation.verdict !== 'PENDING_HUMAN_REVIEW'
        || evaluation.prediction_source !== 'IMMUTABLE_RUN_SIDECARS'
        || evaluation.deterministic_evaluation?.verdict !== 'AGREES'
        || !Array.isArray(evaluation.deterministic_evaluation?.remarks)
        || evaluation.deterministic_evaluation.remarks.length !== 0
        || evaluation.table?.verdict !== 'AGREES'
        || !Array.isArray(holdoutCases) || holdoutCases.length !== 126
        || new Set(holdoutCases.map((row) => row?.case_id)).size !== 126
        || holdoutCases.some((row) => !row || !['MAJOR','MINOR'].includes(row.label))
        || !prereg || canonicalDigest(prereg.seed_rule?.seeds) !== canonicalDigest(V11_SEEDS)
        || prereg.seed_rule?.point_estimate !== 'OBSERVED_RATE_SEED_INVARIANT'
        || !Array.isArray(evaluation.runs) || evaluation.runs.length !== 2
        || !runReports || !predictionRowsByArm) return { ok: false };
    if ((manifest === undefined) !== (frozenTable === undefined)) return { ok: false };
    if (manifest && frozenTable) {
      const table = verifyV4FrozenTable({ prereg, manifest, frozenTable });
      if (!table.ok || canonicalDigest(table) !== canonicalDigest(evaluation.table)) return { ok: false };
    }
    const labels = new Map(holdoutCases.map((row) => [row.case_id, row.label]));
    const scoredRuns = [];
    for (const arm of ['a', 'b']) {
      const sourceRun = runReports[arm];
      const recordedRun = evaluation.runs.find((row) => row?.label === arm);
      const predictions = predictionRowsByArm[arm];
      if (!sourceRun || !recordedRun || !Array.isArray(predictions)
          || recordedRun.raw_run_id !== sourceRun.raw_run_id
          || recordedRun.spent_units !== sourceRun.spent_units
          || recordedRun.model_calls !== sourceRun.model_calls
          || canonicalDigest(basePair(recordedRun)) !== canonicalDigest(basePair(sourceRun))
          || !Array.isArray(recordedRun.trials) || recordedRun.trials.length !== V11_TRIALS.length
          || !DIGEST_RE.test(recordedRun.bootstrap?.output_digest ?? '')
          || recordedRun.bootstrap?.record?.real_start?.proven !== true) return { ok: false };
      const vectors = [];
      const perSeedByTrial = new Map();
      for (const entry of V11_TRIALS) {
        const perSeed = [];
        for (const seed of V11_SEEDS) {
          const cell = predictions.filter((row) => row?.trial_id === entry.trial_id
            && row?.arm_id === entry.arm_id && row?.seed === seed);
          const ids = cell.map((row) => row?.case_id);
          const digest = cell[0]?.prediction_digest;
          if (cell.length !== holdoutCases.length || new Set(ids).size !== holdoutCases.length
              || holdoutCases.some((row) => !ids.includes(row.case_id))
              || typeof digest !== 'string' || !DIGEST_RE.test(digest)
              || cell.some((row) => row.prediction_digest !== digest)) return { ok: false };
          const score = scoreRecordedPredictions({ rows: cell, labels, expectedIds: holdoutCases.map((row) => row.case_id) });
          if (!score.ok) return { ok: false };
          const agreement = holdoutCases.map((row) => cell.find((prediction) => prediction.case_id === row.case_id)?.predicted === row.label ? 1 : 0);
          perSeed.push({ seed, agreeing: score.agreeing, denominator: score.rows,
            observed: score.agreeing / score.rows, unparsed: score.unparsed, prediction_digest: digest });
          vectors.push({ trial_id: entry.trial_id + '@' + seed, arm_id: entry.arm_id, agreement });
        }
        perSeedByTrial.set(entry.trial_id, perSeed);
      }
      const bootstrap = runS2PaidReviewBootstrap({ vectors, seeds: V11_SEEDS,
        samples: prereg.multiplicity_rule?.bootstrap_samples, confidence: prereg.multiplicity_rule?.confidence });
      const scoredTrials = [];
      for (const entry of V11_TRIALS) {
        const perSeed = perSeedByTrial.get(entry.trial_id);
        const bootstrapRows = perSeed.map((row) => {
          const output = bootstrap.results.filter((item) => item.trial_id === entry.trial_id + '@' + row.seed
            && item.arm_id === entry.arm_id && item.seed === row.seed);
          if (output.length !== 1) return null;
          return { ...output[0], trial_id: entry.trial_id };
        });
        if (bootstrapRows.some((row) => !row)) return { ok: false };
        const rescored = scoreV4Trial({ entry, per_seed: perSeed, bootstrapRows, prereg });
        if (!rescored.ok) return { ok: false };
        const actual = recordedRun.trials.find((row) => row?.trial_id === entry.trial_id && row?.arm_id === entry.arm_id);
        if (!actual || !Array.isArray(actual.per_seed) || actual.per_seed.length !== V11_SEEDS.length) return { ok: false };
        const project = (row) => ({ trial_id: row?.trial_id, arm_id: row?.arm_id, agreeing: row?.agreeing,
          denominator: row?.denominator, observed: row?.observed, interval: row?.interval,
          per_seed: row?.per_seed, outcome: row?.outcome, decision: row?.decision });
        if (canonicalDigest(project(actual)) !== canonicalDigest(project(rescored))) return { ok: false };
        scoredTrials.push(rescored);
      }
      const numerator = scoredTrials.reduce((sum, row) => sum + row.agreeing, 0);
      const denominator = scoredTrials.reduce((sum, row) => sum + row.denominator, 0);
      const interval = { lower: Math.min(...scoredTrials.map((row) => row.interval.lower)),
        upper: Math.max(...scoredTrials.map((row) => row.interval.upper)) };
      const campaign = decisionIndependent({ observed: numerator / denominator, lower: interval.lower, upper: interval.upper,
        noiseBand: prereg.noise_rule.band, alpha: prereg.multiplicity_rule.alpha,
        confidence: prereg.multiplicity_rule.confidence, familySize: prereg.multiplicity_rule.family_size,
        direction: prereg.multiplicity_rule.direction, nullValue: prereg.multiplicity_rule.null_value });
      const recordedPooled = recordedRun.pooled;
      if (!recordedPooled || recordedPooled.numerator !== numerator || recordedPooled.denominator !== denominator
          || recordedPooled.observed !== numerator / denominator
          || canonicalDigest(recordedPooled.interval) !== canonicalDigest(interval)
          || canonicalDigest(recordedPooled.decision) !== canonicalDigest(campaign)) return { ok: false };
      const projection = { trials: scoredTrials.map((row) => ({ trial_id: row.trial_id,
        agreeing: row.agreeing, denominator: row.denominator, interval: row.interval, outcome: row.outcome })),
        campaign: campaign.decision };
      if (recordedRun.decision_digest !== canonicalDigest(projection)) return { ok: false };
      scoredRuns.push({ arm, trials: scoredTrials.length, agreeing: numerator, denominator,
        observed: numerator / denominator, decision: campaign.decision });
    }
    if (evaluation.runs[0].raw_run_id === evaluation.runs[1].raw_run_id
        || evaluation.reproducibility?.same_base !== true
        || evaluation.reproducibility?.distinct_raw_run_ids !== true
        || evaluation.reproducibility?.same_decision_digest !== (evaluation.runs[0].decision_digest === evaluation.runs[1].decision_digest)) return { ok: false };
    return {
      ok: true, scoringSource: 'PRIMARY_IMMUTABLE_SIDECARS_AND_EVALUATOR_REVIEW_CAPSULE',
      intervalSource: 'EXISTING_BOOTSTRAP_CLI_REPLAYED_WITHOUT_REOPENING_HOLDOUT',
      runs: scoredRuns,
    };
  } catch {
    return { ok: false };
  }
}

export function validateS2PaidReviewGenerationAccounting({ report, sidecar, sidecars, reconciliation, receipts, version = 11, prereg = null } = {}) {
  const sidecarList = Array.isArray(sidecars) ? sidecars : (sidecar ? [sidecar] : []);
  const localRows = [];
  let sidecarCalls = 0;
  let sidecarTokens = 0;
  for (const item of sidecarList) {
    const accounting = item?.accounting;
    if (item?.kind !== 's2-008-campaign-predictions/1'
        || !accounting || accounting.policy !== 'GENERATION_ID_REQUIRED'
        || !Array.isArray(accounting.rows) || accounting.calls !== accounting.rows.length
        || !Number.isSafeInteger(accounting.tokens) || accounting.tokens < 0) fail('V11_RECONCILIATION_LOCAL_ACCOUNTING_INVALID');
    const rowTokens = accounting.rows.reduce((sum, row) => sum + Number(row?.totalTokens), 0);
    if (accounting.tokens !== rowTokens) fail('V11_RECONCILIATION_LOCAL_ACCOUNTING_INVALID');
    sidecarCalls += accounting.calls;
    sidecarTokens += accounting.tokens;
    localRows.push(...accounting.rows);
  }
  const localIds = new Set();
  const byId = new Map();
  for (const row of localRows) {
    const prompt = Number(row?.input) + Number(row?.cacheRead) + Number(row?.cacheWrite);
    const values = [row?.input, row?.output, row?.cacheRead, row?.cacheWrite, row?.prompt_tokens, row?.totalTokens];
    if (typeof row?.generation_id !== 'string' || !/^gen-\d{10}-[A-Za-z0-9]{16,32}$/.test(row.generation_id)
        || typeof row.case_id !== 'string' || localIds.has(row.generation_id)
        || !values.every((value) => Number.isSafeInteger(value) && value >= 0)
        || row.prompt_tokens !== prompt || row.totalTokens !== prompt + row.output
        || row.prompt_token_basis !== 'input+cacheRead+cacheWrite'
        || row.usage_components_consistent !== true
        || !(row.reported_cost_usd === null || (typeof row.reported_cost_usd === 'number'
          && Number.isFinite(row.reported_cost_usd) && row.reported_cost_usd >= 0))) fail('V11_RECONCILIATION_LOCAL_ACCOUNTING_INVALID');
    localIds.add(row.generation_id);
    byId.set(row.generation_id, row);
  }
  let attempts = 0;
  let calls = 0;
  let unknown = 0;
  let modelSeeds = 0;
  for (const trial of report?.trials ?? []) {
    if (trial?.arm_id !== V11_MODEL_ARM) continue;
    for (const seed of trial.seeds ?? []) {
      const executor = seed?.launch?.arm_report?.executor;
      if (!executor || !Number.isSafeInteger(executor.model_attempts) || executor.model_attempts < 0
          || !Number.isSafeInteger(executor.model_calls) || executor.model_calls < 0
          || !Number.isSafeInteger(executor.unknown_model_attempts) || executor.unknown_model_attempts < 0) {
        fail('V11_RECONCILIATION_ATTEMPT_ACCOUNTING_INVALID');
      }
      attempts += executor.model_attempts;
      calls += executor.model_calls;
      unknown += executor.unknown_model_attempts;
      modelSeeds += 1;
    }
  }
  if (modelSeeds !== V11_SEEDS.length || report.status !== 'MEASURED'
      || report.unreconciled_spend !== false || report.spent_units_is_lower_bound !== false
      || report.model_calls_is_lower_bound !== false || report.model_calls !== calls
      || report.unknown_model_attempts !== unknown || attempts !== calls + unknown || unknown !== 0
      || calls !== sidecarCalls || sidecarTokens !== report.spent_units || localRows.length !== calls) {
    fail('V11_RECONCILIATION_COMPLETENESS_INVALID');
  }
  const receiptRows = receipts?.receipts;
  const reconRows = reconciliation?.rows;
  if (!Array.isArray(receiptRows) || !Array.isArray(reconRows)
      || receiptRows.length !== calls || reconRows.length !== calls) fail('V11_RECONCILIATION_RECEIPT_SET_INVALID');
  const receiptById = new Map();
  for (const row of receiptRows) {
    if (typeof row?.id !== 'string' || receiptById.has(row.id)) fail('V11_RECONCILIATION_RECEIPT_SET_INVALID');
    receiptById.set(row.id, row);
  }
  const reconById = new Map();
  for (const row of reconRows) {
    if (typeof row?.generation_id !== 'string' || reconById.has(row.generation_id)) fail('V11_RECONCILIATION_RECEIPT_SET_INVALID');
    reconById.set(row.generation_id, row);
  }
  let tokens = 0;
  let usd = 0;
  for (const [id, local] of byId) {
    const receipt = receiptById.get(id);
    const reconciled = reconById.get(id);
    const idEpoch = Number(id.match(/^gen-(\d{10})-/)?.[1]);
    const createdEpoch = canonicalInstant(receipt?.created_at) ? Math.floor(Date.parse(receipt.created_at) / 1000) : NaN;
    const allowedModels = version === 15
      ? [assertV15ExecutorPolicy(prereg?.executor).model, V15_MODEL_POLICY.catalog_slug]
      : version === 14
        ? [assertV14ExecutorPolicy(prereg?.executor).model, prereg.executor.pi_model_catalog_binding.canonical_slug]
        : [version === 13 ? V13_MODEL_POLICY.model : 'stealth/space-bunny-alpha'];
    const providerBound = version === 15
      ? receipt?.provider === V15_MODEL_POLICY.provider_name
        && reconciled?.provider === V15_MODEL_POLICY.provider_name
      : version === 13 || version === 14
        ? typeof receipt?.provider === 'string' && /^[A-Za-z0-9][A-Za-z0-9 ._:+/-]{0,63}$/.test(receipt.provider)
          && reconciled?.provider === receipt.provider
        : receipt?.provider === 'Stealth';
    if (!receipt || !reconciled || receipt.http_status !== 200 || !providerBound
        || !allowedModels.includes(receipt.model) || !canonicalInstant(receipt.created_at)
        || Math.abs(createdEpoch - idEpoch) > 1
        || !Number.isSafeInteger(receipt.native_prompt) || receipt.native_prompt !== local.prompt_tokens
        || !Number.isSafeInteger(receipt.native_completion) || receipt.native_completion !== local.output
        || !Number.isSafeInteger(receipt.native_cached) || receipt.native_cached !== local.cacheRead
        || !Number.isFinite(receipt.generation_time) || receipt.generation_time < 0
        || receipt.cancelled !== false || typeof receipt.finish_reason !== 'string'
        || receipt.matches_local !== true || typeof receipt.total_cost !== 'number'
        || !Number.isFinite(receipt.total_cost) || receipt.total_cost < 0
        || receipt.native_prompt + receipt.native_completion !== local.totalTokens
        || reconciled.case_id !== local.case_id || reconciled.created_at !== receipt.created_at
        || reconciled.input !== local.input || reconciled.output !== local.output
        || reconciled.cached !== local.cacheRead || reconciled.total_tokens !== local.totalTokens
        || typeof reconciled.provider_reported_usd !== 'number'
        || !sameUsd(reconciled.provider_reported_usd, receipt.total_cost)) {
      fail('V11_RECONCILIATION_LOCAL_PROVIDER_MISMATCH');
    }
    tokens += local.totalTokens;
    usd += receipt.total_cost;
  }
  if (receiptById.size !== byId.size || reconById.size !== byId.size
      || reconciliation?.status !== 'RECONCILED'
      || reconciliation?.completeness_basis !== 'KNOWN_ATTEMPTS_ALL_RECEIPTS'
      || reconciliation?.completeness?.basis !== 'KNOWN_ATTEMPTS_ALL_RECEIPTS'
      || reconciliation?.completeness?.all_local_attempts_accounted !== true
      || reconciliation?.completeness?.unfiltered_account_ledger_claimed !== false
      || reconciliation?.completeness?.confirmed_by !== null
      || reconciliation?.provider_rows_verified_via_api !== true
      || reconciliation?.completeness_verified_via_api !== false
      || reconciliation?.local_model_attempts !== attempts
      || reconciliation?.locally_accounted_model_calls !== calls
      || reconciliation?.matching_requests !== calls || reconciliation?.unreconciled_attempts !== 0
      || reconciliation?.actual_tokens !== tokens || !sameUsd(reconciliation?.actual_usd, usd)
      || receipts.status !== 'KNOWN_GENERATIONS_MATCH' || receipts.known_calls !== calls
      || receipts.known_tokens !== tokens || receipts.unknown_attempts !== 0
      || !sameUsd(receipts.known_provider_usd, usd)) {
    fail('V11_RECONCILIATION_COMPLETENESS_INVALID');
  }
  return { calls, tokens, usd };
}

export function buildS2PaidReviewTask({
  version, taskId, workspaceId, evidenceDigest, imageId,
  ownerPrincipalId, producerPrincipalId, adapterId, at, fixtureOnly = false,
} = {}) {
  const productionIdentity = taskId === 'abt-s2-008-v' + version + '-paid-review'
    && workspaceId === 'ws-s2-008-v' + version + '-paid-review' && adapterId === 'adr-s2-008-v' + version + '-importer';
  const fixturePrefix = 'v' + version + '-fixture-';
  const fixtureIdentity = fixtureOnly === true
    && new RegExp('^abt-s2-008-' + fixturePrefix + '[a-f0-9]{12}$').test(taskId ?? '')
    && new RegExp('^ws-s2-008-' + fixturePrefix + '[a-f0-9]{12}$').test(workspaceId ?? '')
    && new RegExp('^adr-s2-008-' + fixturePrefix + '[a-f0-9]{12}$').test(adapterId ?? '');
  const adapterIdentity = fixtureOnly === true
    ? new RegExp('^adr-s2-008-' + fixturePrefix + '[a-f0-9]{12}$').test(adapterId ?? '')
    : adapterId === 'adr-s2-008-v' + version + '-importer';
  if (!isCapsuleVersion(version) || (!productionIdentity && !fixtureIdentity) || !DIGEST_RE.test(evidenceDigest)
      || !/^sha256:[0-9a-f]{64}$/.test(imageId ?? '') || ownerPrincipalId !== OWNER
      || producerPrincipalId !== PRODUCER || ownerPrincipalId === producerPrincipalId
      || !adapterIdentity || !canonicalInstant(at)) fail('PAID_REVIEW_TASK_INVALID');
  const digest = (value) => 'sha256:' + canonicalDigest(value);
  const task = {
    contractVersion: '1.0.0', task_id: taskId, workspace_id: workspaceId,
    title: fixtureOnly ? '[FIXTURE ONLY] Проверить изолированный snapshot A-MVP-05' : 'Проверить неизменяемые результаты кампании S2-008 v' + version,
    goal: fixtureOnly ? 'Только тестовый офлайн-импорт синтетического snapshot; не является решением по кампании.' : 'Связать опубликованные A/B результаты с подписанным протоколом и передать точный снимок владельцу для решения.',
    description: fixtureOnly ? '[FIXTURE ONLY] Синтетические данные в случайном пространстве; нет кампании, модели или фактических расходов.' : 'Офлайн-импорт фиксированных отчетов, sidecar, квитанций, проверки и оценки; запуск модели запрещен.',
    acceptance_criteria: ['Все три preregistered arms и три seed представлены; A/B, оценка, проверки и квитанции связаны по хешам.'],
    state: 'BACKLOG', revision: 1, priority: 'HIGH', dependencies: [],
    required_capabilities: ['task.read', 'artifact.write'],
    allowed_tools: ['tool:fs.read', 'tool:fs.write', 'tool:process.exec'],
    workspace_ref: { workspace_id: workspaceId, root_ref: 'evidence',
      isolation_profile_id: 'sbx-podman-local-restricted-v1',
      sandbox_profile_digest: digest({ image: imageId, network: 'none', read_only_evidence: true }),
      read_only_paths: ['input', 'source'] },
    time_limits: { timeout_ms: 120000, max_runtime_ms: 120000, deadline: null },
    // This is only AgentBoard's small positive ceiling for the local offline importer.
    // It is not a model budget or a provider-spend measurement.
    cost_limits: { currency: 'USD', max_task_cost: 0.01, max_campaign_cost: 0.01, max_day_cost: 0.01 },
    acl: { visibility: 'personal', allowed_principal_ids: [ownerPrincipalId, producerPrincipalId] },
    brief_digest: digest({ taskId, evidenceDigest, imageId, at }),
    policy_digest: digest({ mode: 'OFFLINE_EVIDENCE_IMPORT', network: 'none', model_calls: 0, tokens: 0, agentboard_cap_only: 0.01, fixtureOnly }),
    manifest_digest: digest({ evidenceDigest, imageId, version, taskId, fixtureOnly }),
    assigned_adapter_id: null, active_lease_id: null, fencing_token: null, attempts: 0,
    artifacts: [], evidence_refs: [], block_reason: null, created_at: at, updated_at: at,
    history_digest: digest([]),
  };
  return assertBoardContract('board-task', task);
}

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

function verifyRunSidecars(reader, report, version, arm, holdoutCount, sharedIds, reasons, holdoutCaseIds = [], controlPin = null, controlSamples = null, controlTimeoutMs = null) {
  let rows = 0;
  let modelRows = 0;
  let controlRows = 0;
  let unparsed = 0;
  let modelUnparsed = 0;
  let controlUnparsed = 0;
  let calls = 0;
  let tokens = 0;
  const predictions = new Map();
  const predictionRows = [];
  const accountingIds = new Set();
  const accountingSidecars = [];
  const coverageCells = [];
  let controlExecutions = 0;
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
      if (isControlPinVersion(version) && trial.arm_id !== V11_MODEL_ARM) {
        if (!validV12ControlCell({ report, trial, seed, pin: controlPin, caseIds: holdoutCaseIds,
          samples: controlSamples, timeoutMs: controlTimeoutMs, expectedOutcome: 'MEASURED_CONTROL', sidecar })) {
          addReason(reasons, 'CONTROL_EXECUTION_INVALID');
        } else controlExecutions += 1;
      }
      rows += sidecar.rows.length;
      const isModelArm = trial.arm_id === V11_MODEL_ARM;
      if (isModelArm) modelRows += sidecar.rows.length;
      else controlRows += sidecar.rows.length;
      const cellCaseIds = [];
      const cellSeen = new Set();
      let cellUnparsed = 0;
      for (const row of sidecar.rows) {
        if (typeof row?.case_id !== 'string' || typeof row?.predicted !== 'string'
            || !['MAJOR', 'MINOR', 'UNPARSED'].includes(row.predicted)
            || cellSeen.has(row.case_id)) {
          addReason(reasons, 'PREDICTION_ROW_INVALID');
          continue;
        }
        cellSeen.add(row.case_id);
        cellCaseIds.push(row.case_id);
        if (row.predicted === 'UNPARSED') {
          unparsed += 1; cellUnparsed += 1;
          if (isModelArm) modelUnparsed += 1;
          else controlUnparsed += 1;
        }
        const key = [trial.trial_id, trial.arm_id, String(seed.seed), row.case_id].join(':');
        if (predictions.has(key)) addReason(reasons, 'PREDICTION_DUPLICATE');
        predictions.set(key, row.predicted);
        predictionRows.push({ trial_id: trial.trial_id, arm_id: trial.arm_id, seed: seed.seed,
          case_id: row.case_id, predicted: row.predicted, prediction_digest: seed.predictions.digest });
      }
      if (isCapsuleVersion(version) && (sidecar.rows.length !== holdoutCount || cellSeen.size !== holdoutCount)) {
        addReason(reasons, 'PREDICTION_CELL_INCOMPLETE');
      }
      coverageCells.push({ trial_id: trial.trial_id, arm_id: trial.arm_id, seed: seed.seed,
        caseIds: cellCaseIds, unparsed: cellUnparsed });
      const accounting = sidecar.accounting;
      if (trial.arm_id === V11_MODEL_ARM || trial.arm_id === 'arm-model-zai-glm53flash') {
        if (!accounting || accounting.policy !== 'GENERATION_ID_REQUIRED' || !Array.isArray(accounting.rows)) {
          addReason(reasons, 'MODEL_ACCOUNTING_MISSING');
          continue;
        }
        accountingSidecars.push(sidecar);
        calls += accounting.rows.length;
        for (const item of accounting.rows) {
          const id = item?.generation_id;
          const prompt = Number(item?.input) + Number(item?.cacheRead) + Number(item?.cacheWrite);
          if (typeof id !== 'string' || !/^gen-\d{10}-[A-Za-z0-9]{16,32}$/.test(id) || sharedIds.has(id)
              || !Number.isSafeInteger(item?.input) || item.input < 0
              || !Number.isSafeInteger(item?.output) || item.output < 0
              || !Number.isSafeInteger(item?.cacheRead) || item.cacheRead < 0
              || !Number.isSafeInteger(item?.cacheWrite) || item.cacheWrite < 0
              || !Number.isSafeInteger(item?.prompt_tokens) || item.prompt_tokens !== prompt
              || !Number.isSafeInteger(item?.totalTokens) || item.totalTokens !== prompt + item.output
              || item.prompt_token_basis !== 'input+cacheRead+cacheWrite'
              || item.usage_components_consistent !== true
              || !(item.reported_cost_usd === null || (typeof item.reported_cost_usd === 'number'
                && Number.isFinite(item.reported_cost_usd) && item.reported_cost_usd >= 0))) {
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
  const maximum = isCapsuleVersion(version) ? holdoutCount * 9 : holdoutCount * 3;
  if (rows > maximum) addReason(reasons, 'PREDICTION_COUNT_INVALID');
  if (isCapsuleVersion(version)) {
    try {
      verifyS2PaidReviewCoverage({ trialList: trials.map(({ trial_id, arm_id }) => ({ trial_id, arm_id })),
        seeds: V11_SEEDS, holdoutCaseIds, observed: coverageCells });
    } catch { addReason(reasons, 'RUN_COVERAGE_INVALID'); }
  }
  return { rows, modelRows, controlRows, unparsed, modelUnparsed, controlUnparsed, calls, tokens, predictions, predictionRows, accountingIds, accountingSidecars, coverageCells, controlExecutions };
}

function basePair(value) {
  return {
    commit: value?.commit_sha ?? value?.base?.commit_sha ?? null,
    tree: value?.tree_sha ?? value?.base?.tree_sha ?? null,
  };
}

export function validateS2PaidReviewControlPinArtifact({ bytes, reference, report, label, expectedBase, version = 12 } = {}) {
  try {
    const relative = 'evidence/s2-008-campaign/control-image-pin-v' + version + '-' + label + '.json';
    if (!Buffer.isBuffer(bytes) || !reference
        || Object.keys(reference).sort().join(',') !== 'bytes,file,sha256'
        || reference.file !== relative || reference.bytes !== bytes.length
        || reference.sha256 !== hash(bytes)) return { ok: false };
    const artifact = JSON.parse(bytes.toString('utf8'));
    if (Object.keys(artifact ?? {}).sort().join(',') !== 'base,control_image_pin,kind,label,nonce,raw_run_id'
        || artifact.kind !== 's2-008-campaign-control-image-pin-artifact/1'
        || artifact.label !== label || artifact.raw_run_id !== report?.raw_run_id
        || artifact.nonce !== report?.nonce
        || artifact.base?.commit_sha !== expectedBase?.commit
        || artifact.base?.tree_sha !== expectedBase?.tree
        || canonicalDigest(artifact.control_image_pin) !== canonicalDigest(report?.control_image_pin)
        || !validateS2PaidReviewControlPinEvidence(artifact.control_image_pin, expectedBase)) return { ok: false };
    return { ok: true, pin: artifact.control_image_pin };
  } catch { return { ok: false }; }
}

function readV12ControlPinArtifact(reader, report, label, expectedBase, reasons, version = 12) {
  const relative = 'evidence/s2-008-campaign/control-image-pin-v' + version + '-' + label + '.json';
  const ref = report?.control_image_pin_artifact;
  if (!ref || Object.keys(ref).sort().join(',') !== 'bytes,file,sha256'
      || ref.file !== relative || !Number.isSafeInteger(ref.bytes) || ref.bytes < 1
      || !DIGEST_RE.test(ref.sha256 ?? '')) {
    addReason(reasons, 'CONTROL_IMAGE_PIN_REFERENCE_INVALID');
    return null;
  }
  const captured = reader.text(relative, new RegExp('^evidence/s2-008-campaign/control-image-pin-v' + version + '-' + label + '[.]json$'));
  const validation = captured && validateS2PaidReviewControlPinArtifact({
    bytes: captured.bytes, reference: ref, report, label, expectedBase, version,
  });
  if (!validation?.ok) {
    addReason(reasons, 'CONTROL_IMAGE_PIN_ARTIFACT_INVALID');
    return null;
  }
  return validation.pin;
}

function validateReconciliationFile(reader, report, version, arm, preregDigest, accounting, sidecarRefs, reasons, sharedIds) {
  const rel = 'evidence/s2-008-campaign/reconciliation-v' + version + '-' + arm + '.json';
  if (isCapsuleVersion(version)) {
    const reconciliation = reader.json(rel, new RegExp('^evidence/s2-008-campaign/reconciliation-v' + version + '-[ab]\\.json$'));
    const reconciliationBytes = reader.text(rel, new RegExp('^evidence/s2-008-campaign/reconciliation-v' + version + '-[ab]\\.json$'));
    const reportPath = 'evidence/s2-008-campaign/run-v' + version + '-' + arm + '.json';
    const reportBytes = reader.text(reportPath, new RegExp('^evidence/s2-008-campaign/run-v' + version + '-' + arm + '\\.json$'));
    const receiptRef = reconciliation?.known_receipts_file;
    const receiptPrefix = 'evidence/s2-008-campaign/provider-receipts-v' + version + '-' + arm + '-' ;
    const receiptPathOk = typeof receiptRef === 'string'
      && receiptRef.startsWith(receiptPrefix)
      && /^[A-Za-z0-9._-]+\.json$/.test(receiptRef.slice(receiptPrefix.length));
    const receipts = receiptPathOk
      ? reader.json(receiptRef, new RegExp('^evidence/s2-008-campaign/provider-receipts-v' + version + '-' + arm + '-[A-Za-z0-9._-]+\\.json$'))
      : null;
    const receiptBytes = receiptPathOk
      ? reader.text(receiptRef, new RegExp('^evidence/s2-008-campaign/provider-receipts-v' + version + '-' + arm + '-[A-Za-z0-9._-]+\\.json$'))
      : null;
    let totals = null;
    try {
      totals = validateS2PaidReviewGenerationAccounting({
        report, sidecars: accounting.accountingSidecars, reconciliation, receipts, version,
      });
    } catch { addReason(reasons, 'RUN_' + arm.toUpperCase() + '_RECONCILIATION_INVALID'); }
    const expectedFinancialSidecars = sidecarRefs
      .filter((row) => row.arm_id === V11_MODEL_ARM)
      .map((row) => ({ file: row.path, sha256: row.sha256 }));
    const boundSidecars = reconciliation?.sidecars;
    const sidecarsMatch = Array.isArray(boundSidecars)
      && boundSidecars.length === expectedFinancialSidecars.length
      && expectedFinancialSidecars.every((row) => boundSidecars.some((item) => item.file === row.file && item.sha256 === row.sha256));
    const valid = totals !== null
      && reconciliation?.kind === 's2-008-v' + version + '-' + arm + '-reconciliation/1'
      && reconciliation.status === 'RECONCILED'
      && reconciliation.preregistration_digest === preregDigest
      && reconciliation.prior_run_id === report.raw_run_id
      && reconciliation.prior_run_sha256 === reportBytes?.sha256
      && reconciliation.provider === 'openrouter'
      && (version === 15
        ? [V15_MODEL_POLICY.model, V15_MODEL_POLICY.catalog_slug].includes(reconciliation.model)
        : reconciliation.model === (version === 14 ? V14_MODEL_POLICY.model : version === 13 ? V13_MODEL_POLICY.model : 'stealth/space-bunny-alpha'))
      && sidecarsMatch
      && receipts?.run_id === report.raw_run_id
      && receiptBytes?.sha256 === reconciliation.known_receipts_sha256
      && reconciliationBytes?.sha256
      && sameUsd(reconciliation.actual_usd, totals?.usd)
      && reconciliation.actual_tokens === totals?.tokens
      && reconciliation.matching_requests === totals?.calls
      && reconciliation.unreconciled_attempts === 0;
    if (!valid) addReason(reasons, 'RUN_' + arm.toUpperCase() + '_RECONCILIATION_INVALID');
    return {
      valid,
      tokens: valid ? totals.tokens : null,
      usd: valid ? totals.usd : null,
      unreconciledAttempts: valid ? 0 : (reconciliation?.unreconciled_attempts ?? null),
      rawUnknownAttempts: report.unknown_model_attempts ?? null,
      runWasLowerBound: report.spent_units_is_lower_bound === true,
      calls: valid ? totals.calls : null,
    };
  }
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
    const run = rootReader.json(runRel, /^evidence\/s2-008-campaign\/run-v10-a\.json$/);
    const stopped = rootReader.json('evidence/s2-008-campaign/stopped-v10-a.json', /^evidence\/s2-008-campaign\/stopped-v10-a\.json$/);
    if (!runText || file.prior_run_sha256 !== runText.sha256 || stopped?.raw_run_sha256 !== runText.sha256) {
      return { status: 'UNKNOWN', tokens: null, usd: null };
    }
    return { status: 'RECONCILED', tokens: file.actual_tokens, usd: file.actual_usd,
      rawUnknownAttempts: run?.unknown_model_attempts ?? null,
      rawTokens: run?.spent_units ?? null,
      rawTokensAreLowerBound: run?.spent_units_is_lower_bound === true,
      unreconciledFinancialAttempts: file.unreconciled_attempts ?? null };
  }
  return { status: 'RECONCILED', tokens: file.actual_tokens, usd: file.actual_usd };
}

export function inspectS2PaidReviewEvidence(root = ROOT) {
  const reasons = [];
  const reader = readerFor(root, reasons);
  const manifestPath = 'corpus/s2-008-campaign/manifest.json';
  const manifest = reader.json(manifestPath, /^corpus\/s2-008-campaign\/manifest\.json$/);
  const versionMatch = manifest?.preregistration?.file?.match(/^preregistration\.v(10|11|12|13|14|15)\.in-force\.json$/);
  const version = versionMatch ? Number(versionMatch[1]) : null;
  if (!versionMatch) addReason(reasons, 'ACTIVE_PREREGISTRATION_PATH_INVALID');
  if (manifest?.preregistration?.status !== 'IN_FORCE'
      || manifest?.preregistration?.sealed_before_first_trial !== true) addReason(reasons, 'ACTIVE_PREREGISTRATION_NOT_IN_FORCE');

  const preregPath = version ? 'corpus/s2-008-campaign/preregistration.v' + version + '.in-force.json' : null;
  const prereg = preregPath ? reader.json(preregPath, /^corpus\/s2-008-campaign\/preregistration\.v(?:10|11|12|13|14|15)\.in-force\.json$/) : null;
  let digest = null;
  let preregValid = false;
  if (prereg && version) {
    try {
      assertPreregistration(prereg);
      if (version === 13) assertV13ExecutorPolicy(prereg.executor);
      if (version === 14) { assertV14ExecutorPolicy(prereg.executor); assertV14ModelTimeoutPolicy(prereg.executor?.model_launch_timeout); }
      if (version === 15) {
        assertV15PreregistrationPolicy(prereg);
        const seal = checkV15OnDisk(root);
        if (seal.preregistration_digest !== prereg.preregistration_digest) throw new Error('V15_SEAL_BINDING_INVALID');
      }
      const { approval, status, preregistration_digest: storedDigest, ...body } = prereg;
      const v14ApprovalKeys = 'authority,becomes_in_force_when,in_force,issued_at,label,principal_id,signed_digest_over,status';
      const validV14Approval = version !== 14 || (approval && Object.keys(approval).sort().join(',') === v14ApprovalKeys
        && approval.status === 'APPROVED' && approval.authority === 'HUMAN_OWNER' && approval.principal_id === OWNER
        && approval.label === 'Daniil' && approval.in_force === true
        && approval.signed_digest_over === 'the scientific body: every member except approval, status and preregistration_digest'
        && approval.becomes_in_force_when === 'scripts/s2-008-campaign-prepare.mjs --seal-v14 records this digest and supersession in the corpus manifest'
        && Number.isFinite(Date.parse(approval.issued_at)) && new Date(approval.issued_at).toISOString() === approval.issued_at);
      const validV15Approval = version !== 15 || (approval && Object.keys(approval).sort().join(',') === v14ApprovalKeys
        && approval.status === 'APPROVED' && approval.authority === 'HUMAN_OWNER' && approval.principal_id === OWNER
        && approval.label === 'Daniil' && approval.in_force === true
        && approval.signed_digest_over === 'the scientific body: every member except approval, status and preregistration_digest'
        && approval.becomes_in_force_when === 'scripts/s2-008-campaign-prepare.mjs --seal-v15 records this digest and supersession in the corpus manifest'
        && Number.isFinite(Date.parse(approval.issued_at)) && new Date(approval.issued_at).toISOString() === approval.issued_at
        && Date.parse(approval.issued_at) < Date.parse('2026-10-12T00:00:00.000Z'));
      digest = canonicalDigest(body);
      preregValid = prereg.rule === 's2-008-prereg-v' + version
        && prereg.preregistration_id === 'xpr-s2-008c-' + String(version).padStart(2, '0')
        && prereg.status === 'APPROVED'
        && approval?.status === 'APPROVED'
        && approval?.authority === 'HUMAN_OWNER'
        && approval?.principal_id === OWNER
        && approval?.in_force === true
        && approval?.signed_digest_over === 'the scientific body: every member except approval, status and preregistration_digest'
        && validV14Approval
        && validV15Approval
        && storedDigest === digest
        && preregistrationDigest(prereg) === digest
        && manifest?.preregistration?.file === 'preregistration.v' + version + '.in-force.json'
        && manifest?.preregistration?.preregistration_digest === digest
        && prereg.executor?.provider === 'openrouter'
        && prereg.executor?.model === (version === 15 ? V15_MODEL_POLICY.model : version === 14 ? V14_MODEL_POLICY.model : version === 13 ? V13_MODEL_POLICY.model : 'stealth/space-bunny-alpha')
        && prereg.executor?.model_launch_timeout?.per_model_call_timeout_ms === 180000
        && ([13, 14, 15].includes(version) ? (prereg.budget_reservation?.granted_units === 5000000
          && prereg.budget_reservation?.ceiling_scope === 'PER_RUN_A_OR_B'
          && prereg.budget_reservation?.expires_at === '2026-10-12T00:00:00.000Z') : true)
        && (![14, 15].includes(version) || (prereg.executor?.model_call_pacing?.min_start_interval_ms === 60000
          && prereg.executor?.model_launch_timeout?.total_container_timeout_ms === 30540000
          && prereg.holdout_access?.case_count === 126))
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
  let v11PriorScanStatus = 'NOT_INSPECTED';
  let v10RestartReconciliationStatus = 'NOT_INSPECTED';
  let v12APriorReconciliationStatus = 'NOT_INSPECTED';
  let v14PriorReconciliationStatus = 'NOT_INSPECTED';
  let v15PriorReconciliationStatus = 'NOT_INSPECTED';
  if (version === 12 && preregValid) {
    try {
      assertV12RestartReconciliation(prereg);
      v10RestartReconciliationStatus = 'RECONCILED';
    } catch {
      v10RestartReconciliationStatus = 'UNKNOWN';
      addReason(reasons, 'V10_RESTART_RECONCILIATION_NOT_VERIFIED');
    }
  }
  if (version === 13 && preregValid) {
    try {
      const baseInputs = readV13BaseInputs({ repoRoot: root, allowHistorical: true });
      const priorInputs = readV13PriorV12AInputs({ repoRoot: root });
      const prior = assertV13RestartReconciliation(baseInputs.base, priorInputs);
      if (canonicalDigest(prereg.v12_prior_execution_reconciliation) !== canonicalDigest(prior)) {
        throw new Error('V13_V12A_BINDING_INVALID');
      }
      v10RestartReconciliationStatus = 'RECONCILED';
      v12APriorReconciliationStatus = 'RECONCILED';
    } catch {
      v10RestartReconciliationStatus = 'UNKNOWN';
      v12APriorReconciliationStatus = 'UNKNOWN';
      addReason(reasons, 'V13_PRIOR_RECONCILIATION_NOT_VERIFIED');
    }
  }
  if (version === 15 && preregValid) {
    try {
      const seal = checkV15OnDisk(root);
      if (seal.preregistration_digest !== prereg.preregistration_digest) throw new Error('V15_SEAL_DIGEST_MISMATCH');
      v10RestartReconciliationStatus = 'RECONCILED';
      v12APriorReconciliationStatus = 'RECONCILED';
      v14PriorReconciliationStatus = 'RECONCILED';
      v15PriorReconciliationStatus = 'RECONCILED';
    } catch {
      v15PriorReconciliationStatus = 'UNKNOWN';
      addReason(reasons, 'V15_PRIOR_RECONCILIATION_NOT_VERIFIED');
    }
  }
  if (version === 14 && preregValid) {
    try {
      const baseInputs = readV14BaseInputs({ repoRoot: root, allowHistorical: true });
      const prior = assertV14RestartReconciliation(baseInputs.base, readV14RestartInputs({ repoRoot: root }));
      if (canonicalDigest(prereg.v13_restart_reconciliation) !== canonicalDigest(prior)) throw new Error('V14_PRIOR_BINDING_INVALID');
      v10RestartReconciliationStatus = 'RECONCILED';
      v12APriorReconciliationStatus = 'RECONCILED';
      v14PriorReconciliationStatus = 'RECONCILED';
    } catch {
      v14PriorReconciliationStatus = 'UNKNOWN';
      addReason(reasons, 'V14_PRIOR_RECONCILIATION_NOT_VERIFIED');
    }
  }
  if (version === 12 && preregValid) {
    try {
      const prior = assertV12PriorExecutionEvidence(prereg.v11_prior_execution_evidence?.scan, { repoRoot: root });
      v11PriorScanStatus = prior.status;
      if (prereg.v11_prior_execution_evidence?.scan_digest !== canonicalDigest(prior)
          || prereg.v11_prior_execution_evidence?.base_preregistration_digest !== prereg.supersession?.superseded_digest) {
        addReason(reasons, 'V11_PRIOR_EXECUTION_EVIDENCE_BINDING_INVALID');
      }
    } catch { addReason(reasons, 'V11_PRIOR_EXECUTION_EVIDENCE_RECONCILIATION_REQUIRED'); }
  }

  const filePattern = /^evidence\/s2-008-campaign\/[A-Za-z0-9._/-]+\.(?:json|log|ndjson)$/;
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
      a: { status: 'NOT_RUN', outcomeClass: null, predictions: 0, modelPredictions: 0, controlPredictions: 0,
        totalPredictions: 0, expectedPredictions: 378, expectedControlPredictions: 756, expectedTotalPredictions: 1134,
        unparsed: null, controlUnparsed: null, rawUnknownAttempts: null, rawTokens: null, rawTokensAreLowerBound: false,
        confirmedTokens: null, confirmedUsd: null, unreconciledAttempts: null, financialStatus: 'UNKNOWN' },
      b: { status: 'NOT_RUN', outcomeClass: null, predictions: 0, modelPredictions: 0, controlPredictions: 0,
        totalPredictions: 0, expectedPredictions: 378, expectedControlPredictions: 756, expectedTotalPredictions: 1134,
        unparsed: null, controlUnparsed: null, rawUnknownAttempts: null, rawTokens: null, rawTokensAreLowerBound: false,
        confirmedTokens: null, confirmedUsd: null, unreconciledAttempts: null, financialStatus: 'UNKNOWN' },
    },
    evaluationRecord: { status: 'NOT_RUN', recordedVerdict: null, recordedRemarks: null,
      linkage: 'NOT_VALIDATED', independentScoringValidation: 'NOT_RECOMPUTED_BY_REVIEWER' },
    verificationChecks: {},
    aEqualsB: null,
    aggregate: { confirmedTokens: null, complete: false, equalityIsDisclosureOnly: true },
    history: {
      v10: historyV10,
      v9: historyV9,
      v8: historyV8,
      v7: { status: 'UNKNOWN', tokens: null },
      ...([12, 13, 14, 15].includes(version) ? {
        v10RestartReconciliationBinding: { status: v10RestartReconciliationStatus },
        v11: { status: v11PriorScanStatus, provider_completeness_claimed: false, tokens: null },
        ...([13, 14, 15].includes(version) ? { v12APriorReconciliationBinding: { status: v12APriorReconciliationStatus, account_completeness_claimed: false } } : {}),
        ...([14, 15].includes(version) ? { v13RestartReconciliationBinding: { status: v14PriorReconciliationStatus, account_completeness_claimed: false } } : {}),
        ...(version === 15 ? { v14RequestOutcomeBinding: { status: v15PriorReconciliationStatus, financial_unknowns_preserved: true, account_completeness_claimed: false } } : {}),
      } : {}),
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
    ...(isCapsuleVersion(version) ? [
      'evidence/s2-008-campaign/v' + version + '-evaluation-access/registry.json',
      'evidence/s2-008-campaign/v' + version + '-evaluation-access/journal.ndjson',
      'evidence/s2-008-campaign/v' + version + '-evaluation-access/head.json',
      'evidence/s2-008-campaign/v' + version + '-evaluation-access/operations.ndjson',
      'scripts/s2-008-campaign-evaluate.mjs',
      'scripts/s2-008-campaign-bootstrap.mjs',
    ] : []),
    'scripts/s2-008-paid-review-import.mjs',
    ...['npm-test', 'test-research', 'test-s2-008', 'test-s2-002-isolation', 'lint', 'typecheck', 'verify-s2-008']
      .map((name) => 'evidence/s2-008-campaign/v' + (version ?? 10) + '-checks/' + name + '.log'),
  ];
  for (const rel of baseNames) {
    const isCorpus = rel.startsWith('corpus/');
    const isScript = rel.startsWith('scripts/');
    const isImporter = rel === 'scripts/s2-008-paid-review-import.mjs';
    const allow = isCorpus ? /^corpus\/s2-008-campaign\/(?:cases\/)?[A-Za-z0-9._-]+\.json$/
      : isScript ? /^scripts\/s2-008-campaign-(?:evaluate|bootstrap)\.mjs$|^scripts\/s2-008-paid-review-import\.mjs$/
        : filePattern;
    const captured = reader.text(rel, allow, false);
    if (!captured && (rel.includes('-checks/') || isImporter
        || (isCapsuleVersion(version) && rel.startsWith('scripts/s2-008-campaign-')))) addReason(reasons, 'VERIFICATION_EVIDENCE_MISSING');
    if (rel.includes('-checks/')) {
      const name = rel.slice(rel.lastIndexOf('/') + 1, -4);
      if (captured) {
        try { campaign.verificationChecks[name] = verifyS2PaidReviewCheckLog(name, captured.text); }
        catch { addReason(reasons, 'VERIFICATION_EVIDENCE_INVALID'); }
      }
    }
  }

  let holdoutCaseIds = [];
  let blindSha256 = null;
  if (isCapsuleVersion(version)) {
    const blindPath = 'corpus/s2-008-campaign/cases/holdout.blind.json';
    const blindRows = reader.json(blindPath, /^corpus\/s2-008-campaign\/cases\/holdout\.blind\.json$/);
    const blindBytes = reader.text(blindPath, /^corpus\/s2-008-campaign\/cases\/holdout\.blind\.json$/);
    blindSha256 = blindBytes?.sha256 ?? null;
    const declared = Object.keys(manifest?.case_digests ?? {}).filter((key) => key.startsWith('HOLDOUT:'))
      .map((key) => key.slice('HOLDOUT:'.length)).sort();
    const blindIndex = validateS2PaidReviewBlindIndex(blindRows, declared);
    if (!blindIndex.ok) addReason(reasons, 'HOLDOUT_BLIND_INDEX_INVALID');
    else holdoutCaseIds = blindIndex.caseIds;
  }
  const pinPath = 'evidence/s2-008-campaign/model-image-pin-v' + (version ?? 10) + '.json';
  const pin = reader.json(pinPath, /^evidence\/s2-008-campaign\/model-image-pin-v(?:10|11|12|13|14|15)\.json$/);
  const preregBytes = preregPath
    ? reader.text(preregPath, /^corpus\/s2-008-campaign\/preregistration\.v(?:10|11|12|13|14|15)\.in-force\.json$/, false)
    : null;
  const pinValidation = validateS2PaidReviewPin({
    pin, preregistrationSha256: preregBytes?.sha256, blindSha256, version,
  });
  let v13PinValid = true;
  let v14PinValid = true;
  let v15PinValid = true;
  if (version === 13) {
    try { assertV13PresealPin({ pin, baseBytes: preregBytes?.bytes,
      commitment: prereg?.executor?.model_image?.content_commitment }); }
    catch { v13PinValid = false; }
  }
  if (version === 14) {
    try { assertV14PresealPin({ pin, baseBytes: preregBytes?.bytes, commitment: prereg?.executor?.model_image?.content_commitment }); }
    catch { v14PinValid = false; }
  }
  if (version === 15) {
    try { assertV15PresealPin({ pin, baseBytes: preregBytes?.bytes, commitment: prereg?.executor?.model_image?.content_commitment }); }
    catch { v15PinValid = false; }
  }
  const pinOk = isCapsuleVersion(version)
    ? pinValidation.ok === true && (version !== 13 || v13PinValid) && (version !== 14 || v14PinValid) && (version !== 15 || v15PinValid)
      && pin?.schema === 's2-008-model-image-pin/' + version
      && prereg?.executor?.model_image?.built_image_pin === pinPath
      && pin.first.content_commitment === prereg?.executor?.model_image?.content_commitment
    : pin?.schema === 's2-008-model-image-pin/' + version
      && prereg?.executor?.model_image?.built_image_pin === pinPath
      && typeof pin.first?.imageId === 'string' && pin.first.imageId === pin.second?.imageId
      && pin.first.digest === pin.second?.digest
      && pin.first.content_commitment === pin.second?.content_commitment
      && pin.first.content_commitment === prereg?.executor?.model_image?.content_commitment
      && /^sha256:[0-9a-f]{64}$/.test(pin.first.digest);
  if (!pinOk) addReason(reasons, 'MODEL_IMAGE_PIN_INVALID');

  const probes = reader.json('evidence/s2-008-campaign/probes-v' + (version ?? 10) + '.json', /^evidence\/s2-008-campaign\/probes-v(?:10|11|12|13|14|15)\.json$/);
  const security = reader.json('evidence/s2-008-campaign/security-probes-v' + (version ?? 10) + '.json', /^evidence\/s2-008-campaign\/security-probes-v(?:10|11|12|13|14|15)\.json$/);
  const dry = reader.json('evidence/s2-008-campaign/dry-run-v' + (version ?? 10) + '-clean-base.json', /^evidence\/s2-008-campaign\/dry-run-v(?:10|11|12|13|14|15)-clean-base\.json$/);
  const base = basePair(probes);
  const securityBase = basePair(security);
  const dryBase = basePair(dry);
  const dryControlPin = isControlPinVersion(version)
    ? readV12ControlPinArtifact(reader, dry, 'clean-base', dryBase, reasons, version) : null;
  const dryValidation = isCapsuleVersion(version)
    ? validateS2PaidReviewDryRun({ dry, preregistrationDigest: digest, pin, expectedBase: base,
      version, controlPin: dryControlPin, expectedCaseIds: holdoutCaseIds,
      samples: prereg?.noise_rule?.bootstrap_samples, timeoutMs: prereg?.budget_reservation?.trial_timeout_ms })
    : { ok: dry?.status === 'DRY_RUN' && dry?.dry_run === true
        && Number.isSafeInteger(dry?.model_calls) && dry.model_calls === 0
        && Number.isSafeInteger(dry?.spent_units) && dry.spent_units === 0
        && dry?.unreconciled_spend === false
        && dryBase.commit === base.commit && dryBase.tree === base.tree };
  if (probes?.status !== 'PASS' || probes?.ok !== true || probes?.exitCode !== 0
      || probes?.preregistration_file !== preregPath || probes?.preregistration_digest !== digest
      || security?.status !== 'PASS' || security?.ok !== true || security?.exitCode !== 0
      || !base.commit || !base.tree || securityBase.commit !== base.commit || securityBase.tree !== base.tree
      || dryValidation.ok !== true) addReason(reasons, 'PROBE_OR_DRY_RUN_INVALID');

  const sharedIds = new Set();
  const armReconciliations = {};
  const armSidecars = {};
  const armReports = {};
  const armControlPins = {};
  for (const arm of ['a', 'b']) {
    const rel = 'evidence/s2-008-campaign/run-v' + (version ?? 10) + '-' + arm + '.json';
    const report = reader.json(rel, new RegExp('^evidence/s2-008-campaign/run-v' + (version ?? 10) + '-' + arm + '\\.json$'), false);
    if (!report) {
      campaign.arms[arm].status = 'NOT_RUN';
      addReason(reasons, 'RUN_' + arm.toUpperCase() + '_MISSING');
      continue;
    }
    armReports[arm] = report;
    const baseRun = basePair(report);
    const controlPin = isControlPinVersion(version)
      ? readV12ControlPinArtifact(reader, report, arm, baseRun, reasons, version) : null;
    armControlPins[arm] = controlPin;
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
    const accounting = verifyRunSidecars(reader, report, version ?? 10, arm, 126, sharedIds, reasons, holdoutCaseIds,
      controlPin, prereg?.noise_rule?.bootstrap_samples, prereg?.budget_reservation?.trial_timeout_ms);
    for (const trial of report.trials ?? []) for (const seed of trial.seeds ?? []) {
      const ref = seed?.predictions?.file;
      if (typeof ref === 'string') {
        const value = reader.text(ref, new RegExp('^evidence/s2-008-campaign/predictions-v' + (version ?? 10) + '-' + arm + '-[A-Za-z0-9._-]+\\.json$'), false);
        if (value) sidecarRefs.push({ path: ref, sha256: value.sha256, arm_id: trial.arm_id });
      }
    }
    armSidecars[arm] = accounting;
    const recon = validateReconciliationFile(reader, report, version ?? 10, arm, digest, accounting, sidecarRefs, reasons, sharedIds);
    armReconciliations[arm] = recon;
    if (arm === 'a' && version === 10) campaign.history.v10 = { status: recon.valid ? 'RECONCILED' : 'UNKNOWN', tokens: recon.tokens, usd: recon.usd, unreconciledAttempts: recon.unreconciledAttempts, rawUnknownAttempts: recon.rawUnknownAttempts };
    const expectedModel = 126 * 3;
    const expectedControls = 126 * 3 * 2;
    const expectedTotal = expectedModel + expectedControls;
    const measured = report.status === 'MEASURED' && report.unreconciled_spend === false
      && report.spent_units_is_lower_bound === false && report.model_calls_is_lower_bound === false
      && report.unknown_model_attempts === 0
      && accounting.modelRows === expectedModel && accounting.controlRows === expectedControls
      && accounting.rows === expectedTotal && accounting.calls === expectedModel
      && (!isControlPinVersion(version) || accounting.controlExecutions === 6)
      && recon.valid && recon.unreconciledAttempts === 0;
    campaign.arms[arm] = {
      status: report.status === 'MEASURED' ? 'MEASURED' : report.status === 'BLOCKED' ? 'BLOCKED' : 'INVALID',
      outcomeClass: report.outcome_class ?? report.trials?.[0]?.seeds?.[0]?.outcome_class ?? null,
      predictions: accounting.modelRows,
      modelPredictions: accounting.modelRows,
      controlPredictions: accounting.controlRows,
      totalPredictions: accounting.rows,
      expectedPredictions: expectedModel,
      expectedControlPredictions: expectedControls,
      expectedTotalPredictions: expectedTotal,
      unparsed: accounting.modelUnparsed,
      controlUnparsed: accounting.controlUnparsed,
      rawUnknownAttempts: report.unknown_model_attempts ?? null,
      rawTokens: report.spent_units ?? null,
      rawTokensAreLowerBound: report.spent_units_is_lower_bound === true,
      confirmedTokens: recon.valid ? recon.tokens : null,
      confirmedUsd: recon.valid ? recon.usd : null,
      unreconciledAttempts: recon.valid ? recon.unreconciledAttempts : (report.unknown_model_attempts ?? null),
      financialStatus: recon.valid ? 'RECONCILED' : 'UNKNOWN',
    };
    if (report.status !== 'MEASURED' || campaign.arms[arm].outcomeClass !== 'MEASURED') addReason(reasons, 'RUN_' + arm.toUpperCase() + '_INFRA');
    if (!measured) addReason(reasons, 'RUN_' + arm.toUpperCase() + '_INCOMPLETE');
  }

  if (isControlPinVersion(version) && (!dryControlPin || !armControlPins.a || !armControlPins.b
      || canonicalDigest(dryControlPin) !== canonicalDigest(armControlPins.a)
      || canonicalDigest(dryControlPin) !== canonicalDigest(armControlPins.b))) {
    addReason(reasons, 'CONTROL_IMAGE_PIN_LINEAGE_INVALID');
  }

  let probeValidation = null;
  if (isCapsuleVersion(version)) {
    try {
      const validateProbe = version === 15 ? validateV15ProbeEvidence : version === 14 ? validateV14ProbeEvidence : version === 13 ? validateV13ProbeEvidence : version === 12 ? validateV12ProbeEvidence : validateV11ProbeEvidence;
      probeValidation = validateProbe({ campaignProbes: probes, securityControls: security,
        prereg, runA: armReports.a, runB: armReports.b });
      if (probeValidation?.ok !== true || probeValidation.status !== 'PASS') addReason(reasons, 'PROBE_OR_DRY_RUN_INVALID');
    } catch { addReason(reasons, 'PROBE_OR_DRY_RUN_INVALID'); }
  }

  const evaluationPath = 'evidence/s2-008-campaign/evaluation-v' + (version ?? 10) + '.json';
  const comparisonPath = 'evidence/s2-008-campaign/comparison-v' + (version ?? 10) + '.json';
  const checksComplete = !isCapsuleVersion(version) || Object.keys(PAID_CHECK_COMMANDS)
    .every((name) => campaign.verificationChecks[name]?.exitStatus === 0);
  const runsComplete = !isCapsuleVersion(version) || ['a', 'b'].every((arm) => {
    const report = armReports[arm];
    const accounting = armSidecars[arm];
    const reconciliation = armReconciliations[arm];
    return validateS2PaidReviewRunReadiness({ report, accounting, reconciliation, version,
      controlPin: armControlPins[arm], caseIds: holdoutCaseIds, samples: prereg?.noise_rule?.bootstrap_samples,
      timeoutMs: prereg?.budget_reservation?.trial_timeout_ms }).ok;
  });
  const canReadEvaluation = !isCapsuleVersion(version)
    || (reasons.length === 0 && checksComplete && runsComplete && pinOk && dryValidation.ok === true
      && probeValidation?.ok === true && preregValid);
  const evaluation = canReadEvaluation
    ? reader.json(evaluationPath, /^evidence\/s2-008-campaign\/evaluation-v(?:10|11|12|13|14|15)\.json$/, false)
    : null;
  const comparison = reader.json(comparisonPath, /^evidence\/s2-008-campaign\/comparison-v(?:10|11|12|13|14|15)\.json$/, false);
  if (isCapsuleVersion(version) && !canReadEvaluation) {
    campaign.evaluationRecord = { status: 'NOT_RUN', recordedVerdict: null, recordedRemarks: null,
      linkage: 'NOT_VALIDATED', independentScoringValidation: 'WAITING_FOR_COMPLETE_A_B_AND_REQUIRED_CHECKS' };
    addReason(reasons, 'EVALUATION_NOT_RUN_UNTIL_PREREQUISITES_COMPLETE');
  } else if (!evaluation) addReason(reasons, 'EVALUATION_MISSING');
  else if (isCapsuleVersion(version)) {
    try {
      const capturedSourcePaths = version === 15 ? [...V15_REVIEW_CAPSULE_SOURCE_PATHS] : version === 14 ? [...V14_REVIEW_CAPSULE_SOURCE_PATHS] : [
        'corpus/s2-008-campaign/preregistration.v' + version + '.in-force.json',
        'corpus/s2-008-campaign/manifest.json',
        'corpus/s2-008-campaign/frozen-table.v3.json',
        'corpus/s2-008-campaign/cases/holdout.blind.json',
        'scripts/s2-008-campaign-evaluate.mjs',
        'scripts/s2-008-campaign-bootstrap.mjs',
        ...([12, 13].includes(version) ? ['scripts/s2-008-campaign-adapter.mjs'] : []),
        ...(version === 13 ? [
          'scripts/s2-008-campaign-arm-model.mjs',
          'scripts/s2-008-campaign-credential-env.mjs',
          'scripts/s2-008-campaign-model-image.mjs',
          'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json',
        ] : []),
      ];
      const capturedSourceInputs = capturedSourcePaths.map((file) => {
        const allow = file.startsWith('corpus/')
          ? /^corpus\/s2-008-campaign\/(?:cases\/)?[A-Za-z0-9._-]+\.json$/
          : [V15_MODEL_POLICY.catalog_file, V15_MODEL_POLICY.endpoint_catalog_file].includes(file)
            ? new RegExp('^' + file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$')
            : file === 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json'
              ? /^evidence\/s2-008-campaign\/provider-model-catalog-ling-v13\.json$/
              : /^scripts\/s2-008-campaign-(?:evaluate|bootstrap|adapter|arm-model|credential-env|model-image|v14-approval|v14-pacing|seal-v14|run|approve|prepare|prepare-cli|v15-policy|v15-approval|seal-v15|probes)\.mjs$|^scripts\/s2-008-paid-review-workflow\.mjs$/;
        const value = reader.text(file, allow);
        return value ? { path: file, bytes: value.bytes.length, sha256: value.sha256 } : null;
      });
      const runReportSha256 = {};
      const capsuleSidecars = {};
      for (const arm of ['a', 'b']) {
        const runPath = 'evidence/s2-008-campaign/run-v' + version + '-' + arm + '.json';
        const runBytes = reader.text(runPath, new RegExp('^evidence/s2-008-campaign/run-v' + version + '-' + arm + '\\.json$'));
        runReportSha256[arm] = runBytes?.sha256;
        capsuleSidecars[arm] = [];
        for (const trial of armReports[arm].trials) for (const seed of trial.seeds) {
          const sidecarPath = seed.predictions.file;
          const sidecar = reader.text(sidecarPath, new RegExp('^evidence/s2-008-campaign/predictions-v' + version + '-[ab]-[A-Za-z0-9._-]+\\.json$'));
          if (!sidecar) throw new Error('PAID_REVIEW_SIDECAR_MISSING');
          capsuleSidecars[arm].push({
            trial_id: trial.trial_id, arm_id: trial.arm_id, seed: seed.seed,
            path: sidecarPath, digest: seed.predictions.digest, sha256: sidecar.sha256,
            bytes: sidecar.bytes.length, rows: seed.predictions.rows,
          });
        }
      }
      const registryPaths = [
        'evidence/s2-008-campaign/v' + version + '-evaluation-access/registry.json',
        'evidence/s2-008-campaign/v' + version + '-evaluation-access/journal.ndjson',
        'evidence/s2-008-campaign/v' + version + '-evaluation-access/head.json',
        'evidence/s2-008-campaign/v' + version + '-evaluation-access/operations.ndjson',
      ];
      const registryFiles = registryPaths.map((file) => {
        const bytes = reader.text(file, new RegExp('^evidence/s2-008-campaign/v' + version + '-evaluation-access/[A-Za-z0-9._-]+\\.(?:json|ndjson)$'));
        return bytes ? { path: file, bytes: bytes.bytes.length, sha256: bytes.sha256, contents: bytes.bytes } : null;
      });
      const capsuleFiles = registryFiles.map((file) => file && ({ path: file.path, bytes: file.bytes, sha256: file.sha256 }));
      const accessJournal = registryFiles[1];
      const replay = registryFiles.every(Boolean)
        ? replayS2PaidReviewAccessFiles({ files: registryFiles, journalSha256: accessJournal.sha256, version })
        : { ok: false };
      const capsuleValidation = validateS2PaidReviewReviewCapsule({
        capsule: evaluation.review_capsule, evaluation, prereg, declaredCaseIds: holdoutCaseIds,
        runReports: armReports, runReportSha256,
        sidecarRefs: capsuleSidecars, sourceInputs: capturedSourceInputs,
        accessJournal: replay.ok ? replay.rows : [], accessJournalSha256: accessJournal?.sha256,
        registryFiles: capsuleFiles, registryReplay: replay, version,
      });
      if (!replay.ok || !capsuleValidation.ok) throw new Error('PAID_REVIEW_EVALUATION_CAPSULE_INVALID');
      const validation = validateS2PaidReviewEvaluation({
        evaluation, runReports: armReports,
        predictionRowsByArm: { a: armSidecars.a.predictionRows, b: armSidecars.b.predictionRows },
        holdoutCases: capsuleValidation.holdoutCases, prereg, manifest,
        frozenTable: reader.json('corpus/s2-008-campaign/frozen-table.v3.json',
          /^corpus\/s2-008-campaign\/frozen-table\.v3\.json$/),
        capsuleVerified: true,
      });
      if (!validation.ok) throw new Error('PAID_REVIEW_EVALUATION_REPLAY_INVALID');
      campaign.evaluationRecord = {
        status: 'RECORDED_LINKED',
        recordedVerdict: evaluation.deterministic_evaluation.verdict,
        recordedRemarks: evaluation.deterministic_evaluation.remarks,
        linkage: 'CAPSULE_LABELS_RUN_SIDECARS_AND_REPLAYED_ACCESS_JOURNAL',
        independentScoringValidation: validation.scoringSource,
        intervalValidation: validation.intervalSource,
        capsuleDigest: capsuleValidation.capsuleDigest,
        runSummaries: validation.runs,
      };
    } catch {
      campaign.evaluationRecord = { status: 'INVALID', recordedVerdict: null, recordedRemarks: null,
        linkage: 'INVALID', independentScoringValidation: 'NOT_VALIDATED' };
      addReason(reasons, 'EVALUATION_CAPSULE_OR_REPLAY_INVALID');
    }
  } else {
    const linked = Array.isArray(evaluation.runs) && evaluation.runs.length === 2
      && ['a', 'b'].every((arm) => {
        const report = armReports[arm];
        const scored = evaluation.runs.find((row) => row.label === arm);
        return report && scored && scored.raw_run_id === report.raw_run_id
          && scored.spent_units === report.spent_units && scored.model_calls === report.model_calls
          && basePair(scored).commit === basePair(report).commit
          && basePair(scored).tree === basePair(report).tree
          && Array.isArray(scored.trials) && scored.trials.length === V11_TRIALS.length
          && V11_TRIALS.every((trial) => scored.trials.some((row) => row.trial_id === trial.trial_id
            && Number.isSafeInteger(row.denominator) && row.denominator === 126 * V11_SEEDS.length
            && Number.isSafeInteger(row.agreeing) && row.agreeing >= 0 && row.agreeing <= row.denominator));
      })
      && evaluation.runs[0].raw_run_id !== evaluation.runs[1].raw_run_id;
    if (!linked || evaluation.preregistration_digest !== digest
        || evaluation.verdict !== 'PENDING_HUMAN_REVIEW'
        || evaluation.prediction_source !== 'IMMUTABLE_RUN_SIDECARS'
        || evaluation.deterministic_evaluation?.verdict !== 'AGREES'
        || !Array.isArray(evaluation.deterministic_evaluation?.remarks)
        || evaluation.deterministic_evaluation.remarks.length !== 0
        || evaluation.table?.verdict !== 'AGREES'
        || evaluation.reproducibility?.same_base !== true
        || evaluation.reproducibility?.distinct_raw_run_ids !== true) addReason(reasons, 'EVALUATION_INVALID');
    else campaign.evaluationRecord = {
      status: 'RECORDED_LINKED',
      recordedVerdict: evaluation.deterministic_evaluation.verdict,
      recordedRemarks: evaluation.deterministic_evaluation.remarks,
      linkage: 'PREREGISTRATION_AND_RUN_IDS_MATCH',
      independentScoringValidation: 'LEGACY_RECORDED_EVALUATOR_OUTPUT_BOUND_TO_RUNS',
    };
  }
  if (!comparison) addReason(reasons, 'COMPARISON_MISSING');
  else if (isCapsuleVersion(version)) {
    try {
      validateS2PaidReviewComparison({
        comparison, version,
        preregistrationDigest: digest,
        holdoutCaseIds,
        aPredictions: armSidecars.a?.predictionRows ?? [],
        bPredictions: armSidecars.b?.predictionRows ?? [],
      });
    } catch { addReason(reasons, 'COMPARISON_CONTENT_INVALID'); }
  } else if (comparison.preregistration_digest !== digest) addReason(reasons, 'COMPARISON_BINDING_INVALID');

  const a = campaign.arms.a;
  const b = campaign.arms.b;
  if (a.totalPredictions === a.expectedTotalPredictions && b.totalPredictions === b.expectedTotalPredictions) {
    const left = armSidecars.a?.predictions ?? new Map();
    const right = armSidecars.b?.predictions ?? new Map();
    const equivalent = (leftMap, rightMap) => leftMap.size === rightMap.size
      && [...leftMap].every(([key, value]) => rightMap.get(key) === value);
    const leftModel = new Map([...left].filter(([key]) => key.includes(':' + V11_MODEL_ARM + ':')));
    const rightModel = new Map([...right].filter(([key]) => key.includes(':' + V11_MODEL_ARM + ':')));
    campaign.aEqualsB = {
      allPredictions: equivalent(left, right),
      modelPredictions: equivalent(leftModel, rightModel),
      equalityIsDisclosureOnly: true,
    };
  }
  if (a.confirmedTokens !== null && b.confirmedTokens !== null) {
    campaign.aggregate = { confirmedTokens: a.confirmedTokens + b.confirmedTokens, complete: true, equalityIsDisclosureOnly: true };
  } else {
    const known = [a.confirmedTokens, b.confirmedTokens].filter((value) => Number.isSafeInteger(value));
    campaign.aggregate = { confirmedTokens: known.length ? known.reduce((sum, value) => sum + value, 0) : null,
      complete: false, equalityIsDisclosureOnly: true };
  }
  if (!isCapsuleVersion(version)) addReason(reasons, 'PAID_REVIEW_VERSION_UNSUPPORTED');
  const records = reader.records();
  const artifactManifestDigest = canonicalDigest(records);
  return {
    ready: reasons.length === 0,
    state: reasons.length === 0 ? 'PENDING' : 'NOT_READY',
    workflow: { mode: reasons.length === 0 ? 'OWNER_REVIEW' : 'NOT_READY', actionable: reasons.length === 0 },
    version,
    modelImagePin: pinOk ? { imageId: pin.first.imageId, digest: pin.first.digest, content_commitment: pin.first.content_commitment } : null,
    fixture_only: false,
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
  const actions = options.credential?.actions;
  const requiredActions = ['approve', 'request_changes', 'start', 'view'];
  if (!Array.isArray(actions) || [...actions].sort().join(',') !== requiredActions.join(',')) fail('REVIEW_CREDENTIAL_INVALID');
  if (!isTrustedS2PaidReviewWorkflow(workflow) || workflow.taskId !== expectedTask || workflow.fixtureOnly === true) {
    fail('PAID_REVIEW_WORKFLOW_INVALID');
  }
  return createA05ReviewServer({ ...options, workflow, presentation: 'paid-evidence-review' });
}

export function createS2PaidReviewWorkflow(options = {}) {
  const fixtureOnly = options.fixtureOnly === true;
  return createPaidWorkflow({
    pool: options.pool ?? null, evidenceRoot: options.evidenceRoot ?? ROOT,
    inspectEvidence: inspectS2PaidReviewEvidence, buildTask: buildS2PaidReviewTask,
    ownerPrincipalId: OWNER, producerPrincipalId: PRODUCER,
    stateRoot: fixtureOnly && typeof options.stateRoot === 'string' ? options.stateRoot : STATE,
    replayJournal: replayA05Journal, fixtureOnly,
    fixtureRoot: fixtureOnly ? options.fixtureRoot : null,
    fixtureRecords: fixtureOnly ? options.fixtureRecords : null, version: options.version ?? 11,
  });
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
  const credentialPath = path.join(dir, 'reviewer.private.v2.json');
  if (mode === '--serve') {
    let credential;
    try { credential = JSON.parse(privateRead(credentialPath)); }
    catch { fail('PRIVATE_CREDENTIAL_UNAVAILABLE'); }
    const { pool } = await setupA05Database();
    const workflow = createS2PaidReviewWorkflow({ pool, evidenceRoot: ROOT, version: evidence.version });
    const server = createS2PaidReviewServer({ credential, workflow, evidenceRoot: ROOT });
    server.once('close', () => pool.end());
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(8787, '127.0.0.1', resolve);
    });
    console.log(JSON.stringify({ state: evidence.ready ? 'PENDING' : 'NOT_READY', ready: evidence.ready, url: 'http://127.0.0.1:8787', version: evidence.version, reasons: evidence.reasons }));
    return;
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tokenPath = path.join(dir, 'reviewer.private.v2.token');
  if (!fs.existsSync(credentialPath)) {
    const token = randomBytes(32).toString('base64url');
    fs.writeFileSync(tokenPath, token, { mode: 0o600, flag: 'wx' });
    save(credentialPath, { tokenHash: hashS2PaidReviewToken(token), principalId: OWNER,
      taskId: 'abt-s2-008-v' + evidence.version + '-paid-review',
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      actions: ['view','start','approve','request_changes'] }, true);
  }
  console.log(JSON.stringify({ state: evidence.ready ? 'PENDING' : 'NOT_READY', ready: evidence.ready, version: evidence.version, reasons: evidence.reasons, token_file: tokenPath, credential_file: credentialPath }));
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(JSON.stringify({ code: error.code ?? error.message ?? 'PAID_REVIEW_FAILED' }));
    process.exitCode = 1;
  });
}
