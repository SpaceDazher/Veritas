import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { FROZEN_MEMBERS, preregistrationDigest, scopeDrift, scientificBody } from './s2-008-campaign-approve.mjs';
import { assertPreregistration } from '../src/lib/research/preregistration.mjs';
import { assertVersionedPresealPin } from './s2-008-campaign-v6-approval.mjs';
import { assertV6ModelTimeoutPolicy } from './s2-008-campaign-v6-timeout.mjs';
import { V11_FAILURE_DIAGNOSTICS_POLICY } from './s2-008-campaign-arm-model.mjs';
import { V8_EXECUTOR_POLICY, V7_PI_SETTINGS, assertV8ExecutorPolicy } from './s2-008-campaign-credential-env.mjs';
import { assertV10AReconciliation, readV11ReconciliationInputs } from './s2-008-campaign-v11-approval.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EVIDENCE_DIR = path.join(ROOT, 'evidence/s2-008-campaign');
const BASE_FILE = 'preregistration.v11.in-force.json';
const BASE_DIGEST = '244a6801e4b1f6ea4bd71097fb70a768113b72f085d4899e876993627590bf4c';
const BASE_SHA256 = '63f9b66761263a056cd9f6c4d54c97e0c5b063d08c19a08dec3be611dfc04e5d';
const BASE_SUPERSESSION_FILE = 'preregistration-v11-supersession.json';
const BASE_SUPERSESSION_ID = 'spr-6f5e296f15e53ae440c57ef5';
const BASE_SUPERSESSION_DIGEST = '39d04daa7e700305740fb3597fe8ec4cfb3fde4bcffd834ad0130de3c7b4b713';
const BASE_SUPERSESSION_SHA256 = '40db1f8440be2a7eb20765de979fb13df9c0154a57962b2f9ca97b3cef9a7e8c';
const V12_EXPIRY = '2026-10-12T00:00:00.000Z';
const V12_OWNER = 'prn-s2007r-owner';
const SCAN_KIND = 's2-008-v12-prior-v11-execution-scan/1';
const SCAN_SCOPE = 'evidence/s2-008-campaign/{run-v11-[ab].json,predictions-v11-[ab]-*.json,reconciliation-v11-[ab].json,provider-receipt(s)-v11-[ab]-*.json,stopped-v11-[ab].json,campaign-v11-[ab]-attempt-*.json} in this checkout';
const CANDIDATE_FILE = /^(?:run-v11-[ab]\.json|predictions-v11-[ab]-.+\.json|reconciliation-v11-[ab]\.json|provider-receipts-v11-[ab]-.+\.json|provider-receipt-v11-[ab]-.+\.json|stopped-v11-[ab]\.json|campaign-v11-[ab]-attempt-[A-Za-z0-9._-]+\.json)$/;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const parseBytes = (value) => JSON.parse(Buffer.from(value).toString('utf8'));
const isCount = (value) => Number.isSafeInteger(value) && value >= 0;

export function assertV12RestartReconciliation(prereg, inputs = readV11ReconciliationInputs()) {
  let pinnedBaseBytes;
  let pinnedBase;
  try {
    pinnedBaseBytes = fs.readFileSync(path.join(ROOT, 'corpus/s2-008-campaign', BASE_FILE));
    pinnedBase = parseBytes(pinnedBaseBytes);
  } catch {
    throw new Error('V12_RESTART_RECONCILIATION_BASE_INVALID');
  }
  const bound = prereg?.restart_reconciliation;
  const pinnedBinding = pinnedBase?.restart_reconciliation;
  if (sha256(pinnedBaseBytes) !== BASE_SHA256 || !bound || !pinnedBinding ||
      canonicalDigest(bound) !== canonicalDigest(pinnedBinding)) {
    throw new Error('V12_RESTART_RECONCILIATION_BINDING_MISMATCH');
  }
  const actual = assertV10AReconciliation(inputs);
  if (bound.kind !== actual.kind ||
      bound.file !== 'evidence/s2-008-campaign/reconciliation-v10-a.json' ||
      bound.raw_sha256 !== actual.reconciliationSha256 ||
      bound.canonical_digest !== actual.canonicalDigest ||
      bound.known_receipts_file !== 'evidence/s2-008-campaign/provider-receipts-v10-a-known.json' ||
      bound.known_receipts_sha256 !== actual.knownReceiptSha256 ||
      bound.overlap_receipt_file !== 'evidence/s2-008-campaign/provider-receipt-v10-a-overlap.json' ||
      bound.overlap_receipt_sha256 !== actual.overlapReceiptSha256 ||
      bound.prior_run_id !== actual.priorRunId ||
      bound.prior_run_sha256 !== actual.priorRunSha256 ||
      bound.prior_sidecar_file !== 'evidence/s2-008-campaign/predictions-v10-a-trl-s2-008c-01-20260926.json' ||
      bound.prior_sidecar_sha256 !== actual.priorSidecarSha256 ||
      bound.preregistration_digest !== actual.preregistrationDigest ||
      bound.reconciled_campaign_tokens !== actual.actualTokens ||
      bound.reconciled_campaign_usd !== actual.actualUsd ||
      bound.provider_calls !== actual.providerCalls ||
      bound.local_attempts !== actual.localAttempts ||
      bound.unreconciled_attempts !== actual.unreconciledAttempts ||
      bound.prior_v9_campaign_tokens !== actual.priorV9Tokens ||
      bound.aggregate_prior_campaign_tokens !== actual.aggregatePriorTokens ||
      bound.separate_v9_diagnostic_tokens !== actual.diagnosticTokens ||
      bound.aggregate_campaign_and_diagnostic_tokens !== actual.aggregateIncludingDiagnostics) {
    throw new Error('V12_RESTART_RECONCILIATION_BINDING_MISMATCH');
  }
  return actual;
}

export function readV12BaseInputs() {
  const corpus = path.join(ROOT, 'corpus/s2-008-campaign');
  const baseBytes = fs.readFileSync(path.join(corpus, BASE_FILE));
  const supersessionBytes = fs.readFileSync(path.join(corpus, BASE_SUPERSESSION_FILE));
  return {
    base: parseBytes(baseBytes),
    baseBytes,
    manifest: JSON.parse(fs.readFileSync(path.join(corpus, 'manifest.json'), 'utf8')),
    supersession: parseBytes(supersessionBytes),
    supersessionBytes,
    table: JSON.parse(fs.readFileSync(path.join(corpus, 'frozen-table.v3.json'), 'utf8')),
  };
}

export function assertV12BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table } = {}) {
  if (!base || !Buffer.isBuffer(baseBytes) || !manifest || !supersession ||
      !Buffer.isBuffer(supersessionBytes) || !table) throw new Error('V12_BASE_INPUTS_MISSING');
  let parsedBase;
  let parsedSupersession;
  try {
    parsedBase = parseBytes(baseBytes);
    parsedSupersession = parseBytes(supersessionBytes);
  } catch {
    throw new Error('V12_BASE_BYTES_INVALID');
  }
  if (sha256(baseBytes) !== BASE_SHA256 ||
      canonicalDigest(parsedBase) !== canonicalDigest(base) ||
      base.rule !== 's2-008-prereg-v11' ||
      base.preregistration_id !== 'xpr-s2-008c-11' ||
      base.preregistration_digest !== BASE_DIGEST ||
      base.preregistration_digest !== preregistrationDigest(base) ||
      base.status !== 'APPROVED' ||
      base.approval?.status !== 'APPROVED' ||
      base.approval?.authority !== 'HUMAN_OWNER' ||
      base.approval?.principal_id !== V12_OWNER ||
      base.approval?.in_force !== true ||
      !Number.isFinite(Date.parse(base.approval?.issued_at ?? '')) ||
      base.budget_reservation?.granted_units !== 5000000 ||
      base.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      base.budget_reservation?.expires_at !== '2026-10-05T00:00:00.000Z') {
    throw new Error('V12_BASE_BINDING_INVALID');
  }
  assertV12RestartReconciliation(base);
  if (sha256(supersessionBytes) !== BASE_SUPERSESSION_SHA256 ||
      canonicalDigest(parsedSupersession) !== canonicalDigest(supersession) ||
      supersession?.kind !== 'SUPERSESSION' ||
      supersession?.supersession_id !== BASE_SUPERSESSION_ID ||
      supersession?.supersession_digest !== BASE_SUPERSESSION_DIGEST ||
      supersession?.replaced_by_preregistration_digest !== BASE_DIGEST ||
      supersession?.expected_table_digest !== canonicalDigest(table)) {
    throw new Error('V12_BASE_SUPERSESSION_INVALID');
  }
  if (manifest.preregistration?.file !== BASE_FILE ||
      manifest.preregistration?.status !== 'IN_FORCE' ||
      manifest.preregistration?.preregistration_digest !== BASE_DIGEST ||
      manifest.supersession?.file !== BASE_SUPERSESSION_FILE ||
      manifest.supersession?.supersession_id !== BASE_SUPERSESSION_ID ||
      manifest.supersession?.supersession_digest !== BASE_SUPERSESSION_DIGEST ||
      manifest.supersession_history?.at(-1)?.file !== BASE_SUPERSESSION_FILE ||
      manifest.supersession_history?.at(-1)?.supersession_id !== BASE_SUPERSESSION_ID ||
      manifest.supersession_history?.at(-1)?.supersession_digest !== BASE_SUPERSESSION_DIGEST ||
      manifest.superseded_preregistration?.file !== 'preregistration-v10-superseded.json' ||
      manifest.superseded_preregistration?.superseded_by !== BASE_FILE ||
      manifest.frozen_table?.digest !== canonicalDigest(table) ||
      base.expected_table_digest !== canonicalDigest(table)) {
    throw new Error('V12_BASE_MANIFEST_INVALID');
  }
  return Object.freeze({
    baseDigest: BASE_DIGEST,
    baseSha256: BASE_SHA256,
    supersessionId: BASE_SUPERSESSION_ID,
    supersessionDigest: BASE_SUPERSESSION_DIGEST,
    supersessionSha256: BASE_SUPERSESSION_SHA256,
    tableDigest: canonicalDigest(table),
  });
}

export function inspectV11PriorExecutionEvidence({ repoRoot = ROOT } = {}) {
  const evidenceDir = path.resolve(repoRoot, 'evidence/s2-008-campaign');
  if (!fs.existsSync(evidenceDir) || !fs.statSync(evidenceDir).isDirectory()) {
    throw new Error('V12_PRIOR_SCAN_SCOPE_INVALID');
  }
  const names = fs.readdirSync(evidenceDir).filter((name) => CANDIDATE_FILE.test(name)).sort();
  const findings = [];
  const unrelated = [];
  for (const name of names) {
    const file = path.join(evidenceDir, name);
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      findings.push({ file: name, sha256: null, reason: 'UNSAFE_V11_NAMED_EVIDENCE_FILE' });
      continue;
    }
    const bytes = fs.readFileSync(file);
    let value;
    try {
      value = JSON.parse(bytes.toString('utf8'));
    } catch {
      findings.push({ file: name, sha256: sha256(bytes), reason: 'UNPARSEABLE_V11_NAMED_EVIDENCE' });
      continue;
    }
    const digests = [
      value?.preregistration_digest,
      value?.preregistration?.preregistration_digest,
      value?.campaign?.preregistration_digest,
      value?.base?.preregistration_digest,
    ].filter((entry) => typeof entry === 'string');
    if (digests.includes(BASE_DIGEST)) {
      findings.push({ file: name, sha256: sha256(bytes), reason: 'V11_PREREGISTRATION_BOUND_EVIDENCE' });
    } else if (digests.length > 0 && digests.every((entry) => entry !== BASE_DIGEST)) {
      unrelated.push({ file: name, sha256: sha256(bytes), reason: 'OTHER_PREREGISTRATION_DIGEST' });
    } else {
      findings.push({ file: name, sha256: sha256(bytes), reason: 'V11_NAMED_EVIDENCE_WITHOUT_BASE_BINDING' });
    }
  }
  return Object.freeze({
    kind: SCAN_KIND,
    status: findings.length ? 'RECONCILIATION_REQUIRED' : 'NOT_FOUND_IN_INSPECTED_SCOPE',
    inspected_scope: SCAN_SCOPE,
    base_preregistration_digest: BASE_DIGEST,
    candidate_count: names.length,
    findings: Object.freeze(findings),
    unrelated_candidates: Object.freeze(unrelated),
    provider_completeness_claimed: false,
  });
}

export function assertV12PriorExecutionEvidence(evidence, { repoRoot = ROOT } = {}) {
  const observed = inspectV11PriorExecutionEvidence({ repoRoot });
  if (!evidence || canonicalDigest(evidence) !== canonicalDigest(observed)) {
    throw new Error('V12_PRIOR_EVIDENCE_SCAN_MISMATCH');
  }
  if (observed.status !== 'NOT_FOUND_IN_INSPECTED_SCOPE' || observed.provider_completeness_claimed !== false) {
    throw new Error('V12_V11_EXECUTION_RECONCILIATION_REQUIRED');
  }
  return observed;
}

export function assertV12PresealPin({ pin, baseBytes, commitment = null }) {
  return assertVersionedPresealPin({
    pin,
    baseBytes,
    commitment,
    version: 12,
    requiredSources: [
      'pi_runtime_tree', 'timeout_policy', 'credential_env_policy',
      'pi_shrinkwrap', 'pi_package_manifest', 'pi_launcher',
    ],
  });
}

export function createV12Draft({
  base, baseBytes, manifest, supersession, supersessionBytes, table, pin,
  priorExecutionEvidence, repoRoot = ROOT,
}) {
  const lineage = assertV12BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table });
  const observedPrior = inspectV11PriorExecutionEvidence({ repoRoot });
  if (priorExecutionEvidence && canonicalDigest(priorExecutionEvidence) !== canonicalDigest(observedPrior)) {
    throw new Error('V12_PRIOR_EVIDENCE_SCAN_MISMATCH');
  }
  assertV12PriorExecutionEvidence(observedPrior, { repoRoot });
  if (!pin) throw new Error('V12_PRESEAL_PIN_REQUIRED');
  const { commitment, covers } = assertV12PresealPin({ pin, baseBytes });
  const measurement = base.budget_reservation?.usd_reference?.measurement;
  if (!measurement ||
      !['input', 'output', 'cacheRead', 'totalTokens'].every((key) => isCount(measurement[key])) ||
      measurement.totalTokens <= 0 || !/^[0-9a-f]{64}$/.test(measurement.traceSha256 ?? '')) {
    throw new Error('V12_MEASUREMENT_INVALID');
  }
  assertV6ModelTimeoutPolicy(base.executor?.model_launch_timeout);
  assertV8ExecutorPolicy(base.executor);
  const calls = base.holdout_access.case_count * base.seed_count;
  const projected = calls * measurement.totalTokens;
  if (!Number.isSafeInteger(projected) || projected > base.budget_reservation.granted_units) {
    throw new Error('V12_PROJECTION_EXCEEDS_CEILING');
  }

  const draft = {
    ...base,
    rule: 's2-008-prereg-v12',
    preregistration_id: 'xpr-s2-008c-12',
    executor: {
      ...base.executor,
      ...V8_EXECUTOR_POLICY,
      pi_settings: structuredClone(V7_PI_SETTINGS),
      model_image: {
        ...base.executor.model_image,
        content_commitment: commitment,
        covers,
        excludes: ['prereg'],
        built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v12.json',
        built_image_pin_reason: 'v12 binds a new independently built image while preserving the signed v11 provider, model, package, timeout, accounting, and frozen science controls',
      },
    },
    budget_reservation: {
      ...base.budget_reservation,
      reservation_id: 'rsv-s2-008c-12',
      expires_at: V12_EXPIRY,
      usd_reference: {
        ...base.budget_reservation.usd_reference,
        confirmed_usd: null,
        confirmed_usd_status: 'NOT_VERIFIED',
        why_null: 'No new provider invoice is asserted by the v12 draft.',
        measurement: structuredClone(measurement),
        measurement_basis: 'Inherited signed predecessor reference; it is not a v12 provider spend measurement.',
        projection: {
          calls,
          cases_per_seed: base.holdout_access.case_count,
          seeds: base.seed_count,
          tokens_per_call: measurement.totalTokens,
          tokens_estimate: projected,
          status: 'PROJECTION_NOT_MEASUREMENT',
          caveat: 'Actual provider usage is measured during execution; the unchanged 5,000,000-token ceiling applies independently to each A and B run.',
        },
        ceiling_scope: 'PER_RUN_A_OR_B',
        aggregate_spend: 'Report v12 A and B separately, and report reconciled v10 history separately; no v11 provider-completeness claim is made by this source scan.',
      },
    },
    accounting_protocol: {
      ...structuredClone(base.accounting_protocol),
      generation_id: 'one unique observed assistant responseId for each v12 model call',
    },
    failure_diagnostics_protocol: structuredClone(V11_FAILURE_DIAGNOSTICS_POLICY),
    v11_prior_execution_evidence: {
      scan: structuredClone(observedPrior),
      scan_digest: canonicalDigest(observedPrior),
      base_preregistration_digest: lineage.baseDigest,
    },
    supersession: {
      supersedes: base.preregistration_id,
      superseded_digest: base.preregistration_digest,
      scope: 'fresh v12 identity and expiry, and a new image commitment; frozen science, provider, model, package, retry policy, timeout and per-run ceiling remain unchanged',
      reason: 'v12 is a distinct successor to the signed v11 preregistration with a fresh reservation expiry and image pin; no provider history completeness is inferred from this checkout scan',
      unchanged: [...FROZEN_MEMBERS],
    },
    recorded_before_first_trial: {
      first_trial: 'NOT_STARTED',
      proof: 'The signed v11 bytes and active manifest pointer are bound. The checked-in v11 execution-evidence paths were not found in the explicitly recorded scope; this is not a provider-ledger completeness claim and is not a zero-spend assertion.',
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
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v12 records this digest and supersession in the corpus manifest',
    },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertPreregistration(draft);
  return draft;
}

export function approveV12({
  draft, base, baseBytes, manifest, supersession, supersessionBytes, table, pin,
  priorExecutionEvidence, repoRoot = ROOT, principal, label, issuedAt,
}) {
  if (principal !== V12_OWNER || typeof label !== 'string' || !label.trim() ||
      typeof issuedAt !== 'string' || !Number.isFinite(Date.parse(issuedAt)) ||
      Date.parse(issuedAt) >= Date.parse(V12_EXPIRY)) {
    throw new Error('V12_APPROVAL_IDENTITY_INVALID');
  }
  if (draft?.rule !== 's2-008-prereg-v12' || draft.preregistration_id !== 'xpr-s2-008c-12') {
    throw new Error('V12_VERSION_MISMATCH');
  }
  if (draft.status !== 'DRAFT' || draft.approval?.status !== null) throw new Error('V12_ALREADY_SIGNED');
  if (draft.preregistration_digest !== preregistrationDigest(draft)) throw new Error('V12_DIGEST_MISMATCH');
  const lineage = assertV12BaseBinding({ base, baseBytes, manifest, supersession, supersessionBytes, table });
  const prior = assertV12PriorExecutionEvidence(priorExecutionEvidence, { repoRoot });
  if (draft.v11_prior_execution_evidence?.scan_digest !== canonicalDigest(prior) ||
      draft.v11_prior_execution_evidence?.base_preregistration_digest !== lineage.baseDigest) {
    throw new Error('V12_PRIOR_EVIDENCE_BINDING_MISMATCH');
  }
  if (draft.expected_table_digest !== canonicalDigest(table)) throw new Error('V12_TABLE_MISMATCH');
  const drift = scopeDrift(base, draft);
  if (drift) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  assertV12PresealPin({ pin, baseBytes, commitment: draft.executor?.model_image?.content_commitment });
  const expected = createV12Draft({
    base, baseBytes, manifest, supersession, supersessionBytes, table, pin,
    priorExecutionEvidence: prior, repoRoot,
  });
  if (canonicalDigest(scientificBody(expected)) !== canonicalDigest(scientificBody(draft))) {
    throw new Error('V12_SCOPE_MISMATCH');
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
