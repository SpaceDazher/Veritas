import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import {
  V17_MODEL_POLICY,
  assertV17CredentialMetadata,
  assertV17ExecutorPolicy,
  assertV17ModelCatalogFiles,
  assertV17PreregistrationPolicy,
  createV17PiModelsFile,
} from './s2-008-campaign-v17-policy.mjs';

export const V18_MODEL_POLICY = Object.freeze({
  ...V17_MODEL_POLICY,
  rule: 's2-008-prereg-v18',
  preregistration_id: 'xpr-s2-008c-18',
  expires_at: '2026-11-07T00:00:00.000Z',
  predecessor_version: 17,
});

const V18_RECOVERY_EVIDENCE_DIGEST = '294c052165ddd34aa80fcfc32fefbbb68d04e2c9e92ec194b688b92a12528beb';
const V18_PRIOR_RUN_ID = 's2-008c-v17-a-3bfe162cc5774fa38a3a';
const V18_PRIOR_PREREGISTRATION_DIGEST = '8a2df9a2c37751098a28706bddf71dcff5b58656886baabceff2712b2798742f';
const V18_PRIOR_RUN_SHA256 = '2aa18416cdb8cd42c5800d872c6c7b95c42ef5694b1955e117a8a559fe7aa31c';
const V18_PRIOR_CLOSURE_SHA256 = 'cafc6ad2c55f55dc6271ba4a2b38bd37738fd81d6cd98ca7df598078a79b3b08';
const V18_PRIOR_ACCOUNTING_SHA256 = '44bbfa20ca6dcb02004be3ed9f4b1b486bde3620d2ffdfb4b401382c021a0c58';
const V18_PRIOR_RECONCILIATION_DIGEST = 'd52c2aada88fc5e75ba0958a20732e3fd17eb583b58cad98d37507dfd301b7ce';
const V18_OWNER_STATEMENT = 'Да, отдельный новый A по новому протоколу';

export function assertV18ModelCatalogFiles(catalogFile, endpointFile, responseFile) {
  try {
    return assertV17ModelCatalogFiles(catalogFile, endpointFile, responseFile);
  } catch {
    throw new Error('V18_MODEL_CATALOG_ARTIFACT_INVALID');
  }
}

export function assertV18ExecutorPolicy(executor) {
  try {
    const policy = assertV17ExecutorPolicy(executor);
    if (executor?.provider !== V18_MODEL_POLICY.provider ||
        executor?.model !== V18_MODEL_POLICY.model ||
        executor?.credential_env_name !== V18_MODEL_POLICY.credential_env_name ||
        executor?.credential_source !== V18_MODEL_POLICY.credential_source ||
        executor?.model_call_pacing?.min_start_interval_ms !== V18_MODEL_POLICY.min_start_interval_ms ||
        canonicalDigest(executor?.pi_model_registration ?? null) !== canonicalDigest(V18_MODEL_POLICY.pi_model_registration)) {
      throw new Error('V18_MODEL_POLICY_INVALID');
    }
    return Object.freeze({ ...policy, predecessorVersion: 17 });
  } catch {
    throw new Error('V18_MODEL_POLICY_INVALID');
  }
}

export function assertV18CredentialMetadata(executor, metadata, processEnv = undefined) {
  try {
    assertV18ExecutorPolicy(executor);
    const result = assertV17CredentialMetadata(executor, metadata, processEnv);
    return Object.freeze({ ...result, version: 18 });
  } catch (error) {
    if (String(error?.message).includes('FINGERPRINT_MISMATCH')) {
      throw new Error('V18_CREDENTIAL_ENV_FINGERPRINT_MISMATCH');
    }
    throw new Error('V18_CREDENTIAL_METADATA_INVALID');
  }
}

export function assertV18PreregistrationPolicy(prereg) {
  if (prereg?.rule !== V18_MODEL_POLICY.rule ||
      prereg?.preregistration_id !== V18_MODEL_POLICY.preregistration_id ||
      prereg?.budget_reservation?.currency !== 'tokens' ||
      prereg?.budget_reservation?.granted_units !== 5000000 ||
      prereg?.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      prereg?.budget_reservation?.expires_at !== V18_MODEL_POLICY.expires_at) {
    throw new Error('V18_BUDGET_POLICY_INVALID');
  }
  assertV18ExecutorPolicy(prereg.executor);
  return true;
}

export function assertV18RecoveryAuthorizationPolicy(prereg) {
  const authorization = prereg?.recovery_authorization;
  const predecessor = prereg?.v17_prior_execution_reconciliation;
  const approval = prereg?.approval;
  const artifacts = predecessor?.immutable_artifacts;
  const artifact = (suffix) => Array.isArray(artifacts)
    ? artifacts.find((row) => row?.file === 'evidence/s2-008-campaign/v17-a-stopped/' + suffix) : null;
  const run = artifact('run-v17-a.json');
  const closure = artifact('request-outcome-reconciliation.json');
  const accounting = artifact('partial-accounting.json');
  const issuedAt = approval?.issued_at;
  const expectedScope = {
    protocol_version: 18, maximum_new_a_runs: 1, maximum_new_b_runs: 1,
    maximum_total_new_runs: 2, b_condition: 'A_FULLY_MEASURED_AND_RECEIPTS_RECONCILED',
    same_run_retry_permitted: false, on_infra: 'RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO',
    automatic_next_version_permitted: false,
  };
  if (prereg?.rule !== V18_MODEL_POLICY.rule || prereg.preregistration_id !== V18_MODEL_POLICY.preregistration_id ||
      approval?.status !== 'APPROVED' || approval.authority !== 'HUMAN_OWNER' ||
      approval.principal_id !== 'prn-s2007r-owner' || approval.label !== 'Daniil' || approval.in_force !== true ||
      approval.signed_digest_over !== 'the scientific body: every member except approval, status and preregistration_digest' ||
      typeof issuedAt !== 'string' || !Number.isFinite(Date.parse(issuedAt)) || Date.parse(issuedAt) >= Date.parse(V18_MODEL_POLICY.expires_at) ||
      !authorization || Object.keys(authorization).sort().join(',') !== 'authorization_basis,authorization_scope,authorization_status,kind,owner_approval,predecessor' ||
      authorization.kind !== 's2-008-v18-authorized-recovery/1' ||
      authorization.authorization_status !== 'OWNER_APPROVAL_BINDS_TO_SIGNED_PREREGISTRATION' ||
      canonicalDigest(authorization.authorization_basis ?? null) !== canonicalDigest({
        source: 'EXPLICIT_HUMAN_OWNER_APPROVAL', statement: V18_OWNER_STATEMENT,
      }) || canonicalDigest(authorization.authorization_scope ?? null) !== canonicalDigest(expectedScope) ||
      canonicalDigest(authorization.owner_approval ?? null) !== canonicalDigest({ authority: 'HUMAN_OWNER',
        principal_id: 'prn-s2007r-owner', label: 'Daniil', issued_at: issuedAt, in_force: true }) ||
      canonicalDigest(predecessor ?? null) !== canonicalDigest(authorization.predecessor ?? null) ||
      canonicalDigest(predecessor ?? null) !== V18_PRIOR_RECONCILIATION_DIGEST ||
      predecessor?.kind !== 's2-008-v18-predecessor-outcome-binding/1' ||
      predecessor.prior_raw_run_id !== V18_PRIOR_RUN_ID ||
      predecessor.prior_preregistration_digest !== V18_PRIOR_PREREGISTRATION_DIGEST ||
      predecessor.prior_raw_run_sha256 !== V18_PRIOR_RUN_SHA256 ||
      predecessor.prior_closure_sha256 !== V18_PRIOR_CLOSURE_SHA256 ||
      predecessor.prior_partial_accounting_sha256 !== V18_PRIOR_ACCOUNTING_SHA256 ||
      predecessor.disposition !== 'RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO' || predecessor.prior_outcome !== 'INFRA' ||
      predecessor.known_model_calls !== 10 || predecessor.known_tokens_lower_bound !== 11677 ||
      predecessor.known_provider_usd_lower_bound !== 0 || predecessor.classified_unknown_attempts !== 1 ||
      predecessor.unclassified_attempts !== 0 || predecessor.failed_generation_id !== null ||
      predecessor.failed_request_tokens_confirmed !== null || predecessor.failed_request_usd_confirmed !== null ||
      predecessor.total_tokens_confirmed !== null || predecessor.total_usd_confirmed !== null ||
      predecessor.financial_reconciliation_complete !== false || predecessor.raw_unreconciled_spend_preserved !== true ||
      predecessor.retry_performed !== false || predecessor.account_wide_completeness_claimed !== false ||
      predecessor.owner_completeness_attestation?.complete !== true ||
      predecessor.owner_completeness_attestation?.unfiltered !== true ||
      predecessor.owner_completeness_attestation?.includes_errors_and_cancellations !== true ||
      predecessor.owner_completeness_attestation?.confirmed_by !== 'Daniil' ||
      artifacts?.length !== 16 || canonicalDigest(artifacts) !== V18_RECOVERY_EVIDENCE_DIGEST ||
      run?.bytes !== 23781 || run?.sha256 !== V18_PRIOR_RUN_SHA256 ||
      closure?.bytes !== 1912 || closure?.sha256 !== V18_PRIOR_CLOSURE_SHA256 ||
      accounting?.bytes !== 4904 || accounting?.sha256 !== V18_PRIOR_ACCOUNTING_SHA256) {
    throw new Error('V18_RECOVERY_AUTHORIZATION_INVALID');
  }
  return true;
}

export function createV18PiModelsFile(executor) {
  assertV18ExecutorPolicy(executor);
  return createV17PiModelsFile(executor);
}

export { assertV17PreregistrationPolicy };
