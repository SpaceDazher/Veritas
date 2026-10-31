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

export function createV18PiModelsFile(executor) {
  assertV18ExecutorPolicy(executor);
  return createV17PiModelsFile(executor);
}

export { assertV17PreregistrationPolicy };
