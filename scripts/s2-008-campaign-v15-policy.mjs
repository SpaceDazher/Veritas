import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { V7_PI_SETTINGS } from './s2-008-campaign-credential-env.mjs';
import { assertV14ModelTimeoutPolicy, createV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const V15_MODEL_POLICY = Object.freeze({
  provider: 'openrouter',
  provider_name: 'Google AI Studio',
  model: 'google/gemma-4-31b-it:free',
  catalog_slug: 'google/gemma-4-31b-it-20260402:free',
  credential_env_name: 'OPENROUTER_API_KEY',
  credential_source: 'EXPLICIT_PROCESS_ENV_ONLY',
  credential_fingerprint: '8f7ea446a8707bea',
  catalog_file: 'evidence/s2-008-campaign/provider-model-catalog-gemma-v15.json',
  catalog_sha256: '5f854e52fcddb2aac4cc7094e67df5ffeb06995595008cab89bed268936be651',
  endpoint_catalog_file: 'evidence/s2-008-campaign/provider-model-endpoints-gemma-v15.json',
  endpoint_catalog_sha256: '830836f5dd4474b652a9f7d50ea44b24544d1b78261f07e0552a5f757f127bd8',
  pi_model_registration: Object.freeze({
    id: 'google/gemma-4-31b-it:free',
    name: 'Google: Gemma 4 31B IT (free)',
    api: 'openai-completions',
    baseUrl: 'https://openrouter.ai/api/v1',
    input: Object.freeze(['text']),
    contextWindow: 262144,
    maxTokens: 32768,
    reasoning: true,
  }),
  min_start_interval_ms: 60000,
});
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
function catalogError() { throw new Error('V15_MODEL_CATALOG_ARTIFACT_INVALID'); }
export function assertV15ModelCatalogFiles(
  catalogFile = path.join(ROOT, V15_MODEL_POLICY.catalog_file),
  endpointFile = path.join(ROOT, V15_MODEL_POLICY.endpoint_catalog_file),
) {
  let catalogBytes, endpointBytes, catalog, endpoints;
  try {
    catalogBytes = fs.readFileSync(catalogFile);
    endpointBytes = fs.readFileSync(endpointFile);
    catalog = JSON.parse(catalogBytes.toString('utf8'));
    endpoints = JSON.parse(endpointBytes.toString('utf8'));
  } catch { return catalogError(); }
  const endpoint = endpoints?.data?.endpoints;
  if (sha(catalogBytes) !== V15_MODEL_POLICY.catalog_sha256 ||
      sha(endpointBytes) !== V15_MODEL_POLICY.endpoint_catalog_sha256 ||
      catalog?.id !== V15_MODEL_POLICY.model ||
      catalog?.pricing?.prompt !== '0' || catalog?.pricing?.completion !== '0' ||
      endpoints?.data?.id !== V15_MODEL_POLICY.model ||
      !Array.isArray(endpoint) || endpoint.length !== 1 ||
      endpoint[0]?.name !== 'Google AI Studio | google/gemma-4-31b-it-20260402:free' ||
      endpoint[0]?.pricing?.prompt !== '0' || endpoint[0]?.pricing?.completion !== '0' ||
      endpoint[0]?.context_length !== 262144 || endpoint[0]?.max_completion_tokens !== 32768) return catalogError();
  return true;
}
export function assertV15ExecutorPolicy(executor) {
  const binding = executor?.pi_model_catalog_binding;
  const expectedBinding = {
    file: V15_MODEL_POLICY.catalog_file,
    sha256: V15_MODEL_POLICY.catalog_sha256,
    endpoint_file: V15_MODEL_POLICY.endpoint_catalog_file,
    endpoint_sha256: V15_MODEL_POLICY.endpoint_catalog_sha256,
    canonical_slug: V15_MODEL_POLICY.catalog_slug,
    prompt_price: '0',
    completion_price: '0',
    prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY',
    cache_pricing: 'NOT_PROVIDED',
    client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE',
  };
  if (executor?.provider !== V15_MODEL_POLICY.provider || executor?.model !== V15_MODEL_POLICY.model ||
      executor?.credential_env_name !== V15_MODEL_POLICY.credential_env_name ||
      executor?.credential_source !== V15_MODEL_POLICY.credential_source ||
      canonicalDigest(executor?.pi_settings ?? null) !== canonicalDigest(V7_PI_SETTINGS) ||
      canonicalDigest(executor?.pi_model_registration ?? null) !== canonicalDigest(V15_MODEL_POLICY.pi_model_registration) ||
      canonicalDigest(binding ?? null) !== canonicalDigest(expectedBinding) ||
      canonicalDigest(executor?.model_call_pacing ?? null) !== canonicalDigest({ min_start_interval_ms: 60000 }) ||
      canonicalDigest(executor?.model_launch_timeout ?? null) !== canonicalDigest(createV14ModelTimeoutPolicy())) {
    throw new Error('V15_MODEL_POLICY_INVALID');
  }
  assertV14ModelTimeoutPolicy(executor.model_launch_timeout);
  return Object.freeze({
    provider: V15_MODEL_POLICY.provider,
    model: V15_MODEL_POLICY.model,
    canonicalSlug: V15_MODEL_POLICY.catalog_slug,
    envName: V15_MODEL_POLICY.credential_env_name,
    credentialSource: V15_MODEL_POLICY.credential_source,
    minStartIntervalMs: V15_MODEL_POLICY.min_start_interval_ms,
    registration: V15_MODEL_POLICY.pi_model_registration,
    settings: V7_PI_SETTINGS,
    catalogSha256: V15_MODEL_POLICY.catalog_sha256,
  });
}
export function assertV15CredentialMetadata(executor, metadata, processEnv = undefined) {
  assertV15ExecutorPolicy(executor);
  if (metadata?.present !== true || metadata.fingerprint !== V15_MODEL_POLICY.credential_fingerprint) {
    throw new Error('V15_CREDENTIAL_METADATA_INVALID');
  }
  if (processEnv !== undefined) {
    const value = processEnv?.[V15_MODEL_POLICY.credential_env_name];
    if (typeof value !== 'string' || value.length < 8 ||
        sha(Buffer.from(value, 'utf8')).slice(0, 16) !== V15_MODEL_POLICY.credential_fingerprint) {
      throw new Error('V15_CREDENTIAL_ENV_FINGERPRINT_MISMATCH');
    }
  }
  return Object.freeze({ present: true, fingerprint: V15_MODEL_POLICY.credential_fingerprint,
    envName: V15_MODEL_POLICY.credential_env_name });
}
export function assertV15PreregistrationPolicy(prereg) {
  if (prereg?.rule !== 's2-008-prereg-v15' || prereg.preregistration_id !== 'xpr-s2-008c-15' ||
      prereg.budget_reservation?.currency !== 'tokens' || prereg.budget_reservation?.granted_units !== 5000000 ||
      prereg.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      prereg.budget_reservation?.expires_at !== '2026-10-12T00:00:00.000Z') throw new Error('V15_BUDGET_POLICY_INVALID');
  assertV15ExecutorPolicy(prereg.executor);
  return true;
}
export function createV15PiModelsFile(executor) {
  assertV15ExecutorPolicy(executor);
  return Object.freeze({
    providers: Object.freeze({
      openrouter: Object.freeze({
        baseUrl: V15_MODEL_POLICY.pi_model_registration.baseUrl,
        api: V15_MODEL_POLICY.pi_model_registration.api,
        apiKey: '$OPENROUTER_API_KEY',
        models: Object.freeze([structuredClone(V15_MODEL_POLICY.pi_model_registration)]),
      }),
    }),
  });
}
