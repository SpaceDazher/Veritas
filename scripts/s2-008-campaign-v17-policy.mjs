import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { V7_PI_SETTINGS } from './s2-008-campaign-credential-env.mjs';
import { assertV14ModelTimeoutPolicy, createV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const V17_MODEL_POLICY = Object.freeze({
  provider: 'openrouter',
  provider_name: 'Nvidia',
  model: 'nvidia/nemotron-3.5-lightning:free',
  catalog_slug: 'nvidia/nemotron-3.5-lightning-20260807',
  endpoint_slug: 'nvidia/nemotron-3.5-lightning-20260807:free',
  catalog_response_file: 'evidence/s2-008-campaign/provider-model-catalog-response-nvidia-v17.json',
  catalog_response_sha256: '9ebec09cfd65e64fb1c57b67cc96ea19558008134a6c12b018681c5d21e18710',
  catalog_response_bytes: 810217,
  credential_env_name: 'OPENROUTER_API_KEY',
  credential_source: 'EXPLICIT_PROCESS_ENV_ONLY',
  credential_fingerprint: '8f7ea446a8707bea',
  catalog_file: 'evidence/s2-008-campaign/provider-model-catalog-nvidia-v17.json',
  catalog_sha256: '86169d2099cc8385856bcd780b50d4269486608b4db130eaf7620535685e19f5',
  endpoint_catalog_file: 'evidence/s2-008-campaign/provider-model-endpoints-nvidia-v17.json',
  endpoint_catalog_sha256: '149341e3c6ae97478f640368f7877f7212469791ad84c0d18d831d29373eaf6c',
  pi_model_registration: Object.freeze({
    id: 'nvidia/nemotron-3.5-lightning:free',
    name: "NVIDIA: Nemotron 3.5 Lightning (free)",
    api: 'openai-completions',
    baseUrl: 'https://openrouter.ai/api/v1',
    input: Object.freeze(['text']),
    contextWindow: 1000000,
    maxTokens: 65536,
    reasoning: true,
    compat: Object.freeze({
      openRouterRouting: Object.freeze({ only: Object.freeze(['Nvidia']), allow_fallbacks: false }),
    }),
  }),
  min_start_interval_ms: 60000,
});
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
function catalogError() { throw new Error('V17_MODEL_CATALOG_ARTIFACT_INVALID'); }
export function assertV17ModelCatalogFiles(
  catalogFile = path.join(ROOT, V17_MODEL_POLICY.catalog_file),
  endpointFile = path.join(ROOT, V17_MODEL_POLICY.endpoint_catalog_file),
  responseFile = path.join(ROOT, V17_MODEL_POLICY.catalog_response_file),
) {
  let catalogBytes, endpointBytes, responseBytes, catalog, endpoints, response;
  try {
    catalogBytes = fs.readFileSync(catalogFile);
    endpointBytes = fs.readFileSync(endpointFile);
    responseBytes = fs.readFileSync(responseFile);
    catalog = JSON.parse(catalogBytes.toString('utf8'));
    endpoints = JSON.parse(endpointBytes.toString('utf8'));
    response = JSON.parse(responseBytes.toString('utf8'));
  } catch { return catalogError(); }
  const endpoint = endpoints?.data?.endpoints;
  const rawDescriptor = Array.isArray(response?.data)
    ? response.data.find((entry) => entry?.id === V17_MODEL_POLICY.model) : null;
  if (sha(catalogBytes) !== V17_MODEL_POLICY.catalog_sha256 ||
      sha(endpointBytes) !== V17_MODEL_POLICY.endpoint_catalog_sha256 ||
      sha(responseBytes) !== V17_MODEL_POLICY.catalog_response_sha256 ||
      responseBytes.length !== V17_MODEL_POLICY.catalog_response_bytes ||
      !rawDescriptor || canonicalDigest(rawDescriptor) !== canonicalDigest(catalog) ||
      catalog?.id !== V17_MODEL_POLICY.model ||
      catalog?.canonical_slug !== V17_MODEL_POLICY.catalog_slug ||
      catalog?.pricing?.prompt !== '0' || catalog?.pricing?.completion !== '0' ||
      catalog?.context_length !== 1000000 || catalog?.top_provider?.max_completion_tokens !== 65536 ||
      catalog?.expiration_date !== null ||
      endpoints?.data?.id !== V17_MODEL_POLICY.model ||
      !Array.isArray(endpoint) || endpoint.length !== 1 ||
      endpoint[0]?.name !== 'Nvidia | ' + V17_MODEL_POLICY.endpoint_slug ||
      endpoint[0]?.model_id !== V17_MODEL_POLICY.model ||
      endpoint[0]?.provider_name !== V17_MODEL_POLICY.provider_name ||
      endpoint[0]?.pricing?.prompt !== '0' || endpoint[0]?.pricing?.completion !== '0' ||
      endpoint[0]?.context_length !== 1000000 || endpoint[0]?.max_completion_tokens !== 65536) return catalogError();
  return true;
}
export function assertV17ExecutorPolicy(executor) {
  const binding = executor?.pi_model_catalog_binding;
  const expectedBinding = {
    file: V17_MODEL_POLICY.catalog_file,
    sha256: V17_MODEL_POLICY.catalog_sha256,
    endpoint_file: V17_MODEL_POLICY.endpoint_catalog_file,
    endpoint_sha256: V17_MODEL_POLICY.endpoint_catalog_sha256,
    response_file: V17_MODEL_POLICY.catalog_response_file,
    response_sha256: V17_MODEL_POLICY.catalog_response_sha256,
    canonical_slug: V17_MODEL_POLICY.catalog_slug,
    endpoint_slug: V17_MODEL_POLICY.endpoint_slug,
    prompt_price: '0',
    completion_price: '0',
    prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY',
    cache_pricing: 'NOT_PROVIDED',
    client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE',
  };
  if (executor?.provider !== V17_MODEL_POLICY.provider || executor?.model !== V17_MODEL_POLICY.model ||
      executor?.credential_env_name !== V17_MODEL_POLICY.credential_env_name ||
      executor?.credential_source !== V17_MODEL_POLICY.credential_source ||
      canonicalDigest(executor?.pi_settings ?? null) !== canonicalDigest(V7_PI_SETTINGS) ||
      canonicalDigest(executor?.pi_model_registration ?? null) !== canonicalDigest(V17_MODEL_POLICY.pi_model_registration) ||
      canonicalDigest(binding ?? null) !== canonicalDigest(expectedBinding) ||
      canonicalDigest(executor?.model_call_pacing ?? null) !== canonicalDigest({ min_start_interval_ms: 60000 }) ||
      canonicalDigest(executor?.model_launch_timeout ?? null) !== canonicalDigest(createV14ModelTimeoutPolicy())) {
    throw new Error('V17_MODEL_POLICY_INVALID');
  }
  assertV14ModelTimeoutPolicy(executor.model_launch_timeout);
  return Object.freeze({
    provider: V17_MODEL_POLICY.provider,
    model: V17_MODEL_POLICY.model,
    canonicalSlug: V17_MODEL_POLICY.catalog_slug,
    endpointSlug: V17_MODEL_POLICY.endpoint_slug,
    envName: V17_MODEL_POLICY.credential_env_name,
    credentialSource: V17_MODEL_POLICY.credential_source,
    minStartIntervalMs: V17_MODEL_POLICY.min_start_interval_ms,
    registration: V17_MODEL_POLICY.pi_model_registration,
    settings: V7_PI_SETTINGS,
    catalogSha256: V17_MODEL_POLICY.catalog_sha256,
  });
}
export function assertV17CredentialMetadata(executor, metadata, processEnv = undefined) {
  assertV17ExecutorPolicy(executor);
  if (metadata?.present !== true || metadata.fingerprint !== V17_MODEL_POLICY.credential_fingerprint) {
    throw new Error('V17_CREDENTIAL_METADATA_INVALID');
  }
  if (processEnv !== undefined) {
    const value = processEnv?.[V17_MODEL_POLICY.credential_env_name];
    if (typeof value !== 'string' || value.length < 8 ||
        sha(Buffer.from(value, 'utf8')).slice(0, 16) !== V17_MODEL_POLICY.credential_fingerprint) {
      throw new Error('V17_CREDENTIAL_ENV_FINGERPRINT_MISMATCH');
    }
  }
  return Object.freeze({ present: true, fingerprint: V17_MODEL_POLICY.credential_fingerprint,
    envName: V17_MODEL_POLICY.credential_env_name });
}
export function assertV17PreregistrationPolicy(prereg) {
  if (prereg?.rule !== 's2-008-prereg-v17' || prereg.preregistration_id !== 'xpr-s2-008c-17' ||
      prereg.budget_reservation?.currency !== 'tokens' || prereg.budget_reservation?.granted_units !== 5000000 ||
      prereg.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      prereg.budget_reservation?.expires_at !== '2026-11-07T00:00:00.000Z') throw new Error('V17_BUDGET_POLICY_INVALID');
  assertV17ExecutorPolicy(prereg.executor);
  return true;
}
export function createV17PiModelsFile(executor) {
  assertV17ExecutorPolicy(executor);
  return Object.freeze({
    providers: Object.freeze({
      openrouter: Object.freeze({
        baseUrl: V17_MODEL_POLICY.pi_model_registration.baseUrl,
        api: V17_MODEL_POLICY.pi_model_registration.api,
        apiKey: '$OPENROUTER_API_KEY',
        models: Object.freeze([structuredClone(V17_MODEL_POLICY.pi_model_registration)]),
      }),
    }),
  });
}
