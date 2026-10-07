import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { V7_PI_SETTINGS } from './s2-008-campaign-credential-env.mjs';
import { assertV14ModelTimeoutPolicy, createV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const V16_MODEL_POLICY = Object.freeze({
  provider: 'openrouter',
  provider_name: 'Poolside',
  model: 'poolside/laguna-s-2.1:free',
  catalog_slug: 'poolside/laguna-s-2.1-20260720',
  endpoint_slug: 'poolside/laguna-s-2.1-20260720:free',
  catalog_response_file: 'evidence/s2-008-campaign/provider-model-catalog-response-poolside-v16.json',
  catalog_response_sha256: 'ba5e4ddcf9aea4e6bf1b5a2706ae4f3898591fb19a1450667029c8f7beb841bf',
  catalog_response_bytes: 774407,
  credential_env_name: 'OPENROUTER_API_KEY',
  credential_source: 'EXPLICIT_PROCESS_ENV_ONLY',
  credential_fingerprint: '8f7ea446a8707bea',
  catalog_file: 'evidence/s2-008-campaign/provider-model-catalog-poolside-v16.json',
  catalog_sha256: '747cf8b27cbf0f386535c2121b5d17ef0fa032a0720408aa080e4586cad1c66d',
  endpoint_catalog_file: 'evidence/s2-008-campaign/provider-model-endpoints-poolside-v16.json',
  endpoint_catalog_sha256: '053599a4cc5be69b21fd58d7e00d4394c145b63f120725d09f1720fb309325ba',
  pi_model_registration: Object.freeze({
    id: 'poolside/laguna-s-2.1:free',
    name: 'Poolside: Laguna S 2.1 (free)',
    api: 'openai-completions',
    baseUrl: 'https://openrouter.ai/api/v1',
    input: Object.freeze(['text']),
    contextWindow: 262144,
    maxTokens: 32768,
    reasoning: true,
    compat: Object.freeze({
      openRouterRouting: Object.freeze({ only: Object.freeze(['Poolside']), allow_fallbacks: false }),
    }),
  }),
  min_start_interval_ms: 60000,
});
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
function catalogError() { throw new Error('V16_MODEL_CATALOG_ARTIFACT_INVALID'); }
export function assertV16ModelCatalogFiles(
  catalogFile = path.join(ROOT, V16_MODEL_POLICY.catalog_file),
  endpointFile = path.join(ROOT, V16_MODEL_POLICY.endpoint_catalog_file),
  responseFile = path.join(ROOT, V16_MODEL_POLICY.catalog_response_file),
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
    ? response.data.find((entry) => entry?.id === V16_MODEL_POLICY.model) : null;
  if (sha(catalogBytes) !== V16_MODEL_POLICY.catalog_sha256 ||
      sha(endpointBytes) !== V16_MODEL_POLICY.endpoint_catalog_sha256 ||
      sha(responseBytes) !== V16_MODEL_POLICY.catalog_response_sha256 ||
      responseBytes.length !== V16_MODEL_POLICY.catalog_response_bytes ||
      !rawDescriptor || canonicalDigest(rawDescriptor) !== canonicalDigest(catalog) ||
      catalog?.id !== V16_MODEL_POLICY.model ||
      catalog?.canonical_slug !== V16_MODEL_POLICY.catalog_slug ||
      catalog?.pricing?.prompt !== '0' || catalog?.pricing?.completion !== '0' ||
      catalog?.context_length !== 262144 || catalog?.top_provider?.max_completion_tokens !== 32768 ||
      catalog?.expiration_date !== '2026-10-31' ||
      endpoints?.data?.id !== V16_MODEL_POLICY.model ||
      !Array.isArray(endpoint) || endpoint.length !== 1 ||
      endpoint[0]?.name !== 'Poolside | ' + V16_MODEL_POLICY.endpoint_slug ||
      endpoint[0]?.model_id !== V16_MODEL_POLICY.model ||
      endpoint[0]?.provider_name !== V16_MODEL_POLICY.provider_name ||
      endpoint[0]?.pricing?.prompt !== '0' || endpoint[0]?.pricing?.completion !== '0' ||
      endpoint[0]?.context_length !== 262144 || endpoint[0]?.max_completion_tokens !== 32768) return catalogError();
  return true;
}
export function assertV16ExecutorPolicy(executor) {
  const binding = executor?.pi_model_catalog_binding;
  const expectedBinding = {
    file: V16_MODEL_POLICY.catalog_file,
    sha256: V16_MODEL_POLICY.catalog_sha256,
    endpoint_file: V16_MODEL_POLICY.endpoint_catalog_file,
    endpoint_sha256: V16_MODEL_POLICY.endpoint_catalog_sha256,
    response_file: V16_MODEL_POLICY.catalog_response_file,
    response_sha256: V16_MODEL_POLICY.catalog_response_sha256,
    canonical_slug: V16_MODEL_POLICY.catalog_slug,
    endpoint_slug: V16_MODEL_POLICY.endpoint_slug,
    prompt_price: '0',
    completion_price: '0',
    prompt_completion_pricing_source: 'PROVIDER_CATALOG_LISTING_ONLY',
    cache_pricing: 'NOT_PROVIDED',
    client_cost_authority: 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE',
  };
  if (executor?.provider !== V16_MODEL_POLICY.provider || executor?.model !== V16_MODEL_POLICY.model ||
      executor?.credential_env_name !== V16_MODEL_POLICY.credential_env_name ||
      executor?.credential_source !== V16_MODEL_POLICY.credential_source ||
      canonicalDigest(executor?.pi_settings ?? null) !== canonicalDigest(V7_PI_SETTINGS) ||
      canonicalDigest(executor?.pi_model_registration ?? null) !== canonicalDigest(V16_MODEL_POLICY.pi_model_registration) ||
      canonicalDigest(binding ?? null) !== canonicalDigest(expectedBinding) ||
      canonicalDigest(executor?.model_call_pacing ?? null) !== canonicalDigest({ min_start_interval_ms: 60000 }) ||
      canonicalDigest(executor?.model_launch_timeout ?? null) !== canonicalDigest(createV14ModelTimeoutPolicy())) {
    throw new Error('V16_MODEL_POLICY_INVALID');
  }
  assertV14ModelTimeoutPolicy(executor.model_launch_timeout);
  return Object.freeze({
    provider: V16_MODEL_POLICY.provider,
    model: V16_MODEL_POLICY.model,
    canonicalSlug: V16_MODEL_POLICY.catalog_slug,
    endpointSlug: V16_MODEL_POLICY.endpoint_slug,
    envName: V16_MODEL_POLICY.credential_env_name,
    credentialSource: V16_MODEL_POLICY.credential_source,
    minStartIntervalMs: V16_MODEL_POLICY.min_start_interval_ms,
    registration: V16_MODEL_POLICY.pi_model_registration,
    settings: V7_PI_SETTINGS,
    catalogSha256: V16_MODEL_POLICY.catalog_sha256,
  });
}
export function assertV16CredentialMetadata(executor, metadata, processEnv = undefined) {
  assertV16ExecutorPolicy(executor);
  if (metadata?.present !== true || metadata.fingerprint !== V16_MODEL_POLICY.credential_fingerprint) {
    throw new Error('V16_CREDENTIAL_METADATA_INVALID');
  }
  if (processEnv !== undefined) {
    const value = processEnv?.[V16_MODEL_POLICY.credential_env_name];
    if (typeof value !== 'string' || value.length < 8 ||
        sha(Buffer.from(value, 'utf8')).slice(0, 16) !== V16_MODEL_POLICY.credential_fingerprint) {
      throw new Error('V16_CREDENTIAL_ENV_FINGERPRINT_MISMATCH');
    }
  }
  return Object.freeze({ present: true, fingerprint: V16_MODEL_POLICY.credential_fingerprint,
    envName: V16_MODEL_POLICY.credential_env_name });
}
export function assertV16PreregistrationPolicy(prereg) {
  if (prereg?.rule !== 's2-008-prereg-v16' || prereg.preregistration_id !== 'xpr-s2-008c-16' ||
      prereg.budget_reservation?.currency !== 'tokens' || prereg.budget_reservation?.granted_units !== 5000000 ||
      prereg.budget_reservation?.ceiling_scope !== 'PER_RUN_A_OR_B' ||
      prereg.budget_reservation?.expires_at !== '2026-10-12T00:00:00.000Z') throw new Error('V16_BUDGET_POLICY_INVALID');
  assertV16ExecutorPolicy(prereg.executor);
  return true;
}
export function createV16PiModelsFile(executor) {
  assertV16ExecutorPolicy(executor);
  return Object.freeze({
    providers: Object.freeze({
      openrouter: Object.freeze({
        baseUrl: V16_MODEL_POLICY.pi_model_registration.baseUrl,
        api: V16_MODEL_POLICY.pi_model_registration.api,
        apiKey: '$OPENROUTER_API_KEY',
        models: Object.freeze([structuredClone(V16_MODEL_POLICY.pi_model_registration)]),
      }),
    }),
  });
}
