import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';

export const V7_CREDENTIAL_ENV_NAME = 'ZAI_CODING_CN_API_KEY';
export const V7_PI_SETTINGS = Object.freeze({
  config_dir_env: 'PI_CODING_AGENT_DIR',
  retry: Object.freeze({ enabled: false, maxRetries: 0, provider: Object.freeze({ maxRetries: 0 }) }),
  cacheWarming: 'off',
  compaction: Object.freeze({ enabled: false }),
});

export function assertV7ExecutorPolicy(executor) {
  if (executor?.provider !== 'zai-coding-cn' ||
      executor?.credential_env_name !== V7_CREDENTIAL_ENV_NAME ||
      canonicalDigest(executor?.pi_settings ?? null) !== canonicalDigest(V7_PI_SETTINGS)) {
    throw new Error('V7_CREDENTIAL_ENV_OR_RETRY_POLICY_INVALID');
  }
  return Object.freeze({ envName: V7_CREDENTIAL_ENV_NAME, settings: V7_PI_SETTINGS });
}

/**
 * v8 runs the executor on the same model this session uses, measured through the
 * provider's own OpenAI-compatible endpoint.
 *
 * Two facts about that measurement are part of the policy and not a footnote:
 *
 *   * the raw `cost.total` pi reports for this provider is `0`, which is an
 *     observation of the client, not a price. The confirmed USD cost is therefore
 *     `null` / NOT_VERIFIED, and a `0` must never be carried into a signed
 *     document as a measured reference — MISSING IS NOT ZERO is the rule this
 *     repository applies to every other unit, and USD is a unit;
 *   * the measurement was taken with tools enabled, while the container runs with
 *     them off. The container figure is therefore expected to be LOWER, and the
 *     plan is recomputed from a container measurement or not at all.
 */
export const V8_CREDENTIAL_ENV_NAME = 'OPENROUTER_API_KEY';
export const V8_EXECUTOR_POLICY = Object.freeze({
  provider: 'openrouter',
  model: 'stealth/space-bunny-alpha',
  credential_env_name: V8_CREDENTIAL_ENV_NAME,
});

export const V13_MODEL_POLICY = Object.freeze({
  provider: 'openrouter',
  model: 'inclusionai/ling-3.1-flash',
  credential_env_name: 'OPENROUTER_API_KEY',
  catalog_sha256: '5f8d6f77af15a6af97bcd06229a146e10a524f76f2d06878b941e586e3c765a6',
  catalog_slug: 'inclusionai/ling-3.1-flash-20261002',
  pi_model_registration: Object.freeze({
    id: 'inclusionai/ling-3.1-flash',
    name: 'inclusionAI: Ling 3.1 Flash',
    api: 'openai-completions',
    baseUrl: 'https://openrouter.ai/api/v1',
    input: Object.freeze(['text']),
    contextWindow: 262144,
    maxTokens: 32768,
    reasoning: true,
  }),
});

export const V14_MODEL_POLICY = Object.freeze({
  ...V13_MODEL_POLICY,
  credential_source: 'EXPLICIT_PROCESS_ENV_ONLY',
  min_start_interval_ms: 60000,
});

export function assertV14ExecutorPolicy(executor) {
  const base = assertV13ExecutorPolicy(executor);
  if (executor?.credential_source !== V14_MODEL_POLICY.credential_source ||
      canonicalDigest(executor?.model_call_pacing ?? null) !== canonicalDigest({ min_start_interval_ms: V14_MODEL_POLICY.min_start_interval_ms })) {
    throw new Error('V14_MODEL_PACING_OR_CREDENTIAL_POLICY_INVALID');
  }
  return Object.freeze({ ...base, credentialSource: V14_MODEL_POLICY.credential_source, minStartIntervalMs: V14_MODEL_POLICY.min_start_interval_ms });
}

export function assertV13ExecutorPolicy(executor) {
  const binding = executor?.pi_model_catalog_binding;
  if (executor?.provider !== V13_MODEL_POLICY.provider ||
      executor?.model !== V13_MODEL_POLICY.model ||
      executor?.credential_env_name !== V13_MODEL_POLICY.credential_env_name ||
      canonicalDigest(executor?.pi_settings ?? null) !== canonicalDigest(V7_PI_SETTINGS) ||
      canonicalDigest(executor?.pi_model_registration ?? null) !== canonicalDigest(V13_MODEL_POLICY.pi_model_registration) ||
      binding?.file !== 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json' ||
      binding?.sha256 !== V13_MODEL_POLICY.catalog_sha256 ||
      binding?.canonical_slug !== V13_MODEL_POLICY.catalog_slug ||
      binding?.prompt_completion_pricing_source !== 'PROVIDER_CATALOG_LISTING_ONLY' ||
      binding?.cache_pricing !== 'NOT_PROVIDED' ||
      binding?.client_cost_authority !== 'ESTIMATE_ONLY_PROVIDER_RECEIPT_AUTHORITATIVE') {
    throw new Error('V13_MODEL_POLICY_INVALID');
  }
  return Object.freeze({
    envName: V13_MODEL_POLICY.credential_env_name,
    provider: V13_MODEL_POLICY.provider,
    model: V13_MODEL_POLICY.model,
    registration: V13_MODEL_POLICY.pi_model_registration,
    catalogSha256: V13_MODEL_POLICY.catalog_sha256,
    settings: V7_PI_SETTINGS,
  });
}

export function createV13PiModelsFile(executor) {
  const policy = assertV13ExecutorPolicy(executor);
  return Object.freeze({
    providers: Object.freeze({
      [policy.provider]: Object.freeze({
        baseUrl: policy.registration.baseUrl,
        api: policy.registration.api,
        apiKey: '$OPENROUTER_API_KEY',
        models: Object.freeze([structuredClone(policy.registration)]),
      }),
    }),
  });
}

export function assertV8ExecutorPolicy(executor) {
  if (executor?.provider !== V8_EXECUTOR_POLICY.provider ||
      executor?.model !== V8_EXECUTOR_POLICY.model ||
      executor?.credential_env_name !== V8_EXECUTOR_POLICY.credential_env_name ||
      canonicalDigest(executor?.pi_settings ?? null) !== canonicalDigest(V7_PI_SETTINGS)) {
    throw new Error('V8_CREDENTIAL_ENV_OR_RETRY_POLICY_INVALID');
  }
  return Object.freeze({ envName: V8_CREDENTIAL_ENV_NAME, provider: V8_EXECUTOR_POLICY.provider, settings: V7_PI_SETTINGS });
}

/**
 * Every env name the policy has ever declared for a provider.
 *
 * The name is a property of the SIGNED RULE, not of the provider alone: v4-v6
 * bind ZAI_API_KEY and v7 binds ZAI_CODING_CN_API_KEY for the same provider, and
 * both documents are or were in force. So the pairing check has to accept every
 * name this provider was ever signed with, or it refuses a running campaign on
 * the strength of a rule it never read.
 */
const ENV_NAMES_BY_PROVIDER = Object.freeze({
  'zai-coding-cn': Object.freeze(['ZAI_API_KEY', V7_CREDENTIAL_ENV_NAME]),
  openrouter: Object.freeze([V8_CREDENTIAL_ENV_NAME]),
});

export function credentialEnvNamesForProvider(provider) {
  const names = ENV_NAMES_BY_PROVIDER[provider];
  if (names === undefined) throw new Error(`MODEL_CREDENTIAL_ENV_POLICY_UNSUPPORTED:${String(provider)}`);
  return names;
}

export function credentialEnvNameForPreregistration(prereg) {
  if (prereg?.rule === 's2-008-prereg-v14') return assertV14ExecutorPolicy(prereg.executor).envName;
  if (prereg?.rule === 's2-008-prereg-v13') return assertV13ExecutorPolicy(prereg.executor).envName;
  if (['s2-008-prereg-v8','s2-008-prereg-v9','s2-008-prereg-v10','s2-008-prereg-v11','s2-008-prereg-v12'].includes(prereg?.rule)) return assertV8ExecutorPolicy(prereg.executor).envName;
  if (prereg?.rule === 's2-008-prereg-v7') return assertV7ExecutorPolicy(prereg.executor).envName;
  if (['s2-008-prereg-v4', 's2-008-prereg-v5', 's2-008-prereg-v6'].includes(prereg?.rule)) return 'ZAI_API_KEY';
  throw new Error('MODEL_CREDENTIAL_ENV_POLICY_UNSUPPORTED');
}

export function createV7PiSettingsFile(settings = V7_PI_SETTINGS) {
  if (canonicalDigest(settings) !== canonicalDigest(V7_PI_SETTINGS)) throw new Error('V7_PI_SETTINGS_POLICY_INVALID');
  const { config_dir_env: _configDirEnv, ...piSettings } = settings;
  return Object.freeze({ ...piSettings });
}
