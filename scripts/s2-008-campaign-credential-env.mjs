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
  if (['s2-008-prereg-v8','s2-008-prereg-v9','s2-008-prereg-v10'].includes(prereg?.rule)) return assertV8ExecutorPolicy(prereg.executor).envName;
  if (prereg?.rule === 's2-008-prereg-v7') return assertV7ExecutorPolicy(prereg.executor).envName;
  if (['s2-008-prereg-v4', 's2-008-prereg-v5', 's2-008-prereg-v6'].includes(prereg?.rule)) return 'ZAI_API_KEY';
  throw new Error('MODEL_CREDENTIAL_ENV_POLICY_UNSUPPORTED');
}

export function createV7PiSettingsFile(settings = V7_PI_SETTINGS) {
  if (canonicalDigest(settings) !== canonicalDigest(V7_PI_SETTINGS)) throw new Error('V7_PI_SETTINGS_POLICY_INVALID');
  const { config_dir_env: _configDirEnv, ...piSettings } = settings;
  return Object.freeze({ ...piSettings });
}
