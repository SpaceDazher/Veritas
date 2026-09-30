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

export function credentialEnvNameForPreregistration(prereg) {
  if (prereg?.rule === 's2-008-prereg-v7') return assertV7ExecutorPolicy(prereg.executor).envName;
  if (['s2-008-prereg-v4', 's2-008-prereg-v5', 's2-008-prereg-v6'].includes(prereg?.rule)) return 'ZAI_API_KEY';
  throw new Error('MODEL_CREDENTIAL_ENV_POLICY_UNSUPPORTED');
}

export function createV7PiSettingsFile(settings = V7_PI_SETTINGS) {
  if (canonicalDigest(settings) !== canonicalDigest(V7_PI_SETTINGS)) throw new Error('V7_PI_SETTINGS_POLICY_INVALID');
  const { config_dir_env: _configDirEnv, ...piSettings } = settings;
  return Object.freeze({ ...piSettings });
}
