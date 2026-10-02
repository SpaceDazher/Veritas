export const V6_MODEL_TIMEOUT_CONSTANTS = Object.freeze({
  perModelCallTimeoutMs: 180_000,
  holdoutCaseCount: 126,
  bridgeReportMarginMs: 300_000,
  totalContainerTimeoutFormula: 'holdout_case_count * per_model_call_timeout_ms + bridge_report_margin_ms',
  totalContainerTimeoutScope: 'ONE_MODEL_CONTAINER_PER_SEED',
  piArgvFlags: Object.freeze(['--no-tools', '--no-extensions', '--no-skills']),
});

export function createV6ModelTimeoutPolicy() {
  const constants = V6_MODEL_TIMEOUT_CONSTANTS;
  return Object.freeze({
    per_model_call_timeout_ms: constants.perModelCallTimeoutMs,
    holdout_case_count: constants.holdoutCaseCount,
    bridge_report_margin_ms: constants.bridgeReportMarginMs,
    total_container_timeout_ms:
      constants.holdoutCaseCount * constants.perModelCallTimeoutMs + constants.bridgeReportMarginMs,
    total_container_timeout_formula: constants.totalContainerTimeoutFormula,
    total_container_timeout_scope: constants.totalContainerTimeoutScope,
    pi_argv_flags: [...constants.piArgvFlags],
  });
}

export function assertV6ModelTimeoutPolicy(policy) {
  const expected = createV6ModelTimeoutPolicy();
  const keys = Object.keys(expected).sort();
  if (typeof policy !== 'object' || policy === null || Array.isArray(policy) ||
      Object.keys(policy).sort().join(',') !== keys.join(',') ||
      !Number.isSafeInteger(policy.per_model_call_timeout_ms) ||
      !Number.isSafeInteger(policy.holdout_case_count) ||
      !Number.isSafeInteger(policy.bridge_report_margin_ms) ||
      !Number.isSafeInteger(policy.total_container_timeout_ms) ||
      policy.per_model_call_timeout_ms !== expected.per_model_call_timeout_ms ||
      policy.holdout_case_count !== expected.holdout_case_count ||
      policy.bridge_report_margin_ms !== expected.bridge_report_margin_ms ||
      policy.total_container_timeout_ms !== expected.total_container_timeout_ms ||
      policy.total_container_timeout_ms !==
        policy.holdout_case_count * policy.per_model_call_timeout_ms + policy.bridge_report_margin_ms ||
      policy.total_container_timeout_formula !== expected.total_container_timeout_formula ||
      policy.total_container_timeout_scope !== expected.total_container_timeout_scope ||
      !Array.isArray(policy.pi_argv_flags) ||
      JSON.stringify(policy.pi_argv_flags) !== JSON.stringify(expected.pi_argv_flags)) {
    throw new Error('V6_MODEL_TIMEOUT_POLICY_INVALID');
  }
  return policy;
}

export function modelContainerTimeoutFromPreregistration(prereg) {
  if (prereg?.rule !== 's2-008-prereg-v6') throw new Error('V6_MODEL_TIMEOUT_POLICY_INVALID');
  return assertV6ModelTimeoutPolicy(prereg.executor?.model_launch_timeout).total_container_timeout_ms;
}
