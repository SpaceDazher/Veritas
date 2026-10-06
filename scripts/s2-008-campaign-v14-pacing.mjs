import { performance } from 'node:perf_hooks';

export const V14_MIN_START_INTERVAL_MS = 60000;
export const V14_TIMEOUT_POLICY = Object.freeze({
  holdout_case_count: 126,
  per_model_call_timeout_ms: 180000,
  min_start_interval_ms: V14_MIN_START_INTERVAL_MS,
  bridge_report_margin_ms: 300000,
  total_container_timeout_ms: 30540000,
  formula: 'holdout_case_count * (per_model_call_timeout_ms + min_start_interval_ms) + bridge_report_margin_ms',
  scope: 'ONE_MODEL_CONTAINER_PER_SEED',
  pi_argv_flags: Object.freeze(['--no-tools', '--no-extensions', '--no-skills']),
});

export function assertV14MinStartInterval(value) {
  if (!Number.isSafeInteger(value) || value !== V14_MIN_START_INTERVAL_MS) {
    throw new Error('V14_MIN_START_INTERVAL_INVALID');
  }
  return value;
}

export function createV14ModelTimeoutPolicy() {
  return structuredClone(V14_TIMEOUT_POLICY);
}

export function assertV14ModelTimeoutPolicy(policy) {
  const expected = V14_TIMEOUT_POLICY;
  if (policy === null || typeof policy !== 'object' ||
      Object.keys(policy).sort().join(',') !== Object.keys(expected).sort().join(',') ||
      Object.keys(expected).some((key) => Array.isArray(expected[key])
        ? JSON.stringify(policy[key]) !== JSON.stringify(expected[key])
        : policy[key] !== expected[key])) {
    throw new Error('V14_MODEL_TIMEOUT_POLICY_INVALID');
  }
  return policy;
}

export function createV14StartPacer({
  minStartIntervalMs = V14_MIN_START_INTERVAL_MS,
  now = () => performance.now(),
  sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms),
  sleepAsync = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  const interval = assertV14MinStartInterval(minStartIntervalMs);
  let lastStart = null;
  let failed = false;
  let callsStarted = 0;
  let waitCount = 0;
  let waitedMs = 0;

  const readClock = () => {
    const value = now();
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      throw new Error('V14_MONOTONIC_CLOCK_INVALID');
    }
    return value;
  };
  const check = (shouldContinue) => {
    if (failed) throw new Error('V14_PACING_STOPPED_AFTER_FAILURE');
    if (typeof shouldContinue !== 'function' || shouldContinue() !== true) {
      return false;
    }
    return true;
  };

  function runSync(operation, { enabled = true, shouldContinue = () => true } = {}) {
    if (typeof operation !== 'function') throw new Error('V14_PACING_OPERATION_INVALID');
    if (enabled === false) return Object.freeze({ proceeded: true, called: false });
    if (enabled !== true) throw new Error('V14_PACING_ENABLED_INVALID');
    if (!check(shouldContinue)) return Object.freeze({ proceeded: false, called: false });

    if (lastStart !== null) {
      const deadline = lastStart + interval;
      while (readClock() < deadline) {
        if (!check(shouldContinue)) return Object.freeze({ proceeded: false, called: false });
        const before = readClock();
        const remaining = deadline - before;
        sleep(remaining);
        waitCount += 1;
        waitedMs += remaining;
        const after = readClock();
        if (after <= before) throw new Error('V14_PACING_CLOCK_DID_NOT_ADVANCE');
      }
    }
    if (!check(shouldContinue)) return Object.freeze({ proceeded: false, called: false });
    lastStart = readClock();
    callsStarted += 1;
    try {
      return Object.freeze({ proceeded: true, called: true, value: operation(), startedAt: lastStart });
    } catch (error) {
      failed = true;
      throw error;
    }
  }

  async function run(operation, { enabled = true, shouldContinue = () => true } = {}) {
    if (typeof operation !== 'function') throw new Error('V14_PACING_OPERATION_INVALID');
    if (enabled === false) return Object.freeze({ proceeded: true, called: false });
    if (enabled !== true) throw new Error('V14_PACING_ENABLED_INVALID');
    if (!check(shouldContinue)) return Object.freeze({ proceeded: false, called: false });

    if (lastStart !== null) {
      const deadline = lastStart + interval;
      while (readClock() < deadline) {
        if (!check(shouldContinue)) return Object.freeze({ proceeded: false, called: false });
        const before = readClock();
        const remaining = deadline - before;
        await sleepAsync(remaining);
        waitCount += 1;
        waitedMs += remaining;
        const after = readClock();
        if (after <= before) throw new Error('V14_PACING_CLOCK_DID_NOT_ADVANCE');
      }
    }
    if (!check(shouldContinue)) return Object.freeze({ proceeded: false, called: false });
    lastStart = readClock();
    try {
      return Object.freeze({ proceeded: true, called: true, value: await operation(), startedAt: lastStart });
    } catch (error) {
      failed = true;
      throw error;
    }
  }

  return Object.freeze({
    runSync,
    run,
    snapshot: () => Object.freeze({ minStartIntervalMs: interval, lastStart, callsStarted, waitCount, waitedMs, failed }),
  });
}

export function createV14ContainerPacer({
  minStartIntervalMs = V14_MIN_START_INTERVAL_MS,
  now = () => performance.now(),
  sleepAsync = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  const interval = assertV14MinStartInterval(minStartIntervalMs);
  let lastCompletion = null;
  let failed = false;
  let containerStarts = 0;
  let waitCount = 0;
  let waitedMs = 0;
  const readClock = () => {
    const value = now();
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new Error('V14_MONOTONIC_CLOCK_INVALID');
    return value;
  };
  const canContinue = (shouldContinue) => {
    if (failed) throw new Error('V14_PACING_STOPPED_AFTER_FAILURE');
    return typeof shouldContinue === 'function' && shouldContinue() === true;
  };
  async function run(operation, { enabled = true, shouldContinue = () => true } = {}) {
    if (typeof operation !== 'function') throw new Error('V14_PACING_OPERATION_INVALID');
    if (enabled === false) return Object.freeze({ proceeded: true, called: false });
    if (enabled !== true) throw new Error('V14_PACING_ENABLED_INVALID');
    if (!canContinue(shouldContinue)) return Object.freeze({ proceeded: false, called: false });
    if (lastCompletion !== null) {
      const deadline = lastCompletion + interval;
      while (readClock() < deadline) {
        if (!canContinue(shouldContinue)) return Object.freeze({ proceeded: false, called: false });
        const before = readClock();
        const delay = deadline - before;
        await sleepAsync(delay);
        waitCount += 1;
        waitedMs += delay;
        if (readClock() <= before) throw new Error('V14_PACING_CLOCK_DID_NOT_ADVANCE');
      }
    }
    if (!canContinue(shouldContinue)) return Object.freeze({ proceeded: false, called: false });
    const startedAt = readClock();
    containerStarts += 1;
    try {
      const value = await operation();
      lastCompletion = readClock();
      return Object.freeze({ proceeded: true, called: true, value, startedAt, completedAt: lastCompletion });
    } catch (error) {
      failed = true;
      throw error;
    }
  }
  return Object.freeze({ run, snapshot: () => Object.freeze({ minStartIntervalMs: interval, lastCompletion, containerStarts, waitCount, waitedMs, failed }) });
}
