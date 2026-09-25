// SLOQUAL-001 measurement statistics (Veritas-local SLO qualification).
// Node stdlib only. Every function fails closed: a non-finite, negative or
// empty sample set throws instead of degrading to 0, 100% or an empty
// interval. An unmeasured SLI must surface as a structural failure upstream,
// never as a satisfied threshold.
//
// Percentiles are nearest-rank over the sorted sample vector, the CI is a
// seeded percentile bootstrap, and proportions use the Wilson score
// interval. The bootstrap seed is part of the frozen contract, so the same
// raw samples always produce the same interval bytes.
export const STATISTICS_RULE = 'sloqual-statistics-v1';

function invalid(reason, detail) {
  const error = new TypeError(`SLOQUAL_STATISTICS_INVALID: ${reason}${detail === undefined ? '' : `: ${detail}`}`);
  error.code = 'SLOQUAL_STATISTICS_INVALID';
  return error;
}

// Deterministic PRNG (mulberry32): the same integer seed yields the same
// stream on every host and Node version, so bootstrap intervals reproduce.
export function seededRandom(seed) {
  if (!Number.isInteger(seed) || seed < 0) throw invalid('seed must be a non-negative integer', String(seed));
  let state = seed >>> 0;
  return function next() {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function assertSampleVector(samples, label = 'samples') {
  if (!Array.isArray(samples) || samples.length === 0) throw invalid(`${label} must be a non-empty array`, typeof samples);
  for (let index = 0; index < samples.length; index += 1) {
    const value = samples[index];
    if (typeof value !== 'number' || !Number.isFinite(value)) throw invalid(`${label}[${index}] is not a finite number`, String(value));
    if (value < 0) throw invalid(`${label}[${index}] is negative`, String(value));
  }
  return samples;
}

export function sortedSamples(samples, label = 'samples') {
  return [...assertSampleVector(samples, label)].sort((a, b) => a - b);
}

// Nearest-rank percentile: the smallest value at or above ceil(p * n) rank.
export function nearestRankPercentile(samples, p, label = 'samples') {
  if (typeof p !== 'number' || !Number.isFinite(p) || p <= 0 || p > 1) throw invalid('percentile must be in (0, 1]', String(p));
  const sorted = sortedSamples(samples, label);
  const rank = Math.max(1, Math.ceil(p * sorted.length));
  return sorted[rank - 1];
}

export function mean(samples, label = 'samples') {
  const vector = assertSampleVector(samples, label);
  return vector.reduce((sum, value) => sum + value, 0) / vector.length;
}

export function max(samples, label = 'samples') {
  return sortedSamples(samples, label).at(-1);
}

// Seeded percentile bootstrap over the sample vector. Returns the point
// estimate, the percentile interval and the exact parameters used, so the
// evidence record can be re-derived from the raw samples.
export function percentileBootstrapInterval({
  samples,
  p,
  resamples = 2000,
  confidence = 0.95,
  seed,
  label = 'samples',
} = {}) {
  assertSampleVector(samples, label);
  if (typeof p !== 'number' || !Number.isFinite(p) || p <= 0 || p > 1) throw invalid('percentile must be in (0, 1]', String(p));
  if (!Number.isInteger(resamples) || resamples < 1) throw invalid('resamples must be a positive integer', String(resamples));
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence <= 0 || confidence >= 1) {
    throw invalid('confidence must be in (0, 1)', String(confidence));
  }
  const sorted = sortedSamples(samples, label);
  const n = sorted.length;
  const point = nearestRankPercentile(sorted, p, label);
  if (n === 1) {
    return {
      pointEstimate: point,
      lower: point,
      upper: point,
      method: 'percentile_bootstrap',
      resamples: 0,
      confidence,
      seed,
      samples: n,
      note: 'single-sample vector: interval degenerates to the observation and carries no power',
    };
  }
  const random = seededRandom(seed);
  const statistics = new Array(resamples);
  const resampled = new Array(n);
  for (let b = 0; b < resamples; b += 1) {
    for (let i = 0; i < n; i += 1) {
      resampled[i] = sorted[Math.floor(random() * n)];
    }
    statistics[b] = nearestRankPercentile(resampled, p, 'bootstrap-resample');
  }
  statistics.sort((a, b) => a - b);
  const alpha = (1 - confidence) / 2;
  return {
    pointEstimate: point,
    lower: nearestRankPercentile(statistics, alpha, 'bootstrap-statistics'),
    upper: nearestRankPercentile(statistics, 1 - alpha, 'bootstrap-statistics'),
    method: 'percentile_bootstrap',
    resamples,
    confidence,
    seed,
    samples: n,
  };
}

export function wilsonInterval({ successes, trials, confidence = 0.95 } = {}) {
  if (!Number.isInteger(trials) || trials < 1) throw invalid('trials must be a positive integer', String(trials));
  if (!Number.isInteger(successes) || successes < 0 || successes > trials) throw invalid('successes must be an integer in [0, trials]', String(successes));
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence <= 0 || confidence >= 1) {
    throw invalid('confidence must be in (0, 1)', String(confidence));
  }
  // Normal quantile for the two-sided confidence level, computed from the
  // inverse error function (no dependency, deterministic, stdlib only).
  const z = normalQuantile(1 - (1 - confidence) / 2);
  const p = successes / trials;
  const z2 = z * z;
  const denominator = 1 + z2 / trials;
  const center = (p + z2 / (2 * trials)) / denominator;
  const margin = (z / denominator) * Math.sqrt((p * (1 - p)) / trials + z2 / (4 * trials * trials));
  return {
    pointEstimate: p,
    // Exact endpoints when no event (or every event) was observed: floating
    // point must not turn a zero lower bound into 3.5e-18.
    lower: successes === 0 ? 0 : Math.max(0, center - margin),
    upper: successes === trials ? 1 : Math.min(1, center + margin),
    method: 'wilson_score',
    confidence,
    successes,
    trials,
  };
}

// Abramowitz & Stegun 26.2.17 rational approximation of the standard
// normal CDF, inverted by bisection on the CDF (deterministic, 200 steps).
function normalQuantile(target) {
  let low = -12;
  let high = 12;
  for (let i = 0; i < 200; i += 1) {
    const mid = (low + high) / 2;
    if (standardNormalCdf(mid) < target) low = mid;
    else high = mid;
  }
  return (low + high) / 2;
}

function standardNormalCdf(x) {
  const t = 1 / (1 + 0.2316419 * Math.abs(x));
  const d = 0.3989422804014327 * Math.exp(-0.5 * x * x);
  const probability = 1 - d * t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));
  return x >= 0 ? probability : 1 - probability;
}
