// SLOQUAL-001 statistics: nearest-rank percentiles, seeded percentile
// bootstrap, Wilson interval and the fail-closed guards that keep an
// unmeasured SLI from degrading into a satisfied threshold.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  assertSampleVector,
  mean,
  nearestRankPercentile,
  percentileBootstrapInterval,
  seededRandom,
  sortedSamples,
  wilsonInterval,
} from '../../src/lib/sloqual/statistics.mjs';

describe('SLOQUAL-001 statistics: fail-closed sample guards', () => {
  test('empty, missing, non-finite and negative sample vectors are rejected', () => {
    assert.throws(() => assertSampleVector([]), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => assertSampleVector('0.1,0.2'), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => assertSampleVector([1, Number.NaN]), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => assertSampleVector([1, Number.POSITIVE_INFINITY]), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => assertSampleVector([-0.001]), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => nearestRankPercentile([], 0.95), /SLOQUAL_STATISTICS_INVALID/);
  });

  test('percentiles outside (0, 1] are rejected', () => {
    assert.throws(() => nearestRankPercentile([1, 2], 0), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => nearestRankPercentile([1, 2], 1.5), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => nearestRankPercentile([1, 2], Number.NaN), /SLOQUAL_STATISTICS_INVALID/);
  });

  test('sortedSamples and mean do not mutate their input', () => {
    const samples = [3, 1, 2];
    assert.deepEqual(sortedSamples(samples), [1, 2, 3]);
    assert.deepEqual(samples, [3, 1, 2]);
    assert.equal(mean(samples), 2);
  });
});

describe('SLOQUAL-001 statistics: nearest-rank percentiles', () => {
  const samples = [5, 1, 4, 2, 3];

  test('nearest rank selects ceil(p * n) over the sorted vector', () => {
    assert.equal(nearestRankPercentile(samples, 0.5), 3);
    assert.equal(nearestRankPercentile(samples, 0.95), 5);
    assert.equal(nearestRankPercentile(samples, 0.99), 5);
    assert.equal(nearestRankPercentile(samples, 1), 5);
  });

  test('a single observation is its own percentile', () => {
    assert.equal(nearestRankPercentile([7.5], 0.95), 7.5);
    assert.equal(nearestRankPercentile([7.5], 0.5), 7.5);
  });
});

describe('SLOQUAL-001 statistics: seeded percentile bootstrap', () => {
  const samples = Array.from({length: 200}, (_, index) => (index % 20) + 0.5);

  test('the interval contains the point estimate and is reproducible from the seed', () => {
    const a = percentileBootstrapInterval({samples, p: 0.95, resamples: 500, confidence: 0.95, seed: 20260925});
    const b = percentileBootstrapInterval({samples, p: 0.95, resamples: 500, confidence: 0.95, seed: 20260925});
    assert.deepEqual(a, b, 'same samples and seed must reproduce the interval byte-for-byte');
    assert.ok(a.lower <= a.pointEstimate, `${a.lower} <= ${a.pointEstimate}`);
    assert.ok(a.pointEstimate <= a.upper, `${a.pointEstimate} <= ${a.upper}`);
    assert.equal(a.method, 'percentile_bootstrap');
    assert.equal(a.samples, 200);
  });

  test('a different seed can move the interval but never breaks containment', () => {
    const other = percentileBootstrapInterval({samples, p: 0.95, resamples: 500, confidence: 0.95, seed: 7});
    assert.ok(other.lower <= other.pointEstimate && other.pointEstimate <= other.upper);
  });

  test('a single-sample interval degenerates and declares that it carries no power', () => {
    const single = percentileBootstrapInterval({samples: [3.2], p: 0.95, resamples: 200, confidence: 0.95, seed: 1});
    assert.equal(single.resamples, 0);
    assert.equal(single.lower, 3.2);
    assert.equal(single.upper, 3.2);
    assert.match(single.note, /no power/);
  });

  test('invalid statistics parameters are rejected instead of defaulted', () => {
    assert.throws(() => percentileBootstrapInterval({samples, p: 0.95, resamples: 0, confidence: 0.95, seed: 1}), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => percentileBootstrapInterval({samples, p: 0.95, resamples: 10, confidence: 1, seed: 1}), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => percentileBootstrapInterval({samples, p: 0.95, resamples: 10, confidence: 0.95}), /SLOQUAL_STATISTICS_INVALID/);
  });
});

describe('SLOQUAL-001 statistics: Wilson proportion interval', () => {
  test('zero events still produce a finite, non-degenerate upper bound', () => {
    const interval = wilsonInterval({successes: 0, trials: 105, confidence: 0.95});
    assert.equal(interval.pointEstimate, 0);
    assert.equal(interval.lower, 0);
    assert.ok(interval.upper > 0 && interval.upper < 0.05, `upper=${interval.upper}`);
  });

  test('proportions and counts are validated', () => {
    assert.throws(() => wilsonInterval({successes: 0, trials: 0}), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => wilsonInterval({successes: 5, trials: 4}), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => wilsonInterval({successes: 1.5, trials: 4}), /SLOQUAL_STATISTICS_INVALID/);
  });
});

describe('SLOQUAL-001 statistics: seeded PRNG', () => {
  test('the stream is deterministic and seed-dependent', () => {
    const first = Array.from({length: 5}, seededRandom(42));
    const second = Array.from({length: 5}, seededRandom(42));
    const other = Array.from({length: 5}, seededRandom(43));
    assert.deepEqual(first, second);
    assert.notDeepEqual(first, other);
    assert.ok(first.every((value) => value >= 0 && value < 1));
  });

  test('invalid seeds are rejected', () => {
    assert.throws(() => seededRandom(-1), /SLOQUAL_STATISTICS_INVALID/);
    assert.throws(() => seededRandom(1.5), /SLOQUAL_STATISTICS_INVALID/);
  });
});
