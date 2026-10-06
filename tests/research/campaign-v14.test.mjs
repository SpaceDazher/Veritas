import test from 'node:test';
import assert from 'node:assert/strict';

const pacing = await import('../../scripts/s2-008-campaign-v14-policy.mjs').catch(() => ({}));

test('v14 pacing waits at least 60 seconds after a completed call before the next starts', () => {
  assert.equal(typeof pacing.createV14StartPacer, 'function');
  let now = 100;
  const sleeps = [];
  const starts = [];
  const pacer = pacing.createV14StartPacer({
    minStartIntervalMs: 60000,
    now: () => now,
    sleep: (ms) => { sleeps.push(ms); now += ms; },
  });
  pacer.runSync(() => { starts.push(now); now += 3; });
  pacer.runSync(() => { starts.push(now); now += 2; });
  assert.deepEqual(starts, [100, 60100]);
  assert.deepEqual(sleeps, [59997]);
});

test('v14 pacing rejects non-integer intervals and avoids waiting after a stop or in dry run', () => {
  assert.equal(pacing.assertV14MinStartInterval(60000), 60000);
  for (const value of [0, -1, 60000.5, Infinity, '60000', null]) {
    assert.throws(() => pacing.assertV14MinStartInterval(value));
  }
  let now = 0, calls = 0, allowed = false;
  const sleeps = [];
  const pacer = pacing.createV14StartPacer({ minStartIntervalMs: 60000,
    now: () => now, sleep: (ms) => { sleeps.push(ms); now += ms; } });
  assert.equal(pacer.runSync(() => { calls += 1; }, { shouldContinue: () => allowed }).proceeded, false);
  assert.deepEqual(sleeps, []);
  assert.equal(pacer.runSync(() => { calls += 1; }, { enabled: false }).proceeded, true);
  assert.equal(calls, 1);
  assert.deepEqual(sleeps, []);
});
