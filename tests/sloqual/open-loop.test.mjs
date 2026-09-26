// SLOQUAL-001 open-loop arrival model. The regression under test is
// coordinated omission: when the system under test is slow, the offered
// load must NOT shrink. Every request keeps its planned arrival instant, so
// queueing shows up as latency and lateness instead of disappearing.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildArrivalSchedule, dispatchAt, nowNs } from '../../src/lib/sloqual/open-loop.mjs';

const sleep = (ms) => {
  const waiter = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(waiter, 0, 0, ms);
};

describe('SLOQUAL-001 open-loop schedule', () => {
  test('offsets are planned up front, non-decreasing and reproducible from the seed', () => {
    const a = buildArrivalSchedule({mode: 'open_loop', requests: 50, ratePerSecond: 500, seed: 11});
    const b = buildArrivalSchedule({mode: 'open_loop', requests: 50, ratePerSecond: 500, seed: 11});
    const other = buildArrivalSchedule({mode: 'open_loop', requests: 50, ratePerSecond: 500, seed: 12});
    assert.deepEqual(a.offsetsMs, b.offsetsMs);
    assert.notDeepEqual(a.offsetsMs, other.offsetsMs);
    assert.equal(a.offsetsMs.length, 50);
    for (let index = 1; index < a.offsetsMs.length; index += 1) {
      assert.ok(a.offsetsMs[index] >= a.offsetsMs[index - 1], `offset ${index} went backwards`);
    }
    assert.ok(a.offsetsMs[0] >= 0);
  });

  test('the mean inter-arrival time tracks the declared rate', () => {
    const schedule = buildArrivalSchedule({mode: 'open_loop', requests: 2000, ratePerSecond: 1000, seed: 11});
    const span = schedule.offsetsMs.at(-1) / (schedule.requests - 1);
    assert.ok(Math.abs(span - 1) < 0.25, `mean spacing ${span} ms should be near 1 ms at 1000 rps`);
  });

  test('a burst packs its requests into the declared window and then returns to open-loop arrivals', () => {
    const schedule = buildArrivalSchedule({mode: 'burst', requests: 100, ratePerSecond: 600, burstSize: 40, burstWindowMs: 20, seed: 11});
    assert.equal(schedule.offsetsMs[0], 0);
    assert.ok(schedule.offsetsMs[39] <= 20, `burst tail ${schedule.offsetsMs[39]} ms must stay inside the window`);
    assert.ok(schedule.offsetsMs[40] > 20, 'post-burst arrivals resume the open-loop schedule');
    assert.ok(schedule.offsetsMs[99] > schedule.offsetsMs[39]);
  });

  test('closed-loop mode plans every request immediately (security family)', () => {
    const schedule = buildArrivalSchedule({mode: 'closed_loop', requests: 5});
    assert.deepEqual(schedule.offsetsMs, [0, 0, 0, 0, 0]);
  });

  test('invalid arrival parameters are rejected instead of silently defaulted', () => {
    assert.throws(() => buildArrivalSchedule({mode: 'open_loop', requests: 0, ratePerSecond: 100, seed: 1}), /SLOQUAL_ARRIVAL_INVALID/);
    assert.throws(() => buildArrivalSchedule({mode: 'open_loop', requests: 5, ratePerSecond: 0, seed: 1}), /SLOQUAL_ARRIVAL_INVALID/);
    assert.throws(() => buildArrivalSchedule({mode: 'open_loop', requests: 5, ratePerSecond: 100, seed: -1}), /SLOQUAL_ARRIVAL_INVALID/);
    assert.throws(() => buildArrivalSchedule({mode: 'teleport', requests: 5, ratePerSecond: 100, seed: 1}), /SLOQUAL_ARRIVAL_INVALID/);
  });
});

describe('SLOQUAL-001 open-loop dispatch accounting', () => {
  test('a fast dispatch measures latency from the planned instant, not from its own start', () => {
    const epoch = nowNs();
    sleep(5);
    const dispatch = dispatchAt(0, epoch, () => 'ok');
    assert.equal(dispatch.result, 'ok');
    assert.ok(dispatch.latenessMs >= 4, `lateness ${dispatch.latenessMs} ms should reflect the missed start`);
    assert.ok(dispatch.latencyMs >= dispatch.latenessMs);
    assert.ok(dispatch.serviceMs < dispatch.latencyMs);
  });

  test('coordinated-omission regression: a slow service inflates later latencies instead of reducing the offered load', () => {
    const epoch = nowNs();
    const schedule = buildArrivalSchedule({mode: 'open_loop', requests: 6, ratePerSecond: 1000, seed: 11});
    const latencies = [];
    let slow = false;
    for (let index = 0; index < schedule.requests; index += 1) {
      const dispatch = dispatchAt(schedule.offsetsMs[index], epoch, () => {
        if (!slow) {
          slow = true;
          sleep(60); // one 60 ms stall, as a saturated host would produce
        }
        return 'ok';
      });
      latencies.push(dispatch.latencyMs);
    }
    // All six requests keep their planned instant, so the stall is charged to
    // the requests that followed it instead of being absorbed by a slower
    // arrival rate.
    assert.ok(latencies[0] >= 59, `first request latency ${latencies[0]} ms`);
    for (let index = 1; index < latencies.length; index += 1) {
      assert.ok(latencies[index] >= 50, `request ${index} latency ${latencies[index]} ms should still carry the stall`);
    }
  });
});
