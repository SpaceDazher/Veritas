// S2-002 — survivor-verdict transport policy.
//
// SpaceDazher/Veritas#16 recorded the identity suite red twice and the sandbox
// suite red once under clean-checkout load, with no recoverable failing
// subtest. The mechanism these tests pin is the one that produced those runs:
// the Windows liveness query shells out to PowerShell/CIM, a query that never
// answers was read as "every candidate is still alive", and the settle loop
// was bounded by an iteration count whose cost grew with host load.
//
// The policy is asserted here, on every platform, with injected clocks and
// injected queries — the live Windows probes only run on a Windows host, and
// a policy that can only be exercised there is a policy that stays broken.
// Every case below is a property of the production helper, not of a stub
// re-implementation: the helpers ARE the policy.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  awaitTree,
  descendantsIn,
  parseProcessTable,
  queryUntilAnswered,
  settleUntilGone,
  DESCENDANT_DEPTH,
  QUERY_MAX_ATTEMPTS,
  QUERY_MIN_ATTEMPTS,
  SETTLE_MAX_STEPS,
} from '../../src/lib/identity/process-verdict.mjs';

// A clock that only advances when the test says so, so budget behaviour is
// asserted in simulated milliseconds instead of wall-clock seconds.
function fakeClock(start = 0) {
  let value = start;
  return {
    now: () => value,
    advance: (ms) => { value += ms; },
  };
}

const noSleep = async () => {};

describe('S2-002 process table parsing', () => {
  test('a snapshot is parsed into pid/parent pairs', () => {
    const entries = parseProcessTable('100 1\n101 100\n\r\n102 101\n');
    assert.deepEqual(entries, [
      { pid: 100, parentPid: 1 },
      { pid: 101, parentPid: 100 },
      { pid: 102, parentPid: 101 },
    ]);
  });

  test('malformed lines are dropped rather than read as pids', () => {
    const entries = parseProcessTable('not a pid\n100 1\n101\n101 x\n-5 1\n');
    assert.deepEqual(entries, [{ pid: 100, parentPid: 1 }]);
  });

  test('descendants are the whole subtree, not just direct children', () => {
    const entries = parseProcessTable([
      '100 1',   // root
      '101 100', // child
      '102 101', // grandchild
      '103 102', // great-grandchild
      '104 100', // second child
      '105 1',   // sibling of the root, must not be collected
    ].join('\n'));
    assert.deepEqual(descendantsIn(entries, 100).sort((a, b) => a - b), [101, 102, 103, 104]);
  });

  test('a re-parented orphan is no longer reported as a descendant', () => {
    // Once the parent dies Windows re-parents the child, so a post-kill
    // snapshot cannot find it. This is why the pre-kill snapshot is retained;
    // the traversal itself must not invent a relationship that the OS no
    // longer reports.
    const beforeKill = parseProcessTable('100 1\n101 100\n');
    const afterKill = parseProcessTable('101 4\n');
    assert.deepEqual(descendantsIn(beforeKill, 100), [101]);
    assert.deepEqual(descendantsIn(afterKill, 100), []);
  });

  test('the root is never reported as its own descendant', () => {
    const entries = parseProcessTable('100 1\n100 100\n');
    assert.deepEqual(descendantsIn(entries, 100), []);
  });

  test('traversal is depth-limited so a cycle cannot hang the settle loop', () => {
    const cycle = ['1 0', '2 1', '3 2', '4 3', '5 4', '6 5', '7 6', '8 7'];
    const found = descendantsIn(parseProcessTable(cycle.join('\n')), 1);
    assert.equal(found.length, DESCENDANT_DEPTH, 'a cycle must terminate at the depth cap');
    assert.ok(!found.includes(1), 'the root must not be collected');
  });
});

describe('S2-002 process query retry policy', () => {
  test('an answered query is used and no further query is issued', async () => {
    let calls = 0;
    const result = await queryUntilAnswered(async () => {
      calls += 1;
      return { answered: true, value: [7] };
    }, { sleep: noSleep });
    assert.equal(result.answered, true);
    assert.deepEqual(result.value, [7]);
    assert.equal(result.attempts, 1);
    assert.equal(calls, 1);
  });

  test('a transient transport failure is retried instead of becoming the verdict', async () => {
    // The regression from #16: a single WMI hiccup used to resolve as
    // "every candidate is alive" and the suite went red.
    let calls = 0;
    const result = await queryUntilAnswered(async () => {
      calls += 1;
      if (calls < 3) return { answered: false, reason: 'nonzero_exit:1' };
      return { answered: true, value: [] };
    }, { sleep: noSleep });
    assert.equal(result.answered, true, 'a retryable failure must not settle the verdict');
    assert.deepEqual(result.value, [], 'the OS answer is the verdict');
    assert.equal(calls, 3);
    assert.equal(result.failures, 2);
  });

  test('a query that never answers fails closed within the budget', async () => {
    const clock = fakeClock();
    let calls = 0;
    const result = await queryUntilAnswered(async () => {
      calls += 1;
      clock.advance(50);
      return { answered: false, reason: 'spawn_error:EAGAIN' };
    }, { budgetMs: 1000, sleep: async () => { clock.advance(50); }, now: clock.now });
    assert.equal(result.answered, false, 'unanswered must never look like an answer');
    assert.equal(result.lastFailure, 'spawn_error:EAGAIN');
    assert.ok(calls >= QUERY_MIN_ATTEMPTS, 'the minimum attempt count is still honoured');
    assert.ok(result.attempts < QUERY_MAX_ATTEMPTS, 'the attempt ceiling bounds a stuck clock');
  });

  test('a throwing attempt is a transport failure, not a crash', async () => {
    const error = new Error('spawn failed');
    error.code = 'ENOENT';
    const result = await queryUntilAnswered(async () => { throw error; }, { sleep: noSleep, maxAttempts: 2 });
    assert.equal(result.answered, false);
    assert.equal(result.lastFailure, 'query_threw:ENOENT');
  });

  test('the minimum attempt count survives a zero budget', async () => {
    let calls = 0;
    const result = await queryUntilAnswered(async () => {
      calls += 1;
      return { answered: false, reason: 'boom' };
    }, { budgetMs: 0, sleep: noSleep });
    assert.equal(calls, QUERY_MIN_ATTEMPTS);
    assert.equal(result.answered, false);
  });

  test('an attempt is required', async () => {
    await assert.rejects(() => queryUntilAnswered(null), /PROCESS_QUERY_REQUIRED/);
  });
});

describe('S2-002 tree formation wait', () => {
  test('returns as soon as a descendant is observable', async () => {
    let polls = 0;
    const result = await awaitTree(async () => {
      polls += 1;
      return polls >= 3 ? [11] : [];
    }, 10, { sleep: noSleep });
    assert.deepEqual(result, { formed: true, seen: 1, attempts: 3 });
    assert.equal(polls, 3, 'no polling past the moment the tree exists');
  });

  test('a tree that never forms fails closed within the attempt budget', async () => {
    let polls = 0;
    const result = await awaitTree(async () => { polls += 1; return []; }, 10, { sleep: noSleep, attempts: 4 });
    assert.deepEqual(result, { formed: false, seen: 0, attempts: 4 });
    assert.equal(polls, 4, 'the wait is bounded, not open-ended');
  });

  test('the descendant probe is required', async () => {
    await assert.rejects(() => awaitTree(null, 10), /PROCESS_DESCENDANT_PROBE_REQUIRED/);
  });
});

describe('S2-002 tree settle policy', () => {
  test('settles as soon as one observation reports nothing alive', async () => {
    const observations = [
      { settled: false, answered: true, alive: [100, 101] },
      { settled: true, answered: true, alive: [] },
    ];
    const killed = [];
    let index = 0;
    const result = await settleUntilGone({
      observe: async () => observations[Math.min(index++, observations.length - 1)],
      terminate: async (alive) => { killed.push([...alive]); },
      sleep: noSleep,
    });
    assert.equal(result.settled, true);
    assert.equal(result.steps, 2);
    assert.equal(result.unanswered, 0);
    assert.deepEqual(killed, [[100, 101]], 'only the first observation had survivors');
  });

  test('an unanswerable observation never settles the tree', async () => {
    // Fail-closed: no answer means every tracked pid is assumed alive, so the
    // loop keeps working instead of reporting a clean cancellation.
    let calls = 0;
    const result = await settleUntilGone({
      observe: async () => {
        calls += 1;
        return { settled: false, answered: false, alive: [100], reason: 'nonzero_exit:1' };
      },
      terminate: async () => {},
      sleep: noSleep,
      maxSteps: 3,
    });
    assert.equal(result.settled, false);
    assert.equal(calls, 3);
    assert.equal(result.unanswered, 3);
    assert.equal(result.lastFailure, 'nonzero_exit:1');
  });

  test('a throwing observer is a failed observation, not a crash', async () => {
    const result = await settleUntilGone({
      observe: async () => { throw Object.assign(new Error('gone'), { code: 'EPIPE' }); },
      terminate: async () => {},
      sleep: noSleep,
      maxSteps: 2,
    });
    assert.equal(result.settled, false);
    assert.equal(result.unanswered, 2);
    assert.equal(result.lastFailure, 'observer_threw:EPIPE');
  });

  test('the loop is bounded by wall clock, not by a fixed iteration count', async () => {
    // Each step costs 200ms of host time. The old adapter ran a fixed 20
    // iterations regardless, which is 4s here and minutes on a loaded host
    // where a process-table query costs seconds.
    const clock = fakeClock();
    const result = await settleUntilGone({
      observe: async () => { clock.advance(200); return { settled: false, answered: true, alive: [100] }; },
      terminate: async () => {},
      sleep: async () => { clock.advance(100); },
      budgetMs: 1000,
      now: clock.now,
    });
    assert.equal(result.settled, false);
    assert.equal(result.timedOut, true);
    assert.ok(result.steps <= 5, `expected a wall-clock bound, ran ${result.steps} steps`);
    assert.ok(result.steps < SETTLE_MAX_STEPS);
  });

  test('a clock that never advances is bounded by the step ceiling', async () => {
    let calls = 0;
    const result = await settleUntilGone({
      observe: async () => { calls += 1; return { settled: false, answered: true, alive: [100] }; },
      terminate: async () => {},
      sleep: noSleep,
      maxSteps: 5,
    });
    assert.equal(calls, 5);
    assert.equal(result.settled, false);
    assert.equal(result.timedOut, false, 'the ceiling, not the clock, ended the loop');
  });

  test('observer and terminator are required', async () => {
    await assert.rejects(() => settleUntilGone({ terminate: async () => {} }), /PROCESS_OBSERVER_REQUIRED/);
    await assert.rejects(() => settleUntilGone({ observe: async () => ({ settled: true }) }), /PROCESS_TERMINATOR_REQUIRED/);
  });
});
