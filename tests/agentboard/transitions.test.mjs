// S2-007 — the board state machine is exactly the frozen table
// (issue #7 §2 "one store, one policy path"; module spec §1, §3.1, §3.2).
//
// WHY THIS FILE EXISTS. constants.mjs TRANSITIONS is the ONLY edge list in the
// repository, and decideTransition() in policy.mjs is the ONLY way to reach a
// guard. Both claims are load-bearing and both are easy to break silently:
//
//   * a second, hand-written edge list (here, in commands.mjs, in the store or
//     in a test) is a second editable form of the truth the boundary contract
//     forbids — so the test below asserts the TABLE, and derives every
//     expectation from it instead of re-typing 22 edges;
//   * DONE is the single most valuable state on the board. If DONE ever grows
//     an outgoing edge, or if any state other than IN_REVIEW can reach it, the
//     independent-approval guarantee is gone and nothing else would report it;
//   * a guard that can be called for an edge the table does not bind is a
//     guard that authorizes a move nobody reviewed — so every exported guard
//     is driven against a pair the table does not name and must refuse;
//   * every guard name the table references must be a real exported function.
//     A typo in the table would otherwise turn an edge into GUARD_MISSING at
//     run time, in production, after a claim had already been taken.
//
// The transition DECISION is what is checked against the table, for all 9x9
// state pairs: isTransitionAllowed, allowedTargets, isKnownState and
// decideTransition must agree with each other and with the table. Anything
// else is a second machine.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  ACTOR_KINDS,
  BOARD_STATES,
  ERROR_CODES,
  TRANSITIONS,
  allowedTargets,
  isKnownState,
  isTransitionAllowed,
} from '../../src/lib/agentboard/constants.mjs';
import * as policy from '../../src/lib/agentboard/policy.mjs';
import { decideTransition } from '../../src/lib/agentboard/policy.mjs';
import { isBoardError } from '../../src/lib/agentboard/errors.mjs';

// The eleven guard names are FROZEN by the module spec §1 (and repeated in the
// constants.mjs header). They are written out here once so that a twelfth
// guard cannot be smuggled into the table or into policy.mjs; the guards
// themselves are still looked up BY NAME from the table below.
const FROZEN_GUARDS = Object.freeze([
  'guardBacklogToReady',
  'guardReadyToClaimed',
  'guardClaimedToRunning',
  'guardRunningToInReview',
  'guardInReviewToDone',
  'guardRelease',
  'guardRequeueAfterReconciliation',
  'guardBlock',
  'guardFail',
  'guardCancel',
  'guardUnblock',
]);

const TERMINAL_STATES = Object.freeze(['DONE', 'CANCELLED']);
const SHA = `sha256:${'f'.repeat(64)}`;
const NOW = '2026-03-22T09:30:00.000Z';

/** A task row in `state`, with only the fields a guard reads before it refuses. */
function taskIn(state) {
  return {
    contractVersion: '1.0.0',
    task_id: 'abt-alpha',
    workspace_id: 'ws-alpha',
    state,
    revision: 2,
    brief_digest: SHA,
    policy_digest: SHA,
    manifest_digest: SHA,
    workspace_ref: {
      workspace_id: 'ws-alpha',
      root_ref: 'projects/alpha',
      isolation_profile_id: 'sbx-podman-local-restricted-v1',
      sandbox_profile_digest: SHA,
      read_only_paths: [],
    },
    cost_limits: { currency: 'USD', max_task_cost: 1, max_campaign_cost: 2, max_day_cost: 3 },
    acl: { visibility: 'project', allowed_principal_ids: ['prn-owner'] },
    active_lease_id: null,
    assigned_adapter_id: null,
    fencing_token: null,
  };
}

function refusal(fn) {
  let thrown = null;
  try {
    fn();
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown !== null, 'the call was allowed but the table forbids it');
  assert.ok(isBoardError(thrown), `expected a typed BoardError, got ${thrown?.name}: ${thrown?.message}`);
  assert.ok(ERROR_CODES.includes(thrown.code), `error code ${thrown.code} is outside the closed set`);
  return thrown;
}

function refusesWith(fn, code) {
  const thrown = refusal(fn);
  assert.equal(thrown.code, code, `expected ${code}, got ${thrown.code}: ${thrown.message}`);
  return thrown;
}

/** Every (from, to) pair the table admits, derived from the table itself. */
const ALLOWED_EDGES = BOARD_STATES.flatMap((from) =>
  Object.keys(TRANSITIONS[from] ?? {}).map((to) => ({ from, to, guard: TRANSITIONS[from][to] })));

/** Every (from, to) pair the table does NOT admit. */
const DISALLOWED_EDGES = BOARD_STATES.flatMap((from) =>
  BOARD_STATES.filter((to) => !isTransitionAllowed(from, to)).map((to) => ({ from, to })));

describe('S2-007 the transition table is the whole machine', () => {
  test('it is keyed by exactly the nine canonical states and is frozen', () => {
    assert.equal(BOARD_STATES.length, 9);
    assert.deepEqual(Object.keys(TRANSITIONS).sort(), [...BOARD_STATES].sort());
    assert.ok(Object.isFrozen(TRANSITIONS), 'a mutable edge list is a second editable form of the truth');
    for (const from of BOARD_STATES) {
      assert.ok(Object.isFrozen(TRANSITIONS[from]), `TRANSITIONS.${from} is mutable`);
    }
  });

  test('it is not a byzantine machine: 23 edges, every target is a known state, no self loop', () => {
    assert.equal(ALLOWED_EDGES.length, 23, 'the edge count changed: every new edge needs a guard and a reason');
    for (const edge of ALLOWED_EDGES) {
      assert.ok(isKnownState(edge.to), `edge ${edge.from} -> ${edge.to} leaves the nine canonical states`);
      assert.notEqual(edge.from, edge.to, `edge ${edge.from} -> ${edge.to} is a self loop`);
      assert.match(edge.guard, /^guard[A-Z]/, `edge ${edge.from} -> ${edge.to} names no guard`);
    }
  });

  test('DONE is terminal: no outgoing edge at all', () => {
    assert.deepEqual(TRANSITIONS.DONE, {}, 'DONE grew an outgoing edge: the board would be able to un-finish work silently');
    for (const to of BOARD_STATES) {
      assert.equal(isTransitionAllowed('DONE', to), false, `DONE -> ${to} is not in the table`);
      assert.deepEqual(allowedTargets('DONE'), []);
    }
  });

  test('CANCELLED is terminal as well', () => {
    assert.deepEqual(TRANSITIONS.CANCELLED, {}, 'CANCELLED grew an outgoing edge');
    for (const to of BOARD_STATES) {
      assert.equal(isTransitionAllowed('CANCELLED', to), false, `CANCELLED -> ${to} is not in the table`);
    }
  });

  test('every non-terminal state can still be cancelled, and nothing else can', () => {
    // A task that cannot be cancelled can only be left to expire or to be
    // finished, which is not a boundary this project can afford.
    for (const from of BOARD_STATES) {
      const cancellable = isTransitionAllowed(from, 'CANCELLED');
      if (TERMINAL_STATES.includes(from)) {
        assert.equal(cancellable, false, `${from} is terminal and cannot be cancelled again`);
      } else {
        assert.equal(cancellable, true, `${from} has no way to be cancelled`);
      }
    }
  });

  test('DONE is reachable only through the independent-approval edge', () => {
    const intoDone = ALLOWED_EDGES.filter((edge) => edge.to === 'DONE');
    assert.equal(intoDone.length, 1, 'more than one path into DONE exists');
    assert.equal(intoDone[0].from, 'IN_REVIEW');
    assert.equal(intoDone[0].guard, 'guardInReviewToDone');
  });

  test('isKnownState, isTransitionAllowed and allowedTargets agree with the table', () => {
    for (const state of [...BOARD_STATES, 'PAUSED', 'done', '', null, undefined, 7]) {
      assert.equal(isKnownState(state), BOARD_STATES.includes(state), `isKnownState(${String(state)})`);
    }
    for (const from of BOARD_STATES) {
      const expected = Object.keys(TRANSITIONS[from]).sort();
      assert.deepEqual(allowedTargets(from), expected, `allowedTargets(${from}) drifted from the table`);
      for (const to of BOARD_STATES) {
        assert.equal(
          isTransitionAllowed(from, to),
          Object.prototype.hasOwnProperty.call(TRANSITIONS[from], to),
          `isTransitionAllowed(${from}, ${to}) drifted from the table`,
        );
      }
    }
  });

  test('an unknown state has no edges and does not crash the helpers', () => {
    for (const from of ['PAUSED', 'done', '', null, undefined]) {
      assert.deepEqual(allowedTargets(from), []);
      assert.equal(isTransitionAllowed(from, 'READY'), false);
    }
  });
});

describe('S2-007 every guard the table names is really exported', () => {
  test('the table references exactly the eleven frozen guards', () => {
    const named = [...new Set(ALLOWED_EDGES.map((edge) => edge.guard))].sort();
    assert.deepEqual(named, [...FROZEN_GUARDS].sort());
  });

  test('each referenced guard name resolves to a function in policy.mjs', () => {
    for (const guard of FROZEN_GUARDS) {
      assert.equal(typeof policy[guard], 'function', `policy.mjs does not export ${guard}`);
    }
    for (const edge of ALLOWED_EDGES) {
      assert.equal(typeof policy[edge.guard], 'function', `edge ${edge.from} -> ${edge.to} names an unexported guard ${edge.guard}`);
    }
  });

  test('policy.mjs exports no guard outside the frozen eleven', () => {
    const exported = Object.keys(policy).filter((name) => /^guard[A-Z]/.test(name)).sort();
    assert.deepEqual(exported, [...FROZEN_GUARDS].sort());
  });

  test('decideTransition is exported and is the only way in', () => {
    assert.equal(typeof policy.decideTransition, 'function');
    assert.equal(decideTransition, policy.decideTransition);
  });
});

describe('S2-007 every disallowed pair is refused with TRANSITION_NOT_ALLOWED', () => {
  test('the table and the decision function agree on all 81 state pairs', () => {
    let allowed = 0;
    let refused = 0;
    for (const from of BOARD_STATES) {
      for (const to of BOARD_STATES) {
        const tableAllows = isTransitionAllowed(from, to);
        let thrown = null;
        try {
          decideTransition({ task: taskIn(from), toState: to, context: { fromState: from, toState: to } });
        } catch (error) {
          thrown = error;
        }
        assert.ok(thrown !== null, `${from} -> ${to} was ALLOWED although the table does not name it`);
        assert.ok(isBoardError(thrown), `${from} -> ${to} refused with an untyped ${thrown?.name}: ${thrown?.message}`);
        if (tableAllows) {
          allowed += 1;
          // Allowed by the table, still refused: the guard demands proof. The
          // only thing that must NOT happen is a silent success.
          assert.notEqual(thrown.code, 'TRANSITION_NOT_ALLOWED', `${from} -> ${to} is in the table but the decision refused it as a forbidden edge`);
        } else {
          refused += 1;
          assert.equal(thrown.code, 'TRANSITION_NOT_ALLOWED', `${from} -> ${to} is not in the table and must be TRANSITION_NOT_ALLOWED, got ${thrown.code}`);
        }
      }
    }
    assert.equal(allowed, 23);
    assert.equal(refused, 58);
  });

  test('all 58 disallowed pairs are enumerated, so a new edge cannot appear unnoticed', () => {
    assert.equal(DISALLOWED_EDGES.length, 58);
    for (const { from, to } of DISALLOWED_EDGES) {
      refusesWith(() => decideTransition({ task: taskIn(from), toState: to, context: { fromState: from, toState: to } }), 'TRANSITION_NOT_ALLOWED');
    }
  });

  test('DONE refuses every target, including itself', () => {
    for (const to of BOARD_STATES) {
      refusesWith(() => decideTransition({ task: taskIn('DONE'), toState: to, context: { fromState: 'DONE', toState: to } }), 'TRANSITION_NOT_ALLOWED');
    }
  });

  test('an unknown source or target state is refused, not coerced', () => {
    for (const state of ['PAUSED', 'done', 'ARCHIVED', '', null, 7]) {
      refusesWith(() => decideTransition({ task: taskIn(state), toState: 'READY' }), 'TRANSITION_NOT_ALLOWED');
      refusesWith(() => decideTransition({ task: taskIn('READY'), toState: state }), 'TRANSITION_NOT_ALLOWED');
    }
    for (const badTask of [null, undefined, 'abt-alpha', [], {}, { task_id: 'abt-alpha' }, { task_id: 'abt-alpha', state: null }]) {
      refusesWith(() => decideTransition({ task: badTask, toState: 'READY' }), 'TRANSITION_NOT_ALLOWED');
    }
  });

  test('the current state is read from the task row, never from the caller claim', () => {
    // A caller that lies about where the task is must not be able to move it.
    const done = taskIn('DONE');
    let thrown = null;
    try {
      decideTransition({ task: done, toState: 'IN_REVIEW', context: { fromState: 'RUNNING', toState: 'IN_REVIEW' } });
    } catch (error) {
      thrown = error;
    }
    assert.ok(isBoardError(thrown), 'a forged from_state was accepted');
    assert.ok(
      ['TRANSITION_NOT_ALLOWED', 'BLOCKED_POLICY'].includes(thrown.code),
      `a forged from_state gave ${thrown.code}`,
    );
    assert.equal(done.state, 'DONE', 'the task row was mutated by a refused decision');
  });

  test('no argument is optional', () => {
    for (const call of [() => decideTransition(), () => decideTransition({}), () => decideTransition({ task: taskIn('READY') })]) {
      refusal(call);
    }
  });
});

describe('S2-007 a guard authorizes only the edge the table binds it to', () => {
  test('each guard refuses a pair that is not its own', () => {
    for (const guardName of FROZEN_GUARDS) {
      // Find a pair the table does not bind to THIS guard. The guard reads the
      // table before it reads anything else, so the refusal must be about the
      // edge, not about the missing context.
      const foreign = ALLOWED_EDGES.find((edge) => edge.guard !== guardName)
        ?? { from: 'DONE', to: 'CANCELLED' };
      const call = () => policy[guardName]({
        task: taskIn(foreign.from),
        fromState: foreign.from,
        toState: foreign.to,
        now: NOW,
        expectedRevision: 2,
        actor: 'prn-owner',
        actorKind: 'human_owner',
        reason: 'attempting an edge the table does not bind',
        capabilities: [],
      });
      refusesWith(call, 'TRANSITION_NOT_ALLOWED');
    }
  });

  test('a guard given only its own edge and no proof still refuses', () => {
    // The table authorises the EDGE; the guard authorises the MOVE. An edge that
    // exists is never by itself a permission to act.
    for (const edge of ALLOWED_EDGES) {
      let thrown = null;
      try {
        policy[edge.guard]({ task: taskIn(edge.from), fromState: edge.from, toState: edge.to });
      } catch (error) {
        thrown = error;
      }
      assert.ok(
        isBoardError(thrown),
        `${edge.from} -> ${edge.to} (${edge.guard}) was allowed with no actor, clock, revision, reason or digests`,
      );
      assert.notEqual(
        thrown.code,
        'TRANSITION_NOT_ALLOWED',
        `${edge.from} -> ${edge.to} is in the table and must not be refused as a forbidden edge`,
      );
    }
  });

  test('a guard with a context that is not an object refuses', () => {
    for (const guardName of FROZEN_GUARDS) {
      for (const bad of [null, undefined, 'BACKLOG->READY', 7, []]) {
        refusal(() => policy[guardName](bad));
      }
    }
  });
});

describe('S2-007 actor kinds are closed and machine kinds cannot be the gate', () => {
  test('the actor kind list is the frozen six', () => {
    assert.deepEqual([...ACTOR_KINDS].sort(), [
      'adapter',
      'deterministic_gate',
      'human_owner',
      'human_reviewer',
      'scheduler',
      'system',
    ]);
  });

  test('the DONE edge requires an approval actor kind, so a producer cannot finish its own task', () => {
    assert.equal(TRANSITIONS.IN_REVIEW.DONE, 'guardInReviewToDone');
    // The narrowing itself lives in policy.guardInReviewToDone and is exercised
    // there; here the claim is only that the edge is bound to that guard and to
    // nothing that a machine actor could reach.
    const doneGuard = ALLOWED_EDGES.filter((edge) => edge.to === 'DONE');
    assert.equal(doneGuard.length, 1);
    assert.equal(doneGuard[0].guard, 'guardInReviewToDone');
    assert.equal(typeof policy.assertHumanOnlyApproval, 'function');
    assert.equal(typeof policy.assertNotSelfApproved, 'function');
  });
});
