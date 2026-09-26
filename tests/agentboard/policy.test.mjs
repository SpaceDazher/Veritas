// S2-007 — the policy surface: default-deny, fail-closed, no second authority
// (issue #7 §2 "one store, one policy path", §5 "fail closed"; module spec §3.1).
//
// WHY THIS FILE EXISTS. policy.mjs is the only place where a request may be
// REFUSED for containment reasons that S2-002 has no equivalent for: the board
// lease and its fence, the empty-set rule, the board actor taxonomy, numeric
// budget and the board ACL row. Every one of those checks may only ever REMOVE
// permission. The properties asserted here are the ones that, once lost, turn
// the live board into something the issue forbids:
//
//   * EMPTY IS NOT EVERYTHING. An empty granted tool set, an empty granted
//     scope set and an empty ACL list each mean NOBODY, not "all". The three
//     most dangerous single-line regressions in this module are the three
//     vacuous-truth bugs an empty set invites.
//   * AN UNASSIGNED BUDGET IS NOT ZERO. A missing, null, zero, negative or
//     non-numeric limit is BUDGET_EXCEEDED, and a free model is not an
//     authorization. budgetRemaining() must never answer Infinity.
//   * A WORKSPACE REF IS RELATIVE AND CONTAINED. Absolute paths, '..',
//     backslashes, NUL bytes and a symlink that leaves the root are all
//     refused; with no root set at all nothing is inside anything.
//   * A PRODUCER IS NEVER THE GATE, and a machine actor is never a gate at all.
//   * A DIGEST IS AN INTEGRITY CONTROL. Matching digests prove nothing moved;
//     a moved-on, malformed or missing observed digest is MALFORMED_RESULT and
//     never a pass.
//   * THE COMMAND BOUNDARY IS CLOSED. An unknown argument key is refused, and
//     an argument that names the authority (principal, actor, scope, budget,
//     approval, lease, fence) may never disagree with the value the SERVER
//     resolved — that is the confused-deputy check.
//   * THE IDEMPOTENCY KEY IS A FUNCTION OF THE CANONICAL ARGUMENTS, and of
//     nothing else: same arguments -> same key, member order irrelevant, array
//     order significant, actor significant, non-canonical input refused.
//   * redact() is defence in depth: a token-shaped secret never survives into
//     a message, a detail or an outbox row.
//
// Every refusal below must be a TYPED BoardError whose code is in the closed
// ERROR_CODES set. An untyped throw, a returned `false` and a silent success
// are all failures of this file.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  assertActor,
  assertBudgetAssignable,
  assertCanonicalArguments,
  assertCapabilitySubset,
  assertDigestsMatch,
  assertHumanOnlyApproval,
  assertNotSelfApproved,
  assertSandboxExecutable,
  assertScopeSubset,
  assertTaskVisible,
  assertToolSubset,
  assertWithinBudget,
  assertWorkspaceWithin,
  budgetRemaining,
  commandIdempotencyKey,
  fixedClock,
  isVisible,
  sequenceIdFactory,
} from '../../src/lib/agentboard/policy.mjs';
import {
  BOARD_CAPABILITIES,
  EXECUTION_SCOPES,
  PROVEN_SANDBOX_PROFILE_IDS,
  SANDBOX_PROFILES,
} from '../../src/lib/agentboard/constants.mjs';
import { AuthRequired, BoardError, ERROR_CODES, isBoardError, redact } from '../../src/lib/agentboard/errors.mjs';

const SHA = `sha256:${'f'.repeat(64)}`;
const SHA_OTHER = `sha256:${'e'.repeat(64)}`;
const HEX64 = /^[0-9a-f]{64}$/;
const OWNER = 'prn-owner';
const ADAPTER = 'prn-adapter';

// --- refusal helpers --------------------------------------------------------

function refusal(fn) {
  let thrown = null;
  let result;
  try {
    result = fn();
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown !== null, `expected a refusal, got the value ${JSON.stringify(result)}`);
  assert.ok(isBoardError(thrown), `expected a typed BoardError, got ${thrown?.name}: ${thrown?.message}`);
  assert.ok(ERROR_CODES.includes(thrown.code), `error code ${thrown.code} is outside the closed set`);
  return thrown;
}

function refuses(fn, code) {
  const thrown = refusal(fn);
  if (code !== undefined) {
    assert.equal(thrown.code, code, `expected ${code}, got ${thrown.code}: ${thrown.message}`);
  }
  return thrown;
}

function allows(fn) {
  let thrown = null;
  let result;
  try {
    result = fn();
  } catch (error) {
    thrown = error;
  }
  assert.equal(thrown, null, `expected the call to be allowed, got ${thrown?.code}: ${thrown?.message}`);
  return result;
}

const COST_LIMITS = Object.freeze({
  currency: 'USD',
  max_task_cost: 10,
  max_campaign_cost: 100,
  max_day_cost: 40,
});

const GRANT_LIMITS = Object.freeze({
  currency: 'USD',
  task_limit: 10,
  campaign_limit: 100,
  day_limit: 40,
  timeout_ms: 60000,
  granted_by: OWNER,
  granted_at: '2026-03-22T09:30:00.000Z',
});

function taskWith(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    task_id: 'abt-alpha',
    workspace_id: 'ws-alpha',
    state: 'RUNNING',
    brief_digest: SHA,
    policy_digest: SHA,
    manifest_digest: SHA,
    cost_limits: { ...COST_LIMITS },
    acl: { visibility: 'project', allowed_principal_ids: [OWNER] },
    ...overrides,
  };
}

function workspaceRef(overrides = {}) {
  return {
    workspace_id: 'ws-alpha',
    root_ref: 'projects/alpha',
    isolation_profile_id: 'sbx-podman-local-restricted-v1',
    sandbox_profile_digest: SHA,
    read_only_paths: [],
    ...overrides,
  };
}

describe('S2-007 policy: the empty set is not everything', () => {
  test('an empty granted tool set grants no tool, including none at all', () => {
    refuses(() => assertToolSubset(['tool:read'], []), 'CAPABILITY_MISMATCH');
    refuses(() => assertToolSubset(['tool:read', 'tool:write'], []), 'CAPABILITY_MISMATCH');
    // Nothing required and nothing granted is genuinely an empty intersection,
    // not a wildcard: it is allowed precisely because it asks for nothing.
    allows(() => assertToolSubset([], []));
  });

  test('a granted tool set covers the task tools and nothing more is inferred', () => {
    allows(() => assertToolSubset(['tool:read'], ['tool:read', 'tool:write']));
    allows(() => assertToolSubset([], ['tool:read']));
    refuses(() => assertToolSubset(['tool:write'], ['tool:read']), 'CAPABILITY_MISMATCH');
    // A prefix is not a tool: tool:read-write is not tool:read.
    refuses(() => assertToolSubset(['tool:read'], ['tool:read-write']), 'CAPABILITY_MISMATCH');
  });

  test('a malformed or non-array tool list is refused rather than coerced', () => {
    for (const bad of ['tool:read', 7, {}, [7], ['read'], ['tool:'], ['tool:Read'], ['']]) {
      refuses(() => assertToolSubset(bad, ['tool:read']), 'CAPABILITY_MISMATCH');
      refuses(() => assertToolSubset(['tool:read'], bad), 'CAPABILITY_MISMATCH');
    }
  });

  test('an empty granted scope set grants no execution scope', () => {
    refuses(() => assertScopeSubset(['task.read'], []), 'CAPABILITY_MISMATCH');
    allows(() => assertScopeSubset([], []));
    allows(() => assertScopeSubset(['task.read'], EXECUTION_SCOPES));
    refuses(() => assertScopeSubset(['artifact.write'], ['task.read']), 'CAPABILITY_MISMATCH');
  });

  test('a scope outside the closed vocabulary is refused on both sides', () => {
    for (const unknown of ['task.admin', 'TASK.READ', 'budget.spend.extra', 'root', '']) {
      refuses(() => assertScopeSubset([unknown], [unknown]), 'CAPABILITY_MISMATCH');
      refuses(() => assertScopeSubset([], [unknown]), 'CAPABILITY_MISMATCH');
    }
    for (const bad of ['task.read', 7, {}, [null], [[]]]) {
      refuses(() => assertScopeSubset(bad, ['task.read']), 'CAPABILITY_MISMATCH');
      refuses(() => assertScopeSubset(['task.read'], bad), 'CAPABILITY_MISMATCH');
    }
  });

  test('board capabilities obey the same rule', () => {
    refuses(() => assertCapabilitySubset(['board.task.transition'], []), 'CAPABILITY_MISMATCH');
    allows(() => assertCapabilitySubset(['board.task.transition'], BOARD_CAPABILITIES));
    allows(() => assertCapabilitySubset([], BOARD_CAPABILITIES));
    refuses(() => assertCapabilitySubset(['board.review.approve'], ['board.task.read']), 'CAPABILITY_MISMATCH');
    // Containment is a subset over well-formed names. Membership of the closed
    // BOARD_CAPABILITIES vocabulary is decided by assertActor, which is the
    // layer that knows the caller; this layer may only subtract.
    for (const malformed of ['BOARD.TASK.READ', 'board task read', 'board.task.read!', 'board.task.read ']) {
      refuses(() => assertCapabilitySubset([malformed], [malformed]), 'CAPABILITY_MISMATCH');
    }
    for (const bad of ['board.task.read', 7, {}, [7]]) {
      refuses(() => assertCapabilitySubset(bad, BOARD_CAPABILITIES), 'CAPABILITY_MISMATCH');
    }
  });
});

describe('S2-007 policy: the workspace ref is relative and contained', () => {
  const ROOTS = ['/srv/ws'];

  test('a relative ref inside a known root is accepted', () => {
    allows(() => assertWorkspaceWithin(workspaceRef(), ROOTS));
    allows(() => assertWorkspaceWithin(workspaceRef({ root_ref: 'a' }), ROOTS));
    allows(() => assertWorkspaceWithin(workspaceRef({ read_only_paths: ['vendor'] }), ROOTS));
  });

  test('an absolute path is refused', () => {
    for (const root of ['/etc/passwd', '/srv/ws/../etc', 'C:/Windows', 'c:\\Windows', '\\\\server\\share', '~/secrets', '/']) {
      refuses(() => assertWorkspaceWithin(workspaceRef({ root_ref: root }), ROOTS), 'ACL_DENIED');
    }
  });

  test('a traversal segment is refused', () => {
    for (const root of ['..', '../etc', 'projects/../../etc', 'projects/..', 'a/b/../../../c', './..']) {
      refuses(() => assertWorkspaceWithin(workspaceRef({ root_ref: root }), ROOTS), 'ACL_DENIED');
    }
    refuses(() => assertWorkspaceWithin(workspaceRef({ read_only_paths: ['../etc'] }), ROOTS), 'ACL_DENIED');
  });

  test('a backslash is refused on every platform, not only on Windows', () => {
    for (const root of ['projects\\alpha', 'projects\\..\\..\\etc', 'a\\b', '\\', 'projects/alpha\\..\\..\\etc']) {
      refuses(() => assertWorkspaceWithin(workspaceRef({ root_ref: root }), ROOTS), 'ACL_DENIED');
    }
  });

  test('a NUL byte is refused', () => {
    refuses(() => assertWorkspaceWithin(workspaceRef({ root_ref: 'projects/alpha\u0000.txt' }), ROOTS), 'ACL_DENIED');
    refuses(() => assertWorkspaceWithin(workspaceRef({ root_ref: 'projects/\u0000' }), ROOTS), 'ACL_DENIED');
    refuses(() => assertWorkspaceWithin(workspaceRef({ read_only_paths: ['vendor\u0000'] }), ROOTS), 'ACL_DENIED');
    refuses(() => assertWorkspaceWithin(workspaceRef(), ['/srv/ws\u0000']), 'ACL_DENIED');
  });

  test('a symlink that leaves the root is refused when a resolver is injected', () => {
    const escape = {
      realpath: (target) => {
        if (target === '/srv/ws') return '/srv/ws';
        if (target === '/srv/ws/projects/alpha') return '/etc/shadow';
        return target;
      },
    };
    refuses(() => assertWorkspaceWithin(workspaceRef(), ROOTS, escape), 'ACL_DENIED');
    // The same ref, resolved inside the root, is fine: the check is real, not a
    // blanket denial of injected resolvers.
    allows(() => assertWorkspaceWithin(workspaceRef(), ROOTS, {
      realpath: (target) => (target === '/srv/ws/projects/alpha' ? '/srv/ws/projects/alpha' : target),
    }));
  });

  test('an unresolvable ref is refused, not assumed safe', () => {
    refuses(() => assertWorkspaceWithin(workspaceRef(), ROOTS, {
      realpath: () => { throw new Error('ENOENT'); },
    }), 'ACL_DENIED');
    refuses(() => assertWorkspaceWithin(workspaceRef(), ROOTS, { realpath: () => '' }), 'ACL_DENIED');
  });

  test('no known root means nothing is contained: an empty root set is not a wildcard', () => {
    for (const roots of [[], null, undefined, 'not-an-array', [''], [7], [null]]) {
      refuses(() => assertWorkspaceWithin(workspaceRef(), roots), 'ACL_DENIED');
    }
  });

  test('a malformed ref or root set is refused', () => {
    for (const bad of [null, undefined, 'projects/alpha', [], {}, { root_ref: 'projects/alpha' }, { workspace_id: 'nope', root_ref: 'a' }]) {
      refuses(() => assertWorkspaceWithin(bad, ROOTS), 'ACL_DENIED');
    }
  });

  test('containment is the relative-path check plus the symlink check, under any server-chosen root', () => {
    // root_ref is relative BY CONTRACT and the root is chosen by the SERVER, so
    // a syntactically contained ref is inside whichever root the server named.
    // The two real escapes are therefore a traversal segment and a symlink, and
    // both are refused under every root form.
    for (const roots of [['/srv/ws'], ['/srv/ws', '/srv/wsx'], ['/srv/ws/'], ['/opt/other']]) {
      allows(() => assertWorkspaceWithin(workspaceRef({ root_ref: 'alpha' }), roots), `root ${JSON.stringify(roots)}`);
      allows(() => assertWorkspaceWithin(workspaceRef(), roots), `root ${JSON.stringify(roots)}`);
      refuses(() => assertWorkspaceWithin(workspaceRef({ root_ref: '../../etc' }), roots), 'ACL_DENIED');
      refuses(() => assertWorkspaceWithin(workspaceRef({ root_ref: '/etc' }), roots), 'ACL_DENIED');
    }
    // Nothing is inside nothing: a root set that contains no usable segment
    // proves nothing and is refused. (A syntactically odd but non-empty root
    // string is not an escape — the ref is still relative and traversal-free,
    // and the live enforcement of the executor's own paths stays in S2-002.)
    for (const roots of [[''], ['/'], ['.'], [null]]) {
      refuses(() => assertWorkspaceWithin(workspaceRef(), roots), 'ACL_DENIED');
    }
  });

  test('a Windows device name is refused on every platform', () => {
    for (const root of ['NUL', 'con', 'projects/COM1', 'projects/lpt9.txt']) {
      refuses(() => assertWorkspaceWithin(workspaceRef({ root_ref: root }), ROOTS), 'ACL_DENIED');
    }
  });
});

describe('S2-007 policy: only a proven sandbox profile is executable', () => {
  test('each profile whose OS controls are proven is executable', () => {
    for (const profileId of PROVEN_SANDBOX_PROFILE_IDS) {
      allows(() => assertSandboxExecutable(profileId));
    }
  });

  test('a registered but unproven profile is blocked, not degraded', () => {
    const blocked = SANDBOX_PROFILES.map((profile) => profile.profile_id).filter((id) => !PROVEN_SANDBOX_PROFILE_IDS.includes(id));
    assert.ok(blocked.length > 0, 'the frozen profile list has no fail-closed variant');
    for (const profileId of blocked) {
      refuses(() => assertSandboxExecutable(profileId), 'BLOCKED_SANDBOX');
    }
  });

  test('an unknown or missing profile is blocked', () => {
    for (const bad of ['', 'sbx-does-not-exist', 'local-restricted', null, undefined, 7, {}, []]) {
      refuses(() => assertSandboxExecutable(bad), 'BLOCKED_SANDBOX');
    }
  });
});

describe('S2-007 policy: a digest is an integrity control, never a signature', () => {
  test('matching wire digests agree', () => {
    allows(() => assertDigestsMatch(taskWith(), { briefDigest: SHA, policyDigest: SHA, manifestDigest: SHA }));
  });

  test('the stored (bare hex) form compares equal to the wire form', () => {
    allows(() => assertDigestsMatch(taskWith(), {
      briefDigest: 'f'.repeat(64),
      policyDigest: SHA,
      manifestDigest: SHA,
    }));
  });

  test('a moved-on digest on any of the three bindings is refused', () => {
    for (const key of ['briefDigest', 'policyDigest', 'manifestDigest']) {
      refuses(() => assertDigestsMatch(taskWith(), {
        briefDigest: SHA,
        policyDigest: SHA,
        manifestDigest: SHA,
        [key]: SHA_OTHER,
      }), 'MALFORMED_RESULT');
    }
  });

  test('an unobserved or malformed observed digest is refused, never a pass', () => {
    for (const bad of [undefined, null, '', 'f'.repeat(63), `sha256:${'F'.repeat(64)}`, 7, {}, []]) {
      refuses(() => assertDigestsMatch(taskWith(), {
        briefDigest: bad,
        policyDigest: SHA,
        manifestDigest: SHA,
      }), 'MALFORMED_RESULT');
    }
  });

  test('a task whose own digest is malformed cannot be bound to anything', () => {
    for (const field of ['brief_digest', 'policy_digest', 'manifest_digest']) {
      const task = taskWith({ [field]: 'not-a-digest' });
      refuses(() => assertDigestsMatch(task, { briefDigest: SHA, policyDigest: SHA, manifestDigest: SHA }), 'MALFORMED_RESULT');
    }
  });

  test('no task and no argument object means no binding', () => {
    for (const bad of [null, undefined, 'abt-alpha', [], 7]) {
      refuses(() => assertDigestsMatch(bad, { briefDigest: SHA, policyDigest: SHA, manifestDigest: SHA }), 'MALFORMED_RESULT');
    }
    refuses(() => assertDigestsMatch(taskWith()), 'MALFORMED_RESULT');
  });

  // KNOWN DEFECT IN policy.mjs, asserted against the frozen spec and therefore
  // RED until its owner fixes it: the `{ ... } = {}` default only covers
  // `undefined`, so an explicit `null` escapes as a bare TypeError from the
  // destructuring. Spec rule 5 forbids an untyped throw crossing the boundary:
  // every refusal must be a BoardError. A one-line shape check on the observed
  // digests object fixes it.
  test('an untyped TypeError must never escape the digest binding', () => {
    for (const observed of [null, 'sha256:ff', 7, []]) {
      const thrown = refusal(() => assertDigestsMatch(taskWith(), observed));
      assert.equal(thrown.code, 'MALFORMED_RESULT');
    }
  });
});

describe('S2-007 policy: the producer is never the gate', () => {
  test('an independent human gate is allowed', () => {
    for (const actorKind of ['human_owner', 'human_reviewer', 'deterministic_gate']) {
      allows(() => assertHumanOnlyApproval(actorKind));
      allows(() => assertNotSelfApproved({ actorKind, producerPrincipalId: ADAPTER, gatePrincipalId: OWNER }));
    }
  });

  test('a machine actor is never an approval gate', () => {
    for (const actorKind of ['adapter', 'scheduler', 'system']) {
      refuses(() => assertHumanOnlyApproval(actorKind), 'BLOCKED_POLICY');
      refuses(() => assertNotSelfApproved({ actorKind, producerPrincipalId: ADAPTER, gatePrincipalId: OWNER }), 'BLOCKED_POLICY');
    }
  });

  test('self-approval by the producing principal is refused', () => {
    refuses(() => assertNotSelfApproved({
      actorKind: 'human_owner',
      producerPrincipalId: OWNER,
      gatePrincipalId: OWNER,
    }), 'BLOCKED_POLICY');
    // ... and a near-miss is still a different principal, so it is allowed: the
    // control is identity equality, not a guess about who really did the work.
    allows(() => assertNotSelfApproved({
      actorKind: 'human_owner',
      producerPrincipalId: 'prn-owner-2',
      gatePrincipalId: OWNER,
    }));
  });

  test('an unidentified producer or gate is refused', () => {
    for (const missing of [undefined, null, '', 'owner', 7, {}]) {
      refuses(() => assertNotSelfApproved({ actorKind: 'human_owner', producerPrincipalId: missing, gatePrincipalId: OWNER }), 'BLOCKED_POLICY');
      const thrown = refuses(() => assertNotSelfApproved({ actorKind: 'human_owner', producerPrincipalId: ADAPTER, gatePrincipalId: missing }));
      assert.equal(thrown.code, 'AUTH_REQUIRED', `a missing gate principal gave ${thrown.code}`);
    }
  });

  test('an unknown actor kind is refused rather than defaulted', () => {
    for (const actorKind of ['human', 'admin', 'root', 'HUMAN_OWNER', '', null, undefined, 7]) {
      refuses(() => assertHumanOnlyApproval(actorKind), 'BLOCKED_POLICY');
      refuses(() => assertNotSelfApproved({ actorKind, producerPrincipalId: ADAPTER, gatePrincipalId: OWNER }), 'BLOCKED_POLICY');
    }
  });
});

describe('S2-007 policy: an unassigned budget is not zero', () => {
  test('an explicitly assigned positive budget at every scope is acceptable', () => {
    allows(() => assertBudgetAssignable(GRANT_LIMITS));
    allows(() => assertBudgetAssignable(COST_LIMITS));
  });

  test('a missing scope is refused on the grant form and on the task cost_limits form', () => {
    for (const field of ['task_limit', 'campaign_limit', 'day_limit']) {
      const limits = { ...GRANT_LIMITS };
      delete limits[field];
      refuses(() => assertBudgetAssignable(limits), 'BUDGET_EXCEEDED');
    }
    for (const field of ['max_task_cost', 'max_campaign_cost', 'max_day_cost']) {
      const limits = { ...COST_LIMITS };
      delete limits[field];
      refuses(() => assertBudgetAssignable(limits), 'BUDGET_EXCEEDED');
    }
    for (const bad of [{}, null, undefined, 'USD', 7, []]) {
      refuses(() => assertBudgetAssignable(bad), 'BUDGET_EXCEEDED');
    }
  });

  test('a zero or negative scope is refused on both shapes', () => {
    for (const [base, fields] of [
      [GRANT_LIMITS, ['task_limit', 'campaign_limit', 'day_limit']],
      [COST_LIMITS, ['max_task_cost', 'max_campaign_cost', 'max_day_cost']],
    ]) {
      for (const field of fields) {
        for (const value of [0, -0, -1, -0.01, Number.NEGATIVE_INFINITY]) {
          refuses(() => assertBudgetAssignable({ ...base, [field]: value }), 'BUDGET_EXCEEDED');
        }
      }
    }
  });

  test('a null, NaN or non-numeric scope is refused', () => {
    for (const value of [null, Number.NaN, '10', true, {}, []]) {
      refuses(() => assertBudgetAssignable({ ...GRANT_LIMITS, task_limit: value }), 'BUDGET_EXCEEDED');
    }
  });

  test('the remaining headroom is the limit minus the spend, per scope', () => {
    assert.deepEqual(budgetRemaining(COST_LIMITS, { spent_task: 0, spent_campaign: 0, spent_day: 0 }), {
      task_remaining: 10,
      campaign_remaining: 100,
      day_remaining: 40,
    });
    assert.deepEqual(budgetRemaining(COST_LIMITS, { task_spent: 4.5, campaign_spent: 10, day_spent: 40 }), {
      task_remaining: 5.5,
      campaign_remaining: 90,
      day_remaining: 0,
    });
  });

  test('an overspend clamps at zero and never reports negative headroom', () => {
    const remaining = budgetRemaining(COST_LIMITS, { task_spent: 999, campaign_spent: 999, day_spent: 999 });
    assert.deepEqual(remaining, { task_remaining: 0, campaign_remaining: 0, day_remaining: 0 });
  });

  test('an unassigned budget has no headroom to report, and Infinity is not an answer', () => {
    for (const bad of [{}, { ...COST_LIMITS, max_task_cost: 0 }, null, undefined]) {
      refuses(() => budgetRemaining(bad, { spent_task: 0 }), 'BUDGET_EXCEEDED');
    }
    for (const bad of [undefined, null, 'not-an-object', {}]) {
      allows(() => budgetRemaining(COST_LIMITS, bad));
    }
  });

  test('a negative recorded spend is refused rather than treated as headroom', () => {
    refuses(() => budgetRemaining(COST_LIMITS, { spent_task: -1 }), 'BUDGET_EXCEEDED');
  });

  test('a settle within the headroom is allowed, including exactly the headroom', () => {
    allows(() => assertWithinBudget(COST_LIMITS, { spent_task: 0, spent_campaign: 0, spent_day: 0 }, 0));
    allows(() => assertWithinBudget(COST_LIMITS, { spent_task: 4, spent_campaign: 0, spent_day: 0 }, 6));
  });

  test('a settle that would exceed any scope is refused', () => {
    refuses(() => assertWithinBudget(COST_LIMITS, { spent_task: 4, spent_campaign: 0, spent_day: 0 }, 6.01), 'BUDGET_EXCEEDED');
    refuses(() => assertWithinBudget(COST_LIMITS, { spent_campaign: 100, spent_task: 0, spent_day: 0 }, 0.01), 'BUDGET_EXCEEDED');
    refuses(() => assertWithinBudget(COST_LIMITS, { spent_day: 40, spent_task: 0, spent_campaign: 0 }, 0.01), 'BUDGET_EXCEEDED');
  });

  test('a non-finite, negative or non-numeric settle amount is refused', () => {
    for (const amount of [-1, Number.NaN, Number.POSITIVE_INFINITY, '1', null, undefined, {}, []]) {
      refuses(() => assertWithinBudget(COST_LIMITS, { spent_task: 0, spent_campaign: 0, spent_day: 0 }, amount), 'BUDGET_EXCEEDED');
    }
  });

  test('settling against an unassigned budget is refused', () => {
    refuses(() => assertWithinBudget({}, { spent_task: 0 }, 0.01), 'BUDGET_EXCEEDED');
    refuses(() => assertWithinBudget(null, {}, 0.01), 'BUDGET_EXCEEDED');
  });
});

describe('S2-007 policy: the command boundary is closed (confused deputy)', () => {
  const ALLOWED = Object.freeze(['task_id', 'to_state', 'reason', 'idempotency_key']);

  test('an argument outside the canonical set of the command is refused', () => {
    refuses(
      () => assertCanonicalArguments('tasks.transition', { task_id: 'abt-alpha', to_state: 'READY', is_admin: true }, { allowedKeys: ALLOWED }),
      'BLOCKED_POLICY',
    );
    refuses(
      () => assertCanonicalArguments('tasks.transition', { task_id: 'abt-alpha', to_state: 'READY', approved: 'yes' }, { allowedKeys: ALLOWED }),
      'BLOCKED_POLICY',
    );
    allows(() => assertCanonicalArguments('tasks.transition', { task_id: 'abt-alpha', to_state: 'READY' }, { allowedKeys: ALLOWED }));
  });

  test('a non-canonical argument NAME is refused even without an allowlist', () => {
    for (const key of ['Task-Id', 'task id', 'TaskId', '1task', 'constructor', '__proto__', 'to-state', 'a'.repeat(65), '']) {
      const args = JSON.parse(`{"${key.replace(/"/g, '')}":"abt-alpha"}`);
      refuses(() => assertCanonicalArguments('tasks.transition', args), 'BLOCKED_POLICY');
    }
  });

  test('a prototype-polluting key is refused outright', () => {
    const args = {};
    Object.defineProperty(args, '__proto__', { value: { polluted: true }, enumerable: true, configurable: true, writable: true });
    refuses(() => assertCanonicalArguments('tasks.transition', args), 'BLOCKED_POLICY');
    assert.equal({}.polluted, undefined, 'the prototype was touched');
  });

  test('an authority-shaped argument carrying a nested structure is refused', () => {
    // The classic confused-deputy payload: the client sends the authority it
    // would like the server to believe. A scalar repeat of a server-resolved
    // value is legal; a nested object never is.
    for (const [key, value] of [
      ['granted_scope', { escalate: true }],
      ['granted_scope', [{ scope: 'task.write' }]],
      ['allowed_tools', [{ tool: 'tool:shell' }]],
      ['capabilities', { board: 'all' }],
      ['budget_grant', { task_limit: 1e9 }],
      ['budget', { currency: 'USD' }],
      ['approval', { approved: true }],
      ['approved', { by: 'prn-owner' }],
      ['actor', { principal_id: 'prn-owner' }],
      ['role', { name: 'admin' }],
    ]) {
      const thrown = refuses(() => assertCanonicalArguments('tasks.transition', { task_id: 'abt-alpha', [key]: value }), 'BLOCKED_POLICY');
      assert.ok(
        thrown.message.includes(key) || thrown.message.includes('AUTHORITY') || thrown.message.includes('ARGUMENT'),
        `the refusal did not name ${key}: ${thrown.message}`,
      );
    }
  });

  test('an argument that names a resource other than the authorized one is refused', () => {
    // Policy authorized task A; the payload mutates task B.
    const error = refuses(
      () => assertCanonicalArguments('tasks.transition', { task_id: 'abt-beta', to_state: 'READY' }, { authorized: { task_id: 'abt-alpha' } }),
      'BLOCKED_POLICY',
    );
    assert.match(error.message, /ARGUMENT_TARGET_MISMATCH|task_id/);
    allows(() => assertCanonicalArguments('tasks.transition', { task_id: 'abt-alpha', to_state: 'READY' }, { authorized: { task_id: 'abt-alpha' } }));
  });

  test('omitting the authorized target is refused: the store must not act on an unnamed resource', () => {
    refuses(
      () => assertCanonicalArguments('tasks.transition', { to_state: 'READY' }, { authorized: { task_id: 'abt-alpha' } }),
      'BLOCKED_POLICY',
    );
  });

  test('a fence or lease id in the payload must be the authorized one and well formed', () => {
    refuses(
      () => assertCanonicalArguments('execution.start', { task_id: 'abt-alpha', lease_id: 'lse-other', fencing_token: 4 }, { authorized: { lease_id: 'lse-alpha', fencing_token: 3 } }),
      'BLOCKED_POLICY',
    );
    refuses(() => assertCanonicalArguments('execution.start', { task_id: 'abt-alpha', fencing_token: -1 }), 'BLOCKED_POLICY');
    refuses(() => assertCanonicalArguments('execution.start', { task_id: 'abt-alpha', fencing_token: 1.5 }), 'BLOCKED_POLICY');
    allows(() => assertCanonicalArguments('execution.start', { task_id: 'abt-alpha', lease_id: 'lse-alpha', fencing_token: 3 }, { authorized: { lease_id: 'lse-alpha', fencing_token: 3 } }));
  });

  test('a target id must belong to its own id family', () => {
    // The public demo id can never be a board target: 'VT-001' is not an abt- id.
    refuses(() => assertCanonicalArguments('tasks.transition', { task_id: 'VT-001' }), 'BLOCKED_POLICY');
    refuses(() => assertCanonicalArguments('tasks.transition', { task_id: '../../etc/passwd' }), 'BLOCKED_POLICY');
    refuses(() => assertCanonicalArguments('tasks.transition', { task_id: 'abt-' }), 'BLOCKED_POLICY');
    refuses(() => assertCanonicalArguments('execution.start', { task_id: 'abt-alpha', lease_id: 'lse-' }), 'BLOCKED_POLICY');
    refuses(() => assertCanonicalArguments('execution.start', { task_id: 'abt-alpha', lease_id: 'lse-A' }), 'BLOCKED_POLICY');
    refuses(() => assertCanonicalArguments('tasks.claim', { task_id: 'abt-alpha', adapter_id: 'adr-../x' }), 'BLOCKED_POLICY');
    allows(() => assertCanonicalArguments('execution.start', { task_id: 'abt-alpha', lease_id: 'lse-alpha' }));
  });

  test('an idempotency key must be 64 lowercase hex characters', () => {
    allows(() => assertCanonicalArguments('tasks.transition', { task_id: 'abt-alpha', idempotency_key: 'a'.repeat(64) }));
    for (const key of ['', 'A'.repeat(64), 'a'.repeat(63), 'zz', 7, null, {}]) {
      refuses(() => assertCanonicalArguments('tasks.transition', { task_id: 'abt-alpha', idempotency_key: key }), 'BLOCKED_POLICY');
    }
  });

  test('an unknown command name and a non-object argument set are refused', () => {
    for (const command of ['TASKS.CREATE', 'tasks', 'tasks_create', '', 'tasks.', null, undefined, 7, {}]) {
      refuses(() => assertCanonicalArguments(command, { task_id: 'abt-alpha' }), 'BLOCKED_POLICY');
    }
    for (const args of [null, undefined, 'task_id', 7, []]) {
      refuses(() => assertCanonicalArguments('tasks.transition', args), 'BLOCKED_POLICY');
    }
  });

  test('a well formed read argument set is allowed', () => {
    allows(() => assertCanonicalArguments('tasks.get', { task_id: 'abt-alpha' }, { allowedKeys: ['task_id'] }));
    allows(() => assertCanonicalArguments('tasks.list', { state: 'READY' }, { allowedKeys: ['state'] }));
  });
});

describe('S2-007 policy: the idempotency key is a function of the canonical arguments', () => {
  test('the same arguments always produce the same key', () => {
    const args = { command: 'tasks.transition', args: { task_id: 'abt-alpha', to_state: 'READY' }, actor: OWNER };
    const first = commandIdempotencyKey(args);
    const second = commandIdempotencyKey(JSON.parse(JSON.stringify(args)));
    assert.equal(first, second);
    assert.match(first, HEX64, 'the key is not the 64 hex chars the board stores');
  });

  test('member order is irrelevant, at every level', () => {
    assert.equal(
      commandIdempotencyKey({ command: 'tasks.create', args: { a: 1, b: 2 }, actor: OWNER }),
      commandIdempotencyKey({ actor: OWNER, args: { b: 2, a: 1 }, command: 'tasks.create' }),
    );
    assert.equal(
      commandIdempotencyKey({ command: 'tasks.create', args: { nested: { x: 1, y: [1, { p: 1, q: 2 }] } }, actor: OWNER }),
      commandIdempotencyKey({ command: 'tasks.create', args: { nested: { y: [1, { q: 2, p: 1 }], x: 1 } }, actor: OWNER }),
    );
  });

  test('array order is significant: it is part of the request, not a set', () => {
    assert.notEqual(
      commandIdempotencyKey({ command: 'tasks.create', args: { tool: ['tool:read', 'tool:write'] } }),
      commandIdempotencyKey({ command: 'tasks.create', args: { tool: ['tool:write', 'tool:read'] } }),
    );
  });

  test('a different value, an added member or a different actor is a different key', () => {
    const base = { command: 'tasks.create', args: { task_id: 'abt-alpha' }, actor: OWNER };
    const key = commandIdempotencyKey(base);
    assert.notEqual(commandIdempotencyKey({ ...base, command: 'tasks.transition' }), key);
    assert.notEqual(commandIdempotencyKey({ ...base, actor: ADAPTER }), key, 'one principal could replay another principal work');
    assert.notEqual(commandIdempotencyKey({ ...base, args: { task_id: 'abt-beta' } }), key);
    assert.notEqual(commandIdempotencyKey({ ...base, args: { task_id: 'abt-alpha', reason: 'x' } }), key);
  });

  test('a non-canonical argument value is refused instead of being silently mangled', () => {
    const circular = { command: 'tasks.create' };
    circular.args = circular;
    for (const bad of [
      { command: 'tasks.create', args: { amount: Number.NaN } },
      { command: 'tasks.create', args: { amount: Number.POSITIVE_INFINITY } },
      { command: 'tasks.create', args: { at: new Date(0) } },
      { command: 'tasks.create', args: { fn: () => 1 } },
      { command: 'tasks.create', args: { big: 1n } },
      { command: 'tasks.create', args: [1, undefined] },
      { command: 'tasks.create', args: new Map() },
      circular,
      undefined,
    ]) {
      refusal(() => commandIdempotencyKey(bad));
    }
  });
});

describe('S2-007 policy: the task ACL is the only visibility authority', () => {
  // The three visibility classes CLASSIFY a task; none of them widens access.
  // The allowlist is the authority in all three, which is why a 'shared' task
  // is not readable by everyone.
  for (const visibility of ['personal', 'project', 'shared']) {
    test(`${visibility}: only an allowlisted principal is visible`, () => {
      const task = taskWith({ acl: { visibility, allowed_principal_ids: [OWNER, ADAPTER] } });
      assert.equal(isVisible(task, OWNER), true);
      assert.equal(isVisible(task, ADAPTER), true);
      for (const stranger of ['prn-stranger', 'prn-owner-2', 'VT-001', 'owner', '', null, undefined, 7, {}]) {
        assert.equal(isVisible(task, stranger), false, `${visibility}: ${String(stranger)} saw the task`);
        refuses(() => assertTaskVisible(task, stranger), 'ACL_DENIED');
      }
      assert.equal(assertTaskVisible(task, OWNER), true);
    });

    test(`${visibility}: an empty allowlist is nobody, not everyone`, () => {
      const task = taskWith({ acl: { visibility, allowed_principal_ids: [] } });
      for (const principal of [OWNER, ADAPTER, 'prn-stranger']) {
        assert.equal(isVisible(task, principal), false, `${visibility}: an empty allowlist was read as a wildcard`);
        refuses(() => assertTaskVisible(task, principal), 'ACL_DENIED');
      }
    });
  }

  test('an unknown or malformed ACL is invisible to everyone', () => {
    for (const acl of [
      { visibility: 'public', allowed_principal_ids: [OWNER] },
      { visibility: 'PROJECT', allowed_principal_ids: [OWNER] },
      { visibility: 'project' },
      { visibility: 'project', allowed_principal_ids: OWNER },
      { visibility: 'project', allowed_principal_ids: [7] },
      { allowed_principal_ids: [OWNER] },
      null,
      'project',
      [],
    ]) {
      assert.equal(isVisible(taskWith({ acl }), OWNER), false, `acl ${JSON.stringify(acl)} was readable`);
      refuses(() => assertTaskVisible(taskWith({ acl }), OWNER), 'ACL_DENIED');
    }
  });

  test('a malformed task is invisible to everyone', () => {
    for (const bad of [null, undefined, 'abt-alpha', [], 7, {}, { task_id: 'abt-alpha' }]) {
      assert.equal(isVisible(bad, OWNER), false);
      refuses(() => assertTaskVisible(bad, OWNER), 'ACL_DENIED');
    }
  });
});

describe('S2-007 policy: the clock and the id factory are injected, never sampled', () => {
  test('a fixed clock returns the same instant forever', () => {
    const clock = fixedClock('2026-03-22T09:30:00.000Z');
    assert.equal(clock.now().toISOString(), '2026-03-22T09:30:00.000Z');
    assert.equal(clock.now().getTime(), clock.now().getTime());
    assert.equal(typeof clock.nowIso, 'function');
    assert.equal(clock.nowIso(), '2026-03-22T09:30:00.000Z');
  });

  test('a malformed instant is refused instead of becoming "now"', () => {
    for (const bad of ['', '2026-03-22', 'not-a-date', 0, null, undefined, new Date(0)]) {
      refusal(() => fixedClock(bad));
    }
  });

  test('the id factory is a pure function of the sequence', () => {
    const ids = sequenceIdFactory('abt-');
    assert.equal(ids(0), ids(0));
    assert.notEqual(ids(0), ids(1));
    assert.match(ids(0), /^abt-[a-z0-9][a-z0-9-]{0,62}$/);
    assert.equal(sequenceIdFactory('abt-', { seed: 7 })(0), `abt-${(7).toString(36).padStart(8, '0')}`);
  });

  test('a malformed prefix, seed or sequence is refused', () => {
    for (const bad of ['', 'ABT-', 'a-', 'abt', 'abtt-', 7, null, undefined]) {
      refusal(() => sequenceIdFactory(bad));
    }
    const ids = sequenceIdFactory('abt-');
    for (const bad of [-1, 1.5, Number.NaN, '0', null, undefined]) {
      refusal(() => ids(bad));
    }
    refusal(() => sequenceIdFactory('abt-', { seed: -1 }));
    refusal(() => sequenceIdFactory('abt-', { seed: 1.5 }));
  });
});

describe('S2-007 policy: redact() removes token-shaped secrets', () => {
  const SECRETS = Object.freeze({
    githubToken: `ghp_${'A'.repeat(36)}`,
    githubPat: `github_pat_${'b'.repeat(22)}_${'c'.repeat(8)}`,
    openAiKey: `sk-${'d'.repeat(32)}`,
    apiKey: 'api_key=SUPERSECRET1234',
    tokenAssignment: 'token: aBcDeFgHiJkLmNoP',
    passwordAssignment: 'password=hunter2hunter2',
    bearer: 'Bearer abcdefghijklmnopqrstuvwxyz',
    // Assembled from parts on purpose: `scripts/check-public-artifacts.mjs` fails the build on any
    // credential-shaped literal in a tracked file, and a test fixture must not be one. The shape
    // redacted() has to catch is still produced exactly.
    privateKey: `-----BEGIN RSA ${'PRIVATE'} KEY-----\nMIIEow\n-----END RSA ${'PRIVATE'} KEY-----`,
    privateLocator: '/home/daniil/.ssh/id_rsa',
  });

  test('no secret survives redaction, whatever its shape', () => {
    for (const [name, secret] of Object.entries(SECRETS)) {
      const text = `adapter failed while calling the API with ${secret} and then timed out`;
      const out = redact(text);
      assert.notEqual(out, text, `${name} was not touched at all`);
      const needle = secret.length > 24 ? secret.slice(0, 24) : secret;
      assert.ok(!out.includes(needle), `${name} survived redaction: ${out}`);
    }
  });

  test('non-secret text is left readable, so a redaction is still diagnosable', () => {
    const text = 'task abt-alpha could not be claimed by adapter adr-test-transport';
    assert.equal(redact(text), text);
    assert.equal(redact('BLOCKED_SANDBOX: profile sbx-no-exec-default executes nothing'), 'BLOCKED_SANDBOX: profile sbx-no-exec-default executes nothing');
  });

  test('a non-string value is passed through, never mangled into a string', () => {
    for (const value of [42, null, undefined, true, { a: 1 }, ['x']]) {
      assert.equal(redact(value), value);
    }
  });

  test('a secret in a message or a detail never reaches a BoardError', () => {
    const error = new AuthRequired('AUTH_REQUIRED', `auth failed for ${SECRETS.githubToken}`);
    assert.ok(!error.message.includes(SECRETS.githubToken), 'the token survived in the message');
    assert.ok(error.message.includes('redacted') || !error.message.includes('ghp_'), `unredacted message: ${error.message}`);

    const withDetail = new BoardError('PROVIDER_FAILURE', 'provider refused', `POST /v1/run with ${SECRETS.openAiKey} and ${SECRETS.apiKey}`);
    assert.ok(!withDetail.detail.includes(SECRETS.openAiKey), 'the key survived in the detail');
    assert.ok(!withDetail.detail.includes('SUPERSECRET1234'), 'the api key survived in the detail');
  });

  test('a message and a detail are bounded so an error cannot become a log dump', () => {
    const error = new BoardError('PROVIDER_FAILURE', 'x'.repeat(5000), 'y'.repeat(5000));
    assert.ok(error.message.length <= 500, `message length ${error.message.length}`);
    assert.ok(error.detail.length <= 2000, `detail length ${error.detail.length}`);
  });
});


// Regression for a proved authority-expansion defect (adversarial review S1):
// `assertActor` used to skip the grant check entirely when `capabilities` was
// ABSENT, and the command layer coerced a missing principal field to `null`,
// which then became `undefined`. A collaborator record with no `capabilities`
// field could therefore grant itself a numeric budget, a claim, an adapter
// registration and a reassignment. An absent grant is not an empty grant: an
// empty grant refuses everything, and an absent one must refuse too.
describe('S2-007 policy: an absent capability grant fails closed', () => {
  const principal = 'prn-absent-grant';
  const now = '2026-09-25T00:00:00.000Z';

  test('a principal with NO capabilities field is refused, not waved through', () => {
    for (const capabilities of [undefined, null]) {
      assert.throws(
        () => assertActor({
          principal, actorKind: 'human_owner', capability: 'board.budget.grant', capabilities, now,
        }),
        (error) => isBoardError(error) && error.code === 'AUTH_REQUIRED',
        `an absent grant (${String(capabilities)}) must be AUTH_REQUIRED, never an allow`,
      );
    }
  });

  test('every command capability is refused without a grant', () => {
    for (const capability of BOARD_CAPABILITIES) {
      assert.throws(
        () => assertActor({ principal, actorKind: 'human_owner', capability, now }),
        (error) => isBoardError(error) && error.code === 'AUTH_REQUIRED',
        `${capability} must not be granted by an absent grant`,
      );
    }
  });

  test('an EMPTY grant is refused exactly like an absent one (nothing is everything)', () => {
    for (const capability of BOARD_CAPABILITIES) {
      assert.throws(
        () => assertActor({
          principal, actorKind: 'human_owner', capability, capabilities: [], now,
        }),
        (error) => isBoardError(error) && error.code === 'AUTH_REQUIRED',
        `${capability} must not be granted by an empty grant`,
      );
    }
  });

  test('a malformed grant is a hard refusal, never a partial allow', () => {
    for (const capabilities of ['board.task.read', 42, {}, ['ok', 7], null]) {
      if (capabilities === null) continue; // covered as the absent case above
      assert.throws(
        () => assertActor({ principal, actorKind: 'human_owner', capability: 'board.task.read', capabilities, now }),
        (error) => isBoardError(error) && error.code === 'BLOCKED_POLICY',
        `a malformed grant (${JSON.stringify(capabilities)}) must be BLOCKED_POLICY`,
      );
    }
  });

  test('a real grant is the only thing that authorizes, and only its own members', () => {
    const granted = ['board.task.read', 'board.budget.grant'];
    const allowed = assertActor({
      principal, actorKind: 'human_owner', capability: 'board.budget.grant', capabilities: granted, now,
    });
    assert.equal(allowed, principal, 'an authorized call returns the server-resolved principal id');
    assert.throws(
      () => assertActor({
        principal, actorKind: 'human_owner', capability: 'board.adapter.register', capabilities: granted, now,
      }),
      (error) => isBoardError(error) && error.code === 'AUTH_REQUIRED',
      'a capability outside the grant stays refused',
    );
  });
});
