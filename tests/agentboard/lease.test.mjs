// S2-007 — LEASES, FENCING AND THE EXECUTION BOUNDARY (issue #7 §4).
//
// WHY THIS FILE EXISTS
// A lease is the only thing that turns "somebody may work on this task" into
// "this specific executor, at this specific moment, may mutate this task". It
// is a right, and a right that cannot be withdrawn is not a right. The four
// properties below are what make the right worth anything:
//
//   1. AT MOST ONE. Exactly one ACTIVE lease per task, with a fencing token
//      taken from a monotonic sequence — never from the clock, never from a
//      counter that a process restart could rewind. A second claim while a
//      lease is ACTIVE is a refusal, and a refusal writes NOTHING: not a task
//      row, not a journal entry, not an outbox row, not a ledger marker.
//   2. REVOKE BEFORE REASSIGN. When a lease is released, revoked, expired or
//      rebound to another adapter, the OLD right is withdrawn in the same
//      transaction that issues the new one, and the new right carries a
//      STRICTLY GREATER fence. A late callback from the previous adapter is
//      then stale by construction and can never win a race it lost.
//   3. A STALE FENCE MUTATES NOTHING. This is decided on the task row, on the
//      transition journal, on the audit log and on the outbox, and it is
//      proved here by comparing the canonical digest of the WHOLE committed
//      dump before and after — not by inspecting a return value the
//      implementation could have shaped. Transition, execution event, result
//      collection, renewal and release are all covered, because a fence that
//      is enforced on only one of them is not a fence.
//   4. EXPIRY IS DECIDED AGAINST THE DATABASE CLOCK, AND IT NEVER REQUEUES
//      BY ITSELF. An expired lease withdraws the right and says so; the task
//      does not silently fall back into READY, because the external side
//      effect of a run that lost its lease is unknown. Only a recorded,
//      human-or-gate-decided reconciliation (guardRequeueAfterReconciliation)
//      may put a RUNNING task back into the queue.
//
// TIER. This file drives the store tier of the frozen spec §3.2 — the surface
// the command boundary and the scheduler sit on. Guards are exercised through
// policy.mjs's frozen `decideTransition` because the store tier deliberately
// does not own policy: it refuses only what the transition table and the lease
// invariant already forbid.
//
// store.mjs is a sibling worker's file. Where a test below fails, the failure
// text names the property that is not implemented yet; a fixture error would
// instead surface as NEEDS_INPUT/AUTH_REQUIRED on a setup call.
//
// DETERMINISM. One injected clock (mutable, but never the process clock) and
// one injected id factory. No Date.now(), no Math.random().

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { InMemoryAgentBoardStore } from '../../src/lib/agentboard/store.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { isBoardError } from '../../src/lib/agentboard/errors.mjs';
import { ERROR_CODES, ID_PREFIXES, NON_RETRYABLE_CODES, TRANSITIONS } from '../../src/lib/agentboard/constants.mjs';
import { decideTransition, fixedClock, commandIdempotencyKey } from '../../src/lib/agentboard/policy.mjs';

const WORKSPACE = 'ws-lease-boundary';
const OWNER = 'prn-lease-owner';
const REVIEWER = 'prn-lease-reviewer';
const SCHEDULER = 'prn-lease-scheduler';
const PRODUCER = 'prn-lease-producer';
const RECONCILER = 'prn-lease-reconciler';
const PROFILE = 'sbx-podman-local-restricted-v1';
const TASK_ID = 'abt-lease-1';
const SECOND_TASK_ID = 'abt-lease-2';
const ADAPTER_A = 'adr-lease-a';
const ADAPTER_B = 'adr-lease-b';
const GRANT_ID = 'grt-lease-1';
const T0 = '2026-09-25T12:00:00.000Z';
const TTL_MS = 60_000;

// The closed typed error set. A refusal on this boundary is a member of it,
// never a plain Error and never a free-form string.
const CLOSED_CODES = new Set(ERROR_CODES);
const NON_RETRYABLE = new Set(NON_RETRYABLE_CODES);
const ALL_SCOPES = ['task.read', 'task.write', 'artifact.write', 'evidence.submit', 'checkpoint.write', 'budget.spend'];

const digest = (char) => `sha256:${char.repeat(64)}`;
const BRIEF = digest('b');
const POLICY = digest('c');
const MANIFEST = digest('d');

/**
 * Deterministic id factory: one monotonic counter shared by every kind, so
 * every generated id is unique without a random source.
 */
function deterministicIds() {
  const counters = new Map();
  return (kind) => {
    const next = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, next);
    return `${next.toString(36).padStart(6, '0')}`;
  };
}

/**
 * A store whose clock the TEST controls. The store reads the clock exactly
 * once per transaction, so moving `now` between calls is what "the clock
 * moved" means here — never the process clock.
 */
function makeStore({ now = T0, seed = 's2-007-lease' } = {}) {
  const state = { now };
  const store = new InMemoryAgentBoardStore({
    clock: () => new Date(state.now),
    ids: deterministicIds(),
    seed,
  });
  store.setNow = (iso) => { state.now = iso; };
  return store;
}

function taskDocument(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    task_id: TASK_ID,
    workspace_id: WORKSPACE,
    title: 'Bounded source collection with an independent review',
    goal: 'Assemble and verify the source set for the alpha claim',
    description: 'A bounded, human-reviewed collection task.',
    acceptance_criteria: ['At least 3 primary sources with digests'],
    state: 'BACKLOG',
    revision: 1,
    priority: 'HIGH',
    dependencies: [],
    required_capabilities: ['source.read'],
    allowed_tools: ['tool:fs.read'],
    workspace_ref: {
      workspace_id: WORKSPACE,
      root_ref: 'projects/alpha',
      isolation_profile_id: PROFILE,
      sandbox_profile_digest: digest('a'),
      read_only_paths: ['vendor'],
    },
    time_limits: { timeout_ms: 60_000, max_runtime_ms: 120_000, deadline: null },
    cost_limits: { currency: 'USD', max_task_cost: 5, max_campaign_cost: 20, max_day_cost: 10 },
    acl: { visibility: 'project', allowed_principal_ids: [OWNER, REVIEWER, SCHEDULER, PRODUCER, RECONCILER] },
    brief_digest: BRIEF,
    policy_digest: POLICY,
    manifest_digest: MANIFEST,
    assigned_adapter_id: null,
    active_lease_id: null,
    fencing_token: null,
    attempts: 0,
    artifacts: [],
    evidence_refs: [],
    block_reason: null,
    created_at: T0,
    updated_at: T0,
    history_digest: digest('e'),
    ...overrides,
  };
}

function adapterRegistration(adapterId, principalId) {
  return {
    contractVersion: '1.0.0',
    adapter_id: adapterId,
    adapter_interface: 'veritas.adapter/1.0.0',
    provider: 'test',
    display_name: `Test transport ${adapterId}`,
    adapter_kind: 'test',
    health: 'healthy',
    workspace_id: WORKSPACE,
    principal_id: principalId,
    declared_capabilities: ['source.read'],
    declared_tools: ['tool:fs.read'],
    sandbox_profile_id: PROFILE,
    max_concurrency: 1,
    // No genuinely installed executor backs a test transport, so this is the
    // honest provenance and it is never upgraded by fixture evidence.
    real_adapter_provenance: {
      status: 'NOT_RUN_REAL_ADAPTER',
      detail: 'test transport: no installed executor is bound to this adapter',
    },
    registered_at: T0,
  };
}

function budgetGrant(overrides = {}) {
  return {
    grant_id: GRANT_ID,
    workspace_id: WORKSPACE,
    task_id: TASK_ID,
    currency: 'USD',
    task_limit: 5,
    campaign_limit: 20,
    day_limit: 10,
    timeout_ms: 60_000,
    granted_by: OWNER,
    ...overrides,
  };
}

/** The command key the boundary computes: command + args + actor. */
function key(command, args, actor = SCHEDULER) {
  return commandIdempotencyKey({ command, args, actor });
}

async function createTask(store, task = taskDocument(), actor = OWNER) {
  const k = key('tasks.create', { task_id: task.task_id, title: task.title }, actor);
  return store.createTask({ task, actor, actorKind: 'human_owner', idempotencyKey: k, argsDigest: k });
}

async function moveToReady(store, taskId, actor = OWNER) {
  const task = await store.getTask(taskId, { workspaceId: WORKSPACE, principalId: actor });
  const k = key('tasks.transition', { task_id: taskId, to: 'READY', revision: task.revision }, actor);
  return store.transitionTask({
    taskId,
    toState: 'READY',
    expectedRevision: task.revision,
    actor,
    actorKind: 'human_owner',
    reason: 'brief validated, dependencies closed, budget assigned',
    idempotencyKey: k,
    argsDigest: k,
    outboxEvent: { event_type: 'board.task.transitioned', payload: { task_id: taskId, to: 'READY' } },
  });
}

async function registerAdapter(store, adapterId = ADAPTER_A, principalId = PRODUCER) {
  const registration = adapterRegistration(adapterId, principalId);
  const k = key('adapters.register', { adapter_id: adapterId }, OWNER);
  return store.registerAdapter({ registration, actor: OWNER, idempotencyKey: k, argsDigest: k });
}

async function assignBudget(store, grant = budgetGrant()) {
  const k = key('budget.grant', { grant_id: grant.grant_id }, OWNER);
  return store.grantBudget({ grant, actor: OWNER, idempotencyKey: k, argsDigest: k });
}

async function claim(store, {
  taskId = TASK_ID, adapterId = ADAPTER_A, expectedRevision = 2, ttlMs = TTL_MS, actor = SCHEDULER, actorKind = 'scheduler',
} = {}) {
  const k = key('tasks.claim', { task_id: taskId, adapter_id: adapterId, revision: expectedRevision }, actor);
  return store.claimTask({
    taskId,
    workspaceId: WORKSPACE,
    adapterId,
    ttlMs,
    expectedRevision,
    actor,
    actorKind,
    idempotencyKey: k,
    argsDigest: k,
  });
}

/**
 * Full committed state as ONE canonical digest. `debugSnapshot()` is the
 * store's own dump and covers every table including the ones the public reads
 * do not expose (the operation ledger, the fence counter). The fallback keeps
 * the property testable if that helper disappears: it then hashes exactly the
 * public reads the assertions rely on (task, journal, leases, runs, audit,
 * outbox) and is still a whole-state comparison.
 *
 * `includeLedger: false` drops the idempotency ledger. A sweep that finds
 * nothing still marks its own operation (that marker IS its idempotency key,
 * derived from the observed database time, and is what makes a repeated sweep
 * at the same instant a replay instead of a second effect). A marker is
 * bookkeeping, not a state change, so the "a sweep that finds nothing
 * changes no entity" claim is made without it — and the marker is then
 * asserted separately.
 */
async function stateDigest(store, { taskId = TASK_ID, principalId = OWNER, includeLedger = true } = {}) {
  if (includeLedger && typeof store.debugSnapshot === 'function') {
    return canonicalDigest(JSON.parse(JSON.stringify(await store.debugSnapshot())));
  }
  return canonicalDigest({
    task: await store.getTask(taskId, { workspaceId: WORKSPACE, principalId }),
    transitions: await store.listTransitions(taskId, { workspaceId: WORKSPACE, principalId }),
    leases: await store.listLeases({ workspaceId: WORKSPACE, taskId }),
    runs: await store.listRuns({ workspaceId: WORKSPACE, taskId }),
    audit: await store.listAudit({ workspaceId: WORKSPACE, taskId }),
    outbox: await store.listOutbox({ workspaceId: WORKSPACE }),
  });
}

/**
 * A refusal on this boundary is a TYPED, non-retryable BoardError from the
 * closed set. `codes` is the set of codes the frozen spec permits for this
 * specific refusal — the test names which decision it is asserting, so an
 * implementation cannot satisfy it with a different, weaker error.
 */
async function expectRefusal(promise, codes, label) {
  let resolved = null;
  let thrown = null;
  try {
    resolved = await promise;
  } catch (error) {
    thrown = error;
  }
  assert.equal(resolved, null, `${label}: the call must be REFUSED, it resolved with ${JSON.stringify(resolved)}`);
  assert.ok(thrown !== null, `${label}: the call must reject`);
  assert.ok(isBoardError(thrown), `${label}: a refusal must be a typed BoardError, got ${thrown?.name}: ${thrown?.message}`);
  assert.ok(CLOSED_CODES.has(thrown.code), `${label}: ${thrown.code} is not a member of the closed ERROR_CODES set`);
  assert.ok(
    (Array.isArray(codes) ? codes : [codes]).includes(thrown.code),
    `${label}: expected one of ${[].concat(codes).join('|')}, got ${thrown.code} (${thrown.message})`,
  );
  return thrown;
}

/** Everything a claim needs: a task in READY, a registered adapter, a budget. */
async function readyToClaim(store, { taskId = TASK_ID, adapterId = ADAPTER_A } = {}) {
  await createTask(store, taskDocument({ task_id: taskId }));
  await moveToReady(store, taskId);
  await registerAdapter(store, adapterId);
  await registerAdapter(store, adapterId === ADAPTER_A ? ADAPTER_B : ADAPTER_A, PRODUCER);
  await assignBudget(store, budgetGrant({ task_id: taskId, grant_id: `grt-${taskId.slice(4)}` }));
  return store.getTask(taskId, { workspaceId: WORKSPACE, principalId: OWNER });
}

// ===========================================================================
// 1. AT MOST ONE ACTIVE LEASE, WITH A MONOTONIC FENCE
// ===========================================================================

describe('S2-007 lease: claimTask issues exactly one ACTIVE lease with a strictly monotonic fence', () => {
  test('the claim binds the lease, the fence and the adapter to the task row in one write', async () => {
    const store = makeStore();
    await readyToClaim(store);

    const claimed = await claim(store);
    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    const lease = await store.readLease(claimed.lease_id);

    assert.equal(claimed.replayed, false, 'a first claim is a fresh commit, not a replay');
    assert.equal(lease.lease_state, 'ACTIVE', 'the issued lease is the right to act');
    assert.equal(lease.task_id, TASK_ID);
    assert.equal(lease.adapter_id, ADAPTER_A);
    assert.equal(lease.principal_id, SCHEDULER);
    assert.match(lease.lease_id, new RegExp(`^${ID_PREFIXES.lease}`));
    assert.equal(task.state, 'CLAIMED', 'READY->CLAIMED is driven by the claim, in the same transaction');
    assert.equal(task.active_lease_id, claimed.lease_id);
    assert.equal(task.fencing_token, claimed.fencing_token, 'the task row carries the fence of the ACTIVE lease');
    assert.equal(task.assigned_adapter_id, ADAPTER_A);
    assert.equal(task.attempts, 1, 'one claim is one attempt');

    const active = await store.listLeases({ workspaceId: WORKSPACE, taskId: TASK_ID, leaseState: 'ACTIVE' });
    assert.equal(active.length, 1, 'exactly one ACTIVE lease per task');
    assert.equal((await store.listLeases({ workspaceId: WORKSPACE, taskId: TASK_ID })).length, 1);
  });

  test('the fence comes from a monotonic sequence: every later claim is strictly greater', async () => {
    const store = makeStore();
    await readyToClaim(store, { taskId: TASK_ID, adapterId: ADAPTER_A });
    const first = await claim(store, { taskId: TASK_ID, adapterId: ADAPTER_A });

    await createTask(store, taskDocument({ task_id: SECOND_TASK_ID }));
    await moveToReady(store, SECOND_TASK_ID);
    const second = await claim(store, { taskId: SECOND_TASK_ID, adapterId: ADAPTER_B, expectedRevision: 2 });

    assert.ok(
      Number(second.fencing_token) > Number(first.fencing_token),
      `the fencing sequence must be strictly increasing: ${first.fencing_token} then ${second.fencing_token}`,
    );
    assert.ok(Number(first.fencing_token) >= 1, 'a fence is a positive integer');

    // A fence is never a timestamp and never derived from the clock: moving
    // the injected clock by a year must not change the allocation.
    const other = makeStore({ seed: 's2-007-lease-fence' });
    await readyToClaim(other, { taskId: TASK_ID, adapterId: ADAPTER_A });
    other.setNow('2027-09-25T12:00:00.000Z');
    const third = await claim(other, { taskId: TASK_ID, adapterId: ADAPTER_A });
    assert.equal(Number(third.fencing_token), Number(first.fencing_token), 'the fence is a sequence, not a clock reading');
  });

  test('a second claim while a lease is ACTIVE is refused and writes nothing', async () => {
    const store = makeStore();
    await readyToClaim(store);
    const claimed = await claim(store);
    const before = await stateDigest(store);
    const beforeLease = await store.readLease(claimed.lease_id);

    // (a) the natural race loser: the same expected revision it presented.
    await expectRefusal(
      claim(store, { adapterId: ADAPTER_B }),
      ['REVISION_CONFLICT', 'TRANSITION_NOT_ALLOWED'],
      'second claim with the consumed expected revision',
    );
    // (b) a caller that re-read the revision first and tries anyway: the lease
    //     is still the only right, and the second claim is still refused.
    const refreshed = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    await expectRefusal(
      claim(store, { adapterId: ADAPTER_B, expectedRevision: refreshed.revision }),
      ['TRANSITION_NOT_ALLOWED', 'REVISION_CONFLICT'],
      'second claim against a live lease',
    );

    assert.equal(await stateDigest(store), before, 'a refused claim must leave the whole store byte-identical');
    const active = await store.listLeases({ workspaceId: WORKSPACE, taskId: TASK_ID, leaseState: 'ACTIVE' });
    assert.equal(active.length, 1, 'a refused claim must not create a second lease');
    assert.deepEqual(await store.readLease(claimed.lease_id), beforeLease, 'the winning lease is untouched');
    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(task.state, 'CLAIMED');
    assert.equal(task.attempts, 1, 'a refused claim does not consume an attempt');
  });
});

// ===========================================================================
// 2. RENEWAL IS BOUND TO THE CURRENT FENCE
// ===========================================================================

describe('S2-007 lease: renewLease extends only for the current fence', () => {
  test('a renewal at the current fence extends the lease and changes nothing else', async () => {
    const store = makeStore();
    await readyToClaim(store);
    const claimed = await claim(store, { ttlMs: 1_000 });
    const before = await store.readLease(claimed.lease_id);
    const taskBefore = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });

    store.setNow('2026-09-25T12:00:30.000Z');
    const k = key('tasks.lease.renew', { lease_id: claimed.lease_id, fence: claimed.fencing_token });
    const renewed = await store.renewLease({
      leaseId: claimed.lease_id,
      fencingToken: claimed.fencing_token,
      ttlMs: TTL_MS,
      actor: SCHEDULER,
      idempotencyKey: k,
      argsDigest: k,
    });

    const after = await store.readLease(claimed.lease_id);
    assert.equal(renewed.replayed, false);
    assert.equal(after.lease_state, 'ACTIVE', 'a renewal keeps the right alive');
    assert.equal(after.fencing_token, before.fencing_token, 'a renewal NEVER changes the fence');
    assert.equal(after.issued_at, before.issued_at, 'a renewal does not re-issue the lease');
    assert.ok(
      Date.parse(after.expires_at) > Date.parse(before.expires_at),
      'a renewal must actually extend the window',
    );
    assert.equal(after.expires_at, renewed.expires_at);

    const taskAfter = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(taskAfter.revision, taskBefore.revision, 'a renewal is not a state change and must not bump the revision');
    assert.equal(taskAfter.fencing_token, taskBefore.fencing_token);
    assert.equal(taskAfter.state, 'CLAIMED');
    const journal = await store.listTransitions(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(journal.length, 2, 'only BACKLOG->READY and READY->CLAIMED are journalled; a renewal adds none');
  });

  test('a renewal with a stale fence, a guessed fence or no fence is refused and changes nothing', async () => {
    const store = makeStore();
    await readyToClaim(store);
    const claimed = await claim(store);
    const before = await stateDigest(store);
    const fence = Number(claimed.fencing_token);

    for (const [label, token] of [
      ['a superseded fence', fence - 1],
      ['a fence that was never issued', fence + 7],
      ['no fence at all', undefined],
    ]) {
      const k = key('tasks.lease.renew', { lease_id: claimed.lease_id, fence: token ?? null });
      const error = await expectRefusal(
        store.renewLease({ leaseId: claimed.lease_id, fencingToken: token, ttlMs: TTL_MS, actor: SCHEDULER, idempotencyKey: k, argsDigest: k }),
        ['STALE_FENCE'],
        `renewal with ${label}`,
      );
      assert.ok(NON_RETRYABLE.has(error.code), `${error.code} must never be presented as a blind retry`);
      assert.equal(await stateDigest(store), before, `renewal with ${label} must leave the store byte-identical`);
    }

    const lease = await store.readLease(claimed.lease_id);
    assert.equal(lease.lease_state, 'ACTIVE', 'the live right survives the refused renewals');
    assert.equal(lease.fencing_token, fence);
  });
});

// ===========================================================================
// 3. REVOKE BEFORE REASSIGN, AND A STRICTLY GREATER FENCE FOR THE NEW RIGHT
// ===========================================================================

describe('S2-007 lease: the old right is revoked before any reassignment, and the new fence is greater', () => {
  test('reassignLease revokes the previous lease first and issues a strictly greater fence', async () => {
    const store = makeStore();
    await readyToClaim(store);
    const first = await claim(store, { adapterId: ADAPTER_A });

    const k = key('tasks.lease.reassign', { lease_id: first.lease_id, adapter: ADAPTER_B });
    const rebound = await store.reassignLease({
      leaseId: first.lease_id,
      fencingToken: first.fencing_token,
      newAdapterId: ADAPTER_B,
      reason: 'the first adapter is unreachable; hand the right to the second',
      actor: OWNER,
      actorKind: 'human_owner',
      idempotencyKey: k,
      argsDigest: k,
    });

    const oldLease = await store.readLease(first.lease_id);
    const newLease = await store.readLease(rebound.lease_id);

    assert.notEqual(rebound.lease_id, first.lease_id, 'a reassignment issues a NEW lease, it does not edit the old one');
    assert.equal(oldLease.lease_state, 'REVOKED', 'the previous right is withdrawn');
    assert.ok(oldLease.released_at !== null, 'the revocation is timestamped');
    assert.equal(newLease.lease_state, 'ACTIVE');
    assert.equal(newLease.adapter_id, ADAPTER_B);
    assert.ok(
      Number(newLease.fencing_token) > Number(first.fencing_token),
      `the reassigned lease must carry a strictly greater fence: ${first.fencing_token} then ${newLease.fencing_token}`,
    );
    assert.ok(
      Date.parse(oldLease.released_at) <= Date.parse(newLease.issued_at),
      'revocation must not be later than the issue of the new right',
    );

    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(task.state, 'CLAIMED', 'a rebind does not move the task out of its executing state');
    assert.equal(task.active_lease_id, rebound.lease_id);
    assert.equal(task.fencing_token, rebound.fencing_token);
    assert.equal(task.assigned_adapter_id, ADAPTER_B);

    const active = await store.listLeases({ workspaceId: WORKSPACE, taskId: TASK_ID, leaseState: 'ACTIVE' });
    assert.equal(active.length, 1, 'still exactly one ACTIVE lease after a rebind');

    const journal = await store.listTransitions(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    const rebind = journal.at(-1);
    // A rebind changes no state, so the journal entry is a same-state record.
    // The board-transition contract exposes no payload member, so what the
    // journal can be asked to prove here is: which lease, which fence, and
    // that the state did not move.
    assert.equal(rebind.from_state, 'CLAIMED');
    assert.equal(rebind.to_state, 'CLAIMED');
    assert.equal(rebind.lease_id, rebound.lease_id, 'the journal entry records the NEW lease');
    assert.equal(rebind.fencing_token, rebound.fencing_token, 'the journal entry records the NEW fence');
    assert.notEqual(rebind.lease_id, first.lease_id, 'the withdrawn right is not the one the history points at');
  });

  test('a late callback from the adapter that lost the lease mutates nothing', async () => {
    const store = makeStore();
    await readyToClaim(store);
    const first = await claim(store, { adapterId: ADAPTER_A });
    const k = key('tasks.lease.reassign', { lease_id: first.lease_id, adapter: ADAPTER_B });
    const rebound = await store.reassignLease({
      leaseId: first.lease_id,
      fencingToken: first.fencing_token,
      newAdapterId: ADAPTER_B,
      reason: 'the first adapter is unreachable; hand the right to the second',
      actor: OWNER,
      actorKind: 'human_owner',
      idempotencyKey: k,
      argsDigest: k,
    });
    const afterRebind = await stateDigest(store);

    // The old holder comes back and tries to give the lease back. Its right is
    // gone: the fence it still holds is no longer current.
    const releaseKey = key('tasks.lease.release', { lease_id: first.lease_id, fence: first.fencing_token });
    await expectRefusal(
      store.releaseLease({
        leaseId: first.lease_id,
        fencingToken: first.fencing_token,
        reason: 'the work finished',
        expectedRevision: (await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER })).revision,
        actor: SCHEDULER,
        actorKind: 'adapter',
        idempotencyKey: releaseKey,
        argsDigest: releaseKey,
      }),
      ['STALE_FENCE'],
      'release presented by the adapter that lost the lease',
    );
    assert.equal(await stateDigest(store), afterRebind, 'a late callback must change nothing');

    // The current holder may still release — the fence, not the adapter id, is
    // what the store trusts, and the new lease is the current right.
    const newLease = await store.readLease(rebound.lease_id);
    assert.equal(newLease.lease_state, 'ACTIVE');
  });

  test('releaseLease withdraws the right, clears the task pointer and hands the next claim a greater fence', async () => {
    const store = makeStore();
    await readyToClaim(store);
    const first = await claim(store, { adapterId: ADAPTER_A });

    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    const k = key('tasks.lease.release', { lease_id: first.lease_id, to: 'READY' });
    const released = await store.releaseLease({
      leaseId: first.lease_id,
      fencingToken: first.fencing_token,
      reason: 'the adapter returned the task to the queue voluntarily',
      expectedRevision: task.revision,
      actor: SCHEDULER,
      actorKind: 'scheduler',
      idempotencyKey: k,
      argsDigest: k,
      toState: 'READY',
    });

    const lease = await store.readLease(first.lease_id);
    assert.equal(lease.lease_state, 'RELEASED');
    assert.equal(released.task.state, 'READY');
    assert.equal(released.task.active_lease_id, null, 'a released lease is no longer the task pointer');
    assert.equal(released.task.fencing_token, null, 'no lease means no current fence');

    const second = await claim(store, { adapterId: ADAPTER_B, expectedRevision: released.revision });
    assert.ok(
      Number(second.fencing_token) > Number(first.fencing_token),
      'a re-claim after a release must receive a strictly greater fence',
    );
  });

  test('revokeLease withdraws the right without inventing a state change', async () => {
    const store = makeStore();
    await readyToClaim(store);
    const claimed = await claim(store);

    const k = key('tasks.lease.revoke', { lease_id: claimed.lease_id });
    const revoked = await store.revokeLease({
      leaseId: claimed.lease_id,
      fencingToken: claimed.fencing_token,
      reason: 'the operator withdrew the lease pending an audit',
      actor: OWNER,
      actorKind: 'human_owner',
      idempotencyKey: k,
      argsDigest: k,
    });

    const lease = await store.readLease(claimed.lease_id);
    assert.equal(lease.lease_state, 'REVOKED');
    assert.equal(revoked.task.active_lease_id, null);
    assert.equal(revoked.task.fencing_token, null);
    assert.equal(revoked.task.state, 'CLAIMED', 'a revocation withdraws the right; the state is decided by an explicit transition');

    // And the withdrawn fence is dead: nothing may be written with it.
    const after = await stateDigest(store);
    const renewKey = key('tasks.lease.renew', { lease_id: claimed.lease_id, fence: claimed.fencing_token });
    await expectRefusal(
      store.renewLease({
        leaseId: claimed.lease_id,
        fencingToken: claimed.fencing_token,
        ttlMs: TTL_MS,
        actor: SCHEDULER,
        idempotencyKey: renewKey,
        argsDigest: renewKey,
      }),
      ['STALE_FENCE'],
      'renewal of a revoked lease',
    );
    assert.equal(await stateDigest(store), after);
  });
});

// ===========================================================================
// 4. A STALE FENCE IS REFUSED ON EVERY OPERATION THAT MUTATES THE TASK
// ===========================================================================

/**
 * Build a CLAIMED task with a live run bound to the current lease: claim →
 * budget-backed run → dispatched. The task deliberately stays in CLAIMED: the
 * fence-guarded transition is CLAIMED -> RUNNING (an edge INTO an executing
 * state), and a fence is only checked on the edges that carry the right. Every
 * document here is contract-valid on purpose: a stale fence must be the ONLY
 * reason a call is refused, otherwise the test would pass for the wrong reason.
 */
async function claimedTaskWithRun(store) {
  await readyToClaim(store);
  const claimed = await claim(store, { ttlMs: TTL_MS });
  const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });

  const request = {
    contract_version: 'veritas.execution/1.0.0',
    request_id: 'xer-lease-1',
    idempotency_key: commandIdempotencyKey({ command: 'execution.start', args: { task_id: TASK_ID } }),
    task_id: TASK_ID,
    workspace_id: WORKSPACE,
    brief_digest: BRIEF,
    policy_digest: POLICY,
    manifest_digest: MANIFEST,
    principal_id: PRODUCER,
    granted_scope: ALL_SCOPES,
    allowed_tools: ['tool:fs.read'],
    workspace_ref: taskDocument().workspace_ref,
    budget_grant: {
      currency: 'USD',
      task_limit: 5,
      campaign_limit: 20,
      day_limit: 10,
      timeout_ms: 60_000,
      granted_by: OWNER,
      granted_at: T0,
    },
    deadline: null,
    lease_id: claimed.lease_id,
    fencing_token: claimed.fencing_token,
    adapter_id: ADAPTER_A,
    issued_at: T0,
  };
  const startKey = key('execution.start', { request_id: request.request_id });
  const run = await store.createRun({ request, actor: SCHEDULER, idempotencyKey: startKey, argsDigest: startKey });
  const dispatchKey = key('execution.dispatch', { run_id: run.run_id });
  await store.markRunDispatched({ runId: run.run_id, actor: SCHEDULER, idempotencyKey: dispatchKey, argsDigest: dispatchKey });
  return {
    claim: claimed,
    lease: await store.readLease(claimed.lease_id),
    run,
    task,
    fence: Number(claimed.fencing_token),
    revision: task.revision,
  };
}

function executionEvent(overrides = {}) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    event_id: 'eve-lease-1',
    run_id: 'run-placeholder',
    task_id: TASK_ID,
    workspace_id: WORKSPACE,
    lease_id: 'lse-placeholder',
    fencing_token: 1,
    sequence: 1,
    event_type: 'PROGRESS',
    payload: { note: 'untrusted executor data' },
    outcome: null,
    emitted_at: T0,
    ...overrides,
  };
}

function executionResult(overrides = {}) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    run_id: 'run-placeholder',
    task_id: TASK_ID,
    workspace_id: WORKSPACE,
    lease_id: 'lse-placeholder',
    fencing_token: 1,
    sequence: 1,
    outcome: 'SUCCEEDED',
    checkpoints: [],
    artifact_hashes: [],
    measurements: { duration_ms: 120, spend: 0.25, currency: 'USD', model_id: null, tool_calls: 2 },
    error: null,
    reconciliation_required: false,
    completed_at: T0,
    ...overrides,
  };
}

describe('S2-007 lease: a stale fencing token is refused on every mutating operation, and mutates nothing', () => {
  /** Each entry is one operation the fence is supposed to guard. */
  const operations = [
    {
      name: 'tasks.transition',
      // The revision presented is the CURRENT one on purpose: the store
      // checks the compare-and-swap before the fence, so a stale revision here
      // would make the test pass on REVISION_CONFLICT and never exercise the
      // fence at all. The target is an EXECUTING state because that is where
      // the right is carried; an edge out of an executing state is refused for
      // a different reason (the lease must be withdrawn first) and would prove
      // nothing about the fence.
      build: ({ claim, staleFence, revision }) => (store) => {
        const k = key('tasks.transition', { task_id: TASK_ID, to: 'RUNNING', fence: staleFence });
        return store.transitionTask({
          taskId: TASK_ID,
          toState: 'RUNNING',
          expectedRevision: revision,
          actor: SCHEDULER,
          actorKind: 'adapter',
          reason: 'the run is starting under the current lease',
          lease: claim.lease_id,
          fencingToken: staleFence,
          idempotencyKey: k,
          argsDigest: k,
        });
      },
    },
    {
      name: 'execution.event',
      build: ({ claim, run, staleFence }) => (store) => {
        const event = executionEvent({ run_id: run.run_id, lease_id: claim.lease_id, fencing_token: staleFence });
        const k = key('execution.event', { event_id: event.event_id, fence: staleFence });
        return store.appendExecutionEvent({ event, actor: PRODUCER, idempotencyKey: k, argsDigest: k });
      },
    },
    {
      name: 'execution.collect_result',
      build: ({ claim, run, staleFence }) => (store) => {
        const result = executionResult({ run_id: run.run_id, lease_id: claim.lease_id, fencing_token: staleFence });
        const k = key('execution.collect_result', { run_id: run.run_id, fence: staleFence });
        return store.collectResult({ result, actor: PRODUCER, idempotencyKey: k, argsDigest: k });
      },
    },
    {
      name: 'tasks.lease.renew',
      build: ({ claim, staleFence }) => (store) => {
        const k = key('tasks.lease.renew', { lease_id: claim.lease_id, fence: staleFence });
        return store.renewLease({
          leaseId: claim.lease_id,
          fencingToken: staleFence,
          ttlMs: TTL_MS,
          actor: SCHEDULER,
          idempotencyKey: k,
          argsDigest: k,
        });
      },
    },
    {
      name: 'tasks.lease.release',
      build: ({ claim, staleFence }) => async (store) => {
        const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
        const k = key('tasks.lease.release', { lease_id: claim.lease_id, fence: staleFence });
        return store.releaseLease({
          leaseId: claim.lease_id,
          fencingToken: staleFence,
          reason: 'the holder gives the right back',
          expectedRevision: task.revision,
          actor: SCHEDULER,
          actorKind: 'adapter',
          idempotencyKey: k,
          argsDigest: k,
        });
      },
    },
  ];

  for (const operation of operations) {
    test(`${operation.name} refuses a superseded fence and leaves the whole store byte-identical`, async () => {
      const store = makeStore({ seed: `s2-007-lease-stale-${operation.name}` });
      const context = await claimedTaskWithRun(store);
      const before = await stateDigest(store);
      // Row counts make the "no journal or outbox row" claim readable on its
      // own, next to the whole-dump digest that proves it byte for byte.
      const journalBefore = (await store.listTransitions(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER })).length;
      const auditBefore = (await store.listAudit({ workspaceId: WORKSPACE, taskId: TASK_ID })).length;
      const outboxBefore = (await store.listOutbox({ workspaceId: WORKSPACE })).length;

      // A fence the store never issued (below) and one it issued but superseded
      // (the previous lease of this task, i.e. below 1 here) are both stale.
      const staleFence = context.fence - 1;
      const error = await expectRefusal(
        operation.build({ ...context, staleFence })(store),
        ['STALE_FENCE'],
        `${operation.name} with fence ${staleFence}`,
      );
      assert.ok(NON_RETRYABLE.has(error.code), 'a stale fence is never a blind retry');

      assert.equal(
        await stateDigest(store),
        before,
        `${operation.name}: the task row, the journal, the audit log and the outbox must be byte-identical after a stale fence`,
      );

      const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
      assert.equal(task.state, 'CLAIMED', `${operation.name}: the state must not move`);
      assert.equal(task.fencing_token, context.fence, `${operation.name}: the current fence must survive`);
      assert.equal(
        (await store.listTransitions(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER })).length,
        journalBefore,
        `${operation.name}: no journal row may be appended`,
      );
      assert.equal(
        (await store.listAudit({ workspaceId: WORKSPACE, taskId: TASK_ID })).length,
        auditBefore,
        `${operation.name}: no audit row may be written`,
      );
      assert.equal(
        (await store.listOutbox({ workspaceId: WORKSPACE })).length,
        outboxBefore,
        `${operation.name}: no outbox row may be written`,
      );
    });
  }

  test('the same five operations also refuse a fence that was never issued', async () => {
    for (const operation of operations) {
      const store = makeStore({ seed: `s2-007-lease-unissued-${operation.name}` });
      const context = await claimedTaskWithRun(store);
      const before = await stateDigest(store);
      const unissued = context.fence + 5;

      await expectRefusal(
        operation.build({ ...context, staleFence: unissued })(store),
        ['STALE_FENCE'],
        `${operation.name} with the unissued fence ${unissued}`,
      );
      assert.equal(await stateDigest(store), before, `${operation.name}: an unissued fence must change nothing`);
    }
  });

  test('the CURRENT fence still works on the same operations', async () => {
    // The anti-pattern this file guards against is a fence check that refuses
    // everything. Each guarded operation must accept the current fence,
    // otherwise the stale-fence assertions above would pass vacuously.
    const store = makeStore({ seed: 's2-007-lease-current-fence' });
    const context = await claimedTaskWithRun(store);
    const { claim, run, fence, revision } = context;

    // (a) the transition: CLAIMED -> RUNNING at the current fence.
    const moveKey = key('tasks.transition', { task_id: TASK_ID, to: 'RUNNING' });
    const running = await store.transitionTask({
      taskId: TASK_ID,
      toState: 'RUNNING',
      expectedRevision: revision,
      actor: SCHEDULER,
      actorKind: 'adapter',
      reason: 'the run is starting under the current lease',
      lease: claim.lease_id,
      fencingToken: fence,
      idempotencyKey: moveKey,
      argsDigest: moveKey,
    });
    assert.equal(running.task.state, 'RUNNING', 'the current fence drives a state change');
    assert.equal(running.task.fencing_token, fence);

    const event = executionEvent({ run_id: run.run_id, lease_id: claim.lease_id, fencing_token: fence });
    const eventKey = key('execution.event', { event_id: event.event_id });
    const appended = await store.appendExecutionEvent({ event, actor: PRODUCER, idempotencyKey: eventKey, argsDigest: eventKey });
    assert.equal(appended.sequence, 1);

    const renewKey = key('tasks.lease.renew', { lease_id: claim.lease_id, fence });
    const renewed = await store.renewLease({
      leaseId: claim.lease_id, fencingToken: fence, ttlMs: TTL_MS, actor: SCHEDULER, idempotencyKey: renewKey, argsDigest: renewKey,
    });
    assert.equal(renewed.lease.fencing_token, fence);

    const result = executionResult({ run_id: run.run_id, lease_id: claim.lease_id, fencing_token: fence, sequence: 2 });
    const resultKey = key('execution.collect_result', { run_id: run.run_id });
    const collected = await store.collectResult({ result, actor: PRODUCER, idempotencyKey: resultKey, argsDigest: resultKey });
    assert.equal(collected.outcome, 'SUCCEEDED');
    assert.notEqual(collected.task?.state, 'DONE', 'a collected result is evidence, never a DONE');

    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(task.state, 'RUNNING', 'collecting a result does not move the task');

    // (b) and the current fence may give the right back.
    const releaseKey = key('tasks.lease.release', { lease_id: claim.lease_id, fence });
    const released = await store.releaseLease({
      leaseId: claim.lease_id,
      fencingToken: fence,
      reason: 'the holder returns the right to the queue',
      expectedRevision: task.revision,
      actor: SCHEDULER,
      actorKind: 'adapter',
      idempotencyKey: releaseKey,
      argsDigest: releaseKey,
    });
    assert.equal(released.lease.lease_state, 'RELEASED');
    assert.equal(released.task.fencing_token, null, 'a released right is no longer the current fence');
  });
});

// ===========================================================================
// 5. EXPIRY IS DECIDED AGAINST THE CLOCK, AND NEVER REQUEUES BY ITSELF
// ===========================================================================

describe('S2-007 lease: expiry follows the database clock and never requeues a task by itself', () => {
  test('a sweep before the expiry observes nothing and changes nothing', async () => {
    const store = makeStore();
    await readyToClaim(store);
    const claimed = await claim(store, { ttlMs: 60_000 });
    assert.equal(claimed.lease.expires_at, '2026-09-25T12:01:00.000Z');

    const before = await stateDigest(store, { includeLedger: false });
    const journalBefore = (await store.listTransitions(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER })).length;
    store.setNow('2026-09-25T12:00:30.000Z');
    const swept = await store.expireLeases({ actor: SCHEDULER, now: '2026-09-25T12:00:30.000Z' });

    assert.deepEqual(swept.expired, [], 'nothing is due before expires_at');
    assert.equal(
      await stateDigest(store, { includeLedger: false }),
      before,
      'a sweep that finds nothing must move no task, lease, journal row, run, audit row or outbox row',
    );
    assert.equal(
      (await store.listTransitions(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER })).length,
      journalBefore,
      'an empty sweep writes no journal row',
    );
    assert.equal((await store.readLease(claimed.lease_id)).lease_state, 'ACTIVE', 'the live right is untouched');
  });

  test('a sweep after the expiry withdraws the right and leaves the task where it is', async () => {
    const store = makeStore();
    await readyToClaim(store);
    const claimed = await claim(store, { ttlMs: 60_000 });

    store.setNow('2026-09-25T12:05:00.000Z');
    const swept = await store.expireLeases({ actor: SCHEDULER });

    assert.equal(swept.expired.length, 1, 'exactly the one due lease');
    assert.equal(swept.expired[0].lease_id, claimed.lease_id);
    assert.equal(swept.expired[0].fencing_token, Number(claimed.fencing_token));
    assert.equal((await store.readLease(claimed.lease_id)).lease_state, 'EXPIRED');

    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.notEqual(task.state, 'READY', 'an expiry must NOT silently return the task to READY');
    assert.equal(task.active_lease_id, null, 'the right is gone');
    assert.equal(task.fencing_token, null, 'there is no current fence after an expiry');
    assert.equal(task.state, 'CLAIMED', 'the state is only changed by an explicit, authorized transition');

    // And the expired fence is dead: it may not renew, release or re-bind.
    const after = await stateDigest(store);
    const renewKey = key('tasks.lease.renew', { lease_id: claimed.lease_id, fence: claimed.fencing_token });
    await expectRefusal(
      store.renewLease({
        leaseId: claimed.lease_id, fencingToken: claimed.fencing_token, ttlMs: TTL_MS, actor: SCHEDULER, idempotencyKey: renewKey, argsDigest: renewKey,
      }),
      ['STALE_FENCE'],
      'renewal of an expired lease',
    );
    assert.equal(await stateDigest(store), after, 'a late renewal after expiry must change nothing');
  });

  test('a task in RUNNING whose lease expired returns to READY only through guardRequeueAfterReconciliation', async () => {
    const store = makeStore();
    const context = await claimedTaskWithRun(store);
    // Drive it to RUNNING under the current fence first: the edge under test
    // is RUNNING -> READY, so the task has to be there.
    const running = await store.transitionTask({
      taskId: TASK_ID,
      toState: 'RUNNING',
      expectedRevision: context.revision,
      actor: SCHEDULER,
      actorKind: 'scheduler',
      reason: 'the run was dispatched to the lease holder',
      lease: context.claim.lease_id,
      fencingToken: context.fence,
      idempotencyKey: key('tasks.transition', { task_id: TASK_ID, to: 'RUNNING', start: true }),
      argsDigest: key('tasks.transition', { task_id: TASK_ID, to: 'RUNNING', start: true }),
    });
    assert.equal(running.task.state, 'RUNNING');

    store.setNow('2026-09-25T13:00:00.000Z');
    const swept = await store.expireLeases({ actor: SCHEDULER });
    assert.equal(swept.expired.length, 1, 'the RUNNING task lease expired too');

    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(task.state, 'RUNNING', 'the sweep must not move the task out of RUNNING by itself');
    assert.equal(task.active_lease_id, null);
    assert.equal(task.fencing_token, null);

    // The frozen table binds exactly one guard to RUNNING -> READY. Reading it
    // here means the test cannot pass with a differently-guarded edge.
    assert.equal(TRANSITIONS.RUNNING.READY, 'guardRequeueAfterReconciliation');

    const base = {
      task,
      fromState: 'RUNNING',
      toState: 'READY',
      expectedRevision: task.revision,
      actor: REVIEWER,
      actorKind: 'human_reviewer',
      capabilities: ['board.reconciliation.decide', 'board.task.read'],
      now: '2026-09-25T13:00:00.000Z',
      reason: 'the external effect of the run is now accounted for',
      // The requeue cites the lease whose expiry is being reconciled. A
      // decision about an unknown side effect must name the run it is about;
      // a context that simply omits the lease is refused by the fence check
      // before the reconciliation is even read, which is the safe order but
      // not the one this test is about.
      lease: context.claim.lease,
      producer_principal_id: PRODUCER,
    };

    // (a) a context that names no lease at all cannot even reach the
    //     reconciliation check: the edge demands the current lease record.
    await assert.rejects(
      async () => decideTransition({ task, toState: 'READY', context: { ...base, lease: undefined } }),
      (error) => isBoardError(error) && error.code === 'STALE_FENCE',
      'a requeue that cannot name the lease whose run is being reconciled is refused',
    );

    // (b) no recorded reconciliation at all.
    await assert.rejects(
      async () => decideTransition({ task, toState: 'READY', context: base }),
      (error) => isBoardError(error) && error.code === 'RECONCILIATION_REQUIRED',
      'a requeue without a recorded reconciliation must be refused',
    );

    // (c) an undetermined effect is not a decision.
    await assert.rejects(
      async () => decideTransition({
        task,
        toState: 'READY',
        context: { ...base, reconciliation: { resolution: 'EFFECT_UNDETERMINED', decided_by: RECONCILER, decided_by_kind: 'human_reviewer' } },
      }),
      (error) => isBoardError(error) && error.code === 'RECONCILIATION_REQUIRED',
      'an undetermined external effect must not be closable by requeueing',
    );

    // (d) the principal that drives the requeue may not be the principal that
    //     decided the reconciliation: that would be a self-approval.
    await assert.rejects(
      async () => decideTransition({
        task,
        toState: 'READY',
        context: {
          ...base,
          actor: RECONCILER,
          actorKind: 'human_reviewer',
          reconciliation: { resolution: 'OBSERVED_NO_EFFECT', decided_by: RECONCILER, decided_by_kind: 'human_reviewer' },
        },
      }),
      (error) => isBoardError(error) && error.code === 'BLOCKED_POLICY',
      'the actor driving a requeue may not be the actor that decided its reconciliation',
    );

    // (d) the producer (the adapter that ran the work) may not decide its own
    //     reconciliation, and a machine actor may not be the gate at all.
    await assert.rejects(
      async () => decideTransition({
        task,
        toState: 'READY',
        context: {
          ...base,
          actor: PRODUCER,
          actorKind: 'adapter',
          capabilities: ['board.reconciliation.decide'],
          reconciliation: { resolution: 'OBSERVED_NO_EFFECT', decided_by: PRODUCER, decided_by_kind: 'adapter' },
        },
      }),
      (error) => isBoardError(error) && (error.code === 'BLOCKED_POLICY' || error.code === 'AUTH_REQUIRED'),
      'the producer must not be the reconciliation gate for its own run',
    );

    const before = await stateDigest(store);
    // (e) the honest path: an authenticated human, a different principal from
    //     the producer and from the driver, and a recorded observation.
    assert.equal(
      decideTransition({
        task,
        toState: 'READY',
        context: {
          ...base,
          actor: OWNER,
          actorKind: 'human_owner',
          capabilities: ['board.reconciliation.decide', 'board.task.read'],
          reconciliation: {
            resolution: 'OBSERVED_NO_EFFECT',
            decided_by: RECONCILER,
            decided_by_kind: 'human_reviewer',
          },
        },
      }),
      true,
      'a requeue behind a recorded, human-decided reconciliation is allowed',
    );
    assert.equal(await stateDigest(store), before, 'deciding a transition is a decision, not a write');
  });
});
