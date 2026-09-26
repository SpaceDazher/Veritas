// S2-007 — the idempotency ledger (issue #7 §2 "one authoritative contract",
// §6 "no blind retry", module spec §3.2 return convention).
//
// WHY THIS FILE EXISTS. The board's only defence against a duplicate mutation
// is the pair (idempotency_key, args_digest) recorded in
// agentboard_operation. A replay MUST return the FIRST committed result and
// write nothing at all — not a second task row, not a second journal entry,
// not a second outbox row, not a second fence. A reuse of the same key with
// DIFFERENT canonical arguments must be refused and must leave the store
// byte-identical, because a store that half-applies a refusal is a store whose
// history_digest no longer describes what happened.
//
// The key itself is the other half of the control. It is SHA-256 over the
// S2-006 canonical-json-v1 form of { command, args, actor }, so:
//   * member order is irrelevant (canonicalize sorts keys),
//   * array order is significant (it is part of the request, not a set),
//   * adding OR removing a field changes the key,
//   * a different actor changes the key — one principal can never replay
//     another principal's work.
//
// Everything here runs on InMemoryAgentBoardStore with an INJECTED clock and an
// INJECTED id factory. No Date.now(), no Math.random(), no real side effect.
// store.mjs is a sibling worker's file and may still be incomplete: a failure
// here must be read as "the property is not implemented yet", and the failure
// text names the property.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { InMemoryAgentBoardStore } from '../../src/lib/agentboard/store.mjs';
import { fixedClock, commandIdempotencyKey } from '../../src/lib/agentboard/policy.mjs';
import { isBoardError, IdempotencyConflict } from '../../src/lib/agentboard/errors.mjs';
import { NON_RETRYABLE_CODES } from '../../src/lib/agentboard/constants.mjs';

const NON_RETRYABLE = new Set(NON_RETRYABLE_CODES);

const NOW = '2026-03-22T00:00:00.000Z';
const OWNER = 'prn-owner';
const REVIEWER = 'prn-reviewer';
const WORKSPACE = 'ws-alpha';
const PROFILE = 'sbx-podman-local-restricted-v1';
const HEX64 = /^[0-9a-f]{64}$/;
const digest = (char) => `sha256:${char.repeat(64)}`;

/**
 * Deterministic id factory. The store only requires a bounded string, so a
 * per-kind counter is enough — and it keeps the ids inside the frozen
 * patterns without touching randomness.
 */
function deterministicIds() {
  const counters = new Map();
  return () => {
    const next = (counters.get('id') ?? 0) + 1;
    counters.set('id', next);
    return next.toString(36).padStart(6, '0');
  };
}

function makeStore() {
  return new InMemoryAgentBoardStore({ clock: fixedClock(NOW), ids: deterministicIds(), seed: 's2-007-idempotency' });
}

function taskDocument(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    task_id: 'abt-alpha-1',
    workspace_id: WORKSPACE,
    title: 'Collect primary sources',
    goal: 'Assemble the source set for the alpha claim',
    description: 'Bounded, human-reviewed source collection.',
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
    time_limits: { timeout_ms: 60000, max_runtime_ms: 120000, deadline: null },
    cost_limits: { currency: 'USD', max_task_cost: 5, max_campaign_cost: 20, max_day_cost: 10 },
    acl: { visibility: 'project', allowed_principal_ids: [OWNER, REVIEWER] },
    brief_digest: digest('a'),
    policy_digest: digest('b'),
    manifest_digest: digest('c'),
    assigned_adapter_id: null,
    active_lease_id: null,
    fencing_token: null,
    attempts: 0,
    artifacts: [],
    evidence_refs: [],
    block_reason: null,
    created_at: NOW,
    updated_at: NOW,
    history_digest: digest('d'),
    ...overrides,
  };
}

/** The command key is what commands.mjs computes: command + args + actor. */
function commandKey(command, args, actor) {
  return commandIdempotencyKey({ command, args, actor });
}

/**
 * Byte-level state fingerprint used for the "a refusal mutates nothing"
 * assertions. debugSnapshot() is the store's own committed-state dump; when a
 * future store revision does not expose it, the fingerprint falls back to the
 * same public reads the assertions below already use, so the property under
 * test is never replaced by a missing debug helper.
 */
async function fingerprint(store, { taskId = 'abt-alpha-1' } = {}) {
  if (typeof store.debugSnapshot === 'function') {
    return JSON.stringify(await store.debugSnapshot());
  }
  return JSON.stringify({
    task: await store.getTask(taskId, { workspaceId: WORKSPACE, principalId: OWNER }),
    transitions: await store.listTransitions(taskId, { workspaceId: WORKSPACE, principalId: OWNER }),
    audit: await store.listAudit({ workspaceId: WORKSPACE, taskId }),
    outbox: await store.listOutbox({ workspaceId: WORKSPACE }),
  });
}

async function counts(store, { taskId = 'abt-alpha-1' } = {}) {
  return {
    transitions: (await store.listTransitions(taskId, { workspaceId: WORKSPACE, principalId: OWNER })).length,
    audit: (await store.listAudit({ workspaceId: WORKSPACE, taskId })).length,
    outbox: (await store.listOutbox({ workspaceId: WORKSPACE })).length,
  };
}

function createTaskCall(store, { task = taskDocument(), key, argsDigest, actor = OWNER, actorKind = 'human_owner' }) {
  return store.createTask({
    task,
    actor,
    actorKind,
    idempotencyKey: key,
    argsDigest,
    // The outbox row is written in the SAME transaction as the task row, so a
    // replay that re-wrote it would be a duplicate external effect.
    outboxEvent: { event_type: 'board.task.created', payload: { task_id: task.task_id, state: 'BACKLOG' } },
  });
}

// ---------------------------------------------------------------------------
// Execution-boundary fixtures.
//
// A replay is only interesting where the side effect is real: a lease mints a
// fencing token, a run opens an execution boundary, a callback appends to an
// append-only journal. Each of those is one row that must never exist twice.
// The ids the SCHEDULER hands out must already carry their contract prefix —
// the scheduler refuses to rewrite an id, because a silently repaired id is a
// second, invisible source of identity — so this factory emits prefixes.
// ---------------------------------------------------------------------------

const SCHEDULER = 'prn-idempotency-scheduler';
const PRODUCER = 'prn-idempotency-producer';
const ADAPTER_ID = 'adr-idempotency-a';
const GRANT_ID = 'grt-idempotency-1';

function schedulerIds() {
  const counters = new Map();
  return (kind) => {
    const next = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, next);
    const prefix = { decision: 'dsc-', request: 'xer-', event: 'eve-', run: 'run-' }[kind] ?? `${kind}-`;
    return `${prefix}${next.toString(36).padStart(6, '0')}`;
  };
}

function adapterRegistration() {
  return {
    contractVersion: '1.0.0',
    adapter_id: ADAPTER_ID,
    adapter_interface: 'veritas.adapter/1.0.0',
    provider: 'test',
    display_name: 'Idempotency test transport',
    adapter_kind: 'test',
    health: 'healthy',
    workspace_id: WORKSPACE,
    principal_id: PRODUCER,
    declared_capabilities: ['source.read'],
    declared_tools: ['tool:fs.read'],
    sandbox_profile_id: PROFILE,
    max_concurrency: 1,
    // Honest provenance: fixture evidence never upgrades this to a real run.
    real_adapter_provenance: {
      status: 'NOT_RUN_REAL_ADAPTER',
      detail: 'idempotency fixture: no installed executor is bound to this adapter',
    },
    registered_at: NOW,
  };
}

function budgetGrant() {
  return {
    grant_id: GRANT_ID,
    workspace_id: WORKSPACE,
    task_id: taskDocument().task_id,
    currency: 'USD',
    task_limit: 5,
    campaign_limit: 20,
    day_limit: 10,
    timeout_ms: 60_000,
    granted_by: OWNER,
  };
}

/** BACKLOG -> READY, plus a registered adapter and an approved budget. */
async function seedExecutableTask(store, task = taskDocument()) {
  const createKey = commandKey('tasks.create', { task_id: task.task_id }, OWNER);
  await createTaskCall(store, { task, key: createKey, argsDigest: createKey });
  const readyKey = commandKey('tasks.transition', { task_id: task.task_id, to: 'READY' }, OWNER);
  await store.transitionTask({
    taskId: task.task_id,
    toState: 'READY',
    expectedRevision: 1,
    actor: OWNER,
    actorKind: 'human_owner',
    reason: 'immutable brief validated and dependencies closed',
    idempotencyKey: readyKey,
    argsDigest: readyKey,
  });
  const adapterKey = commandKey('adapters.register', { adapter_id: ADAPTER_ID }, OWNER);
  await store.registerAdapter({
    registration: adapterRegistration(),
    actor: OWNER,
    idempotencyKey: adapterKey,
    argsDigest: adapterKey,
  });
  const grantKey = commandKey('budget.grant', { grant_id: GRANT_ID }, OWNER);
  await store.grantBudget({ grant: budgetGrant(), actor: OWNER, idempotencyKey: grantKey, argsDigest: grantKey });
  return store.getTask(task.task_id, { workspaceId: WORKSPACE, principalId: OWNER });
}

/** READY -> CLAIMED: the one write that mints a fencing token. */
async function claim(store, task, { key = commandKey('tasks.claim', { task_id: task.task_id, adapter_id: ADAPTER_ID }, SCHEDULER) } = {}) {
  return store.claimTask({
    taskId: task.task_id,
    workspaceId: WORKSPACE,
    adapterId: ADAPTER_ID,
    ttlMs: 60_000,
    expectedRevision: task.revision,
    actor: SCHEDULER,
    actorKind: 'scheduler',
    idempotencyKey: key,
    argsDigest: key,
  });
}

function executionRequest(task, lease, { requestId = 'xer-idempotency-1' } = {}) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    request_id: requestId,
    idempotency_key: commandKey('execution.request', { task_id: task.task_id, request_id: requestId }, SCHEDULER),
    task_id: task.task_id,
    workspace_id: WORKSPACE,
    brief_digest: task.brief_digest,
    policy_digest: task.policy_digest,
    manifest_digest: task.manifest_digest,
    principal_id: SCHEDULER,
    granted_scope: ['task.read', 'task.write', 'checkpoint.write'],
    allowed_tools: task.allowed_tools,
    workspace_ref: task.workspace_ref,
    budget_grant: {
      currency: 'USD',
      task_limit: 5,
      campaign_limit: 20,
      day_limit: 10,
      timeout_ms: 60_000,
      granted_by: OWNER,
      granted_at: NOW,
    },
    deadline: null,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    adapter_id: ADAPTER_ID,
    issued_at: NOW,
  };
}

function executionEvent(run, lease, overrides = {}) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    event_id: 'eve-idempotency-1',
    run_id: run.run_id,
    task_id: run.task_id,
    workspace_id: WORKSPACE,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    sequence: 1,
    event_type: 'STARTED',
    payload: { note: 'executor accepted the request' },
    outcome: null,
    emitted_at: NOW,
    ...overrides,
  };
}

describe('S2-007 idempotency: replay of an identical key and identical canonical arguments', () => {
  test('a replayed create returns the FIRST result and writes nothing new', async () => {
    const store = makeStore();
    const task = taskDocument();
    const key = commandKey('tasks.create', { task_id: task.task_id, title: task.title }, OWNER);

    const first = await createTaskCall(store, { task, key, argsDigest: key });
    assert.equal(first.replayed, false, 'the first call is a fresh write, not a replay');
    assert.equal(first.task_id, task.task_id);

    const before = await counts(store);
    const taskBefore = await store.getTask(task.task_id, { workspaceId: WORKSPACE, principalId: OWNER });
    const stateBefore = await fingerprint(store);

    const second = await createTaskCall(store, { task, key, argsDigest: key });

    assert.equal(second.replayed, true, 'the replay must be reported as a replay, not as a fresh commit');
    const { replayed: _firstFlag, ...firstBody } = first;
    const { replayed: _secondFlag, ...secondBody } = second;
    assert.deepEqual(secondBody, firstBody, 'the replay must return the FIRST committed result unchanged');

    const after = await counts(store);
    assert.deepEqual(after, before, 'a replay must not add a transition, a journal row or an outbox row');
    const taskAfter = await store.getTask(task.task_id, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.deepEqual(taskAfter, taskBefore, 'the task row must be byte-identical after a replay');
    assert.equal(await fingerprint(store), stateBefore, 'the committed state must be byte-identical after a replay');
  });

  test('a replayed transition appends no second journal row and does not re-bump the revision', async () => {
    const store = makeStore();
    const task = taskDocument();
    const createKey = commandKey('tasks.create', { task_id: task.task_id }, OWNER);
    await createTaskCall(store, { task, key: createKey, argsDigest: createKey });

    const transitionKey = commandKey('tasks.transition', { task_id: task.task_id, to: 'READY', revision: 1 }, OWNER);
    const transition = () => store.transitionTask({
      taskId: task.task_id,
      toState: 'READY',
      expectedRevision: 1,
      actor: OWNER,
      actorKind: 'human_owner',
      reason: 'brief validated and dependencies closed',
      idempotencyKey: transitionKey,
      argsDigest: transitionKey,
      outboxEvent: { event_type: 'board.task.transitioned', payload: { task_id: task.task_id, to: 'READY' } },
    });

    const first = await transition();
    assert.equal(first.replayed, false);
    assert.equal(first.task.state, 'READY');

    const before = await counts(store);
    const stateBefore = await fingerprint(store);

    const replay = await transition();

    assert.equal(replay.replayed, true);
    const { replayed: _a, ...firstBody } = first;
    const { replayed: _b, ...replayBody } = replay;
    assert.deepEqual(replayBody, firstBody, 'the replay returns the first committed transition record');
    assert.deepEqual(await counts(store), before, 'a replayed transition appends no journal row and no outbox row');
    assert.equal(await fingerprint(store), stateBefore);
  });

  test('the ledger holds exactly one committed record per key', async () => {
    const store = makeStore();
    const task = taskDocument();
    const key = commandKey('tasks.create', { task_id: task.task_id }, OWNER);
    await createTaskCall(store, { task, key, argsDigest: key });
    await createTaskCall(store, { task, key, argsDigest: key });
    await createTaskCall(store, { task, key, argsDigest: key });

    const operation = await store.readOperation(key);
    assert.ok(operation, 'the committed operation record must be readable by its key');
    assert.equal(operation.idempotency_key, key);
    assert.equal(operation.args_digest, key, 'the stored digest is the canonical argument digest of the command');
    assert.equal(operation.operation, 'board.task.create');
  });
});

describe('S2-007 idempotency: the same key with a different payload', () => {
  test('a different canonical argument digest is refused with IdempotencyConflict and mutates nothing', async () => {
    const store = makeStore();
    const task = taskDocument();
    const committedKey = commandKey('tasks.create', { task_id: task.task_id, title: task.title }, OWNER);
    await createTaskCall(store, { task, key: committedKey, argsDigest: committedKey });

    const before = await fingerprint(store);

    // Same key, DIFFERENT canonical arguments: this is the confused-deputy
    // replay — one principal reusing a key to smuggle a second mutation in.
    const smuggledKey = commandKey('tasks.create', { task_id: 'abt-alpha-2', title: task.title }, OWNER);
    assert.notEqual(smuggledKey, committedKey, 'the two commands must not share a key');

    await assert.rejects(
      () => createTaskCall(store, { task: taskDocument({ task_id: 'abt-alpha-2' }), key: committedKey, argsDigest: smuggledKey }),
      (error) => {
        assert.ok(isBoardError(error), `a refusal must be a typed BoardError, got ${error?.name}`);
        assert.ok(error instanceof IdempotencyConflict, `expected IdempotencyConflict, got ${error?.name}`);
        assert.equal(error.code, 'IDEMPOTENCY_CONFLICT');
        assert.equal(error.retryable, false, 'an idempotency conflict is never a blind retry');
        return true;
      },
    );

    assert.equal(await fingerprint(store), before, 'a refused reuse must leave the store byte-identical');
  });

  test('the same key with a different digest is refused even for the identical entity', async () => {
    const store = makeStore();
    const task = taskDocument();
    const key = commandKey('tasks.create', { task_id: task.task_id }, OWNER);
    await createTaskCall(store, { task, key, argsDigest: key });
    const before = await fingerprint(store);

    // Identical task, different claimed arguments: a caller that reuses a key
    // with a different digest has not proven it means the same thing.
    const otherDigest = commandKey('tasks.create', { task_id: task.task_id, title: 'a different title' }, OWNER);
    await assert.rejects(
      () => createTaskCall(store, { task, key, argsDigest: otherDigest }),
      (error) => error instanceof IdempotencyConflict && error.code === 'IDEMPOTENCY_CONFLICT',
    );
    assert.equal(await fingerprint(store), before);
  });
});

describe('S2-007 idempotency: the key is a canonical function of the command arguments', () => {
  const args = { task_id: 'abt-alpha-1', expected_revision: 3, to: 'RUNNING' };

  test('member order does not change the key', () => {
    const straight = commandKey('tasks.transition', args, OWNER);
    const reordered = commandKey('tasks.transition', { to: 'RUNNING', expected_revision: 3, task_id: 'abt-alpha-1' }, OWNER);
    const nested = commandKey('tasks.transition', { ...args, acl: { visibility: 'project', allowed_principal_ids: [OWNER] } }, OWNER);
    const nestedReordered = commandKey('tasks.transition', { ...args, acl: { allowed_principal_ids: [OWNER], visibility: 'project' } }, OWNER);

    assert.equal(straight, reordered, 'canonicalization must sort object members');
    assert.equal(nested, nestedReordered, 'canonicalization must sort nested object members too');
  });

  test('the key is 64 lowercase hex characters and is stable across calls', () => {
    const key = commandKey('tasks.transition', args, OWNER);
    assert.match(key, HEX64);
    assert.equal(key, commandKey('tasks.transition', args, OWNER), 'the same arguments must always produce the same key');
  });

  test('adding a field changes the key', () => {
    const without = commandKey('tasks.transition', args, OWNER);
    const with_ = commandKey('tasks.transition', { ...args, reason: 'execution dispatched' }, OWNER);
    assert.notEqual(without, with_, 'an added argument is a different request and needs a different key');
  });

  test('removing a field changes the key', () => {
    const full = commandKey('tasks.transition', { ...args, reason: 'execution dispatched' }, OWNER);
    const reduced = commandKey('tasks.transition', args, OWNER);
    assert.notEqual(full, reduced, 'a dropped argument is a different request and needs a different key');
  });

  test('a different actor produces a different key', () => {
    const owner = commandKey('tasks.transition', args, OWNER);
    const reviewer = commandKey('tasks.transition', args, REVIEWER);
    assert.notEqual(owner, reviewer, 'one principal must never be able to replay another principal\'s work');
  });

  test('a different command produces a different key', () => {
    const created = commandKey('tasks.create', args, OWNER);
    const claimed = commandKey('tasks.claim', args, OWNER);
    assert.notEqual(created, claimed, 'the key binds the command, not just the argument body');
  });

  test('array order is significant because a list is part of the request, not a set', () => {
    const ascending = commandKey('tasks.transition', { ...args, allowed_tools: ['tool:fs.read', 'tool:fs.write'] }, OWNER);
    const reversed = commandKey('tasks.transition', { ...args, allowed_tools: ['tool:fs.write', 'tool:fs.read'] }, OWNER);
    assert.notEqual(ascending, reversed, 'reordering a request list is a different request');
  });

  test('a non-canonical argument is refused rather than silently mangled', () => {
    // NaN has no canonical JSON form: silently stringifying it would let two
    // different requests share one key.
    assert.throws(
      () => commandIdempotencyKey({ command: 'tasks.transition', args: { amount: Number.NaN }, actor: OWNER }),
      (error) => isBoardError(error) && error.code === 'BLOCKED_POLICY',
    );
  });
});

// ============================================================================
// The execution boundary.
//
// A replay is only interesting where the side effect is real. A claim mints a
// fencing token, a run opens an execution boundary, a callback appends to an
// append-only journal: each of those must exist exactly once even when the
// caller cannot know whether its first attempt reached the database.
// ============================================================================

describe('S2-007 idempotency: replay across the execution boundary', () => {
  test('a replayed claim mints no second lease and does not advance the fencing sequence', async () => {
    const store = makeStore();
    const task = await seedExecutableTask(store);

    const first = await claim(store, task);
    assert.equal(first.replayed, false);
    const before = {
      snapshot: JSON.stringify(await store.debugSnapshot()),
      leases: (await store.listLeases({ workspaceId: WORKSPACE })).length,
      audit: (await store.listAudit({ workspaceId: WORKSPACE, taskId: task.task_id })).length,
    };

    const replay = await claim(store, task);
    assert.equal(replay.replayed, true, 'the identical claim is a replay');
    assert.equal(replay.lease.lease_id, first.lease.lease_id, 'the first lease is the committed one');
    assert.equal(replay.lease.fencing_token, first.lease.fencing_token, 'the fence is not re-minted');

    const after = JSON.stringify(await store.debugSnapshot());
    assert.equal(after, before.snapshot, 'a replayed claim must leave the store byte-identical, sequence included');
    assert.equal((await store.listLeases({ workspaceId: WORKSPACE })).length, before.leases);
    assert.equal((await store.listAudit({ workspaceId: WORKSPACE, taskId: task.task_id })).length, before.audit);
  });

  test('a second claim with a NEW key is refused instead of opening a second execution boundary', async () => {
    const store = makeStore();
    const task = await seedExecutableTask(store);
    await claim(store, task);
    const before = JSON.stringify(await store.debugSnapshot());

    const secondKey = commandKey('tasks.claim', { task_id: task.task_id, adapter_id: ADAPTER_ID, attempt: 2 }, SCHEDULER);
    await assert.rejects(
      () => claim(store, { ...task, revision: task.revision + 1 }, { key: secondKey }),
      (error) => {
        assert.ok(error instanceof IdempotencyConflict || isBoardError(error), 'a refused claim is a typed refusal');
        assert.ok(NON_RETRYABLE.has(error.code), 'a refused claim is never a blind retry');
        return true;
      },
    );
    assert.equal(JSON.stringify(await store.debugSnapshot()), before, 'the refusal must not leave a lease or a fence behind');
  });

  test('a replayed run start writes no second run, no second outbox row and no second audit row', async () => {
    const store = makeStore();
    const task = await seedExecutableTask(store);
    const lease = (await claim(store, task)).lease;
    const running = await store.getTask(task.task_id, { workspaceId: WORKSPACE, principalId: OWNER });
    const runningKey = commandKey('tasks.transition', { task_id: task.task_id, to: 'RUNNING' }, SCHEDULER);
    await store.transitionTask({
      taskId: task.task_id,
      toState: 'RUNNING',
      expectedRevision: running.revision,
      actor: SCHEDULER,
      actorKind: 'scheduler',
      reason: 'execution request recorded',
      lease: lease.lease_id,
      fencingToken: lease.fencing_token,
      idempotencyKey: runningKey,
      argsDigest: runningKey,
    });
    const runningTask = await store.getTask(task.task_id, { workspaceId: WORKSPACE, principalId: OWNER });
    const request = executionRequest(runningTask, lease);
    const runKey = commandKey('execution.start', { task_id: task.task_id }, SCHEDULER);

    const first = await store.createRun({ request, actor: SCHEDULER, idempotencyKey: runKey, argsDigest: runKey });
    assert.equal(first.replayed, false);
    const before = {
      runs: (await store.listRuns({ workspaceId: WORKSPACE })).length,
      outbox: (await store.listOutbox({ workspaceId: WORKSPACE })).length,
      audit: (await store.listAudit({ workspaceId: WORKSPACE, taskId: task.task_id })).length,
      snapshot: JSON.stringify(await store.debugSnapshot()),
    };
    assert.equal(before.runs, 1, 'the fixture must have exactly one run');
    // The claim already left its own outbox row, so only the DELTA matters here.

    const replay = await store.createRun({ request, actor: SCHEDULER, idempotencyKey: runKey, argsDigest: runKey });
    assert.equal(replay.replayed, true);
    assert.equal(replay.run_id, first.run_id, 'the replay returns the first run');
    assert.equal(replay.outbox_id, first.outbox_id, 'and the first outbox row');

    assert.equal((await store.listRuns({ workspaceId: WORKSPACE })).length, before.runs, 'no second run');
    assert.equal((await store.listOutbox({ workspaceId: WORKSPACE })).length, before.outbox, 'no second outbox row');
    assert.equal(
      (await store.listAudit({ workspaceId: WORKSPACE, taskId: task.task_id })).length,
      before.audit,
      'no second audit row',
    );
    assert.equal(JSON.stringify(await store.debugSnapshot()), before.snapshot);

    // A second run under a different key while one is live is refused: a
    // duplicate live run is a duplicate external effect, not a retry.
    const otherKey = commandKey('execution.start', { task_id: task.task_id, attempt: 2 }, SCHEDULER);
    await assert.rejects(
      () => store.createRun({
        request: executionRequest(runningTask, lease, { requestId: 'xer-idempotency-2' }),
        actor: SCHEDULER,
        idempotencyKey: otherKey,
        argsDigest: otherKey,
      }),
      (error) => isBoardError(error) && error.code === 'TRANSITION_NOT_ALLOWED',
    );
    assert.equal((await store.listRuns({ workspaceId: WORKSPACE })).length, 1);
  });

  test('a replayed dispatch step replays, and the state machine still refuses a NEW key', async () => {
    const store = makeStore();
    const task = await seedExecutableTask(store);
    const lease = (await claim(store, task)).lease;
    const running = await store.getTask(task.task_id, { workspaceId: WORKSPACE, principalId: OWNER });
    const runningKey = commandKey('tasks.transition', { task_id: task.task_id, to: 'RUNNING' }, SCHEDULER);
    await store.transitionTask({
      taskId: task.task_id,
      toState: 'RUNNING',
      expectedRevision: running.revision,
      actor: SCHEDULER,
      actorKind: 'scheduler',
      reason: 'execution request recorded',
      lease: lease.lease_id,
      fencingToken: lease.fencing_token,
      idempotencyKey: runningKey,
      argsDigest: runningKey,
    });
    const runningTask = await store.getTask(task.task_id, { workspaceId: WORKSPACE, principalId: OWNER });
    const request = executionRequest(runningTask, lease);
    const runKey = commandKey('execution.start', { task_id: task.task_id }, SCHEDULER);
    const created = await store.createRun({ request, actor: SCHEDULER, idempotencyKey: runKey, argsDigest: runKey });
    const outboxId = created.outbox_id;

    const sentKey = commandKey('outbox.dispatch.intent', { outbox_id: outboxId }, SCHEDULER);
    const first = await store.markOutboxSent({ outboxId, actor: SCHEDULER, idempotencyKey: sentKey, argsDigest: sentKey });
    assert.equal(first.dispatch_state, 'SENT');
    const before = JSON.stringify(await store.debugSnapshot());

    const replay = await store.markOutboxSent({ outboxId, actor: SCHEDULER, idempotencyKey: sentKey, argsDigest: sentKey });
    assert.equal(replay.replayed, true, 'the identical dispatch intent is a replay');
    assert.equal(JSON.stringify(await store.debugSnapshot()), before, 'a replayed intent writes nothing');

    // A different key for the same step is a state machine question, not an
    // idempotency one: SENT -> SENT is not a step.
    const repeatKey = commandKey('outbox.dispatch.intent.again', { outbox_id: outboxId }, SCHEDULER);
    await assert.rejects(
      () => store.markOutboxSent({ outboxId, actor: SCHEDULER, idempotencyKey: repeatKey, argsDigest: repeatKey }),
      (error) => isBoardError(error) && error.code === 'TRANSITION_NOT_ALLOWED',
    );
    assert.equal(JSON.stringify(await store.debugSnapshot()), before, 'the refused step must not have written anything');
  });

  test('a replayed execution callback appends no second journal row', async () => {
    const store = makeStore();
    const task = await seedExecutableTask(store);
    const lease = (await claim(store, task)).lease;
    const running = await store.getTask(task.task_id, { workspaceId: WORKSPACE, principalId: OWNER });
    const runningKey = commandKey('tasks.transition', { task_id: task.task_id, to: 'RUNNING' }, SCHEDULER);
    await store.transitionTask({
      taskId: task.task_id,
      toState: 'RUNNING',
      expectedRevision: running.revision,
      actor: SCHEDULER,
      actorKind: 'scheduler',
      reason: 'execution request recorded',
      lease: lease.lease_id,
      fencingToken: lease.fencing_token,
      idempotencyKey: runningKey,
      argsDigest: runningKey,
    });
    const runningTask = await store.getTask(task.task_id, { workspaceId: WORKSPACE, principalId: OWNER });
    const request = executionRequest(runningTask, lease);
    const runKey = commandKey('execution.start', { task_id: task.task_id }, SCHEDULER);
    const created = await store.createRun({ request, actor: SCHEDULER, idempotencyKey: runKey, argsDigest: runKey });

    const event = executionEvent(created.run, lease);
    const eventKey = commandKey('execution.event', { run_id: created.run_id, sequence: 1 }, SCHEDULER);
    const first = await store.appendExecutionEvent({ event, actor: SCHEDULER, idempotencyKey: eventKey, argsDigest: eventKey });
    assert.equal(first.replayed, false);
    const before = JSON.stringify(await store.debugSnapshot());

    const replay = await store.appendExecutionEvent({ event, actor: SCHEDULER, idempotencyKey: eventKey, argsDigest: eventKey });
    assert.equal(replay.replayed, true, 'the identical callback is a replay');
    assert.equal((await store.listEvents(created.run_id)).length, 1, 'the append-only journal has exactly one row');
    assert.equal(JSON.stringify(await store.debugSnapshot()), before, 'and nothing else moved');

    // A re-sent callback under a new key is a duplicate, not a retry.
    const resentKey = commandKey('execution.event.resent', { run_id: created.run_id, sequence: 1 }, SCHEDULER);
    await assert.rejects(
      () => store.appendExecutionEvent({
        event: executionEvent(created.run, lease, { event_id: 'eve-idempotency-2' }),
        actor: SCHEDULER,
        idempotencyKey: resentKey,
        argsDigest: resentKey,
      }),
      (error) => {
        // The duplicate is refused either as an out-of-order sequence or as an
        // inadmissible state step; both are typed and neither is retryable.
        assert.ok(isBoardError(error), `a duplicate callback must be a typed refusal, got ${error?.name}`);
        assert.ok(NON_RETRYABLE.has(error.code), `a duplicate callback is not a blind retry, got ${error?.code}`);
        return true;
      },
    );
    assert.equal((await store.listEvents(created.run_id)).length, 1, 'a duplicate callback must not become a second record');
  });

  test('a refused command leaves no ledger entry, so a corrected retry is a first commit', async () => {
    const store = makeStore();
    const task = await seedExecutableTask(store);
    const k = commandKey('tasks.transition', { task_id: task.task_id, to: 'DONE' }, OWNER);
    const before = JSON.stringify(await store.debugSnapshot());

    // READY -> DONE is not an edge of the frozen transition table.
    await assert.rejects(
      () => store.transitionTask({
        taskId: task.task_id,
        toState: 'DONE',
        expectedRevision: task.revision,
        actor: OWNER,
        actorKind: 'human_owner',
        reason: 'a shortcut to done',
        idempotencyKey: k,
        argsDigest: k,
      }),
      (error) => isBoardError(error) && error.code === 'TRANSITION_NOT_ALLOWED',
    );
    assert.equal(await store.readOperation(k), null, 'a refusal must not be remembered as a committed result');
    assert.equal(JSON.stringify(await store.debugSnapshot()), before);

    // The corrected command, once the cause is gone, commits normally and is
    // then replayable like any other committed command.
    const blockKey = commandKey('tasks.transition', { task_id: task.task_id, to: 'BLOCKED' }, OWNER);
    const committed = await store.transitionTask({
      taskId: task.task_id,
      toState: 'BLOCKED',
      expectedRevision: task.revision,
      actor: OWNER,
      actorKind: 'human_owner',
      reason: 'the budget grant is missing',
      blockReason: 'the budget grant is missing',
      idempotencyKey: blockKey,
      argsDigest: blockKey,
    });
    assert.equal(committed.replayed, false);
    assert.equal(committed.task.state, 'BLOCKED');
    const replay = await store.transitionTask({
      taskId: task.task_id,
      toState: 'BLOCKED',
      expectedRevision: task.revision,
      actor: OWNER,
      actorKind: 'human_owner',
      reason: 'the budget grant is missing',
      blockReason: 'the budget grant is missing',
      idempotencyKey: blockKey,
      argsDigest: blockKey,
    });
    assert.equal(replay.replayed, true);
  });

  test('one key cannot be replayed as a DIFFERENT operation, even with an identical argument digest', async () => {
    const store = makeStore();
    const task = taskDocument();
    const k = commandKey('tasks.create', { task_id: task.task_id }, OWNER);
    await createTaskCall(store, { task, key: k, argsDigest: k });
    const before = JSON.stringify(await store.debugSnapshot());

    // Same key, same digest, different operation: the ledger binds the key to
    // the operation, not only to the arguments.
    await assert.rejects(
      () => store.transitionTask({
        taskId: task.task_id,
        toState: 'READY',
        expectedRevision: 1,
        actor: OWNER,
        actorKind: 'human_owner',
        reason: 'the same key, a different meaning',
        idempotencyKey: k,
        argsDigest: k,
        operation: 'board.task.transition',
      }),
      (error) => {
        assert.ok(error instanceof IdempotencyConflict, `expected IdempotencyConflict, got ${error?.name}`);
        assert.equal(error.code, 'IDEMPOTENCY_CONFLICT');
        return true;
      },
    );
    assert.equal(JSON.stringify(await store.debugSnapshot()), before);
  });
});
