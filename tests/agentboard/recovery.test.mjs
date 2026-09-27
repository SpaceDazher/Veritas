// S2-007 — crash injection, outbox recovery and the reconciliation boundary
// (issue #7 §5 "no blind retry", §6 "fail closed"; module spec §3.2 return
// convention, §3.3 driveOutbox/recoverOutbox, §0 rule 9).
//
// WHY THIS FILE EXISTS
// The Agent Board performs side effects it does not own: telling an executor
// to start, collecting its result, settling a budget. A process can die at any
// instant, and the database cannot. Every boundary below is therefore a place
// where the board can silently do the wrong thing:
//
//   B1  task state change  -> journal (append-only transition) row
//   B2  journal row         -> outbox row
//   B3  outbox row          -> dispatch send (the external effect)
//   B4  dispatch send       -> result collection
//
// The invariants asserted here are the ones a reader of the journal must be
// able to rely on:
//   * no lost record  — every committed state change has its journal row, its
//     audit row and its outbox row, and none of the three can exist alone;
//   * no double record — a command that is retried after a crash commits once,
//     because the idempotency ledger is consulted before the write;
//   * canonical state recovered after restart — the state a restarted process
//     reads is the state that was committed, and recovery reissues nothing.
//
// HOW THE CRASH IS INJECTED (and why that is honest)
// store.mjs has no `failAfter` option, so this file injects the crash with the
// smallest possible shim instead of pretending it has one:
//
//   * INSIDE a transaction — `CrashingStore` overrides the two private write
//     steps the base class itself documents as the crash-relevant ones
//     (`_appendTransition`, `_insertOutbox`) plus `_commitUnitOfWork`, and
//     throws a plain Error there. The store must turn that into a typed
//     BoardError and must commit nothing. This is the real thing a real crash
//     does to a PostgreSQL transaction: the whole unit of work disappears.
//   * AFTER a transaction committed but BEFORE the caller learned the outcome
//     — the method is wrapped so it performs the real write and then throws.
//     This is the unknowable case; the only correct answer is the idempotency
//     ledger, never a second write.
//   * BETWEEN commands (B3/B4) — the "crash" is simply that the next call is
//     never made. Nothing is faked: a driver that dies after the outbox row and
//     before the send leaves exactly the rows a real crash leaves.
//
// `restart()` hands the COMMITTED `_state` to a brand new store instance. That
// is the in-memory twin of "a new process opens the same database": only
// committed state survives, and every in-memory cache is gone. It is a local
// shim over one underscore field and is documented as such — the PostgreSQL
// twin needs none of it, because there the data is already durable.
//
// DETERMINISM. One injected clock (mutable, never the process clock), one
// injected id factory shared by every store instance in a test, and a
// hand-counted transport. No Date.now(), no Math.random(), no wall clock, no
// real executor: the test transport is declared NOT_RUN_REAL_ADAPTER and this
// file never claims otherwise.
//
// A failure here must be read as "the property is not implemented yet". The
// failure text names the property, and a fixture error would instead surface
// as NEEDS_INPUT/AUTH_REQUIRED/MALFORMED_RESULT on a setup call.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { InMemoryAgentBoardStore } from '../../src/lib/agentboard/store.mjs';
import { commandIdempotencyKey, decideTransition } from '../../src/lib/agentboard/policy.mjs';
import { driveOutbox, recoverOutbox, runSchedulerTick } from '../../src/lib/agentboard/scheduler.mjs';
import { isBoardError } from '../../src/lib/agentboard/errors.mjs';
import { ERROR_CODES, NON_RETRYABLE_CODES } from '../../src/lib/agentboard/constants.mjs';

const WORKSPACE = 'ws-recovery';
const OWNER = 'prn-recovery-owner';
const SCHEDULER = 'prn-recovery-scheduler';
const PRODUCER = 'prn-recovery-producer';
const RECONCILER = 'prn-recovery-reconciler';
const OTHER_REVIEWER = 'prn-recovery-reviewer';
const PROFILE = 'sbx-podman-local-restricted-v1';
const TASK_ID = 'abt-recovery-1';
const ADAPTER_ID = 'adr-recovery-a';
const GRANT_ID = 'grt-recovery-1';
const T0 = '2026-09-25T12:00:00.000Z';
// Still inside the claim TTL, for the edges that legitimately require a LIVE
// lease. T1 is past it, for the edges that do not (a release or a requeue).
const T_INSIDE_LEASE = '2026-09-25T12:00:30.000Z';
const T1 = '2026-09-25T12:05:00.000Z';
const TTL_MS = 60_000;

const CLOSED_CODES = new Set(ERROR_CODES);
const digest = (char) => `sha256:${char.repeat(64)}`;
const BRIEF = digest('b');
const POLICY = digest('c');
const MANIFEST = digest('d');

/** The command key the boundary computes: canonical-json-v1 of command+args+actor. */
function key(command, args, actor = OWNER) {
  return commandIdempotencyKey({ command, args, actor });
}

/**
 * One monotonic counter per identifier kind. Shared by every store instance of
 * a test, so a restart continues the sequence instead of re-minting an id —
 * a re-minted id would be a second, invisible source of identity.
 */
function deterministicIds() {
  const counters = new Map();
  return (kind) => {
    const next = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, next);
    // The scheduler refuses an id that does not already carry its contract
    // prefix, so the factory emits the prefix itself.
    const prefix = { decision: 'dsc-', request: 'xer-', event: 'eve-', run: 'run-' }[kind] ?? `${kind}-`;
    return `${prefix}${next.toString(36).padStart(6, '0')}`;
  };
}

/**
 * The store under test. `crashPoint` arms a ONE-SHOT fault at a documented
 * write step; the throw is a plain Error on purpose, because that is what a
 * dead process leaves behind — the store is responsible for turning it into a
 * typed refusal instead of a silent success.
 */
class CrashingStore extends InMemoryAgentBoardStore {
  constructor(options = {}) {
    super(options);
    this.crashPoint = options.crashPoint ?? null;
    this.crashes = [];
  }

  arm(point) {
    this.crashPoint = point;
    return this;
  }

  _maybeCrash(point, label) {
    if (this.crashPoint !== point) return;
    this.crashPoint = null;
    this.crashes.push(point);
    throw new Error(`simulated process crash at ${point} (before ${label} is committed)`);
  }

  // B1: the task row and the new revision are staged, the journal row is not.
  async _appendTransition(...args) {
    this._maybeCrash('journal', 'the append-only journal row');
    return super._appendTransition(...args);
  }

  // B2: task + journal + audit are staged, the outbox row is not.
  async _insertOutbox(...args) {
    this._maybeCrash('outbox', 'the outbox row');
    return super._insertOutbox(...args);
  }

  // The last possible instant of a unit of work.
  async _commitUnitOfWork(tx) {
    this._maybeCrash('commit', 'COMMIT');
    return super._commitUnitOfWork(tx);
  }
}

/**
 * A "restart": a brand new store instance that inherits ONLY the committed
 * state. Local shim over `_state` (the in-memory twin has no other place to
 * keep durable data); the PostgreSQL twin gets this for free.
 */
function restart(store, { clock, ids }) {
  const restarted = new CrashingStore({ clock, ids, seed: `${store.seed}-restart` });
  restarted._state = store._state;
  return restarted;
}

/** A transport that counts every crossing of the external boundary by hand. */
function countingTransport({ fail = null } = {}) {
  const sends = [];
  return {
    sends,
    transport: {
      async dispatch(payload) {
        sends.push(payload);
        if (fail !== null) throw fail;
        return { accepted: true };
      },
    },
  };
}

// --- fixture -----------------------------------------------------------------

function makeStore({ crashPoint = null, now = T0 } = {}) {
  const state = { now };
  const ids = deterministicIds();
  const clock = () => new Date(state.now);
  const store = new CrashingStore({ clock, ids, seed: 's2-007-recovery', crashPoint });
  store.setNow = (iso) => { state.now = iso; };
  store.restart = () => restart(store, { clock, ids });
  return store;
}

function taskDocument(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    task_id: TASK_ID,
    workspace_id: WORKSPACE,
    title: 'Bounded collection whose side effect may be unknown',
    goal: 'Prove that an unknown external outcome is never a retry',
    description: 'A crash-injection fixture task.',
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
    time_limits: { timeout_ms: TTL_MS, max_runtime_ms: 2 * TTL_MS, deadline: null },
    cost_limits: { currency: 'USD', max_task_cost: 5, max_campaign_cost: 20, max_day_cost: 10 },
    acl: {
      visibility: 'project',
      allowed_principal_ids: [OWNER, SCHEDULER, PRODUCER, RECONCILER, OTHER_REVIEWER],
    },
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

function adapterRegistration() {
  return {
    contractVersion: '1.0.0',
    adapter_id: ADAPTER_ID,
    adapter_interface: 'veritas.adapter/1.0.0',
    provider: 'test',
    display_name: 'Recovery test transport',
    adapter_kind: 'test',
    health: 'healthy',
    workspace_id: WORKSPACE,
    principal_id: PRODUCER,
    declared_capabilities: ['source.read'],
    declared_tools: ['tool:fs.read'],
    sandbox_profile_id: PROFILE,
    max_concurrency: 1,
    // Honest provenance: no installed executor backs this transport, and no
    // fixture in this file may upgrade it to a real-adapter result.
    real_adapter_provenance: {
      status: 'NOT_RUN_REAL_ADAPTER',
      detail: 'crash/recovery fixture: no installed executor is bound to this adapter',
    },
    registered_at: T0,
  };
}

function budgetGrant() {
  return {
    grant_id: GRANT_ID,
    workspace_id: WORKSPACE,
    task_id: TASK_ID,
    currency: 'USD',
    task_limit: 5,
    campaign_limit: 20,
    day_limit: 10,
    timeout_ms: TTL_MS,
    granted_by: OWNER,
  };
}

const SCHEDULER_ACTOR = Object.freeze({
  principal_id: SCHEDULER,
  capabilities: ['board.task.read', 'board.task.transition', 'board.execution.start'],
});

async function createTask(store, { now = T0 } = {}) {
  const task = taskDocument();
  const k = key('tasks.create', { task_id: task.task_id, title: task.title });
  await store.createTask({
    task: { ...task, created_at: now, updated_at: now },
    actor: OWNER,
    actorKind: 'human_owner',
    idempotencyKey: k,
    argsDigest: k,
  });
  return task;
}

async function makeReady(store) {
  await createTask(store);
  const k = key('tasks.transition', { task_id: TASK_ID, to: 'READY' });
  await store.transitionTask({
    taskId: TASK_ID,
    toState: 'READY',
    expectedRevision: 1,
    actor: OWNER,
    actorKind: 'human_owner',
    reason: 'immutable brief validated, dependencies closed',
    idempotencyKey: k,
    argsDigest: k,
  });
}

async function registerAdapterAndBudget(store) {
  const reg = adapterRegistration();
  const ak = key('adapters.register', { adapter_id: reg.adapter_id });
  await store.registerAdapter({ registration: reg, actor: OWNER, idempotencyKey: ak, argsDigest: ak });
  const grant = budgetGrant();
  const bk = key('budget.grant', { grant_id: grant.grant_id });
  await store.grantBudget({ grant, actor: OWNER, idempotencyKey: bk, argsDigest: bk });
  return { reg, grant };
}

/** A full tick: claim -> run -> outbox -> RUNNING. The pre-send canonical state. */
async function tick(store, { now = T0, ids = deterministicIds() } = {}) {
  return runSchedulerTick({
    store,
    workspaceId: WORKSPACE,
    actor: SCHEDULER_ACTOR,
    now,
    ids,
    sandbox: { profile_id: PROFILE, proven: true },
  });
}

async function counts(store, { taskId = TASK_ID } = {}) {
  return {
    tasks: (await store.listTasks({ workspaceId: WORKSPACE, principalId: OWNER, limit: 50 })).length,
    transitions: (await store.listTransitions(taskId, { workspaceId: WORKSPACE, principalId: OWNER })).length,
    audit: (await store.listAudit({ workspaceId: WORKSPACE, taskId })).length,
    outbox: (await store.listOutbox({ workspaceId: WORKSPACE })).length,
    runs: (await store.listRuns({ workspaceId: WORKSPACE })).length,
    leases: (await store.listLeases({ workspaceId: WORKSPACE })).length,
  };
}

function assertRefusal(error, { code = undefined, message = 'a refusal' } = {}) {
  assert.ok(isBoardError(error), `${message} must be a typed BoardError, got ${error?.name}: ${error?.message}`);
  assert.ok(CLOSED_CODES.has(error.code), `${message} must use a code from the closed set, got ${String(error.code)}`);
  if (code !== undefined) assert.equal(error.code, code, `${message}: expected ${code}, got ${error.code}`);
  return error;
}

function transitionOutboxEvent(taskId, to) {
  return { event_type: 'board.task.transitioned', payload: { task_id: taskId, to_state: to } };
}

function boardErrorDocument(code, message) {
  return {
    contractVersion: '1.0.0',
    code,
    message,
    retryable: false,
    detail: null,
    occurred_at: T0,
  };
}

function unknownEvent(run, lease) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    event_id: 'eve-recovery-unknown',
    run_id: run.run_id,
    task_id: run.task_id,
    workspace_id: WORKSPACE,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    sequence: 1,
    event_type: 'UNKNOWN',
    payload: { note: 'the executor never answered; this is data, not a decision' },
    outcome: 'RECONCILIATION_REQUIRED',
    emitted_at: T0,
  };
}

// ============================================================================
// 1. Crash injection at the four write boundaries
// ============================================================================

describe('S2-007 recovery: a crash inside a write commits nothing and is retried exactly once', () => {
  for (const [point, label] of [
    ['journal', 'between the task transition and the journal write'],
    ['outbox', 'between the journal and the outbox write'],
    ['commit', 'between the last staged write and COMMIT'],
  ]) {
    test(`a crash ${label} leaves the store byte-identical and no lost or double record`, async () => {
      const store = makeStore();
      await createTask(store);
      const k = key('tasks.transition', { task_id: TASK_ID, to: 'READY' });
      const call = () => store.transitionTask({
        taskId: TASK_ID,
        toState: 'READY',
        expectedRevision: 1,
        actor: OWNER,
        actorKind: 'human_owner',
        reason: 'immutable brief validated',
        idempotencyKey: k,
        argsDigest: k,
        outboxEvent: transitionOutboxEvent(TASK_ID, 'READY'),
      });

      const before = { snapshot: JSON.stringify(await store.debugSnapshot()), counts: await counts(store) };

      store.arm(point);
      const failure = await call().then(
        (value) => ({ value }),
        (error) => ({ error }),
      );
      assert.ok(failure.error !== undefined, 'a crashed write must never be reported as a success');
      assertRefusal(failure.error, { message: `a crash at ${point}` });
      assert.deepEqual(store.crashes, [point], 'the fault must have fired at the intended write step');

      const after = { snapshot: JSON.stringify(await store.debugSnapshot()), counts: await counts(store) };
      assert.deepEqual(after.counts, before.counts, 'no lost and no double record: every count must be unchanged');
      assert.equal(after.snapshot, before.snapshot, 'a crashed unit of work must leave the store byte-identical');
      assert.equal(
        await store.readOperation(k),
        null,
        'a crashed command must not leave a ledger entry claiming a committed result',
      );
      const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
      assert.equal(task.state, 'BACKLOG', 'the task state must not have moved');
      assert.equal(task.revision, 1, 'the revision must not have moved either');

      // Restart: the only thing that survived is the committed state.
      const restarted = store.restart();
      const retried = await restarted.transitionTask({
        taskId: TASK_ID,
        toState: 'READY',
        expectedRevision: 1,
        actor: OWNER,
        actorKind: 'human_owner',
        reason: 'immutable brief validated',
        idempotencyKey: k,
        argsDigest: k,
        outboxEvent: transitionOutboxEvent(TASK_ID, 'READY'),
      });

      assert.equal(retried.replayed, false, 'the retry after the crash is a first commit, not a replay');
      assert.equal(retried.task.state, 'READY');
      const afterRetry = await counts(restarted);
      assert.equal(afterRetry.transitions, before.counts.transitions + 1, 'exactly one journal row');
      assert.equal(afterRetry.audit, before.counts.audit + 1, 'exactly one audit row');
      assert.equal(afterRetry.outbox, before.counts.outbox + 1, 'exactly one outbox row');
      const operation = await restarted.readOperation(k);
      assert.ok(operation, 'the committed command must be in the ledger');
      assert.equal(operation.operation, 'board.task.transition');

      // And a third identical call is a pure replay.
      const replay = await restarted.transitionTask({
        taskId: TASK_ID,
        toState: 'READY',
        expectedRevision: 1,
        actor: OWNER,
        actorKind: 'human_owner',
        reason: 'immutable brief validated',
        idempotencyKey: k,
        argsDigest: k,
        outboxEvent: transitionOutboxEvent(TASK_ID, 'READY'),
      });
      assert.equal(replay.replayed, true);
      assert.deepEqual(await counts(restarted), afterRetry, 'the replay must add nothing');
    });
  }

  test('a crash after COMMIT and before the caller learned the outcome resolves through the ledger, never through a second write', async () => {
    const store = makeStore();
    await createTask(store);
    const k = key('tasks.transition', { task_id: TASK_ID, to: 'READY' });
    const args = {
      taskId: TASK_ID,
      toState: 'READY',
      expectedRevision: 1,
      actor: OWNER,
      actorKind: 'human_owner',
      reason: 'immutable brief validated',
      idempotencyKey: k,
      argsDigest: k,
      outboxEvent: transitionOutboxEvent(TASK_ID, 'READY'),
    };

    // The write really happens; only the RESPONSE is lost.
    const real = store.transitionTask.bind(store);
    let lostResponse = true;
    store.transitionTask = async (...call) => {
      const result = await real(...call);
      if (lostResponse) {
        lostResponse = false;
        store.transitionTask = real;
        throw new Error('simulated process crash after COMMIT and before the response reached the caller');
      }
      return result;
    };

    const failure = await store.transitionTask(args).then((value) => ({ value }), (error) => ({ error }));
    assert.ok(failure.error !== undefined, 'the caller must not be told the write failed when it committed');
    store.transitionTask = real;

    const committed = await counts(store);
    const restarted = store.restart();
    assert.deepEqual(await counts(restarted), committed, 'a restart must read exactly the committed state');

    // At-least-once delivery: the caller retries the very same command.
    const replay = await restarted.transitionTask(args);
    assert.equal(replay.replayed, true, 'the retried command must resolve to the first committed result');
    assert.equal(replay.task.state, 'READY');
    assert.deepEqual(await counts(restarted), committed, 'an unknown commit outcome must never produce a second record');
  });

  test('history_digest after a crash-and-retry describes exactly the transitions that were written', async () => {
    const store = makeStore();
    await createTask(store);
    const k = key('tasks.transition', { task_id: TASK_ID, to: 'READY' });
    const args = {
      taskId: TASK_ID,
      toState: 'READY',
      expectedRevision: 1,
      actor: OWNER,
      actorKind: 'human_owner',
      reason: 'immutable brief validated',
      idempotencyKey: k,
      argsDigest: k,
      outboxEvent: transitionOutboxEvent(TASK_ID, 'READY'),
    };

    store.arm('outbox');
    await store.transitionTask(args).then(() => assert.fail('the crash must reject'), () => {});

    const retried = await store.transitionTask(args);
    const journal = await store.listTransitions(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(journal.length, 1, 'exactly one journal row may exist');
    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(
      task.history_digest,
      retried.task.history_digest,
      'the task must publish the digest of the history that was actually written',
    );
    const audit = await store.listAudit({ workspaceId: WORKSPACE, taskId: TASK_ID });
    const createAudit = audit.find((row) => row.operation === 'board.task.create');
    const transitionAudit = audit.find((row) => row.operation === 'board.task.transition');
    assert.ok(createAudit, 'the birth record must not be lost');
    assert.ok(transitionAudit, 'the state change must not be lost');
    assert.equal(
      transitionAudit.detail.history_digest,
      retried.task.history_digest,
      'the journal and the audit must agree with the task row on the history (both in wire form)',
    );
  });
});

describe('S2-007 recovery: a crash after the outbox write and before the dispatch send', () => {
  test('the PENDING row survives the crash, is re-dispatchable, and is sent exactly once', async () => {
    const store = makeStore();
    await makeReady(store);
    await registerAdapterAndBudget(store);

    // The tick committed: claim, run, outbox row, RUNNING. Then the process
    // died BEFORE the send. Nothing is faked — the send simply never happens.
    const dispatched = await tick(store);
    assert.ok(dispatched.run, 'the fixture requires a live run to reach the send boundary');
    const outboxId = dispatched.outbox.outbox_id;
    assert.equal(dispatched.outbox.dispatch_state, 'PENDING');

    const before = await counts(store);
    const restarted = store.restart();

    // Recovery sees an un-crossed boundary and must say so without acting.
    const recovered = await recoverOutbox({ store: restarted, actor: SCHEDULER, now: T0, workspaceId: WORKSPACE });
    assert.equal(recovered.escalated, 0, 'a row that never crossed the boundary is not an unknown outcome');
    assert.equal(recovered.externalEffectsIssued, 0, 'recovery reissues no side effect, ever');
    assert.deepEqual(
      recovered.rows.map((row) => row.re_dispatchable),
      [true],
      'a PENDING row after a pre-send crash is legitimately re-dispatchable',
    );
    assert.deepEqual(await counts(restarted), before, 'recovery must not write anything for a PENDING row');

    // A repeat tick is a no-op: the task is not READY any more, so a second
    // run/lease/outbox row would be a duplicate external effect.
    const again = await runSchedulerTick({
      store: restarted,
      workspaceId: WORKSPACE,
      actor: SCHEDULER_ACTOR,
      now: T1,
      ids: deterministicIds(),
      sandbox: { profile_id: PROFILE, proven: true },
    });
    assert.equal(again.run, null, 'a restarted tick must not start a second run');
    assert.equal(again.decision.selected_task_id, null, 'the decision must record that nothing was selected');
    const excluded = again.decision.excluded.find((entry) => entry.subject_id === TASK_ID);
    assert.ok(excluded, 'an unselected candidate must be recorded, not silently dropped');
    assert.ok(
      excluded.reasons.includes('STATE_NOT_READY'),
      `the exclusion reason must name the real cause, got ${JSON.stringify(excluded.reasons)}`,
    );
    assert.deepEqual(await counts(restarted), before, 'the blind retry must not have written anything');

    // And the still-PENDING row is now sent exactly once.
    const { sends, transport } = countingTransport();
    const summary = await driveOutbox({ store: restarted, transport, actor: SCHEDULER, now: T1, workspaceId: WORKSPACE });
    assert.equal(sends.length, 1, 'exactly one crossing of the external boundary');
    assert.equal(summary.externalEffectsIssued, 1);
    assert.equal(summary.acked, 1);
    const rows = await restarted.listOutbox({ workspaceId: WORKSPACE });
    const row = rows.find((entry) => entry.outbox_id === outboxId);
    assert.equal(row.dispatch_state, 'ACKED');
    assert.ok(row.sent_at !== null && row.acked_at !== null, 'the happy path stamps both instants');

    const second = await driveOutbox({ store: restarted, transport, actor: SCHEDULER, now: T1, workspaceId: WORKSPACE });
    assert.equal(sends.length, 1, 'an acknowledged row is history and is never sent again');
    assert.equal(second.inspected, 0, 'there is nothing left to inspect');
  });
});

describe('S2-007 recovery: a crash after the dispatch send and before the result collection', () => {
  /**
   * The unknowable case. `driveOutbox` records the send intent BEFORE it calls
   * the transport, so a crash between the send and the acknowledgement leaves
   * a SENT row with no ack. Whether the executor ran is unknown, and the only
   * correct answers are: never send it again, and escalate.
   */
  async function sentWithoutAck() {
    const store = makeStore();
    await makeReady(store);
    await registerAdapterAndBudget(store);
    const dispatched = await tick(store);
    const k = key('outbox.dispatch.intent', { outbox_id: dispatched.outbox.outbox_id }, SCHEDULER);
    await store.markOutboxSent({ outboxId: dispatched.outbox.outbox_id, actor: SCHEDULER, idempotencyKey: k, argsDigest: k });
    // The executor was told to start (one crossing), then the process died
    // before the acknowledgement and before any result was collected.
    const { sends, transport } = countingTransport();
    await transport.dispatch(dispatched.outbox.payload);
    return { store, dispatched, sends, transport };
  }

  test('a SENT row with no acknowledgement escalates and is NEVER re-sent', async () => {
    const { store, dispatched, sends, transport } = await sentWithoutAck();
    const outboxId = dispatched.outbox.outbox_id;
    assert.equal(sends.length, 1, 'the fixture crossed the boundary exactly once');

    // A driver that finds a SENT row has nothing to do with it: the intent was
    // already recorded, so the effect may already have happened.
    const second = await driveOutbox({ store, transport, actor: SCHEDULER, now: T1, workspaceId: WORKSPACE });
    assert.equal(sends.length, 1, 'a SENT row must never be handed to the transport again');
    assert.equal(second.intentRecorded, 0);

    // A blind retry of the dispatch is not re-sent: the driver simply has
    // nothing in its PENDING batch, and the row it must not touch is untouched.
    const blind = await driveOutbox({ store, transport, actor: SCHEDULER, now: T1, workspaceId: WORKSPACE });
    assert.equal(blind.inspected, 0, 'a SENT row is not part of the PENDING batch');
    assert.equal(blind.externalEffectsIssued, 0, 'a blind retry must not cross the boundary');
    assert.equal(sends.length, 1, 'the dispatch attempts must stay at 1 for the whole lifecycle of this row');

    const row = (await store.listOutbox({ workspaceId: WORKSPACE })).find((entry) => entry.outbox_id === outboxId);
    assert.ok(['RECONCILIATION_REQUIRED', 'SENT'].includes(row.dispatch_state), `unexpected state ${row.dispatch_state}`);

    const recovered = await recoverOutbox({
      store, actor: SCHEDULER, now: T1, workspaceId: WORKSPACE, ids: deterministicIds(),
    });
    assert.equal(sends.length, 1, 'recoverOutbox has no transport at all and must reissue nothing');
    assert.equal(recovered.externalEffectsIssued, 0);
    assert.equal(recovered.escalated, 1, 'a SENT row without an ack must escalate');
    const escalated = (await store.listOutbox({ workspaceId: WORKSPACE })).find((entry) => entry.outbox_id === outboxId);
    assert.equal(escalated.dispatch_state, 'RECONCILIATION_REQUIRED');
    assert.match(String(escalated.last_error), /UNKNOWN_OUTCOME/, 'the escalation must name the unknown outcome');
    assert.equal(recovered.rows[0].re_dispatchable, false, 'RECONCILIATION_REQUIRED is terminal for retry purposes');

    // No lost record: the journal explains the escalation, and the run and the
    // task keep the state that was actually committed.
    const events = await store.listEvents(dispatched.run.run_id);
    assert.ok(
      events.some((event) => event.event_type === 'UNKNOWN' && event.outcome === 'RECONCILIATION_REQUIRED'),
      'the append-only journal must record the unknown outcome',
    );
    const run = await store.readRun(dispatched.run.run_id, { principalId: SCHEDULER, workspaceId: WORKSPACE });
    assert.equal(run.run_state, 'RECONCILIATION_REQUIRED', 'the run must not claim a success it never observed');
    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(task.state, 'RUNNING', 'the task state is not rewritten by an escalation');
    assert.notEqual(task.state, 'IN_REVIEW');
    assert.notEqual(task.state, 'DONE');

    // RECONCILIATION_REQUIRED is terminal for the outbox state machine.
    await assert.rejects(
      () => store.escalateOutbox({
        outboxId,
        reason: 'UNKNOWN_OUTCOME: a second escalation attempt',
        actor: SCHEDULER,
        idempotencyKey: key('outbox.escalate.again', { outbox_id: outboxId }, SCHEDULER),
        argsDigest: key('outbox.escalate.again', { outbox_id: outboxId }, SCHEDULER),
      }),
      (error) => isBoardError(error) && error.code === 'TRANSITION_NOT_ALLOWED',
    );

    // And after a restart the escalation is still the canonical state.
    const restarted = store.restart();
    const afterRestart = await recoverOutbox({
      store: restarted, actor: SCHEDULER, now: T1, workspaceId: WORKSPACE, ids: deterministicIds(),
    });
    assert.equal(afterRestart.escalated, 0, 'recovery is idempotent: the escalation is already recorded');
    assert.equal(afterRestart.externalEffectsIssued, 0);
    assert.equal(sends.length, 1, 'a restart must not re-send anything');
  });

  test('a transport that dies at the boundary escalates instead of being retried', async () => {
    const store = makeStore();
    await makeReady(store);
    await registerAdapterAndBudget(store);
    const dispatched = await tick(store);
    const { sends, transport } = countingTransport({
      fail: Object.assign(new Error('the socket closed after the write'), { code: 'ECONNRESET' }),
    });

    await assert.rejects(
      () => driveOutbox({ store, transport, actor: SCHEDULER, now: T0, workspaceId: WORKSPACE }),
      (error) => {
        assertRefusal(error, { code: 'RECONCILIATION_REQUIRED', message: 'an unknown boundary outcome' });
        assert.ok(
          NON_RETRYABLE_CODES.includes(error.code),
          'an unknown outcome is never a blind retry',
        );
        return true;
      },
    );
    assert.equal(sends.length, 1, 'the boundary was crossed once, unacknowledged');
    const row = (await store.listOutbox({ workspaceId: WORKSPACE })).find((entry) => entry.outbox_id === dispatched.outbox.outbox_id);
    assert.equal(row.dispatch_state, 'RECONCILIATION_REQUIRED');

    const second = await driveOutbox({ store, transport, actor: SCHEDULER, now: T1, workspaceId: WORKSPACE });
    assert.equal(sends.length, 1, 'the failed dispatch must never be re-sent');
    assert.equal(second.inspected, 0, 'an escalated row is out of the PENDING batch');
  });

  test('the outbox state machine never skips SENT and never walks backwards', async () => {
    const store = makeStore();
    await makeReady(store);
    await registerAdapterAndBudget(store);
    const dispatched = await tick(store);
    const outboxId = dispatched.outbox.outbox_id;

    // PENDING -> ACKED is not a step.
    const ackKey = key('outbox.ack.early', { outbox_id: outboxId }, SCHEDULER);
    await assert.rejects(
      () => store.markOutboxAcked({ outboxId, actor: SCHEDULER, idempotencyKey: ackKey, argsDigest: ackKey }),
      (error) => isBoardError(error) && error.code === 'TRANSITION_NOT_ALLOWED',
    );
    const stillPending = (await store.listOutbox({ workspaceId: WORKSPACE })).find((entry) => entry.outbox_id === outboxId);
    assert.equal(stillPending.dispatch_state, 'PENDING', 'a refused step must not change the state');

    // PENDING -> SENT -> ACKED is the only happy path.
    const sentKey = key('outbox.sent', { outbox_id: outboxId }, SCHEDULER);
    const sent = await store.markOutboxSent({ outboxId, actor: SCHEDULER, idempotencyKey: sentKey, argsDigest: sentKey });
    assert.equal(sent.dispatch_state, 'SENT');
    const ackKey2 = key('outbox.ack', { outbox_id: outboxId }, SCHEDULER);
    const acked = await store.markOutboxAcked({ outboxId, actor: SCHEDULER, idempotencyKey: ackKey2, argsDigest: ackKey2 });
    assert.equal(acked.dispatch_state, 'ACKED');
  });

  test('KNOWN GAP (expected red until store.mjs accounts for it): the outbox row records how many times the boundary was crossed', async () => {
    // `agentboard_outbox.attempts` exists in the frozen migration and is the
    // per-row evidence a `duplicateExternalEffects` hard gate has to read. The
    // in-memory twin never increments it, so today the only trustworthy
    // observation of "was this sent more than once" is the transport's own
    // counter. This test pins the requirement: the row must account for every
    // crossing. It is RED while the store does not maintain the column.
    const store = makeStore();
    await makeReady(store);
    await registerAdapterAndBudget(store);
    const dispatched = await tick(store);
    const { sends, transport } = countingTransport();
    const summary = await driveOutbox({ store, transport, actor: SCHEDULER, now: T0, workspaceId: WORKSPACE });
    assert.equal(sends.length, 1);
    assert.equal(summary.externalEffectsIssued, 1);

    const row = (await store.listOutbox({ workspaceId: WORKSPACE })).find((entry) => entry.outbox_id === dispatched.outbox.outbox_id);
    assert.equal(
      row.attempts,
      sends.length,
      'the outbox row must account for exactly the number of boundary crossings, so a duplicate effect is provable from the row alone',
    );
  });
});

// ============================================================================
// 2. Closing a RECONCILIATION_REQUIRED run
// ============================================================================

describe('S2-007 recovery: closing a RECONCILIATION_REQUIRED run requires an authorized decider', () => {
  async function escalatedRun() {
    const store = makeStore();
    await makeReady(store);
    await registerAdapterAndBudget(store);
    const dispatched = await tick(store);
    const intent = key('outbox.dispatch.intent', { outbox_id: dispatched.outbox.outbox_id }, SCHEDULER);
    await store.markOutboxSent({ outboxId: dispatched.outbox.outbox_id, actor: SCHEDULER, idempotencyKey: intent, argsDigest: intent });
    await recoverOutbox({ store, actor: SCHEDULER, now: T0, workspaceId: WORKSPACE, ids: deterministicIds() });
    return { store, dispatched };
  }

  function decision(runId, overrides = {}) {
    return {
      run_id: runId,
      resolution: 'OBSERVED_NO_EFFECT',
      detail: 'the executor log shows the job never started',
      ...overrides,
    };
  }

  test('the producing adapter is refused: a producer may never close its own run', async () => {
    const { store, dispatched } = await escalatedRun();
    for (const kind of ['adapter', 'scheduler', 'system']) {
      const k = key('reconciliation.record', { run_id: dispatched.run.run_id, kind }, PRODUCER);
      await assert.rejects(
        () => store.recordReconciliation({
          reconciliation: decision(dispatched.run.run_id),
          actor: PRODUCER,
          actorKind: kind,
          idempotencyKey: k,
          argsDigest: k,
        }),
        (error) => {
          assertRefusal(error, { code: 'BLOCKED_POLICY', message: `a ${kind} decider` });
          return true;
        },
      );
    }
    assert.deepEqual(
      await store.listReconciliations({ runId: dispatched.run.run_id }),
      [],
      'no refused decider may leave a reconciliation record',
    );
  });

  test('an authenticated human or an explicitly authorized deterministic gate may close it', async () => {
    for (const kind of ['human_owner', 'human_reviewer', 'deterministic_gate']) {
      const { store, dispatched } = await escalatedRun();
      const k = key('reconciliation.record', { run_id: dispatched.run.run_id, kind }, RECONCILER);
      const recorded = await store.recordReconciliation({
        reconciliation: decision(dispatched.run.run_id),
        actor: RECONCILER,
        actorKind: kind,
        idempotencyKey: k,
        argsDigest: k,
      });
      assert.equal(recorded.reconciliation.resolution, 'OBSERVED_NO_EFFECT');
      assert.equal(recorded.reconciliation.decided_by, RECONCILER, 'the decider is the server-resolved actor');
      assert.equal(recorded.reconciliation.decided_by_kind, kind);

      // The same decision replayed is one record, not two.
      const replay = await store.recordReconciliation({
        reconciliation: decision(dispatched.run.run_id),
        actor: RECONCILER,
        actorKind: kind,
        idempotencyKey: k,
        argsDigest: k,
      });
      assert.equal(replay.replayed, true);
      assert.equal((await store.listReconciliations({ runId: dispatched.run.run_id })).length, 1);
    }
  });

  test('a payload may not name its own decider', async () => {
    const { store, dispatched } = await escalatedRun();
    const k = key('reconciliation.record', { run_id: dispatched.run.run_id, forged: true }, RECONCILER);
    await assert.rejects(
      () => store.recordReconciliation({
        reconciliation: decision(dispatched.run.run_id, { decided_by: OWNER }),
        actor: RECONCILER,
        actorKind: 'human_owner',
        idempotencyKey: k,
        argsDigest: k,
      }),
      (error) => {
        assertRefusal(error, { code: 'AUTH_REQUIRED', message: 'a payload that names its own decider' });
        return true;
      },
    );
    assert.deepEqual(await store.listReconciliations({ runId: dispatched.run.run_id }), []);
  });

  test('an unknown resolution is refused rather than stored as a decision', async () => {
    const { store, dispatched } = await escalatedRun();
    const k = key('reconciliation.record', { run_id: dispatched.run.run_id, bogus: true }, RECONCILER);
    await assert.rejects(
      () => store.recordReconciliation({
        reconciliation: decision(dispatched.run.run_id, { resolution: 'PROBABLY_FINE' }),
        actor: RECONCILER,
        actorKind: 'human_owner',
        idempotencyKey: k,
        argsDigest: k,
      }),
      (error) => {
        assertRefusal(error, { code: 'BLOCKED_POLICY', message: 'an unknown resolution' });
        return true;
      },
    );
  });

  test('a requeue is refused without a recorded decision and allowed after one', async () => {
    const { store, dispatched } = await escalatedRun();
    const lease = await store.readLease(dispatched.lease.lease_id, { principalId: OWNER, workspaceId: WORKSPACE });
    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    const ctx = {
      task,
      fromState: 'RUNNING',
      toState: 'READY',
      actor: OWNER,
      actorKind: 'human_owner',
      now: T1,
      reason: 'requeue after an authorized decision',
      lease,
      fencingToken: lease.fencing_token,
      expectedRevision: task.revision,
      adapters: [adapterRegistration()],
      sandboxProfileId: PROFILE,
      workspaceRoots: ['/tmp', 'projects/alpha'],
      capabilities: ['board.reconciliation.decide'],
      budgetGrant: budgetGrant(),
      budgetSpent: { spent_task: 0, spent_campaign: 0, spent_day: 0 },
    };

    assert.throws(
      () => decideTransition({ task, toState: 'READY', context: ctx }),
      (error) => {
        assertRefusal(error, { code: 'RECONCILIATION_REQUIRED', message: 'a requeue without a decision' });
        return true;
      },
      'a blind requeue is not a recovery',
    );

    // The same actor may not be the decider of its own requeue.
    assert.throws(
      () => decideTransition({
        task,
        toState: 'READY',
        context: {
          ...ctx,
          actor: PRODUCER,
          capabilities: ['board.reconciliation.decide'],
          reconciliation: { resolution: 'OBSERVED_NO_EFFECT', decided_by: PRODUCER, decided_by_kind: 'human_reviewer' },
        },
      }),
      (error) => {
        assertRefusal(error, { code: 'BLOCKED_POLICY', message: 'a self-reconciling requeue' });
        return true;
      },
    );

    const k = key('reconciliation.record', { run_id: dispatched.run.run_id, decider: 'reviewer' }, OTHER_REVIEWER);
    await store.recordReconciliation({
      reconciliation: decision(dispatched.run.run_id),
      actor: OTHER_REVIEWER,
      actorKind: 'human_reviewer',
      idempotencyKey: k,
      argsDigest: k,
    });
    const recorded = (await store.listReconciliations({ runId: dispatched.run.run_id }))[0];
    // decideTransition returns nothing on ALLOW — the absence of a typed
    // refusal IS the permission, and a re-invented return value would be a
    // second, invisible verdict.
    assert.doesNotThrow(
      () => decideTransition({
        task,
        toState: 'READY',
        context: {
          ...ctx,
          reconciliation: {
            resolution: recorded.resolution,
            decided_by: recorded.decided_by,
            decided_by_kind: recorded.decided_by_kind,
          },
        },
      }),
      'an authorized, recorded decision makes the requeue admissible',
    );
  });
});

// ============================================================================
// 3. An unknown outcome is never a review, a DONE or a retry
// ============================================================================

describe('S2-007 recovery: an unknown outcome never becomes IN_REVIEW, DONE or a retry', () => {
  /** A live run whose executor reported that it does not know what happened. */
  async function unknownOutcomeRun() {
    const store = makeStore();
    await makeReady(store);
    await registerAdapterAndBudget(store);
    const dispatched = await tick(store);
    const run = dispatched.run;
    const lease = await store.readLease(dispatched.lease.lease_id, { principalId: OWNER, workspaceId: WORKSPACE });

    const dispatchKey = key('execution.dispatch', { run_id: run.run_id }, SCHEDULER);
    await store.markRunDispatched({ runId: run.run_id, actor: SCHEDULER, idempotencyKey: dispatchKey, argsDigest: dispatchKey });

    const eventKey = key('execution.event', { run_id: run.run_id, sequence: 1 }, SCHEDULER);
    await store.appendExecutionEvent({
      event: unknownEvent(run, lease),
      actor: SCHEDULER,
      idempotencyKey: eventKey,
      argsDigest: eventKey,
    });
    return { store, dispatched, run, lease };
  }

  test('the unknown outcome is recorded and the task state is not moved by it', async () => {
    const { store, run } = await unknownOutcomeRun();
    const closed = await store.readRun(run.run_id, { principalId: SCHEDULER, workspaceId: WORKSPACE });
    assert.equal(closed.run_state, 'RECONCILIATION_REQUIRED', 'an unknown outcome closes the run as unknown');
    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    assert.equal(task.state, 'RUNNING', 'a result is evidence, not a state change');
    assert.notEqual(task.state, 'IN_REVIEW');
    assert.notEqual(task.state, 'DONE');
  });

  test('the run cannot be retried: a new-key result is refused and the same key replays', async () => {
    const { store, run, lease } = await unknownOutcomeRun();
    const result = {
      contract_version: 'veritas.execution/1.0.0',
      run_id: run.run_id,
      task_id: run.task_id,
      workspace_id: WORKSPACE,
      lease_id: lease.lease_id,
      fencing_token: lease.fencing_token,
      sequence: 1,
      outcome: 'RECONCILIATION_REQUIRED',
      checkpoints: [],
      artifact_hashes: [],
      measurements: { duration_ms: 0, spend: 0, currency: 'USD', model_id: null, tool_calls: 0 },
      error: boardErrorDocument('UNKNOWN_OUTCOME', 'the executor never answered'),
      reconciliation_required: true,
      completed_at: T0,
    };

    const blindKey = key('execution.collect_result', { run_id: run.run_id, attempt: 2 }, SCHEDULER);
    await assert.rejects(
      () => store.collectResult({ result, actor: SCHEDULER, idempotencyKey: blindKey, argsDigest: blindKey }),
      (error) => {
        assertRefusal(error, { code: 'TRANSITION_NOT_ALLOWED', message: 'a result for a run that is no longer live' });
        return true;
      },
    );
    const unchanged = await store.readRun(run.run_id, { principalId: SCHEDULER, workspaceId: WORKSPACE });
    assert.equal(unchanged.run_state, 'RECONCILIATION_REQUIRED', 'a refused retry must not change the run');
    assert.equal((await store.listEvents(run.run_id)).length, 1, 'no second journal entry');
  });

  test('a duplicate execution event is refused and the identical one replays', async () => {
    const { store, run, lease } = await unknownOutcomeRun();
    const eventKey = key('execution.event', { run_id: run.run_id, sequence: 1 }, SCHEDULER);
    const replay = await store.appendExecutionEvent({
      event: unknownEvent(run, lease),
      actor: SCHEDULER,
      idempotencyKey: eventKey,
      argsDigest: eventKey,
    });
    assert.equal(replay.replayed, true, 'the identical callback is a replay, not a second record');
    assert.equal((await store.listEvents(run.run_id)).length, 1);

    const duplicateKey = key('execution.event', { run_id: run.run_id, sequence: 1, resent: true }, SCHEDULER);
    await assert.rejects(
      () => store.appendExecutionEvent({
        event: { ...unknownEvent(run, lease), event_id: 'eve-recovery-unknown-again' },
        actor: SCHEDULER,
        idempotencyKey: duplicateKey,
        argsDigest: duplicateKey,
      }),
      (error) => {
        assertRefusal(error, { code: 'TRANSITION_NOT_ALLOWED', message: 'a duplicated sequence' });
        return true;
      },
    );
    assert.equal((await store.listEvents(run.run_id)).length, 1, 'a duplicate callback must not become a second record');
  });

  test('an undetermined effect is refused at the review edge and at the DONE edge', async () => {
    const { store, run, lease } = await unknownOutcomeRun();
    const task = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });
    const undetermined = {
      resolution: 'EFFECT_UNDETERMINED',
      decided_by: RECONCILER,
      decided_by_kind: 'human_reviewer',
    };
    const ctx = {
      task,
      actor: PRODUCER,
      actorKind: 'adapter',
      // RUNNING -> IN_REVIEW legitimately requires a LIVE lease, so the
      // injected instant must still be inside the claim TTL.
      now: T_INSIDE_LEASE,
      reason: 'the producer reports the work is ready for review',
      lease,
      fencingToken: lease.fencing_token,
      expectedRevision: task.revision,
      adapters: [adapterRegistration()],
      sandboxProfileId: PROFILE,
      workspaceRoots: ['/tmp', 'projects/alpha'],
      capabilities: ['board.evidence.submit', 'board.review.approve'],
      budgetGrant: budgetGrant(),
      budgetSpent: { spent_task: 0, spent_campaign: 0, spent_day: 0 },
      reconciliation: undetermined,
      canonicalArgs: { brief_digest: BRIEF, policy_digest: POLICY, manifest_digest: MANIFEST },
    };

    assert.throws(
      () => decideTransition({ task, toState: 'IN_REVIEW', context: { ...ctx, fromState: 'RUNNING', toState: 'IN_REVIEW' } }),
      (error) => {
        assertRefusal(error, { code: 'RECONCILIATION_REQUIRED', message: 'an IN_REVIEW behind an undetermined effect' });
        return true;
      },
      'an unknown outcome never becomes a review',
    );

    // The same rule on the only edge into DONE. Reaching it honestly needs the
    // task to actually be in review, so the lease is released into IN_REVIEW
    // first (the release itself moves the task there, in one transaction).
    const releaseKey = key('tasks.lease.release', { lease_id: lease.lease_id, to: 'IN_REVIEW' }, OWNER);
    const released = await store.releaseLease({
      leaseId: lease.lease_id,
      fencingToken: lease.fencing_token,
      reason: 'executor reported an unknown outcome; the work is submitted for an independent decision',
      expectedRevision: task.revision,
      actor: OWNER,
      actorKind: 'human_owner',
      toState: 'IN_REVIEW',
      idempotencyKey: releaseKey,
      argsDigest: releaseKey,
    });
    assert.throws(
      () => decideTransition({
        task: released.task,
        toState: 'DONE',
        context: {
          ...ctx,
          task: released.task,
          fromState: 'IN_REVIEW',
          toState: 'DONE',
          actor: OWNER,
          actorKind: 'human_owner',
          // The release bumped the revision; a stale one is a REVISION_CONFLICT
          // and would mask the property under test.
          expectedRevision: released.task.revision,
        },
      }),
      (error) => {
        assertRefusal(error, { code: 'RECONCILIATION_REQUIRED', message: 'a DONE behind an undetermined effect' });
        return true;
      },
      'an unknown outcome never becomes a DONE',
    );
    assert.equal((await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER })).state, 'IN_REVIEW');
  });

  test('the producing adapter is refused at the DONE edge, and the lease holder cannot approve its own work', async () => {
    const { store, dispatched } = await unknownOutcomeRun();
    const lease = await store.readLease(dispatched.lease.lease_id, { principalId: OWNER, workspaceId: WORKSPACE });
    const running = await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER });

    // The only honest way into IN_REVIEW with a released lease: the release
    // itself moves the task there in one transaction.
    const releaseKey = key('tasks.lease.release', { lease_id: lease.lease_id, to: 'IN_REVIEW' }, OWNER);
    const released = await store.releaseLease({
      leaseId: lease.lease_id,
      fencingToken: lease.fencing_token,
      reason: 'executor reported an unknown outcome; the work is submitted for an independent decision',
      expectedRevision: running.revision,
      actor: OWNER,
      actorKind: 'human_owner',
      toState: 'IN_REVIEW',
      idempotencyKey: releaseKey,
      argsDigest: releaseKey,
    });
    assert.equal(released.task.state, 'IN_REVIEW');
    const task = released.task;
    const ctx = {
      task,
      fromState: 'IN_REVIEW',
      toState: 'DONE',
      now: T1,
      reason: 'approval of the submitted work',
      lease,
      fencingToken: lease.fencing_token,
      expectedRevision: task.revision,
      adapters: [adapterRegistration()],
      sandboxProfileId: PROFILE,
      workspaceRoots: ['/tmp', 'projects/alpha'],
      capabilities: ['board.review.approve'],
      budgetGrant: budgetGrant(),
      budgetSpent: { spent_task: 0, spent_campaign: 0, spent_day: 0 },
      reconciliation: { resolution: 'OBSERVED_NO_EFFECT', decided_by: RECONCILER, decided_by_kind: 'human_reviewer' },
      canonicalArgs: { brief_digest: BRIEF, policy_digest: POLICY, manifest_digest: MANIFEST },
    };

    assert.throws(
      () => decideTransition({ task, toState: 'DONE', context: { ...ctx, actor: PRODUCER, actorKind: 'adapter' } }),
      (error) => {
        assertRefusal(error, { code: 'BLOCKED_POLICY', message: 'a producer-driven DONE' });
        return true;
      },
      'an adapter is not a review gate',
    );
    assert.throws(
      () => decideTransition({ task, toState: 'DONE', context: { ...ctx, actor: SCHEDULER, actorKind: 'human_owner' } }),
      (error) => {
        assertRefusal(error, { code: 'BLOCKED_POLICY', message: 'a self-approved DONE' });
        return true;
      },
      'the principal that holds the lease is the recorded producer, so it may never be the gate — not even with a human actor kind',
    );
    assert.equal(
      (await store.getTask(TASK_ID, { workspaceId: WORKSPACE, principalId: OWNER })).state,
      'IN_REVIEW',
      'a refused approval must not move the task',
    );
  });
});
