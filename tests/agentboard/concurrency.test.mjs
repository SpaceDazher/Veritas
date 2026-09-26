// S2-007 — CONCURRENCY: two independent processes, one task, one lease
// (issue #7 §4 "the execution boundary", spec §3.2 store tier, spec §4 hard
// gate `duplicateActiveLeases`).
//
// WHY THIS FILE EXISTS
// Every other property of the board is single-writer. This one is not, and it
// is the one that decides whether the board is safe to run at all:
//
//   1. TWO PROCESSES, ONE TASK. Two INDEPENDENT OS processes claim the same
//      task at the same moment, each with its own connection, its own session
//      and its own memory. Exactly one may win; the loser must receive a TYPED
//      BoardError, and the database must end up with exactly one ACTIVE lease,
//      one transition and one attempt. This is driven with node:child_process
//      against a real PostgreSQL (the store's "real gate"): two awaited calls
//      inside one JavaScript heap are cooperative, not concurrent, and the
//      in-memory twin has no row locks, so nothing about the cross-process
//      guarantee can be decided without a database.
//   2. THE SAME CLAIM AGAINST THE IN-MEMORY TWIN. The twin exists so the rest
//      of the suite is deterministic, which makes it the tier the probes run
//      on. If two concurrent claims both succeed there, the twin is NOT a
//      behavioural twin of the real store and a hard-gate counter computed on
//      it is worthless.
//   3. THE DATABASE CLOCK, NOT THE PROCESS CLOCK. A lease decision that reads
//      the process clock is wrong on every machine whose clock drifts, and the
//      in-memory twin cannot show it. A store is deliberately given an
//      injected clock in the year 2099 (everything "expired") and in 1970
//      (nothing "expired"); the sweep must ignore both and follow `NOW()`.
//   4. A LATE CALLBACK MUTATES NOTHING — after an expiry, after a cancel, and
//      after a RESTART, where the restart is a brand new store instance opened
//      over the same committed contents. No task row, no journal row, no audit
//      row, no outbox row: the comparison is a canonical digest of the whole
//      workspace read straight out of PostgreSQL, not an in-process snapshot.
//
// WHY A FAILURE HERE IS NOT A FLAKY TEST
// The race is not left to chance. The two children are started, each writes a
// readiness marker and then blocks on a barrier FILE, and the parent only
// releases them once both are parked on that barrier. The winner is asserted
// by the DATABASE, not by the order in which the answers arrived: exactly one
// ACTIVE lease row, one transition into CLAIMED, `attempts = 1`.
//
// NOT RUN_DB IS NOT A SKIP. A cross-process claim cannot be faked, and a test
// that quietly passed without a database would be exactly the "fake green"
// this repository forbids. If no PostgreSQL can be reached the test FAILS with
// NOT_RUN_DB and the reason. A connection string is used when the environment
// supplies one (VERITAS_S2_007_TEST_DATABASE_URL, then DATABASE_URL);
// otherwise a disposable container is started from the PINNED image with
// `--pull=never` and removed again in the file-level `after` hook.

import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import pg from 'pg';

import { InMemoryAgentBoardStore, PostgresAgentBoardStore } from '../../src/lib/agentboard/store.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { isBoardError } from '../../src/lib/agentboard/errors.mjs';
import { ERROR_CODES } from '../../src/lib/agentboard/constants.mjs';
import { commandIdempotencyKey, fixedClock } from '../../src/lib/agentboard/policy.mjs';
import { applyMigrations } from '../../scripts/apply-migrations.mjs';

const { Pool } = pg;
const execFileAsync = promisify(execFile);

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
// The race child lives in this chat's tmp/ and imports the store by absolute
// path. If it is missing the test fails loudly — a helper that vanished must
// never turn into a green cross-process claim.
const RACE_CHILD = path.join(ROOT, '.bb/chats/thr_8sxageuj7j/tmp/s2-007-claim-race-child.mjs');

// The image is pinned by digest (spec §5): a floating tag would make this test
// depend on whatever the registry served today.
const PINNED_POSTGRES = 'docker.io/library/postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73';
const CONTAINER = 's2007-concurrency-pg';

const CLOSED_CODES = new Set(ERROR_CODES);
const RACE_LOSS_CODES = ['REVISION_CONFLICT', 'TRANSITION_NOT_ALLOWED', 'STALE_FENCE', 'IDEMPOTENCY_CONFLICT'];
const PROFILE = 'sbx-podman-local-restricted-v1';
const OWNER = 'prn-race-owner';
const SCHEDULER = 'prn-race-scheduler';
const PRODUCER = 'prn-race-producer';

const digest = (char) => `sha256:${char.repeat(64)}`;
const BRIEF = digest('b');
const POLICY = digest('c');
const MANIFEST = digest('d');

// ===========================================================================
// Fixtures — the same shape the store tier freezes, parameterised by workspace
// so several tests can share one database without colliding.
// ===========================================================================

function taskDocument({ taskId, workspaceId, now }) {
  return {
    contractVersion: '1.0.0',
    task_id: taskId,
    workspace_id: workspaceId,
    title: 'Concurrent claim fixture',
    goal: 'Prove that one task yields at most one active lease',
    description: 'Bounded fixture for the concurrency suite.',
    acceptance_criteria: ['Exactly one active lease at any time'],
    state: 'BACKLOG',
    revision: 1,
    priority: 'HIGH',
    dependencies: [],
    required_capabilities: [],
    allowed_tools: [],
    workspace_ref: {
      workspace_id: workspaceId,
      root_ref: 'projects/race',
      isolation_profile_id: PROFILE,
      sandbox_profile_digest: digest('a'),
      read_only_paths: [],
    },
    time_limits: { timeout_ms: 60_000, max_runtime_ms: 120_000, deadline: null },
    cost_limits: { currency: 'USD', max_task_cost: 5, max_campaign_cost: 20, max_day_cost: 10 },
    acl: { visibility: 'project', allowed_principal_ids: [OWNER, SCHEDULER, PRODUCER] },
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
    created_at: now,
    updated_at: now,
    history_digest: digest('e'),
  };
}

function adapterRegistration(adapterId, workspaceId, now) {
  return {
    contractVersion: '1.0.0',
    adapter_id: adapterId,
    adapter_interface: 'veritas.adapter/1.0.0',
    provider: 'test',
    display_name: `Race transport ${adapterId}`,
    adapter_kind: 'test',
    health: 'healthy',
    workspace_id: workspaceId,
    principal_id: PRODUCER,
    declared_capabilities: [],
    declared_tools: [],
    sandbox_profile_id: PROFILE,
    max_concurrency: 1,
    real_adapter_provenance: {
      status: 'NOT_RUN_REAL_ADAPTER',
      detail: 'test transport: no installed executor is bound to this adapter',
    },
    registered_at: now,
  };
}

/**
 * Deterministic id factory. The namespace is part of every id on purpose:
 * `agentboard_audit`, `agentboard_outbox` and `agentboard_transition` are
 * keyed by their own id alone, so two store instances sharing one database
 * must never mint the same one — that would be a spurious IDEMPOTENCY_CONFLICT
 * that has nothing to do with the property under test.
 */
function deterministicIds(namespace) {
  const counters = new Map();
  return (kind) => {
    const next = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, next);
    return `${kind}-${namespace}-${next.toString(36).padStart(6, '0')}`;
  };
}

const key = (command, args, actor = SCHEDULER) => commandIdempotencyKey({ command, args, actor });

async function seedReadyTask(store, { taskId, workspaceId, now, adapters }) {
  const task = taskDocument({ taskId, workspaceId, now });
  const createKey = key('tasks.create', { task_id: taskId }, OWNER);
  await store.createTask({ task, actor: OWNER, actorKind: 'human_owner', idempotencyKey: createKey, argsDigest: createKey });
  const readyKey = key('tasks.transition', { task_id: taskId, to: 'READY' }, OWNER);
  await store.transitionTask({
    taskId,
    toState: 'READY',
    expectedRevision: 1,
    actor: OWNER,
    actorKind: 'human_owner',
    reason: 'fixture: brief validated, budget assigned',
    idempotencyKey: readyKey,
    argsDigest: readyKey,
  });
  for (const adapterId of adapters) {
    const adapterKey = key('adapters.register', { adapter_id: adapterId }, OWNER);
    await store.registerAdapter({
      registration: adapterRegistration(adapterId, workspaceId, now),
      actor: OWNER,
      idempotencyKey: adapterKey,
      argsDigest: adapterKey,
    });
  }
  return store.getTask(taskId, { workspaceId, principalId: OWNER });
}

function claimCall({ taskId, workspaceId, adapterId, expectedRevision, ttlMs = 60_000, label }) {
  const k = key('tasks.claim', { task_id: taskId, adapter_id: adapterId, label });
  return (store) => store.claimTask({
    taskId,
    workspaceId,
    adapterId,
    ttlMs,
    expectedRevision,
    actor: SCHEDULER,
    actorKind: 'scheduler',
    idempotencyKey: k,
    argsDigest: k,
  });
}

// ===========================================================================
// PostgreSQL harness. One disposable container for the whole file.
// ===========================================================================

function notRunDb(detail) {
  return new Error(
    `NOT_RUN_DB: the cross-process claim race needs a real PostgreSQL and none could be reached — ${detail}. `
    + 'Set VERITAS_S2_007_TEST_DATABASE_URL (or DATABASE_URL) to a migrated database. '
    + 'This test deliberately fails instead of skipping: a concurrency gate that silently does not run is a fake PASS.',
  );
}

async function podman(args) {
  return execFileAsync('podman', args, { maxBuffer: 4 * 1024 * 1024 });
}

async function waitForPostgres(connectionString, attempts = 60) {
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 2000 });
  try {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        await pool.query('SELECT 1');
        return true;
      } catch {
        await delay(500);
      }
    }
    return false;
  } finally {
    await pool.end().catch(() => {});
  }
}

let shared = null;

async function acquirePostgres() {
  const provided = process.env.VERITAS_S2_007_TEST_DATABASE_URL ?? process.env.DATABASE_URL;
  if (typeof provided === 'string' && provided !== '') {
    if (!await waitForPostgres(provided, 4)) throw notRunDb(`the supplied connection string ${provided} is not reachable`);
    await applyMigrations({ connectionString: provided });
    return { connectionString: provided, disposable: false, pool: new Pool({ connectionString: provided, max: 6 }) };
  }

  try {
    await podman(['--version']);
  } catch (error) {
    throw notRunDb(`podman is not usable on this host (${String(error?.message ?? error).slice(0, 200)})`);
  }
  // A container left behind by an aborted run would make the fixed name
  // unbindable; removing it first is safe because the name is ours.
  await podman(['rm', '-f', CONTAINER]).catch(() => {});
  try {
    await podman([
      'run', '-d', '--rm', '--name', CONTAINER,
      '-e', 'POSTGRES_USER=veritas',
      '-e', 'POSTGRES_PASSWORD=veritas',
      '-e', 'POSTGRES_DB=veritas',
      // An empty host port asks podman for a free one: two runs of this file
      // (or a developer's own database) can never collide on 5432.
      '-p', '127.0.0.1::5432',
      '--pull=never',
      PINNED_POSTGRES,
    ]);
  } catch (error) {
    throw notRunDb(`the pinned postgres image could not be started (${String(error?.message ?? error).slice(0, 300)})`);
  }
  const { stdout } = await podman(['port', CONTAINER, '5432/tcp']);
  const port = /:(\d+)\s*$/.exec(String(stdout).trim());
  if (!port) throw notRunDb(`could not determine the mapped port from "${String(stdout).trim()}"`);
  const connectionString = `postgres://veritas:veritas@127.0.0.1:${port[1]}/veritas`;
  if (!await waitForPostgres(connectionString)) throw notRunDb('the container did not become ready in 30s');
  await applyMigrations({ connectionString });
  return { connectionString, disposable: true, pool: new Pool({ connectionString, max: 6 }) };
}

before(async () => {
  shared = await acquirePostgres();
});

after(async () => {
  if (shared) {
    await shared.pool.end().catch(() => {});
    if (shared.disposable) await podman(['rm', '-f', CONTAINER]).catch(() => {});
    shared = null;
  }
});

/** The whole workspace as a canonical digest, read straight out of the database. */
async function databaseDigest(pool, workspaceId) {
  const tables = [
    'agentboard_task', 'agentboard_acl', 'agentboard_lease', 'agentboard_adapter',
    'agentboard_budget_grant', 'agentboard_budget_spend', 'agentboard_run',
    'agentboard_execution_event', 'agentboard_transition', 'agentboard_audit',
    'agentboard_outbox', 'agentboard_operation', 'agentboard_reconciliation',
  ];
  const out = {};
  for (const table of tables) {
    const result = await pool.query(`SELECT * FROM ${table} WHERE workspace_id = $1 ORDER BY 1`, [workspaceId]);
    // The driver hands back Date instances and int8 as strings; the canonical
    // form is the JSON one, so the digest is taken over that.
    out[table] = canonicalDigest(JSON.parse(JSON.stringify(result.rows)));
  }
  return canonicalDigest(out);
}

async function countRows(pool, table, workspaceId) {
  const result = await pool.query(`SELECT count(*)::int AS total FROM ${table} WHERE workspace_id = $1`, [workspaceId]);
  return result.rows[0].total;
}

// ===========================================================================
// 1. TWO INDEPENDENT PROCESSES, ONE TASK
// ===========================================================================

describe('S2-007 concurrency: two INDEPENDENT processes racing for one task', () => {
  test('exactly one lease exists and the loser receives a typed error', async (t) => {
    assert.ok(existsSync(RACE_CHILD), `the race helper ${RACE_CHILD} is missing; the cross-process claim cannot be faked`);
    const workspaceId = 'ws-race-proc';
    const taskId = 'abt-race-proc';
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
    const store = new PostgresAgentBoardStore({
      connectionString: shared.connectionString,
      max: 2,
      seed: 's2-007-race-parent',
      ids: deterministicIds('proc'),
    });
    t.after(async () => { await store.close(); });

    const task = await seedReadyTask(store, {
      taskId, workspaceId, now, adapters: ['adr-race-a', 'adr-race-b'],
    });
    const expectedRevision = task.revision;

    // Both children park on the barrier before either one attempts the claim.
    const workdir = mkdtempSync(path.join(tmpdir(), 's2-007-race-'));
    t.after(() => { rmSync(workdir, { recursive: true, force: true }); });
    const barrier = path.join(workdir, 'barrier');

    const start = (label, adapterId) => {
      const env = {
        ...process.env,
        S2_007_REPO_ROOT: ROOT,
        S2_007_RACE_LABEL: label,
        S2_007_TASK_ID: taskId,
        S2_007_WORKSPACE_ID: workspaceId,
        S2_007_ADAPTER_ID: adapterId,
        S2_007_EXPECTED_REVISION: String(expectedRevision),
        S2_007_ACTOR: SCHEDULER,
        S2_007_TTL_MS: '60000',
        S2_007_IDEMPOTENCY_KEY: key('tasks.claim', { task_id: taskId, adapter_id: adapterId, process: label }),
        S2_007_ARGS_DIGEST: key('tasks.claim', { task_id: taskId, adapter_id: adapterId, process: label }),
        S2_007_BARRIER: barrier,
        S2_007_RESULT: path.join(workdir, `${label}.json`),
        DATABASE_URL: shared.connectionString,
      };
      return new Promise((resolve) => {
        execFileAsync(process.execPath, [RACE_CHILD], { env }, (error, stdout, stderr) => {
          resolve({ label, error, stdout: String(stdout), stderr: String(stderr) });
        });
      });
    };

    const children = [
      start('alpha', 'adr-race-a'),
      start('beta', 'adr-race-b'),
    ];
    // Bounded wait for both markers, then release them together.
    for (const label of ['alpha', 'beta']) {
      let ready = false;
      for (let attempt = 0; attempt < 300; attempt += 1) {
        if (existsSync(`${barrier}.ready.${label}`)) { ready = true; break; }
        await delay(100);
      }
      assert.ok(ready, `race child ${label} never reported ready`);
    }
    writeFileSync(barrier, 'go', 'utf8');

    const finished = await Promise.all(children);
    const reports = finished.map((child) => {
      assert.equal(child.error, null, `race child ${child.label} crashed: ${child.stderr.slice(0, 500)}`);
      const line = child.stdout.trim().split('\n').at(-1);
      assert.ok(line, `race child ${child.label} produced no outcome line`);
      return JSON.parse(line);
    });

    const winners = reports.filter((report) => report.ok === true);
    const losers = reports.filter((report) => report.ok === false);
    assert.equal(reports.length, 2, 'both children must report an outcome');
    assert.equal(winners.length, 1, `exactly one process may win the claim, got ${JSON.stringify(reports)}`);
    assert.equal(losers.length, 1);
    assert.equal(winners[0].lease_state, 'ACTIVE', 'the winner really holds the right');

    // The loser's refusal is a TYPED, non-retryable BoardError from the closed
    // set. A plain Error, a silent success or a fabricated failure all fail.
    assert.equal(losers[0].typed, true, `the loser's refusal must be a typed BoardError, got ${JSON.stringify(losers[0])}`);
    assert.ok(CLOSED_CODES.has(losers[0].code), `${losers[0].code} is not a member of the closed ERROR_CODES set`);
    assert.ok(RACE_LOSS_CODES.includes(losers[0].code), `unexpected race-loss code ${losers[0].code}: ${losers[0].message}`);
    assert.equal(losers[0].retryable, false, 'losing a claim race is never a blind retry');

    // The database is the authority on what happened.
    const active = await store.listLeases({ workspaceId, taskId, leaseState: 'ACTIVE' });
    const all = await store.listLeases({ workspaceId, taskId });
    assert.equal(active.length, 1, 'exactly one ACTIVE lease may exist for the task');
    assert.equal(all.length, 1, `the losing process must leave no partial lease row: ${JSON.stringify(all)}`);
    assert.equal(active[0].lease_id, winners[0].lease_id, 'the stored lease is the one the winner was told about');

    const after = await store.getTask(taskId, { workspaceId, principalId: OWNER });
    assert.equal(after.state, 'CLAIMED');
    assert.equal(after.revision, expectedRevision + 1, 'exactly one committed state change');
    assert.equal(after.attempts, 1, 'the loser must not consume an attempt');
    assert.equal(after.active_lease_id, winners[0].lease_id);
    assert.equal(after.fencing_token, winners[0].fencing_token);

    const journal = await store.listTransitions(taskId, { workspaceId, principalId: OWNER });
    const intoClaimed = journal.filter((entry) => entry.to_state === 'CLAIMED');
    assert.equal(intoClaimed.length, 1, 'exactly one transition into CLAIMED');
    const claims = (await store.listAudit({ workspaceId, taskId })).filter((row) => row.operation === 'board.task.claim');
    assert.equal(claims.length, 1, 'exactly one committed claim, and therefore one audit row');
    assert.ok(Number(winners[0].fencing_token) >= 1, 'the fence is a positive integer from the sequence');

    // The lease the winner was handed must still be readable — a claim that
    // reported success but was rolled back would be a lie.
    const lease = await store.readLease(winners[0].lease_id, { workspaceId, principalId: OWNER });
    assert.equal(lease.fencing_token, winners[0].fencing_token);
    assert.equal(lease.adapter_id, winners[0].label === 'alpha' ? 'adr-race-a' : 'adr-race-b');
  });

  test('two concurrent sessions in ONE process are serialized by the same rule', async (t) => {
    // Same invariant, same database, no child processes: two store instances
    // over two pools are two real sessions, and the row lock plus the
    // compare-and-swap must decide between them exactly as it did above.
    const workspaceId = 'ws-race-session';
    const taskId = 'abt-race-session';
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
    const makeStore = (seed, namespace) => new PostgresAgentBoardStore({
      connectionString: shared.connectionString, max: 2, seed, ids: deterministicIds(namespace),
    });
    const first = makeStore('s2-007-session-1', 'session-1');
    const second = makeStore('s2-007-session-2', 'session-2');
    t.after(async () => { await first.close(); await second.close(); });

    await seedReadyTask(first, { taskId, workspaceId, now, adapters: ['adr-race-session'] });
    const revision = (await first.getTask(taskId, { workspaceId, principalId: OWNER })).revision;

    const attempt = (store, label) => claimCall({
      taskId, workspaceId, adapterId: 'adr-race-session', expectedRevision: revision, label,
    })(store).then((result) => ({ label, ok: true, result }), (error) => ({ label, ok: false, error }));

    const outcomes = await Promise.all([attempt(first, 'one'), attempt(second, 'two')]);
    const winners = outcomes.filter((entry) => entry.ok);
    const losers = outcomes.filter((entry) => !entry.ok);
    assert.equal(winners.length, 1, `exactly one session may win, got ${JSON.stringify(outcomes.map((o) => [o.label, o.ok]))}`);
    assert.equal(losers.length, 1);
    assert.ok(isBoardError(losers[0].error), 'the losing session must receive a typed BoardError');
    assert.ok(RACE_LOSS_CODES.includes(losers[0].error.code), `unexpected race-loss code ${losers[0].error.code}`);

    const active = await first.listLeases({ workspaceId, taskId, leaseState: 'ACTIVE' });
    assert.equal(active.length, 1, 'exactly one ACTIVE lease');
    const task = await first.getTask(taskId, { workspaceId, principalId: OWNER });
    assert.equal(task.revision, revision + 1);
    assert.equal(task.attempts, 1);
  });
});

// ===========================================================================
// 2. THE IN-MEMORY TWIN MUST NOT BE A WEAKER GATE
// ===========================================================================

describe('S2-007 concurrency: the in-memory twin does not admit two live claims either', () => {
  test('two concurrent claimTask calls yield one winner, one typed refusal and one ACTIVE lease', async () => {
    const workspaceId = 'ws-race-twin';
    const taskId = 'abt-race-twin';
    const now = '2026-09-25T12:00:00.000Z';
    const store = new InMemoryAgentBoardStore({ clock: fixedClock(now), ids: deterministicIds('twin'), seed: 's2-007-race-twin' });

    await seedReadyTask(store, { taskId, workspaceId, now, adapters: ['adr-race-twin-a', 'adr-race-twin-b'] });
    const revision = (await store.getTask(taskId, { workspaceId, principalId: OWNER })).revision;

    const attempt = (label, adapterId) => claimCall({
      taskId, workspaceId, adapterId, expectedRevision: revision, label,
    })(store).then((result) => ({ label, ok: true, lease_id: result.lease_id, fencing_token: result.fencing_token }), (error) => ({ label, ok: false, error }));

    const outcomes = await Promise.all([
      attempt('one', 'adr-race-twin-a'),
      attempt('two', 'adr-race-twin-b'),
    ]);

    const winners = outcomes.filter((entry) => entry.ok);
    const losers = outcomes.filter((entry) => !entry.ok);

    // Evidence is gathered BEFORE the assertions so that a failing assertion
    // carries the whole picture: not only were two claims reported as
    // committed, but the lease the first one was handed is no longer there —
    // a committed write that the second unit of work silently dropped.
    const leasesAfter = await store.listLeases({ workspaceId, taskId });
    const stillReadable = await Promise.all(winners.map((winner) => store.readLease(winner.lease_id, { workspaceId, principalId: OWNER })
      .then(() => true, () => false)));

    assert.equal(
      winners.length,
      1,
      'the in-memory twin must not report two successful claims for one task (duplicate external effect + a silently '
      + `dropped write): outcomes=${JSON.stringify(outcomes)} leases=${JSON.stringify(leasesAfter.map((lease) => ({ id: lease.lease_id, state: lease.lease_state, fence: lease.fencing_token })))} `
      + `winnerLeasesStillReadable=${JSON.stringify(stillReadable)}`,
    );
    assert.equal(losers.length, 1);
    assert.ok(isBoardError(losers[0].error), `the losing call must receive a typed BoardError, got ${String(losers[0].error)}`);
    assert.ok(CLOSED_CODES.has(losers[0].error.code), `${losers[0].error.code} is not a member of the closed ERROR_CODES set`);
    assert.ok(RACE_LOSS_CODES.includes(losers[0].error.code), `unexpected race-loss code ${losers[0].error.code}`);

    assert.deepEqual(stillReadable, [true], 'a claim that reported success must still be readable: the twin may not acknowledge a lease it then drops');
    const active = await store.listLeases({ workspaceId, taskId, leaseState: 'ACTIVE' });
    assert.equal(active.length, 1, 'exactly one ACTIVE lease');
    const task = await store.getTask(taskId, { workspaceId, principalId: OWNER });
    assert.equal(task.revision, revision + 1, 'exactly one committed state change');
    assert.equal(task.attempts, 1);
    const lease = await store.readLease(winners[0].lease_id, { workspaceId, principalId: OWNER });
    assert.equal(lease.lease_state, 'ACTIVE');
    assert.equal(lease.fencing_token, task.fencing_token);
  });
});

// ===========================================================================
// 3. THE DATABASE CLOCK DECIDES EXPIRY, NEVER THE PROCESS CLOCK
// ===========================================================================

describe('S2-007 concurrency: expiry follows the DATABASE clock, not the process clock', () => {
  test('a store whose injected clock says 2099 expires nothing while the database says the lease is live', async (t) => {
    const workspaceId = 'ws-clock-future';
    const taskId = 'abt-clock-future';
    const store = new PostgresAgentBoardStore({
      connectionString: shared.connectionString,
      max: 2,
      seed: 's2-007-clock-future',
      ids: deterministicIds('clock-future'),
      // A process clock three decades in the future would expire EVERY lease
      // if the sweep consulted it. It must not.
      clock: () => new Date('2099-01-01T00:00:00.000Z'),
    });
    t.after(async () => { await store.close(); });

    const now = await store.dbNow();
    await seedReadyTask(store, { taskId, workspaceId, now, adapters: ['adr-clock-future'] });
    const revision = (await store.getTask(taskId, { workspaceId, principalId: OWNER })).revision;
    const claimed = await claimCall({ taskId, workspaceId, adapterId: 'adr-clock-future', expectedRevision: revision, label: 'future', ttlMs: 600_000 })(store);
    assert.equal(claimed.lease.lease_state, 'ACTIVE');

    const swept = await store.expireLeases({ actor: SCHEDULER });
    assert.deepEqual(
      swept.expired.map((entry) => entry.lease_id),
      [],
      `the sweep followed something other than the database clock (it expired ${JSON.stringify(swept.expired)})`,
    );
    assert.equal((await store.readLease(claimed.lease_id, { workspaceId, principalId: OWNER })).lease_state, 'ACTIVE');
  });

  test('a store whose injected clock says 1970 still expires a lease the database has passed', async (t) => {
    const workspaceId = 'ws-clock-past';
    const taskId = 'abt-clock-past';
    const store = new PostgresAgentBoardStore({
      connectionString: shared.connectionString,
      max: 2,
      seed: 's2-007-clock-past',
      ids: deterministicIds('clock-past'),
      // The mirror image: a process clock in the past would keep EVERY lease
      // alive forever, however far the database clock has moved.
      clock: () => new Date('1970-01-01T00:00:00.000Z'),
    });
    t.after(async () => { await store.close(); });

    const now = await store.dbNow();
    await seedReadyTask(store, { taskId, workspaceId, now, adapters: ['adr-clock-past'] });
    const revision = (await store.getTask(taskId, { workspaceId, principalId: OWNER })).revision;
    const claimed = await claimCall({ taskId, workspaceId, adapterId: 'adr-clock-past', expectedRevision: revision, label: 'past', ttlMs: 1 })(store);
    assert.ok(
      Date.parse(claimed.lease.expires_at) > Date.parse(now),
      'the lease window is computed from the database clock, not from the injected 1970 clock',
    );

    await delay(400);
    const swept = await store.expireLeases({ actor: SCHEDULER });
    assert.deepEqual(
      swept.expired.map((entry) => entry.lease_id),
      [claimed.lease_id],
      'the sweep must follow the database clock even when the injected clock is in the past',
    );
    assert.equal((await store.readLease(claimed.lease_id, { workspaceId, principalId: OWNER })).lease_state, 'EXPIRED');
  });
});

// ===========================================================================
// 4. A LATE CALLBACK MUTATES NOTHING — AFTER EXPIRY, CANCEL AND RESTART
// ===========================================================================

describe('S2-007 concurrency: a late callback after expiry, after cancel and after a restart mutates nothing', () => {
  test('after an expiry the withdrawn fence writes no journal row and no outbox row', async (t) => {
    const workspaceId = 'ws-late-expiry';
    const taskId = 'abt-late-expiry';
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
    const store = new PostgresAgentBoardStore({
      connectionString: shared.connectionString, max: 2, seed: 's2-007-late-expiry', ids: deterministicIds('late-expiry'),
    });
    t.after(async () => { await store.close(); });

    await seedReadyTask(store, { taskId, workspaceId, now, adapters: ['adr-late-expiry'] });
    const revision = (await store.getTask(taskId, { workspaceId, principalId: OWNER })).revision;
    const claimed = await claimCall({ taskId, workspaceId, adapterId: 'adr-late-expiry', expectedRevision: revision, label: 'late', ttlMs: 1 })(store);

    await delay(400);
    const swept = await store.expireLeases({ actor: SCHEDULER });
    assert.equal(swept.expired.length, 1, 'the lease expired before the late callback arrives');

    const before = await databaseDigest(shared.pool, workspaceId);
    const journalBefore = await countRows(shared.pool, 'agentboard_transition', workspaceId);
    const outboxBefore = await countRows(shared.pool, 'agentboard_outbox', workspaceId);
    const auditBefore = await countRows(shared.pool, 'agentboard_audit', workspaceId);

    const renewKey = key('tasks.lease.renew', { lease_id: claimed.lease_id, late: true });
    await assert.rejects(
      () => store.renewLease({
        leaseId: claimed.lease_id, fencingToken: claimed.fencing_token, ttlMs: 60_000, actor: SCHEDULER, idempotencyKey: renewKey, argsDigest: renewKey,
      }),
      (error) => isBoardError(error) && error.code === 'STALE_FENCE',
      'the expired fence must not renew',
    );

    const task = await store.getTask(taskId, { workspaceId, principalId: OWNER });
    const releaseKey = key('tasks.lease.release', { lease_id: claimed.lease_id, late: true });
    await assert.rejects(
      () => store.releaseLease({
        leaseId: claimed.lease_id,
        fencingToken: claimed.fencing_token,
        reason: 'the adapter answers long after the fact',
        expectedRevision: task.revision,
        actor: SCHEDULER,
        actorKind: 'adapter',
        idempotencyKey: releaseKey,
        argsDigest: releaseKey,
      }),
      (error) => isBoardError(error) && error.code === 'STALE_FENCE',
      'the expired fence must not release the lease either',
    );

    assert.equal(await databaseDigest(shared.pool, workspaceId), before, 'a late callback after expiry must change nothing');
    assert.equal(await countRows(shared.pool, 'agentboard_transition', workspaceId), journalBefore, 'no journal row');
    assert.equal(await countRows(shared.pool, 'agentboard_outbox', workspaceId), outboxBefore, 'no outbox row');
    assert.equal(await countRows(shared.pool, 'agentboard_audit', workspaceId), auditBefore, 'no audit row');
  });

  test('after a cancel the withdrawn fence writes no journal row and no outbox row', async (t) => {
    const workspaceId = 'ws-late-cancel';
    const taskId = 'abt-late-cancel';
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
    const store = new PostgresAgentBoardStore({
      connectionString: shared.connectionString, max: 2, seed: 's2-007-late-cancel', ids: deterministicIds('late-cancel'),
    });
    t.after(async () => { await store.close(); });

    await seedReadyTask(store, { taskId, workspaceId, now, adapters: ['adr-late-cancel'] });
    const revision = (await store.getTask(taskId, { workspaceId, principalId: OWNER })).revision;
    const claimed = await claimCall({ taskId, workspaceId, adapterId: 'adr-late-cancel', expectedRevision: revision, label: 'cancel' })(store);

    // Issue §4: the right is withdrawn FIRST, and only then is the task
    // cancelled. A cancel that leaves an ACTIVE lease behind is not a cancel.
    const revokeKey = key('tasks.lease.revoke', { lease_id: claimed.lease_id });
    const revoked = await store.revokeLease({
      leaseId: claimed.lease_id,
      fencingToken: claimed.fencing_token,
      reason: 'the operator cancels the work',
      actor: OWNER,
      actorKind: 'human_owner',
      idempotencyKey: revokeKey,
      argsDigest: revokeKey,
    });
    assert.equal(revoked.lease.lease_state, 'REVOKED');

    const cancelKey = key('tasks.transition', { task_id: taskId, to: 'CANCELLED' });
    const cancelled = await store.transitionTask({
      taskId,
      toState: 'CANCELLED',
      expectedRevision: revoked.revision,
      actor: OWNER,
      actorKind: 'human_owner',
      reason: 'the operator cancels the work',
      idempotencyKey: cancelKey,
      argsDigest: cancelKey,
    });
    assert.equal(cancelled.task.state, 'CANCELLED');
    assert.equal(cancelled.task.active_lease_id, null);

    const before = await databaseDigest(shared.pool, workspaceId);
    const journalBefore = await countRows(shared.pool, 'agentboard_transition', workspaceId);
    const outboxBefore = await countRows(shared.pool, 'agentboard_outbox', workspaceId);

    const lateKey = key('tasks.transition', { task_id: taskId, to: 'RUNNING', late: true });
    await assert.rejects(
      () => store.transitionTask({
        taskId,
        toState: 'RUNNING',
        expectedRevision: cancelled.revision,
        actor: SCHEDULER,
        actorKind: 'adapter',
        reason: 'the cancelled adapter reports that it started anyway',
        lease: claimed.lease_id,
        fencingToken: claimed.fencing_token,
        idempotencyKey: lateKey,
        argsDigest: lateKey,
      }),
      (error) => isBoardError(error),
      'a callback arriving after a cancel must be refused',
    );

    assert.equal(await databaseDigest(shared.pool, workspaceId), before, 'a late callback after a cancel must change nothing');
    assert.equal(await countRows(shared.pool, 'agentboard_transition', workspaceId), journalBefore, 'no journal row');
    assert.equal(await countRows(shared.pool, 'agentboard_outbox', workspaceId), outboxBefore, 'no outbox row');
    assert.equal((await store.getTask(taskId, { workspaceId, principalId: OWNER })).state, 'CANCELLED', 'CANCELLED is terminal');
  });

  test('after a RESTART a brand new store instance over the same contents still refuses the late callback', async (t) => {
    const workspaceId = 'ws-late-restart';
    const taskId = 'abt-late-restart';
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
    const before = new PostgresAgentBoardStore({
      connectionString: shared.connectionString, max: 2, seed: 's2-007-restart-before', ids: deterministicIds('restart-before'),
    });
    // close() ends the pool, so it must be called exactly once: the restart
    // below needs the first store's connections gone, and the test-level
    // cleanup needs a close too.
    let beforeClosed = false;
    const closeBefore = async () => {
      if (beforeClosed) return;
      beforeClosed = true;
      await before.close();
    };
    t.after(closeBefore);

    await seedReadyTask(before, { taskId, workspaceId, now, adapters: ['adr-late-restart'] });
    const revision = (await before.getTask(taskId, { workspaceId, principalId: OWNER })).revision;
    const claimed = await claimCall({ taskId, workspaceId, adapterId: 'adr-late-restart', expectedRevision: revision, label: 'restart', ttlMs: 1 })(before);

    await delay(400);
    const swept = await before.expireLeases({ actor: SCHEDULER });
    assert.equal(swept.expired.length, 1);

    // The restart: a NEW store object, a NEW pool, the SAME committed contents.
    // Nothing is carried over in memory — that is the point of the test.
    await closeBefore();
    const after = new PostgresAgentBoardStore({
      connectionString: shared.connectionString, max: 2, seed: 's2-007-restart-after', ids: deterministicIds('restart-after'),
    });
    t.after(async () => { await after.close(); });

    const digestBefore = await databaseDigest(shared.pool, workspaceId);
    const journalBefore = await countRows(shared.pool, 'agentboard_transition', workspaceId);
    const outboxBefore = await countRows(shared.pool, 'agentboard_outbox', workspaceId);
    const auditBefore = await countRows(shared.pool, 'agentboard_audit', workspaceId);

    // The restarted process sees the lease as EXPIRED and the fence as dead.
    const lease = await after.readLease(claimed.lease_id, { workspaceId, principalId: OWNER });
    assert.equal(lease.lease_state, 'EXPIRED', 'the restart reads the committed lease, it does not re-derive it');
    const task = await after.getTask(taskId, { workspaceId, principalId: OWNER });
    assert.equal(task.fencing_token, null);

    const renewKey = key('tasks.lease.renew', { lease_id: claimed.lease_id, restart: true });
    await assert.rejects(
      () => after.renewLease({
        leaseId: claimed.lease_id, fencingToken: claimed.fencing_token, ttlMs: 60_000, actor: SCHEDULER, idempotencyKey: renewKey, argsDigest: renewKey,
      }),
      (error) => isBoardError(error) && error.code === 'STALE_FENCE',
      'a restarted process must not honour a fence that died before the restart',
    );

    assert.equal(await databaseDigest(shared.pool, workspaceId), digestBefore, 'a late callback after a restart must change nothing');
    assert.equal(await countRows(shared.pool, 'agentboard_transition', workspaceId), journalBefore, 'no journal row');
    assert.equal(await countRows(shared.pool, 'agentboard_outbox', workspaceId), outboxBefore, 'no outbox row');
    assert.equal(await countRows(shared.pool, 'agentboard_audit', workspaceId), auditBefore, 'no audit row');
  });
});
