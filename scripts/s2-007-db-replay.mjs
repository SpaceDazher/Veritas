// S2-007 DB replay COORDINATOR (issue #7; frozen spec §3.2 store tier, §4 hard
// gates; the two-process tier of the PostgreSQL gate).
//
// WHAT THIS PROCESS IS, AND WHAT IT IS NOT
// It is the ONLY process that touches the container, the migrations and the
// comparison. It NEVER runs board logic: no `commands.execute`, no store write,
// no lease. Every board decision in this replay was taken by a child process
// with its own `pg.Pool` and its own `PostgresAgentBoardStore`, because the
// property under test is what two independent TRANSACTIONS do to one row, and
// two awaited calls in one heap are cooperative, never concurrent.
//
// WHY A PORTABLE CONTAINER HELPER AND NOT wsl.exe
// The S2-005 smoke and the S2-006 replay shell out to `wsl.exe -d Ubuntu-24.04
// -- podman …` and therefore only work on the Windows host. This replay has to
// run on the Linux host too, so it builds its own argv: `podman …` directly on
// posix, `wsl.exe -d <distro> -- podman …` on win32. Nothing else about the
// provisioning is different from the S2-005 smoke, and the S2-005/S2-006 scripts
// are NOT edited: their evidence digests are frozen.
//
// THE EPHEMERAL DATABASE
//   * tmpfs data directory and a read-only root filesystem: nothing survives the
//     container, and nothing is written to the host's disk;
//   * published on 127.0.0.1 with a random free port — loopback only;
//   * RANDOM runtime credentials (`randomBytes`), never written to evidence;
//   * ALL ordered migrations applied with `applyMigrations` (0001…0008), each
//     digest-bound, and the digests are reported;
//   * removal is guaranteed in a `finally`, and the run is only green when
//     `podman container exists <name>` afterwards FAILS, i.e. the container is
//     provably gone.
//
// ONE DATABASE, TWO SCHEMAS, TWO PROCESSES, AND A SHARED CONTENDED SCHEMA
// The contention properties need shared rows: both executors claim the SAME
// task in the `public` schema, at the same instant, released from a file
// barrier and a database rendezvous. The A-versus-B digest comparison needs
// rows that are IDENTICAL except for the process identity, and two processes
// cannot write identical rows into one schema without colliding on primary
// keys. So the deterministic scenario runs in `run_a` and `run_b` — two schemas
// of the SAME database instance, same server, same credentials, same
// migrations, each with its own pool and its own search_path — while the
// contested phase runs in the shared `public` schema. One database, two
// processes, genuinely shared rows where sharing is the point.
//
// A === B IS NOT A PASS
// Two identically wrong runs are still wrong. `runIssues` checks each run
// against an EXPECTED-VALUE TABLE declared from the transition table, the
// contract and the scenario's own step list, and `A === B` is an additional
// requirement, never a substitute. The run injects the SAME deterministic
// wrongness into both runs as a control and records the findings the table
// produces for it: a table that cannot fail that control is not a check.
//
// WHAT THE EVIDENCE MUST CARRY
// The commit, the TREE, the pinned image digest, the OBSERVED server version,
// the raw run ids and both run timestamps: the record is only fresh while it
// still describes this tree, and `freshnessVerdict` / `classifyCurrentDbReplay`
// (exported for the aggregator) refuse a record whose tree, image, version,
// timestamp order or age does not match. A previous green file can never turn
// a current NOT_RUN_DB or FAIL into a PASS, and a NOT_RUN_DB exits non-zero.
//
//   node scripts/s2-007-db-replay.mjs                    # podman flow
//   DATABASE_URL=… node scripts/s2-007-db-replay.mjs     # external database
//   node scripts/s2-007-db-replay.mjs --no-write         # do not touch evidence/
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

import pg from 'pg';
import { applyMigrations, discoverMigrations } from './apply-migrations.mjs';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { MAX_CONCURRENT_TASKS, TRANSITIONS } from '../src/lib/agentboard/constants.mjs';

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EXECUTOR = path.join(ROOT, 'scripts/s2-007-db-replay-executor.mjs');
const EVIDENCE_DIR = path.join(ROOT, 'evidence');
const POSTGRES_IMAGE = 'docker.io/library/postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73';
const CONTAINER = 'veritas-s2-007-db-replay';
const DISTRO = process.env.S2_007_WSL_DISTRO ?? 'Ubuntu-24.04';
// The evidence is only fresh while it still describes this tree. A record older
// than the freshness window is refused by the aggregator, not silently reused.
const FRESHNESS_WINDOW_MS = Number(process.env.S2_007_FRESHNESS_WINDOW_MS ?? 24 * 60 * 60 * 1000);

const WS = Object.freeze({ race: 'ws-s2007-db-race', scenario: 'ws-s2007-db-scenario', crash: 'ws-s2007-db-crash' });
const T = Object.freeze({
  contested: 'abt-s2007-db-contested',
  perRun: { a: 'abt-s2007-db-a', b: 'abt-s2007-db-b' },
  idem: 'abt-s2007-db-idem',
  s1: 'abt-s2007-db-s1', s2: 'abt-s2007-db-s2', s3: 'abt-s2007-db-s3', s4: 'abt-s2007-db-s4',
});

// ---------------------------------------------------------------------------
// The expected-value table. Declared from the frozen transition table, the
// contract and the enumerated step list of the scenario — NOT from the
// implementation's current behaviour, and NOT from the previous run. Every
// entry is checked against BOTH runs.
// ---------------------------------------------------------------------------
const EXPECTED_FINAL_STATES = Object.freeze({
  // create(1) -> READY(2) -> CLAIMED(3) -> RUNNING(4) -> IN_REVIEW(5) -> DONE(6);
  // the DONE edge releases the lease, so the task ends with no active right.
  [T.s1]: { state: 'DONE', revision: 6, active_lease_id: null, fencing_token: null },
  // create(1) -> READY(2) -> CLAIMED(3) -> reassign(4) -> revoke(5); a renew
  // writes no transition (the journal is the audit), so it does not bump.
  [T.s2]: { state: 'CLAIMED', revision: 5, active_lease_id: null, fencing_token: null },
  // create(1) -> READY(2) -> CLAIMED(3) -> the sweep's expiry edge(4).
  [T.s3]: { state: 'CLAIMED', revision: 4, active_lease_id: null, fencing_token: null },
  // create(1) -> READY(2) -> CLAIMED(3) -> CANCELLED(4); the cancel withdraws
  // the lease in the same transaction as the state change.
  [T.s4]: { state: 'CANCELLED', revision: 4, active_lease_id: null, fencing_token: null },
});
const EXPECTED_SCENARIO_SQL = Object.freeze({
  // Four tasks, one lease each for s1/s3/s4 and TWO for s2 (the reassignment
  // mints a new lease and revokes the old one in the same transaction), none
  // of them active at the end.
  tasks: 4, leases: 5, active_leases: 0,
  // The transition journal, counted from the step list: s1 walks
  // READY/CLAIMED/RUNNING/IN_REVIEW/DONE (5), s2 READY/CLAIMED/rebind/revoke
  // (4), s3 READY/CLAIMED/expiry-rebind (3), s4 READY/CLAIMED/CANCELLED (3).
  transitions: 15,
  // One run (s1), one outbox row, acknowledged exactly once, one settled grant.
  runs: 1, outbox: 1, outbox_acked: 1, spend_rows: 1,
});
// The refusal codes the contract admits for each negative step. A weaker
// refusal cannot satisfy the table, and an UNDECLARED acceptance is a finding.
const EXPECTED_CODES = Object.freeze({
  staleFence: ['STALE_FENCE', 'TRANSITION_NOT_ALLOWED', 'LEASE_REQUIRED', 'ACL_DENIED'],
  boundedClaim: ['TRANSITION_NOT_ALLOWED', 'BLOCKED_POLICY'],
  claimRace: ['REVISION_CONFLICT', 'TRANSITION_NOT_ALLOWED', 'STALE_FENCE', 'LEASE_ALREADY_ACTIVE'],
  sharedKeyRace: ['IDEMPOTENCY_CONFLICT', 'REVISION_CONFLICT'],
  selfApproval: ['BLOCKED_POLICY', 'CAPABILITY_MISMATCH', 'ACL_DENIED', 'TRANSITION_NOT_ALLOWED', 'AUTH_REQUIRED'],
  lateResult: ['RECONCILIATION_REQUIRED', 'STALE_FENCE', 'TRANSITION_NOT_ALLOWED', 'UNKNOWN_OUTCOME', 'MALFORMED_RESULT'],
  producerReconciliation: ['BLOCKED_POLICY', 'CAPABILITY_MISMATCH', 'AUTH_REQUIRED', 'ACL_DENIED'],
});
// The guard name of every edge the scenario walks, read from the FROZEN
// transition table rather than re-declared: the report must never become a
// second editable copy of which guard owns an edge.
const EXPECTED_GUARDS = Object.freeze({
  [T.s1]: [['BACKLOG', 'READY', 'ACCEPT'], ['IN_REVIEW', 'DONE', 'ACCEPT']],
  [T.s2]: [['BACKLOG', 'READY', 'ACCEPT']],
  [T.s3]: [['BACKLOG', 'READY', 'ACCEPT']],
  [T.s4]: [['BACKLOG', 'READY', 'ACCEPT']],
  // The producer's own approval attempt: the same edge, the same guard, and a
  // REFUSAL. It is an observation in its own right, not a silent overwrite of
  // the human approval that answers it.
  [`self-approval-attempt:${T.s1}`]: [['IN_REVIEW', 'DONE', 'REFUSE']],
});

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) args[argv[i].slice(2)] = 'true';
      else { args[argv[i].slice(2)] = next; i += 1; }
    } else args._.push(argv[i]);
  }
  return args;
}

// ---------------------------------------------------------------------------
// The portable container helper
// ---------------------------------------------------------------------------
function containerArgv(argv) {
  if (process.platform === 'win32') return { command: 'wsl.exe', args: ['-d', DISTRO, '--', ...argv] };
  return { command: 'podman', args: argv };
}

function containerRun(argv, { timeout = 60000, allowFailure = false } = {}) {
  const { command, args } = containerArgv(argv);
  const result = spawnSync(command, args, { encoding: 'utf8', shell: false, timeout, maxBuffer: 4 * 1024 * 1024 });
  if (result.error) {
    if (allowFailure) return { ok: false, status: null, stdout: '', stderr: String(result.error.message) };
    throw new Error(`CONTAINER_COMMAND_UNAVAILABLE:${command}:${String(result.error.message).slice(0, 200)}`);
  }
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: String(result.stdout ?? '').trim(),
    stderr: String(result.stderr ?? '').trim(),
  };
}

function containerAvailable() {
  return containerRun(['--version'], { timeout: 20000, allowFailure: true }).ok;
}

function containerExists(name) {
  const result = containerRun(['container', 'exists', name], { timeout: 20000, allowFailure: true });
  // `podman container exists` exits 0 when the container is there and 1 when it
  // is not; a non-zero exit is the PROOF of removal, an error is not.
  if (result.status === null) return { known: false, exists: null };
  return { known: true, exists: result.status === 0 };
}

function removeContainer() {
  return containerRun(['rm', '--force', '--time', '0', CONTAINER], { timeout: 30000, allowFailure: true });
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitForPostgres(connectionString, attempts = 300) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 2000 });
    try {
      await pool.query('SELECT 1');
      await pool.end();
      return true;
    } catch {
      await pool.end().catch(() => {});
      await new Promise((resolve) => { setTimeout(resolve, 250); });
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Child process control. `spawn` (not spawnSync) for the contended phase: two
// processes that are started one after the other and each wait for the other
// are not competing for anything.
// ---------------------------------------------------------------------------
function spawnExecutor(extraArgs, { env = {}, onExit = null } = {}) {
  const child = spawn(process.execPath, [EXECUTOR, ...extraArgs], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on('data', (chunk) => stdout.push(String(chunk)));
  child.stderr.on('data', (chunk) => stderr.push(String(chunk)));
  const done = new Promise((resolve) => {
    child.on('close', (code, signal) => {
      if (onExit !== null) onExit(code, signal);
      resolve({ code, signal, stdout: stdout.join(''), stderr: stderr.join('') });
    });
  });
  return { child, done };
}

/** The file barrier: release both executors only once both are parked on it. */
async function releaseBarrier(dir, label, expected, { timeoutMs = 120000 } = {}) {
  const go = path.join(dir, `go.${label}`);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const ready = expected.filter((id) => fs.existsSync(path.join(dir, `ready.${label}.${id}`)));
    if (ready.length === expected.length) {
      fs.writeFileSync(go, `${process.pid}\n`, 'utf8');
      return ready;
    }
    if (Date.now() > deadline) {
      throw new Error(`BARRIER_RELEASE_TIMEOUT:${label}:${ready.length}/${expected.length}`);
    }
    await new Promise((resolve) => { setTimeout(resolve, 25); });
  }
}

function gitFacts() {
  const read = (args) => {
    try {
      return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', timeout: 20000 }).trim();
    } catch {
      return null;
    }
  };
  const head = read(['rev-parse', 'HEAD']);
  return {
    commit_sha: head,
    // The TREE, not the commit: a record is stale when the files it describes
    // have changed, and an amended commit is a different commit over the same
    // tree. Both are recorded so an aggregator can check either.
    tree_sha: head === null ? null : read(['rev-parse', 'HEAD^{tree}']),
    dirty: read(['status', '--porcelain', '--untracked-files=no']) !== '',
  };
}

// ---------------------------------------------------------------------------
// The expected-value checks
// ---------------------------------------------------------------------------
/**
 * The expected-value check of ONE run, as a pure function of the run record.
 * It is exported so the property "two identically wrong runs are not a pass"
 * can be demonstrated without a database: feed it a record that is wrong in
 * the same way twice and it still returns findings.
 */
export function runIssues(run, letter) {
  const issues = [];
  const tag = (text) => `run-${letter}:${text}`;
  if (run.status === 'ERROR') issues.push(tag(`executor-error:${run.error ?? ''}`));
  const scenario = run.phase_result;
  if (scenario === null || typeof scenario !== 'object' || typeof scenario.digest !== 'string') {
    issues.push(tag('no-scenario-result'));
    return issues;
  }
  // 1. every executor-declared BOOLEAN check must hold, and every guard
  //    observation must name the guard the frozen table assigns to that edge.
  for (const [name, value] of Object.entries(run.checks ?? {})) {
    if (name.startsWith('guard:')) {
      // `guard:<subject>:<FROM>-><TO>`; the DECISION lives in the value and the
      // subject may itself carry a label (`self-approval-attempt:<task>`).
      const rest = name.slice('guard:'.length);
      const cut = rest.lastIndexOf(':');
      const subject = cut === -1 ? '' : rest.slice(0, cut);
      const [from, to] = rest.slice(cut + 1).split('->');
      const decision = value !== null && typeof value === 'object' ? value.decision : undefined;
      const expected = TRANSITIONS[from]?.[to] ?? null;
      const allowed = (EXPECTED_GUARDS[subject] ?? []).some(([f, t, d]) => f === from && t === to && d === decision);
      if (!allowed) {
        issues.push(tag(`guard-${name}-undeclared-edge`));
        continue;
      }
      if (value === null || typeof value !== 'object') {
        issues.push(tag(`guard-observation-missing-${name}`));
        continue;
      }
      if (value.guard !== expected) issues.push(tag(`guard-${name}-${value.guard}-expected-${expected}`));
      if (decision === 'ACCEPT' && value.code !== null) issues.push(tag(`guard-${name}-accepted-with-code`));
      if (decision === 'REFUSE' && (typeof value.code !== 'string' || value.code === '')) {
        issues.push(tag(`guard-${name}-untyped-refusal`));
      }
      continue;
    }
    if (value !== true) issues.push(tag(`check-${name}`));
  }
  // 2. the canonical final state of every task, declared from the transition table
  for (const [taskId, expected] of Object.entries(EXPECTED_FINAL_STATES)) {
    const observed = scenario.finalStates?.[taskId];
    if (!isDeepStrictEqual(observed, expected)) {
      issues.push(tag(`final-state-${taskId}:${JSON.stringify(observed)}`));
    }
  }
  // 3. the exact row counts of the scenario workspace
  for (const [name, expected] of Object.entries(EXPECTED_SCENARIO_SQL)) {
    if (scenario.sql?.[name] !== expected) issues.push(tag(`sql-${name}-${scenario.sql?.[name]}-expected-${expected}`));
  }
  // 4. the expected command outcomes, per step
  const byStep = new Map((run.calls ?? []).map((call) => [call.step, call]));
  const expect = (step, outcome, codes = null) => {
    const call = byStep.get(step);
    if (call === undefined) {
      issues.push(tag(`missing-step-${step}`));
      return;
    }
    if (call.outcome !== outcome) {
      issues.push(tag(`step-${step}-${call.outcome}-expected-${outcome}`));
      return;
    }
    if (outcome === 'REFUSE') {
      if (call.typed !== true) issues.push(tag(`step-${step}-untyped`));
      if (codes !== null && !codes.includes(call.code)) issues.push(tag(`step-${step}-code-${call.code}`));
    }
  };
  for (const step of ['scenario.register-alpha', 'scenario.register-alt', `scenario.create.${T.s1}`, `scenario.ready.${T.s1}`, `scenario.grant.${T.s1}`]) {
    expect(step, 'ACCEPT');
  }
  expect('scenario.start', 'ACCEPT');
  expect('scenario.dispatch', 'ACCEPT');
  expect('scenario.dispatch-replay', 'ACCEPT');
  expect('scenario.event', 'ACCEPT');
  expect('scenario.collect', 'ACCEPT');
  expect('scenario.approve-by-producer', 'REFUSE', EXPECTED_CODES.selfApproval);
  expect('scenario.approve-by-human', 'ACCEPT');
  expect('scenario.settle', 'ACCEPT');
  for (const [taskId, prefix] of [[T.s2, 's2'], [T.s3, 's3'], [T.s4, 's4']]) {
    expect(`scenario.create.${taskId}`, 'ACCEPT');
    expect(`scenario.ready.${taskId}`, 'ACCEPT');
    expect(`scenario.grant.${taskId}`, 'ACCEPT');
    expect(`scenario.claim-${prefix}`, 'ACCEPT');
    expect(`scenario.stale-renew-${prefix}`, 'REFUSE', EXPECTED_CODES.staleFence);
    expect(`scenario.stale-release-${prefix}`, 'REFUSE', EXPECTED_CODES.staleFence);
  }
  expect('scenario.reassign-s2', 'ACCEPT');
  expect('scenario.live-renew-s2', 'ACCEPT');
  expect('scenario.revoke-s2', 'ACCEPT');
  expect('scenario.cancel-s4', 'ACCEPT');
  // 5. exactly one external effect was issued, and it was acknowledged
  if (run.effects_issued !== 1) issues.push(tag(`effects-issued-${run.effects_issued}`));
  if (scenario.readBack?.outbox_rows !== 1) issues.push(tag(`outbox-read-${scenario.readBack?.outbox_rows}`));
  if (scenario.readBack?.task_rows !== 4) issues.push(tag(`task-read-${scenario.readBack?.task_rows}`));
  return issues;
}

function verifyRun(run, { letter, issues }) {
  for (const issue of runIssues(run, letter)) issues.push(issue);
}

function verifyCrash(crash, { letter, issues }) {
  const tag = (text) => `crash-${letter}:${text}`;
  if (crash === null || crash === undefined) {
    issues.push(tag('no-crash-report'));
    return;
  }
  for (const [name, value] of Object.entries(crash.checks ?? {})) {
    // Two entries are not booleans: the effect COUNTER and the recorded code.
    if (name === 'effectsIssuedAfterBlindRetry') {
      if (value !== 1) issues.push(tag(`effects-issued-after-blind-retry-${value}`));
      continue;
    }
    if (name === 'lateResultCode') {
      if (!EXPECTED_CODES.lateResult.includes(value)) issues.push(tag(`late-result-code-${value}`));
      continue;
    }
    if (value !== true) issues.push(tag(`check-${name}`));
  }
  if (crash.sql?.effects_issued !== 1) issues.push(tag(`effects-issued-${crash.sql?.effects_issued}`));
  if (crash.sql?.reconciliations !== 1) issues.push(tag(`reconciliations-${crash.sql?.reconciliations}`));
  if (!EXPECTED_CODES.lateResult.includes(crash.codes?.lateResult)) {
    issues.push(tag(`late-result-code-${crash.codes?.lateResult}`));
  }
  if (!EXPECTED_CODES.producerReconciliation.includes(crash.codes?.reconcileByProducer)) {
    issues.push(tag(`producer-reconciliation-code-${crash.codes?.reconcileByProducer}`));
  }
  if (crash.observed?.outbox_after?.dispatch_state !== 'RECONCILIATION_REQUIRED') {
    issues.push(tag(`outbox-state-${crash.observed?.outbox_after?.dispatch_state}`));
  }
  // The run keeps its unknown outcome: an authorized decision is recorded and
  // the TASK is cancelled, but nothing ever "resolves" an effect nobody
  // observed. The store must not invent a resolution.
  if (crash.observed?.run_after?.run_state !== 'RECONCILIATION_REQUIRED') {
    issues.push(tag(`run-state-${crash.observed?.run_after?.run_state}`));
  }
  if (crash.observed?.final_task?.state !== 'CANCELLED') {
    issues.push(tag(`task-state-${crash.observed?.final_task?.state}`));
  }
  if (crash.handoff?.crash_pid === crash.handoff?.recovery_pid) issues.push(tag('recovery-pid-identical'));
}

/** The two-process contention, verified in SQL rather than in a return value. */
async function verifyContended(pool, { issues, report, sharedKey }) {
  const tag = (text) => `contended:${text}`;
  const leaseRows = (await pool.query(
    `SELECT lease_id, task_id, adapter_id, principal_id, lease_state, fencing_token
     FROM agentboard_lease WHERE task_id = $1 ORDER BY lease_id`, [T.contested],
  )).rows;
  const active = leaseRows.filter((row) => row.lease_state === 'ACTIVE');
  if (active.length !== 1) issues.push(tag(`contested-active-leases-${active.length}`));
  if (leaseRows.length !== 1) issues.push(tag(`contested-lease-rows-${leaseRows.length}`));

  const task = (await pool.query(
    `SELECT state, revision, attempts, active_lease_id, fencing_token FROM agentboard_task WHERE task_id = $1`,
    [T.contested],
  )).rows[0];
  if (task?.state !== 'CLAIMED') issues.push(tag(`contested-state-${task?.state}`));
  if (Number(task?.attempts) !== 1) issues.push(tag(`contested-attempts-${task?.attempts}`));

  const claimed = (await pool.query(
    `SELECT count(*)::int AS total FROM agentboard_transition WHERE task_id = $1 AND to_state = 'CLAIMED'`,
    [T.contested],
  )).rows[0].total;
  if (Number(claimed) !== 1) issues.push(tag(`contested-claimed-transitions-${claimed}`));

  // MAX_CONCURRENT_TASKS === 1 is a WORKSPACE bound, not a per-task one: with
  // one active lease the other executor's claim on a DIFFERENT task is refused.
  const workspaceActive = (await pool.query(
    `SELECT count(*)::int AS total FROM agentboard_lease WHERE workspace_id = $1 AND lease_state = 'ACTIVE'`,
    [WS.race],
  )).rows[0].total;
  if (Number(workspaceActive) !== 1) issues.push(tag(`workspace-active-leases-${workspaceActive}`));
  if (MAX_CONCURRENT_TASKS !== 1) issues.push(tag(`max-concurrent-tasks-${MAX_CONCURRENT_TASKS}`));
  for (const taskId of [T.perRun.a, T.perRun.b]) {
    const row = (await pool.query(
      `SELECT state, attempts, active_lease_id FROM agentboard_task WHERE task_id = $1`, [taskId],
    )).rows[0];
    if (row?.state !== 'READY') issues.push(tag(`${taskId}-state-${row?.state}`));
    if (Number(row?.attempts) !== 0) issues.push(tag(`${taskId}-attempts-${row?.attempts}`));
    if (row?.active_lease_id !== null) issues.push(tag(`${taskId}-lease-${row?.active_lease_id}`));
  }

  // The same idempotency key from two processes yields ONE record: one task
  // row, one ledger row and one birth audit row, whatever the two processes
  // returned. The count in SQL is the verdict, not a return value.
  const idemTask = (await pool.query(
    `SELECT count(*)::int AS total, min(revision) AS revision FROM agentboard_task WHERE task_id = $1`, [T.idem],
  )).rows[0];
  if (Number(idemTask.total) !== 1) issues.push(tag(`idem-task-rows-${idemTask.total}`));
  const idemOperations = (await pool.query(
    `SELECT count(*)::int AS total FROM agentboard_operation WHERE idempotency_key = $1`, [sharedKey],
  )).rows[0].total;
  if (Number(idemOperations) !== 1) issues.push(tag(`idem-operation-rows-${idemOperations}`));
  const idemAudit = (await pool.query(
    `SELECT count(*)::int AS total FROM agentboard_audit WHERE idempotency_key = $1`, [sharedKey],
  )).rows[0].total;
  if (Number(idemAudit) !== 1) issues.push(tag(`idem-audit-rows-${idemAudit}`));
  // A conflict must not leave a second ACL row or a second transition either.
  const idemTransitions = (await pool.query(
    `SELECT count(*)::int AS total FROM agentboard_transition WHERE task_id = $1`, [T.idem],
  )).rows[0].total;
  if (Number(idemTransitions) !== 0) issues.push(tag(`idem-transition-rows-${idemTransitions}`));

  report.contendedSql = {
    contested_lease_rows: leaseRows.length,
    contested_active_leases: active.length,
    contested_claimed_transitions: Number(claimed),
    contested_attempts: Number(task?.attempts),
    workspace_active_leases: Number(workspaceActive),
    max_concurrent_tasks: MAX_CONCURRENT_TASKS,
    bounded_tasks_attempts: {
      [T.perRun.a]: Number((await pool.query('SELECT attempts FROM agentboard_task WHERE task_id = $1', [T.perRun.a])).rows[0].attempts),
      [T.perRun.b]: Number((await pool.query('SELECT attempts FROM agentboard_task WHERE task_id = $1', [T.perRun.b])).rows[0].attempts),
    },
    shared_key_task_rows: Number(idemTask.total),
    shared_key_operation_rows: Number(idemOperations),
    shared_key_audit_rows: Number(idemAudit),
    shared_key_transition_rows: Number(idemTransitions),
  };
}

/** The hard-gate counters. Any non-zero value is a failure, whatever else is green. */
function hardGateCounters({ runs, crashRuns, report }) {
  const counters = {
    crossWorkspaceLeaks: 0,
    authorityExpansions: 0,
    duplicateActiveLeases: 0,
    duplicateExternalEffects: 0,
    staleFenceMutations: 0,
    missingJournalOrOutbox: 0,
    falseApprovals: 0,
  };
  for (const [letter, run] of Object.entries(runs)) {
    const checks = run.checks ?? {};
    if (checks.staleFenceAfterReassignChangesNothing !== true) counters.staleFenceMutations += 1;
    if (checks.staleFenceAfterExpiryChangesNothing !== true) counters.staleFenceMutations += 1;
    if (checks.staleFenceAfterCancelChangesNothing !== true) counters.staleFenceMutations += 1;
    if (run.effects_issued !== 1) counters.duplicateExternalEffects += 1;
    if (checks.producerCannotApproveItsOwnRun !== true) counters.falseApprovals += 1;
    if (run.phase_result?.readBack?.outbox_rows !== 1) counters.missingJournalOrOutbox += 1;
    // A refusal that is not typed is an untyped refusal escaping the boundary.
    for (const call of run.calls ?? []) {
      if (call.outcome === 'REFUSE' && call.typed !== true) counters.authorityExpansions += 1;
    }
    void letter;
  }
  for (const [letter, crash] of Object.entries(crashRuns)) {
    if (crash?.sql?.effects_issued !== 1) counters.duplicateExternalEffects += 1;
    if (crash?.checks?.effectsIssuedAfterBlindRetry !== 1) counters.duplicateExternalEffects += 1;
    if (crash?.checks?.lateResultRefused !== true) counters.falseApprovals += 1;
    if (crash?.checks?.producerCannotCloseItsOwnOutcome !== true) counters.falseApprovals += 1;
    if (crash?.checks?.unknownOutcomeIsJournalled !== true) counters.missingJournalOrOutbox += 1;
    void letter;
  }
  if (report.contendedSql !== undefined) {
    if (report.contendedSql.contested_active_leases > 1) counters.duplicateActiveLeases += 1;
    if (report.contendedSql.workspace_active_leases > 1) counters.duplicateActiveLeases += 1;
    if (report.contendedSql.shared_key_task_rows > 1) counters.duplicateExternalEffects += 1;
  }
  const violations = Object.entries(counters).filter(([, value]) => value !== 0).map(([name, value]) => `${name}=${value}`);
  return { counters, violations, ok: violations.length === 0 };
}

// ---------------------------------------------------------------------------
// Freshness. A DB replay is evidence about a TREE, so the record carries the
// commit, the tree, the image digest, the observed server version and the raw
// run identities — and the aggregator can tell a fresh record from a stale one.
// ---------------------------------------------------------------------------
export function freshnessVerdict({ record, headTreeSha, observedAtIso, windowMs = FRESHNESS_WINDOW_MS }) {
  const freshness = record?.freshness ?? {};
  const startedAt = Date.parse(freshness.started_at ?? '');
  const finishedAt = Date.parse(freshness.finished_at ?? '');
  const observedAt = Date.parse(observedAtIso ?? '');
  const issues = [];
  if (record?.git?.commit_sha === null || record?.git?.commit_sha === undefined) issues.push('missing-commit-sha');
  if (record?.git?.tree_sha !== headTreeSha) issues.push('stale-tree-sha');
  if (record?.container?.image_digest !== POSTGRES_IMAGE) issues.push('image-digest-mismatch');
  if (!/^PostgreSQL 1[0-9]\./.test(record?.container?.server_version ?? '')) issues.push('server-version-unobserved');
  if (!Number.isFinite(startedAt) || !Number.isFinite(finishedAt)) issues.push('missing-run-timestamps');
  else if (finishedAt < startedAt) issues.push('run-timestamps-out-of-order');
  if (Number.isFinite(observedAt) && Number.isFinite(finishedAt)) {
    freshness.age_ms = observedAt - finishedAt;
    if (observedAt < finishedAt) issues.push('record-from-the-future');
    if (observedAt - finishedAt > windowMs) issues.push('stale-run-timestamp');
  } else {
    issues.push('unverifiable-run-timestamp');
  }
  if (freshness.run_ids_unique !== true) issues.push('run-ids-not-unique');
  if (record?.exitCode !== undefined && record?.status === 'PASS' && record.exitCode !== 0) issues.push('green-with-nonzero-exit');
  return { ok: issues.length === 0, issues, age_ms: freshness.age_ms ?? null };
}

/**
 * The aggregator contract: the report of THIS invocation and the record on
 * disk must be the same bytes, the record must be fresh, and a previous green
 * file can never turn a current NOT_RUN_DB or FAIL into a PASS.
 */
export function classifyCurrentDbReplay(executed, writtenEvidence, { headTreeSha = null, observedAtIso = null, windowMs = FRESHNESS_WINDOW_MS } = {}) {
  let observed = null;
  try {
    observed = JSON.parse(executed.stdout);
  } catch {
    observed = null;
  }
  const matchesCurrentRun = observed !== null && typeof observed === 'object'
    && isDeepStrictEqual(writtenEvidence, { ...observed, exitCode: executed.exitCode });
  if (!matchesCurrentRun) {
    return {
      gate: { status: 'FAIL', exitCode: executed.exitCode, source: 'current S2-007 DB replay', reason: 'report absent or differs from the written evidence' },
      evidence: null,
    };
  }
  if (executed.exitCode !== 0) {
    return {
      gate: { status: observed.status === 'NOT_RUN_DB' ? 'NOT_RUN_DB' : 'FAIL', exitCode: executed.exitCode, source: 'current S2-007 DB replay', reason: observed.reason ?? 'the DB replay process failed' },
      evidence: writtenEvidence,
    };
  }
  const freshness = freshnessVerdict({ record: writtenEvidence, headTreeSha: headTreeSha ?? writtenEvidence?.git?.tree_sha ?? null, observedAtIso, windowMs });
  const green = observed.status === 'PASS' && observed.ok === true
    && observed.comparison?.ok === true && observed.hardGates?.ok === true && observed.crashPhase?.ok === true;
  if (!green) {
    return {
      gate: { status: 'FAIL', exitCode: 0, source: 'current S2-007 DB replay', reason: 'the comparison, the hard gates or the crash phase did not pass' },
      evidence: writtenEvidence,
    };
  }
  if (!freshness.ok) {
    return {
      gate: { status: 'FAIL', exitCode: 0, source: 'current S2-007 DB replay', stale: true, reason: `stale evidence: ${freshness.issues.join(',')}` },
      evidence: null,
    };
  }
  return { gate: { status: 'PASS', exitCode: 0, source: 'current S2-007 DB replay', fresh: true }, evidence: writtenEvidence };
}

/** A NOT_RUN_DB is never a green replay: the DB gate fails closed on it. */
export function dbGateExitCode(report) {
  if (report?.status === 'PASS' && report?.ok === true && report?.hardGates?.ok === true
    && report?.comparison?.ok === true && report?.crashPhase?.ok === true) return 0;
  return 1;
}

// ---------------------------------------------------------------------------
// The coordinator
// ---------------------------------------------------------------------------
async function coordinator(args) {
  const writeEvidence = args['no-write'] !== 'true';
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 's2-007-db-replay-'));
  const barrierDir = path.join(workdir, 'barrier');
  const startedAtIso = new Date().toISOString();
  const git = gitFacts();
  let containerStarted = false;
  let external = false;
  let connectionString = process.env.DATABASE_URL ?? null;
  let report = null;

  const finish = (status, extra, exitCode) => {
    const finishedAtIso = new Date().toISOString();
    const record = {
      schemaVersion: 1,
      ticket: 'S2-007',
      harness: 's2-007-db-replay-v1',
      role: 'two-process PostgreSQL replay of the canonical Agent Board store through commands.execute',
      status,
      ok: status === 'PASS',
      ...extra,
      git: {
        commit_sha: git.commit_sha,
        tree_sha: git.tree_sha,
        dirty: git.dirty,
        note: 'the record describes this TREE; an aggregator re-reads HEAD^{tree} and refuses a record that no longer matches',
      },
      container: {
        image_digest: POSTGRES_IMAGE,
        server_version: extra?.container?.server_version ?? null,
        host_port_exposed_beyond_loopback: false,
        data_directory: 'tmpfs (ephemeral, nothing written to the host disk)',
        cleanup: extra?.container?.cleanup ?? null,
      },
      freshness: {
        started_at: startedAtIso,
        finished_at: finishedAtIso,
        duration_ms: Date.parse(finishedAtIso) - Date.parse(startedAtIso),
        observed_at: finishedAtIso,
        run_ids: extra?.freshness?.run_ids ?? null,
        run_ids_unique: extra?.freshness?.run_ids_unique ?? null,
        window_ms: FRESHNESS_WINDOW_MS,
      },
      exitCode,
    };
    const verdict = freshnessVerdict({ record, headTreeSha: gitFacts().tree_sha, observedAtIso: finishedAtIso });
    record.freshness.verdict = verdict;
    if (writeEvidence) fs.writeFileSync(path.join(EVIDENCE_DIR, 's2-007-db-comparison.json'), `${JSON.stringify(record, null, 2)}\n`);
    process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
    process.exit(exitCode);
  };

  try {
    if (connectionString === null) {
      if (!containerAvailable()) {
        finish('NOT_RUN_DB', {
          reason: 'NEEDS_INPUT: no DATABASE_URL and no usable podman environment; the persistence gate is NOT passed and a NOT_RUN_DB result is never a green replay',
          needsInput: 'NEEDS_INPUT',
          databaseEngine: 'PostgreSQL',
          container: { engine: 'podman', provisioned: false, cleanup: { attempted: true, container_absent: null, verified: false } },
        }, 1);
        return;
      }
      const port = await freePort();
      const secret = randomBytes(24).toString('hex');
      const user = 'veritas_s2_007_replay';
      const database = 'veritas_s2_007_replay';
      const url = new URL(`postgresql://127.0.0.1:${port}/${database}`);
      url.username = user;
      url.password = secret;
      connectionString = url.toString();
      removeContainer();
      const started = containerRun([
        'run', '--detach', `--name=${CONTAINER}`, '--pull=never',
        '--publish', `127.0.0.1:${port}:5432`,
        '--read-only', '--user=70:70', '--cap-drop', 'all',
        '--security-opt', 'no-new-privileges', '--pids-limit=64',
        '--memory=384m', '--memory-swap=384m', '--cpus=1',
        '--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=256m,mode=1777',
        '--tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=8m,mode=1777',
        '--env', 'PGDATA=/var/lib/postgresql/data/pgdata',
        '--env', `POSTGRES_USER=${user}`, '--env', `POSTGRES_PASSWORD=${secret}`, '--env', `POSTGRES_DB=${database}`,
        POSTGRES_IMAGE,
      ], { timeout: 120000 });
      if (!started.ok) {
        finish('NOT_RUN_DB', {
          reason: `NEEDS_INPUT: the pinned PostgreSQL image could not be started — ${String(started.stderr || started.stdout).slice(0, 300)}`,
          needsInput: 'NEEDS_INPUT',
          databaseEngine: 'PostgreSQL',
          container: { engine: 'podman', provisioned: false, cleanup: { attempted: true, container_absent: null, verified: false } },
        }, 1);
        return;
      }
      containerStarted = true;
      if (!await waitForPostgres(connectionString)) {
        const logs = containerRun(['logs', '--tail', '40', CONTAINER], { allowFailure: true });
        const state = containerRun(['inspect', CONTAINER, '--format', '{{json .State}}'], { allowFailure: true });
        removeContainer();
        containerStarted = false;
        finish('NOT_RUN_DB', {
          reason: `NEEDS_INPUT: the ephemeral PostgreSQL never accepted a connection — state=${String(state.stdout).slice(0, 200)}; logs=${String(logs.stdout).slice(0, 400)}`,
          needsInput: 'NEEDS_INPUT',
          databaseEngine: 'PostgreSQL',
          container: { engine: 'podman', provisioned: false, cleanup: { attempted: true, container_absent: containerExists(CONTAINER).exists === false, verified: containerExists(CONTAINER).exists === false } },
        }, 1);
        return;
      }
    } else {
      external = true;
    }

    // --- the migrations, ALL of them, in order, digest bound -----------------
    const bootstrap = new Pool({ connectionString, max: 1 });
    const server = (await bootstrap.query('SELECT version() AS version, current_database() AS database, current_user AS role')).rows[0];
    const applied = [];
    for (const schema of ['run_a', 'run_b']) {
      await bootstrap.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
      const schemaPool = new Pool({ connectionString, max: 1, options: `-c search_path=${schema}` });
      try {
        const migration = await applyMigrations({ connectionString, root: ROOT, pool: schemaPool });
        applied.push({ schema, applied: migration.applied });
      } finally {
        await schemaPool.end().catch(() => {});
      }
    }
    const publicPool = new Pool({ connectionString, max: 1, options: '-c search_path=public' });
    const publicMigration = await applyMigrations({ connectionString, root: ROOT, pool: publicPool });
    applied.push({ schema: 'public', applied: publicMigration.applied });
    await publicPool.end().catch(() => {});
    const migrationDigests = discoverMigrations(ROOT).map(({ name, sha256 }) => ({ name, sha256 }));

    const env = { VERITAS_S2_007_DB_URL: connectionString };
    const issues = [];
    const childReports = {};

    // --- phase 1: the shared contended workspace ---------------------------
    const setupOut = path.join(workdir, 'setup.json');
    const setup = spawnExecutor(['--phase', 'setup', '--executor-id', 'exec-s2-007-db-setup', '--run-id', 's2-007-db-setup', '--schema', 'public', '--out', setupOut], { env });
    const setupDone = await setup.done;
    if (setupDone.code !== 0) {
      issues.push(`setup-exit-${setupDone.code}:${String(setupDone.stderr).slice(0, 300)}`);
    }
    childReports.setup = fs.existsSync(setupOut) ? JSON.parse(fs.readFileSync(setupOut, 'utf8')) : { status: 'ERROR', error: 'no report' };
    if (childReports.setup?.status === 'ERROR') issues.push(`setup-error:${childReports.setup.error ?? ''}`);

    // --- phase 2: the two executors, released together, then their own scenario
    // The harness rendezvous table is scaffolding, not canonical state: it is
    // created HERE (one session, no DDL race between the two executors) and
    // dropped when the contended phase is over, which the run then verifies.
    const scaffoldingPool = new Pool({ connectionString, max: 1, options: '-c search_path=public' });
    await scaffoldingPool.query(
      `CREATE TABLE IF NOT EXISTS s2_007_replay_rendezvous (
         label text NOT NULL, executor_id text NOT NULL, pid integer NOT NULL,
         observed_at timestamptz NOT NULL DEFAULT NOW(), PRIMARY KEY (label, executor_id))`,
    );
    await scaffoldingPool.end().catch(() => {});
    const letters = { a: { schema: 'run_a', executorId: 'exec-s2-007-db-a' }, b: { schema: 'run_b', executorId: 'exec-s2-007-db-b' } };
    const contenders = [];
    for (const [label, config] of Object.entries(letters)) {
      const out = path.join(workdir, `contended-${label}.json`);
      contenders.push({
        label,
        config,
        out,
        handle: spawnExecutor([
          '--phase', 'contended', '--executor-id', config.executorId, '--run-id', `s2-007-db-run-${label}`,
          '--schema', 'public', '--label', label, '--barrier-dir', barrierDir, '--out', out,
        ], { env }),
      });
    }
    // Three barriers, released in order, only once both executors are parked.
    for (const stage of ['race', 'bound', 'idem']) {
      try {
        await releaseBarrier(barrierDir, stage, [letters.a.executorId, letters.b.executorId]);
      } catch (error) {
        issues.push(String(error.message ?? error));
      }
    }
    const contendedDone = await Promise.all(contenders.map((entry) => entry.handle.done));
    for (const [index, done] of contendedDone.entries()) {
      if (done.code !== 0) {
        issues.push(`contended-${contenders[index].label}-exit-${done.code}:${String(done.stderr).slice(0, 400)}`);
      }
    }
    // The scaffolding goes away with the phase that needed it.
    const dropPool = new Pool({ connectionString, max: 1, options: '-c search_path=public' });
    await dropPool.query('DROP TABLE IF EXISTS s2_007_replay_rendezvous');
    await dropPool.end().catch(() => {});

    // --- phase 3: the deterministic scenario, one schema per run -----------
    const scenarioReports = {};
    for (const entry of contenders) {
      const { label } = entry;
      const out = path.join(workdir, `scenario-${label}.json`);
      const handle = spawnExecutor([
        '--phase', 'scenario', '--executor-id', entry.config.executorId, '--run-id', `s2-007-db-run-${label}`,
        '--schema', entry.config.schema, '--label', label, '--id-namespace', 's2007db-scenario', '--out', out,
      ], { env });
      const done = await handle.done;
      if (done.code !== 0) issues.push(`scenario-${label}-exit-${done.code}:${String(done.stderr).slice(0, 300)}`);
      scenarioReports[label] = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, 'utf8')) : { status: 'ERROR', error: 'no report' };
    }

    // --- phase 4: the crash/restart, per run -------------------------------
    // A child that dies by SIGKILL never writes a report: the coordinator reads
    // the effect log and the SQL rows instead, which is the only evidence a
    // dead process can leave behind.
    const crashReports = {};
    const crashMeta = {};
    for (const [label, config] of Object.entries(letters)) {
      const handoff = path.join(workdir, `handoff-${label}.json`);
      const effectLog = path.join(workdir, `effects-${label}.log`);
      const crash = spawnExecutor([
        '--phase', 'crash', '--executor-id', config.executorId, '--run-id', `s2-007-db-crash-${label}`,
        '--schema', config.schema, '--label', label, '--id-namespace', 's2-007-db-crash',
        '--handoff', handoff, '--effect-log', effectLog,
      ], { env });
      const died = await crash.done;
      // SIGKILL is reported by the OS, not by the exit code alone: a process
      // that exits 0 after the boundary would have collected a result.
      const diedAsDesigned = died.code === null && died.signal === 'SIGKILL';
      if (!diedAsDesigned) issues.push(`crash-${label}-did-not-die:code=${died.code} signal=${died.signal} stderr=${String(died.stderr).slice(0, 500)}`);
      crashMeta[label] = { exitCode: died.code, signal: died.signal, diedAsDesigned, pid: null };
      if (fs.existsSync(handoff)) {
        const handoffBody = JSON.parse(fs.readFileSync(handoff, 'utf8'));
        crashMeta[label].pid = handoffBody.crash_pid;
        crashMeta[label].executorId = handoffBody.crash_executor_id;
      }
      const recoverOut = path.join(workdir, `recover-${label}.json`);
      const recover = spawnExecutor([
        '--phase', 'recover', '--executor-id', `${config.executorId}-recover`, '--run-id', `s2-007-db-crash-${label}`,
        '--schema', config.schema, '--label', label, '--id-namespace', 's2-007-db-recover', '--handoff', handoff, '--out', recoverOut,
      ], { env });
      const recovered = await recover.done;
      if (recovered.code !== 0) issues.push(`recover-${label}-exit-${recovered.code}:${String(recovered.stderr).slice(0, 300)}`);
      const body = fs.existsSync(recoverOut) ? JSON.parse(fs.readFileSync(recoverOut, 'utf8')) : { status: 'ERROR', error: 'no report' };
      if (body.status === 'ERROR') issues.push(`recover-${label}-error:${body.error ?? ''}`);
      crashReports[label] = body.phase_result ?? null;
    }

    // --- the comparison ---------------------------------------------------
    const runs = {};
    for (const [label] of Object.entries(letters)) {
      runs[label] = {
        schemaVersion: 1,
        ticket: 'S2-007',
        harness: 's2-007-db-replay-run-v1',
        label,
        run_id: `s2-007-db-run-${label}`,
        executor_id: letters[label].executorId,
        executor_ids: {
          contended: letters[label].executorId,
          scenario: letters[label].executorId,
          crash: crashMeta[label].executorId ?? null,
          recover: `${letters[label].executorId}-recover`,
        },
        schema: letters[label].schema,
        database_engine: 'PostgreSQL',
        server_version: server.version,
        pids: {
          contended: JSON.parse(fs.readFileSync(contenders.find((entry) => entry.label === label).out, 'utf8')).identity?.pid ?? null,
          crash: crashMeta[label].pid,
        },
        status: 'RECORDED',
        calls: scenarioReports[label].calls ?? [],
        checks: scenarioReports[label].checks ?? {},
        effects_issued: scenarioReports[label].effects_issued ?? null,
        phase_result: scenarioReports[label].phase_result ?? null,
        contended: JSON.parse(fs.readFileSync(contenders.find((entry) => entry.label === label).out, 'utf8')).phase_result ?? null,
        crash: crashMeta[label],
      };
      if (scenarioReports[label].status === 'ERROR') issues.push(`scenario-${label}-error:${scenarioReports[label].error ?? ''}`);
    }
    // The contended phase: exactly one ACCEPT and one typed refusal per contest.
    for (const [label, entry] of Object.entries(contenders)) {
      const body = JSON.parse(fs.readFileSync(entry.out, 'utf8'));
      const contended = body.phase_result;
      if (contended === null || contended === undefined) {
        issues.push(`contended-${label}-no-result:${JSON.stringify(body).slice(0, 600)}`);
        continue;
      }
      const claim = contended.contestedClaim;
      if (claim.outcome === 'ACCEPT' && claim.code !== null) issues.push(`contended-${label}-accepted-with-code`);
      if (claim.outcome === 'REFUSE') {
        if (claim.typed !== true) issues.push(`contended-${label}-untyped-claim-refusal`);
        if (!EXPECTED_CODES.claimRace.includes(claim.code)) issues.push(`contended-${label}-claim-code-${claim.code}`);
      }
      const bounded = contended.boundedClaim;
      if (bounded.outcome !== 'REFUSE') issues.push(`contended-${label}-bounded-claim-accepted`);
      else if (!EXPECTED_CODES.boundedClaim.includes(bounded.code)) issues.push(`contended-${label}-bounded-code-${bounded.code}`);
      const shared = contended.sharedIdempotency;
      // The race on ONE key from two processes has two honest outcomes: the
      // winner commits, the loser EITHER replays the committed record or is
      // refused with a typed conflict because it lost the primary key. What is
      // NOT acceptable is a second record, and that is decided in SQL below.
      if (shared.outcome === 'REFUSE') {
        if (shared.typed !== true) issues.push(`contended-${label}-shared-key-untyped`);
        if (!EXPECTED_CODES.sharedKeyRace.includes(shared.code)) issues.push(`contended-${label}-shared-key-code-${shared.code}`);
      }
      const settled = contended.sharedIdempotencySettled;
      if (settled === null || settled === undefined) {
        issues.push(`contended-${label}-shared-key-not-settled`);
      } else {
        if (settled.outcome === 'REFUSE' && settled.typed !== true) issues.push(`contended-${label}-settled-untyped`);
        if (settled.outcome === 'REFUSE' && !EXPECTED_CODES.sharedKeyRace.includes(settled.code)) {
          issues.push(`contended-${label}-settled-code-${settled.code}`);
        }
        // The verdict is the SQL: ONE record, and the retry wrote NOTHING.
        // `replayed` is recorded as an observation only — see the report's
        // `interfaceObservations`: the command boundary does not propagate the
        // store's replay flag for `tasks.create`, so it would be dishonest to
        // require a flag the interface does not carry. The deterministic replay
        // proof at the boundary is `scenario.dispatch-replay` instead.
        if (settled.one_record !== true) issues.push(`contended-${label}-settled-rows-${JSON.stringify(settled.rows_after)}`);
        if (settled.nothing_written_twice !== true) issues.push(`contended-${label}-settled-wrote-twice`);
        if (settled.answeredTheCommittedResult !== true) {
          issues.push(`contended-${label}-settled-revision-${settled.reported_revision}-committed-${settled.committed_revision}`);
        }
      }
    }
    // One record for the shared key, from either process: the SQL counts decide.
    // `replayed` is reported, not required: the boundary does not propagate the
    // store's replay flag for `tasks.create` (see `interfaceObservations`), and a
    // flag that is structurally always false would be a weaker check than the
    // SQL counts, not a stronger one.
    const replayedObservations = { contended: null };
    const sharedRows = Object.values(runs).map((run) => run.contended?.sharedIdempotencySettled ?? null);
    if (sharedRows.length === 2 && sharedRows.every((row) => row !== null)) {
      if (new Set(sharedRows.map((row) => row.idempotency_key)).size !== 1) issues.push('contended:shared-keys-differ');
      replayedObservations.contended = sharedRows.filter((row) => row.replayed === true).length;
    }
    if (runs.a.executor_id === runs.b.executor_id) issues.push('identity:executor-ids-identical');
    for (const [label, run] of Object.entries(runs)) {
      if (!Number.isInteger(run.pids?.contended)) issues.push(`identity:contended-pid-missing-${label}`);
    }
    if (Number.isInteger(runs.a.pids?.contended) && runs.a.pids.contended === runs.b.pids.contended) {
      issues.push('identity:contended-pids-identical');
    }

    for (const [label, run] of Object.entries(runs)) verifyRun(run, { letter: label, issues });
    for (const [label, crash] of Object.entries(crashReports)) verifyCrash(crash, { letter: label, issues });

    // The contention counters are read out of PostgreSQL, not out of a return value.
    const contendedPool = new Pool({ connectionString, max: 1, options: '-c search_path=public' });
    const report = {};
    const sharedKey = runs.a.contended?.sharedIdempotencySettled?.idempotency_key ?? null;
    if (sharedKey === null) issues.push('contended:no-shared-key-observed');
    await verifyContended(contendedPool, { issues, report, sharedKey: sharedKey ?? '' });
    report.replayed_observations = replayedObservations;
    await contendedPool.end().catch(() => {});

    // A === B is required IN ADDITION to the expected values, and the raw
    // digests are reported next to the projected ones: the raw digests cannot
    // match, because the database clock wrote different instants into the two
    // schemas, and pretending otherwise would be the dishonest comparison.
    const digestsMatch = runs.a.phase_result?.digest === runs.b.phase_result?.digest;
    if (!digestsMatch) issues.push('comparison:canonical-digest-mismatch');
    const crashChecksMatch = canonicalDigest(crashReports.a?.checks ?? null) === canonicalDigest(crashReports.b?.checks ?? null);
    if (!crashChecksMatch) issues.push('comparison:crash-phase-digest-mismatch');
    // The crash phase is green only when BOTH processes really died by SIGKILL,
    // the recovery reissued nothing, the effect crossed the boundary exactly
    // once and the unknown outcome was closed by an authenticated human.
    const crashOk = crashChecksMatch && Object.entries(crashReports).every(([label]) => crashMeta[label].diedAsDesigned === true
      && crashReports[label] !== null
      && Object.entries(crashReports[label]?.checks ?? {})
        .filter(([name]) => name !== 'effectsIssuedAfterBlindRetry' && name !== 'lateResultCode')
        .every(([, value]) => value === true)
      && crashReports[label]?.checks?.effectsIssuedAfterBlindRetry === 1
      && EXPECTED_CODES.lateResult.includes(crashReports[label]?.codes?.lateResult));
    if (!crashOk) issues.push('crash-phase:not-green');

    // A control on the comparison itself: the same deterministic WRONGNESS is
    // injected into BOTH runs (a wrong final state and a missing transition),
    // their digests are left equal, and the expected-value table must still
    // produce findings. A table that cannot fail this is not a check.
    const identicalWrong = (() => {
      const mutate = (run) => {
        const copy = JSON.parse(JSON.stringify(run));
        copy.phase_result.finalStates[T.s2].state = 'DONE';
        copy.phase_result.finalStates[T.s2].revision = 4;
        copy.phase_result.sql.transitions -= 1;
        return copy;
      };
      const mutatedA = mutate(runs.a);
      const mutatedB = mutate(runs.b);
      const findingsA = runIssues(mutatedA, 'control-a');
      const findingsB = runIssues(mutatedB, 'control-b');
      return {
        injected: 'the same wrong final state (s2 DONE at revision 4) and one missing transition in BOTH runs',
        digests_still_equal: mutatedA.phase_result.digest === mutatedB.phase_result.digest,
        findings: { control_a: findingsA, control_b: findingsB },
        not_a_pass: findingsA.length > 0 && findingsB.length > 0,
      };
    })();
    if (!identicalWrong.not_a_pass) issues.push('comparison:expected-value-table-not-load-bearing');

    const hardGates = hardGateCounters({ runs, crashRuns: crashReports, report });
    for (const violation of hardGates.violations) issues.push(`hard-gate:${violation}`);

    // The harness rendezvous table is scaffolding, not canonical state.
    const scaffolding = (await (await new Pool({ connectionString, max: 1 })).query(
      `SELECT table_schema, table_name FROM information_schema.tables
       WHERE table_name = 's2_007_replay_rendezvous' ORDER BY 1`,
    )).rows;
    if (scaffolding.length > 0) issues.push(`scaffolding-not-removed:${scaffolding.length}`);

    // --- cleanup, and the PROOF that it happened ---------------------------
    let cleanup = { attempted: false, container_absent: null, verified: false };
    if (containerStarted) {
      removeContainer();
      containerStarted = false;
      const exists = containerExists(CONTAINER);
      cleanup = {
        attempted: true,
        container_absent: exists.exists === false,
        verified: exists.known === true && exists.exists === false,
        note: '`podman container exists <name>` must FAIL after the run; an unknown exit is not a removal',
      };
      if (!cleanup.verified) issues.push('cleanup:container-still-present');
    }
    fs.rmSync(workdir, { recursive: true, force: true });

    const runIds = Object.values(runs).map((run) => run.run_id);
    const ok = issues.length === 0;
    for (const [label] of Object.entries(letters)) {
      if (writeEvidence) {
        fs.writeFileSync(path.join(EVIDENCE_DIR, `s2-007-db-run-${label}.json`), `${JSON.stringify(runs[label], null, 2)}\n`);
      }
    }
    finish(ok ? 'PASS' : 'FAIL', {
      databaseEngine: 'PostgreSQL',
      databaseSource: external ? 'external DATABASE_URL' : 'ephemeral loopback-only podman container, tmpfs, random runtime credentials',
      server_version: server.version,
      container: {
        engine: 'podman',
        provisioned: true,
        name: CONTAINER,
        server_version: server.version,
        credentials_persisted: false,
        host_port_exposed_beyond_loopback: false,
        cleanup,
      },
      migrations: { applied, all: migrationDigests, count: migrationDigests.length },
      boundary: {
        entryPoint: 'src/lib/agentboard/commands.mjs#execute',
        store: 'src/lib/agentboard/store.mjs#PostgresAgentBoardStore',
        note: 'Every mutation and every read of this replay went through execute() in a child process with its own pg.Pool; the coordinator ran no board logic and read the committed truth in SQL.',
        max_concurrent_tasks: MAX_CONCURRENT_TASKS,
      },
      honesty: {
        realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
        note: 'No installed, genuinely distinct executor backs any run here: every boundary crossing is a scripted veritas.adapter/1.0.0 test transport. This record is a store/persistence gate, never an A-MVP or real-adapter PASS.',
      },
      interfaceObservations: [
        'The lease-expiry sweep has no command in COMMANDS; `store.expireLeases` is the only entry point, so the sweep is exercised at the store tier and labelled as such.',
        '`recoverOutbox` (commands.outbox.recover) takes no transport parameter at all, which is what makes "recovery reissues nothing" structural rather than a promise.',
        '`tasks.lease.reassign` fills its `fencing_token` response field from the ADAPTER registration, so the field is NaN; the replay reads the new fence from the committed lease row, which is the authority for it.',
        'A concurrent `tasks.create` under the same idempotency key cannot REPLAY when it loses the primary key race: its ledger read happens before the winner commits. It is refused with a typed IDEMPOTENCY_CONFLICT (nothing written twice), and the replay path is proved deterministically afterwards against the committed ledger.',
        '`commands.execute` returns `replayed: result.replayed === true`, but the `tasks.create` (and most) handlers return only `{ data, revision }`, so the store\'s replay flag never reaches the caller. The store still writes nothing a second time: the SQL counts and the returned revision (equal to the COMMITTED revision) prove the answer came from the ledger.',
        '`outbox.dispatch` derives its ledger keys per STAGE inside `driveOutbox`, so the CALLER\'s idempotency key is not itself a ledger row and the command\'s own replay branch cannot fire. The second dispatch of the same key is therefore proved by what did NOT happen: no second boundary crossing and no second row.',
        'The lease-expiry sweep keys its ledger row on the observed DATABASE instant by design, so that key, the outbox send-intent key (it binds the request digest) and the request digest itself are the only digest classes the A/B comparison normalizes. Everything else, including every state, revision, identifier and counter, is compared verbatim.',
      ],
      contended: {
        ...report.contendedSql,
        scenario: 'two processes, one task, one lease; two processes, two tasks, one workspace-wide bound; one idempotency key, two processes, one record',
        replayed_observations: report.replayed_observations ?? null,
      },
      comparison: {
        ok: digestsMatch && crashChecksMatch && issues.filter((issue) => issue.startsWith('comparison:') || issue.startsWith('run-') || issue.startsWith('crash-')).length === 0,
        canonical_digests: { run_a: runs.a.phase_result?.digest ?? null, run_b: runs.b.phase_result?.digest ?? null },
        raw_digests: { run_a: runs.a.phase_result?.rawDigest ?? null, run_b: runs.b.phase_result?.rawDigest ?? null },
        raw_digest_note: 'the raw digests differ by construction: the database clock wrote different instants into the two schemas. The canonical comparison uses the documented projection (see the executor header).',
        crash_phase_digests: { run_a: canonicalDigest(crashReports.a?.checks ?? null), run_b: canonicalDigest(crashReports.b?.checks ?? null) },
        expected_value_table: { final_states: EXPECTED_FINAL_STATES, scenario_sql: EXPECTED_SCENARIO_SQL, codes: EXPECTED_CODES },
        two_identically_wrong_runs_are_not_a_pass: {
          note: 'runIssues() checks EACH run against the expected-value table; A === B is an additional requirement, never a substitute.',
          control: identicalWrong,
        },
        issues,
      },
      crashPhase: {
        ok: crashOk,
        scenario: 'the executor is SIGKILLed inside the transport after the outbox SEND and before any result; a NEW process recovers the canonical state and reissues nothing',
        died_as_designed: Object.fromEntries(Object.entries(crashMeta).map(([label, meta]) => [label, meta.diedAsDesigned])),
        signals: Object.fromEntries(Object.entries(crashMeta).map(([label, meta]) => [label, meta.signal])),
        pids: Object.fromEntries(Object.entries(crashMeta).map(([label, meta]) => [label, meta.pid])),
        effects_issued: Object.fromEntries(Object.entries(crashReports).map(([label, crash]) => [label, crash?.sql?.effects_issued ?? null])),
        effects_issued_after_blind_retry: Object.fromEntries(Object.entries(crashReports).map(([label, crash]) => [label, crash?.checks?.effectsIssuedAfterBlindRetry ?? null])),
        refusals: Object.fromEntries(Object.entries(crashReports).map(([label, crash]) => [label, crash?.codes ?? null])),
      },
      hardGates,
      freshness: { run_ids: runIds, run_ids_unique: new Set(runIds).size === runIds.length },
    }, dbGateExitCode({
      status: ok ? 'PASS' : 'FAIL',
      ok,
      comparison: { ok: issues.length === 0 },
      hardGates,
      crashPhase: { ok: crashOk },
    }));
  } catch (error) {
    removeContainer();
    containerStarted = false;
    const exists = containerExists(CONTAINER);
    finish('FAIL', {
      reason: String(error?.message ?? error).slice(0, 800),
      stack: String(error?.stack ?? '').split('\n').slice(0, 10),
      databaseEngine: 'PostgreSQL',
      container: {
        engine: 'podman',
        provisioned: containerStarted,
        cleanup: { attempted: true, container_absent: exists.exists === false, verified: exists.known === true && exists.exists === false },
      },
      comparison: { ok: false, issues: ['coordinator-threw'] },
      hardGates: { ok: false, counters: {}, violations: ['coordinator-threw'] },
      crashPhase: { ok: false },
      freshness: { run_ids: [], run_ids_unique: false },
    }, 1);
  }
}

const args = parseArgs(process.argv);
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await coordinator(args);
}
