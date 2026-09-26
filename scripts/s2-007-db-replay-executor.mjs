// S2-007 DB replay EXECUTOR — one OS process, one pg Pool, one agentboard
// store (issue #7 §4 "the execution boundary"; frozen spec §3.2 store tier and
// §4 hard gates).
//
// WHY A SEPARATE PROCESS AND NOT A FUNCTION CALL
// The properties this file exists to prove are the ones a single JavaScript heap
// cannot express. `await` makes two in-process calls COOPERATIVE, never
// concurrent; two promises on one event loop take turns at the transaction
// boundary, so a second writer can only ever observe a committed first writer
// and never a row lock held by a peer session. The guarantee under test is
// "two independent transactions, two connections, two sessions, one lease",
// so the race must be a race between PROCESSES. Each executor therefore opens
// its OWN `pg.Pool` (its own backend sessions), builds its own
// `PostgresAgentBoardStore` over it, and reaches the board only through
// `commands.execute` — the single mutation surface of the frozen spec §1. The
// store is used to OBSERVE committed rows in SQL, never to decide anything.
//
// WHAT IS FIXED AND WHAT IS INJECTED
//   * The clock is a counter over one frozen base instant, advanced once per
//     boundary call, and it is passed INTO the boundary as `now`/`clock`.
//     There is no `Date.now()` and no `new Date()` without that injection in
//     this file: a replay that read the process clock could not be compared
//     byte for byte against the other run.
//   * Identifiers come from a deterministic, namespaced id factory. The
//     namespace is per PHASE, not per executor, in the phases whose output is
//     compared between run A and run B — the two runs live in two schemas of
//     the same database, so identical generated ids cannot collide, and
//     identical ids are what makes `A === B` a meaningful statement.
//   * The database clock still decides lease expiry and the fencing token; that
//     is the store's rule, not this file's.
//
// PHASES (one process each; the coordinator spawns them)
//   setup     — seeds the shared contended workspace: two adapters, one
//               contested READY task, one per-executor READY task, budgets.
//   contended — the cross-process contention. Executor A and executor B are
//               released from a file barrier and a database rendezvous and then
//               (1) claim the SAME task, (2) each try to claim their OWN task
//               while the workspace already runs one active task, (3) create a
//               task with the SAME idempotency key and the same arguments and
//               (4) each repeat that create AFTER the race, so the committed
//               ledger answers instead of a second write.
//   scenario  — the deterministic, comparable full lifecycle in this run's own
//               schema: register, create, ready, grant, start, dispatch, the
//               SAME dispatch key presented a second time (no second effect, no
//               second row), event, collect, human approval, settle, then three
//               fenced-lease stories (reassign, expiry, cancel) each proved to
//               change nothing for a stale fence.
//   crash     — drives a run to the outbox SEND and is then SIGKILLed by its
//               own transport before any result is collected. It writes no
//               report: dying is the assertion.
//   recover   — a DIFFERENT process (new pid, new executor id) that observes
//               the committed SENT row, recovers the canonical state WITHOUT
//               reissuing the side effect, and proves it by the number of
//               effects the crashed process actually issued.
//
//   node scripts/s2-007-db-replay-executor.mjs --phase <p> --executor-id <id>
//        --run-id <id> --schema <name> --out <file> [--label <a|b>]
//
// VERITAS_S2_007_DB_URL carries the connection string; nothing else is read
// from the environment. Exit code 0 = the phase completed and wrote its report,
// 2 = the phase ran and its own checks failed, 3 = the phase could not start.
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

import { PostgresAgentBoardStore } from '../src/lib/agentboard/store.mjs';
import { execute } from '../src/lib/agentboard/commands.mjs';
import { createTestTransport } from '../src/lib/agentboard/adapters.mjs';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { isBoardError } from '../src/lib/agentboard/errors.mjs';
import { fixedClock } from '../src/lib/agentboard/policy.mjs';
import { ID_PREFIXES, NON_RETRYABLE_CODES, TRANSITIONS } from '../src/lib/agentboard/constants.mjs';

const { Pool } = pg;

// ---------------------------------------------------------------------------
// The frozen world. Every identifier below is a FIXTURE: it is namespaced per
// phase so two executors can never mint the same key on shared rows, and so the
// primary keys of the append-only tables are a function of the call sequence
// rather than of the wall clock.
// ---------------------------------------------------------------------------
const CLOCK_BASE = '2026-09-25T12:00:00.000Z';
const STEP_MS = 1000;
const CLOCK_DAY = '2026-09-25';
const PROVEN_PROFILE = 'sbx-podman-local-restricted-v1';

const WS = Object.freeze({ race: 'ws-s2007-db-race', scenario: 'ws-s2007-db-scenario', crash: 'ws-s2007-db-crash' });
const ROOTS = Object.freeze({
  [WS.race]: ['/srv/workspaces/veritas-s2007-db'],
  [WS.scenario]: ['/srv/workspaces/veritas-s2007-db'],
  [WS.crash]: ['/srv/workspaces/veritas-s2007-db'],
});
// `agentboard_adapter.adapter_id` is the table's PRIMARY KEY, so an adapter
// identity is a DATABASE-WIDE claim, not a per-workspace one: each phase
// registers its own ids instead of re-registering one id in another workspace,
// which the store correctly refuses as a reused identity with new content.
const A = Object.freeze({
  race: Object.freeze({ alpha: 'adr-s2007-db-race-a', alt: 'adr-s2007-db-race-b' }),
  scenario: Object.freeze({ alpha: 'adr-s2007-db-scen-a', alt: 'adr-s2007-db-scen-b' }),
  crash: Object.freeze({ alpha: 'adr-s2007-db-crash-a' }),
});
const T = Object.freeze({
  contested: 'abt-s2007-db-contested',
  perRun: { a: 'abt-s2007-db-a', b: 'abt-s2007-db-b' },
  idem: 'abt-s2007-db-idem',
  s1: 'abt-s2007-db-s1', s2: 'abt-s2007-db-s2', s3: 'abt-s2007-db-s3', s4: 'abt-s2007-db-s4',
  crash: 'abt-s2007-db-c1',
});
const P = Object.freeze({
  owner: 'prn-s2007-db-owner',
  reviewer: 'prn-s2007-db-reviewer',
  scheduler: 'prn-s2007-db-scheduler',
  producer: 'prn-s2007-db-producer',
  execA: 'prn-s2007-db-exec-a',
  execB: 'prn-s2007-db-exec-b',
  sweeper: 'prn-s2007-db-sweeper',
});
  // Real, different grants. A capability that is missing here is refused by the
  // boundary before any payload is read; keeping the sets apart is the point.
  // The reviewer holds `board.reconciliation.decide` because closing an unknown
  // outcome is a HUMAN act in this design; the producer deliberately does not
  // hold it, and the sweeper holds the transition scope the outbox recovery
  // command requires.
  const CAP = Object.freeze({
  owner: [
    'board.task.read', 'board.task.create', 'board.task.transition', 'board.task.claim', 'board.task.release',
    'board.execution.start', 'board.execution.cancel', 'board.result.collect', 'board.evidence.submit',
    'board.review.challenge', 'board.adapter.register', 'board.budget.grant', 'board.reconciliation.decide',
  ],
  reviewer: ['board.task.read', 'board.task.transition', 'board.review.approve', 'board.review.challenge', 'board.reconciliation.decide'],
  scheduler: [
    'board.task.read', 'board.task.claim', 'board.task.release',
    'board.execution.start', 'board.execution.cancel', 'board.result.collect',
  ],
  producer: ['board.task.read', 'board.task.transition', 'board.execution.start', 'board.result.collect', 'board.evidence.submit'],
  sweeper: ['board.task.read', 'board.task.transition', 'board.task.release', 'board.reconciliation.decide'],
});
const ACL_RACE = Object.freeze([P.owner, P.reviewer, P.scheduler, P.producer, P.execA, P.execB, P.sweeper]);

const d = (char) => `sha256:${char.repeat(64)}`;

/** One idempotency key per (phase namespace, step, command, args, actor). */
function key(namespace, command, args, actor) {
  return canonicalDigest({ namespace, command, args, actor });
}

/**
 * Deterministic id factories. The `namespace` argument is the whole reason two
 * runs are comparable: identical namespaces over identical call sequences mint
 * identical identifiers, so a canonical digest of the committed rows is a
 * statement about the CALL SEQUENCE and not about the two processes.
 *
 * TWO factories, because the two consumers of an id have OPPOSITE contracts
 * and neither of them repairs what it is given:
 *   * `store.newId(kind)` PREPENDS the frozen `ID_PREFIXES[kind]`, so the
 *     store factory must return the bare suffix or every id would read
 *     `lse-lse-…`;
 *   * the scheduler's `resolveId(kind)` REFUSES an id that does not already
 *     carry the contract prefix (`ID_FACTORY_PREFIX_MISMATCH`), because a
 *     silently repaired id is a second, invisible source of identity.
 * Both counters are driven by the same fixed call sequence, so run A and run B
 * still mint the same identifiers on both sides.
 */
function storeIds(namespace) {
  const counters = new Map();
  return (kind) => {
    const next = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, next);
    return `${namespace}-${next.toString(36).padStart(6, '0')}`;
  };
}

function boundaryIds(namespace) {
  const counters = new Map();
  return (kind) => {
    const next = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, next);
    return `${ID_PREFIXES[kind] ?? ''}${namespace}-${next.toString(36).padStart(6, '0')}`;
  };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
function taskDocument(taskId, workspaceId, {
  title, acl = ACL_RACE, dependencies = [], priority = 'HIGH', profile = PROVEN_PROFILE, rootRef = 'db',
}) {
  return {
    contractVersion: '1.0.0',
    task_id: taskId,
    workspace_id: workspaceId,
    title,
    goal: 'Prove that one canonical store serves two independent processes',
    description: 'S2-007 PostgreSQL two-process replay fixture.',
    acceptance_criteria: [
      'Exactly one process may hold the lease',
      'A stale fence changes nothing',
    ],
    state: 'BACKLOG',
    revision: 1,
    priority,
    dependencies,
    required_capabilities: ['source.read'],
    allowed_tools: ['tool:fs.read'],
    workspace_ref: {
      workspace_id: workspaceId,
      root_ref: rootRef,
      isolation_profile_id: profile,
      sandbox_profile_digest: d('a'),
      read_only_paths: [],
    },
    time_limits: { timeout_ms: 60000, max_runtime_ms: 120000, deadline: null },
    cost_limits: { currency: 'USD', max_task_cost: 5, max_campaign_cost: 20, max_day_cost: 10 },
    acl: { visibility: 'project', allowed_principal_ids: [...acl] },
    brief_digest: d('b'),
    policy_digest: d('c'),
    manifest_digest: d('e'),
    assigned_adapter_id: null,
    active_lease_id: null,
    fencing_token: null,
    attempts: 0,
    artifacts: [],
    evidence_refs: [],
    block_reason: null,
    created_at: CLOCK_BASE,
    updated_at: CLOCK_BASE,
    history_digest: d('f'),
  };
}

function budgetGrant(taskId, workspaceId) {
  return {
    grant_id: `grt-${taskId.slice(4)}`,
    workspace_id: workspaceId,
    task_id: taskId,
    currency: 'USD',
    task_limit: 5,
    campaign_limit: 20,
    day_limit: 10,
    timeout_ms: 60000,
    granted_by: P.owner,
    expires_at: null,
    revoked_at: null,
  };
}

function principalOf(principalId, capabilityKey) {
  return { principal_id: principalId, capabilities: [...CAP[capabilityKey]], workspace_ids: [WS.race, WS.scenario, WS.crash] };
}

function eventDocument({ run, sequence = 1, instant }) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    event_id: `eve-${run.run_id}-progress`,
    run_id: run.run_id,
    task_id: run.task_id,
    workspace_id: run.workspace_id,
    lease_id: run.lease_id,
    fencing_token: Number(run.fencing_token),
    sequence,
    event_type: 'PROGRESS',
    payload: { note: 'bounded collection progress recorded by the scripted transport' },
    outcome: null,
    emitted_at: instant,
  };
}

function resultDocument({ run, sequence = 2, instant, spend = 0.25, outcome = 'SUCCEEDED' }) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    run_id: run.run_id,
    task_id: run.task_id,
    workspace_id: run.workspace_id,
    lease_id: run.lease_id,
    fencing_token: Number(run.fencing_token),
    sequence,
    outcome,
    checkpoints: [],
    artifact_hashes: [{ artifact_id: `art-${run.task_id.slice(4)}`, digest: d('9'), media_type: 'application/json' }],
    measurements: {
      duration_ms: 1200, spend, currency: 'USD', model_id: 's2-007-db-scripted-test-transport', tool_calls: 2,
    },
    error: null,
    reconciliation_required: false,
    completed_at: instant,
  };
}

function reconciliationDocument({ reconciliationId, taskId, runId, resolution, detail }) {
  return {
    reconciliation_id: reconciliationId,
    workspace_id: WS.crash,
    task_id: taskId,
    run_id: runId,
    resolution,
    detail,
    evidence_ref: null,
  };
}

// ---------------------------------------------------------------------------
// The canonical cross-run projection.
//
// WHY A PROJECTION AND NOT THE RAW ROWS
// `A === B` is only a meaningful claim if the two runs differ in exactly the
// two things they are supposed to differ in (the executor id and the pid) and
// in nothing else. Two sources of unavoidable difference exist and both are
// removed BY NAME, never by pattern-matching a whole row away:
//
//   1. Columns written from the DATABASE clock (issued_at, committed_at, …).
//      They are wall time by construction; a lease is written with the
//      database's `NOW()` and no injected clock can make two processes agree
//      on it. Those columns are excluded.
//   2. ISO-8601 instants that appear INSIDE a text column (a lease edge writes
//      "granted … until <db clock>" into `reason`; a lease wire document
//      embeds `expires_at`). Those values are normalized to a fixed token so
//      the surrounding text is still compared.
//
// Everything else — identifiers, states, revisions, fencing tokens, dispatch
// states, digests, counters, sequences, amounts — is projected verbatim. The
// column lists are checked against `information_schema` before use, so a
// renamed or newly added column fails the replay loudly instead of silently
// leaving the projection behind the schema.
// ---------------------------------------------------------------------------
const VOLATILE_COLUMNS = Object.freeze([
  'created_at', 'updated_at', 'issued_at', 'expires_at', 'released_at', 'granted_at', 'committed_at',
  'occurred_at', 'started_at', 'completed_at', 'received_at', 'sent_at', 'acked_at', 'registered_at', 'emitted_at',
  'revoked_at',
]);
// The three digest CLASSES that a database clock necessarily enters. They are
// normalized BY NAME to a fixed token, never dropped, and every other value in
// the row — operation, actor, outcome, ids, revisions, states — is compared
// verbatim:
//
//   1. the ExecutionRequest digest (run.request_digest and the outbox
//      payload_digest): the request embeds the budget grant's `granted_at` and
//      the lease's issue/expiry, all written from the server's `NOW()`;
//   2. the outbox send intent key (operation `outbox.dispatch`): it binds that
//      request digest, so the clock enters the ledger key by construction;
//   3. the lease-expiry sweep (operation `board.lease.expire` and the
//      `lease_rebind` transition it appends): the sweep keys on the observed
//      instant BY DESIGN — "a sweep is a distinct operation per instant".
//
// The claim is falsifiable, which is the only thing that makes it honest: run
// the same harness twice and these three classes are the ONLY values that move.
// The documents they cover are still compared (request_payload, the outbox
// payload, the audit details) with their instants normalized, which is strictly
// stronger than comparing the digest alone.
const DB_CLOCK_DIGEST = '<DB_CLOCK_DIGEST>';
const DB_CLOCK_KEYED_OPERATIONS = Object.freeze(['outbox.dispatch', 'board.lease.expire']);
// `request_digest` is the digest of the ExecutionRequest, so it appears at any
// depth of any table that embeds a run: the run row, the audit detail of the
// start, the result payload the store returns. `payload_digest` is that same
// value on the outbox row. `args_digest` is deterministic everywhere EXCEPT
// for the two clock-keyed operations below, so it is normalized only there —
// a general rule would delete the comparison it claims to make.
const REQUEST_DIGEST_KEYS = Object.freeze(['request_digest', 'payload_digest']);
const CLOCK_KEYED_DIGEST_KEYS = Object.freeze(['args_digest', 'payload_digest']);
const PROJECTION = Object.freeze({
  agentboard_task: ['task_id', 'workspace_id', 'revision', 'state', 'priority', 'title', 'goal', 'description', 'dependencies', 'required_capabilities', 'allowed_tools', 'workspace_ref', 'time_limits', 'cost_limits', 'brief_digest', 'policy_digest', 'manifest_digest', 'brief_validated', 'assigned_adapter_id', 'active_lease_id', 'fencing_token', 'attempts', 'artifacts', 'evidence_refs', 'block_reason', 'history_digest'],
  agentboard_acl: ['task_id', 'workspace_id', 'visibility', 'allowed_principal_ids'],
  agentboard_lease: ['lease_id', 'task_id', 'workspace_id', 'adapter_id', 'principal_id', 'fencing_token', 'lease_state', 'revoked_reason'],
  agentboard_adapter: ['adapter_id', 'workspace_id', 'provider', 'display_name', 'adapter_kind', 'health', 'principal_id', 'declared_capabilities', 'declared_tools', 'sandbox_profile_id', 'max_concurrency', 'provenance_status', 'provenance_detail'],
  agentboard_budget_grant: ['grant_id', 'workspace_id', 'task_id', 'currency', 'task_limit', 'campaign_limit', 'day_limit', 'timeout_ms', 'granted_by'],
  agentboard_budget_spend: ['grant_id', 'operation_id', 'task_id', 'workspace_id', 'day_key', 'currency', 'spent_task', 'spent_campaign', 'spent_day'],
  agentboard_run: ['run_id', 'task_id', 'workspace_id', 'adapter_id', 'lease_id', 'fencing_token', 'request_id', 'idempotency_key', 'run_state', 'last_sequence', 'brief_digest', 'policy_digest', 'manifest_digest', 'request_payload', 'request_digest', 'result_payload', 'result_digest', 'error_payload', 'spend', 'currency', 'dispatch_attempts'],
  agentboard_execution_event: ['event_id', 'run_id', 'task_id', 'workspace_id', 'lease_id', 'fencing_token', 'sequence', 'event_type', 'outcome', 'payload', 'payload_digest'],
  agentboard_transition: ['transition_id', 'task_id', 'workspace_id', 'from_state', 'to_state', 'revision', 'actor', 'actor_kind', 'idempotency_key', 'reason', 'lease_id', 'fencing_token', 'brief_digest', 'policy_digest', 'manifest_digest', 'payload', 'payload_digest'],
  agentboard_audit: ['audit_id', 'workspace_id', 'task_id', 'actor', 'operation', 'idempotency_key', 'outcome', 'detail'],
  agentboard_outbox: ['outbox_id', 'workspace_id', 'task_id', 'run_id', 'event_type', 'idempotency_key', 'dispatch_state', 'payload', 'payload_digest', 'attempts', 'last_error'],
  agentboard_operation: ['idempotency_key', 'workspace_id', 'operation', 'args_digest', 'result_payload', 'actor'],
  agentboard_reconciliation: ['reconciliation_id', 'workspace_id', 'task_id', 'run_id', 'resolution', 'decided_by', 'decided_by_kind', 'evidence_ref', 'detail'],
});
const ISO_INSTANT = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z/g;

function normalizeInstants(value) {
  if (typeof value === 'string') return value.replace(ISO_INSTANT, '<DB_CLOCK>');
  if (Array.isArray(value)) return value.map(normalizeInstants);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = normalizeInstants(v);
    return out;
  }
  return value;
}

/** Mark the named digest fields wherever they appear, at any depth. */
function normalizeDigests(value, names, token = DB_CLOCK_DIGEST) {
  if (Array.isArray(value)) return value.map((item) => normalizeDigests(item, names, token));
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = names.includes(k) ? token : normalizeDigests(v, names, token);
    return out;
  }
  return value;
}

/**
 * The per-table, per-row normalization. It is deliberately explicit: a
 * general "anything that looks like a digest" rule would delete the very
 * comparison it claims to perform, so each class is matched by the column or
 * the operation that produced it.
 */
function normalizeTableRows(table, rows) {
  return rows.map((row) => {
    // 1. instants, everywhere, at any depth;
    const timed = normalizeInstants(JSON.parse(JSON.stringify(row)));
    // 2. the request digest, at any depth, in any table that embeds a run;
    const record = normalizeDigests(timed, REQUEST_DIGEST_KEYS);
    // 3. the two operations the database clock keys by design, plus the
    //    transition the sweep appends.
    if (table === 'agentboard_transition' && record.payload?.kind === 'lease_rebind' && record.payload.expired_at !== undefined) {
      record.idempotency_key = DB_CLOCK_DIGEST;
      record.payload_digest = DB_CLOCK_DIGEST;
    }
    if (DB_CLOCK_KEYED_OPERATIONS.includes(record.operation) && (table === 'agentboard_audit' || table === 'agentboard_operation')) {
      record.idempotency_key = DB_CLOCK_DIGEST;
      record.args_digest = DB_CLOCK_DIGEST;
      if (table === 'agentboard_audit') record.detail = normalizeDigests(record.detail, CLOCK_KEYED_DIGEST_KEYS);
      if (table === 'agentboard_operation') record.result_payload = normalizeDigests(record.result_payload, CLOCK_KEYED_DIGEST_KEYS);
    }
    return record;
  });
}

/** The committed rows of one workspace, projected, normalized and digested. */
async function workspaceDigest(pool, schema, workspaceId) {
  const out = {};
  for (const [table, columns] of Object.entries(PROJECTION)) {
    const present = await pool.query(
      'SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2',
      [schema, table],
    );
    const actual = new Set(present.rows.map((row) => row.column_name));
    const unknown = columns.filter((column) => !actual.has(column));
    if (unknown.length > 0) throw new Error(`PROJECTION_UNKNOWN_COLUMN:${schema}.${table}:${unknown.join(',')}`);
    const leaked = [...actual].filter((column) => !columns.includes(column) && !VOLATILE_COLUMNS.includes(column));
    if (leaked.length > 0) throw new Error(`PROJECTION_UNPROJECTED_COLUMN:${schema}.${table}:${leaked.sort().join(',')}`);
    const result = await pool.query(
      `SELECT ${columns.join(', ')} FROM ${schema}.${table} WHERE workspace_id = $1`,
      [workspaceId],
    );
    // Sorted AFTER the normalization: `agentboard_operation` is keyed by a
    // database-clock-derived ledger key, so ordering by that key would make the
    // row ORDER a function of the wall clock instead of of the call sequence.
    const rows = normalizeTableRows(table, result.rows);
    rows.sort((left, right) => (JSON.stringify(left) < JSON.stringify(right) ? -1 : 1));
    out[table] = canonicalDigest(rows);
  }
  return canonicalDigest(out);
}

/** The same workspace WITHOUT the projection: the raw committed truth. */
async function rawWorkspaceDigest(pool, schema, workspaceId) {
  const out = {};
  for (const table of Object.keys(PROJECTION).sort()) {
    const result = await pool.query(`SELECT * FROM ${schema}.${table} WHERE workspace_id = $1 ORDER BY 1`, [workspaceId]);
    out[table] = canonicalDigest(JSON.parse(JSON.stringify(result.rows)));
  }
  return canonicalDigest(out);
}

async function countRows(pool, schema, table, where = '', params = []) {
  const result = await pool.query(`SELECT count(*)::int AS total FROM ${schema}.${table} ${where}`, params);
  return Number(result.rows[0].total);
}

// ---------------------------------------------------------------------------
// The executor
// ---------------------------------------------------------------------------
class Executor {
  constructor({ pool, schema, executorId, runId, idNamespace, phase, label, now }) {
    this.pool = pool;
    this.schema = schema;
    this.executorId = executorId;
    this.runId = runId;
    this.phase = phase;
    this.label = label;
    this.storeIds = storeIds(idNamespace);
    this.boundaryIds = boundaryIds(idNamespace);
    this.tick = 0;
    this.step = 0;
    this.readSeq = 0;
    this.clock = () => new Date(Date.parse(CLOCK_BASE) + this.tick * STEP_MS);
    this.store = new PostgresAgentBoardStore({ pool, clock: { now: this.clock }, ids: this.storeIds, seed: `s2-007-db-${idNamespace}` });
    this.calls = [];
    this.effects = [];
    this.checks = {};
    this.findings = [];
  }

  /** The server-resolved instant: one fixed step per boundary call. */
  instant() {
    this.tick += 1;
    return this.clock().toISOString();
  }

  /**
   * THE production-facing call. Every mutation and every read of the replay
   * goes through here, and nothing untyped is allowed to escape into the
   * report: an untyped throw is a finding, not a pass.
   */
  async call(step, command, args, { principal, actorKind, workspaceId, transport = null, adapters = null, idempotencyKey = null }) {
    const instant = this.instant();
    // A non-canonical argument (a NaN fence read from the wrong place, an
    // undefined member) must fail LOUDLY and locally: the canonicalizer is the
    // single argument contract, and a harness bug must never look like a
    // board refusal.
    let keyValue = idempotencyKey;
    try {
      if (keyValue === null) keyValue = key(this.idNamespace, command, { step, ...args }, principal.principal_id);
    } catch (error) {
      throw new Error(`HARNESS_NON_CANONICAL_ARGS:${step}:${String(error?.message ?? error).slice(0, 200)}`);
    }
    const row = { step, command, actor: principal.principal_id, actor_kind: actorKind, workspace_id: workspaceId, idempotency_key: keyValue };
    try {
      const result = await execute({
        command,
        args: { ...args, idempotency_key: keyValue },
        principal,
        actorKind,
        store: this.store,
        adapters,
        transport,
        clock: { now: this.clock },
        now: instant,
        workspaceRoots: ROOTS[workspaceId],
        ids: this.boundaryIds,
      });
      this.step += 1;
      const record = {
        ...row,
        outcome: 'ACCEPT',
        code: null,
        typed: true,
        replayed: result.replayed === true,
        revision: result.revision ?? null,
      };
      this.calls.push(record);
      return { ...result, data: result.data ?? null, record };
    } catch (error) {
      this.step += 1;
      const typed = isBoardError(error);
      const record = {
        ...row,
        outcome: 'REFUSE',
        code: typed ? error.code : `UNTYPED_${String(error?.name ?? 'UNKNOWN')}`,
        typed,
        retryable: typed ? error.retryable : null,
        non_retryable: typed ? NON_RETRYABLE_CODES.includes(error.code) : false,
        message: String(error?.message ?? error).slice(0, 200),
      };
      this.calls.push(record);
      return { ok: false, error, record, data: null };
    }
  }

  /** A production READ. The step is unique per call, so a read never replays. */
  async readTask(taskId, workspaceId, principal) {
    this.readSeq += 1;
    const out = await this.call(`read.${String(this.readSeq).padStart(4, '0')}.${taskId}`, 'tasks.get', { task_id: taskId }, {
      principal, actorKind: 'human_owner', workspaceId,
    });
    if (out.record.outcome !== 'ACCEPT' || !out.data?.task) {
      throw new Error(`TASK_UNREADABLE:${taskId}:${out.record.code ?? 'no-task'}:${out.record.message ?? ''}`);
    }
    return out.data.task;
  }

  /**
   * The edge's guard is READ OUT of the frozen transition table, so the report
   * never re-declares which guard owns an edge. `observation` names the
   * recorded check, so a REFUSED attempt and the ACCEPT that answers it are two
   * observations instead of one overwritten entry.
   */
  transition({ step, task, toState, workspaceId, principal, actorKind, reason, observation = null }) {
    const from = task.state;
    return this.call(step, 'tasks.transition', {
      task_id: task.task_id,
      to_state: toState,
      expected_revision: task.revision,
      reason,
      brief_digest: task.brief_digest,
      policy_digest: task.policy_digest,
      manifest_digest: task.manifest_digest,
    }, { principal, actorKind, workspaceId }).then((out) => {
      this.checks[observation ?? `guard:${task.task_id}:${from}->${toState}`] = {
        guard: TRANSITIONS[from]?.[toState] ?? null,
        decision: out.record.outcome === 'ACCEPT' ? 'ACCEPT' : 'REFUSE',
        code: out.record.code ?? null,
      };
      return out;
    });
  }
}

// ---------------------------------------------------------------------------
// Transports. The side effect is a LINE IN A FILE: the crash phase has to prove
// that a recovery process reissued nothing, and only an independently
// observable counter can carry that proof across a SIGKILL.
// ---------------------------------------------------------------------------
function scriptedTransport(executor, adapterId, workspaceId, { script = {} } = {}) {
  return createTestTransport({
    script,
    clock: { now: executor.clock },
    ids: executor.boundaryIds,
    provenance: {
      adapter_id: adapterId,
      workspace_id: workspaceId,
      principal_id: P.producer,
      declared_capabilities: ['source.read'],
      declared_tools: ['tool:fs.read'],
      sandbox_profile_id: PROVEN_PROFILE,
      health: 'healthy',
      display_name: `S2-007 db replay transport ${adapterId}`,
      detail: 'S2-007 PostgreSQL replay fixture: no installed executor is bound to this adapter',
    },
  });
}

/**
 * The dispatch shim `driveOutbox` prefers over `start()`: it COUNTS the
 * boundary crossings, and a count is the only proof that survives a SIGKILL.
 *
 * `start()` takes the run identity EXPLICITLY — the ExecutionRequest is the
 * handoff document and deliberately carries no run_id, because the run row and
 * its id are the board's and an executor may not invent a run identity. The
 * shim therefore passes the run the board minted, next to the payload the
 * driver handed it, and records the crossing under that same run id.
 */
function outboxShim(executor, transport, { runId, workspaceId, effectLog = null, onSend = null } = {}) {
  return {
    async dispatch(payload) {
      if (effectLog !== null) fs.appendFileSync(effectLog, `${runId}\n`, 'utf8');
      executor.effects.push(runId);
      if (onSend !== null) onSend(payload);
      // The two-argument form: the ExecutionRequest is a whole contract
      // document, so it is handed over as `request` and the run identity as the
      // call object. The one-object form would be read as a call with no
      // run_id, which the transport refuses.
      return transport.start(payload, { run_id: runId, workspace_id: workspaceId, at: executor.clock().toISOString() });
    },
    async cancel(args) { return transport.cancel(args); },
    async health() { return transport.health(); },
    async identify() { return transport.identify(); },
  };
}

// ---------------------------------------------------------------------------
// The file barrier. The race is not left to chance: both executors park here
// and the coordinator releases them only once both markers exist.
// ---------------------------------------------------------------------------
// The marker names are `<kind>.<stage>.<executor>` and `go.<stage>`: the
// coordinator releases a stage only once it has SEEN `ready.<stage>.<id>` for
// every executor it started, so the two sides cannot disagree about the
// spelling of a barrier.
function barrierReady(dir, stage, executorId) {
  return path.join(dir, `ready.${stage}.${executorId}`);
}

function barrierGo(dir, stage) {
  return path.join(dir, `go.${stage}`);
}

async function arriveAtBarrier(dir, label, executorId, { timeoutMs = 120000 } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(barrierReady(dir, label, executorId), `${process.pid}\n`, 'utf8');
  const go = barrierGo(dir, label);
  const deadline = Date.now() + timeoutMs;
  while (!fs.existsSync(go)) {
    if (Date.now() > deadline) throw new Error(`BARRIER_TIMEOUT:${label}:${executorId}`);
    await new Promise((resolve) => { setTimeout(resolve, 20); });
  }
}

/**
 * The database rendezvous. A file barrier proves both processes are alive; it
 * does not prove both are AT the claim. Each executor records itself in a
 * harness table and waits until both records are visible, so the two
 * transactions are issued from the same instant as far as the database is
 * concerned.
 */
const RENDEZVOUS_TABLE = 's2_007_replay_rendezvous';

/**
 * Two processes may reach the harness DDL at the same instant, and
 * `CREATE TABLE IF NOT EXISTS` is NOT atomic across sessions: the loser gets a
 * `pg_type_typname_nsp_index` unique violation, not a no-op. The scaffolding is
 * therefore created by the coordinator BEFORE either executor starts, and this
 * helper only tolerates the race: a duplicate-object error means the other
 * process created it a microsecond earlier, which is exactly the outcome this
 * barrier wants.
 */
async function ensureRendezvousTable(pool, schema) {
  const deadline = Date.now() + 30000;
  for (;;) {
    try {
      await pool.query(
        `CREATE TABLE IF NOT EXISTS ${schema}.${RENDEZVOUS_TABLE} (
           label text NOT NULL, executor_id text NOT NULL, pid integer NOT NULL,
           observed_at timestamptz NOT NULL DEFAULT NOW(), PRIMARY KEY (label, executor_id))`,
      );
      return true;
    } catch (error) {
      const message = String(error?.message ?? error);
      if (message.includes('pg_type_typname_nsp_index') || message.includes('already exists')) return true;
      if (Date.now() > deadline) throw new Error(`RENDEZVOUS_DDL_FAILED:${message.slice(0, 200)}`);
      await new Promise((resolve) => { setTimeout(resolve, 25); });
    }
  }
}

async function rendezvous(pool, schema, label, executorId) {
  await ensureRendezvousTable(pool, schema);
  await pool.query(
    `INSERT INTO ${schema}.${RENDEZVOUS_TABLE}(label, executor_id, pid) VALUES ($1, $2, $3)
     ON CONFLICT (label, executor_id) DO UPDATE SET observed_at = NOW()`,
    [label, executorId, process.pid],
  );
  const deadline = Date.now() + 120000;
  for (;;) {
    const result = await pool.query(
      `SELECT count(*)::int AS total FROM ${schema}.${RENDEZVOUS_TABLE} WHERE label = $1`, [label],
    );
    if (Number(result.rows[0].total) >= 2) return Number(result.rows[0].total);
    if (Date.now() > deadline) throw new Error(`RENDEZVOUS_TIMEOUT:${label}:${executorId}`);
    await new Promise((resolve) => { setTimeout(resolve, 20); });
  }
}

// ---------------------------------------------------------------------------
// PHASE: setup
// ---------------------------------------------------------------------------
async function phaseSetup(executor) {
  const owner = principalOf(P.owner, 'owner');
  const transport = scriptedTransport(executor, A.race.alpha, WS.race);
  await executor.call('setup.register-alpha', 'adapters.register', { registration: transport.registration }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.race,
  });
  const alt = createTestTransport({
    script: {},
    clock: { now: executor.clock },
    ids: executor.boundaryIds,
    provenance: {
      adapter_id: A.race.alt,
      workspace_id: WS.race,
      principal_id: P.producer,
      declared_capabilities: ['source.read'],
      declared_tools: ['tool:fs.read'],
      sandbox_profile_id: PROVEN_PROFILE,
      health: 'healthy',
      display_name: `S2-007 db replay transport ${A.race.alt}`,
      detail: 'S2-007 PostgreSQL replay fixture: the second authorized executor',
    },
  });
  await executor.call('setup.register-alt', 'adapters.register', { registration: alt.registration }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.race,
  });
  for (const taskId of [T.contested, T.perRun.a, T.perRun.b]) {
    await executor.call(`setup.create.${taskId}`, 'tasks.create', {
      task: taskDocument(taskId, WS.race, { title: `S2-007 db replay ${taskId.slice(8)}` }),
    }, { principal: owner, actorKind: 'human_owner', workspaceId: WS.race });
    const task = await executor.readTask(taskId, WS.race, owner);
    await executor.transition({
      step: `setup.ready.${taskId}`,
      task,
      toState: 'READY',
      workspaceId: WS.race,
      principal: owner,
      actorKind: 'human_owner',
      reason: 'fixture: immutable brief validated, dependencies closed, numeric budget assigned',
    });
    await executor.call(`setup.grant.${taskId}`, 'budget.grant', { grant: budgetGrant(taskId, WS.race) }, {
      principal: owner, actorKind: 'human_owner', workspaceId: WS.race,
    });
  }
  return { seeded: [T.contested, T.perRun.a, T.perRun.b], adapters: [A.race.alpha, A.race.alt] };
}

// ---------------------------------------------------------------------------
// PHASE: contended — two processes, one database, one lease
// ---------------------------------------------------------------------------
async function phaseContended(executor, { barrierDir }) {
  const letter = executor.label;
  const own = principalOf(letter === 'a' ? P.execA : P.execB, 'scheduler');
  const owner = principalOf(P.owner, 'owner');
  const scheduler = principalOf(P.scheduler, 'scheduler');
  const transport = scriptedTransport(executor, A.race.alpha, WS.race);
  const observations = { barrierDir, label: letter };

  // --- 1. two processes, ONE task, at the same time -------------------------
  await arriveAtBarrier(barrierDir, 'race', executor.executorId);
  await rendezvous(executor.pool, executor.schema, 'race', executor.executorId);
  const contestedBefore = await executor.readTask(T.contested, WS.race, owner);
  const claim = await executor.call('contended.claim-contested', 'tasks.claim', {
    task_id: T.contested,
    adapter_id: A.race.alpha,
    expected_revision: contestedBefore.revision,
    ttl_ms: 600000,
  }, { principal: own, actorKind: 'scheduler', workspaceId: WS.race, transport, adapters: [transport.registration] });
  observations.contestedClaim = {
    outcome: claim.record.outcome,
    code: claim.record.code ?? null,
    typed: claim.record.typed,
    presented_revision: contestedBefore.revision,
    lease_id: claim.data?.lease?.lease_id ?? claim.data?.lease_id ?? null,
    fencing_token: claim.data?.lease?.fencing_token ?? claim.data?.fencing_token ?? null,
  };

  // --- 2. two processes, TWO different tasks, one active lease --------------
  await arriveAtBarrier(barrierDir, 'bound', executor.executorId);
  await rendezvous(executor.pool, executor.schema, 'bound', executor.executorId);
  const ownTaskId = letter === 'a' ? T.perRun.a : T.perRun.b;
  const ownBefore = await executor.readTask(ownTaskId, WS.race, owner);
  const bounded = await executor.call('contended.claim-own-task', 'tasks.claim', {
    task_id: ownTaskId,
    adapter_id: A.race.alpha,
    expected_revision: ownBefore.revision,
    ttl_ms: 600000,
  }, { principal: scheduler, actorKind: 'scheduler', workspaceId: WS.race, transport, adapters: [transport.registration] });
  observations.boundedClaim = {
    task_id: ownTaskId,
    outcome: bounded.record.outcome,
    code: bounded.record.code ?? null,
    lease_id: bounded.data?.lease_id ?? null,
  };

  // --- 3. the SAME idempotency key from both processes ----------------------
  await arriveAtBarrier(barrierDir, 'idem', executor.executorId);
  await rendezvous(executor.pool, executor.schema, 'idem', executor.executorId);
  // The key AND the actor are identical on purpose: a different actor would
  // change the canonical argument digest and turn a replay into a conflict,
  // which is a different property. The identity that must differ here is the
  // PROCESS, and the process identity is the pid and this executor id.
  const sharedKey = key('s2-007-db-contended-shared', 'tasks.create', { task: T.idem }, P.owner);
  const shared = await executor.call('contended.create-shared-key', 'tasks.create', {
    task: taskDocument(T.idem, WS.race, { title: 'S2-007 db replay shared idempotency key' }),
  }, { principal: owner, actorKind: 'human_owner', workspaceId: WS.race, idempotencyKey: sharedKey });
  observations.sharedIdempotency = {
    idempotency_key: sharedKey,
    outcome: shared.record.outcome,
    replayed: shared.record.replayed === true,
    code: shared.record.code ?? null,
    typed: shared.record.typed,
    revision: shared.record.revision ?? null,
  };
  // A race loser may not be able to REPLAY: its ledger read happens before the
  // winner commits, and the primary key on the task id then refuses the second
  // insert. That refusal is the correct fail-closed outcome — nothing is
  // written twice — so BOTH are recorded and the COUNT in SQL is the verdict.
  // The replay path is then proved deterministically, from the same process,
  // against the committed ledger.
  observations.sharedIdempotencySettled = await sharedIdempotencySettled(executor, sharedKey, letter);

  return observations;
}

/** The row counts that decide "the same key yielded ONE record". */
async function countSharedKeyRows(executor, sharedKey) {
  const task = await executor.pool.query(
    `SELECT count(*)::int AS total FROM ${executor.schema}.agentboard_task WHERE task_id = $1`, [T.idem],
  );
  const operation = await executor.pool.query(
    `SELECT count(*)::int AS total FROM ${executor.schema}.agentboard_operation WHERE idempotency_key = $1`, [sharedKey],
  );
  const audit = await executor.pool.query(
    `SELECT count(*)::int AS total FROM ${executor.schema}.agentboard_audit WHERE idempotency_key = $1`, [sharedKey],
  );
  return {
    tasks: Number(task.rows[0].total),
    operations: Number(operation.rows[0].total),
    audit: Number(audit.rows[0].total),
  };
}

/**
 * The deterministic half of the shared-key proof, read AFTER the race: the same
 * command with the same key is issued again. It must replay the committed
 * result, or be refused with a typed conflict, and in both cases the counts
 * must be unchanged.
 */
async function sharedIdempotencySettled(executor, sharedKey, letter) {
  const owner = principalOf(P.owner, 'owner');
  const before = await countSharedKeyRows(executor, sharedKey);
  const retry = await executor.call('contended.replay-shared-key', 'tasks.create', {
    task: taskDocument(T.idem, WS.race, { title: 'S2-007 db replay shared idempotency key' }),
  }, { principal: owner, actorKind: 'human_owner', workspaceId: WS.race, idempotencyKey: sharedKey });
  const after = await countSharedKeyRows(executor, sharedKey);
  // The COMMITTED revision, read back through the boundary. A retry that
  // answers with THIS revision answered from the ledger; a retry that created
  // anything would report a second revision, which is what the row counts and
  // this number jointly rule out.
  const committed = await executor.readTask(T.idem, WS.race, owner);
  return {
    letter,
    idempotency_key: sharedKey,
    outcome: retry.record.outcome,
    replayed: retry.record.replayed === true,
    code: retry.record.code ?? null,
    typed: retry.record.typed,
    reported_revision: retry.record.revision ?? null,
    committed_revision: committed.revision,
    rows_before: before,
    rows_after: after,
    one_record: before.tasks === 1 && after.tasks === 1 && before.operations === 1 && after.operations === 1,
    nothing_written_twice: JSON.stringify(before) === JSON.stringify(after),
    answeredTheCommittedResult: retry.record.outcome === 'ACCEPT'
      && Number(retry.record.revision) === Number(committed.revision),
  };
}

// ---------------------------------------------------------------------------
// PHASE: scenario — the deterministic, comparable lifecycle
// ---------------------------------------------------------------------------
async function phaseScenario(executor) {
  const owner = principalOf(P.owner, 'owner');
  const reviewer = principalOf(P.reviewer, 'reviewer');
  const scheduler = principalOf(P.scheduler, 'scheduler');
  const producer = principalOf(P.producer, 'producer');
  const transport = scriptedTransport(executor, A.scenario.alpha, WS.scenario);
  const registration = transport.registration;
  const altRegistration = scriptedTransport(executor, A.scenario.alt, WS.scenario).registration;
  const workspaces = [];
  const sql = {};

  await executor.call('scenario.register-alpha', 'adapters.register', { registration }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.scenario,
  });
  await executor.call('scenario.register-alt', 'adapters.register', { registration: altRegistration }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.scenario,
  });

  const ready = async (taskId) => {
    await executor.call(`scenario.create.${taskId}`, 'tasks.create', {
      task: taskDocument(taskId, WS.scenario, { title: `S2-007 db scenario ${taskId.slice(8)}` }),
    }, { principal: owner, actorKind: 'human_owner', workspaceId: WS.scenario });
    const task = await executor.readTask(taskId, WS.scenario, owner);
    await executor.transition({
      step: `scenario.ready.${taskId}`,
      task,
      toState: 'READY',
      workspaceId: WS.scenario,
      principal: owner,
      actorKind: 'human_owner',
      reason: 'fixture: immutable brief validated, dependencies closed, numeric budget assigned',
    });
    await executor.call(`scenario.grant.${taskId}`, 'budget.grant', { grant: budgetGrant(taskId, WS.scenario) }, {
      principal: owner, actorKind: 'human_owner', workspaceId: WS.scenario,
    });
  };

  // --- 1. the full lifecycle, approved by an authenticated human ------------
  await ready(T.s1);
  const start = await executor.call('scenario.start', 'execution.start', { task_id: T.s1, adapter_id: A.scenario.alpha }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario, transport, adapters: [registration, altRegistration],
  });
  const run = start.data?.run ?? null;
  if (run === null) throw new Error(`SCENARIO_START_REFUSED:${start.record.code ?? ''}:${start.record.message ?? ''}`);
  const shim = outboxShim(executor, transport, { runId: run.run_id, workspaceId: WS.scenario });
  // ONE key, presented twice: the first call crosses the boundary, the second
  // must be answered from the committed ledger with `replayed: true` and must
  // NOT issue a second effect. This is the deterministic half of the
  // idempotency proof; the concurrent half is the shared-key race.
  const dispatchKey = key('s2007db-scenario', 'outbox.dispatch', { step: 'scenario.dispatch', workspace_id: WS.scenario }, P.scheduler);
  const dispatch = await executor.call('scenario.dispatch', 'outbox.dispatch', { workspace_id: WS.scenario }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario, transport: shim,
    adapters: [registration, altRegistration], idempotencyKey: dispatchKey,
  });
  const effectsAfterFirstDispatch = executor.effects.length;
  const outboxAfterFirstDispatch = await countRows(
    executor.pool, executor.schema, 'agentboard_outbox', 'WHERE workspace_id = $1', [WS.scenario],
  );
  const dispatchReplay = await executor.call('scenario.dispatch-replay', 'outbox.dispatch', { workspace_id: WS.scenario }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario, transport: shim,
    adapters: [registration, altRegistration], idempotencyKey: dispatchKey,
  });
  // The SECOND dispatch of the same key is answered from the committed state:
  // no second boundary crossing, no second row. `outbox.dispatch` derives its
  // ledger keys per STAGE inside the driver, so the caller's key is not itself
  // in the ledger and the replay flag is not the evidence here — the effect
  // count and the row count are (see `interfaceObservations`).
  executor.checks.idempotentReplayWasAccepted = dispatchReplay.record.outcome === 'ACCEPT';
  executor.checks.idempotentReplayIssuedNoSecondEffect = executor.effects.length === effectsAfterFirstDispatch;
  executor.checks.idempotentReplayWroteNoSecondRow = await countRows(
    executor.pool, executor.schema, 'agentboard_outbox', 'WHERE workspace_id = $1', [WS.scenario],
  ) === outboxAfterFirstDispatch;
  await executor.call('scenario.event', 'execution.event', {
    run_id: run.run_id, event: eventDocument({ run, sequence: 1, instant: executor.instant() }),
  }, { principal: producer, actorKind: 'adapter', workspaceId: WS.scenario, transport, adapters: [registration, altRegistration] });
  await executor.call('scenario.collect', 'execution.collect_result', {
    run_id: run.run_id, result: resultDocument({ run, sequence: 2, instant: executor.instant() }),
  }, { principal: producer, actorKind: 'adapter', workspaceId: WS.scenario, transport, adapters: [registration, altRegistration] });
  const inReview = await executor.readTask(T.s1, WS.scenario, owner);
  // The producer may not approve its own work: the refusal is the independence
  // guarantee, so it is attempted on purpose.
  const selfApproval = await executor.transition({
    step: 'scenario.approve-by-producer',
    task: inReview,
    toState: 'DONE',
    workspaceId: WS.scenario,
    principal: producer,
    actorKind: 'adapter',
    reason: 'the producer asserts that its own output is correct',
    observation: `guard:self-approval-attempt:${T.s1}:IN_REVIEW->DONE`,
  });
  await executor.transition({
    step: 'scenario.approve-by-human',
    task: inReview,
    toState: 'DONE',
    workspaceId: WS.scenario,
    principal: reviewer,
    actorKind: 'human_reviewer',
    reason: 'independent human review confirmed the bound brief, policy and manifest digests',
  });
  await executor.call('scenario.settle', 'budget.settle', {
    grant_id: `grt-${T.s1.slice(4)}`, operation_id: `op-${T.s1.slice(4)}`, task_id: T.s1, amount: 0.25, currency: 'USD', day_key: CLOCK_DAY,
  }, { principal: owner, actorKind: 'human_owner', workspaceId: WS.scenario });

  // --- 2. the reassigned fence: the old one changes nothing -----------------
  await ready(T.s2);
  const claim2 = await executor.call('scenario.claim-s2', 'tasks.claim', {
    task_id: T.s2, adapter_id: A.scenario.alpha, expected_revision: (await executor.readTask(T.s2, WS.scenario, owner)).revision, ttl_ms: 600000,
  }, { principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario, transport, adapters: [registration, altRegistration] });
  const oldLease = claim2.data?.lease_id ?? claim2.data?.lease?.lease_id ?? null;
  const oldFence = Number(claim2.data?.lease?.fencing_token ?? claim2.data?.fencing_token ?? 0);
  const reassign = await executor.call('scenario.reassign-s2', 'tasks.lease.reassign', {
    lease_id: oldLease, fencing_token: oldFence, new_adapter_id: A.scenario.alt, reason: 'fixture: the first executor is withdrawn',
  }, { principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario });
  const newLease = reassign.data?.lease_id ?? reassign.data?.lease?.lease_id ?? null;
  // The new fence is read from the committed LEASE, never from the command
  // response: `tasks.lease.reassign` fills its `fencing_token` field from the
  // ADAPTER registration, so that field is NaN (see the report's
  // `interfaceObservations`). The lease row is the authority for the fence.
  const newFence = Number(reassign.data?.lease?.fencing_token ?? reassign.data?.task?.fencing_token ?? 0);
  executor.checks.reassignedFenceComesFromTheLease = Number.isFinite(newFence) && newFence > oldFence;
  const beforeStale = await workspaceDigest(executor.pool, executor.schema, WS.scenario);
  await executor.call('scenario.stale-renew-s2', 'tasks.lease.renew', { lease_id: oldLease, fencing_token: oldFence, ttl_ms: 600000 }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario,
  });
  await executor.call('scenario.stale-release-s2', 'tasks.lease.release', { lease_id: oldLease, fencing_token: oldFence, reason: 'fixture: the withdrawn executor tries to release' }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario,
  });
  const afterStale = await workspaceDigest(executor.pool, executor.schema, WS.scenario);
  executor.checks.staleFenceAfterReassignChangesNothing = beforeStale === afterStale;
  // The fence, not a blanket refusal: the CURRENT lease of the same task still
  // works after the reassignment.
  const liveRenew = await executor.call('scenario.live-renew-s2', 'tasks.lease.renew', { lease_id: newLease, fencing_token: newFence, ttl_ms: 600000 }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario,
  });
  executor.checks.currentFenceStillAccepted = liveRenew.record.outcome === 'ACCEPT';
  await executor.call('scenario.revoke-s2', 'tasks.lease.revoke', { lease_id: newLease, fencing_token: newFence, reason: 'fixture: the reassigned right is withdrawn' }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario,
  });

  // --- 3. the expired fence: the DATABASE clock decides --------------------
  await ready(T.s3);
  const claim3 = await executor.call('scenario.claim-s3', 'tasks.claim', {
    task_id: T.s3, adapter_id: A.scenario.alpha, expected_revision: (await executor.readTask(T.s3, WS.scenario, owner)).revision, ttl_ms: 1,
  }, { principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario, transport, adapters: [registration, altRegistration] });
  const expiredLease = claim3.data?.lease_id ?? claim3.data?.lease?.lease_id ?? null;
  const expiredFence = Number(claim3.data?.lease?.fencing_token ?? claim3.data?.fencing_token ?? 0);
  // No command exposes the sweep (see the report's `interfaceObservations`),
  // so it is called on the store, which is the documented tier for it and the
  // only place where the DATABASE clock is read.
  await new Promise((resolve) => { setTimeout(resolve, 60); });
  // The sweep is asked by a store whose injected clock says 1970 — "nothing has
  // ever expired". It still expires the lease, because the DECISION is read from
  // the database clock and the injected instant is only a request marker. The
  // converse is checked on the live lease of s4 below, so neither clock can
  // quietly become the decision input.
  const preSweep = new PostgresAgentBoardStore({
    pool: executor.pool, clock: fixedClock('1970-01-01T00:00:00.000Z'), ids: executor.storeIds, seed: executor.store.seed,
  });
  const sweep = await preSweep.expireLeases({ actor: P.sweeper, now: '1970-01-01T00:00:00.000Z' });
  const expiredRow = (await executor.pool.query(
    `SELECT lease_state FROM ${executor.schema}.agentboard_lease WHERE lease_id = $1`, [expiredLease],
  )).rows[0];
  const sweepNow = String(sweep?.now ?? '');
  const sweepRequested = String(sweep?.requested_at ?? '');
  executor.checks.expiredLeaseObservedExpired = expiredRow?.lease_state === 'EXPIRED';
  // The request marker is the injected 1970 instant; the DECISION instant is
  // the database clock. Both are asserted, so neither clock can quietly become
  // the decision input.
  executor.checks.sweepIgnoredTheInjectedClock = expiredRow?.lease_state === 'EXPIRED'
    && Number.isFinite(Date.parse(sweepNow))
    && sweepNow !== '1970-01-01T00:00:00.000Z'
    && sweepRequested.startsWith('1970-01-01T00:00:00.000Z');
  const beforeExpiryStale = await workspaceDigest(executor.pool, executor.schema, WS.scenario);
  await executor.call('scenario.stale-renew-s3', 'tasks.lease.renew', { lease_id: expiredLease, fencing_token: expiredFence, ttl_ms: 600000 }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario,
  });
  await executor.call('scenario.stale-release-s3', 'tasks.lease.release', { lease_id: expiredLease, fencing_token: expiredFence, reason: 'fixture: the expired executor tries to release' }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario,
  });
  const afterExpiryStale = await workspaceDigest(executor.pool, executor.schema, WS.scenario);
  executor.checks.staleFenceAfterExpiryChangesNothing = beforeExpiryStale === afterExpiryStale;

  // --- 4. the cancelled fence ----------------------------------------------
  await ready(T.s4);
  const claim4 = await executor.call('scenario.claim-s4', 'tasks.claim', {
    task_id: T.s4, adapter_id: A.scenario.alpha, expected_revision: (await executor.readTask(T.s4, WS.scenario, owner)).revision, ttl_ms: 600000,
  }, { principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario, transport, adapters: [registration, altRegistration] });
  const cancelledLease = claim4.data?.lease_id ?? claim4.data?.lease?.lease_id ?? null;
  const cancelledFence = Number(claim4.data?.lease?.fencing_token ?? claim4.data?.fencing_token ?? 0);
  // The converse of the 1970 sweep: a store whose injected clock says 2099 —
  // "everything expired long ago" — must NOT expire a lease the DATABASE clock
  // still considers live. A sweep that read the process or injected clock would
  // revoke a right that is still valid.
  const futureSweepStore = new PostgresAgentBoardStore({
    pool: executor.pool, clock: fixedClock('2099-01-01T00:00:00.000Z'), ids: executor.storeIds, seed: executor.store.seed,
  });
  const futureSweep = await futureSweepStore.expireLeases({ actor: P.sweeper, now: '2099-01-01T00:00:00.000Z' });
  const liveRow = (await executor.pool.query(
    `SELECT lease_state FROM ${executor.schema}.agentboard_lease WHERE lease_id = $1`, [cancelledLease],
  )).rows[0];
  // The converse of the 1970 sweep: a request marked 2099 must not expire a
  // lease the DATABASE clock still considers live, and the decision instant
  // must still be the database's.
  executor.checks.sweepFollowedTheDatabaseClock = liveRow?.lease_state === 'ACTIVE'
    && !String(futureSweep?.now ?? '').startsWith('2099-')
    && String(futureSweep?.requested_at ?? '').startsWith('2099-');
  await executor.call('scenario.cancel-s4', 'tasks.cancel', { task_id: T.s4, reason: 'fixture: the owner withdraws the task' }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.scenario,
  });
  const beforeCancelStale = await workspaceDigest(executor.pool, executor.schema, WS.scenario);
  await executor.call('scenario.stale-renew-s4', 'tasks.lease.renew', { lease_id: cancelledLease, fencing_token: cancelledFence, ttl_ms: 600000 }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario,
  });
  await executor.call('scenario.stale-release-s4', 'tasks.lease.release', { lease_id: cancelledLease, fencing_token: cancelledFence, reason: 'fixture: the cancelled executor tries to release' }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.scenario,
  });
  const afterCancelStale = await workspaceDigest(executor.pool, executor.schema, WS.scenario);
  executor.checks.staleFenceAfterCancelChangesNothing = beforeCancelStale === afterCancelStale;

  // --- 5. the reads a deployment would make --------------------------------
  const outboxList = await executor.call('scenario.read-outbox', 'outbox.list', { workspace_id: WS.scenario }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.scenario,
  });
  const auditList = await executor.call('scenario.read-audit', 'audit.list', { workspace_id: WS.scenario, limit: 200 }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.scenario,
  });
  const taskList = await executor.call('scenario.read-tasks', 'tasks.list', { workspace_id: WS.scenario }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.scenario,
  });

  const finalStates = {};
  for (const taskId of [T.s1, T.s2, T.s3, T.s4]) {
    const task = await executor.readTask(taskId, WS.scenario, owner);
    finalStates[taskId] = { state: task.state, revision: task.revision, active_lease_id: task.active_lease_id, fencing_token: task.fencing_token };
  }
  // The expected states, revisions and row counts are NOT declared here. They
  // live in ONE table in the coordinator, which checks BOTH runs against it —
  // a per-run self-check plus a coordinator check would be two declarations of
  // the same truth, and two declarations are exactly what the contract forbids.
  executor.checks.producerCannotApproveItsOwnRun = selfApproval.record.outcome === 'REFUSE';
  executor.checks.dispatchIssuedExactlyOneEffect = executor.effects.length === 1;
  executor.checks.dispatchAcked = dispatch.data?.summary?.acked === 1;

  for (const taskId of [T.s1, T.s2, T.s3, T.s4]) workspaces.push(taskId);
  Object.assign(sql, {
    tasks: await countRows(executor.pool, executor.schema, 'agentboard_task', 'WHERE workspace_id = $1', [WS.scenario]),
    leases: await countRows(executor.pool, executor.schema, 'agentboard_lease', 'WHERE workspace_id = $1', [WS.scenario]),
    active_leases: await countRows(executor.pool, executor.schema, 'agentboard_lease', "WHERE workspace_id = $1 AND lease_state = 'ACTIVE'", [WS.scenario]),
    runs: await countRows(executor.pool, executor.schema, 'agentboard_run', 'WHERE workspace_id = $1', [WS.scenario]),
    transitions: await countRows(executor.pool, executor.schema, 'agentboard_transition', 'WHERE workspace_id = $1', [WS.scenario]),
    audit: await countRows(executor.pool, executor.schema, 'agentboard_audit', 'WHERE workspace_id = $1', [WS.scenario]),
    outbox: await countRows(executor.pool, executor.schema, 'agentboard_outbox', 'WHERE workspace_id = $1', [WS.scenario]),
    outbox_acked: await countRows(executor.pool, executor.schema, 'agentboard_outbox', "WHERE workspace_id = $1 AND dispatch_state = 'ACKED'", [WS.scenario]),
    operations: await countRows(executor.pool, executor.schema, 'agentboard_operation', 'WHERE workspace_id = $1', [WS.scenario]),
    spend_rows: await countRows(executor.pool, executor.schema, 'agentboard_budget_spend', 'WHERE workspace_id = $1', [WS.scenario]),
  });

  return {
    workspace_id: WS.scenario,
    tasks: workspaces,
    finalStates,
    readBack: {
      outbox_rows: outboxList.data?.outbox?.length ?? null,
      audit_rows: auditList.data?.audit?.length ?? null,
      task_rows: taskList.data?.tasks?.length ?? null,
    },
    sql,
    digest: await workspaceDigest(executor.pool, executor.schema, WS.scenario),
    rawDigest: await rawWorkspaceDigest(executor.pool, executor.schema, WS.scenario),
  };
}

// ---------------------------------------------------------------------------
// PHASE: crash — SIGKILL after the outbox SEND, before the result
// ---------------------------------------------------------------------------
async function phaseCrash(executor, { handoffFile, effectLog }) {
  const owner = principalOf(P.owner, 'owner');
  const scheduler = principalOf(P.scheduler, 'scheduler');
  const producer = principalOf(P.producer, 'producer');
  const transport = scriptedTransport(executor, A.crash.alpha, WS.crash);

  await executor.call('crash.register', 'adapters.register', { registration: transport.registration }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.crash,
  });
  await executor.call('crash.create', 'tasks.create', {
    task: taskDocument(T.crash, WS.crash, { title: 'S2-007 db crash fixture' }),
  }, { principal: owner, actorKind: 'human_owner', workspaceId: WS.crash });
  const task = await executor.readTask(T.crash, WS.crash, owner);
  await executor.transition({
    step: 'crash.ready',
    task,
    toState: 'READY',
    workspaceId: WS.crash,
    principal: owner,
    actorKind: 'human_owner',
    reason: 'fixture: immutable brief validated, dependencies closed, numeric budget assigned',
  });
  await executor.call('crash.grant', 'budget.grant', { grant: budgetGrant(T.crash, WS.crash) }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.crash,
  });
  const start = await executor.call('crash.start', 'execution.start', { task_id: T.crash, adapter_id: A.crash.alpha }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.crash, transport, adapters: [transport.registration],
  });
  const run = start.data?.run ?? null;
  if (run === null) throw new Error(`CRASH_START_REFUSED:${start.record.code ?? ''}:${start.record.message ?? ''}`);

  fs.writeFileSync(handoffFile, `${JSON.stringify({
    run_id: run.run_id,
    task_id: run.task_id,
    lease_id: run.lease_id,
    fencing_token: Number(run.fencing_token),
    crash_pid: process.pid,
    crash_executor_id: executor.executorId,
    effect_log: effectLog,
  }, null, 2)}\n`, 'utf8');
  // The effect log belongs to this process: it is truncated here so the count
  // the recovery process reads is THIS run's count, never an earlier one's.
  if (effectLog !== null) fs.writeFileSync(effectLog, '', 'utf8');

  // The transport is the boundary. It issues the effect, records that it did,
  // and then the PROCESS dies: no acknowledgement, no result, no report. The
  // only thing that survives is what PostgreSQL already committed.
  const shim = outboxShim(executor, transport, {
    runId: run.run_id,
    workspaceId: WS.crash,
    effectLog,
    onSend: () => { process.kill(process.pid, 'SIGKILL'); },
  });
  await executor.call('crash.dispatch', 'outbox.dispatch', { workspace_id: WS.crash }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.crash, transport: shim, adapters: [transport.registration],
  });
  // Unreachable by design: the SIGKILL above lands inside the transport.
  await executor.call('crash.collect-should-not-happen', 'execution.collect_result', {
    run_id: run.run_id, result: resultDocument({ run, sequence: 2, instant: executor.instant() }),
  }, { principal: producer, actorKind: 'adapter', workspaceId: WS.crash, transport, adapters: [transport.registration] });
  throw new Error('CRASH_PROCESS_SURVIVED:the crashing process was supposed to be SIGKILLed at the boundary');
}

// ---------------------------------------------------------------------------
// PHASE: recover — a NEW process, no side effect, canonical state restored
// ---------------------------------------------------------------------------
async function phaseRecover(executor, { handoffFile }) {
  const handoff = JSON.parse(fs.readFileSync(handoffFile, 'utf8'));
  const owner = principalOf(P.owner, 'owner');
  const scheduler = principalOf(P.scheduler, 'scheduler');
  const reviewer = principalOf(P.reviewer, 'reviewer');
  const transport = scriptedTransport(executor, A.crash.alpha, WS.crash);
  const effectLog = handoff.effect_log;
  const effectsIssued = () => (fs.existsSync(effectLog)
    ? fs.readFileSync(effectLog, 'utf8').split('\n').filter((line) => line.trim() !== '').length
    : 0);

  const checks = {};
  // 1. What the crashed process actually committed: the SEND is recorded, the
  //    result is not, and the effect crossed the boundary exactly once.
  const outboxBefore = (await executor.pool.query(
    `SELECT outbox_id, dispatch_state, attempts, last_error FROM ${executor.schema}.agentboard_outbox
     WHERE workspace_id = $1 AND run_id = $2 ORDER BY 1`, [WS.crash, handoff.run_id],
  )).rows;
  const runBefore = (await executor.pool.query(
    `SELECT run_state, last_sequence, result_payload FROM ${executor.schema}.agentboard_run WHERE run_id = $1`, [handoff.run_id],
  )).rows[0];
  checks.sentRowCommitted = outboxBefore.some((row) => row.dispatch_state === 'SENT');
  checks.noResultCommitted = runBefore !== undefined && runBefore.result_payload === null;
  checks.effectsIssuedExactlyOnce = effectsIssued() === 1;
  checks.crashedPidIsNotThisProcess = handoff.crash_pid !== process.pid;
  checks.recoveryIsANewProcess = handoff.crash_executor_id !== executor.executorId;

  // 2. A new store over the same committed contents is a RESTART: the state it
  //    reads is the state that was written, not an in-process snapshot.
  const restarted = new PostgresAgentBoardStore({
    pool: executor.pool, clock: { now: executor.clock }, ids: executor.storeIds, seed: executor.store.seed,
  });
  const seen = await restarted.listOutbox({ workspaceId: WS.crash, dispatchState: 'SENT', principalId: P.scheduler });
  checks.restartObservesTheSentRow = Array.isArray(seen) && seen.length === 1 && seen[0].outbox_id === outboxBefore[0].outbox_id;

  // 3. Recovery reconstructs the canonical state and reissues NOTHING. The
  //    outbox recovery command requires the task-transition scope, so the
  //    authorized recovery principal is the one that holds it.
  const recover = await executor.call('recover.outbox', 'outbox.recover', { workspace_id: WS.crash, limit: 10 }, {
    principal: principalOf(P.sweeper, 'sweeper'), actorKind: 'scheduler', workspaceId: WS.crash,
  });
  const summary = recover.data?.summary ?? {};
  checks.recoveryEscalatedTheSentRow = summary.escalated === 1;
  checks.recoveryIssuedNoEffect = summary.externalEffectsIssued === 0;
  checks.effectsStillIssuedExactlyOnce = effectsIssued() === 1;

  // 4. A blind retry of the dispatch finds nothing to send.
  const blind = await executor.call('recover.blind-retry', 'outbox.dispatch', { workspace_id: WS.crash, limit: 10 }, {
    principal: scheduler, actorKind: 'scheduler', workspaceId: WS.crash,
    transport: outboxShim(executor, transport, { runId: handoff.run_id, workspaceId: WS.crash, effectLog }),
  });
  checks.blindRetryDispatchedNothing = (blind.data?.summary?.inspected ?? -1) === 0;
  checks.blindRetryIssuedNoEffect = (blind.data?.summary?.externalEffectsIssued ?? -1) === 0;
  checks.effectsIssuedAfterBlindRetry = effectsIssued();

  // 5. The run never claims a success it did not observe, and the unknown
  //    outcome is in the append-only journal.
  const runAfter = (await executor.pool.query(
    `SELECT run_state, last_sequence FROM ${executor.schema}.agentboard_run WHERE run_id = $1`, [handoff.run_id],
  )).rows[0];
  const events = (await executor.pool.query(
    `SELECT event_type, outcome FROM ${executor.schema}.agentboard_execution_event WHERE run_id = $1 ORDER BY sequence`, [handoff.run_id],
  )).rows;
  checks.runIsReconciliationRequired = runAfter?.run_state === 'RECONCILIATION_REQUIRED';
  checks.unknownOutcomeIsJournalled = events.some((row) => row.event_type === 'UNKNOWN' && row.outcome === 'RECONCILIATION_REQUIRED');

  // 6. A result may not be collected over an undetermined effect, not even by
  //    the producer that ran it.
  const lateResult = await executor.call('recover.late-result', 'execution.collect_result', {
    run_id: handoff.run_id, result: resultDocument({ run: { ...handoff, workspace_id: WS.crash }, sequence: 1, instant: executor.instant() }),
  }, { principal: principalOf(P.producer, 'producer'), actorKind: 'adapter', workspaceId: WS.crash, transport, adapters: [transport.registration] });
  checks.lateResultRefused = lateResult.record.outcome === 'REFUSE' && lateResult.record.typed === true;
  checks.lateResultCode = lateResult.record.code ?? null;

  // 7. Only an authenticated human closes an unknown outcome.
  const byProducer = await executor.call('recover.reconcile-by-producer', 'reconciliation.record', {
    reconciliation: {
      reconciliation_id: 'rec-s2007-db-producer', workspace_id: WS.crash, task_id: handoff.task_id, run_id: handoff.run_id,
      resolution: 'OBSERVED_EFFECT_COMPLETED', detail: 'the producer may never close its own unknown outcome', evidence_ref: null,
    },
  }, { principal: principalOf(P.producer, 'producer'), actorKind: 'adapter', workspaceId: WS.crash });
  checks.producerCannotCloseItsOwnOutcome = byProducer.record.outcome === 'REFUSE' && byProducer.record.typed === true;

  const reconciliation = await executor.call('recover.reconcile-by-human', 'reconciliation.record', {
    reconciliation: {
      reconciliation_id: 'rec-s2007-db-human', workspace_id: WS.crash, task_id: handoff.task_id, run_id: handoff.run_id,
      resolution: 'OBSERVED_EFFECT_COMPLETED', detail: 'fixture: an authenticated human observed the effect as completed', evidence_ref: null,
    },
  }, { principal: reviewer, actorKind: 'human_reviewer', workspaceId: WS.crash });
  checks.humanReconciliationAccepted = reconciliation.record.outcome === 'ACCEPT';
  const cancel = await executor.call('recover.cancel', 'execution.cancel', { run_id: handoff.run_id, reason: 'fixture: the reconciled run is withdrawn' }, {
    principal: owner, actorKind: 'human_owner', workspaceId: WS.crash,
  });
  checks.cancelAccepted = cancel.record.outcome === 'ACCEPT';

  const finalTask = (await executor.pool.query(
    `SELECT state, revision FROM ${executor.schema}.agentboard_task WHERE task_id = $1`, [handoff.task_id],
  )).rows[0];
  const escalation = (await executor.pool.query(
    `SELECT dispatch_state, attempts, last_error FROM ${executor.schema}.agentboard_outbox WHERE outbox_id = $1`,
    [outboxBefore[0].outbox_id],
  )).rows[0];
  const sql = {
    reconciliations: await countRows(executor.pool, executor.schema, 'agentboard_reconciliation', 'WHERE workspace_id = $1', [WS.crash]),
    events: await countRows(executor.pool, executor.schema, 'agentboard_execution_event', 'WHERE workspace_id = $1', [WS.crash]),
    effects_issued: effectsIssued(),
  };
  checks.outboxStaysReconciliationRequired = escalation?.dispatch_state === 'RECONCILIATION_REQUIRED';
  // The send-attempt counter must not move: recovery escalates, it never re-sends.
  checks.outboxAttemptCountUnchanged = Number(escalation?.attempts) === Number(outboxBefore[0].attempts);
  checks.reconciliationRecordedOnce = sql.reconciliations === 1;

  return {
    handoff,
    checks,
    codes: {
      lateResult: lateResult.record.code ?? null,
      reconcileByProducer: byProducer.record.code ?? null,
    },
    observed: {
      outbox_before: outboxBefore,
      outbox_after: escalation,
      run_before: { run_state: runBefore?.run_state ?? null, result_payload_present: runBefore?.result_payload !== null },
      run_after: runAfter,
      events,
      final_task: finalTask,
    },
    sql,
    recovery_summary: {
      escalated: summary.escalated ?? null,
      journal_appended: summary.journalAppended ?? null,
      external_effects_issued: summary.externalEffectsIssued ?? null,
    },
  };
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
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

const args = parseArgs(process.argv);
const phase = args.phase;
const connectionString = process.env.VERITAS_S2_007_DB_URL;
if (!connectionString) {
  console.error('executor requires VERITAS_S2_007_DB_URL');
  process.exit(3);
}
if (!['setup', 'contended', 'scenario', 'crash', 'recover'].includes(phase)) {
  console.error(`unknown phase ${String(phase)}`);
  process.exit(3);
}
const schema = args.schema ?? 'public';
const idNamespace = args['id-namespace'] ?? args['executor-id'];
const pool = new Pool({
  connectionString,
  max: 3,
  connectionTimeoutMillis: 10000,
  options: `-c search_path=${schema} -c timezone=UTC`,
});
const executor = new Executor({
  pool,
  schema,
  executorId: args['executor-id'],
  runId: args['run-id'],
  idNamespace,
  phase,
  label: args.label ?? 'a',
  now: CLOCK_BASE,
});

let payload = null;
let exitCode = 0;
try {
  const server = (await pool.query('SELECT version() AS version, current_database() AS database, current_schema() AS schema')).rows[0];
  const identity = {
    phase,
    executor_id: executor.executorId,
    run_id: executor.runId,
    label: executor.label,
    pid: process.pid,
    schema,
    id_namespace: idNamespace,
    database_engine: 'PostgreSQL',
    server_version: server.version,
    database: server.database,
    observed_schema: server.schema,
    migration_count: await countRows(pool, schema, 'veritas_schema_migrations'),
  };
  if (phase === 'setup') payload = await phaseSetup(executor);
  else if (phase === 'contended') payload = await phaseContended(executor, { barrierDir: args['barrier-dir'] });
  else if (phase === 'scenario') payload = await phaseScenario(executor);
  else if (phase === 'crash') {
    await phaseCrash(executor, { handoffFile: args.handoff, effectLog: args['effect-log'] });
  } else if (phase === 'recover') {
    payload = await phaseRecover(executor, { handoffFile: args.handoff });
    // Every boolean check must hold, the effect COUNTER must be exactly one,
    // and the recorded refusal code must be a non-empty frozen typed code.
    const booleans = Object.entries(payload.checks)
      .filter(([name]) => name !== 'effectsIssuedAfterBlindRetry' && name !== 'lateResultCode');
    exitCode = booleans.every(([, value]) => value === true)
      && payload.checks.effectsIssuedAfterBlindRetry === 1
      && typeof payload.codes?.lateResult === 'string'
      && payload.codes.lateResult !== ''
      ? 0
      : 2;
  }
  const report = {
    schemaVersion: 1,
    ticket: 'S2-007',
    harness: 's2-007-db-replay-executor-v1',
    identity,
    checks: executor.checks,
    calls: executor.calls,
    effects_issued: executor.effects.length,
    phase_result: payload,
  };
  if (exitCode === 2) report.status = 'CHECKS_FAILED';
  fs.writeFileSync(args.out, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  if (phase === 'recover' && exitCode === 2) {
    await pool.end().catch(() => {});
    process.exit(2);
  }
  if (phase !== 'crash') await pool.end().catch(() => {});
  if (exitCode === 0) process.exit(0);
  process.exit(exitCode);
} catch (error) {
  const failure = {
    schemaVersion: 1,
    ticket: 'S2-007',
    harness: 's2-007-db-replay-executor-v1',
    phase,
    status: 'ERROR',
    executor_id: executor.executorId,
    run_id: executor.runId,
    schema,
    pid: process.pid,
    error: String(error?.message ?? error).slice(0, 800),
    stack: String(error?.stack ?? '').split('\n').slice(0, 8),
    calls: executor.calls,
    checks: executor.checks,
  };
  // A crashing process is given no --out on purpose (its death IS the
  // assertion), so a failure before the SIGKILL has nowhere to write a report
  // and must say so on stderr instead of failing on a second error.
  if (typeof args.out === 'string' && args.out !== '') {
    fs.writeFileSync(args.out, `${JSON.stringify(failure, null, 2)}\n`, 'utf8');
  } else {
    process.stderr.write(`${JSON.stringify(failure)}\n`);
  }
  await pool.end().catch(() => {});
  process.exit(2);
}
