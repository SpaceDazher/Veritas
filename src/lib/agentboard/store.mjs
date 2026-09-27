// S2-007 Agent Board store — the single persistence gate (spec §3.2).
//
// WHY this module exists
// ---------------------
// The board has exactly one source of truth for task state, and every change
// to it is evidence. A state change that is not accompanied, in the SAME
// transaction, by the append-only transition record, the audit record and the
// outbox row is a state change nobody can prove later. A write that is
// half-applied is worse than a write that was refused: it is a lie the board
// cannot detect. Therefore every write in this file is
//
//     BEGIN -> idempotency ledger check -> row locks -> compare-and-swap ->
//     entity + transition + audit + outbox -> operation marker -> COMMIT
//
// and a failure anywhere before COMMIT leaves the store byte-identical. The
// operation row is written LAST inside the transaction, so its presence is
// proof that everything before it committed with it.
//
// The two implementations below share one engine (`AgentBoardStoreBase`).
// That is deliberate: an in-memory store that "roughly" implements the same
// rules is a second, weaker, silently divergent authorization path. Here the
// ordering of the checks, the error codes and the idempotency semantics are
// literally the same code for both backends; only the unit-of-work primitive
// differs.
//
// Semantics that MUST NOT be "improved" later
// --------------------------------------------
//  * IDEMPOTENCY FIRST. `agentboard_operation` is consulted before any row
//    lock is taken. Same key + same args_digest -> the prior committed result
//    is returned with replayed:true and nothing is written. Same key +
//    different args_digest -> IdempotencyConflict, nothing written.
//  * REVISION IS A COMPARE-AND-SWAP. Writes are `WHERE task_id = $1 AND
//    revision = $2`; zero updated rows is RevisionConflict, never a blind
//    last-write-wins.
//  * FENCING. Any mutation that carries a fencing_token must match BOTH
//    agentboard_task.fencing_token AND the ACTIVE lease row, otherwise
//    StaleFence and no mutation. Revoke/expire always happens BEFORE a
//    reassignment, so a late callback can never win a race it lost.
//  * CLAIM LOSER. Two concurrent claims serialize on `SELECT ... FOR UPDATE`
//    of the task row. The loser observes the winner's committed revision, so
//    it fails the CAS and receives REVISION_CONFLICT (documented choice, see
//    `claimTask`). The partial unique index
//    `idx_agentboard_lease_single_active` is the independent backstop for a
//    claim that somehow reaches the INSERT without a correct expected
//    revision; that path yields TRANSITION_NOT_ALLOWED.
//  * THE STORE NEVER INVENTS A STATE CHANGE. Guards and policy live in
//    policy.mjs; this file only refuses an edge that is not in the frozen
//    TRANSITIONS table, refuses READY->CLAIMED (claimTask allocates the lease
//    and the fence atomically), and refuses to leave the executing states with
//    a lease still ACTIVE (revoke/release first, exactly as issue §4
//    requires for cancel and timeout).
//  * DB TIME ONLY. Lease issue, renewal and expiry decisions read the database
//    clock (`SELECT NOW() AT TIME ZONE 'UTC'`). The process clock is never
//    consulted: no Date.now(), no Math.random(), no `new Date()` without an
//    argument. The in-memory twin reads its INJECTED clock and never the
//    process clock either.
//  * NO BLIND RETRY. A run whose outcome is unknown becomes
//    RECONCILIATION_REQUIRED, which is terminal for the outbox dispatch state
//    machine; a store commit whose outcome cannot be confirmed escalates to
//    ReconciliationRequired rather than pretending to have failed.
//  * FAIL CLOSED. Nothing untyped escapes: every refusal is a BoardError from
//    errors.mjs, and a contract-valid document is asserted with
//    assertBoardContract() instead of being returned unchecked.
//
// Documented storage decisions (no migration change was permitted)
// ---------------------------------------------------------------
//  * `acceptance_criteria` is required by contracts/board-task.schema.json but
//    has no column in migrations/0008_agent_board.sql. It is stored in the
//    `detail.task.acceptance_criteria` member of the create command's audit
//    record — an append-only row written in the same transaction as the task
//    and indexed by task_id — and joined back on read. A task whose create
//    record is missing fails closed with MalformedResult on read.
//  * A reassignment or a revocation of a lease changes the task row
//    (active_lease_id / fencing_token) without changing its state. That write
//    still bumps the revision and appends a transition record whose
//    `payload.kind` is `lease_rebind` / `lease_revoke`, so the journal
//    remains complete and the same-state record is explicitly classified
//    rather than looking like a bogus state edge.
//  * A lease renewal changes no task state, so it writes an audit record and
//    nothing else; `agentboard_transition.revision` is CHECK (> 1) and unique
//    per task, so a no-op revision could never be journalled honestly.
//  * `ID_PREFIXES` in the frozen constants has no entry for the three journal
//    identifiers; the migration only bounds them to VARCHAR(64). The local
//    prefixes aud-/obx-/rec- are the documented extension.
//  * The board lease row is an INTERNAL store record, not a boundary
//    document: the eight BOARD_CONTRACTS are the only wire shapes and none of
//    them is a lease, so the lease is returned as a normalized record and is
//    never re-declared as a second contract.
//
// Every read is ACL-first: a caller that is not in the task ACL receives
// AclDenied and no payload field whatsoever. The visibility rule used here is
// deny-by-default: the principal must be listed in
// acl.allowed_principal_ids, or the task is `shared` AND the caller named the
// matching workspace. `policy.mjs` owns the canonical `isVisible`; it is
// injected (or lazily resolved) and this file's equivalent is only the
// fallback used when no policy module is supplied.
import pg from 'pg';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import {
  ACTOR_KINDS,
  BOARD_CONTRACT_VERSION,
  ID_PREFIXES,
  PRIORITY_RANK,
  TRANSITIONS,
  isTransitionAllowed,
  toStoredDigest,
  toWireDigest,
} from './constants.mjs';
import {
  AclDenied,
  AgentUnavailable,
  AuthRequired,
  BlockedPolicy,
  BudgetExceeded,
  CapabilityMismatch,
  IdempotencyConflict,
  MalformedResult,
  NeedsInput,
  ReconciliationRequired,
  RevisionConflict,
  StaleFence,
  TransitionNotAllowed,
  isBoardError,
  toBoardError,
} from './errors.mjs';
import { assertBoardContract } from './contracts.mjs';

const { Pool } = pg;

// ---------------------------------------------------------------------------
// Small typed validation helpers. Every one of them throws a member of the
// closed ERROR_CODES set; none of them can return a "probably fine" value.
// ---------------------------------------------------------------------------

const HEX64 = /^[0-9a-f]{64}$/;
const PRINCIPAL_ID = /^prn-[a-z0-9][a-z0-9-]{0,62}$/;
const ISO_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DAY_KEY = /^\d{4}-\d{2}-\d{2}$/;
const MAX_TTL_MS = 86_400_000;

const LOCAL_ID_PREFIXES = Object.freeze({ audit: 'aud-', outbox: 'obx-', reconciliation: 'rec-' });

function requirePlainObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new NeedsInput(`${label} must be a plain object`);
  }
  return value;
}

function requireActor(actor) {
  // A store write without a server-resolved principal is an authorization
  // failure, not a validation nicety: a hidden UI button is not authority.
  if (typeof actor !== 'string' || !PRINCIPAL_ID.test(actor)) {
    throw new AuthRequired('a server-resolved principal id (prn-…) is required for every write');
  }
  return actor;
}

function requireActorKind(actorKind) {
  if (typeof actorKind !== 'string' || !ACTOR_KINDS.includes(actorKind)) {
    throw new BlockedPolicy(`actor_kind must be one of ${ACTOR_KINDS.join('|')}, got ${String(actorKind)}`);
  }
  return actorKind;
}

function requireIdempotency({ idempotencyKey, argsDigest, label = 'write' }) {
  const hasKey = idempotencyKey !== undefined && idempotencyKey !== null;
  const hasDigest = argsDigest !== undefined && argsDigest !== null;
  if (hasKey !== hasDigest) {
    throw new NeedsInput(`${label}: idempotency_key and args_digest must be supplied together`);
  }
  if (!hasKey) return null;
  if (typeof idempotencyKey !== 'string' || !HEX64.test(idempotencyKey)) {
    throw new NeedsInput(`${label}: idempotency_key must be 64 lowercase hex characters`);
  }
  if (typeof argsDigest !== 'string' || !HEX64.test(argsDigest)) {
    throw new NeedsInput(`${label}: args_digest must be 64 lowercase hex characters`);
  }
  return { key: idempotencyKey, digest: argsDigest };
}

function requireText(value, label, { max = 500, min = 1 } = {}) {
  if (typeof value !== 'string' || value.length < min || value.length > max) {
    throw new NeedsInput(`${label} must be a string of ${min}..${max} characters`);
  }
  return value;
}

function requirePositiveInteger(value, label, max = Number.MAX_SAFE_INTEGER) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0 || value > max) {
    throw new NeedsInput(`${label} must be an integer in 1..${max}`);
  }
  return value;
}

function requireNonNegativeNumber(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new NeedsInput(`${label} must be a finite number >= 0`);
  }
  return value;
}

function requireRevision(expectedRevision, label) {
  return requirePositiveInteger(expectedRevision, `${label} expectedRevision`);
}

function toIsoMs(value, label = 'timestamp') {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new NeedsInput(`${label} is not a valid Date`);
    return value.toISOString();
  }
  if (typeof value === 'string') {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) throw new NeedsInput(`${label} is not a parseable timestamp`);
    return parsed.toISOString();
  }
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value).toISOString();
  throw new NeedsInput(`${label} must be a Date, an ISO string or epoch millis`);
}

function plusMs(iso, ms) {
  return new Date(Date.parse(iso) + ms).toISOString();
}

function dayKeyOf(iso) {
  return iso.slice(0, 10);
}

// Stored digests are bare 64-hex (CHAR(64)); the wire carries `sha256:<hex>`.
// Both directions are fail-closed: a malformed stored digest never becomes
// null on the wire and never silently disappears.
function storedDigest(hex, label) {
  if (typeof hex !== 'string' || !HEX64.test(hex)) {
    throw new MalformedResult(`STORED_DIGEST_MALFORMED:${label}`);
  }
  return hex;
}

function wireDigest(hex, label) {
  const value = toWireDigest(storedDigest(hex, label));
  if (value === null) throw new MalformedResult(`STORED_DIGEST_MALFORMED:${label}`);
  return value;
}

function storedFromWire(digest, label) {
  const value = toStoredDigest(digest);
  if (value === null) throw new NeedsInput(`${label} must be a sha256:<64 hex> wire digest`);
  return value;
}

function sameJson(left, right) {
  return canonicalDigest(left) === canonicalDigest(right);
}

function isPlainRow(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function byNumber(a, b, column) {
  const left = a[column] === null || a[column] === undefined ? -1 : Number(a[column]);
  const right = b[column] === null || b[column] === undefined ? -1 : Number(b[column]);
  return left - right;
}

// ---------------------------------------------------------------------------
// Table metadata. The column whitelist mirrors migrations/0008_agent_board.sql
// and exists so that a generated statement can never interpolate a name that
// was not part of the frozen migration: an unknown column fails closed with a
// typed error instead of producing subtly wrong SQL.
// ---------------------------------------------------------------------------

const TABLE_COLUMNS = Object.freeze({
  agentboard_task: 'task_id workspace_id revision state priority title goal description dependencies required_capabilities allowed_tools workspace_ref time_limits cost_limits brief_digest policy_digest manifest_digest brief_validated assigned_adapter_id active_lease_id fencing_token attempts artifacts evidence_refs block_reason history_digest created_at updated_at'.split(' '),
  agentboard_acl: 'task_id workspace_id visibility allowed_principal_ids updated_at'.split(' '),
  agentboard_lease: 'lease_id task_id workspace_id adapter_id principal_id fencing_token lease_state issued_at expires_at released_at revoked_reason'.split(' '),
  agentboard_adapter: 'adapter_id workspace_id provider display_name adapter_kind health principal_id declared_capabilities declared_tools sandbox_profile_id max_concurrency provenance_status provenance_detail registered_at'.split(' '),
  agentboard_budget_grant: 'grant_id workspace_id task_id currency task_limit campaign_limit day_limit timeout_ms granted_by granted_at expires_at revoked_at'.split(' '),
  agentboard_budget_spend: 'grant_id operation_id task_id workspace_id day_key currency spent_task spent_campaign spent_day updated_at'.split(' '),
  agentboard_run: 'run_id task_id workspace_id adapter_id lease_id fencing_token request_id idempotency_key run_state last_sequence brief_digest policy_digest manifest_digest request_payload request_digest result_payload result_digest error_payload spend currency dispatch_attempts started_at completed_at created_at'.split(' '),
  agentboard_execution_event: 'event_id run_id task_id workspace_id lease_id fencing_token sequence event_type outcome payload payload_digest emitted_at received_at'.split(' '),
  agentboard_transition: 'transition_id task_id workspace_id from_state to_state revision actor actor_kind idempotency_key reason lease_id fencing_token brief_digest policy_digest manifest_digest payload payload_digest occurred_at'.split(' '),
  agentboard_audit: 'audit_id workspace_id task_id actor operation idempotency_key outcome detail occurred_at'.split(' '),
  agentboard_outbox: 'outbox_id workspace_id task_id run_id event_type idempotency_key dispatch_state payload payload_digest attempts last_error created_at sent_at acked_at'.split(' '),
  agentboard_operation: 'idempotency_key workspace_id operation args_digest result_payload actor committed_at'.split(' '),
  agentboard_reconciliation: 'reconciliation_id workspace_id task_id run_id resolution decided_by decided_by_kind evidence_ref detail created_at'.split(' '),
});

// Primary keys, straight from the frozen migration. They are what makes a
// bounded UPDATE expressible: PostgreSQL has no `UPDATE … LIMIT`, so the row to
// write is selected first in a CTE and joined back on its primary key. Without
// this map a "update at most N rows" would have to be either a silent
// all-matching UPDATE or an unverifiable LIMIT.
const TABLE_PRIMARY_KEY = Object.freeze({
  agentboard_task: ['task_id'],
  agentboard_acl: ['task_id'],
  agentboard_lease: ['lease_id'],
  agentboard_adapter: ['adapter_id'],
  agentboard_budget_grant: ['grant_id'],
  agentboard_budget_spend: ['grant_id', 'day_key'],
  agentboard_run: ['run_id'],
  agentboard_execution_event: ['event_id'],
  agentboard_transition: ['transition_id'],
  agentboard_audit: ['audit_id'],
  agentboard_outbox: ['outbox_id'],
  agentboard_operation: ['idempotency_key'],
  agentboard_reconciliation: ['reconciliation_id'],
});

// Columns that are JSONB on the wire as documents and DOUBLE PRECISION /
// BIGINT on the wire as scalars need explicit conversion per backend.
const TABLE_BIGINT = Object.freeze({
  agentboard_task: ['fencing_token'],
  agentboard_lease: ['fencing_token'],
  agentboard_run: ['fencing_token'],
  agentboard_execution_event: ['fencing_token'],
});

const TABLE_TIMESTAMPS = Object.freeze({
  agentboard_task: ['created_at', 'updated_at'],
  agentboard_acl: ['updated_at'],
  agentboard_lease: ['issued_at', 'expires_at', 'released_at'],
  agentboard_adapter: ['registered_at'],
  agentboard_budget_grant: ['granted_at', 'expires_at', 'revoked_at'],
  agentboard_budget_spend: ['updated_at'],
  agentboard_run: ['started_at', 'completed_at', 'created_at'],
  agentboard_execution_event: ['emitted_at', 'received_at'],
  agentboard_transition: ['occurred_at'],
  agentboard_audit: ['occurred_at'],
  agentboard_outbox: ['created_at', 'sent_at', 'acked_at'],
  agentboard_operation: ['committed_at'],
  agentboard_reconciliation: ['created_at'],
});

// JSONB columns are passed as text and parsed by the driver.
const TABLE_JSONB = Object.freeze({
  agentboard_task: ['dependencies', 'required_capabilities', 'allowed_tools', 'workspace_ref', 'time_limits', 'cost_limits', 'artifacts', 'evidence_refs'],
  agentboard_acl: ['allowed_principal_ids'],
  agentboard_adapter: ['declared_capabilities', 'declared_tools'],
  agentboard_run: ['request_payload', 'result_payload', 'error_payload'],
  agentboard_execution_event: ['payload'],
  agentboard_transition: ['payload'],
  agentboard_audit: ['detail'],
  agentboard_outbox: ['payload'],
  agentboard_operation: ['result_payload'],
});

// Closed set of orderings. The in-memory twin implements the same keys as
// comparators, so both backends return rows in the same order.
const ORDERINGS = Object.freeze({
  task_priority: { sql: 'CASE priority WHEN \'HIGH\' THEN 0 WHEN \'MEDIUM\' THEN 1 ELSE 2 END ASC, task_id ASC', compare: (a, b) => (PRIORITY_RANK[a.priority] ?? 3) - (PRIORITY_RANK[b.priority] ?? 3) || a.task_id.localeCompare(b.task_id) },
  task_id: { sql: 'task_id ASC', compare: (a, b) => a.task_id.localeCompare(b.task_id) },
  // A row of a different table never shares another table's ordering key, so
  // every table gets its own closed ordering instead of borrowing `task_id`
  // for a table that has no task_id column.
  adapter_id: { sql: 'adapter_id ASC', compare: (a, b) => a.adapter_id.localeCompare(b.adapter_id) },
  transition_revision: { sql: 'revision ASC', compare: (a, b) => byNumber(a, b, 'revision') },
  event_sequence: { sql: 'sequence ASC', compare: (a, b) => byNumber(a, b, 'sequence') },
  run_created: { sql: 'created_at ASC, run_id ASC', compare: (a, b) => String(a.created_at).localeCompare(String(b.created_at)) || a.run_id.localeCompare(b.run_id) },
  run_id: { sql: 'run_id ASC', compare: (a, b) => a.run_id.localeCompare(b.run_id) },
  lease_id: { sql: 'lease_id ASC', compare: (a, b) => a.lease_id.localeCompare(b.lease_id) },
  grant_id: { sql: 'grant_id ASC', compare: (a, b) => a.grant_id.localeCompare(b.grant_id) },
  audit_occurred: { sql: 'occurred_at ASC, audit_id ASC', compare: (a, b) => String(a.occurred_at).localeCompare(String(b.occurred_at)) || a.audit_id.localeCompare(b.audit_id) },
  outbox_created: { sql: 'created_at ASC, outbox_id ASC', compare: (a, b) => String(a.created_at).localeCompare(String(b.created_at)) || a.outbox_id.localeCompare(b.outbox_id) },
  reconciliation_created: { sql: 'created_at ASC, reconciliation_id ASC', compare: (a, b) => String(a.created_at).localeCompare(String(b.created_at)) || a.reconciliation_id.localeCompare(b.reconciliation_id) },
  event_received: { sql: 'received_at ASC, event_id ASC', compare: (a, b) => String(a.received_at).localeCompare(String(b.received_at)) || a.event_id.localeCompare(b.event_id) },
});

const DEFAULT_OUTBOX_EVENT_TYPES = Object.freeze({
  createTask: 'board.task.created',
  transitionTask: 'board.task.transitioned',
  createRun: 'board.execution.request',
  leaseExpired: 'board.execution.reconciliation_required',
  reconciliation: 'board.reconciliation.recorded',
});

// The four reconciliation resolutions and the three decider kinds are CHECKed
// by the frozen migration (and therefore by PostgreSQL itself). The in-memory
// twin cannot execute a CHECK, so it mirrors the two closed sets here; in
// PostgreSQL a divergence fails closed as a check violation mapped to
// BlockedPolicy. `policy.mjs` remains the owner of the human-gate rule
// (assertHumanOnlyApproval); this list is the store's last-line fallback.
const RECONCILIATION_RESOLUTIONS = Object.freeze([
  'OBSERVED_NO_EFFECT', 'OBSERVED_EFFECT_COMPLETED', 'OBSERVED_EFFECT_UNDONE', 'EFFECT_UNDETERMINED',
]);
const RECONCILIATION_DECIDER_KINDS = Object.freeze(['human_owner', 'human_reviewer', 'deterministic_gate']);

const TERMINAL_EVENT_TYPES = Object.freeze(['COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'UNKNOWN']);
const LIVE_RUN_STATES = Object.freeze(['DISPATCH_PENDING', 'DISPATCHED', 'RUNNING']);

// States in which a pending execution handoff may NEVER be issued.
//
// Only CANCELLED is listed, and the reason is the difference between a
// WITHDRAWAL and a REPORT. A cancel withdraws the work: the board decided that
// this instruction must not exist, so issuing it afterwards would start work
// somebody explicitly stopped. A FAILED, BLOCKED or
// RECONCILIATION_REQUIRED unit is only a report about work the executor was
// already handed; its handoff row is still PENDING because the send did not
// complete, and delivering that ONE pending instruction is not a blind retry —
// what may never happen for those states either is a SECOND send, and that is
// what the outbox state machine below enforces. A DONE or IN_REVIEW task is
// not listed for the same reason: it can only be reached after the executor
// answered, so its handoff row is ACKED and never reaches this check.
const STATES_BARRING_DISPATCH = Object.freeze(['CANCELLED']);
const EXECUTING_STATES = Object.freeze(['CLAIMED', 'RUNNING']);

const RUN_STATE_FOR_OUTCOME = Object.freeze({
  SUCCEEDED: 'COLLECTED',
  BLOCKED: 'COLLECTED',
  FAILED: 'FAILED',
  TIMEOUT: 'FAILED',
  CANCELLED: 'CANCELLED',
  RECONCILIATION_REQUIRED: 'RECONCILIATION_REQUIRED',
});

// ---------------------------------------------------------------------------
// Wire builders. Every document that crosses this file's boundary is asserted
// with the ONE contract registry; a document that cannot be asserted is never
// returned (fail closed instead of handing out an unchecked payload).
// ---------------------------------------------------------------------------

/**
 * Assert a task document against contracts/board-task.schema.json.
 * DEBUG-able on purpose: a violation is never swallowed, it is a typed
 * MalformedResult that names the schema and the failing instance paths.
 */
export function validateTaskDocument(document) {
  return assertBoardContract('board-task', document, MalformedResult);
}

function buildTaskWire({ row, aclRow, createDetail }) {
  const acceptance = createDetail?.task?.acceptance_criteria;
  if (!Array.isArray(acceptance) || acceptance.length === 0) {
    throw new MalformedResult('CREATE_RECORD_MISSING', 'the create record for this task is absent or has no acceptance_criteria');
  }
  return validateTaskDocument({
    contractVersion: BOARD_CONTRACT_VERSION,
    task_id: row.task_id,
    workspace_id: row.workspace_id,
    title: row.title,
    goal: row.goal,
    description: row.description,
    acceptance_criteria: acceptance,
    state: row.state,
    revision: Number(row.revision),
    priority: row.priority,
    dependencies: row.dependencies,
    required_capabilities: row.required_capabilities,
    allowed_tools: row.allowed_tools,
    workspace_ref: row.workspace_ref,
    time_limits: row.time_limits,
    cost_limits: row.cost_limits,
    acl: {
      visibility: aclRow.visibility,
      allowed_principal_ids: aclRow.allowed_principal_ids,
    },
    brief_digest: wireDigest(row.brief_digest, 'task.brief_digest'),
    policy_digest: wireDigest(row.policy_digest, 'task.policy_digest'),
    manifest_digest: wireDigest(row.manifest_digest, 'task.manifest_digest'),
    assigned_adapter_id: row.assigned_adapter_id ?? null,
    active_lease_id: row.active_lease_id ?? null,
    fencing_token: row.fencing_token === null || row.fencing_token === undefined ? null : Number(row.fencing_token),
    attempts: Number(row.attempts),
    artifacts: row.artifacts,
    evidence_refs: row.evidence_refs,
    block_reason: row.block_reason ?? null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    history_digest: wireDigest(row.history_digest, 'task.history_digest'),
  });
}

function buildTransitionWire(row) {
  return assertBoardContract('board-transition', {
    contractVersion: BOARD_CONTRACT_VERSION,
    transition_id: row.transition_id,
    task_id: row.task_id,
    workspace_id: row.workspace_id,
    from_state: row.from_state,
    to_state: row.to_state,
    revision: Number(row.revision),
    actor: row.actor,
    idempotency_key: row.idempotency_key,
    reason: row.reason,
    lease_id: row.lease_id ?? null,
    fencing_token: row.fencing_token === null || row.fencing_token === undefined ? null : Number(row.fencing_token),
    brief_digest: wireDigest(row.brief_digest, 'transition.brief_digest'),
    policy_digest: wireDigest(row.policy_digest, 'transition.policy_digest'),
    manifest_digest: wireDigest(row.manifest_digest, 'transition.manifest_digest'),
    occurred_at: row.occurred_at,
  }, MalformedResult);
}

function buildEventWire(row) {
  return assertBoardContract('execution-event', {
    contract_version: 'veritas.execution/1.0.0',
    event_id: row.event_id,
    run_id: row.run_id,
    task_id: row.task_id,
    workspace_id: row.workspace_id,
    lease_id: row.lease_id,
    fencing_token: Number(row.fencing_token),
    sequence: Number(row.sequence),
    event_type: row.event_type,
    payload: row.payload,
    outcome: row.outcome ?? null,
    emitted_at: row.emitted_at,
  }, MalformedResult);
}

function buildLeaseWire(row) {
  return {
    lease_id: row.lease_id,
    task_id: row.task_id,
    workspace_id: row.workspace_id,
    adapter_id: row.adapter_id,
    principal_id: row.principal_id,
    fencing_token: Number(row.fencing_token),
    lease_state: row.lease_state,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    released_at: row.released_at ?? null,
    revoked_reason: row.revoked_reason ?? null,
  };
}

function buildAdapterWire(row) {
  return assertBoardContract('adapter-registration', {
    contractVersion: BOARD_CONTRACT_VERSION,
    adapter_id: row.adapter_id,
    adapter_interface: 'veritas.adapter/1.0.0',
    provider: row.provider,
    display_name: row.display_name,
    adapter_kind: row.adapter_kind,
    health: row.health,
    workspace_id: row.workspace_id,
    principal_id: row.principal_id,
    declared_capabilities: row.declared_capabilities,
    declared_tools: row.declared_tools,
    sandbox_profile_id: row.sandbox_profile_id,
    max_concurrency: Number(row.max_concurrency),
    real_adapter_provenance: { status: row.provenance_status, detail: row.provenance_detail },
    registered_at: row.registered_at,
  }, MalformedResult);
}

function buildRunWire(row) {
  const wire = {
    run_id: row.run_id,
    task_id: row.task_id,
    workspace_id: row.workspace_id,
    adapter_id: row.adapter_id,
    lease_id: row.lease_id,
    fencing_token: Number(row.fencing_token),
    request_id: row.request_id,
    idempotency_key: row.idempotency_key,
    run_state: row.run_state,
    last_sequence: Number(row.last_sequence),
    brief_digest: wireDigest(row.brief_digest, 'run.brief_digest'),
    policy_digest: wireDigest(row.policy_digest, 'run.policy_digest'),
    manifest_digest: wireDigest(row.manifest_digest, 'run.manifest_digest'),
    request: assertBoardContract('execution-request', row.request_payload, MalformedResult),
    request_digest: wireDigest(row.request_digest, 'run.request_digest'),
    result: row.result_payload === null || row.result_payload === undefined
      ? null
      : assertBoardContract('execution-result', row.result_payload, MalformedResult),
    result_digest: row.result_digest === null || row.result_digest === undefined
      ? null
      : wireDigest(row.result_digest, 'run.result_digest'),
    error: row.error_payload ?? null,
    spend: Number(row.spend),
    currency: row.currency,
    dispatch_attempts: Number(row.dispatch_attempts),
    started_at: row.started_at ?? null,
    completed_at: row.completed_at ?? null,
    created_at: row.created_at,
  };
  return wire;
}

function buildOutboxWire(row) {
  return {
    outbox_id: row.outbox_id,
    workspace_id: row.workspace_id,
    task_id: row.task_id ?? null,
    run_id: row.run_id ?? null,
    event_type: row.event_type,
    idempotency_key: row.idempotency_key,
    dispatch_state: row.dispatch_state,
    payload: row.payload,
    payload_digest: wireDigest(row.payload_digest, 'outbox.payload_digest'),
    attempts: Number(row.attempts),
    last_error: row.last_error ?? null,
    created_at: row.created_at,
    sent_at: row.sent_at ?? null,
    acked_at: row.acked_at ?? null,
  };
}

function buildAuditWire(row) {
  return {
    audit_id: row.audit_id,
    workspace_id: row.workspace_id,
    task_id: row.task_id ?? null,
    actor: row.actor,
    operation: row.operation,
    idempotency_key: row.idempotency_key,
    outcome: row.outcome,
    detail: row.detail,
    occurred_at: row.occurred_at,
  };
}

function buildGrantWire(row) {
  return {
    grant_id: row.grant_id,
    workspace_id: row.workspace_id,
    task_id: row.task_id ?? null,
    currency: row.currency,
    task_limit: row.task_limit === null ? null : Number(row.task_limit),
    campaign_limit: row.campaign_limit === null ? null : Number(row.campaign_limit),
    day_limit: row.day_limit === null ? null : Number(row.day_limit),
    timeout_ms: row.timeout_ms === null ? null : Number(row.timeout_ms),
    granted_by: row.granted_by,
    granted_at: row.granted_at,
    expires_at: row.expires_at ?? null,
    revoked_at: row.revoked_at ?? null,
  };
}

function buildReconciliationWire(row) {
  return {
    reconciliation_id: row.reconciliation_id,
    workspace_id: row.workspace_id,
    task_id: row.task_id ?? null,
    run_id: row.run_id ?? null,
    resolution: row.resolution,
    decided_by: row.decided_by,
    decided_by_kind: row.decided_by_kind,
    evidence_ref: row.evidence_ref ?? null,
    detail: row.detail,
    created_at: row.created_at,
  };
}

function buildOperationWire(row) {
  return {
    idempotency_key: row.idempotency_key,
    workspace_id: row.workspace_id,
    operation: row.operation,
    args_digest: row.args_digest,
    result_payload: row.result_payload ?? null,
    actor: row.actor,
    committed_at: row.committed_at,
  };
}

// ---------------------------------------------------------------------------
// Deterministic id factory. No Math.random anywhere: a seeded SHA-256 prefix
// plus a monotonic counter, so a test can predict every id it will see.
// ---------------------------------------------------------------------------

function defaultIdFactory(seed) {
  const prefix = canonicalDigest({ seed: String(seed), v: 's2-007-store-ids' }).slice(0, 10);
  let counter = 0;
  return (kind) => {
    counter += 1;
    const id = `${prefix}${counter.toString(36).padStart(6, '0')}`;
    return id.length > 64 ? id.slice(0, 64) : id;
  };
}

function makeIdFactory(injected) {
  if (typeof injected === 'function') return injected;
  if (isPlainRow(injected) && typeof injected.next === 'function') return (kind) => injected.next(kind);
  return defaultIdFactory('veritas-s2-007');
}

// ---------------------------------------------------------------------------
// Policy bridge. policy.mjs owns isVisible/assertHumanOnlyApproval; this file
// must not import it statically (it is a sibling worker's file), so the module
// is resolved lazily and cached. When no policy module is available the
// documented local equivalent is used — the same deny-by-default rule, never a
// weaker one. `constructor({ policy })` always wins over the lazy resolution.
// ---------------------------------------------------------------------------

let POLICY_MODULE_PROMISE = null;

function loadPolicyModule() {
  if (POLICY_MODULE_PROMISE === null) {
    POLICY_MODULE_PROMISE = import('./policy.mjs').catch(() => null);
  }
  return POLICY_MODULE_PROMISE;
}

function fallbackIsVisible({ acl, workspace_id: workspaceId, principal_id: principalId }, requestedWorkspaceId) {
  const allowed = Array.isArray(acl?.allowed_principal_ids) ? acl.allowed_principal_ids : [];
  if (allowed.includes(principalId)) return true;
  if (acl?.visibility !== 'shared') return false;
  return requestedWorkspaceId !== undefined && requestedWorkspaceId !== null && requestedWorkspaceId === workspaceId;
}

// ---------------------------------------------------------------------------
// The engine shared by both backends.
// ---------------------------------------------------------------------------

/**
 * AgentBoardStoreBase — every semantic rule of the S2-007 board store.
 *
 * Documented throws (the ONLY exceptions this module can raise; everything
 * else is translated by toBoardError):
 *   AuthRequired            no server-resolved principal on a write or read
 *   AclDenied               caller outside the task ACL, or cross-workspace
 *   NeedsInput              missing/malformed argument, unknown referenced id
 *   BlockedPolicy           actor_kind / attempt to bypass the state machine
 *   TransitionNotAllowed    edge absent from the frozen TRANSITIONS table,
 *                           a task already holding an active lease, an
 *                           illegal outbox dispatch step
 *   RevisionConflict        compare-and-swap on expected_revision failed
 *   StaleFence              fencing token is not the current one, or the lease
 *                           is no longer ACTIVE
 *   IdempotencyConflict     same key with different args_digest, or a unique
 *                           identity re-used with different content
 *   BudgetExceeded          an unassigned, revoked, expired or exhausted
 *                           budget scope
 *   MalformedResult         a document that is not contract-valid, a stored
 *                           digest that is malformed, an out-of-order event
 *   CapabilityMismatch      a run bound to a workspace/tool/grant the task or
 *                           the grant does not authorize
 *   AgentUnavailable        unknown/unhealthy adapter
 *   ReconciliationRequired  the outcome of a side effect is unknown
 *   ContractVersionUnknown / TimeoutError / ProviderFailure (translated)
 */
export class AgentBoardStoreBase {
  constructor({ clock, ids, seed = 'veritas-s2-007', policy = null } = {}) {
    // `clock` is either { now(): Date } or () => Date|string. The process
    // clock is never read: an uninjected store uses a fixed epoch.
    if (typeof clock === 'function') this.clock = clock;
    else if (isPlainRow(clock) && typeof clock.now === 'function') this.clock = () => clock.now();
    else this.clock = () => new Date(0);
    this.seed = String(seed);
    this.ids = makeIdFactory(ids);
    this.policyOverride = policy;
    this._policy = null;
    this._policyResolved = false;
  }

  // --- plumbing -------------------------------------------------------------

  // _acquireUnitOfWork / _commitUnitOfWork / _discardUnitOfWork are the three
  // primitives a backend must provide. Everything else in this class is
  // backend-agnostic, which is what makes the two stores behavioural twins.

  // Documented abstract primitive: a backend MUST provide all three.
  _acquireUnitOfWork() { throw new NeedsInput('store backend does not implement _acquireUnitOfWork'); }

  // Documented abstract primitive: a backend MUST provide all three.
  _commitUnitOfWork() { throw new NeedsInput('store backend does not implement _commitUnitOfWork'); }

  // Documented abstract primitive: a backend MUST provide all three.
  _discardUnitOfWork() { throw new NeedsInput('store backend does not implement _discardUnitOfWork'); }

  // Documented OPTIONAL primitive. A backend that CANNOT hand out two
  // concurrent write snapshots must serialize here and return the release
  // function; the default is the no-op, which is correct for PostgreSQL
  // because its transactions serialize through row locks. The in-memory twin
  // has no row locks — it builds a copy-on-write draft per transaction — so
  // two concurrent writers would each read the same revision and the second
  // commit would silently drop the first one's committed rows. Taking the
  // chain in `_withUnitOfWork` is what makes the twin a behavioural twin of
  // the real store rather than a weaker gate.
  _serializeWrite() { return () => {}; }

  async _withUnitOfWork(handler, { write = false, fallback = 'PROVIDER_FAILURE' } = {}) {
    let release = null;
    let tx = null;
    try {
      if (write) release = await this._serializeWrite();
      tx = await this._acquireUnitOfWork();
    } catch (error) {
      if (release) release();
      throw toBoardError(error, fallback);
    }
    let committed = false;
    try {
      const result = await handler(tx);
      if (write) {
        await this._commitUnitOfWork(tx);
        committed = true;
      }
      return result;
    } catch (error) {
      throw isBoardError(error) ? error : toBoardError(error, fallback);
    } finally {
      if (!committed) {
        try {
          await this._discardUnitOfWork(tx);
        } catch {
          // The original failure is the one that matters; a rollback error
          // must never mask it (and must never become a success).
        }
      }
      if (release) release();
    }
  }

  async _read(handler, options = {}) {
    return this._withUnitOfWork(handler, { ...options, write: false });
  }

  async _write(handler, options = {}) {
    return this._withUnitOfWork(handler, { ...options, write: true });
  }

  newId(kind) {
    const prefix = ID_PREFIXES[kind] ?? LOCAL_ID_PREFIXES[kind] ?? '';
    const id = this.ids(kind);
    if (typeof id !== 'string' || id.length === 0 || id.length > 64) {
      throw new NeedsInput(`id factory returned an unusable ${kind} identifier`);
    }
    return prefix === '' ? id : `${prefix}${id}`;
  }

  async _policyModule() {
    if (this._policyResolved) return this._policy;
    this._policyResolved = true;
    if (this.policyOverride) {
      this._policy = this.policyOverride;
    } else {
      const policyModule = await loadPolicyModule();
      this._policy = policyModule && typeof policyModule.isVisible === 'function' ? policyModule : null;
    }
    return this._policy;
  }

  async _assertVisible(tx, taskId, { principalId, workspaceId }) {
    if (principalId === undefined || principalId === null || principalId === '') {
      throw new AuthRequired('a principal id is required to read a board task');
    }
    if (typeof principalId !== 'string' || !PRINCIPAL_ID.test(principalId)) {
      throw new AuthRequired('principal id must be a server-resolved prn-… identifier');
    }
    const { task, acl, create } = await this._loadTaskWithAcl(tx, taskId);
    if (!task) throw new NeedsInput(`unknown task ${String(taskId)}`);
    if (workspaceId !== undefined && workspaceId !== null && workspaceId !== task.workspace_id) {
      // Cross-workspace isolation is absolute: it does not depend on the ACL
      // list, and it never returns a payload field.
      throw new AclDenied('cross_workspace_read_denied');
    }
    const subject = {
      acl: { visibility: acl.visibility, allowed_principal_ids: acl.allowed_principal_ids },
      workspace_id: task.workspace_id,
      principal_id: principalId,
    };
    const policy = await this._policyModule();
    const visible = policy && typeof policy.isVisible === 'function'
      ? policy.isVisible(subject, principalId) === true
      : fallbackIsVisible(subject, workspaceId);
    if (!visible) throw new AclDenied('acl_denied');
    // `create` is the task's birth record; a caller that rebuilds the task
    // wire needs it, so it travels with the authorized read instead of being
    // silently dropped.
    return { task, acl, create };
  }

  async _loadTaskWithAcl(tx, taskId) {
    const task = await tx.selectRow('agentboard_task', { where: { task_id: taskId } });
    if (!task) return { task: null, acl: null };
    const acl = await tx.selectRow('agentboard_acl', { where: { task_id: taskId } });
    if (!acl) throw new MalformedResult('TASK_ACL_MISSING', `task ${taskId} has no ACL row`);
    const create = await tx.selectRow('agentboard_audit', {
      where: { task_id: taskId, operation: 'board.task.create' },
      order: 'audit_occurred',
      limit: 1,
    });
    return { task, acl, create: create ? create.detail : null };
  }

  async _taskWire(tx, taskId) {
    const { task, acl, create } = await this._loadTaskWithAcl(tx, taskId);
    if (!task) throw new NeedsInput(`unknown task ${String(taskId)}`);
    return buildTaskWire({ row: task, aclRow: acl, createDetail: create });
  }

  // --- ledger ---------------------------------------------------------------

  /**
   * The idempotency ledger, consulted BEFORE any row lock. Returns the prior
   * committed result on a replay, or null when this is a fresh operation.
   */
  async _replay(tx, idem, { operation }) {
    if (idem === null) return null;
    const prior = await tx.selectRow('agentboard_operation', { where: { idempotency_key: idem.key } });
    if (!prior) return null;
    if (prior.args_digest !== idem.digest) {
      throw new IdempotencyConflict(
        'IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_ARGUMENTS',
        `key ${idem.key} was already committed for operation ${String(prior.operation)} with a different canonical argument digest`,
      );
    }
    if (prior.operation !== operation) {
      throw new IdempotencyConflict(
        'IDEMPOTENCY_KEY_REUSED_FOR_OTHER_OPERATION',
        `key ${idem.key} is bound to operation ${String(prior.operation)}, not ${String(operation)}`,
      );
    }
    if (prior.result_payload === null || prior.result_payload === undefined) {
      // The marker exists but records no result: the prior outcome is unknown
      // and must never be reported as a success or as a clean failure.
      throw new ReconciliationRequired('IDEMPOTENCY_LEDGER_WITHOUT_RESULT', `key ${idem.key}`);
    }
    return { ...prior.result_payload, replayed: true };
  }

  /**
   * Commit tail. The outbox row and the audit row are written here and the
   * operation marker LAST: its presence inside a committed transaction is the
   * proof that the entity, the transition, the audit and the outbox committed
   * together. (createTask is the one command that writes its own audit row
   * earlier, because that row is the task's birth record and the task wire
   * cannot be built before it exists.)
   */
  async _commitMark(tx, { idem, workspaceId, operation, actor, audit, outbox, result, now }) {
    if (outbox) await this._insertOutbox(tx, outbox, { now });
    if (audit) {
      await tx.insertRow('agentboard_audit', {
        audit_id: this.newId('audit'),
        workspace_id: workspaceId,
        task_id: audit.task_id ?? null,
        actor,
        operation,
        idempotency_key: audit.idempotency_key ?? idem?.key ?? canonicalDigest({ operation, actor, at: now }),
        outcome: 'COMMITTED',
        detail: audit.detail ?? {},
        occurred_at: now,
      });
    }
    if (idem) {
      await tx.insertRow('agentboard_operation', {
        idempotency_key: idem.key,
        workspace_id: workspaceId,
        operation,
        args_digest: idem.digest,
        result_payload: result,
        actor,
        committed_at: now,
      });
    }
    return { ...result, replayed: false };
  }

  /**
   * Insert one outbox row. `dispatchState` defaults to PENDING because that is
   * the re-dispatchable state, and it is only overridden when the row is born
   * into a terminal state: a row that records an UNKNOWN external side effect
   * must never start out PENDING, or the outbox driver would re-issue the very
   * dispatch whose outcome nobody knows.
   */
  async _insertOutbox(tx, outbox, { now, dispatchState = 'PENDING', lastError = null } = {}) {
    const payload = requirePlainObject(outbox.payload, 'outboxEvent.payload');
    const row = {
      outbox_id: outbox.outbox_id ?? this.newId('outbox'),
      workspace_id: outbox.workspace_id,
      task_id: outbox.task_id ?? null,
      run_id: outbox.run_id ?? null,
      event_type: requireText(outbox.event_type, 'outboxEvent.event_type', { max: 48 }),
      idempotency_key: requireText(outbox.idempotency_key, 'outboxEvent.idempotency_key', { max: 64 }),
      dispatch_state: dispatchState,
      payload,
      payload_digest: canonicalDigest(payload),
      attempts: 0,
      last_error: lastError === null ? null : requireText(lastError, 'outboxEvent.last_error', { max: 500 }),
      created_at: now,
      sent_at: null,
      acked_at: null,
    };
    return tx.insertRow('agentboard_outbox', row);
  }

  // --- history --------------------------------------------------------------

  /**
   * history_digest = canonicalDigest(transition ids in revision order). It is
   * recomputed on every transition so a reader can prove that the history it
   * read is the history that was written. The list is read INSIDE the
   * transaction, after the new transition row was appended, so the digest can
   * never lag the journal.
   */
  async _historyDigest(tx, taskId) {
    const rows = await tx.selectRows('agentboard_transition', {
      where: { task_id: taskId },
      order: 'transition_revision',
    });
    return canonicalDigest(rows.map((row) => row.transition_id));
  }

  async _appendTransition(tx, {
    taskId, workspaceId, fromState, toState, actor, actorKind, idem, reason,
    leaseId = null, fencingToken = null, revision, payload, now, digests,
  }) {
    // A transition is BOUND to the immutable documents the task was created
    // with: brief, policy and manifest digests are copied from the task row
    // that the caller already holds under a lock, never from a payload.
    const source = digests ?? await tx.selectRow('agentboard_task', { where: { task_id: taskId } });
    if (!source) throw new NeedsInput(`unknown task ${String(taskId)}`);
    const row = {
      transition_id: this.newId('transition'),
      task_id: taskId,
      workspace_id: workspaceId,
      from_state: fromState,
      to_state: toState,
      revision,
      actor,
      actor_kind: actorKind,
      idempotency_key: requireText(idem, 'transition idempotency_key', { max: 64 }),
      reason: requireText(reason, 'transition reason', { max: 500 }),
      lease_id: leaseId,
      fencing_token: fencingToken,
      brief_digest: source.brief_digest,
      policy_digest: source.policy_digest,
      manifest_digest: source.manifest_digest,
      payload: payload ?? {},
      payload_digest: canonicalDigest(payload ?? {}),
      occurred_at: now,
    };
    const inserted = await tx.insertRow('agentboard_transition', row);
    return inserted;
  }

  // --- shared write helpers -------------------------------------------------

  _requireFenceMatch(task, lease, fencingToken, label) {
    if (fencingToken === undefined || fencingToken === null) {
      throw new StaleFence('FENCE_REQUIRED', `${label}: a fencing token is required while a lease is active`);
    }
    const token = Number(fencingToken);
    if (!Number.isInteger(token) || token <= 0) throw new StaleFence('FENCE_MALFORMED', `${label}`);
    const taskFence = task.fencing_token === null || task.fencing_token === undefined ? null : Number(task.fencing_token);
    if (taskFence !== token) {
      throw new StaleFence('FENCE_NOT_CURRENT', `${label}: task fence ${String(taskFence)} != presented ${token}`);
    }
    if (!lease || lease.lease_state !== 'ACTIVE' || Number(lease.fencing_token) !== token) {
      throw new StaleFence('LEASE_NOT_ACTIVE', `${label}: lease ${lease?.lease_id ?? 'none'} is not ACTIVE at fence ${token}`);
    }
    return token;
  }

  async _activeLease(tx, taskId) {
    return tx.selectRow('agentboard_lease', { where: { task_id: taskId, lease_state: 'ACTIVE' } });
  }

  // =========================================================================
  // READS
  // =========================================================================

  async dbNow() {
    return this._read(async (tx) => tx.now());
  }

  async nextFencingToken() {
    // Allocating a fence is a side effect of its own, so it runs in a COMMITTED
    // unit of work. In PostgreSQL `nextval` is already non-transactional; in the
    // in-memory twin a read-only unit of work would be discarded and the same
    // fence would be handed out twice, which is exactly the divergence the
    // shared engine exists to prevent.
    return this._write(async (tx) => tx.nextFencingToken());
  }

  async close() { /* nothing to release by default */ }

  async getTask(taskId, { workspaceId = undefined, principalId = undefined } = {}) {
    requireText(taskId, 'taskId', { max: 64 });
    return this._read(async (tx) => {
      const { task, acl, create } = await this._assertVisible(tx, taskId, { principalId, workspaceId });
      return buildTaskWire({ row: task, aclRow: acl, createDetail: create });
    });
  }

  async listTasks({ workspaceId, principalId, state = undefined, limit = 50 } = {}) {
    requireText(workspaceId, 'workspaceId', { max: 64 });
    if (principalId === undefined || principalId === null) {
      throw new AuthRequired('a principal id is required to list board tasks');
    }
    const max = requirePositiveInteger(limit, 'limit', 200);
    return this._read(async (tx) => {
      const policy = await this._policyModule();
      const rows = await tx.selectRows('agentboard_task', {
        where: state === undefined ? { workspace_id: workspaceId } : { workspace_id: workspaceId, state },
        order: 'task_priority',
        limit: max,
      });
      // ONE pass per task, not three: the ACL row is read once and reused for
      // the visibility decision AND for the wire document, and the birth
      // record is read alongside it. At `limit: 200` the previous shape cost
      // 600 round trips for one list, on the hot path the live board polls.
      const visible = [];
      for (const row of rows) {
        const acl = await tx.selectRow('agentboard_acl', { where: { task_id: row.task_id } });
        if (!acl) continue;
        const subject = {
          acl: { visibility: acl.visibility, allowed_principal_ids: acl.allowed_principal_ids },
          workspace_id: row.workspace_id,
          principal_id: principalId,
        };
        const ok = policy && typeof policy.isVisible === 'function'
          ? policy.isVisible(subject, principalId) === true
          : fallbackIsVisible(subject, workspaceId);
        if (!ok) continue;
        const create = await tx.selectRow('agentboard_audit', {
          where: { task_id: row.task_id, operation: 'board.task.create' },
          order: 'audit_occurred',
          limit: 1,
        });
        visible.push({ row, acl, createDetail: create?.detail ?? null });
      }
      return visible.map(({ row, acl, createDetail }) => buildTaskWire({ row, aclRow: acl, createDetail }));
    });
  }

  async listTransitions(taskId, { workspaceId = undefined, principalId = undefined } = {}) {
    requireText(taskId, 'taskId', { max: 64 });
    return this._read(async (tx) => {
      await this._assertVisible(tx, taskId, { principalId, workspaceId });
      const rows = await tx.selectRows('agentboard_transition', { where: { task_id: taskId }, order: 'transition_revision' });
      return rows.map(buildTransitionWire);
    });
  }

  async getAcl(taskId, { principalId = undefined, workspaceId = undefined } = {}) {
    requireText(taskId, 'taskId', { max: 64 });
    return this._read(async (tx) => {
      if (principalId !== undefined && principalId !== null) {
        await this._assertVisible(tx, taskId, { principalId, workspaceId });
      }
      const acl = await tx.selectRow('agentboard_acl', { where: { task_id: taskId } });
      if (!acl) throw new NeedsInput(`unknown task ${String(taskId)}`);
      return {
        task_id: acl.task_id,
        workspace_id: acl.workspace_id,
        visibility: acl.visibility,
        allowed_principal_ids: acl.allowed_principal_ids,
        updated_at: acl.updated_at,
      };
    });
  }

  async readLease(leaseId, { principalId = undefined, workspaceId = undefined } = {}) {
    requireText(leaseId, 'leaseId', { max: 64 });
    return this._read(async (tx) => {
      const lease = await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId } });
      if (!lease) throw new NeedsInput(`unknown lease ${String(leaseId)}`);
      if (principalId !== undefined && principalId !== null) {
        await this._assertVisible(tx, lease.task_id, { principalId, workspaceId });
      }
      return buildLeaseWire(lease);
    });
  }

  async listLeases({ workspaceId, taskId = undefined, leaseState = undefined, principalId = undefined } = {}) {
    requireText(workspaceId, 'workspaceId', { max: 64 });
    return this._read(async (tx) => {
      const where = { workspace_id: workspaceId };
      if (taskId !== undefined && taskId !== null) where.task_id = taskId;
      if (leaseState !== undefined && leaseState !== null) where.lease_state = leaseState;
      const rows = await tx.selectRows('agentboard_lease', { where, order: 'lease_id' });
      if (principalId === undefined || principalId === null) return rows.map(buildLeaseWire);
      const out = [];
      for (const row of rows) {
        try {
          await this._assertVisible(tx, row.task_id, { principalId, workspaceId });
          out.push(buildLeaseWire(row));
        } catch (error) {
          if (isBoardError(error) && (error.code === 'AclDenied' || error.code === 'AuthRequired')) continue;
          throw error;
        }
      }
      return out;
    });
  }

  async getAdapter(adapterId) {
    requireText(adapterId, 'adapterId', { max: 64 });
    return this._read(async (tx) => {
      const row = await tx.selectRow('agentboard_adapter', { where: { adapter_id: adapterId } });
      if (!row) throw new NeedsInput(`unknown adapter ${String(adapterId)}`);
      return buildAdapterWire(row);
    });
  }

  async listAdapters({ workspaceId } = {}) {
    requireText(workspaceId, 'workspaceId', { max: 64 });
    return this._read(async (tx) => {
      const rows = await tx.selectRows('agentboard_adapter', { where: { workspace_id: workspaceId }, order: 'adapter_id' });
      return rows.map(buildAdapterWire);
    });
  }

  async readRun(runId, { principalId = undefined, workspaceId = undefined } = {}) {
    requireText(runId, 'runId', { max: 64 });
    return this._read(async (tx) => {
      const row = await tx.selectRow('agentboard_run', { where: { run_id: runId } });
      if (!row) throw new NeedsInput(`unknown run ${String(runId)}`);
      if (principalId !== undefined && principalId !== null) {
        await this._assertVisible(tx, row.task_id, { principalId, workspaceId });
      }
      return buildRunWire(row);
    });
  }

  async listRuns({ workspaceId, taskId = undefined, principalId = undefined } = {}) {
    requireText(workspaceId, 'workspaceId', { max: 64 });
    return this._read(async (tx) => {
      const where = { workspace_id: workspaceId };
      if (taskId !== undefined && taskId !== null) where.task_id = taskId;
      const rows = await tx.selectRows('agentboard_run', { where, order: 'run_created' });
      if (principalId === undefined || principalId === null) return rows.map(buildRunWire);
      const out = [];
      for (const row of rows) {
        try {
          await this._assertVisible(tx, row.task_id, { principalId, workspaceId });
          out.push(buildRunWire(row));
        } catch (error) {
          if (isBoardError(error) && (error.code === 'AclDenied' || error.code === 'AuthRequired')) continue;
          throw error;
        }
      }
      return out;
    });
  }

  async listEvents(runId, { principalId = undefined, workspaceId = undefined } = {}) {
    requireText(runId, 'runId', { max: 64 });
    return this._read(async (tx) => {
      const run = await tx.selectRow('agentboard_run', { where: { run_id: runId } });
      if (!run) throw new NeedsInput(`unknown run ${String(runId)}`);
      if (principalId !== undefined && principalId !== null) {
        await this._assertVisible(tx, run.task_id, { principalId, workspaceId });
      }
      const rows = await tx.selectRows('agentboard_execution_event', { where: { run_id: runId }, order: 'event_sequence' });
      return rows.map(buildEventWire);
    });
  }

  async readBudgetGrant(grantId) {
    requireText(grantId, 'grantId', { max: 64 });
    return this._read(async (tx) => {
      const row = await tx.selectRow('agentboard_budget_grant', { where: { grant_id: grantId } });
      if (!row) throw new NeedsInput(`unknown budget grant ${String(grantId)}`);
      return buildGrantWire(row);
    });
  }

  async listBudgetGrants({ workspaceId, taskId = undefined } = {}) {
    requireText(workspaceId, 'workspaceId', { max: 64 });
    return this._read(async (tx) => {
      const where = { workspace_id: workspaceId };
      if (taskId !== undefined && taskId !== null) where.task_id = taskId;
      const rows = await tx.selectRows('agentboard_budget_grant', { where, order: 'grant_id' });
      return rows.map(buildGrantWire);
    });
  }

  async readBudgetSpend(grantId, dayKey) {
    requireText(grantId, 'grantId', { max: 64 });
    if (typeof dayKey !== 'string' || !DAY_KEY.test(dayKey)) {
      throw new NeedsInput('dayKey must be a UTC calendar day (YYYY-MM-DD)');
    }
    return this._read(async (tx) => {
      const row = await tx.selectRow('agentboard_budget_spend', { where: { grant_id: grantId, day_key: dayKey } });
      if (!row) return null;
      return {
        grant_id: row.grant_id,
        operation_id: row.operation_id,
        task_id: row.task_id,
        workspace_id: row.workspace_id,
        day_key: row.day_key,
        currency: row.currency,
        spent_task: Number(row.spent_task),
        spent_campaign: Number(row.spent_campaign),
        spent_day: Number(row.spent_day),
        updated_at: row.updated_at,
      };
    });
  }

  async listOutbox({ workspaceId, dispatchState = undefined, principalId = undefined } = {}) {
    requireText(workspaceId, 'workspaceId', { max: 64 });
    return this._read(async (tx) => {
      const where = { workspace_id: workspaceId };
      if (dispatchState !== undefined && dispatchState !== null) where.dispatch_state = dispatchState;
      const rows = await tx.selectRows('agentboard_outbox', { where, order: 'outbox_created' });
      if (principalId === undefined || principalId === null) return rows.map(buildOutboxWire);
      const out = [];
      for (const row of rows) {
        if (!row.task_id) { out.push(buildOutboxWire(row)); continue; }
        try {
          await this._assertVisible(tx, row.task_id, { principalId, workspaceId });
          out.push(buildOutboxWire(row));
        } catch (error) {
          if (isBoardError(error) && (error.code === 'AclDenied' || error.code === 'AuthRequired')) continue;
          throw error;
        }
      }
      return out;
    });
  }

  async listAudit({ workspaceId, taskId = undefined, limit = 100 } = {}) {
    requireText(workspaceId, 'workspaceId', { max: 64 });
    const max = requirePositiveInteger(limit, 'limit', 1000);
    return this._read(async (tx) => {
      const where = { workspace_id: workspaceId };
      if (taskId !== undefined && taskId !== null) where.task_id = taskId;
      const rows = await tx.selectRows('agentboard_audit', { where, order: 'audit_occurred', limit: max });
      return rows.map(buildAuditWire);
    });
  }

  async listReconciliations({ runId, principalId = undefined, workspaceId = undefined } = {}) {
    requireText(runId, 'runId', { max: 64 });
    return this._read(async (tx) => {
      const run = await tx.selectRow('agentboard_run', { where: { run_id: runId } });
      if (principalId !== undefined && principalId !== null) {
        if (run) await this._assertVisible(tx, run.task_id, { principalId, workspaceId });
      }
      const rows = await tx.selectRows('agentboard_reconciliation', { where: { run_id: runId }, order: 'reconciliation_created' });
      return rows.map(buildReconciliationWire);
    });
  }

  async readOperation(idempotencyKey) {
    if (typeof idempotencyKey !== 'string' || !HEX64.test(idempotencyKey)) {
      throw new NeedsInput('idempotencyKey must be 64 lowercase hex characters');
    }
    return this._read(async (tx) => {
      const row = await tx.selectRow('agentboard_operation', { where: { idempotency_key: idempotencyKey } });
      if (!row) return null;
      return buildOperationWire(row);
    });
  }

  // =========================================================================
  // WRITES
  // =========================================================================

  /**
   * createTask — a task is born in BACKLOG at revision 1 with an explicit ACL.
   * The caller-supplied state, revision, attempts, lease and adapter are
   * REFUSED, not silently normalized: creating a task that is already claimed
   * would be an authority escalation through the write path.
   */
  async createTask({ task, actor, actorKind, idempotencyKey, argsDigest, operation = 'board.task.create', outboxEvent = undefined }) {
    requireActor(actor);
    requireActorKind(actorKind);
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'createTask' });
    const document = validateTaskDocument(requirePlainObject(task, 'task'));
    if (document.state !== 'BACKLOG') {
      throw new BlockedPolicy('TASK_CREATE_STATE_ESCALATION', 'a task is created in BACKLOG; createTask never mints a task in an executing state');
    }
    if (Number(document.revision) !== 1 || Number(document.attempts) !== 0) {
      throw new MalformedResult('TASK_CREATE_COUNTERS', 'a new task has revision 1 and attempts 0');
    }
    if (document.active_lease_id !== null || document.fencing_token !== null || document.assigned_adapter_id !== null) {
      throw new BlockedPolicy('TASK_CREATE_ESCALATION', 'a new task carries no lease, fence or adapter; claimTask allocates them atomically');
    }
    if (document.acl.visibility === 'personal' && document.acl.allowed_principal_ids.length === 0) {
      throw new BlockedPolicy('TASK_CREATE_UNREADABLE', 'a personal task with an empty ACL list would be unreadable by anyone, including its creator');
    }
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const exists = await tx.selectRow('agentboard_task', { where: { task_id: document.task_id } });
      if (exists) {
        throw new IdempotencyConflict('TASK_ID_REUSED', `task ${document.task_id} already exists`);
      }
      const historyDigest = canonicalDigest([]);
      const row = {
        task_id: document.task_id,
        workspace_id: document.workspace_id,
        revision: 1,
        state: 'BACKLOG',
        priority: document.priority,
        title: document.title,
        goal: document.goal,
        description: document.description,
        dependencies: document.dependencies,
        required_capabilities: document.required_capabilities,
        allowed_tools: document.allowed_tools,
        workspace_ref: document.workspace_ref,
        time_limits: document.time_limits,
        cost_limits: document.cost_limits,
        brief_digest: storedFromWire(document.brief_digest, 'brief_digest'),
        policy_digest: storedFromWire(document.policy_digest, 'policy_digest'),
        manifest_digest: storedFromWire(document.manifest_digest, 'manifest_digest'),
        brief_validated: false,
        assigned_adapter_id: null,
        active_lease_id: null,
        fencing_token: null,
        attempts: 0,
        artifacts: [],
        evidence_refs: [],
        block_reason: null,
        history_digest: historyDigest,
        created_at: now,
        updated_at: now,
      };
      await tx.insertRow('agentboard_task', row);
      await tx.insertRow('agentboard_acl', {
        task_id: document.task_id,
        workspace_id: document.workspace_id,
        visibility: document.acl.visibility,
        allowed_principal_ids: document.acl.allowed_principal_ids,
        updated_at: now,
      });
      // The birth record is written BEFORE the task wire is built, because it
      // is the only place acceptance_criteria exists: migration 0008 has no
      // column for it (see the header). Writing it after the wire would make
      // every read of a freshly created task fail closed on its own record.
      await tx.insertRow('agentboard_audit', {
        audit_id: this.newId('audit'),
        workspace_id: document.workspace_id,
        task_id: document.task_id,
        actor,
        operation,
        idempotency_key: idem?.key ?? canonicalDigest({ operation, task_id: document.task_id, at: now }),
        outcome: 'COMMITTED',
        detail: {
          args_digest: idem?.digest ?? null,
          task: { acceptance_criteria: document.acceptance_criteria },
          time_limits: document.time_limits,
          cost_limits: document.cost_limits,
          workspace_ref: document.workspace_ref,
          brief_digest: document.brief_digest,
          policy_digest: document.policy_digest,
          manifest_digest: document.manifest_digest,
          state_at_create: 'BACKLOG',
          history_digest_at_create: `sha256:${historyDigest}`,
        },
        occurred_at: now,
      });
      const task = await this._taskWire(tx, document.task_id);
      const result = { task, task_id: task.task_id, revision: task.revision };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: document.workspace_id,
        task_id: document.task_id,
        event_type: outboxEvent.event_type ?? DEFAULT_OUTBOX_EVENT_TYPES.createTask,
        idempotency_key: idem?.key ?? canonicalDigest({ operation, task_id: document.task_id, at: now }),
        payload: outboxEvent.payload ?? { task_id: document.task_id, state: 'BACKLOG', revision: 1 },
      };
      return this._commitMark(tx, {
        // The audit row above IS this command's journal record; _commitMark
        // only has to close the transaction with the outbox row and the
        // operation marker, in that order.
        idem, workspaceId: document.workspace_id, operation, actor, audit: null, outbox, result, now,
      });
    });
  }

  /**
   * transitionTask — the single state-change entry point. `expectedRevision`
   * is a compare-and-swap; zero updated rows is RevisionConflict and nothing
   * was written. Guards live in policy.mjs; this method refuses only what the
   * frozen TRANSITIONS table and the lease invariant already forbid.
   */
  async transitionTask({
    taskId, toState, expectedRevision, actor, actorKind, reason, lease = undefined, fencingToken = undefined,
    idempotencyKey, argsDigest, operation = 'board.task.transition', outboxEvent = undefined, blockReason = undefined,
  }) {
    requireActor(actor);
    requireActorKind(actorKind);
    requireText(taskId, 'taskId', { max: 64 });
    requireText(toState, 'toState', { max: 16 });
    requireText(reason, 'reason', { max: 500 });
    requireRevision(expectedRevision, 'transitionTask');
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'transitionTask' });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const { task } = await this._loadTaskWithAcl(tx, taskId);
      if (!task) throw new NeedsInput(`unknown task ${String(taskId)}`);
      if (Number(task.revision) !== Number(expectedRevision)) {
        throw new RevisionConflict(
          'REVISION_CONFLICT',
          `task ${taskId} is at revision ${task.revision}, caller presented ${expectedRevision}`,
        );
      }
      if (toState === 'CLAIMED') {
        throw new TransitionNotAllowed('CLAIM_REQUIRES_LEASE', 'READY->CLAIMED is driven by claimTask, which allocates the lease and the fence atomically');
      }
      if (!isTransitionAllowed(task.state, toState)) {
        throw new TransitionNotAllowed('EDGE_NOT_ALLOWED', `${task.state} -> ${toState} is not an edge of the canonical transition table`);
      }
      const activeLease = await this._activeLease(tx, taskId);
      if (activeLease) {
        if (EXECUTING_STATES.includes(toState)) {
          this._requireFenceMatch(task, activeLease, fencingToken, 'transitionTask');
        } else {
          throw new TransitionNotAllowed(
            'ACTIVE_LEASE_MUST_BE_REVOKED_FIRST',
            `task ${taskId} still holds active lease ${activeLease.lease_id}; release or revoke it before moving out of ${task.state}`,
          );
        }
      } else if (task.active_lease_id !== null && task.active_lease_id !== undefined) {
        throw new NeedsInput('TASK_LEASE_POINTER_DANGLING', `task ${taskId} references lease ${task.active_lease_id} which is not ACTIVE`);
      } else if (fencingToken !== undefined && fencingToken !== null) {
        // A fence presented for a task that holds no active lease can never be
        // current; accepting it would be honouring a withdrawn right.
        this._requireFenceMatch(task, null, fencingToken, 'transitionTask');
      }
      const revision = Number(task.revision) + 1;
      // `lease` is accepted as either the lease record or its id (the
      // scheduler passes the id it just read back from the claim). The
      // transition always records the lease the fence was checked against, so
      // a caller can never journal a lease it did not actually hold.
      const presentedLeaseId = typeof lease === 'string' ? lease : (lease?.lease_id ?? null);
      const leaseId = activeLease?.lease_id ?? presentedLeaseId;
      const fence = fencingToken === undefined || fencingToken === null ? null : Number(fencingToken);
      const transition = await this._appendTransition(tx, {
        taskId,
        workspaceId: task.workspace_id,
        fromState: task.state,
        toState,
        actor,
        actorKind,
        idem: idem?.key ?? canonicalDigest({ operation, taskId, revision, at: now }),
        reason,
        leaseId,
        fencingToken: fence,
        revision,
        payload: { kind: 'state_transition', expected_revision: Number(expectedRevision) },
        now,
      });
      const historyDigest = await this._historyDigest(tx, taskId);
      const updated = await tx.updateRows('agentboard_task', {
        where: { task_id: taskId, revision: Number(expectedRevision) },
        sets: {
          state: toState,
          block_reason: toState === 'BLOCKED' ? requireText(blockReason ?? reason, 'blockReason', { max: 500 }) : null,
          history_digest: historyDigest,
          updated_at: now,
        },
        bump: 'revision',
        limit: 1,
      });
      if (updated.length === 0) {
        // Unreachable while the row lock is held, and a hard failure if it
        // ever is: better a typed refusal than a silent divergence.
        throw new RevisionConflict('REVISION_CONFLICT', `task ${taskId} changed under the writer`);
      }
      const taskWire = await this._taskWire(tx, taskId);
      const result = {
        task: taskWire,
        transition: buildTransitionWire(transition),
        task_id: taskId,
        revision: taskWire.revision,
      };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: task.workspace_id,
        task_id: taskId,
        event_type: outboxEvent.event_type ?? DEFAULT_OUTBOX_EVENT_TYPES.transitionTask,
        idempotency_key: idem?.key ?? canonicalDigest({ operation, taskId, revision, at: now }),
        payload: outboxEvent.payload ?? {
          task_id: taskId, from_state: task.state, to_state: toState, revision: taskWire.revision, fencing_token: fence,
        },
      };
      return this._commitMark(tx, {
        idem, workspaceId: task.workspace_id, operation, actor, outbox, result, now,
        audit: {
          task_id: taskId,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            from_state: task.state,
            to_state: toState,
            revision: taskWire.revision,
            transition_id: transition.transition_id,
            history_digest: `sha256:${historyDigest}`,
            lease_id: leaseId,
            fencing_token: fence,
          },
        },
      });
    });
  }

  /**
   * claimTask — READY -> CLAIMED with the unique active lease, in one
   * transaction, with a fencing token taken from
   * agentboard_fencing_token_seq.
   *
   * Concurrency: the task row is locked FOR UPDATE first, so two concurrent
   * claims serialize. The loser observes the winner's committed revision and
   * fails the compare-and-swap with REVISION_CONFLICT — the documented choice
   * for the loser of a claim race, because the stale `expectedRevision` is
   * exactly what the winner consumed. A claim that reaches the INSERT without
   * a correct expected revision can only lose against the partial unique
   * index `idx_agentboard_lease_single_active`, and that path is mapped to
   * TRANSITION_NOT_ALLOWED. Either way the loser leaves no partial row: the
   * whole transaction rolls back.
   */
  async claimTask({
    taskId, workspaceId, adapterId, ttlMs, expectedRevision, actor, actorKind,
    idempotencyKey, argsDigest, operation = 'board.task.claim',
  }) {
    requireActor(actor);
    requireActorKind(actorKind);
    requireText(taskId, 'taskId', { max: 64 });
    requireText(workspaceId, 'workspaceId', { max: 64 });
    requireText(adapterId, 'adapterId', { max: 64 });
    const ttl = requirePositiveInteger(ttlMs, 'ttlMs', MAX_TTL_MS);
    requireRevision(expectedRevision, 'claimTask');
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'claimTask' });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const task = (await tx.selectRow('agentboard_task', { where: { task_id: taskId }, forUpdate: true }));
      if (!task) throw new NeedsInput(`unknown task ${String(taskId)}`);
      if (task.workspace_id !== workspaceId) throw new AclDenied('cross_workspace_claim_denied');
      if (Number(task.revision) !== Number(expectedRevision)) {
        throw new RevisionConflict('REVISION_CONFLICT', `task ${taskId} is at revision ${task.revision}, caller presented ${expectedRevision}`);
      }
      if (!isTransitionAllowed(task.state, 'CLAIMED')) {
        throw new TransitionNotAllowed('EDGE_NOT_ALLOWED', `${task.state} -> CLAIMED is not an edge of the canonical transition table`);
      }
      const adapter = await tx.selectRow('agentboard_adapter', { where: { adapter_id: adapterId } });
      if (!adapter) throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', `adapter ${adapterId} is not registered`);
      if (adapter.workspace_id !== workspaceId) throw new AclDenied('cross_workspace_adapter_denied');
      if (adapter.health === 'unhealthy') throw new AgentUnavailable('ADAPTER_UNHEALTHY', `adapter ${adapterId} is unhealthy`);
      const existing = await this._activeLease(tx, taskId);
      if (existing) {
        throw new TransitionNotAllowed('LEASE_ALREADY_ACTIVE', `task ${taskId} already holds active lease ${existing.lease_id}`);
      }
      const fencingToken = await tx.nextFencingToken();
      const leaseId = this.newId('lease');
      await tx.insertRow('agentboard_lease', {
        lease_id: leaseId,
        task_id: taskId,
        workspace_id: task.workspace_id,
        adapter_id: adapterId,
        principal_id: actor,
        fencing_token: fencingToken,
        lease_state: 'ACTIVE',
        issued_at: now,
        expires_at: plusMs(now, ttl),
        released_at: null,
        revoked_reason: null,
      });
      const revision = Number(task.revision) + 1;
      const transition = await this._appendTransition(tx, {
        taskId,
        workspaceId: task.workspace_id,
        fromState: task.state,
        toState: 'CLAIMED',
        actor,
        actorKind,
        idem: idem?.key ?? canonicalDigest({ operation, taskId, revision, at: now }),
        reason: `lease ${leaseId} granted to ${adapterId} until ${plusMs(now, ttl)}`,
        leaseId,
        fencingToken,
        revision,
        payload: { kind: 'state_transition', adapter_id: adapterId, ttl_ms: ttl },
        now,
      });
      const historyDigest = await this._historyDigest(tx, taskId);
      const updated = await tx.updateRows('agentboard_task', {
        where: { task_id: taskId, revision: Number(expectedRevision) },
        sets: {
          state: 'CLAIMED',
          active_lease_id: leaseId,
          fencing_token: fencingToken,
          assigned_adapter_id: adapterId,
          attempts: Number(task.attempts) + 1,
          history_digest: historyDigest,
          updated_at: now,
        },
        bump: 'revision',
        limit: 1,
      });
      if (updated.length === 0) throw new RevisionConflict('REVISION_CONFLICT', `task ${taskId} changed under the writer`);
      const taskWire = await this._taskWire(tx, taskId);
      const leaseWire = buildLeaseWire(await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId } }));
      const result = {
        task: taskWire,
        lease: leaseWire,
        transition: buildTransitionWire(transition),
        task_id: taskId,
        lease_id: leaseId,
        fencing_token: fencingToken,
        revision: taskWire.revision,
        expires_at: leaseWire.expires_at,
      };
      return this._commitMark(tx, {
        idem, workspaceId: task.workspace_id, operation, actor, result, now,
        audit: {
          task_id: taskId,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            lease_id: leaseId,
            adapter_id: adapterId,
            fencing_token: fencingToken,
            ttl_ms: ttl,
            revision: taskWire.revision,
            transition_id: transition.transition_id,
            history_digest: `sha256:${historyDigest}`,
          },
        },
      });
    });
  }

  /**
   * renewLease — extends an ACTIVE lease at the current fence. No task state
   * changes, so no transition record is written (agentboard_transition
   * requires a strictly increasing revision); the audit record is the journal.
   */
  async renewLease({ leaseId, fencingToken, ttlMs, actor, idempotencyKey, argsDigest }) {
    const operation = 'board.lease.renew';
    requireActor(actor);
    requireText(leaseId, 'leaseId', { max: 64 });
    const ttl = requirePositiveInteger(ttlMs, 'ttlMs', MAX_TTL_MS);
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'renewLease' });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const lease = await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId }, forUpdate: true });
      if (!lease) throw new NeedsInput(`unknown lease ${String(leaseId)}`);
      const task = await tx.selectRow('agentboard_task', { where: { task_id: lease.task_id }, forUpdate: true });
      if (!task) throw new NeedsInput(`unknown task ${String(lease.task_id)}`);
      this._requireFenceMatch(task, lease, fencingToken, 'renewLease');
      const expiresAt = plusMs(now, ttl);
      const updated = await tx.updateRows('agentboard_lease', {
        where: { lease_id: leaseId, lease_state: 'ACTIVE', fencing_token: Number(fencingToken) },
        sets: { expires_at: expiresAt },
        limit: 1,
      });
      if (updated.length === 0) throw new StaleFence('LEASE_NOT_ACTIVE', `lease ${leaseId} is no longer ACTIVE at fence ${String(fencingToken)}`);
      const leaseWire = buildLeaseWire(await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId } }));
      const result = { lease: leaseWire, lease_id: leaseId, fencing_token: Number(fencingToken), expires_at: expiresAt };
      return this._commitMark(tx, {
        idem, workspaceId: lease.workspace_id, operation, actor, result, now,
        audit: {
          task_id: lease.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            lease_id: leaseId,
            fencing_token: Number(fencingToken),
            ttl_ms: ttl,
            expires_at: expiresAt,
            previous_expires_at: lease.expires_at,
          },
        },
      });
    });
  }

  /**
   * releaseLease — the holder gives the right back voluntarily: the lease
   * becomes RELEASED, the task pointer is cleared, the revision is bumped and
   * the state moves to `toState` (READY by default) in the same transaction.
   */
  async releaseLease({
    leaseId, fencingToken, reason, expectedRevision, actor, actorKind, idempotencyKey, argsDigest,
    operation = 'board.lease.release', toState = 'READY', outboxEvent = undefined,
  }) {
    requireActor(actor);
    requireActorKind(actorKind);
    requireText(leaseId, 'leaseId', { max: 64 });
    requireText(reason, 'reason', { max: 500 });
    requireText(toState, 'toState', { max: 16 });
    requireRevision(expectedRevision, 'releaseLease');
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'releaseLease' });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const lease = await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId }, forUpdate: true });
      if (!lease) throw new NeedsInput(`unknown lease ${String(leaseId)}`);
      const task = await tx.selectRow('agentboard_task', { where: { task_id: lease.task_id }, forUpdate: true });
      if (!task) throw new NeedsInput(`unknown task ${String(lease.task_id)}`);
      this._requireFenceMatch(task, lease, fencingToken, 'releaseLease');
      if (Number(task.revision) !== Number(expectedRevision)) {
        throw new RevisionConflict('REVISION_CONFLICT', `task ${task.task_id} is at revision ${task.revision}, caller presented ${expectedRevision}`);
      }
      if (!isTransitionAllowed(task.state, toState)) {
        throw new TransitionNotAllowed('EDGE_NOT_ALLOWED', `${task.state} -> ${toState} is not an edge of the canonical transition table`);
      }
      const updated = await tx.updateRows('agentboard_lease', {
        where: { lease_id: leaseId, lease_state: 'ACTIVE', fencing_token: Number(fencingToken) },
        sets: { lease_state: 'RELEASED', released_at: now, revoked_reason: reason },
        limit: 1,
      });
      if (updated.length === 0) throw new StaleFence('LEASE_NOT_ACTIVE', `lease ${leaseId} is no longer ACTIVE at fence ${String(fencingToken)}`);
      const revision = Number(task.revision) + 1;
      const transition = await this._appendTransition(tx, {
        taskId: task.task_id,
        workspaceId: task.workspace_id,
        fromState: task.state,
        toState,
        actor,
        actorKind,
        idem: idem?.key ?? canonicalDigest({ operation, leaseId, revision, at: now }),
        reason,
        leaseId,
        fencingToken: Number(fencingToken),
        revision,
        payload: { kind: 'state_transition', lease_released: true, adapter_id: lease.adapter_id },
        now,
      });
      const historyDigest = await this._historyDigest(tx, task.task_id);
      const taskUpdated = await tx.updateRows('agentboard_task', {
        where: { task_id: task.task_id, revision: Number(expectedRevision) },
        sets: {
          state: toState,
          active_lease_id: null,
          fencing_token: null,
          history_digest: historyDigest,
          updated_at: now,
        },
        bump: 'revision',
        limit: 1,
      });
      if (taskUpdated.length === 0) throw new RevisionConflict('REVISION_CONFLICT', `task ${task.task_id} changed under the writer`);
      const leaseWire = buildLeaseWire(await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId } }));
      const taskWire = await this._taskWire(tx, task.task_id);
      const result = {
        lease: leaseWire,
        task: taskWire,
        transition: buildTransitionWire(transition),
        task_id: task.task_id,
        lease_id: leaseId,
        revision: taskWire.revision,
      };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: task.workspace_id,
        task_id: task.task_id,
        event_type: outboxEvent.event_type ?? 'board.lease.released',
        idempotency_key: idem?.key ?? canonicalDigest({ operation, leaseId, at: now }),
        payload: outboxEvent.payload ?? { task_id: task.task_id, lease_id: leaseId, state: toState, fencing_token: Number(fencingToken) },
      };
      return this._commitMark(tx, {
        idem, workspaceId: task.workspace_id, operation, actor, outbox, result, now,
        audit: {
          task_id: task.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            lease_id: leaseId,
            fencing_token: Number(fencingToken),
            from_state: task.state,
            to_state: toState,
            revision: taskWire.revision,
            transition_id: transition.transition_id,
            history_digest: `sha256:${historyDigest}`,
          },
        },
      });
    });
  }

  /**
   * reassignLease — revoke BEFORE reassign, always. The old lease is marked
   * REVOKED in this transaction and a NEW lease is issued with a NEW, strictly
   * greater fencing token, so a late callback from the previous adapter is
   * stale by construction and can never mutate the task. The task state does
   * not change, so the journal entry is classified `lease_rebind`.
   */
  async reassignLease({
    leaseId, fencingToken, newAdapterId, reason, actor, actorKind, idempotencyKey, argsDigest,
    operation = 'board.lease.reassign', ttlMs = undefined, outboxEvent = undefined,
  }) {
    requireActor(actor);
    requireActorKind(actorKind);
    requireText(leaseId, 'leaseId', { max: 64 });
    requireText(newAdapterId, 'newAdapterId', { max: 64 });
    requireText(reason, 'reason', { max: 500 });
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'reassignLease' });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const lease = await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId }, forUpdate: true });
      if (!lease) throw new NeedsInput(`unknown lease ${String(leaseId)}`);
      const task = await tx.selectRow('agentboard_task', { where: { task_id: lease.task_id }, forUpdate: true });
      if (!task) throw new NeedsInput(`unknown task ${String(lease.task_id)}`);
      this._requireFenceMatch(task, lease, fencingToken, 'reassignLease');
      const adapter = await tx.selectRow('agentboard_adapter', { where: { adapter_id: newAdapterId } });
      if (!adapter) throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', `adapter ${newAdapterId} is not registered`);
      if (adapter.workspace_id !== task.workspace_id) throw new AclDenied('cross_workspace_adapter_denied');
      if (adapter.health === 'unhealthy') throw new AgentUnavailable('ADAPTER_UNHEALTHY', `adapter ${newAdapterId} is unhealthy`);
      // 1. revoke the previous right …
      const revoked = await tx.updateRows('agentboard_lease', {
        where: { lease_id: leaseId, lease_state: 'ACTIVE', fencing_token: Number(fencingToken) },
        sets: { lease_state: 'REVOKED', released_at: now, revoked_reason: reason },
        limit: 1,
      });
      if (revoked.length === 0) throw new StaleFence('LEASE_NOT_ACTIVE', `lease ${leaseId} is no longer ACTIVE at fence ${String(fencingToken)}`);
      // 2. … and only then issue the new one.
      const previousWindow = Math.max(1, Date.parse(lease.expires_at) - Date.parse(lease.issued_at));
      const ttl = ttlMs === undefined || ttlMs === null ? previousWindow : requirePositiveInteger(ttlMs, 'ttlMs', MAX_TTL_MS);
      const nextFence = await tx.nextFencingToken();
      if (nextFence <= Number(fencingToken)) {
        throw new StaleFence('FENCE_NOT_MONOTONIC', `fencing sequence produced ${nextFence} which is not greater than ${String(fencingToken)}`);
      }
      const newLeaseId = this.newId('lease');
      await tx.insertRow('agentboard_lease', {
        lease_id: newLeaseId,
        task_id: task.task_id,
        workspace_id: task.workspace_id,
        adapter_id: newAdapterId,
        principal_id: adapter.principal_id,
        fencing_token: nextFence,
        lease_state: 'ACTIVE',
        issued_at: now,
        expires_at: plusMs(now, ttl),
        released_at: null,
        revoked_reason: null,
      });
      const revision = Number(task.revision) + 1;
      const transition = await this._appendTransition(tx, {
        taskId: task.task_id,
        workspaceId: task.workspace_id,
        fromState: task.state,
        toState: task.state,
        actor,
        actorKind,
        idem: idem?.key ?? canonicalDigest({ operation, leaseId, revision, at: now }),
        reason,
        leaseId: newLeaseId,
        fencingToken: nextFence,
        revision,
        payload: {
          kind: 'lease_rebind',
          previous_lease_id: leaseId,
          previous_adapter_id: lease.adapter_id,
          previous_fencing_token: Number(fencingToken),
          new_adapter_id: newAdapterId,
          new_fencing_token: nextFence,
        },
        now,
      });
      const historyDigest = await this._historyDigest(tx, task.task_id);
      const taskUpdated = await tx.updateRows('agentboard_task', {
        where: { task_id: task.task_id, revision: Number(task.revision) },
        sets: {
          active_lease_id: newLeaseId,
          fencing_token: nextFence,
          assigned_adapter_id: newAdapterId,
          history_digest: historyDigest,
          updated_at: now,
        },
        bump: 'revision',
        limit: 1,
      });
      if (taskUpdated.length === 0) throw new RevisionConflict('REVISION_CONFLICT', `task ${task.task_id} changed under the writer`);
      const result = {
        lease: buildLeaseWire(await tx.selectRow('agentboard_lease', { where: { lease_id: newLeaseId } })),
        previous_lease: buildLeaseWire(await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId } })),
        task: await this._taskWire(tx, task.task_id),
        transition: buildTransitionWire(transition),
        task_id: task.task_id,
        lease_id: newLeaseId,
        fencing_token: nextFence,
        revision: Number(task.revision) + 1,
      };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: task.workspace_id,
        task_id: task.task_id,
        event_type: outboxEvent.event_type ?? 'board.lease.reassigned',
        idempotency_key: idem?.key ?? canonicalDigest({ operation, leaseId, at: now }),
        payload: outboxEvent.payload ?? { task_id: task.task_id, lease_id: newLeaseId, fencing_token: nextFence, adapter_id: newAdapterId },
      };
      return this._commitMark(tx, {
        idem, workspaceId: task.workspace_id, operation, actor, outbox, result, now,
        audit: {
          task_id: task.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            previous_lease_id: leaseId,
            previous_fencing_token: Number(fencingToken),
            lease_id: newLeaseId,
            fencing_token: nextFence,
            adapter_id: newAdapterId,
            revision: Number(task.revision) + 1,
            transition_id: transition.transition_id,
            history_digest: `sha256:${historyDigest}`,
          },
        },
      });
    });
  }

  /**
   * revokeLease — withdraws the right without handing it to anybody. The task
   * state is NOT decided here: a revocation is followed by an explicit,
   * policy-guarded transition (cancel, block, requeue after reconciliation).
   */
  async revokeLease({
    leaseId, fencingToken, reason, actor, actorKind, idempotencyKey, argsDigest,
    operation = 'board.lease.revoke', outboxEvent = undefined,
  }) {
    requireActor(actor);
    requireActorKind(actorKind);
    requireText(leaseId, 'leaseId', { max: 64 });
    requireText(reason, 'reason', { max: 500 });
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'revokeLease' });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const lease = await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId }, forUpdate: true });
      if (!lease) throw new NeedsInput(`unknown lease ${String(leaseId)}`);
      const task = await tx.selectRow('agentboard_task', { where: { task_id: lease.task_id }, forUpdate: true });
      if (!task) throw new NeedsInput(`unknown task ${String(lease.task_id)}`);
      this._requireFenceMatch(task, lease, fencingToken, 'revokeLease');
      const revoked = await tx.updateRows('agentboard_lease', {
        where: { lease_id: leaseId, lease_state: 'ACTIVE', fencing_token: Number(fencingToken) },
        sets: { lease_state: 'REVOKED', released_at: now, revoked_reason: reason },
        limit: 1,
      });
      if (revoked.length === 0) throw new StaleFence('LEASE_NOT_ACTIVE', `lease ${leaseId} is no longer ACTIVE at fence ${String(fencingToken)}`);
      const revision = Number(task.revision) + 1;
      const transition = await this._appendTransition(tx, {
        taskId: task.task_id,
        workspaceId: task.workspace_id,
        fromState: task.state,
        toState: task.state,
        actor,
        actorKind,
        idem: idem?.key ?? canonicalDigest({ operation, leaseId, revision, at: now }),
        reason,
        leaseId,
        fencingToken: Number(fencingToken),
        revision,
        payload: { kind: 'lease_revoke', adapter_id: lease.adapter_id },
        now,
      });
      const historyDigest = await this._historyDigest(tx, task.task_id);
      const taskUpdated = await tx.updateRows('agentboard_task', {
        where: { task_id: task.task_id, revision: Number(task.revision) },
        sets: {
          active_lease_id: null,
          fencing_token: null,
          history_digest: historyDigest,
          updated_at: now,
        },
        bump: 'revision',
        limit: 1,
      });
      if (taskUpdated.length === 0) throw new RevisionConflict('REVISION_CONFLICT', `task ${task.task_id} changed under the writer`);
      const result = {
        lease: buildLeaseWire(await tx.selectRow('agentboard_lease', { where: { lease_id: leaseId } })),
        task: await this._taskWire(tx, task.task_id),
        transition: buildTransitionWire(transition),
        task_id: task.task_id,
        lease_id: leaseId,
        revision,
      };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: task.workspace_id,
        task_id: task.task_id,
        event_type: outboxEvent.event_type ?? 'board.lease.revoked',
        idempotency_key: idem?.key ?? canonicalDigest({ operation, leaseId, at: now }),
        payload: outboxEvent.payload ?? { task_id: task.task_id, lease_id: leaseId, fencing_token: Number(fencingToken), reason },
      };
      return this._commitMark(tx, {
        idem, workspaceId: task.workspace_id, operation, actor, outbox, result, now,
        audit: {
          task_id: task.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            lease_id: leaseId,
            fencing_token: Number(fencingToken),
            reason,
            revision,
            transition_id: transition.transition_id,
            history_digest: `sha256:${historyDigest}`,
          },
        },
      });
    });
  }

  /**
   * expireLeases — the sweep. The DECISION is made against the DATABASE clock
   * (never the process clock and never the caller's idea of "now"); the `now`
   * argument is only recorded as the request marker. For every lease whose
   * expires_at has passed the right is withdrawn first (lease -> EXPIRED, task
   * pointer cleared, revision bumped, journal entry written). If a run was
   * still live on that lease the outcome is unknown, so the run becomes
   * RECONCILIATION_REQUIRED and an outbox row asks for an authorized decision:
   * never a blind retry.
   *
   * WHY `workspaceId` IS REQUIRED
   * The sweep is a WRITE, and an unscoped write across every `agentboard_lease`
   * row in the installation would be the one path in this file that ignores the
   * tenancy rule every other path enforces: `claimTask` refuses
   * `cross_workspace_claim_denied`, `createRun` refuses
   * `cross_workspace_run_denied`, and `_assertVisible` refuses a cross-workspace
   * read absolutely. A caller holding a handle to this store in workspace A
   * could otherwise withdraw every lease in workspace B.
   *
   * It also has to be in the scope for a non-security reason: a sweep reads
   * `lease_state = 'ACTIVE'` and no lease, so a caller that had a global view
   * would mutate rows it never enumerated and could not attribute. `workspaceId`
   * bounds both the decision and the journal, and it is part of the ledger key
   * so two workspaces swept at the same database instant are two operations
   * rather than one operation replayed into the wrong workspace.
   */
  async expireLeases({ actor, workspaceId, now: requestedAt = undefined } = {}) {
    const operation = 'board.lease.expire';
    requireActor(actor);
    const workspace = requireText(workspaceId, 'expireLeases workspaceId', { max: 64 });
    const marker = requestedAt === undefined || requestedAt === null ? null : toIsoMs(requestedAt, 'now');
    return this._write(async (tx) => {
      const now = await tx.now();
      // The ledger key is derived from the observed database time, so a sweep
      // is a distinct operation per instant and a re-sweep cannot double-spend.
      const key = canonicalDigest({ operation, actor, workspace, now });
      const idem = { key, digest: canonicalDigest({ operation, actor, workspace, now }) };
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const due = await tx.selectRows('agentboard_lease', {
        where: { lease_state: 'ACTIVE', workspace_id: workspace },
        order: 'lease_id',
      });
      const expired = [];
      for (const lease of due) {
        if (Date.parse(lease.expires_at) > Date.parse(now)) continue;
        const task = await tx.selectRow('agentboard_task', { where: { task_id: lease.task_id }, forUpdate: true });
        if (!task) continue;
        // Defence in depth: the row filter already bounds the sweep to one
        // workspace, and a lease whose task row names a different one is a
        // corrupt pair that this sweep must not act on.
        if (task.workspace_id !== workspace) continue;
        const stillActive = await tx.selectRow('agentboard_lease', { where: { lease_id: lease.lease_id, lease_state: 'ACTIVE' }, forUpdate: true });
        if (!stillActive) continue;
        await tx.updateRows('agentboard_lease', {
          where: { lease_id: lease.lease_id, lease_state: 'ACTIVE' },
          sets: { lease_state: 'EXPIRED', released_at: now, revoked_reason: 'lease expiry observed against the database clock' },
          limit: 1,
        });
        const revision = Number(task.revision) + 1;
        const transition = await this._appendTransition(tx, {
          taskId: task.task_id,
          workspaceId: task.workspace_id,
          fromState: task.state,
          toState: task.state,
          actor,
          actorKind: 'system',
          idem: key,
          reason: `lease ${lease.lease_id} expired at ${lease.expires_at} (database clock ${now})`,
          leaseId: lease.lease_id,
          fencingToken: Number(lease.fencing_token),
          revision,
          // Withdrawn, not rebound. A rebind is the reassign case (a new lease
          // carries a strictly greater fence); an expiry issues nothing, so
          // filing it under `lease_rebind` would make the journal unable to
          // tell "somebody else took over" from "the right simply ran out".
          payload: {
            kind: 'lease_expire',
            expired_at: lease.expires_at,
            observed_at: now,
            previous_fencing_token: Number(lease.fencing_token),
          },
          now,
        });
        const historyDigest = await this._historyDigest(tx, task.task_id);
        const taskUpdated = await tx.updateRows('agentboard_task', {
          where: { task_id: task.task_id, revision: Number(task.revision) },
          sets: { active_lease_id: null, fencing_token: null, history_digest: historyDigest, updated_at: now },
          bump: 'revision',
          limit: 1,
        });
        // Unreachable while the row lock is held, and a hard failure if it
        // ever is: the whole point of a sweep is that it is unattended, so a
        // silently skipped revision bump would leave the journal claiming a
        // revision the task row never reached.
        if (taskUpdated.length === 0) {
          throw new RevisionConflict('REVISION_CONFLICT', `task ${task.task_id} changed under the expiry sweep`);
        }
        let runId = null;
        // A task may own SEVERAL historical runs, so the live one cannot be
        // assumed to be the oldest: every run of the task is examined and the
        // live run bound to THIS lease is the one escalated. Missing it would
        // leave an unknown external side effect looking like a clean failure.
        const taskRuns = await tx.selectRows('agentboard_run', {
          where: { task_id: task.task_id },
          order: 'run_created',
        });
        const live = taskRuns.find((row) => LIVE_RUN_STATES.includes(row.run_state) && row.lease_id === lease.lease_id) ?? null;
        if (live) {
          runId = live.run_id;
          await tx.updateRows('agentboard_run', {
            where: { run_id: live.run_id },
            sets: { run_state: 'RECONCILIATION_REQUIRED', completed_at: now },
            limit: 1,
          });
          await this._insertOutbox(tx, {
            workspace_id: task.workspace_id,
            task_id: task.task_id,
            run_id: live.run_id,
            event_type: DEFAULT_OUTBOX_EVENT_TYPES.leaseExpired,
            idempotency_key: canonicalDigest({ kind: 'lease_expired', run_id: live.run_id, lease_id: lease.lease_id }),
            payload: {
              run_id: live.run_id,
              task_id: task.task_id,
              lease_id: lease.lease_id,
              fencing_token: Number(lease.fencing_token),
              reason: 'lease expired while the run was still live; the external side effect is unknown',
            },
          }, {
            now,
            // Born terminal: the dispatch itself may already have crossed the
            // boundary, so this row may never be picked up as re-dispatchable
            // work. An authorized human or gate decision closes it.
            dispatchState: 'RECONCILIATION_REQUIRED',
            lastError: 'lease expired while the run was still live; the external side effect is unknown',
          });
        }
        await tx.insertRow('agentboard_audit', {
          audit_id: this.newId('audit'),
          workspace_id: task.workspace_id,
          task_id: task.task_id,
          actor,
          operation,
          idempotency_key: key,
          outcome: 'COMMITTED',
          detail: {
            args_digest: idem.digest,
            lease_id: lease.lease_id,
            run_id: runId,
            fencing_token: Number(lease.fencing_token),
            expired_at: lease.expires_at,
            requested_at: marker,
            revision,
            transition_id: transition.transition_id,
            history_digest: `sha256:${historyDigest}`,
          },
          occurred_at: now,
        });
        expired.push({
          lease_id: lease.lease_id,
          task_id: task.task_id,
          adapter_id: lease.adapter_id,
          fencing_token: Number(lease.fencing_token),
          state: task.state,
          revision,
          run_id: runId,
        });
      }
      const result = { expired, now, requested_at: marker, workspace_id: workspace };
      await tx.insertRow('agentboard_operation', {
        idempotency_key: idem.key,
        workspace_id: workspace,
        operation,
        args_digest: idem.digest,
        result_payload: result,
        actor,
        committed_at: now,
      });
      return { ...result, replayed: false };
    });
  }

  /**
   * registerAdapter — insert-only. A registration is a CLAIM about what an
   * executor can do; re-registering the same identity with different content is
   * a conflict, never an in-place rewrite of the claim.
   */
  async registerAdapter({ registration, actor, idempotencyKey, argsDigest, operation = 'board.adapter.register', outboxEvent = undefined }) {
    requireActor(actor);
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'registerAdapter' });
    const document = assertBoardContract('adapter-registration', requirePlainObject(registration, 'registration'), MalformedResult);
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const existing = await tx.selectRow('agentboard_adapter', { where: { adapter_id: document.adapter_id } });
      if (existing) {
        if (sameJson(buildAdapterWire(existing), document)) {
          return this._commitMark(tx, {
            idem, workspaceId: document.workspace_id, operation, actor, result: { adapter: document, adapter_id: document.adapter_id }, now,
            audit: { task_id: null, idempotency_key: idem?.key, detail: { args_digest: idem?.digest ?? null, adapter_id: document.adapter_id, unchanged: true } },
          });
        }
        throw new IdempotencyConflict('ADAPTER_REUSED_WITH_DIFFERENT_CONTENT', `adapter ${document.adapter_id} is already registered with a different registration`);
      }
      const row = {
        adapter_id: document.adapter_id,
        workspace_id: document.workspace_id,
        provider: document.provider,
        display_name: document.display_name,
        adapter_kind: document.adapter_kind,
        health: document.health,
        principal_id: document.principal_id,
        declared_capabilities: document.declared_capabilities,
        declared_tools: document.declared_tools,
        sandbox_profile_id: document.sandbox_profile_id,
        max_concurrency: document.max_concurrency,
        provenance_status: document.real_adapter_provenance.status,
        provenance_detail: document.real_adapter_provenance.detail,
        registered_at: now,
      };
      await tx.insertRow('agentboard_adapter', row);
      const result = { adapter: buildAdapterWire(row), adapter_id: row.adapter_id };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: row.workspace_id,
        task_id: null,
        event_type: outboxEvent.event_type ?? 'board.adapter.registered',
        idempotency_key: idem?.key ?? canonicalDigest({ operation, adapter_id: row.adapter_id, at: now }),
        payload: outboxEvent.payload ?? { adapter_id: row.adapter_id, adapter_kind: row.adapter_kind, provenance_status: row.provenance_status },
      };
      return this._commitMark(tx, {
        idem, workspaceId: row.workspace_id, operation, actor, outbox, result, now,
        audit: {
          task_id: null,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            adapter_id: row.adapter_id,
            adapter_kind: row.adapter_kind,
            provenance_status: row.provenance_status,
            declared_capabilities: row.declared_capabilities,
          },
        },
      });
    });
  }

  /**
   * updateAdapterHealth — the only sanctioned in-place change to a
   * registration. It is validated by rebuilding the whole registration
   * document and asserting it against the contract, so the health enum is
   * never re-declared here.
   */
  async updateAdapterHealth({ adapterId, health, actor, idempotencyKey, argsDigest, operation = 'board.adapter.health', outboxEvent = undefined }) {
    requireActor(actor);
    requireText(adapterId, 'adapterId', { max: 64 });
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'updateAdapterHealth' });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const row = await tx.selectRow('agentboard_adapter', { where: { adapter_id: adapterId }, forUpdate: true });
      if (!row) throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', `adapter ${adapterId} is not registered`);
      const updated = await tx.updateRows('agentboard_adapter', {
        where: { adapter_id: adapterId },
        sets: { health },
        limit: 1,
      });
      if (updated.length === 0) throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', `adapter ${adapterId} vanished under the writer`);
      // Rebuild + assert: an unknown health value is a contract violation and
      // therefore a typed MalformedResult, not a silently stored string.
      const adapter = buildAdapterWire(updated[0]);
      const result = { adapter, adapter_id: adapterId, health: adapter.health };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: row.workspace_id,
        task_id: null,
        event_type: outboxEvent.event_type ?? 'board.adapter.health',
        idempotency_key: idem?.key ?? canonicalDigest({ operation, adapter_id: adapterId, at: now }),
        payload: outboxEvent.payload ?? { adapter_id: adapterId, health: adapter.health },
      };
      return this._commitMark(tx, {
        idem, workspaceId: row.workspace_id, operation, actor, outbox, result, now,
        audit: {
          task_id: null,
          idempotency_key: idem?.key,
          detail: { args_digest: idem?.digest ?? null, adapter_id: adapterId, health: adapter.health, previous_health: row.health },
        },
      });
    });
  }

  /**
   * grantBudget — insert-only numeric authorization. A grant is never updated
   * in place: changing a budget means issuing a new grant, so a hidden budget
   * change cannot ride in on a repeat of an existing command.
   */
  async grantBudget({ grant, actor, idempotencyKey, argsDigest, operation = 'board.budget.grant', outboxEvent = undefined }) {
    requireActor(actor);
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'grantBudget' });
    const document = requirePlainObject(grant, 'grant');
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const grantId = requireText(document.grant_id, 'grant.grant_id', { max: 64 });
      const workspaceId = requireText(document.workspace_id, 'grant.workspace_id', { max: 64 });
      const grantedBy = requireText(document.granted_by, 'grant.granted_by', { max: 64 });
      if (!PRINCIPAL_ID.test(grantedBy)) throw new NeedsInput('grant.granted_by must be a prn-… principal');
      const limits = {
        task_limit: document.task_limit,
        campaign_limit: document.campaign_limit,
        day_limit: document.day_limit,
      };
      for (const [key, value] of Object.entries(limits)) {
        if (value !== null && value !== undefined) {
          if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
            throw new NeedsInput(`grant.${key} must be a positive number or null; an unassigned budget is not zero`);
          }
        }
      }
      if (document.timeout_ms !== null && document.timeout_ms !== undefined) {
        requirePositiveInteger(document.timeout_ms, 'grant.timeout_ms', MAX_TTL_MS);
      }
      const row = {
        grant_id: grantId,
        workspace_id: workspaceId,
        task_id: document.task_id ?? null,
        currency: document.currency,
        task_limit: document.task_limit ?? null,
        campaign_limit: document.campaign_limit ?? null,
        day_limit: document.day_limit ?? null,
        timeout_ms: document.timeout_ms ?? null,
        granted_by: grantedBy,
        granted_at: now,
        expires_at: document.expires_at === undefined || document.expires_at === null ? null : toIsoMs(document.expires_at, 'grant.expires_at'),
        revoked_at: document.revoked_at === undefined || document.revoked_at === null ? null : toIsoMs(document.revoked_at, 'grant.revoked_at'),
      };
      const existing = await tx.selectRow('agentboard_budget_grant', { where: { grant_id: grantId } });
      if (existing) {
        if (sameJson(buildGrantWire(existing), buildGrantWire(row))) {
          return this._commitMark(tx, {
            idem, workspaceId, operation, actor, result: { grant: buildGrantWire(existing), grant_id: grantId }, now,
            audit: { task_id: row.task_id, idempotency_key: idem?.key, detail: { args_digest: idem?.digest ?? null, grant_id: grantId, unchanged: true } },
          });
        }
        throw new IdempotencyConflict('BUDGET_GRANT_REUSED_WITH_DIFFERENT_LIMITS', `grant ${grantId} already exists with different limits; issue a new grant instead of rewriting one`);
      }
      await tx.insertRow('agentboard_budget_grant', row);
      const result = { grant: buildGrantWire(row), grant_id: grantId };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: workspaceId,
        task_id: row.task_id,
        event_type: outboxEvent.event_type ?? 'board.budget.granted',
        idempotency_key: idem?.key ?? canonicalDigest({ operation, grant_id: grantId, at: now }),
        payload: outboxEvent.payload ?? { grant_id: grantId, task_id: row.task_id, currency: row.currency },
      };
      return this._commitMark(tx, {
        idem, workspaceId, operation, actor, outbox, result, now,
        audit: {
          task_id: row.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            grant_id: grantId,
            task_limit: row.task_limit,
            campaign_limit: row.campaign_limit,
            day_limit: row.day_limit,
            currency: row.currency,
            granted_by: grantedBy,
          },
        },
      });
    });
  }

  /**
   * createRun — binds a contract-valid ExecutionRequest to the CURRENT lease
   * and fence, and creates the dispatch outbox row in the same transaction.
   * The task state is not changed here: the caller drives the state machine
   * with the fence it already holds.
   */
  async createRun({ request, actor, idempotencyKey, argsDigest, operation = 'board.execution.start', outboxEvent = undefined }) {
    requireActor(actor);
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'createRun' });
    const document = assertBoardContract('execution-request', requirePlainObject(request, 'request'), MalformedResult);
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const task = await tx.selectRow('agentboard_task', { where: { task_id: document.task_id }, forUpdate: true });
      if (!task) throw new NeedsInput(`unknown task ${String(document.task_id)}`);
      if (task.workspace_id !== document.workspace_id) throw new AclDenied('cross_workspace_run_denied');
      // The run must be bound to the documents the task was created with; a
      // swapped brief, policy or manifest is a refusal, not a new run.
      if (storedFromWire(document.brief_digest, 'request.brief_digest') !== task.brief_digest
        || storedFromWire(document.policy_digest, 'request.policy_digest') !== task.policy_digest
        || storedFromWire(document.manifest_digest, 'request.manifest_digest') !== task.manifest_digest) {
        throw new MalformedResult('RUN_DIGESTS_DISAGREE', 'the request digests do not describe the current immutable task documents');
      }
      if (!sameJson(document.workspace_ref, task.workspace_ref)) {
        throw new CapabilityMismatch('RUN_WORKSPACE_DISAGREES', 'a run may not be bound to a workspace other than the task workspace_ref');
      }
      const notAllowed = document.allowed_tools.filter((tool) => !task.allowed_tools.includes(tool));
      if (notAllowed.length > 0) {
        throw new CapabilityMismatch('RUN_TOOL_GRANT_WIDER', `tools not granted by the task: ${notAllowed.join(',')}`);
      }
      const lease = await tx.selectRow('agentboard_lease', { where: { lease_id: document.lease_id }, forUpdate: true });
      const fence = this._requireFenceMatch(task, lease, document.fencing_token, 'createRun');
      if (lease.task_id !== task.task_id) {
        throw new StaleFence('LEASE_BELONGS_TO_OTHER_TASK', `lease ${document.lease_id} does not belong to task ${task.task_id}`);
      }
      const adapter = await tx.selectRow('agentboard_adapter', { where: { adapter_id: document.adapter_id } });
      if (!adapter) throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', `adapter ${document.adapter_id} is not registered`);
      if (adapter.workspace_id !== task.workspace_id) throw new AclDenied('cross_workspace_adapter_denied');
      if (adapter.health === 'unhealthy') throw new AgentUnavailable('ADAPTER_UNHEALTHY', `adapter ${document.adapter_id} is unhealthy`);
      if (!EXECUTING_STATES.includes(task.state)) {
        throw new TransitionNotAllowed('RUN_NOT_ADMITTED', `task ${task.task_id} is ${task.state}; a run is only admitted from CLAIMED or RUNNING`);
      }
      const live = await tx.selectRows('agentboard_run', { where: { task_id: task.task_id }, order: 'run_created' });
      if (live.some((row) => LIVE_RUN_STATES.includes(row.run_state))) {
        throw new TransitionNotAllowed('RUN_ALREADY_LIVE', `task ${task.task_id} already has a live run`);
      }
      // Budget: an unassigned budget is not zero. Every scope of the request
      // must be covered by a live grant for this task, with the same numbers.
      const grant = await tx.selectRow('agentboard_budget_grant', { where: { grant_id: document.budget_grant.grant_id ?? null } });
      const grantForTask = (await tx.selectRows('agentboard_budget_grant', { where: { task_id: task.task_id }, order: 'grant_id' }))
        .find((row) => row.revoked_at === null && (row.expires_at === null || Date.parse(row.expires_at) > Date.parse(now)));
      if (!grantForTask) {
        throw new BudgetExceeded('BUDGET_NOT_ASSIGNED', `task ${task.task_id} has no live budget grant; an unassigned budget is not zero`);
      }
      if (grant && grant.grant_id !== grantForTask.grant_id) {
        throw new BudgetExceeded('BUDGET_GRANT_MISMATCH', 'the request names a grant that is not the live grant for this task');
      }
      const requestLimits = document.budget_grant;
      for (const [key, grantKey] of [['task_limit', 'task_limit'], ['campaign_limit', 'campaign_limit'], ['day_limit', 'day_limit']]) {
        const granted = grantForTask[grantKey];
        if (granted === null || granted === undefined) {
          throw new BudgetExceeded('BUDGET_SCOPE_UNASSIGNED', `budget scope ${key} was never assigned; an unassigned budget is not zero`);
        }
        if (Number(granted) !== Number(requestLimits[key])) {
          throw new BudgetExceeded('BUDGET_LIMITS_DISAGREE', `the request ${key} does not equal the granted ${key}`);
        }
      }
      if (grantForTask.currency !== requestLimits.currency) {
        throw new BudgetExceeded('BUDGET_CURRENCY_DISAGREE', 'the request currency does not equal the granted currency');
      }
      if (grantForTask.timeout_ms !== null && grantForTask.timeout_ms !== undefined
        && Number(grantForTask.timeout_ms) !== Number(requestLimits.timeout_ms)) {
        throw new BudgetExceeded('BUDGET_TIMEOUT_DISAGREE', 'the request timeout does not equal the granted timeout');
      }
      const runId = this.newId('run');
      const runKey = document.idempotency_key;
      const existingRun = await tx.selectRow('agentboard_run', { where: { idempotency_key: runKey } });
      if (existingRun) {
        throw new IdempotencyConflict('RUN_ALREADY_STARTED', `run ${existingRun.run_id} was already started with request key ${runKey}`);
      }
      const row = {
        run_id: runId,
        task_id: task.task_id,
        workspace_id: task.workspace_id,
        adapter_id: document.adapter_id,
        lease_id: document.lease_id,
        fencing_token: fence,
        request_id: document.request_id,
        idempotency_key: runKey,
        run_state: 'DISPATCH_PENDING',
        last_sequence: 0,
        brief_digest: task.brief_digest,
        policy_digest: task.policy_digest,
        manifest_digest: task.manifest_digest,
        request_payload: document,
        request_digest: canonicalDigest(document),
        result_payload: null,
        result_digest: null,
        error_payload: null,
        spend: 0,
        currency: requestLimits.currency,
        dispatch_attempts: 0,
        started_at: null,
        completed_at: null,
        created_at: now,
      };
      await tx.insertRow('agentboard_run', row);
      const outboxKey = outboxEvent?.idempotency_key ?? canonicalDigest({ operation, run_id: runId, request_id: document.request_id });
      const outboxRow = await this._insertOutbox(tx, {
        workspace_id: task.workspace_id,
        task_id: task.task_id,
        run_id: runId,
        event_type: outboxEvent?.event_type ?? DEFAULT_OUTBOX_EVENT_TYPES.createRun,
        idempotency_key: outboxKey,
        payload: outboxEvent?.payload ?? document,
      }, { now });
      const result = {
        run: buildRunWire(row),
        outbox: buildOutboxWire(outboxRow),
        run_id: runId,
        task_id: task.task_id,
        lease_id: document.lease_id,
        fencing_token: fence,
        outbox_id: outboxRow.outbox_id,
        dispatch_state: outboxRow.dispatch_state,
      };
      return this._commitMark(tx, {
        idem, workspaceId: task.workspace_id, operation, actor, result, now,
        audit: {
          task_id: task.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            run_id: runId,
            request_id: document.request_id,
            run_idempotency_key: runKey,
            lease_id: document.lease_id,
            fencing_token: fence,
            adapter_id: document.adapter_id,
            grant_id: grantForTask.grant_id,
            request_digest: `sha256:${canonicalDigest(document)}`,
            outbox_id: outboxRow.outbox_id,
            outbox_key: outboxKey,
          },
        },
      });
    });
  }

  /**
   * markRunDispatched — advances the run out of DISPATCH_PENDING. This is a
   * transport fact, not a task state change: the task moves to RUNNING through
   * transitionTask with the fence the caller already holds.
   */
  async markRunDispatched({ runId, actor, idempotencyKey, argsDigest, operation = 'board.execution.dispatch', outboxEvent = undefined }) {
    requireActor(actor);
    requireText(runId, 'runId', { max: 64 });
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'markRunDispatched' });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const run = await tx.selectRow('agentboard_run', { where: { run_id: runId }, forUpdate: true });
      if (!run) throw new NeedsInput(`unknown run ${String(runId)}`);
      if (run.run_state !== 'DISPATCH_PENDING') {
        throw new TransitionNotAllowed('RUN_NOT_DISPATCH_PENDING', `run ${runId} is ${run.run_state}`);
      }
      const updated = await tx.updateRows('agentboard_run', {
        where: { run_id: runId, run_state: 'DISPATCH_PENDING' },
        sets: { run_state: 'DISPATCHED', dispatch_attempts: Number(run.dispatch_attempts) + 1, started_at: run.started_at ?? now },
        limit: 1,
      });
      if (updated.length === 0) throw new TransitionNotAllowed('RUN_NOT_DISPATCH_PENDING', `run ${runId} changed under the writer`);
      const result = { run: buildRunWire(updated[0]), run_id: runId, run_state: 'DISPATCHED', dispatch_attempts: Number(updated[0].dispatch_attempts) };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: run.workspace_id,
        task_id: run.task_id,
        run_id: runId,
        event_type: outboxEvent.event_type ?? 'board.execution.dispatched',
        idempotency_key: idem?.key ?? canonicalDigest({ operation, run_id: runId, at: now }),
        payload: outboxEvent.payload ?? { run_id: runId, request_id: run.request_id, fencing_token: Number(run.fencing_token) },
      };
      return this._commitMark(tx, {
        idem, workspaceId: run.workspace_id, operation, actor, outbox, result, now,
        audit: {
          task_id: run.task_id,
          idempotency_key: idem?.key,
          detail: { args_digest: idem?.digest ?? null, run_id: runId, run_state: 'DISPATCHED', dispatch_attempts: result.dispatch_attempts },
        },
      });
    });
  }

  /**
   * appendExecutionEvent — append-only, gap-free, monotonic per run.
   *
   *   * `sequence` must be exactly `run.last_sequence + 1`; a duplicate or an
   *     older sequence is MalformedResult and `last_sequence` is never touched
   *     ("never repair state by guesswork").
   *   * the fence must be the current one, otherwise StaleFence and nothing is
   *     written — this is the late-callback path after expiry, cancel or
   *     reassignment.
   *   * a run that is no longer live rejects further events.
   *   * a re-submitted event_id with the same payload replays; with a
   *     different payload it is an IdempotencyConflict.
   *   * an UNKNOWN event (or an explicit RECONCILIATION_REQUIRED outcome)
   *     closes the run as RECONCILIATION_REQUIRED: an unknown side effect is
   *     never left open for a blind retry.
   */
  async appendExecutionEvent({ event, actor, idempotencyKey, argsDigest, operation = 'board.execution.event', outboxEvent = undefined }) {
    requireActor(actor);
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'appendExecutionEvent' });
    const document = assertBoardContract('execution-event', requirePlainObject(event, 'event'), MalformedResult);
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const payloadDigest = canonicalDigest(document.payload);
      const prior = await tx.selectRow('agentboard_execution_event', { where: { event_id: document.event_id } });
      if (prior) {
        if (prior.payload_digest !== payloadDigest || prior.sequence !== Number(document.sequence)
          || prior.event_type !== document.event_type || prior.run_id !== document.run_id) {
          throw new IdempotencyConflict('EVENT_ID_REUSED_WITH_DIFFERENT_PAYLOAD', `event ${document.event_id} was already recorded with different content`);
        }
        const run = await tx.selectRow('agentboard_run', { where: { run_id: document.run_id } });
        return { event: buildEventWire(prior), run: run ? buildRunWire(run) : null, run_id: prior.run_id, sequence: Number(prior.sequence), replayed: true };
      }
      const run = await tx.selectRow('agentboard_run', { where: { run_id: document.run_id }, forUpdate: true });
      if (!run) throw new NeedsInput(`unknown run ${String(document.run_id)}`);
      if (run.task_id !== document.task_id || run.workspace_id !== document.workspace_id) {
        throw new MalformedResult('EVENT_RUN_MISMATCH', `event ${document.event_id} does not belong to run ${run.run_id} of task ${run.task_id}`);
      }
      const task = await tx.selectRow('agentboard_task', { where: { task_id: run.task_id }, forUpdate: true });
      if (!task) throw new NeedsInput(`unknown task ${String(run.task_id)}`);
      const lease = await tx.selectRow('agentboard_lease', { where: { lease_id: document.lease_id } });
      if (Number(run.fencing_token) !== Number(document.fencing_token)) {
        throw new StaleFence('FENCE_NOT_CURRENT', `run ${run.run_id} is bound to fence ${run.fencing_token}, the event presented ${document.fencing_token}`);
      }
      this._requireFenceMatch(task, lease, document.fencing_token, 'appendExecutionEvent');
      if (!LIVE_RUN_STATES.includes(run.run_state)) {
        throw new TransitionNotAllowed('RUN_NOT_LIVE', `run ${run.run_id} is ${run.run_state} and admits no further events`);
      }
      const expected = Number(run.last_sequence) + 1;
      if (Number(document.sequence) !== expected) {
        throw new MalformedResult('EVENT_SEQUENCE_OUT_OF_ORDER', `run ${run.run_id} expects sequence ${expected}, the event presented ${document.sequence}`);
      }
      const row = {
        event_id: document.event_id,
        run_id: document.run_id,
        task_id: document.task_id,
        workspace_id: document.workspace_id,
        lease_id: document.lease_id,
        fencing_token: Number(document.fencing_token),
        sequence: Number(document.sequence),
        event_type: document.event_type,
        outcome: document.outcome ?? null,
        payload: document.payload,
        payload_digest: payloadDigest,
        emitted_at: document.emitted_at,
        received_at: now,
      };
      await tx.insertRow('agentboard_execution_event', row);
      const sets = { last_sequence: Number(document.sequence) };
      let runState = run.run_state;
      if (document.event_type === 'STARTED') {
        runState = 'RUNNING';
        sets.run_state = runState;
        sets.started_at = run.started_at ?? now;
      }
      if (document.event_type === 'UNKNOWN' || document.outcome === 'RECONCILIATION_REQUIRED') {
        runState = 'RECONCILIATION_REQUIRED';
        sets.run_state = runState;
        sets.completed_at = now;
      }
      const updated = await tx.updateRows('agentboard_run', {
        where: { run_id: document.run_id, run_state: run.run_state },
        sets,
        limit: 1,
      });
      if (updated.length === 0) throw new TransitionNotAllowed('RUN_NOT_LIVE', `run ${run.run_id} changed under the writer`);
      const result = {
        event: buildEventWire(row),
        run: buildRunWire(updated[0]),
        run_id: document.run_id,
        sequence: Number(document.sequence),
        run_state: runState,
      };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: run.workspace_id,
        task_id: run.task_id,
        run_id: run.run_id,
        event_type: outboxEvent.event_type ?? 'board.execution.event',
        idempotency_key: idem?.key ?? canonicalDigest({ operation, event_id: document.event_id }),
        payload: outboxEvent.payload ?? { run_id: run.run_id, sequence: Number(document.sequence), event_type: document.event_type },
      };
      return this._commitMark(tx, {
        idem, workspaceId: run.workspace_id, operation, actor, outbox, result, now,
        audit: {
          task_id: run.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            run_id: run.run_id,
            event_id: document.event_id,
            sequence: Number(document.sequence),
            event_type: document.event_type,
            run_state: runState,
            payload_digest: payloadDigest,
          },
        },
      });
    });
  }

  /**
   * collectResult — evidence that work was collected, never proof of
   * correctness and never a DONE. Refused when the fence is not current
   * (StaleFence), when the run is not live, or when the run_id/task_id pair
   * disagrees with the stored run (MalformedResult).
   */
  async collectResult({ result, actor, idempotencyKey, argsDigest, operation = 'board.execution.collect_result', outboxEvent = undefined }) {
    requireActor(actor);
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'collectResult' });
    const document = assertBoardContract('execution-result', requirePlainObject(result, 'result'), MalformedResult);
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const run = await tx.selectRow('agentboard_run', { where: { run_id: document.run_id }, forUpdate: true });
      if (!run) throw new NeedsInput(`unknown run ${String(document.run_id)}`);
      if (run.task_id !== document.task_id || run.workspace_id !== document.workspace_id) {
        throw new MalformedResult('RESULT_RUN_MISMATCH', `result ${document.run_id} does not belong to run ${run.run_id} of task ${run.task_id}`);
      }
      const resultDigest = canonicalDigest(document);
      if (run.run_state === 'COLLECTED' && run.result_digest === resultDigest) {
        return { run: buildRunWire(run), run_id: run.run_id, run_state: 'COLLECTED', outcome: document.outcome, replayed: true };
      }
      const task = await tx.selectRow('agentboard_task', { where: { task_id: run.task_id }, forUpdate: true });
      if (!task) throw new NeedsInput(`unknown task ${String(run.task_id)}`);
      const lease = await tx.selectRow('agentboard_lease', { where: { lease_id: document.lease_id } });
      if (Number(run.fencing_token) !== Number(document.fencing_token)) {
        throw new StaleFence('FENCE_NOT_CURRENT', `run ${run.run_id} is bound to fence ${run.fencing_token}, the result presented ${document.fencing_token}`);
      }
      this._requireFenceMatch(task, lease, document.fencing_token, 'collectResult');
      if (!LIVE_RUN_STATES.includes(run.run_state)) {
        throw new TransitionNotAllowed('RUN_NOT_LIVE', `run ${run.run_id} is ${run.run_state} and admits no result`);
      }
      // The result is the terminal record of the run: it either continues the
      // event sequence, or it describes the terminal event that already closed
      // that sequence. Anything else is out of order.
      const last = Number(run.last_sequence);
      const terminal = await tx.selectRow('agentboard_execution_event', { where: { run_id: run.run_id, sequence: last }, order: 'event_sequence' });
      const isTerminalEcho = Number(document.sequence) === last && terminal !== null && TERMINAL_EVENT_TYPES.includes(terminal.event_type);
      if (Number(document.sequence) !== last + 1 && !isTerminalEcho) {
        throw new MalformedResult('RESULT_SEQUENCE_OUT_OF_ORDER', `run ${run.run_id} expects sequence ${last + 1}, the result presented ${document.sequence}`);
      }
      const runState = RUN_STATE_FOR_OUTCOME[document.outcome] ?? 'COLLECTED';
      const updated = await tx.updateRows('agentboard_run', {
        where: { run_id: run.run_id },
        sets: {
          run_state: runState,
          result_payload: document,
          result_digest: resultDigest,
          error_payload: document.error ?? null,
          spend: Number(document.measurements.spend),
          currency: document.measurements.currency,
          completed_at: now,
        },
        limit: 1,
      });
      if (updated.length === 0) throw new TransitionNotAllowed('RUN_NOT_LIVE', `run ${run.run_id} changed under the writer`);
      // The task's artifact/evidence accumulators grow, but the task STATE and
      // its revision do not: a result is evidence, not a state change, and the
      // caller's expected_revision must stay valid across a collection.
      const artifacts = [...task.artifacts];
      for (const artifact of document.artifact_hashes) {
        if (!artifacts.some((existing) => existing.artifact_id === artifact.artifact_id)) {
          artifacts.push({
            artifact_id: artifact.artifact_id,
            digest: artifact.digest,
            media_type: artifact.media_type,
          });
        }
      }
      const evidenceRefs = task.evidence_refs.includes(run.run_id) ? task.evidence_refs : [...task.evidence_refs, run.run_id];
      const taskUpdated = await tx.updateRows('agentboard_task', {
        where: { task_id: task.task_id },
        sets: { artifacts, evidence_refs: evidenceRefs, updated_at: now },
        limit: 1,
      });
      // The accumulators are the only record that a result was ever produced.
      // A silently skipped write would leave the task with no evidence ref
      // while the run says COLLECTED, which is a claim nobody can check.
      if (taskUpdated.length === 0) {
        throw new NeedsInput('REFERENCED_ROW_MISSING', `task ${task.task_id} vanished under the collector`);
      }
      const resultRow = { run: buildRunWire(updated[0]), run_id: run.run_id, run_state: runState, outcome: document.outcome };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: run.workspace_id,
        task_id: run.task_id,
        run_id: run.run_id,
        event_type: outboxEvent.event_type ?? 'board.execution.result',
        idempotency_key: idem?.key ?? canonicalDigest({ operation, run_id: run.run_id, result_digest: resultDigest }),
        payload: outboxEvent.payload ?? { run_id: run.run_id, outcome: document.outcome, run_state: runState },
      };
      return this._commitMark(tx, {
        idem, workspaceId: run.workspace_id, operation, actor, outbox, result: resultRow, now,
        audit: {
          task_id: run.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            run_id: run.run_id,
            outcome: document.outcome,
            run_state: runState,
            result_digest: resultDigest,
            spend: Number(document.measurements.spend),
            currency: document.measurements.currency,
            reconciliation_required: document.reconciliation_required === true,
            artifacts: document.artifact_hashes.map((artifact) => artifact.artifact_id),
          },
        },
      });
    });
  }

  /**
   * settleBudget — the serialization point. The spend row is created with
   * INSERT … ON CONFLICT DO NOTHING and then locked with SELECT … FOR UPDATE,
   * the grant is read under the same lock, and every scope (task / campaign /
   * day) is checked BEFORE the accumulators are updated. Two parallel settles
   * therefore cannot both observe headroom: the second one waits for the first
   * and then sees the new totals.
   *
   * WHAT `operationId` DOES AND DOES NOT BUY
   * `operation_id` is a canonical argument of the `budget.settle` command, so
   * it is part of the canonical `argsDigest` the ledger stores. The dedup is
   * therefore exact for the intended use — a caller that derives its
   * `idempotency_key` from the operation:
   *
   *   same key + same operation_id  -> the prior committed result is replayed,
   *                                    nothing is written, nothing is spent;
   *   same key + different operation_id -> IdempotencyConflict, nothing spent;
   *   different key                  -> a DIFFERENT operation, and it spends.
   *
   * The last line is the honest limit and it is a caller contract, not a store
   * bug: minting a fresh key per attempt is how a caller asks for two spends.
   * The row's own `operation_id` column records the operation that CREATED
   * that (grant, day) bucket — the primary key is (grant_id, day_key), so it
   * holds one value and is deliberately NOT a uniqueness constraint on
   * operations. Nothing in this method may be read as "operation_id
   * deduplicates": the ledger does, and only for a key the caller reuses.
   */
  async settleBudget({ grantId, operationId, taskId, amount, currency, dayKey, actor, idempotencyKey, argsDigest }) {
    const operation = 'board.budget.settle';
    requireActor(actor);
    requireText(grantId, 'grantId', { max: 64 });
    requireText(operationId, 'operationId', { max: 64 });
    requireText(taskId, 'taskId', { max: 64 });
    const spend = requireNonNegativeNumber(amount, 'amount');
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'settleBudget' });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const bucket = dayKey === undefined || dayKey === null ? dayKeyOf(now) : dayKey;
      if (typeof bucket !== 'string' || !DAY_KEY.test(bucket)) {
        throw new NeedsInput('dayKey must be a UTC calendar day (YYYY-MM-DD)');
      }
      const grant = await tx.selectRow('agentboard_budget_grant', { where: { grant_id: grantId }, forUpdate: true });
      if (!grant) {
        throw new BudgetExceeded('BUDGET_NOT_ASSIGNED', `grant ${grantId} does not exist; an unassigned budget is not zero`);
      }
      if (grant.revoked_at !== null && grant.revoked_at !== undefined) {
        throw new BudgetExceeded('BUDGET_REVOKED', `grant ${grantId} was revoked at ${grant.revoked_at}`);
      }
      if (grant.expires_at !== null && grant.expires_at !== undefined && Date.parse(grant.expires_at) <= Date.parse(now)) {
        throw new BudgetExceeded('BUDGET_EXPIRED', `grant ${grantId} expired at ${grant.expires_at}`);
      }
      if (grant.task_id !== null && grant.task_id !== taskId) {
        throw new CapabilityMismatch('BUDGET_GRANT_SCOPE', `grant ${grantId} is scoped to task ${grant.task_id}, not ${taskId}`);
      }
      if (currency !== undefined && currency !== null && currency !== grant.currency) {
        throw new BudgetExceeded('BUDGET_CURRENCY_DISAGREE', `grant ${grantId} is denominated in ${grant.currency}, not ${currency}`);
      }
      await tx.insertRow('agentboard_budget_spend', {
        grant_id: grantId,
        operation_id: operationId,
        task_id: taskId,
        workspace_id: grant.workspace_id,
        day_key: bucket,
        currency: grant.currency,
        spent_task: 0,
        spent_campaign: 0,
        spent_day: 0,
        updated_at: now,
      }, { onConflictDoNothing: true });
      const row = await tx.selectRow('agentboard_budget_spend', { where: { grant_id: grantId, day_key: bucket }, forUpdate: true });
      if (!row) throw new NeedsInput(`budget spend bucket ${grantId}/${bucket} is unavailable`);
      const scopes = [
        ['task_limit', Number(row.spent_task) + spend],
        ['campaign_limit', Number(row.spent_campaign) + spend],
        ['day_limit', Number(row.spent_day) + spend],
      ];
      for (const [column, projected] of scopes) {
        const limit = grant[column];
        if (limit === null || limit === undefined) {
          throw new BudgetExceeded('BUDGET_SCOPE_UNASSIGNED', `grant ${grantId} has no ${column}; an unassigned budget is not zero`);
        }
        if (projected > Number(limit)) {
          throw new BudgetExceeded(
            'BUDGET_EXCEEDED',
            `settling ${spend} ${grant.currency} would raise ${column} to ${projected}, above the granted limit ${Number(limit)}`,
          );
        }
      }
      const updated = await tx.updateRows('agentboard_budget_spend', {
        where: { grant_id: grantId, day_key: bucket },
        sets: {
          spent_task: Number(row.spent_task) + spend,
          spent_campaign: Number(row.spent_campaign) + spend,
          spent_day: Number(row.spent_day) + spend,
          updated_at: now,
        },
        limit: 1,
      });
      const totals = updated[0];
      const result = {
        grant_id: grantId,
        day_key: bucket,
        operation_id: operationId,
        task_id: taskId,
        amount: spend,
        currency: grant.currency,
        spent: { task: Number(totals.spent_task), campaign: Number(totals.spent_campaign), day: Number(totals.spent_day) },
        remaining: {
          task: Number(grant.task_limit) - Number(totals.spent_task),
          campaign: Number(grant.campaign_limit) - Number(totals.spent_campaign),
          day: Number(grant.day_limit) - Number(totals.spent_day),
        },
      };
      return this._commitMark(tx, {
        idem, workspaceId: grant.workspace_id, operation, actor, result, now,
        audit: {
          task_id: taskId,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            grant_id: grantId,
            day_key: bucket,
            operation_id: operationId,
            amount: spend,
            currency: grant.currency,
            spent: result.spent,
            remaining: result.remaining,
          },
        },
      });
    });
  }

  // --- outbox dispatch state machine ---------------------------------------

  /**
   * The dispatch state machine only ever moves forward:
   *   PENDING -> SENT -> ACKED, and PENDING | SENT | FAILED ->
   *   RECONCILIATION_REQUIRED, which is TERMINAL for retry purposes. A crash
   *   before SENT is re-dispatchable; a crash after SENT with no ACK is not,
   *   because the external side effect may already have happened.
   */
  async _advanceOutbox({ outboxId, from, to, actor, idempotencyKey, argsDigest, operation, stamp = {} }) {
    requireActor(actor);
    requireText(outboxId, 'outboxId', { max: 64 });
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: operation });
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const row = await tx.selectRow('agentboard_outbox', { where: { outbox_id: outboxId }, forUpdate: true });
      if (!row) throw new NeedsInput(`unknown outbox row ${String(outboxId)}`);
      if (!from.includes(row.dispatch_state)) {
        throw new TransitionNotAllowed('OUTBOX_STATE_NOT_ADMISSIBLE', `outbox ${outboxId} is ${row.dispatch_state}; ${from.join('|')} was required`);
      }
      // The SENT step is the point of no return: the intent is committed
      // BEFORE the transport is called, so a dispatch that reaches this line
      // may already have started work on the executor. A handoff whose work was
      // WITHDRAWN must therefore never get there, and re-checking it here —
      // inside the transaction, immediately before the write — is what makes
      // the withdrawal win even when the driver had already read its PENDING
      // batch. Only the execution handoff is bound this way: a reconciliation
      // notification is supposed to be delivered precisely because its run is
      // no longer live.
      if (stamp.sent_at && row.event_type === DEFAULT_OUTBOX_EVENT_TYPES.createRun) {
        if (row.run_id) {
          const run = await tx.selectRow('agentboard_run', { where: { run_id: row.run_id } });
          if (!run) {
            throw new NeedsInput('REFERENCED_ROW_MISSING', `outbox ${outboxId} names an unknown run ${String(row.run_id)}`);
          }
          if (STATES_BARRING_DISPATCH.includes(run.run_state)) {
            throw new TransitionNotAllowed(
              'OUTBOX_RUN_NOT_DISPATCHABLE',
              `run ${run.run_id} is ${run.run_state}; a ${run.run_state} run may not be handed to an executor`,
            );
          }
        }
        if (row.task_id) {
          const task = await tx.selectRow('agentboard_task', { where: { task_id: row.task_id } });
          if (!task) {
            throw new NeedsInput('REFERENCED_ROW_MISSING', `outbox ${outboxId} names an unknown task ${String(row.task_id)}`);
          }
          if (STATES_BARRING_DISPATCH.includes(task.state)) {
            throw new TransitionNotAllowed(
              'OUTBOX_TASK_NOT_DISPATCHABLE',
              `task ${task.task_id} is ${task.state}; a ${task.state} task may not be handed to an executor`,
            );
          }
        }
      }
      // `stamp` names the timestamp column each step fills with the database
      // clock, so a step can never stamp a NULL time.
      const sets = { dispatch_state: to };
      if (stamp.sent_at) sets.sent_at = now;
      if (stamp.acked_at) sets.acked_at = now;
      // `attempts` is the per-row count of BOUNDARY CROSSINGS, and the
      // SENT step is the crossing: the send intent is committed BEFORE the
      // transport is called, so the row proves how many times the executor may
      // have been told to start. A `duplicateExternalEffects` gate reads this
      // column, not an in-process counter, so it survives a crash and a
      // restart. A row that is never sent keeps its 0.
      if (stamp.sent_at) sets.attempts = Number(row.attempts) + 1;
      const updated = await tx.updateRows('agentboard_outbox', {
        where: { outbox_id: outboxId, dispatch_state: row.dispatch_state },
        sets,
        limit: 1,
      });
      if (updated.length === 0) throw new TransitionNotAllowed('OUTBOX_STATE_NOT_ADMISSIBLE', `outbox ${outboxId} changed under the writer`);
      const result = { outbox: buildOutboxWire(updated[0]), outbox_id: outboxId, dispatch_state: to };
      return this._commitMark(tx, {
        idem, workspaceId: row.workspace_id, operation, actor, result, now,
        audit: {
          task_id: row.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            outbox_id: outboxId,
            run_id: row.run_id,
            event_type: row.event_type,
            from_state: row.dispatch_state,
            to_state: to,
            attempts: Number(updated[0].attempts),
            last_error: updated[0].last_error ?? null,
          },
        },
      });
    });
  }

  async markOutboxSent({ outboxId, actor, idempotencyKey, argsDigest, operation = 'board.outbox.sent' }) {
    return this._advanceOutbox({
      outboxId,
      from: ['PENDING'],
      to: 'SENT',
      actor,
      idempotencyKey,
      argsDigest,
      operation,
      stamp: { sent_at: true },
    });
  }

  async markOutboxAcked({ outboxId, actor, idempotencyKey, argsDigest, operation = 'board.outbox.acked' }) {
    return this._advanceOutbox({
      outboxId,
      from: ['SENT'],
      to: 'ACKED',
      actor,
      idempotencyKey,
      argsDigest,
      operation,
      stamp: { acked_at: true },
    });
  }

  async escalateOutbox({ outboxId, reason, actor, idempotencyKey, argsDigest, operation = 'board.outbox.escalate' }) {
    requireText(reason, 'reason', { max: 500 });
    return this._write(async (tx) => {
      const now = await tx.now();
      const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'escalateOutbox' });
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      const outbox = await tx.selectRow('agentboard_outbox', { where: { outbox_id: requireText(outboxId, 'outboxId', { max: 64 }) }, forUpdate: true });
      if (!outbox) throw new NeedsInput(`unknown outbox row ${String(outboxId)}`);
      if (['ACKED', 'RECONCILIATION_REQUIRED'].includes(outbox.dispatch_state)) {
        // RECONCILIATION_REQUIRED is terminal for retry purposes and an
        // acknowledged dispatch has nothing left to reconcile.
        throw new TransitionNotAllowed('OUTBOX_STATE_TERMINAL', `outbox ${outboxId} is ${outbox.dispatch_state} and cannot be escalated`);
      }
      const updated = await tx.updateRows('agentboard_outbox', {
        where: { outbox_id: outbox.outbox_id, dispatch_state: outbox.dispatch_state },
        sets: { dispatch_state: 'RECONCILIATION_REQUIRED', last_error: reason },
        limit: 1,
      });
      if (updated.length === 0) throw new TransitionNotAllowed('OUTBOX_STATE_TERMINAL', `outbox ${outboxId} changed under the writer`);
      const result = { outbox: buildOutboxWire(updated[0]), outbox_id: outboxId, dispatch_state: 'RECONCILIATION_REQUIRED', reason };
      return this._commitMark(tx, {
        idem, workspaceId: outbox.workspace_id, operation, actor, result, now,
        audit: {
          task_id: outbox.task_id,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            outbox_id: outboxId,
            run_id: outbox.run_id,
            event_type: outbox.event_type,
            from_state: outbox.dispatch_state,
            to_state: 'RECONCILIATION_REQUIRED',
            reason,
          },
        },
      });
    });
  }

  /**
   * recordReconciliation — the ONLY way an unknown external side effect is
   * closed. It is recorded, never guessed: the decider is the server-resolved
   * actor, the kind must be an authenticated human or a separately authorized
   * deterministic gate, and a producer (adapter) can never close its own run.
   */
  async recordReconciliation({ reconciliation, actor, actorKind, idempotencyKey, argsDigest, operation = 'board.reconciliation.record', outboxEvent = undefined }) {
    requireActor(actor);
    requireActorKind(actorKind);
    const idem = requireIdempotency({ idempotencyKey, argsDigest, label: 'recordReconciliation' });
    const document = requirePlainObject(reconciliation, 'reconciliation');
    const policy = await this._policyModule();
    if (policy && typeof policy.assertHumanOnlyApproval === 'function') {
      policy.assertHumanOnlyApproval(actorKind);
    } else if (!RECONCILIATION_DECIDER_KINDS.includes(actorKind)) {
      throw new BlockedPolicy('RECONCILIATION_DECIDER_NOT_AUTHORIZED', 'only an authenticated human or an authorized deterministic gate may close a reconciliation');
    }
    if (document.decided_by !== undefined && document.decided_by !== null && document.decided_by !== actor) {
      throw new AuthRequired('RECONCILIATION_DECIDER_MISMATCH', 'decided_by must be the server-resolved actor; a payload never names its own decider');
    }
    if (!RECONCILIATION_RESOLUTIONS.includes(document.resolution)) {
      throw new BlockedPolicy('RECONCILIATION_RESOLUTION_UNKNOWN', `resolution must be one of ${RECONCILIATION_RESOLUTIONS.join('|')}`);
    }
    return this._write(async (tx) => {
      const now = await tx.now();
      const replay = await this._replay(tx, idem, { operation });
      if (replay) return replay;
      let workspaceId = document.workspace_id ?? null;
      let taskId = document.task_id ?? null;
      if (document.run_id !== undefined && document.run_id !== null) {
        const run = await tx.selectRow('agentboard_run', { where: { run_id: document.run_id } });
        if (!run) throw new NeedsInput(`unknown run ${String(document.run_id)}`);
        workspaceId = run.workspace_id;
        taskId = run.task_id;
      }
      requireText(workspaceId, 'reconciliation.workspace_id', { max: 64 });
      const row = {
        reconciliation_id: document.reconciliation_id ?? this.newId('reconciliation'),
        workspace_id: workspaceId,
        task_id: taskId,
        run_id: document.run_id ?? null,
        resolution: document.resolution,
        decided_by: actor,
        decided_by_kind: actorKind,
        evidence_ref: document.evidence_ref ?? null,
        detail: requireText(document.detail, 'reconciliation.detail', { max: 1000 }),
        created_at: now,
      };
      const existing = await tx.selectRow('agentboard_reconciliation', { where: { reconciliation_id: row.reconciliation_id } });
      if (existing) {
        if (sameJson(buildReconciliationWire(existing), buildReconciliationWire(row))) {
          return { reconciliation: buildReconciliationWire(existing), reconciliation_id: row.reconciliation_id, replayed: true };
        }
        throw new IdempotencyConflict('RECONCILIATION_ID_REUSED', `reconciliation ${row.reconciliation_id} already records a different decision`);
      }
      await tx.insertRow('agentboard_reconciliation', row);
      const result = { reconciliation: buildReconciliationWire(row), reconciliation_id: row.reconciliation_id };
      const outbox = outboxEvent === undefined ? null : {
        workspace_id: workspaceId,
        task_id: taskId,
        run_id: document.run_id ?? null,
        event_type: outboxEvent.event_type ?? DEFAULT_OUTBOX_EVENT_TYPES.reconciliation,
        idempotency_key: idem?.key ?? canonicalDigest({ operation, reconciliation_id: row.reconciliation_id }),
        payload: outboxEvent.payload ?? { reconciliation_id: row.reconciliation_id, resolution: row.resolution, run_id: row.run_id },
      };
      return this._commitMark(tx, {
        idem, workspaceId, operation, actor, outbox, result, now,
        audit: {
          task_id: taskId,
          idempotency_key: idem?.key,
          detail: {
            args_digest: idem?.digest ?? null,
            reconciliation_id: row.reconciliation_id,
            run_id: row.run_id,
            resolution: row.resolution,
            decided_by: actor,
            decided_by_kind: actorKind,
            evidence_ref: row.evidence_ref,
          },
        },
      });
    });
  }
}

// ---------------------------------------------------------------------------
// In-memory unit of work.
//
// Every write runs against a STRUCTURED CLONE of the committed state which is
// swapped in only on commit, so the twin is genuinely all-or-nothing and a
// refusal really does leave the store byte-identical. It is a behavioural
// twin, not a concurrency simulator: two interleaved claims cannot be
// expressed here the way two PostgreSQL sessions can.
// ---------------------------------------------------------------------------

function cloneState(state) {
  return {
    tasks: new Map([...state.tasks].map(([key, value]) => [key, structuredClone(value)])),
    acls: new Map([...state.acls].map(([key, value]) => [key, structuredClone(value)])),
    leases: new Map([...state.leases].map(([key, value]) => [key, structuredClone(value)])),
    adapters: new Map([...state.adapters].map(([key, value]) => [key, structuredClone(value)])),
    grants: new Map([...state.grants].map(([key, value]) => [key, structuredClone(value)])),
    spends: new Map([...state.spends].map(([key, value]) => [key, structuredClone(value)])),
    runs: new Map([...state.runs].map(([key, value]) => [key, structuredClone(value)])),
    events: new Map([...state.events].map(([key, value]) => [key, structuredClone(value)])),
    transitions: new Map([...state.transitions].map(([key, value]) => [key, structuredClone(value)])),
    // The audit table is keyed by audit_id like every other table, so a unit
    // of work clones it exactly like the rest of the state.
    audit: new Map([...state.audit].map(([key, value]) => [key, structuredClone(value)])),
    outbox: new Map([...state.outbox].map(([key, value]) => [key, structuredClone(value)])),
    operations: new Map([...state.operations].map(([key, value]) => [key, structuredClone(value)])),
    reconciliations: new Map([...state.reconciliations].map(([key, value]) => [key, structuredClone(value)])),
    fenceCounter: state.fenceCounter,
  };
}

function tableOf(state, table) {
  switch (table) {
    case 'agentboard_task': return { rows: state.tasks, key: 'task_id' };
    case 'agentboard_acl': return { rows: state.acls, key: 'task_id' };
    case 'agentboard_lease': return { rows: state.leases, key: 'lease_id' };
    case 'agentboard_adapter': return { rows: state.adapters, key: 'adapter_id' };
    case 'agentboard_budget_grant': return { rows: state.grants, key: 'grant_id' };
    case 'agentboard_budget_spend': return { rows: state.spends, key: ['grant_id', 'day_key'] };
    case 'agentboard_run': return { rows: state.runs, key: 'run_id' };
    case 'agentboard_execution_event': return { rows: state.events, key: 'event_id' };
    case 'agentboard_transition': return { rows: state.transitions, key: 'transition_id' };
    case 'agentboard_audit': return { rows: state.audit, key: 'audit_id' };
    case 'agentboard_outbox': return { rows: state.outbox, key: 'outbox_id' };
    case 'agentboard_operation': return { rows: state.operations, key: 'idempotency_key' };
    case 'agentboard_reconciliation': return { rows: state.reconciliations, key: 'reconciliation_id' };
    default: throw new NeedsInput(`unknown table ${String(table)}`);
  }
}

function keyOf(spec, row) {
  return Array.isArray(spec.key) ? spec.key.map((column) => String(row[column])).join('|') : String(row[spec.key]);
}

function matches(row, where) {
  return Object.entries(where).every(([column, value]) => (value === undefined ? true : String(row[column] ?? '') === String(value ?? '')));
}

class InMemoryUnitOfWork {
  constructor(store) {
    this.store = store;
    this.draft = cloneState(store._state);
    this._now = null;
  }

  async now() {
    if (this._now === null) this._now = toIsoMs(this.store.clock(), 'clock.now()');
    return this._now;
  }

  async nextFencingToken() {
    this.draft.fenceCounter += 1;
    return this.draft.fenceCounter;
  }

  _rows(table) {
    return [...tableOf(this.draft, table).rows.values()];
  }

  async selectRow(table, { where = {}, order = undefined } = {}) {
    const rows = this._rows(table).filter((row) => matches(row, where));
    if (rows.length === 0) return null;
    if (order) return structuredClone([...rows].sort(ORDERINGS[order].compare)[0]);
    return structuredClone(rows[0]);
  }

  async selectRows(table, { where = {}, order = undefined, limit = undefined } = {}) {
    let rows = this._rows(table).filter((row) => matches(row, where));
    if (order) rows = [...rows].sort(ORDERINGS[order].compare);
    if (limit !== undefined) rows = rows.slice(0, limit);
    return rows.map((row) => structuredClone(row));
  }

  async insertRow(table, row, { onConflictDoNothing = false } = {}) {
    const spec = tableOf(this.draft, table);
    const key = keyOf(spec, row);
    if (spec.rows.has(key)) {
      if (onConflictDoNothing) return null;
      if (table === 'agentboard_lease' && this.draft.leases.get(key)) {
        throw new IdempotencyConflict('LEASE_ID_REUSED', `lease ${row.lease_id} already exists`);
      }
      if (table === 'agentboard_transition') throw new RevisionConflict('TRANSITION_REVISION_REUSED', `transition ${row.transition_id} already exists`);
      if (table === 'agentboard_outbox' || table === 'agentboard_operation') {
        throw new IdempotencyConflict('LEDGER_KEY_REUSED', `${table} key ${key} already exists`);
      }
      throw new IdempotencyConflict('PRIMARY_KEY_REUSED', `${table} key ${key} already exists`);
    }
    const stored = structuredClone(row);
    // The unique indexes the migration declares, mirrored so the twin raises
    // the same typed error the database would. They are evaluated against the
    // rows as they were BEFORE this insert: a mirror that ran afterwards would
    // match the row itself and refuse every insert.
    this._assertUniqueIndexes(table, stored);
    spec.rows.set(key, stored);
    return structuredClone(stored);
  }

  _assertUniqueIndexes(table, stored) {
    if (table === 'agentboard_lease') {
      const activeOnTask = [...this.draft.leases.values()].find((lease) => lease.task_id === stored.task_id && lease.lease_state === 'ACTIVE');
      if (activeOnTask) {
        throw new TransitionNotAllowed('LEASE_ALREADY_ACTIVE', `task ${stored.task_id} already holds active lease ${activeOnTask.lease_id}`);
      }
      if ([...this.draft.leases.values()].some((lease) => Number(lease.fencing_token) === Number(stored.fencing_token))) {
        throw new TransitionNotAllowed('FENCING_TOKEN_REUSED', `fencing token ${stored.fencing_token} is already in use`);
      }
    }
    if (table === 'agentboard_run') {
      if ([...this.draft.runs.values()].some((run) => run.idempotency_key === stored.idempotency_key)) {
        throw new IdempotencyConflict('RUN_ALREADY_STARTED', `a run with key ${stored.idempotency_key} already exists`);
      }
      if (LIVE_RUN_STATES.includes(stored.run_state)
        && [...this.draft.runs.values()].some((run) => run.task_id === stored.task_id && LIVE_RUN_STATES.includes(run.run_state))) {
        throw new TransitionNotAllowed('RUN_ALREADY_LIVE', `task ${stored.task_id} already has a live run`);
      }
    }
    if (table === 'agentboard_outbox') {
      if ([...this.draft.outbox.values()].some((existing) => existing.idempotency_key === stored.idempotency_key)) {
        throw new IdempotencyConflict('OUTBOX_KEY_REUSED', `an outbox row with key ${stored.idempotency_key} already exists`);
      }
    }
    if (table === 'agentboard_execution_event') {
      if ([...this.draft.events.values()].some((event) => event.run_id === stored.run_id && Number(event.sequence) === Number(stored.sequence))) {
        throw new MalformedResult('EVENT_SEQUENCE_OUT_OF_ORDER', `run ${stored.run_id} already has an event at sequence ${stored.sequence}`);
      }
    }
    if (table === 'agentboard_transition') {
      if ([...this.draft.transitions.values()].some((existing) => existing.task_id === stored.task_id && Number(existing.revision) === Number(stored.revision))) {
        throw new RevisionConflict('TRANSITION_REVISION_REUSED', `task ${stored.task_id} already has a transition at revision ${stored.revision}`);
      }
    }
  }

  async updateRows(table, { where = {}, sets = {}, bump = undefined, limit = 1 }) {
    const spec = tableOf(this.draft, table);
    const targets = [...spec.rows.entries()].filter(([, row]) => matches(row, where));
    if (targets.length === 0) return [];
    const applied = [];
    for (const [key, row] of targets.slice(0, limit === undefined ? targets.length : limit)) {
      const next = { ...row };
      for (const [column, value] of Object.entries(sets)) {
        if (!TABLE_COLUMNS[table].includes(column)) throw new NeedsInput(`unknown column ${table}.${column}`);
        next[column] = structuredClone(value);
      }
      if (bump !== undefined) {
        if (!TABLE_COLUMNS[table].includes(bump)) throw new NeedsInput(`unknown column ${table}.${bump}`);
        next[bump] = Number(next[bump]) + 1;
      }
      spec.rows.set(key, next);
      applied.push(structuredClone(next));
    }
    return applied;
  }
}

export class InMemoryAgentBoardStore extends AgentBoardStoreBase {
  constructor({ clock, ids, seed, policy } = {}) {
    super({ clock, ids, seed, policy });
    this.backend = 'memory';
    this._state = cloneState({
      tasks: new Map(), acls: new Map(), leases: new Map(), adapters: new Map(),
      grants: new Map(), spends: new Map(), runs: new Map(), events: new Map(),
      transitions: new Map(), audit: new Map(), outbox: new Map(), operations: new Map(),
      reconciliations: new Map(), fenceCounter: 0,
    });
    // The FIFO write chain. A unit of work clones the committed state when it
    // is ACQUIRED, so a second writer that acquired before the first one
    // committed would branch from a pre-commit snapshot and its commit would
    // erase the first writer's rows. The chain makes a write take its
    // snapshot only after the previous write has committed or rolled back,
    // which is exactly what `SELECT ... FOR UPDATE` gives the PostgreSQL
    // store — and it is what makes two concurrent claims produce one winner
    // and one typed REVISION_CONFLICT here as well.
    this._writeQueue = Promise.resolve();
  }

  /**
   * Wait for the previous write on this store to finish, then return the
   * release function. Reads are deliberately NOT queued: a read observes the
   * committed state at the moment it takes its snapshot, which is the
   * READ COMMITTED behaviour the real store has.
   */
  async _serializeWrite() {
    const previous = this._writeQueue;
    let open;
    const held = new Promise((resolve) => { open = resolve; });
    this._writeQueue = previous.then(() => held, () => held);
    await previous.catch(() => {});
    return () => { open(); };
  }

  async _acquireUnitOfWork() {
    return new InMemoryUnitOfWork(this);
  }

  async _commitUnitOfWork(tx) {
    this._state = tx.draft;
  }

  async _discardUnitOfWork(tx) {
    tx.draft = null;
  }

  // Snapshot of the committed state, for DEBUG assertions about the
  // byte-identical guarantee after a refusal. Never used by a write path.
  async debugSnapshot() {
    return structuredClone({
      tasks: [...this._state.tasks.entries()],
      acls: [...this._state.acls.entries()],
      leases: [...this._state.leases.entries()],
      adapters: [...this._state.adapters.entries()],
      grants: [...this._state.grants.entries()],
      spends: [...this._state.spends.entries()],
      runs: [...this._state.runs.entries()],
      events: [...this._state.events.entries()],
      transitions: [...this._state.transitions.entries()],
      audit: [...this._state.audit.entries()],
      outbox: [...this._state.outbox.entries()],
      operations: [...this._state.operations.entries()],
      reconciliations: [...this._state.reconciliations.entries()],
      fenceCounter: this._state.fenceCounter,
    });
  }
}

// ---------------------------------------------------------------------------
// PostgreSQL unit of work.
//
// A real `pg` Pool, real BEGIN/COMMIT/ROLLBACK, real SELECT ... FOR UPDATE,
// real partial unique indexes. Identifiers can only come from the frozen
// column whitelist, so a generated statement can never interpolate caller
// input. A commit whose outcome cannot be confirmed is escalated to
// ReconciliationRequired instead of being reported as a failure.
// ---------------------------------------------------------------------------

const PG_UNIQUE_VIOLATION = '23505';
const PG_FOREIGN_KEY_VIOLATION = '23503';
const PG_CHECK_VIOLATION = '23514';

const CONSTRAINT_ERROR_CODES = Object.freeze({
  idx_agentboard_lease_single_active: () => new TransitionNotAllowed('LEASE_ALREADY_ACTIVE', 'the task already holds an active lease'),
  idx_agentboard_transition_revision: () => new RevisionConflict('TRANSITION_REVISION_REUSED', 'a transition already exists at this revision'),
  idx_agentboard_run_single_live: () => new TransitionNotAllowed('RUN_ALREADY_LIVE', 'the task already has a live run'),
  idx_agentboard_run_idem: () => new IdempotencyConflict('RUN_ALREADY_STARTED', 'a run with this idempotency key already exists'),
  idx_agentboard_outbox_idem: () => new IdempotencyConflict('OUTBOX_KEY_REUSED', 'an outbox row with this idempotency key already exists'),
  agentboard_operation_pkey: () => new IdempotencyConflict('LEDGER_KEY_REUSED', 'this idempotency key is already committed'),
  idx_agentboard_lease_fence_unique: () => new TransitionNotAllowed('FENCING_TOKEN_REUSED', 'this fencing token is already in use'),
  agentboard_lease_pkey: () => new IdempotencyConflict('LEASE_ID_REUSED', 'this lease id already exists'),
  agentboard_task_pkey: () => new IdempotencyConflict('TASK_ID_REUSED', 'this task id already exists'),
  agentboard_acl_pkey: () => new IdempotencyConflict('TASK_ID_REUSED', 'this task id already exists'),
  agentboard_adapter_pkey: () => new IdempotencyConflict('ADAPTER_REUSED_WITH_DIFFERENT_CONTENT', 'this adapter id is already registered'),
  agentboard_budget_grant_pkey: () => new IdempotencyConflict('BUDGET_GRANT_REUSED_WITH_DIFFERENT_LIMITS', 'this grant id already exists'),
  agentboard_execution_event_pkey: () => new IdempotencyConflict('EVENT_ID_REUSED', 'this event id already exists'),
  agentboard_execution_event_run_id_sequence_key: () => new MalformedResult('EVENT_SEQUENCE_OUT_OF_ORDER', 'this run already has an event at that sequence'),
  agentboard_transition_pkey: () => new IdempotencyConflict('TRANSITION_ID_REUSED', 'this transition id already exists'),
  agentboard_audit_pkey: () => new IdempotencyConflict('AUDIT_ID_REUSED', 'this audit id already exists'),
  agentboard_outbox_pkey: () => new IdempotencyConflict('OUTBOX_ID_REUSED', 'this outbox id already exists'),
  agentboard_run_pkey: () => new IdempotencyConflict('RUN_ID_REUSED', 'this run id already exists'),
  agentboard_reconciliation_pkey: () => new IdempotencyConflict('RECONCILIATION_ID_REUSED', 'this reconciliation id already exists'),
  agentboard_budget_spend_pkey: () => new IdempotencyConflict('SPEND_BUCKET_REUSED', 'this spend bucket already exists'),
});

/**
 * Translate a driver error into a typed BoardError. PostgreSQL's own
 * constraints are the authority for the invariants the in-memory twin has to
 * mirror by hand, so their violations become the same typed refusals the twin
 * raises.
 */
export function mapPostgresError(error) {
  if (!error || typeof error !== 'object') return error;
  if (isBoardError(error)) return error;
  const constraint = typeof error.constraint === 'string' ? error.constraint : null;
  if (error.code === PG_UNIQUE_VIOLATION) {
    const factory = constraint ? CONSTRAINT_ERROR_CODES[constraint] : null;
    if (factory) return factory();
    return new IdempotencyConflict('UNIQUE_VIOLATION', `unique constraint ${String(constraint ?? 'unknown')} violated`);
  }
  if (error.code === PG_CHECK_VIOLATION) {
    return new MalformedResult('CONSTRAINT_VIOLATION', `the row violates the frozen CHECK ${String(constraint ?? 'unknown')}`);
  }
  if (error.code === PG_FOREIGN_KEY_VIOLATION) {
    return new NeedsInput('REFERENCED_ROW_MISSING', `referenced row is missing (${String(constraint ?? 'unknown')})`);
  }
  return error;
}

function assertColumn(table, column) {
  const columns = TABLE_COLUMNS[table];
  if (!columns || !columns.includes(column)) {
    throw new NeedsInput(`unknown column ${String(table)}.${String(column)}`);
  }
  return column;
}

function normalizeRow(table, row) {
  if (!row) return null;
  const out = { ...row };
  for (const column of TABLE_BIGINT[table] ?? []) {
    if (out[column] !== null && out[column] !== undefined) out[column] = Number(out[column]);
  }
  for (const column of TABLE_TIMESTAMPS[table] ?? []) {
    if (out[column] !== null && out[column] !== undefined) out[column] = toIsoMs(out[column], `${table}.${column}`);
  }
  for (const column of TABLE_JSONB[table] ?? []) {
    if (typeof out[column] === 'string') out[column] = JSON.parse(out[column]);
  }
  return out;
}

class PostgresUnitOfWork {
  constructor(client) {
    this.client = client;
    this._now = null;
    this._day = null;
  }

  async now() {
    if (this._now === null) {
      // The DATABASE clock, read once per transaction so that issued_at,
      // expires_at, updated_at and every ledger row of one write agree.
      const result = await this.client.query(
        `SELECT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS iso,
                to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day`,
      );
      this._now = result.rows[0].iso;
      this._day = result.rows[0].day;
    }
    return this._now;
  }

  async nextFencingToken() {
    const result = await this.client.query(`SELECT nextval('agentboard_fencing_token_seq')::bigint AS value`);
    return Number(result.rows[0].value);
  }

  // WHERE clauses are built only from the frozen column whitelist and are
  // always fully parameterized, so no caller-supplied identifier or literal
  // can ever reach a generated statement.
  _where(table, where, offset) {
    const params = [];
    const clauses = Object.entries(where)
      .filter(([, value]) => value !== undefined)
      .map(([column, value]) => {
        assertColumn(table, column);
        params.push(value);
        return `${column} = $${params.length + offset}`;
      });
    return { sql: clauses.length === 0 ? '' : ` WHERE ${clauses.join(' AND ')}`, params };
  }

  async selectRow(table, { where = {}, order = undefined, forUpdate = false } = {}) {
    const { sql: whereSql, params } = this._where(table, where, 0);
    const orderSql = order === undefined ? '' : ` ORDER BY ${ORDERINGS[order].sql}`;
    const lockSql = forUpdate ? ' FOR UPDATE' : '';
    const result = await this.client.query(`SELECT * FROM ${table}${whereSql}${orderSql} LIMIT 1${lockSql}`, params);
    return normalizeRow(table, result.rows[0]);
  }

  async selectRows(table, { where = {}, order = undefined, limit = undefined, forUpdate = false } = {}) {
    const { sql: whereSql, params } = this._where(table, where, 0);
    const orderSql = order === undefined ? '' : ` ORDER BY ${ORDERINGS[order].sql}`;
    const limitSql = limit === undefined ? '' : ` LIMIT ${Number(limit)}`;
    const lockSql = forUpdate ? ' FOR UPDATE' : '';
    const result = await this.client.query(`SELECT * FROM ${table}${whereSql}${orderSql}${limitSql}${lockSql}`, params);
    return result.rows.map((row) => normalizeRow(table, row));
  }

  _param(table, column, value) {
    if (TABLE_JSONB[table]?.includes(column) && value !== null && value !== undefined) return JSON.stringify(value);
    return value === undefined ? null : value;
  }

  async insertRow(table, row, { onConflictDoNothing = false } = {}) {
    const entries = Object.keys(row);
    entries.forEach((column) => assertColumn(table, column));
    const params = entries.map((column) => this._param(table, column, row[column]));
    const placeholders = entries.map((column, index) => `$${index + 1}`);
    const conflict = onConflictDoNothing ? ' ON CONFLICT DO NOTHING' : '';
    const result = await this.client.query(
      `INSERT INTO ${table} (${entries.join(', ')}) VALUES (${placeholders.join(', ')})${conflict} RETURNING *`,
      params,
    );
    if (onConflictDoNothing && result.rows.length === 0) return null;
    return normalizeRow(table, result.rows[0]);
  }

  async updateRows(table, { where = {}, sets = {}, bump = undefined, limit = 1 }) {
    const setClauses = [];
    const params = [];
    for (const [column, value] of Object.entries(sets)) {
      assertColumn(table, column);
      params.push(this._param(table, column, value));
      setClauses.push(`${column} = $${params.length}`);
    }
    if (bump !== undefined) {
      assertColumn(table, bump);
      setClauses.push(`${bump} = ${bump} + 1`);
    }
    const keyColumns = TABLE_PRIMARY_KEY[table];
    if (!keyColumns || keyColumns.length === 0) throw new NeedsInput(`no primary key declared for ${table}`);
    const { sql: whereSql, params: whereParams } = this._where(table, where, params.length);
    params.push(...whereParams);
    const limitSql = limit === undefined ? '' : ` LIMIT ${Number(limit)}`;
    const join = keyColumns.map((column) => `t.${column} = target.${column}`).join(' AND ');
    // The target rows are selected (and locked) in a CTE, then joined back on
    // the primary key: PostgreSQL rejects a bare LIMIT on UPDATE, and an
    // unbounded UPDATE would make "at most one row" unenforceable.
    const result = await this.client.query(
      `WITH target AS (SELECT ${keyColumns.join(', ')} FROM ${table}${whereSql}${limitSql} FOR UPDATE)
       UPDATE ${table} AS t SET ${setClauses.join(', ')} FROM target WHERE ${join} RETURNING t.*`,
      params,
    );
    return result.rows.map((row) => normalizeRow(table, row));
  }
}

export class PostgresAgentBoardStore extends AgentBoardStoreBase {
  constructor({ pool, connectionString, max = 5, connectionTimeoutMillis = 5000, clock, ids, seed, policy } = {}) {
    super({ clock, ids, seed, policy });
    this.backend = 'postgres';
    this.ownsPool = pool === undefined;
    this.pool = pool ?? new Pool({ connectionString, max, connectionTimeoutMillis, options: '-c timezone=UTC' });
  }

  async _acquireUnitOfWork() {
    let client;
    try {
      client = await this.pool.connect();
    } catch (error) {
      throw toBoardError(mapPostgresError(error), 'PROVIDER_FAILURE');
    }
    try {
      await client.query('BEGIN');
    } catch (error) {
      client.release(true);
      throw toBoardError(mapPostgresError(error), 'PROVIDER_FAILURE');
    }
    // Every statement of the unit of work passes through mapPostgresError, so
    // a frozen constraint violation becomes the same typed refusal the
    // in-memory twin raises and no driver error can escape untyped.
    const unit = new PostgresUnitOfWork(client);
    for (const method of ['selectRow', 'selectRows', 'insertRow', 'updateRows', 'now', 'nextFencingToken']) {
      const original = unit[method].bind(unit);
      unit[method] = async (...rest) => {
        try {
          return await original(...rest);
        } catch (error) {
          throw toBoardError(mapPostgresError(error), 'PROVIDER_FAILURE');
        }
      };
    }
    return unit;
  }

  async _commitUnitOfWork(tx) {
    try {
      await tx.client.query('COMMIT');
    } catch (error) {
      // The outcome of a COMMIT that fails mid-flight is UNKNOWN. Reporting it
      // as a clean failure would invite a blind retry of a side effect that may
      // already have happened.
      throw new ReconciliationRequired(
        'STORE_COMMIT_OUTCOME_UNKNOWN',
        toBoardError(mapPostgresError(error), 'PROVIDER_FAILURE').message,
      );
    } finally {
      tx.client.release();
    }
  }

  async _discardUnitOfWork(tx) {
    let destroyed = false;
    try {
      await tx.client.query('ROLLBACK');
    } catch {
      destroyed = true;
    } finally {
      tx.client.release(destroyed ? true : undefined);
    }
  }

  async close() {
    if (this.ownsPool) await this.pool.end();
  }
}

export const STORE_VERSION = 's2-007-store-v1';
export { TABLE_COLUMNS, TABLE_PRIMARY_KEY, ORDERINGS, RECONCILIATION_RESOLUTIONS, RECONCILIATION_DECIDER_KINDS };
