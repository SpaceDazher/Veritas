// S2-007 Agent Board COMMAND BOUNDARY (issue #7 §2, §3, §5, §6).
//
// WHAT THIS MODULE IS
// -------------------
// The single mutation and read surface of the live board. Web, the HTTP API,
// the CLI, the scheduler, the probes and the tests all come through
// `execute()`; nothing else may write an `agentboard_*` row, and no caller may
// reach the store or policy.mjs directly for a board operation. It owns:
//
//   1. THE CLOSED COMMAND SET. `COMMANDS` is the whole vocabulary; a name that
//      is not in it is BLOCKED_POLICY, never a free-form passthrough. Each
//      command declares exactly ONE required board capability, one canonical
//      argument set, and whether it mutates. That table is the only command
//      table in the repository, so `assertCanonicalArguments` can enforce a
//      per-command allowlist without policy.mjs having to restate it.
//   2. THE SERVER-RESOLVED ACTOR. `principal` and `actorKind` are what the
//      server resolved (a session, a service identity, a scheduled principal).
//      Nothing in `args` can authenticate a caller: an authority-shaped
//      argument may only REPEAT the resolved value, and a disagreement is
//      AUTH_REQUIRED. The check runs before any payload data is read, and it
//      runs again immediately before every side effect.
//   3. THE IDEMPOTENCY CONTRACT. `argsDigest =
//      policy.commandIdempotencyKey({ command, args, actor })` and the caller's
//      `idempotency_key` go to the store on EVERY write, so replay detection,
//      digest conflicts and operation binding are store-enforced. Nothing is
//      memoised in this process: a boundary that remembered a result in memory
//      would be a second, invisible source of truth.
//   4. THE ACL. Every read passes the server-resolved principal id into the
//      store, which applies the task ACL before a row is returned, and this
//      module re-checks `assertTaskVisible` before any payload leaves. A
//      refusal returns no payload field at all.
//
// WHY THE COMMANDS ARE WIRED THE WAY THEY ARE
// --------------------------------------------
//   * `tasks.transition` runs `policy.decideTransition`, which reads the edge
//     table in constants.mjs and re-checks the actor, the ACL, the fence, the
//     digests, the budget and the sandbox inside the guard. This module
//     re-asserts the command capability first, so a caller without
//     `board.task.transition` is refused before a row is even read; the
//     edge-specific capability (board.review.approve on the DONE edge,
//     board.task.release on a release, ...) stays owned by the guard, so there
//     is no second edge->capability table here.
//   * `tasks.claim` is the one place where the fence is minted rather than
//     presented. `store.claimTask` is the atomic single-active-lease primitive
//     (DB sequence fence, compare-and-swap revision, journal + audit in one
//     transaction), so the boundary runs every pre-check it can BEFORE the
//     write and then re-runs the full guard against the lease that actually
//     committed. A post-commit guard failure is RECONCILIATION_REQUIRED, never
//     a success and never a silent rollback.
//   * `execution.start` runs the scheduler's dispatch for a READY task
//     (`runSchedulerTick` claims, builds the request, records the run and the
//     outbox row) and, for a task that is already CLAIMED/RUNNING under a live
//     lease, builds the very same server-side ExecutionRequest shape and calls
//     `store.createRun`. In both paths the request is SERVER-BUILT: the scope
//     comes from `deriveExecutionScope(principal)`, the tools from the task, the
//     budget from the stored grant and the digests from the task row. A payload
//     may not contribute a scope, a tool, a budget or a workspace.
//   * `execution.collect_result` writes through `store.collectResult` and then
//     withdraws the lease in the same command. A SUCCEEDED result moves the
//     task to IN_REVIEW (evidence, not correctness); every other outcome moves
//     it to FAILED or BLOCKED and never requeues it — a requeue needs an
//     authorized reconciliation decision, which is a separate command.
//   * `reconciliation.record` requires an authenticated human or an authorized
//     deterministic gate: a producer (adapter) and an uncalibrated semantic
//     verifier can never close an unknown outcome.
//
// DETERMINISM
// -----------
// No Math.random(), no Date.now(), no bare `new Date()`. Every instant is
// injected (`now` / `clock`), every identifier is DERIVED from the S2-006
// canonical digest of the facts that produced it (`deterministicId`), and every
// internal stage key is a canonical digest over the command, the stage and the
// canonical arguments. The same request against the same store state therefore
// produces the same ids, the same keys and the same result on every run.
//
// HONEST STATUS
// -------------
// `capabilities()` reports `mode: 'LIVE_AGENT_BOARD'`, the nine states, the
// closed command set and the contract digests, and it enables execution ONLY
// when a genuinely installed real adapter AND a proven isolation profile both
// exist. On a host with no installed executor it says `executionEnabled:
// false` and `realAdapterStatus: 'NOT_RUN_REAL_ADAPTER'`, and no fixture,
// replay or scripted transport can move that value.
//
// THE SMALL EXTENSIONS TO THE FROZEN SIGNATURE (each one is additive and
// reported, never a re-declaration of a frozen truth)
// ------------------------------------------------------------------------
//  1. `capabilities({ adapters, now, probe, realAdapterStatus })` — the frozen
//     signature is zero-argument. The options object is optional, so
//     `capabilities()` still answers; it exists because `executionEnabled` may
//     only be true on evidence, and the evidence is the caller's (registered
//     adapters + a `probeRealAdapters` result). With no evidence the honest
//     answer is the blocked one. There is no JSON Schema for a discovery
//     document, so the shape is checked with `assertBoardVersion` plus the
//     frozen states/commands/versions — the demo document in src/lib/board.ts
//     is never edited to match.
//  2. `execute({ ..., workspaceRoots, realpath, sandbox, authorizer,
//     requireAuthorizer, ids })` — additive context. `workspaceRoots`/`realpath`
//     are the server-side containment evidence, `sandbox` the proven isolation
//     profile, `ids` the injected id factory (a deterministic digest-derived one
//     is used when it is absent), and `authorizer`/`requireAuthorizer` are
//     handed to the EXPLICIT S2-002 consults this module builds (task.create,
//     board.read, task.cancel) so a deployment can demand the S2-002 decision
//     where a faithful request exists and be refused where it does not. They are
//     deliberately NOT handed to the edge guards: a guard consults S2-002 with
//     the arguments it derives itself, and replacing that decision with a
//     caller-supplied function would put the authorization point outside the one
//     engine the contract names.
//  3. `tasks.claim` asks for `board.execution.start` (the right to execute)
//     rather than `board.task.claim`, and the guard context does not carry the
//     caller's `capabilities` list: grant membership is decided ONCE here,
//     against the server-resolved grant for the COMMAND's capability, while the
//     guard keeps owning the edge capability it was written for.
//  4. Executor-authored text is passed through `redact()` before the store sees
//     it. It is the only place a document is rewritten, and it can only remove
//     a secret-shaped substring.

import {
  ADAPTER_INTERFACE_VERSION,
  BOARD_CONTRACT_VERSION,
  BOARD_STATES,
  COMMAND_BOUNDARY_VERSION,
  EXECUTION_CONTRACT_VERSION,
  ID_PREFIXES,
  PROVEN_SANDBOX_PROFILE_IDS,
  isExecutableSandboxProfile,
} from './constants.mjs';
import {
  crossCheckCapabilities,
  probeRealAdapters,
} from './adapters.mjs';
import {
  allContractDigests,
  assertBoardContract,
  assertBoardVersion,
  assertDigestAgreement,
  assertExecutionVersion,
} from './contracts.mjs';
import {
  AclDenied,
  AgentUnavailable,
  AuthRequired,
  BlockedPolicy,
  BlockedSandbox,
  BudgetExceeded,
  IdempotencyConflict,
  MalformedResult,
  NeedsInput,
  NotRunRealAdapter,
  ReconciliationRequired,
  StaleFence,
  isBoardError,
  redact,
  toBoardError,
} from './errors.mjs';
import {
  assertActor,
  assertCanonicalArguments,
  assertCapabilitySubset,
  assertDigestsMatch,
  assertHumanOnlyApproval,
  assertNotSelfApproved,
  assertLiveExecutionAuthorized,
  assertSandboxExecutable,
  assertScopeSubset,
  assertTaskVisible,
  assertToolSubset,
  assertWorkspaceWithin,
  assertBudgetAssignable,
  assertWithinBudget,
  commandIdempotencyKey,
  decideTransition,
  fixedClock,
} from './policy.mjs';
import {
  deriveExecutionScope,
  driveOutbox,
  planDispatch,
  recoverOutbox,
  runSchedulerTick,
  toInjectedInstant,
} from './scheduler.mjs';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import { WORKSPACES } from '../identity/principals.mjs';

export const COMMANDS_VERSION = COMMAND_BOUNDARY_VERSION;

// The closed command vocabulary of the live board (frozen spec §3.5). An
// unknown name is BLOCKED_POLICY: there is no dynamic dispatch here, so a new
// operation is a new entry in this file, reviewed like any other boundary.
export const COMMANDS = Object.freeze([
  'tasks.list', 'tasks.get', 'tasks.create', 'tasks.transition',
  'tasks.claim', 'tasks.lease.renew', 'tasks.lease.release', 'tasks.lease.reassign', 'tasks.lease.revoke',
  'tasks.cancel', 'adapters.list', 'adapters.register', 'adapters.health',
  'dispatch.plan', 'dispatch.tick', 'execution.start', 'execution.event', 'execution.collect_result',
  'execution.cancel', 'budget.grant', 'budget.settle', 'outbox.list', 'outbox.dispatch', 'outbox.recover',
  'audit.list', 'reconciliation.record', 'capabilities',
]);

// Payload fields that name the authority itself. A request may carry one only
// to repeat what the server resolved; disagreement is AUTH_REQUIRED. The list
// is the frozen spec §3.5 list verbatim — it decides what is CHECKED here, not
// what is granted.
const AUTHORITY_ARGUMENTS = Object.freeze([
  'principal_id', 'actor', 'actor_kind', 'granted_scope', 'allowed_tools', 'budget', 'budget_grant',
  'approved', 'approval', 'lease_id', 'fencing_token', 'role', 'capabilities',
]);

// The command table: capability, canonical arguments and mutability. `keys` is
// the allowlist handed to assertCanonicalArguments; the authority arguments are
// added to it automatically so that a faithful repeat is accepted (and then
// ignored) while anything else is ARGUMENT_NOT_CANONICAL.
const COMMAND_TABLE = Object.freeze({
  'tasks.list': {
    capability: 'board.task.read',
    mutating: false,
    keys: ['workspace_id', 'state', 'limit', 'idempotency_key'],
  },
  'tasks.get': {
    capability: 'board.task.read',
    mutating: false,
    keys: ['task_id', 'idempotency_key'],
  },
  'tasks.create': {
    capability: 'board.task.create',
    mutating: true,
    keys: ['task', 'idempotency_key'],
  },
  'tasks.transition': {
    capability: 'board.task.transition',
    mutating: true,
    keys: [
      'task_id', 'to_state', 'expected_revision', 'reason', 'brief_digest', 'policy_digest',
      'manifest_digest', 'reconciliation_id', 'idempotency_key',
    ],
  },
  // A claim grants the RIGHT TO EXECUTE this task, so the capability it asks
  // for is `board.execution.start` — the same grant an executor principal
  // holds for the work it is about to run. `board.task.claim` stays the
  // capability the READY -> CLAIMED guard asserts through its own actor check;
  // this table does not restate it (see the guard-context note in the header).
  'tasks.claim': {
    capability: 'board.execution.start',
    mutating: true,
    keys: ['task_id', 'adapter_id', 'expected_revision', 'ttl_ms', 'idempotency_key'],
  },
  'tasks.lease.renew': {
    capability: 'board.execution.start',
    mutating: true,
    keys: ['lease_id', 'fencing_token', 'ttl_ms', 'idempotency_key'],
  },
  'tasks.lease.release': {
    capability: 'board.task.release',
    mutating: true,
    keys: ['lease_id', 'fencing_token', 'reason', 'reconciliation_id', 'idempotency_key'],
  },
  'tasks.lease.reassign': {
    capability: 'board.task.claim',
    mutating: true,
    keys: ['lease_id', 'fencing_token', 'new_adapter_id', 'reason', 'idempotency_key'],
  },
  'tasks.lease.revoke': {
    capability: 'board.task.release',
    mutating: true,
    keys: ['lease_id', 'fencing_token', 'reason', 'idempotency_key'],
  },
  'tasks.cancel': {
    capability: 'board.execution.cancel',
    mutating: true,
    keys: ['task_id', 'reason', 'idempotency_key'],
  },
  'adapters.list': {
    capability: 'board.task.read',
    mutating: false,
    keys: ['workspace_id', 'idempotency_key'],
  },
  'adapters.register': {
    capability: 'board.adapter.register',
    mutating: true,
    keys: ['registration', 'idempotency_key'],
  },
  'adapters.health': {
    capability: 'board.adapter.register',
    mutating: true,
    keys: ['adapter_id', 'health', 'idempotency_key'],
  },
  'dispatch.plan': {
    capability: 'board.task.read',
    mutating: false,
    keys: ['workspace_id', 'idempotency_key'],
  },
  'dispatch.tick': {
    capability: 'board.task.claim',
    mutating: true,
    keys: ['workspace_id', 'idempotency_key'],
  },
  'execution.start': {
    capability: 'board.execution.start',
    mutating: true,
    keys: ['task_id', 'adapter_id', 'idempotency_key'],
  },
  'execution.event': {
    capability: 'board.evidence.submit',
    mutating: true,
    keys: ['run_id', 'event', 'idempotency_key'],
  },
  'execution.collect_result': {
    capability: 'board.result.collect',
    mutating: true,
    keys: ['run_id', 'result', 'idempotency_key'],
  },
  'execution.cancel': {
    capability: 'board.execution.cancel',
    mutating: true,
    keys: ['run_id', 'reason', 'idempotency_key'],
  },
  'budget.grant': {
    capability: 'board.budget.grant',
    mutating: true,
    keys: ['grant', 'idempotency_key'],
  },
  'budget.settle': {
    capability: 'board.budget.grant',
    mutating: true,
    keys: ['grant_id', 'operation_id', 'task_id', 'amount', 'currency', 'day_key', 'idempotency_key'],
  },
  'outbox.list': {
    capability: 'board.task.read',
    mutating: false,
    keys: ['workspace_id', 'dispatch_state', 'idempotency_key'],
  },
  'outbox.dispatch': {
    capability: 'board.execution.start',
    mutating: true,
    keys: ['workspace_id', 'limit', 'idempotency_key'],
  },
  'outbox.recover': {
    capability: 'board.task.transition',
    mutating: true,
    keys: ['workspace_id', 'limit', 'idempotency_key'],
  },
  'audit.list': {
    capability: 'board.task.read',
    mutating: false,
    keys: ['workspace_id', 'task_id', 'limit', 'idempotency_key'],
  },
  'reconciliation.record': {
    capability: 'board.reconciliation.decide',
    mutating: true,
    keys: ['reconciliation', 'idempotency_key'],
  },
  'capabilities': {
    capability: 'board.task.read',
    mutating: false,
    keys: ['workspace_id', 'idempotency_key'],
  },
});

// The approval edge is the one place where the command capability is NOT the
// whole requirement: IN_REVIEW -> DONE is an approval, not a state change, so
// `board.review.approve` is required IN ADDITION to `board.task.transition`.
// This is a narrowing on top of the guard (which independently re-checks the
// actor kind, the self-approval rule and the reviewed digests), never a
// replacement for it.
const EDGE_CAPABILITY_NARROWING = Object.freeze({ DONE: 'board.review.approve' });

const MUTATING_COMMANDS = Object.freeze(new Set(
  Object.entries(COMMAND_TABLE).filter(([, spec]) => spec.mutating).map(([command]) => command),
));

const HEX64 = /^[0-9a-f]{64}$/;
const DIGEST_WIRE = /^sha256:[0-9a-f]{64}$/;
const MAX_LIST_LIMIT = 200;
const DEFAULT_LIST_LIMIT = 50;
// The least-privilege scope of a task run. A bounded run reads its own task and
// writes that task's artifacts; every wider scope (task.write,
// evidence.submit, checkpoint.write, budget.spend) is only handed over when the
// operator's principal carries an explicit server-resolved `granted_scope`.
// It is a default that a request may only narrow, never widen.
const DEFAULT_RUN_SCOPE = Object.freeze(['task.read', 'artifact.write']);
// Fields whose value IS an identity or a closed enum. They are compared with
// server state and must survive byte-identical, so the redaction pass below
// leaves them alone (the redaction patterns could never match them anyway).
const NON_REDACTABLE_FIELDS = Object.freeze(new Set([
  'contract_version', 'run_id', 'task_id', 'workspace_id', 'lease_id', 'event_id', 'request_id',
  'adapter_id', 'artifact_id', 'checkpoint_id', 'event_type', 'outcome', 'media_type', 'currency',
  'sequence', 'fencing_token', 'state',
]));
const MAX_REDACT_DEPTH = 8;
// A grant is only usable while it is neither revoked nor expired against the
// injected instant; both facts are re-read at the side effect, never cached.

// --- small deterministic helpers -------------------------------------------

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(value, label) {
  if (!isPlainObject(value)) throw new NeedsInput(`${label}_MISSING`, `${label} must be a plain object`);
  return value;
}

function requireText(value, label, max = 256) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    throw new NeedsInput(`ARGUMENT_INVALID:${label}`);
  }
  return value;
}

function requirePositiveInteger(value, label, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isInteger(value) || value <= 0 || value > max) throw new NeedsInput(`ARGUMENT_INVALID:${label}`);
  return value;
}

function optionalInteger(value, label, max) {
  if (value === undefined || value === null) return null;
  return requirePositiveInteger(value, label, max);
}

/**
 * The server-resolved principal. `principal` is NEVER read out of `args`:
 * a payload field named principal_id can only be compared with what this
 * function resolved, never supply it.
 */
function resolvePrincipal(principal) {
  const principalId = typeof principal === 'string' ? principal : principal?.principal_id;
  if (typeof principalId !== 'string' || principalId.length === 0) {
    throw new AuthRequired('AUTH_REQUIRED', 'no server-resolved principal on the request');
  }
  const capabilities = isPlainObject(principal) && principal.capabilities !== undefined
    ? principal.capabilities
    : null;
  return { principal_id: principalId, capabilities, workspace_ids: isPlainObject(principal) ? principal.workspace_ids ?? null : null };
}

/** The injected instant. The host clock is never read; a missing injection falls back to the store's DB clock. */
async function resolveInstant({ now, clock }, store) {
  if (now !== undefined && now !== null) return toInjectedInstant(now, 'now');
  if (clock !== undefined && clock !== null) return toInjectedInstant(clock, 'now');
  if (store && typeof store.dbNow === 'function') return toInjectedInstant(await store.dbNow(), 'now');
  throw new NeedsInput('INJECTED_CLOCK_MISSING', 'the command boundary never reads the process clock');
}

/** A stable id derived from the facts that produced it. No randomness, no counter, no host clock. */
function deterministicId(kind, seed) {
  const prefix = ID_PREFIXES[kind];
  if (!prefix) throw new NeedsInput(`ID_KIND_UNKNOWN:${String(kind)}`);
  const digest = canonicalDigest({ kind, seed });
  return `${prefix}${digest.slice(0, 16)}`;
}

/** A deterministic id FACTORY for the scheduler, which asks for one prefix at a time. */
function deterministicIdFactory(seed) {
  return (kind, hint = 0) => deterministicId(kind, { ...seed, hint });
}

/** One ledger key per operation. A multi-stage command derives a key per stage. */
function stageKey({ command, stage, actor, args }) {
  return commandIdempotencyKey({ command, stage, actor, args });
}

function argsDigestOf({ command, args, actor }) {
  return commandIdempotencyKey({ command, args, actor });
}

function requireIdempotencyKey(args, command) {
  const key = args.idempotency_key;
  if (!MUTATING_COMMANDS.has(command)) return typeof key === 'string' && HEX64.test(key) ? key : null;
  if (typeof key !== 'string' || !HEX64.test(key)) {
    // A mutating command without a stable key cannot be replayed, cannot be
    // conflict-detected and cannot be reconciled after a crash. Refused.
    throw new NeedsInput('IDEMPOTENCY_KEY_REQUIRED', `${command} requires a 64 hex idempotency_key`);
  }
  return key;
}

function boundedLimit(value) {
  if (value === undefined || value === null) return DEFAULT_LIST_LIMIT;
  return requirePositiveInteger(value, 'limit', MAX_LIST_LIMIT);
}

/**
 * The authority-agreement rule (frozen spec §3.5). An argument that names the
 * authority may only REPEAT the server-resolved value; a disagreement is
 * AUTH_REQUIRED, never a merge, never a widening, and never a silent ignore.
 *
 * `lease_id` and `fencing_token` are handled separately and deliberately: a
 * lease id SELECTS the target (it is resolved by a server read, and the ACL,
 * the workspace and the fence are then checked against it), while the fence is
 * an authority and must equal the current one — `resolveFence` compares it and
 * a disagreement is STALE_FENCE.
 */
function assertAuthorityAgreement(args, resolved) {
  for (const key of AUTHORITY_ARGUMENTS) {
    if (key === 'lease_id' || key === 'fencing_token') continue;
    if (!Object.hasOwn(args, key)) continue;
    const presented = args[key];
    if (presented === null || presented === undefined) continue;
    const expected = resolved[key];
    if (expected === undefined) {
      // The server resolved nothing for this field, so a payload may not
      // supply it at all: an unresolvable authority is not a claimable one.
      throw new AuthRequired('AUTH_REQUIRED', `${key} is not a server-resolved value of this request`);
    }
    if (!sameValue(presented, expected)) {
      throw new AuthRequired('AUTH_REQUIRED', `${key} disagrees with the server-resolved authority`);
    }
  }
  return true;
}

function sameValue(left, right) {
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    return left.every((item, index) => sameValue(item, right[index]));
  }
  if (isPlainObject(left) || isPlainObject(right)) {
    if (!isPlainObject(left) || !isPlainObject(right)) return false;
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    if (leftKeys.length !== rightKeys.length) return false;
    if (!leftKeys.every((key, index) => key === rightKeys[index])) return false;
    return leftKeys.every((key) => sameValue(left[key], right[key]));
  }
  return Object.is(left, right);
}

function allowedKeysFor(command) {
  const spec = COMMAND_TABLE[command];
  return Object.freeze([...spec.keys, ...AUTHORITY_ARGUMENTS.filter((key) => !spec.keys.includes(key))]);
}

// --- workspace roots (S2-002 registry, never a second source) ---------------

/**
 * Absolute server-side roots for a workspace. `workspaceRoots` is the
 * caller's injection point (an operator-deployed board knows its own roots);
 * without it the S2-002 WORKSPACES registry is consulted, exactly as
 * policy.mjs does. An unknown workspace is ACL_DENIED, never "everything".
 */
function resolveWorkspaceRoots(workspaceId, injected) {
  if (Array.isArray(injected) && injected.length > 0) return injected;
  const workspace = WORKSPACES.find((entry) => entry.workspace_id === workspaceId);
  if (workspace && Array.isArray(workspace.allowed_roots) && workspace.allowed_roots.length > 0) {
    return workspace.allowed_roots;
  }
  throw new AclDenied('WORKSPACE_ROOTS_UNKNOWN', `no workspace root is registered for ${String(workspaceId)}`);
}

// --- server-side facts the guards consume -----------------------------------

function briefIsValidated(task) {
  // The immutable brief is "validated" when the task row still carries the
  // three digests it was created with. A task whose digests are missing or
  // malformed has no validated brief, and the BACKLOG->READY and BLOCKED->READY
  // edges stay closed. A payload can only disagree with this, never assert it.
  return [task.brief_digest, task.policy_digest, task.manifest_digest].every((digest) => DIGEST_WIRE.test(String(digest)));
}

async function dependenciesAreSatisfied(store, task, { workspaceId, principalId }) {
  const dependencies = Array.isArray(task.dependencies) ? task.dependencies : [];
  if (dependencies.length === 0) return true;
  for (const dependency of dependencies) {
    if (typeof dependency !== 'string') return false;
    const row = await store.getTask(dependency, { workspaceId, principalId });
    if (!isPlainObject(row) || row.state !== 'DONE') return false;
  }
  return true;
}

/** The stored grant that covers this task right now. An unassigned budget is NOT zero. */
async function resolveGrant(store, { workspaceId, taskId, now }) {
  const grants = await store.listBudgetGrants({ workspaceId, task_id: taskId });
  const usable = (Array.isArray(grants) ? grants : []).filter((grant) => (
    isPlainObject(grant)
    && (grant.task_id === null || grant.task_id === undefined || grant.task_id === taskId)
    && (grant.revoked_at === null || grant.revoked_at === undefined)
    && (grant.expires_at === null || grant.expires_at === undefined || Date.parse(grant.expires_at) > Date.parse(now))
    && [grant.task_limit, grant.campaign_limit, grant.day_limit].every(
      (value) => typeof value === 'number' && Number.isFinite(value) && value > 0,
    )
  ));
  return usable[0] ?? null;
}

async function resolveSpent(store, grant, now) {
  if (!isPlainObject(grant) || typeof grant.grant_id !== 'string') return {};
  const dayKey = now.slice(0, 10);
  const row = await store.readBudgetSpend(grant.grant_id, dayKey);
  if (!isPlainObject(row)) return {};
  return {
    spent_task: Number(row.spent_task ?? 0),
    spent_campaign: Number(row.spent_campaign ?? 0),
    spent_day: Number(row.spent_day ?? 0),
  };
}

/** The registered adapters a guard may consider: server state, never a payload list. */
async function registeredAdapters({ store, adapters, workspaceId, injected }) {
  if (Array.isArray(injected) && injected.length > 0) return injected.filter(isPlainObject);
  const rows = await store.listAdapters({ workspaceId });
  return (Array.isArray(rows) ? rows : []).filter(isPlainObject);
}

/** The live lease of a task, read server-side. A payload may only repeat its fence. */
async function activeLeaseOf(store, task) {
  if (typeof task.active_lease_id !== 'string') return null;
  const lease = await store.readLease(task.active_lease_id);
  if (!isPlainObject(lease) || lease.lease_state !== 'ACTIVE') return null;
  return lease;
}

async function countActiveLeases(store, workspaceId) {
  const rows = await store.listLeases({ workspaceId, leaseState: 'ACTIVE' });
  return (Array.isArray(rows) ? rows : []).length;
}

// --- the boundary context ---------------------------------------------------

/**
 * Everything a handler and the guards may use. It carries the server-resolved
 * actor, the injected instant, the server-side roots/resolver and the optional
 * authorizer. Handlers never see `args` except as the value they validate.
 */
function makeContext({ command, args, principal, actorKind, store, adapters, clock, transport, now, instant, workspaceRoots, realpath, authorizer, requireAuthorizer, ids }) {
  return {
    command,
    args,
    principal,
    principalId: principal.principal_id,
    actorKind,
    store,
    adapters,
    transport,
    clock,
    now,
    instant,
    workspaceRoots,
    realpath,
    authorizer,
    requireAuthorizer,
    ids,
    idempotencyKey: null,
    argsDigest: null,
  };
}

/**
 * The re-check that runs IMMEDIATELY BEFORE every side effect. A grant, an ACL
 * or a canonical argument that changed between the first check and the write is
 * refused here rather than discovered afterwards. It is cheap on purpose: the
 * store re-verifies the revision, the fence and the ACL under its own locks, and
 * this re-check is what makes the "re-check immediately before the side effect"
 * rule true for the actor, the arguments and the ACL.
 */
async function recheck(ctx, { command = ctx.command, args = ctx.args, capability = null, task = null } = {}) {
  const spec = COMMAND_TABLE[command];
  if (!spec) throw new BlockedPolicy(`COMMAND_UNKNOWN:${String(command)}`);
  if (capability) {
    // The re-check is the COARSE authorization decision repeated immediately
    // before the side effect: the server-resolved principal, the actor kind and
    // the membership of the command's capability in the server-resolved grant.
    // The S2-002 decision is NOT re-taken here — it is taken by the consult the
    // handler already ran (assertIdentityConsult) and, for the edges, by the
    // guard's own consult inside decideTransition.
    assertActor({
      principal: ctx.principal,
      actorKind: ctx.actorKind,
      capability,
      capabilities: ctx.principal.capabilities,
      workspaceId: task ? task.workspace_id : args.workspace_id,
      resourceId: task ? task.task_id : undefined,
      now: ctx.instant,
    });
  }
  policyAssertCanonicalArguments(command, args);
  if (task) assertTaskVisible(task, ctx.principalId);
  return true;
}

// `policy.assertCanonicalArguments` names a command with its own grammar
// (`^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$`), which requires a dot — while the
// frozen COMMANDS list contains exactly one undotted name, `capabilities`.
// Rather than re-implement the canonical-argument check here, the discovery
// command is validated under this documented ALIAS. The alias is not in
// COMMANDS, so it is unreachable through execute(): the entry point still
// refuses it as an unknown command. One shim, one line, no second validator.
const ARGUMENT_VALIDATION_ALIAS = Object.freeze({ capabilities: 'capabilities.discovery' });

function policyAssertCanonicalArguments(command, args) {
  return assertCanonicalArguments(ARGUMENT_VALIDATION_ALIAS[command] ?? command, args, { allowedKeys: allowedKeysFor(command) });
}

/** Read the task the caller named, with the ACL applied inside the store. */
async function readTask(ctx, taskId, { workspaceId = undefined } = {}) {
  const task = await ctx.store.getTask(taskId, { workspaceId, principalId: ctx.principalId });
  if (!isPlainObject(task)) throw new NeedsInput(`TASK_NOT_FOUND:${String(taskId)}`);
  // The ACL is applied by the store before the row exists here; this is the
  // second, local application so that no handler can accidentally return a
  // task it read through another path.
  assertTaskVisible(task, ctx.principalId);
  return task;
}

/** Every guard context field the policy contract documents, resolved server-side. */
async function guardContextFor(ctx, { task, toState, expectedRevision, reason, lease, fencingToken, digests, reconciliation, adapters, budgetGrant, budgetSpent, dependenciesSatisfied, briefValidated, actorAdapterId, activeLeaseCount }) {
  const workspaceId = task.workspace_id;
  // Both facts are RESOLVED HERE, never taken from the payload: an absent
  // override means "look it up", and the lookup is a server read.
  const dependencies = dependenciesSatisfied === undefined
    ? await dependenciesAreSatisfied(ctx.store, task, { workspaceId, principalId: ctx.principalId })
    : dependenciesSatisfied === true;
  const brief = briefValidated === undefined ? briefIsValidated(task) : briefValidated === true;
  const context = {
    task,
    toState,
    expectedRevision,
    reason,
    lease: lease ?? null,
    fencingToken: fencingToken ?? null,
    actor: actorAdapterId
      ? { principal_id: ctx.principalId, adapter_id: actorAdapterId }
      : { principal_id: ctx.principalId },
    actorKind: ctx.actorKind,
    now: ctx.instant,
    adapters: adapters ?? await registeredAdapters({ store: ctx.store, adapters: ctx.adapters, workspaceId }),
    budgetGrant: budgetGrant ?? undefined,
    budgetSpent: budgetSpent ?? undefined,
    dependenciesSatisfied: dependencies,
    briefValidated: brief,
    reconciliation: reconciliation ?? null,
    digests: digests ?? undefined,
    canonicalArgs: { ...ctx.args },
    // The server-resolved grant IS forwarded into the guard, so the edge
    // capability the guard owns (board.task.claim on READY->CLAIMED, say) is
    // checked against the same authoritative list. Forwarding it can only
    // NARROW: an absent grant now fails closed in assertActor instead of
    // skipping the check, and a grant that omits the edge capability refuses
    // the edge. Nothing is widened — the boundary additionally re-asserts the
    // command's own capability immediately before every side effect, and an
    // approval needs the narrowing capability as well.
    capabilities: ctx.principal.capabilities,
    workspaceRoots: resolveWorkspaceRoots(workspaceId, ctx.workspaceRoots),
    realpath: ctx.realpath,
    requireAuthorizer: false,
    // The guard consults S2-002 ITSELF, with the canonical arguments it derives
    // from the task row (task.cancel on a cancel, task.transition on a move,
    // and so on). This boundary never substitutes its own authorizer for that
    // decision: `ctx.authorizer` / `ctx.requireAuthorizer` reach the explicit
    // consults (assertIdentityConsult) only, where this module built the
    // request and can therefore vouch for it.
    authorizer: undefined,
    // The server-resolved named human authorisation for a run bound to the
    // HOST_UNISOLATED floor tier (issue #45). It is forwarded so the guard's own
    // live-execution gate judges the same document execution.start judged; it
    // is never taken from the payload.
    unisolatedExecutionAuthorization: ctx.unisolatedExecutionAuthorization ?? null,
    // The count that AUTHORIZED the edge. A claim is judged against the
    // workspace as it stood before the claim, which is also the count the
    // post-commit verification must use — otherwise the lease the claim itself
    // created would read as a concurrency violation.
    activeLeaseCount: activeLeaseCount === undefined
      ? await countActiveLeases(ctx.store, workspaceId)
      : activeLeaseCount,
  };
  return context;
}

/** Decide and re-check in the order the contract demands: decide, then re-check, then write. */
async function decide(ctx, { task, toState, expectedRevision, reason, lease, fencingToken, digests, reconciliation, adapters, budgetGrant, budgetSpent, actorAdapterId, activeLeaseCount }) {
  const context = await guardContextFor(ctx, {
    task,
    toState,
    expectedRevision,
    reason,
    lease,
    fencingToken,
    digests,
    reconciliation,
    adapters,
    budgetGrant,
    budgetSpent,
    actorAdapterId,
    activeLeaseCount,
  });
  await recheck(ctx, { task });
  decideTransition({ task, toState, context });
  return context;
}

// --- discovery ---------------------------------------------------------------

/**
 * The live board's discovery document. It is a contract-SHAPED document
 * (assertBoardVersion + the frozen states/commands/versions, never a private
 * list) and it is honest: `executionEnabled` is true only when a genuinely
 * installed real adapter AND a proven isolation profile are BOTH present, and
 * `realAdapterStatus` is NOT_RUN_REAL_ADAPTER otherwise. `adapters` and
 * `probe` are the caller-supplied live evidence; with no evidence the honest
 * answer is the blocked one.
 */
export function capabilities({
  adapters = [],
  now = null,
  probe = null,
  realAdapterStatus = 'NOT_RUN_REAL_ADAPTER',
} = {}) {
  const registrations = (Array.isArray(adapters) ? adapters : []).filter(isPlainObject);
  const provenSandbox = PROVEN_SANDBOX_PROFILE_IDS.filter((profileId) => isExecutableSandboxProfile(profileId));
  const declaredReal = registrations.filter((adapter) => (
    adapter.adapter_kind === 'real'
    && isPlainObject(adapter.real_adapter_provenance)
    && adapter.real_adapter_provenance.status === 'REAL_ADAPTER_AVAILABLE'
  ));
  const probeRows = Array.isArray(probe) ? probe.filter(isPlainObject) : [];
  const installedProbe = new Map(probeRows.map((row) => [row.adapter_id, row]));
  // A registration may CLAIM a real adapter; only the host probe may CONFIRM
  // one. A claim without a matching host fact is not an installation.
  const installed = declaredReal.filter((adapter) => installedProbe.get(adapter.adapter_id)?.installed === true);
  const executionEnabled = installed.length > 0 && provenSandbox.length > 0;
  const status = executionEnabled ? 'REAL_ADAPTER_AVAILABLE' : 'NOT_RUN_REAL_ADAPTER';
  const document = {
    contractVersion: BOARD_CONTRACT_VERSION,
    mode: 'LIVE_AGENT_BOARD',
    boundaryVersion: COMMANDS_VERSION,
    interfaces: ['web', 'http', 'cli', 'scheduler'],
    states: [...BOARD_STATES],
    commands: [...COMMANDS],
    capabilities: Object.freeze(COMMANDS.map((command) => ({
      command,
      required: COMMAND_TABLE[command].capability,
      mutating: COMMAND_TABLE[command].mutating,
    }))),
    contractVersions: {
      board: BOARD_CONTRACT_VERSION,
      execution: EXECUTION_CONTRACT_VERSION,
      adapter: ADAPTER_INTERFACE_VERSION,
    },
    contractDigests: allContractDigests(),
    adapters: registrations.map((adapter) => ({
      adapter_id: adapter.adapter_id,
      adapter_kind: adapter.adapter_kind,
      health: adapter.health,
      workspace_id: adapter.workspace_id,
      sandbox_profile_id: adapter.sandbox_profile_id,
      provenance_status: adapter.real_adapter_provenance?.status ?? 'NOT_RUN_REAL_ADAPTER',
    })),
    executionEnabled,
    approvalEnabled: true,
    realAdapterStatus: executionEnabled ? status : realAdapterStatus,
    sandboxProfileIds: [...provenSandbox],
    realAdapterProbe: probeRows,
    privateDataAllowed: false,
    limits: 'Live board. Every mutation is authorized server-side, idempotent and audited; leases are fenced and budgets are numeric. No payload ever authenticates a caller.',
  };
  assertBoardVersion(document);
  return document;
}

/** The live, probe-backed discovery document for the `capabilities` command. */
async function liveCapabilities({ adapters, workspaceId, clock, instant }) {
  const registrations = (Array.isArray(adapters) ? adapters : []).filter(isPlainObject);
  const claimsReal = registrations.some((adapter) => (
    adapter.adapter_kind === 'real'
    && adapter.real_adapter_provenance?.status === 'REAL_ADAPTER_AVAILABLE'
  ));
  // Only probe the host when a registration actually claims a real adapter:
  // spawning `which` for a board that runs nothing would be theatre.
  if (!claimsReal) return capabilities({ adapters: registrations, now: instant });
  const probe = await probeRealAdapters({ clock: clock ?? fixedClock(instant) });
  return capabilities({ adapters: registrations, now: instant, probe });
}

// --- handlers ---------------------------------------------------------------

const handlers = Object.freeze({
  // --- reads ---------------------------------------------------------------

  async 'tasks.list'(ctx) {
    const workspaceId = requireText(ctx.args.workspace_id, 'workspace_id', 64);
    assertIdentityConsult(ctx, 'board.task.read', { workspace_id: workspaceId }, { workspaceId, resourceId: workspaceId }, { required: ['workspace_id'] });
    const tasks = await ctx.store.listTasks({
      workspaceId,
      principalId: ctx.principalId,
      state: ctx.args.state ?? undefined,
      limit: boundedLimit(ctx.args.limit),
    });
    // The capability, the ACL and the consult are all re-checked before the
    // rows leave this module.
    await recheck(ctx, { capability: COMMAND_TABLE['tasks.list'].capability, task: null });
    return { data: { tasks, workspace_id: workspaceId }, revision: null };
  },

  async 'tasks.get'(ctx) {
    const taskId = requireText(ctx.args.task_id, 'task_id', 64);
    const task = await readTask(ctx, taskId, { workspaceId: ctx.args.workspace_id ?? undefined });
    // The S2-002 board.read consult first (it fixes ctx.identityArgs), then the
    // command capability and the ACL again, and only then the payload exists
    // for the caller.
    assertIdentityConsultForRead(ctx, task);
    await recheck(ctx, {
      capability: COMMAND_TABLE['tasks.get'].capability,
      task,
    });
    return { data: { task }, revision: task.revision };
  },

  async 'adapters.list'(ctx) {
    const workspaceId = requireText(ctx.args.workspace_id, 'workspace_id', 64);
    assertIdentityConsult(ctx, 'board.task.read', { workspace_id: workspaceId }, { workspaceId, resourceId: workspaceId }, { required: ['workspace_id'] });
    const adapters = await ctx.store.listAdapters({ workspaceId });
    await recheck(ctx, { capability: COMMAND_TABLE['adapters.list'].capability });
    return { data: { adapters, workspace_id: workspaceId }, revision: null };
  },

  async 'outbox.list'(ctx) {
    const workspaceId = requireText(ctx.args.workspace_id, 'workspace_id', 64);
    const rows = await ctx.store.listOutbox({
      workspaceId,
      principalId: ctx.principalId,
      dispatchState: ctx.args.dispatch_state ?? undefined,
    });
    await recheck(ctx, { capability: COMMAND_TABLE['outbox.list'].capability });
    return { data: { outbox: rows, workspace_id: workspaceId }, revision: null };
  },

  async 'audit.list'(ctx) {
    const workspaceId = requireText(ctx.args.workspace_id, 'workspace_id', 64);
    const taskId = ctx.args.task_id ?? null;
    if (taskId !== null) {
      const task = await readTask(ctx, taskId, { workspaceId });
      await recheck(ctx, { capability: COMMAND_TABLE['audit.list'].capability, task });
    } else {
      await recheck(ctx, { capability: COMMAND_TABLE['audit.list'].capability });
    }
    const rows = await ctx.store.listAudit({ workspaceId, taskId, limit: boundedLimit(ctx.args.limit) });
    return { data: { audit: rows, workspace_id: workspaceId }, revision: null };
  },

  async 'dispatch.plan'(ctx) {
    const workspaceId = requireText(ctx.args.workspace_id, 'workspace_id', 64);
    const tasks = await ctx.store.listTasks({ workspaceId, principalId: ctx.principalId, limit: MAX_LIST_LIMIT });
    // A plan is a READ: it explains a decision, it issues nothing.
    await recheck(ctx, { capability: COMMAND_TABLE['dispatch.plan'].capability });
    const decision = await planFor(ctx, { workspaceId, tasks });
    return { data: { decision }, revision: null };
  },

  async capabilities(ctx) {
    await recheck(ctx, { capability: COMMAND_TABLE.capabilities.capability });
    const adapters = Array.isArray(ctx.adapters) && ctx.adapters.length > 0
      ? ctx.adapters
      : (ctx.args.workspace_id ? await ctx.store.listAdapters({ workspaceId: ctx.args.workspace_id }) : []);
    return { data: { capabilities: await liveCapabilities({ adapters, workspaceId: ctx.args.workspace_id ?? null, clock: ctx.clock, instant: ctx.instant }) }, revision: null };
  },

  // --- task lifecycle ------------------------------------------------------

  async 'tasks.create'(ctx) {
    const task = requireObject(ctx.args.task, 'task');
    // 1. the wire shape, through the single contract registry;
    assertBoardContract('board-task', task, MalformedResult);
    // 2. the S2-002 consult for task.create, built only from the document the
    //    caller will really create (never from an authorization field).
    assertIdentityConsult(ctx, 'board.task.create', { title: task.title, criteria: task.acceptance_criteria }, {
      workspaceId: task.workspace_id,
      resourceId: task.task_id,
    });
    // 3. the ACL the caller declares must include the caller: a task that
    //    hides itself from its own creator can never be approved or read.
    const acl = requireObject(task.acl, 'task.acl');
    if (!Array.isArray(acl.allowed_principal_ids) || !acl.allowed_principal_ids.includes(ctx.principalId)) {
      throw new BlockedPolicy('TASK_ACL_EXCLUDES_CREATOR', 'a task may not be created into an ACL that excludes its creator');
    }
    // 4. the workspace must be inside a registered root (lexical + symlink).
    assertWorkspaceWithin(
      task.workspace_ref,
      resolveWorkspaceRoots(task.workspace_id, ctx.workspaceRoots),
      { realpath: ctx.realpath },
    );
    // 5. the budget the task authorizes must be assignable now: a task with no
    //    numeric budget is a task nobody may schedule.
    assertBudgetAssignable(task.cost_limits);
    assertWithinBudget(task.cost_limits, {}, 0);
    await recheck(ctx, { capability: COMMAND_TABLE['tasks.create'].capability });
    const created = await ctx.store.createTask({
      task,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    const wire = isPlainObject(created?.task) ? created.task : null;
    return { data: { task: wire, task_id: wire?.task_id ?? task.task_id }, revision: wire?.revision ?? null };
  },

  async 'tasks.transition'(ctx) {
    const taskId = requireText(ctx.args.task_id, 'task_id', 64);
    const toState = requireText(ctx.args.to_state, 'to_state', 16);
    const expectedRevision = requirePositiveInteger(ctx.args.expected_revision, 'expected_revision');
    const task = await readTask(ctx, taskId, { workspaceId: ctx.args.workspace_id ?? undefined });
    // The digests the caller observed are pinned to the task row: a review
    // (or any other edge) may only CONFIRM the documents, never replace them.
    const digests = observedDigests(ctx.args, task);
    if (toState === 'DONE' && digests.brief_digest === null) {
      throw new NeedsInput('DIGEST_OBSERVED_REQUIRED', 'an approval must name the digests it approved');
    }
    const narrowed = EDGE_CAPABILITY_NARROWING[toState];
    if (typeof narrowed === 'string') {
      assertActor({
        principal: ctx.principal,
        actorKind: ctx.actorKind,
        capability: narrowed,
        capabilities: ctx.principal.capabilities,
        workspaceId: task.workspace_id,
        resourceId: task.task_id,
        now: ctx.instant,
      });
    }
    const lease = await activeLeaseOf(ctx.store, task);
    const fencingToken = resolveFence(ctx, task, lease);
    const reconciliation = await resolveReconciliation(ctx, task);
    const grant = await resolveGrant(ctx.store, { workspaceId: task.workspace_id, taskId: task.task_id, now: ctx.instant });
    const spent = grant ? await resolveSpent(ctx.store, grant, ctx.instant) : undefined;
    await decide(ctx, {
      task,
      toState,
      expectedRevision,
      reason: ctx.args.reason,
      lease,
      fencingToken,
      digests,
      reconciliation,
      budgetGrant: grant ? budgetLimitsOf(grant) : undefined,
      budgetSpent: spent,
    });
    // The command capability is re-asserted with the task in hand, then the
    // store performs the compare-and-swap under its own lock.
    await recheck(ctx, { capability: COMMAND_TABLE['tasks.transition'].capability, task });
    const moved = await ctx.store.transitionTask({
      taskId: task.task_id,
      toState,
      expectedRevision,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      reason: requireText(ctx.args.reason, 'reason', 500),
      lease: lease ? lease.lease_id : undefined,
      fencingToken: fencingToken ?? undefined,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
      blockReason: toState === 'BLOCKED' ? requireText(ctx.args.reason, 'reason', 500) : undefined,
    });
    return { data: { task: moved.task ?? null, transition: moved.transition ?? null }, revision: moved.revision ?? null };
  },

  async 'tasks.claim'(ctx) {
    const taskId = requireText(ctx.args.task_id, 'task_id', 64);
    const expectedRevision = requirePositiveInteger(ctx.args.expected_revision, 'expected_revision');
    const task = await readTask(ctx, taskId, { workspaceId: ctx.args.workspace_id ?? undefined });
    // The adapter is SERVER-READ: the caller may propose one, and the
    // registration is what decides whether it may serve this task.
    const adapters = await registeredAdapters({ store: ctx.store, adapters: ctx.adapters, workspaceId: task.workspace_id });
    const adapter = resolveAdapter(adapters, ctx.args.adapter_id, task);
    crossCheckAdapterAgainstTask(adapter, task, ctx);
    const grant = await resolveGrant(ctx.store, { workspaceId: task.workspace_id, taskId: task.task_id, now: ctx.instant });
    const spent = grant ? await resolveSpent(ctx.store, grant, ctx.instant) : undefined;
    // The concurrency count is read BEFORE the claim and is the very count the
    // post-commit verification re-uses.
    const activeLeaseCount = await countActiveLeases(ctx.store, task.workspace_id);
    // Everything decidable BEFORE the fence exists is decided here: the actor,
    // the ACL, the arguments, the adapter, the workspace, the sandbox, the
    // budget, the digests and the dependency closure.
    await decide(ctx, {
      task,
      toState: 'CLAIMED',
      expectedRevision,
      reason: `lease requested for adapter ${adapter.adapter_id}`,
      lease: null,
      fencingToken: null,
      digests: observedDigests(ctx.args, task),
      adapters,
      budgetGrant: grant ? budgetLimitsOf(grant) : undefined,
      budgetSpent: spent,
      actorAdapterId: adapter.adapter_id,
      activeLeaseCount,
    }).catch((error) => {
      // guardReadyToClaimed needs the lease the claim is about to create. The
      // claim itself is the fence authority, so the pre-write checks that the
      // guard would add on top of the store's own claim invariants are run
      // explicitly instead of being skipped: any failure here is a refusal
      // BEFORE the write, and only STALE_FENCE (the not-yet-minted fence) is
      // tolerated to proceed to the atomic claim.
      if (isBoardError(error) && error.code === 'STALE_FENCE') return null;
      throw error;
    });
    await recheck(ctx, { capability: COMMAND_TABLE['tasks.claim'].capability, task });
    const ttlMs = optionalInteger(ctx.args.ttl_ms, 'ttl_ms', 86_400_000) ?? taskTimeLimit(task);
    const claim = await ctx.store.claimTask({
      taskId: task.task_id,
      workspaceId: task.workspace_id,
      adapterId: adapter.adapter_id,
      ttlMs,
      expectedRevision,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    // Post-commit verification: the full guard against the lease that actually
    // committed. A failure here is an unknown canonical state, never a success.
    await verifyClaim(ctx, { task, claim, adapters, actorAdapterId: adapter.adapter_id, activeLeaseCount });
    return {
      data: { task: claim.task ?? null, lease: claim.lease ?? null, lease_id: claim.lease_id ?? null },
      revision: claim.revision ?? null,
    };
  },

  async 'tasks.cancel'(ctx) {
    const taskId = requireText(ctx.args.task_id, 'task_id', 64);
    const reason = requireText(ctx.args.reason, 'reason', 500);
    const task = await readTask(ctx, taskId, { workspaceId: ctx.args.workspace_id ?? undefined });
    const lease = await activeLeaseOf(ctx.store, task);
    const fence = resolveFence(ctx, task, lease);
    // The S2-002 twin of a cancel is task.cancel and its canonical arguments
    // (the task, the reason) are faithfully resolvable, so the decision is
    // asked of S2-002 instead of being taken here.
    assertIdentityConsult(ctx, 'board.execution.cancel', { task_id: task.task_id, reason: ctx.args.reason }, {
      workspaceId: task.workspace_id,
      resourceId: task.task_id,
    }, { required: ['task_id'] });
    await decide(ctx, { task, toState: 'CANCELLED', expectedRevision: task.revision, reason, lease, fencingToken: fence });
    await recheck(ctx, { capability: COMMAND_TABLE['tasks.cancel'].capability, task });
    // A cancel from an executing state needs the lease withdrawn first: the
    // store refuses to leave an executing state while a right is still active.
    const released = await withdrawLease(ctx, { task, lease, fence, reason, toState: 'CANCELLED' });
    return { data: { task: released.task ?? null }, revision: released.revision ?? null };
  },

  // --- leases --------------------------------------------------------------

  async 'tasks.lease.renew'(ctx) {
    const leaseId = requireText(ctx.args.lease_id, 'lease_id', 64);
    const lease = await ctx.store.readLease(leaseId);
    requireObject(lease, 'lease');
    const task = await readTask(ctx, lease.task_id, { workspaceId: lease.workspace_id });
    const fence = resolveFence(ctx, task, lease, { required: true });
    await recheck(ctx, { capability: COMMAND_TABLE['tasks.lease.renew'].capability, task });
    const renewed = await ctx.store.renewLease({
      leaseId: lease.lease_id,
      fencingToken: fence,
      ttlMs: requirePositiveInteger(ctx.args.ttl_ms, 'ttl_ms', 86_400_000),
      actor: ctx.principalId,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return {
      data: { lease: renewed.lease ?? null, lease_id: lease.lease_id, fencing_token: fence },
      revision: task.revision,
    };
  },

  async 'tasks.lease.release'(ctx) {
    const leaseId = requireText(ctx.args.lease_id, 'lease_id', 64);
    const reason = requireText(ctx.args.reason, 'reason', 500);
    const lease = await ctx.store.readLease(leaseId);
    requireObject(lease, 'lease');
    const task = await readTask(ctx, lease.task_id, { workspaceId: lease.workspace_id });
    const fence = resolveFence(ctx, task, lease, { required: true });
    // A release is a requeue, so it requires a recorded, authorized
    // reconciliation decision (guardRelease / assertReconciled). A blind
    // release would be exactly the blind retry the contract forbids.
    const reconciliation = await resolveReconciliation(ctx, task);
    await decide(ctx, { task, toState: 'READY', expectedRevision: task.revision, reason, lease, fencingToken: fence, reconciliation });
    await recheck(ctx, { capability: COMMAND_TABLE['tasks.lease.release'].capability, task });
    const released = await ctx.store.releaseLease({
      leaseId: lease.lease_id,
      fencingToken: fence,
      reason,
      expectedRevision: task.revision,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      toState: 'READY',
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return {
      data: { task: released.task ?? null, lease: released.lease ?? null, lease_id: lease.lease_id },
      revision: released.revision ?? null,
    };
  },

  async 'tasks.lease.reassign'(ctx) {
    const leaseId = requireText(ctx.args.lease_id, 'lease_id', 64);
    const reason = requireText(ctx.args.reason, 'reason', 500);
    const lease = await ctx.store.readLease(leaseId);
    requireObject(lease, 'lease');
    const task = await readTask(ctx, lease.task_id, { workspaceId: lease.workspace_id });
    const fence = resolveFence(ctx, task, lease, { required: true });
    const adapters = await registeredAdapters({ store: ctx.store, adapters: ctx.adapters, workspaceId: task.workspace_id });
    const next = resolveAdapter(adapters, ctx.args.new_adapter_id, task);
    crossCheckAdapterAgainstTask(next, task, ctx);
    // The new holder is authorized before the old right is withdrawn, so a
    // reassignment can never leave a task with nobody authorized to run it.
    await recheck(ctx, { capability: COMMAND_TABLE['tasks.lease.reassign'].capability, task });
    const result = await ctx.store.reassignLease({
      leaseId: lease.lease_id,
      fencingToken: fence,
      newAdapterId: next.adapter_id,
      reason,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return {
      data: { task: result.task ?? null, lease: result.lease ?? null, lease_id: result.lease_id ?? next.lease_id, fencing_token: Number(next.fencing_token) },
      revision: result.revision ?? null,
    };
  },

  async 'tasks.lease.revoke'(ctx) {
    const leaseId = requireText(ctx.args.lease_id, 'lease_id', 64);
    const reason = requireText(ctx.args.reason, 'reason', 500);
    const lease = await ctx.store.readLease(leaseId);
    requireObject(lease, 'lease');
    const task = await readTask(ctx, lease.task_id, { workspaceId: lease.workspace_id });
    const fence = resolveFence(ctx, task, lease, { required: true });
    await recheck(ctx, { capability: COMMAND_TABLE['tasks.lease.revoke'].capability, task });
    const revoked = await ctx.store.revokeLease({
      leaseId: lease.lease_id,
      fencingToken: fence,
      reason,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return {
      data: { task: revoked.task ?? null, lease: revoked.lease ?? null, lease_id: lease.lease_id },
      revision: revoked.revision ?? null,
    };
  },

  // --- adapters ------------------------------------------------------------

  async 'adapters.register'(ctx) {
    const registration = requireObject(ctx.args.registration, 'registration');
    assertBoardContract('adapter-registration', registration, MalformedResult);
    // Honesty gate: a registration may CLAIM a real adapter, only the host may
    // CONFIRM one. A claim the host cannot corroborate is refused, and a
    // scripted/wrapper transport can never raise the provenance status.
    await assertRealAdapterClaimIsTrue(ctx, registration);
    await assertIdentityConsult(ctx, 'board.adapter.register', null, {
      workspaceId: registration.workspace_id,
      resourceId: registration.adapter_id,
    }, { required: ['task_id', 'to_principal'] });
    await recheck(ctx, { capability: COMMAND_TABLE['adapters.register'].capability });
    const registered = await ctx.store.registerAdapter({
      registration,
      actor: ctx.principalId,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return { data: { adapter: registered.adapter ?? null }, revision: null };
  },

  async 'adapters.health'(ctx) {
    const adapterId = requireText(ctx.args.adapter_id, 'adapter_id', 64);
    const health = requireText(ctx.args.health, 'health', 16);
    const registration = await ctx.store.getAdapter(adapterId);
    requireObject(registration, 'adapter');
    // A health value is adjudicated by the frozen registration schema, never by
    // a local enum, so a typo cannot become a third state.
    assertBoardContract('adapter-registration', { ...registration, health }, MalformedResult);
    await recheck(ctx, { capability: COMMAND_TABLE['adapters.health'].capability });
    const updated = await ctx.store.updateAdapterHealth({
      adapterId,
      health,
      actor: ctx.principalId,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return { data: { adapter: updated.adapter ?? null }, revision: null };
  },

  // --- dispatch / execution ------------------------------------------------

  async 'dispatch.tick'(ctx) {
    const workspaceId = requireText(ctx.args.workspace_id, 'workspace_id', 64);
    await recheck(ctx, { capability: COMMAND_TABLE['dispatch.tick'].capability });
    // The scheduler owns the decision; the boundary only authorizes it and
    // hands it the server-resolved actor and the injected instant.
    const tick = await runSchedulerTick({
      store: ctx.store,
      workspaceId,
      actor: schedulerActorFor(ctx),
      adapter: ctx.transport ?? null,
      now: ctx.instant,
      ids: ctx.ids,
      sandbox: ctx.sandbox ?? null,
      idempotencyKey: ctx.idempotencyKey,
      workspaceRoots: resolveWorkspaceRoots(workspaceId, ctx.workspaceRoots),
      unisolatedExecutionAuthorization: ctx.unisolatedExecutionAuthorization ?? null,
    });
    const selected = tick.decision?.selected_task_id ?? null;
    const moved = typeof selected === 'string' ? await readTask(ctx, selected, { workspaceId }) : null;
    return {
      data: { decision: tick.decision, run: tick.run, request: tick.request },
      revision: moved === null ? null : moved.revision,
    };
  },

  async 'execution.start'(ctx) {
    const taskId = requireText(ctx.args.task_id, 'task_id', 64);
    const task = await readTask(ctx, taskId, { workspaceId: ctx.args.workspace_id ?? undefined });
    const workspaceId = task.workspace_id;
    // Gates that hold in both paths: the isolation profile must be proven, the
    // adapter must be registered, healthy and actually cover the task, and the
    // budget must be assigned. An unassigned budget is not zero.
    const profileId = task.workspace_ref?.isolation_profile_id ?? null;
    // A live execution passes ONE gate. An isolated tier with measured OS
    // controls needs nothing beyond the proven-set check; the HOST_UNISOLATED
    // floor is admitted only with a valid named human authorisation resolved
    // server-side, and the resolved decision is returned so the run record can
    // quote it verbatim. Everything else is refused exactly as before.
    const sandboxDecision = assertLiveExecutionAuthorized(profileId, {
      authorization: ctx.unisolatedExecutionAuthorization,
      now: ctx.instant,
    });
    const adapters = await registeredAdapters({ store: ctx.store, adapters: ctx.adapters, workspaceId });
    const grant = await resolveGrant(ctx.store, { workspaceId, taskId, now: ctx.instant });
    if (!isPlainObject(grant)) {
      throw new BudgetExceeded('BUDGET_NOT_ASSIGNED', `no approved positive numeric budget grant covers task ${taskId}`);
    }
    const spent = await resolveSpent(ctx.store, grant, ctx.instant);
    assertWithinBudget(budgetLimitsOf(grant), spent, 0);
    assertWorkspaceWithin(task.workspace_ref, resolveWorkspaceRoots(workspaceId, ctx.workspaceRoots), { realpath: ctx.realpath });

    if (task.state === 'READY' && task.active_lease_id === null) {
      // The scheduler's own dispatch: it claims (minting the fence), builds the
      // request, records the run and the outbox row, and moves the task to
      // RUNNING. The caller never names the lease, the scope or the budget. The
      // plan is restricted to the task the caller NAMED, so a start request can
      // never dispatch a different task than the one that was asked for — the
      // decision, its exclusions and its reason still come from planDispatch.
      const decision = await planFor(ctx, { workspaceId, tasks: [task] });
      await recheck(ctx, { capability: COMMAND_TABLE['execution.start'].capability, task });
      const tick = await runSchedulerTick({
        store: ctx.store,
        workspaceId,
        actor: schedulerActorFor(ctx),
        adapter: ctx.transport ?? null,
        now: ctx.instant,
        ids: ctx.ids,
        sandbox: ctx.sandbox ?? null,
        dispatch: decision,
        idempotencyKey: ctx.idempotencyKey,
        workspaceRoots: resolveWorkspaceRoots(workspaceId, ctx.workspaceRoots),
      });
      return { data: { decision: tick.decision, run: tick.run, request: tick.request }, revision: (await readTask(ctx, task.task_id, { workspaceId })).revision };
    }

    // Already claimed: the lease and the fence already exist and are current.
    const lease = await activeLeaseOf(ctx.store, task);
    if (!isPlainObject(lease)) {
      throw new StaleFence('LEASE_REQUIRED', `task ${taskId} holds no active lease; claim it before starting a run`);
    }
    const fence = resolveFence(ctx, task, lease, { required: true });
    const adapter = resolveAdapter(adapters, ctx.args.adapter_id ?? task.assigned_adapter_id, task);
    crossCheckAdapterAgainstTask(adapter, task, ctx);
    if (adapter.sandbox_profile_id !== profileId) {
      throw new BlockedSandbox('ADAPTER_SANDBOX_MISMATCH', 'the adapter is not bound to the task isolation profile');
    }
    // The handoff scope is DERIVED from the authenticated grant, never taken
    // from the request: an unresolvable scope is an empty scope, not "all".
    // The run itself is granted the least-privilege default unless the
    // operator's principal carries an explicit server-resolved scope, and the
    // result is proven to be a subset of what the grant allows — a request may
    // narrow this default and can never widen it.
    const scope = resolveRunScope(ctx);
    const request = buildServerExecutionRequest({
      ctx,
      task,
      lease,
      fence,
      adapter,
      grant,
      scope,
    });
    await recheck(ctx, { capability: COMMAND_TABLE['execution.start'].capability, task });
    const created = await ctx.store.createRun({
      request,
      actor: ctx.principalId,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    // The sandbox decision travels with the run so the journal, the run record
    // and any later verifier read the SAME authorisation that let the run
    // start. A run that was authorised on the host-unisolated floor therefore
    // carries the permit by value, and a reviewer can re-judge it.
    return {
      data: {
        run: created.run ?? null,
        request,
        sandboxDecision: {
          tier: sandboxDecision.tier,
          profile_id: sandboxDecision.profile_id,
          authorization: sandboxDecision.authorization,
        },
      },
      revision: task.revision,
    };
  },

  async 'execution.event'(ctx) {
    const runId = requireText(ctx.args.run_id, 'run_id', 64);
    // 0. executor output is redacted BEFORE anything is validated or stored, so
    //    a credential can never reach the journal even for a callback that is
    //    about to be refused.
    const event = redactExecutorOutput(requireObject(ctx.args.event, 'event'));
    // 1. the wire shape, so a malformed callback is MALFORMED_RESULT and never
    //    a semantic refusal of something the contract does not allow.
    assertBoardContract('execution-event', event, MalformedResult);
    assertExecutionVersion(event);
    // 2. the run is server-read and ACL-filtered; the callback must name it.
    const { run, task } = await readRunFor(ctx, runId);
    assertCallbackBinding(run, event, 'event');
    // 3. the checkpoint/substitution digests, when the payload carries any.
    assertCallbackDigests(run, event);
    await recheck(ctx, { capability: COMMAND_TABLE['execution.event'].capability, task });
    const recorded = await ctx.store.appendExecutionEvent({
      event,
      actor: ctx.principalId,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return { data: { event: recorded.event ?? null, run: recorded.run ?? null }, revision: null };
  },

  async 'execution.collect_result'(ctx) {
    const runId = requireText(ctx.args.run_id, 'run_id', 64);
    const result = redactExecutorOutput(requireObject(ctx.args.result, 'result'));
    assertBoardContract('execution-result', result, MalformedResult);
    assertExecutionVersion(result);
    const { run } = await readRunFor(ctx, runId);
    assertCallbackBinding(run, result, 'result');
    assertCallbackDigests(run, result);
    const task = await readTask(ctx, run.task_id, { workspaceId: run.workspace_id });
    const lease = await activeLeaseOf(ctx.store, task);
    // The fence the result claims must be the run's own current fence.
    if (Number(result.fencing_token) !== Number(run.fencing_token)) {
      throw new StaleFence('FENCE_NOT_CURRENT', `run ${runId} is bound to fence ${run.fencing_token}`);
    }
    await recheck(ctx, { capability: COMMAND_TABLE['execution.collect_result'].capability, task });
    const collected = await ctx.store.collectResult({
      result,
      actor: ctx.principalId,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    if (collected?.replayed === true) {
      // A replay returns the prior committed result and touches nothing, so
      // the teardown below must not run a second time.
      return { data: { run: collected.run ?? null, task: null }, revision: task.revision, replayed: true };
    }
    const closed = await closeRunAfterCollection(ctx, { task, run, result, lease, collected });
    return { data: { run: collected.run ?? null, task: closed.task ?? null }, revision: closed.revision ?? null };
  },

  async 'execution.cancel'(ctx) {
    const runId = requireText(ctx.args.run_id, 'run_id', 64);
    const reason = requireText(ctx.args.reason, 'reason', 500);
    const { run, task } = await readRunFor(ctx, runId);
    const lease = await activeLeaseOf(ctx.store, task);
    const fence = resolveFence(ctx, task, lease);
    // The S2-002 twin of a cancel is task.cancel, whose canonical arguments
    // (the task and the reason) ARE faithfully resolvable here, so the consult
    // runs: an operator without a cancel grant in S2-002 is refused, and this
    // boundary never decides that question itself.
    assertIdentityConsult(ctx, 'board.execution.cancel', { task_id: task.task_id, reason }, {
      workspaceId: task.workspace_id,
      resourceId: task.task_id,
    }, { required: ['task_id'] });
    // Cancelling a run moves the task through the SAME edge a cancel command
    // uses, so the same guard runs here: the transition table and its guards are
    // the only way any state changes.
    await decide(ctx, { task, toState: 'CANCELLED', expectedRevision: task.revision, reason, lease, fencingToken: fence });
    await recheck(ctx, { capability: COMMAND_TABLE['execution.cancel'].capability, task });
    // A cancel is an external effect: the transport is told first, and an
    // unknown outcome is a reconciliation, never a local state change.
    if (isPlainObject(ctx.transport) && typeof ctx.transport.cancel === 'function') {
      try {
        await ctx.transport.cancel({
          run_id: run.run_id,
          task_id: task.task_id,
          lease_id: lease?.lease_id ?? run.lease_id,
          fencing_token: Number(run.fencing_token),
          reason,
          at: ctx.instant,
        });
      } catch (error) {
        throw toBoardError(error, 'UNKNOWN_OUTCOME');
      }
    }
    const closed = await withdrawLease(ctx, { task, lease, fence, reason, toState: 'CANCELLED' });
    return { data: { task: closed.task ?? null }, revision: closed.revision ?? null };
  },

  // --- budget / outbox / audit / reconciliation ----------------------------

  async 'budget.grant'(ctx) {
    const grant = requireObject(ctx.args.grant, 'grant');
    // A grant is insert-only and attributed to the server-resolved approver. A
    // payload that names somebody else is AUTH_REQUIRED, never a re-attribution.
    if (grant.granted_by !== undefined && grant.granted_by !== null && grant.granted_by !== ctx.principalId) {
      throw new AuthRequired('AUTH_REQUIRED', 'granted_by must be the server-resolved approver');
    }
    const document = { ...grant, granted_by: ctx.principalId };
    assertBudgetAssignable(document);
    // The S2-002 twin of a budget grant is task.reassign, whose required
    // canonical arguments (a task and a new owner) are not what this operation
    // is about, so no request is invented and the board's own checks decide.
    assertIdentityConsult(ctx, 'board.budget.grant', null, {
      workspaceId: document.workspace_id,
      resourceId: document.grant_id,
    }, { required: ['task_id', 'to_principal'] });
    await recheck(ctx, { capability: COMMAND_TABLE['budget.grant'].capability });
    const granted = await ctx.store.grantBudget({
      grant: document,
      actor: ctx.principalId,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return { data: { grant: granted.grant ?? null, grant_id: document.grant_id }, revision: null };
  },

  async 'budget.settle'(ctx) {
    const grantId = requireText(ctx.args.grant_id, 'grant_id', 64);
    const taskId = requireText(ctx.args.task_id, 'task_id', 64);
    const amount = ctx.args.amount;
    if (typeof amount !== 'number' || !Number.isFinite(amount) || amount < 0) {
      throw new NeedsInput('ARGUMENT_INVALID:amount', 'a settled amount is a non-negative number');
    }
    const grant = await ctx.store.readBudgetGrant(grantId);
    requireObject(grant, 'grant');
    const task = await readTask(ctx, taskId, { workspaceId: grant.workspace_id });
    // The grant is re-read here, so a grant revoked between the authorize step
    // and this settle is refused by the store, not by a cached opinion.
    assertBudgetAssignable(budgetLimitsOf(grant));
    await recheck(ctx, { capability: COMMAND_TABLE['budget.settle'].capability, task });
    const settled = await ctx.store.settleBudget({
      grantId,
      operationId: requireText(ctx.args.operation_id, 'operation_id', 64),
      taskId,
      amount,
      currency: ctx.args.currency ?? null,
      dayKey: ctx.args.day_key ?? null,
      actor: ctx.principalId,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return { data: { spend: settled.spend ?? null, grant_id: grantId }, revision: task.revision };
  },

  async 'outbox.dispatch'(ctx) {
    const workspaceId = requireText(ctx.args.workspace_id, 'workspace_id', 64);
    if (ctx.transport === undefined || ctx.transport === null) {
      throw new NeedsInput('OUTBOX_TRANSPORT_MISSING', 'a dispatch needs a server-injected transport');
    }
    // The caller's key is checked against the ledger: the same key with a
    // different payload is an IDEMPOTENCY_CONFLICT, never a second dispatch.
    const prior = await readOperationSafely(ctx.store, ctx.idempotencyKey);
    if (prior !== null) {
      if (prior.args_digest !== ctx.argsDigest) {
        throw new IdempotencyConflict(
          'IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_ARGUMENTS',
          'this key was already committed for a different canonical argument digest',
        );
      }
      return { data: prior.result_payload ?? null, revision: null, replayed: true };
    }
    await recheck(ctx, { capability: COMMAND_TABLE['outbox.dispatch'].capability });
    // driveOutbox is the single dispatcher: it records the send intent BEFORE
    // crossing the boundary, so a crash after the intent escalates to
    // RECONCILIATION_REQUIRED instead of re-issuing the effect.
    const summary = await driveOutbox({
      store: ctx.store,
      transport: ctx.transport,
      actor: ctx.principalId,
      now: ctx.instant,
      limit: boundedLimit(ctx.args.limit),
      workspaceId,
    });
    return { data: { summary }, revision: null };
  },

  async 'outbox.recover'(ctx) {
    const workspaceId = requireText(ctx.args.workspace_id, 'workspace_id', 64);
    await recheck(ctx, { capability: COMMAND_TABLE['outbox.recover'].capability });
    // recoverOutbox has no transport parameter at all: it reconstructs the
    // canonical state and never reissues a side effect.
    const summary = await recoverOutbox({
      store: ctx.store,
      actor: ctx.principalId,
      now: ctx.instant,
      limit: boundedLimit(ctx.args.limit),
      workspaceId,
      ids: ctx.ids,
    });
    return { data: { summary }, revision: null };
  },

  async 'reconciliation.record'(ctx) {
    const reconciliation = requireObject(ctx.args.reconciliation, 'reconciliation');
    // Only an authenticated human or an authorized deterministic gate may close
    // an unknown outcome. A producer and an uncalibrated semantic verifier are
    // refused here, before the store is touched.
    assertHumanOnlyApproval(ctx.actorKind);
    const decidedBy = reconciliation.decided_by ?? null;
    if (decidedBy !== null && decidedBy !== ctx.principalId) {
      throw new AuthRequired('AUTH_REQUIRED', 'decided_by must be the server-resolved decider');
    }
    const document = { ...reconciliation, decided_by: ctx.principalId };
    if (typeof document.resolution !== 'string' || document.resolution.length === 0) {
      throw new NeedsInput('RECONCILIATION_RESOLUTION_REQUIRED');
    }
    // A producer may not decide its own unknown effect.
    if (typeof document.run_id === 'string') {
      const { run } = await readRunFor(ctx, document.run_id);
      const producer = run.request?.principal_id ?? null;
      if (typeof producer === 'string' && producer === ctx.principalId) {
        assertNotSelfApproved({ actorKind: ctx.actorKind, producerPrincipalId: producer, gatePrincipalId: ctx.principalId });
      }
    }
    await recheck(ctx, { capability: COMMAND_TABLE['reconciliation.record'].capability });
    const recorded = await ctx.store.recordReconciliation({
      reconciliation: document,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return { data: { reconciliation: recorded.reconciliation ?? null }, revision: null };
  },
});

// --- shared handler helpers --------------------------------------------------

function taskTimeLimit(task) {
  const timeout = Number(task?.time_limits?.timeout_ms);
  return Number.isFinite(timeout) && timeout > 0 ? Math.trunc(timeout) : 60_000;
}

/**
 * Executor output is DATA, and data that leaves the process must never carry a
 * secret. Every callback document is passed through `redact()` (errors.mjs)
 * before the store sees it, so a log line, an artifact note or an error detail
 * cannot deposit a credential in the journal, the outbox, the audit trail or a
 * later API response. Redaction is defence in depth — the real rule stays "do
 * not hand a secret to the boundary" — and it is applied to executor-authored
 * text only: human-authored task text is stored verbatim, because silently
 * editing an operator's brief is its own kind of corruption.
 */
function redactExecutorOutput(value, depth = 0) {
  if (typeof value === 'string') return redact(value);
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= MAX_REDACT_DEPTH) return null;
  if (Array.isArray(value)) return value.map((item) => redactExecutorOutput(item, depth + 1));
  if (isPlainObject(value)) {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) continue;
      out[key] = NON_REDACTABLE_FIELDS.has(key) && (typeof item === 'string' || typeof item === 'number')
        ? item
        : redactExecutorOutput(item, depth + 1);
    }
    return out;
  }
  // A function, a symbol or a bigint has no place in an execution document.
  return null;
}

function budgetLimitsOf(grant) {
  return {
    task_limit: Number(grant.task_limit),
    campaign_limit: Number(grant.campaign_limit),
    day_limit: Number(grant.day_limit),
  };
}

/** The digests the caller OBSERVED. A presented digest is pinned to the task row. */
function observedDigests(args, task) {
  const brief = typeof args.brief_digest === 'string' ? args.brief_digest : null;
  const policyDigest = typeof args.policy_digest === 'string' ? args.policy_digest : null;
  const manifest = typeof args.manifest_digest === 'string' ? args.manifest_digest : null;
  if (brief !== null && brief !== task.brief_digest) {
    throw new MalformedResult('DIGEST_MISMATCH', 'the observed brief digest is not the one the task was created with');
  }
  if (policyDigest !== null && policyDigest !== task.policy_digest) {
    throw new MalformedResult('DIGEST_MISMATCH', 'the observed policy digest is not the one the task was created with');
  }
  if (manifest !== null && manifest !== task.manifest_digest) {
    throw new MalformedResult('DIGEST_MISMATCH', 'the observed manifest digest is not the one the task was created with');
  }
  return {
    brief_digest: brief,
    policy_digest: policyDigest,
    manifest_digest: manifest,
  };
}

/**
 * The fence. It is always resolved from the SERVER state (the task row and its
 * active lease). A presented `fencing_token` may only confirm it: a
 * disagreement is a stale fence, and a fence for a task that holds no active
 * lease can never be current.
 */
function resolveFence(ctx, task, lease, { required = false } = {}) {
  const current = typeof task.fencing_token === 'number' ? task.fencing_token : null;
  const presented = typeof ctx.args.fencing_token === 'number' ? ctx.args.fencing_token : null;
  if (presented !== null) {
    if (current === null || presented !== current) {
      throw new StaleFence('FENCE_NOT_CURRENT', `task ${task.task_id} is at fence ${String(current)}`);
    }
  }
  if (required && (current === null || !isPlainObject(lease))) {
    throw new StaleFence('LEASE_REQUIRED', 'this operation requires the current active lease');
  }
  return current;
}

/**
 * The recorded, authorized reconciliation a release or requeue must present.
 *
 * The store exposes exactly one read for decisions — `listReconciliations({
 * runId })`, which REQUIRES a run id — so a decision is discoverable through
 * the task's own runs. A `reconciliation_id` in the arguments is a cross-check
 * only: when it names a row that cannot be read back here, the decision is
 * treated as absent and the guard answers RECONCILIATION_REQUIRED. Nothing is
 * guessed, and a decision is never taken from a payload.
 */
async function resolveReconciliation(ctx, task) {
  const runs = await ctx.store.listRuns({
    workspaceId: task.workspace_id,
    taskId: task.task_id,
    principalId: ctx.principalId,
  });
  const decisions = [];
  for (const run of (Array.isArray(runs) ? runs : [])) {
    const rows = await ctx.store.listReconciliations({
      runId: run.run_id,
      principalId: ctx.principalId,
      workspaceId: task.workspace_id,
    });
    for (const row of (Array.isArray(rows) ? rows : [])) decisions.push(row);
  }
  const wanted = typeof ctx.args.reconciliation_id === 'string' ? ctx.args.reconciliation_id : null;
  const selected = wanted === null
    ? (decisions.length === 0 ? null : decisions[decisions.length - 1])
    : decisions.find((row) => row.reconciliation_id === wanted) ?? null;
  return selected;
}

function resolveAdapter(adapters, adapterId, task) {
  const wanted = adapterId ?? task.assigned_adapter_id;
  if (typeof wanted !== 'string' || wanted.length === 0) {
    throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', 'no adapter is named for this task');
  }
  const adapter = (Array.isArray(adapters) ? adapters : []).find((entry) => isPlainObject(entry) && entry.adapter_id === wanted);
  if (!isPlainObject(adapter)) {
    throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', `adapter ${wanted} is not registered in this workspace`);
  }
  if (adapter.workspace_id !== task.workspace_id) {
    throw new AclDenied('cross_workspace_adapter_denied', 'an adapter of another workspace may not serve this task');
  }
  if (adapter.health !== 'healthy' || adapter.adapter_kind === 'unavailable') {
    throw new AgentUnavailable('ADAPTER_NOT_HEALTHY', `adapter ${wanted} is ${String(adapter.health)}`);
  }
  return adapter;
}

function crossCheckAdapterAgainstTask(adapter, task, ctx = null) {
  // The task's requirements are the floor; an adapter that declares less may
  // not serve it, and a self-declared capability is a claim, never a grant.
  crossCheckCapabilities({
    registration: adapter,
    claimed: { capabilities: adapter.declared_capabilities, tools: adapter.declared_tools },
    grant: { capabilities: adapter.declared_capabilities, tools: adapter.declared_tools },
  });
  assertCapabilitySubset(task.required_capabilities, adapter.declared_capabilities);
  assertToolSubset(task.allowed_tools, adapter.declared_tools);
  // The live-execution gate, not the bare proven-set check (issue #45). An
  // isolated tier needs nothing beyond the proven set; the HOST_UNISOLATED
  // floor needs the named human authorisation the boundary resolved
  // server-side, which is why the context is threaded in here rather than
  // being invented at each call site. Every other profile is refused exactly
  // as before — this is not a relaxation of the proven set, it is the same
  // proven set plus one loudly-named floor that needs a permit.
  assertLiveExecutionAuthorized(adapter.sandbox_profile_id, {
    authorization: ctx?.unisolatedExecutionAuthorization ?? null,
    now: ctx?.instant ?? null,
  });
  return true;
}

/** A callback must name exactly the run the board recorded for it. */
function assertCallbackBinding(run, document, label) {
  if (document.run_id !== run.run_id) {
    throw new MalformedResult('CALLBACK_RUN_MISMATCH', `${label} does not belong to run ${run.run_id}`);
  }
  if (document.task_id !== run.task_id) {
    throw new MalformedResult('CALLBACK_TASK_MISMATCH', `${label} does not belong to task ${run.task_id}`);
  }
  if (document.workspace_id !== run.workspace_id) {
    // Workspace isolation is absolute and precedes every payload read: a
    // callback for another workspace returns no field of this one.
    throw new AclDenied('cross_workspace_callback_denied', `the ${label} names workspace ${String(document.workspace_id)}`);
  }
  if (document.lease_id !== run.lease_id) {
    throw new StaleFence('LEASE_NOT_CURRENT', `run ${run.run_id} is bound to lease ${run.lease_id}`);
  }
  return true;
}

/** A checkpoint may only report the documents the run was started under. */
function assertCallbackDigests(run, document) {
  const checkpoints = Array.isArray(document.checkpoints) ? document.checkpoints : [];
  for (const checkpoint of checkpoints) {
    if (!isPlainObject(checkpoint)) continue;
    if (typeof checkpoint.brief_digest === 'string') {
      assertDigestAgreement(run.request?.brief_digest, checkpoint.brief_digest, 'checkpoint.brief_digest');
    }
  }
  return true;
}

/**
 * The run the callback names, plus the ACL-filtered task behind it. Both reads
 * are server reads with the principal id attached, so nothing a principal may
 * not see ever reaches this module.
 */
async function readRunFor(ctx, runId) {
  const run = await ctx.store.readRun(runId, { principalId: ctx.principalId, workspaceId: ctx.args.workspace_id ?? undefined });
  if (!isPlainObject(run)) throw new NeedsInput(`RUN_NOT_FOUND:${String(runId)}`);
  const task = await readTask(ctx, run.task_id, { workspaceId: run.workspace_id });
  return { run, task };
}

async function readOperationSafely(store, key) {
  try {
    const row = await store.readOperation(key);
    return isPlainObject(row) ? row : null;
  } catch (error) {
    if (isBoardError(error) && error.code === 'NEEDS_INPUT') return null;
    throw error;
  }
}

/**
 * Withdraw the lease and move the task, in one store transaction when the
 * store can do it (releaseLease), or as revoke + transition when the state
 * change has to happen on its own. Either way the lease is withdrawn BEFORE
 * the state changes: a right that is still active may not be left behind a new
 * state.
 */
async function withdrawLease(ctx, { task, lease, fence, reason, toState }) {
  if (!isPlainObject(lease)) {
    // Nothing active: the transition stands on its own.
    await recheck(ctx, { task });
    const moved = await ctx.store.transitionTask({
      taskId: task.task_id,
      toState,
      expectedRevision: task.revision,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      reason,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return { task: moved.task ?? null, revision: moved.revision ?? null };
  }
  if (toState === task.state) {
    // Only the lease changes (a cancel/revoke that keeps the state).
    await recheck(ctx, { task });
    const revoked = await ctx.store.revokeLease({
      leaseId: lease.lease_id,
      fencingToken: fence,
      reason,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      idempotencyKey: ctx.idempotencyKey,
      argsDigest: ctx.argsDigest,
    });
    return { task: revoked.task ?? null, revision: revoked.revision ?? null };
  }
  await recheck(ctx, { task });
  const released = await ctx.store.releaseLease({
    leaseId: lease.lease_id,
    fencingToken: fence,
    reason,
    expectedRevision: task.revision,
    actor: ctx.principalId,
    actorKind: ctx.actorKind,
    toState,
    idempotencyKey: ctx.idempotencyKey,
    argsDigest: ctx.argsDigest,
  });
  return { task: released.task ?? null, revision: released.revision ?? null };
}

/**
 * Post-collection teardown. The result is a fact about the run, never an
 * approval: SUCCEEDED moves the task to IN_REVIEW (evidence, not correctness),
 * a known failure to FAILED, and everything else to BLOCKED. Nothing here
 * requeues a task — a requeue needs an authorized reconciliation decision,
 * which is a different command with a different actor.
 */
async function closeRunAfterCollection(ctx, { task, run, result, lease, collected }) {
  const target = result.outcome === 'SUCCEEDED' ? 'IN_REVIEW' : (result.outcome === 'FAILED' ? 'FAILED' : 'BLOCKED');
  const reason = `run ${run.run_id} collected as ${result.outcome}`
    + (result.error ? ` (${result.error.code})` : '');
  const current = isPlainObject(collected?.task) ? collected.task : task;
  const active = isPlainObject(lease) && lease.lease_state === 'ACTIVE' ? lease : await activeLeaseOf(ctx.store, current);
  const teardownKey = stageKey({
    command: 'execution.collect_result',
    stage: `to_${result.outcome}`,
    actor: ctx.principalId,
    args: { run_id: run.run_id, to_state: target, result_digest: canonicalDigest(result) },
  });

  if (target === 'IN_REVIEW' && isPlainObject(active)) {
    // The RUNNING -> IN_REVIEW edge needs the live, current lease as evidence,
    // and the store performs it in the same transaction that releases it.
    const leaseId = active.lease_id;
    const stageDigest = stageKey({
      command: 'execution.collect_result',
      stage: 'release',
      actor: ctx.principalId,
      args: { run_id: run.run_id, lease_id: leaseId, fencing_token: Number(active.fencing_token), to_state: 'IN_REVIEW', result_digest: canonicalDigest(result) },
    });
    const context = await guardContextFor(ctx, {
      task: current,
      toState: 'IN_REVIEW',
      expectedRevision: current.revision,
      reason,
      lease: active,
      fencingToken: Number(active.fencing_token),
    });
    decideTransition({ task: current, toState: 'IN_REVIEW', context });
    await recheck(ctx, { task: current });
    const released = await ctx.store.releaseLease({
      leaseId,
      fencingToken: Number(active.fencing_token),
      reason,
      expectedRevision: current.revision,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      toState: 'IN_REVIEW',
      idempotencyKey: stageDigest,
      argsDigest: stageDigest,
    });
    return { task: released.task ?? null, revision: released.revision ?? null };
  }

  // FAILED and BLOCKED are transitions like any other and go through the SAME
  // guard + re-check path as IN_REVIEW. Writing them straight to the store let a
  // principal holding only board.result.collect move a task RUNNING->FAILED,
  // because this branch asserted neither the edge capability nor the canonical
  // arguments (adversarial review S2). Collection never implies a state
  // decision: the guard, not the collector, decides whether the task may move.
  //
  // ORDER MATTERS and mirrors the IN_REVIEW branch: the guard runs FIRST, while
  // the current lease is still the evidence that the collector is the executor
  // entitled to end the run, and only then is the lease revoked. Revoking first
  // and deciding afterwards would always read as a stale fence, which is the
  // defect the unguarded write was silently hiding. The revocation and the
  // state change then commit together in the store's own transaction, so there
  // is no window in which the task is FAILED while the right to act survives.
  const fence = isPlainObject(active) ? Number(active.fencing_token) : null;
  await decide(ctx, {
    task: current,
    toState: target,
    expectedRevision: current.revision,
    reason,
    lease: isPlainObject(active) ? active : undefined,
    fencingToken: fence ?? undefined,
  });
  if (isPlainObject(active)) {
    const released = await ctx.store.releaseLease({
      leaseId: active.lease_id,
      fencingToken: fence,
      reason,
      expectedRevision: current.revision,
      actor: ctx.principalId,
      actorKind: ctx.actorKind,
      toState: target,
      idempotencyKey: teardownKey,
      argsDigest: teardownKey,
    });
    return { task: released.task ?? null, revision: released.revision ?? null };
  }
  const moved = await ctx.store.transitionTask({
    taskId: current.task_id,
    toState: target,
    expectedRevision: current.revision,
    actor: ctx.principalId,
    actorKind: ctx.actorKind,
    reason,
    idempotencyKey: teardownKey,
    argsDigest: teardownKey,
    blockReason: target === 'BLOCKED' ? reason : undefined,
  });
  return { task: moved.task ?? null, revision: moved.revision ?? null };
}

/** Post-commit verification of a claim against the lease that actually exists. */
async function verifyClaim(ctx, { task, claim, adapters, actorAdapterId, activeLeaseCount }) {
  const lease = isPlainObject(claim.lease) ? claim.lease : await ctx.store.readLease(claim.lease_id);
  try {
    const context = await guardContextFor(ctx, {
      task,
      toState: 'CLAIMED',
      expectedRevision: task.revision,
      reason: `lease ${lease.lease_id} granted to ${actorAdapterId}`,
      lease,
      fencingToken: Number(lease.fencing_token),
      adapters,
      actorAdapterId,
      activeLeaseCount,
    });
    decideTransition({ task, toState: 'CLAIMED', context });
  } catch (error) {
    // The claim is committed. A guard that refuses it afterwards means the
    // canonical state is not what policy authorizes: that is an unknown
    // outcome for a human, never a success and never a silent rollback.
    throw new ReconciliationRequired(
      'CLAIMED_WITHOUT_AUTHORIZATION',
      `lease ${lease.lease_id} committed but the guard refused it afterwards: ${toBoardError(error, 'BLOCKED_POLICY').code}`,
    );
  }
  return true;
}

/**
 * A contract-valid DispatchDecision for a snapshot. The scheduler's own
 * `planDispatch` is the only decision maker: it applies the frozen exclusion
 * reasons, the deterministic order, the capability/workspace/budget/sandbox
 * gates and MAX_CONCURRENT_TASKS. This function only assembles the snapshot
 * (tasks, adapters, grants, spend, active leases) from server reads.
 */
async function planFor(ctx, { workspaceId, tasks }) {
  const adapters = await registeredAdapters({ store: ctx.store, adapters: ctx.adapters, workspaceId });
  const budgets = await ctx.store.listBudgetGrants({ workspaceId });
  const leases = await ctx.store.listLeases({ workspaceId });
  const dayKey = ctx.instant.slice(0, 10);
  const spent = [];
  for (const grant of (Array.isArray(budgets) ? budgets : [])) {
    const row = await ctx.store.readBudgetSpend(grant.grant_id, dayKey);
    if (isPlainObject(row)) spent.push(row);
  }
  // planDispatch is SYNCHRONOUS, so the dependency closure is resolved here (a
  // server read per dependency) and handed over as a map. A dependency that
  // cannot be read is an open dependency, never an assumed closed one.
  const closure = new Map();
  for (const task of tasks) {
    const dependencies = Array.isArray(task.dependencies) ? task.dependencies : [];
    let satisfied = true;
    for (const dependency of dependencies) {
      if (typeof dependency !== 'string') { satisfied = false; break; }
      try {
        const row = await ctx.store.getTask(dependency, { workspaceId, principalId: ctx.principalId });
        if (!isPlainObject(row) || row.state !== 'DONE') { satisfied = false; break; }
      } catch {
        satisfied = false;
        break;
      }
    }
    closure.set(task.task_id, satisfied);
  }
  return planDispatch({
    workspaceId,
    tasks,
    adapters,
    budgets,
    spent,
    activeLeases: leases,
    sandbox: ctx.sandbox ?? null,
    now: ctx.instant,
    ids: ctx.ids,
    principalId: ctx.principalId,
    dependenciesSatisfiedFor: (task) => closure.get(task.task_id) === true,
    briefValidatedFor: (task) => briefIsValidated(task),
  });
}

/**
 * The execution scope of a run. Two server-side facts, never a payload:
 *  * `granted` — what the authenticated principal's board capabilities allow
 *    (scheduler.deriveExecutionScope; an unresolvable grant is AuthRequired,
 *    never "everything");
 *  * `requested` — the least-privilege default, or the operator's explicit
 *    server-resolved `granted_scope` on the principal.
 * The result is `requested`, proven to be a subset of `granted`, so a run can
 * only ever hold LESS than its actor is authorized to give it.
 */
function resolveRunScope(ctx) {
  const granted = deriveExecutionScope(ctx.principal);
  const explicit = Array.isArray(ctx.principal.granted_scope) ? ctx.principal.granted_scope : null;
  const requested = explicit === null ? [...DEFAULT_RUN_SCOPE] : [...new Set(explicit)];
  assertScopeSubset(requested, granted);
  return requested;
}

/**
 * The actor record handed to the scheduler. It is the server-resolved principal
 * plus the RESOLVED run scope, so the scheduler's own `deriveExecutionScope`
 * returns exactly the scope this boundary decided — the tick path and the
 * claimed-task path can therefore never hand an executor different powers.
 */
function schedulerActorFor(ctx) {
  return {
    principal_id: ctx.principalId,
    capabilities: ctx.principal.capabilities ?? [],
    granted_scope: resolveRunScope(ctx),
  };
}

/** The server-built ExecutionRequest. Nothing in `args` contributes to it. */
function buildServerExecutionRequest({ ctx, task, lease, fence, adapter, grant, scope }) {
  const timeoutMs = Number.isFinite(Number(grant.timeout_ms)) && Number(grant.timeout_ms) > 0
    ? Math.trunc(Number(grant.timeout_ms))
    : taskTimeLimit(task);
  const request = {
    contract_version: EXECUTION_CONTRACT_VERSION,
    request_id: deterministicId('request', {
      task_id: task.task_id,
      revision: task.revision,
      lease_id: lease.lease_id,
      fencing_token: fence,
      adapter_id: adapter.adapter_id,
      principal_id: ctx.principalId,
    }),
    idempotency_key: ctx.idempotencyKey,
    task_id: task.task_id,
    workspace_id: task.workspace_id,
    brief_digest: task.brief_digest,
    policy_digest: task.policy_digest,
    manifest_digest: task.manifest_digest,
    principal_id: ctx.principalId,
    granted_scope: [...scope],
    allowed_tools: [...task.allowed_tools],
    workspace_ref: task.workspace_ref,
    budget_grant: {
      currency: grant.currency,
      task_limit: Number(grant.task_limit),
      campaign_limit: Number(grant.campaign_limit),
      day_limit: Number(grant.day_limit),
      timeout_ms: timeoutMs,
      granted_by: grant.granted_by,
      granted_at: toInjectedInstant(grant.granted_at, 'granted_at'),
    },
    deadline: task.time_limits?.deadline ?? null,
    lease_id: lease.lease_id,
    fencing_token: fence,
    adapter_id: adapter.adapter_id,
    issued_at: ctx.instant,
  };
  assertExecutionVersion(request);
  assertBoardContract('execution-request', request, MalformedResult);
  // The handoff may not describe different documents than the task's.
  assertDigestsMatch(task, {
    briefDigest: request.brief_digest,
    policyDigest: request.policy_digest,
    manifestDigest: request.manifest_digest,
  });
  return request;
}

/**
 * The S2-002 consult. The request is built ONLY from values the server
 * resolved and from the document the caller really asked to create. When the
 * mapped S2-002 action declares a required canonical argument the board cannot
 * faithfully resolve (an `artifact_id` in the S2-002 registry, the
 * `to_principal` of a reassignment this operation is not), NO request is
 * invented: there is nothing to ask S2-002 about, the consult is simply absent,
 * and the board's own narrowing checks decide. `requireAuthorizer` (or an
 * injected `authorizer`) turns that absence into a refusal, which is how a
 * deployment makes the consult unconditional. The resolved arguments are kept
 * on the context so the immediate pre-side-effect re-check repeats the SAME
 * consult instead of silently skipping it.
 */
function assertIdentityConsult(ctx, capability, identityArgs, { workspaceId = undefined, resourceId = undefined } = {}, { required = [] } = {}) {
  const usable = isPlainObject(identityArgs)
    && required.every((name) => identityArgs[name] !== undefined && identityArgs[name] !== null);
  const resolvable = isPlainObject(identityArgs)
    && Object.values(identityArgs).every((value) => value !== undefined);
  ctx.identityArgs = usable && resolvable ? identityArgs : null;
  if (ctx.identityArgs === null && ctx.authorizer === undefined && ctx.requireAuthorizer !== true) return null;
  assertActor({
    principal: ctx.principal,
    actorKind: ctx.actorKind,
    capability,
    capabilities: ctx.principal.capabilities,
    workspaceId: workspaceId ?? ctx.args.workspace_id,
    resourceId,
    identityArgs: ctx.identityArgs,
    now: ctx.instant,
    authorizer: ctx.authorizer,
    requireAuthorizer: ctx.requireAuthorizer,
  });
  return true;
}

/** The board.read twin of a task read: the workspace id is always resolvable. */
function assertIdentityConsultForRead(ctx, task) {
  assertIdentityConsult(ctx, 'board.task.read', { workspace_id: task.workspace_id }, {
    workspaceId: task.workspace_id,
    resourceId: task.task_id,
  }, { required: ['workspace_id'] });
  return true;
}

/**
 * Honesty gate for an adapter registration. `real_adapter_provenance.status`
 * is a CLAIM; only an installed executable on this host can CONFIRM it, and a
 * fixture/wrapper/test transport can never be one.
 */
async function assertRealAdapterClaimIsTrue(ctx, registration) {
  const status = registration.real_adapter_provenance?.status;
  if (status !== 'REAL_ADAPTER_AVAILABLE') {
    if (registration.adapter_kind === 'real' && status !== 'REAL_ADAPTER_AVAILABLE') {
      throw new NotRunRealAdapter('NOT_RUN_REAL_ADAPTER', 'adapter_kind real requires a corroborated REAL_ADAPTER_AVAILABLE provenance');
    }
    return true;
  }
  if (registration.adapter_kind !== 'real') {
    throw new BlockedPolicy('PROVENANCE_UPGRADE_REFUSED', 'only a real adapter may declare REAL_ADAPTER_AVAILABLE');
  }
  const probe = await probeRealAdapters({ clock: ctx.clock ?? fixedClock(ctx.instant) });
  const hit = probe.find((row) => row.adapter_id === registration.adapter_id && row.installed === true)
    ?? probe.find((row) => row.installed === true && String(row.adapter_id).includes(registration.provider));
  if (!isPlainObject(hit)) {
    throw new NotRunRealAdapter(
      'NOT_RUN_REAL_ADAPTER',
      `no installed executor corroborates the REAL_ADAPTER_AVAILABLE claim of ${registration.adapter_id}`,
    );
  }
  return true;
}

// --- the single entry point --------------------------------------------------

/**
 * The one entry point. Web, the HTTP API, the CLI, the scheduler, the probes
 * and the tests all come through here; nothing else writes the live board.
 *
 *   1. an unknown command is BLOCKED_POLICY;
 *   2. the actor is resolved SERVER-SIDE and asserted against the command's
 *      required board capability before any payload data is read;
 *   3. `argsDigest = policy.commandIdempotencyKey({ command, args, actor })` and
 *      the caller's `idempotency_key` (required for every mutating command) go
 *      to the store on every write;
 *   4. `assertCanonicalArguments` rejects an unknown or non-canonical argument;
 *   5. an authority-shaped argument may only repeat the resolved value;
 *   6. the ACL is applied before any payload leaves;
 *   7. the actor, the arguments and the ACL are re-checked immediately before
 *      every side effect;
 *   8. the result is `{ ok: true, data, revision, replayed }` or a typed
 *      BoardError. A failure is never a partial success and never an `ok:false`
 *      that a caller could mistake for a completed operation.
 */
export async function execute({
  command,
  args,
  principal,
  actorKind,
  store,
  adapters = [],
  clock = null,
  transport = null,
  now = null,
  // Additive, documented context. `workspaceRoots`/`realpath` are the
  // server-side containment evidence, `sandbox` the proven isolation profile,
  // `ids` an injected id factory (a deterministic one is derived when it is
  // absent), and `authorizer`/`requireAuthorizer` let a deployment make the
  // S2-002 consult unconditional.
  workspaceRoots = null,
  realpath = null,
  sandbox = null,
  authorizer = null,
  requireAuthorizer = false,
  ids = null,
  // The named human authorisation for a run bound to the HOST_UNISOLATED floor
  // tier (issue #45). It is SERVER-RESOLVED and deliberately not a payload
  // argument: an adapter, a task, an execution event, a skill or a replayed
  // record can neither supply nor widen it. Isolated profiles need nothing
  // here, and supplying a permit for one is refused rather than ignored.
  unisolatedExecutionAuthorization = null,
} = {}) {
  try {
    return await run({ command, args, principal, actorKind, store, adapters, clock, transport, now, workspaceRoots, realpath, sandbox, authorizer, requireAuthorizer, ids, unisolatedExecutionAuthorization });
  } catch (error) {
    // Nothing escapes untyped: a crash inside a handler is a typed refusal,
    // never a success and never a partially applied operation reported as one.
    throw isBoardError(error) ? error : toBoardError(error, 'PROVIDER_FAILURE');
  }
}

async function run(input) {
  const { command, principal } = input;
  if (typeof command !== 'string' || !COMMANDS.includes(command)) {
    throw new BlockedPolicy(`COMMAND_UNKNOWN:${String(command)}`, 'the live board has a closed command vocabulary');
  }
  const spec = COMMAND_TABLE[command];
  const args = requireObject(input.args ?? {}, 'args');
  if (input.store === undefined || input.store === null || typeof input.store.getTask !== 'function') {
    throw new NeedsInput('STORE_MISSING', 'the command boundary requires a store');
  }
  // 1. the server-resolved actor. A payload field can never supply it, and the
  //    instant it will be judged against comes from the injection (or, when the
  //    caller injected none, from the store's own database clock).
  const resolved = resolvePrincipal(principal);
  const instant = await resolveInstant({ now: input.now, clock: input.clock }, input.store);
  // 2. the command capability, asserted BEFORE any payload data is read.
  assertActor({
    principal: resolved.principal_id,
    actorKind: input.actorKind,
    capability: spec.capability,
    capabilities: resolved.capabilities,
    now: instant,
  });
  // 3. the idempotency contract, before the arguments are trusted.
  const idempotencyKey = requireIdempotencyKey(args, command);
  const argsDigest = argsDigestOf({ command, args, actor: resolved.principal_id });
  // 4. the canonical arguments, with the per-command allowlist.
  policyAssertCanonicalArguments(command, args);
  // 5. the authority agreement rule.
  assertAuthorityAgreement(args, {
    principal_id: resolved.principal_id,
    actor: resolved.principal_id,
    actor_kind: input.actorKind,
    capabilities: resolved.capabilities ?? null,
  });
  const ctx = makeContext({
    command,
    args,
    principal: resolved,
    actorKind: input.actorKind,
    store: input.store,
    adapters: input.adapters,
    clock: input.clock,
    transport: input.transport,
    now: input.now,
    instant,
    workspaceRoots: input.workspaceRoots,
    realpath: input.realpath,
    authorizer: input.authorizer ?? undefined,
    requireAuthorizer: input.requireAuthorizer === true,
    ids: input.ids ?? deterministicIdFactory({ command, workspace_id: args.workspace_id ?? null, actor: resolved.principal_id }),
  });
  ctx.sandbox = input.sandbox;
  ctx.unisolatedExecutionAuthorization = input.unisolatedExecutionAuthorization ?? null;
  ctx.idempotencyKey = idempotencyKey;
  ctx.argsDigest = argsDigest;
  ctx.identityArgs = null;

  const handler = handlers[command];
  const result = await handler(ctx);
  return {
    ok: true,
    data: result.data ?? null,
    revision: result.revision ?? null,
    replayed: result.replayed === true,
  };
}
