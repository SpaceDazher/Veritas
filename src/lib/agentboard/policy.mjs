// S2-007 Agent Board policy module (issue #7, §2 execution boundary).
//
// WHAT THIS MODULE IS
// A default-deny refusal surface. Every exported function either returns
// (the request is provably inside the boundary) or throws a typed BoardError
// from ./errors.mjs whose `code` is a member of ERROR_CODES. Nothing here
// returns "allowed: false" as a value, and nothing here performs I/O, reads a
// clock or touches the store: the guards are pure functions of the context the
// caller supplies, so store.mjs, commands.mjs and the tests can all call the
// exact same function and get the exact same answer.
//
// WHY THE POLICY IS SHAPED THIS WAY (the four load-bearing rules)
//  1. ONE AUTHORIZATION POINT. S2-002 (src/lib/identity/policy-engine.mjs) is
//     the single authorization engine and is consulted here for the real
//     decision — never a second, weaker authorizer. A DENY from it is fatal and
//     is mapped to a typed board error. The local checks in this module exist
//     only because S2-002 has NO equivalent for them, and each one can only
//     ever REMOVE permission, never add it:
//       * board lease/fence state  — S2-002 leases are its own fixture records
//         with their own ids; the board lease is a different artifact
//         (agentboard_lease) with a monotonic fence, so the board checks it.
//       * the empty-set rule       — S2-002 has no tool/scope allowlist.
//       * actor kinds              — S2-002 principals have kinds, not the
//         board's human_owner | human_reviewer | deterministic_gate |
//         adapter | scheduler | system taxonomy.
//       * budget arithmetic        — S2-002 has no numeric budget at all.
//       * ACL narrowing            — the task ACL row is a board artifact.
//     Every such place says so in a comment next to the code.
//  2. ONE DIGEST CONVENTION. S2-006 canonical-json-v1 (./verifier/
//     canonical-json.mjs) is the only serializer and the only hash. This
//     module never writes a canonicalizer: commandIdempotencyKey() and the
//     history/idempotency bindings are canonicalDigest() over canonicalize().
//  3. DATA IS NOT AUTHORITY. A digest proves that nothing changed, never who
//     changed it. A prompt, a log, a model answer, a TaskBrief body, a client
//     payload or an environment variable never grants capability, budget,
//     approval or identity. assertActor therefore takes the principal that the
//     CALLER resolved server-side; it never accepts one out of a payload.
//  4. FAIL CLOSED. An empty array is never "everything": an empty granted tool
//     set with a non-empty required set is CAPABILITY_MISMATCH, an empty scope
//     grant is CAPABILITY_MISMATCH, an empty ACL list is NOBODY, and an
//     unassigned budget is not zero (BUDGET_EXCEEDED). An unknown external
//     side effect is never a retry: EFFECT_UNDETERMINED keeps
//     RECONCILIATION_REQUIRED and no edge that could start new work may pass
//     through it.
//
// DETERMINISM
// No Math.random(), no Date.now(), no bare `new Date()` without an injected
// clock. fixedClock() and sequenceIdFactory() are the only clock/id sources
// this module offers. `now` in a guard context is an ISO string the caller
// injected (DB time in production — SELECT NOW()), and it is parsed, never
// sampled from the process clock. Given the same context, every function here
// returns the same answer forever.
//
// TRANSITIONS
// The edge list lives in constants.mjs (TRANSITIONS) and nowhere else.
// decideTransition() is the ONLY way to reach a guard, it reads that table, it
// verifies the named guard is one of the eleven exported guards, and each
// guard re-checks that it was handed its own edge. A second, hand-written edge
// list anywhere would be a second editable form of the truth the boundary
// contract forbids — so this module has exactly eleven guard exports and
// nothing that can invent a twelfth edge.
//
// GUARD CONTEXT (built by store.mjs / commands.mjs, documented contract)
//   required : task, fromState, toState, actor, actorKind, now,
//              expectedRevision, capabilities
//   optional : reason, lease, fencingToken, adapters, budgetGrant, budgetSpent,
//              dependenciesSatisfied, briefValidated, reconciliation,
//              canonicalArgs
//   documented optional additions used by this module (all fail closed when
//   they are absent, or the check is simply not applicable to the edge):
//     workspaceRoots    — absolute server-side roots; when absent the S2-002
//                         WORKSPACES registry is consulted by workspace_id.
//     realpath          — fs.realpathSync-shaped resolver for symlink escape.
//     sandboxProfileId  — overrides adapter.sandbox_profile_id.
//     requestScopes / grantedScopes — ExecutionRequest scopes to contain.
//     digests           — the digests the caller actually observed.
//     producer_principal_id — the run producer, when not derivable from lease
//                         or adapter registration.
//     identityArgs      — the S2-002 canonical arguments the caller resolved;
//                         an S2-002 consult is built only from them, never
//                         from arguments this module invents.
//     verdict           — APPROVED | REJECTED for the approval consult.
//     authorizer        — an S2-002 `authorize(request)` function; when
//                         present its decision is authoritative.
//     requireAuthorizer — refuse unless an authorizer is injected.
//     activeLeaseCount  — live-lease count for MAX_CONCURRENT_TASKS.
import {
  ACTOR_KINDS,
  BOARD_CAPABILITIES,
  BOARD_STATES,
  EXECUTION_SCOPES,
  ID_PREFIXES,
  MAX_CONCURRENT_TASKS,
  SANDBOX_PROFILES,
  TRANSITIONS,
  isExecutableSandboxProfile,
  isHostUnisolatedSandboxProfile,
  isKnownState,
  toStoredDigest,
  toWireDigest,
} from './constants.mjs';
import { toInjectedInstant } from './clock.mjs';
import {
  AclDenied,
  AgentUnavailable,
  AuthRequired,
  BlockedPolicy,
  BlockedSandbox,
  BudgetExceeded,
  CapabilityMismatch,
  MalformedResult,
  NeedsInput,
  ReconciliationRequired,
  RevisionConflict,
  StaleFence,
  TransitionNotAllowed,
} from './errors.mjs';
import { canonicalDigest, canonicalize } from '../verifier/canonical-json.mjs';
import { createPolicyEngine } from '../identity/policy-engine.mjs';
import { CAPABILITIES, WORKSPACES } from '../identity/principals.mjs';

export const POLICY_VERSION = 's2-007-policy-v1';

// --- closed vocabularies and shapes ----------------------------------------
// Every pattern here mirrors an already-frozen contract (contracts/*.schema.json,
// identity/policy-engine.mjs id patterns) and is used only to REJECT. None of
// them grants anything.
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PRINCIPAL_ID_RE = /^prn-[a-z0-9][a-z0-9-]{0,62}$/;
const WORKSPACE_ID_RE = /^ws-[a-z0-9][a-z0-9-]{0,62}$/;
const TASK_ID_RE = /^abt-[a-z0-9][a-z0-9-]{0,62}$/;
const LEASE_ID_RE = /^lse-[a-z0-9][a-z0-9-]{0,62}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const TOOL_RE = /^tool:[a-z0-9][a-z0-9._-]{0,62}$/;
const CAPABILITY_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const ARGUMENT_NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const COMMAND_RE = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_]*)+$/;
const ID_FACTORY_PREFIX_RE = /^[a-z]{3}-$/;
const WORKSPACE_SEGMENT_RE = /^[A-Za-z0-9._-]{1,255}$/;
const RESERVED_ARGUMENT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_REASON = 500;

// The board ACL visibility classes. This mirrors the board-task schema enum;
// it is a shape check on a board-owned row, not a second authority.
const VISIBILITIES = new Set(['personal', 'project', 'shared']);

// Actor kinds that may act as the approval gate. S2-002 has no equivalent
// (it knows principal kinds, not board actor kinds), so this list is
// board-local and it is a REDUCTION: everything else is refused.
const APPROVAL_ACTOR_KINDS = new Set(['human_owner', 'human_reviewer', 'deterministic_gate']);
// Actor kinds that are never a human gate: an adapter, a scheduler and a
// system component can block, fail or cancel, but can never approve.
const NON_APPROVING_ACTOR_KINDS = new Set(['adapter', 'scheduler', 'system']);

// Board capability -> the S2-002 action that carries the same resource and
// side effect. This is a MAPPING, not an authorizer: the decision is still
// taken by S2-002. A board capability that has no S2-002 twin simply is not
// listed, and is then decided by the board's own narrowing checks alone.
const IDENTITY_CAPABILITY_MAP = Object.freeze({
  'board.task.create': 'task.create',
  'board.task.read': 'board.read',
  'board.task.transition': 'task.transition',
  'board.task.claim': 'task.update',
  'board.task.release': 'task.update',
  'board.execution.start': 'tool.execute',
  'board.execution.cancel': 'task.cancel',
  'board.result.collect': 'artifact.read',
  'board.evidence.submit': 'task.update',
  'board.review.approve': 'approval.decide',
  'board.review.challenge': 'approval.decide',
  'board.adapter.register': 'task.reassign',
  'board.budget.grant': 'task.reassign',
  'board.reconciliation.decide': 'approval.decide',
});

// S2-002 capabilities whose constraints require_lease. The board lease
// (agentboard_lease) is a different artifact with a different id space, so a
// board call can never satisfy an S2-002 lease. For these, S2-002 is consulted
// only when the caller injects an authorizer that can honour the board lease
// or an owner-maintenance waiver; otherwise the board's own fence check is the
// authority and the mapping is NOT attempted (see assertActor).
const IDENTITY_LEASE_BOUND = new Set([
  'task.update', 'task.transition', 'claim.write', 'summary.generate',
  'cache.write', 'tool.execute', 'tool.execute.untrusted',
]);

const S2_WORKSPACES = new Map(WORKSPACES.map((workspace) => [workspace.workspace_id, workspace]));
// S2-002's own declaration of each action: its resource type and its canonical
// argument names. Read from the registry, never restated here, so the request
// this module builds to ask S2-002 is shaped by the single authority itself.
const S2_CAPABILITIES = new Map(CAPABILITIES.map((capability) => [capability.action, capability]));
// resource_type -> the canonical argument that must name that resource.
const S2_RESOURCE_ARGUMENT = Object.freeze({
  board: 'workspace_id', task: 'task_id', artifact: 'artifact_id', tool: 'tool_id', approval: 'approval_id',
});
// Actions whose resource id is minted by the call itself, so no argument can
// (or should) name it yet.
const S2_MINTED_RESOURCE = Object.freeze(new Set(['task.create']));

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

// --- clock and id helpers ---------------------------------------------------

/**
 * A fixed, injected clock. `{ now: () => Date }` plus `nowIso()` for the
 * string form every guard context carries. Nothing samples the process clock:
 * an instant that is not supplied by the caller does not exist here.
 */
export function fixedClock(iso) {
  if (typeof iso !== 'string' || !ISO_RE.test(iso) || !Number.isFinite(Date.parse(iso))) {
    throw new NeedsInput(`CLOCK_INVALID:${String(iso)}`);
  }
  const instant = new Date(iso);
  return Object.freeze({
    now: () => new Date(instant.getTime()),
    nowIso: () => iso,
  });
}

/**
 * Deterministic id factory. Ids are `${prefix}${base36(seed + seq)}` padded to
 * eight characters, which keeps them inside the frozen id patterns
 * (^abt-[a-z0-9][a-z0-9-]{0,62}$ and friends) and byte-identical across runs
 * for the same sequence — the property the append-only ledger and the replay
 * harness depend on. No randomness: a random suffix would make two runs of the
 * same test incomparable.
 */
export function sequenceIdFactory(prefix, { seed = 0 } = {}) {
  if (typeof prefix !== 'string' || !ID_FACTORY_PREFIX_RE.test(prefix)) {
    throw new NeedsInput(`ID_PREFIX_INVALID:${String(prefix)}`);
  }
  if (!Number.isInteger(seed) || seed < 0) {
    throw new NeedsInput(`ID_SEED_INVALID:${String(seed)}`);
  }
  return Object.freeze((seq) => {
    if (!Number.isInteger(seq) || seq < 0) {
      throw new NeedsInput(`ID_SEQUENCE_INVALID:${String(seq)}`);
    }
    return `${prefix}${(seq + seed).toString(36).padStart(8, '0')}`;
  });
}

/**
 * Idempotency key: SHA-256 over the canonical-json-v1 form of the command
 * arguments, through the S2-006 canonicalizer. Key order is irrelevant
 * (canonicalize sorts keys), argument order in arrays is significant (it is
 * part of the request), and a non-canonical value (undefined member, NaN,
 * circular, class instance) is refused rather than silently mangled by
 * JSON.stringify. Returns bare 64 hex — the form agentboard_operation stores.
 */
export function commandIdempotencyKey(args) {
  let canonical;
  try {
    canonical = canonicalize(args);
  } catch (error) {
    throw new BlockedPolicy('IDEMPOTENCY_ARGS_NOT_CANONICAL', String(error?.message ?? '').slice(0, 400));
  }
  return canonicalDigest(args);
}

// --- ACL --------------------------------------------------------------------

/**
 * Task-level ACL narrowing, applied before any payload is returned AND before
 * any mutation. `visibility` classifies the task and never widens access: in
 * all three classes the only principals that may see or touch the task are the
 * ones the server resolved into acl.allowed_principal_ids. An empty list means
 * NOBODY — the same fail-closed rule that governs allowed_tools.
 * Widening beyond the list is the S2-002 workspace ACL's job and happens in
 * commands.mjs before isVisible(); this function can only subtract.
 */
export function isVisible(task, principalId) {
  if (!isPlainObject(task) || !isPlainObject(task.acl)) return false;
  const acl = task.acl;
  if (!VISIBILITIES.has(acl.visibility)) return false;
  if (typeof principalId !== 'string' || !PRINCIPAL_ID_RE.test(principalId)) return false;
  if (!isStringArray(acl.allowed_principal_ids)) return false;
  return acl.allowed_principal_ids.includes(principalId);
}

export function assertTaskVisible(task, principalId) {
  if (isVisible(task, principalId)) return true;
  throw new AclDenied(
    'ACL_DENIED',
    `principal ${String(principalId)} is not in the ACL of task ${String(task?.task_id)}`,
  );
}

// --- authority --------------------------------------------------------------

/**
 * The actor check. `principal` is the SERVER-RESOLVED principal (never a
 * payload field), `capability` is the board capability the edge needs and
 * `capabilities` is the server-resolved grant set the principal holds.
 *
 * Layer 1 (board-local, narrowing only): shape of the principal, a known actor
 * kind, a known board capability, and membership of that capability in the
 * granted set. An empty granted set grants nothing.
 *
 * Layer 2 (S2-002, the real decision): when a mapping exists, when the
 * workspace and principal are inside the S2-002 registry, and when the
 * capability's S2-002 twin is not lease-bound, `createPolicyEngine` is asked
 * directly. ALLOW continues; DENY is AUTH_REQUIRED; BLOCKED_SANDBOX is
 * BLOCKED_SANDBOX; NEEDS_APPROVAL is BLOCKED_POLICY. When the caller injects
 * `authorizer`, that decision is always authoritative — and an injected
 * authorizer is a DEMAND, not a hint: if the resolved arguments cannot be
 * shaped into a complete S2-002 request the call is refused (BLOCKED_POLICY)
 * instead of being decided by the board alone. The board's own lease
 * gate is not a substitute for S2-002 — it is a different artifact — and the
 * board's narrow checks below are additions on top of whatever S2-002 decided,
 * never a relaxation of it.
 */
export function assertActor(options = {}) {
  const {
    principal,
    actorKind,
    capability,
    capabilities,
    workspaceId,
    resourceId,
    producerPrincipalId,
    identityArgs,
    verdict = 'APPROVED',
    now,
    authorizer,
    requireAuthorizer = false,
    grantUnchecked = false,
  } = options ?? {};

  const principalId = typeof principal === 'string' ? principal : principal?.principal_id;
  if (typeof principalId !== 'string' || !PRINCIPAL_ID_RE.test(principalId)) {
    throw new AuthRequired('AUTH_REQUIRED', 'no server-resolved principal on the request');
  }
  if (typeof actorKind !== 'string' || !ACTOR_KINDS.includes(actorKind)) {
    throw new BlockedPolicy(`ACTOR_KIND_UNKNOWN:${String(actorKind)}`);
  }
  if (typeof capability !== 'string' || !BOARD_CAPABILITIES.includes(capability)) {
    throw new BlockedPolicy(`CAPABILITY_UNKNOWN:${String(capability)}`);
  }
  if (capabilities !== undefined && capabilities !== null) {
    if (!isStringArray(capabilities)) {
      throw new BlockedPolicy('CAPABILITY_GRANT_MALFORMED');
    }
    if (!capabilities.includes(capability)) {
      throw new AuthRequired('AUTH_REQUIRED', `capability ${capability} is not in the server-resolved grant`);
    }
  } else if (grantUnchecked !== true) {
    // FAIL CLOSED. An ABSENT grant is not an empty grant: an empty grant
    // refuses everything, an absent grant used to skip the check entirely,
    // which let a principal record with no `capabilities` field grant itself
    // budget, claims and adapter registration — the exact authority expansion
    // the boundary exists to prevent. Only a caller that has deliberately
    // delegated authorization elsewhere may set grantUnchecked, and no command
    // on the production path does.
    throw new AuthRequired('AUTH_REQUIRED', 'no server-resolved capability grant on the request');
  }
  if (requireAuthorizer && typeof authorizer !== 'function') {
    throw new BlockedPolicy('AUTHORIZER_NOT_INJECTED');
  }
  if (typeof now !== 'undefined' && (typeof now !== 'string' || !ISO_RE.test(now))) {
    throw new NeedsInput(`CLOCK_INVALID:${String(now)}`);
  }

  const identityAction = IDENTITY_CAPABILITY_MAP[capability];
  const targetWorkspace = workspaceId;
  // A contradiction between what the server resolved and what the caller says
  // the operation is about is never downgraded into "there is no S2-002
  // request to build", which would silently remove the consult. It is an
  // authority disagreement, and it fails closed here, before any consult.
  assertNoAuthorityContradiction({ identityAction, workspaceId: targetWorkspace, resourceId, identityArgs, verdict });
  const knowsWorkspace = typeof targetWorkspace === 'string'
    && WORKSPACE_ID_RE.test(targetWorkspace)
    && S2_WORKSPACES.has(targetWorkspace);
  // A principal outside the S2-002 registry has no S2-002 decision to reuse:
  // the board then stands on layer 1 alone, which is why layer 1 is strict and
  // narrowing. When the caller needs the S2-002 guarantee unconditionally it
  // passes requireAuthorizer (or a real workspace) and this refuses instead.
  if (identityAction && (authorizer !== undefined || knowsWorkspace)) {
    if (authorizer === undefined && IDENTITY_LEASE_BOUND.has(identityAction)) {
      // S2-002 would demand one of ITS lease records for this capability. The
      // board lease cannot satisfy it, so an automatic consult here could only
      // ever produce a false DENY that hides the real authorization path. The
      // board's own fence check in assertFenceFresh is the authority for these
      // edges; inject an authorizer to have S2-002 decide anyway.
    } else {
      // The S2-002 request is built ONLY from arguments the caller actually
      // resolved. A canonical argument this module cannot derive is never
      // invented to make an authorization look present: without a faithful
      // argument set there is no request to ask S2-002 about, so no consult
      // happens and the caller must pass requireAuthorizer to demand one.
      const request = buildIdentityRequest({
        action: identityAction,
        principalId,
        workspaceId: targetWorkspace,
        resourceId,
        producerPrincipalId,
        identityArgs,
        verdict,
      });
      if (!request && authorizer !== undefined) {
        // An injected authorizer is a DEMAND for the S2-002 decision. When no
        // faithful request can be built from what the caller resolved the
        // demand cannot be met, and quietly falling back to the board's own
        // checks would be precisely the weakened second authorizer the contract
        // forbids. Fail closed instead. (Without an injected authorizer the
        // automatic consult is simply absent — layer 1 is strict and narrowing,
        // and requireAuthorizer is how a caller makes the demand unconditional.)
        throw new BlockedPolicy(
          'IDENTITY_REQUEST_UNAVAILABLE',
          `${capability} cannot be mapped onto a complete ${identityAction} request from the resolved arguments`,
        );
      }
      if (request) assertIdentityAllow(request, now, authorizer);
    }
  }
  return principalId;
}

/**
 * Fail closed on an authority contradiction. The admissible argument names come
 * from the S2-002 capability registry itself, never restated here, so this can
 * only narrow. `approval` and `board` resources are deliberately excluded from
 * the resource comparison: their id is resolved elsewhere (from identityArgs
 * and from the workspace respectively), and a guard passes a task id as the
 * generic resourceId, so comparing them here would invent a contradiction. The
 * resource-vs-payload comparison for those two is owned by
 * assertCanonicalArguments' `authorized` map at the command boundary, where the
 * server-resolved id is known.
 */
function assertNoAuthorityContradiction({ identityAction, workspaceId, resourceId, identityArgs, verdict }) {
  if (!identityAction || !isPlainObject(identityArgs)) return;
  const record = S2_CAPABILITIES.get(identityAction);
  if (!record) return;
  const declared = new Set(record.canonical_arguments.map((argument) => argument.name));
  if (declared.has('workspace_id') && identityArgs.workspace_id !== undefined
    && identityArgs.workspace_id !== null && identityArgs.workspace_id !== workspaceId) {
    throw new AuthRequired('AUTH_REQUIRED', `workspace_id does not name the authorized workspace of ${identityAction}`);
  }
  if (declared.has('verdict') && identityArgs.verdict !== undefined
    && identityArgs.verdict !== null && identityArgs.verdict !== verdict) {
    throw new BlockedPolicy('IDENTITY_VERDICT_MISMATCH', `verdict does not name the authorized verdict of ${identityAction}`);
  }
  const resourceType = record.resource_type;
  const resourceArgument = S2_RESOURCE_ARGUMENT[resourceType] ?? null;
  if (resourceType === 'approval' || resourceType === 'board') return;
  if (!resourceArgument || !declared.has(resourceArgument)) return;
  if (S2_MINTED_RESOURCE.has(identityAction)) return;
  if (typeof resourceId !== 'string' || resourceId.length === 0) return;
  if (typeof identityArgs[resourceArgument] !== 'string' || identityArgs[resourceArgument].length === 0) return;
  if (identityArgs[resourceArgument] !== resourceId) {
    throw new AuthRequired('AUTH_REQUIRED', `${resourceArgument} does not name the authorized resource of ${identityAction}`);
  }
}

// resource_type per S2-002 action. Anything not listed has no board mapping and
// is therefore never consulted.
function buildIdentityRequest({ action, principalId, workspaceId, resourceId, producerPrincipalId, identityArgs, verdict }) {
  const capability = S2_CAPABILITIES.get(action);
  if (!capability) return null;
  if (!isPlainObject(identityArgs)) return null;
  if (typeof workspaceId !== 'string' || !WORKSPACE_ID_RE.test(workspaceId)) return null;
  const declared = capability.canonical_arguments;
  const declaredNames = new Set(declared.map((argument) => argument.name));
  for (const argument of declared) {
    if (!argument.required) continue;
    if (!Object.hasOwn(identityArgs, argument.name)
      || identityArgs[argument.name] === undefined || identityArgs[argument.name] === null) return null;
  }
  if (declaredNames.has('workspace_id') && identityArgs.workspace_id !== workspaceId) return null;
  const resourceType = capability.resource_type;
  const resourceArgument = S2_RESOURCE_ARGUMENT[resourceType] ?? null;
  // The resource id the SERVER authorized is resolved BEFORE the comparison
  // below. It is not always the caller's `resourceId`: board.read names the
  // workspace itself and approval.decide names the caller's approval record.
  // Comparing those two arguments against a resource the caller never passed
  // would be vacuous, and a vacuous comparison used to make this function
  // return null — which silently removed the S2-002 consult altogether.
  const id = resourceType === 'board' ? workspaceId
    : resourceType === 'approval' ? identityArgs.approval_id
      : resourceId;
  if (typeof id !== 'string' || id.length === 0) return null;
  if (resourceArgument && declaredNames.has(resourceArgument) && !S2_MINTED_RESOURCE.has(action)) {
    // The caller's arguments must name the resource the server authorized: the
    // confused-deputy check. board.read is already bound above (its workspace_id
    // must equal the server's workspace). S2-002's own approval rules own the
    // independence of an approval record, so that comparison is skipped here.
    if (typeof identityArgs[resourceArgument] !== 'string' || identityArgs[resourceArgument].length === 0) return null;
    if (resourceType !== 'approval' && identityArgs[resourceArgument] !== id) return null;
  }
  if (resourceType === 'approval' && identityArgs.verdict !== verdict) return null;
  const resource = { type: resourceType, id };
  if (resourceType === 'approval' && typeof producerPrincipalId === 'string') {
    resource.producerPrincipalId = producerPrincipalId;
  }
  return { adapter: 'api', principalId, workspaceId, action, resource, args: { ...identityArgs }, context: {} };
}

/**
 * The canonical arguments for an S2-002 consult, taken from the guard's own
 * data. `ctx.identityArgs` (arguments the caller resolved) always wins; the
 * derived set is filtered down to the arguments S2-002 declares for that
 * action, so nothing is invented and nothing undeclared is smuggled in. A
 * required argument with no faithful value yields no request at all.
 */
function derivedIdentityArgs(ctx, capability, task) {
  if (ctx.identityArgs !== undefined) return isPlainObject(ctx.identityArgs) ? ctx.identityArgs : null;
  const record = S2_CAPABILITIES.get(IDENTITY_CAPABILITY_MAP[capability]);
  if (!record) return null;
  const candidate = {
    task_id: task.task_id,
    workspace_id: task.workspace_id,
    from_status: ctx.fromState,
    to_status: ctx.toState,
    expected_revision: ctx.expectedRevision,
    revision: ctx.expectedRevision,
    reason: ctx.reason,
  };
  const args = {};
  for (const argument of record.canonical_arguments) {
    const value = candidate[argument.name];
    if (value !== undefined && value !== null) args[argument.name] = value;
  }
  return args;
}

function assertIdentityAllow(request, now, authorizer) {
  let decision;
  if (authorizer !== undefined) {
    if (typeof authorizer !== 'function') throw new BlockedPolicy('AUTHORIZER_INVALID');
    try {
      decision = authorizer(request);
    } catch (error) {
      throw new AuthRequired('IDENTITY_AUTHORIZER_FAILED', String(error?.message ?? '').slice(0, 300));
    }
  } else {
    let engine;
    try {
      engine = createPolicyEngine({ now });
    } catch (error) {
      throw new BlockedPolicy('IDENTITY_ENGINE_UNAVAILABLE', String(error?.message ?? '').slice(0, 300));
    }
    try {
      decision = engine.authorize(request);
    } catch (error) {
      throw new AuthRequired('IDENTITY_AUTHORIZER_FAILED', String(error?.message ?? '').slice(0, 300));
    }
  }
  if (!isPlainObject(decision) || typeof decision.decision !== 'string') {
    throw new BlockedPolicy('AUTHORIZATION_DECISION_UNKNOWN');
  }
  if (decision.decision === 'ALLOW') return true;
  const reasons = isStringArray(decision.reasonCodes) ? decision.reasonCodes.join('|') : '';
  if (decision.decision === 'DENY') throw new AuthRequired('AUTH_REQUIRED', `identity policy denied: ${reasons}`.slice(0, 400));
  if (decision.decision === 'BLOCKED_SANDBOX') throw new BlockedSandbox('IDENTITY_SANDBOX_BLOCKED', reasons.slice(0, 400));
  throw new BlockedPolicy(`IDENTITY_${decision.decision}`, reasons.slice(0, 400));
}

// --- capability / tool / scope containment ----------------------------------

/** Every required capability must be in the granted set. Empty granted set = nothing granted. */
export function assertCapabilitySubset(required, granted) {
  const requiredSet = normalizeNameSet(required, CAPABILITY_NAME_RE, 'REQUIRED_CAPABILITIES');
  const grantedSet = normalizeNameSet(granted, CAPABILITY_NAME_RE, 'GRANTED_CAPABILITIES');
  for (const name of requiredSet) {
    if (!grantedSet.has(name)) {
      throw new CapabilityMismatch('CAPABILITY_MISMATCH', `capability ${name} is not granted`);
    }
  }
  return true;
}

/**
 * Task tool grant containment. The empty set is never "everything": an empty
 * granted set with a non-empty required set is CAPABILITY_MISMATCH, and a task
 * whose allowed_tools is empty may not exercise any tool at all.
 */
export function assertToolSubset(taskTools, grantedTools) {
  const requiredSet = normalizeNameSet(taskTools, TOOL_RE, 'TASK_TOOLS');
  const grantedSet = normalizeNameSet(grantedTools, TOOL_RE, 'GRANTED_TOOLS');
  for (const name of requiredSet) {
    if (!grantedSet.has(name)) {
      throw new CapabilityMismatch('CAPABILITY_MISMATCH', `tool ${name} is not granted`);
    }
  }
  return true;
}

/** Requested execution scopes must be inside the granted scopes, and both must be real scopes. */
export function assertScopeSubset(requestScopes, grantedScopes) {
  const requested = normalizeNameSet(requestScopes, null, 'REQUESTED_SCOPES');
  const granted = normalizeNameSet(grantedScopes, null, 'GRANTED_SCOPES');
  for (const scope of requested) {
    if (!EXECUTION_SCOPES.includes(scope)) {
      throw new CapabilityMismatch('CAPABILITY_MISMATCH', `unknown execution scope ${scope}`);
    }
    if (!granted.has(scope)) {
      throw new CapabilityMismatch('CAPABILITY_MISMATCH', `execution scope ${scope} is not granted`);
    }
  }
  for (const scope of granted) {
    if (!EXECUTION_SCOPES.includes(scope)) {
      throw new CapabilityMismatch('CAPABILITY_MISMATCH', `unknown granted execution scope ${scope}`);
    }
  }
  return true;
}

function normalizeNameSet(value, pattern, label) {
  if (value === undefined || value === null) return new Set();
  if (!isStringArray(value)) {
    throw new CapabilityMismatch('CAPABILITY_MISMATCH', `${label} must be an array of strings`);
  }
  const set = new Set();
  for (const item of value) {
    if (pattern && !pattern.test(item)) {
      throw new CapabilityMismatch('CAPABILITY_MISMATCH', `${label} contains a malformed name: ${item}`.slice(0, 200));
    }
    set.add(item);
  }
  return set;
}

// --- workspace containment --------------------------------------------------

/**
 * Workspace containment for a task's workspace_ref. Lexical, deterministic and
 * fail-closed: absolute paths, drive letters, UNC, backslashes, NUL bytes,
 * device names, '..' and '.' segments and any path that escapes the roots
 * after normalization are AclDenied. When a real filesystem resolver is
 * injected ({ realpath }), a symlink/junction that leaves the root is refused
 * too; without one the check stays pure and never touches the disk.
 *
 * S2-002's sandbox.resolvePath is deliberately NOT called here: it needs a
 * fully built sandbox instance, does live filesystem access and hard-codes
 * Windows device-name handling, so reusing it would make this function
 * impure and untestable. The lexical rules are at least as strict as the
 * board-task schema pattern, and the live-run enforcement stays where it
 * belongs — in the S2-002 sandbox the adapter is actually launched through.
 */
export function assertWorkspaceWithin(workspaceRef, workspaceRoots, { realpath } = {}) {
  if (!isPlainObject(workspaceRef)) {
    throw new AclDenied('WORKSPACE_REF_MALFORMED', 'workspace_ref must be an object');
  }
  if (typeof workspaceRef.workspace_id !== 'string' || !WORKSPACE_ID_RE.test(workspaceRef.workspace_id)) {
    throw new AclDenied('WORKSPACE_REF_MALFORMED', 'workspace_ref.workspace_id is malformed');
  }
  if (!isStringArray(workspaceRoots) || workspaceRoots.length === 0) {
    // An empty or unknown root set proves nothing: nothing is inside it.
    throw new AclDenied('WORKSPACE_ROOTS_REQUIRED', 'no workspace root is known for this task');
  }
  assertRelativePath(workspaceRef.root_ref, 'root_ref');

  const roots = workspaceRoots.map((root) => {
    if (typeof root !== 'string' || root.length === 0) {
      throw new AclDenied('WORKSPACE_ROOTS_REQUIRED', 'workspace root must be a non-empty string');
    }
    if (root.includes('\u0000')) {
      throw new AclDenied('WORKSPACE_ROOT_MALFORMED', 'workspace root contains a NUL byte');
    }
    return root;
  });
  for (const relative of isStringArray(workspaceRef.read_only_paths) ? workspaceRef.read_only_paths : []) {
    assertRelativePath(relative, 'read_only_path');
  }

  // Normalization without touching the disk: the candidate must be a strict
  // descendant of exactly one root, compared segment by segment so that
  // "/srv/wsx-evil" never passes for the root "/srv/ws".
  let matchedRoot = null;
  for (const root of roots) {
    const rootSegments = splitPath(root);
    if (rootSegments.length === 0) continue;
    const candidate = [...rootSegments, ...splitPath(workspaceRef.root_ref)];
    if (segmentsWithin(candidate, rootSegments)) {
      matchedRoot = { root, rootSegments };
      break;
    }
  }
  if (!matchedRoot) {
    throw new AclDenied('WORKSPACE_ESCAPE', `root_ref ${workspaceRef.root_ref} is not inside any workspace root`);
  }

  if (typeof realpath === 'function') {
    const rootReal = safeRealpath(realpath, matchedRoot.root);
    const candidateReal = safeRealpath(realpath, joinPath(matchedRoot.root, workspaceRef.root_ref));
    if (rootReal === null || candidateReal === null) {
      throw new AclDenied('WORKSPACE_UNRESOLVABLE', 'workspace root could not be resolved');
    }
    if (!segmentsWithin(splitPath(candidateReal), splitPath(rootReal))) {
      throw new AclDenied('WORKSPACE_LINK_ESCAPE', 'workspace_ref resolves outside the workspace root');
    }
  }
  return true;
}

function assertRelativePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) {
    throw new AclDenied('WORKSPACE_PATH_MALFORMED', `${label} must be a relative path of 1..255 characters`);
  }
  if (value.includes('\u0000')) throw new AclDenied('WORKSPACE_PATH_MALFORMED', `${label} contains a NUL byte`);
  if (value.includes('\\')) throw new AclDenied('WORKSPACE_PATH_MALFORMED', `${label} contains a backslash`);
  if (value.startsWith('/') || value.startsWith('~')) {
    throw new AclDenied('WORKSPACE_PATH_ABSOLUTE', `${label} must be relative`);
  }
  if (/^[A-Za-z]:/.test(value)) {
    throw new AclDenied('WORKSPACE_PATH_ABSOLUTE', `${label} must be relative`);
  }
  const segments = value.split('/');
  for (const segment of segments) {
    if (segment === '') throw new AclDenied('WORKSPACE_PATH_MALFORMED', `${label} has an empty segment`);
    if (segment === '.' || segment === '..') {
      throw new AclDenied('WORKSPACE_PATH_TRAVERSAL', `${label} contains a ${segment} segment`);
    }
    if (!WORKSPACE_SEGMENT_RE.test(segment)) {
      throw new AclDenied('WORKSPACE_PATH_MALFORMED', `${label} has an unsupported character`);
    }
  }
  // Windows device names are refused on every platform: a board artifact must
  // never open CON, NUL or a COM port, and a Linux host that later syncs this
  // task to a Windows executor must not inherit the trapdoor.
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i.test(segments[segments.length - 1])) {
    throw new AclDenied('WORKSPACE_PATH_MALFORMED', `${label} names a device`);
  }
  return true;
}

function splitPath(value) {
  // Trusted roots and realpath() results use the host separator. The untrusted
  // relative ref rejects backslashes above, but Windows realpaths do not.
  return value.split(/[\\/]/).filter((segment) => segment.length > 0 && segment !== '.');
}

function joinPath(root, relative) {
  return `${root.replace(/\/+$/, '')}/${relative}`;
}

function segmentsWithin(candidateSegments, rootSegments) {
  if (candidateSegments.length <= rootSegments.length) return false;
  for (let index = 0; index < rootSegments.length; index += 1) {
    if (candidateSegments[index] !== rootSegments[index]) return false;
  }
  return true;
}

function safeRealpath(realpath, target) {
  try {
    const resolved = realpath(target);
    return typeof resolved === 'string' && resolved.length > 0 ? resolved : null;
  } catch {
    return null;
  }
}

function resolveWorkspaceRoots(task, ctx) {
  if (ctx.workspaceRoots !== undefined) return ctx.workspaceRoots;
  const workspaceId = isPlainObject(task?.workspace_ref) ? task.workspace_ref.workspace_id : task?.workspace_id;
  const workspace = typeof workspaceId === 'string' ? S2_WORKSPACES.get(workspaceId) : undefined;
  if (workspace && isStringArray(workspace.allowed_roots) && workspace.allowed_roots.length > 0) {
    return workspace.allowed_roots;
  }
  throw new AclDenied('WORKSPACE_ROOTS_UNKNOWN', `no workspace root is registered for ${String(workspaceId)}`);
}

/**
 * A run may only be bound to a sandbox profile whose OS controls are backed by
 * measured S2-002 evidence. constants.mjs owns the proven set; this module
 * reuses it and never widens it. A *_blocked profile and NO_EXEC are
 * contract-valid but execute nothing, so they are BLOCKED_SANDBOX here rather
 * than a degraded unisolated run.
 */
export function assertSandboxExecutable(profileId) {
  if (typeof profileId !== 'string' || profileId.length === 0) {
    throw new BlockedSandbox('BLOCKED_SANDBOX', 'no sandbox profile is bound to this run');
  }
  if (!SANDBOX_PROFILES.some((profile) => profile.profile_id === profileId)) {
    throw new BlockedSandbox('BLOCKED_SANDBOX', `sandbox profile ${profileId} is not a registered S2-002 profile`);
  }
  if (!isExecutableSandboxProfile(profileId)) {
    throw new BlockedSandbox('BLOCKED_SANDBOX', `sandbox profile ${profileId} has no proven OS controls on this host`);
  }
  return true;
}

// --- the host-unisolated floor (issue #45) -----------------------------------

// The shape a named human authorisation must have. It is a document, not a
// flag: an approval with no author, no scope, no window and no digest over its
// own body is indistinguishable from a value somebody typed into a payload, so
// it is refused. Field names are fixed and closed; `additionalProperties` is
// false in spirit because every property below is checked for type and shape
// and anything extra is ignored rather than trusted.
const HOST_UNISOLATED_AUTHORISATION_FIELDS = Object.freeze([
  'authorization_id', 'authorised_by_principal_id', 'authorised_by_label',
  'authority', 'scope', 'profile_id', 'issued_at', 'expires_at', 'body_digest',
]);

const HOST_UNISOLATED_AUTHORISATION_PATTERNS = Object.freeze({
  authorization_id: /^aut-hu-[a-z0-9][a-z0-9-]{0,56}$/,
  authorised_by_principal_id: /^prn-[a-z0-9][a-z0-9-]{0,62}$/,
  // A human label is prose, not a parsed token: the charset is bounded so the
  // field cannot smuggle a value, and wide enough to say who actually signed.
  authorised_by_label: /^[A-Za-z0-9][A-Za-z0-9 ._@:,()'\-]{0,119}$/,
  profile_id: /^sbx-[a-z0-9][a-z0-9-]{0,62}$/,
  issued_at: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
  expires_at: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
  body_digest: /^sha256:[0-9a-f]{64}$/,
});

export const HOST_UNISOLATED_AUTHORISATION_KINDS = Object.freeze(['HUMAN_OWNER']);
export const HOST_UNISOLATED_AUTHORISATION_SCOPES = Object.freeze(['SINGLE_PILOT_RUN']);

/**
 * The digest an authorisation must carry over its own body. It is an
 * integrity control, not a signature: it proves the document the caller holds
 * is the document the server recorded, and it proves nothing about who wrote
 * it. The identity comes from the recorded principal, never from the document.
 */
export function hostUnisolatedAuthorizationDigest(authorization) {
  const { body_digest: ignored, ...body } = isPlainObject(authorization) ? authorization : {};
  // canonicalDigest returns the bare hex; the wire form of every digest on this
  // boundary is `sha256:<hex>` (constants.DIGEST_PATTERN), so the prefix is
  // added here rather than left to each caller to remember.
  return `sha256:${canonicalDigest(body)}`;
}

/**
 * Validate a named human authorisation for unisolated host execution.
 *
 * The authorisation is resolved SERVER-SIDE and handed to execute() as an
 * option; it is never a payload argument, so the confused-deputy rule holds —
 * an adapter, a task, an execution event, a skill or a replayed record cannot
 * supply, widen or renew it. Every check here is fail-closed and typed.
 */
export function assertUnisolatedExecutionAuthorized(authorization, { profileId, now } = {}) {
  if (!isPlainObject(authorization)) {
    throw new BlockedSandbox(
      'BLOCKED_SANDBOX',
      'a run bound to the host-unisolated tier requires a named human authorisation document resolved server-side; none was supplied',
    );
  }
  for (const field of HOST_UNISOLATED_AUTHORISATION_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(authorization, field)) {
      throw new BlockedSandbox('BLOCKED_SANDBOX', `the unisolated-execution authorisation is missing ${field}`);
    }
  }
  for (const [field, pattern] of Object.entries(HOST_UNISOLATED_AUTHORISATION_PATTERNS)) {
    if (typeof authorization[field] !== 'string' || !pattern.test(authorization[field])) {
      throw new BlockedSandbox('BLOCKED_SANDBOX', `the unisolated-execution authorisation field ${field} is malformed`);
    }
  }
  if (!HOST_UNISOLATED_AUTHORISATION_KINDS.includes(authorization.authority)) {
    throw new BlockedSandbox(
      'BLOCKED_SANDBOX',
      `only ${HOST_UNISOLATED_AUTHORISATION_KINDS.join('|')} may authorise unisolated host execution; got ${authorization.authority}`,
    );
  }
  if (!HOST_UNISOLATED_AUTHORISATION_SCOPES.includes(authorization.scope)) {
    throw new BlockedSandbox(
      'BLOCKED_SANDBOX',
      `the unisolated-execution authorisation scope must be one of ${HOST_UNISOLATED_AUTHORISATION_SCOPES.join('|')}; got ${authorization.scope}`,
    );
  }
  if (authorization.profile_id !== profileId) {
    throw new BlockedSandbox(
      'BLOCKED_SANDBOX',
      `the authorisation names profile ${authorization.profile_id} but the run is bound to ${String(profileId)}`,
    );
  }
  if (hostUnisolatedAuthorizationDigest(authorization) !== authorization.body_digest) {
    throw new BlockedSandbox('BLOCKED_SANDBOX', 'the unisolated-execution authorisation digest does not match its own body');
  }
  const issued = Date.parse(authorization.issued_at);
  const expires = Date.parse(authorization.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued) {
    throw new BlockedSandbox('BLOCKED_SANDBOX', 'the unisolated-execution authorisation window is not a real interval');
  }
  // `now` is the injected board clock, never the wall clock: a run must not
  // depend on when the guard happened to be evaluated.
  const instant = toInjectedInstant(now, 'now');
  const at = Date.parse(instant);
  if (at < issued || at > expires) {
    throw new BlockedSandbox(
      'BLOCKED_SANDBOX',
      `the unisolated-execution authorisation is outside its window (${authorization.issued_at}..${authorization.expires_at}, now ${instant})`,
    );
  }
  return Object.freeze({ ...authorization });
}

/**
 * The single gate a LIVE execution passes through.
 *
 * An isolated tier with measured OS controls needs nothing beyond
 * assertSandboxExecutable — this function is not a relaxation for it. The
 * host-unisolated floor is admitted only with a valid named authorisation, and
 * the authorisation is returned to the caller so the run record can quote it
 * verbatim. Every other profile, including the *_blocked and NO_EXEC ones, is
 * refused exactly as before.
 */
export function assertLiveExecutionAuthorized(profileId, { authorization, now } = {}) {
  if (typeof profileId !== 'string' || profileId.length === 0) {
    throw new BlockedSandbox('BLOCKED_SANDBOX', 'no sandbox profile is bound to this run');
  }
  if (!SANDBOX_PROFILES.some((profile) => profile.profile_id === profileId)) {
    throw new BlockedSandbox('BLOCKED_SANDBOX', `sandbox profile ${profileId} is not a registered S2-002 profile`);
  }
  if (isExecutableSandboxProfile(profileId)) {
    if (authorization !== undefined && authorization !== null) {
      // An authorisation for a profile that does not need one is a smell, not
      // a harmless extra: it means somebody believed a permit was required, or
      // that it buys something. Refuse rather than ignore it.
      throw new BlockedSandbox(
        'BLOCKED_SANDBOX',
        `profile ${profileId} has measured OS controls and needs no unisolated-execution authorisation; one was supplied`,
      );
    }
    return Object.freeze({ tier: 'ISOLATED', profile_id: profileId, authorization: null });
  }
  if (isHostUnisolatedSandboxProfile(profileId)) {
    const checked = assertUnisolatedExecutionAuthorized(authorization, { profileId, now });
    return Object.freeze({ tier: 'HOST_UNISOLATED', profile_id: profileId, authorization: checked });
  }
  throw new BlockedSandbox('BLOCKED_SANDBOX', `sandbox profile ${profileId} has no proven OS controls on this host`);
}

/**
 * Digest binding. A digest is an integrity control, never a signature: this
 * proves the caller's document is the one the task still names, and proves
 * nothing about who produced it. Wire form (sha256:<hex>) and stored form
 * (bare hex) both compare equal. A missing or malformed observed digest is
 * MALFORMED_RESULT — a review that cannot name what it reviewed never passes.
 */
export function assertDigestsMatch(task, observed) {
  if (!isPlainObject(task)) {
    throw new MalformedResult('DIGEST_TASK_MISSING', 'no task to bind the digests to');
  }
  // The observed-digests object is a shape like any other. A `{ ... } = {}`
  // parameter default only covers `undefined`, so an explicit `null`, a string
  // or a number would escape as a bare TypeError from the destructuring — an
  // untyped throw across the boundary, which spec rule 5 forbids. An
  // unbindable observation is MALFORMED_RESULT like every other malformed one.
  if (!isPlainObject(observed)) {
    throw new MalformedResult('DIGEST_OBSERVED_MALFORMED', `the observed digests must be an object, got ${observed === null ? 'null' : typeof observed}`);
  }
  const { briefDigest, policyDigest, manifestDigest } = observed;
  for (const [label, expected, actual] of [
    ['brief', task.brief_digest, briefDigest],
    ['policy', task.policy_digest, policyDigest],
    ['manifest', task.manifest_digest, manifestDigest],
  ]) {
    const expectedStored = toStoredDigest(expected);
    const actualStored = toStoredDigest(actual) ?? (typeof actual === 'string' && HEX64_RE.test(actual) ? actual : null);
    if (expectedStored === null) {
      throw new MalformedResult('DIGEST_TASK_MALFORMED', `task ${label} digest is not a valid digest`);
    }
    if (actualStored === null) {
      throw new MalformedResult('DIGEST_OBSERVED_MISSING', `no observed ${label} digest to compare`);
    }
    if (expectedStored !== actualStored) {
      throw new MalformedResult(
        'DIGEST_MISMATCH',
        `${label} digest does not match the task (task ${toWireDigest(expectedStored)} observed ${toWireDigest(actualStored)})`,
      );
    }
  }
  return true;
}

// --- approval ---------------------------------------------------------------

/**
 * The producer may never approve its own work, and a machine actor may never
 * be the gate. A producer that cannot be identified is refused too: an
 * approval whose producer is unknown cannot be shown to be independent.
 */
export function assertNotSelfApproved({ actorKind, producerPrincipalId, gatePrincipalId } = {}) {
  if (typeof actorKind !== 'string' || !ACTOR_KINDS.includes(actorKind)) {
    throw new BlockedPolicy(`ACTOR_KIND_UNKNOWN:${String(actorKind)}`);
  }
  if (NON_APPROVING_ACTOR_KINDS.has(actorKind) || !APPROVAL_ACTOR_KINDS.has(actorKind)) {
    throw new BlockedPolicy('APPROVAL_ACTOR_KIND_FORBIDDEN', `actor kind ${actorKind} may not approve`);
  }
  if (typeof gatePrincipalId !== 'string' || !PRINCIPAL_ID_RE.test(gatePrincipalId)) {
    throw new AuthRequired('AUTH_REQUIRED', 'no server-resolved gate principal on the approval');
  }
  if (typeof producerPrincipalId !== 'string' || !PRINCIPAL_ID_RE.test(producerPrincipalId)) {
    throw new BlockedPolicy('PRODUCER_PRINCIPAL_UNKNOWN', 'the producing principal of this work is not identified');
  }
  if (producerPrincipalId === gatePrincipalId) {
    throw new BlockedPolicy('SELF_APPROVAL', 'the producer may not approve its own work');
  }
  return true;
}

export function assertHumanOnlyApproval(actorKind) {
  if (typeof actorKind !== 'string' || !ACTOR_KINDS.includes(actorKind)) {
    throw new BlockedPolicy(`ACTOR_KIND_UNKNOWN:${String(actorKind)}`);
  }
  if (!APPROVAL_ACTOR_KINDS.has(actorKind)) {
    throw new BlockedPolicy('APPROVAL_ACTOR_KIND_FORBIDDEN', `actor kind ${actorKind} is not an approval gate`);
  }
  return true;
}

// --- budget -----------------------------------------------------------------

const BUDGET_SCOPES = Object.freeze([
  Object.freeze({ name: 'task', limit: ['task_limit', 'max_task_cost'], spent: ['spent_task', 'task_spent', 'task'] }),
  Object.freeze({ name: 'campaign', limit: ['campaign_limit', 'max_campaign_cost'], spent: ['spent_campaign', 'campaign_spent', 'campaign'] }),
  Object.freeze({ name: 'day', limit: ['day_limit', 'max_day_cost'], spent: ['spent_day', 'day_spent', 'day'] }),
]);

/**
 * A budget must be explicitly assigned at every scope before any work may be
 * scheduled. Missing, null, zero, negative, NaN — all BUDGET_EXCEEDED. An
 * unassigned budget is NOT zero and a free model is NOT an authorization.
 * Both the grant row (task_limit/campaign_limit/day_limit) and the task's cost
 * limits (max_task_cost/max_campaign_cost/max_day_cost) are accepted, because
 * the board carries both shapes.
 */
export function assertBudgetAssignable(limits) {
  for (const scope of BUDGET_SCOPES) {
    const value = readBudgetNumber(limits, scope.limit);
    if (value === null || !Number.isFinite(value) || value <= 0) {
      throw new BudgetExceeded('BUDGET_EXCEEDED', `${scope.name} budget is not assigned with a positive limit`);
    }
  }
  return true;
}

/** Remaining headroom per scope. Refuses on an unassigned budget: Infinity is not an answer. */
export function budgetRemaining(limits, spent) {
  assertBudgetAssignable(limits);
  const remaining = {};
  for (const scope of BUDGET_SCOPES) {
    const limit = readBudgetNumber(limits, scope.limit);
    const used = readBudgetNumber(spent, scope.spent) ?? 0;
    if (used < 0) {
      throw new BudgetExceeded('BUDGET_EXCEEDED', `${scope.name} spend is negative`);
    }
    remaining[`${scope.name}_remaining`] = Math.max(0, limit - used);
  }
  return remaining;
}

/** Headroom check for a prospective settle. Never rounds and never widens. */
export function assertWithinBudget(limits, spent, amount) {
  assertBudgetAssignable(limits);
  if (typeof amount !== 'number' || !Number.isFinite(amount) || amount < 0) {
    throw new BudgetExceeded('BUDGET_EXCEEDED', 'a settle amount must be a finite non-negative number');
  }
  for (const scope of BUDGET_SCOPES) {
    const limit = readBudgetNumber(limits, scope.limit);
    const used = readBudgetNumber(spent, scope.spent) ?? 0;
    if (used < 0) {
      throw new BudgetExceeded('BUDGET_EXCEEDED', `${scope.name} spend is negative`);
    }
    if (used + amount > limit) {
      throw new BudgetExceeded(
        'BUDGET_EXCEEDED',
        `${scope.name} budget would be exceeded: ${used + amount} > ${limit}`,
      );
    }
  }
  return true;
}

function readBudgetNumber(source, keys) {
  if (!isPlainObject(source)) return null;
  for (const key of keys) {
    if (Object.hasOwn(source, key) && source[key] !== null && source[key] !== undefined) {
      return typeof source[key] === 'number' ? source[key] : Number.NaN;
    }
  }
  return null;
}

function resolveBudgetLimits(task, ctx) {
  if (isPlainObject(ctx.budgetGrant)) return ctx.budgetGrant;
  if (isPlainObject(task?.cost_limits)) return task.cost_limits;
  return null;
}

// --- shared guard plumbing --------------------------------------------------

function beginGuard(ctx, { guardName, to, capability }) {
  if (!isPlainObject(ctx)) {
    throw new NeedsInput('GUARD_CONTEXT_REQUIRED');
  }
  const task = ctx.task;
  if (!isPlainObject(task) || typeof task.task_id !== 'string' || !TASK_ID_RE.test(task.task_id)) {
    throw new NeedsInput('GUARD_TASK_REQUIRED');
  }
  // A guard is reachable ONLY from an edge constants.mjs binds it to. The
  // check reads that table (it never re-lists the edges), so a guard shared by
  // several edges — guardCancel, guardBlock, guardFail — still refuses any
  // pair the table does not name, and a guard unique to one edge refuses every
  // other source state for free.
  const from = ctx.fromState;
  if (!isKnownState(from) || task.state !== from) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', `${guardName} authorizes only ${from} -> ${to}`);
  }
  if (ctx.toState !== to || TRANSITIONS[from]?.[to] !== guardName) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', `${guardName} authorizes only ${from} -> ${to}`);
  }
  if (typeof ctx.now !== 'string' || !ISO_RE.test(ctx.now) || !Number.isFinite(Date.parse(ctx.now))) {
    throw new NeedsInput(`CLOCK_INVALID:${String(ctx.now)}`);
  }
  if (!Number.isInteger(ctx.expectedRevision) || ctx.expectedRevision < 1) {
    throw new NeedsInput('EXPECTED_REVISION_REQUIRED');
  }
  if (ctx.expectedRevision !== task.revision) {
    throw new RevisionConflict('REVISION_CONFLICT', `expected revision ${ctx.expectedRevision}, task is at ${task.revision}`);
  }
  // An empty string is not a valid reason, but it IS an absent one: let the
  // edge's own requireReason produce its specific refusal instead of a generic
  // input error, so a missing approval reason on the DONE edge reports
  // BLOCKED_POLICY (the reason the approval cannot stand) rather than a
  // retryable NEEDS_INPUT. A wrong TYPE or an over-long string stays a hard
  // input error here.
  if (ctx.reason !== undefined && ctx.reason !== null && ctx.reason !== '') {
    if (typeof ctx.reason !== 'string' || ctx.reason.length > MAX_REASON) {
      throw new NeedsInput('REASON_INVALID');
    }
  }
  // ACL first: nothing is read, decided or written for a principal the task
  // does not name.
  const principalId = assertActor({
    principal: ctx.actor,
    actorKind: ctx.actorKind,
    capability,
    capabilities: ctx.capabilities,
    workspaceId: task.workspace_id,
    resourceId: task.task_id,
    producerPrincipalId: resolveProducerPrincipalId(ctx) ?? ctx.producer_principal_id,
    identityArgs: derivedIdentityArgs(ctx, capability, task),
    verdict: ctx.verdict ?? 'APPROVED',
    now: ctx.now,
    authorizer: ctx.authorizer,
    requireAuthorizer: ctx.requireAuthorizer === true,
  });
  assertTaskVisible(task, principalId);
  return { task, principalId, from, to };
}

function requireReason(ctx, code) {
  if (typeof ctx.reason !== 'string' || ctx.reason.length === 0) {
    throw new BlockedPolicy(code, `${code}: a reason is required for this edge`);
  }
  return true;
}

/**
 * Fence freshness. `required` means "this edge may only be driven by the
 * current lease"; `live` additionally means the lease must still be ACTIVE and
 * unexpired. A release or a post-expiry requeue legitimately carries a lease
 * that is no longer live, so those edges require the fence without requiring
 * liveness. The fence is compared against the TASK's fence, which is what
 * makes a callback from a superseded lease unable to mutate anything.
 */
function assertFenceFresh(task, ctx, { required, live }) {
  const lease = ctx.lease;
  const hasLease = lease !== undefined && lease !== null;
  if (!hasLease) {
    if (required) throw new StaleFence('STALE_FENCE', 'this edge requires the current lease');
    return null;
  }
  if (!isPlainObject(lease)) throw new StaleFence('LEASE_MALFORMED');
  if (typeof lease.lease_id !== 'string' || !LEASE_ID_RE.test(lease.lease_id)) {
    throw new StaleFence('LEASE_MALFORMED', 'lease_id is not a well-formed lease id');
  }
  if (lease.task_id !== undefined && lease.task_id !== task.task_id) {
    throw new StaleFence('LEASE_TASK_MISMATCH', 'the presented lease belongs to another task');
  }
  if (!Number.isInteger(lease.fencing_token) || lease.fencing_token < 1) {
    throw new StaleFence('LEASE_FENCING_TOKEN_INVALID', 'the lease carries no usable fence');
  }
  if (ctx.fencingToken !== undefined && ctx.fencingToken !== null && ctx.fencingToken !== lease.fencing_token) {
    throw new StaleFence('FENCING_TOKEN_MISMATCH', 'the presented fence is not the lease fence');
  }
  if (task.fencing_token !== undefined && task.fencing_token !== null
    && task.fencing_token !== lease.fencing_token) {
    throw new StaleFence('STALE_FENCING_TOKEN', 'the lease fence is not the current task fence');
  }
  if (lease.lease_state !== undefined && lease.lease_state !== 'ACTIVE' && live) {
    throw new StaleFence('LEASE_NOT_ACTIVE', `lease state is ${String(lease.lease_state)}`);
  }
  if (live) {
    if (typeof lease.expires_at !== 'string' || !ISO_RE.test(lease.expires_at)) {
      throw new StaleFence('LEASE_EXPIRY_UNKNOWN', 'the lease carries no usable expiry');
    }
    if (Date.parse(lease.expires_at) <= Date.parse(ctx.now)) {
      throw new StaleFence('LEASE_EXPIRED', 'the lease expired; expire it before acting on it');
    }
  }
  return lease;
}

/** A claim mints a NEW fence, so the fence must be strictly monotonic and no other lease may be active. */
function assertClaimFence(task, ctx) {
  const lease = ctx.lease;
  if (!isPlainObject(lease)) {
    throw new StaleFence('LEASE_REQUIRED', 'a claim must present the lease it creates');
  }
  if (typeof lease.lease_id !== 'string' || !LEASE_ID_RE.test(lease.lease_id)) {
    throw new StaleFence('LEASE_MALFORMED', 'lease_id is not a well-formed lease id');
  }
  if (lease.task_id !== undefined && lease.task_id !== task.task_id) {
    throw new StaleFence('LEASE_TASK_MISMATCH', 'the lease belongs to another task');
  }
  if (!Number.isInteger(lease.fencing_token) || lease.fencing_token < 1) {
    throw new StaleFence('LEASE_FENCING_TOKEN_INVALID', 'a claim must mint a positive fence');
  }
  if (task.active_lease_id !== undefined && task.active_lease_id !== null
    && task.active_lease_id !== lease.lease_id) {
    throw new StaleFence('ACTIVE_LEASE_EXISTS', `task already holds lease ${task.active_lease_id}`);
  }
  if (Number.isInteger(task.fencing_token) && lease.fencing_token <= task.fencing_token) {
    throw new StaleFence('STALE_FENCING_TOKEN', 'a new lease must carry a strictly larger fence');
  }
  if (ctx.fencingToken !== undefined && ctx.fencingToken !== null && ctx.fencingToken !== lease.fencing_token) {
    throw new StaleFence('FENCING_TOKEN_MISMATCH', 'the presented fence is not the lease fence');
  }
  if (typeof lease.expires_at !== 'string' || !ISO_RE.test(lease.expires_at)
    || Date.parse(lease.expires_at) <= Date.parse(ctx.now)) {
    throw new StaleFence('LEASE_EXPIRY_INVALID', 'a claim must present a future expiry');
  }
  return lease;
}

function requireRegisteredAdapter(adapters, adapterId) {
  if (typeof adapterId !== 'string' || adapterId.length === 0) {
    throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', 'no adapter is bound to this task');
  }
  if (!Array.isArray(adapters) || adapters.length === 0) {
    throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', 'no adapter registration was supplied');
  }
  const adapter = adapters.find((entry) => isPlainObject(entry) && entry.adapter_id === adapterId);
  if (!adapter) {
    throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', `adapter ${adapterId} is not registered`);
  }
  if (adapter.health !== 'healthy') {
    throw new AgentUnavailable('ADAPTER_NOT_HEALTHY', `adapter ${adapterId} is ${String(adapter.health)}`);
  }
  return adapter;
}

/** The executor must still be able to do the work, and only that work. */
function assertAdapterCoversTask(task, ctx) {
  // The task row is authoritative about which executor owns the work; the
  // actor's adapter_id is a fallback for the claim itself, where the task has
  // not been re-bound yet.
  const adapterId = task.assigned_adapter_id ?? ctx.actor?.adapter_id;
  const adapter = requireRegisteredAdapter(ctx.adapters, adapterId);
  assertCapabilitySubset(task.required_capabilities, adapter.declared_capabilities);
  assertToolSubset(task.allowed_tools, adapter.declared_tools);
  // The live-execution gate, not the bare proven-set check: an isolated tier
  // needs nothing beyond the proven set, and the HOST_UNISOLATED floor needs
  // the named human authorisation the boundary resolved server-side. Every
  // other profile is refused exactly as before (issue #45).
  assertLiveExecutionAuthorized(ctx.sandboxProfileId ?? adapter.sandbox_profile_id, {
    authorization: ctx.unisolatedExecutionAuthorization ?? null,
    now: ctx.now ?? null,
  });
  assertWorkspaceWithin(task.workspace_ref, resolveWorkspaceRoots(task, ctx), { realpath: ctx.realpath });
  if (ctx.requestScopes !== undefined || ctx.grantedScopes !== undefined) {
    assertScopeSubset(ctx.requestScopes ?? [], ctx.grantedScopes ?? []);
  }
  return adapter;
}

/** Bind the digests the caller actually observed to the task. Nothing observed = the task's own bound digests. */
function bindDigests(task, ctx) {
  const observed = isPlainObject(ctx.digests) ? ctx.digests : isPlainObject(ctx.canonicalArgs) ? ctx.canonicalArgs : {};
  return {
    briefDigest: observed.brief_digest ?? observed.briefDigest ?? task.brief_digest,
    policyDigest: observed.policy_digest ?? observed.policyDigest ?? task.policy_digest,
    manifestDigest: observed.manifest_digest ?? observed.manifestDigest ?? task.manifest_digest,
  };
}

function assertBudgetForEdge(task, ctx) {
  assertBudgetAssignable(resolveBudgetLimits(task, ctx));
  assertWithinBudget(resolveBudgetLimits(task, ctx), ctx.budgetSpent ?? {}, 0);
  return true;
}

/** An undetermined external effect is never a retry and never a review or a DONE. */
function assertNoUndeterminedEffect(ctx) {
  const reconciliation = ctx.reconciliation;
  if (isPlainObject(reconciliation) && reconciliation.resolution === 'EFFECT_UNDETERMINED') {
    throw new ReconciliationRequired(
      'RECONCILIATION_REQUIRED',
      'the external effect of this run is undetermined; only an authorized decision may close it',
    );
  }
  return true;
}

/**
 * Reconciliation decisions are recorded, never guessed. A release or a requeue
 * may only follow a decision by an authenticated human or an explicitly
 * authorized deterministic gate, never by the producer, and EFFECT_UNDETERMINED
 * is never a close.
 */
function assertReconciled(ctx, principalId) {
  const reconciliation = ctx.reconciliation;
  if (!isPlainObject(reconciliation)) {
    throw new ReconciliationRequired('RECONCILIATION_REQUIRED', 'no reconciliation decision accompanies this edge');
  }
  if (reconciliation.resolution === 'EFFECT_UNDETERMINED') {
    throw new ReconciliationRequired('RECONCILIATION_REQUIRED', 'an undetermined effect is not a decision');
  }
  if (!['OBSERVED_NO_EFFECT', 'OBSERVED_EFFECT_COMPLETED', 'OBSERVED_EFFECT_UNDONE']
    .includes(reconciliation.resolution)) {
    throw new ReconciliationRequired('RECONCILIATION_REQUIRED', `unknown resolution ${String(reconciliation.resolution)}`);
  }
  assertHumanOnlyApproval(reconciliation.decided_by_kind);
  if (typeof reconciliation.decided_by !== 'string' || !PRINCIPAL_ID_RE.test(reconciliation.decided_by)) {
    throw new AuthRequired('AUTH_REQUIRED', 'the reconciliation decision has no server-resolved principal');
  }
  if (reconciliation.decided_by === principalId) {
    throw new BlockedPolicy('SELF_RECONCILIATION', 'the actor of this transition may not decide its own reconciliation');
  }
  const producer = resolveProducerPrincipalId(ctx);
  if (producer !== null && reconciliation.decided_by === producer) {
    throw new BlockedPolicy('SELF_RECONCILIATION', 'the producer may not decide the reconciliation of its own run');
  }
  return true;
}

/** The principal that produced the work: explicit, else the lease holder, else the adapter's principal. */
function resolveProducerPrincipalId(ctx) {
  const explicit = ctx.producer_principal_id ?? ctx.canonicalArgs?.producer_principal_id;
  if (typeof explicit === 'string' && PRINCIPAL_ID_RE.test(explicit)) return explicit;
  const leasePrincipal = isPlainObject(ctx.lease) ? ctx.lease.principal_id : null;
  if (typeof leasePrincipal === 'string' && PRINCIPAL_ID_RE.test(leasePrincipal)) return leasePrincipal;
  const adapterId = ctx.task?.assigned_adapter_id;
  if (Array.isArray(ctx.adapters) && typeof adapterId === 'string') {
    const adapter = ctx.adapters.find((entry) => isPlainObject(entry) && entry.adapter_id === adapterId);
    if (adapter && typeof adapter.principal_id === 'string' && PRINCIPAL_ID_RE.test(adapter.principal_id)) {
      return adapter.principal_id;
    }
  }
  return null;
}

// --- the eleven transition guards -------------------------------------------

/** BACKLOG -> READY: the immutable brief validated, dependencies closed, budget assigned. */
export function guardBacklogToReady(ctx) {
  const { task } = beginGuard(ctx, {
    guardName: 'guardBacklogToReady', to: 'READY', capability: 'board.task.transition',
  });
  if (ctx.briefValidated !== true) {
    throw new BlockedPolicy('BRIEF_NOT_VALIDATED', 'a validated immutable TaskBrief is required before READY');
  }
  if (ctx.dependenciesSatisfied !== true) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', 'dependencies are not DONE');
  }
  assertBudgetForEdge(task, ctx);
  assertDigestsMatch(task, bindDigests(task, ctx));
  assertNoUndeterminedEffect(ctx);
}

/** READY -> CLAIMED: one healthy, capable, sandboxed executor and a fresh monotonic fence. */
export function guardReadyToClaimed(ctx) {
  const { task } = beginGuard(ctx, {
    guardName: 'guardReadyToClaimed', to: 'CLAIMED', capability: 'board.task.claim',
  });
  if (ctx.dependenciesSatisfied !== true) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', 'dependencies are not DONE');
  }
  if (Number.isInteger(ctx.activeLeaseCount) && ctx.activeLeaseCount >= MAX_CONCURRENT_TASKS) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', 'the board runs at most one active task');
  }
  assertClaimFence(task, ctx);
  assertAdapterCoversTask(task, ctx);
  assertBudgetForEdge(task, ctx);
  assertDigestsMatch(task, bindDigests(task, ctx));
  assertNoUndeterminedEffect(ctx);
}

/** CLAIMED -> RUNNING: the live, unfenced-out right to execute this exact brief. */
export function guardClaimedToRunning(ctx) {
  const { task } = beginGuard(ctx, {
    guardName: 'guardClaimedToRunning', to: 'RUNNING', capability: 'board.execution.start',
  });
  assertFenceFresh(task, ctx, { required: true, live: true });
  assertAdapterCoversTask(task, ctx);
  assertBudgetForEdge(task, ctx);
  assertDigestsMatch(task, bindDigests(task, ctx));
  assertNoUndeterminedEffect(ctx);
}

/** RUNNING -> IN_REVIEW: a live callback on the current fence, with the run's side effects accounted for. */
export function guardRunningToInReview(ctx) {
  const { task } = beginGuard(ctx, {
    guardName: 'guardRunningToInReview', to: 'IN_REVIEW', capability: 'board.evidence.submit',
  });
  assertFenceFresh(task, ctx, { required: true, live: true });
  assertAdapterCoversTask(task, ctx);
  assertBudgetForEdge(task, ctx);
  assertDigestsMatch(task, bindDigests(task, ctx));
  assertNoUndeterminedEffect(ctx);
}

/**
 * IN_REVIEW -> DONE. The only edge into DONE, and therefore the whole
 * independent-approval guarantee: the gate must be a human or an explicitly
 * authorized deterministic gate, it must not be the producer, and the digests
 * it reviewed must be the task's own. An uncalibrated semantic verifier
 * arrives as actor_kind 'adapter' or 'system' and is refused here.
 */
export function guardInReviewToDone(ctx) {
  const { task, principalId } = beginGuard(ctx, {
    guardName: 'guardInReviewToDone', to: 'DONE', capability: 'board.review.approve',
  });
  requireReason(ctx, 'APPROVAL_REASON_REQUIRED');
  assertHumanOnlyApproval(ctx.actorKind);
  const producerPrincipalId = resolveProducerPrincipalId(ctx);
  if (producerPrincipalId === null) {
    throw new BlockedPolicy(
      'PRODUCER_PRINCIPAL_UNKNOWN',
      'the producing principal must be identifiable (lease.principal_id, adapter principal_id or producer_principal_id) before DONE',
    );
  }
  assertNotSelfApproved({ actorKind: ctx.actorKind, producerPrincipalId, gatePrincipalId: principalId });
  assertFenceFresh(task, ctx, { required: false, live: false });
  // A review that cannot name the document it reviewed is not a review.
  const observed = isPlainObject(ctx.digests) ? ctx.digests : isPlainObject(ctx.canonicalArgs) ? ctx.canonicalArgs : null;
  if (!observed || observed.brief_digest === undefined && observed.briefDigest === undefined) {
    throw new MalformedResult('DIGEST_OBSERVED_MISSING', 'the review must name the digests it approved');
  }
  assertDigestsMatch(task, {
    briefDigest: observed.brief_digest ?? observed.briefDigest,
    policyDigest: observed.policy_digest ?? observed.policyDigest,
    manifestDigest: observed.manifest_digest ?? observed.manifestDigest,
  });
  assertBudgetForEdge(task, ctx);
  assertNoUndeterminedEffect(ctx);
}

/** CLAIMED -> READY: release. Always after an authorized reconciliation decision, never as a blind retry. */
export function guardRelease(ctx) {
  const { task, principalId } = beginGuard(ctx, {
    guardName: 'guardRelease', to: 'READY', capability: 'board.task.release',
  });
  requireReason(ctx, 'RELEASE_REASON_REQUIRED');
  assertFenceFresh(task, ctx, { required: true, live: false });
  assertReconciled(ctx, principalId);
  assertBudgetForEdge(task, ctx);
}

/** RUNNING|IN_REVIEW|FAILED -> READY: an explicit requeue behind a recorded decision. */
export function guardRequeueAfterReconciliation(ctx) {
  const { task, principalId } = beginGuard(ctx, {
    guardName: 'guardRequeueAfterReconciliation', to: 'READY', capability: 'board.reconciliation.decide',
  });
  requireReason(ctx, 'REQUEUE_REASON_REQUIRED');
  assertFenceFresh(task, ctx, { required: true, live: false });
  assertReconciled(ctx, principalId);
  assertBudgetForEdge(task, ctx);
}

/** * -> BLOCKED: an agent or a human may stop work, but only with a recorded reason. */
export function guardBlock(ctx) {
  const { task } = beginGuard(ctx, {
    guardName: 'guardBlock', to: 'BLOCKED', capability: 'board.task.transition',
  });
  requireReason(ctx, 'BLOCK_REASON_REQUIRED');
  assertFenceFresh(task, ctx, { required: false, live: false });
  assertNoUndeterminedEffect(ctx);
}

/** RUNNING|IN_REVIEW -> FAILED: a known failure, never dressed up as a semantic verdict. */
export function guardFail(ctx) {
  const { task } = beginGuard(ctx, {
    guardName: 'guardFail', to: 'FAILED', capability: 'board.task.transition',
  });
  requireReason(ctx, 'FAIL_REASON_REQUIRED');
  // A machine actor may only fail a task on the current fence; a human may
  // always fail it, but a stale callback may never touch the task at all.
  assertFenceFresh(task, ctx, {
    required: ctx.actorKind === 'adapter' || ctx.actorKind === 'scheduler',
    live: ctx.actorKind === 'adapter' || ctx.actorKind === 'scheduler',
  });
  assertBudgetForEdge(task, ctx);
}

/** * -> CANCELLED: always available to an authenticated caller, never to a stale fence. */
export function guardCancel(ctx) {
  const { task } = beginGuard(ctx, {
    guardName: 'guardCancel', to: 'CANCELLED', capability: 'board.execution.cancel',
  });
  requireReason(ctx, 'CANCEL_REASON_REQUIRED');
  assertFenceFresh(task, ctx, { required: false, live: false });
  assertNoUndeterminedEffect(ctx);
}

/** BLOCKED -> READY: the block is resolved, the brief still validates, the budget is still assigned. */
export function guardUnblock(ctx) {
  const { task } = beginGuard(ctx, {
    guardName: 'guardUnblock', to: 'READY', capability: 'board.task.transition',
  });
  requireReason(ctx, 'UNBLOCK_REASON_REQUIRED');
  if (ctx.briefValidated !== true) {
    throw new BlockedPolicy('BRIEF_NOT_VALIDATED', 'a validated immutable TaskBrief is required before READY');
  }
  if (ctx.dependenciesSatisfied !== true) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', 'dependencies are not DONE');
  }
  assertFenceFresh(task, ctx, { required: false, live: false });
  assertBudgetForEdge(task, ctx);
  assertDigestsMatch(task, bindDigests(task, ctx));
  assertNoUndeterminedEffect(ctx);
}

const GUARDS = Object.freeze({
  guardBacklogToReady,
  guardReadyToClaimed,
  guardClaimedToRunning,
  guardRunningToInReview,
  guardInReviewToDone,
  guardRelease,
  guardRequeueAfterReconciliation,
  guardBlock,
  guardFail,
  guardCancel,
  guardUnblock,
});

// --- canonical command arguments -------------------------------------------

// Payload fields that name the authority itself. A request may carry them only
// to repeat what the server resolved; disagreement is a refusal in
// commands.mjs (AUTH_REQUIRED) and here (BLOCKED_POLICY). Neither ever widens.
const AUTHORITY_ARGUMENTS = Object.freeze([
  'actor', 'actor_kind', 'allowed_tools', 'approval', 'approved', 'budget', 'budget_grant',
  'capabilities', 'fencing_token', 'granted_scope', 'lease_id', 'principal_id', 'role',
]);

// Argument names that must hold a well-formed id of the family their prefix
// implies, so a target can never smuggle a path or a foreign id.
const TARGET_ID_FAMILIES = Object.freeze(
  Object.entries(ID_PREFIXES).map(([family, prefix]) => Object.freeze({
    family,
    pattern: new RegExp(`^${prefix}[a-z0-9][a-z0-9-]{0,62}$`),
  })),
);
const ID_ARGUMENTS_EXEMPT = new Set(['idempotency_key', 'args_digest', 'workspace_id', 'producer_principal_id']);

function targetFamilyFor(key) {
  if (!key.endsWith('_id') || ID_ARGUMENTS_EXEMPT.has(key)) return null;
  const base = key.slice(0, -3);
  return TARGET_ID_FAMILIES.find((entry) => entry.family === base) ?? null;
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

/**
 * Canonical argument validation for the command boundary.
 *
 * The list of commands and their canonical argument sets belongs to
 * commands.mjs (COMMANDS), so this module does not re-declare it: pass
 * `allowedKeys` and the per-command allowlist is enforced exactly, otherwise
 * the generic name/shape rules below apply. Either way three things always
 * hold:
 *   * no unknown argument can be smuggled in (an allowlist when supplied, a
 *     closed snake_case name + id-family shape check otherwise);
 *   * an argument that names the target resource must EQUAL the resource the
 *     server authorized (`authorized`) — the confused-deputy check, where
 *     policy authorizes task A while the payload mutates task B;
 *   * an authority-shaped field may only repeat the server-resolved value.
 */
export function assertCanonicalArguments(command, args, { authorized, allowedKeys } = {}) {
  if (typeof command !== 'string' || !COMMAND_RE.test(command)) {
    throw new BlockedPolicy(`COMMAND_UNKNOWN:${String(command)}`);
  }
  if (!isPlainObject(args)) {
    throw new BlockedPolicy('ARGUMENTS_MISSING', 'command arguments must be a plain object');
  }
  const allow = allowedKeys === undefined ? null : allowedKeys;
  if (allow !== null && !isStringArray(allow)) {
    throw new BlockedPolicy('ALLOWED_KEYS_INVALID');
  }
  for (const key of Object.keys(args)) {
    if (RESERVED_ARGUMENT_KEYS.has(key)) {
      throw new BlockedPolicy('ARGUMENT_NOT_CANONICAL', `argument ${key} is not a canonical argument`);
    }
    if (!ARGUMENT_NAME_RE.test(key)) {
      throw new BlockedPolicy('ARGUMENT_NOT_CANONICAL', `argument ${key} is not a canonical argument name`);
    }
    if (allow !== null && !allow.includes(key)) {
      throw new BlockedPolicy('ARGUMENT_NOT_CANONICAL', `argument ${key} is not canonical for ${command}`);
    }
    const family = targetFamilyFor(key);
    if (family && (typeof args[key] !== 'string' || !family.pattern.test(args[key]))) {
      throw new BlockedPolicy('ARGUMENT_TARGET_MALFORMED', `argument ${key} is not a well-formed ${family.family} id`);
    }
    if (key === 'idempotency_key' && (typeof args[key] !== 'string' || !HEX64_RE.test(args[key]))) {
      throw new BlockedPolicy('IDEMPOTENCY_KEY_INVALID', 'idempotency_key must be 64 lowercase hex characters');
    }
    if (key === 'fencing_token' && args[key] !== null
      && (!Number.isInteger(args[key]) || args[key] < 0)) {
      throw new BlockedPolicy('ARGUMENT_TARGET_MALFORMED', 'fencing_token must be a non-negative integer or null');
    }
  }
  if (authorized !== undefined) {
    if (!isPlainObject(authorized)) {
      throw new BlockedPolicy('AUTHORIZED_TARGET_INVALID');
    }
    for (const [key, expected] of Object.entries(authorized)) {
      if (expected === undefined || expected === null) continue;
      if (!Object.hasOwn(args, key) || args[key] === undefined) {
        // A command acting on a resource must name it; omitting the authorized
        // target would let the store act on something the caller never said.
        if (targetFamilyFor(key)) {
          throw new BlockedPolicy('ARGUMENT_TARGET_MISSING', `argument ${key} is required by ${command}`);
        }
        continue;
      }
      if (!sameValue(args[key], expected)) {
        throw new BlockedPolicy(
          'ARGUMENT_TARGET_MISMATCH',
          `argument ${key} does not name the authorized resource of ${command}`,
        );
      }
    }
  }
  // An authority-shaped argument may only repeat a value the server resolved.
  // Even when the caller passes no authorized map, the value must be a scalar
  // or a list of scalars: a nested object in `allowed_tools`, `budget_grant` or
  // `capabilities` is a smuggling shape, never a canonical argument.
  for (const key of AUTHORITY_ARGUMENTS) {
    if (!Object.hasOwn(args, key)) continue;
    const value = args[key];
    if (value === null) continue;
    if (Array.isArray(value)) {
      if (!value.every((item) => item === null || typeof item !== 'object')) {
        throw new BlockedPolicy('ARGUMENT_NOT_CANONICAL', `argument ${key} carries a nested authority structure`);
      }
      continue;
    }
    if (typeof value === 'object') {
      throw new BlockedPolicy('ARGUMENT_NOT_CANONICAL', `argument ${key} carries a nested authority structure`);
    }
    if (value === undefined) {
      throw new BlockedPolicy('ARGUMENT_NOT_CANONICAL', `argument ${key} carries no value`);
    }
  }
  return true;
}

// --- the single transition decision -----------------------------------------

/**
 * The only way to run a guard. The edge list is read from constants.mjs
 * TRANSITIONS, so a second, hand-written edge list cannot exist: an unknown
 * from/to pair is TRANSITION_NOT_ALLOWED, a state that is not one of the nine
 * is TRANSITION_NOT_ALLOWED, and a table entry whose guard is not one of the
 * eleven exported guards fails closed instead of running anything.
 * `fromState` is taken from the TASK ROW, never from the caller's claim: a
 * caller that disagrees about where the task is cannot move it.
 */
export function decideTransition({ task, toState, context } = {}) {
  if (!isPlainObject(task) || !isKnownState(task.state)) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', 'the task row is not in a known state');
  }
  if (!isKnownState(toState)) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', `unknown target state ${String(toState)}`);
  }
  const fromState = task.state;
  if (!BOARD_STATES.includes(fromState)) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', `unknown source state ${String(fromState)}`);
  }
  const table = TRANSITIONS[fromState] ?? {};
  const guardName = Object.prototype.hasOwnProperty.call(table, toState) ? table[toState] : null;
  if (!guardName) {
    throw new TransitionNotAllowed('TRANSITION_NOT_ALLOWED', `no edge ${fromState} -> ${toState}`);
  }
  const guard = GUARDS[guardName];
  if (typeof guard !== 'function') {
    throw new BlockedPolicy('GUARD_MISSING', `${guardName} is not an exported guard`);
  }
  if (isPlainObject(context) && context.fromState !== undefined && context.fromState !== fromState) {
    throw new BlockedPolicy('FROM_STATE_MISMATCH', `context says ${String(context.fromState)}, task row says ${fromState}`);
  }
  if (isPlainObject(context) && context.toState !== undefined && context.toState !== toState) {
    throw new BlockedPolicy('TO_STATE_MISMATCH', `context says ${String(context.toState)}, target is ${toState}`);
  }
  const guardContext = { ...(isPlainObject(context) ? context : {}), task, fromState, toState };
  guard(guardContext);
  return true;
}
