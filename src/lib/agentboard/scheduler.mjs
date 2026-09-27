// S2-007 Agent Board scheduler — deterministic selection, contract-valid
// DispatchDecision construction, and the recovery-safe outbox driver.
//
// WHY this module exists
// ----------------------
// The board must answer three questions without guessing: "which task may run
// now, on which registered adapter, and why was everything else refused?"
// `dispatch-decision.schema.json` exists precisely so that the answer is a
// replayable document instead of a log line. Everything in this file exists to
// make that document truthful:
//
//   * selection is a total order over facts, never over chance — priority
//     (HIGH < MEDIUM < LOW via the frozen PRIORITY_RANK) then stable
//     task_id / adapter_id ascending. No Math.random, no Date.now, no
//     insertion-order dependence. Two schedulers that read the same snapshot
//     MUST produce the same decision_id inputs, the same candidate order and
//     the same selection;
//   * EVERY ineligible candidate is recorded with its exclusion reason from
//     the closed enum in the schema. An unrecorded exclusion is an
//     unauditable decision, and a decision that cannot be audited is not a
//     decision — it is a preference;
//   * the bounded profile runs at most ONE active task
//     (MAX_CONCURRENT_TASKS === 1). If an active lease exists the tick is a
//     NO-OP that still records CONCURRENCY_LIMIT_REACHED, because "we did
//     nothing" is itself a decision a reader must be able to see;
//   * a more privileged agent is never substituted. An adapter whose declared
//     capabilities/tools do not cover the task, or whose sandbox is not
//     provable, is EXCLUDED — never quietly swapped for a stronger one, and
//     a task with `assigned_adapter_id` set is dispatched to exactly that
//     adapter or to nobody;
//   * an unassigned budget is NOT zero and a free model is NOT an
//     authorization (BUDGET_NOT_ASSIGNED / BudgetExceeded);
//   * an unprovable isolation profile is NOT "run it anyway"
//     (SANDBOX_NOT_PROVEN / BlockedSandbox).
//
// Outbox dispatch semantics (the part that bites hardest)
// -------------------------------------------------------
// The external effect (telling an executor to start) is not transactional with
// our database, so the send is guarded by an INTENT record:
//
//   crash BEFORE the intent record  -> the row is still PENDING  -> re-sendable
//   crash AFTER  the intent record  -> the row is SENT, no ack   -> ESCALATE to
//                                      RECONCILIATION_REQUIRED, NEVER re-send
//   ack recorded                    -> nothing left to do
//
// The middle case is unknowable on purpose: "SENT with no ack" may mean the
// executor started the work and the acknowledgement was lost. A blind re-send
// there would be a DUPLICATE EXTERNAL EFFECT, which is a hard-gate violation,
// so `recoverOutbox` reconstructs canonical state and reissues nothing.
// This is why `driveOutbox` marks SENT *before* it calls the transport rather
// than after: marking afterwards would make a crash between "send" and
// "mark SENT" look like a fresh PENDING row and silently duplicate the effect.
//
// Determinism
// -----------
// The clock and the id factory are injected (`now`: Date | ISO string |
// { now() }; `ids`: a factory yielding contract-shaped ids). This module never
// reads the process clock and never generates an id from entropy. Where the
// id shape is a contract requirement (`dsc-`, `xer-`, `eve-`), a factory that
// returns anything else is refused instead of being silently rewritten — a
// rewritten id would be a second, invisible source of identity.
//
// What is deliberately NOT here
// -----------------------------
// No state list, no transition edge, no error code, no payload shape and no
// idempotency-key convention is re-declared. States/edges/reasons of authority
// come from `constants.mjs`, every wire shape from `contracts/*.schema.json`
// via `contracts.mjs`, every refusal from `errors.mjs`, every authorization
// decision (capability, tool, scope, workspace, sandbox, budget) from
// `policy.mjs` and every digest from the S2-006 `canonical-json.mjs`. The
// exclusion-reason strings below are the one place where this file names schema
// enum members, and an import-time probe validates every one of them against
// the frozen contract, so a schema change fails loudly here instead of
// producing a contract-invalid decision later.
import {
  BOARD_STATES,
  BOARD_CAPABILITIES,
  EXECUTION_SCOPES,
  ID_PREFIXES,
  MAX_CONCURRENT_TASKS,
  PRIORITY_RANK,
  PROVEN_SANDBOX_PROFILE_IDS,
  SCHEDULER_VERSION as SCHEDULER_VERSION_SOURCE,
  DIGEST_PATTERN,
  isExecutableSandboxProfile,
} from './constants.mjs';
import {
  assertBoardContract,
  assertDigestAgreement,
  assertExecutionVersion,
  boardContractErrors,
  isBoardContractValid,
} from './contracts.mjs';
import {
  AclDenied,
  AgentUnavailable,
  AuthRequired,
  BlockedPolicy,
  BlockedSandbox,
  BudgetExceeded,
  MalformedResult,
  NeedsInput,
  ReconciliationRequired,
  isBoardError,
  toBoardError,
} from './errors.mjs';
import { SANDBOX_LOCAL_RESTRICTED_PODMAN, SANDBOX_UNTRUSTED_CODE_GVISOR } from '../identity/sandbox-profiles.mjs';
import { isHostUnisolatedSandboxProfile } from './constants.mjs';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import * as policy from './policy.mjs';
import { toInjectedInstant, dayKeyOf, ISO_INSTANT } from './clock.mjs';

// Re-exported from constants.mjs, never re-declared here (issue §"one
// authoritative contract").
export const SCHEDULER_VERSION = SCHEDULER_VERSION_SOURCE;

// --- closed enum references (validated against the frozen schema) -----------

// These strings are the only schema members this module names. They are NOT a
// second definition of the enum: `assertExclusionEnumMatchesContract` builds a
// minimal DispatchDecision for each one and asks the frozen contract whether it
// accepts it. If a reason is ever renamed or removed in
// contracts/dispatch-decision.schema.json, importing this module fails closed
// instead of emitting a decision the contract would reject.
const EXCLUSION_REASONS = Object.freeze({
  STATE_NOT_READY: 'STATE_NOT_READY',
  DEPENDENCIES_OPEN: 'DEPENDENCIES_OPEN',
  BRIEF_NOT_VALIDATED: 'BRIEF_NOT_VALIDATED',
  CAPABILITY_MISMATCH: 'CAPABILITY_MISMATCH',
  NO_HEALTHY_ADAPTER: 'NO_HEALTHY_ADAPTER',
  BUDGET_NOT_ASSIGNED: 'BUDGET_NOT_ASSIGNED',
  BUDGET_EXHAUSTED: 'BUDGET_EXHAUSTED',
  SANDBOX_NOT_PROVEN: 'SANDBOX_NOT_PROVEN',
  CONCURRENCY_LIMIT_REACHED: 'CONCURRENCY_LIMIT_REACHED',
  ACTIVE_LEASE_EXISTS: 'ACTIVE_LEASE_EXISTS',
  ACL_DENIED: 'ACL_DENIED',
  STALE_FENCE: 'STALE_FENCE',
});

const MAX_DECISION_ENTRIES = 256;   // dispatch-decision maxItems for candidates/excluded
const MAX_EXCLUSION_REASONS = 8;    // dispatch-decision maxItems per exclusion list
const MAX_OUTBOX_BATCH = 64;        // bounded work per driver call
const MAX_CANDIDATE_TASKS = 256;    // bounded read per plan
const MAX_STORE_TASK_READ = 200;    // the store refuses a listTasks limit above 200

const PRINCIPAL_ID = /^prn-[a-z0-9][a-z0-9-]{0,62}$/;
const HEX64 = /^[0-9a-f]{64}$/;

// A fixed instant is used ONLY to build the enum-conformance probe below. It
// is a constant, not a clock read: nothing in this module ever derives a
// timestamp from the host.
const ENUM_PROBE_DECISION = Object.freeze({
  contractVersion: '1.0.0',
  decision_id: 'dsc-s2-007-enum-probe',
  workspace_id: 'ws-s2-007-enum-probe',
  max_concurrency: MAX_CONCURRENT_TASKS,
  selected_task_id: null,
  selected_adapter_id: null,
  selected_lease_id: null,
  selected_fencing_token: null,
  candidates: [],
  excluded: [],
  reason: 'exclusion reason enum conformance probe',
  budget_snapshot: {
    currency: 'USD',
    task_remaining: 0,
    campaign_remaining: 0,
    day_remaining: 0,
    assigned: false,
  },
  decided_at: '2000-01-01T00:00:00.000Z',
});

function assertExclusionEnumMatchesContract() {
  for (const code of Object.values(EXCLUSION_REASONS)) {
    const probe = {
      ...ENUM_PROBE_DECISION,
      excluded: [{ subject_kind: 'task', subject_id: 'abt-s2-007-probe', reasons: [code] }],
    };
    if (!isBoardContractValid('dispatch-decision', probe)) {
      throw new NeedsInput(
        `DISPATCH_EXCLUSION_REASON_NOT_IN_CONTRACT:${code}:${boardContractErrors('dispatch-decision', probe).join('; ')}`,
      );
    }
  }
}
assertExclusionEnumMatchesContract();

// --- small deterministic helpers -------------------------------------------

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isPositiveNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) && value > 0;
}

function asFiniteNumber(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  return null;
}

function clampZero(value) {
  const numeric = asFiniteNumber(value);
  return numeric === null || numeric < 0 ? 0 : numeric;
}

function dedupeReasons(reasons) {
  const seen = new Set();
  const out = [];
  for (const reason of reasons) {
    if (!seen.has(reason)) {
      seen.add(reason);
      out.push(reason);
    }
  }
  return out.slice(0, MAX_EXCLUSION_REASONS);
}

/**
 * The injected clock. Accepts a Date, a fixed ISO instant, a zero-arg clock
 * function or a `{ now() }` object and always returns the contract-shaped
 * `YYYY-MM-DDTHH:MM:SS.sssZ` string. A missing or unparseable clock is a
 * refusal, never a fallback to the host clock.
 */
// The injected-clock reader now lives in clock.mjs and is re-exported here, so
// every existing importer of scheduler.toInjectedInstant keeps working while
// policy.mjs can use it without importing this module back.
export { toInjectedInstant, dayKeyOf, ISO_INSTANT, CLOCK_VERSION } from './clock.mjs';



/**
 * Resolve the injected id factory for a contract prefix. The factory may be a
 * function or an object exposing `next`/`id`/<kind>. Whatever it returns MUST
 * already carry the contract prefix (`dsc-`, `xer-`, `eve-`, `run-`): this
 * module refuses a malformed id rather than rewriting it, because a silently
 * repaired id is a second, invisible source of identity.
 */
function resolveId(ids, kind, hint = 0) {
  if (ids === null || ids === undefined) {
    throw new NeedsInput(`ID_FACTORY_MISSING:${kind}`);
  }
  let produced = null;
  if (typeof ids === 'function') produced = ids(kind, hint);
  else if (isPlainObject(ids)) {
    if (typeof ids[kind] === 'function') produced = ids[kind](hint);
    else if (typeof ids.next === 'function') produced = ids.next(kind, hint);
    else if (typeof ids.id === 'function') produced = ids.id(kind, hint);
  }
  if (typeof produced !== 'string' || produced.length === 0) {
    throw new NeedsInput(`ID_FACTORY_INVALID:${kind}:${String(produced)}`);
  }
  const prefix = ID_PREFIXES[kind];
  if (prefix && !produced.startsWith(prefix)) {
    throw new NeedsInput(`ID_FACTORY_PREFIX_MISMATCH:${kind}:expected ${prefix}:got ${produced}`);
  }
  return produced;
}

function policyFunction(name) {
  const fn = policy?.[name];
  if (typeof fn !== 'function') throw new NeedsInput(`POLICY_BOUNDARY_INCOMPLETE:${name}`);
  return fn;
}

/**
 * Subset questions are asked through the S2-002-derived policy authorizer, not
 * through a local set comparison: a second implementation of "does the grant
 * cover the requirement" is exactly the weakened copy of the authorizer that
 * the boundary contract forbids. A CAPABILITY_MISMATCH refusal is data here (it
 * becomes an exclusion reason); any other failure is propagated as a typed
 * error instead of being flattened into "excluded".
 */
function coversViaAuthorizer(assertName, required, granted) {
  const assertFn = policyFunction(assertName);
  try {
    assertFn(required, granted);
    return true;
  } catch (error) {
    if (isBoardError(error) && error.code === 'CAPABILITY_MISMATCH') return false;
    throw toBoardError(error, 'CAPABILITY_MISMATCH');
  }
}

/**
 * Board capability -> execution scope. Reported as a shim: the frozen surface
 * declares both closed sets (`BOARD_CAPABILITIES`, `EXECUTION_SCOPES`) but no
 * mapping between them, and the ExecutionRequest requires a non-empty
 * server-resolved `granted_scope`. When the caller supplies an explicit
 * server-resolved `granted_scope` that value wins; this table is only the
 * default derivation, and the result is still validated as a subset of
 * EXECUTION_SCOPES by the policy authorizer.
 */
const BOARD_CAPABILITY_TO_EXECUTION_SCOPE = Object.freeze({
  'board.task.read': 'task.read',
  'board.task.transition': 'task.write',
  'board.result.collect': 'artifact.write',
  'board.evidence.submit': 'evidence.submit',
  'board.execution.start': 'checkpoint.write',
  'board.budget.grant': 'budget.spend',
});

/**
 * Server-resolve the execution scope for a run.
 *
 * The scope is derived from the authenticated principal's grant and never from
 * a request payload, a prompt, source data or model output: "data is not
 * authority". With no resolvable grant the tick refuses (AuthRequired) instead
 * of assuming a scope — an unassigned scope list is not "everything".
 */
export function deriveExecutionScope(actor) {
  if (isPlainObject(actor) && Array.isArray(actor.granted_scope)) {
    const scope = dedupeExecutionScopes(actor.granted_scope);
    if (scope.length === 0) {
      throw new AuthRequired('an empty granted scope authorizes nothing and is not everything', 'EXECUTION_SCOPE_EMPTY');
    }
    policyFunction('assertScopeSubset')(scope, EXECUTION_SCOPES);
    return scope;
  }
  const capabilities = isPlainObject(actor) && Array.isArray(actor.capabilities) ? actor.capabilities : null;
  if (capabilities) {
    const unknown = capabilities.filter((capability) => !BOARD_CAPABILITIES.includes(capability));
    if (unknown.length > 0) {
      throw new AuthRequired(`unknown board capability: ${unknown.join(',')}`, 'EXECUTION_CAPABILITY_UNKNOWN');
    }
    const scope = dedupeExecutionScopes(
      capabilities.map((capability) => BOARD_CAPABILITY_TO_EXECUTION_SCOPE[capability]).filter(Boolean),
    );
    if (scope.length === 0) {
      throw new AuthRequired('the principal grants no execution scope', 'EXECUTION_SCOPE_UNRESOLVED');
    }
    policyFunction('assertScopeSubset')(scope, EXECUTION_SCOPES);
    return scope;
  }
  throw new AuthRequired('no server-resolved execution grant was supplied', 'EXECUTION_SCOPE_UNRESOLVED');
}

function dedupeExecutionScopes(scopes) {
  const allowed = new Set(EXECUTION_SCOPES);
  const out = [];
  for (const scope of scopes) {
    if (typeof scope !== 'string' || !allowed.has(scope)) {
      throw new AuthRequired(`execution scope is outside the closed set: ${String(scope)}`, 'EXECUTION_SCOPE_UNKNOWN');
    }
    if (!out.includes(scope)) out.push(scope);
  }
  return out;
}

function normalizeActor(actor) {
  const actorId = typeof actor === 'string' ? actor : isPlainObject(actor) ? actor.principal_id ?? actor.actor : null;
  if (typeof actorId !== 'string' || !PRINCIPAL_ID.test(actorId)) {
    throw new AuthRequired('the scheduler requires a server-resolved principal id', 'PRINCIPAL_UNRESOLVED');
  }
  return { actorId, record: isPlainObject(actor) ? actor : { principal_id: actorId } };
}

// --- candidate evaluation ---------------------------------------------------

function compareTasks(a, b) {
  const rankA = PRIORITY_RANK[a.priority];
  const rankB = PRIORITY_RANK[b.priority];
  if (rankA !== rankB) return rankA - rankB;
  if (a.task_id < b.task_id) return -1;
  if (a.task_id > b.task_id) return 1;
  return 0;
}

function compareIds(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function pushExcluded(list, entry) {
  const key = `${entry.subject_kind}|${entry.subject_id}|${entry.reasons.join(',')}`;
  if (list.some((existing) => `${existing.subject_kind}|${existing.subject_id}|${existing.reasons.join(',')}` === key)) return;
  list.push(entry);
}

/**
 * The default dependency oracle: a dependency is satisfied only when it is
 * visible in the SAME snapshot and DONE there. A dependency missing from the
 * snapshot is treated as open (fail closed) — the scheduler never assumes a
 * dependency it cannot see is finished.
 */
function defaultDependenciesSatisfied(task, context) {
  const dependencies = Array.isArray(task.dependencies) ? task.dependencies : [];
  for (const dependency of dependencies) {
    const found = context.tasks.find((candidate) => candidate.task_id === dependency);
    if (!found || found.state !== 'DONE') return false;
  }
  return true;
}

/**
 * Structural eligibility of every task in the snapshot, in the exact evaluation
 * order the decision records: priority HIGH < MEDIUM < LOW, then stable
 * `task_id` ascending. Never insertion order, never a random tiebreak.
 *
 * Returns `{ task, eligible, exclusion_reasons }[]` for ALL considered tasks
 * (eligible or not) so that no candidate can be dropped from the audit trail.
 *
 * Options:
 *   dependenciesSatisfiedFor(task, context) -> boolean  (injected oracle)
 *   briefValidatedFor(task) -> boolean                  (injected oracle)
 *   principalId + policy.isVisible                      (ACL gate)
 *   sandbox: { proven, profile_id }                     (context gate; omitted = not evaluated)
 *   grantFor(task) -> grant|undefined                   (context gate; omitted = not evaluated)
 *   spentFor(grant, dayKey) -> spend                    (context gate)
 */
export function evaluateTaskCandidates(tasks, options = {}) {
  if (!Array.isArray(tasks)) throw new NeedsInput('TASKS_MISSING');
  const {
    dependenciesSatisfiedFor = defaultDependenciesSatisfied,
    briefValidatedFor = null,
    principalId = null,
    sandbox = null,
    grantFor = null,
    spentFor = null,
    activeLeaseTaskIds = null,
    now = null,
  } = options;
  const dayKey = now ? dayKeyOf(toInjectedInstant(now, 'now')) : null;

  const known = tasks.filter((task) => isPlainObject(task) && typeof task.task_id === 'string');
  const context = { tasks: known, now };
  const ordered = [...known].sort(compareTasks);
  const evaluated = ordered.slice(0, MAX_CANDIDATE_TASKS);
  const isVisible = principalId ? policyFunction('isVisible') : null;
  const leaseHeld = activeLeaseTaskIds instanceof Set ? activeLeaseTaskIds : new Set(activeLeaseTaskIds ?? []);

  const out = [];
  for (const task of evaluated) {
    const reasons = [];

    if (!BOARD_STATES.includes(task.state)) reasons.push(EXCLUSION_REASONS.STATE_NOT_READY);
    else if (task.state !== 'READY') reasons.push(EXCLUSION_REASONS.STATE_NOT_READY);

    let dependenciesSatisfied = false;
    try {
      dependenciesSatisfied = dependenciesSatisfiedFor(task, context) === true;
    } catch (error) {
      throw toBoardError(error, 'NEEDS_INPUT');
    }
    if (!dependenciesSatisfied) reasons.push(EXCLUSION_REASONS.DEPENDENCIES_OPEN);

    // `brief_validated` is a store-side fact (a DB column), not a BoardTask
    // field, so the rule is "exclude on an explicit negative": the real
    // authority on a validated brief remains guardBacklogToReady /
    // guardReadyToClaimed in policy.mjs, not this projection.
    const briefValidated = briefValidatedFor
      ? briefValidatedFor(task) === true
      : task.brief_validated !== false;
    if (!briefValidated) reasons.push(EXCLUSION_REASONS.BRIEF_NOT_VALIDATED);

    if (isVisible && isVisible(task, principalId) !== true) reasons.push(EXCLUSION_REASONS.ACL_DENIED);
    if (leaseHeld.has(task.task_id)) reasons.push(EXCLUSION_REASONS.ACTIVE_LEASE_EXISTS);

    if (sandbox && !sandboxProvenFor(sandbox, task, { authorization: context.unisolatedExecutionAuthorization ?? null, now: context.now ?? null })) reasons.push(EXCLUSION_REASONS.SANDBOX_NOT_PROVEN);

    if (grantFor) {
      const grant = grantFor(task);
      if (!isBudgetAssigned(grant)) reasons.push(EXCLUSION_REASONS.BUDGET_NOT_ASSIGNED);
      else if (isBudgetExhausted(grant, spentFor ? spentFor(grant, dayKey) : null)) {
        reasons.push(EXCLUSION_REASONS.BUDGET_EXHAUSTED);
      }
    }

    out.push({ task, eligible: reasons.length === 0, exclusion_reasons: dedupeReasons(reasons) });
  }
  return out;
}

/**
 * READY tasks whose dependencies are closed, in the exact evaluation order.
 * This is the structural projection of `evaluateTaskCandidates` (state +
 * dependencies only); the context gates (sandbox, budget, adapter) are applied
 * by `planDispatch`, which is the only function allowed to produce a
 * DispatchDecision.
 */
export function eligibleTasks(tasks, { dependenciesSatisfiedFor } = {}) {
  return evaluateTaskCandidates(tasks, { dependenciesSatisfiedFor })
    .filter((candidate) => candidate.eligible)
    .map((candidate) => candidate.task);
}

// --- sandbox ----------------------------------------------------------------

/**
 * A task is dispatchable only when its isolation profile is one of the two
 * profiles whose OS controls are backed by measured S2-002 evidence
 * (`PROVEN_SANDBOX_PROFILE_IDS` in constants.mjs). `sbx-no-exec-default` is a
 * contract-valid profile that executes nothing, and the `*-blocked` profiles
 * exist exactly because that tier could not be proven on this host. A missing
 * sandbox context is NOT proven.
 */
function sandboxProvenFor(sandbox, task, options = {}) {
  const declared = typeof sandbox === 'string' ? { profile_id: sandbox, proven: true } : sandbox;
  if (!isPlainObject(declared)) return false;
  if (declared.proven === false) return false;
  const taskProfile = task?.workspace_ref?.isolation_profile_id ?? null;
  const contextProfile = declared.profile_id ?? null;
  if (contextProfile && taskProfile && contextProfile !== taskProfile) return false;
  const effective = taskProfile ?? contextProfile;
  if (typeof effective !== 'string' || effective.length === 0) return false;
  // A profile with measured OS controls needs nothing beyond the proven set.
  if (PROVEN_SANDBOX_PROFILE_IDS.includes(effective)) return sandboxProfileExecutable(effective);
  // The HOST_UNISOLATED floor (issue #45) is dispatchable only with a valid
  // named human authorisation resolved server-side. It is NOT proven and it is
  // never reported as proven: the decision that admits it is the same
  // assertLiveExecutionAuthorized gate the command boundary uses, so a tick and
  // a manual execution.start can never disagree about whether a run is allowed.
  return sandboxProfileExecutable(effective, options);
}

/**
 * Executability is decided by policy.assertSandboxExecutable (the S2-002-derived
 * authority); constants.isExecutableSandboxProfile is the same proven set and
 * stays a cheap pre-filter. A refusal is data here — it becomes the
 * SANDBOX_NOT_PROVEN exclusion reason — while any other failure propagates.
 */
function sandboxProfileExecutable(profileId, options = {}) {
  if (typeof profileId !== 'string' || profileId.length === 0) return false;
  if (!isExecutableSandboxProfile(profileId) && !isHostUnisolatedSandboxProfile(profileId)) return false;
  try {
    if (isHostUnisolatedSandboxProfile(profileId)) {
      policyFunction('assertLiveExecutionAuthorized')(profileId, {
        authorization: options.authorization ?? null,
        now: options.now ?? null,
      });
      return true;
    }
    policyFunction('assertSandboxExecutable')(profileId);
    return true;
  } catch (error) {
    if (isBoardError(error) && error.code === 'BLOCKED_SANDBOX') return false;
    throw toBoardError(error, 'BLOCKED_SANDBOX');
  }
}

/**
 * Filesystem roots of a PROVEN profile, read from the S2-002 profile objects
 * themselves (reuse, never a copy). Reported as a shim: constants.mjs exports
 * the proven profile IDS but S2-002 does not expose an id -> profile lookup.
 */
function provenProfileRoots(profileId) {
  const profile = [SANDBOX_LOCAL_RESTRICTED_PODMAN, SANDBOX_UNTRUSTED_CODE_GVISOR]
    .find((candidate) => candidate.profile_id === profileId);
  const roots = profile?.filesystem?.roots;
  return Array.isArray(roots) ? roots : null;
}

// --- budget -----------------------------------------------------------------

/**
 * An unassigned budget is never zero and a free model is never an
 * authorization: every scope must carry an explicitly approved positive
 * number. `assertBudgetAssignable` is the authority (it throws
 * BudgetExceeded); this wrapper only converts that refusal into a boolean for
 * the decision's exclusion list.
 */
function isBudgetAssigned(grant) {
  if (!isPlainObject(grant)) return false;
  if (typeof grant.revoked_at === 'string') return false;
  try {
    policyFunction('assertBudgetAssignable')(grant);
    return true;
  } catch (error) {
    if (isBoardError(error) && error.code === 'BUDGET_EXCEEDED') return false;
    throw toBoardError(error, 'BUDGET_EXCEEDED');
  }
}

function isBudgetExhausted(grant, spent) {
  if (!isBudgetAssigned(grant)) return false;
  const remaining = remainingBudget(grant, spent);
  return remaining.task_remaining <= 0 || remaining.campaign_remaining <= 0 || remaining.day_remaining <= 0;
}

function spentOf(spent) {
  const record = isPlainObject(spent) ? spent : {};
  return {
    task: clampZero(record.spent_task ?? record.task_spent ?? record.task_spend),
    campaign: clampZero(record.spent_campaign ?? record.campaign_spent ?? record.campaign_spend),
    day: clampZero(record.spent_day ?? record.day_spent ?? record.day_spend),
  };
}

/**
 * Budget headroom for the decision's snapshot. The AUTHORIZATION is decided by
 * policy.assertBudgetAssignable; this function only reports numbers, so a
 * policy helper that returns a differently named shape degrades to a local
 * clamp for reporting instead of blocking or, worse, authorizing.
 */
function remainingBudget(grant, spent) {
  const limits = {
    task_limit: asFiniteNumber(grant?.task_limit) ?? 0,
    campaign_limit: asFiniteNumber(grant?.campaign_limit) ?? 0,
    day_limit: asFiniteNumber(grant?.day_limit) ?? 0,
  };
  const spentRecord = spentOf(spent);
  const compute = () => ({
    task_remaining: clampZero(limits.task_limit - spentRecord.task),
    campaign_remaining: clampZero(limits.campaign_limit - spentRecord.campaign),
    day_remaining: clampZero(limits.day_limit - spentRecord.day),
  });
  const helper = policy?.budgetRemaining;
  if (typeof helper === 'function') {
    try {
      const result = helper(
        { ...limits, currency: grant?.currency },
        { ...spentRecord, spent_task: spentRecord.task, spent_campaign: spentRecord.campaign, spent_day: spentRecord.day },
      );
      if (isPlainObject(result) && asFiniteNumber(result.task_remaining) !== null) {
        return {
          task_remaining: clampZero(result.task_remaining),
          campaign_remaining: clampZero(result.campaign_remaining),
          day_remaining: clampZero(result.day_remaining),
        };
      }
    } catch (error) {
      if (!isBoardError(error)) throw toBoardError(error, 'BUDGET_EXCEEDED');
    }
  }
  return compute();
}

function budgetSnapshot(grant, spent) {
  const assigned = isBudgetAssigned(grant);
  if (!assigned) {
    return {
      currency: isPlainObject(grant) && typeof grant.currency === 'string' ? grant.currency : 'USD',
      task_remaining: 0,
      campaign_remaining: 0,
      day_remaining: 0,
      assigned: false,
    };
  }
  return { currency: grant.currency, assigned: true, ...remainingBudget(grant, spent) };
}

/** A task grant wins over a workspace grant; revoked/expired grants are out. */
function pickGrant(grants, task, now) {
  const instant = toInjectedInstant(now, 'now');
  const usable = grants.filter((grant) => {
    if (!isPlainObject(grant)) return false;
    if (grant.workspace_id && task.workspace_id && grant.workspace_id !== task.workspace_id) return false;
    if (typeof grant.revoked_at === 'string') return false;
    if (typeof grant.expires_at === 'string' && grant.expires_at <= instant) return false;
    return true;
  });
  const taskScoped = usable.find((grant) => grant.task_id === task.task_id);
  if (taskScoped) return taskScoped;
  return usable.find((grant) => grant.task_id === null || grant.task_id === undefined) ?? null;
}

function asGrantList(value) {
  if (Array.isArray(value)) return value;
  if (value instanceof Map) return [...value.values()];
  if (isPlainObject(value)) return Object.values(value);
  return [];
}

function spentForGrant(spentRows, grant, dayKey) {
  const rows = Array.isArray(spentRows) ? spentRows : (isPlainObject(spentRows) ? [spentRows] : []);
  if (!grant) return null;
  const total = { spent_task: 0, spent_campaign: 0, spent_day: 0 };
  for (const row of rows) {
    if (!isPlainObject(row)) continue;
    if (row.grant_id && row.grant_id !== grant.grant_id) continue;
    if (row.day_key && dayKey && row.day_key !== dayKey) continue;
    if (row.task_id && grant.task_id && row.task_id !== grant.task_id) continue;
    total.spent_task += clampZero(row.spent_task);
    total.spent_campaign += clampZero(row.spent_campaign);
    total.spent_day += clampZero(row.spent_day);
  }
  return total;
}

// --- adapter selection ------------------------------------------------------

/**
 * Exclusion reasons for one adapter against one task.
 *
 * `NO_HEALTHY_ADAPTER` covers an unhealthy/degraded/unknown registration and
 * an `unavailable` adapter kind: the bounded profile does not silently run on
 * a degraded executor, because "degraded" has no measured meaning for a
 * scheduler that may not retry a blind run.
 *
 * `CAPABILITY_MISMATCH` is decided by the policy authorizer over the adapter's
 * DECLARED capabilities/tools. A declaration is a claim, not a permission; it
 * is checked here, cross-checked against the grant by adapters.mjs and
 * enforced again by the transition guards.
 */
function adapterExclusionReasons(adapter, task, context) {
  const reasons = [];
  if (!isPlainObject(adapter) || typeof adapter.adapter_id !== 'string') {
    reasons.push(EXCLUSION_REASONS.NO_HEALTHY_ADAPTER);
    return dedupeReasons(reasons);
  }
  if (adapter.health !== 'healthy') reasons.push(EXCLUSION_REASONS.NO_HEALTHY_ADAPTER);
  if (adapter.adapter_kind === 'unavailable') reasons.push(EXCLUSION_REASONS.NO_HEALTHY_ADAPTER);
  if (adapter.workspace_id && task.workspace_id && adapter.workspace_id !== task.workspace_id) {
    reasons.push(EXCLUSION_REASONS.ACL_DENIED);
  }

  const taskProfile = task?.workspace_ref?.isolation_profile_id ?? null;
  const adapterProfile = adapter.sandbox_profile_id ?? null;
  if (context.sandbox && !sandboxProvenFor(context.sandbox, task, { authorization: context.unisolatedExecutionAuthorization ?? null, now: context.now ?? null })) reasons.push(EXCLUSION_REASONS.SANDBOX_NOT_PROVEN);
  if (taskProfile && adapterProfile && taskProfile !== adapterProfile) reasons.push(EXCLUSION_REASONS.SANDBOX_NOT_PROVEN);
  if (!sandboxProfileExecutable(taskProfile) || !sandboxProfileExecutable(adapterProfile)) {
    reasons.push(EXCLUSION_REASONS.SANDBOX_NOT_PROVEN);
  }

  if (!coversViaAuthorizer('assertCapabilitySubset', task.required_capabilities ?? [], adapter.declared_capabilities ?? [])) {
    reasons.push(EXCLUSION_REASONS.CAPABILITY_MISMATCH);
  }
  if (!coversViaAuthorizer('assertToolSubset', task.allowed_tools ?? [], adapter.declared_tools ?? [])) {
    reasons.push(EXCLUSION_REASONS.CAPABILITY_MISMATCH);
  }
  if (context.budgetAvailable === false) {
    reasons.push(EXCLUSION_REASONS.BUDGET_NOT_ASSIGNED);
  } else if (context.budgetAvailable && context.budgetAvailable.assigned === false) {
    reasons.push(EXCLUSION_REASONS.BUDGET_NOT_ASSIGNED);
  } else if (context.budgetAvailable && context.budgetAvailable.exhausted === true) {
    reasons.push(EXCLUSION_REASONS.BUDGET_EXHAUSTED);
  }
  return dedupeReasons(reasons);
}

/**
 * Choose the adapter for a task: stable registered `adapter_id` ascending
 * among the eligible ones, first fit wins.
 *
 * Never substitutes: when the task names an `assigned_adapter_id`, that
 * adapter is the ONLY candidate — a more capable adapter is not a better one
 * when the plan of record says otherwise, and swapping silently would change
 * the meaning of the task's capability/tool contract.
 *
 * `budgetAvailable` may be a boolean or `{ assigned, exhausted }`;
 * `sandboxProven` may be a boolean or `{ proven, profile_id }`. Either way a
 * falsy/absent value means NOT proven / NOT assigned (fail closed).
 *
 * Returns `{ selected, candidates, excluded }` where `candidates` is the
 * evaluation order and `excluded` records every refused adapter with reasons.
 */
export function selectAdapter(adapters, task, { budgetAvailable, sandboxProven } = {}) {
  if (!Array.isArray(adapters)) throw new NeedsInput('ADAPTERS_MISSING');
  if (!isPlainObject(task)) throw new NeedsInput('TASK_MISSING');
  const sandboxContext = sandboxProven === undefined ? null
    : (typeof sandboxProven === 'boolean' ? { proven: sandboxProven } : sandboxProven);
  const context = { sandbox: sandboxContext, budgetAvailable: budgetAvailable ?? null };

  const assigned = task.assigned_adapter_id ?? null;
  const pool = assigned
    ? adapters.filter((adapter) => isPlainObject(adapter) && adapter.adapter_id === assigned)
    : [...adapters];

  // Stable order: registered adapter_id ascending. Never registration order.
  pool.sort((a, b) => compareIds(String(a?.adapter_id ?? ''), String(b?.adapter_id ?? '')));

  const candidates = [];
  const excluded = [];
  for (const adapter of pool.slice(0, MAX_DECISION_ENTRIES)) {
    const reasons = adapterExclusionReasons(adapter, task, context);
    const adapterId = String(adapter?.adapter_id ?? 'unregistered');
    candidates.push({ adapter_id: adapterId, eligible: reasons.length === 0, exclusion_reasons: reasons });
    if (reasons.length > 0) {
      excluded.push({ subject_kind: 'adapter', subject_id: adapterId, reasons });
    }
  }
  if (assigned && !adapters.some((adapter) => isPlainObject(adapter) && adapter.adapter_id === assigned)) {
    // The adapter of record is not registered in this workspace: dispatch is
    // refused, not downgraded to whatever else is lying around.
    excluded.push({
      subject_kind: 'adapter',
      subject_id: assigned,
      reasons: [EXCLUSION_REASONS.NO_HEALTHY_ADAPTER],
    });
  }
  const winner = candidates.find((candidate) => candidate.eligible) ?? null;
  return {
    selected: winner ? adapters.find((adapter) => adapter.adapter_id === winner.adapter_id) : null,
    candidates,
    excluded,
  };
}

// --- planDispatch -----------------------------------------------------------

/**
 * Build the contract-valid DispatchDecision for a workspace snapshot.
 *
 * The decision is the audit record: it names the selected pair AND every
 * refused candidate with the reason, plus the budget headroom that justified
 * the decision. `assertBoardContract('dispatch-decision', ...)` runs before the
 * value leaves this function, so a decision that would be rejected by the
 * contract is never returned to a caller.
 */
export function planDispatch({
  workspaceId,
  tasks,
  adapters,
  budgets = [],
  spent = [],
  activeLeases = [],
  sandbox = null,
  now,
  ids,
  principalId = null,
  dependenciesSatisfiedFor = null,
  briefValidatedFor = null,
  // Server-resolved named human authorisation (issue #45). Only the
  // HOST_UNISOLATED floor tier consults it; an isolated profile ignores it and
  // the caller is refused if it supplies one (policy.assertLiveExecutionAuthorized).
  unisolatedExecutionAuthorization = null,
} = {}) {
  if (typeof workspaceId !== 'string' || workspaceId.length === 0) throw new NeedsInput('WORKSPACE_ID_MISSING');
  const instant = toInjectedInstant(now, 'now');
  if (!Array.isArray(tasks)) throw new NeedsInput('TASKS_MISSING');
  if (!Array.isArray(adapters)) throw new NeedsInput('ADAPTERS_MISSING');

  const grants = asGrantList(budgets);
  const workspaceTasks = tasks.filter((task) => isPlainObject(task) && (!task.workspace_id || task.workspace_id === workspaceId));
  const workspaceAdapters = adapters.filter((adapter) => isPlainObject(adapter) && (!adapter.workspace_id || adapter.workspace_id === workspaceId));
  const active = activeLeases.filter((lease) => isPlainObject(lease) && (!lease.lease_state || lease.lease_state === 'ACTIVE'));
  const concurrencyReached = active.length >= MAX_CONCURRENT_TASKS;
  const activeTaskIds = new Set(active.map((lease) => lease.task_id).filter((taskId) => typeof taskId === 'string'));
  const dayKey = dayKeyOf(instant);

  const grantForTask = (task) => pickGrant(grants, task, instant);
  const evaluated = evaluateTaskCandidates(workspaceTasks, {
    unisolatedExecutionAuthorization,
    dependenciesSatisfiedFor: dependenciesSatisfiedFor ?? undefined,
    briefValidatedFor,
    principalId,
    sandbox,
    grantFor: grantForTask,
    spentFor: (grant) => spentForGrant(spent, grant, dayKey),
    activeLeaseTaskIds: activeTaskIds,
    now: instant,
  });

  const candidates = [];
  const excluded = [];
  let selected = null;
  let selection = null;
  const notes = [];
  if (evaluated.length > workspaceTasks.length) {
    notes.push(`evaluation truncated at ${MAX_CANDIDATE_TASKS} candidates by the bounded profile`);
  }

  for (const entry of evaluated) {
    if (concurrencyReached) {
      // While an active lease exists the bounded profile dispatches nothing.
      // Every candidate carries that reason, so a no-op decision explains
      // itself instead of looking like an empty queue.
      entry.eligible = false;
      entry.exclusion_reasons = dedupeReasons([...entry.exclusion_reasons, EXCLUSION_REASONS.CONCURRENCY_LIMIT_REACHED]);
    }
    if (entry.eligible) {
      const grant = grantForTask(entry.task);
      const outcome = selectAdapter(workspaceAdapters, entry.task, {
        budgetAvailable: isBudgetAssigned(grant)
          ? { assigned: true, exhausted: isBudgetExhausted(grant, spentForGrant(spent, grant, dayKey)) }
          : false,
        sandboxProven: sandbox,
      });
      for (const refused of outcome.excluded) {
        // The exclusion list carries no task reference (the frozen schema has
        // no such field), so an identical adapter refusal recorded for two
        // candidates is one entry, not two indistinguishable ones.
        pushExcluded(excluded, { subject_kind: 'adapter', subject_id: refused.subject_id, reasons: refused.reasons });
      }
      if (outcome.selected) {
        // The first eligible pair wins; a later eligible candidate stays in the
        // record as `eligible: true` with no selection, because it was not
        // refused — it simply lost the deterministic order.
        if (selection === null) selection = { task: entry.task, adapter: outcome.selected, grant };
      } else {
        // No adapter may serve this task: the task inherits the adapter-side
        // reasons so the record explains WHY, not merely THAT.
        const derived = outcome.excluded.length > 0
          ? [...new Set(outcome.excluded.flatMap((item) => item.reasons))]
          : [EXCLUSION_REASONS.NO_HEALTHY_ADAPTER];
        entry.eligible = false;
        entry.exclusion_reasons = dedupeReasons([...entry.exclusion_reasons, ...derived]);
      }
    }
    if (!entry.eligible) {
      pushExcluded(excluded, {
        subject_kind: 'task',
        subject_id: entry.task.task_id,
        reasons: entry.exclusion_reasons,
      });
    }
    candidates.push({
      task_id: entry.task.task_id,
      priority: PRIORITY_RANK[entry.task.priority] === undefined ? 'LOW' : entry.task.priority,
      eligible: entry.eligible,
      exclusion_reasons: entry.exclusion_reasons,
    });
  }

  let reason;
  if (selection) {
    reason = `selected ${selection.task.task_id} (${selection.task.priority}) on ${selection.adapter.adapter_id}`;
  } else if (concurrencyReached) {
    reason = `no selection: the bounded profile already runs ${MAX_CONCURRENT_TASKS} active task(s)`;
  } else if (candidates.length === 0) {
    reason = 'no selection: the workspace has no task in the snapshot';
  } else {
    reason = 'no selection: every candidate was excluded, see candidates/excluded';
  }
  if (notes.length > 0) reason = `${reason}; ${notes.join('; ')}`;
  reason = reason.slice(0, 500);

  const snapshotGrant = selection
    ? selection.grant
    : (grants.find((grant) => isPlainObject(grant) && !grant.task_id) ?? grants[0] ?? null);
  const decision = {
    contractVersion: '1.0.0',
    decision_id: resolveId(ids, 'decision', candidates.length),
    workspace_id: workspaceId,
    max_concurrency: MAX_CONCURRENT_TASKS,
    selected_task_id: selection ? selection.task.task_id : null,
    selected_adapter_id: selection ? selection.adapter.adapter_id : null,
    selected_lease_id: null,
    selected_fencing_token: null,
    candidates: candidates.slice(0, MAX_DECISION_ENTRIES),
    excluded: excluded.slice(0, MAX_DECISION_ENTRIES),
    reason,
    budget_snapshot: budgetSnapshot(
      snapshotGrant,
      snapshotGrant ? spentForGrant(spent, snapshotGrant, dayKey) : null,
    ),
    decided_at: instant,
  };
  assertBoardContract('dispatch-decision', decision);
  return decision;
}

/**
 * Plan from a live store snapshot. Used by `runSchedulerTick` when the caller
 * does not hand in a pre-computed decision: the store is the authority on
 * tasks, adapters, grants and active leases, so the plan is always built from
 * server-side state and never from a request payload.
 */
async function planFromStore({ store, workspaceId, principalId, now, ids, sandbox, unisolatedExecutionAuthorization = null }) {
  const [tasks, adapters, grants, leases] = await Promise.all([
    // A bounded read: the store caps `limit` at 200, and the decision is
    // evaluated over at most MAX_CANDIDATE_TASKS rows anyway.
    store.listTasks({ workspaceId, principalId, limit: MAX_STORE_TASK_READ }),
    store.listAdapters({ workspaceId }),
    store.listBudgetGrants({ workspaceId }),
    store.listLeases({ workspaceId, leaseState: 'ACTIVE', principalId }),
  ]);
  const spent = [];
  for (const grant of grants) {
    const dayKey = dayKeyOf(toInjectedInstant(now, 'now'));
    const row = await store.readBudgetSpend(grant.grant_id, dayKey);
    if (row) spent.push(row);
  }
  return planDispatch({
    workspaceId,
    tasks,
    adapters,
    budgets: grants,
    spent,
    activeLeases: leases,
    sandbox,
    now,
    ids,
    principalId,
  });
}

// --- ExecutionRequest construction ------------------------------------------

function assertTaskDigests(task) {
  for (const field of ['brief_digest', 'policy_digest', 'manifest_digest', 'history_digest']) {
    if (typeof task[field] !== 'string' || !DIGEST_PATTERN.test(task[field])) {
      throw new MalformedResult(`TASK_DIGEST_MALFORMED:${field}`, 'a digest is an integrity control and must be a well-formed wire digest');
    }
  }
}

function assertRequestDigestsAgreeWithTask(task, request) {
  // A digest is never a signature: this proves only that the documents the
  // caller is about to act on are the ones that were hashed.
  policyFunction('assertDigestsMatch')(task, {
    briefDigest: request.brief_digest,
    policyDigest: request.policy_digest,
    manifestDigest: request.manifest_digest,
  });
  assertDigestAgreement(task.brief_digest, request.brief_digest, 'brief_digest');
  assertDigestAgreement(task.policy_digest, request.policy_digest, 'policy_digest');
  assertDigestAgreement(task.manifest_digest, request.manifest_digest, 'manifest_digest');
  assertDigestAgreement(task.workspace_ref.sandbox_profile_digest, request.workspace_ref.sandbox_profile_digest, 'sandbox_profile_digest');
  return true;
}

function buildExecutionRequest({ task, workspaceId, actorId, scope, allowedTools, grant, leaseId, fencingToken, adapterId, now, ids, idempotencyKey }) {
  const timeoutMs = asFiniteNumber(grant.timeout_ms) ?? asFiniteNumber(task.time_limits?.timeout_ms);
  if (!isPositiveNumber(timeoutMs)) {
    throw new BudgetExceeded('BUDGET_TIMEOUT_MISSING', 'an approved numeric timeout is required before CLAIMED->RUNNING');
  }
  if (typeof grant.granted_by !== 'string' || !PRINCIPAL_ID.test(grant.granted_by)) {
    throw new BudgetExceeded('BUDGET_GRANT_UNATTRIBUTED', 'a budget grant must name the principal that approved it');
  }
  const request = {
    contract_version: 'veritas.execution/1.0.0',
    request_id: resolveId(ids, 'request', 0),
    idempotency_key: idempotencyKey,
    task_id: task.task_id,
    workspace_id: workspaceId,
    brief_digest: task.brief_digest,
    policy_digest: task.policy_digest,
    manifest_digest: task.manifest_digest,
    principal_id: actorId,
    granted_scope: scope,
    allowed_tools: allowedTools,
    workspace_ref: task.workspace_ref,
    budget_grant: {
      currency: grant.currency,
      task_limit: asFiniteNumber(grant.task_limit),
      campaign_limit: asFiniteNumber(grant.campaign_limit),
      day_limit: asFiniteNumber(grant.day_limit),
      timeout_ms: Math.trunc(timeoutMs),
      granted_by: grant.granted_by,
      granted_at: toInjectedInstant(grant.granted_at, 'granted_at'),
    },
    deadline: task.time_limits?.deadline ?? null,
    lease_id: leaseId,
    fencing_token: fencingToken,
    adapter_id: adapterId,
    issued_at: now,
  };
  assertExecutionVersion(request);
  assertBoardContract('execution-request', request);
  assertRequestDigestsAgreeWithTask(task, request);
  return request;
}

// --- scheduler tick ---------------------------------------------------------

function registrationSandboxProfileId(registration) {
  const profileId = isPlainObject(registration) ? registration.sandbox_profile_id : null;
  if (typeof profileId !== 'string' || profileId.length === 0) {
    throw new BlockedSandbox('SANDBOX_NOT_PROVEN', 'the adapter registration names no sandbox profile');
  }
  return profileId;
}

function normalizeLease(claim) {
  const candidate = isPlainObject(claim) && isPlainObject(claim.lease) ? claim.lease : claim;
  if (!isPlainObject(candidate)) {
    throw new NeedsInput('CLAIM_RESULT_MALFORMED', 'claimTask must return the lease it created');
  }
  const leaseId = candidate.lease_id ?? candidate.leaseId;
  const fencingToken = candidate.fencing_token ?? candidate.fencingToken;
  if (typeof leaseId !== 'string' || !Number.isInteger(fencingToken)) {
    throw new NeedsInput('CLAIM_RESULT_MALFORMED', 'claimTask must return lease_id and fencing_token');
  }
  return { ...candidate, lease_id: leaseId, fencing_token: fencingToken };
}

function normalizeRun(created) {
  const candidate = isPlainObject(created) && isPlainObject(created.run) ? created.run : created;
  if (!isPlainObject(candidate) || typeof candidate.run_id !== 'string') {
    throw new NeedsInput('RUN_RESULT_MALFORMED', 'createRun must return the run it created');
  }
  return candidate;
}

function stageKey({ command, stage, actorId, args }) {
  const key = policy?.commandIdempotencyKey;
  const material = { command, stage, actor: actorId, args };
  // commandIdempotencyKey is SHA-256 over the canonical-json-v1 form, i.e.
  // exactly canonicalDigest. The S2-006 canonicalizer is the single digest
  // convention, so the fallback below is the same function, not a variant.
  if (typeof key === 'function') {
    const produced = key(material);
    if (typeof produced === 'string' && HEX64.test(produced)) return produced;
  }
  return canonicalDigest(material);
}

/**
 * One scheduler tick: plan, gate, claim, record the run and its dispatch
 * record, and move CLAIMED -> RUNNING.
 *
 * Order matters and is deliberate:
 *   1. every gate (sandbox proven, health current, exact tool/workspace grant,
 *      approved numeric budget, digests, ACL) runs BEFORE the first write, so
 *      a refusal changes nothing;
 *   2. claimTask is a single transaction (lease + transition + audit);
 *   3. createRun records the run and its outbox row;
 *   4. the CLAIMED -> RUNNING transition happens only once the dispatch record
 *      is durable — a RUNNING task without a recorded run would be a lie the
 *      recovery path could not reconstruct.
 *
 * A crash between (2) and (3) leaves CLAIMED with a lease, which the lease
 * expiry/release path reconciles. A crash before (2) leaves the task READY and
 * the next tick re-derives the same decision from the same snapshot.
 *
 * `dispatch` may be a pre-computed DispatchDecision, a function producing one,
 * or omitted (the plan is then built from the store snapshot).
 */
export async function runSchedulerTick({
  store,
  workspaceId,
  actor,
  adapter = null,
  now,
  dispatch = null,
  ids = null,
  sandbox = null,
  idempotencyKey = null,
  workspaceRoots = null,
  // Server-resolved named human authorisation for a run bound to the
  // HOST_UNISOLATED floor tier (issue #45). Never a payload argument.
  unisolatedExecutionAuthorization = null,
  options = {},
} = {}) {
  if (!isPlainObject(store)) throw new NeedsInput('STORE_MISSING');
  if (typeof workspaceId !== 'string' || workspaceId.length === 0) throw new NeedsInput('WORKSPACE_ID_MISSING');
  const instant = toInjectedInstant(now, 'now');
  const { actorId, record: actorRecord } = normalizeActor(actor);

  let decision = null;
  if (typeof dispatch === 'function') {
    decision = await dispatch({ workspaceId, now: instant, actor: actorRecord, adapter });
  } else if (dispatch !== null && dispatch !== undefined) {
    decision = dispatch;
  } else {
    decision = await planFromStore({ store, workspaceId, principalId: actorId, now: instant, ids, sandbox, unisolatedExecutionAuthorization });
  }
  assertBoardContract('dispatch-decision', decision);
  if (decision.workspace_id !== workspaceId) {
    throw new AclDenied('DECISION_WORKSPACE_MISMATCH', 'a plan for another workspace is never actionable here');
  }

  // A no-op is still an answer: the caller receives the decision that explains
  // why nothing was dispatched.
  if (decision.selected_task_id === null || decision.selected_adapter_id === null) {
    return { decision, run: null, request: null, lease: null, outbox: null };
  }

  const task = await store.getTask(decision.selected_task_id, { workspaceId, principalId: actorId });
  if (!isPlainObject(task)) throw new NeedsInput('TASK_NOT_FOUND');
  if (task.workspace_id !== workspaceId) {
    throw new AclDenied('TASK_WORKSPACE_MISMATCH');
  }
  if (task.state !== 'READY') {
    // The store is the authority on state: a plan computed from a stale
    // snapshot may not be executed.
    throw new BlockedPolicy('TASK_NOT_READY', `the task is ${String(task.state)}, not READY`);
  }
  assertTaskDigests(task);
  if (task.active_lease_id) {
    throw new BlockedPolicy('ACTIVE_LEASE_EXISTS', 'the task already holds an active lease');
  }

  // --- gates, all before any write -----------------------------------------
  let registration = null;
  try {
    registration = await store.getAdapter(decision.selected_adapter_id);
  } catch (error) {
    // An unknown, unreadable or unregistered adapter is the same operational
    // fact to a scheduler: there is no executor to run this task.
    throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', `${decision.selected_adapter_id}: ${toBoardError(error, 'AGENT_UNAVAILABLE').message}`);
  }
  if (!isPlainObject(registration)) {
    throw new AgentUnavailable('ADAPTER_NOT_REGISTERED', decision.selected_adapter_id);
  }
  // 1. Sandbox: the isolation profile must be provable AND the executor must be
  //    bound to the same profile the task was authorized for.
  const profileId = task.workspace_ref?.isolation_profile_id ?? null;
  const liveAuthorization = options.unisolatedExecutionAuthorization
    ?? options.unisolated_execution_authorization
    ?? null;
  if (sandboxProvenFor(sandbox ?? profileId, task, { authorization: liveAuthorization, now: instant }) !== true) {
    throw new BlockedSandbox('SANDBOX_NOT_PROVEN', `isolation profile ${String(profileId)} is not provable on this host`);
  }
  const sandboxDecision = policyFunction('assertLiveExecutionAuthorized')(profileId, {
    authorization: liveAuthorization,
    now: instant,
  });
  // 2. Health is current, server-side: the registration is the authority and
  //    the live transport may only veto it.
  if (registration.health !== 'healthy') {
    throw new AgentUnavailable('ADAPTER_NOT_HEALTHY', `adapter health is ${String(registration.health)}`);
  }
  if (registration.adapter_kind === 'unavailable') {
    throw new AgentUnavailable('ADAPTER_UNAVAILABLE', 'the adapter is registered as unavailable');
  }
  const adapterProfileId = registrationSandboxProfileId(registration);
  policyFunction('assertLiveExecutionAuthorized')(adapterProfileId, {
    authorization: liveAuthorization,
    now: instant,
  });
  if (adapterProfileId !== profileId) {
    throw new BlockedSandbox('ADAPTER_SANDBOX_MISMATCH', 'the adapter is not bound to the task isolation profile');
  }
  // The live transport may only VETO. Health is server-resolved from the
  // registration; an unrecognized transport health signal never widens it, and
  // a recognized unhealthy signal is fatal.
  if (adapter !== null && adapter !== undefined) {
    if (typeof adapter.health === 'function') {
      let reported = null;
      try {
        reported = await adapter.health();
      } catch (error) {
        throw toBoardError(error, 'AGENT_UNAVAILABLE');
      }
      const signal = isPlainObject(reported) ? reported.health ?? reported.status : reported;
      if (typeof signal === 'string' && ['unhealthy', 'degraded', 'down', 'failed', 'error'].includes(signal.toLowerCase())) {
        throw new AgentUnavailable('ADAPTER_HEALTH_VETO', `transport reported ${signal}`);
      }
    }
    if (typeof adapter.identify === 'function') {
      let identity = null;
      try {
        identity = await adapter.identify();
      } catch (error) {
        throw toBoardError(error, 'AGENT_UNAVAILABLE');
      }
      if (isPlainObject(identity) && typeof identity.adapter_id === 'string'
          && identity.adapter_id !== decision.selected_adapter_id) {
        throw new MalformedResult('ADAPTER_IDENTITY_MISMATCH', 'the transport identifies as another adapter');
      }
    }
  }

  // 2. Exact tool/workspace grant: the request carries the TASK's tools (never
  //    the adapter's wider set and never a payload value) and the task's
  //    workspace, both proven to stay inside the granted boundaries.
  const allowedTools = [...(task.allowed_tools ?? [])];
  if (!coversViaAuthorizer('assertToolSubset', allowedTools, registration.declared_tools ?? [])) {
    throw new MalformedResult('TOOL_GRANT_MISMATCH', 'the registered adapter does not cover the task tool grant');
  }
  const roots = Array.isArray(workspaceRoots) && workspaceRoots.length > 0
    ? workspaceRoots
    : (provenProfileRoots(String(profileId)) ?? []);
  policyFunction('assertWorkspaceWithin')(task.workspace_ref, roots);

  // 3. Approved numeric budget: unassigned is not zero, free is not authorized.
  const dayKey = dayKeyOf(instant);
  const grants = await store.listBudgetGrants({ workspaceId, taskId: task.task_id });
  const grant = pickGrant(Array.isArray(grants) ? grants : [], task, instant);
  if (!isBudgetAssigned(grant)) {
    throw new BudgetExceeded('BUDGET_NOT_ASSIGNED', 'no approved positive numeric budget grant covers this task');
  }
  const spendRow = await store.readBudgetSpend(grant.grant_id, dayKey);
  const spent = spentForGrant(spendRow ? [spendRow] : [], grant, dayKey);
  if (isBudgetExhausted(grant, spent)) {
    throw new BudgetExceeded('BUDGET_EXHAUSTED', 'the approved budget has no remaining headroom');
  }
  // A zero prospective settle is the honest start-of-run question: "is the
  // recorded spend already inside the approved numbers?" A non-zero amount
  // would be a claim about work that has not been done yet.
  policyFunction('assertWithinBudget')(
    {
      task_limit: asFiniteNumber(grant.task_limit),
      campaign_limit: asFiniteNumber(grant.campaign_limit),
      day_limit: asFiniteNumber(grant.day_limit),
    },
    { spent_task: spent.spent_task, spent_campaign: spent.spent_campaign, spent_day: spent.spent_day },
    0,
  );

  // 4. Server-resolved execution scope. Never from the request or the payload.
  const scope = deriveExecutionScope(actorRecord);

  // --- writes --------------------------------------------------------------
  const taskId = task.task_id;
  const adapterId = decision.selected_adapter_id;
  const baseArgs = {
    workspace_id: workspaceId,
    task_id: taskId,
    adapter_id: adapterId,
    expected_revision: task.revision,
    brief_digest: task.brief_digest,
    policy_digest: task.policy_digest,
    manifest_digest: task.manifest_digest,
  };
  const claimKey = idempotencyKey ?? stageKey({ command: 'tasks.claim', stage: 'claim', actorId, args: baseArgs });
  const ttlMs = asFiniteNumber(task.time_limits?.timeout_ms) ?? 60000;

  const claim = await store.claimTask({
    taskId,
    workspaceId,
    adapterId,
    ttlMs,
    expectedRevision: task.revision,
    actor: actorId,
    actorKind: 'scheduler',
    idempotencyKey: claimKey,
    argsDigest: stageKey({ command: 'tasks.claim', stage: 'claim', actorId, args: baseArgs }),
    operation: 'board.task.claim',
  });
  const lease = normalizeLease(claim);
  if (lease.replayed === true) {
    // The ledger already holds a claim for exactly these arguments while the
    // task is still READY at the same revision: the canonical state cannot be
    // trusted. Re-dispatching on a possibly-stale lease would be a duplicate
    // external effect, so the tick refuses and asks for reconciliation.
    throw new ReconciliationRequired(
      'CLAIM_REPLAYED_ON_READY_TASK',
      'the idempotency ledger holds a claim for this exact task revision while the task is still READY',
    );
  }

  const runKey = stageKey({ command: 'execution.start', stage: 'run', actorId, args: baseArgs });
  const request = buildExecutionRequest({
    task,
    workspaceId,
    actorId,
    scope,
    allowedTools,
    grant,
    leaseId: lease.lease_id,
    fencingToken: lease.fencing_token,
    adapterId,
    now: instant,
    ids,
    idempotencyKey: runKey,
  });

  const created = await store.createRun({
    request,
    actor: actorId,
    idempotencyKey: runKey,
    argsDigest: stageKey({ command: 'execution.start', stage: 'run', actorId, args: { ...baseArgs, request_id: request.request_id } }),
    operation: 'execution.start',
    actorKind: 'scheduler',
  });
  const run = normalizeRun(created);
  const pendingRows = await store.listOutbox({ workspaceId, dispatchState: 'PENDING', principalId: actorId });

  // The dispatch record must be discoverable by the outbox driver. The store
  // creates it with the run; when a store does not hand it back, the row is
  // looked up rather than assumed, and a missing one is reported instead of
  // being silently accepted.
  const outbox = isPlainObject(created) && isPlainObject(created.outbox)
    ? created.outbox
    : (Array.isArray(pendingRows) ? pendingRows : [])
      .find((row) => row.run_id === run.run_id || (row.task_id === taskId && row.idempotency_key === runKey)) ?? null;

  const runningKey = stageKey({ command: 'tasks.transition', stage: 'running', actorId, args: { ...baseArgs, run_id: run.run_id } });
  await store.transitionTask({
    taskId,
    toState: 'RUNNING',
    expectedRevision: task.revision + 1,
    actor: actorId,
    actorKind: 'scheduler',
    reason: 'execution request recorded; run is DISPATCH_PENDING until the outbox is acknowledged',
    lease: lease.lease_id,
    fencingToken: lease.fencing_token,
    idempotencyKey: runningKey,
    argsDigest: stageKey({ command: 'tasks.transition', stage: 'running', actorId, args: { ...baseArgs, run_id: run.run_id, to_state: 'RUNNING' } }),
    operation: 'board.task.transition',
  });

  return { decision, run, request, lease, outbox };
}

// --- outbox driver ----------------------------------------------------------

function boundedLimit(limit) {
  if (limit === undefined || limit === null) return MAX_OUTBOX_BATCH;
  const numeric = asFiniteNumber(limit);
  if (numeric === null || numeric < 1) throw new NeedsInput('OUTBOX_LIMIT_INVALID');
  return Math.min(Math.trunc(numeric), MAX_OUTBOX_BATCH);
}

function outboxOrder(a, b) {
  const byTime = compareIds(String(a?.created_at ?? ''), String(b?.created_at ?? ''));
  if (byTime !== 0) return byTime;
  return compareIds(String(a?.outbox_id ?? ''), String(b?.outbox_id ?? ''));
}

/** The first candidate that is a non-empty string, or null. Never invents one. */
function firstIdentifier(...candidates) {
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.length > 0) return candidate;
  }
  return null;
}

function transportSend(transport) {
  if (!isPlainObject(transport) && typeof transport !== 'function') {
    throw new NeedsInput('OUTBOX_TRANSPORT_MISSING', 'a dispatch driver needs a transport');
  }
  if (transport && typeof transport.dispatch === 'function') return transport.dispatch.bind(transport);
  if (transport && typeof transport.start === 'function') return transport.start.bind(transport);
  throw new NeedsInput('OUTBOX_TRANSPORT_MISSING', 'the transport must expose dispatch() or start()');
}

/**
 * Idempotent outbox dispatch: PENDING -> SENT -> ACKED, with a recovery-safe
 * crash semantic.
 *
 * The intent record (SENT) is written BEFORE the transport is called, so:
 *   * a crash before that record leaves the row PENDING and re-dispatchable;
 *   * a crash after it leaves the row SENT with no ack, which is unknowable by
 *     construction and escalates to RECONCILIATION_REQUIRED instead of being
 *     re-sent. A duplicate external effect is a hard-gate violation, and
 *     "probably fine" is not a mitigation strategy.
 *
 * `externalEffectsIssued` in the result is the counter a probe asserts is
 * exactly the number of rows that crossed the boundary.
 *
 * `workspaceId` is REQUIRED here (the frozen store refuses an unscoped
 * outbox query, and an unscoped dispatch is a cross-workspace hazard); it is an
 * additive parameter relative to the signature in the module spec.
 */
export async function driveOutbox({ store, transport, actor, now, limit, workspaceId, workspace_id: workspaceAlias } = {}) {
  if (!isPlainObject(store)) throw new NeedsInput('STORE_MISSING');
  workspaceId = workspaceId ?? workspaceAlias;
  if (typeof workspaceId !== 'string' || workspaceId.length === 0) throw new NeedsInput('OUTBOX_WORKSPACE_REQUIRED');
  const instant = toInjectedInstant(now, 'now');
  const { actorId } = normalizeActor(actor);
  const batch = boundedLimit(limit);

  const rows = await store.listOutbox({ workspaceId, dispatchState: 'PENDING', principalId: actorId });
  const pending = (Array.isArray(rows) ? rows : [])
    .filter((row) => isPlainObject(row) && row.dispatch_state === 'PENDING' && row.workspace_id === workspaceId);
  pending.sort(outboxOrder);

  const summary = {
    now: instant,
    actor: actorId,
    inspected: 0,
    intentRecorded: 0,
    acked: 0,
    escalated: 0,
    failed: 0,
    externalEffectsIssued: 0,
    rows: [],
  };

  for (const row of pending.slice(0, batch)) {
    summary.inspected += 1;
    const entry = { outbox_id: row.outbox_id, event_type: row.event_type, task_id: row.task_id ?? null, run_id: row.run_id ?? null };
    // A dispatch event carries a contract-valid ExecutionRequest; sending
    // anything else would be an unverified handoff.
    if (isPlainObject(row.payload) && row.payload.contract_version !== undefined) {
      assertBoardContract('execution-request', row.payload);
    }
    const argsDigest = stageKey({
      command: 'outbox.dispatch',
      stage: 'intent',
      actorId,
      args: { outbox_id: row.outbox_id, idempotency_key: row.idempotency_key, payload_digest: row.payload_digest },
    });
    // 1. Intent first. This is the point of no return.
    const marked = await store.markOutboxSent({
      outboxId: row.outbox_id,
      actor: actorId,
      idempotencyKey: argsDigest,
      argsDigest,
      operation: 'outbox.dispatch',
    });
    if (isPlainObject(marked) && marked.replayed === true) {
      // The intent was already recorded by an earlier attempt: the external
      // effect may already have happened. Never send again.
      await store.escalateOutbox({
        outboxId: row.outbox_id,
        reason: 'UNKNOWN_OUTCOME: send intent was already recorded without an acknowledgement',
        actor: actorId,
        idempotencyKey: stageKey({ command: 'outbox.dispatch', stage: 'escalate-replayed', actorId, args: { outbox_id: row.outbox_id } }),
        argsDigest: stageKey({ command: 'outbox.dispatch', stage: 'escalate-replayed', actorId, args: { outbox_id: row.outbox_id } }),
        operation: 'outbox.escalate',
      });
      summary.escalated += 1;
      entry.dispatch_state = 'RECONCILIATION_REQUIRED';
      entry.external_effect_issued = false;
      summary.rows.push(entry);
      continue;
    }
    summary.intentRecorded += 1;

    // 2. Cross the boundary exactly once.
    let acknowledged = false;
    try {
      const send = transportSend(transport);
      const result = await send(row.payload);
      acknowledged = result !== false;
      summary.externalEffectsIssued += 1;
      entry.external_effect_issued = true;
    } catch (error) {
      // The boundary cannot prove the absence of an external effect, so an
      // unknown outcome is escalated, never retried.
      const failure = toBoardError(error, 'UNKNOWN_OUTCOME');
      await store.escalateOutbox({
        outboxId: row.outbox_id,
        reason: `UNKNOWN_OUTCOME:${failure.code}:${String(failure.message).slice(0, 200)}`,
        actor: actorId,
        idempotencyKey: stageKey({ command: 'outbox.dispatch', stage: 'escalate-error', actorId, args: { outbox_id: row.outbox_id, code: failure.code } }),
        argsDigest: stageKey({ command: 'outbox.dispatch', stage: 'escalate-error', actorId, args: { outbox_id: row.outbox_id, code: failure.code } }),
        operation: 'outbox.escalate',
      });
      summary.escalated += 1;
      entry.dispatch_state = 'RECONCILIATION_REQUIRED';
      entry.error_code = failure.code;
      summary.rows.push(entry);
      continue;
    }

    if (acknowledged) {
      const ackDigest = stageKey({ command: 'outbox.dispatch', stage: 'ack', actorId, args: { outbox_id: row.outbox_id } });
      await store.markOutboxAcked({
        outboxId: row.outbox_id,
        actor: actorId,
        idempotencyKey: ackDigest,
        argsDigest: ackDigest,
        operation: 'outbox.ack',
      });
      summary.acked += 1;
      entry.dispatch_state = 'ACKED';
    } else {
      const refuseDigest = stageKey({ command: 'outbox.dispatch', stage: 'refused', actorId, args: { outbox_id: row.outbox_id } });
      await store.escalateOutbox({
        outboxId: row.outbox_id,
        reason: 'UNKNOWN_OUTCOME: the transport refused the dispatch after the send intent was recorded',
        actor: actorId,
        idempotencyKey: refuseDigest,
        argsDigest: refuseDigest,
        operation: 'outbox.escalate',
      });
      summary.escalated += 1;
      entry.dispatch_state = 'RECONCILIATION_REQUIRED';
    }
    summary.rows.push(entry);
  }

  if (summary.escalated > 0) {
    const error = new ReconciliationRequired(
      'RECONCILIATION_REQUIRED',
      `${summary.escalated} outbox row(s) have an unknown external outcome and must be decided by an authenticated human or an authorized deterministic gate`,
    );
    error.summary = summary;
    throw error;
  }
  return summary;
}

/**
 * Rebuild canonical outbox state WITHOUT reissuing a side effect.
 *
 * There is deliberately no `transport` parameter: this function cannot send
 * even if a caller wanted it to. SENT-without-ack rows are escalated to
 * RECONCILIATION_REQUIRED (the effect may already have happened), PENDING rows
 * are reported as re-dispatchable and left alone, and ACKED rows are history.
 * When an id factory is supplied the unknown outcome is also appended to the
 * execution journal as a contract-valid `UNKNOWN` event, so the append-only
 * record explains the escalation instead of leaving a silent gap.
 *
 * `workspaceId` is REQUIRED (same reason as in driveOutbox) and `ids` is
 * optional: without an injected id factory no journal entry is appended, and
 * the summary says so instead of inventing an identifier.
 */
export async function recoverOutbox({ store, actor, now, limit, workspaceId, workspace_id: workspaceAlias, ids = null } = {}) {
  if (!isPlainObject(store)) throw new NeedsInput('STORE_MISSING');
  workspaceId = workspaceId ?? workspaceAlias;
  if (typeof workspaceId !== 'string' || workspaceId.length === 0) throw new NeedsInput('OUTBOX_WORKSPACE_REQUIRED');
  const instant = toInjectedInstant(now, 'now');
  const { actorId } = normalizeActor(actor);
  const batch = boundedLimit(limit);

  const listFor = async (dispatchState) => {
    const rows = await store.listOutbox({ workspaceId, dispatchState, principalId: actorId });
    return (Array.isArray(rows) ? rows : [])
      .filter((row) => isPlainObject(row) && row.dispatch_state === dispatchState && row.workspace_id === workspaceId);
  };

  const [pendingRows, sentRows] = await Promise.all([listFor('PENDING'), listFor('SENT')]);
  pendingRows.sort(outboxOrder);
  sentRows.sort(outboxOrder);

  const summary = {
    now: instant,
    actor: actorId,
    inspected: pendingRows.length + sentRows.length,
    pending: 0,
    escalated: 0,
    acked: 0,
    journalAppended: 0,
    externalEffectsIssued: 0,
    rows: [],
  };

  for (const row of pendingRows.slice(0, batch)) {
    // A crash before the send intent leaves a legitimately re-dispatchable
    // row. Recovery reports it and touches nothing.
    summary.pending += 1;
    summary.rows.push({ outbox_id: row.outbox_id, dispatch_state: 'PENDING', action: 'none', re_dispatchable: true });
  }

  for (const row of sentRows.slice(0, batch)) {
    const escalateDigest = stageKey({
      command: 'outbox.recover',
      stage: 'escalate',
      actorId,
      args: { outbox_id: row.outbox_id, idempotency_key: row.idempotency_key, payload_digest: row.payload_digest },
    });
    await store.escalateOutbox({
      outboxId: row.outbox_id,
      reason: 'UNKNOWN_OUTCOME: sent without an acknowledgement; observation or an authorized reconciliation decision is required',
      actor: actorId,
      idempotencyKey: escalateDigest,
      argsDigest: escalateDigest,
      operation: 'outbox.escalate',
    });
    summary.escalated += 1;
    summary.rows.push({ outbox_id: row.outbox_id, dispatch_state: 'RECONCILIATION_REQUIRED', action: 'escalated', re_dispatchable: false });

    // Optional journal entry so the append-only record explains the gap. Every
    // identifier is resolved from the run or the recorded payload; an event is
    // never written with an invented id, because a fabricated lease id in an
    // append-only journal is a fabricated fact. Without a resolvable identity
    // the escalation above stands alone and the reason is reported.
    if (ids && typeof row.run_id === 'string') {
      try {
        const run = await store.readRun(row.run_id, { principalId: actorId, workspaceId });
        const runId = isPlainObject(run) && typeof run.run_id === 'string' ? run.run_id : row.run_id;
        const leaseId = firstIdentifier(run?.lease_id, row.payload?.lease_id, row.lease_id);
        const taskId = firstIdentifier(run?.task_id, row.payload?.task_id, row.task_id);
        const workspaceOfEvent = firstIdentifier(run?.workspace_id, row.payload?.workspace_id, row.workspace_id);
        if (runId === null || leaseId === null || taskId === null || workspaceOfEvent === null) {
          throw new NeedsInput('OUTBOX_JOURNAL_IDENTITY_UNRESOLVED', `run ${runId}: the lease/task/workspace identity is not readable`);
        }
        const lastSequence = isPlainObject(run) ? asFiniteNumber(run.last_sequence) ?? 0 : 0;
        const event = {
          contract_version: 'veritas.execution/1.0.0',
          event_id: resolveId(ids, 'event', Math.trunc(lastSequence) + 1),
          run_id: runId,
          task_id: taskId,
          workspace_id: workspaceOfEvent,
          lease_id: leaseId,
          fencing_token: isPlainObject(run) ? asFiniteNumber(run.fencing_token) ?? 0 : 0,
          sequence: Math.trunc(lastSequence) + 1,
          event_type: 'UNKNOWN',
          payload: {
            outbox_id: row.outbox_id,
            dispatch_state: 'SENT_WITHOUT_ACK',
            note: 'data only; it grants nothing and decides nothing',
          },
          outcome: 'RECONCILIATION_REQUIRED',
          emitted_at: instant,
        };
        assertBoardContract('execution-event', event);
        // A DIFFERENT idempotency key from the escalation above: one key per
        // operation. Reusing the escalation key would be an IDEMPOTENCY_CONFLICT
        // against the ledger entry the escalation just wrote, which would
        // silently cost the journal entry on every recovery.
        const journalDigest = stageKey({
          command: 'outbox.recover',
          stage: 'journal',
          actorId,
          args: { outbox_id: row.outbox_id, event_id: event.event_id, sequence: event.sequence },
        });
        await store.appendExecutionEvent({
          event,
          actor: actorId,
          idempotencyKey: journalDigest,
          argsDigest: journalDigest,
          operation: 'execution.event',
        });
        summary.journalAppended += 1;
      } catch (error) {
        // The journal is a defence-in-depth record here; the escalation above
        // is the canonical state and must never be undone by a journal miss.
        summary.rows[summary.rows.length - 1].journal_error = toBoardError(error, 'PROVIDER_FAILURE').code;
      }
    }
  }

  return summary;
}
