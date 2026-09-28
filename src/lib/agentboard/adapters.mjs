// S2-007 Agent Board execution boundary (issue #7 §4, §5, §8).
//
// WHY this file exists
// ---------------------
// Veritas owns the task, the frozen brief, the policy, the grant, the budget,
// the lease and the evidence. An executor is a SEPARATE engine (AgentOS /
// Codex / pi); this module is the only place where Veritas speaks to one, and
// it owns four things:
//
//   1. SHAPE COMES FROM ONE PLACE. Every document that crosses the boundary is
//      validated through contracts.mjs (assertBoardContract /
//      assertExecutionVersion) BEFORE the caller sees it. This file declares no
//      state, no transition, no error code and no payload shape of its own.
//      Where a value must belong to a closed enum that lives in a frozen
//      schema (health, event_type, outcome), this file asks the schema to
//      adjudicate instead of keeping a second copy of the list — see
//      assertHealthValue() and verifyEventOutcomeDerivation().
//   2. DATA IS NOT AUTHORITY. A scripted step, an event payload, a result
//      document and a replayed record are DATA. They can never grant a
//      capability, widen a tool set, name a principal, move a task to DONE or
//      decide a verdict. A capability an adapter reports is a CLAIM and is
//      cross-checked against the operator registration AND the current grant
//      (crossCheckCapabilities).
//   3. FAIL CLOSED, ALWAYS TYPED. Every method of every transport rejects with
//      a BoardError from errors.mjs — never a plain Error, never a silent
//      success, never an exception mapped to a semantic verdict. An unknown
//      external side effect is UNKNOWN_OUTCOME / RECONCILIATION_REQUIRED, is
//      non-retryable by construction, and closes only through observation or a
//      separately authorized reconciliation decision.
//   4. HONEST STATUS. Nothing here claims a real executor ran. The scripted
//      and replayed transports exist to make the boundary testable, and both
//      are recorded as NOT_RUN_REAL_ADAPTER (issue §4, §8).
//
// STRUCTURAL IMPOSSIBILITY OF A "REAL" ADAPTER FROM THIS FILE
// -----------------------------------------------------------
// `createTestTransport` and `createReplayTransport` are the only constructors
// here and both call one private builder, `buildRegistration`, in which
// `adapter_kind` and `real_adapter_provenance.status` are LITERAL constants
// chosen by this file: 'test' for the scripted transport, 'wrapper' for the
// replay transport, and 'NOT_RUN_REAL_ADAPTER' for both. The caller's
// `provenance` argument is NEVER a source for those two fields — it is only
// inspected in order to REJECT an attempt to widen them, and the assembled
// registration is validated against the frozen schema and deep-frozen before
// it is handed out. There is therefore no argument value, no script step and
// no code path in this file that can turn a mock, a wrapper or a replay into
// adapter_kind 'real' or provenance REAL_ADAPTER_AVAILABLE. Honesty about the
// host comes from probeRealAdapters, which reports one narrow fact — an
// executable with a given name is on PATH — and nothing more. An installed
// executable is a HOST FACT; it is not evidence that a Veritas adapter ran a
// task for the board, and it never upgrades a run's NOT_RUN_REAL_ADAPTER.
//
// DETERMINISM
// -----------
// No Date.now(), no new Date() without the injected clock, no Math.random(),
// no process.hrtime, and no environment variable is ever read as authority.
// The clock is REQUIRED. The id factory is optional; when it is absent, ids
// are DERIVED as a pure function of (run id, id name, sequence) through the
// S2-006 canonical-json-v1 digest convention, which is deterministic and not
// random. When it is present it must return ids carrying the frozen prefix
// from ID_PREFIXES, or the call fails closed with MALFORMED_RESULT.
//
// WHAT IS VALIDATED WHERE
// -----------------------
//   identify()      -> adapter-registration (deep frozen)
//   capabilities() -> discovery view derived from the registration; a claimed
//                     capability/tool not covered by the registration is
//                     CAPABILITY_MISMATCH
//   health()        -> small view; the `health` value itself is adjudicated by
//                     the adapter-registration schema, so the enum is never
//                     duplicated here
//   claim()         -> fenced lease acknowledgement
//   start(request)  -> validates the inbound ExecutionRequest, returns the
//                      ACCEPTED ExecutionEvent. All ten methods take ONE call
//                      object; because the ExecutionRequest is a whole contract
//                      document, start() also accepts the uniform form
//                      start({ request, run_id })
//   status()        -> ExecutionEvent
//   checkpoint()    -> ExecutionEvent (CHECKPOINT) bound to brief/workspace/
//                     tool digests
//   cancel()        -> ExecutionEvent (CANCELLED)
//   collect_result()-> ExecutionResult
//   release()       -> fenced lease acknowledgement
//
// The lease acknowledgement is the single smallest local extension in this
// file: the board has no contract document for a lease receipt (lease.schema
// .json is the S2-001 record, not a boundary acknowledgement, and it is not one
// of the eight board contracts), so claim/release return a minimal, frozen,
// fully checked descriptor whose ids are validated against the frozen
// ID_PREFIXES. Everything else that crosses the boundary is a frozen contract
// document.
//
// On the REPLAY transport claim/release only acknowledge the lease named by the
// record (marked `replayed: true`) so the crash/restart path can reconstruct
// and free a lease whose run is known solely from the record. They never take a
// lease and never reissue a side effect.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
// S2-002 remains the single source of sandbox profiles; a transport that
// executes nothing is honestly bound to the NO_EXEC profile rather than to an
// isolation tier it never used.
import { SANDBOX_NO_EXEC } from '../identity/sandbox-profiles.mjs';
// S2-006 remains the single digest convention.
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import {
  ADAPTER_INTERFACE_VERSION,
  ADAPTER_METHODS,
  BOARD_CONTRACT_VERSION,
  ERROR_CODES,
  EXECUTION_CONTRACT_VERSION,
  ID_PREFIXES,
} from './constants.mjs';
import {
  assertBoardContract,
  assertExecutionVersion,
} from './contracts.mjs';
import {
  BlockedPolicy,
  Cancelled,
  CapabilityMismatch,
  EmptyResponse,
  MalformedResult,
  NeedsInput,
  NotRunRealAdapter,
  StaleFence,
  TimeoutError,
  errorClassForCode,
  isBoardError,
  redact,
  toBoardError,
} from './errors.mjs';

export const ADAPTERS_VERSION = 's2-007-adapters-v1';

// Candidate executables for the host probe. This is the probe's own table, not
// a contract: it names what a "genuinely different installed executor" would
// be called on a developer host. `kind` is used structurally — a candidate
// declared as a mock/wrapper/test/replay can never be reported as installed.
export const REAL_ADAPTER_PROBE_CANDIDATES = Object.freeze([
  Object.freeze({ adapter_id: 'adr-codex-local', provider: 'codex', kind: 'real', executables: Object.freeze(['codex']) }),
  Object.freeze({ adapter_id: 'adr-pi-local', provider: 'pi', kind: 'real', executables: Object.freeze(['pi']) }),
  Object.freeze({ adapter_id: 'adr-claude-code-local', provider: 'claude_code', kind: 'real', executables: Object.freeze(['claude']) }),
  Object.freeze({ adapter_id: 'adr-opencode-local', provider: 'opencode', kind: 'real', executables: Object.freeze(['opencode']) }),
  Object.freeze({ adapter_id: 'adr-hermes-local', provider: 'hermes', kind: 'real', executables: Object.freeze(['hermes']) }),
  Object.freeze({ adapter_id: 'adr-generic-cli', provider: 'generic_cli', kind: 'real', executables: Object.freeze(['veritas-adapter-generic']) }),
]);

// A candidate that is not a real executor can never be reported as installed.
const NEVER_INSTALLABLE_KINDS = new Set([
  'mock', 'wrapper', 'test', 'replay', 'fixture', 'stub', 'fake', 'simulated',
]);

// Terminal event type -> the outcome it implies. Both lists are defined ONLY in
// contracts/execution-event.schema.json; this table is the boundary's semantic
// derivation ("a TIMED_OUT event means the outcome is TIMEOUT") and it is
// checked against the schema at import time by verifyEventOutcomeDerivation(),
// so it can never drift into a second, weaker enum.
const OUTCOME_BY_EVENT_TYPE = Object.freeze({
  COMPLETED: 'SUCCEEDED',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED',
  TIMED_OUT: 'TIMEOUT',
  UNKNOWN: 'RECONCILIATION_REQUIRED',
});
const TERMINAL_EVENT_TYPES = new Set(Object.keys(OUTCOME_BY_EVENT_TYPE));

// The single hard-coded honesty pair. See the header comment: these values are
// chosen by this file and are never taken from a caller.
const TRANSPORT_KINDS = Object.freeze({ test: 'test', replay: 'wrapper' });
const TRANSPORT_PROVENANCE_STATUS = 'NOT_RUN_REAL_ADAPTER';

// Canonical argument sets of the boundary calls. A key outside the set is a
// REFUSED call (BLOCKED_POLICY), not a silently ignored field: an unknown
// argument is how a caller tries to hand authority (principal, scope, budget,
// approval, verdict) to the executor. The board-level canonical-argument check
// stays in policy.mjs; this is the transport-side mirror of the confused-deputy
// rule, and it is intentionally strict.
const CANONICAL_ARGS = Object.freeze({
  identify: Object.freeze([]),
  capabilities: Object.freeze(['claimed', 'claimed_capabilities', 'claimed_tools']),
  health: Object.freeze([]),
  claim: Object.freeze(['task_id', 'workspace_id', 'lease_id', 'fencing_token', 'adapter_id', 'ttl_ms', 'at']),
  // start() takes the run identity explicitly: ExecutionRequest is the handoff
  // document and deliberately carries no run_id — the run row (and its id) is
  // the board's, and the executor may not invent a run identity.
  start: Object.freeze(['run_id', 'workspace_id', 'at']),
  status: Object.freeze(['run_id', 'task_id', 'lease_id', 'fencing_token', 'expected_sequence', 'at']),
  checkpoint: Object.freeze(['run_id', 'task_id', 'lease_id', 'fencing_token', 'brief_digest', 'workspace_digest', 'tool_digest', 'expected_sequence', 'at']),
  cancel: Object.freeze(['run_id', 'task_id', 'lease_id', 'fencing_token', 'reason', 'at']),
  collect_result: Object.freeze(['run_id', 'task_id', 'lease_id', 'fencing_token', 'expected_sequence', 'at']),
  release: Object.freeze(['task_id', 'lease_id', 'fencing_token', 'run_id', 'reason', 'at']),
});

const REQUIRED_ARGS = Object.freeze({
  claim: Object.freeze(['task_id', 'lease_id', 'fencing_token']),
  start: Object.freeze(['run_id']),
  status: Object.freeze(['run_id', 'lease_id', 'fencing_token']),
  checkpoint: Object.freeze(['run_id', 'lease_id', 'fencing_token', 'brief_digest', 'workspace_digest', 'tool_digest']),
  cancel: Object.freeze(['run_id', 'lease_id', 'fencing_token']),
  collect_result: Object.freeze(['run_id', 'lease_id', 'fencing_token']),
  release: Object.freeze(['task_id', 'lease_id', 'fencing_token']),
});

// Failure codes whose external side effect is unknown. After such a failure
// the transport asserts NOTHING further about the run: every run-level call
// rejects with the same non-retryable code, because only observation or an
// authorized reconciliation decision may close it, and a producer may never be
// that decision.
const UNKNOWN_CODES = new Set(['UNKNOWN_OUTCOME', 'RECONCILIATION_REQUIRED']);

// --- small helpers ---------------------------------------------------------

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(value, label) {
  if (!isPlainObject(value)) throw new NeedsInput(`${label}: object required`);
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new NeedsInput(`${label}: array required`);
  return value;
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new NeedsInput(`${label}: non-empty string required`);
  return value;
}

function requireInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) throw new NeedsInput(`${label}: non-negative integer required`);
  return value;
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return Object.freeze(value);
}

function sortedUnique(list) {
  return [...new Set(list)].sort();
}

// The clock is required and is the only source of "now" in this file. An ISO
// string or a Date is accepted for convenience; both are caller-injected
// values, never the process clock.
function requireClock(clock) {
  if (typeof clock === 'string' || clock instanceof Date) {
    const fixed = new Date(clock);
    if (Number.isNaN(fixed.getTime())) throw new NeedsInput('CLOCK_SHAPE: ISO string or Date required');
    return { now: () => new Date(fixed.getTime()) };
  }
  if (isPlainObject(clock) && typeof clock.now === 'function') {
    const probe = clock.now();
    if (!(probe instanceof Date) || Number.isNaN(probe.getTime())) {
      throw new NeedsInput('CLOCK_SHAPE: now() must return a valid Date');
    }
    return { now: () => clock.now() };
  }
  throw new NeedsInput('CLOCK_REQUIRED: an injected clock is mandatory; the process clock is never read');
}

function timestampOf(clock) {
  const value = clock.now();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new NeedsInput('CLOCK_SHAPE: now() must return a valid Date');
  }
  return value.toISOString();
}

// ids(name, seed) -> `${ID_PREFIXES[name]}${sha256(canonical)[0..32]}`:
// deterministic (no randomness, no clock), contract-shaped and stable for the
// same run. Used when the caller injects no id factory; when a factory IS
// injected it must honour the same frozen prefixes or the call fails closed.
function derivedId(name, seed) {
  const prefix = ID_PREFIXES[name];
  if (typeof prefix !== 'string') throw new NeedsInput(`ID_KIND_UNKNOWN:${name}`);
  return `${prefix}${canonicalDigest({ name, seed: String(seed) }).slice(0, 32)}`;
}

function requireIdFactory(ids) {
  if (ids === undefined || ids === null) return (name, seed) => derivedId(name, seed);
  if (typeof ids !== 'function') throw new NeedsInput('ID_FACTORY_SHAPE: (name, seed) => id required');
  return (name, seed) => {
    const prefix = ID_PREFIXES[name];
    const value = ids(name, seed);
    if (typeof prefix !== 'string' || typeof value !== 'string' || !value.startsWith(prefix)) {
      throw new MalformedResult(
        `ID_FACTORY_SHAPE:${name}`,
        `injected id for ${name} must be a string starting with ${String(prefix)}`,
      );
    }
    return value;
  };
}

// ---------------------------------------------------------------------------
// S2-001 interface check
// ---------------------------------------------------------------------------

/**
 * The ten S2-001 adapter methods (constants.mjs ADAPTER_METHODS) must all be
 * present and must all be `async` functions. A method that is missing, is not
 * a function, or is a plain function that merely happens to return a promise is
 * a CAPABILITY_MISMATCH: a non-async method can throw synchronously, and a
 * synchronous throw from inside the board's async chain is exactly the shape of
 * an untyped error escaping the execution boundary.
 */
export function assertAdapterInterface(adapter) {
  if (adapter === null || typeof adapter !== 'object') {
    throw new CapabilityMismatch('ADAPTER_INTERFACE_SHAPE: adapter object required');
  }
  const problems = [];
  for (const name of ADAPTER_METHODS) {
    const method = adapter[name];
    if (typeof method !== 'function') {
      problems.push(`${name}:missing_or_not_a_function`);
      continue;
    }
    if (method.constructor?.name !== 'AsyncFunction') problems.push(`${name}:not_async`);
  }
  if (problems.length > 0) {
    throw new CapabilityMismatch(
      `ADAPTER_INTERFACE_INCOMPLETE:${ADAPTER_INTERFACE_VERSION}`,
      `missing or non-async adapter methods: ${problems.join(', ')}`,
    );
  }
  return adapter;
}

// ---------------------------------------------------------------------------
// Capability cross-check: registration vs claim vs grant
// ---------------------------------------------------------------------------

// A claim or a grant may be a bare list of capabilities or an object with
// explicit `capabilities` / `tools` dimensions. A dimension the grant does not
// declare is granted NOTHING (fail closed) — an absent grant is not "any".
function normalizeClaimSet(value, label) {
  if (value === undefined || value === null) {
    return { capabilities: [], tools: [] };
  }
  if (Array.isArray(value)) {
    return {
      capabilities: value.map((item) => requireString(item, label)),
      tools: [],
    };
  }
  const object = requireObject(value, label);
  const capabilities = object.capabilities === undefined || object.capabilities === null
    ? [] : requireArray(object.capabilities, `${label}.capabilities`);
  const tools = object.tools === undefined || object.tools === null
    ? [] : requireArray(object.tools, `${label}.tools`);
  return {
    capabilities: capabilities.map((item) => requireString(item, `${label}.capabilities`)),
    tools: tools.map((item) => requireString(item, `${label}.tools`)),
  };
}

function uncoveredItems(claimedItems, coveringItems) {
  const covering = new Set(coveringItems);
  return claimedItems.filter((item) => !covering.has(item)).sort();
}

/**
 * A self-declared capability is a CLAIM, never a permission (issue §4,
 * PRODUCT_CONTRACT §"Adapter interface"). Three rules, in this order:
 *
 *   1. every claimed capability/tool must be covered by the operator
 *      registration — an adapter may not report more than it was registered
 *      with;
 *   2. every granted capability/tool must also be covered by the registration
 *      — a grant the registration does not describe is a mismatch, not a
 *      silent widening in either direction;
 *   3. a registration MAY declare more than the current grant. That surplus is
 *      never used to widen anything: the effective set returned here is the
 *      intersection of claim, registration and grant, and a dimension the
 *      grant does not declare yields the empty set.
 */
export function crossCheckCapabilities({ registration, claimed, grant } = {}) {
  const reg = assertBoardContract('adapter-registration', requireObject(registration, 'registration'));
  const claim = normalizeClaimSet(claimed, 'claimed');
  const granted = normalizeClaimSet(grant, 'grant');

  const unclaimed = {
    capabilities: uncoveredItems(claim.capabilities, reg.declared_capabilities),
    tools: uncoveredItems(claim.tools, reg.declared_tools),
  };
  const unregistered = {
    capabilities: uncoveredItems(granted.capabilities, reg.declared_capabilities),
    tools: uncoveredItems(granted.tools, reg.declared_tools),
  };

  if (unclaimed.capabilities.length > 0 || unclaimed.tools.length > 0) {
    throw new CapabilityMismatch(
      'ADAPTER_CLAIM_NOT_REGISTERED',
      `adapter ${reg.adapter_id} claims capabilities/tools absent from its registration: `
      + `${[...unclaimed.capabilities, ...unclaimed.tools].join(', ')}`,
    );
  }
  if (unregistered.capabilities.length > 0 || unregistered.tools.length > 0) {
    throw new CapabilityMismatch(
      'GRANT_NOT_REGISTERED',
      `grant for adapter ${reg.adapter_id} names capabilities/tools absent from its registration: `
      + `${[...unregistered.capabilities, ...unregistered.tools].join(', ')}`,
    );
  }

  return deepFreeze({
    adapter_id: reg.adapter_id,
    adapter_kind: reg.adapter_kind,
    provider: reg.provider,
    claimed_capabilities: sortedUnique(claim.capabilities),
    claimed_tools: sortedUnique(claim.tools),
    granted_capabilities: sortedUnique(granted.capabilities),
    granted_tools: sortedUnique(granted.tools),
    // The intersection — never the registration's own, possibly wider, set.
    effective_capabilities: sortedUnique(claim.capabilities.filter((item) => granted.capabilities.includes(item))),
    effective_tools: sortedUnique(claim.tools.filter((item) => granted.tools.includes(item))),
    registration_wider_than_grant: reg.declared_capabilities.length > granted.capabilities.length
      || reg.declared_tools.length > granted.tools.length,
    provenance_status: reg.real_adapter_provenance.status,
  });
}

// ---------------------------------------------------------------------------
// Adapter registration — the honesty boundary
// ---------------------------------------------------------------------------

/**
 * Assemble an AdapterRegistration whose honesty fields are LITERAL constants of
 * this file. The caller's `provenance` may describe the registration
 * (workspace, principal, declared capabilities, display name, health) but it
 * can never widen `adapter_kind` or `real_adapter_provenance.status`: an
 * attempt to do so is refused loudly with NOT_RUN_REAL_ADAPTER instead of being
 * silently honoured or silently ignored.
 */
function buildRegistration({ kind, source, provenance, clock, registeredAt, detail }) {
  const meta = provenance === undefined || provenance === null ? {} : requireObject(provenance, 'provenance');
  const expectedKind = TRANSPORT_KINDS[kind];
  if (typeof expectedKind !== 'string') throw new NeedsInput(`TRANSPORT_KIND_UNKNOWN:${String(kind)}`);

  const requestedKind = meta.adapter_kind ?? meta.kind;
  if (requestedKind !== undefined && requestedKind !== expectedKind) {
    throw new NotRunRealAdapter(
      'ADAPTER_KIND_NOT_ASSIGNABLE',
      `this file only builds adapter_kind '${expectedKind}'; '${String(requestedKind)}' is not assignable by a ${source} transport`,
    );
  }
  const requestedStatus = meta.real_adapter_provenance?.status ?? meta.provenance_status ?? meta.status;
  if (requestedStatus !== undefined && requestedStatus !== TRANSPORT_PROVENANCE_STATUS) {
    throw new NotRunRealAdapter(
      'PROVENANCE_NOT_ASSIGNABLE',
      `this file only builds real_adapter_provenance.status '${TRANSPORT_PROVENANCE_STATUS}'; `
      + `'${String(requestedStatus)}' is not assignable by a ${source} transport`,
    );
  }

  const registration = {
    contractVersion: BOARD_CONTRACT_VERSION,
    adapter_id: meta.adapter_id ?? `adr-${expectedKind}-${source}`,
    adapter_interface: ADAPTER_INTERFACE_VERSION,
    provider: meta.provider ?? 'test',
    display_name: meta.display_name ?? `Veritas ${source} transport (${expectedKind})`,
    adapter_kind: expectedKind,
    health: meta.health ?? 'unknown',
    workspace_id: meta.workspace_id ?? `ws-${expectedKind}-${source}`,
    principal_id: meta.principal_id ?? `prn-${expectedKind}-${source}`,
    declared_capabilities: [...requireArray(meta.declared_capabilities ?? [], 'provenance.declared_capabilities')],
    declared_tools: [...requireArray(meta.declared_tools ?? [], 'provenance.declared_tools')],
    // A transport that executes nothing is bound to the NO_EXEC profile; it
    // never claims an isolation tier it did not use.
    sandbox_profile_id: meta.sandbox_profile_id ?? SANDBOX_NO_EXEC.profile_id,
    max_concurrency: 1,
    real_adapter_provenance: {
      status: TRANSPORT_PROVENANCE_STATUS,
      detail: requireString(meta.detail ?? detail, 'provenance.detail').slice(0, 500),
    },
    registered_at: registeredAt ?? timestampOf(clock),
  };

  // The frozen schema is the only authority on the shape, then the object is
  // frozen so no caller can rewrite adapter_kind or the provenance status.
  return deepFreeze(assertBoardContract('adapter-registration', registration));
}

// A small discovery view still has to be honest about the health enum, which
// lives only in the schema: adjudicate it by validating a registration clone.
function assertHealthValue(registration, health) {
  assertBoardContract('adapter-registration', { ...registration, health });
  return health;
}

// ---------------------------------------------------------------------------
// Scripted steps and injected failures
// ---------------------------------------------------------------------------

function normalizeScriptedEvent(raw, index) {
  const event = requireObject(raw, `script.events[${index}]`);
  return {
    event_type: requireString(event.event_type, `script.events[${index}].event_type`),
    sequence: event.sequence === undefined || event.sequence === null
      ? null : requireInteger(event.sequence, `script.events[${index}].sequence`),
    outcome: event.outcome === undefined ? null : event.outcome,
    payload: event.payload === undefined || event.payload === null
      ? {} : requireObject(event.payload, `script.events[${index}].payload`),
    at: event.at === undefined || event.at === null ? null : requireString(event.at, `script.events[${index}].at`),
    event_id: event.event_id === undefined || event.event_id === null ? null : requireString(event.event_id, `script.events[${index}].event_id`),
  };
}

function normalizeFailureEntry(raw, label) {
  if (typeof raw === 'string') {
    // Shorthand: a bare code injects a failure of the start() call, the point
    // at which an external side effect first happens. The code is checked
    // against the closed set here exactly as it is in the object form: a code
    // outside ERROR_CODES must fail closed at build time, never surface later
    // as an unmapped error.
    if (!ERROR_CODES.includes(raw)) throw new NeedsInput(`${label}.code: unknown board error code ${raw}`);
    return { method: 'start', code: raw, message: undefined };
  }
  const object = requireObject(raw, label);
  let method = object.method;
  let code = object.code;
  if (method === undefined) {
    const entries = Object.entries(object).filter(([key]) => !['code', 'message'].includes(key));
    if (entries.length !== 1) throw new NeedsInput(`${label}: { method, code } required`);
    const [entryMethod, entryCode] = entries[0];
    method = entryMethod;
    code = isPlainObject(entryCode) ? entryCode.code : entryCode;
  }
  requireString(method, `${label}.method`);
  if (!ADAPTER_METHODS.includes(method)) throw new NeedsInput(`${label}.method: unknown adapter method ${String(method)}`);
  requireString(code, `${label}.code`);
  if (!ERROR_CODES.includes(code)) throw new NeedsInput(`${label}.code: unknown board error code ${String(code)}`);
  return { method, code, message: object.message };
}

function normalizeFailures(script) {
  const collected = [];
  for (const source of [script.failures, script.failWith, script.fail_with]) {
    if (source === undefined || source === null) continue;
    if (typeof source === 'string') {
      // Bare-code shorthand: the failure lands on start(), the first call at
      // which an external side effect can happen.
      collected.push(normalizeFailureEntry(source, 'script.failWith'));
    } else if (Array.isArray(source)) {
      source.forEach((entry, index) => collected.push(normalizeFailureEntry(entry, `script.failures[${index}]`)));
    } else if (typeof source === 'object') {
      const keys = Object.keys(source);
      if (keys.length === 1 && (keys[0] === 'method' || keys[0] === 'code')) {
        collected.push(normalizeFailureEntry(source, 'script.failWith'));
      } else {
        for (const method of keys) {
          collected.push(normalizeFailureEntry({ method, code: source[method] }, `script.failWith.${method}`));
        }
        if (keys.length === 0) throw new NeedsInput('script.failWith: { method, code } required');
      }
    } else {
      throw new NeedsInput('script.failWith: string, array or object required');
    }
  }
  return collected;
}

function normalizeScript(script) {
  const raw = script === undefined || script === null ? {} : requireObject(script, 'script');
  const events = raw.events === undefined || raw.events === null
    ? [] : requireArray(raw.events, 'script.events').map(normalizeScriptedEvent);
  const timeoutAfter = raw.timeoutAfter ?? raw.timeout_after;
  return {
    events,
    result: raw.result === undefined || raw.result === null ? null : requireObject(raw.result, 'script.result'),
    failures: normalizeFailures(raw),
    health: raw.health === undefined || raw.health === null ? undefined : raw.health,
    timeout_after_sequence: timeoutAfter === undefined || timeoutAfter === null
      ? null : requireInteger(timeoutAfter, 'script.timeout_after'),
  };
}

// ---------------------------------------------------------------------------
// Boundary call argument checking
// ---------------------------------------------------------------------------

function assertCallArgs(method, args) {
  const allowed = CANONICAL_ARGS[method];
  const object = args === undefined || args === null ? {} : requireObject(args, `${method} arguments`);
  const unknown = Object.keys(object).filter((key) => !allowed.includes(key)).sort();
  if (unknown.length > 0) {
    // Refused, not ignored: an unknown argument is how a caller tries to hand
    // authority (principal, scope, budget, approval, verdict) to the executor.
    throw new BlockedPolicy(
      `BOUNDARY_ARGUMENT_NOT_CANONICAL:${method}`,
      `unexpected arguments for ${method}(): ${unknown.join(', ')}`,
    );
  }
  for (const key of REQUIRED_ARGS[method] ?? []) {
    if (object[key] === undefined || object[key] === null) {
      throw new NeedsInput(`BOUNDARY_ARGUMENT_MISSING:${method}.${key}`);
    }
  }
  return object;
}

function verifyExpectedSequence(args, expected) {
  if (args.expected_sequence === undefined || args.expected_sequence === null) return expected;
  const wanted = requireInteger(args.expected_sequence, 'expected_sequence');
  if (wanted !== expected) {
    const label = wanted < expected ? 'DUPLICATE' : 'OUT_OF_ORDER';
    throw new MalformedResult(
      `CALL_SEQUENCE_${label}:expected ${expected} got ${wanted}`,
      'the caller and the executor disagree about the run sequence; nothing is repaired by guesswork',
    );
  }
  return expected;
}

// ---------------------------------------------------------------------------
// The transport core shared by the scripted and the replay transport
// ---------------------------------------------------------------------------

function guard(state, body) {
  try {
    return body();
  } catch (error) {
    throw recordFailure(state, error);
  }
}

function recordFailure(state, error) {
  const typed = isBoardError(error) ? error : toBoardError(error);
  state.errors.push(deepFreeze(assertBoardContract('board-error', typed.toDocument(timestampOf(state.clock)))));
  return typed;
}

// Successive calls to the same method consume successive injected failures, so
// a probe can script "the first status fails, the second succeeds".
function takeFailure(state, method) {
  const index = state.failures.findIndex((entry) => entry.method === method);
  if (index === -1) return null;
  const [entry] = state.failures.splice(index, 1);
  const ErrorClass = errorClassForCode(entry.code);
  return { entry, error: new ErrorClass(entry.message ?? `${entry.code}: injected by the ${state.source} transport`) };
}

function buildLeaseAck({ operation, registration, lease, runId, clock, replayed, reason }) {
  return deepFreeze({
    contractVersion: BOARD_CONTRACT_VERSION,
    kind: 'lease-ack',
    operation,
    adapter_id: registration.adapter_id,
    adapter_kind: registration.adapter_kind,
    task_id: lease.task_id,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    run_id: runId ?? null,
    // A replayed acknowledgement states that a side effect was NOT reissued.
    replayed,
    reason: reason ?? null,
    acknowledged_at: timestampOf(clock),
  });
}

function createTransportCore({ kind, source, registration, clock, ids, script, replayRecord }) {
  const idFor = requireIdFactory(ids);
  const state = {
    kind,
    source,
    replay: replayRecord !== null,
    clock,
    registration,
    script,
    failures: [...script.failures],
    events: [],
    errors: [],
    checkpoints: [],
    artifacts: [],
    result: null,
    lease: null,
    run: null,
    unknownCode: null,
    released: null,
    replayCursor: 0,
  };

  // --- event emission ------------------------------------------------------
  // A sequence that is not exactly previous + 1 is REJECTED, never renumbered.
  // The board's store enforces the same rule independently, so a defect on
  // either side of the boundary still fails closed.
  function emitEvent(eventType, { outcome = null, payload = {}, at = null, eventId = null, sequence = null } = {}) {
    const run = state.run;
    const expected = run.last_sequence + 1;
    if (sequence !== null && sequence !== expected) {
      const label = sequence < expected ? 'DUPLICATE' : 'OUT_OF_ORDER';
      throw new MalformedResult(
        `EVENT_SEQUENCE_${label}:run ${run.run_id}:expected ${expected} got ${sequence}`,
        'events are append-only and gap-free; the boundary never repairs an ordering defect',
      );
    }
    const event = deepFreeze(assertBoardContract('execution-event', {
      contract_version: EXECUTION_CONTRACT_VERSION,
      event_id: eventId ?? idFor('event', `${run.run_id}:${expected}`),
      run_id: run.run_id,
      task_id: run.task_id,
      workspace_id: run.workspace_id,
      lease_id: run.lease_id,
      fencing_token: run.fencing_token,
      sequence: expected,
      event_type: eventType,
      // Payload is DATA. It is never interpreted as a grant, a system
      // instruction, an identity claim or a verdict.
      payload,
      outcome,
      emitted_at: at ?? timestampOf(state.clock),
    }));
    state.events.push(event);
    run.last_sequence = expected;
    if (eventType === 'CHECKPOINT') {
      state.checkpoints.push({
        checkpoint_id: payload.checkpoint_id ?? idFor('checkpoint', `${run.run_id}:${expected}`),
        sequence: expected,
        brief_digest: payload.brief_digest,
        workspace_digest: payload.workspace_digest,
        tool_digest: payload.tool_digest,
        recorded_at: event.emitted_at,
      });
    }
    if (eventType === 'ARTIFACT' && payload.artifact_id !== undefined) {
      state.artifacts.push({
        artifact_id: payload.artifact_id,
        digest: payload.digest,
        media_type: payload.media_type,
      });
    }
    return event;
  }

  // ONE scripted step per run-advancing call. The caller observes the run one
  // event at a time, exactly as a real executor emits them, so a duplicated or
  // out-of-order sequence is refused against the sequence the caller actually
  // expected instead of being hidden inside a batch. `collect_result` consumes
  // the remainder of the script through drainScriptedEvents().
  function takeScriptedStep() {
    // A recorded terminal outcome is final: no scripted step may follow it.
    if (state.script.events.length === 0 || terminalEvent() !== null) return null;
    const [next] = state.script.events.splice(0, 1);
    const payload = { ...next.payload };
    if (payload.checkpoint_id === undefined && next.event_type === 'CHECKPOINT') {
      payload.checkpoint_id = idFor('checkpoint', `${state.run.run_id}:${state.run.last_sequence + 1}`);
    }
    return emitEvent(next.event_type, {
      outcome: next.outcome,
      payload,
      at: next.at,
      eventId: next.event_id,
      sequence: next.sequence,
    });
  }

  // The remainder of the script, for the one call that legitimately consumes
  // everything: collecting the result of a run that was never polled.
  function drainScriptedEvents() {
    let last = null;
    for (;;) {
      const event = takeScriptedStep();
      if (event === null) return last;
      last = event;
      if (TERMINAL_EVENT_TYPES.has(event.event_type)) return last;
    }
  }

  // --- run binding ---------------------------------------------------------

  function requireRun() {
    if (state.run === null) {
      throw new NeedsInput('RUN_NOT_STARTED: the execution boundary is asked about a run that was never started');
    }
    return state.run;
  }

  // An unknown external side effect asserts nothing further. A producer may
  // not decide its own unknown outcome, and a blind retry is not available
  // because every one of these rejections is non-retryable.
  function rejectUnknownOutcome() {
    if (state.unknownCode === null) return;
    const ErrorClass = errorClassForCode(state.unknownCode);
    throw new ErrorClass(
      'RUN_OUTCOME_UNKNOWN',
      'the external side effect of this run is unknown; only observation or an authorized reconciliation decision closes it',
    );
  }

  function assertRunIdentity(args, run) {
    if (args.run_id !== undefined && args.run_id !== null && args.run_id !== run.run_id) {
      throw new MalformedResult(`RUN_ID_MISMATCH:expected ${run.run_id} got ${String(args.run_id)}`);
    }
    if (args.task_id !== undefined && args.task_id !== null && args.task_id !== run.task_id) {
      throw new MalformedResult(`TASK_ID_MISMATCH:expected ${run.task_id} got ${String(args.task_id)}`);
    }
    if (args.lease_id !== run.lease_id) {
      throw new MalformedResult(`RUN_LEASE_MISMATCH:expected ${run.lease_id} got ${String(args.lease_id)}`);
    }
    const fence = requireInteger(args.fencing_token, 'fencing_token');
    if (fence < run.fencing_token) {
      throw new StaleFence(
        `STALE_FENCE:run ${run.run_id}`,
        `presented fence ${fence} is behind the current fence ${run.fencing_token}; a late callback mutates nothing`,
      );
    }
    if (fence > run.fencing_token) {
      throw new MalformedResult(
        `FENCE_AHEAD_OF_RUN:presented ${fence} current ${run.fencing_token}`,
        'a caller may not present a fence the board has not issued for this run',
      );
    }
    return fence;
  }

  function assertWithinTimeout() {
    const limit = state.script.timeout_after_sequence;
    if (limit !== null && state.run !== null && state.run.last_sequence >= limit) {
      throw new TimeoutError(
        `RUN_TIMED_OUT:after sequence ${state.run.last_sequence}`,
        `the scripted budget timeout was reached at sequence ${limit}`,
      );
    }
  }

  function markFailure(error) {
    const run = state.run;
    if (run === null) return;
    if (UNKNOWN_CODES.has(error.code)) {
      run.unknown = true;
      state.unknownCode = error.code;
      return;
    }
    run.failed_error = error;
    if (error.code === 'TIMEOUT') run.timed_out = true;
    if (error.code === 'CANCELLED') run.cancelled = true;
  }

  // --- result assembly -----------------------------------------------------

  function terminalEvent() {
    return [...state.events].reverse().find((event) => TERMINAL_EVENT_TYPES.has(event.event_type)) ?? null;
  }

  // Success is never invented: with neither a terminal event nor a scripted
  // result there is no outcome to report, and EMPTY_RESPONSE is the honest
  // answer.
  function derivedOutcome() {
    const run = state.run;
    if (run.unknown) return 'RECONCILIATION_REQUIRED';
    if (run.cancelled) return 'CANCELLED';
    if (run.timed_out) return 'TIMEOUT';
    if (run.failed_error) return 'FAILED';
    const terminal = terminalEvent();
    return terminal ? OUTCOME_BY_EVENT_TYPE[terminal.event_type] : null;
  }

  function terminalErrorDocument(outcome, run) {
    if (state.script.result?.error) {
      return deepFreeze(assertBoardContract('board-error', state.script.result.error));
    }
    const scripted = terminalEvent()?.payload?.error_code;
    let code = null;
    if (typeof scripted === 'string' && ERROR_CODES.includes(scripted)) code = scripted;
    else if (run.unknown) code = state.unknownCode;
    else if (run.failed_error) code = run.failed_error.code;
    else if (outcome === 'FAILED') code = 'PROVIDER_FAILURE';
    else if (outcome === 'RECONCILIATION_REQUIRED') code = 'RECONCILIATION_REQUIRED';
    if (code === null) return null;
    const ErrorClass = errorClassForCode(code);
    return deepFreeze(assertBoardContract('board-error', new ErrorClass(
      code,
      `recorded terminal outcome ${outcome}`,
      'derived from the recorded boundary state; never a semantic verdict',
    ).toDocument(timestampOf(state.clock))));
  }

  function buildResult() {
    const run = state.run;
    const scripted = state.script.result ?? {};
    const outcome = scripted.outcome ?? derivedOutcome();
    if (outcome === null) {
      throw new EmptyResponse(
        'NO_RECORDED_OUTCOME',
        'the boundary produced neither a terminal event nor a scripted result; success is never invented',
      );
    }
    const error = outcome === 'SUCCEEDED' ? (scripted.error ?? null) : terminalErrorDocument(outcome, run);
    return deepFreeze(assertBoardContract('execution-result', {
      contract_version: EXECUTION_CONTRACT_VERSION,
      run_id: run.run_id,
      task_id: run.task_id,
      workspace_id: run.workspace_id,
      lease_id: run.lease_id,
      fencing_token: run.fencing_token,
      sequence: run.last_sequence,
      outcome,
      checkpoints: scripted.checkpoints ?? state.checkpoints.map((checkpoint) => ({ ...checkpoint })),
      artifact_hashes: scripted.artifact_hashes ?? state.artifacts.map((artifact) => ({ ...artifact })),
      // A transport spends nothing because it calls no model. Recording a
      // fabricated cost or model id would be a measurement that never
      // happened; the currency comes from the authorized budget grant.
      measurements: scripted.measurements ?? {
        duration_ms: 0,
        spend: 0,
        currency: run.budget_currency,
        model_id: null,
        tool_calls: state.events.length,
      },
      error,
      reconciliation_required: outcome === 'RECONCILIATION_REQUIRED'
        || error?.code === 'UNKNOWN_OUTCOME'
        || error?.code === 'RECONCILIATION_REQUIRED',
      completed_at: scripted.completed_at ?? timestampOf(state.clock),
    }));
  }

  // --- replay helpers ------------------------------------------------------
  // A replay RE-CONSTRUCTS: it never reissues a side effect and never re-derives
  // an outcome. Every replayed call reads the recorded record and nothing else.

  function recordedEvents() {
    return replayRecord.events;
  }

  function assertReplayIdentity(args, { requireDigests = false } = {}) {
    const { result } = replayRecord;
    requireString(args.run_id, 'run_id');
    requireString(args.lease_id, 'lease_id');
    requireInteger(args.fencing_token, 'fencing_token');
    if (args.run_id !== result.run_id || args.lease_id !== result.lease_id) {
      throw new MalformedResult('REPLAY_RUN_MISMATCH: the call does not name the recorded run');
    }
    if (args.task_id !== undefined && args.task_id !== null && args.task_id !== result.task_id) {
      throw new MalformedResult('REPLAY_RUN_MISMATCH: task_id does not name the recorded run');
    }
    if (args.fencing_token < result.fencing_token) {
      throw new StaleFence(
        `STALE_FENCE:replay ${result.run_id}`,
        `presented fence ${args.fencing_token} is behind the recorded fence ${result.fencing_token}`,
      );
    }
    if (requireDigests) {
      if (args.brief_digest !== replayRecord.request?.brief_digest) {
        throw new MalformedResult(
          'CHECKPOINT_BRIEF_MISMATCH',
          'a replay cannot invent a checkpoint under digests the recorded run did not authorize',
        );
      }
    }
  }

  function requireRecordedEvents() {
    if (recordedEvents().length === 0) {
      throw new NeedsInput('RECORDED_RUN_HAS_NO_EVENTS: a replay cannot invent the acceptance it did not record');
    }
    return recordedEvents();
  }

  // --- the ten methods -----------------------------------------------------
  // All ten are declared `async` on the returned object: assertAdapterInterface
  // rejects a synchronous method, because a synchronous throw from inside the
  // board's async chain is an untyped error escaping the execution boundary.

  const transport = {
    async identify(args) {
      return guard(state, () => {
        assertCallArgs('identify', args);
        // Identity IS the registration: it is the only self-description the
        // board accepts, and it can never say 'real'.
        return state.registration;
      });
    },

    async capabilities(args) {
      return guard(state, () => {
        const object = assertCallArgs('capabilities', args);
        const registration = state.registration;
        const claimedCapabilities = object.claimed_capabilities
          ?? (object.claimed === undefined || object.claimed === null
            ? undefined
            : (Array.isArray(object.claimed) ? object.claimed : object.claimed.capabilities));
        const claimedTools = object.claimed_tools
          ?? (object.claimed === undefined || object.claimed === null || Array.isArray(object.claimed)
            ? undefined
            : object.claimed.tools);
        // Self-check the adapter's own claim against its own registration: a
        // transport reporting more than it was registered with is a
        // CAPABILITY_MISMATCH, never a silent widening.
        if (claimedCapabilities !== undefined || claimedTools !== undefined) {
          crossCheckCapabilities({
            registration,
            claimed: { capabilities: claimedCapabilities ?? [], tools: claimedTools ?? [] },
            grant: {
              capabilities: [...registration.declared_capabilities],
              tools: [...registration.declared_tools],
            },
          });
        }
        return deepFreeze({
          adapter_id: registration.adapter_id,
          adapter_interface: registration.adapter_interface,
          adapter_kind: registration.adapter_kind,
          capabilities: [...registration.declared_capabilities],
          tools: [...registration.declared_tools],
          sandbox_profile_id: registration.sandbox_profile_id,
          provenance_status: registration.real_adapter_provenance.status,
        });
      });
    },

    async health(args) {
      return guard(state, () => {
        assertCallArgs('health', args);
        const registration = state.registration;
        // The health value is adjudicated by the registration schema, so the
        // enum is never duplicated here.
        const health = assertHealthValue(registration, script.health ?? registration.health);
        return deepFreeze({
          adapter_id: registration.adapter_id,
          health,
          adapter_kind: registration.adapter_kind,
          provenance_status: registration.real_adapter_provenance.status,
          checked_at: timestampOf(state.clock),
        });
      });
    },

    async claim(args) {
      return guard(state, () => {
        const object = assertCallArgs('claim', args);
        const lease = {
          task_id: requireString(object.task_id, 'task_id'),
          lease_id: requireString(object.lease_id, 'lease_id'),
          fencing_token: requireInteger(object.fencing_token, 'fencing_token'),
          adapter_id: object.adapter_id ?? state.registration.adapter_id,
        };
        if (state.replay) {
          // A replay ACKNOWLEDGES the recorded lease; it never takes one. The
          // acknowledgement is marked replayed so the board can tell a
          // reconstruction from a fresh side effect.
          const recorded = replayRecord.result;
          if (lease.task_id !== recorded.task_id || lease.lease_id !== recorded.lease_id) {
            throw new MalformedResult(
              `REPLAY_RUN_MISMATCH:the claim names ${lease.task_id}/${lease.lease_id}; the record holds ${recorded.task_id}/${recorded.lease_id}`,
            );
          }
          if (lease.fencing_token < recorded.fencing_token) {
            throw new StaleFence(
              `STALE_FENCE:replay ${recorded.run_id}`,
              `presented fence ${lease.fencing_token} is behind the recorded fence ${recorded.fencing_token}`,
            );
          }
          return buildLeaseAck({
            operation: 'claim',
            registration: state.registration,
            lease: { ...lease, fencing_token: recorded.fencing_token },
            runId: recorded.run_id,
            clock: state.clock,
            replayed: true,
          });
        }
        if (lease.adapter_id !== state.registration.adapter_id) {
          throw new CapabilityMismatch(
            'ADAPTER_SUBSTITUTION_REFUSED',
            `the lease names adapter ${lease.adapter_id}; this transport is ${state.registration.adapter_id}`,
          );
        }
        const failure = takeFailure(state, 'claim');
        if (failure) {
          markFailure(failure.error);
          throw failure.error;
        }
        if (state.lease !== null) {
          const held = state.lease;
          if (lease.fencing_token < held.fencing_token) {
            throw new StaleFence(
              `STALE_FENCE:claim ${held.lease_id}`,
              `presented fence ${lease.fencing_token} is behind the held fence ${held.fencing_token}`,
            );
          }
          const identical = lease.task_id === held.task_id
            && lease.lease_id === held.lease_id
            && lease.fencing_token === held.fencing_token;
          if (!identical) {
            // Never a second lease and never a silent substitution.
            throw new MalformedResult(
              'LEASE_ALREADY_CLAIMED',
              `this transport already holds ${held.lease_id}@${held.fencing_token}; a second, different claim is never honoured`,
            );
          }
          // Idempotent repeat: no second lease, no second side effect.
          return buildLeaseAck({
            operation: 'claim',
            registration: state.registration,
            lease: held,
            runId: state.run?.run_id ?? null,
            clock: state.clock,
            replayed: state.replay,
          });
        }
        state.lease = lease;
        return buildLeaseAck({
          operation: 'claim',
          registration: state.registration,
          lease,
          runId: null,
          clock: state.clock,
          replayed: state.replay,
        });
      });
    },

    // Every one of the ten methods takes ONE call object. The ExecutionRequest
    // is the single exception in shape (it is a whole contract document), so
    // start() accepts both the two-argument form start(request, { run_id })
    // and the uniform form start({ request, run_id }). The two are unambiguous:
    // an ExecutionRequest carries `contract_version` and never a `request` key.
    async start(request, args) {
      return guard(state, () => {
        let handoff = request;
        let rawCall = args;
        if (isPlainObject(request) && request.request !== undefined && args === undefined) {
          const { request: nested, ...rest } = request;
          handoff = nested;
          rawCall = rest;
        }
        const call = assertCallArgs('start', rawCall);
        const presentedRunId = requireString(call.run_id, 'run_id');
        if (state.replay) {
          // Version handshake, then digest agreement with the recorded run.
          assertExecutionVersion(requireObject(handoff, 'execution request'));
          const validated = assertBoardContract('execution-request', handoff);
          const presented = { ...validated, run_id: presentedRunId };
          const recorded = replayRecord.request;
          if (recorded !== null) {
            for (const field of ['brief_digest', 'policy_digest', 'manifest_digest', 'workspace_id', 'lease_id', 'fencing_token']) {
              if (recorded[field] !== validated[field]) {
                throw new MalformedResult(
                  `REPLAY_REQUEST_MISMATCH:${field}`,
                  `recorded ${String(recorded[field])} but the caller presented ${String(validated[field])}`,
                );
              }
            }
          }
          // The recorded result and the presented run must be the same run,
          // under the same lease and fence.
          for (const field of ['run_id', 'task_id', 'workspace_id', 'lease_id', 'fencing_token']) {
            if (replayRecord.result[field] !== presented[field]) {
              throw new MalformedResult(
                `REPLAY_RESULT_MISMATCH:${field}`,
                `the recorded result carries ${String(replayRecord.result[field])}; the presented run carries ${String(presented[field])}`,
              );
            }
          }
          return requireRecordedEvents()[0];
        }

        // Version handshake first: an unknown major version is rejected before
        // any state changes.
        assertExecutionVersion(requireObject(handoff, 'execution request'));
        const validated = assertBoardContract('execution-request', handoff);
        if (call.workspace_id !== undefined && call.workspace_id !== null && call.workspace_id !== validated.workspace_id) {
          throw new MalformedResult(
            'REQUEST_WORKSPACE_MISMATCH',
            `the call names workspace ${call.workspace_id}; the request authorizes ${validated.workspace_id}`,
          );
        }
        const leaseId = requireString(validated.lease_id, 'request.lease_id');
        const fence = requireInteger(validated.fencing_token, 'request.fencing_token');

        if (state.lease !== null) {
          if (leaseId !== state.lease.lease_id) {
            throw new MalformedResult(
              'REQUEST_LEASE_MISMATCH',
              `the request carries lease ${leaseId}; the held lease is ${state.lease.lease_id}`,
            );
          }
          if (fence < state.lease.fencing_token) {
            throw new StaleFence(
              `STALE_FENCE:request ${validated.request_id}`,
              `request fence ${fence} is behind the held fence ${state.lease.fencing_token}`,
            );
          }
          if (fence > state.lease.fencing_token) {
            throw new MalformedResult(
              'FENCE_AHEAD_OF_LEASE',
              `request fence ${fence} is ahead of the held fence ${state.lease.fencing_token}; a caller may not raise its own fence`,
            );
          }
        }
        if (state.run !== null) {
          if (state.run.request_id === validated.request_id) {
            // Idempotent repeat: the same request returns the same event and
            // starts nothing twice.
            const accepted = state.events[0];
            if (accepted !== undefined) return accepted;
            // The first attempt failed before an acceptance existed. A retry of
            // the IDENTICAL request may neither silently succeed (returning
            // nothing) nor emit a second acceptance: it re-reports the failure
            // the boundary already knows about, which is the only honest answer
            // until an authorized reconciliation decision closes the run.
            rejectUnknownOutcome();
            const recorded = state.run.failed_error;
            if (recorded !== null) {
              const ErrorClass = errorClassForCode(recorded.code);
              throw new ErrorClass(
                'RUN_START_FAILED',
                `the first start of run ${state.run.run_id} failed with ${recorded.code}: ${recorded.message}`,
              );
            }
            throw new MalformedResult(
              'RUN_START_INCOMPLETE',
              `run ${state.run.run_id} is bound to request ${validated.request_id} but no acceptance was ever recorded`,
            );
          }
          throw new MalformedResult(
            'RUN_ALREADY_STARTED',
            `run ${state.run.run_id} is already started; a second request is never merged into it`,
          );
        }

        state.run = {
          request_id: validated.request_id,
          run_id: presentedRunId,
          task_id: requireString(validated.task_id, 'request.task_id'),
          workspace_id: requireString(validated.workspace_id, 'request.workspace_id'),
          lease_id: leaseId,
          fencing_token: fence,
          brief_digest: validated.brief_digest,
          budget_currency: validated.budget_grant.currency,
          last_sequence: 0,
          cancelled: false,
          timed_out: false,
          unknown: false,
          failed_error: null,
        };
        if (state.lease === null) {
          state.lease = {
            task_id: state.run.task_id,
            lease_id: leaseId,
            fencing_token: fence,
            adapter_id: state.registration.adapter_id,
          };
        }

        const failure = takeFailure(state, 'start');
        if (failure) {
          markFailure(failure.error);
          // Nothing is asserted about the run: no ACCEPTED event exists and a
          // caller cannot read one out of a failed start.
          throw failure.error;
        }
        return emitEvent('ACCEPTED', {
          payload: { request_id: validated.request_id, idempotency_key: validated.idempotency_key },
        });
      });
    },

    async status(args) {
      return guard(state, () => {
        const object = assertCallArgs('status', args);
        if (state.replay) {
          assertReplayIdentity(object);
          const events = requireRecordedEvents();
          const event = events[state.replayCursor] ?? events[events.length - 1];
          state.replayCursor = Math.min(state.replayCursor + 1, events.length);
          return event;
        }
        const run = requireRun();
        rejectUnknownOutcome();
        assertRunIdentity(object, run);
        const terminal = terminalEvent();
        if (terminal) {
          // A terminal run's status is a READ of recorded state, not a new
          // event: nothing is appended once the outcome is known.
          return terminal;
        }
        const failure = takeFailure(state, 'status');
        if (failure) {
          markFailure(failure.error);
          throw failure.error;
        }
        verifyExpectedSequence(object, run.last_sequence + 1);
        assertWithinTimeout();
        return takeScriptedStep() ?? emitEvent('PROGRESS', { payload: { heartbeat: true } });
      });
    },

    async checkpoint(args) {
      return guard(state, () => {
        const object = assertCallArgs('checkpoint', args);
        if (state.replay) {
          assertReplayIdentity(object, { requireDigests: true });
          const recorded = recordedEvents().find((event) => event.event_type === 'CHECKPOINT');
          if (!recorded) {
            throw new EmptyResponse('RECORDED_RUN_HAS_NO_CHECKPOINT: a replay never fabricates resume state');
          }
          return recorded;
        }
        const run = requireRun();
        rejectUnknownOutcome();
        assertRunIdentity(object, run);
        const failure = takeFailure(state, 'checkpoint');
        if (failure) {
          markFailure(failure.error);
          throw failure.error;
        }
        verifyExpectedSequence(object, run.last_sequence + 1);
        assertWithinTimeout();
        const settled = terminalEvent();
        if (settled) {
          // A checkpoint after a terminal event would extend an outcome that is
          // already known. It is refused, never appended.
          throw new MalformedResult(
            'CHECKPOINT_AFTER_TERMINAL',
            `run ${run.run_id} already recorded ${settled.event_type}; a checkpoint cannot extend a known outcome`,
          );
        }
        // A checkpoint is bound to the brief, workspace and tool digests it was
        // produced under. The brief digest is the request's own value and is
        // COMPARED, not copied: a resume under a changed brief is refused. The
        // workspace and tool digests are the board's server-resolved values —
        // their canonical form belongs to policy.mjs — so this file records them
        // and lets the frozen result contract adjudicate their shape.
        if (object.brief_digest !== run.brief_digest) {
          throw new MalformedResult(
            'CHECKPOINT_BRIEF_MISMATCH',
            `checkpoint brief ${String(object.brief_digest)} does not match the authorized brief ${run.brief_digest}`,
          );
        }
        const next = state.script.events[0];
        if (next !== undefined && next.event_type === 'CHECKPOINT'
          && (next.sequence === null || next.sequence === run.last_sequence + 1)) {
          // The script recorded a checkpoint for this position: replay it
          // instead of inventing a second one.
          return takeScriptedStep();
        }
        return emitEvent('CHECKPOINT', {
          payload: {
            brief_digest: object.brief_digest,
            workspace_digest: object.workspace_digest,
            tool_digest: object.tool_digest,
          },
          sequence: run.last_sequence + 1,
        });
      });
    },

    async cancel(args) {
      return guard(state, () => {
        const object = assertCallArgs('cancel', args);
        if (state.replay) {
          assertReplayIdentity(object);
          const recorded = recordedEvents().find((event) => event.event_type === 'CANCELLED');
          if (!recorded) {
            throw new Cancelled(
              'REPLAYED_RUN_NOT_CANCELLABLE',
              `the recorded run ended as ${replayRecord.result.outcome}; a replay reissues nothing, not even a cancel`,
            );
          }
          return recorded;
        }
        const run = requireRun();
        rejectUnknownOutcome();
        assertRunIdentity(object, run);
        const terminal = terminalEvent();
        if (terminal) {
          throw new MalformedResult(
            'CANCEL_AFTER_TERMINAL',
            `run ${run.run_id} already recorded ${terminal.event_type}; a cancel cannot rewrite a known outcome`,
          );
        }
        const failure = takeFailure(state, 'cancel');
        if (failure) {
          markFailure(failure.error);
          throw failure.error;
        }
        verifyExpectedSequence(object, run.last_sequence + 1);
        // cancel stays available after a scripted timeout on purpose: a fenced
        // cancel is exactly what a timeout must produce (issue §4). It is
        // refused only when the outcome is genuinely unknown, above.
        const event = emitEvent('CANCELLED', {
          outcome: 'CANCELLED',
          payload: { reason: object.reason ?? 'cancelled by the board' },
        });
        run.cancelled = true;
        return event;
      });
    },

    async collect_result(args) {
      return guard(state, () => {
        const object = assertCallArgs('collect_result', args);
        if (state.replay) {
          assertReplayIdentity(object);
          verifyExpectedSequence(object, replayRecord.result.sequence);
          // The recorded result, verbatim. Even a recorded SUCCEEDED outcome
          // stays NOT_RUN_REAL_ADAPTER: the registration above says so.
          return replayRecord.result;
        }
        const run = requireRun();
        if (state.result !== null) {
          // Idempotent read: the same result document, no new side effect.
          return state.result;
        }
        rejectUnknownOutcome();
        assertRunIdentity(object, run);
        const failure = takeFailure(state, 'collect_result');
        if (failure) {
          markFailure(failure.error);
          throw failure.error;
        }
        verifyExpectedSequence(object, run.last_sequence + 1);
        if (state.script.timeout_after_sequence !== null && run.last_sequence >= state.script.timeout_after_sequence) {
          run.timed_out = true;
        }
        // Drain the remaining scripted events so the recorded sequence is
        // complete. An out-of-order or duplicate sequence aborts right here.
        drainScriptedEvents();
        state.result = buildResult();
        return state.result;
      });
    },

    async release(args) {
      return guard(state, () => {
        const object = assertCallArgs('release', args);
        const taskId = requireString(object.task_id, 'task_id');
        const leaseId = requireString(object.lease_id, 'lease_id');
        const fence = requireInteger(object.fencing_token, 'fencing_token');
        if (state.replay) {
          // A replay RE-CONSTRUCTS: it acknowledges the recorded lease so the
          // crash/restart path can free it, and it reissues nothing at all.
          const recorded = replayRecord.result;
          if (taskId !== recorded.task_id || leaseId !== recorded.lease_id) {
            throw new MalformedResult(
              `RELEASE_LEASE_MISMATCH:the release names ${taskId}/${leaseId}; the record holds ${recorded.task_id}/${recorded.lease_id}`,
            );
          }
          if (fence < recorded.fencing_token) {
            throw new StaleFence(
              `STALE_FENCE:release ${leaseId}`,
              `presented fence ${fence} is behind the recorded fence ${recorded.fencing_token}; a stale release mutates nothing`,
            );
          }
          return buildLeaseAck({
            operation: 'release',
            registration: state.registration,
            lease: { task_id: recorded.task_id, lease_id: recorded.lease_id, fencing_token: recorded.fencing_token },
            runId: recorded.run_id,
            clock: state.clock,
            replayed: true,
            reason: object.reason ?? null,
          });
        }
        const failure = takeFailure(state, 'release');
        if (failure) {
          markFailure(failure.error);
          throw failure.error;
        }
        if (state.lease === null) {
          throw new NeedsInput('NO_HELD_LEASE: there is nothing to release on this transport');
        }
        if (leaseId !== state.lease.lease_id || taskId !== state.lease.task_id) {
          throw new MalformedResult(
            'RELEASE_LEASE_MISMATCH',
            `the release names ${taskId}/${leaseId}; the held lease is ${state.lease.task_id}/${state.lease.lease_id}`,
          );
        }
        if (fence < state.lease.fencing_token) {
          throw new StaleFence(
            `STALE_FENCE:release ${leaseId}`,
            `presented fence ${fence} is behind the held fence ${state.lease.fencing_token}; a stale release mutates nothing`,
          );
        }
        // Releasing the lease asserts nothing about the run's outcome: the run
        // and the lease are separate facts.
        state.released = { ...state.lease };
        return buildLeaseAck({
          operation: 'release',
          registration: state.registration,
          lease: state.lease,
          runId: state.run?.run_id ?? null,
          clock: state.clock,
          replayed: state.replay,
          reason: object.reason ?? null,
        });
      });
    },

    // --- non-contract observability (never part of the ten methods) --------
    /** The frozen AdapterRegistration this transport may present. */
    registration: state.registration,
    /** The honest provenance of this transport. Never 'real'. */
    provenance: deepFreeze({
      status: TRANSPORT_PROVENANCE_STATUS,
      detail: state.registration.real_adapter_provenance.detail,
      source,
      adapter_kind: state.registration.adapter_kind,
    }),
    /** Every event this transport emitted, contract-valid and frozen. */
    get events() {
      return deepFreeze([...state.events]);
    },
    /** Every typed failure, as validated BoardError documents. */
    get errors() {
      return deepFreeze([...state.errors]);
    },
    /** Read-only view of the run state, for evidence and probes. */
    get state() {
      return deepFreeze({
        kind,
        source,
        replay: state.replay,
        started: state.run !== null,
        run_id: state.run?.run_id ?? null,
        task_id: state.run?.task_id ?? state.lease?.task_id ?? null,
        lease_id: state.lease?.lease_id ?? null,
        fencing_token: state.lease?.fencing_token ?? null,
        last_sequence: state.run?.last_sequence ?? 0,
        cancelled: state.run?.cancelled ?? false,
        timed_out: state.run?.timed_out ?? false,
        outcome_unknown: state.run?.unknown ?? false,
        collected: state.result !== null,
        outcome: state.result?.outcome ?? null,
        checkpoints: state.checkpoints.length,
        artifacts: state.artifacts.length,
      });
    },
  };

  assertAdapterInterface(transport);
  return transport;
}

// ---------------------------------------------------------------------------
// Test transport
// ---------------------------------------------------------------------------

/**
 * Model the execution boundary with a deterministic script. `script` is the
 * list of steps the transport replays:
 *
 *   { events: [ { event_type, sequence?, outcome?, payload?, at? } ],
 *     result: { ...partial ExecutionResult },
 *     failWith: 'TIMEOUT' | 'UNKNOWN_OUTCOME' | ... | [ { method, code } ],
 *     health: 'healthy' | 'degraded' | 'unhealthy' | 'unknown',
 *     timeout_after: <sequence> }
 *
 * Semantics that matter:
 *   * `events` is a queue. `start()` emits the ACCEPTED event, each
 *     run-advancing call (`status`, `checkpoint`) consumes at most ONE scripted
 *     event so the caller sees the run exactly as an executor emitted it, and
 *     `collect_result()` consumes the remainder. No step is ever emitted after
 *     a recorded terminal event. A scripted `sequence` that is not exactly
 *     previous + 1 is REJECTED (MalformedResult) and never renumbered: an
 *     out-of-order or duplicate callback is a defect to be refused, not
 *     smoothed over. The board's store enforces the same rule independently,
 *     so a defect on either side still fails closed.
 *   * `result` contributes outcome / checkpoints / artifact_hashes /
 *     measurements / error / completed_at. Anything the script does not supply
 *     is derived from the recorded boundary state, and success is never
 *     invented: with neither a terminal event nor a scripted result,
 *     `collect_result` rejects EMPTY_RESPONSE.
 *   * `failWith` injects typed failures per method. UNKNOWN_OUTCOME /
 *     RECONCILIATION_REQUIRED put the run into a permanently unknown state:
 *     every later run-level call rejects with the same non-retryable code,
 *     because a producer may never decide its own unknown side effect.
 *   * `health` is adjudicated by the registration schema.
 */
export function createTestTransport({ script, provenance, clock, ids } = {}) {
  const injectedClock = requireClock(clock);
  const normalized = normalizeScript(script);
  const built = buildRegistration({
    kind: 'test',
    source: 'test',
    provenance,
    clock: injectedClock,
    detail: 'scripted boundary transport: no external executor was invoked and no real adapter backed this run',
  });
  // `script.health` is a data declaration about the scripted transport; it is
  // folded into the registration and then adjudicated by the schema, so it
  // cannot introduce a value the contract does not know.
  const registration = normalized.health === undefined
    ? built
    : deepFreeze(assertBoardContract('adapter-registration', { ...built, health: assertHealthValue(built, normalized.health) }));
  return createTransportCore({
    kind: 'test',
    source: 'test',
    registration,
    clock: injectedClock,
    ids,
    script: normalized,
    replayRecord: null,
  });
}

// ---------------------------------------------------------------------------
// Replay transport
// ---------------------------------------------------------------------------

function normalizeRecordedEvents(rawEvents, result) {
  if (rawEvents === undefined || rawEvents === null) return [];
  return requireArray(rawEvents, 'record.events').map((event, index) => {
    const validated = deepFreeze(assertBoardContract('execution-event', event));
    // A recorded event stream must be gap-free from 1 and belong to the
    // recorded run; a corrupted record is refused, never repaired.
    if (validated.sequence !== index + 1) {
      throw new MalformedResult(
        `RECORDED_EVENT_SEQUENCE:${validated.run_id}:expected ${index + 1} got ${validated.sequence}`,
        'a recorded event stream must be gap-free; a replay never repairs it',
      );
    }
    if (validated.run_id !== result.run_id) {
      throw new MalformedResult(`RECORDED_EVENT_RUN_MISMATCH:expected ${result.run_id} got ${validated.run_id}`);
    }
    if (validated.sequence > result.sequence) {
      throw new MalformedResult(`RECORDED_EVENT_AHEAD_OF_RESULT:${validated.sequence} is ahead of ${result.sequence}`);
    }
    return validated;
  });
}

/**
 * Replay a recorded ExecutionResult deterministically for the crash/restart
 * phase. Replay RECONSTRUCTS: it never reissues a side effect and it never
 * re-derives an outcome. `collect_result()` returns the recorded document
 * verbatim (validated); `status()` walks the recorded events; `start()`
 * validates the inbound request and, when the record carries the original
 * request, checks that the run, lease, fence and the brief/policy/manifest
 * digests still agree — a replay under moved-on digests is MALFORMED_RESULT,
 * not a silent pass.
 *
 * Like the test transport, this transport is NOT_RUN_REAL_ADAPTER. Replay
 * evidence never upgrades a fixture to a real-adapter PASS (issue §8): the
 * registration is rebuilt here with adapter_kind 'wrapper', whatever the
 * recorded run claimed.
 */
export function createReplayTransport(record) {
  const raw = requireObject(record, 'record');
  const result = deepFreeze(assertBoardContract('execution-result', requireObject(raw.result, 'record.result')));
  const events = normalizeRecordedEvents(raw.events, result);
  const request = raw.request === undefined || raw.request === null
    ? null : deepFreeze(assertBoardContract('execution-request', raw.request));
  // The recorded documents already carry their own timestamps, so a replay
  // never needs the process clock: without an injected one the recorded
  // completion instant is the reference point.
  const injectedClock = raw.clock === undefined || raw.clock === null
    ? requireClock(result.completed_at) : requireClock(raw.clock);
  const registration = buildRegistration({
    kind: 'replay',
    source: 'replay',
    provenance: raw.provenance,
    clock: injectedClock,
    registeredAt: raw.registered_at,
    detail: `replay of recorded run ${result.run_id} (${result.outcome}); replay evidence never upgrades NOT_RUN_REAL_ADAPTER`,
  });
  return createTransportCore({
    kind: 'replay',
    source: 'replay',
    registration,
    clock: injectedClock,
    ids: raw.ids,
    script: { events: [], result, failures: [], health: undefined, timeout_after_sequence: null },
    replayRecord: { result, events, request },
  });
}

// ---------------------------------------------------------------------------
// Real-adapter host probe
// ---------------------------------------------------------------------------

function safeLocation(value) {
  const home = os.homedir();
  if (home && value.startsWith(home)) return `$HOME${value.slice(home.length)}`;
  return value;
}

function pathEntries(env) {
  const raw = typeof env.PATH === 'string' ? env.PATH : '';
  return raw.split(path.delimiter).filter((entry) => entry.length > 0);
}

// The detail string is a report, not a log: it is bounded to the same 500
// characters the AdapterRegistration provenance detail allows, and it passes
// through redact() so a home directory or a credential-shaped token in a PATH
// entry never reaches a report or an outbox row.
function probeDetail(text) {
  return redact(String(text)).replace(/\s+/g, ' ').trim().slice(0, 500);
}

function executableNames(name, platform) {
  if (platform !== 'win32') return [name];
  const extensions = (process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  return [name, ...extensions.map((extension) => `${name}${extension.toLowerCase()}`)];
}

// PATH resolution only: no shell, no eval, no name lookup through /bin/sh.
function findExecutable(name, env, platform) {
  for (const directory of pathEntries(env)) {
    for (const candidate of executableNames(name, platform)) {
      const full = path.join(directory, candidate);
      try {
        if (!fs.statSync(full).isFile()) continue;
        fs.accessSync(full, fs.constants.X_OK);
        return full;
      } catch {
        // Absent, not a file or not executable: keep looking. Never guess.
      }
    }
  }
  return null;
}

// Optional extra evidence. execFileSync with an argv ARRAY (never a shell
// string), a hard timeout, a minimal environment and a bounded output buffer.
function probeVersion(found, env) {
  try {
    const stdout = execFileSync(found, ['--version'], {
      timeout: 4000,
      maxBuffer: 4096,
      windowsHide: true,
      encoding: 'utf8',
      cwd: os.tmpdir(),
      // No secret of this process reaches a child process.
      env: { PATH: env.PATH ?? '', HOME: os.homedir() },
    });
    return redact(String(stdout).split('\n')[0]).trim().slice(0, 120);
  } catch (error) {
    return `version probe failed: ${redact(String(error?.message ?? error)).slice(0, 80)}`;
  }
}

function normalizeCandidates(candidates) {
  if (candidates === undefined || candidates === null) return REAL_ADAPTER_PROBE_CANDIDATES;
  return requireArray(candidates, 'candidates').map((entry, index) => {
    if (typeof entry === 'string') {
      return {
        adapter_id: `adr-probe-${entry.replace(/[^a-z0-9-]/gi, '-').toLowerCase()}`,
        kind: 'real',
        executables: [entry],
      };
    }
    const object = requireObject(entry, `candidates[${index}]`);
    const executables = object.executables ?? object.executable ?? object.command;
    return {
      adapter_id: requireString(object.adapter_id, `candidates[${index}].adapter_id`),
      kind: typeof object.kind === 'string' ? object.kind : 'real',
      executables: Array.isArray(executables)
        ? executables.map((item) => requireString(item, `candidates[${index}].executables`))
        : [requireString(executables, `candidates[${index}].executables`)],
    };
  });
}

/**
 * Check the host for actually installed executables. This is a HOST FACT and
 * nothing more: `installed: true` means "an executable with this name is on
 * PATH and executable". It is NOT evidence that a Veritas adapter ran a task
 * for the board, NOT a registration, and never an upgrade of a run's
 * NOT_RUN_REAL_ADAPTER. A candidate declared as a mock/wrapper/test/replay is
 * structurally unable to be reported as installed.
 *
 * The clock is accepted and validated so the caller can stamp the observation
 * with its own injected time; the probe itself never reads the process clock.
 */
export async function probeRealAdapters({ candidates, clock, versionProbe = false, env = process.env } = {}) {
  requireClock(clock);
  const list = normalizeCandidates(candidates);
  const platform = process.platform;
  const results = [];
  for (const candidate of list) {
    // Structural rule: a non-executor candidate can never be installed.
    if (NEVER_INSTALLABLE_KINDS.has(String(candidate.kind).toLowerCase())) {
      results.push({
        adapter_id: candidate.adapter_id,
        installed: false,
        detail: probeDetail(`${candidate.executables.join(', ')}: candidate kind '${candidate.kind}' can never be reported as installed`),
      });
      continue;
    }
    const found = candidate.executables
      .map((name) => findExecutable(name, env, platform))
      .find((hit) => hit !== null) ?? null;
    if (found === null) {
      results.push({
        adapter_id: candidate.adapter_id,
        installed: false,
        detail: probeDetail(`${candidate.executables.join(', ')}: not found on PATH (${pathEntries(env).length} entries searched)`),
      });
      continue;
    }
    const version = versionProbe ? ` (${probeVersion(found, env)})` : '';
    results.push({
      adapter_id: candidate.adapter_id,
      installed: true,
      detail: probeDetail(
        `${path.basename(found)}: executable found on PATH at ${safeLocation(found)}${version}; `
        + 'a host fact only, not a registered veritas adapter and not a real-adapter run',
      ),
    });
  }
  return results;
}

// --- import-time guard on the derived outcome table -------------------------
// If the frozen event contract ever stopped accepting one of these derivations,
// the module refuses to load rather than emitting a value the contract rejects.
function verifyEventOutcomeDerivation() {
  for (const [eventType, outcome] of Object.entries(OUTCOME_BY_EVENT_TYPE)) {
    assertBoardContract('execution-event', {
      contract_version: EXECUTION_CONTRACT_VERSION,
      event_id: 'eve-outcome-derivation-probe',
      run_id: 'run-outcome-derivation-probe',
      task_id: 'abt-outcome-derivation-probe',
      workspace_id: 'ws-outcome-derivation-probe',
      lease_id: 'lse-outcome-derivation-probe',
      fencing_token: 1,
      sequence: 1,
      event_type: eventType,
      payload: {},
      outcome,
      emitted_at: '2026-01-01T00:00:00.000Z',
    });
  }
  return true;
}

verifyEventOutcomeDerivation();
