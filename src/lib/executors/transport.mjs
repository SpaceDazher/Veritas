// S2-007R real executor transport (issue #45). The first module in this tree
// that drives a GENUINELY INSTALLED codex or pi process across the
// veritas.adapter/1.0.0 boundary.
//
// WHY THIS FILE EXISTS
// --------------------
// adapters.mjs owns the execution boundary and states in prose that
// `createTestTransport` and `createReplayTransport` are its only constructors
// and that `adapter_kind` + `real_adapter_provenance.status` are literals of
// that file (its header, lines 36-51). That file is NOT edited here. This is a
// separate module that speaks the same ten-method interface and builds its own
// AdapterRegistration, so the honesty pair in adapters.mjs stays exactly as
// written and a third constructor never appears in it.
//
// FIVE RULES THIS FILE ENFORCES STRUCTURALLY, NOT BY CONVENTION
// --------------------------------------------------------------
//
//  1. `real_adapter_provenance.status` is NOT_RUN_REAL_ADAPTER by default and
//     can only be REAL_ADAPTER_AVAILABLE from a real-run evidence record that
//     THIS MODULE produced from a process IT ACTUALLY SPAWNED AND OBSERVED
//     (evidenceRecord() is the only source; see assertRealRunEvidence). The
//     record is then re-derived from the filesystem and BOUND to the raw
//     process log: the log is PARSED, not merely digested, and its record kind,
//     executor version, run id, provider, binary digest, argv shape and exit
//     status must all agree with the record. A record that agrees with itself
//     and with two files that merely exist proves nothing, so the three
//     bindings that decide are these: (a) OBSERVATION — the record object was
//     minted by evidenceRecord() from this transport's own observed exit, so a
//     hand-typed literal, a repository test stub, /bin/false and a JSON file
//     reconstructed by hand are all refused; (b) IDENTITY — the binary is a
//     real executable whose bytes match the digest and it is the provider's own
//     named binary; (c) AGREEMENT — the log on disk corroborates the record
//     field by field. Any missing field, any disagreement, an unobserved
//     record, a path that is not a real executable, a symlink that was not
//     resolved, or a zero/absent exit status REFUSES the claim with
//     NotRunRealAdapter. The refusal path is written first (see
//     assertRealRunEvidence) and the accept path is what remains.
//
//     Deliberate conservatism, stated rather than hidden: the gate requires a
//     NON-ZERO exit status, so a clean exit-0 run on its own never upgrades the
//     status. A record that documents a run whose outcome the executor itself
//     reported as a failure is the shape this module will corroborate. That is
//     the safe direction (it can only ever make the claim harder) and it is a
//     limitation of the ticket, not a design win.
//
//     Two consequences of (a) are stated rather than hidden. FIRST: a
//     registration is only upgradable in the process that performed the run;
//     re-adjudicating a serialized record in a later process is REFUSED,
//     because nothing on disk can prove that some earlier process really
//     observed that exit. SECOND: the honest acceptance path is therefore NOT
//     reachable from the default test suite, which drives a test stub. It is
//     reachable only from a run of a genuinely installed provider, and that
//     test is opt-in (VERITAS_S2_007R_REAL=1) exactly because it costs a real
//     process. A suite that could reach REAL_ADAPTER_AVAILABLE by itself would
//     be the defect, not the coverage.
//
//  2. The child argv is an ARRAY built from a fixed allowlist
//     (PROVIDER_ARGV_ALLOWLIST) and re-validated element by element by
//     assertArgvAllowed immediately before the spawn. There is no shell, ever.
//     The prompt and the cwd are DATA: the prompt is a single trailing
//     positional that may not begin with '-', and the cwd is resolved through
//     the board's own ACL (policy.assertWorkspaceWithin) before the process
//     exists. No task, brief, skill or model output can introduce a flag.
//
//     The CONFIGURATION SURFACE is an explicit, validated option and the ONLY
//     thing that may differ between two cells of a comparison. `A` passes no
//     suppression flag at all — the host's default context surface is left
//     alone — and `B` suppresses skills, extensions, prompt templates, context
//     files and themes. Same model pin, same derived --tools, same timeout,
//     same prompt, same project, same budget. Round 2 measured
//     `argv_identical: true` for both providers because no surface argument
//     existed and pi's argv always carried the `--no-*` set, so an A/B
//     comparison would have differenced a cell with itself; the surface is
//     therefore REQUIRED (never defaulted, because a silent default would make
//     every unmarked run a B cell) and it may only select flags the allowlist
//     already carries. `configurationAxis()` decides STRUCTURALLY whether a
//     provider can be compared at all: pi can, codex 0.157.1 cannot, because
//     `codex exec --help` lists 27 flags and none of them suppresses a context
//     surface — so codex is recorded as EXCLUDED with that reason rather than
//     as "no difference observed".
//
//     The evidence publishes BOTH argv digests. The raw one is the exact argv
//     as the OS received it; the normalised one folds out the per-run project
//     copy, the evidence root, the injected containment roots and the run id —
//     nothing else — and a comparison asserts on that one. Publishing both is
//     what makes the distinction checkable: round 2 nearly mis-read a per-run
//     `--output-last-message` path as a configuration difference.
//
//  3. The effective tool set is the INTERSECTION of the operator registration
//     and the current grant — declared ∩ grant, where the grant is the board's
//     own grant object when the caller supplied one and the request's
//     allowed_tools otherwise — reduced further to what the operator explicitly
//     bound to an executor-native tool name. The cross-check's own
//     `effective_tools` is the value that is used, never a set recomputed from
//     the request alone, so the tools the child can call are never wider than
//     the board's grant. Only those names ever reach argv.
//     A skill bundle is an explicit, recorded part of the run configuration and
//     it cannot widen anything: it may *ask* for a tool (declared
//     `requested_tools`), and an ask outside the intersection is refused with
//     CapabilityMismatch and recorded as an authority-expansion observation.
//
//  4. Every method rejects only with a BoardError from errors.mjs, including
//     on the paths nobody awaits: the budget timer, the observer wrappers and
//     the terminateGroup() calls are fire-and-forget, and a bare Error escaping
//     one of them is an unhandled rejection, not a typed refusal. The child is
//     spawned detached, i.e. as the leader of its OWN POSIX process group, so
//     cancel() can signal the GROUP and then ACCOUNT for what survived: the
//     shipped createProcessObserver() re-reads the pids after the kill and the
//     three-way proof TERMINATED | SURVIVORS_REMAINING | UNVERIFIED is carried
//     verbatim. The proof is UNVERIFIED — never TERMINATED, never survivors: 0
//     — when nothing was observed alive before the kill AND no signal was
//     actually delivered, because a zero there is the false zero the board's
//     evidence rules exist to prevent. A cancel that cannot prove the group is
//     gone throws UnknownOutcome, still writes the raw log for the invocation
//     it could not account for, and mutates nothing; it never reports success.
//     A cancel for a process that has ALREADY exited is refused with
//     MalformedResult: the run's real outcome is decided by collect_result, and
//     a cancel never rewrites a known outcome into a CANCELLED.
//
//     A TIMEOUT IS A KILL, so it carries the same proof. The deadline this
//     transport enforced killed a process group; publishing `TIMEOUT` with no
//     proof at all is the round-2 defect TRANSPORT_PUBLISHES_NO_TERMINATION_
//     PROOF_ON_TIMEOUT, and a timeout whose group kill cannot be proved
//     TERMINATED is reported as the unknown it is, with the proof beside it.
//
//     THE REAP COMES BEFORE THE ACCOUNTING. A killed child that has not been
//     reaped is still in the process table, so the observer asked immediately
//     after the kill reports SURVIVORS_REMAINING for a process that is already
//     gone — round 2's CANCEL_PROOF_IS_A_REAPING_RACE, which turned a correct
//     cancel into UNKNOWN_OUTCOME. The child exit is therefore WAITED FOR before
//     the survivor accounting, and when the two readings disagree BOTH are
//     published: the observer's first answer is never overwritten by the
//     accounting one.
//
//     NOTHING PENDING OUTLIVES A RUN. Every wait is bounded and its timer
//     destroyed in a `finally` — the deadline timer on every path including the
//     failure paths, and the losing side of every race, which is what held a
//     4 s run's process alive for 5m01s in round 2. `pendingTimers` is the
//     read-only surface that shows it.
//
//  5. A provider error inside the executor's own output is PROVIDER_FAILURE and
//     an empty assistant message is EMPTY_RESPONSE. This matters because the
//     two CLIs disagree about failure (measured on this host, recon 6 §2.3/2.4):
//     codex exits 1 with a structured turn.failed, and pi exits 0 on a total
//     model failure with stopReason "error" and a free-text `402:` message. The
//     exit code is therefore NEVER the sole classifier; the executor's own
//     records are. A process that was signalled and produced no OBSERVED exit
//     at all is UNKNOWN / RECONCILIATION_REQUIRED, non-retryable and never
//     dressed up as a stop — and that arm is checked BEFORE the timeout arm, so
//     a run that timed out without an observed exit is RECONCILIATION_REQUIRED
//     rather than a definite TIMEOUT. A process killed by a signal this
//     transport DID send, whose exit the parent observed, is a known stop and
//     is classified as such.
//
// DETERMINISM
// -----------
// No Date.now(), no new Date() without the injected clock, no Math.random(), no
// process.hrtime in this file. Timestamps come from the injected clock. Raw log
// paths are a pure function of (evidenceDir, run_id, index). A real timer is
// armed for the caller-authorized `budget_grant.timeout_ms`; that is the
// ENFORCEMENT of a bound the board granted, not a reading of the process clock,
// and the duration that lands in the result is the injected clock's.
//
// SECRETS
// -------
// A raw log records the exact argv, the cwd, the exit status, the stdout/stderr
// digests and the executor's own token/cost report. It NEVER records an
// environment value, and it never records the executor's output text: only its
// digest and byte length. Credentials are referred to by variable name and file
// location and are never read here.
//
// The brief IS in the log, in CLEARTEXT, and the log says so. Both CLIs take
// the prompt as a trailing positional argument (measured, recon 6 §1.2/§2.1),
// so argv cannot avoid carrying it; a `prompt_sha256` beside that text would
// read as a protection that does not exist, so there is no such field. What the
// log records instead is the board's own `brief_digest` — the value the request
// was authorized under — plus `argv_carries_prompt_in_cleartext: true`.
//
// ISOLATION IS RECORDED, NEVER CLAIMED
// ------------------------------------
// The registered sandbox profile is a REQUEST-side declaration, and this
// transport spawns the child DIRECTLY ON THE HOST: no podman, no gVisor, no
// network namespace, no read-only mount, no empty environment allowlist. So
// every artifact that carries the profile id also carries the truth about what
// was actually in force: `isolation_applied: false` with the reason, the
// profile tier, the declared network policy / filesystem roots / environment
// allowlist and the requested read-only paths, in the ACCEPTED event and in the
// raw process log. A reader that takes the profile id off the registration
// cannot be misled about what the run was, because the run's own evidence says
// the isolation was not applied. Running the provider inside its profile's own
// wrapper is the fix and it is not this file's to make: it needs the host
// launcher, and on a host where the executor cannot run inside the image at all
// it needs the separately authorized HOST_UNISOLATED floor tier and its named
// human authorisation (policy.assertLiveExecutionAuthorized). Until then the
// honest label is HOST_UNISOLATED in the artifacts, not a proven tier id on a
// confined child.
//
// MEASURED HOST FACTS THIS MODULE IS BUILT ON (recon 6, this Linux host)
// --------------------------------------------------------------------
//   codex 0.157.1: `codex exec --json --skip-git-repo-check --ephemeral
//   --sandbox read-only -C <dir> --output-last-message <file>`; no tool
//   allowlist flag and no --skill flag exist, so for codex the structural tool
//   control is `--sandbox read-only` plus the fact that no tool name is ever
//   passed; the effective allowlist is RECORDED, not flag-enforced.
//   pi 0.87.1: `pi -p --mode json --model <provider/id> --no-session
//   [--tools a,b | --no-tools] [--skill <path> | --no-skills ...] <prompt>`; no
//   cwd flag, so the child inherits the spawn cwd. `--tools` IS the structural
//   control and is derived from the intersection. A model id must always be
//   explicit: this host's configured pi default is not the verified model.
//   Both CLIs read the child's stdin: a piped stdin changes the prompt, so the
//   child is always given an ignored stdin.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import { createProcessObserver } from '../identity/process-observer.mjs';
import { assertAdapterInterface, crossCheckCapabilities } from '../agentboard/adapters.mjs';
import {
  ADAPTER_INTERFACE_VERSION,
  BOARD_CONTRACT_VERSION,
  ERROR_CODES,
  EXECUTION_CONTRACT_VERSION,
  ID_PREFIXES,
  SANDBOX_PROFILES,
  classifySandboxProfile,
  isExecutableSandboxProfile,
} from '../agentboard/constants.mjs';
import { assertBoardContract, assertExecutionVersion } from '../agentboard/contracts.mjs';
import {
  AclDenied,
  AgentUnavailable,
  BlockedPolicy,
  BlockedSandbox,
  CapabilityMismatch,
  MalformedResult,
  NeedsInput,
  NotRunRealAdapter,
  StaleFence,
  UnknownOutcome,
  errorClassForCode,
  isBoardError,
  redact,
  toBoardError,
} from '../agentboard/errors.mjs';
import { assertLiveExecutionAuthorized, assertWorkspaceWithin } from '../agentboard/policy.mjs';
import {
  CAP_LIMIT,
  CANONICAL_PROVENANCE_STATUS,
  HOST_UNISOLATED_EVIDENCE_DIGEST,
  HOST_UNISOLATED_EVIDENCE_PATH,
  MODEL_RE,
  NATIVE_TOOL_RE,
  OUTCOME_BY_EVENT_TYPE,
  POSIX_GROUP_SIGNAL,
  PROVIDER_ARGV_ALLOWLIST,
  REAL_EXECUTOR_VERSION,
  REAL_PROVIDERS,
  RUN_ID_RE,
  TERMINAL_EVENT_TYPES,
  TOOL_ID_RE,
} from './constants.mjs';
import {
  OBSERVATION_TRUST,
  acquireMintCapability,
  assertRealRunEvidence,
  mintObservedRunEvidence,
} from './evidence-writer.mjs';

// The one-time mint capability, claimed at module evaluation and never exported
// from here: the evidence writer refuses every later acquisition, so this module
// is the only one in the tree that can register an observed run record. The
// round-3 honesty audit forged one through the previously exported mint.
const MINT_CAPABILITY = acquireMintCapability();
if (MINT_CAPABILITY === null) {
  throw new Error('EXECUTOR_MINT_CAPABILITY_ALREADY_CLAIMED: another module claimed the evidence mint before this one');
}
import { extractUsage, readExecutorOutcome } from './failure-map.mjs';
import { isMintedRegistration } from './registration.mjs';
import {
  assertArgvAllowed,
  assertDescendant,
  argvDigests,
  configurationAxisFor,
  deepFreeze,
  derivedId,
  isPlainObject,
  requireArray,
  requireClock,
  requireIdFactory,
  requireInteger,
  requireObject,
  requireString,
  resolveConfigurationSurface,
  sortedUnique,
  timestampOf,
  wireDigest,
} from './internals.mjs';

// --- the canonical-argument tables (re-derived from adapters.mjs) ----------

const CANONICAL_ARGS = Object.freeze({
  identify: Object.freeze([]),
  capabilities: Object.freeze(['claimed', 'claimed_capabilities', 'claimed_tools']),
  health: Object.freeze([]),
  claim: Object.freeze(['task_id', 'workspace_id', 'lease_id', 'fencing_token', 'adapter_id', 'ttl_ms', 'at']),
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

function assertCallArgs(method, args) {
  const allowed = CANONICAL_ARGS[method];
  const object = args === undefined || args === null ? {} : requireObject(args, `${method} arguments`);
  const unknown = Object.keys(object).filter((key) => !allowed.includes(key)).sort();
  if (unknown.length > 0) {
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
// The transport
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

/**
 * createRealExecutorTransport(options) -> the ten async methods.
 *
 * One transport instance describes ONE run configuration: the provider, the
 * resolved executor binary, the prompt (the brief as data), the evidence
 * directory, the skill bundle, the tool bindings and the workspace roots. The
 * ExecutionRequest itself deliberately carries no run_id and no prompt, so
 * those are configuration, not per-call authority; the ten methods take the same
 * canonical argument set as the scripted transport and refuse an unknown key.
 */
export function createRealExecutorTransport({
  provider,
  registration,
  clock,
  ids,
  executorPath,
  evidenceDir,
  workspaceRoots,
  realpath,
  prompt,
  model = null,
  toolBindings = {},
  skillBundle = null,
  skillRoots = [],
  grant = null,
  observer = null,
  // THE CONFIGURATION AXIS (issue #45, round 3). An EXPLICIT, validated surface:
  // `A` leaves the host's default context surface alone and `B` suppresses every
  // one of skills / extensions / prompt templates / context files / themes. It is
  // configuration, not authority, and it is REQUIRED rather than defaulted: a
  // transport that does not know which surface it was handed cannot be one half
  // of a comparison, and an absent value defaulting to the limited build would
  // turn every unmarked run into a silent B cell. The surface selects flags that
  // the argv allowlist already carries; it can never introduce a new one.
  configuration = null,
  cancelGraceMs = 300,
  observerSettleMs = 2000,
  // The named human permit for the HOST_UNISOLATED floor (issue #45). It is a
  // SERVER-RESOLVED option the caller passes through, never a payload argument:
  // an adapter, a task, an execution event, a skill or a replayed record can
  // neither supply nor widen it. The transport adjudicates it with the same
  // policy.assertLiveExecutionAuthorized the command boundary uses, so the run
  // and the decision that let it start can never disagree.
  unisolatedExecutionAuthorization = null,
} = {}) {
  const injectedClock = requireClock(clock);
  const idFor = requireIdFactory(ids);
  if (!REAL_PROVIDERS.includes(provider)) {
    throw new NeedsInput(`REAL_PROVIDER_UNKNOWN:${String(provider)}`);
  }
  // The registration is a CONTRACT document first and a minting fact second.
  // `adapter_kind: 'real'` is a string anybody can type, so the string is not
  // what authorises this transport: the document is validated against the
  // frozen schema, and it must be one THIS module's createRealRegistration
  // produced — which is the only place its provenance status was adjudicated.
  // A hand-typed literal is refused here, so identify()/capabilities()/health()
  // can never echo a status this module did not adjudicate.
  const candidate = requireObject(registration, 'registration');
  let bound;
  try {
    bound = assertBoardContract('adapter-registration', candidate);
  } catch (error) {
    throw new NotRunRealAdapter(
      'REGISTRATION_NOT_CONTRACT_VALID',
      `the registration is not a valid adapter-registration document: ${redact(String(error?.message ?? error)).slice(0, 200)}`,
    );
  }
  if (!isMintedRegistration(candidate) && !isMintedRegistration(bound)) {
    throw new NotRunRealAdapter(
      'REGISTRATION_NOT_MINTED_HERE',
      'this transport only drives a registration built by createRealRegistration() of this module; a document '
      + 'assembled by hand carries a provenance status that nothing here ever adjudicated',
    );
  }
  if (bound.adapter_kind !== 'real') {
    throw new NotRunRealAdapter(
      'ADAPTER_KIND_NOT_ASSIGNABLE',
      `this transport only drives a registration whose adapter_kind is its own literal 'real', got ${String(bound.adapter_kind)}`,
    );
  }
  if (bound.provider !== provider) {
    throw new CapabilityMismatch(
      'REGISTRATION_PROVIDER_MISMATCH',
      `the registration names provider ${String(bound.provider)}; this transport is ${provider}`,
    );
  }
  if (model !== null && !MODEL_RE.test(String(model))) {
    throw new NeedsInput(`MODEL_MALFORMED:${String(model)}: expected an explicit provider/id`);
  }
  const binary = resolveExecutorBinary(executorPath);
  const roots = requireArray(workspaceRoots, 'workspaceRoots').map((root) => requireString(root, 'workspaceRoots[]'));
  if (roots.length === 0) {
    // An empty or unknown root set proves nothing: nothing is inside it.
    throw new AclDenied('WORKSPACE_ROOTS_REQUIRED', 'no workspace root is known for this run');
  }
  if (typeof prompt !== 'string' || prompt.length === 0) {
    throw new NeedsInput('PROMPT_REQUIRED', 'the brief text is the executor input and may not be empty');
  }
  const evidenceRoot = requireString(evidenceDir, 'evidenceDir');
  if (!path.isAbsolute(evidenceRoot)) {
    throw new NeedsInput('EVIDENCE_DIR_NOT_ABSOLUTE', 'evidenceDir must be an absolute path');
  }
  const bindings = normalizeToolBindings(toolBindings);
  const bundle = normalizeSkillBundle(skillBundle, skillRoots, realpath);
  // The surface and whether this provider can be compared at all, both resolved
  // before any process exists.
  const surface = resolveConfigurationSurface(provider, configuration);
  const configurationAxis = configurationAxisFor(provider);
  const procObserver = observer === null || observer === undefined ? createProcessObserver() : observer;
  const declaredTools = new Set(bound.declared_tools);

  const state = {
    events: [],
    errors: [],
    checkpoints: [],
    artifacts: [],
    result: null,
    lease: null,
    run: null,
    // The run correlation the BOARD committed, bound out of band (SPEC D12:
    // an ExecutionRequest carries no run_id by design, and the outbox payload
    // is that request). bindRun() writes it; start() consumes it.
    boundRun: null,
    unknownCode: null,
    released: null,
    authorityExpansions: [],
    rawLogs: [],
    sandboxDecision: null,
    cancelProof: null,
    // Live process state. Never part of the frozen view.
    child: null,
    pgid: null,
    pid: null,
    pidIdentities: {},
    groupPids: [],
    exit: null,
    exitPromise: null,
    resolveExit: null,
    exitObserved: false,
    cause: null,
    timer: null,
    argv: [],
    // The surface, the axis and BOTH argv digests (raw and normalised), computed
    // once at the spawn and published by the raw log and the ACCEPTED event.
    argvEvidence: null,
    isolation: null,
    stdout: '',
    stderr: '',
    stdoutBytes: 0,
    stderrBytes: 0,
    truncated: false,
    startedAt: null,
    startedAtMs: null,
    lastMessagePath: null,
    readOutcome: null,
  };

  // --- typed failure recording ---------------------------------------------

  function recordFailure(error) {
    const typed = isBoardError(error) ? error : toBoardError(error);
    state.errors.push(deepFreeze(assertBoardContract('board-error', typed.toDocument(timestampOf(injectedClock)))));
    return typed;
  }

  async function guard(body) {
    try {
      return await body();
    } catch (error) {
      throw recordFailure(error);
    }
  }

  // --- events --------------------------------------------------------------

  function emitEvent(eventType, { outcome = null, payload = {}, sequence = null } = {}) {
    const run = state.run;
    if (run === null) {
      throw new NeedsInput('RUN_NOT_STARTED', 'an event may not be emitted for a run that was never started');
    }
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
      event_id: idFor('event', `${run.run_id}:${expected}`),
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
      emitted_at: timestampOf(injectedClock),
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
    return event;
  }

  function terminalEvent() {
    return [...state.events].reverse().find((event) => TERMINAL_EVENT_TYPES.has(event.event_type)) ?? null;
  }

  // --- run binding ---------------------------------------------------------

  function requireRun() {
    if (state.run === null) {
      throw new NeedsInput('RUN_NOT_STARTED', 'the execution boundary is asked about a run that was never started');
    }
    return state.run;
  }

  // An unknown external side effect asserts nothing further. A producer may not
  // decide its own unknown outcome, and a blind retry is not available because
  // every one of these rejections is non-retryable.
  function rejectUnknownOutcome() {
    if (state.unknownCode === null) return;
    const ErrorClass = errorClassForCode(state.unknownCode);
    throw new ErrorClass(
      'RUN_OUTCOME_UNKNOWN',
      'the external side effect of this run is unknown; only observation or an authorized reconciliation decision closes it',
    );
  }

  function markUnknown() {
    if (state.run !== null) state.run.unknown = true;
    state.unknownCode = 'UNKNOWN_OUTCOME';
    // An unknown run is over for this transport: nothing it arms may stay armed.
    clearDeadline();
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

  // --- the effective tool set ----------------------------------------------

  function effectiveToolIds(grantSet) {
    // The intersection of the registration and the grant, and nothing else.
    return sortedUnique([...declaredTools].filter((tool) => grantSet.has(tool)));
  }

  function effectiveNativeTools(effective) {
    const names = [];
    const unbound = [];
    for (const tool of effective) {
      const native = bindings[tool];
      if (native === undefined) {
        // The board granted and registered a tool that the operator bound to no
        // executor-native name: the child cannot reach it. Recorded, not
        // silently widened to "everything".
        unbound.push(tool);
        continue;
      }
      names.push(native);
    }
    return { names: sortedUnique(names), unbound };
  }

  function recordExpansion(source, tool, detail) {
    state.authorityExpansions.push(Object.freeze({
      source,
      requested_tool: tool,
      verdict: 'REFUSED',
      recorded_at: timestampOf(injectedClock),
      detail,
    }));
  }

  /**
   * A skill bundle may ASK for a tool. An ask outside the effective
   * intersection is refused with CAPABILITY_MISMATCH and recorded. The bundle
   * therefore cannot widen anything: the argv is built from the intersection
   * alone, so even a bundle that loads successfully cannot reach the tool it
   * asked for.
   */
  function assertNoAuthorityExpansion(bundleValue, effective) {
    if (bundleValue === null) return;
    for (const tool of bundleValue.requested_tools) {
      if (effective.includes(tool)) continue;
      recordExpansion('skill_bundle', tool, 'the requested tool is not in declared ∩ grant');
      throw new CapabilityMismatch(
        'SKILL_AUTHORITY_EXPANSION_REFUSED',
        `the skill bundle asks for ${tool}, which is not in the effective tool set `
        + `[${effective.join(', ')}]; a skill may ask, and the boundary refuses`,
      );
    }
  }

  // --- the workspace ACL ----------------------------------------------------

  function resolveCwd(workspaceRef) {
    let lastError = null;
    for (const root of roots) {
      try {
        // The board's own ACL, once per candidate root: the first root that
        // admits the ref is the matched root, so the containment rule is not
        // re-implemented here.
        assertWorkspaceWithin(workspaceRef, [root], { realpath });
      } catch (error) {
        lastError = error;
        continue;
      }
      return { root, cwd: path.resolve(root, workspaceRef.root_ref) };
    }
    throw lastError ?? new AclDenied('WORKSPACE_ESCAPE', 'the workspace ref is inside no known root');
  }

  // --- the process group ----------------------------------------------------

  function buildArgv({ cwd, messageFile, native, runId }) {
    const argv = [];
    const skillPaths = bundle === null ? [] : [...bundle.paths];
    if (provider === 'codex') {
      if (bundle !== null) {
        throw new BlockedPolicy(
          'SKILL_BUNDLE_UNSUPPORTED_PROVIDER',
          'codex 0.157.1 exposes no --skill flag (measured, recon 6 §1.2); a skill directory is not loadable '
          + 'through its argv, so loading one is refused rather than approximated',
        );
      }
      argv.push('exec', '--json', '--skip-git-repo-check', '--ephemeral', '--sandbox', 'read-only', '-C', cwd, '--output-last-message', messageFile);
      if (model !== null) argv.push('--model', model);
      // The surface, for codex, selects no flags at all: `codex exec --help`
      // lists 27 and none suppresses a context surface. The loop is kept so the
      // argv is built from the surface uniformly and a future end of the axis
      // needs no second code path.
      argv.push(...surface.surface_flags);
    } else {
      if (model === null) {
        throw new NeedsInput(
          'MODEL_REQUIRED:pi',
          'this host\'s configured pi default is not the verified model, so an explicit --model provider/id is mandatory',
        );
      }
      argv.push('-p', '--mode', 'json', '--model', model, '--no-session');
      // The STRUCTURAL control: only names derived from the intersection are
      // ever passed. An empty effective set authorizes no tool call at all.
      if (native.names.length === 0) argv.push('--no-tools');
      else argv.push('--tools', native.names.join(','));
      // THE ONLY difference between two cells of a comparison. Configuration A
      // passes no suppression flag at all (the host's own surface is left
      // alone) and configuration B suppresses all five. The same model pin, the
      // same derived --tools, the same timeout, the same prompt and the same
      // project are on both sides: this loop is the whole delta.
      argv.push(...surface.surface_flags);
      for (const skillPath of skillPaths) argv.push('--skill', skillPath);
    }
    argv.push(prompt);
    assertArgvAllowed(provider, argv);
    // BOTH digests, and the folds that produced the normalised one. The raw
    // digest is published because a reader must be able to see that the two
    // differ; the normalised one is published because a comparison must assert
    // on it — the per-run project copy, the evidence root and the run id are
    // inside the raw argv and would otherwise read as a configuration delta.
    const folds = [
      { from: cwd, to: '<project_root>', kind: 'per-run project copy' },
      { from: evidenceRoot, to: '<evidence_dir>', kind: 'per-invocation evidence root' },
      ...roots.map((root) => ({ from: root, to: '<workspace_root>', kind: 'injected containment root' })),
      { from: runId, to: '<run_id>', kind: 'per-run identity' },
    ];
    const digests = argvDigests(argv, folds);
    state.argvEvidence = {
      configuration: surface.configuration,
      configuration_name: surface.name,
      configuration_note: surface.surface_note,
      surface_flags: [...surface.surface_flags],
      skill_paths: skillPaths,
      axis: configurationAxis,
      raw: digests.raw,
      normalised: digests.normalised,
      normalised_argv: [...digests.normalised_argv],
      folds: [...digests.folds],
    };
    return Object.freeze({
      argv,
      unbound_effective_tools: native.unbound,
      tool_control: PROVIDER_ARGV_ALLOWLIST[provider].tool_control,
      surface,
      axis: configurationAxis,
    });
  }

  function appendCapped(stream, chunk) {
    const text = String(chunk);
    const bytes = Buffer.byteLength(text, 'utf8');
    if (state[`${stream}Bytes`] + bytes <= CAP_LIMIT) {
      state[stream] += text;
      state[`${stream}Bytes`] += bytes;
      return;
    }
    state.truncated = true;
  }

  function spawnExecutor({ cwd, argv }) {
    let child;
    try {
      child = spawn(binary.resolved, argv, {
        // No shell, ever. detached:true makes the child the leader of its OWN
        // POSIX process group, so the group can be signalled as a unit and the
        // observer can sweep it. stdin is ignored: both CLIs read it and a piped
        // stdin would change the prompt.
        detached: true,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd,
        windowsHide: true,
        // Only the three non-secret variables a CLI needs to resolve a
        // provider config. No value of a credential variable is ever read,
        // passed or logged.
        env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', LANG: 'C.UTF-8' },
      });
    } catch (error) {
      throw new AgentUnavailable('EXECUTOR_SPAWN_FAILED', redact(String(error?.message ?? error)).slice(0, 300));
    }
    if (child === null || typeof child.pid !== 'number') {
      throw new AgentUnavailable('EXECUTOR_SPAWN_REFUSED', 'the OS did not hand back a process id for the executor');
    }
    state.child = child;
    state.pid = child.pid;
    state.pgid = child.pid; // detached:true ⇒ the child's pid IS the new pgid
    state.argv = [...argv];
    state.pidIdentities = {
      [child.pid]: typeof procObserver.identityFor === 'function'
        ? procObserver.identityFor(child.pid)
        : String(child.pid),
    };
    state.exitPromise = new Promise((resolve) => { state.resolveExit = resolve; });
    child.on('error', (error) => {
      if (state.exit !== null) return;
      // A spawn that never became a process is not an observed exit; the
      // distinction is what keeps UNKNOWN/RECONCILIATION_REQUIRED reachable.
      state.exit = { code: null, signal: null, cause: state.cause ?? 'spawn_error' };
      state.exitObserved = false;
      settleExit(error);
    });
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk) => appendCapped('stdout', chunk));
    child.stderr?.on('data', (chunk) => appendCapped('stderr', chunk));
    child.on('exit', (code, signal) => {
      if (state.exit !== null) return;
      state.exit = { code: code === null ? null : Number(code), signal: signal ?? null, cause: state.cause };
      // The parent SAW the process leave. This is the fact the whole
      // classification turns on: an exit that was never observed leaves the
      // external effect unknown, and an exit that was observed is a fact even
      // when the code is null because the process was signalled.
      state.exitObserved = true;
      settleExit();
    });
    return child;
  }

  function settleExit(error) {
    clearDeadline();
    if (error !== undefined) {
      const note = `spawn_error: ${redact(String(error.message ?? error)).slice(0, 300)}\n`;
      state.stderr += note;
      state.stderrBytes += Buffer.byteLength(note, 'utf8');
    }
    if (typeof state.resolveExit === 'function') state.resolveExit(state.exit);
  }

  // --- the deadline timer, and every other timer this module arms ----------
  //
  // A run that settles must leave NOTHING pending that can hold the event loop
  // open. Round 2 measured a 4 s run keeping the process alive for 5m01s, and
  // the cause was not the deadline (that one is unref'd) but the losing side of
  // two Promise.race waits: `node:timers/promises` keeps its timer REF'd, so a
  // bounded wait that lost the race still held the loop for its whole duration.
  // So there is exactly one way to wait in this file now — `boundedRace` — and
  // it destroys its timer in a `finally` on every path, the losing and the
  // winning one alike.
  function armDeadline(timeoutMs) {
    clearDeadline();
    const timer = setTimeout(() => {
      if (state.exit !== null) return;
      terminateGroup('timeout').catch((error) => {
        const typed = isBoardError(error) ? error : toBoardError(error);
        state.errors.push(deepFreeze(assertBoardContract(
          'board-error',
          typed.toDocument(timestampOf(injectedClock)),
        )));
      });
    }, timeoutMs);
    // The deadline enforces a granted bound; it is not a reason to keep a
    // process alive, so it never holds the loop open by itself.
    if (typeof timer.unref === 'function') timer.unref();
    state.timer = timer;
    return timer;
  }

  function clearDeadline() {
    if (state.timer === null) return false;
    clearTimeout(state.timer);
    state.timer = null;
    return true;
  }

  /**
   * `Promise.race` against a bounded wait whose timer is DESTROYED in a finally.
   * Returns `{ timedOut: true }` when the bound elapsed first and
   * `{ timedOut: false, value }` when the promise settled first. The waiter's
   * timer exists for at most the duration of the call.
   */
  async function boundedRace(promise, ms) {
    const controller = new AbortController();
    // An aborted `timers/promises` sleep rejects with AbortError; it is
    // translated here so aborting the loser is not an unhandled rejection, and
    // the same value is returned for an abort as for an elapsed wait: either way
    // the bounded wait is over.
    const waiter = sleep(ms, undefined, { signal: controller.signal })
      .then(() => ({ timedOut: true, value: null }))
      .catch(() => ({ timedOut: true, value: null }));
    try {
      return await Promise.race([promise.then((value) => ({ timedOut: false, value })), waiter]);
    } finally {
      // Every path, including the throwing one: the loser of the race must not
      // outlive it.
      controller.abort();
    }
  }

  // The group kill. Signals the GROUP (negative pid), never the pid alone: a
  // pid kill leaves grandchildren, which is the exact defect the board's
  // cancellation evidence exists to catch.
  async function terminateGroup(cause) {
    if (state.pgid === null) {
      return { verdict: 'UNVERIFIED', survivors: null, remaining_process_ids: [], reason: 'NO_PROCESS_GROUP', signals: [] };
    }
    // Snapshot WHAT IS ALIVE first. A post-kill read that finds nothing is
    // only meaningful if the pre-kill read was non-empty.
    await snapshotGroup();
    const running = state.exit === null && state.child !== null;
    const signals = [];
    const signalGroup = (signal) => {
      if (!POSIX_GROUP_SIGNAL) {
        signals.push(`${signal}:UNAVAILABLE_ON_THIS_PLATFORM`);
        return false;
      }
      try {
        process.kill(-state.pgid, signal);
        signals.push(signal);
        return true;
      } catch (error) {
        if (error?.code === 'ESRCH') return true; // already gone: that is the goal
        return false;
      }
    };
    if (running) {
      if (state.cause === null) state.cause = cause;
      signalGroup('SIGTERM');
      // A plain bounded wait, not a race: nothing else is competing for it, and
      // it is the transport's own grace. It ends by itself.
      await sleep(cancelGraceMs);
    }
    if (state.exit === null) signalGroup('SIGKILL');
    // REAP BEFORE THE ACCOUNTING (round 3, measured in round 2). A child that
    // was killed and not yet reaped is still in the process table, so a survivor
    // count taken the instant after the kill names a process that is already
    // gone: that is exactly how round 2 reported SURVIVORS_REMAINING for a
    // cancel whose child was dead, and then escalated a correct stop to
    // UNKNOWN_OUTCOME. The exit is therefore WAITED FOR before the observer is
    // asked anything, and both readings are published.
    const immediate = await proveTermination({ signalDelivered: signals.includes('SIGTERM') || signals.includes('SIGKILL') });
    const reaped = await boundedRace(state.exitPromise ?? Promise.resolve(null), observerSettleMs);
    const proof = reaped.timedOut
      ? immediate
      : await proveTermination({ signalDelivered: signals.includes('SIGTERM') || signals.includes('SIGKILL') });
    proof.reaped_before_accounting = !reaped.timedOut;
    proof.accounting = reaped.timedOut
      ? 'IMMEDIATE_AFTER_SIGNAL_NO_EXIT_WAS_OBSERVED_WITHIN_THE_BOUND'
      : 'AFTER_THE_CHILD_EXIT_WAS_OBSERVED';
    // THE STALENESS OF THE OBSERVER'S OWN READ (measured, issue #45, round 3).
    // Waiting for the exit before accounting closes the parent's reaping race,
    // and it does NOT close the observer's: the shipped observer memoises its
    // /proc snapshot for a short TTL (src/lib/identity/process-observer.mjs
    // #procTable), so a reading taken inside that window still sees the pid that
    // has just been reaped. Measured on this host with no model involved: after a
    // killed child's `exit` event had already fired in the parent, `listExisting`
    // still reported the pid alive, and 1.5 s later reported it gone, while
    // `process.kill(pid, 0)` answered ESRCH throughout. The proof therefore
    // carries the caveat wherever the survivor set can only come from a captured
    // pid, and the parent-side later reading is the independent one.
    proof.observer_read_staleness = 'the shipped observer memoises its /proc snapshot for a short TTL (src/lib/identity/process-observer.mjs#procTable), so a survivor count taken within that window of a reap can name a pid that is already gone. A survivor set consisting only of pids this transport captured, with no process ever seen alive before the kill, must be read against an independent parent-side check of the same pids.';
    // When the two readings disagree, the observer's first answer is KEPT beside
    // the accounting one, never overwritten by it: the disagreement is itself
    // the finding, and an unreaped-but-dead pid is the ordinary reason for it.
    proof.readings_disagree = !reaped.timedOut && (immediate.verdict !== proof.verdict
      || immediate.survivors !== proof.survivors);
    proof.pre_accounting_reading = {
      when: 'immediately after the group signal, before the child was reaped',
      verdict: immediate.verdict,
      survivors: immediate.survivors,
      remaining_process_ids: immediate.remaining_process_ids,
      reason: immediate.reason,
    };
    proof.accounting_reading = {
      when: 'after the child exit was observed',
      verdict: proof.verdict,
      survivors: proof.survivors,
      remaining_process_ids: proof.remaining_process_ids,
    };
    // The pair of observations is the evidence: what was alive BEFORE the kill
    // and what was still alive AFTER it. A zero-survivor claim with an empty
    // before-list proves nothing, and the record must show both. The signals
    // actually sent are part of it: a proof that hides them cannot be checked.
    proof.pids_before_kill = [...state.groupPids];
    proof.pids_after_kill = [...proof.remaining_process_ids];
    proof.signals = [...signals];
    proof.kill_was_needed = running;
    // When nothing was observed alive before the kill, `survivors: 0` covers
    // only what this transport had already seen. That caveat is stated in the
    // proof itself, so nobody can read the zero as stronger evidence than it is.
    proof.caveat = state.groupPids.length === 0
      ? 'NO_PROCESS_WAS_OBSERVED_BEFORE_THE_KILL: the survivor count covers only the processes already seen'
      : null;
    state.cancelProof = proof;
    return proof;
  }

  async function snapshotGroup() {
    if (typeof procObserver.listDescendants !== 'function') return [];
    try {
      const tree = await procObserver.listDescendants(state.pid, {
        // detached:true makes the child a session leader, so its sid is its
        // pid and its pgid is its pid. Recorded, never assumed elsewhere.
        sessions: [state.pid],
        processGroups: [state.pgid],
      });
      if (Array.isArray(tree?.pids)) state.groupPids = sortedUnique([...state.groupPids, ...tree.pids]);
      return tree;
    } catch {
      return null;
    }
  }

  async function proveTermination({ signalDelivered = false } = {}) {
    if (state.pgid === null) {
      return { verdict: 'UNVERIFIED', survivors: null, remaining_process_ids: [], reason: 'NO_PROCESS_GROUP' };
    }
    if (!POSIX_GROUP_SIGNAL) {
      return {
        verdict: 'UNVERIFIED',
        survivors: null,
        remaining_process_ids: [],
        reason: 'POSIX_GROUP_SIGNAL_UNAVAILABLE_ON_THIS_PLATFORM',
      };
    }
    const captured = [...state.groupPids, ...Object.keys(state.pidIdentities).map(Number)];
    let tree = { pids: [], observable: false, reason: 'OBSERVER_TREE_UNAVAILABLE' };
    if (typeof procObserver.listDescendants === 'function') {
      try {
        tree = await procObserver.listDescendants(state.pid, {
          sessions: [state.pid],
          processGroups: [state.pgid],
        });
      } catch {
        tree = { pids: [], observable: false, reason: 'OBSERVER_TREE_THREW' };
      }
    }
    const set = sortedUnique([...captured, ...(Array.isArray(tree.pids) ? tree.pids : [])])
      .filter((pid) => Number.isInteger(pid) && pid > 0);
    // listExisting is the one observer call that is NOT defensive: an observer
    // that throws here used to reject terminateGroup() and, from the budget
    // timer, escape as an unhandled rejection. A throw is an observation this
    // transport cannot make, which is UNVERIFIED, never a failure of the kill.
    let existing;
    try {
      existing = await procObserver.listExisting(set, state.pidIdentities);
    } catch {
      existing = { alive: [], observable: false, reason: 'OBSERVER_LIST_EXISTING_THREW' };
    }
    const alive = Array.isArray(existing?.alive) ? existing.alive : [];
    const observable = existing?.observable === true && tree.observable !== false;
    if (!observable) {
      return {
        verdict: 'UNVERIFIED',
        // survivors is NULL, never 0: an unobservable process space proves
        // nothing, and reporting 0 here is the false zero the board's
        // evidence rules exist to prevent.
        survivors: null,
        remaining_process_ids: alive,
        reason: existing?.reason ?? tree.reason ?? 'OBSERVATION_UNAVAILABLE',
      };
    }
    // The false zero, in the one place it used to appear: an OBSERVABLE process
    // space that was empty, where nothing was ever seen alive and no signal
    // was ever delivered. `TERMINATED` with `survivors: 0` there describes a
    // kill that never happened. UNVERIFIED with survivors: null is the only
    // honest answer, and it is what makes the cancel refuse instead of
    // reporting a clean stop.
    if (alive.length === 0 && !signalDelivered && state.groupPids.length === 0) {
      return {
        verdict: 'UNVERIFIED',
        survivors: null,
        remaining_process_ids: [],
        reason: 'NO_PROCESS_WAS_OBSERVED_BEFORE_THE_KILL',
      };
    }
    return {
      verdict: alive.length === 0 ? 'TERMINATED' : 'SURVIVORS_REMAINING',
      survivors: alive.length,
      remaining_process_ids: alive,
      reason: alive.length === 0 ? null : 'PROCESSES_SURVIVED_THE_GROUP_KILL',
    };
  }

  // --- the raw process log --------------------------------------------------

  function rawLogPath(runId, index) {
    return path.join(evidenceRoot, runId, 'raw', `exec-${String(index).padStart(3, '0')}.log.json`);
  }

  /**
   * Write the raw process log ONCE per run and return its path plus digests.
   * The document records the exact argv, the cwd, the exit status, the
   * stdout/stderr digests and the executor's own token/cost report. It NEVER
   * records an environment value and never records the executor's output TEXT:
   * only its digest and byte length. That is why no secret can reach it.
   *
   * Every real invocation writes one, including a cancelled one: an invocation
   * that was stopped is still an invocation and still needs its log.
   */
  function ensureRawLog(run) {
    if (state.rawLogs.length > 0) return state.rawLogs[0];
    const lastMessageText = state.lastMessagePath === null ? null : safeReadText(state.lastMessagePath);
    const read = readExecutorOutcome({
      provider,
      exitCode: state.exit?.code ?? null,
      signal: state.exit?.signal ?? null,
      stdoutText: state.stdout,
      stderrText: state.stderr,
      lastMessageText,
    });
    state.readOutcome = read;
    const target = rawLogPath(run.run_id, 0);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const document = {
      contractVersion: BOARD_CONTRACT_VERSION,
      record_kind: 'real-executor-raw-process-log',
      executor_version: REAL_EXECUTOR_VERSION,
      run_id: run.run_id,
      executor: {
        provider,
        binary_path: binary.resolved,
        binary_named_path: binary.named,
        binary_sha256: binary.sha256,
      },
      invocation: {
        // argv as an ARRAY: the exact tokens the OS received, in order. Its
        // last element is the brief, in CLEARTEXT, because the provider CLI
        // takes the prompt as a positional argument. There is no prompt digest
        // here pretending otherwise; the board's own brief_digest is the value
        // this invocation was authorized under.
        argv: [...state.argv],
        argv_carries_prompt_in_cleartext: true,
        brief_digest: run.brief_digest,
        cwd: run.cwd,
        skills: bundle === null ? null : { paths: [...bundle.paths], requested_tools: [...bundle.requested_tools] },
        effective_tools: [...run.effective_tools],
        unbound_effective_tools: [...effectiveNativeTools(run.effective_tools).unbound],
        tool_control: PROVIDER_ARGV_ALLOWLIST[provider].tool_control,
        argv_allowlist: [...PROVIDER_ARGV_ALLOWLIST[provider].tokens],
        argv_allowlist_digest: wireDigest(PROVIDER_ARGV_ALLOWLIST[provider].tokens.join(' ')),
        // THE CONFIGURATION AXIS, as executed. `configuration` is which end of
        // the axis this invocation ran; `configuration_axis.distinguishable` is
        // whether this provider may be compared at all, and the reason is the
        // measurement that decides it. TWO digests are published, always both:
        // the raw one is the exact argv as the OS received it, and the
        // normalised one has the per-run paths (the project copy, the evidence
        // root, the injected roots, the run id) folded out. A comparison asserts
        // on the normalised digest; publishing the raw one is what lets a reader
        // check that the normalisation removed the run and not the surface.
        configuration: state.argvEvidence?.configuration ?? null,
        configuration_name: state.argvEvidence?.configuration_name ?? null,
        configuration_surface_flags: state.argvEvidence?.surface_flags ?? [],
        configuration_note: state.argvEvidence?.configuration_note ?? null,
        configuration_axis: state.argvEvidence === null ? null : {
          axis: state.argvEvidence.axis.axis,
          provider,
          configurations: [...state.argvEvidence.axis.configurations],
          configuration_a_flags: [...state.argvEvidence.axis.configuration_a_flags],
          configuration_b_flags: [...state.argvEvidence.axis.configuration_b_flags],
          distinguishable: state.argvEvidence.axis.distinguishable,
          reason: state.argvEvidence.axis.reason,
          measured: state.argvEvidence.axis.measured === null ? null : { ...state.argvEvidence.axis.measured },
          exclusion: state.argvEvidence.axis.distinguishable
            ? null
            : `EXCLUDED_FROM_COMPARISON:${provider}:${state.argvEvidence.axis.reason}`,
        },
        argv_digest_raw: state.argvEvidence?.raw ?? null,
        argv_digest_normalised: state.argvEvidence?.normalised ?? null,
        argv_normalised: state.argvEvidence?.normalised_argv ?? null,
        argv_normalisation: {
          rule: 'per-run values are folded out (the resolved project directory, the evidence root, the injected containment roots, the run id); nothing else is touched, so a difference that survives normalisation is a difference in the command itself',
          folds: state.argvEvidence?.folds ?? [],
        },
        // NOT recorded: every environment value. Only the variable-shaped keys
        // the child needed, by name.
        environment_keys: ['PATH', 'HOME', 'LANG'],
      },
      // What the registered sandbox profile DECLARED next to what was actually
      // in force. isolation_applied is false on every run this transport makes:
      // the child ran on the host, not inside the profile.
      isolation: state.isolation,
      started_at: state.startedAt,
      ended_at: timestampOf(injectedClock),
      // The grant the run was authorized under, recorded separately from the
      // measurement: the executor's cost report is USD and the grant may be
      // EUR/GBP/RUB, and no rate is ever invented here.
      budget_grant: { currency: run.budget_currency, timeout_ms: run.timeout_ms },
      exit_status: read.exit_code,
      signal: read.signal,
      cause: state.cause,
      stdout_sha256: wireDigest(state.stdout),
      stdout_bytes: state.stdoutBytes,
      stderr_sha256: read.stderr_digest,
      stderr_bytes: state.stderrBytes,
      output_truncated: state.truncated,
      assistant_text_sha256: read.assistant_text === null ? null : wireDigest(read.assistant_text),
      assistant_text_bytes: read.assistant_text === null ? 0 : Buffer.byteLength(read.assistant_text, 'utf8'),
      provider_error: read.failure,
      usage: read.usage,
      exit_observed: state.exitObserved,
      cancel_proof: state.cancelProof,
      event_sequence: state.events.map((event) => ({ sequence: event.sequence, event_type: event.event_type })),
    };
    const bytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`, 'utf8');
    fs.writeFileSync(target, bytes);
    const entry = Object.freeze({
      path: target,
      sha256: wireDigest(bytes),
      bytes: bytes.length,
      stdout_sha256: document.stdout_sha256,
      stderr_sha256: document.stderr_sha256,
      usage: read.usage,
      provider_error: read.failure,
    });
    state.rawLogs.push(entry);
    return entry;
  }

  // --- the ten methods ------------------------------------------------------

  const transport = {
    async identify(args) {
      return guard(async () => {
        assertCallArgs('identify', args);
        // Identity IS the registration: it is the only self-description the
        // board accepts, and it is the CONTRACT-VALIDATED document this
        // transport was bound to at construction, not a caller's copy.
        return bound;
      });
    },

    async capabilities(args) {
      return guard(async () => {
        const object = assertCallArgs('capabilities', args);
        const claimedCapabilities = object.claimed_capabilities
          ?? (object.claimed === undefined || object.claimed === null
            ? undefined
            : (Array.isArray(object.claimed) ? object.claimed : object.claimed.capabilities));
        const claimedTools = object.claimed_tools
          ?? (object.claimed === undefined || object.claimed === null || Array.isArray(object.claimed)
            ? undefined
            : object.claimed.tools);
        // A self-declared capability is a CLAIM. It is cross-checked against
        // the operator registration AND the grant, and a tool the registration
        // does not carry is refused. This is the arm a planted SKILL.md hits: a
        // skill that "grants itself" tool:net.fetch is refused here, and the
        // attempt is recorded as an authority expansion.
        if (claimedCapabilities !== undefined || claimedTools !== undefined) {
          const tools = claimedTools ?? [];
          for (const tool of tools) {
            if (!declaredTools.has(tool)) {
              recordExpansion('adapter_claim', tool, 'the claim is absent from the operator registration');
            }
          }
          crossCheckCapabilities({
            registration,
            claimed: { capabilities: claimedCapabilities ?? [], tools },
            grant: {
              capabilities: [...registration.declared_capabilities],
              tools: [...registration.declared_tools],
            },
          });
        }
        return deepFreeze({
          adapter_id: bound.adapter_id,
          adapter_interface: bound.adapter_interface,
          adapter_kind: bound.adapter_kind,
          capabilities: [...bound.declared_capabilities],
          tools: [...bound.declared_tools],
          sandbox_profile_id: bound.sandbox_profile_id,
          provenance_status: bound.real_adapter_provenance.status,
          // The structural half of the tool control, made legible: what this
          // provider's argv could carry at all.
          argv_tool_control: PROVIDER_ARGV_ALLOWLIST[provider].tool_control,
          argv_allowlist: [...PROVIDER_ARGV_ALLOWLIST[provider].tokens],
          skill_support: PROVIDER_ARGV_ALLOWLIST[provider].skill_support,
        });
      });
    },

    async health(args) {
      return guard(async () => {
        assertCallArgs('health', args);
        // A host fact, not a claim: is the resolved binary still executable?
        let present = true;
        try {
          fs.accessSync(binary.resolved, fs.constants.X_OK);
        } catch {
          present = false;
        }
        return deepFreeze({
          adapter_id: bound.adapter_id,
          health: present ? bound.health : 'unhealthy',
          adapter_kind: bound.adapter_kind,
          provenance_status: bound.real_adapter_provenance.status,
          executor_present: present,
          checked_at: timestampOf(injectedClock),
        });
      });
    },

    async claim(args) {
      return guard(async () => {
        const object = assertCallArgs('claim', args);
        const lease = {
          task_id: requireString(object.task_id, 'task_id'),
          lease_id: requireString(object.lease_id, 'lease_id'),
          fencing_token: requireInteger(object.fencing_token, 'fencing_token'),
          adapter_id: object.adapter_id ?? registration.adapter_id,
        };
        if (lease.adapter_id !== registration.adapter_id) {
          throw new CapabilityMismatch(
            'ADAPTER_SUBSTITUTION_REFUSED',
            `the lease names adapter ${lease.adapter_id}; this transport is ${registration.adapter_id}`,
          );
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
            throw new MalformedResult(
              'LEASE_ALREADY_CLAIMED',
              `this transport already holds ${held.lease_id}@${held.fencing_token}; a second, different claim is never honoured`,
            );
          }
          return buildLeaseAck('claim', lease, state.run?.run_id ?? null, 'idempotent repeat; no second lease');
        }
        state.lease = lease;
        return buildLeaseAck('claim', lease, null, null);
      });
    },

    async start(request, args) {
      return guard(async () => {
        let handoff = request;
        let rawCall = args;
        if (isPlainObject(request) && request.request !== undefined && args === undefined) {
          const { request: nested, ...rest } = request;
          handoff = nested;
          rawCall = rest;
        }
        const call = assertCallArgs('start', rawCall);
        // The run id is a CALL argument when the caller can pass one, and the
        // out-of-band correlation when it cannot: `driveOutbox` sends exactly
        // the request payload, so a governed dispatch reaches this method with
        // no args at all. A missing id with no binding is still a refusal — the
        // run is never given an id this transport invented.
        const presentedRunId = call.run_id !== undefined && call.run_id !== null
          ? requireString(call.run_id, 'run_id')
          : requireString(state.boundRun?.run_id, 'run_id (no bindRun() correlation and no call argument)');
        const document = requireObject(handoff, 'execution request');
        // Version handshake first, then the frozen shape: an unknown major
        // version is rejected before any state changes and before any process
        // exists.
        assertExecutionVersion(document);
        const preflight = assertBoardContract('execution-request', document);
        if (state.run !== null) {
          rejectUnknownOutcome();
          if (state.run.request_id === preflight.request_id) {
            const accepted = state.events[0];
            if (accepted !== undefined) return accepted;
            throw new MalformedResult(
              'RUN_START_INCOMPLETE',
              `run ${state.run.run_id} is bound to request ${state.run.request_id} but no acceptance was ever recorded`,
            );
          }
          throw new MalformedResult(
            'RUN_ALREADY_STARTED',
            `run ${state.run.run_id} is already started; a second request is never merged into it`,
          );
        }
        if (call.workspace_id !== undefined && call.workspace_id !== null && call.workspace_id !== preflight.workspace_id) {
          throw new MalformedResult(
            'REQUEST_WORKSPACE_MISMATCH',
            `the call names workspace ${call.workspace_id}; the request authorizes ${preflight.workspace_id}`,
          );
        }
        const leaseId = requireString(preflight.lease_id, 'request.lease_id');
        const fence = requireInteger(preflight.fencing_token, 'request.fencing_token');
        if (state.lease !== null) {
          if (leaseId !== state.lease.lease_id) {
            throw new MalformedResult(
              'REQUEST_LEASE_MISMATCH',
              `the request names lease ${leaseId}; this transport holds ${state.lease.lease_id}`,
            );
          }
          if (fence < state.lease.fencing_token) {
            throw new StaleFence(
              `STALE_FENCE:request ${preflight.request_id}`,
              `request fence ${fence} is behind the held fence ${state.lease.fencing_token}`,
            );
          }
          if (fence > state.lease.fencing_token) {
            throw new MalformedResult(
              'FENCE_AHEAD_OF_LEASE',
              `request fence ${fence} is ahead of the held lease fence ${state.lease.fencing_token}`,
            );
          }
        }

        // --- everything below happens BEFORE a process exists --------------
        // The workspace ACL: the cwd is derived from the request's own
        // workspace_ref through the board's own guard.
        const workspaceRef = requireObject(preflight.workspace_ref, 'request.workspace_ref');
        if (workspaceRef.workspace_id !== preflight.workspace_id) {
          throw new AclDenied('WORKSPACE_REF_MISMATCH', 'workspace_ref names a different workspace than the request');
        }
        // THE SANDBOX GATE (owner decision, issue #45). One function decides, and
        // the transport enforces whatever it returns:
        //   * a proven LOCAL_RESTRICTED / UNTRUSTED_CODE tier passes this check
        //     and REFUSES a permit — and then this transport still cannot put
        //     the child inside it, so it refuses the run rather than naming
        //     controls it does not have;
        //   * the HOST_UNISOLATED floor is admitted only with a complete permit
        //     and runs as an ordinary host child, recorded with
        //     isolation_observed:false;
        //   * everything else (NO_EXEC, the *_blocked tiers, an invented id) is
        //     BLOCKED_SANDBOX.
        // A profile that is merely DECLARED is a control that does not exist, so
        // the "really enforce it" branch below is a refusal, not a guess.
        const sandboxDecision = assertLiveExecutionAuthorized(workspaceRef.isolation_profile_id, {
          authorization: unisolatedExecutionAuthorization,
          now: () => timestampOf(injectedClock),
        });
        if (sandboxDecision.tier === 'ISOLATED') {
          throw new BlockedSandbox(
            'SANDBOX_NOT_ENFORCED_BY_THIS_TRANSPORT',
            `the request names ${workspaceRef.isolation_profile_id}, whose OS controls are measured, but this `
            + 'transport spawns the child directly on the host and therefore cannot enforce them. A run record '
            + 'may not name a profile whose controls were not in force, so the run is refused rather than '
            + 'misreported. Running a model-calling executor inside that tier needs the pinned image, the '
            + 'network allowlist and the secret-handle mechanism, and is issue #12\'s dependency, not a knob.',
          );
        }
        if (workspaceRef.isolation_profile_id !== bound.sandbox_profile_id) {
          throw new BlockedPolicy(
            'ADAPTER_SANDBOX_PROFILE_MISMATCH',
            `the request is bound to ${workspaceRef.isolation_profile_id}; this adapter is registered for `
            + `${bound.sandbox_profile_id}`,
          );
        }
        // The isolation TRUTH, recorded after the cwd is resolved and before
        // anything is spawned. The profile is a request-side declaration; this
        // transport spawns the child directly on the host, so
        // `isolation_applied` is false and every declared control is recorded as
        // declared-not-applied. A reader that takes the profile id off the
        // registration cannot be misled about what the run was, because the
        // run's own evidence says so.
        const resolved = resolveCwd(workspaceRef);
        if (typeof realpath === 'function') {
          let real = null;
          try {
            real = realpath(resolved.cwd);
          } catch {
            real = null;
          }
          if (real === null) {
            throw new AclDenied('WORKSPACE_UNRESOLVABLE', 'the resolved workspace directory could not be resolved');
          }
          resolved.cwd = real;
        }
        state.sandboxDecision = sandboxDecision;
        state.isolation = describeIsolation({
          profileId: workspaceRef.isolation_profile_id,
          workspaceRef,
          sandboxDecision,
          cwd: resolved.cwd,
        });

        // --- capability / tool cross-check, before the spawn ---------------
        // The INTERSECTION comes from the cross-check's own effective_tools,
        // which is claim ∩ grant. Recomputing it from the request alone would
        // silently widen the child's authority to everything the request asks
        // for, which is wider than what the BOARD granted.
        let effective;
        if (grant !== null) {
          const cross = crossCheckCapabilities({
            registration: bound,
            claimed: { capabilities: preflight.granted_scope, tools: preflight.allowed_tools },
            grant,
          });
          effective = effectiveToolIds(new Set(cross.effective_tools));
        } else {
          // Without a grant object the request's own tool list is the grant for
          // the effective set, and a tool the registration does not carry is
          // refused here rather than at the child.
          for (const tool of preflight.allowed_tools) {
            if (declaredTools.has(tool)) continue;
            recordExpansion('execution_request', tool, 'the request grants a tool absent from the operator registration');
            throw new CapabilityMismatch(
              'GRANT_NOT_REGISTERED',
              `the request grants ${tool}, which the registration for ${bound.adapter_id} does not declare`,
            );
          }
          effective = effectiveToolIds(new Set(preflight.allowed_tools));
        }
        assertNoAuthorityExpansion(bundle, effective);
        const native = effectiveNativeTools(effective);

        const rawDir = path.join(evidenceRoot, presentedRunId, 'raw');
        const messageFile = path.join(rawDir, 'last-message.txt');
        // Only codex writes its answer to a file; pi's answer is in its own
        // JSONL. Recording which one is in play is part of reading the output
        // honestly rather than assuming both look the same.
        state.lastMessagePath = provider === 'codex' ? messageFile : null;
        const argvConfig = buildArgv({ cwd: resolved.cwd, messageFile, native, runId: presentedRunId });

        state.run = {
          request_id: preflight.request_id,
          run_id: presentedRunId,
          task_id: requireString(preflight.task_id, 'request.task_id'),
          workspace_id: requireString(preflight.workspace_id, 'request.workspace_id'),
          lease_id: leaseId,
          fencing_token: fence,
          brief_digest: preflight.brief_digest,
          budget_currency: preflight.budget_grant.currency,
          timeout_ms: preflight.budget_grant.timeout_ms,
          cwd: resolved.cwd,
          effective_tools: effective,
          last_sequence: 0,
          cancelled: false,
          unknown: false,
        };
        if (state.lease === null) {
          state.lease = {
            task_id: state.run.task_id,
            lease_id: leaseId,
            fencing_token: fence,
            adapter_id: registration.adapter_id,
          };
        }

        const startedAtMs = injectedClock.now().getTime();
        state.startedAtMs = startedAtMs;
        state.startedAt = timestampOf(injectedClock);
        try {
          fs.mkdirSync(rawDir, { recursive: true });
          spawnExecutor({ cwd: resolved.cwd, argv: [...argvConfig.argv] });
          // The real timer enforces the caller-authorized budget timeout. It is
          // enforcement of a granted bound, not a reading of the process clock;
          // the duration that lands in the result is the injected clock's. The
          // callback is fire-and-forget, so its rejection is CONVERTED, not
          // dropped: a bare Error from an observer inside terminateGroup() would
          // otherwise leave this module as an unhandled rejection, which is not
          // a typed refusal and is not inside this module's control.
          armDeadline(preflight.budget_grant.timeout_ms);
          return emitEvent('ACCEPTED', {
            payload: {
              request_id: preflight.request_id,
              idempotency_key: preflight.idempotency_key,
              // The crossing is recorded as a FACT, not as a verdict.
              executor: { provider, version: REAL_EXECUTOR_VERSION, binary_sha256: binary.sha256 },
              tool_control: argvConfig.tool_control,
              effective_tools: [...native.names],
              unbound_effective_tools: [...native.unbound],
              cwd_digest: wireDigest(resolved.cwd),
              // The profile id the request named, and the truth about what was
              // actually in force while the child ran.
              isolation: state.isolation,
              // THE CONFIGURATION AXIS, published on the run's own first event:
              // which end of the axis this run is, whether the provider can be
              // compared at all, and BOTH argv digests. A comparison asserts on
              // `normalised`; `raw` sits beside it so a reader can see that what
              // the normalisation removed was the per-run paths and not the
              // surface.
              configuration: state.argvEvidence.configuration,
              configuration_name: state.argvEvidence.configuration_name,
              configuration_axis: {
                axis: configurationAxis.axis,
                distinguishable: configurationAxis.distinguishable,
                reason: configurationAxis.reason,
                configuration_a_flags: [...configurationAxis.configuration_a_flags],
                configuration_b_flags: [...configurationAxis.configuration_b_flags],
              },
              argv_digest_raw: state.argvEvidence.raw,
              argv_digest_normalised: state.argvEvidence.normalised,
              argv_normalised: state.argvEvidence.normalised_argv,
              argv_normalisation_folds: state.argvEvidence.folds,
            },
          });
        } catch (error) {
          // A failed start asserts nothing about the run: the run binding is
          // rolled back so the caller may retry with a fixed configuration, and
          // NOTHING is left pending. The deadline is cleared and a child that
          // did start is signalled and accounted for, so a throw between the
          // spawn and the ACCEPTED event cannot leave an armed timer or an
          // unowned process group behind.
          clearDeadline();
          if (state.child !== null) {
            try {
              await terminateGroup('start_failed');
            } catch {
              // Best-effort: the caller is being told about the start failure,
              // and whatever the kill produced is on transport.cancelProof.
            }
          }
          state.run = null;
          throw error;
        }
      });
    },

    async status(args) {
      return guard(async () => {
        const object = assertCallArgs('status', args);
        const run = requireRun();
        rejectUnknownOutcome();
        assertRunIdentity(object, run);
        const terminal = terminalEvent();
        if (terminal !== null) return terminal;
        verifyExpectedSequence(object, run.last_sequence + 1);
        const live = liveProcessState();
        if (live === 'RUNNING') {
          // Observing the live process is what status() is for, so the process
          // TREE is recorded here too. Without a pre-kill observation a
          // zero-survivor claim would be an empty answer, not a measurement.
          await snapshotGroup();
          // The live process state maps to a non-terminal execution event: the
          // first observation of a live child is STARTED, every later poll is
          // PROGRESS. A child that has already exited is still PROGRESS until
          // collect_result classifies it, because the outcome is not known yet
          // and PROGRESS never claims one.
          const first = state.events.some((event) => event.event_type === 'STARTED');
          return emitEvent(first ? 'PROGRESS' : 'STARTED', {
            payload: { process: live, pid_digest: wireDigest(String(state.pid)) },
          });
        }
        if (live === 'EXITED') {
          return emitEvent('PROGRESS', { payload: { process: live } });
        }
        throw new AgentUnavailable('PROCESS_STATE_UNREADABLE', 'the executor process state could not be read');
      });
    },

    async checkpoint(args) {
      return guard(async () => {
        const object = assertCallArgs('checkpoint', args);
        const run = requireRun();
        rejectUnknownOutcome();
        assertRunIdentity(object, run);
        verifyExpectedSequence(object, run.last_sequence + 1);
        const settled = terminalEvent();
        if (settled !== null) {
          throw new MalformedResult(
            'CHECKPOINT_AFTER_TERMINAL',
            `run ${run.run_id} already recorded ${settled.event_type}; a checkpoint cannot extend a known outcome`,
          );
        }
        // A checkpoint is bound to the brief, workspace and tool digests it was
        // produced under. The brief digest is the request's own value and is
        // COMPARED, not copied: a resume under a changed brief is refused.
        if (object.brief_digest !== run.brief_digest) {
          throw new MalformedResult(
            'CHECKPOINT_BRIEF_MISMATCH',
            `checkpoint brief ${String(object.brief_digest)} does not match the authorized brief ${run.brief_digest}`,
          );
        }
        return emitEvent('CHECKPOINT', {
          payload: {
            checkpoint_id: idFor('checkpoint', `${run.run_id}:${run.last_sequence + 1}`),
            brief_digest: object.brief_digest,
            workspace_digest: object.workspace_digest,
            tool_digest: object.tool_digest,
            effective_tools: [...run.effective_tools],
          },
          sequence: run.last_sequence + 1,
        });
      });
    },

    async cancel(args) {
      return guard(async () => {
        const object = assertCallArgs('cancel', args);
        const run = requireRun();
        rejectUnknownOutcome();
        assertRunIdentity(object, run);
        const terminal = terminalEvent();
        if (terminal !== null) {
          throw new MalformedResult(
            'CANCEL_AFTER_TERMINAL',
            `run ${run.run_id} already recorded ${terminal.event_type}; a cancel cannot rewrite a known outcome`,
          );
        }
        verifyExpectedSequence(object, run.last_sequence + 1);
        // A cancel for a process that has ALREADY EXITED is not a cancel, and
        // re-labelling a finished run as CANCELLED would overwrite a real
        // outcome (exit 0 with a real answer) with a stop that never happened.
        // The run's real outcome stays decidable through collect_result().
        if (state.exit !== null) {
          throw new MalformedResult(
            `CANCEL_AFTER_PROCESS_EXIT:${String(state.exit.code)}`,
            'the executor process has already exited, so there is nothing to cancel; the run\'s real outcome is '
            + `decided by collect_result() and a cancel never rewrites it into a ${'CANCELLED'}`,
          );
        }
        if (state.cause === null) state.cause = 'cancel';
        // Signal the group promptly: a cancel waits for SIGTERM to be absorbed
        // (cancelGraceMs) and then escalates to SIGKILL. A child that has
        // already exited is still snapshotted and accounted for.
        const proof = await terminateGroup('cancel');
        // The run is over on every path out of a cancel: proved or not, no
        // deadline stays armed behind it.
        clearDeadline();
        if (proof.verdict !== 'TERMINATED') {
          // The invocation happened and cannot be accounted for, so it still
          // gets its raw log: the one moment the evidence matters most is the
          // one where a run cannot be explained, and a spawn+signal with no
          // log, no terminal event and no record of the kill is the least
          // evidence of all.
          ensureRawLog(run);
          // A cancel that cannot prove the group is gone says so. It does not
          // emit CANCELLED, does not report a clean stop, and puts the run into
          // the non-retryable unknown state.
          markUnknown();
          throw new UnknownOutcome(
            `CANCEL_UNPROVEN:${proof.verdict}`,
            `survivors ${String(proof.survivors)}; remaining pids ${JSON.stringify(proof.remaining_process_ids)}; `
            + `reason ${String(proof.reason)}; a cancel that cannot prove the group is gone never reports success`,
          );
        }
        run.cancelled = true;
        const event = emitEvent('CANCELLED', {
          outcome: 'CANCELLED',
          payload: {
            reason: object.reason ?? 'cancelled by the board',
            termination: terminationBlock(proof),
          },
        });
        // A cancelled invocation is still an invocation: it gets its raw log,
        // with whatever exit status could be observed after the group kill.
        await boundedRace(state.exitPromise ?? Promise.resolve(null), observerSettleMs);
        ensureRawLog(run);
        return event;
      });
    },

    async collect_result(args) {
      return guard(async () => {
        const object = assertCallArgs('collect_result', args);
        const run = requireRun();
        // Identity BEFORE the cache: a cached result is still this run's
        // record, and a caller presenting another run's id, task, lease or a
        // stale fence has no business reading it. The short-circuit is a
        // performance convenience, never an authorization.
        assertRunIdentity(object, run);
        if (state.result !== null) return state.result;
        rejectUnknownOutcome();
        verifyExpectedSequence(object, run.last_sequence + 1);
        // A run whose terminal event is already recorded is READ, not
        // re-classified: the outcome was decided once and nothing here may
        // append a second terminal event or re-derive an outcome.
        const recorded = terminalEvent();
        if (recorded !== null) {
          state.result = buildResultFromTerminal(run, recorded);
          return state.result;
        }
        await awaitChildExit(run);
        const outcome = classify(run);
        emitEvent(outcome.event_type, { outcome: outcome.outcome, payload: outcome.payload });
        state.result = buildResult(run, outcome);
        // The run is decided, so nothing this transport armed may stay armed.
        clearDeadline();
        return state.result;
      });
    },

    async release(args) {
      return guard(async () => {
        const object = assertCallArgs('release', args);
        const taskId = requireString(object.task_id, 'task_id');
        const leaseId = requireString(object.lease_id, 'lease_id');
        const fence = requireInteger(object.fencing_token, 'fencing_token');
        if (state.lease === null) {
          throw new NeedsInput('NO_HELD_LEASE', 'there is nothing to release on this transport');
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
        // Releasing the lease asserts nothing about the run's outcome.
        state.released = { ...state.lease };
        return buildLeaseAck('release', state.lease, state.run?.run_id ?? null, object.reason ?? null);
      });
    },

    // --- non-contract observability (never part of the ten methods) --------
    /** The frozen AdapterRegistration this transport may present. */
    registration: bound,
    /** Every event this transport emitted, contract-valid and frozen. */
    get events() {
      return deepFreeze([...state.events]);
    },
    /** Every typed failure, as validated BoardError documents. */
    get errors() {
      return deepFreeze([...state.errors]);
    },
    /** Every authority-expansion attempt observed. All of them refused. */
    get authorityExpansions() {
      return deepFreeze([...state.authorityExpansions]);
    },
    /** Every raw process log this transport wrote, with its digests. */
    get rawLogs() {
      return deepFreeze([...state.rawLogs]);
    },
    /**
     * The real-run evidence record for the run this transport performed, and
     * the ONLY source a real registration can be built from. It is a record
     * about a process THIS transport spawned and observed — the exit below is
     * the one the parent saw, not one a caller typed.
     *
     * It still has to survive assertRealRunEvidence (the log must agree with
     * it, the digests must match the bytes on disk, the binary must be the
     * provider's own, the exit must be non-zero), and it returns null until a
     * run has actually been performed: there is nothing to corroborate.
     */
    /**
     * Bind the run the BOARD committed, so `start()` can correlate a governed
     * dispatch that arrives with no call arguments.
     *
     * Why this exists and what it is NOT: an ExecutionRequest deliberately
     * carries no run_id, because the request is what the operator authorised
     * and the run is what the board later assigned. `driveOutbox` sends exactly
     * that payload, so a real transport has no way to learn the run id on its
     * own. Binding it is a CORRELATION, not an authority: it names no scope, no
     * tool, no budget and no fence, and `start()` still re-checks the lease, the
     * fence, the workspace, the digests, the budget and the permit against the
     * request it was actually handed. A binding that disagrees with the request
     * is refused, and a second binding for a different run is refused too.
     */
    async bindRun(correlation) {
      return guard(async () => {
        const call = requireObject(correlation, 'correlation');
        const runId = requireString(call.runId ?? call.run_id, 'run_id');
        const taskId = requireString(call.taskId ?? call.task_id, 'task_id');
        const workspaceId = requireString(call.workspaceId ?? call.workspace_id, 'workspace_id');
        if (state.boundRun !== null && state.boundRun.run_id !== runId) {
          throw new MalformedResult(
            'RUN_CORRELATION_CONFLICT',
            `this transport is already correlated to run ${state.boundRun.run_id}; it is never re-correlated to ${runId}`,
          );
        }
        if (state.run !== null) {
          throw new MalformedResult(
            'RUN_CORRELATION_AFTER_START',
            `run ${state.run.run_id} has already started; a late correlation cannot rename it`,
          );
        }
        state.boundRun = deepFreeze({
          run_id: runId,
          task_id: taskId,
          workspace_id: workspaceId,
          lease_id: typeof (call.leaseId ?? call.lease_id) === 'string' ? (call.leaseId ?? call.lease_id) : null,
          fencing_token: Number.isInteger(call.fencingToken ?? call.fencing_token) ? (call.fencingToken ?? call.fencing_token) : null,
          request_idempotency_key: typeof (call.requestIdempotencyKey ?? call.request_idempotency_key) === 'string'
            ? (call.requestIdempotencyKey ?? call.request_idempotency_key)
            : null,
        });
        return state.boundRun;
      });
    },

    /** The correlation this transport holds, or null. Read-only, for evidence. */
    runCorrelation() {
      return state.boundRun === null ? null : deepFreeze({ ...state.boundRun });
    },

    evidenceRecord() {
      const run = state.run;
      const [entry] = state.rawLogs;
      if (run === null || entry === null) return null;
      if (state.exit === null) return null;
      const record = {
        run_id: run.run_id,
        executor: {
          version: REAL_EXECUTOR_VERSION,
          provider,
          // The NAMED path (what the host probe resolved), so the record names
          // the provider's own binary; the bytes are the resolved target's.
          binary_path: binary.named,
          binary_sha256: binary.sha256,
        },
        raw_process_log_path: entry.path,
        raw_process_log_sha256: entry.sha256,
        exit_status: state.exit.code,
        exit_observed: state.exitObserved,
      };
      // OBSERVED: this object came out of the transport's own state, and the
      // registry is what assertRealRunEvidence checks last. Nothing else in
      // the process can produce an object in it.
      // The published record states what its observation is worth, so a later
      // reader of the JSON cannot read the registry entry as more than it is.
      record.observation_trust = OBSERVATION_TRUST;
      mintObservedRunEvidence(record, MINT_CAPABILITY);
      return Object.freeze(record);
    },
    /** The last cancellation proof: TERMINATED | SURVIVORS_REMAINING | UNVERIFIED. */
    get cancelProof() {
      return state.cancelProof === null ? null : deepFreeze(state.cancelProof);
    },
    /**
     * What this transport still has PENDING. A run that settled must leave
     * nothing here, or a timer outlives the work and holds the event loop open:
     * round 2 measured a 4 s run keeping its process alive for 5m01s.
     */
    get pendingTimers() {
      return deepFreeze({
        deadline_armed: state.timer !== null,
        deadline_timeout_ms: state.run?.timeout_ms ?? null,
        rule: 'every wait in this transport is bounded and its timer destroyed in a finally, so this is the whole of what can outlive a run',
      });
    },
    /**
     * The configuration this transport was built for, the axis it sits on, and
     * BOTH argv digests. Published before the spawn, so a driver can read the
     * axis without waiting for a run to finish.
     */
    get configurationAxis() {
      return deepFreeze({
        ...configurationAxis,
        configuration: surface.configuration,
        name: surface.name,
        surface_flags: [...surface.surface_flags],
        surface_note: surface.surface_note,
        argv_digest_raw: state.argvEvidence?.raw ?? null,
        argv_digest_normalised: state.argvEvidence?.normalised ?? null,
        exclusion: configurationAxis.distinguishable
          ? null
          : `EXCLUDED_FROM_COMPARISON:${provider}:${configurationAxis.reason}`,
      });
    },
    /**
     * The parent-side view of the child process. This is a CORROBORATION
     * surface for the evidence writer, not an outcome: it reports what the
     * parent observed about the OS process, and it can never assert that the
     * run succeeded.
     */
    get processObservation() {
      return deepFreeze({
        pid: state.pid,
        pgid: state.pgid,
        process_group_signalling: POSIX_GROUP_SIGNAL ? 'POSIX_GROUP' : 'UNAVAILABLE_ON_THIS_PLATFORM',
        exit_code: state.exit?.code ?? null,
        signal: state.exit?.signal ?? null,
        cause: state.cause,
        started_at: state.startedAt,
        observed_pids: [...state.groupPids],
      });
    },
    /** Read-only view of the run state, for evidence and probes. */
    get state() {
      return deepFreeze({
        provider,
        executor_version: REAL_EXECUTOR_VERSION,
        executor_path: binary.resolved,
        executor_sha256: binary.sha256,
        adapter_kind: registration.adapter_kind,
        provenance_status: registration.real_adapter_provenance.status,
        started: state.run !== null,
        run_id: state.run?.run_id ?? null,
        task_id: state.run?.task_id ?? state.lease?.task_id ?? null,
        lease_id: state.lease?.lease_id ?? null,
        fencing_token: state.lease?.fencing_token ?? null,
        last_sequence: state.run?.last_sequence ?? 0,
        process: liveProcessState(),
        cause: state.cause,
        cancelled: state.run?.cancelled ?? false,
        outcome_unknown: state.run?.unknown ?? false,
        collected: state.result !== null,
        outcome: state.result?.outcome ?? null,
        // Which end of the configuration axis this run is, and whether the
        // provider may be compared at all.
        configuration: surface.configuration,
        configuration_axis_distinguishable: configurationAxis.distinguishable,
        checkpoints: state.checkpoints.length,
        authority_expansions: state.authorityExpansions.length,
        raw_logs: state.rawLogs.length,
        skills: bundle === null ? null : { paths: [...bundle.paths], requested_tools: [...bundle.requested_tools] },
      });
    },

    /**
     * The effective tool set for a proposed grant: the intersection of the
     * operator registration and the grant. Exposed so the start() path and any
     * evidence recorder derive the SAME intersection rather than two copies of
     * the rule.
     */
    effectiveToolIds(allowedTools) {
      return effectiveToolIds(new Set(requireArray(allowedTools, 'allowed_tools')));
    },
  };

  assertAdapterInterface(transport);
  return transport;

  // --- internals declared after the return, hoisted like any closure -------

  function buildLeaseAck(operation, lease, runId, reason) {
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
      // A real lease acknowledgement is NOT a replay: this transport took the
      // lease, it did not reconstruct one from a record.
      replayed: false,
      reason: reason ?? null,
      acknowledged_at: timestampOf(injectedClock),
    });
  }

  function liveProcessState() {
    if (state.child === null) return 'NOT_STARTED';
    if (state.exit !== null) return 'EXITED';
    return 'RUNNING';
  }

  async function awaitChildExit(run) {
    if (state.child === null) return null;
    if (state.exit !== null) return state.exit;
    const raced = await boundedRace(state.exitPromise, run.timeout_ms);
    if (!raced.timedOut) return state.exit;
    // The real timer may already have fired; if it has not, the wait itself is
    // what exhausted the granted budget.
    if (state.cause === null) state.cause = 'timeout';
    await terminateGroup('timeout');
    const settled = await boundedRace(state.exitPromise, observerSettleMs);
    if (settled.timedOut) {
      // The process exists, was signalled, and produced no observable exit.
      // The external effect is unknown and nothing here may call it a stop.
      state.exit = { code: null, signal: null, cause: 'UNOBSERVED_EXIT' };
      state.exitObserved = false;
      settleExit();
    }
    return state.exit;
  }

  /**
   * The three-way termination proof, as it travels on an event payload and in
   * the raw log. `survivors: 0` never appears without a TERMINATED, and both
   * readings of a reap race travel with it so the observer's first answer is
   * never overwritten by the accounting one.
   */
  function terminationBlock(proof) {
    return {
      verdict: proof.verdict,
      survivors: proof.survivors,
      pids_before_kill: [...proof.pids_before_kill],
      pids_after_kill: [...proof.pids_after_kill],
      remaining_process_ids: [...proof.remaining_process_ids],
      signals: [...proof.signals],
      observer: typeof procObserver.id === 'string' ? procObserver.id : null,
      reaped_before_accounting: proof.reaped_before_accounting ?? null,
      accounting: proof.accounting ?? null,
      observer_read_staleness: proof.observer_read_staleness ?? null,
      readings_disagree: proof.readings_disagree ?? null,
      pre_accounting_reading: proof.pre_accounting_reading ?? null,
      accounting_reading: proof.accounting_reading ?? null,
      caveat: proof.caveat ?? null,
    };
  }

  /**
   * The classification table. Deliberately NOT an exit-code mapping: measured
   * on this host, codex exits 1 on a model error and pi exits 0 on the same
   * class of failure, so the executor's own records decide.
   */
  function classify(run) {
    const exit = state.exit;
    const read = ensureRawLog(run);
    const base = {
      raw_process_log: read,
      executor_session_id: read.usage.executor_session_id,
      usage: read.usage,
      cancel_proof: state.cancelProof,
    };
    // THE TIMEOUT KILL IS A KILL, SO IT CARRIES THE SAME PROOF (round 3, after
    // round 2 measured `TIMEOUT` with `cancelProof === null`). A deadline that
    // this transport enforced killed a process group, and an unaccounted kill is
    // exactly the false zero the evidence rules exist to prevent. So a timeout
    // whose group kill cannot be proved TERMINATED is not a definite TIMEOUT: it
    // is the unknown it is, with the proof beside it.
    const killedForDeadline = state.cause === 'timeout';
    const termination = state.cancelProof === null ? null : terminationBlock(state.cancelProof);
    if (killedForDeadline && (state.cancelProof === null || state.cancelProof.verdict !== 'TERMINATED')) {
      return {
        event_type: 'UNKNOWN',
        outcome: 'RECONCILIATION_REQUIRED',
        payload: {
          ...base,
          reason: state.cancelProof === null
            ? 'TERMINATION_PROOF_MISSING: the granted deadline elapsed and the group kill published no proof at all'
            : `TERMINATION_PROOF_UNPROVEN:${state.cancelProof.verdict}`,
          termination,
        },
      };
    }

    if (state.cause === 'cancel') {
      return { event_type: 'CANCELLED', outcome: 'CANCELLED', payload: { ...base, reason: 'the board cancelled the run', termination } };
    }
    if (read.provider_error !== null) {
      // A provider error inside the executor's own output. PROVIDER_FAILURE,
      // never BUDGET_EXCEEDED (that code is the board's own numeric grant) and
      // never a success.
      return {
        event_type: 'FAILED',
        outcome: 'FAILED',
        payload: { ...base, error_code: 'PROVIDER_FAILURE', credit_limited: read.provider_error.credit_limited },
      };
    }
    const elapsed = injectedClock.now().getTime() - state.startedAtMs;
    // OBSERVATION BEFORE CLASSIFICATION. A signalled process whose exit the
    // parent never saw leaves the external effect unknown, whatever the timer
    // said: the timeout arm used to sit above this one, so exactly the state
    // this module's own comment calls unknowable was reported as a definite
    // TIMEOUT and RECONCILIATION_REQUIRED was unreachable on that path. A
    // signal this transport DID send and an exit the parent DID observe is a
    // known stop, and that is the case the timeout arm is for.
    if (exit === null || state.exitObserved !== true) {
      // Signalled, and no exit was ever observed. The external effect is
      // unknown; it is non-retryable and is never dressed up as a stop.
      return { event_type: 'UNKNOWN', outcome: 'RECONCILIATION_REQUIRED', payload: { ...base, reason: 'NO_OBSERVED_EXIT', termination } };
    }
    if (killedForDeadline || elapsed >= run.timeout_ms) {
      // The proof travels with the terminal event. `termination: null` on this
      // arm means NO KILL WAS NEEDED: the work finished and the injected clock
      // had already passed the granted deadline, so there is nothing to prove.
      return {
        event_type: 'TIMED_OUT',
        outcome: 'TIMEOUT',
        payload: {
          ...base,
          timeout_ms: run.timeout_ms,
          termination,
          termination_note: termination === null
            ? 'NO_KILL_WAS_NEEDED: the executor finished and the injected clock had passed the granted deadline'
            : 'the granted deadline elapsed and this transport killed the process group; the proof is the same three-way proof an explicit cancel carries',
        },
      };
    }
    if (exit.signal !== null) {
      // Killed by a signal this transport did not send. UNKNOWN_OUTCOME.
      return {
        event_type: 'UNKNOWN',
        outcome: 'RECONCILIATION_REQUIRED',
        payload: { ...base, reason: `UNATTRIBUTED_SIGNAL:${exit.signal}`, termination },
      };
    }
    if (state.readOutcome.exit_code !== 0) {
      return { event_type: 'FAILED', outcome: 'FAILED', payload: { ...base, error_code: 'PROVIDER_FAILURE' } };
    }
    if (state.readOutcome.assistant_text === null) {
      // Exit 0 and nothing to show for it. Never a success.
      return { event_type: 'FAILED', outcome: 'FAILED', payload: { ...base, error_code: 'EMPTY_RESPONSE' } };
    }
    return { event_type: 'COMPLETED', outcome: 'SUCCEEDED', payload: base };
  }

  // The result of a run whose terminal event was already recorded. It reads the
  // recorded event; it never re-classifies and never invents a second verdict.
  function buildResultFromTerminal(run, event) {
    const code = event.event_type === 'COMPLETED' ? null
      : (typeof event.payload?.error_code === 'string' && ERROR_CODES.includes(event.payload.error_code)
        ? event.payload.error_code
        : (event.event_type === 'CANCELLED' ? 'CANCELLED'
          : (event.event_type === 'TIMED_OUT' ? 'TIMEOUT' : 'RECONCILIATION_REQUIRED')));
    const outcome = OUTCOME_BY_EVENT_TYPE[event.event_type];
    return assembleResult(run, outcome, code, state.readOutcome?.usage ?? null);
  }

  function buildResult(run, outcome) {
    // A terminal outcome without an explicit error_code still names one: the
    // recorded outcome is not a verdict with no failure attached.
    const fallback = {
      CANCELLED: 'CANCELLED',
      TIMEOUT: 'TIMEOUT',
      RECONCILIATION_REQUIRED: 'RECONCILIATION_REQUIRED',
      FAILED: 'PROVIDER_FAILURE',
    }[outcome.outcome] ?? null;
    return assembleResult(
      run,
      outcome.outcome,
      outcome.payload.error_code ?? fallback,
      outcome.payload.usage,
    );
  }

  function assembleResult(run, outcome, code, usage) {
    let error = null;
    if (outcome !== 'SUCCEEDED' && code !== null && ERROR_CODES.includes(code)) {
      const ErrorClass = errorClassForCode(code);
      error = deepFreeze(assertBoardContract('board-error', new ErrorClass(
        code,
        `recorded terminal outcome ${outcome}`,
        'derived from the observed executor process state; never a semantic verdict',
      ).toDocument(timestampOf(injectedClock))));
    }
    const measured = usage ?? {
      input_tokens: null,
      output_tokens: null,
      reasoning_tokens: null,
      cache_read_tokens: null,
      cache_write_tokens: null,
      proxy_tokens: null,
      cost_usd_micros: null,
      cost_basis: 'NOT_REPORTED_BY_EXECUTOR',
      model_id: null,
      tool_calls: 0,
      executor_session_id: null,
    };
    return deepFreeze(assertBoardContract('execution-result', {
      contract_version: EXECUTION_CONTRACT_VERSION,
      run_id: run.run_id,
      task_id: run.task_id,
      workspace_id: run.workspace_id,
      lease_id: run.lease_id,
      fencing_token: run.fencing_token,
      sequence: run.last_sequence,
      outcome,
      checkpoints: state.checkpoints.map((checkpoint) => ({ ...checkpoint })),
      artifact_hashes: state.artifacts.map((artifact) => ({ ...artifact })),
      measurements: {
        // The board's own injected clock, so the number is reproducible; the
        // wall clock of the child is a measurement recorded in the raw log and
        // is never used as authority.
        duration_ms: Math.max(0, injectedClock.now().getTime() - state.startedAtMs),
        // The executor's OWN reported cost, in the unit the executor reported
        // it in — USD, per the raw log's cost_basis. The grant currency is the
        // currency of the GRANT, and a USD figure labelled EUR/GBP/RUB is a
        // wrong number by a currency factor; this schema has no field for both
        // and a rate is never invented here. The comparison against a foreign
        // grant is a caller's, and it can now see which unit this is.
        spend: measured.cost_usd_micros === null ? 0 : measured.cost_usd_micros / 1e6,
        currency: 'USD',
        model_id: measured.model_id,
        tool_calls: Number.isInteger(measured.tool_calls) ? measured.tool_calls : 0,
      },
      error,
      reconciliation_required: outcome === 'RECONCILIATION_REQUIRED',
      completed_at: timestampOf(injectedClock),
    }));
  }
}



// --- the isolation truth, recorded rather than claimed ---------------------

/**
 * What the registered sandbox profile DECLARES, and what this transport
 * actually enforced while the child ran. The two are different documents and
 * conflating them is how a contract-valid profile id ends up describing an
 * isolation that was not in force. This transport spawns the child directly on
 * the host (no podman, no gVisor), so `isolation_applied` is false, always,
 * and the declared controls are recorded as DECLARED — not as applied.
 */
function describeIsolation({ profileId, workspaceRef, cwd = null, sandboxDecision = null }) {
  const profile = SANDBOX_PROFILES.find((entry) => entry.profile_id === profileId) ?? null;
  const roots = profile === null ? [] : [...(profile.filesystem?.roots ?? [])];
  const insideDeclaredRoot = cwd === null || roots.length === 0
    ? null
    : roots.some((root) => cwd === root || cwd.startsWith(root.endsWith(path.sep) ? root : root + path.sep));
  return Object.freeze({
    requested_profile_id: profileId,
    profile_tier: classifySandboxProfile(profileId),
    // The permit, BY VALUE, and the digest of the record that measured the
    // ABSENCE of OS controls. Both travel with the run so a later reader can
    // re-judge the same document this run started under, and so nobody has to
    // take the profile id on trust.
    sandbox_decision: sandboxDecision === null ? null : {
      tier: sandboxDecision.tier,
      profile_id: sandboxDecision.profile_id,
      authorization: sandboxDecision.authorization,
    },
    os_controls_absence_evidence: {
      path: HOST_UNISOLATED_EVIDENCE_PATH,
      sha256: HOST_UNISOLATED_EVIDENCE_DIGEST,
      binds: profile?.os_controls_evidence ?? null,
      note: 'this digest is the profile\'s own os_controls_evidence: the content address of the record that '
        + 'MEASURED that no OS isolation control is available to a model-calling executor on this host. It is '
        + 'quoted here so the run record names the measurement, not just the tier.',
    },
    // The load-bearing field. It is false, and it is false on every run.
    isolation_applied: false,
    reason: 'THIS_TRANSPORT_SPAWNS_THE_CHILD_DIRECTLY_ON_THE_HOST',
    enforcement: 'NONE_BY_THIS_TRANSPORT',
    declared_network_policy: profile === null ? null : profile.network.policy,
    declared_filesystem_roots: Object.freeze(roots),
    declared_environment_allowlist: Object.freeze([...(profile?.environment?.allowlist ?? [])]),
    // The child really is handed PATH/HOME/LANG, which an empty allowlist
    // forbids. Recording the two side by side is the point: the profile's
    // allowlist is NOT what the child got.
    environment_keys_handed_to_child: Object.freeze(['PATH', 'HOME', 'LANG']),
    requested_read_only_paths: Object.freeze([...(workspaceRef?.read_only_paths ?? [])]),
    read_only_paths_enforced: false,
    cwd: cwd,
    cwd_inside_declared_roots: insideDeclaredRoot,
    os_controls_evidence: profile === null ? null : (profile.os_controls_evidence ?? null),
    limit: 'a real run on this host is HOST_UNISOLATED; the profile id is the request-side declaration only, '
      + 'and no A-MVP isolation clause may be scored against a run whose own evidence says isolation_applied:false',
  });
}

function normalizeToolBindings(raw) {
  const object = raw === undefined || raw === null ? {} : requireObject(raw, 'toolBindings');
  const out = {};
  for (const [key, value] of Object.entries(object)) {
    if (!TOOL_ID_RE.test(key)) {
      throw new NeedsInput(`TOOL_BINDING_KEY:${key}`, 'a tool binding key must match the frozen tool id pattern');
    }
    if (typeof value !== 'string' || !NATIVE_TOOL_RE.test(value)) {
      throw new NeedsInput(`TOOL_BINDING_VALUE:${key}`, 'an executor-native tool name has its own narrow pattern');
    }
    out[key] = value;
  }
  return Object.freeze(out);
}

function normalizeSkillBundle(raw, skillRoots, realpath) {
  if (raw === undefined || raw === null) return null;
  const object = requireObject(raw, 'skillBundle');
  const paths = requireArray(object.paths ?? [], 'skillBundle.paths');
  const requested = requireArray(object.requested_tools ?? [], 'skillBundle.requested_tools');
  for (const tool of requested) {
    if (!TOOL_ID_RE.test(tool)) {
      throw new NeedsInput(`SKILL_REQUESTED_TOOL_MALFORMED:${String(tool)}`, 'expected the frozen tool id pattern');
    }
  }
  const roots = requireArray(skillRoots ?? [], 'skillRoots').map((root) => requireString(root, 'skillRoots[]'));
  if (roots.length === 0) {
    throw new NeedsInput('SKILL_ROOTS_REQUIRED', 'a skill bundle may only be loaded from a configured root set');
  }
  const resolvedPaths = paths.map((entry) => {
    const value = requireString(entry, 'skillBundle.paths[]');
    if (!path.isAbsolute(value)) {
      throw new NeedsInput('SKILL_PATH_NOT_ABSOLUTE', 'a skill path must be absolute so it cannot depend on the child cwd');
    }
    if (!fs.existsSync(value)) {
      throw new NeedsInput('SKILL_PATH_MISSING', `the skill path does not exist: ${redact(value).slice(0, 200)}`);
    }
    for (const root of roots) assertDescendant(value, root, 'SKILL_PATH', realpath);
    return path.resolve(value);
  });
  return Object.freeze({
    paths: Object.freeze([...resolvedPaths]),
    requested_tools: Object.freeze([...requested]),
  });
}

function resolveExecutorBinary(executorPath) {
  const value = requireString(executorPath, 'executorPath');
  if (!path.isAbsolute(value)) {
    throw new NeedsInput(
      'EXECUTOR_PATH_NOT_ABSOLUTE',
      'the executor is passed as a resolved absolute path (the host probe resolves it), never looked up on PATH here',
    );
  }
  let resolved;
  try {
    resolved = fs.realpathSync(value);
  } catch (error) {
    throw new AgentUnavailable(
      'EXECUTOR_NOT_RESOLVABLE',
      `the executor binary does not resolve: ${redact(String(error?.message ?? error)).slice(0, 200)}`,
    );
  }
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch {
    throw new AgentUnavailable('EXECUTOR_NOT_PRESENT', 'the executor binary is not present on this host');
  }
  if (!stat.isFile()) {
    throw new AgentUnavailable('EXECUTOR_NOT_A_FILE', 'the executor path is not a regular file');
  }
  try {
    fs.accessSync(resolved, fs.constants.X_OK);
  } catch {
    throw new AgentUnavailable('EXECUTOR_NOT_EXECUTABLE', 'the executor binary is not executable');
  }
  // `named` is the path the host probe resolved, `resolved` is what the bytes
  // actually live at. Both are recorded: a record that names the launcher is
  // adjudicated against the target's bytes, and the launcher name is what ties
  // the record to a provider rather than to any executable at all.
  return Object.freeze({ named: value, resolved, sha256: wireDigest(fs.readFileSync(resolved)) });
}

function safeReadText(absolutePath) {
  try {
    return fs.readFileSync(absolutePath, 'utf8');
  } catch {
    return null;
  }
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