#!/usr/bin/env node
// S2-007 AGENT BOARD ACCEPTANCE RUN (issue #7, module spec §1–§5).
//
// WHAT THIS FILE IS
// -----------------
// The non-database, deterministic, OFFLINE acceptance harness of the live
// Agent Board. It is a SCRIPT, not a test: `npm run s2-007:run` drives a whole
// realistic board scenario through the PRODUCTION-FACING entry point
// (`commands.execute` from src/lib/agentboard/commands.mjs — the same function
// Web, the HTTP API, the CLI, the scheduler and the tests use), records what
// happened, and writes three evidence documents:
//
//   evidence/s2-007-run-a.json        run A, its own identity, full trace
//   evidence/s2-007-run-b.json        run B, a DIFFERENT identity, same input
//   evidence/s2-007-comparison.json   the A/B comparison + expected-value table
//
// WHY IT IS BUILT THIS WAY
// ------------------------
//   * ONE BOUNDARY. Every mutation and every read in the scenario goes through
//     `commands.execute`. Nothing calls a guard, a handler or a store write
//     directly. The store is touched for exactly one honest reason: to OBSERVE
//     a committed run row so the next boundary call can be built. Observation
//     never substitutes for the boundary.
//   * FIXED CLOCK, FIXED IDS. Every instant is injected (`now` plus a store
//     clock driven by one shared counter) and every identifier is minted by one
//     injected, prefixed, monotonic id factory. There is no `Date.now()`, no
//     `Math.random()` and no bare `new Date()` anywhere below, so the two runs
//     and every re-run of this file are byte-reproducible.
//   * TWO RUNS, AND A COMPARISON THAT CAN FAIL. A/B carry DIFFERENT run
//     identities (run id, executor id, store seed, id-factory offset — the
//     generated lease/run/transition ids therefore genuinely differ) over the
//     SAME canonical input. Their identity-free projections must be identical
//     AND must independently match a preregistered EXPECTED-VALUE TABLE. "A
//     equals B" alone would pass two identically wrong runs; the table is what
//     makes the comparison falsifiable, and it is derived from the frozen
//     contract (the transition table in constants.mjs, the closed error set,
//     the required final states) rather than from whatever the code happens to
//     do today.
//   * FAIL CLOSED. A non-zero hard-gate counter, an unexpected refusal, an
//     unexpected acceptance, a missing guard, a missing final state or a
//     non-matching expectation is a violation, and the process exits non-zero.
//     Nothing in this file can turn a failure into a green record.
//
// THE HARNESS-SIDE TRANSPORT SHIM (a documented, local adaptation)
// ---------------------------------------------------------------
// `scheduler.driveOutbox` calls `transport.start(payload)`, while the
// `veritas.adapter/1.0.0` test transport's `start()` takes
// `{ request, run_id }`. The shim below is the smallest local bridge between
// the two: it exposes `dispatch(payload)` (the method `driveOutbox` prefers),
// forwards the payload as the request, supplies the run id the harness read
// back from the committed run row, and COUNTS how many times a payload
// actually crossed the boundary. That count is this run's own
// `duplicateExternalEffects` counter, and it is why "a timed-out dispatch is
// never re-sent" is a measurement here and not a claim. The shim is a fixture:
// it is never a real adapter and it never upgrades the provenance status.
//
// HONEST STATUS (issue #7 §8, module spec §0.8, §0.10)
// ----------------------------------------------------
//   * `realAdapterStatus` is ALWAYS `NOT_RUN_REAL_ADAPTER`. No genuinely
//     installed, genuinely distinct executor exists on this host, the scripted
//     transport is the only boundary model, and no part of this harness may
//     raise that value. A registration that CLAIMS `REAL_ADAPTER_AVAILABLE` is
//     attempted on purpose and is recorded as REFUSED.
//   * Every latency, cost and "quality" number below is an ENGINEERING PROXY
//     computed from the board's own contract documents and from the injected
//     clock. None of them is an empirical measurement of human work, model
//     quality, real cost or real latency, and each metric record says so in
//     its own `measurementKind`/`empirical` fields.
//   * `assuranceStatus` is `NOT_MEASURED` and `aMvpStatus` is `NOT_CLAIMED`.
//     No A-MVP PASS appears anywhere in this file or in the records it writes.
//
//   node scripts/s2-007-run.mjs                 # run A, run B, comparison
//   node scripts/s2-007-run.mjs --evidence-dir <dir>
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { execute } from '../src/lib/agentboard/commands.mjs';
import { InMemoryAgentBoardStore } from '../src/lib/agentboard/store.mjs';
import { createTestTransport, probeRealAdapters } from '../src/lib/agentboard/adapters.mjs';
import { isBoardError } from '../src/lib/agentboard/errors.mjs';
import {
  BOARD_CAPABILITIES,
  BOARD_STATES,
  ERROR_CODES,
  ID_PREFIXES,
  NON_RETRYABLE_CODES,
  TRANSITIONS,
} from '../src/lib/agentboard/constants.mjs';
import { runAllProbes, HARD_GATE_COUNTERS } from '../src/lib/agentboard/probes.mjs';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let EVIDENCE_DIR = path.join(ROOT, 'evidence');

const HARNESS_VERSION = 's2-007-run-v1';
const SPEC_REVISION = 's2-007-module-spec-frozen@d7ea79f';

// --- the frozen instant -------------------------------------------------------
// One base instant, advanced by STEP_MS on every boundary call. The clock is the
// ONLY source of time in this harness: the store reads the same counter, so a
// task's committed timestamps are a pure function of the call sequence.
const CLOCK_BASE = '2026-09-25T12:00:00.000Z';
const STEP_MS = 1000;
const CLOCK_DAY = '2026-09-25';
const FIXTURE_INSTANT = CLOCK_BASE;

// --- the world ----------------------------------------------------------------
const ALPHA = 'ws-s2007-alpha';
const BETA = 'ws-s2007-beta';
const ROOTS = Object.freeze({
  [ALPHA]: ['/srv/workspaces/veritas-s2007'],
  [BETA]: ['/srv/workspaces/veritas-s2007-beta'],
});
// The only two isolation profiles with measured S2-002 controls behind them.
// Every other registered profile is BLOCKED_SANDBOX on this host.
const PROVEN_PROFILE = 'sbx-podman-local-restricted-v1';
const BLOCKED_PROFILE = 'sbx-no-exec-default';

const P = Object.freeze({
  owner: 'prn-s2007-owner',
  reviewer: 'prn-s2007-reviewer',
  scheduler: 'prn-s2007-scheduler',
  producer: 'prn-s2007-producer',
  gate: 'prn-s2007-gate',
  verifier: 'prn-s2007-verifier',
  outsider: 'prn-s2007-outsider',
  betaOnly: 'prn-s2007-beta-only',
});
// Real, different grants. A capability that is absent here is refused by the
// boundary before any payload is read, which is the point of keeping them apart.
const CAP = Object.freeze({
  owner: [
    'board.task.read', 'board.task.create', 'board.task.transition', 'board.task.claim', 'board.task.release',
    'board.execution.start', 'board.execution.cancel', 'board.result.collect', 'board.evidence.submit',
    'board.review.challenge', 'board.adapter.register', 'board.budget.grant', 'board.reconciliation.decide',
  ],
  reviewer: ['board.task.read', 'board.task.transition', 'board.review.approve', 'board.review.challenge'],
  scheduler: ['board.task.read', 'board.task.claim', 'board.task.release', 'board.execution.start', 'board.execution.cancel', 'board.result.collect'],
  producer: ['board.task.read', 'board.task.transition', 'board.execution.start', 'board.result.collect', 'board.evidence.submit'],
  // The adversarial producer: the server resolved board.review.approve FOR IT.
  // Nothing but the self-approval/actor-kind rule may still refuse it, and that
  // is what makes the DONE refusal a real independence guarantee.
  producerWithApprove: ['board.task.read', 'board.task.transition', 'board.execution.start', 'board.result.collect', 'board.evidence.submit', 'board.review.approve'],
  // The uncalibrated semantic verifier, twice: once honestly narrow (no approve
  // capability) and once with the capability resolved for it and the actor kind
  // `system`. The first is refused by the GRANT, the second only by the RULE.
  verifierNarrow: ['board.task.read', 'board.task.transition'],
  verifierWithApprove: ['board.task.read', 'board.task.transition', 'board.review.approve'],
  gate: ['board.task.read', 'board.task.transition', 'board.reconciliation.decide', 'board.review.approve'],
  betaOnly: ['board.task.read', 'board.task.transition', 'board.review.approve'],
});
const ACL_ALPHA = Object.freeze([P.owner, P.reviewer, P.scheduler, P.producer, P.gate, P.verifier]);
const ACL_BETA = Object.freeze([P.owner, P.scheduler, P.producer, P.gate]);

const A = Object.freeze({
  collector: 'adr-s2007-a-collector',
  bulk: 'adr-s2007-b-bulk',
  timeout: 'adr-s2007-c-timeout',
  blocked: 'adr-s2007-x-blocked',
  tick: 'adr-s2007-d-tick',
  realClaim: 'adr-s2007-r-real-claim',
});
const T = Object.freeze({
  openDep: 'abt-s2007-01-open-dep',
  ready: 'abt-s2007-02-ready',
  done: 'abt-s2007-03-done',
  challenge: 'abt-s2007-04-challenge',
  blocked: 'abt-s2007-05-blocked',
  unblock: 'abt-s2007-06-unblock',
  collectFailed: 'abt-s2007-07-collect-failed',
  requeue: 'abt-s2007-08-requeue',
  release: 'abt-s2007-09-release',
  timeout: 'abt-s2007-10-timeout',
  cancel: 'abt-s2007-11-cancel',
  tick: 'abt-s2007-12-tick',
  guardFail: 'abt-s2007-13-guard-fail',
  claimed: 'abt-s2007-14-claimed',
  blockedSandbox: 'abt-s2007-15-blocked-sandbox',
  running: 'abt-s2007-16-running',
});
const ALL_TASKS = Object.freeze(Object.values(T));

const d = (char) => `sha256:${char.repeat(64)}`;
const DIGEST_CHAR = { brief: 'b', policy: 'c', manifest: 'e', sandbox: 'a', history: 'f' };

// ===========================================================================
// The preregistered EXPECTED-VALUE TABLE
// ===========================================================================
// Declared BEFORE the run and derived from the frozen contract, never from the
// implementation's current behaviour. `REFUSE` entries name the closed error
// codes the contract admits for that decision, so a weaker refusal cannot
// satisfy the table. The run verifies, for BOTH runs, that
//   (a) every expected step happened with the expected outcome, and
//   (b) every observed step was expected (an undeclared acceptance is a
//       finding, not a bonus).
const EXPECTED = Object.freeze([
  // --- discovery and honesty ------------------------------------------------
  { step: 'discovery.capabilities', command: 'capabilities', outcome: 'ACCEPT' },
  { step: 'discovery.real-claim-registration', command: 'adapters.register', outcome: 'REFUSE', codes: ['NOT_RUN_REAL_ADAPTER', 'BLOCKED_POLICY'] },
  { step: 'setup.register-collector', command: 'adapters.register', outcome: 'ACCEPT' },
  { step: 'setup.register-bulk', command: 'adapters.register', outcome: 'ACCEPT' },
  { step: 'setup.register-timeout', command: 'adapters.register', outcome: 'ACCEPT' },
  { step: 'setup.register-blocked-sandbox-adapter', command: 'adapters.register', outcome: 'ACCEPT' },
  { step: 'setup.register-tick', command: 'adapters.register', outcome: 'ACCEPT' },
  { step: 'setup.health-degraded', command: 'adapters.health', outcome: 'ACCEPT' },
  { step: 'setup.health-restored', command: 'adapters.health', outcome: 'ACCEPT' },
  // --- task creation --------------------------------------------------------
  ...ALL_TASKS.map((taskId) => ({ step: `create.${taskId}`, command: 'tasks.create', outcome: 'ACCEPT' })),
  // --- BACKLOG -> READY, closed and open dependency ------------------------
  { step: 'deps.open-backlog-to-ready', command: 'tasks.transition', outcome: 'REFUSE', codes: ['TRANSITION_NOT_ALLOWED', 'BLOCKED_POLICY'] },
  { step: 'ready.backlog-to-ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'ready.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'ready.cross-workspace-read', command: 'tasks.get', outcome: 'REFUSE', codes: ['ACL_DENIED', 'NEEDS_INPUT'] },
  { step: 'sandbox.blocked-profile-ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'sandbox.blocked-profile-grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'sandbox.blocked-profile-dispatch', command: 'execution.start', outcome: 'REFUSE', codes: ['BLOCKED_SANDBOX'] },
  { step: 'closed-dep.backlog-to-ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  // --- the scheduler tick on the second tenant ------------------------------
  { step: 'tick.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'tick.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'tick.plan', command: 'dispatch.plan', outcome: 'ACCEPT' },
  { step: 'tick.execute', command: 'dispatch.tick', outcome: 'ACCEPT' },
  { step: 'tick.dispatch', command: 'outbox.dispatch', outcome: 'ACCEPT' },
  { step: 'tick.collect', command: 'execution.collect_result', outcome: 'ACCEPT' },
  // --- the full lifecycle, approved by a human ------------------------------
  { step: 'done.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'done.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'done.start', command: 'execution.start', outcome: 'ACCEPT' },
  { step: 'done.dispatch', command: 'outbox.dispatch', outcome: 'ACCEPT' },
  { step: 'done.event', command: 'execution.event', outcome: 'ACCEPT' },
  { step: 'done.collect', command: 'execution.collect_result', outcome: 'ACCEPT' },
  { step: 'done.approve-by-producer', command: 'tasks.transition', outcome: 'REFUSE', codes: ['BLOCKED_POLICY', 'CAPABILITY_MISMATCH', 'ACL_DENIED'] },
  { step: 'done.approve-by-human', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'done.settle', command: 'budget.settle', outcome: 'ACCEPT' },
  // --- an unapproved result and a challenged one -----------------------------
  { step: 'review.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'review.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'review.start', command: 'execution.start', outcome: 'ACCEPT' },
  { step: 'review.dispatch', command: 'outbox.dispatch', outcome: 'ACCEPT' },
  { step: 'review.collect', command: 'execution.collect_result', outcome: 'ACCEPT' },
  { step: 'review.approve-by-uncalibrated-verifier-without-capability', command: 'tasks.transition', outcome: 'REFUSE', codes: ['AUTH_REQUIRED'] },
  { step: 'review.approve-by-uncalibrated-verifier-with-capability', command: 'tasks.transition', outcome: 'REFUSE', codes: ['BLOCKED_POLICY'] },
  { step: 'review.challenge', command: 'tasks.transition', outcome: 'ACCEPT' },
  // --- block / unblock / a collected failure --------------------------------
  { step: 'blocked.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'blocked.block', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'unblock.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'unblock.block', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'unblock.unblock', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'collect-failed.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'collect-failed.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'collect-failed.start', command: 'execution.start', outcome: 'ACCEPT' },
  { step: 'collect-failed.dispatch', command: 'outbox.dispatch', outcome: 'ACCEPT' },
  { step: 'collect-failed.collect', command: 'execution.collect_result', outcome: 'ACCEPT' },
  // --- claim / renew / run / the requeue the contract requires --------------
  { step: 'requeue.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'requeue.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'requeue.claim', command: 'tasks.claim', outcome: 'ACCEPT' },
  { step: 'requeue.renew', command: 'tasks.lease.renew', outcome: 'ACCEPT' },
  { step: 'requeue.to-running', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'requeue.start', command: 'execution.start', outcome: 'ACCEPT' },
  { step: 'requeue.dispatch', command: 'outbox.dispatch', outcome: 'ACCEPT' },
  { step: 'requeue.reconcile', command: 'reconciliation.record', outcome: 'ACCEPT' },
  { step: 'requeue.requeue-with-live-lease', command: 'tasks.transition', outcome: 'REFUSE', codes: ['TRANSITION_NOT_ALLOWED', 'STALE_FENCE'] },
  { step: 'requeue.revoke', command: 'tasks.lease.revoke', outcome: 'ACCEPT' },
  { step: 'requeue.requeue-without-lease', command: 'tasks.transition', outcome: 'REFUSE', codes: ['STALE_FENCE'] },
  { step: 'requeue.cancel', command: 'execution.cancel', outcome: 'ACCEPT' },
  // --- release --------------------------------------------------------------
  { step: 'release.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'release.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'release.claim', command: 'tasks.claim', outcome: 'ACCEPT' },
  { step: 'release.start', command: 'execution.start', outcome: 'ACCEPT' },
  { step: 'release.dispatch', command: 'outbox.dispatch', outcome: 'ACCEPT' },
  { step: 'release.reconcile', command: 'reconciliation.record', outcome: 'ACCEPT' },
  { step: 'release.release', command: 'tasks.lease.release', outcome: 'ACCEPT' },
  // --- timeout: never a blind retry -----------------------------------------
  { step: 'timeout.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'timeout.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'timeout.claim', command: 'tasks.claim', outcome: 'ACCEPT' },
  { step: 'timeout.to-running', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'timeout.start', command: 'execution.start', outcome: 'ACCEPT' },
  { step: 'timeout.dispatch-timed-out', command: 'outbox.dispatch', outcome: 'REFUSE', codes: ['RECONCILIATION_REQUIRED', 'UNKNOWN_OUTCOME'] },
  { step: 'timeout.dispatch-not-retried', command: 'outbox.dispatch', outcome: 'ACCEPT' },
  { step: 'timeout.recover', command: 'outbox.recover', outcome: 'ACCEPT' },
  { step: 'timeout.reconcile', command: 'reconciliation.record', outcome: 'ACCEPT' },
  { step: 'timeout.cancel', command: 'tasks.cancel', outcome: 'ACCEPT' },
  // --- cancel from READY ----------------------------------------------------
  { step: 'cancel.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'cancel.cancel', command: 'tasks.cancel', outcome: 'ACCEPT' },
  // --- the fail guard on a withdrawn run ------------------------------------
  { step: 'guard-fail.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'guard-fail.claim', command: 'tasks.claim', outcome: 'ACCEPT' },
  { step: 'guard-fail.to-running', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'guard-fail.revoke', command: 'tasks.lease.revoke', outcome: 'ACCEPT' },
  { step: 'guard-fail.fail', command: 'tasks.transition', outcome: 'ACCEPT' },
  // --- a live right at the end of the board ---------------------------------
  { step: 'claimed.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'claimed.claim', command: 'tasks.claim', outcome: 'ACCEPT' },
  // A task left RUNNING at the end of the board, in the SECOND tenant so the
  // bounded profile's one-active-lease rule is not bent: the alpha board ends
  // with one CLAIMED right, the beta board with one RUNNING run in flight.
  { step: 'running.ready', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'running.grant', command: 'budget.grant', outcome: 'ACCEPT' },
  { step: 'running.claim', command: 'tasks.claim', outcome: 'ACCEPT' },
  { step: 'running.to-running', command: 'tasks.transition', outcome: 'ACCEPT' },
  { step: 'running.start', command: 'execution.start', outcome: 'ACCEPT' },
  { step: 'running.dispatch', command: 'outbox.dispatch', outcome: 'ACCEPT' },
  // --- tenancy, authority, sandbox and the closing reads --------------------
  { step: 'tenancy.cross-workspace-read', command: 'tasks.get', outcome: 'REFUSE', codes: ['ACL_DENIED', 'NEEDS_INPUT'] },
  { step: 'tenancy.outsider-read', command: 'tasks.get', outcome: 'REFUSE', codes: ['ACL_DENIED', 'NEEDS_INPUT'] },
  { step: 'tenancy.forged-authority-argument', command: 'tasks.transition', outcome: 'REFUSE', codes: ['AUTH_REQUIRED', 'BLOCKED_POLICY'] },
  { step: 'read.tasks-list', command: 'tasks.list', outcome: 'ACCEPT' },
  { step: 'read.audit-list', command: 'audit.list', outcome: 'ACCEPT' },
  { step: 'read.outbox-list', command: 'outbox.list', outcome: 'ACCEPT' },
  { step: 'read.adapters-list', command: 'adapters.list', outcome: 'ACCEPT' },
  { step: 'read.capabilities-final', command: 'capabilities', outcome: 'ACCEPT' },
]);

// The canonical final state of every task, declared from the transition table
// (issue "Agent Board MVP contract") rather than from the run.
const EXPECTED_FINAL_STATES = Object.freeze({
  [T.openDep]: 'BACKLOG',
  [T.ready]: 'READY',
  [T.done]: 'DONE',
  [T.challenge]: 'BLOCKED',
  [T.blocked]: 'BLOCKED',
  [T.unblock]: 'READY',
  [T.collectFailed]: 'FAILED',
  [T.requeue]: 'CANCELLED',
  [T.release]: 'READY',
  [T.timeout]: 'CANCELLED',
  [T.cancel]: 'CANCELLED',
  [T.tick]: 'IN_REVIEW',
  [T.guardFail]: 'FAILED',
  [T.claimed]: 'CLAIMED',
  [T.blockedSandbox]: 'READY',
  [T.running]: 'RUNNING',
});

// Every guard the frozen table names must be exercised at least once, ACCEPTED
// or REFUSED. The names are READ OUT of constants.mjs TRANSITIONS (never
// re-declared here), so a new edge in the table immediately fails this run.
function frozenGuardNames() {
  return [...new Set(Object.values(TRANSITIONS).flatMap((edges) => Object.values(edges)))].sort();
}

// ===========================================================================
// Deterministic primitives
// ===========================================================================
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

/**
 * One monotonic, prefixed id factory for the whole run. `offset` is the ONLY
 * thing that differs between run A and run B: it shifts every generated
 * identifier, which is what makes the two runs genuinely distinct runs rather
 * than one run reported twice.
 */
function makeIdFactory(offset) {
  const counters = new Map();
  return (name) => {
    const prefix = typeof ID_PREFIXES[name] === 'string' ? ID_PREFIXES[name] : `${String(name).slice(0, 3)}-`;
    const next = (counters.get(name) ?? offset) + 1;
    counters.set(name, next);
    return `${prefix}${next.toString(36).padStart(6, '0')}`;
  };
}

function writeEvidence(name, value) {
  const target = path.join(EVIDENCE_DIR, name);
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return path.relative(ROOT, target);
}

function principalOf(principalId, capabilityKey, workspaceId) {
  const capabilities = CAP[capabilityKey];
  if (!Array.isArray(capabilities)) throw new Error(`CAPABILITY_SET_UNKNOWN:${String(capabilityKey)}`);
  for (const capability of capabilities) {
    if (!BOARD_CAPABILITIES.includes(capability)) throw new Error(`CAPABILITY_UNKNOWN:${capability}`);
  }
  return { principal_id: principalId, capabilities: [...capabilities], workspace_ids: [workspaceId] };
}

// ===========================================================================
// The harness
// ===========================================================================
class BoardRun {
  constructor({ runId, executorId, idOffset, storeSeed }) {
    this.runId = runId;
    this.executorId = executorId;
    this.storeSeed = storeSeed;
    this.tick = 0;
    this.step = 0;
    this.ids = makeIdFactory(idOffset);
    this.clock = () => new Date(Date.parse(CLOCK_BASE) + this.tick * STEP_MS);
    this.store = new InMemoryAgentBoardStore({ clock: this.clock, ids: this.ids, seed: storeSeed });
    this.calls = [];
    this.transitions = [];
    this.readSeq = 0;
    this.transportEffects = new Map();
    this.findings = [];
    this.settled = [];
    this.collected = [];
    this.dispatched = [];
    this.escalations = [];
  }

  now() { return this.clock().toISOString(); }

  /** The server-resolved instant: one fixed step per boundary call, never the process clock. */
  nextInstant() {
    this.tick += 1;
    return this.now();
  }

  /**
   * THE production-facing call. Records the decision, the typed refusal code and
   * the actor, and never lets an untyped error escape into the evidence.
   */
  async call(step, command, args, { principal, actorKind, workspaceId, adapters = null, transport = null }) {
    const instant = this.nextInstant();
    const idempotencyKey = canonicalDigest({ run: this.runId, step, command, args, actor: principal.principal_id });
    const row = {
      step,
      command,
      actor: principal.principal_id,
      actor_kind: actorKind,
      workspace_id: workspaceId,
      idempotency_key: idempotencyKey,
    };
    try {
      const result = await execute({
        command,
        args: { ...args, idempotency_key: idempotencyKey },
        principal,
        actorKind,
        store: this.store,
        adapters,
        transport,
        clock: { now: this.clock },
        now: instant,
        workspaceRoots: ROOTS[workspaceId],
      });
      this.step += 1;
      const record = {
        ...row,
        outcome: 'ACCEPT',
        revision: result.revision ?? null,
        replayed: result.replayed === true,
        data: result.data ?? null,
      };
      this.calls.push(record);
      return record;
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
        detail: String(error?.detail ?? '').slice(0, 300),
        data: null,
      };
      this.calls.push(record);
      return record;
    }
  }

  /**
   * A production READ of one task: the only source of a revision in this file.
   * The step (and therefore the idempotency key) is unique per call: a repeated
   * key with identical arguments is a REPLAY, and a replayed read would return a
   * stale revision and quietly drive the next transition from a stale state.
   */
  async readTask(taskId, workspaceId = ALPHA) {
    this.readSeq += 1;
    const row = await this.call(`read.${String(this.readSeq).padStart(4, '0')}.${taskId}`, 'tasks.get', { task_id: taskId }, {
      principal: principalOf(P.owner, 'owner', workspaceId), actorKind: 'human_owner', workspaceId,
    });
    if (row.outcome !== 'ACCEPT' || !row.data?.task) {
      throw new Error(`HARNESS_TASK_UNREADABLE:${taskId}:${row.code ?? 'no-task'}:${row.message ?? ''}:${row.detail ?? ''}`);
    }
    return row.data.task;
  }

  /** Observation only: the committed run rows of a task, as the store holds them. */
  async observeRuns(workspaceId, taskId) {
    const rows = await this.store.listRuns({ workspaceId, taskId });
    return Array.isArray(rows) ? rows : [];
  }

  /**
   * A transition through the boundary. The edge's GUARD is derived from the
   * frozen table, so the record never re-declares which guard owns an edge.
   */
  async transition(step, { task, toState, workspaceId = ALPHA, actor, actorKind, reason, extra = {} }) {
    const from = task.state;
    const row = await this.call(step, 'tasks.transition', {
      task_id: task.task_id,
      to_state: toState,
      expected_revision: task.revision,
      reason,
      brief_digest: task.brief_digest,
      policy_digest: task.policy_digest,
      manifest_digest: task.manifest_digest,
      ...extra,
    }, { principal: actor, actorKind, workspaceId });
    this.transitions.push({
      step,
      task_id: task.task_id,
      from_state: from,
      to_state: toState,
      guard: TRANSITIONS[from]?.[toState] ?? null,
      decision: row.outcome === 'ACCEPT' ? 'ACCEPT' : 'REFUSE',
      code: row.code ?? null,
      actor: actor.principal_id,
      actor_kind: actorKind,
    });
    return row;
  }

  /** Record the harness-side transport shim's effect counter for a run. */
  noteEffect(runId, effect) {
    this.transportEffects.set(runId, (this.transportEffects.get(runId) ?? 0) + effect);
  }

  /**
   * An edge the BOUNDARY drove inside a larger command (a claim mints the lease
   * and the READY->CLAIMED edge; a result collection moves RUNNING->IN_REVIEW; a
   * release moves CLAIMED->READY). It is journalled here with the guard read
   * out of the frozen table, so the guard coverage is the coverage of real
   * committed transitions and not only of the explicit `tasks.transition` calls.
   */
  recordEdge({ step, taskId, fromState, toState, decision, code = null, actor, actorKind }) {
    this.transitions.push({
      step,
      task_id: taskId,
      from_state: fromState,
      to_state: toState,
      guard: TRANSITIONS[fromState]?.[toState] ?? null,
      decision,
      code,
      actor,
      actor_kind: actorKind,
    });
  }
}

// ===========================================================================
// Fixtures
// ===========================================================================
function taskDocument(taskId, workspaceId, { title, acl, dependencies = [], priority = 'HIGH', profile = PROVEN_PROFILE, rootRef = 'alpha' }) {
  return {
    contractVersion: '1.0.0',
    task_id: taskId,
    workspace_id: workspaceId,
    title,
    goal: 'Move one bounded research unit through the live board to a state a human can defend',
    description: 'S2-007 acceptance fixture: a bounded, human-reviewed source-selection unit.',
    acceptance_criteria: [
      'Every state change is authorized server-side and journalled',
      'No DONE without an independent authenticated human decision',
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
      sandbox_profile_digest: d(DIGEST_CHAR.sandbox),
      read_only_paths: [],
    },
    time_limits: { timeout_ms: 60000, max_runtime_ms: 120000, deadline: null },
    cost_limits: { currency: 'USD', max_task_cost: 5, max_campaign_cost: 20, max_day_cost: 10 },
    acl: { visibility: 'project', allowed_principal_ids: [...acl] },
    brief_digest: d(DIGEST_CHAR.brief),
    policy_digest: d(DIGEST_CHAR.policy),
    manifest_digest: d(DIGEST_CHAR.manifest),
    assigned_adapter_id: null,
    active_lease_id: null,
    fencing_token: null,
    attempts: 0,
    artifacts: [],
    evidence_refs: [],
    block_reason: null,
    created_at: FIXTURE_INSTANT,
    updated_at: FIXTURE_INSTANT,
    history_digest: d(DIGEST_CHAR.history),
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

/**
 * A scripted `veritas.adapter/1.0.0` test transport. Its registration is the
 * document the boundary registers, so the store, the guards and the transport
 * cannot disagree about which executor exists. The provenance status is left to
 * adapters.mjs, which can only ever build NOT_RUN_REAL_ADAPTER here.
 */
function scriptedTransport(run, adapterId, workspaceId, { capabilities = ['source.read'], tools = ['tool:fs.read'], script = {}, profile = PROVEN_PROFILE } = {}) {
  return createTestTransport({
    script,
    clock: { now: run.clock },
    ids: run.ids,
    provenance: {
      adapter_id: adapterId,
      workspace_id: workspaceId,
      principal_id: P.producer,
      declared_capabilities: capabilities,
      declared_tools: tools,
      sandbox_profile_id: profile,
      health: 'healthy',
      display_name: `S2-007 scripted transport ${adapterId}`,
      detail: 'S2-007 acceptance fixture: no installed executor is bound to this adapter',
    },
  });
}

/** The blocked-sandbox adapter: contract-valid, and refused at every live edge. */
function blockedProfileRegistration(adapterId, workspaceId) {
  return {
    contractVersion: '1.0.0',
    adapter_id: adapterId,
    adapter_interface: 'veritas.adapter/1.0.0',
    provider: 'test',
    display_name: `S2-007 blocked-sandbox transport ${adapterId}`,
    adapter_kind: 'test',
    health: 'healthy',
    workspace_id: workspaceId,
    principal_id: P.producer,
    declared_capabilities: ['source.read'],
    declared_tools: ['tool:fs.read'],
    sandbox_profile_id: BLOCKED_PROFILE,
    max_concurrency: 1,
    real_adapter_provenance: {
      status: 'NOT_RUN_REAL_ADAPTER',
      detail: 'registered to prove a non-proven isolation profile is refused, not to execute anything',
    },
    registered_at: FIXTURE_INSTANT,
  };
}

/**
 * The harness-side transport shim (see the header). It exposes `dispatch()`,
 * which `driveOutbox` prefers over `start()`, forwards the outbox payload as the
 * ExecutionRequest, supplies the run id the harness observed, and COUNTS the
 * boundary crossings. `failWith` models an executor that never answers.
 */
function outboxShim(run, transport, runId, { failWith = null } = {}) {
  return {
    async dispatch(payload) {
      if (failWith !== null) {
        const error = new Error(`scripted executor never answered: ${failWith}`);
        error.code = failWith;
        throw error;
      }
      const event = await transport.start({ request: payload, run_id: runId });
      run.noteEffect(runId, 1);
      return event;
    },
    async cancel(args) { return transport.cancel(args); },
    async health() { return transport.health(); },
    async identify() { return transport.identify(); },
  };
}

function executionEventDocument(run, runRow, { sequence = 1 } = {}) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    event_id: `eve-${runRow.run_id.slice(4)}-progress`,
    run_id: runRow.run_id,
    task_id: runRow.task_id,
    workspace_id: runRow.workspace_id,
    lease_id: runRow.lease_id,
    fencing_token: Number(runRow.fencing_token),
    sequence,
    event_type: 'PROGRESS',
    payload: { note: 'bounded collection progress recorded by the scripted transport' },
    outcome: null,
    emitted_at: run.now(),
  };
}

function executionResultDocument(run, runRow, { sequence = 1, outcome = 'SUCCEEDED', spend = 0.25, durationMs = 1200, error = null, reconciliationRequired = false, artifacts = true } = {}) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    run_id: runRow.run_id,
    task_id: runRow.task_id,
    workspace_id: runRow.workspace_id,
    lease_id: runRow.lease_id,
    fencing_token: Number(runRow.fencing_token),
    sequence,
    outcome,
    checkpoints: [],
    artifact_hashes: artifacts
      ? [{ artifact_id: `art-${runRow.task_id.slice(4)}`, digest: d('9'), media_type: 'application/json' }]
      : [],
    measurements: {
      duration_ms: durationMs,
      spend,
      currency: 'USD',
      model_id: 's2-007-scripted-test-transport',
      tool_calls: 2,
    },
    error,
    reconciliation_required: reconciliationRequired,
    completed_at: run.now(),
  };
}

function boardErrorDocument(run, code, message) {
  return {
    contractVersion: '1.0.0',
    code,
    message,
    retryable: !NON_RETRYABLE_CODES.includes(code),
    detail: null,
    occurred_at: run.now(),
  };
}

function reconciliationDocument(taskId, runId, workspaceId, resolution, detail, reconciliationId) {
  return {
    reconciliation_id: reconciliationId,
    workspace_id: workspaceId,
    task_id: taskId,
    run_id: runId,
    resolution,
    detail,
    evidence_ref: null,
  };
}

/**
 * The edges a `tasks.claim` drove inside ONE command: the claim mints the lease
 * and the READY->CLAIMED edge, and the dispatch then moves CLAIMED->RUNNING.
 * Both are journalled by the store; both are recorded here, so the guard
 * coverage of this run is the coverage of real committed transitions and not
 * only of the explicit `tasks.transition` calls.
 */
function recordClaimEdge(run, step, call, taskId, actor, actorKind) {
  run.recordEdge({
    step,
    taskId,
    fromState: 'READY',
    toState: 'CLAIMED',
    decision: call.outcome === 'ACCEPT' ? 'ACCEPT' : 'REFUSE',
    code: call.code ?? null,
    actor,
    actorKind,
  });
}

/** The same two edges for a dispatch that started from a READY task. */
function recordStartEdges(run, step, call, taskId, actor, actorKind) {
  if (call.outcome !== 'ACCEPT' || !call.data?.run) return;
  recordClaimEdge(run, step, call, taskId, actor, actorKind);
  run.recordEdge({ step, taskId, fromState: 'CLAIMED', toState: 'RUNNING', decision: 'ACCEPT', actor, actorKind });
}

// ===========================================================================
// The scenario
// ===========================================================================
async function runScenario({ runId, executorId, idOffset, storeSeed }) {
  const run = new BoardRun({ runId, executorId, idOffset, storeSeed });
  const alpha = {
    ws: ALPHA,
    owner: principalOf(P.owner, 'owner', ALPHA),
    reviewer: principalOf(P.reviewer, 'reviewer', ALPHA),
    scheduler: principalOf(P.scheduler, 'scheduler', ALPHA),
    producer: principalOf(P.producer, 'producer', ALPHA),
  };
  const beta = {
    ws: BETA,
    owner: principalOf(P.owner, 'owner', BETA),
    scheduler: principalOf(P.scheduler, 'scheduler', BETA),
    producer: principalOf(P.producer, 'producer', BETA),
  };
  // A different authenticated human from the one who recorded the
  // reconciliation: a decider may not be the actor of the edge it closes.
  const requeueDecider = principalOf(P.gate, 'gate', ALPHA);

  const transportSpec = Object.freeze({
    [A.collector]: { workspace: ALPHA, script: { events: [{ event_type: 'PROGRESS', payload: { note: 'collection in progress' } }], result: { outcome: 'SUCCEEDED' } } },
    [A.bulk]: { workspace: ALPHA, script: { events: [{ event_type: 'PROGRESS', payload: { note: 'bulk pass in progress' } }], result: { outcome: 'SUCCEEDED' } } },
    [A.timeout]: { workspace: ALPHA, script: { failWith: { start: 'TIMEOUT' } } },
    [A.tick]: { workspace: BETA, script: { events: [{ event_type: 'PROGRESS', payload: { note: 'pilot pass in progress' } }], result: { outcome: 'SUCCEEDED' } } },
  });
  // One scripted transport INSTANCE per run. The instance is the modelled
  // boundary state: it accepts exactly one handoff and refuses a second, so a
  // transport shared across two runs would report a lease/run mismatch that has
  // nothing to do with the board. The REGISTRATION is registered once per
  // adapter, from the first instance, so the store, the guards and the
  // transport can never disagree about which executor exists.
  const registrations = new Map();
  function transportFor(adapterId) {
    const spec = transportSpec[adapterId];
    const transport = scriptedTransport(run, adapterId, spec.workspace, { script: spec.script });
    if (!registrations.has(adapterId)) registrations.set(adapterId, transport.registration);
    return transport;
  }
  for (const adapterId of [A.collector, A.bulk, A.timeout, A.tick]) transportFor(adapterId);
  const alphaAdapters = [
    registrations.get(A.collector),
    registrations.get(A.bulk),
    registrations.get(A.timeout),
    blockedProfileRegistration(A.blocked, ALPHA),
  ];
  const betaAdapters = [registrations.get(A.tick)];

  // --- 0. discovery, and the honesty gate -----------------------------------
  const hostProbe = await probeRealAdapters({ clock: { now: run.clock } });
  const capabilities = await run.call('discovery.capabilities', 'capabilities', {}, {
    principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA,
  });
  run.findings.push({
    id: 'real-adapter-not-run',
    severity: 'declared-limit',
    detail: `host probe found ${hostProbe.filter((row) => row.installed === true).length} installed candidate executor(s); every run below is a scripted transport`,
    realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
  });
  // A registration may CLAIM a real adapter; only an installed executable may
  // CONFIRM one. The claim is attempted on purpose and must be refused.
  await run.call('discovery.real-claim-registration', 'adapters.register', {
    registration: {
      ...blockedProfileRegistration(A.realClaim, ALPHA),
      adapter_kind: 'real',
      sandbox_profile_id: PROVEN_PROFILE,
      real_adapter_provenance: { status: 'REAL_ADAPTER_AVAILABLE', detail: 'claimed by the fixture and expected to be refused' },
    },
  }, { principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA });

  // --- 1. the registered executors ------------------------------------------
  for (const [step, registration, workspaceId] of [
    ['setup.register-collector', registrations.get(A.collector), ALPHA],
    ['setup.register-bulk', registrations.get(A.bulk), ALPHA],
    ['setup.register-timeout', registrations.get(A.timeout), ALPHA],
    ['setup.register-blocked-sandbox-adapter', alphaAdapters[3], ALPHA],
    ['setup.register-tick', registrations.get(A.tick), BETA],
  ]) {
    await run.call(step, 'adapters.register', { registration }, {
      principal: workspaceId === BETA ? beta.owner : alpha.owner,
      actorKind: 'human_owner',
      workspaceId,
    });
  }
  // An operator health signal, and its restoration: the server-resolved health
  // is what a dispatch reads, so both transitions are recorded.
  await run.call('setup.health-degraded', 'adapters.health', { adapter_id: A.collector, health: 'degraded' }, {
    principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA,
  });
  await run.call('setup.health-restored', 'adapters.health', { adapter_id: A.collector, health: 'healthy' }, {
    principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA,
  });

  // --- 2. the tasks ---------------------------------------------------------
  // Fifteen bounded units, every one of them created through the boundary with
  // an ACL that names its real actors, so a later read or transition is subject
  // to the same ACL a deployment would apply.
  const created = [];
  for (const taskId of ALL_TASKS) {
    const workspaceId = taskId === T.tick || taskId === T.running ? BETA : ALPHA;
    const row = await run.call(`create.${taskId}`, 'tasks.create', {
      task: taskDocument(taskId, workspaceId, {
        title: `S2-007 acceptance task ${taskId.slice(8)}`,
        acl: workspaceId === BETA ? ACL_BETA : ACL_ALPHA,
        dependencies: taskId === T.openDep ? [T.ready] : (taskId === T.blocked ? [T.done] : []),
        priority: 'HIGH',
        profile: taskId === T.blockedSandbox ? BLOCKED_PROFILE : PROVEN_PROFILE,
        rootRef: workspaceId === BETA ? 'pilot' : 'alpha',
      }),
    }, { principal: workspaceId === BETA ? beta.owner : alpha.owner, actorKind: 'human_owner', workspaceId });
    if (row.outcome === 'ACCEPT') created.push({ task_id: taskId, workspace_id: workspaceId });
    else {
      run.findings.push({
        id: 'task-creation-refused',
        severity: 'defect',
        task_id: taskId,
        code: row.code,
        message: row.message,
        detail: row.detail,
      });
    }
  }
  // A refused fixture build is a defect and the record carries it; the
  // S2_007_DEBUG channel makes it visible without a second code path.
  if (process.env.S2_007_DEBUG === '1') {
    for (const finding of run.findings) process.stderr.write(`FINDING ${JSON.stringify(finding)}\n`);
  }

  const readyTask = async (step, taskId, workspaceId = ALPHA) => {
    const task = await run.readTask(taskId, workspaceId);
    const actor = workspaceId === BETA ? beta.owner : alpha.owner;
    await run.transition(step, {
      task,
      toState: 'READY',
      workspaceId,
      actor,
      actorKind: 'human_owner',
      reason: 'immutable brief validated, dependencies closed, numeric budget assigned',
    });
    return run.readTask(taskId, workspaceId);
  };
  const grantTask = async (step, taskId, workspaceId = ALPHA) => {
    const actor = workspaceId === BETA ? beta.owner : alpha.owner;
    return run.call(step, 'budget.grant', { grant: budgetGrant(taskId, workspaceId) }, {
      principal: actor, actorKind: 'human_owner', workspaceId,
    });
  };

  // --- 3. BACKLOG -> READY with an OPEN dependency: refused -----------------
  await run.transition('deps.open-backlog-to-ready', {
    task: await run.readTask(T.openDep),
    toState: 'READY',
    actor: alpha.owner,
    actorKind: 'human_owner',
    reason: 'the operator believes the upstream source selection is finished',
  });

  // --- 4. BACKLOG -> READY, closed dependencies -----------------------------
  await readyTask('ready.backlog-to-ready', T.ready);
  await grantTask('ready.grant', T.ready);
  // A principal authenticated in the OTHER tenant names a task of this one: the
  // ACL, not the workspace label, is what decides.
  await run.call('ready.cross-workspace-read', 'tasks.get', { task_id: T.ready }, {
    principal: principalOf(P.betaOnly, 'betaOnly', BETA), actorKind: 'human_reviewer', workspaceId: ALPHA,
  });
  // A task bound to an isolation profile with no measured controls on this host
  // can be created and even readied, and can never be started.
  await readyTask('sandbox.blocked-profile-ready', T.blockedSandbox);
  await grantTask('sandbox.blocked-profile-grant', T.blockedSandbox);
  await run.call('sandbox.blocked-profile-dispatch', 'execution.start', { task_id: T.blockedSandbox, adapter_id: A.collector }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.collector),
  });

  // --- 5. the scheduler tick on the second tenant ----------------------------
  await readyTask('tick.ready', T.tick, BETA);
  await grantTask('tick.grant', T.tick, BETA);
  const plan = await run.call('tick.plan', 'dispatch.plan', { workspace_id: BETA }, {
    principal: beta.scheduler, actorKind: 'scheduler', workspaceId: BETA, adapters: betaAdapters,
  });
  const tick = await run.call('tick.execute', 'dispatch.tick', { workspace_id: BETA }, {
    principal: beta.scheduler, actorKind: 'scheduler', workspaceId: BETA, adapters: betaAdapters, transport: transportFor(A.tick),
  });
  const tickRun = tick.data?.run ?? null;
  if (tickRun) run.dispatched.push({ run_id: tickRun.run_id, task_id: tickRun.task_id, adapter_id: A.tick });
  if (tick.outcome === 'ACCEPT' && tickRun) {
    run.recordEdge({ step: 'tick.execute', taskId: tickRun.task_id, fromState: 'READY', toState: 'CLAIMED', decision: 'ACCEPT', actor: P.scheduler, actorKind: 'scheduler' });
    run.recordEdge({ step: 'tick.execute', taskId: tickRun.task_id, fromState: 'CLAIMED', toState: 'RUNNING', decision: 'ACCEPT', actor: P.scheduler, actorKind: 'scheduler' });
  }
  await run.call('tick.dispatch', 'outbox.dispatch', { workspace_id: BETA }, {
    principal: beta.scheduler, actorKind: 'scheduler', workspaceId: BETA, adapters: betaAdapters,
    transport: outboxShim(run, transportFor(A.tick), tickRun.run_id),
  });
  const tickCollect = await run.call('tick.collect', 'execution.collect_result', {
    run_id: tickRun.run_id,
    result: executionResultDocument(run, tickRun),
  }, { principal: beta.producer, actorKind: 'adapter', workspaceId: BETA, adapters: betaAdapters, transport: transportFor(A.tick) });
  if (tickCollect.outcome === 'ACCEPT') {
    run.collected.push({ run_id: tickRun.run_id, task_id: tickRun.task_id, outcome: 'SUCCEEDED', spend: 0.25, duration_ms: 1200 });
    run.recordEdge({ step: 'tick.collect', taskId: tickRun.task_id, fromState: 'RUNNING', toState: 'IN_REVIEW', decision: 'ACCEPT', actor: P.producer, actorKind: 'adapter' });
  }

  // --- 6. the full lifecycle, approved by an authenticated human ------------
  await readyTask('done.ready', T.done);
  await grantTask('done.grant', T.done);
  const doneStart = await run.call('done.start', 'execution.start', { task_id: T.done, adapter_id: A.collector }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.collector),
  });
  const doneRun = doneStart.data?.run ?? null;
  if (doneRun) run.dispatched.push({ run_id: doneRun.run_id, task_id: doneRun.task_id, adapter_id: A.collector });
  recordStartEdges(run, 'done.start', doneStart, T.done, P.scheduler, 'scheduler');
  await run.call('done.dispatch', 'outbox.dispatch', { workspace_id: ALPHA }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters,
    transport: outboxShim(run, transportFor(A.collector), doneRun.run_id),
  });
  await run.call('done.event', 'execution.event', {
    run_id: doneRun.run_id, event: executionEventDocument(run, doneRun),
  }, { principal: alpha.producer, actorKind: 'adapter', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.collector) });
  const doneCollect = await run.call('done.collect', 'execution.collect_result', {
    run_id: doneRun.run_id, result: executionResultDocument(run, doneRun, { sequence: 2 }),
  }, { principal: alpha.producer, actorKind: 'adapter', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.collector) });
  if (doneCollect.outcome === 'ACCEPT') {
    run.collected.push({ run_id: doneRun.run_id, task_id: doneRun.task_id, outcome: 'SUCCEEDED', spend: 0.25, duration_ms: 1200 });
    run.recordEdge({ step: 'done.collect', taskId: doneRun.task_id, fromState: 'RUNNING', toState: 'IN_REVIEW', decision: 'ACCEPT', actor: P.producer, actorKind: 'adapter' });
  }
  const inReviewDone = await run.readTask(T.done);
  // The producer holds board.review.approve in its SERVER-RESOLVED grant on
  // purpose: only the independence rule itself may refuse it.
  await run.transition('done.approve-by-producer', {
    task: inReviewDone,
    toState: 'DONE',
    actor: principalOf(P.producer, 'producerWithApprove', ALPHA),
    actorKind: 'adapter',
    reason: 'the producer asserts that its own output is correct',
  });
  await run.transition('done.approve-by-human', {
    task: inReviewDone,
    toState: 'DONE',
    actor: alpha.reviewer,
    actorKind: 'human_reviewer',
    reason: 'independent human review confirmed the bound brief, policy and manifest digests',
  });
  await run.call('done.settle', 'budget.settle', {
    grant_id: budgetGrant(T.done, ALPHA).grant_id,
    operation_id: `op-${T.done.slice(4)}-run`,
    task_id: T.done,
    amount: 0.25,
    currency: 'USD',
    day_key: CLOCK_DAY,
  }, { principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA });
  run.settled.push({ task_id: T.done, amount: 0.25, currency: 'USD', day_key: CLOCK_DAY });

  // --- 7. an unapproved result, then a challenged one -----------------------
  await readyTask('review.ready', T.challenge);
  await grantTask('review.grant', T.challenge);
  const reviewStart = await run.call('review.start', 'execution.start', { task_id: T.challenge, adapter_id: A.collector }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.collector),
  });
  const reviewRun = reviewStart.data?.run ?? null;
  if (reviewRun) run.dispatched.push({ run_id: reviewRun.run_id, task_id: reviewRun.task_id, adapter_id: A.collector });
  recordStartEdges(run, 'review.start', reviewStart, T.challenge, P.scheduler, 'scheduler');
  await run.call('review.dispatch', 'outbox.dispatch', { workspace_id: ALPHA }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters,
    transport: outboxShim(run, transportFor(A.bulk), reviewRun.run_id),
  });
  const reviewCollect = await run.call('review.collect', 'execution.collect_result', {
    run_id: reviewRun.run_id, result: executionResultDocument(run, reviewRun),
  }, { principal: alpha.producer, actorKind: 'adapter', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.bulk) });
  if (reviewCollect.outcome === 'ACCEPT') {
    run.collected.push({ run_id: reviewRun.run_id, task_id: reviewRun.task_id, outcome: 'SUCCEEDED', spend: 0.25, duration_ms: 1200 });
    run.recordEdge({ step: 'review.collect', taskId: reviewRun.task_id, fromState: 'RUNNING', toState: 'IN_REVIEW', decision: 'ACCEPT', actor: P.producer, actorKind: 'adapter' });
  }
  const inReviewChallenge = await run.readTask(T.challenge);
  await run.transition('review.approve-by-uncalibrated-verifier-without-capability', {
    task: inReviewChallenge,
    toState: 'DONE',
    actor: principalOf(P.verifier, 'verifierNarrow', ALPHA),
    actorKind: 'system',
    reason: 'the uncalibrated semantic verifier believes the claim set is correct',
  });
  await run.transition('review.approve-by-uncalibrated-verifier-with-capability', {
    task: inReviewChallenge,
    toState: 'DONE',
    actor: principalOf(P.verifier, 'verifierWithApprove', ALPHA),
    actorKind: 'system',
    reason: 'the uncalibrated semantic verifier believes the claim set is correct',
  });
  await run.transition('review.challenge', {
    task: inReviewChallenge,
    toState: 'BLOCKED',
    actor: alpha.reviewer,
    actorKind: 'human_reviewer',
    reason: 'the reviewer challenges the source selection and asks for a second primary source',
  });

  // --- 8. a closed dependency, block and unblock ----------------------------
  await grantTask('blocked.grant', T.blocked);
  await run.transition('closed-dep.backlog-to-ready', {
    task: await run.readTask(T.blocked),
    toState: 'READY',
    actor: alpha.owner,
    actorKind: 'human_owner',
    reason: 'the upstream task is DONE, so the dependency closure is satisfied',
  });
  await run.transition('blocked.block', {
    task: await run.readTask(T.blocked),
    toState: 'BLOCKED',
    actor: alpha.owner,
    actorKind: 'human_owner',
    reason: 'the required source is not retrievable from any registered mirror',
  });
  await readyTask('unblock.ready', T.unblock);
  await run.transition('unblock.block', {
    task: await run.readTask(T.unblock),
    toState: 'BLOCKED',
    actor: alpha.owner,
    actorKind: 'human_owner',
    reason: 'the operator needs a human decision on the licence of the secondary source',
  });
  await run.transition('unblock.unblock', {
    task: await run.readTask(T.unblock),
    toState: 'READY',
    actor: alpha.owner,
    actorKind: 'human_owner',
    reason: 'the licence question is resolved and the immutable brief still validates',
  });

  // --- 9. a collected FAILED result ----------------------------------------
  await readyTask('collect-failed.ready', T.collectFailed);
  await grantTask('collect-failed.grant', T.collectFailed);
  const failedStart = await run.call('collect-failed.start', 'execution.start', { task_id: T.collectFailed, adapter_id: A.collector }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.collector),
  });
  const failedRun = failedStart.data?.run ?? null;
  if (failedRun) run.dispatched.push({ run_id: failedRun.run_id, task_id: failedRun.task_id, adapter_id: A.collector });
  recordStartEdges(run, 'collect-failed.start', failedStart, T.collectFailed, P.scheduler, 'scheduler');
  await run.call('collect-failed.dispatch', 'outbox.dispatch', { workspace_id: ALPHA }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters,
    transport: outboxShim(run, transportFor(A.bulk), failedRun.run_id),
  });
  const failedCollect = await run.call('collect-failed.collect', 'execution.collect_result', {
    run_id: failedRun.run_id,
    result: executionResultDocument(run, failedRun, {
      outcome: 'FAILED',
      spend: 0.1,
      durationMs: 900,
      error: boardErrorDocument(run, 'PROVIDER_FAILURE', 'the scripted executor reported a known, non-ambiguous failure'),
    }),
  }, { principal: alpha.producer, actorKind: 'adapter', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.bulk) });
  if (failedCollect.outcome === 'ACCEPT') {
    run.collected.push({ run_id: failedRun.run_id, task_id: failedRun.task_id, outcome: 'FAILED', spend: 0.1, duration_ms: 900 });
  }

  // --- 10. claim, renew, run, and the requeue the contract requires ---------
  await readyTask('requeue.ready', T.requeue);
  await grantTask('requeue.grant', T.requeue);
  const requeueClaim = await run.call('requeue.claim', 'tasks.claim', {
    task_id: T.requeue,
    adapter_id: A.collector,
    expected_revision: (await run.readTask(T.requeue)).revision,
    ttl_ms: 60000,
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.collector) });
  recordClaimEdge(run, 'requeue.claim', requeueClaim, T.requeue, P.scheduler, 'scheduler');
  const requeueLease = requeueClaim.data?.lease_id ?? null;
  const requeueFence = Number(requeueClaim.data?.lease?.fencing_token ?? 0);
  await run.call('requeue.renew', 'tasks.lease.renew', {
    lease_id: requeueLease, fencing_token: requeueFence, ttl_ms: 120000,
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.collector) });
  await run.transition('requeue.to-running', {
    task: await run.readTask(T.requeue),
    toState: 'RUNNING',
    actor: alpha.producer,
    actorKind: 'adapter',
    reason: 'the executor acknowledged the handoff under the current fence',
    extra: { fencing_token: requeueFence },
  });
  const requeueExec = transportFor(A.collector);
  const requeueStart = await run.call('requeue.start', 'execution.start', { task_id: T.requeue, adapter_id: A.collector }, {
    principal: alpha.producer, actorKind: 'adapter', workspaceId: ALPHA, adapters: alphaAdapters, transport: requeueExec,
  });
  const requeueRunId = requeueStart.data?.run?.run_id ?? (await run.observeRuns(ALPHA, T.requeue))[0]?.run_id ?? null;
  if (requeueStart.data?.run) run.dispatched.push({ run_id: requeueRunId, task_id: T.requeue, adapter_id: A.collector });
  await run.call('requeue.dispatch', 'outbox.dispatch', { workspace_id: ALPHA }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters,
    transport: outboxShim(run, requeueExec, requeueRunId),
  });
  const requeueReconcile = await run.call('requeue.reconcile', 'reconciliation.record', {
    reconciliation: reconciliationDocument(
      T.requeue,
      requeueRunId,
      ALPHA,
      'OBSERVED_EFFECT_COMPLETED',
      'the operator observed that the single dispatched handoff produced one bounded artifact and no further effect',
      `rec-${T.requeue.slice(4)}`,
    ),
  }, { principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA, adapters: alphaAdapters });
  // The requeue edge, attempted honestly in both orderings the board allows.
  await run.transition('requeue.requeue-with-live-lease', {
    task: await run.readTask(T.requeue),
    toState: 'READY',
    actor: requeueDecider,
    actorKind: 'human_reviewer',
    reason: 'the reconciliation decision authorizes a requeue of this task',
    extra: { reconciliation_id: `rec-${T.requeue.slice(4)}` },
  });
  await run.call('requeue.revoke', 'tasks.lease.revoke', {
    lease_id: requeueLease,
    fencing_token: requeueFence,
    reason: 'the right to execute is withdrawn before the board re-decides the task',
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters });
  await run.transition('requeue.requeue-without-lease', {
    task: await run.readTask(T.requeue),
    toState: 'READY',
    actor: requeueDecider,
    actorKind: 'human_reviewer',
    reason: 'the reconciliation decision authorizes a requeue of this task',
    extra: { reconciliation_id: `rec-${T.requeue.slice(4)}` },
  });
  const requeueCancel = await run.call('requeue.cancel', 'execution.cancel', {
    run_id: requeueRunId,
    reason: 'the operator cancelled the run after the handoff stalled',
  }, { principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA, adapters: alphaAdapters, transport: requeueExec });
  run.recordEdge({
    step: 'requeue.cancel',
    taskId: T.requeue,
    fromState: 'RUNNING',
    toState: 'CANCELLED',
    decision: requeueCancel.outcome === 'ACCEPT' ? 'ACCEPT' : 'REFUSE',
    code: requeueCancel.code ?? null,
    actor: P.owner,
    actorKind: 'human_owner',
  });
  if (requeueReconcile.outcome === 'ACCEPT') {
    run.escalations.push({
      task_id: T.requeue,
      resolution: 'OBSERVED_EFFECT_COMPLETED',
      decided_by: P.owner,
      closed_by: 'human',
      requeue_attempts: [
        { ordering: 'lease-live', outcome: 'REFUSE', code: run.calls.find((call) => call.step === 'requeue.requeue-with-live-lease')?.code ?? null },
        { ordering: 'lease-withdrawn', outcome: 'REFUSE', code: run.calls.find((call) => call.step === 'requeue.requeue-without-lease')?.code ?? null },
      ],
    });
  }

  // --- 11. the release edge: a claimed task behind a decision ---------------
  await readyTask('release.ready', T.release);
  await grantTask('release.grant', T.release);
  const releaseClaim = await run.call('release.claim', 'tasks.claim', {
    task_id: T.release,
    adapter_id: A.bulk,
    expected_revision: (await run.readTask(T.release)).revision,
    ttl_ms: 60000,
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.bulk) });
  recordClaimEdge(run, 'release.claim', releaseClaim, T.release, P.scheduler, 'scheduler');
  const releaseLease = releaseClaim.data?.lease_id ?? null;
  const releaseFence = Number(releaseClaim.data?.lease?.fencing_token ?? 0);
  const releaseStart = await run.call('release.start', 'execution.start', { task_id: T.release, adapter_id: A.bulk }, {
    principal: alpha.producer, actorKind: 'adapter', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.bulk),
  });
  const releaseRunId = releaseStart.data?.run?.run_id ?? (await run.observeRuns(ALPHA, T.release))[0]?.run_id ?? null;
  if (releaseStart.data?.run) run.dispatched.push({ run_id: releaseRunId, task_id: T.release, adapter_id: A.bulk });
  await run.call('release.dispatch', 'outbox.dispatch', { workspace_id: ALPHA }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters,
    transport: outboxShim(run, transportFor(A.bulk), releaseRunId),
  });
  await run.call('release.reconcile', 'reconciliation.record', {
    reconciliation: reconciliationDocument(
      T.release,
      releaseRunId,
      ALPHA,
      'OBSERVED_NO_EFFECT',
      'the operator observed that the executor produced no external effect at all',
      `rec-${T.release.slice(4)}`,
    ),
  }, { principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA, adapters: alphaAdapters });
  const releaseCall = await run.call('release.release', 'tasks.lease.release', {
    lease_id: releaseLease,
    fencing_token: releaseFence,
    reason: 'no external effect was observed, so the task returns to the queue behind a recorded decision',
    reconciliation_id: `rec-${T.release.slice(4)}`,
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters });
  run.recordEdge({
    step: 'release.release',
    taskId: T.release,
    fromState: 'CLAIMED',
    toState: 'READY',
    decision: releaseCall.outcome === 'ACCEPT' ? 'ACCEPT' : 'REFUSE',
    code: releaseCall.code ?? null,
    actor: P.scheduler,
    actorKind: 'scheduler',
  });
  run.escalations.push({
    task_id: T.release,
    resolution: 'OBSERVED_NO_EFFECT',
    decided_by: P.owner,
    closed_by: 'human',
    release_code: run.calls.find((call) => call.step === 'release.release')?.code ?? null,
  });

  // --- 12. a timed-out dispatch: never a blind retry ------------------------
  await readyTask('timeout.ready', T.timeout);
  await grantTask('timeout.grant', T.timeout);
  const timeoutClaim = await run.call('timeout.claim', 'tasks.claim', {
    task_id: T.timeout,
    adapter_id: A.timeout,
    expected_revision: (await run.readTask(T.timeout)).revision,
    ttl_ms: 60000,
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.timeout) });
  recordClaimEdge(run, 'timeout.claim', timeoutClaim, T.timeout, P.scheduler, 'scheduler');
  const timeoutFence = Number(timeoutClaim.data?.lease?.fencing_token ?? 0);
  await run.transition('timeout.to-running', {
    task: await run.readTask(T.timeout),
    toState: 'RUNNING',
    actor: alpha.producer,
    actorKind: 'adapter',
    reason: 'the handoff was accepted by the scripted executor',
    extra: { fencing_token: timeoutFence },
  });
  const timeoutStart = await run.call('timeout.start', 'execution.start', { task_id: T.timeout, adapter_id: A.timeout }, {
    principal: alpha.producer, actorKind: 'adapter', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.timeout),
  });
  const timeoutRunId = timeoutStart.data?.run?.run_id ?? (await run.observeRuns(ALPHA, T.timeout))[0]?.run_id ?? null;
  if (timeoutStart.data?.run) run.dispatched.push({ run_id: timeoutRunId, task_id: T.timeout, adapter_id: A.timeout });
  const timeoutShim = outboxShim(run, transportFor(A.timeout), timeoutRunId, { failWith: 'TIMEOUT' });
  const timeoutDispatch = await run.call('timeout.dispatch-timed-out', 'outbox.dispatch', { workspace_id: ALPHA }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: timeoutShim,
  });
  // The second dispatch attempt: the row is no longer PENDING, so nothing may
  // cross the boundary again. The shim counter is the proof.
  const timeoutRetry = await run.call('timeout.dispatch-not-retried', 'outbox.dispatch', { workspace_id: ALPHA }, {
    principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: timeoutShim,
  });
  const timeoutRecover = await run.call('timeout.recover', 'outbox.recover', { workspace_id: ALPHA }, {
    principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA,
  });
  await run.call('timeout.reconcile', 'reconciliation.record', {
    reconciliation: reconciliationDocument(
      T.timeout,
      timeoutRunId,
      ALPHA,
      'OBSERVED_NO_EFFECT',
      'the dispatch intent was recorded and the executor never answered; the operator observed no effect',
      `rec-${T.timeout.slice(4)}`,
    ),
  }, { principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA, adapters: alphaAdapters });
  const timeoutCancel = await run.call('timeout.cancel', 'tasks.cancel', {
    task_id: T.timeout,
    reason: 'the dispatch timed out and the task is withdrawn from this campaign',
  }, { principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA, adapters: alphaAdapters });
  run.recordEdge({
    step: 'timeout.cancel',
    taskId: T.timeout,
    fromState: 'RUNNING',
    toState: 'CANCELLED',
    decision: timeoutCancel.outcome === 'ACCEPT' ? 'ACCEPT' : 'REFUSE',
    code: timeoutCancel.code ?? null,
    actor: P.owner,
    actorKind: 'human_owner',
  });
  run.escalations.push({
    task_id: T.timeout,
    resolution: 'OBSERVED_NO_EFFECT',
    decided_by: P.owner,
    closed_by: 'human',
    dispatch_code: timeoutDispatch.code ?? null,
    repeat_dispatch_inspected: timeoutRetry.data?.summary?.inspected ?? null,
    repeat_dispatch_effects: timeoutRetry.data?.summary?.externalEffectsIssued ?? null,
    recover_escalated: timeoutRecover.data?.summary?.escalated ?? null,
  });

  // --- 13. cancel from READY -----------------------------------------------
  await readyTask('cancel.ready', T.cancel);
  const cancelCall = await run.call('cancel.cancel', 'tasks.cancel', {
    task_id: T.cancel,
    reason: 'the owner withdrew this unit from the campaign',
  }, { principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA, adapters: alphaAdapters });
  run.recordEdge({
    step: 'cancel.cancel',
    taskId: T.cancel,
    fromState: 'READY',
    toState: 'CANCELLED',
    decision: cancelCall.outcome === 'ACCEPT' ? 'ACCEPT' : 'REFUSE',
    code: cancelCall.code ?? null,
    actor: P.owner,
    actorKind: 'human_owner',
  });

  // --- 14. the fail guard on a withdrawn run --------------------------------
  await readyTask('guard-fail.ready', T.guardFail);
  const guardFailClaim = await run.call('guard-fail.claim', 'tasks.claim', {
    task_id: T.guardFail,
    adapter_id: A.bulk,
    expected_revision: (await run.readTask(T.guardFail)).revision,
    ttl_ms: 60000,
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.bulk) });
  recordClaimEdge(run, 'guard-fail.claim', guardFailClaim, T.guardFail, P.scheduler, 'scheduler');
  const guardFailFence = Number(guardFailClaim.data?.lease?.fencing_token ?? 0);
  await run.transition('guard-fail.to-running', {
    task: await run.readTask(T.guardFail),
    toState: 'RUNNING',
    actor: alpha.producer,
    actorKind: 'adapter',
    reason: 'the executor acknowledged the handoff under the current fence',
    extra: { fencing_token: guardFailFence },
  });
  await run.call('guard-fail.revoke', 'tasks.lease.revoke', {
    lease_id: guardFailClaim.data?.lease_id,
    fencing_token: guardFailFence,
    reason: 'the right to execute is withdrawn; the run can no longer speak',
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters });
  await run.transition('guard-fail.fail', {
    task: await run.readTask(T.guardFail),
    toState: 'FAILED',
    actor: alpha.owner,
    actorKind: 'human_owner',
    reason: 'the run produced no admissible result and its right was withdrawn',
  });

  // --- 15. a live right, and the tenancy / sandbox refusals -----------------
  await readyTask('claimed.ready', T.claimed);
  const claimedClaim = await run.call('claimed.claim', 'tasks.claim', {
    task_id: T.claimed,
    adapter_id: A.collector,
    expected_revision: (await run.readTask(T.claimed)).revision,
    ttl_ms: 60000,
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters, transport: transportFor(A.collector) });
  recordClaimEdge(run, 'claimed.claim', claimedClaim, T.claimed, P.scheduler, 'scheduler');

  // The in-flight task of the second tenant: claimed, started, dispatched, and
  // deliberately LEFT RUNNING. Its lease and its run are live at the end of the
  // board, which is the honest end state for work that is still in flight.
  await readyTask('running.ready', T.running, BETA);
  await grantTask('running.grant', T.running, BETA);
  const runningExec = transportFor(A.tick);
  const runningClaim = await run.call('running.claim', 'tasks.claim', {
    task_id: T.running,
    adapter_id: A.tick,
    expected_revision: (await run.readTask(T.running, BETA)).revision,
    ttl_ms: 60000,
  }, { principal: beta.scheduler, actorKind: 'scheduler', workspaceId: BETA, adapters: betaAdapters, transport: runningExec });
  recordClaimEdge(run, 'running.claim', runningClaim, T.running, P.scheduler, 'scheduler');
  const runningFence = Number(runningClaim.data?.lease?.fencing_token ?? 0);
  await run.transition('running.to-running', {
    task: await run.readTask(T.running, BETA),
    toState: 'RUNNING',
    workspaceId: BETA,
    actor: beta.producer,
    actorKind: 'adapter',
    reason: 'the pilot executor acknowledged the handoff under the current fence',
    extra: { fencing_token: runningFence },
  });
  const runningStart = await run.call('running.start', 'execution.start', { task_id: T.running, adapter_id: A.tick }, {
    principal: beta.producer, actorKind: 'adapter', workspaceId: BETA, adapters: betaAdapters, transport: runningExec,
  });
  const runningRunId = runningStart.data?.run?.run_id ?? (await run.observeRuns(BETA, T.running))[0]?.run_id ?? null;
  if (runningStart.data?.run) run.dispatched.push({ run_id: runningRunId, task_id: T.running, adapter_id: A.tick });
  await run.call('running.dispatch', 'outbox.dispatch', { workspace_id: BETA }, {
    principal: beta.scheduler, actorKind: 'scheduler', workspaceId: BETA, adapters: betaAdapters,
    transport: outboxShim(run, runningExec, runningRunId),
  });

  await run.call('tenancy.cross-workspace-read', 'tasks.get', { task_id: T.tick }, {
    principal: alpha.reviewer, actorKind: 'human_reviewer', workspaceId: BETA,
  });
  await run.call('tenancy.outsider-read', 'tasks.get', { task_id: T.done }, {
    principal: principalOf(P.outsider, 'reviewer', ALPHA), actorKind: 'human_reviewer', workspaceId: ALPHA,
  });
  // A payload that names the authority it wants: refused as AUTH_REQUIRED
  // before any state is touched.
  await run.call('tenancy.forged-authority-argument', 'tasks.transition', {
    task_id: T.ready,
    to_state: 'CANCELLED',
    expected_revision: (await run.readTask(T.ready)).revision,
    reason: 'a payload that tries to assert the owner identity',
    principal_id: P.owner,
    actor_kind: 'human_owner',
  }, { principal: alpha.scheduler, actorKind: 'scheduler', workspaceId: ALPHA, adapters: alphaAdapters });

  // --- 16. the closing reads -----------------------------------------------
  const tasksList = await run.call('read.tasks-list', 'tasks.list', { workspace_id: ALPHA, limit: 50 }, {
    principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA,
  });
  const auditList = await run.call('read.audit-list', 'audit.list', { workspace_id: ALPHA, limit: 200 }, {
    principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA,
  });
  const outboxList = await run.call('read.outbox-list', 'outbox.list', { workspace_id: ALPHA }, {
    principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA,
  });
  await run.call('read.adapters-list', 'adapters.list', { workspace_id: ALPHA }, {
    principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA,
  });
  const finalCapabilities = await run.call('read.capabilities-final', 'capabilities', { workspace_id: ALPHA }, {
    principal: alpha.owner, actorKind: 'human_owner', workspaceId: ALPHA, adapters: alphaAdapters,
  });

  // --- 17. the final state table, read back through the boundary ------------
  const finalStates = [];
  for (const taskId of ALL_TASKS) {
    const workspaceId = taskId === T.tick || taskId === T.running ? BETA : ALPHA;
    const task = await run.readTask(taskId, workspaceId);
    finalStates.push({
      task_id: taskId,
      workspace_id: workspaceId,
      state: task.state,
      revision: task.revision,
      priority: task.priority,
      active_lease: task.active_lease_id === null ? 'none' : 'held',
      fencing_token: task.fencing_token === null ? 'none' : 'held',
    });
  }

  return {
    run,
    created,
    finalStates,
    hostProbe,
    capabilities: capabilities.data?.capabilities ?? null,
    finalCapabilities: finalCapabilities.data?.capabilities ?? null,
    planDigest: plan.data?.decision ? canonicalDigest(plan.data.decision) : null,
    tickDecisionDigest: tick.data?.decision ? canonicalDigest(tick.data.decision) : null,
    observedCounts: {
      tasks_listed: tasksList.data?.tasks?.length ?? 0,
      audit_rows: auditList.data?.audit?.length ?? 0,
      outbox_rows: outboxList.data?.outbox?.length ?? 0,
    },
  };
}

// ===========================================================================
// Verification: the expected-value table
// ===========================================================================
function verifyExpectations(calls) {
  const observed = new Map();
  const mismatches = [];
  for (const call of calls) {
    if (observed.has(call.step)) {
      mismatches.push({ kind: 'duplicate-step', step: call.step, observed: call.outcome, code: call.code ?? null });
      continue;
    }
    observed.set(call.step, call);
  }
  let matched = 0;
  for (const expectation of EXPECTED) {
    const call = observed.get(expectation.step);
    if (call === undefined) {
      mismatches.push({ kind: 'missing-step', step: expectation.step, expected: expectation.outcome });
      continue;
    }
    if (call.outcome !== expectation.outcome) {
      mismatches.push({
        kind: 'wrong-outcome',
        step: expectation.step,
        expected: expectation.outcome,
        observed: call.outcome,
        code: call.code ?? null,
        message: call.message ?? null,
        detail: call.detail ?? null,
      });
      continue;
    }
    if (expectation.outcome === 'REFUSE') {
      if (call.typed !== true) {
        mismatches.push({ kind: 'untyped-refusal', step: expectation.step, code: call.code ?? null });
        continue;
      }
      if (!ERROR_CODES.includes(call.code)) {
        mismatches.push({ kind: 'code-outside-closed-set', step: expectation.step, code: call.code });
        continue;
      }
      if (!expectation.codes.includes(call.code)) {
        mismatches.push({ kind: 'wrong-refusal-code', step: expectation.step, expected: expectation.codes, observed: call.code, detail: call.detail ?? null });
        continue;
      }
    }
    matched += 1;
  }
  const declared = new Set(EXPECTED.map((entry) => entry.step));
  for (const call of calls) {
    if (/^read\./.test(call.step)) continue;
    if (!declared.has(call.step)) {
      mismatches.push({ kind: 'undeclared-step', step: call.step, observed: call.outcome, code: call.code ?? null });
    }
  }
  return { ok: mismatches.length === 0, mismatches, matched, expected: EXPECTED.length };
}

function verifyFinalStates(finalStates) {
  const problems = [];
  const seen = new Set();
  for (const row of finalStates) {
    const expectedState = EXPECTED_FINAL_STATES[row.task_id];
    if (expectedState === undefined) problems.push({ kind: 'undeclared-task', task_id: row.task_id });
    else if (row.state !== expectedState) {
      problems.push({ kind: 'wrong-final-state', task_id: row.task_id, expected: expectedState, observed: row.state });
    }
    seen.add(row.state);
  }
  for (const state of BOARD_STATES) {
    if (!seen.has(state)) problems.push({ kind: 'uncovered-state', state });
  }
  const doneRows = finalStates.filter((row) => row.state === 'DONE');
  if (doneRows.length !== 1) problems.push({ kind: 'done-count', observed: doneRows.length, expected: 1 });
  return { ok: problems.length === 0, problems, coveredStates: BOARD_STATES.filter((state) => seen.has(state)) };
}

function verifyGuards(transitions) {
  const names = frozenGuardNames();
  const exercised = new Map();
  for (const row of transitions) {
    if (row.guard === null) continue;
    const current = exercised.get(row.guard) ?? { accepted: 0, refused: 0 };
    if (row.decision === 'ACCEPT') current.accepted += 1;
    else current.refused += 1;
    exercised.set(row.guard, current);
  }
  const missing = names.filter((name) => !exercised.has(name));
  return {
    ok: missing.length === 0,
    guards: names,
    coverage: Object.fromEntries(names.map((name) => [name, exercised.get(name) ?? { accepted: 0, refused: 0 }])),
    missing,
  };
}

function verifyExternalEffects(run) {
  // One crossing per dispatched run, none for a refused/escalated dispatch.
  const crossings = Object.fromEntries([...run.transportEffects.entries()].sort());
  const total = Object.values(crossings).reduce((sum, value) => sum + value, 0);
  const dispatched = run.dispatched.length;
  return {
    ok: total <= dispatched,
    crossings,
    totalCrossings: total,
    dispatchedRuns: dispatched,
    duplicateCrossings: Math.max(0, total - dispatched),
  };
}

// ===========================================================================
// Metrics — every one of them names what it actually measured
// ===========================================================================
function computeMetrics({ finalStates, run, expectations, guards, effects, tasksListed }) {
  const acceptedCalls = run.calls.filter((call) => call.outcome === 'ACCEPT');
  const refusedCalls = run.calls.filter((call) => call.outcome === 'REFUSE');
  const humanCalls = run.calls.filter((call) => ['human_owner', 'human_reviewer', 'deterministic_gate'].includes(call.actor_kind));
  const runs = run.collected;
  const succeeded = runs.filter((row) => row.outcome === 'SUCCEEDED');
  const settledTotal = run.settled.reduce((sum, row) => sum + row.amount, 0);
  const spendTotal = runs.reduce((sum, row) => sum + row.spend, 0);
  const durations = runs.map((row) => row.duration_ms);
  // The intervention span: injected-clock steps between a task's first READY
  // transition and the next human command after it. The clock advances exactly
  // STEP_MS per boundary call, so this is a CALL-COUNT proxy for operator
  // attention and never a measured human latency.
  // The first ACCEPTED transition of each task into READY, taken from the
  // recorded transitions (which carry the task id), not from a step name.
  const readySteps = new Map();
  for (const edge of run.transitions) {
    if (edge.to_state !== 'READY' || edge.decision !== 'ACCEPT') continue;
    if (!readySteps.has(edge.task_id)) readySteps.set(edge.task_id, edge.step);
  }
  const humanStepIndex = run.calls
    .map((call, index) => ({ call, index }))
    .filter(({ call }) => ['human_owner', 'human_reviewer', 'deterministic_gate'].includes(call.actor_kind) && call.command !== 'tasks.list');
  const spans = [];
  for (const row of finalStates) {
    const readyStep = readySteps.get(row.task_id);
    if (readyStep === undefined) continue;
    const readyIndex = run.calls.findIndex((call) => call.step === readyStep);
    const next = humanStepIndex.find(({ index }) => index > readyIndex);
    if (next === undefined) continue;
    spans.push({ task_id: row.task_id, final_state: row.state, steps: next.index - readyIndex });
  }
  const unexpectedRefusals = expectations.mismatches.filter(
    (entry) => entry.kind === 'wrong-outcome' || entry.kind === 'wrong-refusal-code' || entry.kind === 'untyped-refusal',
  ).length;

  return {
    acceptedTaskQualityProxy: {
      value: runs.length === 0 ? null : Number((succeeded.length / runs.length).toFixed(6)),
      numerator: succeeded.length,
      denominator: runs.length,
      measurementKind: 'engineering_proxy',
      empirical: false,
      definition: 'share of COLLECTED ExecutionResults whose recorded outcome is SUCCEEDED',
      limitation: 'a PROCESS measure of the board (a run was collected and its outcome recorded). It is NOT a measure of research quality, correctness or human acceptance: no independent reviewer judged any output in this run, and a SUCCEEDED result is evidence, not correctness.',
    },
    passAt1: {
      value: finalStates.length === 0 ? null : Number(((finalStates.length - expectations.mismatches.length) / finalStates.length).toFixed(6)),
      numerator: finalStates.length - expectations.mismatches.length,
      denominator: finalStates.length,
      measurementKind: 'engineering_proxy',
      empirical: false,
      definition: 'share of tasks that reached their preregistered final state on the first attempt, with no expectation-table mismatch anywhere in the run',
      limitation: 'measures determinism and state-machine convergence of the board, not task success in the field',
    },
    interventionTime: {
      valueMs: spans.length === 0 ? null : spans.reduce((sum, row) => sum + row.steps * STEP_MS, 0),
      tasksMeasured: spans.length,
      stepMs: STEP_MS,
      measurementKind: 'engineering_proxy',
      empirical: false,
      definition: 'sum over tasks of (injected-clock steps from the task\'s first accepted READY transition to the next authenticated human command) x STEP_MS',
      limitation: 'the clock is injected and advances one fixed step per boundary call, so this is a CALL-COUNT proxy for operator attention. It is NOT a measured human response time.',
    },
    cost: {
      settled: Number(settledTotal.toFixed(6)),
      executorReportedSpend: Number(spendTotal.toFixed(6)),
      currency: 'USD',
      measurementKind: 'board_recorded_synthetic',
      empirical: false,
      definition: 'sum of the amounts committed through budget.settle, next to the spend the scripted executor reported in ExecutionResult.measurements',
      limitation: 'both numbers come from the fixture. No provider was called, no money moved, and this is NOT a measured cost of any real work.',
    },
    latency: {
      reportedMs: durations,
      p50Ms: durations.length === 0 ? null : [...durations].sort((a, b) => a - b)[Math.floor(durations.length / 2)],
      maxMs: durations.length === 0 ? null : Math.max(...durations),
      measurementKind: 'engineering_proxy',
      empirical: false,
      definition: 'the duration_ms the scripted executor wrote into each collected ExecutionResult.measurements',
      limitation: 'these are fixture literals, NOT wall-clock latencies of any process.',
    },
    regressionRate: {
      value: run.calls.length === 0 ? null : Number((unexpectedRefusals / run.calls.length).toFixed(6)),
      unexpectedRefusals,
      totalCalls: run.calls.length,
      measurementKind: 'engineering_proxy',
      empirical: false,
      definition: 'share of boundary calls whose outcome contradicted the preregistered expectation table (a refused call the table did not name, or an accepted call it declared refused)',
      limitation: 'a regression against a FIXTURE expectation table. It says nothing about behaviour on inputs this harness never generated.',
    },
    activity: {
      acceptedCalls: acceptedCalls.length,
      refusedCalls: refusedCalls.length,
      humanCalls: humanCalls.length,
      transitions: run.transitions.length,
      guardsExercised: Object.values(guards.coverage).filter((row) => row.accepted + row.refused > 0).length,
      externalEffectCrossings: effects.totalCrossings,
      tasksListed: tasksListed,
      finalStatesByState: Object.fromEntries(BOARD_STATES.map((state) => [state, finalStates.filter((row) => row.state === state).map((row) => row.task_id)])),
      terminalTasks: finalStates.filter((row) => ['DONE', 'FAILED', 'CANCELLED'].includes(row.state)).length,
    },
  };
}

// ===========================================================================
// The canonical projection (identity-free) and the record
// ===========================================================================
function canonicalProjection({ run, finalStates, expectations, guards, effects, metrics, probeProjection }) {
  return {
    harness: HARNESS_VERSION,
    calls: run.calls.map((call) => ({
      step: call.step,
      command: call.command,
      outcome: call.outcome,
      code: call.code ?? null,
      typed: call.typed ?? true,
      actor_kind: call.actor_kind,
      actor: call.actor,
      revision: call.revision ?? null,
      replayed: call.replayed === true,
    })),
    transitions: run.transitions,
    finalStates,
    created: run.calls.filter((call) => call.command === 'tasks.create').map((call) => call.step).sort(),
    // The run_id of a collected result is IDENTITY-BOUND (it comes from the
    // id factory, whose offset differs between the two runs), so the canonical
    // projection carries the outcome facts without it. The full rows, with their
    // run ids, stay in the evidence record outside the compared projection.
    collected: run.collected.map(({ task_id, outcome, spend, duration_ms }) => ({ task_id, outcome, spend, duration_ms })),
    settled: run.settled,
    escalations: run.escalations,
    dispatchedTasks: run.dispatched.map((row) => row.task_id).sort(),
    effects: { totalCrossings: effects.totalCrossings, duplicateCrossings: effects.duplicateCrossings },
    expectations: { ok: expectations.ok, matched: expectations.matched, expected: expectations.expected, mismatches: expectations.mismatches },
    guards,
    metrics,
    probes: probeProjection,
    findings: run.findings,
  };
}

function probeProjectionOf(probeSuite) {
  return {
    version: probeSuite.version,
    status: probeSuite.status,
    counters: probeSuite.counters,
    totals: probeSuite.totals,
    registry: probeSuite.registry,
    probes: probeSuite.probes.map((row) => ({
      family: row.family, probe: row.probe, status: row.status, counter: row.counter, counted: row.counted,
    })),
    notRun: (probeSuite.hardGates?.notRun ?? []).map((row) => ({ probe: row.probe, family: row.family, code: row.code ?? null })),
  };
}

function buildRecord({ scenario, probeSuite, probeProjection, identity }) {
  const { run, finalStates, created, hostProbe } = scenario;
  const expectations = verifyExpectations(run.calls);
  const guards = verifyGuards(run.transitions);
  const finalStateCheck = verifyFinalStates(finalStates);
  const effects = verifyExternalEffects(run);
  const metrics = computeMetrics({
    finalStates, run, expectations, guards, effects, tasksListed: scenario.observedCounts.tasks_listed,
  });
  const canonical = canonicalProjection({ run, finalStates, expectations, guards, effects, metrics, probeProjection });
  const canonicalDigestValue = canonicalDigest(canonical);
  const hardGates = {
    counters: probeProjection.counters,
    ok: HARD_GATE_COUNTERS.every((counter) => probeProjection.counters[counter] === 0),
  };
  const violations = [];
  if (!expectations.ok) violations.push(`EXPECTATION_TABLE:${expectations.mismatches.length}`);
  if (!finalStateCheck.ok) violations.push(`FINAL_STATES:${finalStateCheck.problems.length}`);
  if (!guards.ok) violations.push(`GUARDS_MISSING:${guards.missing.join('|')}`);
  if (!effects.ok) violations.push(`DUPLICATE_EXTERNAL_EFFECTS:${effects.duplicateCrossings}`);
  if (!hardGates.ok) violations.push(`HARD_GATES:${HARD_GATE_COUNTERS.filter((counter) => probeProjection.counters[counter] !== 0).join('|')}`);
  if (probeSuite.status === 'BLOCKED_SAFETY') violations.push('PROBES_BLOCKED_SAFETY');
  if (run.calls.some((call) => call.outcome === 'REFUSE' && call.typed !== true)) violations.push('UNTYPED_REFUSAL');
  if (finalStates.filter((row) => row.state === 'DONE').length !== 1) violations.push('DONE_INDEPENDENCE');

  const record = {
    schemaVersion: 1,
    ticket: 'S2-007',
    harness: HARNESS_VERSION,
    role: 'deterministic offline acceptance run of the live Agent Board through commands.execute',
    run: identity.letter,
    status: violations.length === 0 ? 'ENGINEERING_GATES_OK' : 'REVISE',
    statusSemantics: 'ENGINEERING_GATES_OK means every deterministic engineering gate of THIS harness held. It is not an A-MVP PASS, not a real-adapter PASS and not an assurance result.',
    identity,
    spec: {
      revision: SPEC_REVISION,
      contractVersion: '1.0.0',
      executionVersion: 'veritas.execution/1.0.0',
      adapterVersion: 'veritas.adapter/1.0.0',
    },
    honestStatus: {
      realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
      engineeringStatus: violations.length === 0 ? 'GATES_OK' : 'GATES_VIOLATED',
      assuranceStatus: 'NOT_MEASURED',
      aMvpStatus: 'NOT_CLAIMED',
      note: 'No genuinely installed, genuinely distinct executor backs any run in this record. Every execution is a scripted veritas.adapter/1.0.0 test transport, and fixture or scripted evidence never upgrades NOT_RUN_REAL_ADAPTER.',
    },
    hostProbe: {
      installedCandidates: hostProbe.filter((row) => row.installed === true).map((row) => row.adapter_id),
      probed: hostProbe.map((row) => ({ adapter_id: row.adapter_id, installed: row.installed })),
    },
    boundary: {
      entryPoint: 'src/lib/agentboard/commands.mjs#execute',
      note: 'Every mutation and every read in this run went through execute(). The store was used only to OBSERVE committed run rows, never to drive a decision.',
      commandsExercised: [...new Set(run.calls.map((call) => call.command))].sort(),
      refusalCodes: [...new Set(run.calls.filter((call) => call.outcome === 'REFUSE').map((call) => call.code))].sort(),
    },
    inputs: {
      workspaces: { [ALPHA]: ROOTS[ALPHA], [BETA]: ROOTS[BETA] },
      isolationProfile: PROVEN_PROFILE,
      blockedIsolationProfile: BLOCKED_PROFILE,
      principals: Object.values(P),
      principalGrants: CAP,
      adapters: [A.collector, A.bulk, A.timeout, A.blocked, A.tick].map((adapterId) => ({
        adapter_id: adapterId,
        workspace_id: adapterId === A.tick ? BETA : ALPHA,
        adapter_kind: 'test',
        real_adapter_provenance: 'NOT_RUN_REAL_ADAPTER',
      })),
      adapterRegistrationClaimRefused: {
        adapter_id: A.realClaim,
        claimed: 'REAL_ADAPTER_AVAILABLE',
        refused_code: run.calls.find((call) => call.step === 'discovery.real-claim-registration')?.code ?? null,
      },
      tasks: created,
      taskDigests: { brief: d(DIGEST_CHAR.brief), policy: d(DIGEST_CHAR.policy), manifest: d(DIGEST_CHAR.manifest) },
      clock: { base: CLOCK_BASE, step_ms: STEP_MS, ticks: run.tick, source: 'injected' },
      idFactory: { kind: 'injected prefixed monotonic counter', offset: identity.id_offset },
      store: {
        backend: 'InMemoryAgentBoardStore',
        reason: 'this harness is the offline, non-database acceptance tier; the PostgreSQL gate is a separate run',
      },
    },
    discovery: {
      executionEnabled: scenario.capabilities?.executionEnabled ?? null,
      realAdapterStatus: scenario.capabilities?.realAdapterStatus ?? null,
      approvalEnabled: scenario.capabilities?.approvalEnabled ?? null,
      mode: scenario.capabilities?.mode ?? null,
      states: scenario.capabilities?.states ?? null,
      commandCount: scenario.capabilities?.commands?.length ?? null,
      contractDigests: scenario.capabilities?.contractDigests ?? null,
      finalExecutionEnabled: scenario.finalCapabilities?.executionEnabled ?? null,
      finalRealAdapterStatus: scenario.finalCapabilities?.realAdapterStatus ?? null,
      dispatchPlanDigest: scenario.planDigest,
      dispatchTickDecisionDigest: scenario.tickDecisionDigest,
    },
    expectedValueTable: {
      declared: EXPECTED.length,
      matched: expectations.matched,
      ok: expectations.ok,
      mismatches: expectations.mismatches,
      source: 'preregistered in scripts/s2-007-run.mjs, derived from the frozen transition table and the closed error set',
    },
    finalStates,
    finalStateCheck,
    guardCoverage: guards,
    externalEffects: effects,
    transitions: run.transitions,
    escalations: run.escalations,
    metrics,
    probes: probeProjection,
    hardGates,
    findings: run.findings,
    violations,
    reproduce: {
      command: 'npm run s2-007:run',
      node: '>=22',
      deterministic: true,
      determinismNotes: [
        'no Date.now(), no Math.random(), no bare new Date() and no process.hrtime in this file',
        'every instant is injected; the store clock and the boundary `now` share one counter',
        'every identifier comes from one prefixed monotonic factory whose only per-run difference is its offset',
        'no wall clock, no pid, no temp path and no host fact is written into the identity-free projection',
      ],
      excludedFromComparison: [
        'run_id / executor_id / store seed / id-factory offset: the identities that make run A and run B different runs',
        'every generated lease / run / transition / event / outbox identifier, for the same reason',
      ],
    },
    limits: [
      'No real adapter ran: the only execution boundary model is a scripted veritas.adapter/1.0.0 test transport (NOT_RUN_REAL_ADAPTER).',
      'No PostgreSQL: the store tier exercised is the in-memory twin; the database gate, the cross-process claim race and the crash/restart replay are separate runs, and probes.runAllProbes reports the race NOT_RUN_DB here.',
      'Every metric in this record is an engineering proxy over contract documents and an injected clock. None is an empirical human-quality, cost or latency measurement.',
      'assuranceStatus is NOT_MEASURED: nothing here establishes accuracy, calibration, SLO or production readiness.',
      'A metric named acceptedTaskQualityProxy is NOT a human-quality metric and is never presented as one.',
    ],
  };
  return { record, canonical, canonicalDigestValue, violations, expectations, guards, effects, hardGates, finalStateCheck, metrics };
}

// ===========================================================================
// A / B comparison
// ===========================================================================
function compareRuns({ a, b }) {
  const failures = [];
  const identityA = a.record.identity;
  const identityB = b.record.identity;
  if (identityA.run_id === identityB.run_id) failures.push('IDENTITY_RUN_ID_NOT_DISTINCT');
  if (identityA.executor_id === identityB.executor_id) failures.push('IDENTITY_EXECUTOR_NOT_DISTINCT');
  if (identityA.store_seed === identityB.store_seed) failures.push('IDENTITY_SEED_NOT_DISTINCT');
  if (identityA.id_offset === identityB.id_offset) failures.push('IDENTITY_OFFSET_NOT_DISTINCT');
  if (a.canonical.effects.totalCrossings !== b.canonical.effects.totalCrossings) failures.push('IDENTITY_EFFECT_COUNTERS_DIFFER');
  if (a.canonicalDigestValue !== b.canonicalDigestValue) failures.push('CANONICAL_DIGEST_MISMATCH');
  if (a.violations.length > 0) failures.push(`RUN_A_VIOLATIONS:${a.violations.join('|')}`);
  if (b.violations.length > 0) failures.push(`RUN_B_VIOLATIONS:${b.violations.join('|')}`);
  // The falsifiability requirement: A == B is NOT a pass on its own, so the
  // comparison also re-checks each run against the preregistered table and
  // against the canonical final-state table.
  const tableEntries = [
    ...a.canonical.expectations.mismatches.map((entry) => ({ run: 'A', ...entry })),
    ...b.canonical.expectations.mismatches.map((entry) => ({ run: 'B', ...entry })),
  ];
  if (tableEntries.length > 0) failures.push('EXPECTED_VALUE_TABLE_MISMATCH');
  if (!a.record.finalStateCheck.ok) failures.push('RUN_A_FINAL_STATES');
  if (!b.record.finalStateCheck.ok) failures.push('RUN_B_FINAL_STATES');
  if (a.canonical.guards.missing.length > 0) failures.push(`RUN_A_GUARDS_MISSING:${a.canonical.guards.missing.join('|')}`);
  if (b.canonical.guards.missing.length > 0) failures.push(`RUN_B_GUARDS_MISSING:${b.canonical.guards.missing.join('|')}`);
  if (JSON.stringify(a.canonical.probes.counters) !== JSON.stringify(b.canonical.probes.counters)) failures.push('PROBE_COUNTERS_DIFFER');
  if (JSON.stringify(a.canonical.metrics) !== JSON.stringify(b.canonical.metrics)) failures.push('METRICS_DIFFER');
  return {
    ok: failures.length === 0,
    failures,
    tableEntries,
    identityDistinct: failures.filter((failure) => failure.startsWith('IDENTITY_')).length === 0,
    canonicalDigestsEqual: a.canonicalDigestValue === b.canonicalDigestValue,
  };
}

// ===========================================================================
// main
// ===========================================================================
async function main() {
  const args = parseArgs(process.argv);
  if (args['evidence-dir']) EVIDENCE_DIR = path.resolve(ROOT, String(args['evidence-dir']));

  const identities = [
    { letter: 'A', runId: 's2-007-run-a', executorId: 'exec-s2-007-a', idOffset: 0, storeSeed: 's2-007-run-a' },
    { letter: 'B', runId: 's2-007-run-b', executorId: 'exec-s2-007-b', idOffset: 500, storeSeed: 's2-007-run-b' },
  ];

  const results = [];
  for (const identity of identities) {
    const scenario = await runScenario(identity);
    const probeSuite = await runAllProbes({ now: CLOCK_BASE });
    const probeProjection = probeProjectionOf(probeSuite);
    const identityBlock = {
      letter: identity.letter,
      run_id: identity.runId,
      executor_id: identity.executorId,
      store_seed: identity.storeSeed,
      id_offset: identity.idOffset,
    };
    const built = buildRecord({ scenario, probeSuite, probeProjection, identity: identityBlock });
    const target = identity.letter === 'A' ? 's2-007-run-a.json' : 's2-007-run-b.json';
    writeEvidence(target, built.record);
    results.push({ ...built, written: path.relative(ROOT, path.join(EVIDENCE_DIR, target)) });
  }

  const [a, b] = results;
  const comparison = compareRuns({ a, b });
  const comparisonRecord = {
    schemaVersion: 1,
    ticket: 'S2-007',
    role: 'two independent runs over the same canonical input, compared against a preregistered expected-value table',
    ok: comparison.ok,
    status: comparison.ok ? 'COMPARISON_OK' : 'COMPARISON_FAILED',
    statusSemantics: 'COMPARISON_OK means: the two runs differ in identity, agree on every identity-free fact, and BOTH independently match the preregistered table. It is not an A-MVP PASS and not an assurance result.',
    honestStatus: {
      realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
      engineeringStatus: comparison.ok ? 'GATES_OK' : 'GATES_VIOLATED',
      assuranceStatus: 'NOT_MEASURED',
      aMvpStatus: 'NOT_CLAIMED',
    },
    method: {
      identityDifferences: ['run_id', 'executor_id', 'store seed', 'id-factory offset (every generated lease/run/transition id therefore differs)'],
      comparedFacts: 'an identity-free canonical projection: every call with its decision and refusal code, every transition with the guard read out of the frozen table, every final state and revision, the expected-value result, the guard coverage, the external-effect counters, every metric and the probe projection',
      falsifiability: 'A == B is necessary and NOT sufficient. Each run is additionally re-checked against the preregistered expected-value table and the canonical final-state table, so two identically wrong runs are a FAILURE, not a pass.',
      determinism: 'fixed injected clock, fixed prefixed id counters, no wall clock, no pid, no temp path in the compared projection',
    },
    runs: {
      A: {
        run_id: a.record.identity.run_id,
        executor_id: a.record.identity.executor_id,
        store_seed: a.record.identity.store_seed,
        id_offset: a.record.identity.id_offset,
        canonical_digest: a.canonicalDigestValue,
        status: a.record.status,
        violations: a.violations,
        evidence: a.written,
      },
      B: {
        run_id: b.record.identity.run_id,
        executor_id: b.record.identity.executor_id,
        store_seed: b.record.identity.store_seed,
        id_offset: b.record.identity.id_offset,
        canonical_digest: b.canonicalDigestValue,
        status: b.record.status,
        violations: b.violations,
        evidence: b.written,
      },
    },
    identityDistinct: comparison.identityDistinct,
    canonicalDigestsEqual: comparison.canonicalDigestsEqual,
    expectedValueTable: {
      declared: EXPECTED.length,
      matchedA: a.expectations.matched,
      matchedB: b.expectations.matched,
      okA: a.expectations.ok,
      okB: b.expectations.ok,
      mismatches: comparison.tableEntries,
    },
    finalStates: { okA: a.finalStateCheck.ok, okB: b.finalStateCheck.ok, table: a.canonical.finalStates },
    guardCoverage: { okA: a.guards.ok, okB: b.guards.ok, coverage: a.canonical.guards.coverage },
    hardGates: { okA: a.hardGates.ok, okB: b.hardGates.ok, counters: a.canonical.probes.counters },
    probes: {
      statusA: a.canonical.probes.status,
      statusB: b.canonical.probes.status,
      totals: a.canonical.probes.totals,
      notRun: a.canonical.probes.notRun,
    },
    metrics: a.metrics,
    failures: comparison.failures,
    limits: a.record.limits,
  };
  const writtenComparison = writeEvidence('s2-007-comparison.json', comparisonRecord);

  const ok = comparison.ok;
  process.stdout.write(`${JSON.stringify({
    ok,
    comparison: {
      ok: comparison.ok,
      failures: comparison.failures,
      canonicalDigestsEqual: comparison.canonicalDigestsEqual,
      identityDistinct: comparison.identityDistinct,
    },
    runs: results.map((result) => ({
      run: result.record.identity.letter,
      status: result.record.status,
      canonical_digest: result.canonicalDigestValue,
      expectations: `${result.expectations.matched}/${result.expectations.expected}`,
      guards: `${Object.values(result.guards.coverage).filter((row) => row.accepted + row.refused > 0).length}/${result.guards.guards.length}`,
      hard_gates_ok: result.hardGates.ok,
      violations: result.violations,
      evidence: result.written,
    })),
    probes: { status: a.canonical.probes.status, totals: a.canonical.probes.totals, counters: a.canonical.probes.counters },
    finalStates: a.canonical.finalStates.map((row) => `${row.task_id}=${row.state}`),
    realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
    assuranceStatus: 'NOT_MEASURED',
    aMvpStatus: 'NOT_CLAIMED',
    written: [...results.map((result) => result.written), writtenComparison],
  }, null, 2)}\n`);
  process.exit(ok ? 0 : 1);
}

await main();
