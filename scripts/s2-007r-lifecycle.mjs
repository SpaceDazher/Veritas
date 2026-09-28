#!/usr/bin/env node
// S2-007R LIFECYCLE HARNESS (issue SpaceDazher/Veritas#45).
//
// WHAT THIS FILE IS
// -----------------
// The part of the real pilot that does NOT go through a task edge: the process
// lifecycle arms of A-MVP-04 (cancel, timeout, an external SIGKILL of the child's
// process group) and the two configuration surfaces of SPEC §4, both measured
// against REAL installed executors and REAL child processes.
//
// WHAT IT IS NOT, STATED BEFORE ANYTHING ELSE
// --------------------------------------------
//   * It is not a run. No board command is called from this file: there is no
//     task, no lease, no grant, no outbox row and no `agentboard_*` write. A
//     transport can be driven without a board, and that is exactly what this
//     file does, because the task edges are refused on this checkout (see
//     `BOARD_EDGE_GATE` below and the driver record's `claim-refused`).
//   * It lifts no status. Nothing here can move `realAdapterStatus`,
//     `assuranceStatus` or `aMvpStatus`; those are the evidence writer's and the
//     verifier's to decide, and `evidence-writer.mjs` is the only module that may
//     read a real crossing and decide what it means.
//   * It does not claim OS isolation. Every child here is an ordinary host
//     process under `sbx-host-unisolated-v1` with `isolation_observed:false`, and
//     the absence-of-controls record is quoted by digest, exactly as the run
//     records do.
//
// BOARD_EDGE_GATE (measured, not assumed)
// ---------------------------------------
// `policy.assertSandboxExecutable('sbx-host-unisolated-v1')` throws
// BLOCKED_SANDBOX, and `policy.assertAdapterCoversTask` calls it for EVERY task
// edge (src/lib/agentboard/policy.mjs:1263). The floor tier is therefore
// refused on READY->CLAIMED, CLAIMED->RUNNING and RUNNING->IN_REVIEW, so
// `tasks.claim` on a floor-tier task is refused `BLOCKED_SANDBOX` and no governed
// run exists on this checkout. The gate that IS live,
// `policy.assertLiveExecutionAuthorized(profileId, {authorization, now})`, admits
// the same profile with the named permit (measured: tier HOST_UNISOLATED,
// authorization_id aut-hu-s2-007r-01), and the two disagree. Both measurements
// are reproduced in `boardGate()` below so the report is a measurement and not a
// claim about someone else's code.
//
// THE THREE ARMS, AND WHAT EACH ONE IS FOR
// -----------------------------------------
//   cancel   the caller asks the transport to stop a live child. The transport
//            signals the POSIX process GROUP, waits a bounded grace, escalates to
//            SIGKILL, and proves the result with the SHIPPED observer
//            (src/lib/identity/process-observer.mjs). The three-way verdict
//            (TERMINATED | SURVIVORS_REMAINING | UNVERIFIED) is recorded
//            verbatim and `survivors:0` is never reported without a TERMINATED.
//   timeout  the granted budget's own timeout_ms elapses, so the kill comes from
//            the transport's timer rather than from a caller. Same proof.
//   sigkill  the PARENT signals the group directly, with no call into the
//            transport at all, and then asks the transport what happened. This is
//            the "crossing without an acknowledgement" shape: a third party
//            killed the work and the boundary has to account for it.
//
// After each arm a LATE CALLBACK is attempted (a checkpoint and a status with a
// deliberately stale `expected_sequence`, and a second cancel). Every one of
// them is expected to be refused with a typed error and the code is recorded; a
// late write that is ACCEPTED would be a fence failure and is reported as one.
//
// THE CONFIGURATION SURFACES
// --------------------------
// SPEC §4 compares configuration A (the host's default skill/context surface)
// with configuration B (the limited build) on one executor. This file MEASURES
// that axis against the transport as built, by running one real crossing per
// (provider, surface) with an unresolvable model id — so a real process, a real
// argv, a real non-zero exit and no billable token — and then comparing the argv
// the transport actually executed. The surface is a required, validated argument
// (issue #45, round 3), so the two arms differ in exactly that and nothing else;
// the result is reported whatever it is, and a provider whose two ends select
// the same argv is EXCLUDED from the comparison with that reason rather than
// reported as "no difference observed".
//
// CLI
// ---
//   --help                         this text, and nothing else: no arm runs, no
//                                   record is written
//   --arms cancel,timeout,sigkill   which lifecycle arms to run (default: all)
//   --surfaces codex,pi             which providers get the surface measurement
//   --model <provider/id>          the pi model (default: the operator's pin)
//   --out <path>                    the record to write (default
//                                   results/s2-007r/lifecycle-record.json)
//   --workspace-root <path>         the containment root (default
//                                   /tmp/veritas-s2-007r-ws/lifecycle)
//
// EXIT CODES
//   0  every arm that ran produced its proof and no hard gate tripped
//   1  a hard gate tripped (a survivor was left unaccounted for, a proof was
//      missing, a late callback was accepted, a credential-shaped literal was
//      found in the record)
//   3  a precondition could not be established (no executor, no permit, no
//      workspace root); always with a typed error code
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createProcessObserver } from '../src/lib/identity/process-observer.mjs';
import { SANDBOX_HOST_UNISOLATED } from '../src/lib/identity/sandbox-profiles.mjs';
import { ID_PREFIXES } from '../src/lib/agentboard/constants.mjs';
import { isBoardError, toBoardError, redact } from '../src/lib/agentboard/errors.mjs';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { createRealRegistration } from '../src/lib/executors/registration.mjs';
import { createRealExecutorTransport } from '../src/lib/executors/transport.mjs';
import { REAL_EXECUTOR_VERSION } from '../src/lib/executors/constants.mjs';
import { buildUnisolatedAuthorization } from './s2-007r-authorization.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TICKET = 'S2-007R';
const ISSUE = 'SpaceDazher/Veritas#45';
const HARNESS_VERSION = 's2-007r-lifecycle-v1';
const FLOOR_PROFILE = SANDBOX_HOST_UNISOLATED.profile_id;
const UNISOLATED_AUTHORIZATION = buildUnisolatedAuthorization();
const WORKSPACE_ID = 'ws-s2007r-lifecycle';
const PRINCIPAL_ID = 'prn-s2007r-producer';
const DEFAULT_MODEL = 'openrouter/amazon/nova-lite-v1';
// The model id the surface measurement uses: unresolvable on purpose, so a real
// process really starts, really answers with a non-zero exit, and no token is
// billed. Measured on this host: pi exits 1 with a client-side `Model "..."
// not found`, codex exits 1 with a structured `status:400`.
const SURFACE_MODEL = 'veritas-s2-007r-nonexistent/no-such-model';
const SURFACE_PROMPT = 'Say PING.';
// The prompt the three lifecycle arms use. It is a real question about the real
// fixture, so a child that is not cancelled in time produces a real answer and a
// real cost; the arms are about stopping it, and the record publishes whatever
// the executor reported either way.
const LIFECYCLE_PROMPT = 'Read src/calc.js in this workspace and reply with only the number of lines it has.';
const TIMEOUT_MS = 1_500;
const ARM_CANCEL_GRACE_MS = 300;
const ARM_SETTLE_MS = 4_000;
const CANCEL_AFTER_MS = 900;
const REAP_CHECK_MS = 2_000;

// --- the injected clock ------------------------------------------------------
// No Date.now(), no bare new Date(), no Math.random(): the board instant below is
// a counter over a fixed base, and the only real time source in this file is
// process.hrtime.bigint(), used to MEASURE a wall clock for the record.
const CLOCK_BASE = '2026-09-26T09:00:00.000Z';
const STEP_MS = 1_000;
let clockTicks = 0;
/** The injected clock's own reading: a Date, advancing one STEP_MS per call. */
const clockNow = () => new Date(Date.parse(CLOCK_BASE) + (clockTicks += 1) * STEP_MS);
/** The same instant as the wire form the frozen schemas ask for. */
const now = () => clockNow().toISOString();
const injectedClock = () => ({ now: clockNow, call: clockNow, get: clockNow });

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
const digest = (value) => (typeof value === 'string' || Buffer.isBuffer(value) ? `sha256:${createHash('sha256').update(value).digest('hex')}` : `sha256:${canonicalDigest(value)}`);
const displayPath = (target) => {
  const relative = path.relative(ROOT, target);
  return relative.startsWith('..') ? target : relative;
};
const isPlainRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

/** The same credential-shaped literals scripts/check-public-artifacts.mjs scans. */
const CREDENTIAL_PATTERNS = Object.freeze([
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /gh[pousr]_[A-Za-z0-9]{30,}/,
  /github_pat_[A-Za-z0-9_]{40,}/,
  /sk-(?:proj-)?[A-Za-z0-9_-]{35,}/,
  /postgres(?:ql)?:\/\/[^\s/:]+:[^\s@]+@/,
]);

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 2; i < argv.length; i += 1) {
    if (!argv[i].startsWith('--')) { args._.push(argv[i]); continue; }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) args[argv[i].slice(2)] = null;
    else { args[argv[i].slice(2)] = next; i += 1; }
  }
  return args;
}

function resolveOnPath(name) {
  for (const directory of (process.env.PATH ?? '').split(path.delimiter).filter((entry) => entry.length > 0)) {
    const candidate = path.join(directory, name);
    try {
      if (fs.statSync(candidate).isFile()) { fs.accessSync(candidate, fs.constants.X_OK); return candidate; }
    } catch { /* keep looking; never guess */ }
  }
  return null;
}

function prepareWorkspaceRoot(requested) {
  const absolute = path.resolve(requested);
  fs.mkdirSync(absolute, { recursive: true, mode: 0o700 });
  const real = fs.realpathSync(absolute);
  if (process.platform !== 'win32') fs.chmodSync(real, 0o700);
  const stat = fs.statSync(real);
  const mode = stat.mode & 0o777;
  if (process.platform !== 'win32' && mode !== 0o700) {
    throw new Error(`WORKSPACE_ROOT_MODE:${mode.toString(8)}`);
  }
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  if (process.platform !== 'win32' && uid !== null && stat.uid !== uid) {
    throw new Error(`WORKSPACE_ROOT_NOT_OWNED:${stat.uid}`);
  }
  let segments = '';
  for (const segment of real.split('/').filter((item) => item.length > 0)) {
    segments += `/${segment}`;
    if (fs.lstatSync(segments).isSymbolicLink()) throw new Error(`WORKSPACE_ROOT_SYMLINK:${segments}`);
  }
  return { absolute: real, mode: `0${mode.toString(8)}`, owner_uid: stat.uid, symlink_free: true, source: 'INJECTED_NOT_REGISTRY' };
}

/**
 * The mint counter for the transport's id factory. Deterministic, never random.
 * The prefixes are the frozen `ID_PREFIXES` of src/lib/agentboard/constants.mjs:
 * a mint that does not carry the kind's prefix is refused with
 * ID_FACTORY_SHAPE, so the table is read from the boundary, not retyped.
 */
function makeIdFactory(namespace) {
  const counters = new Map();
  return (kind) => {
    const next = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, next);
    const prefix = ID_PREFIXES[kind];
    if (typeof prefix !== 'string') {
      throw new Error(`ID_FACTORY_SHAPE_UNKNOWN_KIND:${String(kind)}`);
    }
    return `${prefix}${namespace}-${next.toString(36).padStart(4, '0')}`;
  };
}

/** The permit, adjudicated by the board's own gate, measured live. */
function boardGate() {
  // Imported lazily so the measurement below is a MEASUREMENT of this checkout's
  // policy module and not a restatement of a comment.
  const policy = globalThis.__veritasPolicy;
  const live = policy.assertLiveExecutionAuthorized(FLOOR_PROFILE, {
    authorization: UNISOLATED_AUTHORIZATION,
    now: () => '2026-09-26T10:00:00.000Z',
  });
  let perEdge = null;
  try {
    policy.assertSandboxExecutable(FLOOR_PROFILE);
    perEdge = { admitted: true, code: null };
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'BLOCKED_SANDBOX');
    perEdge = { admitted: false, code: typed.code, message: redact(String(typed.message ?? typed)).slice(0, 200) };
  }
  return {
    floor_profile: FLOOR_PROFILE,
    floor_tier: SANDBOX_HOST_UNISOLATED.tier,
    live_gate: {
      function: 'policy.assertLiveExecutionAuthorized(profileId, {authorization, now})',
      admitted: live.tier === 'HOST_UNISOLATED',
      tier: live.tier,
      authorization_id: live.authorization?.authorization_id ?? null,
      authorization_body_digest: live.authorization?.body_digest ?? null,
    },
    per_edge_gate: {
      function: 'policy.assertSandboxExecutable(profileId), called for EVERY task edge by policy.assertAdapterCoversTask (src/lib/agentboard/policy.mjs:1263)',
      ...perEdge,
    },
    consequence: perEdge.admitted === true
      ? 'both gates admit the floor tier, so a governed run on this profile is possible'
      : 'the per-edge gate refuses the floor tier, so READY->CLAIMED, CLAIMED->RUNNING and RUNNING->IN_REVIEW are all refused BLOCKED_SANDBOX and no governed run exists on this checkout. The two gates disagree: the live gate admits the tier with the named permit, the per-edge gate admits no tier that isExecutableSandboxProfile reports, and the floor tier is deliberately NOT in that set.',
    the_two_agree: perEdge.admitted === (live.tier === 'ISOLATED'),
    fix_owner: 'src/lib/agentboard/policy.mjs is a frozen target of the S2-007/S2-002 units and is digest-bound in evidence/frozen-manifest.json; this harness does not edit it and this pilot does not ship a patch for it',
  };
}

function buildRegistration({ provider, adapterId, clock }) {
  return createRealRegistration({
    provider,
    adapterId,
    workspaceId: WORKSPACE_ID,
    principalId: PRINCIPAL_ID,
    displayName: `${provider} CLI (installed on this host)`,
    health: 'healthy',
    declaredCapabilities: ['task.read', 'artifact.write', 'source.read', 'code.write'],
    declaredTools: ['tool:fs.read', 'tool:fs.write', 'tool:test.run'],
    sandboxProfileId: FLOOR_PROFILE,
    clock,
    unisolatedExecutionAuthorization: UNISOLATED_AUTHORIZATION,
    realRunEvidence: null,
  });
}

function buildRequest({ provider, taskId, leaseId, fence, rootRef, timeoutMs, model }) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    request_id: `xer-${taskId}`,
    idempotency_key: digest(`lifecycle:${taskId}`).slice(7),
    task_id: taskId,
    workspace_id: WORKSPACE_ID,
    brief_digest: digest({ kind: 'lifecycle-brief', taskId }),
    policy_digest: digest({ kind: 'lifecycle-policy', profile: FLOOR_PROFILE }),
    manifest_digest: digest({ kind: 'lifecycle-manifest' }),
    principal_id: PRINCIPAL_ID,
    granted_scope: ['task.read', 'artifact.write'],
    allowed_tools: ['tool:fs.read'],
    workspace_ref: {
      workspace_id: WORKSPACE_ID,
      root_ref: rootRef,
      isolation_profile_id: FLOOR_PROFILE,
      sandbox_profile_digest: digest({ profile: FLOOR_PROFILE }),
      read_only_paths: [],
    },
    budget_grant: {
      currency: 'USD',
      task_limit: 0.5,
      campaign_limit: 2,
      day_limit: 2,
      timeout_ms: timeoutMs,
      granted_by: 'prn-s2007r-owner',
      granted_at: now(),
    },
    deadline: null,
    lease_id: leaseId,
    fencing_token: fence,
    adapter_id: `adr-${provider}-local`,
    issued_at: now(),
  };
}

/**
 * The surface every transport this harness builds is given. It is a REQUIRED,
 * VALIDATED argument (issue #45, round 3): a transport that is not told which
 * context surface it was handed cannot be one half of a comparison, and a
 * defaulted surface would make every unmarked run a silent B cell.
 *
 * The three lifecycle arms (cancel, timeout, sigkill) are not a comparison and
 * take no part in one, but their argv must still be reproducible, so they are
 * built with the provider-documented default end: `A`, which passes no
 * suppression flag at all. The surface arms below pass their own end explicitly.
 */
const LIFECYCLE_CONFIGURATION = 'A';

// What `--help` prints. Kept as data so the guard and the header comment above
// cannot drift apart.
const USAGE_TEXT = [
  's2-007r-lifecycle.mjs — the three process-lifecycle arms and the configuration-surface',
  'measurement, against REAL installed executors and REAL child processes.',
  '',
  '  --help                         this text, and nothing else',
  '  --arms cancel,timeout,sigkill   which lifecycle arms to run (default: all)',
  '  --surfaces codex,pi             which providers get the surface measurement',
  '  --model <provider/id>          the pi model (default: the operator\'s pin)',
  '  --out <path>                    the record to write (default results/s2-007r/lifecycle-record.json)',
  '  --workspace-root <path>         the containment root (default /tmp/veritas-s2-007r-ws/lifecycle)',
  '',
  'It is not a run: it calls no board command, opens no lease and writes no board row.',
  'It DOES spawn real executors, so a real model call is possible and a real child can be',
  'killed. Exit codes: 0 all clauses observed, 1 a hard gate or defect, 3 nothing ran.',
].join('\n');

// The same closed terminal set the transport and the frozen event contract use.
const TERMINAL_EVENT_TYPES = new Set(['COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'UNKNOWN']);

function makeTransport({ provider, binary, root, projectDir, evidenceDir, model, prompt, timeoutMs, ids, grant, configuration = LIFECYCLE_CONFIGURATION }) {
  return createRealExecutorTransport({
    provider,
    registration: buildRegistration({ provider, adapterId: `adr-${provider}-local`, clock: injectedClock() }),
    clock: injectedClock(),
    ids,
    executorPath: binary,
    evidenceDir,
    workspaceRoots: [root],
    realpath: fs.realpathSync,
    prompt,
    model,
    configuration,
    grant: grant ?? { capabilities: ['task.read', 'artifact.write'], tools: ['tool:fs.read'] },
    unisolatedExecutionAuthorization: UNISOLATED_AUTHORIZATION,
    cancelGraceMs: ARM_CANCEL_GRACE_MS,
    observerSettleMs: ARM_SETTLE_MS,
  });
}

/** The parent-side, independent view of one pid. Not the transport's own report. */
function parentPidState(observer, pid) {
  if (!Number.isInteger(pid) || pid <= 0) return { pid, alive: null, note: 'no pid was published for this run' };
  let alive = false;
  try { process.kill(pid, 0); alive = true; } catch (error) { alive = error?.code === 'EPERM'; }
  return {
    pid,
    alive,
    method: 'process.kill(pid, 0) from the PARENT of the transport, i.e. this harness process',
    note: alive ? 'the pid was still resolvable at the moment of this read' : 'the pid was no longer resolvable at the moment of this read',
  };
}

async function drainEvents(transport, { runId, taskId, leaseId, fence, max = 96 }) {
  const events = [];
  for (let round = 0; round < max; round += 1) {
    let status;
    try {
      status = await transport.status({ run_id: runId, task_id: taskId, lease_id: leaseId, fencing_token: fence, at: now() });
    } catch (error) {
      const typed = isBoardError(error) ? error : toBoardError(error, 'MALFORMED_RESULT');
      events.push({ refused: true, code: typed.code, message: redact(String(typed.message ?? typed)).slice(0, 200) });
      break;
    }
    if (!isPlainRecord(status) || typeof status.sequence !== 'number') break;
    const row = { sequence: status.sequence, event_type: status.event_type, outcome: status.outcome ?? null };
    // The TERMINAL event's own `termination` block is kept (issue #45, round 3):
    // a deadline this transport enforced is a kill, and the proof it published
    // travels on that event. Dropping the payload is what let this record report
    // a timeout arm with no proof while the transport had published one.
    if (TERMINAL_EVENT_TYPES.has(String(status.event_type)) && isPlainRecord(status.payload?.termination)) {
      row.termination = status.payload.termination;
    }
    events.push(row);
    if (['COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'UNKNOWN'].includes(status.event_type)) break;
  }
  return events;
}

async function collect(transport, { runId, taskId, leaseId, fence }) {
  try {
    const collected = await transport.collect_result({
      run_id: runId, task_id: taskId, lease_id: leaseId, fencing_token: fence, at: now(),
    });
    const document = isPlainRecord(collected) && isPlainRecord(collected.result) ? collected.result : collected;
    return {
      submitted: true,
      outcome: isPlainRecord(document) ? (document.outcome ?? null) : null,
      sequence: isPlainRecord(document) ? (document.sequence ?? null) : null,
      error: isPlainRecord(document) && isPlainRecord(document.error)
        ? { code: document.error.code ?? null, message: redact(String(document.error.message ?? '')).slice(0, 200) }
        : null,
      measurements: isPlainRecord(document) ? (document.measurements ?? null) : null,
      document: document,
    };
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'MALFORMED_RESULT');
    return {
      submitted: false,
      refused: true,
      code: typed.code,
      message: redact(String(typed.message ?? typed)).slice(0, 200),
    };
  }
}

function readRawLogs(transport) {
  return (transport.rawLogs ?? []).map((entry) => ({
    path: displayPath(entry.path ?? ''),
    bytes: entry.bytes ?? null,
    sha256: entry.sha256 ?? null,
  }));
}

/**
 * The argv with the parts that differ per RUN folded out, so two surfaces are
 * compared on what they actually select.
 *
 * Without this the comparison is a false positive waiting to happen: the codex
 * argv carries `--output-last-message <evidence>/<run_id>/raw/last-message.txt`,
 * so an A run and a B run differ by the run id alone and the digest would say
 * "the surfaces differ" when only the file name did (measured before this
 * normalisation: codex A and B hashed differently for exactly that reason). The
 * RAW digest is kept beside the normalised one so both are auditable.
 *
 * The fold list is the transport's own rule, re-declared here: the resolved
 * project directory, the per-invocation evidence root, the injected containment
 * root and the run id — nothing else. Longest first, so the project copy inside
 * the workspace root is folded before the root that contains it. The harness
 * recomputes the digest from the bytes it re-read and compares it with the one
 * the transport published; two implementations of one rule is a check, and one
 * is a claim.
 */
function normaliseArgv(argv, folds) {
  if (argv === null) return null;
  const ordered = [...folds]
    .filter((fold) => typeof fold?.from === 'string' && fold.from.length > 0)
    .sort((left, right) => String(right.from).length - String(left.from).length);
  return argv.map((item) => {
    let value = String(item);
    for (const fold of ordered) value = value.split(String(fold.from)).join(String(fold.to));
    return path.sep === '\\' ? value.split('\\').join('/') : value;
  });
}

/** The per-arm fold list, in the transport's order and with the same labels. */
function surfaceFolds({ runId, evidenceDir, projectDir, root }) {
  const realProject = (() => { try { return fs.realpathSync(projectDir); } catch { return projectDir; } })();
  return [
    { from: projectDir, to: '<project_root>', kind: 'per-run project copy' },
    { from: realProject, to: '<project_root>', kind: 'per-run project copy (realpath)' },
    { from: evidenceDir, to: '<evidence_dir>', kind: 'per-invocation evidence root' },
    { from: root, to: '<workspace_root>', kind: 'injected containment root' },
    { from: runId, to: '<run_id>', kind: 'per-run identity' },
  ];
}

function readArgvFromRawLog(paths) {
  for (const entry of paths) {
    try {
      const document = JSON.parse(fs.readFileSync(entry.path, 'utf8'));
      if (Array.isArray(document.invocation?.argv)) return document.invocation.argv.map((item) => redact(String(item)));
    } catch { /* the next log, then none */ }
  }
  return null;
}

/**
 * The argv evidence the TRANSPORT published in its own raw process log: the
 * exact argv, the argv with the per-run values folded out, BOTH digests, and the
 * configuration axis it actually selected (issue #45, round 3).
 *
 * This harness keeps its own `normaliseArgv` above and re-computes the
 * normalised digest independently; `argv_digest_agrees` is the two computations
 * compared. A surface difference that only one of them can see is not a finding.
 */
function readArgvEvidenceFromRawLog(paths) {
  for (const entry of paths) {
    try {
      const document = JSON.parse(fs.readFileSync(entry.path, 'utf8'));
      const invocation = document.invocation;
      if (!isPlainRecord(invocation) || !Array.isArray(invocation.argv)) continue;
      return {
        argv: invocation.argv.map((item) => redact(String(item))),
        argv_normalised: Array.isArray(invocation.argv_normalised) ? invocation.argv_normalised.map((item) => redact(String(item))) : null,
        argv_digest_raw: invocation.argv_digest_raw ?? null,
        argv_digest_normalised: invocation.argv_digest_normalised ?? null,
        argv_normalisation: isPlainRecord(invocation.argv_normalisation) ? invocation.argv_normalisation : null,
        configuration: invocation.configuration ?? null,
        configuration_name: invocation.configuration_name ?? null,
        configuration_surface_flags: Array.isArray(invocation.configuration_surface_flags) ? [...invocation.configuration_surface_flags] : [],
        configuration_note: invocation.configuration_note ?? null,
        configuration_axis: isPlainRecord(invocation.configuration_axis) ? invocation.configuration_axis : null,
      };
    } catch { /* the next log, then none */ }
  }
  return null;
}

function measureSpend(measurements) {
  if (!isPlainRecord(measurements)) return { usd: null, basis: 'NO_USD_REPORTED_BY_EXECUTOR' };
  const value = Number(measurements.spend);
  return {
    usd: Number.isFinite(value) ? value : null,
    basis: Number.isFinite(value) && value > 0 ? 'EXECUTOR_REPORTED_USD' : 'NO_USD_REPORTED_BY_EXECUTOR',
    note: 'the executor\'s own reported figure; nothing here is priced from a published rate card',
  };
}

// ---------------------------------------------------------------------------
// The three lifecycle arms
// ---------------------------------------------------------------------------
async function lifecycleArm({ arm, provider, binary, root, projectDir, evidenceDir, model, observer }) {
  const ids = makeIdFactory(`lc-${arm}-${provider}`);
  const runId = `run-lifecycle-${arm}-${provider}`;
  const taskId = `abt-lc-${arm}-${provider}`;
  const leaseId = `lse-lc-${arm}-${provider}`;
  const fence = 1;
  const started = process.hrtime.bigint();
  const record = {
    arm,
    provider,
    adapter_id: `adr-${provider}-local`,
    run_id: runId,
    board_commands_called: 0,
    governed: false,
    is_a_run: false,
    profile_id: FLOOR_PROFILE,
    isolation_observed: false,
    prompt: LIFECYCLE_PROMPT,
    model,
    started_at: now(),
    events: [],
    terminal_event: null,
    cancel_proof: null,
    process_before_signal: null,
    process_after_signal: null,
    parent_sightings: [],
    late_callbacks: [],
    result: null,
    spend: { usd: null, basis: 'UNMEASURED' },
    raw_logs: [],
    argv: null,
    error: null,
    wall_ms: null,
    what_this_establishes: '',
  };
  let transport;
  try {
    transport = makeTransport({
      provider, binary, root, projectDir,
      evidenceDir: path.join(evidenceDir, arm, provider),
      model,
      prompt: LIFECYCLE_PROMPT,
      // The timeout arm is the only one that shortens the granted budget: the
      // kill must come from the transport's own timer, not from a caller.
      timeoutMs: arm === 'timeout' ? TIMEOUT_MS : 300_000,
      ids,
    });
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'AGENT_UNAVAILABLE');
    record.error = { code: typed.code, message: redact(String(typed.message ?? typed)).slice(0, 300) };
    return record;
  }
  const request = buildRequest({
    provider, taskId, leaseId, fence,
    rootRef: 'project',
    timeoutMs: arm === 'timeout' ? TIMEOUT_MS : 300_000,
    model,
  });
  try {
    const accepted = await transport.start(request, { run_id: runId });
    if (isPlainRecord(accepted)) {
      record.events.push({ sequence: accepted.sequence, event_type: accepted.event_type, outcome: accepted.outcome ?? null });
    }
    record.process_before_signal = transport.processObservation;
    record.parent_sightings.push({ when: 'after start() returned', ...parentPidState(observer, transport.processObservation?.pid) });

    if (arm === 'cancel') {
      // Wait for the child to be genuinely alive before asking for a stop: a
      // cancel issued to a process that already exited is not a cancel, and the
      // transport refuses it as one.
      await sleep(CANCEL_AFTER_MS);
      record.parent_sightings.push({ when: `after ${CANCEL_AFTER_MS} ms`, ...parentPidState(observer, transport.processObservation?.pid) });
      try {
        // The canonical arguments of `cancel` (src/lib/executors/transport.mjs
        // CANONICAL_ARGS/REQUIRED_ARGS): run_id, task_id, lease_id,
        // fencing_token, reason, at. A missing one is NEEDS_INPUT
        // BOUNDARY_ARGUMENT_MISSING, never a silent no-op.
        const cancelled = await transport.cancel({
          run_id: runId, task_id: taskId, lease_id: leaseId, fencing_token: fence,
          reason: 'S2-007R lifecycle arm: a bounded pilot stop on a real child', at: now(),
        });
        record.cancel_call = { accepted: true, event: isPlainRecord(cancelled) ? { sequence: cancelled.sequence, event_type: cancelled.event_type } : null };
      } catch (error) {
        const typed = isBoardError(error) ? error : toBoardError(error, 'MALFORMED_RESULT');
        record.cancel_call = { accepted: false, code: typed.code, message: redact(String(typed.message ?? typed)).slice(0, 300) };
      }
      record.cancel_proof = transport.cancelProof;
    } else if (arm === 'sigkill') {
      // NO call into the transport: the parent signals the process GROUP itself,
      // which is the shape a crashed or externally killed executor leaves behind.
      await sleep(CANCEL_AFTER_MS);
      const observation = transport.processObservation;
      const pgid = observation?.pgid ?? null;
      record.parent_sightings.push({ when: `after ${CANCEL_AFTER_MS} ms`, ...parentPidState(observer, observation?.pid) });
      const signal = { attempted: false, target: 'process group', pgid, method: 'process.kill(-pgid, "SIGKILL") from the harness process' };
      try {
        if (Number.isInteger(pgid) && pgid > 0) {
          process.kill(-pgid, 'SIGKILL');
          signal.attempted = true;
          signal.sent = 'SIGKILL';
        } else {
          signal.sent = null;
          signal.reason = 'the transport published no process group to signal';
        }
      } catch (error) {
        signal.attempted = true;
        signal.sent = null;
        signal.error = redact(String(error?.message ?? error)).slice(0, 200);
      }
      record.external_signal = signal;
      await sleep(ARM_SETTLE_MS);
    } else {
      // timeout: the transport's own timer fires; nothing is called from here.
      record.wait_note = `no call was made after start(): the granted timeout_ms (${TIMEOUT_MS}) is the transport's own deadline`;
      await sleep(TIMEOUT_MS + ARM_SETTLE_MS);
    }

    record.process_after_signal = transport.processObservation;
    // THE PROOF, FROM WHATEVER KILLED THE CHILD (issue #45, round 3). A cancel is
    // not the only thing that kills: the transport's own deadline does too, and
    // that kill carries the same three-way proof. So the proof is read from the
    // transport's own surface for EVERY arm, and the terminal event's own
    // `termination` block is published beside it. Reading it only on the cancel
    // arm is what made this record say "no termination proof was published" for a
    // timeout that had published one.
    record.cancel_proof = transport.cancelProof ?? null;
    const terminalRow = record.events.filter((row) => TERMINAL_EVENT_TYPES.has(String(row.event_type))).slice(-1)[0] ?? null;
    record.termination_on_terminal_event = isPlainRecord(terminalRow?.termination)
      ? terminalRow.termination
      : null;
    if (record.cancel_proof === null && record.termination_on_terminal_event === null) {
      record.proof_absent_reason = arm === 'sigkill'
        ? 'the child was killed by a signal this transport never sent, so it ran no kill of its own and there is no kill of ITSS to prove; the boundary\'s job here is to reconcile the crossing it cannot acknowledge'
        : 'the transport published no termination proof and the terminal event carried no `termination` block';
    }
    record.parent_sightings.push({ when: 'after the arm settled', ...parentPidState(observer, record.process_after_signal?.pid) });
    record.events = await drainEvents(transport, { runId, taskId, leaseId, fence });
    record.terminal_event = record.events.filter((row) => typeof row.event_type === 'string').slice(-1)[0] ?? null;
    record.result = await collect(transport, { runId, taskId, leaseId, fence });
    // The terminal row is re-read after the drain, so the proof is taken from the
    // event that actually ended the run rather than from the arm's shape.
    const drainedTerminal = record.events.filter((row) => TERMINAL_EVENT_TYPES.has(String(row.event_type))).slice(-1)[0] ?? null;
    if (isPlainRecord(drainedTerminal?.termination)) record.termination_on_terminal_event = drainedTerminal.termination;
    if (record.cancel_proof === null) record.cancel_proof = transport.cancelProof ?? null;
    record.spend = measureSpend(record.result?.measurements);
    // The reaping check. The shipped observer's verdict is taken at the moment
    // the kill settles, and a process that is dead but not yet reaped is still in
    // the process table. So the SAME pid is read again a couple of seconds later
    // from the parent, and both readings are published: the observer's answer is
    // never overwritten, it is only put next to an independent later one.
    await sleep(REAP_CHECK_MS);
    record.reap_check = {
      when: `${REAP_CHECK_MS} ms after the arm settled`,
      ...parentPidState(observer, record.process_after_signal?.pid),
      why: 'a killed child that has not been reaped is still in the process table, so a survivor count taken at the instant of the kill can name a process that is already gone; this later reading is the independent one',
    };
    // THE TWO READINGS, COMPARED (issue #45, round 3). The transport waits for the
    // child's exit before it accounts, so the observer's survivor set is not a
    // reaping race in the parent. What it CAN still be is the observer's own
    // memoised /proc snapshot (src/lib/identity/process-observer.mjs#procTable,
    // SNAPSHOT_TTL_MS), which is up to a few tens of milliseconds stale. So this
    // harness states, in one place, whether the observer and the parent agree
    // about the SAME pid, and it never overwrites either answer.
    {
      const observerVerdict = record.cancel_proof?.verdict ?? null;
      const observerSurvivors = Array.isArray(record.cancel_proof?.remaining_process_ids)
        ? record.cancel_proof.remaining_process_ids
        : null;
      const parentAlive = record.reap_check?.alive ?? null;
      const observerSaysGone = observerVerdict === 'TERMINATED';
      const parentSaysGone = parentAlive === false;
      record.readings = {
        observer: {
          when: 'at the accounting point, after the child exit was observed',
          verdict: observerVerdict,
          survivors: record.cancel_proof?.survivors ?? null,
          remaining_process_ids: observerSurvivors,
          snapshot_staleness: record.cancel_proof?.observer_read_staleness ?? null,
        },
        parent: {
          when: record.reap_check?.when ?? null,
          pid: record.reap_check?.pid ?? null,
          alive: parentAlive,
          method: record.reap_check?.method ?? null,
        },
        agree: observerVerdict === null ? null : (observerSaysGone === parentSaysGone),
        independent_reading_contradicts_the_observer: observerVerdict === null ? null : (!observerSaysGone && parentSaysGone),
        if_they_disagree: 'the observer answer is KEPT as the transport\'s proof; the parent-side reading is published beside it. Neither is overwritten, and the clause is NOT_RUN with the observer\'s exact reason: a proof this transport cannot stand behind is not rounded up to a pass.',
        root_cause_of_the_staleness: 'the shipped observer memoises its /proc snapshot for SNAPSHOT_TTL_MS (src/lib/identity/process-observer.mjs:191), so a survivor count taken inside that window of a reap can name a pid that is already gone. Measured on this host with no model involved: after the child\'s exit event had fired in the parent, listExisting still reported the pid alive and 1.5 s later reported it gone, while process.kill(pid, 0) answered ESRCH throughout.',
      };
    }

    // --- the late callbacks -------------------------------------------------
    // `status` is a READ and accepting it is correct, so it is recorded as a
    // read and never counted as a fence gate. The two WRITES a late adapter
    // would actually send are a checkpoint and a second cancel, and both carry a
    // deliberately stale `expected_sequence` where the call allows one. Both must
    // be refused; an accepted write is a fence failure and is a hard gate.
    const lateCalls = [
      ['checkpoint with a stale expected_sequence', 'write', () => transport.checkpoint({
        run_id: runId, task_id: taskId, lease_id: leaseId, fencing_token: fence,
        expected_sequence: 1,
        brief_digest: request.brief_digest,
        workspace_digest: digest({ workspace: request.workspace_ref }),
        tool_digest: digest(request.allowed_tools),
        at: now(),
      })],
      ['second cancel after the arm settled', 'write', () => transport.cancel({
        run_id: runId, task_id: taskId, lease_id: leaseId, fencing_token: fence,
        reason: 'S2-007R late-callback probe', at: now(),
      })],
      ['status after the arm settled', 'read', () => transport.status({
        run_id: runId, task_id: taskId, lease_id: leaseId, fencing_token: fence, at: now(),
      })],
    ];
    for (const [label, kind, call] of lateCalls) {
      try {
        const value = await call();
        record.late_callbacks.push({
          probe: label,
          kind,
          accepted: true,
          note: kind === 'write'
            ? 'ACCEPTED: a late WRITE was not refused, which is a fence failure and is reported as a hard gate'
            : 'accepted: this is a read, and delivering the terminal event to a reader is what it is for',
          value: isPlainRecord(value) ? { sequence: value.sequence ?? null, event_type: value.event_type ?? null } : String(value).slice(0, 120),
        });
      } catch (error) {
        const typed = isBoardError(error) ? error : toBoardError(error, 'MALFORMED_RESULT');
        record.late_callbacks.push({
          probe: label, kind, accepted: false, code: typed.code,
          message: redact(String(typed.message ?? typed)).slice(0, 200),
        });
      }
    }
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'AGENT_UNAVAILABLE');
    record.error = { code: typed.code, message: redact(String(typed.message ?? typed)).slice(0, 300) };
  }
  record.raw_logs = readRawLogs(transport);
  record.argv = readArgvFromRawLog(record.raw_logs);
  record.wall_ms = Math.round(Number((process.hrtime.bigint() - started) / 1000n) / 1000);
  record.errors_reported_by_transport = (transport.errors ?? []).map((row) => ({
    code: row.code ?? null, class: row.class ?? null, message: redact(String(row.message ?? '')).slice(0, 200),
  }));
  record.evidence = typeof transport.evidenceRecord === 'function' ? (() => {
    const evidence = transport.evidenceRecord();
    return evidence === null ? null : {
      run_id: evidence.run_id,
      provider: evidence.executor.provider,
      binary_path: displayPath(evidence.executor.binary_path),
      binary_sha256: evidence.executor.binary_sha256,
      raw_process_log_sha256: evidence.raw_process_log_sha256,
      exit_status: evidence.exit_status,
      exit_observed: evidence.exit_observed,
    };
  })() : null;
  record.what_this_establishes = arm === 'cancel'
    ? 'a real installed executor was really spawned as a POSIX process-group leader, a caller really asked the boundary to stop it, the group was really signalled, and the shipped process observer really accounted for the result'
    : arm === 'timeout'
      ? 'a real installed executor really ran under a granted deadline and really was stopped by the transport\'s own timer, with the same group proof'
      : 'a real installed executor\'s process group really was killed by a third party with no call into the boundary, and the boundary really accounted for the crossing it could not acknowledge';
  return record;
}

// ---------------------------------------------------------------------------
// The configuration-surface measurement
// ---------------------------------------------------------------------------
async function surfaceArm({ provider, binary, root, projectDir, evidenceDir, model, configuration }) {
  const ids = makeIdFactory(`sf-${provider}-${String(configuration).toLowerCase()}`);
  const runId = `run-surface-${provider}-${String(configuration).toLowerCase()}`;
  const taskId = `abt-sf-${provider}-${String(configuration).toLowerCase()}`;
  const leaseId = `lse-sf-${provider}-${String(configuration).toLowerCase()}`;
  const record = {
    provider,
    configuration,
    requested_surface: configuration,
    run_id: runId,
    board_commands_called: 0,
    governed: false,
    is_a_run: false,
    isolation_observed: false,
    model: SURFACE_MODEL,
    model_rationale: 'unresolvable on purpose: a real process, a real argv and a real non-zero exit, with no billable token',
    argv: null,
    argv_digest: null,
    exit_status: null,
    outcome: null,
    raw_logs: [],
    spend: { usd: null, basis: 'UNMEASURED' },
    events: [],
    error: null,
    note: 'the surface is a required, validated argument of the transport (issue #45, round 3): this arm names the end of the axis it is measuring, and the transport publishes the flags it selected plus BOTH argv digests in its own raw process log. The normalised digest is what the comparison below asserts on.',
  };
  let transport;
  try {
    transport = makeTransport({
      provider, binary, root, projectDir,
      evidenceDir: path.join(evidenceDir, 'surface', provider, String(configuration).toLowerCase()),
      model: SURFACE_MODEL,
      prompt: SURFACE_PROMPT,
      timeoutMs: 120_000,
      ids,
      configuration,
    });
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'AGENT_UNAVAILABLE');
    record.error = { code: typed.code, message: redact(String(typed.message ?? typed)).slice(0, 300) };
    return record;
  }
  const request = buildRequest({ provider, taskId, leaseId, fence: 1, rootRef: 'project', timeoutMs: 120_000, model: SURFACE_MODEL });
  try {
    const accepted = await transport.start(request, { run_id: runId });
    if (isPlainRecord(accepted)) record.events.push({ sequence: accepted.sequence, event_type: accepted.event_type, outcome: accepted.outcome ?? null });
    record.events = await drainEvents(transport, { runId, taskId, leaseId, fence: 1 });
    const collected = await collect(transport, { runId, taskId, leaseId, fence: 1 });
    record.outcome = collected.outcome ?? null;
    record.spend = measureSpend(collected.measurements);
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'AGENT_UNAVAILABLE');
    record.error = { code: typed.code, message: redact(String(typed.message ?? typed)).slice(0, 300) };
  }
  record.exit_status = transport.processObservation?.exit_code ?? null;
  record.raw_logs = readRawLogs(transport);
  // What the transport published about the argv it built, and this harness's own
  // independent normalisation of the same bytes. The two normalised digests are
  // compared below: one implementation is a claim, two agreeing ones are a check.
  const published = readArgvEvidenceFromRawLog(record.raw_logs);
  const armEvidenceDir = path.join(evidenceDir, 'surface', provider, String(configuration).toLowerCase());
  const folds = surfaceFolds({ runId, evidenceDir: armEvidenceDir, projectDir, root });
  const ownNormalised = normaliseArgv(published?.argv ?? readArgvFromRawLog(record.raw_logs), folds);
  record.argv = published?.argv ?? readArgvFromRawLog(record.raw_logs);
  record.argv_digest_raw = published?.argv_digest_raw ?? (record.argv === null ? null : digest(record.argv.join('\u0000')));
  record.argv_normalised = published?.argv_normalised ?? ownNormalised;
  record.argv_digest = published?.argv_digest_normalised ?? (ownNormalised === null ? null : digest(ownNormalised.join('\u0000')));
  record.argv_normalisation_rule = published?.argv_normalisation?.rule ?? 'this harness folded the per-run values out of the argv itself';
  record.argv_digest_recomputed_by_this_harness = ownNormalised === null ? null : digest(ownNormalised.join('\u0000'));
  record.argv_digest_agrees = record.argv_digest !== null
    && record.argv_digest === record.argv_digest_recomputed_by_this_harness;
  record.selected_configuration = published?.configuration ?? null;
  record.selected_surface_flags = published?.configuration_surface_flags ?? [];
  record.configuration_axis = published?.configuration_axis ?? null;
  return record;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
async function main() {
  const args = parseArgs(process.argv);
  // `--help` prints the usage and STOPS. This harness SPAWNS REAL EXECUTORS
  // against a real model, so a flag that ran the arms anyway would spend money and
  // overwrite a published record on a typo.
  if (args.help !== undefined || args.h !== undefined) {
    process.stdout.write(`${USAGE_TEXT}\n`);
    return 0;
  }
  const armList = args.arms === null || args.arms === undefined
    ? ['cancel', 'timeout', 'sigkill']
    : String(args.arms).split(',').map((item) => item.trim()).filter(Boolean);
  const surfaceList = args.surfaces === null || args.surfaces === undefined
    ? ['codex', 'pi']
    : String(args.surfaces).split(',').map((item) => item.trim()).filter(Boolean);
  const model = args.model === null || args.model === undefined ? DEFAULT_MODEL : String(args.model);
  const outPath = path.resolve(ROOT, args.out === null || args.out === undefined ? 'results/s2-007r/lifecycle-record.json' : String(args.out));
  const rootPath = path.resolve(ROOT, args['workspace-root'] === null || args['workspace-root'] === undefined
    ? '/tmp/veritas-s2-007r-ws/lifecycle' : String(args['workspace-root']));
  const fixture = path.resolve(ROOT, 'corpus/s2-007r/project');
  const evidenceDir = path.join(path.dirname(outPath), 'lifecycle');

  const record = {
    contractVersion: '1.0.0',
    record_kind: 's2-007r-lifecycle-record',
    ticket: TICKET,
    issue: ISSUE,
    harness: {
      version: HARNESS_VERSION,
      file: 'scripts/s2-007r-lifecycle.mjs',
      node: process.version,
      platform: `${process.platform}/${process.arch}`,
      argv: process.argv.slice(2).map((item) => redact(String(item))),
      clock_base: CLOCK_BASE,
      clock_step_ms: STEP_MS,
      clock_semantics: 'a counter over a fixed base; the only real time source in this file is process.hrtime.bigint(), used to MEASURE a wall clock, never to decide an instant',
    },
    what_this_is_not: {
      not_a_run: 'no board command is called from this file: no task, no lease, no grant, no outbox row, no agentboard_* write',
      not_a_status: 'nothing here may move realAdapterStatus, assuranceStatus or aMvpStatus; only src/lib/executors/evidence-writer.mjs reads a real crossing and decides what it means',
      not_isolation: `every child below is an ordinary host process under ${FLOOR_PROFILE} with isolation_observed:false`,
      not_a_comparison_cell: 'a SPEC §4 comparison cell is a governed run on a board row; the surface measurement below is a transport-level argv measurement and is labelled as such',
    },
    sandbox: {
      profile_id: FLOOR_PROFILE,
      tier: SANDBOX_HOST_UNISOLATED.tier,
      isolation_observed: false,
      authorization: { ...UNISOLATED_AUTHORIZATION, source: 'scripts/s2-007r-authorization.mjs#buildUnisolatedAuthorization' },
      os_controls_absence_evidence: {
        path: 'evidence/s2-007r-host-unisolated.json',
        sha256: SANDBOX_HOST_UNISOLATED.os_controls_evidence,
        note: 'the profile\'s own os_controls_evidence: the content address of the record that measured that no OS isolation control is available to a model-calling executor on this host',
      },
    },
    board_gate: null,
    workspace_root: null,
    fixture: { source: displayPath(fixture), exists: fs.existsSync(fixture) },
    arms: [],
    surfaces: [],
    surface_comparison: null,
    spend: { total_usd: null, basis: 'EXECUTOR_REPORTED_USD', rows: [] },
    hard_gates: [],
    gate_detail: [],
    findings: [],
    clauses_not_run: [],
    verdict: { status: 'NOT_RUN', exit_code: 3, hard_gates: [] },
    limitations: [],
    record_digest: null,
  };

  try {
    if (!fs.existsSync(fixture)) {
      throw new Error(`FIXTURE_ABSENT:${displayPath(fixture)}`);
    }
    // The board gate measurement, from this checkout's own policy module.
    globalThis.__veritasPolicy = await import('../src/lib/agentboard/policy.mjs');
    record.board_gate = boardGate();
    const root = prepareWorkspaceRoot(rootPath);
    record.workspace_root = { ...root, note: 'the cwd of every child below; a real, 0700, symlink-free directory under /tmp, resolved by the board\'s own workspace guard' };
    const projectDir = path.join(root.absolute, 'project');
    fs.rmSync(projectDir, { recursive: true, force: true });
    fs.cpSync(fixture, projectDir, { recursive: true });
    if (process.platform !== 'win32') fs.chmodSync(fs.realpathSync(projectDir), 0o700);

    const observer = createProcessObserver();
    record.observer = { id: observer.id, what_this_is: 'the SHIPPED process observer of src/lib/identity/process-observer.mjs, used both by the transport and by this harness for an independent parent-side reading' };

    // --- the lifecycle arms --------------------------------------------------
    for (const arm of armList) {
      for (const provider of surfaceList.length > 0 ? ['pi'] : []) {
        const binary = resolveOnPath(provider);
        if (binary === null) {
          record.arms.push({ arm, provider, error: { code: 'EXECUTOR_NOT_RESOLVABLE', message: `${provider} is not on PATH` } });
          continue;
        }
        const row = await lifecycleArm({
          arm, provider, binary, root: root.absolute, projectDir,
          evidenceDir, model: provider === 'pi' ? model : null, observer,
        });
        record.arms.push(row);
      }
    }

    // --- the configuration surfaces -----------------------------------------
    for (const provider of surfaceList) {
      const binary = resolveOnPath(provider);
      if (binary === null) {
        record.surfaces.push({ provider, error: { code: 'EXECUTOR_NOT_RESOLVABLE', message: `${provider} is not on PATH` } });
        continue;
      }
      for (const configuration of ['A', 'B']) {
        record.surfaces.push(await surfaceArm({
          provider, binary, root: root.absolute, projectDir, evidenceDir, model, configuration,
        }));
      }
    }
    const byProvider = new Map();
    for (const row of record.surfaces) {
      if (row.error !== null && row.error !== undefined) continue;
      if (!byProvider.has(row.provider)) byProvider.set(row.provider, {});
      byProvider.get(row.provider)[row.configuration] = row;
    }
    record.surface_comparison = [...byProvider.entries()].map(([provider, pair]) => {
      const a = pair.A ?? null;
      const b = pair.B ?? null;
      const same = a !== null && b !== null && a.argv_digest !== null && a.argv_digest === b.argv_digest;
      // The axis decision is the TRANSPORT's, made from the flags each end
      // selects before anything is spawned. It is read here, never re-derived,
      // and a provider whose two ends select the same flags is EXCLUDED from any
      // A/B comparison with that reason.
      const axis = a?.configuration_axis ?? b?.configuration_axis ?? null;
      const distinguishable = axis?.distinguishable === true;
      const comparable = a !== null && b !== null && !same;
      return {
        provider,
        configuration_a: a === null ? null : { run_id: a.run_id, selected_configuration: a.selected_configuration, surface_flags: a.selected_surface_flags, argv: a.argv_normalised, argv_digest_raw: a.argv_digest_raw, argv_digest: a.argv_digest, argv_digest_agrees: a.argv_digest_agrees, exit_status: a.exit_status },
        configuration_b: b === null ? null : { run_id: b.run_id, selected_configuration: b.selected_configuration, surface_flags: b.selected_surface_flags, argv: b.argv_normalised, argv_digest_raw: b.argv_digest_raw, argv_digest: b.argv_digest, argv_digest_agrees: b.argv_digest_agrees, exit_status: b.exit_status },
        argv_identical: same,
        surface_axis_exists: same === false,
        configuration_axis: axis,
        excluded_from_comparison: distinguishable ? null : `EXCLUDED_FROM_COMPARISON:${provider}:${String(axis?.reason ?? 'this provider exposes no context-surface flag, so both ends select the identical argv')}`,
        comparable,
        comparison_basis: 'the normalised argv, with the run id and the per-run evidence directory folded out; the raw digests are beside it so a reader can see that the difference was only the run-specific file name',
        both_digests_recomputed_and_agreeing: a?.argv_digest_agrees === true && b?.argv_digest_agrees === true,
        finding: same === true
          ? 'the two configurations produced IDENTICAL normalised argv, so this provider cannot take part in an A/B comparison: it would be a cell differenced against itself. That is an EXCLUSION with a reason, never a "no difference observed".'
          : 'the two configurations produced different normalised argv, so the axis exists on this provider: configuration A leaves the host default context surface alone and configuration B suppresses every surface it discovers',
        what_this_does_not_settle: 'a different argv is a different COMMAND, not a different RESULT. These two crossings used an unresolvable model id on purpose, so neither spent a token, and this record differences the commands only. Any quality, cost or latency statement needs governed runs and is the measurement set\'s work, not this harness\'s.',
      };
    });

    // --- the spend -----------------------------------------------------------
    const spendRows = [
      ...record.arms.map((row) => ({ arm: row.arm, provider: row.provider, run_id: row.run_id, usd: row.spend?.usd ?? 0, basis: row.spend?.basis ?? null })),
      ...record.surfaces.map((row) => ({ arm: 'surface', provider: row.provider, configuration: row.configuration, run_id: row.run_id, usd: row.spend?.usd ?? 0, basis: row.spend?.basis ?? null })),
    ];
    const total = spendRows.reduce((sum, row) => sum + (Number.isFinite(row.usd) ? row.usd : 0), 0);
    record.spend = {
      total_usd: Number(total.toFixed(8)),
      currency: 'USD',
      basis: 'EXECUTOR_REPORTED_USD',
      rows: spendRows,
      accounting: 'only what an executor itself reported; an executor that reports no monetary cost contributes 0 and is marked NO_USD_REPORTED_BY_EXECUTOR rather than being priced from a list',
    };

    // --- the hard gates ------------------------------------------------------
    // Two kinds, kept apart on purpose. A DEFECT is something this harness can
    // name as wrong: a late write accepted, a pid still resolvable after an
    // external kill, a kill whose crossing was reported successful, a missing raw
    // log, an arm that errored. A CLAUSE is a SPEC §7 A-MVP-04 verdict: a
    // termination proof that is not TERMINATED makes that arm NOT_RUN with this
    // exact reason, which is what the SPEC asks for and is NOT a defect of the
    // repository and NOT a pass either.
    const gates = [];
    const clauseArms = [];
    const findings = [];
    for (const row of record.arms) {
      if (row.error !== null) {
        gates.push({ kind: 'DEFECT', id: `ARM_ERRORED:${row.arm}:${row.provider}:${row.error.code}`, detail: row.error.message });
        row.clause = { observed: 'NOT_RUN', reason: `the arm errored before a proof could exist: ${row.error.code}` };
        continue;
      }
      const proof = row.cancel_proof;
      if (row.arm === 'sigkill') {
        // The external kill has no transport-side proof object; the accounting
        // requirement is that the process is gone AND the boundary refused to
        // call the crossing successful.
        const later = row.reap_check?.alive === true;
        if (later) gates.push({ kind: 'DEFECT', id: `PROCESS_SURVIVED_EXTERNAL_KILL:${row.provider}:${row.reap_check?.pid}`, detail: 'the pid was still resolvable in the independent parent-side reading two seconds after the group kill' });
        if (row.result?.outcome === 'SUCCEEDED') gates.push({ kind: 'DEFECT', id: `EXTERNAL_KILL_REPORTED_SUCCESS:${row.provider}`, detail: 'a crossing whose process group was killed by a third party was reported successful' });
        if (row.terminal_event === null) gates.push({ kind: 'DEFECT', id: `NO_TERMINAL_EVENT_AFTER_EXTERNAL_KILL:${row.provider}`, detail: 'the transport recorded no terminal event after the external kill' });
        row.clause = {
          observed: 'OBSERVED',
          external_signal: row.external_signal ?? null,
          process_resolvable_later: later,
          note: 'a third party killed the process group with no call into the boundary, and the boundary accounted for the crossing it could not acknowledge',
        };
      } else {
        if (proof === null || proof === undefined) {
          // A kill this transport performed ALWAYS publishes its proof now
          // (issue #45, round 3: a deadline that fires is a kill, and it carries
          // the same three-way proof an explicit cancel does), and this arm reads
          // the proof for every arm rather than only the cancel one. So a null
          // proof here is the transport having published nothing at all, which is
          // a CLAUSE that cannot be evidenced and a transport-level FINDING — not
          // a pass, and not a defect of this harness.
          findings.push({
            id: `TRANSPORT_PUBLISHES_NO_TERMINATION_PROOF_ON_${row.arm.toUpperCase()}`,
            detail: `the ${row.arm} arm reached outcome ${String(row.result?.outcome ?? 'none')} with no proof on the transport, on the terminal event, or in the raw process log; the group kill ran but nothing publishes the observer's verdict for it`,
            consequence: 'A-MVP-04\'s timeout clause is NOT_RUN: the proof the SPEC asks for does not exist to be quoted',
          });
          clauseArms.push(row);
          row.clause = {
            observed: 'NOT_RUN',
            reason: 'NO_TERMINATION_PROOF_PUBLISHED: the arm reached a terminal outcome but the transport published no termination proof for it',
            independent_later_reading: row.reap_check ?? null,
            why_not_a_pass: 'a clause whose proof does not exist cannot be reported as observed, in either direction',
          };
        } else if (proof.verdict !== 'TERMINATED') {
          if (proof.survivors === 0 || proof.survivors === null) {
            // survivors:0 without TERMINATED is the one report the SPEC forbids.
            gates.push({ kind: 'DEFECT', id: `SURVIVORS_WITHOUT_TERMINATED:${row.arm}:${row.provider}:${proof.verdict}`, detail: 'a survivor count was reported beside a verdict that is not TERMINATED' });
          }
          clauseArms.push(row);
          row.clause = {
            observed: 'NOT_RUN',
            reason: `${proof.verdict}: ${String(proof.reason ?? 'no reason recorded')}`,
            survivors: proof.survivors,
            remaining_process_ids: proof.remaining_process_ids ?? null,
            caveat: proof.caveat ?? null,
            independent_later_reading: row.reap_check ?? null,
            why_not_a_pass: 'SPEC §7 A-MVP-04: a proof of SURVIVORS_REMAINING or UNVERIFIED makes the arm NOT_RUN with that exact reason, never a CANCELLED-as-pass. This harness reports it and does not upgrade it.',
          };
        } else {
          row.clause = { observed: 'OBSERVED', survivors: proof.survivors, independent_later_reading: row.reap_check ?? null };
        }
      }
      for (const late of row.late_callbacks ?? []) {
        if (late.accepted === true && late.kind === 'write') {
          gates.push({ kind: 'DEFECT', id: `LATE_WRITE_ACCEPTED:${row.arm}:${row.provider}:${late.probe}`, detail: 'a late write after the arm settled was accepted' });
        }
      }
      if ((row.raw_logs ?? []).length === 0) gates.push({ kind: 'DEFECT', id: `NO_RAW_PROCESS_LOG:${row.arm}:${row.provider}`, detail: 'the arm published no raw process log' });
    }
    record.hard_gates = gates.map((row) => row.id);
    record.gate_detail = gates;
    record.findings = findings;
    record.clauses_not_run = clauseArms.map((row) => ({ arm: row.arm, provider: row.provider, reason: row.clause.reason }));
    const executed = record.arms.filter((row) => row.error === null).length;
    const status = gates.length > 0 ? 'FAIL' : (clauseArms.length > 0 ? 'PARTIAL' : (executed > 0 ? 'PASS' : 'NOT_RUN'));
    record.verdict = {
      status,
      exit_code: status === 'PASS' ? 0 : (status === 'NOT_RUN' ? 3 : 1),
      hard_gates: record.hard_gates,
      defects: gates.length,
      clauses_not_run: clauseArms.length,
      arms_requested: armList.length,
      arms_executed: executed,
    };

    record.limitations = [
      `every child in this record ran as an ordinary host process under ${FLOOR_PROFILE}: no OS isolation control was in force, isolation_observed is false in every row, and A-MVP-04's ISOLATION clause is NOT_RUN on this host`,
      'this is NOT a governed run: no board command is called from this harness, so no arm here is a task, a lease, a grant, an outbox row or an A-MVP PASS. A-MVP-04\'s board clauses (the fence in the terminal event, byte-identical audit/outbox row counts) are NOT_RUN because the task edges are refused on this checkout; see board_gate',
      'the process-group proof is the shipped observer\'s own verdict; this harness adds an independent parent-side pid reading and never overwrites the observer\'s answer with it',
      'the surface measurement runs one real crossing per (provider, configuration) with an unresolvable model id, so it measures the argv the transport builds and nothing about model behaviour, cost or quality',
      'a lifecycle arm that is stopped before the model answers bills nothing, and an arm that is not stopped in time reports whatever the executor reported; both are published as measured',
    ];
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'AGENT_UNAVAILABLE');
    record.verdict = { status: 'NOT_RUN', exit_code: 3, hard_gates: [], reason: { code: typed.code, message: redact(String(typed.message ?? typed)).slice(0, 300) } };
  }

  // --- the credential scan and the write ------------------------------------
  let body = `${JSON.stringify(record, null, 2)}\n`;
  const hits = CREDENTIAL_PATTERNS.filter((pattern) => pattern.test(body));
  if (hits.length > 0) {
    record.hard_gates = [...record.hard_gates, 'CREDENTIAL_SHAPED_LITERAL_IN_RECORD'];
    record.verdict = { ...record.verdict, status: 'FAIL', exit_code: 1, hard_gates: record.hard_gates };
    body = `${JSON.stringify(record, null, 2)}\n`;
  }
  // The digest is over the document WITHOUT the field, and it is computed last,
  // so the published bytes and the published digest are the same document.
  const { record_digest: ignored, ...withoutDigest } = record;
  const finalRecord = { ...withoutDigest, record_digest: digest(withoutDigest) };
  fs.mkdirSync(path.dirname(outPath), { recursive: true, mode: 0o755 });
  fs.writeFileSync(outPath, `${JSON.stringify(finalRecord, null, 2)}\n`, { mode: 0o644 });
  process.stdout.write(`${JSON.stringify({
    ok: record.verdict.status === 'PASS',
    status: record.verdict.status,
    exit_code: record.verdict.exit_code,
    out: displayPath(outPath),
    arms: record.arms.map((row) => ({
      arm: row.arm, provider: row.provider, run_id: row.run_id ?? null,
      terminal: row.terminal_event?.event_type ?? null,
      clause: row.clause?.observed ?? null,
      proof: row.cancel_proof?.verdict ?? (row.arm === 'sigkill' ? 'EXTERNAL' : null),
      survivors: row.cancel_proof?.survivors ?? null,
      surviving_pids: row.cancel_proof?.remaining_process_ids ?? null,
      pid_resolvable_later: row.reap_check?.alive ?? null,
      spend_usd: row.spend?.usd ?? null,
      error: row.error?.code ?? null,
    })),
    surfaces: record.surface_comparison,
    spend: record.spend.total_usd,
    board_gate: record.board_gate === null ? null : {
      live_gate_admits: record.board_gate.live_gate.admitted,
      per_edge_gate_admits: record.board_gate.per_edge_gate.admitted,
      the_two_agree: record.board_gate.the_two_agree,
    },
    hard_gates: record.verdict.hard_gates,
    record_digest: finalRecord.record_digest,
  }, null, 2)}\n`);
  // MEASURED DEFECT IN THE TRANSPORT (reported, not worked around silently): the
  // transport's granted-deadline timer (`state.timer = setTimeout(...)` at
  // src/lib/executors/transport.mjs) is never cleared when a run reaches a
  // terminal state, so a process that finished in four seconds kept the event
  // loop alive for the full `timeout_ms` (measured: a 5m01s process whose arms
  // finished in 4s). This harness exits explicitly once its record is written;
  // the fix belongs to the transport's owner, not to this file.
  process.exit(record.verdict.exit_code);
}

await main();
