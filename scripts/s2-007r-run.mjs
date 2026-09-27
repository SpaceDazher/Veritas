#!/usr/bin/env node
// S2-007R REAL RUN DRIVER (issue SpaceDazher/Veritas#45; SPEC §3, D1–D14).
//
// WHAT THIS FILE IS
// -----------------
// The RUN DRIVER of the S2-007R ticket: a script that takes the REAL transport
// tree (`src/lib/executors/`, SPEC §2 files 2–8, owned by a different item)
// and drives a genuine end-to-end execution on this host, through the ONE
// command boundary (`commands.execute` from `src/lib/agentboard/commands.mjs`)
// and the canonical store, and writes the RAW RUN RECORD of what happened.
//
// WHAT THIS FILE IS NOT
// ---------------------
//   * It is not a test, not a replay, not a fixture and not a mock. Nothing
//     below simulates an executor. If the real transport is absent the driver
//     REFUSES (typed BoardError, exit 3); it never falls back to a scripted
//     transport, because a scripted transport producing a record that reads
//     like a real run is the one failure mode this repository exists to stop.
//   * It does not decide a status. It records observations. `realAdapterStatus`
//     is `NOT_RUN_REAL_ADAPTER` in every record this file writes, and stays
//     there: only `src/lib/executors/evidence-writer.mjs` (a different owner)
//     may lift it, and only from a run record like this one.
//   * It writes RAW run output only, under `--out` (default `results/s2-007r/`).
//     It never writes `evidence/`, never touches a manifest, never reads a
//     credential and never runs git.
//
// ONE BOUNDARY
// -------------
// Every mutation and every read goes through `execute()`. The store is read
// directly for exactly one honest reason — to observe what was COMMITTED after
// a boundary call (the event stream, the outbox row, the run row, the journal)
// — and observation never substitutes for the boundary. A step that the
// boundary refused is recorded as a refusal; it is never retried by hand and
// never "completed" by writing a store row.
//
// THE ADAPTER BINDING, AND WHY IT IS AN EXPLICIT CLAIM
// ----------------------------------------------------
// `scheduler.selectAdapter` sorts the registered adapters by `adapter_id`
// ascending, so a bare `dispatch.tick` would deterministically pick
// `adr-codex-local` and could never reach `adr-pi-local`. The driver therefore
// binds the requested adapter through the claim edge — `tasks.claim` with an
// explicit `adapter_id`, which mints the lease and the fencing token in one
// transaction — and records the scheduler's OWN derived decision
// (`dispatch.plan`) beside it, labelled as the decision the driver did not
// follow. SPEC §3 step 8 proposes `dispatch.tick`; the explicit claim is used
// instead, for the reason above, and nothing else in the sequence differs.
//
// A DETERMINISTIC, READ-ONLY TASK
// -------------------------------
// Each task asks the real executor to INVENTORY the fixture project (list the
// files and their line counts) and to modify nothing. That is a real unit of
// work a real model performs, it costs almost nothing, and it gives this driver
// one property it can check itself: the project digest before the run and after
// the run are both recorded, and a difference is reported as a finding rather
// than hidden. Task content is derived deterministically from the fixture, so a
// third party can re-derive the prompt from `--project` and the recorded
// digests. The seven measurements of SPEC §5 are NOT computed here (a different
// owner, `src/lib/executors/measure.mjs`); this driver only produces the raw
// facts they are computed from.
//
// THE PROVENANCE BOOTSTRAP, AND WHY IT IS NOT A RUN
// --------------------------------------------------
// `src/lib/executors/registration.mjs` raises
// `real_adapter_provenance.status` to REAL_ADAPTER_AVAILABLE only from a real
// observed crossing (that is rule 1 of this ticket: a probe, a fixture or a
// registration is never evidence of a process). The board
// (`commands.mjs#assertRealAdapterClaimIsTrue`) refuses to REGISTER a
// `real` adapter whose status is anything else. So the first governed run is a
// fixed point with no entry: the registration needs a crossing, and the crossing
// needs the registration. This is measured, not theoretical — the driver reached
// exactly that refusal (`ADAPTER_REGISTRATION_REFUSED`) with `realRunEvidence:
// null`.
//
// The two ways out are both a decision about what a registration's provenance
// MEANS, so neither is taken silently here:
//
//   (a) let a host probe mint REAL_ADAPTER_AVAILABLE (the pre-implementation
//       reading of SPEC D1). Cheap, and it makes the status reachable from a
//       `which codex`. It is refused: that status would then assert a crossing
//       that never happened.
//   (b) make ONE crossing, outside the board, whose entire purpose is to be a
//       crossing, and corroborate the registration with the record the PARENT
//       minted from the process it really observed. This is what
//       provenanceBootstrap() does, and it is what
//       `tests/agentboard/real-executor.test.mjs`'s opt-in real case does.
//
// The bootstrap crossing is deliberately NOT a run and is recorded as one that did
// not happen: no task, no lease, no grant, no outbox, no board row. Its model id
// is one the provider cannot resolve, so the CLI really starts, really answers
// with a non-zero exit, and bills no token (measured on this host: codex exit 1
// with a structured `status:400`, pi exit 1 with a client-side `Model not found`).
// What it establishes is exactly one fact: this adapter_id is a genuinely
// installed CLI that really crosses a process boundary and reports its own
// session id. What it does NOT establish, and what the record says it does not
// establish: that any task ran, that any answer is of any quality, and that any
// run's realAdapterStatus moved. Those need the governed runs below.
//
// CLI (every value that could flatter a result is required, not defaulted)
// -----------------------------------------------------------------------
//   --project <dir>     REQUIRED. The ONE isolated repository fixture. Absent →
//                       NeedsInput('PROJECT_REQUIRED'), exit 3. A default path
//                       would let a run claim a project nobody named.
//   --budget <number>   REQUIRED. The ONE budget, in USD. Absent →
//                       NeedsInput('BUDGET_REQUIRED'), exit 3. The single number
//                       is used verbatim as task_limit AND campaign_limit AND
//                       day_limit, so no scope can exceed it by construction.
//                       MEASURED CONSTRAINT: `store.createRun` resolves a run's
//                       grant by `task_id` and refuses a workspace-scoped row
//                       with BUDGET_NOT_ASSIGNED, so a single campaign-wide
//                       grant row cannot back a run at this HEAD. The ONE budget
//                       is therefore the ONE number, and the board receives one
//                       grant ROW per task, every row carrying that identical
//                       number. Each run's record names its own grant_id and the
//                       scope reason, so no comparison is ever presented as
//                       single-grant when it is not.
//   --adapters a,b      REQUIRED. Comma list from {codex,pi}. BOTH real adapters
//                       are always REGISTERED; the list says which ones a task
//                       is bound to (task N is bound to adapter N mod count).
//   --config <A|B>      REQUIRED. The executor's skill/context surface id. It is
//                       passed to the transport and recorded; this driver never
//                       decides which surface is "better".
//   --tasks <n>         1..8, default 1.
//   --out <dir>         Output directory, default `results/s2-007r`. A defaulted
//                       value is recorded as `out_defaulted: true`.
//   --in-memory         In-memory store (DEFAULT, no external dependency).
//   --postgres <url>    Real PostgreSQL. Exactly one of the two; both → refuse.
//   --seed <string>     Id/store namespace, default `s2-007r`. Also names the
//                       PostgreSQL schema, so two invocations never collide.
//   --model <p/id>      Optional explicit pi model. Default: the transport tree's
//                       own pin (`PI_MODEL_PINNED`). pi with no pin at all is
//                       NEEDS_INPUT, never a silent fall back to an unverified
//                       default model that would spend real money.
//   --grant-id <id>     The ONE campaign grant id every run of this campaign
//                       carries. Default `grt-s2007r-<seed>`. A comparison that
//                       spans two grant ids is two budgets, so the operator names
//                       the id once and every invocation of the campaign passes
//                       the same value.
//   --task-limit <n>    The grant's per-task limit in USD. Default: --budget.
//   --campaign-limit <n>The grant's campaign limit in USD. Default: --budget.
//   --day-limit <n>     The grant's per-day limit in USD. Default: --budget.
//   --campaign-ledger <path>
//                       JSON ledger of the campaign's self-reported spend.
//                       Default `results/s2-007r/campaign-ledger.json`. The run
//                       REFUSES to dispatch when the ledger plus the ceiling
//                       would pass CAMPAIGN_STOP_FRACTION of the campaign cap, and
//                       it appends its own settled spend to the ledger. The board
//                       cannot enforce a campaign across separate invocations, so
//                       this file is the enforcement and it is quoted in the
//                       record.
//   --provenance-bootstrap <off|codex,pi>
//                       Which providers need the pre-registration crossing (see
//                       `provenanceBootstrap`). Default: every requested adapter.
//   --clock-base <iso>  Injected board clock base, default 2026-09-25T12:00:00.000Z.
//   --workspace-root <p> Containment root, default /tmp/veritas-s2-007r-ws,
//                       created 0700, owner- and symlink-asserted before use.
//
// HOW TO OBTAIN A REAL POSTGRESQL URL IN THIS REPOSITORY
// ------------------------------------------------------
// (1) An existing instance: put the connection string in the DATABASE_URL
//     environment variable — the user, the password, the host, the port and the
//     database name, colon- and at-separated in the usual way — then
//     `node scripts/s2-007r-run.mjs --postgres "$DATABASE_URL" …`.
//     The URL is spelled this way rather than written out in full on purpose:
//     a connection string pasted into a source comment is a credential-shaped
//     literal, and scripts/check-public-artifacts.mjs refuses a committed file
//     that contains one. Read the value, never the example.
// (2) The repository's own ephemeral recipe — a digest-pinned image, rootless
//     podman, a tmpfs PGDATA, a random free loopback port and RANDOM runtime
//     credentials that are never written to a record (reference them by
//     variable name only):
//
//       PORT=$(node -e "const n=require('net'),s=n.createServer();s.listen(0,'127.0.0.1',()=>{console.log(s.address().port);s.close()})")
//       podman run --detach --name=veritas-s2-007r-db --pull=never \
//         --publish 127.0.0.1:$PORT:5432 --read-only --user=70:70 --cap-drop all \
//         --security-opt no-new-privileges --pids-limit=64 --memory=384m \
//         --memory-swap=384m --cpus=1 \
//         --tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=256m,mode=1777 \
//         --tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=8m,mode=1777 \
//         --env PGDATA=/var/lib/postgresql/data/pgdata \
//         --env POSTGRES_USER=veritas_s2_007r --env POSTGRES_DB=veritas_s2_007r \
//         --env POSTGRES_PASSWORD="$S2_007R_DB_PASSWORD" \
//         docker.io/library/postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73
//
//     `--pull=never` means the image must already be in the local rootless
//     store. On WSL2 the sandbox backend runs in the same-named distro, so on
//     the Windows host prefix with `wsl.exe -d Ubuntu-24.04 --`, exactly as
//     `scripts/s2-007-db-replay.mjs` does. This driver applies every ordered
//     migration itself, through `scripts/apply-migrations.mjs`, into a schema
//     named after `--seed` (so it never touches `public`). It does NOT start
//     or stop a container: the recipe above is the operator's, and the driver
//     reports NOT_RUN_DB when the URL does not answer.
//
// EXIT CODES (never a partial success dressed as a pass)
// ------------------------------------------------------
//   0  PASS      every requested run produced a contract-valid, COLLECTED
//                 SUCCEEDED ExecutionResult and the task reached IN_REVIEW.
//   1  PARTIAL   at least one run produced a collected result and at least one
//                 did not, or a step was refused. Never reported as PASS.
//   1  FAIL      a hard gate of this driver tripped (an untyped error escaped, a
//                 digest disagrees with the bytes, a credential-shaped literal
//                 reached an output file, a failure was mapped to a success).
//   3  NOT_RUN   a precondition could not be established (no project, no budget,
//                 no store, no real transport, no installed executor). Always
//                 accompanied by a typed BoardError from ERROR_CODES.
//
//   node scripts/s2-007r-run.mjs --project corpus/s2-007r/project --budget 0.10 \
//     --adapters codex,pi --config A --tasks 2 --out results/s2-007r --in-memory
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { execute } from '../src/lib/agentboard/commands.mjs';
import { InMemoryAgentBoardStore, PostgresAgentBoardStore } from '../src/lib/agentboard/store.mjs';
import { assertAdapterInterface, probeRealAdapters } from '../src/lib/agentboard/adapters.mjs';
import { boardContractErrors } from '../src/lib/agentboard/contracts.mjs';
import { createProcessObserver } from '../src/lib/identity/process-observer.mjs';
import {
  AgentUnavailable,
  MalformedResult,
  NeedsInput,
  NotRunDb,
  NotRunRealAdapter,
  isBoardError,
  redact,
  toBoardError,
} from '../src/lib/agentboard/errors.mjs';
import {
  BOARD_CAPABILITIES,
  CANONICAL_JSON_VERSION,
  ID_PREFIXES,
  NON_RETRYABLE_CODES,
  isHostUnisolatedSandboxProfile,
} from '../src/lib/agentboard/constants.mjs';
import { SANDBOX_HOST_UNISOLATED } from '../src/lib/identity/sandbox-profiles.mjs';
import { buildUnisolatedAuthorization } from './s2-007r-authorization.mjs';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DRIVER_VERSION = 's2-007r-run-v1';
const TICKET = 'S2-007R';
const ISSUE = 'SpaceDazher/Veritas#45';

// --- the injected clock ------------------------------------------------------
// The board's time is injected and counter-driven. There is no Date.now() and no
// bare `new Date()` below; the only real time source in this file is
// `process.hrtime.bigint()`, used exclusively to MEASURE a wall clock for the
// record (SPEC §5 #5: parent-side measurement, never authority).
//
// The base is inside the named permit's window on purpose. The permit is judged
// against THIS injected clock and never against the process clock, so a run can
// only start while the authorisation it carries is still open. One step of
// STEP_MS per boundary call, so a long run walks forward deterministically and
// never leaves the window from below; the driver also refuses to start a run
// whose projected end instant would leave it (see assertClockInsidePermit).
const PERMIT_WINDOW = Object.freeze({ issued_at: '2026-09-26T00:00:00.000Z', expires_at: '2026-09-27T00:00:00.000Z' });
const CLOCK_BASE = '2026-09-26T09:00:00.000Z';
const STEP_MS = 1000;
const CLOCK_CALLS_PER_RUN = 400;

// --- the world ---------------------------------------------------------------
const WORKSPACE_ID = 'ws-s2007r-project';
// FINDING (run-driver review #10), APPLIED: the default root carried no seed,
// and `materialiseRunProject` rmSync's `<root>/run-NN/project`, so a second
// invocation — another agent, or another seed — wiped the first run's project
// copy mid-flight and produced a spurious `project-modified` finding. The seed
// is part of the default path, so two invocations never share a root unless the
// operator asks them to.
const DEFAULT_WORKSPACE_ROOT = '/tmp/veritas-s2-007r-ws';
// THE PROFILE OF THIS RUN (owner decision, issue #45, D3 revised). A real
// model-calling executor cannot run inside a proven profile on this host, so
// the run is bound to the HOST_UNISOLATED floor, which is NOT a proven tier and
// is admitted only by the named human permit below. Naming a proven profile for
// a process that never entered its container is the one thing that would make
// the record lie in the field a reader checks first.
const FLOOR_PROFILE = SANDBOX_HOST_UNISOLATED.profile_id;
// The one grant the owner authorised for this pilot, minted by the same function
// that verifies it. Its body_digest is computed, never typed, so a hand-edited
// document cannot keep a valid digest.
const UNISOLATED_AUTHORIZATION = buildUnisolatedAuthorization();
const BUDGET_TIMEOUT_MS = 600000;
const CURRENCY = 'USD';

// The campaign stop rule, fixed by the owner before the run: the campaign cap is
// never passed, and the driver stops at this fraction of it. The board's own
// grant cannot enforce a campaign across separate invocations of this driver (a
// grant row is task-scoped at this HEAD), so the ledger below is the enforcement
// and the record quotes it.
const CAMPAIGN_STOP_FRACTION = 0.8;
// The model id the provenance bootstrap asks for. It is deliberately
// unresolvable: the CLI really starts, really crosses the process boundary and
// really answers with a non-zero exit, and no token is billed (measured on this
// host — codex: exit 1 with a structured `status:400`; pi: exit 1 with a
// client-side `Model "..." not found`). The shape satisfies the transport's own
// MODEL_RE, so the argv it builds is a real provider argv.
const BOOTSTRAP_MODEL = 'veritas-s2-007r-nonexistent/no-such-model';
const BOOTSTRAP_PROMPT = 'Reply with exactly one token: PING.';
// The context surface the bootstrap crossing is built with. It is one of the
// two validated ends of the axis and it is NOT a cell of the comparison: the
// bootstrap collects no result and asserts no delta. Recorded in the report so
// a reader can see which argv the registration-corroborating crossing used.
const BOOTSTRAP_CONFIGURATION = 'A';

// What `--help` prints. Kept as data so the guard and the header comment cannot
// drift apart.
const USAGE_TEXT = [
  's2-007r-run.mjs — one real-adapter invocation: probes the executables, bootstraps each',
  'registration with a real observed crossing, then drives a real codex/pi run per task through',
  'the board boundary and writes the run record.',
  '',
  '  --help                 this text, and nothing else',
  '  --project <dir>        REQUIRED: the ONE project every run uses (refused if absent)',
  '  --out <dir>            the record directory (default results/s2-007r)',
  '  --seed <slug>          a run-seed slug, part of the run-set identity',
  '  --config A|B           the context surface (default A). REQUIRED by the transport and',
  '                         validated against the executor tree\'s own CONFIG_SURFACES',
  '  --adapters codex,pi    which installed executors to drive',
  '  --tasks <n>            how many tasks, each a real run',
  '  --model <provider/id>  an explicit model pin; pi is never left on a default',
  '  --postgres <url>       a DATABASE_URL, otherwise the rootless-podman recipe provisions one',
  '',
  'It SPAWNS REAL EXECUTORS and can spend real money. Exit codes: 0 pass, 1 fail, 3 not run.',
].join('\n');

// The ONE budget, the ONE project and the ONE workspace. `budgetAuthority` is
// recorded verbatim: this is a run-operator declared number, not a product
// approval (SPEC D4, issue #12).
const BUDGET_AUTHORITY = 'RUN_OPERATOR_DECLARED_NOT_PRODUCT_APPROVED';
const BUDGET_APPROVAL_OWNER = 'issue #12 (S2-012)';

// Declared authority. `board.review.approve` is deliberately ABSENT from every
// principal below: this run has no authenticated human reviewer, so the
// IN_REVIEW -> DONE edge is structurally unreachable here rather than merely
// unexercised (SPEC §7, A-MVP-05 `NOT_RUN`).
const P = Object.freeze({
  owner: 'prn-s2007r-owner',
  scheduler: 'prn-s2007r-scheduler',
  producer: 'prn-s2007r-producer',
});
const CAP = Object.freeze({
  owner: [
    'board.task.read', 'board.task.create', 'board.task.transition', 'board.budget.grant',
    'board.adapter.register', 'board.execution.cancel',
  ],
  scheduler: [
    'board.task.read', 'board.task.claim', 'board.task.release', 'board.execution.start',
    'board.execution.cancel', 'board.result.collect',
  ],
  producer: [
    'board.task.read', 'board.task.transition', 'board.execution.start', 'board.result.collect',
    'board.evidence.submit',
  ],
});
const ACL = Object.freeze([P.owner, P.scheduler, P.producer]);

// The two real adapters. `declared_capabilities` / `declared_tools` are the real
// surface the boundary checks a task's grant against: the request carries the
// TASK's tools, and the task's tools must be covered by the registration.
//
// They are NOT arbitrary: they are the union of what the board can enforce on a
// host process and what the executor can actually be asked to do, and they are
// intersected with the task's grant before anything reaches argv. The task below
// is read-only, so it is granted strictly less than the adapter declares; see
// ADAPTERS note in the report and the `declared_capabilities` vs the task's
// `required_capabilities` check below.
//
// `declared_capabilities` MUST also cover the scope the BOARD grants a run. The
// server resolves a run's `granted_scope` to `DEFAULT_RUN_SCOPE`
// (src/lib/agentboard/commands.mjs:380 = ['task.read','artifact.write']) and the
// transport cross-checks that scope against this registration before the spawn
// (src/lib/executors/transport.mjs:1254), so a registration that declared only
// the task's own vocabulary ('source.read','code.write') would be refused with
// ADAPTER_CLAIM_NOT_REGISTERED — measured, not assumed. A registration may
// declare a superset of the current grant; the surplus is never used to widen
// anything (adapters.mjs#crossCheckCapabilities).
const ADAPTERS = Object.freeze({
  codex: Object.freeze({
    provider: 'codex',
    adapter_id: 'adr-codex-local',
    module: 'transport',
    module_file: 'transport.mjs',
    factory: 'createRealExecutorTransport',
    declared_capabilities: Object.freeze(['task.read', 'artifact.write', 'source.read', 'code.write']),
    declared_tools: Object.freeze(['tool:fs.read', 'tool:fs.write', 'tool:test.run']),
    binary: 'codex',
  }),
  pi: Object.freeze({
    provider: 'pi',
    adapter_id: 'adr-pi-local',
    module: 'transport',
    module_file: 'transport.mjs',
    factory: 'createRealExecutorTransport',
    declared_capabilities: Object.freeze(['task.read', 'artifact.write', 'source.read', 'code.write']),
    declared_tools: Object.freeze(['tool:fs.read', 'tool:fs.write', 'tool:test.run']),
    binary: 'pi',
  }),
});
const ADAPTER_KEYS = Object.freeze(Object.keys(ADAPTERS));

// The terminal event types, mirroring the frozen derivation in
// contracts/execution-event.schema.json (adapters.mjs verifies that same table
// against the schema at import time). One of them ends the drain loop.
const TERMINAL_EVENT_TYPES = new Set(['COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'UNKNOWN']);

// The same credential-shaped literals `scripts/check-public-artifacts.mjs`
// scans tracked files for. A raw executor log is written into a TRACKED output
// directory, so the driver scans its own output before the record is written and
// withholds any file that trips one of these, rather than publishing it.
const CREDENTIAL_PATTERNS = Object.freeze([
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /gh[pousr]_[A-Za-z0-9]{30,}/,
  /github_pat_[A-Za-z0-9_]{40,}/,
  /sk-(?:proj-)?[A-Za-z0-9_-]{35,}/,
  /postgres(?:ql)?:\/\/[^\s/:]+:[^\s@]+@/,
]);

const PRECONDITION_CODES = new Set([
  'NEEDS_INPUT', 'NOT_RUN_REAL_ADAPTER', 'NOT_RUN_DB', 'AGENT_UNAVAILABLE', 'BLOCKED_SANDBOX',
]);

// ===========================================================================
// Small deterministic helpers
// ===========================================================================
/** Repo-relative when it stays inside the repo, absolute when it does not. */
function displayPath(target) {
  const relative = path.relative(ROOT, target);
  return relative.startsWith('..') ? target : relative;
}

/**
 * The CLI as it was typed, with every credential-shaped value removed. A
 * `--postgres` URL carries a password, and the record is a TRACKED file, so the
 * URL is reduced to its scheme and host before it is written.
 */
function redactArgv(items) {
  return items.map((item) => {
    const text = String(item);
    if (/^postgres(?:ql)?:\/\//i.test(text)) {
      try {
        const url = new URL(text);
        return `${url.protocol}//<credentials-redacted>@${url.host}${url.pathname}`;
      } catch {
        return 'postgresql://<credentials-redacted>';
      }
    }
    return redact(text);
  });
}

/** The board's own bounded redaction, applied to any value a third party handed us. */
function deepRedact(value, depth = 0) {
  if (typeof value === 'string') return redact(value);
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= 6) return null;
  if (Array.isArray(value)) return value.map((item) => deepRedact(item, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = deepRedact(item, depth + 1);
    return out;
  }
  return null;
}

/**
 * The injected clock in the shape this repository uses everywhere else
 * (`clock: { now() }`, see scripts/s2-007-run.mjs and adapters.mjs
 * requireClock), with `call`/`get` aliases and a separate `now` callback beside
 * it, so a factory that reaches for a differently spelled accessor still
 * receives the same counter-driven instant. There is no process clock behind any
 * of them. A transport that calls the object itself raises a TypeError, which
 * this driver records verbatim as an interface finding rather than working
 * around: the clock's contract belongs to the transport, not to the run.
 */
function injectedClock(fn) {
  return { now: () => fn(), call: () => fn(), get: () => fn() };
}

function wireDigest(value) {
  return `sha256:${canonicalDigest(value)}`;
}

function sha256File(absolute) {
  return createHash('sha256').update(fs.readFileSync(absolute)).digest('hex');
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 2; i < argv.length; i += 1) {
    if (!argv[i].startsWith('--')) { args._.push(argv[i]); continue; }
    const next = argv[i + 1];
    // A flag with no value is NULL, not the string 'true'. A bare `--model`
    // must not reach the transport as the model id "true", and a bare `--out`
    // must not create a directory called "true".
    if (next === undefined || next.startsWith('--')) args[argv[i].slice(2)] = null;
    else { args[argv[i].slice(2)] = next; i += 1; }
  }
  return args;
}

/**
 * The resolved absolute path of an executable the host probe already found.
 *
 * The NAMED path is returned, not its symlink target: on this host `pi` and
 * `codex` are npm launchers, so the realpath's basename is `cli.js` / `codex.js`
 * and the evidence writer requires the record to name the provider's own binary
 * (measured: "a pi run must name the 'pi' binary, got \"cli.js\""). The transport
 * resolves the symlink and digests the target's bytes itself, and records both
 * paths, so nothing is lost by handing it the name a host probe would report.
 */
function resolveExecutable(binary) {
  const found = resolveOnPath(binary);
  if (found === null) {
    throw new AgentUnavailable('EXECUTOR_NOT_RESOLVABLE', `${binary} is not on PATH, so no absolute executor path can be given to the transport`);
  }
  if (!fs.existsSync(found)) {
    throw new AgentUnavailable('EXECUTOR_NOT_RESOLVABLE', `${found} was found on PATH but no longer exists`);
  }
  return found;
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

function positiveNumber(value, label, { min = 0, max = Number.MAX_VALUE } = {}) {
  const numeric = typeof value === 'number' ? value : Number(String(value));
  if (!Number.isFinite(numeric) || numeric <= min || numeric > max) {
    throw new NeedsInput(`NEEDS_INPUT:${label}`, `${label} must be a finite number greater than ${min}`);
  }
  return numeric;
}

function positiveInteger(value, label, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const numeric = typeof value === 'number' ? value : Number(String(value));
  if (!Number.isInteger(numeric) || numeric < min || numeric > max) {
    throw new NeedsInput(`NEEDS_INPUT:${label}`, `${label} must be an integer in ${min}..${max}`);
  }
  return numeric;
}

function principalOf(principalId, capabilityKey) {
  const capabilities = CAP[capabilityKey];
  if (!Array.isArray(capabilities)) throw new NeedsInput('NEEDS_INPUT:CAPABILITY_SET_UNKNOWN', String(capabilityKey));
  for (const capability of capabilities) {
    if (!BOARD_CAPABILITIES.includes(capability)) {
      throw new NeedsInput('NEEDS_INPUT:CAPABILITY_UNKNOWN', `the driver named a capability outside the closed set: ${capability}`);
    }
  }
  return { principal_id: principalId, capabilities: [...capabilities], workspace_ids: [WORKSPACE_ID] };
}

/** One monotonic, PREFIXED id factory for the boundary; a bare one for the store. */
function makeIdFactories(namespace) {
  const boundaryCounters = new Map();
  const storeCounters = new Map();
  return {
    boundary: (kind) => {
      const next = (boundaryCounters.get(kind) ?? 0) + 1;
      boundaryCounters.set(kind, next);
      return `${ID_PREFIXES[kind] ?? ''}${namespace}-${next.toString(36).padStart(6, '0')}`;
    },
    store: (kind) => {
      const next = (storeCounters.get(kind) ?? 0) + 1;
      storeCounters.set(kind, next);
      return `${namespace}-${next.toString(36).padStart(6, '0')}`;
    },
  };
}

// ===========================================================================
// The ONE project: validation, digest, materialisation
// ===========================================================================
function listProjectFiles(root) {
  const out = [];
  const walk = (absolute, relative) => {
    const entries = fs.readdirSync(absolute, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const entry of entries) {
      const childAbsolute = path.join(absolute, entry.name);
      const childRelative = relative === '' ? entry.name : `${relative}/${entry.name}`;
      if (entry.isSymbolicLink()) {
        throw new NeedsInput('NEEDS_INPUT:PROJECT_SYMLINK', `the fixture contains a symlink: ${childRelative} (a link is not a project byte)`);
      }
      if (entry.isDirectory()) { walk(childAbsolute, childRelative); continue; }
      if (!entry.isFile()) {
        throw new NeedsInput('NEEDS_INPUT:PROJECT_NON_FILE', `the fixture contains a non-regular entry: ${childRelative}`);
      }
      out.push({ relative: childRelative, bytes: fs.statSync(childAbsolute).size });
    }
  };
  walk(root, '');
  return out.sort((left, right) => (left.relative < right.relative ? -1 : 1));
}

/** sha256 over the sorted `relative path -> {bytes, sha256}` map. Recomputable by anyone. */
function projectDigest(root) {
  const map = {};
  for (const file of listProjectFiles(root)) {
    map[file.relative] = { bytes: file.bytes, sha256: sha256File(path.join(root, file.relative)) };
  }
  if (Object.keys(map).length === 0) {
    throw new NeedsInput('NEEDS_INPUT:PROJECT_EMPTY', 'the project fixture holds no regular file; an empty project is not an input');
  }
  return { digest: wireDigest(map), files: map, fileCount: Object.keys(map).length, totalBytes: Object.values(map).reduce((sum, row) => sum + row.bytes, 0) };
}

/**
 * The containment root, asserted before a single byte is executed inside it:
 * created 0700, owned by this uid, and free of symlinks on the path (the
 * profile's deny_link_escape / deny_traversal rules). The root is labelled
 * INJECTED_NOT_REGISTRY everywhere, because the S2-002 workspace registry on this
 * host holds Windows roots only and authorised nothing here.
 *
 * The MODE is tightened only when this invocation is the one that created the
 * directory. An operator-named directory that already existed keeps the mode it
 * had: this run is not entitled to re-permission a shared directory it merely
 * borrowed.
 */
function prepareWorkspaceRoot(requested) {
  const absolute = path.resolve(requested);
  const existed = fs.existsSync(absolute);
  fs.mkdirSync(absolute, { recursive: true, mode: 0o700 });
  const real = fs.realpathSync(absolute);
  const created = !existed;
  if (created && process.platform !== 'win32') {
    const mode = fs.statSync(real).mode & 0o777;
    if (mode !== 0o700) fs.chmodSync(real, 0o700);
  }
  const stat = fs.statSync(real);
  const finalMode = stat.mode & 0o777;
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  if (process.platform !== 'win32' && uid !== null && stat.uid !== uid) {
    throw new NeedsInput('WORKSPACE_ROOT_NOT_OWNED', `the workspace root ${real} is owned by uid ${stat.uid}, not by this run's uid ${uid}`);
  }
  let segments = '';
  for (const segment of real.split('/').filter((item) => item.length > 0)) {
    segments += `/${segment}`;
    if (fs.lstatSync(segments).isSymbolicLink()) {
      throw new NeedsInput('WORKSPACE_ROOT_SYMLINK', `the workspace root path crosses a symlink at ${segments}`);
    }
  }
  return {
    requested,
    absolute: real,
    mode: `0${finalMode.toString(8)}`,
    owner_uid: stat.uid,
    symlink_free: true,
    created_by_this_invocation: created,
    mode_note: created
      ? 'this invocation created the root and set it to 0700'
      : 'this invocation did NOT create the root, so it did not change its mode; the root keeps the permissions it already had',
  };
}

function validateProjectFixture(source) {
  const absolute = path.resolve(ROOT, source);
  if (!fs.existsSync(absolute)) {
    throw new NeedsInput('NEEDS_INPUT:PROJECT_REQUIRED', `--project ${source} does not exist; the run has no project to work on`);
  }
  const stat = fs.lstatSync(absolute);
  if (stat.isSymbolicLink()) {
    throw new NeedsInput('NEEDS_INPUT:PROJECT_SYMLINK_ROOT', `--project ${source} is a symlink; a run may not claim a project through a link`);
  }
  if (!stat.isDirectory()) {
    throw new NeedsInput('NEEDS_INPUT:PROJECT_NOT_A_DIRECTORY', `--project ${source} is not a directory`);
  }
  const real = fs.realpathSync(absolute);
  return { requested: source, absolute, realpath: real, ...projectDigest(real) };
}

/**
 * A FRESH copy of the frozen fixture per run, so run N+1 never inherits run N's
 * edits. The copy's digest is computed from the bytes on disk and compared with
 * the source digest: a difference is a typed refusal, not a note.
 */
function materialiseRunProject(source, destinationRoot) {
  const destination = path.join(destinationRoot, 'project');
  fs.rmSync(destination, { recursive: true, force: true });
  fs.mkdirSync(destinationRoot, { recursive: true, mode: 0o700 });
  fs.cpSync(source.realpath, destination, { recursive: true, dereference: false });
  const materialised = projectDigest(destination);
  if (materialised.digest !== source.digest) {
    throw new NeedsInput(
      'COMPARISON_INPUT_MISMATCH:project_digest',
      `the materialised copy of the fixture (${materialised.digest}) does not match the source (${source.digest})`,
    );
  }
  return { destination, realpath: fs.realpathSync(destination), digest: materialised.digest, fileCount: materialised.fileCount, totalBytes: materialised.totalBytes };
}

// The real transport tree (SPEC §2 files 2–8, now relocated out of the frozen
// `src/lib/agentboard` target into `src/lib/executors/`; the layout deviation
// is recorded in src/lib/executors/README.md). The driver only CONSUMES it.
// The check stays strict on purpose: a source that is present but incomplete is
// a typed refusal, and when no source resolves at all the driver refuses
// rather than falling back to a scripted transport, because a scripted
// transport producing a record that reads like a real run is the one failure
// mode this repository exists to stop.
const TRANSPORT_SOURCES = Object.freeze([
  Object.freeze({
    id: 'executors-tree',
    dir: 'src/lib/executors',
    modules: Object.freeze([
      'constants.mjs', 'internals.mjs', 'failure-map.mjs', 'evidence-writer.mjs',
      'registration.mjs', 'transport.mjs', 'measure.mjs',
    ]),
    registration_export: 'createRealRegistration',
    shared_transport: 'createRealExecutorTransport',
  }),
]);

/** Normalise one real transport source into the single shape this driver consumes. */
function normaliseTransportSource(source, loaded) {
  // The exports are looked up across every module of the source, in order: the
  // SPEC tree keeps the registration in registration.mjs, the single-module
  // transport keeps both exports in real-executor.mjs, and which file holds what
  // is not this driver's to assume.
  const find = (exportName) => source.modules
    .map((name) => loaded[name]?.[exportName])
    .find((value) => typeof value === 'function') ?? null;
  const registrationFactory = find(source.registration_export);
  if (registrationFactory === null) {
    throw new NotRunRealAdapter('NOT_RUN_REAL_ADAPTER', `${source.dir} does not export ${source.registration_export}(); the driver binds to the documented export name`);
  }
  const constants = loaded['constants.mjs'] ?? loaded[source.modules[0]] ?? {};
  return {
    id: source.id,
    dir: source.dir,
    modules: [...source.modules],
    constants,
    createRegistration: (options) => registrationFactory(options),
    hasTransport(provider) {
      if (source.shared_transport !== null) return find(source.shared_transport) !== null;
      return false;
    },
    createTransport(provider, options) {
      if (source.shared_transport !== null) {
        const shared = find(source.shared_transport);
        if (shared === null) {
          throw new NotRunRealAdapter('NOT_RUN_REAL_ADAPTER', `${source.dir} exports no ${source.shared_transport}()`);
        }
        return shared({ ...options, provider });
      }
      throw new NotRunRealAdapter('NOT_RUN_REAL_ADAPTER', `${source.dir} declares no transport factory for ${provider}`);
    },
    /**
     * The provenance string a run record carries, DERIVED from the tree that was
     * actually resolved and the factory that was actually called. A literal
     * written by this driver would name a module that need not exist, and the
     * one field whose job is provenance must not be a constant.
     */
    transportSource(provider) {
      return `${source.dir}#${source.shared_transport ?? 'per-provider factory'}(provider=${provider})`;
    },
  };
}

async function loadExecutorTree() {
  const attempts = [];
  for (const source of TRANSPORT_SOURCES) {
    const base = path.join(ROOT, source.dir);
    const loaded = {};
    const missing = [];
    for (const name of source.modules) {
      const target = path.join(base, name);
      if (!fs.existsSync(target)) { missing.push(path.relative(ROOT, target)); continue; }
      try {
        loaded[name] = await import(pathToFileURL(target).href);
      } catch (error) {
        throw new NotRunRealAdapter('NOT_RUN_REAL_ADAPTER', `${path.relative(ROOT, target)} did not load: ${String(error?.message ?? error).slice(0, 200)}`);
      }
    }
    if (missing.length === source.modules.length) {
      attempts.push({ source: source.id, dir: source.dir, modules_present: 0, modules_expected: source.modules.length });
      continue;
    }
    if (missing.length > 0) {
      throw new NotRunRealAdapter('NOT_RUN_REAL_ADAPTER', `${source.dir} is present but incomplete: missing ${missing.join(', ')}`);
    }
    return { binding: normaliseTransportSource(source, loaded), attempts, source: source.id, dir: source.dir };
  }
  throw new NotRunRealAdapter(
    'NOT_RUN_REAL_ADAPTER',
    `no real transport is present in this checkout (${attempts.map((row) => `${row.dir}: 0/${row.modules_expected} modules`).join('; ')}). This driver never substitutes a scripted transport`,
  );
}
// ===========================================================================
// Preflight: the board's host probe + a real child process per executable
// ===========================================================================
function versionProcessProbe(binary) {
  // A PATH hit is not a run. This is a real child process: it starts, it
  // answers, it exits with a code this driver records. It still does NOT prove
  // a model call can complete — only the collected result of a run does that.
  const started = process.hrtime.bigint();
  let result;
  try {
    result = spawnSync(binary, ['--version'], {
      encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024, windowsHide: true, shell: false,
      cwd: ROOT, env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' },
    });
  } catch (error) {
    return {
      binary, spawn_ok: false, exit_code: null, signal: null, stdout: '', stderr: redact(String(error?.message ?? error)).slice(0, 200),
      wall_ms: Number((process.hrtime.bigint() - started) / 1000n) / 1000,
    };
  }
  const wallNs = process.hrtime.bigint() - started;
  return {
    binary,
    spawn_ok: result.error === undefined || result.error === null,
    exit_code: result.status === null ? null : result.status,
    signal: result.signal ?? null,
    stdout: redact(String(result.stdout ?? '')).split('\n')[0].trim().slice(0, 200),
    stderr: redact(String(result.stderr ?? '')).split('\n')[0].trim().slice(0, 200),
    wall_ms: Math.round(Number(wallNs / 1000n) / 1000),
  };
}

// ===========================================================================
// The store: in-memory (default) or the real PostgreSQL tier
// ===========================================================================
async function openStore({ tier, connectionString, schema, clock, storeIds, seed }) {
  if (tier === 'memory') {
    return {
      tier: 'memory',
      backend: new InMemoryAgentBoardStore({ clock, ids: storeIds, seed }),
      details: { class: 'InMemoryAgentBoardStore', durability: 'none; a run that happened cannot be re-read after this process exits' },
      close: async () => {},
    };
  }
  let pg;
  try {
    pg = (await import('pg')).default ?? (await import('pg'));
  } catch (error) {
    throw new NotRunDb('NOT_RUN_DB', `the PostgreSQL driver is not installed: ${String(error?.message ?? error).slice(0, 160)}`);
  }
  const { Pool } = pg;
  let bootstrap;
  try {
    bootstrap = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 5000 });
    const probe = await bootstrap.query('SELECT 1 AS ok');
    if (probe.rows[0]?.ok !== 1) throw new Error('SELECT 1 did not answer');
    await bootstrap.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
  } catch (error) {
    await bootstrap?.end().catch(() => {});
    throw new NotRunDb('NOT_RUN_DB', `the PostgreSQL URL did not answer (${String(error?.message ?? error).slice(0, 160)}); the persistence tier is NOT run, never a silent in-memory fallback`);
  }
  await bootstrap.end().catch(() => {});

  const pool = new Pool({ connectionString, max: 5, options: `-c search_path=${schema} -c timezone=UTC` });
  let migration;
  let migrations;
  try {
    const applyMigrationsModule = await import('./apply-migrations.mjs');
    migration = await applyMigrationsModule.applyMigrations({ connectionString, root: ROOT, pool });
    migrations = applyMigrationsModule.discoverMigrations(ROOT).map(({ name, sha256 }) => ({ name, sha256 }));
  } catch (error) {
    await pool.end().catch(() => {});
    throw new NotRunDb('NOT_RUN_DB', `the ordered migrations did not apply: ${String(error?.message ?? error).slice(0, 200)}`);
  }
  const backend = new PostgresAgentBoardStore({ pool, clock, ids: storeIds, seed });
  return {
    tier: 'postgres',
    backend,
    details: {
      class: 'PostgresAgentBoardStore',
      schema,
      applied: migration?.applied ?? null,
      migration_digests: migrations,
      credentials: 'referenced by the --postgres URL in the operator environment; no value is read, printed, hashed or recorded',
    },
    close: async () => { await pool.end().catch(() => {}); },
  };
}

// ===========================================================================
// The harness
// ===========================================================================
class RealRun {
  constructor({ options, store, executors, adapterKeys }) {
    this.options = options;
    this.store = store;
    this.executors = executors;
    this.adapterKeys = adapterKeys;
    this.tick = 0;
    this.readSeq = 0;
    this.ids = makeIdFactories(options.seed);
    this.clock = () => new Date(Date.parse(options.clockBase) + this.tick * STEP_MS);
    this.calls = [];
    this.errors = [];
    this.transitions = [];
    this.principal = {
      owner: principalOf(P.owner, 'owner'),
      scheduler: principalOf(P.scheduler, 'scheduler'),
      producer: principalOf(P.producer, 'producer'),
    };
    this.workspaceRoots = [options.workspaceRoot];
  }

  now() { return this.clock().toISOString(); }

  /** The server-resolved instant: one fixed step per boundary call, never the process clock. */
  instant() { this.tick += 1; return this.now(); }

  key(step, command, args, actor) {
    try {
      return canonicalDigest({ driver: DRIVER_VERSION, seed: this.options.seed, step, command, args, actor });
    } catch (error) {
      // A non-canonical argument is a bug in THIS file and must fail loudly
      // here, where it can still be named, instead of looking like a refusal.
      throw new NeedsInput('DRIVER_NON_CANONICAL_ARGS', `${step}: ${String(error?.message ?? error).slice(0, 200)}`);
    }
  }

  /** THE production-facing call. Every mutation and every read goes through it. */
  async call(step, command, args, { principal, actorKind, transport = null, adapters = null }) {
    const instant = this.instant();
    const idempotencyKey = this.key(step, command, args, principal.principal_id);
    const row = {
      step, command, actor: principal.principal_id, actor_kind: actorKind,
      workspace_id: WORKSPACE_ID, idempotency_key: idempotencyKey, board_instant: instant,
    };
    let result;
    try {
      result = await execute({
        command,
        args: { ...args, idempotency_key: idempotencyKey },
        principal,
        actorKind,
        store: this.store,
        adapters,
        transport,
        clock: { now: this.clock },
        now: instant,
        workspaceRoots: this.workspaceRoots,
        realpath: fs.realpathSync,
        sandbox: FLOOR_PROFILE,
        // The named human permit, SERVER-RESOLVED and passed as an option. It is
        // never a payload argument: no command below can supply, widen or renew
        // it, and the board adjudicates it against `now`, the injected instant.
        unisolatedExecutionAuthorization: UNISOLATED_AUTHORIZATION,
        ids: this.ids.boundary,
      });
    } catch (error) {
      const typed = isBoardError(error);
      const record = {
        ...row,
        outcome: 'REFUSE',
        code: typed ? error.code : `UNTYPED_${String(error?.name ?? 'UNKNOWN')}`,
        typed,
        retryable: typed ? error.retryable : null,
        non_retryable: typed ? NON_RETRYABLE_CODES.includes(error.code) : false,
        message: redact(String(error?.message ?? error)).slice(0, 300),
        detail: typed && error.detail !== undefined ? redact(String(error.detail)).slice(0, 400) : null,
      };
      this.calls.push(record);
      this.errors.push({ step, command, code: record.code, typed, message: record.message, board_instant: instant });
      return record;
    }
    const record = {
      ...row,
      outcome: 'ACCEPT',
      code: null,
      typed: true,
      replayed: result.replayed === true,
      revision: result.revision ?? null,
    };
    this.calls.push(record);
    return { ...record, data: result.data ?? null };
  }

  /** A production READ. The step is unique per call, so a read never replays. */
  async readTask(taskId) {
    this.readSeq += 1;
    const row = await this.call(`read.${String(this.readSeq).padStart(3, '0')}.${taskId}`, 'tasks.get', { task_id: taskId }, {
      principal: this.principal.owner, actorKind: 'human_owner',
    });
    if (row.outcome !== 'ACCEPT' || !row.data?.task) {
      throw new NeedsInput('TASK_UNREADABLE', `${taskId}: ${row.code ?? 'no-task'} ${row.message ?? ''}`.slice(0, 300));
    }
    return row.data.task;
  }

  /** The edge's guard is read out of the FROZEN transition table, never re-declared. */
  async transition(step, { task, toState, principal, actorKind, reason, extra = {} }) {
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
    }, { principal, actorKind });
    this.transitions.push({
      step, task_id: task.task_id, from_state: from, to_state: toState,
      decision: row.outcome === 'ACCEPT' ? 'ACCEPT' : 'REFUSE',
      code: row.code ?? null, actor: principal.principal_id, actor_kind: actorKind,
      idempotency_key: row.idempotency_key,
    });
    return row;
  }
}

// ===========================================================================
// The transport observation ladder
// ===========================================================================
// The keys a crossing record MAY carry, and the aliases the observation ladder
// accepts for each. Kept next to the ladder so a new alias is one edit.
const EXECUTOR_OBSERVATION_ALIASES = Object.freeze([
  'argv', 'bin', 'command', 'cwd', 'env_names', 'env', 'exit_code', 'exitCode', 'signal',
  'pid', 'pgid', 'session_id', 'sessionId', 'thread_id', 'model_id', 'model', 'usage',
  'wall_ms', 'duration_ms', 'stdout_path', 'stderr_path', 'raw_logs', 'error',
]);

/**
 * What the executor's own parent observed about the crossing.
 *
 * FINDING (run-driver review #2), APPLIED IN FULL. The ladder used to read a
 * `transport.crossings` / `transport.lastCrossing` field that the real transport
 * does not have, so it ALWAYS returned `available:false` and the gate built on
 * it was dead. It now reads the two surfaces that really exist and that are
 * genuinely parent-side:
 *
 *   1. `transport.processObservation` — the pid, the process group, the exit
 *      code and the signal the PARENT saw;
 *   2. the raw process log the transport WROTE, re-read here FROM DISK. That is
 *      not the transport reporting on itself: it is this driver parsing bytes
 *      it is about to publish, with the digest it is about to record.
 *
 * A field either surface does not carry stays `null` and is named in `missing`.
 * A gap filled with a guess is exactly how a run record stops being evidence.
 *
 * `readRawProcessLog` is the one reader both surfaces go through, so the argv
 * evidence below and the observation beside it can never disagree about which
 * bytes they read.
 */
function readRawProcessLog(transport) {
  const logs = Array.isArray(transport?.rawLogs) ? transport.rawLogs : [];
  const first = logs.find((entry) => isPlainRecord(entry) && typeof entry.path === 'string') ?? null;
  if (first === null) return { log: null, path: null, entry: null, logs };
  try {
    return { log: JSON.parse(fs.readFileSync(first.path, 'utf8')), path: first.path, entry: first, logs };
  } catch {
    return { log: null, path: first.path, entry: first, logs };
  }
}

/**
 * THE CONFIGURATION AXIS, as the driver observed it executing (issue #45,
 * round 3). Both digests are published, always both: the raw one is the exact
 * argv the OS received (which carries the per-run project copy, the per-run
 * `--output-last-message` path and the run id), and the normalised one has
 * exactly those folded out. A comparison asserts on the NORMALISED digest; the
 * raw one is published so a reader can check that the normalisation removed the
 * run and not the surface.
 *
 * `config_delta` is DERIVED from the axis the argv really carried, never from
 * the `--config` label the driver was invoked with: a label that selected
 * nothing is `none`, and a label that selected a real surface is that surface's
 * axis. That is the only way a "no configuration difference" cell can be
 * detected instead of assumed.
 */
function extractArgvEvidence(transport, configuration) {
  const { log } = readRawProcessLog(transport);
  const invocation = isPlainRecord(log?.invocation) ? log.invocation : null;
  if (invocation === null) {
    return {
      observed: false,
      reason: 'the transport wrote no raw process log, so the argv it built, the surface it selected and both argv digests are UNOBSERVED by this driver',
      configuration: configuration ?? null,
      config_delta: 'none',
      configuration_axis: null,
      argv_digest_raw: null,
      argv_digest_normalised: null,
      argv: null,
    };
  }
  const axis = isPlainRecord(invocation.configuration_axis) ? invocation.configuration_axis : null;
  const distinguishable = axis?.distinguishable === true;
  return {
    observed: true,
    reason: null,
    configuration: invocation.configuration ?? null,
    configuration_name: invocation.configuration_name ?? null,
    configuration_note: invocation.configuration_note ?? null,
    configuration_surface_flags: Array.isArray(invocation.configuration_surface_flags) ? [...invocation.configuration_surface_flags] : [],
    config_delta: distinguishable ? 'context_surface' : 'none',
    config_delta_reason: distinguishable
      ? `this provider's configuration A and B select different flags, so the two ends are different commands; the axis this cell moved on is ${String(axis?.axis)}`
      : `this provider's configuration A and B select the IDENTICAL argv, so the ${String(configuration)} label moved nothing and this cell is config_delta none by construction`,
    configuration_axis: axis === null ? null : {
      axis: axis.axis ?? null,
      provider: axis.provider ?? null,
      configurations: Array.isArray(axis.configurations) ? [...axis.configurations] : [],
      configuration_a_flags: Array.isArray(axis.configuration_a_flags) ? [...axis.configuration_a_flags] : [],
      configuration_b_flags: Array.isArray(axis.configuration_b_flags) ? [...axis.configuration_b_flags] : [],
      distinguishable,
      reason: axis.reason ?? null,
      exclusion: axis.exclusion ?? null,
    },
    argv_digest_raw: invocation.argv_digest_raw ?? null,
    argv_digest_normalised: invocation.argv_digest_normalised ?? null,
    argv: Array.isArray(invocation.argv) ? invocation.argv.map((item) => redact(String(item))) : null,
    argv_normalised: Array.isArray(invocation.argv_normalised) ? invocation.argv_normalised.map((item) => redact(String(item))) : null,
    argv_normalisation: isPlainRecord(invocation.argv_normalisation) ? invocation.argv_normalisation : null,
    observed_by: 'the raw process log the transport wrote, re-read by this driver from the bytes it publishes; the log is the transport\'s own record of what it handed the OS, and the digests above are the digests of those bytes',
  };
}

/**
 * The configuration axis AS THIS CELL EXECUTED IT, aggregated over the cell's
 * runs. A cell is one surface on one provider, so a cell that published two
 * different NORMALISED digests for the same provider did not run one command
 * twice — it ran two different commands inside one cell, which is reported as
 * `digests_agree: false` and never averaged.
 */
function cellConfigurationAxis(runs) {
  const byProvider = new Map();
  for (const row of runs) {
    const key = `${String(row.provider)}|${String(row.adapter_id)}`;
    if (!byProvider.has(key)) byProvider.set(key, []);
    byProvider.get(key).push(row);
  }
  const perProvider = [...byProvider.entries()].map(([key, rows]) => {
    const observed = rows.filter((row) => row.argv?.observed === true);
    const digests = [...new Set(observed.map((row) => String(row.argv.argv_digest_normalised)))];
    const deltas = [...new Set(observed.map((row) => String(row.argv.config_delta)))];
    const axis = observed.find((row) => isPlainRecord(row.argv.configuration_axis))?.argv.configuration_axis ?? null;
    return {
      provider: key.split('|')[0],
      adapter_id: key.split('|')[1],
      runs: rows.length,
      runs_with_an_observed_argv: observed.length,
      config_delta: deltas.length === 1 ? deltas[0] : [...deltas].sort(),
      config_delta_agrees_across_runs: deltas.length <= 1,
      argv_digest_raw: [...new Set(observed.map((row) => String(row.argv.argv_digest_raw)))],
      argv_digest_normalised: digests,
      normalised_digest_agrees_across_runs: digests.length <= 1,
      axis_distinguishable: axis?.distinguishable ?? null,
      exclusion: axis?.exclusion ?? null,
      reason: axis?.reason ?? null,
    };
  });
  return {
    axis: 'context_surface',
    basis: 'the argv the transport really built, read back from the raw process log it wrote; a comparison asserts on argv_digest_normalised, never on argv_digest_raw',
    providers: perProvider,
    excluded_providers: perProvider.filter((row) => row.axis_distinguishable === false).map((row) => row.provider),
  };
}

/**
 * Put the axis evidence on the run record. `config_delta` is the string the
 * measurement layer reads, and it is `none` for every run that has not been
 * observed to carry a real surface difference — which is the correct value for a
 * run with no raw process log, and never a rounding-up of one.
 */
function publishArgvEvidence(record, transport, configuration) {
  const argv = extractArgvEvidence(transport, configuration);
  record.argv = argv;
  record.config_delta = argv.config_delta;
  return argv;
}

function extractExecutorObservation(transport) {
  const parent = isPlainRecord(transport?.processObservation) ? transport.processObservation : null;
  const { log, path: logPath, entry: first, logs } = readRawProcessLog(transport);
  if (parent === null && log === null) {
    return {
      available: false,
      reason: 'the transport published no parent-side process observation and wrote no raw process log; argv, exit code, session id and pid are therefore UNOBSERVED by this driver',
      reported: null,
      missing: ['argv', 'cwd', 'exit_code', 'session_id', 'pid', 'usage'],
    };
  }
  const invocation = isPlainRecord(log?.invocation) ? log.invocation : {};
  const usage = isPlainRecord(log?.usage) ? log.usage : null;
  // The exit code is only an OBSERVATION when the two parent-side sources agree
  // with each other: the live process observation and the log the parent wrote.
  const logExit = log?.exit_status ?? null;
  const parentExit = parent?.exit_code ?? null;
  const exitAgrees = logExit !== null && parentExit !== null && Number(logExit) === Number(parentExit);
  const reported = {
    argv: Array.isArray(invocation.argv) ? invocation.argv.map((item) => redact(String(item))) : null,
    bin: isPlainRecord(log?.executor) ? redact(String(log.executor.binary_named_path ?? '')) : null,
    cwd: invocation.cwd === undefined ? null : redact(String(invocation.cwd)),
    env_names: Array.isArray(invocation.environment_keys) ? invocation.environment_keys.map((item) => redact(String(item))).slice(0, 64) : null,
    exit_code: exitAgrees ? Number(logExit) : null,
    exit_code_agreement: exitAgrees ? 'the live process observation and the published log carry the same exit status' : 'the two parent-side sources do not agree, so the exit code is reported as UNOBSERVED',
    signal: parent?.signal ?? log?.signal ?? null,
    pid: Number.isInteger(parent?.pid) ? parent.pid : null,
    pgid: Number.isInteger(parent?.pgid) ? parent.pgid : null,
    session_id: usage?.executor_session_id === undefined || usage?.executor_session_id === null ? null : redact(String(usage.executor_session_id)),
    model_id: usage?.model_id === undefined || usage?.model_id === null ? null : redact(String(usage.model_id)),
    usage: usage === null ? null : deepRedact(usage),
    stdout_path: logPath,
    raw_logs: logs.length === 0 ? null : logs.map((entry) => ({ path: entry.path, sha256: entry.sha256, bytes: entry.bytes ?? null })),
    error: log?.provider_error === undefined || log?.provider_error === null ? null : redact(JSON.stringify(log.provider_error)).slice(0, 400),
    observed_by: {
      process_observation: parent === null ? null : 'the transport\'s parent-side view of the child (pid, pgid, exit code, signal)',
      raw_process_log: first === null ? null : 're-read by this driver from the bytes it publishes, with the digest it records',
    },
  };
  // `missing` names the REPORTED fields neither surface filled in. It is
  // computed from the reported object, not from the list of keys the transport
  // might have used, so an alias the driver looked for twice cannot report a
  // present field as missing.
  const missing = Object.entries(reported)
    .filter(([key, value]) => !ALWAYS_PRESENT_OBSERVATION_FIELDS.has(key) && (value === null || value === undefined))
    .map(([key]) => key);
  return { available: true, reason: null, reported, missing };
}

// Fields of the observation that are narrative rather than measurements: a null
// there is not a missing observation, so it must not trip the gate.
const ALWAYS_PRESENT_OBSERVATION_FIELDS = new Set(['exit_code_agreement', 'observed_by']);

function isPlainRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Raw logs this driver is about to publish: bytes, digest, and a credential scan. */
function describeRawLogs(rawDir) {
  if (!fs.existsSync(rawDir)) return { directory: displayPath(rawDir), files: [], withheld: [] };
  const files = [];
  const withheld = [];
  for (const name of fs.readdirSync(rawDir).sort()) {
    const absolute = path.join(rawDir, name);
    if (!fs.statSync(absolute).isFile()) continue;
    const buffer = fs.readFileSync(absolute);
    const text = buffer.toString('utf8');
    const hit = CREDENTIAL_PATTERNS.findIndex((pattern) => pattern.test(text));
    if (hit >= 0) {
      // The bytes are NOT published and NOT rewritten: a raw artefact that
      // trips the repository's own credential scan is withheld with the exact
      // reason, and the run is reported non-zero.
      fs.rmSync(absolute, { force: true });
      withheld.push({
        file: name,
        pattern_index: hit,
        pattern: CREDENTIAL_PATTERNS[hit].toString(),
        bytes: buffer.length,
        reason: 'credential-shaped literal detected by the same patterns scripts/check-public-artifacts.mjs scans; the raw bytes were withheld, not published and not rewritten',
      });
      continue;
    }
    files.push({ file: name, bytes: buffer.length, sha256: createHash('sha256').update(buffer).digest('hex') });
  }
  return { directory: displayPath(rawDir), files, withheld };
}

// ===========================================================================
// The campaign ledger: the enforcement of a cap the board cannot enforce
// ===========================================================================
/**
 * Read the campaign ledger, refusing to start a run whose dispatch would pass
 * the stop fraction. The ledger is a plain JSON file of self-reported spend: the
 * board's grant row is task-scoped at this HEAD, so nothing in the store knows
 * about a campaign that spans invocations of this driver. A ledger that is
 * missing is a fresh campaign; a ledger that cannot be parsed is a refusal, never
 * a reset — silently restarting the counter at zero is how a cap gets passed.
 */
function readCampaignLedger(absolutePath, { grantId, capUsd, stopFraction }) {
  if (!fs.existsSync(absolutePath)) {
    return { path: displayPath(absolutePath), existed: false, entries: [], total_usd: 0, readable: true };
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
  } catch (error) {
    throw new NeedsInput('CAMPAIGN_LEDGER_UNREADABLE', `${displayPath(absolutePath)} exists and could not be parsed; a ledger this driver cannot read is not a ledger it may reset`);
  }
  if (!isPlainRecord(parsed) || !Array.isArray(parsed.entries)) {
    throw new NeedsInput('CAMPAIGN_LEDGER_MALFORMED', `${displayPath(absolutePath)} is not a campaign ledger this driver wrote`);
  }
  if (typeof parsed.grant_id === 'string' && parsed.grant_id !== grantId) {
    throw new NeedsInput('CAMPAIGN_LEDGER_GRANT_MISMATCH', `${displayPath(absolutePath)} accumulates grant ${parsed.grant_id}, this run was given ${grantId}; one ledger, one grant`);
  }
  const total = parsed.entries.reduce((sum, row) => sum + (Number.isFinite(Number(row?.usd)) ? Number(row.usd) : 0), 0);
  return {
    path: displayPath(absolutePath),
    existed: true,
    entries: parsed.entries,
    total_usd: Number(total.toFixed(8)),
    readable: true,
    cap_usd: capUsd,
    stop_fraction: stopFraction,
  };
}

/** The typed refusal a campaign stop produces. Exit 3: a precondition, not a failure. */
function assertCampaignHeadroom(ledger, { capUsd, stopFraction }) {
  const stopAt = capUsd * stopFraction;
  if (ledger.total_usd >= stopAt) {
    throw new NeedsInput('CAMPAIGN_STOP_REACHED', `the campaign ledger already holds ${ledger.total_usd} USD, at or past the ${stopFraction * 100}% stop (${stopAt} USD) of the ${capUsd} USD cap; no executor is dispatched`);
  }
}

/** Append this invocation's settled spend. Called after the record is written. */
function appendCampaignLedger(absolutePath, { grantId, capUsd, stopFraction, runRows, invocation }) {
  let existing = { entries: [] };
  if (fs.existsSync(absolutePath)) {
    try { existing = JSON.parse(fs.readFileSync(absolutePath, 'utf8')); } catch { existing = { entries: [] }; }
  }
  const rows = runRows.map((row) => ({
    run_id: row.run_id ?? null,
    label: row.label,
    adapter: row.adapter_id ?? row.provider ?? null,
    configuration: invocation.configuration,
    usd: Number.isFinite(Number(row.cost?.settled_amount)) ? Number(row.cost.settled_amount) : 0,
    cost_basis: row.cost?.cost_basis ?? null,
  }));
  const entries = [...(Array.isArray(existing.entries) ? existing.entries : []), ...rows];
  const total = entries.reduce((sum, row) => sum + (Number.isFinite(Number(row?.usd)) ? Number(row.usd) : 0), 0);
  const document = {
    record_kind: 's2-007r-campaign-ledger',
    ticket: TICKET,
    grant_id: grantId,
    currency: CURRENCY,
    cap_usd: capUsd,
    stop_fraction: stopFraction,
    stop_at_usd: Number((capUsd * stopFraction).toFixed(6)),
    budget_authority: BUDGET_AUTHORITY,
    budget_approval_owner: BUDGET_APPROVAL_OWNER,
    accounting: 'self-reported executor spend only; an executor that reports no monetary cost contributes 0 and is marked NO_USD_REPORTED_BY_EXECUTOR rather than being priced from a list',
    total_usd: Number(total.toFixed(8)),
    entries,
  };
  fs.writeFileSync(absolutePath, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o644 });
  return { path: displayPath(absolutePath), appended: rows, total_usd: document.total_usd, entries: entries.length };
}

// ===========================================================================
// The provenance bootstrap: ONE crossing, outside the board, whose only job is
// to be a crossing. See the header block "THE PROVENANCE BOOTSTRAP".
//
// It is a real transport, the real installed binary, a real process group, a
// real raw process log on disk and a real exit status observed by THIS process.
// What it is not: a task, a lease, a grant, an outbox row, a board row, a run.
// No board command is called from here, and the record says `governed: false`.
//
// The record this returns is the transport's OWN `evidenceRecord()`, i.e. the
// object identity `evidence-writer.mjs` refuses to accept from anywhere else. If
// the crossing does not produce a non-zero observed exit with a raw log on disk,
// this returns null and the registration stays NOT_RUN_REAL_ADAPTER — which the
// board then refuses, which is the honest outcome and not a workaround.
// ===========================================================================
async function provenanceBootstrap({ run, key, spec, rawLogDir }) {
  const binding = run.executors.binding;
  const bootstrapRunId = `run-bootstrap-${key}-${run.options.seedSlug}`;
  const started = process.hrtime.bigint();
  const report = {
    provider: spec.provider,
    adapter_id: spec.adapter_id,
    run_id: bootstrapRunId,
    governed: false,
    is_a_run: false,
    board_commands_called: 0,
    task_id: null,
    lease_id: null,
    fencing_token: null,
    grant_id: null,
    model: BOOTSTRAP_MODEL,
    model_rationale: 'a model id the provider cannot resolve: the CLI really starts and really answers with a non-zero exit, and no token is billed',
    configuration: BOOTSTRAP_CONFIGURATION,
    configuration_note: 'the surface is a validated argument of the transport, and the bootstrap names the provider-documented default end (A: no suppression flag). It is NOT a cell of the A/B comparison: no result is collected here, no task exists, and nothing below differences it against another crossing.',
    workspace_root: run.options.workspaceRoot,
    raw_log_dir: displayPath(rawLogDir),
    events: [],
    outcome: null,
    exit_status: null,
    exit_observed: null,
    process: null,
    raw_logs: [],
    evidence: null,
    spend: { usd: null, basis: 'UNMEASURED', tokens: null },
    error: null,
    what_this_establishes: 'this adapter_id is a genuinely installed CLI that really crossed a process boundary and reported its own session id; its REGISTRATION may therefore be corroborated by a real observed crossing',
    what_this_does_not_establish: [
      'this is not a run: nothing below upgrades any run\'s realAdapterStatus, and this crossing contributes to no measurement and to no comparison cell',
      'no task ran: there is no task, lease, grant, outbox row or board row in this crossing',
      'no answer of any quality: the model id is unresolvable and nothing was asked',
      "no run's realAdapterStatus moved: only the governed runs below, whose results the parent collected, can do that",
    ],
    wall_ms: null,
  };
  let transport;
  try {
    // A NOT_RUN_REAL_ADAPTER registration is enough to start a crossing: the
    // transport requires a MINTED registration and the floor permit, and it does
    // not require the provenance to be lifted. Lifting it is what the record
    // below is for.
    const registration = binding.createRegistration({
      adapterId: spec.adapter_id,
      provider: spec.provider,
      displayName: `${spec.provider} CLI (installed on this host)`,
      health: 'healthy',
      clock: injectedClock(run.clock),
      ids: run.ids.boundary,
      workspaceId: WORKSPACE_ID,
      principalId: P.producer,
      declaredCapabilities: [...spec.declared_capabilities],
      declaredTools: [...spec.declared_tools],
      sandboxProfileId: FLOOR_PROFILE,
      unisolatedExecutionAuthorization: UNISOLATED_AUTHORIZATION,
      realRunEvidence: null,
    });
    transport = await binding.createTransport(spec.provider, {
      adapterId: spec.adapter_id,
      provider: spec.provider,
      registration,
      clock: injectedClock(run.clock),
      now: () => run.now(),
      ids: run.ids.boundary,
      workspaceId: WORKSPACE_ID,
      workspaceRoot: run.options.workspaceRoot,
      workspaceRoots: run.options.workspaceRoot ? [run.options.workspaceRoot] : [],
      realpath: fs.realpathSync,
      executorPath: resolveExecutable(spec.binary),
      evidenceDir: rawLogDir,
      rawLogDir,
      principalId: P.producer,
      sandboxProfileId: FLOOR_PROFILE,
      unisolatedExecutionAuthorization: UNISOLATED_AUTHORIZATION,
      grant: { capabilities: [...spec.declared_capabilities], tools: [...spec.declared_tools] },
      allowedTools: ['tool:fs.read'],
      toolBindings: {},
      // The surface is a REQUIRED, VALIDATED argument (issue #45, round 3): a
      // transport that is not told which context surface it was given cannot be
      // one half of a comparison, and defaulting it would make every unmarked
      // run a silent B cell. So the bootstrap names a real end of the axis. It
      // is NOT a cell of the comparison and takes no part in one: it collects no
      // ExecutionResult, opens no task and asserts nothing about a delta. `A` is
      // named because it is the provider's documented default behaviour — no
      // suppression flag is passed — which keeps the bootstrap argv identical to
      // what the provider would do with no configuration argument at all. The
      // report below says the same thing where a reader of the record sees it.
      configuration: BOOTSTRAP_CONFIGURATION,
      prompt: BOOTSTRAP_PROMPT,
      model: BOOTSTRAP_MODEL,
      timeoutMs: BUDGET_TIMEOUT_MS,
      cancelGraceMs: 2000,
    });
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'AGENT_UNAVAILABLE');
    report.error = { code: typed.code, message: deepRedact(String(typed.message ?? typed)).slice(0, 300) };
    return report;
  }

  // The request the transport adjudicates. It is shaped exactly like the board's
  // own ExecutionRequest so the transport exercises the same admission path a
  // governed run does, and it names the floor profile with the permit. The
  // frozen schema REQUIRES a task id, a lease and a budget row, so this crossing
  // carries the operator's declared numbers and a `bootstrap` identity: those
  // values satisfy the CONTRACT, they do not name a board row, and the report
  // says so where a reader can see them.
  const request = {
    contract_version: 'veritas.execution/1.0.0',
    request_id: `xer-bootstrap-${key}-${run.options.seedSlug}`,
    idempotency_key: createHash('sha256').update(`bootstrap:${key}:${run.options.seedSlug}`).digest('hex'),
    task_id: `abt-bootstrap-${key}-${run.options.seedSlug}`,
    workspace_id: WORKSPACE_ID,
    brief_digest: wireDigest({ kind: 'bootstrap', provider: spec.provider }),
    policy_digest: wireDigest({ kind: 'bootstrap-policy', profile: FLOOR_PROFILE }),
    manifest_digest: wireDigest({ kind: 'bootstrap-manifest' }),
    principal_id: P.producer,
    // The board's OWN default run scope, verbatim: `DEFAULT_RUN_SCOPE` in
    // src/lib/agentboard/commands.mjs:380. A governed run's request carries
    // exactly this, so the bootstrap request carries it too and the transport
    // cross-checks the same pair of sets it would cross-check for a real run.
    granted_scope: ['task.read', 'artifact.write'],
    allowed_tools: ['tool:fs.read'],
    workspace_ref: {
      workspace_id: WORKSPACE_ID,
      root_ref: 'bootstrap',
      isolation_profile_id: FLOOR_PROFILE,
      sandbox_profile_digest: wireDigest({ profile: FLOOR_PROFILE }),
      read_only_paths: [],
    },
    budget_grant: {
      currency: CURRENCY,
      task_limit: run.options.taskLimit,
      campaign_limit: run.options.campaignLimit,
      day_limit: run.options.dayLimit,
      timeout_ms: BUDGET_TIMEOUT_MS,
      granted_by: P.owner,
      granted_at: run.now(),
    },
    deadline: null,
    lease_id: `lse-bootstrap-${key}-${run.options.seedSlug}`,
    fencing_token: 1,
    adapter_id: spec.adapter_id,
    issued_at: run.now(),
  };
  report.request_summary = {
    task_id: request.task_id,
    lease_id: request.lease_id,
    fencing_token: request.fencing_token,
    root_ref: request.workspace_ref.root_ref,
    isolation_profile_id: request.workspace_ref.isolation_profile_id,
    budget_grant: request.budget_grant,
    budget_row_note: 'the frozen ExecutionRequest contract requires a budget row, so the request carries the operator\'s declared numbers; no agentboard_budget row exists for this crossing and nothing is settled against it',
  };
  try {
    const accepted = await transport.start(request, { run_id: bootstrapRunId });
    if (isEventDocument(accepted)) {
      report.events.push({ sequence: accepted.sequence, event_type: accepted.event_type, outcome: accepted.outcome ?? null });
    }
    // Drain the transport's own event stream, the same way the governed path
    // does: one status() call per event, stopping at the terminal one. The
    // events are NOT submitted to any board command: there is no board run.
    for (let round = 0; round < 64; round += 1) {
      const status = await transport.status({
        run_id: bootstrapRunId, task_id: request.task_id, lease_id: request.lease_id, fencing_token: request.fencing_token, at: run.now(),
      });
      if (!isEventDocument(status)) break;
      if (report.events.some((row) => row.sequence === status.sequence)) break;
      report.events.push({ sequence: status.sequence, event_type: status.event_type, outcome: status.outcome ?? null });
      if (TERMINAL_EVENT_TYPES.has(status.event_type)) break;
    }
    const collected = await transport.collect_result({
      run_id: bootstrapRunId, task_id: request.task_id, lease_id: request.lease_id, fencing_token: request.fencing_token, at: run.now(),
    });
    const document = isPlainRecord(collected) && isPlainRecord(collected.result) ? collected.result : collected;
    report.outcome = isPlainRecord(document) ? (document.outcome ?? null) : null;
    if (isPlainRecord(document) && isPlainRecord(document.error)) {
      report.result_error = { code: document.error.code ?? null, message: deepRedact(String(document.error.message ?? '')).slice(0, 200) };
    }
    // The executor's OWN reported usage, and nothing else. On this host a
    // bootstrap crossing bills nothing (the model id cannot be resolved), and the
    // record says what the executor reported rather than what that ought to be.
    const measurements = isPlainRecord(document) && isPlainRecord(document.measurements) ? document.measurements : null;
    const reportedSpend = measurements !== null && Number.isFinite(Number(measurements.spend)) ? Number(measurements.spend) : null;
    report.spend = {
      usd: reportedSpend,
      basis: reportedSpend === null ? 'NO_USD_REPORTED_BY_EXECUTOR' : 'EXECUTOR_REPORTED_USD',
      tokens: measurements?.usage_tokens ?? null,
      note: 'the bootstrap crossing asks for a model id that cannot be resolved, so the measured expectation is 0 billed tokens; the value published here is what the executor itself reported, and a null means it reported no monetary cost at all',
    };
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'AGENT_UNAVAILABLE');
    report.error = { code: typed.code, message: deepRedact(String(typed.message ?? typed)).slice(0, 300) };
  }
  report.wall_ms = Math.round(Number((process.hrtime.bigint() - started) / 1000n) / 1000);
  const observation = isPlainRecord(transport.processObservation) ? transport.processObservation : null;
  report.process = observation === null ? null : {
    pid: observation.pid,
    pgid: observation.pgid,
    process_group_signalling: observation.process_group_signalling,
    exit_code: observation.exit_code,
    signal: observation.signal,
    cause: observation.cause,
    observed_pids: observation.observed_pids,
    isolation_observed: false,
  };
  report.exit_status = observation?.exit_code ?? null;
  report.exit_observed = Number.isInteger(report.exit_status);
  report.raw_logs = (transport.rawLogs ?? []).map((entry) => ({
    path: displayPath(entry.path), bytes: entry.bytes ?? null, sha256: entry.sha256 ?? null,
  }));
  // The argv this bootstrap really built, with BOTH digests, so a reader can see
  // the surface it was given without opening the raw log. It is recorded for
  // reproducibility; the bootstrap takes no part in the comparison and this
  // digest is never differenced against another crossing.
  report.argv = extractArgvEvidence(transport, BOOTSTRAP_CONFIGURATION);
  report.evidence = typeof transport.evidenceRecord === 'function' ? transport.evidenceRecord() : null;
  if (report.evidence === null) {
    report.evidence_refusal = 'the transport minted no evidence record: no crossing was performed, or its exit was never observed';
  } else {
    report.evidence_summary = {
      run_id: report.evidence.run_id,
      provider: report.evidence.executor.provider,
      binary_path: displayPath(report.evidence.executor.binary_path),
      binary_sha256: report.evidence.executor.binary_sha256,
      raw_process_log_sha256: report.evidence.raw_process_log_sha256,
      exit_status: report.evidence.exit_status,
      exit_observed: report.evidence.exit_observed,
    };
  }
  return report;
}

// ===========================================================================
// Registration: both real adapters, verified against the frozen schema
// ===========================================================================
async function registerAdapters({ run, adapterKeys, probeRows, bootstrap }) {
  const binding = run.executors.binding;
  const registrations = [];
  for (const key of adapterKeys) {
    const spec = ADAPTERS[key];
    const registration = binding.createRegistration({
      adapterId: spec.adapter_id,
      provider: spec.provider,
      displayName: `${spec.provider} CLI (installed on this host)`,
      health: 'healthy',
      clock: injectedClock(run.clock),
      ids: run.ids.boundary,
      workspaceId: WORKSPACE_ID,
      principalId: P.producer,
      declaredCapabilities: [...spec.declared_capabilities],
      declaredTools: [...spec.declared_tools],
      sandboxProfileId: FLOOR_PROFILE,
      // The permit, handed to the transport so it adjudicates the SAME
      // authorisation the command boundary adjudged. A transport that received
      // the profile without the permit would have to invent one.
      unisolatedExecutionAuthorization: UNISOLATED_AUTHORIZATION,
      // The corroborating record, when this provider's bootstrap crossing
      // produced one. It is the transport's own object, minted in this process
      // from the exit this process observed; `createRealRegistration` re-adjudicates
      // it against the bytes on disk and refuses anything weaker.
      realRunEvidence: bootstrap?.get(key)?.evidence ?? null,
    });
    if (!isPlainRecord(registration)) {
      throw new MalformedResult('REGISTRATION_MALFORMED', `${spec.adapter_id}: ${binding.id} returned no registration document`);
    }
    // The frozen wire schema is the authority, and it is re-checked here, by
    // the driver, before the document reaches the boundary.
    const schemaErrors = boardContractErrors('adapter-registration', registration);
    if (schemaErrors.length > 0) {
      throw new MalformedResult('REGISTRATION_SCHEMA_INVALID', `${spec.adapter_id}: ${schemaErrors.slice(0, 3).join('; ').slice(0, 300)}`);
    }
    const probeRow = probeRows.find((row) => row.adapter_id === spec.adapter_id) ?? null;
    registrations.push({
      key,
      spec,
      registration,
      schema_valid: true,
      probe_row: probeRow,
      digest: wireDigest(registration),
      provenance_status: registration.real_adapter_provenance?.status ?? null,
      provenance_detail: deepRedact(String(registration.real_adapter_provenance?.detail ?? '')).slice(0, 500),
      corroborated_by: bootstrap?.get(key)?.evidence_summary ?? null,
    });
  }
  return registrations;
}

// ===========================================================================
// One run, end to end
// ===========================================================================
async function runOneTask({ run, index, source, budget, registration, rawLogDir }) {
  // The ACCEPTED event `start()` emits is returned to `driveOutbox`, which
  // keeps it for itself, so the wrapper captures it: without it the event
  // stream would start at 2 and the store would refuse every event. It is
  // declared at the TOP of this function, not next to the call that reads
  // it: a `const` read above its own declaration is a temporal-dead-zone
  // ReferenceError, and round 3 saw exactly that as PROVIDER_FAILURE.
  const capture = { dispatchReturn: undefined };
  const spec = ADAPTERS[registration.key];
  const label = String(index).padStart(2, '0');
  const taskId = `abt-s2007r-${run.options.seedSlug}-${label}`;
  const runRoot = path.join(run.options.workspaceRoot, `run-${label}`);
  const record = {
    index,
    label,
    task_id: taskId,
    adapter_id: spec.adapter_id,
    provider: spec.provider,
    configuration: run.options.configuration,
    // THE CONFIGURATION AXIS, as executed. Until the transport has written a
    // raw process log there is no argv to read, so the cell is `config_delta
    // none` and says why. The value is replaced the moment the log exists, and
    // it is always derived from the argv, never from the --config label.
    config_delta: 'none',
    argv: {
      observed: false,
      reason: 'this run has not produced a raw process log yet, so the argv it built and the surface it selected are UNOBSERVED by this driver',
      configuration: run.options.configuration,
      config_delta: 'none',
      configuration_axis: null,
      argv_digest_raw: null,
      argv_digest_normalised: null,
      argv: null,
    },
    transport_source: spec.transport_source,
    findings: [],
    events: [],
    raw_logs: null,
    verdict: 'NOT_RUN',
  };

  // --- 0. a fresh copy of the ONE project, and its digest, BEFORE anything ---
  const copy = materialiseRunProject(source, runRoot);
  record.project = {
    source: source.requested,
    source_realpath: source.realpath,
    workspace_root_ref: `run-${label}/project`,
    workspace_root_absolute: copy.realpath,
    workspace_root_source: 'INJECTED_NOT_REGISTRY',
    workspace_root_note: 'the S2-002 workspace registry holds Windows roots only (src/lib/identity/principals.mjs), so containment came from the documented execute({workspaceRoots, realpath}) injection point; the registry did not authorise this root',
    digest_before: copy.digest,
    file_count: copy.fileCount,
    total_bytes: copy.totalBytes,
  };

  // --- 1. the task, through the command boundary ---------------------------
  const goal = 'Inventory the project in the workspace and report its files with their line counts.';
  const createdAt = run.instant();
  const acceptanceCriteria = [
    'A file inventory of the workspace is reported as the run result.',
    'No file in the workspace is modified: the project digest before and after the run is identical.',
    'The executor process is a real installed CLI, and its own output is recorded as the run record.',
  ];
  const taskDocument = {
    contractVersion: '1.0.0',
    task_id: taskId,
    workspace_id: WORKSPACE_ID,
    title: `S2-007R real adapter run ${label} (${spec.provider}/${run.options.configuration})`,
    goal,
    description: 'S2-007R: one bounded, read-only unit of work executed by a real installed executor through veritas.execution/1.0.0.',
    acceptance_criteria: acceptanceCriteria,
    state: 'BACKLOG',
    revision: 1,
    priority: 'HIGH',
    dependencies: [],
    required_capabilities: ['source.read'],
    // FINDING (run-driver review #7), APPLIED: the task's goal and acceptance
    // criteria forbid modification, so the grant is READ-ONLY. The adapter still
    // declares more (a registration may declare a superset of what one task is
    // granted), but the boundary narrows upward from here, and the post-hoc
    // project-digest check is a second control rather than the only one. The
    // child therefore physically cannot reach a tool the board did not grant.
    allowed_tools: ['tool:fs.read'],
    workspace_ref: {
      workspace_id: WORKSPACE_ID,
      root_ref: `run-${label}/project`,
      isolation_profile_id: FLOOR_PROFILE,
      sandbox_profile_digest: wireDigest({ profile: FLOOR_PROFILE }),
      read_only_paths: [],
    },
    time_limits: { timeout_ms: BUDGET_TIMEOUT_MS, max_runtime_ms: BUDGET_TIMEOUT_MS, deadline: null },
    cost_limits: {
      currency: CURRENCY,
      max_task_cost: budget.task_limit,
      max_campaign_cost: budget.campaign_limit,
      max_day_cost: budget.day_limit,
    },
    acl: { visibility: 'project', allowed_principal_ids: [...ACL] },
    brief_digest: wireDigest({ kind: 'brief', task: taskId, goal, acceptance_criteria: acceptanceCriteria, project: copy.digest }),
    policy_digest: wireDigest({ kind: 'policy', ticket: TICKET, boundary: 'commands.execute', profile: FLOOR_PROFILE }),
    manifest_digest: wireDigest({ kind: 'manifest', files: source.files }),
    assigned_adapter_id: null,
    active_lease_id: null,
    fencing_token: null,
    attempts: 0,
    artifacts: [],
    evidence_refs: [],
    block_reason: null,
    created_at: createdAt,
    updated_at: createdAt,
    history_digest: wireDigest({ kind: 'history', at: 'create' }),
  };
  record.task_document_digest = wireDigest(taskDocument);

  const created = await run.call(`create.${label}`, 'tasks.create', { task: taskDocument }, {
    principal: run.principal.owner, actorKind: 'human_owner',
  });
  if (created.outcome !== 'ACCEPT') {
    record.verdict = 'NOT_RUN';
    record.findings.push({ id: 'task-create-refused', code: created.code, message: created.message });
    return record;
  }

  // --- 2. the ONE budget, as this task's grant -----------------------------
  // MEASURED CONSTRAINT, not a choice: `store.createRun` looks the grant up by
  // `task_id` and refuses a workspace-scoped row with BUDGET_NOT_ASSIGNED
  // (src/lib/agentboard/store.mjs, "task ${id} has no live budget grant"), so a
  // single campaign-wide grant row cannot back a run at this HEAD. The ONE
  // budget is therefore the ONE number from `--budget`; the board receives one
  // grant ROW per task, all carrying that identical number, and the record says
  // so instead of pretending a campaign-wide grant existed.
  const grantDocument = {
    grant_id: `${budget.grant_id}-${label}`,
    workspace_id: WORKSPACE_ID,
    task_id: taskId,
    currency: CURRENCY,
    task_limit: budget.task_limit,
    campaign_limit: budget.campaign_limit,
    day_limit: budget.day_limit,
    timeout_ms: budget.timeout_ms,
    granted_by: P.owner,
    expires_at: null,
    revoked_at: null,
  };
  const grantId = grantDocument.grant_id;
  record.budget = {
    grant_id: grantId,
    one_budget_number: budget.amount,
    currency: CURRENCY,
    task_limit: budget.amount,
    campaign_limit: budget.amount,
    day_limit: budget.amount,
    timeout_ms: BUDGET_TIMEOUT_MS,
    authority: budget.authority,
    approval_owner: budget.approval_owner,
    grant_scope: 'TASK_SCOPED_ROW',
    grant_scope_reason: 'store.createRun resolves the grant by task_id and refuses a workspace-scoped row (BUDGET_NOT_ASSIGNED), so one task needs one grant row; every row carries the identical --budget number',
    grant_digest: wireDigest(grantDocument),
  };
  const granted = await run.call(`grant.${label}`, 'budget.grant', { grant: grantDocument }, {
    principal: run.principal.owner, actorKind: 'human_owner',
  });
  if (granted.outcome !== 'ACCEPT') {
    record.verdict = 'NOT_RUN';
    record.findings.push({ id: 'budget-grant-refused', code: granted.code, message: granted.message });
    return record;
  }

  // --- 2. BACKLOG -> READY, with the observed digests ------------------------
  const ready = await run.transition(`ready.${label}`, {
    task: await run.readTask(taskId), toState: 'READY',
    principal: run.principal.owner, actorKind: 'human_owner',
    reason: 'immutable brief validated, no open dependency, numeric budget assigned',
  });
  if (ready.outcome !== 'ACCEPT') {
    record.verdict = 'NOT_RUN';
    record.findings.push({ id: 'ready-refused', code: ready.code, message: ready.message });
    return record;
  }

  // --- 3. the scheduler's OWN decision, recorded next to the claim ----------
  // `dispatch.plan` is a READ and never fatal here. At this HEAD it is refused
  // with a typed PROVIDER_FAILURE carrying an untyped core defect
  // (`unisolatedExecutionAuthorization is not defined`, src/lib/agentboard/
  // scheduler.mjs planDispatch), and the driver records that refusal instead of
  // stepping around the boundary to produce a decision of its own.
  const plan = await run.call(`plan.${label}`, 'dispatch.plan', { workspace_id: WORKSPACE_ID }, {
    principal: run.principal.scheduler, actorKind: 'scheduler',
  });
  record.dispatched_decision = {
    derived_by: 'dispatch.plan (the scheduler\'s own deterministic order)',
    followed: false,
    reason_not_followed: 'selectAdapter sorts registered adapters by adapter_id ascending, so the derived decision can only ever reach adr-codex-local; the requested adapter is bound explicitly on the claim edge instead',
    decision: plan.outcome === 'ACCEPT' ? plan.data.decision : null,
    decision_digest: plan.outcome === 'ACCEPT' ? wireDigest(plan.data.decision) : null,
    refusal: plan.outcome === 'ACCEPT' ? null : { code: plan.code, typed: plan.typed, message: plan.message },
  };
  if (plan.outcome !== 'ACCEPT') {
    record.findings.push({
      id: 'dispatch-plan-unavailable',
      code: plan.code,
      message: plan.message,
      detail: 'the derived decision could not be read at this HEAD; the claim that follows binds the requested adapter explicitly and the decision column of this record is empty rather than reconstructed',
    });
  }

  // --- 4. the claim: lease + fencing token, in one transaction --------------
  const claim = await run.call(`claim.${label}`, 'tasks.claim', {
    task_id: taskId,
    adapter_id: spec.adapter_id,
    expected_revision: (await run.readTask(taskId)).revision,
    ttl_ms: BUDGET_TIMEOUT_MS,
  }, { principal: run.principal.scheduler, actorKind: 'scheduler' });
  if (claim.outcome !== 'ACCEPT' || !isPlainRecord(claim.data?.lease)) {
    record.verdict = 'NOT_RUN';
    record.findings.push({ id: 'claim-refused', code: claim.code ?? 'NO_LEASE', message: claim.message });
    return record;
  }
  const leaseId = claim.data.lease.lease_id;
  const fencingToken = Number(claim.data.lease.fencing_token);
  record.lease = { lease_id: leaseId, fencing_token: fencingToken, ttl_ms: BUDGET_TIMEOUT_MS, claimed_by: P.scheduler, actor_kind: 'scheduler' };
  run.transitions.push({
    step: `claim.${label}`, task_id: taskId, from_state: 'READY', to_state: 'CLAIMED',
    decision: 'ACCEPT', code: null, actor: P.scheduler, actor_kind: 'scheduler', idempotency_key: claim.idempotency_key,
  });

  // --- 5. CLAIMED -> RUNNING under the current fence ------------------------
  const running = await run.transition(`running.${label}`, {
    task: await run.readTask(taskId), toState: 'RUNNING',
    principal: run.principal.producer, actorKind: 'adapter',
    reason: 'the executor acknowledged the handoff under the current fence',
    extra: { fencing_token: fencingToken },
  });
  if (running.outcome !== 'ACCEPT') {
    record.verdict = 'NOT_RUN';
    record.findings.push({ id: 'running-refused', code: running.code, message: running.message });
    return record;
  }

  // --- 6. the real transport -------------------------------------------------
  if (!run.executors.binding.hasTransport(spec.provider)) {
    record.verdict = 'NOT_RUN';
    record.findings.push({ id: 'transport-factory-absent', detail: `${run.executors.dir} exports no transport factory for ${spec.provider}` });
    return record;
  }
  const prompt = buildPrompt({ taskId, goal, acceptanceCriteria, copy, spec, run });
  // The option bag carries BOTH naming conventions: the SPEC §2 tree takes
  // `projectRoot`/`workspaceRoot`/`allowedTools`, the single-module transport
  // takes `executorPath`/`evidenceDir`/`workspaceRoots`/`realpath`/`toolBindings`.
  // Extra keys are inert for a factory that does not read them, and every one of
  // them is derived from a fact this driver measured.
  const binaryPath = resolveExecutable(spec.binary);
  const transportOptions = {
    adapterId: spec.adapter_id,
    provider: spec.provider,
    registration: registration.registration,
    clock: injectedClock(run.clock),
    now: () => run.now(),
    ids: run.ids.boundary,
    workspaceId: WORKSPACE_ID,
    workspaceRoot: run.options.workspaceRoot,
    projectRoot: copy.realpath,
    workspaceRoots: run.options.workspaceRoot ? [run.options.workspaceRoot] : [],
    realpath: fs.realpathSync,
    executorPath: binaryPath,
    evidenceDir: rawLogDir,
    principalId: P.producer,
    sandboxProfileId: FLOOR_PROFILE,
    unisolatedExecutionAuthorization: UNISOLATED_AUTHORIZATION,
    // FINDING (run-driver review #6), APPLIED. Two separate things were both
    // called `budget` before and neither reached the transport: the transport
    // destructures `grant`, and it reads that object as the AUTHORITY SET
    // ({capabilities, tools}), not as a numeric row. The numeric row is passed
    // under its own name so any spend the executor self-reports is keyed to the
    // grant `budget.settle` actually writes.
    grant: {
      capabilities: [...spec.declared_capabilities],
      tools: [...spec.declared_tools],
    },
    budget_grant: {
      grant_id: grantDocument.grant_id,
      currency: CURRENCY,
      task_limit: budget.task_limit,
      campaign_limit: budget.campaign_limit,
      day_limit: budget.day_limit,
      timeout_ms: budget.timeout_ms,
    },
    configuration: run.options.configuration,
    config: run.options.configuration,
    prompt,
    allowedTools: taskDocument.allowed_tools,
    toolBindings: {},
    model: run.options.model,
    timeoutMs: BUDGET_TIMEOUT_MS,
    // Observation seams the driver offers. A transport that ignores them simply
    // leaves the record's corroboration fields null, which is reported as
    // UNOBSERVED rather than filled in.
    rawLogDir,
    // FINDING (run-driver review #13), APPLIED IN PART: the observation now
    // names the DRIVER's own liveness as such, and the executor's process group
    // is observed by the parent through `processObservation` (see
    // extractExecutorObservation). A field that reads like executor liveness and
    // is really the driver's own pid would be the same kind of lie.
    onCrossing: (crossing) => { record.crossing_reported_by_transport = deepRedact(crossing); },
  };
  let transport;
  try {
    transport = await run.executors.binding.createTransport(spec.provider, transportOptions);
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'AGENT_UNAVAILABLE');
    record.verdict = 'NOT_RUN';
    record.findings.push({ id: 'transport-construction-refused', code: typed.code, message: typed.message });
    return record;
  }
  // The board's own ten-method interface check, run by the driver before the
  // transport is handed to a command: an adapter that is not an adapter is
  // refused here, not discovered at the boundary.
  const dispatchTransport = observingTransport(transport, capture);
  try {
    // FINDING (run-driver review #12), APPLIED: the object the BOARD receives is
    // the wrapper, so the wrapper is what is checked. Checking the raw transport
    // left the boundary holding an object nothing had ever validated.
    assertAdapterInterface(dispatchTransport);
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'AGENT_UNAVAILABLE');
    record.verdict = 'NOT_RUN';
    record.findings.push({ id: 'transport-interface-refused', code: typed.code, message: typed.message });
    return record;
  }
  record.transport = {
    module: run.executors.dir,
    factory: `${spec.provider} transport factory of ${run.executors.source}`,
    // FINDING (run-driver review #11), APPLIED: DERIVED from the tree that was
    // resolved and the factory that was called, instead of a literal that named
    // a module this checkout may not contain.
    source: run.executors.binding.transportSource(spec.provider),
    adapter_interface_verified: true,
    interface_checked_on: 'the observing wrapper the boundary receives (not the raw transport)',
    configuration: run.options.configuration,
    model_requested: run.options.model ?? run.executors.binding.constants?.PI_MODEL_PINNED ?? null,
    model_pin_source: run.options.model ? 'operator flag --model' : `${run.executors.dir}#PI_MODEL_PINNED`,
  };
  record.prompt = { text_digest: wireDigest(prompt), bytes: Buffer.byteLength(prompt, 'utf8'), text: prompt };

  // --- 7. execution.start: the board mints the request, the run, the outbox --
  const start = await run.call(`start.${label}`, 'execution.start', { task_id: taskId, adapter_id: spec.adapter_id }, {
    principal: run.principal.producer, actorKind: 'adapter', transport,
  });
  const boardRun = start.outcome === 'ACCEPT' ? start.data.run : null;
  const request = start.outcome === 'ACCEPT' ? start.data.request : null;
  if (!isPlainRecord(boardRun) || !isPlainRecord(request)) {
    record.verdict = 'NOT_RUN';
    record.findings.push({ id: 'start-refused', code: start.code ?? 'NO_RUN', message: start.message });
    return record;
  }
  record.run_id = boardRun.run_id;
  // The sandbox decision the board itself resolved, quoted verbatim: the run and
  // the authorisation that let it start can never disagree, because a later
  // reader re-judges this same document.
  record.sandbox_decision = start.data.sandboxDecision ?? null;
  record.sandbox_decision_agrees_with_permit = isPlainRecord(start.data.sandboxDecision)
    ? start.data.sandboxDecision.authorization?.body_digest === UNISOLATED_AUTHORIZATION.body_digest
    : false;
  record.request = {
    request_id: request.request_id,
    idempotency_key: request.idempotency_key,
    contract_version: request.contract_version,
    granted_scope: request.granted_scope,
    allowed_tools: request.allowed_tools,
    budget_grant: request.budget_grant,
    principal_id: request.principal_id,
    request_digest: wireDigest(request),
    allowed_tools_digest: wireDigest(request.allowed_tools),
  };
  record.budget.request_view = request.budget_grant;
  if (typeof transport.bindRun === 'function') {
    // `ExecutionRequest` carries no run_id by design (SPEC D12), so the
    // correlation is bound from the response the boundary just committed.
    await transport.bindRun({
      requestIdempotencyKey: request.idempotency_key,
      runId: boardRun.run_id,
      taskId,
      workspaceId: WORKSPACE_ID,
      leaseId,
      fencingToken,
    });
    record.transport.run_correlation = 'bound from execution.start by request.idempotency_key (never guessed)';
  } else {
    record.transport.run_correlation = null;
    record.findings.push({ id: 'transport-bind-run-missing', severity: 'declared-limit', detail: 'the real transport exposes no bindRun(); its run correlation could not be established from the committed execution.start response' });
  }

  // --- 8. the crossing: outbox.dispatch with the real transport -------------
  const observer = createProcessObserver();
  const selfIdentity = observer.identityFor(process.pid);
  const before = await observer.listExisting([process.pid], { [process.pid]: selfIdentity });
  const started = process.hrtime.bigint();
  const dispatch = await run.call(`dispatch.${label}`, 'outbox.dispatch', { workspace_id: WORKSPACE_ID, limit: 8 }, {
    principal: run.principal.scheduler, actorKind: 'scheduler',
    transport: dispatchTransport,
  });
  const wallNs = process.hrtime.bigint() - started;
  const driverAfter = await observer.listExisting([process.pid], { [process.pid]: selfIdentity });
  record.outbox = {
    summary: dispatch.outcome === 'ACCEPT' ? dispatch.data.summary : null,
    refusal: dispatch.outcome === 'ACCEPT' ? null : { code: dispatch.code, message: dispatch.message },
    parent_wall_ms: Math.round(Number(wallNs / 1000n) / 1000),
  };
  record.observed_by_driver = {
    kind: 'PARENT_SIDE_MEASUREMENT',
    note: 'the wall clock and the process observation below were taken by THIS driver, around the outbox dispatch; the executor argv, exit code and usage are reported by the transport, which is the executor\'s own parent, and are labelled as reported',
    wall_clock_source: 'process.hrtime.bigint() (monotonic); the board clock is the injected counter and is never read from the process',
    process_observer: {
      id: observer.id,
      what_this_is: 'the DRIVER liveness and the driver process tree, NOT the executor. The executor is observed separately, by its own parent, in `executor`.',
      driver_pid: process.pid,
      driver_alive_before: before.alive.includes(process.pid),
      driver_alive_after: driverAfter.alive.includes(process.pid),
      identity_supported: before.identitySupported,
      descendant_enumeration: await descendantEnumerationReason(observer),
    },
  };
  const summary = record.outbox.summary;
  if (dispatch.outcome !== 'ACCEPT' || !isPlainRecord(summary)) {
    record.verdict = 'NOT_RUN';
    // The escalation REASON lives on the outbox row the boundary wrote, not on
    // the refusal this driver saw: `driveOutbox` records
    // `UNKNOWN_OUTCOME:<code>:<message>` when the transport throws, and that
    // string is the only place the transport's own refusal appears. Reading it
    // back is the difference between "it failed" and "it failed because X".
    let outboxRows = null;
    try {
      const listed = await run.call('outbox.list', 'outbox.list', { workspace_id: WORKSPACE_ID, limit: 8 }, {
        principal: run.principal.owner,
      });
      const payload = listed?.data ?? null;
      const rows = Array.isArray(payload) ? payload
        : Array.isArray(payload?.outbox) ? payload.outbox
          : Array.isArray(payload?.rows) ? payload.rows
            : null;
      if (Array.isArray(rows)) {
        outboxRows = rows.map((row) => ({
          outbox_id: row.outbox_id ?? null,
          dispatch_state: row.dispatch_state ?? null,
          escalation_reason: row.escalation_reason ?? row.reason ?? null,
          attempts: row.attempts ?? null,
        }));
      }
    } catch (error) {
      outboxRows = [{ unreadable: String(error?.message ?? error).slice(0, 200) }];
    }
    // The detail travels: a refusal whose reason is dropped is a refusal nobody
    // can diagnose, and this driver publishes the reason rather than the code
    // alone.
    record.findings.push({
      id: 'dispatch-refused',
      code: dispatch.code,
      message: dispatch.message,
      detail: dispatch.detail ?? null,
      outbox_rows: outboxRows,
    });
    record.raw_logs = describeRawLogs(rawLogDir);
    return record;
  }
  if (summary.escalated > 0 || summary.acked === 0) {
    // The crossing happened and its outcome is unknown to the board, or it was
    // never made. Both are reported; neither is completed by hand.
    record.verdict = 'RUN_ESCALATED';
    record.findings.push({
      id: 'outbox-escalated',
      detail: `intentRecorded=${summary.intentRecorded} acked=${summary.acked} escalated=${summary.escalated} externalEffectsIssued=${summary.externalEffectsIssued}; the boundary escalated the row and a human reconciliation is required`,
    });
    record.raw_logs = describeRawLogs(rawLogDir);
    record.executor = extractExecutorObservation(transport);
    publishArgvEvidence(record, transport, run.options.configuration);
    return record;
  }

  // --- 9. the event stream, in order, one command per event ----------------
  // `status()` answers with ONE event per call, and the sequence discipline is
  // the BOARD's: `expected_sequence` is deliberately not sent, because the
  // store's `sequence === last + 1` rule is the authority and a driver-side
  // guess at the executor's own counter could only ever fight with it. The
  // ACCEPTED event that `start()` emitted during the crossing is submitted
  // first when the transport handed it back through `dispatch`.
  let sequence = 0;
  const pending = [];
  if (isEventDocument(capture.dispatchReturn)) {
    pending.push(capture.dispatchReturn);
    record.dispatch_return_captured = true;
  } else {
    record.dispatch_return_captured = false;
    record.findings.push({
      id: 'accepted-event-not-returned',
      severity: 'declared-limit',
      detail: 'the transport returned no ACCEPTED event from dispatch(); if the run already emitted one, the store will refuse the first event this driver submits and the refusal is recorded below',
    });
  }
  for (let round = 0; round < 64; round += 1) {
    let status;
    try {
      status = await transport.status({
        run_id: boardRun.run_id, task_id: taskId, lease_id: leaseId,
        fencing_token: fencingToken, at: run.now(),
      });
    } catch (error) {
      const typed = isBoardError(error) ? error : toBoardError(error, 'MALFORMED_RESULT');
      record.findings.push({ id: 'transport-status-refused', code: typed.code, message: typed.message });
      break;
    }
    if (!isEventDocument(status)) break;
    if (status.sequence <= sequence) break; // the transport repeated itself; nothing new to submit
    pending.push(status);
    if (TERMINAL_EVENT_TYPES.has(status.event_type)) break;
  }
  for (const event of pending) {
    if (event.sequence !== sequence + 1) {
      record.findings.push({
        id: 'event-sequence-not-gap-free',
        sequence: event.sequence,
        detail: `the transport presented sequence ${event.sequence} where the stream stands at ${sequence}; the driver never repairs an ordering defect, so the event is not submitted`,
      });
      break;
    }
    const row = await run.call(`event.${label}.${String(event.sequence).padStart(2, '0')}`, 'execution.event', {
      run_id: boardRun.run_id, event,
    }, { principal: run.principal.producer, actorKind: 'adapter', transport });
    record.events.push({
      sequence: event.sequence,
      event_type: event.event_type,
      outcome: event.outcome ?? null,
      decision: row.outcome,
      code: row.code ?? null,
      digest: wireDigest(event),
      payload_digest: wireDigest(event.payload ?? {}),
    });
    if (row.outcome !== 'ACCEPT') {
      record.findings.push({ id: 'event-refused', sequence: event.sequence, code: row.code, message: row.message });
      break;
    }
    sequence = event.sequence;
  }
  if (record.events.length === 0) {
    record.findings.push({ id: 'no-events', severity: 'declared-limit', detail: 'the transport reported no execution events; the store therefore holds no callback stream for this run' });
  }

  // --- 10. collect the result ------------------------------------------------
  let collected = null;
  try {
    collected = await transport.collect_result({
      run_id: boardRun.run_id, task_id: taskId, lease_id: leaseId,
      fencing_token: fencingToken, at: run.now(),
    });
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'MALFORMED_RESULT');
    record.findings.push({ id: 'transport-collect-refused', code: typed.code, message: typed.message });
  }
  const resultDocument = isPlainRecord(collected) && isPlainRecord(collected.result)
    ? collected.result
    : (isPlainRecord(collected) && typeof collected.outcome === 'string' ? collected : null);
  if (resultDocument !== null) {
    const collect = await run.call(`collect.${label}`, 'execution.collect_result', {
      run_id: boardRun.run_id, result: resultDocument,
    }, { principal: run.principal.producer, actorKind: 'adapter', transport });    record.result = {
      decision: collect.outcome,
      code: collect.code ?? null,
      replayed: collect.replayed === true,
      outcome: resultDocument.outcome ?? null,
      sequence: resultDocument.sequence ?? null,
      digest: wireDigest(resultDocument),
      error: resultDocument.error ?? null,
      measurements: resultDocument.measurements ?? null,
      checkpoints: Array.isArray(resultDocument.checkpoints) ? resultDocument.checkpoints.length : 0,
      artifact_hashes: Array.isArray(resultDocument.artifact_hashes) ? resultDocument.artifact_hashes.length : 0,
      reconciliation_required: resultDocument.reconciliation_required ?? null,
    };
    if (collect.outcome !== 'ACCEPT' && collect.code === 'MALFORMED_RESULT') {
      record.findings.push({
        id: 'result-refused',
        code: collect.code,
        message: collect.message,
        detail: `the store admits a result whose sequence is last+1, or a terminal ECHO of the last committed event (src/lib/agentboard/store.mjs collectResult); the transport presented sequence ${resultDocument.sequence} with the stream at ${sequence} and the driver does not repair it`,
      });
    }
  } else {
    record.result = { decision: 'NOT_SUBMITTED', reason: collected === null ? 'the transport returned no result document' : 'the transport result carried no contract-shaped result document' };
  }

  // --- 11. settle the ONE budget with what the executor itself reported ----
  const spend = isPlainRecord(record.result?.measurements) && Number.isFinite(Number(record.result.measurements.spend))
    ? Number(record.result.measurements.spend)
    : 0;
  const costBasis = Number.isFinite(Number(record.result?.measurements?.spend)) && spend > 0
    ? 'EXECUTOR_REPORTED_USD'
    : 'NO_USD_REPORTED_BY_EXECUTOR';
  record.cost = {
    settled_amount: spend,
    currency: CURRENCY,
    cost_basis: costBasis,
    note: costBasis === 'NO_USD_REPORTED_BY_EXECUTOR'
      ? 'this executor reported no monetary cost in its own output; the board is settled with 0 and no cost figure is estimated, published or priced from a list'
      : 'the settled amount is the executor\'s own reported cost, rounded to the grant currency by the boundary',
  };
  const settle = await run.call(`settle.${label}`, 'budget.settle', {
    grant_id: grantId,
    operation_id: `op-s2007r-${run.options.seedSlug}-${label}`,
    task_id: taskId,
    amount: spend,
    currency: CURRENCY,
    day_key: run.now().slice(0, 10),
  }, { principal: run.principal.owner, actorKind: 'human_owner' });
  record.budget.settle = { decision: settle.outcome, code: settle.code ?? null, amount: spend, currency: CURRENCY };

  // --- 12. what the store committed, read for observation only --------------
  const finalTask = await run.readTask(taskId);
  const committedEvents = await run.store.listEvents(boardRun.run_id, { workspaceId: WORKSPACE_ID });
  const committedOutbox = await run.store.listOutbox({ workspaceId: WORKSPACE_ID });
  const committedRun = await run.store.readRun(boardRun.run_id, { workspaceId: WORKSPACE_ID });
  const grant = await run.store.readBudgetGrant(grantId);
  const spendRow = await run.store.readBudgetSpend(grantId, run.now().slice(0, 10));
  const projectAfter = projectDigest(copy.realpath);
  record.committed = {
    task: {
      task_id: finalTask.task_id, state: finalTask.state, revision: finalTask.revision,
      attempts: finalTask.attempts, active_lease_id: finalTask.active_lease_id,
      fencing_token: finalTask.fencing_token, assigned_adapter_id: finalTask.assigned_adapter_id,
      history_digest: finalTask.history_digest, brief_validated_observed: finalTask.brief_digest,
    },
    run: isPlainRecord(committedRun)
      ? { run_id: committedRun.run_id, run_state: committedRun.run_state, last_sequence: committedRun.last_sequence, spend: committedRun.spend, request_digest: committedRun.request_digest, result_digest: committedRun.result_digest }
      : null,
    events: (Array.isArray(committedEvents) ? committedEvents : []).map((row) => ({
      sequence: row.sequence, event_type: row.event_type, outcome: row.outcome, payload_digest: row.payload_digest,
    })),
    events_gap_free: (Array.isArray(committedEvents) ? committedEvents : []).every((row, index) => row.sequence === index + 1),
    outbox: (Array.isArray(committedOutbox) ? committedOutbox : [])
      .filter((row) => row.task_id === taskId)
      .map((row) => ({ outbox_id: row.outbox_id, event_type: row.event_type, dispatch_state: row.dispatch_state, attempts: row.attempts, last_error: row.last_error ?? null, payload_digest: row.payload_digest })),
    grant: isPlainRecord(grant) ? { grant_id: grant.grant_id, task_id: grant.task_id, task_limit: grant.task_limit, campaign_limit: grant.campaign_limit, day_limit: grant.day_limit, currency: grant.currency, granted_by: grant.granted_by } : null,
    spend: isPlainRecord(spendRow) ? { grant_id: spendRow.grant_id, day_key: spendRow.day_key, spent_task: spendRow.spent_task, spent_campaign: spendRow.spent_campaign, spent_day: spendRow.spent_day, currency: spendRow.currency } : null,
  };
  record.project.digest_after = projectAfter.digest;
  record.project.unchanged = projectAfter.digest === copy.digest;
  if (!record.project.unchanged) {
    record.findings.push({ id: 'project-modified', severity: 'defect', detail: 'the executor changed the fixture bytes; the task forbade it and the change is reported, not hidden' });
  }

  record.executor = extractExecutorObservation(transport);
  publishArgvEvidence(record, transport, run.options.configuration);
  record.raw_logs = describeRawLogs(rawLogDir);

  // --- the verdict of THIS run, from what was actually collected ------------
  const collectedSucceeded = record.result?.decision === 'ACCEPT' && record.result?.outcome === 'SUCCEEDED';
  if (collectedSucceeded && finalTask.state === 'IN_REVIEW') record.verdict = 'RUN_SUCCEEDED';
  else if (record.result?.decision === 'ACCEPT') record.verdict = 'RUN_TERMINAL_NOT_REVIEW';
  else record.verdict = 'RUN_FAILED';
  return record;
}

function buildPrompt({ taskId, goal, acceptanceCriteria, copy, spec, run }) {
  return [
    `You are executing one bounded unit of work for the Veritas Agent Board (${TICKET}).`,
    `Workspace: ${copy.realpath} (the only location you may read or write).`,
    `Task: ${taskId}`,
    `Goal: ${goal}`,
    'Acceptance criteria:',
    ...acceptanceCriteria.map((item, index) => `${index + 1}. ${item}`),
    'Report every regular file in the workspace (paths relative to it) with its line count,',
    'then state in one line whether you modified any file (you must not).',
    'Do not read or write anything outside the workspace. Do not use the network.',
  ].join('\n');
}

/**
 * A delegating wrapper around the REAL transport. It adds nothing to the call
 * itself: `dispatch` is what `driveOutbox` prefers, every other method is
 * forwarded untouched, and every own method the transport has is carried over,
 * so the board receives an object with the same surface the driver asserted.
 *
 * FINDING (run-driver review #3), APPLIED: the wrapper used to call
 * `transport.dispatch` unconditionally. The real transport has no `dispatch`
 * (it implements `start`), so the send intent was already recorded when the call
 * threw, and `driveOutbox` escalated the row to RECONCILIATION_REQUIRED with an
 * UNKNOWN_OUTCOME the row could never shed. The wrapper now prefers `dispatch`
 * when the transport has one and falls back to `start`, exactly as
 * `transportSend` does.
 *
 * FINDING (run-driver review #12), APPLIED: the interface check now runs on the
 * WRAPPER, because the wrapper is what the boundary receives, and the
 * transport's own methods (evidenceRecord, bindRun, rawLogs, …) are spread in
 * rather than enumerated, so the wrapper cannot silently drop one.
 */
function observingTransport(transport, capture) {
  const wrapper = {
    ...transport,
    async dispatch(payload) {
      const answer = typeof transport.dispatch === 'function'
        ? await transport.dispatch(payload)
        : await transport.start(payload);
      capture.dispatchReturn = answer;
      capture.dispatchPath = typeof transport.dispatch === 'function' ? 'dispatch' : 'start';
      return answer;
    },
  };
  for (const name of ['identify', 'capabilities', 'health', 'claim', 'start', 'status', 'checkpoint', 'cancel', 'collect_result', 'release', 'bindRun']) {
    if (typeof transport[name] === 'function') wrapper[name] = transport[name].bind(transport);
  }
  return wrapper;
}

/** A contract-shaped execution-event, identified structurally and never repaired. */
function isEventDocument(value) {
  return isPlainRecord(value)
    && typeof value.event_type === 'string'
    && Number.isInteger(value.sequence)
    && value.sequence >= 1;
}

async function descendantEnumerationReason(observer) {
  try {
    const tree = await observer.listDescendants(process.pid, {});
    return {
      attempted: true,
      observable: tree.observable,
      reason: tree.reason ?? null,
      descendants: Array.isArray(tree.pids) ? tree.pids.length : 0,
      note: 'the driver itself is not an isolated process-group leader, so the shipped observer refuses to sweep its group; a zero here is NOT a survivor count',
    };
  } catch (error) {
    return { attempted: true, observable: false, reason: `SBX_OBSERVER_FAILED:${String(error?.message ?? error).slice(0, 120)}`, descendants: 0 };
  }
}

// ===========================================================================
// main
// ===========================================================================
async function main() {
  const args = parseArgs(process.argv);
  // `--help` prints the usage and STOPS. This driver SPAWNS REAL EXECUTORS and
  // can spend real money, so a flag that ran the set anyway would spend it and
  // overwrite a published record on a typo.
  if (args.help !== undefined || args.h !== undefined) {
    process.stdout.write(`${USAGE_TEXT}\n`);
    return 0;
  }
  let exitCode = 0;
  let record = null;
  // FINDING (run-driver review #8), APPLIED: these two live in the OUTER scope
  // so the catch can report the runs that really executed. They used to be
  // declared inside the try, so a throw after a successful run published
  // `runs: []` and a false "no execution happened".
  const runsSoFar = [];
  let taskCountOrNull = null;
  let written = { written: [], withheld: false, reason: null };
  // Everything established before a refusal, so a NOT_RUN record still says what
  // was true about this host instead of only what was missing.
  const context = {
    project: null,
    workspace_root: null,
    transport_tree: {
      expected_sources: TRANSPORT_SOURCES.map((row) => row.id),
      resolved_source: null,
      resolved_dir: null,
      modules: [],
      attempts: [],
    },
    configuration: null,
    model: null,
    preflight: null,
    registration: null,
    store: null,
  };

  // --- flag resolution. Every absent value that could flatter the result is a refusal.
  // FINDING (run-driver review #9), APPLIED. `value()` maps BOTH an absent flag
  // and a VALUELESS flag to null. `String(null)` is the four characters "null",
  // so a bare `--model` used to reach the transport as the model id "null" and
  // a bare `--out` used to create a directory called "null"; the model pin guard
  // tested for the string 'true', which the valueless form no longer produces
  // and which was bypassable anyway.
  const value = (raw) => (raw === undefined || raw === null ? null : String(raw));
  const options = {
    project: value(args.project),
    budget: value(args.budget),
    adapters: value(args.adapters),
    configuration: value(args.config),
    tasks: args.tasks === undefined ? '1' : String(args.tasks),
    out: value(args.out) === null ? path.join(ROOT, 'results/s2-007r') : path.resolve(ROOT, String(args.out)),
    outDefaulted: value(args.out) === null,
    postgres: value(args.postgres),
    inMemory: args['in-memory'] !== undefined,
    seed: value(args.seed) ?? 's2-007r',
    clockBase: value(args['clock-base']) ?? CLOCK_BASE,
    workspaceRoot: value(args['workspace-root']),
    model: value(args.model),
    grantId: value(args['grant-id']),
    taskLimit: value(args['task-limit']),
    campaignLimit: value(args['campaign-limit']),
    dayLimit: value(args['day-limit']),
    campaignLedger: value(args['campaign-ledger']),
    provenanceBootstrap: value(args['provenance-bootstrap']),
  };

  try {
    if (options.project === null) {
      throw new NeedsInput('PROJECT_REQUIRED', '--project <dir> is required: this driver never picks a project for you, and a run without a named project is not a run');
    }
    if (options.budget === null) {
      throw new NeedsInput('BUDGET_REQUIRED', '--budget <number> is required: an absent budget is NEEDS_INPUT, not a default, and an unassigned budget is not zero');
    }
    if (options.adapters === null) {
      throw new NeedsInput('ADAPTERS_REQUIRED', '--adapters codex,pi is required: which real executors cross the boundary must be named by the operator');
    }
    if (options.configuration === null) {
      throw new NeedsInput('CONFIGURATION_REQUIRED', '--config <name> is required: the executor surface under test must be named, not chosen by the driver');
    }
    const budgetAmount = positiveNumber(options.budget, 'budget', { min: 0, max: 1_000_000 });
    // The ONE grant, with its three scopes. `--budget` remains the per-task
    // number; a campaign and a day scope are named explicitly when the operator's
    // grant carries different numbers, because a campaign cap that silently
    // equals the task cap is a cap nobody asked for.
    options.taskLimit = positiveNumber(options.taskLimit ?? options.budget, 'task-limit', { min: 0, max: 1_000_000 });
    options.campaignLimit = positiveNumber(options.campaignLimit ?? options.budget, 'campaign-limit', { min: 0, max: 10_000_000 });
    options.dayLimit = positiveNumber(options.dayLimit ?? options.budget, 'day-limit', { min: 0, max: 10_000_000 });
    options.grantId = options.grantId ?? `grt-s2007r-${options.seed}`;
    if (!/^grt-[a-z0-9][a-z0-9-]{0,62}$/.test(options.grantId)) {
      throw new NeedsInput('GRANT_ID_INVALID', '--grant-id must match ^grt-[a-z0-9][a-z0-9-]{0,62}$ (contracts/grant.schema.json; it is the ONE campaign id every cell of a comparison must carry)');
    }
    if (options.campaignLimit < options.taskLimit || options.dayLimit < options.taskLimit) {
      throw new NeedsInput('GRANT_SCOPE_INCONSISTENT', `a grant whose task limit (${options.taskLimit}) exceeds its campaign (${options.campaignLimit}) or day (${options.dayLimit}) limit is not a grant; the scopes are contradictory`);
    }
    const taskCount = positiveInteger(options.tasks, 'tasks', { min: 1, max: 8 });
    const adapterKeys = options.adapters.split(',').map((item) => item.trim()).filter((item) => item.length > 0);
    if (adapterKeys.length === 0) throw new NeedsInput('ADAPTERS_REQUIRED', '--adapters named no adapter');
    for (const key of adapterKeys) {
      if (!ADAPTER_KEYS.includes(key)) {
        throw new NeedsInput('ADAPTER_UNKNOWN', `adapter "${key}" is not one of ${ADAPTER_KEYS.join(', ')}`);
      }
    }
    if (!/^[a-z0-9][a-z0-9-]{0,23}$/.test(options.seed)) {
      throw new NeedsInput('SEED_INVALID', '--seed must match ^[a-z0-9][a-z0-9-]{0,23}$ (it also names the PostgreSQL schema)');
    }
    if (Number.isNaN(Date.parse(options.clockBase))) {
      throw new NeedsInput('CLOCK_BASE_INVALID', '--clock-base must be an ISO-8601 instant');
    }
    // The bound profile must be the HOST_UNISOLATED floor, and it must be one
    // the board actually recognises. `isExecutableSandboxProfile` is deliberately
    // NOT the test here: the floor is NOT an executable-in-the-isolation-sense
    // profile, and pretending otherwise is how a run ends up naming a tier whose
    // controls were never in force.
    if (!isHostUnisolatedSandboxProfile(FLOOR_PROFILE)) {
      throw new NotRunRealAdapter('NOT_RUN_REAL_ADAPTER', `the bound isolation profile ${FLOOR_PROFILE} is not the HOST_UNISOLATED floor the board recognises`);
    }
    // The permit is judged against the INJECTED clock, and the run must not walk
    // out of its window while it executes: a long run would otherwise start
    // authorised and finish unauthorised, and the boundary would then refuse a
    // command mid-run for a reason that looks like a bug.
    const projectedEnd = Date.parse(options.clockBase) + (CLOCK_CALLS_PER_RUN * taskCount + 64) * STEP_MS;
    if (projectedEnd > Date.parse(PERMIT_WINDOW.expires_at)) {
      throw new NeedsInput('UNISOLATED_AUTHORIZATION_WINDOW', `--clock-base ${options.clockBase} would walk this run past the permit window (${PERMIT_WINDOW.expires_at}); pick a base inside it`);
    }
    if (Date.parse(options.clockBase) < Date.parse(PERMIT_WINDOW.issued_at)) {
      throw new NeedsInput('UNISOLATED_AUTHORIZATION_WINDOW', `--clock-base ${options.clockBase} is before the permit was issued (${PERMIT_WINDOW.issued_at}); the board judges the window against its injected clock`);
    }
    if (options.postgres !== null && options.inMemory) {
      throw new NeedsInput('STORE_TIER_AMBIGUOUS', '--postgres and --in-memory are mutually exclusive: a run does not quietly pick a store tier');
    }
    const tier = options.postgres === null ? 'memory' : 'postgres';
    if (tier === 'postgres' && !/^postgres(?:ql)?:\/\//.test(options.postgres)) {
      throw new NotRunDb('NOT_RUN_DB', '--postgres expects a postgresql:// URL; the value is referenced, never logged');
    }

    if (options.workspaceRoot === null) {
      options.workspaceRoot = `${DEFAULT_WORKSPACE_ROOT}/${options.seed}`;
    }
    const source = validateProjectFixture(options.project);
    context.project = {
      source: source.requested, realpath: source.realpath, digest: source.digest,
      file_count: source.fileCount, total_bytes: source.totalBytes, files: source.files,
    };
    const workspaceRoot = prepareWorkspaceRoot(options.workspaceRoot);
    options.workspaceRoot = workspaceRoot.absolute;
    context.workspace_root = { ...workspaceRoot, source: 'INJECTED_NOT_REGISTRY' };
    const executors = await loadExecutorTree();
    context.transport_tree = {
      resolved_source: executors.source,
      resolved_dir: executors.dir,
      modules: executors.binding.modules,
      attempts: executors.attempts,
    };
    const outDir = options.out;
    fs.mkdirSync(outDir, { recursive: true, mode: 0o755 });
    // The raw-log tree is seed-scoped too, for the same reason: a shared
    // `results/s2-007r/raw` let two invocations write into each other's future
    // evidence. When --out is given explicitly the operator owns the directory
    // and the seed is still appended, so the two are never the same directory.
    const rawLogDir = path.join(outDir, 'raw', options.seed);

    // --- the ONE budget, declared before anything is dispatched -------------
    const budget = {
      grant_id: options.grantId,
      amount: budgetAmount,
      task_limit: options.taskLimit,
      campaign_limit: options.campaignLimit,
      day_limit: options.dayLimit,
      timeout_ms: BUDGET_TIMEOUT_MS,
      currency: CURRENCY,
      authority: BUDGET_AUTHORITY,
      approval_owner: BUDGET_APPROVAL_OWNER,
      derivation: 'the operator named one grant: --task-limit / --campaign-limit / --day-limit, each defaulting to the single --budget number. Every run of the campaign passes the same --grant-id, so a comparison never spans two budgets',
      campaign_enforcement: {
        stop_fraction: CAMPAIGN_STOP_FRACTION,
        stop_at_usd: Number((options.campaignLimit * CAMPAIGN_STOP_FRACTION).toFixed(6)),
        cap_usd: options.campaignLimit,
        enforcement: 'the board grant row is task-scoped at this HEAD, so a campaign cap is enforced by the JSON ledger this driver appends its settled spend to; a run that would pass the stop fraction is refused with CAMPAIGN_STOP_REACHED before any executor is dispatched',
        ledger: null,
        note: 'the ledger is the enforcement, so it is read, quoted and written on every invocation',
      },
    };

    const ids = makeIdFactories(options.seed);
    // FINDING (run-driver review #14), APPLIED: the store used to get a
    // CONSTANT clock while the boundary advanced one STEP_MS per call, so
    // committed `created_at`/`updated_at` and the boundary's `board_instant`
    // disagreed and a third party rebuilding a timeline got two clocks. The
    // store now reads the SAME advancing instant the boundary does, and
    // `invocation.clock_semantics` says so.
    const storeClock = { ticks: 0 };
    const clock = () => new Date(Date.parse(options.clockBase) + (storeClock.ticks += 1) * STEP_MS);
    const storeHandle = await openStore({
      tier,
      connectionString: options.postgres,
      schema: `s2_007r_${options.seed.replace(/-/g, '_')}`,
      clock,
      storeIds: ids.store,
      seed: `s2-007r-${options.seed}`,
    });

    const run = new RealRun({
      options: { ...options, seedSlug: options.seed, tasks: taskCount, configuration: options.configuration, model: options.model },
      store: storeHandle.backend,
      executors,
      adapterKeys,
    });

    // --- preflight: the board's host probe, then a real process per binary ---
    const probeRows = await probeRealAdapters({ clock: { now: run.clock }, versionProbe: true });    const preflightVersion = {};
    for (const key of adapterKeys) {
      preflightVersion[key] = versionProcessProbe(ADAPTERS[key].binary);
      const row = probeRows.find((entry) => entry.adapter_id === ADAPTERS[key].adapter_id) ?? null;
      if (row === null || row.installed !== true) {
        throw new NotRunRealAdapter('NOT_RUN_REAL_ADAPTER', `the host probe found no installed executable for ${ADAPTERS[key].adapter_id}: ${row?.detail ?? 'no probe row'}`);
      }
      if (preflightVersion[key].exit_code !== 0) {
        throw new AgentUnavailable('EXECUTOR_NOT_RUNNABLE', `${ADAPTERS[key].binary} --version exited ${preflightVersion[key].exit_code}: ${preflightVersion[key].stderr || preflightVersion[key].stdout || 'no output'}`);
      }
    }

    context.preflight = {
      board_probe: probeRows,
      version_process: preflightVersion,
    };
    context.store = { tier, ...storeHandle.details };

    // --- the configuration and the model must be NAMEABLE, not guessed -------
    const surfaces = isPlainRecord(executors.binding.constants?.CONFIG_SURFACES)
      ? Object.keys(executors.binding.constants.CONFIG_SURFACES)
      : null;
    if (surfaces !== null && !surfaces.includes(options.configuration)) {
      throw new NeedsInput('CONFIGURATION_UNKNOWN', `--config ${options.configuration} is not one of the surfaces the transport tree declares (${surfaces.join(', ')})`);
    }
    context.configuration = {
      name: options.configuration,
      declared_surfaces: surfaces,
      validation: surfaces === null
        ? 'the resolved transport tree exports no CONFIG_SURFACES, so this driver cannot validate the name; the transport itself is the authority and refuses an undeclared surface with CONFIGURATION_UNKNOWN, and the argv as executed is then the only record of what it selected'
        : 'validated against the transport tree\'s own CONFIG_SURFACES, and re-validated inside the transport on every crossing (resolveConfigurationSurface); a surface that selected a flag outside the argv allowlist would be refused with CONFIGURATION_FLAG_NOT_ALLOWLISTED',
    };
    // pi is only verified on this host with a small-max-output model; without a
    // pin it would silently fall back to its configured default, which is a
    // different and unverified spend. Refuse rather than guess.
    const pinnedPiModel = executors.binding.constants?.PI_MODEL_PINNED ?? null;
    if (adapterKeys.includes('pi') && options.model === null && typeof pinnedPiModel !== 'string') {
      throw new NeedsInput('MODEL_UNPINNED', 'pi has no model pin: pass --model <provider/id>, or the transport tree must export PI_MODEL_PINNED. This driver never lets an executor fall back to an unverified default model');
    }
    context.model = {
      flag: options.model,
      pi_pin_from_transport_tree: adapterKeys.includes('pi') ? pinnedPiModel : null,
      codex_model: 'the codex CLI\'s configured default; its JSONL reports no model id, which this record states rather than resolves',
    };

    // --- 0. discovery, before and after the registrations --------------------
    const capabilitiesBefore = await run.call('discovery.capabilities.before', 'capabilities', { workspace_id: WORKSPACE_ID }, {
      principal: run.principal.owner, actorKind: 'human_owner',
    });

    // --- 1. BOTH real adapters, registered and schema-verified ---------------
    // The campaign cap is checked BEFORE a single process is dispatched, and the
    // ledger it reads is quoted in the record either way.
    const ledgerPath = options.campaignLedger === null
      ? path.join(outDir, 'campaign-ledger.json')
      : path.resolve(ROOT, options.campaignLedger);
    const ledger = readCampaignLedger(ledgerPath, {
      grantId: options.grantId, capUsd: options.campaignLimit, stopFraction: CAMPAIGN_STOP_FRACTION,
    });
    budget.campaign_enforcement.ledger = {
      path: ledger.path, existed: ledger.existed, entries_before: ledger.entries.length,
      total_usd_before: ledger.total_usd,
    };
    assertCampaignHeadroom(ledger, { capUsd: options.campaignLimit, stopFraction: CAMPAIGN_STOP_FRACTION });

    // The provenance bootstrap, per provider that needs one. `off` disables it,
    // and then the registrations stay NOT_RUN_REAL_ADAPTER and the board
    // refuses them — which is the honest outcome, not a failure of this driver.
    const bootstrapKeys = options.provenanceBootstrap === 'off'
      ? []
      : adapterKeys.filter((key) => String(options.provenanceBootstrap ?? '').split(',').map((item) => item.trim()).includes(key)
        || options.provenanceBootstrap === null || options.provenanceBootstrap === 'on');
    // Its cwd is a real, EMPTY directory inside the containment root: the
    // transport derives it from `workspace_ref.root_ref` through the board's own
    // guard, so the crossing runs against a workspace the same way a governed run
    // does. It is empty on purpose: nothing there can be read, so a model that
    // did answer would have had nothing to do.
    const bootstrapRoot = path.join(options.workspaceRoot, 'bootstrap');
    if (bootstrapKeys.length > 0) {
      fs.mkdirSync(bootstrapRoot, { recursive: true, mode: 0o700 });
      if (process.platform !== 'win32') fs.chmodSync(fs.realpathSync(bootstrapRoot), 0o700);
    }
    // Published by reference, so a bootstrap that fails is visible in the record
    // a refusal writes: a fixed point this driver cannot enter is exactly what a
    // reader needs to see, not something to hide behind an error code.
    const bootstrapReports = [];
    context.provenance_bootstrap = bootstrapReports;
    const bootstrap = new Map();
    for (const key of bootstrapKeys) {
      const report = await provenanceBootstrap({
        run, key, spec: ADAPTERS[key], rawLogDir: path.join(rawLogDir, 'bootstrap', key),
      });
      bootstrap.set(key, report);
      bootstrapReports.push({
        provider: report.provider,
        adapter_id: report.adapter_id,
        run_id: report.run_id,
        governed: report.governed,
        is_a_run: report.is_a_run,
        board_commands_called: report.board_commands_called,
        model: report.model,
        outcome: report.outcome,
        events: report.events,
        exit_status: report.exit_status,
        exit_observed: report.exit_observed,
        process: report.process,
        raw_logs: report.raw_logs,
        evidence: report.evidence_summary,
        evidence_refusal: report.evidence_refusal ?? null,
        spend: report.spend,
        wall_ms: report.wall_ms,
        request_summary: report.request_summary ?? null,
        result_error: report.result_error ?? null,
        error: report.error,
      });
      if (report.evidence === null) {
        throw new NotRunRealAdapter(
          'NOT_RUN_REAL_ADAPTER',
          `${ADAPTERS[key].adapter_id}: the provenance bootstrap crossing produced no corroborating record (${report.evidence_refusal ?? 'no raw process log with an observed exit'}). `
          + 'The registration therefore stays NOT_RUN_REAL_ADAPTER and the boundary will refuse it, which is the honest outcome: no registration, probe or fixture may stand in for an observed crossing.',
        );
      }
    }

    const registered = await registerAdapters({ run, adapterKeys, probeRows, bootstrap });
    for (const entry of registered) {
      const row = await run.call(`register.${entry.key}`, 'adapters.register', { registration: entry.registration }, {
        principal: run.principal.owner, actorKind: 'human_owner',
      });
      entry.registration_decision = row.outcome;
      entry.registration_code = row.code ?? null;
      if (row.outcome !== 'ACCEPT') {
        throw new AgentUnavailable(
          'ADAPTER_REGISTRATION_REFUSED',
          `${entry.spec.adapter_id}: the boundary refused the registration (${row.code} ${row.message}); no run is attempted through an unregistered adapter`,
        );
      }
    }
    const capabilitiesAfter = await run.call('discovery.capabilities.after', 'capabilities', { workspace_id: WORKSPACE_ID }, {
      principal: run.principal.owner, actorKind: 'human_owner',
    });
    context.registration = registered.map((entry) => ({
      adapter_id: entry.spec.adapter_id,
      register_decision: entry.registration_decision,
      register_code: entry.registration_code,
      registration_digest: entry.digest,
      schema_valid: entry.schema_valid,
    }));

    // --- 2. the runs, one task each ------------------------------------------
    // The ONE budget number is granted per task inside runOneTask (the store
    // resolves a run's grant by task_id), so there is no campaign-wide grant row
    // here to pretend to.
    taskCountOrNull = taskCount;
    const runs = runsSoFar;
    // A run that never crossed the boundary is NOT_RUN; a run that crossed and
    // did not collect a result is a failure of that run, not of the invocation.
    // The verdict ladder reads this rather than guessing from the exit code.
    let executedNothing = true;
    for (let index = 1; index <= taskCount; index += 1) {
      const key = adapterKeys[(index - 1) % adapterKeys.length];
      const entry = registered.find((item) => item.key === key);
      // Pushed only after runOneTask RETURNED, so a throw inside it never adds a
      // half-built run to the record; a completed run is never removed from it.
      runs.push(await runOneTask({
        run, index, source, budget, registration: entry,
        rawLogDir: path.join(rawLogDir, `run-${String(index).padStart(2, '0')}-${key}`),
      }));
    }

    // --- 4. the verdict -------------------------------------------------------
    // The campaign ledger moves BEFORE the record is published, because the
    // spends it records already happened: a withheld record (a credential-shaped
    // literal) does not un-spend them, and a ledger that only moved on a clean
    // write would be a counter an untrusted record could reset.
    const campaignLedger = appendCampaignLedger(ledgerPath, {
      grantId: options.grantId,
      capUsd: options.campaignLimit,
      stopFraction: CAMPAIGN_STOP_FRACTION,
      runRows: runs,
      invocation: { configuration: options.configuration, adapters: options.adapters, seed: options.seed },
    });
    // The store is closed before the record is written: the record is built from
    // what was committed, not from a connection that is still open.
    await storeHandle.close();
    const succeeded = runs.filter((row) => row.verdict === 'RUN_SUCCEEDED');
    const collectedAny = runs.filter((row) => row.result?.decision === 'ACCEPT').length;
    executedNothing = runs.every((row) => row.verdict === 'NOT_RUN');
    const findings = runs.flatMap((row) => row.findings.map((item) => ({ run: row.label, ...item })));
    const hardGates = [];
    if (findings.some((item) => item.id === 'project-modified')) hardGates.push('PROJECT_MODIFIED_BY_EXECUTOR');
    if (findings.some((item) => String(item.code ?? '').startsWith('UNTYPED_'))) hardGates.push('UNTYPED_ERROR_ESCAPED');
    if (runs.some((row) => row.raw_logs?.withheld?.length > 0)) hardGates.push('CREDENTIAL_SHAPED_LITERAL_WITHHELD');
    if (runs.some((row) => row.committed && row.committed.events_gap_free === false)) hardGates.push('EVENT_SEQUENCE_GAP');
    if (runs.some((row) => row.result?.decision === 'ACCEPT' && row.committed?.task?.state === 'DONE')) {
      hardGates.push('TASK_REACHED_DONE_WITHOUT_HUMAN_REVIEW');
    }
    if (runs.some((row) => row.executor?.available !== true
      || row.executor.missing.includes('argv')
      || row.executor.missing.includes('exit_code')
      || row.executor.missing.includes('pid')
      || row.executor.missing.includes('pgid'))) {
      // FINDING (run-driver review #2), APPLIED. The gate used to read
      // `available === true && missing.includes('argv')`, which can only be
      // true when the transport published SOMETHING: with no crossing record at
      // all it is structurally dead, so a transport that returned
      // `{result:{outcome:'SUCCEEDED'}}`, wrote no log and published no crossing
      // reached PASS with zero independently observed executor facts. The
      // verdict now follows the OBSERVED evidence: a run counts as an observed
      // crossing only when the argv, the exit code, the session id and the pid
      // are all present, and an empty raw-log directory is a gate of its own.
      hardGates.push('EXECUTOR_NOT_INDEPENDENTLY_OBSERVED');
    }
    if (runs.some((row) => (row.raw_logs?.files?.length ?? 0) === 0)) {
      hardGates.push('NO_RAW_PROCESS_LOG_PUBLISHED');
    }
    // TASK 3: ONE project digest, asserted identical across every run of this
    // comparison. Each run got a FRESH copy, and a fresh copy that does not
    // hash to the same value is a different input, so the comparison would be
    // across two projects and this gate says so instead of averaging them.
    const digests = [...new Set(runs.map((row) => row.project?.digest_before).filter((value) => typeof value === 'string'))];
    if (digests.length > 1) {
      hardGates.push('PROJECT_DIGEST_DIFFERS_ACROSS_RUNS');
    }
    // FINDING (run-driver review #15), APPLIED: the two PARTIAL branches were
    // identical and the `status === 'NOT_RUN'` arm was unreachable. The verdict
    // is now a single ladder whose arms are distinguishable and whose exit code
    // follows the STATUS, not the intent of the code path that was entered:
    //   FAIL    a hard gate tripped, or a run reached DONE with no human review
    //   PASS    every requested run collected a SUCCEEDED result and the task
    //           reached IN_REVIEW, with every hard gate clear
    //   PARTIAL something ran and something did not, or nothing was collected
    //   NOT_RUN nothing executed at all
    const statuses = {
      FAIL: 'FAIL',
      PASS: 'PASS',
      PARTIAL: 'PARTIAL',
      NOT_RUN: 'NOT_RUN',
    };
    let status;
    if (hardGates.length > 0) status = statuses.FAIL;
    else if (succeeded.length === runs.length && runs.length > 0) status = statuses.PASS;
    else if (collectedAny > 0) status = statuses.PARTIAL;
    else if (executedNothing) status = statuses.NOT_RUN;
    else status = statuses.PARTIAL;
    exitCode = status === statuses.PASS ? 0 : (status === statuses.NOT_RUN ? 3 : 1);

    record = {
      contractVersion: '1.0.0',
      record_kind: 's2-007r-raw-run-record',
      ticket: TICKET,
      issue: ISSUE,
      driver: {
        version: DRIVER_VERSION,
        file: 'scripts/s2-007r-run.mjs',
        node: process.version,
        platform: `${process.platform}/${process.arch}`,
        argv: process.argv.slice(2).map((item) => redactArgv([item])[0]),
      },
      invocation: {
        project: options.project,
        budget: options.budget,
        adapters: options.adapters,
        configuration: options.configuration,
        configuration_detail: context.configuration,
        configuration_axis: cellConfigurationAxis(runs),
        model_resolution: context.model,
        tasks: taskCount,
        out: displayPath(outDir),
        out_defaulted: options.outDefaulted,
        store_tier: tier,
        seed: options.seed,
        clock_base: options.clockBase,
        clock_step_ms: STEP_MS,
        clock_semantics: 'the boundary clock advances one STEP_MS per call; the STORE clock advances one STEP_MS per store read of the clock, i.e. the same base and the same step, so a third party rebuilding a timeline gets ONE clock and not two',
        permit_window: PERMIT_WINDOW,
        sandbox_profile: {
          profile_id: FLOOR_PROFILE,
          tier: SANDBOX_HOST_UNISOLATED.tier,
          isolation_observed: false,
          authorization_id: UNISOLATED_AUTHORIZATION.authorization_id,
          authorization_body_digest: UNISOLATED_AUTHORIZATION.body_digest,
          os_controls_absence_evidence: SANDBOX_HOST_UNISOLATED.os_controls_evidence,
        },
        workspace_root: options.workspaceRoot,
        model_flag: options.model,
      },
      honesty: {
        script_used: false,
        replay_used: false,
        transport_source: runs[0]?.transport_source ?? null,
        boundary_entry_point: 'src/lib/agentboard/commands.mjs#execute',
        store_writes: 'every write went through commands.execute; the store was read only to observe what was committed',
        realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
        realAdapterStatusSemantics: 'nothing in THIS file lifts a status: a real installed executor crossing the boundary is a fact recorded here, and only src/lib/executors/evidence-writer.mjs may read this record and decide what it means',
        assuranceStatus: 'NOT_MEASURED',
        aMvpStatus: 'NOT_CLAIMED',
        notInferred: [
          'human_review', 'empirical_semantic_accuracy', 'A_MVP_PASS', 'production_readiness',
          'os_isolation', 'model_quality', 'cross_executor_comparability',
        ],
        done_edge: 'IN_REVIEW -> DONE is unreachable in this run by construction: no principal defined here holds board.review.approve (SPEC §7, A-MVP-05 NOT_RUN)',
      },
      preflight: {
        board_probe: { rows: probeRows, kind: 'HOST_FACT_ONLY: an executable on PATH is not a run and not a registration' },
        version_process: Object.fromEntries(Object.entries(preflightVersion).map(([key, value]) => [key, value])),
        version_process_note: 'each entry is a REAL child process started by this driver (spawn with an argv array, no shell); it proves the executable starts and answers, and it does NOT prove a model call can complete — only a collected run result does that',
      },
      registration: registered.map((entry) => ({
        adapter_id: entry.spec.adapter_id,
        provider: entry.spec.provider,
        adapter_kind: entry.registration.adapter_kind ?? null,
        declared_capabilities: entry.registration.declared_capabilities ?? null,
        declared_tools: entry.registration.declared_tools ?? null,
        sandbox_profile_id: entry.registration.sandbox_profile_id ?? null,
        real_adapter_provenance: entry.registration.real_adapter_provenance ?? null,
        registration_digest: entry.digest,
        schema_valid: entry.schema_valid,
        schema_source: 'contracts/adapter-registration.schema.json via src/lib/agentboard/contracts.mjs#boardContractErrors',
        register_decision: entry.registration_decision,
        register_code: entry.registration_code,
        probe_row: entry.probe_row,
        provenance_status: entry.provenance_status,
        corroborated_by: entry.corroborated_by,
      })),
      // The pre-registration crossings, in full. They are quoted here rather
      // than summarised because a reader who cannot see the process observation
      // has to take the status on faith, and a status taken on faith is what this
      // ticket exists to stop.
      provenance_bootstrap: {
        why: "a real registration is refused by the boundary unless its provenance is REAL_ADAPTER_AVAILABLE, and that status is only ever minted from an observed crossing of an installed executor; the crossing below is the fixed point's entry, it is NOT a run, and it is recorded as one that did not happen",
        governed: false,
        board_commands_called: 0,
        crossings: bootstrapReports,
      },
      capabilities: {
        before: capabilitiesBefore.outcome === 'ACCEPT' ? capabilitiesBefore.data.capabilities : { refusal: { code: capabilitiesBefore.code, message: capabilitiesBefore.message } },
        after: capabilitiesAfter.outcome === 'ACCEPT' ? capabilitiesAfter.data.capabilities : { refusal: { code: capabilitiesAfter.code, message: capabilitiesAfter.message } },
        // THE FIELD A READER COULD MISREAD, DISAMBIGUATED IN PLACE. The board's
        // discovery document carries `sandboxProfileIds`: the profile ids this
        // workspace KNOWS are proven on this host. It is a capability list, not a
        // statement about this run. This run is bound to the HOST_UNISOLATED
        // floor (see invocation.sandbox_profile and sandboxClaim), no process in it
        // was inside a container, and the driver does not edit the board's own
        // document to make that easier to see — it says so next to it instead.
        sandboxProfileIds_note: 'the `sandboxProfileIds` in the documents above are the proven profile ids this workspace knows (the board\'s own discovery output, quoted verbatim); they are NOT the profile of any run. The profile every run in this record is bound to is `invocation.sandbox_profile.profile_id` = sbx-host-unisolated-v1, with isolation_observed:false.',
        run_profile_id: FLOOR_PROFILE,
        run_isolation_observed: false,
      },
      budget: {
        ...budget,
        grants: runs.map((row) => row.budget).filter((row) => row !== undefined),
        grant_policy: 'one task-scoped grant row per task, every row carrying the identical --grant-id and the identical three limits; the store resolves a run\'s grant by task_id, so a single campaign-wide row cannot back a run at this HEAD',
        campaign_ledger: campaignLedger,
        campaign_ledger_note: 'the ledger was appended before this record was published; the appended rows are exactly the runs\' own settled amounts, and the sum is recomputable from `runs[].cost.settled_amount`',
      },
      project: {
        source: source.requested,
        source_realpath: source.realpath,
        digest: source.digest,
        file_count: source.fileCount,
        total_bytes: source.totalBytes,
        files: source.files,
        digest_method: 'sha256 over the canonical-json-v1 form of the sorted `relative path -> {bytes, sha256}` map; recomputable by anyone with the fixture. corpus/s2-007r/project/verify.mjs prints the SAME string for the SAME bytes, because both use src/lib/verifier/canonical-json.mjs#canonicalDigest.',
        one_project_assertion: {
          distinct_digests_across_runs: digests.length,
          digests,
          fresh_copy_per_run: true,
          note: 'every run materialised its own copy of the tracked fixture into the workspace root and the copy digest was compared with the source digest before the executor started; a difference is a typed COMPARISON_INPUT_MISMATCH refusal, not a note',
        },
      },
      workspace_root: {
        ...workspaceRoot,
        source: 'INJECTED_NOT_REGISTRY',
        note: 'the containment root came from the documented execute({workspaceRoots, realpath}) injection point; the S2-002 workspace registry holds Windows roots only and authorised nothing on this host (SPEC D2)',
      },
      sandboxClaim: {
        // THE OWNER'S DECISION (issue #45, D3 revised). The run's profile IS the
        // HOST_UNISOLATED floor, and it says so everywhere: in the registration,
        // in the task's workspace_ref, in execute({sandbox}) and in the
        // execution.start response. No field of this record names a proven tier,
        // because no process in this run was inside one.
        profile_id: FLOOR_PROFILE,
        tier: SANDBOX_HOST_UNISOLATED.tier,
        claim_source: 'board_execution_start_live_authorisation_gate',
        observed_execution_context: 'HOST_PROCESS_SPACE',
        isolation_observed: false,
        measured_by_this_run: false,
        // The permit, by value, and the digest of the record that MEASURED the
        // absence of OS controls. Both are required of every run record under
        // this tier; a record without them is refused.
        authorization: {
          ...UNISOLATED_AUTHORIZATION,
          source: 'scripts/s2-007r-authorization.mjs#buildUnisolatedAuthorization (the same function that verifies it)',
        },
        // FINDING (driver, this run), APPLIED: this read `record.sandbox_decision`
        // while `record` was still the variable being assigned, i.e. it was null
        // by construction, so a record could never quote the decision the board
        // itself resolved. The decision is per RUN, so the first run that has one
        // is the one quoted, and the count says how many runs carried it.
        authorization_resolved: runs.find((row) => isPlainRecord(row.sandbox_decision))?.sandbox_decision?.authorization ?? null,
        authorization_resolved_runs: runs.filter((row) => isPlainRecord(row.sandbox_decision)).length,
        os_controls_absence_evidence: {
          path: 'evidence/s2-007r-host-unisolated.json',
          sha256: SANDBOX_HOST_UNISOLATED.os_controls_evidence,
          binds_profile_field: 'os_controls_evidence',
          note: 'this is the profile\'s own os_controls_evidence: the content address of the record that measured that no OS isolation control is available to a model-calling executor on this host',
        },
        blockers: [
          'runtime_absent_in_image',
          'no_egress_network_none',
          'no_secret_handle_profile',
        ],
        blockers_source: 'measured on this host by scripts/verify-s2-007r-host-unisolated.mjs into evidence/s2-007r-host-unisolated.json and digest-bound into the profile; NOT re-measured by this run, which spawned the executor as a direct child process and created no container',
        unblocking_requires: [
          'pinned image with a node runtime',
          'network allowlist replacing --network=none',
          'secret-handle mechanism in the profile',
        ],
        claim: 'this run may claim that a real installed executor crossed the boundary, and it claims NOTHING about OS isolation. A-MVP-04\'s isolation clause is NOT_RUN on this host, always.',
      },
      store: { tier, ...storeHandle.details },
      context,
      runs,
      journal: {
        calls: run.calls,
        transitions: run.transitions,
        errors: run.errors,
        boundary_call_count: run.calls.length,
        refused_call_count: run.calls.filter((row) => row.outcome === 'REFUSE').length,
      },
      canonical_json: CANONICAL_JSON_VERSION,
      verdict: { status, exit_code: exitCode, hard_gates: hardGates, succeeded: succeeded.length, requested: runs.length },
      limitations: [],
    };

    record.limitations = collectLimitations({ record, runs, tier, options, source });
    // FINDING (run-driver review #1), APPLIED. The digest used to be computed
    // here and the file then REWRITTEN by the registration-gate block below, so
    // the published `record_digest` was the digest of a document that was not
    // the one on disk — the one integrity field in the record, unverifiable by
    // anyone. The post-publication note is now applied inside writeRecord, which
    // recomputes the digest over the final document, so the published bytes and
    // the published digest are the same document by construction.
    written = await writeRecord(outDir, record, runs, withRegistrationGateNote);
    if (written.withheld) {
      record.verdict = { ...record.verdict, hard_gates: [...record.verdict.hard_gates, 'CREDENTIAL_SHAPED_LITERAL_IN_RECORD'] };
      record.verdict.status = 'FAIL';
      record.verdict.exit_code = 1;
      exitCode = 1;
      process.stderr.write(`${written.reason}\n`);
    }
  } catch (error) {
    // FINDING (run-driver review #15), APPLIED: an untyped error from THIS file
    // used to be published as PROVIDER_FAILURE, so the next reader debugged the
    // provider instead of the driver. The UNTYPED_ marker is the driver's own
    // convention and it is applied here too, and it is a hard gate, not a
    // provider verdict.
    const typed = isBoardError(error) ? error : toBoardError(error, 'PROVIDER_FAILURE');
    const untypedDriverDefect = !isBoardError(error);
    const status = 'NOT_RUN';
    exitCode = PRECONDITION_CODES.has(typed.code) ? 3 : 1;
    const limitation = `${typed.code}: ${redact(String(typed.message ?? typed)).slice(0, 300)}`;
    // FINDING (run-driver review #8), APPLIED. `runs` is hoisted OUT of the try,
    // and the catch derives the status from the runs that really executed. The
    // old catch wrote `runs: []` and the unconditional limitation "this record
    // contains no execution" over whatever had already run: a driver-side throw
    // AFTER a successful run (projectDigest on an emptied workspace,
    // materialiseRunProject, resolveExecutable) destroyed the executed run's data
    // and replaced it with a false statement.
    const executedRuns = runsSoFar;
    const executedAny = executedRuns.length > 0;
    record = {
      contractVersion: '1.0.0',
      record_kind: 's2-007r-raw-run-record',
      ticket: TICKET,
      issue: ISSUE,
      driver: { version: DRIVER_VERSION, file: 'scripts/s2-007r-run.mjs', node: process.version, platform: `${process.platform}/${process.arch}`, argv: redactArgv(process.argv.slice(2)) },
      invocation: {
        project: options.project, budget: options.budget, adapters: options.adapters, configuration: options.configuration,
        out: displayPath(options.out), store_tier: options.postgres === null ? 'memory' : 'postgres', seed: options.seed,
        clock_base: options.clockBase, workspace_root: options.workspaceRoot,
      },
      honesty: {
        script_used: false, replay_used: false, transport_source: null,
        boundary_entry_point: 'src/lib/agentboard/commands.mjs#execute',
        realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
        assuranceStatus: 'NOT_MEASURED',
        aMvpStatus: 'NOT_CLAIMED',
        notInferred: ['real_adapter_execution', 'human_review', 'A_MVP_PASS', 'production_readiness'],
      },
      runs: executedRuns,
      context,
      refusal: { code: typed.code, class: typed.name, message: redact(String(typed.message ?? typed)).slice(0, 300), detail: typed.detail === undefined ? null : redact(String(typed.detail)).slice(0, 400), retryable: typed.retryable },
      verdict: {
        status: executedAny ? 'PARTIAL' : status,
        exit_code: exitCode,
        // A hard gate is the typed code itself, plus the driver's own marker when
        // the throw came from this file rather than from the boundary.
        hard_gates: [typed.code, ...(untypedDriverDefect ? [`UNTYPED_${String(error?.name ?? 'UNKNOWN')}`] : [])],
        executed_before_the_failure: executedRuns.length,
        requested: options.tasks === null ? null : taskCountOrNull,
      },
      limitations: [
        limitation,
        ...(executedAny
          ? [`PARTIAL: ${executedRuns.length} run(s) executed and are reported above; the driver then threw ${typed.code} outside the board. The runs are NOT discarded and this record does NOT claim that no execution happened.`]
          : ['NOT_RUN: this record contains no execution. The boundary was never asked to dispatch an executor, so no real-adapter fact, no usage figure and no status is established by it.']),
        ...(untypedDriverDefect
          ? ['UNTYPED_DRIVER_DEFECT: the throw above came from scripts/s2-007r-run.mjs, not from the board and not from the provider. It is a defect in this driver and is reported as one, so the next reader debugs this module. The raw message and the stack shape are in the refusal field.']
          : []),
        context.project === null
          ? 'project: never validated, because the run was refused before the fixture was read'
          : `project: ${context.project.source} (${context.project.file_count} files, digest ${context.project.digest})`,
        `transport tree: ${context.transport_tree.resolved_source === null ? 'unresolved' : `${context.transport_tree.resolved_source} (${context.transport_tree.resolved_dir}, modules: ${(context.transport_tree.modules ?? []).join(', ')})`}`,
      ],
    };
    try {
      written = await writeRecord(options.out, record, executedRuns, withRegistrationGateNote);
    } catch (writeError) {
      // FINDING (run-driver review #15), APPLIED: the write error used to be
      // swallowed, so a record that could not be published was indistinguishable
      // from one that was. The stdout summary below carries it, and it is a hard
      // gate: a run whose record is not on disk is not a recorded run.
      record.verdict = {
        ...record.verdict,
        hard_gates: [...record.verdict.hard_gates, 'RECORD_NOT_PUBLISHED'],
        status: 'FAIL',
        exit_code: 1,
      };
      record.limitations = [...(record.limitations ?? []), `RECORD_NOT_PUBLISHED: ${redact(String(writeError?.message ?? writeError)).slice(0, 200)}`];
      written = { written: [], withheld: false, reason: 'the record could not be written' };
      exitCode = 1;
    }
  }

  // The registration gate is a chicken-and-egg worth naming in the record
  // itself: the transport's own constructor only corroborates a registration
  // from a real-run evidence record, and such a record can only exist after a
  // real executor process has run. Saying it here beats leaving the next reader
  // to rediscover it from two modules. It is applied by writeRecord BEFORE the
  // digest is computed, so the note cannot invalidate the digest (finding #1).

  process.stdout.write(`${JSON.stringify({
    ok: exitCode === 0,
    verdict: record.verdict,
    status: record.verdict.status,
    exit_code: exitCode,
    realAdapterStatus: record.honesty.realAdapterStatus,
    out: record.invocation?.out ?? null,
    written: written.written,
    record_withheld: written.withheld === true ? written.reason : null,
    refusal: record.refusal ?? null,
    runs: (record.runs ?? []).map((row) => ({
      label: row.label, task_id: row.task_id, adapter_id: row.adapter_id, run_id: row.run_id ?? null,
      verdict: row.verdict, outcome: row.result?.outcome ?? null, task_state: row.committed?.task?.state ?? null,
      exit_code_reported_by_transport: row.executor?.reported?.exit_code ?? null,
      session_id_reported_by_transport: row.executor?.reported?.session_id ?? null,
      parent_wall_ms: row.outbox?.parent_wall_ms ?? null,
      findings: (row.findings ?? []).map((item) => item.id),
    })),
    limitations: record.limitations,
  }, null, 2)}\n`);
  process.exit(exitCode);
}

function collectLimitations({ record, runs, tier, options, source }) {
  const limitations = [];
  if (tier === 'postgres') {
    limitations.push('the --postgres URL is referenced by variable name only: its password is never read into, printed by, or hashed into this record, and the CLI line is redacted before it is written');
  }
  limitations.push(`project fixture: ${source.requested} (${source.fileCount} files, digest ${source.digest}); a run against a scratch fixture is a run against those bytes, and the digest is the only identity of them`);
  limitations.push(`store tier: ${tier}. The in-memory store has no durability and no cross-process concurrency, so nothing in this record is evidence about a second process racing this run.`);
  limitations.push('wall clock: parent-side measurement with process.hrtime.bigint() around the outbox dispatch; it is startup-dominated and is meaningful only within one (adapter, configuration) cell. It is not model latency.');
  limitations.push('executor argv, exit code and usage are REPORTED by the real transport, which is the executor\'s own parent process; this driver measured the wall clock and its own liveness independently and did not launder a reported value into an independent observation.');
  for (const row of runs) {
    if (row.executor?.available !== true) {
      limitations.push(`run ${row.label}: the transport published no crossing record, so argv/exit code/usage are UNOBSERVED: ${row.executor?.reason ?? 'unknown'}`);
      continue;
    }
    if (row.executor.missing.length > 0) {
      limitations.push(`run ${row.label}: the transport did not report ${row.executor.missing.join(', ')}; those fields stay null in this record and are not estimated`);
    }
  }
  if (record.verdict?.hard_gates?.includes('EXECUTOR_NOT_INDEPENDENTLY_OBSERVED')) {
    limitations.push('EXECUTOR_NOT_INDEPENDENTLY_OBSERVED: the run\'s claim that a real executor ran is supported by the collected result and the transport\'s own report, not by an argv, an exit code, a session id and a pid the PARENT can re-read. A missing one of those is a missing observation, and the run is a FAIL until the transport publishes it.');
  }
  limitations.push('no human reviewer exists in this run: every task stops at IN_REVIEW and the DONE edge is structurally unreachable (no principal holds board.review.approve)');
  limitations.push(`configuration: this invocation drove the validated surface "${options.configuration}" (an explicit, required argument of the transport, not a label), so it resolves ONE cell of the axis and difference of nothing. A comparison is a separate aggregation over one project digest and one campaign grant; scripts/s2-007r-measurement-set.mjs is what differences the cells, and it asserts on the NORMALISED argv digest, never on the raw one`);
  for (const row of runs) {
    if (row.argv?.observed === true && row.argv.config_delta === 'none' && options.configuration !== 'none') {
      limitations.push(`run ${row.label}: the argv the transport built carried no configuration difference for ${String(row.provider)} (${row.argv.config_delta_reason}); the cell is config_delta none by construction and is EXCLUDED from the comparison with that reason, not reported as "no difference observed"`);
    }
  }
  return limitations;
}

/**
 * The record itself is scanned with the same patterns before it is published.
 * A record that trips one is NOT written: the raw log scan already withholds
 * offending executor output, so a hit here means something this driver put in
 * the record, and publishing it anyway would defeat the whole point.
 */
function scanRecordForCredentials(record) {
  const text = `${JSON.stringify(record, null, 2)}\n`;
  for (let index = 0; index < CREDENTIAL_PATTERNS.length; index += 1) {
    if (CREDENTIAL_PATTERNS[index].test(text)) {
      return { clean: false, pattern_index: index, pattern: CREDENTIAL_PATTERNS[index].toString(), bytes: Buffer.byteLength(text, 'utf8') };
    }
  }
  return { clean: true, pattern_index: null, pattern: null, bytes: Buffer.byteLength(text, 'utf8') };
}

/**
 * The registration gate is a chicken-and-egg worth naming in the record itself:
 * the transport's own constructor only corroborates a registration from a
 * real-run evidence record, and such a record can only exist after a real
 * executor process has run. It is applied HERE, before the digest is computed,
 * so the note can never invalidate the digest it is added to.
 */
const REGISTRATION_GATE_NOTE = 'registration gate (observed here, not worked around): createRealRegistration() yields NOT_RUN_REAL_ADAPTER unless the caller hands it a realRunEvidence record, and src/lib/agentboard/commands.mjs refuses to register an adapter_kind "real" whose provenance is not REAL_ADAPTER_AVAILABLE. That evidence requires a prior REAL executor crossing whose raw process log exists on disk with a NON-ZERO exit status, so the FIRST governed run cannot itself produce it. The driver does not fabricate that record and does not spawn an executor outside the board to obtain one: both would be a run the board never authorised. Unblocking it is a decision for the transport owner (issue #45), not for this driver.';

function withRegistrationGateNote(final) {
  if (final.refusal?.code !== 'AGENT_UNAVAILABLE'
      || !`${final.refusal.message ?? ''}${final.refusal.detail ?? ''}`.includes('ADAPTER_REGISTRATION_REFUSED')) {
    return final;
  }
  if ((final.limitations ?? []).includes(REGISTRATION_GATE_NOTE)) return final;
  return { ...final, limitations: [...(final.limitations ?? []), REGISTRATION_GATE_NOTE] };
}

async function writeRecord(outDir, record, runs, finalise = null) {
  // FINDING (run-driver review #1), APPLIED. The finaliser runs first and the
  // digest is computed over the FINAL document, so `record_digest` in the file
  // is the digest of the file's own bytes. The previous order published a digest
  // of a document that a later block then changed.
  const final = typeof finalise === 'function' ? finalise(record) : record;
  const scan = scanRecordForCredentials(final);
  if (!scan.clean) {
    return {
      written: [],
      withheld: true,
      reason: `the record itself tripped credential pattern ${scan.pattern} (${scan.bytes} bytes); it was NOT written, and the refusal is on stdout instead`,
    };
  }
  fs.mkdirSync(outDir, { recursive: true, mode: 0o755 });
  const published = { ...final, record_digest: wireDigest({ ...final, record_digest: undefined }) };
  const written = [path.join(outDir, 'run-record.json')];
  fs.writeFileSync(written[0], `${JSON.stringify(published, null, 2)}\n`, 'utf8');
  record.record_digest = published.record_digest;
  record.limitations = published.limitations;
  // One file per run, so a third party can read a single run without the rest.
  for (const row of runs) {
    const target = path.join(outDir, `run-${row.label}.json`);
    fs.writeFileSync(target, `${JSON.stringify(row, null, 2)}\n`, 'utf8');
    written.push(target);
  }
  return { written, withheld: false, reason: null };
}

await main();
