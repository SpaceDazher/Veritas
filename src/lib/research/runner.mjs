// S2-008 research track — the DETERMINISTIC RUN ENGINE (issue #8, track
// "deterministic parallel research track"; issue SpaceDazher/Veritas#8).
//
// WHAT THIS MODULE IS
// The engine that turns ONE preregistration into ONE run record, in this order
// and in no other: read and validate the preregistration -> freeze the
// expected-value table -> resolve the preregistered seed set, metric, stopping
// rule, noise band, decision rule, timeout and budget reservation -> purge this
// run's own registry root -> record the preregistration in the ledger -> PROVE
// the ordering against that ledger -> OPEN the budget reservation -> for EVERY
// preregistered trial, in the preregistered order: re-prove the seed set is
// frozen, re-check and settle the reservation, execute the trial, classify its
// outcome, resolve its verdict, append its result -> aggregate the metric ->
// record wall-clock latency -> bind the whole thing to a provenance block and to
// a decision digest.
//
// WHAT THIS MODULE IS NOT
//   * It is NOT a verdict layer. A trial verdict comes from `resolveTrialVerdict`
//     and a campaign verdict from `resolveCampaignVerdict`, both in
//     ./comparator.mjs (W3), which in turn delegates to `resolveVerdict` in
//     src/lib/sloqual/comparator.mjs. This file names no verdict of its own and
//     contains no statistics.
//   * It is NOT a store. The journal, the revision CAS, the idempotency ledger,
//     the torn-tail recovery and the purge live in ./registry.mjs (W2). This file
//     writes only through `appendRecord` / `recordSpend` / `purgeRegistry`.
//   * It is NOT an executor. `executeTrial` is injected and has NO default. A run
//     engine with a built-in trial would let a pass be produced by the engine
//     rather than by the thing under test, so a missing executor is a refusal
//     (NeedsInput) and never a synthetic result.
//   * It is NOT parallel. The engine walks its trials SEQUENTIALLY. The
//     parallelism the ticket asks for is two PROCESS-SEPARATED runs with
//     distinct ids and nonces (scripts/s2-008-run.mjs, W4). A sequential engine
//     is what makes the A5 field-by-field repeat-run comparison meaningful: an
//     interleaved engine would make the observed order a function of the host.
//   * It is NOT a source of expectations. The expected-value table is frozen in
//     ./expected-values.mjs (W3) and pinned against the preregistration by
//     `assertTableFrozen` BEFORE trial one. This file reads it and never writes
//     it: an engine that could edit the expectation after the fact would make
//     every property below unfalsifiable.
//
// THE FIVE OUTCOMES ARE DISTINCT AND NONE IS A ZERO
//   POSITIVE / NEGATIVE / NULL come from a measured observation, through
//   `decisionFromInterval` (comparator.mjs). INFRA is a definite, observed
//   failure of the machinery. UNRESOLVED is an effect nobody observed. They are
//   four different facts and the record keeps them apart:
//     * a NEGATIVE result is a measurement that clears the noise band the other
//       way; a NULL result is a measurement INSIDE the band. Merging them is how
//       "no effect" becomes "no measurement" and back.
//     * an INFRA failure is a first-class outcome, not a skip and not a zero, and
//       it does NOT open a reconciliation: a definite failure is not an unknown
//       effect.
//     * an UNRESOLVED trial (interrupted, timed out, or measured as nothing at
//       all) opens a RECONCILIATION with an explicit decider kind. It is never a
//       blind retry (there is no retry path in this file at all) and never a
//       silent zero (`metricsSummary` in comparator.mjs counts it separately, and
//       `resolveTrialVerdict` fails it closed).
//
// THE CLOCK IS INJECTED AND NO VERDICT READS IT
//   The clock is `fixedClock` from src/lib/agentboard/policy.mjs — the only
//   clock source on this boundary. It appears in exactly three places, all of
//   them bookkeeping: the journal records' `at`/`created_at`, the reservation
//   comparison, and the per-trial `elapsed_ms` fallback. Wall-clock latency is
//   MEASURED and stored under `latency`, which `latencyRecorded` stamps
//   `decides: false` — and this file REFUSES a latency block that claims
//   otherwise, so "latency never decides" is a guard and not a convention.
//   `decisionDigest` hashes an explicit ALLOWLIST projection that contains no
//   wall-clock field, and `assertNoWallClockInVerdict` walks that projection and
//   throws on a timestamp-shaped string or an excluded field name, so a future
//   edit that leaks a clock reading into the verdict fails loudly. The property
//   "two different wall-clock values produce a bit-identical verdict" is
//   EXECUTABLE here as `verifyClockInvariance`, including its own non-vacuity
//   check: the two record digests must DIFFER and a one-trial mutation must
//   change the decision digest, or the invariance is proven by nothing.
//   The honest boundary of the property: a clock that crosses a PREREGISTERED
//   threshold (a reservation's `expires_at`, a trial's timeout) MUST change the
//   verdict, because that is the budget and timeout rules doing their job. What
//   must never change the verdict is a wall-clock OBSERVATION. `verifyClockInvariance`
//   checks the former is not in play by requiring both clocks to sit inside the
//   reservation window, and says so in its witness.
//
// EVERY ARTEFACT IS BOUND (A5)
//   `bindArtefact` writes the provenance block INTO the document — commit SHA,
//   tree SHA, raw run id, executor id, pid and a per-process nonce — and adds
//   `artefact_digest` over the whole document. `assertArtefactBound` recomputes
//   it, so a mutated artefact is detectable, and `writeArtefact` refuses to write
//   one that does not verify. The nonce is derived by `deriveProcessNonce` from
//   the label, the raw run id, the attempt and the pid: distinct per process,
//   and EXCLUDED from `decisionDigest` along with every timestamp and latency
//   sample, because A5 names `run_id`, `pid`, `executor_id` and timestamps as
//   the only differences a repeat run may show.
//
// REFUSALS ARE TYPED, AND A REFUSED RUN STILL PRODUCES A RECORD
//   Every refusal is a BoardError from src/lib/agentboard/errors.mjs. A run that
//   is refused (budget exceeded, reservation expired, a trial that could not be
//   executed) returns a record with `run.status = 'REFUSED'` or
//   'RECONCILIATION_REQUIRED' and its unexecuted trials recorded as SKIPPED with
//   the code that refused them. It does NOT throw, because a refusal that
//   produced no artefact would be indistinguishable from a run that never
//   happened, and "I could not produce a result" must itself be evidence. The
//   engine throws only when it cannot produce an honest record at all: a
//   malformed context, a missing executor, a missing dependency, a
//   non-canonical artefact, a tamper.
//
// DEPENDENCY SEAM, AND THE ONE DEFAULT PATH NOT SATISFIABLE YET
//   Every sibling boundary is reached through `deps` — `{constants,
//   preregistration, registry, comparator, expected}` — defaulting to this
//   directory's real modules. Nothing here re-implements a sibling: a missing
//   function is NeedsInput('RUNNER_DEPENDENCY_MISSING:<group>.<name>'), never a
//   private fallback, and a sibling still throwing NOT_IMPLEMENTED propagates
//   unchanged rather than being caught and turned into a result. A test double
//   may be injected; it is a stand-in for the sibling and never a second verdict
//   layer. The vocabulary (TRIAL_STATUSES, RESEARCH_OUTCOMES,
//   RESEARCH_ID_PREFIXES, RESEARCH_HARD_GATE_COUNTERS) is read from
//   ./constants.mjs (W1) at CALL time through the closed-set checks, so a
//   widened vocabulary is a refusal at the point of use and not a silent
//   extension here. W1's reconciliation-id prefix is found by looking for the
//   key that names a reconciliation (`reconciliation` -> `rec-`); a caller whose
//   table names it differently may pass `reconciliationPrefix` explicitly, and
//   a name this file guesses wrong is reported rather than papered over.
//
// THREE GAPS THIS FILE REPORTS INSTEAD OF CLOSING
//   1. NO PREREGISTERED PER-TRIAL TIMEOUT IN THE CORPUS. The engine enforces
//      one and refuses to invent one, so against the corpus as it stands
//      today it refuses with TRIAL_TIMEOUT_NOT_PREREGISTERED. W2 owns
//      corpus/s2-008/preregistration.json and must publish `trial_timeout_ms`
//      (the four members searched are in TRIAL_TIMEOUT_PATHS). This is a hole
//      in the track, not a defect here, and the refusal is the honest state of
//      it.
//   2. TWO FROZEN SURFACES SPELL THE PREREGISTRATION ROW DIFFERENTLY —
//      `PREREGISTRATION_RECORD` (preregistration.mjs:227, read by the ordering
//      proof) vs `PREREGISTRATION_RECORDED` (expected-values.mjs:154, the
//      ledger table). The engine writes both names on one row; D owns the
//      reconciliation.
//   3. THE CAMPAIGN VERDICT IS NOT DECIDED HERE AND CANNOT BE.
//      `resolveCampaignVerdict` (comparator.mjs) resolves from `{failures,
//      limits, proofStatus}` — the OUTPUT of a two-run comparison. Calling it
//      with a single run record's empty failure list would return PASS for a
//      run nobody compared, which is the silent pass the ticket names. The
//      engine therefore records per-trial verdicts and stops there.
//
// DETERMINISM
//   No network, no LLM, no credentials, no `Date.now()`, no `Math.random()`, no
//   argument-less `new Date()`. `process.pid` is read once, by
//   `deriveProcessNonce`, and only to make the nonce distinct per process; it is
//   excluded from every decision digest. Same base + same injected clock =>
//   same decision digest, and that is checkable with `verifyClockInvariance`
//   rather than asserted here.
//
// OWNER: W2-lineage engine worker. This file is not in the judged plan's frozen
// interface list (plan §1 freezes eleven modules plus index.mjs, and no
// runner), so its export surface is owned here and reported to D: the barrel
// index.mjs does not re-export it, and a caller must import
// `src/lib/research/runner.mjs` directly.
import { writeFileSync } from 'node:fs';

import { canonicalDigest, canonicalize, assertCanonicalSafety } from '../verifier/canonical-json.mjs';
import { fixedClock } from '../agentboard/policy.mjs';
import { RECONCILIATION_DECIDER_KINDS, RECONCILIATION_RESOLUTIONS } from '../agentboard/store.mjs';
import {
  BlockedPolicy,
  BudgetExceeded,
  MalformedResult,
  NeedsInput,
  ProviderFailure,
  ReconciliationRequired,
  isBoardError,
  redact,
  toBoardError,
} from '../agentboard/errors.mjs';
import * as researchConstants from './constants.mjs';
import * as researchPreregistration from './preregistration.mjs';
import * as researchRegistry from './registry.mjs';
import * as researchComparator from './comparator.mjs';
import * as researchExpected from './expected-values.mjs';
import * as researchContracts from './contracts.mjs';

/**
 * The version string of the run engine, for the evidence record. Frozen
 * literal; changing it re-versions every record this file writes.
 * @type {string}
 */
export const RUNNER_VERSION = 's2-008-runner-v1';

/**
 * The fields a repeat run MAY differ in, named here once so
 * `evidence/s2-008-replay.json`'s field-by-field diff and `verdictProjection`
 * cannot drift apart (A5).
 *
 * This is NOT an allowlist of what may vary in the ARTEFACT — every run has a
 * different run id, nonce and pid — it is the list of fields that must not
 * reach the DECISION digest, plus the clock-shaped names a caller must never
 * put into a verdict-bearing position. `assertNoWallClockInVerdict` rejects all
 * of them inside the hashed projection.
 * @type {ReadonlyArray<string>}
 */
export const DECISION_EXCLUDED_FIELDS = Object.freeze([
  'run_id',
  'nonce',
  'pid',
  'executor_id',
  'clock',
  'started_at',
  'finished_at',
  'duration_ms',
  'created_at',
  'recorded_at',
  'at',
  'elapsed_ms',
  'latency_ms',
  'latency',
]);

// --- shapes, only ever used to REJECT ---------------------------------------
const GIT_OBJECT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const RUN_ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const EXECUTOR_ID_RE = /^exec-[a-z0-9][a-z0-9-]{0,40}$/;
const NONCE_RE = /^n-[a-z0-9][a-z0-9-]{0,19}-[0-9a-f]{16}$/;
const LABEL_RE = /^[a-z0-9][a-z0-9-]{0,19}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_DETAIL = 400;

// The four dependency groups. Anything else a caller passes is ignored rather
// than honoured, so a typo in a group name cannot silently disable a boundary.
const DEP_GROUPS = Object.freeze(['constants', 'preregistration', 'registry', 'comparator', 'expected', 'contracts']);const DEFAULT_DEPS = Object.freeze({
  constants: researchConstants,
  preregistration: researchPreregistration,
  registry: researchRegistry,
  comparator: researchComparator,
  expected: researchExpected,
  // S3: the engine validates the hypothesis card against the FROZEN schema
  // before it copies the card into every trial, so the comparator — the one
  // place a causal claim is classified — is never handed a document the frozen
  // contract would have rejected.
  contracts: researchContracts,
});

// The final run statuses. Three values, and one of them ("COMPLETED") does not
// mean "the hypothesis held" — it means every preregistered trial produced a
// record. The verdict is the comparator's, never this file's.
/** The record kinds THIS ENGINE writes. Used by `purgeForThisRun` to prove
 *  that a caller-performed purge really removed a previous run's rows. */
const ENGINE_OWNED_RECORD_KINDS = Object.freeze([
  'PREREGISTRATION', 'BUDGET_RESERVATION', 'BUDGET_SPEND', 'BUDGET_RELEASE', 'TRIAL_RESULT', 'RECONCILIATION',
]);

const RUN_COMPLETED = 'COMPLETED';
const RUN_REFUSED = 'REFUSED';const RUN_RECONCILIATION = 'RECONCILIATION_REQUIRED';

// Reason codes the runner itself opens a reconciliation for. The BoardError
// codes come from src/lib/agentboard/errors.mjs and are never re-declared.
const REASON_UNKNOWN_OUTCOME = 'UNKNOWN_OUTCOME';
const REASON_TIMEOUT = 'TIMEOUT';
const REASON_MEASUREMENT_ABSENT = 'MEASUREMENT_ABSENT';
const REASON_RESERVATION_EXPIRED = 'BUDGET_RESERVATION_EXPIRED';

// The journal record kinds this engine writes. The ENVELOPE kind and the
// payload `record_kind` are two different members with two different jobs, and
// they are spelled differently on purpose:
//
//   * `PREREGISTRATION_ROW_KIND` is the envelope kind, and it is the spelling
//     `preregistration.mjs#assertPreregisteredBeforeRun` recognises when it
//     proves the ordering (its frozen `PREREGISTRATION_ROW_KINDS` is
//     PREREGISTRATION | PREREG | PREREGISTRATION_RECORD). Without it the
//     ordering proof cannot see the row and refuses with
//     PREREGISTRATION_NOT_IN_JOURNAL.
//   * `PREREGISTRATION_RECORD_KIND` is the payload's own name for the fact, and
//     it is the spelling the track's frozen ledger table uses
//     (`EXPECTED_LEDGER_SHAPE` in ./expected-values.mjs) and the spelling
//     scripts/s2-008-harness.mjs writes.
//
// KNOWN DISAGREEMENT, REPORTED AND NOT PAPERED OVER: those two frozen surfaces
// do not share a spelling for one fact (`PREREGISTRATION_RECORD` in
// preregistration.mjs:227 vs `PREREGISTRATION_RECORDED` in
// expected-values.mjs:154). The engine writes BOTH names on the SAME row
// rather than choosing one and losing the other property, and the run record
// reports the envelope kinds it actually wrote under `ledger.kinds`. D owns
// reconciling the two tables; this file may not edit either.
const PREREGISTRATION_ROW_KIND = 'PREREGISTRATION';
const PREREGISTRATION_RECORD_KIND = 'PREREGISTRATION_RECORDED';
const TRIAL_RESULT_ROW_KIND = 'TRIAL_RESULT';
const BUDGET_RESERVATION_KIND = 'BUDGET_RESERVATION';

// The preregistration members a per-trial timeout may be published in, in the
// order they are read. The FIRST one present wins and the name it came from is
// reported in `run.engine.trial_timeout_source`, so a reader can see which
// document fixed the budget. There is no default: an engine that supplied its
// own timeout would be enforcing a rule chosen after the hypothesis was
// registered, which is the run-time choice the ticket forbids.
const TRIAL_TIMEOUT_PATHS = Object.freeze([
  Object.freeze(['trial_timeout_ms']),
  Object.freeze(['budget_reservation', 'trial_timeout_ms']),
  Object.freeze(['stopping_rule', 'trial_timeout_ms']),
  Object.freeze(['noise_rule', 'trial_timeout_ms']),
]);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function boundDetail(value) {
  const text = redact(String(value ?? ''));
  return text.length > MAX_DETAIL ? `${text.slice(0, MAX_DETAIL - 1)}…` : text;
}

function isoOf(clock) {
  const value = clock.nowIso();
  if (typeof value !== 'string' || !ISO_RE.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new NeedsInput('CLOCK_INVALID', `the injected clock produced ${String(value)}`);
  }
  return value;
}

/**
 * Resolve the dependency seam. Missing or malformed groups are refused; a
 * group is never replaced by this file's own logic.
 * @param {object} [injected] Partial dependency override, e.g. test doubles.
 * @returns {Readonly<Record<string, object>>} The five resolved groups.
 * @throws {import('../agentboard/errors.mjs').NeedsInput} 'RUNNER_DEPENDENCY_GROUP_INVALID'.
 */
function resolveDeps(injected) {
  if (injected === undefined) return DEFAULT_DEPS;
  if (!isPlainObject(injected)) {
    throw new NeedsInput('RUNNER_DEPENDENCY_GROUP_INVALID', 'deps must be a plain object of dependency groups');
  }
  const deps = { ...DEFAULT_DEPS };
  for (const key of Object.keys(injected)) {
    if (!DEP_GROUPS.includes(key)) {
      throw new NeedsInput('RUNNER_DEPENDENCY_GROUP_INVALID', `unknown dependency group ${key}; expected one of ${DEP_GROUPS.join('|')}`);
    }
    if (!isPlainObject(injected[key])) {
      throw new NeedsInput('RUNNER_DEPENDENCY_GROUP_INVALID', `dependency group ${key} must be a module namespace or an object of functions`);
    }
    deps[key] = injected[key];
  }
  return Object.freeze(deps);
}

function requireFn(deps, group, name) {
  const fn = deps?.[group]?.[name];
  if (typeof fn !== 'function') {
    throw new NeedsInput(
      `RUNNER_DEPENDENCY_MISSING:${group}.${name}`,
      `the runner refuses to substitute its own implementation of ${group}.${name}`,
    );
  }
  return fn;
}

function requireList(deps, group, name) {
  const list = deps?.[group]?.[name];
  if (!Array.isArray(list) || list.length === 0) {
    throw new NeedsInput(
      `RUNNER_DEPENDENCY_MISSING:${group}.${name}`,
      `the closed vocabulary ${group}.${name} is unavailable; the engine names a status or an outcome and refuses to invent one`,
    );
  }
  return list;
}

function requireMember(deps, group, name, value, what) {
  const list = requireList(deps, group, name);
  if (!list.includes(value)) {
    throw new MalformedResult(
      'RESEARCH_VOCABULARY_UNKNOWN',
      `${what} ${String(value)} is not a member of ${group}.${name} (${list.join('|')})`,
    );
  }
  return value;
}

/**
 * The id prefix used for reconciliation rows. Read from W1's
 * `RESEARCH_ID_PREFIXES` at CALL time; an explicit prefix wins, because the
 * plan froze the prefix VALUES but not the KEY NAMES, and a guessed key would
 * mint ids outside the track's own vocabulary.
 * @param {object} deps The resolved dependency groups.
 * @param {string|undefined} explicit A caller-supplied prefix, when given.
 * @returns {string} The prefix, including its trailing `-`.
 * @throws {import('../agentboard/errors.mjs').NeedsInput} when neither the
 *   explicit value nor the table can supply one.
 */
function reconciliationPrefix(deps, explicit) {
  if (typeof explicit === 'string' && explicit.length > 0) return explicit;
  const table = deps?.constants?.RESEARCH_ID_PREFIXES;
  if (!isPlainObject(table)) {
    throw new NeedsInput('RESEARCH_ID_PREFIXES_UNAVAILABLE', 'constants.mjs exports no RESEARCH_ID_PREFIXES table yet; pass reconciliationPrefix explicitly');
  }
  for (const [kind, prefix] of Object.entries(table)) {
    if (kind.includes('recon') && typeof prefix === 'string' && prefix.length > 0) return prefix;
  }
  throw new NeedsInput(
    'RESEARCH_ID_PREFIXES_UNAVAILABLE',
    `no reconciliation key in RESEARCH_ID_PREFIXES (keys: ${Object.keys(table).join('|')}); pass reconciliationPrefix explicitly`,
  );
}

// --- provenance (A5) ---------------------------------------------------------

/**
 * A per-process nonce, distinct from every other process's, derived WITHOUT
 * randomness from the label, the raw run id, the attempt and the pid. Two runs
 * of the same base therefore differ in their nonce and in nothing else that
 * matters, and the nonce is excluded from `decisionDigest`.
 * @param {{label?: string, runId?: string, attempt?: number, pid?: number}} [args]
 * @returns {string} `n-<label>-<16 hex>`.
 * @throws {import('../agentboard/errors.mjs').NeedsInput} on a malformed
 *   label, run id, attempt or pid.
 */
export function deriveProcessNonce({ label = 'a', runId, attempt = 0, pid } = {}) {
  if (typeof label !== 'string' || !LABEL_RE.test(label)) {
    throw new NeedsInput(`NONCE_LABEL_INVALID:${String(label)}`);
  }
  if (typeof runId !== 'string' || !RUN_ID_RE.test(runId)) {
    throw new NeedsInput(`NONCE_RUN_ID_INVALID:${String(runId)}`);
  }
  if (!Number.isInteger(attempt) || attempt < 0) {
    throw new NeedsInput(`NONCE_ATTEMPT_INVALID:${String(attempt)}`);
  }
  const processId = pid ?? process.pid;
  if (!isPositiveInteger(processId)) {
    throw new NeedsInput(`NONCE_PID_INVALID:${String(processId)}`);
  }
  const nonce = `n-${label}-${canonicalDigest({ label, runId, attempt, pid: processId }).slice(0, 16)}`;
  if (!NONCE_RE.test(nonce)) throw new NeedsInput('NONCE_FORM_INVALID', nonce);
  return nonce;
}

/**
 * Freeze the provenance block every artefact of this run carries: the commit
 * SHA, the tree SHA, the raw run id, the executor id, the pid, a per-process
 * nonce and the injected clock instant. A run without a provenance block has no
 * evidence value at all (A5), so a missing commit or tree is a refusal, never a
 * placeholder.
 * @param {{commit: string, tree: string, runId: string, label?: string,
 *   executorId?: string, nonce?: string, attempt?: number, pid?: number,
 *   clock?: string, startedAt?: string}} args
 * @returns {Readonly<object>} The frozen provenance block.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} on a malformed
 *   commit, tree, run id, executor id, nonce or clock.
 */
export function freezeProvenance({
  commit,
  tree,
  runId,
  label = 'a',
  executorId = `exec-s2-008-${label}`,
  nonce,
  attempt = 0,
  pid,
  clock,
  startedAt,
} = {}) {
  if (typeof commit !== 'string' || !GIT_OBJECT_RE.test(commit)) {
    throw new MalformedResult('PROVENANCE_COMMIT_INVALID', `commit must be a git object id, got ${String(commit)}`);
  }
  if (typeof tree !== 'string' || !GIT_OBJECT_RE.test(tree)) {
    throw new MalformedResult('PROVENANCE_TREE_INVALID', `tree must be a git object id, got ${String(tree)}`);
  }
  if (typeof runId !== 'string' || !RUN_ID_RE.test(runId)) {
    throw new MalformedResult('PROVENANCE_RUN_ID_INVALID', `run id ${String(runId)} is not a lowercase id`);
  }
  if (typeof executorId !== 'string' || !EXECUTOR_ID_RE.test(executorId)) {
    throw new MalformedResult('PROVENANCE_EXECUTOR_ID_INVALID', `executor id ${String(executorId)}`);
  }
  if (typeof label !== 'string' || !LABEL_RE.test(label)) {
    throw new MalformedResult('PROVENANCE_LABEL_INVALID', `label ${String(label)}`);
  }
  const instant = clock ?? startedAt;
  if (typeof instant !== 'string' || !ISO_RE.test(instant) || !Number.isFinite(Date.parse(instant))) {
    throw new MalformedResult('PROVENANCE_CLOCK_INVALID', `clock must be an ISO-8601 instant, got ${String(instant)}`);
  }
  return Object.freeze({
    version: RUNNER_VERSION,
    commit,
    tree,
    run_id: runId,
    label,
    executor_id: executorId,
    pid: pid ?? process.pid,
    nonce: nonce ?? deriveProcessNonce({ label, runId, attempt, pid }),
    clock: instant,
    started_at: startedAt ?? instant,
  });
}

/**
 * Assert a provenance block carries the five bindings A5 requires: commit SHA,
 * tree SHA, raw run id, a distinct-per-process nonce and an executor id.
 * @param {object} provenance The block to check.
 * @returns {object} The same block, unchanged.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} naming the
 *   missing or malformed field.
 */
export function assertProvenance(provenance) {
  if (!isPlainObject(provenance)) {
    throw new MalformedResult('PROVENANCE_MISSING', 'a run record without provenance has no evidence value (A5)');
  }
  for (const field of ['commit', 'tree', 'run_id', 'executor_id', 'nonce', 'clock']) {
    if (provenance[field] === undefined || provenance[field] === null) {
      throw new MalformedResult('PROVENANCE_FIELD_MISSING', `provenance.${field} is required`);
    }
  }
  if (!GIT_OBJECT_RE.test(provenance.commit) || !GIT_OBJECT_RE.test(provenance.tree)) {
    throw new MalformedResult('PROVENANCE_OBJECT_INVALID', 'provenance.commit and provenance.tree must both be git object ids');
  }
  if (!RUN_ID_RE.test(provenance.run_id) || !EXECUTOR_ID_RE.test(provenance.executor_id) || !NONCE_RE.test(provenance.nonce)) {
    throw new MalformedResult('PROVENANCE_FIELD_INVALID', 'run id, executor id and nonce are malformed');
  }
  if (!ISO_RE.test(provenance.clock)) {
    throw new MalformedResult('PROVENANCE_CLOCK_INVALID', `provenance.clock ${String(provenance.clock)}`);
  }
  return provenance;
}

// --- artefact binding (A5) ---------------------------------------------------

/**
 * Bind a document to its provenance and to a content digest. The provenance
 * block is written INTO the document, so an artefact that lost it cannot be
 * produced by this function at all.
 * @param {object} record The document to bind.
 * @param {object} provenance A block from `freezeProvenance`, or one already
 *   carried by `record.provenance`.
 * @returns {object} A NEW document carrying `provenance` and
 *   `artefact_digest`. The input is not mutated.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} on a missing
 *   provenance block or a value that canonical-json-v1 cannot represent.
 */
export function bindArtefact(record, provenance) {
  if (!isPlainObject(record)) {
    throw new MalformedResult('ARTEFACT_MALFORMED', 'an artefact must be a plain object');
  }
  assertProvenance(provenance);
  const body = { ...record, provenance };
  delete body.artefact_digest;
  try {
    assertCanonicalSafety(body);
  } catch (error) {
    throw new MalformedResult('ARTEFACT_NOT_CANONICAL', boundDetail(error?.message ?? error));
  }
  return { ...body, artefact_digest: canonicalDigest(body) };
}

/**
 * Recompute an artefact's digest and refuse a mutated one. A tampered evidence
 * file is a finding, never a formatting difference.
 * @param {object} document A document from `bindArtefact` (or read back from disk).
 * @returns {object} The same document, unchanged.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'ARTEFACT_DIGEST_MISMATCH' / 'ARTEFACT_DIGEST_MISSING'.
 */
export function assertArtefactBound(document) {
  if (!isPlainObject(document)) {
    throw new MalformedResult('ARTEFACT_MALFORMED', 'an artefact must be a plain object');
  }
  if (typeof document.artefact_digest !== 'string') {
    throw new MalformedResult('ARTEFACT_DIGEST_MISSING', 'the artefact carries no artefact_digest');
  }
  const body = { ...document };
  delete body.artefact_digest;
  const actual = canonicalDigest(body);
  if (actual !== document.artefact_digest) {
    throw new MalformedResult('ARTEFACT_DIGEST_MISMATCH', `recorded ${document.artefact_digest}, recomputed ${actual}`);
  }
  return document;
}

/**
 * Write a bound artefact as one canonical-JSON line. The binding is VERIFIED
 * first: an artefact that does not verify is never written, because a written
 * and unreadable file is worse than a refusal that names the field.
 * @param {string} filePath Absolute path of the destination.
 * @param {object} document The bound artefact.
 * @param {{write?: (path: string, data: string) => unknown}} [options]
 *   An injectable writer (the harness seam and the test seam); defaults to
 *   `fs.writeFileSync`.
 * @returns {{path: string, bytes: number, artefact_digest: string}} What was
 *   written, so the harness can log it.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} on a relative
 *   path or an unbound document; `ProviderFailure` when the write itself fails.
 */
export function writeArtefact(filePath, document, { write } = {}) {
  if (typeof filePath !== 'string' || !filePath.startsWith('/') || filePath.length < 2) {
    throw new MalformedResult('ARTEFACT_PATH_INVALID', `an artefact path must be absolute, got ${String(filePath)}`);
  }
  assertArtefactBound(document);
  const writer = write ?? ((target, data) => writeFileSync(target, data, 'utf8'));
  if (typeof writer !== 'function') {
    throw new NeedsInput('ARTEFACT_WRITER_INVALID', 'options.write must be a function when present');
  }
  const payload = `${canonicalize(document)}\n`;
  try {
    writer(filePath, payload);
  } catch (error) {
    throw new ProviderFailure('ARTEFACT_WRITE_FAILED', boundDetail(error?.message ?? error));
  }
  return { path: filePath, bytes: payload.length, artefact_digest: document.artefact_digest };
}

// --- the decision digest, and the no-wall-clock guard ------------------------

/**
 * The verdict-bearing projection of a run record: an explicit ALLOWLIST of the
 * fields the decision may depend on.
 *
 * It is an allowlist and NOT a filtered copy of the record, so a field that is
 * not named here cannot reach the decision digest even by accident — including
 * every wall-clock field, every per-process identity field and the whole
 * `latency` block. What a field is DOES say is the run status, the
 * preregistration and table digests, the seed count, the stopping rule, the
 * budget totals, and per trial the index, id, seed, status, outcome, reason
 * codes, measurement, interval, noise band, decision, verdict, the four bindings
 * and its budget settlement.
 *
 * A preregistered trial id that happens to look like a timestamp is refused by
 * `assertNoWallClockInVerdict`; the fix is the preregistration's, not a
 * relaxation of this list.
 * @param {object} record A run record (bound or raw).
 * @returns {object} The projection that `decisionDigest` hashes.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when the record
 *   has no `trials` array or no run block.
 */
export function verdictProjection(record) {
  if (!isPlainObject(record) || !Array.isArray(record.trials) || !isPlainObject(record.run)) {
    throw new MalformedResult('RUN_RECORD_MALFORMED', 'verdictProjection needs a run record with a run block and a trials array');
  }
  return {
    version: record.version ?? null,
    ticket: record.ticket ?? null,
    run_status: record.run.status ?? null,
    // Projected field by field rather than copied whole: `budget.expires_at`
    // is a PREREGISTERED instant, and a preregistered instant is a constant of
    // the decision, not a wall-clock reading of it — so it is named here and
    // kept out of the hashed form on purpose.
    preregistration: isPlainObject(record.preregistration)
      ? {
        digest: record.preregistration.digest ?? null,
        expected_table_digest: record.preregistration.expected_table_digest ?? null,
        seed_count: record.preregistration.seed_count ?? null,
        trial_count: record.preregistration.trial_count ?? null,
        inference_mode: record.preregistration.inference_mode ?? null,
        stopping_rule: record.preregistration.stopping_rule ?? null,
        // The two rules the decision was made under. The stopping rule says
        // when the run stopped, the noise rule fixes the band and the
        // multiplicity rule fixes the correction: a record that hashed the
        // trials but not the rules it was judged by would compare two runs
        // that answered two different questions.
        noise_rule: record.preregistration.noise_rule ?? null,
        decision_rule: record.preregistration.decision_rule ?? null,
        budget: isPlainObject(record.preregistration.budget)
          ? {
            reservation_id: record.preregistration.budget.reservation_id ?? null,
            granted_units: record.preregistration.budget.granted_units ?? null,
            spent_units: record.preregistration.budget.spent_units ?? null,
            currency: record.preregistration.budget.currency ?? null,
          }
          : null,
      }
      : null,
    // The purge is NOT projected. `purge.purged` and `removedFiles` describe
    // the state of the caller's scratch directory — how many files the previous
    // run left behind — and a run on a clean root legitimately reports
    // `purged: false, removedFiles: 0` where a repeat run reports `true, 3`.
    // Hashing them made the decision digest a function of the housekeeping
    // and broke the clock-invariance property for a reason that has nothing to
    // do with the clock. Same rule as the `replayed` settlement flag below.
    trials: record.trials.map((trial) => ({
      index: trial.index ?? null,
      trial: trial.trial ?? null,
      // The seed SET. It used to be projected as `trial.seed` (singular), a
      // member no trial record has carried since the engine began writing
      // `seeds`, so the seed binding was hashed as a permanent null and a
      // substituted seed set could not move the digest at all.
      seeds: trial.seeds ?? trial.seed ?? null,
      metric: trial.metric ?? null,
      status: trial.status ?? null,
      outcome: trial.outcome ?? null,
      reason_codes: Array.isArray(trial.reason_codes) ? trial.reason_codes.slice() : null,
      observed: trial.observed ?? null,
      // The interval is projected member by member: only `lower` and `upper`
      // reach a decision, and copying the whole object would let an executor's
      // own timestamp ride into the hashed projection.
      interval: isPlainObject(trial.interval) ? { lower: trial.interval.lower ?? null, upper: trial.interval.upper ?? null } : null,
      noise_band: trial.noise_band ?? null,
      decision: trial.decision ?? null,
      verdict: trial.verdict ?? null,
      // The four bindings are projected field by field, and `replayed` is
      // deliberately NOT among them. A replayed settlement is a property of
      // whether the caller purged its own scratch ledger — which is exactly
      // what an idempotency ledger is FOR: a crash and restart must re-settle
      // the same charge without charging twice — and not a property of what the
      // experiment found. A verdict that moved with the purge state would be a
      // verdict about housekeeping.
      bindings: isPlainObject(trial.bindings)
        ? {
          seed: isPlainObject(trial.bindings.seed) ? { seeds: trial.bindings.seed.seeds ?? null, source: trial.bindings.seed.source ?? null } : null,
          // The holdout access instants (`read_at`, `decision_at`) are the one
          // pair of timestamps a decision genuinely reads, and they are NOT
          // projected: they are not measurement detail, they are the evidence
          // the comparator's own `holdoutBinding` check compares, and a digest
          // that hashed them would move with the clock. What IS projected is
          // the verdict itself plus the declared flags, so a peek that flips
          // ALLOW to VIOLATION still moves the digest — through the verdict,
          // which is the fact the A3/A5 witness is about.
          holdout: isPlainObject(trial.bindings.holdout)
            ? {
              partition: trial.bindings.holdout.partition ?? null,
              opens: trial.bindings.holdout.opens ?? null,
              max_opens: trial.bindings.holdout.max_opens ?? null,
              opened_before_decision_point: trial.bindings.holdout.opened_before_decision_point ?? null,
              one_shot: trial.bindings.holdout.one_shot ?? null,
              unseal_digest_present: typeof trial.bindings.holdout.unseal_digest === 'string' && trial.bindings.holdout.unseal_digest.length > 0,
            }
            : null,
          budget: isPlainObject(trial.bindings.budget)
            ? {
              reservation_id: trial.bindings.budget.reservation_id ?? null,
              units: trial.bindings.budget.units ?? null,
              settle_key: trial.bindings.budget.settle_key ?? null,
            }
            : null,
          evaluator: trial.bindings.evaluator ?? null,
        }
        : null,
      budget: isPlainObject(trial.budget)
        ? {
          units: trial.budget.units ?? null,
          settle_key: trial.budget.settle_key ?? null,
        }
        : null,
      reconciliation_id: trial.reconciliation_id ?? null,
    })),
    metrics: record.metrics ?? null,
    run_counters: record.run_counters ?? null,
    refusals: Array.isArray(record.refusals) ? record.refusals.map((refusal) => ({ code: refusal.code ?? null, trial_index: refusal.trial_index ?? null })) : null,
    reconciliations: Array.isArray(record.reconciliations)
      ? record.reconciliations.map((row) => ({
        reconciliation_id: row.reconciliation_id ?? null,
        trial_index: row.trial_index ?? null,
        resolution: row.resolution ?? null,
        decider_kind: row.decider_kind ?? null,
        reason_code: row.reason_code ?? null,
        decided: row.decided === true,
      }))
      : null,
  };
}

/**
 * Refuse a wall-clock reading inside the hashed verdict. Walks the projection
 * and throws on an excluded field NAME or on any ISO-8601-shaped string, so
 * "no verdict depends on wall-clock latency" is enforced at the only place it
 * could be broken.
 * @param {object} record A run record (bound or raw).
 * @returns {object} The projection, when it is clean.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'WALL_CLOCK_FIELD_IN_VERDICT' / 'TIMESTAMP_IN_VERDICT', naming the path.
 */
export function assertNoWallClockInVerdict(record) {
  const projection = verdictProjection(record);
  const excluded = new Set(DECISION_EXCLUDED_FIELDS);
  const walk = (value, where) => {
    if (typeof value === 'string') {
      if (ISO_RE.test(value)) {
        throw new BlockedPolicy('TIMESTAMP_IN_VERDICT', `a verdict-bearing value at ${where} is a timestamp: ${value}`);
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, index) => walk(item, `${where}[${index}]`));
      return;
    }
    if (!isPlainObject(value)) return;
    for (const [key, child] of Object.entries(value)) {
      if (excluded.has(key)) {
        throw new BlockedPolicy('WALL_CLOCK_FIELD_IN_VERDICT', `${key} must not reach the decision digest (at ${where})`);
      }
      walk(child, where === '' ? key : `${where}.${key}`);
    }
  };
  walk(projection, '');
  return projection;
}

/**
 * The digest of the verdict-bearing projection: `sha256:<64 hex>` over the
 * canonical-json-v1 form. Two runs of the same base at different wall-clock
 * values produce the SAME decision digest; a mutation of any verdict-bearing
 * field produces a different one. That is the A3/A5 "same base => same
 * verdict" witness, and it is comparable across processes.
 * @param {object} record A run record.
 * @returns {string} `sha256:<64 hex>`.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy} when the record
 *   carries a wall-clock field inside the projection.
 */
export function decisionDigest(record) {
  return canonicalDigest(assertNoWallClockInVerdict(record));
}

// --- reconciliation ----------------------------------------------------------

/**
 * Assert a decider kind is admissible for a resolution.
 *
 * A machine may not decide an effect nobody observed: `deterministic_gate` is
 * refused for `EFFECT_UNDETERMINED` and admitted only for a resolution whose
 * effect WAS observed. An undetermined effect is a human decision, and this file
 * has no way to pretend otherwise.
 * @param {string} kind A member of the frozen `RECONCILIATION_DECIDER_KINDS`
 *   (src/lib/agentboard/store.mjs:385).
 * @param {{resolution: string}} args The resolution the decider would close.
 * @returns {string} The same kind, unchanged.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'RECONCILIATION_DECIDER_KIND_UNKNOWN' /
 *   'RECONCILIATION_DECIDER_KIND_INSUFFICIENT'.
 */
export function assertReconciliationDeciderKind(kind, { resolution } = {}) {
  if (typeof kind !== 'string' || !RECONCILIATION_DECIDER_KINDS.includes(kind)) {
    throw new BlockedPolicy('RECONCILIATION_DECIDER_KIND_UNKNOWN', `decider kind must be one of ${RECONCILIATION_DECIDER_KINDS.join('|')}, got ${String(kind)}`);
  }
  if (typeof resolution !== 'string' || !RECONCILIATION_RESOLUTIONS.includes(resolution)) {
    throw new BlockedPolicy('RECONCILIATION_RESOLUTION_UNKNOWN', `resolution must be one of ${RECONCILIATION_RESOLUTIONS.join('|')}, got ${String(resolution)}`);
  }
  if (resolution === 'EFFECT_UNDETERMINED' && kind === 'deterministic_gate') {
    throw new BlockedPolicy('RECONCILIATION_DECIDER_KIND_INSUFFICIENT', 'no deterministic gate may close an effect nobody observed');
  }
  return kind;
}

/**
 * Build the OPEN reconciliation row for an interrupted, timed-out, unmeasured
 * or unbooked effect. The row records the OBLIGATION, never a decision:
 * `decided` is always false, `resolution` is `EFFECT_UNDETERMINED`, and the
 * resolutions a decider may choose from are the frozen four. The id is a digest
 * of the pure fields, so the same interruption replayed in the same run yields
 * the SAME id and cannot become a second, differently-identified row.
 * @param {{run: object, index: number, trial: string, reasonCode: string,
 *   detail?: string, deciderKind?: string, deps: object, prefix?: string,
 *   clockIso: string, reservationId?: string|null}} args
 * @returns {object} The reconciliation row.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy} on an
 *   inadmissible decider kind, as above.
 */
export function reconciliationRow({
  run,
  index,
  trial,
  reasonCode,
  detail = '',
  deciderKind = 'human_owner',
  deps,
  prefix,
  clockIso,
  reservationId = null,
} = {}) {
  const resolution = 'EFFECT_UNDETERMINED';
  assertReconciliationDeciderKind(deciderKind, { resolution });
  const provenance = run?.provenance;
  if (!isPlainObject(provenance)) {
    throw new MalformedResult('PROVENANCE_MISSING', 'a reconciliation row is bound to the run provenance');
  }
  const idPrefix = reconciliationPrefix(deps, prefix);
  const idBody = {
    run_id: provenance.run_id,
    index: index ?? null,
    reason_code: String(reasonCode ?? 'UNKNOWN_OUTCOME'),
    preregistration_digest: run?.preregistration?.digest ?? null,
  };
  return {
    record_kind: 'RECONCILIATION',
    reconciliation_id: `${idPrefix}${canonicalDigest(idBody).slice(0, 16)}`,
    run_id: provenance.run_id,
    nonce: provenance.nonce,
    trial_index: index ?? null,
    trial: trial ?? null,
    resolution,
    allowed_resolutions: RECONCILIATION_RESOLUTIONS.slice(),
    decider_kind: deciderKind,
    decided: false,
    reason_code: String(reasonCode ?? REASON_UNKNOWN_OUTCOME),
    preregistration_digest: run?.preregistration?.digest ?? null,
    reservation_id: reservationId ?? null,
    created_at: clockIso,
    detail: boundDetail(detail),
  };
}

// --- trial classification ----------------------------------------------------

/**
 * Classify ONE trial observation into the four first-class outcomes, with the
 * timeout enforced and no outcome collapsed into a zero. Pure: no clock, no
 * process, no filesystem, so a classification is checkable on its own.
 *
 * The order below IS the precedence, and it is the precedence the ticket needs:
 *   1. a definite infrastructure failure -> INFRA_ERROR / INFRA, and NO
 *      reconciliation, because a definite failure is not an unknown effect;
 *   2. an explicitly unknown or interrupted effect -> UNRESOLVED / UNRESOLVED
 *      plus a reconciliation row;
 *   3. a reported elapsed time beyond the PREREGISTERED per-trial timeout ->
 *      UNRESOLVED / UNRESOLVED plus a reconciliation row (the trial may or may
 *      not have completed, which is exactly an undetermined effect);
 *   4. no measurement at all -> UNRESOLVED / UNRESOLVED plus a reconciliation
 *      row. A null measurement is NOT a zero and NOT a skip;
 *   5. a finite measurement -> RESOLVED, with POSITIVE / NEGATIVE / NULL
 *      decided by `decisionFromInterval` against the preregistered noise band.
 * Anything else — a non-object, a string, NaN, an unknown status word — is a
 * refusal, never a guess.
 * @param {object} observation What `executeTrial` returned.
 * @param {{timeoutMs?: number, deps: object, index?: number, trial?: string,
 *   noiseBand?: number, rule?: object}} args
 *   `timeoutMs` and `noiseBand` are PREREGISTERED values read by
 *   `runDeterministicRun`; `rule` is the preregistered DECISION rule
 *   (`preregistration.multiplicity_rule`, projected by `decisionRuleOf`),
 *   NOT the stopping rule — `decisionFromInterval` corrects for a family and
 *   refuses a rule with no alpha.
 * @returns {{status: string, outcome: string, reason_codes: ReadonlyArray<string>,
 *   observed: number|null, interval: object|null, elapsed_ms: number|null,
 *   latency_source: string, infra: object|null,
 *   reconciliation: {reasonCode: string, detail: string}|null}}
 * @throws {import('../agentboard/errors.mjs').MalformedResult} /
 *   'NeedsInput' on a malformed observation or a missing preregistered rule.
 */
export function classifyTrialObservation(observation, { timeoutMs, deps, index = 0, trial = 'unknown', noiseBand, rule } = {}) {
  if (!isPlainObject(observation)) {
    throw new MalformedResult('TRIAL_OBSERVATION_MALFORMED', `trial ${String(trial)} at index ${index} returned ${observation === null ? 'null' : typeof observation}`);
  }
  const elapsed = observation.elapsed_ms;
  if (elapsed !== undefined && elapsed !== null && (typeof elapsed !== 'number' || !Number.isFinite(elapsed) || elapsed < 0)) {
    throw new MalformedResult('TRIAL_ELAPSED_INVALID', `trial ${String(trial)} reported elapsed_ms ${String(elapsed)}`);
  }
  const reportedInterval = isPlainObject(observation.interval) ? observation.interval : null;
  const base = {
    index,
    trial: String(trial),
    observed: null,
    interval: reportedInterval,
    elapsed_ms: typeof elapsed === 'number' ? elapsed : null,
    latency_source: typeof elapsed === 'number' ? 'executor_reported' : 'not_reported',
    decision: null,
    infra: null,
  };

  // 1. definite infrastructure failure.
  if (observation.infra !== undefined && observation.infra !== null) {
    const infra = isPlainObject(observation.infra) ? observation.infra : { code: 'PROVIDER_FAILURE', message: boundDetail(observation.infra) };
    return {
      ...base,
      status: requireMember(deps, 'constants', 'TRIAL_STATUSES', 'INFRA_ERROR', 'a trial status'),
      outcome: requireMember(deps, 'constants', 'RESEARCH_OUTCOMES', 'INFRA', 'a research outcome'),
      reason_codes: [typeof infra.code === 'string' ? infra.code : 'PROVIDER_FAILURE'],
      infra: { code: typeof infra.code === 'string' ? infra.code : 'PROVIDER_FAILURE', message: boundDetail(infra.message ?? '') },
      reconciliation: null,
    };
  }

  // 2. an effect nobody observed.
  if (observation.outcome_unknown === true || observation.interrupted === true || typeof observation.interrupted_at === 'string') {
    return unresolved(base, deps, typeof observation.code === 'string' ? observation.code : REASON_UNKNOWN_OUTCOME, boundDetail(observation.detail ?? observation.message ?? 'the executor reported an undetermined effect'));
  }

  // 3. the per-trial timeout, against the PREREGISTERED budget.
  if (isPositiveInteger(timeoutMs) && typeof elapsed === 'number' && elapsed > timeoutMs) {
    return unresolved(base, deps, REASON_TIMEOUT, `elapsed_ms ${elapsed} exceeds the preregistered per-trial timeout ${timeoutMs}`);
  }

  // 4. no measurement. Never a zero, never a skip.
  if (observation.measured === undefined || observation.measured === null) {
    return unresolved(base, deps, REASON_MEASUREMENT_ABSENT, 'the executor returned no measurement; a missing measurement is not a zero and not a skip');
  }

  // 5. a measurement.
  if (typeof observation.measured !== 'number' || !Number.isFinite(observation.measured)) {
    throw new MalformedResult('TRIAL_MEASUREMENT_INVALID', `trial ${String(trial)} reported measured=${String(observation.measured)}; a non-finite measurement is not a result`);
  }
  if (reportedInterval === null) {
    throw new NeedsInput('TRIAL_INTERVAL_MISSING', 'the engine does not invent an interval; a measured trial must report {lower, upper}');
  }
  if (!Number.isFinite(noiseBand) || noiseBand < 0) {
    throw new NeedsInput('NOISE_BAND_NOT_PREREGISTERED', 'the noise band must come from the preregistered stopping rule');
  }
  if (!isPlainObject(rule)) {
    throw new NeedsInput('DECISION_RULE_NOT_PREREGISTERED', 'the decision rule must come from the preregistration');
  }
  const decisionFromInterval = requireFn(deps, 'comparator', 'decisionFromInterval');
  const decision = decisionFromInterval({
    observed: observation.measured,
    lower: reportedInterval.lower,
    upper: reportedInterval.upper,
    noiseBand,
    rule,
  });
  if (!isPlainObject(decision) || typeof decision.decision !== 'string') {
    throw new MalformedResult('DECISION_SHAPE_INVALID', 'decisionFromInterval must return {decision, ...}');
  }
  return {
    ...base,
    status: requireMember(deps, 'constants', 'TRIAL_STATUSES', 'RESOLVED', 'a trial status'),
    outcome: requireMember(deps, 'constants', 'RESEARCH_OUTCOMES', decision.decision, 'a research outcome'),
    reason_codes: [],
    observed: observation.measured,
    decision: {
      decision: decision.decision,
      reason: typeof decision.reason === 'string' ? decision.reason : null,
      insideNoiseBand: decision.insideNoiseBand === true,
      intervalClearsNoise: decision.intervalClearsNoise === true,
      // The comparator's OWN correction block, kept so a record can be asked
      // why a measured trial came back UNRESOLVED. It matters here: with
      // alpha 0.05, confidence 0.95 and a declared family of three, the
      // published rule computes `never_rejects: true` — the rule can only ever
      // answer NULL or UNRESOLVED — and that is a fact about the published
      // constants, not about the effect. Dropping the block made a trial the
      // rule could never have resolved look identical to one the effect did not
      // clear.
      correction: isPlainObject(decision.correction) ? { ...decision.correction } : null,
    },
    infra: null,
    reconciliation: null,
  };
}

function unresolved(base, deps, reasonCode, detail) {
  return {
    ...base,
    status: requireMember(deps, 'constants', 'TRIAL_STATUSES', 'UNRESOLVED', 'a trial status'),
    outcome: requireMember(deps, 'constants', 'RESEARCH_OUTCOMES', 'UNRESOLVED', 'a research outcome'),
    reason_codes: [String(reasonCode)],
    infra: null,
    reconciliation: { reasonCode: String(reasonCode), detail: boundDetail(detail) },
  };
}

// --- the engine --------------------------------------------------------------

function plannedTrialsOf(prereg) {
  // The REQUIRED SHAPE of the preregistration names the list `trial_list`, and
  // every entry in it carries a `trial_id`. The runner used to read
  // `prereg.trials` and a singular `entry.seed`, neither of which exists in a
  // document that loads — so `runDeterministicRun` was unreachable for the same
  // reason the probes were (S2-008-SD-07). `trials` is still accepted so a
  // caller that passes the older shape gets a named refusal rather than a
  // silent empty plan.
  const list = Array.isArray(prereg?.trial_list) ? prereg.trial_list : (Array.isArray(prereg?.trials) ? prereg.trials : null);
  if (list === null || list.length === 0) {
    throw new NeedsInput('PREREGISTERED_TRIALS_MISSING', 'the preregistration must ENUMERATE its trials in `trial_list`; a dynamically grown trial list is how a stopping rule becomes a choice');
  }
  // The frozen seed SET, from the rule the preregistration published. The
  // public derivation of the other two rule kinds is the interface gap already
  // reported in preregistration.mjs (no frozen export names it), so a document
  // that does not state its set is refused here rather than re-derived twice.
  const frozen = Array.isArray(prereg?.seeds) ? prereg.seeds
    : (isPlainObject(prereg?.seed_rule) && Array.isArray(prereg.seed_rule.seeds) ? prereg.seed_rule.seeds : null);
  if (frozen === null || frozen.length === 0) {
    throw new NeedsInput('PREREGISTERED_SEED_SET_MISSING', 'the preregistration states no seed set; every trial runs the FROZEN set, never a selected one');
  }
  return list.map((entry, position) => {
    if (!isPlainObject(entry)) {
      throw new NeedsInput('PREREGISTERED_TRIAL_MALFORMED', `preregistered trial at position ${position} is not an object`);
    }
    const id = entry.trial ?? entry.trial_id ?? entry.id ?? null;
    if (id === undefined || id === null || String(id).length === 0) {
      throw new NeedsInput('PREREGISTERED_TRIAL_ID_MISSING', `preregistered trial at position ${position} has no id`);
    }
    return Object.freeze({
      index: Number.isInteger(entry.index) ? entry.index : position,
      trial: String(id),
      // The SET, not a member: `assertSeedSetFrozen` refuses a partial set, and
      // `scoreSeedDisclosure` counts distinct seeds, so a singular `seed` on
      // the record is what made a fully bound run score as unbound (SD-02).
      seeds: Object.freeze(Array.isArray(entry.seeds) ? [...entry.seeds] : [...frozen]),
    });
  });
}

function reservationOf(prereg) {
  const reservation = prereg?.budget_reservation;
  if (!isPlainObject(reservation)) {
    throw new NeedsInput('BUDGET_RESERVATION_MISSING', 'an opaque budget is refused (P4): the reservation must be preregistered, not discovered at run time');
  }
  for (const field of ['reservation_id', 'granted_units', 'expires_at']) {
    if (reservation[field] === undefined || reservation[field] === null) {
      throw new NeedsInput(`BUDGET_RESERVATION_FIELD_MISSING:${field}`, `budget_reservation.${field} is required`);
    }
  }
  if (!isPositiveInteger(reservation.granted_units)) {
    throw new NeedsInput('BUDGET_RESERVATION_UNITS_INVALID', `granted_units must be a positive integer, got ${String(reservation.granted_units)}`);
  }
  if (typeof reservation.expires_at !== 'string' || !ISO_RE.test(reservation.expires_at)) {
    throw new NeedsInput('BUDGET_RESERVATION_EXPIRY_INVALID', `expires_at must be an ISO-8601 instant, got ${String(reservation.expires_at)}`);
  }
  return reservation;
}

/**
 * The preregistered STOPPING rule, read through
 * `preregistration.mjs#stoppingRuleOf` (which re-validates it against the
 * enumerated trial ids). The stopping rule says when to stop; it does NOT carry
 * the noise band, so nothing here reads a band out of it. The version that did
 * (`rule.noise_band`) refused every preregistration the track actually ships,
 * because corpus/s2-008/preregistration.json publishes the band in
 * `noise_rule.band` and in `metric.noiseBand`.
 * @param {object} prereg The preregistration in force.
 * @param {object} deps The resolved dependency groups.
 * @returns {object} The stopping rule, unchanged.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'STOPPING_RULE_MALFORMED'.
 */
function stoppingRuleOf(prereg, deps) {
  const stoppingRuleOfFn = requireFn(deps, 'preregistration', 'stoppingRuleOf');
  const rule = stoppingRuleOfFn(prereg);
  if (!isPlainObject(rule)) {
    throw new MalformedResult('STOPPING_RULE_MALFORMED', 'stoppingRuleOf must return the preregistered stopping_rule object');
  }
  return rule;
}

/**
 * The PREREGISTERED noise band, and nothing else.
 *
 * Two preregistration members may publish it — `noise_rule.band` and
 * `metric.noiseBand` — and when both are present they must AGREE. A band that
 * appears twice with two values is not a lenient reading of one value: the
 * decision a trial receives depends on which one the engine happened to pick,
 * so a divergence is refused by name instead.
 *
 * The engine never derives, widens or defaults a band. `decisionFromInterval`
 * (comparator.mjs) is handed exactly this number.
 * @param {object} prereg The preregistration in force.
 * @returns {{band: number, source: string}} The frozen band and the member it
 *   was read from, so the record can say which part of the document fixed it.
 * @throws {import('../agentboard/errors.mjs').NeedsInput}
 *   'NOISE_BAND_NOT_PREREGISTERED' / 'PREREGISTERED_NOISE_BAND_INVALID'.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'PREREGISTERED_NOISE_BAND_DIVERGES'.
 */
function noiseBandOf(prereg) {
  const noiseRule = isPlainObject(prereg?.noise_rule) ? prereg.noise_rule : null;
  const fromRule = noiseRule === null ? undefined : (noiseRule.band ?? noiseRule.noise_band);
  const metric = isPlainObject(prereg?.metric) ? prereg.metric : null;
  const fromMetric = metric === null ? undefined : (metric.noiseBand ?? metric.noise_band);
  const candidates = [['noise_rule.band', fromRule], ['metric.noiseBand', fromMetric]].filter(([, value]) => value !== undefined && value !== null);
  if (candidates.length === 0) {
    throw new NeedsInput(
      'NOISE_BAND_NOT_PREREGISTERED',
      'the preregistration publishes no noise band (looked at noise_rule.band and metric.noiseBand); a band chosen at run time is not a noise band',
    );
  }
  for (const [name, value] of candidates) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      throw new NeedsInput('PREREGISTERED_NOISE_BAND_INVALID', `${name} must be a finite non-negative number, got ${String(value)}`);
    }
  }
  const distinct = new Set(candidates.map(([, value]) => value));
  if (distinct.size > 1) {
    throw new MalformedResult('PREREGISTERED_NOISE_BAND_DIVERGES', `the preregistration publishes two noise bands (${candidates.map(([name, value]) => `${name}=${value}`).join(', ')}); the engine picks neither`);
  }
  return { band: candidates[0][1], source: candidates.map(([name]) => name).join(' + ') };
}

/**
 * The PREREGISTERED decision rule, projected field by field for
 * `decisionFromInterval` (comparator.mjs), which needs `alpha`, `method`,
 * `confidence`, `direction` and an optional `null_value`.
 *
 * It is `preregistration.multiplicity_rule` and NOT the stopping rule: the
 * stopping rule says when to stop, the multiplicity rule says what counts as an
 * effect and how the family is corrected. Passing the stopping rule instead
 * made every measured trial die on `ALPHA_ABSENT_OR_INVALID` inside the
 * comparator, which is the right refusal for the wrong input.
 *
 * Three members are read under the preregistration's own spellings, because
 * `decisionFromInterval` reads different names and the preregistration's names
 * are the frozen ones:
 *   * the DECLARED FAMILY is `declared_comparisons` (a list of trial ids) and
 *     is handed over as `comparisons`. Dropping it made every measured trial
 *     die on MULTIPLICITY_FAMILY_ABSENT, because a decision corrected over a
 *     family of one is not corrected at all.
 *   * the NULL VALUE is `null_value` when the rule publishes one, and
 *     otherwise the FROZEN BASELINE — but only when the preregistered noise
 *     rule's own text names the baseline (`UPPER_MINUS_BASELINE_LT_NEG_BAND`),
 *     which is the document saying what its reference point is. The source is
 *     reported in `null_value_source`, because a decision rule whose reference
 *     point the engine inferred is a fact the evidence has to carry, not a
 *     detail. When neither is published the member stays null and the
 *     comparator applies its own documented default of 0.
 *
 * The projection copies the named members and nothing else, so a stray member
 * of the preregistration can never reach the comparator's arithmetic.
 * @param {object} prereg The preregistration in force.
 * @returns {object} `{alpha, method, confidence, direction, null_value,
 *   null_value_source, comparisons}`.
 * @throws {import('../agentboard/errors.mjs').NeedsInput}
 *   'DECISION_RULE_NOT_PREREGISTERED' / 'DECISION_RULE_FIELD_ABSENT'.
 */
function decisionRuleOf(prereg) {
  const rule = isPlainObject(prereg?.multiplicity_rule) ? prereg.multiplicity_rule : null;
  if (rule === null) {
    throw new NeedsInput('DECISION_RULE_NOT_PREREGISTERED', 'the preregistration publishes no multiplicity_rule; an uncorrected decision is not a decision');
  }
  const alpha = typeof rule.alpha === 'number' && Number.isFinite(rule.alpha) ? rule.alpha : null;
  if (alpha === null) {
    throw new NeedsInput('DECISION_RULE_FIELD_ABSENT', 'multiplicity_rule.alpha is required; decisionFromInterval refuses a decision with no family-wise alpha');
  }
  if (typeof rule.method !== 'string' || rule.method.length === 0) {
    throw new NeedsInput('DECISION_RULE_FIELD_ABSENT', 'multiplicity_rule.method is required; an unnamed correction method is not a correction');
  }
  const comparisons = Array.isArray(rule.declared_comparisons)
    ? rule.declared_comparisons
    : (Array.isArray(rule.comparisons) ? rule.comparisons : null);
  if (comparisons === null || comparisons.length === 0) {
    throw new NeedsInput('DECISION_RULE_FIELD_ABSENT', 'multiplicity_rule.declared_comparisons is required; a decision corrected over a family of one is not multiplicity-corrected');
  }
  const noiseRule = isPlainObject(prereg.noise_rule) ? prereg.noise_rule : null;
  const noiseText = noiseRule === null
    ? ''
    : [noiseRule.positive_rule, noiseRule.negative_rule, noiseRule.null_rule].filter((value) => typeof value === 'string').join(' ');
  const baseline = isPlainObject(prereg.frozen_baseline) ? prereg.frozen_baseline.value : undefined;
  const declaredNull = typeof rule.null_value === 'number' && Number.isFinite(rule.null_value) ? rule.null_value : null;
  const baselineNull = typeof baseline === 'number' && Number.isFinite(baseline) && noiseText.includes('BASELINE') ? baseline : null;
  return {
    alpha,
    method: rule.method,
    confidence: typeof rule.confidence === 'number' && Number.isFinite(rule.confidence) ? rule.confidence : null,
    direction: typeof rule.direction === 'string' ? rule.direction : null,
    null_value: declaredNull ?? baselineNull,
    null_value_source: declaredNull !== null
      ? 'multiplicity_rule.null_value'
      : (baselineNull !== null ? 'frozen_baseline.value (the preregistered noise rule names the baseline as its reference point)' : 'comparator default 0 (the preregistration published none)'),
    comparisons: comparisons.slice(),
  };
}

/**
 * The per-trial timeout, read from the preregistration and reported with the
 * member it came from. There is NO default and no fallback: a timeout supplied
 * by the caller would be a run-time choice, and the ticket's budget rule is
 * that the budget is reserved BEFORE the first trial, not negotiated during it.
 *
 * REPORTED GAP: `corpus/s2-008/preregistration.json` publishes no per-trial
 * timeout in any of `TRIAL_TIMEOUT_PATHS`, so the default path refuses with
 * `TRIAL_TIMEOUT_NOT_PREREGISTERED` until W2 publishes one. That refusal is the
 * correct behaviour and it is also a hole in the track: it is in the BLOCKED
 * list of this file's owner, not silently papered over.
 * @param {object} prereg The preregistration in force.
 * @returns {{timeoutMs: number, source: string}} The timeout and its source.
 * @throws {import('../agentboard/errors.mjs').NeedsInput}
 *   'TRIAL_TIMEOUT_NOT_PREREGISTERED'.
 */
function trialTimeoutOf(prereg) {
  for (const path of TRIAL_TIMEOUT_PATHS) {
    let value = prereg;
    let present = true;
    for (const key of path) {
      if (!isPlainObject(value) || value[key] === undefined) {
        present = false;
        break;
      }
      value = value[key];
    }
    if (present && isPositiveInteger(value)) {
      return { timeoutMs: value, source: path.join('.') };
    }
  }
  throw new NeedsInput(
    'TRIAL_TIMEOUT_NOT_PREREGISTERED',
    `the preregistration publishes no per-trial timeout (looked at ${TRIAL_TIMEOUT_PATHS.map((path) => path.join('.')).join(', ')}); a timeout chosen at run time is not a timeout`,
  );
}

/**
 * Project the registry's journal ENVELOPES into the row shape
 * `assertPreregisteredBeforeRun` reads.
 *
 * `registry.mjs#readJournal` returns envelopes — `{index, record_id, kind,
 * campaign_id, at, payload, prev_digest, ...}` — while the ordering proof reads
 * `preregistration_digest` and `run_id` at the row's TOP level. The projection
 * lifts those two members out of the payload and adds nothing else: every value
 * in a projected row is either the envelope's own field or a member of its
 * payload, so a row can never claim a digest the ledger does not hold. A payload
 * that carries no digest projects to `null`, and the proof then refuses with
 * PREREGISTRATION_NOT_IN_JOURNAL — the failure mode is a refusal, never a
 * pass.
 * @param {ReadonlyArray<object>} rows `readJournal`'s committed records.
 * @returns {ReadonlyArray<object>} The projected rows, in journal order.
 * @throws {import('../agentboard/errors.mjs').MalformedResult}
 *   'JOURNAL_RECORD_UNNAMED' when a committed row carries no kind at all.
 */
function journalRowsOf(rows) {
  return rows.map((row, position) => {
    if (!isPlainObject(row) || typeof row.kind !== 'string' || row.kind.length === 0) {
      throw new MalformedResult('JOURNAL_RECORD_UNNAMED', `journal row ${position} carries no record kind; a fact nobody can name cannot be ordered`);
    }
    const payload = isPlainObject(row.payload) ? row.payload : {};
    return {
      index: Number.isInteger(row.index) ? row.index : position,
      kind: row.kind,
      record_kind: typeof payload.record_kind === 'string' ? payload.record_kind : row.kind,
      preregistration_digest: payload.preregistration_digest ?? payload.prereg_digest ?? null,
      run_id: payload.run_id ?? payload.raw_run_id ?? null,
    };
  });
}

function refused(code, message, trialIndex = null) {
  return { code: String(code), message: boundDetail(message), trial_index: trialIndex };
}

/**
 * THE PURGE, OR A PROOF THAT THE CALLER PERFORMED IT.
 *
 * Two ways this engine can start on a clean ledger, and only two:
 *   * it purges the ledger itself (the default), or
 *   * the caller purged it FIRST — because the caller has to open the one-shot
 *     holdout before the engine exists — and the ledger is PROVEN empty here.
 *
 * The proof is the point. `scripts/s2-008-run.mjs` used to open the holdout and
 * then let the engine purge, and the engine's purge ERASED the ACCESS row: the
 * run record named an `access_record_id` that its own journal did not contain,
 * `EXPECTED_LEDGER_SHAPE` (one ACCESS row) could never hold, and a refusal here
 * is what makes the second ordering impossible to reintroduce silently. The
 * proof is not "the journal is empty" — the holdout ACCESS row is legitimately
 * there — but "no row THIS ENGINE writes survived a previous run", which is the
 * property the purge exists for.
 *
 * @returns {{purged: true, removedFiles: number, snapshotDigest: string,
 *   performed_by: string, pre_existing_rows: ReadonlyArray<string>,
 *   engine_rows_inherited: number}}
 * @throws {import('../agentboard/errors.mjs').MalformedResult} 'PURGE_NOT_PERFORMED'
 *   when the caller claims a purge and a row this engine writes is still present.
 */
function purgeForThisRun(registry, { readJournal, snapshotDigest, purgeRegistry, alreadyPurged, purgeRemovedFiles, label }) {
  if (alreadyPurged !== true) {
    const purge = purgeRegistry(registry);
    return isPlainObject(purge) ? purge : { purged: true, removedFiles: 0, snapshotDigest: snapshotDigest(registry) };
  }
  const rows = readJournal(registry);
  const inherited = (Array.isArray(rows) ? rows : []).filter((row) => {
    const kind = typeof row?.kind === 'string' ? row.kind : (typeof row?.payload?.kind === 'string' ? row.payload.kind : null);
    return kind !== null && ENGINE_OWNED_RECORD_KINDS.includes(kind);
  });
  if (inherited.length > 0) {
    throw new MalformedResult(
      'PURGE_NOT_PERFORMED',
      `the caller claims it purged run ${String(label)}'s ledger before starting, but the journal still holds ${inherited.length} row(s) this engine writes (${inherited.map((row) => String(row.kind)).join(', ')}); a run that inherited another run's rows would be scored against rows it did not write`,
    );
  }
  return {
    purged: true,
    removedFiles: Number.isInteger(purgeRemovedFiles) ? purgeRemovedFiles : 0,
    snapshotDigest: snapshotDigest(registry),
    performed_by: 'CALLER_BEFORE_FIRST_WRITE',
    // The rows that legitimately predate the engine: the one-shot holdout open,
    // which the caller performs BEFORE the engine exists (the executor is
    // injected, so it has to be built from the open). They are named, and the
    // proof is that nothing THIS ENGINE writes survived a previous run.
    pre_existing_rows: (Array.isArray(rows) ? rows : []).map((row) => String(row?.kind ?? 'UNNAMED')),
    engine_rows_inherited: inherited.length,
  };
}

/**
 * OPEN the preregistered budget reservation, before the first trial.
 *
 * It goes through `registry.mjs#putExperiment` — the revision-CAS,
 * idempotency-keyed write path — with the preregistration's own reservation as
 * the payload, because `recordSpend` looks the reservation up by
 * `record.kind === 'BUDGET_RESERVATION'` and refuses a spend it cannot find.
 * Taking the reservation at the point of the spend would be exactly the
 * run-time budget the ticket rules out.
 *
 * The idempotency key and `args` deliberately EXCLUDE the clock instant: a
 * replay of this write after a crash must be a replay, not a conflict, and the
 * instant lives in the record payload where it is evidence rather than an
 * argument. `expectedRevision` is the handle's live revision, so a second
 * writer that moved the ledger between the read and the write loses the CAS
 * instead of overwriting it.
 * @param {{registry: object, reservation: object, preregDigest: string,
 *   runId: string, nonce: string, clockIso: string, putExperiment: Function}} args
 * @returns {{result: object, revision: number, replayed: boolean}} What the
 *   ledger committed.
 * @throws {import('../agentboard/errors.mjs').NeedsInput}
 *   'REGISTRY_REVISION_UNAVAILABLE' when the handle is not an open registry.
 */
function openBudgetReservation({ registry, reservation, preregDigest, runId, nonce, clockIso, putExperiment } = {}) {
  if (!isPlainObject(registry) || typeof registry.revision !== 'function') {
    throw new NeedsInput('REGISTRY_REVISION_UNAVAILABLE', 'the reservation is taken through the handle openRegistry returned; a path or a plain object cannot be written through');
  }
  const payload = {
    kind: BUDGET_RESERVATION_KIND,
    reservation_id: reservation.reservation_id,
    granted_units: reservation.granted_units,
    spent_units: 0,
    currency: reservation.currency ?? null,
    expires_at: reservation.expires_at,
    preregistration_digest: preregDigest,
    run_id: runId,
    nonce,
  };
  return putExperiment(registry, {
    key: canonicalDigest({ operation: 'OPEN_RESERVATION', ...payload }),
    args: { ...payload },
    expectedRevision: registry.revision(),
    // `taken_at` is in the record and not in the arguments, so the same
    // reservation written twice at two different injected instants is the same
    // write replayed rather than the same key with different arguments.
    mutate: () => ({ ...payload, taken_at: clockIso }),
  });
}

// A typed refusal of a budget edge is recognised by its CLOSED code AND its
// CLOSED class, in that order. A BoardError whose code says RECONCILIATION_REQUIRED
// but which is not that class would mean the taxonomy of
// src/lib/agentboard/errors.mjs had forked; that is a defect to be named, not a
// branch to guess on.
const RECONCILIATION_REFUSAL = Object.freeze({ code: 'RECONCILIATION_REQUIRED', ErrorClass: ReconciliationRequired });
const BUDGET_REFUSAL = Object.freeze({ code: 'BUDGET_EXCEEDED', ErrorClass: BudgetExceeded });

function isTypedRefusal(error, expectation) {
  if (error.code !== expectation.code) return false;
  if (!(error instanceof expectation.ErrorClass)) {
    throw new MalformedResult('ERROR_TAXONOMY_MISMATCH', `code ${expectation.code} is not carried by ${expectation.ErrorClass.name}`);
  }
  return true;
}

/**
 * A preregistered trial that was NOT executed, recorded as SKIPPED with the
 * code that refused it.
 *
 * It carries the SAME members an executed trial carries — `metric`, `seeds`,
 * `numerator`, `denominator` — because the aggregate runs over every trial in
 * the record: `metricsSummary` throws `METRIC_NAME_ABSENT` on a trial that
 * names no metric, so a skipped trial without one made a refused run
 * unaggregatable AFTER its ledger had already been written. A refused run must
 * still be readable, and "not measured" is a count of its own, never a zero in
 * a denominator.
 * @param {{index: number, trial: string, seeds: ReadonlyArray<number|string>}} planned
 *   The preregistered trial that was not executed.
 * @param {string} code The refusal code that stopped it.
 * @param {string} message A bounded, secret-free detail.
 * @param {object} deps The resolved dependency groups (closed vocabulary).
 * @param {string} metric The preregistered metric name.
 * @returns {object} The trial record, SKIPPED, with the comparator's verdict.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} on a status or
 *   outcome outside the closed vocabulary, and on a verdict this engine
 *   refuses to record.
 */
function skippedTrial(planned, code, message, deps, metric) {
  const trial = {
    index: planned.index,
    trial: planned.trial,
    seeds: planned.seeds,
    metric,
    numerator: null,
    denominator: null,
    status: requireMember(deps, 'constants', 'TRIAL_STATUSES', 'SKIPPED', 'a trial status'),
    outcome: requireMember(deps, 'constants', 'RESEARCH_OUTCOMES', 'UNRESOLVED', 'a research outcome'),
    reason_codes: [String(code)],
    observed: null,
    interval: null,
    noise_band: null,
    decision: null,
    bindings: { seed: { seeds: planned.seeds, source: 'PREREGISTERED' }, holdout: null, budget: null, evaluator: null },
    seedBinding: { seeds: planned.seeds, source: 'PREREGISTERED' },
    holdoutBinding: null,
    budgetBinding: null,
    evaluatorBinding: null,
    budget: null,
    elapsed_ms: null,
    latency_ms: null,
    latency_source: 'not_executed',
    infra: null,
    reconciliation_id: null,
    detail: boundDetail(message),
  };
  // A skipped trial is SCORED, not left blank. `verdict: null` on a trial that
  // never ran reads as "nothing to decide" to any consumer that checks for a
  // string, and a record whose unrun trials are silent is a record that can be
  // passed by the trials that did not happen. `resolveTrialVerdict` is the one
  // place a trial verdict is named, and it names VIOLATION here — the engine
  // then refuses the record if the comparator ever said otherwise.
  const resolveTrialVerdict = requireFn(deps, 'comparator', 'resolveTrialVerdict');
  const verdict = resolveTrialVerdict(trial);
  if (!isPlainObject(verdict) || typeof verdict.verdict !== 'string') {
    throw new MalformedResult('TRIAL_VERDICT_SHAPE_INVALID', 'resolveTrialVerdict must return {verdict, ...} for a skipped trial as well');
  }
  if (verdict.verdict !== 'VIOLATION') {
    throw new MalformedResult('SKIPPED_TRIAL_ALLOWED', `a skipped trial was scored ${verdict.verdict}; only a RESOLVED trial with four satisfied bindings may be ALLOW`);
  }
  trial.verdict = verdict.verdict;
  trial.verdict_reasons = Array.isArray(verdict.reasons) ? [...verdict.reasons] : [];
  return trial;
}

/**
 * Execute ONE deterministic research run: read the preregistration, freeze the
 * table, open the budget, run every preregistered seed, classify every outcome,
 * record wall-clock latency, and bind the result to a provenance block and a
 * decision digest.
 *
 * The engine returns a BOUND run record. A refused or degraded run returns a
 * record too, with its unexecuted trials recorded as SKIPPED and the code that
 * refused them — a refusal that produced no artefact would be
 * indistinguishable from a run that never happened, and "I could not produce a
 * result" has to be evidence. The engine throws only when it cannot produce an
 * honest record at all: a malformed context, a missing executor, a missing
 * dependency, a non-canonical artefact, a tamper.
 *
 * The budget is decided in two halves, and the split is deliberate. The
 * engine computes the ARITHMETIC itself — `spent + units > granted` is its own
 * check, before any delegation — and delegates LIVENESS and EXPIRY to
 * `assertBudgetReservation` (preregistration.mjs) against the INJECTED clock.
 * The local half can only remove permission, never grant any, which is the rule
 * src/lib/agentboard/policy.mjs states for its own local checks; and it exists
 * because the reservation is a preregistered document whose `spent_units` does
 * not advance by itself, so delegating the arithmetic to a stale object would
 * let the whole reservation be spent once and look unspent forever after.
 *
 * There is no retry path anywhere in this function, by construction: the trial
 * loop is a single `for` over the preregistered list, and a settlement key seen
 * twice inside one run is a refusal. That is the runner's mirror of the board's
 * "an unknown external side effect is never a retry" rule.
 *
 * @param {object} ctx
 * @param {object} ctx.prereg The preregistration in force.
 * @param {object} ctx.registry An open registry handle (registry.mjs).
 * @param {(trial: object, ctx: object) => (object|Promise<object>)} ctx.executeTrial
 *   The injected executor. REQUIRED, with no default.
 * @param {object} ctx.provenance A block from `freezeProvenance`.
 * @param {object|string} [ctx.clock] An injected fixed clock, or an ISO instant
 *   to wrap with `fixedClock`.
 * @param {string} [ctx.label='a'] The run label, part of the nonce and the run id.
 * @param {string} [ctx.outputRoot] The run's own output root, recorded when
 *   given: `compareParallelTrack` reads it as one of the five fields two
 *   process-separated runs must never share.
 * @param {string} [ctx.deciderKind='human_owner'] The decider kind recorded on
 *   every reconciliation row this run opens.
 * @param {number} [ctx.unitsPerTrial=1] Budget units charged per trial.
 * @param {boolean} [ctx.alreadyPurged=false] The caller purged this ledger
 *   before the engine started (scripts/s2-008-run.mjs does, because it opens the
 *   one-shot holdout before the engine runs). The engine then PROVES the journal
 *   is empty instead of purging again, and refuses when it is not.
 * @param {number} [ctx.purgeRemovedFiles=0] What the caller's purge removed, so
 *   the record's own `purge` block still reports it.
 * @param {string} [ctx.reconciliationPrefix] An explicit id prefix, when
 *   W1's `RESEARCH_ID_PREFIXES` key names differ from this file's lookup.
 * @param {object} [ctx.deps] Dependency override (test doubles only).
 * @returns {Promise<object>} The bound run record. Its `run.status` is
 *   COMPLETED, REFUSED or RECONCILIATION_REQUIRED; the verdict of every trial
 *   is the comparator's, and the campaign verdict is not decided here.
 */
export async function runDeterministicRun(ctx = {}) {
  const {
    prereg,
    registry,
    executeTrial,
    provenance,
    clock: injectedClock,
    label = 'a',
    outputRoot = null,
    deciderKind = 'human_owner',
    unitsPerTrial = 1,
    reconciliationPrefix: explicitPrefix,
    deps: injectedDeps,
    // The caller already purged THIS ledger before it opened the holdout, and
    // the engine must not purge again afterwards: the second purge is what used
    // to erase the ACCESS row the one-shot holdout open had committed, so the
    // run record named an `access_record_id` its own journal did not contain and
    // the frozen ledger shape could never hold. The claim is PROVED, not
    // believed — `purgeForThisRun` refuses to start unless the journal really is
    // empty — and it is a refusal rather than a silent second purge, so a caller
    // that lies about it cannot quietly drop the holdout access row.
    alreadyPurged = false,
    purgeRemovedFiles = 0,
  } = ctx;
  const deps = resolveDeps(injectedDeps);
  if (typeof executeTrial !== 'function') {
    throw new NeedsInput('TRIAL_EXECUTOR_REQUIRED', 'executeTrial is injected and has no default: an engine that could produce a result by itself could certify its own result');
  }
  if (!isPlainObject(prereg)) {
    throw new NeedsInput('PREREGISTRATION_MISSING', 'the engine reads a preregistration; it never invents one');
  }
  if (!isPositiveInteger(unitsPerTrial)) {
    throw new NeedsInput('BUDGET_UNITS_PER_TRIAL_INVALID', `unitsPerTrial must be a positive integer, got ${String(unitsPerTrial)}`);
  }
  assertReconciliationDeciderKind(deciderKind, { resolution: 'EFFECT_UNDETERMINED' });
  const clock = typeof injectedClock === 'string' ? fixedClock(injectedClock) : injectedClock;
  if (!isPlainObject(clock) || typeof clock.now !== 'function' || typeof clock.nowIso !== 'function') {
    throw new NeedsInput('CLOCK_REQUIRED', 'an injected fixed clock (fixedClock from src/lib/agentboard/policy.mjs) is required; the process clock is never sampled');
  }
  const bound = assertProvenance(provenance);
  const startedAt = isoOf(clock);

  // --- before trial one: the preregistration, the table, the purge ---------
  const assertPreregistration = requireFn(deps, 'preregistration', 'assertPreregistration');
  const preregistrationDigest = requireFn(deps, 'preregistration', 'preregistrationDigest');
  const assertPreregisteredBeforeRun = requireFn(deps, 'preregistration', 'assertPreregisteredBeforeRun');
  const assertSeedSetFrozen = requireFn(deps, 'preregistration', 'assertSeedSetFrozen');
  const assertTableFrozen = requireFn(deps, 'expected', 'assertTableFrozen');
  const purgeRegistry = requireFn(deps, 'registry', 'purgeRegistry');
  const appendRecord = requireFn(deps, 'registry', 'appendRecord');
  const recordSpend = requireFn(deps, 'registry', 'recordSpend');
  const readJournal = requireFn(deps, 'registry', 'readJournal');
  const snapshotDigest = requireFn(deps, 'registry', 'snapshotDigest');
  const assertBudgetReservation = requireFn(deps, 'preregistration', 'assertBudgetReservation');
  const resolveTrialVerdict = requireFn(deps, 'comparator', 'resolveTrialVerdict');
  const metricsSummary = requireFn(deps, 'comparator', 'metricsSummary');
  const latencyRecorded = requireFn(deps, 'comparator', 'latencyRecorded');
  const putExperiment = requireFn(deps, 'registry', 'putExperiment');

  assertPreregistration(prereg);
  const preregDigest = preregistrationDigest(prereg);
  if (typeof preregDigest !== 'string' || preregDigest.length === 0) {
    throw new MalformedResult('PREREGISTRATION_DIGEST_INVALID', 'preregistrationDigest must return a non-empty digest string');
  }
  // The table is frozen BEFORE trial one and read, never written. A run that
  // could edit the expectation after the fact would make A3 unfalsifiable.
  const tableDigest = assertTableFrozen(prereg);
  const planned = plannedTrialsOf(prereg);
  const seeds = [...planned[0].seeds];
  const metricName = isPlainObject(prereg.metric)
    ? (prereg.metric.name ?? prereg.metric.metric_id ?? null)
    : null;
  if (metricName === null) {
    throw new NeedsInput('PREREGISTERED_METRIC_NAME_MISSING', 'the preregistration names no metric; a trial that does not say what it measured cannot be aggregated');
  }
  const rule = stoppingRuleOf(prereg, deps);
  if (rule.max_trials !== undefined && rule.max_trials !== planned.length) {
    throw new NeedsInput('STOPPING_RULE_TRIAL_COUNT_MISMATCH', `the stopping rule caps at ${rule.max_trials} trials but ${planned.length} are enumerated; truncation is not a stopping rule`);
  }
  const { timeoutMs, source: timeoutSource } = trialTimeoutOf(prereg);
  // The two decision inputs, both read from the document and nowhere else.
  const { band: noiseBand, source: noiseBandSource } = noiseBandOf(prereg);
  const decisionRule = decisionRuleOf(prereg);
  const reservation = reservationOf(prereg);
  assertSeedSetFrozen(seeds, prereg);

  // The purge comes FIRST, before anything this run writes. A run that
  // inherited a previous run's journal would be scored against rows it did not
  // write, and a repeat run on the same base has to fail on the property, not
  // on its own leftovers.
  const purge = purgeForThisRun(registry, { readJournal, snapshotDigest, purgeRegistry, alreadyPurged, purgeRemovedFiles, label });
  // S3: the hypothesis card is VALIDATED AGAINST THE FROZEN SCHEMA before it is
  // copied into every trial. `card: isPlainObject(prereg.card) ? prereg.card : null`
  // copied whatever the preregistration carried, so a document the frozen
  // `contracts/hypothesis-card.schema.json` would have rejected reached the
  // comparator unvalidated — and the comparator is where a causal claim is
  // read, so the one component that must not classify an arbitrary object was
  // handed one. `assertResearchContract` is the SAME path
  // `scripts/s2-008-build-corpus.mjs` uses, and it is fail-closed.
  const assertResearchContract = requireFn(deps, 'contracts', 'assertResearchContract');
  const cardUnderTest = isPlainObject(prereg.card) ? prereg.card : null;
  if (cardUnderTest !== null) {
    assertResearchContract('hypothesis-card', cardUnderTest);
  }
  const run = {
    version: RUNNER_VERSION,
    ticket: 'S2-008',
    label: String(label),
    status: RUN_COMPLETED,
    started_at: startedAt,
    finished_at: startedAt,
    engine: {
      units_per_trial: unitsPerTrial,
      trial_timeout_ms: timeoutMs,
      trial_timeout_source: timeoutSource,
      trial_count: planned.length,
      sequential: true,
      retriable: false,
    },
  };
  const record = {
    version: RUNNER_VERSION,
    ticket: 'S2-008',
    // The five bindings A5 requires are at the TOP level, in the spellings the
    // track's own readers use: `expectedValueIssues` compares a trial's
    // provenance against `run.raw_run_id` / `run.commit_sha` / `run.tree_sha`,
    // and `compareParallelTrack` refuses an unbound run before it compares
    // anything. They were nested under `provenance` only, which made every run
    // this engine produced read as UNBOUND to the scorer.
    commit_sha: bound.commit,
    tree_sha: bound.tree,
    raw_run_id: bound.run_id,
    nonce: bound.nonce,
    executor_id: bound.executor_id,
    pid: bound.pid,
    ...(typeof outputRoot === 'string' && outputRoot.length > 0 ? { output_root: outputRoot } : {}),
    preregistration_digest: preregDigest,
    expected_table_digest: typeof tableDigest === 'string' ? tableDigest : null,
    run,
    preregistration: {
      digest: preregDigest,
      expected_table_digest: typeof tableDigest === 'string' ? tableDigest : null,
      seed_count: seeds.length,
      trial_count: planned.length,
      stopping_rule: rule,
      noise_rule: { source: noiseBandSource, band: noiseBand },
      decision_rule: decisionRule,
      inference_mode: typeof prereg.inference_mode === 'string' ? prereg.inference_mode : null,
      budget: {
        reservation_id: reservation.reservation_id,
        granted_units: reservation.granted_units,
        spent_units: 0,
        currency: typeof reservation.currency === 'string' ? reservation.currency : null,
        expires_at: reservation.expires_at,
      },
    },
    purge: isPlainObject(purge) ? { purged: purge.purged === true, removedFiles: purge.removedFiles ?? null, snapshotDigest: purge.snapshotDigest ?? null, performed_by: purge.performed_by ?? 'ENGINE', empty_when_claimed: purge.empty_when_claimed ?? null } : null,
    trials: [],
    metrics: null,
    latency: null,
    // `codes` is every refusal code the run actually emitted, in first-seen
    // order. It is the record the frozen table reads for the codes a run may
    // NEVER emit (`BLIND_RETRY_AFTER_INFRA`, `IMPLICIT_ZERO`, `SKIP_AS_PASS`,
    // `CAUSAL_FROM_SIMULATION`): an engine that never wrote one had nothing to
    // declare, and an engine that writes one is caught by name.
    codes: [],
    // The hard-gate counters, filled from this run's own observations at the
    // end. They are never initialised to zero here: an unobserved counter is
    // not a passing counter.
    counters: null,
    counter_sources: null,
    run_counters: { executed: 0, resolved: 0, infra: 0, unresolved: 0, skipped: 0, reconciliations: 0, budget_exceeded: 0 },
    refusals: [],
    reconciliations: [],
  };
  // The counter object is the record's own; the engine mutates no other state.
  const runCounters = record.run_counters;
  // Two readings of the SAME injected clock, in the two units the two
  // boundaries speak. `assertBudgetReservation` reads NANOSECONDS
  // (`clockToNs` in preregistration.mjs rejects anything else), and a Date's
  // `getTime()` is MILLISECONDS: passing the millisecond reading under the name
  // `nowNs` put every instant in 1970, so an EXPIRED reservation still granted
  // its budget and a run that must reconcile completed instead. The elapsed
  // fallback below is the other way round — a millisecond delta reported as
  // `elapsed_ms` — so the two readings are named for what they are and neither
  // is passed to the other. Neither reads a wall clock.
  const nowNs = () => clock.now().getTime() * 1e6;
  const nowMs = () => clock.now().getTime();
  const openReconciliation = (plannedEntry, reasonCode, detail) => {
    const row = reconciliationRow({
      run: { provenance: bound, preregistration: record.preregistration },
      index: plannedEntry?.index ?? null,
      trial: plannedEntry?.trial ?? null,
      reasonCode,
      detail,
      deciderKind,
      deps,
      prefix: explicitPrefix,
      clockIso: isoOf(clock),
      reservationId: reservation.reservation_id,
    });
    record.reconciliations.push(row);
    run.status = RUN_RECONCILIATION;
    runCounters.reconciliations += 1;
    return row;
  };

  appendRecord(registry, {
    // The ENVELOPE kind is what the ordering proof reads; the payload's
    // `record_kind` is what the track's frozen ledger table reads. Both are the
    // same fact, and the disagreement between the two frozen spellings is
    // reported in this file's header rather than resolved by dropping one.
    kind: PREREGISTRATION_ROW_KIND,
    record_kind: PREREGISTRATION_RECORD_KIND,
    run_id: bound.run_id,
    nonce: bound.nonce,
    preregistration_digest: preregDigest,
    expected_table_digest: typeof tableDigest === 'string' ? tableDigest : null,
    trial_count: planned.length,
    seed_count: seeds.length,
    inference_mode: record.preregistration.inference_mode,
    recorded_at: isoOf(clock),
  });

  // P1, EXECUTED rather than asserted: the preregistration row is now committed
  // and the ordering proof runs against the REAL journal. The call used to
  // pass no journal at all, which reduced "preregistration before the first
  // run" to "this document parses" — the check that a result recorded first
  // must be refused was never run, so the property was vacuous.
  assertPreregisteredBeforeRun({
    prereg,
    runId: bound.run_id,
    journal: journalRowsOf(readJournal(registry)),
  });

  // The budget is TAKEN here, before the first trial, and never negotiated at
  // the spend: `recordSpend` refuses a reservation it cannot find, and a
  // spend against a reservation this run did not take is a spend nobody
  // authorised. The idempotency key and the args are clock-free on purpose, so
  // a replayed reservation write is a replay and not a second charge.
  const reservationWrite = openBudgetReservation({
    registry,
    reservation,
    preregDigest,
    runId: bound.run_id,
    nonce: bound.nonce,
    clockIso: isoOf(clock),
    putExperiment,
  });
  record.budget_reservation_row = {
    reservation_id: reservation.reservation_id,
    record_id: reservationWrite?.result?.reservation_id ?? null,
    revision: Number.isInteger(reservationWrite?.revision) ? reservationWrite.revision : null,
    replayed: reservationWrite?.replayed === true,
  };

  // --- open the budget ------------------------------------------------------
  let budgetLive = true;
  let spentUnits = 0;
  try {
    assertBudgetReservation(reservation, { nowNs: nowNs() });
  } catch (error) {
    const typed = isBoardError(error) ? error : toBoardError(error, 'PROVIDER_FAILURE');
    if (isTypedRefusal(typed, RECONCILIATION_REFUSAL)) {
      record.refusals.push(refused('RECONCILIATION_REQUIRED', typed.message));
      openReconciliation(null, REASON_RESERVATION_EXPIRED, `the preregistered reservation expired before trial one: ${typed.message}`);
      budgetLive = false;
    } else {
      record.refusals.push(refused(typed.code, typed.message));
      run.status = RUN_REFUSED;
      budgetLive = false;
    }
  }

  // --- every preregistered trial, in the preregistered order ---------------
  const settleKeys = new Set();
  for (let position = 0; position < planned.length; position += 1) {
    const entry = planned[position];
    if (!budgetLive) {
      const code = record.reconciliations.length > 0 ? RECONCILIATION_REFUSAL.code : (record.refusals[0]?.code ?? BUDGET_REFUSAL.code);
      record.trials.push(skippedTrial(entry, code, `not executed: the reservation is not live (${code})`, deps, metricName));
      runCounters.skipped += 1;
      continue;
    }
    // P2 on EVERY trial, not only before the first one.
    assertSeedSetFrozen(seeds, prereg);
    // The engine's OWN budget arithmetic, checked before the delegation below.
    // It can only ever REMOVE permission, never grant any — the same rule
    // src/lib/agentboard/policy.mjs states for its local checks — and it exists
    // because the reservation handed to `assertBudgetReservation` is the
    // preregistered document, whose `spent_units` does not advance on its own.
    // Delegating the liveness and the expiry, and deciding the arithmetic here,
    // keeps one number (the ledger's) authoritative and stops a stale
    // reservation from reading as an unspent one.
    if (spentUnits + unitsPerTrial > reservation.granted_units) {
      const message = `settling ${unitsPerTrial} unit(s) with ${spentUnits} of ${reservation.granted_units} spent exceeds the preregistered reservation ${reservation.reservation_id}`;
      record.refusals.push(refused(BUDGET_REFUSAL.code, message, entry.index));
      runCounters.budget_exceeded += 1;
      run.status = RUN_REFUSED;
      budgetLive = false;
      record.trials.push(skippedTrial(entry, BUDGET_REFUSAL.code, message, deps, metricName));
      runCounters.skipped += 1;
      continue;
    }
    // The budget, re-checked per trial against the INJECTED clock.
    try {
      assertBudgetReservation(reservation, { nowNs: nowNs() });
    } catch (error) {
      const typed = isBoardError(error) ? error : toBoardError(error, 'PROVIDER_FAILURE');
      if (typed.code === 'RECONCILIATION_REQUIRED') {
        record.refusals.push(refused('RECONCILIATION_REQUIRED', typed.message, entry.index));
        openReconciliation(entry, REASON_RESERVATION_EXPIRED, typed.message);
      } else {
        record.refusals.push(refused(typed.code, typed.message, entry.index));
        runCounters.budget_exceeded += 1;
        run.status = RUN_REFUSED;
      }
      budgetLive = false;
      // The `deps` argument was missing on this path, so a refusal that
      // arrived here died inside the closed-vocabulary check with a
      // dependency error instead of being recorded — the one branch where
      // "I could not run it" produced no evidence at all.
      record.trials.push(skippedTrial(entry, typed.code, typed.message, deps, metricName));
      runCounters.skipped += 1;
      continue;
    }
    const settleKey = canonicalDigest({ run_id: bound.run_id, index: entry.index, trial: entry.trial, units: unitsPerTrial, reservation_id: reservation.reservation_id });
    if (settleKeys.has(settleKey)) {
      // Structural proof that there is no blind retry inside one run: the same
      // settlement cannot be attempted twice, and it is a refusal, not a re-send.
      throw new MalformedResult('SETTLE_REPLAYED_WITHIN_RUN', `settlement ${settleKey} was already used in this run; a re-send is a blind retry`);
    }
    settleKeys.add(settleKey);
    let settlement;
    try {
      settlement = recordSpend(registry, {
        reservationId: reservation.reservation_id,
        key: settleKey,
        // The settle arguments deliberately EXCLUDE the clock, so replaying a
        // settle is idempotent instead of a second charge.
        args: { run_id: bound.run_id, index: entry.index, trial: entry.trial, units: unitsPerTrial, preregistration_digest: preregDigest },
      });
    } catch (error) {
      const typed = isBoardError(error) ? error : toBoardError(error, 'PROVIDER_FAILURE');
      if (isTypedRefusal(typed, RECONCILIATION_REFUSAL)) {
        record.refusals.push(refused(typed.code, typed.message, entry.index));
        openReconciliation(entry, REASON_RESERVATION_EXPIRED, typed.message);
        budgetLive = false;
        record.trials.push(skippedTrial(entry, typed.code, typed.message, deps, metricName));
        runCounters.skipped += 1;
        continue;
      }
      if (isTypedRefusal(typed, BUDGET_REFUSAL)) {
        record.refusals.push(refused(typed.code, typed.message, entry.index));
        runCounters.budget_exceeded += 1;
        run.status = RUN_REFUSED;
        budgetLive = false;
        record.trials.push(skippedTrial(entry, typed.code, typed.message, deps, metricName));
        runCounters.skipped += 1;
        continue;
      }
      throw typed;
    }
    if (isPlainObject(settlement) && Number.isFinite(settlement.spent_units)) {
      if (settlement.spent_units !== spentUnits + unitsPerTrial) {
        throw new MalformedResult('BUDGET_LEDGER_DISAGREEMENT', `the ledger reports ${settlement.spent_units} spent units, the engine expected ${spentUnits + unitsPerTrial}`);
      }
      spentUnits = settlement.spent_units;
    } else {
      spentUnits += unitsPerTrial;
    }
    record.preregistration.budget.spent_units = spentUnits;

    // --- the trial itself ---------------------------------------------------
    const trialStartMs = nowMs();
    let observation = null;
    let executionError = null;
    try {
      observation = await executeTrial(entry, {
        run_id: bound.run_id,
        nonce: bound.nonce,
        index: entry.index,
        trial: entry.trial,
        seeds: entry.seeds,
        timeout_ms: timeoutMs,
        preregistration_digest: preregDigest,
        clock,
        registry,
      });
    } catch (error) {
      executionError = isBoardError(error) ? error : toBoardError(error, 'PROVIDER_FAILURE');
    }
    let classified;
    if (executionError) {
      // A thrown BoardError keeps its own code. UNKNOWN_OUTCOME and
      // RECONCILIATION_REQUIRED are an undetermined effect (UNRESOLVED plus a
      // reconciliation row); every other throw is a definite infrastructure
      // failure (INFRA, kept as a first-class outcome, never a skip).
      const undetermined = executionError.code === 'UNKNOWN_OUTCOME' || executionError.code === 'RECONCILIATION_REQUIRED';
      const synthetic = undetermined
        ? { outcome_unknown: true, code: executionError.code, detail: executionError.message, elapsed_ms: null }
        : { infra: { code: executionError.code, message: executionError.message } };
      classified = classifyTrialObservation(synthetic, { timeoutMs, deps, index: entry.index, trial: entry.trial, noiseBand, rule: { ...decisionRule, subject: entry.trial } });
    } else {
      // A trial that reports no elapsed time gets the INJECTED clock's own
      // delta, recorded with an explicit `latency_source` — with `fixedClock`
      // that delta is 0 by construction, and 0 is a MEASUREMENT OF THIS CLOCK,
      // not a claim that the trial was instantaneous.
      const withElapsed = typeof observation?.elapsed_ms === 'number'
        ? observation
        : { ...observation, elapsed_ms: nowMs() - trialStartMs };
      classified = classifyTrialObservation(withElapsed, { timeoutMs, deps, index: entry.index, trial: entry.trial, noiseBand, rule: { ...decisionRule, subject: entry.trial } });
    }

    const bindings = isPlainObject(observation?.bindings) ? observation.bindings : {};
    // The units already settled against the reservation BEFORE this trial, so
    // the budget binding states the position the trial was authorised in rather
    // than a running total that would be trivially self-consistent.
    const spentUnitsBefore = spentUnits;
    const trialRecord = {
      index: entry.index,
      trial: entry.trial,
      // S2-008-SD-01: the trial record must name the METRIC and carry the
      // counts `metricsSummary` aggregates. It used to carry `seed` (singular)
      // and no metric at all, so the aggregation aborted the whole comparison
      // with `METRIC_NAME_ABSENT` AFTER the trial loop, after
      // PREREGISTRATION_RECORDED and after every per-trial row was journalled —
      // a run that had already written its ledger could not be scored.
      // S2-008-SD-02: the member is `seeds` (the SET), because that is what
      // `DECISION_TRIAL_FIELDS` and `scoreSeedDisclosure` read and what
      // `assertSeedSetFrozen` checks; a singular `seed` scored as
      // `MISSING_SEED_BINDING` on a run that had bound one.
      seeds: entry.seeds,
      metric: metricName,
      numerator: isFinite(observation?.numerator) ? observation.numerator : (Number.isFinite(classified.numerator) ? classified.numerator : null),
      denominator: isFinite(observation?.denominator) ? observation.denominator : (Number.isFinite(classified.denominator) ? classified.denominator : null),
      // The value the case RECORD carried, when the measurer published one and
      // it is not the count-derived rate the metric is defined on. It is
      // carried, not dropped: `observed` is `numerator / denominator` (so the
      // record's own arithmetic closes), and a second, different number that
      // the measurer saw must stay visible instead of vanishing into the
      // rounding. Absent is `null`, which reads as "the measurer published no
      // separate raw value" and not as zero.
      case_record_rate: isFinite(observation?.case_record_rate) ? observation.case_record_rate : null,
      status: classified.status,
      outcome: classified.outcome,
      reason_codes: classified.reason_codes.slice(),
      observed: classified.observed,
      interval: classified.interval,
      noise_band: noiseBand,
      decision: classified.decision,
      // The four bindings the comparator needs for ALLOW. A binding the executor
      // did not declare is explicit null, so a missing binding fails closed
      // instead of reading as "nothing to check". They are written under
      // `bindings` (the nested spelling the comparator also reads) AND the
      // seed set is written flat, so the comparator's seed check and its
      // binding check see the same bytes.
      bindings: {
        seed: { seeds: entry.seeds, source: 'PREREGISTERED' },
        holdout: bindings.holdout ?? null,
        budget: { reservation_id: reservation.reservation_id, granted_units: reservation.granted_units, spent_units: spentUnitsBefore, units: unitsPerTrial, settle_key: settleKey, replayed: settlement?.replayed === true },
        evaluator: bindings.evaluator ?? null,
      },
      seedBinding: { seeds: entry.seeds, source: 'PREREGISTERED' },
      holdoutBinding: bindings.holdout ?? null,
      budgetBinding: { reservation_id: reservation.reservation_id, granted_units: reservation.granted_units, spent_units: spentUnitsBefore, currency: reservation.currency ?? 'UNITS' },
      evaluatorBinding: bindings.evaluator ?? null,
      evaluator: bindings.evaluator ?? null,
      calibration: isPlainObject(observation?.calibration) ? observation.calibration : null,
      card: isPlainObject(prereg.card) ? prereg.card : null,
      // A5, per trial: the trial names the SAME execution the run names. The
      // three members were read as `bound.raw_run_id` / `bound.commit_sha` /
      // `bound.tree_sha`, none of which exist on the provenance block (it
      // carries `run_id` / `commit` / `tree`), so every value was `undefined`,
      // the whole object was stripped at canonicalisation, and the block
      // reached the evidence as `{}` — an artefact that claimed a binding and
      // carried none, with `expectedValueIssues` skipping it on `undefined`.
      provenance: {
        raw_run_id: bound.run_id,
        commit_sha: bound.commit,
        tree_sha: bound.tree,
        nonce: bound.nonce,
        executor_id: bound.executor_id,
      },
      budget: { units: unitsPerTrial, settle_key: settleKey, replayed: settlement?.replayed === true },
      elapsed_ms: classified.elapsed_ms,
      latency_ms: classified.elapsed_ms,
      latency_source: classified.latency_source,
      infra: classified.infra,
      reconciliation_id: null,
      detail: boundDetail(observation?.detail ?? ''),
    };
    const verdict = resolveTrialVerdict(trialRecord);
    if (!isPlainObject(verdict) || typeof verdict.verdict !== 'string') {
      throw new MalformedResult('TRIAL_VERDICT_SHAPE_INVALID', 'resolveTrialVerdict must return {verdict, ...}');
    }
    trialRecord.verdict = verdict.verdict;
    // The comparator's own reasons, kept verbatim. They are the evidence the
    // hard-gate counters are counted FROM (`CAUSAL_CLAIM_UNSUPPORTED:...`,
    // `EVALUATOR_NOT_INDEPENDENT:...`, `UNSATISFIED_HOLDOUT_BINDING:...`):
    // a counter with no source is a number nobody can check, and this is the
    // source.
    trialRecord.verdict_reasons = Array.isArray(verdict.reasons) ? [...verdict.reasons] : [];
    if (classified.reconciliation) {
      const row = openReconciliation(entry, classified.reconciliation.reasonCode, classified.reconciliation.detail);
      trialRecord.reconciliation_id = row.reconciliation_id;
    }
    record.trials.push(trialRecord);
    runCounters.executed += 1;
    if (trialRecord.status === 'RESOLVED') runCounters.resolved += 1;
    else if (trialRecord.status === 'INFRA_ERROR') runCounters.infra += 1;
    else if (trialRecord.status === 'UNRESOLVED') runCounters.unresolved += 1;
    appendRecord(registry, {
      // Envelope kind for the ordering proof, payload `record_kind` for the
      // track's ledger table — see this file's header.
      kind: TRIAL_RESULT_ROW_KIND,
      record_kind: TRIAL_RESULT_ROW_KIND,
      run_id: bound.run_id,
      nonce: bound.nonce,
      index: entry.index,
      trial: entry.trial,
      seeds: entry.seeds,
      status: trialRecord.status,
      outcome: trialRecord.outcome,
      verdict: trialRecord.verdict,
      reason_codes: trialRecord.reason_codes,
      preregistration_digest: preregDigest,
      reconciliation_id: trialRecord.reconciliation_id,
      recorded_at: isoOf(clock),
    });
  }

  // --- aggregate, measure latency, bind -------------------------------------
  record.metrics = metricsSummary(record.trials);
  // SD-12: the PREREGISTERED bootstrap parameters are handed to
  // `latencyRecorded`, so the block reports the seed and sample count the
  // preregistration fixed instead of the module's defaults. The one-argument
  // call made the JSDoc's promise false and unprovable from the record.
  const latency = latencyRecorded(record.trials, isPlainObject(prereg.noise_rule) ? prereg.noise_rule : null);
  if (!isPlainObject(latency) || latency.decides !== false) {
    // "Latency never decides" is a guard, not a convention: a latency block
    // that claims to decide fails the run instead of being trusted.
    throw new BlockedPolicy('LATENCY_DECIDES', 'latencyRecorded must return a block whose `decides` is literally false');
  }
  record.latency = latency;
  const journal = readJournal(registry);
  if (!Array.isArray(journal)) {
    throw new MalformedResult('JOURNAL_SHAPE_INVALID', 'readJournal must return an array of records');
  }
  // `readJournal` returns ENVELOPES: the kind lives at `row.kind` and the
  // record's own members at `row.payload`. The check below used to read
  // `row.record_kind`, which no envelope carries, so it threw
  // JOURNAL_RECORD_UNNAMED on every run — including the clean ones — after the
  // ledger had already been written. `journalRowsOf` is the one place that
  // knows the envelope shape, and it is the same projection the ordering proof
  // is given, so the two cannot drift apart.
  const rows = journalRowsOf(journal);
  record.ledger = {
    record_count: rows.length,
    kinds: rows.map((row) => row.kind),
    payload_kinds: rows.map((row) => row.record_kind),
    counts: rows.reduce((tally, row) => ({ ...tally, [row.record_kind]: (tally[row.record_kind] ?? 0) + 1 }), {}),
    snapshot_digest: snapshotDigest(registry),
  };
  // The codes the run emitted, and the hard-gate counters derived FROM this
  // record. Both are computed at the end, from what actually happened, and
  // neither is initialised to a passing value anywhere above.
  record.codes = [...new Set([
    ...record.refusals.map((entry) => entry.code),
    ...record.trials.flatMap((entry) => (Array.isArray(entry.reason_codes) ? entry.reason_codes : [])),
  ])].sort();
  const hardGates = hardGateCounters(record, deps);
  record.counters = hardGates.values;
  record.counter_sources = hardGates.sources;
  run.finished_at = isoOf(clock);
  // The decision digest is computed BEFORE the binding, and is then carried
  // INSIDE the bound artefact, so the artefact digest covers it and the
  // returned document re-verifies byte for byte. It does not appear in the
  // projection, so inserting it cannot change the value it holds.
  const digest = decisionDigest(record);
  return bindArtefact({ ...record, decision_digest: digest }, bound);
}

/**
 * The six hard-gate counters, counted from THIS record and from nothing else.
 *
 * Each counter is derived from named members of the run record — the refusal
 * codes the engine pushed, and the comparator's own verdict reasons — and
 * `sources` reports that derivation next to the number, so "0" is a claim a
 * reader can re-derive instead of a value the engine asserted. The counters
 * are NOT initialised to 0 and NOT defaulted: a counter name the engine cannot
 * derive is a `NeedsInput`, not a zero.
 *
 * Two of the six are FATAL in this engine rather than counted: a seed
 * substitution and a post-result hypothesis rewrite are thrown by
 * `assertSeedSetFrozen` / `assertPreregistration`, so a record that exists
 * never contains them. Their 0 therefore means "no such refusal was RECORDED",
 * and the run that suffered one produced no record at all — which is the
 * stronger statement, not a weaker one, and is why the header says a refusal
 * that produced no artefact is the one case the engine does not paper over.
 * @param {object} record The run record, with its refusals and trials filled.
 * @param {object} deps The resolved dependency groups.
 * @returns {{values: Readonly<Record<string, number>>, sources: Readonly<Record<string, string>>}}
 * @throws {import('../agentboard/errors.mjs').NeedsInput} when the closed
 *   counter vocabulary is unavailable.
 */
function hardGateCounters(record, deps) {
  const names = requireList(deps, 'constants', 'RESEARCH_HARD_GATE_COUNTERS');
  const refusalCodes = record.refusals.map((entry) => String(entry.code));
  const verdictReasons = record.trials.flatMap((entry) => (Array.isArray(entry.verdict_reasons) ? entry.verdict_reasons.map(String) : []));
  // The reasons of trials that MEASURED something. A trial that produced no
  // measurement has no evaluator to be independent of, no interval to have
  // been read before a decision point, and no relation to upgrade — counting
  // those absences as gate hits made a clean run with one preregistered INFRA
  // trial report `missingEvaluator: 1`, which is a false accusation against a
  // trial that never claimed a measurement.
  const resolvedReasons = record.trials
    .filter((entry) => entry.status === 'RESOLVED')
    .flatMap((entry) => (Array.isArray(entry.verdict_reasons) ? entry.verdict_reasons.map(String) : []));
  const countRefusals = (prefixes) => refusalCodes.filter((code) => prefixes.some((prefix) => code.startsWith(prefix))).length;
  const countReasons = (prefixes) => verdictReasons.filter((reason) => prefixes.some((prefix) => reason.startsWith(prefix))).length;
  const countResolved = (prefixes) => resolvedReasons.filter((reason) => prefixes.some((prefix) => reason.startsWith(prefix))).length;
  const DERIVATIONS = Object.freeze({
    // A peek is a peek whatever the trial went on to produce, so this one
    // counts every trial's reasons.
    holdoutPeek: () => countRefusals(['HOLDOUT_']) + countReasons(['UNSATISFIED_HOLDOUT_BINDING', 'CAUSAL_CLAIM_UNSUPPORTED:read_before_decision_point']),
    seedSubstitution: () => countRefusals(['SEED_']),
    hypothesisRewrite: () => countRefusals(['HYPOTHESIS_', 'PREREGISTRATION_', 'AMENDMENT_']),
    budgetOpacity: () => countRefusals(['BUDGET_']),
    causalUpgrade: () => countReasons(['CAUSAL_CLAIM_UNSUPPORTED']),
    missingEvaluator: () => countResolved(['EVALUATOR_NOT_INDEPENDENT', 'CALIBRATION_NOT_MEASURED', 'UNSATISFIED_EVALUATOR_BINDING']),
  });
  const values = {};
  const sources = {};
  for (const name of names) {
    if (typeof DERIVATIONS[name] !== 'function') {
      throw new NeedsInput('HARD_GATE_COUNTER_UNNAMED', `the run must report the hard-gate counter ${name}, and this engine names no way to derive it; an uncounted counter is not a zero counter`);
    }
    values[name] = DERIVATIONS[name]();
    sources[name] = (name === 'seedSubstitution' || name === 'hypothesisRewrite')
      ? 'refusals[].code (fatal in this engine: a substitution or a rewrite throws and returns no record)'
      : (name === 'missingEvaluator'
        ? 'refusals[].code and trials[].verdict_reasons of trials with status RESOLVED'
        : 'refusals[].code and trials[].verdict_reasons');
  }
  return { values: Object.freeze(values), sources: Object.freeze(sources) };
}

// --- the executable clock-invariance property -------------------------------

/**
 * EXECUTE the property "two runs of the same base at different wall-clock
 * values produce a bit-identical verdict", and refuse to certify it vacuously.
 *
 * What it does, in order, and why each step is necessary:
 *   1. runs the engine once per injected clock, with the SAME preregistration,
 *      the same seeds and the same executor;
 *   2. requires every decision digest to be EQUAL — the property;
 *   3. requires the artefact digests NOT to be equal — non-vacuity: if nothing
 *      changed, "identical verdicts" was proven by an input that never differed;
 *   4. mutates ONE verdict-bearing field of the first record and requires the
 *      decision digest to CHANGE — sensitivity: a digest that cannot move would
 *      satisfy step 2 while deciding nothing.
 *
 * The honest boundary, and it is checked here rather than assumed: a clock that
 * crosses a PREREGISTERED threshold (the reservation's `expires_at`, the
 * per-trial timeout) MUST change the verdict, because that is the budget and
 * timeout rules working. This function therefore refuses clocks outside the
 * reservation window, and reports which thresholds were outside the tested
 * range so the evidence record does not overstate what was proven.
 * @param {object} ctx The engine context, plus:
 * @param {ReadonlyArray<object|string>} ctx.clocks Two or more injected clocks
 *   (or ISO instants) that all sit inside the reservation window.
 * @returns {Promise<{ok: true, decision_digests: ReadonlyArray<string>,
 *   decision_digests_equal: boolean, artefact_digests: ReadonlyArray<string>,
 *   artefact_digests_differ: boolean, mutated_decision_digest: string,
 *   mutation_changes_digest: boolean, run_statuses: ReadonlyArray<string>,
 *   thresholds_outside_tested_range: ReadonlyArray<string>}>} The witness.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'CLOCK_INVARIANCE_VIOLATED' / 'CLOCK_INVARIANCE_VACUOUS' /
 *   'CLOCK_OUTSIDE_RESERVATION'.
 */
export async function verifyClockInvariance(ctx = {}) {
  const { clocks, ...engineCtx } = ctx;
  if (!Array.isArray(clocks) || clocks.length < 2) {
    throw new NeedsInput('CLOCK_SET_REQUIRED', 'verifyClockInvariance needs at least two injected clocks');
  }
  const results = [];
  for (const clock of clocks) results.push(await runDeterministicRun({ ...engineCtx, clock }));
  const decisionDigests = results.map((result) => result.decision_digest);
  const artefactDigests = results.map((result) => result.artefact_digest);
  const runStatuses = results.map((result) => result.run.status);
  const decisionDigestsEqual = decisionDigests.every((digest) => digest === decisionDigests[0]);
  if (!decisionDigestsEqual) {
    throw new BlockedPolicy('CLOCK_INVARIANCE_VIOLATED', `the decision digest moved with the clock: ${decisionDigests.join(' != ')}`);
  }
  const artefactDigestsDiffer = artefactDigests.some((digest) => digest !== artefactDigests[0]);
  if (!artefactDigestsDiffer) {
    throw new BlockedPolicy('CLOCK_INVARIANCE_VACUOUS', 'the clocks produced byte-identical artefacts, so "identical verdicts" was proven by an input that never differed');
  }
  const mutated = mutatedRecord(results[0]);
  const mutatedDigest = decisionDigest(mutated);
  if (mutatedDigest === decisionDigests[0]) {
    throw new BlockedPolicy('CLOCK_INVARIANCE_VACUOUS', 'a verdict-bearing mutation did not move the decision digest, so the digest decides nothing');
  }
  const reservation = engineCtx?.prereg?.budget_reservation;
  const tested = clocks.map((clock) => (typeof clock === 'string' ? clock : clock.nowIso()));
  const outside = [];
  if (isPlainObject(reservation) && typeof reservation.expires_at === 'string') {
    for (const instant of tested) {
      if (Date.parse(instant) >= Date.parse(reservation.expires_at)) {
        throw new BlockedPolicy('CLOCK_OUTSIDE_RESERVATION', `${instant} is at or past the preregistered reservation expiry ${reservation.expires_at}; a verdict that ignores an expired reservation is the bug, not the property`);
      }
    }
    outside.push(`budget_reservation.expires_at=${reservation.expires_at} (both clocks are inside it; crossing it MUST change the verdict)`);
  }
  outside.push('trial_timeout_ms (a reported elapsed time beyond it MUST open a reconciliation, and is not exercised by the clock sweep)');
  return {
    ok: true,
    decision_digests: decisionDigests,
    decision_digests_equal: true,
    artefact_digests: artefactDigests,
    artefact_digests_differ: true,
    mutated_decision_digest: mutatedDigest,
    mutation_changes_digest: true,
    run_statuses: runStatuses,
    thresholds_outside_tested_range: outside,
  };
}

function mutatedRecord(record) {
  const clone = JSON.parse(canonicalize(record));
  const first = Array.isArray(clone.trials) ? clone.trials[0] : null;
  if (!first) {
    throw new MalformedResult('MUTATION_TARGET_MISSING', 'the non-vacuity mutation needs at least one trial record');
  }
  if (typeof first.observed === 'number' && Number.isFinite(first.observed)) {
    first.observed += 1;
  } else {
    // No measurement to move: flip the status instead, which is verdict-bearing
    // by construction (ALLOW requires RESOLVED).
    first.status = 'SKIPPED';
    first.verdict = 'VIOLATION';
  }
  return clone;
}
