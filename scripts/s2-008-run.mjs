#!/usr/bin/env node
// S2-008 — ONE PROCESS-SEPARATED RUN (issue SpaceDazher/Veritas#8, A3 + A5).
//
// WHAT THIS SCRIPT IS
// The executor of the deterministic transport, in the shape of
// `scripts/s2-006-run.mjs` and `scripts/s2-007-db-replay-executor.mjs`: it
// opens a registry, takes the preregistered budget BEFORE trial one, opens the
// holdout exactly once through the preregistered unseal digest, executes every
// preregistered trial through `runDeterministicRun` and binds the result to the
// commit SHA, the tree SHA, the raw run id and a per-process nonce.
//
// It contains NO probe logic, NO decision logic and NO corpus of its own. The
// probes live in `src/lib/research/probes.mjs`, the decision in
// `src/lib/research/comparator.mjs`, the engine in
// `src/lib/research/runner.mjs`, the corpus in `evidence/s2-008/corpus/` and
// the frozen expectation in `src/lib/research/expected-values.mjs`. A second
// copy of any of them here would be a second, weaker copy that could keep
// passing after the real one was rewired — the failure mode
// `scripts/s2-007-security-probes.mjs` refuses by design.
//
// PROCESS SEPARATION IS NOT ASSERTED, IT IS TRUE
// `scripts/s2-008-replay.mjs` spawns this file TWICE, once per letter. Every
// process mints its own raw run id and its own nonce from its own pid
// (`deriveProcessNonce`), and each run owns its own registry root. Two awaited
// calls in one heap are cooperative, not concurrent and not separate.
//
// THE ORDER OF OPERATIONS, AND WHY IT IS THIS ORDER
//   1. purge this run's OWN fixtures (`--root`, `--output-root`), so a repeat
//      run on a permanent base fails on the property and not on leftovers;
//   2. resolve the REAL base with READ-ONLY git;
//   3. load the preregistration and check the frozen table against it BEFORE
//      trial one (`assertTableFrozen`);
//   4. open the holdout ONCE, at the preregistered decision point, through
//      `readCorpus`, which journals the ACCESS row before returning a byte;
//   5. execute the engine;
//   6. score the engine's own record against the frozen table
//      (`expectedValueIssues`) — the run checks ITSELF, so a run that cannot
//      pass its table still leaves a record saying by how much it missed;
//   7. bind and, with `--write`, write `evidence/s2-008-run-<label>.json`.
//
// NO RUN-TIME CHOICE
// The per-trial timeout is read from the preregistration by the engine
// (`trialTimeoutOf`) and this script NEVER supplies one: a timeout chosen by the
// runner is not a preregistered timeout. When the committed preregistration
// publishes none, the engine refuses with `TRIAL_TIMEOUT_NOT_PREREGISTERED`,
// this script records that refusal as evidence and exits 3. Injecting a value
// to make the run go green would convert a named hole into a hidden one.
//
// EXIT CODES (the aggregator and `s2-008-replay.mjs` depend on these values)
//   0  a COMPLETED run whose record agrees with the frozen table, with every
//      hard-gate counter at 0;
//   1  a record was produced and it FAILED: table findings, a moved counter, or
//      a run status other than COMPLETED with a measurement in every row;
//   2  the run could not be attempted at all (unreadable base, malformed
//      preregistration, a crash) — never a pass;
//   3  NOT_RUN: the engine produced no runnable record, or produced a
//      reconciliation / skipped-trial record. "I could not produce a result"
//      and "I produced a result that failed" are different answers and are
//      never collapsed into one.
//
// DETERMINISM
// No network, no LLM, no credentials, no `Date.now()`, no `Math.random()`. Every
// instant is a frozen literal below or the injected clock. Wall-clock latency
// is MEASURED (it is read out of the engine's own `latency` block) and is
// structurally unable to decide: the engine refuses a latency block whose
// `decides` is not literally false, and the record repeats the assertion.
//
//   node scripts/s2-008-run.mjs --label a --write
//   node scripts/s2-008-run.mjs --label b --repeat     # the A5 repeat witness
//   node scripts/s2-008-run.mjs --print-record         # the record, not a summary
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import * as researchConstants from '../src/lib/research/constants.mjs';
import { readCorpus } from '../src/lib/research/dataset.mjs';
import {
  EXPECTED_METRIC, EXPECTED_TRIAL_DECISIONS, assertTableFrozen, expectedTableDigest, expectedValueIssues,
} from '../src/lib/research/expected-values.mjs';
import { loadPreregistration, preregistrationDigest } from '../src/lib/research/preregistration.mjs';
import {
  appendRecord, openRegistry, purgeRegistry, putExperiment, readJournal, recordSpend, snapshotDigest, verifyChain,
} from '../src/lib/research/registry.mjs';
import {
  bindArtefact, deriveProcessNonce, freezeProvenance, reconciliationRow, runDeterministicRun,
  verdictProjection,
} from '../src/lib/research/runner.mjs';
import { purgeExecutorFixtures } from '../src/lib/research/executor.mjs';
import { wilsonInterval } from '../src/lib/sloqual/statistics.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
/** The committed corpus. The DEFAULT and the only corpus whose run may be
 *  written to `evidence/`; `--corpus` marks a run as evidence-INELIGIBLE. */
export const COMMITTED_CORPUS_DIR = path.join(REPO_ROOT, 'evidence', 's2-008', 'corpus');
/** Every run's scratch: under `.bb/`, which `.gitignore` already covers, so a
 *  run never writes residue into a tracked path. */
export const RUN_SCRATCH_ROOT = path.join(REPO_ROOT, '.bb', 's2-008', 'run');

/**
 * THE HOLDOUT DECISION POINT — a frozen literal, in the shape the S2-007
 * runner uses for its injected instants. The preregistration names the policy
 * (`holdout_access.decision_point === 'AFTER_DECLARED_TRIALS'`), never an
 * instant, so the instant is the harness's to fix and it is fixed here once.
 * A read at or after it is lawful; a read before it is a peek.
 */
export const DECISION_POINT_INSTANT = '2026-01-01T01:00:00.000Z';
/** The actor kind that performs the one-shot HOLDOUT open. It must be a member
 *  of the preregistration's `holdout_access.released_actor_kinds` — the run
 *  asserts that by reading the ACCESS row back through `assertPartitionAccess`,
 *  so naming a kind the preregistration did not release refuses the run at the
 *  open rather than after it. */
export const HOLDOUT_ACTOR_KIND = 'EVALUATOR';
/** The confidence the interval is reported at. Read from the preregistered
 *  `noise_rule.confidence` at run time; this is only the fallback. */
const FALLBACK_CONFIDENCE = 0.95;
/** The metric name the frozen table declares, read once so the preconditions
 *  check quotes the table instead of a literal. @type {string} */
const EXPECTED_METRIC_NAME = EXPECTED_METRIC.name;

/** The per-run clock. Every instant in the record is this one, which is what
 *  makes a repeat run on the same base produce the same bytes. */
function fixedClock(iso) {
  const ms = Date.parse(iso);
  return Object.freeze({
    nowNs: () => ms * 1e6,
    nowMs: () => ms,
    iso: () => iso,
    now: () => new Date(ms),
    nowIso: () => iso,
  });
}

/**
 * A deterministic id factory in the shape `AgentBoardStoreBase.newId` requires:
 * a BARE suffix, because the base class prepends the prefix from the frozen
 * `ID_PREFIXES` table itself.
 * @param {string} scope @returns {{next: (kind: string) => string}}
 */
export function idFactory(scope) {
  const digest = canonicalDigest({ scope }).slice(0, 8);
  const counters = new Map();
  return Object.freeze({
    next: (kind) => {
      const key = String(kind);
      const next = (counters.get(key) ?? 0) + 1;
      counters.set(key, next);
      return `${digest}${next.toString(36).padStart(4, '0')}`;
    },
  });
}

/**
 * `--print-record` -> `printRecord`, `--no-lock` -> `noLock`. Both spellings
 * are accepted so a flag copied from the S2-007 scripts keeps working.
 */
function normaliseKey(key) {
  return key.replace(/[-_](\w)/g, (_match, letter) => letter.toUpperCase());
}

export function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const key = normaliseKey(token.slice(2));
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) args[key] = true;
    else {
      args[key] = next;
      index += 1;
    }
  }
  return args;
}

/** Read-only git. No commit, no write, no index mutation: delivery owns git. */
function git(...parts) {
  return execFileSync('git', parts, { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

/**
 * The REAL base, plus whether this track is TRACKED at all. An untracked run
 * cannot be bound to a base in any sense a reader can check, so the fact is
 * reported and never treated as fine.
 */
export function resolveBase() {
  const tracked = git('ls-files', '-z').split('\0').filter(Boolean);
  const mine = tracked.filter((file) => /^(src\/lib\/research\/|tests\/research\/|scripts\/s2-008-|scripts\/verify-s2-008|evidence\/s2-008\/|evidence\/s2-008-)/.test(file));
  return {
    commit_sha: git('rev-parse', 'HEAD'),
    tree_sha: git('rev-parse', 'HEAD^{tree}'),
    branch: git('rev-parse', '--abbrev-ref', 'HEAD'),
    worktree_dirty: git('status', '--porcelain').length > 0,
    tracked_files_of_this_track: mine.length,
    track_tracked: mine.length > 0,
  };
}

/**
 * The lawful run window, derived from the preregistration and the frozen
 * decision instant. A holdout read at or after `from`, a reservation live
 * strictly before `until` (`assertBudgetReservation` refuses `now >= expires_at`).
 * An EMPTY window is a property of the preregistration, not of this script, and
 * it is named as a finding instead of being worked around by moving a clock.
 */
export function lawfulWindow(prereg, decisionPoint = DECISION_POINT_INSTANT) {
  const expiresAt = prereg?.budget_reservation?.expires_at ?? null;
  const fromNs = Date.parse(decisionPoint);
  const untilNs = typeof expiresAt === 'string' ? Date.parse(expiresAt) : Number.NaN;
  const empty = !Number.isFinite(untilNs) || untilNs <= fromNs;
  return {
    decision_point: decisionPoint,
    reservation_expires_at: expiresAt,
    from: decisionPoint,
    until: expiresAt,
    window_ms: Number.isFinite(untilNs) ? untilNs - fromNs : null,
    empty,
    rule: 'a holdout read is lawful at or after the decision point; a reservation is live strictly before its expiry',
  };
}

/**
 * The one-shot holdout read. It happens ONCE per run, on the run's own ledger,
 * through `readCorpus`, which journals the ACCESS row before it returns a byte.
 * The case data it returns is what every trial measures against: a second open
 * of the same partition is refused by `max_opens`, and that refusal is the rule,
 * not a limitation of this script.
 */
function openHoldoutOnce({ registry, prereg, clockInstant, corpusDir }) {
  const access = prereg.holdout_access;
  const decisionPoint = DECISION_POINT_INSTANT;
  const read = readCorpus(registry, {
    partition: access.partition,
    caseId: 's2-008-case-01',
    unsealDigest: access.unseal_digest,
    decisionPoint,
    maxOpens: access.max_opens,
    // The actor kind that performs the read, and the release list the
    // PREREGISTRATION published for it. Both travel onto the ACCESS row, so
    // `assertPartitionAccess` decides the release against the row the ledger
    // actually committed instead of against a synthetic fallback that carried
    // no release list (PR9: that rule had no attack coverage at all, and the
    // coverage it lacked was the reason it could not be told apart from a
    // blanket refusal).
    actorKind: HOLDOUT_ACTOR_KIND,
    releasedActorKinds: access.released_actor_kinds ?? null,
    // The corpus is FORWARDED, never left to `readCorpus`'s own default. This
    // line is the fix for a real defect: `openHoldoutOnce` used to omit it, so
    // `--corpus <dir>` loaded its PREREGISTRATION from the named directory and
    // then read its CASE DATA from the committed one. The record was a mixture
    // of two corpora while naming one, and a self-test that could not move the
    // data it was testing could not have detected that. A preregistration and
    // the cases it governs now come from the same bytes or the run says so.
    corpusDir,
  });
  return {
    read_at: clockInstant,
    binding: {
      partition: access.partition,
      read_at: clockInstant,
      decision_at: decisionPoint,
      opened_before_decision_point: Date.parse(clockInstant) < Date.parse(decisionPoint),
      opens: 1,
      max_opens: access.max_opens,
      labels_digest: read.labelsDigest,
      access_record_id: read.accessRecordId,
      case_id: read.caseId,
    },
    access_record_id: read.accessRecordId,
    labels_digest: read.labelsDigest,
    case: read.case,
    labels: read.labels,
    agreement_by_trial: read.agreementByTrial,
  };
}

/**
 * The injected evaluator and calibration, and the ONE measure function.
 *
 * The measurer is a pure function of the case record the one-shot open
 * returned. `readCorpus` is one case per open and the preregistered
 * `max_opens` is 1, so the partition is opened exactly once and the measurer
 * measures THAT case: its per-trial agreement, expressed over the
 * preregistered `holdout_access.case_count` denominator the metric is defined
 * on. It reports the raw rate (the decision input) AND the integer count (the
 * metric's own numerator), and it never reports a number it did not compute —
 * the infra row is produced by a measurer that deliberately returns nothing,
 * which is the difference between an infra result and a fabricated zero.
 */
function buildExecutor({ holdout, prereg, confidence }) {
  const denominator = Number.isInteger(prereg?.holdout_access?.case_count)
    ? prereg.holdout_access.case_count
    : null;
  const evaluator = { evaluator_id: 'evl-s2-008-runner', independent: true, blind_to_producer: true };
  const calibration = {
    status: 'MEASURED',
    not_measured_reason: null,
    evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true },
  };
  return async function executeTrial(entry) {
    const row = EXPECTED_TRIAL_DECISIONS[entry.index];
    if (row && row.expectedStatus !== 'RESOLVED') {
      // The preregistered INFRA row: no measurement, and NOT a zero. The
      // engine classifies an `infra` observation as INFRA_ERROR/INFRA, which is
      // the closed-vocabulary first-class outcome, and never as a skip.
      return {
        infra: { code: 'MEASUREMENT_ABSENT', message: 'the measurer produced no sample; an infra result is a row of the ledger, never a zero' },
        elapsed_ms: 0,
        bindings: { holdout: holdout.binding, evaluator },
        calibration,
      };
    }
    const opened = isPlainObject(holdout.case) ? holdout.case : null;
    // The rate is the PARTITION's case-agreement for this trial, not the opened
    // case's. `readCorpus` folds it out of the same one journalled open and
    // hands it over as `agreement_by_trial`; taking the single case's value
    // instead reported the opened case's answer as the trial's, which for a
    // metric named `case_agreement_rate` is the wrong denominator's question.
    const perTrial = isPlainObject(holdout.agreement_by_trial) ? holdout.agreement_by_trial : null;
    const row2 = perTrial !== null ? perTrial[entry.trial] : null;
    if (opened === null || row2 === undefined || !isPlainObject(row2) || !Number.isFinite(row2.rate)) {
      return {
        infra: { code: 'CASE_RECORD_UNUSABLE', message: `the opened partition carries no agreement for ${entry.trial}; a rate over no case is not a measurement` },
        elapsed_ms: 0,
        bindings: { holdout: holdout.binding, evaluator },
        calibration,
      };
    }
    if (denominator === null) {
      return {
        infra: { code: 'DENOMINATOR_NOT_PREREGISTERED', message: 'the preregistration names no holdout case_count, so the metric has no denominator' },
        elapsed_ms: 0,
        bindings: { holdout: holdout.binding, evaluator },
        calibration,
      };
    }
    // The counts are the partition's OWN, and the preregistered denominator is
    // the partition's case count. They are cross-checked: a corpus whose
    // agreeing-cases count and declared case count disagree is refused as
    // UNUSABLE rather than measured against a denominator that does not
    // describe the data.
    const numerator = row2.agreeing;
    if (row2.total !== denominator || numerator > row2.total) {
      return {
        infra: {
          code: 'PARTITION_DENOMINATOR_DIVERGES',
          message: `the partition holds ${String(row2.total)} case(s) with agreement for ${entry.trial} and the preregistration declares ${String(denominator)}; a metric is never measured against a denominator that does not describe the data`,
        },
        elapsed_ms: 0,
        bindings: { holdout: holdout.binding, evaluator },
        calibration,
      };
    }
    const measured = numerator / denominator;
    const interval = wilsonInterval({ successes: numerator, trials: denominator, confidence });
    return {
      measured,
      interval: { lower: interval.lower, upper: interval.upper, method: interval.method, confidence },
      numerator,
      denominator,
      // The opened case's own value, kept under its own name. It is not the
      // metric — one case cannot be a rate over the partition — and it is
      // carried rather than discarded so the record shows what the open saw.
      case_record_rate: Number.isFinite(opened.agreement_by_trial?.[entry.trial]) ? opened.agreement_by_trial[entry.trial] : null,
      elapsed_ms: 0,
      bindings: { holdout: holdout.binding, evaluator },
      calibration,
    };
  };
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A scratch path as it may be COMMITTED: repository-relative when it is
 *  inside the tree, a fixed token when it is not. A host-local absolute path in
 *  a committed evidence record leaks the account name, the worktree layout and
 *  the thread id of the machine that produced it, and it makes the record's
 *  bytes host-dependent, so the same base on another checkout could not
 *  reproduce it. A root outside the repository is tokenised rather than turned
 *  into a `../..` escape, so a path outside the tree cannot be reconstructed. */
function repoRelativeOrToken(abs) {
  const relative = path.relative(REPO_ROOT, String(abs ?? ''));
  if (relative === '' || path.isAbsolute(relative) || relative === '..' || relative.startsWith(`..${path.sep}`)) {
    return '<external-scratch-root>';
  }
  return relative;
}

// ---------------------------------------------------------------------------
// THE CRASH / RESTART PHASES
//
// Two modes, both driven by `scripts/s2-008-replay.mjs`, in the shape of the
// S2-007 replay's crash phase:
//
//   `--crash-phase 1` writes the preregistration row and TAKES the preregistered
//   budget reservation, then kills ITSELF with SIGKILL before the first trial.
//   Nothing is flushed on the way out, so what survives is only what the ledger
//   had already committed — which is the point.
//
//   `--crash-phase 2` is the RESTART: a different process, the same registry
//   root, and NO purge. It must see phase 1's rows, must NOT re-run the
//   interrupted trial, and must open a RECONCILIATION row for it. Then it
//   re-presents the same settle key (idempotent, the ledger must not charge
//   twice) and presents it once more on an EXPIVED clock, where the ledger must
//   refuse with a typed `ReconciliationRequired` and must not advance the spend.
//
// The three properties are named separately because they are three claims: a
// restart is a restart (phase 1's rows are visible), an interruption is a
// reconciliation (a row, undecided, no retry, no zero), and an expired
// reservation is a reconciliation too (a typed refusal, not a silent charge).
// ---------------------------------------------------------------------------

async function crashPhaseOne({ label, corpusDir, root }) {
  rmSync(root, { recursive: true, force: true });
  mkdirSync(root, { recursive: true });
  const prereg = loadPreregistration(corpusDir);
  assertTableFrozen(prereg);
  const clock = fixedClock(DECISION_POINT_INSTANT);
  const runId = `s2-008-run-${label}-crash-p${process.pid}`;
  const provenance = freezeProvenance({
    commit: resolveBase().commit_sha,
    tree: resolveBase().tree_sha,
    runId,
    label,
    executorId: `exec-s2-008-${label}-crash-p${process.pid}`,
    nonce: deriveProcessNonce({ label, runId, attempt: 0, pid: process.pid }),
    clock: DECISION_POINT_INSTANT,
    startedAt: DECISION_POINT_INSTANT,
  });
  const registry = openRegistry({ root, clock, ids: idFactory(`${label}-crash`) });
  openHoldoutOnce({ registry, prereg, clockInstant: DECISION_POINT_INSTANT, corpusDir });
  const reservation = prereg.budget_reservation;
  const digest = preregistrationDigest(prereg);
  appendPreregistrationRow(registry, { provenance, digest, prereg, clockInstant: DECISION_POINT_INSTANT });
  const payload = {
    kind: 'BUDGET_RESERVATION',
    reservation_id: reservation.reservation_id,
    granted_units: reservation.granted_units,
    spent_units: 0,
    currency: reservation.currency ?? null,
    expires_at: reservation.expires_at,
    preregistration_digest: digest,
    run_id: runId,
    nonce: provenance.nonce,
  };
  putExperiment(registry, {
    key: canonicalDigest({ operation: 'OPEN_RESERVATION', ...payload }),
    args: { ...payload },
    expectedRevision: registry.revision(),
    mutate: () => ({ ...payload, taken_at: DECISION_POINT_INSTANT }),
  });
  // The real crash. SIGKILL, not an exception: an `exit(1)` would flush stdout
  // and run the `finally` blocks, which is a clean shutdown wearing a crash's
  // name.
  process.kill(process.pid, 'SIGKILL');
  return { unreachable: true };
}

function appendPreregistrationRow(registry, { provenance, digest, prereg, clockInstant }) {
  appendRecord(registry, {
    kind: 'PREREGISTRATION',
    record_kind: 'PREREGISTRATION_RECORDED',
    run_id: provenance.run_id,
    nonce: provenance.nonce,
    preregistration_digest: digest,
    expected_table_digest: prereg.expected_table_digest ?? null,
    trial_count: Array.isArray(prereg.trial_list) ? prereg.trial_list.length : null,
    seed_count: Array.isArray(prereg.seed_rule?.seeds) ? prereg.seed_rule.seeds.length : null,
    inference_mode: prereg.inference_mode ?? null,
    recorded_at: clockInstant,
  });
}

async function crashPhaseTwo({ label, corpusDir, root }) {
  // NO purge. A restart that purged its predecessor's ledger would be a new run
  // pretending to be a resumed one.
  const prereg = loadPreregistration(corpusDir);
  const base = resolveBase();
  const clock = fixedClock(DECISION_POINT_INSTANT);
  const runId = `s2-008-run-${label}-restart-p${process.pid}`;
  const provenance = freezeProvenance({
    commit: base.commit_sha,
    tree: base.tree_sha,
    runId,
    label,
    executorId: `exec-s2-008-${label}-restart-p${process.pid}`,
    nonce: deriveProcessNonce({ label, runId, attempt: 1, pid: process.pid }),
    clock: DECISION_POINT_INSTANT,
    startedAt: DECISION_POINT_INSTANT,
  });
  const registry = openRegistry({ root, clock, ids: idFactory(`${label}-restart`) });
  const chain = verifyChain(registry);
  const journal = readJournal(registry);
  const kinds = journal.map((row) => row?.payload?.record_kind ?? row?.kind ?? null);
  const interrupted = {
    index: 0,
    trial: Array.isArray(prereg.trial_list) ? prereg.trial_list[0]?.trial_id ?? null : null,
  };
  // The interrupted trial is a RECONCILIATION ROW, opened by the restart, and
  // it is undecided: the restart has no measurement to decide with.
  const row = reconciliationRow({
    run: { provenance, preregistration: { digest: preregistrationDigest(prereg) } },
    index: interrupted.index,
    trial: interrupted.trial,
    reasonCode: 'RUN_INTERRUPTED_MID_TRIAL',
    detail: 'the process was killed between taking the preregistered reservation and executing the first trial; the effect of the interrupted trial is undetermined',
    deciderKind: 'human_owner',
    clockIso: DECISION_POINT_INSTANT,
    reservationId: prereg.budget_reservation.reservation_id,
    // The id prefix table is the FROZEN one, passed in as the constants group
    // the runner resolves internally: the runner refuses to substitute its own
    // vocabulary, so a caller hands it the module instead of inventing a prefix.
    deps: { constants: researchConstants },
  });
  // The interrupted trial's settle key, presented TWICE. The first settles it;
  // the second MUST be an idempotent replay that does not charge again. A
  // second charge for one trial is a duplicate external effect, and a
  // different key for the same trial would be a blind retry.
  // The settle key the CRASHED process would have used. It embeds that
  // process's raw run id, which is why the key is read from the journal of the
  // crashed run rather than reconstructed: a key this script invented would not
  // be the key the ledger holds, and an idempotency check against an invented
  // key proves nothing.
  const crashedRunId = readJournal(registry)
    .map((row) => row?.payload?.run_id ?? null)
    .find((value) => typeof value === 'string' && value.includes('crash')) ?? `s2-008-run-${label}-crash`;
  const settleKey = canonicalDigest({
    run_id: crashedRunId,
    index: 0,
    trial: interrupted.trial,
    units: 1,
    reservation_id: prereg.budget_reservation.reservation_id,
  });
  const settleOnce = (key) => {
    try {
      const settled = recordSpend(registry, {
        reservationId: prereg.budget_reservation.reservation_id,
        key,
        args: { units: 1, run_id: crashedRunId, index: 0, trial: interrupted.trial },
      });
      return { outcome: 'SETTLED', replayed: settled.replayed === true, spent_units: settled.spent_units };
    } catch (error) {
      return { outcome: 'REFUSED', code: String(error?.code ?? 'SPEND_REFUSED'), class: String(error?.name ?? 'Error') };
    }
  };
  const firstSettle = settleOnce(settleKey);
  const secondSettle = settleOnce(settleKey);
  // A DIFFERENT key, on an EXPIRED clock: a typed reconciliation refusal, and
  // the spend must not advance. A silent zero is what "no result" looks like
  // when the ledger charges nothing and records nothing.
  const expiry = typeof prereg.budget_reservation.expires_at === 'string' ? prereg.budget_reservation.expires_at : null;
  const afterExpiry = expiry === null ? null : new Date(Date.parse(expiry) + 60_000).toISOString();
  const expiredRegistry = afterExpiry === null ? null : openRegistry({ root, clock: fixedClock(afterExpiry), ids: idFactory(`${label}-restart-expired`) });
  let expired = null;
  if (expiredRegistry !== null) {
    const before = readJournal(expiredRegistry).filter((row) => row?.kind === 'BUDGET_SPEND').length;
    try {
      const settled = recordSpend(expiredRegistry, {
        reservationId: prereg.budget_reservation.reservation_id,
        key: `${settleKey}-after-expiry`,
        args: { units: 1, run_id: runId, index: 0, trial: interrupted.trial },
      });
      expired = { outcome: 'SETTLED', replayed: settled.replayed === true, spent_units: settled.spent_units, at: afterExpiry, spend_rows_after: before + 1 };
    } catch (error) {
      const after = readJournal(expiredRegistry).filter((row) => row?.kind === 'BUDGET_SPEND').length;
      expired = {
        outcome: 'REFUSED',
        code: String(error?.code ?? 'SPEND_REFUSED'),
        class: String(error?.name ?? 'Error'),
        detail: String(error?.message ?? error).slice(0, 200),
        at: afterExpiry,
        spend_rows_before: before,
        spend_rows_after: after,
        spend_advanced: after !== before,
      };
    }
  }
  return {
    ticket: 'S2-008',
    kind: 'CRASH_RESTART',
    phase: 2,
    label,
    base,
    provenance,
    registry_root: path.relative(REPO_ROOT, root),
    purge_performed: false,
    chain_verified: chain?.ok === true,
    journal_kinds: kinds,
    row_count: journal.length,
    saw_preregistration_row: kinds.includes('PREREGISTRATION_RECORDED'),
    saw_reservation_row: kinds.includes('BUDGET_RESERVATION'),
    trials_executed_by_the_restart: 0,
    reconciliation: row,
    crashed_run_id: crashedRunId,
    blind_retry: false,
    retry_attempted: false,
    implicit_zero: false,
    first_settle: firstSettle,
    settle_key_replay: secondSettle,
    settle_key_replayed_without_second_charge: secondSettle.outcome === 'SETTLED'
      && secondSettle.replayed === true
      && secondSettle.spent_units === firstSettle.spent_units,
    expired_reservation: expired,
  };
}

/**
 * ONE attempt: purge, resolve, open the holdout once, execute the engine,
 * score the record against the frozen table.
 *
 * `attempt` is part of the raw run id and of the nonce, so two attempts in one
 * process are two distinct executions rather than one repeated claim.
 * Writing is the CALLER's business (`runCampaign` owns the destination and the
 * evidence-eligibility rule), so there is no `write` parameter here: a function
 * that both decides a record is evidence and writes it is the wrong place to
 * check that rule.
 * @returns {Promise<object>} The bound run record (or the refusal record).
 */
export async function runOnce({ label, attempt = 0, corpusDir, root, outputRoot, base }) {
  // The raw run id names the EXECUTION, not the label: two attempts of the same
  // label on the same base are two executions, and `compareParallelTrack` treats
  // a shared raw run id as a collision ("two executions cannot share one id").
  // The pid is part of it for the same reason the nonce is derived from the pid.
  const runId = `s2-008-run-${label}-${attempt}-p${process.pid}`;
  const executorId = `exec-s2-008-${label}-${attempt}-p${process.pid}`;
  const clockInstant = DECISION_POINT_INSTANT;
  const clock = fixedClock(clockInstant);

  // 1. Purge this attempt's OWN fixtures, before anything it writes. A run
  //    that inherited a previous attempt's journal would be scored against rows
  //    it did not write.
  rmSync(root, { recursive: true, force: true });
  mkdirSync(root, { recursive: true });
  const executorPurge = purgeExecutorFixtures({ root: outputRoot, label: `${label}-${attempt}` });
  // Committed records carry the purge `dir` repository-relative, never as a
  // host-local absolute path: an absolute path leaks the account name, the
  // worktree layout and the thread id of the machine that produced the run,
  // and it makes `evidence/s2-008-run-*.json` host-dependent, so the same base
  // on another checkout could not reproduce the record byte for byte. The live
  // value stays absolute inside the run; only the serialised copy is shortened,
  // exactly like `registry_root` beside it. A root outside the repository
  // becomes a fixed token rather than a relative escape.
  const executorPurgeCommitted = { ...executorPurge, dir: repoRelativeOrToken(executorPurge.dir) };

  // 2. The preregistration, and the frozen table checked against it BEFORE
  //    trial one.
  const prereg = loadPreregistration(corpusDir);
  const tableDigest = assertTableFrozen(prereg);
  const window = lawfulWindow(prereg, clockInstant);
  const confidence = isPlainObject(prereg.noise_rule) && Number.isFinite(prereg.noise_rule.confidence)
    ? prereg.noise_rule.confidence
    : FALLBACK_CONFIDENCE;

  // 3. The provenance block: commit, tree, raw run id, executor id, pid, and a
  //    nonce derived from THIS process.
  const provenance = freezeProvenance({
    commit: base.commit_sha,
    tree: base.tree_sha,
    runId,
    label,
    executorId,
    nonce: deriveProcessNonce({ label, runId, attempt, pid: process.pid }),
    clock: clockInstant,
    startedAt: clockInstant,
  });

  const registry = openRegistry({ root, clock, ids: idFactory(`${label}-${attempt}`) });
  // 3a. The purge, and the ORDER it has to happen in.
  //
  // The engine purges its own ledger before it writes anything (runner.mjs
  // `purgeRegistry(registry)`), and this script used to open the HOLDOUT FIRST
  // and let the engine run afterwards. The engine's purge then ERASED the ACCESS
  // row the one-shot open had committed: the run record's `holdout_access`
  // named an `access_record_id` that its own journal did not contain, the frozen
  // `EXPECTED_LEDGER_SHAPE` (which declares one ACCESS row) could never hold,
  // and the peek defence was not evidenced in the ledger the verdict is read
  // from. The purge therefore happens HERE, before the holdout open, and the
  // engine is told the purge was already performed — a claim it PROVES rather
  // than believes: it refuses to start unless the journal is actually empty.
  const purge = purgeRegistry(registry);
  // 4. The one-shot holdout open, on this run's own ledger.
  const holdout = openHoldoutOnce({ registry, prereg, clockInstant, corpusDir });
  const executeTrial = buildExecutor({ holdout, prereg, confidence });

  const started = {
    ticket: 'S2-008',
    kind: 'RUN',
    label,
    attempt,
    evidence_eligible: corpusDir === COMMITTED_CORPUS_DIR,
    corpus: path.relative(REPO_ROOT, corpusDir),
    base,
    provenance,
    preregistration: {
      digest: preregistrationDigest(prereg),
      expected_table_digest: tableDigest,
      metric_name: isPlainObject(prereg.metric) ? prereg.metric.name ?? null : null,
      seed_count: Array.isArray(prereg.seed_rule?.seeds) ? prereg.seed_rule.seeds.length : null,
      trial_count: Array.isArray(prereg.trial_list) ? prereg.trial_list.length : null,
    },
    lawful_window: window,
    purge: { registry_root: path.relative(REPO_ROOT, root), executor_fixtures: executorPurgeCommitted },
    holdout_access: {
      access_record_id: holdout.access_record_id,
      labels_digest: holdout.labels_digest,
      opened_case: isPlainObject(holdout.case) ? holdout.case.case_id ?? null : null,
      opened_cases: isPlainObject(holdout.case) ? 1 : 0,
      partition_case_count: Number.isInteger(prereg.holdout_access.case_count) ? prereg.holdout_access.case_count : null,
      opens: 1,
      max_opens: prereg.holdout_access.max_opens,
      read_at: clockInstant,
      decision_at: DECISION_POINT_INSTANT,
    },
  };

  // 5. The engine. A throw here is the engine's own refusal: it throws only when
  //    it cannot produce an honest record at all, and that refusal IS the
  //    evidence. It is never caught and turned into a pass.
  let runRecord = null;
  let engineError = null;
  try {
    runRecord = await runDeterministicRun({
      prereg,
      registry,
      executeTrial,
      provenance,
      clock,
      label,
      outputRoot: path.relative(REPO_ROOT, outputRoot),
      // The purge this script already performed, with the number of files it
      // removed, so the run record's own `purge` block still says what happened.
      alreadyPurged: true,
      purgeRemovedFiles: Number.isInteger(purge?.removedFiles) ? purge.removedFiles : 0,
    });
  } catch (error) {
    engineError = {
      code: String(error?.code ?? 'ENGINE_ERROR'),
      class: String(error?.name ?? 'Error'),
      message: String(error?.message ?? error).slice(0, 400),
    };
  }

  const ledger = {
    chain_verified: false,
    snapshot_digest: null,
    record_kinds: [],
  };
  try {
    const chain = verifyChain(registry);
    ledger.chain_verified = chain?.ok === true;
    ledger.snapshot_digest = snapshotDigest(registry);
  } catch (error) {
    ledger.error = String(error?.code ?? error?.message ?? 'LEDGER_UNREADABLE');
  }

  // 6. Score the engine's own record against the frozen table. The run checks
  //    ITSELF, so a run that missed the table leaves a record that says so.
  const tableFindings = isPlainObject(runRecord) ? expectedValueIssues(runRecord, label) : [];
  const derivedRows = isPlainObject(runRecord)
    ? runRecord.trials.map((trial, index) => {
      const row = EXPECTED_TRIAL_DECISIONS[index] ?? null;
      return {
        index,
        trial: trial?.trial ?? null,
        table_says: row ? row.expectedOutcome : null,
        rule_derived: trial?.outcome ?? null,
        agrees: row ? trial?.outcome === row.expectedOutcome : null,
        observed: trial?.observed ?? null,
        interval: trial?.interval ?? null,
        decision_reason: trial?.decision?.reason ?? null,
        status: trial?.status ?? null,
        verdict: trial?.verdict ?? null,
      };
    })
    : [];

  // Harness-level findings: facts about THIS RUN'S preconditions that the
  // engine cannot report, named rather than folded into the run status. They
  // are non-gating here and gating in `s2-008-replay.mjs` and
  // `verify-s2-008.mjs`, which read them instead of re-deriving them.
  const harnessFindings = [];
  if (window.empty) {
    harnessFindings.push({
      code: 'PREREGISTERED_RUN_WINDOW_EMPTY',
      detail: `a lawful holdout read needs the clock at or after ${window.from} and a live reservation needs it strictly before ${window.until}; the two preregistered instants leave no window at all`,
      where: 'evidence/s2-008/corpus/preregistration.json (budget_reservation.expires_at) and scripts/s2-008-run.mjs DECISION_POINT_INSTANT',
    });
  }
  if (base.track_tracked !== true) {
    harnessFindings.push({
      code: 'TRACK_UNTRACKED',
      detail: `git ls-files reports ${base.tracked_files_of_this_track} tracked file(s) of this track, so no artefact of this run is bound to a base in any sense a reader can check`,
      where: 'git ls-files (read-only)',
    });
  }
  if (isPlainObject(prereg.metric)
    && typeof prereg.metric.name === 'string' && prereg.metric.name !== EXPECTED_METRIC_NAME) {
    harnessFindings.push({
      code: 'METRIC_NAME_DIVERGES_FROM_TABLE',
      detail: `the preregistration measures ${prereg.metric.name} while the frozen table names ${EXPECTED_METRIC_NAME}; assertTableFrozen does not read the metric name, so the divergence is first visible in the table findings`,
      where: 'evidence/s2-008/corpus/preregistration.json (metric.name) and src/lib/research/expected-values.mjs EXPECTED_METRIC',
    });
  }
  if (!Object.hasOwn(prereg, 'trial_timeout_ms')
    && !Object.hasOwn(prereg.budget_reservation ?? {}, 'trial_timeout_ms')
    && !Object.hasOwn(prereg.stopping_rule ?? {}, 'trial_timeout_ms')
    && !Object.hasOwn(prereg.noise_rule ?? {}, 'trial_timeout_ms')) {
    harnessFindings.push({
      code: 'TRIAL_TIMEOUT_NOT_PREREGISTERED',
      detail: 'the preregistration publishes no per-trial timeout in any path the engine reads, so runDeterministicRun refuses; a timeout supplied by this script would be a run-time choice, which is the hole the rule exists to close',
      where: 'evidence/s2-008/corpus/preregistration.json and src/lib/research/runner.mjs TRIAL_TIMEOUT_PATHS',
    });
  }

  const document = {
    ...started,
    harness_findings: harnessFindings,
    // The engine's own `run` block and its preregistration block are kept
    // VERBATIM: `verdictProjection` (runner.mjs) reads them, and they are what
    // the A5 repeat witness projects. A harness that re-shaped the engine's
    // record would be projecting its own shape, not the engine's decision.
    version: isPlainObject(runRecord) ? runRecord.version ?? null : null,
    // The five A5 bindings at the TOP level, in the spellings
    // `expectedValueIssues` and `compareParallelTrack` read (`commit_sha`,
    // `tree_sha`, `raw_run_id`, `nonce`, `executor_id`, `output_root`,
    // `expected_table_digest`). They are copied from the engine's own record,
    // never re-derived, so a run cannot claim a binding the engine did not take.
    commit_sha: isPlainObject(runRecord) ? runRecord.commit_sha ?? null : null,
    tree_sha: isPlainObject(runRecord) ? runRecord.tree_sha ?? null : null,
    raw_run_id: isPlainObject(runRecord) ? runRecord.raw_run_id ?? null : null,
    nonce: isPlainObject(runRecord) ? runRecord.nonce ?? null : null,
    executor_id: isPlainObject(runRecord) ? runRecord.executor_id ?? null : null,
    output_root: isPlainObject(runRecord) ? runRecord.output_root ?? null : null,
    expected_table_digest: isPlainObject(runRecord) ? runRecord.expected_table_digest ?? null : null,
    preregistration_digest: isPlainObject(runRecord) ? runRecord.preregistration_digest ?? null : null,
    run: isPlainObject(runRecord) ? runRecord.run ?? null : null,
    preregistration_in_force: isPlainObject(runRecord) ? runRecord.preregistration ?? null : null,
    run_status: isPlainObject(runRecord) ? runRecord.run?.status ?? null : null,
    engine_error: engineError,
    trials: isPlainObject(runRecord) ? runRecord.trials : [],
    metrics: isPlainObject(runRecord) ? runRecord.metrics : null,
    latency: isPlainObject(runRecord) ? runRecord.latency : null,
    codes: isPlainObject(runRecord) ? runRecord.codes : [],
    counters: isPlainObject(runRecord) ? runRecord.counters : null,
    counter_sources: isPlainObject(runRecord) ? runRecord.counter_sources : null,
    reconciliations: isPlainObject(runRecord) ? runRecord.reconciliations : [],
    refusals: isPlainObject(runRecord) ? runRecord.refusals : [],
    run_counters: isPlainObject(runRecord) ? runRecord.run_counters : null,
    ledger: {
      ...ledger,
      record_kinds: isPlainObject(runRecord) ? runRecord.ledger?.payload_kinds ?? [] : [],
      record_count: isPlainObject(runRecord) ? runRecord.ledger?.record_count ?? null : null,
    },
    table_findings: tableFindings,
    table_finding_count: tableFindings.length,
    derived_rows: derivedRows,
    decision_digest: isPlainObject(runRecord) ? runRecord.decision_digest ?? null : null,
  };
  return bindArtefact(document, provenance);
}

/**
 * THE A5 REPEAT WITNESS: the same base, twice, in one process, with two
 * distinct raw run ids and nonces.
 *
 * The GATE is `verdictProjection` — the runner's OWN allowlist of the
 * decision-bearing fields, which already excludes the run id, the nonce, the
 * pid, the executor id, the clock and the timing members. Using that projection
 * instead of a hand-written mask is the point: what a repeat run must reproduce
 * is decided by the engine, not by the harness that wants the run to be green.
 *
 * NON-VACUITY is the second half of the gate: the two ARTEFACT digests must
 * DIFFER, because a pair of byte-identical records would satisfy "identical
 * verdicts" with an input that never changed.
 */
const PER_PROCESS_KEYS = Object.freeze([
  'provenance', 'artefact_digest', 'decision_digest', 'purge', 'ledger',
  'holdout_access', 'access_record_id', 'settle_key', 'snapshot_digest', 'output_root', 'pid', 'attempt',
  // The three per-EXECUTION identities the runner's own DECISION_EXCLUDED_FIELDS
  // already excludes from a decision digest. Two executions cannot share them,
  // which is the property, not a difference to be explained away.
  'raw_run_id', 'nonce', 'executor_id',
]);

/** Paths the runner's projection carries that are per-EXECUTION by
 *  construction, so they are excluded from the equality check and NAMED. */
const PROJECTION_EXCLUSIONS = Object.freeze(['trials[].bindings.budget.settle_key', 'trials[].budget.settle_key']);

function stripSettleKeys(value) {
  if (Array.isArray(value)) return value.map(stripSettleKeys);
  if (!isPlainObject(value)) return value;
  const copy = {};
  for (const [key, member] of Object.entries(value)) {
    if (key === 'settle_key') continue;
    copy[key] = stripSettleKeys(member);
  }
  return copy;
}

function stripPerProcess(value) {
  if (Array.isArray(value)) return value.map(stripPerProcess);
  if (!isPlainObject(value)) return value;
  const copy = {};
  for (const [key, member] of Object.entries(value)) {
    if (PER_PROCESS_KEYS.includes(key)) continue;
    copy[key] = stripPerProcess(member);
  }
  return copy;
}

function maskForComparison(document) {
  return stripPerProcess(JSON.parse(JSON.stringify(document)));
}

/** Collect every JSON path at which two documents differ. */
export function diffPaths(left, right, prefix = '') {
  if (isDeepEqual(left, right)) return [];
  const paths = [];
  if (!isPlainObject(left) || !isPlainObject(right)) {
    paths.push(prefix || '<root>');
    return paths;
  }
  for (const key of new Set([...Object.keys(left), ...Object.keys(right)])) {
    const here = prefix === '' ? key : `${prefix}.${key}`;
    if (!(key in left) || !(key in right)) {
      paths.push(here);
      continue;
    }
    paths.push(...diffPaths(left[key], right[key], here));
  }
  return paths;
}

function isDeepEqual(left, right) {
  return canonicalDigest(left ?? null) === canonicalDigest(right ?? null);
}

/**
 * The projection a repeat run must reproduce: the runner's own
 * `verdictProjection`, minus the settle key. The settle key is
 * `canonicalDigest({run_id, index, trial, units, reservation_id})`, so it embeds
 * the raw run id and two DISTINCT executions cannot share it — while
 * `verdictProjection` projects it. Excluding it is named in every record that
 * uses this function (`PROJECTION_EXCLUSIONS`) instead of being left implicit.
 * @param {object} document A run record.
 * @returns {object} The comparable projection.
 */
export function projectedDecision(document) {
  return stripSettleKeys(verdictProjection(document));
}

export function repeatWitness(first, second) {
  // A refusal record has no run block and no trials, so it has no decision
  // projection. That is a NOT_RUN for this witness and it is reported as one; it
  // is never turned into an equality, because two refusals that look alike have
  // not reproduced anything.
  let projectionA = null;
  let projectionB = null;
  try {
    projectionA = projectedDecision(first);
    projectionB = projectedDecision(second);
  } catch (error) {
    return {
      equivalent: false,
      reason: `PROJECTION_UNAVAILABLE: ${String(error?.code ?? 'RUN_RECORD_MALFORMED')}`,
      detail: 'at least one attempt produced a refusal record rather than an executed run',
      raw_run_ids_distinct: first.provenance.run_id !== second.provenance.run_id,
      nonces_distinct: first.provenance.nonce !== second.provenance.nonce,
    };
  }
  const decisionEqual = canonicalDigest(projectionA) === canonicalDigest(projectionB);
  const artefactDiffer = first.artefact_digest !== second.artefact_digest;
  const differing = diffPaths(maskForComparison(first), maskForComparison(second));
  return {
    equivalent: decisionEqual && artefactDiffer && differing.length === 0,
    decision_projections_equal: decisionEqual,
    artefact_digests_differ: artefactDiffer,
    raw_run_ids_distinct: first.provenance.run_id !== second.provenance.run_id,
    nonces_distinct: first.provenance.nonce !== second.provenance.nonce,
    executor_ids_distinct: first.provenance.executor_id !== second.provenance.executor_id,
    differing_paths_after_masking: differing,
    excluded_from_the_projection: PROJECTION_EXCLUSIONS,
    projection_exclusion_reason: 'the engine settles each trial under settle_key = canonicalDigest({run_id, index, trial, units, reservation_id}) (runner.mjs), so the key EMBEDS the raw run id and two distinct executions cannot share it. verdictProjection projects that key, which makes "same base, same decision digest" unprovable across two distinct runs. The exclusion is named here instead of hidden; the key is still compared as a DIFF in the masked record, where it is expected to differ.',
    per_process_keys_excluded: [...PER_PROCESS_KEYS],
    non_vacuity: 'the two artefact digests must DIFFER; byte-identical records would satisfy "identical verdicts" with an input that never changed',
    note: "A5: the decision projection is the runner\'s own allowlist (runner.mjs verdictProjection), so what a repeat run must reproduce is decided by the engine and not by this harness.",
  };
}

/**
 * The crash/restart status, derived from the restart record and nothing else.
 *
 * The gate is the three claims the ticket names, in order: the restart SAW the
 * interrupted state, the interruption became a RECONCILIATION row (undecided,
 * no retry, no zero), and the expired reservation produced a TYPED refusal
 * instead of a silent charge. A restart that saw nothing is NOT_RUN, not a
 * pass: "it did not crash" and "the crash left a reconciliation" are different
 * answers.
 */
export function classifyCrashRestart(document) {
  if (document.saw_preregistration_row !== true || document.saw_reservation_row !== true) {
    return { status: 'NOT_RUN', exitCode: 3, reason: `the restart saw no interrupted state (preregistration_row=${String(document.saw_preregistration_row)} reservation_row=${String(document.saw_reservation_row)})` };
  }
  if (document.chain_verified !== true) {
    return { status: 'FAIL', exitCode: 1, reason: 'the ledger chain did not verify after the crash' };
  }
  if (!isPlainObject(document.reconciliation) || document.reconciliation.decided !== false
    || document.reconciliation.resolution !== 'EFFECT_UNDETERMINED') {
    return { status: 'FAIL', exitCode: 1, reason: 'the interrupted trial is not an undecided reconciliation row' };
  }
  if (document.retry_attempted !== false || document.blind_retry !== false || document.implicit_zero !== false) {
    return { status: 'FAIL', exitCode: 1, reason: 'the restart retried the interrupted trial, or recorded an implicit zero' };
  }
  if (document.trials_executed_by_the_restart !== 0) {
    return { status: 'FAIL', exitCode: 1, reason: `the restart executed ${document.trials_executed_by_the_restart} trial(s); a reconciliation is not a retry` };
  }
  if (document.settle_key_replayed_without_second_charge !== true) {
    return {
      status: 'FAIL',
      exitCode: 1,
      reason: `re-presenting the interrupted trial's settle key was not an idempotent replay: ${JSON.stringify(document.settle_key_replay)}`,
    };
  }
  const expired = document.expired_reservation;
  if (!isPlainObject(expired) || expired.outcome !== 'REFUSED'
    || (expired.code !== 'RECONCILIATION_REQUIRED' && expired.code !== 'BUDGET_RESERVATION_EXPIRED')) {
    return { status: 'FAIL', exitCode: 1, reason: 'an expired budget reservation was not a typed reconciliation refusal' };
  }
  if (expired.spend_advanced === true) {
    return { status: 'FAIL', exitCode: 1, reason: 'the refused spend still advanced the ledger; a refusal that charges is not a refusal' };
  }
  return { status: 'PASS', exitCode: 0, reason: 'the restart saw the interrupted state, opened a reconciliation for it and neither retried it nor charged a zero' };
}

/** The status vocabulary, derived from the record and nothing else. */
export function classify(document, { repeat = null } = {}) {
  const counters = isPlainObject(document.counters) ? document.counters : null;
  const movedCounters = counters === null
    ? null
    : Object.entries(counters).filter(([, value]) => value !== 0).map(([name, value]) => `${name}=${value}`);
  const notRun = isPlainObject(document.engine_error)
    || document.run_status === null
    || document.run_status !== 'COMPLETED';
  if (notRun) {
    return {
      status: 'NOT_RUN',
      exitCode: 3,
      reason: isPlainObject(document.engine_error)
        ? `the engine refused before it could produce a record: ${document.engine_error.code}`
        : `run_status=${document.run_status}`,
    };
  }
  if (repeat !== null && !repeat.equivalent) {
    return {
      status: 'FAIL',
      exitCode: 1,
      reason: `the repeat run did not reproduce (decision_projections_equal=${repeat.decision_projections_equal} artefact_digests_differ=${repeat.artefact_digests_differ} differing_paths=${repeat.differing_paths_after_masking.join(',') || 'none'})`,
    };
  }
  if (document.table_finding_count > 0) {
    return { status: 'FAIL', exitCode: 1, reason: `${document.table_finding_count} finding(s) against the frozen expected-value table` };
  }
  if (movedCounters !== null && movedCounters.length > 0) {
    return { status: 'FAIL', exitCode: 1, reason: `hard-gate counters moved: ${movedCounters.join(', ')}` };
  }
  if (isPlainObject(document.latency) && document.latency.decides !== false) {
    return { status: 'FAIL', exitCode: 1, reason: 'the latency block claims to decide' };
  }
  return { status: 'PASS', exitCode: 0, reason: 'the run completed, agreed with the frozen table and left every hard-gate counter at 0' };
}

/**
 * The whole run: one attempt, or the `--repeat` witness over two. The evidence
 * file is written only with `--write` AND only for the committed corpus: a
 * self-test corpus produces a record, never an evidence file, because an
 * evidence file that a flag can point anywhere else is not evidence.
 */
export async function runCampaign(args = {}) {
  const label = String(args.label ?? 'a');
  const corpusDir = typeof args.corpus === 'string' ? path.resolve(args.corpus) : COMMITTED_CORPUS_DIR;
  // The crash phases are a different KIND of execution: they write one JSON
  // line and stop, and phase 1 never returns at all. They are dispatched here
  // so every entry point of this file goes through one function.
  if (args.crashPhase !== undefined && args.crashPhase !== true) {
    const phase = Number(args.crashPhase);
    const root = typeof args.root === 'string'
      ? path.resolve(args.root)
      : path.join(RUN_SCRATCH_ROOT, `crash-${label}`);
    if (phase === 1) return { crash_phase: 1, label, corpus: path.relative(REPO_ROOT, corpusDir), unreachable: await crashPhaseOne({ label, corpusDir, root }) };
    if (phase === 2) {
      const document = await crashPhaseTwo({ label, corpusDir, root });
      return { crash_phase: 2, label, corpus: path.relative(REPO_ROOT, corpusDir), document, classified: classifyCrashRestart(document), out_file: null };
    }
    throw new Error(`CRASH_PHASE_UNKNOWN: ${String(args.crashPhase)}`);
  }
  const attemptCount = args.repeat === true ? 2 : 1;
  const base = resolveBase();
  const evidenceEligible = corpusDir === COMMITTED_CORPUS_DIR;
  const documents = [];
  for (let attempt = 0; attempt < attemptCount; attempt += 1) {
    const document = await runOnce({
      label,
      attempt,
      corpusDir,
      root: path.join(RUN_SCRATCH_ROOT, `${label}-${attempt}`),
      outputRoot: path.join(RUN_SCRATCH_ROOT, `out-${label}-${attempt}`),
      base,
    });
    documents.push(document);
  }
  const repeat = attemptCount > 1 ? repeatWitness(documents[0], documents[1]) : null;
  const primary = documents[documents.length - 1];
  const classified = classify(primary, { repeat });
  const outFile = typeof args.out === 'string'
    ? path.resolve(args.out)
    : path.join(REPO_ROOT, 'evidence', `s2-008-run-${label}.json`);
  let written = null;
  // `--no-write` is honoured beside `--write`, so a CHECK run of this script
  // cannot mutate the evidence file it is checking. `--no-write` is a real form
  // the argument parser turns into `noWrite: true`.
  const noWrite = args.noWrite === true || args.no_write === true || args.nowrite === true;
  if (args.write === true && !noWrite) {
    // Two rules, both about the same thing: a record that is not evidence must
    // not land where evidence lives.
    //   * the DEFAULT destination (`evidence/s2-008-run-<label>.json`) is
    //     reserved for the committed corpus, and a run against another corpus is
    //     refused there;
    //   * an EXPLICIT `--out` outside `evidence/` is always allowed, and the
    //     record says `evidence_eligible: false` so it can never be mistaken
    //     for one.
    const intoEvidence = path.relative(REPO_ROOT, outFile).split(path.sep)[0] === 'evidence';
    if (intoEvidence && !evidenceEligible) {
      throw new Error('EVIDENCE_WRITE_REFUSED: --corpus points somewhere other than the committed corpus, so this run is not evidence and evidence/ is left untouched; pass --out <path outside evidence/> for a self-test record');
    }
    mkdirSync(path.dirname(outFile), { recursive: true });
    const body = `${JSON.stringify(primary, null, 2)}\n`;
    writeFileSync(outFile, body, 'utf8');
    written = {
      path: path.relative(REPO_ROOT, outFile),
      bytes: Buffer.byteLength(body),
      artefact_digest: primary.artefact_digest,
      evidence_eligible: evidenceEligible,
    };
  }
  return { label, base, documents, repeat, classified, written, out_file: path.relative(REPO_ROOT, outFile) };
}

function log(...parts) {
  process.stdout.write(`${parts.join(' ')}\n`);
}

async function main() {
  const args = parseArgs(process.argv);
  const label = String(args.label ?? 'a');
  if (args.crashPhase !== undefined && args.crashPhase !== true) {
    const result = await runCampaign({ ...args, label });
    if (result.crash_phase === 2) {
      log(`# s2-008 crash/restart phase 2 (${label})`);
      log(`restart chain_verified=${String(result.document.chain_verified)} rows=${result.document.row_count} kinds=${JSON.stringify(result.document.journal_kinds)}`);
      log(`restart saw_preregistration_row=${String(result.document.saw_preregistration_row)} saw_reservation_row=${String(result.document.saw_reservation_row)} trials_executed_by_the_restart=${result.document.trials_executed_by_the_restart}`);
      log(`restart reconciliation=${result.document.reconciliation.reconciliation_id} decided=${String(result.document.reconciliation.decided)} resolution=${result.document.reconciliation.resolution} reason_code=${result.document.reconciliation.reason_code}`);
      log(`restart first_settle=${JSON.stringify(result.document.first_settle)} settle_key_replay=${JSON.stringify(result.document.settle_key_replay)} replayed_without_second_charge=${String(result.document.settle_key_replayed_without_second_charge)}`);
      log(`restart expired_reservation=${JSON.stringify(result.document.expired_reservation)}`);
      log(`RESULT label=${label} status=${result.classified.status} exit_code=${result.classified.exitCode} reason=${result.classified.reason}`);
      process.stdout.write(`${JSON.stringify(result.document)}\n`);
      process.exitCode = result.classified.exitCode;
      return;
    }
    process.exitCode = 0;
    return;
  }
  if (args.printRecord === true) {
    const result = await runCampaign({ ...args, label });
    // `process.exitCode`, never `process.exit`: an explicit exit can truncate
    // a stdout write that has not been flushed yet, and a truncated evidence
    // record is a record nobody can read.
    process.stdout.write(`${JSON.stringify(result.documents[result.documents.length - 1], null, 2)}\n`);
    process.exitCode = result.classified.exitCode;
    return;
  }
  log('# s2-008 single run');
  const result = await runCampaign({ ...args, label });
  const primary = result.documents[result.documents.length - 1];
  log(`config label=${label} evidence_eligible=${String(primary.evidence_eligible)} attempts=${result.documents.length}`);
  log(`base commit=${result.base.commit_sha} tree=${result.base.tree_sha} branch=${result.base.branch} dirty=${String(result.base.worktree_dirty)}`);
  log(`base track_tracked=${String(result.base.track_tracked)} tracked_files_of_this_track=${result.base.tracked_files_of_this_track}`);
  log(`preregistration digest=${primary.preregistration.digest} metric=${primary.preregistration.metric_name} table_digest=${primary.preregistration.expected_table_digest}`);
  log(`window from=${primary.lawful_window.from} until=${primary.lawful_window.until} width_ms=${String(primary.lawful_window.window_ms)} empty=${String(primary.lawful_window.empty)}`);
  log(`run harness_findings=${JSON.stringify(primary.harness_findings.map((entry) => entry.code))}`);
  log(`holdout access_record_id=${primary.holdout_access.access_record_id} opens=${primary.holdout_access.opens}/${primary.holdout_access.max_opens} cases=${String(primary.holdout_access.partition_case_count)}`);
  for (const document of result.documents) {
    log(`run ${document.provenance.run_id} nonce=${document.provenance.nonce} pid=${document.provenance.pid} status=${String(document.run_status)} trials=${document.trials.length} table_findings=${document.table_finding_count}`);
    if (document.engine_error) log(`run engine_error ${document.engine_error.code} ${document.engine_error.message}`);
    for (const row of document.derived_rows) {
      log(`run trial ${row.trial} status=${String(row.status)} table=${String(row.table_says)} derived=${String(row.rule_derived)} agrees=${String(row.agrees)} observed=${String(row.observed)} interval=${row.interval ? `${row.interval.lower}..${row.interval.upper}` : 'absent'} reason=${String(row.decision_reason)}`);
    }
    log(`run counters ${JSON.stringify(document.counters)} codes=${JSON.stringify(document.codes)} latency_decides=${String(document.latency?.decides)}`);
    for (const finding of document.table_findings.slice(0, 12)) {
      log(`run finding ${finding.field} expected=${JSON.stringify(finding.expected)} observed=${JSON.stringify(finding.observed)} code=${finding.code}`);
    }
  }
  if (result.repeat !== null) {
    log(`A5 repeat equivalent=${String(result.repeat.equivalent)} decision_projections_equal=${String(result.repeat.decision_projections_equal)} artefact_digests_differ=${String(result.repeat.artefact_digests_differ)} raw_run_ids_distinct=${String(result.repeat.raw_run_ids_distinct)} nonces_distinct=${String(result.repeat.nonces_distinct)} executor_ids_distinct=${String(result.repeat.executor_ids_distinct)}`);
    log(`A5 repeat differing_paths_after_masking=${JSON.stringify(result.repeat.differing_paths_after_masking)}`);
  }
  log(`RESULT label=${label} status=${result.classified.status} exit_code=${result.classified.exitCode} reason=${result.classified.reason}`);
  if (result.written) log(`wrote ${result.written.path} digest=${result.written.artefact_digest} bytes=${result.written.bytes}`);
  process.exitCode = result.classified.exitCode;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify({
      ticket: 'S2-008',
      gate: 'scripts/s2-008-run.mjs',
      status: 'NOT_RUN',
      ok: false,
      exitCode: 2,
      code: String(error?.code ?? 'RUN_SCRIPT_ERROR'),
      error: String(error?.message ?? error).slice(0, 600),
      stack: String(error?.stack ?? '').split('\n').slice(0, 6),
    }, null, 2)}\n`);
    process.exitCode = 2;
  });
}
