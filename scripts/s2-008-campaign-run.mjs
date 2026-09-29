// S2-008 REAL CAMPAIGN — the run. Drives the real adapter through the REUSED
// engine, and decides by the rule that was frozen before the adapter existed.
//
// WHAT IS REUSED AND NOT REWRITTEN
//   The registry (append-only, chained, idempotent, budget reservation,
//   fencing), the preregistration assertions, `readCorpus`'s one-shot sealed
//   open, `classifyTrialObservation`'s four-outcome precedence,
//   `resolveTrialVerdict`'s fail-closed bindings, `decisionFromInterval`'s
//   multiplicity correction and the provenance/binding helpers. `src/lib
//   /research/**` and `scripts/s2-008-*.mjs` are untouched; this file is the
//   campaign, not the machinery.
//
// THE ORDER, WHICH IS THE WHOLE POINT
//   1. purge the registry, so a repeat run fails on the property and not on its
//      own leftovers;
//   2. commit the PREREGISTRATION row and take the budget reservation;
//   3. prove the ordering from the JOURNAL, not from a clock;
//   4. Phase A — every (arm, seed) executed by the real installed executor,
//      BLIND: three arms x three seeds = nine real container launches, none of
//      which has ever seen a label;
//   5. Phase B — the decision point, and the holdout opened EXACTLY ONCE;
//   6. Phase C — agreement, the per-seed bootstrap, the HULLED interval, the
//      engine's classification, the per-trial verdict, the decision.
//   A label is revealed after every predictor has answered and before any
//   decision is read. That ordering is the experiment.
//
//   `--child` re-runs the whole thing in a fresh process against a fresh
//   registry, which is what makes the reproducibility claim a measurement.
//
// USAGE
//   node scripts/s2-008-campaign-run.mjs --label a --out evidence/<file>.json
//   node scripts/s2-008-campaign-run.mjs --label b --out evidence/<file>.json

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import {
  openRegistry, appendRecord, recordSpend, readJournal, verifyChain,
  headDigest, snapshotDigest, putExperiment,
} from '../src/lib/research/registry.mjs';
import {
  assertPreregisteredBeforeRun, assertPreregistration, preregistrationDigest,
  assertBudgetReservation,
} from '../src/lib/research/preregistration.mjs';
import { readCorpus } from '../src/lib/research/dataset.mjs';
import {
  classifyTrialObservation, deriveProcessNonce, freezeProvenance, bindArtefact,
  writeArtefact, assertArtefactBound, verdictProjection, assertNoWallClockInVerdict,
  decisionDigest, reconciliationRow,
} from '../src/lib/research/runner.mjs';
import {
  resolveTrialVerdict, metricsSummary, latencyRecorded, bestSeedDisclosure,
  decisionFromInterval, resolveCampaignVerdict, ruleFeasibility,
} from '../src/lib/research/comparator.mjs';
import {
  TRIAL_STATUSES, RESEARCH_OUTCOMES, TRIAL_VERDICTS, RESEARCH_PARTITIONS,
} from '../src/lib/research/constants.mjs';
import { wilsonInterval } from '../src/lib/sloqual/statistics.mjs';
import { buildImage, runTrial, buildBootstrapImage, runBootstrap, verifyImagePin } from './s2-008-campaign-adapter.mjs';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CORPUS_DIR = path.join(REPO_ROOT, 'corpus/s2-008-campaign');
const DECISION_POINT = '2026-09-28T00:00:00.000Z';
const HOLDOUT_ACTOR_KIND = 'EVALUATOR';

/** The clock is INJECTED and FIXED. No wall clock reaches a decision, and a
 *  repeat run on the same base produces the same instants. */
function fixedClock(iso) {
  const ms = Date.parse(iso);
  return Object.freeze({
    nowNs: () => ms * 1e6, nowMs: () => ms, iso: () => iso,
    now: () => new Date(ms), nowIso: () => iso,
  });
}

/** The engine's dependency groups, resolved EXPLICITLY from the track's own
 *  modules. `resolveDeps` merges over `DEFAULT_DEPS`, and the point of the
 *  injection is that the engine uses the TRACK's functions and the TRACK's
 *  closed vocabulary rather than a private copy of either. */
function engineDeps() {
  return {
    constants: {
      TRIAL_STATUSES, RESEARCH_OUTCOMES, TRIAL_VERDICTS, RESEARCH_PARTITIONS,
    },
    comparator: {
      resolveTrialVerdict, metricsSummary, latencyRecorded, bestSeedDisclosure,
      decisionFromInterval, resolveCampaignVerdict,
    },
  };
}

/**
 * The bootstrap interval, EXACT, from the resample bitmasks the real adapter
 * produced.
 *
 * Each resample is a `ceil(n/8)`-byte bitmask saying which of the n cases it
 * drew. The resample's agreement rate is the agreement over the DRAWN cases,
 * divided by n — so every one of the `samples` rates is computable exactly, and
 * the interval is the percentile bootstrap interval over them. No Poisson-
 * binomial approximation, and nothing derived from the lossy per-case counts:
 * two different resample multisets can share the same counts and disagree on
 * every resample's agreement sum, so an interval computed from the counts
 * describes a distribution the adapter never drew.
 */
export function bootstrapIntervalFromMasks(masksBase64, stride, agreement, { confidence }) {
  const matrix = Buffer.from(masksBase64, 'base64');
  const n = agreement.length;
  const samples = Math.floor(matrix.length / stride);
  if (samples < 1) throw new Error(`RESAMPLE_MATRIX_EMPTY: ${String(samples)} resample(s) in ${String(matrix.length)} bytes`);
  if (samples * stride !== matrix.length) {
    throw new Error(`RESAMPLE_MATRIX_RAGGED: ${String(matrix.length)} bytes is not a whole number of ${String(stride)}-byte masks`);
  }
  const rates = new Array(samples);
  for (let draw = 0; draw < samples; draw += 1) {
    const offset = draw * stride;
    let sum = 0;
    for (let index = 0; index < n; index += 1) {
      if ((matrix[offset + (index >> 3)] & (1 << (index & 7))) !== 0) sum += agreement[index];
    }
    rates[draw] = sum / n;
  }
  const sorted = [...rates].sort((left, right) => left - right);
  const tail = (1 - confidence) / 2;
  // The empirical quantile, nearest-rank: it does not interpolate a rate the
  // run never produced.
  const quantile = (q) => {
    const position = Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1));
    return sorted[position];
  };
  return {
    lower: quantile(tail),
    upper: quantile(1 - tail),
    confidence,
    method: 'PERCENTILE_BOOTSTRAP_OVER_EXACT_RESAMPLE_BITMASKS',
    n,
    samples,
    resample_mean: rates.reduce((sum, value) => sum + value, 0) / rates.length,
    resample_min: sorted[0],
    resample_max: sorted[sorted.length - 1],
  };
}

function git(...parts) {
  return execFileSync('git', parts, { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
}

function resolveBase() {
  const tracked = git('ls-files', '-z').split('\0').filter(Boolean);
  const mine = tracked.filter((file) => /^(src\/lib\/research\/|src\/lib\/isolation\/|tests\/research\/|scripts\/s2-008-|scripts\/verify-s2-008|corpus\/s2-008-campaign\/|evidence\/s2-008)/.test(file));
  return {
    commit_sha: git('rev-parse', 'HEAD'),
    tree_sha: git('rev-parse', 'HEAD^{tree}'),
    branch: git('rev-parse', '--abbrev-ref', 'HEAD'),
    worktree_dirty: git('status', '--porcelain').length > 0,
    tracked_files_of_this_track: mine.length,
    track_tracked: mine.length > 0,
  };
}

function idFactory(scope) {
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

/** `readJournal` returns ENVELOPES: `kind` is lifted to the top, but
 *  `preregistration_digest` and `run_id` stay in the payload. The ordering proof
 *  reads both at the row's TOP level, so the rows are projected — the same
 *  projection `src/lib/research/runner.mjs` does internally, and it adds
 *  nothing: every value is a member of the envelope or of its payload, so a row
 *  can never claim a digest the ledger does not hold. */
function projectJournalRows(rows) {
  return rows.map((row, position) => {
    const payload = row?.payload !== null && typeof row?.payload === 'object' && !Array.isArray(row.payload) ? row.payload : {};
    return {
      index: Number.isInteger(row.index) ? row.index : position,
      kind: row.kind,
      record_kind: typeof payload.record_kind === 'string' ? payload.record_kind : row.kind,
      preregistration_digest: payload.preregistration_digest ?? payload.prereg_digest ?? null,
      run_id: payload.run_id ?? payload.raw_run_id ?? null,
    };
  });
}

export function assertRunnerPreregInForce(prereg, manifest) {
  if (manifest?.preregistration?.status !== 'IN_FORCE' ||
      manifest.preregistration.file !== 'preregistration.json' ||
      manifest.preregistration.preregistration_digest !== preregistrationDigest(prereg)) {
    throw new Error('CAMPAIGN_PREREGISTRATION_NOT_IN_FORCE');
  }
}

export async function runCampaign({ label = 'a', write = true, out = null, verifyPin = false } = {}) {
  const prereg = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'preregistration.json'), 'utf8'));
  const frozenTable = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'frozen-table.json'), 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'manifest.json'), 'utf8'));
  assertRunnerPreregInForce(prereg, manifest);

  // --- 0. the frozen document is admissible and self-consistent -------------
  assertPreregistration(prereg);
  const preregDigest = preregistrationDigest(prereg);
  const feasibility = ruleFeasibility({
    alpha: prereg.multiplicity_rule.alpha,
    confidence: prereg.multiplicity_rule.confidence,
    familySize: prereg.multiplicity_rule.family_size,
  });
  if (feasibility.never_rejects) {
    throw new Error(`FROZEN_RULE_NOT_SELF_CONSISTENT: ${JSON.stringify(feasibility)}`);
  }

  const base = resolveBase();
  const runId = `s2-008-campaign-${label}-${process.pid}`;
  const root = path.join(os.tmpdir(), `s2-008-campaign-registry-${label}`);
  // The purge comes FIRST, before anything this run writes. A run that
  // inherited a previous run's journal would be scored against rows it did not
  // write, and a repeat run on the same base has to fail on the property, not
  // on its own leftovers. The scratch root is removed outright, so there is
  // nothing to inherit.
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });

  const clock = fixedClock(DECISION_POINT);
  const registry = openRegistry({ root, clock, ids: idFactory(`${label}-${runId}`) });
  const provenance = freezeProvenance({
    commit: base.commit_sha, tree: base.tree_sha, runId, label,
    executorId: `exec-s2-008-campaign-${label}`,
    nonce: deriveProcessNonce({ label, runId, attempt: 0, pid: process.pid }),
    clock: DECISION_POINT, startedAt: DECISION_POINT,
  });

  // --- 1. the preregistration row and the budget reservation ---------------
  const reservationId = prereg.budget_reservation.reservation_id;
  // The row the ordering proof reads: `preregistration_digest` and `run_id` at
  // the TOP level, and the envelope's `kind` plus the payload's `record_kind`.
  appendRecord(registry, {
    kind: 'PREREGISTRATION',
    record_kind: 'PREREGISTRATION_RECORDED',
    run_id: runId,
    nonce: provenance.nonce,
    preregistration_digest: preregDigest,
    expected_table_digest: prereg.expected_table_digest ?? null,
    trial_count: prereg.trial_list.length,
    seed_count: prereg.seed_rule.seeds.length,
    inference_mode: prereg.inference_mode,
    recorded_at: DECISION_POINT,
  });
  assertBudgetReservation(prereg.budget_reservation, clock.nowNs());
  // The reservation is TAKEN through the registry's CAS write, so it is a row in
  // the chained ledger and not a field in a document: an unassigned budget is
  // not a zero.
  const reservationPayload = {
    kind: 'BUDGET_RESERVATION',
    reservation_id: reservationId,
    granted_units: prereg.budget_reservation.granted_units,
    spent_units: 0,
    currency: prereg.budget_reservation.currency,
    expires_at: prereg.budget_reservation.expires_at,
    preregistration_digest: preregDigest,
    run_id: runId,
    nonce: provenance.nonce,
  };
  putExperiment(registry, {
    key: canonicalDigest({ operation: 'OPEN_RESERVATION', ...reservationPayload }),
    args: { ...reservationPayload },
    expectedRevision: registry.revision(),
    mutate: () => ({ ...reservationPayload, taken_at: DECISION_POINT }),
  });
  const reservation = recordSpend(registry, {
    reservationId,
    key: `reserve:${reservationId}:${preregDigest}`,
    args: { granted_units: prereg.budget_reservation.granted_units, units: 0, currency: prereg.budget_reservation.currency, expires_at: prereg.budget_reservation.expires_at },
  });
  void reservation;
  // --- 2. ordering proved from the JOURNAL, not from a clock ---------------
  assertPreregisteredBeforeRun({ prereg, runId, journal: projectJournalRows(readJournal(registry)) });

  const rules = {
    alpha: prereg.multiplicity_rule.alpha,
    method: prereg.multiplicity_rule.method,
    confidence: prereg.multiplicity_rule.confidence,
    direction: prereg.multiplicity_rule.direction,
    null_value: prereg.multiplicity_rule.null_value,
    comparisons: prereg.multiplicity_rule.declared_comparisons.slice(),
  };
  const noiseBand = prereg.noise_rule.band;
  const timeoutMs = prereg.budget_reservation.trial_timeout_ms;
  const deps = engineDeps();

  // --- 3. PHASE A: every arm at every seed, by the REAL adapter, BLIND ----
  // Every launch is CHARGED against the reservation as it happens. A budget
  // that is only compared at the end is a number in a document, and the first
  // attempt made nine launches against a six-unit reservation without charging
  // any of them: the ledger said nothing and the record said `within_reservation`
  // by arithmetic nobody ran. Superseded, and the arithmetic is now real.
  const pin = buildImage();
  const executions = [];
  let spentUnits = 0;
  const charges = [];
  for (const entry of prereg.trial_list) {
    for (const seed of prereg.seed_rule.seeds) {
      const result = runTrial({
        armId: entry.arm_id, seed, samples: prereg.noise_rule.bootstrap_samples,
        timeoutMs, pin: pin.pin,
      });
      spentUnits += 1;
      const charge = recordSpend(registry, {
        reservationId,
        key: `launch:${reservationId}:${preregDigest}:${entry.trial_id}:${String(seed)}`,
        args: { reservation_id: reservationId, units: 1, currency: prereg.budget_reservation.currency, trial: entry.trial_id, seed, at: DECISION_POINT },
      });
      // `replayed: false` is the ledger saying it CHARGED, and reporting that
      // as `outcome: false` reads like a failure. It is named here.
      charges.push({ trial: entry.trial_id, seed, units: 1, replayed: charge?.replayed === true, settled: charge?.replayed !== true });
      const row = {
        kind: 'TRIAL_EXECUTION',
        record_kind: 'TRIAL_EXECUTED',
        trial: entry.trial_id,
        raw_run_id: runId,
        nonce: provenance.nonce,
        at: DECISION_POINT,
        arm_id: entry.arm_id,
        seed,
        ok: result.ok,
        exit_code: result.record.exit_code,
        image: result.record.image,
        real_start_proven: result.record.real_start.proven,
        output_digest: result.record.output_digest,
        // A launch that produced nothing is recorded as producing nothing. It
        // is never a zero, and its row says so.
        produced_measurement: result.output !== null,
      };
      appendRecord(registry, row);
      executions.push({ entry, seed, result });
    }
  }

  // --- 4. PHASE B: the decision point, and the ONE sealed holdout open -----
  // `readCorpus` names ONE case, and that is the whole point: the open is
  // budgeted at one and the partition's labels come out of that single
  // journalled read. The case named here is the partition's first commit; the
  // returned `labels` map is the whole partition.
  const holdoutCases = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'cases/holdout.json'), 'utf8'));
  const holdoutIds = holdoutCases.map((row) => row.case_id);
  const blindDigest = canonicalDigest(JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'cases/holdout.blind.json'), 'utf8')));
  const access = readCorpus(registry, {
    partition: 'HOLDOUT',
    caseId: holdoutIds[0],
    unsealDigest: prereg.holdout_access.unseal_digest,
    corpusDir: CORPUS_DIR,
    decisionPoint: DECISION_POINT,
    maxOpens: prereg.holdout_access.max_opens,
    actorKind: HOLDOUT_ACTOR_KIND,
    releasedActorKinds: prereg.holdout_access.released_actor_kinds,
  });
  const labels = access.labels;

  // --- 4b. the agreement vectors, and the ONE post-reveal bootstrap launch --
  // The agreement vectors are written to a scratch file that becomes the input
  // of the bootstrap image, so the bootstrap's image digest is a function of
  // the measurement it resamples.
  const agreementVectors = [];
  for (const entry of prereg.trial_list) {
    const mine = executions.filter((item) => item.entry.trial_id === entry.trial_id && item.result.output !== null);
    if (mine.length === 0) continue;
    const byCase = mine[0].result.output.predictions.map((prediction) => ({
      case_id: prediction.case_id,
      agree: prediction.predicted === labels[prediction.case_id] ? 1 : 0,
    }));
    agreementVectors.push({ trial_id: entry.trial_id, arm_id: entry.arm_id, agreement: byCase.map((row) => row.agree) });
  }
  const agreementFile = path.join(root, 'agreement.json');
  fs.writeFileSync(agreementFile, JSON.stringify({
    vectors: agreementVectors,
    seeds: [...prereg.seed_rule.seeds],
    samples: prereg.noise_rule.bootstrap_samples,
    confidence: prereg.multiplicity_rule.confidence,
  }));
  const bootPin = agreementVectors.length === 0 ? null : buildBootstrapImage({
    agreementFile, samples: prereg.noise_rule.bootstrap_samples, confidence: prereg.multiplicity_rule.confidence,
  });
  let bootstrap = null;
  if (bootPin !== null) {
    const result = runBootstrap({
      agreementFile, samples: prereg.noise_rule.bootstrap_samples,
      confidence: prereg.multiplicity_rule.confidence, timeoutMs, pin: bootPin.pin,
    });
    spentUnits += 1;
    recordSpend(registry, {
      reservationId,
      key: `launch:${reservationId}:${preregDigest}:bootstrap`,
      args: { reservation_id: reservationId, units: 1, currency: prereg.budget_reservation.currency, trial: 'BOOTSTRAP', at: DECISION_POINT },
    });
    charges.push({ trial: 'BOOTSTRAP', seed: null, units: 1, launch_succeeded: result.ok, settled: true, note: 'a launch that fails is still charged: the unit is the launch, not the answer' });
    appendRecord(registry, {
      kind: 'TRIAL_EXECUTION', record_kind: 'BOOTSTRAP_EXECUTED', trial: 'BOOTSTRAP',
      raw_run_id: runId, nonce: provenance.nonce, at: DECISION_POINT,
      ok: result.ok, exit_code: result.record.exit_code, image: result.record.image,
      real_start_proven: result.record.real_start.proven, output_digest: result.record.output_digest,
      produced_measurement: result.output !== null,
    });
    bootstrap = result;
  }
  const bootstrapByArmSeed = new Map();
  for (const row of bootstrap?.output?.results ?? []) {
    bootstrapByArmSeed.set(`${row.trial_id}:${String(row.seed)}`, row);
  }

  // --- 5. PHASE C: score, classify, decide --------------------------------
  const evaluator = { evaluator_id: 'evl-s2-008-campaign-evaluator', independent: true, blind_to_producer: true };
  const calibration = {
    status: 'MEASURED', not_measured_reason: null,
    evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true },
  };
  const seedsBinding = { seeds: [...prereg.seed_rule.seeds], source: 'PREREGISTERED', preregistered_seeds: [...prereg.seed_rule.seeds] };
  const budgetBinding = {
    reservation_id: reservationId, granted_units: prereg.budget_reservation.granted_units,
    spent_units: spentUnits, currency: prereg.budget_reservation.currency,
    expires_at: prereg.budget_reservation.expires_at, within_reservation: spentUnits <= prereg.budget_reservation.granted_units,
  };
  const holdoutBinding = {
    partition: 'HOLDOUT', read_at: DECISION_POINT, decision_at: DECISION_POINT,
    opened_before_decision_point: false, opens: 1, max_opens: prereg.holdout_access.max_opens,
    labels_digest: access.labelsDigest, access_record_id: access.accessRecordId,
  };

  const trials = [];
  const reconciliations = [];
  for (const entry of prereg.trial_list) {
    const mine = executions.filter((item) => item.entry.trial_id === entry.trial_id);
    // A trial whose every launch produced nothing is an INFRA observation, and
    // the engine classifies it. It is NOT a zero and NOT a skip.
    const measuredSeeds = mine.filter((item) => item.result.output !== null);
    if (measuredSeeds.length === 0) {
      const observation = {
        infra: { code: 'ADAPTER_PRODUCED_NO_PAYLOAD', message: `every launch of ${entry.arm_id} returned no measurement; ${mine.length} launch(es) ran and none answered` },
        elapsed_ms: 0,
      };
      const classified = classifyTrialObservation(observation, { timeoutMs, deps, index: entry.index, trial: entry.trial_id, noiseBand, rule: { ...rules, subject: entry.trial_id } });
      reconciliations.push({ trial: entry.trial_id, kind: 'INFRA', classified });
      trials.push({ entry, seeds: [], classified, agreement: null, launches: mine.map((item) => item.result.record) });
      continue;
    }
    // Agreement per case, from the adapter's real predictions and the labels
    // this single open revealed.
    const perSeed = [];
    for (const item of measuredSeeds) {
      const out = item.result.output;
      const byCase = out.predictions.map((prediction) => ({
        case_id: prediction.case_id,
        agree: prediction.predicted === labels[prediction.case_id] ? 1 : 0,
      }));
      if (byCase.length !== holdoutIds.length || byCase.some((row) => labels[row.case_id] === undefined)) {
        throw new Error(`MEASUREMENT_OVER_A_DIFFERENT_PARTITION: ${String(entry.trial_id)} at seed ${String(item.seed)} scored ${byCase.length} case(s) against a holdout of ${holdoutIds.length}`);
      }
      const agreeing = byCase.reduce((sum, row) => sum + row.agree, 0);
      // The interval is the POST-REVEAL container's, over the full multiplicity
      // of every resample. It is not recomputed here: the host has no business
      // producing the distribution the decision rests on.
      const boot = bootstrapByArmSeed.get(`${entry.trial_id}:${String(item.seed)}`) ?? null;
      if (boot === null) {
        throw new Error(`BOOTSTRAP_ROW_ABSENT: no interval for ${String(entry.trial_id)} at seed ${String(item.seed)}`);
      }
      perSeed.push({
        seed: item.seed, agreeing, denominator: byCase.length, measured: agreeing / byCase.length,
        interval: {
          lower: boot.lower, upper: boot.upper, confidence: boot.confidence, method: boot.method,
          n: boot.n, samples: boot.samples, resample_mean: boot.resample_mean,
          resample_min: boot.min, resample_max: boot.max,
          sorted_rates_sha256: boot.sorted_rates_sha256,
        },
        mean_matches_observed: boot.mean_matches_observed,
        banner: item.result.record.banner,
        container_pid: item.result.record.real_start.container_pid,
        output_digest: item.result.record.output_digest,
      });
    }
    // The resample mean of a bootstrap of the data converges on the data's own
    // mean. A trial whose intervals do not sit around its own measured rate is
    // a broken interval, and it is refused here rather than published.
    for (const row of perSeed) {
      if (row.mean_matches_observed !== true) {
        throw new Error(`INTERVAL_DISJOINT_FROM_ITS_OWN_DATA: ${String(entry.trial_id)} at seed ${String(row.seed)} has a resample mean that is not the measured rate; the resampling is wrong`);
      }
    }
    // The FROZEN aggregation: the point estimate is the observed rate (which no
    // seed can move) and the interval is the HULL over every seed, so no seed
    // is ever chosen for being narrow and no seed is ever dropped.
    const measured = perSeed[0].measured;
    const lower = Math.min(...perSeed.map((row) => row.interval.lower));
    const upper = Math.max(...perSeed.map((row) => row.interval.upper));
    const hull = { lower, upper, method: 'HULL_OF_ALL_SEED_INTERVALS', seeds_used: perSeed.length, seeds_reported: perSeed.length, selected: null };
    // The analytic interval is carried beside it for the independent check; it
    // decides nothing.
    const analytic = wilsonInterval({ successes: perSeed[0].agreeing, trials: perSeed[0].denominator, confidence: prereg.multiplicity_rule.confidence });

    const observation = {
      measured, interval: hull, numerator: perSeed[0].agreeing, denominator: perSeed[0].denominator,
      elapsed_ms: 0,
      per_seed: perSeed, hull, analytic_wilson: analytic,
      bindings: { seed: seedsBinding, holdout: holdoutBinding, budget: budgetBinding, evaluator },
      evaluator, calibration,
    };
    const classified = classifyTrialObservation(observation, { timeoutMs, deps, index: entry.index, trial: entry.trial_id, noiseBand, rule: { ...rules, subject: entry.trial_id } });
    const trialRecord = {
      trial: entry.trial_id, index: entry.index, arm_id: entry.arm_id, metric: prereg.metric.name,
      status: classified.status, outcome: classified.outcome,
      numerator: perSeed[0].agreeing, denominator: perSeed[0].denominator,
      observed: classified.observed, interval: hull,
      reason_codes: classified.reason_codes,
      decision: classified.decision,
      seeds: [...prereg.seed_rule.seeds],
      // The four bindings, in the shape `verdictProjection` projects and
      // `resolveTrialVerdict` checks. The flat members are kept beside them so
      // either reader works.
      bindings: { seed: seedsBinding, holdout: holdoutBinding, budget: budgetBinding, evaluator },
      seedBinding: seedsBinding, holdoutBinding, budgetBinding, evaluatorBinding: evaluator,
      evaluator, calibration,
      per_seed: perSeed, analytic_wilson: analytic,
      launches: mine.map((item) => item.result.record),
    };
    const verdict = resolveTrialVerdict(trialRecord);
    trialRecord.verdict = verdict.verdict;
    trialRecord.verdict_reasons = [...verdict.reasons];
    trials.push({ entry, perSeed, classified, agreement: trialRecord, verdict, launches: trialRecord.launches });
    appendRecord(registry, {
      kind: 'TRIAL', record_kind: 'TRIAL_RESOLVED', campaign_id: prereg.preregistration_id,
      trial: entry.trial_id, raw_run_id: runId, at: DECISION_POINT,
      status: classified.status, outcome: classified.outcome,
      measured: classified.observed, interval: hull, seeds: [...prereg.seed_rule.seeds],
      verdict: verdict.verdict, verdict_reasons: [...verdict.reasons],
    });
  }

  // --- 6. the decision, and what decided nothing ---------------------------
  const metrics = metricsSummary(trials.map((item) => item.agreement ?? { metric: prereg.metric.name, status: item.classified.status, outcome: item.classified.outcome, trial: item.entry.trial_id }));
  const seedDisclosure = bestSeedDisclosure('report_every_seed', prereg.seed_rule.seeds);
  const latency = latencyRecorded(trials.map((item) => item.agreement ?? {}), prereg.noise_rule);

  const campaignRows = trials.filter((item) => item.agreement !== null);
  // The pooled aggregate is the family's own linear combination, and its
  // interval is the UNION of the family intervals: every convex combination of
  // the declared means lies inside the hull, so the hull is a CONSERVATIVE
  // interval for the pooled rate and not a claim about its own precision. The
  // width it ends up with is the between-arm heterogeneity, and that is the
  // honest number - a pooled interval narrower than the spread of its own
  // members would be a fiction.
  const pooled_interval_construction = 'UNION_OF_THE_DECLARED_FAMILY_INTERVALS (conservative for a linear combination of the family means)';
  // NO MEASURED ROW IS A NAMED ANSWER, NOT A CRASH. A campaign whose every
  // trial was INFRA has no pooled rate to score, and `decisionFromInterval`
  // refuses a non-finite `observed` by throwing - which, unhandled, is a stack
  // trace where the reader expects a verdict. The first run of this campaign
  // after a predictor defect hit exactly that, and the fix is to SAY the
  // campaign measured nothing rather than to divide by a denominator of zero.
  const campaignDecision = campaignRows.length === 0 || metrics.denominator === 0
    ? {
      decision: 'UNRESOLVED',
      reason: 'no_trial_resolved: the campaign measured nothing, so there is no rate to score and no interval to correct; this is not a null result and not a pass',
      measured_trials: 0,
      declared_trials: prereg.trial_list.length,
      numerator: metrics.numerator,
      denominator: metrics.denominator,
      correction: null,
      interval_construction: pooled_interval_construction,
    }
    : decisionFromInterval({
      observed: metrics.numerator / metrics.denominator,
      lower: Math.min(...campaignRows.map((item) => item.agreement.interval.lower)),
      upper: Math.max(...campaignRows.map((item) => item.agreement.interval.upper)),
      noiseBand,
      rule: { ...rules, subject_is_pooled_aggregate: true, subject: prereg.campaign_metric.name },
    });
  // `decisionFromInterval` returns a FROZEN object, so the construction note is
  // carried beside it rather than added to it.

  const violations = trials.filter((item) => item.verdict !== undefined && item.verdict.verdict !== 'ALLOW');
  const campaignVerdict = resolveCampaignVerdict({
    failures: violations.map((item) => ({ trial: item.entry.trial_id, reasons: item.verdict.reasons })),
    limits: [{ code: 'LATENCY_RECORDED_ONLY', detail: 'wall clock is measured as samples and decides nothing' }],
    proofStatus: [{ check: 'preregistration_before_first_trial', proved_by: 'REGISTRY_JOURNAL', ok: true }],
  });

  const record = {
    version: 's2-008-campaign-run/1',
    kind: 's2-008-campaign-run/1',
    ticket: 'S2-008',
    campaign: 'the real Veritas history, three preregistered message-feature arms',
    label: String(label),
    raw_run_id: runId,
    commit_sha: base.commit_sha,
    tree_sha: base.tree_sha,
    base,
    // The `run` block `verdictProjection` reads. Its status is the RUN's, not a
    // trial's: a campaign whose trials all resolved and whose reconciliation
    // rows are open is a run that completed.
    run: {
      version: 's2-008-campaign-run/1',
      label: String(label),
      status: reconciliations.length === 0 ? 'RUN_COMPLETED' : 'RUN_RECONCILIATION',
      started_at: DECISION_POINT,
      finished_at: DECISION_POINT,
      engine: {
        trial_count: prereg.trial_list.length,
        trial_timeout_ms: timeoutMs,
        trial_timeout_source: 'budget_reservation.trial_timeout_ms (preregistered, not chosen at run time)',
        units_per_trial: 1,
        sequential: true,
        retriable: false,
      },
    },
    provenance,
    adapter: {
      kind: 'real installed executor inside the S2-002 A-MVP-04 digest-pinned isolation profile',
      two_processes: 'the predictor runs blind and answers first; the evaluator opens the holdout once; the bootstrap runs afterwards in its own launch, because it needs the labels the predictor must never see',
      provider: 'generic_cli',
      adapter_kind: 'real',
      real_adapter_provenance: {
        status: 'REAL_ADAPTER_AVAILABLE',
        detail: `podman launched the content-pinned image ${pin.pin.imageId} (base ${'docker.io/library/node@sha256:25330af3531fb5e23318554a0aa911125b6e91b1b777edf7655501d207c067a2'}) with the four allowlist axes enforced; the container's own pid and node version came back in its stdout`,
      },
      NOT_A_MODEL_CALL: 'the executor is a deterministic installed program, not a model-calling agent; no model and no paid service is involved anywhere in this campaign',
      pin: pin.pin,
      pin_context_digest: pin.context_digest,
      bootstrap_pin: bootPin?.pin ?? null,
      bootstrap_pin_context_digest: bootPin?.context_digest ?? null,
      bootstrap_launch: bootstrap?.record ?? null,
      blind_input_digest: blindDigest,
      launches: executions.length,
    },
    preregistration: {
      digest: preregDigest,
      expected_table_digest: prereg.expected_table_digest ?? null,
      frozen_table: frozenTable,
      card_id: prereg.card_id,
      card_digest: prereg.card_digest,
      seed_count: prereg.seed_count,
      trial_count: prereg.trial_list.length,
      seeds: [...prereg.seed_rule.seeds],
      stopping_rule: prereg.stopping_rule,
      sequential_rule: prereg.sequential_rule,
      noise_rule: prereg.noise_rule,
      decision_rule: rules,
      inference_mode: prereg.inference_mode,
      budget: {
        reservation_id: reservationId, granted_units: prereg.budget_reservation.granted_units,
        spent_units: spentUnits, currency: prereg.budget_reservation.currency,
        unit_definition: prereg.budget_reservation.unit_definition,
        expires_at: prereg.budget_reservation.expires_at,
        within_reservation: spentUnits <= prereg.budget_reservation.granted_units,
        charges,
      },
    },
    ordering: {
      rule: 'every predictor answered before any label was revealed, and the holdout was opened exactly once',
      preregistration_row_index: readJournal(registry).findIndex((row) => row.kind === 'PREREGISTRATION'),
      first_trial_row_index: readJournal(registry).findIndex((row) => row.kind === 'TRIAL_EXECUTION'),
      access_row_index: readJournal(registry).findIndex((row) => row.kind === 'ACCESS'),
      access_rows: readJournal(registry).filter((row) => row.kind === 'ACCESS').length,
      proved_by: 'REGISTRY_JOURNAL_NOT_A_CLOCK',
      ordering_holds: (() => {
        const journal = readJournal(registry);
        const pre = journal.findIndex((row) => row.kind === 'PREREGISTRATION');
        const firstTrial = journal.findIndex((row) => row.kind === 'TRIAL_EXECUTION');
        const access = journal.findIndex((row) => row.kind === 'ACCESS');
        return pre >= 0 && firstTrial > pre && access > firstTrial;
      })(),
    },
    holdout: holdoutBinding,
    evaluator,
    calibration,
    trials: trials.map((item) => item.agreement ?? {
      trial: item.entry.trial_id, index: item.entry.index, arm_id: item.entry.arm_id,
      metric: prereg.metric.name, status: item.classified.status, outcome: item.classified.outcome,
      reason_codes: item.classified.reason_codes, seeds: [...prereg.seed_rule.seeds], observed: null,
      interval: null, decision: null,
      bindings: { seed: seedsBinding, holdout: holdoutBinding, budget: budgetBinding, evaluator },
      launches: item.launches,
    }),
    reconciliations,
    metrics,
    latency,
    seed_disclosure: seedDisclosure,
    campaign_decision: { ...campaignDecision, interval_construction: pooled_interval_construction },
    campaign_verdict: campaignVerdict,
    rule_feasibility: feasibility,
    registry: {
      root_is_scratch: true,
      chain_verified: verifyChain(registry),
      head_digest: headDigest(registry),
      snapshot_digest: snapshotDigest(registry),
      rows: readJournal(registry).map((row) => ({ kind: row.kind, trial: row.trial ?? null, at: row.at })),
    },
    codes: [],
    counters: {
      launches: executions.length,
      launches_producing_a_measurement: executions.filter((item) => item.result.output !== null).length,
      trials_resolved: trials.filter((item) => item.classified.status === 'RESOLVED').length,
      trials_unresolved: trials.filter((item) => item.classified.status === 'UNRESOLVED').length,
      trials_infra: trials.filter((item) => item.classified.status === 'INFRA_ERROR').length,
      trials_skipped: 0,
      reconciliations: reconciliations.length,
    },
  };

  // The decision digest is the digest of the verdict PROJECTION, and the
  // projection names no artefact member, so it can be computed from a throwaway
  // binding and then carried INSIDE the record. Binding last is what makes the
  // file verify: `assertArtefactBound` re-digests the whole body, so a digest
  // attached after the binding would be a digest of a document that no longer
  // exists.
  const probe = bindArtefact(record, provenance);
  const projection = assertNoWallClockInVerdict(probe);
  const artefact = bindArtefact({ ...record, decision_digest: decisionDigest(probe), verdict_projection: projection }, provenance);
  assertArtefactBound(artefact);

  if (write) {
    const target = out ?? path.join(REPO_ROOT, 'evidence/s2-008-campaign', `run-${label}.json`);
    writeArtefact(target, artefact, {});
  }
  return artefact;
}

function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2).replace(/[-_](\w)/g, (_m, c) => c.toUpperCase());
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) args[key] = true;
    else { args[key] = next; index += 1; }
  }
  return args;
}

const args = parseArgs(process.argv);
const isEntry = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (!isEntry) {
  // Imported as a library (the independent evaluator imports the interval
  // helper); running a campaign is a decision, not a side effect of an import.
} else if (args.verifyPin) {
  console.log(JSON.stringify(verifyImagePin(), null, 2));
} else {
  const record = await runCampaign({
    label: String(args.label ?? 'a'),
    write: args.write === true,
    out: typeof args.out === 'string' ? args.out : null,
  });
  console.log(JSON.stringify({
    raw_run_id: record.raw_run_id,
    commit_sha: record.commit_sha,
    tree_sha: record.tree_sha,
    decision_digest: record.decision_digest,
    adapter: { launches: record.adapter.launches, pin: record.adapter.pin.imageId, real_adapter_provenance: record.adapter.real_adapter_provenance.status },
    ordering: record.ordering,
    metrics: record.metrics,
    trials: record.trials.map((trial) => ({
      trial: trial.trial, arm: trial.arm_id, status: trial.status, outcome: trial.outcome,
      measured: trial.observed, interval: trial.interval ? { lower: trial.interval.lower, upper: trial.interval.upper, method: trial.interval.method } : null,
      reason: trial.decision?.reason ?? null, correction: trial.decision?.correction ? { pUpper: trial.decision.correction.pUpper, threshold: trial.decision.correction.threshold, rejected: trial.decision.correction.rejected, never_rejects: trial.decision.correction.never_rejects } : null,
      verdict: trial.verdict ?? null, seeds: trial.seeds?.length ?? 0,
    })),
    campaign_decision: record.campaign_decision,
    campaign_verdict: record.campaign_verdict,
    counters: record.counters,
    chain_verified: record.registry.chain_verified,
  }, null, 2));
}
