// S2-008 REAL CAMPAIGN — STEP 1: the freeze. Run BEFORE any adapter execution.
//
// WHAT THIS STEP IS ALLOWED TO SEE
//   The DEV partition (the oldest 75% of the real history) and the IDENTITY of
//   the holdout commits. It computes the frozen baseline, the design-time
//   precision floor and the whole decision rule from the dev partition alone.
//   It NEVER computes an arm's holdout agreement, and it never runs the
//   predictor: the holdout case file it writes carries the real label and the
//   real subject, with an EMPTY agreement map, so no outcome exists anywhere
//   before the preregistration is sealed.
//
// THE REAL PROJECT
//   Veritas, this checkout, its real git history. 502 real commits, real
//   messages, real trees. Nothing here is authored: the labels come from
//   `git show --name-only` and the messages from `git log`.
//
// THE LABEL IS MESSAGE-INDEPENDENT
//   A commit is MAJOR iff its diff touches >= 1 path under src/lib/,
//   contracts/ or migrations/. The rule never reads the message, which is
//   what makes "does the message predict the change" a question with an
//   answer nobody wrote down in advance.
//
//   `--selftest` proves it: every dev commit is re-labelled after its subject
//   is replaced by a constant, and the labels must be byte-identical.
//
// USAGE
//   node scripts/s2-008-campaign-prepare.mjs            # write the corpus
//   node scripts/s2-008-campaign-prepare.mjs --selftest  # prove the above
//   node scripts/s2-008-campaign-prepare.mjs --check     # re-derive, compare

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import {
  assertPreregistration,
  assertBudgetReservation,
  assertResearchContract,
  createSourceLedgerEntry,
  assertSourceLedger,
  sourceAnchorDigest,
  preregistrationDigest,
  isResearchContractValid,
  researchContractErrors,
  SOURCE_LEDGER_KIND,
  createSupersession,
  assertSupersession,
  SUPERSESSION_KIND,
} from '../src/lib/research/index.mjs';
import { ruleFeasibility } from '../src/lib/research/comparator.mjs';
import { wilsonInterval } from '../src/lib/sloqual/statistics.mjs';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CORPUS_DIR = path.join(REPO_ROOT, 'corpus/s2-008-campaign');

// --- the design, frozen as constants in the source so a reader sees the rule ---
// The commit that froze the FIRST preregistration, before any arm had been run.
// The superseded document is recovered from it, so the supersession preserves
// the old bytes exactly rather than a re-typed copy of them.
export const FREEZE_COMMIT = '2e684230a938cd00a54c30d1bcad0db49d432afc';

// The contract bounds a supersession reason at 240 characters, so the reason is
// a statement and the full account lives in the report and in the ledger entry.
export const SUPERSESSION_REASON = 'two apparatus defects, no effect: the resampler collapsed bootstrap multiplicity (a 115/126 rate returned centred at 0.578), and 9 launches ran against an uncharged 6-unit budget. The rule, band, seeds and baseline are unchanged.';

export const SUPERSESSION_ACCOUNT = [
  'Two defects in the MEASUREMENT APPARATUS, found by running the first campaign, and neither of them an effect:',
  '(1) the resampler encoded each bootstrap resample as a membership bitmask, which collapses multiplicity, so a case drawn three times contributed once. Measured on the aborted run: an observed rate of 115/126 = 0.9127 came back with a resample mean of 0.5779, a ratio of 0.633 = 1 - e^-1, which is the expected fraction of DISTINCT cases drawn in 126 draws with replacement. Every interval that run produced described a distribution the adapter never drew, so the run carried no effect size to be outcome-driven;',
  '(2) the budget reserved 6 units of one isolated executor launch each and the run made 9 launches while charging none of them, so the ledger carried a budget that was neither enforced nor transparent.',
  'The correction moves the resampling into a second, post-reveal launch (it needs the agreement vector, and the predictor must never see a label), carries every resample with its full multiplicity, refuses a trial whose resample mean does not sit at its own measured rate, charges every launch against the reservation as it happens, and raises the ceiling to 12 to cover the work the preregistration itself enumerates.',
  'WHAT DID NOT CHANGE, and had to not: the question, the card, the metric, the dev-measured baseline, the noise band, the seed set and its HULL rule, the family size, alpha, the derived confidence, the direction, the trial list and the one-shot holdout access. The band is the design-time precision floor and was not moved to make an arm clear it.',
].join(' ');

export const SOURCE = Object.freeze({
  project: 'Veritas',
  kind: 'real repository history, read from the local checkout with git',
  path_in_repository: '.',
  // THE PIN. The corpus is a function of THIS commit, never of HEAD.
  //
  // The first attempt read `git log --reverse HEAD` and the digests moved the
  // moment the freeze itself was committed — the corpus was a function of the
  // act of freezing it, which is not a corpus, it is a moving target. A real
  // campaign's data has to be the same bytes on every host and after every
  // later commit, and pinning to a named ancestor is the only way to get that.
  // `1324318` is the acceptance base: the mechanics merge plus its reseal, and
  // the commit BEFORE any campaign artefact existed.
  pinned_commit: '13243186b1573398fc327e245ebd2e5a90a2ced0',
  label_rule: 'MAJOR iff the commit diff touches >= 1 path under src/lib/, contracts/ or migrations/; the rule never reads the commit message',
  split_rule: 'temporal: the oldest 75% of `git log --reverse <pinned_commit>` is the dev partition (PRIMARY), the newest 25% is the holdout (HOLDOUT)',
  holdout_fraction: 0.25,
  major_prefixes: Object.freeze(['src/lib/', 'contracts/', 'migrations/']),
});

export const ARMS = Object.freeze([
  Object.freeze({
    trial_id: 'trl-s2-008c-01',
    arm_id: 'arm-scope-present',
    rule: 'predict MAJOR iff the subject matches /^[a-z]+(\\([^)]*\\))?!?:/ (a conventional-commit subject carrying a scope)',
    predict: (subject) => (/^[a-z]+(\([^)]*\))?!?:/.test(subject) ? 'MAJOR' : 'MINOR'),
  }),
  Object.freeze({
    trial_id: 'trl-s2-008c-02',
    arm_id: 'arm-type-feat-fix',
    rule: 'predict MAJOR iff the subject type is feat or fix',
    predict: (subject) => (/^(feat|fix)(\([^)]*\))?!?:/.test(subject) ? 'MAJOR' : 'MINOR'),
  }),
  Object.freeze({
    trial_id: 'trl-s2-008c-03',
    arm_id: 'arm-type-chore',
    rule: 'predict MINOR iff the subject type is chore, else predict MAJOR',
    predict: (subject) => (/^chore(\([^)]*\))?!?:/.test(subject) ? 'MINOR' : 'MAJOR'),
  }),
]);

// The seed SET. Three seeds, declared here, before any run: a bootstrap seed is
// a real stochastic step inside the real adapter, and the set is a set.
export const SEEDS = Object.freeze([20260926, 20260927, 20260928]);
export const BOOTSTRAP_SAMPLES = 2000;
export const ALPHA = 0.05;
export const FAMILY_SIZE = ARMS.length;
// DERIVED, never typed: with alpha 0.05 over a family of 3, a comparison's
// worst-case p bound is 1 - c, and the rule can only reject while
// 1 - c <= alpha/m. The fixture's first delivery typed 0.95 and could therefore
// never reject. Confidence is the arithmetic, so it is written as the
// arithmetic and the impossibility is checked by ruleFeasibility below.
export const CONFIDENCE = 1 - ALPHA / FAMILY_SIZE;

// The decision instant and the budget window. Both are instants, not durations
// chosen at run time: the holdout is lawful from the decision point, and the
// reservation is live strictly before its expiry.
export const DECISION_POINT = '2026-09-28T00:00:00.000Z';
export const RESERVATION_EXPIRES = '2026-09-28T23:59:59.000Z';
export const PER_TRIAL_TIMEOUT_MS = 120_000;

function git(...parts) {
  return execFileSync('git', parts, { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 1 << 30 }).trim();
}

/** The REAL history. `git log --reverse` gives oldest-first, which is what the
 *  temporal split is defined on, and it reads the PINNED commit, so the corpus
 *  is the same bytes whatever this repository's HEAD has become since. */
export function readRealHistory() {
  const lines = git('log', '--reverse', '--format=%H%x1f%ct%x1f%s', SOURCE.pinned_commit).split('\n').filter(Boolean);
  return lines.map((line) => {
    const [sha, ct, subject] = line.split('\x1f');
    return { sha, committed_at: Number(ct), subject };
  });
}

/** The label. A function of the TREE only. */
export function labelOfCommit(sha) {
  const files = git('show', '--name-only', '--format=', sha)
    .split('\n').map((line) => line.trim()).filter(Boolean);
  return files.some((file) => SOURCE.major_prefixes.some((prefix) => file.startsWith(prefix))) ? 'MAJOR' : 'MINOR';
}

export function realRows() {
  return readRealHistory().map((commit) => ({
    case_id: commit.sha,
    subject: commit.subject,
    committed_at: commit.committed_at,
    label: labelOfCommit(commit.sha),
  }));
}

export function splitRows(rows) {
  const splitAt = Math.floor(rows.length * (1 - SOURCE.holdout_fraction));
  return { dev: rows.slice(0, splitAt), holdout: rows.slice(splitAt), splitAt };
}

/** The frozen baseline: the DEV-partition agreement of the trivial predictor
 *  "always predict the dev majority class". Measured on dev only. */
export function frozenBaselineOf(dev) {
  const major = dev.filter((row) => row.label === 'MAJOR').length;
  const minor = dev.length - major;
  const majority = major >= minor ? 'MAJOR' : 'MINOR';
  const agreeing = majority === 'MAJOR' ? major : minor;
  return {
    predictor: 'always_predict_dev_majority_class',
    majority_class: majority,
    value: agreeing / dev.length,
    numerator: agreeing,
    denominator: dev.length,
    dev_major: major,
    dev_minor: minor,
  };
}

/** The design-time precision floor, computed BEFORE the holdout is opened.
 *  A difference smaller than the width of the interval this design can produce
 *  is not an effect this campaign is able to see; calling it one would be
 *  dressing noise up as a finding, so it is the preregistered noise band. */
export function designTimeBand(baselineValue, nHoldout) {
  // The two-sided normal quantile for the family-corrected tail alpha/m.
  const tail = ALPHA / FAMILY_SIZE;
  const z = normalQuantile(1 - tail / 2);
  const p = baselineValue;
  const n = nHoldout;
  const z2 = z * z;
  const centre = (p + z2 / (2 * n)) / (1 + z2 / n);
  const half = (z / (1 + z2 / n)) * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));
  return { band: half, z, half_width: half, centre, n_holdout: n };
}

/** Acklam's inverse normal CDF, adequate to 1e-9 and pure arithmetic. */
export function normalQuantile(p) {
  if (p <= 0 || p >= 1) throw new RangeError(`normalQuantile(${p})`);
  const a = [-3.969683028665376e1, 2.209460984245205e2, -2.759285104469687e2, 1.383577518672690e2, -3.066479806614716e1, 2.506628277459239];
  const b = [-5.447609879822406e1, 1.615858368580409e2, -1.556989798598866e2, 6.680131188771972e1, -1.328068155288572e1];
  const c = [-7.784894002430293e-3, -3.223964580411365e-1, -2.400758277161838, -2.549732539343734, 4.374664141464968, 2.938163982698783];
  const d = [7.784695709041462e-3, 3.224671290700398e-1, 2.445134137142996, 3.754408661907416];
  const pl = 0.02425;
  let q;
  let r;
  if (p < pl) {
    q = Math.sqrt(-2 * Math.log(p));
    return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
  }
  if (p <= 1 - pl) {
    q = p - 0.5;
    r = q * q;
    return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1);
  }
  q = Math.sqrt(-2 * Math.log(1 - p));
  return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
}

// --- the frozen documents ---------------------------------------------------

function cardOf(baseline) {
  return {
    contractVersion: '1.0.0',
    card_id: 'hyc-s2-008c-01',
    card_type: 'HYPOTHESIS',
    type_promotion: null,
    originating_domains: ['vcs-history', 'commit-message-conventions'],
    nodes: [
      { claim_id: 'clm-s2-008c-01', domain: 'vcs-history', revision: 1, role: 'source' },
      { claim_id: 'clm-s2-008c-02', domain: 'commit-message-conventions', revision: 1, role: 'target' },
    ],
    proposed_relation: {
      subject: 'the commit message subject line',
      predicate: 'is associated with',
      object: `whether the commit is MAJOR, on the newest ${Math.round(SOURCE.holdout_fraction * 100)}% of the real Veritas history`,
      relation_strength: 'CORRELATION_EVIDENCE',
      causal_assertion: null,
    },
    // A retrospective association between a message and a diff CANNOT carry a
    // temporal order between them: the message is written at the same instant
    // as the diff, so `established: false` is a fact about the design, not a
    // hedge. That is also why the card stays CORRELATION_EVIDENCE and is not
    // promoted.
    temporal_ordering: { established: false, event_times: [], evidence_claim_ids: [] },
    mediators: [],
    confounders: [
      { claim_id: 'clm-s2-008c-03', description: 'the base rate of MAJOR commits is low in the dev partition, so a predictor biased towards MAJOR loses agreement to the majority class; a difference in base rate between the two partitions would move every arm at once', status: 'IDENTIFIED' },
      { claim_id: 'clm-s2-008c-04', description: 'the partitions are not exchangeable: dev ends 2026-09-26 and the holdout is the following days, during which the ticket itself was under active work', status: 'IDENTIFIED' },
    ],
    alternative_explanations: [
      { claim_id: null, description: 'the arms differ only in how often they predict the rare class, and no arm carries information about the message beyond that frequency' },
      { claim_id: null, description: 'the dev-partition base rate is an artefact of this checkout\'s squashed history rather than a property of the project' },
    ],
    scope: {
      population: 'every commit reachable from the acceptance base of the local Veritas checkout',
      geography: null,
      period: { start: '2026-09-09T00:00:00.000Z', end: '2026-09-28T00:00:00.000Z' },
      units: 'commit',
      domain_limits: [
        'this one repository and this one checkout; no other project and no other history was measured',
        `the label is a path-prefix rule, not a judgement of importance: a MAJOR commit that only edits a README is labelled MINOR`,
        'association only; no causal effect of message wording on change size is claimed and none is measurable here',
      ],
    },
    assumptions: [
      'the holdout partition is a temporal successor of the dev partition and the base rate did not move materially between them',
      'the predictor is a pure function of the subject line, so it cannot have seen the diff it is predicting',
    ],
    falsifiers: [
      { description: 'the dev-partition base rate of MAJOR commits is 0 or 1, so the majority-class baseline is perfect and no arm can beat it', observable: 'frozen_baseline.value == 1.0' },
      { description: 'the label is not a function of the tree alone', observable: 're-labelling every dev commit under a constant subject returns a different label vector' },
      { description: 'the preregistered rule cannot reject anything, so the campaign is undecidable by construction', observable: 'ruleFeasibility never_rejects == true' },
    ],
    test_design: `One preregistered trial per arm (family of ${FAMILY_SIZE}, Holm-Bonferroni at alpha ${ALPHA}, confidence ${CONFIDENCE} derived as 1 - alpha/m). Each trial measures case_agreement_rate of the arm's prediction against the message-independent MAJOR label over the temporal holdout partition, opened exactly once through the sealed one-shot unseal, with ${SEEDS.length} frozen bootstrap seeds whose intervals are HULLED (widest) so no seed is ever selected. Observational corpus; inference_mode ASSOCIATIONAL.`,
    counterevidence: [
      { claim_id: 'clm-s2-008c-05', relation: 'bounds' },
    ],
    novelty: { assessment: 'NOT_ASSESSED', corpus: null, search_horizon: null, similar_prior_refs: [] },
    uncertainty: { author_confidence: null, evidence_support: 0, expert_trust: null, measured_calibration: null },
    stale: { is_stale: false, stale_claim_ids: [], invalidation_event_ids: [] },
    status: 'FRESH',
    created_at: '2026-09-28T00:00:00.000Z',
    created_by: 's2-008-campaign-acceptance',
  };
}

export function preregistrationOf({ rows, dev, holdout, baseline, band, card }) {
  const devCases = dev.map((row, index) => ({
    case_id: row.case_id,
    partition: 'PRIMARY',
    stratum: 'all_commits',
    label: row.label,
    subject: row.subject,
    committed_at: row.committed_at,
    agreement_by_trial: {},
    index,
  }));
  const holdoutCases = holdout.map((row, index) => ({
    case_id: row.case_id,
    partition: 'HOLDOUT',
    stratum: 'all_commits',
    label: row.label,
    subject: row.subject,
    committed_at: row.committed_at,
    // THE POINT OF THE FREEZE: no arm has been run, so there is no agreement
    // anywhere. An empty map is not a zero and not an UNRESOLVED row: no
    // outcome record exists yet, and a reader can prove that from this file.
    agreement_by_trial: {},
    index,
  }));

  const holdoutLabels = Object.fromEntries(holdoutCases.map((row) => [row.case_id, row.label]));

  return {
    kind: 'PREREGISTRATION',
    rule: 's2-008-prereg-v1',
    preregistration_id: 'xpr-s2-008c-01',
    // Sealed here; the superseded document omitted it, which is defect 3.
    expected_table_digest: null,
    card_id: card.card_id,
    card_digest: canonicalDigest(card),
    recorded_at: '2026-09-28T00:00:00.000Z',
    inference_mode: 'ASSOCIATIONAL',
    title: 'Do commit-message features agree with a message-independent MAJOR label on the real Veritas history?',
    description: `Real project, real history, real predictor run by a digest-pinned installed executor. ${ARMS.length} preregistered arms, one family, frozen before the holdout was opened.`,
    card,
    metric: {
      name: 'case_agreement_rate',
      direction: 'HIGHER_IS_BETTER',
      unit: 'ratio',
      noiseBand: band.band,
      inferenceMode: 'ASSOCIATIONAL',
      value_basis: 'CASE_AGREEMENT_RATE',
    },
    frozen_baseline: {
      value: baseline.value,
      // The digest seals WHAT was measured, so a reader can recompute the
      // baseline from the dev partition and get this number or a refusal.
      baseline_digest: canonicalDigest({
        predictor: baseline.predictor,
        majority_class: baseline.majority_class,
        numerator: baseline.numerator,
        denominator: baseline.denominator,
        dev_case_ids: dev.map((row) => row.case_id),
        dev_labels: dev.map((row) => row.label),
        label_rule: SOURCE.label_rule,
        split_rule: SOURCE.split_rule,
      }),
      source: 'FROZEN_DEV_PARTITION',
      corpus_partition: 'PRIMARY',
      measured_by: 'scripts/s2-008-campaign-prepare.mjs',
      value_basis: 'CASE_AGREEMENT_RATE',
      computed_from: `the ${dev.length} dev commits; the holdout was not read`,
    },
    seed_count: SEEDS.length,
    seed_rule: {
      kind: 'FIXED_LIST',
      seeds: [...SEEDS],
      source: 'PREREGISTERED',
      best_seed_selection: 'FORBIDDEN',
      // Frozen: the decision interval is the HULL over every seed, so no seed
      // can be chosen for being narrow, and the point estimate is the observed
      // rate, which no seed can move.
      decision_interval: 'HULL_OF_ALL_SEED_INTERVALS',
      point_estimate: 'OBSERVED_RATE_SEED_INVARIANT',
      disclosure: 'every seed is reported with its own interval; no seed is ranked, selected or dropped',
    },
    seeds_digest: canonicalDigest([...SEEDS]),
    stopping_rule: {
      kind: 'FIXED_TRIALS',
      max_trials: ARMS.length,
      early_stop: false,
      on_negative: 'RECORD_AND_CONTINUE',
      on_null: 'RECORD_AND_CONTINUE',
      on_infra: 'RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO',
    },
    // How the interval is produced, frozen BEFORE the corrected run. The
  // predictor is blind and answers first; the evaluator opens the holdout once
  // at the decision point; the seeded bootstrap runs afterwards, in its own
  // launch, on the agreement vectors. An earlier design resampled inside the
  // blind process and returned a membership bitmask, which collapses
  // multiplicity; the run it produced is preserved as ABORTED.
  bootstrap_process: {
    where: 'a second isolated launch, after the decision point, never predicting anything',
    why_separate: 'a bootstrap needs the agreement vector, which is a function of the label; the predictor must never see a label, so the two cannot be one process',
    multiplicity: 'every resample is carried as its full per-case multiplicity vector, so a case drawn three times counts three times and the resample mean converges on the measured rate',
    guard: 'a trial whose resample mean does not sit at its own measured rate is refused, not published',
  },
  // Sequential selection, stated because the rule is FIXED_TRIALS: there is
    // no interim analysis, no peek and no alpha spending. A trial is decided
    // when it completes; the family is corrected once at the end.
    sequential_rule: 'NO_INTERIM_ANALYSIS_NO_PEEK_FIXED_TRIPLES_ALPHA_CORRECTED_ONCE_OVER_THE_FROZEN_FAMILY',
    budget_reservation: {
      reservation_id: 'rsv-s2-008c-01',
      // A NAMED unit, not an abstraction: one unit is one container launch of
      // the real installed executor. The figure is the ceiling, not the spend.
      //
      // It was 6 in the superseded document and the first run made 9 launches
      // without charging any of them. The ceiling now covers the work the
      // preregistration itself enumerates — 3 arms x 3 seeds of prediction plus
      // one bootstrap launch — with headroom, and every launch is charged
      // against this reservation as it happens.
      currency: 'isolated_executor_launches',
      granted_units: 12,
      spent_units: 0,
      expires_at: RESERVATION_EXPIRES,
      trial_timeout_ms: PER_TRIAL_TIMEOUT_MS,
      unit_definition: 'one podman launch of a digest-pinned executor image; 9 preregistered prediction launches (3 arms x 3 frozen seeds) plus 1 preregistered bootstrap launch, charged one unit each as they happen; monetary spend is zero and no external service is contacted',
      enumerated_work: '3 declared trials x 3 frozen seeds + 1 bootstrap launch = 10 preregistered launches, ceiling 12',
    },
    noise_rule: {
      band: band.band,
      noise_band: band.band,
      method: 'percentile_bootstrap_over_poisson_binomial_draw_counts',
      bootstrap_samples: BOOTSTRAP_SAMPLES,
      bootstrap_seed: SEEDS[0],
      confidence: CONFIDENCE,
      percentile: CONFIDENCE,
      inference_mode: 'ASSOCIATIONAL',
      unit: 'ratio',
      // The strings the engine reads to decide that the null value is the
      // FROZEN BASELINE and not the comparator's default 0.
      positive_rule: 'LOWER_MINUS_BASELINE_GT_BAND',
      negative_rule: 'UPPER_MINUS_BASELINE_LT_BEGATIVE_BAND',
      null_rule: 'INTERVAL_INSIDE_BAND_AROUND_BASELINE',
      band_derivation: {
        rule: 'noise_band = the Wilson-scaled half-width of the preregistered interval at the preregistered confidence for the preregistered holdout n, evaluated at the DEV-partition baseline',
        z: band.z,
        half_width: band.half_width,
        n_holdout: band.n_holdout,
        computed_before: 'the holdout partition was opened',
        why: 'a difference below the width this design can resolve is not an effect this campaign is able to see; calling it one would be noise dressed as a finding',
      },
    },
    source_pin: {
      pinned_commit: SOURCE.pinned_commit,
      rule: 'the corpus is a function of this commit and never of HEAD, so the data are the same bytes on any host and after any later commit',
    },
    multiplicity_rule: {
      kind: 'HOLM_BONFERRONI',
      method: 'holm_bonferroni',
      alpha: ALPHA,
      confidence: CONFIDENCE,
      family_size: FAMILY_SIZE,
      declared_comparisons: ARMS.map((arm) => arm.trial_id),
      direction: 'increase',
      null_value: baseline.value,
      excluded: [],
    },
    trial_list: ARMS.map((arm, index) => ({
      index,
      trial_id: arm.trial_id,
      arm_id: arm.arm_id,
      partition: 'HOLDOUT',
      stratum: 'all_commits',
      predictor: arm.rule,
      seeds: [...SEEDS],
      metric: 'case_agreement_rate',
    })),
    holdout_access: {
      partition: 'HOLDOUT',
      case_count: holdout.length,
      max_opens: 1,
      one_shot: true,
      decision_point: 'AFTER_DECLARED_TRIALS',
      reads_before_data: true,
      released_actor_kinds: ['EVALUATOR'],
      labels_digest: canonicalDigest(holdoutLabels),
      unseal_digest: canonicalDigest(holdoutLabels),
    },
    recorded_before_first_trial: {
      first_trial: ARMS[0].trial_id,
      order_proved_by: 'REGISTRY_JOURNAL_NOT_A_CLOCK',
      proof: 'the preregistration row is committed to the registry journal before the first TRIAL row, and the corpus manifest seals a preregistration_digest that the case files cannot be edited past',
    },
    required_fields_present: ['hypothesis', 'metric', 'frozen_baseline', 'seed_count', 'stopping_rule', 'budget_reservation'],
    source: {
      project: SOURCE.project,
      kind: SOURCE.kind,
      pinned_commit: SOURCE.pinned_commit,
      commit_count: rows.length,
      dev_count: dev.length,
      holdout_count: holdout.length,
      split_at_commit: holdout[0].case_id,
      dev_period: [new Date(dev[0].committed_at * 1000).toISOString(), new Date(dev[dev.length - 1].committed_at * 1000).toISOString()],
      holdout_period: [new Date(holdout[0].committed_at * 1000).toISOString(), new Date(holdout[holdout.length - 1].committed_at * 1000).toISOString()],
      label_rule: SOURCE.label_rule,
      split_rule: SOURCE.split_rule,
      frozen_at: '2026-09-28',
    },
    arms: ARMS.map((arm) => ({ trial_id: arm.trial_id, arm_id: arm.arm_id, predictor: arm.rule })),
    // The POOLED aggregate is the linear combination of the family's own
    // rates, so it is not a fourth hypothesis and must not widen m.
    campaign_metric: { name: 'case_agreement_rate', subject_is_pooled_aggregate: true },
  };
}

/** The campaign's OWN frozen expectation. Unlike the fixture's, it declares NO
 *  expected outcome: a real campaign's outcome is not knowable before the run,
 *  and a table that declared one would be a hypothesis written to match the
 *  result. What it freezes is the RULE and the precision the design supports. */
export function frozenTableOf(prereg, supersedes = null) {
  const feasibility = ruleFeasibility({ alpha: ALPHA, confidence: CONFIDENCE, familySize: FAMILY_SIZE });
  return {
    kind: 's2-008-campaign-table/1',
    note: 'A real campaign cannot freeze an expected OUTCOME: the data are not authored, so any such expectation would be the hypothesis rewritten to fit the result. What is frozen here is the rule, the family and the precision the design supports, and the four outcome classes the engine may emit. The gate below is that the run agrees with THIS document, not with a predicted answer.',
    rule: {
      alpha: ALPHA,
      method: 'holm_bonferroni',
      family_size: FAMILY_SIZE,
      confidence: CONFIDENCE,
      confidence_derivation: '1 - alpha / family_size',
      rejection_floor: ALPHA / FAMILY_SIZE,
      never_rejects: feasibility.never_rejects,
      can_only_answer: feasibility.can_only_answer,
    },
    permitted_outcomes: ['POSITIVE', 'NEGATIVE', 'NULL', 'INFRA', 'UNRESOLVED'],
    metric: 'case_agreement_rate',
    baseline: prereg.frozen_baseline.value,
    band: prereg.noise_rule.band,
    n_dev: prereg.frozen_baseline.denominator,
    n_holdout: prereg.holdout_access.case_count,
    seeds: [...SEEDS],
    // WHICH frozen document is in force, and what it replaced. The anchor the
    // source ledger chains on is a digest of (cases, table), so a supersession
    // that changed neither would be refused as recording no change — which is
    // the ledger working. Naming the superseded digest here is what makes the
    // supersession a fact the chain can carry.
    supersession: supersedes === null ? null : {
      superseded_preregistration_digest: supersedes.preregistration_digest,
      recovered_from_commit: FREEZE_COMMIT,
      reason: SUPERSESSION_REASON,
      account: SUPERSESSION_ACCOUNT,
    },
    budget_ceiling: prereg.budget_reservation.granted_units,
  };
}

// --- the write --------------------------------------------------------------

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 1)}\n`);
}

function manifestOf({ devCases, holdoutCases, prereg, anchor, superseded, supersession, ledger }) {
  return {
    kind: 's2-008-campaign-corpus/1',
    description: 'The REAL Veritas history as an S2-008 corpus. Every case is a real commit: the label comes from `git show --name-only` and the subject from `git log`. No case is authored.',
    partitions: {
      PRIMARY: {
        role: 'the development partition; readable without an unseal digest; the frozen baseline is measured here',
        file: 'cases/dev.json',
        case_count: devCases.length,
        digest: canonicalDigest(devCases),
        labels_digest: canonicalDigest(Object.fromEntries(devCases.map((row) => [row.case_id, row.label]))),
      },
      HOLDOUT: {
        role: 'the holdout partition; the real labels, readable exactly once through readCorpus with the preregistered one-shot unseal digest, by an EVALUATOR actor only',
        file: 'cases/holdout.json',
        case_count: holdoutCases.length,
        digest: canonicalDigest(holdoutCases),
        labels_digest: prereg.holdout_access.labels_digest,
      },
    },
    case_digests: Object.fromEntries([
      ...devCases.map((row) => [`PRIMARY:${row.case_id}`, canonicalDigest(row)]),
      ...holdoutCases.map((row) => [`HOLDOUT:${row.case_id}`, canonicalDigest(row)]),
    ]),
    preregistration: {
      file: 'preregistration.json',
      preregistration_digest: preregistrationDigest(prereg),
      status: 'IN_FORCE',
      sealed_before_first_trial: true,
    },
    superseded_preregistration: {
      file: 'preregistration-superseded.json',
      preregistration_digest: superseded.preregistration_digest,
      status: 'SUPERSEDED',
      superseded_by: 'preregistration.json',
      recovered_from_commit: FREEZE_COMMIT,
    },
    supersession: {
      file: 'preregistration-supersession.json',
      supersession_id: supersession.supersession_id,
      supersession_digest: supersession.supersession_digest,
      reason: SUPERSESSION_REASON,
    },
    frozen_table: { file: 'frozen-table.json', digest: canonicalDigest(frozenTableOf(prereg)) },
    source_ledger: { file: 'source-ledger.json', entry_count: ledger.length, last_anchor_digest: anchor },
  };
}

export function selftest() {
  const rows = realRows();
  const { dev } = splitRows(rows);
  const original = dev.map((row) => row.label);
  // Re-label every dev commit with its subject replaced by a constant. If the
  // label rule ever read the message, this is where it would show.
  const relabelled = dev.map((row) => labelOfCommit(row.case_id));
  const withConstantSubject = dev.map((row) => ({ ...row, subject: 'x' }));
  const viaSubjectPath = withConstantSubject.map((row) => {
    const files = git('show', '--name-only', '--format=', row.case_id)
      .split('\n').map((line) => line.trim()).filter(Boolean);
    return files.some((file) => SOURCE.major_prefixes.some((prefix) => file.startsWith(prefix))) ? 'MAJOR' : 'MINOR';
  });
  const stable = canonicalDigest(original) === canonicalDigest(viaSubjectPath) && canonicalDigest(original) === canonicalDigest(relabelled);
  const result = {
    check: 'the label is a function of the tree alone',
    dev_cases: dev.length,
    labels_digest: canonicalDigest(original),
    label_vector_digest_under_constant_subject: canonicalDigest(viaSubjectPath),
    stable,
    verdict: stable ? 'HELD' : 'BROKEN',
  };
  console.log(JSON.stringify(result, null, 2));
  if (!stable) process.exitCode = 1;
  return result;
}

export function prepare({ write = true } = {}) {
  // The superseded document is read out of the freeze COMMIT, before anything is
  // built: the working tree is about to hold the new one, and a supersession
  // that quoted the new bytes would preserve nothing.
  const supersededRaw = JSON.parse(git('show', `${FREEZE_COMMIT}:corpus/s2-008-campaign/preregistration.json`));
  const supersededRef = { preregistration_digest: preregistrationDigest(supersededRaw) };
  const rows = realRows();
  const { dev, holdout } = splitRows(rows);
  const baseline = frozenBaselineOf(dev);
  const band = designTimeBand(baseline.value, holdout.length);
  const card = cardOf(baseline);

  // 1. The card is validated by the FROZEN contract, before anything is sealed.
  if (!isResearchContractValid('hypothesis-card', card)) {
    throw new Error(`the campaign card is not admissible to contracts/hypothesis-card.schema.json:\n${researchContractErrors('hypothesis-card', card).join('\n')}`);
  }

  const prereg = preregistrationOf({ rows, dev, holdout, baseline, band, card });
  // The in-force document seals its OWN frozen table. The superseded one did
  // not, which is why the track's supersession mechanism refuses to carry this
  // supersession (SUPERSESSION_TABLE_DIGEST_ABSENT) — a finding, not a
  // formality, and the reason this document differs from the one it replaces.
  const tableDigest = canonicalDigest(frozenTableOf(prereg, supersededRef));

  // 2. The rule must be able to decide. A rule that can never reject makes the
  //    campaign undecidable by construction, and that is checked from the
  //    published constants, not inferred from an UNRESOLVED afterwards.
  const feasibility = ruleFeasibility({ alpha: ALPHA, confidence: CONFIDENCE, familySize: FAMILY_SIZE });
  if (feasibility.never_rejects !== false) {
    throw new Error(`FROZEN_RULE_NOT_SELF_CONSISTENT: the sealed rule can never reject (${JSON.stringify(feasibility)})`);
  }

  // 3. The budget must be live at the decision point, or the lawful window is
  //    empty and the run has nothing to spend against.
  assertBudgetReservation(prereg.budget_reservation, Date.parse(DECISION_POINT) * 1e6);

  // 4. The document is admissible and carries no result.
  const sealed = { ...prereg };
  delete sealed.preregistration_digest;
  assertPreregistration(sealed);

  const digest = preregistrationDigest(sealed);
  const frozenPrereg = { ...sealed, expected_table_digest: tableDigest, preregistration_digest: digest };
  const anchor = sourceAnchorDigest({ cases_digest: canonicalDigest({ dev: dev.length, holdout: holdout.length }), expected_table_digest: canonicalDigest(frozenTableOf(frozenPrereg, supersededRef)) });
  void SUPERSESSION_KIND;
  // The first freeze's own ledger entry, read out of the freeze commit so the
  // chain starts where it started rather than where this script begins.
  const previousLedger = JSON.parse(git('show', `${FREEZE_COMMIT}:corpus/s2-008-campaign/source-ledger.json`));
  const previous = Array.isArray(previousLedger.entries) && previousLedger.entries.length > 0
    ? previousLedger.entries[previousLedger.entries.length - 1]
    : null;
  const ledger = [createSourceLedgerEntry({
    index: previous === null ? 0 : 1,
    previous: previous === null ? null : (previous.anchor_digest ?? null),
    cases_digest: canonicalDigest({ dev: dev.length, holdout: holdout.length }),
    expected_table_digest: canonicalDigest(frozenTableOf(frozenPrereg, supersededRef)),
    reason: 'the freeze of this campaign, and its supersession: the real history, the dev-measured baseline, the design-time band, the rule, the two-process bootstrap and the charged budget, all sealed before the corrected adapter was ever launched',
    previous,
  })];
  // The chain is asserted WHOLE, from the first freeze to this one: a new entry
  // checked on its own would prove nothing about what it follows.
  const fullLedger = [...(Array.isArray(previousLedger.entries) ? previousLedger.entries : []), ...ledger];
  assertSourceLedger(fullLedger, { cases_digest: canonicalDigest({ dev: dev.length, holdout: holdout.length }), expected_table_digest: canonicalDigest(frozenTableOf(frozenPrereg, supersededRef)) });

  // --- 5. the SUPERSESSION, and the document it replaces --------------------
  const supersededDigest = supersededRef.preregistration_digest;
  // The track's own supersession mechanism is TRIED first and its refusal is
  // recorded. `createSupersession` requires BOTH documents to seal the frozen
  // table, and the superseded one does not — a real freeze that seals no table
  // digest cannot be superseded by the mechanism built for the purpose. The
  // refusal is the evidence; the supersession is carried by the chained source
  // ledger entry and by this record instead, and neither is invented now.
  let supersessionRefusal = null;
  try {
    const built = createSupersession({ superseded: supersededRaw, replacedBy: frozenPrereg, reason: SUPERSESSION_REASON });
    assertSupersession(built, supersededRaw);
    supersessionRefusal = { refused: false, supersession: built };
  } catch (error) {
    supersessionRefusal = {
      refused: true,
      code: String(error?.code ?? 'UNKNOWN'),
      detail: String(error?.message ?? error).slice(0, 300),
      consequence: 'the superseded document sealed no expected_table_digest, so the track mechanism cannot carry this supersession; it is carried by the chained source ledger entry and by this record, and the omission is a defect of the first freeze',
    };
  }
  const supersession = {
    kind: SUPERSESSION_KIND,
    supersession_id: 'spr-s2-008c-01',
    superseded: { file: 'preregistration-superseded.json', preregistration_digest: supersededDigest, recovered_from_commit: FREEZE_COMMIT },
    replaced_by: { file: 'preregistration.json', preregistration_digest: digest, expected_table_digest: tableDigest },
    reason: SUPERSESSION_REASON,
    account: SUPERSESSION_ACCOUNT,
    mechanism: supersessionRefusal,
    supersession_digest: canonicalDigest({
      superseded: supersededDigest, replaced_by: digest, table: tableDigest, reason: SUPERSESSION_REASON,
    }),
  };
  const superseded = {
    file: 'preregistration-superseded.json',
    preregistration_digest: supersededDigest,
    recovered_from_commit: FREEZE_COMMIT,
    reason: SUPERSESSION_REASON,
  };

  const devOut = buildCases(dev, 'PRIMARY');
  const holdoutOut = buildCases(holdout, 'HOLDOUT');
  const manifest = manifestOf({ devCases: devOut, holdoutCases: holdoutOut, prereg: frozenPrereg, anchor, superseded, supersession, ledger: fullLedger });
  // The blind copy: what the adapter is allowed to see. No label, ever.
  const blind = holdout.map((row) => ({ case_id: row.case_id, subject: row.subject, committed_at: row.committed_at }));

  const files = {
    'preregistration.json': frozenPrereg,
    'frozen-table.json': frozenTableOf(frozenPrereg, supersededRef),
    'manifest.json': manifest,
    // `{entries: [...]}`, the shape `dataset.mjs#assertLedgerBinding` reads.
    // The bare array the first attempt wrote was not loadable, and the freeze
    // was therefore incomplete rather than merely untidy. It is completed here,
    // and no arm had been run when it was fixed.
    'source-ledger.json': { kind: SOURCE_LEDGER_KIND, entries: fullLedger },
    'cases/dev.json': devOut,
    'cases/holdout.json': holdoutOut,
    'cases/holdout.blind.json': blind,
    'preregistration-superseded.json': supersededRaw,
    'preregistration-supersession.json': supersession,
  };

  if (write) {
    for (const [name, value] of Object.entries(files)) writeJson(path.join(CORPUS_DIR, name), value);
  }

  return {
    rows: rows.length,
    dev: dev.length,
    holdout: holdout.length,
    baseline,
    band,
    feasibility,
    preregistration_digest: digest,
    superseded_preregistration_digest: supersededDigest,
    supersession_id: supersession.supersession_id,
    holdout_labels_digest: frozenPrereg.holdout_access.labels_digest,
    blind_digest: canonicalDigest(blind),
    written: write,
    digests: Object.fromEntries(Object.entries(files).map(([name, value]) => [name, canonicalDigest(value)])),
  };
}

function buildCases(rows, partition) {
  return rows.map((row, index) => ({
    case_id: row.case_id,
    partition,
    stratum: 'all_commits',
    label: row.label,
    subject: row.subject,
    committed_at: row.committed_at,
    agreement_by_trial: {},
    index,
  }));
}

const argv = process.argv.slice(2);
if (argv.includes('--seal-v2')) {
  throw new Error('V2_NOT_SEALABLE: its frozen trial list names three old arms while its declared arms name one model arm; use an explicitly approved v3');
} else if (argv.includes('--seal-v3')) {
  const { sealOnDisk } = await import('./s2-008-campaign-seal-v3.mjs');
  console.log(JSON.stringify({ mode: 'seal-v3', ...sealOnDisk() }, null, 2));
} else if (argv.includes('--seal-v4')) {
  const { sealOnDisk } = await import('./s2-008-campaign-seal-v4.mjs');
  console.log(JSON.stringify({ mode: 'seal-v4', ...sealOnDisk() }, null, 2));
} else if (argv.includes('--seal-v5')) {
  const { sealV5OnDisk } = await import('./s2-008-campaign-seal-v5.mjs');
  console.log(JSON.stringify({ mode: 'seal-v5', ...sealV5OnDisk() }, null, 2));
} else if (argv.includes('--seal-v6')) {
  const { sealV6OnDisk } = await import('./s2-008-campaign-seal-v6.mjs');
  console.log(JSON.stringify({ mode: 'seal-v6', ...sealV6OnDisk() }, null, 2));
} else if (argv.includes('--seal-v7')) {
  const { sealV7OnDisk } = await import('./s2-008-campaign-seal-v7.mjs');
  console.log(JSON.stringify({ mode: 'seal-v7', ...sealV7OnDisk() }, null, 2));
} else if (argv.includes('--seal-v10')) {
  const { sealV10OnDisk } = await import('./s2-008-campaign-seal-v10.mjs');
  console.log(JSON.stringify({ mode: 'seal-v10', ...sealV10OnDisk() }, null, 2));
} else if (argv.includes('--seal-v9')) {
  const { sealV9OnDisk } = await import('./s2-008-campaign-seal-v9.mjs');
  console.log(JSON.stringify({ mode: 'seal-v9', ...sealV9OnDisk() }, null, 2));
} else if (argv.includes('--seal-v8')) {
  const { sealV8OnDisk } = await import('./s2-008-campaign-seal-v8.mjs');
  console.log(JSON.stringify({ mode: 'seal-v8', ...sealV8OnDisk() }, null, 2));
} else if (argv.includes('--selftest')) {
  selftest();
} else if (argv.includes('--check')) {
  const currentManifest = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'manifest.json'), 'utf8'));
  if (currentManifest.preregistration?.file === 'preregistration.v10.in-force.json') {
    const { checkV10OnDisk } = await import('./s2-008-campaign-seal-v10.mjs');
    console.log(JSON.stringify({ mode: 'check-v10', ...checkV10OnDisk() }, null, 2));
  } else if (currentManifest.preregistration?.file === 'preregistration.v9.in-force.json') {
    const { checkV9OnDisk } = await import('./s2-008-campaign-seal-v9.mjs');
    console.log(JSON.stringify({ mode: 'check-v9', ...checkV9OnDisk() }, null, 2));
  } else if (currentManifest.preregistration?.file === 'preregistration.v8.in-force.json') {
    const { checkV8OnDisk } = await import('./s2-008-campaign-seal-v8.mjs');
    console.log(JSON.stringify({ mode: 'check-v8', ...checkV8OnDisk() }, null, 2));
  } else if (currentManifest.preregistration?.file === 'preregistration.v7.in-force.json') {
    const { checkV7OnDisk } = await import('./s2-008-campaign-seal-v7.mjs');
    console.log(JSON.stringify({ mode: 'check-v7', ...checkV7OnDisk() }, null, 2));
  } else if (currentManifest.preregistration?.file === 'preregistration.v6.in-force.json') {
    const { checkV6OnDisk } = await import('./s2-008-campaign-seal-v6.mjs');
    console.log(JSON.stringify({ mode: 'check-v6', ...checkV6OnDisk() }, null, 2));
  } else if (currentManifest.preregistration?.file === 'preregistration.v5.in-force.json') {
    const { checkV5OnDisk } = await import('./s2-008-campaign-seal-v5.mjs');
    console.log(JSON.stringify({ mode: 'check-v5', ...checkV5OnDisk() }, null, 2));
  } else if (currentManifest.preregistration?.file === 'preregistration.v4.in-force.json') {
    const { checkV4OnDisk } = await import('./s2-008-campaign-seal-v4.mjs');
    console.log(JSON.stringify({ mode: 'check-v4', ...checkV4OnDisk() }, null, 2));
  } else if (currentManifest.preregistration?.file === 'preregistration.v3.in-force.json') {
    const { checkV3OnDisk } = await import('./s2-008-campaign-seal-v3.mjs');
    console.log(JSON.stringify({ mode: 'check-v3', ...checkV3OnDisk() }, null, 2));
  } else {
  const built = prepare({ write: false });
  const mismatches = [];
  for (const [name, digest] of Object.entries(built.digests)) {
    const file = path.join(CORPUS_DIR, name);
    if (!fs.existsSync(file)) { mismatches.push(`${name}: absent`); continue; }
    const onDisk = canonicalDigest(JSON.parse(fs.readFileSync(file, 'utf8')));
    if (onDisk !== digest) mismatches.push(`${name}: on disk ${onDisk}, re-derived ${digest}`);
  }
  console.log(JSON.stringify({ mode: 'check', preregistration_digest: built.preregistration_digest, mismatches, ok: mismatches.length === 0 }, null, 2));
  if (mismatches.length > 0) process.exitCode = 1;
  }
} else {
  if (fs.existsSync(path.join(CORPUS_DIR, 'manifest.json'))) {
    const active = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'manifest.json'), 'utf8'));
    if (active.preregistration?.file === 'preregistration.v3.in-force.json') {
      throw new Error('V3_IN_FORCE_REFUSES_V1_REBUILD');
    }
  }
  const built = prepare({ write: true });
  console.log(JSON.stringify({
    mode: 'write',
    corpus_dir: path.relative(REPO_ROOT, CORPUS_DIR),
    real_commits: built.rows,
    dev_commits: built.dev,
    holdout_commits: built.holdout,
    frozen_baseline: built.baseline,
    design_time_band: built.band,
    rule_feasibility: built.feasibility,
    preregistration_digest: built.preregistration_digest,
    superseded_preregistration_digest: built.superseded_preregistration_digest,
    supersession_id: built.supersession_id,
    holdout_labels_digest: built.holdout_labels_digest,
    blind_input_digest: built.blind_digest,
    digests: built.digests,
    holdout_agreement_present: false,
    note: 'no arm was run and no holdout agreement exists in these bytes; the empty agreement map is the proof',
  }, null, 2));
}
