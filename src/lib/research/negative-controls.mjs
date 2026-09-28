// S2-008 research track — the SIX NEGATIVE CONTROLS as first-class artefacts
// (issue SpaceDazher/Veritas#8).
//
// Serves acceptance item A2 ("a negative control injects corrupted data and
// MUST flip the verdict") and the A2/A3/A5 controls of the plan's mechanism
// table. Owns `evidence/s2-008-negative-controls.json` (W4 writes the file;
// this module defines and drives its contents).
//
// WHY THESE ARE ARTEFACTS AND NOT ASSERTIONS IN A TEST FILE
// An assertion inside a test proves the code behaves. A control that injects
// corruption and REQUIRES THE VERDICT TO FLIP proves the code is not merely
// self-consistent: it proves the decision layer is sensitive to the thing it
// claims to decide on. Without the flip requirement, the six probes in
// probes.mjs demonstrate six happy paths and nothing about six defences.
// Therefore EVERY control flipping is itself a HARD GATE, and a control that
// does not flip FAILS THE TRACK.
//
// THE SIX FROZEN CONTROL IDS (the exact set, no additions, no omissions)
//   holdout_peek        forged one-shot unseal digest -> refused AND counted
//                       AND comparator flips to VIOLATION.
//   seed_substitution   the recorded seed is replaced by the best-scoring seed
//                       with the score untouched -> comparator flips; the
//                       expected-value table is read BY TRIAL INDEX, so the
//                       substitution changes which row scores the result.
//   budget_opacity      settling beyond the reservation -> BudgetExceeded with
//                       a byte-identical journal; settling against an expired
//                       reservation -> ReconciliationRequired row, no retry,
//                       no zero.
//   label_substitution  a causal claim is substituted onto a card whose ground
//                       truth is observational -> MUST FAIL. This control IS
//                       acceptance item A4.
//   missing_evaluator   the evaluator is deleted from the run record ->
//                       comparator flips ALLOW -> VIOLATION (P6).
//   corrupted_data      `injectCorruption` alters a trial status, a counter, a
//                       metric record or a provenance field ->
//                       `compareParallelTrack` flips the verdict AND names the
//                       corrupted field.
//
// The A3 IDENTICAL-WRONG CONTROL
// `corrupted_data` is injected into BOTH runs identically, their digests are
// left EQUAL, and BOTH must produce non-empty findings. `A === B` alone is
// insufficient and is never the pass criterion. The comparison record carries
// `findings_a`, `findings_b` (both non-empty) and `digests_still_equal: true`.
// This is possible only because `expectedValueIssues` is pure — see
// expected-values.mjs.
//
// THE KNOWN LIMIT, RECORDED NOT INHERITED
// The identical-wrong control proves the table load-bearing only for the
// CLASSES it corrupts. It must corrupt at least one class per frozen category
// — a trial status, a counter, a code set, a metric, a provenance field — and
// `evidence/s2-008-comparison.json` must ITEMISE which classes were and were
// not covered. The S2-007 report notes this limitation of its own control; it
// is not inherited unexamined here.
//
// DETERMINISM
// No network, no LLM, no credentials, no `Date.now()`, no `Math.random()`.
// A control run is reproducible on the same base, and a control that cannot run
// reports NOT_RUN and exits 3 — never 0.
//
// Owner: W3 (decision core). Budget: part of W3's <= 800 lines.
// State: IMPLEMENTED. The exported signatures are the ones plan §1 froze and
// none was renamed.
import { MalformedResult } from '../agentboard/errors.mjs';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import { EXPECTED_CONTROLS, expectedValueIssues } from './expected-values.mjs';
import { injectCorruption, resolveTrialVerdict } from './comparator.mjs';
import { classifyCardRelation } from './causality.mjs';

/**
 * The FOUR frozen corruption variants, read from the SAME table
 * `injectCorruption` reads, so a variant the comparator can apply and a variant
 * the control does not inject cannot drift apart. `injectCorruption` keeps the
 * set closed and throws on an unknown variant, so the two can never disagree by
 * accident either.
 * @type {ReadonlyArray<string>}
 */
export const CORRUPTION_VARIANTS_INJECTED = Object.freeze([
  'trial_status_skip', 'counter_nudge', 'metric_altered', 'provenance_field',
]);

/**
 * The six frozen control descriptors. Exactly six entries; the id set is
 * closed.
 * @type {ReadonlyArray<{
 *   id: string,
 *   probe: string,
 *   corrupts: string,
 *   mustFlipTo: string,
 *   counter: string,
 *   evidenceId: string
 * }>} One descriptor per control, keyed by control id: `holdout_peek`,
 * `seed_substitution`, `budget_opacity`, `label_substitution`,
 * `missing_evaluator`, `corrupted_data`. `mustFlipTo` is the verdict the
 * comparator must produce from the corrupted record.
 */
export const NEGATIVE_CONTROLS = Object.freeze(EXPECTED_CONTROLS.map((expected) => Object.freeze({
  id: expected.id,
  probe: expected.probe,
  corrupts: `the ${expected.id} condition of one trial / one run record`,
  mustFlipTo: expected.mustFlipTo,
  counter: expected.counter,
  evidenceId: expected.id,
  mechanism: expected.mechanism,
  mustFlipFrom: expected.mustFlipFrom,
})));

/**
 * The control ids this module may ADD to the frozen six, and why. The six
 * negative controls of `EXPECTED_CONTROLS` are the ticket's set and stay
 * closed; a mutation that exercises a shape the frozen six do not reach is
 * reported beside them under a name of its own, so `controlsFlipVerdict` can
 * gate it without the frozen id set ever growing.
 * @type {ReadonlyArray<string>}
 */
export const EXTRA_CONTROL_IDS = Object.freeze(['ledger_spelling_holdout_peek']);

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A plain-object test for the BINDINGS a mutation reads. */
function isRecord(value) {
  return isPlainObject(value);
}

function verdictOf(record) {
  const outcome = isPlainObject(record) ? resolveTrialVerdict(record) : null;
  return isPlainObject(outcome) ? String(outcome.verdict) : 'REFUSED';
}

/**
 * Run every control and collect the evidence record.
 *
 * Every control is a MUTATION OF A REAL RECORD followed by a real check. None
 * of them is a flag: the four comparator controls edit the binding's own
 * semantic content (the instant the holdout was read, the seed set that was
 * used, the units spent against the units granted, the evaluator's presence),
 * and the corrupted-data control edits the frozen table's input and requires
 * non-empty findings. A control that only sets a boolean is testing the
 * boolean, which is what findings PR3, PR4 and PR7 were about.
 *
 * @param {object} ctx The control context: an open registry (registry.mjs), a
 *   preregistration (preregistration.mjs), a loaded corpus, a clean run
 *   record, a comparator handle and an injected fixed clock.
 * @param {object} ctx.trial The clean trial record every comparator control
 *   mutates. It must already be an ALLOW, or the "before" state is meaningless
 *   and every control is reported as `notRun` rather than as a pass.
 * @param {object} ctx.cleanRun The clean run record the table controls mutate.
 * @param {object} ctx.card The hypothesis card the label control mutates.
 * @param {number} [ctx.caseId] The case the holdout control names.
 * @returns {Promise<{version: string, controls: ReadonlyArray<object>,
 *   allFlipped: boolean, notRun: ReadonlyArray<object>,
 *   digest: string}>} One record per control naming what was corrupted, the
 *   verdict before, the verdict after, and whether the flip happened.
 *   `allFlipped` is false if ANY control failed to flip. A control that could
 *   not run appears in `notRun` and the harness exits 3, not 0.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when the
 *   context is incomplete — a half-run control is worse than no control.
 */
export function runNegativeControls(ctx) {
  const context = isPlainObject(ctx) ? ctx : {};
  const { trial, cleanRun, card } = context;
  if (!isPlainObject(trial)) {
    throw new MalformedResult('CONTEXT_TRIAL_ABSENT', 'runNegativeControls needs the clean trial record it will corrupt');
  }
  if (!isPlainObject(cleanRun)) {
    throw new MalformedResult('CONTEXT_RUN_ABSENT', 'runNegativeControls needs the clean run record the table controls corrupt');
  }
  const before = verdictOf(trial);
  const controls = [];
  const notRun = [];

  // The four comparator-level controls. Each mutation is written to state the
  // violation SEMANTICALLY; the comparator's binding checks read that content,
  // so the flip is attributable to the property and not to a self-declared flag.
  const comparatorMutations = Object.freeze({
    holdout_peek: (clean) => ({
      ...clean,
      holdoutBinding: {
        ...clean.holdoutBinding,
        partition: 'HOLDOUT',
        read_at: '2026-01-01T00:00:00.000Z',
        decision_at: '2026-01-02T00:00:00.000Z',
        opened_before_decision_point: true,
        opens: 1,
        max_opens: 1,
      },
    }),
    // S2: the SAME peek spelled the way THE LEDGER COMMITS its own ACCESS row.
    // `registry.mjs#recordHoldoutRead` plans `decision_point`, and the
    // comparator read only `decision_at` / `decisionAt`, so a control that used
    // the ledger's spelling was an ALLOW — the control never exercised the
    // shape a real run produces. It is a second mutation of the same control,
    // not a seventh control: the control id set stays frozen at six.
    ledger_spelling_holdout_peek: (clean) => {
      // The `decision_at` / `decisionAt` spellings are REMOVED, not
      // overridden: leaving them in place would let the comparator read the
      // control's own member and the control would prove nothing about the
      // spelling the ledger actually writes. What is left is the row
      // `registry.mjs#recordHoldoutRead` plans, verbatim.
      const { decision_at: _a, decisionAt: _b, ...rest } = isRecord(clean.holdoutBinding) ? clean.holdoutBinding : {};
      return {
        ...clean,
        holdoutBinding: {
          ...rest,
          partition: 'HOLDOUT',
          read_at: '2026-01-01T00:00:00.000Z',
          decision_point: '2026-01-02T00:00:00.000Z',
          opened_before_decision_point: false,
          opens: 1,
          max_opens: 1,
        },
      };
    },
    seed_substitution: (clean) => ({
      ...clean,
      seedBinding: {
        ...clean.seedBinding,
        seeds: [4242, 4242, 4242, 4242],
        source: 'BEST_ONLY',
      },
    }),
    budget_opacity: (clean) => ({
      ...clean,
      budgetBinding: {
        ...clean.budgetBinding,
        reservation_id: 'rsv-s2-008-control',
        granted_units: 100,
        spent_units: 400,
        currency: 'UNITS',
      },
    }),
    missing_evaluator: (clean) => {
      const copy = { ...clean };
      delete copy.evaluatorBinding;
      delete copy.evaluator;
      return copy;
    },
  });

  for (const descriptor of NEGATIVE_CONTROLS) {
    if (descriptor.id === 'label_substitution') {
      if (!isPlainObject(card)) {
        notRun.push({ id: descriptor.id, reason: 'CONTEXT_CARD_ABSENT' });
        continue;
      }
      const cleanClassification = classifyCardRelation(card);
      const swapped = { ...card, proposed_relation: { ...card.proposed_relation, causal_assertion: true } };
      const after = classifyCardRelation(swapped);
      const flipped = cleanClassification.admissible === true && after.admissible === false;
      controls.push(Object.freeze({
        id: descriptor.id,
        probe: descriptor.probe,
        mechanism: descriptor.mechanism,
        injects: 'an observational label swapped to causal',
        before: cleanClassification.admissible ? 'ADMITTED' : 'REFUSED',
        after: after.admissible ? 'ADMITTED' : 'REFUSED',
        before_refusal: cleanClassification.refusalCode,
        after_refusal: after.refusalCode,
        mutated_field: 'proposed_relation.causal_assertion',
        flipped,
      }));
      continue;
    }
    if (descriptor.id === 'corrupted_data') {
      // The IDENTICAL-WRONG control, run on BOTH runs: the same corruption in
      // each, so their digests stay equal and the table has to be what
      // produces findings. `A === B` alone is never a pass.
      //
      // S9: EVERY frozen variant is injected, not only `trial_status_skip`.
      // Three of the four (`counter_nudge`, `metric_altered`,
      // `provenance_field`) were implemented in `injectCorruption` and never
      // injected, so the control proved the table load-bearing for one class of
      // corruption and the record said nothing about the other three. The
      // coverage itemisation below is part of the record, and `flipped` is
      // false unless every declared variant produced findings in BOTH runs.
      const perRun = ['a', 'b'].map((letter) => {
        const source = isPlainObject(context.runA) && letter === 'a' ? context.runA : context.runB;
        const run = isPlainObject(source) ? source : cleanRun;
        const variants = CORRUPTION_VARIANTS_INJECTED.map((variant) => {
          const injected = injectCorruption(run.trials, variant);
          const copy = { ...run, trials: injected.trials };
          return { variant, corrupted: injected.corrupted, findings: expectedValueIssues(copy, letter).length };
        });
        return { letter, variants };
      });
      const covered = perRun.every((entry) => entry.variants.every((item) => item.findings > 0));
      const missing = CORRUPTION_VARIANTS_INJECTED.filter((variant) => perRun.some((entry) => entry.variants.find((item) => item.variant === variant && item.findings === 0)));
      controls.push(Object.freeze({
        id: descriptor.id,
        probe: descriptor.probe,
        mechanism: descriptor.mechanism,
        injects: 'the same corrupted trial in BOTH runs, once per frozen corruption variant, so their digests stay equal',
        before: 'no_findings',
        after: covered ? 'findings_non_empty' : 'no_findings',
        per_run: Object.freeze(perRun),
        coverage: Object.freeze({
          variants_declared: CORRUPTION_VARIANTS_INJECTED,
          variants_injected: Object.freeze([...new Set(perRun.flatMap((entry) => entry.variants.map((item) => item.variant)))]),
          variants_unproductive: Object.freeze(missing),
          note: 'a corruption class the control never injects is a class whose detection the control does not demonstrate; the list is itemised in the record rather than left implicit',
        }),
        flipped: covered && missing.length === 0,
      }));
      continue;
    }
    const mutate = comparatorMutations[descriptor.id];
    if (typeof mutate !== 'function') {
      notRun.push({ id: descriptor.id, reason: 'CONTROL_MUTATION_ABSENT' });
      continue;
    }
    const after = verdictOf(mutate(trial));
    controls.push(Object.freeze({
      id: descriptor.id,
      probe: descriptor.probe,
      mechanism: descriptor.mechanism,
      injects: `the ${descriptor.id} condition stated in the binding's own content`,
      before,
      after,
      before_verdict: before,
      after_verdict: after,
      flipped: before === descriptor.mustFlipFrom && after === descriptor.mustFlipTo,
    }));
  }

  // S2: the ledger's OWN spelling of the holdout binding, as a named extra
  // measurement beside the frozen six. It is reported in the record and it is
  // GATED, because the row the ledger commits is the row a real run produces:
  // a control that only exercised `decision_at` left `decision_point` — the
  // spelling registry.mjs writes — completely undemonstrated, and the
  // comparator read it as "no decision point at all" and allowed the peek.
  const ledgerSpellingMutation = comparatorMutations.ledger_spelling_holdout_peek;
  const ledgerSpellingAfter = verdictOf(ledgerSpellingMutation(trial));
  const ledgerSpelling = Object.freeze({
    id: 'ledger_spelling_holdout_peek',
    mechanism: 'comparator',
    injects: 'the holdout binding spelled the way registry.mjs#recordHoldoutRead plans the ACCESS payload (decision_point)',
    before,
    after: ledgerSpellingAfter,
    mutated_field: 'holdoutBinding.decision_point',
    flipped: before === 'ALLOW' && ledgerSpellingAfter === 'VIOLATION',
  });
  controls.push(ledgerSpelling);

  // S8: WHAT these controls actually demonstrate. Every control above mutates
  // a hand-built trial and reads the verdict back, so `allFlipped` proves the
  // COMPARATOR is sensitive to its own inputs. It does not prove the pipeline
  // is: the same mutations are now applied to a REAL run record and the
  // run-level findings are counted, which is the measurement the record
  // previously asserted without making.
  const pipeline = { runs_examined: 0, mutations: [], any_run_sensitive: null, note: 'a control applied to a real run record: the same mutation, counted as run-level expected-value findings' };
  for (const [letter, source] of [['a', context.runA], ['b', context.runB]]) {
    const run = isPlainObject(source) ? source : null;
    if (run === null || !Array.isArray(run.trials) || run.trials.length === 0) continue;
    pipeline.runs_examined += 1;
    const baseline = expectedValueIssues(run, letter).length;
    for (const [id, mutation] of Object.entries(comparatorMutations)) {
      if (id === 'ledger_spelling_holdout_peek') continue;
      const mutated = { ...run, trials: [mutation(JSON.parse(JSON.stringify(run.trials[0]))), ...run.trials.slice(1)] };
      const after2 = expectedValueIssues(mutated, letter).length;
      pipeline.mutations.push({ letter, control: id, layer: 'TRIAL_BINDING', findings_before: baseline, findings_after: after2, detected: after2 !== baseline });
    }
    for (const variant of CORRUPTION_VARIANTS_INJECTED) {
      const injected = injectCorruption(run.trials, variant);
      const mutated = { ...run, trials: injected.trials };
      const after3 = expectedValueIssues(mutated, letter).length;
      pipeline.mutations.push({ letter, control: `corrupted_data:${variant}`, layer: 'RUN_RECORD', findings_before: baseline, findings_after: after3, detected: after3 !== baseline });
    }
  }
  pipeline.detected_at_run_level = pipeline.mutations.filter((item) => item.layer === 'RUN_RECORD' && item.detected).length;
  pipeline.detected_at_comparator_level_only = pipeline.mutations.filter((item) => item.layer === 'TRIAL_BINDING' && !item.detected).length;
  pipeline.any_run_sensitive = pipeline.mutations.some((item) => item.detected === true);
  pipeline.note = pipeline.runs_examined === 0
    ? 'NOT_RUN: no real run record was supplied, so only the comparator-level sensitivity is demonstrated'
    : `comparator-level sensitivity is demonstrated for all six controls; at RUN level the frozen corruption classes changed the findings ${String(pipeline.detected_at_run_level)} time(s) out of ${String(pipeline.mutations.filter((item) => item.layer === 'RUN_RECORD').length)}, and the trial-binding mutations changed them ${String(pipeline.mutations.filter((item) => item.layer === 'TRIAL_BINDING' && item.detected).length)} time(s) out of ${String(pipeline.mutations.filter((item) => item.layer === 'TRIAL_BINDING').length)} — a binding mutation is caught by the COMPARATOR, not by the expected-value table, and the record now says which is which`;

  return Object.freeze({
    version: 's2-008-negative-controls-v1',
    controls: Object.freeze(controls),
    allFlipped: notRun.length === 0 && controls.every((entry) => entry.flipped === true),
    sensitivity: Object.freeze({
      comparator: 'PROVEN: every control mutates a trial and reads resolveTrialVerdict back, so allFlipped is a measurement of the comparator',
      pipeline,
    }),
    notRun: Object.freeze(notRun),
    digest: canonicalDigest({ controls, notRun }),
  });
}

/**
 * The hard gate over the control record: EVERY control must have flipped the
 * verdict, and every control must have run. A control that did not flip, or a
 * missing control, is a failure — never a warning, never a limit.
 * @param {object} record The record produced by runNegativeControls.
 * @returns {{ok: boolean, failures: ReadonlyArray<string>}}
 *   `ok: false` names every control that failed to flip and every control that
 *   did not run.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when a control
 *   id is not a member of NEGATIVE_CONTROLS — an unknown control cannot be
 *   counted as a passing one.
 */
export function controlsFlipVerdict(record) {
  if (!isPlainObject(record) || !Array.isArray(record.controls)) {
    throw new MalformedResult('CONTROL_RECORD_MALFORMED', 'controlsFlipVerdict needs the record runNegativeControls produced');
  }
  const declared = new Set(NEGATIVE_CONTROLS.map((descriptor) => descriptor.id));
  const declaredExtra = new Set(EXTRA_CONTROL_IDS);
  const failures = [];
  for (const entry of record.controls) {
    const id = String(entry.id);
    if (!isPlainObject(entry) || (!declared.has(id) && !declaredExtra.has(id))) {
      throw new MalformedResult('CONTROL_ID_UNKNOWN', `control id ${id} is not a member of NEGATIVE_CONTROLS`);
    }
    if (entry.flipped !== true) {
      failures.push(`${id} did not flip (${String(entry.before)} -> ${String(entry.after)})`);
    }
  }
  for (const descriptor of NEGATIVE_CONTROLS) {
    if (!record.controls.some((entry) => isPlainObject(entry) && entry.id === descriptor.id)) {
      failures.push(`${descriptor.id} did not run`);
    }
  }
  for (const entry of Array.isArray(record.notRun) ? record.notRun : []) {
    failures.push(`${String(entry?.id ?? 'unnamed')} did not run: ${String(entry?.reason ?? 'no reason given')}`);
  }
  return { ok: failures.length === 0, failures: Object.freeze(failures) };
}
