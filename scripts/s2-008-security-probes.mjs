#!/usr/bin/env node
// S2-008 — THE SIX NEGATIVE PROBES AND THE SIX NEGATIVE CONTROLS
// (issue SpaceDazher/Veritas#8, A1 + A2), the runner behind
// `test:s2-008-security-probes`.
//
// WHAT THIS SCRIPT IS
// The runner, in the shape of `scripts/s2-007-security-probes.mjs`. It contains
// NO probe logic and NO control logic: the six families live in
// `src/lib/research/probes.mjs` and the six controls in
// `src/lib/research/negative-controls.mjs`, both driving the PUBLIC exports of
// registry / causality / comparator / preregistration. Duplicating them here
// would create a second, weaker copy of the adversarial suite — the
// "two independently editable payload forms" failure the ticket forbids — and a
// copy can keep passing after the real boundary is rewired. This file owns
// exactly three things: WHICH registry root the probes run against, WHAT the
// record says, and WHAT the exit code means.
//
// A CONTROL THAT DID NOT FLIP IS A FAILURE
// The ticket's A2 is not "the controls ran"; it is that a negative control
// injects corrupted data and the verdict MUST flip. A control that runs and
// leaves the verdict alone has proved nothing about the defence, so
// `controlsFlipVerdict` is a hard gate here and not a reported fact: a
// non-flipping control is exit 1 whatever the counters say.
//
// EXIT CODE CONTRACT (the aggregator depends on these exact values)
//   0  all six families ran, all six controls ran and every one flipped, and
//      every hard-gate counter is 0;
//   1  a probe failed, a control did not flip, or at least one hard-gate
//      counter is > 0;
//   3  every counter is 0 but a mandatory probe or control did not run.
//
// A counter finding is NEVER exit 0, and a skip is never exit 0 either: an
// unproven defence and a proven defence are different states, and collapsing
// them is how a fake green gets written.
//
// ONE PURGED ROOT
// Every probe world is created from ONE root, and that root is purged before
// the gate runs (`runAllProbes` calls `purgeProbeFixtures`). Without the purge a
// repeat run on a permanent base fails on its own leftovers instead of on the
// property, and the second run of the gate would look like a regression.
//
//   node scripts/s2-008-security-probes.mjs
//   node scripts/s2-008-security-probes.mjs --write
//   node scripts/s2-008-security-probes.mjs --print-record
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { EXPECTED_CAMPAIGN, EXPECTED_CONTROLS, EXPECTED_TRIAL_DECISIONS, EXPECTED_METRIC } from '../src/lib/research/expected-values.mjs';
import { assertFrozenCampaignDerivable } from '../src/lib/research/campaign-expectation.mjs';
import { CORRUPTION_VARIANTS_INJECTED, controlsFlipVerdict, EXTRA_CONTROL_IDS, runNegativeControls } from '../src/lib/research/negative-controls.mjs';
import { HARD_GATE_COUNTERS, PROBE_FAMILIES, PROBE_NAMES, runAllProbes } from '../src/lib/research/probes.mjs';
import { loadPreregistration } from '../src/lib/research/preregistration.mjs';
import { COMMITTED_CORPUS_DIR, parseArgs, resolveBase } from './s2-008-run.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
/** The gate's own scratch. Under `.bb/`, which `.gitignore` covers. */
const SCRATCH = path.join(REPO_ROOT, '.bb', 's2-008', 'probes');
const OUT_RELATIVE = 'evidence/s2-008-security-probes.json';

const EXIT_PASS = 0;
const EXIT_SAFETY = 1;
const EXIT_NOT_RUN = 3;

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function log(...parts) {
  process.stdout.write(`${parts.join(' ')}\n`);
}

/** The purge record as it is COMMITTED: `base` is repository-relative, never
 * a host-local absolute path. An absolute path would carry the account name,
 * the worktree layout and the thread id of the machine that produced the
 * record, and it would make these bytes host-dependent, so the same base on
 * another checkout could not reproduce the file byte for byte. A root outside
 * the repository becomes a fixed token rather than a relative escape, so a
 * path outside the tree cannot be reconstructed from the record either. */
function purgedRecordForCommit(purged) {
  const relative = path.relative(REPO_ROOT, purged?.base ?? '');
  const outside = relative === ''
    || path.isAbsolute(relative)
    || relative === '..'
    || relative.startsWith(`..${path.sep}`);
  return { ...purged, base: outside ? '<external-scratch-root>' : relative };
}

/**
 * The control trial the four comparator-level controls mutate. It must already
 * be an ALLOW: a control whose "before" state is already a VIOLATION cannot
 * demonstrate a flip, and the six controls would be reported `notRun` rather
 * than as passes.
 *
 * The evaluator is declared MEASURED here on purpose. The track's DELIVERED
 * calibration is `NOT_MEASURED`, and a NOT_MEASURED calibration makes every
 * trial a VIOLATION by the comparator's own rule — which is the right rule for a
 * campaign and the wrong starting point for a control.
 */
function controlTrial(prereg) {
  const seeds = Array.isArray(prereg?.seed_rule?.seeds) ? [...prereg.seed_rule.seeds] : [101, 202, 303, 404, 505];
  return {
    trial: 'trl-s2-008-control',
    status: 'RESOLVED',
    outcome: 'POSITIVE',
    metric: EXPECTED_METRIC.name,
    numerator: 7,
    denominator: 8,
    seedBinding: { seeds, source: 'PREREGISTERED', preregistered_seeds: seeds },
    holdoutBinding: {
      partition: 'HOLDOUT', read_at: '2026-01-01T01:00:00.000Z', decision_at: '2026-01-01T01:00:00.000Z', opened_before_decision_point: false, opens: 1, max_opens: 1,
    },
    budgetBinding: { reservation_id: 'rsv-s2-008-control', granted_units: 100, spent_units: 40, currency: 'UNITS' },
    evaluatorBinding: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    evaluator: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    calibration: {
      status: 'MEASURED',
      not_measured_reason: null,
      evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true },
    },
  };
}

/**
 * The control RUN, for the one control that corrupts a run rather than a trial
 * (`corrupted_data`). Its per-trial rows are projected from the FROZEN table's
 * declared counts — not from an executed campaign, and not from a run that
 * happened to be lying around — and it is marked `synthetic: true` so a reader
 * can never mistake it for a result. The control needs a run whose digests are
 * equal on both sides; asserting a real campaign's numbers here would make the
 * gate depend on the campaign, and a gate that depends on the thing it polices
 * polices nothing.
 */
function controlRun(prereg, base) {
  const seeds = Array.isArray(prereg?.seed_rule?.seeds) ? [...prereg.seed_rule.seeds] : [101, 202, 303, 404, 505];
  const trials = EXPECTED_TRIAL_DECISIONS.map((row) => ({
    index: row.index,
    trial: row.trial,
    status: row.expectedStatus,
    outcome: row.expectedOutcome,
    metric: EXPECTED_METRIC.name,
    numerator: row.expectedNumerator,
    denominator: row.expectedDenominator,
    seeds,
    seedBinding: { seeds, source: 'PREREGISTERED', preregistered_seeds: seeds },
    holdoutBinding: {
      partition: 'HOLDOUT', read_at: '2026-01-01T01:00:00.000Z', decision_at: '2026-01-01T01:00:00.000Z', opened_before_decision_point: false, opens: 1, max_opens: 1,
    },
    budgetBinding: { reservation_id: 'rsv-s2-008-control', granted_units: 100, spent_units: row.index, currency: 'UNITS' },
    evaluatorBinding: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    evaluator: { evaluator_id: 'evl-s2-008-control', independent: true, blind_to_producer: true },
    calibration: { status: 'MEASURED', not_measured_reason: null, evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true } },
  }));
  return {
    synthetic: true,
    note: 'a CONTROL FIXTURE projected from the frozen table, not an executed campaign; the corrupted_data control needs a run whose digests are equal on both sides',
    commit_sha: base.commit_sha,
    tree_sha: base.tree_sha,
    raw_run_id: 's2-008-control-fixture-a',
    nonce: 'n-ctl-0123456789abcdef',
    executor_id: 'exec-s2-008-control',
    preregistration_digest: prereg?.preregistration_digest ?? null,
    expected_table_digest: prereg?.expected_table_digest ?? null,
    trials,
  };
}

/**
 * THE GATE MAPPING, as a pure function of the two records, so it can be checked
 * without a probe world. Four inputs, four answers, and the two middle ones are
 * kept apart on purpose:
 *
 *   nothing wrong                                   -> 0 PASS
 *   a defence failed (probe failed, counter moved,
 *     a control did not flip)                       -> 1 BLOCKED_SAFETY
 *   a defence is UNPROVEN (something did not run)
 *     and nothing failed                             -> 3 NOT_RUN
 *   a defence failed AND something did not run       -> 1 BLOCKED_SAFETY
 *     (a failure dominates: an unrun control must never soften a real failure)
 *
 * @param {{expectedProbes: number, results: ReadonlyArray<object>,
 *   notRun: ReadonlyArray<object>, broken: ReadonlyArray<object>,
 *   controls: ReadonlyArray<object>, controlsNotRun: ReadonlyArray<object>,
 *   counters: Record<string, number>}} input
 * @returns {{exitCode: number, status: string, reasons: string[]}}
 */
export function gateExitCode({ expectedProbes, results, notRun, broken, controls, controlsNotRun, counters, comparatorIntegrityOk = true }) {
  const movedCounters = Object.entries(counters ?? {}).filter(([, value]) => value !== 0).map(([name, value]) => `${name}=${value}`);
  const failedProbes = (results ?? []).filter((entry) => entry.status === 'failed').map((entry) => entry.probe);
  const didNotFlip = (controls ?? []).filter((entry) => entry.flipped !== true).map((entry) => entry.id);
  const reasons = [];
  if ((results ?? []).length !== expectedProbes) reasons.push(`probe-count:${(results ?? []).length}/${expectedProbes}`);
  if ((notRun ?? []).length > 0) reasons.push(`probe-not-run:${(notRun ?? []).map((entry) => entry.probe).join(',')}`);
  if ((broken ?? []).length > 0) reasons.push(`probe-broken:${(broken ?? []).map((entry) => entry.probe).join(',')}`);
  if (failedProbes.length > 0) reasons.push(`probe-failed:${failedProbes.join(',')}`);
  if ((controlsNotRun ?? []).length > 0) reasons.push(`control-not-run:${(controlsNotRun ?? []).map((entry) => entry.id).join(',')}`);
  if (didNotFlip.length > 0) reasons.push(`control-did-not-flip:${didNotFlip.join(',')}`);
  // S9: a control id nobody declared is an unnamed control, and a corruption
  // class the table control did not inject is a class whose detection the
  // control does not demonstrate. Both are reported here, at the gate, rather
  // than only in the record a reader may not open.
  const unaccounted = (controls ?? [])
    .filter((entry) => !EXPECTED_CONTROLS.some((descriptor) => descriptor.id === entry.id)
      && !EXTRA_CONTROL_IDS.includes(String(entry.id)))
    .map((entry) => String(entry.id));
  if (unaccounted.length > 0) reasons.push(`control-id-unaccounted:${unaccounted.join(',')}`);
  const coverage = (controls ?? []).find((entry) => entry.id === 'corrupted_data')?.coverage ?? null;
  if (coverage !== null) {
    const unproductive = Array.isArray(coverage.variants_unproductive) ? coverage.variants_unproductive : [];
    if (unproductive.length > 0) reasons.push(`corruption-variant-unproductive:${unproductive.join(',')}`);
    const injected = Array.isArray(coverage.variants_injected) ? coverage.variants_injected : [];
    const missing = CORRUPTION_VARIANTS_INJECTED.filter((variant) => !injected.includes(variant));
    if (missing.length > 0) reasons.push(`corruption-variant-never-injected:${missing.join(',')}`);
  }
  if (movedCounters.length > 0) reasons.push(`hard-gate-counter:${movedCounters.join(',')}`);
  // F4: the comparator's decision arithmetic. A comparator that cannot
  // reproduce the frozen campaign decision is a broken instrument, and a
  // broken instrument produces green probes: the six families attack the RUN's
  // integrity and would not notice a decision function that always answers
  // POSITIVE. It is a FAILURE, not a NOT_RUN: the check ran, and it did not
  // hold.
  if (comparatorIntegrityOk !== true) reasons.push('comparator-decision-arithmetic:the frozen campaign decision is not what the comparator derives');
  if (reasons.length === 0) return { exitCode: EXIT_PASS, status: 'PASS', reasons };
  // "Every counter is 0 but something mandatory did not run" is its own exit
  // code: the defence is unproven, which is neither a pass nor a failure.
  const countersClean = movedCounters.length === 0 && failedProbes.length === 0 && (broken ?? []).length === 0;
  const somethingNotRun = (notRun ?? []).length > 0 || (controlsNotRun ?? []).length > 0
    || (results ?? []).length !== expectedProbes || didNotFlip.length > 0
    || reasons.some((reason) => reason.startsWith('corruption-variant-') || reason.startsWith('control-id-unaccounted'));
  const exitCode = countersClean && somethingNotRun ? EXIT_NOT_RUN : EXIT_SAFETY;
  return { exitCode, status: exitCode === EXIT_NOT_RUN ? 'NOT_RUN' : 'BLOCKED_SAFETY', reasons };
}

/**
 * The comparator-integrity check the probes gate now raises (F4), as its own
 * exported function so a test can reach it without a probe run.
 *
 * PURE and fail-closed, and it is a CALL rather than a copy: the derivation is
 * `assertFrozenCampaignDerivable` from `campaign-expectation.mjs`, the same
 * function `scripts/s2-008-build-corpus.mjs` and both acceptance gates use. A
 * second copy of the arithmetic here would be exactly the "two independently
 * editable payload forms" failure the header of this file exists to prevent,
 * and it would keep passing after the real comparator was rewired.
 *
 * @returns {{ok: boolean, decision: string|null, declared: string, reason: string|null, refusal: string|null}}
 *   `ok` is false when the comparator derives a decision the frozen table does
 *   not declare, or when the derivation raises at all — a comparator that
 *   throws is not a comparator that passed.
 */
export function comparatorIntegrity() {
  const declared = String(EXPECTED_CAMPAIGN?.decision ?? 'ABSENT');
  try {
    const derived = assertFrozenCampaignDerivable();
    const ok = derived.decision === declared;
    return {
      ok,
      decision: derived.decision,
      declared,
      reason: derived.decisionReason,
      refusal: ok ? null : `the comparator derives ${derived.decision} while the frozen table declares ${declared}`,
    };
  } catch (error) {
    return {
      ok: false,
      decision: null,
      declared,
      reason: null,
      refusal: `the frozen campaign decision could not be re-derived: ${String(error?.code ?? 'REFUSED')} ${String(error?.message ?? error).slice(0, 200)}`,
    };
  }
}

export async function runSecurityProbes(args = {}) {
  const corpusDir = typeof args.corpus === 'string' ? path.resolve(args.corpus) : COMMITTED_CORPUS_DIR;
  const base = resolveBase();
  const prereg = loadPreregistration(corpusDir);

  // 1. The six families on ONE purged root.
  const probes = await runAllProbes({ registryRoot: SCRATCH, corpusDir });
  const probeCount = PROBE_FAMILIES.reduce((total, family) => total + PROBE_NAMES[family].length, 0);
  log(`A1 probes ran=${probes.results.length}/${probeCount} allPassed=${String(probes.allPassed)} notRun=${probes.notRun.length} broken=${probes.broken.length}`);
  for (const result of probes.results) {
    log(`A1 probe ${result.family}/${result.probe} status=${result.status} counter=${result.counter} counted=${String(result.counted)}`);
  }
  log(`A1 counters ${JSON.stringify(probes.counters)}`);
  log(`A1 purge base=${probes.purged.base} removed=${probes.purged.removed} of ${probes.purged.roots} removed_roots=${JSON.stringify(probes.purged.removed_roots)}`);

  // 2. The six negative controls.
  const trial = controlTrial(prereg);
  const run = controlRun(prereg, base);
  const controls = runNegativeControls({ trial, cleanRun: run, runA: run, runB: run, card: prereg.card });
  const gate = controlsFlipVerdict(controls);
  log(`A2 controls ran=${controls.controls.length}/${EXPECTED_CONTROLS.length} allFlipped=${String(controls.allFlipped)} gate_ok=${String(gate.ok)} notRun=${controls.notRun.length}`);
  for (const control of controls.controls) {
    log(`A2 control ${control.id} ${control.before} -> ${control.after} flipped=${String(control.flipped)} counter=${String(control.counter)}`);
  }
  for (const failure of gate.failures ?? []) log(`A2 gate failure ${failure}`);

  // 2b. F4: THE COMPARATOR'S DECISION ARITHMETIC IS A GATE HERE TOO.
  //
  //     The six probe families are holdout peek, seed-set freeze, post-result
  //     rewrite, budget, causal label and evaluator independence. None of them
  //     calls `decisionFromInterval`, and none of them needs to: they are
  //     attacks on the RUN's integrity, not on the DECISION rule. The measured
  //     consequence is a real one — a comparator whose first statement was
  //     `return {decision: 'POSITIVE'}` left this gate at exit 0 with 6/6
  //     probes passed (reproduction F4), and the honest answer on this corpus is
  //     UNRESOLVED, so a comparator that cannot say UNRESOLVED is not
  //     fail-closed, it is just wrong.
  //
  //     The check re-derives the frozen campaign decision through the
  //     comparator's own rule from the frozen table's own counts — the SAME
  //     function the corpus builder and both gates call, never a second
  //     arithmetic copy — and compares it with the declaration. It is a
  //     REFUSAL this gate raises, so a comparator that always answers POSITIVE,
  //     always answers NULL, or throws a verdict out of a constant is exit 1
  //     here instead of exit 0 with six green probes.
  const integrity = comparatorIntegrity();
  log(`A3 comparator_integrity ok=${String(integrity.ok)} decision=${String(integrity.decision)} declared=${String(integrity.declared)} reason=${integrity.refusal ?? 'agrees'}`);
  if (!integrity.ok) log(`A3 comparator_integrity REFUSED ${JSON.stringify(integrity)}`);

  // 3. The exit code, derived from the two records and nothing else.
  const gate_ = gateExitCode({
    expectedProbes: probeCount,
    results: probes.results,
    notRun: probes.notRun,
    broken: probes.broken,
    controls: controls.controls,
    controlsNotRun: controls.notRun,
    counters: probes.counters,
    // F4: a comparator whose decision arithmetic does not reproduce the frozen
    // declaration is a failure, and it is counted as one next to the probes.
    comparatorIntegrityOk: integrity.ok,
  });
  const { exitCode, status, reasons } = gate_;

  const record = {
    ticket: 'S2-008',
    gate: 'test:s2-008-security-probes',
    script: 'scripts/s2-008-security-probes.mjs',
    version: probes.version,
    status,
    ok: exitCode === EXIT_PASS,
    exitCode,
    reasons,
    base,
    corpus: path.relative(REPO_ROOT, corpusDir),
    hardGates: {
      counters: probes.counters,
      names: [...HARD_GATE_COUNTERS],
      ok: Object.values(probes.counters).every((value) => value === 0),
      moved: Object.entries(probes.counters).filter(([, value]) => value !== 0).map(([name, value]) => `${name}=${value}`),
    },
    totals: {
      families: PROBE_FAMILIES.length,
      probes: probeCount,
      probes_ran: probes.results.length,
      passed: probes.results.filter((entry) => entry.status === 'pass').length,
      failed: probes.results.filter((entry) => entry.status === 'failed').length,
      not_run: probes.notRun.length,
      broken: probes.broken.length,
      // S9 / S2: the control counts are ITEMISED, because `declared: 6, ran: 7`
      // reads like a bug until the seventh is named. The frozen six are the
      // ticket's set; `controls_extra_declared` is the named extra that closes
      // the `decision_point` spelling gap in the holdout binding; and
      // `corruption_variants_injected` itemises the frozen corruption classes
      // the table control actually injected (it used to inject one of four).
      controls_declared: EXPECTED_CONTROLS.length,
      controls_extra_declared: EXTRA_CONTROL_IDS.length,
      controls_extra_ids: [...EXTRA_CONTROL_IDS],
      controls_ran: controls.controls.length,
      controls_flipped: controls.controls.filter((entry) => entry.flipped === true).length,
      controls_unaccounted: controls.controls
        .filter((entry) => !EXPECTED_CONTROLS.some((descriptor) => descriptor.id === entry.id)
          && !EXTRA_CONTROL_IDS.includes(String(entry.id)))
        .map((entry) => String(entry.id)),
      corruption_variants_declared: [...CORRUPTION_VARIANTS_INJECTED],
      corruption_variants_injected: [...(controls.controls.find((entry) => entry.id === 'corrupted_data')?.coverage?.variants_injected ?? [])],
      corruption_variants_unproductive: [...(controls.controls.find((entry) => entry.id === 'corrupted_data')?.coverage?.variants_unproductive ?? [])],
      sensitivity: controls.sensitivity ?? null,
    },
    purged: purgedRecordForCommit(probes.purged),
    familiesAttempted: PROBE_FAMILIES.map((family) => ({
      family,
      probes: [...PROBE_NAMES[family]],
      status: probes.results.filter((entry) => entry.family === family)
        .every((entry) => entry.status === 'pass') ? 'pass' : 'failed',
    })),
    probes: {
      results: probes.results,
      notRun: probes.notRun,
      broken: probes.broken,
    },
    controls: {
      allFlipped: controls.allFlipped,
      gate,
      notRun: controls.notRun,
      records: controls.controls,
      digest: controls.digest,
    },
    // The control fixtures, named so nobody reads them as results.
    control_fixtures: { trial: 'synthetic: one ALLOW trial with four satisfied bindings', run: 'synthetic: projected from EXPECTED_TRIAL_DECISIONS' },
    // F4: the comparator-integrity member, published with the probes it did not
    // replace. The six families are unchanged, the sixth negative control is
    // unchanged, and the gate additionally refuses a comparator that cannot
    // re-derive the frozen campaign decision.
    comparator_integrity: integrity,
  };
  log(`RESULT status=${status} exit_code=${exitCode} reasons=${JSON.stringify(reasons)}`);

  let written = null;
  if (args.write === true || args.write === 'true') {
    const outFile = path.join(REPO_ROOT, OUT_RELATIVE);
    mkdirSync(path.dirname(outFile), { recursive: true });
    const body = `${JSON.stringify(record, null, 2)}\n`;
    writeFileSync(outFile, body, 'utf8');
    written = { path: OUT_RELATIVE, bytes: Buffer.byteLength(body), digest: canonicalDigest(record) };
    log(`wrote ${OUT_RELATIVE} digest=${written.digest} bytes=${written.bytes}`);
  }
  return { record, exitCode, evidence: written ?? {} };
}

async function main() {
  const args = parseArgs(process.argv);
  const result = await runSecurityProbes(args);
  if (args.printRecord === true) {
    process.stdout.write(`${JSON.stringify(result.record, null, 2)}\n`);
  } else {
    process.stdout.write(`${JSON.stringify({
      ticket: 'S2-008',
      gate: 'test:s2-008-security-probes',
      status: result.record.status,
      ok: result.record.ok,
      exitCode: result.exitCode,
      counters: result.record.hardGates.counters,
      totals: result.record.totals,
      reasons: result.record.reasons,
      ...result.evidence,
    }, null, 2)}\n`);
  }
  process.exitCode = result.exitCode;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  main().catch((error) => {
    // An untyped throw out of the gate is a gate failure, never a green run.
    process.stderr.write(`${JSON.stringify({
      ticket: 'S2-008',
      gate: 'test:s2-008-security-probes',
      status: 'BLOCKED_SAFETY',
      ok: false,
      exitCode: EXIT_SAFETY,
      code: String(error?.code ?? 'PROBE_GATE_ERROR'),
      error: String(error?.message ?? error).slice(0, 600),
      stack: String(error?.stack ?? '').split('\n').slice(0, 6),
    }, null, 2)}\n`);
    process.exitCode = EXIT_SAFETY;
  });
}
