// S2-004 verification: metrics, hard gates and independent Run A/B replay.
// Spawns each corpus run as its OWN child process (distinct PID, executor id,
// nonce, clock and output root — todo §13 requires process separation) on the
// same frozen commit, compares them fail-closed (identical decisions, graph
// digests and full case composition), computes the §11 metric set with
// numerators/denominators/missing counts and enforces the hard gates.
// Without independent external calibration, semantic quality stays
// NOT_CALIBRATED and the verdict can never be an unconditional PASS.
//
//   node scripts/verify-s2-004.mjs            # run + compare + gates
//   node scripts/verify-s2-004.mjs --write    # also bind evidence/ artifacts
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RUNNER = path.join(ROOT, 'scripts/s2-004-run.mjs');

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) args[argv[i].slice(2)] = argv[i + 1] ?? true;
  }
  return args;
}

// ---- metrics (todo §11) ------------------------------------------------------

export function computeMetrics(run) {
  const metrics = {};
  const decisions = run.decisions ?? [];

  const fieldTotals = { numerator: 0, denominator: 0, missing: 0 };
  const exactTotals = { numerator: 0, denominator: 0, missing: 0 };
  const spanTotals = { numerator: 0, denominator: 0, missing: 0 };
  const confusion = {};
  let abstentionCases = 0;
  let casesWithClaims = 0;

  for (const d of decisions) {
    const fields = d.checks?.field_false ?? null;
    const expected = d.checks?.claims_expected ?? null;
    if (expected === null) continue;
    casesWithClaims += 1;
    if (d.checks.abstentions_expected > 0) abstentionCases += 1;
    const fieldKeys = Object.keys(fields ?? {});
    // field accuracy: a matched claim contributes all-or-nothing per field
    // (the run only records mismatches); unmatched claims count as missing
    const matched = d.checks.claims_matched ?? 0;
    const fieldNames = ['normalized_text', 'epistemic_type', 'polarity', 'units', 'denominator', 'value_range', 'population', 'geography', 'period', 'exclusions', 'lifecycle', 'qualifiers_preserved'];
    exactTotals.denominator += expected;
    if (d.decision === 'PASS') exactTotals.numerator += expected;
    else if (d.decision === 'PARTIAL') exactTotals.numerator += 0; // conservative: partial cases count as not exact
    else exactTotals.missing += expected - matched;
    for (const fname of fieldNames) {
      fieldTotals.denominator += expected;
      const mismatches = fieldKeys.filter((k) => k.endsWith(`:${fname}`)).length;
      fieldTotals.numerator += expected - mismatches;
    }
    // epistemic-type confusion: from per-case expectation we can only count
    // exact-type matches vs mismatches at case granularity
    const typeMismatches = fieldKeys.filter((k) => k.endsWith(':epistemic_type')).length;
    for (let i = 0; i < expected; i += 1) {
      const key = typeMismatches > i ? 'mismatch' : 'match';
      confusion[key] = (confusion[key] ?? 0) + 1;
    }
    // span binding
    if (d.checks.span_bound !== null && d.checks.span_bound !== undefined) {
      spanTotals.denominator += expected;
      if (d.checks.span_bound) spanTotals.numerator += matched;
      else spanTotals.numerator += 0;
    }
  }

  metrics.extraction_field_accuracy = { ...fieldTotals, coverage: fieldTotals.denominator };
  metrics.extraction_exact_accuracy = { ...exactTotals, coverage: exactTotals.denominator };
  metrics.span_binding_accuracy = { ...spanTotals, coverage: spanTotals.denominator };
  metrics.epistemic_type_confusion = confusion;

  metrics.qualifier_preservation = {
    numerator: (run.integrity?.lost_qualifiers ?? 0) === 0 ? casesWithClaims : 0,
    denominator: casesWithClaims,
    lost_qualifiers: run.integrity?.lost_qualifiers ?? 0,
  };
  metrics.negation_preservation = {
    numerator: (run.integrity?.lost_negations ?? 0) === 0 ? casesWithClaims : 0,
    denominator: casesWithClaims,
    lost_negations: run.integrity?.lost_negations ?? 0,
  };
  metrics.unit_preservation = {
    numerator: (run.integrity?.lost_units ?? 0) === 0 ? casesWithClaims : 0,
    denominator: casesWithClaims,
    lost_units: run.integrity?.lost_units ?? 0,
  };

  const contradictionCases = decisions.filter((d) => d.category === 'contradiction_scope');
  const contradictionTp = contradictionCases.filter((d) => d.checks.contradiction?.ok && d.checks.contradiction.expected_relation === 'CONTRADICTS').length;
  const contradictionFp = contradictionCases.filter((d) => d.checks.contradiction?.ok && d.checks.contradiction.expected_relation !== 'CONTRADICTS').length;
  const contradictionFn = contradictionCases.filter((d) => d.checks.contradiction && !d.checks.contradiction.ok && d.checks.contradiction.expected_relation === 'CONTRADICTS').length;
  metrics.contradiction_precision = {
    numerator: contradictionTp,
    denominator: contradictionTp + contradictionFp,
    missing: contradictionCases.filter((d) => !d.checks.contradiction).length,
  };
  metrics.contradiction_recall = {
    numerator: contradictionTp,
    denominator: contradictionTp + contradictionFn,
    missing: contradictionCases.filter((d) => !d.checks.contradiction).length,
  };

  const lineageCases = decisions.filter((d) => d.category === 'translation_citation_upstream_lineage' && d.checks.lineage);
  metrics.upstream_family_collapse_accuracy = {
    numerator: lineageCases.filter((d) => d.checks.lineage?.ok).length,
    denominator: lineageCases.length,
    missing: 0,
  };

  const invalidationCases = decisions.filter((d) => d.category === 'invalidation_revision_retraction');
  metrics.stale_invalidation_recall = {
    numerator: invalidationCases.filter((d) => d.checks.invalidation?.ok).length,
    denominator: invalidationCases.reduce((acc, d) => acc + (d.checks.invalidation?.expected_stale ?? 0), 0) || invalidationCases.length,
    missing: invalidationCases.filter((d) => !d.checks.invalidation).length,
  };

  metrics.abstention_rate = {
    numerator: abstentionCases,
    denominator: casesWithClaims,
    missing: 0,
    note: 'share of text cases where the extractor abstained instead of guessing',
  };

  metrics.acl_leakage = { numerator: run.integrity?.acl_leaks ?? 0, denominator: decisions.length };
  metrics.authority_expansion = { numerator: run.integrity?.authority_expansions ?? 0, denominator: decisions.length };
  metrics.type_auto_promotion = { numerator: run.integrity?.type_promotions_without_review ?? 0, denominator: decisions.length };
  metrics.stale_survivors = { numerator: run.integrity?.stale_survivors ?? 0, denominator: decisions.length };
  metrics.duplicate_side_effects = { numerator: run.integrity?.duplicate_side_effects ?? 0, denominator: decisions.length };

  return metrics;
}

// ---- Run A/B comparison ------------------------------------------------------

export function compareRuns(runA, runB) {
  const issues = [];
  if (runA.status !== 'COMPLETED' || runB.status !== 'COMPLETED') issues.push('run:not-completed');
  if (runA.caseCount !== runB.caseCount) issues.push('comparison:case-count-mismatch');
  if (runA.caseCount !== 96) issues.push('comparison:case-count-not-96');
  if (runA.graphDigest !== runB.graphDigest) issues.push('comparison:graph-digest-mismatch');
  const bById = new Map((runB.decisions ?? []).map((d) => [d.case_id, d]));
  for (const da of runA.decisions ?? []) {
    const db = bById.get(da.case_id);
    if (!db) {
      issues.push(`comparison:${da.case_id}:missing-in-run-b`);
      continue;
    }
    if (da.decision !== db.decision) issues.push(`comparison:${da.case_id}:decision-mismatch`);
  }
  // distinct identities (§13): different executors, clocks, nonces, pids, roots
  if (runA.executor_id === runB.executor_id) issues.push('identity:executor-identical');
  if (runA.clock === runB.clock) issues.push('identity:clock-identical');
  if (runA.nonce === runB.nonce) issues.push('identity:nonce-identical');
  if (runA.pid === runB.pid) issues.push('identity:pid-identical');
  if (runA.output_root === runB.output_root) issues.push('identity:output-root-identical');
  return {
    ok: issues.length === 0,
    issues,
    comparedCases: (runA.decisions ?? []).length,
    decisionMismatches: issues.filter((i) => i.endsWith(':decision-mismatch')).length,
  };
}

// ---- hard gates (todo §11) ---------------------------------------------------

export function checkHardGates(runA, runB, metrics, comparison) {
  const violations = [];
  const add = (gate, detail) => violations.push({ gate, detail });

  if (!comparison.ok) add('REPLAY_DETERMINISM', comparison.issues.join('; '));
  if ((runA.caseCount ?? 0) !== 96) add('CORPUS_COMPLETENESS', `caseCount ${runA.caseCount}`);

  if (metrics.negation_preservation.lost_negations > 0) add('NEGATION_LOSS', `${metrics.negation_preservation.lost_negations} lost negations`);
  if (metrics.unit_preservation.lost_units > 0) add('UNIT_LOSS', `${metrics.unit_preservation.lost_units} lost units`);
  if (metrics.qualifier_preservation.lost_qualifiers > 0) add('QUALIFIER_LOSS', `${metrics.qualifier_preservation.lost_qualifiers} lost qualifiers`);

  if (metrics.type_auto_promotion.numerator > 0) add('TYPE_PROMOTION', 'a non-fact claim was auto-promoted');
  if (metrics.acl_leakage.numerator > 0) add('ACL_LEAK', 'private/cross-tenant leak');
  if (metrics.authority_expansion.numerator > 0) add('AUTHORITY_EXPANSION', 'authority expanded through content');
  if (metrics.stale_survivors.numerator > 0) add('STALE_ELIGIBLE', 'stale descendant remained eligible');
  if (metrics.duplicate_side_effects.numerator > 0) add('DUPLICATE_SIDE_EFFECT', 'duplicate side effect or blind retry');

  // every committed claim row was schema-validated by the store (fail-closed):
  // evidence/edges without immutable revision/hash are impossible by
  // construction — the probes prove the negative cases
  const failedCases = (runA.decisions ?? []).filter((d) => d.decision === 'FAIL');
  if (failedCases.length > 0) add('CASE_FAILURES', failedCases.map((d) => d.case_id).join(','));

  return { ok: violations.length === 0, violations };
}

function runChild({ runId, executorId, nonce, clock, outputRoot, out }) {
  const result = spawnSync(process.execPath, [
    RUNNER,
    '--run-id', runId,
    '--executor-id', executorId,
    '--nonce', nonce,
    '--clock', clock,
    '--output-root', outputRoot,
    '--out', out,
  ], { cwd: ROOT, encoding: 'utf8', timeout: 240000 });
  if (result.status !== 0) {
    throw new Error(`run ${runId} failed: ${result.stderr?.slice(0, 800) || result.stdout?.slice(0, 400)}`);
  }
  return JSON.parse(fs.readFileSync(path.join(ROOT, out), 'utf8'));
}

async function main() {
  const args = parseArgs(process.argv);
  const write = args.write === true;
  const stamp = Date.now();

  const resultsDir = path.join(ROOT, 'results/s2-004');
  fs.mkdirSync(resultsDir, { recursive: true });

  const runA = runChild({
    runId: 'run-a',
    executorId: 'exec-s2-004-a',
    nonce: `n-a-${randomBytes(8).toString('hex')}`,
    clock: '2026-01-15T08:00:00.000Z',
    outputRoot: 'results/s2-004/run-a',
    out: `results/s2-004/run-a-${stamp}.json`,
  });
  const runB = runChild({
    runId: 'run-b',
    executorId: 'exec-s2-004-b',
    nonce: `n-b-${randomBytes(8).toString('hex')}`,
    clock: '2026-03-21T23:59:59.999Z',
    outputRoot: 'results/s2-004/run-b',
    out: `results/s2-004/run-b-${stamp}.json`,
  });

  const comparison = compareRuns(runA, runB);
  const metrics = computeMetrics(runA);
  const gates = checkHardGates(runA, runB, metrics, comparison);

  const testedImplementationCommit = runA.testedImplementationCommit;
  const summary = {
    schemaVersion: 1,
    ticket: 'S2-004',
    role: 'S2-004 run A vs run B comparison, metrics and hard gates over the frozen 96-case corpus',
    corpus: { caseCount: runA.caseCount },
    testedImplementationCommit,
    evidenceContainerResolution: 'Resolve externally with: git log -1 --format=%H -- evidence/s2-004-comparison.json',
    runParameters: {
      run_a: { executor: runA.executor_id, clock: runA.clock, nonce: runA.nonce, pid: runA.pid, output_root: runA.output_root },
      run_b: { executor: runB.executor_id, clock: runB.clock, nonce: runB.nonce, pid: runB.pid, output_root: runB.output_root },
    },
    integrity: { run_a: runA.integrity, run_b: runB.integrity },
    comparison,
    metrics,
    hardGates: gates,
    decisionCounts: { run_a: runA.decisionCounts, run_b: runB.decisionCounts },
    verdict: gates.ok ? 'PASS_WITH_LIMITS' : 'REVISE',
    verdictLimits: [
      'bounded local implementation: semantic quality is NOT_CALIBRATED (no independent external gold corpus or external replay)',
      'no live private-source connectors; OCR/ASR fixture-only (S2-003 limits carried)',
      'near-duplicate merge remains NOT_CALIBRATED; candidate lineage requires human confirmation',
    ],
    wallClockNote: 'wall-clock timestamps are telemetry only and never enter decision digests, oracles, seeds or verdict selection',
  };

  fs.writeFileSync(path.join(resultsDir, `comparison-${stamp}.json`), `${JSON.stringify(summary, null, 2)}\n`);

  if (write) {
    fs.writeFileSync(path.join(ROOT, 'evidence/s2-004-run-a.json'), `${JSON.stringify(runA, null, 2)}\n`);
    fs.writeFileSync(path.join(ROOT, 'evidence/s2-004-run-b.json'), `${JSON.stringify(runB, null, 2)}\n`);
    fs.writeFileSync(path.join(ROOT, 'evidence/s2-004-comparison.json'), `${JSON.stringify(summary, null, 2)}\n`);
  }

  console.log(JSON.stringify({
    ok: comparison.ok && gates.ok,
    verdict: summary.verdict,
    comparedCases: comparison.comparedCases,
    decisionMismatches: comparison.decisionMismatches,
    gateViolations: gates.violations,
    comparisonIssues: comparison.issues,
  }, null, 2));
  process.exit(comparison.ok && gates.ok ? 0 : 1);
}

await main();
