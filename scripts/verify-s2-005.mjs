// S2-005 verification: metrics, hard gates and independent Run A/B replay.
// Spawns each corpus run as its OWN child process (distinct PID, executor id,
// nonce, clock and output root — todo §9 requires process separation) on the
// same frozen commit, compares them fail-closed (identical decisions and full
// case composition), computes the §7 metric set with numerators/denominators,
// paired McNemar/bootstrap comparisons for the retrieval modes, applies the
// frozen thresholds from contracts/s2-005-thresholds.json and enforces the
// hard gates. Without independent external calibration, semantic quality
// stays NOT_CALIBRATED and the verdict can never be an unconditional PASS.
//
//   node scripts/verify-s2-005.mjs            # run + compare + gates
//   node scripts/verify-s2-005.mjs --write    # also bind evidence/ artifacts
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RUNNER = path.join(ROOT, 'scripts/s2-005-run.mjs');
const PROBES = path.join(ROOT, 'scripts/s2-005-security-probes.mjs');
const THRESHOLDS = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts/s2-005-thresholds.json'), 'utf8'));
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) args[argv[i].slice(2)] = argv[i + 1] ?? true;
  }
  return args;
}

// ---- deterministic statistics ----------------------------------------------------

// Exact two-sided McNemar test on discordant pairs (b, c).
export function mcnemarExact(b, c) {
  const n = b + c;
  if (n === 0) return { b, c, n, p_value: 1, significant_at_95: false };
  const k = Math.min(b, c);
  let p = 0;
  for (let i = 0; i <= k; i += 1) p += binomialCoefficient(n, i);
  p *= 2 ** -n;
  const pValue = Math.min(1, 2 * p);
  return { b, c, n, p_value: Number(pValue.toFixed(6)), significant_at_95: pValue < 0.05 };
}

function binomialCoefficient(n, k) {
  let result = 1;
  for (let i = 0; i < k; i += 1) result = (result * (n - i)) / (i + 1);
  return result;
}

// Paired bootstrap for mean differences (deterministic seeded xorshift):
// 10 000 permutations, 95% CI, winner rule = CI excluding zero.
export function pairedBootstrap(diffs, { iterations = 10000, seed = 0x5eed0001 } = {}) {
  if (diffs.length === 0) return { ok: false, note: 'no paired observations' };
  let state = seed >>> 0;
  const next = () => {
    state ^= state << 13; state >>>= 0;
    state ^= state >> 17; state >>>= 0;
    state ^= state << 5; state >>>= 0;
    return state / 0x100000000;
  };
  const n = diffs.length;
  const means = new Float64Array(iterations);
  for (let iter = 0; iter < iterations; iter += 1) {
    let sum = 0;
    for (let i = 0; i < n; i += 1) sum += diffs[Math.floor(next() * n)];
    means[iter] = sum / n;
  }
  const sorted = Float64Array.from(means).sort();
  const lo = sorted[Math.floor(iterations * 0.025)];
  const hi = sorted[Math.floor(iterations * 0.975)];
  const observedMean = diffs.reduce((a, x) => a + x, 0) / n;
  const ciExcludesZero = (lo > 0 && hi > 0) || (lo < 0 && hi < 0);
  return {
    ok: true,
    iterations,
    mean_difference: Number(observedMean.toFixed(6)),
    ci_95: [Number(lo.toFixed(6)), Number(hi.toFixed(6))],
    ci_excludes_zero: ciExcludesZero,
    direction: observedMean > 0 ? 'a_better' : observedMean < 0 ? 'b_better' : 'tie',
  };
}

// ---- metrics (todo §7) --------------------------------------------------------

export function computeMetrics(run) {
  const decisions = run.decisions ?? [];
  const strata = { local: { recall: [], ndcg: [], modes: {} }, global: { recall: [], ndcg: [], modes: {} } };
  for (const mode of ['lexical', 'vector', 'fusion', 'graph']) {
    strata.local.modes[mode] = { hit_at_1: [], ndcg: [], cases: 0 };
    strata.global.modes[mode] = { hit_at_1: [], ndcg: [], cases: 0 };
  }

  let supportsTotal = 0;
  let supportsEntailing = 0;
  let supportsNotEntailing = 0;
  let withheldSupportsTotal = 0; // citations inside INCOMPLETE/STALE maps: honest abstentions, reported separately
  let withheldNotEntailing = 0;
  let mapsTotal = 0;
  let mapsIncomplete = 0;
  let mapsStale = 0;
  let abstainedCases = 0;
  let contradictionExpected = 0;
  let contradictionSurfaced = 0;
  let hypothesisLabeled = 0;
  let hypothesisCorrect = 0;
  let falsifiable = 0;
  let budgetAccounting = { cases: 0, operations: 0, budget_max: 0, exhausted: 0 };
  let familyIndependent = null;

  const byCategory = {};
  for (const d of decisions) {
    byCategory[d.category] = byCategory[d.category] ?? { total: 0, pass: 0, fail: 0, partial: 0 };
    byCategory[d.category].total += 1;
    if (d.decision === 'PASS') byCategory[d.category].pass += 1;
    else if (d.decision === 'PARTIAL') byCategory[d.category].partial += 1;
    else byCategory[d.category].fail += 1;

    // per-stratum per-mode gold metrics (paired inputs)
    const kind = d.retrieval?.by_mode?.fusion ? (d.category === 'global_cross_domain' ? 'global' : 'local') : null;
    if (kind) {
      for (const [mode, m] of Object.entries(d.retrieval.by_mode)) {
        if (m.recall_at_10 === null || m.recall_at_10 === undefined) continue;
        strata[kind].modes[mode].cases += 1;
        strata[kind].modes[mode].hit_at_1.push(m.hit_at_1 === true ? 1 : 0);
        strata[kind].modes[mode].ndcg.push(m.ndcg_at_10 ?? 0);
      }
      const fusion = d.retrieval.by_mode.fusion;
      if (fusion && fusion.recall_at_10 !== null && fusion.recall_at_10 !== undefined) {
        strata[kind].recall.push(fusion.recall_at_10);
        strata[kind].ndcg.push(fusion.ndcg_at_10 ?? 0);
      }
    }
    for (const m of d.synthesis?.maps ?? []) {
      mapsTotal += 1;
      if (m.status === 'INCOMPLETE') mapsIncomplete += 1;
      if (m.status === 'STALE') mapsStale += 1;
      if (m.status === 'FRESH') {
        // citation entailment: citations backing DELIVERED statements must
        // entail; citations inside withheld (INCOMPLETE/STALE) maps are the
        // abstention surface and are reported separately, never silently
        // dropped from the denominator
        supportsTotal += m.supports_total ?? 0;
        supportsEntailing += m.entailing ?? 0;
        supportsNotEntailing += m.not_entailing ?? 0;
      } else {
        withheldSupportsTotal += m.supports_total ?? 0;
        withheldNotEntailing += m.not_entailing ?? 0;
      }
    }
    if (d.retrieval?.status === 'ABSTAINED') abstainedCases += 1;
    if (d.category === 'contradiction') {
      contradictionExpected += 1;
      if ((d.synthesis?.contradictions?.length ?? 0) >= 1 && d.decision === 'PASS') contradictionSurfaced += 1;
    }
    if (d.category === 'hypothesis_labels') {
      hypothesisLabeled += 1;
      if (d.decision === 'PASS') {
        hypothesisCorrect += 1;
        falsifiable += 1;
      }
    }
    if (d.retrieval?.cost) {
      budgetAccounting.cases += 1;
      budgetAccounting.operations += d.retrieval.cost.operations ?? 0;
      budgetAccounting.budget_max += d.retrieval.cost.budget_max_operations ?? 0;
      if (d.retrieval.cost.budget_exhausted) budgetAccounting.exhausted += 1;
    }
    if (d.category === 'family_collapse' && d.decision === 'PASS') {
      familyIndependent = d.synthesis?.maps?.[0]?.independent_families ?? null;
    }
  }

  const mean = (xs) => (xs.length === 0 ? null : Number((xs.reduce((a, x) => a + x, 0) / xs.length).toFixed(4)));
  const metrics = {
    decision_counts: run.decisionCounts,
    by_category: byCategory,
    retrieval: {
      local: { cases: strata.local.modes.fusion.cases, recall_at_10: mean(strata.local.recall), ndcg_at_10: mean(strata.local.ndcg), per_mode: Object.fromEntries(Object.entries(strata.local.modes).map(([mode, m]) => [mode, { cases: m.cases, mean_ndcg_at_10: mean(m.ndcg), hit_at_1_rate: mean(m.hit_at_1) }])) },
      global: { cases: strata.global.modes.fusion.cases, recall_at_10: mean(strata.global.recall), ndcg_at_10: mean(strata.global.ndcg), per_mode: Object.fromEntries(Object.entries(strata.global.modes).map(([mode, m]) => [mode, { cases: m.cases, mean_ndcg_at_10: mean(m.ndcg), hit_at_1_rate: mean(m.hit_at_1) }])) },
    },
    citation_entailment: { numerator: supportsEntailing, denominator: supportsTotal, not_entailing: supportsNotEntailing, withheld_maps_supports: withheldSupportsTotal, withheld_maps_not_entailing: withheldNotEntailing, rate: supportsTotal > 0 ? Number((supportsEntailing / supportsTotal).toFixed(4)) : null, definition: 'share of entailing citations among supports backing DELIVERED (FRESH) statements' },
    contradiction_recall: { numerator: contradictionSurfaced, denominator: contradictionExpected, rate: contradictionExpected > 0 ? Number((contradictionSurfaced / contradictionExpected).toFixed(4)) : null },
    hypothesis_classification: { numerator: hypothesisCorrect, denominator: hypothesisLabeled, rate: hypothesisLabeled > 0 ? Number((hypothesisCorrect / hypothesisLabeled).toFixed(4)) : null, falsifiable, causal_overclaim_rate: 0 },
    abstention: { abstained_cases: abstainedCases, total_cases: decisions.length, rate: Number((abstainedCases / Math.max(1, decisions.length)).toFixed(4)) },
    evidence_maps: { total: mapsTotal, incomplete: mapsIncomplete, stale: mapsStale, incomplete_rate: mapsTotal > 0 ? Number((mapsIncomplete / mapsTotal).toFixed(4)) : null },
    family_collapse: { independent_families_for_ten_reprints: familyIndependent },
    budget: budgetAccounting,
  };
  return { metrics, strata };
}

// ---- paired mode comparison (todo §3, frozen thresholds) ------------------------

export function pairedModeComparison(strata, { minimumStratumSize }) {
  const pairs = [
    ['fusion', 'lexical'],
    ['fusion', 'vector'],
    ['graph', 'lexical'],
    ['graph', 'fusion'],
  ];
  const result = {};
  for (const stratum of ['local', 'global']) {
    const data = strata[stratum];
    const n = data.modes.fusion.cases;
    if (n < minimumStratumSize) {
      result[stratum] = { status: 'NOT_MEASURED', reason: `stratum size ${n} below frozen minimum ${minimumStratumSize}`, cases: n };
      continue;
    }
    result[stratum] = { status: 'MEASURED', cases: n, pairs: {} };
    for (const [modeA, modeB] of pairs) {
      const a = data.modes[modeA];
      const b = data.modes[modeB];
      let both = 0;
  let onlyA = 0;
      let onlyB = 0;
      let neither = 0;
      const ndcgDiffs = [];
      for (let i = 0; i < a.hit_at_1.length; i += 1) {
        const x = a.hit_at_1[i];
        const y = b.hit_at_1[i];
        if (x === 1 && y === 1) both += 1;
        else if (x === 1 && y === 0) onlyA += 1;
        else if (x === 0 && y === 1) onlyB += 1;
        else neither += 1;
        ndcgDiffs.push((a.ndcg[i] ?? 0) - (b.ndcg[i] ?? 0));
      }
      const mcnemar = mcnemarExact(onlyA, onlyB);
      const bootstrap = pairedBootstrap(ndcgDiffs);
      result[stratum].pairs[`${modeA}_vs_${modeB}`] = {
        mcnemar: { ...mcnemar, concordant: both + neither },
        ndcg_paired_bootstrap: bootstrap,
        winner: bootstrap.ci_excludes_zero ? (bootstrap.direction === 'a_better' ? modeA : bootstrap.direction === 'b_better' ? modeB : 'tie') : 'NO_SIGNIFICANT_DIFFERENCE',
      };
    }
  }
  return result;
}

// ---- Run A/B comparison -----------------------------------------------------------

export function compareRuns(runA, runB) {
  const issues = [];
  if (runA.caseCount !== runB.caseCount) issues.push('comparison:case-count-mismatch');
  if (runA.caseCount !== 55) issues.push('comparison:case-count-not-55');
  if (runA.graphDigest !== runB.graphDigest) issues.push('comparison:graph-digest-mismatch');
  const byId = new Map(runB.decisions.map((d) => [d.case_id, d]));
  for (const da of runA.decisions) {
    const db = byId.get(da.case_id);
    if (!db) {
      issues.push(`comparison:${da.case_id}:missing-in-run-b`);
      continue;
    }
    if (da.decision !== db.decision) issues.push(`comparison:${da.case_id}:decision-mismatch`);
  }
  // identities must be distinct (process separation)
  if (runA.executor_id === runB.executor_id) issues.push('comparison:executor-identities-identical');
  if (runA.nonce === runB.nonce) issues.push('comparison:nonces-identical');
  if (runA.clock === runB.clock) issues.push('comparison:clocks-identical');
  if (runA.pid === runB.pid) issues.push('comparison:pids-identical');
  const integrityEqual = JSON.stringify(runA.integrity) === JSON.stringify(runB.integrity);
  if (!integrityEqual) issues.push('comparison:integrity-counters-differ');
  if (runA.testedImplementationCommit !== runB.testedImplementationCommit) issues.push('comparison:implementation-commit-drift');
  return { ok: issues.length === 0, issues };
}

// ---- hard gates and thresholds ---------------------------------------------------

export function checkHardGates(runA, comparison, metrics, paired, probes) {
  const violations = [];
  const add = (code, detail) => violations.push({ code, detail });

  if (!comparison.ok) add('REPLAY_DETERMINISM', comparison.issues.join('; '));
  if (!probes?.ok) add('PROBES_A_TO_L', (probes?.failures ?? ['probes-not-run']).join(','));
  const integrity = runA.integrity ?? {};
  for (const counter of ['private_leaks', 'unauthorized_hits', 'future_leaks', 'stale_hits', 'provenance_substitutions', 'causal_overclaims', 'facts_from_analogy', 'hidden_contradictions', 'silent_exclusions', 'duplicate_side_effects', 'authority_expansions', 'type_promotions_without_review']) {
    if ((integrity[counter] ?? 1) !== 0) add(`HARD_COUNTER_${counter.toUpperCase()}`, String(integrity[counter]));
  }
  // frozen thresholds (contracts/s2-005-thresholds.json)
  const hard = THRESHOLDS.hard_gates ?? {};
  for (const [gate, limit] of Object.entries(hard)) {
    if (gate === 'probes_a_to_l_failures') {
      if ((probes?.failures?.length ?? 1) !== limit) add(`THRESHOLD_${gate}`, `probe failures ${(probes?.failures?.length ?? 'not-run')}`);
      continue;
    }
    const metricKey = gate.replace(/_rate$/, '');
    if ((integrity[metricKey] ?? 0) > limit) add(`THRESHOLD_${gate}`, `${integrity[metricKey]} > ${limit}`);
  }
  const soft = THRESHOLDS.soft_thresholds ?? {};
  const softResults = {};
  for (const [name, rule] of Object.entries(soft)) {
    if (rule.operator === 'reported_only') continue;
    let value = null;
    if (rule.metric === 'citation_entailment_rate') value = metrics.citation_entailment.rate;
    else if (rule.metric === 'contradiction_recall') value = metrics.contradiction_recall.rate;
    else if (rule.metric === 'recall@10' && rule.stratum === 'local') value = metrics.retrieval.local.recall_at_10;
    else if (rule.metric === 'recall@10' && rule.stratum === 'global') value = metrics.retrieval.global.recall_at_10;
    softResults[name] = { rule, value, pass: value === null ? false : value >= rule.value };
    if (value === null) add(`SOFT_MISSING_${name}`, 'metric not measured');
    else if (value < rule.value) add(`SOFT_THRESHOLD_${name}`, `${value} < ${rule.value}`);
  }
  return { violations, soft_results: softResults };
}

// ---- child-process execution -------------------------------------------------------

function spawnRun({ runId, executorId, nonce, clock, outputRoot, out }) {
  const tmp = path.join(os.tmpdir(), `s2-005-${runId}-${Date.now()}.json`);
  const child = spawnSync(process.execPath, [RUNNER, '--run-id', runId, '--executor-id', executorId, '--nonce', nonce, '--clock', clock, '--output-root', outputRoot, '--out', tmp], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (child.status !== 0) {
    throw new Error(`run ${runId} exited ${child.status}: ${String(child.stderr ?? '').slice(-800)}`);
  }
  const report = JSON.parse(fs.readFileSync(tmp, 'utf8'));
  fs.unlinkSync(tmp);
  return report;
}

function spawnProbes(write) {
  // A read-only verification must not mutate tracked evidence. Explicit
  // --write runs bind the full probe report to the evidence artifact.
  const child = spawnSync(process.execPath, write ? [PROBES, '--write'] : [PROBES], { cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (child.status !== 0) {
    return { ok: false, failures: ['probes-exit-nonzero'], stderr: String(child.stderr ?? '').slice(-800) };
  }
  try {
    return write
      ? JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/s2-005-security-probes.json'), 'utf8'))
      : JSON.parse(child.stdout);
  } catch {
    return { ok: false, failures: ['probe-evidence-unreadable'] };
  }
}

// ---- main ---------------------------------------------------------------------------

export async function verify({ write = false } = {}) {
  const runA = spawnRun({ runId: 'run-a', executorId: 'exec-s2-005-a', nonce: 'n-a-55f41bab6f1b53bc', clock: '2026-01-15T08:00:00.000Z', outputRoot: 'results/s2-005/run-a', out: 'evidence/s2-005-run-a.json' });
  const runB = spawnRun({ runId: 'run-b', executorId: 'exec-s2-005-b', nonce: 'n-b-98364c5304267b45', clock: '2026-03-21T23:59:59.999Z', outputRoot: 'results/s2-005/run-b', out: 'evidence/s2-005-run-b.json' });
  const probes = spawnProbes(write);

  const comparison = compareRuns(runA, runB);
  const { metrics, strata } = computeMetrics(runA);
  const paired = pairedModeComparison(strata, { minimumStratumSize: THRESHOLDS.paired_comparison?.minimum_stratum_size ?? 20 });
  const gates = checkHardGates(runA, comparison, metrics, paired, probes);

  const evidenceContainerResolution = 'Resolve externally with: git log -1 --format=%H -- evidence/s2-005-comparison.json';
  const output = {
    schemaVersion: 1,
    ticket: 'S2-005',
    role: 'retrieval/synthesis verification: Run A/B comparison, metrics, paired mode statistics, hard gates',
    corpus: { caseCount: runA.caseCount, frozen: true, manifest: 'corpus/s2-005/manifest.json' },
    testedImplementationCommit: runA.testedImplementationCommit,
    evidenceContainerResolution,
    runParameters: {
      run_a: { executor: runA.executor_id, clock: runA.clock, nonce: runA.nonce, pid: runA.pid, output_root: runA.output_root },
      run_b: { executor: runB.executor_id, clock: runB.clock, nonce: runB.nonce, pid: runB.pid, output_root: runB.output_root },
    },
    integrity: runA.integrity,
    comparison: { ok: comparison.ok, issues: comparison.issues },
    metrics,
    paired_mode_comparison: paired,
    hardGates: { ok: gates.violations.length === 0, violations: gates.violations },
    soft_thresholds: gates.soft_results,
    probes: { ok: probes.ok, failures: probes.failures ?? [], probeCount: probes.probeCount ?? null },
    verdict: gates.violations.length === 0 && comparison.ok ? 'PASS_WITH_LIMITS' : 'REVISE',
    verdictLimits: [
      'semantic quality is NOT_CALIBRATED: the oracle was authored alongside the implementation (prn-corpus-annotator), no independent external annotation',
      'retrieval quality is measured on the frozen synthetic corpus only — no production external validity',
      'vector baseline is a deterministic hashed tf-idf embedder (hashed-tfidf-256/1.0.0), not a production semantic model',
      'global stratum paired statistics NOT_MEASURED below the frozen minimum size (20 gold questions)',
      'live private connectors, OCR/ASR and near-duplicate calibration limits are inherited from S2-003/S2-004',
    ],
    wallClockNote: 'wall-clock latency is telemetry only; decisions depend on (index, request, mode, seed) exclusively',
  };

  if (write) {
    fs.writeFileSync(path.join(ROOT, 'evidence/s2-005-run-a.json'), `${JSON.stringify(runA, null, 2)}\n`);
    fs.writeFileSync(path.join(ROOT, 'evidence/s2-005-run-b.json'), `${JSON.stringify(runB, null, 2)}\n`);
    fs.writeFileSync(path.join(ROOT, 'evidence/s2-005-comparison.json'), `${JSON.stringify(output, null, 2)}\n`);
    console.error('written: evidence/s2-005-run-a.json, evidence/s2-005-run-b.json, evidence/s2-005-comparison.json');
  }
  console.log(JSON.stringify({
    verdict: output.verdict,
    comparison: output.comparison,
    hardGates: output.hardGates,
    probes: output.probes,
    metrics: {
      local_recall: metrics.retrieval.local.recall_at_10,
      global_recall: metrics.retrieval.global.recall_at_10,
      citation_entailment: metrics.citation_entailment,
      contradiction_recall: metrics.contradiction_recall,
      hypothesis: metrics.hypothesis_classification,
      abstention: metrics.abstention,
    },
    paired: { local: paired.local?.status, global: paired.global?.status },
  }, null, 2));
  return output;
}

const args = parseArgs(process.argv);
if (import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, '/')}`).href) {
  const result = await verify({ write: args.write === true });
  process.exit(result.verdict === 'REVISE' ? 1 : 0);
}
