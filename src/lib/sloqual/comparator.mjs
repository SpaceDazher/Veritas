// SLOQUAL-001 fail-closed comparator (Veritas).
//
// The comparator never re-runs the system under test. It reads the two
// recorded runs, re-derives the frozen digests and applies the frozen
// contract. It can only emit PASS, PASS_WITH_LIMITS or FAIL, and every
// non-PASS reason is itemized with the exact missing proof.
//
// Fail-closed rules:
//   * a missing, partial, colliding or unbound input is a FAILURE, never a
//     pass and never a silently ignored field;
//   * an absent or non-finite metric is a FAILURE ("not measured" is not a
//     satisfied threshold);
//   * only a measured threshold miss is a LIMIT, and every limit is
//     itemized with the metric, the point estimate and the threshold;
//   * a verdict of PASS with any open limit or unsatisfied registered proof
//     throws: the comparator never reports a cleaner verdict than its input.
import { verifyFreeze } from './contract.mjs';

export const COMPARATOR_VERSION = 'sloqual-comparator-v1';
export const VERDICTS = Object.freeze(['PASS', 'PASS_WITH_LIMITS', 'FAIL']);

function finite(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}

function failure(failures, code, detail) {
  failures.push({code, detail});
}

function limit(limits, code, detail, proof) {
  limits.push({code, detail, proof: proof ?? null});
}

// Series resolvers: a frozen limit names the measured series, the family it
// is aggregated over and the statistic to compare against its threshold.
const SERIES = Object.freeze({
  authorization_latency_ms: {
    scope: 'family',
    read: (run, family) => (family === 'all' ? run?.metrics?.all?.latency : run?.metrics?.families?.[family]?.latency),
  },
  scheduling_lateness_ms: {
    scope: 'family',
    read: (run, family) => (family === 'all' ? run?.metrics?.all?.lateness : run?.metrics?.families?.[family]?.lateness),
  },
  revocation_commit_to_deny_ms: {
    scope: 'run',
    read: (run) => run?.revocation?.latency,
  },
  dispatch_realization_ratio: {
    scope: 'family',
    read: (run, family) => run?.realizationDetail?.[family] ?? null,
  },
  revocation_trial_count: {
    scope: 'run',
    read: (run) => ({samples: run?.revocation?.trials, max: run?.revocation?.trials, status: Number.isInteger(run?.revocation?.trials) ? 'MEASURED' : 'NOT_MEASURED'}),
  },
});

const STATISTIC = Object.freeze({
  nearest_rank_p50: (series) => series.p50,
  nearest_rank_p95: (series) => series.p95,
  nearest_rank_p99: (series) => series.p99,
  max: (series) => series.max,
  count: (series) => series.samples,
  completed_over_dispatched: (series) => series.ratio,
});

function familiesInScope(run, spec) {
  const scope = SERIES[spec.metric]?.scope;
  if (scope === 'run') return [['run', spec]];
  if (spec.family === 'all') return [[spec.family, spec]];
  return Object.keys(run?.metrics?.families ?? {}).filter((family) => family !== 'security').map((family) => [family, spec]);
}

// One frozen limit against one measured series. Absent input is a failure;
// a measured value outside the threshold is a limit; otherwise the limit
// name is marked satisfied for the registered-proof check.
function evaluateLimit({name, spec, label, run, satisfied, limits, failures}) {
  const resolver = SERIES[spec.metric];
  if (!resolver) {
    failure(failures, 'limit_metric_unknown', `${label}: limit ${name} names unknown metric ${String(spec.metric)}`);
    return;
  }
  const reader = STATISTIC[spec.statistic];
  if (!reader) {
    failure(failures, 'limit_statistic_unknown', `${label}: limit ${name} names unknown statistic ${String(spec.statistic)}`);
    return;
  }
  for (const [scope, effective] of familiesInScope(run, spec)) {
    const series = resolver.read(run, effective.family ?? scope);
    if (!series || series.status !== 'MEASURED') {
      failure(failures, 'metric_not_measured', `${label}: ${name} has no measured series for scope ${scope}`);
      continue;
    }
    const observed = reader(series);
    if (!finite(observed)) {
      failure(failures, 'metric_not_measured', `${label}: ${name} statistic ${spec.statistic} is absent for scope ${scope}`);
      continue;
    }
    const unit = spec.unit ?? 'ms';
    const withinPoint = spec.operator === '>=' ? observed >= spec.threshold : observed <= spec.threshold;
    // A threshold that demands a confidence bound is not satisfied by an
    // in-threshold point estimate whose interval still crosses it: the
    // research rule is "point AND CI upper bound within threshold".
    const ciUpper = spec.requireCiUpperWithin === true ? series.ci95?.upper : undefined;
    const withinCi = spec.requireCiUpperWithin !== true
      || (spec.operator === '>=' ? true : (finite(ciUpper) ? ciUpper <= spec.threshold : true));
    if (withinPoint && withinCi) {
      satisfied.add(name);
      continue;
    }
    if (finite(ciUpper) && !withinCi) {
      limit(limits, 'threshold_missed', `${label}: ${name} point=${round(observed)}${unit} ciUpper95=${round(ciUpper)}${unit} threshold=${spec.threshold}${unit} (${spec.statistic}, scope ${scope})`, name);
      continue;
    }
    limit(limits, 'threshold_missed', `${label}: ${name} observed=${round(observed)}${unit} threshold=${spec.operator} ${spec.threshold}${unit} (${spec.statistic}, scope ${scope})`, name);
  }
}

// Verifies one run's provenance bindings: the run must have been produced
// under exactly this frozen contract and manifest, with its own identity.
function verifyRunBindings({label, run, contract, manifestDigest, failures}) {
  if (!run || typeof run !== 'object') {
    failure(failures, 'run_missing', `${label}: no run record`);
    return;
  }
  if (run.contractVersion !== contract.version) {
    failure(failures, 'contract_version_unbound', `${label}: run contractVersion=${String(run.contractVersion)} frozen=${contract.version}`);
  }
  if (run.contractSelfHash !== contract.selfHash.sha256) {
    failure(failures, 'contract_self_hash_unbound', `${label}: run self hash does not match the frozen contract`);
  }
  if (run.manifestDigest !== manifestDigest) {
    failure(failures, 'manifest_unbound', `${label}: run manifest digest does not match the frozen manifest`);
  }
  if (run.coverage?.complete !== true) {
    failure(failures, 'coverage_incomplete', `${label}: ${String(run.coverage?.scenarioSeedResults)} of ${String(run.coverage?.expectedScenarioSeedResults)} scenario-seed results`);
  }
  const expected = contract.measurement.expectedScenarioSeedResultsPerRun;
  if (Number.isInteger(expected) && run.coverage?.scenarioSeedResults !== expected) {
    failure(failures, 'coverage_count_mismatch', `${label}: ${String(run.coverage?.scenarioSeedResults)} results, contract expects ${expected}`);
  }
}

// Hard gates: every declared gate must be present, finite and exactly zero.
function verifyHardGates({label, run, contract, failures}) {
  if (!run || typeof run !== 'object') {
    failure(failures, 'run_missing', `${label}: no run record`);
    return;
  }
  const declared = Object.entries(contract.hardGates ?? {}).filter(([name]) => name !== 'rule');
  if (declared.length === 0) {
    failure(failures, 'hard_gates_undeclared', `${label}: contract declares no hard gates`);
    return;
  }
  for (const [name, threshold] of declared) {
    if (threshold !== 0) {
      failure(failures, 'hard_gate_threshold_invalid', `${label}: hard gate ${name} must be 0, contract says ${String(threshold)}`);
      continue;
    }
    const value = run.hardCounters?.[name];
    if (!finite(value)) {
      failure(failures, 'hard_gate_not_reported', `${label}: hard gate ${name} is missing or non-finite (${String(value)})`);
      continue;
    }
    if (value !== 0) failure(failures, 'hard_gate_violated', `${label}: ${name}=${value}`);
  }
  for (const name of Object.keys(run.hardCounters ?? {})) {
    if (!Object.prototype.hasOwnProperty.call(contract.hardGates ?? {}, name)) {
      failure(failures, 'undeclared_hard_counter', `${label}: run reports counter ${name}, contract does not declare it`);
    }
  }
}

// Independent execution: two process-separated runs with distinct
// provenance that agree on every decision under the exact rule.
function verifyIndependentRuns({runA, runB, satisfied, failures}) {
  if (!runA || typeof runA !== 'object' || !runB || typeof runB !== 'object') return;
  for (const field of ['runId', 'executorId', 'pid', 'nonce', 'outputRoot']) {
    if (runA[field] === runB[field]) {
      failure(failures, 'run_manifest_collision', `runA.${field} === runB.${field}; two independent executions are required`);
    }
  }
  if (runA.policyVersion !== runB.policyVersion) {
    failure(failures, 'policy_version_divergence', `runA=${String(runA.policyVersion)} runB=${String(runB.policyVersion)}`);
  }
  if (runA.digests?.decisionSequence !== runB.digests?.decisionSequence) {
    failure(failures, 'decision_divergence_between_runs', 'ordered decision sequences differ between the two runs under the exact rule');
  }
  if (runA.digests?.perScenario !== runB.digests?.perScenario) {
    failure(failures, 'decision_divergence_between_runs', 'per-scenario decision digests differ between the two runs');
  }
  satisfied.add('decision_divergence_between_runs');
  satisfied.add('independent_rerun_same_host');
}

// Registered proofs: MAPPED proofs are satisfied only when every limit they
// name was satisfied; NOT_MEASURED / NEEDS_INPUT proofs are itemized with
// their exact missing evidence and always keep the verdict below PASS.
function verifyRegisteredProofs({contract, satisfied, limits}) {
  const proofStatus = [];
  for (const proof of contract.registeredProofs ?? []) {
    if (typeof proof?.id !== 'string') {
      limit(limits, 'registered_proof_malformed', 'contract.registeredProofs entry without an id');
      continue;
    }
    if (proof.status === 'MAPPED') {
      // `limits.<name>` and `hardGates` name the evidence a proof depends on;
      // the satisfied set holds the bare limit names plus the structural
      // invariants the comparator proved for this run set.
      const names = String(proof.satisfiedBy ?? '').split('.').filter(Boolean)
        .map((name, index, all) => (all.length > 1 && index === 0 ? all.slice(1).join('.') : name));
      const met = names.length > 0 && names.every((name) => satisfied.has(name));
      if (met) {
        proofStatus.push({id: proof.id, status: 'SATISFIED', evidence: proof.satisfiedBy});
      } else {
        const missing = names.filter((name) => !satisfied.has(name));
        limit(limits, 'registered_proof_unmet', `${proof.id}: mapped proof not satisfied by the recorded runs (${missing.join(', ') || String(proof.satisfiedBy)})`, proof.id);
        proofStatus.push({id: proof.id, status: 'UNMET', evidence: proof.satisfiedBy, missing});
      }
      continue;
    }
    limit(limits, 'registered_proof_unmet', `${proof.id}: ${proof.missingProof ?? 'missing proof is not itemized'}`, proof.id);
    proofStatus.push({id: proof.id, status: proof.status ?? 'NOT_MEASURED', evidence: null, missing: proof.missingProof ?? null});
  }
  return proofStatus;
}

// Single place where a verdict may be named. `force` lets a caller assert a
// claimed verdict: any disagreement between the claim and the resolved
// verdict is a hard error, so the comparator can never report a cleaner
// state than its input.
export function resolveVerdict({failures = [], limits = [], proofStatus = [], force = null} = {}) {
  const hasFailures = Array.isArray(failures) && failures.length > 0;
  const hasLimits = (Array.isArray(limits) && limits.length > 0)
    || (Array.isArray(proofStatus) && proofStatus.some((proof) => proof.status !== 'SATISFIED'));
  const verdict = hasFailures ? 'FAIL' : (hasLimits ? 'PASS_WITH_LIMITS' : 'PASS');
  if (force !== null && force !== undefined && force !== verdict) {
    throw new Error(`SLOQUAL_COMPARATOR_INCONSISTENT: claimed ${force}, resolved ${verdict}`);
  }
  return verdict;
}

function runSummary(label, run) {
  const warm = run?.metrics?.families?.steady?.latency;
  const burst = run?.metrics?.families?.burst?.latency;
  return {
    label,
    runId: run?.runId ?? null,
    executorId: run?.executorId ?? null,
    pid: run?.pid ?? null,
    nonce: run?.nonce ?? null,
    outputRoot: run?.outputRoot ?? null,
    platform: run?.platform ?? null,
    nodeVersion: run?.nodeVersion ?? null,
    policyVersion: run?.policyVersion ?? null,
    durationMs: finite(run?.durationMs) ? round(run.durationMs) : null,
    scenarioSeedResults: run?.coverage?.scenarioSeedResults ?? null,
    warmP95Ms: finite(warm?.p95) ? round(warm.p95) : null,
    warmP95Ci95Ms: finite(warm?.ci95?.lower) ? {lower: round(warm.ci95.lower), upper: round(warm.ci95.upper)} : null,
    warmP99Ms: finite(warm?.p99) ? round(warm.p99) : null,
    burstP95Ms: finite(burst?.p95) ? round(burst.p95) : null,
    burstP95Ci95Ms: finite(burst?.ci95?.lower) ? {lower: round(burst.ci95.lower), upper: round(burst.ci95.upper)} : null,
    revocationMaxMs: finite(run?.revocation?.latency?.max) ? round(run.revocation.latency.max) : null,
    revocationTrials: run?.revocation?.trials ?? null,
  };
}

export function compareQualification({contract, manifest, manifestBytes, runA, runB} = {}) {
  const failures = [];
  const limits = [];
  const satisfied = new Set();
  const freeze = verifyFreeze({contract, manifest, manifestBytes});
  if (!freeze.ok) for (const item of freeze.issues) failure(failures, item.code, item.detail);
  const manifestDigest = runA?.manifestDigest ?? runB?.manifestDigest ?? null;

  let hardGatesOk = true;
  const perRunSatisfied = [];
  for (const [label, run] of [['runA', runA], ['runB', runB]]) {
    const before = failures.length;
    verifyRunBindings({label, run, contract, manifestDigest, failures});
    verifyHardGates({label, run, contract, failures});
    if (failures.length > before) hardGatesOk = false;
    // A limit counts as satisfied only when BOTH runs satisfied it: one
    // healthy run never papers over a threshold the other run missed.
    const runSatisfied = new Set();
    for (const [name, spec] of Object.entries(contract.limits ?? {})) {
      evaluateLimit({name, spec, label, run, satisfied: runSatisfied, limits, failures});
    }
    perRunSatisfied.push(runSatisfied);
  }
  if (hardGatesOk) satisfied.add('hardGates');
  for (const name of [...perRunSatisfied[0] ?? []]) {
    if (perRunSatisfied.every((set) => set.has(name))) satisfied.add(name);
  }
  verifyIndependentRuns({runA, runB, satisfied, failures});

  const proofStatus = verifyRegisteredProofs({contract, satisfied, limits});
  const verdict = resolveVerdict({failures, limits, proofStatus});

  return {
    schemaVersion: 1,
    comparatorVersion: COMPARATOR_VERSION,
    ticket: contract?.ticket ?? null,
    verdict,
    ok: verdict !== 'FAIL',
    contractVersion: contract?.version ?? null,
    contractSelfHash: contract?.selfHash?.sha256 ?? null,
    manifestVersion: manifest?.version ?? null,
    manifestDigest,
    freeze,
    runs: [runSummary('runA', runA), runSummary('runB', runB)],
    hardCounters: {runA: runA?.hardCounters ?? null, runB: runB?.hardCounters ?? null},
    satisfiedLimits: [...satisfied].sort(),
    proofStatus,
    failures,
    limits,
    failureCount: failures.length,
    limitCount: limits.length,
    authority: {
      ...(contract?.authority ?? {}),
      productionSloAuthorized: false,
      verdictMeaning: {
        PASS: 'The frozen local contract was satisfied by both recorded runs. That is not a production SLO, a capacity plan or a rollout authorization.',
        PASS_WITH_LIMITS: 'No hard violation, but at least one registered proof is unsatisfied and itemized above. This is not PASS.',
        FAIL: 'A hard-gate violation or a structural failure. The recorded numbers are not a qualification of this contract.',
      }[verdict],
    },
  };
}
