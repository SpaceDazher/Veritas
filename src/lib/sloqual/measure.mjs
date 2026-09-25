// SLOQUAL-001 scenario execution against the real Veritas policy engine.
//
// Every measured unit is one live `createPolicyEngine().authorize()` call on
// the frozen workload templates. No decision is simulated, replayed from a
// fixture or substituted by a stub: the engine module under qualification is
// the same module the identity tests and the S2-002 replay gate use.
//
// The engine clock is injected from the frozen manifest, so decisions are
// deterministic and the ordered decision sequence must be byte-identical in
// an independent process. Latency is measured with the monotonic clock, so
// timings differ between runs by design; only decisions are compared exactly.
import { createHash } from 'node:crypto';
import os from 'node:os';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import { createPolicyEngine, POLICY_VERSION } from '../identity/policy-engine.mjs';
import { buildArrivalSchedule, dispatchAt, nowNs } from './open-loop.mjs';
import { seededRandom, nearestRankPercentile, percentileBootstrapInterval } from './statistics.mjs';

export const RUNNER_VERSION = 'sloqual-runner-v1';
export const REVOCATION_PROBE = Object.freeze({
  trialPrincipalId: 'prn-agent-alice',
  trialWorkspaceId: 'ws-alice-private',
  trialGrantId: 'grt-alice-agent-read-0001',
  request: {
    adapter: 'api',
    principalId: 'prn-agent-alice',
    workspaceId: 'ws-alice-private',
    action: 'board.read',
    resource: {type: 'board', id: 'board:primary'},
    args: {workspace_id: 'ws-alice-private'},
  },
  expectedAllowReasonCode: 'GRANT_VALID',
  expectedDenyReasonCode: 'GRANT_REVOKED',
});

// Deterministic request plan: weights are expanded with the largest-remainder
// method (exact counts, no rounding drift) and then shuffled with a seeded
// Fisher-Yates. Same (scenario, seed) always yields the same sequence.
export function buildRequestPlan(scenario, seed) {
  const mix = scenario.mix ?? [];
  const total = scenario.arrival.requests;
  const weightTotal = mix.reduce((sum, entry) => sum + (Number.isFinite(entry?.weight) ? entry.weight : 0), 0);
  if (weightTotal !== 100) {
    throw new Error(`SLOQUAL_MANIFEST_INVALID: scenario ${scenario.id} mix weights sum to ${weightTotal}, expected exactly 100`);
  }
  const quotas = mix.map((entry) => ({workloadId: entry.workloadId, exact: (entry.weight * total) / 100}));
  const plan = [];
  for (const quota of quotas) {
    const count = Math.floor(quota.exact);
    for (let i = 0; i < count; i += 1) plan.push(quota.workloadId);
    quota.remainder = quota.exact - count;
  }
  const remainders = [...quotas].sort((a, b) => (b.remainder - a.remainder) || a.workloadId.localeCompare(b.workloadId));
  let assigned = plan.length;
  let cursor = 0;
  while (assigned < total) {
    plan.push(remainders[cursor % remainders.length].workloadId);
    assigned += 1;
    cursor += 1;
  }
  const random = seededRandom(seed + plan.length);
  for (let i = plan.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [plan[i], plan[j]] = [plan[j], plan[i]];
  }
  return plan;
}

function newEngine(clock) {
  return createPolicyEngine({now: clock});
}

function decide(engine, workload) {
  const outcome = engine.authorize(structuredClone(workload.request));
  return {decision: outcome.decision, reasonCodes: outcome.reasonCodes ?? []};
}

// One (scenario, seed) execution. Returns the raw request records and the
// per-scenario counters the comparator consumes.
export function executeScenarioSeed({scenario, workloads, seed, clock}) {
  const byId = new Map(workloads.map((workload) => [workload.id, workload]));
  const isSecurity = scenario.family === 'security';
  const plan = isSecurity ? [] : buildRequestPlan(scenario, seed);
  const arrival = buildArrivalSchedule({
    mode: scenario.arrival.mode,
    requests: scenario.arrival.requests,
    ratePerSecond: scenario.arrival.ratePerSecond,
    burstSize: scenario.arrival.burstSize,
    burstWindowMs: scenario.arrival.burstWindowMs,
    seed,
  });
  const records = [];
  const counters = {
    cross_tenant_allow: 0,
    unexpected_decision: 0,
    allow_after_principal_freeze: 0,
    single_use_grant_replay_allow: 0,
    decision_divergence_within_run: 0,
    missing_or_censored_samples: 0,
    degenerate_scenario_decision_distribution: 0,
    allow_after_revocation_commit: 0,
    revocation_trial_precondition_failures: 0,
  };
  const decisionClasses = new Set();

  if (isSecurity) {
    const trialCount = scenario.revocationTrials ?? scenario.arrival.requests;
    for (let trial = 0; trial < trialCount; trial += 1) {
      const engine = newEngine(clock);
      const before = decide(engine, {request: REVOCATION_PROBE.request});
      decisionClasses.add(before.decision);
      if (before.decision !== 'ALLOW' || !before.reasonCodes.includes(REVOCATION_PROBE.expectedAllowReasonCode)) {
        counters.revocation_trial_precondition_failures += 1;
        records.push({index: trial, kind: 'revocation', trialId: `revocation/${trial}`, decision: before.decision, reasonCodes: before.reasonCodes, latencyMs: null, precondition: 'FAILED'});
        continue;
      }
      const dispatch = dispatchAt(0, nowNs(), () => {
        engine.revokeGrant(REVOCATION_PROBE.trialGrantId);
        return decide(engine, {request: REVOCATION_PROBE.request});
      });
      const after = dispatch.result;
      if (after.decision !== 'DENY' || !after.reasonCodes.includes(REVOCATION_PROBE.expectedDenyReasonCode)) {
        counters.allow_after_revocation_commit += 1;
      }
      decisionClasses.add(after.decision);
      records.push({
        index: trial,
        kind: 'revocation',
        trialId: `revocation/${trial}`,
        decision: after.decision,
        reasonCodes: after.reasonCodes,
        latencyMs: dispatch.latencyMs,
        latenessMs: dispatch.latenessMs,
        serviceMs: dispatch.serviceMs,
      });
    }
  } else {
    let engine = newEngine(clock);
    const epochNs = nowNs();
    const recreateEvery = Number.isInteger(scenario.engineRecreateEveryRequests) ? scenario.engineRecreateEveryRequests : null;
    const freezeAfter = Number.isInteger(scenario.freezeAfterRequests) ? scenario.freezeAfterRequests : null;
    const freezePrincipalId = scenario.freezePrincipalId ?? null;
    const referenceDecisions = (recreateEvery === null) ? null : (() => {
      const referenceEngine = newEngine(clock);
      return plan.map((workloadId) => decide(referenceEngine, byId.get(workloadId)).decision);
    })();
    const seenStatefulAllow = new Set();
    for (let index = 0; index < plan.length; index += 1) {
      const workloadId = plan[index];
      const workload = byId.get(workloadId);
      if (!workload) throw new Error(`SLOQUAL_MANIFEST_INVALID: scenario ${scenario.id} references unknown workload ${workloadId}`);
      if (recreateEvery !== null && index > 0 && index % recreateEvery === 0) engine = newEngine(clock);
      if (freezeAfter !== null && index === freezeAfter) engine.freezePrincipal(freezePrincipalId);
      const dispatch = dispatchAt(arrival.offsetsMs[index], epochNs, () => decide(engine, workload));
      const {decision, reasonCodes} = dispatch.result;
      // A frozen principal is expected to be denied from the freeze instant
      // on: the expectation follows the injected fault, and any ALLOW after
      // the freeze is still counted as a hard-gate violation.
      const frozenNow = freezeAfter !== null && index >= freezeAfter && workload.request.principalId === freezePrincipalId;
      const expectedDecisions = frozenNow ? ['DENY'] : workload.expectedDecisions;
      if (!expectedDecisions.includes(decision)) counters.unexpected_decision += 1;
      if (workload.denialClass === 'cross_tenant' && decision === 'ALLOW') counters.cross_tenant_allow += 1;
      if (workload.stateful === true) {
        const firstAllow = !seenStatefulAllow.has(workloadId) && decision === 'ALLOW';
        if (firstAllow) seenStatefulAllow.add(workloadId);
        else if (decision === 'ALLOW') counters.single_use_grant_replay_allow += 1;
      }
      if (frozenNow && decision === 'ALLOW') {
        counters.allow_after_principal_freeze += 1;
      }
      if (referenceDecisions !== null && referenceDecisions[index] !== decision) {
        counters.decision_divergence_within_run += 1;
      }
      decisionClasses.add(decision);
      records.push({
        index,
        kind: 'authorization',
        workloadId,
        principalId: workload.request.principalId,
        denialClass: workload.denialClass,
        decision,
        reasonCodes,
        expectedDecisions,
        latencyMs: dispatch.latencyMs,
        latenessMs: dispatch.latenessMs,
        serviceMs: dispatch.serviceMs,
      });
    }
  }
  // Degeneracy guard: a scenario-seed that never produced one of its
  // required decision classes is a broken run, not a clean result.
  const required = scenario.decisionClassesRequired ?? [];
  if (required.some((requiredClass) => !decisionClasses.has(requiredClass))) {
    counters.degenerate_scenario_decision_distribution += 1;
  }

  // Declared warmup: the first N requests of a scenario-seed are excluded
  // from the latency statistics only. Every request is still dispatched,
  // judged, counted and recorded.
  const warmupRequests = Number.isInteger(scenario.warmupRequests) && scenario.warmupRequests > 0 ? scenario.warmupRequests : 0;
  const measured = records.filter((record) => record.index >= warmupRequests);
  const latencySamples = measured.filter((record) => Number.isFinite(record.latencyMs)).map((record) => record.latencyMs);
  const latenessSamples = measured.filter((record) => Number.isFinite(record.latenessMs)).map((record) => Math.max(0, record.latenessMs));
  counters.missing_or_censored_samples += (scenario.arrival.requests - records.length) + (isSecurity ? 0 : records.filter((record) => !Number.isFinite(record.latencyMs)).length);

  return {
    scenarioId: scenario.id,
    family: scenario.family,
    scaleClass: scenario.scaleClass,
    seed,
    records,
    counters,
    latencySamples,
    latenessSamples,
    warmupRequests: Math.min(warmupRequests, records.length),
    measuredWindow: {dispatched: measured.length, completed: latencySamples.length},
    decisionClasses: [...decisionClasses].sort(),
  };
}

function summarizeSamples(samples, {bootstrap} = {}) {
  if (!Array.isArray(samples) || samples.length === 0) return {samples: 0, status: 'NOT_MEASURED'};
  const summary = {
    samples: samples.length,
    status: 'MEASURED',
    p50: nearestRankPercentile(samples, 0.5),
    p95: nearestRankPercentile(samples, 0.95),
    p99: nearestRankPercentile(samples, 0.99),
    max: nearestRankPercentile(samples, 1),
    mean: samples.reduce((sum, value) => sum + value, 0) / samples.length,
  };
  if (bootstrap) {
    const interval = percentileBootstrapInterval({samples, p: bootstrap.p ?? 0.95, resamples: bootstrap.resamples, confidence: bootstrap.confidence, seed: bootstrap.seed});
    summary.ci95 = {lower: interval.lower, upper: interval.upper, method: interval.method, resamples: interval.resamples, confidence: interval.confidence, seed: interval.seed, samples: interval.samples};
  }
  return summary;
}

function addCounters(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (typeof value !== 'number') continue;
    target[key] = (target[key] ?? 0) + value;
  }
  return target;
}

// Executes the full frozen manifest (every scenario x every seed) once.
// Returns the run record; raw per-request observations are returned to the
// caller for the run's own output root and are never silently dropped.
export function executeRun({contract, manifest, runId, executorId, nonce, outputRoot, policyVersion = POLICY_VERSION}) {
  const clock = manifest.policyEngine.fixedClock;
  const scenarioSeedResults = [];
  const hardCounters = {
    cross_tenant_allow: 0,
    unexpected_decision: 0,
    allow_after_principal_freeze: 0,
    single_use_grant_replay_allow: 0,
    decision_divergence_within_run: 0,
    missing_or_censored_samples: 0,
    degenerate_scenario_decision_distribution: 0,
    allow_after_revocation_commit: 0,
    revocation_trial_precondition_failures: 0,
  };
  const familyLatency = new Map();
  const familyLateness = new Map();
  const familyDispatched = new Map();
  const familyCompleted = new Map();
  const allLatency = [];
  const allLateness = [];
  const decisionSequence = [];
  const perScenario = {};
  const decisionProjection = {};
  const revocationLatencies = [];
  const startedAtNs = nowNs();

  for (const scenario of manifest.scenarios) {
    for (const seed of manifest.seeds) {
      const execution = executeScenarioSeed({scenario, workloads: manifest.workloads, seed, clock});
      addCounters(hardCounters, execution.counters);
      if (!familyLatency.has(scenario.family)) {
        familyLatency.set(scenario.family, []);
        familyLateness.set(scenario.family, []);
        familyDispatched.set(scenario.family, 0);
        familyCompleted.set(scenario.family, 0);
      }
      familyDispatched.set(scenario.family, familyDispatched.get(scenario.family) + execution.measuredWindow.dispatched);
      familyCompleted.set(scenario.family, familyCompleted.get(scenario.family) + execution.measuredWindow.completed);
      familyLatency.get(scenario.family).push(...execution.latencySamples);
      familyLateness.get(scenario.family).push(...execution.latenessSamples);
      allLatency.push(...execution.latencySamples);
      allLateness.push(...execution.latenessSamples);
      for (const record of execution.records) {
        decisionSequence.push([scenario.id, seed, record.index, record.workloadId ?? null, record.decision].join('|'));
        if (record.kind === 'revocation') {
          if (Number.isFinite(record.latencyMs)) revocationLatencies.push(record.latencyMs);
          decisionSequence.push([scenario.id, seed, record.index, 'revocation', record.decision].join('|'));
        }
      }
      const perScenarioKey = `${scenario.id}#${seed}`;
      // Decision-only projection: timing values differ between runs by
      // design, so the cross-run digest must never include them.
      decisionProjection[perScenarioKey] = {
        scenarioId: scenario.id,
        family: scenario.family,
        seed,
        requests: execution.records.length,
        warmupRequests: execution.warmupRequests,
        decisionClasses: execution.decisionClasses,
        counters: execution.counters,
        decisions: execution.records.map((record) => [record.index, record.workloadId ?? null, record.decision].join(':')),
      };
      perScenario[perScenarioKey] = {
        scenarioId: scenario.id,
        family: scenario.family,
        seed,
        requests: execution.records.length,
        warmupRequests: execution.warmupRequests,
        measuredRequests: execution.measuredWindow.dispatched,
        decisionClasses: execution.decisionClasses,
        counters: execution.counters,
        latency: summarizeSamples(execution.latencySamples),
        lateness: summarizeSamples(execution.latenessSamples),
      };
      scenarioSeedResults.push({scenarioId: scenario.id, seed, records: execution.records});
    }
  }

  const bootstrap = {
    p: 0.95,
    resamples: contract.statistics.latencyConfidenceInterval.resamples,
    confidence: contract.statistics.latencyConfidenceInterval.confidence,
    seed: contract.statistics.latencyConfidenceInterval.seed,
  };
  const families = {};
  for (const [family, samples] of familyLatency) {
    families[family] = {
      latency: summarizeSamples(samples, {bootstrap}),
      lateness: summarizeSamples(familyLateness.get(family) ?? [], {bootstrap}),
    };
  }
  const bootstrapP99 = {p: 0.99, resamples: bootstrap.resamples, confidence: bootstrap.confidence, seed: bootstrap.seed};
  families.steady.latency.p99Ci95 = percentileBootstrapInterval({samples: familyLatency.get('steady') ?? [], p: 0.99, resamples: bootstrap.resamples, confidence: bootstrap.confidence, seed: bootstrap.seed});

  const totalDispatched = scenarioSeedResults.reduce((sum, entry) => sum + entry.records.length, 0);
  // Realization ratio: measured samples over dispatched requests. Below 1.0
  // the offered load was not actually delivered, so the run does not measure
  // the scenario it claims to measure.
  const realization = {};
  const realizationDetail = {};
  let allDispatched = 0;
  let allCompleted = 0;
  for (const [family, dispatched] of familyDispatched) {
    const completed = familyCompleted.get(family);
    realization[family] = dispatched > 0 ? completed / dispatched : null;
    realizationDetail[family] = {dispatched, completed, ratio: realization[family], status: 'MEASURED'};
    allDispatched += dispatched;
    allCompleted += completed;
  }
  realization.all = allDispatched > 0 ? allCompleted / allDispatched : null;
  realizationDetail.all = {dispatched: allDispatched, completed: allCompleted, ratio: realization.all, status: 'MEASURED'};
  const revocation = {
    trials: revocationLatencies.length,
    allowAfterCommit: hardCounters.allow_after_revocation_commit,
    preconditionFailures: hardCounters.revocation_trial_precondition_failures,
    latency: summarizeSamples(revocationLatencies),
    forbiddenPostRevokeEffects: hardCounters.allow_after_revocation_commit,
  };

  const runRecord = {
    schemaVersion: 1,
    ticket: contract.ticket,
    runnerVersion: RUNNER_VERSION,
    contractVersion: contract.version,
    contractSelfHash: contract.selfHash.sha256,
    manifestVersion: manifest.version,
    manifestDigest: canonicalDigest(manifest),
    policyVersion,
    runId,
    executorId,
    pid: process.pid,
    nonce,
    outputRoot,
    platform: `${process.platform}/${process.arch}`,
    nodeVersion: process.version,
    policyClock: clock,
    coverage: {
      scenariosDeclared: manifest.scenarios.length,
      seedsDeclared: manifest.seeds.length,
      scenarioSeedResults: scenarioSeedResults.length,
      expectedScenarioSeedResults: manifest.scenarios.length * manifest.seeds.length,
      complete: scenarioSeedResults.length === manifest.scenarios.length * manifest.seeds.length,
    },
    dispatchedSamples: totalDispatched,
    measuredSamples: allCompleted,
    warmupPolicy: {
      requestsPerScenarioSeed: manifest.warmupPolicy?.requestsPerScenarioSeed ?? 0,
      excludedFromLatencyStatistics: true,
      retainedInHardCountersAndDecisionSequence: true,
      rule: manifest.warmupPolicy?.rule ?? null,
    },
    realization,
    realizationDetail,
    metrics: {
      all: {latency: summarizeSamples(allLatency, {bootstrap}), lateness: summarizeSamples(allLateness, {bootstrap})},
      families,
      perScenario,
    },
    revocation,
    hardCounters,
    digests: {
      decisionSequence: canonicalDigest(decisionSequence),
      perScenario: canonicalDigest(decisionProjection),
      digestsExclude: ['latency', 'lateness', 'duration', 'host load'],
    },
    durationMs: Number(nowNs() - startedAtNs) / 1e6,
  };
  return {runRecord, raw: {scenarioSeedResults, perScenario}};
}

export function environmentManifest({runRecord, runId, executorId, nonce, outputRoot}) {
  return {
    schemaVersion: 1,
    artifact: 'environment-manifest',
    ticket: runRecord.ticket,
    runId,
    executorId,
    nonce,
    outputRoot,
    runnerVersion: RUNNER_VERSION,
    contractVersion: runRecord.contractVersion,
    contractSelfHash: runRecord.contractSelfHash,
    manifestVersion: runRecord.manifestVersion,
    manifestDigest: runRecord.manifestDigest,
    policyVersion: runRecord.policyVersion,
    policyClock: runRecord.policyClock,
    platform: runRecord.platform,
    nodeVersion: runRecord.nodeVersion,
    host: {
      // Recorded, never controlled: this host also runs the operator's
      // editor, the database and the agent harness. That is precisely why a
      // same-host independent rerun is a declared limit, not proof.
      cpuModel: os.cpus()[0]?.model ?? null,
      cpuCount: os.cpus().length,
      totalMemoryBytes: os.totalmem(),
      loadAverage: os.loadavg(),
      hostnameDigest: createHash('sha256').update(os.hostname()).digest('hex').slice(0, 16),
    },
    limits: {
      note: 'Host resources and load are recorded, not controlled. This is a single-host qualification: the host is shared with the operator and the harness, and process separation is not host separation.',
    },
  };
}
