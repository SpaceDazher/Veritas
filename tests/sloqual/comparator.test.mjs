// SLOQUAL-001 fail-closed comparator.
//
// The comparator is the only component allowed to name a verdict, so its
// behaviour on hostile input is the regression target: a missing metric, a
// partial coverage, a provenance collision, a decision divergence or a
// violated hard gate must produce FAIL, and a healthy local run must still
// produce PASS_WITH_LIMITS because the unmapped proofs stay unmapped.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareQualification, resolveVerdict } from '../../src/lib/sloqual/comparator.mjs';
import { CONTRACT_PATH, MANIFEST_PATH, stampContract } from '../../src/lib/sloqual/contract.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const manifestBytes = fs.readFileSync(path.join(ROOT, MANIFEST_PATH));
const frozenContract = JSON.parse(fs.readFileSync(path.join(ROOT, CONTRACT_PATH), 'utf8'));
const manifest = JSON.parse(manifestBytes.toString('utf8'));

function latencySeries(overrides = {}) {
  return {
    samples: 1000,
    status: 'MEASURED',
    p50: 0.2,
    p95: 0.6,
    p99: 1.2,
    max: 3.1,
    mean: 0.25,
    ci95: {lower: 0.55, upper: 0.65, method: 'percentile_bootstrap', resamples: 2000, confidence: 0.95, seed: 20260925, samples: 1000},
    ...overrides,
  };
}

function healthyRun(overrides = {}) {
  const {manifestDigest, ...rest} = overrides;
  return {
    schemaVersion: 1,
    contractVersion: frozenContract.version,
    contractSelfHash: frozenContract.selfHash.sha256,
    manifestDigest: manifestDigest ?? 'a96d76d1b87c183e9930a767490699ce3d0edad9ddc98813271d4510801363b5',
    policyVersion: 's2-002-policy-v5',
    runId: 'sloqual-a',
    executorId: 'exec-alpha',
    pid: 1001,
    nonce: 'nonce-alpha',
    outputRoot: 'results/sloqual-001/sloqual-a',
    platform: 'linux/x64',
    nodeVersion: 'v22.23.2',
    coverage: {scenariosDeclared: 17, seedsDeclared: 5, scenarioSeedResults: 85, expectedScenarioSeedResults: 85, complete: true},
    dispatchedSamples: 10000,
    measuredSamples: 9800,
    metrics: {
      all: {latency: latencySeries(), lateness: latencySeries({p95: 0.3, samples: 10000})},
      families: {
        steady: {latency: latencySeries(), lateness: latencySeries({p95: 0.2, samples: 5000})},
        burst: {latency: latencySeries({p95: 1.1, samples: 1800}), lateness: latencySeries({p95: 2.0, samples: 1800})},
        fault: {latency: latencySeries(), lateness: latencySeries()},
        soak: {latency: latencySeries(), lateness: latencySeries()},
      },
      perScenario: {},
    },
    realization: {steady: 1, burst: 1, fault: 1, soak: 1, all: 1},
    realizationDetail: {
      steady: {dispatched: 5000, completed: 5000, ratio: 1, status: 'MEASURED'},
      burst: {dispatched: 1800, completed: 1800, ratio: 1, status: 'MEASURED'},
      fault: {dispatched: 3000, completed: 3000, ratio: 1, status: 'MEASURED'},
      soak: {dispatched: 3600, completed: 3600, ratio: 1, status: 'MEASURED'},
      all: {dispatched: 13400, completed: 13400, ratio: 1, status: 'MEASURED'},
    },
    revocation: {
      trials: 105,
      allowAfterCommit: 0,
      preconditionFailures: 0,
      latency: latencySeries({samples: 105, p95: 0.2, max: 0.4, p99: 0.3}),
      forbiddenPostRevokeEffects: 0,
    },
    hardCounters: {
      cross_tenant_allow: 0,
      unexpected_decision: 0,
      allow_after_principal_freeze: 0,
      single_use_grant_replay_allow: 0,
      decision_divergence_within_run: 0,
      missing_or_censored_samples: 0,
      degenerate_scenario_decision_distribution: 0,
      allow_after_revocation_commit: 0,
      revocation_trial_precondition_failures: 0,
    },
    digests: {decisionSequence: 'seq-digest', perScenario: 'scenario-digest', digestsExclude: ['latency']},
    durationMs: 60000,
    ...rest,
  };
}

function compare(runA, runB, contract = frozenContract) {
  return compareQualification({contract, manifest, manifestBytes, runA, runB});
}

describe('SLOQUAL-001 comparator: verdict resolution', () => {
  test('failures outrank limits, limits outrank PASS', () => {
    assert.equal(resolveVerdict({failures: [{code: 'x'}], limits: [], proofStatus: []}), 'FAIL');
    assert.equal(resolveVerdict({failures: [], limits: [{code: 'y'}], proofStatus: []}), 'PASS_WITH_LIMITS');
    assert.equal(resolveVerdict({failures: [], limits: [], proofStatus: [{id: 'p', status: 'SATISFIED'}]}), 'PASS');
  });

  test('a PASS with an open limit or an unsatisfied proof is refused', () => {
    assert.throws(() => resolveVerdict({failures: [], limits: [{code: 'y'}], proofStatus: [], force: 'PASS'}), /SLOQUAL_COMPARATOR_INCONSISTENT/);
    assert.throws(() => resolveVerdict({failures: [], limits: [], proofStatus: [{id: 'p', status: 'UNMET'}], force: 'PASS'}), /SLOQUAL_COMPARATOR_INCONSISTENT/);
  });
});

describe('SLOQUAL-001 comparator: healthy local runs', () => {
  const result = compare(healthyRun(), healthyRun({
    runId: 'sloqual-b',
    executorId: 'exec-beta',
    pid: 2002,
    nonce: 'nonce-beta',
    outputRoot: 'results/sloqual-001/sloqual-b',
  }));

  test('a clean local run is PASS_WITH_LIMITS, never PASS', () => {
    assert.equal(result.verdict, 'PASS_WITH_LIMITS', JSON.stringify(result.failures));
    assert.equal(result.ok, true);
    assert.deepEqual(result.failures, []);
    assert.equal(result.authority.productionSloAuthorized, false);
    assert.match(result.authority.verdictMeaning, /not PASS/);
    assert.equal(result.proofStatus.filter((proof) => proof.status === 'SATISFIED').length, 5);
  });

  test('every unmapped proof is itemized with its exact missing evidence', () => {
    const unmapped = result.proofStatus.filter((proof) => proof.status !== 'SATISFIED');
    assert.ok(unmapped.length >= 4, `expected several unmapped proofs, got ${unmapped.length}`);
    for (const proof of unmapped) {
      const itemized = result.limits.find((item) => item.proof === proof.id);
      assert.ok(itemized, `${proof.id} must be itemized as a limit`);
      assert.match(itemized.detail, /:/);
      assert.ok(proof.missing && proof.missing.length > 20);
    }
    const ids = unmapped.map((proof) => proof.id);
    assert.ok(ids.includes('production_profile_mapping'));
    assert.ok(ids.includes('human_slo_countersignature'));
    assert.ok(ids.includes('external_independent_execution'));
  });

  test('the mapped proofs and thresholds are reported as satisfied', () => {
    const satisfied = new Set(result.proofStatus.filter((proof) => proof.status === 'SATISFIED').map((proof) => proof.id));
    for (const id of ['warm_latency_within_threshold', 'burst_latency_within_threshold', 'revocation_gate_s1_008', 'fail_closed_invariants', 'independent_rerun_same_host']) {
      assert.ok(satisfied.has(id), `${id} should be satisfied`);
    }
    for (const limit of ['warm_authorization_p95_ms', 'warm_authorization_p99_ms', 'burst_authorization_p95_ms', 'revocation_to_deny_max_ms', 'revocation_trials_per_run', 'realization_ratio', 'scheduling_lateness_p95_ms']) {
      assert.ok(result.satisfiedLimits.includes(limit), `${limit} should be satisfied`);
    }
  });
});

describe('SLOQUAL-001 comparator: fail-closed behaviour', () => {
  test('a violated hard gate is FAIL, itemized with the counter', () => {
    const runA = healthyRun();
    runA.hardCounters.cross_tenant_allow = 1;
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'hard_gate_violated' && /cross_tenant_allow=1/.test(failure.detail)));
  });

  test('a missing hard counter is a FAIL, not an implicit pass', () => {
    const runA = healthyRun();
    delete runA.hardCounters.single_use_grant_replay_allow;
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'hard_gate_not_reported'));
  });

  test('an undeclared extra counter is a FAIL', () => {
    const runA = healthyRun();
    runA.hardCounters.invented_counter = 0;
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'undeclared_hard_counter'));
  });

  test('an absent metric is FAIL, not a satisfied threshold', () => {
    const runA = healthyRun();
    runA.metrics.families.steady.latency = null;
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'metric_not_measured'));
  });

  test('a non-finite metric is FAIL', () => {
    const runA = healthyRun();
    runA.metrics.families.burst.latency.p95 = null;
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'FAIL');
  });

  test('partial scenario coverage is FAIL', () => {
    const runA = healthyRun();
    runA.coverage = {scenariosDeclared: 17, seedsDeclared: 5, scenarioSeedResults: 34, expectedScenarioSeedResults: 85, complete: false};
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'coverage_incomplete'));
  });

  test('a run measured against another contract or manifest is FAIL', () => {
    const drifted = healthyRun({contractVersion: '0.9.0'});
    const result = compare(drifted, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'contract_version_unbound'));
  });

  test('two runs sharing provenance are FAIL: one execution is not an independent rerun', () => {
    const result = compare(healthyRun(), healthyRun());
    assert.equal(result.verdict, 'FAIL');
    const collisions = result.failures.filter((failure) => failure.code === 'run_manifest_collision');
    assert.equal(collisions.length, 5, JSON.stringify(collisions.map((item) => item.detail)));
  });

  test('divergent decisions between the two runs are FAIL', () => {
    const runB = healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'});
    runB.digests = {decisionSequence: 'other-seq', perScenario: 'other-scenario', digestsExclude: ['latency']};
    const result = compare(healthyRun(), runB);
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'decision_divergence_between_runs'));
  });

  test('a policy-version divergence between the runs is FAIL', () => {
    const runB = healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'});
    runB.policyVersion = 's2-002-policy-v4';
    const result = compare(healthyRun(), runB);
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'policy_version_divergence'));
  });

  test('a missing run is FAIL', () => {
    const result = compare(healthyRun(), null);
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'run_missing'));
  });

  test('a tampered frozen contract is FAIL before any measurement is trusted', () => {
    const tampered = structuredClone(frozenContract);
    tampered.limits.warm_authorization_p95_ms.threshold = 200;
    const result = compare(healthyRun(), healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}), tampered);
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'contract_self_hash_mismatch'));
  });

  test('an unfrozen contract with no registered proofs is FAIL', () => {
    const empty = structuredClone(frozenContract);
    empty.registeredProofs = [];
    const result = compare(healthyRun(), healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}), empty);
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.failures.some((failure) => failure.code === 'registered_proofs_missing'));
  });
});

describe('SLOQUAL-001 comparator: threshold misses are limits, not failures', () => {
  test('a warm p95 whose CI crosses the threshold is a limit with numbers', () => {
    const runA = healthyRun();
    runA.metrics.families.steady.latency = latencySeries({p95: 19.4, ci95: {lower: 18.1, upper: 26.15, method: 'percentile_bootstrap', resamples: 2000, confidence: 0.95, seed: 20260925, samples: 1000}});
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'PASS_WITH_LIMITS');
    const miss = result.limits.find((item) => item.proof === 'warm_authorization_p95_ms');
    assert.ok(miss, JSON.stringify(result.limits));
    assert.match(miss.detail, /19\.4ms/);
    assert.match(miss.detail, /26\.15ms/);
    assert.ok(result.proofStatus.some((proof) => proof.id === 'warm_latency_within_threshold' && proof.status === 'UNMET'));
  });

  test('a revocation maximum above the S1-008 threshold is a limit', () => {
    const runA = healthyRun();
    runA.revocation.latency = latencySeries({samples: 105, max: 5001, p95: 800, p99: 1200});
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'PASS_WITH_LIMITS');
    assert.ok(result.limits.some((item) => item.proof === 'revocation_to_deny_max_ms'));
  });

  test('too few revocation trials is a limit, not a fabricated pass', () => {
    const runA = healthyRun();
    runA.revocation.trials = 100;
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'PASS_WITH_LIMITS');
    assert.ok(result.limits.some((item) => item.proof === 'revocation_trials_per_run'));
  });

  test('an under-delivered load is a limit (the run did not measure what it claims)', () => {
    const runA = healthyRun();
    runA.realization.steady = 0.98;
    runA.realizationDetail.steady = {dispatched: 5000, completed: 4900, ratio: 0.98, status: 'MEASURED'};
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'PASS_WITH_LIMITS');
    assert.ok(result.limits.some((item) => item.proof === 'realization_ratio' && /steady/.test(item.detail)));
  });

  test('a host that could not keep the frozen schedule is a limit', () => {
    const runA = healthyRun();
    runA.metrics.all.lateness = latencySeries({p95: 250, samples: 10000});
    const result = compare(runA, healthyRun({runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}));
    assert.equal(result.verdict, 'PASS_WITH_LIMITS');
    assert.ok(result.limits.some((item) => item.proof === 'scheduling_lateness_p95_ms'));
  });
});

describe('SLOQUAL-001 comparator: a fully mapped contract can reach PASS', () => {
  test('PASS is reachable only when every registered proof is mapped and satisfied, and still grants no production authority', () => {
    // A hypothetical next version in which every registered proof is mapped
    // and measured. It is re-stamped, because an unstamped edit is exactly
    // what the freeze check must reject.
    const complete = structuredClone(frozenContract);
    complete.version = '1.1.0';
    complete.registeredProofs = complete.registeredProofs
      .filter((proof) => proof.status === 'MAPPED')
      .map((proof) => (proof.id === 'independent_rerun_same_host' ? {id: proof.id, description: proof.description, status: 'MAPPED', satisfiedBy: 'decision_divergence_between_runs'} : proof));
    const stamped = stampContract({contract: complete, manifestBytes, manifest});
    const bound = {contractVersion: stamped.version, contractSelfHash: stamped.selfHash.sha256};
    const result = compare(
      healthyRun(bound),
      healthyRun({...bound, runId: 'b', executorId: 'exec-beta', pid: 2, nonce: 'n2', outputRoot: 'b'}),
      stamped,
    );
    assert.equal(result.verdict, 'PASS', JSON.stringify(result.failures));
    assert.deepEqual(result.limits, []);
    assert.equal(result.authority.productionSloAuthorized, false);
    assert.match(result.authority.verdictMeaning, /not a production SLO/);
  });
});
