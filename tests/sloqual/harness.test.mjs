// SLOQUAL-001 harness: the measured unit is a real policy-engine decision.
// These tests execute frozen scenarios in-process (a few hundred
// milliseconds each) and assert the properties the qualification relies on:
// deterministic request plans, expected decisions, zero fail-closed
// violations, the single-use grant replay guard, the principal-freeze guard,
// engine recreation under load, and the S1-008 revocation gate.
//
// The full 17 x 5 qualification with two independent processes is the gate
// `npm run verify:sloqual-001`, not this suite.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { MANIFEST_PATH } from '../../src/lib/sloqual/contract.mjs';
import { buildRequestPlan, executeScenarioSeed, REVOCATION_PROBE } from '../../src/lib/sloqual/measure.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, MANIFEST_PATH), 'utf8'));
const clock = manifest.policyEngine.fixedClock;
const scenarioById = new Map(manifest.scenarios.map((scenario) => [scenario.id, scenario]));

function run(scenarioId, seed = 11) {
  const scenario = scenarioById.get(scenarioId);
  assert.ok(scenario, `unknown scenario ${scenarioId}`);
  return executeScenarioSeed({scenario, workloads: manifest.workloads, seed, clock});
}

describe('SLOQUAL-001 request plan', () => {
  test('the plan has exactly the declared request count and is reproducible per seed', () => {
    const scenario = scenarioById.get('uniform_mixed_workload');
    const first = buildRequestPlan(scenario, 11);
    const again = buildRequestPlan(scenario, 11);
    const otherSeed = buildRequestPlan(scenario, 12);
    assert.equal(first.length, scenario.arrival.requests);
    assert.deepEqual(first, again);
    assert.notDeepEqual(first, otherSeed);
  });

  test('the plan is not sorted by workload: the mix is shuffled, not batched', () => {
    const plan = buildRequestPlan(scenarioById.get('uniform_mixed_workload'), 11);
    const transitions = plan.filter((id, index) => index > 0 && id !== plan[index - 1]).length;
    assert.ok(transitions > plan.length / 2, 'a batched plan would hide ordering effects');
  });

  test('mix weights that do not sum to 100 are rejected', () => {
    const broken = {...scenarioById.get('warm_steady_state'), mix: [{workloadId: 'allow_acl_owner_read', weight: 50}]};
    assert.throws(() => buildRequestPlan(broken, 11), /SLOQUAL_MANIFEST_INVALID/);
  });
});

describe('SLOQUAL-001 warm steady state', () => {
  const execution = run('warm_steady_state');

  test('every dispatch produced a decision and every decision matched the frozen expectation', () => {
    assert.equal(execution.records.length, scenarioById.get('warm_steady_state').arrival.requests);
    assert.equal(execution.counters.unexpected_decision, 0);
    assert.equal(execution.counters.cross_tenant_allow, 0);
    assert.equal(execution.counters.missing_or_censored_samples, 0);
  });

  test('the run contains both decision classes (no degenerate measurement)', () => {
    assert.deepEqual(execution.decisionClasses, ['ALLOW', 'DENY']);
    assert.equal(execution.counters.degenerate_scenario_decision_distribution, 0);
  });

  test('the declared warmup is excluded from latency statistics but keeps its decisions', () => {
    const scenario = scenarioById.get('warm_steady_state');
    assert.equal(execution.warmupRequests, scenario.warmupRequests);
    assert.equal(execution.measuredWindow.dispatched, execution.records.length - scenario.warmupRequests);
    assert.equal(execution.latencySamples.length, execution.measuredWindow.dispatched);
    for (const sample of execution.latencySamples) assert.ok(Number.isFinite(sample) && sample >= 0);
  });

  test('independent executions of the same (scenario, seed) agree decision for decision', () => {
    const again = run('warm_steady_state');
    assert.deepEqual(
      execution.records.map((record) => record.decision),
      again.records.map((record) => record.decision),
    );
  });
});

describe('SLOQUAL-001 injected faults', () => {
  test('single-use grant replay: the grant is spent once and every replay is denied', () => {
    const execution = run('single_use_grant_replay');
    const exportRecords = execution.records.filter((record) => record.workloadId === 'single_use_grant_export');
    assert.ok(exportRecords.length > 1, 'the scenario must actually replay the grant');
    assert.equal(exportRecords[0].decision, 'ALLOW');
    assert.ok(exportRecords.slice(1).every((record) => record.decision === 'DENY'));
    assert.equal(execution.counters.single_use_grant_replay_allow, 0);
  });

  test('principal freeze: no allow survives the freeze instant', () => {
    const scenario = scenarioById.get('principal_freeze_fault');
    const execution = run('principal_freeze_fault');
    assert.equal(execution.counters.allow_after_principal_freeze, 0);
    const afterFreeze = execution.records.filter((record) => record.index >= scenario.freezeAfterRequests && record.principalId === scenario.freezePrincipalId);
    assert.ok(afterFreeze.length > 0, 'the frozen principal must be exercised after the freeze');
    assert.ok(afterFreeze.every((record) => record.decision === 'DENY'));
    assert.ok(afterFreeze.every((record) => record.reasonCodes.includes('PRINCIPAL_NOT_ACTIVE')));
  });

  test('engine recreation under load does not change a single decision', () => {
    const execution = run('engine_recreation_fault');
    assert.equal(execution.counters.decision_divergence_within_run, 0);
    assert.equal(execution.counters.unexpected_decision, 0);
  });
});

describe('SLOQUAL-001 S1-008 revocation gate', () => {
  const execution = run('revocation_gate_s1_008');

  test('every trial revokes an allowable grant and then denies with GRANT_REVOKED', () => {
    assert.equal(execution.records.length, scenarioById.get('revocation_gate_s1_008').revocationTrials);
    assert.equal(execution.counters.revocation_trial_precondition_failures, 0);
    assert.equal(execution.counters.allow_after_revocation_commit, 0);
    for (const record of execution.records) {
      assert.equal(record.decision, 'DENY');
      assert.ok(record.reasonCodes.includes(REVOCATION_PROBE.expectedDenyReasonCode), JSON.stringify(record.reasonCodes));
      assert.ok(Number.isFinite(record.latencyMs) && record.latencyMs >= 0);
    }
  });

  test('the commit-to-deny maximum stays far inside the S1-008 gate', () => {
    const max = Math.max(...execution.records.map((record) => record.latencyMs));
    assert.ok(max < 5000, `max commit-to-deny ${max} ms`);
  });
});

describe('SLOQUAL-001 pilot-scale honesty', () => {
  test('no scenario claims full scale and every full-scale requirement is NOT_RUN', () => {
    for (const scenario of manifest.scenarios) {
      assert.equal(scenario.scaleClass, 'PILOT');
      assert.equal(scenario.fullScaleRequirement.status, 'NOT_RUN');
    }
  });

  test('the soak scenario is declared pilot scale in seconds, not the full-scale 24 h requirement', () => {
    const soak = scenarioById.get('sustained_soak_pilot');
    assert.match(soak.fullScaleRequirement.requirement, /24 h/);
    assert.equal(soak.arrival.requests * manifest.seeds.length, 3600);
  });
});
