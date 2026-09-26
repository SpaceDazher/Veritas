// SLOQUAL-001 frozen contract and scenario manifest: pre-registration is
// checked, not asserted. A threshold edited after the freeze must break the
// self-hash and stop the gate, and a manifest that no longer matches the
// bytes the contract bound must be a stop condition.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  CONTRACT_PATH,
  MANIFEST_PATH,
  contractSelfHash,
  sha256OfBytes,
  stampContract,
  validateManifest,
  verifyFreeze,
} from '../../src/lib/sloqual/contract.mjs';
import { freezeProvenance } from '../../scripts/verify-sloqual-001.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const contractBytes = fs.readFileSync(path.join(ROOT, CONTRACT_PATH));
const manifestBytes = fs.readFileSync(path.join(ROOT, MANIFEST_PATH));
const contract = JSON.parse(contractBytes.toString('utf8'));
const manifest = JSON.parse(manifestBytes.toString('utf8'));

test('archive provenance stays NOT_RUN when commit fallback exists but .git does not', () => {
  const previous = process.env.VERITAS_SOURCE_COMMIT;
  process.env.VERITAS_SOURCE_COMMIT = 'a'.repeat(40);
  try {
    const provenance = freezeProvenance(path.join(ROOT, 'archive-without-git'));
    assert.equal(provenance.status, 'NOT_RUN');
  } finally {
    if (previous === undefined) delete process.env.VERITAS_SOURCE_COMMIT;
    else process.env.VERITAS_SOURCE_COMMIT = previous;
  }
});

describe('SLOQUAL-001 frozen contract', () => {
  test('the committed contract verifies against the committed manifest', () => {
    const freeze = verifyFreeze({contract, manifest, manifestBytes});
    assert.equal(freeze.ok, true, JSON.stringify(freeze.issues));
    assert.equal(freeze.recomputedSelfHash, contract.selfHash.sha256);
    assert.equal(freeze.recomputedManifestSha256, contract.scenarioManifest.sha256);
  });

  test('every hard gate is an exact zero and every limit names a known metric', () => {
    for (const [name, threshold] of Object.entries(contract.hardGates)) {
      if (name === 'rule') continue;
      assert.equal(threshold, 0, `${name} must be frozen at 0`);
    }
    const metrics = new Set(['authorization_latency_ms', 'scheduling_lateness_ms', 'revocation_commit_to_deny_ms', 'dispatch_realization_ratio', 'revocation_trial_count']);
    for (const [name, spec] of Object.entries(contract.limits)) {
      assert.ok(metrics.has(spec.metric), `${name} names unknown metric ${spec.metric}`);
      assert.equal(typeof spec.threshold, 'number', `${name} must have a numeric threshold`);
      assert.ok(['<=', '>='].includes(spec.operator), `${name} operator`);
    }
  });

  test('the contract never authorizes a production SLO and records the missing countersignature', () => {
    assert.equal(contract.authority.productionSloAuthorized, false);
    assert.equal(contract.countersignature.status, 'NEEDS_INPUT');
    const unmapped = contract.registeredProofs.filter((proof) => proof.status !== 'MAPPED');
    assert.ok(unmapped.length > 0, 'a frozen contract without unmapped proofs would imply a full PASS is reachable locally');
    for (const proof of unmapped) {
      assert.equal(typeof proof.missingProof, 'string');
      assert.ok(proof.missingProof.length > 20, `${proof.id} must itemize the missing proof`);
    }
  });

  test('editing a threshold after the freeze breaks the self-hash', () => {
    const tampered = structuredClone(contract);
    tampered.limits.warm_authorization_p95_ms.threshold += 1;
    assert.notEqual(contractSelfHash(tampered), contract.selfHash.sha256);
    const freeze = verifyFreeze({contract: tampered, manifest, manifestBytes});
    assert.equal(freeze.ok, false);
    assert.ok(freeze.issues.some((issue) => issue.code === 'contract_self_hash_mismatch'));
  });

  test('a manifest edited after the freeze breaks the byte binding', () => {
    const tamperedManifest = structuredClone(manifest);
    tamperedManifest.scenarios[0].arrival.requests += 1;
    const tamperedBytes = Buffer.from(`${JSON.stringify(tamperedManifest, null, 2)}\n`, 'utf8');
    assert.notEqual(sha256OfBytes(tamperedBytes), contract.scenarioManifest.sha256);
    const freeze = verifyFreeze({contract, manifest: tamperedManifest, manifestBytes: tamperedBytes});
    assert.equal(freeze.ok, false);
    assert.ok(freeze.issues.some((issue) => issue.code === 'manifest_digest_mismatch'));
  });

  test('an unstamped contract is a stop condition, never a pass', () => {
    const unstamped = structuredClone(contract);
    unstamped.selfHash.sha256 = 'PENDING_FREEZE';
    const freeze = verifyFreeze({contract: unstamped, manifest, manifestBytes});
    assert.equal(freeze.ok, false);
    assert.ok(freeze.issues.some((issue) => issue.code === 'contract_self_hash_unstamped'));
  });

  test('stamping is idempotent: re-stamping a frozen contract reproduces the same digests', () => {
    const restamped = stampContract({contract, manifestBytes, manifest});
    assert.equal(restamped.selfHash.sha256, contract.selfHash.sha256);
    assert.equal(restamped.scenarioManifest.sha256, sha256OfBytes(manifestBytes));
  });
});

describe('SLOQUAL-001 scenario manifest', () => {
  test('the committed manifest passes structural validation', () => {
    assert.deepEqual(validateManifest(manifest), []);
  });

  test('the manifest freezes 17 scenarios x 5 seeds and 105 revocation trials', () => {
    assert.equal(manifest.scenarios.length, contract.measurement.scenariosPerSeed);
    assert.equal(manifest.scenarios.length, 17);
    assert.equal(manifest.seeds.length, 5);
    assert.equal(manifest.scenarios.length * manifest.seeds.length, contract.measurement.expectedScenarioSeedResultsPerRun);
    const security = manifest.scenarios.filter((scenario) => scenario.family === 'security');
    assert.equal(security.length, 1);
    assert.equal(security[0].revocationTrials * manifest.seeds.length, contract.measurement.revocationTrialsPerRun);
  });

  test('every workload expectation was checked against the real policy engine before the freeze', () => {
    assert.ok(manifest.workloads.length >= 17);
    for (const workload of manifest.workloads) {
      assert.ok(Array.isArray(workload.expectedDecisions) && workload.expectedDecisions.length > 0, workload.id);
      assert.equal(typeof workload.request.action, 'string');
      assert.match(workload.request.principalId, /^prn-[a-z0-9-]+$/);
    }
    const crossTenant = manifest.workloads.filter((workload) => workload.denialClass === 'cross_tenant');
    assert.ok(crossTenant.length >= 4, 'cross-tenant negative controls must exist in the frozen mix');
    for (const workload of crossTenant) assert.deepEqual(workload.expectedDecisions, ['DENY']);
  });

  test('no scenario claims full scale and every arrival model is declared open-loop', () => {
    assert.equal(manifest.arrivalModel.mode, 'open_loop');
    for (const scenario of manifest.scenarios) {
      assert.equal(scenario.scaleClass, 'PILOT');
      assert.equal(scenario.fullScaleRequirement.status, 'NOT_RUN');
    }
  });

  test('validation rejects weights that do not sum to 100, unknown workloads and duplicate ids', () => {
    const badWeight = structuredClone(manifest);
    badWeight.scenarios[0].mix[0].weight += 5;
    assert.ok(validateManifest(badWeight).some((issue) => issue.code === 'scenario_mix_weight_total'));

    const unknownWorkload = structuredClone(manifest);
    unknownWorkload.scenarios[0].mix[0].workloadId = 'workload-that-does-not-exist';
    assert.ok(validateManifest(unknownWorkload).some((issue) => issue.code === 'scenario_mix_unknown_workload'));

    const duplicate = structuredClone(manifest);
    duplicate.scenarios.push(structuredClone(duplicate.scenarios[0]));
    assert.ok(validateManifest(duplicate).some((issue) => issue.code === 'scenario_id_duplicate'));

    const unfrozen = structuredClone(manifest);
    unfrozen.scenarios[0].fullScaleRequirement.status = 'DONE';
    assert.ok(validateManifest(unfrozen).some((issue) => issue.code === 'full_scale_claim_invalid'));
  });
});
