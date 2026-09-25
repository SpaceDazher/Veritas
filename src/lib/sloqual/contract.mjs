// SLOQUAL-001 frozen contract and scenario-manifest handling.
//
// The contract is pre-registered: thresholds, statistics, gates and the list
// of registered proofs are frozen (self-hashed) before the first
// measurement, and the frozen contract binds the exact scenario-manifest
// bytes. A run that does not match both digests is not a qualification of
// this contract, and `verifyFreeze` fails closed instead of degrading.
import { createHash } from 'node:crypto';
import { canonicalDigest } from '../verifier/canonical-json.mjs';

export const FREEZE_RULE = 'sloqual-freeze-v1';

export const CONTRACT_PATH = 'contracts/sloqual-001-slo-contract.json';
export const MANIFEST_PATH = 'contracts/sloqual-001-scenario-manifest.json';

const SHA256 = /^[0-9a-f]{64}$/;
const PENDING = 'PENDING_FREEZE';

function issue(code, detail) {
  return {code, detail};
}

export function sha256OfBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

// Self-hash is taken over the contract with the digest field itself removed:
// a document cannot contain its own hash.
export function contractSelfHash(contract) {
  const { selfHash, ...rest } = contract ?? {};
  return canonicalDigest(rest);
}

export function manifestDigest(manifest) {
  return canonicalDigest(manifest);
}

// Stamps the manifest binding first (it changes the contract bytes) and only
// then the self-hash, so a stamped contract verifies immediately.
export function stampContract({ contract, manifestBytes, manifest }) {
  const stamped = structuredClone(contract);
  if (!stamped.scenarioManifest || typeof stamped.scenarioManifest !== 'object') {
    throw new TypeError('SLOQUAL_FREEZE_INVALID: contract.scenarioManifest binding is missing');
  }
  stamped.scenarioManifest.sha256 = sha256OfBytes(manifestBytes);
  if (manifest && typeof manifest.version === 'string') stamped.scenarioManifest.version = manifest.version;
  stamped.selfHash = {...(stamped.selfHash ?? {}), sha256: contractSelfHash(stamped)};
  return stamped;
}

export function assertStampable({ contract, manifestBytes, manifest }) {
  const issues = [];
  if (!contract || typeof contract !== 'object') return [issue('contract_missing', 'contract is not an object')];
  if (contract.status !== 'FROZEN') issues.push(issue('contract_not_frozen', `status=${String(contract.status)}`));
  if (typeof contract.version !== 'string' || contract.version.length === 0) issues.push(issue('contract_version_missing', ''));
  if (typeof contract.hardGates !== 'object' || contract.hardGates === null || Array.isArray(contract.hardGates)) {
    issues.push(issue('hard_gates_missing', 'contract.hardGates must be an object'));
  }
  if (!Array.isArray(contract.registeredProofs) || contract.registeredProofs.length === 0) {
    issues.push(issue('registered_proofs_missing', 'contract.registeredProofs must be a non-empty array'));
  }
  if (!Buffer.isBuffer(manifestBytes) && !(manifestBytes instanceof Uint8Array)) {
    issues.push(issue('manifest_bytes_missing', 'raw manifest bytes are required'));
  } else {
    if (!SHA256.test(contract.scenarioManifest?.sha256 ?? '') || contract.scenarioManifest.sha256 === PENDING) {
      issues.push(issue('manifest_binding_unstamped', `scenarioManifest.sha256=${String(contract.scenarioManifest?.sha256)}`));
    } else if (sha256OfBytes(manifestBytes) !== contract.scenarioManifest.sha256) {
      issues.push(issue('manifest_digest_mismatch', 'manifest bytes digest != contract.scenarioManifest.sha256'));
    }
  }
  if (!SHA256.test(contract.selfHash?.sha256 ?? '') || contract.selfHash.sha256 === PENDING) {
    issues.push(issue('contract_self_hash_unstamped', `selfHash.sha256=${String(contract.selfHash?.sha256)}`));
  } else if (contractSelfHash(contract) !== contract.selfHash.sha256) {
    issues.push(issue('contract_self_hash_mismatch', 'recomputed contract self-hash != recorded selfHash.sha256'));
  }
  if (manifest && typeof manifest.version === 'string' && contract.scenarioManifest?.version !== manifest.version) {
    issues.push(issue('manifest_version_mismatch', `contract=${String(contract.scenarioManifest?.version)} manifest=${manifest.version}`));
  }
  for (const [name, gate] of Object.entries(contract.hardGates ?? {})) {
    if (name === 'rule') continue;
    if (gate !== 0) issues.push(issue('hard_gate_not_zero', `${name}=${String(gate)}`));
  }
  return issues;
}

export function verifyFreeze({ contract, manifest, manifestBytes }) {
  const issues = assertStampable({ contract, manifestBytes, manifest });
  return {
    rule: FREEZE_RULE,
    ok: issues.length === 0,
    issues,
    contractVersion: contract?.version ?? null,
    contractSelfHash: contract?.selfHash?.sha256 ?? null,
    recomputedSelfHash: contract && typeof contract === 'object' ? contractSelfHash(contract) : null,
    manifestVersion: manifest?.version ?? null,
    manifestSha256: SHA256.test(contract?.scenarioManifest?.sha256 ?? '') ? contract.scenarioManifest.sha256 : null,
    recomputedManifestSha256: manifestBytes ? sha256OfBytes(manifestBytes) : null,
    manifestDigest: manifest ? manifestDigest(manifest) : null,
  };
}

// Structural validation of the scenario manifest. Returns a list of issues;
// the caller must treat a non-empty list as a stop condition.
export function validateManifest(manifest) {
  const issues = [];
  const add = (code, detail) => issues.push(issue(code, detail));
  if (!manifest || typeof manifest !== 'object') return [issue('manifest_missing', 'scenario manifest is not an object')];
  if (manifest.status !== 'FROZEN') add('manifest_not_frozen', `status=${String(manifest.status)}`);
  if (typeof manifest.version !== 'string') add('manifest_version_missing', '');
  if (!Array.isArray(manifest.seeds) || manifest.seeds.length === 0) add('seeds_missing', 'at least one seed is required');
  else if (manifest.seeds.some((seed) => !Number.isInteger(seed) || seed < 0)) add('seed_invalid', JSON.stringify(manifest.seeds));
  else if (new Set(manifest.seeds).size !== manifest.seeds.length) add('seed_duplicate', JSON.stringify(manifest.seeds));
  if (manifest.arrivalModel?.mode !== 'open_loop') add('arrival_model_invalid', `mode=${String(manifest.arrivalModel?.mode)}`);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(manifest.policyEngine?.fixedClock ?? '')) {
    add('policy_clock_invalid', String(manifest.policyEngine?.fixedClock));
  }

  const workloadIds = new Set();
  for (const workload of manifest.workloads ?? []) {
    if (typeof workload?.id !== 'string' || workload.id.length === 0) add('workload_id_missing', JSON.stringify(workload?.id));
    else if (workloadIds.has(workload.id)) add('workload_id_duplicate', workload.id);
    else workloadIds.add(workload.id);
    if (!workload?.request || typeof workload.request !== 'object') add('workload_request_missing', String(workload?.id));
    if (!Array.isArray(workload?.expectedDecisions) || workload.expectedDecisions.length === 0) {
      add('workload_expectation_missing', String(workload?.id));
    }
  }

  const scenarioIds = new Set();
  for (const scenario of manifest.scenarios ?? []) {
    const id = scenario?.id ?? '<missing>';
    if (typeof scenario?.id !== 'string' || scenario.id.length === 0) add('scenario_id_missing', id);
    else if (scenarioIds.has(scenario.id)) add('scenario_id_duplicate', scenario.id);
    else scenarioIds.add(scenario.id);
    if (typeof scenario?.family !== 'string') add('scenario_family_missing', id);
    if (scenario?.scaleClass !== 'PILOT') add('scenario_scale_class_invalid', `${id}: scaleClass=${String(scenario?.scaleClass)}`);
    if (scenario?.fullScaleRequirement?.status !== 'NOT_RUN') add('full_scale_claim_invalid', `${id}: ${String(scenario?.fullScaleRequirement?.status)}`);
    const mix = Array.isArray(scenario?.mix) ? scenario.mix : [];
    if (mix.length === 0) add('scenario_mix_empty', id);
    const weightTotal = mix.reduce((sum, entry) => sum + (Number.isFinite(entry?.weight) ? entry.weight : 0), 0);
    if (mix.length > 0 && weightTotal !== 100) add('scenario_mix_weight_total', `${id}: ${weightTotal}`);
    for (const entry of mix) {
      if (!workloadIds.has(entry?.workloadId)) add('scenario_mix_unknown_workload', `${id}: ${String(entry?.workloadId)}`);
    }
    const classes = new Set((mix.map((entry) => manifest.workloads.find((w) => w.id === entry.workloadId)?.expectedDecisions ?? []).flat()));
    for (const required of scenario?.decisionClassesRequired ?? []) {
      if (!classes.has(required)) add('scenario_decision_class_unreachable', `${id}: ${required}`);
    }
    const requests = scenario?.arrival?.requests;
    if (!Number.isInteger(requests) || requests < 1) add('scenario_requests_invalid', `${id}: ${String(requests)}`);
    const rate = scenario?.arrival?.ratePerSecond;
    if (scenario?.arrival?.mode !== 'closed_loop' && (!Number.isFinite(rate) || rate <= 0)) {
      add('scenario_rate_invalid', `${id}: ${String(rate)}`);
    }
    if (scenario?.arrival?.mode === 'burst') {
      if (!Number.isInteger(scenario.arrival.burstSize) || scenario.arrival.burstSize < 1) add('scenario_burst_size_invalid', id);
      if (!Number.isFinite(scenario.arrival.burstWindowMs) || scenario.arrival.burstWindowMs < 0) add('scenario_burst_window_invalid', id);
    }
    if (scenario?.family === 'security' && !Number.isInteger(scenario?.revocationTrials)) add('scenario_revocation_trials_invalid', id);
  }
  return issues;
}
