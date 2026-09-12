import Ajv2020 from 'ajv/dist/2020.js';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {evaluatePolicy, baseline} from '../src/lib/contract-policy.mjs';
import {runPolicyProbes} from './policy-probes.mjs';

const root = process.cwd();
const read = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), 'utf8'));
const writeJson = (relativePath, value) => fs.writeFileSync(path.join(root, relativePath), JSON.stringify(value, null, 2) + '\n');
const ajv = new Ajv2020({allErrors: true, strict: false});
for (const file of fs.readdirSync(path.join(root, 'contracts')).filter((file) => file.endsWith('.schema.json'))) {
  const schema = read(`contracts/${file}`);
  ajv.addSchema(schema, schema.$id);
}
let schemaExamples = 0;
let schemaMutationsRejected = 0;
const validate = (schemaName, data) => {
  const schemaId = `https://veritas.local/contracts/${schemaName}.schema.json`;
  const fn = ajv.getSchema(schemaId);
  assert(fn, `schema not registered: ${schemaName}`);
  const ok = fn(data);
  return {ok, errors: fn.errors};
};
const check = (schemaName, data) => {
  const result = validate(schemaName, data);
  assert.equal(result.ok, true, `${schemaName} rejected valid fixture: ${JSON.stringify(result.errors)}`);
  schemaExamples++;
};
const reject = (schemaName, data) => {
  const result = validate(schemaName, data);
  assert.equal(result.ok, false, `${schemaName} accepted invalid mutation`);
  schemaMutationsRejected++;
};

check('pilot-profile', read('pilots/pilot-profile.json'));
for (const scenario of ['a', 'b']) {
  const scenarioRoot = `pilots/scenario-${scenario}`;
  for (const name of ['task-brief', 'source-selection-manifest', 'acceptance-cases']) {
    check(name, read(`${scenarioRoot}/${name}.json`));
  }
  const outputName = scenario === 'a' ? 'solution-pack' : 'research-dossier';
  const output = read(`${scenarioRoot}/${outputName}.example.json`);
  check(outputName, output);
  check('human-decision', read(`${scenarioRoot}/human-decision.example.json`));

  const brief = read(`${scenarioRoot}/task-brief.json`);
  const acceptance = read(`${scenarioRoot}/acceptance-cases.json`);
  const caseIds = acceptance.cases.map((item) => item.id);
  assert.equal(new Set(caseIds).size, caseIds.length, `${scenario} acceptance case ids must be unique`);
  assert.equal(new Set(brief.output_ids).size, brief.output_ids.length, `${scenario} output ids must be unique`);
  for (const outputId of brief.output_ids) {
    const artifact = output.artifacts[outputId];
    assert(artifact, `${scenario} output ${outputId} has no artifact record`);
    const matchingCases = acceptance.cases.filter((item) => item.input === outputId);
    assert.equal(matchingCases.length, 1, `${scenario} output ${outputId} must map to one acceptance case`);
    assert.equal(artifact.acceptance_case, matchingCases[0].id);
    assert.equal(artifact.status, 'NOT_RUN');
    assert.equal(artifact.path, null);
    assert.equal(artifact.sha256, null);
  }
  for (const property of ['goal', 'unknowns', 'execution_authorized']) {
    const changed = structuredClone(brief);
    delete changed[property];
    reject('task-brief', changed);
  }
  reject('task-brief', {...brief, execution_authorized: true});
  reject('task-brief', {...brief, status: 'FROZEN'});
  reject(outputName, {...output, execution_status: 'MEASURED'});
  reject('human-decision', {...read(`${scenarioRoot}/human-decision.example.json`), status: 'APPROVED'});
  reject('human-decision', {...read(`${scenarioRoot}/human-decision.example.json`), actor_type: 'agent'});
  const manifest = read(`${scenarioRoot}/source-selection-manifest.json`);
  reject('source-selection-manifest', {...manifest, contains_private_content: true});
  const leak = structuredClone(manifest);
  leak.sources[0].content = 'synthetic private canary';
  reject('source-selection-manifest', leak);
  const traversal = structuredClone(manifest);
  traversal.sources[0].safe_reference = 'repo:../../.env';
  reject('source-selection-manifest', traversal);
  const result = structuredClone(output);
  const first = Object.keys(result.artifacts)[0];
  result.artifacts[first].status = 'PRESENT';
  reject(outputName, result);
}

const policyReport = runPolicyProbes({writeReport: true});
const adversarial = policyReport.results.filter((result) => result.id.startsWith('S2-001-'));
assert.equal(adversarial.length, 7);
assert.equal(adversarial.every((result) => result.pass && result.entryPoint.endsWith('#evaluatePolicy')), true);
assert.equal(evaluatePolicy(baseline).verdict, 'ELIGIBLE_FOR_LOCAL_CHECK');
assert.equal(evaluatePolicy({}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...baseline, permissionChange: true}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...baseline, rolloutRequested: true}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...baseline, finalApproval: true, actor: 'human', authenticated: true, humanIdentityConfirmed: true}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...baseline, status: 'DONE', actorType: 'service'}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...baseline, artifactCount: -1}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...baseline, coverage: Number.NaN}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...baseline, unknownAuthority: true}).verdict, 'BLOCKED');

reject('pilot-profile', {...read('pilots/pilot-profile.json'), status: 'READY'});
const budget = {...baseline, operation: 'read', actorId: 'synthetic-budget-actor', requiresSpend: true, budgetApproved: true, taskBudget: 1, campaignBudget: 2, dailyBudget: 3, timeout: 1, currency: 'TST', budgetGrant: {type: 'budget_grant', authenticated: true, principalId: 'synthetic-budget-actor', scope: 'budget', grantRef: 'synthetic-grant-001', expiresAt: '2099-01-01T00:00:00Z', taskBudget: 1, campaignBudget: 2, dailyBudget: 3, currency: 'TST', timeout: 1}};
assert.equal(evaluatePolicy(budget).verdict, 'ELIGIBLE_FOR_LOCAL_CHECK');
for (const field of ['taskBudget', 'campaignBudget', 'dailyBudget', 'timeout']) {
  const value = {...budget};
  delete value[field];
  assert.equal(evaluatePolicy(value).verdict, 'NEEDS_INPUT');
}
assert.equal(evaluatePolicy({...budget, budgetApproved: false}).verdict, 'NEEDS_INPUT');
assert.equal(evaluatePolicy({...budget, budgetGrant: undefined}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...budget, taskBudget: 0}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...budget, taskBudget: NaN}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...budget, coverage: NaN}).verdict, 'BLOCKED');
assert.equal(evaluatePolicy({...baseline, requiresSource: true, sourcePresent: true, sourceAuthorized: false}).verdict, 'NEEDS_INPUT');
assert.equal(evaluatePolicy({...baseline, requiresSource: true, sourcePresent: true, sourceAuthorized: true}).verdict, 'BLOCKED');

const frozenTargets = [
  'contracts', 'pilots', 'docs/product', 'docs/scenarios',
  'src/lib/contract-policy.mjs', 'scripts/policy-probes.mjs', 'scripts/validate-contracts.mjs', 'evidence/probe-registry.json',
  // S2-002: identity/sandbox implementation, oracle suites, corpus runner,
  // comparator and security documentation are frozen alongside S2-001 files.
  'src/lib/identity', 'tests/identity', 'docs/security',
  'scripts/s2-002-run.mjs', 'scripts/security-probes.mjs', 'scripts/verify-s2-002.mjs',
  'scripts/verify-s2-002-dependencies.mjs', 'scripts/verify-clean-checkout.mjs',
  'evidence/s2-002-dependency-binding.json', 'evidence/s2-002-security-probes.json',
];
const walk = (target) => {
  const normalized = target.split(path.sep).join('/');
  const full = path.join(root, ...target.split(/[\\/]/));
  if (!fs.existsSync(full)) return [];
  if (fs.statSync(full).isFile()) return [normalized];
  return fs.readdirSync(full, {withFileTypes: true})
    .flatMap((entry) => {
      const nested = `${normalized}/${entry.name}`;
      return entry.isDirectory() ? walk(nested) : [nested];
    });
};
const relative = (full) => path.relative(root, full).split(path.sep).join('/');
const frozenFiles = frozenTargets.flatMap((target) => walk(target)).map(relative).sort();
const frozenManifest = Object.fromEntries(frozenFiles.map((file) => [file, crypto.createHash('sha256').update(fs.readFileSync(path.join(root, file))).digest('hex')]));
const frozenPath = 'evidence/frozen-manifest.json';
if (process.argv.includes('--freeze')) {
  writeJson(frozenPath, {
    schemaVersion: 1,
    scope: 'Draft contract, policy and validator integrity only; not experiment authorization',
    algorithm: 'SHA-256 raw file bytes',
    files: frozenManifest,
  });
} else {
  assert.deepEqual(frozenManifest, read(frozenPath).files, 'Frozen draft files changed: run an explicit reviewed freeze');
}

const report = {
  schemaVersion: 1,
  scope: 'Offline contract validation; no real adapters, no semantic calibration, no pilot imports or paid experiments',
  policyEntryPoints: ['src/lib/contract-policy.mjs#evaluatePolicy'],
  schemaExamples,
  schemaMutationsRejected,
  policyProbes: policyReport.total,
  policyProbesPassed: policyReport.passed,
  adversarialProbes: adversarial.length,
  adversarialProbesPassed: adversarial.filter((result) => result.pass).length,
  positiveControls: 2,
  additionalPrerequisiteChecks: 8,
  pilotExecutions: 0,
  fullAcceptanceAtZeroExecutions: 'BLOCKED',
  exitCode: 0,
};
writeJson('evidence/contract-tests.json', report);
console.log(JSON.stringify(report, null, 2));
