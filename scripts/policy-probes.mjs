import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {evaluatePolicy, baseline, mutations, policyVersion} from '../src/lib/contract-policy.mjs';

const root = process.cwd();
const registryPath = path.join(root, 'evidence/probe-registry.json');
const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
const entryPoint = '../src/lib/contract-policy.mjs#evaluatePolicy';

function inputFor(probe) {
  const mutation = mutations[probe];
  assert(mutation, `missing production mutation fixture: ${probe}`);
  // JSON cannot represent NaN; construct it in the production-facing input here.
  return probe === 'nan-coverage' ? {...baseline, ...mutation, coverage: Number.NaN} : {...baseline, ...mutation};
}

export function runPolicyProbes({writeReport = false} = {}) {
  const results = registry.map((probe) => {
    const input = inputFor(probe.probe);
    const actual = evaluatePolicy(input);
    assert.equal(actual.verdict, probe.expected, `${probe.id} expected ${probe.expected}, got ${actual.verdict}`);
    assert.equal(actual.policyVersion, policyVersion, `${probe.id} must report the canonical policy version`);
    assert(Array.isArray(actual.issues), `${probe.id} must return an issue list`);
    if (probe.expected === 'BLOCKED') assert(actual.issues.some((issue) => issue.level === 'blocked'), `${probe.id} must contain a blocked issue`);
    if (probe.expected === 'NEEDS_INPUT') assert(actual.issues.some((issue) => issue.level === 'needs_input'), `${probe.id} must contain a needs_input issue`);
    if (probe.expected === 'HUMAN_REVIEW') assert(actual.issues.some((issue) => issue.level === 'human_review'), `${probe.id} must contain a human_review issue`);
    return {
      id: probe.id,
      probe: probe.probe,
      expected: probe.expected,
      actual: actual.verdict,
      pass: true,
      entryPoint,
      policyVersion,
      operation: actual.operation,
      issues: actual.issues,
      scope: 'synthetic production-facing policy entry point; no runtime authority is granted',
    };
  });
  const report = {
    schemaVersion: 1,
    policyVersion,
    entryPoint,
    total: results.length,
    passed: results.filter((result) => result.pass).length,
    pilotExecutions: 0,
    results,
  };
  if (writeReport) {
    fs.writeFileSync(path.join(root, 'evidence/policy-probes.json'), JSON.stringify(report, null, 2) + '\n');
  }
  return report;
}

const modulePath = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  try {
    const report = runPolicyProbes({writeReport: true});
    console.log(JSON.stringify({...report, results: undefined}, null, 2));
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}
