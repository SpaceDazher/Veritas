import fs from 'node:fs';
import assert from 'node:assert/strict';
import {evaluatePolicy, baseline} from '../src/lib/contract-policy.mjs';
import {runPolicyProbes} from './policy-probes.mjs';
import {readAcceptanceState} from './acceptance-gate.mjs';

const policy = evaluatePolicy(baseline);
assert.equal(policy.verdict, 'ELIGIBLE_FOR_LOCAL_CHECK');
const probes = runPolicyProbes({writeReport: true});
assert.equal(probes.passed, probes.total);
const acceptance = readAcceptanceState();
assert.equal(acceptance.verdict, 'BLOCKED');
assert.equal(acceptance.pilotExecutions, 0);
const report = {
  schemaVersion: 1,
  exitCode: 0,
  scope: 'Deterministic offline synthetic smoke; no database, browser, adapter, paid model or pilot execution',
  policyEntryPoints: ['src/lib/contract-policy.mjs#evaluatePolicy'],
  policyProbesPassed: probes.passed,
  policyProbesTotal: probes.total,
  acceptanceVerdict: acceptance.verdict,
  pilotExecutions: acceptance.pilotExecutions,
  databaseWorkspaceSmoke: process.env.DATABASE_URL ? 'NOT_RUN_REQUIRES_LOCAL_SERVER' : 'NOT_RUN_DATABASE_URL_ABSENT',
  screenshots: [],
};
fs.writeFileSync('evidence/synthetic-smoke.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
