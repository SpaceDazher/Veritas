import fs from 'node:fs';
import assert from 'node:assert/strict';
import {evaluatePolicy, baseline} from '../src/lib/contract-policy.mjs';
import {runPolicyProbes} from './policy-probes.mjs';
import {readAcceptanceState} from './acceptance-gate.mjs';
import {verifyPostgresSmokeRecord} from './verify-postgres-smoke.mjs';

const policy = evaluatePolicy(baseline);
assert.equal(policy.verdict, 'ELIGIBLE_FOR_LOCAL_CHECK');
const probes = runPolicyProbes({writeReport: true});
assert.equal(probes.passed, probes.total);
const acceptance = readAcceptanceState();
assert.equal(acceptance.verdict, 'BLOCKED');
assert.equal(acceptance.pilotExecutions, 0);
const postgresEvidence = JSON.parse(fs.readFileSync('evidence/postgres-smoke.json', 'utf8'));
assert.deepEqual(verifyPostgresSmokeRecord(postgresEvidence), {ok: true, issues: []});
const report = {
  schemaVersion: 1,
  exitCode: 0,
  scope: 'Deterministic offline synthetic smoke plus validation of tracked real PostgreSQL evidence; no browser, adapter, paid model or pilot execution',
  policyEntryPoints: ['src/lib/contract-policy.mjs#evaluatePolicy'],
  policyProbesPassed: probes.passed,
  policyProbesTotal: probes.total,
  acceptanceVerdict: acceptance.verdict,
  pilotExecutions: acceptance.pilotExecutions,
  databaseWorkspaceSmoke: 'PASS_TRACKED_EPHEMERAL_POSTGRES',
  databaseEvidence: {
    path: 'evidence/postgres-smoke.json',
    image: postgresEvidence.image,
    serverVersion: postgresEvidence.serverVersion,
    migrationCount: postgresEvidence.migrationCount,
    transactionCommitted: postgresEvidence.transactionCommitted,
    duplicateOperationRejected: postgresEvidence.duplicateOperationRejected,
  },
  screenshots: [],
};
fs.writeFileSync('evidence/synthetic-smoke.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
