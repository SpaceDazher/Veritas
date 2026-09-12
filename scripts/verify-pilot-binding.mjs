import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const HEX64 = /^[0-9a-f]{64}$/;
const normalize = (value) => {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, normalize(value[key])]));
  }
  return value;
};
const canonicalHash = (value) => crypto.createHash('sha256')
  .update(JSON.stringify(normalize(value)), 'utf8').digest('hex');
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), 'utf8'));

const binding = readJson('evidence/s2-001-pilot-binding.json');
const { bindingDigest, ...bindingInput } = binding;
assert.equal(bindingDigest, canonicalHash(bindingInput));
assert.equal(binding.ticketId, 'S2-001');
assert.equal(binding.result, 'PASS_WITH_LIMITS');
assert.equal(binding.upstream.repository, 'SpaceDazher/Veritas-AI-Production-Pilot');
assert.equal(binding.upstream.mainCommit, '6845858bccf3aec27c656649ac40ad01148e7505');
assert.equal(binding.upstream.treeSha, 'b5341a37be08b318f28015cf83afeb106fe4138b');
assert.equal(binding.productionDeploymentAuthorized, false);
assert.equal(binding.scenarioB.status, 'CONTRACT_ONLY_NOT_EXECUTED');
assert.equal(binding.artifacts.length, 4);

for (const artifact of binding.artifacts) {
  assert(HEX64.test(artifact.upstreamFileSha256));
  assert(HEX64.test(artifact.canonicalJsonSha256));
  const snapshot = readJson(artifact.snapshotPath);
  assert.equal(canonicalHash(snapshot), artifact.canonicalJsonSha256);
}

const closure = readJson('evidence/external/s2-001/pilot-closure-manifest.json');
const { closureDigest, ...closureInput } = closure;
assert.equal(closureDigest, canonicalHash(closureInput));
assert.equal(closure.verdict, 'PASS_WITH_LIMITS');
assert.equal(closure.status, 'DONE');
assert.equal(closure.decision.actorId, 'repository-owner');
assert.equal(closure.decision.scope, 'solution');
assert.equal(closure.productionDeploymentAuthorized, false);
assert.equal(closure.productionDeployed, false);

const replay = readJson('evidence/external/s2-001/clean-checkout.json');
const { evidenceDigest, ...replayInput } = replay;
assert.equal(evidenceDigest, canonicalHash(replayInput));
assert.equal(replay.exitCode, 0);
assert.equal(replay.verdict, 'PASS_PILOT_COMPLETE_WITH_LIMITS');

const run = readJson('evidence/external/s2-001/pilot-run-manifest.json');
const { pilotRunDigest, ...runInput } = run;
assert.equal(pilotRunDigest, canonicalHash(runInput));
assert.equal(run.taskId, closure.taskId);
assert.equal(run.submissionDigest, closure.submissionDigest);

const acceptance = readJson('evidence/external/s2-001/acceptance-cases.json');
assert.equal(acceptance.status, 'PASS_WITH_LIMITS');
assert.deepEqual(
  acceptance.cases.filter((item) => item.status === 'NOT_PROVEN').map((item) => item.id),
  ['AC-06', 'AC-09'],
);

console.log(JSON.stringify({
  verdict: 'PASS',
  ticketId: binding.ticketId,
  result: binding.result,
  upstreamMainCommit: binding.upstream.mainCommit,
  verifiedArtifacts: binding.artifacts.length,
  productionDeploymentAuthorized: false,
}, null, 2));
