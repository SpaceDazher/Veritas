import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { createA05ReviewServer, hashA05ReviewToken } from '../../scripts/a-mvp05-review.mjs';
import { setupA05Database } from '../../scripts/a-mvp05-runtime.mjs';
import { createS2PaidReviewWorkflow } from '../../scripts/s2-008-paid-review.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';

const OWNER = 'prn-s2007r-owner';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
function makeFixtureTreeRemovable(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('FIXTURE_CLEANUP_PATH_INVALID');
  fs.chmodSync(directory, 0o700);
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    const child = fs.lstatSync(target);
    if (child.isDirectory() && !child.isSymbolicLink()) makeFixtureTreeRemovable(target);
    else if (child.isFile() && !child.isSymbolicLink()) fs.chmodSync(target, 0o600);
    else throw new Error('FIXTURE_CLEANUP_ENTRY_INVALID');
  }
}

test('opt-in fixture-only paid review runs the isolated AgentBoard import lifecycle over authenticated HTTP', {
  skip: process.env.S2_008_PAID_REVIEW_INTEGRATION !== '1',
}, async (t) => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-paid-review-fixture-'));
  fs.chmodSync(temporaryRoot, 0o700);
  const fixtureRoot = path.join(temporaryRoot, 'evidence');
  const stateRoot = path.join(temporaryRoot, 'state');
  fs.mkdirSync(path.join(fixtureRoot, 'fixture'), { recursive: true, mode: 0o700 });
  const fixtureBytes = Buffer.from(JSON.stringify({ fixture_only: true, purpose: 'offline-importer-integration' }) + '\n');
  fs.writeFileSync(path.join(fixtureRoot, 'fixture', 'snapshot.json'), fixtureBytes, { mode: 0o600, flag: 'wx' });
  const fixtureRecords = [{ path: 'fixture/snapshot.json', bytes: fixtureBytes.length, sha256: sha(fixtureBytes) }];
  let pool;
  let server;
  t.after(async () => {
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
    if (pool) await pool.end();
    makeFixtureTreeRemovable(temporaryRoot);
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  });

  ({ pool } = await setupA05Database());
  const workflow = createS2PaidReviewWorkflow({
    pool, fixtureOnly: true, fixtureRoot, fixtureRecords, stateRoot,
  });
  assert.match(workflow.taskId, /^abt-s2-008-v11-fixture-[a-f0-9]{12}$/);
  assert.notEqual(workflow.taskId, 'abt-s2-008-v11-paid-review');
  const token = randomBytes(32).toString('base64url');
  const credential = {
    tokenHash: hashA05ReviewToken(token), principalId: OWNER, taskId: workflow.taskId,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    actions: ['view', 'start', 'request_changes'],
  };
  server = createA05ReviewServer({ credential, workflow, presentation: 'paid-evidence-review' });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const origin = 'http://127.0.0.1:' + server.address().port;
  const headers = { authorization: 'Bearer ' + token };
  const start = await fetch(origin + '/api/start', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(start.status, 200, JSON.stringify(await start.clone().json()));
  const started = await start.json();
  assert.equal(started.taskId, workflow.taskId);
  assert.equal(started.fixture_only, true);
  assert.equal(started.state, 'IN_REVIEW');
  assert.equal(started.ready, true, JSON.stringify({ reasons: started.reasons, importReport: started.importReport }));
  assert.equal(started.importReport.status, 'PASS');
  assert.equal(started.importReport.fixture_only, true);
  assert.equal(started.importReport.network, 'none');
  assert.equal(started.importReport.model_calls, 0);
  assert.equal(started.importReport.tokens, 0);
  assert.equal(started.journal.ok, true);
  const transitions = (await pool.query('SELECT from_state,to_state FROM agentboard_transition WHERE task_id=$1 ORDER BY revision', [workflow.taskId])).rows;
  assert.ok(transitions.some((row) => row.to_state === 'READY'));
  assert.ok(transitions.some((row) => row.to_state === 'IN_REVIEW'));

  const taskDirectory = path.join(stateRoot, 'fixtures', workflow.taskId);
  const manifest = JSON.parse(fs.readFileSync(path.join(taskDirectory, 'artifact-manifest.json'), 'utf8'));
  const output = JSON.parse(fs.readFileSync(path.join(taskDirectory, 'output', 'import.json'), 'utf8'));
  assert.equal(manifest.fixture_only, true);
  assert.equal(manifest.process.network, 'none');
  assert.equal(manifest.process.exit_status, 0);
  assert.equal(manifest.process.model_calls, 0);
  assert.equal(manifest.process.tokens, 0);
  assert.ok(manifest.process.argv.includes('--network=none'));
  assert.ok(manifest.process.argv.includes('--workdir'));
  assert.equal(manifest.process.argv[manifest.process.argv.indexOf('--workdir') + 1], '/source');
  assert.ok(manifest.process.argv.includes(manifest.image_id));
  assert.equal(manifest.importer_report.sha256, sha(fs.readFileSync(path.join(taskDirectory, 'output', 'import.json'))));
  assert.equal(output.fixture_only, true);
  assert.equal(output.network, 'none');
  assert.equal(output.model_calls, 0);
  assert.equal(output.tokens, 0);

  const decision = await fetch(origin + '/api/decision', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' },
    body: JSON.stringify({ decision: 'request_changes', reason: 'Fixture-only snapshot audit.',
      observed_manifest_digest: started.artifactManifestDigest, expected_revision: started.revision }),
  });
  assert.equal(decision.status, 200);
  const decided = await decision.json();
  assert.equal(decided.state, 'BLOCKED');
  assert.equal(decided.fixture_only, true);
  assert.equal(decided.decisionReceipt.fixture_only, true);
  assert.equal(decided.decisionReceipt.actor_principal_id, OWNER);
  assert.notEqual(decided.decisionReceipt.actor_principal_id, decided.decisionReceipt.producer_principal_id);
  assert.equal(decided.decisionReceipt.artifact_manifest_digest, started.artifactManifestDigest);
  assert.ok(decided.decisionReceipt.audit.audit.length > 0);

  const approval = await fetch(origin + '/api/decision', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' },
    body: JSON.stringify({ decision: 'approve', reason: 'Fixture must refuse approval.',
      observed_manifest_digest: started.artifactManifestDigest, expected_revision: started.revision }),
  });
  assert.equal(approval.status, 403);
  const receipt = JSON.parse(fs.readFileSync(path.join(taskDirectory, 'decision-receipt.json'), 'utf8'));
  assert.equal(receipt.fixture_only, true);
  assert.equal(receipt.decision, 'request_changes');
  assert.equal(receipt.state, 'BLOCKED');
  assert.ok(receipt.audit.audit.length > 0);
  assert.equal(receipt.audit_digest, canonicalDigest(receipt.audit));
});
