import test from 'node:test';
import assert from 'node:assert/strict';
import { createA05ReviewServer, hashA05ReviewToken } from '../../scripts/a-mvp05-review.mjs';

const TOKEN = 'fixture-only-paid-review-action-token';
const OWNER = 'prn-s2007r-owner';
const TASK = 'abt-s2-008-v11-paid-review';
const DIGEST = 'a'.repeat(64);

test('fixture-only paid review uses the authenticated human start and snapshot decision protocol', async (t) => {
  const credential = {
    tokenHash: hashA05ReviewToken(TOKEN),
    principalId: OWNER,
    taskId: TASK,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    actions: ['view', 'start', 'approve', 'request_changes'],
  };
  let task = { state: 'PENDING', ready: true, revision: 1,
    producerPrincipalId: 'prn-s2-008-evidence-importer' };
  let starts = 0;
  let decisions = 0;
  const workflow = {
    async status() {
      return { ...task, artifactManifestDigest: DIGEST,
        expectedArtifactManifestDigest: DIGEST, currentArtifactManifestDigest: DIGEST };
    },
    async start({ principalId, taskId }) {
      assert.equal(principalId, OWNER);
      assert.equal(taskId, TASK);
      starts += 1;
      task = { ...task, state: 'IN_REVIEW', revision: 2 };
      return this.status();
    },
    async decide({ principalId, taskId, decision, observed }) {
      assert.equal(principalId, OWNER);
      assert.equal(taskId, TASK);
      assert.equal(decision, 'approve');
      assert.deepEqual(observed, { artifactManifestDigest: DIGEST, taskRevision: 2 });
      decisions += 1;
      task = { ...task, state: 'DONE', revision: 3 };
      return { ...(await this.status()), decisionReceipt: { actor: OWNER, fixture_test_only: true } };
    },
  };
  const server = createA05ReviewServer({ credential, workflow, presentation: 'paid-evidence-review' });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const origin = 'http://127.0.0.1:' + server.address().port;
  const headers = { authorization: 'Bearer ' + TOKEN };

  const page = await fetch(origin + '/');
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Принять/);
  const script = await fetch(origin + '/paid-review-app.js');
  assert.equal(script.status, 200);

  const stateResponse = await fetch(origin + '/api/state', { headers });
  assert.equal(stateResponse.status, 200);
  assert.equal((await stateResponse.json()).state, 'PENDING');
  const started = await fetch(origin + '/api/start', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(started.status, 200);
  assert.equal((await started.json()).state, 'IN_REVIEW');
  assert.equal(starts, 1);

  const decided = await fetch(origin + '/api/decision', {
    method: 'POST', headers: { ...headers, origin, 'content-type': 'application/json' },
    body: JSON.stringify({ decision: 'approve', reason: 'Reviewed the bound paid evidence snapshot.',
      observed_manifest_digest: DIGEST, expected_revision: 2 }),
  });
  assert.equal(decided.status, 200);
  const receipt = await decided.json();
  assert.equal(receipt.state, 'DONE');
  assert.equal(receipt.decisionReceipt.actor, OWNER);
  assert.equal(starts, 1);
  assert.equal(decisions, 1);
});
