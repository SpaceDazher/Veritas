import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import { campaignCliMode, productionPaidRunRefusal, runV4Campaign } from '../../scripts/s2-008-campaign-run.mjs';
import { modelImagePaths } from '../../scripts/s2-008-campaign-model-image.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const corpus = path.join(root, 'corpus/s2-008-campaign');
const baseBytes = fs.readFileSync(path.join(corpus, 'preregistration.v6.in-force.json'));
const base = JSON.parse(baseBytes);
const table = JSON.parse(fs.readFileSync(path.join(corpus, 'frozen-table.v3.json')));
const ledger = JSON.parse(fs.readFileSync(path.join(corpus, 'source-ledger.v3.json')));
const activeManifest = JSON.parse(fs.readFileSync(path.join(corpus, 'manifest.json')));
const pinV6 = JSON.parse(fs.readFileSync(path.join(root, 'evidence/s2-008-campaign/model-image-pin-v6.json')));
const model = 'arm-model-zai-glm53flash';

const manifestV6 = structuredClone(activeManifest);
if (manifestV6.supersession_history?.at(-1)?.file === 'preregistration-v7-supersession.json') {
  manifestV6.supersession_history.pop();
  manifestV6.supersession = manifestV6.supersession_history.at(-1);
}
manifestV6.preregistration = {
  file: 'preregistration.v6.in-force.json', status: 'IN_FORCE',
  preregistration_digest: base.preregistration_digest,
};

function makePinV7() {
  const sources = {
    ...pinV6.first.sources,
    arm: 'a'.repeat(64),
    credential_env_policy: 'c'.repeat(64),
    prereg: createHash('sha256').update(baseBytes).digest('hex'),
  };
  const covers = Object.keys(sources).filter((name) => name !== 'prereg').sort();
  const commitment = canonicalDigest(Object.fromEntries(covers.map((name) => [name, sources[name]])));
  const first = {
    ...pinV6.first,
    sources,
    source_digest: canonicalDigest(sources),
    content_commitment: commitment,
    content_commitment_covers: covers,
  };
  return {
    ...pinV6,
    schema: 's2-008-model-image-pin/7',
    image_tag: 'localhost/veritas-s2-008-model:v7',
    first,
    second: structuredClone(first),
    commitment: { covers, excludes: ['prereg'] },
  };
}

async function makeV7() {
  const pin = makePinV7();
  const { createV7Draft, approveV7 } = await import('../../scripts/s2-008-campaign-v7-approval.mjs');
  const draft = createV7Draft({ base, baseBytes, pin });
  const signed = approveV7({ draft, base, baseBytes, table, pin,
    principal: 'prn-owner', label: 'Daniil (repository owner)', issuedAt: '2026-09-30T00:00:00.000Z' });
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  return { pin, draft, signed, prereg };
}

test('v7 approval binds only provider credential routing while retaining frozen science and run policy', async () => {
  const { createV7Draft, approveV7 } = await import('../../scripts/s2-008-campaign-v7-approval.mjs');
  const pin = makePinV7();
  const draft = createV7Draft({ base, baseBytes, pin });
  assert.equal(draft.rule, 's2-008-prereg-v7');
  assert.equal(draft.preregistration_id, 'xpr-s2-008c-07');
  assert.equal(draft.executor.credential_env_name, 'ZAI_CODING_CN_API_KEY');
  assert.equal(draft.budget_reservation.granted_units, 5_000_000);
  assert.equal(draft.budget_reservation.ceiling_scope, 'PER_RUN_A_OR_B');
  assert.deepEqual(draft.executor.model_launch_timeout, base.executor.model_launch_timeout);
  assert.deepEqual(draft.executor.pi_argv_flags, base.executor.pi_argv_flags);
  assert.equal(canonicalDigest(draft.trial_list), canonicalDigest(base.trial_list));
  assert.equal(draft.expected_table_digest, base.expected_table_digest);
  const signed = approveV7({ draft, base, baseBytes, table, pin, principal: 'prn-owner', label: 'Daniil' });
  assert.equal(signed.approval.in_force, false);

  const wrongEnv = structuredClone(draft);
  wrongEnv.executor.credential_env_name = 'ZAI_API_KEY';
  wrongEnv.preregistration_digest = preregistrationDigest(wrongEnv);
  assert.throws(() => approveV7({ draft: wrongEnv, base, baseBytes, table, pin, principal: 'prn-owner', label: 'Daniil' }), /V7_SCOPE_MISMATCH|CREDENTIAL_ENV/);
  const retryMutation = structuredClone(draft);
  retryMutation.executor.pi_settings.retry.provider.maxRetries = 3;
  retryMutation.preregistration_digest = preregistrationDigest(retryMutation);
  assert.throws(() => approveV7({ draft: retryMutation, base, baseBytes, table, pin, principal: 'prn-owner', label: 'Daniil' }), /V7_CREDENTIAL_ENV_OR_RETRY_POLICY_INVALID/);
  const changedScience = structuredClone(draft);
  changedScience.trial_list[0].arm_id = 'arm-type-chore';
  changedScience.preregistration_digest = preregistrationDigest(changedScience);
  assert.throws(() => approveV7({ draft: changedScience, base, baseBytes, table, pin, principal: 'prn-owner', label: 'Daniil' }), /APPROVAL_SCOPE_DRIFT:trial_list/);
});

test('v7 seal preserves v6 history and commits an immutable supersession', async () => {
  const { pin, draft, signed } = await makeV7();
  const { sealV7, assertV7ManifestBinding } = await import('../../scripts/s2-008-campaign-seal-v7.mjs');
  const result = sealV7({ signed, draft, base, baseBytes, table, pin, manifest: manifestV6, ledger });
  assert.equal(result.prereg.approval.in_force, true);
  assert.equal(result.manifest.preregistration.file, 'preregistration.v7.in-force.json');
  assert.equal(result.manifest.supersession_history.length, manifestV6.supersession_history.length + 1);
  assert.equal(result.manifest.supersession_history.at(-1).file, 'preregistration-v7-supersession.json');
  assert.equal(result.manifest.superseded_preregistration.file, 'preregistration-v6-superseded.json');
  assert.equal(result.ledger.entries.length, ledger.entries.length);
  assert.equal(assertV7ManifestBinding({
    prereg: result.prereg, base, manifest: result.manifest,
    supersession: result.supersession, table, ledger: result.ledger,
  }).ok, true);
});

test('v7 CLI/image routes select v7 while v6 paid runs refuse before launch', async () => {
  assert.deepEqual(campaignCliMode({ v7: true, dryRun: true }), { predictionRunner: true, requestedVersion: 7 });
  assert.throws(() => campaignCliMode({ v6: true, v7: true }), /CAMPAIGN_VERSION_FLAGS_CONFLICT/);
  assert.equal(modelImagePaths('v7', { preseal: true }).stagedPrereg,
    'corpus/s2-008-campaign/preregistration.v6.in-force.json');
  assert.equal(modelImagePaths('v7').stagedPrereg,
    'corpus/s2-008-campaign/preregistration.v7.in-force.json');

  let v6Calls = 0;
  const reportV6 = await runV4Campaign({
    label: 'legacy-v6', arm: model, write: false, dryRun: false,
    prereg: JSON.parse(fs.readFileSync(path.join(corpus, 'preregistration.v6.in-force.json'))),
    manifest: manifestV6, modelPin: pinV6, dispatchableArms: [model],
    resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
    now: () => Date.parse('2026-09-30T00:00:00.000Z'),
    runModel: async () => { v6Calls += 1; throw new Error('must not launch'); },
  });
  assert.equal(v6Calls, 0);
  assert.equal(reportV6.code, 'MODEL_CREDENTIAL_ENV_RESEAL_REQUIRED');
  assert.equal(reportV6.launches, 0);
});

test('v7 paid routing keeps signed timeout and per-run cap and dispatches only under v7 pin', async () => {
  const { pin, prereg } = await makeV7();
  const seen = [];
  const manifest = { preregistration: {
    file: 'preregistration.v7.in-force.json', status: 'IN_FORCE',
    preregistration_digest: prereg.preregistration_digest,
  } };
  const report = await runV4Campaign({
    label: 'synthetic-v7', arm: model, seed: prereg.seed_rule.seeds[0], write: false,
    prereg, manifest, modelPin: pin, dispatchableArms: [model],
    resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
    now: () => Date.parse('2026-09-30T00:00:00.000Z'),
    runModel: async (options) => {
      seen.push(options);
      return {
        ok: true,
        output: { outcome_class: 'MEASURED', budget: { currency: 'tokens', spent_tokens: 17, unreconciled_spend: false },
          executor: { model_calls: 1 }, predictions: [{ case_id: 'sample', predicted: 'MINOR' }] },
        record: { image: pin.first.imageId, image_digest: pin.first.digest, exit_code: 0 },
      };
    },
  });
  assert.equal(report.kind, 's2-008-campaign-v7-predictions/1');
  assert.equal(report.status, 'MEASURED');
  assert.equal(report.spent_units, 17);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].timeoutMs, 22_980_000);
  assert.equal(seen[0].remainingTokens, 5_000_000);
  assert.equal(seen[0].prereg.executor.credential_env_name, 'ZAI_CODING_CN_API_KEY');
});

test('paid production CLI requires durable A/B evidence and refuses collisions before launch', async () => {
  assert.equal(productionPaidRunRefusal({ dryRun: false, label: 'a', write: 'false' }).code, 'PAID_RUN_EVIDENCE_REQUIRED');
  assert.equal(productionPaidRunRefusal({ dryRun: false, label: 'c', write: true }).code, 'PAID_RUN_LABEL_INVALID');
  assert.equal(productionPaidRunRefusal({ dryRun: true, label: 'c', write: 'false' }), null);

  const { pin, prereg } = await makeV7();
  const manifest = { preregistration: { file: 'preregistration.v7.in-force.json', status: 'IN_FORCE', preregistration_digest: prereg.preregistration_digest } };
  const baseFn = () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false });
  const defaultPaidWriteDisabled = await runV4Campaign({
    label: 'a', write: false, prereg, manifest, modelPin: pin, dispatchableArms: [model], resolveBaseFn: baseFn,
  });
  assert.equal(defaultPaidWriteDisabled.code, 'PAID_RUN_EVIDENCE_REQUIRED');
  assert.equal(defaultPaidWriteDisabled.launches, 0);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-v7-evidence-collision-'));
  const out = path.join(dir, 'existing-run.json');
  fs.writeFileSync(out, '{}');
  let launches = 0;
  try {
    const collision = await runV4Campaign({
      label: 'a', write: true, out, prereg, manifest, modelPin: pin, dispatchableArms: [model], resolveBaseFn: baseFn,
      runModel: async () => { launches += 1; throw new Error('must not launch'); },
    });
    assert.equal(collision.code, 'CAMPAIGN_EVIDENCE_TARGET_EXISTS');
    assert.equal(collision.spent_units, 0);
    assert.equal(collision.launches, 0);
    assert.deepEqual(collision.charges, []);
    assert.equal(launches, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
