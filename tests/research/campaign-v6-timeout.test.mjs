import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { modelTrialArgv } from '../../scripts/s2-008-campaign-adapter.mjs';
import { runV4Campaign } from '../../scripts/s2-008-campaign-run.mjs';
import {
  assertV6ModelTimeoutPolicy,
  createV6ModelTimeoutPolicy,
} from '../../scripts/s2-008-campaign-v6-timeout.mjs';
import {
  approveV6,
  createV6Draft,
} from '../../scripts/s2-008-campaign-v6-approval.mjs';
import { modelImagePaths } from '../../scripts/s2-008-campaign-model-image.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const corpus = path.join(root, 'corpus/s2-008-campaign');
const baseBytes = fs.readFileSync(path.join(corpus, 'preregistration.v5.in-force.json'));
const base = JSON.parse(baseBytes);
const table = JSON.parse(fs.readFileSync(path.join(corpus, 'frozen-table.v3.json')));
const previousPin = JSON.parse(fs.readFileSync(path.join(root, 'evidence/s2-008-campaign/model-image-pin-v5.json')));
const MODEL = 'arm-model-zai-glm53flash';

function pinV6() {
  const sources = { ...previousPin.first.sources, arm: 'f'.repeat(64) };
  const covers = Object.keys(sources).filter((key) => key !== 'prereg').sort();
  const commitment = canonicalDigest(Object.fromEntries(covers.map((key) => [key, sources[key]])));
  const first = {
    ...previousPin.first,
    sources,
    source_digest: canonicalDigest(sources),
    content_commitment: commitment,
    content_commitment_covers: covers,
  };
  return {
    ...previousPin,
    schema: 's2-008-model-image-pin/6',
    first,
    second: structuredClone(first),
    commitment: { ...previousPin.commitment, covers },
  };
}

const presealPin = pinV6();

test('v6 timeout policy signs a finite per-call limit and a formula-bound per-container limit', () => {
  const policy = createV6ModelTimeoutPolicy();
  assert.equal(policy.per_model_call_timeout_ms, 180_000);
  assert.equal(policy.holdout_case_count, 126);
  assert.equal(policy.bridge_report_margin_ms, 300_000);
  assert.equal(policy.total_container_timeout_ms, 22_980_000);
  assert.equal(policy.total_container_timeout_scope, 'ONE_MODEL_CONTAINER_PER_SEED');
  assert.doesNotThrow(() => assertV6ModelTimeoutPolicy(policy));

  for (const altered of [
    { ...policy, per_model_call_timeout_ms: Number.POSITIVE_INFINITY },
    { ...policy, total_container_timeout_ms: policy.total_container_timeout_ms + 1 },
    { ...policy, holdout_case_count: 127 },
    { ...policy, total_container_timeout_scope: 'UNBOUNDED' },
  ]) {
    assert.throws(() => assertV6ModelTimeoutPolicy(altered), /V6_MODEL_TIMEOUT_POLICY_INVALID/);
  }
});

test('v6 approval preserves every frozen scientific member and binds only the v6 preseal commitment plus timeout policy', () => {
  const draft = createV6Draft({ base, baseBytes, pin: presealPin });
  assert.equal(draft.rule, 's2-008-prereg-v6');
  assert.equal(draft.preregistration_id, 'xpr-s2-008c-06');
  assert.equal(draft.executor.model_launch_timeout.per_model_call_timeout_ms, 180_000);
  assert.equal(draft.executor.model_launch_timeout.total_container_timeout_ms, 22_980_000);
  assert.equal(draft.budget_reservation.granted_units, 5_000_000);
  assert.equal(draft.budget_reservation.ceiling_scope, 'PER_RUN_A_OR_B');
  assert.equal(draft.supersession.scope, 'executor timeout policy only; frozen scientific members and 5M per-run ceiling unchanged');
  const signed = approveV6({
    draft, base, baseBytes, table, pin: presealPin,
    principal: 'prn-s2007r-owner', label: 'Daniil (repository owner)',
  });
  assert.equal(signed.approval.status, 'APPROVED');
  assert.equal(signed.approval.in_force, false);

  const moved = structuredClone(draft);
  moved.trial_list[0].arm_id = 'arm-type-chore';
  moved.preregistration_digest = canonicalDigest((({ approval, status, preregistration_digest, ...body }) => body)(moved));
  assert.throws(() => approveV6({
    draft: moved, base, baseBytes, table, pin: presealPin,
    principal: 'prn-s2007r-owner', label: 'Daniil',
  }), /APPROVAL_SCOPE_DRIFT:trial_list/);
});

test('v6 model dispatch uses the signed total container timeout and routes to the v6 preregistration path', async () => {
  const draft = createV6Draft({ base, baseBytes, pin: presealPin });
  const signed = approveV6({
    draft, base, baseBytes, table, pin: presealPin,
    principal: 'prn-s2007r-owner', label: 'Daniil (repository owner)',
  });
  const prereg = { ...signed, approval: { ...signed.approval, in_force: true } };
  const pin = { ...presealPin, schema: 's2-008-model-image-pin/6' };
  const seen = [];
  const report = await runV4Campaign({
    label: 'timeout-v6', arm: MODEL, seed: prereg.seed_rule.seeds[0], dryRun: true, write: false,
    prereg,
    manifest: { preregistration: { file: 'preregistration.v6.in-force.json', status: 'IN_FORCE', preregistration_digest: prereg.preregistration_digest } },
    modelPin: pin,
    dispatchableArms: [MODEL],
    runModel: async (options) => {
      seen.push(options);
      return {
        ok: true,
        output: { outcome_class: 'DRY_RUN', budget: { currency: 'tokens', spent_tokens: 0, unreconciled_spend: false }, executor: { model_calls: 0 }, predictions: [] },
        record: { image: pin.first.imageId, image_digest: pin.first.digest, exit_code: 0, output_digest: 'dry-run' },
      };
    },
  });
  assert.equal(report.kind, 's2-008-campaign-v6-predictions/1');
  assert.equal(report.status, 'DRY_RUN');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].timeoutMs, 22_980_000);
  assert.equal(seen[0].prereg.executor.model_launch_timeout.per_model_call_timeout_ms, 180_000);

  const argv = modelTrialArgv({ armId: MODEL, seed: 20260926, dryRun: true, preregRule: 's2-008-prereg-v6' });
  assert.ok(argv.includes('/opt/veritas/corpus/s2-008-campaign/preregistration.v6.in-force.json'));
});

test('v5 paid model dispatch is blocked because its outer timeout cannot cover the full model container', async () => {
  const v5 = structuredClone(base);
  let launched = false;
  const report = await runV4Campaign({
    label: 'timeout-v5', arm: MODEL, write: false, prereg: v5,
    manifest: { preregistration: { file: 'preregistration.v5.in-force.json', status: 'IN_FORCE', preregistration_digest: v5.preregistration_digest } },
    modelPin: previousPin,
    dispatchableArms: [MODEL],
    runModel: async () => { launched = true; throw new Error('must not launch'); },
  });
  assert.equal(report.status, 'BLOCKED');
  assert.equal(report.code, 'MODEL_TOTAL_TIMEOUT_RESEAL_REQUIRED');
  assert.equal(report.spent_units, 0);
  assert.equal(launched, false);

  const paths = modelImagePaths('v6');
  assert.equal(paths.stagedPrereg, 'corpus/s2-008-campaign/preregistration.v6.in-force.json');
});
