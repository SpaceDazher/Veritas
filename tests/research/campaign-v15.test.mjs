import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { canonicalDigest } from "../../src/lib/verifier/canonical-json.mjs";
import * as image from "../../scripts/s2-008-campaign-model-image.mjs";
import * as approveRoute from "../../scripts/s2-008-campaign-approve.mjs";
import * as prepareRoute from "../../scripts/s2-008-campaign-prepare-cli.mjs";
import * as runRoute from "../../scripts/s2-008-campaign-run.mjs";
import * as evalRoute from "../../scripts/s2-008-campaign-evaluate.mjs";
import * as credential from "../../scripts/s2-008-campaign-credential-env.mjs";
import * as adapter from "../../scripts/s2-008-campaign-adapter.mjs";
import * as paidReview from "../../scripts/s2-008-paid-review.mjs";
import * as oldV13 from "../../scripts/s2-008-campaign-v13-approval.mjs";
import * as oldV14 from "../../scripts/s2-008-campaign-v14-approval.mjs";
import { FROZEN_MEMBERS, preregistrationDigest, scopeDrift } from "../../scripts/s2-008-campaign-approve.mjs";

const approval = await import("../../scripts/s2-008-campaign-v15-approval.mjs").catch(() => ({}));
const seal = await import("../../scripts/s2-008-campaign-seal-v15.mjs").catch(() => ({}));
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const v15Inputs = () => {
  const baseInputs = approval.readV15BaseInputs({ allowHistorical: true });
  const restartInputs = approval.readV15PriorExecutionInputs();
  const pin = makePin(baseInputs.baseBytes);
  const draft = approval.createV15Draft({ ...baseInputs, pin, restartInputs });
  return { baseInputs, restartInputs, pin, draft };
};
function makePin(baseBytes) {
  const schema = "s2-008-model-image-pin/15";
  const { sourceNames } = image.modelImagePolicyInputs(schema);
  const sources = Object.fromEntries([...sourceNames, "prereg"].sort().map((name) => [name,
    name === "provider_model_catalog" ? credential.V15_MODEL_POLICY.catalog_sha256
      : name === "provider_model_endpoint_catalog" ? credential.V15_MODEL_POLICY.endpoint_catalog_sha256
        : name === "model_call_pacing_policy" ? sha(fs.readFileSync(path.join(root, "scripts/s2-008-campaign-v14-pacing.mjs")))
          : name === "prereg" ? sha(baseBytes) : sha(Buffer.from("v15-fixture:" + name))]));
  const covers = Object.keys(sources).filter((name) => name !== "prereg").sort();
  const first = { imageId: "sha256:" + "a".repeat(64), digest: "sha256:" + "b".repeat(64), sources,
    source_digest: canonicalDigest(sources),
    content_commitment: canonicalDigest(Object.fromEntries(covers.map((key) => [key, sources[key]]))),
    content_commitment_covers: covers };
  return { schema, identical: true, context_digest_stable: true, content_commitment_stable: true,
    commitment_excludes_preregistration: true, commitment: { covers, excludes: ["prereg"] },
    first: structuredClone(first), second: structuredClone(first) };
}
function paidEvidence(model) {
  const seeds = [20260926, 20260927, 20260928], provider = "Google AI Studio";
  const createdAt = "2026-01-01T00:00:00.000Z", epoch = Math.floor(Date.parse(createdAt) / 1000);
  const sidecars = [], receipts = [], rows = [];
  for (let i = 0; i < seeds.length; i += 1) {
    const id = "gen-" + epoch + "-" + String(i + 1).padStart(16, "0"), caseId = "case-" + i;
    const local = { generation_id: id, case_id: caseId, input: 3, output: 2, cacheRead: 0, cacheWrite: 0,
      prompt_tokens: 3, totalTokens: 5, prompt_token_basis: "input+cacheRead+cacheWrite",
      usage_components_consistent: true, reported_cost_usd: null };
    sidecars.push({ kind: "s2-008-campaign-predictions/1", accounting: {
      policy: "GENERATION_ID_REQUIRED", calls: 1, tokens: 5, rows: [local] } });
    receipts.push({ id, provider, model, created_at: createdAt, http_status: 200, native_prompt: 3,
      native_completion: 2, native_cached: 0, generation_time: 12, cancelled: false,
      finish_reason: "stop", matches_local: true, total_cost: 0 });
    rows.push({ generation_id: id, provider, case_id: caseId, created_at: createdAt,
      input: 3, output: 2, cached: 0, total_tokens: 5, provider_reported_usd: 0 });
  }
  const report = { status: "MEASURED", spent_units: 15, spent_units_is_lower_bound: false,
    unreconciled_spend: false, model_calls_is_lower_bound: false, model_calls: 3, unknown_model_attempts: 0,
    trials: seeds.map((seed) => ({ arm_id: "arm-model-zai-glm53flash", seeds: [
      { seed, launch: { arm_report: { executor: { model_attempts: 1, model_calls: 1, unknown_model_attempts: 0 } } } },
    ] })) };
  const reconciliation = { status: "RECONCILED", completeness_basis: "KNOWN_ATTEMPTS_ALL_RECEIPTS",
    completeness: { basis: "KNOWN_ATTEMPTS_ALL_RECEIPTS", all_local_attempts_accounted: true,
      unfiltered_account_ledger_claimed: false, confirmed_by: null },
    provider_rows_verified_via_api: true, completeness_verified_via_api: false,
    local_model_attempts: 3, locally_accounted_model_calls: 3, matching_requests: 3,
    unreconciled_attempts: 0, actual_tokens: 15, actual_usd: 0, provider, model, rows };
  return { report, sidecars, reconciliation, receipts: { status: "KNOWN_GENERATIONS_MATCH",
    known_calls: 3, known_tokens: 15, unknown_attempts: 0, known_provider_usd: 0, receipts } };
}

test("v15 routes image build/dry-run through v14 and rejects v16", () => {
  assert.deepEqual(image.modelImagePaths("v15", { preseal: true }), {
    tag: "localhost/veritas-s2-008-model:v15",
    stagedPrereg: "corpus/s2-008-campaign/preregistration.v14.in-force.json",
    pinFile: "evidence/s2-008-campaign/model-image-pin-v15-preseal.json",
    schema: "s2-008-model-image-pin/15",
  });
  assert.equal(image.modelImagePaths("v15").stagedPrereg, "corpus/s2-008-campaign/preregistration.v15.in-force.json");
  const policyInputs = image.modelImagePolicyInputs("s2-008-model-image-pin/15");
  assert.ok(policyInputs.stageFiles.includes("evidence/s2-008-campaign/provider-model-catalog-gemma-v15.json"));
  assert.ok(policyInputs.stageFiles.includes("evidence/s2-008-campaign/provider-model-endpoints-gemma-v15.json"));
  assert.ok(policyInputs.sourceNames.includes("provider_model_catalog"));
  assert.ok(policyInputs.sourceNames.includes("provider_model_endpoint_catalog"));
  assert.equal(image.modelImageVersionFromArgv(["node", "builder", "--v15"]), "v15");
  assert.equal(image.parseModelImageCliArgs(["node", "builder", "--v15", "--preseal", "--pi-package-dir", "/tmp/pi"]).version, "v15");
  assert.throws(() => image.modelImageVersionFromArgv(["node", "builder", "--v16"]), /MODEL_IMAGE_VERSION_INVALID/);
  assert.equal(image.modelImagePaths("v14").schema, "s2-008-model-image-pin/14");
});

test("v15 pins exact raw model catalog bytes, zero prices, and only the free Google AI Studio endpoint", () => {
  const descriptorPath = path.join(root, "evidence/s2-008-campaign/provider-model-catalog-gemma-v15.json");
  const endpointsPath = path.join(root, "evidence/s2-008-campaign/provider-model-endpoints-gemma-v15.json");
  const descriptorBytes = fs.readFileSync(descriptorPath), endpointBytes = fs.readFileSync(endpointsPath);
  const descriptor = JSON.parse(descriptorBytes), endpoints = JSON.parse(endpointBytes);
  assert.equal(sha(descriptorBytes), "5f854e52fcddb2aac4cc7094e67df5ffeb06995595008cab89bed268936be651");
  assert.equal(sha(endpointBytes), "830836f5dd4474b652a9f7d50ea44b24544d1b78261f07e0552a5f757f127bd8");
  assert.equal(descriptor.id, "google/gemma-4-31b-it:free");
  assert.deepEqual(descriptor.pricing, { prompt: "0", completion: "0" });
  assert.equal(endpoints.data.id, "google/gemma-4-31b-it:free");
  assert.deepEqual(endpoints.data.endpoints.map((entry) => entry.name),
    ["Google AI Studio | google/gemma-4-31b-it-20260402:free"]);
  assert.deepEqual(endpoints.data.endpoints[0].pricing, { prompt: "0", completion: "0", discount: 0 });
  assert.equal(endpoints.data.endpoints[0].context_length, 262144);
  assert.equal(endpoints.data.endpoints[0].max_completion_tokens, 32768);
  assert.equal(credential.V15_MODEL_POLICY.model, "google/gemma-4-31b-it:free");
  assert.equal(credential.V15_MODEL_POLICY.catalog_slug, "google/gemma-4-31b-it-20260402:free");
  assert.equal(credential.V15_MODEL_POLICY.catalog_sha256, sha(descriptorBytes));
  assert.equal(credential.V15_MODEL_POLICY.endpoint_catalog_sha256, sha(endpointBytes));
  assert.equal(credential.assertV15ModelCatalogFiles(descriptorPath, endpointsPath), true);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v15-catalog-"));
  try {
    const changed = path.join(temp, "descriptor.json");
    fs.writeFileSync(changed, Buffer.concat([descriptorBytes, Buffer.from(" ")]));
    assert.throws(() => credential.assertV15ModelCatalogFiles(changed, endpointsPath), /V15_MODEL_CATALOG_ARTIFACT_INVALID/);
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("v15 approval, prepare, run, and evaluator dispatch supports 15 and rejects 16", () => {
  assert.equal(approveRoute.parseArgs(["--version", "v15", "--principal", "prn-s2007r-owner", "--label", "Daniil"]).version, "v15");
  assert.equal(prepareRoute.parsePrepareMode(["--seal-v15"]), "seal-v15");
  assert.equal(runRoute.campaignCliMode({ v15: true }).requestedVersion, 15);
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: "preregistration.v15.in-force.json" } }), "v15");
  assert.throws(() => approveRoute.parseArgs(["--version", "v16"]), /APPROVE_VERSION_INVALID/);
  assert.throws(() => prepareRoute.parsePrepareMode(["--seal-v16"]), /PREPARE_VERSION_INVALID/);
  assert.throws(() => runRoute.campaignCliMode({ v16: true }), /CAMPAIGN_VERSION_INVALID/);
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: "preregistration.v16.in-force.json" } }), null);
});

test("v15 base and prior closure bind raw v14 bytes and keep failed spend unknown", () => {
  const input = approval.readV15BaseInputs({ allowHistorical: true });
  assert.equal(input.baseBytes.length, 28400);
  assert.equal(sha(input.baseBytes), "77fabbe9ef92c8dbc281a78f7242fa6ce8f42031b8a4642783a2e3869c3d40bc");
  assert.equal(input.base.supersession?.superseded_digest, undefined);
  assert.equal(input.supersessionBytes.length, 689);
  assert.equal(sha(input.supersessionBytes), "4330a5ba0a429e9f8ea151773758ef29c3af75bd1c92c293ca3749371e65c13e");
  assert.equal(input.supersession.replaced_by_preregistration_digest, input.base.preregistration_digest);
  assert.equal(approval.assertV15BaseBinding(input).baseDigest, input.base.preregistration_digest);
  assert.throws(() => approval.assertV15BaseBinding({ ...input,
    baseBytes: Buffer.concat([input.baseBytes, Buffer.from("\n")]) }), /V15_BASE_BINDING_INVALID/);
  assert.throws(() => approval.assertV15BaseBinding({ ...input,
    supersession: { ...input.supersession, supersession_digest: "0".repeat(64) } }), /V15_BASE_SUPERSESSION_INVALID/);
  const restart = approval.readV15PriorExecutionInputs();
  const closure = approval.assertV15PriorExecutionReconciliation(input.base, restart);
  assert.equal(closure.status, "REQUEST_OUTCOMES_RECONCILED");
  assert.equal(closure.local_attempts, 33);
  assert.equal(closure.successful_generations, 32);
  assert.equal(closure.known_tokens, 33246);
  assert.equal(closure.known_usd, 0);
  assert.equal(closure.failed_request_tokens_confirmed, null);
  assert.equal(closure.failed_request_usd_confirmed, null);
  assert.equal(closure.total_tokens_confirmed, null);
  assert.equal(closure.total_usd_confirmed, null);
  assert.equal(closure.raw_report_unreconciled_spend, true);
  assert.equal(closure.account_wide_completeness_claimed, false);
  assert.equal(closure.owner_statement, "\u042d\u0442\u043e \u0432\u0441\u0435 \u0431\u043e\u043b\u044c\u0448\u0435 \u043d\u0435\u0442");
  assert.equal(closure.failure_generation_id, "gen-1791320426-Czrswj5nXxDzTpuQHNXU");
  assert.equal(closure.failure_provider, "Novita");
  assert.equal(closure.failure_http_status, 429);
  assert.equal(closure.failure_total_latency_ms, 186);
  assert.equal(closure.failure_attempts, 1);
  assert.equal(closure.failure_fallback_latency_ms, 0);
  assert.equal(closure.failure_generation_api_http_status, 404);
  assert.throws(() => approval.assertV15PriorExecutionReconciliation(input.base, {
    ...restart, run: { ...restart.run, bytes: Buffer.concat([restart.run.bytes, Buffer.from(" ")]) },
  }), /V15_PRIOR_EXECUTION_RAW_INPUT_MISMATCH/);
  assert.throws(() => approval.assertV15PriorExecutionReconciliation(input.base, {
    ...restart, reconciliation: { ...restart.reconciliation,
      value: { ...restart.reconciliation.value, total_usd_confirmed: 0 } },
  }), /V15_PRIOR_EXECUTION_RECONCILIATION_INVALID/);
});

test("v15 draft binds exact free identity and preserves frozen science and bounded budgets", () => {
  const { baseInputs, restartInputs, pin, draft } = v15Inputs();
  assert.equal(FROZEN_MEMBERS.length, 15);
  for (const member of FROZEN_MEMBERS) {
    assert.deepEqual(draft[member], baseInputs.base[member], member);
    const changed = structuredClone(draft);
    changed[member] = draft[member] === null ? "tampered" : null;
    assert.equal(scopeDrift(baseInputs.base, changed, [member]).member, member);
  }
  assert.equal(draft.rule, "s2-008-prereg-v15");
  assert.equal(draft.preregistration_id, "xpr-s2-008c-15");
  assert.equal(draft.executor.model, "google/gemma-4-31b-it:free");
  assert.equal(draft.executor.provider, "openrouter");
  assert.equal(draft.executor.credential_source, "EXPLICIT_PROCESS_ENV_ONLY");
  assert.equal(draft.executor.model_call_pacing.min_start_interval_ms, 60000);
  assert.equal(draft.executor.model_launch_timeout.total_container_timeout_ms, 30540000);
  assert.equal(draft.executor.pi_settings.retry.enabled, false);
  assert.equal(draft.executor.pi_settings.retry.maxRetries, 0);
  assert.equal(draft.executor.pi_model_catalog_binding.prompt_price, "0");
  assert.equal(draft.executor.pi_model_catalog_binding.completion_price, "0");
  assert.equal(draft.executor.pi_model_catalog_binding.canonical_slug, "google/gemma-4-31b-it-20260402:free");
  assert.equal(draft.budget_reservation.granted_units, 5000000);
  assert.equal(draft.budget_reservation.ceiling_scope, "PER_RUN_A_OR_B");
  assert.equal(draft.budget_reservation.expires_at, "2026-10-12T00:00:00.000Z");
  assert.deepEqual(draft.v14_prior_execution_reconciliation, restartInputs.expectedClosure);
  assert.equal(draft.v14_prior_execution_reconciliation.total_tokens_confirmed, null);
  assert.equal(draft.v14_prior_execution_reconciliation.total_usd_confirmed, null);
  assert.equal(draft.preregistration_digest, preregistrationDigest(draft));
  assert.equal(credential.credentialEnvNameForPreregistration(draft), "OPENROUTER_API_KEY");
  assert.equal(credential.assertV15ExecutorPolicy(draft.executor).model, "google/gemma-4-31b-it:free");
  const changed = structuredClone(draft);
  changed.executor.model = "google/gemma-4-31b-it";
  changed.preregistration_digest = preregistrationDigest(changed);
  assert.throws(() => credential.assertV15ExecutorPolicy(changed.executor), /V15_MODEL_POLICY_INVALID/);
  const argv = adapter.modelTrialArgv({ armId: "arm-model-zai-glm53flash", seed: 20260926,
    remainingTokens: 4999999, preregRule: "s2-008-prereg-v15", minStartIntervalMs: 60000 });
  assert.ok(argv.includes("/opt/veritas/corpus/s2-008-campaign/preregistration.v15.in-force.json"));
  assert.equal(argv[argv.indexOf("--min-start-interval-ms") + 1], "60000");
  assert.throws(() => adapter.modelTrialArgv({ armId: "arm-model-zai-glm53flash", seed: 20260926,
    remainingTokens: 1, preregRule: "s2-008-prereg-v15", minStartIntervalMs: 59999 }), /V15_MIN_START_INTERVAL_INVALID/);
});

test("v15 real-document seal preserves v14/v13 history and rejects digest drift", () => {
  const { baseInputs, restartInputs, pin, draft } = v15Inputs();
  const signed = approval.approveV15({ ...baseInputs, draft, pin, restartInputs,
    principal: "prn-s2007r-owner", label: "Daniil", issuedAt: "2026-10-07T09:05:00.000Z" });
  const result = seal.sealV15({ ...baseInputs, signed, draft, pin, restartInputs });
  assert.equal(result.prereg.approval.in_force, true);
  assert.equal(result.manifest.preregistration.file, "preregistration.v15.in-force.json");
  assert.equal(result.manifest.superseded_preregistration.file, "preregistration-v14-superseded.json");
  assert.equal(result.manifest.superseded_preregistration.preregistration_digest, baseInputs.base.preregistration_digest);
  assert.equal(result.manifest.supersession_history.at(-1).file, "preregistration-v15-supersession.json");
  assert.equal(seal.assertV15ManifestBinding({ ...baseInputs, prereg: result.prereg,
    manifest: result.manifest, supersession: result.supersession }).ok, true);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v15-history-reader-"));
  try {
    fs.cpSync(path.join(root, "corpus"), path.join(temp, "corpus"), { recursive: true });
    fs.cpSync(path.join(root, "evidence"), path.join(temp, "evidence"), { recursive: true });
    fs.writeFileSync(path.join(temp, "corpus/s2-008-campaign/manifest.json"), JSON.stringify(result.manifest, null, 2) + "\n");
    assert.equal(oldV14.readV14BaseInputs({ repoRoot: temp, allowHistorical: true }).base.preregistration_id, "xpr-s2-008c-14");
    assert.equal(oldV13.readV13BaseInputs({ repoRoot: temp, allowHistorical: true }).base.preregistration_id, "xpr-s2-008c-13");
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
  const wrong = structuredClone(result.manifest);
  wrong.supersession_history.at(-1).supersession_digest = "0".repeat(64);
  assert.throws(() => seal.assertV15ManifestBinding({ ...baseInputs, prereg: result.prereg,
    manifest: wrong, supersession: result.supersession }), /V15_MANIFEST_BINDING_INVALID/);
});

test("v15 receipt validation accepts only requested free ID or bound canonical free slug", () => {
  const { draft } = v15Inputs();
  for (const model of ["google/gemma-4-31b-it:free", "google/gemma-4-31b-it-20260402:free"]) {
    assert.deepEqual(paidReview.validateS2PaidReviewGenerationAccounting({
      ...paidEvidence(model), version: 15, prereg: draft,
    }), { calls: 3, tokens: 15, usd: 0 });
  }
  for (const model of ["google/gemma-4-31b-it", "google/gemma-4-31b-it-20260402"]) {
    assert.throws(() => paidReview.validateS2PaidReviewGenerationAccounting({
      ...paidEvidence(model), version: 15, prereg: draft,
    }));
  }
});
