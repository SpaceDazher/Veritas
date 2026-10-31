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
import * as probeRoute from "../../scripts/s2-008-campaign-probes.mjs";
import * as armRoute from "../../scripts/s2-008-campaign-arm-model.mjs";
import * as credential from "../../scripts/s2-008-campaign-credential-env.mjs";
import * as adapter from "../../scripts/s2-008-campaign-adapter.mjs";
import * as paidReview from "../../scripts/s2-008-paid-review.mjs";
import * as oldV13 from "../../scripts/s2-008-campaign-v13-approval.mjs";
import * as oldV14 from "../../scripts/s2-008-campaign-v14-approval.mjs";
import * as oldV16 from "../../scripts/s2-008-campaign-v16-approval.mjs";
import * as oldV15 from "../../scripts/s2-008-campaign-v15-approval.mjs";
import { FROZEN_MEMBERS, preregistrationDigest, scopeDrift } from "../../scripts/s2-008-campaign-approve.mjs";

const modelPolicy = await import("../../scripts/s2-008-campaign-v17-policy.mjs").catch(() => ({}));
const approval = await import("../../scripts/s2-008-campaign-v17-approval.mjs").catch(() => ({}));
const seal = await import("../../scripts/s2-008-campaign-seal-v17.mjs").catch(() => ({}));
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const v17Inputs = () => {
  const baseInputs = approval.readV17BaseInputs({ allowHistorical: true });
  const restartInputs = approval.readV17PriorExecutionInputs();
  const pin = makePin(baseInputs.baseBytes);
  const draft = approval.createV17Draft({ ...baseInputs, pin, restartInputs });
  return { baseInputs, restartInputs, pin, draft };
};
function makePin(baseBytes) {
  const schema = "s2-008-model-image-pin/17";
  const { sourceNames } = image.modelImagePolicyInputs(schema);
  const sources = Object.fromEntries([...sourceNames, "prereg"].sort().map((name) => [name,
    name === "provider_model_catalog" ? modelPolicy.V17_MODEL_POLICY.catalog_sha256
      : name === "provider_model_catalog_response" ? modelPolicy.V17_MODEL_POLICY.catalog_response_sha256
        : name === "provider_model_endpoint_catalog" ? modelPolicy.V17_MODEL_POLICY.endpoint_catalog_sha256
          : name === "model_call_pacing_policy" ? sha(fs.readFileSync(path.join(root, "scripts/s2-008-campaign-v14-pacing.mjs")))
            : name === "v17_model_policy" ? sha(fs.readFileSync(path.join(root, "scripts/s2-008-campaign-v17-policy.mjs")))
              : name === "prereg" ? sha(baseBytes) : sha(Buffer.from("v17-fixture:" + name))]));
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
  const seeds = [20260926, 20260927, 20260928], provider = "Nvidia";
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

test("v17 image build routing remains stable and unsupported v19 stays rejected", () => {
  assert.deepEqual(image.modelImagePaths("v17", { preseal: true }), {
    tag: "localhost/veritas-s2-008-model:v17",
    stagedPrereg: "corpus/s2-008-campaign/preregistration.v16.in-force.json",
    pinFile: "evidence/s2-008-campaign/model-image-pin-v17-preseal.json",
    schema: "s2-008-model-image-pin/17",
  });
  assert.equal(image.modelImagePaths("v17").stagedPrereg, "corpus/s2-008-campaign/preregistration.v17.in-force.json");
  const policyInputs = image.modelImagePolicyInputs("s2-008-model-image-pin/17");
  assert.ok(policyInputs.stageFiles.includes("scripts/s2-008-campaign-v17-policy.mjs"));
  assert.ok(policyInputs.stageFiles.includes("evidence/s2-008-campaign/provider-model-catalog-response-nvidia-v17.json"));
  assert.ok(policyInputs.stageFiles.includes("evidence/s2-008-campaign/provider-model-catalog-nvidia-v17.json"));
  assert.ok(policyInputs.stageFiles.includes("evidence/s2-008-campaign/provider-model-endpoints-nvidia-v17.json"));
  assert.ok(policyInputs.sourceNames.includes("provider_model_catalog_response"));
  assert.equal(image.modelImageVersionFromArgv(["node", "builder", "--v17"]), "v17");
  assert.equal(image.modelImagePolicyInputs("s2-008-model-image-pin/17").sourceNames.includes("v17_model_policy"), true);
  assert.throws(() => image.modelImageVersionFromArgv(["node", "builder", "--v19"]), /MODEL_IMAGE_VERSION_INVALID/);
  assert.equal(image.modelImagePaths("v16").schema, "s2-008-model-image-pin/16");
});

test("v17 pins raw catalog response, exact free descriptor and Nvidia endpoint", () => {
  const descriptorPath = path.join(root, "evidence/s2-008-campaign/provider-model-catalog-nvidia-v17.json");
  const endpointsPath = path.join(root, "evidence/s2-008-campaign/provider-model-endpoints-nvidia-v17.json");
  const responsePath = path.join(root, "evidence/s2-008-campaign/provider-model-catalog-response-nvidia-v17.json");
  const descriptorBytes = fs.readFileSync(descriptorPath), endpointBytes = fs.readFileSync(endpointsPath);
  const responseBytes = fs.readFileSync(responsePath), descriptor = JSON.parse(descriptorBytes);
  const endpoints = JSON.parse(endpointBytes), raw = JSON.parse(responseBytes);
  assert.equal(sha(descriptorBytes), "86169d2099cc8385856bcd780b50d4269486608b4db130eaf7620535685e19f5");
  assert.equal(sha(endpointBytes), "149341e3c6ae97478f640368f7877f7212469791ad84c0d18d831d29373eaf6c");
  assert.equal(sha(responseBytes), "9ebec09cfd65e64fb1c57b67cc96ea19558008134a6c12b018681c5d21e18710");
  assert.equal(responseBytes.length, 810217);
  assert.deepEqual(descriptor.pricing, { prompt: "0", completion: "0" });
  assert.equal(descriptor.id, "nvidia/nemotron-3.5-lightning:free");
  assert.equal(descriptor.canonical_slug, "nvidia/nemotron-3.5-lightning-20260807");
  assert.deepEqual(raw.data.find((entry) => entry.id === descriptor.id), descriptor);
  assert.equal(endpoints.data.id, "nvidia/nemotron-3.5-lightning:free");
  assert.deepEqual(endpoints.data.endpoints.map((entry) => entry.name),
    ["Nvidia | nvidia/nemotron-3.5-lightning-20260807:free"]);
  assert.equal(endpoints.data.endpoints[0].model_id, "nvidia/nemotron-3.5-lightning:free");
  assert.equal(endpoints.data.endpoints[0].provider_name, "Nvidia");
  assert.deepEqual(endpoints.data.endpoints[0].pricing, { prompt: "0", completion: "0", discount: 0 });
  assert.equal(endpoints.data.endpoints[0].context_length, 1000000);
  assert.equal(endpoints.data.endpoints[0].max_completion_tokens, 65536);
  assert.equal(modelPolicy.V17_MODEL_POLICY.model, "nvidia/nemotron-3.5-lightning:free");
  assert.equal(modelPolicy.V17_MODEL_POLICY.provider_name, "Nvidia");
  assert.equal(modelPolicy.V17_MODEL_POLICY.catalog_slug, "nvidia/nemotron-3.5-lightning-20260807");
  assert.equal(modelPolicy.V17_MODEL_POLICY.endpoint_slug, "nvidia/nemotron-3.5-lightning-20260807:free");
  assert.deepEqual(modelPolicy.V17_MODEL_POLICY.pi_model_registration.compat.openRouterRouting,
    { only: ["Nvidia"], allow_fallbacks: false });
  assert.equal(modelPolicy.V17_MODEL_POLICY.catalog_sha256, sha(descriptorBytes));
  assert.equal(modelPolicy.V17_MODEL_POLICY.catalog_response_sha256, sha(responseBytes));
  assert.equal(modelPolicy.V17_MODEL_POLICY.endpoint_catalog_sha256, sha(endpointBytes));
  assert.equal(modelPolicy.assertV17ModelCatalogFiles(descriptorPath, endpointsPath, responsePath), true);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v17-catalog-"));
  try {
    const changed = path.join(temp, "descriptor.json");
    fs.writeFileSync(changed, Buffer.concat([descriptorBytes, Buffer.from(" ")]));
    assert.throws(() => modelPolicy.assertV17ModelCatalogFiles(changed, endpointsPath, responsePath), /V17_MODEL_CATALOG_ARTIFACT_INVALID/);
    fs.writeFileSync(changed, JSON.stringify({ ...descriptor, pricing: { prompt: "0", completion: "0.000001" } }));
    assert.throws(() => modelPolicy.assertV17ModelCatalogFiles(changed, endpointsPath, responsePath), /V17_MODEL_CATALOG_ARTIFACT_INVALID/);
    fs.writeFileSync(changed, JSON.stringify({ ...descriptor, id: "nvidia/nemotron-3.5-lightning" }));
    assert.throws(() => modelPolicy.assertV17ModelCatalogFiles(changed, endpointsPath, responsePath), /V17_MODEL_CATALOG_ARTIFACT_INVALID/);
    fs.writeFileSync(changed, JSON.stringify({ ...descriptor, canonical_slug: "nvidia/nemotron-3.5-lightning-20260807:free" }));
    assert.throws(() => modelPolicy.assertV17ModelCatalogFiles(changed, endpointsPath, responsePath), /V17_MODEL_CATALOG_ARTIFACT_INVALID/);
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("v17 approval, prepare, run, and evaluator dispatch supports 17 and rejects 19", () => {
  assert.equal(approveRoute.parseArgs(["--version", "v17", "--principal", "prn-s2007r-owner", "--label", "Daniil"]).version, "v17");
  assert.equal(prepareRoute.parsePrepareMode(["--seal-v17"]), "seal-v17");
  assert.equal(runRoute.campaignCliMode({ v17: true }).requestedVersion, 17);
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: "preregistration.v17.in-force.json" } }), "v17");
  assert.equal(probeRoute.resolveProbePreregistrationPath("corpus/s2-008-campaign/preregistration.v17.in-force.json", root),
    path.join(root, "corpus/s2-008-campaign/preregistration.v17.in-force.json"));
  assert.equal(path.basename(probeRoute.defaultProbeOutputPath({ rule: "s2-008-prereg-v17" }, root)), "probes-v17.json");
  const capsuleSources = evalRoute.V17_REVIEW_CAPSULE_SOURCE_PATHS;
  assert.ok(capsuleSources.includes("scripts/s2-008-campaign-v17-policy.mjs"));
  assert.ok(capsuleSources.includes("scripts/s2-008-campaign-probes.mjs"));
  assert.ok(capsuleSources.includes(modelPolicy.V17_MODEL_POLICY.catalog_file));
  assert.equal(evalRoute.buildV17ReviewCapsuleSourceInputs(capsuleSources.map((sourcePath) => ({
    path: sourcePath, contents: Buffer.from("pinned-test-source"),
  }))).length, capsuleSources.length);
  const accessRoot = fs.mkdtempSync(path.join(os.tmpdir(), "v17-review-once-"));
  try {
    const target = path.join(accessRoot, "v17-evaluation-access");
    assert.equal(evalRoute.reserveV17EvaluationAccessRoot(target), target);
    assert.throws(() => evalRoute.reserveV17EvaluationAccessRoot(target), /V17_HOLDOUT_ACCESS_ALREADY_RECORDED/);
  } finally { fs.rmSync(accessRoot, { recursive: true, force: true }); }
  assert.throws(() => approveRoute.parseArgs(["--version", "v19"]), /APPROVE_VERSION_INVALID/);
  assert.throws(() => prepareRoute.parsePrepareMode(["--seal-v19"]), /PREPARE_VERSION_INVALID/);
  assert.throws(() => runRoute.campaignCliMode({ v19: true }), /CAMPAIGN_VERSION_INVALID/);
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: "preregistration.v19.in-force.json" } }), null);
});

test("v17 base and prior closure bind exact v16 bytes and preserve unknown failed outcomes", () => {
  const input = approval.readV17BaseInputs({ allowHistorical: true });
  assert.equal(input.baseBytes.length, 33640);
  assert.equal(sha(input.baseBytes), "e43d221b17ef3be95e68eb67f07ca422ec97fe5f8b325bb020eacd6d05e57077");
  assert.equal(input.base.rule, "s2-008-prereg-v16");
  assert.equal(input.base.supersession?.supersession_digest, undefined);
  assert.equal(input.supersessionBytes.length, 772);
  assert.equal(sha(input.supersessionBytes), "3bc72148941d4a722581e348478b3ecb4b177181355dac2d0327321d149cb7e8");
  assert.equal(input.supersession.replaced_by_preregistration_digest, input.base.preregistration_digest);
  assert.equal(approval.assertV17BaseBinding(input).baseDigest, input.base.preregistration_digest);
  assert.throws(() => approval.assertV17BaseBinding({ ...input,
    baseBytes: Buffer.concat([input.baseBytes, Buffer.from("\n")]) }), /V17_BASE_BINDING_INVALID/);
  assert.throws(() => approval.assertV17BaseBinding({ ...input,
    base: { ...input.base, approval: { ...input.base.approval, issued_at: "2026-10-07T12:00:01.000Z" } },
  }), /V17_BASE_BINDING_INVALID/);
  assert.throws(() => approval.assertV17BaseBinding({ ...input,
    supersession: { ...input.supersession, supersession_digest: "0".repeat(64) } }), /V17_BASE_SUPERSESSION_INVALID/);
  assert.throws(() => approval.assertV17BaseBinding({ ...input,
    supersessionBytes: Buffer.concat([input.supersessionBytes, Buffer.from(" ")]) }), /V17_BASE_SUPERSESSION_INVALID/);
  const restart = approval.readV17PriorExecutionInputs();
  const closure = approval.assertV17PriorExecutionReconciliation(input.base, restart);
  assert.equal(closure.status, "REQUEST_OUTCOMES_RECONCILED");
  assert.equal(closure.local_attempts, 1);
  assert.equal(closure.successful_generations, 0);
  assert.equal(closure.failed_upstream_requests, 1);
  assert.equal(closure.classified_unknown_attempts, 1);
  assert.equal(closure.unclassified_attempts, 0);
  assert.equal(closure.known_tokens_lower_bound, 0);
  assert.equal(closure.known_usd_lower_bound, 0);
  assert.equal(closure.failed_request_tokens_confirmed, null);
  assert.equal(closure.failed_request_usd_confirmed, null);
  assert.equal(closure.total_tokens_confirmed, null);
  assert.equal(closure.total_usd_confirmed, null);
  assert.equal(closure.raw_report_unreconciled_spend, true);
  assert.equal(closure.account_wide_completeness_claimed, false);
  assert.equal(closure.no_cost_claim_for_failed_request, true);
  assert.equal(closure.owner_statement, "\u0414\u0430, \u043f\u043e\u043b\u043d\u044b\u0439 \u0441\u043f\u0438\u0441\u043e\u043a; \u0442\u043e\u043b\u044c\u043a\u043e \u044d\u0442\u043e\u0442 429");
  assert.equal(closure.failure_generation_id, "gen-1791385538-Kv8guCF6fgfxeioKvMfY");
  assert.equal(closure.failure_provider, "Poolside");
  assert.equal(closure.failure_http_status, 429);
  assert.equal(closure.failure_attempts, 1);
  assert.equal(closure.failure_fallback_latency_ms, 0);
  assert.equal(closure.failure_generation_api_http_status, 404);
  assert.throws(() => approval.assertV17PriorExecutionReconciliation(input.base, {
    ...restart, run: { ...restart.run, bytes: Buffer.concat([restart.run.bytes, Buffer.from(" ")]) },
  }), /V17_PRIOR_EXECUTION_RAW_INPUT_MISMATCH/);
  assert.throws(() => approval.assertV17PriorExecutionReconciliation(input.base, {
    ...restart, reconciliation: { ...restart.reconciliation,
      value: { ...restart.reconciliation.value, total_usd_confirmed: 0 } },
  }), /V17_PRIOR_EXECUTION_RECONCILIATION_INVALID/);
  assert.throws(() => approval.assertV17PriorExecutionReconciliation(input.base, {
    ...restart, reconciliation: { ...restart.reconciliation,
      value: { ...restart.reconciliation.value, unclassified_attempts: 1 } },
  }), /V17_PRIOR_EXECUTION_RECONCILIATION_INVALID/);
});

test("v17 draft binds exact free identity and preserves frozen science and bounded budgets", () => {
  const { baseInputs, restartInputs, pin, draft } = v17Inputs();
  assert.equal(FROZEN_MEMBERS.length, 15);
  for (const member of FROZEN_MEMBERS) {
    assert.deepEqual(draft[member], baseInputs.base[member], member);
    const changed = structuredClone(draft);
    changed[member] = draft[member] === null ? "tampered" : null;
    assert.equal(scopeDrift(baseInputs.base, changed, [member]).member, member);
  }
  assert.equal(draft.rule, "s2-008-prereg-v17");
  assert.equal(draft.preregistration_id, "xpr-s2-008c-17");
  assert.equal(draft.executor.model, "nvidia/nemotron-3.5-lightning:free");
  assert.equal(draft.executor.provider, "openrouter");
  assert.equal(draft.executor.credential_source, "EXPLICIT_PROCESS_ENV_ONLY");
  assert.equal(draft.executor.model_call_pacing.min_start_interval_ms, 60000);
  assert.equal(draft.executor.model_launch_timeout.total_container_timeout_ms, 30540000);
  assert.equal(draft.executor.pi_settings.retry.enabled, false);
  assert.equal(draft.executor.pi_settings.retry.maxRetries, 0);
  assert.equal(draft.executor.pi_model_catalog_binding.prompt_price, "0");
  assert.equal(draft.executor.pi_model_catalog_binding.completion_price, "0");
  assert.equal(draft.executor.pi_model_catalog_binding.canonical_slug, "nvidia/nemotron-3.5-lightning-20260807");
  assert.equal(draft.executor.pi_model_catalog_binding.endpoint_slug, "nvidia/nemotron-3.5-lightning-20260807:free");
  assert.equal(draft.budget_reservation.granted_units, 5000000);
  assert.equal(draft.budget_reservation.ceiling_scope, "PER_RUN_A_OR_B");
  assert.equal(draft.budget_reservation.expires_at, "2026-11-07T00:00:00.000Z");
  assert.deepEqual(draft.v16_prior_execution_reconciliation, restartInputs.expectedClosure);
  assert.equal(draft.v16_prior_execution_reconciliation.failed_request_tokens_confirmed, null);
  assert.equal(draft.v16_prior_execution_reconciliation.failed_request_usd_confirmed, null);
  assert.equal(draft.v16_prior_execution_reconciliation.total_tokens_confirmed, null);
  assert.equal(draft.v16_prior_execution_reconciliation.total_usd_confirmed, null);
  assert.equal(draft.budget_reservation.usd_reference.why_null.includes("Nvidia"), true);
  assert.equal(draft.budget_reservation.usd_reference.projection.reason.includes("Nvidia"), true);
  assert.equal(draft.preregistration_digest, preregistrationDigest(draft));
  assert.equal(modelPolicy.assertV17ExecutorPolicy(draft.executor).envName, "OPENROUTER_API_KEY");
  assert.equal(modelPolicy.assertV17ExecutorPolicy(draft.executor).model, "nvidia/nemotron-3.5-lightning:free");
  assert.throws(() => modelPolicy.assertV17CredentialMetadata(draft.executor,
    { present: true, fingerprint: "0".repeat(16) }), /V17_CREDENTIAL_METADATA_INVALID/);
  assert.throws(() => modelPolicy.assertV17CredentialMetadata(draft.executor,
    { present: true, fingerprint: modelPolicy.V17_MODEL_POLICY.credential_fingerprint },
    { OPENROUTER_API_KEY: "test-value-not-the-bound-key" }), /V17_CREDENTIAL_ENV_FINGERPRINT_MISMATCH/);
  const retryDrift = structuredClone(draft.executor);
  retryDrift.pi_settings.retry.maxRetries = 1;
  assert.throws(() => modelPolicy.assertV17ExecutorPolicy(retryDrift), /V17_MODEL_POLICY_INVALID/);
  const intervalDrift = structuredClone(draft.executor);
  intervalDrift.model_call_pacing.min_start_interval_ms = 59999;
  assert.throws(() => modelPolicy.assertV17ExecutorPolicy(intervalDrift), /V17_MODEL_POLICY_INVALID/);
  const changedBudget = structuredClone(draft);
  changedBudget.budget_reservation.granted_units = 5000001;
  assert.throws(() => modelPolicy.assertV17PreregistrationPolicy(changedBudget), /V17_BUDGET_POLICY_INVALID/);
  const changed = structuredClone(draft);
  changed.executor.model = "nvidia/nemotron-3.5-lightning";
  changed.preregistration_digest = preregistrationDigest(changed);
  assert.throws(() => modelPolicy.assertV17ExecutorPolicy(changed.executor), /V17_MODEL_POLICY_INVALID/);
  const argv = adapter.modelTrialArgv({ armId: "arm-model-zai-glm53flash", seed: 20260926,
    remainingTokens: 4999999, preregRule: "s2-008-prereg-v17", minStartIntervalMs: 60000 });
  assert.ok(argv.includes("/opt/veritas/corpus/s2-008-campaign/preregistration.v17.in-force.json"));
  assert.equal(argv[argv.indexOf("--min-start-interval-ms") + 1], "60000");
  assert.throws(() => adapter.modelTrialArgv({ armId: "arm-model-zai-glm53flash", seed: 20260926,
    remainingTokens: 1, preregRule: "s2-008-prereg-v17", minStartIntervalMs: 59999 }), /V17_MIN_START_INTERVAL_INVALID/);
});

test("v17 real-document seal preserves v16/v14/v13 history and rejects digest drift", () => {
  const { baseInputs, restartInputs, pin, draft } = v17Inputs();
  const signed = approval.approveV17({ ...baseInputs, draft, pin, restartInputs,
    principal: "prn-s2007r-owner", label: "Daniil", issuedAt: "2026-10-31T10:00:00.000Z" });
  const result = seal.sealV17({ ...baseInputs, signed, draft, pin, restartInputs });
  const wrongSigner = structuredClone(signed);
  wrongSigner.approval.label = "Unapproved";
  assert.throws(() => seal.sealV17({ ...baseInputs, signed: wrongSigner, draft, pin, restartInputs }),
    /V17_NOT_APPROVED/);
  assert.equal(result.prereg.approval.in_force, true);
  assert.equal(result.manifest.preregistration.file, "preregistration.v17.in-force.json");
  assert.equal(result.manifest.superseded_preregistration.file, "preregistration-v16-superseded.json");
  assert.equal(result.manifest.superseded_preregistration.preregistration_digest, baseInputs.base.preregistration_digest);
  assert.equal(result.manifest.supersession_history.at(-1).file, "preregistration-v17-supersession.json");
  assert.equal(seal.assertV17ManifestBinding({ ...baseInputs, prereg: result.prereg,
    manifest: result.manifest, supersession: result.supersession }).ok, true);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v17-history-reader-"));
  try {
    fs.cpSync(path.join(root, "corpus"), path.join(temp, "corpus"), { recursive: true });
    fs.cpSync(path.join(root, "evidence"), path.join(temp, "evidence"), { recursive: true });
    fs.writeFileSync(path.join(temp, "corpus/s2-008-campaign/preregistration-v16-superseded.json"), baseInputs.baseBytes);
    fs.writeFileSync(path.join(temp, "corpus/s2-008-campaign/preregistration.v17.in-force.json"), JSON.stringify(result.prereg, null, 2) + "\n");
    fs.writeFileSync(path.join(temp, "corpus/s2-008-campaign/preregistration-v17-supersession.json"), JSON.stringify(result.supersession, null, 2) + "\n");
    fs.writeFileSync(path.join(temp, "corpus/s2-008-campaign/manifest.json"), JSON.stringify(result.manifest, null, 2) + "\n");

    fs.writeFileSync(path.join(temp, "corpus/s2-008-campaign/preregistration.v17.draft.json"), JSON.stringify(draft, null, 2) + "\n");
    fs.writeFileSync(path.join(temp, "corpus/s2-008-campaign/preregistration.v17.approved.json"), JSON.stringify(signed, null, 2) + "\n");
    fs.writeFileSync(path.join(temp, "evidence/s2-008-campaign/model-image-pin-v17-preseal.json"), JSON.stringify(pin, null, 2) + "\n");
    const finalPin = structuredClone(pin);
    for (const stage of [finalPin.first, finalPin.second]) {
      stage.sources.prereg = sha(Buffer.from(JSON.stringify(result.prereg, null, 2) + "\n"));
      stage.source_digest = canonicalDigest(stage.sources);
    }
    fs.writeFileSync(path.join(temp, "evidence/s2-008-campaign/model-image-pin-v17.json"), JSON.stringify(finalPin, null, 2) + "\n");
    assert.equal(oldV16.readV16BaseInputs({ repoRoot: temp, allowHistorical: true }).base.preregistration_id, "xpr-s2-008c-15");
    assert.equal(oldV15.readV15BaseInputs({ repoRoot: temp, allowHistorical: true }).base.preregistration_id, "xpr-s2-008c-14");
    assert.equal(oldV14.readV14BaseInputs({ repoRoot: temp, allowHistorical: true }).base.preregistration_id, "xpr-s2-008c-13");
    assert.equal(oldV13.readV13BaseInputs({ repoRoot: temp, allowHistorical: true }).base.preregistration_id, "xpr-s2-008c-12");
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
  const wrong = structuredClone(result.manifest);
  wrong.supersession_history.at(-1).supersession_digest = "0".repeat(64);
  assert.throws(() => seal.assertV17ManifestBinding({ ...baseInputs, prereg: result.prereg,
    manifest: wrong, supersession: result.supersession }), /V17_MANIFEST_BINDING_INVALID/);
});

test("v17 runModelTrial refuses policy and credential drift before mocked dry or paid launch", async () => {
  const { pin, draft } = v17Inputs();
  const prereg = { ...draft, status: "APPROVED",
    approval: { ...draft.approval, status: "APPROVED", principal_id: "prn-s2007r-owner",
      label: "Daniil", issued_at: "2026-10-31T10:00:00.000Z", in_force: true } };
  const assertPin = () => ({ imageId: pin.first.imageId });
  let dryCalls = 0, paidCalls = 0;
  const badInterval = structuredClone(prereg);
  badInterval.executor.model_call_pacing.min_start_interval_ms = 59999;
  await assert.rejects(adapter.runModelTrial({ armId: "arm-model-zai-glm53flash", seed: 20260926,
    timeoutMs: 30540000, dryRun: true, pin, prereg: badInterval, assertPin,
    executeDry: async () => { dryCalls += 1; return { exitCode: 0, stdout: "" }; } }),
  /V17_MODEL_POLICY_INVALID/);
  await assert.rejects(adapter.runModelTrial({ armId: "arm-model-zai-glm53flash", seed: 20260926,
     timeoutMs: 30540000, dryRun: false, pin, prereg: badInterval, assertPin, remainingTokens: 4999999,
    processEnv: { OPENROUTER_API_KEY: "test-value-not-the-bound-key" },
    executePaid: async () => { paidCalls += 1; return {}; } }), /V17_MODEL_POLICY_INVALID/);
  await assert.rejects(adapter.runModelTrial({ armId: "arm-model-zai-glm53flash", seed: 20260926,
     timeoutMs: 30540000, dryRun: false, pin, prereg, assertPin, remainingTokens: 4999999,
    processEnv: { OPENROUTER_API_KEY: "test-value-not-the-bound-key" },
    executePaid: async () => { paidCalls += 1; return {}; } }), /V17_CREDENTIAL_METADATA_INVALID/);
  assert.equal(dryCalls, 0);
  assert.equal(paidCalls, 0);
});

test("v17 callModel registers the exact free NVIDIA model and extracts a mocked billed JSONL response", () => {
  const { draft } = v17Inputs();
  const fakeCredential = "unit-test-only-synthetic-credential";
  const responseId = "gen-1791320426-AbcdefghijklmnopQRST";
  const stdout = JSON.stringify({ type: "agent_end", messages: [{
    role: "assistant", responseId, stopReason: "stop",
    usage: { input: 3, output: 2, cacheRead: 0, cacheWrite: 0, totalTokens: 5, cost: { total: 0 } },
    content: [{ type: "text", text: "MINOR" }],
  }] }) + "\n";
  let launch;
  const result = armRoute.callModel("fix: synthetic subject", {
    modelPolicyModule: modelPolicy,
    provider: modelPolicy.V17_MODEL_POLICY.provider,
    model: modelPolicy.V17_MODEL_POLICY.model,
    envName: modelPolicy.V17_MODEL_POLICY.credential_env_name,
    env: { OPENROUTER_API_KEY: fakeCredential, HTTPS_PROXY: "http://127.0.0.1:43123" },
    dryRun: false, timeoutMs: 180000,
    piSettings: draft.executor.pi_settings, piExecutor: draft.executor,
    captureFailureDiagnostics: true,
    execFile: (command, argv, options) => {
      launch = { command, argv, env: options.env, configDir: options.env.PI_CODING_AGENT_DIR };
      const models = JSON.parse(fs.readFileSync(path.join(launch.configDir, "models.json"), "utf8"));
      const settings = JSON.parse(fs.readFileSync(path.join(launch.configDir, "settings.json"), "utf8"));
      assert.deepEqual(models.providers.openrouter.models.map((entry) => entry.id),
        ["nvidia/nemotron-3.5-lightning:free"]);
      assert.equal(models.providers.openrouter.models[0].baseUrl, "https://openrouter.ai/api/v1");
      assert.deepEqual(models.providers.openrouter.models[0].compat.openRouterRouting,
        { only: ["Nvidia"], allow_fallbacks: false });
      assert.equal(settings.retry.enabled, false);
      assert.equal(settings.retry.maxRetries, 0);
      assert.equal(settings.cacheWarming, "off");
      assert.equal(settings.compaction.enabled, false);
      assert.equal(argv[argv.indexOf("--model") + 1], "nvidia/nemotron-3.5-lightning:free");
      assert.ok(argv.includes("--no-tools"));
      assert.ok(argv.includes("--no-extensions"));
      assert.ok(argv.includes("--no-skills"));
      return stdout;
    },
  });
  assert.equal(launch.command, "pi");
  assert.equal(launch.env.OPENROUTER_API_KEY, fakeCredential);
  assert.equal(fs.existsSync(launch.configDir), false);
  assert.equal(result.text, "MINOR");
  assert.equal(result.model_called, true);
  assert.equal(result.usage.totalTokens, 5);
  assert.equal(result.accounting.generation_id, responseId);
  assert.equal(result.accounting.correlation_status, "CORRELATED");
  assert.equal(result.accounting.usage_components_consistent, true);
});

test("v17 receipt validation accepts only requested free ID or bound canonical free slug", () => {
  const { draft } = v17Inputs();
  for (const model of ["nvidia/nemotron-3.5-lightning:free", "nvidia/nemotron-3.5-lightning-20260807:free"]) {
    assert.deepEqual(paidReview.validateS2PaidReviewGenerationAccounting({
      ...paidEvidence(model), version: 17, prereg: draft,
    }), { calls: 3, tokens: 15, usd: 0 });
  }
  for (const model of ["nvidia/nemotron-3.5-lightning", "nvidia/nemotron-3.5-lightning-20260807"]) {
    assert.throws(() => paidReview.validateS2PaidReviewGenerationAccounting({
      ...paidEvidence(model), version: 17, prereg: draft,
    }));
  }
  const wrongProvider = paidEvidence("nvidia/nemotron-3.5-lightning:free");
  wrongProvider.receipts.receipts.forEach((row) => { row.provider = "Novita"; });
  wrongProvider.reconciliation.rows.forEach((row) => { row.provider = "Novita"; });
  assert.throws(() => paidReview.validateS2PaidReviewGenerationAccounting({
    ...wrongProvider, version: 17, prereg: draft,
  }));
});


const sealedV17RunnerInputs = () => ({
  prereg: JSON.parse(fs.readFileSync(path.join(root, 'corpus/s2-008-campaign/preregistration.v17.in-force.json'))),
  manifest: JSON.parse(fs.readFileSync(path.join(root, 'corpus/s2-008-campaign/manifest.json'))),
  modelPin: JSON.parse(fs.readFileSync(path.join(root, 'evidence/s2-008-campaign/model-image-pin-v17.json'))),
  expectedVersion: 17, write: false,
  resolveBaseFn: () => ({ commit_sha: 'a'.repeat(40), tree_sha: 'b'.repeat(40), worktree_dirty: false }),
});
test('v17 runner checks the shared container pacer before a paid model launch', async () => {
  const input = sealedV17RunnerInputs();
  let now = Date.parse('2026-11-01T00:00:00.000Z'), pacerCalls = 0, modelCalls = 0;
  const result = await runRoute.runV4Campaign({ ...input, arm: 'arm-model-zai-glm53flash', now: () => now,
    containerPacer: { run: async (_launch, { shouldContinue }) => {
      pacerCalls += 1;
      assert.equal(shouldContinue(), true);
      now = Date.parse(input.prereg.budget_reservation.expires_at);
      assert.equal(shouldContinue(), false);
      return { proceeded: false, called: false };
    }, snapshot: () => ({ minStartIntervalMs: 60000, containerStarts: 0, waitCount: 1, waitedMs: 60000 }) },
    runModel: async () => { modelCalls += 1; throw new Error('UNEXPECTED_MODEL_LAUNCH'); },
    buildRegex: () => { throw new Error('UNEXPECTED_CONTROL_BUILD'); },
  });
  assert.equal(pacerCalls, 1);
  assert.equal(modelCalls, 0);
  assert.equal(result.code, 'BUDGET_RESERVATION_EXPIRED');
});
test('v17 runner rejects unequal independent control builds before any model launch', async () => {
  let builds = 0, launches = 0;
  const result = await runRoute.runV4Campaign({ ...sealedV17RunnerInputs(), now: () => Date.parse('2026-11-01T00:00:00.000Z'),
    buildRegex: () => ({ pin: { imageId: 'sha256:' + String(++builds).repeat(64),
      digest: 'sha256:' + 'd'.repeat(64), architecture: 'amd64' }, context_digest: 'c'.repeat(64), build_exit: 0 }),
    runModel: async () => { launches += 1; throw new Error('UNEXPECTED_MODEL_LAUNCH'); },
    runRegex: async () => { launches += 1; throw new Error('UNEXPECTED_CONTROL_LAUNCH'); },
  });
  assert.equal(builds, 2);
  assert.equal(launches, 0);
  assert.equal(result.code, 'CONTROL_IMAGE_PIN_INVALID');
});
