import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { canonicalDigest } from "../../src/lib/verifier/canonical-json.mjs";
import { FROZEN_MEMBERS, scopeDrift } from "../../scripts/s2-008-campaign-approve.mjs";
import * as image from "../../scripts/s2-008-campaign-model-image.mjs";
import * as approveRoute from "../../scripts/s2-008-campaign-approve.mjs";
import * as prepareRoute from "../../scripts/s2-008-campaign-prepare-cli.mjs";
import * as runRoute from "../../scripts/s2-008-campaign-run.mjs";
import * as evalRoute from "../../scripts/s2-008-campaign-evaluate.mjs";
import * as probeRoute from "../../scripts/s2-008-campaign-probes.mjs";
import * as adapter from "../../scripts/s2-008-campaign-adapter.mjs";
import * as paidReview from "../../scripts/s2-008-paid-review.mjs";

const approval = await import("../../scripts/s2-008-campaign-v18-approval.mjs").catch(() => ({}));
const seal = await import("../../scripts/s2-008-campaign-seal-v18.mjs").catch(() => ({}));
const modelPolicy = await import("../../scripts/s2-008-campaign-v18-policy.mjs").catch(() => ({}));
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha = (value) => createHash("sha256").update(value).digest("hex");
let fixtureCache;

function makePin(schema, preregBytes) {
  const { sourceNames } = image.modelImagePolicyInputs(schema);
  const catalog = modelPolicy.V18_MODEL_POLICY ?? {};
  const paths = {
    provider_model_catalog: catalog.catalog_file,
    provider_model_catalog_response: catalog.catalog_response_file,
    provider_model_endpoint_catalog: catalog.endpoint_catalog_file,
    model_call_pacing_policy: "scripts/s2-008-campaign-v14-pacing.mjs",
    v18_model_policy: "scripts/s2-008-campaign-v18-policy.mjs",
    v18_approval_policy: "scripts/s2-008-campaign-v18-approval.mjs",
    v18_seal_policy: "scripts/s2-008-campaign-seal-v18.mjs",
  };
  const sources = Object.fromEntries([...sourceNames, "prereg"].sort().map((name) => [name,
    name === "prereg" ? sha(preregBytes)
      : paths[name] ? sha(fs.readFileSync(path.join(root, paths[name])))
        : name === "provider_model_catalog" ? catalog.catalog_sha256
          : name === "provider_model_catalog_response" ? catalog.catalog_response_sha256
            : name === "provider_model_endpoint_catalog" ? catalog.endpoint_catalog_sha256
              : sha(Buffer.from("v18-fixture:" + name))]));
  const covers = Object.keys(sources).filter((name) => name !== "prereg").sort();
  const commitment = canonicalDigest(Object.fromEntries(covers.map((key) => [key, sources[key]])));
  const first = { imageId: "sha256:" + "a".repeat(64), digest: "sha256:" + "b".repeat(64),
    sources, source_digest: canonicalDigest(sources), content_commitment: commitment,
    content_commitment_covers: covers };
  return { schema, identical: true, context_digest_stable: true, content_commitment_stable: true,
    commitment_excludes_preregistration: true, commitment: { covers, excludes: ["prereg"] },
    first: structuredClone(first), second: structuredClone(first) };
}

function v18Fixture() {
  if (fixtureCache) return fixtureCache;
  const baseInputs = approval.readV18BaseInputs({ repoRoot: root, allowHistorical: true });
  const restartInputs = approval.readV18PriorExecutionInputs({ repoRoot: root });
  const pin = makePin("s2-008-model-image-pin/18", baseInputs.baseBytes);
  const draft = approval.createV18Draft({ ...baseInputs, pin, restartInputs, repoRoot: root });
  const signed = approval.approveV18({ ...baseInputs, draft, pin, restartInputs, repoRoot: root,
    principal: "prn-s2007r-owner", label: "Daniil", issuedAt: "2026-11-01T00:00:00.000Z" });
  const sealed = seal.sealV18({ ...baseInputs, signed, draft, pin, restartInputs, repoRoot: root });
  const preregBytes = Buffer.from(JSON.stringify(sealed.prereg, null, 2) + "\n");
  const finalPin = makePin("s2-008-model-image-pin/18", preregBytes);
  fixtureCache = { baseInputs, restartInputs, pin, draft, signed, sealed, preregBytes, finalPin };
  return fixtureCache;
}

test("v18 model-image build stages v17 before seal and commits the recovery policy", () => {
  assert.deepEqual(image.modelImagePaths("v18", { preseal: true }), {
    tag: "localhost/veritas-s2-008-model:v18",
    stagedPrereg: "corpus/s2-008-campaign/preregistration.v17.in-force.json",
    pinFile: "evidence/s2-008-campaign/model-image-pin-v18-preseal.json",
    schema: "s2-008-model-image-pin/18",
  });
  assert.equal(image.modelImagePaths("v18").stagedPrereg, "corpus/s2-008-campaign/preregistration.v18.in-force.json");
  assert.equal(image.modelImageVersionFromArgv(["node", "builder", "--v18"]), "v18");
  const inputs = image.modelImagePolicyInputs("s2-008-model-image-pin/18");
  assert.ok(inputs.stageFiles.includes("scripts/s2-008-campaign-v18-policy.mjs"));
  assert.ok(inputs.stageFiles.includes("scripts/s2-008-campaign-v18-approval.mjs"));
  assert.ok(inputs.stageFiles.includes("scripts/s2-008-campaign-seal-v18.mjs"));
  assert.ok(inputs.stageFiles.includes("evidence/s2-008-campaign/v17-a-stopped/run-v17-a.json"));
  assert.ok(inputs.sourceNames.includes("v18_model_policy"));
  assert.ok(inputs.sourceNames.includes("v18_approval_policy"));
  assert.ok(inputs.sourceNames.includes("v18_predecessor_evidence"));
});

test("v18 approval, seal, run, probe, evaluator and paid-review dispatch are supported", () => {
  assert.equal(approveRoute.parseArgs(["--version", "v18", "--principal", "prn-s2007r-owner", "--label", "Daniil"]).version, "v18");
  assert.equal(prepareRoute.parsePrepareMode(["--seal-v18"]), "seal-v18");
  assert.equal(runRoute.campaignCliMode({ v18: true }).requestedVersion, 18);
  assert.equal(evalRoute.activeCampaignVersion({ preregistration: { file: "preregistration.v18.in-force.json" } }), "v18");
  assert.equal(probeRoute.resolveProbePreregistrationPath("corpus/s2-008-campaign/preregistration.v18.in-force.json", root),
    path.join(root, "corpus/s2-008-campaign/preregistration.v18.in-force.json"));
  assert.equal(path.basename(probeRoute.defaultProbeOutputPath({ rule: "s2-008-prereg-v18" }, root)), "probes-v18.json");
  assert.ok(evalRoute.V18_REVIEW_CAPSULE_SOURCE_PATHS.includes("scripts/s2-008-campaign-v18-approval.mjs"));
  assert.ok(evalRoute.V18_REVIEW_CAPSULE_SOURCE_PATHS.includes("evidence/s2-008-campaign/v17-a-stopped/request-outcome-reconciliation.json"));
  assert.equal(evalRoute.buildV18ReviewCapsuleSourceInputs(evalRoute.V18_REVIEW_CAPSULE_SOURCE_PATHS.map((file) => ({
    path: file, contents: Buffer.from("v18-review-fixture"),
  }))).length, evalRoute.V18_REVIEW_CAPSULE_SOURCE_PATHS.length);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-inspector-route-"));
  try {
    fs.mkdirSync(path.join(temp, "corpus/s2-008-campaign"), { recursive: true });
    fs.writeFileSync(path.join(temp, "corpus/s2-008-campaign/manifest.json"), JSON.stringify({
      preregistration: { file: "preregistration.v18.in-force.json", status: "IN_FORCE", sealed_before_first_trial: true },
    }));
    const inspected = paidReview.inspectS2PaidReviewEvidence(temp);
    assert.equal(inspected.version, 18);
    assert.equal(inspected.reasons.includes("PAID_REVIEW_VERSION_UNSUPPORTED"), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("v18 binds every immutable v17 artifact and keeps unknown historical totals null", () => {
  assert.equal(typeof approval.readV18PriorExecutionInputs, "function");
  const inputs = approval.readV18PriorExecutionInputs({ repoRoot: root });
  const predecessor = approval.assertV18PriorExecutionReconciliation(inputs);
  assert.equal(predecessor.prior_raw_run_id, "s2-008c-v17-a-3bfe162cc5774fa38a3a");
  assert.equal(predecessor.prior_preregistration_digest, "8a2df9a2c37751098a28706bddf71dcff5b58656886baabceff2712b2798742f");
  assert.equal(predecessor.prior_outcome, "INFRA");
  assert.equal(predecessor.disposition, "RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO");
  assert.equal(predecessor.known_model_calls, 10);
  assert.equal(predecessor.known_tokens_lower_bound, 11677);
  assert.equal(predecessor.known_provider_usd_lower_bound, 0);
  assert.equal(predecessor.classified_unknown_attempts, 1);
  assert.equal(predecessor.unclassified_attempts, 0);
  assert.equal(predecessor.failed_request_tokens_confirmed, null);
  assert.equal(predecessor.failed_request_usd_confirmed, null);
  assert.equal(predecessor.total_tokens_confirmed, null);
  assert.equal(predecessor.total_usd_confirmed, null);
  assert.equal(predecessor.raw_unreconciled_spend_preserved, true);
  assert.equal(predecessor.account_wide_completeness_claimed, false);
  assert.equal(predecessor.immutable_artifacts.length, 16);
  assert.ok(predecessor.immutable_artifacts.every((artifact) =>
    Number.isSafeInteger(artifact.bytes) && /^[0-9a-f]{64}$/.test(artifact.sha256)));
  const changed = { ...inputs, run: { ...inputs.run, bytes: Buffer.concat([inputs.run.bytes, Buffer.from(" ")]) } };
  assert.throws(() => approval.assertV18PriorExecutionReconciliation(changed), /V18_PRIOR_EXECUTION_ARTIFACT_BINDING_INVALID/);
});

test("v18 adds a signed one-A/conditional-B recovery scope without changing frozen science", () => {
  const { baseInputs, restartInputs, pin, draft, signed } = v18Fixture();
  assert.equal(FROZEN_MEMBERS.length, 15);
  for (const member of FROZEN_MEMBERS) assert.deepEqual(draft[member], baseInputs.base[member], member);
  assert.equal(scopeDrift(baseInputs.base, draft), null);
  assert.equal(draft.rule, "s2-008-prereg-v18");
  assert.equal(draft.preregistration_id, "xpr-s2-008c-18");
  assert.equal(draft.executor.model, "nvidia/nemotron-3.5-lightning:free");
  assert.deepEqual(draft.executor.pi_settings.retry, { enabled: false, maxRetries: 0, provider: { maxRetries: 0 } });
  assert.equal(draft.executor.model_call_pacing.min_start_interval_ms, 60000);
  assert.equal(draft.budget_reservation.granted_units, 5000000);
  assert.equal(draft.budget_reservation.ceiling_scope, "PER_RUN_A_OR_B");
  assert.equal(draft.budget_reservation.expires_at, "2026-11-07T00:00:00.000Z");
  assert.equal(draft.recovery_authorization.predecessor.known_tokens_lower_bound, 11677);
  assert.equal(draft.recovery_authorization.predecessor.classified_unknown_attempts, 1);
  assert.equal(draft.recovery_authorization.predecessor.total_tokens_confirmed, null);
  assert.equal(draft.recovery_authorization.authorization_scope.maximum_new_a_runs, 1);
  assert.equal(draft.recovery_authorization.authorization_scope.maximum_new_b_runs, 1);
  assert.equal(draft.recovery_authorization.authorization_scope.b_condition, "A_FULLY_MEASURED_AND_RECEIPTS_RECONCILED");
  assert.equal(draft.recovery_authorization.authorization_scope.within_run_infra_retry_count, 0);
  assert.equal(draft.recovery_authorization.authorization_scope.next_version_automatic, false);
  assert.equal(signed.recovery_authorization.authority, "HUMAN_OWNER");
  assert.equal(signed.recovery_authorization.principal_id, "prn-s2007r-owner");
  assert.equal(signed.recovery_authorization.label, "Daniil");
  assert.equal(approval.assertV18RecoveryAuthorization({
    authorization: signed.recovery_authorization,
    preregistrationId: signed.preregistration_id,
    recoveryScopeDigest: signed.recovery_authorization.recovery_scope_digest,
    priorInputs: restartInputs,
  }).ok, true);
  const altered = structuredClone(signed.recovery_authorization);
  altered.predecessor.raw_run_sha256 = "0".repeat(64);
  assert.throws(() => approval.assertV18RecoveryAuthorization({
    authorization: altered, preregistrationId: signed.preregistration_id,
    recoveryScopeDigest: altered.recovery_scope_digest, priorInputs: restartInputs,
  }), /V18_RECOVERY_AUTHORIZATION_INVALID/);
  const alteredScience = structuredClone(draft);
  alteredScience.metric = { changed: true };
  assert.equal(scopeDrift(baseInputs.base, alteredScience)?.member, "metric");
  const unsigned = structuredClone(draft);
  unsigned.recovery_authorization = null;
  assert.throws(() => seal.sealV18({ ...baseInputs, signed: unsigned, draft: unsigned, pin, restartInputs }),
    /V18_RECOVERY_AUTHORIZATION_INVALID|V18_NOT_APPROVED/);
});

test("v18 runner preserves container pacing and builds two controls before any model launch", async () => {
  const { sealed, preregBytes, finalPin } = v18Fixture();
  let pacerCalls = 0, modelCalls = 0, builds = 0, controlLaunches = 0;
  const common = {
    prereg: sealed.prereg,
    preregistrationBytes: preregBytes,
    manifest: sealed.manifest,
    modelPin: finalPin,
    expectedVersion: 18,
    write: false,
    now: () => Date.parse("2026-11-01T00:00:00.000Z"),
    resolveBaseFn: () => ({ commit_sha: "a".repeat(40), tree_sha: "b".repeat(40), worktree_dirty: false }),
  };
  const paced = await runRoute.runV4Campaign({ ...common, arm: "arm-model-zai-glm53flash",
    containerPacer: { run: async (_launch, { shouldContinue }) => {
      pacerCalls += 1;
      assert.equal(shouldContinue(), true);
      return { proceeded: false, called: false };
    }, snapshot: () => ({ minStartIntervalMs: 60000, containerStarts: 0, waitCount: 1, waitedMs: 60000 }) },
    runModel: async () => { modelCalls += 1; throw new Error("UNEXPECTED_MODEL_LAUNCH"); },
    buildRegex: () => { throw new Error("UNEXPECTED_CONTROL_BUILD"); },
  });
  assert.equal(pacerCalls, 1);
  assert.equal(modelCalls, 0);
  assert.equal(paced.code, "BUDGET_RESERVATION_EXPIRED");

  const controls = await runRoute.runV4Campaign({ ...common, arm: null,
    buildRegex: () => ({ pin: { imageId: "sha256:" + String(++builds).repeat(64),
      digest: "sha256:" + "d".repeat(64), architecture: "amd64" }, context_digest: "c".repeat(64), build_exit: 0 }),
    runModel: async () => { modelCalls += 1; throw new Error("UNEXPECTED_MODEL_LAUNCH"); },
    runRegex: async () => { controlLaunches += 1; throw new Error("UNEXPECTED_CONTROL_LAUNCH"); },
  });
  assert.equal(builds, 2);
  assert.equal(modelCalls, 0);
  assert.equal(controlLaunches, 0);
  assert.equal(controls.code, "CONTROL_IMAGE_PIN_INVALID");
});

test("v18 adapter pins the new prereg path and enforces the 60-second pacing contract", () => {
  const argv = adapter.modelTrialArgv({ armId: "arm-model-zai-glm53flash", seed: 20260926,
    remainingTokens: 4999999, preregRule: "s2-008-prereg-v18", minStartIntervalMs: 60000 });
  assert.ok(argv.includes("/opt/veritas/corpus/s2-008-campaign/preregistration.v18.in-force.json"));
  assert.equal(argv[argv.indexOf("--min-start-interval-ms") + 1], "60000");
  assert.throws(() => adapter.modelTrialArgv({ armId: "arm-model-zai-glm53flash", seed: 20260926,
    remainingTokens: 1, preregRule: "s2-008-prereg-v18", minStartIntervalMs: 59999 }),
  /V18_MIN_START_INTERVAL_INVALID/);
});
