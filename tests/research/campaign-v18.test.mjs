import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalDigest } from "../../src/lib/verifier/canonical-json.mjs";
import { buildInvocation } from "../../src/lib/isolation/launch.mjs";
import { SANDBOX_ISOLATION_EXECUTOR } from "../../src/lib/isolation/profile.mjs";
import { FROZEN_MEMBERS, scopeDrift } from "../../scripts/s2-008-campaign-approve.mjs";
import { preregistrationDigest } from "../../src/lib/research/index.mjs";
import * as image from "../../scripts/s2-008-campaign-model-image.mjs";
import * as approveRoute from "../../scripts/s2-008-campaign-approve.mjs";
import * as prepareRoute from "../../scripts/s2-008-campaign-prepare-cli.mjs";
import * as runRoute from "../../scripts/s2-008-campaign-run.mjs";
import * as evalRoute from "../../scripts/s2-008-campaign-evaluate.mjs";
import * as probeRoute from "../../scripts/s2-008-campaign-probes.mjs";
import * as adapter from "../../scripts/s2-008-campaign-adapter.mjs";
import * as paidReview from "../../scripts/s2-008-paid-review.mjs";
import * as armRoute from "../../scripts/s2-008-campaign-arm-model.mjs";
import * as oldV13 from "../../scripts/s2-008-campaign-v13-approval.mjs";
import * as oldV14 from "../../scripts/s2-008-campaign-v14-approval.mjs";
import * as oldV15 from "../../scripts/s2-008-campaign-v15-approval.mjs";
import * as oldV16 from "../../scripts/s2-008-campaign-v16-approval.mjs";
const oldV17 = await import("../../scripts/s2-008-campaign-v17-approval.mjs");

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
    v17_model_policy: "scripts/s2-008-campaign-v17-policy.mjs",
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
        : name === "v18_predecessor_evidence" ? approval.V18_RECOVERY_EVIDENCE_DIGEST
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

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + "\n");
  fs.writeFileSync(file, bytes, { flag: "wx", mode: 0o600 });
  return bytes;
}

const ARM_SCRIPT = path.join(root, "scripts/s2-008-campaign-arm-model.mjs");
const BLIND_INPUT = path.join(root, "corpus/s2-008-campaign/cases/holdout.blind.json");
function runArmKernel(temp, name, prereg, intervalMs = 60000) {
  const preregPath = path.join(temp, `${name}.prereg.json`);
  const outPath = path.join(temp, `${name}.out.json`);
  writeJson(preregPath, prereg);
  const child = spawnSync(process.execPath, [ARM_SCRIPT, BLIND_INPUT, outPath,
    "arm-model-zai-glm53flash", preregPath, "20260926", "--dry-run", "--remaining-tokens", "5000000",
    "--min-start-interval-ms", String(intervalMs)], { cwd: root, encoding: "utf8" });
  if (child.error) throw child.error;
  return { ...child, outPath };
}

function makeV18ImageContext(temp) {
  const context = path.join(temp, "v18-image-context");
  const veritas = path.join(context, "opt/veritas");
  const baseFiles = [
    "scripts/s2-008-campaign-arm-model.mjs", "scripts/s2-008-egress-bridge.mjs",
    "src/lib/verifier/canonical-json.mjs", "corpus/s2-008-campaign/cases/holdout.blind.json",
    image.modelImagePaths("v18").stagedPrereg, "scripts/s2-008-campaign-v6-timeout.mjs",
    "scripts/s2-008-campaign-credential-env.mjs", "scripts/s2-008-campaign-v14-pacing.mjs",
  ];
  const files = new Set([...baseFiles, ...image.modelImagePolicyInputs("s2-008-model-image-pin/18").stageFiles,
    "scripts/s2-008-campaign-v17-policy.mjs"]);
  for (const relative of files) {
    const target = path.join(veritas, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `fixture:${relative}\n`);
  }
  for (const relative of ["opt/pi/package.json", "opt/pi/npm-shrinkwrap.json", "opt/pi/dist/bundle/cli.js",
    "usr/local/bin/pi", "Containerfile"]) {
    const target = path.join(context, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `fixture:${relative}\n`);
  }
  return context;
}

function createV18ARepoFixture(tempRoot, fixture) {
  const aRoot = path.join(tempRoot, "a-clone");
  execFileSync("git", ["clone", "--quiet", "--shared", "--no-hardlinks", root, aRoot]);
  const v17Manifest = approval.readV18BaseInputs({ repoRoot: root, allowHistorical: true }).manifest;
  fs.writeFileSync(path.join(aRoot, "corpus/s2-008-campaign/manifest.json"),
    JSON.stringify(v17Manifest, null, 2) + "\n");
  for (const relative of [
    "corpus/s2-008-campaign/preregistration.v18.draft.json",
    "corpus/s2-008-campaign/preregistration.v18.approved.json",
    ...seal.V18_SEAL_TARGETS.map((name) => "corpus/s2-008-campaign/" + name),
    "evidence/s2-008-campaign/model-image-pin-v18-preseal.json",
    "evidence/s2-008-campaign/model-image-pin-v18.json",
  ]) fs.rmSync(path.join(aRoot, relative), { force: true });
  for (const relative of image.modelImagePolicyInputs("s2-008-model-image-pin/18").stageFiles) {
    const source = path.join(root, relative);
    assert.ok(fs.existsSync(source), `missing bound fixture input ${relative}`);
    const target = path.join(aRoot, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(source, target);
  }

  const corpus = path.join(aRoot, "corpus/s2-008-campaign");
  const evidence = path.join(aRoot, "evidence/s2-008-campaign");
  writeJson(path.join(corpus, "preregistration.v18.draft.json"), fixture.draft);
  writeJson(path.join(corpus, "preregistration.v18.approved.json"), fixture.signed);
  writeJson(path.join(evidence, "model-image-pin-v18-preseal.json"), fixture.pin);
  writeJson(path.join(evidence, "model-image-pin-v18.json"), fixture.finalPin);
  seal.sealV18OnDisk(aRoot);
  assert.equal(seal.checkV18OnDisk(aRoot).preregistration_digest, fixture.sealed.prereg.preregistration_digest);

  const commit = execFileSync("git", ["-C", aRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const tree = execFileSync("git", ["-C", aRoot, "rev-parse", "HEAD^{tree}"], { encoding: "utf8" }).trim();
  const caseRows = JSON.parse(fs.readFileSync(path.join(root, "corpus/s2-008-campaign/cases/holdout.blind.json"), "utf8"));
  const caseIds = caseRows.map((row) => row.case_id).sort();
  assert.equal(caseIds.length, 126);
  const context = adapter.campaignImageContextDigest();
  const controlImageId = "sha256:" + "1".repeat(64);
  const controlDigest = "sha256:" + "2".repeat(64);
  const controlPin = {
    kind: "s2-008-campaign-control-image-pin/1",
    first: { imageId: controlImageId, digest: controlDigest, architecture: "amd64", context_digest: context, build_exit: 0 },
    second: { imageId: controlImageId, digest: controlDigest, architecture: "amd64", context_digest: context, build_exit: 0 },
    identical: true, context_digest_stable: true, source_base: { commit_sha: commit, tree_sha: tree },
  };
  assert.equal(adapter.validateControlImagePinEvidence(controlPin, { commit, tree }), true);
  const runId = "s2-008c-v18-a-positive-fixture";
  const nonce = "nonce-v18-positive-fixture";
  const report = {
    kind: "s2-008-campaign-v18-predictions/1", raw_run_id: runId, label: "a", nonce,
    status: "MEASURED", preregistration_digest: fixture.sealed.prereg.preregistration_digest,
    base: { commit_sha: commit, tree_sha: tree, worktree_dirty: false },
    model_calls: 3, model_calls_is_lower_bound: false, spent_units: 15,
    spent_units_is_lower_bound: false, unknown_model_attempts: 0, unreconciled_spend: false,
    model_call_pacing: { min_start_interval_ms: 60000, container_starts: 3, wait_count: 2, waited_ms: 120000 },
    control_image_pin: controlPin, trials: [],
  };
  const pinRelative = "evidence/s2-008-campaign/control-image-pin-v18-a.json";
  const pinBytes = writeJson(path.join(aRoot, pinRelative), {
    kind: "s2-008-campaign-control-image-pin-artifact/1", label: "a", raw_run_id: runId, nonce,
    base: { commit_sha: commit, tree_sha: tree }, control_image_pin: controlPin,
  });
  report.control_image_pin_artifact = { file: pinRelative, bytes: pinBytes.length, sha256: sha(pinBytes) };

  const provider = modelPolicy.V18_MODEL_POLICY.provider_name;
  const model = modelPolicy.V18_MODEL_POLICY.model;
  const createdAt = "2026-11-01T00:00:00.000Z";
  const epoch = Math.floor(Date.parse(createdAt) / 1000);
  const receiptRows = [];
  const reconciliationRows = [];
  const modelSidecars = [];
  const samples = fixture.sealed.prereg.noise_rule.bootstrap_samples;
  const timeoutMs = fixture.sealed.prereg.budget_reservation.trial_timeout_ms;

  for (const trial of fixture.sealed.prereg.trial_list) {
    const isModel = trial.arm_id === "arm-model-zai-glm53flash";
    const seeds = [];
    for (const [seedIndex, seed] of fixture.sealed.prereg.seed_rule.seeds.entries()) {
      const rows = caseIds.map((case_id) => ({ case_id, predicted: "MINOR" }));
      const sidecar = {
        kind: "s2-008-campaign-predictions/1", run: "a", arm_id: trial.arm_id, seed,
        unparsed: 0, model_calls: isModel ? 1 : null, spent_tokens: isModel ? 5 : null,
        usd_spent: isModel ? 0 : null, outcome_class: isModel ? "MEASURED" : null, rows,
      };
      if (isModel) {
        const generationId = `gen-${epoch}-${String(seedIndex + 1).padStart(16, "0")}`;
        const caseId = `fixture-case-${seed}`;
        const local = { generation_id: generationId, case_id: caseId, input: 3, output: 2,
          cacheRead: 0, cacheWrite: 0, prompt_tokens: 3, totalTokens: 5,
          prompt_token_basis: "input+cacheRead+cacheWrite", usage_components_consistent: true,
          reported_cost_usd: null };
        sidecar.accounting = { policy: "GENERATION_ID_REQUIRED", calls: 1, tokens: 5, rows: [local] };
        const receipt = { id: generationId, provider, model, created_at: createdAt, http_status: 200,
          native_prompt: 3, native_completion: 2, native_cached: 0, generation_time: 1,
          cancelled: false, finish_reason: "stop", matches_local: true, total_cost: 0 };
        receiptRows.push(receipt);
        reconciliationRows.push({ generation_id: generationId, provider, case_id: caseId,
          created_at: createdAt, input: 3, output: 2, cached: 0, total_tokens: 5, provider_reported_usd: 0 });
      }
      const relative = `evidence/s2-008-campaign/predictions-v18-a-${trial.trial_id}-${seed}.json`;
      const sidecarBytes = writeJson(path.join(aRoot, relative), sidecar);
      const predictionRef = { file: relative, digest: canonicalDigest(sidecar), rows: 126, unparsed: 0 };
      let launch;
      if (isModel) {
        launch = { exit_code: 0, signal: null, timed_out: false, arm_report: {
          outcome_class: "MEASURED", executor: { model_attempts: 1, model_calls: 1,
            unknown_model_attempts: 0, model_call_pacing: { min_start_interval_ms: 60000,
              call_starts: 1, wait_count: 0, waited_ms: 0 } },
        } };
        modelSidecars.push({ relative, sha256: sha(sidecarBytes) });
      } else {
        const pid = process.pid + 10000 + seedIndex;
        const output = { kind: "s2-008-campaign-adapter-predict/1", arm_id: trial.arm_id, seed,
          n_cases: 126, predictions: rows, container: { node_version: process.version, pid,
            argv_tail: [trial.arm_id, String(seed)], cwd: "/opt/campaign", labels_seen: false } };
        const invocation = buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
          image: controlImageId,
          argv: ["/usr/local/bin/node", "/opt/campaign/arm.mjs", "/opt/campaign/holdout.blind.json",
            "/tmp/campaign-out.json", trial.arm_id, String(seed), String(samples)],
          timeoutMs, name: `s2-008-campaign-${trial.arm_id}-${seed}`,
        });
        const record = { arm_id: trial.arm_id, seed, samples, podman: { executable: "podman", argv_prefix: [] },
          container_argv: invocation.podmanArgv, image: controlImageId, image_break_requested: false,
          axes: invocation.axes, exit_code: 0, signal: null, timed_out: false, stderr_excerpt: "",
          banner: `ADAPTER_OK arm=${trial.arm_id} seed=${seed} n=126 predictions=126 pid=${pid} node=${process.version}`,
          payload_chunks: 1, payload_error: null, output_digest: canonicalDigest(output),
          predictions: { digest: canonicalDigest(sidecar), rows: 126, unparsed: 0 },
          real_start: { proven: true, separate_process: true, container_pid: pid, host_pid: process.pid,
            container_runtime_version: process.version, pin_rechecked_by: "src/lib/isolation/image.mjs#assertImageMatchesPin" } };
        assert.equal(adapter.validateControlExecution({ ok: true, output, record }, { armId: trial.arm_id,
          seed, samples, timeoutMs, runLabel: "a", caseIds, imageId: controlImageId, imageDigest: controlDigest }), true);
        launch = { ...record, image_digest: controlDigest, arm_report: output,
          control_execution: { kind: "s2-008-campaign-control-execution/1", outcome_class: "MEASURED_CONTROL",
            pin_digest: canonicalDigest(controlPin), output_digest: canonicalDigest(output) },
          predictions: record.predictions };
      }
      if (!isModel) launch.predictions = predictionRef;
      seeds.push({ seed, outcome_class: isModel ? "MEASURED" : "MEASURED_CONTROL",
        predictions: predictionRef, launch });
    }
    report.trials.push({ trial_id: trial.trial_id, arm_id: trial.arm_id, seeds });
  }

  const reportBytes = Buffer.from(JSON.stringify(report, null, 2) + "\n");
  const reportPath = path.join(evidence, "run-v18-a.json");
  fs.writeFileSync(reportPath, reportBytes, { flag: "wx", mode: 0o600 });
  const receiptsRelative = "evidence/s2-008-campaign/provider-receipts-v18-a-positive-fixture.json";
  const receipts = { status: "KNOWN_GENERATIONS_MATCH", run_id: runId, known_calls: 3,
    known_tokens: 15, known_provider_usd: 0, unknown_attempts: 0, receipts: receiptRows };
  const receiptsBytes = writeJson(path.join(aRoot, receiptsRelative), receipts);
  writeJson(path.join(evidence, "reconciliation-v18-a.json"), {
    kind: "s2-008-v18-a-reconciliation/1", status: "RECONCILED",
    preregistration_digest: fixture.sealed.prereg.preregistration_digest, prior_run_id: runId,
    prior_run_sha256: sha(reportBytes), provider: "openrouter", model,
    sidecars: modelSidecars.map((row) => ({ file: row.relative, sha256: row.sha256 })),
    known_receipts_file: receiptsRelative, known_receipts_sha256: sha(receiptsBytes),
    completeness_basis: "KNOWN_ATTEMPTS_ALL_RECEIPTS",
    completeness: { basis: "KNOWN_ATTEMPTS_ALL_RECEIPTS", all_local_attempts_accounted: true,
      unfiltered_account_ledger_claimed: false, confirmed_by: null },
    provider_rows_verified_via_api: true, completeness_verified_via_api: false,
    local_model_attempts: 3, locally_accounted_model_calls: 3, matching_requests: 3,
    unreconciled_attempts: 0, actual_tokens: 15, actual_usd: 0, rows: reconciliationRows,
  });
  return { aRoot, evidenceRoot: evidence, reportPath, modelSidecarPath: path.join(aRoot, modelSidecars[0].relative), reportBytes, runId };
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
  const v17Prereg = JSON.parse(fs.readFileSync(path.join(root,
    "corpus/s2-008-campaign/preregistration.v17.in-force.json"), "utf8"));
  assert.deepEqual(evalRoute.validateV18ProbeEvidence({ prereg: v17Prereg }), {
    ok: false, status: "NOT_RUN", reason: "V18_PREREGISTRATION_DIGEST_MISMATCH",
  });
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

test("v18 paid-review capsule producer and consumer bind all 16 predecessor artifacts", () => {
  const sourcePaths = evalRoute.V18_REVIEW_CAPSULE_SOURCE_PATHS;
  const predecessorPaths = sourcePaths.filter((file) => file.startsWith("evidence/s2-008-campaign/v17-a-stopped/"));
  assert.equal(predecessorPaths.length, 16);
  const { preregBytes } = v18Fixture();
  const sourceEntries = sourcePaths.map((file) => ({ path: file,
    contents: file === "corpus/s2-008-campaign/preregistration.v18.in-force.json"
      ? preregBytes : fs.readFileSync(path.join(root, file)) }));
  const capsuleInputs = evalRoute.buildV18ReviewCapsuleSourceInputs(sourceEntries);
  assert.deepEqual(paidReview.capsuleSourcePaths(18), sourcePaths);
  assert.deepEqual(paidReview.validateS2PaidReviewCapsuleSourceInputs(capsuleInputs, capsuleInputs, { version: 18 }), { ok: true });
  assert.deepEqual(paidReview.validateS2PaidReviewCapsuleSourceInputs(capsuleInputs.slice(1), capsuleInputs, { version: 18 }), { ok: false });
  assert.deepEqual(paidReview.validateS2PaidReviewCapsuleSourceInputs(capsuleInputs, capsuleInputs, { version: 19 }), { ok: false });
});

test("paid-review comparison reader accepts the active v18 comparison artifact name", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-paid-review-comparison-"));
  try {
    const corpus = path.join(temp, "corpus/s2-008-campaign");
    const evidence = path.join(temp, "evidence/s2-008-campaign");
    fs.mkdirSync(corpus, { recursive: true });
    fs.mkdirSync(evidence, { recursive: true });
    fs.writeFileSync(path.join(corpus, "manifest.json"), JSON.stringify({
      preregistration: { file: "preregistration.v18.in-force.json", status: "IN_FORCE", sealed_before_first_trial: true },
    }));
    fs.writeFileSync(path.join(evidence, "comparison-v18.json"), JSON.stringify({ kind: "v18-review-comparison-fixture" }));
    const inspected = paidReview.inspectS2PaidReviewEvidence(temp);
    const comparison = inspected.artifactManifest.find((entry) => entry.path === "evidence/s2-008-campaign/comparison-v18.json");
    assert.equal(inspected.version, 18);
    assert.match(comparison?.sha256 ?? "", /^[0-9a-f]{64}$/);
    assert.equal(inspected.reasons.includes("COMPARISON_MISSING"), false);
    assert.equal(inspected.reasons.includes("EVIDENCE_PATH_INVALID"), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("paid-review evaluation and comparison path contracts accept v18 and reject v19", () => {
  assert.equal(paidReview.PAID_REVIEW_RECORD_PATH_PATTERN.evaluation.test("evidence/s2-008-campaign/evaluation-v18.json"), true);
  assert.equal(paidReview.PAID_REVIEW_RECORD_PATH_PATTERN.comparison.test("evidence/s2-008-campaign/comparison-v18.json"), true);
  assert.equal(paidReview.PAID_REVIEW_RECORD_PATH_PATTERN.evaluation.test("evidence/s2-008-campaign/evaluation-v19.json"), false);
  assert.equal(paidReview.PAID_REVIEW_RECORD_PATH_PATTERN.comparison.test("evidence/s2-008-campaign/comparison-v19.json"), false);
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
  const { baseInputs, restartInputs, pin, draft, signed, sealed } = v18Fixture();
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
  assert.equal(draft.recovery_authorization.authorization_scope.same_run_retry_permitted, false);
  assert.equal(draft.recovery_authorization.authorization_scope.on_infra, "RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO");
  assert.equal(draft.recovery_authorization.authorization_scope.automatic_next_version_permitted, false);
  assert.equal(signed.recovery_authorization.owner_approval.authority, "HUMAN_OWNER");
  assert.equal(signed.recovery_authorization.owner_approval.principal_id, "prn-s2007r-owner");
  assert.equal(signed.recovery_authorization.owner_approval.label, "Daniil");
  assert.equal(approval.assertV18RecoveryAuthorization(sealed.prereg,
    approval.assertV18PriorExecutionReconciliation(restartInputs)), true);
  const altered = structuredClone(sealed.prereg);
  altered.recovery_authorization.predecessor.prior_raw_run_sha256 = "0".repeat(64);
  altered.preregistration_digest = preregistrationDigest(altered);
  assert.throws(() => approval.assertV18RecoveryAuthorization(altered,
    approval.assertV18PriorExecutionReconciliation(restartInputs)), /V18_RECOVERY_AUTHORIZATION_INVALID/);
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


test("v18 paid authorization is consumed once in shared state and B blocks until reconciled A", async () => {
  assert.equal(typeof approval.reserveV18RunAuthorization, "function");
  assert.equal(typeof approval.assertV18BEligibility, "function");
  const { sealed } = v18Fixture();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-run-authorization-"));
  const stateDir = path.join(temp, "shared-state");
  try {
    const dry = approval.reserveV18RunAuthorization({ prereg: sealed.prereg, label: "a",
      runId: "dry-run", stateDir, dryRun: true, repoRoot: root });
    assert.deepEqual(dry, { consumed: false, reason: "DRY_RUN" });
    assert.equal(fs.existsSync(stateDir), false);
    const first = approval.reserveV18RunAuthorization({ prereg: sealed.prereg, label: "a",
      runId: "s2-008c-v18-a-test-one", stateDir, repoRoot: root });
    assert.equal(first.consumed, true);
    assert.throws(() => approval.reserveV18RunAuthorization({ prereg: sealed.prereg, label: "a",
      runId: "s2-008c-v18-a-test-two", stateDir, repoRoot: root }),
    /V18_RUN_AUTHORIZATION_ALREADY_CONSUMED/);
    await assert.rejects(() => approval.assertV18BEligibility({ repoRoot: root, prereg: sealed.prereg, stateDir }),
    /V18_B_REQUIRES_RECONCILED_A/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("v18 production reservation ignores environment path overrides across processes", () => {
  const { sealed } = v18Fixture();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-authorization-env-"));
  const home = path.join(temp, "home");
  const redirectOne = path.join(temp, "redirect-one");
  const redirectTwo = path.join(temp, "redirect-two");
  fs.mkdirSync(home, { recursive: true });
  const approvalUrl = new URL("../../scripts/s2-008-campaign-v18-approval.mjs", import.meta.url).href;
  const child = [
    "import fs from 'node:fs';",
    "import os from 'node:os';",
    "os.homedir = () => process.env.VERITAS_V18_TEST_HOME;",
    "os.userInfo = () => ({ homedir: process.env.VERITAS_V18_TEST_ACCOUNT_HOME });",
    `const { reserveV18RunAuthorization } = await import(${JSON.stringify(approvalUrl)});`,
    "const prereg = JSON.parse(fs.readFileSync(0, 'utf8'));",
    "try {",
    "  reserveV18RunAuthorization({ prereg, label: 'a', runId: process.env.VERITAS_V18_TEST_RUN_ID, repoRoot: process.env.VERITAS_V18_TEST_REPO });",
    "  process.stdout.write('RESERVED');",
    "} catch (error) {",
    "  if (error?.message !== 'V18_RUN_AUTHORIZATION_ALREADY_CONSUMED') throw error;",
    "  process.stdout.write('BLOCKED');",
    "}",
  ].join("\n");
  const invoke = (override, runId, untrustedHome) => execFileSync(process.execPath,
    ["--input-type=module", "-e", child], {
      cwd: root,
      env: { PATH: process.env.PATH ?? "", TMPDIR: temp, VERITAS_V18_TEST_HOME: untrustedHome,
        VERITAS_V18_TEST_ACCOUNT_HOME: home,
        VERITAS_V18_AUTHORIZATION_STATE: override,
        VERITAS_V18_TEST_RUN_ID: runId, VERITAS_V18_TEST_REPO: root },
      input: JSON.stringify(sealed.prereg), encoding: "utf8",
    });
  try {
    assert.equal(invoke(redirectOne, "s2-008c-v18-a-env-first", redirectOne), "RESERVED");
    assert.equal(invoke(redirectTwo, "s2-008c-v18-a-env-second", redirectTwo), "BLOCKED");
    const ledger = path.join(home, ".local/state/veritas/s2-008-v18-authorization",
      sealed.prereg.preregistration_digest + "-a.json");
    assert.equal(fs.existsSync(ledger), true);
    assert.equal(fs.existsSync(redirectOne), false);
    assert.equal(fs.existsSync(redirectTwo), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("v18 production runner checks durable A reservation before dispatching any model adapter", async () => {
  const { sealed, preregBytes, finalPin } = v18Fixture();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-runner-reservation-"));
  const stateDir = path.join(temp, "shared-state");
  const out = path.join(temp, "must-not-be-written.json");
  let modelCalls = 0;
  try {
    approval.reserveV18RunAuthorization({ prereg: sealed.prereg, label: "a",
      runId: "s2-008c-v18-a-prereserved", stateDir, repoRoot: root });
    const result = await runRoute.runV4Campaign({
      label: "a", arm: "arm-model-zai-glm53flash", expectedVersion: 18, write: true, out,
      prereg: sealed.prereg, preregistrationBytes: preregBytes, manifest: sealed.manifest,
      modelPin: finalPin, authorizationStateDir: stateDir,
      resolveBaseFn: () => ({ commit_sha: "a".repeat(40), tree_sha: "b".repeat(40), worktree_dirty: false }),
      runModel: async () => { modelCalls += 1; throw new Error("UNEXPECTED_MODEL_DISPATCH"); },
    });
    assert.equal(result.code, "V18_RUN_AUTHORIZATION_ALREADY_CONSUMED");
    assert.equal(result.launches, 0);
    assert.equal(modelCalls, 0);
    assert.equal(fs.existsSync(out), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("v18 B accepts a fully validated A and rejects a changed A prediction sidecar", async () => {
  const fixture = v18Fixture();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-b-eligibility-"));
  const stateDir = path.join(temp, "shared-state");
  try {
    const a = createV18ARepoFixture(temp, fixture);
    approval.reserveV18RunAuthorization({ prereg: fixture.sealed.prereg, label: "a",
      runId: a.runId, stateDir, repoRoot: root });
    approval.completeV18RunAuthorization({ prereg: fixture.sealed.prereg, label: "a", runId: a.runId,
      stateDir, reportPath: a.reportPath, evidenceRoot: a.evidenceRoot, repoRoot: root });
    const eligible = await approval.assertV18BEligibility({ repoRoot: root, prereg: fixture.sealed.prereg,
      stateDir, aEvidenceRoot: a.evidenceRoot });
    assert.equal(eligible.ok, true);
    assert.equal(eligible.tokens, 15);
    assert.equal(eligible.usd, 0);

    const tampered = JSON.parse(fs.readFileSync(a.modelSidecarPath, "utf8"));
    tampered.rows[0].predicted = "MAJOR";
    fs.writeFileSync(a.modelSidecarPath, JSON.stringify(tampered, null, 2) + "\n");
    await assert.rejects(() => approval.assertV18BEligibility({ repoRoot: root,
      prereg: fixture.sealed.prereg, stateDir, aEvidenceRoot: a.evidenceRoot }),
    /V18_A_REQUIRES_MEASURED_RECEIPTS_RECONCILIATION|V18_B_REQUIRES_RECONCILED_A/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("v18 model image stages and hashes the transitive v17 policy dependency", () => {
  const inputs = image.modelImagePolicyInputs("s2-008-model-image-pin/18");
  assert.ok(inputs.stageFiles.includes("scripts/s2-008-campaign-v17-policy.mjs"));
  assert.ok(inputs.sourceNames.includes("v17_model_policy"));

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-image-v17-policy-"));
  try {
    const context = makeV18ImageContext(temp);
    const policyPath = path.join(context, "opt/veritas/scripts/s2-008-campaign-v17-policy.mjs");
    const before = image.modelImageSourcesFromContext(context, { version: "v18" });
    assert.equal(before.v17_model_policy, sha(fs.readFileSync(policyPath)));
    fs.writeFileSync(policyPath, "tampered staged v17 policy\n");
    const after = image.modelImageSourcesFromContext(context, { version: "v18" });
    assert.notEqual(after.v17_model_policy, before.v17_model_policy);
    assert.throws(() => image.assertModelImageSourcesStable(before, after), /MODEL_BUILD_CONTEXT_MUTATED/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("v18 arm kernel accepts the sealed signed preregistration for a zero-call dry run", () => {
  const { sealed } = v18Fixture();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-arm-kernel-dry-run-"));
  try {
    const child = runArmKernel(temp, "valid", sealed.prereg);
    assert.equal(child.status, 0, child.stderr);
    const record = JSON.parse(fs.readFileSync(child.outPath, "utf8"));
    assert.equal(record.dry_run, true);
    assert.equal(record.outcome_class, "DRY_RUN");
    assert.equal(record.budget.granted_tokens, 5000000);
    assert.equal(record.executor.provider, "openrouter");
    assert.equal(record.executor.model, "nvidia/nemotron-3.5-lightning:free");
    assert.equal(record.executor.model_call_pacing.min_start_interval_ms, 60000);
    assert.equal(record.executor.model_calls, 0);
    assert.equal(record.executor.model_attempts, 0);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("v18 arm kernel refuses unsupported, unsigned, changed-digest, unsealed and sub-minute preregistrations", () => {
  const { sealed } = v18Fixture();
  const unsupported = structuredClone(sealed.prereg);
  unsupported.rule = "s2-008-prereg-v19";
  unsupported.preregistration_digest = preregistrationDigest(unsupported);
  const unsigned = structuredClone(sealed.prereg);
  unsigned.approval.status = null;
  const digestChanged = structuredClone(sealed.prereg);
  digestChanged.kernel_test_mutation = true;
  const unsealed = structuredClone(sealed.prereg);
  unsealed.approval.in_force = false;
  const recoveryChanged = structuredClone(sealed.prereg);
  recoveryChanged.v17_prior_execution_reconciliation.owner_completeness_attestation.UTC_interval = [
    "2026-01-01T00:00:00Z", "2026-01-01T00:00:59Z",
  ];
  recoveryChanged.recovery_authorization.predecessor = structuredClone(recoveryChanged.v17_prior_execution_reconciliation);
  recoveryChanged.preregistration_digest = preregistrationDigest(recoveryChanged);

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-arm-kernel-refusals-"));
  try {
    const cases = [
      ["unsupported", unsupported, 60000, /PREREGISTRATION_VERSION_UNSUPPORTED/],
      ["unsigned", unsigned, 60000, /PREREGISTRATION_NOT_APPROVED/],
      ["digest-changed", digestChanged, 60000, /PREREGISTRATION_DIGEST_MISMATCH/],
      ["unsealed", unsealed, 60000, /PREREGISTRATION_NOT_IN_FORCE/],
      ["recovery-changed", recoveryChanged, 60000, /V18_RECOVERY_AUTHORIZATION_INVALID/],
      ["invalid-pacing", sealed.prereg, 59999, /V18_MODEL_POLICY_INVALID/],
    ];
    for (const [name, prereg, interval, expected] of cases) {
      const child = runArmKernel(temp, name, prereg, interval);
      assert.notEqual(child.status, 0, `${name} preregistration reached the model arm`);
      assert.match(child.stderr, expected, `${name} preregistration was refused for the wrong reason`);
      assert.equal(fs.existsSync(child.outPath), false, `${name} refusal wrote a run record`);
    }
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("v18 arm main uses v18 policy, pacing, credential route and strict generation accounting with a fake Pi process", async () => {
  const { sealed } = v18Fixture();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-arm-kernel-fake-pi-"));
  const inputPath = path.join(temp, "blind.json");
  const preregPath = path.join(temp, "prereg.json");
  const outPath = path.join(temp, "out.json");
  fs.copyFileSync(BLIND_INPUT, inputPath);
  writeJson(preregPath, sealed.prereg);
  let bridgeStarts = 0, callCount = 0, piExecCount = 0, stagedModels = null;
  const piOutput = JSON.stringify({ type: "agent_end", sessionId: "session-v18-fixture", messages: [{
    role: "assistant", responseId: "gen-1790000001-AbcdefghijklmnopQRST", stopReason: "stop",
    content: [{ type: "text", text: "MINOR" }],
    usage: { input: 4, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 5, cost: { total: 0 } },
  }] }) + "\n";
  try {
    const code = await armRoute.main([inputPath, outPath, "arm-model-zai-glm53flash", preregPath, "20260926",
      "--remaining-tokens", "1", "--min-start-interval-ms", "60000"],
    { OPENROUTER_API_KEY: "fixture-only-openrouter-value" }, {
      startBridge: async () => {
        bridgeStarts += 1;
        return { host: "127.0.0.1", port: 18441, stop() {} };
      },
      pacer: {
        runSync(invoke, { shouldContinue }) {
          assert.equal(shouldContinue(), true);
          return { proceeded: true, called: true, value: invoke() };
        },
        snapshot() { return { callsStarted: callCount, waitCount: 0, waitedMs: 0 }; },
      },
      callModel: (subject, options) => {
        callCount += 1;
        assert.equal(typeof options.modelPolicyModule?.assertV18ExecutorPolicy, "function");
        assert.equal(options.provider, "openrouter");
        assert.equal(options.model, "nvidia/nemotron-3.5-lightning:free");
        assert.equal(options.envName, "OPENROUTER_API_KEY");
        assert.deepEqual(options.piSettings, sealed.prereg.executor.pi_settings);
        return armRoute.callModel(subject, { ...options,
          execFile: (command, _args, execOptions) => {
            piExecCount += 1;
            assert.equal(command, "pi");
            const settingsDir = execOptions.env.PI_CODING_AGENT_DIR;
            stagedModels = JSON.parse(fs.readFileSync(path.join(settingsDir, "models.json"), "utf8"));
            return piOutput;
          },
        });
      },
      writeStdout() {},
    });
    assert.equal(code, 6);
    assert.equal(bridgeStarts, 1);
    assert.equal(callCount, 1);
    assert.equal(piExecCount, 1);
    assert.deepEqual(stagedModels, modelPolicy.createV18PiModelsFile(sealed.prereg.executor));
    const record = JSON.parse(fs.readFileSync(outPath, "utf8"));
    assert.equal(record.accounting.length, 1);
    assert.equal(record.accounting[0].correlation_status, "CORRELATED");
    assert.equal(record.accounting[0].usage_components_consistent, true);
    assert.equal(record.executor.model_calls, 1);
    assert.equal(record.executor.model_attempts, 1);
    assert.equal(record.executor.unknown_model_attempts, 0);
    assert.equal(record.budget.unreconciled_spend, false);
    assert.equal(record.stop.reason, "BUDGET_EXHAUSTED");
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("v13-v17 allowHistorical readers use a validated v18 bridge without changing their raw signed bytes", () => {
  const fixture = v18Fixture();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "v18-legacy-history-"));
  try {
    const aRoot = createV18ARepoFixture(temp, fixture).aRoot;
    const v17View = seal.historicalV17ManifestForV18(aRoot,
      JSON.parse(fs.readFileSync(path.join(aRoot, "corpus/s2-008-campaign/manifest.json"), "utf8")));
    assert.equal(v17View.preregistration.file, "preregistration.v17.in-force.json");
    assert.equal(v17View.preregistration.sealed_before_first_trial, true);
    assert.equal(v17View.superseded_preregistration.superseded_by, "preregistration.v17.in-force.json");
    const readers = [
      [13, oldV13.readV13BaseInputs, "preregistration.v12.in-force.json", "preregistration-v12-supersession.json"],
      [14, oldV14.readV14BaseInputs, "preregistration.v13.in-force.json", "preregistration-v13-supersession.json"],
      [15, oldV15.readV15BaseInputs, "preregistration.v14.in-force.json", "preregistration-v14-supersession.json"],
      [16, oldV16.readV16BaseInputs, "preregistration.v15.in-force.json", "preregistration-v15-supersession.json"],
      [17, oldV17.readV17BaseInputs, "preregistration.v16.in-force.json", "preregistration-v16-supersession.json"],
    ];
    for (const [version, read, preregFile, supersessionFile] of readers) {
      const actual = read({ repoRoot: aRoot, allowHistorical: true });
      const raw = fs.readFileSync(path.join(root, "corpus/s2-008-campaign", preregFile));
      assert.deepEqual(actual.baseBytes, raw, `v${version} raw preregistration bytes changed`);
      assert.equal(actual.activeManifest.preregistration.file, "preregistration.v18.in-force.json");
      assert.equal(actual.manifest.preregistration.file, preregFile);
      assert.equal(actual.manifest.preregistration.status, "IN_FORCE");
      assert.equal(actual.manifest.preregistration.preregistration_digest, actual.base.preregistration_digest);
      assert.equal(actual.manifest.supersession_history.at(-1).file, supersessionFile);
      assert.equal(actual.manifest.supersession_history.at(-1).supersession_digest, actual.supersession.supersession_digest);
    }

    const manifestPath = path.join(aRoot, "corpus/s2-008-campaign/manifest.json");
    const changedManifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    changedManifest.preregistration.preregistration_digest = "0".repeat(64);
    fs.writeFileSync(manifestPath, JSON.stringify(changedManifest, null, 2) + "\n");
    assert.throws(() => oldV17.readV17BaseInputs({ repoRoot: aRoot, allowHistorical: true }),
      /V18_ACTIVE_MANIFEST_BINDING_INVALID/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

// The production build must accept the explicit pinned pi package source.
test("v18 builder accepts an absolute pi source and rejects relative and duplicate sources", async () => {
  const { parseModelImageCliArgs } = await import("../../scripts/s2-008-campaign-model-image.mjs");
  assert.deepEqual(parseModelImageCliArgs(["node", "builder", "--v18", "--preseal", "--pi-package-dir", "/recovered/pi"]),
    { version: "v18", preseal: true, packageRoot: "/recovered/pi" });
  for (const argv of [
    ["node", "builder", "--v18", "--pi-package-dir", "relative/pi"],
    ["node", "builder", "--v18", "--pi-package-dir", "/pi", "--pi-package-dir", "/other"],
  ]) assert.throws(() => parseModelImageCliArgs(argv), /MODEL_PI_PACKAGE_SOURCE_INVALID/);
});

const v18RuntimePrereg = JSON.parse(fs.readFileSync(path.join(root,
  "corpus/s2-008-campaign/preregistration.v18.in-force.json"), "utf8"));
const v18RuntimePin = JSON.parse(fs.readFileSync(path.join(root,
  "evidence/s2-008-campaign/model-image-pin-v18.json"), "utf8"));
const v18RuntimeInspect = () => ({
  Id: v18RuntimePin.first.imageId,
  Digest: v18RuntimePin.first.digest,
  Architecture: v18RuntimePin.first.architecture,
});

test("v18 runtime adapter applies the signed pin and pacing before dry dispatch", async () => {
  const invocations = [];
  let paidCalls = 0;
  const result = await adapter.runModelTrial({
    armId: "arm-model-zai-glm53flash", seed: 20260926, timeoutMs: 30540000,
    dryRun: true, pin: v18RuntimePin, prereg: v18RuntimePrereg, remainingTokens: 4999999,
    inspect: v18RuntimeInspect,
    executeDry: async (invocation) => {
      invocations.push(invocation);
      return { exitCode: 0, signal: null, timedOut: false, stdout: "", stderr: "" };
    },
    executePaid: async () => { paidCalls += 1; throw new Error("PAID_PATH_MUST_NOT_RUN"); },
  });
  assert.equal(invocations.length, 1);
  assert.equal(result.record.arm_id, "arm-model-zai-glm53flash");
  const argv = invocations[0].podmanArgv;
  assert.ok(argv.includes("/opt/veritas/corpus/s2-008-campaign/preregistration.v18.in-force.json"));
  assert.equal(argv[argv.indexOf("--min-start-interval-ms") + 1], "60000");
  assert.deepEqual(argv.slice(argv.indexOf("--remaining-tokens"), argv.indexOf("--remaining-tokens") + 2),
    ["--remaining-tokens", "4999999"]);
  assert.ok(argv.includes("--dry-run"));
  assert.equal(paidCalls, 0);
});

test("v18 runtime rejects a bad pin, mismatched credential, and mutated predecessor before side effects", async () => {
  let dryCalls = 0;
  let paidCalls = 0;
  const wrongPin = { ...v18RuntimePin,
    first: { ...v18RuntimePin.first, content_commitment: "sha256:" + "0".repeat(64) } };
  await assert.rejects(adapter.runModelTrial({
    armId: "arm-model-zai-glm53flash", seed: 20260926, timeoutMs: 30540000,
    dryRun: true, pin: wrongPin, prereg: v18RuntimePrereg, inspect: v18RuntimeInspect,
    executeDry: async () => { dryCalls += 1; return { exitCode: 0, stdout: "" }; },
  }), /MODEL_CONTENT_COMMITMENT_MISMATCH/);
  await assert.rejects(adapter.runModelTrial({
    armId: "arm-model-zai-glm53flash", seed: 20260926, timeoutMs: 30540000,
    dryRun: false, pin: v18RuntimePin, prereg: v18RuntimePrereg, remainingTokens: 4999999,
    inspect: v18RuntimeInspect, processEnv: { OPENROUTER_API_KEY: "synthetic-wrong-fingerprint" },
    executePaid: async () => { paidCalls += 1; return {}; },
  }), /V18_CREDENTIAL_METADATA_INVALID/);

  const tampered = structuredClone(v18RuntimePrereg);
  tampered.v17_prior_execution_reconciliation.known_tokens_lower_bound += 1;
  assert.throws(() => adapter.assertPinnedModelImage({
    pin: v18RuntimePin, prereg: tampered, inspect: v18RuntimeInspect,
  }), /MODEL_V18_PRIOR_RECONCILIATION_BINDING_MISMATCH/);
  assert.equal(dryCalls, 0);
  assert.equal(paidCalls, 0);
});
