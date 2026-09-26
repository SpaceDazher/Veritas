// SLOQUAL-001 single-run runner (one independent execution).
//
// Executes the complete frozen scenario manifest — every scenario x every
// seed, including the S1-008 revocation gate trials — against the real
// Veritas policy engine with an open-loop arrival model, and writes the run
// record, the raw per-request observations and the environment manifest to
// its own output root.
//
// Determinism: the engine clock is injected from the frozen manifest, the
// request plan is derived from the frozen weights and the seed, and nothing
// reads wall-clock time for decisions. Two executions of this script with
// different --run-id / --executor-id / --nonce / --output-root must produce
// identical decision sequences; latency values differ by design.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { CONTRACT_PATH, MANIFEST_PATH } from '../src/lib/sloqual/index.mjs';
import { verifyFreeze, validateManifest } from '../src/lib/sloqual/contract.mjs';
import { environmentManifest, executeRun } from '../src/lib/sloqual/measure.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function argument(name, fallback) {
  const args = process.argv.slice(2);
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] !== undefined ? args[index + 1] : fallback;
}

export function runQualificationOnce({
  runId,
  executorId,
  nonce,
  outputRoot,
  root = ROOT,
} = {}) {
  const contract = JSON.parse(fs.readFileSync(path.join(root, CONTRACT_PATH), 'utf8'));
  const manifestBytes = fs.readFileSync(path.join(root, MANIFEST_PATH));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const freeze = verifyFreeze({contract, manifest, manifestBytes});
  if (!freeze.ok) {
    throw new Error(`SLOQUAL_FREEZE_INVALID: ${JSON.stringify(freeze.issues)}`);
  }
  const manifestIssues = validateManifest(manifest);
  if (manifestIssues.length > 0) {
    throw new Error(`SLOQUAL_MANIFEST_INVALID: ${JSON.stringify(manifestIssues)}`);
  }
  const absoluteOutputRoot = path.isAbsolute(outputRoot) ? outputRoot : path.join(root, ...outputRoot.split('/'));
  fs.mkdirSync(absoluteOutputRoot, {recursive: true});
  const {runRecord, raw} = executeRun({contract, manifest, runId, executorId, nonce, outputRoot});

  const observations = raw.scenarioSeedResults.flatMap((entry) => entry.records.map((record) => ({
    scenarioId: entry.scenarioId,
    seed: entry.seed,
    index: record.index,
    kind: record.kind,
    workloadId: record.workloadId ?? null,
    decision: record.decision,
    reasonCodes: record.reasonCodes ?? [],
    latencyMs: record.latencyMs ?? null,
    latenessMs: record.latenessMs ?? null,
  })));
  fs.writeFileSync(path.join(absoluteOutputRoot, 'run.json'), `${JSON.stringify(runRecord, null, 2)}\n`);
  fs.writeFileSync(path.join(absoluteOutputRoot, 'observations.json'), `${JSON.stringify(observations)}\n`);
  fs.writeFileSync(
    path.join(absoluteOutputRoot, 'environment-manifest.json'),
    `${JSON.stringify(environmentManifest({runRecord, runId, executorId, nonce, outputRoot}), null, 2)}\n`,
  );
  fs.writeFileSync(
    path.join(absoluteOutputRoot, 'freeze-verification.json'),
    `${JSON.stringify({...freeze, manifestIssues}, null, 2)}\n`,
  );
  return {runRecord, observations, outputRoot, absoluteOutputRoot, freeze};
}

function main() {
  const runId = argument('--run-id');
  const executorId = argument('--executor-id');
  const nonce = argument('--nonce');
  const outputRoot = argument('--output-root') ?? path.join('results', 'sloqual-001', runId ?? 'run-x');
  if (!runId || !executorId || !nonce) {
    console.error('usage: node scripts/sloqual-run.mjs --run-id <id> --executor-id <id> --nonce <nonce> [--output-root <path>]');
    process.exit(2);
  }
  const {runRecord} = runQualificationOnce({runId, executorId, nonce, outputRoot});
  console.log(JSON.stringify({
    exitCode: 0,
    runId: runRecord.runId,
    executorId: runRecord.executorId,
    pid: runRecord.pid,
    nonce: runRecord.nonce,
    outputRoot: runRecord.outputRoot,
    coverage: runRecord.coverage,
    dispatchedSamples: runRecord.dispatchedSamples,
    hardCounters: runRecord.hardCounters,
    warmP95Ms: runRecord.metrics.families.steady.latency.p95,
    burstP95Ms: runRecord.metrics.families.burst.latency.p95,
    revocationMaxMs: runRecord.revocation.latency.max,
    revocationTrials: runRecord.revocation.trials,
    durationMs: runRecord.durationMs,
  }, null, 2));
  process.exit(0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    console.error(String(error?.message ?? error));
    process.exit(1);
  }
}
