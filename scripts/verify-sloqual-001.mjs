// SLOQUAL-001 independent qualification verifier.
//
// Spawns TWO process-separated runs (distinct run id, executor id, pid,
// nonce and output root) over the same frozen SLO contract, scenario
// manifest and seeds, then applies the fail-closed comparator. It exits
// non-zero only on FAIL: PASS_WITH_LIMITS is the honest expected state of
// this ticket and is recorded as such, never promoted to PASS.
//
// Pre-registration is checked, not asserted: the frozen contract must be
// recorded in a commit that is an ancestor of the commit under test, so a
// threshold cannot be edited after the fact and still qualify.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { CONTRACT_PATH, MANIFEST_PATH } from '../src/lib/sloqual/index.mjs';
import { compareQualification } from '../src/lib/sloqual/comparator.mjs';
import { verifyFreeze, validateManifest } from '../src/lib/sloqual/contract.mjs';
import { gitText } from './git-client.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RUN_TIMEOUT_MS = 900000;

function gitAvailable(root) {
  // A clean archive may have VERITAS_SOURCE_COMMIT as a read-only fallback
  // for rev-parse, but it has no object database for log/merge-base.
  if (!fs.existsSync(path.join(root, '.git'))) return false;
  try {
    gitText(root, ['rev-parse', 'HEAD']);
    return true;
  } catch {
    return false;
  }
}

// The contract must be frozen in an ancestor commit of the implementation
// under test. Without git (clean archive) this is reported as NOT_RUN, not
// as a pass.
export function freezeProvenance(root = ROOT) {
  if (!gitAvailable(root)) {
    return {
      status: 'NOT_RUN',
      reason: 'no git metadata in this checkout; freeze provenance is resolved externally with git log -1 -- contracts/sloqual-001-slo-contract.json',
    };
  }
  const head = gitText(root, ['rev-parse', 'HEAD']);
  const freezeCommit = gitText(root, ['log', '-1', '--format=%H', '--', CONTRACT_PATH]);
  const manifestCommit = gitText(root, ['log', '-1', '--format=%H', '--', MANIFEST_PATH]);
  let frozenBeforeImplementation = false;
  try {
    gitText(root, ['merge-base', '--is-ancestor', freezeCommit, head]);
    frozenBeforeImplementation = true;
  } catch {
    frozenBeforeImplementation = false;
  }
  return {
    status: frozenBeforeImplementation ? 'VERIFIED' : 'FAILED',
    head,
    freezeCommit,
    manifestCommit,
    frozenBeforeImplementation,
    rule: 'The recorded thresholds and proofs must be committed before the commit whose implementation produced the runs.',
  };
}

function spawnRun({runId, executorId, nonce, outputRoot}) {
  const absoluteOutputRoot = path.join(ROOT, ...outputRoot.split('/'));
  fs.rmSync(absoluteOutputRoot, {recursive: true, force: true});
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'scripts', 'sloqual-run.mjs'),
    '--run-id', runId,
    '--executor-id', executorId,
    '--nonce', nonce,
    '--output-root', outputRoot,
  ], {encoding: 'utf8', timeout: RUN_TIMEOUT_MS, cwd: ROOT, maxBuffer: 30 * 1024 * 1024});
  if (result.status !== 0) {
    throw new Error(`SLOQUAL_RUN_PROCESS_FAILED (${runId}): exit ${result.status}: ${(result.stderr ?? '').slice(0, 2000)}`);
  }
  const run = JSON.parse(fs.readFileSync(path.join(absoluteOutputRoot, 'run.json'), 'utf8'));
  const observationsDigest = crypto.createHash('sha256')
    .update(fs.readFileSync(path.join(absoluteOutputRoot, 'observations.json')))
    .digest('hex');
  const environment = JSON.parse(fs.readFileSync(path.join(absoluteOutputRoot, 'environment-manifest.json'), 'utf8'));
  return {run, observationsDigest, environment};
}

function writeJson(relativePath, value) {
  fs.writeFileSync(path.join(ROOT, relativePath), `${JSON.stringify(value, null, 2)}\n`);
}

function main() {
  const contract = JSON.parse(fs.readFileSync(path.join(ROOT, CONTRACT_PATH), 'utf8'));
  const manifestBytes = fs.readFileSync(path.join(ROOT, MANIFEST_PATH));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));

  const freeze = verifyFreeze({contract, manifest, manifestBytes});
  const manifestIssues = validateManifest(manifest);
  if (!freeze.ok || manifestIssues.length > 0) {
    console.log(JSON.stringify({
      exitCode: 1,
      verdict: 'NOT_RUN',
      ok: false,
      freezeIssues: freeze.issues,
      manifestIssues,
      reason: 'The frozen contract or scenario manifest does not verify. No measurement was executed: a qualification of an unfrozen contract is not evidence.',
    }, null, 2));
    process.exit(1);
  }
  const provenance = freezeProvenance();
  if (provenance.status === 'FAILED') {
    console.log(JSON.stringify({
      exitCode: 1,
      verdict: 'NOT_RUN',
      ok: false,
      provenance,
      reason: 'The frozen contract is not recorded in an ancestor commit of HEAD. Thresholds may have been edited after the fact.',
    }, null, 2));
    process.exit(1);
  }

  const startedAt = new Date().toISOString();
  const runA = spawnRun({runId: 'sloqual-a', executorId: 'exec-alpha', nonce: 'sloqual-nonce-alpha-4d21', outputRoot: 'results/sloqual-001/sloqual-a'});
  const runB = spawnRun({runId: 'sloqual-b', executorId: 'exec-beta', nonce: 'sloqual-nonce-beta-9c07', outputRoot: 'results/sloqual-001/sloqual-b'});
  const comparison = compareQualification({
    contract,
    manifest,
    manifestBytes,
    runA: runA.run,
    runB: runB.run,
  });

  const evidence = {
    'evidence/sloqual-001-run-a.json': {
      schemaVersion: 1,
      role: 'SLOQUAL-001 independent qualification run A',
      freeze: {contractVersion: contract.version, contractSelfHash: contract.selfHash.sha256, manifestVersion: manifest.version, manifestSha256: contract.scenarioManifest.sha256},
      provenance,
      run: runA.run,
      observationsSha256: runA.observationsDigest,
      environment: runA.environment,
    },
    'evidence/sloqual-001-run-b.json': {
      schemaVersion: 1,
      role: 'SLOQUAL-001 independent qualification run B',
      freeze: {contractVersion: contract.version, contractSelfHash: contract.selfHash.sha256, manifestVersion: manifest.version, manifestSha256: contract.scenarioManifest.sha256},
      provenance,
      run: runB.run,
      observationsSha256: runB.observationsDigest,
      environment: runB.environment,
    },
    'evidence/sloqual-001-comparison.json': {
      schemaVersion: 1,
      role: 'SLOQUAL-001 run A vs run B fail-closed comparison',
      ticket: 'SLOQUAL-001',
      verdict: comparison.verdict,
      provenance,
      startedAt,
      completedAt: new Date().toISOString(),
      command: 'npm run verify:sloqual-001',
      rawObservationRoots: [runA.run.outputRoot, runB.run.outputRoot],
      ...comparison,
    },
  };
  for (const [relative, payload] of Object.entries(evidence)) writeJson(relative, payload);
  const integrity = Object.fromEntries(Object.entries(evidence).map(([relative, payload]) => [
    relative,
    crypto.createHash('sha256').update(`${JSON.stringify(payload, null, 2)}\n`).digest('hex'),
  ]));
  writeJson('evidence/sloqual-001-integrity.json', {
    schemaVersion: 1,
    algorithm: 'SHA-256 of the canonical written evidence file bytes',
    files: integrity,
    note: 'Re-derive with: node -e "const fs=require(\'fs\');const c=require(\'crypto\');for(const [p] of Object.entries(JSON.parse(fs.readFileSync(\'evidence/sloqual-001-integrity.json\')).files))console.log(p, c.createHash(\'sha256\').update(fs.readFileSync(p)).digest(\'hex\'))"',
  });

  console.log(JSON.stringify({
    exitCode: comparison.verdict === 'FAIL' ? 1 : 0,
    verdict: comparison.verdict,
    ok: comparison.ok,
    productionSloAuthorized: false,
    contractVersion: contract.version,
    contractSelfHash: contract.selfHash.sha256,
    manifestSha256: contract.scenarioManifest.sha256,
    runs: comparison.runs,
    satisfiedLimits: comparison.satisfiedLimits,
    failures: comparison.failures,
    limits: comparison.limits,
    proofStatus: comparison.proofStatus,
  }, null, 2));
  process.exit(comparison.verdict === 'FAIL' ? 1 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    console.log(JSON.stringify({exitCode: 1, verdict: 'NOT_RUN', ok: false, reason: String(error?.message ?? error)}, null, 2));
    process.exit(1);
  }
}
