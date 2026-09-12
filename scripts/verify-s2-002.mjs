// S2-002 independent replay verifier.
// Spawns TWO process-separated corpus runs (distinct executor ids, nonce
// bases and output roots) over one frozen corpus, compares every trial
// decision between Run A and Run B, and enforces the hard counters:
//   - cross-tenant successes, authority expansions, filesystem/network/secret
//     escapes, survivors after cancellation, allow-after-revocation-commit,
//     missing or censored trials: all zero;
//   - revocation decision latency: >= 100 trials per run, max <= 5000 ms;
//   - Run A vs Run B decision mismatches: zero.
// Writes evidence/s2-002-run-a.json, evidence/s2-002-run-b.json and
// evidence/s2-002-comparison.json; exits non-zero on any violation.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const COUNTER_LIMITS = Object.freeze({
  cross_tenant_success: 0,
  authority_expansion: 0,
  fs_network_secret_escapes: 0,
  survivors_after_cancellation: 0,
  allow_after_revocation_commit: 0,
  missing_or_censored_trials: 0,
});

const REVOCATION_MIN_TRIALS = 100;
const REVOCATION_MAX_MS = 5000;

export function compareRuns(summaryA, summaryB, observationsA, observationsB) {
  const decisionsA = new Map(observationsA.map((o) => [o.trialId, o.decision]));
  const decisionsB = new Map(observationsB.map((o) => [o.trialId, o.decision]));
  const keys = new Set([...decisionsA.keys(), ...decisionsB.keys()]);
  let mismatchedDecisions = 0;
  const mismatches = [];
  for (const key of keys) {
    const a = decisionsA.get(key);
    const b = decisionsB.get(key);
    if (a === undefined || b === undefined) {
      mismatchedDecisions += 1;
      mismatches.push({ trialId: key, reason: 'MISSING_IN_ONE_RUN' });
      continue;
    }
    if (a !== b) {
      mismatchedDecisions += 1;
      mismatches.push({ trialId: key, runA: a, runB: b });
    }
  }
  const counterViolations = [];
  for (const [summary, label] of [[summaryA, 'run-a'], [summaryB, 'run-b']]) {
    for (const [counter, limit] of Object.entries(COUNTER_LIMITS)) {
      if ((summary.counters?.[counter] ?? Number.NaN) > limit) {
        counterViolations.push(`${label}/${counter}=${summary.counters[counter]}`);
      }
    }
    const stats = summary.revocationLatency ?? {};
    if ((stats.trials ?? 0) < REVOCATION_MIN_TRIALS) {
      counterViolations.push(`${label}/revocationTrials=${stats.trials ?? 0}`);
    }
    if ((stats.maxMs ?? Number.POSITIVE_INFINITY) > REVOCATION_MAX_MS) {
      counterViolations.push(`${label}/revocationMaxMs=${stats.maxMs}`);
    }
    if ((stats.allowAfterCommit ?? 1) !== 0) {
      counterViolations.push(`${label}/allowAfterCommit=${stats.allowAfterCommit}`);
    }
    if (summary.corpusDigest !== summaryA.corpusDigest) {
      counterViolations.push(`${label}/corpusDigestDrift`);
    }
  }
  return {
    comparedTrials: keys.size,
    mismatchedDecisions,
    mismatches,
    counterViolations,
    ok: mismatchedDecisions === 0 && counterViolations.length === 0,
  };
}

function spawnRun({ runId, executorId, nonceBase }) {
  const outputRoot = path.join(ROOT, 'results', 's2-002', runId);
  fs.rmSync(outputRoot, { recursive: true, force: true });
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'scripts', 's2-002-run.mjs'),
    '--run-id', runId,
    '--executor-id', executorId,
    '--nonce-base', nonceBase,
    '--output-root', outputRoot,
  ], { encoding: 'utf8', timeout: 300000 });
  if (result.status !== 0) {
    throw new Error(`CORPUS_RUN_PROCESS_FAILED (${runId}): exit ${result.status}: ${result.stderr?.slice(0, 2000)}`);
  }
  const observations = JSON.parse(fs.readFileSync(path.join(outputRoot, 'observations.json'), 'utf8'));
  const summary = JSON.parse(fs.readFileSync(path.join(outputRoot, 'summary.json'), 'utf8'));
  return { summary, observations };
}

function evidenceDigest(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function main() {
  const runA = spawnRun({ runId: 'run-a', executorId: 'exec-alpha', nonceBase: 'nb-alpha-7f3a' });
  const runB = spawnRun({ runId: 'run-b', executorId: 'exec-beta', nonceBase: 'nb-beta-c91d' });
  const comparison = compareRuns(runA.summary, runB.summary, runA.observations, runB.observations);

  const evidenceDir = path.join(ROOT, 'evidence');
  const files = {
    'evidence/s2-002-run-a.json': {
      schemaVersion: 1, role: 'independent replay run A', summary: runA.summary,
      observationsDigest: createHash('sha256').update(JSON.stringify(runA.observations)).digest('hex'),
    },
    'evidence/s2-002-run-b.json': {
      schemaVersion: 1, role: 'independent replay run B', summary: runB.summary,
      observationsDigest: createHash('sha256').update(JSON.stringify(runB.observations)).digest('hex'),
    },
    'evidence/s2-002-comparison.json': {
      schemaVersion: 1, role: 'run A vs run B comparison', comparison,
      hardCounterLimits: COUNTER_LIMITS,
      revocationRequirements: { minTrialsPerRun: REVOCATION_MIN_TRIALS, maxLatencyMs: REVOCATION_MAX_MS },
    },
  };
  for (const [relative, payload] of Object.entries(files)) {
    fs.writeFileSync(path.join(ROOT, relative), `${JSON.stringify(payload, null, 2)}\n`);
  }

  const integrity = Object.fromEntries(Object.keys(files).map((relative) => [relative, evidenceDigest(path.join(ROOT, relative))]));
  fs.writeFileSync(path.join(ROOT, 'evidence', 's2-002-comparison-integrity.json'), `${JSON.stringify({ schemaVersion: 1, algorithm: 'SHA-256 raw file bytes', files: integrity }, null, 2)}\n`);

  console.log(JSON.stringify({
    exitCode: comparison.ok ? 0 : 1,
    runA: { trials: runA.summary.trialCount, counters: runA.summary.counters, revocationLatency: runA.summary.revocationLatency },
    runB: { trials: runB.summary.trialCount, counters: runB.summary.counters, revocationLatency: runB.summary.revocationLatency },
    comparison: {
      comparedTrials: comparison.comparedTrials,
      mismatchedDecisions: comparison.mismatchedDecisions,
      counterViolations: comparison.counterViolations,
    },
    ok: comparison.ok,
  }, null, 2));
  process.exit(comparison.ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
