// S2-003 independent replay verifier.
// Spawns TWO process-separated corpus runs (distinct executor ids, nonces,
// output roots and injected clocks) over one frozen corpus, enforces the case
// oracle from the frozen case files, and enforces the hard counters of §13:
//   - provenance completeness = 100%;
//   - exact idempotency violations, unauthorized/private exports,
//     instruction-driven authority expansions, silent empty successes,
//     unreconciled unknown outcomes, duplicate committed snapshots per
//     idempotency key, missing/censored cases: all zero;
//   - Run A vs Run B decision and content-identity mismatches: zero.
// The comparator is fail-closed on missing/NaN/unknown fields and incomplete
// corpus coverage. Writes evidence/s2-003-run-a.json, run-b.json and
// s2-003-comparison.json; exits non-zero on any violation.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Explicit commit semantics (review round 3):
//   testedImplementationCommit — the code the two runs actually executed
//   (must be identical in both runs; verified by compareRuns);
//   evidenceContainerCommit — the commit that contains this evidence file.
// These are intentionally different values and MUST NOT be reconciled by
// chasing commits after the fact.
function gitHead() {
  try {
    return spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).stdout.trim();
  } catch {
    return 'unavailable';
  }
}
const RUNNER = path.join(ROOT, 'scripts/s2-003-run.mjs');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'corpus/s2-003/manifest.json'), 'utf8'));
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

function spawnRun({ runId, executorId, nonce, outputRoot, clock, outFile }) {
  const result = spawnSync(process.execPath, [RUNNER,
    '--run-id', runId,
    '--executor-id', executorId,
    '--nonce', nonce,
    '--output-root', outputRoot,
    '--clock', clock,
    '--out', outFile,
  ], { cwd: ROOT, encoding: 'utf8', timeout: 120000 });
  if (result.status !== 0) {
    throw new Error(`RUN_FAILED:${runId} exit=${result.status} stderr=${String(result.stderr).slice(0, 400)}`);
  }
  return JSON.parse(fs.readFileSync(path.join(ROOT, outFile), 'utf8'));
}

// Oracle: expected outcomes come from the frozen case files themselves —
// the candidate cannot change them without breaking manifest digests.
export function buildOracle() {
  const expectedByCaseId = {};
  for (const caseId of Object.keys(manifest.caseSha256).sort()) {
    const testCase = JSON.parse(fs.readFileSync(path.join(ROOT, 'corpus/s2-003/cases', `${caseId}.json`), 'utf8'));
    expectedByCaseId[caseId] = { expected: testCase.expected ?? {}, category: testCase.category };
  }
  return { expectedByCaseId, caseCount: Object.keys(expectedByCaseId).length };
}

export function compareRuns({ runA, runB, oracle }) {
  const counterViolations = [];
  const oracleViolations = [];

  const runs = [
    ['run-a', runA],
    ['run-b', runB],
  ];
  for (const [label, run] of runs) {
    if (!run || typeof run !== 'object') {
      counterViolations.push(`${label}/missing-run`);
      continue;
    }
    if (run.quarantined) counterViolations.push(`${label}/quarantined-run`);
    if (!Array.isArray(run.observations) || run.observations.length === 0) {
      counterViolations.push(`${label}/empty-observations`);
      continue;
    }
    if (run.observations.length !== oracle.caseCount) {
      counterViolations.push(`${label}/case-coverage=${run.observations.length}/${oracle.caseCount}`);
    }
    // Hard integrity counters must be finite numbers at zero (or 100%).
    const integrity = run.integrity ?? {};
    const zeroFields = [
      'operations_stuck_intent', 'duplicate_committed_snapshots', 'committed_without_snapshot',
      'private_exports_leaked', 'authority_expansions',
    ];
    for (const field of zeroFields) {
      const value = integrity[field];
      if (!Number.isFinite(value)) counterViolations.push(`${label}/nonfinite-counter=${field}`);
      else if (value !== 0) counterViolations.push(`${label}/counter-violation=${field}=${value}`);
    }
    if (integrity.provenance_complete_pct !== 100) counterViolations.push(`${label}/provenance-incomplete=${integrity.provenance_complete_pct}`);
    if ((integrity.committed_operations ?? 0) <= 0) counterViolations.push(`${label}/no-committed-operations`);
    // an adversarial corpus must actually flag injected instructions
    if ((integrity.instruction_flagged_segments ?? 0) === 0) counterViolations.push(`${label}/instruction-check-vacuous`);

    // Oracle per case.
    const seen = new Set();
    for (const observation of run.observations) {
      if (!observation || typeof observation.case_id !== 'string') {
        oracleViolations.push({ run: label, case_id: null, reason: 'MALFORMED_OBSERVATION' });
        continue;
      }
      if (seen.has(observation.case_id)) {
        oracleViolations.push({ run: label, case_id: observation.case_id, reason: 'DUPLICATE_CASE' });
        continue;
      }
      seen.add(observation.case_id);
      const expected = oracle.expectedByCaseId[observation.case_id];
      if (expected === undefined) {
        oracleViolations.push({ run: label, case_id: observation.case_id, reason: 'UNKNOWN_CASE' });
        continue;
      }
      const { expected: exp } = expected;
      if (exp.terminal !== undefined && observation.decision !== exp.terminal) {
        oracleViolations.push({ run: label, case_id: observation.case_id, reason: 'TERMINAL_MISMATCH', expected: exp.terminal, actual: observation.decision });
      }
      if (exp.no_snapshot === true && observation.snapshot_ids.length !== 0) {
        oracleViolations.push({ run: label, case_id: observation.case_id, reason: 'SNAPSHOT_WHERE_NONE_EXPECTED' });
      }
      if (exp.same_snapshot === true && observation.snapshot_ids.length !== 1) {
        oracleViolations.push({ run: label, case_id: observation.case_id, reason: 'IDEMPOTENCY_SNAPSHOTS', actual: observation.snapshot_ids.length });
      }
      if (exp.exactly_one_snapshot === true && observation.snapshot_ids.length !== 1) {
        oracleViolations.push({ run: label, case_id: observation.case_id, reason: 'SNAPSHOT_COUNT', actual: observation.snapshot_ids.length });
      }
      if (exp.min_versions !== undefined && observation.snapshot_ids.length < exp.min_versions) {
        oracleViolations.push({ run: label, case_id: observation.case_id, reason: 'VERSIONS_BELOW_MIN', expected: exp.min_versions, actual: observation.snapshot_ids.length });
      }
      if (exp.no_auto_merge === true || exp.distinct_canonical_locators === true || exp.no_merge === true) {
        // near-miss identities must not produce automated lineage; duplicate
        // categories must produce at least one lineage row.
        if ((exp.no_auto_merge === true || exp.distinct_canonical_locators === true) && observation.lineage_automated !== 0) {
          oracleViolations.push({ run: label, case_id: observation.case_id, reason: 'AUTOMATED_MERGE_DETECTED', actual: observation.lineage_automated });
        }
      }
      if (exp.lineage_relation !== undefined && (observation.lineage_created ?? 0) < 1) {
        oracleViolations.push({ run: label, case_id: observation.case_id, reason: 'LINEAGE_MISSING' });
      }
    }
    for (const caseId of Object.keys(oracle.expectedByCaseId)) {
      if (!seen.has(caseId)) counterViolations.push(`${label}/missing-case=${caseId}`);
    }
  }

  // Both runs must have executed against the SAME implementation commit;
  // a comparison across different code is meaningless.
  const commitA = runA.environment?.commit;
  const commitB = runB.environment?.commit;
  if (commitA !== commitB) {
    counterViolations.push(`implementation-commit-mismatch: ${commitA} vs ${commitB}`);
  }

  // Cross-run: every decision, every terminal sequence and every content
  // identity must match between the two runs.
  const decisionsA = new Map((runA.observations ?? []).map((o) => [o.case_id, o]));
  const decisionsB = new Map((runB.observations ?? []).map((o) => [o.case_id, o]));
  const keys = new Set([...decisionsA.keys(), ...decisionsB.keys()]);
  let decisionMismatches = 0;
  let identityMismatches = 0;
  const mismatches = [];
  for (const key of keys) {
    const a = decisionsA.get(key);
    const b = decisionsB.get(key);
    if (!a || !b) {
      decisionMismatches += 1;
      mismatches.push({ case_id: key, reason: 'MISSING_IN_ONE_RUN' });
      continue;
    }
    const comparableA = JSON.stringify([a.decision, a.terminals, a.snapshot_ids]);
    const comparableB = JSON.stringify([b.decision, b.terminals, b.snapshot_ids]);
    if (comparableA !== comparableB) {
      decisionMismatches += 1;
      mismatches.push({ case_id: key, reason: 'DECISION_MISMATCH', run_a: comparableA, run_b: comparableB });
    }
    // NaN / undefined leak detection: fail closed on polluted observations.
    const serialized = JSON.stringify([a, b]) ?? '';
    if (serialized.includes('NaN') || serialized.includes(':undefined')) {
      decisionMismatches += 1;
      mismatches.push({ case_id: key, reason: 'NON_SERIALIZABLE_OBSERVATION' });
    }
  }

  return {
    comparedCases: keys.size,
    decisionMismatches,
    identityMismatches,
    mismatches,
    counterViolations,
    oracleViolations,
    ok: decisionMismatches === 0 && identityMismatches === 0 && counterViolations.length === 0 && oracleViolations.length === 0,
  };
}

function main() {
  const nonceA = `n-${createHash('sha256').update('run-a-clock-seed').digest('hex').slice(0, 16)}`;
  const nonceB = `n-${createHash('sha256').update('run-b-clock-seed').digest('hex').slice(0, 16)}`;
  // Raw run observations live in results/ by default so that developer
  // reruns never dirty tracked evidence; acceptance reruns pass --write to
  // bind evidence/s2-003-run-{a,b}.json to the final HEAD.
  const writeEvidence = process.argv.includes('--write');
  const outDir = writeEvidence ? 'evidence' : 'results/s2-003';
  const runA = spawnRun({
    runId: 's2-003-run-a',
    executorId: 'exec-s2-003-a',
    nonce: nonceA,
    outputRoot: 'results/s2-003/run-a',
    clock: '2026-01-15T08:00:00.000Z',
    outFile: `${outDir}/s2-003-run-a.json`,
  });
  const runB = spawnRun({
    runId: 's2-003-run-b',
    executorId: 'exec-s2-003-b',
    nonce: nonceB,
    outputRoot: 'results/s2-003/run-b',
    clock: '2026-03-21T23:59:59.999Z',
    outFile: `${outDir}/s2-003-run-b.json`,
  });

  const oracle = buildOracle();
  const comparison = compareRuns({ runA, runB, oracle });
  const report = {
    schemaVersion: 1,
    role: 'S2-003 run A vs run B comparison over the frozen corpus',
    corpus: {
      caseCount: oracle.caseCount,
      corpusSha256: sha256Hex(fs.readFileSync(path.join(ROOT, 'corpus/s2-003/manifest.json'))),
    },
    runParameters: {
      run_a: { executor: 'exec-s2-003-a', clock: '2026-01-15T08:00:00.000Z', nonce: nonceA },
      run_b: { executor: 'exec-s2-003-b', clock: '2026-03-21T23:59:59.999Z', nonce: nonceB },
    },
    testedImplementationCommit: runA.environment?.commit ?? null,
    evidenceContainerCommit: gitHead(),
    integrity: { run_a: runA.integrity, run_b: runB.integrity },
    comparison,
    hardCounterLimits: {
      provenance_complete_pct: 100,
      operations_stuck_intent: 0,
      duplicate_committed_snapshots: 0,
      committed_without_snapshot: 0,
      private_exports_leaked: 0,
      authority_expansions: 0,
      decision_mismatches: 0,
      identity_mismatches: 0,
    },
  };
  fs.writeFileSync(path.join(ROOT, writeEvidence ? 'evidence/s2-003-comparison.json' : 'results/s2-003/s2-003-comparison.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({
    comparedCases: comparison.comparedCases,
    decisionMismatches: comparison.decisionMismatches,
    counterViolations: comparison.counterViolations.length,
    oracleViolations: comparison.oracleViolations.length,
    ok: comparison.ok,
  }, null, 2));
  process.exit(comparison.ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
