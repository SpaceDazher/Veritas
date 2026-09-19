// S2-006 verification aggregator (spec §14, §16).
//
// Pipeline:
//   1. dependency gate        — scripts/verify-s2-006-dependencies.mjs (Git
//                               bytes; runs only in a working repository —
//                               in an archive checkout it is recorded as
//                               NOT_RUN_ARCHIVE_DEGRADED, same convention as
//                               the S2-005 gate). The gate canonizes the
//                               dependency base and RECORDS the owner-input
//                               state without requiring emptiness (P2-7a).
//   2. contract type drift    — scripts/generate-verifier-types.mjs (no
//                               --write: exits non-zero on drift)
//   3. verifier test suite    — npm run test:verifier (offline, node --test)
//   4. evidence run           — scripts/s2-006-run.mjs: two process-separated
//                               candidate children, sealed prediction sets,
//                               exact comparator, fixture calibration metrics,
//                               adversarial probes A–S with honest
//                               pass|failed|not_run statuses (writes evidence/)
//   5. db replay status       — evidence/s2-006-db-comparison.json from an
//                               explicit `npm run verify:s2-006-db-replay`
//                               (or --with-db to run it first); missing
//                               evidence is an honest NOT_RUN_DB
//   6. summary + verdict      — evidence/s2-006-summary.json with the §16
//                               outcome precedence, DERIVED from the actual
//                               evidence fields (P2-7b), never a constant.
//                               Probe S is green ONLY through the green
//                               crash/restart phase of the DB replay
//                               (review P2-6d).
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) args[argv[i].slice(2)] = argv[i + 1] ?? true;
  }
  return args;
}

function runNode(script, scriptArgs = [], { timeout = 900000 } = {}) {
  const result = spawnSync(process.execPath, [path.join(ROOT, script), ...scriptArgs], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout,
  });
  return {
    exitCode: result.status ?? 1,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    timedOut: Boolean(result.error && result.error.code === 'ETIMEDOUT'),
  };
}

function runNpm(args, { timeout = 900000 } = {}) {
  // Node >= 18.20 refuses to spawn .cmd shims without a shell (Windows).
  const usesShell = process.platform === 'win32' && NPM === 'npm.cmd';
  const result = spawnSync(
    usesShell ? 'cmd.exe' : NPM,
    usesShell ? ['/d', '/s', '/c', NPM, ...args] : args,
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout },
  );
  return {
    exitCode: result.status ?? 1,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    timedOut: Boolean(result.error && result.error.code === 'ETIMEDOUT'),
  };
}

function parseTapCounts(output) {
  const tests = output.match(/^# tests (\d+)/m);
  const pass = output.match(/^# pass (\d+)/m);
  const fail = output.match(/^# fail (\d+)/m);
  const skipped = output.match(/^# skipped (\d+)/m);
  return {
    tests: tests ? Number(tests[1]) : null,
    pass: pass ? Number(pass[1]) : null,
    fail: fail ? Number(fail[1]) : null,
    skipped: skipped ? Number(skipped[1]) : null,
  };
}

function readJson(relativePath) {
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), 'utf8'));
  } catch {
    return null;
  }
}

function headCommit() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unavailable';
  }
}

// ---- §16 outcome precedence, derived from actual evidence (review P2-7) -----
// Order: BLOCKED_SAFETY / BLOCKED_AUTHORITY -> BLOCKED_DEPENDENCY ->
// NEEDS_INPUT (with the CONCRETE list of missing inputs) -> HUMAN_REVIEW ->
// REVISE -> PASS_WITH_LIMITS. Non-primary observations are still appended to
// the reason list so a higher-precedence verdict never masks a defect.
export function deriveVerdict({ gates, runReport = null, calibration = null, comparison = null, probes = null, dbEvidence = null } = {}) {
  const safety = [];
  const authority = [];
  const missingInputs = [];
  const defects = [];
  const verdictReasons = [];

  // 1. safety/authority hard failures: hard counters, failed probes (an
  //    attempted violation was NOT blocked), comparator hard-gate violations
  const probesHard = probes?.hardCounters ?? {};
  const calibrationHard = calibration?.hardViolations ?? {};
  const totalHard = (probesHard.total ?? 0) + (calibrationHard.total ?? 0);
  const failedProbes = (probes?.probes ?? []).filter((p) => p.status === 'failed');
  if (totalHard > 0) {
    const leak = (probesHard.unauthorizedLeakageEvents ?? 0) + (calibrationHard.unauthorizedLeakageEvents ?? 0);
    const target = leak > 0 ? safety : authority;
    target.push(`hard violation counters are non-zero (${totalHard}): private leakage=${probesHard.unauthorizedLeakageEvents ?? 0}/${calibrationHard.unauthorizedLeakageEvents ?? 0}, locked-label access=${probesHard.lockedLabelAccessEvents ?? 0}, producer self-review=${probesHard.producerSelfReviewEvents ?? 0}, upstream mutation=${probesHard.upstreamArtifactMutationEvents ?? 0}, unauthorized side effects=${probesHard.unauthorizedSideEffectEvents ?? 0}`);
  }
  for (const p of failedProbes) {
    (['G', 'H', 'I', 'Q', 'R', 'S'].includes(p.id) ? safety : authority).push(`probe ${p.id} (${p.name}) FAILED: an attempted violation was not blocked`);
  }
  if (comparison?.hardGates?.ok === false) {
    safety.push(`comparator hard gates violated: ${(comparison.hardGates.violations ?? []).join(', ')}`);
  }

  // 2. dependency
  const depFail = gates.dependency.status !== 'PASS' && gates.dependency.status !== 'NOT_RUN_ARCHIVE_DEGRADED';

  // 3. missing owner inputs (NEEDS_INPUT), each naming what would advance it
  const decision = calibration?.decision ?? {};
  const needsInputReasons = decision.needsInputReasons ?? [];
  if (calibration === null) {
    missingInputs.push('calibration evidence unavailable: evidence/s2-006-calibration.json is missing — run npm run verify:s2-006');
  } else {
    if (needsInputReasons.includes('missing_human_decision')) {
      missingInputs.push('thresholds decision not resolved: contracts/s2-006-thresholds.json is NEEDS_INPUT — an immutable HumanDecision from authenticated owner=user bound to the exact canonical thresholds digest (verified against the authority registry) would advance it');
    }
    if (needsInputReasons.includes('missing_thresholds')) {
      missingInputs.push('numeric thresholds not authored: coverage_floor, non_inferiority_margin.delta, confidence_level, tie_rule and every thresholds.soft_thresholds value are null');
    }
    if (calibration.independence?.status === 'NOT_MEASURED' || calibration.independence?.tier === 'NOT_INDEPENDENT') {
      missingInputs.push('annotators not independent: annotators/adjudicator are fixture principals (evaluator_not_independent) — real independent annotators and a separate adjudicator would advance it');
    }
    if (calibration.externalStratum?.status === 'NEEDS_INPUT') {
      missingInputs.push('external corpus stratum absent: only the 45-case fixture stratum exists — an externally authored, independently labelled locked_test stratum would advance it');
    }
  }
  if (gates.dbReplay.status === 'NOT_RUN_DB') {
    missingInputs.push('PostgreSQL replay unavailable: a green npm run verify:s2-006-db-replay (including the crash/restart phase for probe S) would advance it');
  }
  if (gates.probes.status === 'NOT_RUN_DB') {
    missingInputs.push('probe S crash/restart half not run: the mandatory two-process PostgreSQL crash/restart phase has not produced a green crashPhase');
  }
  if (gates.dependency.status === 'NOT_RUN_ARCHIVE_DEGRADED') {
    missingInputs.push('archive checkout: the byte-level dependency gate requires a working Git repository');
  }
  // provider stratum: NOT mandatory for the first calibration scope, so its
  // absence stays NOT_RUN_PROVIDER and never blocks the ticket

  // 4. inconclusive decision rule
  const inconclusive = decision.status === 'HUMAN_REVIEW'
    ? 'the lexicographic decision rule is inconclusive (HUMAN_REVIEW, no winner)'
    : null;

  // 5. fixable non-safety defects
  if (gates.types.status !== 'IN_SYNC') defects.push(`contract type drift (${gates.types.status})`);
  if (gates.testVerifier.status !== 'PASS') defects.push(`verifier test suite failing (${gates.testVerifier.counts?.fail ?? '?'} fail)`);
  if (gates.evidenceRun.status !== 'PASS') defects.push(`offline evidence run failed (exit ${gates.evidenceRun.exitCode})`);
  if (gates.evidenceRun.status === 'PASS' && gates.evidenceRun.comparisonOk === false) defects.push('comparator reports a divergence between the sealed runs');
  if (gates.dbReplay.status === 'FAIL') defects.push('PostgreSQL replay or its crash/restart phase failed');
  if (gates.probes.status === 'FAIL') defects.push(`probes gate failed: ${JSON.stringify(gates.probes.failed ?? gates.probes.reason ?? null)}`);
  for (const v of runReport?.violations ?? []) {
    if (!defects.some((d) => d.includes(v))) defects.push(`evidence run violation: ${v}`);
  }

  const mandatoryGreen = gates.dependency.status === 'PASS'
    && gates.types.status === 'IN_SYNC'
    && gates.testVerifier.status === 'PASS'
    && gates.evidenceRun.status === 'PASS'
    && gates.probes.status === 'PASS'
    && gates.dbReplay.status === 'PASS'
    && (calibration?.independence?.tier === 'INDEPENDENTLY_CALIBRATED')
    && (calibration?.externalStratum?.status ?? 'NEEDS_INPUT') !== 'NEEDS_INPUT'
    && decision.status === 'DECIDED';

  let verdict;
  if (safety.length > 0) {
    verdict = 'BLOCKED_SAFETY';
    verdictReasons.push(...safety);
  } else if (authority.length > 0) {
    verdict = 'BLOCKED_AUTHORITY';
    verdictReasons.push(...authority);
  } else if (depFail) {
    verdict = 'BLOCKED_DEPENDENCY';
    verdictReasons.push(`dependency gate: ${gates.dependency.status} (${(gates.dependency.stderrTail ?? '').slice(-200) || 'see evidence/s2-006-dependency-binding.json'})`);
  } else if (missingInputs.length > 0) {
    verdict = 'NEEDS_INPUT';
    verdictReasons.push(...missingInputs);
  } else if (inconclusive) {
    verdict = 'HUMAN_REVIEW';
    verdictReasons.push(inconclusive);
  } else if (defects.length > 0) {
    verdict = 'REVISE';
    verdictReasons.push(...defects);
  } else if (mandatoryGreen) {
    verdict = 'PASS_WITH_LIMITS';
    verdictReasons.push('all mandatory independent held-out, security, persistence and reproducibility gates are green; explicit external-validity/model/population/production limits remain — an unconditional PASS is forbidden (spec §16)');
  } else {
    verdict = 'REVISE';
    verdictReasons.push('not all mandatory gates are green and no higher-precedence condition explains the state');
    verdictReasons.push(...defects);
  }
  // transparency: never mask lower-precedence observations
  for (const [label, list] of [['safety', safety], ['authority', authority], ['dependency', depFail ? ['dependency gate failed'] : []], ['missing-input', missingInputs], ['defect', defects]]) {
    for (const item of list) {
      if (!verdictReasons.includes(item)) verdictReasons.push(`[${verdict} context: ${label}] ${item}`);
    }
  }
  return { verdict, verdictReasons, needsInputPath: missingInputs };
}

export async function verifyS2_006(args = {}) {
  const gates = {};
  const notRun = [];

  // ---- 1. dependency gate (Git bytes; working repository only) ------------
  const archiveMode = !fs.existsSync(path.join(ROOT, '.git'));
  if (archiveMode) {
    gates.dependency = {
      status: 'NOT_RUN_ARCHIVE_DEGRADED',
      note: 'no .git in this checkout: the byte-level dependency gate runs only in the working repository (S2-005 convention)',
    };
    notRun.push('NOT_RUN_ARCHIVE_DEGRADED: dependency gate requires the Git object database');
  } else {
    const dep = runNode('scripts/verify-s2-006-dependencies.mjs');
    let parsed = null;
    try {
      parsed = JSON.parse(dep.stdout);
    } catch {
      parsed = null;
    }
    gates.dependency = {
      status: dep.exitCode === 0 ? 'PASS' : 'BLOCKED_DEPENDENCY',
      exitCode: dep.exitCode,
      checked: parsed?.checked ?? null,
      mode: parsed?.mode ?? 'unknown',
      stderrTail: dep.exitCode === 0 ? undefined : dep.stderr.slice(-800),
    };
  }

  // ---- 2. contract type drift ---------------------------------------------
  const types = runNode('scripts/generate-verifier-types.mjs');
  gates.types = {
    status: types.exitCode === 0 ? 'IN_SYNC' : 'DRIFT',
    exitCode: types.exitCode,
    detail: types.exitCode === 0 ? (types.stdout.trim().split('\n').pop() ?? null) : types.stderr.slice(-400),
  };

  // ---- 3. verifier test suite ----------------------------------------------
  const testSuite = runNpm(['run', 'test:verifier'], { timeout: 1200000 });
  gates.testVerifier = {
    status: testSuite.exitCode === 0 ? 'PASS' : 'FAIL',
    exitCode: testSuite.exitCode,
    counts: parseTapCounts(testSuite.stdout),
    stderrTail: testSuite.exitCode === 0 ? undefined : testSuite.stderr.slice(-1200),
  };

  // ---- 4. offline evidence run (Run A/B, comparator, calibration, probes) --
  const evidenceRun = runNode('scripts/s2-006-run.mjs', [], { timeout: 1200000 });
  let runReport = null;
  try {
    runReport = JSON.parse(evidenceRun.stdout);
  } catch {
    runReport = null;
  }
  gates.evidenceRun = {
    status: evidenceRun.exitCode === 0 ? 'PASS' : 'FAIL',
    exitCode: evidenceRun.exitCode,
    comparisonOk: runReport?.comparison?.ok ?? null,
    calibration: runReport?.calibration ?? null,
    probes: runReport?.probes ?? null,
    stderrTail: evidenceRun.exitCode === 0 ? undefined : evidenceRun.stderr.slice(-1200),
  };

  // ---- 5. db replay status --------------------------------------------------
  if (args['with-db'] === true) {
    const replay = runNpm(['run', 'verify:s2-006-db-replay'], { timeout: 900000 });
    gates.dbReplay = {
      status: replay.exitCode === 0 ? 'PASS' : 'FAIL',
      exitCode: replay.exitCode,
      source: 'executed in this aggregation (--with-db)',
    };
  }
  const dbEvidence = readJson('evidence/s2-006-db-comparison.json');
  if (!gates.dbReplay) {
    if (dbEvidence && dbEvidence.status === 'PASS') {
      gates.dbReplay = {
        status: 'PASS',
        exitCode: dbEvidence.exitCode ?? 0,
        source: 'evidence/s2-006-db-comparison.json from a prior verify:s2-006-db-replay run',
        crashPhaseOk: dbEvidence.crashPhase?.ok === true,
      };
    } else if (dbEvidence && dbEvidence.status === 'NOT_RUN_DB') {
      gates.dbReplay = { status: 'NOT_RUN_DB', source: 'evidence/s2-006-db-comparison.json', reason: dbEvidence.reason ?? null };
      notRun.push('NOT_RUN_DB: PostgreSQL two-process verifier store replay');
    } else if (dbEvidence) {
      gates.dbReplay = { status: 'FAIL', source: 'evidence/s2-006-db-comparison.json', issues: dbEvidence.comparison?.issues ?? null };
    } else {
      gates.dbReplay = { status: 'NOT_RUN_DB', source: null, reason: 'no DB replay evidence; run npm run verify:s2-006-db-replay' };
      notRun.push('NOT_RUN_DB: PostgreSQL two-process verifier store replay');
    }
  }

  // ---- probes gate: honest combine (review P2-6) --------------------------
  // Every probe carries an honest status pass|failed|not_run. The combined
  // gate is green only when every probe passed — probe S resolves to green
  // EXCLUSIVELY through the green crash/restart phase of the DB replay.
  const probesRecord = readJson('evidence/s2-006-security-probes.json');
  const failedProbes = (probesRecord?.probes ?? []).filter((p) => p.status === 'failed');
  const notRunProbes = (probesRecord?.probes ?? []).filter((p) => p.status === 'not_run');
  if (gates.evidenceRun.status !== 'PASS') {
    gates.probes = { status: 'NOT_RUN', reason: 'the offline evidence run did not pass; no honest probe statuses available' };
  } else if (failedProbes.length > 0 || (probesRecord?.hardCounters?.total ?? 0) > 0) {
    gates.probes = {
      status: 'FAIL',
      failed: failedProbes.map((p) => p.id),
      hardCounters: probesRecord?.hardCounters ?? null,
    };
  } else if (notRunProbes.length === 0) {
    gates.probes = { status: 'PASS', totals: probesRecord?.totals ?? null };
  } else if (gates.dbReplay.status === 'PASS' && gates.dbReplay.crashPhaseOk === true) {
    gates.probes = {
      status: 'PASS',
      totals: probesRecord?.totals ?? null,
      probeS: 'RESOLVED_BY_DB_CRASH_PHASE',
      source: 'evidence/s2-006-db-comparison.json crashPhase',
    };
  } else if (gates.dbReplay.status === 'FAIL') {
    gates.probes = { status: 'FAIL', probeS: 'DB_CRASH_PHASE_FAILED', source: 'evidence/s2-006-db-comparison.json crashPhase' };
  } else {
    gates.probes = {
      status: 'NOT_RUN_DB',
      probeS: 'NOT_RUN_DB',
      notRun: notRunProbes.map((p) => p.id),
      reason: 'probe S requires the crash/restart phase of verify:s2-006-db-replay; a not_run mandatory probe is never green',
    };
    notRun.push('NOT_RUN_DB: probe S crash/restart half (PostgreSQL two-process replay)');
  }

  // ---- verdict: DERIVED from actual evidence fields (spec §16, review P2-7)
  const calibrationEvidence = readJson('evidence/s2-006-calibration.json');
  const comparisonEvidence = readJson('evidence/s2-006-comparison.json');
  const { verdict, verdictReasons, needsInputPath } = deriveVerdict({
    gates,
    runReport,
    calibration: calibrationEvidence,
    comparison: comparisonEvidence,
    probes: probesRecord,
    dbEvidence,
  });
  notRun.push('NOT_RUN_PROVIDER: no provider grant/model/runtime was declared mandatory for the first calibration scope; the offline deterministic implementation is fully tested without network or LLM');
  notRun.push('NOT_RUN_HUMAN_INPUTS: no real independent annotators, adjudicator or method-owner HumanDecision exists');

  const summary = {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'verification aggregator: dependency gate (records owner-input state), contract type drift, verifier suite, offline evidence run (Run A/B + comparator + calibration + honest probe statuses), DB replay status with crash/restart phase and the DERIVED §16 verdict',
    testedImplementationCommit: headCommit(),
    evidenceContainerResolution: 'Resolve externally with: git log -1 --format=%H -- evidence/s2-006-summary.json',
    gates,
    verdict,
    verdictDerivation: 'spec §16 precedence computed by deriveVerdict() from the actual evidence fields — never a constant; probe S is green ONLY via the DB crash/restart phase (review P2-6/P2-7)',
    verdictReasons,
    needsInputPath,
    verdictCeiling: verdict === 'NEEDS_INPUT'
      ? 'NEEDS_INPUT is the honest verdict for the current inputs; needsInputPath lists exactly which owner actions would advance the verdict. An unconditional PASS is forbidden (spec §16).'
      : 'An unconditional PASS is forbidden (spec §16): the ceiling is PASS_WITH_LIMITS with explicitly named limits.',
    notRun: [...new Set(notRun)],
    measured: {
      corpus: 'corpus/s2-006 (45 fixture cases; dev 10 / calibration 12 / locked_test 23)',
      calibrationEvidence: 'evidence/s2-006-calibration.json (fixture metrics MEASURED; independence NOT_MEASURED)',
      comparisonEvidence: 'evidence/s2-006-comparison.json',
      probesEvidence: 'evidence/s2-006-security-probes.json',
      dbReplayEvidence: dbEvidence ? 'evidence/s2-006-db-comparison.json' : null,
      dbCrashEvidence: dbEvidence ? 'evidence/s2-006-db-crash-{a,b}.json' : null,
      dependencyBinding: 'evidence/s2-006-dependency-binding.json',
    },
    limitations: [
      'No production claim of any kind; the verifier verdict is advisory and never replaces a human decision.',
      'Fixture-annotator agreement and all quality thresholds are non-authenticated; downstream consumers must treat every numeric as indicative only.',
    ],
  };

  const exitCode = verdict === 'NEEDS_INPUT' ? 0 : 1;
  if (args.write !== 'false') {
    fs.writeFileSync(path.join(ROOT, 'evidence/s2-006-summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  }
  return { summary, exitCode };
}

const args = parseArgs(process.argv);
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, '/')}`).href) {
  const { summary, exitCode } = await verifyS2_006(args);
  console.log(JSON.stringify({
    verdict: summary.verdict,
    verdictReasons: summary.verdictReasons,
    gates: Object.fromEntries(Object.entries(summary.gates).map(([k, v]) => [k, v.status])),
    notRun: summary.notRun,
    exitCode,
  }, null, 2));
  process.exit(exitCode);
}
