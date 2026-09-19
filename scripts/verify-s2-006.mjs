// S2-006 verification aggregator (spec §14, §16).
//
// Pipeline:
//   1. dependency gate        — scripts/verify-s2-006-dependencies.mjs (Git
//                               bytes; runs only in a working repository —
//                               in an archive checkout it is recorded as
//                               NOT_RUN_ARCHIVE_DEGRADED, same convention as
//                               the S2-005 gate)
//   2. contract type drift    — scripts/generate-verifier-types.mjs (no
//                               --write: exits non-zero on drift)
//   3. verifier test suite    — npm run test:verifier (offline, node --test)
//   4. evidence run           — scripts/s2-006-run.mjs: two process-separated
//                               candidate children, sealed prediction sets,
//                               exact comparator, fixture calibration metrics,
//                               adversarial probes A–S (writes evidence/)
//   5. db replay status       — evidence/s2-006-db-comparison.json from an
//                               explicit `npm run verify:s2-006-db-replay`
//                               (or --with-db to run it first); missing
//                               evidence is an honest NOT_RUN_DB
//   6. summary + verdict      — evidence/s2-006-summary.json with the §16
//                               outcome precedence
//
// Verdict precedence: BLOCKED_DEPENDENCY > REVISE > NEEDS_INPUT. With the
// current inputs the honest ceiling is NEEDS_INPUT: thresholds have no
// method-owner HumanDecision, annotators are fixture principals (not
// independent), and the external corpus stratum does not exist. A provider
// stratum was not declared mandatory, so its absence is NOT_RUN_PROVIDER and
// does not block the ticket.
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
      gates.dbReplay = { status: 'PASS', exitCode: dbEvidence.exitCode ?? 0, source: 'evidence/s2-006-db-comparison.json from a prior verify:s2-006-db-replay run' };
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

  // ---- verdict (spec §16 outcome precedence) --------------------------------
  const verdictReasons = [];
  const offlineGreen = gates.types.status === 'IN_SYNC'
    && gates.testVerifier.status === 'PASS'
    && gates.evidenceRun.status === 'PASS';
  let verdict;
  if (gates.dependency.status !== 'PASS' && gates.dependency.status !== 'NOT_RUN_ARCHIVE_DEGRADED') {
    verdict = 'BLOCKED_DEPENDENCY';
    verdictReasons.push(`dependency gate: ${gates.dependency.status}`);
  } else if (!offlineGreen) {
    verdict = 'REVISE';
    verdictReasons.push('offline verifier gates are not green (types/tests/run)');
  } else {
    verdict = 'NEEDS_INPUT';
    verdictReasons.push('method owner has not authored numeric thresholds: contracts/s2-006-thresholds.json is NEEDS_INPUT with ownerDecisionRef null (no immutable HumanDecision)');
    verdictReasons.push('evaluator_not_independent: annotators/adjudicator are fixture principals authored by the same project; inter-annotator agreement is NOT_MEASURED');
    verdictReasons.push('external corpus stratum absent: only the 45-case fixture stratum exists, so no external-validity or global paired statistic is measured');
    if (gates.dbReplay.status === 'NOT_RUN_DB') verdictReasons.push('PostgreSQL replay unavailable: persistence stays NOT_RUN_DB + NEEDS_INPUT, never a pass');
    if (gates.dependency.status === 'NOT_RUN_ARCHIVE_DEGRADED') verdictReasons.push('archive checkout: dependency gate not executed here');
  }
  notRun.push('NOT_RUN_PROVIDER: no provider grant/model/runtime was declared mandatory for the first calibration scope; the offline deterministic implementation is fully tested without network or LLM');
  notRun.push('NOT_RUN_HUMAN_INPUTS: no real independent annotators, adjudicator or method-owner HumanDecision exists');

  const summary = {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'verification aggregator: dependency gate, contract type drift, verifier suite, offline evidence run (Run A/B + comparator + calibration + probes), DB replay status and §16 verdict',
    testedImplementationCommit: headCommit(),
    evidenceContainerResolution: 'Resolve externally with: git log -1 --format=%H -- evidence/s2-006-summary.json',
    gates,
    verdict,
    verdictReasons,
    verdictCeiling: 'NEEDS_INPUT is the honest ceiling: an unconditional PASS or PASS_WITH_LIMITS is forbidden without independent held-out calibration, authored thresholds and PostgreSQL (spec §16).',
    notRun: [...new Set(notRun)],
    measured: {
      corpus: 'corpus/s2-006 (45 fixture cases; dev 10 / calibration 12 / locked_test 23)',
      calibrationEvidence: 'evidence/s2-006-calibration.json (fixture metrics MEASURED; independence NOT_MEASURED)',
      comparisonEvidence: 'evidence/s2-006-comparison.json',
      probesEvidence: 'evidence/s2-006-security-probes.json',
      dbReplayEvidence: dbEvidence ? 'evidence/s2-006-db-comparison.json' : null,
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
