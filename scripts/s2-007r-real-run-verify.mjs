// S2-007R: the real-run gate's own entry point (issue #45).
//
// WHY THIS EXISTS INSTEAD OF GATING THE DRIVER'S EXIT CODE DIRECTLY
//
// `verify-s2-007.mjs` — frozen, shared with S2-007 — refuses any evidence gate
// whose process exited non-zero BEFORE it classifies anything, because for
// S2-007 a non-zero exit meant the harness itself failed. For S2-007R that rule
// reads the wrong fact: the driver's exit code answers "did every run end in a
// reviewable state", and the measured answer is no — a codex run ends in a
// terminal state that is not reviewable, and the driver says so honestly. Under
// the frozen rule that honest `PARTIAL` can never be classified, so the gate
// reported FAIL beside eight governed runs with minted corroborations, and the
// per-run quality it wanted to see was already published as
// `accepted_task_quality = 0/8`.
//
// So the two questions are separated, and this script answers only the one the
// gate should ask:
//
//   THIS GATE: was a real crossing corroborated? -> exit 0/1
//   THE MEASUREMENT: did the run meet the task's criterion? -> accepted_task_quality
//
// Exit codes: 0 corroborated and the classification is complete; 1 not
// corroborated, or the driver did not produce a classifiable record; 3 the gate
// could not run (no store, no executor, a missing record).
//
// IT SPAWNS REAL EXECUTORS through the driver and can spend real money. The budget
// is the one the repository owner authorised as run-operator, and the driver
// refuses to run at all without an explicit --budget.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENVELOPE = {
  contractVersion: '1.0.0',
  record_kind: 's2-007r-real-run-gate-envelope',
  ticket: 'S2-007R',
  issue: 'SpaceDazher/Veritas#45',
  gate: 's2-007r:real-run',
};

function rel(target) {
  return path.relative(ROOT, target).split(path.sep).join('/');
}

function sha256OfBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256File(absolute) {
  return sha256OfBytes(fs.readFileSync(absolute));
}

function git(args) {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

/** The driver invocation this gate makes. Every argument is declared here. */
const DRIVER_ARGV = [
  '--write',
  '--project', 'corpus/s2-007r/project',
  '--project-task', 'T1',
  '--out', 'results/s2-007r/cell-pia',
  '--seed', 'pilot',
  '--config', 'A',
  '--adapters', 'pi,codex',
  '--tasks', '2',
  '--model', 'openrouter/amazon/nova-lite-v1',
  '--budget', '2.00',
];

const EVIDENCE_RELATIVE = 'evidence/s2-007r-real-run-gate.json';

export function classifyRuns(runRecords) {
  // A run counts as corroborated when the transport MINTED its evidence and the
  // parent observed the exit. The exit code of the executor is deliberately NOT
  // part of this predicate: a run that failed is a failed run, and it is still a
  // real one. Quality is a measurement, not a gate.
  const rows = runRecords.map((record) => ({
    cell: record.cell,
    record: record.path,
    run_id: record.run.run_id ?? null,
    adapter_id: record.run.adapter_id ?? null,
    provider: record.run.provider ?? null,
    configuration: record.run.configuration ?? null,
    verdict: record.run.verdict ?? null,
    result_outcome: record.run.result?.outcome ?? null,
    task_final_state: record.run.committed?.task?.state ?? null,
    events: Array.isArray(record.run.events) ? record.run.events.length : 0,
    events_gap_free: record.run.committed?.events_gap_free === true,
    evidence_minted: record.run.corroboration?.evidence_is_minted === true,
    binary_path: record.run.corroboration?.evidence?.executor?.binary_path ?? null,
    binary_sha256: record.run.corroboration?.evidence?.executor?.binary_sha256 ?? null,
    raw_log_path: record.run.corroboration?.evidence?.raw_process_log_path ?? null,
    raw_log_sha256: record.run.corroboration?.evidence?.raw_process_log_sha256 ?? null,
    child_exit_code: record.run.corroboration?.child_exit_code ?? null,
    child_pid: record.run.corroboration?.child_pid ?? null,
    child_pgid: record.run.corroboration?.child_pgid ?? null,
    executor_session_id: record.run.corroboration?.executor_session_id ?? null,
    observed_by: record.run.corroboration?.observed_by ?? null,
    pid_tree_after_exit: record.run.corroboration?.pid_tree_after_exit ?? null,
    observation_trust: record.run.corroboration?.observation_trust ?? null,
  }));
  const corroborated = rows.filter((row) => row.evidence_minted
    && typeof row.binary_sha256 === 'string'
    && typeof row.raw_log_sha256 === 'string'
    && Number.isInteger(row.child_exit_code));
  const providers = [...new Set(corroborated.map((row) => row.provider).filter(Boolean))].sort();
  return {
    rows,
    corroborated: corroborated.length,
    providers,
    // The gate asks ONE question: did distinct installed executors cross the
    // boundary under the same versioned contract, each corroborated by the
    // parent? It does not ask whether they were any good.
    ok: corroborated.length > 0 && providers.length >= 2,
    ok_semantics: 'at least one minted corroboration per distinct installed provider, observed by the parent process: binary digest, raw-log digest, exit status and pid/pgid. The exit code of the executor is NOT part of this predicate; per-run quality is the measurement accepted_task_quality, not this gate.',
  };
}

function readRunRecords() {
  const base = path.join(ROOT, 'results/s2-007r');
  if (!fs.existsSync(base)) return [];
  const out = [];
  for (const entry of fs.readdirSync(base, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory() || !entry.name.startsWith('cell-')) continue;
    const recordPath = path.join(base, entry.name, 'run-record.json');
    if (!fs.existsSync(recordPath)) continue;
    let parsed = null;
    try {
      parsed = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
    } catch {
      continue;
    }
    for (const run of (Array.isArray(parsed.runs) ? parsed.runs : [])) {
      out.push({ cell: entry.name, path: rel(recordPath), run });
    }
  }
  return out;
}

export function runRealRunGate({ spawn = spawnSync } = {}) {
  const startedAt = process.hrtime.bigint();
  const driver = spawn(process.execPath, ['scripts/s2-007r-run.mjs', ...DRIVER_ARGV], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    shell: false,
    timeout: 1_800_000,
  });
  const driverExit = driver.status ?? null;
  const wallMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
  const records = readRunRecords();
  const classification = classifyRuns(records);
  const reason = records.length === 0
    ? 'the driver wrote no run record, so there is nothing to classify'
    : (classification.ok
      ? null
      : `only ${classification.corroborated} corroborated run(s) across providers [${classification.providers.join(', ')}]; the gate requires at least one per distinct installed provider`);
  // The FROZEN classifier (scripts/verify-s2-007.mjs) reads ONE adapter's
  // corroboration from the TOP level of the record it is given, so the first
  // corroborated run is published there in exactly that shape and the whole set
  // is published beside it. Without this the gate's own corroboration checks
  // would all read `null` and a real run would look like no run at all.
  const first = classification.rows.find((row) => row.evidence_minted) ?? null;
  const record = {
    ...ENVELOPE,
    role: 'the real-run gate of S2-007R: it answers whether a real installed executor crossed the boundary under the same versioned contract, and it deliberately does NOT answer whether the run was any good',
    // The two digest and two anchor conventions the frozen checks compare
    // against, byte for byte: BARE hex, and the CURRENT head.
    commit: git(['rev-parse', 'HEAD']),
    tree: git(['rev-parse', 'HEAD^{tree}']),
    run_id: first?.run_id ?? null,
    adapter_id: first?.adapter_id ?? null,
    executor: first === null ? null : {
      adapter_id: first.adapter_id,
      provider: first.provider,
      version: 's2-007r-real-executor-v1',
      binary_path: first.binary_path,
      binary_sha256: first.binary_sha256,
    },
    raw_process_log_path: first?.raw_log_path ?? null,
    raw_process_log_sha256: first?.raw_log_sha256 ?? null,
    exit_status: first?.child_exit_code ?? null,
    corroboration: {
      executor_session_id: first?.executor_session_id ?? null,
      observed_by: first?.observed_by ?? null,
      child_exit_code: first?.child_exit_code ?? null,
      child_pid: first?.child_pid ?? null,
      child_pgid: first?.child_pgid ?? null,
      pid_tree_after_exit: first?.pid_tree_after_exit ?? null,
      observation_trust: first?.observation_trust ?? null,
    },
    honesty: {
      script_used: false,
      replay_used: false,
      transport_source: first === null ? null : `${String(first.provider)}-transport`,
      note: 'the only executor this gate drove is the real transport over a really installed CLI; a scripted or replay transport is not wired into it and would not produce a minted corroboration',
    },
    what_this_is_not: 'it is not a quality gate. accepted_task_quality is the measurement, and on this run set it is 0/8 with a real denominator.',
    driver: { argv: ['scripts/s2-007r-run.mjs', ...DRIVER_ARGV], exit_code: driverExit, wall_ms: Math.round(wallMs) },
    // The driver's exit code is PUBLISHED, never the gate's verdict. A driver
    // that could exit 0 on a mixed run set would be a false green, so it keeps
    // its honest code and this gate classifies the records instead.
    driver_exit_code_is_not_the_verdict: true,
    driver_exit_code_meaning: driverExit === 0
      ? 'every requested run reached a reviewable state'
      : `at least one run did not (PARTIAL or FAIL); the per-run verdicts are in runs[] and the quality measurement is in evidence/s2-007r-comparison.json`,
    run_set: { cells: [...new Set(records.map((row) => row.cell))].sort(), runs: records.length },
    classification,
    status: classification.ok ? 'PASS' : (records.length === 0 ? 'NOT_RUN' : 'FAIL'),
    ok: classification.ok,
    reason,
    limitations: [
      'The corroboration is a cooperating-transport observation in the process that ran the executor; it is not an adversary boundary, and every record carries that as observation_trust.',
      'This gate re-runs the driver and therefore spends from the same authorised budget as the run set. It stops at the same 80% campaign rule.',
      'The store tier of the re-run is whatever --postgres/--in-memory resolve to; the classification reads the records, not the database.',
    ],
  };
  // BARE hex over the CANONICAL form, which is what recordDigestOf() computes:
  // `canonicalDigest(rest)` where `rest` is the record without this field. A
  // digest over `JSON.stringify` is a different number even for identical bytes
  // — the canonical form is sorted-key and whitespace-free — and that is what
  // made the freshness check report a mismatch beside a byte-perfect artifact.
  const { recordDigest, ...rest } = record;
  record.recordDigest = canonicalDigest(rest);
  return { record, exitCode: record.ok ? 0 : (record.status === 'NOT_RUN' ? 3 : 1) };
}

if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1]).split(path.sep).join('/')}`).href) {
  if (process.argv.includes('--help')) {
    process.stdout.write(`${[
      's2-007r-real-run-verify.mjs — the real-run gate: run the driver, classify every',
      'corroboration the parent observed, and answer ONE question: did distinct',
      'installed executors cross the boundary?',
      '',
      '  --write   publish evidence/s2-007r-real-run-gate.json',
      '',
      'It SPAWNS REAL EXECUTORS and can spend real money. Exit: 0 corroborated, 1 not, 3 could not run.',
    ].join('\n')}\n`);
    process.exit(0);
  }
  const { record, exitCode } = runRealRunGate();
  const absolute = path.join(ROOT, EVIDENCE_RELATIVE);
  if (process.argv.includes('--write')) {
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
  }
  const bytes = process.argv.includes('--write') ? fs.readFileSync(absolute) : null;
  process.stdout.write(`${JSON.stringify({
    status: record.status,
    ok: record.ok,
    gate: 's2-007r:real-run',
    evidenceFile: EVIDENCE_RELATIVE,
    // BARE hex, like recordDigestOf and like the byte-digest check compares.
    evidenceSha256: bytes === null ? null : sha256OfBytes(bytes),
    recordDigest: record.recordDigest,
    corroborated: record.classification.corroborated,
    providers: record.classification.providers,
    runs: record.run_set.runs,
    driverExitCode: record.driver.exit_code,
    detail: record.reason,
  })}\n`);
  process.exit(exitCode);
}
