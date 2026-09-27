// S2-007 MANDATORY NEGATIVE-PROBE GATE (issue #7 §5, §6; frozen module spec §3.7, §4).
//
// WHAT THIS SCRIPT IS
// ------------------
// The runner for `test:s2-007-security-probes`. It does NOT contain probe
// logic: the six mandatory families live in `src/lib/agentboard/probes.mjs` as
// reusable functions that attack the PRODUCTION-FACING boundary
// (`commands.execute` / `http.handleRequest`). Duplicating them here would
// create a second, weaker copy of the adversarial suite — exactly the
// "two independently editable payload forms" failure the ticket forbids — and a
// copy could keep passing after the real boundary was rewired. This file owns
// exactly three things: WHICH store the probes run against, WHAT the record
// says, and WHAT the process exit code means.
//
// WHY A REAL POSTGRESQL BY DEFAULT
// The `concurrent_claim` family contains two probes that cannot be faked on
// the in-memory twin: `two_process_claim_race` (two OS processes must race for
// one lease — two awaited calls in one heap are cooperative, not concurrent)
// and `stale_fence_after_restart` (a fence has to survive a process restart,
// which means it has to live in the database, not in a heap that died with the
// process). Without a database both report NOT_RUN_DB, the concurrency family
// is unproven, and a "green" run would be a run that skipped the only probes
// that can catch a double lease. So the gate provisions a DISPOSABLE
// PostgreSQL container by itself, applies the ordered migrations through the
// same `applyMigrations` the deployment uses, and tears the container down
// afterwards. An operator-supplied `DATABASE_URL` / `--database` wins over the
// disposable one; `--no-podman` refuses to provision anything and reports the
// two database probes as NOT_RUN_DB, honestly.
//
// EXIT CODE CONTRACT (the aggregator depends on these exact values)
//   0  every probe ran and every hard-gate counter is 0            -> PASS
//   1  a probe failed, or at least one hard-gate counter is > 0   -> BLOCKED_SAFETY
//   3  every counter is 0 but a mandatory probe did not run         -> NOT_RUN
// A counter finding is NEVER exit 0 (spec §4: any non-zero counter is REVISE or
// BLOCKED_SAFETY even when the overall test count is green), and a skip is never
// exit 0 either: an unproven defence and a proven defence are different states,
// and collapsing them is how a fake green gets written.
//
// DETERMINISM
// No wall clock anywhere in the record. The probe module injects its own fixed
// clock and id factories, so the per-probe verdicts and the counters are
// reproducible. The run id is the digest of (commit, tree, per-probe status
// projection) — a content address, not a timestamp, so two runs of the same
// tree produce the same id and a changed tree cannot reuse the old one.
//
// SECRETS
// The disposable container's password is generated here and never written to
// disk, to stdout or to the record. The record carries a redacted connection
// string (user@host:port/db, no password) plus the image digest that was
// actually run, so the evidence names the engine without naming a credential.
//
//   node scripts/s2-007-security-probes.mjs --write     # bind evidence/
//   node scripts/s2-007-security-probes.mjs --database postgresql://...
//   node scripts/s2-007-security-probes.mjs --no-podman  # offline, NOT_RUN_DB
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { applyMigrations } from './apply-migrations.mjs';
import { freePort, waitForPostgres, POSTGRES_IMAGE } from './verify-postgres-smoke.mjs';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import {
  HARD_GATE_COUNTERS, PROBE_FAMILIES, PROBES_VERSION, purgeProbeFixtures, runAllProbes,
} from '../src/lib/agentboard/probes.mjs';
import { Pool } from 'pg';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT_RELATIVE = 'evidence/s2-007-security-probes.json';
// The S2-006 portable-container convention, reused instead of re-derived: the
// Windows host reaches its podman through WSL, the Linux host calls podman
// directly. A second, subtly different recipe would be one more thing to keep
// in sync for no gain.
const WSL_DISTRO = 'Ubuntu-24.04';
const CONTAINER = 'veritas-s2-007-security-probes';
const DB_USER = 'veritas_s2_007_probes';
const DB_NAME = 'veritas_s2_007_probes';

export const EXIT_PASS = 0;
export const EXIT_SAFETY = 1;
export const EXIT_NOT_RUN = 3;
// The seven hard-gate counters, re-exported unchanged from the probe module.
// The gate, the aggregator and the tests all read THIS binding: a second list
// written anywhere would be a gate that quietly stops counting something.
export const HEAD_GATE_COUNTERS = HARD_GATE_COUNTERS;

function parseArgs(argv) {
  const args = { write: false, podman: true, database: null, out: null, printRecord: false };
  for (let i = 2; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--write') args.write = true;
    else if (token === '--print-record') args.printRecord = true;
    else if (token === '--no-podman') args.podman = false;
    else if (token === '--database') args.database = argv[i + 1] ?? null;
    else if (token === '--out') args.out = argv[i + 1] ?? null;
  }
  return args;
}

/** The commit AND the tree this evidence was produced against. */
export function headIdentity(cwd = ROOT) {
  const one = (argv) => {
    try {
      return execFileSync('git', argv, { cwd, encoding: 'utf8' }).trim();
    } catch {
      return 'unavailable';
    }
  };
  return { commit: one(['rev-parse', 'HEAD']), tree: one(['rev-parse', 'HEAD^{tree}']) };
}

/**
 * The connection string with the password removed. The record has to name the
 * engine it ran on; it must never carry a credential (rule 7).
 */
export function redactConnectionString(connectionString) {
  if (typeof connectionString !== 'string' || connectionString === '') return null;
  try {
    const url = new URL(connectionString);
    const user = url.username ? `${url.username}@` : '';
    return `postgresql://${user}${url.hostname}:${url.port || '5432'}/${url.pathname.replace(/^\//, '')} (password redacted)`;
  } catch {
    return 'unparseable (redacted)';
  }
}

function podmanCommand(argv) {
  if (process.platform === 'win32') return { command: 'wsl.exe', args: ['-d', WSL_DISTRO, '--', 'podman', ...argv] };
  return { command: 'podman', args: argv };
}

function podman(argv, { timeout = 60000, allowed = [0] } = {}) {
  const { command, args } = podmanCommand(argv);
  const result = spawnSync(command, args, { encoding: 'utf8', timeout, maxBuffer: 1 << 24, windowsHide: true });
  if (result.error) return { ok: false, exitCode: null, stdout: '', stderr: String(result.error.message ?? result.error), error: result.error };
  const exitCode = typeof result.status === 'number' ? result.status : null;
  return {
    ok: allowed.includes(exitCode),
    exitCode,
    stdout: String(result.stdout ?? '').trim(),
    stderr: String(result.stderr ?? '').trim(),
  };
}

function podmanAvailable() {
  return podman(['--version'], { timeout: 15000 }).ok;
}

function imagePresentLocally() {
  return podman(['image', 'inspect', POSTGRES_IMAGE, '--format', '{{.Digest}}'], { timeout: 30000 }).ok;
}

function removeContainer() {
  // Best effort, and deliberately quiet: a failed teardown must not turn a
  // completed gate into a different verdict. The container is disposable and
  // namespaced, and the next run removes it again before it starts one.
  podman(['rm', '--force', '--time', '0', CONTAINER], { timeout: 30000, allowed: [0, 1, 125] });
}

/**
 * Resolve the store the probes attack.
 *
 * Resolution order (first hit wins): an explicit `--database`, then
 * `S2_007_DATABASE_URL`, then `DATABASE_URL`, then a disposable container.
 * Every branch returns the SAME shape so the record cannot accidentally claim a
 * database tier it did not run on.
 */
export async function resolveDatabase({ explicit = null, podmanAllowed = true, env = process.env } = {}) {
  const external = explicit ?? env.S2_007_DATABASE_URL ?? env.DATABASE_URL ?? null;
  if (typeof external === 'string' && external !== '') {
    const migrations = await applyMigrations({ connectionString: external, root: ROOT });
    // The fixtures are purged before the run, and the purge is REPORTED.
    //
    // The probe ids are deterministic on purpose — the record is a content
    // address, and the same tree must yield the same ids and digests — and
    // several of them are PRIMARY KEYs. That makes the suite re-runnable only
    // if the previous run's fixtures are gone, and a second run against the
    // same database used to measure the leftovers: the race probe found a task
    // already CLAIMED with an ACTIVE lease, read its own refused claim as a
    // duplicate lease, and reported `duplicateActiveLeases=1` and
    // `staleFenceMutations=1` for a run in which nothing was violated. The
    // purge is bounded to this module's own workspaces and adapter prefix, so
    // an operator's rows are never touched.
    const pool = new Pool({ connectionString: external, max: 2 });
    let purge;
    try {
      purge = await purgeProbeFixtures(pool);
    } finally {
      await pool.end().catch(() => {});
    }
    return {
      connectionString: external,
      tier: 'external',
      external: true,
      engine: 'PostgreSQL',
      image: null,
      container: null,
      migrationsApplied: migrations.applied.length,
      migrationCount: migrations.migrations.length,
      fixturesPurged: purge,
      note: `the operator-supplied database was migrated with the ordered migration set, then the probe suite's OWN fixtures were purged before the run (${Object.entries(purge.rows).filter(([, n]) => n > 0).map(([table, n]) => `${table}=${n}`).join(', ') || 'nothing to remove'}). Ids stay deterministic so the record remains a content address; only rows inside the probe's own workspaces and adapter prefix are ever deleted.`,
      cleanup: () => {},
    };
  }
  if (!podmanAllowed) {
    return {
      connectionString: null,
      tier: 'in_memory',
      external: false,
      reason: 'NO_DATABASE_URL: container provisioning disabled (--no-podman); the two database-backed concurrency probes report NOT_RUN_DB',
      cleanup: () => {},
    };
  }
  if (!podmanAvailable()) {
    return {
      connectionString: null,
      tier: 'in_memory',
      external: false,
      reason: `NO_PODMAN: ${podmanCommand(['--version']).command} is not usable on this host`,
      cleanup: () => {},
    };
  }
  if (!imagePresentLocally()) {
    return {
      connectionString: null,
      tier: 'in_memory',
      external: false,
      reason: `NO_LOCAL_IMAGE: the pinned PostgreSQL image ${POSTGRES_IMAGE} is not present locally and this gate never pulls`,
      cleanup: () => {},
    };
  }
  removeContainer();
  const port = await freePort();
  const secret = randomBytes(24).toString('hex');
  const started = podman([
    'run', '--detach', `--name=${CONTAINER}`, '--pull=never',
    '--publish', `127.0.0.1:${port}:5432`,
    // The same hardening the other disposable-PostgreSQL gates use: read-only
    // root, no capabilities, no privilege escalation, a pid limit, a hard
    // memory ceiling, and tmpfs for the only writable paths.
    '--read-only', '--user=70:70', '--cap-drop', 'all',
    '--security-opt', 'no-new-privileges', '--pids-limit=64', '--memory=256m',
    '--memory-swap=256m', '--cpus=1',
    '--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=192m,mode=1777',
    '--tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=4m,mode=1777',
    '--env', 'PGDATA=/var/lib/postgresql/data/pgdata',
    '--env', `POSTGRES_USER=${DB_USER}`, '--env', `POSTGRES_PASSWORD=${secret}`, '--env', `POSTGRES_DB=${DB_NAME}`,
    POSTGRES_IMAGE,
  ], { timeout: 120000 });
  if (!started.ok) {
    return {
      connectionString: null,
      tier: 'in_memory',
      external: false,
      reason: `CONTAINER_NOT_STARTED: exit=${started.exitCode} ${started.stderr.slice(0, 300)}`,
      cleanup: () => removeContainer(),
    };
  }
  const url = new URL(`postgresql://127.0.0.1:${port}/${DB_NAME}`);
  url.username = DB_USER;
  url.password = secret;
  const connectionString = url.toString();
  try {
    await waitForPostgres(connectionString);
    const migrations = await applyMigrations({ connectionString, root: ROOT });
    return {
      connectionString,
      tier: 'podman_disposable',
      external: false,
      engine: 'PostgreSQL',
      image: POSTGRES_IMAGE,
      container: CONTAINER,
      migrationsApplied: migrations.applied.length,
      migrationCount: migrations.migrations.length,
      note: 'a disposable hardened container was provisioned for this gate, migrated through scripts/apply-migrations.mjs, and removed afterwards',
      cleanup: () => removeContainer(),
    };
  } catch (error) {
    return {
      connectionString: null,
      tier: 'in_memory',
      external: false,
      reason: `POSTGRES_NOT_USABLE: ${String(error?.message ?? error).slice(0, 300)}`,
      cleanup: () => removeContainer(),
    };
  }
}

/** The compact, comparable projection of a probe run. Two runs that agree here agree on every verdict. */
function probeProjection(report) {
  return report.probes.map((row) => [row.family, row.probe, row.status, row.counter]);
}

/**
 * Decide the gate status and the process exit code.
 *
 * Exported so the aggregator's unit test can drive the same mapping instead of
 * restating it: a counter finding outranks a skip, and both outrank a pass.
 */
export function decideGateOutcome({ counters, probeRows, hardGateOk }) {
  const findings = HARD_GATE_COUNTERS.filter((counter) => Number(counters?.[counter] ?? 0) > 0);
  const failed = probeRows.filter((row) => row.status === 'failed');
  const notRun = probeRows.filter((row) => row.status === 'not_run');
  if (findings.length > 0 || failed.length > 0 || hardGateOk !== true) {
    return {
      status: 'BLOCKED_SAFETY',
      ok: false,
      exitCode: EXIT_SAFETY,
      reasons: [
        ...findings.map((counter) => `hard-gate counter non-zero: ${counter}=${counters[counter]}`),
        ...failed.map((row) => `probe failed (attempted violation was not blocked): ${row.family}/${row.probe}`),
        ...(hardGateOk !== true ? ['hardGates.ok is not true'] : []),
      ],
    };
  }
  if (notRun.length > 0) {
    return {
      status: 'NOT_RUN',
      ok: false,
      exitCode: EXIT_NOT_RUN,
      reasons: notRun.map((row) => `mandatory probe not run: ${row.family}/${row.probe} (${row.omit?.code ?? 'NOT_RUN'})`),
    };
  }
  return { status: 'PASS', ok: true, exitCode: EXIT_PASS, reasons: [] };
}

export async function runSecurityProbes(args = {}) {
  const options = {
    write: args.write === true,
    podman: args.podman !== false,
    database: args.database ?? null,
    out: args.out ?? null,
  };
  const database = await resolveDatabase({ explicit: options.database, podmanAllowed: options.podman });
  let report;
  try {
    report = await runAllProbes(database.connectionString ? { database: { connectionString: database.connectionString } } : {});
  } finally {
    database.cleanup?.();
  }

  const outcome = decideGateOutcome({ counters: report.counters, probeRows: report.probes, hardGateOk: report.hardGates.ok });
  const identity = headIdentity();
  const familiesAttempted = PROBE_FAMILIES.map((family) => {
    const row = report.families[family] ?? {};
    return {
      family,
      total: row.total ?? 0,
      passed: row.passed ?? 0,
      failed: row.failed ?? 0,
      notRun: row.notRun ?? 0,
      counters: row.counters ?? null,
      status: (row.failed ?? 0) > 0 ? 'FAILED' : (row.notRun ?? 0) > 0 ? 'PARTIAL_NOT_RUN' : 'PASS',
    };
  });

  const record = {
    schemaVersion: 1,
    ticket: 'S2-007',
    issue: 'SpaceDazher/Veritas#7',
    role: 'mandatory negative-probe gate: the six adversarial families of issue #7 §5, run against the production-facing command/HTTP boundary',
    gate: 'test:s2-007-security-probes',
    probeModule: 'src/lib/agentboard/probes.mjs',
    version: PROBES_VERSION,
    commit: identity.commit,
    tree: identity.tree,
    status: outcome.status,
    ok: outcome.ok,
    exitCode: outcome.exitCode,
    reasons: outcome.reasons,
    // The seven counters of spec §4, spelled out here so a reader never has to
    // infer them from the probe list.
    counters: Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, Number(report.counters?.[counter] ?? 0)])),
    hardGates: {
      ok: report.hardGates.ok === true && outcome.ok,
      counters: report.hardGates.counters,
      notRun: report.hardGates.notRun,
    },
    totals: report.totals,
    familiesAttempted,
    // Per-probe pass/fail, the compact projection. The full check-level
    // evidence follows in `probeEvidence`.
    probes: report.probes.map((row) => ({
      probe: row.probe, family: row.family, status: row.status, passed: row.passed === true, counter: row.counter, detail: row.detail,
    })),
    omits: report.omits,
    registry: report.registry,
    database: {
      tier: database.tier,
      external: database.external === true,
      engine: database.engine ?? 'in-memory twin (no database)',
      image: database.image ?? null,
      container: database.container ?? null,
      migrationsApplied: database.migrationsApplied ?? 0,
      migrationCount: database.migrationCount ?? 0,
      connection: redactConnectionString(database.connectionString),
      reason: database.reason ?? null,
      note: database.note ?? null,
      // What the pre-run purge removed, by table. A re-runnable tier has to be
      // able to SAY it cleaned up: an operator reading a green record has to
      // be able to tell a fresh measurement from one that inherited rows.
      fixturesPurged: database.fixturesPurged ?? null,
    },
    probeEvidence: report.evidence,
    honestStatus: {
      realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
      assuranceStatus: 'NOT_MEASURED',
      aMvpStatus: 'NOT_CLAIMED',
      note: 'a probe suite that attacks the boundary proves the boundary refuses. It does not prove an executor, a reviewer or a semantic accuracy exists.',
    },
    limits: [
      'No real AgentOS/Codex/pi adapter ran: the execution boundary is modelled by the veritas.adapter/1.0.0 test transport (NOT_RUN_REAL_ADAPTER).',
      'A green probe run is evidence about REFUSALS, not about task quality, human review or calibration.',
      database.connectionString === null
        ? 'The two database-backed concurrency probes were not run on this host; the concurrency family is therefore NOT_RUN_DB and the gate is not green.'
        : 'The database tier is a disposable container with a fixture task set; it is not a production persistence, backup or restore validation.',
    ],
  };
  // A content address, not a timestamp: same tree + same verdicts => same id.
  record.runId = `s2-007-probes-${canonicalDigest({
    commit: record.commit, tree: record.tree, projection: probeProjection(report), counters: record.counters,
  }).slice(0, 24)}`;
  record.recordDigest = canonicalDigest({ ...record, recordDigest: undefined });

  const outPath = options.out
    ? path.resolve(ROOT, options.out)
    : path.join(ROOT, OUT_RELATIVE);
  if (options.write) {
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, `${JSON.stringify(record, null, 2)}\n`);
  }
  const bytes = options.write ? fs.readFileSync(outPath) : Buffer.from('');
  return {
    record,
    outPath,
    exitCode: record.exitCode,
    evidence: {
      written: options.write,
      evidenceFile: path.relative(ROOT, outPath).split(path.sep).join('/'),
      evidenceSha256: options.write ? createHash('sha256').update(bytes).digest('hex') : null,
      recordDigest: record.recordDigest,
      commit: record.commit,
      tree: record.tree,
    },
  };
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1]).split(path.sep).join('/')}`).href;
if (isMain) {
  const args = parseArgs(process.argv);
  let result;
  try {
    result = await runSecurityProbes(args);
  } catch (error) {
    // An untyped throw out of the gate is a gate failure, never a green run.
    process.stderr.write(`${JSON.stringify({
      ticket: 'S2-007',
      gate: 'test:s2-007-security-probes',
      status: 'BLOCKED_SAFETY',
      ok: false,
      exitCode: EXIT_SAFETY,
      reasons: [`gate:untyped-failure:${String(error?.message ?? error).slice(0, 400)}`],
    }, null, 2)}\n`);
    process.exit(EXIT_SAFETY);
  }
  const envelope = {
    ticket: 'S2-007',
    gate: 'test:s2-007-security-probes',
    status: result.record.status,
    ok: result.record.ok,
    exitCode: result.exitCode,
    counters: result.record.counters,
    hardGatesOk: result.record.hardGates.ok,
    totals: result.record.totals,
    familiesAttempted: result.record.familiesAttempted.map((row) => `${row.family}:${row.status}`),
    omits: result.record.omits,
    databaseTier: result.record.database.tier,
    runId: result.record.runId,
    reasons: result.record.reasons,
    ...result.evidence,
  };
  if (args.printRecord) process.stdout.write(`${JSON.stringify(result.record, null, 2)}\n`);
  else process.stdout.write(`${JSON.stringify(envelope, null, 2)}\n`);
  process.exit(result.exitCode);
}
