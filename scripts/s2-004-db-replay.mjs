// S2-004 DB-backed independent replay.
// Coordinator process: provisions an ephemeral loopback-only PostgreSQL
// container (same pinned image and hardening flags as the smoke test), applies
// the migrations to TWO separate schemas, then spawns each corpus run as its
// OWN child process (distinct PID, executor id, nonce and clock — §13 requires
// process separation) against a PostgreSQL-backed claim graph store. The
// coordinator never runs corpus logic itself.
//
//   node scripts/s2-004-db-replay.mjs            # compare, write results/
//   node scripts/s2-004-db-replay.mjs --write    # bind evidence/ artifacts
//
// Child mode (internal): --child --schema ... --run-id ... --executor-id ...
// --nonce ... --clock ... --out <file> — executes one run against its schema
// and writes the run summary JSON.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { applyMigrations } from './apply-migrations.mjs';
import { POSTGRES_IMAGE, wsl, freePort, waitForPostgres } from './verify-postgres-smoke.mjs';
import { runCorpus, DEFAULT_CLOCK } from './s2-004-run.mjs';
import { PostgresClaimGraphStore } from '../src/lib/claims/postgres-store.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DISTRO = 'Ubuntu-24.04';
const CONTAINER = 'veritas-s2-004-db-replay';

function cleanupContainer() {
  try {
    return wsl(['podman', 'rm', '--force', '--time', '0', CONTAINER], { expected: null, timeout: 20000 });
  } catch {
    return '';
  }
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) { args[argv[i].slice(2)] = 'true'; }
      else { args[argv[i].slice(2)] = next; i += 1; }
    } else {
      args._.push(argv[i]);
    }
  }
  return args;
}

// Child process: one corpus run against one PostgreSQL schema.
async function runChild({ schema, runId, executorId, nonce, clock, out, databaseUrl }) {
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 2, options: `-c search_path=${schema}` });
  const authorities = (await import('../src/lib/claims/store.mjs')).makeAuthorityRegistry([
    { principal: 'prn-producer', roles: ['producer'], workspaces: ['ws-corpus'] },
    { principal: 'prn-extractor', roles: ['extractor'], workspaces: ['ws-corpus'] },
    { principal: 'prn-reviewer', roles: ['reviewer'], workspaces: ['ws-corpus'] },
    { principal: 'prn-admin', roles: ['admin'], workspaces: ['ws-corpus', 'ws-system'] },
    { principal: 'prn-evaluator', roles: ['evaluator'] },
    { principal: 'prn-system', roles: ['system'], workspaces: ['ws-system'] },
    { principal: 'prn-user-1', roles: [], workspaces: ['ws-corpus'] },
    { principal: 'prn-user-2', roles: [], workspaces: ['ws-corpus'] },
  ]);
  const store = new PostgresClaimGraphStore(pool, { authorities, clock: () => clock });
  const result = await runCorpus({
    runId, executorId, nonce, outputRoot: `results/s2-004/db-${runId}`, clock, pg: true,
  }, { store, authorities });
  fs.writeFileSync(out, `${JSON.stringify({ ...result, dbPid: process.pid }, null, 2)}\n`);
  await pool.end();
  process.exit(result.status === 'COMPLETED' ? 0 : 2);
}

async function coordinator(args) {
  const port = await freePort();
  const secret = randomBytes(24).toString('hex');
  const user = 'veritas_db_replay';
  const database = 'veritas_db_replay';
  const connectionUrl = new URL(`postgresql://127.0.0.1:${port}/${database}`);
  connectionUrl.username = user;
  connectionUrl.password = secret;
  const connectionString = connectionUrl.toString();
  cleanupContainer();
  try {
    wsl([
      'podman', 'run', '--detach', `--name=${CONTAINER}`, '--pull=never',
      '--publish', `127.0.0.1:${port}:5432`, '--read-only', '--user=70:70', '--cap-drop', 'all',
      '--security-opt', 'no-new-privileges', '--pids-limit=64', '--memory=256m',
      '--memory-swap=256m', '--cpus=1',
      '--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=192m,mode=1777',
      '--tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=4m,mode=1777',
      '--env', 'PGDATA=/var/lib/postgresql/data/pgdata',
      '--env', `POSTGRES_USER=${user}`, '--env', `POSTGRES_PASSWORD=${secret}`, '--env', `POSTGRES_DB=${database}`,
      POSTGRES_IMAGE,
    ], { timeout: 60000 });
    await waitForPostgres(connectionString);

    const migrations = [];
    for (const schema of ['run_a', 'run_b']) {
      const bootstrap = new pg.Pool({ connectionString, max: 1 });
      await bootstrap.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
      await bootstrap.end();
      const schemaPool = new pg.Pool({ connectionString, max: 1, options: `-c search_path=${schema}` });
      const migration = await applyMigrations({ connectionString, root: ROOT, pool: schemaPool });
      migrations.push({ schema, migrations: migration.migrations });
      await schemaPool.end();
    }

    const writeEvidence = args.write === 'true' || args.write === '';
    const outDir = writeEvidence ? 'evidence' : 'results/s2-004';
    fs.mkdirSync(path.join(ROOT, outDir), { recursive: true });

    const runParams = [
      { schema: 'run_a', runId: 's2-004-db-run-a', executorId: 'exec-db-a', nonce: 'n-dbclaimreplay01', clock: '2026-01-15T08:00:00.000Z' },
      { schema: 'run_b', runId: 's2-004-db-run-b', executorId: 'exec-db-b', nonce: 'n-dbclaimreplay02', clock: '2026-03-21T23:59:59.999Z' },
    ];
    const summaries = [];
    for (const [i, params] of runParams.entries()) {
      const outFile = path.join(ROOT, outDir, `s2-004-db-run-${i === 0 ? 'a' : 'b'}.json`);
      const childEnv = { ...process.env, VERITAS_DB_URL: connectionString };
      const child = spawnSync(process.execPath, [
        path.join(ROOT, 'scripts/s2-004-db-replay.mjs'),
        '--child', '--schema', params.schema, '--run-id', params.runId,
        '--executor-id', params.executorId, '--nonce', params.nonce,
        '--clock', params.clock, '--out', outFile,
      ], { cwd: ROOT, encoding: 'utf8', timeout: 600000, env: childEnv });
      if (child.status !== 0 && child.status !== 2) {
        throw new Error(`DB_RUN_FAILED:${params.runId} exit=${child.status} stderr=${String(child.stderr).slice(0, 600)}`);
      }
      summaries.push(JSON.parse(fs.readFileSync(outFile, 'utf8')));
    }

    const [a, b] = summaries;
    const issues = [];
    if (a.status !== 'COMPLETED' || b.status !== 'COMPLETED') issues.push('run:not-completed');
    if (a.caseCount !== 96 || b.caseCount !== 96) issues.push('comparison:case-count-not-96');
    if (a.graphDigest !== b.graphDigest) issues.push('comparison:graph-digest-mismatch');
    if (a.executor_id === b.executor_id) issues.push('identity:executor-identical');
    if (a.clock === b.clock) issues.push('identity:clock-identical');
    if (a.dbPid === b.dbPid) issues.push('identity:pid-identical');
    const bById = new Map((b.decisions ?? []).map((d) => [d.case_id, d]));
    for (const da of a.decisions ?? []) {
      const db = bById.get(da.case_id);
      if (!db || db.decision !== da.decision) issues.push(`comparison:${da.case_id}:decision-mismatch`);
    }

    const report = {
      schemaVersion: 1,
      role: 'S2-004 DB-backed run A vs run B comparison (PostgreSQL claim graph stores, separate OS processes)',
      databaseEngine: 'PostgreSQL',
      image: POSTGRES_IMAGE,
      schemas: migrations,
      pids: { run_a: a.dbPid, run_b: b.dbPid },
      executors: { run_a: a.executor_id, run_b: b.executor_id },
      testedImplementationCommit: a.testedImplementationCommit,
      evidenceContainerResolution: 'Resolve externally with: git log -1 --format=%H -- evidence/s2-004-db-comparison.json',
      integrity: { run_a: a.integrity, run_b: b.integrity },
      decisionCounts: { run_a: a.decisionCounts, run_b: b.decisionCounts },
      graphDigests: { run_a: a.graphDigest, run_b: b.graphDigest },
      comparison: {
        ok: issues.length === 0,
        issues,
        comparedCases: (a.decisions ?? []).length,
        decisionMismatches: issues.filter((i) => i.endsWith(':decision-mismatch')).length,
      },
    };
    const comparisonPath = writeEvidence ? 'evidence/s2-004-db-comparison.json' : 'results/s2-004/s2-004-db-comparison.json';
    fs.writeFileSync(path.join(ROOT, comparisonPath), `${JSON.stringify(report, null, 2)}\n`);
    console.log(JSON.stringify({
      pids: report.pids,
      comparedCases: report.comparison.comparedCases,
      decisionMismatches: report.comparison.decisionMismatches,
      issues,
      ok: report.comparison.ok,
    }, null, 2));
    process.exit(report.comparison.ok ? 0 : 1);
  } finally {
    cleanupContainer();
  }
}

const args = parseArgs(process.argv);
if (args.child) {
  runChild({
    schema: args.schema,
    runId: args['run-id'],
    executorId: args['executor-id'],
    nonce: args.nonce,
    clock: args.clock ?? DEFAULT_CLOCK,
    out: args.out,
    databaseUrl: process.env.VERITAS_DB_URL,
  }).catch((error) => { console.error(error.stack || error.message); process.exit(1); });
} else {
  coordinator(args).catch((error) => { console.error(error.stack || error.message); process.exit(1); });
}
