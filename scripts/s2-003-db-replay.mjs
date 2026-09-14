// S2-003 DB-backed independent replay.
// Provisions an ephemeral loopback-only PostgreSQL container (same pinned
// image and hardening flags as the smoke test), applies the ingestion
// migrations to TWO separate schemas, and executes Run A and Run B against
// PostgreSQL-backed stores (real SQL idempotency ledger with the enforced
// INTENT -> terminal transition). The comparator is the same fail-closed
// one used for the in-memory runs; evidence lands in
// evidence/s2-003-db-comparison.json.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { applyMigrations } from './apply-migrations.mjs';
import { POSTGRES_IMAGE, wsl, freePort, waitForPostgres } from './verify-postgres-smoke.mjs';
import { runCorpus, DEFAULT_CLOCK } from './s2-003-run.mjs';
import { buildOracle, compareRuns } from './verify-s2-003.mjs';
import { PostgresIngestionStore } from '../src/lib/ingestion/postgres-store.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DISTRO = 'Ubuntu-24.04';
const CONTAINER = 'veritas-s2-003-db-replay';

function cleanupContainer() {
  try {
    return wsl(['podman', 'rm', '--force', '--time', '0', CONTAINER], { expected: null, timeout: 20000 });
  } catch {
    return ''; // container may not exist; the finally-block removes it anyway
  }
}

async function main() {
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

    // One database, two isolated schemas: Run A and Run B never share a row.
    const runs = [];
    const migrations = [];
    for (const schema of ['run_a', 'run_b']) {
      const bootstrap = new pg.Pool({ connectionString, max: 1 });
      await bootstrap.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
      await bootstrap.end();
      const schemaPool = new pg.Pool({ connectionString, max: 2, options: `-c search_path=${schema}` });
      const migration = await applyMigrations({ connectionString, root: ROOT, pool: schemaPool });
      migrations.push({ schema, migrations: migration.migrations });
      const store = new PostgresIngestionStore(schemaPool);
      runs.push({ schema, pool: schemaPool, store, migration });
    }

    const oracle = buildOracle();
    const clockByRun = [
      { runId: 's2-003-db-run-a', executorId: 'exec-db-a', nonce: 'n-dbareplay000001', outputRoot: 'results/s2-003/db-run-a', clock: '2026-01-15T08:00:00.000Z' },
      { runId: 's2-003-db-run-b', executorId: 'exec-db-b', nonce: 'n-dbbreplay000001', outputRoot: 'results/s2-003/db-run-b', clock: '2026-03-21T23:59:59.999Z' },
    ];
    const summaries = [];
    for (let i = 0; i < 2; i += 1) {
      const params = clockByRun[i];
      const result = await runCorpus({ ...params, store: runs[i].store });
      summaries.push(result);
      await runs[i].store.appendRun({
        contractVersion: '1.0.0', run_id: result.run_id, executor_id: result.executor_id,
        pid: result.pid, nonce: result.nonce, output_root: result.output_root,
        frozen_inputs: result.frozen_inputs, environment: result.environment,
        counts: result.counts, started_at: params.clock, finished_at: null,
      });
    }

    const comparison = compareRuns({ runA: summaries[0], runB: summaries[1], oracle });
    const report = {
      schemaVersion: 1,
      role: 'S2-003 DB-backed run A vs run B comparison (PostgreSQL ingestion stores)',
      databaseEngine: 'PostgreSQL',
      image: POSTGRES_IMAGE,
      schemas: migrations,
      integrity: { run_a: summaries[0].integrity, run_b: summaries[1].integrity },
      counts: { run_a: summaries[0].counts, run_b: summaries[1].counts },
      comparison,
    };
    fs.writeFileSync(path.join(ROOT, 'evidence/s2-003-db-comparison.json'), `${JSON.stringify(report, null, 2)}\n`);
    console.log(JSON.stringify({
      comparedCases: comparison.comparedCases,
      decisionMismatches: comparison.decisionMismatches,
      counterViolations: comparison.counterViolations.length,
      oracleViolations: comparison.oracleViolations.length,
      ok: comparison.ok,
    }, null, 2));
    process.exit(comparison.ok ? 0 : 1);
  } finally {
    spawnSync('wsl.exe', ['-d', DISTRO, '--', 'podman', 'rm', '--force', '--time', '0', CONTAINER], {
      encoding: 'utf8', shell: false, timeout: 20000, windowsHide: true,
    });
  }
}

main().catch((error) => { console.error(error.stack || error.message); process.exit(1); });
