import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import pg from 'pg';
import { applyMigrations } from './apply-migrations.mjs';

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const POSTGRES_IMAGE = 'docker.io/library/postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73';
const DISTRO = 'Ubuntu-24.04';
const CONTAINER = 'veritas-postgres-smoke';

export function wsl(argv, { expected = 0, timeout = 30000 } = {}) {
  const result = spawnSync('wsl.exe', ['-d', DISTRO, '--', ...argv], {
    encoding: 'utf8', shell: false, timeout, windowsHide: true, maxBuffer: 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== expected) throw new Error(`POSTGRES_COMMAND_FAILED:${String(result.stderr).trim()}`);
  return String(result.stdout ?? '').trim();
}

function cleanupContainer() {
  return spawnSync('wsl.exe', [
    '-d', DISTRO, '--', 'podman', 'rm', '--force', '--time', '0', CONTAINER,
  ], { encoding: 'utf8', shell: false, timeout: 10000, windowsHide: true });
}

export async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

export async function waitForPostgres(connectionString) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1000 });
    try {
      await pool.query('SELECT 1');
      await pool.end();
      return;
    } catch {
      await pool.end().catch(() => {});
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error('POSTGRES_NOT_READY');
}

export function verifyPostgresSmokeRecord(record) {
  const issues = [];
  if (record?.schemaVersion !== 1 || record?.status !== 'PASS' || record?.exitCode !== 0) issues.push('terminal');
  if (record?.image !== POSTGRES_IMAGE || record?.databaseEngine !== 'PostgreSQL') issues.push('binding');
  if (!/^PostgreSQL 17\./.test(record?.serverVersion ?? '')) issues.push('version');
  if (record?.migrationCount < 2 || record?.tableCount !== 3) issues.push('schema');
  if (record?.transactionCommitted !== true || record?.duplicateOperationRejected !== true) issues.push('transaction');
  if (record?.taskCount !== 1 || record?.eventCount !== 1 || record?.cleanupVerified !== true) issues.push('observations');
  if (record?.credentialsPersisted !== false || record?.hostPortExposedBeyondLoopback !== false) issues.push('secretsOrNetwork');
  if (record?.migrationCount >= 2) {
    // S2-003: the ingestion migration must be present, digest-bound and prove
    // the INTENT->terminal ledger transition, append-only enforcement and
    // per-workspace operation idempotency.
    const ingestion = record?.migrationDigests?.find((m) => m.name === '0002_source_ingestion.sql');
    if (!ingestion || !/^[0-9a-f]{64}$/.test(ingestion.sha256 ?? '')) issues.push('ingestionMigration');
    if (record?.ingestionAppendOnlyRejected !== true) issues.push('ingestionAppendOnly');
    if (record?.ingestionTransitionEnforced !== true) issues.push('ingestionTransition');
    if (record?.ingestionDuplicateOperationRejected !== true) issues.push('ingestionIdempotency');
    if (record?.ingestionTableCount !== 8) issues.push('ingestionTables');
  }
  return { ok: issues.length === 0, issues };
}

export async function runPostgresSmoke({ writeEvidence = true } = {}) {
  const port = await freePort();
  const secret = randomBytes(24).toString('hex');
  const user = 'veritas_smoke';
  const database = 'veritas_smoke';
  const connectionUrl = new URL(`postgresql://127.0.0.1:${port}/${database}`);
  connectionUrl.username = user;
  connectionUrl.password = secret;
  const connectionString = connectionUrl.toString();
  cleanupContainer();
  let cleanupVerified = false;
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
    try {
      await waitForPostgres(connectionString);
    } catch (error) {
      const logs = wsl(['podman', 'logs', '--tail', '40', CONTAINER]);
      const state = wsl(['podman', 'inspect', CONTAINER, '--format', '{{json .State}}']);
      throw new Error(`${error.message}: state=${state}; logs=${logs.slice(-2000)}`);
    }
    const migration = await applyMigrations({ connectionString, root: ROOT });
    const pool = new Pool({ connectionString, max: 2 });
    let duplicateOperationRejected = false;
    try {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          'INSERT INTO veritas_demo_tasks(id,title,description,status,criteria) VALUES ($1,$2,$3,$4,$5::jsonb)',
          ['smoke-task-1', 'PostgreSQL smoke', 'transactional workspace proof', 'READY', JSON.stringify(['db'])],
        );
        await client.query(
          'INSERT INTO veritas_demo_events(task_id,action,detail,revision,operation_id,request_hash) VALUES ($1,$2,$3,$4,$5,$6)',
          ['smoke-task-1', 'CREATE', 'created in smoke transaction', 1, 'smoke-op-1', 'sha256:smoke'],
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      try {
        await pool.query(
          'INSERT INTO veritas_demo_events(task_id,action,detail,revision,operation_id) VALUES ($1,$2,$3,$4,$5)',
          ['smoke-task-1', 'REPLAY', 'must fail', 1, 'smoke-op-1'],
        );
      } catch (error) {
        duplicateOperationRejected = error?.code === '23505';
      }
      // S2-003 ingestion smoke: descriptor -> snapshot -> idempotency ledger,
      // then append-only enforcement and duplicate-operation rejection.
      let ingestionAppendOnlyRejected = false;
      let ingestionTransitionEnforced = false;
      let ingestionDuplicateOperationRejected = false;
      let ingestionTableCount = 0;
      {
        const ing = await pool.query(`SELECT
          (SELECT count(*)::int FROM information_schema.tables WHERE table_schema='public'
            AND table_name IN ('source_descriptor','source_snapshot','content_segment','source_lineage',
              'ingestion_run','ingestion_event','source_proposal','ingestion_operation')) AS tables`);
        ingestionTableCount = ing.rows[0].tables;
        await pool.query(
          `INSERT INTO source_descriptor(source_id, connector_id, source_kind, canonical_locator, owner,
             workspace_id, tenant_id, classification, license, retention, lifecycle, registered_at, registered_by)
           VALUES ('src-smoke-1','conn-manual-export','manual_export','manual:smoke/1','prn-smoke',
             'ws-smoke','ws-smoke','{"visibility":"public"}','{"spdx":"CC-BY-4.0","attribution_required":true}',
             '{"policy":"keep_forever"}','{"state":"enabled"}', now(), 'prn-smoke')`,
        );
        await pool.query(
          `INSERT INTO source_snapshot(snapshot_id, source_id, connector_id, source_kind, version, snapshot_kind,
             canonical_locator, canonicalization_version, raw_sha256, normalized_sha256, observed_at, fetched_at,
             size_bytes, extraction_status, acl, license, retention, fetch_provenance)
           VALUES ('snp-smoke0000000001','src-smoke-1','conn-manual-export','manual_export',1,'content',
             'manual:smoke/1','1.0.0', repeat('a',64), repeat('b',64), now(), now(),
             10,'COMPLETE','{"visibility":"public","workspace_id":"ws-smoke","tenant_id":"ws-smoke"}',
             '{"spdx":"CC-BY-4.0","attribution_required":true}','{"policy":"keep_forever"}',
             '{"operation_id":"op-smoke-1","connector_id":"conn-manual-export","connector_version":"1.0.0","fetched_from":"smoke","fetched_at":"2026-01-01T00:00:00.000Z","content_type_validated":true}')`,
        );
        // The ledger lifecycle: insert as INTENT, transition once to a
        // terminal status; the server-side trigger rejects any further change.
        await pool.query(
          "INSERT INTO ingestion_operation(workspace_id, operation_id, request_hash) VALUES ('ws-smoke','op-smoke-1', repeat('a',64))",
        );
        await pool.query(
          "UPDATE ingestion_operation SET status = 'COMMITTED', outcome = '{\"terminal\":\"COMMITTED\"}'::jsonb WHERE workspace_id = 'ws-smoke' AND operation_id = 'op-smoke-1'",
        );
        try {
          await pool.query(
            "UPDATE ingestion_operation SET status = 'FAILED' WHERE workspace_id = 'ws-smoke' AND operation_id = 'op-smoke-1'",
          );
        } catch (error) {
          ingestionTransitionEnforced = /OPERATION_ALREADY_TERMINAL/.test(String(error?.message ?? ''));
        }
        try {
          await pool.query("UPDATE source_snapshot SET size_bytes = 99 WHERE snapshot_id = 'snp-smoke0000000001'");
        } catch (error) {
          ingestionAppendOnlyRejected = String(error?.message ?? '').includes('APPEND_ONLY_VIOLATION');
        }
        try {
          await pool.query(
            "INSERT INTO ingestion_operation(workspace_id, operation_id, request_hash) VALUES ('ws-smoke','op-smoke-1', repeat('b',64))",
          );
        } catch (error) {
          ingestionDuplicateOperationRejected = error?.code === '23505';
        }
      }
      const counts = await pool.query(`SELECT
        (SELECT count(*)::int FROM veritas_demo_tasks) AS tasks,
        (SELECT count(*)::int FROM veritas_demo_events) AS events,
        (SELECT count(*)::int FROM information_schema.tables WHERE table_schema='public'
          AND table_name IN ('veritas_schema_migrations','veritas_demo_tasks','veritas_demo_events')) AS tables`);
      const server = await pool.query('SELECT version() AS version');
      const report = {
        schemaVersion: 1, status: 'PASS', exitCode: 0,
        databaseEngine: 'PostgreSQL', image: POSTGRES_IMAGE, serverVersion: server.rows[0].version,
        migrationCount: migration.migrations.length, migrationDigests: migration.migrations,
        tableCount: counts.rows[0].tables, taskCount: counts.rows[0].tasks, eventCount: counts.rows[0].events,
        transactionCommitted: true, duplicateOperationRejected,
        ingestionAppendOnlyRejected, ingestionTransitionEnforced, ingestionDuplicateOperationRejected, ingestionTableCount,
        credentialsPersisted: false, hostPortExposedBeyondLoopback: false,
        cleanupVerified: false,
        scope: 'Ephemeral loopback-only PostgreSQL workspace smoke; tmpfs data and random runtime credentials',
      };
      await pool.end();
      wsl(['podman', 'rm', '--force', '--time', '0', CONTAINER]);
      cleanupVerified = wsl(['podman', 'container', 'exists', CONTAINER], { expected: 1 }) === '';
      report.cleanupVerified = cleanupVerified;
      const verification = verifyPostgresSmokeRecord(report);
      if (!verification.ok) throw new Error(`POSTGRES_SMOKE_INVALID:${verification.issues.join(',')}`);
      if (writeEvidence) fs.writeFileSync(path.join(ROOT, 'evidence/postgres-smoke.json'), `${JSON.stringify(report, null, 2)}\n`);
      return report;
    } finally {
      await pool.end().catch(() => {});
    }
  } finally {
    if (!cleanupVerified) {
      spawnSync('wsl.exe', ['-d', DISTRO, '--', 'podman', 'rm', '--force', '--time', '0', CONTAINER], {
        encoding: 'utf8', shell: false, timeout: 10000, windowsHide: true,
      });
    }
  }
}

async function main() {
  const result = await runPostgresSmoke({ writeEvidence: process.argv.includes('--write') });
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => { console.error(error.message); process.exit(1); });
}
