import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import pg from 'pg';

const { Pool } = pg;
const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function discoverMigrations(root = DEFAULT_ROOT) {
  const directory = path.join(root, 'migrations');
  return fs.readdirSync(directory)
    .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/.test(name))
    .sort((a, b) => a.localeCompare(b))
    .map((name) => {
      const sql = fs.readFileSync(path.join(directory, name), 'utf8');
      return { name, sql, sha256: createHash('sha256').update(sql).digest('hex') };
    });
}

export async function applyMigrations({ connectionString, root = DEFAULT_ROOT, pool: suppliedPool } = {}) {
  if (typeof connectionString !== 'string' && !suppliedPool) throw new Error('DATABASE_URL_REQUIRED');
  const pool = suppliedPool ?? new Pool({ connectionString, max: 1, connectionTimeoutMillis: 5000 });
  const ownPool = !suppliedPool;
  const applied = [];
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS veritas_schema_migrations (
      name text PRIMARY KEY,
      sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
    for (const migration of discoverMigrations(root)) {
      const existing = await pool.query('SELECT sha256 FROM veritas_schema_migrations WHERE name = $1', [migration.name]);
      if (existing.rows.length > 0) {
        if (existing.rows[0].sha256 !== migration.sha256) throw new Error(`MIGRATION_DRIFT:${migration.name}`);
        continue;
      }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(migration.sql);
        await client.query('INSERT INTO veritas_schema_migrations(name, sha256) VALUES ($1, $2)', [migration.name, migration.sha256]);
        await client.query('COMMIT');
        applied.push(migration.name);
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    }
    return { applied, migrations: discoverMigrations(root).map(({ name, sha256 }) => ({ name, sha256 })) };
  } finally {
    if (ownPool) await pool.end();
  }
}

async function main() {
  const result = await applyMigrations({ connectionString: process.env.DATABASE_URL });
  console.log(JSON.stringify({ exitCode: 0, ...result }, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => { console.error(error.message); process.exit(1); });
}
