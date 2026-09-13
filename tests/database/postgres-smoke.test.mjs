import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverMigrations } from '../../scripts/apply-migrations.mjs';
import { verifyPostgresSmokeRecord } from '../../scripts/verify-postgres-smoke.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

describe('S2-002 PostgreSQL workspace smoke contract', () => {
  test('migrations are ordered, content-addressed and include task/event integrity', () => {
    const migrations = discoverMigrations(ROOT);
    assert.ok(migrations.length >= 1);
    assert.deepEqual([...migrations].sort((a, b) => a.name.localeCompare(b.name)), migrations);
    for (const migration of migrations) assert.match(migration.sha256, /^[0-9a-f]{64}$/);
    const sql = migrations.map((migration) => migration.sql).join('\n');
    assert.match(sql, /CREATE TABLE IF NOT EXISTS veritas_demo_tasks/i);
    assert.match(sql, /CREATE TABLE IF NOT EXISTS veritas_demo_events/i);
    assert.match(sql, /operation_id[^;]+UNIQUE/is);
    const verifier = fs.readFileSync(path.join(ROOT, 'scripts/verify-postgres-smoke.mjs'), 'utf8');
    assert.doesNotMatch(verifier, /postgres(?:ql)?:\/\/[^\s/:]+:[^\s@]+@/i);
  });

  test('the tracked smoke record proves a real transaction and omits credentials', () => {
    const record = JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/postgres-smoke.json'), 'utf8'));
    assert.deepEqual(verifyPostgresSmokeRecord(record), { ok: true, issues: [] });
    const serialized = JSON.stringify(record);
    assert.doesNotMatch(serialized, /postgresql:\/\//i);
    assert.doesNotMatch(serialized, /password/i);
  });
});
