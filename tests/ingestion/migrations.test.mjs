// S2-003 migration contract tests (structural, no live database required;
// the live replay is scripts/verify-postgres-smoke.mjs).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverMigrations } from '../../scripts/apply-migrations.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

describe('S2-003 ingestion migrations', () => {
  const migrations = discoverMigrations(ROOT);
  const ingestion = migrations.find((m) => m.name === '0002_source_ingestion.sql');

  test('the ingestion migration exists, is ordered and content-addressed', () => {
    assert.ok(ingestion, '0002_source_ingestion.sql missing');
    assert.deepEqual([...migrations].sort((a, b) => a.name.localeCompare(b.name)), migrations);
    for (const migration of migrations) assert.match(migration.sha256, /^[0-9a-f]{64}$/);
    const attributes = fs.readFileSync(path.join(ROOT, '.gitattributes'), 'utf8');
    assert.match(attributes, /^\*\.sql text eol=lf$/m);
  });

  test('every required table is created with append-only semantics', () => {
    const sql = ingestion.sql;
    for (const table of [
      'source_descriptor', 'source_snapshot', 'content_segment', 'source_lineage',
      'ingestion_run', 'ingestion_event', 'source_proposal', 'ingestion_operation',
    ]) {
      assert.match(sql, new RegExp(`CREATE TABLE IF NOT EXISTS ${table}\\b`, 'i'), table);
    }
    assert.match(sql, /veritas_ingestion_append_only/i);
    for (const trigger of ['source_snapshot_append_only', 'content_segment_append_only', 'source_lineage_append_only', 'ingestion_event_append_only']) {
      assert.match(sql, new RegExp(`CREATE TRIGGER ${trigger}\\b`, 'i'), trigger);
    }
  });

  test('the idempotency ledger is unique per workspace and operation', () => {
    assert.match(ingestion.sql, /PRIMARY KEY \(workspace_id, operation_id\)/i);
    assert.match(ingestion.sql, /APPEND_ONLY_VIOLATION/i);
  });

  test('snapshot versioning supports supersedes chains and unique per-locator versions', () => {
    assert.match(ingestion.sql, /supersedes_snapshot_id text REFERENCES source_snapshot/i);
    assert.match(ingestion.sql, /UNIQUE \(canonical_locator, version\)/i);
    assert.match(ingestion.sql, /snapshot_kind text NOT NULL CHECK \(snapshot_kind IN \('content', 'tombstone'\)\)/i);
  });

  test('near-duplicate lineage can never be confirmed by the schema', () => {
    assert.match(ingestion.sql, /status text NOT NULL CHECK \(status IN \('candidate', 'confirmed'\)\)/i);
    assert.match(ingestion.sql, /CHECK \(upstream_snapshot_id <> downstream_snapshot_id\)/i);
  });
});
