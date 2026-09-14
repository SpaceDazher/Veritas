import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PostgresIngestionStore } from '../../src/lib/ingestion/postgres-store.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function transactionalPool({ failEvent = false } = {}) {
  const queries = [];
  const client = {
    async query(sql) {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      queries.push(normalized);
      if (failEvent && normalized.startsWith('INSERT INTO ingestion_event')) {
        throw new Error('event insert failed');
      }
      if (normalized.startsWith('INSERT INTO ingestion_operation')) {
        return { rows: [{ status: 'INTENT', outcome: null }], rowCount: 1 };
      }
      if (normalized.startsWith('UPDATE ingestion_operation')) {
        return { rows: [], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
    release() { queries.push('RELEASE'); },
  };
  return {
    queries,
    client,
    pool: {
      async connect() { queries.push('CONNECT'); return client; },
      async query() { throw new Error('DIRECT_POOL_QUERY_FORBIDDEN'); },
    },
  };
}

describe('S2-003 transactional PostgreSQL audit', () => {
  test('beginOperation commits INTENT and OPERATION_INTENT on one client transaction', async () => {
    const fixture = transactionalPool();
    const store = new PostgresIngestionStore(fixture.pool);
    const result = await store.beginOperation('ws-audit', 'op-intent', 'a'.repeat(64));

    assert.equal(result.replay, false);
    assert.deepEqual(fixture.queries.slice(0, 2), ['CONNECT', 'BEGIN']);
    assert.match(fixture.queries[2], /^INSERT INTO ingestion_operation/);
    assert.match(fixture.queries[3], /^INSERT INTO ingestion_event/);
    assert.deepEqual(fixture.queries.slice(-2), ['COMMIT', 'RELEASE']);
  });

  test('beginOperation rolls back the ledger row when the audit insert fails', async () => {
    const fixture = transactionalPool({ failEvent: true });
    const store = new PostgresIngestionStore(fixture.pool);
    await assert.rejects(
      store.beginOperation('ws-audit', 'op-failed-intent', 'b'.repeat(64)),
      /event insert failed/,
    );
    assert.deepEqual(fixture.queries.slice(-2), ['ROLLBACK', 'RELEASE']);
    assert.equal(store.events.length, 0, 'uncommitted event leaked into the mirror');
  });

  test('completeOperation commits terminal transition and OPERATION_COMPLETED atomically', async () => {
    const fixture = transactionalPool();
    const store = new PostgresIngestionStore(fixture.pool);
    const outcome = { terminal: 'FAILED', error_code: 'TEST_FAILURE', snapshot_id: null };
    const result = await store.completeOperation('ws-audit', 'op-terminal', outcome);

    assert.equal(result.status, 'FAILED');
    assert.equal(fixture.queries[0], 'CONNECT');
    assert.equal(fixture.queries[1], 'BEGIN');
    assert.match(fixture.queries[2], /^UPDATE ingestion_operation/);
    assert.match(fixture.queries[3], /^INSERT INTO ingestion_event/);
    assert.deepEqual(fixture.queries.slice(-2), ['COMMIT', 'RELEASE']);
    assert.deepEqual(store.events.map((event) => event.type), ['OPERATION_COMPLETED']);
  });
});

describe('S2-003 evidence provenance semantics', () => {
  test('generated evidence never embeds a pre-commit HEAD as evidenceContainerCommit', () => {
    for (const relative of [
      'scripts/verify-s2-003.mjs',
      'scripts/s2-003-db-replay.mjs',
      'scripts/verify-clean-checkout.mjs',
    ]) {
      const source = fs.readFileSync(path.join(ROOT, relative), 'utf8');
      assert.doesNotMatch(source, /evidenceContainerCommit\s*:/, relative);
      assert.match(source, /evidenceContainerResolution\s*:/, relative);
    }
  });

  test('tracked run-comparison evidence omits the impossible self-reference', () => {
    for (const relative of [
      'evidence/s2-003-comparison.json',
      'evidence/s2-003-db-comparison.json',
      'evidence/clean-checkout.json',
    ]) {
      const record = JSON.parse(fs.readFileSync(path.join(ROOT, relative), 'utf8'));
      assert.equal(Object.hasOwn(record, 'evidenceContainerCommit'), false, relative);
      assert.match(record.evidenceContainerResolution, /git log -1 --/);
    }
  });
});
