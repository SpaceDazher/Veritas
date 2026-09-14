import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { applyMigrations } from './scripts/apply-migrations.mjs';
import { POSTGRES_IMAGE, wsl, freePort, waitForPostgres } from './scripts/verify-postgres-smoke.mjs';
import { PostgresIngestionStore } from './src/lib/ingestion/postgres-store.mjs';
import { IngestionPipeline } from './src/lib/ingestion/pipeline.mjs';
import { ManualExportConnector } from './src/lib/ingestion/connectors/manual-export.mjs';
import { createDecisionClock } from './src/lib/ingestion/time-model.mjs';

const CONTAINER = 'veritas-dbg16';
const NOW = '2026-01-15T08:00:00.000Z';
const port = await freePort();
const secret = randomBytes(24).toString('hex');
const csUrl = new URL(`postgresql://127.0.0.1:${port}/dbg`);
csUrl.username = 'dbg'; csUrl.password = secret;
const cs = csUrl.toString();
try { wsl(['podman','rm','--force','--time','0',CONTAINER], { expected: null, timeout: 20000 }); } catch {}
wsl(['podman','run','--detach',`--name=${CONTAINER}`,'--pull=never','--publish',`127.0.0.1:${port}:5432`,'--read-only','--user=70:70','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit=64','--memory=256m','--memory-swap=256m','--cpus=1','--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=192m,mode=1777','--tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=4m,mode=1777','--env','PGDATA=/var/lib/postgresql/data/pgdata','--env','POSTGRES_USER=dbg','--env',`POSTGRES_PASSWORD=${secret}`,'--env','POSTGRES_DB=dbg',POSTGRES_IMAGE], { timeout: 60000 });
await waitForPostgres(cs);
const pool = new pg.Pool({ connectionString: cs, max: 2 });
await applyMigrations({ connectionString: cs, root: process.cwd(), pool });
const store = new PostgresIngestionStore(pool);
const descriptor = { source_id: 'src-aclpriv', connector_id: 'conn-manual-export', source_kind: 'manual_export', canonical_locator: 'manual:export/case-fixture/acl-private', display_locator: 'acl-private', owner: 'prn-corpus-reviewer', author: null, publisher: null, workspace_id: 'ws-corpus', tenant_id: 'ws-corpus', classification: { visibility: 'private', allowed_principal_ids: ['prn-corpus-reviewer'] }, license: { spdx: 'CC-BY-4.0', attribution_required: true }, retention: { policy: 'keep_forever', retain_until: null }, lifecycle: { state: 'enabled', reason: null, changed_at: null }, registered_at: NOW, registered_by: 'prn-corpus-reviewer' };
await store.registerDescriptor(descriptor);
const pipeline = new IngestionPipeline({ store, connectors: new Map([['manual_export', new ManualExportConnector({ clock: { now: () => NOW }, exports: new Map([['case-fixture/acl-private', { bytes: Buffer.from('private canary 7f3a synthetic'), text: 'private canary 7f3a synthetic', mime_type: 'text/plain' }]]) })]]), clock: createDecisionClock(NOW), now: () => NOW });
const request = { contractVersion: '1.0.0', operation_id: 'op-acl-private', source_id: 'src-aclpriv', connector_id: 'conn-manual-export', actor: 'prn-corpus-reviewer', locator: 'case-fixture/acl-private', workspace_id: 'ws-corpus', version_selector: { latest: true }, budget: { max_bytes: 1000000, max_segments: 500, time_limit_ms: 30000 }, grant_id: null, requested_at: NOW };
const outcome = await pipeline.ingest({ request });
console.log('outcome:', JSON.stringify(outcome));
const ledger = await store.getOperation('ws-corpus', 'op-acl-private');
console.log('ledger:', JSON.stringify(ledger));
await pool.end();
try { wsl(['podman','rm','--force','--time','0',CONTAINER], { expected: null, timeout: 20000 }); } catch {}
process.exit(0);
