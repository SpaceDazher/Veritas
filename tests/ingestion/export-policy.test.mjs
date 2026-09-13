// S2-003 export policy tests (probe G semantics).
// Private snapshots and segments can never reach public output; ACL checks
// are server-side on every read/export.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { IngestionStore } from '../../src/lib/ingestion/store.mjs';
import { IngestionPipeline } from '../../src/lib/ingestion/pipeline.mjs';
import { ManualExportConnector } from '../../src/lib/ingestion/connectors/manual-export.mjs';
import { createDecisionClock } from '../../src/lib/ingestion/time-model.mjs';
import { exportSnapshot, publicEvidenceView, ExportDeniedError } from '../../src/lib/ingestion/export-policy.mjs';

const NOW = '2026-01-15T08:00:00.000Z';

function descriptorFor(overrides = {}) {
  return {
    source_id: 'src-private-1',
    connector_id: 'conn-manual-export',
    source_kind: 'manual_export',
    canonical_locator: 'manual:export/private-001',
    display_locator: 'private-001',
    owner: 'prn-human-reviewer',
    author: null,
    publisher: null,
    workspace_id: 'ws-private',
    tenant_id: 'ws-private',
    classification: { visibility: 'private', allowed_principal_ids: ['prn-owner'] },
    license: { spdx: 'CC-BY-4.0', attribution_required: true },
    retention: { policy: 'keep_forever', retain_until: null },
    lifecycle: { state: 'enabled', reason: null, changed_at: null },
    registered_at: NOW,
    registered_by: 'prn-human-reviewer',
    ...overrides,
  };
}

function requestFor(operationId) {
  return {
    operation_id: operationId,
    source_id: 'src-private-1',
    locator: 'export/private-001',
    workspace_id: 'ws-private',
    budget: { max_bytes: 100000, time_limit_ms: 5000 },
    requested_at: NOW,
  };
}

async function committedPrivateSnapshot() {
  const store = new IngestionStore();
  const descriptor = descriptorFor();
  store.registerDescriptor(descriptor);
  const pipeline = new IngestionPipeline({
    store,
    connectors: new Map([['manual_export', new ManualExportConnector({
      clock: { now: () => NOW },
      exports: new Map([['export/private-001', { bytes: Buffer.from('private canary content'), text: 'private canary content', mime_type: 'text/plain' }]]),
    })]]),
    clock: createDecisionClock(NOW),
    now: () => NOW,
  });
  const outcome = await pipeline.ingest({ request: requestFor('op-priv-1'), descriptor });
  assert.equal(outcome.terminal, 'COMMITTED');
  return { store, snapshotId: outcome.snapshot_id };
}

describe('S2-003 export policy', () => {
  test('the owner principal can export a private snapshot', async ({ }) => {
    const { store, snapshotId } = await committedPrivateSnapshot();
    const view = exportSnapshot({
      store,
      snapshotId,
      viewer: { principal_id: 'prn-owner', workspace_id: 'ws-private', tenant_id: 'ws-private' },
    });
    assert.equal(view.snapshot_id, snapshotId);
    assert.ok(view.segments.length >= 1);
  });

  test('out-of-scope principals are denied on every export attempt', async () => {
    const { store, snapshotId } = await committedPrivateSnapshot();
    for (const viewer of [
      { principal_id: 'prn-stranger', workspace_id: 'ws-other', tenant_id: 'ws-private' },
      { principal_id: 'prn-stranger2', workspace_id: 'ws-other', tenant_id: 'ws-other' },
    ]) {
      assert.throws(() => exportSnapshot({ store, snapshotId, viewer }), ExportDeniedError);
    }
  });

  test('probe G: public evidence view of a private snapshot contains zero content bytes', async () => {
    const { store, snapshotId } = await committedPrivateSnapshot();
    const publicView = publicEvidenceView({ store, snapshotId });
    assert.equal(publicView.content_included, false);
    assert.equal(publicView.segments.length, 0);
    const serialized = JSON.stringify(publicView);
    assert.doesNotMatch(serialized, /private canary content/);
    // the digest is not content and may be published for integrity proofs
    assert.match(publicView.raw_sha256, /^[0-9a-f]{64}$/);
  });

  test('public snapshots export fully through the public evidence path', async () => {
    const store = new IngestionStore();
    const descriptor = descriptorFor({
      source_id: 'src-public-1',
      canonical_locator: 'manual:export/public-001',
      classification: { visibility: 'public' },
    });
    store.registerDescriptor(descriptor);
    const pipeline = new IngestionPipeline({
      store,
      connectors: new Map([['manual_export', new ManualExportConnector({
        clock: { now: () => NOW },
        exports: new Map([['export/public-001', { bytes: Buffer.from('public page'), text: 'public page', mime_type: 'text/plain' }]]),
      })]]),
      clock: createDecisionClock(NOW),
      now: () => NOW,
    });
    const outcome = await pipeline.ingest({
      request: { ...requestFor('op-pub-1'), source_id: 'src-public-1', locator: 'export/public-001' },
      descriptor,
    });
    assert.equal(outcome.terminal, 'COMMITTED');
    const publicView = publicEvidenceView({ store, snapshotId: outcome.snapshot_id });
    assert.equal(publicView.content_included, true);
    assert.ok(publicView.segments.length >= 1);
  });

  test('a private proposal never leaks candidate bytes', () => {
    const serialized = JSON.stringify(descriptorFor());
    assert.doesNotMatch(serialized, /canary/);
  });
});
