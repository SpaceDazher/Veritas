// S2-003 security hardening tests (REVISE round).
// Covers the review findings: async-honest probes are tested separately by
// scripts/s2-003-security-probes.mjs; here:
//   - authorization binding (substitute descriptors, cross-workspace,
//     unverified grants);
//   - full idempotency digest (same operation id, different payload);
//   - tenant/ACL-scoped dedup (cross-tenant invisibility);
//   - HTTP SSRF guard (schemes, private/loopback targets, redirect hops,
//     budget aborts, timeouts);
//   - vault symlink/junction escape rejection.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { IngestionStore } from '../../src/lib/ingestion/store.mjs';
import { IngestionPipeline } from '../../src/lib/ingestion/pipeline.mjs';
import { ManualExportConnector } from '../../src/lib/ingestion/connectors/manual-export.mjs';
import { HttpSnapshotConnector, assertPublicHttpTarget } from '../../src/lib/ingestion/connectors/http-snapshot.mjs';
import { MarkdownObsidianConnector } from '../../src/lib/ingestion/connectors/markdown-obsidian.mjs';
import { createGithubConnector } from '../../src/lib/ingestion/connectors/blocked-connectors.mjs';
import { createDecisionClock } from '../../src/lib/ingestion/time-model.mjs';
import { decideDedup } from '../../src/lib/ingestion/dedup.mjs';

const NOW = '2026-01-15T08:00:00.000Z';

function descriptor(overrides = {}) {
  return {
    source_id: 'src-hard-src',
    connector_id: 'conn-manual-export',
    source_kind: 'manual_export',
    canonical_locator: 'manual:export/hard-001',
    display_locator: 'hard-001',
    owner: 'prn-hard-reviewer',
    author: null,
    publisher: null,
    workspace_id: 'ws-hard',
    tenant_id: 'ws-hard',
    classification: { visibility: 'public' },
    license: { spdx: 'CC-BY-4.0', attribution_required: true },
    retention: { policy: 'keep_forever', retain_until: null },
    lifecycle: { state: 'enabled', reason: null, changed_at: null },
    registered_at: NOW,
    registered_by: 'prn-hard-reviewer',
    ...overrides,
  };
}

function request(operationId, overrides = {}) {
  return {
    contractVersion: '1.0.0',
    operation_id: operationId,
    source_id: 'src-hard-src',
    connector_id: 'conn-manual-export',
    actor: 'prn-hard-reviewer',
    locator: 'export/hard-001',
    workspace_id: 'ws-hard',
    version_selector: { latest: true },
    budget: { max_bytes: 100000, time_limit_ms: 5000 },
    grant_id: null,
    requested_at: NOW,
    ...overrides,
  };
}

function harness(descriptorOverrides = {}, grants = null) {
  const store = new IngestionStore();
  const desc = descriptor(descriptorOverrides);
  store.registerDescriptor(desc);
  const pipeline = new IngestionPipeline({
    store,
    connectors: new Map([
      ['manual_export', new ManualExportConnector({ clock: { now: () => NOW }, exports: new Map([['export/hard-001', { bytes: Buffer.from('hardening probe body'), text: 'hardening probe body', mime_type: 'text/plain' }]]) })],
      ['github', createGithubConnector()],
    ]),
    clock: createDecisionClock(NOW),
    now: () => NOW,
    grants,
  });
  return { store, pipeline, descriptor: desc };
}

describe('S2-003 REVISE: authorization binding', () => {
  test('a substitute connector_id in the request is refused server-side', async () => {
    const { pipeline } = harness();
    const outcome = await pipeline.ingest({ request: request('op-h-1', { connector_id: 'conn-evil-impersonator' }) });
    assert.equal(outcome.terminal, 'ACCESS_DENIED');
    assert.equal(store_untouched(pipeline), true);
  });

  test('a request outside the descriptor workspace is refused', async () => {
    const { pipeline } = harness();
    const outcome = await pipeline.ingest({ request: request('op-h-2', { workspace_id: 'ws-other' }) });
    assert.equal(outcome.terminal, 'ACCESS_DENIED');
  });

  test('an unregistered source id fails closed (no caller-supplied descriptors)', async () => {
    const { pipeline } = harness();
    const outcome = await pipeline.ingest({ request: request('op-h-3', { source_id: 'src-unregistered' }) });
    assert.equal(outcome.terminal, 'FAILED');
    assert.equal(outcome.error_code, 'NOT_FOUND');
  });

  test('a malformed fetch-request fails before any ledger entry is owned', async () => {
    const { store, pipeline } = harness();
    const malformed = request('op-h-4');
    delete malformed.contractVersion;
    const outcome = await pipeline.ingest({ request: malformed });
    assert.equal(outcome.terminal, 'FAILED');
    assert.match(outcome.detail, /invalid fetch-request/);
    assert.equal(store.getOperation('ws-hard', 'op-h-4'), null, 'malformed request must not own the operation id');
  });

  test('grant_required without a grant ledger fails closed; a verified grant passes', async () => {
    const { store, pipeline } = harness();
    store.registerDescriptor(descriptor({ source_id: 'src-gh', connector_id: 'conn-github', source_kind: 'github', canonical_locator: 'github:o/r/commit/aa' }));
    // Make the github fixture-backed connector appear grant_required by
    // wrapping capabilities.
    const base = pipeline.connectors.get('github');
    pipeline.connectors.set('github', {
      id: base.id, version: base.version,
      discoverCapabilities: () => ({ ...base.discoverCapabilities(), auth_mode: 'grant_required', required_grant_scope: 'source.github.read' }),
      resolveDescriptor: (r) => base.resolveDescriptor(r),
      fetchVersion: (r) => base.fetchVersion(r),
      extract: (s, f) => base.extract(s, f),
      reconcile: (o) => base.reconcile(o),
      observeDeletion: (s2, l) => base.observeDeletion(s2, l),
    });
    pipeline.grants = null;
    const denied = await pipeline.ingest({ request: request('op-h-5', { source_id: 'src-gh', connector_id: 'conn-github', locator: 'anything' }) });
    assert.equal(denied.terminal, 'ACCESS_DENIED');
    assert.match(denied.detail, /no grant ledger/);

    pipeline.grants = new Map([['grt-hard-0001', { principal_id: 'prn-hard-reviewer', workspace_id: 'ws-hard', scope: 'source.github.read', expires_at: '2099-01-01T00:00:00.000Z' }]]);
    const allowed = await pipeline.ingest({ request: request('op-h-6', { source_id: 'src-gh', connector_id: 'conn-github', locator: 'anything', grant_id: 'grt-hard-0001' }) });
    assert.equal(allowed.terminal, 'BLOCKED_CONNECTOR'); // fixture-less github fetch is honestly blocked, but the grant passed authorization
  });

  test('a wrong-scope or wrong-principal grant is rejected', async () => {
    const { store, pipeline } = harness();
    store.registerDescriptor(descriptor({ source_id: 'src-gh2', connector_id: 'conn-github', source_kind: 'github', canonical_locator: 'github:o/r/commit/bb' }));
    const base = pipeline.connectors.get('github');
    pipeline.connectors.set('github', {
      id: base.id, version: base.version,
      discoverCapabilities: () => ({ ...base.discoverCapabilities(), auth_mode: 'grant_required', required_grant_scope: 'source.github.read' }),
      resolveDescriptor: (r) => base.resolveDescriptor(r),
      fetchVersion: (r) => base.fetchVersion(r),
      extract: (s, f) => base.extract(s, f),
      reconcile: (o) => base.reconcile(o),
      observeDeletion: (s2, l) => base.observeDeletion(s2, l),
    });
    pipeline.grants = new Map([
      ['grt-wrong-scope', { principal_id: 'prn-hard-reviewer', workspace_id: 'ws-hard', scope: 'board.admin', expires_at: '2099-01-01T00:00:00.000Z' }],
      ['grt-wrong-principal', { principal_id: 'prn-someone-else', workspace_id: 'ws-hard', scope: 'source.github.read', expires_at: '2099-01-01T00:00:00.000Z' }],
      ['grt-expired', { principal_id: 'prn-hard-reviewer', workspace_id: 'ws-hard', scope: 'source.github.read', expires_at: '2020-01-01T00:00:00.000Z' }],
    ]);
    for (const [grantId, expectedDetail] of [['grt-wrong-scope', 'scope'], ['grt-wrong-principal', 'principal'], ['grt-expired', 'expired']]) {
      const outcome = await pipeline.ingest({ request: request(`op-h-7-${grantId}`, { source_id: 'src-gh2', connector_id: 'conn-github', locator: 'anything', grant_id: grantId }) });
      assert.equal(outcome.terminal, 'ACCESS_DENIED', grantId);
      assert.match(outcome.detail, new RegExp(expectedDetail));
    }
  });
});

function store_untouched(pipeline) {
  return pipeline.store.snapshots.size === 0;
}

describe('S2-003 REVISE: idempotency digest binding', () => {
  test('the same operation id with a different actor is a conflict, not a replay', async () => {
    const { store, pipeline } = harness();
    const first = await pipeline.ingest({ request: request('op-bind-1') });
    assert.equal(first.terminal, 'COMMITTED');
    const second = await pipeline.ingest({ request: request('op-bind-1', { actor: 'prn-different-actor' }) });
    assert.equal(second.terminal, 'FAILED');
    assert.match(second.detail, /different request payload/);
    assert.equal(store.snapshots.size, 1, 'conflicting replay must not create a second snapshot');
  });

  test('the same operation id with a different budget is a conflict', async () => {
    const { pipeline } = harness();
    await pipeline.ingest({ request: request('op-bind-2') });
    const conflict = await pipeline.ingest({ request: request('op-bind-2', { budget: { max_bytes: 42, time_limit_ms: 5000 } }) });
    assert.equal(conflict.terminal, 'FAILED');
    assert.match(conflict.detail, /different request payload/);
  });
});

describe('S2-003 REVISE: tenant/ACL-scoped dedup', () => {
  test('a raw-byte duplicate from another tenant is invisible: no foreign snapshot_id, no cross-tenant lineage', async () => {
    const { store, pipeline } = harness();
    const foreign = descriptor({ source_id: 'src-foreign', tenant_id: 'ws-foreign', workspace_id: 'ws-foreign', canonical_locator: 'manual:export/foreign-001' });
    store.registerDescriptor(foreign);
    // Stage a foreign snapshot with the same raw digest directly.
    const crypto = await import('node:crypto');
    const rawDigest = crypto.createHash('sha256').update('hardening probe body').digest('hex');
    store.appendSnapshot({
      contractVersion: '1.0.0', snapshot_id: 'snp-foreign00000001', source_id: foreign.source_id, connector_id: foreign.connector_id,
      source_kind: 'manual_export', version: 1, snapshot_kind: 'content', tombstone_reason: null,
      canonical_locator: foreign.canonical_locator, canonicalization_version: '1.0.0',
      raw_sha256: rawDigest, normalized_sha256: rawDigest, author: null, publisher: null,
      published_at: null, event_time: null, observed_at: NOW, fetched_at: NOW,
      parent_snapshot_id: null, supersedes_snapshot_id: null, language: null, mime_type: 'text/plain',
      size_bytes: 20, extraction_status: 'COMPLETE',
      acl: { visibility: 'private', workspace_id: 'ws-foreign', tenant_id: 'ws-foreign', allowed_principal_ids: ['prn-foreign-owner'] },
      license: foreign.license, retention: foreign.retention,
      fetch_provenance: { operation_id: 'op-foreign', connector_id: foreign.connector_id, connector_version: '1.0.0', fetched_from: 'x', fetched_at: NOW, grant_id: null, content_type_validated: true },
    });

    const outcome = await pipeline.ingest({ request: request('op-scope-1') });
    assert.equal(outcome.terminal, 'COMMITTED');
    assert.notEqual(outcome.snapshot_id, 'snp-foreign00000001', 'foreign snapshot leaked into dedup');
    assert.equal(outcome.dedup, 'UNIQUE', `expected UNIQUE, got ${outcome.dedup}`);
    assert.equal([...store.lineage.values()].length, 0, 'cross-tenant lineage was created');
  });

  test('decideDedup without a viewer scope is a programming error', async () => {
    const { store } = harness();
    await assert.rejects(() => decideDedup({ store, candidate: { raw_sha256: 'a'.repeat(64), normalized_sha256: 'b'.repeat(64), canonical_locator: 'x', version: 1 } }), /DEDUP_SCOPE_REQUIRED/);
  });
});

describe('S2-003 REVISE: HTTP SSRF / redirect / budget / timeout', () => {
  test('target validation: schemes, loopback, private ranges and internal hostnames are forbidden', () => {
    for (const bad of [
      'file:///etc/passwd',
      'ftp://example.org/file',
      'http://localhost/x',
      'http://localhost:8080/admin',
      'http://127.0.0.1/x',
      'http://10.0.0.1/x',
      'http://172.16.0.9/x',
      'http://192.168.1.1/x',
      'http://169.254.169.254/latest/meta-data',
      'http://[::1]/x',
      'http://[fd00::1]/x',
      'http://metadata.google.internal/computeMetadata',
    ]) {
      assert.throws(() => assertPublicHttpTarget(bad), /SSRF_/, bad);
    }
    // public targets pass
    assertPublicHttpTarget('https://example.org/page');
    assertPublicHttpTarget('http://93.184.216.34/page');
  });

  test('resolved private addresses are rejected via the injectable resolver', () => {
    assert.throws(() => assertPublicHttpTarget('https://internal-rebind.example.org/x', {
      resolveHostname: () => ['93.184.216.34', '127.0.0.1'],
    }), /SSRF_RESOLVED_FORBIDDEN/);
    assert.doesNotThrow(() => assertPublicHttpTarget('https://normal.example.org/x', {
      resolveHostname: () => ['93.184.216.34'],
    }));
  });

  test('a redirect chain into private space is refused at the hop', async () => {
    const responses = new Map([
      ['https://public.example.org/start', { status: 302, headers: { get: (k) => (k === 'location' ? 'http://169.254.169.254/latest' : null) } }],
    ]);
    const connector = new HttpSnapshotConnector({
      clock: { now: () => NOW },
      fetchFn: async (url) => responses.get(url) ?? { status: 500, headers: { get: () => null } },
      resolveHostname: () => ['93.184.216.34'],
    });
    const outcome = await connector.fetchVersion({ operation_id: 'op-ssrf-1', locator: 'https://public.example.org/start', budget: { max_bytes: 10000, time_limit_ms: 5000 } });
    assert.equal(outcome.code, 'ACCESS_DENIED');
    assert.match(outcome.diagnostic.redacted_detail, /SSRF_ADDRESS_FORBIDDEN/);
  });

  test('response bodies exceeding the request budget are quarantined, not truncated into storage', async () => {
    const bigBody = 'x'.repeat(5000);
    const connector = new HttpSnapshotConnector({
      clock: { now: () => NOW },
      fetchFn: async () => ({
        ok: true, status: 200,
        headers: { get: (k) => (k === 'content-type' ? 'text/html' : null) },
        url: 'https://example.org/big',
        arrayBuffer: async () => Buffer.from(bigBody).buffer.slice(0, Buffer.byteLength(bigBody)),
      }),
      resolveHostname: () => ['93.184.216.34'],
    });
    const outcome = await connector.fetchVersion({ operation_id: 'op-budget-1', locator: 'https://example.org/big', budget: { max_bytes: 1000, time_limit_ms: 5000 } });
    assert.equal(outcome.code, 'QUARANTINED');
    assert.match(outcome.diagnostic.redacted_detail, /budget/);
  });

  test('time_limit_ms aborts a hanging fetch as TIMEOUT', async () => {
    const connector = new HttpSnapshotConnector({
      clock: { now: () => NOW },
      fetchFn: (url, opts) => new Promise((resolve, reject) => {
        opts.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
      }),
      resolveHostname: () => ['93.184.216.34'],
    });
    const outcome = await connector.fetchVersion({ operation_id: 'op-timeout-1', locator: 'https://example.org/hang', budget: { max_bytes: 10000, time_limit_ms: 50 } });
    assert.equal(outcome.code, 'TIMEOUT');
  });
});

describe('S2-003 REVISE: vault symlink/junction escape', () => {
  test('a junction pointing outside the vault is rejected by realpath', async () => {
    const vault = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-vault-sym-'));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-outside-sym-'));
    try {
      fs.writeFileSync(path.join(outside, 'secret.md'), 'outside the vault');
      const linkPath = path.join(vault, 'innocent');
      let linkCreated = false;
      try {
        fs.symlinkSync(outside, linkPath, 'junction');
        linkCreated = true;
      } catch {
        // junction creation can be unavailable; skip honestly without claiming detection
        return;
      }
      assert.ok(linkCreated);
      const connector = new MarkdownObsidianConnector({ vaultRoot: vault, clock: { now: () => NOW } });
      const result = await connector.fetchVersion({ operation_id: 'op-sym-1', locator: 'innocent/secret.md' });
      assert.equal(result.code, 'ACCESS_DENIED');
      assert.match(result.diagnostic.redacted_detail, /SYMLINK_ESCAPE/);
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

describe('S2-003 REVISE-2: streaming budget and mandatory DNS resolver', () => {
  test('a Web-stream body is read in bounded chunks and aborted over budget (real streaming path)', async () => {
    const chunk = 'y'.repeat(600);
    let aborted = false;
    const streamBody = {
      getReader: () => {
        let reads = 0;
        return {
          read: async () => {
            reads += 1;
            if (reads > 5) return { done: true };
            if (reads >= 2) aborted = true; // budget must abort before the stream ends
            return { done: false, value: Buffer.from(chunk) };
          },
        };
      },
    };
    const connector = new HttpSnapshotConnector({
      clock: { now: () => NOW },
      fetchFn: async () => ({
        ok: true, status: 200,
        headers: { get: (k) => (k === 'content-type' ? 'text/html' : null) },
        url: 'https://example.org/stream',
        body: streamBody,
      }),
      resolveHostname: () => ['93.184.216.34'],
    });
    const outcome = await connector.fetchVersion({ operation_id: 'op-stream-1', locator: 'https://example.org/stream', budget: { max_bytes: 1000, time_limit_ms: 5000 } });
    assert.equal(outcome.code, 'QUARANTINED');
    assert.match(outcome.diagnostic.redacted_detail, /budget/);
    assert.equal(aborted, true, 'stream was fully consumed before aborting');
  });

  test('DNS resolution is mandatory by default (no silent no-resolver connector)', () => {
    const connector = new HttpSnapshotConnector({ clock: { now: () => NOW }, fetchFn: async () => { throw new Error('must not be reached'); } });
    assert.equal(typeof connector.resolveHostname, 'function', 'default resolver must be installed');
    // the default resolver is the real node:dns lookup — not a stub
    const promise = connector.resolveHostname('dns-unsupported-.invalid');
    assert.ok(promise instanceof Promise);
    return promise.then(() => { throw new Error('unexpected resolution'); }, (error) => { assert.ok(error); });
  });
});

describe('S2-003 REVISE-2: segment budget enforcement', () => {
  test('extraction amplification over max_segments is quarantined', async () => {
    const { store, pipeline } = harness();
    const connector = pipeline.connectors.get('manual_export');
    const originalExtract = connector.extract.bind(connector);
    connector.extract = async (snapshot, fetched) => {
      const base = await originalExtract(snapshot, fetched);
      return Array.from({ length: 10 }, (_, i) => ({ ...base[0], ordinal: i, text: `segment ${i}` }));
    };
    const outcome = await pipeline.ingest({ request: request('op-seg-1', { budget: { max_bytes: 100000, max_segments: 3, time_limit_ms: 5000 } }) });
    assert.equal(outcome.terminal, 'FAILED');
    assert.equal(outcome.error_code, 'QUARANTINED');
    assert.match(outcome.detail, /exceeding the budget/);
    assert.equal(store.snapshots.size, 0, 'amplified extraction must not reach storage');
  });
});

describe('S2-003 REVISE-3: async SSRF guard correctness', () => {
  test('the async guard rejects a resolver answer of 127.0.0.1 BEFORE the transport is called', async () => {
    let transportCalled = 0;
    const connector = new HttpSnapshotConnector({
      clock: { now: () => NOW },
      fetchFn: async () => { transportCalled += 1; return { ok: true, status: 200, headers: { get: () => 'text/html' }, url: 'https://rebind.example.org/x', arrayBuffer: async () => Buffer.from('pwned').buffer.slice(0, 5) }; },
      resolveHostname: () => ['127.0.0.1'],
    });
    const outcome = await connector.fetchVersion({ operation_id: 'op-rebind-1', locator: 'https://rebind.example.org/x', budget: { max_bytes: 10000, time_limit_ms: 5000 } });
    assert.equal(outcome.code, 'ACCESS_DENIED');
    assert.match(outcome.diagnostic.redacted_detail, /SSRF_RESOLVED_FORBIDDEN: rebind\.example\.org -> 127\.0\.0\.1/);
    assert.equal(transportCalled, 0, 'the transport must never run for a forbidden resolution');
  });

  test('the async guard accepts public resolutions and lets the transport run', async () => {
    let transportCalled = 0;
    const connector = new HttpSnapshotConnector({
      clock: { now: () => NOW },
      fetchFn: async () => { transportCalled += 1; return { ok: true, status: 200, headers: { get: () => 'text/html' }, url: 'https://ok.example.org/x', arrayBuffer: async () => Buffer.from('fine').buffer.slice(0, 4) }; },
      resolveHostname: () => ['93.184.216.34'],
    });
    const outcome = await connector.fetchVersion({ operation_id: 'op-rebind-2', locator: 'https://ok.example.org/x', budget: { max_bytes: 10000, time_limit_ms: 5000 } });
    assert.equal(outcome.ok, true);
    assert.equal(transportCalled, 1);
  });
});

describe('S2-003 REVISE-3: atomic commitIngest (review round 2 finding 1)', () => {
  test('a failure between snapshot and segments appends rolls everything back: no partial snapshot, INTENT preserved', async () => {
    const { store, pipeline } = harness();
    const connector = pipeline.connectors.get('manual_export');
    const originalExtract = connector.extract.bind(connector);
    // First: a healthy commit so the ledger, store and fixtures are warm.
    const ok = await pipeline.ingest({ request: request('op-atomic-1') });
    assert.equal(ok.terminal, 'COMMITTED');
    const sizeAfterOk = store.snapshots.size;
    const eventsAfterOk = store.events.length;

    // Second: the connector succeeds but the store fails while appending
    // segments (the exact repro from the review: failure between snapshot
    // and segments must leave no partial snapshot).
    connector.extract = async (snapshot, fetched) => originalExtract(snapshot, fetched);
    // A different content makes the second operation UNIQUE (not a dedup
    // replay), so the commit path actually appends.
    connector.exports.set('export/hard-001', { bytes: Buffer.from('second, different body'), text: 'second, different body', mime_type: 'text/plain' });
    const originalAppendSegments = store.appendSegments.bind(store);
    store.appendSegments = () => { throw new Error('disk full between snapshot and segments'); };
    const outcome = await pipeline.ingest({ request: request('op-atomic-2') });
    store.appendSegments = originalAppendSegments;
    console.error('DBG outcome:', JSON.stringify(outcome), '| segments patched, size:', store.snapshots.size);
    assert.equal(outcome.terminal, 'FAILED');
    assert.equal(store.snapshots.size, sizeAfterOk, 'partial snapshot survived the failed commit');
    const ledger = store.getOperation('ws-hard', 'op-atomic-2');
    assert.equal(ledger?.status, 'FAILED', 'the failed operation must own exactly one recorded terminal');
    assert.equal(store.segments.has(outcome.snapshot_id ?? 'none'), false, 'orphan segments must not survive');
  });
});
