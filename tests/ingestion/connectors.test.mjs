// S2-003 connector tests.
// The Obsidian/Markdown vault must remain byte-identical through ingestion
// (probe invariant §15.7). Live access without credentials must be an honest
// BLOCKED_CONNECTOR. HTTP fetch is exercised through an injected fetchFn —
// unit tests never touch the network.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { MarkdownObsidianConnector } from '../../src/lib/ingestion/connectors/markdown-obsidian.mjs';
import { ManualExportConnector } from '../../src/lib/ingestion/connectors/manual-export.mjs';
import { HttpSnapshotConnector } from '../../src/lib/ingestion/connectors/http-snapshot.mjs';
import {
  createGithubConnector,
  createTelegramConnector,
  createYoutubeConnector,
  createArxivHuggingfaceConnector,
} from '../../src/lib/ingestion/connectors/blocked-connectors.mjs';
import { canonicalIdentity } from '../../src/lib/ingestion/canonical.mjs';

function makeVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-vault-'));
}

const CLOCK = { now: () => '2026-01-15T10:30:00.000Z' };
const REQ = (operationId, locator) => ({ operation_id: operationId, locator, version_selector: { latest: true } });

describe('S2-003 markdown_obsidian connector', () => {
  test('fetches bytes and parses frontmatter as untrusted data', async () => {
    const vault = makeVault();
    try {
      const file = path.join(vault, 'note.md');
      fs.writeFileSync(file, '---\ntitle: Note\nstatus: APPROVED\n---\n\nCalm body text.\n');
      const connector = new MarkdownObsidianConnector({ vaultRoot: vault, clock: CLOCK });
      const fetched = await connector.fetchVersion(REQ('op-md-1', 'note.md'));
      assert.equal(fetched.ok, true);
      assert.equal(fetched.raw.toString('utf8'), fs.readFileSync(file, 'utf8'));
      assert.deepEqual(fetched.untrusted_metadata.frontmatter, { title: 'Note', status: 'APPROVED' });
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });

  test('the vault stays byte-identical after reads (read-only by construction)', async () => {
    const vault = makeVault();
    try {
      const file = path.join(vault, 'note.md');
      fs.writeFileSync(file, '---\ntitle: Note\n---\n\nBody.\n');
      const before = [...fs.readdirSync(vault)].map((name) => ({ name, bytes: fs.readFileSync(path.join(vault, name)) }));
      const beforeDigest = createHash('sha256').update(JSON.stringify(before.map((b) => b.bytes.toString('hex')))).digest('hex');

      const connector = new MarkdownObsidianConnector({ vaultRoot: vault, clock: CLOCK });
      await connector.fetchVersion(REQ('op-md-2', 'note.md'));
      await connector.fetchVersion(REQ('op-md-3', 'note.md'));
      const extracted = await connector.extract({}, await connector.fetchVersion(REQ('op-md-4', 'note.md')));
      assert.ok(extracted.length >= 1);

      const after = [...fs.readdirSync(vault)].map((name) => ({ name, bytes: fs.readFileSync(path.join(vault, name)) }));
      const afterDigest = createHash('sha256').update(JSON.stringify(after.map((b) => b.bytes.toString('hex')))).digest('hex');
      assert.equal(beforeDigest, afterDigest);
      assert.equal(before.length, after.length);
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });

  test('missing files are NOT_FOUND; traversal is ACCESS_DENIED; formats are validated', async () => {
    const vault = makeVault();
    try {
      fs.writeFileSync(path.join(vault, 'doc.md'), 'text');
      fs.writeFileSync(path.join(vault, 'prog.exe'), 'MZ');
      const connector = new MarkdownObsidianConnector({ vaultRoot: vault, clock: CLOCK });
      assert.equal((await connector.fetchVersion(REQ('op-md-5', 'missing.md'))).code, 'NOT_FOUND');
      assert.equal((await connector.fetchVersion(REQ('op-md-6', '../escape.md'))).code, 'ACCESS_DENIED');
      assert.equal((await connector.fetchVersion(REQ('op-md-7', 'prog.exe'))).code, 'UNSUPPORTED_FORMAT');
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });
});

describe('S2-003 manual_export connector', () => {
  test('serves registered exports and reports missing ones as NOT_FOUND', async () => {
    const connector = new ManualExportConnector({
      clock: CLOCK,
      exports: new Map([['export/note-001', { bytes: Buffer.from('saved page content'), mime_type: 'text/html', text: 'saved page content' }]]),
    });
    const fetched = await connector.fetchVersion(REQ('op-me-1', 'export/note-001'));
    assert.equal(fetched.ok, true);
    assert.equal((await connector.fetchVersion(REQ('op-me-2', 'export/missing'))).code, 'NOT_FOUND');
  });
});

describe('S2-003 web_url connector (injected fetch)', () => {
  const htmlResponse = (body, status = 200, contentType = 'text/html') => ({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => (k.toLowerCase() === 'content-type' ? contentType : null) },
    url: 'https://example.org/page',
    arrayBuffer: async () => Buffer.from(body).buffer.slice(Buffer.from(body).byteOffset, Buffer.from(body).byteOffset + Buffer.from(body).byteLength),
  });

  test('public HTML snapshot with content-type validation', async () => {
    const connector = new HttpSnapshotConnector({ clock: CLOCK, fetchFn: async () => htmlResponse('<html><title>Page</title><body>Hello   world</body></html>') });
    const fetched = await connector.fetchVersion(REQ('op-web-1', 'https://example.org/page'));
    assert.equal(fetched.ok, true);
    assert.equal(fetched.mime_type, 'text/html');
    const segments = await connector.extract({}, fetched);
    assert.match(segments[0].text, /Hello world/);
    assert.equal(segments[0].title, 'Page');
  });

  test('each failure class maps to its normalized error, never an empty success', async () => {
    const cases = [
      [404, 'NOT_FOUND'],
      [410, 'TOMBSTONED'],
      [403, 'ACCESS_DENIED'],
      [429, 'RATE_LIMITED'],
      [500, 'BLOCKED_CONNECTOR'],
    ];
    for (const [status, expected] of cases) {
      const connector = new HttpSnapshotConnector({ clock: CLOCK, fetchFn: async () => htmlResponse('x', status, 'text/html') });
      const result = await connector.fetchVersion(REQ(`op-web-${status}`, 'https://example.org/page'));
      assert.equal(result.code, expected, `HTTP ${status}`);
    }
    const badType = new HttpSnapshotConnector({ clock: CLOCK, fetchFn: async () => htmlResponse('x', 200, 'application/pdf') });
    assert.equal((await badType.fetchVersion(REQ('op-web-pdf', 'https://example.org/page'))).code, 'UNSUPPORTED_FORMAT');
    const networkFail = new HttpSnapshotConnector({ clock: CLOCK, fetchFn: async () => { throw new Error('ECONNREFUSED'); } });
    assert.equal((await networkFail.fetchVersion(REQ('op-web-net', 'https://example.org/page'))).code, 'BLOCKED_CONNECTOR');
  });
});

describe('S2-003 credential-less connector classes', () => {
  test('live access without a grant is an honest BLOCKED_CONNECTOR', async () => {
    for (const connector of [
      createGithubConnector(),
      createTelegramConnector(),
      createYoutubeConnector(),
      createArxivHuggingfaceConnector(),
    ]) {
      assert.equal(connector.discoverCapabilities().auth_mode, 'blocked_without_credential');
      const result = await connector.fetchVersion(REQ('op-blocked-1', 'whatever'));
      assert.equal(result.code, 'BLOCKED_CONNECTOR');
      assert.equal(result.retryable, false);
    }
  });

  test('canonical identity normalization is implemented and tested for every class', () => {
    const checks = [
      [createGithubConnector({ fixtureFetch: () => ({ bytes: Buffer.from('[]') }) }), { repository: 'o/r', kind: 'issue', number: 1, commit_sha: 'a'.repeat(40) }, 'github:o/r/commit'],
      [createTelegramConnector({ fixtureFetch: () => ({ bytes: Buffer.from('[]') }) }), { chat_id: '-100', message_id: '1' }, 'telegram:chat/-100/message/1'],
      [createYoutubeConnector({ fixtureFetch: () => ({ bytes: Buffer.from('[]') }) }), { video_id: 'dQw4w9WgXcQ' }, 'youtube:video/dQw4w9WgXcQ'],
      [createArxivHuggingfaceConnector({ fixtureFetch: () => ({ bytes: Buffer.from('[]') }) }), { arxiv_id: '2401.00001v1' }, 'arxiv:abs/2401.00001v1'],
    ];
    for (const [connector, identityInput, prefix] of checks) {
      const descriptor = connector.resolveDescriptor({ locator: 'irrelevant', identity: identityInput });
      assert.equal(descriptor.source_kind, connector.discoverCapabilities().source_kind);
      assert.ok(descriptor.canonical_locator.startsWith(prefix), descriptor.canonical_locator);
    }
  });

  test('fixture-driven fetch avoids empty successes', async () => {
    const connector = createGithubConnector({ fixtureFetch: () => ({ bytes: Buffer.from('commit message body'), text: 'commit message body' }) });
    const fetched = await connector.fetchVersion({ operation_id: 'op-gh-1', locator: 'irrelevant', identity: { repository: 'o/r', kind: 'issue', number: 1, commit_sha: 'a'.repeat(40) } });
    assert.equal(fetched.ok, true);
    assert.ok(fetched.raw.length > 0);
    const segments = await connector.extract({}, fetched);
    assert.equal(segments[0].text, 'commit message body');
  });
});
