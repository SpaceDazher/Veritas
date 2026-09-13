// S2-003 canonical identity tests.
// Covers probe H (URL alias collision) semantics: aliases, tracking queries,
// redirects and display titles never merge two different provider objects and
// never split one object into two.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalIdentity, CANONICALIZATION_VERSION } from '../../src/lib/ingestion/canonical.mjs';

describe('S2-003 canonical identity', () => {
  test('web_url: tracking parameters, fragments and trailing slashes do not change identity', () => {
    const base = canonicalIdentity('web_url', { url: 'https://example.org/articles/post?utm_source=feed&id=42' });
    const alias = canonicalIdentity('web_url', { url: 'https://example.org/articles/post/?fbclid=xYZ&id=42#top' });
    assert.equal(base.canonical_locator, alias.canonical_locator);
    assert.equal(base.canonicalization_version, CANONICALIZATION_VERSION);
  });

  test('web_url: query order does not matter, but distinct values are distinct objects', () => {
    const a = canonicalIdentity('web_url', { url: 'https://example.org/p?a=1&b=2' });
    const b = canonicalIdentity('web_url', { url: 'https://example.org/p?b=2&a=1' });
    assert.equal(a.canonical_locator, b.canonical_locator);
    const c = canonicalIdentity('web_url', { url: 'https://example.org/p?a=2&b=2' });
    assert.notEqual(a.canonical_locator, c.canonical_locator);
  });

  test('probe H: different provider objects are never merged by alias', () => {
    const video1 = canonicalIdentity('youtube', { video_id: 'dQw4w9WgXcQ' });
    const video2 = canonicalIdentity('youtube', { video_id: 'dQw4w9WgXcR' });
    assert.notEqual(video1.canonical_locator, video2.canonical_locator);

    const message1 = canonicalIdentity('telegram', { chat_id: '-100123', message_id: '42' });
    const message2 = canonicalIdentity('telegram', { chat_id: '-100123', message_id: '43' });
    assert.notEqual(message1.canonical_locator, message2.canonical_locator);

    // A youtube URL and a web page with the same path live in different namespaces.
    const web = canonicalIdentity('web_url', { url: 'https://youtu.be/dQw4w9WgXcQ' });
    assert.notEqual(web.canonical_locator, video1.canonical_locator);
  });

  test('github: case differences in repository names do not split identity; object SHAs pin versions', () => {
    const repo1 = canonicalIdentity('github', { repository: 'SpaceDazher/AgentOS', kind: 'issue', number: 14, commit_sha: '4b4456a3acbe78371e2afcc75d81da59d2765b53' });
    const repo2 = canonicalIdentity('github', { repository: 'spacedazher/agentos', kind: 'issue', number: 14, commit_sha: '4B4456A3ACBE78371E2AFCC75D81DA59D2765B53' });
    assert.equal(repo1.canonical_locator, repo2.canonical_locator);

    const blob1 = canonicalIdentity('github', { repository: 'o/r', commit_sha: 'a'.repeat(40), blob_sha: 'b'.repeat(40) });
    const blob2 = canonicalIdentity('github', { repository: 'o/r', commit_sha: 'a'.repeat(40), blob_sha: 'c'.repeat(40) });
    assert.notEqual(blob1.canonical_locator, blob2.canonical_locator);
  });

  test('arxiv: revisions are identity; unresolved bare ids are rejected', () => {
    const v1 = canonicalIdentity('arxiv_huggingface', { arxiv_id: '2401.12345v2' });
    const v1resolved = canonicalIdentity('arxiv_huggingface', { arxiv_id: '2401.12345', resolved_revision: '2' });
    assert.equal(v1.canonical_locator, v1resolved.canonical_locator);
    const v3 = canonicalIdentity('arxiv_huggingface', { arxiv_id: '2401.12345v3' });
    assert.notEqual(v1.canonical_locator, v3.canonical_locator);
    assert.throws(() => canonicalIdentity('arxiv_huggingface', { arxiv_id: '2401.12345' }), /REVISION_UNRESOLVED/);
  });

  test('markdown_obsidian: identity is vault-relative; traversal is rejected', () => {
    const note = canonicalIdentity('markdown_obsidian', { vault_relative_path: 'projects/veritas/notes.md' });
    assert.equal(note.canonical_locator, 'obsidian:projects/veritas/notes.md');
    assert.notEqual(note.canonical_locator, 'obsidian:/abs/host/path/projects/veritas/notes.md');
    assert.throws(() => canonicalIdentity('markdown_obsidian', { vault_relative_path: '../secrets/key.md' }), /TRAVERSAL/);
  });

  test('manual_export ids are namespaced; different ids never collide', () => {
    const a = canonicalIdentity('manual_export', { export_id: 'export/note-001' });
    const b = canonicalIdentity('manual_export', { export_id: 'export/note-002' });
    assert.equal(a.canonical_locator, 'manual:export/note-001');
    assert.notEqual(a.canonical_locator, b.canonical_locator);
  });

  test('unknown source kinds are rejected fail-closed', () => {
    assert.throws(() => canonicalIdentity('pigeon_post', {}), /UNKNOWN_SOURCE_KIND/);
  });

  test('pdf identity falls back to raw digest when no URL exists', () => {
    const pdf = canonicalIdentity('pdf', { raw_sha256: 'a'.repeat(64) });
    assert.equal(pdf.canonical_locator, `pdf:sha256/${'a'.repeat(64)}`);
    const fromUrl = canonicalIdentity('pdf', { url: 'https://example.org/paper.pdf?utm_source=x' });
    assert.equal(fromUrl.canonical_locator, 'pdf:https://example.org/paper.pdf');
  });
});
