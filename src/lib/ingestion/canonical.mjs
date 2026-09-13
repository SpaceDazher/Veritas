// S2-003 canonical identity and locator canonicalization.
// Provider-specific canonical locators are built here and only here.
// Redirects, tracking queries, URL aliases and display titles can never
// silently create a new entity or merge two different entities:
//   - identity is derived from provider object ids, not from display text;
//   - different providers are namespaced, so cross-provider collisions are
//     impossible;
//   - canonicalization is deterministic and versioned: the same input always
//     yields the same canonical locator for a given version.
// Wall-clock time is never an input to identity.
export const CANONICALIZATION_VERSION = '1.0.0';

// Tracking parameters stripped from web URLs. A stripped value never changes
// identity: two URLs differing only in these parameters are the same object.
const STRIPPED_QUERY_PARAMS = new Set([
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'fbclid', 'gclid', 'yclid', 'mc_cid', 'mc_eid', 'ref', 'ref_src', 'ref_url',
  'igshid', 'si', 'spm', 'scm', 'share_token', 'st', 's', 'fb_action_ids',
]);

const YOUTUBE_HOSTS = new Set(['youtube.com', 'www.youtube.com', 'm.youtube.com', 'music.youtube.com', 'youtu.be']);

function assertTrustedString(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) {
    throw new Error(`CANONICALIZATION_INPUT_INVALID: ${label}`);
  }
  return value;
}

function canonicalizeWebUrl(rawUrl) {
  const urlText = assertTrustedString(rawUrl, 'url');
  let url;
  try {
    url = new URL(urlText);
  } catch {
    throw new Error(`CANONICALIZATION_INPUT_INVALID: url-parse`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('CANONICALIZATION_UNSUPPORTED_PROTOCOL');
  }
  url.hash = '';
  url.hostname = url.hostname.toLowerCase();
  if ((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443')) {
    url.port = '';
  }
  const kept = [];
  for (const [key, value] of url.searchParams.entries()) {
    if (!STRIPPED_QUERY_PARAMS.has(key.toLowerCase())) kept.push([key, value]);
  }
  kept.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  url.search = '';
  for (const [key, value] of kept) url.searchParams.append(key, value);
  // Trailing slash on an empty path is a display artifact, not identity.
  if (url.pathname !== '/' && url.pathname.endsWith('/')) {
    url.pathname = url.pathname.replace(/\/+$/, '');
  }
  return url.toString();
}

function canonicalizeGithub(raw) {
  const repo = assertTrustedString(raw.repository, 'github.repository').toLowerCase();
  if (!/^[a-z0-9-]+\/[a-z0-9_.-]+$/.test(repo)) {
    throw new Error('CANONICALIZATION_INPUT_INVALID: github.repository');
  }
  const parts = [`github:${repo}`];
  if (raw.kind === 'blob' || raw.commit_sha) {
    parts.push(`commit:${assertTrustedString(raw.commit_sha, 'github.commit_sha').toLowerCase()}`);
  }
  if (raw.blob_sha) parts.push(`blob:${assertTrustedString(raw.blob_sha, 'github.blob_sha').toLowerCase()}`);
  if (raw.kind === 'issue') parts.push(`issue:${String(raw.number)}`);
  if (raw.kind === 'pull_request') parts.push(`pull:${String(raw.number)}`);
  if (raw.comment_id !== undefined && raw.comment_id !== null) parts.push(`comment:${String(raw.comment_id)}`);
  return parts.join('/');
}

function canonicalizeTelegram(raw) {
  const chatId = assertTrustedString(String(raw.chat_id), 'telegram.chat_id');
  const messageId = assertTrustedString(String(raw.message_id), 'telegram.message_id');
  if (!/^-?\d{1,20}$/.test(chatId) || !/^\d{1,20}$/.test(messageId)) {
    throw new Error('CANONICALIZATION_INPUT_INVALID: telegram.ids');
  }
  return `telegram:chat/${chatId}/message/${messageId}`;
}

function canonicalizeYoutube(raw) {
  const videoId = assertTrustedString(raw.video_id, 'youtube.video_id');
  if (!/^[A-Za-z0-9_-]{11}$/.test(videoId)) {
    throw new Error('CANONICALIZATION_INPUT_INVALID: youtube.video_id');
  }
  const parts = [`youtube:video/${videoId}`];
  if (raw.transcript_version) parts.push(`transcript/${assertTrustedString(raw.transcript_version, 'youtube.transcript_version')}`);
  return parts.join('/');
}

function canonicalizeArxivHuggingface(raw) {
  if (raw.arxiv_id) {
    const m = assertTrustedString(raw.arxiv_id, 'arxiv_id').match(/^(\d{4}\.\d{4,5})(v\d+)?$/);
    if (!m) throw new Error('CANONICALIZATION_INPUT_INVALID: arxiv_id');
    // The full id including revision is identity; a bare id is only a search
    // key, so it must be resolved to a concrete revision before canonical use.
    const revision = m[2] ?? (raw.resolved_revision ? `v${String(raw.resolved_revision).replace(/^v/, '')}` : null);
    if (!revision) throw new Error('CANONICALIZATION_REVISION_UNRESOLVED: arxiv');
    return `arxiv:abs/${m[1]}${revision}`;
  }
  if (raw.huggingface_id) {
    const id = assertTrustedString(raw.huggingface_id, 'huggingface_id').toLowerCase();
    if (!/^[a-z0-9-]+\/[a-z0-9._-]+$/.test(id) && !/^[a-z0-9._-]+$/.test(id)) {
      throw new Error('CANONICALIZATION_INPUT_INVALID: huggingface_id');
    }
    const kind = raw.huggingface_kind === 'dataset' ? 'datasets' : raw.huggingface_kind === 'space' ? 'spaces' : 'models';
    const revision = raw.revision ? assertTrustedString(raw.revision, 'hf.revision').toLowerCase() : 'main';
    return `huggingface:${kind}/${id}@${revision}`;
  }
  throw new Error('CANONICALIZATION_INPUT_MISSING: arxiv_huggingface');
}

function canonicalizeVaultPath(rawPath) {
  // Identity is the path relative to the vault root with forward slashes.
  // The absolute vault root is host-specific and must never leak into identity.
  const normalized = assertTrustedString(rawPath, 'vault_path')
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\/+/, '');
  if (normalized.split('/').includes('..')) {
    throw new Error('CANONICALIZATION_PATH_TRAVERSAL: vault_path');
  }
  return `obsidian:${normalized}`;
}

// --- public API -------------------------------------------------------------

const CANONICALIZERS = {
  web_url: (raw) => {
    const canonical_url = canonicalizeWebUrl(raw.url);
    return { canonical_locator: canonical_url, ids: { canonical_url } };
  },
  pdf: (raw) => {
    if (raw.url) {
      const canonical_url = canonicalizeWebUrl(raw.url);
      return { canonical_locator: `pdf:${canonical_url}`, ids: { canonical_url } };
    }
    const digest = assertTrustedString(raw.raw_sha256, 'pdf.raw_sha256');
    if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('CANONICALIZATION_INPUT_INVALID: pdf.raw_sha256');
    return { canonical_locator: `pdf:sha256/${digest}`, ids: {} };
  },
  github: (raw) => {
    const locator = canonicalizeGithub(raw);
    return { canonical_locator: locator, ids: { canonical_repository_id: `github:${raw.repository.toLowerCase()}`, canonical_object_id: locator.split('/').slice(1).join('/') } };
  },
  telegram: (raw) => {
    const locator = canonicalizeTelegram(raw);
    return { canonical_locator: locator, ids: { canonical_message_id: locator } };
  },
  youtube: (raw) => {
    const locator = canonicalizeYoutube(raw);
    return { canonical_locator: locator, ids: { canonical_object_id: locator } };
  },
  arxiv_huggingface: (raw) => {
    const locator = canonicalizeArxivHuggingface(raw);
    return { canonical_locator: locator, ids: { canonical_object_id: locator } };
  },
  markdown_obsidian: (raw) => {
    const locator = canonicalizeVaultPath(raw.vault_relative_path);
    return { canonical_locator: locator, ids: {} };
  },
  manual_export: (raw) => {
    const id = assertTrustedString(raw.export_id, 'manual_export.export_id');
    if (!/^[a-z0-9][a-z0-9._/-]{0,127}$/i.test(id)) {
      throw new Error('CANONICALIZATION_INPUT_INVALID: manual_export.export_id');
    }
    return { canonical_locator: `manual:${id}`, ids: {} };
  },
};

export function canonicalIdentity(sourceKind, raw) {
  const canonicalizer = CANONICALIZERS[sourceKind];
  if (!canonicalizer) throw new Error(`CANONICALIZATION_UNKNOWN_SOURCE_KIND: ${String(sourceKind)}`);
  const { canonical_locator, ids } = canonicalizer(raw ?? {});
  return { source_kind: sourceKind, canonical_locator, canonicalization_version: CANONICALIZATION_VERSION, ...ids };
}

export function canonicalIdentityFromLocator(locator) {
  return { canonical_locator: assertTrustedString(locator, 'locator') };
}
