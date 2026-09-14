// markdown_obsidian connector — the only adapter that touches a real vault.
// Invariants:
//   - the vault is opened strictly read-only: no write, rename or delete
//     syscall exists on this code path (enforced by test: byte-identity of
//     the vault before/after ingestion);
//   - identity is the vault-relative path, never the absolute host path;
//   - frontmatter is untrusted data: it can describe the document but can
//     never change ACL, workspace, policy or lifecycle.
import fs from 'node:fs';
import path from 'node:path';
import { canonicalIdentity } from '../canonical.mjs';
import { connectorError, assertConnectorShape } from './base.mjs';

export const MARKDOWN_OBSIDIAN_CONNECTOR_ID = 'conn-markdown-obsidian';
export const MARKDOWN_OBSIDIAN_CONNECTOR_VERSION = '1.0.0';

const ALLOWED_EXTENSIONS = new Set(['.md', '.markdown', '.mdx', '.txt']);

export class MarkdownObsidianConnector {
  constructor({ vaultRoot, clock }) {
    if (typeof vaultRoot !== 'string' || vaultRoot.length === 0) throw new Error('VAULT_ROOT_REQUIRED');
    this.vaultRoot = fs.realpathSync(path.resolve(vaultRoot));
    this.realVaultRoot = this.vaultRoot;
    this.clock = clock;
    this.id = MARKDOWN_OBSIDIAN_CONNECTOR_ID;
    this.version = MARKDOWN_OBSIDIAN_CONNECTOR_VERSION;
  }

  discoverCapabilities() {
    return {
      connector_id: this.id,
      connector_version: this.version,
      source_kind: 'markdown_obsidian',
      auth_mode: 'none',
      read_only: true,
      operations: {
        discoverCapabilities: true,
        resolveDescriptor: true,
        fetchVersion: true,
        extract: true,
        reconcile: true,
        observeDeletion: true,
      },
      limits: { timeout_ms: 10000, max_attempts: 2, max_bytes: 50 * 1024 * 1024 },
      reconciliation: { supported: true, unknown_outcome_policy: 'RECONCILIATION_REQUIRED' },
      terminal_states: ['COMMITTED', 'FAILED', 'QUARANTINED', 'CANCELLED', 'RECONCILIATION_REQUIRED'],
    };
  }

  // Vault-relative path only; traversal outside the root is rejected.
  // #safeResolveInfo returns { absolute, realpath } or null when missing.
  // Both the lexical path AND the realpath (symlink/junction target) must
  // stay inside the vault: readFileSync follows links, so the lexical check
  // alone is not enough.
  #safeResolveInfo(vaultRelativePath) {
    const normalized = String(vaultRelativePath).replace(/\\/g, '/');
    if (normalized.split('/').includes('..')) throw new Error('VAULT_PATH_TRAVERSAL');
    const absolute = path.resolve(this.vaultRoot, normalized);
    if (!absolute.startsWith(this.vaultRoot + path.sep) && absolute !== this.vaultRoot) {
      throw new Error('VAULT_PATH_ESCAPE');
    }
    let realpath = null;
    try {
      realpath = fs.realpathSync(absolute);
    } catch (error) {
      if (error?.code === 'ENOENT') return { absolute, realpath: null };
      throw error;
    }
    const realRoot = this.realVaultRoot;
    if (realpath !== realRoot && !realpath.startsWith(realRoot + path.sep)) {
      throw new Error('VAULT_PATH_SYMLINK_ESCAPE');
    }
    return { absolute, realpath };
  }

  async resolveDescriptor(request) {
    const info = this.#safeResolveInfo(request.locator);
    const relative = path.relative(this.vaultRoot, info.absolute).split(path.sep).join('/');
    const identity = canonicalIdentity('markdown_obsidian', { vault_relative_path: relative });
    return {
      source_kind: 'markdown_obsidian',
      canonical_locator: identity.canonical_locator,
      display_locator: relative,
      connector_id: this.id,
    };
  }

  // Returns raw bytes + metadata, or a normalized connector error.
  async fetchVersion(request) {
    try {
      const info = this.#safeResolveInfo(request.locator);
      if (info.realpath === null) {
        return connectorError('NOT_FOUND', {
          operationId: request.operation_id,
          connectorId: this.id,
          reconciliationAction: 'probe_source',
          detail: `vault entry ${request.locator} does not exist`,
        });
      }
      const absolute = info.absolute;
      const extension = path.extname(absolute).toLowerCase();
      if (!ALLOWED_EXTENSIONS.has(extension)) {
        return connectorError('UNSUPPORTED_FORMAT', {
          operationId: request.operation_id,
          connectorId: this.id,
          retryable: false,
          reconciliationAction: 'manual_review',
          detail: `extension ${extension || '(none)'} is not a vault text format`,
        });
      }
      let bytes;
      try {
        bytes = fs.readFileSync(absolute);
      } catch (error) {
        const code = error?.code === 'ENOENT' ? 'NOT_FOUND' : error?.code === 'EACCES' ? 'ACCESS_DENIED' : 'FAILED_READ';
        if (code === 'FAILED_READ') {
          return connectorError('MALFORMED_CONTENT', { operationId: request.operation_id, connectorId: this.id, detail: error.message });
        }
        return connectorError(code, {
          operationId: request.operation_id,
          connectorId: this.id,
          retryable: code === 'ACCESS_DENIED',
          reconciliationAction: code === 'NOT_FOUND' ? 'probe_source' : 'manual_review',
          detail: error.message,
        });
      }
      const { frontmatter, body } = parseFrontmatter(bytes.toString('utf8'));
      assertConnectorShape({ frontmatter, body });
      return {
        ok: true,
        raw: bytes,
        mime_type: 'text/markdown',
        // Frontmatter is data, never configuration: only descriptive fields
        // are surfaced, and the pipeline validates them against the descriptor.
        untrusted_metadata: {
          frontmatter,
          body_text: body,
        },
      };
    } catch (error) {
      if (error?.message?.startsWith('VAULT_PATH_')) {
        return connectorError('ACCESS_DENIED', { operationId: request.operation_id, connectorId: this.id, detail: error.message });
      }
      throw error;
    }
  }

  // Extraction for vault text is native: one segment per logical block.
  async extract(snapshotInput, fetched) {
    const text = fetched.untrusted_metadata.body_text;
    const blocks = splitBlocks(text);
    return blocks.map((block, index) => ({
      ordinal: index,
      text: block,
      coordinates: { line: { start: block.startLine + 1, end: block.endLine + 1 } },
      extraction: {
        method: 'native_text',
        extractor_name: 'markdown-native',
        extractor_version: '1.0.0',
        confidence: 1,
        uncertainty_flags: [],
      },
    }));
  }

  async reconcile(operationId) {
    return { operation_id: operationId, connector_id: this.id, known: false };
  }

  async observeDeletion(sourceId, locator) {
    try {
      const info = this.#safeResolveInfo(locator);
      return { deleted: info.realpath === null };
    } catch {
      return { deleted: false };
    }
  }
}

// Minimal frontmatter split: a leading --- block. Parsed values stay strings;
// nothing here is ever interpreted as configuration.
export function parseFrontmatter(text) {
  if (!text.startsWith('---')) {
    return { frontmatter: {}, body: text };
  }
  const endIndex = text.indexOf('\n---', 3);
  if (endIndex < 0) return { frontmatter: {}, body: text };
  const header = text.slice(4, endIndex);
  const body = text.slice(text.indexOf('\n', endIndex + 1) + 1);
  const frontmatter = {};
  for (const line of header.split('\n')) {
    const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (match) frontmatter[match[1]] = match[2].trim();
  }
  return { frontmatter, body };
}

export function splitBlocks(text) {
  const lines = text.split('\n');
  const blocks = [];
  let current = [];
  let startLine = 0;
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i].trim() === '' && current.length > 0) {
      blocks.push({ text: current.join('\n').trim(), startLine, endLine: i - 1 });
      current = [];
    } else if (lines[i].trim() !== '') {
      if (current.length === 0) startLine = i;
      current.push(lines[i]);
    }
  }
  if (current.length > 0) {
    blocks.push({ text: current.join('\n').trim(), startLine, endLine: lines.length - 1 });
  }
  return blocks.filter((block) => block.text.length > 0);
}
