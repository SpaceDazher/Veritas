// Credential-less connector classes: github, telegram, youtube,
// arxiv_huggingface. Their canonical identity normalization is fully
// implemented and tested against offline fixtures; live access is honestly
// BLOCKED_CONNECTOR until a verified grant exists. An empty successful
// import is impossible: fetchVersion either returns bytes or a normalized
// error.
import { canonicalIdentity } from '../canonical.mjs';
import { connectorError } from './base.mjs';

class BlockedLiveConnector {
  constructor({ connectorId, connectorVersion, sourceKind, requiredGrantScope, fixtureFetch = null }) {
    this.id = connectorId;
    this.version = connectorVersion;
    this.sourceKind = sourceKind;
    this.requiredGrantScope = requiredGrantScope;
    // fixtureFetch: injectable offline fixture source so identity + extraction
    // semantics stay testable without any live credential.
    this.fixtureFetch = fixtureFetch;
    this.clock = null;
  }

  discoverCapabilities() {
    return {
      connector_id: this.id,
      connector_version: this.version,
      source_kind: this.sourceKind,
      auth_mode: this.fixtureFetch ? 'none' : 'blocked_without_credential',
      read_only: true,
      operations: {
        discoverCapabilities: true,
        resolveDescriptor: true,
        fetchVersion: true,
        extract: true,
        reconcile: true,
        observeDeletion: true,
      },
      limits: { timeout_ms: 30000, max_attempts: 3, max_bytes: 50 * 1024 * 1024 },
      reconciliation: { supported: true, unknown_outcome_policy: 'RECONCILIATION_REQUIRED' },
      terminal_states: ['COMMITTED', 'BLOCKED_CONNECTOR', 'FAILED', 'QUARANTINED', 'CANCELLED', 'RECONCILIATION_REQUIRED'],
    };
  }

  resolveDescriptor(request) {
    const identity = canonicalIdentity(this.sourceKind, request.identity ?? { url: request.locator });
    return {
      source_kind: this.sourceKind,
      canonical_locator: identity.canonical_locator,
      display_locator: request.locator,
      connector_id: this.id,
    };
  }

  async fetchVersion(request) {
    if (this.fixtureFetch) {
      const fixture = this.fixtureFetch(request);
      if (fixture) {
        return {
          ok: true,
          raw: fixture.bytes,
          mime_type: fixture.mime_type ?? 'application/json',
          untrusted_metadata: { upstream: fixture.upstream ?? null, body_text: fixture.text ?? null },
        };
      }
      return connectorError('NOT_FOUND', {
        operationId: request.operation_id,
        connectorId: this.id,
        reconciliationAction: 'probe_source',
        detail: 'no offline fixture for this identity',
      });
    }
    return connectorError('BLOCKED_CONNECTOR', {
      operationId: request.operation_id,
      connectorId: this.id,
      retryable: false,
      reconciliationAction: 'manual_review',
      detail: `live ${this.sourceKind} access requires a verified grant for scope ${this.requiredGrantScope}; none is configured`,
    });
  }

  async extract(snapshotInput, fetched) {
    const text = fetched.untrusted_metadata.body_text;
    if (typeof text !== 'string' || text.length === 0) {
      return [{
        ordinal: 0,
        text: null,
        coordinates: { span: { start: 0, end: fetched.raw.length } },
        extraction: {
          method: 'parser',
          extractor_name: `${this.sourceKind}-fixture-parser`,
          extractor_version: '1.0.0',
          confidence: 0.4,
          uncertainty_flags: ['LOW_CONFIDENCE', 'TRUNCATED'],
        },
        status: 'PARTIAL',
      }];
    }
    return text.split(/\n{2,}/).filter((block) => block.trim().length > 0).map((block, index) => ({
      ordinal: index,
      text: block.trim(),
      coordinates: { span: { start: 0, end: block.length } },
      extraction: {
        method: 'parser',
        extractor_name: `${this.sourceKind}-fixture-parser`,
        extractor_version: '1.0.0',
        confidence: 1,
        uncertainty_flags: [],
      },
    }));
  }

  async reconcile(operationId) {
    return { operation_id: operationId, connector_id: this.id, known: false };
  }

  async observeDeletion() {
    return { deleted: false };
  }
}

export function createGithubConnector(options = {}) {
  return new BlockedLiveConnector({
    connectorId: 'conn-github',
    connectorVersion: '1.0.0',
    sourceKind: 'github',
    requiredGrantScope: 'source.github.read',
    ...options,
  });
}

export function createTelegramConnector(options = {}) {
  return new BlockedLiveConnector({
    connectorId: 'conn-telegram',
    connectorVersion: '1.0.0',
    sourceKind: 'telegram',
    requiredGrantScope: 'source.telegram.read',
    ...options,
  });
}

export function createYoutubeConnector(options = {}) {
  return new BlockedLiveConnector({
    connectorId: 'conn-youtube',
    connectorVersion: '1.0.0',
    sourceKind: 'youtube',
    requiredGrantScope: 'source.youtube.read',
    ...options,
  });
}

export function createArxivHuggingfaceConnector(options = {}) {
  return new BlockedLiveConnector({
    connectorId: 'conn-arxiv-huggingface',
    connectorVersion: '1.0.0',
    sourceKind: 'arxiv_huggingface',
    requiredGrantScope: 'source.arxiv_huggingface.read',
    ...options,
  });
}

export const CONNECTOR_REGISTRY = Object.freeze({
  markdown_obsidian: { connector_id: 'conn-markdown-obsidian', executable: true },
  manual_export: { connector_id: 'conn-manual-export', executable: true },
  web_url: { connector_id: 'conn-web-url', executable: true },
  github: { connector_id: 'conn-github', executable: false },
  telegram: { connector_id: 'conn-telegram', executable: false },
  youtube: { connector_id: 'conn-youtube', executable: false },
  arxiv_huggingface: { connector_id: 'conn-arxiv-huggingface', executable: false },
});
