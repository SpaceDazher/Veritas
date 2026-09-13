// web_url connector — public HTTP snapshot adapter.
// No cookies, no user credentials, no session state. Content-type is
// validated before parse; private or authenticated material cannot arrive
// through this adapter because no credential channel exists.
import { canonicalIdentity } from '../canonical.mjs';
import { connectorError } from './base.mjs';

export const HTTP_SNAPSHOT_CONNECTOR_ID = 'conn-web-url';
export const HTTP_SNAPSHOT_CONNECTOR_VERSION = '1.0.0';

const ALLOWED_CONTENT_TYPES = new Set(['text/html', 'text/plain', 'application/xhtml+xml', 'text/markdown']);

export class HttpSnapshotConnector {
  constructor({ fetchFn, clock }) {
    if (typeof fetchFn !== 'function') throw new Error('FETCH_FN_REQUIRED');
    this.fetchFn = fetchFn;
    this.clock = clock;
    this.id = HTTP_SNAPSHOT_CONNECTOR_ID;
    this.version = HTTP_SNAPSHOT_CONNECTOR_VERSION;
  }

  discoverCapabilities() {
    return {
      connector_id: this.id,
      connector_version: this.version,
      source_kind: 'web_url',
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
      limits: { timeout_ms: 30000, max_attempts: 3, max_bytes: 20 * 1024 * 1024, rate_limit_per_minute: 30 },
      reconciliation: { supported: true, unknown_outcome_policy: 'RECONCILIATION_REQUIRED' },
      terminal_states: ['COMMITTED', 'FAILED', 'QUARANTINED', 'CANCELLED', 'RECONCILIATION_REQUIRED'],
    };
  }

  async resolveDescriptor(request) {
    const identity = canonicalIdentity('web_url', { url: request.locator });
    return {
      source_kind: 'web_url',
      canonical_locator: identity.canonical_locator,
      display_locator: request.locator,
      connector_id: this.id,
    };
  }

  async fetchVersion(request) {
    let response;
    try {
      response = await this.fetchFn(request.locator, {
        method: 'GET',
        redirect: 'follow',
        signal: request.signal,
        headers: { 'user-agent': 'veritas-ingestion/1.0 (+read-only-snapshot)' },
      });
    } catch (error) {
      if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
        return connectorError('TIMEOUT', {
          operationId: request.operation_id,
          connectorId: this.id,
          retryable: true,
          reconciliationAction: 'retry_with_backoff',
          detail: 'fetch exceeded the configured time limit',
        });
      }
      if (error instanceof UnknownOutcomeBridge) {
        return connectorError('UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED', {
          operationId: request.operation_id,
          connectorId: this.id,
          detail: error.message,
        });
      }
      return connectorError('BLOCKED_CONNECTOR', {
        operationId: request.operation_id,
        connectorId: this.id,
        retryable: true,
        reconciliationAction: 'retry_with_backoff',
        detail: `network failure: ${error?.message ?? 'unknown'}`,
      });
    }
    if (response.status === 401 || response.status === 403) {
      return connectorError('ACCESS_DENIED', {
        operationId: request.operation_id,
        connectorId: this.id,
        reconciliationAction: 'manual_review',
        detail: `HTTP ${response.status}`,
      });
    }
    if (response.status === 404 || response.status === 410) {
      return connectorError(response.status === 410 ? 'TOMBSTONED' : 'NOT_FOUND', {
        operationId: request.operation_id,
        connectorId: this.id,
        reconciliationAction: 'probe_source',
        detail: `HTTP ${response.status}`,
      });
    }
    if (response.status === 429) {
      return connectorError('RATE_LIMITED', {
        operationId: request.operation_id,
        connectorId: this.id,
        retryable: true,
        reconciliationAction: 'retry_with_backoff',
        detail: 'HTTP 429 rate limited',
      });
    }
    if (!response.ok) {
      // Closed enum: an upstream 5xx is a connector that cannot currently do
      // its job — retryable, bounded, never a silent success.
      return connectorError('BLOCKED_CONNECTOR', {
        operationId: request.operation_id,
        connectorId: this.id,
        retryable: true,
        reconciliationAction: 'retry_with_backoff',
        detail: `HTTP ${response.status} from upstream`,
      });
    }
    const contentType = String(response.headers?.get?.('content-type') ?? '').split(';')[0].trim().toLowerCase();
    if (!ALLOWED_CONTENT_TYPES.has(contentType)) {
      return connectorError('UNSUPPORTED_FORMAT', {
        operationId: request.operation_id,
        connectorId: this.id,
        reconciliationAction: 'manual_review',
        detail: `content-type ${contentType || '(missing)'} is not an allowed public text type`,
      });
    }
    const buffer = Buffer.from(await response.arrayBuffer());
    return {
      ok: true,
      raw: buffer,
      mime_type: contentType,
      untrusted_metadata: {
        final_url: response.url ?? request.locator,
        body_text: buffer.toString('utf8'),
      },
    };
  }

  async extract(snapshotInput, fetched) {
    const html = fetched.untrusted_metadata.body_text ?? '';
    const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const bodyText = stripHtml(html);
    return [{
      ordinal: 0,
      text: bodyText,
      coordinates: { span: { start: 0, end: bodyText.length } },
      extraction: {
        method: 'parser',
        extractor_name: 'html-text-parser',
        extractor_version: '1.0.0',
        config_sha256: null,
        confidence: 0.95,
        uncertainty_flags: [],
      },
      title: titleMatch ? titleMatch[1].trim() : null,
    }];
  }

  async reconcile(operationId) {
    return { operation_id: operationId, connector_id: this.id, known: false };
  }

  async observeDeletion(sourceId, locator, fetchFn) {
    try {
      const response = await this.fetchFn(locator, { method: 'HEAD' });
      return { deleted: response.status === 404 || response.status === 410 };
    } catch {
      return { deleted: false };
    }
  }
}

export class UnknownOutcomeBridge extends Error {}

export function stripHtml(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\s+/g, ' ')
    .trim();
}
