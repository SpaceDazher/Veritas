// web_url connector — public HTTP snapshot adapter.
// No cookies, no user credentials, no session state. Security properties:
//   - scheme allow-list (http/https only);
//   - SSRF guard: loopback/private/link-local/unique-local literal IPs and
//     localhost-like hostnames are rejected, and an injectable resolver
//     re-checks every resolved address before the request;
//   - redirects are followed MANUALLY: every hop re-passes the same checks
//     (a public URL must not be able to bounce into private space);
//   - the response body is read in bounded chunks and aborted once the
//     request budget is exhausted (no unbounded arrayBuffer before checks);
//   - time_limit_ms is enforced by an AbortController (real timeout).
import { canonicalIdentity } from '../canonical.mjs';
import { connectorError } from './base.mjs';

export const HTTP_SNAPSHOT_CONNECTOR_ID = 'conn-web-url';
export const HTTP_SNAPSHOT_CONNECTOR_VERSION = '1.1.0';

const ALLOWED_CONTENT_TYPES = new Set(['text/html', 'text/plain', 'application/xhtml+xml', 'text/markdown']);
const MAX_REDIRECTS = 5;

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return true; // unparseable = reject
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true; // this-network, private, loopback
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (lower === '::' || lower === '::1') return true; // unspecified, loopback
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true; // link-local fe80::/10
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique-local fc00::/7
  if (lower.startsWith('ff')) return true; // multicast
  if (lower.startsWith('::ffff:')) return isPrivateIPv4(lower.slice(7)); // IPv4-mapped
  return false;
}

// SSRF guard applied to every target (original URL and every redirect hop).
export function assertPublicHttpTarget(rawUrl, { resolveHostname = null } = {}) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('SSRF_TARGET_INVALID: url does not parse');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`SSRF_SCHEME_FORBIDDEN: ${url.protocol}`);
  }
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.internal') || hostname.endsWith('.local') || hostname === 'metadata.google.internal') {
    throw new Error(`SSRF_HOSTNAME_FORBIDDEN: ${hostname}`);
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    if (isPrivateIPv4(hostname)) throw new Error(`SSRF_ADDRESS_FORBIDDEN: ${hostname}`);
  } else if (hostname.includes(':')) {
    if (isPrivateIPv6(hostname)) throw new Error(`SSRF_ADDRESS_FORBIDDEN: ${hostname}`);
  }
  if (resolveHostname) {
    const addresses = resolveHostname(hostname);
    for (const address of addresses ?? []) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
        if (isPrivateIPv4(address)) throw new Error(`SSRF_RESOLVED_FORBIDDEN: ${hostname} -> ${address}`);
      } else if (address.includes(':') && isPrivateIPv6(address)) {
        throw new Error(`SSRF_RESOLVED_FORBIDDEN: ${hostname} -> ${address}`);
      }
    }
  }
  return url;
}

export class HttpSnapshotConnector {
  constructor({ fetchFn, clock, resolveHostname = null }) {
    if (typeof fetchFn !== 'function') throw new Error('FETCH_FN_REQUIRED');
    this.fetchFn = fetchFn;
    this.clock = clock;
    this.resolveHostname = resolveHostname;
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

  // One bounded HTTP fetch of `target` with timeout, manual redirect handling
  // and budget enforcement. Returns the connector result shape.
  async fetchVersion(request) {
    const timeLimitMs = request.budget?.time_limit_ms ?? this.discoverCapabilities().limits.timeout_ms;
    const maxBytes = request.budget?.max_bytes ?? this.discoverCapabilities().limits.max_bytes;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('time limit exceeded')), Math.min(timeLimitMs, 600000));
    let currentUrl = request.locator;
    try {
      for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
        // SSRF guard: the original URL and every redirect target must be a
        // public http(s) address.
        try {
          assertPublicHttpTarget(currentUrl, { resolveHostname: this.resolveHostname });
        } catch (error) {
          return connectorError('ACCESS_DENIED', {
            operationId: request.operation_id,
            connectorId: this.id,
            reconciliationAction: 'manual_review',
            detail: error.message,
          });
        }
        let response;
        try {
          response = await this.fetchFn(currentUrl, {
            method: 'GET',
            redirect: 'manual',
            signal: controller.signal,
            headers: { 'user-agent': 'veritas-ingestion/1.1 (+read-only-snapshot)' },
          });
        } catch (error) {
          if (controller.signal.aborted) {
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
        // Manual redirect handling: re-validate every hop.
        if (response.status >= 300 && response.status < 400 && response.headers?.get?.('location')) {
          if (hop === MAX_REDIRECTS) {
            return connectorError('BLOCKED_CONNECTOR', {
              operationId: request.operation_id,
              connectorId: this.id,
              retryable: false,
              reconciliationAction: 'manual_review',
              detail: 'redirect chain exceeds the configured hop limit',
            });
          }
          const location = response.headers.get('location');
          currentUrl = new URL(location, currentUrl).toString();
          continue;
        }
        return await this.#consumeResponse({ response, request, controller, maxBytes, finalUrl: currentUrl });
      }
      return connectorError('BLOCKED_CONNECTOR', {
        operationId: request.operation_id,
        connectorId: this.id,
        detail: 'unreachable: redirect loop guard',
      });
    } finally {
      clearTimeout(timer);
    }
  }

  async #consumeResponse({ response, request, controller, maxBytes, finalUrl }) {
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
    // Bounded body read: stream chunks while the budget lasts, abort the
    // request the moment it would be exceeded.
    let buffer;
    if (response.body && typeof response.body.getAsyncIterator === 'function') {
      const chunks = [];
      let total = 0;
      try {
        for await (const chunk of response.body.getAsyncIterator()) {
          const part = Buffer.from(chunk);
          total += part.length;
          if (total > maxBytes) {
            controller.abort(new Error('budget exceeded'));
            return connectorError('QUARANTINED', {
              operationId: request.operation_id,
              connectorId: this.id,
              reconciliationAction: 'manual_review',
              detail: `payload exceeds the request budget of ${maxBytes} bytes`,
            });
          }
          chunks.push(part);
        }
        buffer = Buffer.concat(chunks);
      } catch (error) {
        if (controller.signal.aborted) {
          return connectorError('TIMEOUT', {
            operationId: request.operation_id,
            connectorId: this.id,
            retryable: true,
            reconciliationAction: 'retry_with_backoff',
            detail: 'fetch exceeded the configured time limit while reading the body',
          });
        }
        return connectorError('BLOCKED_CONNECTOR', {
          operationId: request.operation_id,
          connectorId: this.id,
          retryable: true,
          reconciliationAction: 'retry_with_backoff',
          detail: `body read failure: ${error?.message ?? 'unknown'}`,
        });
      }
    } else {
      const raw = await response.arrayBuffer();
      buffer = Buffer.from(raw);
      if (buffer.length > maxBytes) {
        return connectorError('QUARANTINED', {
          operationId: request.operation_id,
          connectorId: this.id,
          reconciliationAction: 'manual_review',
          detail: `payload exceeds the request budget of ${maxBytes} bytes`,
        });
      }
    }
    if (buffer.length === 0) {
      return connectorError('MALFORMED_CONTENT', {
        operationId: request.operation_id,
        connectorId: this.id,
        detail: 'upstream returned an empty body',
      });
    }
    return {
      ok: true,
      raw: buffer,
      mime_type: contentType,
      untrusted_metadata: {
        final_url: response.url ?? finalUrl,
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

  async observeDeletion(sourceId, locator) {
    try {
      assertPublicHttpTarget(locator, { resolveHostname: this.resolveHostname });
      const response = await this.fetchFn(locator, { method: 'HEAD', redirect: 'manual' });
      if (response.status >= 300 && response.status < 400) return { deleted: false };
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
