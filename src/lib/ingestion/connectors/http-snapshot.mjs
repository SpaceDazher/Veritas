// web_url connector — public HTTP snapshot adapter.
// No cookies, no user credentials, no session state. Security properties:
//   - scheme allow-list (http/https only);
//   - SSRF guard: loopback/private/link-local/unique-local literal IPs and
//     localhost-like hostnames are rejected; DNS resolution is MANDATORY
//     (default: node:dns lookup with all addresses) and every resolved
//     address re-passes the same check;
//   - DNS TOCTOU: on the production transport the resolved address is the
//     ONLY address the connection can use — the https/http Agent lookup hook
//     re-validates every address at connect time, so a rebinding DNS answer
//     cannot steer the socket elsewhere;
//   - redirects are followed MANUALLY: every hop re-passes the same checks;
//   - the response body is read in bounded chunks (getReader when available,
//     transport-level byte counting otherwise) and aborted once the request
//     budget is exhausted;
//   - time_limit_ms is enforced by an AbortController (real timeout).
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import { canonicalIdentity } from '../canonical.mjs';
import { connectorError } from './base.mjs';

export const HTTP_SNAPSHOT_CONNECTOR_ID = 'conn-web-url';
export const HTTP_SNAPSHOT_CONNECTOR_VERSION = '1.2.0';

const ALLOWED_CONTENT_TYPES = new Set(['text/html', 'text/plain', 'application/xhtml+xml', 'text/markdown']);
const MAX_REDIRECTS = 5;

// Default mandatory resolver: real DNS, every address returned.
export function defaultResolveHostname(hostname) {
  return dns.promises.lookup(hostname, { all: true, verbatim: true }).then((rows) => rows.map((r) => r.address));
}

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
  constructor({ fetchFn = null, clock, resolveHostname = defaultResolveHostname }) {
    this.fetchFn = fetchFn; // injectable offline transport (fixtures/tests); production uses the pinned node transport
    this.clock = clock;
    this.resolveHostname = resolveHostname; // mandatory by default: real DNS
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
    const timeLimitMs = request.budget?.time_limit_ms ?? this.discoverCapabilities().limits.timeout_ms;
    const maxBytes = request.budget?.max_bytes ?? this.discoverCapabilities().limits.max_bytes;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('time limit exceeded')), Math.min(timeLimitMs, 600000));
    let currentUrl = request.locator;
    try {
      for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
        // SSRF guard: the original URL and every redirect target must be a
        // public http(s) address; the mandatory resolver re-checks DNS.
        try {
          await assertPublicHttpTargetAsync(currentUrl, { resolveHostname: this.resolveHostname });
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
          if (this.fetchFn) {
            // Injectable offline transport (fixtures/tests): same checks, no
            // network. Budget enforcement still applies to the returned body.
            response = await this.fetchFn(currentUrl, {
              method: 'GET',
              redirect: 'manual',
              signal: controller.signal,
              headers: { 'user-agent': 'veritas-ingestion/1.2 (+read-only-snapshot)' },
            });
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
              currentUrl = new URL(response.headers.get('location'), currentUrl).toString();
              continue;
            }
            return await this.#consumeInjectedResponse({ response, request, controller, maxBytes, finalUrl: currentUrl });
          }
          // Production transport: node http/https with a lookup hook — the
          // resolved-and-validated address is the only address the socket can
          // use, which closes the DNS rebinding window (no TOCTOU).
          response = await boundedNodeRequest(currentUrl, {
            controller,
            timeoutMs: timeLimitMs,
            maxBytes,
            resolveHostname: this.resolveHostname,
          });
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
            currentUrl = new URL(response.headers.get('location'), currentUrl).toString();
            continue;
          }
          return await this.#consumeNodeResponse({ response, request });
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
          if (/^SSRF_/.test(error?.message ?? '')) {
            return connectorError('ACCESS_DENIED', {
              operationId: request.operation_id,
              connectorId: this.id,
              reconciliationAction: 'manual_review',
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

  // Injected-transport body: streaming when the mock provides a Web stream,
  // buffered otherwise; budget enforced in both cases.
  async #consumeInjectedResponse({ response, request, controller, maxBytes, finalUrl }) {
    const contentType = String(response.headers?.get?.('content-type') ?? '').split(';')[0].trim().toLowerCase();
    const statusFailure = this.#statusFailure(request, response.status, contentType);
    if (statusFailure) return statusFailure;
    let buffer;
    if (response.body && typeof response.body.getReader === 'function') {
      const read = await readWebStreamBounded(response.body.getReader(), maxBytes, controller);
      if (read.exceeded) {
        return connectorError('QUARANTINED', {
          operationId: request.operation_id,
          connectorId: this.id,
          reconciliationAction: 'manual_review',
          detail: `payload exceeds the request budget of ${maxBytes} bytes`,
        });
      }
      buffer = read.buffer;
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

  #statusFailure(request, status, contentType) {
    if (status === 401 || status === 403) {
      return connectorError('ACCESS_DENIED', { operationId: request.operation_id, connectorId: this.id, reconciliationAction: 'manual_review', detail: `HTTP ${status}` });
    }
    if (status === 404 || status === 410) {
      return connectorError(status === 410 ? 'TOMBSTONED' : 'NOT_FOUND', { operationId: request.operation_id, connectorId: this.id, reconciliationAction: 'probe_source', detail: `HTTP ${status}` });
    }
    if (status === 429) {
      return connectorError('RATE_LIMITED', { operationId: request.operation_id, connectorId: this.id, retryable: true, reconciliationAction: 'retry_with_backoff', detail: 'HTTP 429 rate limited' });
    }
    if (status < 200 || status > 299) {
      return connectorError('BLOCKED_CONNECTOR', { operationId: request.operation_id, connectorId: this.id, retryable: true, reconciliationAction: 'retry_with_backoff', detail: `HTTP ${status} from upstream` });
    }
    if (!ALLOWED_CONTENT_TYPES.has(contentType)) {
      return connectorError('UNSUPPORTED_FORMAT', { operationId: request.operation_id, connectorId: this.id, reconciliationAction: 'manual_review', detail: `content-type ${contentType || '(missing)'} is not an allowed public text type` });
    }
    return null;
  }

  // Production transport response: bytes were already bounded at the socket.
  async #consumeNodeResponse({ response, request }) {
    const contentType = response.contentType;
    const statusFailure = this.#statusFailure(request, response.status, contentType);
    if (statusFailure) return statusFailure;
    if (response.budgetExceeded) {
      return connectorError('QUARANTINED', {
        operationId: request.operation_id,
        connectorId: this.id,
        reconciliationAction: 'manual_review',
        detail: `payload exceeds the request budget of ${response.maxBytes} bytes`,
      });
    }
    const buffer = response.bytes;
    if (!buffer || buffer.length === 0) {
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
        final_url: response.url,
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
      await assertPublicHttpTargetAsync(locator, { resolveHostname: this.resolveHostname });
      const response = await boundedNodeRequest(locator, {
        controller: new AbortController(),
        timeoutMs: 15000,
        maxBytes: 1,
        resolveHostname: this.resolveHostname,
        method: 'HEAD',
      });
      if (response.status >= 300 && response.status < 400) return { deleted: false };
      return { deleted: response.status === 404 || response.status === 410 };
    } catch {
      return { deleted: false };
    }
  }
}

export class UnknownOutcomeBridge extends Error {}

// Async canonical guard: awaits the mandatory resolver and re-checks every
// returned address against the private-range rules.
export async function assertPublicHttpTargetAsync(rawUrl, { resolveHostname = null } = {}) {
  const { url, hostname } = assertPublicHttpTarget(rawUrl, {});
  if (resolveHostname) {
    const addresses = await Promise.resolve(resolveHostname(hostname));
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


// Validating lookup hook: THE single address source for the socket. DNS
// answers that fail the SSRF check reject the connection itself.
function validatingLookup(resolveHostname, allowedFamilies) {
  return (hostname, options, callback) => {
    Promise.resolve()
      .then(() => resolveHostname(hostname))
      .then((addresses) => {
        const checked = [];
        for (const address of addresses ?? []) {
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
            if (isPrivateIPv4(address)) {
              callback(new Error(`SSRF_RESOLVED_FORBIDDEN: ${hostname} -> ${address}`));
              return;
            }
            checked.push({ address, family: 4 });
          } else if (address.includes(':')) {
            if (isPrivateIPv6(address)) {
              callback(new Error(`SSRF_RESOLVED_FORBIDDEN: ${hostname} -> ${address}`));
              return;
            }
            checked.push({ address, family: 6 });
          }
        }
        if (checked.length === 0) {
          callback(new Error(`SSRF_RESOLVED_EMPTY: ${hostname}`));
          return;
        }
        const pick = checked.find((c) => !options || !options.family || c.family === options.family) ?? checked[0];
        callback(null, pick.address, pick.family);
      })
      .catch((error) => callback(error));
  };
}

// Production transport: node http/https with the validating lookup hook,
// bounded byte counting at the socket and hard timeout.
function boundedNodeRequest(rawUrl, { controller, timeoutMs, maxBytes, resolveHostname, maxRedirects = MAX_REDIRECTS, method = 'GET' }) {
  return new Promise((resolve, reject) => {
    const attempt = (urlText, hops) => {
      let target;
      try {
        target = new URL(urlText);
      } catch (error) {
        reject(error);
        return;
      }
      const lookup = validatingLookup(resolveHostname);
      const transport = target.protocol === 'https:' ? https : http;
      const agent = new transport.Agent({ keepAlive: false, lookup, maxSockets: 1 });
      const req = transport.request(target, {
        method,
        agent,
        headers: { 'user-agent': 'veritas-ingestion/1.2 (+read-only-snapshot)', host: target.host },
        signal: controller.signal,
      }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          if (hops >= maxRedirects) {
            reject(new Error('redirect chain exceeds the configured hop limit'));
            return;
          }
          attempt(new URL(res.headers.location, target).toString(), hops + 1);
          return;
        }
        const chunks = [];
        let total = 0;
        let exceeded = false;
        res.on('data', (chunk) => {
          total += chunk.length;
          if (total > maxBytes) {
            exceeded = true;
            req.destroy(new Error('budget exceeded'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            contentType: String(res.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase(),
            headers: { get: (k) => res.headers[String(k).toLowerCase()] ?? null },
            url: urlText,
            bytes: exceeded ? null : Buffer.concat(chunks),
            budgetExceeded: exceeded,
            maxBytes,
          });
        });
        res.on('error', (error) => {
          if (controller.signal.aborted) reject(Object.assign(new Error('time limit exceeded'), { name: 'AbortError' }));
          else reject(error);
        });
      });
      req.on('error', (error) => {
        if (controller.signal.aborted) reject(Object.assign(new Error('time limit exceeded'), { name: 'AbortError' }));
        else reject(error);
      });
      req.setTimeout(timeoutMs, () => {
        controller.abort(new Error('time limit exceeded'));
        req.destroy(new Error('time limit exceeded'));
      });
      req.end();
    };
    attempt(rawUrl, 0);
  });
}

async function readWebStreamBounded(reader, maxBytes, controller) {
  const chunks = [];
  let total = 0;
  let exceeded = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const part = Buffer.from(value);
    total += part.length;
    if (total > maxBytes) {
      exceeded = true;
      controller.abort(new Error('budget exceeded'));
      break;
    }
    chunks.push(part);
  }
  return { buffer: Buffer.concat(chunks), exceeded, total };
}

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
