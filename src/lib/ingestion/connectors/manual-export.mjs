// manual_export connector — serves pre-prepared offline fixtures and real
// manual exports (saved HTML, saved transcripts, exported chats) without any
// network or credential access. Bytes come from the caller; the connector
// never fetches anything by itself.
import { createHash } from 'node:crypto';
import { canonicalIdentity } from '../canonical.mjs';
import { connectorError } from './base.mjs';

export const MANUAL_EXPORT_CONNECTOR_ID = 'conn-manual-export';
export const MANUAL_EXPORT_CONNECTOR_VERSION = '1.0.0';

export class ManualExportConnector {
  constructor({ exports = new Map(), clock }) {
    this.exports = exports; // Map<exportId, {bytes, mime_type, source_kind, upstream}>
    this.clock = clock;
    this.id = MANUAL_EXPORT_CONNECTOR_ID;
    this.version = MANUAL_EXPORT_CONNECTOR_VERSION;
  }

  discoverCapabilities() {
    return {
      connector_id: this.id,
      connector_version: this.version,
      source_kind: 'manual_export',
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
      limits: { timeout_ms: 5000, max_attempts: 1, max_bytes: 100 * 1024 * 1024 },
      reconciliation: { supported: true, unknown_outcome_policy: 'RECONCILIATION_REQUIRED' },
      terminal_states: ['COMMITTED', 'FAILED', 'QUARANTINED', 'CANCELLED', 'RECONCILIATION_REQUIRED'],
    };
  }

  async resolveDescriptor(request) {
    const identity = canonicalIdentity('manual_export', { export_id: request.locator });
    return {
      source_kind: 'manual_export',
      canonical_locator: identity.canonical_locator,
      display_locator: request.locator,
      connector_id: this.id,
    };
  }

  async fetchVersion(request) {
    const record = this.exports.get(request.locator);
    if (!record) {
      return connectorError('NOT_FOUND', {
        operationId: request.operation_id,
        connectorId: this.id,
        reconciliationAction: 'probe_source',
        detail: `export ${request.locator} is not registered`,
      });
    }
    return {
      ok: true,
      raw: record.bytes,
      mime_type: record.mime_type ?? 'application/octet-stream',
      untrusted_metadata: {
        upstream: record.upstream ?? null,
        body_text: record.text ?? null,
      },
    };
  }

  async extract(snapshotInput, fetched) {
    const text = fetched.untrusted_metadata.body_text;
    if (typeof text !== 'string') {
      // Binary exports without text are one PARTIAL segment; extraction
      // quality must reflect reality instead of fabricating text.
      return [{
        ordinal: 0,
        text: null,
        text_sha256: createHash('sha256').update(fetched.raw).digest('hex'),
        coordinates: { span: { start: 0, end: fetched.raw.length } },
        extraction: {
          method: 'manual_export',
          extractor_name: 'manual-export-passthrough',
          extractor_version: '1.0.0',
          confidence: 0.3,
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
        method: 'manual_export',
        extractor_name: 'manual-export-text',
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
