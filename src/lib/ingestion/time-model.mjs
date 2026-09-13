// S2-003 temporal model.
// Four separate notions of time exist and must never be conflated:
//   published_at — claimed publication time (source's own claim);
//   event_time   — time of the event the source describes (source's claim);
//   observed_at  — when the ingestion system first observed this version;
//   fetched_at   — operational telemetry of the fetch itself.
// Only observed_at/fetched_at come from the host. Both are audit-only: they
// can never change content digests, identity, dedup verdicts or evaluators.
// Deterministic replay with a different clock must produce identical
// identity, lineage and decisions, so every decision-facing structure here is
// derived exclusively from caller-supplied values.
import { createHash } from 'node:crypto';

const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function assertUtcTimestamp(value, label) {
  if (typeof value !== 'string' || !UTC_TIMESTAMP_PATTERN.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new Error(`INVALID_TIMESTAMP: ${label}`);
  }
  // Reject calendar roll-over (e.g. 2026-02-30 parses to 2026-03-02).
  if (new Date(Date.parse(value)).toISOString() !== value) {
    throw new Error(`INVALID_TIMESTAMP: ${label}`);
  }
  return value;
}

// The decision clock is injected, never read from the wall. Tests pass a
// fixed or perturbed clock; decisions must not change.
export function createDecisionClock(injectedNow) {
  if (injectedNow !== undefined) {
    return {
      kind: 'injected',
      now: () => assertUtcTimestamp(injectedNow, 'injectedNow'),
    };
  }
  return {
    kind: 'injected',
    now: () => {
      throw new Error('DECISION_CLOCK_UNSET: ingestion decisions require an injected clock; wall-clock is not a decision input');
    },
  };
}

// Decision identity: everything that determines identity/dedup/verdicts.
// observed_at and fetched_at are deliberately excluded — including them
// would let wall-clock perturbation change content identity.
export function decisionIdentityInput({ canonical_locator, raw_sha256, normalized_sha256, version }) {
  return JSON.stringify({ canonical_locator, raw_sha256, normalized_sha256, version });
}

export function contentSnapshotId({ canonical_locator, raw_sha256, normalized_sha256, version }) {
  const digest = createHash('sha256').update(decisionIdentityInput({ canonical_locator, raw_sha256, normalized_sha256, version })).digest('hex');
  return `snp-${digest.slice(0, 16)}`;
}

export function tombstoneSnapshotId({ canonical_locator, version }) {
  const digest = createHash('sha256')
    .update(JSON.stringify({ canonical_locator, version, kind: 'tombstone' }))
    .digest('hex');
  return `snp-${digest.slice(0, 16)}`;
}

export function lineageId({ relation, upstream_snapshot_id, downstream_snapshot_id }) {
  const digest = createHash('sha256')
    .update(JSON.stringify({ relation, upstream_snapshot_id, downstream_snapshot_id }))
    .digest('hex');
  return `lin-${digest.slice(0, 16)}`;
}

// Audit-only telemetry may use the wall clock, but must be clearly separated
// from decision inputs.
export function auditTimestamp(clock) {
  return clock.now();
}
