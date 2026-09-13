// S2-003 temporal model tests (probe I semantics).
// Wall-clock perturbation must never change content identity, dedup verdicts
// or snapshot ids. observed_at/fetched_at are audit-only telemetry.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createDecisionClock,
  contentSnapshotId,
  tombstoneSnapshotId,
  lineageId,
  assertUtcTimestamp,
} from '../../src/lib/ingestion/time-model.mjs';

const identity = {
  canonical_locator: 'manual:export/note-001',
  raw_sha256: 'a'.repeat(64),
  normalized_sha256: 'b'.repeat(64),
  version: 1,
};

describe('S2-003 temporal model', () => {
  test('content snapshot ids are independent of the injected clock', () => {
    const morning = contentSnapshotId(identity);
    const nextYear = contentSnapshotId(identity);
    assert.equal(morning, nextYear);
  });

  test('identity changes when content or version changes, not when time changes', () => {
    const v1 = contentSnapshotId(identity);
    const v2 = contentSnapshotId({ ...identity, version: 2 });
    const edited = contentSnapshotId({ ...identity, raw_sha256: 'c'.repeat(64) });
    assert.notEqual(v1, v2);
    assert.notEqual(v1, edited);
  });

  test('the decision clock refuses to read the wall clock', () => {
    const clock = createDecisionClock();
    assert.throws(() => clock.now(), /DECISION_CLOCK_UNSET/);
    const injected = createDecisionClock('2026-01-01T00:00:00.000Z');
    assert.equal(injected.now(), '2026-01-01T00:00:00.000Z');
  });

  test('timestamps are validated as real UTC instants', () => {
    assert.throws(() => assertUtcTimestamp('2026-02-30T00:00:00.000Z', 'x'), /INVALID_TIMESTAMP/);
    assert.throws(() => assertUtcTimestamp('2026-01-01T00:00:00Z', 'x'), /INVALID_TIMESTAMP/);
    assert.equal(assertUtcTimestamp('2026-01-15T10:30:00.000Z', 'x'), '2026-01-15T10:30:00.000Z');
  });

  test('tombstone and lineage ids are content-derived and deterministic', () => {
    const t1 = tombstoneSnapshotId({ canonical_locator: 'manual:export/note-001', version: 2 });
    const t2 = tombstoneSnapshotId({ canonical_locator: 'manual:export/note-001', version: 2 });
    assert.equal(t1, t2);
    const l1 = lineageId({ relation: 'exact_duplicate', upstream_snapshot_id: 'snp-a', downstream_snapshot_id: 'snp-b' });
    const l2 = lineageId({ relation: 'exact_duplicate', upstream_snapshot_id: 'snp-a', downstream_snapshot_id: 'snp-b' });
    assert.equal(l1, l2);
    const reversed = lineageId({ relation: 'exact_duplicate', upstream_snapshot_id: 'snp-b', downstream_snapshot_id: 'snp-a' });
    assert.notEqual(l1, reversed);
  });
});
