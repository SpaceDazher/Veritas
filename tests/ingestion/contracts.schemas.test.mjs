// S2-003 contract schema tests: success fixtures, mutation rejection,
// unknown-field fail-closed and unknown-version rejection for all nine
// ingestion contracts.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  CONTRACT_NAMES,
  validateContract,
  assertValidContract,
  contractDigests,
} from '../../src/lib/ingestion/contract-registry.mjs';

const TS = '2026-01-15T10:30:00.000Z';

export const fixtures = {
  'source-descriptor': {
    contractVersion: '1.0.0',
    source_id: 'src-test-doc-1',
    connector_id: 'conn-manual-export',
    source_kind: 'manual_export',
    canonical_locator: 'manual:export/note-001',
    display_locator: 'note-001 (display)',
    owner: 'prn-human-reviewer',
    author: 'A. Author',
    publisher: null,
    workspace_id: 'ws-ingestion',
    tenant_id: 'ws-ingestion',
    classification: { visibility: 'public' },
    license: { spdx: 'CC-BY-4.0', attribution_required: true },
    retention: { policy: 'keep_forever', retain_until: null },
    lifecycle: { state: 'enabled', reason: null, changed_at: null },
    registered_at: TS,
    registered_by: 'prn-human-reviewer',
  },
  'connector-contract': {
    contractVersion: '1.0.0',
    connector_id: 'conn-manual-export',
    connector_version: '1.0.0',
    source_kind: 'manual_export',
    auth_mode: 'none',
    required_grant_scope: null,
    read_only: true,
    sandbox_profile_id: null,
    capability_id: null,
    operations: {
      discoverCapabilities: true,
      resolveDescriptor: true,
      fetchVersion: true,
      extract: true,
      reconcile: true,
      observeDeletion: true,
    },
    limits: { timeout_ms: 5000, max_attempts: 1, max_bytes: 1000 },
    reconciliation: { supported: true, unknown_outcome_policy: 'RECONCILIATION_REQUIRED' },
    terminal_states: ['COMMITTED', 'FAILED'],
  },
  'fetch-request': {
    contractVersion: '1.0.0',
    operation_id: 'op-test-001',
    source_id: 'src-test-doc-1',
    connector_id: 'conn-manual-export',
    version_selector: { latest: true },
    actor: 'prn-human-reviewer',
    locator: 'export/note-001',
    workspace_id: 'ws-ingestion',
    grant_id: null,
    lease_id: null,
    budget: { max_bytes: 1000000, max_segments: 100, time_limit_ms: 30000 },
    requested_at: TS,
  },
  'source-snapshot': {
    contractVersion: '1.0.0',
    snapshot_id: 'snp-0f4e2a1b3c5d6e7f',
    source_id: 'src-test-doc-1',
    connector_id: 'conn-manual-export',
    source_kind: 'manual_export',
    version: 1,
    snapshot_kind: 'content',
    tombstone_reason: null,
    canonical_url: null,
    canonical_message_id: null,
    canonical_repository_id: null,
    canonical_object_id: null,
    canonical_locator: 'manual:export/note-001',
    canonicalization_version: '1.0.0',
    raw_sha256: 'a'.repeat(64),
    normalized_sha256: 'b'.repeat(64),
    author: 'A. Author',
    publisher: null,
    published_at: '2025-12-01T00:00:00.000Z',
    event_time: null,
    observed_at: TS,
    fetched_at: TS,
    parent_snapshot_id: null,
    supersedes_snapshot_id: null,
    language: 'en',
    mime_type: 'text/markdown',
    size_bytes: 128,
    extraction_status: 'COMPLETE',
    acl: { visibility: 'public', workspace_id: 'ws-ingestion', tenant_id: 'ws-ingestion' },
    license: { spdx: 'CC-BY-4.0', attribution_required: true },
    retention: { policy: 'keep_forever', retain_until: null },
    fetch_provenance: {
      operation_id: 'op-test-001',
      run_id: null,
      connector_id: 'conn-manual-export',
      connector_version: '1.0.0',
      fetched_from: 'manual export',
      fetched_at: TS,
      grant_id: null,
      content_type_validated: true,
    },
  },
  'content-segment': {
    contractVersion: '1.0.0',
    segment_id: 'seg-0f4e2a1b3c5d6e7f',
    snapshot_id: 'snp-0f4e2a1b3c5d6e7f',
    source_id: 'src-test-doc-1',
    ordinal: 0,
    coordinates: { line: { start: 1, end: 4 } },
    text: 'Calm factual text.',
    text_sha256: '78e1198ec36cca11c224d451940b660a30ea9a988de7455dc081801e41394e8c',
    original_language: 'en',
    normalized_language: 'en',
    extraction: {
      method: 'native_text',
      extractor_name: 'markdown-native',
      extractor_version: '1.0.0',
      config_sha256: null,
      confidence: 1,
      uncertainty_flags: [],
      missing_ranges: [],
    },
    coverage: { line_count: 4 },
    embedded_instruction_classification: { present: false, classification: 'none', confidence: 1, note: null },
    status: 'COMPLETE',
  },
  'ingestion-run': {
    contractVersion: '1.0.0',
    run_id: 'run-0f4e2a1b3c5d6e7f',
    executor_id: 'exec-a',
    pid: 4242,
    nonce: 'n-abcdef0123456789',
    output_root: 'results/s2-003/run-a',
    frozen_inputs: {
      connector_contracts_sha256: 'd'.repeat(64),
      corpus_sha256: 'e'.repeat(64),
      policy_sha256: 'f'.repeat(64),
    },
    started_at: TS,
    finished_at: TS,
    environment: { commit: '1'.repeat(40), tree: '2'.repeat(40), node_version: '22.0.0', platform: 'linux' },
    counts: { total: 1, COMMITTED: 1 },
    outcomes: [
      { operation_id: 'op-test-001', case_id: 'gold-001', terminal: 'COMMITTED', snapshot_id: 'snp-0f4e2a1b3c5d6e7f', error_code: null, raw_observation_ref: null },
    ],
  },
  'source-lineage': {
    contractVersion: '1.0.0',
    lineage_id: 'lin-0f4e2a1b3c5d6e7f',
    relation: 'exact_duplicate',
    upstream_snapshot_id: 'snp-aaaaaaaaaaaaaaaa',
    downstream_snapshot_id: 'snp-bbbbbbbbbbbbbbbb',
    evidence: { method: 'exact_raw_digest', digest_sha256: 'a'.repeat(64), detail: null },
    confidence: 1,
    automated: true,
    status: 'confirmed',
    confirmed_by: null,
    created_at: TS,
  },
  'source-proposal': {
    contractVersion: '1.0.0',
    proposal_id: 'prp-0f4e2a1b3c5d6e7f',
    proposer: 'prn-human-reviewer',
    candidate_locator: 'https://example.org/paper',
    proposed_source_kind: 'web_url',
    reason: 'Background reading for the pilot topic.',
    expected_domain: 'example.org',
    uncertainty: { access_uncertain: false, license_uncertain: true, notes: null },
    status: 'PROPOSED',
    reviewed_by: null,
    decision_reason: null,
    decided_at: null,
    created_at: TS,
  },
  'connector-error': {
    contractVersion: '1.0.0',
    error_id: 'err-0f4e2a1b3c5d6e7f',
    connector_id: 'conn-web-url',
    source_id: null,
    operation_id: 'op-test-002',
    code: 'TIMEOUT',
    retryable: true,
    reconciliation_action: 'retry_with_backoff',
    diagnostic: { redacted_detail: 'fetch exceeded the configured time limit', redaction_applied: true, detail_sha256: null },
    occurred_at: TS,
  },
};

describe('S2-003 ingestion contracts', () => {
  test('all nine contracts exist, are versioned 1.0.0 and validate their fixtures', () => {
    assert.equal(CONTRACT_NAMES.length, 9);
    for (const name of CONTRACT_NAMES) {
      const fixture = fixtures[name];
      assert.ok(fixture, `${name} fixture missing`);
      assertValidContract(name, fixture);
    }
  });

  test('every contract exposes a stable SHA-256 digest', () => {
    const digests = contractDigests();
    for (const name of CONTRACT_NAMES) {
      assert.match(digests[name], /^[0-9a-f]{64}$/);
    }
  });

  test('unknown fields are rejected in every contract (fail-closed)', () => {
    for (const name of CONTRACT_NAMES) {
      const mutated = { ...fixtures[name], totally_unknown_field: 'x' };
      const result = validateContract(name, mutated);
      assert.equal(result.valid, false, `${name} accepted an unknown field`);
    }
  });

  test('unknown contract version is rejected', () => {
    for (const name of CONTRACT_NAMES) {
      const mutated = { ...fixtures[name], contractVersion: '9.9.9' };
      const result = validateContract(name, mutated);
      assert.equal(result.valid, false, `${name} accepted version 9.9.9`);
    }
  });

  test('malformed timestamps are rejected semantically', () => {
    const snapshot = { ...fixtures['source-snapshot'], observed_at: '2026-01-15T10:30:00Z' };
    assert.equal(validateContract('source-snapshot', snapshot).valid, false);
    const descriptor = { ...fixtures['source-descriptor'], registered_at: 'not-a-time' };
    assert.equal(validateContract('source-descriptor', descriptor).valid, false);
  });

  test('snapshot digests must be hex sha-256', () => {
    const mutated = { ...fixtures['source-snapshot'], raw_sha256: 'ZZZ' };
    assert.equal(validateContract('source-snapshot', mutated).valid, false);
  });

  test('tombstone snapshots require a reason; content snapshots forbid one', () => {
    const tombstone = { ...fixtures['source-snapshot'], snapshot_kind: 'tombstone', extraction_status: 'FAILED' };
    assert.equal(validateContract('source-snapshot', tombstone).valid, false);
    const withReason = { ...tombstone, tombstone_reason: 'deleted upstream' };
    assert.equal(validateContract('source-snapshot', withReason).valid, true);
    const contentWithReason = { ...fixtures['source-snapshot'], tombstone_reason: 'x' };
    assert.equal(validateContract('source-snapshot', contentWithReason).valid, false);
  });

  test('a snapshot cannot supersede itself', () => {
    const mutated = { ...fixtures['source-snapshot'], supersedes_snapshot_id: fixtures['source-snapshot'].snapshot_id };
    assert.equal(validateContract('source-snapshot', mutated).valid, false);
  });

  test('segments must carry coordinates and a matching text digest', () => {
    const noCoords = { ...fixtures['content-segment'] };
    delete noCoords.coordinates;
    assert.equal(validateContract('content-segment', noCoords).valid, false);
    const badDigest = { ...fixtures['content-segment'], text_sha256: 'd'.repeat(64) };
    assert.equal(validateContract('content-segment', badDigest).valid, false);
    const goodDigest = {
      ...fixtures['content-segment'],
      text: 'hello world',
      text_sha256: createHash('sha256').update('hello world', 'utf8').digest('hex'),
    };
    assert.equal(validateContract('content-segment', goodDigest).valid, true);
  });

  test('low-confidence OCR/ASR must flag uncertainty', () => {
    const mutated = {
      ...fixtures['content-segment'],
      extraction: { ...fixtures['content-segment'].extraction, method: 'ocr', confidence: 0.3, uncertainty_flags: [] },
    };
    assert.equal(validateContract('content-segment', mutated).valid, false);
    const flagged = { ...mutated, extraction: { ...mutated.extraction, uncertainty_flags: ['LOW_CONFIDENCE', 'OCR_NOISY'] } };
    assert.equal(validateContract('content-segment', flagged).valid, true);
  });

  test('ingestion run counts must sum and outcomes must match', () => {
    const mutated = {
      ...fixtures['ingestion-run'],
      counts: { total: 2, COMMITTED: 1 },
    };
    assert.equal(validateContract('ingestion-run', mutated).valid, false);
    const dupOutcome = {
      ...fixtures['ingestion-run'],
      counts: { total: 2, COMMITTED: 2 },
      outcomes: [fixtures['ingestion-run'].outcomes[0], { ...fixtures['ingestion-run'].outcomes[0] }],
    };
    assert.equal(validateContract('ingestion-run', dupOutcome).valid, false);
    const badRoot = { ...fixtures['ingestion-run'], output_root: 'C:\\host\\path' };
    assert.equal(validateContract('ingestion-run', badRoot).valid, false);
  });

  test('only exact relations may be automated; near-duplicate stays a candidate', () => {
    const autoNearDup = {
      ...fixtures['source-lineage'],
      evidence: { method: 'near_duplicate_classifier', digest_sha256: null, detail: null },
      confidence: 0.87,
      automated: true,
    };
    assert.equal(validateContract('source-lineage', autoNearDup).valid, false);
    const candidate = {
      ...fixtures['source-lineage'],
      lineage_id: 'lin-bbbbbbbbbbbbbbbb',
      relation: 'mirror',
      evidence: { method: 'near_duplicate_classifier', digest_sha256: null, detail: null },
      confidence: 0.87,
      automated: false,
      status: 'candidate',
    };
    assert.equal(validateContract('source-lineage', candidate).valid, true);
    const manualAuto = {
      ...fixtures['source-lineage'],
      lineage_id: 'lin-cccccccccccccccc',
      evidence: { method: 'manual', digest_sha256: null, detail: null },
      automated: true,
    };
    assert.equal(validateContract('source-lineage', manualAuto).valid, false);
  });

  test('decided proposals require a human reviewer, time and reason', () => {
    const approved = {
      ...fixtures['source-proposal'],
      status: 'APPROVED',
      reviewed_by: 'prn-human-reviewer',
      decided_at: TS,
      decision_reason: 'license clarified by uploader',
    };
    assert.equal(validateContract('source-proposal', approved).valid, true);
    const missingReviewer = { ...approved, reviewed_by: null };
    assert.equal(validateContract('source-proposal', missingReviewer).valid, false);
  });

  test('connector errors stay inside the closed enum and demand reconciliation for unknowns', () => {
    const unknown = { ...fixtures['connector-error'], code: 'UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED', reconciliation_action: 'none' };
    assert.equal(validateContract('connector-error', unknown).valid, false);
    const mutated = { ...fixtures['connector-error'], code: 'SOMETHING_ELSE' };
    assert.equal(validateContract('connector-error', mutated).valid, false);
  });

  test('diagnostics must never contain credentials', () => {
    const leaked = {
      ...fixtures['connector-error'],
      diagnostic: { redacted_detail: 'token sk-abcdefghijklmnopqrstuvwx in header', redaction_applied: true, detail_sha256: null },
    };
    assert.equal(validateContract('connector-error', leaked).valid, false);
  });

  test('private descriptors must name a scope', () => {
    const mutated = {
      ...fixtures['source-descriptor'],
      classification: { visibility: 'private' },
    };
    assert.equal(validateContract('source-descriptor', mutated).valid, false);
  });

  test('fetch requests cannot smuggle credentials (closed shape)', () => {
    const smuggled = { ...fixtures['fetch-request'], password: 'hunter2' };
    assert.equal(validateContract('fetch-request', smuggled).valid, false);
    const token = { ...fixtures['fetch-request'], credential: { token: 'x' } };
    assert.equal(validateContract('fetch-request', token).valid, false);
  });

  test('connectors are read-only by construction', () => {
    const mutated = { ...fixtures['connector-contract'], read_only: false };
    assert.equal(validateContract('connector-contract', mutated).valid, false);
    const grantMissingScope = { ...fixtures['connector-contract'], auth_mode: 'grant_required', required_grant_scope: null };
    assert.equal(validateContract('connector-contract', grantMissingScope).valid, false);
  });
});
