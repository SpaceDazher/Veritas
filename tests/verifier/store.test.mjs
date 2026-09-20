// S2-006 wave 2A — store contract tests (spec §11).
// Offline part: InMemoryVerifierStore immutability, atomicity, idempotency
// ledger/outbox semantics and the external-call state machine, plus static
// structure checks of migrations/0005_verifier_store.sql.
// PostgreSQL part: exercised ONLY when a database is reachable; otherwise the
// tests are skipped with an explicit NOT_RUN_DB marker (spec §11: absence of
// PostgreSQL is NOT_RUN_DB + NEEDS_INPUT, never a silent pass).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { getVerificationResult } from '../../src/lib/verifier/api.mjs';
import {
  BudgetExceeded,
  InMemoryVerifierStore,
  PostgresVerifierStore,
} from '../../src/lib/verifier/store.mjs';
import {
  AclDenied,
  IdempotencyConflict,
  NeedsInput,
  ReconciliationRequired,
  StoreOutcomeUnknownError,
  VerifierError,
} from '../../src/lib/verifier/errors.mjs';
import {
  makeVerifierAuthorityRegistry,
} from '../../src/lib/verifier/commands.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);

function makeResultRecord(resultId, status = 'READY_FOR_HUMAN_REVIEW') {
  return {
    contractVersion: '1.0.0',
    resultId,
    requestRef: 'svr-store-1',
    inputDigests: { artifactDigest: HEX_A, rubricDigest: HEX_A, corpusManifestDigest: HEX_A, thresholdsDigest: HEX_A },
    outputDigest: HEX_B,
    items: [],
    disagreements: [],
    criticalFindings: [],
    abstentions: [],
    coverage: { denominator: 0, evaluated: 0, missing: 0 },
    independenceProfileRef: 'ind-unverified',
    humanDecisionRequired: true,
    status,
  };
}

function publishArgs(store, { operationId, records, idempotencyKey = 'idem-store-1', operation = 'publishVerificationResult' }) {
  return store.publish({
    workspaceId: 'ws-verifier',
    operationId,
    actor: 'prn-evaluation-harness',
    operation,
    idempotencyKey,
    records,
    // Constant audit payload: the idempotency digest must bind actor +
    // operation + records, not the operation id (a retry uses a new id).
    audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: { probe: 'store-test' } },
  });
}

describe('S2-006 InMemory verifier store contracts', () => {
  test('records are immutable: same id with different content conflicts without mutation', async () => {
    const store = new InMemoryVerifierStore();
    const record = makeResultRecord('sres-store-1');
    await publishArgs(store, { operationId: 'op-store-1', records: [{ kind: 'result', record }] });
    const mutated = makeResultRecord('sres-store-1', 'INCOMPLETE');
    await assert.rejects(
      publishArgs(store, { operationId: 'op-store-2', idempotencyKey: 'idem-store-2', records: [{ kind: 'result', record: mutated }] }),
      IdempotencyConflict,
    );
    assert.deepEqual(await store.getRecord('result', 'sres-store-1'), record, 'original immutable record untouched');
  });

  test('byte-identical republication under a different operation id does not conflict or duplicate', async () => {
    const store = new InMemoryVerifierStore();
    const record = makeResultRecord('sres-store-2');
    await publishArgs(store, { operationId: 'op-store-3', idempotencyKey: 'idem-store-3', records: [{ kind: 'result', record }] });
    const second = await publishArgs(store, { operationId: 'op-store-4', idempotencyKey: 'idem-store-4', records: [{ kind: 'result', record }] });
    assert.equal(second.replayed, false, 'a new operation id is a new operation, not a ledger replay');
    assert.deepEqual(await store.getRecord('result', 'sres-store-2'), record, 'record stays byte-identical');
    assert.equal([...store.records.get('result').values()].length, 1, 'no duplicate record is created');
  });

  test('a failed multi-record publish rolls back every partial write (atomicity)', async () => {
    const store = new InMemoryVerifierStore();
    const good = makeResultRecord('sres-store-good');
    // First publish a conflicting record, then a batch whose second member collides.
    await publishArgs(store, { operationId: 'op-store-5', idempotencyKey: 'idem-store-5', records: [{ kind: 'result', record: good }] });
    const fresh = makeResultRecord('sres-store-fresh');
    const colliding = makeResultRecord('sres-store-good', 'BLOCKED');
    await assert.rejects(
      publishArgs(store, {
        operationId: 'op-store-6', idempotencyKey: 'idem-store-6',
        records: [{ kind: 'result', record: fresh }, { kind: 'result', record: colliding }],
      }),
      IdempotencyConflict,
    );
    assert.equal(await store.getRecord('result', 'sres-store-fresh'), null, 'no partial record survives a failed batch');
    assert.equal(store.listLedger().length, 1);
    assert.equal(store.listOutbox().length, 1);
  });

  test('outbox payload digests are canonical and publication order is deterministic', async () => {
    const build = () => {
      const store = new InMemoryVerifierStore();
      const record = makeResultRecord('sres-store-det');
      store.publish({
        workspaceId: 'ws-verifier',
        operationId: 'op-det-1',
        actor: 'prn-evaluation-harness',
        operation: 'publishVerificationResult',
        idempotencyKey: 'idem-det-1',
        records: [{ kind: 'result', record }],
        audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: { z: 1, a: 'x' } },
      }).catch(() => {});
      return store;
    };
    const first = build().listOutbox();
    const second = build().listOutbox();
    assert.deepEqual(first, second, 'no wall clock, locale or iteration-order dependence');
    assert.match(first[0].payload_digest, /^[0-9a-f]{64}$/);
  });

  test('ledger replays carry the recorded outcome digest; reconciliation rows refuse retries', async () => {
    const store = new InMemoryVerifierStore();
    const record = makeResultRecord('sres-store-ledger');
    const first = await publishArgs(store, { operationId: 'op-store-7', idempotencyKey: 'idem-store-7', records: [{ kind: 'result', record }] });
    const replay = await publishArgs(store, { operationId: 'op-store-8', idempotencyKey: 'idem-store-8', records: [{ kind: 'result', record }] });
    assert.equal(replay.outcomeDigest, first.outcomeDigest);
    assert.match(first.outcomeDigest, /^[0-9a-f]{64}$/);

    store.injectFault({ at: 'unknown-commit', once: true });
    await assert.rejects(
      publishArgs(store, { operationId: 'op-store-9', idempotencyKey: 'idem-store-9', records: [{ kind: 'result', record: makeResultRecord('sres-store-unknown') }] }),
      VerifierError,
    );
    // Retry with the SAME idempotency key (a different operation id cannot
    // bypass the binding): the reconciliation row must refuse re-execution.
    await assert.rejects(
      publishArgs(store, { operationId: 'op-store-10', idempotencyKey: 'idem-store-9', records: [{ kind: 'result', record: makeResultRecord('sres-store-unknown') }] }),
      ReconciliationRequired,
      'retry against a RECONCILIATION_REQUIRED ledger row escalates, never blindly re-executes',
    );
  });

  test('operation ids are validated and unknown record kinds are rejected', async () => {
    const store = new InMemoryVerifierStore();
    await assert.rejects(
      publishArgs(store, { operationId: 'bad id!', records: [{ kind: 'result', record: makeResultRecord('sres-x') }] }),
      (error) => error instanceof VerifierError && error.code === 'OPERATION_ID_INVALID',
    );
    await assert.rejects(
      store.publish({
        workspaceId: 'ws-verifier', operationId: 'op-store-11', actor: 'prn-x', operation: 'op',
        records: [{ kind: 'quantum_state', record: { quantumStateId: 'q-1' } }],
        audit: { type: 'X', payload: {} },
      }),
      (error) => error instanceof VerifierError && error.code === 'RECORD_KIND_UNKNOWN',
    );
  });

  test('external call state machine enforces RESERVED -> ACCEPTED -> FINALIZED -> RECONCILIATION_REQUIRED', async () => {
    const store = new InMemoryVerifierStore();
    const reserved = await store.beginExternalCall({
      callId: 'call-1', workspaceId: 'ws-verifier', actor: 'prn-evaluation-harness',
      grantRef: 'grt-verifier-1', operationId: 'op-call-1', reservation: { items: 2 },
    });
    assert.equal(reserved.state, 'RESERVED');
    assert.equal(reserved.fencingToken, 1);

    await assert.rejects(
      store.finalizeExternalCall({ callId: 'call-1', fencingToken: 1, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 0 } }),
      (error) => error instanceof VerifierError && error.code === 'INVALID_TRANSITION',
      'RESERVED cannot skip ACCEPTED',
    );
    await store.acceptExternalCall({ callId: 'call-1', fencingToken: 1, actor: 'prn-evaluation-harness' });
    await store.finalizeExternalCall({ callId: 'call-1', fencingToken: 1, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 0 } });
    await assert.rejects(
      store.markExternalCallReconciliation({ callId: 'call-1', fencingToken: 1, actor: 'prn-evaluation-harness', reason: 'late regret' }),
      (error) => error instanceof VerifierError && error.code === 'INVALID_TRANSITION',
      'FINALIZED is terminal for reconciliation',
    );
    const call = await store.readExternalCall('call-1');
    assert.equal(call.state, 'FINALIZED');
    assert.equal(call.fencing_token, 1);
  });

  test('external-call transitions are ownership-bound: a foreign actor mutates nothing', async () => {
    const store = new InMemoryVerifierStore();
    await store.beginExternalCall({
      callId: 'call-owner', workspaceId: 'ws-verifier', actor: 'prn-evaluation-harness',
      grantRef: 'grt-verifier-1', operationId: 'op-owner', reservation: {},
    });
    await assert.rejects(
      store.acceptExternalCall({ callId: 'call-owner', fencingToken: 1, actor: 'prn-annotator-1' }),
      AclDenied,
    );
    await assert.rejects(
      store.finalizeExternalCall({ callId: 'call-owner', fencingToken: 1, actor: 'prn-annotator-1', responseDigest: HEX_A, settlement: { amount: 0 } }),
      AclDenied,
    );
    await assert.rejects(
      store.acceptExternalCall({ callId: 'call-owner', fencingToken: 1 }),
      NeedsInput,
      'actor is required for every transition',
    );
    await assert.rejects(
      store.acceptExternalCall({ callId: 'call-owner', fencingToken: 1, actor: 'prn-evaluation-harness', workspaceId: 'ws-other' }),
      AclDenied,
      'a workspace binding that differs from the reservation is refused',
    );
    const call = await store.readExternalCall('call-owner');
    assert.equal(call.state, 'RESERVED', 'no mutation from refused transitions');
  });

  test('records are workspace-scoped: a cross-workspace read is AclDenied, never a silent miss', async () => {
    const store = new InMemoryVerifierStore();
    const record = makeResultRecord('sres-ws-a-1');
    await store.publish({
      workspaceId: 'ws-a',
      operationId: 'op-ws-a-1',
      actor: 'prn-evaluation-harness',
      operation: 'publishVerificationResult',
      idempotencyKey: 'idem-ws-a-1',
      records: [{ kind: 'result', record }],
      audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: { ws: 'a' } },
    });
    assert.equal(await store.getRecord('result', 'sres-ws-a-1', { workspaceId: 'ws-a' }), record);
    await assert.rejects(
      store.getRecord('result', 'sres-ws-a-1', { workspaceId: 'ws-b' }),
      AclDenied,
      'the record EXISTS but in another workspace: AclDenied, not null',
    );
    assert.equal(await store.getRecord('result', 'sres-missing', { workspaceId: 'ws-a' }), null);
  });

  test('calibration report listing is strictly workspace-scoped and fails loudly without a workspace', async () => {
    const store = new InMemoryVerifierStore();
    const report = {
      contractVersion: '1.0.0', reportId: 'rep-store-1', corpusVersion: '0.3.0',
      rubricDigest: HEX_A, thresholdsDigest: HEX_A,
    };
    await store.publish({
      workspaceId: 'ws-a', operationId: 'op-store-12', actor: 'prn-evaluation-harness',
      operation: 'publishCalibrationReport', idempotencyKey: 'idem-store-12',
      records: [{ kind: 'calibration_report', record: report }],
      audit: { type: 'CALIBRATION_REPORT_PUBLISHED', recordKind: 'calibration_report', payload: { reportId: report.reportId } },
    });
    await store.publish({
      workspaceId: 'ws-b', operationId: 'op-store-12b', actor: 'prn-evaluation-harness',
      operation: 'publishCalibrationReport', idempotencyKey: 'idem-store-12b',
      records: [{ kind: 'calibration_report', record: { ...report, reportId: 'rep-store-2' } }],
      audit: { type: 'CALIBRATION_REPORT_PUBLISHED', recordKind: 'calibration_report', payload: { reportId: 'rep-store-2' } },
    });
    await assert.rejects(store.listCalibrationReports({}), NeedsInput, 'a workspace is mandatory: no global listing');
    await assert.rejects(store.listCalibrationReports({ corpusVersion: '0.3.0' }), NeedsInput);
    assert.deepEqual((await store.listCalibrationReports({ workspaceId: 'ws-a' })).map((r) => r.reportId), ['rep-store-1']);
    assert.deepEqual((await store.listCalibrationReports({ workspaceId: 'ws-b', corpusVersion: '0.3.0' })).map((r) => r.reportId), ['rep-store-2']);
    assert.deepEqual(await store.listCalibrationReports({ workspaceId: 'ws-c' }), []);
  });

  test('inherited ACL metadata lives at store level, outside the contract payload', async () => {
    const store = new InMemoryVerifierStore();
    const record = makeResultRecord('sres-acl-1');
    const acl = { visibility: 'private', allowedPrincipalIds: ['prn-reviewer'], inherited: 'strictest_of_inputs' };
    await store.publish({
      workspaceId: 'ws-verifier',
      operationId: 'op-acl-1',
      actor: 'prn-evaluation-harness',
      operation: 'publishVerificationResult',
      idempotencyKey: 'idem-acl-1',
      records: [{ kind: 'result', record, acl }],
      audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: { acl: true } },
    });
    assert.deepEqual(await store.getRecordAcl('result', 'sres-acl-1'), acl);
    const stored = await store.getRecord('result', 'sres-acl-1');
    assert.equal(Object.prototype.hasOwnProperty.call(stored, 'acl'), false, 'the payload stays byte-pure');
    assert.equal(await store.getRecordAcl('result', 'sres-missing'), null);

    const plain = makeResultRecord('sres-acl-2');
    await store.publish({
      workspaceId: 'ws-verifier',
      operationId: 'op-acl-2',
      actor: 'prn-evaluation-harness',
      operation: 'publishVerificationResult',
      idempotencyKey: 'idem-acl-2',
      records: [{ kind: 'result', record: plain }],
      audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: {} },
    });
    assert.equal(Object.prototype.hasOwnProperty.call(await store.getRecord('result', 'sres-acl-2'), 'acl'), false);
    assert.equal(await store.getRecordAcl('result', 'sres-acl-2'), null, 'no inherited ACL without declared inputs');
  });

  test('calibration report listing filters by corpus version', async () => {
    const store = new InMemoryVerifierStore();
    const report = {
      contractVersion: '1.0.0', reportId: 'rep-store-1', corpusVersion: '0.3.0',
      rubricDigest: HEX_A, thresholdsDigest: HEX_A,
    };
    await store.publish({
      workspaceId: 'ws-verifier', operationId: 'op-store-12', actor: 'prn-evaluation-harness',
      operation: 'publishCalibrationReport', idempotencyKey: 'idem-store-12',
      records: [{ kind: 'calibration_report', record: report }],
      audit: { type: 'CALIBRATION_REPORT_PUBLISHED', recordKind: 'calibration_report', payload: { reportId: report.reportId } },
    });
    assert.equal((await store.listCalibrationReports({ workspaceId: 'ws-verifier', corpusVersion: '9.9.9' })).length, 0);
    assert.equal((await store.listCalibrationReports({ workspaceId: 'ws-verifier', corpusVersion: '0.3.0' })).length, 1);
  });

  test('canonical serialization of stored records is stable across reads', async () => {
    const store = new InMemoryVerifierStore();
    const record = makeResultRecord('sres-store-canonical', 'INCOMPLETE');
    await publishArgs(store, { operationId: 'op-store-13', idempotencyKey: 'idem-store-13', records: [{ kind: 'result', record }] });
    const readBack = await store.getRecord('result', 'sres-store-canonical');
    assert.equal(canonicalize(readBack), canonicalize(record));
    assert.equal(canonicalDigest(readBack), canonicalDigest(record));
  });
});

describe('S2-006 migrations/0005_verifier_store.sql (static structure)', () => {
  const sql = fs.readFileSync(path.join(ROOT, 'migrations/0005_verifier_store.sql'), 'utf8');

  test('introduces all verifier tables with immutable payload columns and typed state machines', () => {
    for (const table of [
      'verifier_request', 'verifier_result', 'verifier_calibration_report',
      'verifier_adjudication_record', 'verifier_run',
      'verifier_invalidation_event', 'verifier_external_call_run',
      'verifier_operation_ledger', 'verifier_audit_outbox',
    ]) {
      assert.match(sql, new RegExp(`CREATE TABLE IF NOT EXISTS ${table}\\b`), `missing table ${table}`);
    }
    assert.match(sql, /state\s+VARCHAR\(32\) NOT NULL CHECK \(state IN \(\s*'RESERVED', 'ACCEPTED', 'FINALIZED', 'RECONCILIATION_REQUIRED'/);
    assert.match(sql, /fencing_token\s+BIGINT NOT NULL UNIQUE/);
    assert.match(sql, /CHECK \(state <> 'FINALIZED' OR \(response_digest IS NOT NULL AND settlement IS NOT NULL\)\)/);
    assert.match(sql, /CHECK \(state <> 'RECONCILIATION_REQUIRED' OR reconcile_reason IS NOT NULL\)/);
  });

  test('idempotency key is unique with a typed-conflict-friendly partial index', () => {
    assert.match(sql, /CREATE UNIQUE INDEX idx_verifier_operation_idem\s+ON verifier_operation_ledger \(workspace_id, idempotency_key\)\s+WHERE idempotency_key IS NOT NULL/);
    assert.match(sql, /status\s+VARCHAR\(32\) NOT NULL CHECK \(status IN \('COMMITTED', 'RECONCILIATION_REQUIRED'\)\)/);
  });

  test('frozen migrations 0001-0004 are untouched by this slice', () => {
    for (const name of ['0001_veritas_board.sql', '0002_source_ingestion.sql', '0003_claim_graph.sql', '0004_claim_graph_state.sql']) {
      assert.ok(fs.existsSync(path.join(ROOT, 'migrations', name)));
      assert.doesNotMatch(fs.readFileSync(path.join(ROOT, 'migrations', name), 'utf8'), /verifier_request/);
    }
  });
});

describe('S2-006 migrations/0006_verifier_acl.sql (static structure, fix2-C findings 1+3)', () => {
  const sql = fs.readFileSync(path.join(ROOT, 'migrations/0006_verifier_acl.sql'), 'utf8');

  test('adds store-level ACL metadata for verifier records (finding 1)', () => {
    assert.match(sql, /CREATE TABLE IF NOT EXISTS verifier_record_acl\b/);
    assert.match(sql, /visibility\s+VARCHAR\(16\) NOT NULL CHECK \(visibility IN \('public', 'project', 'private'\)\)/);
    assert.match(sql, /PRIMARY KEY \(record_kind, record_id\)/);
  });

  test('adds the per-grant budget accumulator with a lockable totals row (finding 3)', () => {
    assert.match(sql, /CREATE TABLE IF NOT EXISTS verifier_grant_budget_totals\b/);
    assert.match(sql, /grant_ref\s+VARCHAR\(64\) PRIMARY KEY/);
    assert.match(sql, /day_key\s+VARCHAR\(10\) NOT NULL/);
  });

  test('0006 only ADDS tables: the frozen 0005 surface is not redefined', () => {
    assert.ok(!/CREATE TABLE IF NOT EXISTS verifier_request\b/.test(sql), '0006 must not redefine 0005 tables');
    assert.ok(!/verifier_external_call_run\s*\(/.test(sql.replace(/CREATE INDEX[^;]*;/g, '')), '0006 must not redefine the external-call table');
  });
});

describe('S2-006 fix2-C finding 3 — provider budget day scope (deterministic UTC day bucket, injected clock)', () => {
  const clockAt = (dayIso) => () => dayIso;
  const BINDING = (budget) => ({ grantBinding: { grantDigest: HEX_A, budget, currency: 'USD' } });

  async function reserveAndAccept(store, { callId, grantRef, operationId, budget }) {
    const reserved = await store.beginExternalCall({
      callId, workspaceId: 'ws-verifier', actor: 'prn-evaluation-harness',
      grantRef, operationId, reservation: BINDING(budget),
    });
    await store.acceptExternalCall({ callId, fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness' });
    return reserved;
  }

  test('repro: a day:0 grant settles amount:1 on the old code — now BudgetExceeded with no partial settlement', async () => {
    const store = new InMemoryVerifierStore({ clock: clockAt('2026-03-22T10:00:00.000Z') });
    const reserved = await reserveAndAccept(store, {
      callId: 'call-day0', grantRef: 'grt-day-zero', operationId: 'op-day0',
      budget: { task: 5, campaign: 5, day: 0 },
    });
    // task 0+1 <= 5 and campaign 0+1 <= 5 pass; ONLY the day scope catches it.
    await assert.rejects(
      store.finalizeExternalCall({ callId: 'call-day0', fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 1 } }),
      BudgetExceeded,
      'day:0 with settlement amount:1 must be BudgetExceeded, never finalized',
    );
    const call = await store.readExternalCall('call-day0');
    assert.equal(call.state, 'RECONCILIATION_REQUIRED');
    assert.equal(call.settlement, null, 'no partial settlement');
    assert.equal(call.response_digest, null);
    assert.ok(call.reconcile_reason.includes('day'), 'the reconcile reason names the day scope');
  });

  test('day totals accumulate across calls of one grant within the same UTC day', async () => {
    const store = new InMemoryVerifierStore({ clock: clockAt('2026-03-22T10:00:00.000Z') });
    const budget = { task: 5, campaign: 5, day: 1 };
    const first = await reserveAndAccept(store, { callId: 'call-d1', grantRef: 'grt-day-1', operationId: 'op-d1', budget });
    const ok = await store.finalizeExternalCall({ callId: 'call-d1', fencingToken: first.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 1 } });
    assert.equal(ok.state, 'FINALIZED');

    // A second call under a DIFFERENT operation stays within task/campaign
    // (1+1 <= 5) but crosses the day limit (1+1 > 1). The old code only
    // checked task/campaign and let it through.
    const second = await reserveAndAccept(store, { callId: 'call-d2', grantRef: 'grt-day-1', operationId: 'op-d2', budget });
    await assert.rejects(
      store.finalizeExternalCall({ callId: 'call-d2', fencingToken: second.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 1 } }),
      BudgetExceeded,
    );
    const call = await store.readExternalCall('call-d2');
    assert.equal(call.state, 'RECONCILIATION_REQUIRED');
    assert.equal(call.settlement, null);
  });

  test('crossing a UTC day boundary resets the day bucket deterministically (injected clock)', async () => {
    let now = '2026-03-22T10:00:00.000Z';
    const store = new InMemoryVerifierStore({ clock: () => now });
    const budget = { task: 5, campaign: 5, day: 1 };
    const first = await reserveAndAccept(store, { callId: 'call-boundary-1', grantRef: 'grt-boundary', operationId: 'op-b1', budget });
    await store.finalizeExternalCall({ callId: 'call-boundary-1', fencingToken: first.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 1 } });

    now = '2026-03-23T00:00:01.000Z';
    const second = await reserveAndAccept(store, { callId: 'call-boundary-2', grantRef: 'grt-boundary', operationId: 'op-b2', budget });
    const ok = await store.finalizeExternalCall({ callId: 'call-boundary-2', fencingToken: second.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 1 } });
    assert.equal(ok.state, 'FINALIZED', 'the new UTC day starts with an empty day bucket');

    const third = await reserveAndAccept(store, { callId: 'call-boundary-3', grantRef: 'grt-boundary', operationId: 'op-b3', budget });
    await assert.rejects(
      store.finalizeExternalCall({ callId: 'call-boundary-3', fencingToken: third.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 1 } }),
      BudgetExceeded,
      'the new day bucket fills up again',
    );
  });
});

describe('S2-006 fix2-C finding 4 — atomic failure escalation (no ACCEPTED without a reconcile event after a crash)', () => {
  test('repro: a crash after the rejection checkpoint still finds RECONCILIATION_REQUIRED + exactly one reconcile event', async () => {
    const store = new InMemoryVerifierStore();
    const reserved = await store.beginExternalCall({
      callId: 'call-crash-window', workspaceId: 'ws-verifier', actor: 'prn-evaluation-harness',
      grantRef: 'grt-crash', operationId: 'op-crash-window',
      reservation: { grantBinding: { grantDigest: HEX_A, budget: { task: 0, campaign: 0, day: 0 }, currency: 'USD' } },
    });
    await store.acceptExternalCall({ callId: 'call-crash-window', fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness' });

    // Simulate the production crash window of the old PostgreSQL branch:
    // the failure path commits, then the process dies before the caller
    // learns anything (the old code relied on a SECOND store call to
    // reconcile — a crash between them left ACCEPTED with no event).
    store.injectFault({ at: 'escalated-commit', once: true });
    await assert.rejects(
      store.finalizeExternalCall({ callId: 'call-crash-window', fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 1 } }),
      StoreOutcomeUnknownError,
      'the crash simulation fires at the escalation checkpoint',
    );
    const call = await store.readExternalCall('call-crash-window');
    assert.equal(call.state, 'RECONCILIATION_REQUIRED', 'a crash after the commit must never leave ACCEPTED without a reconcile event');
    assert.equal(call.settlement, null);
    assert.equal(call.response_digest, null);
    assert.ok(call.reconcile_reason.includes('budget'));
    const events = store.listOutbox().filter((e) => e.record_id === 'call-crash-window').map((e) => e.event_type);
    assert.equal(events.filter((t) => t === 'EXTERNAL_CALL_RECONCILIATION_REQUIRED').length, 1, 'exactly one reconcile event, committed atomically with the transition');

    // Recovery is idempotent per fencing token.
    const replay = await store.markExternalCallReconciliation({ callId: 'call-crash-window', fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness', reason: 'recovery' });
    assert.equal(replay.replayed, true);
  });
});

describe('S2-006 PostgresVerifierStore (real database when available)', () => {
  const connectionString = process.env.DATABASE_URL;

  test('transactional publish, idempotent replay, ledger/outbox uniqueness and fencing on PostgreSQL', async (t) => {
    if (!connectionString) {
      t.skip('NOT_RUN_DB: DATABASE_URL is not configured; PostgreSQL store semantics were verified on the in-memory implementation only');
      return;
    }
    let pg;
    try {
      pg = await import('pg');
    } catch {
      t.skip('NOT_RUN_DB: the pg driver is unavailable');
      return;
    }
    const { applyMigrations } = await import('../../scripts/apply-migrations.mjs');
    const pool = new pg.default.Pool({ connectionString, max: 1, connectionTimeoutMillis: 4000 });
    const workspaceId = `ws-vtest-p${process.pid}`;
    try {
      await pool.query('SELECT 1');
    } catch (error) {
      await pool.end().catch(() => {});
      t.skip(`NOT_RUN_DB: PostgreSQL is not reachable (${error.code ?? error.message})`);
      return;
    }
    try {
      await applyMigrations({ connectionString, pool });
      const store = new PostgresVerifierStore(pool);
      const record = makeResultRecord(`sres-pg-p${process.pid}`);
      const args = {
        records: [{ kind: 'result', record }],
        audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: { operationId: 'op-pg-1' } },
      };
      const first = await store.publish({
        workspaceId, operationId: `op-pg-1-p${process.pid}`, actor: 'prn-evaluation-harness',
        operation: 'publishVerificationResult', idempotencyKey: `idem-pg-p${process.pid}`, ...args,
      });
      assert.equal(first.replayed, false);
      const replay = await store.publish({
        workspaceId, operationId: `op-pg-2-p${process.pid}`, actor: 'prn-evaluation-harness',
        operation: 'publishVerificationResult', idempotencyKey: `idem-pg-p${process.pid}`, ...args,
      });
      assert.equal(replay.replayed, true, 'same idempotency key + same args replays the stored outcome');
      assert.equal(replay.outcomeDigest, first.outcomeDigest);
      const ledger = await store.listLedger();
      assert.equal(ledger.filter((row) => row.workspace_id === workspaceId).length, 1, 'no duplicate ledger writes');
      const outbox = await store.listOutbox();
      assert.equal(outbox.filter((row) => row.operation_id === `op-pg-1-p${process.pid}`).length, 1, 'no duplicate outbox writes');
      assert.deepEqual(await store.getRecord('result', record.resultId), record, 'JSONB roundtrip preserves the immutable record');

      await assert.rejects(
        store.publish({
          workspaceId, operationId: `op-pg-3-p${process.pid}`, actor: 'prn-evaluation-harness',
          operation: 'publishVerificationResult', idempotencyKey: `idem-pg-p${process.pid}`,
          records: [{ kind: 'result', record: makeResultRecord(record.resultId, 'BLOCKED') }],
          audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: {} },
        }),
        IdempotencyConflict,
        'idempotency key reuse with different args conflicts without mutation',
      );
      assert.equal((await store.getRecord('result', record.resultId)).status, 'READY_FOR_HUMAN_REVIEW');

      // Fenced external-call machine on the real database.
      const callId = `call-pg-p${process.pid}`;
      const reserved = await store.beginExternalCall({
        callId, workspaceId, actor: 'prn-evaluation-harness', grantRef: 'grt-verifier-1',
        operationId: `op-pg-call-p${process.pid}`, reservation: { items: 1 },
      });
      const second = await store.beginExternalCall({
        callId: `${callId}-b`, workspaceId, actor: 'prn-evaluation-harness', grantRef: 'grt-verifier-1',
        operationId: `op-pg-call-b-p${process.pid}`, reservation: { items: 1 },
      });
      assert.notEqual(second.fencingToken, reserved.fencingToken, 'fencing tokens from the sequence are unique');
      await assert.rejects(
        store.acceptExternalCall({ callId, fencingToken: reserved.fencingToken + 999, actor: 'prn-evaluation-harness' }),
        (error) => error instanceof VerifierError && error.code === 'ACL_DENIED',
      );
      await store.acceptExternalCall({ callId, fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness' });
      await store.markExternalCallReconciliation({ callId, fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness', reason: 'pg crash simulation' });
      await assert.rejects(
        store.finalizeExternalCall({ callId, fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 0 } }),
        ReconciliationRequired,
        'reconciled call refuses finalize on the real database too',
      );
      const callRow = await store.readExternalCall(callId);
      assert.equal(callRow.state, 'RECONCILIATION_REQUIRED');
      assert.equal(callRow.response_digest, null);

      // Atomicity: a record collision rolls the whole batch back. `fresh`
      // carries a DISTINCT output_digest — migration 0005 enforces a unique
      // output_digest per result, so reusing the shared fixture digest here
      // would fail on the index instead of the intended record-id collision.
      const fresh = { ...makeResultRecord(`sres-pg-fresh-p${process.pid}`), outputDigest: 'e'.repeat(64) };
      const colliding = makeResultRecord(record.resultId, 'BLOCKED');
      await assert.rejects(
        store.publish({
          workspaceId, operationId: `op-pg-4-p${process.pid}`, actor: 'prn-evaluation-harness',
          operation: 'publishVerificationResult', idempotencyKey: `idem-pg-fresh-p${process.pid}`,
          records: [{ kind: 'result', record: fresh }, { kind: 'result', record: colliding }],
          audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: {} },
        }),
        IdempotencyConflict,
      );
      assert.equal(await store.getRecord('result', fresh.resultId), null, 'no partial commit after a failed batch');
    } finally {
      for (const table of [
        'verifier_result', 'verifier_request', 'verifier_calibration_report',
        'verifier_adjudication_record', 'verifier_run',
        'verifier_invalidation_event', 'verifier_external_call_run',
        'verifier_operation_ledger',
      ]) {
        await pool.query(`DELETE FROM ${table} WHERE workspace_id = $1`, [workspaceId]).catch(() => {});
      }
      await pool.query('DELETE FROM verifier_audit_outbox WHERE operation_id LIKE $1', [`%p${process.pid}`]).catch(() => {});
      await pool.end().catch(() => {});
    }
  });
});

describe('S2-006 NotRunDb semantics', () => {
  test('a missing store for a read command is NEEDS_INPUT, never a silent skip', async () => {
    const pending = getVerificationResult(null, { resultId: 'x' });
    assert.ok(pending && typeof pending.then === 'function');
    await assert.rejects(pending, NeedsInput);
  });
});

// ---- fix2-C production paths on PostgreSQL (findings 1, 3, 4) --------------
// Honesty convention (same as the existing store tests and the db-replay
// scripts): exercised ONLY when a database is reachable via DATABASE_URL
// (e.g. the ephemeral podman Postgres provisioned exactly like
// scripts/s2-006-db-replay.mjs); otherwise skipped with the explicit
// NOT_RUN_DB marker — never a silent pass.
describe('S2-006 fix2-C production paths on PostgreSQL (findings 1, 3, 4 — real database when available)', () => {
  const connectionString = process.env.DATABASE_URL;

  async function connectPool(t, max = 4) {
    if (!connectionString) {
      t.skip('NOT_RUN_DB: DATABASE_URL is not configured; the production-path regressions (podman Postgres like scripts/s2-006-db-replay.mjs) were not executed here');
      return null;
    }
    let pg;
    try {
      pg = await import('pg');
    } catch {
      t.skip('NOT_RUN_DB: the pg driver is unavailable');
      return null;
    }
    const { applyMigrations } = await import('../../scripts/apply-migrations.mjs');
    const pool = new pg.default.Pool({ connectionString, max, connectionTimeoutMillis: 4000 });
    try {
      await pool.query('SELECT 1');
    } catch (error) {
      await pool.end().catch(() => {});
      t.skip(`NOT_RUN_DB: PostgreSQL is not reachable (${error.code ?? error.message})`);
      return null;
    }
    await applyMigrations({ connectionString, pool });
    return pool;
  }

  async function cleanupWorkspace(pool, workspaceId, pid) {
    for (const table of [
      'verifier_record_acl', 'verifier_grant_budget_totals', 'verifier_external_call_run',
      'verifier_result', 'verifier_request', 'verifier_calibration_report',
      'verifier_adjudication_record', 'verifier_run', 'verifier_invalidation_event',
      'verifier_operation_ledger',
    ]) {
      await pool.query(`DELETE FROM ${table} WHERE workspace_id = $1`, [workspaceId]).catch(() => {});
    }
    await pool.query('DELETE FROM verifier_audit_outbox WHERE operation_id LIKE $1', [`%p${pid}`]).catch(() => {});
    await pool.end().catch(() => {});
  }

  test('finding 1 production repro: a private result is never returned through the async read API', async (t) => {
    const pool = await connectPool(t);
    if (!pool) return;
    const workspaceId = `ws-f1-p${process.pid}`;
    try {
      const store = new PostgresVerifierStore(pool);
      const record = makeResultRecord(`sres-f1-private-p${process.pid}`);
      await store.publish({
        workspaceId, operationId: `op-f1-a-p${process.pid}`, actor: 'prn-evaluation-harness',
        operation: 'publishVerificationResult', idempotencyKey: `idem-f1-a-p${process.pid}`,
        records: [{ kind: 'result', record, acl: { visibility: 'private', allowedPrincipalIds: ['prn-reviewer'], inherited: 'strictest_of_inputs' } }],
        audit: { type: 'VERIFICATION_RESULT_PUBLISHED', recordKind: 'result', payload: {} },
      });
      // Migration 0006: PostgreSQL now PERSISTS the ACL metadata (the old
      // store returned null and had nowhere to store it).
      const acl = await store.getRecordAcl('result', record.resultId);
      assert.equal(acl.visibility, 'private');
      assert.deepEqual(acl.allowedPrincipalIds, ['prn-reviewer']);

      const AUTHORITIES = makeVerifierAuthorityRegistry([
        { principal: 'prn-evaluation-harness', roles: ['evaluation_harness'], workspaces: [workspaceId] },
        { principal: 'prn-reviewer', roles: ['reviewer'], workspaces: [workspaceId] },
      ]);
      const pending = getVerificationResult(store, {
        resultId: record.resultId, actor: 'prn-evaluation-harness', workspaceId, authorities: AUTHORITIES,
      });
      assert.ok(pending && typeof pending.then === 'function', 'the read API must be asynchronous over the Postgres store');
      // Old code: the sync call tested the PROMISE, skipped the ACL check and
      // resolved the private record. It must be a typed AclDenied now.
      await assert.rejects(pending, AclDenied, 'a private record must never resolve for a non-allowed actor');
      const seen = await getVerificationResult(store, {
        resultId: record.resultId, actor: 'prn-reviewer', workspaceId, authorities: AUTHORITIES,
      });
      assert.equal(seen.resultId, record.resultId);
    } finally {
      await cleanupWorkspace(pool, workspaceId, process.pid);
    }
  });

  test('finding 3 production repro: parallel finalizes on one grant are serialized; the day limit holds', async (t) => {
    const pool = await connectPool(t, 4);
    if (!pool) return;
    const workspaceId = `ws-f3-p${process.pid}`;
    try {
      const store = new PostgresVerifierStore(pool);
      const grantRef = `grt-f3-p${process.pid}`;
      const binding = { grantDigest: HEX_A, budget: { task: 1, campaign: 1, day: 1 }, currency: 'USD' };
      const calls = {};
      for (const suffix of ['a', 'b']) {
        const reserved = await store.beginExternalCall({
          callId: `call-f3-${suffix}-p${process.pid}`, workspaceId, actor: 'prn-evaluation-harness',
          grantRef, operationId: `op-f3-${suffix}-p${process.pid}`, reservation: { grantBinding: binding },
        });
        await store.acceptExternalCall({ callId: reserved.callId, fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness' });
        calls[suffix] = reserved;
      }
      // Two separate pool clients = two real connections racing the budget
      // check. The old code summed FINALIZED rows without any lock: both
      // checks passed and both settlements landed. Now the grant totals row
      // is locked INSIDE the finalize transaction.
      const outcomes = await Promise.allSettled([
        store.finalizeExternalCall({ callId: calls.a.callId, fencingToken: calls.a.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 1 } }),
        store.finalizeExternalCall({ callId: calls.b.callId, fencingToken: calls.b.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_B, settlement: { amount: 1 } }),
      ]);
      const fulfilled = outcomes.filter((o) => o.status === 'fulfilled');
      const rejected = outcomes.filter((o) => o.status === 'rejected');
      assert.equal(fulfilled.length, 1, 'exactly one finalize fits the budget');
      assert.equal(rejected.length, 1);
      assert.ok(rejected[0].reason instanceof BudgetExceeded, `the loser is BudgetExceeded, got: ${rejected[0].reason}`);
      const totals = await pool.query(
        'SELECT settled_task, settled_campaign, settled_day FROM verifier_grant_budget_totals WHERE grant_ref = $1',
        [grantRef],
      );
      assert.equal(totals.rows.length, 1);
      assert.ok(Number(totals.rows[0].settled_day) <= 1, 'the day scope never exceeds the grant limit');
      assert.ok(Number(totals.rows[0].settled_task) <= 1, 'the task scope never exceeds the grant limit');
      const a = await store.readExternalCall(calls.a.callId);
      const b = await store.readExternalCall(calls.b.callId);
      assert.deepEqual([a.state, b.state].sort(), ['FINALIZED', 'RECONCILIATION_REQUIRED']);
      const loser = a.state === 'RECONCILIATION_REQUIRED' ? a : b;
      assert.equal(loser.settlement, null, 'no partial settlement for the rejected finalize');
    } finally {
      await cleanupWorkspace(pool, workspaceId, process.pid);
    }
  });

  test('finding 4 production repro: an over-budget finalize commits the RECONCILIATION_REQUIRED transition atomically', async (t) => {
    const pool = await connectPool(t);
    if (!pool) return;
    const workspaceId = `ws-f4-p${process.pid}`;
    try {
      const store = new PostgresVerifierStore(pool);
      const grantRef = `grt-f4-p${process.pid}`;
      const reserved = await store.beginExternalCall({
        callId: `call-f4-p${process.pid}`, workspaceId, actor: 'prn-evaluation-harness',
        grantRef, operationId: `op-f4-p${process.pid}`,
        reservation: { grantBinding: { grantDigest: HEX_A, budget: { task: 0, campaign: 0, day: 0 }, currency: 'USD' } },
      });
      await store.acceptExternalCall({ callId: reserved.callId, fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness' });
      await assert.rejects(
        store.finalizeExternalCall({ callId: reserved.callId, fencingToken: reserved.fencingToken, actor: 'prn-evaluation-harness', responseDigest: HEX_A, settlement: { amount: 1 } }),
        BudgetExceeded,
      );
      // The transition, its reason and the reconcile event are ALREADY
      // committed when BudgetExceeded reaches the caller — one transaction,
      // no second post-COMMIT call, no window with ACCEPTED and no event.
      const call = await store.readExternalCall(reserved.callId);
      assert.equal(call.state, 'RECONCILIATION_REQUIRED');
      assert.equal(call.settlement, null);
      assert.equal(call.response_digest, null);
      const events = await pool.query(
        "SELECT event_type FROM verifier_audit_outbox WHERE record_id = $1 AND event_type = 'EXTERNAL_CALL_RECONCILIATION_REQUIRED'",
        [reserved.callId],
      );
      assert.equal(events.rows.length, 1, 'the reconcile event committed atomically with the transition');
    } finally {
      await cleanupWorkspace(pool, workspaceId, process.pid);
    }
  });
});
