// S2-006 verifier store — one interface, two implementations (spec §11):
//
//   * InMemoryVerifierStore — offline test double with the SAME fail-closed
//     semantics as PostgreSQL: atomic all-or-nothing writes, idempotency
//     keyed by (actor, operation, canonical args digest) with a typed
//     IDEMPOTENCY_CONFLICT on reuse with different arguments, operation
//     ledger + audit outbox, and the external-call state machine
//     RESERVED -> ACCEPTED -> FINALIZED -> RECONCILIATION_REQUIRED behind a
//     unique monotonically increasing fencing token.
//   * PostgresVerifierStore — pg-backed implementation following
//     src/lib/claims/postgres-store.mjs: one transaction per operation,
//     immutable payload rows (INSERT ... ON CONFLICT DO NOTHING plus payload
//     digest equality check — never an UPDATE of a payload column), ledger +
//     outbox in the same transaction, fencing tokens from a sequence.
//
// Records are immutable: a correction publishes a NEW record plus a
// verifier-invalidation-event with an explicit SUPERSEDES link — history is
// never rewritten in place. Unknown commit outcomes escalate to
// reconciliation and are never blindly retried.
import { createHash } from 'node:crypto';
import { canonicalize, canonicalDigest } from './canonical-json.mjs';
import {
  AclDenied,
  IdempotencyConflict,
  NeedsInput,
  ReconciliationRequired,
  StoreOutcomeUnknownError,
  VerifierError,
  VerifierPolicyBlock,
} from './errors.mjs';

const OPERATION_ID = /^op-[a-z0-9][a-z0-9-]{0,62}$/;
const HEX64 = /^[0-9a-f]{64}$/;

function sha256HexText(text) {
  return createHash('sha256').update(String(text), 'utf8').digest('hex');
}

function payloadDigestOf(record) {
  return sha256HexText(canonicalize(record));
}

function normalizeRecordAcl(acl) {
  if (acl === undefined || acl === null) return null;
  if (typeof acl !== 'object' || Array.isArray(acl)) {
    throw new VerifierError('ACL_INVALID', 'record acl must be an object');
  }
  const visibility = acl.visibility;
  if (!['public', 'project', 'private'].includes(visibility)) {
    throw new VerifierError('ACL_INVALID', `record acl visibility must be public|project|private, got ${String(visibility)}`);
  }
  const normalized = {
    visibility,
    inherited: typeof acl.inherited === 'string' && acl.inherited.length > 0
      ? acl.inherited
      : 'strictest_of_inputs',
  };
  if (visibility === 'private') {
    normalized.allowedPrincipalIds = [...new Set(
      (Array.isArray(acl.allowedPrincipalIds) ? acl.allowedPrincipalIds : [])
        .filter((principal) => typeof principal === 'string' && principal.length > 0),
    )].sort();
  }
  return normalized;
}

function auditEventId(type, operationId, sequence) {
  return `aud-${sha256HexText([type, operationId, sequence].join('\u0000')).slice(0, 24)}`;
}

// Idempotency key binding: hash(actor + operation + canonicalArgsDigest)
// over the canonical-json-v1 form (spec §4/§11).
export function deriveIdempotencyKey({ actor, operation, canonicalArgsDigest }) {
  if (typeof actor !== 'string' || actor.length === 0) throw new NeedsInput('idempotency key requires actor');
  if (typeof operation !== 'string' || operation.length === 0) throw new NeedsInput('idempotency key requires operation');
  if (typeof canonicalArgsDigest !== 'string' || !HEX64.test(canonicalArgsDigest)) {
    throw new NeedsInput('idempotency key requires the exact canonicalArgsDigest');
  }
  return canonicalDigest({ actor, operation, canonicalArgsDigest });
}

export class BudgetExceeded extends VerifierError {
  constructor(message, detail = undefined) {
    super('BUDGET_EXCEEDED', message, detail);
    this.name = 'BudgetExceeded';
  }
}

export const RECORD_KINDS = Object.freeze([
  'request', 'result', 'calibration_report', 'adjudication', 'run', 'invalidation',
]);

export function recordIdOf(kind, record) {
  switch (kind) {
    case 'request': return record.requestId;
    case 'result': return record.resultId;
    case 'calibration_report': return record.reportId;
    case 'adjudication': return record.adjudicationId;
    case 'run': return record.runId;
    case 'invalidation': return record.eventId;
    default: throw new VerifierError('RECORD_KIND_UNKNOWN', `unknown verifier record kind: ${kind}`);
  }
}

const EXTERNAL_STATES = Object.freeze(['RESERVED', 'ACCEPTED', 'FINALIZED', 'RECONCILIATION_REQUIRED']);

function canonicalInputDigest({ operation, records, audit }) {
  return canonicalDigest({ operation, records, audit });
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------
export class InMemoryVerifierStore {
  constructor({ clock } = {}) {
    // Decision-affecting output never depends on wall clock; the in-memory
    // store stamps telemetry with a fixed epoch unless a clock is injected.
    this.clock = clock ?? (() => '1970-01-01T00:00:00.000Z');
    this.records = new Map();   // kind -> Map(id -> record)
    this.recordMeta = new Map(); // kind -> Map(id -> { workspaceId, acl })
    this.ledger = new Map();    // `${workspaceId}\u0000${operationId}` -> entry
    this.idempotency = new Map(); // idempotencyKey -> ledgerKey
    this.outbox = [];
    this.externalCalls = new Map(); // callId -> call
    this.fencingCounter = 0;
    this.fault = null;
  }

  // Fault injection for crash simulation: 'unknown-commit' writes the record
  // and a RECONCILIATION_REQUIRED ledger entry (committed-but-unacknowledged)
  // and then throws StoreOutcomeUnknownError — the caller must escalate to
  // reconciliation instead of retrying blindly.
  injectFault(fault) {
    this.fault = fault;
  }

  #ledgerKey(workspaceId, operationId) {
    return `${workspaceId}\u0000${operationId}`;
  }

  #putRecord(kind, record, workspaceId, written, acl = undefined) {
    const id = recordIdOf(kind, record);
    if (typeof id !== 'string' || id.length === 0) throw new NeedsInput(`${kind} record has no id`);
    let byId = this.records.get(kind);
    if (!byId) {
      byId = new Map();
      this.records.set(kind, byId);
    }
    let metaById = this.recordMeta.get(kind);
    if (!metaById) {
      metaById = new Map();
      this.recordMeta.set(kind, metaById);
    }
    const existing = byId.get(id);
    const normalizedAcl = normalizeRecordAcl(acl);
    if (existing) {
      if (payloadDigestOf(existing) !== payloadDigestOf(record)) {
        throw new IdempotencyConflict(`${kind} record ${id} already exists with different content; corrections publish a new version`);
      }
      const existingMeta = metaById.get(id);
      if (!existingMeta || existingMeta.workspaceId !== workspaceId
        || canonicalDigest(existingMeta.acl ?? null) !== canonicalDigest(normalizedAcl)) {
        throw new IdempotencyConflict(`${kind} record ${id} already exists with different workspace/ACL metadata`);
      }
      return existing;
    }
    byId.set(id, record);
    // Store-level ACL metadata (review P1-3): the inherited strictest-of-
    // inputs ACL is persisted OUTSIDE the contract payload, which stays
    // byte-pure against the frozen schemas.
    metaById.set(id, { workspaceId, ...(normalizedAcl ? { acl: normalizedAcl } : {}) });
    written.push(() => {
      byId.delete(id);
      metaById.delete(id);
    });
    return record;
  }

  #pushOutbox({ type, operationId, actor, recordKind, recordId, payload }) {
    const event = {
      event_id: auditEventId(type, operationId, this.outbox.length),
      event_type: type,
      operation_id: operationId,
      actor,
      record_kind: recordKind ?? null,
      record_id: recordId ?? null,
      payload_digest: canonicalDigest(payload ?? {}),
      created_at: this.clock(),
    };
    this.outbox.push(event);
    return event;
  }

  // Atomic publish: idempotency lookup -> record + audit + outbox + ledger
  // in one all-or-nothing step. Replays return the recorded outcome without
  // writing anything twice.
  async publish({ workspaceId, operationId, actor, operation, idempotencyKey, records, audit }) {
    if (!OPERATION_ID.test(operationId ?? '')) throw new VerifierError('OPERATION_ID_INVALID', `bad operation id: ${operationId}`);
    if (!Array.isArray(records) || records.length === 0) throw new NeedsInput('publish requires at least one record');
    const ledgerKey = this.#ledgerKey(workspaceId, operationId);
    const inputDigest = canonicalInputDigest({ operation, records, audit });
    const existing = this.ledger.get(ledgerKey);
    if (existing) {
      if (existing.status === 'RECONCILIATION_REQUIRED') {
        throw new ReconciliationRequired(`operation ${operationId} is marked RECONCILIATION_REQUIRED; manual reconciliation precedes any retry`);
      }
      if (existing.actor !== actor || existing.inputDigest !== inputDigest) {
        throw new IdempotencyConflict(`operation ${operationId} already committed with a different actor/input digest`);
      }
      return { replayed: true, outcomeDigest: existing.outcomeDigest };
    }
    if (idempotencyKey !== undefined && idempotencyKey !== null) {
      const mapped = this.idempotency.get(idempotencyKey);
      if (mapped && mapped !== ledgerKey) {
        const other = this.ledger.get(mapped);
        if (other && (other.actor !== actor || other.inputDigest !== inputDigest)) {
          throw new IdempotencyConflict(`idempotency key ${idempotencyKey} already bound to a different actor/args`);
        }
        if (other && other.status === 'COMMITTED') {
          return { replayed: true, outcomeDigest: other.outcomeDigest };
        }
        if (other) {
          throw new ReconciliationRequired(`idempotency key ${idempotencyKey} maps to unreconciled operation ${other.operation ?? mapped}; reconcile first, never re-execute`);
        }
      }
    }

    const written = [];
    try {
      for (const { kind, record, acl } of records) this.#putRecord(kind, record, workspaceId, written, acl);
      if (this.fault?.at === 'unknown-commit') {
        // Crash simulation: the commit landed but the outcome is unknown to
        // the caller. Recovery records RECONCILIATION_REQUIRED; no outbox.
        this.ledger.set(ledgerKey, {
          status: 'RECONCILIATION_REQUIRED',
          actor,
          operation,
          idempotencyKey: idempotencyKey ?? null,
          inputDigest,
          outcomeDigest: null,
        });
        if (idempotencyKey) this.idempotency.set(idempotencyKey, ledgerKey);
        if (this.fault.once) this.fault = null;
        throw new StoreOutcomeUnknownError(`commit outcome of operation ${operationId} could not be confirmed`);
      }
      const primary = records[0];
      this.#pushOutbox({
        type: audit.type,
        operationId,
        actor,
        recordKind: audit.recordKind ?? primary.kind,
        recordId: audit.recordId ?? recordIdOf(primary.kind, primary.record),
        payload: audit.payload,
      });
      const outcomeDigest = canonicalDigest({
        records: records.map(({ kind, record }) => ({ kind, id: recordIdOf(kind, record) })),
      });
      this.ledger.set(ledgerKey, {
        status: 'COMMITTED',
        actor,
        operation,
        idempotencyKey: idempotencyKey ?? null,
        inputDigest,
        outcomeDigest,
      });
      if (idempotencyKey) this.idempotency.set(idempotencyKey, ledgerKey);
      return { replayed: false, outcomeDigest };
    } catch (error) {
      if (!(error instanceof StoreOutcomeUnknownError)) {
        for (const undo of written.reverse()) undo();
      }
      throw error;
    }
  }

  // ---- external call state machine -----------------------------------------

  async beginExternalCall({ callId, workspaceId, actor, grantRef, operationId, reservation }) {
    if (typeof callId !== 'string' || callId.length === 0) throw new NeedsInput('external call requires callId');
    const inputDigest = canonicalDigest({ callId, grantRef, operationId, reservation: reservation ?? {} });
    const existing = this.externalCalls.get(callId);
    if (existing) {
      if (existing.inputDigest !== inputDigest) {
        throw new IdempotencyConflict(`external call ${callId} already reserved with different arguments`);
      }
      return { callId, state: existing.state, fencingToken: existing.fencing_token, replayed: true };
    }
    this.fencingCounter += 1;
    const call = {
      call_id: callId,
      workspace_id: workspaceId,
      actor,
      grant_ref: grantRef,
      operation_id: operationId,
      state: 'RESERVED',
      fencing_token: this.fencingCounter,
      reservation: reservation ?? {},
      response_digest: null,
      settlement: null,
      reconcile_reason: null,
      inputDigest,
    };
    this.externalCalls.set(callId, call);
    this.#pushOutbox({ type: 'EXTERNAL_CALL_RESERVED', operationId, actor, recordKind: 'external_call', recordId: callId, payload: { callId, state: 'RESERVED' } });
    return { callId, state: 'RESERVED', fencingToken: call.fencing_token, replayed: false };
  }

  #externalCallOrThrow(callId) {
    const call = this.externalCalls.get(callId);
    if (!call) throw new NeedsInput(`unknown external call: ${callId}`);
    return call;
  }

  #assertFencing(call, fencingToken) {
    if (!Number.isInteger(fencingToken) || call.fencing_token !== fencingToken) {
      throw new AclDenied(`fencing token ${String(fencingToken)} is stale for call ${call.call_id} (current: ${call.fencing_token})`);
    }
  }

  // Ownership gate (review P1-2d): every transition carries the acting
  // principal; a foreign actor gets a typed denial WITHOUT any mutation.
  #assertCallActor(call, actor) {
    if (typeof actor !== 'string' || actor.length === 0) {
      throw new NeedsInput(`external call ${call.call_id} transitions require the acting principal`);
    }
    if (call.actor !== actor) {
      throw new AclDenied(`principal ${actor} does not own external call ${call.call_id} (reserved by ${call.actor})`);
    }
  }

  #assertCallWorkspace(call, workspaceId) {
    if (workspaceId !== undefined && workspaceId !== null && call.workspace_id !== workspaceId) {
      throw new AclDenied(`external call ${call.call_id} is bound to workspace ${call.workspace_id}, not ${workspaceId}`);
    }
  }

  #assertCallGrant(call, grant) {
    if (grant === undefined || grant === null) return;
    const binding = call.reservation?.grantBinding;
    if (!binding) {
      throw new VerifierError('GRANT_BINDING_MISSING', `external call ${call.call_id} carries no grant binding; finalize cannot accept a grant`);
    }
    if (canonicalDigest(grant) !== binding.grantDigest) {
      throw new VerifierPolicyBlock(`finalize grant differs from the grant bound in the reservation of ${call.call_id}`);
    }
  }

  // Settlement charge parsing (review P1-2e): the ONLY trusted charge field
  // is a non-negative finite numeric `amount`. Anything else is uncertain
  // billing and escalates to reconciliation — it never silently counts as
  // zero (which would let attacker-chosen fields like `charge: 999` through).
  #parseSettlementAmount(call, settlement) {
    if (!settlement || typeof settlement !== 'object' || Array.isArray(settlement)) return { uncertain: true };
    const amount = settlement.amount;
    if (typeof amount !== 'number' || !Number.isFinite(amount) || amount < 0) return { uncertain: true };
    return { uncertain: false, amount };
  }

  // UTC calendar day of the INJECTED deterministic clock (never the wall
  // clock): the day budget bucket key, 'YYYY-MM-DD'.
  #dayKey() {
    return String(this.clock()).slice(0, 10);
  }

  // Settled totals over a grant: task scope (this operation), campaign scope
  // (the whole grant) and day scope (the UTC calendar day of the injected
  // clock, fix2-C finding 3). Finalized calls carry the day_key they were
  // settled under.
  #settledTotals(grantRef, operationId, dayKey) {
    let task = 0;
    let campaign = 0;
    let day = 0;
    for (const call of this.externalCalls.values()) {
      if (call.state !== 'FINALIZED' || call.grant_ref !== grantRef) continue;
      const amount = call.settlement?.amount;
      if (typeof amount !== 'number' || !Number.isFinite(amount)) continue;
      campaign += amount;
      if (call.operation_id === operationId) task += amount;
      if (call.day_key === dayKey) day += amount;
    }
    return { task, campaign, day };
  }

  // Atomic failure escalation (fix2-C finding 4): the transition to
  // RECONCILIATION_REQUIRED, its reason and the audit/outbox event are ONE
  // step inside the failing operation. A crash after this step (simulated by
  // the 'escalated-commit' fault) can never leave the call ACCEPTED without
  // a reconcile event — there is no second, separate reconciliation call.
  #escalateCall(call, reason) {
    call.state = 'RECONCILIATION_REQUIRED';
    call.reconcile_reason = String(reason ?? 'unknown outcome').slice(0, 1024);
    this.#pushOutbox({ type: 'EXTERNAL_CALL_RECONCILIATION_REQUIRED', operationId: call.operation_id, actor: call.actor, recordKind: 'external_call', recordId: call.call_id, payload: { callId: call.call_id, reason: call.reconcile_reason } });
  }

  // Crash-window simulation: fires ONLY after the escalation step above has
  // been applied (the post-COMMIT point of the old PostgreSQL branch).
  #crashAfterEscalation() {
    if (this.fault?.at === 'escalated-commit') {
      if (this.fault.once) this.fault = null;
      throw new StoreOutcomeUnknownError(`escalation of external call committed; the outcome is unknown to the caller (crash window simulation)`);
    }
  }

  async acceptExternalCall({ callId, fencingToken, actor, workspaceId }) {
    const call = this.#externalCallOrThrow(callId);
    this.#assertFencing(call, fencingToken);
    this.#assertCallActor(call, actor);
    this.#assertCallWorkspace(call, workspaceId);
    if (call.state === 'ACCEPTED' || call.state === 'FINALIZED') {
      return { callId, state: call.state, fencingToken, replayed: true };
    }
    if (call.state === 'RECONCILIATION_REQUIRED') {
      throw new ReconciliationRequired(`external call ${callId} is in RECONCILIATION_REQUIRED`);
    }
    call.state = 'ACCEPTED';
    this.#pushOutbox({ type: 'EXTERNAL_CALL_ACCEPTED', operationId: call.operation_id, actor: call.actor, recordKind: 'external_call', recordId: callId, payload: { callId, state: 'ACCEPTED' } });
    return { callId, state: 'ACCEPTED', fencingToken, replayed: false };
  }

  async finalizeExternalCall({ callId, fencingToken, actor, workspaceId, grant, responseDigest, settlement }) {
    const call = this.#externalCallOrThrow(callId);
    this.#assertFencing(call, fencingToken);
    this.#assertCallActor(call, actor);
    this.#assertCallWorkspace(call, workspaceId);
    this.#assertCallGrant(call, grant);
    if (call.state === 'RECONCILIATION_REQUIRED') {
      throw new ReconciliationRequired(`external call ${callId} is in RECONCILIATION_REQUIRED; reconcile before any result`);
    }
    if (call.state === 'FINALIZED') {
      if (call.response_digest !== responseDigest || canonicalDigest(call.settlement ?? {}) !== canonicalDigest(settlement ?? {})) {
        throw new IdempotencyConflict(`external call ${callId} already finalized with a different response/settlement`);
      }
      return { callId, state: 'FINALIZED', fencingToken, replayed: true };
    }
    if (call.state !== 'ACCEPTED') {
      throw new VerifierError('INVALID_TRANSITION', `external call ${callId} cannot be finalized from state ${call.state}`);
    }
    if (typeof responseDigest !== 'string' || !HEX64.test(responseDigest)) {
      throw new NeedsInput('finalize requires the exact response digest');
    }
    const { uncertain, amount } = this.#parseSettlementAmount(call, settlement);
    if (uncertain) {
      this.#escalateCall(call, 'uncertain billing: settlement carries no parseable non-negative numeric `amount`');
      this.#crashAfterEscalation();
      throw new ReconciliationRequired(`external call ${callId} settlement amount is uncertain; escalated to reconciliation, never silently counted as zero`);
    }
    // Remaining-budget gate over the grant bound at reservation time: task,
    // campaign AND day scopes accumulate across the grant's finalized calls
    // (fix2-C finding 3: the day scope is bucketed by the UTC calendar day
    // of the injected clock). Check + write are one synchronous step: the
    // totals can never be read and charged non-atomically.
    const dayKey = this.#dayKey();
    const binding = call.reservation?.grantBinding ?? null;
    if (binding && binding.budget) {
      const { task, campaign, day } = this.#settledTotals(call.grant_ref, call.operation_id, dayKey);
      if (task + amount > binding.budget.task || campaign + amount > binding.budget.campaign || day + amount > binding.budget.day) {
        this.#escalateCall(call, `settlement ${amount} exceeds the remaining grant budget (task spent ${task}/${binding.budget.task}, campaign spent ${campaign}/${binding.budget.campaign}, day spent ${day}/${binding.budget.day})`);
        this.#crashAfterEscalation();
        throw new BudgetExceeded(`external call ${callId} settlement ${amount} exceeds the remaining budget of grant ${call.grant_ref}`);
      }
      if (binding.currency === 'none' && amount > 0) {
        this.#escalateCall(call, `no-charge grant settled a positive amount (${amount})`);
        this.#crashAfterEscalation();
        throw new BudgetExceeded(`external call ${callId} settled ${amount} under a no-charge (currency none) grant ${call.grant_ref}`);
      }
    }
    call.state = 'FINALIZED';
    call.response_digest = responseDigest;
    call.settlement = settlement ?? {};
    call.day_key = dayKey;
    this.#pushOutbox({ type: 'EXTERNAL_CALL_FINALIZED', operationId: call.operation_id, actor: call.actor, recordKind: 'external_call', recordId: callId, payload: { callId, state: 'FINALIZED', responseDigest } });
    return { callId, state: 'FINALIZED', fencingToken, replayed: false };
  }

  async markExternalCallReconciliation({ callId, fencingToken, actor, reason }) {
    const call = this.#externalCallOrThrow(callId);
    this.#assertFencing(call, fencingToken);
    this.#assertCallActor(call, actor);
    if (call.state === 'FINALIZED') {
      throw new VerifierError('INVALID_TRANSITION', `finalized call ${callId} cannot become RECONCILIATION_REQUIRED`);
    }
    if (call.state === 'RECONCILIATION_REQUIRED') {
      return { callId, state: 'RECONCILIATION_REQUIRED', replayed: true };
    }
    this.#escalateCall(call, reason);
    return { callId, state: 'RECONCILIATION_REQUIRED', replayed: false };
  }

  // ---- reads ---------------------------------------------------------------

  // Workspace-scoped read (review P1-3): with { workspaceId }, a record that
  // exists but lives in another workspace is a typed AclDenied — never a
  // silent null. The two-argument form stays the raw persistence primitive
  // (used by internal tooling, not by the ACL-enforced read API).
  // fix2-C finding 1: the read interface is ASYNCHRONOUS over BOTH stores —
  // exactly the shape PostgresVerifierStore already had — so the query API
  // awaits it and no store can bypass the ACL by testing a Promise.
  async getRecord(kind, id, { workspaceId } = {}) {
    const record = this.records.get(kind)?.get(id) ?? null;
    if (record === null || workspaceId === undefined) return record;
    const meta = this.recordMeta.get(kind)?.get(id);
    if (meta && meta.workspaceId !== workspaceId) {
      throw new AclDenied(`${kind} record ${id} exists but belongs to workspace ${meta.workspaceId}, not ${workspaceId}`);
    }
    return record;
  }

  // Store-level ACL metadata accessor (never part of the contract payload).
  async getRecordAcl(kind, id) {
    return this.recordMeta.get(kind)?.get(id)?.acl ?? null;
  }

  // Strictly workspace-scoped listing (review P1-3): a missing workspace is
  // a loud NEEDS_INPUT — a global listing across tenants can never happen.
  // Async for interface parity with PostgreSQL (fix2-C finding 1).
  async listCalibrationReports(filter = {}) {
    if (!filter || typeof filter.workspaceId !== 'string' || filter.workspaceId.length === 0) {
      throw new NeedsInput('listCalibrationReports requires a workspaceId; un-scoped listing is refused');
    }
    const all = [];
    for (const [id, record] of this.records.get('calibration_report') ?? []) {
      const meta = this.recordMeta.get('calibration_report')?.get(id);
      if (meta?.workspaceId !== filter.workspaceId) continue;
      if (filter.corpusVersion !== undefined && record.corpusVersion !== filter.corpusVersion) continue;
      all.push(record);
    }
    return all;
  }

  listOutbox() {
    return [...this.outbox];
  }

  listLedger() {
    return [...this.ledger.entries()].map(([key, entry]) => {
      const [workspaceId, operationId] = key.split('\u0000');
      return { workspaceId, operationId, ...entry };
    });
  }

  async readExternalCall(callId) {
    const call = this.externalCalls.get(callId);
    if (!call) return null;
    const { inputDigest, ...rest } = call;
    void inputDigest;
    return rest;
  }
}

// ---------------------------------------------------------------------------
// PostgreSQL implementation
// ---------------------------------------------------------------------------

// Column projections EXCLUDING the primary key, workspace_id (always bound
// from the publishing operation) and the payload/payload_digest pair.
const RECORD_SPECS = Object.freeze({
  request: {
    table: 'verifier_request',
    pk: 'request_id',
    columns(record) {
      return {
        cols: ['actor', 'idempotency_key', 'canonical_args_digest'],
        values: [record.actor, record.idempotencyKey, record.canonicalArgsDigest],
      };
    },
  },
  result: {
    table: 'verifier_result',
    pk: 'result_id',
    columns(record) {
      return {
        cols: ['request_ref', 'output_digest', 'status', 'human_decision_required'],
        values: [record.requestRef, record.outputDigest, record.status, record.humanDecisionRequired === true],
      };
    },
  },
  calibration_report: {
    table: 'verifier_calibration_report',
    pk: 'report_id',
    columns(record) {
      return {
        cols: ['corpus_version', 'thresholds_digest', 'independence_tier'],
        values: [record.corpusVersion, record.thresholdsDigest, record.independenceTier],
      };
    },
  },
  adjudication: {
    table: 'verifier_adjudication_record',
    pk: 'adjudication_id',
    columns(record) {
      return {
        cols: ['case_id', 'adjudicator'],
        values: [record.caseId, record.adjudicatorIdentity.principalId],
      };
    },
  },
  run: {
    table: 'verifier_run',
    pk: 'run_id',
    columns(record) {
      return {
        cols: ['run_kind', 'run_manifest_digest', 'prediction_set_digest'],
        values: [record.runKind, record.runManifestDigest, record.predictionSetDigest],
      };
    },
  },
  invalidation: {
    table: 'verifier_invalidation_event',
    pk: 'event_id',
    columns(record) {
      return {
        cols: ['cause'],
        values: [record.cause],
      };
    },
  },
});

export class PostgresVerifierStore {
  constructor(pool, { clock } = {}) {
    this.pool = pool;
    this.clock = clock ?? (() => new Date().toISOString().replace(/\.\d+Z$/, '.000Z'));
  }

  async #one(client, sql, params = []) {
    const res = await client.query(sql, params);
    return res.rows[0] ?? null;
  }

  async #putRecord(client, kind, record, workspaceId) {
    const spec = RECORD_SPECS[kind];
    if (!spec) throw new VerifierError('RECORD_KIND_UNKNOWN', `unknown verifier record kind: ${kind}`);
    const id = recordIdOf(kind, record);
    const { cols, values } = spec.columns(record);
    const payload = canonicalize(record);
    const digest = sha256HexText(payload);
    const allCols = [spec.pk, 'workspace_id', ...cols, 'payload', 'payload_digest'];
    const params = [id, workspaceId, ...values, payload, digest];
    const placeholders = params.map((_, i) => `$${i + 1}`);
    await client.query(
      `INSERT INTO ${spec.table} (${allCols.join(', ')})
       VALUES (${placeholders.join(', ')})
       ON CONFLICT (${spec.pk}) DO NOTHING`,
      params,
    );
    const row = await this.#one(client, `SELECT payload_digest, workspace_id FROM ${spec.table} WHERE ${spec.pk} = $1`, [id]);
    if (!row) throw new VerifierError('RECORD_WRITE_FAILED', `${kind} ${id} could not be read back`);
    if (row.payload_digest !== digest) {
      throw new IdempotencyConflict(`${kind} record ${id} already exists with different content; corrections publish a new version`);
    }
    if (row.workspace_id !== workspaceId) {
      throw new IdempotencyConflict(`${kind} record ${id} already exists in workspace ${row.workspace_id}, not ${workspaceId}`);
    }
  }

  // Store-level ACL metadata row (fix2-C finding 1, migration 0006): the
  // inherited strictest-of-inputs ACL lives OUTSIDE the frozen contract
  // payload and is written in the SAME transaction as the record itself —
  // a published record is never readable before its ACL exists.
  async #putRecordAcl(client, kind, recordId, workspaceId, acl) {
    const normalized = normalizeRecordAcl(acl);
    if (normalized) {
      await client.query(
        `INSERT INTO verifier_record_acl (record_kind, record_id, workspace_id, visibility, inherited, allowed_principal_ids)
         VALUES ($1,$2,$3,$4,$5,$6::jsonb)
         ON CONFLICT (record_kind, record_id) DO NOTHING`,
        [kind, recordId, workspaceId, normalized.visibility, normalized.inherited, JSON.stringify(normalized.allowedPrincipalIds ?? [])],
      );
    }
    const existing = await this.#one(
      client,
      'SELECT workspace_id, visibility, inherited, allowed_principal_ids FROM verifier_record_acl WHERE record_kind = $1 AND record_id = $2',
      [kind, recordId],
    );
    if (normalized === null && existing === null) return;
    const stored = existing ? normalizeRecordAcl({
      visibility: existing.visibility,
      inherited: existing.inherited,
      allowedPrincipalIds: existing.allowed_principal_ids,
    }) : null;
    if (!existing || existing.workspace_id !== workspaceId
      || canonicalDigest(stored) !== canonicalDigest(normalized)) {
      throw new IdempotencyConflict(`${kind} record ${recordId} already exists with different workspace/ACL metadata`);
    }
  }

  async publish({ workspaceId, operationId, actor, operation, idempotencyKey, records, audit }) {
    if (!OPERATION_ID.test(operationId ?? '')) throw new VerifierError('OPERATION_ID_INVALID', `bad operation id: ${operationId}`);
    if (!Array.isArray(records) || records.length === 0) throw new NeedsInput('publish requires at least one record');
    const inputDigest = canonicalInputDigest({ operation, records, audit });
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const existing = await this.#one(
        client,
        'SELECT status, actor, input_digest, outcome_digest FROM verifier_operation_ledger WHERE workspace_id = $1 AND operation_id = $2',
        [workspaceId, operationId],
      );
      if (existing) {
        await client.query('ROLLBACK');
        if (existing.status === 'RECONCILIATION_REQUIRED') {
          throw new ReconciliationRequired(`operation ${operationId} is marked RECONCILIATION_REQUIRED; manual reconciliation precedes any retry`);
        }
        if (existing.actor !== actor || existing.input_digest !== inputDigest) {
          throw new IdempotencyConflict(`operation ${operationId} already committed with a different actor/input digest`);
        }
        return { replayed: true, outcomeDigest: existing.outcome_digest };
      }
      if (idempotencyKey !== undefined && idempotencyKey !== null) {
        const mapped = await this.#one(
          client,
          'SELECT operation_id, status, actor, input_digest, outcome_digest FROM verifier_operation_ledger WHERE workspace_id = $1 AND idempotency_key = $2',
          [workspaceId, idempotencyKey],
        );
        if (mapped && mapped.operation_id !== operationId) {
          if (mapped.actor !== actor || mapped.input_digest !== inputDigest) {
            await client.query('ROLLBACK');
            throw new IdempotencyConflict(`idempotency key ${idempotencyKey} already bound to operation ${mapped.operation_id} with different actor/args`);
          }
          await client.query('ROLLBACK');
          if (mapped.status === 'COMMITTED') return { replayed: true, outcomeDigest: mapped.outcome_digest };
          throw new ReconciliationRequired(`idempotency key ${idempotencyKey} maps to unreconciled operation ${mapped.operation_id}`);
        }
      }
      for (const { kind, record, acl } of records) {
        await this.#putRecord(client, kind, record, workspaceId);
        await this.#putRecordAcl(client, kind, recordIdOf(kind, record), workspaceId, acl);
      }
      const primary = records[0];
      const eventId = auditEventId(audit.type, operationId, `${workspaceId}:${operationId}`);
      await client.query(
        `INSERT INTO verifier_audit_outbox (event_id, event_type, operation_id, actor, record_kind, record_id, payload_digest)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [
          eventId,
          audit.type,
          operationId,
          actor,
          audit.recordKind ?? primary.kind,
          audit.recordId ?? recordIdOf(primary.kind, primary.record),
          canonicalDigest(audit.payload ?? {}),
        ],
      );
      const outcomeDigest = canonicalDigest({
        records: records.map(({ kind, record }) => ({ kind, id: recordIdOf(kind, record) })),
      });
      await client.query(
        `INSERT INTO verifier_operation_ledger
           (workspace_id, operation_id, idempotency_key, actor, operation, input_digest, status, outcome_digest)
         VALUES ($1,$2,$3,$4,$5,$6,'COMMITTED',$7)`,
        [workspaceId, operationId, idempotencyKey ?? null, actor, operation, inputDigest, outcomeDigest],
      );
      await client.query('COMMIT');
      return { replayed: false, outcomeDigest };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async beginExternalCall({ callId, workspaceId, actor, grantRef, operationId, reservation }) {
    if (typeof callId !== 'string' || callId.length === 0) throw new NeedsInput('external call requires callId');
    const reservationJson = canonicalize(reservation ?? {});
    const inputDigest = canonicalDigest({ callId, grantRef, operationId, reservation: reservation ?? {} });
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const existing = await this.#one(
        client,
        `SELECT call_id, state, fencing_token, reservation,
                grant_ref, operation_id
         FROM verifier_external_call_run WHERE call_id = $1`,
        [callId],
      );
      if (existing) {
        await client.query('ROLLBACK');
        if (canonicalDigest(existing.reservation ?? {}) !== canonicalDigest(reservation ?? {}) ||
            existing.grant_ref !== grantRef || existing.operation_id !== operationId) {
          throw new IdempotencyConflict(`external call ${callId} already reserved with different arguments`);
        }
        return { callId, state: existing.state, fencingToken: Number(existing.fencing_token), replayed: true };
      }
      const fencing = await this.#one(client, "SELECT nextval('verifier_fencing_token_seq') AS token");
      const token = Number(fencing.token);
      await client.query(
        `INSERT INTO verifier_external_call_run
           (call_id, workspace_id, actor, grant_ref, operation_id, state, fencing_token, reservation)
         VALUES ($1,$2,$3,$4,$5,'RESERVED',$6,$7::jsonb)`,
        [callId, workspaceId, actor, grantRef, operationId, token, reservationJson],
      );
      await client.query(
        `INSERT INTO verifier_audit_outbox (event_id, event_type, operation_id, actor, record_kind, record_id, payload_digest)
         VALUES ($1,'EXTERNAL_CALL_RESERVED',$2,$3,'external_call',$4,$5)`,
        [auditEventId('EXTERNAL_CALL_RESERVED', operationId, callId), operationId, actor, callId, canonicalDigest({ callId, state: 'RESERVED' })],
      );
      await client.query('COMMIT');
      return { callId, state: 'RESERVED', fencingToken: token, replayed: false };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async #callOrThrow(client, callId) {
    const row = await this.#one(
      client,
      'SELECT call_id, workspace_id, actor, grant_ref, operation_id, state, fencing_token, reservation, response_digest, settlement, reconcile_reason FROM verifier_external_call_run WHERE call_id = $1 FOR UPDATE',
      [callId],
    );
    if (!row) throw new NeedsInput(`unknown external call: ${callId}`);
    return row;
  }

  // Ownership/workspace/grant gates shared with the in-memory implementation
  // (review P1-2c/d): every transition carries the acting principal; the
  // reservation freezes the grant binding; a foreign actor mutates nothing.
  #assertCallActor(call, actor) {
    if (typeof actor !== 'string' || actor.length === 0) {
      throw new NeedsInput(`external call ${call.call_id} transitions require the acting principal`);
    }
    if (call.actor !== actor) {
      throw new AclDenied(`principal ${actor} does not own external call ${call.call_id} (reserved by ${call.actor})`);
    }
  }

  #assertCallWorkspace(call, workspaceId) {
    if (workspaceId !== undefined && workspaceId !== null && call.workspace_id !== workspaceId) {
      throw new AclDenied(`external call ${call.call_id} is bound to workspace ${call.workspace_id}, not ${workspaceId}`);
    }
  }

  #assertCallGrant(call, grant) {
    if (grant === undefined || grant === null) return;
    const binding = call.reservation?.grantBinding;
    if (!binding) {
      throw new VerifierError('GRANT_BINDING_MISSING', `external call ${call.call_id} carries no grant binding; finalize cannot accept a grant`);
    }
    if (canonicalDigest(grant) !== binding.grantDigest) {
      throw new VerifierPolicyBlock(`finalize grant differs from the grant bound in the reservation of ${call.call_id}`);
    }
  }

  async #transition({ callId, fencingToken, actor, workspaceId, fromStates, toState, extraSets = undefined, params = [], eventType = null }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const call = await this.#callOrThrow(client, callId);
      if (Number(call.fencing_token) !== fencingToken) {
        await client.query('ROLLBACK');
        throw new AclDenied(`fencing token ${String(fencingToken)} is stale for call ${callId} (current: ${call.fencing_token})`);
      }
      this.#assertCallActor(call, actor);
      this.#assertCallWorkspace(call, workspaceId);
      if (call.state === toState && fromStates.includes(call.state)) {
        await client.query('ROLLBACK');
        return { callId, state: call.state, fencingToken, replayed: true };
      }
      if (!fromStates.includes(call.state)) {
        await client.query('ROLLBACK');
        if (call.state === 'RECONCILIATION_REQUIRED' && toState !== 'RECONCILIATION_REQUIRED') {
          throw new ReconciliationRequired(`external call ${callId} is in RECONCILIATION_REQUIRED`);
        }
        throw new VerifierError('INVALID_TRANSITION', `external call ${callId} cannot move ${call.state} -> ${toState}`);
      }
      const sets = ['state = $3', 'updated_at = NOW()', ...(extraSets ?? [])];
      const updated = await client.query(
        `UPDATE verifier_external_call_run SET ${sets.join(', ')} WHERE call_id = $1 AND fencing_token = $2 AND state = $${4 + params.length}`,
        [callId, fencingToken, toState, ...params, call.state],
      );
      if (updated.rowCount !== 1) throw new VerifierError('TRANSITION_RACE', `external call ${callId} changed state concurrently`);
      if (eventType) {
        await client.query(
          `INSERT INTO verifier_audit_outbox (event_id, event_type, operation_id, actor, record_kind, record_id, payload_digest)
           VALUES ($1,$2,$3,$4,'external_call',$5,$6)`,
          [auditEventId(eventType, call.operation_id, callId), eventType, call.operation_id, call.actor, callId, canonicalDigest({ callId, state: toState })],
        );
      }
      await client.query('COMMIT');
      return { callId, state: toState, fencingToken, replayed: false };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async acceptExternalCall({ callId, fencingToken, actor, workspaceId }) {
    return this.#transition({ callId, fencingToken, actor, workspaceId, fromStates: ['RESERVED'], toState: 'ACCEPTED', eventType: 'EXTERNAL_CALL_ACCEPTED' });
  }

  // UTC calendar day of the INJECTED deterministic clock (never the wall
  // clock in tests): the day budget bucket key, 'YYYY-MM-DD'.
  #dayKey() {
    return String(this.clock()).slice(0, 10);
  }

  // Campaign/day totals serialize on one grant row. Task totals use a second
  // row keyed by (grant, operation): unrelated tasks never consume each
  // other's task allowance. The lock order is always grant then task.
  async #lockGrantTotals(client, call) {
    const dayKey = this.#dayKey();
    const inserted = await this.#one(
      client,
      `INSERT INTO verifier_grant_budget_totals (grant_ref, workspace_id, day_key)
       VALUES ($1, $2, $3)
       ON CONFLICT (grant_ref) DO NOTHING
       RETURNING grant_ref`,
      [call.grant_ref, call.workspace_id, dayKey],
    );
    if (inserted) {
      await client.query(
        `UPDATE verifier_grant_budget_totals t
         SET settled_campaign = COALESCE(s.total, 0)
         FROM (
           SELECT COALESCE(SUM(CASE WHEN settlement ? 'amount' AND jsonb_typeof(settlement->'amount') = 'number'
                                    THEN (settlement->>'amount')::float8 ELSE 0 END), 0) AS total
           FROM verifier_external_call_run
           WHERE grant_ref = $1 AND state = 'FINALIZED'
         ) s
         WHERE t.grant_ref = $1`,
        [call.grant_ref],
      );
    }
    const grantTotals = await this.#one(
      client,
      'SELECT day_key, settled_task, settled_campaign, settled_day FROM verifier_grant_budget_totals WHERE grant_ref = $1 FOR UPDATE',
      [call.grant_ref],
    );
    const taskInserted = await this.#one(
      client,
      `INSERT INTO verifier_grant_task_budget_totals (grant_ref, operation_id, workspace_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (grant_ref, operation_id) DO NOTHING
       RETURNING grant_ref`,
      [call.grant_ref, call.operation_id, call.workspace_id],
    );
    if (taskInserted) {
      await client.query(
        `UPDATE verifier_grant_task_budget_totals t
         SET settled_task = COALESCE(s.total, 0)
         FROM (
           SELECT COALESCE(SUM(CASE WHEN settlement ? 'amount' AND jsonb_typeof(settlement->'amount') = 'number'
                                    THEN (settlement->>'amount')::float8 ELSE 0 END), 0) AS total
           FROM verifier_external_call_run
           WHERE grant_ref = $1 AND operation_id = $2 AND state = 'FINALIZED'
         ) s
         WHERE t.grant_ref = $1 AND t.operation_id = $2`,
        [call.grant_ref, call.operation_id],
      );
    }
    const taskTotals = await this.#one(
      client,
      `SELECT settled_task FROM verifier_grant_task_budget_totals
       WHERE grant_ref = $1 AND operation_id = $2 FOR UPDATE`,
      [call.grant_ref, call.operation_id],
    );
    return { grantTotals, taskTotals };
  }

  // Atomic failure escalation INSIDE the finalize transaction (fix2-C
  // finding 4): transition + reason + audit/outbox event commit together,
  // before COMMIT returns control to the caller. No second
  // markExternalCallReconciliation call runs after COMMIT.
  async #escalateInTransaction(client, call, fencingToken, reason) {
    const reconcileReason = String(reason ?? 'unknown outcome').slice(0, 1024);
    const updated = await client.query(
      `UPDATE verifier_external_call_run
       SET state = 'RECONCILIATION_REQUIRED', reconcile_reason = $3, updated_at = NOW()
       WHERE call_id = $1 AND fencing_token = $2 AND state = 'ACCEPTED'`,
      [call.call_id, fencingToken, reconcileReason],
    );
    if (updated.rowCount !== 1) throw new VerifierError('TRANSITION_RACE', `external call ${call.call_id} changed state concurrently`);
    await client.query(
      `INSERT INTO verifier_audit_outbox (event_id, event_type, operation_id, actor, record_kind, record_id, payload_digest)
       VALUES ($1,'EXTERNAL_CALL_RECONCILIATION_REQUIRED',$2,$3,'external_call',$4,$5)`,
      [auditEventId('EXTERNAL_CALL_RECONCILIATION_REQUIRED', call.operation_id, call.call_id), call.operation_id, call.actor, call.call_id, canonicalDigest({ callId: call.call_id, reason: reconcileReason })],
    );
    await client.query('COMMIT');
  }

  async finalizeExternalCall({ callId, fencingToken, actor, workspaceId, grant, responseDigest, settlement }) {
    if (typeof responseDigest !== 'string' || !HEX64.test(responseDigest)) {
      throw new NeedsInput('finalize requires the exact response digest');
    }
    const settlementJson = canonicalize(settlement ?? {});
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const call = await this.#callOrThrow(client, callId);
      if (Number(call.fencing_token) !== fencingToken) {
        await client.query('ROLLBACK');
        throw new AclDenied(`fencing token ${String(fencingToken)} is stale for call ${callId} (current: ${call.fencing_token})`);
      }
      this.#assertCallActor(call, actor);
      this.#assertCallWorkspace(call, workspaceId);
      this.#assertCallGrant(call, grant);
      if (call.state === 'FINALIZED') {
        await client.query('ROLLBACK');
        if (call.response_digest !== responseDigest || canonicalDigest(call.settlement ?? {}) !== canonicalDigest(settlement ?? {})) {
          throw new IdempotencyConflict(`external call ${callId} already finalized with a different response/settlement`);
        }
        return { callId, state: 'FINALIZED', fencingToken, replayed: true };
      }
      if (call.state === 'RECONCILIATION_REQUIRED') {
        await client.query('ROLLBACK');
        throw new ReconciliationRequired(`external call ${callId} is in RECONCILIATION_REQUIRED; reconcile before any result`);
      }
      if (call.state !== 'ACCEPTED') {
        await client.query('ROLLBACK');
        throw new VerifierError('INVALID_TRANSITION', `external call ${callId} cannot be finalized from state ${call.state}`);
      }
      const settlementOk = settlement !== null && typeof settlement === 'object' && !Array.isArray(settlement) &&
        typeof settlement.amount === 'number' && Number.isFinite(settlement.amount) && settlement.amount >= 0;
      if (!settlementOk) {
        // fix2-C finding 4: the transition, its reason and the audit/outbox
        // event commit IN THIS transaction (before COMMIT) — one atomic
        // step; there is no second markExternalCallReconciliation call after
        // COMMIT, so a crash can never leave ACCEPTED without an event.
        await this.#escalateInTransaction(client, call, fencingToken,
          'uncertain billing: settlement carries no parseable non-negative numeric `amount`');
        throw new ReconciliationRequired(`external call ${callId} settlement amount is uncertain; escalated to reconciliation, never silently counted as zero`);
      }
      const amount = settlement.amount;
      const binding = call.reservation?.grantBinding ?? null;
      if (binding && binding.budget) {
        // fix2-C finding 3: budget check + settlement are serialized by the
        // grant-level totals row lock (migration 0006) held until COMMIT —
        // parallel finalizes on one grant can never pass the check together,
        // and the day scope is enforced alongside task/campaign.
        const { grantTotals, taskTotals } = await this.#lockGrantTotals(client, call);
        const dayKey = this.#dayKey();
        const taskSpent = Number(taskTotals?.settled_task ?? 0);
        const campaignSpent = Number(grantTotals?.settled_campaign ?? 0);
        const daySpent = grantTotals && grantTotals.day_key === dayKey ? Number(grantTotals.settled_day) : 0;
        if (
          taskSpent + amount > binding.budget.task ||
          campaignSpent + amount > binding.budget.campaign ||
          daySpent + amount > binding.budget.day
        ) {
          await this.#escalateInTransaction(client, call, fencingToken,
            `settlement ${amount} exceeds the remaining grant budget (task spent ${taskSpent}/${binding.budget.task}, campaign spent ${campaignSpent}/${binding.budget.campaign}, day spent ${daySpent}/${binding.budget.day})`);
          throw new BudgetExceeded(`external call ${callId} settlement ${amount} exceeds the remaining budget of grant ${call.grant_ref}`);
        }
        if (binding.currency === 'none' && amount > 0) {
          await this.#escalateInTransaction(client, call, fencingToken,
            `no-charge grant settled a positive amount (${amount})`);
          throw new BudgetExceeded(`external call ${callId} settled ${amount} under a no-charge (currency none) grant ${call.grant_ref}`);
        }
        await client.query(
          `UPDATE verifier_grant_budget_totals
           SET settled_campaign = $2, settled_day = $3, day_key = $4, updated_at = NOW()
           WHERE grant_ref = $1`,
          [call.grant_ref, campaignSpent + amount, daySpent + amount, dayKey],
        );
        await client.query(
          `UPDATE verifier_grant_task_budget_totals
           SET settled_task = $3, updated_at = NOW()
           WHERE grant_ref = $1 AND operation_id = $2`,
          [call.grant_ref, call.operation_id, taskSpent + amount],
        );
      }
      const finalized = await client.query(
        `UPDATE verifier_external_call_run
         SET state = 'FINALIZED', response_digest = $3, settlement = $4::jsonb, day_key = $5, updated_at = NOW()
         WHERE call_id = $1 AND fencing_token = $2 AND state = 'ACCEPTED'`,
        [callId, fencingToken, responseDigest, settlementJson, this.#dayKey()],
      );
      if (finalized.rowCount !== 1) throw new VerifierError('TRANSITION_RACE', `external call ${callId} changed state concurrently`);
      await client.query(
        `INSERT INTO verifier_audit_outbox (event_id, event_type, operation_id, actor, record_kind, record_id, payload_digest)
         VALUES ($1,'EXTERNAL_CALL_FINALIZED',$2,$3,'external_call',$4,$5)`,
        [auditEventId('EXTERNAL_CALL_FINALIZED', call.operation_id, callId), call.operation_id, call.actor, callId, canonicalDigest({ callId, state: 'FINALIZED', responseDigest })],
      );
      await client.query('COMMIT');
      return { callId, state: 'FINALIZED', fencingToken, replayed: false };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async markExternalCallReconciliation({ callId, fencingToken, actor, reason }) {
    const reconcileReason = String(reason ?? 'unknown outcome').slice(0, 1024);
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const call = await this.#callOrThrow(client, callId);
      if (Number(call.fencing_token) !== fencingToken) {
        await client.query('ROLLBACK');
        throw new AclDenied(`fencing token ${String(fencingToken)} is stale for call ${callId} (current: ${call.fencing_token})`);
      }
      this.#assertCallActor(call, actor);
      if (call.state === 'FINALIZED') {
        await client.query('ROLLBACK');
        throw new VerifierError('INVALID_TRANSITION', `finalized call ${callId} cannot become RECONCILIATION_REQUIRED`);
      }
      if (call.state === 'RECONCILIATION_REQUIRED') {
        await client.query('ROLLBACK');
        return { callId, state: 'RECONCILIATION_REQUIRED', replayed: true };
      }
      const updated = await client.query(
        `UPDATE verifier_external_call_run
         SET state = 'RECONCILIATION_REQUIRED', reconcile_reason = $3, updated_at = NOW()
         WHERE call_id = $1 AND fencing_token = $2 AND state IN ('RESERVED','ACCEPTED')`,
        [callId, fencingToken, reconcileReason],
      );
      if (updated.rowCount !== 1) throw new VerifierError('TRANSITION_RACE', `external call ${callId} changed state concurrently`);
      await client.query(
        `INSERT INTO verifier_audit_outbox (event_id, event_type, operation_id, actor, record_kind, record_id, payload_digest)
         VALUES ($1,'EXTERNAL_CALL_RECONCILIATION_REQUIRED',$2,$3,'external_call',$4,$5)`,
        [auditEventId('EXTERNAL_CALL_RECONCILIATION_REQUIRED', call.operation_id, callId), call.operation_id, call.actor, callId, canonicalDigest({ callId, reason: reconcileReason })],
      );
      await client.query('COMMIT');
      return { callId, state: 'RECONCILIATION_REQUIRED', replayed: false };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  // Workspace-scoped read (review P1-3): same semantics as the in-memory
  // implementation — a cross-workspace hit is a typed AclDenied, not null.
  async getRecord(kind, id, { workspaceId } = {}) {
    const spec = RECORD_SPECS[kind];
    if (!spec) throw new VerifierError('RECORD_KIND_UNKNOWN', `unknown verifier record kind: ${kind}`);
    const row = await this.#one(this.pool, `SELECT payload, workspace_id FROM ${spec.table} WHERE ${spec.pk} = $1`, [id]);
    if (!row) return null;
    if (workspaceId !== undefined && row.workspace_id !== workspaceId) {
      throw new AclDenied(`${kind} record ${id} exists but belongs to workspace ${row.workspace_id}, not ${workspaceId}`);
    }
    return row.payload;
  }

  // Interface parity with the in-memory store (fix2-C finding 1, migration
  // 0006): PostgreSQL now PERSISTS the strictest-of-inputs visibility
  // metadata in verifier_record_acl and the read API enforces it.
  async getRecordAcl(kind, id) {
    const row = await this.#one(
      this.pool,
      'SELECT visibility, inherited, allowed_principal_ids FROM verifier_record_acl WHERE record_kind = $1 AND record_id = $2',
      [kind, id],
    );
    if (!row) return null;
    const acl = { visibility: row.visibility, inherited: row.inherited };
    if (Array.isArray(row.allowed_principal_ids) && row.allowed_principal_ids.length > 0) {
      acl.allowedPrincipalIds = row.allowed_principal_ids;
    }
    return acl;
  }

  async listCalibrationReports(filter = {}) {
    if (!filter || typeof filter.workspaceId !== 'string' || filter.workspaceId.length === 0) {
      throw new NeedsInput('listCalibrationReports requires a workspaceId; un-scoped listing is refused');
    }
    if (filter.corpusVersion !== undefined) {
      const res = await this.pool.query(
        'SELECT payload FROM verifier_calibration_report WHERE workspace_id = $1 AND corpus_version = $2 ORDER BY report_id',
        [filter.workspaceId, filter.corpusVersion],
      );
      return res.rows.map((row) => row.payload);
    }
    const res = await this.pool.query(
      'SELECT payload FROM verifier_calibration_report WHERE workspace_id = $1 ORDER BY report_id',
      [filter.workspaceId],
    );
    return res.rows.map((row) => row.payload);
  }

  async listOutbox() {
    const res = await this.pool.query(
      'SELECT event_id, event_type, operation_id, actor, record_kind, record_id, payload_digest, created_at FROM verifier_audit_outbox ORDER BY created_at ASC, event_id ASC',
    );
    return res.rows;
  }

  async listLedger() {
    const res = await this.pool.query(
      'SELECT workspace_id, operation_id, idempotency_key, actor, operation, input_digest, status, outcome_digest, created_at FROM verifier_operation_ledger ORDER BY created_at ASC, operation_id ASC',
    );
    return res.rows;
  }

  async readExternalCall(callId) {
    const row = await this.#one(
      this.pool,
      'SELECT call_id, workspace_id, actor, grant_ref, operation_id, state, fencing_token, reservation, response_digest, settlement, reconcile_reason FROM verifier_external_call_run WHERE call_id = $1',
      [callId],
    );
    return row ?? null;
  }
}
