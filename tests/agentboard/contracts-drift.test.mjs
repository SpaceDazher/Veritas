// S2-007 board contract drift gate.
// The JSON Schemas in contracts/ are the single source of truth for the live
// Agent Board (issue #7 §2: one authoritative contract). This file guards the
// two properties that a hand-maintained type file silently destroys:
//   1. src/lib/agentboard/contracts.d.ts is generated and never drifts from
//      the schemas — the no-write generator run is the drift check and must
//      exit 0; a tampered declaration file makes it exit 1.
//   2. Every board schema still carries its own $id and the 2020-12 draft, is
//      closed, compiles fail-closed under ajv, and still REJECTS malformed
//      documents — including the cross-document $ref closure
//      (execution-request -> board-task $defs/workspaceRef, execution-result
//      -> board-error), which must be resolved automatically rather than
//      hand-listed, and which must fail closed on a missing schema file.
//
// The generator is exercised as a subprocess here on purpose: the committed
// declaration file is temporarily rewritten by the drift probe, so a test
// worker must not be able to hold a stale in-memory copy of it.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  BOARD_CONTRACTS,
  collectExternalRefs,
  loadSchema,
  resolveContractClosure,
  generateTypes,
} from '../../scripts/generate-board-types.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUT_FILE = path.join(ROOT, 'src/lib/agentboard/contracts.d.ts');
const GENERATOR = 'scripts/generate-board-types.mjs';
const DRAFT = 'https://json-schema.org/draft/2020-12/schema';
const CONTRACTS_URL = (name) => `https://veritas.local/contracts/${name}.schema.json`;
const SHA256 = `sha256:${'a'.repeat(64)}`;
const TS = '2026-03-22T00:00:00.000Z';

function buildAjv() {
  const closure = resolveContractClosure();
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  // addSchema only registers; compilation happens on first use, so the
  // cross-document $refs resolve regardless of registration order.
  for (const [name, schema] of closure) ajv.addSchema(schema, schema.$id);
  return { closure, ajv, validate: (name, doc) => {
    const fn = ajv.getSchema(CONTRACTS_URL(name));
    assert.equal(typeof fn, 'function', `${name} did not compile`);
    const ok = fn(doc) === true;
    return { valid: ok, errors: ok ? [] : (fn.errors ?? []).map((e) => `${e.instancePath || '/'} ${e.message}`).join('; ') };
  } };
}

const WORKSPACE_REF = {
  workspace_id: 'ws-alpha',
  root_ref: 'projects/alpha',
  isolation_profile_id: 'sbx-local-restricted',
  sandbox_profile_digest: SHA256,
  read_only_paths: ['vendor'],
};

const ACL = { visibility: 'project', allowed_principal_ids: ['prn-owner'] };

function boardTask(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    task_id: 'abt-alpha-1',
    workspace_id: 'ws-alpha',
    title: 'Collect primary sources',
    goal: 'Assemble the source set for the alpha claim',
    description: 'Bounded, human-reviewed source collection.',
    acceptance_criteria: ['At least 3 primary sources with digests'],
    state: 'BACKLOG',
    revision: 1,
    priority: 'HIGH',
    dependencies: [],
    required_capabilities: ['source.read'],
    allowed_tools: ['tool:fs.read'],
    workspace_ref: WORKSPACE_REF,
    time_limits: { timeout_ms: 60000, max_runtime_ms: 120000, deadline: null },
    cost_limits: { currency: 'USD', max_task_cost: 5, max_campaign_cost: 20, max_day_cost: 10 },
    acl: ACL,
    brief_digest: SHA256,
    policy_digest: SHA256,
    manifest_digest: SHA256,
    assigned_adapter_id: null,
    active_lease_id: null,
    fencing_token: null,
    attempts: 0,
    artifacts: [],
    evidence_refs: [],
    block_reason: null,
    created_at: TS,
    updated_at: TS,
    history_digest: SHA256,
    ...overrides,
  };
}

function boardError(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    code: 'RECONCILIATION_REQUIRED',
    message: 'unknown external side effect',
    retryable: false,
    detail: null,
    occurred_at: TS,
    ...overrides,
  };
}

function executionRequest(overrides = {}) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    request_id: 'xer-alpha-1',
    idempotency_key: 'b'.repeat(64),
    task_id: 'abt-alpha-1',
    workspace_id: 'ws-alpha',
    brief_digest: SHA256,
    policy_digest: SHA256,
    manifest_digest: SHA256,
    principal_id: 'prn-owner',
    granted_scope: ['task.read', 'artifact.write'],
    allowed_tools: ['tool:fs.read'],
    workspace_ref: WORKSPACE_REF,
    budget_grant: {
      currency: 'USD',
      task_limit: 5,
      campaign_limit: 20,
      day_limit: 10,
      timeout_ms: 60000,
      granted_by: 'prn-owner',
      granted_at: TS,
    },
    deadline: null,
    lease_id: 'lse-alpha-1',
    fencing_token: 1,
    adapter_id: 'adr-test-1',
    issued_at: TS,
    ...overrides,
  };
}

function executionResult(overrides = {}) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    run_id: 'run-alpha-1',
    task_id: 'abt-alpha-1',
    workspace_id: 'ws-alpha',
    lease_id: 'lse-alpha-1',
    fencing_token: 1,
    sequence: 2,
    outcome: 'SUCCEEDED',
    checkpoints: [],
    artifact_hashes: [],
    measurements: { duration_ms: 1200, spend: 0.5, currency: 'USD', model_id: 'fixture', tool_calls: 3 },
    error: null,
    reconciliation_required: false,
    completed_at: TS,
    ...overrides,
  };
}

function executionEvent(overrides = {}) {
  return {
    contract_version: 'veritas.execution/1.0.0',
    event_id: 'eve-alpha-1',
    run_id: 'run-alpha-1',
    task_id: 'abt-alpha-1',
    workspace_id: 'ws-alpha',
    lease_id: 'lse-alpha-1',
    fencing_token: 1,
    sequence: 1,
    event_type: 'ACCEPTED',
    payload: { note: 'untrusted executor data' },
    outcome: null,
    emitted_at: TS,
    ...overrides,
  };
}

function dispatchDecision(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    decision_id: 'dsc-alpha-1',
    workspace_id: 'ws-alpha',
    max_concurrency: 1,
    selected_task_id: null,
    selected_adapter_id: null,
    selected_lease_id: null,
    selected_fencing_token: null,
    candidates: [],
    excluded: [],
    reason: 'no eligible task',
    budget_snapshot: {
      currency: 'USD',
      task_remaining: 5,
      campaign_remaining: 20,
      day_remaining: 10,
      assigned: true,
    },
    decided_at: TS,
    ...overrides,
  };
}

function adapterRegistration(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    adapter_id: 'adr-test-1',
    adapter_interface: 'veritas.adapter/1.0.0',
    provider: 'test',
    display_name: 'In-process test transport',
    adapter_kind: 'test',
    health: 'healthy',
    workspace_id: 'ws-alpha',
    principal_id: 'prn-owner',
    declared_capabilities: ['source.read'],
    declared_tools: ['tool:fs.read'],
    sandbox_profile_id: 'sbx-local-restricted',
    max_concurrency: 1,
    real_adapter_provenance: { status: 'NOT_RUN_REAL_ADAPTER', detail: 'no installed executor on this host' },
    registered_at: TS,
    ...overrides,
  };
}

function boardTransition(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    transition_id: 'trn-alpha-1',
    task_id: 'abt-alpha-1',
    workspace_id: 'ws-alpha',
    from_state: 'BACKLOG',
    to_state: 'READY',
    revision: 2,
    actor: 'prn-owner',
    idempotency_key: 'c'.repeat(64),
    reason: 'dependencies satisfied',
    lease_id: null,
    fencing_token: null,
    brief_digest: SHA256,
    policy_digest: SHA256,
    manifest_digest: SHA256,
    occurred_at: TS,
    ...overrides,
  };
}

const VALID = {
  'board-task': boardTask,
  'board-transition': boardTransition,
  'adapter-registration': adapterRegistration,
  'dispatch-decision': dispatchDecision,
  'execution-request': executionRequest,
  'execution-event': executionEvent,
  'execution-result': executionResult,
  'board-error': boardError,
};

describe('S2-007 board contract schemas', () => {
  test('the root contract list is exactly the eight S2-007 documents', () => {
    assert.deepEqual([...BOARD_CONTRACTS], [
      'board-task',
      'board-transition',
      'adapter-registration',
      'dispatch-decision',
      'execution-request',
      'execution-event',
      'execution-result',
      'board-error',
    ]);
  });

  test('every board schema carries its own $id, the 2020-12 draft, and is closed', () => {
    const { closure, ajv } = buildAjv();
    for (const name of BOARD_CONTRACTS) {
      const schema = closure.get(name);
      assert.ok(schema, `closure is missing ${name}`);
      assert.equal(schema.$schema, DRAFT, `${name} $schema draft`);
      assert.equal(schema.$id, CONTRACTS_URL(name), `${name} $id`);
      assert.equal(schema.additionalProperties, false, `${name} must stay closed`);
      assert.ok(schema.properties, `${name} must declare properties`);
      assert.ok(Array.isArray(schema.required) && schema.required.length > 0, `${name} must declare required properties`);
      assert.equal(typeof ajv.getSchema(CONTRACTS_URL(name)), 'function', `${name} did not compile`);
    }
  });

  test('the $ref closure is resolved automatically and covers every referenced contract', () => {
    const { closure } = buildAjv();
    // A schema's own $id is a contract URL too, so the walker also reports the
    // document itself; the cross-document references are what must be found
    // by walking the schemas, never by a hand-written import list.
    const referencedBy = (name) => [...collectExternalRefs(closure.get(name))].filter((ref) => ref !== name).sort();
    assert.deepEqual(referencedBy('execution-request'), ['board-task'], 'execution-request must reference board-task');
    assert.deepEqual(referencedBy('execution-result'), ['board-error'], 'execution-result must reference board-error');
    const refs = new Set();
    for (const [name, schema] of closure) {
      for (const ref of collectExternalRefs(schema)) {
        assert.ok(closure.has(ref), `${name} references ${ref}, which the closure did not resolve`);
        refs.add(ref);
      }
    }
    assert.ok(refs.has('board-task') && refs.has('board-error'));
  });

  test('the closure pulls cross-document $refs in on its own, with a reduced root set', () => {
    // Neither board-task nor board-error is listed as a root here, so they can
    // only appear because the walker followed execution-request -> board-task
    // #/$defs/workspaceRef and execution-result -> board-error.
    // Breadth-first: both roots first (in the order given), then everything
    // they reference, in deterministic sorted order.
    const reduced = resolveContractClosure(['execution-request', 'execution-result']);
    assert.deepEqual([...reduced.keys()], ['execution-request', 'execution-result', 'board-task', 'board-error']);
    // The reduced render is self-consistent: the pulled-in documents are
    // declared, so nothing dangles and nothing degrades to `unknown`.
    const source = generateTypes(['execution-request', 'execution-result']);
    assert.match(source, /export interface BoardTask \{/);
    assert.match(source, /export type BoardTaskWorkspaceRef = /);
    assert.match(source, /export interface BoardError \{/);
    assert.match(source, /export interface ExecutionRequest \{[\s\S]*?workspace_ref: BoardTaskWorkspaceRef;/);
    assert.match(source, /export interface ExecutionResult \{[\s\S]*?error: BoardError \| null;/);
    assert.doesNotMatch(source, /: unknown;/);
  });

  test('a $ref to a missing schema file fails closed instead of degrading', () => {
    assert.throws(() => loadSchema('no-such-board-contract'), (error) => {
      assert.equal(error.code, 'ENOENT');
      return true;
    });
    // A root list containing a missing document must abort generation, not
    // emit a declaration file that silently omits a contract.
    const broken = [...BOARD_CONTRACTS, 'board-task-that-was-never-written'];
    assert.throws(() => resolveContractClosure(broken), (error) => {
      assert.equal(error.code, 'ENOENT');
      return true;
    });
    assert.throws(() => generateTypes(broken), (error) => {
      assert.equal(error.code, 'ENOENT');
      return true;
    });
  });

  test('ajv accepts the reference documents of all eight contracts', () => {
    const { validate } = buildAjv();
    for (const name of BOARD_CONTRACTS) {
      const checked = validate(name, VALID[name]());
      assert.equal(checked.valid, true, `${name} reference document rejected: ${checked.errors}`);
    }
  });

  test('ajv rejects obviously malformed documents for all eight contracts', () => {
    const { validate } = buildAjv();
    for (const name of BOARD_CONTRACTS) {
      const empty = validate(name, {});
      assert.equal(empty.valid, false, `${name} accepted {} — required properties are not enforced`);
      assert.ok(empty.errors.length > 0, `${name} produced no error detail`);
      const extra = validate(name, { ...VALID[name](), not_a_contract_field: true });
      assert.equal(extra.valid, false, `${name} accepted an unknown property`);
    }
  });

  test('ajv rejects the specific mutations the board rules depend on', () => {
    const { validate } = buildAjv();
    // A tenth state must never be admissible.
    assert.equal(validate('board-task', boardTask({ state: 'APPROVED' })).valid, false);
    // A digest is `sha256:<64 hex>`; anything else is not an integrity control.
    assert.equal(validate('board-task', boardTask({ brief_digest: 'a'.repeat(64) })).valid, false);
    // Traversal and absolute paths in root_ref are rejected by the pattern.
    assert.equal(validate('board-task', boardTask({ workspace_ref: { ...WORKSPACE_REF, root_ref: '../../etc' } })).valid, false);
    assert.equal(validate('board-task', boardTask({ workspace_ref: { ...WORKSPACE_REF, root_ref: '/etc/passwd' } })).valid, false);
    // The bounded profile admits at most ONE active task.
    assert.equal(validate('dispatch-decision', dispatchDecision({ max_concurrency: 2 })).valid, false);
    assert.equal(validate('adapter-registration', adapterRegistration({ max_concurrency: 4 })).valid, false);
    // The real-adapter provenance vocabulary is closed. Whether a 'test'
    // adapter may claim REAL_ADAPTER_AVAILABLE is a CROSS-FIELD rule that JSON
    // Schema cannot express and that adapters.mjs enforces; the schema's only
    // job here is to keep the status set closed.
    assert.equal(validate('adapter-registration', adapterRegistration({
      real_adapter_provenance: { status: 'PROVEN', detail: 'invented status' },
    })).valid, false);
    // The execution boundary has one version string and one event sequence rule.
    assert.equal(validate('execution-request', executionRequest({ contract_version: 'veritas.execution/2.0.0' })).valid, false);
    assert.equal(validate('execution-event', executionEvent({ sequence: 0 })).valid, false);
    // The typed error code set is closed, and every error is bounded.
    assert.equal(validate('board-error', boardError({ code: 'RETRY_ANYWAY' })).valid, false);
    assert.equal(validate('board-error', boardError({ message: '' })).valid, false);
    assert.equal(validate('board-error', boardError({ detail: 'x'.repeat(2001) })).valid, false);
    // `retryable: false` for UNKNOWN_OUTCOME / RECONCILIATION_REQUIRED is a
    // constants.mjs rule (NON_RETRYABLE_CODES) rather than a schema rule: the
    // schema describes the shape, it cannot express the cross-field rule that
    // an unknown side effect is never blindly retryable.
    assert.equal(validate('board-error', boardError({ code: 'UNKNOWN_OUTCOME' })).valid, true);
    // A budget grant without a positive task limit is not an authorization.
    assert.equal(validate('execution-request', executionRequest({
      budget_grant: { ...executionRequest().budget_grant, task_limit: 0 },
    })).valid, false);
    // A client-asserted principal is data, not authority: the contract still
    // describes it, so the rejection happens in policy — but the boundary
    // document must at least stay structurally closed to it.
    assert.equal(validate('execution-request', executionRequest({ granted_scope: [] })).valid, false);
  });
});

describe('S2-007 generated board types', () => {
  test('contracts.d.ts declares all eight contracts and their $defs aliases', () => {
    const source = fs.readFileSync(OUT_FILE, 'utf8');
    for (const name of BOARD_CONTRACTS) {
      const typeName = name.split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('');
      assert.match(source, new RegExp(`export interface ${typeName}\\b`), `${typeName} interface missing`);
    }
    for (const alias of ['BoardTaskDigest', 'BoardTaskWorkspaceRef', 'BoardTransitionState', 'BoardTransitionDigest',
      'DispatchDecisionExclusion_reason', 'ExecutionRequestDigest']) {
      assert.match(source, new RegExp(`export type ${alias}\\b`), `${alias} alias missing`);
    }
  });

  test('a cross-document $ref renders with the owning-contract prefix, not `unknown`', () => {
    const source = fs.readFileSync(OUT_FILE, 'utf8');
    // execution-request's workspace_ref points at board-task's $defs — the
    // emitted type must be the same declared type board-task itself uses.
    assert.match(source, /export interface ExecutionRequest \{[\s\S]*?workspace_ref: BoardTaskWorkspaceRef;/);
    assert.match(source, /export interface BoardTask \{[\s\S]*?workspace_ref: BoardTaskWorkspaceRef;/);
    // execution-result's error is the whole board-error document.
    assert.match(source, /export interface ExecutionResult \{[\s\S]*?error: BoardError \| null;/);
    assert.doesNotMatch(source, /: unknown;/, 'no board contract field may degrade to `unknown`');
  });

  test('the no-write drift check exits 0 against the committed declaration file', () => {
    const check = spawnSync(process.execPath, [GENERATOR], { cwd: ROOT, encoding: 'utf8' });
    assert.equal(check.status, 0, check.stderr);
    assert.deepEqual(JSON.parse(check.stdout.trim()), {
      ok: true,
      bytes: fs.readFileSync(OUT_FILE, 'utf8').length,
      contracts: BOARD_CONTRACTS.length,
    });
  });

  test('--write is idempotent and the drift check fails closed on tampering', () => {
    const original = fs.readFileSync(OUT_FILE, 'utf8');
    try {
      const write1 = spawnSync(process.execPath, [GENERATOR, '--write'], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(write1.status, 0, write1.stderr);
      const written = fs.readFileSync(OUT_FILE, 'utf8');
      assert.equal(written, generateTypes(), '--write output must equal generateTypes()');
      const write2 = spawnSync(process.execPath, [GENERATOR, '--write'], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(write2.status, 0, write2.stderr);
      assert.equal(fs.readFileSync(OUT_FILE, 'utf8'), written, '--write must be idempotent');

      fs.writeFileSync(OUT_FILE, `${written}\n// drift\n`);
      const drift = spawnSync(process.execPath, [GENERATOR], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(drift.status, 1, 'the drift check must exit 1 on a stale declaration file');
      assert.match(drift.stderr, /DRIFT/);
      const repair = spawnSync(process.execPath, [GENERATOR, '--write'], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(repair.status, 0, repair.stderr);
      assert.equal(fs.readFileSync(OUT_FILE, 'utf8'), written, '--write must repair drift to the exact canonical bytes');
    } finally {
      fs.writeFileSync(OUT_FILE, original);
    }
  });
});
