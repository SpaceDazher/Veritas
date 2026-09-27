// S2-007 — the contract surface gate for the live Agent Board
// (issue #7 §2 "one authoritative contract"; module spec §1 and §3.1).
//
// WHY THIS FILE EXISTS. contracts/*.schema.json plus
// src/lib/agentboard/contracts.mjs are the ONE place where a board document
// may exist (spec rule 1). Everything downstream — Web, HTTP API, CLI,
// scheduler, store, test transport — is supposed to be incapable of inventing
// a second payload form. A schema that silently accepts an unknown member, an
// unknown enum value or a missing required field destroys that guarantee and
// nothing else in the repository would notice: a store would happily write the
// malformed row and a digest would happily bind to it.
//
// So every claim this file makes is a FAIL-CLOSED claim:
//   * the registry is exactly the eight frozen documents, each with its own
//     $id and the 2020-12 draft, and each reachable only by name;
//   * a minimal document validates, and a document with ANY required field
//     removed, ANY unknown additional property, or ANY value outside a closed
//     enum is refused with a TYPED BoardError — never a silent accept, never
//     an untyped throw;
//   * the version handshake is fail-closed: a board document carries exactly
//     1.0.0, an execution document is veritas.execution/1.0.0, an unknown
//     MAJOR is CONTRACT_VERSION_UNKNOWN before any read, and the same major
//     with another minor is only a negotiated subset;
//   * assertDigestAgreement detects a moved-on artifact, because a digest is an
//     integrity control that is worthless if it does not notice movement;
//   * and the public synthetic demo (veritas_demo_*, src/lib/board.ts) is NOT
//     a BoardTask, so the demo can never masquerade as a live task.
//
// The required-field list, the enum members and the closed-ness of every
// schema are READ from the committed schema files rather than hand-copied
// here: a hand-copied list is a second, independently editable form of the
// contract — the very thing spec rule 1 forbids.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BOARD_CONTRACTS,
  CONTRACT_FILES,
  CONTRACT_IDS,
  CONTRACT_VERSION,
  allContractDigests,
  assertAdapterVersion,
  assertBoardContract,
  assertBoardVersion,
  assertDigestAgreement,
  assertExecutionVersion,
  boardContractErrors,
  contractDigest,
  isBoardContractValid,
} from '../../src/lib/agentboard/contracts.mjs';
import {
  ADAPTER_INTERFACE_VERSION,
  BOARD_CONTRACT_VERSION,
  BOARD_STATES,
  ERROR_CODES,
  EXECUTION_CONTRACT_VERSION,
  EXECUTION_SCOPES,
} from '../../src/lib/agentboard/constants.mjs';
import { isBoardError, NeedsInput } from '../../src/lib/agentboard/errors.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');
const DRAFT = 'https://json-schema.org/draft/2020-12/schema';
const TS = '2026-03-22T09:30:00.000Z';
const HEX64 = 'f'.repeat(64);
/** A digest that is NOT the one above, used to prove movement is detected. */
const HEX64_MOVED = 'e'.repeat(64);
const sha = (hex) => `sha256:${hex}`;
const OUTSIDE = 'S2_007_OUTSIDE_EVERY_ENUM';

const WORKSPACE_REF = Object.freeze({
  workspace_id: 'ws-alpha',
  root_ref: 'projects/alpha',
  isolation_profile_id: 'sbx-podman-local-restricted-v1',
  sandbox_profile_digest: sha(HEX64),
  read_only_paths: [],
});

// --- the eight minimal, fully valid documents -------------------------------
// Each is built fresh per assertion: a shared mutable fixture would let one
// test's edit silently change what the next test validates.

function minimalBoardTask() {
  return {
    contractVersion: '1.0.0',
    task_id: 'abt-alpha',
    workspace_id: 'ws-alpha',
    title: 'Minimal board task',
    goal: 'prove a minimal document satisfies the canonical contract',
    description: '',
    acceptance_criteria: ['one criterion is enough'],
    state: 'BACKLOG',
    revision: 1,
    priority: 'MEDIUM',
    dependencies: [],
    required_capabilities: [],
    allowed_tools: [],
    workspace_ref: { ...WORKSPACE_REF },
    time_limits: { timeout_ms: 1000, max_runtime_ms: 5000, deadline: null },
    cost_limits: { currency: 'USD', max_task_cost: 1, max_campaign_cost: 2, max_day_cost: 3 },
    acl: { visibility: 'project', allowed_principal_ids: ['prn-owner'] },
    brief_digest: sha(HEX64),
    policy_digest: sha(HEX64),
    manifest_digest: sha(HEX64),
    assigned_adapter_id: null,
    active_lease_id: null,
    fencing_token: null,
    attempts: 0,
    artifacts: [],
    evidence_refs: [],
    block_reason: null,
    created_at: TS,
    updated_at: TS,
    history_digest: sha(HEX64),
  };
}

function minimalBoardTransition() {
  return {
    contractVersion: '1.0.0',
    transition_id: 'trn-alpha-1',
    task_id: 'abt-alpha',
    workspace_id: 'ws-alpha',
    from_state: 'BACKLOG',
    to_state: 'READY',
    revision: 2,
    actor: 'prn-owner',
    idempotency_key: 'a'.repeat(64),
    reason: 'dependencies are DONE and the brief validated',
    lease_id: null,
    fencing_token: null,
    brief_digest: sha(HEX64),
    policy_digest: sha(HEX64),
    manifest_digest: sha(HEX64),
    occurred_at: TS,
  };
}

function minimalAdapterRegistration() {
  return {
    contractVersion: '1.0.0',
    adapter_id: 'adr-test-transport',
    adapter_interface: 'veritas.adapter/1.0.0',
    provider: 'test',
    display_name: 'in-process test transport',
    adapter_kind: 'test',
    health: 'unknown',
    workspace_id: 'ws-alpha',
    principal_id: 'prn-adapter',
    declared_capabilities: [],
    declared_tools: [],
    sandbox_profile_id: 'sbx-podman-local-restricted-v1',
    max_concurrency: 1,
    real_adapter_provenance: { status: 'NOT_RUN_REAL_ADAPTER', detail: 'no real executor is installed on this host' },
    registered_at: TS,
  };
}

function minimalDispatchDecision() {
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
    reason: 'no READY task in this workspace',
    budget_snapshot: {
      currency: 'USD',
      task_remaining: 0,
      campaign_remaining: 0,
      day_remaining: 0,
      assigned: false,
    },
    decided_at: TS,
  };
}

function minimalExecutionRequest() {
  return {
    contract_version: 'veritas.execution/1.0.0',
    request_id: 'xer-alpha-1',
    idempotency_key: 'b'.repeat(64),
    task_id: 'abt-alpha',
    workspace_id: 'ws-alpha',
    brief_digest: sha(HEX64),
    policy_digest: sha(HEX64),
    manifest_digest: sha(HEX64),
    principal_id: 'prn-adapter',
    granted_scope: ['task.read'],
    allowed_tools: [],
    workspace_ref: { ...WORKSPACE_REF },
    budget_grant: {
      currency: 'USD',
      task_limit: 1,
      campaign_limit: 2,
      day_limit: 3,
      timeout_ms: 1000,
      granted_by: 'prn-owner',
      granted_at: TS,
    },
    deadline: null,
    lease_id: 'lse-alpha-1',
    fencing_token: 1,
    adapter_id: 'adr-test-transport',
    issued_at: TS,
  };
}

function minimalExecutionEvent() {
  return {
    contract_version: 'veritas.execution/1.0.0',
    event_id: 'eve-alpha-1',
    run_id: 'run-alpha-1',
    task_id: 'abt-alpha',
    workspace_id: 'ws-alpha',
    lease_id: 'lse-alpha-1',
    fencing_token: 1,
    sequence: 1,
    event_type: 'PROGRESS',
    payload: {},
    outcome: null,
    emitted_at: TS,
  };
}

function minimalExecutionResult() {
  return {
    contract_version: 'veritas.execution/1.0.0',
    run_id: 'run-alpha-1',
    task_id: 'abt-alpha',
    workspace_id: 'ws-alpha',
    lease_id: 'lse-alpha-1',
    fencing_token: 1,
    sequence: 7,
    outcome: 'SUCCEEDED',
    checkpoints: [],
    artifact_hashes: [],
    measurements: { duration_ms: 1200, spend: 0.25, currency: 'USD', model_id: null, tool_calls: 3 },
    error: null,
    reconciliation_required: false,
    completed_at: TS,
  };
}

function minimalBoardError() {
  return {
    contractVersion: '1.0.0',
    code: 'MALFORMED_RESULT',
    message: 'the executor returned a document that is not contract valid',
    retryable: false,
    detail: null,
    occurred_at: TS,
  };
}

const MINIMALS = Object.freeze({
  'board-task': minimalBoardTask,
  'board-transition': minimalBoardTransition,
  'adapter-registration': minimalAdapterRegistration,
  'dispatch-decision': minimalDispatchDecision,
  'execution-request': minimalExecutionRequest,
  'execution-event': minimalExecutionEvent,
  'execution-result': minimalExecutionResult,
  'board-error': minimalBoardError,
});

// The version field each document family carries, read from the schema itself.
const VERSION_FIELD = Object.freeze({
  'board-task': 'contractVersion',
  'board-transition': 'contractVersion',
  'adapter-registration': 'contractVersion',
  'dispatch-decision': 'contractVersion',
  'board-error': 'contractVersion',
  'execution-request': 'contract_version',
  'execution-event': 'contract_version',
  'execution-result': 'contract_version',
});

// Closed enums per document, addressed by JSON pointer into the committed
// schema (never hand-typed) with the document mutation that exercises it.
const ENUM_PROBES = Object.freeze({
  'board-task': [
    { pointer: '/properties/state/enum', doc: (v) => ({ ...minimalBoardTask(), state: v }) },
    { pointer: '/properties/priority/enum', doc: (v) => ({ ...minimalBoardTask(), priority: v }) },
    {
      pointer: '/properties/cost_limits/properties/currency/enum',
      doc: (v) => ({ ...minimalBoardTask(), cost_limits: { currency: v, max_task_cost: 1, max_campaign_cost: 2, max_day_cost: 3 } }),
    },
    {
      pointer: '/properties/acl/properties/visibility/enum',
      doc: (v) => ({ ...minimalBoardTask(), acl: { visibility: v, allowed_principal_ids: ['prn-owner'] } }),
    },
  ],
  'board-transition': [
    { pointer: '/$defs/state/enum', doc: (v) => ({ ...minimalBoardTransition(), from_state: v }) },
    { pointer: '/$defs/state/enum', doc: (v) => ({ ...minimalBoardTransition(), to_state: v }) },
  ],
  'adapter-registration': [
    { pointer: '/properties/provider/enum', doc: (v) => ({ ...minimalAdapterRegistration(), provider: v }) },
    { pointer: '/properties/adapter_kind/enum', doc: (v) => ({ ...minimalAdapterRegistration(), adapter_kind: v }) },
    { pointer: '/properties/health/enum', doc: (v) => ({ ...minimalAdapterRegistration(), health: v }) },
    {
      pointer: '/properties/real_adapter_provenance/properties/status/enum',
      doc: (v) => ({ ...minimalAdapterRegistration(), real_adapter_provenance: { status: v, detail: 'probe result' } }),
    },
  ],
  'dispatch-decision': [
    {
      pointer: '/properties/excluded/items/properties/subject_kind/enum',
      doc: (v) => ({ ...minimalDispatchDecision(), excluded: [{ subject_kind: v, subject_id: 'abt-alpha', reasons: ['STATE_NOT_READY'] }] }),
    },
    {
      pointer: '/$defs/exclusion_reason/enum',
      doc: (v) => ({ ...minimalDispatchDecision(), excluded: [{ subject_kind: 'task', subject_id: 'abt-alpha', reasons: [v] }] }),
    },
    {
      pointer: '/properties/budget_snapshot/properties/currency/enum',
      doc: (v) => ({
        ...minimalDispatchDecision(),
        budget_snapshot: { currency: v, task_remaining: 0, campaign_remaining: 0, day_remaining: 0, assigned: false },
      }),
    },
  ],
  'execution-request': [
    { pointer: '/properties/granted_scope/items/enum', doc: (v) => ({ ...minimalExecutionRequest(), granted_scope: [v] }) },
    {
      pointer: '/properties/budget_grant/properties/currency/enum',
      doc: (v) => ({ ...minimalExecutionRequest(), budget_grant: { ...minimalExecutionRequest().budget_grant, currency: v } }),
    },
  ],
  'execution-event': [
    { pointer: '/properties/event_type/enum', doc: (v) => ({ ...minimalExecutionEvent(), event_type: v }) },
    { pointer: '/properties/outcome/oneOf/0/enum', doc: (v) => ({ ...minimalExecutionEvent(), outcome: v }) },
  ],
  'execution-result': [
    { pointer: '/properties/outcome/enum', doc: (v) => ({ ...minimalExecutionResult(), outcome: v }) },
    {
      pointer: '/properties/measurements/properties/currency/enum',
      doc: (v) => ({ ...minimalExecutionResult(), measurements: { ...minimalExecutionResult().measurements, currency: v } }),
    },
  ],
  'board-error': [
    { pointer: '/properties/code/enum', doc: (v) => ({ ...minimalBoardError(), code: v }) },
  ],
});

const schemaCache = new Map();

function schemaOf(name) {
  if (!schemaCache.has(name)) {
    const file = path.join(CONTRACTS_DIR, CONTRACT_FILES[name]);
    schemaCache.set(name, JSON.parse(readFileSync(file, 'utf8')));
  }
  return schemaCache.get(name);
}

/** Resolve a JSON pointer against a schema and return the value it addresses. */
function atPointer(document, pointer) {
  let node = document;
  for (const segment of pointer.split('/').slice(1)) {
    node = node?.[segment];
  }
  return node;
}

function isClosedEnum(value) {
  return Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === 'string');
}

function refusalOf(name, document) {
  let thrown = null;
  try {
    assertBoardContract(name, document);
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown !== null, `${name} accepted a document it must refuse: ${JSON.stringify(document)}`);
  assert.ok(isBoardError(thrown), `${name} refused with an untyped ${thrown?.name}: ${thrown?.message}`);
  assert.ok(ERROR_CODES.includes(thrown.code), `${name} refused with a code outside the closed set: ${thrown.code}`);
  return thrown;
}

describe('S2-007 contract registry: closed, named and fail-closed', () => {
  test('exactly the eight frozen board documents are registered', () => {
    assert.equal(BOARD_CONTRACTS.length, 8);
    assert.deepEqual([...BOARD_CONTRACTS].sort(), [
      'adapter-registration',
      'board-error',
      'board-task',
      'board-transition',
      'dispatch-decision',
      'execution-event',
      'execution-request',
      'execution-result',
    ]);
    for (const name of BOARD_CONTRACTS) {
      assert.match(CONTRACT_FILES[name], /^[a-z-]+\.schema\.json$/);
      assert.equal(CONTRACT_IDS[name], `https://veritas.local/contracts/${CONTRACT_FILES[name]}`);
    }
  });

  test('every registered document is the 2020-12 draft under its own $id and is closed', () => {
    for (const name of BOARD_CONTRACTS) {
      const schema = schemaOf(name);
      assert.equal(schema.$schema, DRAFT, `${name} left the frozen draft`);
      assert.equal(schema.$id, CONTRACT_IDS[name], `${name} carries a foreign $id`);
      assert.equal(schema.additionalProperties, false, `${name} is not closed: an unknown member would survive`);
      assert.ok(Array.isArray(schema.required) && schema.required.length > 0, `${name} declares no required fields`);
    }
  });

  test('the registry version is the frozen board version and every contract has a digest', () => {
    assert.equal(CONTRACT_VERSION, BOARD_CONTRACT_VERSION);
    const digests = allContractDigests();
    assert.deepEqual(Object.keys(digests).sort(), [...BOARD_CONTRACTS].sort());
    for (const name of BOARD_CONTRACTS) {
      assert.match(digests[name], /^sha256:[0-9a-f]{64}$/, `${name} has no sha256 digest`);
      assert.equal(contractDigest(name), digests[name], `${name} digest is not stable`);
    }
  });

  test('an unknown contract name is refused instead of validated best-effort', () => {
    let thrown = null;
    try {
      assertBoardContract('board-task-v2', minimalBoardTask());
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown instanceof NeedsInput, `an unknown contract must be NeedsInput, got ${thrown?.name}`);
    assert.equal(isBoardContractValid('board-task-v2', minimalBoardTask()), false);
  });

  test('a non-object document is refused with a typed error', () => {
    for (const bad of [null, 'abt-alpha', 42, [], undefined]) {
      const thrown = refusalOf('board-task', bad);
      assert.equal(thrown.code, 'MALFORMED_RESULT');
      assert.equal(isBoardContractValid('board-task', bad), false);
    }
  });

  test('boardContractErrors explains the refusal without a second validator', () => {
    const errors = boardContractErrors('board-task', { contractVersion: '1.0.0' });
    assert.ok(Array.isArray(errors) && errors.length > 0, 'a refusal must be explainable');
    assert.ok(errors.some((line) => line.includes('task_id')), `errors did not name the missing field: ${errors.join('; ')}`);
  });
});

for (const name of BOARD_CONTRACTS) {
  describe(`S2-007 contract: ${name}`, () => {
    test('a fully valid minimal document validates', () => {
      const document = MINIMALS[name]();
      assert.equal(assertBoardContract(name, document), document, 'validation must return the document unchanged');
      assert.equal(isBoardContractValid(name, document), true);
      assert.deepEqual(boardContractErrors(name, document), []);
    });

    test('every required field is required', () => {
      for (const field of schemaOf(name).required) {
        const document = MINIMALS[name]();
        assert.ok(Object.hasOwn(document, field), `the minimal ${name} fixture omits required field ${field}`);
        delete document[field];
        const thrown = refusalOf(name, document);
        assert.equal(thrown.code, 'MALFORMED_RESULT');
        assert.equal(isBoardContractValid(name, document), false, `${name} accepted a document without ${field}`);
      }
    });

    test('an unknown additional property is refused', () => {
      for (const extra of ['unknown_field', 'granted_scope', 'principal_id', 'history_digest_v2']) {
        const document = { ...MINIMALS[name](), [extra]: 'sneaked-in' };
        const thrown = refusalOf(name, document);
        assert.equal(thrown.code, 'MALFORMED_RESULT');
        assert.equal(isBoardContractValid(name, document), false, `${name} accepted the unknown property ${extra}`);
      }
    });

    test('every member of every closed enum is accepted and anything else is refused', () => {
      const probes = ENUM_PROBES[name];
      assert.ok(Array.isArray(probes) && probes.length > 0, `${name} has no closed enum under test`);
      for (const probe of probes) {
        const values = atPointer(schemaOf(name), probe.pointer);
        assert.ok(isClosedEnum(values), `${name}${probe.pointer} is not a closed enum of strings: ${JSON.stringify(values)}`);
        for (const value of values) {
          const document = probe.doc(value);
          assert.equal(isBoardContractValid(name, document), true, `${name}${probe.pointer} refused the declared value ${value}`);
        }
        assert.equal(isBoardContractValid(name, probe.doc(OUTSIDE)), false, `${name}${probe.pointer} accepted a value outside the enum`);
        const thrown = refusalOf(name, probe.doc(OUTSIDE));
        assert.equal(thrown.code, 'MALFORMED_RESULT');
      }
    });

    test('a document carrying an unknown contract version is refused', () => {
      const field = VERSION_FIELD[name];
      const good = MINIMALS[name]();
      const acceptedVersion = good[field];
      assert.equal(isBoardContractValid(name, good), true);

      for (const wrong of ['9.9.9', '0.0.1', '1.0', '1.0.0-rc1', '', 2]) {
        const document = { ...good, [field]: wrong };
        assert.equal(isBoardContractValid(name, document), false, `${name} accepted contract version ${String(wrong)}`);
        const thrown = refusalOf(name, document);
        assert.equal(thrown.code, 'MALFORMED_RESULT');
      }
      // The typed handshake is what NAMES the version failure, before a document
      // is interpreted at all (spec §3.1).
      if (field === 'contractVersion') {
        assert.throws(() => assertBoardVersion({ contractVersion: '9.9.9' }), (error) => {
          assert.ok(isBoardError(error));
          assert.equal(error.code, 'CONTRACT_VERSION_UNKNOWN');
          return true;
        });
      }
      assert.ok(typeof acceptedVersion === 'string' && acceptedVersion.length > 0);
    });
  });
}

describe('S2-007 closed enums and constants cannot drift apart', () => {
  test('board-task state is exactly the nine canonical states', () => {
    assert.deepEqual(atPointer(schemaOf('board-task'), '/properties/state/enum'), [...BOARD_STATES]);
  });

  test('board-transition from_state and to_state are the same nine states', () => {
    assert.deepEqual(atPointer(schemaOf('board-transition'), '/$defs/state/enum'), [...BOARD_STATES]);
  });

  test('board-error code is exactly ERROR_CODES', () => {
    assert.deepEqual([...atPointer(schemaOf('board-error'), '/properties/code/enum')].sort(), [...ERROR_CODES].sort());
  });

  test('execution-request granted_scope is exactly EXECUTION_SCOPES', () => {
    assert.deepEqual(
      [...atPointer(schemaOf('execution-request'), '/properties/granted_scope/items/enum')].sort(),
      [...EXECUTION_SCOPES].sort(),
    );
  });

  test('the execution family pins the same version string', () => {
    for (const name of ['execution-request', 'execution-event', 'execution-result']) {
      assert.equal(
        atPointer(schemaOf(name), '/properties/contract_version/const'),
        EXECUTION_CONTRACT_VERSION,
        `${name} pins a different execution version`,
      );
    }
    assert.equal(atPointer(schemaOf('adapter-registration'), '/properties/adapter_interface/const'), ADAPTER_INTERFACE_VERSION);
    assert.equal(atPointer(schemaOf('board-task'), '/properties/contractVersion/const'), BOARD_CONTRACT_VERSION);
  });
});

describe('S2-007 version handshake is fail-closed', () => {
  test('the board version is exactly 1.0.0', () => {
    assert.equal(assertBoardVersion({ contractVersion: BOARD_CONTRACT_VERSION }), true);
    for (const wrong of ['2.0.0', '1.0', '0.9.9', '', null, undefined, '1.0.0 ']) {
      let thrown = null;
      try {
        assertBoardVersion({ contractVersion: wrong });
      } catch (error) {
        thrown = error;
      }
      assert.ok(isBoardError(thrown), `board version ${String(wrong)} was not refused with a typed error`);
      assert.equal(thrown.code, 'CONTRACT_VERSION_UNKNOWN', `board version ${String(wrong)} gave ${thrown.code}`);
    }
  });

  test('an unknown MAJOR of veritas.execution/1.0.0 is rejected before any read', () => {
    for (const wrong of ['veritas.execution/2.0.0', 'veritas.execution/0.1.0', 'veritas.execution/10.0.0']) {
      let thrown = null;
      try {
        assertExecutionVersion({ contract_version: wrong });
      } catch (error) {
        thrown = error;
      }
      assert.ok(isBoardError(thrown), `${wrong} was not refused with a typed error`);
      assert.equal(thrown.code, 'CONTRACT_VERSION_UNKNOWN', `${wrong} gave ${thrown.code}`);
    }
  });

  // KNOWN DEFECT IN THE FROZEN FOUNDATION, asserted against the spec and
  // therefore RED until the contracts.mjs owner fixes it: contracts.mjs
  // `majorOf()` is anchored to a BARE semver (/^\d+\.\d+\.\d+$/) and is
  // applied to the whole `veritas.execution/1.1.0` string, so the negotiated
  // -minor branch is unreachable for any properly prefixed version and the
  // message is the misleading "not a semantic version". The module spec
  // (issue #7 §2, spec §3.1) requires same-major/different-minor to be
  // accepted as a negotiated subset, so this test states the requirement and
  // is expected to fail until the frozen module is corrected. contracts.mjs is
  // not this worker's file and was NOT edited.
  test('the same major with another minor is only a negotiated subset', () => {
    const exact = assertExecutionVersion({ contract_version: EXECUTION_CONTRACT_VERSION });
    assert.equal(exact.minor, '0');
    assert.equal(exact.negotiated, false, 'the exact version is not a negotiated subset');

    for (const [version, minor] of [['veritas.execution/1.1.0', '1'], ['veritas.execution/1.9.3', '9']]) {
      const negotiated = assertExecutionVersion({ contract_version: version });
      assert.equal(negotiated.minor, minor);
      assert.equal(negotiated.negotiated, true, `${version} must be reported as a negotiated subset`);
    }
  });

  test('a non-semver execution version is refused rather than coerced', () => {
    for (const wrong of ['veritas.execution', 'veritas.execution/1.0', 'veritas.execution/1.0.x', 'veritas.execution/1.2.3-beta']) {
      let thrown = null;
      try {
        assertExecutionVersion({ contract_version: wrong });
      } catch (error) {
        thrown = error;
      }
      assert.ok(isBoardError(thrown), `${wrong} was not refused`);
      assert.equal(thrown.code, 'CONTRACT_VERSION_UNKNOWN');
    }
  });

  test('a non-object execution payload is refused', () => {
    for (const bad of [null, 'veritas.execution/1.0.0', 1, []]) {
      let thrown = null;
      try {
        assertExecutionVersion(bad);
      } catch (error) {
        thrown = error;
      }
      assert.ok(isBoardError(thrown));
      assert.equal(thrown.code, 'CONTRACT_VERSION_UNKNOWN');
    }
  });

  test('the adapter interface version is exact', () => {
    assert.equal(assertAdapterVersion(ADAPTER_INTERFACE_VERSION), true);
    for (const wrong of ['veritas.adapter/1.1.0', 'veritas.adapter/2.0.0', 'veritas.execution/1.0.0', '', null]) {
      let thrown = null;
      try {
        assertAdapterVersion(wrong);
      } catch (error) {
        thrown = error;
      }
      assert.ok(isBoardError(thrown), `adapter version ${String(wrong)} was not refused`);
      assert.equal(thrown.code, 'CONTRACT_VERSION_UNKNOWN');
    }
  });
});

describe('S2-007 digest agreement detects a moved-on artifact', () => {
  test('an unchanged digest agrees', () => {
    assert.equal(assertDigestAgreement(sha(HEX64), sha(HEX64), 'brief'), true);
  });

  test('a moved-on digest is detected, not tolerated', () => {
    let thrown = null;
    try {
      assertDigestAgreement(sha(HEX64), sha(HEX64_MOVED), 'brief');
    } catch (error) {
      thrown = error;
    }
    assert.ok(isBoardError(thrown), 'a moved-on digest must raise a typed error');
    assert.equal(thrown.code, 'MALFORMED_RESULT');
    assert.match(thrown.message, /DIGEST_MISMATCH/);
    assert.ok(!thrown.message.includes(HEX64_MOVED), 'the detail leaked the artifact digest verbatim');
  });

  test('every bound document digest participates, not only the first', () => {
    for (const label of ['brief', 'policy', 'manifest', 'artifact', 'workspace']) {
      let thrown = null;
      try {
        assertDigestAgreement(sha(HEX64), sha(HEX64_MOVED), label);
      } catch (error) {
        thrown = error;
      }
      assert.equal(thrown?.code, 'MALFORMED_RESULT', `the ${label} digest was not checked`);
    }
  });

  // assertDigestAgreement is the EQUALITY half of the digest control: it proves
  // nothing moved. The shape half ("an observed digest must be present at
  // all") belongs to policy.assertDigestsMatch and is asserted in
  // policy.test.mjs, so this file only requires that an absent or empty value
  // on one side can never be reported as agreement with a real digest.
  test('a missing or empty digest on one side is a mismatch, never a pass', () => {
    for (const pair of [[undefined, sha(HEX64)], [sha(HEX64), undefined], ['', sha(HEX64)], [sha(HEX64), ''], [null, sha(HEX64)]]) {
      let thrown = null;
      try {
        assertDigestAgreement(pair[0], pair[1], 'brief');
      } catch (error) {
        thrown = error;
      }
      assert.ok(isBoardError(thrown), `digests ${JSON.stringify(pair)} were treated as agreeing`);
      assert.equal(thrown.code, 'MALFORMED_RESULT');
    }
  });
});

// The public synthetic demo (migrations/0001 veritas_demo_tasks, src/db/schema.ts
// boardTasks, src/lib/board.ts fixtures). It is a public planning fixture and
// keeps its labelling forever (spec rule 4). This test is the mechanical proof
// that it cannot masquerade as a live BoardTask: the two shapes are disjoint in
// the CONTRACT, not merely in intent.
const DEMO_ROW = Object.freeze({
  id: 'VT-001',
  title: 'Define the versioned adapter contract',
  description: 'One shared interface for every agent. Define discovery, capabilities and typed errors.',
  status: 'BACKLOG',
  priority: 'High',
  agent: 'Unassigned',
  category: 'Architecture',
  criteria: ['Define all ten adapter methods', 'Document version negotiation', 'Enumerate typed errors'],
  revision: 1,
  createdAt: '2026-03-22T09:30:00.000Z',
});

describe('S2-007 the public demo fixture is not a live BoardTask', () => {
  test('the veritas_demo_tasks row shape is not a contract-valid BoardTask', () => {
    assert.equal(isBoardContractValid('board-task', { ...DEMO_ROW }), false);
    const thrown = refusalOf('board-task', { ...DEMO_ROW });
    assert.equal(thrown.code, 'MALFORMED_RESULT');
    const errors = boardContractErrors('board-task', { ...DEMO_ROW }).join('; ');
    for (const missing of ['contractVersion', 'task_id', 'workspace_id', 'goal', 'state', 'acl', 'brief_digest', 'workspace_ref', 'history_digest']) {
      assert.ok(errors.includes(missing), `the refusal did not name the missing BoardTask field ${missing}: ${errors}`);
    }
  });

  test('renaming the demo columns onto BoardTask names is still refused', () => {
    // The most generous migration anyone could attempt: every demo column is
    // renamed to the closest BoardTask property it could plausibly claim.
    const renamed = {
      contractVersion: '1.0.0',
      task_id: 'abt-vt001',
      workspace_id: 'ws-demo',
      title: DEMO_ROW.title,
      goal: DEMO_ROW.description,
      description: DEMO_ROW.description,
      acceptance_criteria: DEMO_ROW.criteria,
      state: DEMO_ROW.status,
      revision: DEMO_ROW.revision,
      priority: DEMO_ROW.priority,
      dependencies: [],
      required_capabilities: [],
      allowed_tools: [],
      agent: DEMO_ROW.agent,
      category: DEMO_ROW.category,
      criteria: DEMO_ROW.criteria,
      created_at: DEMO_ROW.createdAt,
      updated_at: DEMO_ROW.createdAt,
    };
    assert.equal(isBoardContractValid('board-task', renamed), false, 'a renamed demo row must not become a live task');
    const errors = boardContractErrors('board-task', renamed).join('; ');
    assert.ok(errors.includes('/priority'), `the capitalised demo priority was accepted: ${errors}`);
    // ajv reports a missing required property on the root instancePath with the
    // property name in quotes, so the property name is what is matched here.
    assert.ok(errors.includes("'workspace_ref'"), `the demo carries no workspace containment: ${errors}`);
    assert.ok(errors.includes("'cost_limits'"), `the demo carries no budget authorization: ${errors}`);
    assert.ok(errors.includes("'history_digest'"), `the demo carries no append-only history: ${errors}`);
    assert.ok(errors.includes("'acl'"), `the demo carries no access control: ${errors}`);
  });

  test('a demo task id is not a board task id', () => {
    assert.equal(isBoardContractValid('board-task', { ...minimalBoardTask(), task_id: DEMO_ROW.id }), false);
    assert.equal(isBoardContractValid('board-transition', { ...minimalBoardTransition(), task_id: DEMO_ROW.id }), false);
  });

  test('a demo transition is not a board transition', () => {
    // src/lib/board.ts boardEvents rows: { id, taskId, action, detail, revision,
    // operationId, requestHash, snapshot, createdAt }.
    const demoEvent = {
      id: 1,
      taskId: 'VT-001',
      action: 'Fixture created',
      detail: 'Synthetic planning fixture.',
      revision: 1,
      operationId: 'seed-VT-001',
      createdAt: '2026-03-22T09:30:00.000Z',
    };
    assert.equal(isBoardContractValid('board-transition', demoEvent), false);
    const thrown = refusalOf('board-transition', demoEvent);
    assert.equal(thrown.code, 'MALFORMED_RESULT');
  });
});
