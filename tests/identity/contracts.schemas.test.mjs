// S2-002 phase 1 — contract schemas.
// RED-first suite: every test must fail until the eight identity/sandbox
// contracts and the fail-closed registry exist. Offline, deterministic.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  CONTRACT_NAMES,
  CONTRACT_VERSION,
  validateContract,
  contractDigests,
} from '../../src/lib/identity/contract-registry.mjs';

const T0 = '2026-09-12T12:00:00.000Z';
const T1 = '2026-09-12T12:05:00.000Z';
const HEX64 = 'a'.repeat(64);
const HEX64B = 'b'.repeat(64);
const HEX64C = 'c'.repeat(64);
const SHA = (hex) => `sha256:${hex}`;

const workspace = () => ({
  contractVersion: '1.0.0',
  workspace_id: 'ws-board-core',
  owner: 'prn-owner-alice',
  scope: 'private',
  acl: [{ principal_id: 'prn-owner-alice', role_id: 'rol-workspace-owner' }],
  retention: { policy: 'retain_until_revocation' },
  allowed_roots: ['D:/workspaces/board-core'],
  network_profile: 'deny_all',
  revision: 3,
});

const principalPersonalAgent = () => ({
  contractVersion: '1.0.0',
  principal_id: 'prn-agent-alice',
  display_name: 'Alice Personal Agent',
  kind: 'personal_agent',
  tenant: { tenant_id: 'tn-alice', owner_principal_id: 'prn-owner-alice' },
  authenticated_subject: { subject_type: 'delegated_token', subject_ref: 'tok-alice-agent-001' },
  provider_adapter_identity: { provider: 'pi', adapter_id: 'pi-agent', adapter_version: '1.2.0' },
  lifecycle_state: 'active',
  delegated_by: 'prn-owner-alice',
});

const principalPlatformAgent = () => ({
  contractVersion: '1.0.0',
  principal_id: 'prn-platform-collector',
  display_name: 'Platform Collector',
  kind: 'platform_agent',
  tenant: { tenant_id: 'tn-platform', owner_principal_id: 'prn-platform-operator' },
  authenticated_subject: { subject_type: 'service_identity', subject_ref: 'svc-collector-001' },
  provider_adapter_identity: { provider: 'platform', adapter_id: 'collector' },
  lifecycle_state: 'active',
});

const role = () => ({
  contractVersion: '1.0.0',
  role_id: 'rol-board-reader',
  name: 'Board Reader',
  description: 'Read-only board access within one workspace',
  capabilities: ['cap-board.read', 'cap-task.read'],
});

const capability = () => ({
  contractVersion: '1.0.0',
  capability_id: 'cap-board.read',
  action: 'board.read',
  resource_type: 'board',
  canonical_arguments: [
    { name: 'workspace_id', required: true },
    { name: 'revision', required: false },
  ],
  constraints: {
    requires_lease: false,
    requires_approval: false,
    exec_tier: 'no_exec',
    network: 'none',
    side_effect: 'read',
  },
});

const grant = () => ({
  contractVersion: '1.0.0',
  grant_id: 'grt-alice-board-read-0001',
  issuer: 'prn-owner-alice',
  principal_id: 'prn-agent-alice',
  capability_id: 'cap-board.read',
  resource_scope: {
    workspace_id: 'ws-board-core',
    resource_type: 'board',
    resource_ids: ['board:primary'],
  },
  issued_at: T0,
  expires_at: T1,
  revoked_at: null,
  nonce: 'n-0f8a2b7c1d9e4f36',
  revision: 1,
  status: 'active',
  auth_ref: { scheme: 'offline_signature_v1', reference: SHA(HEX64) },
});

const lease = () => ({
  contractVersion: '1.0.0',
  lease_id: 'lse-run-0001',
  workspace_id: 'ws-board-core',
  owner: 'prn-agent-alice',
  grant_id: 'grt-alice-board-read-0001',
  task_ref: { task_id: 'tsk-0001', run_id: 'run-0001' },
  fencing_token: 7,
  issued_at: T0,
  expires_at: T1,
  state: 'active',
});

const sandboxNoExec = () => ({
  contractVersion: '1.0.0',
  profile_id: 'sbx-no-exec-default',
  tier: 'NO_EXEC',
  filesystem: {
    roots: ['D:/workspaces/board-core'],
    deny_link_escape: true,
    deny_traversal: true,
  },
  network: { policy: 'deny_all', allowlist: [] },
  environment: { allowlist: ['NODE_ENV'], secret_handles: [] },
  process: { max_processes: 1, memory_mb: 512, timeout_ms: 30000 },
  cancellation: { mode: 'process_tree', on_timeout: 'fail_closed' },
});

const sandboxLocalRestricted = () => ({
  ...sandboxNoExec(),
  profile_id: 'sbx-local-restricted-default',
  tier: 'LOCAL_RESTRICTED',
  process: { max_processes: 8, memory_mb: 1024, timeout_ms: 60000 },
  os_controls_evidence: SHA(HEX64B),
});

const decision = () => ({
  contractVersion: '1.0.0',
  decision: 'ALLOW',
  reason_codes: ['GRANT_VALID', 'LEASE_FRESH'],
  policy_version: 's2-002-policy-v1',
  input_digest: SHA(HEX64C),
  audit_ref: 'aud:decision-0001-abcd1234',
  principal_id: 'prn-agent-alice',
  capability_id: 'cap-board.read',
  workspace_id: 'ws-board-core',
  decided_at: T1,
  context: {
    grant_id: 'grt-alice-board-read-0001',
    lease_id: 'lse-run-0001',
    fencing_token: 7,
  },
});

const FIXTURES = Object.freeze({
  workspace,
  principal: principalPersonalAgent,
  role,
  capability,
  grant,
  lease,
  'sandbox-profile': sandboxNoExec,
  'authorization-decision': decision,
});

describe('S2-002 contract registry (fail-closed surface)', () => {
  test('exposes exactly the eight required contracts at version 1.0.0', () => {
    assert.deepEqual(
      [...CONTRACT_NAMES].sort(),
      [
        'authorization-decision',
        'capability',
        'grant',
        'lease',
        'principal',
        'role',
        'sandbox-profile',
        'workspace',
      ],
    );
    assert.equal(CONTRACT_VERSION, '1.0.0');
  });

  test('every canonical fixture validates', () => {
    for (const name of CONTRACT_NAMES) {
      const result = validateContract(name, FIXTURES[name]());
      assert.equal(result.valid, true, `${name} fixture must validate: ${JSON.stringify(result.errors)}`);
    }
  });

  test('schema digests are stable sha256 records', () => {
    const digests = contractDigests();
    assert.deepEqual(Object.keys(digests).sort(), [...CONTRACT_NAMES].sort());
    for (const name of CONTRACT_NAMES) {
      assert.match(digests[name], /^[0-9a-f]{64}$/, `${name} digest must be sha256 hex`);
    }
  });

  test('unknown contract name throws instead of failing open', () => {
    assert.throws(() => validateContract('nonexistent', {}));
    assert.throws(() => validateContract('', {}));
    assert.throws(() => validateContract('Workspace', {}), undefined, 'names are case-sensitive');
  });

  test('non-object inputs never validate for any contract', () => {
    for (const name of CONTRACT_NAMES) {
      for (const bad of [null, undefined, 42, 'x', [], true]) {
        const result = validateContract(name, bad);
        assert.equal(result.valid, false, `${name} must reject ${String(bad)}`);
      }
    }
  });

  test('empty objects are rejected: required fields are mandatory', () => {
    for (const name of CONTRACT_NAMES) {
      const result = validateContract(name, {});
      assert.equal(result.valid, false, `${name} must reject {}`);
    }
  });

  test('unknown contractVersion is rejected (fail-closed versioning)', () => {
    for (const name of CONTRACT_NAMES) {
      const doc = { ...FIXTURES[name](), contractVersion: '9.9.9' };
      const result = validateContract(name, doc);
      assert.equal(result.valid, false, `${name} must reject unknown version 9.9.9`);
    }
  });

  test('injected unknown fields are rejected in every contract', () => {
    for (const name of CONTRACT_NAMES) {
      const doc = { ...FIXTURES[name](), __injected_authority: 'escalate' };
      const result = validateContract(name, doc);
      assert.equal(result.valid, false, `${name} must reject unknown field injection`);
    }
  });

  test('injected unknown fields inside nested objects are rejected', () => {
    const ws = workspace();
    ws.acl[0].impersonate = 'prn-owner-bob';
    assert.equal(validateContract('workspace', ws).valid, false);

    const dec = decision();
    dec.context.elevated = true;
    assert.equal(validateContract('authorization-decision', dec).valid, false);

    const sbx = sandboxLocalRestricted();
    sbx.network.allowlist.push({ host: 'evil.example', ports: [443] });
    // LOCAL_RESTRICTED fixture keeps policy deny_all, so allowlist entries are illegal.
    assert.equal(validateContract('sandbox-profile', sbx).valid, false);
  });
});

describe('S2-002 workspace contract semantics', () => {
  test('scope is limited to private|project|shared', () => {
    for (const scope of ['private', 'project', 'shared']) {
      assert.equal(validateContract('workspace', { ...workspace(), scope }).valid, true);
    }
    for (const scope of ['public', 'tenant', '*', 'PRIVATE']) {
      assert.equal(validateContract('workspace', { ...workspace(), scope }).valid, false);
    }
  });

  test('delete_after retention requires delete_after_days', () => {
    const doc = workspace();
    doc.retention = { policy: 'delete_after' };
    assert.equal(validateContract('workspace', doc).valid, false);
    doc.retention = { policy: 'delete_after', delete_after_days: 30 };
    assert.equal(validateContract('workspace', doc).valid, true);
  });

  test('workspace_id must match the canonical namespace', () => {
    for (const bad of ['ws-', 'board-core', 'WS-X', 'ws/../escape']) {
      assert.equal(validateContract('workspace', { ...workspace(), workspace_id: bad }).valid, false, bad);
    }
  });

  test('revision must be a positive integer (optimistic concurrency)', () => {
    for (const bad of [0, -1, 1.5, '3', null]) {
      assert.equal(validateContract('workspace', { ...workspace(), revision: bad }).valid, false);
    }
  });
});

describe('S2-002 principal contract semantics', () => {
  test('personal agents require explicit delegation by another principal', () => {
    const doc = principalPersonalAgent();
    delete doc.delegated_by;
    assert.equal(validateContract('principal', doc).valid, false);

    doc.delegated_by = 'prn-agent-alice'; // self-delegation
    assert.equal(validateContract('principal', doc).valid, false);
  });

  test('lifecycle state is a closed set', () => {
    for (const state of ['active', 'suspended', 'revoked', 'retired']) {
      assert.equal(validateContract('principal', { ...principalPersonalAgent(), lifecycle_state: state }).valid, true);
    }
    assert.equal(validateContract('principal', { ...principalPlatformAgent(), lifecycle_state: 'enabled' }).valid, false);
  });

  test('platform agents do not carry personal delegation fields', () => {
    const doc = principalPlatformAgent();
    doc.delegated_by = 'prn-owner-alice';
    assert.equal(validateContract('principal', doc).valid, false, 'platform agents must not inherit owner delegation');
  });
});

describe('S2-002 role/capability/grant semantics (no wildcards)', () => {
  test('roles reject wildcard capability references', () => {
    for (const bad of ['*', 'cap-*', 'cap-..*', 'all']) {
      const doc = role();
      doc.capabilities = ['cap-board.read', bad];
      assert.equal(validateContract('role', doc).valid, false, `role must reject ${bad}`);
    }
  });

  test('roles require at least one concrete capability', () => {
    const doc = role();
    doc.capabilities = [];
    assert.equal(validateContract('role', doc).valid, false);
  });

  test('capability actions are exact dotted operations, not patterns', () => {
    assert.equal(validateContract('capability', capability()).valid, true);
    for (const bad of ['board.*', '*', 'BOARD.READ', 'board.read;drop', 'read board']) {
      assert.equal(validateContract('capability', { ...capability(), action: bad }).valid, false, bad);
    }
  });

  test('grants reject wildcard resource ids', () => {
    for (const bad of ['*', 'board:*', 'all']) {
      const doc = grant();
      doc.resource_scope.resource_ids = [bad];
      assert.equal(validateContract('grant', doc).valid, false, `grant must reject resource id ${bad}`);
    }
  });

  test('grants pin issuer, principal and capability as canonical ids', () => {
    const doc = grant();
    doc.issuer = doc.principal_id; // producer approving own authority
    assert.equal(validateContract('grant', doc).valid, false, 'grant issuer must differ from grantee');
  });

  test('grant timestamps are strict ISO-8601 UTC', () => {
    const doc = grant();
    doc.issued_at = '2026-09-12 12:00:00';
    assert.equal(validateContract('grant', doc).valid, false);
    doc.issued_at = T0;
    doc.expires_at = '2026-13-99T99:99:99.999Z';
    assert.equal(validateContract('grant', doc).valid, false);
  });

  test('grant auth reference is a digest or attestation, never free text', () => {
    const doc = grant();
    doc.auth_ref = { scheme: 'offline_signature_v1', reference: 'trust me, I am authenticated' };
    assert.equal(validateContract('grant', doc).valid, false);
    doc.auth_ref = { scheme: 'platform_attestation_v1', reference: `att:${'X'.repeat(16)}` };
    assert.equal(validateContract('grant', doc).valid, true);
  });

  test('revoked grants may record revocation time', () => {
    const doc = grant();
    doc.status = 'revoked';
    doc.revoked_at = T1;
    assert.equal(validateContract('grant', doc).valid, true);
  });
});

describe('S2-002 lease semantics (fencing)', () => {
  test('fencing token must be a positive integer', () => {
    for (const bad of [0, -7, 1.5, '7']) {
      assert.equal(validateContract('lease', { ...lease(), fencing_token: bad }).valid, false);
    }
  });

  test('lease state is a closed set', () => {
    for (const state of ['active', 'expired', 'revoked']) {
      assert.equal(validateContract('lease', { ...lease(), state }).valid, true);
    }
    assert.equal(validateContract('lease', { ...lease(), state: 'done' }).valid, false);
  });
});

describe('S2-002 sandbox profile semantics', () => {
  test('tiers are exactly NO_EXEC | LOCAL_RESTRICTED | UNTRUSTED_CODE', () => {
    for (const tier of ['NO_EXEC', 'LOCAL_RESTRICTED', 'UNTRUSTED_CODE']) {
      const doc = sandboxNoExec();
      doc.tier = tier;
      if (tier !== 'NO_EXEC') doc.os_controls_evidence = SHA(HEX64B);
      assert.equal(validateContract('sandbox-profile', doc).valid, true, tier);
    }
    assert.equal(validateContract('sandbox-profile', { ...sandboxNoExec(), tier: 'FULL' }).valid, false);
  });

  test('restricted tiers require OS control evidence', () => {
    for (const tier of ['LOCAL_RESTRICTED', 'UNTRUSTED_CODE']) {
      const doc = sandboxNoExec();
      doc.tier = tier;
      doc.profile_id = `sbx-${tier.toLowerCase()}-default`;
      assert.equal(validateContract('sandbox-profile', doc).valid, false, `${tier} without evidence must not validate`);
    }
  });

  test('link escape and traversal protections are mandatory constants', () => {
    const doc = sandboxNoExec();
    doc.filesystem.deny_link_escape = false;
    assert.equal(validateContract('sandbox-profile', doc).valid, false);
    const doc2 = sandboxNoExec();
    delete doc2.filesystem.deny_traversal;
    assert.equal(validateContract('sandbox-profile', doc2).valid, false);
  });

  test('deny_all network forbids allowlist entries', () => {
    const doc = sandboxLocalRestricted();
    doc.network.allowlist = [{ host: 'registry.npmjs.org', ports: [443] }];
    assert.equal(validateContract('sandbox-profile', doc).valid, false);
    doc.network.policy = 'allowlist';
    assert.equal(validateContract('sandbox-profile', doc).valid, true);
    doc.network.allowlist = [];
    assert.equal(validateContract('sandbox-profile', doc).valid, false, 'allowlist policy with empty allowlist is a lie');
  });

  test('environment allowlist admits only env-var-shaped names; secrets are opaque handles', () => {
    const doc = sandboxLocalRestricted();
    doc.environment.allowlist = ['NODE_ENV', 'BAD lower', 'PATH='];
    assert.equal(validateContract('sandbox-profile', doc).valid, false);
    doc.environment.allowlist = ['NODE_ENV', 'TEMP'];
    doc.environment.secret_handles = ['sec-postgres-url', 'totally not a secret value'];
    assert.equal(validateContract('sandbox-profile', doc).valid, false);
    doc.environment.secret_handles = ['sec-postgres-url'];
    assert.equal(validateContract('sandbox-profile', doc).valid, true);
  });

  test('cancellation must cover the whole process tree or fail closed', () => {
    const doc = sandboxLocalRestricted();
    doc.cancellation = { mode: 'single_process', on_timeout: 'kill_tree' };
    assert.equal(validateContract('sandbox-profile', doc).valid, false, 'kill_tree is meaningless for a single process');
  });

  test('process limits are positive numbers', () => {
    const doc = sandboxLocalRestricted();
    doc.process.timeout_ms = 0;
    assert.equal(validateContract('sandbox-profile', doc).valid, false);
    doc.process.timeout_ms = 60000;
    doc.process.memory_mb = -1;
    assert.equal(validateContract('sandbox-profile', doc).valid, false);
  });
});

describe('S2-002 authorization decision semantics', () => {
  test('decision is exactly the four-verdict closed set', () => {
    for (const d of ['ALLOW', 'DENY', 'BLOCKED_SANDBOX', 'NEEDS_APPROVAL']) {
      assert.equal(validateContract('authorization-decision', { ...decision(), decision: d }).valid, true, d);
    }
    for (const d of ['allow', 'PASS', 'BLOCKED', '']) {
      assert.equal(validateContract('authorization-decision', { ...decision(), decision: d }).valid, false, d);
    }
  });

  test('at least one UPPER_SNAKE reason code is required', () => {
    const doc = decision();
    doc.reason_codes = [];
    assert.equal(validateContract('authorization-decision', doc).valid, false);
    doc.reason_codes = ['bad reason'];
    assert.equal(validateContract('authorization-decision', doc).valid, false);
  });

  test('input digest and audit reference are mandatory and canonical', () => {
    const doc = decision();
    doc.input_digest = 'sha1:deadbeef';
    assert.equal(validateContract('authorization-decision', doc).valid, false);
    doc.input_digest = SHA(HEX64C);
    doc.audit_ref = '';
    assert.equal(validateContract('authorization-decision', doc).valid, false);
  });
});
