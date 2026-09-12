// S2-002 phase 2 — subjects model and server-side policy engine.
// RED-first suite: the authority registry (20 principals, workspaces, roles,
// capabilities, grants, leases) and the deterministic fail-closed policy
// engine do not exist yet. Offline, no paid calls, fixed clock.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { validateContract, assertValidContract } from '../../src/lib/identity/contract-registry.mjs';
import {
  PRINCIPALS,
  WORKSPACES,
  ROLES,
  CAPABILITIES,
  GRANTS,
  LEASES,
  SANDBOX_PROFILES,
} from '../../src/lib/identity/principals.mjs';
import { createPolicyEngine, POLICY_VERSION } from '../../src/lib/identity/policy-engine.mjs';

const NOW = '2026-09-12T12:00:00.000Z';

const ADAPTERS = ['web', 'api', 'cli'];

// Canonical argument builders per action (mirror of the capability
// contracts). Fixture-side only: the engine validates independently.
const CANONICAL = {
  'board.read': (r) => ({ workspace_id: r.workspaceId }),
  'task.create': () => ({ title: 'Synthetic task' }),
  'task.update': (r) => ({ task_id: r.resource.id, expected_revision: 3 }),
  'approval.decide': (r) => ({ approval_id: r.resource.id, verdict: 'APPROVED' }),
  'message.send': () => ({ to_principal: 'prn-agent-alice', body_digest: `sha256:${'5'.repeat(64)}` }),
  'source.read': (r) => ({ source_id: r.resource.id }),
  'search.query': () => ({ query: 'veritas' }),
  'cache.read': (r) => ({ cache_id: r.resource.id }),
  'summary.generate': (r) => ({ summary_id: r.resource.id, inputs: [{ workspaceId: r.workspaceId, resourceId: 'claim:c1' }] }),
  'claim.write': (r) => ({ claim_id: r.resource.id, provenance: 'synthetic' }),
  'tool.execute': (r) => ({ tool_id: r.resource.id, canonical_args: {} }),
  'tool.discover': (r) => ({ workspace_id: r.workspaceId }),
  'artifact.export': (r) => ({ artifact_id: r.resource.id, destination: 'export:local' }),
  'artifact.read': (r) => ({ artifact_id: r.resource.id }),
  'task.cancel': (r) => ({ task_id: r.resource.id }),
};

describe('S2-002 authority registry (subjects model)', () => {
  test('exposes exactly 20 deterministic principals', () => {
    assert.equal(PRINCIPALS.length, 20);
    const ids = PRINCIPALS.map((p) => p.principal_id);
    assert.equal(new Set(ids).size, 20, 'principal ids must be unique');
  });

  test('principal kinds cover humans, personal agents, externals and platform agents', () => {
    const byKind = Object.groupBy(PRINCIPALS, (p) => p.kind);
    assert.equal(byKind.human.length, 5);
    assert.equal(byKind.personal_agent.length, 5);
    assert.equal(byKind.external_agent.length, 4);
    assert.equal(byKind.platform_agent.length, 6);
    for (const external of byKind.external_agent) {
      assert.ok(['codex', 'pi', 'opencode', 'hermes'].includes(external.provider_adapter_identity.provider));
    }
  });

  test('at least four workspaces exist with explicit scopes', () => {
    assert.ok(WORKSPACES.length >= 4);
    for (const ws of WORKSPACES) {
      assert.ok(['private', 'project', 'shared'].includes(ws.scope));
    }
    assert.equal(WORKSPACES.filter((ws) => ws.scope === 'private').length, 5);
  });

  test('every registry record validates against its S2-002 contract', () => {
    for (const p of PRINCIPALS) assertValidContract('principal', p);
    for (const ws of WORKSPACES) assertValidContract('workspace', ws);
    for (const r of ROLES) assertValidContract('role', r);
    for (const c of CAPABILITIES) assertValidContract('capability', c);
    for (const g of GRANTS) assertValidContract('grant', g);
    for (const l of LEASES) assertValidContract('lease', l);
    for (const s of SANDBOX_PROFILES) assertValidContract('sandbox-profile', s);
  });

  test('personal agents act only via explicit owner delegation; platform agents never delegate', () => {
    for (const p of PRINCIPALS) {
      if (p.kind === 'personal_agent') {
        assert.ok(p.delegated_by, `${p.principal_id} must be delegated`);
        const issuer = PRINCIPALS.find((x) => x.principal_id === p.delegated_by);
        assert.ok(issuer, `${p.principal_id} delegation target must exist`);
        assert.equal(issuer.kind, 'human', 'delegation must come from a human owner');
      }
      if (p.kind === 'platform_agent') {
        assert.equal(p.delegated_by, undefined, `${p.principal_id} must not carry personal delegation`);
      }
    }
  });

  test('every grant is issued by a human and never self-issued', () => {
    for (const g of GRANTS) {
      const issuer = PRINCIPALS.find((p) => p.principal_id === g.issuer);
      assert.ok(issuer, `grant ${g.grant_id} issuer must exist`);
      assert.equal(issuer.kind, 'human', `grant ${g.grant_id} issuer must be human`);
      assert.notEqual(g.issuer, g.principal_id);
    }
  });
});

function makeEngine() {
  return createPolicyEngine({ now: NOW });
}

function req(overrides = {}) {
  const request = {
    adapter: 'api',
    principalId: 'prn-owner-alice',
    action: 'board.read',
    workspaceId: 'ws-alice-private',
    resource: { type: 'board', id: 'board:primary' },
    args: {},
    ...overrides,
  };
  const canonical = CANONICAL[request.action]?.(request) ?? {};
  request.args = { ...canonical, ...(request.args ?? {}) };
  return request;
}
describe('S2-002 policy engine: canonical arguments and resource type', () => {
  test('missing required canonical arguments are denied', () => {
    const engine = makeEngine();
    const result = engine.authorize({ ...req(), args: {} }); // board.read needs workspace_id
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('CANONICAL_ARGUMENTS_MISSING'));
  });

  test('arguments outside the canonical set are denied', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      args: { workspace_id: 'ws-alice-private', escalate: 'true' },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('ARGUMENT_NOT_CANONICAL'));
  });

  test('resource type must match the capability contract', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      resource: { type: 'secret', id: 'board:primary' },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('RESOURCE_TYPE_MISMATCH'));
  });

  test('artifact.export without canonical arguments is denied even with a grant', () => {
    const engine = makeEngine();
    // Raw request (bypassing the fixture helper) with empty args.
    const result = engine.authorize({
      adapter: 'api',
      principalId: 'prn-agent-carol',
      workspaceId: 'ws-carol-private',
      action: 'artifact.export',
      resource: { type: 'artifact', id: 'artifact:final-1' },
      args: {},
    });
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('CANONICAL_ARGUMENTS_MISSING'));
  });

  test('resource-bearing canonical arguments must name the authorized resource', () => {
    const engine = makeEngine();
    const result = engine.authorize({
      adapter: 'api',
      principalId: 'prn-agent-carol',
      workspaceId: 'ws-carol-private',
      action: 'artifact.export',
      resource: { type: 'artifact', id: 'artifact:final-1' },
      args: { artifact_id: 'artifact:outside-scope', destination: 'export:local' },
    });
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('CANONICAL_ARGUMENT_VALUE_MISMATCH'));
  });

  test('workspace_id canonical argument must match the authorized workspace', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      args: { workspace_id: 'ws-bob-private' },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('CANONICAL_ARGUMENT_VALUE_MISMATCH'));
  });

  test('required canonical arguments reject undefined and invalid scalar types', () => {
    const engine = makeEngine();
    const missingValue = engine.authorize(req({
      action: 'task.create',
      resource: { type: 'task', id: 'task:new' },
      args: { title: undefined },
    }));
    assert.equal(missingValue.decision, 'DENY');
    assert.ok(missingValue.reasonCodes.includes('CANONICAL_ARGUMENTS_MISSING'));

    const wrongType = engine.authorize(req({
      action: 'task.update',
      resource: { type: 'task', id: 'task:1' },
      args: { task_id: 'task:1', expected_revision: 'three' },
    }));
    assert.equal(wrongType.decision, 'DENY');
    assert.ok(wrongType.reasonCodes.includes('CANONICAL_ARGUMENT_INVALID'));

    const structuredTitle = engine.authorize(req({
      action: 'task.create',
      resource: { type: 'task', id: 'task:new' },
      args: { title: { injected: 'not text' } },
    }));
    assert.equal(structuredTitle.decision, 'DENY');
    assert.ok(structuredTitle.reasonCodes.includes('CANONICAL_ARGUMENT_INVALID'));

    const invalidVerdict = engine.authorize(req({
      action: 'approval.decide',
      resource: { type: 'approval', id: 'approval:bad' },
      args: { approval_id: 'approval:bad', verdict: 'OWNER_OVERRIDE' },
    }));
    assert.equal(invalidVerdict.decision, 'DENY');
    assert.ok(invalidVerdict.reasonCodes.includes('CANONICAL_ARGUMENT_INVALID'));
  });
});

describe('S2-002 policy engine: exact lease binding', () => {
  test('a lease bound to one capability cannot authorize another', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-platform-curator',
      workspaceId: 'ws-veritas-project',
      action: 'claim.write',
      resource: { type: 'claim', id: 'claim:c1' },
      lease: { leaseId: 'lse-curator-0004', fencingToken: 2 }, // bound to summary.generate
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('LEASE_CAPABILITY_MISMATCH'));
  });

  test('a lease bound to a foreign grant cannot ride on unrelated access', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-1' },
      lease: { leaseId: 'lse-curator-0004', fencingToken: 2 }, // curator lease
    }));
    assert.equal(result.decision, 'DENY');
    // The lease belongs to another principal entirely; ownership is checked
    // before the grant binding chain.
    assert.ok(result.reasonCodes.includes('LEASE_OWNER_MISMATCH'), result.reasonCodes.join(','));
  });

  test('a same-capability lease linked to a different grant is rejected', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-1' },
      lease: { leaseId: 'lse-pi-project-0007', fencingToken: 3 }, // linked to grant 0016, access came via grant 0004
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('LEASE_GRANT_MISMATCH'), result.reasonCodes.join(','));
  });

  test('a presented lease for a capability that needs none is denied', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      lease: { leaseId: 'lse-pi-project-0001', fencingToken: 5 },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('LEASE_NOT_REQUIRED'));
  });

  test('the correctly bound lease still authorizes its own capability', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-1' },
      lease: { leaseId: 'lse-pi-project-0001', fencingToken: 5 },
    }));
    assert.equal(result.decision, 'ALLOW', result.reasonCodes.join(','));
  });

  test('a caller cannot forge a higher fencing token for an existing lease', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-1' },
      args: { task_id: 'task:tsk-pilot-1', expected_revision: 3 },
      lease: { leaseId: 'lse-pi-project-0001', fencingToken: 999999 },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('LEASE_FENCING_TOKEN_MISMATCH'));
  });

  test('a task lease cannot authorize a different task covered by the same grant', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-2' },
      args: { task_id: 'task:tsk-pilot-2', expected_revision: 3 },
      lease: { leaseId: 'lse-pi-project-0001', fencingToken: 5 },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('LEASE_TASK_MISMATCH'));
  });
});

describe('S2-002 policy engine: message recipient scoping', () => {
  test('message to a recipient without workspace access is denied', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      action: 'message.send',
      resource: { type: 'message', id: 'message:m1' },
      args: { to_principal: 'prn-owner-bob', body_digest: `sha256:${'5'.repeat(64)}` },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('RECIPIENT_OUT_OF_SCOPE'));
  });

  test('message to a recipient with a grant in the workspace is allowed', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      action: 'message.send',
      resource: { type: 'message', id: 'message:m2' },
      args: { to_principal: 'prn-agent-alice', body_digest: `sha256:${'5'.repeat(64)}` },
    }));
    assert.equal(result.decision, 'ALLOW', result.reasonCodes.join(','));
  });

  test('unknown recipients are denied', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      action: 'message.send',
      resource: { type: 'message', id: 'message:m3' },
      args: { to_principal: 'prn-ghost', body_digest: `sha256:${'5'.repeat(64)}` },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('UNKNOWN_RECIPIENT'));
  });
});

describe('S2-002 policy engine: default deny', () => {
  test('unknown principal, action or workspace is denied, never error-implicit-allow', () => {
    const engine = makeEngine();
    for (const request of [
      req({ principalId: 'prn-ghost' }),
      req({ action: 'board.destroy' }),
      req({ workspaceId: 'ws-unknown' }),
    ]) {
      const result = engine.authorize(request);
      assert.equal(result.decision, 'DENY');
    }
  });

  test('suspended or revoked principals are denied everywhere', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-platform-operator',
      workspaceId: 'ws-veritas-project',
    }));
    assert.equal(result.decision, 'ALLOW');
    const frozen = engine.freezePrincipal('prn-platform-operator');
    assert.equal(frozen, true);
    const after = engine.authorize(req({
      principalId: 'prn-platform-operator',
      workspaceId: 'ws-veritas-project',
    }));
    assert.equal(after.decision, 'DENY');
    assert.ok(after.reasonCodes.includes('PRINCIPAL_NOT_ACTIVE'));
  });

  test('write capability without ACL or grant is denied', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.create',
      resource: { type: 'task', id: 'task:new-unauthorized' },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('NO_ACCESS'));
  });
});

describe('S2-002 policy engine: ownership and delegation', () => {
  test('human owner has full access inside the owned private workspace', () => {
    const engine = makeEngine();
    const cases = [
      { action: 'board.read', resource: { type: 'board', id: 'board:primary' } },
      { action: 'task.create', resource: { type: 'task', id: 'task:1' } },
      { action: 'task.update', resource: { type: 'task', id: 'task:1' } },
      { action: 'approval.decide', resource: { type: 'approval', id: 'approval:1', producerPrincipalId: 'prn-agent-alice' } },
    ];
    for (const { action, resource } of cases) {
      const result = engine.authorize(req({ action, resource }));
      assert.equal(result.decision, 'ALLOW', `${action} for owner: ${result.reasonCodes}`);
    }
  });

  test('the same owner is denied in another tenant private workspace', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-owner-bob',
      workspaceId: 'ws-alice-private',
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('NO_ACCESS'));
  });

  test('personal agent with explicit grants operates in the granted scope only', () => {
    const engine = makeEngine();
    assert.equal(
      engine.authorize(req({ principalId: 'prn-agent-alice' })).decision,
      'ALLOW',
      'grant 1 covers board.read in alice private',
    );
    assert.equal(
      engine.authorize(req({ principalId: 'prn-agent-alice', workspaceId: 'ws-veritas-project' })).decision,
      'ALLOW',
      'grant 3 covers board.read in the project workspace',
    );
    assert.equal(
      engine.authorize(req({ principalId: 'prn-agent-alice', workspaceId: 'ws-bob-private' })).decision,
      'DENY',
      'no delegation reaches bob private workspace',
    );
    assert.equal(
      engine.authorize(req({
        principalId: 'prn-agent-alice',
        action: 'task.create',
        resource: { type: 'task', id: 'task:new' },
      })).decision,
      'DENY',
      'ungranted capability is denied even in the own workspace',
    );
  });

  test('a personal agent without any delegation is denied even in the owner workspace', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-agent-eve',
      workspaceId: 'ws-eve-private',
    }));
    assert.equal(result.decision, 'DENY');
  });
});

describe('S2-002 policy engine: external service principals', () => {
  test('pi may update tasks in the project workspace via grant plus lease', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-1' },
      lease: { leaseId: 'lse-pi-project-0001', fencingToken: 5 },
    }));
    assert.equal(result.decision, 'ALLOW', result.reasonCodes?.join(','));
  });

  test('codex may create tasks in the project workspace via grant', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-codex',
      workspaceId: 'ws-veritas-project',
      action: 'task.create',
      resource: { type: 'task', id: 'task:new-codex' },
    }));
    assert.equal(result.decision, 'ALLOW', result.reasonCodes?.join(','));
  });

  test('expired grants deny; never-granted opencode is denied everywhere', () => {
    const engine = makeEngine();
    const expired = engine.authorize(req({
      principalId: 'prn-external-hermes',
      workspaceId: 'ws-veritas-project',
      action: 'search.query',
      resource: { type: 'source', id: 'source:docs' },
    }));
    assert.equal(expired.decision, 'DENY');
    assert.ok(expired.reasonCodes.includes('GRANT_EXPIRED'));

    for (const ws of WORKSPACES.map((w) => w.workspace_id)) {
      assert.equal(
        engine.authorize(req({ principalId: 'prn-external-opencode', workspaceId: ws })).decision,
        'DENY',
        `opencode must not read ${ws}`,
      );
    }
  });

  test('externals cannot reach private workspaces even with valid project grants', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-bob-private',
      action: 'task.update',
      resource: { type: 'task', id: 'task:1' },
      lease: { leaseId: 'lse-pi-project-0001', fencingToken: 5 },
    }));
    assert.equal(result.decision, 'DENY');
  });
});

describe('S2-002 policy engine: platform agents', () => {
  test('platform roles apply inside assigned workspaces only', () => {
    const engine = makeEngine();
    assert.equal(
      engine.authorize(req({
        principalId: 'prn-platform-collector',
        workspaceId: 'ws-shared-library',
        action: 'source.read',
        resource: { type: 'source', id: 'source:library-1' },
      })).decision,
      'ALLOW',
    );
    assert.equal(
      engine.authorize(req({
        principalId: 'prn-platform-collector',
        workspaceId: 'ws-alice-private',
        action: 'source.read',
        resource: { type: 'source', id: 'source:private-1' },
      })).decision,
      'DENY',
      'collector must not read alice private sources',
    );
  });

  test('platform agents cannot approve and cannot self-approve their own output', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-platform-verifier',
      workspaceId: 'ws-veritas-project',
      action: 'approval.decide',
      resource: { type: 'approval', id: 'approval:1', producerPrincipalId: 'prn-platform-verifier' },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('APPROVAL_NOT_HUMAN'));
  });
});

describe('S2-002 policy engine: approvals (producer cannot approve own result)', () => {
  test('human owner approves an artifact produced by their agent', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      action: 'approval.decide',
      resource: { type: 'approval', id: 'approval:2', producerPrincipalId: 'prn-agent-alice' },
    }));
    assert.equal(result.decision, 'ALLOW');
  });

  test('producer self-approval is denied for humans too', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      action: 'approval.decide',
      resource: { type: 'approval', id: 'approval:3', producerPrincipalId: 'prn-owner-alice' },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('SELF_APPROVAL'));
  });

  test('approvals outside the approver role are denied for other humans', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-owner-carol',
      workspaceId: 'ws-veritas-project',
      action: 'approval.decide',
      resource: { type: 'approval', id: 'approval:4', producerPrincipalId: 'prn-agent-alice' },
    }));
    assert.equal(result.decision, 'DENY');
  });
});

describe('S2-002 policy engine: leases and fencing tokens', () => {
  test('stale fencing token is denied after a fresh token advanced the fence', () => {
    const engine = makeEngine();
    const fresh = req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-1' },
      lease: { leaseId: 'lse-pi-project-0001', fencingToken: 5 },
    });
    assert.equal(engine.authorize(fresh).decision, 'ALLOW');
    const stale = engine.authorize({ ...fresh, lease: { leaseId: 'lse-pi-project-0001', fencingToken: 4 } });
    assert.equal(stale.decision, 'DENY');
    assert.ok(stale.reasonCodes.includes('LEASE_FENCING_TOKEN_MISMATCH'));
  });

  test('expired or revoked leases are denied', () => {
    const engine = makeEngine();
    const expired = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-2' },
      lease: { leaseId: 'lse-pi-project-0002-expired', fencingToken: 3 },
    }));
    assert.equal(expired.decision, 'DENY');
    assert.ok(expired.reasonCodes.includes('LEASE_EXPIRED'));

    engine.revokeLease('lse-pi-project-0001');
    const revoked = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-1' },
      lease: { leaseId: 'lse-pi-project-0001', fencingToken: 5 },
    }));
    assert.equal(revoked.decision, 'DENY');
    assert.ok(revoked.reasonCodes.includes('LEASE_REVOKED'));
  });

  test('lease use without a lease where one is required is denied', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-1' },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('LEASE_REQUIRED'));
  });
});

describe('S2-002 policy engine: grant revocation and one-time nonce', () => {
  test('revocation forbids further use immediately', () => {
    const engine = makeEngine();
    const read = () => req({ principalId: 'prn-agent-bob', workspaceId: 'ws-bob-private', action: 'source.read', resource: { type: 'source', id: 'source:bob-notes-1' } });
    const before = engine.authorize(read());
    assert.equal(before.decision, 'ALLOW', before.reasonCodes?.join(','));
    engine.revokeGrant('grt-bob-agent-research-0005');
    const after = engine.authorize(read());
    assert.equal(after.decision, 'DENY');
    assert.ok(after.reasonCodes.includes('GRANT_REVOKED'));
  });

  test('one-time nonce grant consumes atomically: replay is denied', () => {
    const engine = makeEngine();
    const exportReq = () => req({
      principalId: 'prn-agent-carol',
      workspaceId: 'ws-carol-private',
      action: 'artifact.export',
      resource: { type: 'artifact', id: 'artifact:final-1' },
    });
    const first = engine.authorize(exportReq());
    assert.equal(first.decision, 'ALLOW', first.reasonCodes?.join(','));
    const replay = engine.authorize(exportReq());
    assert.equal(replay.decision, 'DENY');
    assert.ok(replay.reasonCodes.includes('GRANT_NONCE_CONSUMED'));
  });
});

describe('S2-002 policy engine: derived artifact ACL inheritance', () => {
  test('summary generation from same-workspace inputs is allowed for the curator', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-platform-curator',
      workspaceId: 'ws-veritas-project',
      action: 'summary.generate',
      resource: { type: 'summary', id: 'summary:board-weekly' },
      lease: { leaseId: 'lse-curator-0004', fencingToken: 2 },
      args: { inputs: [{ workspaceId: 'ws-veritas-project', resourceId: 'claim:c1' }] },
    }));
    assert.equal(result.decision, 'ALLOW', result.reasonCodes?.join(','));
  });

  test('a cross-tenant input poisons the derived artifact: denied', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-platform-curator',
      workspaceId: 'ws-veritas-project',
      action: 'summary.generate',
      resource: { type: 'summary', id: 'summary:poisoned' },
      lease: { leaseId: 'lse-curator-0004', fencingToken: 2 },
      args: {
        inputs: [
          { workspaceId: 'ws-veritas-project', resourceId: 'claim:c1' },
          { workspaceId: 'ws-bob-private', resourceId: 'claim:secret' },
        ],
      },
    }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('CROSS_TENANT_INPUT'));
  });

  test('cache reads respect workspace boundaries', () => {
    const engine = makeEngine();
    assert.equal(
      engine.authorize(req({
        principalId: 'prn-owner-alice',
        workspaceId: 'ws-veritas-project',
        action: 'cache.read',
        resource: { type: 'cache', id: 'cache:index' },
      })).decision,
      'ALLOW',
    );
    assert.equal(
      engine.authorize(req({
        principalId: 'prn-owner-alice',
        workspaceId: 'ws-bob-private',
        action: 'cache.read',
        resource: { type: 'cache', id: 'cache:bob-index' },
      })).decision,
      'DENY',
    );
  });
});

describe('S2-002 policy engine: sandbox gate', () => {
  test('execution capability without proven OS controls is BLOCKED_SANDBOX', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-platform-experimenter',
      workspaceId: 'ws-veritas-project',
      action: 'tool.execute',
      resource: { type: 'tool', id: 'tool:runner' },
      lease: { leaseId: 'lse-experimenter-0005', fencingToken: 1 },
    }));
    assert.equal(result.decision, 'BLOCKED_SANDBOX');
    assert.ok(result.reasonCodes.includes('SBX_NO_OS_EVIDENCE'));
  });

  test('tool discovery stays readable (contract-level operation)', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({
      principalId: 'prn-platform-experimenter',
      workspaceId: 'ws-veritas-project',
      action: 'tool.discover',
      resource: { type: 'tool', id: 'tool:runner' },
    }));
    assert.equal(result.decision, 'ALLOW');
  });
});

describe('S2-002 policy engine: ACL matrix over 20 principals x 7 workspaces', () => {
  test('board.read matrix matches the frozen expectation table', () => {
    const engine = makeEngine();
    const allow = new Set([
      'prn-owner-alice|ws-alice-private',
      'prn-owner-bob|ws-bob-private',
      'prn-owner-carol|ws-carol-private',
      'prn-owner-dave|ws-dave-private',
      'prn-owner-eve|ws-eve-private',
      'prn-agent-alice|ws-alice-private',
      'prn-agent-alice|ws-veritas-project',
      'prn-agent-carol|ws-carol-private',
      'prn-external-pi|ws-veritas-project',
      'prn-platform-curator|ws-veritas-project',
      'prn-platform-analyst|ws-veritas-project',
      'prn-platform-experimenter|ws-veritas-project',
      'prn-platform-verifier|ws-veritas-project',
      'prn-platform-operator|ws-veritas-project',
      'prn-owner-alice|ws-veritas-project',
      'prn-owner-bob|ws-veritas-project',
    ]);
    const missing = [];
    for (const principal of PRINCIPALS) {
      for (const ws of WORKSPACES) {
        const key = `${principal.principal_id}|${ws.workspace_id}`;
        const expected = allow.has(key) ? 'ALLOW' : 'DENY';
        const result = engine.authorize(req({
          principalId: principal.principal_id,
          workspaceId: ws.workspace_id,
          action: 'board.read',
          resource: { type: 'board', id: 'board:primary' },
        }));
        if (result.decision !== expected) missing.push(`${key}: got ${result.decision}`);
      }
    }
    assert.deepEqual(missing, []);
    assert.equal(allow.size, 16);
  });
});

describe('S2-002 policy engine: Web/API/CLI parity and decision documents', () => {
  test('identical requests through web, api and cli produce identical decisions', () => {
    const engine = makeEngine();
    const results = ADAPTERS.map((adapter) => engine.authorize(req({
      adapter,
      principalId: 'prn-external-pi',
      workspaceId: 'ws-veritas-project',
      action: 'task.update',
      resource: { type: 'task', id: 'task:tsk-pilot-1' },
      lease: { leaseId: 'lse-pi-project-0001', fencingToken: 5 },
    })));
    // Parity: the transport surface never changes authority. Decision and
    // reason codes are identical; input_digest/audit_ref intentionally
    // record which surface issued the request for audit.
    const normalized = results.map((r) => {
      const { input_digest, audit_ref, ...document } = r.document;
      return { decision: r.decision, reasonCodes: r.reasonCodes, document };
    });
    assert.deepEqual(normalized[0], normalized[1]);
    assert.deepEqual(normalized[1], normalized[2]);
    assert.notEqual(results[0].document.input_digest, results[1].document.input_digest);
  });

  test('every decision carries a contract-valid authorization decision document', () => {
    const engine = makeEngine();
    const samples = [
      req(),
      req({ principalId: 'prn-agent-alice', workspaceId: 'ws-bob-private' }),
      req({
        principalId: 'prn-platform-experimenter',
        workspaceId: 'ws-veritas-project',
        action: 'tool.execute',
        resource: { type: 'tool', id: 'tool:runner' },
        lease: { leaseId: 'lse-experimenter-0005', fencingToken: 1 },
      }),
      req({ args: {} }),
      req({ resource: { type: 'secret', id: 'board:primary' } }),
      req({ principalId: 'prn-ghost' }),
      req({ workspaceId: 'ws-unknown' }),
      req({ action: 'board.destroy', args: {} }),
      req({ adapter: 'carrier-pigeon' }),
      {},
    ];
    for (const request of samples) {
      const result = engine.authorize(request);
      assert.ok(result.document, 'engine must return a decision document');
      assert.equal(result.document.policy_version, POLICY_VERSION);
      assertValidContract('authorization-decision', result.document);
      assert.equal(validateContract('authorization-decision', result.document).valid, true);
    }
  });

  test('unknown adapter names are rejected fail-closed', () => {
    const engine = makeEngine();
    const result = engine.authorize(req({ adapter: 'carrier-pigeon' }));
    assert.equal(result.decision, 'DENY');
    assert.ok(result.reasonCodes.includes('UNKNOWN_ADAPTER'));
  });
});
