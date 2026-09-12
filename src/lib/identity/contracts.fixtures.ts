// Compile-time check that canonical contract fixtures satisfy the S2-002
// TypeScript types. Runtime validation authority is the registry; this file
// only proves the type surface stays aligned with the fixtures used by tests
// and the policy engine. Checked by `npm run typecheck`.
import type {
  AuthorizationDecision,
  Capability,
  Grant,
  Lease,
  Principal,
  Role,
  SandboxProfile,
  Workspace,
} from './contracts.js';

const T0 = '2026-09-12T12:00:00.000Z';
const T1 = '2026-09-12T12:05:00.000Z';
const HEX64 = 'a'.repeat(64);

export const WORKSPACE_FIXTURE: Workspace = {
  contractVersion: '1.0.0',
  workspaceId: 'ws-board-core',
  owner: 'prn-owner-alice',
  scope: 'private',
  acl: [{ principalId: 'prn-owner-alice', roleId: 'rol-workspace-owner' }],
  retention: { policy: 'retain_until_revocation' },
  allowedRoots: ['D:/workspaces/board-core'],
  networkProfile: 'deny_all',
  revision: 3,
};

export const PRINCIPAL_FIXTURE: Principal = {
  contractVersion: '1.0.0',
  principalId: 'prn-agent-alice',
  displayName: 'Alice Personal Agent',
  kind: 'personal_agent',
  tenant: { tenantId: 'tn-alice', ownerPrincipalId: 'prn-owner-alice' },
  authenticatedSubject: { subjectType: 'delegated_token', subjectRef: 'tok-alice-agent-001' },
  providerAdapterIdentity: { provider: 'pi', adapterId: 'pi-agent', adapterVersion: '1.2.0' },
  lifecycleState: 'active',
  delegatedBy: 'prn-owner-alice',
};

export const ROLE_FIXTURE: Role = {
  contractVersion: '1.0.0',
  roleId: 'rol-board-reader',
  name: 'Board Reader',
  description: 'Read-only board access within one workspace',
  capabilities: ['cap-board.read', 'cap-task.read'],
};

export const CAPABILITY_FIXTURE: Capability = {
  contractVersion: '1.0.0',
  capabilityId: 'cap-board.read',
  action: 'board.read',
  resourceType: 'board',
  canonicalArguments: [
    { name: 'workspace_id', required: true },
    { name: 'revision', required: false },
  ],
  constraints: {
    requiresLease: false,
    requiresApproval: false,
    execTier: 'no_exec',
    network: 'none',
    sideEffect: 'read',
  },
};

export const GRANT_FIXTURE: Grant = {
  contractVersion: '1.0.0',
  grantId: 'grt-alice-board-read-0001',
  issuer: 'prn-owner-alice',
  principalId: 'prn-agent-alice',
  capabilityId: 'cap-board.read',
  resourceScope: {
    workspaceId: 'ws-board-core',
    resourceType: 'board',
    resourceIds: ['board:primary'],
  },
  issuedAt: T0,
  expiresAt: T1,
  revokedAt: null,
  nonce: 'n-0f8a2b7c1d9e4f36',
  revision: 1,
  status: 'active',
  authRef: { scheme: 'offline_signature_v1', reference: `sha256:${HEX64}` },
};

export const LEASE_FIXTURE: Lease = {
  contractVersion: '1.0.0',
  leaseId: 'lse-run-0001',
  workspaceId: 'ws-board-core',
  owner: 'prn-agent-alice',
  grantId: 'grt-alice-board-read-0001',
  taskRef: { taskId: 'tsk-0001', runId: 'run-0001' },
  fencingToken: 7,
  issuedAt: T0,
  expiresAt: T1,
  state: 'active',
};

export const SANDBOX_FIXTURE: SandboxProfile = {
  contractVersion: '1.0.0',
  profileId: 'sbx-no-exec-default',
  tier: 'NO_EXEC',
  filesystem: {
    roots: ['D:/workspaces/board-core'],
    denyLinkEscape: true,
    denyTraversal: true,
  },
  network: { policy: 'deny_all', allowlist: [] },
  environment: { allowlist: ['NODE_ENV'], secretHandles: [] },
  process: { maxProcesses: 1, memoryMb: 512, timeoutMs: 30000 },
  cancellation: { mode: 'process_tree', onTimeout: 'fail_closed' },
};

export const DECISION_FIXTURE: AuthorizationDecision = {
  contractVersion: '1.0.0',
  decision: 'ALLOW',
  reasonCodes: ['GRANT_VALID', 'LEASE_FRESH'],
  policyVersion: 's2-002-policy-v1',
  inputDigest: `sha256:${HEX64}`,
  auditRef: 'aud:decision-0001-abcd1234',
  principalId: 'prn-agent-alice',
  capabilityId: 'cap-board.read',
  workspaceId: 'ws-board-core',
  decidedAt: T1,
  context: {
    grantId: 'grt-alice-board-read-0001',
    leaseId: 'lse-run-0001',
    fencingToken: 7,
  },
};
