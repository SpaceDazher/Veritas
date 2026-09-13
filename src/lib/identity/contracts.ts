// S2-002 identity/sandbox TypeScript contract types.
// Mirror image of contracts/*.schema.json (1.0.0). JSON fields are snake_case
// per the schemas; these TypeScript interfaces use camelCase and are the
// compile-time surface for Web/API code. The registry
// (src/lib/identity/contract-registry.mjs) remains the runtime authority.

export type WorkspaceScope = 'private' | 'project' | 'shared';
export type RetentionPolicy = 'retain_until_revocation' | 'delete_after' | 'archive_on_closure';
export type NetworkProfile = 'deny_all' | 'allowlisted';

export interface WorkspaceAclEntry {
  principalId: string;
  roleId: string;
}

export interface WorkspaceRetention {
  policy: RetentionPolicy;
  deleteAfterDays?: number;
}

export interface Workspace {
  contractVersion: '1.0.0';
  workspaceId: string;
  owner: string;
  scope: WorkspaceScope;
  acl: WorkspaceAclEntry[];
  retention: WorkspaceRetention;
  allowedRoots: string[];
  networkProfile: NetworkProfile;
  revision: number;
}

export type PrincipalKind = 'human' | 'personal_agent' | 'platform_agent' | 'external_agent';
export type PrincipalLifecycleState = 'active' | 'suspended' | 'revoked' | 'retired';
export type SubjectType = 'human_attested' | 'delegated_token' | 'service_identity' | 'unauthenticated';
export type Provider = 'human' | 'codex' | 'pi' | 'opencode' | 'hermes' | 'platform';

export interface PrincipalTenant {
  tenantId: string;
  ownerPrincipalId: string;
}

export interface AuthenticatedSubject {
  subjectType: SubjectType;
  subjectRef: string;
}

export interface ProviderAdapterIdentity {
  provider: Provider;
  adapterId: string;
  adapterVersion?: string;
}

export interface Principal {
  contractVersion: '1.0.0';
  principalId: string;
  displayName: string;
  kind: PrincipalKind;
  tenant: PrincipalTenant;
  authenticatedSubject: AuthenticatedSubject;
  providerAdapterIdentity: ProviderAdapterIdentity;
  lifecycleState: PrincipalLifecycleState;
  /** Required exactly for personal agents; forbidden otherwise. */
  delegatedBy?: string;
}

export interface Role {
  contractVersion: '1.0.0';
  roleId: string;
  name: string;
  description: string;
  capabilities: string[];
}

export type ResourceType =
  | 'task'
  | 'source'
  | 'claim'
  | 'summary'
  | 'cache'
  | 'artifact'
  | 'message'
  | 'tool'
  | 'approval'
  | 'workspace'
  | 'board';

export type ExecTier = 'none' | 'no_exec' | 'local_restricted' | 'untrusted_code';
export type CapabilityNetwork = 'none' | 'allowlisted';
export type SideEffect = 'read' | 'write' | 'terminal';

export interface CanonicalArgument {
  name: string;
  required: boolean;
}

export interface CapabilityConstraints {
  requiresLease: boolean;
  requiresApproval: boolean;
  execTier: ExecTier;
  network: CapabilityNetwork;
  sideEffect: SideEffect;
}

export interface Capability {
  contractVersion: '1.0.0';
  capabilityId: string;
  action: string;
  resourceType: ResourceType;
  canonicalArguments: CanonicalArgument[];
  constraints: CapabilityConstraints;
}

export type GrantStatus = 'draft' | 'active' | 'revoked' | 'expired';
export type AuthScheme = 'offline_signature_v1' | 'platform_attestation_v1';

export interface ResourceScope {
  workspaceId: string;
  resourceType: ResourceType;
  /** Canonical "namespace:id" references; wildcards are invalid. */
  resourceIds: string[];
}

export interface GrantAuthRef {
  scheme: AuthScheme;
  reference: string;
}

export interface Grant {
  contractVersion: '1.0.0';
  grantId: string;
  issuer: string;
  principalId: string;
  capabilityId: string;
  resourceScope: ResourceScope;
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
  nonce?: string;
  revision: number;
  status: GrantStatus;
  authRef: GrantAuthRef;
}

export type LeaseState = 'active' | 'expired' | 'revoked';

export interface LeaseTaskRef {
  taskId: string;
  runId: string;
}

export interface Lease {
  contractVersion: '1.0.0';
  leaseId: string;
  workspaceId: string;
  owner: string;
  grantId: string;
  taskRef: LeaseTaskRef;
  fencingToken: number;
  issuedAt: string;
  expiresAt: string;
  revokedAt?: string | null;
  state: LeaseState;
}

export type SandboxTier = 'NO_EXEC' | 'LOCAL_RESTRICTED' | 'UNTRUSTED_CODE';

export interface SandboxFilesystem {
  roots: string[];
  denyLinkEscape: true;
  denyTraversal: true;
}

export interface NetworkTarget {
  host: string;
  ports: number[];
}

export interface SandboxNetwork {
  policy: 'deny_all' | 'allowlist';
  allowlist: NetworkTarget[];
}

export interface SandboxEnvironment {
  allowlist: string[];
  secretHandles: string[];
}

export interface SandboxProcessLimits {
  maxProcesses: number;
  memoryMb: number;
  timeoutMs: number;
  cpuTimeMs?: number;
}

export interface SandboxCancellation {
  mode: 'process_tree' | 'single_process';
  onTimeout: 'kill_tree' | 'fail_closed';
}

export interface SandboxProfile {
  contractVersion: '1.0.0';
  profileId: string;
  tier: SandboxTier;
  /** Required for LOCAL_RESTRICTED and UNTRUSTED_CODE; their absence keeps the tier blocked. */
  osControlsEvidence?: string;
  filesystem: SandboxFilesystem;
  network: SandboxNetwork;
  environment: SandboxEnvironment;
  process: SandboxProcessLimits;
  cancellation: SandboxCancellation;
}

export type Decision = 'ALLOW' | 'DENY' | 'BLOCKED_SANDBOX' | 'NEEDS_APPROVAL';

export interface DecisionContext {
  grantId?: string;
  leaseId?: string;
  fencingToken?: number;
}

export interface AuthorizationDecision {
  contractVersion: '1.0.0';
  decision: Decision;
  reasonCodes: string[];
  policyVersion: string;
  inputDigest: string;
  auditRef: string;
  principalId: string;
  capabilityId: string;
  workspaceId: string;
  decidedAt: string;
  context: DecisionContext;
}
