// S2-002 authority registry: the deterministic subjects model.
// 20 principals across 7 workspaces with roles, capabilities, grants, leases
// and sandbox profiles. Every record validates against the phase-1 contracts
// (enforced by tests/identity/policy-engine.test.mjs). This registry is the
// seeded state for the policy engine; it is synthetic fixture data, not
// production authentication.
//
// Contract version: 1.0.0. Offline and deterministic by design.

export const CONTRACT_VERSION = '1.0.0';

const SHA_A = `sha256:${'a1'.repeat(32)}`;
const SHA_B = `sha256:${'b2'.repeat(32)}`;
const SHA_C = `sha256:${'c3'.repeat(32)}`;
const SHA_D = `sha256:${'d4'.repeat(32)}`;

const ISSUED = '2026-09-01T00:00:00.000Z';
const FAR_FUTURE = '2030-01-01T00:00:00.000Z';
const LEASE_ISSUED = '2026-09-10T00:00:00.000Z';
const LEASE_EXPIRY = '2026-09-20T00:00:00.000Z';
const LEASE_EXPIRED_AT = '2026-09-05T00:00:00.000Z';

const principal = (principal_id, display_name, kind, tenant_id, owner, subject_type, subject_ref, provider, adapter_id, extra = {}) => ({
  contractVersion: CONTRACT_VERSION,
  principal_id,
  display_name,
  kind,
  tenant: { tenant_id, owner_principal_id: owner },
  authenticated_subject: { subject_type, subject_ref },
  provider_adapter_identity: { provider, adapter_id },
  lifecycle_state: 'active',
  ...extra,
});

export const PRINCIPALS = Object.freeze([
  // Human owners (5)
  principal('prn-owner-alice', 'Alice (Owner)', 'human', 'tn-alice', 'prn-owner-alice', 'human_attested', 'human-alice-attested', 'human', 'owner'),
  principal('prn-owner-bob', 'Bob (Owner)', 'human', 'tn-bob', 'prn-owner-bob', 'human_attested', 'human-bob-attested', 'human', 'owner'),
  principal('prn-owner-carol', 'Carol (Owner)', 'human', 'tn-carol', 'prn-owner-carol', 'human_attested', 'human-carol-attested', 'human', 'owner'),
  principal('prn-owner-dave', 'Dave (Owner)', 'human', 'tn-dave', 'prn-owner-dave', 'human_attested', 'human-dave-attested', 'human', 'owner'),
  principal('prn-owner-eve', 'Eve (Owner)', 'human', 'tn-eve', 'prn-owner-eve', 'human_attested', 'human-eve-attested', 'human', 'owner'),
  // Personal agents (5) - act only via explicit owner delegation (grants)
  principal('prn-agent-alice', 'Alice Personal Agent', 'personal_agent', 'tn-alice', 'prn-owner-alice', 'delegated_token', 'tok-alice-agent-001', 'pi', 'pi-agent', { delegated_by: 'prn-owner-alice' }),
  principal('prn-agent-bob', 'Bob Personal Agent', 'personal_agent', 'tn-bob', 'prn-owner-bob', 'delegated_token', 'tok-bob-agent-001', 'codex', 'codex-agent', { delegated_by: 'prn-owner-bob' }),
  principal('prn-agent-carol', 'Carol Personal Agent', 'personal_agent', 'tn-carol', 'prn-owner-carol', 'delegated_token', 'tok-carol-agent-001', 'opencode', 'opencode-agent', { delegated_by: 'prn-owner-carol' }),
  principal('prn-agent-dave', 'Dave Personal Agent', 'personal_agent', 'tn-dave', 'prn-owner-dave', 'delegated_token', 'tok-dave-agent-001', 'hermes', 'hermes-agent', { delegated_by: 'prn-owner-dave' }),
  principal('prn-agent-eve', 'Eve Personal Agent', 'personal_agent', 'tn-eve', 'prn-owner-eve', 'delegated_token', 'tok-eve-agent-001', 'pi', 'pi-agent-eve', { delegated_by: 'prn-owner-eve' }),
  // External service principals (4) - separate identities, no inherited rights
  principal('prn-external-codex', 'Codex Service Principal', 'external_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-codex-001', 'codex', 'codex-cli'),
  principal('prn-external-pi', 'pi Service Principal', 'external_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-pi-001', 'pi', 'pi-cli'),
  principal('prn-external-opencode', 'OpenCode Service Principal', 'external_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-opencode-001', 'opencode', 'opencode-cli'),
  principal('prn-external-hermes', 'Hermes Service Principal', 'external_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-hermes-001', 'hermes', 'hermes-cli'),
  // Platform agents (6)
  principal('prn-platform-collector', 'Platform Collector', 'platform_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-collector-001', 'platform', 'collector'),
  principal('prn-platform-curator', 'Platform Curator', 'platform_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-curator-001', 'platform', 'curator'),
  principal('prn-platform-analyst', 'Platform Analyst', 'platform_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-analyst-001', 'platform', 'analyst'),
  principal('prn-platform-experimenter', 'Platform Experiment Runner', 'platform_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-experimenter-001', 'platform', 'experiment-runner'),
  principal('prn-platform-verifier', 'Platform Verifier', 'platform_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-verifier-001', 'platform', 'verifier'),
  principal('prn-platform-operator', 'Platform Operator', 'platform_agent', 'tn-platform', 'prn-platform-operator', 'service_identity', 'svc-operator-001', 'platform', 'operator'),
]);

const workspace = (workspace_id, owner, scope, acl, revision, roots) => ({
  contractVersion: CONTRACT_VERSION,
  workspace_id,
  owner,
  scope,
  acl,
  retention: { policy: 'retain_until_revocation' },
  allowed_roots: roots,
  network_profile: 'deny_all',
  revision,
});

const acl = (principal_id, role_id) => ({ principal_id, role_id });

export const WORKSPACES = Object.freeze([
  workspace('ws-alice-private', 'prn-owner-alice', 'private', [acl('prn-owner-alice', 'rol-workspace-owner')], 1, ['D:/workspaces/alice-private']),
  workspace('ws-bob-private', 'prn-owner-bob', 'private', [acl('prn-owner-bob', 'rol-workspace-owner')], 1, ['D:/workspaces/bob-private']),
  workspace('ws-carol-private', 'prn-owner-carol', 'private', [acl('prn-owner-carol', 'rol-workspace-owner')], 1, ['D:/workspaces/carol-private']),
  workspace('ws-dave-private', 'prn-owner-dave', 'private', [acl('prn-owner-dave', 'rol-workspace-owner')], 1, ['D:/workspaces/dave-private']),
  workspace('ws-eve-private', 'prn-owner-eve', 'private', [acl('prn-owner-eve', 'rol-workspace-owner')], 1, ['D:/workspaces/eve-private']),
  workspace('ws-veritas-project', 'prn-owner-alice', 'project', [
    acl('prn-owner-alice', 'rol-project-maintainer'),
    acl('prn-owner-alice', 'rol-human-approver'),
    acl('prn-owner-bob', 'rol-project-maintainer'),
    acl('prn-owner-bob', 'rol-human-approver'),
    acl('prn-platform-collector', 'rol-research-reader'),
    acl('prn-platform-curator', 'rol-curator'),
    acl('prn-platform-analyst', 'rol-analyst'),
    acl('prn-platform-experimenter', 'rol-experimenter'),
    acl('prn-platform-verifier', 'rol-verifier'),
    acl('prn-platform-operator', 'rol-operator'),
  ], 4, ['D:/workspaces/veritas-project']),
  workspace('ws-shared-library', 'prn-platform-operator', 'shared', [
    acl('prn-platform-collector', 'rol-research-reader'),
    acl('prn-platform-analyst', 'rol-research-reader'),
    acl('prn-platform-verifier', 'rol-research-reader'),
  ], 2, ['D:/workspaces/shared-library']),
]);

const capability = (capability_id, action, resource_type, canonical_arguments, constraints) => ({
  contractVersion: CONTRACT_VERSION,
  capability_id,
  action,
  resource_type,
  canonical_arguments,
  constraints,
});

const ARGS = (names) => names.map(([name, required]) => ({ name, required }));
const NO_LEASE = { requires_lease: false, requires_approval: false, exec_tier: 'none', network: 'none', side_effect: 'read' };

export const CAPABILITIES = Object.freeze([
  capability('cap-board.read', 'board.read', 'board', ARGS([['workspace_id', true], ['revision', false]]), NO_LEASE),
  capability('cap-task.create', 'task.create', 'task', ARGS([['title', true], ['criteria', false]]), { ...NO_LEASE, side_effect: 'write' }),
  capability('cap-task.update', 'task.update', 'task', ARGS([['task_id', true], ['expected_revision', true]]), { ...NO_LEASE, requires_lease: true, side_effect: 'write' }),
  capability('cap-task.transition', 'task.transition', 'task', ARGS([['task_id', true], ['from_status', true], ['to_status', true]]), { ...NO_LEASE, requires_lease: true, side_effect: 'write' }),
  capability('cap-task.cancel', 'task.cancel', 'task', ARGS([['task_id', true], ['reason', false]]), { ...NO_LEASE, side_effect: 'terminal' }),
  capability('cap-task.reassign', 'task.reassign', 'task', ARGS([['task_id', true], ['to_principal', true]]), { ...NO_LEASE, side_effect: 'write' }),
  capability('cap-source.read', 'source.read', 'source', ARGS([['source_id', true]]), NO_LEASE),
  capability('cap-search.query', 'search.query', 'source', ARGS([['query', true], ['scope', false]]), NO_LEASE),
  capability('cap-claim.read', 'claim.read', 'claim', ARGS([['claim_id', true]]), NO_LEASE),
  capability('cap-claim.write', 'claim.write', 'claim', ARGS([['claim_id', true], ['provenance', true]]), { ...NO_LEASE, requires_lease: true, side_effect: 'write' }),
  capability('cap-summary.read', 'summary.read', 'summary', ARGS([['summary_id', true]]), NO_LEASE),
  capability('cap-summary.generate', 'summary.generate', 'summary', ARGS([['summary_id', true], ['inputs', true]]), { ...NO_LEASE, requires_lease: true, side_effect: 'write' }),
  capability('cap-cache.read', 'cache.read', 'cache', ARGS([['cache_id', true]]), NO_LEASE),
  capability('cap-cache.write', 'cache.write', 'cache', ARGS([['cache_id', true], ['inputs', true]]), { ...NO_LEASE, requires_lease: true, side_effect: 'write' }),
  capability('cap-artifact.read', 'artifact.read', 'artifact', ARGS([['artifact_id', true]]), NO_LEASE),
  capability('cap-artifact.export', 'artifact.export', 'artifact', ARGS([['artifact_id', true], ['destination', true]]), { ...NO_LEASE, side_effect: 'write' }),
  capability('cap-message.send', 'message.send', 'message', ARGS([['to_principal', true], ['body_digest', true]]), { ...NO_LEASE, side_effect: 'write' }),
  capability('cap-message.read', 'message.read', 'message', ARGS([['message_id', true]]), NO_LEASE),
  capability('cap-tool.discover', 'tool.discover', 'tool', ARGS([['workspace_id', true]]), NO_LEASE),
  capability('cap-tool.execute', 'tool.execute', 'tool', ARGS([['tool_id', true], ['canonical_args', true]]), { requires_lease: true, requires_approval: false, exec_tier: 'local_restricted', network: 'allowlisted', side_effect: 'write' }),
  capability('cap-approval.decide', 'approval.decide', 'approval', ARGS([['approval_id', true], ['verdict', true]]), { ...NO_LEASE, side_effect: 'terminal' }),
]);

const role = (role_id, name, description, capabilities) => ({
  contractVersion: CONTRACT_VERSION,
  role_id,
  name,
  description,
  capabilities,
});

export const ROLES = Object.freeze([
  role('rol-workspace-owner', 'Workspace Owner', 'Full maintenance authority inside one owned workspace; lease requirement waived for owner maintenance', [
    'cap-board.read', 'cap-task.create', 'cap-task.update', 'cap-task.transition', 'cap-task.cancel', 'cap-task.reassign',
    'cap-source.read', 'cap-search.query', 'cap-claim.read', 'cap-claim.write', 'cap-summary.read', 'cap-summary.generate',
    'cap-cache.read', 'cap-cache.write', 'cap-artifact.read', 'cap-artifact.export', 'cap-message.send', 'cap-message.read',
    'cap-tool.discover', 'cap-approval.decide',
  ]),
  role('rol-project-maintainer', 'Project Maintainer', 'Planning and research maintenance in the project workspace', [
    'cap-board.read', 'cap-task.create', 'cap-task.update', 'cap-task.transition',
    'cap-source.read', 'cap-search.query', 'cap-claim.read', 'cap-summary.read', 'cap-cache.read',
    'cap-artifact.read', 'cap-message.send', 'cap-message.read', 'cap-tool.discover',
  ]),
  role('rol-human-approver', 'Human Approver', 'Human-only acceptance decisions; engine additionally blocks producers and non-humans', ['cap-approval.decide']),
  role('rol-research-reader', 'Research Reader', 'Read-only research retrieval', [
    'cap-source.read', 'cap-search.query', 'cap-claim.read', 'cap-summary.read', 'cap-cache.read',
  ]),
  role('rol-curator', 'Platform Curator', 'Claim graph and derived view maintenance', [
    'cap-board.read', 'cap-claim.read', 'cap-claim.write', 'cap-summary.read', 'cap-summary.generate', 'cap-cache.read', 'cap-cache.write',
  ]),
  role('rol-analyst', 'Platform Analyst', 'Summary generation over curated inputs', [
    'cap-board.read', 'cap-source.read', 'cap-claim.read', 'cap-summary.read', 'cap-summary.generate', 'cap-cache.read',
  ]),
  role('rol-experimenter', 'Platform Experiment Runner', 'Tool discovery and gated execution', [
    'cap-board.read', 'cap-tool.discover', 'cap-tool.execute', 'cap-cache.read',
  ]),
  role('rol-verifier', 'Platform Verifier', 'Independent evidence verification reads', [
    'cap-board.read', 'cap-artifact.read', 'cap-claim.read', 'cap-summary.read', 'cap-cache.read',
  ]),
  role('rol-operator', 'Platform Operator', 'Cancellation and reassignment duty, no approvals', [
    'cap-board.read', 'cap-task.cancel', 'cap-task.reassign', 'cap-cache.read',
  ]),
  role('rol-messenger', 'Messenger', 'Inter-agent messaging within one workspace', ['cap-message.send', 'cap-message.read']),
]);

const grant = (grant_id, issuer, principal_id, capability_id, workspace_id, resource_type, resource_ids, issued_at, expires_at, extra = {}) => ({
  contractVersion: CONTRACT_VERSION,
  grant_id,
  issuer,
  principal_id,
  capability_id,
  resource_scope: { workspace_id, resource_type, resource_ids },
  issued_at,
  expires_at,
  revoked_at: null,
  revision: 1,
  status: 'active',
  auth_ref: { scheme: 'offline_signature_v1', reference: SHA_A },
  ...extra,
});

export const GRANTS = Object.freeze([
  grant('grt-alice-agent-read-0001', 'prn-owner-alice', 'prn-agent-alice', 'cap-board.read', 'ws-alice-private', 'board', ['board:primary'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_A } }),
  grant('grt-alice-agent-project-read-0003', 'prn-owner-alice', 'prn-agent-alice', 'cap-board.read', 'ws-veritas-project', 'board', ['board:primary'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_B } }),
  grant('grt-alice-pi-project-read-0010', 'prn-owner-alice', 'prn-external-pi', 'cap-board.read', 'ws-veritas-project', 'board', ['board:primary'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_C } }),
  grant('grt-alice-pi-project-update-0004', 'prn-owner-alice', 'prn-external-pi', 'cap-task.update', 'ws-veritas-project', 'task', ['task:tsk-pilot-1', 'task:tsk-pilot-2'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_D } }),
  grant('grt-bob-agent-research-0005', 'prn-owner-bob', 'prn-agent-bob', 'cap-source.read', 'ws-bob-private', 'source', ['source:bob-notes-1', 'source:bob-notes-2'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_B } }),
  grant('grt-bob-agent-cache-0006', 'prn-owner-bob', 'prn-agent-bob', 'cap-cache.read', 'ws-bob-private', 'cache', ['cache:bob-index'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_C } }),
  grant('grt-carol-agent-read-0008', 'prn-owner-carol', 'prn-agent-carol', 'cap-board.read', 'ws-carol-private', 'board', ['board:primary'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_D } }),
  grant('grt-carol-agent-export-0007', 'prn-owner-carol', 'prn-agent-carol', 'cap-artifact.export', 'ws-carol-private', 'artifact', ['artifact:final-1'], ISSUED, FAR_FUTURE, { nonce: 'n-carolnonce0001', auth_ref: { scheme: 'offline_signature_v1', reference: SHA_A } }),
  grant('grt-bob-hermes-expired-0009', 'prn-owner-bob', 'prn-external-hermes', 'cap-search.query', 'ws-veritas-project', 'source', ['source:docs'], '2025-12-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', { status: 'expired', auth_ref: { scheme: 'offline_signature_v1', reference: SHA_B } }),
  grant('grt-bob-codex-create-0011', 'prn-owner-bob', 'prn-external-codex', 'cap-task.create', 'ws-veritas-project', 'task', ['task:new-codex'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_C } }),
  grant('grt-dave-agent-create-0012', 'prn-owner-dave', 'prn-agent-dave', 'cap-task.create', 'ws-dave-private', 'task', ['task:new-dave'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_D } }),
  grant('grt-alice-curator-lease-0013', 'prn-owner-alice', 'prn-platform-curator', 'cap-summary.generate', 'ws-veritas-project', 'summary', ['summary:board-weekly', 'summary:poisoned'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_A } }),
  grant('grt-bob-experimenter-lease-0014', 'prn-owner-bob', 'prn-platform-experimenter', 'cap-tool.execute', 'ws-veritas-project', 'tool', ['tool:runner'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_B } }),
  grant('grt-alice-curator-claimwrite-0015', 'prn-owner-alice', 'prn-platform-curator', 'cap-claim.write', 'ws-veritas-project', 'claim', ['claim:curation-1', 'claim:c1'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_C } }),
  grant('grt-alice-pi-project-update-0016', 'prn-owner-alice', 'prn-external-pi', 'cap-task.update', 'ws-veritas-project', 'task', ['task:tsk-pilot-3'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_D } }),
  grant('grt-alice-curator-cachewrite-0017', 'prn-owner-alice', 'prn-platform-curator', 'cap-cache.write', 'ws-veritas-project', 'cache', ['cache:poisoned-1', 'cache:project-index'], ISSUED, FAR_FUTURE, { auth_ref: { scheme: 'offline_signature_v1', reference: SHA_A } }),
]);

const lease = (lease_id, workspace_id, owner, grant_id, task_id, run_id, fencing_token, issued_at, expires_at, state = 'active') => ({
  contractVersion: CONTRACT_VERSION,
  lease_id,
  workspace_id,
  owner,
  grant_id,
  task_ref: { task_id, run_id },
  fencing_token,
  issued_at,
  expires_at,
  revoked_at: null,
  state,
});

export const LEASES = Object.freeze([
  lease('lse-pi-project-0001', 'ws-veritas-project', 'prn-external-pi', 'grt-alice-pi-project-update-0004', 'tsk-pilot-1', 'run-0001', 5, LEASE_ISSUED, LEASE_EXPIRY),
  lease('lse-pi-project-0002-expired', 'ws-veritas-project', 'prn-external-pi', 'grt-alice-pi-project-update-0004', 'tsk-pilot-2', 'run-0001', 3, '2026-09-01T00:00:00.000Z', LEASE_EXPIRED_AT),
  lease('lse-curator-0004', 'ws-veritas-project', 'prn-platform-curator', 'grt-alice-curator-lease-0013', 'tsk-curation-0001', 'run-0001', 2, LEASE_ISSUED, LEASE_EXPIRY),
  lease('lse-experimenter-0005', 'ws-veritas-project', 'prn-platform-experimenter', 'grt-bob-experimenter-lease-0014', 'tool-run-0001', 'run-0001', 1, LEASE_ISSUED, LEASE_EXPIRY),
  lease('lse-curator-claimwrite-0006', 'ws-veritas-project', 'prn-platform-curator', 'grt-alice-curator-claimwrite-0015', 'tsk-curation-0002', 'run-0001', 1, LEASE_ISSUED, LEASE_EXPIRY),
  lease('lse-pi-project-0007', 'ws-veritas-project', 'prn-external-pi', 'grt-alice-pi-project-update-0016', 'tsk-pilot-3', 'run-0001', 3, LEASE_ISSUED, LEASE_EXPIRY),
  lease('lse-curator-cachewrite-0008', 'ws-veritas-project', 'prn-platform-curator', 'grt-alice-curator-cachewrite-0017', 'tsk-curation-0003', 'run-0001', 1, LEASE_ISSUED, LEASE_EXPIRY),
]);

export const SANDBOX_PROFILES = Object.freeze([
  {
    contractVersion: CONTRACT_VERSION,
    profile_id: 'sbx-no-exec-default',
    tier: 'NO_EXEC',
    filesystem: { roots: ['D:/workspaces'], deny_link_escape: true, deny_traversal: true },
    network: { policy: 'deny_all', allowlist: [] },
    environment: { allowlist: ['NODE_ENV'], secret_handles: [] },
    process: { max_processes: 1, memory_mb: 512, timeout_ms: 30000 },
    cancellation: { mode: 'process_tree', on_timeout: 'fail_closed' },
  },
]);
