// S2-002 sandbox tier specifications.
// SANDBOX_NO_EXEC is a contract-valid profile: contract/evidence operations
// only, no live processes.
//
// Executable profiles are bound to measured host controls and fixed backends.
// LOCAL_RESTRICTED uses rootless Podman. UNTRUSTED_CODE adds gVisor's userspace
// kernel, an outer auto user namespace and rootful cgroup enforcement. The
// rootful launcher accepts no caller-controlled image, mount, environment,
// network or runtime option.
export const CONTRACT_VERSION = '1.0.0';

// Content address of evidence/s2-002-podman-sandbox.json. The profile is
// registered only for LOCAL_RESTRICTED.
export const SANDBOX_LOCAL_RESTRICTED_PODMAN = Object.freeze({
  contractVersion: CONTRACT_VERSION,
  profile_id: 'sbx-podman-local-restricted-v1',
  tier: 'LOCAL_RESTRICTED',
  os_controls_evidence: 'sha256:5b7a6314edaf2860cc78a2855fd2a82fcd17bee8dc358742404ffc006740bf2c',
  filesystem: {
    roots: ['/tmp'],
    deny_link_escape: true,
    deny_traversal: true,
  },
  network: { policy: 'deny_all', allowlist: [] },
  environment: { allowlist: [], secret_handles: [] },
  process: { max_processes: 32, memory_mb: 128, timeout_ms: 30000 },
  cancellation: { mode: 'process_tree', on_timeout: 'kill_tree' },
});

// Replaced after scripts/verify-gvisor-sandbox.mjs --write observes the host.
export const SANDBOX_UNTRUSTED_CODE_GVISOR = Object.freeze({
  contractVersion: CONTRACT_VERSION,
  profile_id: 'sbx-gvisor-untrusted-v1',
  tier: 'UNTRUSTED_CODE',
  os_controls_evidence: 'sha256:c5cc3ce34b92f9ec8d2bc0400fde04f8bcc2e93c5656037712e350c60d4540af',
  filesystem: {
    roots: ['/tmp'],
    deny_link_escape: true,
    deny_traversal: true,
  },
  network: { policy: 'deny_all', allowlist: [] },
  environment: { allowlist: [], secret_handles: [] },
  process: { max_processes: 32, memory_mb: 128, timeout_ms: 30000 },
  cancellation: { mode: 'process_tree', on_timeout: 'kill_tree' },
});

export const SANDBOX_NO_EXEC = Object.freeze({
  contractVersion: CONTRACT_VERSION,
  profile_id: 'sbx-no-exec-default',
  tier: 'NO_EXEC',
  filesystem: {
    roots: ['D:/workspaces'],
    deny_link_escape: true,
    deny_traversal: true,
  },
  network: { policy: 'deny_all', allowlist: [] },
  environment: { allowlist: ['NODE_ENV', 'TEMP', 'TMP'], secret_handles: [] },
  process: { max_processes: 1, memory_mb: 512, timeout_ms: 30000 },
  cancellation: { mode: 'process_tree', on_timeout: 'fail_closed' },
});

export const SANDBOX_LOCAL_RESTRICTED_BLOCKED = Object.freeze({
  contractVersion: CONTRACT_VERSION,
  profile_id: 'sbx-local-restricted-blocked',
  tier: 'LOCAL_RESTRICTED',
  filesystem: {
    roots: ['D:/workspaces'],
    deny_link_escape: true,
    deny_traversal: true,
  },
  network: { policy: 'deny_all', allowlist: [] },
  environment: { allowlist: ['NODE_ENV', 'TEMP', 'TMP', 'SYSTEMROOT'], secret_handles: [] },
  process: { max_processes: 4, memory_mb: 1024, timeout_ms: 60000 },
  cancellation: { mode: 'process_tree', on_timeout: 'kill_tree' },
});

export const SANDBOX_UNTRUSTED_CODE_BLOCKED = Object.freeze({
  contractVersion: CONTRACT_VERSION,
  profile_id: 'sbx-untrusted-code-blocked',
  tier: 'UNTRUSTED_CODE',
  filesystem: {
    roots: ['D:/workspaces'],
    deny_link_escape: true,
    deny_traversal: true,
  },
  network: { policy: 'deny_all', allowlist: [] },
  environment: { allowlist: ['NODE_ENV'], secret_handles: [] },
  process: { max_processes: 2, memory_mb: 512, timeout_ms: 30000 },
  cancellation: { mode: 'process_tree', on_timeout: 'kill_tree' },
});
