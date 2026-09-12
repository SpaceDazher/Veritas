// S2-002 sandbox tier specifications.
// SANDBOX_NO_EXEC is a contract-valid profile: contract/evidence operations
// only, no live processes.
//
// SANDBOX_LOCAL_RESTRICTED_BLOCKED deliberately carries NO
// os_controls_evidence: on the current Windows/Node.js stack we cannot prove
// a kernel-level network boundary (AppContainer or equivalent) for child
// processes, so the LOCAL_RESTRICTED tier stays blocked. This object is the
// reviewed *target specification* of the controls we would run behind that
// boundary; createSandbox() independently re-verifies the boundary at
// runtime and refuses execution while it cannot be proven. It is intentionally
// NOT a valid `sandbox-profile` contract document and must never be
// registered as one until the kernel boundary evidence exists.
export const CONTRACT_VERSION = '1.0.0';

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
