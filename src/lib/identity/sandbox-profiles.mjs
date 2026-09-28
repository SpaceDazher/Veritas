// S2-002 sandbox tier specifications.
// SANDBOX_NO_EXEC is a contract-valid profile: contract/evidence operations
// only, no live processes.
//
// Executable profiles are bound to measured host controls and fixed backends.
// LOCAL_RESTRICTED uses rootless Podman. UNTRUSTED_CODE adds gVisor's userspace
// kernel, an outer auto user namespace and rootful cgroup enforcement. The
// rootful launcher accepts no caller-controlled image, mount, environment,
// network or runtime option.
//
// HOST_UNISOLATED (issue #45) is NOT an executable-in-the-isolation-sense tier.
// It is the honest floor for a host that provably cannot run a model-calling
// executor inside any isolation profile: inside the pinned alpine image there
// is no node/codex/pi, `--network=none` gives no route, and the profile
// carries `mounts:0` + `injectedEnvironment:0` + `secret_handles:[]`, so no
// credential can reach a containerised child either. Its `os_controls_evidence`
// is therefore a digest of a record of the measured ABSENCE of controls
// (scripts/verify-s2-007r-host-unisolated.mjs), and it declares
// `network.policy: 'unrestricted'` and `environment.allowlist: ['*']` because
// those are exactly the controls it does not have — the schema forbids this
// tier from claiming deny_all or an allowlist. A run bound to it is authorised
// only by a separate named human authorisation document resolved server-side
// (policy.assertUnisolatedExecutionAuthorized), never by the adapter, the task
// or the executor, and no A-MVP isolation clause may ever be scored against it.
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

// The floor tier: an ordinary host process, with nothing OS-enforced around it.
// It is added for issue #45 and it is deliberately the weakest profile in the
// registry: `unrestricted` network, an all-environment allowlist and no secret
// handles are not concessions, they are the declaration of what is missing.
// The evidence digest below is the digest of
// evidence/s2-007r-host-unisolated.json and is replaced by
// `node scripts/verify-s2-007r-host-unisolated.mjs --write` after the host has
// been observed, exactly as the gVisor profile's digest is.
export const SANDBOX_HOST_UNISOLATED = Object.freeze({
  contractVersion: CONTRACT_VERSION,
  profile_id: 'sbx-host-unisolated-v1',
  tier: 'HOST_UNISOLATED',
  os_controls_evidence: 'sha256:5e253d183824c5d60d4d9e707adbf879f5ed048df4bcd70f1b739ff145967f1f',
  filesystem: {
    roots: ['D:/workspaces'],
    deny_link_escape: true,
    deny_traversal: true,
  },
  network: { policy: 'unrestricted', allowlist: [] },
  environment: { allowlist: ['*'], secret_handles: [] },
  process: { max_processes: 4, memory_mb: 1024, timeout_ms: 600000 },
  cancellation: { mode: 'process_tree', on_timeout: 'kill_tree' },
});
