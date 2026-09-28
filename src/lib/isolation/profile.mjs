// S2-002 A-MVP-04 — the four allowlist axes, derived from a profile.
//
// The contract in `contracts/sandbox-profile.schema.json` states a shape; this
// module states the same shape as executable predicates and then MEANS it, by
// turning each axis into the podman flags the container is actually launched
// with. The schema is not imported and the file is not read: the schema lives
// in a frozen directory, and a module that parsed it at run time would make a
// change to a frozen file a change to this tree's behaviour without a diff
// anyone reviews. Mirroring it means a reader compares two texts.
//
// THE RULE THIS MODULE EXISTS TO ENFORCE: DENY BY DEFAULT, NO WILDCARD.
//
// `deny` is the default for all four axes, and a wildcard is not a value any
// executable tier may carry:
//
//   * `network.policy` is `deny_all` unless the profile names exact hosts and
//     ports. `unrestricted` is the `HOST_UNISOLATED` tier's declaration of what
//     it does NOT have, and that tier is not in `EXECUTABLE_TIERS` — it can be
//     written down and it can never be launched through this module.
//   * `filesystem.roots` is a list of roots the launcher mounts. The
//     container's own root is read-only, so "not listed" is not "writable by
//     default", it is "not writable at all".
//   * `environment.allowlist` is a list of variable NAMES. The host
//     environment is never inherited: the launcher builds the child's
//     environment from this list alone, so a variable nobody listed is absent
//     rather than leaked, and a secret is a `secret_handles` entry and never a
//     name here.
//   * `process` is a set of ceilings, not a description. `--pids-limit`,
//     `--memory` and `--memory-swap` come from the profile, so the process axis
//     is a number the OS enforces.
import {
  EXECUTOR_ENTRYPOINT,
  EXECUTOR_PACKAGE,
  EXECUTOR_VERSION,
} from './image.mjs';

export const PROFILE_ERRORS = Object.freeze({
  WILDCARD_NOT_PERMITTED: 'ISOLATION_WILDCARD_ALLOWLIST_NOT_PERMITTED',
  TIER_NOT_EXECUTABLE: 'ISOLATION_TIER_NOT_EXECUTABLE',
  PROFILE_MALFORMED: 'ISOLATION_PROFILE_MALFORMED',
  DESTINATION_NOT_ALLOWLISTED: 'ISOLATION_DESTINATION_NOT_ALLOWLISTED',
  SECRET_HANDLE_INVALID: 'ISOLATION_SECRET_HANDLE_INVALID',
  SECRET_HANDLE_NOT_DECLARED: 'ISOLATION_SECRET_HANDLE_NOT_DECLARED',
  ARG_OUTSIDE_ALLOWLIST: 'ISOLATION_ARG_OUTSIDE_ALLOWLIST',
  ENV_NOT_ALLOWLISTED: 'ISOLATION_ENV_NOT_ALLOWLISTED',
  FS_ROOT_INVALID: 'ISOLATION_FS_ROOT_INVALID',
});

// Tiers this module will launch. `NO_EXEC` is absent because it is the tier
// whose meaning is that nothing runs. `HOST_UNISOLATED` is absent because the
// S2-007R record measures that it is not an isolation tier at all: it exists so
// a host that cannot execute a model-calling agent inside an isolation profile
// can still be RECORDED, and it declares `unrestricted` network plus an
// all-environment allowlist precisely as the controls it lacks. Counting it
// here would be the exact substitution the handoff forbids.
export const EXECUTABLE_TIERS = Object.freeze(['LOCAL_RESTRICTED', 'UNTRUSTED_CODE']);

// Recorded, never launched. A profile with this tier is a legal document and an
// illegal invocation, and `assertExecutableProfile` is the single place that
// says so.
export const NON_EXECUTABLE_TIERS = Object.freeze(['NO_EXEC', 'HOST_UNISOLATED']);

export const CONTAINER_UID = 65534;
export const CONTAINER_GID = 65534;
export const CONTAINER_USER = `${CONTAINER_UID}:${CONTAINER_GID}`;

/**
 * The A-MVP-04 profile: a real installed executor, under all four axes.
 *
 * `network.policy` is `deny_all` and the allowlist is empty. That is the honest
 * value for the measurement this ticket makes, and it is the value the default
 * would pick anyway. The one allowlisted destination in the repository's own
 * model configuration is carried by `ISOLATION_EGRESS_ALLOWLIST` below as a
 * *candidate* set, which `buildInvocation` consults only when a profile asks
 * for `allowlist`; a profile that says `deny_all` cannot reach it, because the
 * network flag and the mounted socket are derived from the same field. An
 * allowlist that existed in the profile but was not wired to a flag would be a
 * declaration; this one is either enforced or absent.
 */
export const SANDBOX_ISOLATION_EXECUTOR = Object.freeze({
  contractVersion: '1.0.0',
  profile_id: 'sbx-isolation-executor-local-restricted-v1',
  tier: 'LOCAL_RESTRICTED',
  image_package: EXECUTOR_PACKAGE,
  image_entrypoint: EXECUTOR_ENTRYPOINT,
  image_expected_version: EXECUTOR_VERSION,
  os_controls_evidence: null, // filled by the run; the record carries the digest
  filesystem: Object.freeze({
    roots: Object.freeze(['/tmp']),
    deny_link_escape: true,
    deny_traversal: true,
    root_fs_read_only: true,
    writable_tmpfs: Object.freeze(['/tmp']),
  }),
  network: Object.freeze({ policy: 'deny_all', allowlist: Object.freeze([]) }),
  environment: Object.freeze({
    // Names only. The launcher passes exactly these, and passes nothing else.
    allowlist: Object.freeze(['HOME', 'TMPDIR', 'PI_HOME', 'NODE_ENV']),
    // Descriptors, not values. The value is materialised into the container
    // secret store at launch and is reachable only at /run/secrets/<handle>.
    secret_handles: Object.freeze(['sec-veritas-executor-credential']),
    // Passed as `--env NAME=<value>`; every one of these is a fixed literal
    // this file owns, never a host value carried through.
    fixed: Object.freeze({
      HOME: '/tmp',
      TMPDIR: '/tmp',
      PI_HOME: '/tmp/pi',
      NODE_ENV: 'production',
    }),
  }),
  process: Object.freeze({
    max_processes: 32,
    memory_mb: 256,
    memory_swap_mb: 256,
    timeout_ms: 30_000,
    nano_cpus: 500_000_000,
  }),
  cancellation: Object.freeze({ mode: 'process_tree', on_timeout: 'kill_tree' }),
});

/**
 * The candidate egress set, kept out of the profile on purpose. It is what a
 * profile with `network.policy: 'allowlist'` is allowed to reach, and it is
 * data rather than policy: the two constants are "the model API this host is
 * configured for" and "the ports on it that carry model traffic". Nothing
 * inherits it. A wildcard is absent and cannot be added by a caller without
 * `assertNoWildcard` refusing the profile first.
 */
export const ISOLATION_EGRESS_ALLOWLIST = Object.freeze([
  Object.freeze({ host: 'open.bigmodel.cn', ports: Object.freeze([443]) }),
]);

const HOSTNAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
const SECRET_HANDLE = /^sec-[a-z0-9][a-z0-9-]{0,62}$/;

/**
 * Walk every axis and refuse a wildcard, whatever the tier.
 *
 * The check is on the VALUE `'*'` and it is deliberately not conditioned on the
 * tier. The contract permits `'*'` for `environment.allowlist` on
 * `HOST_UNISOLATED`, and that permission is real — but a wildcard reaching this
 * function means someone is about to LAUNCH with it, and a launch is a
 * different act from a record. `HOST_UNISOLATED` is refused earlier, by
 * `assertExecutableProfile`, with a code that says why; this function then
 * refuses any residual wildcard without needing to know the tier.
 */
export function assertNoWildcard(profile, { path = 'profile' } = {}) {
  const hits = [];
  // Recurses into OBJECTS as well as arrays. The first version of this only
  // walked arrays, so a wildcard in a network allowlist entry —
  // `[{ host: '*', ports: [443] }]` — was never seen, and the negative control
  // that plants exactly that shape reported `refused: false` while the
  // guarantee it was supposed to police went unchecked. A recursive scan that
  // misses the shape the profile actually uses is a scan that misses.
  const scan = (value, where) => {
    if (value === '*') { hits.push(where); return; }
    if (Array.isArray(value)) { value.forEach((item, i) => scan(item, `${where}[${i}]`)); return; }
    if (value && typeof value === 'object') {
      for (const [key, inner] of Object.entries(value)) scan(inner, `${where}.${key}`);
    }
  };
  if (!profile || typeof profile !== 'object') throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:${path}`);
  scan(profile.network?.allowlist, `${path}.network.allowlist`);
  scan(profile.filesystem?.roots, `${path}.filesystem.roots`);
  scan(profile.environment?.allowlist, `${path}.environment.allowlist`);
  scan(profile.environment?.secret_handles, `${path}.environment.secret_handles`);
  scan(profile.environment?.fixed, `${path}.environment.fixed`);
  if (profile.network?.policy === 'unrestricted') hits.push(`${path}.network.policy=unrestricted`);
  if (hits.length > 0) throw new Error(`${PROFILE_ERRORS.WILDCARD_NOT_PERMITTED}:${hits.join(',')}`);
  return true;
}

/**
 * The single gate a profile passes before anything is spawned. Order matters
 * and is the reason the codes are distinct: a caller learns whether the tier is
 * the problem, whether a wildcard is the problem, or whether the shape is.
 */
export function assertExecutableProfile(profile) {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) {
    throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:not-object`);
  }
  if (!EXECUTABLE_TIERS.includes(profile.tier)) {
    throw new Error(`${PROFILE_ERRORS.TIER_NOT_EXECUTABLE}:${String(profile.tier)}`);
  }
  assertNoWildcard(profile);
  const policy = profile.network?.policy;
  if (policy !== 'deny_all' && policy !== 'allowlist') {
    throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:network.policy=${String(policy)}`);
  }
  if (policy === 'deny_all' && (profile.network.allowlist?.length ?? 0) !== 0) {
    throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:deny_all-with-allowlist`);
  }
  if (policy === 'allowlist' && (profile.network.allowlist?.length ?? 0) === 0) {
    throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:allowlist-empty`);
  }
  for (const entry of profile.network.allowlist ?? []) {
    if (!entry || typeof entry.host !== 'string' || !HOSTNAME.test(entry.host)) {
      throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:host=${String(entry?.host)}`);
    }
    if (!Array.isArray(entry.ports) || entry.ports.length === 0) {
      throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:ports=${String(entry?.host)}`);
    }
    for (const port of entry.ports) {
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:port=${String(port)}`);
      }
    }
  }
  if (!Array.isArray(profile.filesystem?.roots) || profile.filesystem.roots.length === 0) {
    throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:filesystem.roots`);
  }
  for (const root of profile.filesystem.roots) {
    if (typeof root !== 'string' || !root.startsWith('/') || root.includes('..')) {
      throw new Error(`${PROFILE_ERRORS.FS_ROOT_INVALID}:${String(root)}`);
    }
  }
  if (profile.filesystem.root_fs_read_only !== true) {
    throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:filesystem.root_fs_read_only`);
  }
  for (const name of profile.environment?.allowlist ?? []) {
    if (typeof name !== 'string' || !ENV_NAME.test(name)) {
      throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:env=${String(name)}`);
    }
  }
  for (const handle of profile.environment?.secret_handles ?? []) {
    assertSecretHandleId(handle);
  }
  const p = profile.process;
  if (!p || !Number.isInteger(p.max_processes) || p.max_processes < 1
    || !Number.isInteger(p.memory_mb) || p.memory_mb < 1
    || !Number.isInteger(p.timeout_ms) || p.timeout_ms < 1) {
    throw new Error(`${PROFILE_ERRORS.PROFILE_MALFORMED}:process`);
  }
  return true;
}

export function assertSecretHandleId(handle) {
  if (typeof handle !== 'string' || !SECRET_HANDLE.test(handle)) {
    throw new Error(`${PROFILE_ERRORS.SECRET_HANDLE_INVALID}:${String(handle)}`);
  }
  return handle;
}

/**
 * The network axis, resolved for one destination. Deny by default is a property
 * of the CODE PATH, not of a flag: nothing consults an allowlist unless the
 * profile asked for `policy: 'allowlist'`, and a destination that is not in the
 * profile's own list is refused even when the policy is `allowlist`.
 *
 * This runs before the container exists, so an out-of-allowlist request costs
 * no process. The OS-level half of the same rule is `--network=none` plus the
 * mounted forwarder, which is what `buildInvocation` assembles; this is the half
 * that stops a caller from asking for the wrong thing at all.
 */
export function resolveEgress(profile, { host, port }) {
  assertExecutableProfile(profile);
  if (profile.network.policy === 'deny_all') {
    return Object.freeze({ allowed: false, reason: 'DENY_ALL', host: String(host), port: Number(port) });
  }
  const hit = profile.network.allowlist.find((entry) => entry.host === host && entry.ports.includes(Number(port)));
  if (!hit) {
    return Object.freeze({
      allowed: false,
      reason: 'NOT_ON_ALLOWLIST',
      code: PROFILE_ERRORS.DESTINATION_NOT_ALLOWLISTED,
      host: String(host),
      port: Number(port),
    });
  }
  return Object.freeze({ allowed: true, reason: 'ON_ALLOWLIST', host, port: Number(port) });
}

/**
 * The environment axis, as a complete list. Returns every `NAME=value` pair the
 * child will see — all of them from `environment.fixed`, which this profile
 * owns as literals. There is no code path that reads `process.env` to build it,
 * which is the property that makes "the host environment is not inherited" a
 * fact about the code rather than a claim about a flag.
 */
export function buildEnvironment(profile) {
  assertExecutableProfile(profile);
  const pairs = [];
  for (const name of profile.environment.allowlist) {
    const value = profile.environment.fixed?.[name];
    if (value === undefined) {
      throw new Error(`${PROFILE_ERRORS.ENV_NOT_ALLOWLISTED}:${name}=UNDEFINED`);
    }
    pairs.push(`${name}=${value}`);
  }
  return Object.freeze(pairs);
}

/** The secret handles a launch may mount: the profile's, and no others. */
export function declaredSecretHandles(profile) {
  assertExecutableProfile(profile);
  return Object.freeze([...profile.environment.secret_handles]);
}
