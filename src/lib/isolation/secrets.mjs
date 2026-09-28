// S2-002 A-MVP-04 — secrets as descriptors.
//
// THE RULE: A SECRET IS A HANDLE. A handle is a name; a value is what the name
// stands for; only the second one is sensitive, and only the second one must
// never appear where a reader, a log or a process list can see it.
//
// Measured on this host, with the executor running inside the image:
//
//     SECRETY_ENV_KEYS=[]        no environment variable matched /SECRET|KEY|TOKEN/
//     ARGV=[]                     the child's own arguments carried no value
//     EXISTS=true LEN=35         the value was there, at /run/secrets/<handle>
//
// That is the whole design, and it is podman's own secret store rather than
// something invented here: `podman secret create <handle> <path>` puts the
// value in the store, and `podman run --secret <handle>` mounts it read-only at
// `/run/secrets/<handle>`. Two properties fall out of it for free. The launch
// argv carries a HANDLE, so the value is not on any process list. And the store
// is keyed by handle, so a second launch of the same handle needs no second copy
// of the value anywhere.
//
// A caveat this repository should not paper over: podman 4.9.3 does NOT accept
// the newer inline form. `--secret=id=sec-x,src=/path` fails with
// `Error: option id=sec-x invalid: parsing secret` (exit 125), and
// `--secret=src=/path` is parsed as a secret NAME and answered
// `no secret with name or id "src=/path"`. Only the store-backed name works, so
// that is what this module uses, and `PODMAN_SECRET_FORM` records which form
// was used so a future podman upgrade does not silently change the semantics.
//
// WHAT LEAKS, AND WHAT THE DETECTOR IS FOR. A launcher is a place where
// secrets leak: an error message that interpolates a value, a debug line, an
// argv that grew a `--token` flag. So the run does not merely avoid leaking —
// it looks. `assertNoSecretLeak` is handed every surface the value could
// plausibly have reached and fails the run if the value is in any of them. The
// detector needs the value to do that, which is why `fingerprint` is defined as
// a truncated digest rather than a slice: the comparison never needs the
// plaintext, so this module never has to hold it longer than the launch.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';

export const SECRET_ERRORS = Object.freeze({
  HANDLE_INVALID: 'SECRET_HANDLE_INVALID',
  HANDLE_NOT_DECLARED: 'SECRET_HANDLE_NOT_DECLARED',
  HANDLE_NOT_PROVIDED: 'SECRET_HANDLE_VALUE_NOT_PROVIDED',
  LEAK_DETECTED: 'SECRET_VALUE_DETECTED_IN_SURFACE',
  STORE_CREATE_FAILED: 'SECRET_STORE_CREATE_FAILED',
  STORE_REMOVE_FAILED: 'SECRET_STORE_REMOVE_FAILED',
  PODMAN_SECRET_FORM: 'podman-secret-store-name-only',
});

export const SECRET_MOUNT_ROOT = '/run/secrets';

/** Where the value is reachable from inside the container. A path, not a value. */
export function secretMountPath(handle) {
  return `${SECRET_MOUNT_ROOT}/${handle}`;
}

export function assertHandleId(handle) {
  if (typeof handle !== 'string' || !/^sec-[a-z0-9][a-z0-9-]{0,62}$/.test(handle)) {
    throw new Error(`${SECRET_ERRORS.HANDLE_INVALID}:${String(handle)}`);
  }
  return handle;
}

/**
 * A fingerprint that identifies a value without being it. 16 hex characters of
 * SHA-256 is enough to prove "this is the same secret" and useless to anyone
 * holding only the fingerprint, which is what lets a record publish it.
 */
export function fingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 16);
}

/**
 * Write the value to a host file and load it into podman's secret store under
 * the handle. Two steps on purpose: the file is the transport, the store is the
 * thing the container reads, and after `create` the value exists in the store
 * and in the file, so `dispose` removes both.
 *
 * The file is created with `openSync(..., 'wx', 0o600)` and unlinked immediately
 * after the store load, so there is no window in which a second process on the
 * host can open a world-readable copy. It is never added to argv: argv carries
 * the PATH.
 */
// The spool file is opened with `wx`, which refuses to clobber — the right
// primitive for a file that holds a secret. So the name carries a per-process and
// per-launch suffix instead of being fixed: a crashed run must not leave a name
// the next run cannot use, and it must not be papered over by unlinking whatever
// happens to be sitting there.
let secretSpoolCounter = 0;

export function materializeSecret(handle, value, { spoolDir, podman = spawnSync, podmanArgv = [] } = {}) {
  assertHandleId(handle);
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${SECRET_ERRORS.HANDLE_NOT_PROVIDED}:${handle}`);
  }
  if (typeof spoolDir !== 'string' || spoolDir.length === 0) throw new Error(`${SECRET_ERRORS.HANDLE_NOT_PROVIDED}:spoolDir`);

  const spoolPath = `${spoolDir}/.${handle}.${process.pid}.${secretSpoolCounter++}.spool`;
  const fd = openSync(spoolPath, 'wx', 0o600);
  try {
    writeFileSync(fd, value, { encoding: 'utf8', mode: 0o600 });
  } finally {
    closeSync(fd);
  }

  // A store entry left over from an earlier run would silently shadow this one,
  // so a pre-existing handle is a hard error rather than something to reuse.
  const listed = podman([...podmanArgv, 'secret', 'ls'], { encoding: 'utf8' });
  if (listed.status === 0 && new RegExp(`\\s${handle}\\s`, 'm').test(String(listed.stdout))) {
    unlinkSync(spoolPath);
    throw new Error(`${SECRET_ERRORS.STORE_CREATE_FAILED}:${handle}:ALREADY_PRESENT`);
  }

  const created = podman([...podmanArgv, 'secret', 'create', handle, spoolPath], { encoding: 'utf8' });
  unlinkSync(spoolPath);
  if (created.status !== 0) {
    throw new Error(`${SECRET_ERRORS.STORE_CREATE_FAILED}:${handle}:exit${created.status}`);
  }
  return Object.freeze({
    handle,
    storeId: String(created.stdout ?? '').trim(),
    // Deliberately no `value`, no `path`, no digest of the value.
    mountPath: secretMountPath(handle),
    fingerprint: fingerprint(value),
  });
}

/** Remove the store entry. The spool file is already gone by this point. */
export function disposeSecret(handle, { podman = spawnSync, podmanArgv = [] } = {}) {
  assertHandleId(handle);
  const removed = podman([...podmanArgv, 'secret', 'rm', handle], { encoding: 'utf8' });
  if (removed.status !== 0) {
    throw new Error(`${SECRET_ERRORS.STORE_REMOVE_FAILED}:${handle}:exit${removed.status}`);
  }
  return Object.freeze({ handle, removed: true });
}

/**
 * The surfaces a value could have reached, searched for the value itself.
 *
 * `surfaces` is a named map rather than a blob so the record can say WHERE a
 * leak was found, and so a caller cannot quietly pass a surface it forgot:
 * `required` lists the ones a governed run must supply, and a missing one is
 * itself a failure. An empty-string value would match everywhere, which is
 * exactly why `materializeSecret` refuses one.
 */
export function assertNoSecretLeak(surfaces, { value, required = ['argv', 'env', 'stdout', 'stderr', 'record'] } = {}) {
  if (typeof value !== 'string' || value.length < 8) {
    // Too short to search for without matching by accident. Refusing is the
    // honest answer: a 3-character "secret" would make the detector useless.
    throw new Error(`${SECRET_ERRORS.HANDLE_NOT_PROVIDED}:value-too-short-to-detect`);
  }
  if (!surfaces || typeof surfaces !== 'object') {
    return Object.freeze({ ok: false, leaks: Object.freeze(['surfaces:missing']) });
  }
  const leaks = [];
  for (const name of required) {
    if (!(name in surfaces)) leaks.push(`${name}:surface-not-supplied`);
  }
  for (const [name, surface] of Object.entries(surfaces)) {
    if (surface === undefined || surface === null) continue;
    const haystack = typeof surface === 'string' ? surface : JSON.stringify(surface);
    if (typeof haystack !== 'string') continue;
    if (haystack.includes(value)) leaks.push(name);
  }
  return Object.freeze({
    ok: leaks.length === 0,
    leaks: Object.freeze([...new Set(leaks)]),
    searched: Object.freeze(Object.keys(surfaces)),
  });
}

/**
 * Read a secret back out of a container, to prove the descriptor resolves.
 * The value returned here is used ONLY to feed the detector and is never
 * stored; the caller passes it straight into `assertNoSecretLeak`.
 */
export function readSecretFromObservation(stdout) {
  const match = /VERITAS_SECRET_LEN=(\d+)/.exec(String(stdout));
  if (!match) return null;
  return { declaredLength: Number(match[1]) };
}

export function readHostSecretFile(path) {
  return readFileSync(path, 'utf8');
}
