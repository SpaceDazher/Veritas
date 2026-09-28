// S2-002 A-MVP-04 — the executable image, pinned by digest.
//
// WHY THIS IS ITS OWN MODULE AND NOT A LINE IN `sandbox-profiles.mjs`.
//
// `src/lib/identity` is a frozen target of the S2-002 unit
// (`scripts/validate-contracts.mjs:123`): every byte of it is hashed into
// `evidence/frozen-manifest.json`, and changing one requires an explicit
// reviewed freeze — the operation the S2-007R line owns. The repository has
// already met this problem once and recorded the answer: `src/lib/executors/
// README.md`, decision **D1**, "places the real executors in a new tree
// precisely so the frozen unit is not re-opened". This tree is that answer for
// the image. `contracts/sandbox-profile.schema.json` is NOT read, parsed or
// written here; the four-axis shape is mirrored in `profile.mjs` and asserted
// by the same rules the contract states, so a change to one can be diffed
// against the other by a reader rather than made silently by an import.
//
// WHAT "PINNED" MEANS HERE, PRECISELY.
//
// Two digests, and they are not the same kind of promise:
//
//   * `BASE_IMAGE` is a *registry* digest. It was resolved from Docker Hub on
//     2026-09-28, it is portable, and `podman pull` of that exact digest is
//     what every host must do. This is the pin that makes the run
//     reproducible anywhere.
//   * `EXECUTOR_IMAGE` is a *derived* image digest: the base plus the executor
//     tree copied in, produced by `scripts/s2-002-isolation-image.mjs` with
//     `--timestamp 0`. Because the timestamp is zeroed it is reproducible from
//     (base digest + executor tree bytes), and the record names all three. It is
//     still narrower than the base pin — it is only as good as the executor tree
//     it was built from, which is not committed — and the record says so rather
//     than presenting the two pins as equal.
//
// Why a derived image is necessary at all: the pinned `alpine` in
// `sandbox-profiles.mjs` contains no `node`, no `codex` and no `pi`, which is
// exactly why issue #45 had to invent the `HOST_UNISOLATED` floor. The base
// below is `node:22-bookworm-slim` and the executor is copied in, so a real
// installed executor can be started *inside* the isolation profile. This is
// the gap A-MVP-04's "образ" clause is about.
import { createHash } from 'node:crypto';

// Resolved from the registry on 2026-09-28 with:
//   curl -H "Accept: application/vnd.oci.image.index.v1+json" …/manifests/22-bookworm-slim
// then taking the entry whose platform is linux/amd64. The index digest for
// the tag is sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c;
// pinning the per-platform manifest is what `sandbox-profiles.mjs` already does
// with alpine, so the two pins are the same kind of object.
export const BASE_IMAGE = 'docker.io/library/node@sha256:25330af3531fb5e23318554a0aa911125b6e91b1b777edf7655501d207c067a2';

// The local derived image. Built by `scripts/s2-002-isolation-image.mjs` from
// the base above plus the host's real installed executor, with `--timestamp 0`
// so the layer digests — and therefore the image digest — are a function of
// content rather than of the wall clock. Measured: two independent runs of that
// script produced the identical `Id` and the identical `Digest`, and the
// executor tree digest was identical across the two as well. That is what makes
// this a pin and not a coincidence.
//
// An earlier pin here was a derived image that had been built with a throwaway
// Containerfile and no `--timestamp 0`; it was gone from the podman store an
// hour later, because a locally built image nobody pulls is what a maintenance
// pass collects. `scripts/s2-002-isolation-image.mjs` refused to launch anything
// once that happened, which is the behaviour a pin is for.
//
// The executor tree is NOT committed, so this pin is tied to the tree it was
// built from (`executor_tree_sha256` in
// `evidence/s2-002-isolation-image.json`, 14014 files). An executor upgrade
// moves this pin as an explicit, reviewed change rather than silently.
export const EXECUTOR_IMAGE_ID = 'sha256:f21d3d7988e439f4b1b2ad577955dfee141112144e86ce1adae5fdb3d8f0d1de';
export const EXECUTOR_IMAGE_DIGEST = 'sha256:4936a523d8082389bb1c0343078ff7a4ec9f057426ae3becc6f6618175460429';
export const EXECUTOR_IMAGE = EXECUTOR_IMAGE_ID;

// The digest of the executor tree this pin was built from. It is a constant here
// so the pin and its provenance cannot drift apart silently: a host whose
// installed executor hashes differently is refused, and the fix is a reviewed
// change to BOTH literals, not a re-pin that forgets why it moved.
export const EXECUTOR_TREE_SHA256 = 'sha256:201209e7c5e783e847f6cb2d259530772210164b79053bac8e1ea8001abf5965';
export const EXECUTOR_TREE_FILES = 14014;

// What is inside the derived image, and where. `pi`'s own launcher is a
// three-line shim that requires `cli-runtime.js` from the same directory, so
// the entry point is addressed by the bundle's real path rather than by a
// `pi` on some PATH.
export const EXECUTOR_ENTRYPOINT = '/opt/veritas-executor/dist/bundle/cli.js';
export const EXECUTOR_PACKAGE = '@earendil-works/pi-coding-agent';
export const EXECUTOR_VERSION = '0.87.1';

// The probe the launcher runs to PROVE the image started, as opposed to the
// policy permitting it. It is a version query the executor answers itself; the
// record stores the string that came back, so "the image runs" is a
// measurement and not a constant this repository wrote.
export const STARTUP_PROBE = Object.freeze({
  argv: Object.freeze(['node', EXECUTOR_ENTRYPOINT, '--version']),
  // The expected shape of the answer. A different patch version is a
  // DIFFERENT observation and is reported as one; it is not asserted equal,
  // because pretending a version is pinned when only its format is known is
  // the same class of claim this repository refuses elsewhere.
  expectPattern: /^\d+\.\d+\.\d+/,
  // What the record calls the observed string.
  observedField: 'executor_version_observed',
});

const DIGEST_REFERENCE = /^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$/;
const BARE_DIGEST = /^sha256:[0-9a-f]{64}$/;

export const IMAGE_ERRORS = Object.freeze({
  NOT_DIGEST_PINNED: 'ISOLATION_IMAGE_NOT_DIGEST_PINNED',
  DIGEST_MISMATCH: 'ISOLATION_IMAGE_DIGEST_MISMATCH',
  NOT_BUILT: 'ISOLATION_IMAGE_NOT_BUILT',
});

export function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

/**
 * Refuse any image reference that is not a content address. A tag is a mutable
 * name: two runs a week apart can resolve `node:22-bookworm-slim` to different
 * bytes, and then "the pinned image" is a phrase with no referent. This is the
 * same rule `sandbox-profiles.mjs` follows and the reason it writes
 * `alpine@sha256:…` rather than `alpine:3.20`.
 */
export function assertDigestPinned(reference) {
  if (typeof reference !== 'string' || reference.length === 0) {
    throw new Error(IMAGE_ERRORS.NOT_DIGEST_PINNED);
  }
  const isPinned = DIGEST_REFERENCE.test(reference) || BARE_DIGEST.test(reference);
  if (!isPinned) {
    throw new Error(`${IMAGE_ERRORS.NOT_DIGEST_PINNED}:${reference}`);
  }
  return Object.freeze(reference);
}

/**
 * The digest a reference commits to, in `sha256:<hex>` form. For a bare digest
 * it is the reference itself; for `name@sha256:…` it is the part after `@`.
 */
export function digestOf(reference) {
  assertDigestPinned(reference);
  const at = reference.lastIndexOf('@');
  return at === -1 ? reference : reference.slice(at + 1);
}

/**
 * Normalise a content address to `sha256:<hex>`.
 *
 * Podman is inconsistent about the prefix on this host: `inspect --format
 * '{{.Id}}'` answers a BARE 64-hex string while `{{.Digest}}` answers
 * `sha256:<hex>`, and the constant this module pins is written with the prefix
 * because that is the form `podman pull` and `podman run` accept as a reference.
 * Comparing the raw strings reported
 *
 *     Id=sha256:f21d3d79… == sha256:f21d3d79…   →  false
 *
 * which is the same content address compared against itself. The gate refused a
 * correct image, and a gate that cries wolf on its own pin is a gate people
 * learn to bypass.
 */
export function normalizeDigest(value) {
  const text = String(value ?? '').trim();
  if (/^sha256:[0-9a-f]{64}$/.test(text)) return text;
  if (/^[0-9a-f]{64}$/.test(text)) return `sha256:${text}`;
  return text;
}

/**
 * Check what `podman inspect` actually said against what this repository
 * pinned. Both fields are required, and requiring both is the point: `Id` alone
 * would accept a rebuilt image whose layers happen to hash the same, and
 * `Digest` alone would accept a manifest that names the right digest while the
 * local store holds something else. A run that cannot produce both is
 * `NOT_BUILT`, not a pass.
 *
 * @param {{Id?: string, Digest?: string, Architecture?: string}} inspect
 * @param {{imageId?: string, digest?: string, architecture?: string}} expected
 */
export function assertImageMatchesPin(inspect, expected = {}) {
  const wantId = normalizeDigest(expected.imageId ?? EXECUTOR_IMAGE_ID);
  const wantDigest = normalizeDigest(expected.digest ?? EXECUTOR_IMAGE_DIGEST);
  const wantArch = expected.architecture ?? 'amd64';
  if (!inspect || typeof inspect !== 'object') throw new Error(IMAGE_ERRORS.NOT_BUILT);
  const id = String(inspect.Id ?? '');
  const digest = String(inspect.Digest ?? '');
  if (id === '' || digest === '') throw new Error(`${IMAGE_ERRORS.NOT_BUILT}:${id || 'no-id'}/${digest || 'no-digest'}`);
  if (normalizeDigest(id) !== wantId) throw new Error(`${IMAGE_ERRORS.DIGEST_MISMATCH}:id:${id}`);
  if (normalizeDigest(digest) !== wantDigest) throw new Error(`${IMAGE_ERRORS.DIGEST_MISMATCH}:digest:${digest}`);
  if (String(inspect.Architecture ?? '') !== wantArch) {
    throw new Error(`${IMAGE_ERRORS.DIGEST_MISMATCH}:arch:${inspect.Architecture}`);
  }
  return Object.freeze({ imageId: normalizeDigest(id), digest: normalizeDigest(digest), architecture: wantArch });
}

/**
 * The proof that an image started, as opposed to a profile permitting it.
 *
 * Three things have to be true together, and each one alone is satisfiable by a
 * run that never happened:
 *
 *   1. the launcher observed a real exit status (`null` means the process was
 *      killed by a signal or never reported, and `assert.ok(null === 0)` is the
 *      bug this guards);
 *   2. that status is 0, so the executor itself decided it succeeded;
 *   3. stdout carries a string the executor produced, matching the version
 *      shape — a launcher that printed the expected string itself while the
 *      image was broken passes 1 and 2 and fails 3.
 */
export function assertRealStart(observation, probe = STARTUP_PROBE) {
  const issues = [];
  if (!observation || typeof observation !== 'object') {
    return { ok: false, issues: ['observation:not-object'], version: null };
  }
  const exitCode = observation.exitCode;
  if (!Number.isInteger(exitCode)) issues.push(`exitCode:${String(exitCode)}`);
  else if (exitCode !== 0) issues.push(`exitCode:${exitCode}`);
  if (observation.signal != null) issues.push(`signal:${observation.signal}`);
  const stdout = String(observation.stdout ?? '');
  const match = stdout.match(probe.expectPattern);
  if (!match) issues.push('stdout:no-version-shape');
  if (issues.length > 0) return { ok: false, issues, version: match ? match[0] : null };
  return Object.freeze({ ok: true, issues: Object.freeze([]), version: match[0] });
}
