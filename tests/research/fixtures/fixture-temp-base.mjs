// The TEMP BASE: one directory per (label, step), purged before the run that
// uses it, and a purge that cannot reach anything it does not own.
//
// WHAT THIS IS: the filesystem half of the fixture set — create a scratch base
// under an INJECTED parent, write fixture files into it, remove exactly what
// this run created. It is the file-based counterpart of `purgeProbeFixtures`
// (src/lib/agentboard/probes.mjs:172) and of `purgeRegistry`
// (src/lib/research/registry.mjs).
//
// WHY A PURGE AT ALL
// Without it, a repeat run on a permanent base fails on its own leftovers
// instead of on the property: the second run would trip over a lock file, a
// journal or a half-written record from the first one, and the result would say
// nothing about the harness. The ticket's A5 ("survives a repeat run on the
// same base") is only meaningful when each run starts from a known state.
//
// WHY THE PURGE IS BOUNDED THREE WAYS
//   1. a base is `<parent>/<label>/<step>` and `label` / `step` must match
//      `[a-z0-9][a-z0-9-]{0,31}`, which makes `..`, an absolute path and a path
//      separator unreachable through the arguments;
//   2. the resolved base must be a STRICT DESCENDANT of the injected parent, so
//      even a surprising argument cannot escape upward;
//   3. an existing base is only ever purged when it carries this module's
//      MARKER, whose content must match the label and step being purged — a
//      directory this code cannot prove it created is refused, not removed.
// The board precedent's own comment is the reason for (3): an operator's data
// must survive a fixture run, and a purge that deletes what it cannot identify
// is how that data dies.
//
// NOTHING WRITTEN HERE IS TIME- OR RANDOM-DEPENDENT
// The marker carries no timestamp and no random suffix, so two processes that
// create the same base produce byte-identical bytes, and a test can assert the
// purge left the base exactly as the fixture declares. `mkdtemp` is
// deliberately NOT used: a random directory name would make the base
// unreproducible and would defeat the point of a deterministic id scheme.
//
// Serves: A5 (repeat-run survival) and the harness-phase requirement that a
// fixture be purged before the run that uses it.
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { fixtureDigest } from './fixture-digest.mjs';

/** The marker file that proves a directory belongs to this fixture set. @type {string} */
export const TEMP_BASE_MARKER_NAME = '.s2-008-fixture-base.json';

/** The kind string the marker must carry. Bump it if the marker's shape changes. @type {string} */
export const TEMP_BASE_KIND = 's2-008-fixture-base/1';

/** The segment pattern a label or step must match. Keeps `..` and separators out by construction. @type {RegExp} */
export const BASE_SEGMENT_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** The name pattern a file written inside a base must match. No separators, no `..`. @type {RegExp} */
export const BASE_FILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * The default parent for fixture scratch space, resolved at CALL time from this
 * module's own location — never a host path written into the source, which is
 * what would make a fixture machine-specific. It points at the repository's
 * `results/s2-008/fixtures/`, the scratch root the fixtures README reserves and
 * the plan assigns to delivery for `.gitignore`. `results/s2-008/` is NOT
 * gitignored yet; that entry is D's to add (plan §2), and it is reported rather
 * than worked around by writing somewhere else.
 * @returns {string} An absolute path.
 */
export function defaultTempBaseParent() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../results/s2-008/fixtures');
}

/**
 * The canonical-JSON marker of a base: no timestamp, no pid, no host path, so
 * the same (label, step) always produces the same bytes.
 * @param {{label: string, step: string}} args
 * @returns {object} The marker document.
 */
function markerFor({ label, step }) {
  return {
    kind: TEMP_BASE_KIND,
    label,
    step,
    owner: 'tests/research/fixtures/fixture-temp-base.mjs',
    // Written into the marker so a human who finds the directory knows what may
    // be deleted from it and what must not.
    rule: 'scratch for one S2-008 fixture run; purged before the run that uses it; nothing outside this base is ever touched',
    digest_placeholder: null,
  };
}

function assertSegment(value, field) {
  if (typeof value !== 'string' || !BASE_SEGMENT_PATTERN.test(value)) {
    throw new Error(`FIXTURE_BASE_SEGMENT_INVALID: ${field} must match ${BASE_SEGMENT_PATTERN.source}, got ${String(value)}`);
  }
  return value;
}

/**
 * Assert `candidate` is a STRICT DESCENDANT of `base`. `base` itself is not a
 * descendant of itself, which is deliberate: a caller that passes the injected
 * parent as the target has made a mistake, and the check says so instead of
 * emptying the operator's whole scratch root.
 * @param {string} candidate The resolved path to test.
 * @param {string} base The resolved directory that must contain it.
 * @returns {string} `candidate`, unchanged, when it is strictly inside `base`.
 * @throws {Error} `FIXTURE_PATH_ESCAPE` when it is not.
 */
export function assertStrictlyInside(candidate, base) {
  const relative = path.relative(path.resolve(base), path.resolve(candidate));
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`FIXTURE_PATH_ESCAPE: ${String(candidate)} is not strictly inside ${String(base)}`);
  }
  return candidate;
}

/**
 * Remove EVERYTHING inside a base and nothing else. Never removes the base
 * directory itself, never walks upward, and never follows a symlink out: a
 * symlink is unlinked rather than recursed into, so a link planted inside the
 * base cannot turn a purge into a deletion elsewhere on the disk.
 *
 * Idempotent in the two senses that matter: purging a base that does not exist
 * is a no-op that says so, and purging an already-purged base removes nothing,
 * changes nothing and leaves the MARKER — the only entry that survives every
 * purge, because it is the base's own identity rather than a run's fixture.
 * @param {string} base The base directory.
 * @param {{parent?: string, dryRun?: boolean}} [args]
 * @param {string} [args.parent] The injected parent; when given, the base must
 *   be strictly inside it.
 * @param {boolean} [args.dryRun] Report what would be removed without removing.
 * @returns {{purged: boolean, changed: boolean, removed: string[], base: string, reason: string|null}}
 * @throws {Error} `FIXTURE_PATH_ESCAPE` when the base escapes `parent`;
 *   `FIXTURE_BASE_NOT_OWNED` when an existing base has no matching marker — an
 *   existing directory this code cannot identify is refused, never removed.
 */
export function purgeTempBase(base, { parent, dryRun = false } = {}) {
  const resolved = path.resolve(base);
  if (parent !== undefined) assertStrictlyInside(resolved, parent);
  if (!existsSync(resolved)) {
    return { purged: true, changed: false, removed: [], base: resolved, reason: 'ABSENT_ALREADY_CLEAN' };
  }
  const markerPath = path.join(resolved, TEMP_BASE_MARKER_NAME);
  if (!existsSync(markerPath)) {
    throw new Error(`FIXTURE_BASE_NOT_OWNED: ${resolved} exists without ${TEMP_BASE_MARKER_NAME}; refusing to remove a directory this fixture set did not create`);
  }
  let marker;
  try {
    marker = JSON.parse(readFileSync(markerPath, 'utf8'));
  } catch (cause) {
    throw new Error(`FIXTURE_BASE_NOT_OWNED: ${resolved} has an unreadable marker (${String(cause && cause.message)})`);
  }
  if (marker.kind !== TEMP_BASE_KIND) {
    throw new Error(`FIXTURE_BASE_NOT_OWNED: ${resolved} has marker kind ${String(marker.kind)}, expected ${TEMP_BASE_KIND}`);
  }
  // The base's own name must agree with the marker: a marker copied from another
  // base must not authorise removing this one.
  const expectedStep = path.basename(resolved);
  const expectedLabel = path.basename(path.dirname(resolved));
  if (marker.step !== expectedStep || marker.label !== expectedLabel) {
    throw new Error(`FIXTURE_BASE_NOT_OWNED: ${resolved} carries the marker of ${String(marker.label)}/${String(marker.step)}`);
  }
  const removed = [];
  for (const entry of sortedDirents(resolved)) {
    // The marker is the base's OWN identity file, not one of this run's
    // fixtures. It is neither removed nor listed, which is what makes a second
    // purge an observable no-op rather than a purge that reports having removed
    // the evidence that it ran at all.
    if (entry.name === TEMP_BASE_MARKER_NAME) continue;
    removed.push(entry.name);
    if (dryRun) continue;
    const target = path.join(resolved, entry.name);
    if (entry.isSymbolicLink) unlinkSync(target);
    else rmSync(target, { recursive: true, force: false });
  }
  // The marker is rewritten rather than left to chance, so a base is always in
  // the same state and its digest is stable across processes.
  if (!dryRun) writeFileSync(markerPath, `${JSON.stringify(marker)}\n`, 'utf8');
  return { purged: true, changed: removed.length > 0, removed, base: resolved, reason: null };
}

/**
 * Directory entries in a stable order, using lstat so a symlink is reported as
 * a symlink. Sorted because a purge that reports its removals in filesystem
 * order would produce a different report on a different host.
 * @param {string} dir The directory to list.
 * @returns {ReadonlyArray<{name: string, isSymbolicLink: boolean}>}
 */
function sortedDirents(dir) {
  // `lstatSync` rather than `withFileTypes`: this is the one place a symlink
  // could be followed out of the base, and deciding it in one visible line
  // makes it auditable. Sorted because a purge reporting its removals in
  // filesystem order would produce a different report on a different host.
  return readdirSync(dir)
    .sort()
    .map((name) => ({ name, isSymbolicLink: lstatSync(path.join(dir, name)).isSymbolicLink() }));
}

/**
 * Create (or reuse) the base for one (label, step) under an injected parent,
 * purging it FIRST so the run starts from a known state. A repeat run therefore
 * fails on the property under test and not on a leftover from the last one.
 *
 * Refuses to adopt an existing directory that lacks a matching marker: reusing
 * an unowned directory is how a fixture run starts writing into somebody
 * else's files.
 * @param {{parent?: string, label: string, step: string, create?: boolean}} args
 * @param {string} [args.parent] The injected parent; defaults to
 *   `defaultTempBaseParent()`. Pass `mkdtemp`-style scratch explicitly rather
 *   than relying on the default when a test wants an isolated tree.
 * @param {string} args.label A member of the run labels, e.g. 'a'.
 * @param {string} args.step The step within the run, e.g. 'probe'.
 * @param {boolean} [args.create] Set false to purge without re-creating.
 * @returns {{base: string, parent: string, label: string, step: string, purged: object, created: boolean}}
 * @throws {Error} `FIXTURE_BASE_SEGMENT_INVALID`; `FIXTURE_PATH_ESCAPE` when
 *   the resolved base is not strictly inside the parent;
 *   `FIXTURE_BASE_NOT_OWNED` when an existing base carries no matching marker.
 */
export function createTempBase({ parent = defaultTempBaseParent(), label, step, create = true } = {}) {
  assertSegment(label, 'label');
  assertSegment(step, 'step');
  const resolvedParent = path.resolve(parent);
  const base = path.join(resolvedParent, label, step);
  assertStrictlyInside(base, resolvedParent);
  const purged = purgeTempBase(base, { parent: resolvedParent });
  if (!create) return { base, parent: resolvedParent, label, step, purged, created: false };
  mkdirSync(base, { recursive: true });
  const marker = markerFor({ label, step });
  writeFileSync(path.join(base, TEMP_BASE_MARKER_NAME), `${JSON.stringify(marker)}\n`, 'utf8');
  return { base, parent: resolvedParent, label, step, purged, created: true };
}

/**
 * Write one file inside a base. The name may not contain a separator, so
 * `writeTempFile(base, '../escape', …)` is a thrown error rather than a write
 * outside the base.
 * @param {string} base The base directory.
 * @param {string} name The file name.
 * @param {string} contents The exact bytes to write.
 * @returns {string} The absolute path written.
 * @throws {Error} `FIXTURE_FILE_NAME_INVALID`; `FIXTURE_PATH_ESCAPE` when the
 *   resolved path is not strictly inside the base.
 */
export function writeTempFile(base, name, contents) {
  if (typeof name !== 'string' || !BASE_FILE_PATTERN.test(name)) {
    throw new Error(`FIXTURE_FILE_NAME_INVALID: name must match ${BASE_FILE_PATTERN.source}, got ${String(name)}`);
  }
  const target = path.join(path.resolve(base), name);
  assertStrictlyInside(target, base);
  if (typeof contents !== 'string') throw new Error('FIXTURE_FILE_CONTENT_INVALID: contents must be a string');
  writeFileSync(target, contents, 'utf8');
  return target;
}

/**
 * Read one file from inside a base, with the same name rules as
 * `writeTempFile`.
 * @param {string} base The base directory.
 * @param {string} name The file name.
 * @returns {string} The file's exact contents.
 * @throws {Error} `FIXTURE_FILE_NAME_INVALID`; `FIXTURE_PATH_ESCAPE`; the
 *   underlying fs error when the file does not exist.
 */
export function readTempFile(base, name) {
  if (typeof name !== 'string' || !BASE_FILE_PATTERN.test(name)) {
    throw new Error(`FIXTURE_FILE_NAME_INVALID: name must match ${BASE_FILE_PATTERN.source}, got ${String(name)}`);
  }
  const target = path.join(path.resolve(base), name);
  assertStrictlyInside(target, base);
  return readFileSync(target, 'utf8');
}

/**
 * The list of entries inside a base, marker included, in stable order. Exposed
 * so a test can assert a purge left NOTHING behind without reaching into fs.
 * @param {string} base The base directory.
 * @returns {ReadonlyArray<string>} Sorted entry names, or `[]` when the base is absent.
 */
export function listTempBase(base) {
  const resolved = path.resolve(base);
  if (!existsSync(resolved)) return [];
  return sortedDirents(resolved).map((entry) => entry.name);
}

/**
 * The digest of a base's marker, so a test can assert the marker is the same
 * bytes in every process. A marker that varied per process would make
 * "byte-identical fixtures" unprovable for the one file that touches disk.
 * @param {{label: string, step: string}} args
 * @returns {string} `sha256:<64 hex>` over the marker document.
 */
export function tempBaseMarkerDigest({ label, step } = {}) {
  assertSegment(label, 'label');
  assertSegment(step, 'step');
  return fixtureDigest(markerFor({ label, step }));
}
