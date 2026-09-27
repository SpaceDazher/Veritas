#!/usr/bin/env node
// S2-008 — THE DEPENDENCY BINDING GATE (issue SpaceDazher/Veritas#8, A5).
//
// WHAT IT CHECKS, AND WHY EACH ONE IS A DEPENDENCY AND NOT A BOOKKEEPING ENTRY
//   1. THE THREE FROZEN CONTRACTS. `contracts/hypothesis-card.schema.json`,
//      `contracts/research-dossier.schema.json` and
//      `contracts/calibration-record.schema.json` are the ONLY validation
//      surface of the track. Their SHA-256 is read from
//      `evidence/frozen-manifest.json` and compared against the bytes at the
//      pinned commit AND against the working tree. A contract that moved is the
//      end of the track's provability: every "the schema refused it" claim would
//      be about a schema that is no longer the one the evidence names.
//   2. NO S2-008 FILE IN A FROZEN TARGET. Every path the frozen manifest pins is
//      re-read from Git; any working-tree drift, and any UNTRACKED file under a
//      frozen tree, is a finding. This is also where the track's own untracked
//      state becomes visible, because `git ls-files` cannot see a file nobody
//      added — a gate that cannot distinguish "absent" from "bound to a base"
//      reports both as green.
//   3. THE FIVE DEPENDENCY BINDINGS THE ISSUE NAMES: S2-002, S2-006, S2-007,
//      S1-004 and S1-011. Each is bound to CANONICAL EVIDENCE, read from Git
//      bytes, never from a narrative in this file.
//   4. MODULE REACHABILITY. Every module of `src/lib/research/` is imported by
//      something else in the track (or by a committed script), and the public
//      barrel re-exports the frozen names. An unreachable module is a module
//      nobody can be shown to run.
//   5. EVIDENCE PRESENCE. Every artefact this track names exists and is
//      readable. Absence is recorded as absence, never as agreement.
//
//   6. THE WHOLE TRACK, NAMED. `frozen_targets` publishes the three views a
//      reader needs to judge provability: `track_files_expected` (the track's
//      file set, walked from the WORKING TREE), `track_files_tracked` (what
//      `git ls-files` reports) and `track_files_untracked` /
//      `track_files_modified` (the two `git status` views). Before this round
//      only the first two existed, and the aggregator read `track_files_tracked
//      === 0` — so a track with 24 of its 57 files still tracked looked proved
//      while the dependency gate itself was naming 33 untracked files that
//      nothing downstream could see. Provability is a property of the WHOLE
//      track, and this gate now publishes the whole track.
//
// BOOTSTRAP ORDERING: `--chain-produced <paths>`
//   `scripts/verify-s2-008.mjs` spawns THIS GATE (its step 1) BEFORE it spawns
//   the replay (its step 3) that writes `evidence/s2-008-replay.json`, while
//   this gate listed that record as REQUIRED. The first chain run on a clean
//   base was therefore red for the existence of a file the chain had not
//   written yet — reproduced with `rm -f evidence/s2-008-replay.json && node
//   scripts/verify-s2-008.mjs --no-write` -> exit 1, defect
//   `evidence-absent:evidence/s2-008-replay.json`, and exit 0 from the second
//   run on. That is not a false green (the chain owns the presence of the
//   records it wrote, and the chain is what checks that), but a gate that is
//   red on a clean base is a gate whose first answer is about ORDERING.
//
//   The chain therefore passes `--chain-produced <comma-separated paths>`
//   (repeatable), and with it those paths are excluded from REQUIRED: they are
//   still READ, still reported with their presence, their byte count and the
//   reason they were excluded, and the aggregator owns whether they exist.
//   WITHOUT the flag the behaviour is byte-for-byte what it was, so
//   `npm run verify:s2-008-dependencies` keeps its contract. A path this gate
//   does not know is a NAMED ISSUE, not a silent exclusion: the flag can only
//   cover this track's own evidence, never an arbitrary path.
//
//   node scripts/verify-s2-008-dependencies.mjs
//   node scripts/verify-s2-008-dependencies.mjs --print-record
//   node scripts/verify-s2-008-dependencies.mjs --chain-produced evidence/s2-008-replay.json
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { parseArgs } from './s2-008-run.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT_RELATIVE = 'evidence/s2-008-dependency-binding.json';
const FROZEN_MANIFEST = 'evidence/frozen-manifest.json';
const ROOT_MANIFEST = 'evidence/root-manifest.json';
const GIT_OBJECT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SHA256 = /^[0-9a-f]{64}$/;

/** The three frozen S2-008 contracts, with the digests the issue pins. */
const FROZEN_CONTRACTS = Object.freeze([
  Object.freeze({ id: 'hypothesis-card', path: 'contracts/hypothesis-card.schema.json', digest: '43b9c81620737b81a589d8e1577b0dc89e8b19fe1ed011edb3514f893b141e97' }),
  Object.freeze({ id: 'research-dossier', path: 'contracts/research-dossier.schema.json', digest: 'fdffd1c0a75f0483a5ab7244ed5463a9786fec4c23daaae8c7b5242167183773' }),
  Object.freeze({ id: 'calibration-record', path: 'contracts/calibration-record.schema.json', digest: '8c7507ebe2f216a46f4c70f7a43e4713ef84f85ac0c14d97e550f953f1b7408d' }),
]);

/** The five dependency bindings the issue records, and the canonical artefact
 *  each one is bound to. A binding with no canonical artefact is reported as
 *  `NOT_BOUND` — never quietly treated as satisfied. */
const DEPENDENCY_BINDINGS = Object.freeze([
  Object.freeze({ id: 'S2-002', artefact: 'evidence/s2-002-dependency-binding.json', kind: 'record' }),
  Object.freeze({ id: 'S2-006', artefact: 'evidence/s2-006-dependency-binding.json', kind: 'record' }),
  Object.freeze({ id: 'S2-007', artefact: 'evidence/s2-007-dependency-binding.json', kind: 'record' }),
  Object.freeze({ id: 'S1-004', artefact: 'docs/stages/stage-1.md', kind: 'documentary' }),
  Object.freeze({ id: 'S1-011', artefact: 'evidence/external/s1-011/evaluation-record.json', kind: 'record' }),
]);

/** The track's scope, as ONE pattern. `git ls-files`, the working-tree walk
 *  and every filter below read the same regex, so "this track's files" is one
 *  definition rather than three that can drift apart. */
const TRACK_PATH = /^(src\/lib\/research\/|tests\/research\/|scripts\/s2-008-|scripts\/verify-s2-008|evidence\/s2-008)/;

/** The roots the working-tree walk reads. `evidence` is walked ONE level deep
 *  on purpose: the track's own records (`evidence/s2-008-*.json`) sit BESIDE
 *  the corpus directory, while `evidence/` also holds every other stage's
 *  evidence and `evidence/external/` a tree of downloaded records. */
const TRACK_WALK_ROOTS = Object.freeze([
  Object.freeze({ rel: 'src/lib/research', deep: true }),
  Object.freeze({ rel: 'tests/research', deep: true }),
  Object.freeze({ rel: 'scripts', deep: true }),
  Object.freeze({ rel: 'evidence/s2-008', deep: true }),
  Object.freeze({ rel: 'evidence', deep: false }),
]);

/** The evidence this gate requires, and the evidence it only reports. Frozen
 *  so the chain's `--chain-produced` flag can be checked against ONE list. */
const REQUIRED_EVIDENCE = Object.freeze([
  'evidence/s2-008-probes.json',
  'evidence/s2-008-controls.json',
  'evidence/s2-008-comparison.json',
  'evidence/s2-008-security-probes.json',
  'evidence/s2-008-run-a.json',
  'evidence/s2-008-run-b.json',
  'evidence/s2-008-replay.json',
  'evidence/s2-008/corpus/manifest.json',
  'evidence/s2-008/corpus/preregistration.json',
]);
const OPTIONAL_EVIDENCE = Object.freeze([
  'evidence/s2-008-summary.json',
  'evidence/s2-008-harness.json',
  'evidence/s2-008-negative-controls.json',
]);
/** Why an excluded path is excluded, in the record, in the same words a
 *  reader needs: the chain that spawned this gate writes the record in the
 *  SAME run and AFTER this gate, and the chain is what checks it exists. */
const CHAIN_PRODUCED_REASON = 'excluded from REQUIRED by --chain-produced: the chain that spawned this gate (scripts/verify-s2-008.mjs) runs this gate BEFORE it spawns the child that writes this record, so requiring it here makes the FIRST run on a clean base red for a file the chain had not written yet. The record is still read and still reported, and the aggregator owns its presence and its bytes.';

/** The records the SPAWNING CHAIN writes in the same run, after this gate.
 *
 *  The list is FROZEN here rather than taken from the caller, because a caller
 *  that may exclude ANY path may as well exclude the corpus manifest or the
 *  security-probes record and call it a bootstrap: the flag is an ORDERING
 *  statement ("this run writes these itself"), not a way to shorten the required
 *  list. Every row is produced by a child `scripts/verify-s2-008.mjs` spawns
 *  after this gate. `evidence/s2-008-security-probes.json` is deliberately NOT
 *  in the set: the chain spawns that gate WITHOUT `--write`, so it writes
 *  nothing and the file has to exist before the chain runs.
 */
const CHAIN_PRODUCED_ALLOWED = Object.freeze([
  OUT_RELATIVE,
  'evidence/s2-008-probes.json',
  'evidence/s2-008-controls.json',
  'evidence/s2-008-comparison.json',
  'evidence/s2-008-harness.json',
  'evidence/s2-008-run-a.json',
  'evidence/s2-008-run-b.json',
  'evidence/s2-008-replay.json',
]);

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Is this path one of the records this gate reads? */
function isKnownEvidence(relPath) {
  return REQUIRED_EVIDENCE.includes(relPath) || OPTIONAL_EVIDENCE.includes(relPath) || relPath === OUT_RELATIVE;
}

function sha256Of(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Read-only git. No commit, no write, no index mutation. */
function git(...parts) {
  return execFileSync('git', parts, { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function gitBytes(commit, relPath) {
  return execFileSync('git', ['cat-file', 'blob', `${commit}:${relPath}`], { cwd: REPO_ROOT, maxBuffer: 1 << 28 });
}

function readWorkingTree(relPath) {
  return readFileSync(path.join(REPO_ROOT, relPath));
}

function readJsonFile(relPath) {
  try {
    return JSON.parse(readWorkingTree(relPath).toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * A DEPENDENCY BINDING READ FROM GIT BYTES — EV4.
 *
 * The five bindings the issue records were all read with `readJsonFile`, i.e.
 * `readFileSync(REPO_ROOT / <path>)`, while the record printed
 * `mode: 'FULL_GIT_BYTES'` and this file's own header said "There is deliberately
 * NO degraded mode". The claim was false: a working-tree edit to any of the five
 * artefacts was read as if it were the bound evidence, and nothing compared the
 * two. That is exactly the drift the gate exists to catch, uncatchable by the
 * gate that looks for it.
 *
 * `readBoundJson` therefore reads the bytes at `HEAD` — a binding is a claim
 * about a BASE — and the working tree is read too, so a drift between them is a
 * NAMED issue instead of a silent substitution. Every row of the record carries
 * `source: 'GIT_BLOB_AT_HEAD'` and both digests.
 *
 * @param {string} commit The commit this gate is proving.
 * @param {string} relPath Repository-relative path.
 * @param {'json'|'text'} [as='json'] `text` for a DOCUMENTARY binding, whose
 *   artefact is a Markdown table rather than a record. Parsing it as JSON made
 *   the source unreadable at the commit and the row looked like a missing
 *   artefact, which is a different failure.
 * @returns {{value: object|string|null, text: string|null, commitSha256: string|null, commitBytes: number|null,
 *   workingTreeSha256: string|null, workingTreeBytes: number|null, drift: boolean,
 *   source: string, readable_at_commit: boolean, error: string|null}}
 */
function readBoundSource(commit, relPath, as = 'json') {
  const row = {
    value: null,
    text: null,
    as,
    commitSha256: null,
    commitBytes: null,
    workingTreeSha256: null,
    workingTreeBytes: null,
    drift: false,
    source: 'GIT_BLOB_AT_HEAD',
    readable_at_commit: false,
    error: null,
  };
  try {
    const bytes = gitBytes(commit, relPath);
    row.commitBytes = bytes.length;
    row.commitSha256 = sha256Of(bytes);
    row.text = bytes.toString('utf8');
    row.value = as === 'text' ? row.text : JSON.parse(row.text);
    row.readable_at_commit = true;
  } catch (error) {
    row.error = String(error?.message ?? error).slice(0, 160);
  }
  try {
    const working = readWorkingTree(relPath);
    row.workingTreeBytes = working.length;
    row.workingTreeSha256 = sha256Of(working);
  } catch {
    row.workingTreeSha256 = null;
    row.workingTreeBytes = null;
  }
  // A binding that exists in the working tree but not at HEAD is a working-tree
  // artefact, not a bound one. That is the exact case this gate must refuse.
  row.drift = row.readable_at_commit
    ? (row.workingTreeSha256 !== null && row.workingTreeSha256 !== row.commitSha256)
    : row.workingTreeSha256 !== null;
  return row;
}

function listFilesRecursive(absDir) {
  if (!existsSync(absDir)) return [];
  const files = [];
  for (const entry of readdirSync(absDir).sort((a, b) => (a < b ? -1 : 1))) {
    const abs = path.join(absDir, entry);
    if (statSync(abs).isDirectory()) files.push(...listFilesRecursive(abs));
    else files.push(abs);
  }
  return files;
}

/**
 * THE TRACK'S FILE SET, FROM THE WORKING TREE.
 *
 * The other two views are Git's (`git ls-files` for tracked, `git status` for
 * untracked and modified), and between them they can only report what Git
 * knows. This walk is the one view Git cannot bias: it enumerates the files
 * that are THERE, so a file that is untracked AND ignored — invisible to both
 * `git ls-files` and `git status --porcelain` — is still in the expected set,
 * and `track_files_unaccounted` names it.
 *
 * @returns {string[]} sorted repository-relative paths inside the track scope
 */
function trackFilesExpected() {
  const found = new Set();
  for (const root of TRACK_WALK_ROOTS) {
    const abs = path.join(REPO_ROOT, root.rel);
    if (root.deep) {
      for (const absFile of listFilesRecursive(abs)) {
        const relPath = path.relative(REPO_ROOT, absFile).split(path.sep).join('/');
        if (TRACK_PATH.test(relPath)) found.add(relPath);
      }
      continue;
    }
    if (!existsSync(abs)) continue;
    for (const entry of readdirSync(abs).sort((a, b) => (a < b ? -1 : 1))) {
      const absFile = path.join(abs, entry);
      if (statSync(absFile).isDirectory()) continue;
      const relPath = path.relative(REPO_ROOT, absFile).split(path.sep).join('/');
      if (TRACK_PATH.test(relPath)) found.add(relPath);
    }
  }
  return [...found].sort();
}

/**
 * THE FROZEN CONTRACTS. Three independent reads of each file: the digest the
 * issue pins, the digest the frozen manifest records, and the digest of the
 * bytes at the pinned commit and in the working tree. A contract that is only
 * checked against itself proves nothing.
 */
function checkContracts(commit, manifestFiles) {
  const rows = [];
  for (const contract of FROZEN_CONTRACTS) {
    const row = {
      id: contract.id,
      path: contract.path,
      issue_digest: contract.digest,
      frozen_manifest_digest: manifestFiles[contract.path] ?? null,
      commit_digest: null,
      working_tree_digest: null,
      issues: [],
    };
    try {
      row.commit_digest = sha256Of(gitBytes(commit, contract.path));
    } catch (error) {
      row.issues.push(`unreadable-at-commit:${String(error?.message ?? error).slice(0, 120)}`);
    }
    try {
      row.working_tree_digest = sha256Of(readWorkingTree(contract.path));
    } catch (error) {
      row.issues.push(`unreadable-in-working-tree:${String(error?.message ?? error).slice(0, 120)}`);
    }
    for (const [label, value] of [['issue_digest', row.issue_digest], ['frozen_manifest_digest', row.frozen_manifest_digest], ['commit_digest', row.commit_digest], ['working_tree_digest', row.working_tree_digest]]) {
      if (value !== null && value !== row.issue_digest) row.issues.push(`${label}-drift`);
    }
    row.ok = row.issues.length === 0;
    rows.push(row);
  }
  return rows;
}

/**
 * FROZEN-TARGET CLEANLINESS. Every pinned path is re-read from Git and compared
 * with the manifest; and every file under a frozen tree must be TRACKED, because
 * an untracked file inside `contracts/` is a schema nobody pinned and a gate
 * that cannot see it is a gate that reports a clean tree.
 */
function checkFrozenTargets(commit, manifestFiles) {
  const issues = [];
  let verified = 0;
  for (const [relPath, digest] of Object.entries(manifestFiles)) {
    if (!SHA256.test(digest)) {
      issues.push(`malformed-digest:${relPath}`);
      continue;
    }
    let atCommit = null;
    try {
      atCommit = sha256Of(gitBytes(commit, relPath));
    } catch {
      issues.push(`absent-at-commit:${relPath}`);
      continue;
    }
    if (atCommit !== digest) {
      issues.push(`commit-digest-drift:${relPath}`);
      continue;
    }
    let working = null;
    try {
      working = sha256Of(readWorkingTree(relPath));
    } catch {
      issues.push(`absent-in-working-tree:${relPath}`);
      continue;
    }
    if (working !== digest) {
      issues.push(`working-tree-digest-drift:${relPath}`);
      continue;
    }
    verified += 1;
  }
  // Untracked residue inside a frozen tree. `git status --porcelain --untracked-files=all`
  // over the frozen roots is the read; the S2-008 track's own untracked files are
  // reported too, because an artefact nobody added is not bound to a base.
  const untracked = [];
  let dirty = [];
  try {
    dirty = git('status', '--porcelain', '--untracked-files=all', '--', 'contracts', 'src/lib/agentboard', 'src/lib/verifier', 'evidence/frozen-manifest.json', 'evidence/root-manifest.json')
      .split('\n').filter(Boolean);
  } catch {
    dirty = [];
  }
  for (const line of dirty) {
    if (line.startsWith('??')) untracked.push(line.slice(3).trim());
    else issues.push(`frozen-target-modified:${line.slice(3).trim()}`);
  }
  const TRACK_SCOPE_NOTE = 'the same regex the tracked/untracked/modified views use: ^(src/lib/research/|tests/research/|scripts/s2-008-|scripts/verify-s2-008|evidence/s2-008)';
  const trackFiles = git('ls-files', '-z').split('\0').filter(Boolean).filter((relPath) => TRACK_PATH.test(relPath));
  // EV6: THE TRACK'S OWN UNTRACKED FILES, NAMED. The frozen-tree scan above
  // can only see untracked files UNDER a frozen root, and this track's files are
  // not under one — so the track's untracked state was reported as an empty list
  // beside `track_files_tracked: 0`, which reads like "nothing is untracked"
  // instead of "everything is". `git ls-files` cannot see a file nobody added,
  // which is the whole reason the second read exists:
  // `scripts/check-inventory.mjs` and `scripts/generate-manifests.mjs` derive
  // their file set from `git ls-files` alone and therefore count 0 of this
  // track's files. They are not this gate's files to change, so the fact is
  // reported here, by name, instead of being left to be discovered.
  let trackUntracked = [];
  try {
    trackUntracked = git('status', '--porcelain', '--untracked-files=all', '--',
      'src/lib/research', 'tests/research', 'scripts', 'evidence')
      .split('\n').filter(Boolean)
      .filter((line) => line.startsWith('??') && TRACK_PATH.test(line.slice(3).trim()))
      .map((line) => line.slice(3).trim());
  } catch {
    trackUntracked = [];
  }
  const trackModified = (() => {
    try {
      return git('status', '--porcelain', '--', 'src/lib/research', 'tests/research', 'scripts', 'evidence')
        .split('\n').filter(Boolean).filter((line) => !line.startsWith('??') && TRACK_PATH.test(line.slice(3).trim()))
        .map((line) => line.slice(3).trim()).sort();
    } catch {
      return [];
    }
  })();
  // The three Git views are read independently of the walk, and the walk is the
  // one that can name a file Git cannot see at all. `track_files_unaccounted` is
  // REPORTED, not an issue: it is empty on a healthy tree, and a reader can see
  // whether the track's whole file set is covered by the three views.
  const trackExpected = trackFilesExpected();
  const seenByGit = new Set([...trackFiles, ...trackUntracked, ...trackModified]);
  // WHICH MODIFICATIONS ARE THE CHAIN'S OWN OUTPUT. The chain's children write
  // these records, so a provability term that blocks on ANY modified track file
  // would be blocking on the evidence the previous chain run produced. Both
  // lists are published: `track_files_modified_other` is the one that names a
  // developer's uncommitted edit, and it is the one a reader should be shown.
  const modifiedByChain = trackModified.filter((relPath) => CHAIN_PRODUCED_ALLOWED.includes(relPath));
  const modifiedOther = trackModified.filter((relPath) => !CHAIN_PRODUCED_ALLOWED.includes(relPath));
  return {
    pinned_paths: Object.keys(manifestFiles).length,
    verified,
    issues,
    untracked_in_frozen_trees: untracked,
    // THE WHOLE TRACK, THREE VIEWS, ONE SCOPE. `track_files_expected` is the
    // working-tree walk (a LIST of repository-relative paths, sorted, unique);
    // `track_files_tracked` is what `git ls-files` reports of them;
    // `track_files_untracked` and `track_files_modified` are the two `git status`
    // views. Provability is a property of the whole set, and the aggregator
    // reads all four.
    track_files_expected: trackExpected,
    track_files_expected_count: trackExpected.length,
    track_files_expected_source: `the WORKING TREE, walked over ${TRACK_WALK_ROOTS.map((root) => root.rel).join(', ')} and filtered with ${TRACK_SCOPE_NOTE}`,
    track_files_unaccounted: trackExpected.filter((relPath) => !seenByGit.has(relPath)),
    track_files_tracked: trackFiles.length,
    track_files_untracked: trackUntracked,
    track_files_modified: trackModified,
    track_files_modified_by_the_chain: modifiedByChain,
    track_files_modified_other: modifiedOther,
    untracked_visibility_note: 'scripts/check-inventory.mjs and scripts/generate-manifests.mjs derive their file set from `git ls-files` alone, so they report 0 tracked files of this track and do not see the untracked ones; this list is the honest count and those two scripts are not this gate\'s files to change',
    note: 'A track whose own files are untracked is NOT bound to a base in any sense a reader can check: `git ls-files` reports 0 and both integrity gates are green for the wrong reason.',
  };
}

/** The five dependency bindings, each read from canonical evidence. */
function checkBindings(commit) {
  const rows = [];
  // EV4: every binding artefact is read from GIT BYTES at HEAD, and the working
  // tree is compared against those bytes rather than substituted for them.
  const bound = new Map(DEPENDENCY_BINDINGS.map((binding) => [binding.id, readBoundSource(commit, binding.artefact, binding.kind === 'documentary' ? 'text' : 'json')]));
  const s2006 = bound.get('S2-006').value;
  for (const binding of DEPENDENCY_BINDINGS) {
    const source = bound.get(binding.id);
    const record = source.value;
    const row = {
      id: binding.id,
      kind: binding.kind,
      artefact: binding.artefact,
      issues: [],
      evidence: {},
      source: source.source,
      commit_sha256: source.commitSha256,
      commit_bytes: source.commitBytes,
      working_tree_sha256: source.workingTreeSha256,
      working_tree_bytes: source.workingTreeBytes,
      drift: source.drift,
    };
    if (source.drift === true) row.issues.push('working-tree-differs-from-the-bound-bytes');
    if (source.readable_at_commit !== true && record === null) row.issues.push('record-unreadable-at-commit');
    if (binding.id === 'S2-002') {
      if (record === null) row.issues.push('record-unreadable');
      else {
        // The real shape: `dependencies` is an ARRAY of `{ticket, status,
        // evidence, ...}` and the upstream pin is
        // `sourceRepository.headCommitAtBindingTime`. Read from the record, not
        // from a shape guessed here, so a change in the record is a finding
        // rather than a silent `undefined`.
        const dependencies = Array.isArray(record.dependencies) ? record.dependencies : [];
        const pinned = record.sourceRepository?.headCommitAtBindingTime ?? record.sourceRepository?.pinnedCommit ?? null;
        const evidenceFiles = dependencies
          .map((entry) => (isPlainObject(entry) ? entry.evidence : null))
          .filter((entry) => typeof entry === 'string' && entry.length > 0);
        const readable = evidenceFiles.filter((relPath) => existsSync(path.join(REPO_ROOT, relPath)));
        row.evidence = {
          schema_version: record.schemaVersion ?? null,
          dependencies: dependencies.length,
          tickets: dependencies.map((entry) => (isPlainObject(entry) ? `${entry.ticket}:${entry.status}` : 'malformed')),
          pinned_commit: pinned,
          dependencies_source: record.dependenciesSource ?? null,
          evidence_files_named: evidenceFiles.length,
          evidence_files_readable: readable.length,
          consequence: record.consequence ?? null,
        };
        if (dependencies.length === 0) row.issues.push('no-dependencies-declared');
        if (dependencies.some((entry) => !isPlainObject(entry) || typeof entry.ticket !== 'string' || typeof entry.status !== 'string')) {
          row.issues.push('malformed-dependency-entry');
        }
        if (!GIT_OBJECT.test(String(pinned))) row.issues.push('upstream-pin-unpinned');
        if (evidenceFiles.length === 0) row.issues.push('no-dependency-evidence-named');
        else if (readable.length !== evidenceFiles.length) {
          row.issues.push(`dependency-evidence-unreadable:${readable.length}/${evidenceFiles.length}`);
        }
      }
    } else if (binding.id === 'S2-006') {
      if (record === null) row.issues.push('record-unreadable');
      else {
        row.evidence = { resolved_ok: record.resolved?.ok ?? null, checked: record.resolved?.checkedCount ?? null };
        if (record.resolved?.ok !== true) row.issues.push('resolved-not-green');
        if (!Number.isInteger(record.resolved?.checkedCount) || record.resolved.checkedCount <= 0) row.issues.push('no-checks-recorded');
      }
    } else if (binding.id === 'S2-007') {
      if (record === null) row.issues.push('record-unreadable');
      else {
        const pinned = record.base?.canonicalizationCommit ?? null;
        const declared = record.base?.expectedParents ?? [];
        let descends = false;
        if (GIT_OBJECT.test(String(pinned))) {
          try {
            git('merge-base', '--is-ancestor', pinned, 'HEAD');
            descends = true;
          } catch {
            descends = false;
          }
        }
        let declaredParentsActual = null;
        if (GIT_OBJECT.test(String(pinned))) {
          declaredParentsActual = git('rev-list', '--parents', '-n', '1', pinned).trim().split(/\s+/).slice(1);
        }
        const foundation = isPlainObject(record.s2_007FrozenFoundation) ? record.s2_007FrozenFoundation : {};
        const foundationPaths = ['contractSchemas', 'migration', 'frozenModules']
          .flatMap((group) => (isPlainObject(foundation[group]) ? Object.keys(foundation[group]) : []));
        let foundationVerified = 0;
        const foundationIssues = [];
        for (const group of ['contractSchemas', 'migration', 'frozenModules']) {
          for (const [relPath, expected] of Object.entries(isPlainObject(foundation[group]) ? foundation[group] : {})) {
            if (!isPlainObject(expected) || !SHA256.test(String(expected.sha256))) {
              foundationIssues.push(`foundation-unbound:${relPath}`);
              continue;
            }
            let atCommit = null;
            try {
              atCommit = sha256Of(gitBytes(record.s2_007FrozenFoundation.commit ?? commit, relPath));
            } catch {
              foundationIssues.push(`foundation-absent-at-commit:${relPath}`);
              continue;
            }
            let working = null;
            try {
              working = sha256Of(readWorkingTree(relPath));
            } catch {
              foundationIssues.push(`foundation-absent-in-working-tree:${relPath}`);
              continue;
            }
            const deviation = isPlainObject(record.reviewedDeviations?.[relPath]) ? record.reviewedDeviations[relPath] : null;
            if (atCommit !== expected.sha256) {
              foundationIssues.push(`foundation-commit-digest-drift:${relPath}`);
            } else if (working === expected.sha256) {
              foundationVerified += 1;
            } else if (deviation !== null) {
              foundationVerified += 1;
            } else {
              foundationIssues.push(`foundation-working-tree-drift:${relPath}`);
            }
          }
        }
        row.evidence = {
          canonicalization_commit: pinned,
          descends_from_head: descends,
          declared_parents: declared.length,
          actual_parents: declaredParentsActual,
          foundation_paths: foundationPaths.length,
          foundation_verified: foundationVerified,
          resolved_ok: record.resolved?.ok ?? null,
        };
        if (!GIT_OBJECT.test(String(pinned))) row.issues.push('canonicalization-commit-unpinned');
        if (!descends) row.issues.push('head-does-not-descend-from-canonicalization');
        if (declared.length === 0) row.issues.push('no-declared-parent-shape');
        else if (!isPlainObject(declaredParentsActual) && !Array.isArray(declaredParentsActual)) row.issues.push('parents-unreadable');
        else if (declaredParentsActual.length !== declared.length || declaredParentsActual.some((parent, index) => parent !== declared[index])) {
          row.issues.push('declared-parent-shape-drift');
        }
        if (foundationPaths.length === 0) row.issues.push('no-frozen-foundation-paths');
        if (foundationIssues.length > 0) row.issues.push(...foundationIssues);
        if (record.resolved?.ok !== true) row.issues.push('resolved-not-green');
      }
    } else if (binding.id === 'S1-004') {
      // S1-004 has NO tracked evaluation record in this repository: the
      // authoritative copy lives in the pinned AgentOS checkout. The binding is
      // therefore DOCUMENTARY, and it is recorded as documentary — a status that
      // says "this is a row in a table, not bytes I verified" instead of a
      // green check on evidence that does not exist here.
      // S1-004 is DOCUMENTARY: the authoritative evaluation record is not tracked
      // in this repository, so the binding is a claim about a row in a table. The
      // TABLE TEXT is read from Git bytes for the same reason as everything else.
      const text = typeof source.text === 'string' ? source.text : '';
      row.evidence.document_source = source.source;
      if (text === '') row.issues.push('document-unreadable');
      const rowMatch = new RegExp(`^\\|\\s*${binding.id}\\s*\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|\\s*\`?([A-Z_]+)\`?\\s*\\|`, 'm').exec(text);
      row.evidence = {
        status: 'DOCUMENTARY_NO_TRACKED_EVALUATION_RECORD',
        issue: rowMatch === null ? null : rowMatch[1].trim().replace(/[[\]]/g, ''),
        wave: rowMatch === null ? null : rowMatch[2].trim(),
        owner: rowMatch === null ? null : rowMatch[3].trim(),
        verdict: rowMatch === null ? null : rowMatch[4].trim(),
        note: 'the authoritative S1-004 evaluation record is not tracked in this repository; this row is a claim about it, not a check of it',
      };
      if (rowMatch === null) row.issues.push('documentary-row-absent');
    } else if (binding.id === 'S1-011') {
      const expected = isPlainObject(s2006?.stage1?.bindings?.s1_011) ? s2006.stage1.bindings.s1_011 : null;
      if (expected === null) {
        row.issues.push('no-binding-in-the-s2-006-record');
      } else {
        // EV4: the tracked copy's digest IS the digest at the commit, and the
        // working tree is compared against it separately by `readBoundJson`. The
        // two used to be read independently and the working-tree value was the
        // one compared against the upstream pin.
        const atCommit = source.commitSha256;
        const actual = atCommit;
        const payload = record;
        if (payload === null) row.issues.push('record-unparseable');
        const fields = expected.expected ?? {};
        row.evidence = {
          expected_sha256: expected.recordSha256 ?? null,
          working_tree_sha256: actual,
          commit_sha256: atCommit,
          expected_bytes: expected.recordBytes ?? null,
          fields: {
            ticket_id: payload?.ticket_id ?? null,
            result: payload?.result ?? null,
            evaluation_id: payload?.evaluation_id ?? null,
          },
        };
        if (actual !== expected.recordSha256) row.issues.push('tracked-copy-digest-drift');
        if (atCommit !== null && atCommit !== expected.recordSha256) row.issues.push('tracked-copy-digest-drift-at-commit');
        if (Number.isInteger(expected.recordBytes) && source.commitBytes !== null
          && source.commitBytes !== expected.recordBytes) {
          row.issues.push(`tracked-copy-length-drift:${String(source.commitBytes)}/${String(expected.recordBytes)}`);
        }
        for (const [key, value] of Object.entries(fields)) {
          if (value !== undefined && payload !== null && payload[key] !== value) row.issues.push(`field-drift:${key}`);
        }
      }
    }
    row.ok = row.issues.length === 0;
    rows.push(row);
  }
  return rows;
}

/**
 * MODULE REACHABILITY. Every module of the track must be imported by something
 * else in the track, and the public barrel must re-export the frozen names. The
 * importers are found by reading the committed sources, so the answer is
 * derived from the tree rather than asserted here.
 */
function checkModules(commit) {
  const dir = path.join(REPO_ROOT, 'src', 'lib', 'research');
  const modules = listFilesRecursive(dir).map((abs) => path.relative(REPO_ROOT, abs).split(path.sep).join('/'));
  const sources = [];
  const scanRoots = [
    path.join(REPO_ROOT, 'src', 'lib', 'research'),
    path.join(REPO_ROOT, 'scripts'),
    path.join(REPO_ROOT, 'tests', 'research'),
  ];
  for (const root of scanRoots) {
    for (const abs of listFilesRecursive(root)) {
      if (!abs.endsWith('.mjs')) continue;
      sources.push({ rel: path.relative(REPO_ROOT, abs).split(path.sep).join('/'), text: readFileSync(abs, 'utf8') });
    }
  }
  const importers = {};
  for (const modulePath of modules) {
    const base = path.basename(modulePath);
    const found = [];
    for (const source of sources) {
      if (source.rel === modulePath) continue;
      if (!new RegExp(`['\"][^'\"]*${base.replace('.', '\\.')}['\"]`).test(source.text)) continue;
      found.push(source.rel);
    }
    importers[modulePath] = found;
  }
  // The frozen public surface: the names `index.mjs` re-exports.
  const barrel = modules.find((relPath) => relPath.endsWith('src/lib/research/index.mjs'));
  const barrelText = barrel === undefined ? '' : readWorkingTree(barrel).toString('utf8');
  const exported = [...barrelText.matchAll(/export\s*\{([^}]*)\}\s*from/g)]
    .flatMap((match) => match[1].split(',').map((name) => name.trim()).filter(Boolean));
  const issues = [];
  for (const modulePath of modules) {
    if (modulePath.endsWith('index.mjs')) continue;
    if (importers[modulePath].length === 0) issues.push(`unreachable:${modulePath}`);
  }
  let barrelPresent = false;
  try {
    git('cat-file', '-e', `${commit}:src/lib/research/index.mjs`);
    barrelPresent = true;
  } catch {
    barrelPresent = false;
  }
  if (!barrelPresent) issues.push('index.mjs-absent-at-commit');
  return {
    modules: modules.length,
    importers,
    barrel: barrel ?? null,
    barrel_exports: exported.length,
    barrel_exports_at_commit: barrelPresent,
    issues,
  };
}

/**
 * S11: PARSE EVERY MODULE OF THE TRACK. `node --check` is the compiler's own
 * syntax check, run as a child process per file, so a module that does not parse
 * is a named issue rather than an import error three layers up.
 *
 * The boundary of this check is stated rather than implied: it proves the tree
 * PARSES. It is not type checking — `tsconfig.json` excludes `.mjs` entirely —
 * and the record says so, so a reader never mistakes a green `syntax` block for
 * a typed one.
 *
 * @returns {{modules: number, parsed: number, issues: ReadonlyArray<string>}}
 */
function checkSyntax() {
  const roots = [
    path.join(REPO_ROOT, 'src', 'lib', 'research'),
    path.join(REPO_ROOT, 'tests', 'research'),
    path.join(REPO_ROOT, 'scripts'),
  ];
  const files = [];
  for (const root of roots) {
    for (const abs of listFilesRecursive(root)) {
      if (!abs.endsWith('.mjs')) continue;
      if (root.endsWith('scripts') && !/-s2-008.*\.mjs$/.test(abs)) continue;
      files.push(abs);
    }
  }
  const issues = [];
  let parsed = 0;
  for (const abs of files) {
    const relPath = path.relative(REPO_ROOT, abs).split(path.sep).join('/');
    try {
      execFileSync(process.execPath, ['--check', abs], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
      parsed += 1;
    } catch (error) {
      issues.push(`unparseable:${relPath}:${String(error?.stderr ?? error?.message ?? error).slice(0, 160).split('\n')[0]}`);
    }
  }
  return { modules: files.length, parsed, issues, note: 'node --check proves the file PARSES; it is not type checking, and tsconfig.json excludes .mjs from `tsc` entirely' };
}

/**
 * THE CHAIN'S OWN RECORDS: `--chain-produced <comma-separated paths>`, passed
 * by `scripts/verify-s2-008.mjs` and readable here more than once.
 *
 * The raw argv is scanned rather than only the parsed args, because
 * `parseArgs` keeps the LAST value of a repeated flag and a chain that lists
 * four records across two flags would silently lose the first two. A value
 * that is a bare `true` (`--chain-produced --no-write`) is a usage error and is
 * a named issue, not an empty exclusion set: a caller who asked to exclude
 * something and named nothing must not get a green gate for having asked.
 *
 * @param {string[]} argv `process.argv`
 * @returns {{paths: string[], flag_seen: boolean, issues: string[]}}
 */
export function resolveChainProduced(argv = []) {
  const raw = [];
  for (let index = 2; index < argv.length; index += 1) {
    const token = String(argv[index] ?? '');
    const match = /^--(?:chain[-_]produced|chain[-_]produced[-_]paths)(?:=(.*))?$/.exec(token);
    if (match === null) continue;
    const inline = match[1];
    if (inline !== undefined) {
      raw.push(inline);
      continue;
    }
    const next = argv[index + 1];
    if (next === undefined || String(next).startsWith('--')) {
      raw.push('');
      continue;
    }
    raw.push(String(next));
    index += 1;
  }
  const paths = [...new Set(raw
    .flatMap((value) => String(value).split(','))
    .map((value) => value.trim())
    .filter((value) => value.length > 0))].sort();
  const issues = [];
  if (raw.length > 0 && paths.length === 0) {
    issues.push('chain-produced-without-a-path: `--chain-produced` was passed with no value, so nothing was excluded; the flag is reported instead of ignored');
  }
  return { paths, flag_seen: raw.length > 0, issues };
}

/** EVIDENCE PRESENCE. Absence is recorded as absence, never as agreement.
 *
 *  `chainProduced` are the paths the spawning chain writes in this same run,
 *  AFTER this gate. They are excluded from REQUIRED — and only from REQUIRED:
 *  they are still read, still counted when present, and still carry their
 *  presence and their byte count in the record, so an exclusion can never look
 *  like a file that was checked and found.
 *
 *  @param {string[]} [chainProduced] paths the spawning chain produces
 * @returns {{rows: object[], excluded: string[], unknown: string[], no_effect: string[]}}
 */
function checkEvidence(chainProduced = []) {
  const excluded = [];
  const unknown = [];
  const noEffect = [];
  const rows = [];
  const push = (relPath, required) => {
    const abs = path.join(REPO_ROOT, relPath);
    const present = existsSync(abs);
    // An exclusion is applied ONLY for a path the chain provably writes after
    // this gate. Anything else is `unknown`, and the caller turns that into an
    // issue: a flag that cannot narrow anything must not read as one that did.
    const chainProducedHere = chainProduced.includes(relPath) && CHAIN_PRODUCED_ALLOWED.includes(relPath);
    const row = {
      path: relPath,
      required: chainProducedHere ? false : required,
      present,
      bytes: present ? statSync(abs).size : null,
      issues: [],
    };
    if (chainProducedHere) {
      row.required = false;
      row.excluded_from_required = true;
      row.chain_produced = true;
      row.exclusion_reason = CHAIN_PRODUCED_REASON;
      excluded.push(relPath);
      if (required !== true) noEffect.push(relPath);
    }
    if (!present && row.required) row.issues.push('absent');
    rows.push(row);
  };
  for (const relPath of chainProduced) {
    if (!CHAIN_PRODUCED_ALLOWED.includes(relPath)) unknown.push(relPath);
  }
  for (const relPath of REQUIRED_EVIDENCE) push(relPath, true);
  for (const relPath of OPTIONAL_EVIDENCE) push(relPath, false);
  return { rows, excluded, unknown, no_effect: noEffect };
}

export function verifyDependencies(args = {}, argv = process.argv) {
  const issues = [];
  const checked = [];
  const chain = resolveChainProduced(argv);
  // A flag the gate cannot honour is reported, never applied. `--chain-produced
  // <a path this gate does not know>` is the shape of a flag aimed at something
  // other than this track's evidence, and an exclusion nobody can read is not a
  // narrowing, it is a hole.
  issues.push(...chain.issues);
  const head = (() => {
    try {
      return git('rev-parse', 'HEAD').trim();
    } catch {
      return null;
    }
  })();
  if (!GIT_OBJECT.test(String(head))) {
    // An archive checkout has no object database, so nothing here can be proven
    // from Git bytes. There is deliberately NO degraded mode: a dependency proof
    // that cannot read Git bytes is not a dependency proof.
    return {
      ok: false,
      status: 'BLOCKED_DEPENDENCY',
      mode: 'FULL_GIT_BYTES',
      checked: 0,
      issues: ['archive-mode:no-object-database'],
      head: null,
      written: null,
    };
  }
  const frozen = readJsonFile(FROZEN_MANIFEST);
  if (frozen === null || !isPlainObject(frozen.files)) issues.push(`${FROZEN_MANIFEST}:unreadable`);
  const manifestFiles = isPlainObject(frozen?.files) ? frozen.files : {};
  checked.push(`frozen-manifest:${Object.keys(manifestFiles).length}`);

  const contracts = checkContracts(head, manifestFiles);
  for (const row of contracts) {
    if (row.ok) checked.push(`contract:${row.id}`);
    else issues.push(...row.issues.map((code) => `${row.path}:${code}`));
  }
  const targets = checkFrozenTargets(head, manifestFiles);
  issues.push(...targets.issues);
  checked.push(`frozen-targets:${targets.verified}/${targets.pinned_paths}`);
  const bindings = checkBindings(head);
  for (const row of bindings) {
    if (row.ok) checked.push(`binding:${row.id}`);
    else issues.push(...row.issues.map((code) => `${row.id}:${code}`));
  }
  const modules = checkModules(head);
  issues.push(...modules.issues);
  checked.push(`modules:${modules.modules}`);
  // S11: A MECHANICAL GATE THAT READS THE .mjs TREE. `tsconfig.json` sets
  // `allowJs: false` and includes only `**/*.ts` / `**/*.tsx`, so
  // `npm run typecheck` reads NONE of `src/lib/research/*.mjs` and exits 0 on a
  // file full of type errors — 620 KB of this track with no type checking at all.
  // ESLint does read it, and so does this gate: every module of the track is
  // PARSED with `node --check`, which is a real mechanical check that fails on a
  // syntax error, and the count is reported. `tsconfig.json` is not this gate's
  // file to change, so the coverage is added where it can be added honestly
  // rather than asserted in a report.
  const syntax = checkSyntax();
  issues.push(...syntax.issues);
  checked.push(`syntax:${syntax.parsed}/${syntax.modules}`);
  const evidence = checkEvidence(chain.paths);
  issues.push(...evidence.unknown.map((relPath) => `chain-produced-unknown-path:${relPath}: --chain-produced can only cover the records the spawning chain writes AFTER this gate (${CHAIN_PRODUCED_ALLOWED.join(', ')}), so this path is not excluded${isKnownEvidence(relPath) ? '; it IS one of this gate\'s own evidence paths and stays REQUIRED' : ''}`));
  for (const row of evidence.rows) {
    if (row.present) checked.push(`evidence:${row.path}`);
    else if (row.required) issues.push(`evidence-absent:${row.path}`);
  }
  const rootManifest = readJsonFile(ROOT_MANIFEST);
  if (rootManifest === null) issues.push(`${ROOT_MANIFEST}:unreadable`);

  // The head TREE, for the same invocation binding the two run gates carry:
  // a record is only this run's record if it names the tree the aggregator
  // observed. Read-only git, and read only after `head` is known to be a
  // commit, so this cannot become a second source of truth for it.
  const headTree = GIT_OBJECT.test(String(head))
    ? (() => {
      try {
        return git('rev-parse', 'HEAD^{tree}').trim();
      } catch {
        return null;
      }
    })()
    : null;
  const invocationId = typeof args.invocationId === 'string' || typeof args.invocation_id === 'string'
    ? String(args.invocationId ?? args.invocation_id)
    : (args.invocationId === true || args.invocation_id === true ? true : null);
  if (invocationId === true) {
    issues.push('invocation-id-without-a-value: `--invocation-id` was passed with no value, so this record cannot be bound to the invocation that asked for it');
  } else if (invocationId !== null && !/^[!-~]{1,200}$/.test(invocationId)) {
    issues.push(`invocation-id-malformed: an invocation id must be 1-200 printable non-space characters; got ${String(invocationId).slice(0, 40).replace(/[^\x21-\x7e]/g, '?')}`);
  }

  const record = {
    ticket: 'S2-008',
    gate: 'scripts/verify-s2-008-dependencies.mjs',
    // EV4: this string is now TRUE, and the record says WHERE each class of byte
    // comes from, so a reader can check the claim instead of taking it. The five
    // dependency bindings are read with `git cat-file blob HEAD:<path>` and the
    // working tree is compared against those bytes; the three frozen contracts
    // and every frozen-target path are read both ways already.
    mode: 'FULL_GIT_BYTES',
    byte_sources: {
      frozen_contracts: 'git blob at HEAD + the working tree, both compared',
      frozen_targets: 'git blob at HEAD + the working tree, both compared',
      dependency_bindings: 'git blob at HEAD, with the working tree compared for drift',
      modules: 'the working tree (reachability and exports are facts about the tree in front of the reader)',
      evidence_presence: 'the working tree (a file is either there or not)',
    },
    scope: 'the dependency bindings the issue records, checked against canonical evidence; NOT experiment authorization and NOT the ticket verdict',
    head,
    head_tree_sha: headTree,
    invocation_id: invocationId,
    contracts,
    frozen_targets: targets,
    bindings,
    modules,
    syntax,
    evidence: evidence.rows,
    // THE CHAIN'S OWN RECORDS, in full: which paths were excluded from
    // REQUIRED, why, whether the exclusion had any effect, and which named
    // paths the gate refused to exclude because it does not know them. Without
    // the flag every list here is empty and the required set is the one above,
    // byte for byte, which is what keeps `npm run verify:s2-008-dependencies`
    // on its own contract.
    chain_run: {
      flag: '--chain-produced <comma-separated paths>',
      flag_seen: chain.flag_seen,
      allowed: [...CHAIN_PRODUCED_ALLOWED],
      excluded: evidence.excluded,
      excluded_had_no_effect: evidence.no_effect,
      refused: evidence.unknown,
      required: [...REQUIRED_EVIDENCE],
      required_effective: evidence.rows.filter((row) => row.required).map((row) => row.path),
      reason: CHAIN_PRODUCED_REASON,
      owner_of_the_excluded_records: 'scripts/verify-s2-008.mjs — the chain spawns this gate before the children that write those records, so the chain is what checks they exist and what their bytes are',
    },
    root_manifest_readable: rootManifest !== null,
    issues,
    checked: checked.length,
    ok: issues.length === 0,
    status: issues.length === 0 ? 'PASS' : 'BLOCKED_DEPENDENCY',
  };
  let written = null;
  // `--no-write`: a CHECK run of this gate must not rewrite the record it is
  // checking. The form was missing, so a reader who wanted to verify the gate
  // had to let it overwrite the evidence first.
  const noWrite = args.noWrite === true || args.no_write === true || args.nowrite === true;
  if (args.write !== false && !noWrite) {
    const outFile = path.join(REPO_ROOT, OUT_RELATIVE);
    mkdirSync(path.dirname(outFile), { recursive: true });
    const body = `${JSON.stringify(record, null, 2)}\n`;
    writeFileSync(outFile, body, 'utf8');
    written = { path: OUT_RELATIVE, bytes: Buffer.byteLength(body) };
  }
  return { ...record, written };
}

function main() {
  const args = parseArgs(process.argv);
  const result = verifyDependencies(args);
  if (args.printRecord === true) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write(`${JSON.stringify({
      ticket: 'S2-008',
      gate: 'scripts/verify-s2-008-dependencies.mjs',
      status: result.status,
      ok: result.ok,
      mode: result.mode,
      head: result.head,
      head_tree_sha: result.head_tree_sha ?? null,
      invocation_id: result.invocation_id ?? null,
      checked: result.checked,
      issues: result.issues,
      // THE WHOLE TRACK, on stdout as well as in the record: the aggregator
      // reads this summary, so a field that lived only in the written record
      // would be a field the chain cannot see.
      track_files_expected: result.frozen_targets?.track_files_expected ?? null,
      track_files_expected_count: result.frozen_targets?.track_files_expected_count ?? null,
      track_files_unaccounted: result.frozen_targets?.track_files_unaccounted ?? null,
      track_files_tracked: result.frozen_targets?.track_files_tracked ?? null,
      track_files_untracked: result.frozen_targets?.track_files_untracked ?? null,
      track_files_modified: result.frozen_targets?.track_files_modified ?? null,
      track_files_modified_by_the_chain: result.frozen_targets?.track_files_modified_by_the_chain ?? null,
      track_files_modified_other: result.frozen_targets?.track_files_modified_other ?? null,
      chain_produced_excluded: result.chain_run?.excluded ?? [],
      chain_produced_refused: result.chain_run?.refused ?? [],
      chain_produced_reason: result.chain_run?.flag_seen === true ? result.chain_run.reason : null,
      syntax: result.syntax ? { modules: result.syntax.modules, parsed: result.syntax.parsed, note: result.syntax.note } : null,
      byte_sources: result.byte_sources ?? null,
      binding_sources: (result.bindings ?? []).map((row) => `${row.id}:${row.source}${row.drift === true ? '(DRIFT)' : ''}`),
      bindings: (result.bindings ?? []).map((row) => `${row.id}:${row.ok ? 'BOUND' : `UNBOUND(${row.issues.join('|')})`}`),
      ...(result.written ? { written: result.written } : {}),
    }, null, 2)}\n`);
  }
  process.exitCode = result.ok ? 0 : 1;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      ticket: 'S2-008',
      gate: 'scripts/verify-s2-008-dependencies.mjs',
      status: 'BLOCKED_DEPENDENCY',
      ok: false,
      code: String(error?.code ?? 'DEPENDENCY_GATE_ERROR'),
      error: String(error?.message ?? error).slice(0, 600),
    }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
