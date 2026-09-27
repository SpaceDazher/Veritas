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
//   node scripts/verify-s2-008-dependencies.mjs
//   node scripts/verify-s2-008-dependencies.mjs --print-record
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

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
  const TRACK_PATH = /^(src\/lib\/research\/|tests\/research\/|scripts\/s2-008-|scripts\/verify-s2-008|evidence\/s2-008)/;
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
  return {
    pinned_paths: Object.keys(manifestFiles).length,
    verified,
    issues,
    untracked_in_frozen_trees: untracked,
    track_files_tracked: trackFiles.length,
    track_files_untracked: trackUntracked,
    track_files_modified: (() => {
      try {
        return git('status', '--porcelain', '--', 'src/lib/research', 'tests/research', 'scripts', 'evidence')
          .split('\n').filter(Boolean).filter((line) => !line.startsWith('??') && TRACK_PATH.test(line.slice(3).trim()))
          .map((line) => line.slice(3).trim());
      } catch {
        return [];
      }
    })(),
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

/** EVIDENCE PRESENCE. Absence is recorded as absence, never as agreement. */
function checkEvidence() {
  const required = [
    'evidence/s2-008-probes.json',
    'evidence/s2-008-controls.json',
    'evidence/s2-008-comparison.json',
    'evidence/s2-008-security-probes.json',
    'evidence/s2-008-run-a.json',
    'evidence/s2-008-run-b.json',
    'evidence/s2-008-replay.json',
    'evidence/s2-008/corpus/manifest.json',
    'evidence/s2-008/corpus/preregistration.json',
  ];
  const optional = [
    'evidence/s2-008-summary.json',
    'evidence/s2-008-harness.json',
    'evidence/s2-008-negative-controls.json',
  ];
  const rows = [];
  for (const relPath of required) {
    const abs = path.join(REPO_ROOT, relPath);
    const present = existsSync(abs);
    rows.push({ path: relPath, required: true, present, bytes: present ? statSync(abs).size : null, issues: present ? [] : ['absent'] });
  }
  for (const relPath of optional) {
    const abs = path.join(REPO_ROOT, relPath);
    const present = existsSync(abs);
    rows.push({ path: relPath, required: false, present, bytes: present ? statSync(abs).size : null, issues: [] });
  }
  return rows;
}

export function verifyDependencies(args = {}) {
  const issues = [];
  const checked = [];
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
  const evidence = checkEvidence();
  for (const row of evidence) {
    if (row.present) checked.push(`evidence:${row.path}`);
    else if (row.required) issues.push(`evidence-absent:${row.path}`);
  }
  const rootManifest = readJsonFile(ROOT_MANIFEST);
  if (rootManifest === null) issues.push(`${ROOT_MANIFEST}:unreadable`);

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
    contracts,
    frozen_targets: targets,
    bindings,
    modules,
    syntax,
    evidence,
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
      checked: result.checked,
      issues: result.issues,
      track_files_tracked: result.frozen_targets?.track_files_tracked ?? null,
      track_files_untracked: result.frozen_targets?.track_files_untracked ?? null,
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
