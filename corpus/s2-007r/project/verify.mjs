#!/usr/bin/env node
// THE ONE DETERMINISTIC ORACLE of the S2-007R project (issue SpaceDazher/Veritas#45).
//
//   node corpus/s2-007r/project/verify.mjs <task_id>   # exit 0 = the criterion is met
//
// WHY A SINGLE ORACLE
// Every measurement of SPEC §5 that says "conformance" is computed from this
// file's exit code and nothing else. A third party with a clean checkout, a Node
// runtime and no credential can recompute all of them: the project digest, the
// accepted-task quality, the pass@1 row, the regression rate. No model, no
// network, no stored fixture.
//
// WHAT IT IS NOT
// It is not a test runner with opinions, and it never edits the project. It
// imports the modules, evaluates the task's criterion, prints a machine-readable
// line, and exits 0 or 1. The digest of the files it read is printed with it, so
// the record that quotes a verdict can also quote WHICH bytes it was computed
// from.
//
// DETERMINISM
// No Date.now(), no Math.random(), no environment value, no clock. The same
// bytes always produce the same output, byte for byte.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The repository's OWN canonical digest, not a local re-implementation: the run
// driver computes `project_digest` with exactly this function, so the digest
// printed here and the digest in a run record are the same string for the same
// bytes and a third party can compare them without translating anything.
import { canonicalDigest } from '../../../src/lib/verifier/canonical-json.mjs';

import { add, sub, mul, sumRange } from './src/calc.js';
import { parsePairs, renderPairs } from './src/parse.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** sha256 over the sorted `relative path -> {bytes, sha256}` map: the project digest. */
function projectDigest(root) {
  const map = {};
  const walk = (absolute, relative) => {
    for (const name of readdirSync(absolute).sort()) {
      const child = path.join(absolute, name);
      const rel = relative === '' ? name : `${relative}/${name}`;
      if (statSync(child).isDirectory()) { walk(child, rel); continue; }
      const bytes = readFileSync(child);
      map[rel] = { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
    }
  };
  walk(root, '');
  return map;
}

/** The five pre-existing tests, as a pure function of the module surface. */
function preExistingTests() {
  const results = [];
  const check = (id, fn) => {
    try {
      fn();
      results.push({ id, passed: true });
    } catch (error) {
      results.push({ id, passed: false, detail: String(error?.message ?? error).slice(0, 160) });
    }
  };
  check('calc:add', () => { if (add(2, 3) !== 5) throw new Error('add(2,3) !== 5'); if (add(-1, 1) !== 0) throw new Error('add(-1,1) !== 0'); });
  check('calc:sub', () => { if (sub(5, 2) !== 3) throw new Error('sub(5,2) !== 3'); if (sub(2, 5) !== -3) throw new Error('sub(2,5) !== -3'); });
  check('calc:mul', () => { if (mul(4, 3) !== 12) throw new Error('mul(4,3) !== 12'); if (mul(0, 9) !== 0) throw new Error('mul(0,9) !== 0'); });
  check('calc:sumRange_inclusive', () => { if (sumRange(1, 4) !== 10) throw new Error(`sumRange(1,4) === ${String(sumRange(1, 4))}, expected 10`); if (sumRange(1, 1) !== 1) throw new Error('sumRange(1,1) !== 1'); });
  check('calc:sumRange_empty', () => { if (sumRange(4, 1) !== 0) throw new Error('sumRange(4,1) !== 0'); if (sumRange(0, 0) !== 0) throw new Error('sumRange(0,0) !== 0'); });
  return results;
}

/** The two T2 tests. They throw on the shipped stub, which is the honest state. */
function t2Tests() {
  const results = [];
  const check = (id, fn) => {
    try {
      fn();
      results.push({ id, passed: true });
    } catch (error) {
      results.push({ id, passed: false, detail: String(error?.message ?? error).slice(0, 160) });
    }
  };
  check('parse:parsePairs', () => {
    const parsed = parsePairs('a=1, b = 2');
    if (Object.getPrototypeOf(parsed) !== null) throw new Error('the result must have a null prototype');
    if (JSON.stringify({ ...parsed }) !== JSON.stringify({ a: '1', b: '2' })) throw new Error('parsePairs did not split and trim');
    if (Object.keys({ ...parsePairs('a=1,broken,__proto__=x') }).join(',') !== 'a') throw new Error('a malformed segment must be ignored');
  });
  check('parse:round_trip', () => {
    const source = { a: '1', b: 'x,y=z' };
    const round = { ...parsePairs(renderPairs(source)) };
    if (JSON.stringify(round) !== JSON.stringify({ a: '1', b: 'x,y=z' })) throw new Error(`the round trip lost data: ${JSON.stringify(round)}`);
  });
  return results;
}

const T1 = () => preExistingTests();
const T2 = () => t2Tests();
// T3 is behaviour-preserving BY DEFINITION: its criterion is that T1's and T2's
// criteria still hold after the refactor. There is no other thing it could mean.
const T3 = () => [...preExistingTests(), ...t2Tests()];

const TASKS = Object.freeze({ T1, T2, T3 });
const DESCRIPTIONS = Object.freeze({
  T1: 'fix the off-by-one in sumRange; the five pre-existing tests pass and sumRange(1,4) === 10',
  T2: 'implement parsePairs and renderPairs to the contract in src/parse.js',
  T3: 'refactor src/calc.js with no observable behaviour change; T1 and T2 still hold',
});

const taskId = process.argv[2] ?? null;
if (taskId === null || !Object.prototype.hasOwnProperty.call(TASKS, taskId)) {
  process.stdout.write(`${JSON.stringify({
    oracle: 's2-007r-project-oracle-v1',
    ok: false,
    error: 'TASK_UNKNOWN',
    known_tasks: Object.keys(TASKS),
  })}\n`);
  process.exit(2);
}

const checks = TASKS[taskId]();
const failed = checks.filter((row) => row.passed !== true);
const digestMap = projectDigest(HERE);
const projectDigestValue = `sha256:${canonicalDigest(digestMap)}`;
process.stdout.write(`${JSON.stringify({
  oracle: 's2-007r-project-oracle-v1',
  task_id: taskId,
  criterion: DESCRIPTIONS[taskId],
  ok: failed.length === 0,
  checks,
  passed: checks.length - failed.length,
  failed: failed.length,
  project_digest: projectDigestValue,
  project_files: Object.keys(digestMap).length,
  project_bytes: Object.values(digestMap).reduce((sum, row) => sum + row.bytes, 0),
  file_digests: digestMap,
})}\n`);
process.exit(failed.length === 0 ? 0 : 1);
