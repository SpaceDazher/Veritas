#!/usr/bin/env node
// S2-002 counter isolation diagnostic.
//
// PURPOSE
// A Windows run of the S2-002 corpus at commit 6a53358 reports
// `fs_network_secret_escapes = 1` and `survivors_after_cancellation = 1`, while
// the committed Windows evidence records 0 and 0. This tool isolates WHICH
// observation produces each non-zero counter, and whether that observation is
// new or was always there. It changes nothing: it refuses to write anywhere
// near evidence/ or results/, and it proves the canonical tree is byte-identical
// before and after.
//
//   node scripts/diagnose-s2-002-counters.mjs
//   node scripts/diagnose-s2-002-counters.mjs --ab            # also run the pre-change tree
//   VERITAS_DIAG_OUT=/tmp/x node scripts/diagnose-s2-002-counters.mjs
//
// What it prints
//   1. the oracle (trial count + digest) and whether it is the committed one;
//   2. every observation with match === false, in full, per run;
//   3. the cancellation trial's full record and how the counter was derived;
//   4. which sandbox controls were not exercised on this platform;
//   5. the counter table, with the contributing observation named for each
//      non-zero value;
//   6. for --ab: the same for the pre-change tree, so a host difference and a
//      code difference can be told apart.
//
// Exit 0 means the diagnostic ran; it is NOT a pass verdict. A non-zero hard
// counter is a finding to investigate, never a downgrade.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildExpectedCorpusOracle } from './s2-002-run.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const COMMITTED_ORACLE_DIGEST = 'a5a63dc0c53c29bcd10003a31179342bc1f3a2fbe0fb39b6c69dbb5ee3eeb7e0';

// The three files this ticket changed in the S2-002 surface. The --ab mode
// restores their PRE-change content into a throwaway copy of the tree so the
// same host can be measured both ways.
const CHANGED_FILES = Object.freeze([
  'src/lib/identity/sandbox.mjs',
  'scripts/s2-002-run.mjs',
  'scripts/verify-s2-002.mjs',
]);
const BASE_REF = '8f6254db1be3eb9a3c886ef41465314bf8e797c8';

const args = process.argv.slice(2);
const doAb = args.includes('--ab');
const OUT = process.env.VERITAS_DIAG_OUT
  ?? fs.mkdtempSync(path.join(os.tmpdir(), 's2-002-diag-'));

// Never inside the canonical directories, whatever the caller asks for.
const canonical = [path.join(ROOT, 'evidence'), path.join(ROOT, 'results')];
for (const dir of canonical) {
  if (path.resolve(OUT).startsWith(`${dir}${path.sep}`) || path.resolve(OUT) === dir) {
    console.error(`REFUSING: --out would write into ${dir}`);
    process.exit(2);
  }
}

function gitOut(...a) {
  return spawnSync('git', a, { cwd: ROOT, encoding: 'utf8', windowsHide: true });
}

/** SHA-256 of every canonical evidence/results file, so we can prove we did not touch it. */
function canonicalFingerprint() {
  const out = new Map();
  const files = gitOut('ls-files', 'evidence', 'results');
  if (files.status !== 0) return out;
  for (const rel of files.stdout.split('\n').filter(Boolean)) {
    try {
      out.set(rel, createHash('sha256').update(fs.readFileSync(path.join(ROOT, rel))).digest('hex'));
    } catch { /* a file may be absent in an archive; skip it */ }
  }
  return out;
}

function reportFingerprintChange(before, after) {
  const changed = [];
  for (const [file, sha] of after) if (before.get(file) !== sha) changed.push(file);
  for (const file of before.keys()) if (!after.has(file)) changed.push(file);
  if (changed.length > 0) {
    console.error(`\nCANONICAL EVIDENCE CHANGED (${changed.length}) — this diagnostic must never do that:`);
    for (const file of changed.slice(0, 20)) console.error(`  ${file}`);
    return false;
  }
  return true;
}

function runCorpus(label, cwd, runId) {
  const outputRoot = path.join(OUT, label);
  const result = spawnSync(process.execPath, [
    path.join(cwd, 'scripts', 's2-002-run.mjs'),
    '--run-id', runId,
    '--executor-id', `diag-${label}`,
    '--nonce-base', `nb-diag-${label}`,
    '--output-root', outputRoot,
  ], { cwd, encoding: 'utf8', windowsHide: true, timeout: 600000 });
  if (result.status !== 0) {
    console.error(`  corpus run "${label}" failed: ${String(result.stderr ?? '').split('\n')[0]}`);
    return null;
  }
  const observations = JSON.parse(fs.readFileSync(path.join(outputRoot, 'observations.json'), 'utf8'));
  const summary = JSON.parse(fs.readFileSync(path.join(outputRoot, 'summary.json'), 'utf8'));
  return { label, cwd, runId, outputRoot, observations, summary };
}

function describe(label, run) {
  const { observations, summary } = run;
  console.log(`\n${'='.repeat(78)}\n${label}\n${'='.repeat(78)}`);
  console.log(`  platform        : ${summary.platform ?? 'unknown'}`);
  console.log(`  trials executed : ${observations.length}`);
  console.log(`  oracle trials   : ${summary.oracleTrialCount ?? buildExpectedCorpusOracle().trialCount}`);

  // 1. every observation that did not match, in full — this is the whole point.
  const mismatches = observations.filter((o) => o.match === false);
  console.log(`\n  -- observations with match === false: ${mismatches.length} --`);
  for (const o of mismatches) {
    console.log(`     trialId   : ${o.trialId}`);
    console.log(`     kind      : ${o.kind}`);
    console.log(`     expected  : ${JSON.stringify(o.expected)}`);
    console.log(`     observed  : ${JSON.stringify(o.observed)}`);
    console.log(`     decision  : ${o.decision}`);
    console.log(`     reasonCodes: ${JSON.stringify(o.reasonCodes)}`);
    if ('survivors' in o) console.log(`     survivors : ${JSON.stringify(o.survivors)}`);
    console.log(`     full      : ${JSON.stringify(o)}`);
  }

  // 2. the not-run controls, so an honest skip is never read as a measurement.
  const notRun = observations.filter((o) => o.notRun === true);
  console.log(`\n  -- controls NOT exercised on this platform: ${notRun.length} --`);
  for (const o of notRun) {
    console.log(`     ${o.trialId}: observed=${JSON.stringify(o.observed)} decision=${o.decision} ` +
      `reasonCodes=${JSON.stringify(o.reasonCodes)} survivors=${JSON.stringify(o.survivors ?? null)}`);
  }

  // 3. the cancellation control in full, with how the counter came from it.
  const cancellation = observations.filter((o) => o.trialId === 'sandbox/cancellation-survivors');
  console.log(`\n  -- cancellation control --`);
  if (cancellation.length === 0) {
    console.log('     ABSENT from the run (it is pushed unconditionally, so this is itself a finding)');
  }
  for (const o of cancellation) console.log(`     ${JSON.stringify(o)}`);

  // 4. the counter table, each non-zero value traced to its observations.
  console.log(`\n  -- counters --`);
  for (const [name, value] of Object.entries(summary.counters ?? {})) {
    const flag = typeof value === 'number' ? (value > 0 ? '  <== NON-ZERO' : '') : (value === null ? '  (unmeasured)' : '');
    console.log(`     ${name.padEnd(32)} ${JSON.stringify(value)}${flag}`);
  }
  const escapeContributors = mismatches.filter((o) => o.kind === 'sandbox');
  console.log(`\n  fs_network_secret_escapes contributors (sandbox, match===false): ${escapeContributors.length}`);
  for (const o of escapeContributors) {
    console.log(`     ${o.trialId}: expected ${JSON.stringify(o.expected)} observed ${JSON.stringify(o.observed)}`);
  }
  return { label, counters: summary.counters ?? {}, mismatches: mismatches.map((o) => o.trialId), platform: summary.platform };
}

// ---------------------------------------------------------------------------

const fingerprintBefore = canonicalFingerprint();
console.log(`diagnostic output root: ${OUT}`);
console.log(`canonical evidence fingerprint: ${fingerprintBefore.size} files (must not change)`);

const oracle = buildExpectedCorpusOracle();
console.log(`\noracle: ${oracle.trialCount} trials, digest ${oracle.digest}`);
console.log(`committed oracle digest: ${COMMITTED_ORACLE_DIGEST}`);
console.log(`oracle MATCHES the committed one: ${oracle.digest === COMMITTED_ORACLE_DIGEST ? 'yes' : 'NO — a finding'}`);

const current = runCorpus('current', ROOT, 'diag-current');
if (current === null) {
  console.error('\nthe corpus run did not complete; nothing can be concluded');
  process.exit(1);
}
const results = [describe('CURRENT TREE (this commit)', current)];

if (doAb) {
  // Build a throwaway copy of the tree with the three changed files restored to
  // their pre-change content, so the same host is measured both ways. The copy
  // is OUTSIDE the repository, so the canonical tree is never at risk.
  const abRoot = path.join(OUT, 'ab-tree');
  fs.rmSync(abRoot, { recursive: true, force: true });
  const tracked = gitOut('ls-files');
  for (const rel of tracked.stdout.split('\n').filter(Boolean)) {
    const dest = path.join(abRoot, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(ROOT, rel), dest);
  }
  let restored = 0;
  for (const rel of CHANGED_FILES) {
    const blob = gitOut('show', `${BASE_REF}:${rel}`);
    if (blob.status !== 0) {
      console.error(`  cannot read ${rel} at ${BASE_REF}: ${String(blob.stderr).split('\n')[0]}`);
      continue;
    }
    fs.writeFileSync(path.join(abRoot, rel), blob.stdout);
    restored += 1;
  }
  // The A/B copy needs its dependencies resolvable, or the runner cannot import
  // ajv/pg. Linking the installed tree is safe: the copy is outside the repo and
  // nothing is written through the link.
  const abModules = path.join(abRoot, 'node_modules');
  if (!fs.existsSync(abModules)) {
    try {
      fs.symlinkSync(path.join(ROOT, 'node_modules'), abModules, 'junction');
    } catch (error) {
      console.error(`  cannot link node_modules into the A/B tree: ${String(error.message).split('\n')[0]}`);
      console.error('  the A/B leg cannot run; the current-tree leg above is still complete');
    }
  }
  console.log(`\nA/B tree built at ${abRoot} (${restored}/${CHANGED_FILES.length} files restored to ${BASE_REF.slice(0, 7)})`);
  console.log(`node_modules resolvable: ${fs.existsSync(abModules) ? 'yes' : 'NO'}`);
  const ab = runCorpus('pre-change', abRoot, 'diag-pre-change');
  if (ab !== null) {
    results.push(describe(`PRE-CHANGE TREE (${BASE_REF.slice(0, 7)}) — same host`, ab));
  }
}

console.log(`\n${'='.repeat(78)}\nSIDE BY SIDE\n${'='.repeat(78)}`);
for (const [name, value] of results[0].counters ? Object.entries(results[0].counters) : []) {
  const other = results[1]?.counters?.[name];
  const verdict = other === undefined ? '—' : (JSON.stringify(value) === JSON.stringify(other) ? 'same' : 'DIFFERS');
  console.log(`  ${name.padEnd(32)} ${String(JSON.stringify(value)).padEnd(12)} pre-change=${String(JSON.stringify(other)).padEnd(12)} ${verdict}`);
}
console.log(`\n  mismatching trials, current : ${JSON.stringify(results[0].mismatches)}`);
if (results[1]) console.log(`  mismatching trials, pre-change: ${JSON.stringify(results[1].mismatches)}`);

const fingerprintAfter = canonicalFingerprint();
const intact = reportFingerprintChange(fingerprintBefore, fingerprintAfter);
console.log(`\ncanonical evidence unchanged by this diagnostic: ${intact ? 'YES' : 'NO'}`);
console.log('DIAGNOSTIC ONLY — this is not a pass verdict. A non-zero hard counter stays a finding.');
process.exit(intact ? 0 : 1);
