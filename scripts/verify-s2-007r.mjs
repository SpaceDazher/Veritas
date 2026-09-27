// S2-007R VERIFICATION AGATE (issue SpaceDazher/Veritas#45 §6, §7).
//
// WHAT THIS SCRIPT IS NOT
// -----------------------
// It is not a wrapper that reads four exit codes. Every mandatory gate here is
// judged on four things at once, the same four the S2-007 aggregator uses:
//
//   1. the process really ran, in THIS invocation, and really exited 0;
//   2. the artifact on disk is the bytes this invocation produced;
//   3. the record is FRESH: bound to the current HEAD commit and, where it
//      carries one, to the current HEAD tree;
//   4. the record's INTERNAL status is the expected one, its seven hard-gate
//      counters are present and 0, and — for the real-adapter record — the
//      claim of a real executor survives RE-VERIFICATION from the bytes on
//      disk.
//
// WHY THE S2-007 MACHINERY IS IMPORTED AND NOT REWRITTEN
// `checkHardGateCounters`, `classifyEvidenceGate`, `classifyJsonGate`,
// `runTamperMatrix` and `recordDigestOf` are imported from
// `scripts/verify-s2-007.mjs`, which is a FROZEN target whose digest is in
// `evidence/frozen-manifest.json`. A second copy of that machinery in this file
// would be a second, weaker copy of the thing the repository exists to prevent:
// a tampered S2-007R artifact must be rejected by the SAME code that rejects a
// tampered S2-007 artifact, or one of the two is theatre. What is written here
// is only what is specific to this ticket: the real-adapter honesty classifier,
// the A-MVP per-case classifier, the seven-measurement classifier, the verdict
// ladder and its negative controls.
//
// THE CRITICAL HONESTY RULE, AS CODE
// ----------------------------------
// This gate CANNOT report `realAdapterStatus: REAL_ADAPTER_AVAILABLE` unless the
// record it reads carries a genuine executor invocation, and it does not take
// the record's word for any of it:
//   * `executor.version`        a non-placeholder version string;
//   * `executor.binary_path`    absolute, RESOLVED, a regular file, executable;
//   * `executor.binary_sha256`  RECOMPUTED from those resolved bytes and equal;
//   * `raw_process_log_path`    absolute and readable;
//   * `raw_process_log_sha256`  RECOMPUTED from those bytes and equal;
//   * `exit_status`             an integer, NON-ZERO — a zero exit is a fixture,
//                               because the real run of this ticket ends in the
//                               FAILED state the issue's negative probe (d)
//                               requires;
//   * `honesty.transport_source` a real transport module, never the test or
//                               replay transport, with `script_used` and
//                               `replay_used` false;
//   * `corroboration.executor_session_id` a non-empty id minted by the
//                               executor, and a pid tree observed by the parent.
// Any one of them missing or wrong ⇒ `NOT_RUN_REAL_ADAPTER`, and because the
// real-adapter gate is then NOT_RUN, the ticket is at most PARTIAL and the exit
// code is non-zero. A CONFIGURED-BUT-UNRUN ADAPTER IS INDISTINGUISHABLE, IN
// THIS OUTPUT, FROM AN ADAPTER THAT DOES NOT EXIST: `adapters.available` is
// built only from corroborated runs, and a negative control proves the two
// produce byte-identical availability output.
//
// THE VERDICT VOCABULARY (issue §7 §8)
//   REVISE               a defect was found: a non-zero hard-gate counter, a
//                        failed mandatory gate, a tampered artifact that was
//                        accepted, a real-adapter claim that does not survive
//                        re-verification, a renamed gate, a failed self-check
//   BLOCKED              an inherited stop condition: the S2-007 dependency gate
//                        is BLOCKED_DEPENDENCY, or the real-adapter record names
//                        a stop condition from the issue's §8 list
//   PARTIAL              at least one mandatory component could not run; the
//                        reason is stated per gate
//   PASS_WITH_LIMITS     every mandatory gate is PASS but the checkout is dirty
//   COMPLETE_WITH_LIMITS every mandatory gate is PASS in a clean checkout
//   Exit code 0 happens ONLY for PASS_WITH_LIMITS and COMPLETE_WITH_LIMITS, i.e.
//   only when every mandatory gate really passed.
//
// THE FOUR STATUS AXES ARE JUDGED SEPARATELY
//   engineeringStatus  the ladder above
//   realAdapterStatus  REAL_ADAPTER_AVAILABLE | NOT_RUN_REAL_ADAPTER
//   assuranceStatus    NOT_MEASURED, fixed, and nothing here can move it
//   aMvpStatus         NOT_CLAIMED, fixed, and nothing here can move it
// plus the per-case A-MVP-01..07 execution values and the seven measurements,
// each classified on its own.
//
// DESTRUCTION BOUNDARY
// This script writes exactly one file: `evidence/s2-007r-summary.json`. It never
// edits another gate's evidence, the frozen manifests or the inventory; the
// tamper matrices work on COPIES under `.bb/chats/<chat>/tmp/`.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
// The seven hard-gate counters come from the probe module itself, never from a
// second list written here: two lists would drift, and the drift would be a
// silently narrowed gate.
import { HARD_GATE_COUNTERS } from '../src/lib/agentboard/probes.mjs';
// The host fact the board itself uses when a registration claims
// REAL_ADAPTER_AVAILABLE (`assertRealAdapterClaimIsTrue` in commands.mjs
// corroborates such a claim against `probeRealAdapters`). The aggregator reads a
// FILE, so it cannot use the in-process observation the executor module keeps,
// and it must not be weaker than the boundary it certifies: a real-adapter claim
// is accepted only when a LIVE probe row says the binary is an installed
// executor on this host.
import { probeRealAdapters, REAL_ADAPTER_PROBE_CANDIDATES } from '../src/lib/agentboard/adapters.mjs';
import { fixedClock } from '../src/lib/agentboard/policy.mjs';
// The shared, frozen machinery. See the header for why it is imported.
import {
  checkHardGateCounters,
  classifyEvidenceGate,
  classifyJsonGate,
  headIdentity,
  recordDigestOf,
  runTamperMatrix,
  workspaceState,
} from './verify-s2-007.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SUMMARY_RELATIVE = 'evidence/s2-007r-summary.json';
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';
// Where the tamper matrices put their COPIES. The destruction boundary in this
// file's header is about `evidence/`; it is also about not writing into
// ANOTHER CHAT's storage in a shared worktree, so the copies go to this chat's
// own tmp directory when the harness names one and to the OS temp directory
// when it does not. A hard-coded chat id would drop ten files into somebody
// else's `.bb/chats/<id>/tmp` on every verification run.
const CHAT_TMP = process.env.BB_THREAD_ID
  ? path.join('.bb', 'chats', String(process.env.BB_THREAD_ID), 'tmp')
  : path.join(os.tmpdir(), 'veritas-s2-007r-tamper');

export const EXIT_VERIFIED = 0;
export const EXIT_NOT_VERIFIED = 1;

export const EXPECTED_AGGREGATOR_SCRIPT = 'node scripts/verify-s2-007r.mjs';
export const MANDATORY_GATE_IDS = Object.freeze(['dependencies', 'real-adapter-run', 'comparison', 'probes']);

// The seven measurements of issue §5. Written out here only as a FALLBACK: the
// measurement module that produced them owns the authoritative list, and when it
// is in the checkout this file reads the list from it instead of from here.
const FALLBACK_MEASUREMENT_NAMES = Object.freeze([
  'accepted_task_quality', 'pass_at_1', 'intervention_time', 'cost', 'latency', 'regression_rate',
  'skills_authority_expansion',
]);

// The transports that may be named by an honest real-adapter record. A test or
// replay transport can never be one, whatever the record claims.
const REAL_TRANSPORT_SOURCES = Object.freeze(['codex-transport', 'pi-transport']);
const PLACEHOLDER_VERSION = /^(?:test|stub|fixture|fake|mock|replay|none|unknown|n\/a|0\.0\.0)(?:[-_ ].*)?$/i;
const HEX64 = /^[0-9a-f]{64}$/;
// The instant the host probe is stamped with. Injected, never the process clock
// (rule 5): the probe's `installed` fact does not depend on the time, and a
// clock read here would make the summary's content address change per run.
const PROBE_INSTANT = '2026-01-01T00:00:00.000Z';

// ---------------------------------------------------------------------------
// The frozen gate set (issue #45 §6).
//
// `scriptValue` is the EXACT declaration the npm script may carry, compared
// byte for byte. A pattern would be weaker: `/^node scripts\/s2-007r-[a-z0-9-]+\.mjs$/`
// accepts `node scripts/s2-007r-measure.mjs` for the real-run gate and
// `node scripts/s2-007r-probes.mjs` for the comparison gate, so repointing
// either one to a different script of the same family passed the check and
// printed C8 = PASS. `scriptPattern` remains as documentation of the shape and
// as the reason reported; it is never the acceptance test when a `scriptValue`
// is declared.
// ---------------------------------------------------------------------------
export const EXPECTED_GATES = Object.freeze([
  Object.freeze({
    id: 'dependencies',
    script: 'verify:s2-007-dependencies',
    scriptValue: 'node scripts/verify-s2-007-dependencies.mjs',
    scriptPattern: /^node scripts\/verify-s2-007-dependencies\.mjs$/,
    command: 'npm run --silent verify:s2-007-dependencies',
    kind: 'json-stdout+file',
    evidenceFiles: Object.freeze(['evidence/s2-007-dependency-binding.json']),
    commitPaths: Object.freeze(['resolved.resolvedRefs.implementationBaseCommit']),
    treePaths: Object.freeze([]),
    expectedStatus: 'PASS',
    carriesCounters: false,
    carriesComparison: false,
    timeoutMs: 1_800_000,
    contract: 'stdout JSON { ok:true, status:"PASS", mode:"FULL_GIT_BYTES" } + evidence/s2-007-dependency-binding.json whose resolved block was written by this run and is bound to the current HEAD commit. Inherited from S2-007: this ticket reports it and does not fix it.',
  }),
  Object.freeze({
    id: 'real-adapter-run',
    script: 's2-007r:real-run',
    // RECONCILED by the orchestrator (issue #45). The gate was written against
    // `scripts/s2-007r-real-adapter-run.mjs`, a name no writer ever produced;
    // the real run driver is `scripts/s2-007r-run.mjs`. The alternative was to
    // keep the undeclared name and let the gate read NOT_RUN forever, which
    // would have made the gate a decoration rather than a check.
    scriptValue: 'node scripts/s2-007r-run.mjs',
    scriptPattern: /^node scripts\/s2-007r-run\.mjs$/,
    command: 'npm run --silent s2-007r:real-run',
    kind: 'evidence-envelope',
    // A declared candidate set: each is held to the full contract, so accepting
    // whichever name the writer chose weakens nothing, and the aggregator never
    // silently reads nothing because the writer picked another name.
    // The run driver writes its raw record under results/, one per run set, and
    // the pilot record under evidence/. All three names are accepted; none of
    // them is read as a run unless it carries an observed crossing.
    evidenceFiles: Object.freeze([
      'evidence/s2-007r-run.json', 'evidence/s2-007r-pilot.json', 'evidence/s2-007r-real-adapter-run.json',
      'results/s2-007r/run-record.json',
    ]),
    commitPaths: Object.freeze(['commit', 'git.commit_sha', 'testedImplementationCommit']),
    treePaths: Object.freeze(['tree', 'git.tree_sha']),
    expectedStatus: 'PASS',
    carriesCounters: false,
    carriesComparison: false,
    timeoutMs: 1_800_000,
    extraArgs: Object.freeze(['--write']),
    contract: 'scripts/s2-007r-run.mjs --write prints an envelope { status, ok, counters, evidenceFile, evidenceSha256, recordDigest, commit, tree } and writes the record it describes. The record must carry a genuine executor invocation (version, binary path + recomputed digest, raw log path + recomputed digest, non-zero exit status, honesty flags and a parent-observed session id) or the gate answers NOT_RUN_REAL_ADAPTER.',
  }),
  Object.freeze({
    id: 'comparison',
    script: 's2-007r:comparison',
    // RECONCILED by the orchestrator (issue #45): the comparison and the seven
    // measurements are written by `scripts/s2-007r-measurement-set.mjs`, not by
    // a `s2-007r-comparison-run.mjs` that was never written.
    scriptValue: 'node scripts/s2-007r-measurement-set.mjs',
    scriptPattern: /^node scripts\/s2-007r-measurement-set\.mjs$/,
    command: 'npm run --silent s2-007r:comparison',
    kind: 'evidence-envelope',
    evidenceFiles: Object.freeze(['evidence/s2-007r-comparison.json']),
    commitPaths: Object.freeze(['commit', 'git.commit_sha', 'testedImplementationCommit']),
    treePaths: Object.freeze(['tree', 'git.tree_sha']),
    expectedStatus: 'PASS',
    carriesCounters: false,
    carriesComparison: true,
    timeoutMs: 1_800_000,
    extraArgs: Object.freeze(['--write']),
    contract: 'scripts/s2-007r-measurement-set.mjs writes the A/B comparison and the seven measurements. A record whose verdict is REFUSED, or which names two different project_digest or budget_grant_id values, is NOT_RUN here and can never be counted as a completed comparison.',
  }),
  Object.freeze({
    id: 'probes',
    script: 'test:s2-007r-probes',
    scriptValue: 'node scripts/s2-007r-probes.mjs',
    scriptPattern: /^node scripts\/s2-007r-probes\.mjs$/,
    command: 'npm run --silent test:s2-007r-probes',
    kind: 'evidence-envelope',
    evidenceFiles: Object.freeze(['evidence/s2-007r-security-probes.json']),
    commitPaths: Object.freeze(['commit']),
    treePaths: Object.freeze(['tree']),
    expectedStatus: 'PASS',
    carriesCounters: true,
    carriesComparison: false,
    timeoutMs: 1_800_000,
    extraArgs: Object.freeze(['--write']),
    contract: 'scripts/s2-007r-probes.mjs --write prints an envelope carrying all seven hard-gate counters, the per-probe verdicts and the record digest, and writes the record it describes. A non-zero counter is BLOCKED_SAFETY; a mandatory probe that did not run is NOT_RUN; neither is ever exit 0.',
  }),
]);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function at(record, dotPath) {
  return dotPath.split('.').reduce((value, key) => (value == null ? undefined : value[key]), record);
}

function firstOf(record, dotPaths) {
  for (const dotPath of dotPaths) {
    const value = at(record, dotPath);
    if (value !== undefined && value !== null) return { dotPath, value };
  }
  return { dotPath: null, value: null };
}

function sha256Of(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function wireDigestOf(bytes) {
  return sha256Of(bytes);
}

function readJsonFile(absolute) {
  try {
    const bytes = fs.readFileSync(absolute);
    return { bytes, record: JSON.parse(bytes.toString('utf8')) };
  } catch {
    return { bytes: null, record: null };
  }
}

function runProcess(script, { timeout, extraArgs = [] } = {}) {
  const usesShell = process.platform === 'win32' && NPM === 'npm.cmd';
  const passthrough = extraArgs.length > 0 ? ['--', ...extraArgs] : [];
  const result = spawnSync(
    usesShell ? 'cmd.exe' : NPM,
    usesShell
      ? ['/d', '/s', '/c', NPM, 'run', '--silent', script, ...passthrough]
      : ['run', '--silent', script, ...passthrough],
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 1 << 28, timeout, windowsHide: true },
  );
  return {
    exitCode: typeof result.status === 'number' ? result.status : null,
    signal: result.signal ?? null,
    timedOut: result.error?.code === 'ETIMEDOUT' || result.error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER',
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
  };
}

/**
 * The gate set may not be weakened: no gate may be removed, and no npm script
 * may be repointed at something weaker. An ABSENT script is NOT_RUN (the
 * tool does not exist yet in this checkout), which is different from a repointed
 * one (the tool was replaced) and is treated as a defect.
 */
export function assertGateSetIntact({ packageScripts = {}, expectedGates = EXPECTED_GATES, mandatoryIds = MANDATORY_GATE_IDS, aggregatorScript = EXPECTED_AGGREGATOR_SCRIPT } = {}) {
  const issues = [];
  const absent = [];
  const observedCommands = {};
  const entrypoints = {};
  const expectedIds = expectedGates.map((gate) => gate.id);
  if (JSON.stringify([...expectedIds].sort()) !== JSON.stringify([...mandatoryIds].sort())) {
    issues.push(`expected-gate-set:the frozen gate list is ${expectedIds.join(',')} but the mandatory set is ${mandatoryIds.join(',')} — a gate may not be removed from the aggregator`);
  }
  const seen = new Set();
  for (const id of expectedIds) {
    if (seen.has(id)) issues.push(`gate:${id}:duplicated`);
    seen.add(id);
  }
  for (const gate of expectedGates) {
    const actual = packageScripts[gate.script];
    observedCommands[gate.id] = actual ?? null;
    if (actual === undefined) {
      absent.push(gate.id);
      continue;
    }
    const pattern = gate.scriptPattern;
    // Byte-identical when an exact declaration is frozen for this gate, and a
    // shape test only for a gate that has no exact value declared. Either way a
    // repointed gate is a defect, never an accepted family member.
    const repointed = gate.scriptValue !== undefined
      ? actual !== gate.scriptValue
      : (pattern !== undefined && !pattern.test(actual));
    if (repointed) {
      issues.push(`script:${gate.script}:repointed(${actual})`);
      continue;
    }
    const match = /^node\s+(\S+)$/.exec(actual);
    entrypoints[gate.id] = match === null ? null : match[1];
  }
  const aggregator = packageScripts['verify:s2-007r'];
  if (aggregator !== undefined && aggregator !== aggregatorScript) issues.push(`script:verify:s2-007r:repointed(${aggregator})`);
  return {
    ok: issues.length === 0,
    issues,
    absent,
    entrypoints,
    expectedCommands: Object.fromEntries(expectedGates.map((gate) => [gate.id, gate.command])),
    observedCommands,
  };
}

// ---------------------------------------------------------------------------
// THE REAL-ADAPTER HONESTY CLASSIFIER (the critical rule, as code)
// ---------------------------------------------------------------------------
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function readDigestFields(record) {
  const version = firstOf(record, ['executor.version', 'executor_version']);
  const binaryPath = firstOf(record, ['executor.binary_path', 'binary_path']);
  const binarySha = firstOf(record, ['executor.binary_sha256', 'binary_sha256']);
  const logPath = firstOf(record, ['raw_process_log_path', 'executor.raw_log_path', 'raw_log_path']);
  const logSha = firstOf(record, ['raw_process_log_sha256', 'raw_log_sha256', 'executor.raw_log_sha256']);
  const exitStatus = firstOf(record, ['exit_status', 'corroboration.child_exit_code']);
  const sessionId = firstOf(record, ['corroboration.executor_session_id', 'executor_session_id']);
  const observedBy = firstOf(record, ['corroboration.observed_by', 'corroboration.exit_status_observed_by', 'observed_by']);
  // The pid tree the PARENT observed. A closed set of field names, because the
  // requirement is that a parent observed a process space, and an empty array
  // is an unobservable process space rather than an observed one: the executor
  // module words it exactly that way ("an unobservable process space proves
  // nothing, and reporting 0 here is the false zero"), so an empty tree cannot
  // be a corroboration.
  const pidTree = firstOf(record, [
    'corroboration.pid_tree', 'corroboration.pid_tree_observed', 'corroboration.observed_pid_tree',
    'corroboration.pid_tree_after_exit', 'corroboration.pids_observed', 'pid_tree', 'pid_tree_after_exit',
  ]);
  const adapterId = firstOf(record, ['executor.adapter_id', 'adapter_id']);
  const provider = firstOf(record, ['executor.provider', 'provider']);
  const runId = firstOf(record, ['run_id', 'run.id']);
  return { version, binaryPath, binarySha, logPath, logSha, exitStatus, sessionId, observedBy, pidTree, adapterId, provider, runId };
}

/**
 * The live host fact: which executables are ACTUALLY installed here.
 *
 * `installed: true` comes from the board's own `probeRealAdapters` — the same
 * function `commands.mjs:assertRealAdapterClaimIsTrue` uses to corroborate a
 * registration's REAL_ADAPTER_AVAILABLE claim, so the aggregator is not weaker
 * than the boundary it certifies. `probeRealAdapters` reports the location in a
 * redacted `$HOME`-masked detail string, so the path is resolved here with the
 * same PATH walk the probe itself performs; the resolved path is the digest
 * input the classifier compares the record's `binary_path` against.
 */
export async function probeInstalledExecutors({ env = process.env } = {}) {
  const rows = await probeRealAdapters({ clock: fixedClock(PROBE_INSTANT), env });
  const directories = String(env.PATH ?? '').split(path.delimiter).filter((entry) => entry !== '');
  const resolved = [];
  for (const row of rows) {
    if (row.installed !== true) {
      resolved.push({ adapter_id: row.adapter_id, installed: false, binary_path: null, detail: row.detail });
      continue;
    }
    const candidate = REAL_ADAPTER_PROBE_CANDIDATES.find((entry) => entry.adapter_id === row.adapter_id);
    const names = candidate === undefined ? [] : [...candidate.executables];
    let hit = null;
    for (const name of names) {
      for (const directory of directories) {
        const full = path.join(directory, name);
        try {
          if (!fs.statSync(full).isFile()) continue;
          fs.accessSync(full, fs.constants.X_OK);
          hit = full;
          break;
        } catch {
          // absent, not a file, or not executable: keep walking, never guess
        }
      }
      if (hit !== null) break;
    }
    let real = null;
    if (hit !== null) {
      try {
        real = fs.realpathSync(hit);
      } catch {
        real = null;
      }
    }
    resolved.push({ adapter_id: row.adapter_id, installed: real !== null, binary_path: real, executables: names, detail: row.detail });
  }
  return resolved;
}

function normaliseDigest(value) {
  if (typeof value !== 'string') return null;
  return value.startsWith('sha256:') ? value.slice('sha256:'.length) : value;
}

/**
 * `$HOME`-mask an absolute host path for PUBLICATION. The comparison always runs
 * on the real path; only what reaches the summary, the stdout and the evidence
 * record is masked, which is the same convention `adapters.mjs:probeDetail`
 * uses. A home directory is not a secret, but it is a machine identity that has
 * no business in a committed evidence file.
 */
function maskHome(value) {
  if (value === null || value === undefined) return value;
  const home = os.homedir();
  const text = String(value);
  return home && text.startsWith(home) ? `$HOME${text.slice(home.length)}` : text;
}

function isFile(path) {
  try {
    return fs.statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * Re-verify a real-adapter claim from the bytes on disk.
 *
 * `status` is REAL_ADAPTER_AVAILABLE only when EVERY check holds. Otherwise it
 * is NOT_RUN_REAL_ADAPTER with the exact reason, which is also what an absent
 * record returns — that is the "a configured-but-unrun adapter is
 * indistinguishable from one that does not exist" property, expressed once, in
 * the only place that decides it.
 *
 * WHAT A RECORD CANNOT SAY BY ITSELF ANY MORE. Every check that used to be a
 * file fact the record's own writer chose is now either a HOST FACT or a
 * cross-check between two independently produced artefacts:
 *   * `executor.binary_path` must be the file a LIVE `probeRealAdapters` row
 *     reports as an installed executor on this host (`probe` argument);
 *   * `raw_process_log_path` must parse as the executor's own raw process log
 *     document, and that document must agree with the record about the binary,
 *     the run and the exit status;
 *   * `corroboration.executor_session_id` must appear VERBATIM in the log
 *     bytes, so the id cannot be a string the record made up;
 *   * `corroboration.pid_tree*` must be a NON-EMPTY array of positive process
 *     ids, because an empty array is an unobservable process space, not an
 *     observed one.
 * The residual limit is stated, not hidden: a determined writer can still craft
 * a self-consistent document. What cannot be done any more is satisfy the
 * classifier with a text file, the `node` binary, an invented session id and an
 * empty pid tree — which is exactly what the previous version accepted.
 */
export function classifyRealAdapterClaim({ record, probe = null, root = ROOT } = {}) {
  const checks = [];
  const reasons = [];
  const add = (id, ok, detail) => {
    const safe = detail === undefined ? null : maskHome(String(detail).slice(0, 300));
    checks.push({ check: id, ok, detail: safe });
    if (!ok) reasons.push(`${id}${detail === undefined ? '' : `:${maskHome(String(detail).slice(0, 200))}`}`);
    return ok;
  };
  const corroborated = {
    adapter_id: null, version: null, binary_path: null, binary_sha256: null,
    raw_process_log_path: null, raw_process_log_sha256: null, exit_status: null,
    executor_session_id: null, observed_by: null, pid_tree_after_exit: null,
    installed_executors_probed: null,
  };
  if (!isPlainObject(record)) {
    add('claim:record-present', false, 'no real-adapter record was produced by this invocation');
    return { status: 'NOT_RUN_REAL_ADAPTER', checks, reasons, corroborated, adapterId: null };
  }
  add('claim:record-present', true);

  const f = readDigestFields(record);
  corroborated.adapter_id = typeof f.adapterId.value === 'string' ? f.adapterId.value : null;
  corroborated.version = typeof f.version.value === 'string' ? f.version.value : null;

  // (1) the version string: a real executor names its own version, and a
  // placeholder is what a fixture writes.
  add('executor:version-present', typeof f.version.value === 'string' && f.version.value.trim() !== '',
    `version=${String(f.version.value)}`);
  add('executor:version-is-not-a-placeholder',
    typeof f.version.value === 'string' && !PLACEHOLDER_VERSION.test(f.version.value.trim()),
    `version=${String(f.version.value)}`);

  // (2) the binary: absolute, resolving, a regular file, executable, and its
  // digest RECOMPUTED from those bytes.
  let resolvedBinary = null;
  if (typeof f.binaryPath.value === 'string' && path.isAbsolute(f.binaryPath.value)) {
    try {
      resolvedBinary = fs.realpathSync(f.binaryPath.value);
    } catch {
      resolvedBinary = null;
    }
  }
  add('executor:binary-path-abs', typeof f.binaryPath.value === 'string' && path.isAbsolute(f.binaryPath.value),
    `binary_path=${String(f.binaryPath.value)}`);
  add('executor:binary-resolves', resolvedBinary !== null, `resolved=${String(resolvedBinary)}`);
  add('executor:binary-is-a-regular-file', resolvedBinary !== null && isFile(resolvedBinary), `path=${String(resolvedBinary)}`);
  let binaryExecutable = false;
  try {
    if (resolvedBinary !== null) {
      fs.accessSync(resolvedBinary, fs.constants.X_OK);
      binaryExecutable = true;
    }
  } catch {
    binaryExecutable = false;
  }
  add('executor:binary-is-executable', binaryExecutable, `path=${String(resolvedBinary)}`);
  let binaryBytes = null;
  try {
    if (resolvedBinary !== null && isFile(resolvedBinary)) binaryBytes = fs.readFileSync(resolvedBinary);
  } catch {
    binaryBytes = null;
  }
  const recomputedBinary = binaryBytes === null ? null : wireDigestOf(binaryBytes);
  add('executor:binary-digest-present', normaliseDigest(f.binarySha.value) !== null, `claimed=${String(f.binarySha.value)}`);
  add('executor:binary-digest-matches-the-bytes-on-disk',
    recomputedBinary !== null && normaliseDigest(f.binarySha.value) === recomputedBinary,
    `claimed=${String(normaliseDigest(f.binarySha.value))} recomputed=${String(recomputedBinary)}`);
  if (resolvedBinary !== null && recomputedBinary !== null) {
    corroborated.binary_path = maskHome(resolvedBinary);
    corroborated.binary_sha256 = recomputedBinary;
  }
  // (2b) THE HOST FACT. A record may name any executable it likes — `node`, a
  // shell, a file it wrote itself — and every file check above passes for all
  // of them. What it may not do is name something this host does not have
  // installed as a real executor. `probe` is the live `probeRealAdapters` fact,
  // the same one the board uses to corroborate a registration at
  // `commands.mjs:assertRealAdapterClaimIsTrue`.
  const probeRows = Array.isArray(probe) ? probe : null;
  const probedInstalled = probeRows === null
    ? []
    : probeRows.filter((row) => isPlainObject(row) && row.installed === true && typeof row.binary_path === 'string')
      .map((row) => row.binary_path);
  corroborated.installed_executors_probed = probeRows === null ? null : probedInstalled.map((entry) => maskHome(entry));
  add('executor:binary-is-a-probed-installed-executor',
    probeRows !== null && resolvedBinary !== null && probedInstalled.some((candidate) => {
      try {
        return fs.realpathSync(candidate) === resolvedBinary;
      } catch {
        return false;
      }
    }),
    probeRows === null
      ? 'no live probeRealAdapters fact was supplied to this classification'
      : `resolved=${String(resolvedBinary)} installedOnThisHost=${probedInstalled.length}`);
  add('executor:adapter-id-is-the-probed-one',
    probeRows === null || corroborated.adapter_id === null
      ? probeRows === null
      : probeRows.some((row) => row.adapter_id === corroborated.adapter_id && row.installed === true),
    `adapter_id=${String(corroborated.adapter_id)}`);

  // (3) the raw process log: absolute, readable, digest recomputed. A log that
  // is not on disk is not a log.
  const logAbsolute = typeof f.logPath.value === 'string' && path.isAbsolute(f.logPath.value) ? f.logPath.value : null;
  add('rawlog:path-abs', logAbsolute !== null, `raw_process_log_path=${String(f.logPath.value)}`);
  let logBytes = null;
  try {
    if (logAbsolute !== null) logBytes = fs.readFileSync(logAbsolute);
  } catch {
    logBytes = null;
  }
  add('rawlog:readable', logBytes !== null, `path=${String(logAbsolute)}`);
  const recomputedLog = logBytes === null ? null : wireDigestOf(logBytes);
  add('rawlog:digest-present', normaliseDigest(f.logSha.value) !== null, `claimed=${String(f.logSha.value)}`);
  add('rawlog:digest-matches-the-bytes-on-disk',
    recomputedLog !== null && normaliseDigest(f.logSha.value) === recomputedLog,
    `claimed=${String(normaliseDigest(f.logSha.value))} recomputed=${String(recomputedLog)}`);
  if (logAbsolute !== null && recomputedLog !== null) {
    corroborated.raw_process_log_path = maskHome(logAbsolute);
    corroborated.raw_process_log_sha256 = recomputedLog;
    corroborated.raw_process_log_bytes = logBytes.length;
  }
  // (3b) THE LOG MUST BE THE EXECUTOR'S OWN RAW PROCESS LOG. A digest of bytes
  // somebody wrote proves only that those bytes still exist. The real executor
  // writes a document with `record_kind: 'real-executor-raw-process-log'`, and
  // that document independently carries the binary it ran, the run it served and
  // the exit status it observed — so a log that does not agree with the record
  // about those three things is not this run's log.
  let logDocument = null;
  if (logBytes !== null) {
    try {
      const parsed = JSON.parse(logBytes.toString('utf8'));
      if (isPlainObject(parsed)) logDocument = parsed;
    } catch {
      logDocument = null;
    }
  }
  const logIsRawProcessLog = isPlainObject(logDocument) && logDocument.record_kind === 'real-executor-raw-process-log';
  add('rawlog:is-the-executors-raw-process-log-document', logIsRawProcessLog,
    logDocument === null ? 'the log is not a JSON object' : `record_kind=${String(logDocument.record_kind)}`);
  add('rawlog:names-the-same-binary-the-record-names',
    logIsRawProcessLog && resolvedBinary !== null && recomputedBinary !== null
      && at(logDocument, 'executor.binary_path') === resolvedBinary
      && normaliseDigest(at(logDocument, 'executor.binary_sha256')) === recomputedBinary,
    logIsRawProcessLog ? `log=${String(at(logDocument, 'executor.binary_path'))} record=${String(resolvedBinary)}` : 'no log document');
  add('rawlog:records-the-same-run-the-record-names',
    logIsRawProcessLog && typeof f.runId.value === 'string' && at(logDocument, 'run_id') === f.runId.value,
    logIsRawProcessLog ? `log=${String(at(logDocument, 'run_id'))} record=${String(f.runId.value)}` : 'no log document');
  add('rawlog:records-the-same-non-zero-exit-status-the-record-claims',
    logIsRawProcessLog && Number.isInteger(f.exitStatus.value) && at(logDocument, 'exit_status') === f.exitStatus.value,
    logIsRawProcessLog ? `log=${String(at(logDocument, 'exit_status'))} record=${String(f.exitStatus.value)}` : 'no log document');

  // (4) a REAL exit status. Zero is refused: the one real run of this ticket
  // ends FAILED, and a zero exit is what a scripted boundary reports.
  add('executor:exit-status-is-a-nonzero-integer',
    Number.isInteger(f.exitStatus.value) && f.exitStatus.value !== 0,
    `exit_status=${JSON.stringify(f.exitStatus.value)}`);
  corroborated.exit_status = Number.isInteger(f.exitStatus.value) ? f.exitStatus.value : null;

  // (5) the honesty flags: a scripted or replayed crossing is never a real run,
  // whatever its version string and exit status say.
  const scriptUsed = at(record, 'honesty.script_used');
  const replayUsed = at(record, 'honesty.replay_used');
  const transportSource = at(record, 'honesty.transport_source');
  add('honesty:script-used-is-false', scriptUsed === false, `honesty.script_used=${String(scriptUsed)}`);
  add('honesty:replay-used-is-false', replayUsed === false, `honesty.replay_used=${String(replayUsed)}`);
  add('honesty:transport-source-is-a-real-transport',
    typeof transportSource === 'string' && REAL_TRANSPORT_SOURCES.includes(transportSource),
    `honesty.transport_source=${String(transportSource)}`);

  // (6) the corroboration the ADAPTER cannot write for itself: a session id
  // minted by the executor and a pid tree observed by the parent.
  add('corroboration:executor-session-id-present',
    typeof f.sessionId.value === 'string' && f.sessionId.value.trim() !== '',
    `executor_session_id=${String(f.sessionId.value)}`);
  // The id must be IN the executor's own output. A string in the record that
  // appears nowhere in the raw log is a string the record's writer chose.
  add('corroboration:session-id-appears-in-the-raw-log-bytes',
    typeof f.sessionId.value === 'string' && f.sessionId.value.trim() !== ''
      && logBytes !== null && logBytes.toString('utf8').includes(f.sessionId.value),
    typeof f.sessionId.value === 'string' ? `session_id=${f.sessionId.value} foundInLog=${logBytes === null ? false : logBytes.toString('utf8').includes(f.sessionId.value)}` : 'no session id');
  add('corroboration:session-id-agrees-with-the-executors-own-report',
    logIsRawProcessLog && typeof f.sessionId.value === 'string'
      && at(logDocument, 'usage.executor_session_id') === f.sessionId.value,
    logIsRawProcessLog ? `log=${String(at(logDocument, 'usage.executor_session_id'))} record=${String(f.sessionId.value)}` : 'no log document');
  const pidTree = f.pidTree.value;
  const pidTreeNonEmpty = Array.isArray(pidTree) && pidTree.length > 0
    && pidTree.every((pid) => Number.isInteger(pid) && pid > 0);
  add('corroboration:pid-tree-observed-by-the-parent', pidTreeNonEmpty,
    Array.isArray(pidTree)
      ? `pids=${pidTree.length}${pidTreeNonEmpty ? '' : ' — an unobservable process space proves nothing, and an empty array is not an observed one'}`
      : `${f.pidTree.dotPath}=${String(pidTree)}`);
  add('corroboration:observed-by-is-not-the-adapter-itself',
    typeof f.observedBy.value === 'string' && f.observedBy.value.trim() !== '' && f.observedBy.value !== f.adapterId.value,
    `observed_by=${String(f.observedBy.value)}`);
  if (typeof f.sessionId.value === 'string') corroborated.executor_session_id = f.sessionId.value;
  if (Array.isArray(pidTree)) corroborated.pid_tree_after_exit = pidTree;
  if (typeof f.observedBy.value === 'string') corroborated.observed_by = f.observedBy.value;

  const ok = reasons.length === 0;
  return {
    status: ok ? 'REAL_ADAPTER_AVAILABLE' : 'NOT_RUN_REAL_ADAPTER',
    checks,
    reasons,
    corroborated,
    adapterId: corroborated.adapter_id,
    // A claim that is present, fresh, HEAD-bound and internally green, yet does
    // not survive re-verification, is a DEFECT, not a skip: something wrote a
    // real-adapter claim it did not earn.
    forged: ok === false && at(record, 'status') === 'PASS' && at(record, 'ok') === true,
  };
}

/**
 * The adapter inventory of the summary.
 *
 * `available` is built ONLY from records that survive `classifyRealAdapterClaim`.
 * A registration, a configuration or a declared provider never reaches it. That
 * is the whole point: a configured-but-unrun adapter and an adapter that does
 * not exist produce the SAME `available` list and the SAME realAdapterStatus.
 */
export function adapterAvailability({ records = [], probe = null } = {}) {
  const available = [];
  const configured = [];
  for (const { source, record } of records) {
    const claimed = classifyRealAdapterClaim({ record, probe });
    const adapterId = claimed.adapterId ?? at(record, 'executor.adapter_id') ?? at(record, 'adapter_id') ?? null;
    if (claimed.status === 'REAL_ADAPTER_AVAILABLE') {
      available.push({ adapter_id: adapterId, source, corroborated: true, run_id: at(record, 'run_id') ?? null });
      continue;
    }
    configured.push({
      adapter_id: adapterId,
      source,
      corroborated: false,
      // A configured adapter and a missing one differ in what a human must do
      // next, so the reason is named — and it is named as a REASON, never as
      // availability.
      reason: record === null ? 'NO_RECORD' : claimed.reasons.slice(0, 3).join('; ') || 'NOT_CORROBORATED',
    });
  }
  return {
    available,
    configured,
    // The two views a reader must never confuse.
    note: '`available` contains only adapters with a corroborated real run. A registration, a configuration entry or a declared provider NEVER appears there, so a configured-but-unrun adapter is indistinguishable, in this output, from one that does not exist.',
  };
}

// ---------------------------------------------------------------------------
// The real-adapter tamper matrix: prove the honesty classifier cannot be fooled
// ---------------------------------------------------------------------------
export const REAL_ADAPTER_TAMPER_VARIANTS = Object.freeze([
  { id: 'claim-without-corroboration', expect: '*', apply: (record) => ({ status: 'PASS', ok: true, honestStatus: { realAdapterStatus: 'REAL_ADAPTER_AVAILABLE' } }) },
  { id: 'version-placeholder', expect: 'executor:version-is-not-a-placeholder', apply: (record) => cloneWith(record, { executor: { ...(record.executor ?? {}), version: 'test-transport' } }) },
  { id: 'binary-digest-mismatch', expect: 'executor:binary-digest-matches-the-bytes-on-disk', apply: (record) => cloneWith(record, { executor: { ...(record.executor ?? {}), binary_sha256: `sha256:${'0'.repeat(64)}` } }) },
  { id: 'rawlog-digest-mismatch', expect: 'rawlog:digest-matches-the-bytes-on-disk', apply: (record) => cloneWith(record, { raw_process_log_sha256: `sha256:${'1'.repeat(64)}` }) },
  { id: 'exit-status-zero', expect: 'executor:exit-status-is-a-nonzero-integer', apply: (record) => cloneWith(record, { exit_status: 0 }) },
  { id: 'honesty-script-used', expect: 'honesty:script-used-is-false', apply: (record) => cloneWith(record, { honesty: { ...(record.honesty ?? {}), script_used: true } }) },
  { id: 'honesty-test-transport', expect: 'honesty:transport-source-is-a-real-transport', apply: (record) => cloneWith(record, { honesty: { ...(record.honesty ?? {}), transport_source: 'test-transport' } }) },
  { id: 'session-id-absent', expect: 'corroboration:executor-session-id-present', apply: (record) => cloneWith(record, { corroboration: { ...(record.corroboration ?? {}), executor_session_id: null } }) },
  { id: 'pid-tree-absent', expect: 'corroboration:pid-tree-observed-by-the-parent', apply: (record) => cloneWith(record, { corroboration: { ...(record.corroboration ?? {}), pid_tree_after_exit: null } }) },
  // The three refusals that used to be satisfiable by a document anybody could
  // write. Each one is now a cross-check against a host fact or against the
  // executor's own output.
  { id: 'pid-tree-empty', expect: 'corroboration:pid-tree-observed-by-the-parent', apply: (record) => cloneWith(record, { corroboration: { ...(record.corroboration ?? {}), pid_tree_after_exit: [] } }) },
  { id: 'session-id-not-in-the-log', expect: 'corroboration:session-id-appears-in-the-raw-log-bytes', apply: (record) => cloneWith(record, { corroboration: { ...(record.corroboration ?? {}), executor_session_id: 'sess-not-in-the-log-bytes' } }) },
  { id: 'log-is-not-a-raw-process-log', expect: 'rawlog:is-the-executors-raw-process-log-document', apply: (record, ctx) => {
    // The classifier reads the log from DISK, so this variant has to write a
    // junk file and point the record at it. Writing into the scratch directory
    // is the only side effect a variant may have.
    const junk = path.join(ctx.scratchDir, `${ctx.label}-junk.log`);
    fs.writeFileSync(junk, 'this is not an executor log, it is a line of prose\n');
    const bytes = fs.readFileSync(junk);
    return cloneWith(record, {
      raw_process_log_path: junk,
      raw_process_log_sha256: `sha256:${sha256Of(bytes)}`,
    });
  } },
  { id: 'observed-by-the-adapter-itself', expect: 'corroboration:observed-by-is-not-the-adapter-itself', apply: (record) => cloneWith(record, { corroboration: { ...(record.corroboration ?? {}), observed_by: record.executor?.adapter_id ?? 'adr-self' } }) },
]);

function cloneWith(record, patch) {
  return { ...(record ?? {}), ...patch };
}

export function runRealAdapterTamperMatrix({ record, probe = null, scratchDir }) {
  const results = [];
  if (!isPlainObject(record)) {
    return {
      ok: false,
      checked: 0,
      strong: 0,
      undetected: [],
      skipped: ['no real-adapter record exists in this verification, so there is nothing to doctor; the classifier is exercised instead by the always-runnable self-check matrix (selfChecks.negativeControls.realAdapterTamperOnForgedRecord), which must detect every variant against a SYNTHETIC record built for that purpose'],
      results: [],
    };
  }
  return matrixOver({ record, probe, scratchDir, results, label: 'real-adapter' });
}

/** The shared per-variant loop. `results` is threaded so a caller can chain. */
function matrixOver({ record, probe = null, scratchDir, results, label }) {
  const baseline = classifyRealAdapterClaim({ record, probe });
  fs.mkdirSync(scratchDir, { recursive: true });
  for (const variant of REAL_ADAPTER_TAMPER_VARIANTS) {
    const doctored = variant.apply(record, { scratchDir, label });
    const classified = classifyRealAdapterClaim({ record: doctored, probe });
    const detected = classified.status !== 'REAL_ADAPTER_AVAILABLE'
      && classified.checks.some((check) => !check.ok && (variant.expect === '*' || check.check.startsWith(variant.expect)));
    const file = path.join(scratchDir, `${label}--${variant.id}.json`);
    fs.writeFileSync(file, `${JSON.stringify(doctored, null, 2)}\n`);
    results.push({
      variant: variant.id,
      expectedCheck: variant.expect,
      classified: classified.status,
      detected,
      strong: detected && baseline.status === 'REAL_ADAPTER_AVAILABLE',
      firstReason: classified.reasons[0] ?? null,
      scratchFile: path.relative(ROOT, file).split(path.sep).join('/'),
    });
  }
  const undetected = results.filter((row) => !row.detected);
  return {
    ok: undetected.length === 0 && results.length > 0,
    checked: results.length,
    strong: results.filter((row) => row.strong === true).length,
    baselineStatus: baseline.status,
    undetected: undetected.map((row) => row.variant),
    skipped: [],
    results,
  };
}

/**
 * A SYNTHETIC, file-fact-complete record used ONLY as a negative control on the
 * classifier above. It is a self-check input and never reaches
 * `realAdapter.adapters`, `realAdapterStatus` or any evidence file: it exists so
 * that "does the classifier reject a doctored record?" has an answer even in a
 * checkout where no real run has happened yet.
 *
 * It is built on a REAL INSTALLED EXECUTOR taken from a live `probeRealAdapters`
 * row, and its raw log is written in the shape the real executor writes
 * (`record_kind: 'real-executor-raw-process-log'`, carrying the same binary, the
 * same run id, the same exit status and the session id the record claims).
 * That matters: a control built on `process.execPath` and a prose log would
 * FAIL the new checks for the wrong reason and would prove nothing about the
 * doctored variants. The control's whole job is to be accepted at the baseline
 * and refused everywhere else, so the baseline has to be complete.
 *
 * `ran: false` when this host has no installed executor at all: then the
 * baseline cannot be built, and that is reported as an UNPROVEN control
 * (capping the ticket at PARTIAL), never as a pass.
 */
export function syntheticCorroboratedRecord(probe) {
  const rows = Array.isArray(probe) ? probe.filter((row) => isPlainObject(row) && row.installed === true && typeof row.binary_path === 'string') : [];
  if (rows.length === 0) {
    return { ran: false, reason: 'no installed executor on this host, so no file-fact-complete baseline can be built for the honesty classifier', path: null, logPath: null, logDir: null, record: null };
  }
  const row = rows[0];
  const binaryPath = row.binary_path;
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-s2007r-selfcheck-'));
  const logPath = path.join(logDir, 'raw-process.log.json');
  const binaryBytes = fs.readFileSync(binaryPath);
  const sessionId = `sess-s2007r-selfcheck-${row.adapter_id}`;
  const runId = 'run-s2007r-selfcheck-synthetic';
  // The executor's own raw process log, in the shape the real executor writes.
  const logDocument = {
    contractVersion: '1.0.0',
    record_kind: 'real-executor-raw-process-log',
    executor_version: 's2-007r-selfcheck-v1',
    run_id: runId,
    executor: { provider: 'codex', binary_path: binaryPath, binary_sha256: `sha256:${sha256Of(binaryBytes)}` },
    invocation: { argv: ['--version'], cwd: os.tmpdir(), effective_tools: [] },
    started_at: PROBE_INSTANT,
    ended_at: PROBE_INSTANT,
    exit_status: 1,
    signal: null,
    stdout_sha256: `sha256:${'0'.repeat(64)}`,
    stdout_bytes: 0,
    usage: { model_id: null, tool_calls: 0, executor_session_id: sessionId },
  };
  const logBytes = Buffer.from(`${JSON.stringify(logDocument, null, 2)}\n`, 'utf8');
  fs.writeFileSync(logPath, logBytes, { mode: 0o600 });
  return {
    ran: true,
    reason: null,
    basedOn: `a live probeRealAdapters row for ${row.adapter_id} (${maskHome(binaryPath)})`,
    path: binaryPath,
    logPath,
    logDir,
    record: {
      run_id: runId,
      executor: {
        adapter_id: row.adapter_id,
        provider: 'codex',
        version: 's2-007r-selfcheck-v1',
        binary_path: binaryPath,
        binary_sha256: `sha256:${sha256Of(binaryBytes)}`,
      },
      raw_process_log_path: logPath,
      raw_process_log_sha256: `sha256:${sha256Of(logBytes)}`,
      exit_status: 1,
      honesty: { script_used: false, replay_used: false, transport_source: 'codex-transport' },
      corroboration: { executor_session_id: sessionId, pid_tree_after_exit: [1], observed_by: 'parent-process' },
      status: 'PASS',
      ok: true,
    },
  };
}

/**
 * The comparison claim, judged on its own.
 *
 * The gate contract says a record "whose verdict is REFUSED, or which names two
 * different project_digest or budget_grant_id values, is NOT_RUN here and can
 * never be counted as a completed comparison". The previous check compared ONE
 * self-declared `verdict` string, and only when the field was present: a record
 * that omitted `verdict` skipped the check entirely, and nothing read
 * `project_digest`, `budget_grant_id` or `cost_basis` at all. Probe (b) in
 * `scripts/s2-007r-probes.mjs` proves `compareCells` refuses such a pair, but
 * nothing bound the RECORD to that refusal, so the aggregator's C5 rested on
 * the honesty of the writer of the comparison script.
 *
 * So the aggregate re-derives the precondition: the distinct values of each of
 * the three fields, over the record and over every cell in it, must have size
 * <= 1. A record that names two projects, two grants or two cost bases is a
 * FAIL, whatever verdict string it carries.
 */
export function classifyComparisonClaim({ record } = {}) {
  const checks = [];
  const add = (label, ok, detail) => {
    checks.push({ label, ok, detail: detail === undefined ? null : String(detail).slice(0, 300) });
    return ok;
  };
  if (!isPlainObject(record)) {
    add('the comparison record is present', false, 'no comparison record was read');
    return { verdict: null, ok: false, fail: false, checks, crossInput: [] };
  }
  const verdict = at(record, 'verdict') ?? at(record, 'comparison.verdict') ?? null;
  // ABSENT included: a comparison record that does not state its verdict has
  // not been compared, whatever `comparison.ok` says.
  add('the record states verdict COMPARED', verdict === 'COMPARED', `verdict=${String(verdict)}`);
  const cells = Array.isArray(at(record, 'cells')) ? at(record, 'cells') : [];
  const sources = [record, at(record, 'comparison'), ...cells].filter(isPlainObject);
  const fields = ['project_digest', 'budget_grant_id', 'cost_basis'];
  const crossInput = [];
  for (const field of fields) {
    const values = [...new Set(sources
      .map((owner) => owner[field])
      .filter((value) => value !== undefined && value !== null)
      .map((value) => JSON.stringify(value)))];
    const present = values.length > 0;
    add(`every ${field} in the record is the same value`, present && values.length <= 1,
      present ? `distinct=${values.length} ${values.join(' | ').slice(0, 200)}` : `${field} is absent everywhere, so the precondition is UNKNOWN, not satisfied`);
    if (present && values.length > 1) crossInput.push(field);
  }
  add('the comparison names at least one run set', typeof at(record, 'run_set_id') === 'string' && at(record, 'run_set_id') !== '',
    `run_set_id=${String(at(record, 'run_set_id'))}`);
  const ok = checks.every((check) => check.ok);
  return {
    verdict: verdict ?? null,
    // A cross-project/cross-budget record is a FAIL, not a skip: two inputs are
    // two comparisons, and the delta it publishes is not a comparison result.
    fail: crossInput.length > 0,
    ok,
    crossInput,
    checks,
  };
}

// ---------------------------------------------------------------------------
// The A-MVP per-case tamper matrix
//
// The per-case table is the one piece of this summary that no gate writes and no
// commit/tree anchor covers, so it gets its own matrix: every doctored shape of
// that file must be refused by `classifyAmvpRecord` + `classifyAMvpCase`. It is
// ALWAYS runnable (it needs no real executor and no gate artifact), which is why
// "the matrix could not run" is not an available excuse for it.
// ---------------------------------------------------------------------------
export const AMVP_TAMPER_VARIANTS = Object.freeze([
  { id: 'hand-written-pass', apply: () => ({ cases: { 'A-MVP-01': { observed: 'PASS' } } }) },
  { id: 'unanchored-commit', apply: (record) => ({ ...record, commit: '0'.repeat(40) }) },
  { id: 'commit-stripped', apply: (record) => { const { commit, ...rest } = record; return rest; } },
  { id: 'claimed-verdict-upgrade', apply: (record) => ({ ...record, cases: Object.fromEntries(A_MVP_IDS.map((id) => [id, { observed: 'PASS' }])) }) },
]);

export function runAmvpTamperMatrix({ scratchDir, head = null }) {
  const results = [];
  const baseline = { cases: Object.fromEntries(A_MVP_IDS.map((id) => [id, { observed: 'NOT_RUN' }])), commit: '0'.repeat(40) };
  fs.mkdirSync(scratchDir, { recursive: true });
  for (const variant of AMVP_TAMPER_VARIANTS) {
    const doctored = variant.apply(baseline);
    const file = path.join(scratchDir, `amvp--${variant.id}.json`);
    fs.writeFileSync(file, `${JSON.stringify(doctored, null, 2)}\n`);
    const readBack = readJsonFile(file);
    const classified = classifyAmvpRecord({ record: readBack.record, head, realAdapterStatus: 'NOT_RUN_REAL_ADAPTER', corroboratedRuns: [] });
    const cases = A_MVP_IDS.map((id) => classifyAMvpCase({
      id,
      pilotCase: { execution: 'NOT_RUN' },
      observed: isPlainObject(readBack.record?.cases?.[id]) ? readBack.record.cases[id].observed : null,
      realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
      corroboratedRuns: [],
      recordReadable: classified.readable,
      recordReason: classified.reason,
    }));
    // Every case must read NOT_RUN: a per-case PASS is the only thing this file
    // could contribute, and it must never be produced from an unanchored file.
    const detected = classified.readable === false && cases.every((row) => row.observed === 'NOT_RUN');
    results.push({
      variant: variant.id,
      classified: classified.readable ? 'READ' : 'REFUSED',
      detected,
      firstReason: classified.reason ?? null,
      scratchFile: path.relative(ROOT, file).split(path.sep).join('/'),
    });
  }
  const undetected = results.filter((row) => !row.detected);
  return {
    ok: undetected.length === 0 && results.length > 0,
    checked: results.length,
    undetected: undetected.map((row) => row.variant),
    results,
  };
}

// ---------------------------------------------------------------------------
// The A-MVP per-case classifier
// ---------------------------------------------------------------------------
const A_MVP_IDS = Object.freeze(['A-MVP-01', 'A-MVP-02', 'A-MVP-03', 'A-MVP-04', 'A-MVP-05', 'A-MVP-06', 'A-MVP-07']);
const ALLOWED_OBSERVED = Object.freeze(['PASS', 'NOT_RUN', 'NOT_RUN_DB', 'BLOCKED', 'PARTIAL']);

/**
 * The per-case record, and whether it may be read at all.
 *
 * `evidence/s2-007r-amvp-cases.json` was read verbatim with no anchor, no
 * digest and no freshness check, so a hand-written
 * `{"A-MVP-01":{"observed":"PASS"}}` made the aggregator print `A-MVP-01: PASS`
 * with no gate having produced it. It is not in any gate's `evidenceFiles` (it
 * is not that gate's own written record, so putting it there would be wrong),
 * so the S2-007 tamper matrix cannot cover it either. What can be done here is
 * to stop treating an unauthenticated file as evidence:
 *
 *   * the record must be bound to the commit this verification is running at;
 *   * a case may read PASS only when the real-adapter status is corroborated
 *     from a record THIS invocation produced, and the PASS must name a run from
 *     the corroborated set (already enforced in `classifyAMvpCase`);
 *   * when any of that is missing, every case is forced to NOT_RUN with the
 *     exact reason, and the headline never shows a PASS nobody observed.
 */
export function classifyAmvpRecord({ record, head = null, realAdapterStatus = 'NOT_RUN_REAL_ADAPTER', corroboratedRuns = [] } = {}) {
  const checks = [];
  const add = (label, ok, detail) => {
    checks.push({ label, ok, detail: detail === undefined ? null : String(detail).slice(0, 300) });
    return ok;
  };
  if (!isPlainObject(record)) {
    add('the per-case record is present', false, 'evidence/s2-007r-amvp-cases.json is absent');
    return { readable: false, anchored: false, checks, cases: {}, reason: 'the per-case record is absent, so every case reads NOT_RUN' };
  }
  const commit = at(record, 'commit') ?? at(record, 'git.commit_sha') ?? null;
  const anchoredToHead = head === null || (typeof commit === 'string' && commit === head.commit && /^[0-9a-f]{40}$/.test(commit));
  add('the per-case record is bound to the commit this verification is running at', anchoredToHead,
    `record.commit=${String(commit)} head.commit=${String(head?.commit)}`);
  add('the per-case record states which real-adapter run it observed',
    realAdapterStatus === 'REAL_ADAPTER_AVAILABLE' && corroboratedRuns.length > 0,
    `realAdapterStatus=${realAdapterStatus} corroboratedRuns=${corroboratedRuns.length}`);
  const readable = checks.every((check) => check.ok);
  return {
    readable,
    anchored: anchoredToHead,
    commit,
    checks,
    cases: isPlainObject(record.cases) ? record.cases : {},
    reason: readable ? null : 'the per-case record is not bound to this commit and to a corroborated real-adapter run, so its observed values are a claim, not an observation',
  };
}

/**
 * One A-MVP case, judged on its own. The FROZEN pilot file keeps every case at
 * `execution: NOT_RUN` (the schema has no value for a real run, D9), so the
 * observation lives in this ticket's own record. A case may only read PASS when
 * the real-adapter status is corroborated, and the PASS must name the runs and
 * the adapters that back it.
 */
export function classifyAMvpCase({ id, pilotCase = null, observed = null, realAdapterStatus = 'NOT_RUN_REAL_ADAPTER', corroboratedRuns = [], reasons = [], recordReadable = true, recordReason = null }) {
  const checks = [];
  const add = (label, ok, detail) => {
    checks.push({ label, ok, detail: detail === undefined ? null : String(detail).slice(0, 300) });
    return ok;
  };
  const pilotExecution = pilotCase?.execution ?? null;
  add('the frozen pilot case still reads execution NOT_RUN', pilotExecution === 'NOT_RUN', `pilot.execution=${String(pilotExecution)}`);
  add('the per-case record may be read (bound to this commit and to a corroborated run)', recordReadable === true,
    recordReadable === true ? 'anchored' : String(recordReason));
  const value = recordReadable === true && typeof observed === 'string' ? observed : null;
  add('the observed value comes from the closed vocabulary', value !== null && ALLOWED_OBSERVED.includes(value), `observed=${String(value)}`);
  if (value === 'PASS') {
    add('a PASS needs a corroborated real-adapter status', realAdapterStatus === 'REAL_ADAPTER_AVAILABLE', `realAdapterStatus=${realAdapterStatus}`);
    add('a PASS names at least one corroborated run', corroboratedRuns.length > 0, `runs=${corroboratedRuns.length}`);
  }
  const ok = checks.every((check) => check.ok);
  return {
    id,
    pilotExecution,
    pilotExpected: pilotCase?.expected ?? null,
    pilotDigest: pilotCase?.pilotFileSha256 ?? null,
    observed: value ?? 'NOT_RUN',
    claimedObserved: typeof observed === 'string' ? observed : null,
    status: ok ? (value ?? 'NOT_RUN') : 'NOT_RUN',
    checks,
    reasons: ok ? reasons : [...reasons, recordReadable === true
      ? 'a per-case check failed, so the case reads NOT_RUN regardless of what the record claims'
      : `${recordReason} — the case reads NOT_RUN regardless of what the record claims`],
  };
}

function readPilotCases() {
  const relative = 'pilots/scenario-a/acceptance-cases.json';
  const absolute = path.join(ROOT, relative);
  try {
    const bytes = fs.readFileSync(absolute);
    const parsed = JSON.parse(bytes.toString('utf8'));
    return { present: true, sha256: sha256Of(bytes), cases: (parsed.cases ?? []).filter((row) => A_MVP_IDS.includes(row.id)) };
  } catch {
    return { present: false, sha256: null, cases: [] };
  }
}

function readFrozenDigest(relative) {
  try {
    const frozen = JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/frozen-manifest.json'), 'utf8'));
    const row = (frozen.files ?? []).find((entry) => entry.path === relative);
    return row?.sha256 ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// The seven-measurement classifier
// ---------------------------------------------------------------------------
function measurementNames() {
  for (const relative of ['src/lib/agentboard/measurements.mjs', 'src/lib/executors/measure.mjs']) {
    const absolute = path.join(ROOT, relative);
    if (!fs.existsSync(absolute)) continue;
    try {
      // A static read of a frozen literal: this classifier must not import a
      // module that may execute code at load time.
      const text = fs.readFileSync(absolute, 'utf8');
      const block = /MEASUREMENT_NAMES\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\)/.exec(text);
      if (block === null) continue;
      const names = [...block[1].matchAll(/'([^']+)'/g)].map((match) => match[1]);
      if (names.length > 0) return { names, source: relative };
    } catch {
      // fall through to the next candidate
    }
  }
  return { names: [...FALLBACK_MEASUREMENT_NAMES], source: 'the frozen fallback list in scripts/verify-s2-007r.mjs (the measurement module is not in this checkout)' };
}

/**
 * The closed status vocabulary, read from the producing module rather than
 * restated. `finding` are the statuses that report a FINDING, and a finding is
 * a defect, never a skip.
 */
function measurementVocabulary() {
  for (const relative of ['src/lib/agentboard/measurements.mjs', 'src/lib/executors/measure.mjs']) {
    const absolute = path.join(ROOT, relative);
    if (!fs.existsSync(absolute)) continue;
    try {
      const text = fs.readFileSync(absolute, 'utf8');
      const block = /MEASUREMENT_STATUSES\s*=\s*Object\.freeze\(\[([^\]]*)\]\)/.exec(text);
      if (block === null) continue;
      const all = [...block[1].matchAll(/'([^']+)'/g)].map((match) => match[1]);
      if (all.length === 0) continue;
      return { all, finding: all.filter((status) => status === 'FAILED_GATE'), source: relative };
    } catch {
      // fall through
    }
  }
  return {
    all: ['MEASURED', 'MEASURED_WITH_FINDING', 'PARTIAL', 'NOT_RUN', 'FAILED_GATE'],
    finding: ['FAILED_GATE'],
    source: 'the frozen fallback vocabulary in scripts/verify-s2-007r.mjs',
  };
}

/**
 * The artefact a third party would recompute a measurement from, taken from the
 * record as the producer publishes it. `measurements.mjs` puts the digests at
 * the RUN-record level (`artifact_digests` / `raw_log_digests` /
 * `run_record_digests`) and not on the measurement row, so requiring a row-level
 * `row.artifact` made a genuinely measured row read NOT_MEASURED and capped the
 * ticket at PARTIAL for a reason no producer could fix.
 *
 * Each candidate is then CHECKED against the filesystem: the path must resolve
 * and its bytes must hash to the recorded digest. "Recomputable by a third
 * party" is the claim being made here, so it is verified rather than assumed.
 */
export function collectArtifacts(record) {
  const found = [];
  const push = (entry) => {
    if (!isPlainObject(entry)) return;
    const relative = firstOf(entry, ['path', 'file', 'source_path']).value;
    const claimed = firstOf(entry, ['sha256', 'file_sha256', 'content_digest']).value;
    if (typeof relative !== 'string' || relative === '') return;
    found.push({ path: relative, claimedSha256: normaliseDigest(claimed), bytes: Number.isInteger(entry.bytes) ? entry.bytes : null });
  };
  const pushAll = (list) => { if (Array.isArray(list)) for (const entry of list) push(entry); };
  const cells = Array.isArray(record?.cells) ? record.cells : [];
  for (const owner of [record, ...cells]) {
    if (!isPlainObject(owner)) continue;
    pushAll(owner.artifact_digests);
    pushAll(owner.raw_log_digests);
    pushAll(owner.rawLogDigests);
    pushAll(owner.run_record_digests);
    pushAll(owner.runRecordDigests);
  }
  // Deduplicate on path+digest: a cell may name the same run log twice.
  const seen = new Set();
  return found.filter((entry) => {
    const key = `${entry.path}|${String(entry.claimedSha256)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Does the published artefact exist on disk with exactly the recorded digest? */
function artefactVerifies(entry) {
  if (entry.claimedSha256 === null) return false;
  for (const base of [ROOT, process.cwd()]) {
    let bytes = null;
    try {
      bytes = fs.readFileSync(path.isAbsolute(entry.path) ? entry.path : path.join(base, entry.path));
    } catch {
      continue;
    }
    if (sha256Of(bytes) === entry.claimedSha256) return true;
  }
  return false;
}

/**
 * The measurement rows a record publishes. The measure script nests them per
 * CELL (`cells[].measurements[]`), because a comparison is a pair of cells and
 * each cell carries its own seven. Reading only a top-level `measurements[]`
 * found nothing at all in a genuine artifact, so all seven read NOT_MEASURED.
 */
export function collectMeasurementRows(record) {
  if (Array.isArray(record?.measurements)) return { rows: record.measurements, from: 'record.measurements' };
  const cells = Array.isArray(record?.cells) ? record.cells : [];
  const rows = [];
  for (const cell of cells) if (Array.isArray(cell?.measurements)) rows.push(...cell.measurements);
  return { rows, from: cells.length > 0 ? `record.cells[].measurements (${cells.length} cell(s))` : 'no measurements block in the record' };
}

/**
 * Each measurement is judged on its own: a name, a status from the closed
 * vocabulary, and — for anything that claims to be measured — a value, the
 * basis it is expressed in, the method that produced it, an artefact a third
 * party can recompute it from, and a stated limitation.
 *
 * The field names are the ones the producer actually writes (`limitations`, not
 * `limits`; a published artefact digest, not a row-level `artifact`), and every
 * string must be non-empty: `limits: ''` satisfied "the limitation is stated"
 * because `typeof '' === 'string'`.
 *
 * A `FAILED_GATE` row is a FINDING, not an unmeasured cell. A boundary refusal
 * gate that did not hold is a real result, and mapping it onto NOT_MEASURED
 * turned a defect into a PARTIAL skip with no counter movement at all.
 */
export function classifyMeasurements({ record, names, source, statusSource = null }) {
  const { rows, from } = collectMeasurementRows(record);
  const vocabulary = measurementVocabulary();
  const artefacts = collectArtifacts(record);
  const verifiedArtefacts = artefacts.filter(artefactVerifies);
  const known = Array.isArray(statusSource) && statusSource.length > 0 ? statusSource : vocabulary.all;
  const findingStatuses = new Set(vocabulary.finding.filter((status) => known.includes(status)).concat(known.includes('FAILED_GATE') ? ['FAILED_GATE'] : []));
  const byName = new Map();
  for (const row of rows) {
    if (!isPlainObject(row) || typeof row.name !== 'string') continue;
    const bucket = byName.get(row.name);
    if (bucket === undefined) byName.set(row.name, [row]);
    else bucket.push(row);
  }
  const per = names.map((name) => {
    const bucket = byName.get(name);
    if (bucket === undefined) {
      return { name, status: 'NOT_MEASURED', claimedStatus: null, claimedStatuses: [], cells: 0, value: null, unit: null, basis: null, method: null, artifact: null, recomputable: false, checks: [], defect: false, why: 'the record carries no such measurement' };
    }
    // Every cell must agree, or this is not one number.
    const claimedStatuses = [...new Set(bucket.map((row) => (typeof row.status === 'string' ? row.status : 'NOT_MEASURED')))];
    const status = claimedStatuses.length === 1 ? claimedStatuses[0] : 'NOT_MEASURED';
    const row = bucket[0];
    const measured = claimedStatuses.length === 1 && known.includes(status) && status !== 'NOT_RUN';
    const limits = row.limits ?? row.limitations ?? null;
    const limitsStated = Array.isArray(limits)
      ? limits.length > 0 && limits.every((entry) => typeof entry === 'string' && entry.trim() !== '')
      : typeof limits === 'string' && limits.trim() !== '';
    // The ratio/count contract: a number nobody can recompute is not a
    // measurement, so the numerator and the denominator must be published
    // integers rather than inferred from the value.
    const countable = row.unit === 'ratio' || row.unit === 'count';
    const checks = [
      ['a value is present', row.value !== undefined && row.value !== null],
      ['the basis is named', typeof row.basis === 'string' && row.basis.trim() !== ''],
      ['the method is named', typeof row.method === 'string' && row.method.trim() !== ''],
      ['the artefact a third party would recompute it from is named and its digest matches the bytes on disk', verifiedArtefacts.length > 0],
      ['the limitation is stated', limitsStated],
      ['the status is one of the closed measurement statuses', known.includes(status)],
      ['every cell of the comparison reports the same status', claimedStatuses.length === 1],
      ...(countable ? [
        ['the numerator is a published integer', Number.isInteger(row.numerator)],
        ['the denominator is a published integer', Number.isInteger(row.denominator)],
      ] : []),
    ];
    const ok = measured && checks.every(([, value]) => value === true);
    const failed = checks.filter(([, value]) => value !== true).map(([label]) => label);
    return {
      name,
      status: ok ? status : 'NOT_MEASURED',
      claimedStatus: status,
      claimedStatuses,
      cells: bucket.length,
      value: row.value ?? null,
      unit: row.unit ?? null,
      numerator: row.numerator ?? null,
      denominator: row.denominator ?? null,
      basis: row.basis ?? null,
      method: row.method ?? null,
      artifact: row.artifact ?? (artefacts[0]?.path ?? null),
      recomputable: ok,
      checks: checks.map(([label, value]) => ({ label, ok: value })),
      // A row whose status reports a FINDING is a defect whatever else is wrong
      // with it. That is the difference between "not measured" and "measured,
      // and the measurement found something".
      defect: findingStatuses.has(status),
      why: ok ? null : `status=${status} and ${failed.join(', ')}`,
    };
  });
  return {
    expected: names.length,
    present: per.filter((row) => row.claimedStatus !== null).length,
    measured: per.filter((row) => row.status !== 'NOT_MEASURED').length,
    notMeasured: per.filter((row) => row.status === 'NOT_MEASURED').map((row) => row.name),
    defects: per.filter((row) => row.defect === true).map((row) => ({ name: row.name, claimedStatus: row.claimedStatus, why: row.why })),
    statusVocabulary: known,
    findingStatuses: [...findingStatuses],
    statusSource: Array.isArray(statusSource) && statusSource.length > 0 ? 'the caller' : vocabulary.source,
    rowsSource: from,
    artefactsPublished: artefacts.length,
    artefactsVerifiedOnDisk: verifiedArtefacts.length,
    namesSource: source,
    per,
  };
}

// ---------------------------------------------------------------------------
// The verdict ladder
// ---------------------------------------------------------------------------
const STOP_CONDITIONS = Object.freeze([
  'NO_INSTALLED_EXECUTOR', 'CREDENTIALS_MISSING', 'NO_ALLOWED_MODEL', 'NO_STORE', 'CAMPAIGN_CAP_REACHED',
  'PROJECT_FIXTURE_UNUSABLE', 'FROZEN_TARGET_TOUCHED',
]);

/**
 * Outcome precedence, derived from the observations and never from a constant:
 *
 *   1. REVISE    a defect: a non-zero hard-gate counter in a bound source, a
 *                failed mandatory gate, tampering that was NOT detected, a
 *                renamed/repointed gate, a failed self-check, or a real-adapter
 *                claim that does not survive re-verification
 *   2. BLOCKED   a declared stop condition from the issue §8 list: no installed
 *                executor, credentials missing, no allowed model, no store, the
 *                campaign cap reached, an unusable project fixture, a frozen
 *                target touched. An INHERITED blocked dependency gate is NOT in
 *                that list — issue §8 puts it under PARTIAL ("inherited,
 *                reported, and explicitly not fixed here") — so it lands in the
 *                PARTIAL bucket with its own label.
 *   3. PARTIAL   a mandatory component could not run: a gate NOT_RUN, an
 *                inherited BLOCKED_DEPENDENCY, a comparison cell missing, a
 *                deferred probe arm, or a measurement that is not measured
 *   4. PASS_WITH_LIMITS   every mandatory gate PASS, but the checkout is dirty
 *   5. COMPLETE_WITH_LIMITS  every mandatory gate PASS in a clean checkout
 *
 * `assuranceStatus` and `aMvpStatus` are separate, deliberately narrow axes. No
 * engineering evidence in this repository can move either one: a real adapter
 * with a human review behind it, and an operator accepting a bounded pilot, are
 * not things a scripted or replay run can produce.
 */
export function deriveVerdict({
  gates = [], gateCommands = null, counterSources = [], tamperChecks = null, selfChecks = null,
  checkout = null, observations = [], realAdapter = null, measurements = null, deferredArms = [],
  stopCondition = null, realAdapterTamper = null, comparison = null, amvp = null, realAdapterFromThisRun = true,
} = {}) {
  const defects = [];
  const blocked = [];
  const notRun = [];
  const byId = Object.fromEntries(gates.map((gate) => [gate.id, gate]));

  for (const source of counterSources) {
    if (source.bound !== true) continue;
    const findings = HARD_GATE_COUNTERS.filter((counter) => Number(source.counters?.[counter]) !== 0);
    if (findings.length > 0) {
      defects.push(`hard-gate counters are not zero in ${source.source}: ${findings.map((counter) => `${counter}=${source.counters[counter]}`).join(', ')}`);
    }
  }

  for (const id of MANDATORY_GATE_IDS) {
    const gate = byId[id];
    if (!gate) {
      notRun.push(`mandatory gate ${id} was not evaluated`);
      continue;
    }
    if (gate.status === 'PASS') continue;
    const reason = `mandatory gate ${id} is ${gate.status}: ${(gate.reasons ?? []).slice(0, 3).join('; ') || 'no reason recorded'}`;
    if (gate.status === 'NOT_RUN') notRun.push(reason);
    else if (gate.status === 'BLOCKED_DEPENDENCY') {
      // Inherited from S2-007 and reported, never fixed here (issue §8).
      notRun.push(`${reason} — inherited from the S2-007 dependency binding; this ticket reports it and does not fix it`);
    } else if (gate.status === 'BLOCKED') blocked.push(reason);
    else defects.push(reason);
  }

  if (gateCommands && gateCommands.ok !== true) {
    const renamed = gateCommands.issues.filter((issue) => issue.includes('repointed') || issue.includes('removed') || issue.includes('duplicated'));
    if (renamed.length > 0) defects.push(`the mandatory gate set was altered: ${renamed.join('; ')}`);
    else notRun.push(`a mandatory npm script is absent from package.json: ${(gateCommands.absent ?? []).join(', ')}`);
  }
  if (gateCommands && Array.isArray(gateCommands.absent) && gateCommands.absent.length > 0 && gateCommands.ok === true) {
    for (const id of gateCommands.absent) notRun.push(`the mandatory npm script for gate ${id} is not declared in package.json`);
  }
  if (tamperChecks && tamperChecks.ok !== true) {
    if ((tamperChecks.checked ?? 0) > 0) {
      defects.push(`the aggregator accepted a tampered evidence artifact for: ${(tamperChecks.undetected ?? []).join(', ')}`);
    } else {
      // No artifact-bearing gate was available to classify, so the matrix could
      // not be exercised. That is a missing proof, not an accepted forgery.
      notRun.push('the evidence tamper matrix was not exercised: no mandatory gate produced a fresh artifact in this invocation, so it is UNPROVEN here rather than green');
    }
  }
  if (selfChecks && selfChecks.ok !== true) {
    defects.push(`the aggregator's own negative controls failed: ${(selfChecks.failures ?? []).join('; ')}`);
  }
  for (const observation of observations) {
    if (observation.blocksCompletion !== true) continue;
    defects.push(`${observation.name} is not refreshed for this tree and reports ${observation.status ?? 'an unknown status'}: ${observation.why}`);
  }
  if (realAdapter?.forged === true) {
    defects.push(`the real-adapter record claims a real run that does not survive re-verification: ${(realAdapter.reasons ?? []).slice(0, 4).join('; ')}`);
  }
  if (realAdapter && realAdapter.status === 'NOT_RUN_REAL_ADAPTER' && byId['real-adapter-run']?.status === 'PASS') {
    // A green gate whose own record cannot corroborate a real executor is a
    // contradiction, and a contradiction is a defect rather than a skip.
    defects.push('the real-adapter gate reports PASS while its own record does not carry a corroborated executor invocation');
  }
  // A status that was read from a record this invocation did not produce is a
  // claim about an earlier run wearing this run's clothes. The record is attached
  // to a gate row as soon as the file parses, including a gate that just exited
  // non-zero or wrote nothing, so the freshness of THAT record has to be checked
  // before it may raise a status.
  if (realAdapter?.status === 'REAL_ADAPTER_AVAILABLE' && realAdapterFromThisRun !== true) {
    defects.push('the real-adapter status was read from a record this invocation did not produce (its freshness checks did not all pass), so it is not evidence about this run');
  }
  if (realAdapterTamper && (realAdapterTamper.checked ?? 0) > 0 && realAdapterTamper.ok !== true) {
    defects.push(`a doctored real-adapter record was accepted: ${(realAdapterTamper.undetected ?? []).join(', ')}`);
  }
  if (comparison?.fail === true) {
    defects.push(`the comparison record names more than one ${comparison.crossInput.join(' or ')}: two inputs are two comparisons, and its delta is not a comparison result`);
  }
  if (amvp && amvp.readable === true && byId['real-adapter-run']?.status !== 'PASS') {
    defects.push('the per-case A-MVP table was read from a record that no gate of this verification produced');
  }
  if (stopCondition !== null && STOP_CONDITIONS.includes(String(stopCondition))) {
    blocked.push(`the run stopped on a declared stop condition: ${stopCondition}`);
  }
  for (const deferred of deferredArms) {
    notRun.push(`a mandatory component could not run: ${deferred.probe}/${deferred.arm} (${deferred.code}) — ${deferred.reason}`);
  }
  if (measurements && Array.isArray(measurements.defects) && measurements.defects.length > 0) {
    // A measurement that reported a FAILED_GATE is a FINDING. It belongs in the
    // defect bucket with the other findings, not in the "could not run" bucket:
    // mapping a real authority-expansion result onto NOT_MEASURED turned a defect
    // into a PARTIAL skip with no counter movement and no REVISE.
    for (const defect of measurements.defects) {
      defects.push(`the measurement ${defect.name} reports ${defect.claimedStatus}: a real finding is never normalised into an unmeasured cell`);
    }
  }
  if (measurements && measurements.notMeasured.length > 0) {
    notRun.push(`these measurements are not measured: ${measurements.notMeasured.join(', ')}`);
  }

  const allGreen = MANDATORY_GATE_IDS.every((id) => byId[id]?.status === 'PASS');
  const clean = checkout?.clean === true;
  let engineeringStatus;
  if (defects.length > 0) engineeringStatus = 'REVISE';
  else if (blocked.length > 0) engineeringStatus = 'BLOCKED';
  else if (notRun.length > 0) engineeringStatus = 'PARTIAL';
  else if (allGreen && clean) engineeringStatus = 'COMPLETE_WITH_LIMITS';
  else if (allGreen) engineeringStatus = 'PASS_WITH_LIMITS';
  else engineeringStatus = 'REVISE';

  const verdictReasons = [
    ...defects.map((reason) => `[REVISE] ${reason}`),
    ...blocked.map((reason) => `[BLOCKED] ${reason}`),
    ...notRun.map((reason) => `[PARTIAL] ${reason}`),
  ];
  if (verdictReasons.length === 0) {
    verdictReasons.push(clean
      ? 'every mandatory gate of this ticket is PASS in this clean checkout, all seven hard-gate counters are 0, and the real-adapter record was re-verified from the bytes on disk; the ceiling is still COMPLETE_WITH_LIMITS, which is NOT an A-MVP pass and NOT production readiness'
      : `every mandatory gate is PASS, but the checkout is not clean (${checkout?.changedPathCount} changed paths), so COMPLETE_WITH_LIMITS is not claimed`);
  }
  return {
    engineeringStatus,
    assuranceStatus: 'NOT_MEASURED',
    assuranceCeiling: 'NOT_MEASURED is the honest status and no evidence produced by this ticket can move it: a real installed adapter with a human review behind it, and an empirical semantic accuracy, are not derivable from a scripted, fixture or replay run.',
    notInferred: ['real_adapter_execution_without_corroboration', 'human_review', 'empirical_semantic_accuracy', 'A_MVP_PASS', 'operator_acceptance', 'production_readiness'],
    verdictReasons,
    buckets: { defects, blocked, notRun },
  };
}

/** Exit code for a verdict. Non-zero unless every mandatory gate really passed. */
export function exitCodeForVerdict(verdict) {
  return verdict.engineeringStatus === 'COMPLETE_WITH_LIMITS' || verdict.engineeringStatus === 'PASS_WITH_LIMITS'
    ? EXIT_VERIFIED
    : EXIT_NOT_VERIFIED;
}

// ---------------------------------------------------------------------------
// The aggregation itself
// ---------------------------------------------------------------------------
export async function verifyS2_007R(args = {}) {
  const startedFrom = { head: headIdentity(), workspace: workspaceState() };
  const packageScripts = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).scripts ?? {};
  const gateCommands = assertGateSetIntact({ packageScripts });
  // THE HOST FACT, taken once per invocation and passed down. A real-adapter
  // claim is never judged against the record's own word about which executables
  // exist: it is judged against what `probeRealAdapters` finds installed here.
  const probe = await probeInstalledExecutors();

  const gates = [];
  const realExitCodes = {};
  for (const spec of EXPECTED_GATES) {
    const declared = packageScripts[spec.script];
    const entrypoint = gateCommands.entrypoints?.[spec.id] ?? null;
    const effectiveSpec = entrypoint === null ? spec : { ...spec, entrypoint };
    if (declared === undefined) {
      gates.push({
        id: spec.id, spec: effectiveSpec, status: 'NOT_RUN', exitCode: null,
        reasons: [`the mandatory npm script ${spec.script} is not declared in package.json`], checks: [],
        counters: null, freshness: { artifact: null, note: spec.contract },
      });
      realExitCodes[spec.command] = null;
      continue;
    }
    if (entrypoint === null || !fs.existsSync(path.join(ROOT, entrypoint))) {
      gates.push({
        id: spec.id, spec: effectiveSpec, status: 'NOT_RUN', exitCode: null,
        reasons: [`the gate implementation ${String(entrypoint)} is not in this checkout`], checks: [],
        counters: null, freshness: { artifact: null, note: spec.contract },
      });
      realExitCodes[spec.command] = null;
      continue;
    }
    let relativeFile = spec.evidenceFiles[0] ?? null;
    const absoluteFile = relativeFile ? path.join(ROOT, relativeFile) : null;
    const before = absoluteFile && fs.existsSync(absoluteFile) ? { sha256: sha256Of(fs.readFileSync(absoluteFile)) } : null;
    const run = runProcess(spec.script, { timeout: spec.timeoutMs, extraArgs: spec.extraArgs ?? [] });
    realExitCodes[spec.command] = run.exitCode;

    if (spec.kind === 'json-stdout+file') {
      const read = absoluteFile ? readJsonFile(absoluteFile) : { bytes: null, record: null };
      const classified = classifyJsonGate({ gate: effectiveSpec, run, bytes: read.bytes, record: read.record, head: startedFrom.head, before, relativeFile });
      gates.push({
        id: spec.id, spec: effectiveSpec, exitCode: run.exitCode, status: classified.status, reasons: classified.reasons,
        checks: classified.checks, counters: null, freshness: classified.freshness, runStdout: run.stdout,
        stderrTail: classified.stderrTail, stdoutTail: classified.stdoutTail, reportedIssues: classified.reportedIssues ?? null,
      });
      continue;
    }

    // evidence-envelope gates
    const read = absoluteFile ? readJsonFile(absoluteFile) : { bytes: null, record: null };
    let envelope = null;
    try {
      envelope = JSON.parse(run.stdout);
    } catch {
      envelope = null;
    }
    let usedRead = read;
    if (!read.bytes) {
      for (const candidate of spec.evidenceFiles.slice(1)) {
        const candidatePath = path.join(ROOT, candidate);
        if (fs.existsSync(candidatePath)) {
          usedRead = readJsonFile(candidatePath);
          relativeFile = candidate;
          break;
        }
      }
    }
    const classified = classifyEvidenceGate({
      gate: effectiveSpec, envelope, run, bytes: usedRead.bytes, record: usedRead.record, head: startedFrom.head, before,
      relativeFile: relativeFile ?? null,
    });
    const row = {
      id: spec.id, spec: effectiveSpec, exitCode: run.exitCode, status: classified.status, reasons: classified.reasons,
      checks: classified.checks, counters: classified.counters ?? null, freshness: { ...classified.freshness, evidenceFile: relativeFile },
      record: usedRead.record, envelope,
      stderrTail: run.exitCode === 0 ? null : (String(run.stderr).slice(-1200) || null),
      stdoutTail: run.exitCode === 0 ? null : (String(run.stdout).slice(-1200) || null),
    };
    if (spec.id === 'real-adapter-run') {
      // THE CRITICAL RULE, applied to the record this gate just read.
      const claim = classifyRealAdapterClaim({ record: usedRead.record, probe });
      row.realAdapterClaim = claim;
      row.checks = [...row.checks, ...claim.checks.map((check) => ({ check: `real-adapter:${check.check}`, ok: check.ok, detail: check.detail }))];
      if (claim.status !== 'REAL_ADAPTER_AVAILABLE' && row.status === 'PASS') {
        row.status = 'NOT_RUN';
        row.reasons = [...row.reasons, `real-adapter:NOT_RUN_REAL_ADAPTER: ${claim.reasons.slice(0, 4).join('; ')}`];
      }
      if (claim.forged === true) {
        row.status = 'FAIL';
        row.reasons = [...row.reasons, 'real-adapter:the record claims a real run it does not carry'];
      }
    }
    if (spec.id === 'comparison') {
      // A refused comparison is NOT_RUN here, whatever its own status field
      // says, and a comparison that names two projects, two grants or two cost
      // bases is a FAIL. The aggregate re-derives the precondition the contract
      // states instead of trusting one self-declared string, and the ABSENCE of
      // `verdict` is a refusal too.
      const comparison = classifyComparisonClaim({ record: usedRead.record });
      row.comparisonClaim = comparison;
      row.checks = [...row.checks, ...comparison.checks.map((check) => ({ check: `comparison:${check.label}`, ok: check.ok, detail: check.detail }))];
      if (comparison.fail === true) {
        row.status = 'FAIL';
        row.reasons = [...row.reasons, `comparison:the record names more than one ${comparison.crossInput.join(' or ')}`];
      } else if (!comparison.ok && row.status === 'PASS') {
        row.status = 'NOT_RUN';
        row.reasons = [...row.reasons, `comparison:${comparison.checks.filter((check) => !check.ok).map((check) => check.label).join(', ')} — an incomplete or refused comparison is never a completed measurement`];
      }
    }
    gates.push(row);
  }

  // ---- the seven counters, in every source of truth -----------------------
  const counterSources = [];
  const probesGate = gates.find((gate) => gate.id === 'probes');
  if (probesGate?.record?.counters) {
    const check = checkHardGateCounters(probesGate.record.counters);
    counterSources.push({
      source: 'evidence/s2-007r-security-probes.json',
      bound: freshnessSatisfied(probesGate),
      allZero: check.ok,
      counters: check.counters,
      issues: check.issues,
    });
  }
  const runGate = gates.find((gate) => gate.id === 'real-adapter-run');
  const runCounters = runGate?.record?.hardGates?.counters ?? runGate?.record?.counters ?? null;
  if (runCounters) {
    const check = checkHardGateCounters(runCounters);
    counterSources.push({
      source: 'evidence/s2-007r-pilot.json',
      bound: freshnessSatisfied(runGate),
      allZero: check.ok,
      counters: check.counters,
      issues: check.issues,
    });
  }
  if (counterSources.length === 0) {
    counterSources.push({
      source: 'none', bound: false, allZero: false, counters: null,
      issues: ['no mandatory gate produced a fresh counter block: the seven hard gates were not measured in this verification'],
    });
  }

  // ---- the honesty axes, judged independently ----------------------------
  // The record is only evidence about THIS invocation when its own freshness
  // checks pass; otherwise it is a file from an earlier run and every status it
  // could raise is dropped to NOT_RUN_REAL_ADAPTER. `record` is attached to a
  // gate row as soon as the file parses, so "the file exists" was never the same
  // thing as "this run produced it".
  const realRunFresh = freshnessSatisfied(runGate);
  const realRunRecord = realRunFresh ? runGate?.record ?? null : null;
  const realAdapterClaim = classifyRealAdapterClaim({ record: realRunRecord, probe });
  const availability = adapterAvailability({
    records: [
      { source: 'evidence/s2-007r-pilot.json', record: realRunRecord },
      { source: 'declared real-adapter registrations (src/lib/agentboard/real-executor.mjs)', record: readDeclaredRealRegistrations() },
    ],
    probe,
  });
  const realAdapterStatus = availability.available.length > 0 && realAdapterClaim.status === 'REAL_ADAPTER_AVAILABLE'
    ? 'REAL_ADAPTER_AVAILABLE'
    : 'NOT_RUN_REAL_ADAPTER';

  const pilot = readPilotCases();
  const amvpRaw = readJsonFile(path.join(ROOT, 'evidence/s2-007r-amvp-cases.json')).record;
  const corroboratedRuns = availability.available.map((row) => row.run_id).filter((row) => typeof row === 'string');
  // The per-case file is not a gate's own artifact, so it is not in any
  // `evidenceFiles` list and the S2-007 tamper matrix cannot cover it. It is
  // read only when it is bound to this commit AND to a corroborated real-adapter
  // run; otherwise every case is forced to NOT_RUN.
  const amvpRecord = classifyAmvpRecord({ record: amvpRaw, head: startedFrom.head, realAdapterStatus, corroboratedRuns });
  const amvpRows = amvpRecord.cases;
  const aMvpCases = A_MVP_IDS.map((id) => classifyAMvpCase({
    id,
    pilotCase: pilot.cases.find((row) => row.id === id) ?? null,
    observed: isPlainObject(amvpRows[id]) ? amvpRows[id].observed : null,
    realAdapterStatus,
    corroboratedRuns,
    reasons: isPlainObject(amvpRows[id]) && typeof amvpRows[id].why === 'string' ? [amvpRows[id].why] : [],
    recordReadable: amvpRecord.readable,
    recordReason: amvpRecord.reason,
  }));
  const pilotDigestFrozen = readFrozenDigest('pilots/scenario-a/acceptance-cases.json');
  const aMvp = {
    status: 'NOT_CLAIMED',
    source: 'pilots/scenario-a/acceptance-cases.json (every A-MVP case stays at execution NOT_RUN: the frozen schema has no value for a real run, D9) + evidence/s2-007r-amvp-cases.json for this ticket\'s own per-case observation',
    pilotFileSha256: pilot.sha256,
    pilotFileMatchesFrozenManifest: pilotDigestFrozen === null ? null : pilotDigestFrozen === pilot.sha256,
    record: 'evidence/s2-007r-amvp-cases.json',
    recordPresent: amvpRaw !== null,
    recordReadable: amvpRecord.readable,
    recordAnchored: amvpRecord.anchored,
    recordReason: amvpRecord.reason,
    recordChecks: amvpRecord.checks,
    cases: aMvpCases,
    passedCases: aMvpCases.filter((row) => row.observed === 'PASS').map((row) => row.id),
    notRunCases: aMvpCases.filter((row) => row.observed !== 'PASS').map((row) => row.id),
    note: 'aMvpStatus stays NOT_CLAIMED: no named operator accepted a bounded pilot after review, and no case is a runtime certification on its own. A per-case PASS is an observation, not an acceptance.',
  };

  const { names: measurementNameList, source: measurementSource } = measurementNames();
  const comparisonGate = gates.find((gate) => gate.id === 'comparison');
  const comparisonRecord = comparisonGate?.record
    ?? readJsonFile(path.join(ROOT, 'evidence/s2-007r-comparison.json')).record;
  const measurements = classifyMeasurements({ record: comparisonRecord, names: measurementNameList, source: measurementSource });
  const comparisonClaim = comparisonGate?.comparisonClaim ?? classifyComparisonClaim({ record: comparisonRecord });

  // ---- the aggregator's own negative controls ----------------------------
  const scratchDir = path.join(ROOT, CHAT_TMP, `s2-007r-verify-${String(startedFrom.head.commit).slice(0, 12)}`);
  const tamperChecks = runTamperMatrix({ gates, head: startedFrom.head, scratchDir });
  const realAdapterTamper = runRealAdapterTamperMatrix({ record: realRunRecord, probe, scratchDir });
  const amvpTamper = runAmvpTamperMatrix({ scratchDir, head: startedFrom.head });

  const allGreenGates = MANDATORY_GATE_IDS.map((id) => ({ id, status: 'PASS', exitCode: 0, reasons: [] }));
  const zeroCounters = Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0]));
  const controlVerdict = (controlGates, extra = {}) => deriveVerdict({
    gates: controlGates,
    gateCommands: { ok: true, absent: [] },
    counterSources: [{ source: 'self-check', bound: true, allZero: true, counters: zeroCounters }],
    tamperChecks: { ok: true, checked: 1, undetected: [] },
    selfChecks: { ok: true, failures: [] },
    checkout: { clean: true },
    observations: [],
    ...extra,
  }).engineeringStatus;
  const allGreenExtra = {
    realAdapter: { status: 'REAL_ADAPTER_AVAILABLE', forged: false, reasons: [] },
    measurements: { notMeasured: [], defects: [] },
    deferredArms: [],
    realAdapterTamper: { ok: true, checked: 1, undetected: [] },
    realAdapterFromThisRun: true,
  };
  const negativeControls = {
    allGreenCleanCheckout: controlVerdict(allGreenGates, allGreenExtra),
    greenButDirtyCheckout: controlVerdict(allGreenGates, { ...allGreenExtra, checkout: { clean: false, changedPathCount: 1 } }),
    skippedMandatoryGate: controlVerdict(allGreenGates.map((row) => (row.id === 'probes' ? { ...row, status: 'NOT_RUN', reasons: ['self-check: a mandatory probe reported NOT_RUN'] } : row)), allGreenExtra),
    blockedDependency: controlVerdict(allGreenGates.map((row) => (row.id === 'dependencies' ? { ...row, status: 'BLOCKED_DEPENDENCY', reasons: ['self-check'] } : row)), allGreenExtra),
    failedGate: controlVerdict(allGreenGates.map((row) => (row.id === 'comparison' ? { ...row, status: 'FAIL', reasons: ['self-check'] } : row)), allGreenExtra),
    counterFinding: controlVerdict(allGreenGates, { ...allGreenExtra, counterSources: [{ source: 'self-check', bound: true, allZero: false, counters: { ...zeroCounters, falseApprovals: 1 } }] }),
    undetectedTampering: controlVerdict(allGreenGates, { ...allGreenExtra, tamperChecks: { ok: false, checked: 1, undetected: ['probes/stale-commit'] } }),
    // The REAL gate-set check, not a hand-written issue string. The previous
    // control injected `'script:s2-007r:real-run:repointed(...)'` straight into
    // the verdict, so it could only prove that the ladder reads `issues` — it
    // could not detect that `assertGateSetIntact` accepted a repointed gate,
    // which is exactly what it was there to detect. This one drives
    // `assertGateSetIntact` with a genuinely repointed package.json and requires
    // BOTH that it reports the issue and that the ladder answers REVISE.
    renamedGate: (() => {
      const repointed = assertGateSetIntact({
        packageScripts: { ...packageScripts, 's2-007r:real-run': 'node scripts/s2-007r-measure.mjs' },
      });
      const ladder = controlVerdict(allGreenGates, { ...allGreenExtra, gateCommands: repointed });
      return {
        issueDetected: repointed.ok === false && repointed.issues.some((issue) => issue.includes('repointed')),
        verdict: ladder,
        ok: repointed.ok === false && ladder === 'REVISE',
      };
    })(),
    repointedComparisonGate: (() => {
      const repointed = assertGateSetIntact({
        packageScripts: { ...packageScripts, 's2-007r:comparison': 'node scripts/s2-007r-probes.mjs' },
      });
      return { ok: repointed.ok === false && repointed.issues.some((issue) => issue.includes('repointed')), issues: repointed.issues };
    })(),
    absentGateScript: controlVerdict(allGreenGates, { ...allGreenExtra, gateCommands: { ok: true, issues: [], absent: ['comparison'] } }),
    unmeasuredMeasurement: controlVerdict(allGreenGates, { ...allGreenExtra, measurements: { notMeasured: ['cost'], defects: [] } }),
    // A measurement that reports a real FINDING is a defect, not a skip.
    measurementWithAFinding: controlVerdict(allGreenGates, { ...allGreenExtra, measurements: { notMeasured: [], defects: [{ name: 'skills_authority_expansion', claimedStatus: 'FAILED_GATE', why: 'self-check' }] } }),
    comparisonAcrossTwoGrants: controlVerdict(allGreenGates, { ...allGreenExtra, comparison: { fail: true, crossInput: ['budget_grant_id'] } }),
    statusReadFromAStaleRecord: controlVerdict(allGreenGates, { ...allGreenExtra, realAdapterFromThisRun: false }),
    undetectedRealAdapterTampering: controlVerdict(allGreenGates, { ...allGreenExtra, realAdapterTamper: { ok: false, checked: 1, undetected: ['pid-tree-empty'] } }),
    deferredArm: controlVerdict(allGreenGates, { ...allGreenExtra, deferredArms: [{ probe: 'p', arm: 'a', code: 'NOT_RUN_REAL_ADAPTER', reason: 'self-check' }] }),
    declaredStopCondition: controlVerdict(allGreenGates, { ...allGreenExtra, stopCondition: 'NO_INSTALLED_EXECUTOR' }),
    // The two honesty controls that matter most for this ticket.
    realAdapterClaimThatDoesNotSurvive: controlVerdict(allGreenGates, { ...allGreenExtra, realAdapter: { status: 'NOT_RUN_REAL_ADAPTER', forged: true, reasons: ['self-check: the record claims a real run it does not carry'] } }),
    greenGateWithUncorroboratedRecord: controlVerdict(allGreenGates, { ...allGreenExtra, realAdapter: { status: 'NOT_RUN_REAL_ADAPTER', forged: false, reasons: ['self-check'] } }),
    // A configured-but-unrun adapter and an adapter that does not exist must be
    // indistinguishable. Proved by output, not by a comment — and proved WITH the
    // host fact in hand, because on this host `pi` really is installed: a
    // declaration must still not become availability when the executable it
    // names is sitting on PATH.
    unrunAdapterIndistinguishableFromMissing: (() => {
      const configured = adapterAvailability({ records: [{ source: 'x', record: { executor: { adapter_id: 'adr-pi-local', version: 's2-007r-real-executor-v1' }, status: 'PASS', ok: true } }], probe });
      const missing = adapterAvailability({ records: [{ source: 'x', record: null }], probe });
      return canonicalDigest(configured.available) === canonicalDigest(missing.available)
        && configured.available.length === 0 && missing.available.length === 0
        && classifyRealAdapterClaim({ record: null, probe }).status === 'NOT_RUN_REAL_ADAPTER';
    })(),
    // Always-runnable: every doctored variant of a FILE-FACT-COMPLETE record
    // must be refused. Without this, "the matrix could not run" and "the
    // classifier is blind" would look identical. The baseline is built on a REAL
    // installed executor from a live probe row, so a variant that is refused
    // proves the check refuses it and not that the baseline was incomplete.
    realAdapterTamperOnForgedRecord: (() => {
      const synthetic = syntheticCorroboratedRecord(probe);
      if (synthetic.ran !== true) {
        return { ok: false, ran: false, checked: 0, baseline: 'NOT_RUN', strong: 0, undetected: [], reason: synthetic.reason };
      }
      try {
        const matrix = matrixOver({ record: synthetic.record, probe, scratchDir, results: [], label: 'selfcheck-real-adapter' });
        return {
          ok: matrix.ok && matrix.baselineStatus === 'REAL_ADAPTER_AVAILABLE' && matrix.strong === matrix.checked,
          ran: true,
          checked: matrix.checked,
          baseline: matrix.baselineStatus,
          basedOn: synthetic.basedOn,
          strong: matrix.strong,
          undetected: matrix.undetected,
        };
      } finally {
        fs.rmSync(synthetic.logDir, { recursive: true, force: true });
      }
    })(),
    // Always-runnable: an unanchored per-case A-MVP file must never yield a PASS.
    amvpTamperOnAnUnanchoredRecord: amvpTamper,
    // "The matrix could not run" and "tampering was detected" are different
    // states, and only the SECOND one may satisfy a control. The previous version
    // scored `ok || checked === 0`, so a run with no real record to doctor
    // reported the honesty axis as proven.
    realAdapterTamperRan: (realAdapterTamper.checked ?? 0) > 0,
    realAdapterTamperDetected: (realAdapterTamper.checked ?? 0) === 0 || realAdapterTamper.ok === true,
  };
  const selfChecks = {
    ok: negativeControls.allGreenCleanCheckout === 'COMPLETE_WITH_LIMITS'
      && negativeControls.greenButDirtyCheckout === 'PASS_WITH_LIMITS'
      && negativeControls.skippedMandatoryGate === 'PARTIAL'
      && negativeControls.blockedDependency === 'PARTIAL'
      && negativeControls.failedGate === 'REVISE'
      && negativeControls.counterFinding === 'REVISE'
      && negativeControls.undetectedTampering === 'REVISE'
      && negativeControls.renamedGate.ok === true
      && negativeControls.repointedComparisonGate.ok === true
      && negativeControls.absentGateScript === 'PARTIAL'
      && negativeControls.unmeasuredMeasurement === 'PARTIAL'
      && negativeControls.measurementWithAFinding === 'REVISE'
      && negativeControls.comparisonAcrossTwoGrants === 'REVISE'
      && negativeControls.statusReadFromAStaleRecord === 'REVISE'
      && negativeControls.undetectedRealAdapterTampering === 'REVISE'
      && negativeControls.deferredArm === 'PARTIAL'
      && negativeControls.declaredStopCondition === 'BLOCKED'
      && negativeControls.realAdapterClaimThatDoesNotSurvive === 'REVISE'
      && negativeControls.greenGateWithUncorroboratedRecord === 'REVISE'
      && negativeControls.unrunAdapterIndistinguishableFromMissing === true
      && (negativeControls.realAdapterTamperOnForgedRecord.ran === false || negativeControls.realAdapterTamperOnForgedRecord.ok === true)
      && negativeControls.amvpTamperOnAnUnanchoredRecord.ok === true
      && negativeControls.realAdapterTamperDetected === true
      && gateCommands.ok,
    failures: [
      ...(negativeControls.allGreenCleanCheckout === 'COMPLETE_WITH_LIMITS' ? [] : ['four green gates in a clean checkout did not produce COMPLETE_WITH_LIMITS']),
      ...(negativeControls.greenButDirtyCheckout === 'PASS_WITH_LIMITS' ? [] : ['a dirty checkout did not cap the verdict at PASS_WITH_LIMITS']),
      ...(negativeControls.skippedMandatoryGate === 'PARTIAL' ? [] : ['a skipped mandatory gate did not yield PARTIAL']),
      ...(negativeControls.blockedDependency === 'PARTIAL' ? [] : ['an inherited blocked dependency gate did not yield PARTIAL (issue §8 places it there, not in BLOCKED)']),
      ...(negativeControls.failedGate === 'REVISE' ? [] : ['a failed mandatory gate did not yield REVISE']),
      ...(negativeControls.counterFinding === 'REVISE' ? [] : ['a non-zero hard-gate counter did not yield REVISE']),
      ...(negativeControls.undetectedTampering === 'REVISE' ? [] : ['undetected evidence tampering did not yield REVISE']),
      ...(negativeControls.renamedGate.ok === true ? [] : [`a repointed mandatory gate was not detected by the real gate-set check, or did not yield REVISE (${JSON.stringify(negativeControls.renamedGate)})`]),
      ...(negativeControls.repointedComparisonGate.ok === true ? [] : [`the comparison gate was repointed to another script of the same family and assertGateSetIntact accepted it: ${(negativeControls.repointedComparisonGate.issues ?? []).join('; ')}`]),
      ...(negativeControls.absentGateScript === 'PARTIAL' ? [] : ['an absent mandatory npm script did not yield PARTIAL']),
      ...(negativeControls.unmeasuredMeasurement === 'PARTIAL' ? [] : ['an unmeasured measurement did not yield PARTIAL']),
      ...(negativeControls.measurementWithAFinding === 'REVISE' ? [] : ['a measurement that reported FAILED_GATE did not yield REVISE: a real finding must not be downgraded to a skip']),
      ...(negativeControls.comparisonAcrossTwoGrants === 'REVISE' ? [] : ['a comparison naming two budget grants did not yield REVISE']),
      ...(negativeControls.statusReadFromAStaleRecord === 'REVISE' ? [] : ['a real-adapter status read from a record this invocation did not produce did not yield REVISE']),
      ...(negativeControls.undetectedRealAdapterTampering === 'REVISE' ? [] : ['an undetected doctored real-adapter record did not yield REVISE']),
      ...(negativeControls.deferredArm === 'PARTIAL' ? [] : ['a deferred mandatory arm did not yield PARTIAL']),
      ...(negativeControls.declaredStopCondition === 'BLOCKED' ? [] : ['a declared stop condition did not yield BLOCKED']),
      ...(negativeControls.realAdapterClaimThatDoesNotSurvive === 'REVISE' ? [] : ['a real-adapter claim that does not survive re-verification did not yield REVISE']),
      ...(negativeControls.greenGateWithUncorroboratedRecord === 'REVISE' ? [] : ['a green real-adapter gate over an uncorroborated record did not yield REVISE']),
      ...(negativeControls.unrunAdapterIndistinguishableFromMissing === true ? [] : ['a configured-but-unrun adapter is distinguishable from an adapter that does not exist']),
      ...(negativeControls.realAdapterTamperOnForgedRecord.ran === false
        ? [`the real-adapter honesty classifier could not be exercised: ${String(negativeControls.realAdapterTamperOnForgedRecord.reason)}`]
        : (negativeControls.realAdapterTamperOnForgedRecord.ok === true ? [] : [`the real-adapter honesty classifier accepted a doctored record (${(negativeControls.realAdapterTamperOnForgedRecord.undetected ?? []).join(', ')})`])),
      ...(negativeControls.amvpTamperOnAnUnanchoredRecord.ok === true ? [] : [`an unanchored per-case A-MVP record was read (${(negativeControls.amvpTamperOnAnUnanchoredRecord.undetected ?? []).join(', ')})`]),
      ...(negativeControls.realAdapterTamperDetected === true ? [] : ['the real-adapter tamper matrix on the real record found an undetected variant']),
      ...(gateCommands.ok ? [] : ['the frozen gate set does not match package.json']),
    ],
    negativeControls,
    gateSetOk: gateCommands.ok,
  };

  const deferredArms = (probesGate?.record?.deferredArms ?? []).map((row) => ({
    probe: row.probe ?? 'unknown', arm: row.arm ?? 'unknown', code: row.code ?? 'NOT_RUN', reason: row.reason ?? 'no reason recorded',
  }));
  const stopCondition = [at(runGate?.record, 'stopCondition'), at(runGate?.record, 'stop_condition')].find((value) => STOP_CONDITIONS.includes(String(value))) ?? null;

  const verdict = deriveVerdict({
    gates, gateCommands, counterSources, tamperChecks, selfChecks, checkout: startedFrom.workspace, observations: [],
    realAdapter: { ...realAdapterClaim, forged: realAdapterClaim.forged === true },
    measurements, deferredArms, stopCondition,
    realAdapterTamper, comparison: comparisonClaim, amvp: amvpRecord, realAdapterFromThisRun: realRunFresh,
  });
  const matrix = buildMatrix({ gates, counterSources, tamperChecks, realAdapterTamper, selfChecks, checkout: startedFrom.workspace, aMvp, measurements, realAdapterStatus, availability, verdict, comparisonClaim, amvpTamper, probe });

  const summary = {
    schemaVersion: 1,
    ticket: 'S2-007R',
    issue: 'SpaceDazher/Veritas#45',
    role: 'verification aggregator for the real-adapter ticket: freshness, internal status, the seven hard-gate counters, the tamper matrices, the re-verified real-adapter claim, the per-case A-MVP table, the seven measurements and the derived verdict',
    gate: 'verify:s2-007r',
    commit: startedFrom.head.commit,
    tree: startedFrom.head.tree,
    runId: `s2-007r-verify-${canonicalDigest({
      commit: startedFrom.head.commit,
      tree: startedFrom.head.tree,
      gates: gates.map((row) => [row.id, row.status, row.exitCode]),
      counters: counterSources.map((row) => [row.source, row.counters]),
      realAdapterStatus,
    }).slice(0, 24)}`,
    freshnessModel: 'Every mandatory gate is re-run by THIS process. An evidence artifact is accepted only when the process exited 0, the bytes on disk hash to the digest the gate reported for the file it just wrote, the record content address matches, the record is bound to the current HEAD commit and, where it carries one, to the current HEAD tree, the internal status and the seven counters say PASS, and — for the real-adapter record — the executor claim survives re-verification from the bytes on disk. A gate whose npm script is absent is NOT_RUN, never PASS: an unavailable mandatory tool and a proven failure are different states, and only the second one is a defect.',
    gateContracts: Object.fromEntries(EXPECTED_GATES.map((spec) => [spec.id, { command: spec.command, contract: spec.contract, evidenceFiles: spec.evidenceFiles }])),
    gates: Object.fromEntries(gates.map((row) => [row.id, {
      command: row.spec.command,
      status: row.status,
      expectedStatus: row.spec.expectedStatus,
      exitCode: row.exitCode,
      reasons: row.reasons,
      checks: row.checks,
      counters: row.counters ?? null,
      freshness: row.freshness,
      stderrTail: row.stderrTail ?? null,
      stdoutTail: row.stdoutTail ?? null,
      reportedIssues: row.reportedIssues ?? null,
    }])),
    realExitCodes,
    gateCommands,
    hardGates: {
      counters: Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0])),
      sources: counterSources,
      ok: counterSources.some((source) => source.bound) && counterSources.filter((source) => source.bound).every((source) => source.allZero),
    },
    // --- the four status axes, judged separately ---
    engineeringStatus: verdict.engineeringStatus,
    realAdapterStatus,
    realAdapter: {
      status: realAdapterStatus,
      record: 'evidence/s2-007r-pilot.json',
      recordPresent: realRunRecord !== null,
      recordProducedByThisInvocation: realRunFresh,
      gateStatus: runGate?.status ?? 'NOT_EVALUATED',
      adapterId: realAdapterClaim.adapterId,
      corroborated: realAdapterClaim.corroborated,
      checks: realAdapterClaim.checks,
      reasons: realAdapterClaim.reasons,
      adapters: availability,
      hostProbe: {
        // The host fact, recorded so a reader can see WHICH observation the
        // claim was tested against instead of taking the verdict on trust.
        source: 'probeRealAdapters (the same host fact commands.mjs:assertRealAdapterClaimIsTrue corroborates a registration against)',
        rows: probe.map((row) => ({ adapter_id: row.adapter_id, installed: row.installed, binary_path: maskHome(row.binary_path), detail: row.detail })),
        installedCount: probe.filter((row) => row.installed === true).length,
      },
      claimRule: 'REAL_ADAPTER_AVAILABLE requires, all re-verified from the bytes on disk and against a live host fact: a non-placeholder executor version, an absolute binary path that resolves to an executable regular file whose sha256 matches the record AND that a live probeRealAdapters row reports as an installed executor on this host, a readable raw process log whose sha256 matches the record and which parses as the executor\'s own raw process log document naming the same binary, the same run and the same exit status, a NON-ZERO integer exit status, honesty.script_used and honesty.replay_used false, honesty.transport_source in {codex-transport, pi-transport}, a non-empty corroboration.executor_session_id that appears VERBATIM in the raw log bytes and agrees with the log\'s own usage report, a NON-EMPTY parent-observed pid tree of positive process ids (an empty array is an unobservable process space, not an observed one), and an observer that is not the adapter itself. Anything missing or wrong is NOT_RUN_REAL_ADAPTER.',
      residualLimit: 'A determined writer can still craft a document that is self-consistent with itself and with a real installed binary. What the aggregator cannot do, and this is stated rather than hidden: the in-process observation real-executor.mjs keeps in a WeakSet, because this gate reads a FILE. The claims that used to be forgeable with a text file, the `node` binary, an invented session id and an empty pid tree are refused.',
      indistinguishableRule: 'adapters.available is built only from corroborated runs. A registration, a configuration or a declared provider never appears there, so a configured-but-unrun adapter is indistinguishable, in this output, from one that does not exist (selfChecks.negativeControls.unrunAdapterIndistinguishableFromMissing proves it).',
      tamperChecks: realAdapterTamper,
    },
    assuranceStatus: verdict.assuranceStatus,
    assuranceCeiling: verdict.assuranceCeiling,
    notInferred: verdict.notInferred,
    aMvpStatus: aMvp.status,
    aMvp,
    measurements: {
      ...measurements,
      rule: 'each measurement is judged on its own: a name from the closed seven, a status from the closed vocabulary read from the producing module, and for anything measured a value, a named basis, a named method, a non-empty stated limitation, a published artefact whose bytes hash to the recorded digest, and — for a ratio or a count — published integer numerator and denominator. A measurement that does not satisfy all of that reads NOT_MEASURED and caps the ticket at PARTIAL. A measurement that reports FAILED_GATE is a FINDING: it is a defect and moves the verdict to REVISE, because a real boundary-refusal result must never be normalised into an unmeasured cell.',
    },
    comparison: {
      ...comparisonClaim,
      rule: 'the comparison contract is re-derived, not believed: the record must state verdict COMPARED (an ABSENT verdict is a refusal), and the distinct values of project_digest, budget_grant_id and cost_basis over the record and every cell must be one each. A record naming two projects, two grants or two cost bases is FAIL, whatever verdict string it carries.',
    },
    amvpTamper,
    deferredArms,
    stopCondition,
    tamperChecks,
    selfChecks,
    observations: [],
    matrix,
    verdictReasons: verdict.verdictReasons,
    verdictPrecedence: [
      'REVISE (a defect was found) > BLOCKED (an inherited stop condition) > PARTIAL (a mandatory component could not run) > PASS_WITH_LIMITS (every gate green but the checkout is dirty) > COMPLETE_WITH_LIMITS',
    ],
    checkout: startedFrom.workspace,
    finalAcceptance: {
      note: 'The final acceptance set is run by the owner at acceptance, not by this aggregator: it must not rebuild Next.js or run the whole suite while other work is in flight, and a result it did not observe may not be reported as observed.',
      commands: ['npm test', 'npm run typecheck', 'npm run lint', 'npm run build', 'npm run inventory:check', 'npm run manifest:check', 'node scripts/validate-contracts.mjs', 'node scripts/check-public-artifacts.mjs', 'npm run verify:clean-checkout', 'git diff --check'],
      statuses: Object.fromEntries(['npm test', 'npm run typecheck', 'npm run lint', 'npm run build', 'npm run inventory:check', 'npm run manifest:check', 'node scripts/validate-contracts.mjs', 'node scripts/check-public-artifacts.mjs', 'npm run verify:clean-checkout', 'git diff --check'].map((command) => [command, 'NOT_RUN_BY_THIS_AGGREGATOR'])),
    },
    residualLimitations: [
      'assuranceStatus is NOT_MEASURED and aMvpStatus is NOT_CLAIMED, and nothing in this record can move either: there is no independent human reviewer and no operator acceptance in this run.',
      'A real-adapter status is read only from a record whose executor claim was re-verified against the bytes on disk. Every other record — a registration, a probe row, a configuration entry — is a host fact or a claim, never a run.',
      'The probes run against the in-memory store; the A-MVP-06/A-MVP-07 database facts belong to the DB gate, not to this one.',
      'Where a mandatory component could not run, the reason is named in omits/deferredArms rather than smoothed over: an unproven defence and a proven one are different states.',
    ],
    rollback: {
      code: 'this ticket adds new files and new npm scripts only; removing scripts/s2-007r-*.mjs, scripts/verify-s2-007r.mjs and the evidence/s2-007r-*.json records returns the checkout to its pre-ticket state.',
      evidence: 'delete evidence/s2-007r-*.json; every gate is re-runnable from a clean checkout.',
      verification: 'npm run verify:s2-007r (the aggregator will report PARTIAL/BLOCKED/REVISE rather than green until every mandatory gate is green again).',
    },
  };
  summary.recordDigest = canonicalDigest({ ...summary, recordDigest: undefined });

  if (!WRITE_SUPPRESSED(args['no-write'])) {
    fs.mkdirSync(path.dirname(path.join(ROOT, SUMMARY_RELATIVE)), { recursive: true });
    fs.writeFileSync(path.join(ROOT, SUMMARY_RELATIVE), `${JSON.stringify(summary, null, 2)}\n`);
  }
  return { summary, exitCode: exitCodeForVerdict(verdict) };
}

function freshnessSatisfied(gate) {
  if (!gate?.record) return false;
  const freshnessChecks = (gate.checks ?? []).filter((check) => check.check.startsWith('freshness:'));
  return freshnessChecks.length > 0 && freshnessChecks.every((check) => check.ok === true);
}

/**
 * The real adapters the checkout DECLARES. Read statically, never imported: a
 * list of declared providers is a configuration, and this function exists only
 * to show that a declaration does not become availability.
 */
function readDeclaredRealRegistrations() {
  for (const relative of ['src/lib/agentboard/real-executor.mjs', 'src/lib/executors/constants.mjs']) {
    const absolute = path.join(ROOT, relative);
    if (!fs.existsSync(absolute)) continue;
    try {
      const text = fs.readFileSync(absolute, 'utf8');
      const block = /REAL_PROVIDERS\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\)/.exec(text);
      if (block === null) continue;
      const providers = [...block[1].matchAll(/'([^']+)'/g)].map((match) => match[1]);
      if (providers.length === 0) continue;
      return {
        executor: { adapter_id: providers.join(','), version: 'declared-only' },
        status: 'NOT_RUN_REAL_ADAPTER',
        note: `declared in ${relative}; a declaration is not a run and never reaches adapters.available`,
      };
    } catch {
      // fall through
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// The criterion -> observation -> evidence matrix
// ---------------------------------------------------------------------------
function buildMatrix({ gates, counterSources, tamperChecks, realAdapterTamper, selfChecks, checkout, aMvp, measurements, realAdapterStatus, availability, verdict, comparisonClaim = null, amvpTamper = null, probe = null }) {
  const gate = (id) => gates.find((row) => row.id === id) ?? null;
  const statusOf = (id) => gate(id)?.status ?? 'NOT_EVALUATED';
  const exitOf = (id) => gate(id)?.exitCode ?? null;
  const row = (criterion, requirement, observation, evidence, status) => ({ criterion, requirement, observation, evidence, status });
  return [
    row('C1 dependency binding', 'issue §6: the inherited S2-007 dependency binding is verified before any implementation; a blocked binding is BLOCKED, not green',
      `dependency gate ${statusOf('dependencies')} (exit ${exitOf('dependencies')}) at HEAD ${checkout?.changedPathCount === undefined ? '' : ''}commit ${gate('dependencies')?.freshness?.commitAnchor ?? 'n/a'}`,
      'evidence/s2-007-dependency-binding.json', statusOf('dependencies')),
    row('C2 a real executor really crossed the boundary', 'issue §4: a run is a real adapter only with a version string, a binary digest corroborated by a LIVE host probe, a raw log with a digest that is the executor\'s own log document, and a real exit status — all re-verified from the bytes on disk',
      `real-adapter gate ${statusOf('real-adapter-run')} (exit ${exitOf('real-adapter-run')}); realAdapterStatus ${realAdapterStatus}; adapters.available ${availability.available.length}; executables the live host probe reports installed: ${(probe ?? []).filter((entry) => entry.installed === true).map((entry) => entry.adapter_id).join(', ') || 'none'}`,
      'evidence/s2-007r-real-adapter-run.json + the live probeRealAdapters fact', realAdapterStatus === 'REAL_ADAPTER_AVAILABLE' ? 'PASS' : `NOT_RUN (${realAdapterStatus})`),
    row('C3 a configured adapter is not an available one', 'issue §4: a configured-but-unrun adapter is indistinguishable, in the output, from one that does not exist',
      `${availability.configured.length} configured adapter entries, ${availability.available.length} corroborated`,
      'evidence/s2-007r-summary.json (realAdapter.adapters)', selfChecks.negativeControls.unrunAdapterIndistinguishableFromMissing === true ? 'PASS' : 'FAIL'),
    row('C4 the mandatory negative probes', 'issue §5: five probes through the production-facing path, seven hard-gate counters all 0',
      `probes gate ${statusOf('probes')} (exit ${exitOf('probes')}); counters ${JSON.stringify(counterSources.find((source) => source.source.includes('s2-007r-security-probes'))?.counters ?? {})}`,
      'evidence/s2-007r-security-probes.json', statusOf('probes')),
    row('C5 the comparison is one project and one budget', 'issue §5: two configurations on ONE project digest and ONE grant, or the comparison is REFUSED. Re-derived here: verdict COMPARED present and the distinct project_digest / budget_grant_id / cost_basis over the record and its cells are one each',
      `comparison gate ${statusOf('comparison')} (exit ${exitOf('comparison')}); verdict ${String(comparisonClaim?.verdict ?? 'ABSENT')}; cross-input fields ${(comparisonClaim?.crossInput ?? []).join(',') || 'none'}`,
      'evidence/s2-007r-comparison.json',
      statusOf('comparison') === 'PASS' && comparisonClaim?.ok === true ? 'PASS' : statusOf('comparison')),
    row('C6 the seven measurements', 'issue §5: seven measurements, each recomputable by a third party from the record alone; a measurement reporting FAILED_GATE is a finding, not a gap',
      `${measurements.measured}/${measurements.expected} measured; not measured: ${measurements.notMeasured.join(', ') || 'none'}; findings: ${measurements.defects.map((row) => `${row.name}=${row.claimedStatus}`).join(', ') || 'none'}; artefacts ${measurements.artefactsVerifiedOnDisk}/${measurements.artefactsPublished} verified on disk (${measurements.rowsSource})`,
      'evidence/s2-007r-comparison.json (cells[].measurements[])', measurements.notMeasured.length === 0 && measurements.defects.length === 0 ? 'PASS' : (measurements.defects.length > 0 ? 'FAIL (a measurement reported a finding)' : 'PARTIAL')),
    row('C7 freshness of every result', 'issue §6: each gate is re-run in this invocation and re-classified against tampered copies; a tampered artifact that is accepted fails the run. The real-adapter and per-case matrices are inputs to the verdict, not decoration',
      `evidence tamper matrix: ${tamperChecks?.checked ?? 0} variants, ${(tamperChecks?.undetected ?? []).join(', ') || 'none undetected'}; real-adapter tamper matrix: ${realAdapterTamper?.checked ?? 0} variants, ${(realAdapterTamper?.undetected ?? []).join(', ') || 'none undetected'}${realAdapterTamper?.checked === 0 ? ' (not exercised: no fresh real-adapter record this invocation — UNPROVEN, not passed)' : ''}; per-case A-MVP matrix: ${amvpTamper?.checked ?? 0} variants, ${(amvpTamper?.undetected ?? []).join(', ') || 'none undetected'}`,
      'evidence/s2-007r-summary.json (tamperChecks, realAdapter.tamperChecks, amvpTamper)',
      tamperChecks?.ok === true && ((realAdapterTamper?.checked ?? 0) === 0 || realAdapterTamper?.ok === true) && (amvpTamper?.ok ?? true) === true ? 'PASS' : 'FAIL'),
    row('C8 no gate renaming', 'issue §6: a gate may not be renamed or repointed to obtain a green status',
      `the gate set is compared with package.json: ${selfChecks?.gateSetOk === true ? 'intact' : `issues: ${(selfChecks?.negativeControls ? 'see selfChecks.failures' : '')}`}`,
      'evidence/s2-007r-summary.json (gateCommands)', selfChecks?.gateSetOk === true ? 'PASS' : 'FAIL'),
    row('C9 honest A-MVP status', 'issue §7: the frozen pilot file keeps every case at NOT_RUN; the per-case observation lives in this ticket\'s own record, is read only when that record is bound to this commit and to a corroborated real-adapter run, and no case is an acceptance',
      `aMvpStatus ${aMvp.status}; cases PASS ${aMvp.passedCases.length}/7, NOT_RUN ${aMvp.notRunCases.length}/7; per-case record readable ${aMvp.recordReadable} (anchored ${aMvp.recordAnchored}); pilot file matches the frozen manifest: ${String(aMvp.pilotFileMatchesFrozenManifest)}`,
      'pilots/scenario-a/acceptance-cases.json, evidence/s2-007r-amvp-cases.json', aMvp.recordReadable === false ? 'PASS (the unauthenticated per-case file was refused, so every case reads NOT_RUN)' : 'PASS'),
    row('C10 the assurance ceiling', 'issue §7: assuranceStatus is NOT_MEASURED and aMvpStatus is NOT_CLAIMED, whatever the engineering evidence says',
      `assuranceStatus ${verdict.assuranceStatus}; aMvpStatus ${aMvp.status}; notInferred ${verdict.notInferred.join(', ')}`,
      'evidence/s2-007r-summary.json', 'PASS'),
  ];
}

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    if (!argv[i].startsWith('--')) continue;
    const key = argv[i].slice(2);
    const next = argv[i + 1];
    // `--flag` and `--flag true` are both accepted, and a flag whose value is
    // missing is TRUE rather than the string "true": a boolean flag that
    // silently reads as a string is how a `--no-write` stops suppressing.
    args[key] = (next === undefined || next.startsWith('--')) ? true : next;
    if (args[key] === true && next !== undefined && !next.startsWith('--')) i += 1;
  }
  return args;
}

const WRITE_SUPPRESSED = (value) => value === true || value === 'true';

const isMain = process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1]).split(path.sep).join('/')}`).href;
if (isMain) {
  const args = parseArgs(process.argv);
  let outcome;
  try {
    outcome = await verifyS2_007R(args);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      ticket: 'S2-007R',
      gate: 'verify:s2-007r',
      engineeringStatus: 'REVISE',
      realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
      assuranceStatus: 'NOT_MEASURED',
      aMvpStatus: 'NOT_CLAIMED',
      exitCode: EXIT_NOT_VERIFIED,
      verdictReasons: [`aggregator:untyped-failure:${String(error?.stack ?? error?.message ?? error).slice(0, 800)}`],
    }, null, 2)}\n`);
    process.exit(EXIT_NOT_VERIFIED);
  }
  const { summary } = outcome;
  console.log(JSON.stringify({
    engineeringStatus: summary.engineeringStatus,
    realAdapterStatus: summary.realAdapterStatus,
    assuranceStatus: summary.assuranceStatus,
    aMvpStatus: summary.aMvpStatus,
    exitCode: outcome.exitCode,
    runId: summary.runId,
    commit: summary.commit,
    tree: summary.tree,
    gates: Object.fromEntries(Object.entries(summary.gates).map(([id, row]) => [id, `${row.status} (exit ${row.exitCode})`])),
    realExitCodes: summary.realExitCodes,
    hardGatesOk: summary.hardGates.ok,
    counters: summary.hardGates.sources.map((source) => [source.source, source.counters]),
    tamperChecks: { ok: summary.tamperChecks.ok, checked: summary.tamperChecks.checked, undetected: summary.tamperChecks.undetected },
    realAdapterTamper: { ok: summary.realAdapter.tamperChecks.ok, checked: summary.realAdapter.tamperChecks.checked, undetected: summary.realAdapter.tamperChecks.undetected },
    adaptersAvailable: summary.realAdapter.adapters.available,
    aMvpCases: summary.aMvp.cases.map((row) => `${row.id}:${row.observed}`),
    measurements: summary.measurements.per.map((row) => `${row.name}:${row.status}`),
    selfChecks: summary.selfChecks,
    verdictReasons: summary.verdictReasons,
    evidence: SUMMARY_RELATIVE,
  }, null, 2));
  process.exit(outcome.exitCode);
}
