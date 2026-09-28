// The ONLY path to REAL_ADAPTER_AVAILABLE (issue #45, SPEC §2 file 10).
//
// This module decides what a run record MEANS. It never mints one: the only
// record it will adjudicate is one the transport minted from a process it
// actually spawned and observed, and the object identity of that record is the
// fact no file on disk can carry. A record reconstructed from JSON, hand-typed,
// copied out of a test fixture or produced by a scripted transport is not in
// the registry and is refused before it can reach the status.
// WHAT THIS MODULE PROVES, AND WHAT IT CANNOT (issue #45, round-3 audit)
//
// The round-3 honesty audit forged a REAL_ADAPTER_AVAILABLE corroboration: it
// wrote a raw process log describing a crossing that never happened, called the
// EXPORTED mint, and assertRealRunEvidence accepted it. The WeakSet below was
// readable by every importer, so the one check that no file on disk can satisfy
// was in fact satisfiable by any code in the process.
//
// Two changes close that, and one sentence states what is left:
//
//   1. The mint is behind a ONE-TIME CAPABILITY. acquireMintCapability() hands
//      the token to the first caller and refuses every later one, so the set of
//      modules that can mint is the transport and, in the worst case, whichever
//      importer won a module-evaluation race. mintObservedRunEvidence now
//      requires that token and mints nothing without it.
//   2. A minted record carries `observation_trust`, so a reader is told what the
//      registry entry is worth instead of inferring it.
//
// THE RESIDUAL, STATED PLAINLY: in-process unforgeability is not achievable
// across ESM modules — any exported function is importable, and a caller that
// wins the acquire race holds the token. Object identity therefore proves
// "this record was minted by the cooperating transport in this process", which
// stops the realistic attack (a record replayed, copied or hand-written from
// disk) and does NOT stop hostile code running in the same process. Verifying
// observation from a DIFFERENT process needs a signature over the log, which
// needs a host key this repository deliberately does not hold. The published
// records therefore say so in `observation_trust`, and the stage record lists it
// as a residual limitation. Claiming more than this is the defect the audit
// found.
import { randomBytes } from 'node:crypto';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { assertBoardContract } from '../agentboard/contracts.mjs';
import { NeedsInput, NotRunRealAdapter, redact } from '../agentboard/errors.mjs';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import { REAL_EXECUTOR_VERSION, REAL_PROVIDERS, PROVIDER_ARGV_ALLOWLIST, RUN_ID_RE } from './constants.mjs';
import { assertArgvAllowed, isPlainObject, requireString, deepFreeze, wireDigest } from './internals.mjs';

// The observation registry. Minted here, read here; nothing else can enter it.
const OBSERVED_RUN_EVIDENCE = new WeakSet();

// The one-time mint capability. It is created here, handed out exactly once,
// and never written anywhere: not to disk, not to a record, not to a log.
const MINT_CAPABILITY = randomBytes(32);
let mintCapabilityClaimed = false;

/** What a registry entry is worth. Published in every minted record. */
export const OBSERVATION_TRUST = 'COOPERATING_TRANSPORT_IN_THIS_PROCESS__NOT_AN_ADVERSARY_BOUNDARY';

/**
 * Hand the mint capability to the one caller that may use it.
 *
 * The first call wins; every later call returns null. A caller that receives the
 * token must keep it private and must pass it back to mintObservedRunEvidence.
 * The transport acquires it at module evaluation, which is why a caller that
 * merely imports this module can no longer mint anything.
 */
export function acquireMintCapability() {
  if (mintCapabilityClaimed) return null;
  mintCapabilityClaimed = true;
  return MINT_CAPABILITY;
}

/** True when the capability is the live one. Never reveals the value. */
export function isMintCapability(candidate) {
  return Buffer.isBuffer(candidate) && candidate.length === MINT_CAPABILITY.length
    && Object.is(candidate[0], MINT_CAPABILITY[0])
    && MINT_CAPABILITY.every((byte, index) => candidate[index] === byte);
}

/**
 * Register a record this process minted from a process it actually observed.
 * Without the one-time capability this mints nothing and throws: the round-3
 * audit forged a corroboration through exactly the exported version of this
 * function, so the exported function is no longer a way in.
 */
export function mintObservedRunEvidence(record, capability) {
  if (!isMintCapability(capability)) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_MINT_REFUSED',
      'minting an observed run record requires the one-time mint capability, which only the transport holds',
    );
  }
  if (!isPlainObject(record)) throw new NeedsInput('record: object required');
  // The trust statement travels WITH the record, so nobody downstream can read
  // the registry entry as more than it is.
  Object.defineProperty(record, 'observation_trust', {
    value: OBSERVATION_TRUST,
    enumerable: true,
    writable: false,
    configurable: false,
  });
  OBSERVED_RUN_EVIDENCE.add(record);
  return record;
}

/** True only for a record minted by mintObservedRunEvidence in THIS process. */
export function isObservedRunEvidence(record) {
  return OBSERVED_RUN_EVIDENCE.has(record);
}

// ---------------------------------------------------------------------------
// REAL-RUN EVIDENCE: the refusal path, written first
// ---------------------------------------------------------------------------

function fileSha256(absolutePath, label) {
  let buffer;
  try {
    buffer = fs.readFileSync(absolutePath);
  } catch (error) {
    throw new NotRunRealAdapter(
      `REAL_RUN_EVIDENCE_UNREADABLE:${label}`,
      `${label} could not be read from disk: ${redact(String(error?.message ?? error)).slice(0, 200)}`,
    );
  }
  return { bytes: buffer.length, sha256: wireDigest(buffer), buffer };
}

/**
 * The ONLY path to REAL_ADAPTER_AVAILABLE. Every field is re-derived here from
 * the filesystem and BOUND to the raw process log, and the record itself must
 * be one this module minted from a process it actually observed.
 *
 * Required, all of them:
 *   run_id                 a `run-` id, EQUAL to the run_id in the log
 *   executor.version       exactly REAL_EXECUTOR_VERSION
 *   executor.provider      one of REAL_PROVIDERS
 *   executor.binary_path   an absolute path that RESOLVES (symlinks followed)
 *                          to an existing, executable regular file, and whose
 *                          BASENAME is that provider's own binary
 *   executor.binary_sha256 sha256 of those resolved bytes
 *   raw_process_log_path   an absolute path to the raw process log
 *   raw_process_log_sha256 sha256 of those bytes
 *   exit_status            an integer, NON-ZERO: an observed exit, EQUAL to the
 *                          exit_status in the log
 *
 * The log is parsed, not merely digested, and it must corroborate the record:
 * its record_kind, executor_version, run_id, provider, binary path, binary
 * digest, exit status and argv shape all have to agree, and the recorded argv
 * is re-validated against the provider's own allowlist. A record that only
 * agrees with ITSELF and with two files that exist proves nothing, so the
 * observation registry closes that last gap: only a record minted by
 * transport.evidenceRecord() from an observed process is adjudicable at all.
 *
 * Anything missing, anything the log disagrees with, any digest that does not
 * match the bytes on disk, a zero or absent exit status, a binary that is not
 * an executable file, and a record that was never observed, is refused with
 * NotRunRealAdapter. There is no partial accept and no fallback.
 */
export function assertRealRunEvidence(record) {
  if (!isPlainObject(record)) throw new NeedsInput('realRunEvidence: object required');
  const raw = record;
  // A missing sub-object is a MISSING FIELD, not a caller typo: this function
  // has one answer for every way the claim fails to be complete.
  if (!isPlainObject(raw.executor)) {
    throw new NotRunRealAdapter('REAL_RUN_EVIDENCE_EXECUTOR', 'the record carries no executor object to verify');
  }
  const executor = raw.executor;

  if (typeof raw.run_id !== 'string' || !RUN_ID_RE.test(raw.run_id)) {
    throw new NotRunRealAdapter('REAL_RUN_EVIDENCE_RUN_ID', `run_id must match ${RUN_ID_RE}, got ${String(raw.run_id)}`);
  }
  if (executor.version !== REAL_EXECUTOR_VERSION) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_VERSION',
      `the record was produced by '${String(executor.version)}', not by this executor (${REAL_EXECUTOR_VERSION})`,
    );
  }
  // The provider is a CLOSED SET, never an optional annotation. A record that
  // cannot name the CLI it really ran is refused before anything is read.
  if (typeof executor.provider !== 'string' || !REAL_PROVIDERS.includes(executor.provider)) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_PROVIDER',
      `executor.provider must be one of ${REAL_PROVIDERS.join(', ')}, got ${JSON.stringify(executor.provider)}`,
    );
  }
  const provider = executor.provider;

  const binaryPath = executor.binary_path;
  if (typeof binaryPath !== 'string' || !path.isAbsolute(binaryPath)) {
    throw new NotRunRealAdapter('REAL_RUN_EVIDENCE_BINARY_PATH', 'binary_path must be an absolute path');
  }
  // IDENTITY: the named path must BE the provider's binary, by name. "Any
  // executable regular file" was enough to make /bin/false an executor; the
  // named basename is what a host probe reports, and it is checked against the
  // provider's own argv allowlist below.
  const namedBinary = path.basename(binaryPath);
  if (namedBinary !== PROVIDER_ARGV_ALLOWLIST[provider].binary) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_BINARY_IDENTITY',
      `a ${provider} run must name the '${PROVIDER_ARGV_ALLOWLIST[provider].binary}' binary, got ${JSON.stringify(namedBinary)}`,
    );
  }
  // A symlink is resolved BEFORE the digest is taken, so a record cannot name a
  // friendly launcher and be corroborated against different bytes.
  let resolved;
  try {
    resolved = fs.realpathSync(binaryPath);
  } catch (error) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_BINARY_UNRESOLVABLE',
      `binary_path does not resolve: ${redact(String(error?.message ?? error)).slice(0, 200)}`,
    );
  }
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch (error) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_BINARY_UNREADABLE',
      `the resolved binary could not be stat'ed: ${redact(String(error?.message ?? error)).slice(0, 200)}`,
    );
  }
  if (!stat.isFile()) {
    throw new NotRunRealAdapter('REAL_RUN_EVIDENCE_BINARY_NOT_A_FILE', 'the resolved binary is not a regular file');
  }
  try {
    fs.accessSync(resolved, fs.constants.X_OK);
  } catch {
    throw new NotRunRealAdapter('REAL_RUN_EVIDENCE_BINARY_NOT_EXECUTABLE', 'the resolved binary is not executable');
  }
  const binary = fileSha256(resolved, 'executor.binary_path');
  if (executor.binary_sha256 !== binary.sha256) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_BINARY_DIGEST_MISMATCH',
      `the record claims ${String(executor.binary_sha256)}; the bytes on disk are ${binary.sha256}`,
    );
  }

  const logPath = raw.raw_process_log_path;
  if (typeof logPath !== 'string' || !path.isAbsolute(logPath)) {
    throw new NotRunRealAdapter('REAL_RUN_EVIDENCE_LOG_PATH', 'raw_process_log_path must be an absolute path');
  }
  const log = fileSha256(logPath, 'raw_process_log_path');
  if (raw.raw_process_log_sha256 !== log.sha256) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_DIGEST_MISMATCH',
      `the record claims ${String(raw.raw_process_log_sha256)}; the bytes on disk are ${log.sha256}`,
    );
  }

  // Non-zero, on purpose: this gate corroborates that a REAL process ran and
  // that its exit status was observed and recorded. An exit of 0, a missing
  // status, a string, a null or a NaN is refused. See the header for why.
  if (!Number.isInteger(raw.exit_status) || raw.exit_status === 0) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_EXIT_STATUS',
      `exit_status must be a recorded NON-ZERO integer, got ${JSON.stringify(raw.exit_status)}`,
    );
  }
  // An exit nobody saw is not an observation of anything. This field is a
  // claim, and the registry check below is the fact; both are required.
  if (raw.exit_observed !== true) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_EXIT_NOT_OBSERVED',
      'the record does not carry an OBSERVED exit; a status this process never saw is not evidence of a crossing',
    );
  }

  // AGREEMENT: the log is the record of the process, so the two must agree
  // field by field. A log that is only digested was a file whose existence was
  // proven, not a run that was.
  let logDocument;
  try {
    logDocument = JSON.parse(log.buffer.toString('utf8'));
  } catch {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_UNPARSEABLE',
      'the raw process log is not JSON, so it cannot corroborate anything',
    );
  }
  if (!isPlainObject(logDocument)) {
    throw new NotRunRealAdapter('REAL_RUN_EVIDENCE_LOG_SHAPE', 'the raw process log is not a JSON object');
  }
  if (logDocument.record_kind !== 'real-executor-raw-process-log') {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_KIND',
      `the file is a '${String(logDocument.record_kind)}', not a raw process log of this executor`,
    );
  }
  if (logDocument.executor_version !== REAL_EXECUTOR_VERSION) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_VERSION',
      `the log was written by '${String(logDocument.executor_version)}', not by ${REAL_EXECUTOR_VERSION}`,
    );
  }
  if (logDocument.run_id !== raw.run_id) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_DISAGREES',
      `the log records run ${JSON.stringify(logDocument.run_id)}; the record claims ${JSON.stringify(raw.run_id)}`,
    );
  }
  if (!isPlainObject(logDocument.executor) || logDocument.executor.provider !== provider) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_DISAGREES',
      `the log records provider ${JSON.stringify(logDocument.executor?.provider)}; the record claims ${JSON.stringify(provider)}`,
    );
  }
  if (logDocument.executor.binary_sha256 !== binary.sha256 || logDocument.executor.binary_path !== resolved) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_DISAGREES',
      `the log records executor ${JSON.stringify(logDocument.executor.binary_path)} `
      + `${JSON.stringify(logDocument.executor.binary_sha256)}; the record names ${resolved} ${binary.sha256}`,
    );
  }
  if (logDocument.executor.binary_named_path !== binaryPath) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_DISAGREES',
      `the log records the executor as ${JSON.stringify(logDocument.executor.binary_named_path)}; `
      + `the record names ${JSON.stringify(binaryPath)}`,
    );
  }
  if (logDocument.exit_status !== raw.exit_status) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_DISAGREES',
      `the log records exit_status ${JSON.stringify(logDocument.exit_status)}; the record claims ${JSON.stringify(raw.exit_status)}`,
    );
  }
  // The recorded argv is re-validated against the provider's own allowlist, so
  // a log is only accepted when it holds a provider-shaped invocation of the
  // provider it names.
  const recordedArgv = isPlainObject(logDocument.invocation) ? logDocument.invocation.argv : null;
  if (!Array.isArray(recordedArgv) || recordedArgv.length === 0) {
    throw new NotRunRealAdapter('REAL_RUN_EVIDENCE_LOG_ARGV', 'the log records no argv to corroborate the run with');
  }
  try {
    assertArgvAllowed(provider, recordedArgv);
  } catch (error) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_LOG_ARGV',
      `the argv the log records is not a ${provider} invocation this executor could have produced: `
      + `${redact(String(error?.message ?? error)).slice(0, 200)}`,
    );
  }

  // OBSERVATION, last: everything above can be read off two files, and two
  // files can be written by anyone. The fact that THIS module really spawned
  // the provider and really observed its exit is carried by the record's own
  // identity, and it is what no forged document can produce.
  if (!OBSERVED_RUN_EVIDENCE.has(raw)) {
    throw new NotRunRealAdapter(
      'REAL_RUN_EVIDENCE_NOT_OBSERVED',
      'this record was not minted by a real observed run of this executor; a record that was never '
      + 'observed by the process that ran the provider is a claim, not a corroboration',
    );
  }

  const verified = deepFreeze({
    run_id: raw.run_id,
    executor: {
      version: REAL_EXECUTOR_VERSION,
      provider,
      binary_path: resolved,
      binary_sha256: binary.sha256,
      binary_bytes: binary.bytes,
    },
    raw_process_log_path: logPath,
    raw_process_log_sha256: log.sha256,
    raw_process_log_bytes: log.bytes,
    exit_status: raw.exit_status,
    // The adjudicated document says so explicitly, so re-adjudicating a
    // VERIFIED record (which is what a registration does) is not refused for
    // a field the verification itself established.
    exit_observed: true,
  });
  // The verified document inherits the observation, so the documented chain
  // mint -> assertRealRunEvidence -> createRealRegistration is closed.
  OBSERVED_RUN_EVIDENCE.add(verified);
  return verified;
}