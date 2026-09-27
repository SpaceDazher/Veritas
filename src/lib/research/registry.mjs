// S2-008 research track — the FILE LEDGER (issue SpaceDazher/Veritas#8).
//
// Serves acceptance items A3 and A5, and negative probes P1 (peek) and P4
// (opaque budget). It is the store the six probes drive: every probe and every
// replay writes through the exports of this file, never through a private
// helper, so a rewired boundary is visible to the probes.
//
// WHY THIS FILE IS SMALL ON PURPOSE
// It is the smallest file-backed store that can support the four proofs, and
// no larger. One canonical-JSON record per line, a `sha256 prev_digest` chain,
// an idempotency ledger consulted BEFORE any read of the business state, a
// revision CAS on `head.json`, a lock that is an OPTIMISATION ONLY, torn-tail
// recovery to the last complete record, and a purge that is idempotent. It is
// not a second distributed state machine and it must not grow into one: a
// reservation state machine is out of scope, and the preregistration-side
// budget rule lives in preregistration.mjs against the same injected clock.
// The ledger enforces the reservation rule INDEPENDENTLY anyway, because the
// ledger is the only thing that can make a spend durable — a rule checked only
// in the preregistration plane is a rule a caller can skip.
//
// WHAT IS ON DISK, AND WHY EXACTLY THESE FOUR FILES
//   registry.json    the ownership marker. `purgeRegistry` refuses a root that
//                    does not carry it, and it is deliberately NOT purged, so
//                    a second purge is a no-op instead of a refusal.
//   journal.ndjson   the domain records, one canonical-JSON line each, chained.
//   operations.ndjson the idempotency ledger AND the operation markers, the
//                    exact `agentboard_operation` split of
//                    src/lib/agentboard/store.mjs. Kept in a SECOND file on
//                    purpose: a marker that is a line of the journal cannot be
//                    "written last" in a way a torn write can fake. Here the
//                    marker names `journal_count` — how many journal lines
//                    committed before it — and `head.json` is written AFTER
//                    it, so head.json is the last word on what is committed.
//   head.json        `{revision, fence, head_digest, record_count,
//                    marker_digest, marker_count, at, version}`. Written last;
//                    its presence proves the journal append and the marker
//                    committed with it.
//   lock/lock.json   the advisory lock. Never part of `snapshotDigest`: a lock
//                    is an optimisation and must not move a digest.
//
// THE THIRTEEN store.mjs DISCIPLINES: FOUR MIRRORED, NINE REFUSED
// The header of src/lib/agentboard/store.mjs carries thirteen disciplines —
// eight "semantics that MUST NOT be improved later" plus five documented
// storage decisions. This file mirrors exactly four and refuses nine, and the
// partition is written out here so a reader can CHECK the claim instead of
// taking it.
//
// MIRRORED (4)
//  M1 IDEMPOTENCY FIRST — `operations.ndjson` is consulted before the head and
//     the journal are read. Same key + same args digest replays the prior
//     result and writes nothing; same key + different args is
//     `IdempotencyConflict` and writes nothing. Mirrors `_replay`
//     (src/lib/agentboard/store.mjs:790-817), including its refusal to report a
//     marker with no result as a success: it is `ReconciliationRequired`.
//  M2 REVISION IS A COMPARE-AND-SWAP — writes to `head.json` are conditional on
//     `revision = expectedRevision`; a mismatch is `RevisionConflict`, never a
//     blind last-write-wins.
//  M3 DB TIME ONLY — there is no database clock, so the ledger reads the
//     INJECTED clock passed to `openRegistry({root, clock, ids})`. No
//     `Date.now()`, no `Math.random()`, no argument-less `new Date()` anywhere
//     in a decision path, and `recordHoldoutRead` refuses a caller-stamped
//     `readAt` outright rather than trusting it.
//  M4 FAIL CLOSED — every refusal is an instance of the closed `BoardError`
//     class set of src/lib/agentboard/errors.mjs, and a document that claims a
//     frozen research contract is asserted through src/lib/research/contracts.mjs
//     before it is journalled AND when it is read back. The classes are
//     imported directly rather than through `refusalClass` (constants.mjs) so
//     that a still-skeleton sibling module can never turn a typed refusal into
//     `NOT_IMPLEMENTED` at run time; `refusalClass` stays the research
//     vocabulary's entry point for the codes this file does not use.
//
// REFUSED (9), each by name and with the reason
//  N1 LEASE-COUPLED FENCING (`fencing_token` agreeing with the ACTIVE lease,
//     revoke before reassign) — this ledger has no lease and no late callback
//     to fence. See E1 below: the MONOTONE half of the discipline is kept, the
//     lease-coupled half is refused.
//  N2 CLAIM LOSER (`SELECT ... FOR UPDATE` plus a partial unique index) — there
//     are no rows to lock and no database index. Two-writer contention is
//     exercised by tests/research/fixtures/ledger-writer-child.mjs under
//     `--no-lock`, and an interleaved write is DETECTED as a broken chain
//     rather than accepted silently.
//  N3 THE STORE NEVER INVENTS A STATE CHANGE — the ledger is a journal, not a
//     state machine. `RESEARCH_TRANSITIONS` (constants.mjs) and policy.mjs own
//     the edges; this file only records them.
//  N4 NO BLIND RETRY, as the board states it (RECONCILIATION_REQUIRED terminal
//     for the outbox dispatch state machine) — there is no outbox and no
//     dispatch state machine here. THE INVARIANT IS KEPT ANYWAY, in a form this
//     file must still honour: `recoverTornTail` returns a reconciliation row
//     instead of a silent truncation, an expired reservation commits a
//     reconciliation row BEFORE it throws, and a write whose outcome could not
//     be confirmed is `ReconciliationRequired`.
//  N5 THE `acceptance_criteria` STORAGE DECISION (kept in
//     `detail.task.acceptance_criteria` because the migration has no column) —
//     an S2-007 `board-task` migration artefact. No board task is stored here.
//  N6 THE `lease_rebind` / `lease_revoke` SAME-STATE JOURNAL RECORD — no lease
//     rebind or revoke event exists in the research boundary.
//  N7 THE LEASE-RENEWAL-WRITES-AUDIT-ONLY RULE — no lease and no renewal.
//  N8 THE `ID_PREFIXES` GAP (`aud- obx- rec-` as the S2-007 local extension of
//     the frozen prefix table) — the research ledger uses its OWN
//     `RESEARCH_ID_PREFIXES` and adds NOTHING to the frozen `ID_PREFIXES` at
//     src/lib/agentboard/constants.mjs:201. Identifiers are minted through the
//     reused `AgentBoardStoreBase.newId` (below), never by a second rule.
//  N9 THE LEASE ROW IS NOT A BOUNDARY DOCUMENT (normalised record, never
//     re-declared as a contract) — the three frozen research schemas are the
//     only boundary shapes and none of them is a registry record, so a journal
//     record is canonical JSON, not schema-shaped. A record that DOES carry a
//     boundary document must name its contract and is validated by it.
//
// TWO DOCUMENTED EXTENSIONS, both required and both named
//  E1 MONOTONE FENCING TOKEN. `head.fence` increases by exactly one per commit.
//     A caller may present `args.fence`; a token that is not the next one is
//     `StaleFence` and writes nothing. A process that read a head an earlier
//     writer has already moved past therefore cannot write, which is the A3/A5
//     requirement that a stale process is fenced. It is OPTIONAL for `args`
//     (the frozen `putExperiment` signature carries no fence parameter and the
//     narrow ledger paths mint theirs from the head they read), and the
//     revision CAS remains the mandatory gate in every case.
//  E2 STORED vs WIRE DIGEST. Every digest RETURNED by this file is the wire form
//     `sha256:<64 hex>` (`toWireDigest`, src/lib/agentboard/constants.mjs:214);
//     every digest STORED in a line is the bare 64-hex CHAR(64) form. Both
//     directions are fail-closed: a malformed stored digest never becomes
//     `null` on the wire.
//
// ORDERING (the one structural rule that is not negotiable)
//     idempotency key -> read head + journal -> revision CAS (+ fence) ->
//     journal record(s) -> operation marker -> head.json -> COMMIT
// head.json is written LAST. Its presence is the proof that everything before
// it committed with it; its absence means nothing was committed, and
// `recoverTornTail` truncates to the last marked record instead of guessing.
// Any failure before that last write restores the pre-transaction bytes, so a
// refusal leaves the ledger byte-identical (`snapshotDigest` unchanged).
//
// REUSE, NEVER FORK
//   * `canonicalDigest` / `assertCanonicalSafety` / `canonicalize` from
//     src/lib/verifier/canonical-json.mjs — the only digest, the only
//     serialisation and the write-safety gate. Every stored line is byte-exactly
//     its own canonical form, so a whitespace or key-order edit is detected.
//   * `AgentBoardStoreBase` from src/lib/agentboard/store.mjs — instantiated
//     once per registry as the injected-clock and identifier authority, and its
//     `newId(kind)` mints every id through the frozen `ID_PREFIXES` rule and
//     the S2-007 local extension.
//   * `toWireDigest`, `RECONCILIATION_RESOLUTIONS` and the closed `BoardError`
//     classes from src/lib/agentboard/{constants,errors,store}.mjs.
//   * `assertResearchContract` from src/lib/research/contracts.mjs — the single
//     validation path for every Campaign/Hypothesis/Experiment document the
//     ledger accepts or emits.
// This file never defines a second digest function, a second error class, a
// second id vocabulary or a second contract surface.
//
// WHAT IS **NOT** REUSED FROM store.mjs, AND WHY — read this before
// "simplifying" this module into an async one
// `AgentBoardStoreBase`'s rule engine (`_withUnitOfWork`, `_replay`,
// `_commitMark`) is `async`. The FROZEN interface of this module is
// SYNCHRONOUS — `putExperiment` returns `{result, revision, replayed,
// headDigest}`, not a Promise, and `dataset.mjs`/`comparator.mjs`/the probes
// consume it synchronously. A synchronous module cannot await the engine, so
// the engine is re-expressed here in a synchronous form and the ORDERING is
// copied line for line. `InMemoryAgentBoardStore` is deliberately NOT
// instantiated: an in-memory twin of a file journal is a second state path that
// can silently diverge from the journal, which is exactly what the header of
// store.mjs (lines 26-32) exists to forbid. Both facts are reported to
// delivery rather than hidden behind an `await` nobody can await.
//
// STATE OF THE SIBLINGS
// This module is implemented and self-contained. Its two `src/lib/research/`
// dependencies are implemented too — `RESEARCH_CONTRACTS` (constants.mjs) names
// the three frozen contracts and `assertResearchContract` (contracts.mjs)
// validates against them — so a document-bearing record is checked here for
// real, not refused for want of a sibling. The earlier state of this comment
// (both siblings still `NOT_IMPLEMENTED`) was honest while it was true and is
// now corrected rather than left to mislead: a stale "fails closed for now"
// note reads as a permanent property. The fail-closed path is still there and
// still typed — an unknown contract name is `NeedsInput('UNKNOWN_RESEARCH_
// CONTRACT')` and a schema violation is `MalformedResult` — and it is a
// property of THIS file, not a temporary state of somebody else's.
//
// OWNER: W2 (preregistration, data, store).
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { canonicalDigest, canonicalize, assertCanonicalSafety } from '../verifier/canonical-json.mjs';
import { AgentBoardStoreBase, RECONCILIATION_RESOLUTIONS } from '../agentboard/store.mjs';
import { toWireDigest } from '../agentboard/constants.mjs';
import {
  BlockedPolicy,
  BudgetExceeded,
  IdempotencyConflict,
  MalformedResult,
  NeedsInput,
  ProviderFailure,
  ReconciliationRequired,
  RevisionConflict,
  StaleFence,
} from '../agentboard/errors.mjs';
import { RESEARCH_ID_PREFIXES } from './constants.mjs';
import { RESEARCH_CONTRACTS, assertResearchContract } from './contracts.mjs';

/**
 * The version of the ledger format. A change to the stored shape is a change to
 * this string; a record written by another version is a `brokenAt`, not a
 * silent pass.
 */
const REGISTRY_VERSION = 's2-008-registry-v1';

/** The ownership marker `purgeRegistry` requires before it removes anything. */
const REGISTRY_MARKER_KIND = 's2-008-research-registry';

const MARKER_FILE = 'registry.json';
const JOURNAL_FILE = 'journal.ndjson';
const OPERATIONS_FILE = 'operations.ndjson';
const HEAD_FILE = 'head.json';
const LOCK_DIR = 'lock';
const LOCK_FILE = 'lock.json';

/** The four files a purge may remove. `registry.json` is NOT one of them. */
const OWNED_FILES = Object.freeze([JOURNAL_FILE, OPERATIONS_FILE, HEAD_FILE]);

/** The `prev_digest` of the first record of an empty journal. */
const GENESIS_DIGEST = '0'.repeat(64);

/** The record kind used when a payload does not name one. */
const DEFAULT_RECORD_KIND = 'RECORD';

const HEX64 = /^[0-9a-f]{64}$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const RECORD_KIND = /^[A-Z][A-Z0-9_]{0,47}$/;
const MAX_KEY_LENGTH = 128;
const LOCK_TTL_NS = 60_000_000_000; // 60 s ON THE INJECTED CLOCK, never on the wall clock

/**
 * Path segments a registry root may never live under. `contracts/` and
 * `evidence/` are frozen targets and `.git` is the delivery worker's; a
 * registry that could remove files there is a registry nobody should run.
 */
const PROTECTED_SEGMENTS = new Set(['.git', 'node_modules', 'contracts', 'evidence']);

/** Handle identity, so a foreign object is refused instead of half-worked. */
const HANDLE = Symbol.for('s2-008-research-registry.handle');

// ---------------------------------------------------------------------------
// Typed validation helpers. Each throws a member of the closed BoardError set;
// none of them can return a "probably fine" value.
// ---------------------------------------------------------------------------

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertRegistry(registry) {
  const ledger = registry !== null && typeof registry === 'object' ? registry[HANDLE] : undefined;
  if (ledger === undefined) {
    throw new NeedsInput('REGISTRY_NOT_OPEN: pass the handle returned by openRegistry, never a path');
  }
  return ledger;
}

function requireText(value, label, max) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    throw new NeedsInput(`${label} must be a string of 1..${max} characters`);
  }
  return value;
}

function requireKey(value, label = 'idempotency key') {
  return requireText(value, label, MAX_KEY_LENGTH);
}

/**
 * `args` carries the write arguments AND the optional fencing token, so a
 * non-object is refused rather than digested: this mirrors
 * `requirePlainObject` at src/lib/agentboard/store.mjs:142 instead of adding a
 * second, weaker rule. `undefined` still means "no arguments" (the frozen
 * signature marks `args` as required but a caller with nothing to say is a
 * caller with an empty argument set, not a caller with a malformed one).
 */
function requireArgs(value, label) {
  if (value === undefined) return {};
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new NeedsInput(`${label} must be a plain object; a non-object cannot carry the optional fencing token`);
  }
  return value;
}

function requireRevision(value, label = 'expectedRevision') {
  if (!Number.isInteger(value) || value < 0) {
    throw new NeedsInput(`${label} must be an integer >= 0 (0 is the revision of an empty ledger)`);
  }
  return value;
}

function requireUnits(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new NeedsInput(`${label} must be a finite number >= 0; a missing budget is not zero`);
  }
  return value;
}

function requireClock(clock) {
  if (!isPlainObject(clock) || typeof clock.nowNs !== 'function' || typeof clock.iso !== 'function') {
    throw new MalformedResult(
      'REGISTRY_CLOCK_NOT_INJECTED',
      'openRegistry requires the INJECTED fixed clock {nowNs, iso}; a registry with no injected clock is refused, never defaulted to the process clock',
    );
  }
  return clock;
}

function requireIds(ids) {
  if (typeof ids === 'function') return ids;
  if (isPlainObject(ids) && typeof ids.next === 'function') return (kind) => ids.next(kind);
  throw new MalformedResult(
    'REGISTRY_ID_FACTORY_NOT_INJECTED',
    'openRegistry requires the INJECTED deterministic id factory {next(kind)}; Math.random() is never consulted here',
  );
}

function requireInjectedClock(ledger) {
  const iso = ledger.clock.iso();
  if (typeof iso !== 'string' || !ISO_INSTANT.test(iso)) {
    throw new MalformedResult('REGISTRY_CLOCK_ISO_MALFORMED', `the injected clock returned ${String(iso)}`);
  }
  const ns = Number(ledger.clock.nowNs());
  if (!Number.isFinite(ns)) {
    throw new MalformedResult('REGISTRY_CLOCK_NOW_NS_MALFORMED', `the injected clock returned nowNs=${String(ledger.clock.nowNs())}`);
  }
  return { iso, ns };
}

function digestOf(value, label) {
  try {
    return canonicalDigest(value);
  } catch (error) {
    // A non-canonical argument is a caller error, not a transport failure, and
    // it must not escape as a TypeError (M4: nothing untyped escapes).
    throw new MalformedResult('REGISTRY_VALUE_NOT_CANONICAL', `${label}: ${String(error?.message ?? error).slice(0, 300)}`);
  }
}

function wireDigestOf(stored, label) {
  const wire = toWireDigest(stored);
  if (wire === null) throw new MalformedResult('STORED_DIGEST_MALFORMED', label);
  return wire;
}

// ---------------------------------------------------------------------------
// File helpers. A refusal must leave the ledger byte-identical, so every
// mutating step goes through writeAtomic and every transaction snapshots the
// bytes it may touch before it starts.
// ---------------------------------------------------------------------------

function readTextOrNull(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new ProviderFailure('REGISTRY_READ_FAILED', `${file}: ${String(error?.message ?? error).slice(0, 200)}`);
  }
  return text;
}

function readJsonStrict(file, label) {
  const text = readTextOrNull(file);
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new MalformedResult('REGISTRY_JSON_MALFORMED', `${label} at ${file} is not JSON: ${String(error?.message ?? error).slice(0, 200)}`);
  }
}

function readJsonLenient(file) {
  try {
    return readJsonStrict(file, 'file');
  } catch {
    // Only the advisory lock is read leniently: an unparseable lock is treated
    // as HELD by somebody, because a lock is an optimisation and stealing one
    // is worse than waiting for a process that does not exist.
    return null;
  }
}

function writeAtomic(file, text) {
  const tmp = `${file}.tmp`;
  try {
    writeFileSync(tmp, text, 'utf8');
    renameSync(tmp, file);
  } catch (error) {
    try {
      unlinkSync(tmp);
    } catch {
      // The temporary file is throwaway; failing to remove it must not mask
      // the failure that is being reported.
    }
    throw new ProviderFailure('REGISTRY_WRITE_FAILED', `${file}: ${String(error?.message ?? error).slice(0, 200)}`);
  }
}

// ---------------------------------------------------------------------------
// The chain. Every stored line is byte-exactly its own canonical form and
// carries `sha256(prev-line)` as `prev_digest`, so a rewrite, a reordering, an
// inserted space or a swapped record is all the same detectable defect.
// ---------------------------------------------------------------------------

function recordDigest(record) {
  const { digest, ...rest } = record;
  return canonicalDigest(rest);
}

function parseChainLine(line, index, prevDigest) {
  let value;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isPlainObject(value)) return null;
  if (value.index !== index) return null;
  if (typeof value.prev_digest !== 'string' || value.prev_digest !== prevDigest) return null;
  if (typeof value.digest !== 'string' || !HEX64.test(value.digest)) return null;
  try {
    if (value.digest !== recordDigest(value)) return null;
    if (canonicalize(value) !== line) return null;
  } catch {
    return null;
  }
  return value;
}

/**
 * Read one chain file. Returns the VALID PREFIX and the index at which it
 * stopped, so "the file is longer than the prefix" and "a line is unreadable"
 * are the same reported defect with two different shapes.
 */
function loadChain(file) {
  const text = readTextOrNull(file);
  if (text === null || text === '') {
    return { records: [], tornFrom: null, tornText: '', present: text !== null };
  }
  const parts = text.split('\n');
  let tornFrom = null;
  let tornText = '';
  if (parts[parts.length - 1] !== '') {
    // The file does not end on a newline: the last element is a HALF-WRITTEN
    // record, and it is the start of a torn tail.
    tornFrom = parts.length - 1;
    tornText = parts.pop();
  } else {
    // The trailing '' after the final newline is not a record.
    parts.pop();
  }
  const records = [];
  let prevDigest = GENESIS_DIGEST;
  for (let index = 0; index < parts.length; index += 1) {
    const record = parseChainLine(parts[index], index, prevDigest);
    if (record === null) {
      tornFrom = index;
      tornText = parts.slice(index).join('\n');
      break;
    }
    records.push(record);
    prevDigest = record.digest;
  }
  return { records, tornFrom, tornText, present: true };
}

function serializeChain(records) {
  return records.length === 0 ? '' : `${records.map((record) => canonicalize(record)).join('\n')}\n`;
}

function genesisHead() {
  return {
    version: REGISTRY_VERSION,
    revision: 0,
    fence: 0,
    head_digest: GENESIS_DIGEST,
    record_count: 0,
    marker_digest: GENESIS_DIGEST,
    marker_count: 0,
    at: null,
  };
}

function readHead(ledger) {
  const value = readJsonStrict(ledger.headPath, 'the ledger head');
  if (value === null) return genesisHead();
  if (!isPlainObject(value)) throw new MalformedResult('REGISTRY_HEAD_MALFORMED', 'head.json is not an object');
  for (const field of ['revision', 'fence', 'record_count', 'marker_count']) {
    if (!Number.isInteger(value[field]) || value[field] < 0) {
      throw new MalformedResult('REGISTRY_HEAD_MALFORMED', `head.json ${field} must be an integer >= 0`);
    }
  }
  for (const field of ['head_digest', 'marker_digest']) {
    if (typeof value[field] !== 'string' || !HEX64.test(value[field])) {
      throw new MalformedResult('REGISTRY_HEAD_MALFORMED', `head.json ${field} must be 64 lowercase hex characters`);
    }
  }
  return value;
}

function headFileText(head) {
  return `${canonicalize(head)}\n`;
}

// ---------------------------------------------------------------------------
// Identifiers. Minted through the reused S2-007 rule, never by a second one.
// ---------------------------------------------------------------------------

/**
 * The research prefix table is looked up under a small ordered alias list, so
 * a record is prefixed whether W1 names its `rec-` entry `record` or
 * `reconciliation` (the S2-007 local table spells it the second way). This is a
 * lookup order, NOT a second vocabulary: nothing is added to the frozen
 * `ID_PREFIXES`, and a kind that is in neither table simply keeps whatever the
 * reused base class produced.
 */
const RESEARCH_PREFIX_ALIASES = Object.freeze({
  record: Object.freeze(['record', 'reconciliation']),
  reconciliation: Object.freeze(['reconciliation', 'record']),
});

function researchPrefixFor(kind) {
  const table = RESEARCH_ID_PREFIXES;
  if (table === null || typeof table !== 'object') return null;
  for (const candidate of RESEARCH_PREFIX_ALIASES[kind] ?? [kind]) {
    if (typeof table[candidate] === 'string' && table[candidate] !== '') return table[candidate];
  }
  return null;
}

function newLedgerId(ledger, kind) {
  // REUSED: AgentBoardStoreBase.newId applies the frozen ID_PREFIXES table plus
  // the S2-007 local extension and refuses an unusable factory value. A ledger
  // record borrows the S2-007 `reconciliation` kind, whose local prefix is the
  // same `rec-` the research table documents.
  const id = ledger.engine.newId(kind === 'record' ? 'reconciliation' : kind);
  const research = researchPrefixFor(kind);
  if (research === null || id.startsWith(research)) return id;
  const dash = id.indexOf('-');
  return dash === -1 ? `${research}${id}` : `${research}${id.slice(dash + 1)}`;
}

// ---------------------------------------------------------------------------
// The state a `mutate` sees. A pure projection of the COMMITTED journal: no
// clock, no lock, no process state, so the same base produces the same state.
// ---------------------------------------------------------------------------

function committedJournal(ledger, head) {
  const journal = loadChain(ledger.journalPath);
  const committed = Math.min(head.record_count, journal.records.length);
  return { journal, committed, records: journal.records.slice(0, committed) };
}

function projectState(head, records) {
  const byKind = {};
  for (const record of records) {
    if (!Array.isArray(byKind[record.kind])) byKind[record.kind] = [];
    byKind[record.kind].push(record);
  }
  return {
    version: REGISTRY_VERSION,
    revision: head.revision,
    fence: head.fence,
    head_digest: head.head_digest,
    record_count: head.record_count,
    records,
    by_kind: byKind,
  };
}

function recordsOfKind(state, kind) {
  return Array.isArray(state.by_kind[kind]) ? state.by_kind[kind] : [];
}

// ---------------------------------------------------------------------------
// The contract gate. A record that carries a Campaign/Hypothesis/Experiment
// document must NAME one of the three frozen research contracts and must
// satisfy it, on the way in and on the way out.
// ---------------------------------------------------------------------------

function assertDocumentGate(document, contractName) {
  if (document === null && contractName === null) return null;
  if (document === null || contractName === null) {
    throw new NeedsInput(
      'REGISTRY_DOCUMENT_CONTRACT_MISSING',
      'a journalled document must name the frozen contract it is validated against, and a contract name without a document is a bug, not a lenient default',
    );
  }
  // While constants.mjs is still a skeleton RESEARCH_CONTRACTS is null; that is
  // a typed refusal, never a TypeError and never a document accepted unchecked.
  const known = Array.isArray(RESEARCH_CONTRACTS) ? RESEARCH_CONTRACTS : [];
  if (!known.includes(contractName)) {
    throw new NeedsInput(
      'UNKNOWN_RESEARCH_CONTRACT',
      `${String(contractName)} is not one of the three frozen research contracts`,
    );
  }
  return assertResearchContract(contractName, document, MalformedResult);
}

function recordFromPayload(ledger, payload, { key, operation, index, at, prevDigest, campaignId }) {
  const kind = payload.kind === undefined ? DEFAULT_RECORD_KIND : payload.kind;
  if (typeof kind !== 'string' || !RECORD_KIND.test(kind)) {
    throw new MalformedResult('REGISTRY_RECORD_KIND_MALFORMED', `record kind ${JSON.stringify(kind)} is not UPPER_SNAKE`);
  }
  const document = payload.document === undefined ? null : payload.document;
  const documentContract = payload.document_contract === undefined ? null : payload.document_contract;
  assertDocumentGate(document, documentContract);
  const record = {
    index,
    record_id: newLedgerId(ledger, 'record'),
    kind,
    campaign_id: typeof payload.campaign_id === 'string' ? payload.campaign_id : (campaignId ?? null),
    key: key ?? null,
    operation: operation ?? null,
    at,
    payload,
    document,
    document_contract: documentContract,
    prev_digest: prevDigest,
  };
  return record;
}

// ---------------------------------------------------------------------------
// The single write path. Everything above is ordering; this is the ordering.
// ---------------------------------------------------------------------------

function checkIdempotency(ledger, key, argsDigest, operation) {
  const markers = loadChain(ledger.operationsPath).records;
  const prior = markers.find((marker) => marker.key === key);
  if (prior === undefined) return null;
  if (prior.args_digest !== argsDigest) {
    throw new IdempotencyConflict(
      'IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_ARGUMENTS',
      `key ${key} is already committed for ${String(prior.operation)} with a different canonical argument digest`,
    );
  }
  if (prior.operation !== operation) {
    throw new IdempotencyConflict(
      'IDEMPOTENCY_KEY_REUSED_FOR_OTHER_OPERATION',
      `key ${key} is bound to operation ${String(prior.operation)}, not ${String(operation)}`,
    );
  }
  const head = readHead(ledger);
  const written = committedJournal(ledger, head).records
    .filter((record) => record.key === key && record.operation === operation);
  if (written.length === 0) {
    // The marker exists and records no result. The prior outcome is UNKNOWN and
    // must never be reported as a success or as a clean failure — the exact
    // refusal _replay makes in src/lib/agentboard/store.mjs:811-816.
    throw new ReconciliationRequired(
      'IDEMPOTENCY_LEDGER_WITHOUT_RESULT',
      `key ${key} has a committed marker and no journalled result; the outcome is undetermined and is not retried`,
    );
  }
  const last = written[written.length - 1];
  return { result: last.payload, record: last, revision: Number(prior.revision), head };
}

function resolveFence(head, presented) {
  if (presented === undefined || presented === null) return head.fence + 1; // no fence presented: the CAS is the gate
  const token = Number(presented);
  if (!Number.isInteger(token) || token <= 0) {
    throw new StaleFence('FENCE_MALFORMED', `a presented fence must be a positive integer, got ${String(presented)}`);
  }
  if (token <= head.fence) {
    throw new StaleFence('FENCE_NOT_CURRENT', `presented fence ${token} is not ahead of the committed fence ${head.fence}`);
  }
  if (token !== head.fence + 1) {
    throw new StaleFence('FENCE_NOT_NEXT', `presented fence ${token} is not the next fence ${head.fence + 1}`);
  }
  return token;
}

/**
 * idempotency -> read -> CAS (+ fence) -> plan -> journal -> marker -> head.
 *
 * `expectedRevision: null` is the WEAKER mode reserved for the two narrow
 * ledger paths whose frozen signatures carry no revision: the CAS then runs
 * against the head read in this same transaction. `putExperiment` always
 * carries the caller's expectation.
 */
function writeOperation(ledger, { operation, key, argsDigest, expectedRevision, fencePresented, plan, guard = null, campaignId = null }) {
  // 1. IDEMPOTENCY FIRST, before any read of the head or the journal.
  const replay = checkIdempotency(ledger, key, argsDigest, operation);
  if (replay !== null) return { ...replay, replayed: true, wrote: null };

  // 2. READ state.
  const head = readHead(ledger);
  const { journal, committed } = committedJournal(ledger, head);
  if (journal.tornFrom !== null || journal.records.length > head.record_count) {
    throw new ReconciliationRequired(
      'JOURNAL_NOT_COMMITTED',
      `the journal holds ${journal.records.length} readable record(s) against a committed count of ${head.record_count}; run recoverTornTail before writing`,
    );
  }

  // 3. GUARD (budget rules), then the revision CAS and the fence.
  if (guard !== null) guard({ head, records: journal.records.slice(0, committed) });
  if (expectedRevision !== null && head.revision !== requireRevision(expectedRevision)) {
    throw new RevisionConflict(
      'REVISION_CONFLICT',
      `expected revision ${expectedRevision}, the ledger is at ${head.revision}; nothing was written`,
    );
  }
  const fence = resolveFence(head, fencePresented);

  // 4. PLAN the record. The payload is the caller's return value, verbatim.
  const payload = plan(projectState(head, journal.records.slice(0, committed)));
  if (!isPlainObject(payload)) {
    throw new MalformedResult('REGISTRY_PAYLOAD_NOT_AN_OBJECT', 'a ledger record payload must be a plain object');
  }
  try {
    assertCanonicalSafety(payload, 'payload');
  } catch (error) {
    throw new MalformedResult('REGISTRY_VALUE_NOT_CANONICAL', `payload: ${String(error?.message ?? error).slice(0, 300)}`);
  }

  // 5. SNAPSHOT the bytes this transaction may touch, so a refusal below leaves
  //    the ledger byte-identical rather than half-written.
  const before = {
    [ledger.journalPath]: readTextOrNull(ledger.journalPath),
    [ledger.operationsPath]: readTextOrNull(ledger.operationsPath),
    [ledger.headPath]: readTextOrNull(ledger.headPath),
  };
  const restore = () => {
    for (const [file, text] of Object.entries(before)) {
      if (text === null) {
        try {
          unlinkSync(file);
        } catch {
          // Already absent: the restore is done.
        }
      } else {
        writeAtomic(file, text);
      }
    }
  };

  try {
    // 6. JOURNAL record(s). The chain link is the committed head digest, so a
    //    record that no head covers is an uncommitted tail by construction.
    const at = requireInjectedClock(ledger).iso;
    const record = recordFromPayload(ledger, payload, {
      key,
      operation,
      index: head.record_count,
      at,
      prevDigest: head.head_digest,
      campaignId,
    });
    record.digest = recordDigest(record);

    // 7. OPERATION MARKER: the idempotency ledger row AND the proof that the
    //    journal append committed with it.
    const markers = loadChain(ledger.operationsPath).records;
    const marker = {
      index: head.marker_count,
      marker_id: newLedgerId(ledger, 'operation'),
      key,
      operation,
      args_digest: argsDigest,
      result_digest: record.digest,
      revision: head.revision + 1,
      journal_count: head.record_count + 1,
      at,
      prev_digest: head.marker_digest,
    };
    marker.digest = recordDigest(marker);

    // 8. head.json LAST. Until it lands, nothing is committed.
    const next = {
      version: REGISTRY_VERSION,
      revision: head.revision + 1,
      fence,
      head_digest: record.digest,
      record_count: head.record_count + 1,
      marker_digest: marker.digest,
      marker_count: head.marker_count + 1,
      at,
    };
    writeAtomic(ledger.journalPath, serializeChain([...journal.records, record]));
    writeAtomic(ledger.operationsPath, serializeChain([...markers, marker]));
    writeAtomic(ledger.headPath, headFileText(next));
    return { result: payload, record, marker, head: next, headDigest: next.head_digest, revision: next.revision, fence, replayed: false, wrote: record };
  } catch (error) {
    restore();
    throw error;
  }
}

function commitReconciliation(ledger, { campaignId, reason, detail, kind = 'RECONCILIATION' }) {
  const payload = {
    kind,
    campaign_id: campaignId,
    reason,
    resolution: 'EFFECT_UNDETERMINED',
    detail,
    at: requireInjectedClock(ledger).iso,
  };
  // Reused closed set: a resolution outside the four the board already froze is
  // a bug, and this file never invents a fifth.
  if (!RECONCILIATION_RESOLUTIONS.includes(payload.resolution)) {
    throw new MalformedResult('REGISTRY_RESOLUTION_UNKNOWN', payload.resolution);
  }
  const key = digestOf({ operation: 'reconciliation', reason, campaign_id: campaignId, detail }, 'reconciliation key');
  const out = writeOperation(ledger, {
    operation: 'reconciliation',
    key,
    argsDigest: key,
    expectedRevision: null,
    fencePresented: null,
    plan: () => payload,
    campaignId,
  });
  return out.record;
}

// ---------------------------------------------------------------------------
// Public surface.
// ---------------------------------------------------------------------------

/**
 * Open a registry root.
 *
 * `root` is created if absent. `clock` is the INJECTED fixed clock — the
 * ledger never reads the process clock. `ids` is a deterministic id factory
 * scoped by the run's label + step, so two runs never collide on one root and
 * a repeat run still fails on the property rather than on its own leftovers.
 *
 * `openRegistry` is not a business write: it creates the directory, the
 * ownership marker and the two empty chain files, and it never creates
 * `head.json` — an absent head IS revision 0, and creating it would make
 * `open` a commit.
 *
 * The returned HANDLE additionally carries four read helpers the frozen
 * signature list has no name for, because the track requires a MISSING outcome
 * to be DETECTABLE and there is no exported reader for it:
 * `registry.campaignOutcome(id)`, `registry.revision()`, `registry.head()` and
 * `registry.recordsOfKind(kind)`. They are members of the handle, not new
 * module exports, and `openRegistry`'s own contract ("carrying at least root,
 * journalPath, headPath, clock and ids") allows them.
 *
 * @param {{root: string, clock: object, ids: object}} args
 * @param {string} args.root Absolute path of the registry root.
 * @param {{nowNs: () => number, iso: () => string}} args.clock Injected fixed
 *   clock. `Date.now()` is never called by this module.
 * @param {{next: (kind: string) => string}} args.ids Deterministic id
 *   factory, scoped by run label + step.
 * @returns {object} An open registry handle carrying at least `root`,
 *   `journalPath`, `headPath`, `clock` and `ids`.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when `clock`
 *   or `ids` is missing — a registry without an injected clock is refused
 *   rather than defaulted to the process clock.
 */
export function openRegistry({ root, clock, ids } = {}) {
  if (typeof root !== 'string' || root === '') {
    throw new NeedsInput('REGISTRY_ROOT_REQUIRED: root must be a non-empty ABSOLUTE path');
  }
  if (!path.isAbsolute(root)) {
    throw new NeedsInput('REGISTRY_ROOT_NOT_ABSOLUTE', `${root} is relative; a relative root would make the same ledger reachable from two directories`);
  }
  const injectedClock = requireClock(clock);
  const injectedIds = requireIds(ids);
  const resolved = path.resolve(root);
  for (const segment of resolved.split(path.sep)) {
    if (PROTECTED_SEGMENTS.has(segment)) {
      throw new BlockedPolicy('REGISTRY_ROOT_PROTECTED', `${resolved} is inside a frozen target or a delivery path (${segment})`);
    }
  }
  mkdirSync(resolved, { recursive: true });

  const markerPath = path.join(resolved, MARKER_FILE);
  const existingMarker = readJsonStrict(markerPath, 'the registry marker');
  if (existingMarker !== null && existingMarker.kind !== REGISTRY_MARKER_KIND) {
    throw new BlockedPolicy('REGISTRY_ROOT_MARKER_MISMATCH', `${resolved} holds a ${MARKER_FILE} that is not ${REGISTRY_MARKER_KIND}`);
  }

  const journalPath = path.join(resolved, JOURNAL_FILE);
  const operationsPath = path.join(resolved, OPERATIONS_FILE);
  const headPath = path.join(resolved, HEAD_FILE);
  const lockDir = path.join(resolved, LOCK_DIR);
  const lockPath = path.join(lockDir, LOCK_FILE);

  // REUSED: the S2-007 base class is the injected-clock and identifier
  // authority. It is constructed once and never used as a state container.
  const engine = new AgentBoardStoreBase({
    clock: () => new Date(Number(injectedClock.nowNs())),
    ids: injectedIds,
  });

  const ledger = {
    root: resolved,
    journalPath,
    operationsPath,
    headPath,
    lockDir,
    lockPath,
    clock: injectedClock,
    ids: injectedIds,
    engine,
    options: { strictRecovery: false },
    holdsLock: null,
  };

  const created = existingMarker === null;
  if (created) {
    writeAtomic(markerPath, `${canonicalize({
      kind: REGISTRY_MARKER_KIND,
      version: REGISTRY_VERSION,
      root_name: path.basename(resolved),
      created_at: String(injectedClock.iso()),
    })}\n`);
  }
  for (const file of [journalPath, operationsPath]) {
    if (!existsSync(file)) writeAtomic(file, '');
  }

  const handle = {
    version: REGISTRY_VERSION,
    root: resolved,
    journalPath,
    headPath,
    operationsPath,
    lockPath,
    clock: injectedClock,
    ids: injectedIds,
    engine,
    options: ledger.options,
    created,

    revision() {
      return readHead(assertRegistry(handle)).revision;
    },

    head() {
      return { ...readHead(assertRegistry(handle)) };
    },

    recordsOfKind(kind) {
      const head = readHead(assertRegistry(handle));
      const { records } = committedJournal(assertRegistry(handle), head);
      return projectState(head, records).by_kind[kind] ?? [];
    },

    /**
     * A MISSING outcome is DETECTABLE, never an implicit zero.
     *
     * A completed campaign with no result record answers
     * `NO_OUTCOME_RECORDED` with `outcome: null` and `implicit_zero: false`.
     * It never answers `0`, never answers `[]`, and never answers a shape a
     * caller can read as "no effect was found" — which is a claim, and a
     * campaign that produced no record has made no claim at all.
     */
    campaignOutcome(campaignId) {
      const self = assertRegistry(handle);
      const head = readHead(self);
      const { records } = committedJournal(self, head);
      const state = projectState(head, records);
      const mine = records.filter((record) => record.campaign_id === campaignId
        || (isPlainObject(record.payload) && record.payload.campaign_id === campaignId));
      const of = (kind) => mine.filter((record) => record.kind === kind);
      const results = of('RESULT');
      const completed = of('CAMPAIGN_COMPLETE');
      const reconciliations = of('RECONCILIATION');
      const status = results.length > 0
        ? 'OUTCOME_RECORDED'
        : (reconciliations.length > 0
          ? 'RECONCILIATION_REQUIRED'
          : (completed.length > 0 ? 'NO_OUTCOME_RECORDED' : 'NO_CAMPAIGN_RECORDS'));
      return {
        campaign_id: campaignId,
        status,
        outcome: results.length > 0 ? results[results.length - 1].payload.outcome ?? null : null,
        implicit_zero: false,
        record_count: mine.length,
        result_record_ids: results.map((record) => record.record_id),
        completed_record_ids: completed.map((record) => record.record_id),
        reconciliation_record_ids: reconciliations.map((record) => record.record_id),
        kinds: Object.keys(state.by_kind).sort(),
        revision: head.revision,
        head_digest: wireDigestOf(head.head_digest, 'campaignOutcome.head_digest'),
      };
    },
  };
  handle[HANDLE] = ledger;
  return handle;
}

/**
 * The single write path: idempotency ledger, then read, then revision CAS,
 * then the journal record, then the operation marker last.
 * @param {object} registry An open registry handle.
 * @param {{key: string, args: object, expectedRevision: number, mutate: Function}} args
 * @param {string} args.key The idempotency key. Consulted BEFORE any read of
 *   state.
 * @param {object} args.args The write arguments; `canonicalDigest(args)` is
 *   the args digest. An `args.fence` (or `args.fencing_token`) is the OPTIONAL
 *   monotone fencing token of E1 and must be `head.fence + 1`.
 * @param {number} args.expectedRevision The revision the caller believes
 *   `head.json` holds.
 * @param {(state: object) => object} args.mutate The pure state transition.
 *   It receives the COMMITTED projection `{version, revision, fence,
 *   head_digest, record_count, records, by_kind}` and returns the record
 *   payload — which is also the returned `result`, verbatim, so what a caller
 *   sees is exactly what was journalled. A payload may name its own `kind`
 *   (UPPER_SNAKE, default `RECORD`), its `campaign_id`, and a `document` plus
 *   the `document_contract` it is validated against.
 * @returns {{result: object, revision: number, replayed: boolean,
 *   headDigest: string}} The committed result, the new revision, and whether
 *   this was an idempotent replay that wrote nothing. `headDigest` is the
 *   CURRENT head in both branches: a replay writes nothing, so there is no
 *   new head to report.
 * @throws {import('../agentboard/errors.mjs').IdempotencyConflict} same key,
 *   different args digest; nothing written.
 * @throws {import('../agentboard/errors.mjs').RevisionConflict} zero updated
 *   rows on the CAS; nothing written.
 * @throws {import('../agentboard/errors.mjs').StaleFence} a presented fence
 *   that is not `head.fence + 1`; nothing written.
 * @throws {import('../agentboard/errors.mjs').ReconciliationRequired} when the
 *   outcome cannot be confirmed, or when the journal holds an uncommitted
 *   tail. Never a silent retry.
 */
export function putExperiment(registry, { key, args, expectedRevision, mutate } = {}) {
  const ledger = assertRegistry(registry);
  if (typeof mutate !== 'function') {
    throw new NeedsInput('putExperiment: mutate must be a function; a command without a state transition is not a command');
  }
  const argsValue = requireArgs(args, 'putExperiment.args');
  const argsDigest = digestOf(argsValue, 'putExperiment.args');
  const fencePresented = isPlainObject(argsValue) ? argsValue.fence ?? argsValue.fencing_token ?? null : null;
  const out = writeOperation(ledger, {
    operation: 'putExperiment',
    key: requireKey(key),
    argsDigest,
    expectedRevision: requireRevision(expectedRevision, 'putExperiment.expectedRevision'),
    fencePresented,
    plan: (state) => mutate(state),
  });
  return {
    result: out.result,
    revision: out.replayed ? out.revision : out.head.revision,
    replayed: out.replayed,
    headDigest: wireDigestOf(out.head.head_digest, 'putExperiment.headDigest'),
  };
}

/**
 * P1: journal an `ACCESS` record for a holdout read. Written BEFORE the case
 * data is returned, so a read cannot be invisible. Idempotency-keyed on
 * `canonicalDigest({trial, unsealDigest})`, so a retried read of the same
 * trial writes nothing.
 *
 * The unseal digest is ONE SHOT: the second presentation of the same digest by
 * a different trial is `HOLDOUT_UNSEAL_DIGEST_REPLAYED` and writes nothing.
 * A retried read by the SAME trial is not a second presentation — it is the
 * same read, and it replays.
 *
 * @param {object} registry An open registry handle.
 * @param {{trial: string, unsealDigest: string, readAt: string, partition?: string, decisionPoint?: string|null, maxOpens?: number, actorKind?: string|null, caseId?: string}} args
 * @param {string} args.trial The trial that read the partition.
 * @param {string} args.unsealDigest The one-shot unseal digest presented.
 * @param {string} args.readAt ISO-8601 instant from the INJECTED clock. When
 *   supplied it MUST equal the injected reading: a caller may not stamp its own
 *   time on an access record, and `Date.now()` is never read.
 * @param {string} [args.partition='HOLDOUT'] OPTIONAL: the partition opened.
 *   Present so the open budget can be counted PER PARTITION rather than per
 *   digest. Counting only by digest let a second, differently-digested read of
 *   the same partition through, which is the same peek with a fresh wrapper.
 * @param {string|null} [args.decisionPoint=null] OPTIONAL: the ISO-8601
 *   instant the preregistration named as the decision point. When supplied, a
 *   read BEFORE it is refused: reading a holdout before the point at which the
 *   decision is due is a peek, and a frozen rule nothing reads is not a rule.
 * @param {number} [args.maxOpens=1] OPTIONAL: the preregistered open budget for
 *   the partition. Anything other than a positive integer is refused, and a
 *   partition already opened `maxOpens` times is refused.
 * @param {string|null} [args.actorKind=null] OPTIONAL: the actor kind that
 *   performed the read, journalled on the ACCESS record.
 * @param {string} [args.caseId] OPTIONAL: the case read, journalled so the
 *   record names WHAT was opened and not only that something was.
 * @param {object} [args] ...
 *   `maxOpens` ...
 * @param {ReadonlyArray<string>} [args.releasedActorKinds] The actor kinds the
 *   PREREGISTRATION released for this partition, recorded on the ACCESS row so
 *   `assertPartitionAccess` decides against the row the ledger actually
 *   committed. Omitting it leaves the list absent, which still fails closed.
 * @returns {{accessRecordId: string, revision: number, replayed: boolean, opens_after: number}}
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'HOLDOUT_UNSEAL_DIGEST_REPLAYED' on a second presentation,
 *   'HOLDOUT_OPEN_BUDGET_EXCEEDED' when the partition has been opened
 *   `maxOpens` times already, 'HOLDOUT_READ_BEFORE_DECISION_POINT' when the
 *   read precedes the declared decision point, and
 *   'HOLDOUT_READ_AT_NOT_INJECTED_CLOCK' on a caller-stamped instant.
 */
export function recordHoldoutRead(registry, { trial, unsealDigest, readAt, partition = 'HOLDOUT', decisionPoint = null, maxOpens = 1, actorKind = null, caseId, releasedActorKinds = null } = {}) {
  const ledger = assertRegistry(registry);
  const trialId = requireText(trial, 'recordHoldoutRead.trial', 64);
  const unseal = requireText(unsealDigest, 'recordHoldoutRead.unsealDigest', 128);
  if (!HEX64.test(unseal)) {
    throw new BlockedPolicy('HOLDOUT_UNSEAL_DIGEST_MALFORMED', 'the one-shot unseal digest must be 64 lowercase hex characters');
  }
  if (!Number.isInteger(maxOpens) || maxOpens < 1) {
    throw new BlockedPolicy('HOLDOUT_MAX_OPENS_INVALID', `max_opens must be a positive integer, got ${String(maxOpens)}; an unreadable open budget is not an open budget`);
  }
  const partitionName = requireText(partition, 'recordHoldoutRead.partition', 16);
  const clock = requireInjectedClock(ledger);
  if (readAt !== undefined && readAt !== null && readAt !== clock.iso) {
    throw new BlockedPolicy(
      'HOLDOUT_READ_AT_NOT_INJECTED_CLOCK',
      `readAt ${String(readAt)} is not the injected reading ${clock.iso}; an access record may not be stamped by the caller`,
    );
  }

  // The one-shot rules, enforced THROUGH THE GUARD and not before the write.
  // That placement is load-bearing, and it is the same reason `recordSpend`
  // puts its budget rule in the guard: the guard runs AFTER the idempotency
  // check, so a RETRIED read by the SAME trial replays its own committed
  // result instead of being counted as a second open of the partition. Counting
  // before the ledger is consulted made a crash-and-restart retry of the very
  // read a peek rule exists to catch — a retry must not be a violation, and an
  // honest holdout protocol is retry-safe.
  //
  // TWO independent, decidable rules, both over COMMITTED records:
  //   1. the presented DIGEST may be spent only once, by one trial;
  //   2. the PARTITION may be opened only `maxOpens` times, whatever digests
  //      are presented.
  const accessRecords = (records) => records.filter((record) => record.kind === 'ACCESS');
  const key = digestOf({ trial: trialId, unsealDigest: unseal, partition: partitionName }, 'recordHoldoutRead key');
  const argsValue = {
    trial: trialId,
    unsealDigest: unseal,
    partition: partitionName,
    readAt: clock.iso,
    decisionPoint,
    maxOpens,
    actorKind,
    caseId,
  };
  const out = writeOperation(ledger, {
    operation: 'recordHoldoutRead',
    key,
    argsDigest: digestOf(argsValue, 'recordHoldoutRead args'),
    expectedRevision: null,
    fencePresented: null,
    guard: ({ records }) => {
      const accesses = accessRecords(records);
      const spentBy = accesses.filter((record) => isPlainObject(record.payload) && record.payload.unseal_digest === unseal);
      if (spentBy.some((record) => record.payload.trial !== trialId)) {
        throw new BlockedPolicy(
          'HOLDOUT_UNSEAL_DIGEST_REPLAYED',
          `the one-shot unseal digest was already spent by trial ${String(spentBy[0].payload.trial)}; a second presentation is a peek, not a retry`,
        );
      }
      const openedPartition = accesses.filter((record) => isPlainObject(record.payload) && record.payload.partition === partitionName);
      if (openedPartition.length >= maxOpens) {
        throw new BlockedPolicy(
          'HOLDOUT_OPEN_BUDGET_EXCEEDED',
          `${partitionName} has been opened ${openedPartition.length} time(s) against a preregistered budget of ${maxOpens}; a partition opened past its budget is a peek`,
        );
      }
      // The decision point. `Date.parse` READS an ISO instant; it never samples
      // one, and the reading compared against it is the injected clock above.
      if (decisionPoint !== undefined && decisionPoint !== null) {
        const decisionAtMs = Date.parse(String(decisionPoint));
        if (!Number.isFinite(decisionAtMs)) {
          throw new BlockedPolicy('HOLDOUT_DECISION_POINT_MALFORMED', `the preregistered decision point ${String(decisionPoint)} is not a parseable instant`);
        }
        if (Date.parse(clock.iso) < decisionAtMs) {
          throw new BlockedPolicy(
            'HOLDOUT_READ_BEFORE_DECISION_POINT',
            `${partitionName} was read at ${clock.iso}, before the preregistered decision point ${String(decisionPoint)}; a holdout read before the decision is the definition of a peek`,
          );
        }
      }
    },
    plan: () => ({
      kind: 'ACCESS',
      trial: trialId,
      partition: partitionName,
      case_id: caseId ?? null,
      actor_kind: actorKind ?? null,
      // The RELEASE LIST travels WITH the access row. `assertPartitionAccess`
      // (dataset.mjs) reads `released_actor_kinds` off the ACCESS record to
      // decide whether the preregistration released this actor for this
      // partition, and the row the ledger commits did not carry it — so the
      // guard always fell through to "released nobody" and could not tell an
      // authorised read from an unauthorised one. A release list that is absent
      // is still absent (and still fails closed); what changed is that an
      // authorising preregistration is now visible in the ledger it authorises
      // through.
      released_actor_kinds: Array.isArray(releasedActorKinds) ? [...releasedActorKinds] : null,
      unseal_digest: unseal,
      decision_point: decisionPoint ?? null,
      max_opens: maxOpens,
      read_at: clock.iso,
      at: clock.iso,
    }),
  });
  return {
    accessRecordId: out.record.record_id,
    revision: out.head.revision,
    replayed: out.replayed,
    // Counted from the ledger AFTER the write, so it is the same number in both
    // branches: a replay does not add an open, and no counter is computed from
    // a pre-write snapshot it could disagree with.
    opens_after: accessRecords(committedJournal(ledger, readHead(ledger)).records)
      .filter((record) => isPlainObject(record.payload) && record.payload.partition === partitionName).length,
  };
}

function findReservation(records, reservationId) {
  const matches = records.filter((record) => record.kind === 'BUDGET_RESERVATION'
    && isPlainObject(record.payload) && record.payload.reservation_id === reservationId);
  if (matches.length === 0) {
    // An unassigned budget is not zero, and a free model is not an
    // authorization — the same sentence src/lib/agentboard/store.mjs uses for
    // the board's own grants.
    throw new BudgetExceeded('BUDGET_RESERVATION_MISSING', `no BUDGET_RESERVATION record for ${reservationId}; an unassigned budget is not a zero`);
  }
  return matches[matches.length - 1];
}

/**
 * P4: journal a budget spend against a reservation. Idempotency-keyed on
 * `canonicalDigest(args)` when no `key` is supplied, so a REPLAYED settle
 * writes nothing and a blind retry is impossible by construction. When a `key`
 * IS supplied it is the ledger key and the args digest covers the whole settle,
 * so the same key with a different reservation or amount is an
 * `IdempotencyConflict` rather than a second settle.
 *
 * The reservation is taken BEFORE the run by journalling a
 * `BUDGET_RESERVATION` record through `putExperiment`; this function enforces
 * it again at the point of spend, because the ledger is the only thing that can
 * make a spend durable. The same rule on the preregistration plane is
 * `assertBudgetReservation` in preregistration.mjs.
 *
 * @param {object} registry An open registry handle.
 * @param {{reservationId: string, key: string, args: object}} args
 * @param {string} args.reservationId The reservation being spent.
 * @param {string} args.key The idempotency key of this settle. Optional: when
 *   absent it is derived from the reservation and the arguments.
 * @param {object} args.args `{units, released?, currency?, fence?}`.
 *   `units` is a finite number >= 0; `released: true` journals a
 *   `BUDGET_RELEASE` instead of a `BUDGET_SPEND`, which is the release of the
 *   remainder after a run.
 * @returns {{spendRecordId: string, revision: number, replayed: boolean,
 *   spent_units: number}} The journalled spend and the CUMULATIVE units spent
 *   against the reservation as of this settle.
 * @throws {import('../agentboard/errors.mjs').BudgetExceeded} when the
 *   reservation is missing or the settle exceeds the remainder; the journal
 *   stays byte-identical.
 * @throws {import('../agentboard/errors.mjs').ReconciliationRequired} when
 *   the reservation expired; a reconciliation row is committed BEFORE the
 *   throw, and there is no retry and no zero.
 */
export function recordSpend(registry, { reservationId, key, args } = {}) {
  const ledger = assertRegistry(registry);
  const reservation = findReservation(committedJournal(ledger, readHead(ledger)).records,
    requireText(reservationId, 'recordSpend.reservationId', 64));
  const clock = requireInjectedClock(ledger);
  const argsValue = isPlainObject(args) ? args : {};
  const units = requireUnits(argsValue.units, 'recordSpend.args.units');
  const released = argsValue.released === true;
  const granted = requireUnits(reservation.payload.granted_units, 'the reservation granted_units');
  // `Date.parse` yields MILLISECONDS and the injected clock yields NANOSECONDS;
  // comparing the two raw numbers would expire every reservation, so the
  // conversion is explicit rather than left to the reader.
  const expiresAtMs = Date.parse(String(reservation.payload.expires_at ?? ''));
  if (!Number.isFinite(expiresAtMs)) {
    throw new MalformedResult(
      'BUDGET_RESERVATION_EXPIRES_AT_MALFORMED',
      `reservation ${String(reservation.payload.reservation_id)} has no parseable expires_at; an unreadable expiry is not "never expires"`,
    );
  }
  const expiresAtNs = expiresAtMs * 1_000_000;
  const spentBefore = committedJournal(ledger, readHead(ledger)).records
    .filter((record) => (record.kind === 'BUDGET_SPEND' || record.kind === 'BUDGET_RELEASE')
      && isPlainObject(record.payload) && record.payload.reservation_id === reservationId)
    .reduce((total, record) => total + Number(record.payload.units ?? 0), 0);
  const settleKey = key === undefined || key === null
    ? digestOf({ reservationId, args: argsValue }, 'recordSpend key')
    : requireKey(key);
  const fencePresented = argsValue.fence ?? argsValue.fencing_token ?? null;

  const out = writeOperation(ledger, {
    operation: 'recordSpend',
    key: settleKey,
    argsDigest: digestOf(argsValue, 'recordSpend.args'),
    expectedRevision: null,
    fencePresented,
    // The guard runs AFTER the idempotency check and BEFORE the journal write,
    // which is why a replay of an expired-then-committed settle can never raise
    // BudgetExceeded against its own earlier spend.
    guard: () => {
      if (clock.ns > expiresAtNs) {
        const row = commitReconciliation(ledger, {
          campaignId: reservation.campaign_id,
          reason: 'BUDGET_RESERVATION_EXPIRED',
          detail: {
            reservation_id: reservationId,
            granted_units: granted,
            spent_units: spentBefore,
            expires_at: String(reservation.payload.expires_at),
            observed_at: clock.iso,
          },
        });
        throw new ReconciliationRequired(
          'BUDGET_RESERVATION_EXPIRED',
          `reservation ${reservationId} expired at ${String(reservation.payload.expires_at)}; reconciliation ${row.record_id} is committed — there is no retry and no zero`,
        );
      }
      if (spentBefore + units > granted) {
        throw new BudgetExceeded(
          'BUDGET_EXCEEDED',
          `settle of ${units} against a remainder of ${granted - spentBefore} on reservation ${reservationId}; the journal is byte-identical`,
        );
      }
    },
    plan: () => ({
      kind: released ? 'BUDGET_RELEASE' : 'BUDGET_SPEND',
      campaign_id: reservation.campaign_id,
      reservation_id: reservationId,
      units,
      granted_units: granted,
      spent_units: spentBefore + units,
      remaining_units: granted - spentBefore - units,
      currency: reservation.payload.currency ?? null,
      expires_at: reservation.payload.expires_at ?? null,
      at: clock.iso,
    }),
  });
  return {
    spendRecordId: out.record.record_id,
    revision: out.head.revision,
    replayed: out.replayed,
    spent_units: Number(out.result.spent_units),
  };
}

/**
 * Append one canonical-JSON record to the journal and chain it. The ONLY
 * primitive that writes a journal line; every other write command goes through
 * `putExperiment` so the ordering rule cannot be bypassed.
 *
 * This primitive does NOT consult the idempotency ledger and does NOT CAS. It
 * exists for two callers: torn-tail recovery, and a record whose shape the
 * narrow writers do not cover — `dataset.mjs`'s `readCorpus` needs an ACCESS
 * record carrying `partition`, `case_id` and `actor_kind`, none of which the
 * frozen `recordHoldoutRead(registry, {trial, unsealDigest, readAt})`
 * signature can carry. A caller that reaches for it instead of `putExperiment`
 * for an ordinary command has opted out of idempotency, and the journal will
 * not tell it apart from a legitimate append.
 *
 * @param {object} registry An open registry handle.
 * @param {object} record The record. `prev_digest` is set by this function,
 *   never by the caller; `kind`, `campaign_id`, `document` and
 *   `document_contract` are lifted from it into the envelope.
 * @returns {{recordId: string, index: number, digest: string,
 *   prev_digest: string}} The chained record; both digests are the STORED
 *   bare 64-hex form (E2), and `sha256:`-prefixed on request via
 *   `wireDigestOf`.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when the record
 *   is not canonically serialisable — `assertCanonicalSafety` from
 *   src/lib/verifier/canonical-json.mjs is the gate.
 */
export function appendRecord(registry, record) {
  const ledger = assertRegistry(registry);
  const payload = isPlainObject(record) ? record : null;
  if (payload === null) {
    throw new MalformedResult('REGISTRY_RECORD_NOT_AN_OBJECT', 'appendRecord takes a plain object record');
  }
  // An IDENTICAL record is a replay, not a second fact: this is a journal of
  // facts and a duplicate fact is not a new fact. A caller that genuinely means
  // to record the same shape twice gives it a distinguishing member.
  const out = writeOperation(ledger, {
    operation: 'appendRecord',
    key: digestOf({ operation: 'appendRecord', payload }, 'appendRecord key'),
    argsDigest: digestOf(payload, 'appendRecord args'),
    expectedRevision: null,
    fencePresented: payload.fence ?? payload.fencing_token ?? null,
    plan: () => payload,
  });
  return {
    recordId: out.record.record_id,
    index: out.record.index,
    digest: out.record.digest,
    prev_digest: out.record.prev_digest,
  };
}

/**
 * Read the journal back. Pure read: no lock, no clock, no write.
 *
 * Only COMMITTED records are returned: the prefix the valid chain covers AND
 * the count `head.json` committed. A torn tail is NOT returned as a record, and
 * neither is a complete line that no head covers — an uncommitted tail is not
 * history.
 *
 * @param {object} registry An open registry handle.
 * @returns {ReadonlyArray<object>} Every complete committed record, in order.
 */
export function readJournal(registry) {
  const ledger = assertRegistry(registry);
  return Object.freeze(committedJournal(ledger, readHead(ledger)).records.map((record) => Object.freeze({ ...record })));
}

/**
 * Verify the `sha256 prev_digest` chain end to end.
 * @param {object} registry An open registry handle.
 * @returns {{ok: boolean, length: number, headDigest: string,
 *   brokenAt: number|null, uncommittedFrom: number|null, headBound: boolean,
 *   recordCount: number,
 *   markers: {ok: boolean, length: number, brokenAt: number|null,
 *     uncommittedFrom: number|null}}} `brokenAt` is the 0-based index of the
 *   first record whose `prev_digest`, index, self digest or byte form does not
 *   verify, or the first index the committed head claims and the file does not
 *   have; null when the chain is intact.
 *   `uncommittedFrom` is the first index that is chain-VALID but that no head
 *   covers — the crash window between the journal append and `head.json`. It is
 *   not history (`readJournal` never returns it and the write path refuses with
 *   `JOURNAL_NOT_COMMITTED`), so `ok` is false while it is set: a ledger that
 *   still needs `recoverTornTail` must not report itself clean.
 *   `headBound` is false when `head.head_digest` is not the digest of the last
 *   committed record — an interleaved two-writer write, which is DETECTED here
 *   and never accepted.
 */
export function verifyChain(registry) {
  const ledger = assertRegistry(registry);
  const head = readHead(ledger);
  const journal = loadChain(ledger.journalPath);
  const markers = loadChain(ledger.operationsPath);
  const lastCommitted = journal.records[Math.min(head.record_count, journal.records.length) - 1] ?? null;
  const headBound = head.record_count === 0
    ? head.head_digest === GENESIS_DIGEST
    : (lastCommitted !== null && lastCommitted.digest === head.head_digest);
  const brokenAt = journal.tornFrom !== null
    ? journal.tornFrom
    : (journal.records.length < head.record_count ? journal.records.length : null);
  const markerChainOk = markers.tornFrom === null && markers.records.length >= head.marker_count;
  const uncommittedFrom = journal.records.length > head.record_count ? head.record_count : null;
  const markerUncommittedFrom = markers.records.length > head.marker_count ? head.marker_count : null;
  return {
    ok: brokenAt === null && uncommittedFrom === null && markerUncommittedFrom === null
      && headBound && markerChainOk,
    length: Math.min(head.record_count, journal.records.length),
    headDigest: wireDigestOf(head.head_digest, 'verifyChain.headDigest'),
    brokenAt,
    uncommittedFrom,
    headBound,
    recordCount: head.record_count,
    markers: {
      ok: markerChainOk && markerUncommittedFrom === null,
      length: Math.min(head.marker_count, markers.records.length),
      brokenAt: markers.tornFrom,
      uncommittedFrom: markerUncommittedFrom,
    },
  };
}

/**
 * Recover a torn tail: truncate to the last COMPLETE and MARKED record, then
 * emit a reconciliation row. Never a guess, never a zero.
 *
 * A record is committed only when `head.json` says so AND the last operation
 * marker covers it, so an append that died before its marker is rolled back
 * rather than half-accepted. Truncation bumps the revision, so a stale writer
 * holding the old `expectedRevision` fails its CAS instead of writing on top
 * of a recovered ledger.
 *
 * @param {object} registry An open registry handle.
 * @returns {{truncatedFrom: number|null, keptRecords: number,
 *   reconciliationRow: object|null, headDigest: string, droppedRecords: number,
 *   torn: boolean, revision: number}} `truncatedFrom` is the 0-based index the
 *   journal was cut at, and `null` when nothing had to be dropped — mirroring
 *   `brokenAt: number|null` above. `reconciliationRow` is non-null exactly when
 *   something was dropped.
 * @throws {import('../agentboard/errors.mjs').ReconciliationRequired} when
 *   `registry.options.strictRecovery` is true and something was dropped: the
 *   reconciliation row is committed FIRST, and then the outcome is escalated
 *   rather than returned.
 */
export function recoverTornTail(registry) {
  const ledger = assertRegistry(registry);
  const head = readHead(ledger);
  const journal = loadChain(ledger.journalPath);
  const markers = loadChain(ledger.operationsPath);
  const lastMarker = markers.records[Math.min(head.marker_count, markers.records.length) - 1] ?? null;
  const markedCount = lastMarker === null ? 0 : Math.min(Number(lastMarker.journal_count), head.record_count);
  const keepJournal = Math.min(head.record_count, markedCount, journal.records.length);
  const keepMarkers = Math.min(head.marker_count, markers.records.length);
  const droppedRecords = journal.records.length - keepJournal;
  const torn = journal.tornFrom !== null || journal.records.length > keepJournal || markers.records.length > keepMarkers;

  if (!torn) {
    return {
      truncatedFrom: null,
      keptRecords: keepJournal,
      reconciliationRow: null,
      headDigest: wireDigestOf(head.head_digest, 'recoverTornTail.headDigest'),
      droppedRecords: 0,
      torn: false,
      revision: head.revision,
    };
  }

  const kept = journal.records.slice(0, keepJournal);
  const headDigestKept = kept.length === 0 ? GENESIS_DIGEST : kept[kept.length - 1].digest;
  const keptMarkers = markers.records.slice(0, keepMarkers);
  const markerDigestKept = keptMarkers.length === 0 ? GENESIS_DIGEST : keptMarkers[keptMarkers.length - 1].digest;
  const at = requireInjectedClock(ledger).iso;
  const truncatedHead = {
    version: REGISTRY_VERSION,
    revision: head.revision + 1,
    fence: head.fence,
    head_digest: headDigestKept,
    record_count: keepJournal,
    marker_digest: markerDigestKept,
    marker_count: keepMarkers,
    at,
  };
  writeAtomic(ledger.journalPath, serializeChain(kept));
  writeAtomic(ledger.operationsPath, serializeChain(keptMarkers));
  writeAtomic(ledger.headPath, headFileText(truncatedHead));

  const row = commitReconciliation(ledger, {
    campaignId: null,
    reason: journal.tornFrom !== null ? 'TORN_TAIL' : 'UNCOMMITTED_TAIL',
    detail: {
      truncated_from: keepJournal,
      dropped_records: droppedRecords,
      dropped_record_ids: journal.records.slice(keepJournal).map((record) => record.record_id),
      torn_bytes: journal.tornFrom !== null ? journal.tornText.length : 0,
      previous_revision: head.revision,
    },
  });
  const after = readHead(ledger);
  if (ledger.options.strictRecovery === true) {
    throw new ReconciliationRequired(
      'STRICT_RECOVERY',
      `dropped ${droppedRecords} uncommitted record(s) at index ${keepJournal}; reconciliation ${row.record_id} is committed and the outcome is escalated`,
    );
  }
  return {
    truncatedFrom: keepJournal,
    keptRecords: keepJournal,
    reconciliationRow: row,
    headDigest: wireDigestOf(after.head_digest, 'recoverTornTail.headDigest'),
    droppedRecords,
    torn: true,
    revision: after.revision,
  };
}

/**
 * The digest of the current journal head.
 * @param {object} registry An open registry handle.
 * @returns {string} `sha256:<64 hex>`, or the genesis digest for an empty
 *   journal.
 */
export function headDigest(registry) {
  const ledger = assertRegistry(registry);
  return wireDigestOf(readHead(ledger).head_digest, 'headDigest');
}

/**
 * The digest of the whole snapshot, used to prove that a refused write left
 * the ledger byte-identical and that a second purge is a no-op.
 *
 * The advisory lock is deliberately EXCLUDED: a lock is an optimisation and
 * must never move a digest.
 *
 * @param {object} registry An open registry handle.
 * @returns {string} `sha256:<64 hex>` over the committed journal chain, the
 *   committed marker chain and the head.
 */
export function snapshotDigest(registry) {
  const ledger = assertRegistry(registry);
  const head = readHead(ledger);
  const journal = committedJournal(ledger, head);
  const markers = loadChain(ledger.operationsPath);
  return wireDigestOf(digestOf({
    version: REGISTRY_VERSION,
    head,
    journal: journal.records.map((record) => record.digest),
    markers: markers.records.slice(0, Math.min(head.marker_count, markers.records.length)).map((marker) => marker.digest),
  }, 'snapshotDigest'), 'snapshotDigest');
}

/**
 * Take the advisory lock. AN OPTIMISATION ONLY: correctness never depends on
 * it, which is why `--no-lock` is a supported mode in the replay harness. The
 * create is `O_EXCL`, so two processes cannot both believe they hold it. A
 * lock whose expiry has passed ON THE INJECTED CLOCK is stale and may be taken
 * once; under a fixed clock it never expires, which is the correct answer for
 * a deterministic run.
 * @param {object} registry An open registry handle.
 * @returns {{held: boolean, lockId: string|null, holder: string}} `held: false`
 *   when the lock is already held; the caller proceeds on the revision CAS.
 */
export function acquireLock(registry) {
  const ledger = assertRegistry(registry);
  mkdirSync(ledger.lockDir, { recursive: true });
  const clock = requireInjectedClock(ledger);
  const lockId = newLedgerId(ledger, 'lock');
  const lock = {
    lock_id: lockId,
    holder: `${lockId}@${clock.iso}`,
    at: clock.iso,
    expires_at_ns: clock.ns + LOCK_TTL_NS,
  };
  const text = `${canonicalize(lock)}\n`;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let fd;
    try {
      fd = openSync(ledger.lockPath, 'wx');
    } catch (error) {
      if (error?.code !== 'EEXIST') {
        throw new ProviderFailure('REGISTRY_LOCK_FAILED', String(error?.message ?? error).slice(0, 200));
      }
      const current = readJsonLenient(ledger.lockPath);
      const stale = isPlainObject(current) && Number(current.expires_at_ns) <= clock.ns;
      if (attempt === 0 && stale) {
        try {
          unlinkSync(ledger.lockPath);
        } catch {
          // A racing stealer wins the next attempt; losing the steal is not an
          // error, it is a lock someone else now holds.
        }
        continue;
      }
      return { held: false, lockId: null, holder: isPlainObject(current) ? String(current.holder ?? '') : '' };
    }
    try {
      writeFileSync(fd, text, 'utf8');
    } finally {
      closeSync(fd);
    }
    ledger.holdsLock = lockId;
    return { held: true, lockId, holder: lock.holder };
  }
  return { held: false, lockId: null, holder: '' };
}

/**
 * Release the advisory lock. Idempotent.
 * @param {object} registry An open registry handle.
 * @returns {{released: boolean, lockId: string|null}} `released: false` when
 *   this caller did not hold the lock.
 */
export function releaseLock(registry) {
  const ledger = assertRegistry(registry);
  const current = readJsonLenient(ledger.lockPath);
  if (current === null) {
    ledger.holdsLock = null;
    return { released: false, lockId: null };
  }
  const lockId = isPlainObject(current) ? current.lock_id ?? null : null;
  if (ledger.holdsLock === null || lockId !== ledger.holdsLock) {
    return { released: false, lockId };
  }
  try {
    unlinkSync(ledger.lockPath);
  } catch {
    // Already gone: releasing twice is a no-op, not a failure.
  }
  ledger.holdsLock = null;
  return { released: true, lockId };
}

function assertOwnRoot(ledger) {
  const marker = readJsonStrict(path.join(ledger.root, MARKER_FILE), 'the registry marker');
  if (marker === null) {
    throw new BlockedPolicy(
      'REGISTRY_ROOT_NOT_OWNED',
      `${ledger.root} carries no ${MARKER_FILE} naming ${REGISTRY_MARKER_KIND}; purge refuses a directory it did not create`,
    );
  }
  if (marker.kind !== REGISTRY_MARKER_KIND) {
    throw new BlockedPolicy('REGISTRY_ROOT_MARKER_MISMATCH', `${ledger.root} holds a ${MARKER_FILE} of kind ${String(marker.kind)}`);
  }
  return marker;
}

/**
 * A5: purge this module's OWN registry root before every run, so a repeat run
 * fails on the property and not on its own leftovers. IDEMPOTENT: a second
 * purge is a no-op and leaves `snapshotDigest` unchanged. It never touches
 * anything outside the four owned files, and the ownership marker is never
 * purged precisely so that the second purge is a no-op instead of a refusal.
 *
 * @param {object} registry An open registry handle.
 * @returns {{purged: boolean, removedFiles: number, snapshotDigest: string}}
 *   `purged: false` and `removedFiles: 0` on the second call.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy} when the root
 *   resolves outside the allowed results/ workspace — no marker, a foreign
 *   marker, or a protected segment such as `.git`, `node_modules`, `contracts`
 *   or `evidence` on the path.
 */
export function purgeRegistry(registry) {
  const ledger = assertRegistry(registry);
  assertOwnRoot(ledger);
  let removedFiles = 0;
  for (const name of OWNED_FILES) {
    const file = path.join(ledger.root, name);
    if (existsSync(file)) {
      unlinkSync(file);
      removedFiles += 1;
    }
  }
  if (existsSync(ledger.lockDir)) {
    rmSync(ledger.lockDir, { recursive: true });
    removedFiles += 1;
  }
  ledger.holdsLock = null;
  return { purged: removedFiles > 0, removedFiles, snapshotDigest: snapshotDigest(registry) };
}
