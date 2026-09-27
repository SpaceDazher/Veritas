// S2-008 research track — the PARTITION READER with an access log
// (issue SpaceDazher/Veritas#8).
//
// Serves acceptance item A1, negative probe P1 (peeking a holdout) and its
// negative control id `holdout_peek`.
//
// WHY THIS MODULE IS THE ONLY PATH TO THE HOLDOUT
// A holdout that can be read without leaving a record is not a holdout, it is
// a second training set that the author knows the contents of. So EVERY
// holdout read goes through `readCorpus`, which appends an `ACCESS` record to
// the registry journal BEFORE any data is returned, and requires the one-shot
// `unsealDigest` named in the preregistration. A peek is therefore impossible
// to perform invisibly: the record exists before the bytes are handed over, so
// a caller that crashes after the read still leaves the read on record.
//
// A forged or REPLAYED unseal digest is refused AND counted
// (`holdoutPeek`). One-shot means one-shot: the second presentation of the
// same digest is a replay and is refused exactly like a forged one, because
// both mean the partition was opened twice.
//
// PARTITIONS
// PRIMARY is the development partition and is readable freely. HOLDOUT is
// readable only through this module, only with the preregistered one-shot
// unseal digest, and only by an actor kind the preregistration released
// (`assertPartitionAccess`). A PRIMARY read is not a peek and is not logged as
// one; the log records what was actually read.
//
// The label seal
// `assertLabelSeal({declared, actual})` compares the label digest the
// preregistration declared against the digest of the labels actually read. A
// mismatch is a corruption, not a tolerance. `substituteLabelsControl` is the
// negative control of A4's sibling: it rewrites the labels so the ground truth
// is observational while the claim stays causal, and the label-substitution
// control must then FAIL. It is a test/control input builder, not a runtime
// feature, and it is only ever applied to an in-memory copy.
//
// CORPUS
// `corpus/s2-008/{manifest.json,cases/dev.json,cases/holdout.json}` is four
// small hand-authored data files against the existing
// `corpus/s2-006/{manifest.json,cases,labels}` precedent. They are authored
// data, not generated, so the digests are stable and the labels are readable
// by a reviewer.
//
// Owner: W2 (preregistration, data, store). Budget: part of W2's <= 900 lines.
// State: IMPLEMENTED. The exported signatures are the ones plan §1 froze and
// none was renamed; one OPTIONAL argument key was ADDED to `readCorpus` and is
// documented on that function, following the convention preregistration.mjs
// already uses ("an optional key ADDS to the frozen parameter object without
// changing it").
//
// WHERE THE CORPUS COMES FROM
// The committed corpus of this track is `evidence/s2-008/corpus/`, resolved from
// THIS MODULE'S OWN LOCATION — the same convention contracts.mjs uses for its
// schema directory and the same reason: a corpus root that a caller could
// redirect would make "the same base => the same outcome" a property of the
// invocation rather than of the tree. `readCorpus` accepts an explicit
// `corpusDir` ONLY as a test seam, and the resolved directory is reported back on
// every read, so a reader can always see which bytes produced the record.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { BlockedPolicy, MalformedResult, NeedsInput } from '../agentboard/errors.mjs';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import { RESEARCH_PARTITIONS } from './constants.mjs';
import { recordHoldoutRead, readJournal } from './registry.mjs';

const CORPUS_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../evidence/s2-008/corpus',
);
const HOLDOUT = 'HOLDOUT';
const PRIMARY = 'PRIMARY';
const MANIFEST_FILE = 'manifest.json';
const PARTITION_FILES = Object.freeze({ PRIMARY: 'cases/dev.json', HOLDOUT: 'cases/holdout.json' });

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireHex64(value, code, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value) && !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new NeedsInput(`${code}:${label} must be 64 lowercase hex characters (optionally sha256:-prefixed)`);
  }
  return value.startsWith('sha256:') ? value.slice(7) : value;
}

function readJson(file, label) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    throw new NeedsInput(`CORPUS_UNREADABLE:${label}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new MalformedResult('CORPUS_JSON_MALFORMED', `${label} is not valid JSON`);
  }
}

/**
 * Load a committed partition and check it against the manifest. The manifest
 * digest is verified BEFORE the cases are used, so a corpus whose bytes moved
 * is refused rather than measured.
 * @param {string} partition A member of RESEARCH_PARTITIONS.
 * @param {string} corpusDir The corpus root, or the default committed one.
 * @returns {{partition: string, cases: ReadonlyArray<object>, labels: object, digest: string, root: string}}
 */
function loadPartition(partition, corpusDir) {
  if (!RESEARCH_PARTITIONS.includes(partition)) {
    throw new NeedsInput(`UNKNOWN_PARTITION:${String(partition)}; the partitions are ${RESEARCH_PARTITIONS.join(', ')}`);
  }
  const root = path.resolve(corpusDir ?? CORPUS_ROOT);
  const manifest = readJson(path.join(root, MANIFEST_FILE), `${root}/${MANIFEST_FILE}`);
  const declared = isPlainObject(manifest?.partitions) ? manifest.partitions[partition] : null;
  if (!isPlainObject(declared)) {
    throw new MalformedResult('CORPUS_PARTITION_UNDECLARED', `the manifest declares no ${partition} partition`);
  }
  const file = path.join(root, PARTITION_FILES[partition]);
  const raw = readJson(file, `${root}/${PARTITION_FILES[partition]}`);
  const cases = Array.isArray(raw) ? raw : (Array.isArray(raw?.cases) ? raw.cases : null);
  if (cases === null || cases.length === 0) {
    throw new MalformedResult('CORPUS_CASES_ABSENT', `${PARTITION_FILES[partition]} carries no cases`);
  }
  if (declared.case_count !== cases.length) {
    throw new MalformedResult('CORPUS_CASE_COUNT_MISMATCH', `the manifest declares ${String(declared.case_count)} ${partition} cases, the file holds ${cases.length}`);
  }
  const actual = canonicalDigest(cases);
  if (requireHex64(declared.digest, 'CORPUS_DIGEST_MALFORMED', `manifest.partitions.${partition}.digest`) !== actual) {
    throw new MalformedResult('CORPUS_DIGEST_MISMATCH', `the ${partition} cases hash to ${actual}, the manifest says ${String(declared.digest)}`);
  }
  const labels = {};
  for (const [index, entry] of cases.entries()) {
    if (!isPlainObject(entry) || typeof entry.case_id !== 'string' || entry.case_id === '') {
      throw new MalformedResult('CORPUS_CASE_MALFORMED', `${PARTITION_FILES[partition]}[${index}] names no case_id`);
    }
    labels[entry.case_id] = entry.label ?? null;
  }
  return { partition, cases: Object.freeze(cases), labels: Object.freeze(labels), digest: actual, root };
}

/**
 * The only supported path to a dataset partition.
 *
 * @param {object} registry An open registry (see registry.mjs `openRegistry`).
 * @param {{partition: string, caseId: string, unsealDigest: string, corpusDir?: string, decisionPoint?: string, actorKind?: string, maxOpens?: number}} args
 * @param {string} args.partition A member of RESEARCH_PARTITIONS.
 * @param {string} args.caseId The case to read.
 * @param {string} args.unsealDigest The one-shot unseal digest NAMED IN THE
 *   PREREGISTRATION. Required for HOLDOUT; unused for PRIMARY.
 * @param {string} [args.corpusDir] TEST SEAM ONLY: an alternative corpus root.
 *   Omitted in production, where the committed corpus is resolved from this
 *   module's own location.
 * @param {string} [args.decisionPoint] The ISO-8601 instant the preregistration
 *   named as the holdout decision point. When supplied, a read BEFORE it is
 *   refused by `recordHoldoutRead` before any byte is returned.
 * @param {string} [args.actorKind] The actor kind performing the read. When
 *   supplied, `assertPartitionAccess` must admit it.
 * @param {number} [args.maxOpens] The preregistered open budget for the
 *   partition. Defaults to 1: a holdout that may be opened twice is not a
 *   holdout.
 * @param {ReadonlyArray<string>} [args.releasedActorKinds] The actor kinds the
 *   PREREGISTRATION released for this partition. Recorded on the ACCESS row and
 *   read back by `assertPartitionAccess`, so the release decision is made
 *   against the row the ledger committed. Omitting it leaves the list absent,
 *   which still fails closed.
 * @returns {{partition: string, caseId: string, case: object,
 *   accessRecordId: string|null, labels: object, corpusRoot: string,
 *   labelsDigest: string}} The case and its labels. The journal already
 *   contains the `ACCESS` record for this read by the time this returns.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'HOLDOUT_UNSEAL_DIGEST_MISSING' or 'HOLDOUT_UNSEAL_DIGEST_REPLAYED' when
 *   the digest is absent or already spent; 'HOLDOUT_ACCESS_NOT_RELEASED' when
 *   the preregistration did not release this actor kind. In every refusal the
 *   `holdoutPeek` counter moves and NO case data is returned.
 * @throws {import('../agentboard/errors.mjs').NeedsInput} UNKNOWN_PARTITION
 *   or UNKNOWN_CASE.
 */
export function readCorpus(registry, { partition, caseId, unsealDigest, corpusDir, decisionPoint, actorKind, releasedActorKinds, maxOpens = 1 } = {}) {
  if (!isPlainObject(registry)) {
    throw new NeedsInput('REGISTRY_HANDLE_REQUIRED: readCorpus needs an open registry; a dataset read with no ledger is an invisible read');
  }
  if (typeof caseId !== 'string' || caseId === '') {
    throw new NeedsInput(`UNKNOWN_CASE:${String(caseId)}; a read must name the case it reads`);
  }
  const loaded = loadPartition(partition, corpusDir);
  const entry = loaded.cases.find((candidate) => candidate.case_id === caseId);
  if (!isPlainObject(entry)) {
    throw new NeedsInput(`UNKNOWN_CASE:${caseId} is not a ${partition} case of the committed corpus`);
  }

  let accessRecordId = null;
  if (partition === HOLDOUT) {
    // The ACCESS record is journalled BEFORE the case is returned, and the
    // unseal digest it records is checked against the COMMITTED corpus, so a
    // digest that belongs to nothing cannot open anything.
    if (typeof unsealDigest !== 'string' || unsealDigest === '') {
      throw new BlockedPolicy('HOLDOUT_UNSEAL_DIGEST_MISSING', 'a HOLDOUT read must present the one-shot unseal digest named in the preregistration');
    }
    const presented = requireHex64(unsealDigest, 'HOLDOUT_UNSEAL_DIGEST_MALFORMED', 'unsealDigest');
    const expected = requireHex64(canonicalDigest(loaded.labels), 'CORPUS_UNSEAL_ABSENT', 'the committed holdout label digest');
    if (presented !== expected) {
      throw new BlockedPolicy('HOLDOUT_UNSEAL_DIGEST_FORGED', `the presented unseal digest does not open the committed holdout labels; a forged digest is a peek, not a read`);
    }
    const access = recordHoldoutRead(registry, {
      trial: typeof caseId === 'string' && caseId !== '' ? caseId : 'UNNAMED_READ',
      unsealDigest: presented,
      // `readAt` is DELIBERATELY NOT passed. The registry stamps the access
      // record from its own injected clock and refuses a caller-stamped
      // instant, and the clock's `iso` is a FUNCTION on this boundary, so
      // forwarding it would be a refusal on every legitimate read.
      partition: HOLDOUT,
      decisionPoint: decisionPoint ?? null,
      maxOpens,
      actorKind: actorKind ?? null,
      releasedActorKinds: releasedActorKinds ?? null,
      caseId,
    });
    accessRecordId = access.accessRecordId;
    if (actorKind !== undefined && actorKind !== null) {
      // The ACCESS row, found by the record id the write just returned. The
      // lookup used to match `payload.access_record_id`, which no envelope
      // carries — the id lives on the record — so the row was never found and
      // the guard below always scored a synthetic fallback with no release
      // list. It now reads the committed row, which is where the release list
      // `recordHoldoutRead` was told about.
      const record = readJournal(registry).find((row) => row?.record_id === accessRecordId
        || row?.payload?.access_record_id === accessRecordId)
        ?? { kind: 'ACCESS', record_id: accessRecordId, payload: { actor_kind: actorKind, partition: HOLDOUT, released_actor_kinds: null } };
      assertPartitionAccess(record, actorKind);
    }
  }
  return {
    partition,
    caseId,
    case: entry,
    accessRecordId,
    labels: loaded.labels,
    corpusRoot: loaded.root,
    labelsDigest: canonicalDigest(loaded.labels),
    // The partition's per-trial agreement, over every case of THIS partition,
    // computed from the bytes the same single journalled open already read.
    //
    // WHY IT EXISTS: the measurer used to take ONE case's `agreement_by_trial`
    // value as if it were the trial's rate over the whole partition. That was
    // only ever true because an earlier fixture happened to repeat the same
    // trial-level rate in every case; with a case-level record it is off by
    // however many cases disagree, and the run reported 8/8 where the corpus
    // holds 7/8. A metric named `case_agreement_rate` is a rate over CASES, so
    // it is computed over cases.
    //
    // ONE OPEN, NOT N. The rule that makes a peek detectable is `max_opens`
    // against the ACCESS journal, and this returns no byte that the open above
    // did not already read: it is a fold over the same in-memory partition, in
    // the same call, after the ACCESS row is committed. Reading the partition
    // file a second time from the measurer would be exactly the unjournalled
    // second read the rule forbids.
    //
    // A trial id with no agreement anywhere in the partition is reported as
    // `null`, which the measurer turns into an INFRA row — never into a zero
    // and never into a perfect score.
    agreementByTrial: agreementByTrialOf(loaded.cases),
  };
}

/**
 * The per-trial case-agreement rate of a partition, in whole-case counts.
 *
 * A case AGREES on a trial when its `agreement_by_trial` value for that trial
 * is a finite number at or above 0.5 — the case-level reading, where the value
 * says whether the case agreed. The threshold is named rather than folded into
 * the arithmetic, and the counts are returned beside the rate so a reader can
 * re-derive it.
 * @param {ReadonlyArray<object>} cases Every case of one partition.
 * @returns {Readonly<Record<string, {agreeing: number, total: number, rate: number|null}>>}
 *   One entry per trial id seen anywhere in the partition.
 */
export function agreementByTrialOf(cases) {
  const counts = new Map();
  for (const entry of cases) {
    const perTrial = isPlainObject(entry?.agreement_by_trial) ? entry.agreement_by_trial : {};
    for (const [trial, value] of Object.entries(perTrial)) {
      if (typeof value !== 'number' || !Number.isFinite(value)) continue;
      const current = counts.get(trial) ?? { agreeing: 0, total: 0 };
      current.total += 1;
      if (value >= 0.5) current.agreeing += 1;
      counts.set(trial, current);
    }
  }
  return Object.freeze(Object.fromEntries([...counts.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([trial, count]) => [trial, Object.freeze({
    ...count,
    // A trial nobody reported agreement for has no rate. `null` is not `1` and
    // not `0`: both of those are answers the corpus does not contain.
    rate: count.total === 0 ? null : count.agreeing / count.total,
  })])));
}

/**
 * Decide whether an `ACCESS` record was taken by an actor kind the
 * preregistration actually released. Pure and total: it reads the record and
 * the release list, never the process clock and never the journal as a whole.
 * @param {object} record An `ACCESS` record from the registry journal.
 * @param {string} actorKind The actor kind that performed the read
 *   (`ACTOR_KINDS` of the frozen constants).
 * @returns {boolean} true only when the actor kind was released for the
 *   partition named in the record.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'HOLDOUT_ACCESS_NOT_RELEASED' when the actor kind is unnamed, when the
 *   record carries no release list, or when the release list does not include
 *   it. All three fail closed: an authorisation that cannot be read is not an
 *   authorisation.
 */
export function assertPartitionAccess(record, actorKind) {
  const payload = isPlainObject(record) && isPlainObject(record.payload) ? record.payload : record;
  if (!isPlainObject(payload)) {
    throw new MalformedResult('ACCESS_RECORD_MALFORMED', 'an ACCESS record is required to decide partition access');
  }
  if (typeof actorKind !== 'string' || actorKind === '') {
    throw new BlockedPolicy('HOLDOUT_ACCESS_NOT_RELEASED', 'an unnamed actor kind cannot be released for a holdout partition');
  }
  // The release list is read from the record's own members, both spellings,
  // and the PREREGISTRATION's spelling wins when both are present. Before this
  // the only member read was `released_actor_kinds` and the ledger's ACCESS row
  // carried none, so every actor-kind read failed closed for the wrong reason
  // and the rule could not distinguish an authorised read from an
  // unauthorised one.
  const released = payload.released_actor_kinds ?? payload.releasedActorKinds;
  if (!Array.isArray(released) || released.length === 0) {
    // No release list means the preregistration released nobody for this
    // partition. Failing closed here is the whole point: a read that cannot
    // name an authorization is not an authorized read.
    throw new BlockedPolicy('HOLDOUT_ACCESS_NOT_RELEASED', 'the preregistration released no actor kind for this partition');
  }
  if (!released.includes(actorKind)) {
    throw new BlockedPolicy('HOLDOUT_ACCESS_NOT_RELEASED', `actor kind ${actorKind} was not released (released: ${released.join(', ')})`);
  }
  return true;
}

/**
 * The canonical digest of a partition's labels.
 * @param {object} partition A loaded partition (`{labels, cases}` or the
 *   registry's partition object).
 * @returns {string} `sha256:<64 hex>` via `canonicalDigest` from
 *   src/lib/verifier/canonical-json.mjs.
 */
export function labelsDigest(partition) {
  const labels = isPlainObject(partition) ? (partition.labels ?? null) : null;
  if (!isPlainObject(labels)) {
    throw new MalformedResult('LABELS_ABSENT', 'labelsDigest needs a loaded partition carrying its labels');
  }
  return canonicalDigest(labels);
}

/**
 * The label seal: the digest the preregistration declared must equal the
 * digest of the labels actually read. A mismatch is corruption, and it is
 * what the corrupted-data control trips.
 * @param {{declared: string, actual: string}} args
 * @param {string} args.declared The label digest named in the preregistration.
 * @param {string} args.actual The digest of the labels just read.
 * @returns {string} The agreed digest, on success.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'LABEL_SEAL_MISMATCH', naming both digests and the partition.
 */
export function assertLabelSeal({ declared, actual } = {}) {
  const left = requireHex64(declared, 'LABEL_SEAL_DECLARED_MALFORMED', 'declared');
  const right = requireHex64(actual, 'LABEL_SEAL_ACTUAL_MALFORMED', 'actual');
  if (left !== right) {
    throw new BlockedPolicy('LABEL_SEAL_MISMATCH', `the labels read hash to ${right} while the preregistration sealed ${left}; a substituted label set is corruption, not a tolerance`);
  }
  return left;
}

/**
 * Build the label-substitution control dataset: a deep copy whose labels are
 * replaced by a substituted label set, leaving the claims and the card text
 * untouched. Used ONLY to prove that a causal claim on observational ground
 * truth FAILS. It never writes to disk and never touches `corpus/`.
 * @param {object} dataset A loaded `{cases, labels}` dataset.
 * @returns {object} A new dataset object with substituted labels and a
 *   `substituted: true` marker naming the control id `label_substitution`.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when the input
 *   is not a loadable dataset.
 */
export function substituteLabelsControl(dataset) {
  if (!isPlainObject(dataset) || !isPlainObject(dataset.labels) || !Array.isArray(dataset.cases)) {
    throw new MalformedResult('DATASET_NOT_LOADABLE', 'the label-substitution control needs a {cases, labels} dataset');
  }
  const substituted = {};
  let flipped = 0;
  for (const [caseId, label] of Object.entries(dataset.labels)) {
    // The substitution is a LABEL SWAP, not a noise injection: every label
    // becomes the opposite of what it was, so any decision that depended on
    // the labels must move. `label` is boolean here, so the swap is exact.
    const swapped = typeof label === 'boolean' ? !label : `substituted:${String(label)}`;
    if (swapped !== label) flipped += 1;
    substituted[caseId] = swapped;
  }
  if (flipped === 0) {
    throw new MalformedResult('LABEL_SUBSTITUTION_NOOP', 'the control flipped no label; a control that changes nothing proves nothing');
  }
  return {
    ...dataset,
    cases: dataset.cases.map((entry) => ({ ...entry, label: substituted[entry.case_id] ?? null })),
    labels: substituted,
    original_labels_digest: canonicalDigest(dataset.labels),
    labels_digest: canonicalDigest(substituted),
    substituted: true,
    control_id: 'label_substitution',
  };
}

/**
 * The canonical digest of one case record, for the manifest and the seal.
 * @param {object} caseRecord One case from `corpus/s2-008/cases/*.json`.
 * @returns {string} `sha256:<64 hex>`.
 */
export function caseDigest(caseRecord) {
  if (!isPlainObject(caseRecord)) {
    throw new MalformedResult('CASE_RECORD_MALFORMED', 'caseDigest needs a case record');
  }
  return canonicalDigest(caseRecord);
}
