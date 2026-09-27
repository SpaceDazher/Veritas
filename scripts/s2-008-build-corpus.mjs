#!/usr/bin/env node
// S2-008 — BUILD THE COMMITTED CORPUS (issue SpaceDazher/Veritas#8).
//
// WHY THIS SCRIPT EXISTS
// A1 needs a real corpus for `readCorpus` to read, `loadPreregistration` to
// load and P1 to peek at. Before it existed, `dataset.mjs` and `causality.mjs`
// were skeletons and there was nothing to read, so the P1 and P5 probes reported
// `not_run` rather than a verdict. The corpus is AUTHORED data — eight
// hand-written observational cases, split into a dev partition and a holdout —
// and this script writes it from the frozen fixture, so:
//   * the fixture set stays the single authoring surface, and
//   * the committed bytes are DERIVED, not re-typed, so a fixture edit that
//     nobody regenerates fails the drift test instead of passing quietly.
//
// DETERMINISM
// No network, no LLM, no credentials, no `Date.now()`, no `Math.random()`. The
// two instants are frozen literals. Running it twice produces byte-identical
// files, which `tests/research/corpus.test.mjs` asserts against the committed
// tree rather than against a fresh temporary directory.
//
// `--check` re-derives everything and compares it with what is on disk, so the
// committed corpus can never drift from the fixture without a non-zero exit.
//
// `--out <dir>` re-derives into a DIFFERENT directory. It exists so the fix for a
// drift can be PROVED without writing into `evidence/`, which this file's owner
// does not own: the self-test writes to scratch, the owner of the corpus runs
// the bare command. The output says in `evidence_eligible` whether the target
// was the committed one, so a self-test build can never be mistaken for a
// corpus a run may be scored against (`--corpus` elsewhere is likewise
// evidence-INELIGIBLE in scripts/s2-008-run.mjs).
//
// OWNER / BOUNDARY
// Writes ONLY under `evidence/s2-008/corpus/`. `corpus/` at the repository root
// belongs to the other stages (`corpus/s2-003/**`, `corpus/s2-006/**`) and this
// worker does not own it, so the S2-008 corpus lives inside the evidence
// directory the ticket's own provability discipline uses. `BLOCKED:` reported in
// the harness log.
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest, canonicalize } from '../src/lib/verifier/canonical-json.mjs';
import {
  assertPreregistration, assertSourceLedger, assertSupersession, createSourceLedgerEntry,
  createSupersession, preregistrationDigest,
} from '../src/lib/research/preregistration.mjs';
import { expectedTableDigest } from '../src/lib/research/expected-values.mjs';
import { assertFrozenCampaignDerivable } from '../src/lib/research/campaign-expectation.mjs';
import { assertCausalDiscipline, classifyCardRelation } from '../src/lib/research/causality.mjs';
import { caseDigest } from '../src/lib/research/dataset.mjs';
import {
  FIXTURE_CASES,
  FIXTURE_PARTITION,
  HOLDOUT_LABELS,
  HOLDOUT_UNSEAL_DIGEST,
  PREREGISTRATION,
} from '../tests/research/fixtures/fixture-measurement-set.mjs';
import {
  FROZEN_CASES_DIGEST, PREREGISTERED_TRIALS, SUPERSEDED_CONFIDENCE, SUPERSEDED_EXPECTED_TABLE_DIGEST,
  SUPERSESSION_LEDGER, SUPERSESSION_REASON, buildSupersededPreregistration as buildSupersededPreregistrationFixture,
} from '../tests/research/fixtures/fixture-preregistration.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const COMMITTED_CORPUS_DIR = path.join(REPO_ROOT, 'evidence', 's2-008', 'corpus');
const CHECK_ONLY = process.argv.includes('--check');

/**
 * The digest the committed `preregistration.json` carried BEFORE the S2-008
 * repair — the value `git show HEAD:evidence/s2-008/corpus/preregistration.json`
 * prints. It is a LITERAL here on purpose: it is history, not a value this script
 * computes. A `git`-derived number would make the check depend on a repository
 * state, and a number derived from the current fixture would make the check a
 * tautology. A reader who wants to re-derive it reads the committed file's own
 * `preregistration_digest` in the commit that published it.
 * @type {string}
 */
const SUPERSEDED_PREREGISTRATION_DIGEST = '8fab7e83d472b7914b6e660dd956f6dc394589bcd4ab323162b6545dde7fe479';

/**
 * The corpus directory to build into: `--out <dir>` when given, resolved
 * against the repository root for a relative path, otherwise the committed
 * directory.
 * @returns {string} An absolute path.
 */
function targetCorpusDir() {
  const flag = process.argv.indexOf('--out');
  if (flag === -1) return COMMITTED_CORPUS_DIR;
  const given = process.argv[flag + 1];
  if (typeof given !== 'string' || given.length === 0) {
    throw new Error('S2_008_CORPUS_OUT_MISSING:--out needs a directory');
  }
  return path.resolve(REPO_ROOT, given);
}

const CORPUS_DIR = targetCorpusDir();

/** The dev partition: the SAME eight cases, carrying the dev label vector the
 * FROZEN BASELINE was measured on. The case ids are deliberately the SAME ids
 * as the holdout partition's — a case is a case, and a probe that has to show
 * "the PRIMARY read works and the HOLDOUT read is refused" reads one id through
 * both paths. Distinct ids would make the HOLDOUT attempt fail as
 * `UNKNOWN_CASE` before the unseal digest was ever examined, which is a refusal
 * for the wrong reason. @type {ReadonlyArray<object>} */
const DEV_CASES = Object.freeze(FIXTURE_CASES.map((entry) => Object.freeze({
  case_id: entry.case_id,
  partition: 'PRIMARY',
  ground_truth_relation: entry.ground_truth_relation,
  observed_relation_strength: entry.observed_relation_strength,
  // The dev partition's label is the baseline's label: 6 of 8 agree, which is
  // the frozen baseline 0.75 written as a dyadic fraction.
  label: Number(entry.case_id.slice(-1)) <= 6 ? 1 : 0,
  stratum: 'all_cases',
})));

const HOLDOUT_CASES = Object.freeze(FIXTURE_CASES.map((entry) => Object.freeze({
  case_id: entry.case_id,
  partition: FIXTURE_PARTITION,
  ground_truth_relation: entry.ground_truth_relation,
  observed_relation_strength: entry.observed_relation_strength,
  label: entry.agreement_label,
  agreement_by_trial: entry.agreement_by_trial,
  stratum: 'all_cases',
})));

function serialise(value) {
  return `${canonicalize(value)}\n`;
}

/**
 * The corpus manifest: what each partition holds and what it hashes to. The
 * digests are over the CANONICAL form of the case arrays, and `dataset.mjs`
 * recomputes and checks them on every load, so a corpus whose bytes moved is
 * refused rather than measured.
 */
function buildManifest() {
  return {
    kind: 's2-008-corpus/1',
    description: 'S2-008 offline deterministic observational corpus. Eight hand-authored cases in two partitions; no real adapter is in scope.',
    partitions: {
      PRIMARY: {
        file: 'cases/dev.json',
        case_count: DEV_CASES.length,
        digest: canonicalDigest(DEV_CASES),
        role: 'the development partition; readable without an unseal digest',
      },
      HOLDOUT: {
        file: 'cases/holdout.json',
        case_count: HOLDOUT_CASES.length,
        digest: canonicalDigest(HOLDOUT_CASES),
        role: 'the holdout partition; readable only through readCorpus with the preregistered one-shot unseal digest',
        labels_digest: canonicalDigest(HOLDOUT_LABELS),
      },
    },
    // F2: the per-case seal, keyed BY PARTITION. The ids are deliberately the
    // same in both partitions (a probe reads one id through both paths), so a
    // map keyed by `case_id` alone could hold only ONE of the two records: the
    // builder's `fromEntries` kept the last writer, the holdout, and a PRIMARY
    // read was "sealed" by a digest that belonged to a different record. The
    // key is `<partition>:<case_id>` and `dataset.mjs` verifies the entry for
    // the partition it is loading.
    case_digests: Object.fromEntries([
      ...DEV_CASES.map((entry) => [`PRIMARY:${entry.case_id}`, caseDigest(entry)]),
      ...HOLDOUT_CASES.map((entry) => [`${FIXTURE_PARTITION}:${entry.case_id}`, caseDigest(entry)]),
    ]),
    trials: PREREGISTERED_TRIALS.map((entry) => ({ index: entry.index, trial: entry.trial, designed_outcome: entry.designed_outcome })),
    // The two PREREGISTRATION documents, named with their own digests, plus the
    // supersession that relates them. A reader who wants to know what the first
    // delivery published reads `preregistration-superseded.json`; a reader who
    // wants to know why it was replaced reads
    // `preregistration-supersession.json`. Neither is derivable from the other,
    // and neither is a member of the other.
    preregistration: Object.freeze({
      file: 'preregistration.json',
      preregistration_digest: buildPreregistration().preregistration_digest,
      expected_table_digest: expectedTableDigest(),
      status: 'IN_FORCE',
    }),
    superseded_preregistration: Object.freeze({
      file: 'preregistration-superseded.json',
      preregistration_digest: buildSupersededPreregistration().preregistration_digest,
      expected_table_digest: SUPERSEDED_EXPECTED_TABLE_DIGEST,
      status: 'SUPERSEDED',
      superseded_by: 'preregistration.json',
    }),
    supersession: Object.freeze({
      file: 'preregistration-supersession.json',
      supersession_id: buildSupersession().supersession_id,
      supersession_digest: buildSupersession().supersession_digest,
      reason: SUPERSESSION_REASON,
    }),
    // A3: the ledger of the frozen SOURCES, named with its own count and its
    // last anchor. A reader of the manifest alone can see how many times the
    // frozen synthetic corpus or the frozen table were changed, and the ledger
    // file beside it carries each change with its reason and both digests.
    source_ledger: Object.freeze({
      file: 'supersession-ledger.json',
      entry_count: buildSourceLedger().entry_count,
      last_anchor_digest: buildSourceLedger().last_anchor_digest,
      records: 'one entry per change to (cases_digest, expected_table_digest), chained by anchor digest',
    }),
  };
}

/**
 * The committed preregistration: the fixture document plus the frozen
 * expected-value table's digest, which `assertTableFrozen` requires. The
 * digest is the in-code table's, so an edit of the table after this file was
 * committed becomes an `EXPECTED_TABLE_DRIFT` refusal rather than a silent
 * re-scoring.
 */
function buildPreregistration() {
  return { ...PREREGISTRATION, expected_table_digest: expectedTableDigest() };
}

/**
 * The SUPERSEDED preregistration, whole, with its own self-seal (R-A).
 *
 * The first delivery of this track published `confidence: 0.95` against
 * `alpha = 0.05` over a family of 3, so the bound it inherited was `0.05`
 * against a corrected level of `0.05/3 = 0.016667` and the rule could reject
 * nothing at all. That is a defect in a FROZEN document, and the honest ways to
 * deal with a defect in a frozen document are to preserve it and say so, or to
 * delete it. This file is the first way: the document is committed here, byte
 * for byte as it was published, beside the one in force.
 *
 * It is re-derived from the same fixture builder with the ONE published
 * confidence and the ONE frozen-table digest the first delivery carried, so
 * `preregistrationDigest` over these bytes is `8fab7e83…` — the value the
 * committed corpus carried before this repair. A reconstruction that did not
 * reproduce that digest would be a new document that happens to look old, and
 * `main()` refuses to write it.
 * @returns {Readonly<object>}
 */
function buildSupersededPreregistration() {
  return buildSupersededPreregistrationFixture({ holdoutUnsealDigest: HOLDOUT_UNSEAL_DIGEST });
}

/**
 * The SUPERSESSION record: what replaced the document above, why, and both
 * states' published values. Its own document kind in
 * `src/lib/research/preregistration.mjs` (`SUPERSESSION_KIND`), asserted here
 * against the document it names, so a supersession that points at nothing is
 * never written.
 * @returns {Readonly<object>}
 */
function buildSupersession() {
  const superseded = buildSupersededPreregistration();
  return createSupersession({ superseded, replacedBy: buildPreregistration(), reason: SUPERSESSION_REASON });
}

/**
 * The ledger of the frozen SOURCES (A3), built from the fixture's declared
 * history and checked against the digests the sources produce right now.
 *
 * Two refusals can be raised here and both are the property:
 *   * the freshly derived case digest is not the literal the fixture declares, so
 *     the eight synthetic cases were edited without an appended entry;
 *   * the chain does not end at `{cases_digest, expected_table_digest}` as the
 *     current table derives it, so the table was edited without an appended
 *     entry.
 * Either one aborts the build before a byte is written, so no run is ever scored
 * against a corpus whose frozen sources moved unrecorded.
 * @returns {Readonly<{kind: string, entries: ReadonlyArray<object>, entry_count: number, last_anchor_digest: string, matches_current: true}>}
 */
function buildSourceLedger() {
  const casesDigest = canonicalDigest(HOLDOUT_CASES);
  if (casesDigest !== FROZEN_CASES_DIGEST) {
    throw new Error(`S2_008_FROZEN_CASES_DIGEST_DRIFT:the fixture's holdout cases hash to ${casesDigest} while the supersession ledger declares ${FROZEN_CASES_DIGEST}; a change to the eight synthetic cases is an appended ledger entry, never a re-seal`);
  }
  const entries = [];
  for (const declared of SUPERSESSION_LEDGER) {
    entries.push(createSourceLedgerEntry({
      index: entries.length,
      previous: entries[entries.length - 1] ?? null,
      cases_digest: declared.cases_digest,
      expected_table_digest: declared.expected_table_digest,
      reason: declared.reason,
    }));
  }
  return assertSourceLedger(entries, { cases_digest: casesDigest, expected_table_digest: expectedTableDigest() });
}

function filesOf() {
  return new Map([
    ['manifest.json', serialise(buildManifest())],
    ['cases/dev.json', serialise(DEV_CASES)],
    ['cases/holdout.json', serialise(HOLDOUT_CASES)],
    ['preregistration.json', serialise(buildPreregistration())],
    ['preregistration-superseded.json', serialise(buildSupersededPreregistration())],
    ['preregistration-supersession.json', serialise(buildSupersession())],
    ['supersession-ledger.json', serialise(buildSourceLedger())],
  ]);
}

function main() {
  // The two documents the corpus is worthless without are validated HERE, at
  // build time, so a corpus that cannot be loaded or whose card cannot carry a
  // causal assertion is never written.
  assertPreregistration(buildPreregistration());
  // R-B/R-C: the frozen table declares a CAMPAIGN decision, and this is where it
  // is re-derived through the comparator's own rule. A declaration the rule does
  // not produce is refused BEFORE anything is sealed, so a campaign is never
  // scored against an expectation nothing derived.
  const campaign = assertFrozenCampaignDerivable();
  const card = PREREGISTRATION.card;
  const classification = classifyCardRelation(card);
  // The card must be OBSERVATIONAL (`relation_strength` in the observational
  // subset), must make NO causal assertion, and must be admissible as it
  // stands. `observational: true` is the desired state, not a defect: A4 is
  // about an observational card, and the label-substitution control is what
  // turns it into a claim.
  if (!classification.observational || classification.causalAssertion || !classification.admissible) {
    throw new Error(`S2_008_CORPUS_CARD_NOT_OBSERVATIONAL:${classification.refusalCode ?? 'card is not an observational non-claim'}`);
  }
  assertCausalDiscipline(card);
  if (HOLDOUT_UNSEAL_DIGEST.slice(7) !== canonicalDigest(HOLDOUT_LABELS)) {
    throw new Error('S2_008_CORPUS_UNSEAL_DRIFT:the fixture unseal digest does not match the corpus label map');
  }
  // The self-seal is asserted against the TRACK's own digest, not the
  // fixture's re-projection (S2-008-SD-08).
  if (PREREGISTRATION.preregistration_digest !== preregistrationDigest(PREREGISTRATION)) {
    throw new Error('S2_008_CORPUS_PREREG_SEAL_DRIFT:the fixture seal does not match the track digest');
  }
  // R-A: the SUPERSESSION and the document it supersedes are validated with the
  // track's own assertions, and the superseded document's digest is compared
  // against the value the COMMITTED corpus carried before this repair. A
  // reconstruction that did not reproduce `8fab7e83…` would be a new document
  // that happens to look old, and the history is the one thing this file exists
  // to preserve.
  const superseded = buildSupersededPreregistration();
  assertPreregistration(superseded);
  if (superseded.preregistration_digest !== SUPERSEDED_PREREGISTRATION_DIGEST) {
    throw new Error(`S2_008_CORPUS_SUPERSEDED_SEAL_DRIFT:the reconstruction of the first delivery seals ${String(superseded.preregistration_digest)} while the committed corpus carried ${String(SUPERSEDED_PREREGISTRATION_DIGEST)}`);
  }
  if (superseded.multiplicity_rule.confidence !== SUPERSEDED_CONFIDENCE) {
    throw new Error(`S2_008_CORPUS_SUPERSEDED_CONFIDENCE_DRIFT:the superseded document publishes confidence ${String(superseded.multiplicity_rule.confidence)}, not the ${String(SUPERSEDED_CONFIDENCE)} the first delivery published`);
  }
  assertSupersession(buildSupersession(), superseded);

  const files = filesOf();
  const drift = [];
  for (const [name, contents] of files) {
    const file = path.join(CORPUS_DIR, name);
    if (CHECK_ONLY) {
      const present = existsSync(file) ? readFileSync(file, 'utf8') : null;
      if (present !== contents) drift.push(name);
      continue;
    }
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, contents);
  }
  if (CHECK_ONLY && drift.length > 0) {
    console.log(JSON.stringify({
      ok: false, mode: 'check', corpusDir: path.relative(REPO_ROOT, CORPUS_DIR), evidence_eligible: CORPUS_DIR === COMMITTED_CORPUS_DIR, drift,
    }, null, 2));
    process.exit(1);
  }
  console.log(JSON.stringify({
    ok: true,
    mode: CHECK_ONLY ? 'check' : 'write',
    corpusDir: path.relative(REPO_ROOT, CORPUS_DIR),
    evidence_eligible: CORPUS_DIR === COMMITTED_CORPUS_DIR,
    files: [...files.keys()].sort(),
    unseal_digest: HOLDOUT_UNSEAL_DIGEST,
    preregistration_digest: buildPreregistration().preregistration_digest,
    expected_table_digest: expectedTableDigest(),
    manifest_digest: canonicalDigest(buildManifest()),
    // R-A/R-B: the supersession and the campaign expectation, printed so a
    // reader of this output sees the history and the declared answer without
    // opening a file.
    superseded_preregistration_digest: buildSupersededPreregistration().preregistration_digest,
    supersession_id: buildSupersession().supersession_id,
    // A3: the ledger's own state, printed so a reader of this output sees how
    // many changes to the frozen sources are on record without opening a file.
    source_ledger_entries: buildSourceLedger().entry_count,
    source_ledger_last_anchor_digest: buildSourceLedger().last_anchor_digest,
    expected_campaign_decision: campaign.decision,
    expected_campaign_interval: campaign.interval,
  }, null, 2));
}

main();
