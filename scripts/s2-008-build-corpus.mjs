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
import { assertPreregistration, preregistrationDigest } from '../src/lib/research/preregistration.mjs';
import { expectedTableDigest } from '../src/lib/research/expected-values.mjs';
import { assertCausalDiscipline, classifyCardRelation } from '../src/lib/research/causality.mjs';
import { caseDigest } from '../src/lib/research/dataset.mjs';
import {
  FIXTURE_CASES,
  FIXTURE_PARTITION,
  HOLDOUT_LABELS,
  HOLDOUT_UNSEAL_DIGEST,
  PREREGISTRATION,
} from '../tests/research/fixtures/fixture-measurement-set.mjs';
import { PREREGISTERED_TRIALS } from '../tests/research/fixtures/fixture-preregistration.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const COMMITTED_CORPUS_DIR = path.join(REPO_ROOT, 'evidence', 's2-008', 'corpus');
const CHECK_ONLY = process.argv.includes('--check');

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
    case_digests: Object.fromEntries([...DEV_CASES, ...HOLDOUT_CASES].map((entry) => [entry.case_id, caseDigest(entry)])),
    trials: PREREGISTERED_TRIALS.map((entry) => ({ index: entry.index, trial: entry.trial, designed_outcome: entry.designed_outcome })),
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

function filesOf() {
  return new Map([
    ['manifest.json', serialise(buildManifest())],
    ['cases/dev.json', serialise(DEV_CASES)],
    ['cases/holdout.json', serialise(HOLDOUT_CASES)],
    ['preregistration.json', serialise(buildPreregistration())],
  ]);
}

function main() {
  // The two documents the corpus is worthless without are validated HERE, at
  // build time, so a corpus that cannot be loaded or whose card cannot carry a
  // causal assertion is never written.
  assertPreregistration(buildPreregistration());
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
  }, null, 2));
}

main();
