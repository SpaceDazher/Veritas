// tests/research/fixtures/ — the deterministic fixture SET, in one import.
//
// WHAT THIS IS: a barrel over the fixture modules plus ONE set-level digest.
// `fixtureSetDigest()` is the cheap check behind "every fixture must be
// byte-identical across processes for the same inputs": two processes that
// import this file and print that digest must print the same string, and a
// fixture that grew a `Date.now()`, a `Math.random()` or a host path would
// move it.
//
// WHAT IT DOES NOT DO
// It does not validate the fixtures (the consuming tests do that), it does not
// decide anything, and it does not hide a failure: every module here is a plain
// data module with named exports, and the digest is a fact about the BYTES, not
// a claim that the bytes are correct.
//
// The set is deterministic by construction, not by luck: no `Date.now()`, no
// `Math.random()`, no argument-less `new Date()`, no network, no credential and
// no host path is baked into any value. The one host-dependent value in the
// whole directory — the default scratch parent — is COMPUTED at call time from
// `import.meta.url` and is never part of a digest.
//
// Serves: A2, A3, A4 and A5, and the test phase's need for one import of
// "the fixtures" rather than eight imports with a chance of picking the wrong
// pair.
export * from './fixture-digest.mjs';
export * from './fixture-fixed-clock.mjs';
export * from './fixture-run-identity.mjs';
export * from './fixture-preregistration.mjs';
export * from './fixture-measurement-set.mjs';
export * from './fixture-expected-values.mjs';
export * from './fixture-corrupted-variants.mjs';
export * from './fixture-temp-base.mjs';

import { fixtureDigest } from './fixture-digest.mjs';
import { EXPECTED_FLIPS, VARIANT_IDS } from './fixture-corrupted-variants.mjs';
import { EXPECTED_TABLE_ARGUMENT, EXPECTED_VALUE_TABLE, expectedTableFixtureDigest } from './fixture-expected-values.mjs';
import { FIXTURE_TRIALS, PREREGISTRATION, PREREGISTRATION_DIGEST, CLEAN_RUNS } from './fixture-measurement-set.mjs';
import { HYPOTHESIS_CARD, HYPOTHESIS_CARD_DIGEST } from './fixture-preregistration.mjs';

/** The fixture module files this barrel covers, in import order. @type {ReadonlyArray<string>} */
export const FIXTURE_MODULES = Object.freeze([
  'fixture-digest.mjs',
  'fixture-fixed-clock.mjs',
  'fixture-run-identity.mjs',
  'fixture-preregistration.mjs',
  'fixture-measurement-set.mjs',
  'fixture-expected-values.mjs',
  'fixture-corrupted-variants.mjs',
  'fixture-temp-base.mjs',
]);

/**
 * One digest over every value the fixture set hands to a test.
 *
 * Deliberately NOT over `CLEAN_RUNS` keyed by label: run A and run B differ in
 * their identity by construction, so both are included under their own labels
 * and a change to either is visible. The per-field digests are here too, so a
 * failure names WHICH part moved rather than only that something did.
 *
 * The corruption variants are in the set digest, and that is the point of the
 * two-process check: a variant's DECLARED flip moving is a fixture edit, and an
 * edit to an expectation is the exact thing the A3 table discipline exists to
 * make visible. The table ARGUMENT is digested separately from the published
 * document, because they are deliberately different values (the argument carries
 * the frozen table's digest; the document carries the fixture's own).
 * @returns {{set: string, preregistration: string, card: string, expected_table: string, expected_table_argument: string, trials: string, runs: object, flips: string, variants: ReadonlyArray<string>}}
 */
export function fixtureSetDigest() {
  return Object.freeze({
    set: fixtureDigest({
      modules: FIXTURE_MODULES,
      preregistration: PREREGISTRATION,
      card: HYPOTHESIS_CARD,
      trials: FIXTURE_TRIALS,
      table: EXPECTED_VALUE_TABLE,
      table_argument: EXPECTED_TABLE_ARGUMENT,
      runs: CLEAN_RUNS,
      flips: EXPECTED_FLIPS,
    }),
    preregistration: PREREGISTRATION_DIGEST,
    card: HYPOTHESIS_CARD_DIGEST,
    expected_table: expectedTableFixtureDigest(),
    expected_table_argument: fixtureDigest(EXPECTED_TABLE_ARGUMENT),
    trials: fixtureDigest(FIXTURE_TRIALS),
    runs: Object.freeze(Object.fromEntries(
      Object.entries(CLEAN_RUNS).map(([label, run]) => [label, fixtureDigest(run)]),
    )),
    flips: fixtureDigest(EXPECTED_FLIPS),
    variants: VARIANT_IDS,
  });
}
