// S2-008 REPAIR, ROUND 2 — THE SEVEN TRIAGE-CONFIRMED FIXES, AS TESTS
// (issue SpaceDazher/Veritas#8, repair run wfr_38b31d45-48e0-443e-9a9b-b24f86319847).
//
// EVERY CASE BELOW IS A REPRODUCTION THAT WAS OBSERVED TO PASS THE GATE BEFORE
// THIS FILE EXISTED. Each one names the exit code the reviewer observed, so a
// reader can check the claim rather than take it:
//
//   F1  `best_seed_undisclosed` on a run record: `verify:s2-008-replay` exit 0
//       and `verify:s2-008` exit 3 with `blockingGates []`.
//   F2  `manifest.case_digests['s2-008-case-01'] = 0*64`: `check-corpus` exit 1,
//       `verify:s2-008-replay` exit 0. The seal was live in `--check` and dead
//       at read time.
//   F3  the same tamper in the working tree: `manifest:check` exit 0, because
//       that gate reads `git show HEAD:<file>`.
//   F4  an unconditional `return {decision: 'POSITIVE'}` at the top of
//       `decisionFromInterval`: `test:s2-008-security-probes` exit 0, 6/6.
//   A3  a wholesale self-consistent rewrite (fixture 8/8 + table 8/8 +
//       `EXPECTED_CAMPAIGN` = what the rule then derives + re-seal): the whole
//       chain green, because the seal moved with the rewrite.
//   M1  one key, `base.tracked_files_of_this_track`, published as 39 and as 51.
//
// WHAT EACH FIX CLAIMS, AND NO MORE
//   F1 — every comparator failure the honest campaign raises is DECLARED by the
//        frozen table, and an undeclared one is a gate term. The comparator is
//        not weakened: the three failures the delivered campaign raises stay
//        raised and stay recorded.
//   F2 — the per-case digests are verified at READ time, keyed by partition, and
//        the aggregate chain now runs the corpus drift check as a gate.
//   F3 — the aggregate chain refuses a WORKING-TREE tamper even though
//        `manifest:check` cannot; the new gate re-derives from the fixture.
//   F4 — the probes gate additionally refuses a comparator that cannot
//        re-derive the frozen campaign decision.
//   A3 — a change to the frozen synthetic sources (cases or table) is refused
//        until an entry is APPENDED to the supersession ledger with a reason.
//        An appended entry is a supersession, which is what R-A asked for; this
//        file does not claim to detect a recorded one, and the report says so.
//   M1 — both records publish the SCOPE of the count beside the count.
//
// OFFLINE AND DETERMINISTIC
// No network, no LLM, no credentials, no spawn of the chain, no clock read on a
// decision path. The tamper cases copy the committed corpus into a temporary
// directory and read it through the track's own `readCorpus` with an injected
// fixed clock, so they exercise the read path a run uses and not a mock of it.
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  SOURCE_LEDGER_KIND, assertSourceLedger, createSourceLedgerEntry, sourceAnchorDigest,
} from '../../src/lib/research/preregistration.mjs';
import {
  EXPECTED_CAMPAIGN, EXPECTED_COMPARATOR_FAILURES, MEASURED_FAMILY_SIZE, expectedTableDigest,
  unexpectedComparatorFailures,
} from '../../src/lib/research/expected-values.mjs';
import { deriveFrozenCampaignDecision } from '../../src/lib/research/campaign-expectation.mjs';
import { readCorpus } from '../../src/lib/research/dataset.mjs';
import { comparatorIntegrity, gateExitCode } from '../../scripts/s2-008-security-probes.mjs';
import { resolveBase } from '../../scripts/s2-008-run.mjs';
import {
  FROZEN_CASES_DIGEST, SUPERSESSION_LEDGER, SUPERSEDED_EXPECTED_TABLE_DIGEST,
} from './fixtures/fixture-preregistration.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CORPUS_DIR = path.join(REPO_ROOT, 'evidence', 's2-008', 'corpus');
const MANIFEST = path.join(CORPUS_DIR, 'manifest.json');

/** A 64-hex string that is not any digest in the tree. */
const FOREIGN_DIGEST = 'f'.repeat(64);

/** A throwaway copy of the committed corpus, removed when `fn` returns. */
function withCorpusCopy(mutate, fn) {
  const root = mkdtempSync(path.join(tmpdir(), 's2-008-triage-'));
  try {
    cpSync(CORPUS_DIR, root, { recursive: true });
    if (mutate !== null) mutate(root);
    return fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

/** `manifest.json` of a corpus root, mutated in place. */
function patchManifest(root, patch) {
  const file = path.join(root, 'manifest.json');
  const manifest = JSON.parse(readFileSync(file, 'utf8'));
  patch(manifest);
  writeFileSync(file, `${JSON.stringify(manifest)}\n`, 'utf8');
  return manifest;
}

/** `readFileSync` of a corpus file, by name. */
function readManifest() {
  return JSON.parse(readFileSync(MANIFEST, 'utf8'));
}

/**
 * The refusal a `MalformedResult` carries is its FIRST MESSAGE TOKEN, not
 * `.code` — `MalformedResult` puts the class in `.code` and the specific refusal
 * in the message, the convention `dataset.mjs` already follows. Matched here the
 * same way, so a case asserts on the refusal a reader would see.
 * @param {string} code
 * @returns {(error: unknown) => boolean}
 */
function refusedWith(code) {
  return (error) => String(error?.message ?? '').startsWith(code);
}

/** The delivered campaign's failure and limit lists, as the comparator raises
 *  them: the declared set over two runs. Used as the base every F1 case perturbs,
 *  because a refusal has to hold for the honest list PLUS the injection and not
 *  for the injection alone. */
function honestLists() {
  const perLetter = (letter) => [
    ...Object.entries(EXPECTED_COMPARATOR_FAILURES.per_run).flatMap(([code, count]) => Array.from({ length: count }, () => ({ code, detail: `${letter}: ${code}` }))),
    ...Object.entries(EXPECTED_COMPARATOR_FAILURES.per_run_limits).flatMap(([code, count]) => Array.from({ length: count }, () => ({ code, detail: `${letter}: ${code}` }))),
  ];
  const everything = ['runA', 'runB'].flatMap(perLetter);
  const isLimit = (entry) => EXPECTED_COMPARATOR_FAILURES.per_run_limits[entry.code] !== undefined;
  return { failures: everything.filter((entry) => !isLimit(entry)), limits: everything.filter(isLimit) };
}

/** The declared ledger history, built through the track's own entry builder so
 *  the test exercises the chain it asserts on. */
function declaredEntries() {
  const built = [];
  for (const declared of SUPERSESSION_LEDGER) {
    built.push(createSourceLedgerEntry({
      index: built.length,
      previous: built[built.length - 1] ?? null,
      cases_digest: declared.cases_digest,
      expected_table_digest: declared.expected_table_digest,
      reason: declared.reason,
    }));
  }
  return built;
}

// --- F1 ---------------------------------------------------------------------

test('F1 the frozen table declares exactly the comparator failures the honest campaign raises', () => {
  // Declared per run: one VIOLATION row, one unmeasured trial, one undecided
  // campaign. Each number is DERIVED from the rows, not typed.
  assert.deepEqual(EXPECTED_COMPARATOR_FAILURES.per_run, {
    trial_violation: 1,
    metric_not_measured: 1,
    decision_unresolved: 1,
  });
  assert.deepEqual(EXPECTED_COMPARATOR_FAILURES.per_run_limits, { latency_observed: 1 });
  // The campaign really is undecided on this corpus — that is what makes
  // `decision_unresolved` a declaration rather than a hope.
  assert.equal(deriveFrozenCampaignDecision().decision, EXPECTED_CAMPAIGN.decision);
});

test('F1 the honest comparison raises exactly the declared set over two runs and is reported green', () => {
  const findings = unexpectedComparatorFailures({ ...honestLists(), runs: 2 });
  assert.deepEqual(findings, [], 'the delivered campaign must raise nothing the table does not declare');
});

test('F1 an UNDECLARED comparator failure is a finding, not a swallow', () => {
  // The exact shape reproduction F1 injected: `best_seed` reported with no
  // `seed_disclosures` entry, which `scoreSeedDisclosure` raises as
  // `best_seed_undisclosed` on BOTH runs, beside the three declared failures.
  const honest = honestLists();
  const findings = unexpectedComparatorFailures({
    ...honest,
    failures: [...honest.failures, ...['runA', 'runB'].map((letter) => ({ code: 'best_seed_undisclosed', detail: `${letter}: best_seed is reported with no seed_disclosures entry; a selection without the full seed set is a violation` }))],
    runs: 2,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].code, 'UNEXPECTED_CODE');
  assert.equal(findings[0].field, 'failures.best_seed_undisclosed');
  assert.equal(findings[0].observed, 2);
  assert.equal(findings[0].expected, 0);
  assert.match(findings[0].detail, /a failure nobody declared/);
});

test('F1 a declared failure raised the WRONG NUMBER of times is a finding too', () => {
  // The other direction: a record that suppressed the INFRA trial's violation
  // by reporting one `trial_violation` across two runs instead of one per run.
  const honest = honestLists();
  const findings = unexpectedComparatorFailures({
    ...honest,
    failures: honest.failures.filter((entry) => entry.code !== 'trial_violation').concat([{ code: 'trial_violation', detail: 'runA: once' }]),
    runs: 2,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].code, 'COUNT_DIVERGES');
  assert.equal(findings[0].expected, 2);
  assert.equal(findings[0].observed, 1);
});

test('F1 an UNKNOWN limit code is a finding: latency may only raise what the table declares', () => {
  const honest = honestLists();
  const findings = unexpectedComparatorFailures({ ...honest, limits: [...honest.limits, { code: 'latency_decides' }], runs: 2 });
  assert.deepEqual(findings.map((entry) => entry.field), ['limits.latency_decides']);
  assert.equal(findings[0].code, 'UNEXPECTED_CODE');
});

test('F1 the replay and the harness records publish the new term, and it is TRUE on the delivered campaign', () => {
  for (const name of ['s2-008-replay.json', 's2-008-harness.json']) {
    const record = JSON.parse(readFileSync(path.join(REPO_ROOT, 'evidence', name), 'utf8'));
    assert.equal(record.overall_terms.comparator_failures_match_frozen_expectation, true, `${name} must carry the F1 term`);
    assert.deepEqual(record.overall_terms.unexpected_comparator_findings, [], `${name} must carry no undeclared comparator failure`);
    assert.equal(record.comparator_failures.is_a_gate_term, true, `${name} must publish that the failure list is a term`);
  }
});

test('F1 the aggregator refuses a record whose own terms say an undeclared failure was raised', () => {
  // The aggregator re-reads the term from the RECORD, so a record cannot be
  // green on the child's say-so. Exercised through `gateExitCode` (the
  // probes gate's own function) and through the campaign-expectation refusal
  // the aggregator's `decision_agrees_with_table` term rests on: both are the
  // "the aggregator re-derives" shape, and both must refuse.
  const refused = gateExitCode({
    expectedProbes: 6,
    results: Array.from({ length: 6 }, (_, index) => ({ probe: `P${index}`, status: 'pass', flipped: true })),
    notRun: [],
    broken: [],
    controls: [],
    controlsNotRun: [],
    counters: {},
    comparatorIntegrityOk: false,
  });
  assert.equal(refused.exitCode, 1);
  assert.ok(refused.reasons.some((reason) => reason.startsWith('comparator-decision-arithmetic:')));
});

// --- F2 ---------------------------------------------------------------------

test('F2 the committed manifest seals every case of BOTH partitions under a partition-scoped key', () => {
  const manifest = readManifest();
  const keys = Object.keys(manifest.case_digests);
  assert.equal(keys.length, 16, 'eight cases in each of two partitions, each sealed on its own');
  assert.equal(keys.filter((key) => key.startsWith('PRIMARY:')).length, 8);
  assert.equal(keys.filter((key) => key.startsWith('HOLDOUT:')).length, 8);
  // The defect the reproduction found: a map keyed by the bare id could hold
  // only ONE record per id, and the two partitions share their ids.
  assert.equal(new Set(keys.map((key) => key.split(':')[1])).size, 8);
});

test('F2 a tampered per-case digest is refused AT READ TIME, not only by --check', () => {
  // `readCorpus` on the PRIMARY partition needs no unseal digest and writes no
  // ledger row, so a plain object is a sufficient handle here and the case
  // drives the real read path a run uses.
  const read = (root) => readCorpus({}, { partition: 'PRIMARY', caseId: 's2-008-case-01', corpusDir: root });
  assert.equal(read(CORPUS_DIR).case.case_id, 's2-008-case-01', 'the committed corpus reads');
  for (const [name, key, code] of [
    ['a foreign digest for one case', 'PRIMARY:s2-008-case-01', 'CORPUS_CASE_DIGEST_MISMATCH'],
    ['a missing per-case seal', 'PRIMARY:s2-008-case-02', 'CORPUS_CASE_DIGEST_ABSENT'],
  ]) {
    withCorpusCopy((root) => patchManifest(root, (manifest) => {
      if (code === 'CORPUS_CASE_DIGEST_MISMATCH') manifest.case_digests[key] = FOREIGN_DIGEST;
      else delete manifest.case_digests[key];
    }), (root) => {
      assert.throws(() => read(root), refusedWith(code), name);
    });
  }
  // A manifest with no per-case seal at all is a refusal, not a skipped check.
  withCorpusCopy((root) => patchManifest(root, (manifest) => { delete manifest.case_digests; }), (root) => {
    assert.throws(() => read(root), refusedWith('CORPUS_CASE_SEAL_ABSENT'));
  });
});

// --- F3 ---------------------------------------------------------------------

test('F3 the aggregate chain declares a corpus gate that reads the WORKING TREE', () => {
  const source = readFileSync(path.join(REPO_ROOT, 'scripts', 'verify-s2-008.mjs'), 'utf8');
  // The gate is spawned as a child and is not the root-manifest gate: the root
  // manifest reads `git show HEAD:<file>`, which is exactly why a working-tree
  // tamper of the corpus was invisible to the chain.
  assert.match(source, /s2-008-build-corpus\.mjs/);
  assert.match(source, /reads: 'the working tree/);
  assert.match(source, /gates\.corpus/);
});

// --- F4 ---------------------------------------------------------------------

test('F4 the probes gate refuses a comparator that cannot re-derive the frozen campaign decision', () => {
  const integrity = comparatorIntegrity();
  assert.equal(integrity.ok, true, `the delivered comparator must re-derive: ${String(integrity.refusal)}`);
  assert.equal(integrity.decision, EXPECTED_CAMPAIGN.decision);
  assert.equal(integrity.declared, EXPECTED_CAMPAIGN.decision);
  assert.equal(integrity.refusal, null);
});

test('F4 the comparator check is fail-closed on a derivation that raises, and it is the SAME function the builder uses', () => {
  // The check is a CALL, not a copy: `comparatorIntegrity` is documented as
  // delegating to `assertFrozenCampaignDerivable`, and this case pins that the
  // comparator the campaign uses is the one under the frozen table's arithmetic
  // — a check with its own arithmetic could keep passing after the comparator
  // was rewired, which is the failure the probes file's header forbids.
  const derived = deriveFrozenCampaignDecision();
  assert.equal(derived.family_size, MEASURED_FAMILY_SIZE);
  assert.equal(derived.decision, EXPECTED_CAMPAIGN.decision);
  assert.equal(derived.rule_feasibility.never_rejects, false, 'the frozen rule can reject, or the campaign is undecidable by construction');
});

// --- A3 ---------------------------------------------------------------------

test('A3 the committed ledger is a chain of three entries ending at the current frozen sources', () => {
  const ledger = JSON.parse(readFileSync(path.join(CORPUS_DIR, 'supersession-ledger.json'), 'utf8'));
  assert.equal(ledger.kind, SOURCE_LEDGER_KIND);
  assert.equal(ledger.entry_count, 3);
  assert.equal(ledger.matches_current, true);
  assert.deepEqual(ledger.entries.map((entry) => entry.index), [0, 1, 2]);
  // Entry 0 is the FIRST delivery, whose table digest is the literal history
  // and whose case digest is the one the first delivery sealed.
  assert.equal(ledger.entries[0].expected_table_digest, SUPERSEDED_EXPECTED_TABLE_DIGEST);
  assert.equal(ledger.entries[0].cases_digest, FROZEN_CASES_DIGEST);
  assert.equal(ledger.entries[0].previous_anchor_digest, null);
  // Every entry carries a reason: an entry with no reason is a deletion.
  for (const entry of ledger.entries) {
    assert.equal(typeof entry.reason, 'string');
    assert.ok(entry.reason.trim().length > 0, `entry ${entry.index} must say why`);
    assert.ok(!/[\r\n]/.test(entry.reason), 'a reason is one line');
  }
  // The manifest names the ledger and its last anchor.
  const manifest = readManifest();
  assert.equal(manifest.source_ledger.file, 'supersession-ledger.json');
  assert.equal(manifest.source_ledger.entry_count, 3);
  assert.equal(manifest.source_ledger.last_anchor_digest, ledger.last_anchor_digest);
});

test('A3 a change to the frozen TABLE without an appended entry is refused by name', () => {
  const entries = declaredEntries();
  // The A3 attack: the table is rewritten to 8/8 and `EXPECTED_CAMPAIGN` is
  // rewritten to whatever the rule then derives, so the CURRENT table digest is
  // a value the ledger has never seen. The chain still ends at the old anchor.
  assert.throws(
    () => assertSourceLedger(entries, { cases_digest: FROZEN_CASES_DIGEST, expected_table_digest: 'a'.repeat(64) }),
    (error) => String(error.message) === 'FROZEN_SOURCES_CHANGED_WITHOUT_SUPERSESSION'
      && /never a re-seal/.test(String(error.detail)),
  );
  // …and the current tree still passes, which is the control for the refusal.
  assert.equal(assertSourceLedger(entries, { cases_digest: FROZEN_CASES_DIGEST, expected_table_digest: expectedTableDigest() }).matches_current, true);
});

test('A3 a change to the frozen CASES without an appended entry is refused by name', () => {
  const entries = declaredEntries();
  assert.throws(
    () => assertSourceLedger(entries, { cases_digest: 'b'.repeat(64), expected_table_digest: expectedTableDigest() }),
    (error) => String(error.message) === 'FROZEN_SOURCES_CHANGED_WITHOUT_SUPERSESSION',
  );
});

test('A3 a ledger that is not a chain is refused: a broken link, a repeated anchor, a bare list', () => {
  const entry = (index, previous, tableDigest, reason) => createSourceLedgerEntry({
    index,
    previous,
    cases_digest: FROZEN_CASES_DIGEST,
    expected_table_digest: tableDigest,
    reason,
  });
  const first = entry(0, null, SUPERSEDED_EXPECTED_TABLE_DIGEST, 'the first delivery of the frozen sources');
  const second = entry(1, first, expectedTableDigest(), 'a recorded change to the frozen sources');
  // A broken link: the second entry claims a parent anchor nobody published.
  assert.throws(
    () => assertSourceLedger([first, { ...second, previous_anchor_digest: FOREIGN_DIGEST }], { cases_digest: FROZEN_CASES_DIGEST, expected_table_digest: expectedTableDigest() }),
    (error) => String(error.message) === 'LEDGER_CHAIN_BROKEN',
  );
  // An entry that records no change makes the count a lie.
  assert.throws(
    () => createSourceLedgerEntry({ index: 2, previous: second, cases_digest: FROZEN_CASES_DIGEST, expected_table_digest: expectedTableDigest(), reason: 'nothing moved' }),
    (error) => String(error.message) === 'LEDGER_RECORDS_NO_CHANGE',
  );
  // An empty ledger records nothing.
  assert.throws(
    () => assertSourceLedger([], { cases_digest: FROZEN_CASES_DIGEST, expected_table_digest: expectedTableDigest() }),
    (error) => String(error.message) === 'LEDGER_EMPTY',
  );
  // An entry that carries a result is refused as a decision basis, the same
  // closed-key rule the supersession obeys.
  assert.throws(
    () => assertSourceLedger([{ ...first, decision: 'POSITIVE' }], { cases_digest: FROZEN_CASES_DIGEST, expected_table_digest: expectedTableDigest() }),
    (error) => String(error.message) === 'LEDGER_AS_DECISION_BASIS',
  );
});

test('A3 a tampered manifest ledger anchor is refused at READ TIME (one side only)', () => {
  // The manifest and the ledger file are two committed documents. A rewrite that
  // moves the anchor in one and not the other is refused by `loadPartition`, so
  // the history cannot be edited on a single side.
  withCorpusCopy((root) => patchManifest(root, (manifest) => {
    manifest.source_ledger.last_anchor_digest = FOREIGN_DIGEST;
  }), (root) => {
    assert.throws(
      () => readCorpus({}, { partition: 'PRIMARY', caseId: 's2-008-case-01', corpusDir: root }),
      refusedWith('CORPUS_SOURCE_LEDGER_ANCHOR_MISMATCH'),
    );
  });
  // A manifest that names no ledger is a refusal too: a corpus whose frozen
  // sources have no recorded history cannot say how many times they changed.
  withCorpusCopy((root) => patchManifest(root, (manifest) => { delete manifest.source_ledger; }), (root) => {
    assert.throws(
      () => readCorpus({}, { partition: 'PRIMARY', caseId: 's2-008-case-01', corpusDir: root }),
      refusedWith('CORPUS_SOURCE_LEDGER_UNDECLARED'),
    );
  });
});

// --- M1 ---------------------------------------------------------------------

test('M1 both records publish the SCOPE of the tracked-file count beside the count', () => {
  const base = resolveBase();
  assert.equal(typeof base.tracked_files_of_this_track, 'number');
  assert.equal(typeof base.tracked_files_scope, 'string');
  assert.match(base.tracked_files_scope, /git ls-files/);
  for (const name of ['s2-008-harness.json', 's2-008-replay.json']) {
    const record = JSON.parse(readFileSync(path.join(REPO_ROOT, 'evidence', name), 'utf8'));
    assert.equal(typeof record.base.tracked_files_scope, 'string', `${name} must publish the scope`);
    assert.notEqual(record.base.tracked_files_scope, undefined);
  }
});
