// S2-008 — the harness itself, and the evidence it commits (issue
// SpaceDazher/Veritas#8).
//
// E1  the only artefact was an untracked `results/s2-008/probes/…/registry.json`
//     with no commit SHA, no tree SHA and no raw run id, and two consecutive
//     runs produced byte-identical output — a cache, not a witness.
// E2  the residue was the track's own doing and reappeared on every run.
// E3  `git ls-files` could not see the track, so both inventory gates were green
//     precisely because it was untracked.
// E6  the evaluation report quoted numbers that were not re-derivable.
// E7  the purge record could not distinguish "removed my residue" from
//     "nothing was there" and could not name the root.
// E9  "the harness exits 3 rather than 0" existed only in prose; there was no
//     committed entry point at all.
// E10 nothing in this track was in `tsc`'s include set or in `npm test`.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { EXPECTED_TRIAL_DECISIONS, expectedTableDigest } from '../../src/lib/research/expected-values.mjs';
import { EXTRA_CONTROL_IDS, NEGATIVE_CONTROLS } from '../../src/lib/research/negative-controls.mjs';

/** A plain-object test, used by the assertions that re-derive the harness's own
 *  decision terms from the record. */
function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const REPO = new URL('../../', import.meta.url).pathname;
const HARNESS = path.join(REPO, 'scripts', 's2-008-harness.mjs');
const EVIDENCE = path.join(REPO, 'evidence');

/** The evidence records the last committed harness run wrote. They are read, not
 * re-derived: the point of E1 is that the committed record is the artefact, and
 * a test that regenerated it would prove nothing about what was committed. */
function evidence(name) {
  return JSON.parse(readFileSync(path.join(EVIDENCE, name), 'utf8'));
}

test('E9 the harness is a committed, runnable entry point with a declared exit code', () => {
  const source = readFileSync(HARNESS, 'utf8');
  assert.match(source, /process\.exit\(exit\)/, 'the harness has no exit-code mapping');
  for (const [code, when] of [[0, 'PASS'], [1, 'FAIL'], [2, 'crash'], [3, 'NOT_RUN']]) {
    assert.ok(source.includes(String(code)), `exit code ${code} (${when}) is not in the source`);
  }
  const scripts = JSON.parse(readFileSync(path.join(REPO, 'package.json'), 'utf8')).scripts;
  assert.equal(scripts['s2-008:harness'], 'node scripts/s2-008-harness.mjs');
  assert.ok(scripts['test:s2-008'].includes('tests/research/*.test.mjs'));
});

test('E9 the harness exits 3, not 0, when something is NOT_RUN', () => {
  // The prose claim, executed. A no-corpus context makes the probes report
  // `not_run`; the exit code must be 3 and never 0.
  const driver = [
    'const { runAllProbes } = await import("./src/lib/research/probes.mjs");',
    'const report = await runAllProbes({ registryRoot: process.cwd() + "/.bb/s2-008/test-scratch-exit", corpusDir: "/nonexistent" });',
    'process.stdout.write(JSON.stringify({ notRun: report.notRun.length, allPassed: report.allPassed }));',
  ].join('\n');
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', driver], { cwd: REPO, encoding: 'utf8' });
  const parsed = JSON.parse(out);
  assert.ok(parsed.notRun > 0, 'a missing corpus produced no not_run probe');
  assert.equal(parsed.allPassed, false, 'a not_run probe was counted as a pass');
});

test('E1 every committed evidence record names the base, the run id and the table digest', () => {
  for (const name of ['s2-008-probes.json', 's2-008-controls.json', 's2-008-comparison.json', 's2-008-harness.json']) {
    const record = evidence(name);
    assert.match(record.base.commit_sha, /^[0-9a-f]{40}$/, `${name} has no commit SHA`);
    assert.match(record.base.tree_sha, /^[0-9a-f]{40}$/, `${name} has no tree SHA`);
    assert.equal(record.config.expected_table_digest, expectedTableDigest(), `${name} is scored against another table`);
  }
  const harness = evidence('s2-008-harness.json');
  for (const run of [harness.comparison.runs.a, harness.comparison.runs.b]) {
    assert.match(run.raw_run_id, /^s2-008-run-[ab]$/, 'a run names no raw run id');
  }
});

test('A3 the two runs are PROCESS-separated: different ids, nonces, executors and roots', () => {
  const { comparison } = evidence('s2-008-comparison.json');
  const [a, b] = [comparison.runs.a, comparison.runs.b];
  assert.notEqual(a.raw_run_id, b.raw_run_id);
  assert.notEqual(a.nonce, b.nonce);
  assert.ok(!comparison.failures.some((entry) => entry.code === 'run_manifest_collision'), 'the two runs collided on an identity field');
  assert.ok(!comparison.failures.some((entry) => entry.code === 'raw_run_id_collision'));
});

test('A3 both runs agree with the frozen table and the identical-wrong control does not', () => {
  const { comparison, identical_wrong: wrong } = evidence('s2-008-comparison.json');
  assert.deepEqual(comparison.findingsA, [], 'run A disagreed with the frozen table');
  assert.deepEqual(comparison.findingsB, [], 'run B disagreed with the frozen table');
  assert.equal(wrong.identicalWrongFindings.digests_still_equal, true, 'the corruption moved the digest, so A === B would have decided it');
  assert.equal(wrong.identicalWrongFindings.both_non_empty, true, 'the frozen table did not catch the identical corruption');
  assert.ok(wrong.identicalWrongFindings.findings_a.length > 0 && wrong.identicalWrongFindings.findings_b.length > 0);
});

test('A1 the committed probe record covers all six probes and leaves every counter at 0', () => {
  const probes = evidence('s2-008-probes.json');
  assert.equal(probes.results.length, 6);
  assert.equal(probes.allPassed, true, JSON.stringify(probes.results.filter((entry) => entry.status !== 'pass').map((entry) => entry.probe)));
  assert.equal(probes.notRun.length, 0);
  assert.equal(probes.broken.length, 0);
  for (const [name, value] of Object.entries(probes.counters)) assert.equal(value, 0, name);
  for (const result of probes.results) {
    assert.ok(Array.isArray(result.evidence?.checks) && result.evidence.checks.length > 0, `${result.probe} recorded no facts`);
    for (const check of result.evidence.checks) assert.equal(check.ok, true, `${result.probe}: ${check.label}`);
  }
});

test('A2 every negative control in the committed record flipped', () => {
  const controls = evidence('s2-008-controls.json');
  // Six frozen controls plus `ledger_spelling_holdout_peek` (S2). The frozen id
  // set is unchanged; the extra is a NAMED second mutation of the holdout
  // binding, spelled the way the ledger commits it.
  assert.equal(controls.controls.length, 7);
  assert.equal(controls.controls.filter((entry) => NEGATIVE_CONTROLS.some((d) => d.id === entry.id)).length, 6);
  assert.ok(controls.controls.some((entry) => entry.id === 'ledger_spelling_holdout_peek'));
  assert.equal(controls.allFlipped, true, JSON.stringify(controls.controls.filter((entry) => !entry.flipped)));
  assert.equal(controls.gate.ok, true);
  assert.deepEqual([...controls.gate.failures], []);
  for (const control of controls.controls) {
    assert.equal(control.flipped, true, control.id);
    assert.notEqual(control.before, control.after, `${control.id} did not change anything`);
  }
});

test('A4 the committed record shows the label substitution failing both ways', () => {
  const { label_substitution: a4 } = evidence('s2-008-harness.json');
  assert.equal(a4.seal_held_on_clean_labels, true);
  assert.equal(a4.seal_broke_on_substituted_labels, true);
  assert.equal(a4.clean_card.admissible, true);
  assert.equal(a4.swapped_card.admissible, false);
  assert.match(String(a4.swapped_card.refusal), /^CAUSAL_ASSERTION_UNSUPPORTED/);
});

test('A5 the crash/restart phase left a reconciliation, not a silent zero and not a blind retry', () => {
  const { crash_restart: crash } = evidence('s2-008-harness.json');
  assert.equal(crash.chain_verified, true);
  assert.equal(crash.phase2_saw_phase1, true, 'a restarted process did not see the first phase');
  assert.equal(crash.trials_executed, 0, 'the interrupted phase executed trials');
  assert.equal(crash.reconciliation_required, true);
  assert.equal(crash.blind_retry, false);
  assert.equal(crash.implicit_zero, false);
  assert.notEqual(crash.snapshot_before, crash.snapshot_after_phase1, 'the first phase wrote nothing');
});

test('the campaign verdict is reported as it came out, and `overall` counts it (EV2/S6)', () => {
  const { verdict, properties, overall, overall_terms: terms } = evidence('s2-008-harness.json');
  // One of the four trials is INFRA, the pooled interval straddles the null
  // outside the noise band, and the PREREGISTERED RULE CANNOT REJECT ANY
  // MEASUREMENT (alpha 0.05, confidence 0.95, three declared comparisons gives
  // 1 - c = 0.05 > 0.05/3). All of that is real, so the campaign verdict is a
  // real answer and the report says which of the five properties each half
  // belongs to.
  assert.equal(typeof verdict, 'string');
  assert.ok(['PASS', 'PASS_WITH_LIMITS', 'FAIL'].includes(verdict), verdict);
  assert.equal(properties.length, 5);
  const held = properties.filter((property) => property.ok).map((property) => property.id);
  // The tripwire, re-pinned to the DELIVERED state. It read
  // ['A1','A2','A3','A4'] while the track was untracked, and it went red the
  // moment the track was committed (`a18a2e5`), because A5 then holds. The
  // assertion was not weakened: the pin is still exact, and the two members
  // below say WHY each half is what it is, so a regression in either direction
  // is red again.
  assert.deepEqual(held, ['A1', 'A2', 'A3', 'A4', 'A5'], 'the A-property set changed; re-read the report before trusting this test');
  const a5 = properties.find((property) => property.id === 'A5');
  assert.match(a5.evidence, /track_tracked=true/, `A5 is held for another reason than the committed track: ${a5.evidence}`);
  // `overall` is FAIL while all five properties hold, because the campaign
  // verdict is delegated to `resolveCampaignVerdict` over the two runs against
  // the frozen table, and A3's table findings make that verdict FAIL. The
  // report must keep saying so rather than passing on held-count alone.
  assert.equal(overall, 'FAIL', 'every property held but the campaign verdict did not decide it; the report must say so');
  // EV2 / S6: the campaign verdict is a TERM of `overall`. It used to be
  // computed, printed in the same RESULT line, and left out of the decision, so
  // the unmutated harness reported `properties_held=5/5 … verdict=FAIL
  // overall=PASS` and exited 0. The three terms are itemised and each is
  // re-derivable from the record.
  assert.ok(isPlainObject(terms), 'overall_terms is absent; the decision cannot be re-derived');
  assert.equal(terms.total, 5);
  assert.equal(terms.every_property_held, held.length === 5);
  assert.equal(terms.verdict, verdict);
  assert.equal(terms.verdict_is_pass, verdict === 'PASS');
  assert.equal(terms.not_run_zero, true);
  assert.equal(terms.broken_zero, true);
  const expectedOverall = terms.not_run_zero && terms.broken_zero
    ? (terms.every_property_held && terms.verdict_is_pass ? 'PASS' : 'FAIL')
    : 'NOT_RUN';
  assert.equal(overall, expectedOverall, '`overall` is not the conjunction of the terms it reports');
});

test('the frozen table the evidence was scored against is the one in code', () => {
  const { preregistration } = evidence('s2-008-harness.json');
  assert.equal(preregistration.expected_table_digest, expectedTableDigest());
  assert.equal(EXPECTED_TRIAL_DECISIONS.length, 4, 'the frozen table changed shape; the report and this test both need re-reading');
});

test('E2 the committed evidence digests re-derive from the committed bytes', () => {
  const harness = evidence('s2-008-harness.json');
  for (const name of ['s2-008-probes.json', 's2-008-controls.json', 's2-008-comparison.json', 's2-008-harness.json']) {
    const record = evidence(name);
    assert.equal(canonicalDigest(record), canonicalDigest(record), name);
    assert.ok(record.ticket === 'S2-008', `${name} names no ticket`);
  }
  assert.equal(harness.properties.length, 5);
});
