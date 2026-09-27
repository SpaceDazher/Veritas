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

import { createHash } from 'node:crypto';

import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import * as expectedValues from '../../src/lib/research/expected-values.mjs';
import { EXPECTED_TRIAL_DECISIONS, expectedTableDigest } from '../../src/lib/research/expected-values.mjs';
import { classifyCurrentReplay } from '../../scripts/verify-s2-008.mjs';
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

test('the campaign decision is a recorded OUTCOME and `overall` gates on AGREEMENT with the frozen table (R-C)', () => {
  const { verdict, properties, overall, overall_terms: terms, ledger_shape: shape } = evidence('s2-008-harness.json');
  // One of the four trials is INFRA and the pooled interval of the other three
  // (18/24) straddles the null outside the 0.02 noise band, so the campaign
  // answer is UNRESOLVED at the DERIVED confidence `1 - alpha/m = 1 - 0.05/3`
  // (the frozen rule is self-consistent: `1 - c <= alpha/m`; the pre-repair
  // published 0.95 made `1 - c = 0.05 > 0.016667` and the rule could not reject
  // anything). UNRESOLVED is an ANSWER. R-C therefore makes the gate green on
  // AGREEMENT with the frozen expectation, never on ALLOW, and keeps the
  // campaign verdict in the record as the honest outcome beside it.
  assert.equal(typeof verdict, 'string');
  assert.ok(['PASS', 'PASS_WITH_LIMITS', 'FAIL'].includes(verdict), verdict);
  assert.equal(verdict, 'FAIL', 'the campaign verdict is still FAIL — the INFRA row is a VIOLATION and the pooled interval is UNRESOLVED — and it must be RECORDED, not hidden');
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
  // `overall` is PASS while the campaign verdict is FAIL: the five properties
  // hold, the comparator's decision is the decision the frozen table declares,
  // the ledger shape matches, every control flipped, and nothing was NOT_RUN
  // or BROKEN. A NULL/UNMET campaign is an ANSWER, recorded as such, and the
  // gate is green on AGREEMENT with it.
  assert.equal(overall, 'PASS', 'the properties hold and the decision agrees with the frozen table; the gate must be green on agreement, not on ALLOW');
  // R-C: the terms `overall` is the conjunction of, each itemised and each
  // re-derivable from the record. `verdict_is_pass` is GONE: with eight
  // synthetic cases the honest campaign answer is a null, and requiring ALLOW
  // was unsatisfiable without tuning the fixtures until a fabricated effect
  // looked legitimate. The verdict stays a REPORTED member, never a term.
  assert.ok(isPlainObject(terms), 'overall_terms is absent; the decision cannot be re-derived');
  assert.equal(terms.total, 5);
  assert.equal(terms.every_property_held, held.length === 5);
  assert.equal('verdict_is_pass' in terms, false, 'verdict_is_pass is a gate term again; R-C removes it at every coupled site');
  assert.equal(terms.verdict, verdict, 'the verdict is reported next to the decision, not counted by it');
  assert.equal(terms.expected_campaign_decision, 'UNRESOLVED');
  assert.equal(terms.observed_campaign_decision, 'UNRESOLVED');
  assert.equal(terms.decision_agrees_with_table, true);
  assert.deepEqual([...(terms.campaign_findings ?? [])], [], 'the honest campaign decision diverges from the frozen expectation');
  assert.equal(terms.controls_all_flipped, true);
  assert.equal(terms.ledger_shape_matches_table, true);
  assert.equal(terms.not_run_zero, true);
  assert.equal(terms.broken_zero, true);
  const expectedOverall = terms.not_run_zero && terms.broken_zero
    ? (terms.every_property_held
      && terms.decision_agrees_with_table
      && terms.controls_all_flipped
      && terms.ledger_shape_matches_table ? 'PASS' : 'FAIL')
    : 'NOT_RUN';
  assert.equal(overall, expectedOverall, '`overall` is not the conjunction of the terms it reports');
  // The ledger-shape term is a MEASUREMENT over a real journal, not a default.
  // The harness's own run ledger holds the four frozen kinds at the frozen
  // counts, read back with `readJournal`; an absent journal reads `false` with
  // the observed counts named.
  assert.ok(isPlainObject(shape), 'the record carries no ledger-shape measurement');
  for (const letter of ['a', 'b']) {
    assert.deepEqual(shape[letter] ?? [], [], `run ${letter}: the journal diverges from the frozen ledger shape`);
    assert.ok(Number.isInteger(shape.rows?.[letter]), `run ${letter}: the journal row count was not measured`);
  }
  assert.deepEqual(shape.observed_record_kinds, shape.expected_record_kinds, 'the observed journal is not the frozen shape');
  assert.equal(shape.chain_verified, true);
});

test('R-C a fabricated POSITIVE campaign against the frozen non-positive expectation is refused (the anti-goal)', () => {
  // THE ANTI-GOAL, EXECUTED. The gate must not be satisfiable by making a
  // fabricated positive look legitimate: a replay record that claims every
  // term is true, claims `overall: PASS`, exits 0 and carries a FRESH
  // timestamp — and whose campaign decision is `POSITIVE` against the frozen
  // `UNRESOLVED` expectation — is refused. Every refusal path that is not the
  // campaign one is neutralised first, so the refusal can only come from the
  // campaign decision.
  const expectation = expectedValues.EXPECTED_CAMPAIGN ?? null;
  assert.ok(isPlainObject(expectation), 'EXPECTED_CAMPAIGN is absent from src/lib/research/expected-values.mjs; there is no frozen campaign decision to agree with');
  assert.notEqual(expectation.decision, 'POSITIVE', 'the frozen campaign expectation is a POSITIVE; the anti-goal case needs a non-positive one to fabricate against');

  // The bytes the aggregator hashes are the ones on disk, so the record under
  // test is the committed one with the members a forger would set. It is built
  // to satisfy EVERY term the pre-R-C gate read — `verdict_is_pass: true`
  // included — so the only thing left that can catch it is the campaign
  // decision, and a red result here cannot be a side effect of some other
  // refusal path.
  const bytes = readFileSync(path.join(EVIDENCE, 's2-008-replay.json'));
  const onDisk = createHash('sha256').update(bytes).digest('hex');
  const executed = { exitCode: 0, stdout: `REPLAY_EVIDENCE_SHA256 ${onDisk}\n` };
  const real = JSON.parse(bytes.toString('utf8'));
  const forged = structuredClone(real);
  forged.verdict = 'PASS';
  forged.overall = 'PASS';
  forged.exitCode = 0;
  forged.ledger_shape_ok = true;
  forged.observed_campaign_decision = 'POSITIVE';
  forged.expected_campaign_decision = 'UNRESOLVED';
  forged.decision_agrees_with_table = true;
  forged.properties = forged.properties.map((property) => ({ ...property, ok: true, status: 'HELD' }));
  forged.overall_terms = {
    every_property_held: true,
    held: forged.properties.length,
    total: forged.properties.length,
    verdict: 'PASS',
    verdict_is_pass: true,
    expected_campaign_decision: 'UNRESOLVED',
    observed_campaign_decision: 'POSITIVE',
    decision_agrees_with_table: true,
    campaign_findings: [],
    controls_all_flipped: true,
    ledger_shape_matches_table: true,
    ledger_shape_findings: 0,
    not_run_zero: true,
  };
  const classified = classifyCurrentReplay(executed, forged, {
    headTreeSha: real.base.tree_sha,
    observedAtIso: real.freshness.finished_at,
  });
  assert.equal(classified.gate.status, 'FAIL', 'a fabricated POSITIVE campaign was accepted; the gate is green-washable');
  assert.match(String(classified.gate.reason), /CAMPAIGN_DECISION_DIVERGES_FROM_FROZEN_TABLE/, classified.gate.reason);
});

test('R-C the committed replay record is accepted on AGREEMENT, with its FAIL verdict recorded (not on ALLOW)', () => {
  // The success case, and the one that must stay true: a record whose campaign
  // decision is the decision the frozen table declares is ACCEPTED while its
  // campaign verdict is FAIL. This is what "green on agreement" means, and it
  // is pinned against the committed bytes.
  const bytes = readFileSync(path.join(EVIDENCE, 's2-008-replay.json'));
  const onDisk = createHash('sha256').update(bytes).digest('hex');
  const real = JSON.parse(bytes.toString('utf8'));
  const classified = classifyCurrentReplay({ exitCode: real.exitCode, stdout: `REPLAY_EVIDENCE_SHA256 ${onDisk}\n` }, structuredClone(real), {
    headTreeSha: real.base.tree_sha,
    observedAtIso: real.freshness.finished_at,
  });
  if (classified.gate.status !== 'PASS') {
    assert.fail(`the committed replay record is not green on agreement (${String(classified.gate.reason)}). If evidence/s2-008-replay.json is the PRE-repair record, regenerate it: run 'npm run verify:s2-008-replay' BEFORE 'npm run test:research', because the test reads the committed bytes and does not re-derive them`);
  }
  assert.equal(real.verdict, 'FAIL', 'the campaign verdict is the honest answer and is recorded beside the decision');
  assert.equal('verdict_is_pass' in real.overall_terms, false, 'the replay still counts verdict_is_pass as a gate term');
  assert.equal(real.overall_terms.decision_agrees_with_table, true);
  assert.equal(real.overall_terms.observed_campaign_decision, 'UNRESOLVED');
  assert.equal(real.overall_terms.expected_campaign_decision, 'UNRESOLVED');
  assert.equal(real.overall_terms.controls_all_flipped, true);
  assert.equal(real.overall_terms.ledger_shape_matches_table, true);
  assert.equal(real.overall_terms.every_property_held, true);
});

test('the frozen table the evidence was scored against is the one in code', () => {
  const { preregistration } = evidence('s2-008-harness.json');
  assert.equal(preregistration.expected_table_digest, expectedTableDigest());
  assert.equal(EXPECTED_TRIAL_DECISIONS.length, 4, 'the frozen table changed shape; the report and this test both need re-reading');
});

test('R-C the frozen campaign expectation is the one the comparator answers with', () => {
  // The gate compares the comparator's decision with a FROZEN expectation, so
  // the expectation has to exist, has to be non-positive for this corpus, and
  // has to be bound by the table digest the evidence records carry.
  const expectation = expectedValues.EXPECTED_CAMPAIGN ?? null;
  assert.ok(isPlainObject(expectation), 'EXPECTED_CAMPAIGN is absent; the gate has nothing to agree with');
  assert.equal(expectation.decision, 'UNRESOLVED', 'the frozen campaign decision moved; re-derive it with decisionFromInterval before editing it');
  assert.equal(expectation.decisionStatus, 'NOT_MEASURED');
  const { config } = evidence('s2-008-harness.json');
  assert.equal(config.expected_table_digest, expectedTableDigest(), 'the campaign expectation is not bound by the digest the record carries');
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
