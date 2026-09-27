// S2-008 REPAIR — the NEW GATE SEMANTICS (R-C) and the failure modes this
// repair could introduce (issue SpaceDazher/Veritas#8, repair run
// wfr_38b31d45-48e0-443e-9a9b-b24f86319847).
//
// WHY THIS FILE EXISTS SEPARATELY FROM `harness.test.mjs`
// `harness.test.mjs` pins the EVIDENCE: that a committed record names its base,
// its run ids and the table it was scored against, and that the five
// acceptance properties hold. It reads the committed bytes and re-derives the
// harness's own `overall` from the terms that record reports. This file pins
// the DECISION: what may make the gate green, what may never make it green,
// and what a fabricated number does to it. R-C changed the pass condition from
// `verdict_is_pass` to a property-and-expectation conjunction, which is a change
// to the gate and not to the evidence — so its tests are its own.
//
// WHAT THE GATE IS NOW (R-C, frozen by the owner)
//   PASS iff EVERY acceptance property held
//     AND the comparator's decision equals the decision the FROZEN
//         expected-value table declares
//     AND the ledger shape matches the table
//     AND every negative control flipped its verdict
//     AND not_run == 0 AND broken == 0.
//   `verdict_is_pass` is REMOVED as a term. A campaign that answers NULL or
//   UNRESOLVED is an ANSWER, recorded as such, not a gate failure: the honest
//   answer on eight synthetic cases is UNRESOLVED, the frozen expectation is
//   UNRESOLVED, and the gate is green on AGREEMENT WITH THAT ANSWER.
//
// THE ANTI-GOAL, AS A TEST
// This repair must not turn the stage green by moving the fixtures' goalposts
// until a fabricated POSITIVE looks legitimate. So the file is built around
// three twins of that failure: a fabricated campaign decision must be a table
// finding and must FAIL; a run bound to a HAND-EDITED table must be refused
// whatever the record claims; and a run that HID an unresolved trial must be
// refused even though the campaign answer is now allowed to be UNRESOLVED.
// If any of the three is ever green, the stage is green for a lie.
//
// WHAT IS RED ON PURPOSE, AND WHY
// The cases below are written against the INTENDED behaviour, so some are red
// until the parallel workers land, and the comment on each names what has to
// arrive. Named here once, as a table:
//   * `EXPECTED_CAMPAIGN` / `expectedCampaignIssues`   — R-B/R-C, the frozen
//     campaign expectation (W2, `src/lib/research/expected-values.mjs`).
//   * `never_rejects === false` and the derived confidence — R-A, the corrected
//     frozen rule (W1, `tests/research/fixtures/fixture-preregistration.mjs`).
//   * the gate accepting a FAIL verdict on agreement, and the committed record
//     carrying the new terms — R-C (W3, `scripts/verify-s2-008.mjs`,
//     `scripts/s2-008-replay.mjs`, then the regenerated evidence).
// A red case here is the ticket's own red state, not a defect in the test.
//
// HOW THE PLANNED EXPORTS ARE READ, AND WHY IT MATTERS
// `expected-values.mjs` is imported TWICE: once by name for the members that
// exist today, once as a NAMESPACE for the members this repair adds. A named
// import of a member that does not exist yet is a LINK-TIME SyntaxError, and
// one missing export would take the whole file down and hide every other case
// behind a single stack trace. A namespace import cannot do that: the missing
// member reads as `undefined` and the case that needs it fails with a message
// that says which arrival it is waiting for.
//
// THE SINGLE DEFINITION POINT OF THE NEW CONDITION
// `campaignDecisionAgreement` in scripts/s2-008-replay.mjs is where "the
// decision the comparator made equals the decision the frozen table declares"
// is DEFINED, and the replay, the harness and the aggregator all call it — so
// "four coupled sites cannot drift apart" is a fact and not a promise. Every
// campaign-agreement case below goes through it, and the two that name
// `expectedValues.EXPECTED_CAMPAIGN` / `expectedValues.expectedCampaignIssues`
// are the TABLE's own copy of the same condition
// (`src/lib/research/expected-values.mjs`, R-B/R-C).
//
// OFFLINE AND DETERMINISTIC
// No network, no LLM, no credential, no spawn, no clock read on a decision
// path. The freshness comparison is a pure string equality against a
// caller-supplied tree sha, so the head tree here is a LITERAL and the test
// never shells out to git. The ONE disk read is the committed replay record,
// because `classifyCurrentReplay` re-hashes the record on disk itself: a test
// that could not produce matching bytes could not reach a single path past that
// check, and every case below would be vacuous.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { wilsonInterval } from '../../src/lib/sloqual/statistics.mjs';
import { decisionFromInterval, latencyRecorded, resolveCampaignVerdict, resolveTrialVerdict, ruleFeasibility } from '../../src/lib/research/comparator.mjs';
import { classifyCurrentReplay, crossRecordAgreement, freshnessVerdict } from '../../scripts/verify-s2-008.mjs';
// The members THIS repair adds to the aggregator are read through a NAMESPACE,
// for the reason this file's header gives for `expected-values.mjs`: a named
// import of a member that does not exist is a LINK-TIME SyntaxError that takes
// the whole file down, so one missing export would hide every other case behind
// a single stack trace. A namespace cannot do that — the missing member reads as
// `undefined` and the case that needs it fails with a message naming the arrival
// it is waiting for.
import * as aggregator from '../../scripts/verify-s2-008.mjs';
import { campaignDecisionAgreement } from '../../scripts/s2-008-replay.mjs';
import * as expectedValues from '../../src/lib/research/expected-values.mjs';
import {
  EXPECTED_CONTROLS, EXPECTED_COUNTERS, EXPECTED_LEDGER_SHAPE, EXPECTED_METRIC, EXPECTED_TRIAL_DECISIONS,
  assertTableFrozen, expectedTableDigest, expectedValueIssues,
} from '../../src/lib/research/expected-values.mjs';
import { buildRunBoundToTable, FIXTURE_TRIALS, POOLED_COUNTS, PREREGISTRATION } from './fixtures/fixture-measurement-set.mjs';
import { PREREGISTERED_TRIALS } from './fixtures/fixture-preregistration.mjs';

const REPO = new URL('../../', import.meta.url).pathname;
const CORPUS_DIR = path.join(REPO, 'evidence', 's2-008', 'corpus');
const REPLAY_RECORD = path.join(REPO, 'evidence', 's2-008-replay.json');

/** A frozen instant, so nothing in this file reads the wall clock. */
const RUN_STARTED_AT = '2026-03-01T12:00:00.000Z';
const RUN_FINISHED_AT = '2026-03-01T12:00:05.000Z';
const GATE_OBSERVED_AT = '2026-03-01T12:00:06.000Z';
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

/** The "head tree" and the commit the aggregator compares against. LITERALS,
 *  not `git rev-parse`: freshness is a pure comparison against a string the
 *  caller supplies, and a literal keeps the case hermetic and host-free. The
 *  stale case below is one character of this pair away. */
const HEAD_TREE_SHA = 'a'.repeat(40);
const HEAD_COMMIT_SHA = 'b'.repeat(40);

/** The committed replay record's bytes, as the aggregator re-hashes them. */
function committedReplayBytes() {
  assert.ok(existsSync(REPLAY_RECORD), `evidence/s2-008-replay.json is absent; every gate case in this file is unreachable without it (${REPLAY_RECORD})`);
  return readFileSync(REPLAY_RECORD);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * A replay record in the POST-REPAIR shape: a campaign verdict of FAIL whose
 * decision AGREES with the frozen table, the five terms R-C names all true, no
 * `verdict_is_pass` member. This is the shape R-C defines as green, and the
 * shape the aggregator must therefore accept.
 */
function replayRecord({ top = {}, terms, properties } = {}) {
  const defaultTerms = {
    every_property_held: true,
    held: 2,
    total: 2,
    verdict: 'FAIL',
    ledger_shape_matches_table: true,
    ledger_shape_findings: 0,
    decision_agrees_with_table: true,
    controls_all_flipped: true,
    not_run_zero: true,
    // F1: the sixth term. A record the aggregator is asked to accept has to
    // PUBLISH it, because a member only the child evaluates is a member the
    // aggregator cannot re-read — and a record that does not publish it is
    // refused rather than assumed green.
    comparator_failures_match_frozen_expectation: true,
    unexpected_comparator_findings: [],
  };
  const observed = derivedCampaignDecision().decision;
  return {
    ticket: 'S2-008',
    kind: 'REPLAY',
    version: 's2-008-replay-v1',
    base: { commit_sha: HEAD_COMMIT_SHA, tree_sha: HEAD_TREE_SHA },
    freshness: { observed_at: RUN_STARTED_AT, finished_at: RUN_FINISHED_AT, decides: false },
    separation: { ok: true, raw_run_id: { a: 's2-008-run-a', b: 's2-008-run-b' } },
    evidence: { a: { digest: '1'.repeat(64) }, b: { digest: '2'.repeat(64) } },
    overall: 'PASS',
    verdict: 'FAIL',
    // A PASS record has to CARRY the exit code it will exit with (EV5), or the
    // freshness rule refuses it at `exit-code-absent`. The record below is the
    // shape R-C defines as green, so it carries 0 — and the case that checks a
    // NOT_RUN exit overrides this member with 3 and expects NOT_RUN back.
    exitCode: 0,
    ledger_shape_ok: true,
    // The decision the comparator made, DERIVED from the frozen measurements
    // and not typed: a record that carries a decision nothing derived is the
    // anti-goal in record form, and the aggregator must read the in-code
    // expectation rather than this member.
    observed_campaign_decision: observed,
    comparison: { runs: { a: { decision: observed } } },
    overall_terms: terms === undefined ? defaultTerms : { ...defaultTerms, ...terms },
    properties: properties === undefined ? [{ id: 'A3', status: 'HELD' }, { id: 'A5', status: 'HELD' }] : properties,
    ...top,
  };
}

/** One invocation of the gate: a synthetic child result plus the record the
 *  aggregator is asked to classify. `digest` defaults to the digest of the
 *  bytes the aggregator will re-hash, i.e. "this invocation wrote exactly
 *  those bytes". */
function gateOf(record, { digest = sha256(committedReplayBytes()), exitCode = 0, headTreeSha = HEAD_TREE_SHA, observedAtIso = GATE_OBSERVED_AT, windowMs = WEEK_MS } = {}) {
  return classifyCurrentReplay(
    { exitCode, stdout: `RESULT properties_held=2/2 not_run=0 verdict=${String(record.verdict)} overall=${String(record.overall)}\nREPLAY_EVIDENCE_SHA256 ${digest}`, stderr: '' },
    record,
    { headTreeSha, observedAtIso, windowMs },
  );
}

/**
 * THE campaign decision, derived from the frozen measurements by the frozen
 * rule — never read out of a run and never typed. Pooled over the measured
 * trials' own counts (18 agreements over 24 cases) at the PREREGISTERED
 * confidence, through the same two functions the engine uses: `wilsonInterval`
 * from the frozen statistics module and `decisionFromInterval` from the
 * comparator.
 * Two details of the rule are the engine's and not this file's, and both are
 * quoted from `scoreMetric` in src/lib/research/comparator.mjs:1690-1700 so
 * the re-derivation below is the SAME question the engine asks: the null value
 * is the frozen baseline's own `value` (scored against zero it is a different
 * question, and `frozen_baseline` is an object, not a number), and the campaign
 * rate is declared the POOLED AGGREGATE of the declared family rather than a
 * fourth comparison of its own.
 * @returns {{decision: string, reason: string|null, lower: number, upper: number, confidence: number}}
 */
function derivedCampaignDecision() {
  const multiplicity = PREREGISTRATION.multiplicity_rule;
  const observed = POOLED_COUNTS.successes / POOLED_COUNTS.trials;
  const interval = wilsonInterval({
    successes: POOLED_COUNTS.successes,
    trials: POOLED_COUNTS.trials,
    confidence: PREREGISTRATION.noise_rule.confidence,
  });
  const applied = decisionFromInterval({
    observed,
    lower: interval.lower,
    upper: interval.upper,
    noiseBand: PREREGISTRATION.noise_rule.band,
    rule: {
      alpha: multiplicity.alpha,
      method: multiplicity.method,
      comparisons: multiplicity.declared_comparisons,
      confidence: PREREGISTRATION.noise_rule.confidence,
      null_value: PREREGISTRATION.frozen_baseline.value,
      subject: 'case_agreement_rate',
      subject_is_pooled_aggregate: true,
    },
  });
  return { decision: applied.decision, reason: applied.reason, correction: applied.correction, lower: interval.lower, upper: interval.upper, confidence: interval.confidence };
}

/** The hand-edited table: the frozen one with the FIRST measured row's
 *  expectation rewritten to the answer a run would have to produce to look
 *  legitimate. It is the anti-goal as a VALUE: if a run bound to THIS table
 *  could pass, the table could be tuned to the result. */
function handEditedTable() {
  return {
    EXPECTED_TRIAL_DECISIONS: Object.freeze(EXPECTED_TRIAL_DECISIONS.map((row, index) => (
      index === 0 ? Object.freeze({ ...row, expectedOutcome: 'UNRESOLVED', why: 'rewritten to match what the run derived' }) : row
    ))),
    EXPECTED_CODES: expectedValues.EXPECTED_CODES,
    EXPECTED_COUNTERS,
    EXPECTED_LEDGER_SHAPE,
    EXPECTED_METRIC,
    EXPECTED_CONTROLS,
  };
}

// --- R-C: the campaign answer and the frozen expectation -------------------

test('R-C the campaign answer is DERIVED, and on eight synthetic cases the honest answer is UNRESOLVED', () => {
  // The tripwire, re-derived on every run of this file from the frozen
  // measurements by the frozen rule — never read out of a run and never typed.
  // Eight cases cannot separate 18/24 from the frozen baseline 0.75 at a
  // corrected level, so the interval straddles the null outside the noise band
  // and the campaign is UNRESOLVED. A later edit that makes this POSITIVE has
  // either changed the corpus or the rule, and both need the report re-read —
  // which is what this assertion is for.
  const derived = derivedCampaignDecision();
  assert.equal(derived.decision, 'UNRESOLVED', `pooled ${String(POOLED_COUNTS.successes)}/${String(POOLED_COUNTS.trials)} at confidence ${String(derived.confidence)} over [${String(derived.lower)}, ${String(derived.upper)}] derived ${String(derived.reason)}`);
  assert.equal(derived.reason, 'interval_straddles_null_outside_noise_band', 'the pooled interval no longer straddles the frozen baseline; the campaign became a different question');
  assert.equal(derived.correction, null, 'an interval that does not exclude the null has no correction to report, and reporting one would be a claim about a comparison that was never made');
});

test('R-C the derived answer AGREES with the frozen campaign decision, and a fabricated POSITIVE does NOT', () => {
  // The success case and the anti-goal, one function apart. This is the single
  // definition point all three gates call, so the pair is the gate itself: the
  // honest UNRESOLVED is agreement, the fabricated POSITIVE is a refusal, and
  // nothing in between is permitted.
  const derived = derivedCampaignDecision();
  const agrees = campaignDecisionAgreement({ observed: derived.decision, expected: derived.decision });
  assert.equal(agrees.agrees, true, `the campaign's own answer disagrees with itself: ${JSON.stringify(agrees.findings)}`);
  assert.deepEqual([...agrees.findings], []);
  const fabricated = campaignDecisionAgreement({ observed: 'POSITIVE', expected: derived.decision });
  assert.equal(fabricated.agrees, false, 'a fabricated POSITIVE was read as agreement with the frozen expectation');
  assert.ok(fabricated.findings.length > 0, 'a fabricated POSITIVE produced no finding');
  assert.equal(fabricated.findings[0].code, 'CAMPAIGN_DECISION_DIVERGES_FROM_FROZEN_TABLE', fabricated.findings[0].code);
  assert.equal(fabricated.findings[0].expected, derived.decision);
  assert.equal(fabricated.findings[0].observed, 'POSITIVE');
  // Two refusals that keep the condition fail-closed at its own edges: a
  // campaign that decided NOTHING and an expectation that does not exist. The
  // second is what the gate reports on this very tree while R-B's
  // `EXPECTED_CAMPAIGN` is still landing, and a gate with no expectation is
  // not a green gate.
  assert.equal(campaignDecisionAgreement({ observed: null, expected: derived.decision }).agrees, false, 'a campaign that decided nothing was read as agreement');
  assert.equal(campaignDecisionAgreement({ observed: derived.decision, expected: null }).agrees, false, 'an expectation that does not exist was read as agreement');
  assert.equal(campaignDecisionAgreement({ observed: derived.decision, expected: null }).findings[0].code, 'EXPECTED_CAMPAIGN_ABSENT');
});

test('R-C a campaign that diverges from the table is FAIL: never PASS, never PASS_WITH_LIMITS, and never forced to ALLOW', () => {
  // Three fail-closed boundaries in one place, because the repair moved the
  // pass condition and the way a limit downgrades a verdict is exactly what a
  // "softened" repair would touch.
  const fabricated = campaignDecisionAgreement({ observed: 'POSITIVE', expected: derivedCampaignDecision().decision }).findings;
  assert.equal(resolveCampaignVerdict({ failures: fabricated, limits: [], proofStatus: [] }), 'FAIL', 'a campaign that diverged from its table did not fail the campaign verdict');
  // A limit ALONE downgrades to PASS_WITH_LIMITS — that is the comparator's
  // published behaviour, and it is why `verdict_is_pass` was unsatisfiable on
  // this stage: every run emits `latency_observed`. With a finding present the
  // limit changes nothing, or the comparator would be a downgrade with extra
  // steps.
  assert.equal(resolveCampaignVerdict({ failures: [], limits: [{ code: 'latency_observed' }], proofStatus: [] }), 'PASS_WITH_LIMITS', 'a bare limit no longer downgrades; the comparator changed and the report has to say so');
  assert.equal(resolveCampaignVerdict({ failures: fabricated, limits: [{ code: 'latency_observed' }], proofStatus: [] }), 'FAIL', 'a limit downgraded a campaign that diverged from its table');
  // And a `force` cannot overrule a finding: the claim and the resolution
  // disagreeing is itself a refusal.
  assert.throws(
    () => resolveCampaignVerdict({ failures: fabricated, limits: [], proofStatus: [], force: 'ALLOW' }),
    (error) => String(error?.message ?? '').startsWith('SLOQUAL_COMPARATOR_INCONSISTENT'),
    'a campaign that diverged from its table was forced to ALLOW',
  );
});

test('R-C the frozen table DECLARES the campaign answer, and the declaration is bound by the table digest', () => {
  // RED until R-B's `EXPECTED_CAMPAIGN` lands in
  // src/lib/research/expected-values.mjs. The expectation has to be a MEMBER of
  // the frozen table rather than a constant in a script: a script constant is
  // edited in the same commit as the run it scores, and nothing binds it to
  // what the rule derives.
  const derived = derivedCampaignDecision();
  assert.ok(typeof expectedValues.EXPECTED_CAMPAIGN === 'object' && expectedValues.EXPECTED_CAMPAIGN !== null, 'src/lib/research/expected-values.mjs must export the frozen EXPECTED_CAMPAIGN (R-B: the campaign expectation is a table member, not a constant in a script)');
  assert.equal(expectedValues.EXPECTED_CAMPAIGN.decision, derived.decision, 'the frozen campaign expectation is not the decision the frozen rule derives from the frozen measurements');
  assert.ok(Object.isFrozen(expectedValues.EXPECTED_CAMPAIGN), 'EXPECTED_CAMPAIGN is not frozen');
  // The declared status is a real member, not a placeholder: a campaign
  // decision is a POOLED answer, so it is not itself a per-trial measurement.
  assert.ok(typeof expectedValues.EXPECTED_CAMPAIGN.decisionStatus === 'string' && expectedValues.EXPECTED_CAMPAIGN.decisionStatus !== '', 'EXPECTED_CAMPAIGN declares no decision status');
});

test('R-C a fabricated POSITIVE is a table FINDING in the frozen table, not only in the gate', () => {
  // RED until R-B's `expectedCampaignIssues` lands in the same module. The gate
  // refuses a fabricated campaign; the TABLE has to name it, so a run is
  // scored against it the way a per-trial divergence is, and the finding is
  // reachable from any caller of the table rather than only from one gate.
  assert.equal(typeof expectedValues.expectedCampaignIssues, 'function', 'src/lib/research/expected-values.mjs must export expectedCampaignIssues({decision, decisionStatus}) (R-C)');
  const findings = expectedValues.expectedCampaignIssues({ decision: 'POSITIVE', decisionStatus: 'NOT_MEASURED' });
  assert.ok(findings.length > 0, 'a fabricated POSITIVE produced no finding against the frozen campaign expectation');
  for (const entry of findings) {
    assert.equal(entry.code, 'CAMPAIGN_DECISION_DIVERGES_FROM_TABLE', entry.code);
  }
  const decisionFinding = findings.find((entry) => entry.field === 'decision');
  assert.ok(decisionFinding !== undefined, `no finding named the decision member: ${JSON.stringify(findings)}`);
  assert.equal(decisionFinding.expected, expectedValues.EXPECTED_CAMPAIGN.decision);
  assert.equal(decisionFinding.observed, 'POSITIVE');
  // And the honest answer produces none: agreement is the success case, and a
  // finding for it would make the green gate unreachable.
  const honest = expectedValues.expectedCampaignIssues({ decision: derivedCampaignDecision().decision, decisionStatus: expectedValues.EXPECTED_CAMPAIGN.decisionStatus });
  assert.deepEqual([...honest], [], 'the derived campaign answer disagrees with the frozen expectation it was derived from');
});

// --- R-C: the gate itself, through the aggregator that judges it -----------

test('R-C the gate is green on AGREEMENT: a FAIL campaign verdict whose decision matches the table is accepted', () => {
  // The gate is green on AGREEMENT: a campaign verdict of FAIL whose decision
  // MATCHES the frozen table is accepted. The reason it was a fake green
  // BEFORE the repair is visible in the record: the pass condition demanded
  // ALLOW, which eight synthetic cases cannot produce, so the stage was red for
  // a reason that had nothing to do with the mechanics.
  //
  // RED while R-B's `EXPECTED_CAMPAIGN` is still landing: the aggregator
  // refuses the record with `EXPECTED_CAMPAIGN_ABSENT`, which is correct and is
  // exactly what the case above pins.
  const record = replayRecord();
  assert.equal(record.verdict, 'FAIL', 'this case is only meaningful with a non-ALLOW campaign verdict');
  assert.equal('verdict_is_pass' in record.overall_terms, false, 'a post-repair record carries no verdict_is_pass member');
  const { gate } = gateOf(record);
  assert.equal(gate.status, 'PASS', `a campaign that agrees with the frozen table was refused: ${String(gate.reason)}`);
  assert.equal(gate.fresh, true);
});

test('R-C the anti-goal twin: a record whose decision diverges from the table is refused — even when it CLAIMS to agree', () => {
  // Two records that differ from the accepted one only in the decision, and
  // neither may ever be green. The pair is the test: a gate that accepts the
  // agreeing record and these two cannot tell an honest UNRESOLVED from a
  // fabricated POSITIVE, and a gate that refuses all three is the old
  // `verdict_is_pass` in a new coat.
  //
  // The second one is the sharper half: its `overall_terms` say the decision
  // AGREES, which is a lie, and the only way to catch it is for the gate to
  // read the IN-CODE expectation and compare the record's own decision against
  // it. A gate that trusts `decision_agrees_with_table` is a gate that
  // believes whatever the record says about itself.
  const honest = replayRecord({ terms: { decision_agrees_with_table: false } });
  const lying = replayRecord({ top: { observed_campaign_decision: 'POSITIVE', comparison: { runs: { a: { decision: 'POSITIVE' } } } } });
  for (const [why, record] of [['a campaign that diverges from the frozen table', honest], ['a record that claims agreement while reporting a fabricated POSITIVE', lying]]) {
    const { gate } = gateOf(record);
    assert.equal(gate.status, 'FAIL', `${why} was accepted`);
    assert.equal(gate.fresh, undefined, `${why} was reported as a freshness problem rather than a decision problem`);
    assert.ok(typeof gate.reason === 'string' && gate.reason.length > 0, 'the refusal named no reason');
  }
  // The lying record really does claim agreement, so the refusal above cannot
  // be an accident of a term that happened to be false.
  assert.equal(lying.overall_terms.decision_agrees_with_table, true, 'the twin does not actually lie, so it tests nothing');
  assert.notEqual(lying.observed_campaign_decision, expectedValues.EXPECTED_CAMPAIGN?.decision ?? 'UNRESOLVED', 'the twin is not actually a fabrication against the expectation');
});

test('R-C a control that did not flip, or a property that did not hold, is refused on the new term set', () => {
  // The three terms that carry the weight `verdict_is_pass` used to carry, each
  // refused on its own. This case only BECOMES discriminating once the gate is
  // otherwise green (i.e. once R-B's `EXPECTED_CAMPAIGN` lands): until then
  // every record is refused for the missing expectation and the reason is
  // masked. That dependency is named here rather than left to be discovered
  // when the case quietly stops proving anything.
  for (const [term, why] of [['controls_all_flipped', 'a negative control that did not flip'], ['every_property_held', 'a property that did not hold'], ['ledger_shape_matches_table', 'a ledger shape that does not match the table'], ['not_run_zero', 'a NOT_RUN that was not counted']]) {
    const { gate } = gateOf(replayRecord({ terms: { [term]: false } }));
    assert.equal(gate.status, 'FAIL', `${why} was accepted`);
  }
  // A property the replay owns did not hold is refused on the record's own
  // property list, independently of the terms block.
  const { gate } = gateOf(replayRecord({ properties: [{ id: 'A3', status: 'FAILED' }, { id: 'A5', status: 'HELD' }] }));
  assert.equal(gate.status, 'FAIL', 'a FAILED property was accepted');
});

test('R-C a NOT_RUN exit is not softened into a pass, and a green record written by a failing run is refused', () => {
  // `exit 3` is NOT_RUN everywhere in this track and is never PASS. The second
  // half is the shape of a fake green file: a record that says PASS whose own
  // recorded exit code is not 0.
  const notRun = gateOf(replayRecord({ top: { exitCode: 3 } }), { exitCode: 3 });
  assert.equal(notRun.gate.status, 'NOT_RUN', `exit 3 was mapped to ${String(notRun.gate.status)}`);
  assert.notEqual(notRun.gate.status, 'PASS');
  const greenFromAFailingRun = freshnessVerdict({
    record: replayRecord({ top: { exitCode: 3 } }),
    headTreeSha: HEAD_TREE_SHA,
    observedAtIso: GATE_OBSERVED_AT,
  });
  assert.equal(greenFromAFailingRun.ok, false);
  assert.ok(greenFromAFailingRun.issues.includes('green-with-nonzero-exit'), `a PASS record written by a non-zero exit was not refused: ${greenFromAFailingRun.issues.join(',')}`);
});

test('R-A a stale evidence file is refused: the tree sha must be the tree the gate ran on, and the commit must be named', () => {
  // Two refusals, both pre-repair and both still required after it. A record
  // is evidence about a TREE, so a record whose tree is not the one under the
  // gate is a previous run's answer; and a record that names no commit is
  // unbound, which is what `verify:clean-checkout` and the manifest gates
  // downstream are there to catch.
  //
  // The freshness rule itself, on its own: pure, and independent of every other
  // term the gate reads.
  const staleRecord = replayRecord({ top: { base: { commit_sha: HEAD_COMMIT_SHA, tree_sha: 'c'.repeat(40) } } });
  const staleFreshness = freshnessVerdict({ record: staleRecord, headTreeSha: HEAD_TREE_SHA, observedAtIso: GATE_OBSERVED_AT });
  assert.equal(staleFreshness.ok, false, 'a record from another tree passed the freshness rule');
  assert.ok(staleFreshness.issues.includes('stale-tree-sha'), `the freshness rule did not name the tree: ${staleFreshness.issues.join(',')}`);
  // The same refusal end to end. It is reached only by a record that is
  // otherwise GREEN, because the aggregator judges the decision terms first and
  // the freshness second — so this half is red until the frozen campaign
  // expectation (`EXPECTED_CAMPAIGN`, R-B) lands, and it is the half that proves
  // the aggregator reports staleness AS staleness instead of as a defect.
  const { gate } = gateOf(staleRecord);
  assert.equal(gate.status, 'FAIL');
  assert.equal(gate.stale, true, `a record from another tree was refused for a reason other than staleness (${String(gate.reason)}), so the staleness reporting is untested`);
  assert.match(String(gate.reason), /stale-tree-sha/, gate.reason);
  const unbound = replayRecord({ top: { base: { commit_sha: null, tree_sha: HEAD_TREE_SHA } } });
  const verdict = freshnessVerdict({ record: unbound, headTreeSha: HEAD_TREE_SHA, observedAtIso: GATE_OBSERVED_AT });
  assert.equal(verdict.ok, false);
  assert.ok(verdict.issues.includes('missing-commit-sha'), verdict.issues.join(','));
});

test('a hand-edited evidence file is refused by its bytes, whatever the record inside it claims', () => {
  // The child prints the digest of the exact bytes it wrote and the aggregator
  // re-hashes the file on disk. A record edited afterwards — a verdict changed
  // from FAIL to PASS by hand — cannot be this invocation's evidence, which is
  // the only reason a previous green file can never make a failing run look
  // current. The digest below is the digest of the committed bytes PLUS one
  // byte: what a hand edit looks like from the gate's side.
  const hand = sha256(Buffer.concat([committedReplayBytes(), Buffer.from(' ')]));
  const { gate, evidence } = gateOf(replayRecord(), { digest: hand });
  assert.equal(gate.status, 'FAIL');
  assert.equal(evidence, null, 'a record whose bytes are not the ones the run reported was returned as evidence');
  assert.match(String(gate.reason), /not the one this invocation wrote/, gate.reason);
});

test('R-C the COMMITTED replay record carries the property-and-expectation terms, and no `verdict_is_pass`', () => {
  // The end-to-end pin. It reads the committed bytes, so it is red until the
  // evidence is regenerated by its own script under the new rule — and it is
  // the case that says the whole repair actually happened rather than merely
  // being intended.
  const record = JSON.parse(committedReplayBytes().toString('utf8'));
  const terms = record.overall_terms;
  assert.ok(typeof terms === 'object' && terms !== null, 'the committed replay record has no overall_terms block');
  assert.equal('verdict_is_pass' in terms, false, 'verdict_is_pass is still a term of the committed replay record');
  for (const term of ['every_property_held', 'decision_agrees_with_table', 'controls_all_flipped', 'ledger_shape_matches_table', 'not_run_zero', 'comparator_failures_match_frozen_expectation']) {
    assert.equal(terms[term], true, `overall_terms.${term} is not true in the committed record`);
  }
  // The campaign answer is RECORDED, and it is the honest one: the comparator
  // decided UNRESOLVED and the gate is green on agreeing with the table. The
  // two decisions are in the record side by side, so the agreement is a fact a
  // reader can check rather than a boolean somebody asserted.
  assert.equal(record.verdict, 'FAIL', 'the committed campaign verdict is not the recorded honest answer');
  assert.deepEqual([...(terms.campaign_findings ?? [])], [], 'the committed record carries campaign findings against the frozen expectation');
  assert.equal(terms.expected_campaign_decision, derivedCampaignDecision().decision, 'the committed record was not scored against the decision the frozen rule derives');
  assert.equal(terms.observed_campaign_decision, terms.expected_campaign_decision, 'the committed record claims an agreement its own two members do not show');
  assert.equal(record.comparison.runs.a.decision, derivedCampaignDecision().decision, 'the committed campaign decision is not the one the frozen rule derives');
  assert.equal(terms.verdict, 'FAIL', 'verdict is a REPORTED member and must say what the comparator decided');
  assert.equal(record.overall, 'PASS', 'a replay whose every term holds did not report PASS');
  assert.equal(record.exitCode, 0, 'a PASS replay did not record the exit code it will exit with');
  // And the rule that produced it can reject, so the recorded UNRESOLVED is a
  // measurement and not the arithmetic impossibility R-A removed.
  assert.equal(record.comparison.runs.a.rule_feasibility.never_rejects, false, 'the committed record was produced by a rule that cannot reject anything');
});

// --- R-A / R-B: the table, the seal and the frozen rule -------------------

test('R-A the digest check refuses a hand-edited expected-value table against the SEALED preregistration', () => {
  // The seal is the corpus document: it carries the table digest as it stood
  // before trial one, and `assertTableFrozen` is the check that the table in
  // code is still that table. Three refusals: a hand-edited seal, a seal whose
  // digest was recomputed after an edit to the table it names, and a document
  // with no digest at all (an expectation published after the run is not an
  // expectation).
  const sealed = JSON.parse(readFileSync(path.join(CORPUS_DIR, 'preregistration.json'), 'utf8'));
  assert.equal(assertTableFrozen(sealed), expectedTableDigest(), 'the sealed corpus document does not seal the table in code');
  assert.equal(
    expectedTableDigest(),
    canonicalDigest({
      EXPECTED_TRIAL_DECISIONS,
      EXPECTED_CODES: expectedValues.EXPECTED_CODES,
      EXPECTED_COUNTERS,
      EXPECTED_LEDGER_SHAPE,
      EXPECTED_METRIC,
      EXPECTED_CONTROLS,
      // R-C: the CAMPAIGN declaration is inside the digest, which is what binds
      // it. A campaign expectation edited after the preregistration was sealed
      // is a detectable change, not a silent one — and the digest is still
      // reproducible from the constants, member for member.
      EXPECTED_CAMPAIGN: expectedValues.EXPECTED_CAMPAIGN,
      // F1: the declaration of which comparator failures the honest campaign
      // carries is inside the digest for the same reason — it is a frozen
      // expectation, so editing it after the seal is a detectable change.
      EXPECTED_COMPARATOR_FAILURES: expectedValues.EXPECTED_COMPARATOR_FAILURES,
    }),
    'the table digest is not reproducible from the frozen constants',
  );
  assert.throws(
    () => assertTableFrozen({ ...sealed, expected_table_digest: `${'0'.repeat(64)}` }),
    (error) => String(error?.message ?? '').startsWith('EXPECTED_TABLE_DRIFT'),
    'a preregistration whose sealed table digest is not the table in code was accepted',
  );
  // The table edited and the seal recomputed to match it: `assertTableFrozen`
  // cannot catch that on its own, and the seal is not supposed to be able to.
  // What catches it is that the table is in CODE and a run is scored against
  // the code — which is the next case, and the reason this case is worth
  // stating out loud rather than discovering later.
  assert.notEqual(canonicalDigest(handEditedTable()), expectedTableDigest(), 'a hand-edited table produced the same digest as the frozen one');
  assert.throws(
    () => assertTableFrozen({ ...sealed, expected_table_digest: undefined, table_digest: undefined }),
    (error) => String(error?.message ?? '').startsWith('EXPECTED_TABLE_DIGEST_ABSENT'),
    'a preregistration that carries no table digest was accepted',
  );
});

test('R-C a run bound to a hand-edited table is refused, whatever the record claims about itself', () => {
  // The anti-goal, as a run. This is the "tune the fixture until a fabricated
  // POSITIVE looks legitimate" move, in the only form a run can take: a record
  // that declares the expectation it wants to be scored against. The table is
  // in code, so the declaration is a finding, and a finding fails the gate.
  const forged = buildRunBoundToTable('a', canonicalDigest(handEditedTable()));
  const findings = expectedValueIssues(forged, 'a');
  const mismatch = findings.find((entry) => entry.code === 'TABLE_DIGEST_MISMATCH');
  assert.ok(mismatch !== undefined, `a run bound to a hand-edited table produced no TABLE_DIGEST_MISMATCH finding: ${JSON.stringify(findings)}`);
  assert.equal(mismatch.observed, canonicalDigest(handEditedTable()));
  assert.equal(mismatch.expected, expectedTableDigest());
  assert.equal(resolveCampaignVerdict({ failures: findings, limits: [], proofStatus: [] }), 'FAIL', 'a run bound to a hand-edited table did not fail the campaign verdict');
  // The same run bound to the FROZEN table is not a finding for that reason:
  // the refusal above is about the table, not about the run being dirty.
  assert.equal(expectedValueIssues(buildRunBoundToTable('a', expectedTableDigest()), 'a').some((entry) => entry.code === 'TABLE_DIGEST_MISMATCH'), false);
});

test('R-B a SKIPPED, UNRESOLVED, INFRA_ERROR or NOT_MEASURED trial is still a VIOLATION under the new gate', () => {
  // The comparator was NOT touched by this repair and must not be touched by
  // it: the gate changed what it demands, not what a trial may decide. A
  // campaign answer of UNRESOLVED is allowed; a trial that did not resolve is
  // not.
  const clean = FIXTURE_TRIALS[0];
  assert.equal(resolveTrialVerdict(clean).verdict, 'ALLOW', 'the clean fixture trial is not an ALLOW, so the cases below would prove nothing');
  for (const status of ['SKIPPED', 'UNRESOLVED', 'INFRA_ERROR', 'NOT_MEASURED']) {
    const verdict = resolveTrialVerdict({ ...clean, status });
    assert.equal(verdict.verdict, 'VIOLATION', `a ${status} trial is no longer a VIOLATION`);
    assert.ok(verdict.reasons.includes(`TRIAL_NOT_RESOLVED:${status}`), `${status}: ${verdict.reasons.join(', ')}`);
  }
  // And a run that HID one is a table finding, so the new gate cannot be green
  // on a run that resolved three trials out of four and said nothing.
  const hidden = buildRunBoundToTable('a', expectedTableDigest());
  const before = expectedValueIssues(hidden, 'a');
  const perturbed = JSON.parse(JSON.stringify(hidden));
  perturbed.trials[0].status = 'UNRESOLVED';
  const after = expectedValueIssues(perturbed, 'a');
  const found = after.filter((entry) => entry.code === 'TRIAL_FIELD_DIVERGES_FROM_TABLE' && entry.observed === 'UNRESOLVED');
  assert.ok(found.length > 0, 'hiding an unresolved trial produced no table finding');
  assert.ok(after.length > before.length, 'a run with a trial hidden as UNRESOLVED is not a worse match to the table than the same run without');
  assert.equal(resolveCampaignVerdict({ failures: after, limits: [], proofStatus: [] }), 'FAIL', 'a run that hid an unresolved trial did not fail the campaign verdict');
});

test('R-B the INFRA trial moved out of the measured campaign and out of the multiplicity family, but NOT out of the table', () => {
  // What R-B changed and what it did not. `trl-s2-008-04` is no longer a member
  // of the measured campaign, so it is no longer inside the corrected family —
  // but it is still ENUMERATED, still has a row, and its row still says
  // VIOLATION. Excluded from the family is not dropped.
  const multiplicity = PREREGISTRATION.multiplicity_rule;
  const infra = PREREGISTERED_TRIALS.filter((entry) => entry.designed_outcome === 'INFRA');
  assert.equal(infra.length, 1, 'the fixture no longer has exactly one INFRA trial; re-read the report before trusting this test');
  const infraId = infra[0].trial;
  assert.equal(PREREGISTERED_TRIALS.length, 4, 'the enumerated trial list shrank');
  assert.ok(PREREGISTERED_TRIALS.some((entry) => entry.trial === infraId), 'the INFRA trial was dropped from the preregistered trial list instead of being reconciled');
  assert.equal(multiplicity.declared_comparisons.includes(infraId), false, 'the INFRA trial is back inside the multiplicity family');
  assert.equal(multiplicity.family_size, multiplicity.declared_comparisons.length, 'the declared family size is not the family that was declared');
  assert.equal(EXPECTED_TRIAL_DECISIONS.length, 4, 'the frozen table lost a row');
  const row = EXPECTED_TRIAL_DECISIONS.find((entry) => entry.trial === infraId);
  assert.ok(row !== undefined, 'the INFRA trial has no row of its own any more');
  assert.equal(row.expectedVerdict, 'VIOLATION');
  assert.equal(row.expectedOutcome, 'INFRA');
  assert.equal(row.expectedStatus, 'INFRA_ERROR', 'the INFRA row is now scored as resolved; an infra result is a reconciliation, never a measurement');
});

test('R-A the frozen rule is SELF-CONSISTENT: 1 - confidence <= alpha / family_size, and ruleFeasibility reports never_rejects === false', () => {
  // The red that started all of this. The fixture froze `alpha: 0.05` with
  // `confidence: 0.95` over a family of 3, so 1 - c = 0.05 > 0.05/3 and the
  // rule could never reject anything: the campaign was undecidable by
  // construction, and no measurement could ever have changed that.
  const multiplicity = PREREGISTRATION.multiplicity_rule;
  const alpha = multiplicity.alpha;
  const floor = alpha / multiplicity.family_size;
  const confidence = multiplicity.confidence;
  // DERIVED, never chosen: the published confidence is `1 - alpha / m` of the
  // same literals, so a typed decimal or a rounded one is a defect. The
  // comparison carries the comparator's own relative tolerance, because
  // `1 - (1 - a/m)` and `a/m` differ in the last bit of a double and the
  // comparator's `DECISION_EPSILON` is what makes that not a rejection failure.
  assert.equal(confidence, 1 - alpha / multiplicity.family_size, 'the published confidence is not derived from alpha and the family; derive it in code, do not type or round it');
  assert.equal(PREREGISTRATION.noise_rule.confidence, confidence, 'noise_rule and multiplicity_rule disagree about the confidence, so the run self-reports an interval the rule did not produce');
  assert.ok(1 - confidence <= floor + Math.abs(floor) * 1e-12, `1 - confidence = ${String(1 - confidence)} exceeds alpha/m = ${String(floor)}; the rule can never reject`);
  const feasibility = ruleFeasibility({ alpha, confidence, familySize: multiplicity.family_size });
  assert.equal(feasibility.never_rejects, false, feasibility.note);
  assert.equal(feasibility.feasible, true, feasibility.note);
  assert.equal(feasibility.can_only_answer, 'ANY_OUTCOME', feasibility.note);
  // The SEALED corpus document publishes the same derived rule, so the repair
  // cannot pass in code and stay red in the corpus.
  const sealed = JSON.parse(readFileSync(path.join(CORPUS_DIR, 'preregistration.json'), 'utf8'));
  assert.equal(sealed.multiplicity_rule.confidence, confidence, 'the sealed corpus document still publishes the old confidence; rebuild the corpus');
  assert.equal(sealed.noise_rule.confidence, confidence, 'the sealed corpus document publishes two different confidences');
  assert.equal(ruleFeasibility({ alpha: sealed.multiplicity_rule.alpha, confidence: sealed.multiplicity_rule.confidence, familySize: sealed.multiplicity_rule.family_size }).never_rejects, false, 'the rule as SEALED can never reject anything');
});

// --- determinism: same base, same answer, whatever the wall clock says -----

test('the same gate, evaluated twice on the same base, decides the same thing', () => {
  // No Date.now() and no Math.random() on a decision path, checked as a
  // BEHAVIOUR rather than as a grep: the same inputs are put through the same
  // exported functions twice and the answers must be identical, member for
  // member. A gate that sampled anything would differ on the second call.
  const first = gateOf(replayRecord());
  const second = gateOf(replayRecord());
  assert.deepEqual(second.gate, first.gate);
  assert.deepEqual(second.evidence, first.evidence);
  assert.equal(second.gate.status, first.gate.status);
  assert.equal(expectedTableDigest(), expectedTableDigest(), 'the frozen table digest is not a function of the table');
  assert.deepEqual(ruleFeasibility({ alpha: PREREGISTRATION.multiplicity_rule.alpha, confidence: PREREGISTRATION.multiplicity_rule.confidence, familySize: PREREGISTRATION.multiplicity_rule.family_size }), ruleFeasibility({ alpha: PREREGISTRATION.multiplicity_rule.alpha, confidence: PREREGISTRATION.multiplicity_rule.confidence, familySize: PREREGISTRATION.multiplicity_rule.family_size }));
  assert.equal(derivedCampaignDecision().decision, derivedCampaignDecision().decision, 'the campaign decision is not a function of the measurements');
});

test('wall-clock LATENCY never changes a decision, and the wall-clock INSTANT never changes the gate', () => {
  // Two readings of "wall clock", both pinned.
  //
  // LATENCY: a trial that took a billion milliseconds is the same trial. The
  // latency block is recorded with `decides: false` and no verdict function
  // reads a `latency_ms`; a repair that let a slow run fail, or a fast one
  // pass, would be scoring the clock.
  const clean = FIXTURE_TRIALS[0];
  const glacial = { ...clean, latency_ms: 987_654_321 };
  assert.equal(resolveTrialVerdict(glacial).verdict, resolveTrialVerdict(clean).verdict, 'a glacial trial is not judged the same as a fast one');
  assert.equal(resolveTrialVerdict(glacial).verdict, 'ALLOW');
  for (const trials of [[clean], [glacial]]) {
    const recorded = latencyRecorded(trials);
    assert.equal(recorded.decides, false, 'a latency block that claims to decide');
    assert.equal(recorded.samples.length, 1);
  }
  // INSTANT: the same record, read a second later and a whole declared window
  // later, is the same record. Freshness is a function of the record and the
  // head tree, not of when the reader happened to look — INSIDE the window the
  // record declares.
  //
  // The later instant is `RUN_FINISHED_AT` plus exactly `WEEK_MS`, because the
  // window is measured from the record's OWN `finished_at`
  // (`freshnessVerdict`: `observedAt - finishedAt > windowMs` is stale). An
  // earlier version of this case used `finished_at + 1 s` for the second read
  // and `finished_at + 1 week + 1 s` for the later one, so the "a week later"
  // read was ONE SECOND outside the window it claimed to be inside — and the
  // case was only green while the campaign decision was absent, because the
  // aggregator refused it before it ever reached the freshness block. The
  // window is a threshold and was NOT widened; the instant was corrected, and
  // the boundary it sat on is now pinned from both sides below.
  const record = replayRecord();
  const soon = gateOf(record, { observedAtIso: GATE_OBSERVED_AT });
  const later = gateOf(record, { observedAtIso: new Date(Date.parse(RUN_FINISHED_AT) + WEEK_MS).toISOString() });
  assert.equal(later.gate.status, soon.gate.status, 'the same record read a window later was decided differently');
  assert.deepEqual(later.gate, soon.gate);
  // AND the other side of the same boundary, which is the property the old
  // literal was accidentally asserting: a read outside the declared window is
  // STALE, and it is reported as staleness rather than as a defect in the
  // record. One millisecond decides it, so the window is a real threshold and
  // not a comment.
  const outside = gateOf(record, { observedAtIso: new Date(Date.parse(RUN_FINISHED_AT) + WEEK_MS + 1).toISOString() });
  assert.equal(outside.gate.stale, true, 'a read one millisecond past the declared window was not reported as stale');
  assert.match(String(outside.gate.reason), /stale-run-timestamp/, String(outside.gate.reason));
  assert.equal(outside.evidence, null, 'a stale record was returned as evidence');
});

test('the decision path reads no clock and no random source', () => {
  // The textual tripwire behind the determinism claims above, over the two
  // modules the new gate reads its answer from. Comments and string literals
  // are stripped first, because both modules DISCUSS `Date.now()` and
  // `Math.random()` in prose while promising never to call either. LIMIT,
  // stated: this is a tripwire for the three obvious forms, not a proof of
  // absence — stripping literals can hide a call, never invent one.
  const stripCommentsAndLiterals = (source) => source
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .split('\n')
    .map((line) => line.replace(/(^|[^:])\/\/.*$/, '$1'))
    .join('\n')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/`(?:\\.|[^`\\])*`/g, '``');
  for (const name of ['comparator.mjs', 'expected-values.mjs']) {
    const code = stripCommentsAndLiterals(readFileSync(path.join(REPO, 'src', 'lib', 'research', name), 'utf8'));
    for (const [pattern, what] of [[/\bDate\.now\s*\(/, 'Date.now()'], [/\bMath\.random\s*\(/, 'Math.random()'], [/new Date\s*\(\s*\)/, 'new Date() with no argument']]) {
      assert.equal(pattern.test(code), false, `src/lib/research/${name} reads ${what} on a decision path`);
    }
  }
});

// --- the aggregator's THREE-WAY SPLIT (F1..F3, the aggregator fix) ---------
//
// WHAT WAS BROKEN, IN THE OWN WORDS OF THE DEFECT: `notRun` received TWO KINDS
// OF ENTRY. Gate-level NOT_RUNs — the dependency gate that could not run, the
// corpus check that could not run, a mandatory probe or control that did not
// run, the cross-process replay, the harness that could not run every property
// — which are real. And two INFORMATIONAL statements about scope: which gate
// OWNS a property (the harness's A3 is table-derived, so the replay's A3 is the
// authoritative one) and which part of the ticket belongs to the campaign behind
// #45. The status line read `notRun.length > 0`, so two notes that are present
// on EVERY run of this track made the aggregator report `NOT_RUN` and exit 3
// forever, with an empty defect list and all five gates PASS.
//
// THE THREE KINDS, AND WHAT EACH ONE MAY DO
//   1. blocking defects      -> FAIL, exit 1. A check this stage performed and
//      that failed, plus the provability precondition (F3: an untracked track
//      turns the gate RED, where it used to be a soft note).
//   2. gate-level NOT_RUNs   -> NOT_RUN, exit 3. "I could not check", never a
//      pass, never a soft pass. UNCHANGED by the repair.
//   3. non-binding scope notes -> recorded in `scopeNotes`, in the summary and
//      in the printed output, and unable to decide anything.
//
// WHY THE SPLIT IS PINNED HERE AND NOT IN A MOCK: every case below calls the
// aggregator's OWN exported functions — `crossRecordAgreement` to produce the
// cross-record verdict the A3 note is written from, `aggregator.ticketScopeNotes`
// to build the notes, `aggregator.gateStatusFromExit` for the child-exit ->
// status mapping a real run applies, and `aggregator.deriveVerdict`, the single
// place the status is computed. A mock of `deriveVerdict` would assert that a
// mock returns what the mock returns; these cases assert the rule the aggregator
// a reader runs enforces. The full aggregator (`verify`) spawns four child gates
// and rewrites the evidence records, so the run that exercises this wiring end to
// end is `npm run verify:s2-008`, not a test — the last case here is a source
// tripwire that the wiring has not been abandoned.

/**
 * The five child gates in the shape `verify` builds them, every one PASS — the
 * shape a real green run has. `overrides` replaces or merges a member, and
 * `trackFilesTracked` is the dependency gate's own `git ls-files` count.
 */
function gatesAllGreen(overrides = {}, { trackFilesTracked = 57 } = {}) {
  const gates = {
    dependency: { status: 'PASS', exitCode: 0, track_files_tracked: trackFilesTracked },
    corpus: { status: 'PASS', exitCode: 0 },
    probes: { status: 'PASS', exitCode: 0 },
    replay: { status: 'PASS', exitCode: 0 },
    harness: { status: 'PASS', exitCode: 0 },
  };
  for (const [id, gate] of Object.entries(overrides)) {
    gates[id] = { ...(gates[id] ?? {}), ...gate };
  }
  return gates;
}

/** The cross-record result of a run whose harness A3 DISCLOSES that it is
 *  table-derived — the shape the delivered harness record has, and the one the
 *  A3-ownership scope note is written from. */
function disclosedCrossRecord() {
  return crossRecordAgreement({
    ticket: 'S2-008',
    kind: 'HARNESS',
    properties: [{ id: 'A3', ok: true, agreement_source: 'TABLE_DERIVED_RUN_RECORDS', evidence: 'findingsA=0 findingsB=0' }],
  }, replayRecord());
}

test('F1 every gate green plus BOTH scope notes is PASS and exit 0, and both notes are still in the summary', () => {
  // The case the defect is about, in the shape it actually occurs: all five
  // gates PASS, no defect, no gate-level NOT_RUN — and the two informational
  // notes present, which is every run of this track.
  const scopeNotes = aggregator.ticketScopeNotes(disclosedCrossRecord());
  assert.equal(scopeNotes.length, 2, `the two scope notes this track always carries were not both built: ${JSON.stringify(scopeNotes)}`);
  assert.match(scopeNotes[0], /table-derived/, `the A3-ownership note says something else: ${scopeNotes[0]}`);
  assert.match(scopeNotes[0], /authoritative A3 is the replay's/, scopeNotes[0]);
  assert.match(scopeNotes[1], /#45/, `the #45 scope statement says something else: ${scopeNotes[1]}`);
  const verdict = aggregator.deriveVerdict({ gates: gatesAllGreen(), defects: [], notRun: [], scopeNotes });
  // The verdict the defect says was unreachable.
  assert.equal(verdict.status, 'PASS', `two scope notes decided the verdict again: ${JSON.stringify(verdict)}`);
  assert.equal(verdict.ok, true);
  assert.equal(verdict.exitCode, 0, 'a PASS must exit 0 — the exit code is the answer a pipeline reads');
  assert.deepEqual([...verdict.blockingGates], []);
  assert.deepEqual([...verdict.notRunGates], []);
  assert.deepEqual([...verdict.notRun], [], 'a green run has no gate-level NOT_RUN');
  assert.deepEqual([...verdict.defects], []);
  // …and the record is not laundered: the notes are STILL THERE, member for
  // member, because the honesty of the record is the point.
  assert.deepEqual([...verdict.scopeNotes], [...scopeNotes], 'the scope notes were dropped from the summary instead of being made non-binding');
  // The note set is DERIVED from the run, not a constant: a harness A3 that
  // claims to be a measurement carries no A3-ownership note, and the verdict is
  // unchanged. A veto that switches off with a disclosure would be a gate whose
  // answer depends on its own honesty about provenance.
  const comparable = crossRecordAgreement({
    properties: [{ id: 'A3', ok: true, agreement_source: 'MEASURED', evidence: 'findingsA=0 findingsB=0' }],
  }, replayRecord());
  assert.equal(comparable.verdict, 'COMPARABLE', 'a measurement-declaring A3 was not treated as a measurement');
  const measuredNotes = aggregator.ticketScopeNotes(comparable);
  assert.equal(measuredNotes.length, 1, `a measured A3 still produced an ownership note: ${JSON.stringify(measuredNotes)}`);
  assert.equal(aggregator.deriveVerdict({ gates: gatesAllGreen(), defects: [], notRun: [], scopeNotes: measuredNotes }).status, 'PASS');
});

test('F1 a child gate that reported NOT_RUN is still NOT_RUN, exit 3, and named in notRunGates', () => {
  // The path the repair must NOT touch: a gate that could not run. Exit 3 stays
  // NOT_RUN, the status is NOT_RUN, the process exits 3, and the gate is named
  // in `notRunGates` so a reader of ONE file knows WHICH check could not be
  // made. The scope notes are present here too — they must not soften it, and
  // they must not sharpen it.
  const scopeNotes = aggregator.ticketScopeNotes(disclosedCrossRecord());
  const verdict = aggregator.deriveVerdict({
    gates: gatesAllGreen({ harness: { status: aggregator.gateStatusFromExit(3), exitCode: 3 } }),
    defects: [],
    notRun: ['NOT_RUN: the harness could not run every property'],
    scopeNotes,
  });
  assert.equal(verdict.status, 'NOT_RUN', `a gate that could not run reported ${verdict.status}: ${JSON.stringify(verdict)}`);
  assert.equal(verdict.exitCode, 3, 'NOT_RUN must exit 3 and never 0');
  assert.equal(verdict.ok, false);
  assert.deepEqual([...verdict.notRunGates], ['harness'], 'the NOT_RUN gate was not named');
  assert.deepEqual([...verdict.blockingGates], [], 'a NOT_RUN is not a blocking gate');
  assert.deepEqual([...verdict.scopeNotes], [...scopeNotes], 'the notes must survive a NOT_RUN run unchanged too');
  // The SECOND gate-level NOT_RUN form: a gate that exits 0 but reported no
  // counter map is a check this stage could not make, and its own status never
  // flips. It stays NOT_RUN — dropping this term would have turned a check that
  // could not be performed into a PASS, which is the weakening the repair is
  // forbidden to make.
  const countersAbsent = aggregator.deriveVerdict({
    gates: gatesAllGreen(),
    defects: [],
    notRun: ['NOT_RUN: the probes gate reported no counter map'],
    scopeNotes,
  });
  assert.equal(countersAbsent.status, 'NOT_RUN', 'a probes gate that printed no counter map was read as a pass');
  assert.equal(countersAbsent.exitCode, 3);
  // The exit-code vocabulary itself, since every case above maps an exit to a
  // status through it: 0 is PASS, 1 is FAIL, 3 is NOT_RUN, and an exit nobody
  // mapped is NOT softened — it is named, it is both a blocking gate and a
  // NOT_RUN gate, and blocking wins, which is the pre-repair behaviour of that
  // path and is left exactly as it was.
  assert.equal(aggregator.gateStatusFromExit(0), 'PASS');
  assert.equal(aggregator.gateStatusFromExit(1), 'FAIL');
  assert.equal(aggregator.gateStatusFromExit(3), 'NOT_RUN');
  assert.match(aggregator.gateStatusFromExit(9), /^NOT_RUN_UNMAPPED_EXIT_/);
  const unmapped = aggregator.deriveVerdict({ gates: gatesAllGreen({ probes: { status: aggregator.gateStatusFromExit(9), exitCode: 9 } }), defects: [], notRun: [], scopeNotes });
  assert.equal(unmapped.status, 'FAIL', 'an unmapped child exit was softened into a pass');
  assert.equal(unmapped.exitCode, 1);
  assert.deepEqual([...unmapped.blockingGates], ['probes']);
  assert.deepEqual([...unmapped.notRunGates], ['probes']);
});

test('F3 an UNTRACKED track file is a DEFECT and exit 1 — strictly stricter than the note it replaced', () => {
  // Provability is a hard requirement of this repository, so a track whose own
  // files `git ls-files` cannot see must turn this gate RED. It was a soft note
  // (and then a NOT_RUN entry) before this repair; nothing here is weaker than
  // that, and this case is the one place the aggregator became stricter.
  const scopeNotes = aggregator.ticketScopeNotes(disclosedCrossRecord());
  const verdict = aggregator.deriveVerdict({ gates: gatesAllGreen({}, { trackFilesTracked: 0 }), defects: [], notRun: [], scopeNotes });
  assert.equal(verdict.status, 'FAIL', `an untracked track was not a failure: ${JSON.stringify(verdict)}`);
  assert.equal(verdict.exitCode, 1, 'a blocking defect must exit 1, not 3 — 3 is NOT_RUN and this is a FAIL');
  assert.equal(verdict.ok, false);
  assert.equal(verdict.defects.length, 1, `the untracked track produced no defect: ${JSON.stringify(verdict.defects)}`);
  assert.match(verdict.defects[0], /untracked/, verdict.defects[0]);
  assert.match(verdict.defects[0], /bound to a base a reader can check/, verdict.defects[0]);
  assert.deepEqual([...verdict.provabilityDefects], [...verdict.defects], 'the provability defect must also be the unmet ticket precondition');
  assert.deepEqual([...verdict.notRunGates], [], 'this is a FAIL, not a NOT_RUN');
  assert.deepEqual([...verdict.scopeNotes], [...scopeNotes], 'a failure must not drop the scope notes from the record');
  // THE CONTROL, or the case proves nothing: the count is the whole rule. One
  // tracked file of this track is enough, and the same gates with it are PASS —
  // so the red above is about provability and not about the gates.
  for (const tracked of [1, 2, 57]) {
    const green = aggregator.deriveVerdict({ gates: gatesAllGreen({}, { trackFilesTracked: tracked }), defects: [], notRun: [], scopeNotes });
    assert.equal(green.status, 'PASS', `${String(tracked)} tracked files did not make the same green run a pass`);
    assert.deepEqual([...green.defects], []);
  }
  // A dependency gate that never reported the count is not the same as zero, and
  // is not invented into a failure: `null` means the gate did not say, and the
  // aggregate verdict reads the gates' own statuses for that.
  const unreported = aggregator.deriveVerdict({ gates: gatesAllGreen({ dependency: { track_files_tracked: null } }), defects: [], notRun: [], scopeNotes });
  assert.equal(unreported.status, 'PASS', 'an unreported tracked-file count was invented into a failure');
  // And a real defect still fails, and still names the gate: the provability
  // term is ADDITIVE to the existing ones, never a replacement for them.
  const alsoFailed = aggregator.deriveVerdict({ gates: gatesAllGreen({ corpus: { status: 'FAIL', exitCode: 1 } }, { trackFilesTracked: 0 }), defects: ['corpus gate: FAIL (drift in evidence/s2-008/corpus/manifest.json)'], notRun: [], scopeNotes });
  assert.equal(alsoFailed.status, 'FAIL');
  assert.equal(alsoFailed.exitCode, 1);
  assert.deepEqual([...alsoFailed.blockingGates], ['corpus']);
  assert.equal(alsoFailed.defects.length, 2, 'the corpus defect was lost when the provability defect fired');
});

test('the aggregator DERIVES its status through deriveVerdict, and its source no longer votes with the notes', () => {
  // The wiring tripwire. `deriveVerdict` and the cases above are only the gate if
  // `verify` actually calls them: a later repair that recomputes the status
  // inline would leave every case above green and the aggregator wrong again.
  const source = readFileSync(path.join(REPO, 'scripts', 'verify-s2-008.mjs'), 'utf8');
  assert.match(source, /deriveVerdict\(\{ gates, defects, notRun, scopeNotes \}\)/, 'verify no longer derives its status through deriveVerdict');
  assert.match(source, /scopeNotes: verdict\.scopeNotes/, 'the summary no longer publishes the notes the derivation returned');
  assert.match(source, /const scopeNotes = ticketScopeNotes\(crossRecord\);/, 'the notes are no longer built by the one function that owns them');
  // The defect itself, as a property of the source: neither note may be pushed
  // into `notRun`, and the two of them are built inside `ticketScopeNotes`
  // rather than typed at a call site.
  assert.equal(/notRun\.push\([^)]*A3 is table-derived/.test(source), false, 'the A3-ownership note is back in notRun');
  assert.equal(/notRun\.push\([^)]*#45/.test(source), false, 'the #45 scope statement is back in notRun');
  assert.equal(/for \(const reason of ticketPreconditions\)/.test(source), false, 'the ticket preconditions are pushed into notRun again');
  // And the freshness and staleness refusals are still in this file, verbatim in
  // shape — the repair was to the status line and to nothing else.
  for (const [pattern, what] of [
    [/'stale-tree-sha'/, 'the stale-tree refusal'],
    [/'stale-run-timestamp'/, 'the stale-run refusal'],
    [/'record-from-the-future'/, 'the record-from-the-future refusal'],
    [/'green-with-nonzero-exit'/, 'the green-written-by-a-failing-run refusal'],
    [/not the one this invocation wrote/, 'the stale-green byte refusal'],
  ]) {
    assert.match(source, pattern, `${what} is gone from the aggregator`);
  }
});
