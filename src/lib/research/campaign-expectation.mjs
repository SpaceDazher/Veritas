// S2-008 REPAIR (R-B / R-C) — the frozen CAMPAIGN decision, RE-DERIVED through
// the comparator's own rule (issue SpaceDazher/Veritas#8).
//
// WHY THIS MODULE EXISTS AT ALL
// `EXPECTED_CAMPAIGN` in `src/lib/research/expected-values.mjs` is a DECLARATION,
// for the same reason every other member of that table is one: a table read out
// of a run that already happened is a description of the answer, not a test of
// it. A declaration, however, is only worth as much as the evidence that it is
// the answer the frozen rule actually gives — and the owner of R-B required that
// evidence to be a re-derivation BY THE RULE, never a number written to reach a
// desired verdict. This module is that evidence, in source rather than in prose.
//
// WHY IT IS ITS OWN MODULE AND NOT A PART OF expected-values.mjs
// The re-derivation needs the comparator (`decisionFromInterval`,
// `ruleFeasibility`), and the comparator imports `expectedValueIssues` from
// `expected-values.mjs`. Putting the re-derivation inside the table would make
// those two modules circular, and a cycle evaluated at import time is exactly
// the shape of failure that hides itself until a consumer loads the graph from
// the other end: the table's module body would call a comparator function while
// the comparator's own module-level constants are still in their temporal dead
// zone. The dependency therefore points ONE way — this module reads the table,
// the table knows nothing about this module — and the two can be loaded in
// either order.
//
// WHAT IT DERIVES, AND WHAT IT DELIBERATELY DOES NOT
//   * `decision` and `decisionReason`: re-derived, through the SAME two
//     functions `scoreMetric` uses — `wilsonInterval` from the frozen statistics
//     module and `decisionFromInterval` from the comparator — over the counts
//     the frozen table publishes and at the confidence the table derives. The
//     rule object below is the same shape `scoreMetric` builds (comparator.mjs
//     `scoreMetric`, the `const rule = {...}` block), with the campaign
//     declared as the POOLED AGGREGATE of the declared family, which is what
//     keeps the subject from joining the family and widening it from m = 3 to
//     m = 4. At m = 4 the derived confidence CANNOT reject, and a campaign
//     scored that way would report `never_rejects: true` — a false alarm about a
//     family this preregistration never declared;
//   * `rule_feasibility`: the comparator's own `ruleFeasibility`, so the record
//     that says the rule can reject is the comparator's statement and not this
//     module's re-derivation of it;
//   * `decisionStatus` is NOT re-derived. It is the comparator's private
//     mapping from a decision to a status (POSITIVE -> SATISFIED, NEGATIVE and
//     NULL -> UNMET, everything else -> NOT_MEASURED, in `scoreMetric`), and
//     re-typing that mapping here would be a SECOND SPELLING of one rule — the
//     defect this whole file exists to avoid. The declared status is pinned
//     instead by `tests/research/harness.test.mjs` ("the frozen campaign
//     expectation is the one the comparator answers with"), which is the place a
//     pinned value belongs.
//
// THE ONE-LINE SUMMARY OF WHAT THIS PREVENTS
// A repair that re-tuned the eight synthetic cases until the designed effect
// cleared the 0.02 band would produce a POSITIVE here — and this module is what
// makes that visible: the table's declaration would stop being what the rule
// derives, and every caller of `assertFrozenCampaignDerivable` would refuse
// before a single run was scored.
//
// PURE AND DETERMINISTIC
// No clock, no `Date.now()`, no `Math.random()`, no process, no filesystem, no
// network. The same table gives the same derivation in every process, which is
// what makes it usable as a build-time gate.
import { wilsonInterval } from '../sloqual/statistics.mjs';
import { BlockedPolicy, MalformedResult } from '../agentboard/errors.mjs';
import { decisionFromInterval, ruleFeasibility } from './comparator.mjs';
import {
  EXPECTED_CAMPAIGN, EXPECTED_CAMPAIGN_METRIC, EXPECTED_RULE, assertFrozenTableSelfConsistent,
} from './expected-values.mjs';

/**
 * Re-derive the frozen campaign decision from the frozen table's own counts,
 * through the comparator's rule. No assertion, no throwing: this is the
 * measurement, and a caller decides what a divergence means.
 *
 * @returns {Readonly<{decision: string, decisionReason: string|null, observed: number,
 *   numerator: number, denominator: number, interval: Readonly<{lower: number, upper: number, confidence: number, method: string}>,
 *   correction: object|null, rule_feasibility: Readonly<object>, null_value: number,
 *   noise_band: number, confidence: number, alpha: number, family_size: number}>}
 *   `correction` is `null` when the interval does not exclude the null value:
 *   there was no comparison to correct, and reporting one would be a claim about
 *   a test that was never made.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} whatever
 *   `decisionFromInterval` raises on a table it cannot decide with — a
 *   non-finite count, an inverted interval, an unknown multiplicity method, a
 *   confidence outside (0, 1). Those are the comparator's refusals and they are
 *   not re-typed here.
 */
export function deriveFrozenCampaignDecision() {
  const { numerator, denominator } = EXPECTED_CAMPAIGN_METRIC;
  if (!Number.isInteger(numerator) || !Number.isInteger(denominator) || denominator < 1) {
    throw new MalformedResult(
      'CAMPAIGN_MEASUREMENT_ABSENT',
      `the frozen table pools ${String(numerator)}/${String(denominator)} cases; a campaign rate with no denominator is not a measurement`,
    );
  }
  const observed = numerator / denominator;
  const interval = wilsonInterval({ successes: numerator, trials: denominator, confidence: EXPECTED_CAMPAIGN.confidence });
  const applied = decisionFromInterval({
    observed,
    lower: interval.lower,
    upper: interval.upper,
    noiseBand: EXPECTED_CAMPAIGN.noise_band,
    rule: {
      alpha: EXPECTED_CAMPAIGN.alpha,
      method: EXPECTED_RULE.method,
      // The DECLARED family, by trial id, exactly as the preregistration
      // declares it — the measured rows, which is what the table's own
      // `comparisons` member carries.
      comparisons: [...EXPECTED_CAMPAIGN.comparisons],
      confidence: EXPECTED_CAMPAIGN.confidence,
      null_value: EXPECTED_CAMPAIGN.null_value,
      // The metric's own direction, from the frozen table's campaign rule
      // (which `assertFrozenTableSelfConsistent` has already checked against the
      // metric's `HIGHER_IS_BETTER`), never a literal at the call site.
      direction: EXPECTED_CAMPAIGN.direction,
      subject: EXPECTED_CAMPAIGN.metric,
      // THE LINE THAT KEEPS THE FAMILY AT m = 3. Without it the subject is
      // matched against the family, matches nothing, and is APPENDED — the
      // evidence then reports m = 4, at which the derived confidence cannot
      // reject and a correct campaign is reported as undecidable.
      subject_is_pooled_aggregate: true,
    },
  });
  return Object.freeze({
    decision: applied.decision,
    decisionReason: applied.reason,
    observed,
    numerator,
    denominator,
    interval: Object.freeze({ lower: interval.lower, upper: interval.upper, confidence: interval.confidence, method: interval.method }),
    correction: applied.correction ?? null,
    rule_feasibility: ruleFeasibility({ alpha: EXPECTED_CAMPAIGN.alpha, confidence: EXPECTED_CAMPAIGN.confidence, familySize: EXPECTED_CAMPAIGN.family_size }),
    null_value: EXPECTED_CAMPAIGN.null_value,
    noise_band: EXPECTED_CAMPAIGN.noise_band,
    confidence: EXPECTED_CAMPAIGN.confidence,
    alpha: EXPECTED_CAMPAIGN.alpha,
    family_size: EXPECTED_CAMPAIGN.family_size,
  });
}

/**
 * The gate on the re-derivation: the table's own self-consistency, then the
 * declaration against what the rule produces.
 *
 * Called by `scripts/s2-008-build-corpus.mjs` before it seals anything and by
 * `scripts/s2-008-harness.mjs` before it runs anything, so a campaign is never
 * scored against an expectation the frozen rule does not produce. Fail-closed:
 * a divergence is a refusal with a non-zero exit, never a warning.
 *
 * `declared` exists so the refusal is EXERCISABLE. It defaults to the frozen
 * declaration and nothing in the track passes anything else: a test needs to be
 * able to hand this function a hand-edited expectation and watch it refuse,
 * because a refusal no test can reach is a refusal nobody knows works. The
 * derivation itself is NEVER parameterised — it always runs over the table's own
 * counts, so a caller cannot make this agree by supplying numbers.
 *
 * @param {{declared?: Readonly<object>}} [args]
 * @param {Readonly<object>} [args.declared=EXPECTED_CAMPAIGN] The declaration to
 *   check against the re-derivation. Defaults to the frozen one.
 * @returns {Readonly<object>} The derivation, so a caller can publish the
 *   measured interval beside the declaration instead of asserting that they
 *   agree.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'EXPECTED_CAMPAIGN_DIVERGES_FROM_RULE' when the declared decision is not
 *   the decision the frozen rule derives from the frozen counts, and
 *   'EXPECTED_CAMPAIGN_REASON_DIVERGES_FROM_RULE' when only the reason differs —
 *   a right answer for the wrong reason is still a different question.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} whatever
 *   `assertFrozenTableSelfConsistent` raises — the table publishes a rule that
 *   can reject nothing, pools counts its own rows do not carry, or declares a
 *   row outside a closed set.
 */
export function assertFrozenCampaignDerivable({ declared = EXPECTED_CAMPAIGN } = {}) {
  assertFrozenTableSelfConsistent();
  const derived = deriveFrozenCampaignDecision();
  if (derived.decision !== declared.decision) {
    throw new BlockedPolicy(
      'EXPECTED_CAMPAIGN_DIVERGES_FROM_RULE',
      `the frozen table declares campaign ${String(declared.decision)} while the frozen rule derives ${String(derived.decision)} from ${String(derived.numerator)}/${String(derived.denominator)} cases at confidence ${String(derived.confidence)} over [${String(derived.interval.lower)}, ${String(derived.interval.upper)}] (${String(derived.decisionReason)}); an expectation the rule does not produce is not an expectation`,
    );
  }
  if (derived.decisionReason !== declared.decisionReason) {
    throw new BlockedPolicy(
      'EXPECTED_CAMPAIGN_REASON_DIVERGES_FROM_RULE',
      `the frozen table declares the campaign reason ${String(declared.decisionReason)} while the rule reports ${String(derived.decisionReason)}`,
    );
  }
  return derived;
}
