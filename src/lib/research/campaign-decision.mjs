// S2-008 THE SHARED VERDICT PURE FUNCTIONS — no side effects, no process, no I/O.
//
// WHY THIS MODULE EXISTS (issue #8, acceptance A2, A3 and A5):
// `frozenCampaignDecision`, `campaignDecisionAgreement` and `ledgerShapeIssues`
// used to live in `scripts/s2-008-replay.mjs`, and BOTH the harness
// (`scripts/s2-008-harness.mjs`) and the aggregator (`scripts/verify-s2-008.mjs`)
// reached in and STATICALLY IMPORTED them. That gave the "process-separated"
// replay the same address space as the two processes that judge it: one
// `process.exit(0)` at the top level of the replay module terminated the
// aggregator INSIDE its own process, the aggregator printed no report and wrote
// no summary, and the shell saw exit 0. A gate that the code it judges can kill
// has a silence indistinguishable from a pass.
//
// The dependency is one-way now: the run gates import these pure functions;
// nothing that EXECUTES a run imports a run gate. The three bodies below are
// moved verbatim from the replay (via Function.prototype.toString, so they are
// character-identical), which keeps every call site, every refusal
// (EXPECTED_CAMPAIGN_ABSENT, LEDGER_SHAPE_DIVERGES_FROM_TABLE) and every
// expected value exactly as it was.

import { EXPECTED_LEDGER_SHAPE } from './expected-values.mjs';
// A NAMESPACE import, on purpose, and for the reason the replay used one: the
// frozen CAMPAIGN decision must not stop this module LOADING when the member is
// absent. Absence is a NAMED refusal, never agreement.
import * as expectedValues from './expected-values.mjs';

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function ledgerShapeIssues(runRecord) {
  const observed = Array.isArray(runRecord?.ledger?.record_kinds) ? runRecord.ledger.record_kinds : [];
  const issues = [];
  for (const row of EXPECTED_LEDGER_SHAPE) {
    const seen = observed.filter((kind) => kind === row.kind).length;
    if (seen !== row.count) {
      issues.push({ code: 'LEDGER_SHAPE_DIVERGES_FROM_TABLE', kind: row.kind, expected: row.count, observed: seen, note: row.note });
    }
  }
  return issues;
}

export function frozenCampaignDecision() {
  const declared = expectedValues.EXPECTED_CAMPAIGN;
  return isPlainObject(declared) && typeof declared.decision === 'string' && declared.decision !== ''
    ? declared.decision
    : null;
}

export function campaignDecisionAgreement({ observed = null, expected = null } = {}) {
  const observedDecision = typeof observed === 'string' && observed !== '' ? observed : null;
  const expectedDecision = typeof expected === 'string' && expected !== '' ? expected : null;
  const findings = [];
  if (expectedDecision === null) {
    findings.push({
      code: 'EXPECTED_CAMPAIGN_ABSENT',
      field: 'expected_campaign_decision',
      expected: 'a frozen campaign decision in EXPECTED_CAMPAIGN',
      observed: expectedDecision,
      detail: 'src/lib/research/expected-values.mjs publishes no EXPECTED_CAMPAIGN, so the campaign decision has nothing to agree with; a gate with no expectation is not green',
    });
  } else if (observedDecision === null) {
    findings.push({
      code: 'CAMPAIGN_DECISION_ABSENT',
      field: 'observed_campaign_decision',
      expected: expectedDecision,
      observed: observedDecision,
      detail: 'the comparator produced no campaign decision, so nothing was measured to agree with',
    });
  } else if (observedDecision !== expectedDecision) {
    findings.push({
      code: 'CAMPAIGN_DECISION_DIVERGES_FROM_FROZEN_TABLE',
      field: 'observed_campaign_decision',
      expected: expectedDecision,
      observed: observedDecision,
      detail: `the campaign decided ${observedDecision} while the frozen expected-value table declares ${expectedDecision}; a decision the table does not declare is not a pass`,
    });
  }
  return Object.freeze({
    expected: expectedDecision,
    observed: observedDecision,
    agrees: findings.length === 0,
    findings: Object.freeze(findings),
  });
}
