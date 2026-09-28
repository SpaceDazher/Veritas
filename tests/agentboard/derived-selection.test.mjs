// A-MVP-03: the derived decision selects the adapter (issue #12).
//
// This file is the regression net for the defect the acceptance case actually
// named — "8 dispatch decision(s), 0 with a selected adapter" — and for the
// four properties that close it. The interesting part is not that the positive
// path works; it is that the NEGATIVES hold, because the defect itself was a
// silent substitution, and a fix that only makes the happy path pass would
// leave the substitution in place.
//
// The chain under test, end to end inside one process:
//
//   server-resolved permit -> planDispatch -> DispatchDecision
//     -> deriveAdapterSelection -> selection record -> classifyCrossing
//
// No wall-clock, no randomness, no process spawn: every id and digest here is a
// pure function of its input, so each case is exactly reproducible.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { planDispatch } from '../../src/lib/agentboard/scheduler.mjs';
import { ID_PREFIXES } from '../../src/lib/agentboard/constants.mjs';
import { SANDBOX_HOST_UNISOLATED } from '../../src/lib/identity/sandbox-profiles.mjs';
import { isBoardError } from '../../src/lib/agentboard/errors.mjs';
import {
  SELECTION_RULE_ID,
  classifyCrossing,
  decisionDigestOf,
  deriveAdapterSelection,
} from '../../src/lib/agentboard/selection.mjs';
import { buildUnisolatedAuthorization } from '../../scripts/s2-007r-authorization.mjs';

const PROFILE = SANDBOX_HOST_UNISOLATED.profile_id;
const NOW = '2026-09-26T12:00:00.000Z';
const WORKSPACE = 'ws-derived-selection';

const permit = () => buildUnisolatedAuthorization();

/** Ids that honour the frozen prefixes, so the contract check is exercised. */
function idFactory() {
  let n = 0;
  return (name) => ID_PREFIXES[name] + String(++n).padStart(6, '0');
}

function makeTask(overrides = {}) {
  return {
    task_id: 'abt-derived-1',
    state: 'READY',
    workspace_id: WORKSPACE,
    priority: 'HIGH',
    brief_validated: true,
    acl: { allowed_principal_ids: ['prn-scheduler'] },
    workspace_ref: {
      isolation_profile_id: PROFILE,
      sandbox_profile_digest: `sha256:${'a'.repeat(64)}`,
    },
    ...overrides,
  };
}

function makeAdapter(adapterId, overrides = {}) {
  return {
    adapter_id: adapterId,
    workspace_id: WORKSPACE,
    health: 'healthy',
    adapter_kind: 'real',
    provider: adapterId.replace('adr-', '').replace('-local', ''),
    declared_capabilities: [],
    declared_tools: [],
    sandbox_profile_id: PROFILE,
    ...overrides,
  };
}

function makeGrant(overrides = {}) {
  return {
    grant_id: 'grt-derived-1',
    workspace_id: WORKSPACE,
    task_id: 'abt-derived-1',
    currency: 'USD',
    task_limit: 5,
    campaign_limit: 5,
    day_limit: 5,
    timeout_ms: 60_000,
    granted_by: 'prn-owner',
    granted_at: NOW,
    ...overrides,
  };
}

function plan({ tasks = [makeTask()], adapters = [makeAdapter('adr-pi-local'), makeAdapter('adr-codex-local')], budgets = [makeGrant()], ...rest } = {}) {
  return planDispatch({
    workspaceId: WORKSPACE, tasks, adapters, budgets, spent: [], now: NOW, ids: idFactory(), ...rest,
  });
}

const refuses = (fn, expectedCode) => {
  let thrown = null;
  try {
    fn();
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown, 'the call must refuse');
  assert.equal(isBoardError(thrown), true, 'a refusal must be a typed BoardError, never a plain Error');
  assert.equal(thrown.code, expectedCode);
  return thrown;
};

describe('the derived decision reaches an adapter (A-MVP-03)', () => {
  test('a permitted HOST_UNISOLATED task is dispatched onto a real adapter', () => {
    const decision = plan({ sandbox: PROFILE, unisolatedExecutionAuthorization: permit() });
    assert.equal(decision.selected_task_id, 'abt-derived-1');
    assert.equal(decision.selected_adapter_id, 'adr-codex-local');
    assert.equal(decision.candidates[0].eligible, true);
    assert.deepEqual(decision.candidates[0].exclusion_reasons, []);
  });

  test('the permit may ride inside the sandbox declaration instead of beside it', () => {
    // The declaration is what the command boundary already forwards, so this is
    // the shape the live path actually uses.
    const decision = plan({ sandbox: { profile_id: PROFILE, authorization: permit() } });
    assert.equal(decision.selected_adapter_id, 'adr-codex-local');
  });

  test('the choice is deterministic and independent of registration order', () => {
    const first = plan({ sandbox: PROFILE, unisolatedExecutionAuthorization: permit() });
    const shuffled = plan({
      adapters: [makeAdapter('adr-codex-local'), makeAdapter('adr-pi-local')],
      sandbox: PROFILE,
      unisolatedExecutionAuthorization: permit(),
    });
    assert.equal(first.selected_adapter_id, shuffled.selected_adapter_id);
    assert.equal(decisionDigestOf(first), decisionDigestOf(shuffled));
  });

  test('a candidate that merely lost the order is not reported as refused', () => {
    // Each task needs its own task-scoped grant: a budget row is resolved by
    // task_id, so one grant cannot admit two candidates.
    const decision = plan({
      tasks: [makeTask({ task_id: 'abt-high', priority: 'HIGH' }), makeTask({ task_id: 'abt-low', priority: 'LOW' })],
      budgets: [makeGrant({ grant_id: 'grt-high', task_id: 'abt-high' }), makeGrant({ grant_id: 'grt-low', task_id: 'abt-low' })],
      sandbox: PROFILE,
      unisolatedExecutionAuthorization: permit(),
    });
    assert.equal(decision.selected_task_id, 'abt-high', 'HIGH outranks LOW');
    // It was not refused, it just lost the tie-break: inventing a reason for it
    // would misreport an ordering as an exclusion.
    const loser = decision.candidates.find((entry) => entry.task_id === 'abt-low');
    assert.equal(loser.eligible, true);
    assert.deepEqual(loser.exclusion_reasons, []);
    assert.ok(
      !decision.excluded.some((entry) => entry.subject_id === 'abt-low'),
      'a candidate that merely lost the order must not appear as excluded',
    );
  });

  test('a genuinely refused candidate appears in excluded with a reason', () => {
    const decision = plan({
      tasks: [makeTask({ task_id: 'abt-high', priority: 'HIGH' }), makeTask({ task_id: 'abt-low', priority: 'LOW' })],
      budgets: [makeGrant({ grant_id: 'grt-high', task_id: 'abt-high' })],
      sandbox: PROFILE,
      unisolatedExecutionAuthorization: permit(),
    });
    assert.equal(decision.selected_task_id, 'abt-high');
    const refused = decision.excluded.find((entry) => entry.subject_id === 'abt-low');
    assert.ok(refused, 'the unbudgeted candidate must appear in excluded');
    assert.deepEqual(refused.reasons, ['BUDGET_NOT_ASSIGNED']);
    // The whole excluded list is reason-bearing, never an empty refusal.
    for (const entry of decision.excluded) {
      assert.ok(Array.isArray(entry.reasons) && entry.reasons.length > 0, `${entry.subject_id} must carry a reason`);
    }
  });

  test('an unhealthy adapter is refused rather than quietly skipped to another', () => {
    const decision = plan({
      adapters: [makeAdapter('adr-codex-local', { health: 'degraded' }), makeAdapter('adr-pi-local')],
      sandbox: PROFILE,
      unisolatedExecutionAuthorization: permit(),
    });
    assert.equal(decision.selected_adapter_id, 'adr-pi-local');
    const refused = decision.excluded.find((entry) => entry.subject_id === 'adr-codex-local');
    assert.ok(refused, 'the unhealthy adapter must appear in excluded');
    assert.deepEqual(refused.reasons, ['NO_HEALTHY_ADAPTER']);
  });
});

describe('the floor tier stays shut without a server-resolved permit', () => {
  test('no permit at all means no selection, and never a fallback adapter', () => {
    const decision = plan({ sandbox: PROFILE });
    assert.equal(decision.selected_adapter_id, null);
    assert.equal(decision.candidates[0].eligible, false);
    assert.deepEqual(decision.candidates[0].exclusion_reasons, ['SANDBOX_NOT_PROVEN']);
  });

  test('a bare profile id is not a permit', () => {
    // The regression that made the whole case NOT_RUN: passing the profile
    // alone used to be indistinguishable from passing an authorised sandbox.
    const decision = plan({ sandbox: PROFILE });
    assert.equal(decision.selected_adapter_id, null);
  });

  test('a forged permit digest is refused', () => {
    const forged = { ...permit(), body_digest: `sha256:${'0'.repeat(64)}` };
    const decision = plan({ sandbox: { profile_id: PROFILE, authorization: forged } });
    assert.equal(decision.selected_adapter_id, null);
  });

  test('a permit issued for another profile is refused', () => {
    const decision = plan({ sandbox: { profile_id: PROFILE, authorization: { ...permit(), profile_id: 'sbx-local-restricted-podman' } } });
    assert.equal(decision.selected_adapter_id, null);
  });
});

describe('the selection is a projection of the decision, not a second opinion', () => {
  const decision = () => plan({ sandbox: PROFILE, unisolatedExecutionAuthorization: permit() });

  test('the record carries the decision digest, the rule and the basis', () => {
    const doc = decision();
    const selection = deriveAdapterSelection({
      decision: doc,
      adapters: [makeAdapter('adr-pi-local'), makeAdapter('adr-codex-local')],
    });
    assert.equal(selection.decision_digest, decisionDigestOf(doc));
    assert.equal(selection.decision_id, doc.decision_id);
    assert.equal(selection.rule.rule_id, SELECTION_RULE_ID);
    assert.equal(selection.adapter_id, doc.selected_adapter_id);
    assert.equal(selection.basis.selected_task_id, doc.selected_task_id);
    assert.equal(selection.basis.candidates.length, doc.candidates.length);
  });

  test('re-deriving from the same decision is byte-identical', () => {
    const doc = decision();
    const adapters = [makeAdapter('adr-pi-local'), makeAdapter('adr-codex-local')];
    assert.equal(
      JSON.stringify(deriveAdapterSelection({ decision: doc, adapters })),
      JSON.stringify(deriveAdapterSelection({ decision: doc, adapters })),
    );
  });

  test('a manual adapter that the decision did not select is refused', () => {
    const doc = decision();
    const error = refuses(
      () => deriveAdapterSelection({ decision: doc, adapters: [makeAdapter('adr-pi-local')], requestedAdapterId: 'adr-pi-local' }),
      'BLOCKED_POLICY',
    );
    assert.match(`${error.message} ${error.detail ?? ''}`, /ADAPTER_SELECTION_CONTRADICTS_DECISION/);
  });

  test('agreeing with the decision is not treated as a contradiction', () => {
    const doc = decision();
    const selection = deriveAdapterSelection({
      decision: doc,
      adapters: [makeAdapter(doc.selected_adapter_id)],
      requestedAdapterId: doc.selected_adapter_id,
    });
    assert.equal(selection.adapter_id, doc.selected_adapter_id);
  });

  test('a decision that selected nothing is infeasible, never "any available adapter"', () => {
    const empty = plan({ sandbox: PROFILE });
    const error = refuses(
      () => deriveAdapterSelection({ decision: empty, adapters: [makeAdapter('adr-pi-local'), makeAdapter('adr-codex-local')] }),
      'AGENT_UNAVAILABLE',
    );
    assert.match(`${error.message} ${error.detail ?? ''}`, /ADAPTER_SELECTION_INFEASIBLE/);
    // The neighbouring board gates put the code in `message` and the sentence
    // in `detail`; both travel in the board-error document, so the reason the
    // decision gives must be readable in either field.
    assert.match(`${error.message} ${error.detail ?? ''}`, /SANDBOX_NOT_PROVEN/, 'the refusal must quote the decision\'s own reason');
  });

  test('a decision naming an unregistered adapter is refused', () => {
    const doc = { ...decision(), selected_adapter_id: 'adr-hermes-local' };
    refuses(() => deriveAdapterSelection({ decision: doc, adapters: [makeAdapter('adr-pi-local')] }), 'BLOCKED_POLICY');
  });

  test('a document that is not a decision is refused', () => {
    refuses(() => deriveAdapterSelection({ decision: null, adapters: [] }), 'BLOCKED_POLICY');
    refuses(() => deriveAdapterSelection({ decision: 'adr-pi-local', adapters: [] }), 'BLOCKED_POLICY');
  });
});

describe('a selection is never a crossing', () => {
  const realSelection = () => deriveAdapterSelection({
    decision: plan({ sandbox: PROFILE, unisolatedExecutionAuthorization: permit() }),
    adapters: [makeAdapter('adr-codex-local'), makeAdapter('adr-pi-local')],
  });

  test('a fresh selection reports NOT_RUN_REAL_ADAPTER and observed=false', () => {
    const selection = realSelection();
    assert.equal(selection.crossing, 'NOT_RUN_REAL_ADAPTER');
    assert.equal(selection.crossing_observed, false);
    const crossing = classifyCrossing(selection, {});
    assert.equal(crossing.status, 'NOT_RUN_REAL_ADAPTER');
    assert.equal(crossing.crossing_observed, false);
  });

  test('an observation missing its exit code or raw log is not a crossing', () => {
    const selection = realSelection();
    const noExit = classifyCrossing(selection, { raw_process_log_sha256: `sha256:${'b'.repeat(64)}` });
    assert.equal(noExit.status, 'NOT_RUN_REAL_ADAPTER');
    const noLog = classifyCrossing(selection, { child_exit_code: 0 });
    assert.equal(noLog.status, 'NOT_RUN_REAL_ADAPTER');
    const badDigest = classifyCrossing(selection, { child_exit_code: 0, raw_process_log_sha256: 'not-a-digest' });
    assert.equal(badDigest.status, 'NOT_RUN_REAL_ADAPTER');
  });

  test('a scripted transport is never upgraded to a real crossing', () => {
    const selection = realSelection();
    const observation = { child_exit_code: 0, raw_process_log_sha256: `sha256:${'c'.repeat(64)}`, transport_kind: 'test' };
    assert.equal(classifyCrossing(selection, observation).status, 'NOT_RUN_REAL_ADAPTER');
  });

  test('a non-real adapter kind is never upgraded', () => {
    const doc = plan({ sandbox: PROFILE, unisolatedExecutionAuthorization: permit() });
    const selection = deriveAdapterSelection({
      decision: doc,
      adapters: [makeAdapter(doc.selected_adapter_id, { adapter_kind: 'test' })],
    });
    const observation = { child_exit_code: 0, raw_process_log_sha256: `sha256:${'d'.repeat(64)}` };
    assert.equal(classifyCrossing(selection, observation).status, 'NOT_RUN_REAL_ADAPTER');
  });

  test('a real child with an exit code and a raw log IS a crossing, and says what it observed', () => {
    const selection = realSelection();
    const observation = {
      child_exit_code: 0,
      raw_process_log_sha256: `sha256:${'e'.repeat(64)}`,
      transport_kind: 'real',
    };
    const crossing = classifyCrossing(selection, observation);
    assert.equal(crossing.status, 'REAL_ADAPTER_CROSSING');
    assert.equal(crossing.crossing_observed, true);
    assert.equal(crossing.decision_digest, selection.decision_digest);
    assert.match(crossing.provenance.causal_claim, /none/);
  });
});
