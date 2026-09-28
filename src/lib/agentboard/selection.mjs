// S2-007R: the derived decision selects the adapter (issue #12, A-MVP-03).
//
// WHY THIS FILE EXISTS
// --------------------
// A DispatchDecision names the adapter a task should run on. Until now nothing
// on the execution path READ that name: the operator named an adapter on the
// command line and the decision was recorded beside the claim with
// `followed: false` and a note that it could not be followed. The record was
// honest about that, which is why A-MVP-03 read "8 dispatch decision(s), 0
// with a selected adapter" — the decision half was observed, the selection half
// simply did not exist.
//
// This module is the missing half. It answers exactly one question — "given an
// ACCEPTED decision, which adapter runs this task?" — and it answers it the same
// way every time, from the decision alone.
//
// FOUR PROPERTIES, EACH ENFORCED STRUCTURALLY
// ------------------------------------------
//   1. THE DECISION IS THE ONLY AUTHORITY. `requested_adapter_id` may be passed
//      by a caller, but it is never a source of truth: when it disagrees with
//      the decision the call is REFUSED with BLOCKED_POLICY /
//      ADAPTER_SELECTION_CONTRADICTS_DECISION. A hand-picked adapter that does
//      not match the decision is exactly the defect this ticket closes, so it is
//      not a convenience — it is an error.
//   2. NO SILENT FALLBACK. A decision that selected no adapter is
//      AGENT_UNAVAILABLE / ADAPTER_SELECTION_INFEASIBLE. There is no "pick any
//      available adapter" path anywhere in this file, and the refusal carries
//      the decision's own exclusion reasons so the operator can see WHY.
//   3. THE CHOICE IS AUDITABLE. Every returned record carries the digest of the
//      decision it was derived from, the id of the rule that mapped the decision
//      to the adapter, the candidate order the decision published, and every
//      exclusion with its reason. Re-deriving from the same decision yields the
//      same record byte for byte: no clock, no randomness, no environment.
//   4. IT NEVER CLAIMS AN EXECUTOR RAN. A selection is a DECISION about an
//      adapter, not an observation of one. This file spawns nothing, so it
//      always publishes `crossing: NOT_RUN_REAL_ADAPTER` and
//      `crossing_observed: false`. Only a parent process that really spawned a
//      child may write anything else, and it must say so with a provenance
//      label. This is the same honesty rule adapters.mjs enforces structurally
//      on the transport side.
//
// The rule below is deliberately the narrowest one that is still a derivation.
// It reads the selection the decision already made rather than re-implementing
// an ordering, because a second ordering in a second file is a second source of
// truth — and the first one is the frozen decision the board already published.
import { AgentUnavailable, BlockedPolicy, isBoardError } from './errors.mjs';
import { canonicalDigest } from '../verifier/canonical-json.mjs';

export const SELECTION_VERSION = 's2-007-selection-v1';

// The single mapping rule. Named in every record so a reader can tell WHICH
// rule produced a selection without reading this file.
export const SELECTION_RULE_ID = 'decision.selected_adapter_id/v1';

// The rule, spelled out, and published verbatim into the record. `basis` is the
// decision's own explanation, never a second opinion.
const RULE_STATEMENT = Object.freeze({
  rule_id: SELECTION_RULE_ID,
  source_field: 'DispatchDecision.selected_adapter_id',
  statement: 'the adapter of record is the adapter the accepted decision selected; '
    + 'a caller-supplied adapter_id never overrides it and is refused when it disagrees',
  ordered_by: 'the candidate order the decision itself published (priority rank, then task_id)',
});

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(value, label) {
  if (!isPlainObject(value)) throw new BlockedPolicy('ADAPTER_SELECTION_MALFORMED', `${label}: object required`);
  return value;
}

/**
 * The digest of a decision, in the same wire form the board publishes: a
 * canonical (sorted-key, whitespace-free) digest over the whole document. Two
 * decisions that differ in one selected_adapter_id differ in this digest, which
 * is what makes a selection traceable to the exact decision that justified it.
 */
export function decisionDigestOf(decision) {
  return `sha256:${canonicalDigest(requireObject(decision, 'decision'))}`;
}

/**
 * Derive the executor for one task from an accepted decision.
 *
 * Throws, never falls back:
 *   - AGENT_UNAVAILABLE / ADAPTER_SELECTION_INFEASIBLE — the decision selected
 *     no adapter. The refusal quotes the decision's exclusions so the cause is
 *     visible instead of guessed at.
 *   - BLOCKED_POLICY / ADAPTER_SELECTION_CONTRADICTS_DECISION — a caller named
 *     an adapter the decision did not select.
 *   - BLOCKED_POLICY / ADAPTER_SELECTION_MALFORMED — the decision is not a
 *     decision, or the requested adapter is not registered in this workspace.
 *
 * `adapters` is the live registration set. It is used for ONE thing: proving
 * that the selected adapter is actually registered here. It is never scanned
 * for a substitute, because "some other registered adapter" is not an answer
 * the decision gave.
 */
export function deriveAdapterSelection({ decision, adapters = [], requestedAdapterId = null } = {}) {
  const doc = requireObject(decision, 'decision');
  const digest = decisionDigestOf(doc);
  const selected = doc.selected_adapter_id ?? null;

  // The manual-selection escape hatch, refused by name. Recording that a caller
  // asked for something the decision did not choose is the whole point: the
  // defect this ticket closes used to be silent.
  if (requestedAdapterId !== null && requestedAdapterId !== undefined
    && requestedAdapterId !== selected) {
    throw new BlockedPolicy(
      'ADAPTER_SELECTION_CONTRADICTS_DECISION',
      `the caller named ${String(requestedAdapterId)} but the accepted decision (${digest}) selected `
      + `${selected === null ? 'no adapter' : String(selected)}; a manual adapter may not override the decision`,
    );
  }

  if (selected === null || selected === undefined || selected === '') {
    const exclusions = Array.isArray(doc.excluded) ? doc.excluded : [];
    const reasons = [...new Set(exclusions.flatMap((entry) => (
      isPlainObject(entry) && Array.isArray(entry.reasons) ? entry.reasons : []
    )))].sort();
    throw new AgentUnavailable(
      'ADAPTER_SELECTION_INFEASIBLE',
      `the accepted decision (${digest}) selected no adapter and the scheduler may not substitute one; `
      + `exclusions: ${reasons.length > 0 ? reasons.join(', ') : 'none recorded'}`,
    );
  }

  const registration = (Array.isArray(adapters) ? adapters : [])
    .find((adapter) => isPlainObject(adapter) && adapter.adapter_id === selected);
  if (!isPlainObject(registration)) {
    throw new BlockedPolicy(
      'ADAPTER_SELECTION_MALFORMED',
      `the decision (${digest}) selected ${String(selected)}, which is not a registered adapter in this workspace`,
    );
  }

  return Object.freeze({
    selection_version: SELECTION_VERSION,
    rule: RULE_STATEMENT,
    // --- the traceability triple the ticket asks for ---
    decision_id: doc.decision_id ?? null,
    decision_digest: digest,
    basis: Object.freeze({
      selected_task_id: doc.selected_task_id ?? null,
      reason: doc.reason ?? null,
      decided_at: doc.decided_at ?? null,
      budget_snapshot: doc.budget_snapshot ?? null,
      // The order the decision published, kept verbatim: the selection is a
      // projection of it, not a re-ordering.
      candidates: Object.freeze((Array.isArray(doc.candidates) ? doc.candidates : []).map((entry) => Object.freeze({
        task_id: entry?.task_id ?? null,
        priority: entry?.priority ?? null,
        eligible: entry?.eligible === true,
        exclusion_reasons: Object.freeze([...(Array.isArray(entry?.exclusion_reasons) ? entry.exclusion_reasons : [])]),
      }))),
      excluded: Object.freeze((Array.isArray(doc.excluded) ? doc.excluded : []).map((entry) => Object.freeze({
        subject_kind: entry?.subject_kind ?? null,
        subject_id: entry?.subject_id ?? null,
        reasons: Object.freeze([...(Array.isArray(entry?.reasons) ? entry.reasons : [])]),
      }))),
    }),
    // --- what the decision chose ---
    adapter_id: selected,
    provider: registration.provider ?? null,
    adapter_kind: registration.adapter_kind ?? null,
    sandbox_profile_id: registration.sandbox_profile_id ?? null,
    // --- what has NOT happened yet ---
    // A selection is not a crossing. Nothing in this file spawns a process, so
    // these two fields are constants here by construction: only a parent that
    // really observed a child may replace them, and it must label the
    // observation it is making.
    crossing: 'NOT_RUN_REAL_ADAPTER',
    crossing_observed: false,
    provenance: Object.freeze({
      derived_from: 'an accepted DispatchDecision',
      derived_by: 'src/lib/agentboard/selection.mjs (a pure function of the decision and the registration set)',
      transport: 'none — this module spawns no process and runs no model',
      note: 'a selected adapter is a decision about an executor, never evidence that one ran',
    }),
  });
}

/**
 * The single honest answer to "did the selection actually reach an executor?".
 * It takes the observation a parent collected and refuses to upgrade anything
 * the parent did not actually observe.
 *
 * The rules, all fail-closed:
 *   - a selection that is still `NOT_RUN_REAL_ADAPTER` can never be upgraded;
 *   - an observation without a real (non-test) adapter_kind, a child exit code
 *     and a raw process log digest is `NOT_RUN_REAL_ADAPTER`, whatever the
 *     caller hoped;
 *   - a scripted or replay transport can never be reported as a crossing.
 *
 * The result always names its provenance: this is an OBSERVATION made by a
 * cooperating parent process about a child it spawned. It is not an adversarial
 * boundary, and it never claims causality for the run's quality.
 */
export function classifyCrossing(selection, observation = {}) {
  const base = {
    selection_version: SELECTION_VERSION,
    decision_digest: isPlainObject(selection) ? (selection.decision_digest ?? null) : null,
    adapter_id: isPlainObject(selection) ? (selection.adapter_id ?? null) : null,
    provider: isPlainObject(selection) ? (selection.provider ?? null) : null,
    provenance: {
      method: 'parent-process observation of a directly spawned child',
      observation_trust: 'cooperating_transport_observation',
      causal_claim: 'none — this records that a child process was spawned and exited, not that the run was any good',
    },
  };

  const record = (status, detail) => Object.freeze({ ...base, status, crossing_observed: status === 'REAL_ADAPTER_CROSSING', detail });

  if (!isPlainObject(selection) || selection.crossing !== 'NOT_RUN_REAL_ADAPTER') {
    // The selection this module produces always carries that marker. Anything
    // else is a document from elsewhere and is not this gate's to upgrade.
    if (isPlainObject(selection) && selection.crossing === 'REAL_ADAPTER_CROSSING') {
      return record('REAL_ADAPTER_CROSSING', 'the selection already carried a crossing observation');
    }
    return record('NOT_RUN_REAL_ADAPTER', 'the selection is not one this gate can upgrade');
  }
  if (selection.adapter_kind !== 'real') {
    return record('NOT_RUN_REAL_ADAPTER', `adapter_kind ${String(selection.adapter_kind)} is not a real executor`);
  }
  const childExit = observation.child_exit_code;
  const rawLogDigest = observation.raw_process_log_sha256;
  if (!Number.isInteger(childExit)) {
    return record('NOT_RUN_REAL_ADAPTER', 'the parent observed no child exit code');
  }
  if (typeof rawLogDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(rawLogDigest)) {
    return record('NOT_RUN_REAL_ADAPTER', 'the parent observed no raw process log digest');
  }
  if (observation.transport_kind === 'test' || observation.transport_kind === 'wrapper'
    || observation.transport_kind === 'replay') {
    return record('NOT_RUN_REAL_ADAPTER', `a ${String(observation.transport_kind)} transport is never a real crossing`);
  }
  return record('REAL_ADAPTER_CROSSING', 'a real child process was spawned, exited, and left a raw process log');
}

// Re-exported so a caller can narrow a refusal without importing errors.mjs.
export { isBoardError };
