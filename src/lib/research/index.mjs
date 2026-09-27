// S2-008 research track — the PUBLIC SURFACE (issue SpaceDazher/Veritas#8).
//
// Serves acceptance items A1, A2, A3, A4 and A5 by being the single import
// point of the track, in the style of `src/lib/sloqual/index.mjs`.
//
// WRITTEN LAST, AFTER EVERY MODULE FILE EXISTS. This file re-exports EXACTLY
// the names the judged plan §1 froze — no additions, no renames, no aliases,
// no convenience wrappers. The surface is the interface: a name that appears
// here is a name the track promised, and a name that does not appear here
// does not exist on the research boundary.
//
// WHAT IS DELIBERATELY NOT RE-EXPORTED
//   * `policy.mjs` — the judged plan freezes no export names for it (see that
//     file's header). Re-exporting it under a name the plan did not freeze
//     would make the gap permanent instead of reported.
//   * `src/lib/sloqual/**` — imported BY comparator.mjs, never re-exported and
//     never forked. A caller that needs `resolveVerdict` imports it from
//     sloqual; the research surface never becomes a second entry point to a
//     verdict layer.
//   * `src/lib/agentboard/**` — the board's errors, constants and canonical
//     JSON helpers are used by the research modules and stay owned by the
//     board. Re-exporting them here would give this track a second path to the
//     frozen vocabulary.
//
// STATE: every re-exported function currently throws
// `Error('NOT_IMPLEMENTED: <name>')` from its own module. This barrel is
// therefore real and importable, but nothing behind it is implemented. That is
// the intended state of the skeleton: the interfaces are frozen and the bodies
// are absent, never a pass-through that could be mistaken for a working
// implementation.
//
// Owner: W4 (policy, probes, harness). Budget: part of W4's <= 1,100 lines.

export {
  RESEARCH_VERSION,
  RESEARCH_STATES,
  RESEARCH_TRANSITIONS,
  RESEARCH_ID_PREFIXES,
  RESEARCH_OUTCOMES,
  TRIAL_STATUSES,
  TRIAL_VERDICTS,
  RESEARCH_PARTITIONS,
  RESEARCH_HARD_GATE_COUNTERS,
  refusalClass,
} from './constants.mjs';

export {
  RESEARCH_CONTRACTS,
  RESEARCH_CONTRACT_FILES,
  RESEARCH_CONTRACT_IDS,
  researchContractDigest,
  allResearchContractDigests,
  assertResearchContract,
  isResearchContractValid,
  researchContractErrors,
  loadResearchContracts,
} from './contracts.mjs';

export {
  RESEARCH_CARD_TYPES,
  RESEARCH_RELATION_STRENGTHS,
  OBSERVATIONAL_RELATION_STRENGTHS,
  classifyCardRelation,
  assertCausalDiscipline,
  assertNoCausalFromSimulation,
} from './causality.mjs';

export {
  PREREGISTRATION_KIND,
  AMENDMENT_KIND,
  PREREGISTRATION_RULE,
  preregistrationDigest,
  loadPreregistration,
  assertPreregistration,
  assertPreregisteredBeforeRun,
  assertSeedSetFrozen,
  assertNoPostResultRewrite,
  createAmendment,
  assertAmendmentNotDecisionBasis,
  assertBudgetReservation,
  seedCountOf,
  stoppingRuleOf,
} from './preregistration.mjs';

export {
  readCorpus,
  assertPartitionAccess,
  labelsDigest,
  assertLabelSeal,
  substituteLabelsControl,
  caseDigest,
} from './dataset.mjs';

export {
  openRegistry,
  putExperiment,
  recordHoldoutRead,
  recordSpend,
  appendRecord,
  readJournal,
  verifyChain,
  recoverTornTail,
  headDigest,
  snapshotDigest,
  acquireLock,
  releaseLock,
  purgeRegistry,
} from './registry.mjs';

export {
  EXPECTED_TRIAL_DECISIONS,
  EXPECTED_CODES,
  EXPECTED_COUNTERS,
  EXPECTED_LEDGER_SHAPE,
  EXPECTED_METRIC,
  EXPECTED_CONTROLS,
  expectedValueIssues,
  expectedTableDigest,
  assertTableFrozen,
} from './expected-values.mjs';

export {
  COMPARATOR_VERSION,
  resolveTrialVerdict,
  assertEvaluatorPresent,
  decisionFromInterval,
  compareParallelTrack,
  resolveCampaignVerdict,
  metricsSummary,
  latencyRecorded,
  injectCorruption,
} from './comparator.mjs';

export {
  NEGATIVE_CONTROLS,
  runNegativeControls,
  controlsFlipVerdict,
} from './negative-controls.mjs';

export {
  PROBES_VERSION,
  PROBE_FAMILIES,
  PROBE_NAMES,
  HARD_GATE_COUNTERS,
  createWorld,
  runProbe,
  runAllProbes,
  ProbeRecorder,
} from './probes.mjs';
