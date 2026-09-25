// SLOQUAL-001 public surface: frozen contract, scenario manifest, runner and
// fail-closed comparator. Node stdlib only; no web, database or network
// dependency. The product surface (Web/API/CLI) does not expose any of this:
// qualification is an offline harness, not a runtime feature.
export {
  CONTRACT_PATH,
  MANIFEST_PATH,
  FREEZE_RULE,
  assertStampable,
  contractSelfHash,
  manifestDigest,
  sha256OfBytes,
  stampContract,
  validateManifest,
  verifyFreeze,
} from './contract.mjs';

export {
  ARRIVAL_MODEL_VERSION,
  buildArrivalSchedule,
  dispatchAt,
  nowNs,
} from './open-loop.mjs';

export {
  RUNNER_VERSION,
  REVOCATION_PROBE,
  buildRequestPlan,
  environmentManifest,
  executeRun,
  executeScenarioSeed,
} from './measure.mjs';

export {COMPARATOR_VERSION, VERDICTS, compareQualification} from './comparator.mjs';

export {
  STATISTICS_RULE,
  assertSampleVector,
  mean,
  nearestRankPercentile,
  percentileBootstrapInterval,
  seededRandom,
  sortedSamples,
  wilsonInterval,
} from './statistics.mjs';
