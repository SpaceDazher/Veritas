// The real AdapterRegistration (issue #45, SPEC §2 file 3, decision D1).
//
// `adapter_kind` is the literal 'real' of THIS file, exactly as it is a literal
// of adapters.mjs for 'test' and 'wrapper'. A caller that tries to assign a
// different kind is refused with NotRunRealAdapter rather than honoured.
//
// The provenance status starts at NOT_RUN_REAL_ADAPTER and is raised only when a
// realRunEvidence record survives evidence-writer.assertRealRunEvidence. The
// assembled document is validated against the frozen schema and DEEP FROZEN, and
// it is REGISTERED as minted, because a transport refuses any registration this
// tree did not build.
import { ADAPTER_INTERFACE_VERSION, BOARD_CONTRACT_VERSION } from '../agentboard/constants.mjs';
import { assertBoardContract } from '../agentboard/contracts.mjs';
import {
  BlockedPolicy, CapabilityMismatch, NeedsInput, NotRunRealAdapter,
} from '../agentboard/errors.mjs';
import { assertLiveExecutionAuthorized } from '../agentboard/policy.mjs';
import {
  CANONICAL_PROVENANCE_STATUS, HOST_UNISOLATED_PROFILE_ID, REAL_PROVENANCE_STATUS,
  REAL_EXECUTOR_VERSION, REAL_PROVIDERS,
} from './constants.mjs';
import { assertRealRunEvidence } from './evidence-writer.mjs';
import {
  deepFreeze, requireArray, requireClock, requireString, timestampOf,
} from './internals.mjs';

// Minted registrations, for the same reason as the run-evidence registry: only
// createRealRegistration() of THIS tree may hand a document to a transport, and
// only after it adjudicated the provenance status itself.
const MINTED_REGISTRATIONS = new WeakSet();

/** True only for a registration minted by createRealRegistration in THIS process. */
export function isMintedRegistration(value) {
  return MINTED_REGISTRATIONS.has(value);
}

// ---------------------------------------------------------------------------
// The real AdapterRegistration
// ---------------------------------------------------------------------------

/**
 * Build the real AdapterRegistration. `adapter_kind` is the literal 'real' of
 * THIS file, exactly as it is a literal of adapters.mjs for 'test' and
 * 'wrapper'; a caller that tries to assign a different kind is refused with
 * NotRunRealAdapter rather than honoured or ignored.
 *
 * `real_adapter_provenance.status` starts at NOT_RUN_REAL_ADAPTER and is raised
 * to REAL_ADAPTER_AVAILABLE only when `realRunEvidence` survives
 * assertRealRunEvidence above. The assembled document is validated against the
 * frozen schema and then DEEP FROZEN, so nothing downstream can rewrite it.
 */
export function createRealRegistration({
  provider,
  adapterId,
  workspaceId,
  principalId,
  displayName,
  health = 'unknown',
  declaredCapabilities = [],
  declaredTools = [],
  sandboxProfileId,
  clock,
  realRunEvidence = null,
  // The named human permit for the HOST_UNISOLATED floor (issue #45). A
  // SERVER-RESOLVED argument, adjudicated by the same policy gate the command
  // boundary uses, so a registration can never name a tier the run did not
  // actually start under.
  unisolatedExecutionAuthorization = null,
} = {}) {
  const injectedClock = requireClock(clock);
  if (!REAL_PROVIDERS.includes(provider)) {
    throw new NeedsInput(`REAL_PROVIDER_UNKNOWN:${String(provider)}: expected one of ${REAL_PROVIDERS.join(', ')}`);
  }
  // The literal lives here. A caller-supplied kind may only confirm it.
  const expectedKind = 'real';
  if (health !== undefined && health !== null
    && !['healthy', 'degraded', 'unhealthy', 'unknown'].includes(health)) {
    throw new NeedsInput(`HEALTH_VALUE_UNKNOWN:${String(health)}`);
  }
  if (sandboxProfileId !== HOST_UNISOLATED_PROFILE_ID) {
    // A registration is the document a reader looks at FIRST, so it may not
    // name controls this tree does not have. A proven LOCAL_RESTRICTED /
    // UNTRUSTED_CODE id is refused exactly like sbx-no-exec-default and the
    // *_blocked profiles: this transport spawns the child on the host and
    // cannot put it inside a container, so a registration naming one would be a
    // claim rather than a fact. The floor tier is the only profile this tree can
    // run truthfully, and it is admitted only with a complete permit.
    throw new BlockedPolicy(
      'SANDBOX_PROFILE_NOT_EXECUTABLE',
      `a real transport may only bind the HOST_UNISOLATED floor (${HOST_UNISOLATED_PROFILE_ID}) on a host where no `
      + `model-calling executor can run inside a proven profile; got ${String(sandboxProfileId)}. A registration is `
      + 'the document a reader checks first, so it may not name a tier whose controls are not in force.',
    );
  }
  // BLOCKED_SANDBOX when the permit is absent, incomplete, mis-digested or
  // outside its window. Never degraded into a default.
  assertLiveExecutionAuthorized(sandboxProfileId, {
    authorization: unisolatedExecutionAuthorization,
    now: () => timestampOf(injectedClock),
  });

  let status = CANONICAL_PROVENANCE_STATUS;
  let evidence = null;
  if (realRunEvidence !== null && realRunEvidence !== undefined) {
    // Any failure inside here propagates as NotRunRealAdapter: the constructor
    // REFUSES the claim rather than degrading it to the default.
    evidence = assertRealRunEvidence(realRunEvidence);
    // The corroboration must be of THIS provider. A pi registration cannot be
    // upgraded by a codex run, or the provenance status would describe a
    // crossing that a different executor made.
    if (evidence.executor.provider !== provider) {
      throw new NotRunRealAdapter(
        'REAL_RUN_EVIDENCE_PROVIDER_MISMATCH',
        `the record corroborates a ${evidence.executor.provider} run; this registration is ${provider}`,
      );
    }
    status = REAL_PROVENANCE_STATUS;
  }

  const detail = status === REAL_PROVENANCE_STATUS
    ? `real ${provider} executor ${REAL_EXECUTOR_VERSION}; corroborated on this host by run ${evidence.run_id}: `
      + `binary ${evidence.executor.binary_sha256} and raw process log ${evidence.raw_process_log_sha256}. `
      + 'That corroboration covers the process crossing only: the sandbox profile id on this document is a '
      + 'request-side declaration, and this transport spawns the child directly on the host, so no OS isolation '
      + 'was applied. Every run records isolation_applied:false in its own evidence.'
    : `real ${provider} executor transport (${REAL_EXECUTOR_VERSION}); no real run has corroborated this `
      + 'registration on this host, so it stays NOT_RUN_REAL_ADAPTER until a verifiable real-run record exists';

  const registration = {
    contractVersion: BOARD_CONTRACT_VERSION,
    adapter_id: requireString(adapterId, 'adapterId'),
    adapter_interface: ADAPTER_INTERFACE_VERSION,
    provider,
    display_name: requireString(displayName, 'displayName').slice(0, 120),
    adapter_kind: expectedKind,
    health: health ?? 'unknown',
    workspace_id: requireString(workspaceId, 'workspaceId'),
    principal_id: requireString(principalId, 'principalId'),
    declared_capabilities: [...requireArray(declaredCapabilities, 'declaredCapabilities')],
    declared_tools: [...requireArray(declaredTools, 'declaredTools')],
    sandbox_profile_id: sandboxProfileId,
    max_concurrency: 1,
    real_adapter_provenance: { status, detail: detail.slice(0, 500) },
    registered_at: timestampOf(injectedClock),
  };
  const validated = deepFreeze(assertBoardContract('adapter-registration', registration));
  // Minted here and nowhere else: a transport refuses any registration that
  // this module did not build, so a hand-typed literal carrying
  // REAL_ADAPTER_AVAILABLE cannot drive one.
  MINTED_REGISTRATIONS.add(validated);
  return validated;
}