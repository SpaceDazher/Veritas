import { isDeepStrictEqual } from 'node:util';

// The coordinator prints the report it has just produced; --write persists
// the same report plus exitCode. Both must match. A previous green file alone
// is never evidence of the DB phase in this invocation.
export function classifyCurrentDbReplay(replay, writtenEvidence) {
  let observed;
  try {
    observed = JSON.parse(replay.stdout);
  } catch {
    observed = null;
  }
  const matchesCurrentRun = observed && typeof observed === 'object'
    && isDeepStrictEqual(writtenEvidence, { ...observed, exitCode: replay.exitCode });
  if (!matchesCurrentRun) {
    return {
      gate: { status: 'FAIL', exitCode: replay.exitCode, source: 'current DB replay', reason: 'DB report absent or differs from written evidence' },
      evidence: null,
    };
  }
  if (replay.exitCode !== 0) {
    return { gate: { status: 'FAIL', exitCode: replay.exitCode, source: 'current DB replay', reason: 'DB replay process failed' }, evidence: writtenEvidence };
  }
  if (observed.status === 'NOT_RUN_DB' && observed.ok === false) {
    return { gate: { status: 'NOT_RUN_DB', exitCode: 0, source: 'current DB replay', reason: observed.reason ?? 'PostgreSQL unavailable' }, evidence: writtenEvidence };
  }
  const green = observed.status === 'PASS' && observed.ok === true
    && observed.comparison?.ok === true && observed.hardGates?.ok === true
    && observed.crashPhase?.ok === true;
  return {
    gate: {
      status: green ? 'PASS' : 'FAIL',
      exitCode: 0,
      source: 'current DB replay',
      crashPhaseOk: observed.crashPhase?.ok === true,
      ...(green ? {} : { reason: 'DB comparison, hard gates or crash phase did not pass' }),
    },
    evidence: writtenEvidence,
  };
}

export function engineeringGateExitCode(verdict, gates) {
  return gates.dbReplay?.status === 'PASS'
    && ['NEEDS_INPUT', 'HUMAN_REVIEW', 'PASS_WITH_LIMITS'].includes(verdict) ? 0 : 1;
}
