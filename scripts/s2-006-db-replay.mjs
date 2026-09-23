// S2-006 PostgreSQL two-process store replay (spec §11, §14 gate 9).
// Coordinator process: provisions an ephemeral loopback-only PostgreSQL
// (ephemeral podman container with the SAME pinned image and hardening flags
// as the S2-005 smoke/replay, or an external DATABASE_URL), applies the
// migrations to TWO separate schemas, then spawns each store-replay as its
// OWN child process (distinct PID and executor id — spec §11 requires
// process separation). The coordinator never runs store logic itself.
//
// Each child executes the SAME deterministic set of store operations through
// the canonical command API on PostgresVerifierStore:
//   publishVerificationResult -> idempotent replay of the same publish
//   publishCalibrationReport  -> publishAdjudication
//   reserve/accept/finalize of a fenced external call
// and reads back the immutable records. The coordinator then fails closed on
// any divergence: outcome digests, record identity sets, ledger/outbox
// uniqueness, fencing token, process provenance and a degenerate all-ERROR
// distribution (the S2-005 regression: two identically broken runs are never
// a match).
//
// Honest DB availability handling: if no PostgreSQL can be provisioned the
// script reports status NOT_RUN_DB with exit code 0 (the same explicit
// skip-with-marker convention as tests/verifier/store.test.mjs) — it never
// crashes and never reports the persistence gate as passed. Any real replay
// failure or hard-gate violation exits 1.
//
//   node scripts/s2-006-db-replay.mjs                  # podman flow or NOT_RUN_DB
//   DATABASE_URL=… node scripts/s2-006-db-replay.mjs   # external database
//
// Child mode (internal): --child --schema … --run-id … --executor-id … --out <file>
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { computeCanonicalArgsDigest, verifyClaim } from '../src/lib/verifier/api.mjs';
import { AclDenied, ReconciliationRequired, VerifierError } from '../src/lib/verifier/errors.mjs';
import { registerKey, sign } from '../src/lib/verifier/signature.mjs';
import {
  makeVerifierAuthorityRegistry,
  publishVerificationResult,
  publishCalibrationReport,
  publishAdjudication,
  registerProviderGrant,
  reserveExternalCall,
  acceptExternalCall,
  finalizeExternalCall,
} from '../src/lib/verifier/commands.mjs';
import { PostgresVerifierStore } from '../src/lib/verifier/store.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTAINER = 'veritas-s2-006-db-replay';
const DISTRO = 'Ubuntu-24.04';
const WORKSPACE = 'ws-verifier';
const ACTOR = 'prn-evaluation-harness';
const ADJUDICATOR = 'prn-adjudicator-1';
const FIXED_CLOCK = () => '2026-01-15T08:00:00.000Z';

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) args[argv[i].slice(2)] = 'true';
      else { args[argv[i].slice(2)] = next; i += 1; }
    } else {
      args._.push(argv[i]);
    }
  }
  return args;
}

function wsl(argv, { expected = 0, timeout = 30000 } = {}) {
  const result = spawnSync('wsl.exe', ['-d', DISTRO, '--', ...argv], {
    encoding: 'utf8', shell: false, timeout, windowsHide: true, maxBuffer: 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== expected) throw new Error(`POSTGRES_COMMAND_FAILED:${String(result.stderr).trim()}`);
  return String(result.stdout ?? '').trim();
}

function podmanAvailable() {
  try {
    wsl(['podman', '--version'], { timeout: 15000 });
    return true;
  } catch {
    return false;
  }
}

function cleanupContainer() {
  try {
    wsl(['podman', 'rm', '--force', '--time', '0', CONTAINER], { expected: null, timeout: 20000 });
  } catch {
    // best effort
  }
}

// ---- deterministic replay fixture (store semantics under test, not semantics
// of the verdicts: the checker is a typed abstain checker, the calibration
// report is a fixture record, the grant is a zero-budget no-provider grant) ----

const DIGEST_RUBRIC = '9559406c3f14249f7c5302b44fddcfe1bc286af0da51e324468f5020062bd0dc'; // corpus/s2-006/rubric-v1.json
const DIGEST_MANIFEST = '93ca54b2a954fdaffe93616b66c4efdcd70c43e971572b552a5b468c24c6cce0'; // corpus/s2-006/manifest.json
const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);
const HEX_C = 'c'.repeat(64);
const HEX_D = 'd'.repeat(64);

// fix2: the replay artifact is the schema-valid canonical claim fixture —
// the verifier fail-closed validates upstream payloads against the frozen
// producer contract (review P1: ArtifactContractViolation), so a homemade
// claim shape is correctly rejected before persistence.
const PAYLOAD = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'tests/verifier/fixtures/canonical/claim.json'), 'utf8'),
);

function makeRequest() {
  const base = {
    contractVersion: '1.0.0',
    requestId: 'svr-db-replay-1',
    actor: ACTOR,
    workspaceId: WORKSPACE,
    artifact: { kind: 'claim', artifactId: 'clm-alpha-1', revision: 1, digest: canonicalDigest(PAYLOAD) },
    requestedChecks: ['citation_entailment'],
    asOf: '2026-03-22T00:00:00.000Z',
    aclGrantRef: 'cap-verifier.read',
    rubricVersion: '1.0.0',
    corpusVersion: '1.0.0',
    thresholdVersion: '1.0.0',
    idempotencyKey: 'idem-db-replay-1',
  };
  base.canonicalArgsDigest = computeCanonicalArgsDigest(base);
  return base;
}

// Typed abstain checker: the replay exercises store persistence/idempotency,
// never a semantic pass; INSUFFICIENT_EVIDENCE is an abstention, not a fail.
const ABSTAIN_CHECKER = { check: () => ({ verdict: 'INSUFFICIENT_EVIDENCE', reasonCodes: ['missing_citation'] }) };
const ALLOW_ALL_ACL = { can: () => true };

async function verifiedResultFixture() {
  const request = makeRequest();
  const { result } = await verifyClaim(request, {
    checker: ABSTAIN_CHECKER,
    acl: ALLOW_ALL_ACL,
    digests: { rubricDigest: DIGEST_RUBRIC, corpusManifestDigest: DIGEST_MANIFEST, thresholdsDigest: HEX_A },
    artifact: { kind: 'claim', artifactId: request.artifact.artifactId, revision: 1, payload: PAYLOAD },
  });
  return { request, result };
}

function calibrationReportFixture() {
  return {
    contractVersion: '1.0.0',
    reportId: 'rep-db-replay-fixture-1',
    corpusVersion: '1.0.0',
    rubricDigest: DIGEST_RUBRIC,
    thresholdsDigest: HEX_B,
    metricRecords: [
      { name: 'decision_availability', numerator: 45, denominator: 45, missingCount: 0, value: 1, intervalMethod: 'wilson', interval: { lower: 0.9212, upper: 1, confidenceLevel: 0.95 }, status: 'MEASURED' },
      { name: 'inter_annotator_agreement', numerator: 42, denominator: 45, missingCount: 0, value: null, intervalMethod: 'none', interval: null, status: 'NOT_MEASURED', notMeasuredReason: 'evaluator_not_independent' },
    ],
    confusionMatrices: [
      { name: 'SUPPORTED', truePositive: 8, falsePositive: 0, falseNegative: 0, trueNegative: 37, missing: 0 },
    ],
    slices: [
      { name: 'fixture-all', stratum: 'fixture', caseCount: 45, metricNames: ['decision_availability'] },
    ],
    selectiveRisk: { risk: null, coverage: 0.5778, curve: [{ coverage: 0.5778, risk: 0.0769 }] },
    coverage: { denominator: 45, evaluated: 45, missing: 0, floor: 0 },
    thresholdDecision: { thresholdsDigest: HEX_B, status: 'NEEDS_INPUT', ownerDecisionRef: null, appliedAt: null },
    independenceTier: 'NOT_INDEPENDENT',
    limitations: ['Store-replay fixture report; the measured calibration aggregate lives in evidence/s2-006-calibration.json.'],
    expiry: { at: '2027-01-01T00:00:00.000Z', cause: 'corpus_drift' },
    driftScope: ['corpus/s2-006@1.0.0', 'rub-s2006-semantic-v1@1.0.0', 'contracts/s2-006-thresholds.json (NEEDS_INPUT preregistration)'],
  };
}

function adjudicationFixture() {
  // The real frozen adjudication record of the fixture corpus (case-s2006-05).
  const all = JSON.parse(fs.readFileSync(path.join(ROOT, 'corpus/s2-006/adjudication.json'), 'utf8'));
  return all[0];
}

function grantFixture() {
  return {
    contractVersion: '1.0.0',
    grantId: 'grt-db-replay-1',
    authenticatedPrincipal: ACTOR,
    tool: 'semantic-verifier',
    workspaceId: WORKSPACE,
    modelAccess: { modelId: 'offline-deterministic', modelVersion: '1.0.0', access: 'inference_only' },
    currency: 'none',
    timeoutMs: 30000,
    budget: { task: 0, campaign: 0, day: 0 },
    noTraining: true,
    noRetention: true,
    issuedAt: '2026-03-01T00:00:00.000Z',
    expiresAt: '2027-01-01T00:00:00.000Z',
  };
}

const AUTHORITIES = makeVerifierAuthorityRegistry([
  { principal: ACTOR, roles: ['evaluation_harness'], workspaces: [WORKSPACE] },
  { principal: ADJUDICATOR, roles: ['adjudicator'], workspaces: [WORKSPACE] },
  { principal: 'prn-reviewer-1', roles: ['reviewer'], workspaces: [WORKSPACE] },
]);

// Fixture custody key of the grant ISSUER (review P1-2): the beneficiary —
// the evaluation harness — can never issue its own grant, so a reviewer
// signs the exact canonical grant digest and the MAC is verified at
// registration AND at every use. Test-only fixture material.
const GRANT_KEY_REF = 'kms://fixture/s2-006/db-replay/grant-issuer';
const GRANT_ISSUER = 'prn-reviewer-1';
const GRANT_KEY_REGISTRY = new Map();
registerKey({
  keyRef: GRANT_KEY_REF,
  secret: 's2-006-fixture-db-replay-grant-issuer-key',
  custodian: GRANT_ISSUER,
  role: 'reviewer',
  registry: GRANT_KEY_REGISTRY,
});

// Registers the reviewer-issued grant once per process (registerProviderGrant
// verifies the issuer role/workspace, the non-self-issuance and the MAC).
function registeredGrant() {
  const grant = grantFixture();
  registerProviderGrant(AUTHORITIES, {
    grant,
    issuer: GRANT_ISSUER,
    signature: sign(GRANT_ISSUER, GRANT_KEY_REF, canonicalDigest(grant), { registry: GRANT_KEY_REGISTRY }),
    registry: GRANT_KEY_REGISTRY,
  });
  return grant;
}

const GRANT = registeredGrant();

// ---- child: one deterministic store-replay against one schema ----------------

async function runChild({ schema, runId, executorId, out, databaseUrl }) {
  const pg = (await import('pg')).default;
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 2, options: `-c search_path=${schema}` });
  const store = new PostgresVerifierStore(pool, { clock: FIXED_CLOCK });
  const ops = [];
  const record = async (operationId, op, fn) => {
    try {
      const outcome = await fn();
      ops.push({ operationId, op, ok: true, error: null, ...outcome });
    } catch (error) {
      ops.push({ operationId, op, ok: false, error: `${error.name ?? 'Error'}: ${error.message}`, replayed: false, outcomeDigest: null });
    }
  };

  const { request, result } = await verifiedResultFixture();

  await record('op-s2006-replay-publish-01', 'publishVerificationResult', async () => {
    const published = await publishVerificationResult({
      store, authorities: AUTHORITIES, actor: ACTOR, request, result,
      operationId: 'op-s2006-replay-publish-01',
    });
    return { replayed: published.replayed, outcomeDigest: published.outcomeDigest };
  });
  await record('op-s2006-replay-replay-01', 'publishVerificationResultReplay', async () => {
    const replayed = await publishVerificationResult({
      store, authorities: AUTHORITIES, actor: ACTOR, request, result,
      operationId: 'op-s2006-replay-publish-01',
    });
    return { replayed: replayed.replayed, outcomeDigest: replayed.outcomeDigest };
  });
  await record('op-s2006-replay-calibration-01', 'publishCalibrationReport', async () => {
    const published = await publishCalibrationReport({
      store, authorities: AUTHORITIES, actor: ACTOR,
      report: calibrationReportFixture(), operationId: 'op-s2006-replay-calibration-01', workspaceId: WORKSPACE,
    });
    return { replayed: published.replayed, outcomeDigest: published.outcomeDigest };
  });
  await record('op-s2006-replay-adjudication-01', 'publishAdjudication', async () => {
    const published = await publishAdjudication({
      store, authorities: AUTHORITIES, actor: ADJUDICATOR,
      adjudication: adjudicationFixture(), operationId: 'op-s2006-replay-adjudication-01', workspaceId: WORKSPACE,
    });
    return { replayed: published.replayed, outcomeDigest: published.outcomeDigest };
  });
  await record('op-s2006-replay-external-01', 'externalCallReserveAcceptFinalize', async () => {
    const reserved = await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: ACTOR, grant: GRANT,
      callId: 'call-s2006-replay-1', operationId: 'op-s2006-replay-external-01',
      reservation: { purpose: 'store-replay fixture; no provider is called' }, workspaceId: WORKSPACE,
      now: FIXED_CLOCK(), keyRegistry: GRANT_KEY_REGISTRY,
    });
    await acceptExternalCall({ store, actor: ACTOR, callId: reserved.callId, fencingToken: reserved.fencingToken });
    const finalized = await finalizeExternalCall({
      store, actor: ACTOR, callId: reserved.callId, fencingToken: reserved.fencingToken,
      responseDigest: canonicalDigest({ replay: 'fixture-response', abstention: 'INSUFFICIENT_EVIDENCE' }),
      settlement: { amount: 0, currency: 'none', note: 'zero-budget no-provider fixture' },
      outcome: 'finalized',
    });
    return { replayed: finalized.replayed ?? false, outcomeDigest: canonicalDigest({ state: finalized.state ?? 'FINALIZED', fencingToken: reserved.fencingToken }), fencingToken: reserved.fencingToken };
  });

  const count = async (table) => Number((await pool.query(`SELECT count(*)::int AS n FROM ${schema}.${table}`)).rows[0].n);
  const rows = {
    verifier_request: await count('verifier_request'),
    verifier_result: await count('verifier_result'),
    verifier_calibration_report: await count('verifier_calibration_report'),
    verifier_adjudication_record: await count('verifier_adjudication_record'),
    verifier_operation_ledger: await count('verifier_operation_ledger'),
    verifier_audit_outbox: await count('verifier_audit_outbox'),
    verifier_external_call_run: await count('verifier_external_call_run'),
  };
  const ledger = (await pool.query(`SELECT operation_id, status, idempotency_key FROM ${schema}.verifier_operation_ledger ORDER BY operation_id`)).rows;
  const outbox = (await pool.query(`SELECT event_id, event_type, operation_id FROM ${schema}.verifier_audit_outbox ORDER BY event_id`)).rows;
  const externalCall = (await pool.query(`SELECT call_id, state, fencing_token FROM ${schema}.verifier_external_call_run ORDER BY call_id`)).rows;
  await pool.end();

  const committedOps = ops.filter((o) => o.ok && !o.replayed).length;
  const replayedOps = ops.filter((o) => o.ok && o.replayed).length;
  const errors = ops.filter((o) => !o.ok);
  const report = {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'deterministic verifier store replay on PostgreSQL (PostgresVerifierStore, migration 0005)',
    runId,
    executorId,
    pid: process.pid,
    databaseEngine: 'PostgreSQL',
    schema,
    ops,
    committedOps,
    replayedOps,
    errorOps: errors.length,
    rows,
    ledger,
    outbox,
    externalCall,
    status: errors.length === 0 && committedOps >= 4 ? 'COMPLETED' : 'ERROR',
    digest: canonicalDigest({ ops: ops.map(({ operationId, op, ok, replayed, outcomeDigest }) => ({ operationId, op, ok, replayed, outcomeDigest })), rows, ledger, outbox, externalCall }),
  };
  fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  process.exit(report.status === 'COMPLETED' ? 0 : 2);
}

// ---- crash/restart phase (probe S DB half; review P2-6 + fix2-D finding 5)
// Two SEPARATE OS processes per schema drive the FULL production recovery
// sequence — a recovery that finalizes an ACCEPTED call directly with a
// pre-known digest/settlement is NOT reconciliation and fails this phase:
//   crash-first : reserve -> accept -> abrupt death (exit 70) WITHOUT any
//                 finalize — the provider outcome never lands;
//   crash-recover: a NEW process/pool (1) OBSERVES the atomic escalation of
//                 the call into RECONCILIATION_REQUIRED (state + reason +
//                 exactly one outbox event, one transaction), (2) proves the
//                 reconciled call is fenced (stale fencing refused,
//                 escalation replay idempotent, direct finalize = blind
//                 retry REFUSED, settlement stays null), (3) resolves the
//                 outcome through an AUTHORIZED reconciliation decision — a
//                 reviewer-issued grant naming the EXACT resolving actor —
//                 whose replacement call settles EXACTLY ONCE, and (4) a
//                 duplicate resolution replays without a second event.

const CRASH_CALL = 'call-s2006-crash-1';
const CRASH_OPERATION = 'op-s2006-crash-external-1';
const CRASH_RESOLUTION_CALL = 'call-s2006-crash-resolution-1';
const CRASH_REASON = 'crash/restart replay: process 1 died after REQUEST_ACCEPTED; provider outcome unknown';
const CRASH_RESPONSE_DIGEST = canonicalDigest({ replay: 'crash-recovery', verdict: 'INSUFFICIENT_EVIDENCE' });
const CRASH_SETTLEMENT = { amount: 0, currency: 'none', note: 'authorized reconciliation settlement; fenced, exactly once' };
const CRASH_RESERVATION = { purpose: 'crash/restart replay: reserved + accepted, then the process dies without finalize' };
const CRASH_DECISION = {
  decisionId: 'recd-s2006-crash-1',
  reconcilesCallId: CRASH_CALL,
  resolution: { replacementCallId: CRASH_RESOLUTION_CALL, responseDigest: CRASH_RESPONSE_DIGEST, settlement: CRASH_SETTLEMENT },
  role: 'evaluation_harness',
};

// The reconciliation decision grant: reviewer-ISSUED, names the EXACT
// resolving actor (the evaluation harness). registerProviderGrant verifies
// the issuer role/workspace, non-self-issuance and the issuer MAC at
// registration; requireGrant re-verifies registry resolution, digest,
// issuer/beneficiary separation, expiry (against the injected clock) and
// the MAC at EVERY use — a decision without this authority cannot reserve
// the resolution call.
function reconciliationDecisionGrant() {
  return {
    contractVersion: '1.0.0',
    grantId: 'grt-s2006-crash-reconcile',
    authenticatedPrincipal: ACTOR,
    tool: 'reconciliation-resolution',
    workspaceId: WORKSPACE,
    modelAccess: { modelId: 'none', modelVersion: '1.0.0', access: 'inference_only' },
    currency: 'none',
    timeoutMs: 30000,
    budget: { task: 0, campaign: 0, day: 0 },
    noTraining: true,
    noRetention: true,
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2027-01-01T00:00:00.000Z',
  };
}

async function crashFirstChild({ schema, executorId, stateFile, databaseUrl }) {
  const pg = (await import('pg')).default;
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 1, options: `-c search_path=${schema}` });
  const store = new PostgresVerifierStore(pool, { clock: FIXED_CLOCK });
  const reserved = await reserveExternalCall({
    store, authorities: AUTHORITIES, actor: ACTOR, grant: GRANT,
    callId: CRASH_CALL, operationId: CRASH_OPERATION,
    reservation: CRASH_RESERVATION, workspaceId: WORKSPACE,
    now: FIXED_CLOCK(), keyRegistry: GRANT_KEY_REGISTRY,
  });
  await acceptExternalCall({ store, actor: ACTOR, callId: reserved.callId, fencingToken: reserved.fencingToken, workspaceId: WORKSPACE });
  fs.writeFileSync(stateFile, `${JSON.stringify({
    schema,
    callId: reserved.callId,
    fencingToken: reserved.fencingToken,
    crashFirstPid: process.pid,
    crashFirstExecutor: executorId,
  }, null, 2)}\n`);
  await pool.end();
  // die as designed: no finalize, no settlement — the recovery process must
  // observe the reconciliation escalation before ANY outcome is recorded
  process.exit(70);
}

async function crashRecoverChild({ schema, runId, executorId, stateFile, out, databaseUrl }) {
  const handoff = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  const pg = (await import('pg')).default;
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 1, options: `-c search_path=${schema}` });
  const store = new PostgresVerifierStore(pool, { clock: FIXED_CLOCK });
  const checks = {};
  const count = async (sql, params = []) => Number((await pool.query(sql, params)).rows[0].n);

  // 1. the crashed process left the call in ACCEPTED (crash after REQUEST_ACCEPTED)
  const crashed = await store.readExternalCall(handoff.callId);
  checks.crashedCallObservedInAcceptedState = crashed?.state === 'ACCEPTED' && Number(crashed.fencing_token) === handoff.fencingToken;

  // 2. a stale fencing token can never touch the call
  let staleRefused = false;
  try {
    await finalizeExternalCall({ store, actor: ACTOR, callId: handoff.callId, fencingToken: handoff.fencingToken + 999, responseDigest: CRASH_RESPONSE_DIGEST, settlement: CRASH_SETTLEMENT, workspaceId: WORKSPACE, grant: GRANT });
  } catch (error) {
    staleRefused = error instanceof AclDenied;
  }
  checks.staleFencingRefused = staleRefused;

  // 3. OBSERVED atomic escalation (fix2-C mechanism): the unknown outcome
  // moves the call into RECONCILIATION_REQUIRED — state + reason + outbox
  // event in ONE transaction. The recovery process finalizes NOTHING here.
  const escalated = await finalizeExternalCall({ store, actor: ACTOR, callId: handoff.callId, fencingToken: handoff.fencingToken, outcome: 'unknown', reason: CRASH_REASON, workspaceId: WORKSPACE });
  const reconciled = await store.readExternalCall(handoff.callId);
  checks.reconciliationObserved = escalated.state === 'RECONCILIATION_REQUIRED' && escalated.replayed === false
    && reconciled.state === 'RECONCILIATION_REQUIRED';
  checks.reconciliationReasonRecorded = reconciled.reconcile_reason === CRASH_REASON;

  // 4. the escalation replay is idempotent: no second reconciliation event
  const escalateAgain = await finalizeExternalCall({ store, actor: ACTOR, callId: handoff.callId, fencingToken: handoff.fencingToken, outcome: 'unknown', reason: CRASH_REASON, workspaceId: WORKSPACE });
  checks.escalationReplayIdempotent = escalateAgain.replayed === true
    && (await count("SELECT count(*)::int AS n FROM verifier_audit_outbox WHERE event_type = 'EXTERNAL_CALL_RECONCILIATION_REQUIRED' AND record_id = $1", [handoff.callId])) === 1;

  // 5. BLIND RETRY REFUSED: a direct finalize over the reconciled call can
  // never record a result; the call stays RECONCILIATION_REQUIRED, null-settled.
  let blindRetryRefused = false;
  try {
    await finalizeExternalCall({ store, actor: ACTOR, callId: handoff.callId, fencingToken: handoff.fencingToken, responseDigest: CRASH_RESPONSE_DIGEST, settlement: CRASH_SETTLEMENT, workspaceId: WORKSPACE, grant: GRANT });
  } catch (error) {
    blindRetryRefused = error instanceof ReconciliationRequired;
  }
  checks.blindRetryRefused = blindRetryRefused;
  const afterBlindRetry = await store.readExternalCall(handoff.callId);
  checks.reconciledCallNeverFinalized = afterBlindRetry.state === 'RECONCILIATION_REQUIRED' && afterBlindRetry.settlement === null;

  // 6. the AUTHORIZED reconciliation decision: a reviewer-issued grant names
  // the exact resolving actor; a same-workspace principal with a different
  // identity (the adjudicator) and an unregistered forged grant are both
  // REFUSED before any resolution call can exist.
  const decisionGrant = reconciliationDecisionGrant();
  registerProviderGrant(AUTHORITIES, {
    grant: decisionGrant,
    issuer: GRANT_ISSUER,
    signature: sign(GRANT_ISSUER, GRANT_KEY_REF, canonicalDigest(decisionGrant), { registry: GRANT_KEY_REGISTRY }),
    registry: GRANT_KEY_REGISTRY,
  });
  const decisionReservation = {
    reconcilesCallId: handoff.callId,
    observedState: reconciled.state,
    observedReason: reconciled.reconcile_reason,
    decisionDigest: canonicalDigest({ ...CRASH_DECISION, observedState: reconciled.state, observedReason: reconciled.reconcile_reason }),
  };
  let wrongActorRefused = false;
  try {
    await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: ADJUDICATOR, grant: decisionGrant,
      callId: CRASH_RESOLUTION_CALL, operationId: CRASH_OPERATION,
      reservation: decisionReservation, workspaceId: WORKSPACE,
      now: FIXED_CLOCK(), keyRegistry: GRANT_KEY_REGISTRY,
    });
  } catch (error) {
    wrongActorRefused = error instanceof AclDenied;
  }
  const forgedGrant = { ...decisionGrant, grantId: 'grt-s2006-crash-reconcile-forged' };
  let forgedGrantRefused = false;
  try {
    await reserveExternalCall({
      store, authorities: AUTHORITIES, actor: ACTOR, grant: forgedGrant,
      callId: 'call-s2006-crash-forged', operationId: CRASH_OPERATION,
      reservation: decisionReservation, workspaceId: WORKSPACE,
      now: FIXED_CLOCK(), keyRegistry: GRANT_KEY_REGISTRY,
    });
  } catch (error) {
    forgedGrantRefused = error instanceof AclDenied;
  }
  checks.unauthorizedDecisionRefused = wrongActorRefused && forgedGrantRefused;

  // 7. authorized resolution: the replacement call settles EXACTLY ONCE.
  const replacement = await reserveExternalCall({
    store, authorities: AUTHORITIES, actor: ACTOR, grant: decisionGrant,
    callId: CRASH_RESOLUTION_CALL, operationId: CRASH_OPERATION,
    reservation: { ...decisionReservation, purpose: 'authorized reconciliation resolution' },
    workspaceId: WORKSPACE, now: FIXED_CLOCK(), keyRegistry: GRANT_KEY_REGISTRY,
  });
  checks.reconciliationDecisionAuthorized = replacement.replayed === false && replacement.state === 'RESERVED';
  await acceptExternalCall({ store, actor: ACTOR, callId: replacement.callId, fencingToken: replacement.fencingToken, workspaceId: WORKSPACE });
  const settled = await finalizeExternalCall({ store, actor: ACTOR, callId: replacement.callId, fencingToken: replacement.fencingToken, responseDigest: CRASH_RESPONSE_DIGEST, settlement: CRASH_SETTLEMENT, workspaceId: WORKSPACE, grant: decisionGrant });
  checks.resolutionSettledExactlyOnce = settled.state === 'FINALIZED' && settled.replayed === false;
  // 8. a duplicate resolution replays WITHOUT a second event
  const duplicate = await finalizeExternalCall({ store, actor: ACTOR, callId: replacement.callId, fencingToken: replacement.fencingToken, responseDigest: CRASH_RESPONSE_DIGEST, settlement: CRASH_SETTLEMENT, workspaceId: WORKSPACE, grant: decisionGrant });
  checks.duplicateResolutionReplayed = duplicate.replayed === true;

  // counts over the whole schema: no duplicate ledger/outbox writes, the
  // reconciled call is never finalized, the operation settled EXACTLY once
  const counts = {};
  counts.outboxTotal = await count('SELECT count(*)::int AS n FROM verifier_audit_outbox');
  counts.ledgerTotal = await count('SELECT count(*)::int AS n FROM verifier_operation_ledger');
  counts.externalCallRows = await count('SELECT count(*)::int AS n FROM verifier_external_call_run');
  counts.crashCallEvents = await count('SELECT count(*)::int AS n FROM verifier_audit_outbox WHERE record_id = $1', [handoff.callId]);
  counts.crashCallReconciliationEvents = await count("SELECT count(*)::int AS n FROM verifier_audit_outbox WHERE record_id = $1 AND event_type = 'EXTERNAL_CALL_RECONCILIATION_REQUIRED'", [handoff.callId]);
  counts.crashCallFinalizedEvents = await count("SELECT count(*)::int AS n FROM verifier_audit_outbox WHERE record_id = $1 AND event_type = 'EXTERNAL_CALL_FINALIZED'", [handoff.callId]);
  counts.operationFinalizedEvents = await count("SELECT count(*)::int AS n FROM verifier_audit_outbox WHERE operation_id = $1 AND event_type = 'EXTERNAL_CALL_FINALIZED'", [CRASH_OPERATION]);
  counts.operationSettledCalls = await count("SELECT count(*)::int AS n FROM verifier_external_call_run WHERE operation_id = $1 AND state = 'FINALIZED' AND settlement IS NOT NULL", [CRASH_OPERATION]);
  counts.duplicateOutboxIds = await count('SELECT count(*)::int AS n FROM (SELECT event_id FROM verifier_audit_outbox GROUP BY event_id HAVING count(*) > 1) AS d');
  const countsExpected = {
    outboxTotal: 12, // 3 publishes + main call RESERVED/ACCEPTED/FINALIZED + crash call RESERVED/ACCEPTED/RECONCILIATION_REQUIRED + resolution call RESERVED/ACCEPTED/FINALIZED
    ledgerTotal: 3,
    externalCallRows: 3, // main replay call + reconciled crash call + authorized resolution call
    crashCallEvents: 3,
    crashCallReconciliationEvents: 1,
    crashCallFinalizedEvents: 0, // the reconciled call is NEVER finalized
    operationFinalizedEvents: 1, // the authorized resolution settles EXACTLY once
    operationSettledCalls: 1,
    duplicateOutboxIds: 0,
  };
  checks.reconciliationEventAtomicSingle = counts.crashCallReconciliationEvents === 1 && counts.crashCallEvents === 3;
  const countsOk = Object.entries(countsExpected).every(([k, v]) => counts[k] === v);
  const report = {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'crash/restart replay (probe S DB half): the first process died after REQUEST_ACCEPTED (exit 70, no finalize); this recovery process OBSERVED the atomic RECONCILIATION_REQUIRED escalation, proved blind retry is refused, resolved the outcome through an AUTHORIZED reconciliation decision (reviewer-issued, actor-exact) and settled EXACTLY once',
    runId,
    executorId,
    schema,
    recoveryPid: process.pid,
    crashFirstPid: handoff.crashFirstPid,
    crashFirstExecutor: handoff.crashFirstExecutor,
    fencingToken: handoff.fencingToken,
    decision: { decisionGrantRef: decisionGrant.grantId, decidedBy: ACTOR, reconcilesCallId: handoff.callId },
    checks,
    counts,
    countsExpected,
    status: Object.values(checks).every((v) => v === true) && countsOk ? 'COMPLETED' : 'ERROR',
    digest: canonicalDigest({ checks, counts, fencingToken: handoff.fencingToken }),
  };
  fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  await pool.end();
  process.exit(report.status === 'COMPLETED' ? 0 : 2);
}

// Fail-closed comparison of the two schema crash/restart reports.
export function crashPhaseIssues(a, b) {
  const issues = [];
  for (const [label, r] of [['a', a], ['b', b]]) {
    if (r.diedAsDesigned !== true) issues.push(`crash-${label}:first-process-exit-${r.crashFirstExitCode}`);
    if (r.status !== 'COMPLETED') issues.push(`crash-${label}:not-completed`);
    for (const [check, ok] of Object.entries(r.checks ?? {})) {
      if (ok !== true) issues.push(`crash-${label}:check-${check}`);
    }
    for (const [name, value] of Object.entries(r.counts ?? {})) {
      if (value !== r.countsExpected?.[name]) issues.push(`crash-${label}:count-${name}`);
    }
  }
  if (a.digest !== b.digest) issues.push('crash:digest-mismatch');
  if (a.executorId === b.executorId) issues.push('crash:executor-identical');
  if (a.recoveryPid === b.recoveryPid) issues.push('crash:recovery-pid-identical');
  if (a.crashFirstPid === b.crashFirstPid) issues.push('crash:first-pid-identical');
  return issues;
}

// ---- comparison ---------------------------------------------------------------

export function dbReplayIssues(a, b) {
  const issues = [];
  for (const [label, run] of [['a', a], ['b', b]]) {
    if (run.status !== 'COMPLETED') issues.push(`run-${label}:not-completed`);
    if (run.errorOps !== 0) issues.push(`run-${label}:error-ops-${run.errorOps}`);
    if (!(run.committedOps >= 4)) issues.push(`run-${label}:degenerate-committed-${run.committedOps}`);
    for (const [table, expected] of [['verifier_request', 1], ['verifier_result', 1], ['verifier_calibration_report', 1], ['verifier_adjudication_record', 1]]) {
      if (run.rows?.[table] !== expected) issues.push(`run-${label}:${table}-count-${run.rows?.[table]}`);
    }
    // Exact counts: 3 ledger rows (the idempotent replay of op-01 correctly
    // returns the recorded outcome WITHOUT a second ledger row) and 6 outbox
    // events (3 publishes + RESERVED/ACCEPTED/FINALIZED of the external call).
    if (run.rows?.verifier_operation_ledger !== 3) issues.push(`run-${label}:ledger-count-${run.rows?.verifier_operation_ledger}`);
    if (run.rows?.verifier_audit_outbox !== 6) issues.push(`run-${label}:outbox-count-${run.rows?.verifier_audit_outbox}`);
    const outboxIds = (run.outbox ?? []).map((e) => e.event_id);
    if (new Set(outboxIds).size !== outboxIds.length) issues.push(`run-${label}:duplicate-outbox-events`);
  }
  if (a.digest !== b.digest) issues.push('comparison:replay-digest-mismatch');
  if (a.executorId === b.executorId) issues.push('identity:executor-identical');
  if (a.pid === b.pid) issues.push('identity:pid-identical');
  return issues;
}

// ---- coordinator ---------------------------------------------------------------

async function coordinator(args) {
  const writeEvidence = args.write === 'true';
  const outDir = writeEvidence ? path.join(ROOT, 'evidence') : path.join(ROOT, 'results/s2-006');
  fs.mkdirSync(outDir, { recursive: true });
  const writeReport = (report, exitCode) => {
    const target = path.join(outDir, 's2-006-db-comparison.json');
    fs.writeFileSync(target, `${JSON.stringify({ ...report, exitCode }, null, 2)}\n`);
    console.log(JSON.stringify(report, null, 2));
    process.exit(exitCode);
  };

  let connectionString = process.env.DATABASE_URL ?? null;
  let external = Boolean(connectionString);
  let containerStarted = false;
  if (!connectionString) {
    if (!podmanAvailable()) {
      writeReport({
        schemaVersion: 1,
        ticket: 'S2-006',
        role: 'PostgreSQL two-process verifier store replay',
        status: 'NOT_RUN_DB',
        ok: false,
        reason: 'no DATABASE_URL and no usable podman/WSL environment; the persistence gate is NOT passed (spec §11: NOT_RUN_DB + NEEDS_INPUT, never a silent skip)',
        databaseEngine: 'PostgreSQL',
      }, 0);
      return;
    }
    const { freePort, waitForPostgres } = await import('./verify-postgres-smoke.mjs');
    const port = await freePort();
    const secret = randomBytes(24).toString('hex');
    const user = 'veritas_s2_006_replay';
    const database = 'veritas_s2_006_replay';
    const connectionUrl = new URL(`postgresql://127.0.0.1:${port}/${database}`);
    connectionUrl.username = user;
    connectionUrl.password = secret;
    connectionString = connectionUrl.toString();
    cleanupContainer();
    try {
      execFileSync('wsl.exe', ['-d', DISTRO, '--', 'podman', 'run', '--detach', `--name=${CONTAINER}`, '--pull=never',
        '--publish', `127.0.0.1:${port}:5432`, '--read-only', '--user=70:70', '--cap-drop', 'all',
        '--security-opt', 'no-new-privileges', '--pids-limit=64', '--memory=256m',
        '--memory-swap=256m', '--cpus=1',
        '--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=192m,mode=1777',
        '--tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=4m,mode=1777',
        '--env', 'PGDATA=/var/lib/postgresql/data/pgdata',
        '--env', `POSTGRES_USER=${user}`, '--env', `POSTGRES_PASSWORD=${secret}`, '--env', `POSTGRES_DB=${database}`,
        'docker.io/library/postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73',
      ], { encoding: 'utf8', timeout: 60000, windowsHide: true });
      containerStarted = true;
      await waitForPostgres(connectionString);
    } catch (error) {
      if (containerStarted) cleanupContainer();
      writeReport({
        schemaVersion: 1,
        ticket: 'S2-006',
        role: 'PostgreSQL two-process verifier store replay',
        status: 'NOT_RUN_DB',
        ok: false,
        reason: `ephemeral PostgreSQL could not be provisioned: ${String(error.message ?? error).slice(0, 400)}`,
        databaseEngine: 'PostgreSQL',
      }, 0);
      return;
    }
  }

  try {
    const { applyMigrations } = await import('./apply-migrations.mjs');
    const pg = (await import('pg')).default;
    const migrations = [];
    for (const schema of ['run_a', 'run_b']) {
      const bootstrap = new pg.Pool({ connectionString, max: 1 });
      await bootstrap.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
      await bootstrap.end();
      const schemaPool = new pg.Pool({ connectionString, max: 1, options: `-c search_path=${schema}` });
      const migration = await applyMigrations({ connectionString, root: ROOT, pool: schemaPool });
      migrations.push({ schema, migrations: migration.migrations });
      await schemaPool.end();
    }

    const runParams = [
      { schema: 'run_a', runId: 's2-006-db-run-a', executorId: 'exec-db-s2006-a' },
      { schema: 'run_b', runId: 's2-006-db-run-b', executorId: 'exec-db-s2006-b' },
    ];
    const summaries = [];
    for (const [i, params] of runParams.entries()) {
      const outFile = path.join(os.tmpdir(), `s2-006-db-run-${i === 0 ? 'a' : 'b'}-${process.pid}.json`);
      const child = spawnSync(process.execPath, [
        path.join(ROOT, 'scripts/s2-006-db-replay.mjs'),
        '--child', '--schema', params.schema, '--run-id', params.runId,
        '--executor-id', params.executorId, '--out', outFile,
      ], { cwd: ROOT, encoding: 'utf8', timeout: 300000, env: { ...process.env, VERITAS_DB_URL: connectionString } });
      if (child.status !== 0 && child.status !== 2) {
        throw new Error(`DB_RUN_FAILED:${params.runId} exit=${child.status} stderr=${String(child.stderr).slice(0, 600)}`);
      }
      summaries.push(JSON.parse(fs.readFileSync(outFile, 'utf8')));
      fs.unlinkSync(outFile);
    }

    const [a, b] = summaries;
    const issues = dbReplayIssues(a, b);

    // ---- third phase: crash/restart (probe S DB half; review P2-6) --------
    const crashRuns = [];
    for (const [i, params] of runParams.entries()) {
      const suffix = i === 0 ? 'a' : 'b';
      const stateFile = path.join(os.tmpdir(), `s2-006-crash-state-${suffix}-${process.pid}.json`);
      const recoverOut = path.join(os.tmpdir(), `s2-006-crash-recover-${suffix}-${process.pid}.json`);
      const first = spawnSync(process.execPath, [
        path.join(ROOT, 'scripts/s2-006-db-replay.mjs'),
        '--child', '--crash-first', 'true', '--schema', params.schema,
        '--run-id', `s2-006-db-crash-${suffix}`, '--executor-id', `exec-db-s2006-dies-${suffix}`,
        '--state', stateFile,
      ], { cwd: ROOT, encoding: 'utf8', timeout: 300000, env: { ...process.env, VERITAS_DB_URL: connectionString } });
      // exit 70 = died as designed (accepted, then killed without finalize)
      const diedAsDesigned = first.status === 70;
      if (!diedAsDesigned) {
        throw new Error(`CRASH_FIRST_NOT_DIED:${params.schema} exit=${first.status} stderr=${String(first.stderr).slice(0, 400)}`);
      }
      const recover = spawnSync(process.execPath, [
        path.join(ROOT, 'scripts/s2-006-db-replay.mjs'),
        '--child', '--crash-recover', 'true', '--schema', params.schema,
        '--run-id', `s2-006-db-crash-${suffix}`, '--executor-id', `exec-db-s2006-crash-${suffix}`,
        '--state', stateFile, '--out', recoverOut,
      ], { cwd: ROOT, encoding: 'utf8', timeout: 300000, env: { ...process.env, VERITAS_DB_URL: connectionString } });
      if (recover.status !== 0 && recover.status !== 2) {
        throw new Error(`CRASH_RECOVER_FAILED:${params.schema} exit=${recover.status} stderr=${String(recover.stderr).slice(0, 600)}`);
      }
      crashRuns.push({ ...JSON.parse(fs.readFileSync(recoverOut, 'utf8')), diedAsDesigned, crashFirstExitCode: first.status });
      fs.unlinkSync(stateFile);
      fs.unlinkSync(recoverOut);
    }
    const [crashA, crashB] = crashRuns;
    const crashIssues = crashPhaseIssues(crashA, crashB);
    const allIssues = [...issues, ...crashIssues.map((c) => `crash-phase:${c}`)];
    const report = {
      schemaVersion: 1,
      ticket: 'S2-006',
      role: 'S2-006 DB-backed verifier store replay A vs B (PostgresVerifierStore, separate OS processes) + crash/restart phase (probe S DB half)',
      databaseEngine: 'PostgreSQL',
      databaseSource: external ? 'external DATABASE_URL' : 'ephemeral loopback-only podman container',
      schemas: ['run_a', 'run_b'],
      migrations,
      pids: { run_a: a.pid, run_b: b.pid },
      executors: { run_a: a.executorId, run_b: b.executorId },
      rows: a.rows,
      committedOps: a.committedOps,
      replayedOps: a.replayedOps,
      digests: { run_a: a.digest, run_b: b.digest },
      crashPhase: {
        ok: crashIssues.length === 0,
        issues: crashIssues,
        executors: { run_a: crashA.executorId, run_b: crashB.executorId },
        crashFirstExecutors: { run_a: crashA.crashFirstExecutor, run_b: crashB.crashFirstExecutor },
        pids: { recovery: { run_a: crashA.recoveryPid, run_b: crashB.recoveryPid }, crash_first: { run_a: crashA.crashFirstPid, run_b: crashB.crashFirstPid } },
        fencingToken: crashA.fencingToken,
        digests: { run_a: crashA.digest, run_b: crashB.digest },
        counts: crashA.counts,
        scenario: 'process 1: reserve -> accept -> abrupt death (exit 70, no finalize); process 2: fenced reconciliation over the fencing token, exactly one settlement, zero duplicate ledger/outbox writes',
      },
      comparison: { ok: allIssues.length === 0, issues: allIssues },
      hardGates: { ok: allIssues.length === 0, violations: allIssues },
      status: allIssues.length === 0 ? 'PASS' : 'FAIL',
      ok: allIssues.length === 0,
    };
    if (writeEvidence) {
      fs.writeFileSync(path.join(ROOT, 'evidence/s2-006-db-run-a.json'), `${JSON.stringify(a, null, 2)}\n`);
      fs.writeFileSync(path.join(ROOT, 'evidence/s2-006-db-run-b.json'), `${JSON.stringify(b, null, 2)}\n`);
      fs.writeFileSync(path.join(ROOT, 'evidence/s2-006-db-crash-a.json'), `${JSON.stringify(crashA, null, 2)}\n`);
      fs.writeFileSync(path.join(ROOT, 'evidence/s2-006-db-crash-b.json'), `${JSON.stringify(crashB, null, 2)}\n`);
    }
    writeReport(report, allIssues.length === 0 ? 0 : 1);
  } catch (error) {
    if (!external && containerStarted) cleanupContainer();
    writeReport({
      schemaVersion: 1,
      ticket: 'S2-006',
      role: 'PostgreSQL two-process verifier store replay',
      status: 'FAIL',
      ok: false,
      reason: String(error.message ?? error).slice(0, 800),
      databaseEngine: 'PostgreSQL',
    }, 1);
  } finally {
    if (!external && containerStarted) cleanupContainer();
  }
}

const args = parseArgs(process.argv);
if (args.child === 'true') {
  const databaseUrl = process.env.VERITAS_DB_URL;
  if (!databaseUrl) {
    console.error('child mode requires VERITAS_DB_URL');
    process.exit(3);
  }
  if (args['crash-first'] === 'true') {
    await crashFirstChild({
      schema: args.schema,
      executorId: args['executor-id'],
      stateFile: args.state,
      databaseUrl,
    });
  } else if (args['crash-recover'] === 'true') {
    await crashRecoverChild({
      schema: args.schema,
      runId: args['run-id'],
      executorId: args['executor-id'],
      stateFile: args.state,
      out: args.out,
      databaseUrl,
    });
  } else {
    await runChild({
      schema: args.schema,
      runId: args['run-id'],
      executorId: args['executor-id'],
      out: args.out,
      databaseUrl,
    });
  }
} else if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await coordinator(args);
}
