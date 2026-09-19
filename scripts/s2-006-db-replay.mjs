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
import {
  makeVerifierAuthorityRegistry,
  publishVerificationResult,
  publishCalibrationReport,
  publishAdjudication,
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

const PAYLOAD = {
  statement: 'Replay fixture: trial X reported a 12% reduction in systolic blood pressure versus placebo.',
  citations: [{ claimId: 'clm-src-0001', claimRevision: 1, segmentId: 'seg-0001' }],
};

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
]);

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
      store, authorities: AUTHORITIES, actor: ACTOR, grant: grantFixture(),
      callId: 'call-s2006-replay-1', operationId: 'op-s2006-replay-external-01',
      reservation: { purpose: 'store-replay fixture; no provider is called' }, workspaceId: WORKSPACE,
    });
    await acceptExternalCall({ store, actor: ACTOR, callId: reserved.callId, fencingToken: reserved.fencingToken });
    const finalized = await finalizeExternalCall({
      store, actor: ACTOR, callId: reserved.callId, fencingToken: reserved.fencingToken,
      responseDigest: canonicalDigest({ replay: 'fixture-response', abstention: 'INSUFFICIENT_EVIDENCE' }),
      settlement: { charged: 0, currency: 'none', note: 'zero-budget no-provider fixture' },
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
    const report = {
      schemaVersion: 1,
      ticket: 'S2-006',
      role: 'S2-006 DB-backed verifier store replay A vs B (PostgresVerifierStore, separate OS processes)',
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
      comparison: { ok: issues.length === 0, issues },
      hardGates: { ok: issues.length === 0, violations: issues },
      status: issues.length === 0 ? 'PASS' : 'FAIL',
      ok: issues.length === 0,
    };
    if (writeEvidence) {
      fs.writeFileSync(path.join(ROOT, 'evidence/s2-006-db-run-a.json'), `${JSON.stringify(a, null, 2)}\n`);
      fs.writeFileSync(path.join(ROOT, 'evidence/s2-006-db-run-b.json'), `${JSON.stringify(b, null, 2)}\n`);
    }
    writeReport(report, issues.length === 0 ? 0 : 1);
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
  await runChild({
    schema: args.schema,
    runId: args['run-id'],
    executorId: args['executor-id'],
    out: args.out,
    databaseUrl,
  });
} else if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await coordinator(args);
}
