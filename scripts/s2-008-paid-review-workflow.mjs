import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PostgresAgentBoardStore } from '../src/lib/agentboard/store.mjs';
import { assertBoardContract } from '../src/lib/agentboard/contracts.mjs';
import { execute } from '../src/lib/agentboard/commands.mjs';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { PODMAN_HOST } from '../src/lib/isolation/launch.mjs';
import { BASE_IMAGE } from '../src/lib/isolation/image.mjs';

const IMPORTER = path.join(path.dirname(fileURLToPath(import.meta.url)), 's2-008-paid-review-import.mjs');
const TRUSTED_WORKFLOWS = new WeakSet();
export const isTrustedS2PaidReviewWorkflow = (workflow) => TRUSTED_WORKFLOWS.has(workflow);
const fail = (code) => { const error = new Error(code); error.code = code; throw error; };
const addReason = (list, reason) => { if (!list.includes(reason)) list.push(reason); };
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const wire = (value) => 'sha256:' + canonicalDigest(value);
const clean = (value) => String(value).replace(/^sha256:/, '');
const normalizeImageId = (value) => value.startsWith('sha256:') ? value : 'sha256:' + value;
const safeRelative = (value) => typeof value === 'string' && value.length > 0
  && !value.startsWith('/') && !value.includes('\\')
  && value.split('/').every((part) => part && part !== '.' && part !== '..')
  && path.posix.normalize(value) === value;
const iso = () => new Date().toISOString();

function privateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const info = fs.lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid()) fail('PAID_REVIEW_STATE_INVALID');
  fs.chmodSync(directory, 0o700);
  return fs.realpathSync(directory);
}
function saveImmutable(file, bytes) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o400);
  try { fs.writeSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function privateBytes(file) {
  let fd;
  try {
    const before = fs.lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (before.mode & 0o077) || before.uid !== process.getuid()) fail('PAID_REVIEW_PRIVATE_FILE_INVALID');
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino) fail('PAID_REVIEW_PRIVATE_FILE_INVALID');
    return fs.readFileSync(fd);
  } catch (error) {
    if (error?.code?.startsWith('PAID_REVIEW_')) throw error;
    fail('PAID_REVIEW_PRIVATE_FILE_INVALID');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function privateJson(file) {
  try { return JSON.parse(privateBytes(file).toString('utf8')); }
  catch (error) {
    if (error?.code?.startsWith('PAID_REVIEW_')) throw error;
    fail('PAID_REVIEW_PRIVATE_FILE_INVALID');
  }
}
function readBoundEvidence(root, record) {
  if (!safeRelative(record.path)) fail('PAID_REVIEW_EVIDENCE_PATH_INVALID');
  const realRoot = fs.realpathSync(root);
  const target = path.resolve(realRoot, ...record.path.split('/'));
  const relative = path.relative(realRoot, target);
  if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) fail('PAID_REVIEW_EVIDENCE_PATH_INVALID');
  const parent = fs.realpathSync(path.dirname(target));
  const parentRelative = path.relative(realRoot, parent);
  if (parentRelative === '..' || parentRelative.startsWith('..' + path.sep) || path.isAbsolute(parentRelative)) fail('PAID_REVIEW_EVIDENCE_PATH_INVALID');
  let fd;
  try {
    const before = fs.lstatSync(target);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) fail('PAID_REVIEW_EVIDENCE_FILE_INVALID');
    fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1) fail('PAID_REVIEW_EVIDENCE_FILE_INVALID');
    const bytes = fs.readFileSync(fd);
    if (bytes.length !== record.bytes || sha(bytes) !== record.sha256) fail('PAID_REVIEW_EVIDENCE_CHANGED');
    return bytes;
  } catch (error) {
    if (error?.code?.startsWith('PAID_REVIEW_')) throw error;
    fail('PAID_REVIEW_EVIDENCE_FILE_INVALID');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function runPodman(args, timeout = 120000) {
  const env = { PATH: '/usr/bin:/bin', HOME: os.homedir(), TMPDIR: '/tmp', XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR || '/tmp/xdg-rt' };
  const result = spawnSync('/usr/bin/podman', [...PODMAN_HOST.argvPrefix, ...args], {
    encoding: 'buffer', timeout, maxBuffer: 256 * 1024, env,
  });
  if (result.error || result.status !== 0) fail('PAID_REVIEW_PODMAN_FAILED');
  return result;
}

export function createS2PaidReviewWorkflow({
  pool, evidenceRoot, inspectEvidence, buildTask, ownerPrincipalId, producerPrincipalId,
  stateRoot, replayJournal, fixtureOnly = false, fixtureRoot = null, fixtureRecords = null, version = 11,
} = {}) {
  if (typeof inspectEvidence !== 'function' || typeof buildTask !== 'function'
      || typeof replayJournal !== 'function' || !ownerPrincipalId || !producerPrincipalId
      || typeof stateRoot !== 'string') fail('PAID_REVIEW_WORKFLOW_INVALID');
  if (fixtureOnly && (!fixtureRoot || !Array.isArray(fixtureRecords) || fixtureRecords.length < 1)) fail('PAID_REVIEW_FIXTURE_INVALID');
  if (version !== 11 && version !== 12) fail('PAID_REVIEW_VERSION_UNSUPPORTED');
  const suffix = randomBytes(6).toString('hex');
  const taskId = fixtureOnly ? 'abt-s2-008-v' + version + '-fixture-' + suffix : 'abt-s2-008-v' + version + '-paid-review';
  const workspaceId = fixtureOnly ? 'ws-s2-008-v' + version + '-fixture-' + suffix : 'ws-s2-008-v' + version + '-paid-review';
  const adapterId = fixtureOnly ? 'adr-s2-008-v' + version + '-fixture-' + suffix : 'adr-s2-008-v' + version + '-importer';
  const workRoot = privateDirectory(stateRoot);
  const taskDirectory = path.join(workRoot, fixtureOnly ? 'fixtures' : 'v' + version, taskId);
  const clock = { now: () => new Date() };
  const store = pool ? new PostgresAgentBoardStore({ pool, clock, ids: () => randomBytes(16).toString('hex') }) : null;
  const producer = (who) => ({
    principal_id: who === 'human' ? ownerPrincipalId : producerPrincipalId,
    workspace_ids: [workspaceId],
    capabilities: who === 'human'
      ? ['board.task.read','board.task.create','board.task.transition','board.adapter.register','board.budget.grant','board.review.approve']
      : ['board.task.read','board.task.transition','board.execution.start','board.result.collect','board.evidence.submit'],
  });
  async function command(name, args, who, step, transport = null) {
    if (!store) fail('PAID_REVIEW_WORKFLOW_UNAVAILABLE');
    const idem = canonicalDigest({ taskId, step, args });
    const result = await execute({
      command: name, args: { ...args, idempotency_key: idem }, principal: producer(who),
      actorKind: who === 'human' ? 'human_owner' : 'adapter', store, clock, now: iso(),
      workspaceRoots: [taskDirectory], transport,
    });
    return result.data;
  }
  async function findTask() {
    if (!store) return null;
    const rows = await store.listTasks({ workspaceId, principalId: ownerPrincipalId, limit: 50 });
    return rows.find((row) => row.task_id === taskId) ?? null;
  }
  async function campaignEvidence() {
    if (fixtureOnly) {
      const records = structuredClone(fixtureRecords);
      return { ready: true, version, state: 'PENDING', reasons: [], fixture_only: true,
        artifactManifest: records, artifactManifestDigest: canonicalDigest(records), campaign: { arms: {} } };
    }
    return inspectEvidence(evidenceRoot);
  }
  async function journal(task) {
    const rows = (await pool.query('SELECT * FROM agentboard_transition WHERE task_id=$1 ORDER BY revision', [taskId])).rows;
    return { ...replayJournal(task, rows), rows: rows.map((row) => ({
      ...row, occurred_at: row.occurred_at instanceof Date ? row.occurred_at.toISOString() : String(row.occurred_at),
    })) };
  }
  function recordPaths() {
    return {
      intent: path.join(taskDirectory, 'start-intent.json'),
      bundle: path.join(taskDirectory, 'input', 'bundle.json'),
      importer: path.join(taskDirectory, 'source', 'importer.mjs'),
      report: path.join(taskDirectory, 'output', 'import.json'),
      manifest: path.join(taskDirectory, 'artifact-manifest.json'),
      decisionIntent: path.join(taskDirectory, 'decision-intent.json'),
      decisionReceipt: path.join(taskDirectory, 'decision-receipt.json'),
    };
  }
  function stage(evidence) {
    const evidenceRootForRun = fixtureOnly ? fixtureRoot : evidenceRoot;
    const paths = recordPaths();
    for (const [directory, parent] of [
      [path.dirname(paths.bundle), taskDirectory], [path.dirname(paths.importer), taskDirectory],
      [path.dirname(paths.report), taskDirectory],
    ]) fs.mkdirSync(directory, { recursive: false, mode: 0o700 });
    const records = evidence.artifactManifest;
    if (!Array.isArray(records) || records.length < 1 || canonicalDigest(records) !== evidence.artifactManifestDigest) fail('PAID_REVIEW_EVIDENCE_MANIFEST_INVALID');
    const bundleFiles = records.map((record) => {
      if (record.missing === true) {
        if (Object.keys(record).sort().join(',') !== 'missing,path' || !safeRelative(record.path)) fail('PAID_REVIEW_EVIDENCE_MANIFEST_INVALID');
        const missing = path.join(path.dirname(paths.bundle), ...record.path.split('/'));
        if (fs.existsSync(missing)) fail('PAID_REVIEW_EVIDENCE_CHANGED');
        return { path: record.path, missing: true };
      }
      if (Object.keys(record).sort().join(',') !== 'bytes,path,sha256'
          || !Number.isSafeInteger(record.bytes) || record.bytes < 0 || !/^[0-9a-f]{64}$/.test(record.sha256)) fail('PAID_REVIEW_EVIDENCE_MANIFEST_INVALID');
      const bytes = readBoundEvidence(evidenceRootForRun, record);
      const destination = path.join(path.dirname(paths.bundle), ...record.path.split('/'));
      const relative = path.relative(path.dirname(paths.bundle), destination);
      if (relative.startsWith('..') || path.isAbsolute(relative)) fail('PAID_REVIEW_EVIDENCE_PATH_INVALID');
      fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
      saveImmutable(destination, bytes);
      return { path: record.path, bytes: record.bytes, sha256: record.sha256 };
    });
    const bundle = {
      kind: 's2-008-paid-review-import-bundle/1', fixture_only: fixtureOnly,
      artifact_manifest_digest: canonicalDigest(bundleFiles), files: bundleFiles,
    };
    const bundleBytes = Buffer.from(JSON.stringify(bundle) + '\n');
    saveImmutable(paths.bundle, bundleBytes);
    const importerBytes = fs.readFileSync(IMPORTER);
    saveImmutable(paths.importer, importerBytes);
    fs.chmodSync(path.dirname(paths.bundle), 0o500);
    fs.chmodSync(path.dirname(paths.importer), 0o500);
    return { paths, bundle, bundleBytes, importerBytes, records: bundleFiles };
  }
  function inspectImage() {
    if (!BASE_IMAGE.endsWith('@sha256:25330af3531fb5e23318554a0aa911125b6e91b1b777edf7655501d207c067a2')) fail('PAID_REVIEW_IMPORT_IMAGE_REF_INVALID');
    const result = runPodman(['image','inspect',BASE_IMAGE,'--format','{{.Id}}'], 30000);
    const rawId = result.stdout.toString('utf8').trim();
    const imageId = rawId.startsWith('sha256:') ? rawId : 'sha256:' + rawId;
    if (!/^sha256:[0-9a-f]{64}$/.test(imageId)) fail('PAID_REVIEW_IMPORT_IMAGE_INVALID');
    return imageId;
  }
  function launchImporter(staged, imageId) {
    const outputRoot = path.dirname(staged.paths.report);
    const uid = String(process.getuid());
    const gid = String(process.getgid());
    const args = [
      'run','--rm','--pull=never','--network=none','--read-only','--cap-drop=all',
      '--security-opt=no-new-privileges','--pids-limit=32','--memory=256m','--memory-swap=256m','--cpus=1',
      '--userns=keep-id','--user=' + uid + ':' + gid,
      '--tmpfs=/tmp:rw,nosuid,nodev,size=8m,mode=1777','--workdir','/source',
      '--volume', path.dirname(staged.paths.bundle) + ':/input:ro',
      '--volume', path.dirname(staged.paths.importer) + ':/source:ro',
      '--volume', outputRoot + ':/output:rw', imageId,
      'node','/source/importer.mjs','--bundle','/input/bundle.json','--output','/output/import.json',
    ];
    const started = performance.now();
    const result = runPodman(args, 120000);
    const reportBytes = fs.readFileSync(staged.paths.report);
    const report = JSON.parse(reportBytes.toString('utf8'));
    const expectedFiles = staged.records.filter((row) => row.missing !== true).length;
    const expectedMissing = staged.records.length - expectedFiles;
    if (result.status !== 0 || report.kind !== 's2-008-paid-review-import/1' || report.status !== 'PASS'
        || report.fixture_only !== fixtureOnly || report.network !== 'none' || report.model_calls !== 0 || report.tokens !== 0
        || report.artifact_manifest_digest !== staged.bundle.artifact_manifest_digest
        || report.bundle_sha256 !== sha(staged.bundleBytes) || report.verified_records !== staged.records.length
        || report.verified_files !== expectedFiles || report.verified_missing !== expectedMissing) fail('PAID_REVIEW_IMPORT_RESULT_INVALID');
    fs.chmodSync(staged.paths.report, 0o400);
    const finalImageId = inspectImage();
    if (finalImageId !== imageId) fail('PAID_REVIEW_IMPORT_IMAGE_CHANGED');
    return {
      report, reportBytes,
      process: {
        executable: '/usr/bin/podman', boundary: PODMAN_HOST.boundary,
        argv: [...PODMAN_HOST.argvPrefix, ...args], exit_status: result.status,
        signal: result.signal ?? null, pid: result.pid, duration_ms: Math.ceil(performance.now() - started),
        stdout_bytes: result.stdout.length, stdout_sha256: sha(result.stdout),
        stderr_bytes: result.stderr.length, stderr_sha256: sha(result.stderr),
        network: 'none', model_calls: 0, tokens: 0,
      },
    };
  }
  async function status({ principalId, taskId: requestedTaskId }) {
    if (principalId !== ownerPrincipalId || requestedTaskId !== taskId) fail('ACTOR_TASK_MISMATCH');
    const evidence = await campaignEvidence();
    if (!fixtureOnly && evidence.version !== version) fail('PAID_REVIEW_VERSION_UNSUPPORTED');
    if (!fixtureOnly && evidence.ready !== true) {
      return { ...evidence, ready: false, state: 'NOT_READY', revision: 1, taskId, workspaceId,
        producerPrincipalId, fixture_only: false, importReport: null,
        reviewSummary: { campaign: evidence.campaign, importer: null, journal: null,
          scientificDecision: evidence.campaign?.evaluationRecord ?? null },
        workflow: { mode: 'NOT_READY', actionable: false },
        artifactManifestDigest: evidence.artifactManifestDigest,
        expectedArtifactManifestDigest: evidence.artifactManifestDigest,
        currentArtifactManifestDigest: evidence.artifactManifestDigest };
    }
    const task = pool ? await findTask() : null;
    if (!task) {
      const intentExists = fs.existsSync(recordPaths().intent);
      const reasons = [...(evidence.reasons ?? [])];
      if (intentExists) reasons.push('START_REQUIRES_RECONCILIATION');
      const ready = evidence.ready === true && !intentExists;
      return {
        ...evidence, ready, state: ready ? 'PENDING' : 'NOT_READY', revision: 1,
        taskId, workspaceId, producerPrincipalId, fixture_only: fixtureOnly, importReport: null,
        reviewSummary: { campaign: evidence.campaign, importer: null, journal: null,
          scientificDecision: evidence.campaign?.evaluationRecord ?? null },
        workflow: { mode: fixtureOnly ? 'FIXTURE_ONLY' : ready ? 'OWNER_REVIEW' : 'NOT_READY', actionable: ready },
        reasons, artifactManifestDigest: evidence.artifactManifestDigest,
        expectedArtifactManifestDigest: evidence.artifactManifestDigest,
        currentArtifactManifestDigest: evidence.artifactManifestDigest,
        databaseJournal: 'NOT_CREATED_UNTIL_AUTHENTICATED_START',
      };
    }
    const runs = await store.listRuns({ workspaceId, taskId, principalId: ownerPrincipalId });
    const run = runs.at(-1) ?? null;
    let expectedDigest = null;
    let currentDigest = null;
    let importSummary = null;
    const reasons = [...(evidence.reasons ?? [])];
    try {
      const paths = recordPaths();
      const manifestBytes = privateBytes(paths.manifest);
      const manifest = JSON.parse(manifestBytes.toString('utf8'));
      currentDigest = sha(manifestBytes);
      expectedDigest = clean(run?.result?.artifact_hashes?.[0]?.digest ?? '');
      const resultArtifacts = run?.result?.artifact_hashes;
      const resultArtifactBound = Array.isArray(resultArtifacts) && resultArtifacts.length === 1
        && resultArtifacts[0]?.artifact_id === 'art-' + taskId.slice(4)
        && resultArtifacts[0]?.digest === 'sha256:' + currentDigest
        && resultArtifacts[0]?.media_type === 'application/vnd.veritas.paid-review-import+json';
      const reportBytes = privateBytes(paths.report);
      const report = JSON.parse(reportBytes.toString('utf8'));
      const bundleBytes = privateBytes(paths.bundle);
      const bundle = JSON.parse(bundleBytes.toString('utf8'));
      const importerBytes = privateBytes(paths.importer);
      const rootImporterSha = sha(fs.readFileSync(IMPORTER));
      const reportBinding = manifest.importer_report;
      const process = manifest.process;
      const argv = process?.argv;
      const stagedRecords = manifest.evidence_records;
      const bundleFiles = Array.isArray(bundle.files) ? bundle.files : [];
      const imageId = normalizeImageId(runPodman(['image','inspect',BASE_IMAGE,'--format','{{.Id}}'],30000).stdout.toString('utf8').trim());
      const requiredArgs = ['run','--rm','--pull=never','--network=none','--read-only',
        '--cap-drop=all','--security-opt=no-new-privileges','--memory=256m','--memory-swap=256m',
        '--workdir','/source',imageId,'node','/source/importer.mjs','--bundle','/input/bundle.json','--output','/output/import.json'];
      const argvValid = Array.isArray(argv) && requiredArgs.every((arg) => argv.includes(arg))
        && argv.filter((arg) => arg.startsWith('--network=')).every((arg) => arg === '--network=none');
      if (!Array.isArray(stagedRecords) || canonicalDigest(stagedRecords) !== canonicalDigest(evidence.artifactManifest)
          || canonicalDigest(bundleFiles) !== canonicalDigest(stagedRecords)
          || bundle.kind !== 's2-008-paid-review-import-bundle/1' || bundle.fixture_only !== fixtureOnly
          || bundle.artifact_manifest_digest !== canonicalDigest(bundleFiles)
          || sha(bundleBytes) !== manifest.bundle_sha256
          || sha(importerBytes) !== manifest.importer_sha256 || rootImporterSha !== manifest.importer_sha256
          || reportBinding?.sha256 !== sha(reportBytes) || reportBinding?.bytes !== reportBytes.length
          || reportBinding?.status !== report.status || reportBinding?.verified_records !== report.verified_records
          || reportBinding?.verified_files !== report.verified_files || reportBinding?.verified_missing !== report.verified_missing
          || reportBinding?.fixture_only !== report.fixture_only || reportBinding?.network !== report.network
          || reportBinding?.model_calls !== report.model_calls || reportBinding?.tokens !== report.tokens
          || report.kind !== 's2-008-paid-review-import/1' || report.status !== 'PASS'
          || report.fixture_only !== fixtureOnly || report.artifact_manifest_digest !== evidence.artifactManifestDigest
          || report.model_calls !== 0 || report.tokens !== 0
          || manifest.kind !== 's2-008-paid-review-execution/1' || manifest.task_id !== taskId
          || manifest.fixture_only !== fixtureOnly || manifest.evidence_manifest_digest !== evidence.artifactManifestDigest
          || manifest.image_ref !== BASE_IMAGE || manifest.image_id !== imageId
          || process?.executable !== '/usr/bin/podman' || process?.boundary !== PODMAN_HOST.boundary
          || process?.network !== 'none' || process?.exit_status !== 0 || process?.signal !== null
          || process?.model_calls !== 0 || process?.tokens !== 0 || !Number.isSafeInteger(process?.pid)
          || !Number.isSafeInteger(process?.duration_ms) || process.duration_ms < 0 || !argvValid
          || !/^[0-9a-f]{64}$/.test(process?.stdout_sha256 ?? '')
          || !/^[0-9a-f]{64}$/.test(process?.stderr_sha256 ?? '')
          || expectedDigest !== currentDigest || !resultArtifactBound) fail('PAID_REVIEW_SNAPSHOT_INVALID');
      for (const record of stagedRecords) {
        const stagedPath = path.join(path.dirname(paths.bundle), ...record.path.split('/'));
        if (record.missing === true) {
          if (fs.existsSync(stagedPath)) fail('PAID_REVIEW_SNAPSHOT_INVALID');
        } else {
          readBoundEvidence(path.dirname(paths.bundle), record);
        }
      }
      importSummary = {
        status: report.status, fixture_only: report.fixture_only,
        verified_records: report.verified_records, verified_files: report.verified_files,
        verified_missing: report.verified_missing, model_calls: report.model_calls, tokens: report.tokens,
        image_ref: manifest.image_ref, image_id: manifest.image_id,
        network: process.network, exit_status: process.exit_status,
        duration_ms: process.duration_ms, output_sha256: reportBinding.sha256,
        source_sha256: manifest.importer_sha256,
      };
    } catch {
      addReason(reasons, 'PAID_REVIEW_SNAPSHOT_INVALID');
    }
    const journalRows = (await pool.query('SELECT * FROM agentboard_transition WHERE task_id=$1 ORDER BY revision', [taskId])).rows;
    const journal = replayJournal(task, journalRows);
    const ready = evidence.ready === true && reasons.length === 0;
    return {
      ...evidence, ready, state: task.state, revision: task.revision, taskId, workspaceId,
      producerPrincipalId, fixture_only: fixtureOnly, reasons,
      artifactManifestDigest: expectedDigest || null,
      expectedArtifactManifestDigest: expectedDigest || null,
      currentArtifactManifestDigest: currentDigest,
      importReport: importSummary, importer: importSummary, journal,
      reviewSummary: { campaign: evidence.campaign, importer: importSummary, journal,
        scientificDecision: evidence.campaign?.evaluationRecord ?? null },
      workflow: { mode: fixtureOnly ? 'FIXTURE_ONLY' : ready ? 'OWNER_REVIEW' : 'NOT_READY', actionable: ready },
    };
  }
  async function start({ principalId, taskId: requestedTaskId }) {
    if (principalId !== ownerPrincipalId || requestedTaskId !== taskId) fail('ACTOR_TASK_MISMATCH');
    const evidence = await campaignEvidence();
    if ((!fixtureOnly && evidence.version !== version) || evidence.ready !== true) fail('PAID_REVIEW_NOT_READY');
    if (await findTask()) return status({ principalId, taskId: requestedTaskId });
    const paths = recordPaths();
    if (fs.existsSync(paths.intent)) fail('RECONCILIATION_REQUIRED');
    const imageId = inspectImage();
    privateDirectory(path.dirname(taskDirectory));
    fs.mkdirSync(taskDirectory, { mode: 0o700 });
    const intent = {
      kind: 's2-008-paid-review-start-intent/1', task_id: taskId, workspace_id: workspaceId,
      evidence_manifest_digest: evidence.artifactManifestDigest, image_ref: BASE_IMAGE,
      fixture_only: fixtureOnly, actor_principal_id: principalId, created_at: iso(),
    };
    saveImmutable(paths.intent, Buffer.from(JSON.stringify(intent) + '\n'));
    const staged = stage(evidence);
    const at = iso();
    const registration = {
      contractVersion: '1.0.0', adapter_id: adapterId, adapter_interface: 'veritas.adapter/1.0.0',
      provider: 'generic_cli', display_name: 'Restricted offline paid-evidence importer', adapter_kind: 'wrapper',
      health: 'healthy', workspace_id: workspaceId, principal_id: producerPrincipalId,
      declared_capabilities: ['task.read','artifact.write'], declared_tools: ['tool:fs.read','tool:fs.write','tool:process.exec'],
      sandbox_profile_id: 'sbx-podman-local-restricted-v1', max_concurrency: 1,
      real_adapter_provenance: { status: 'NOT_RUN_REAL_ADAPTER',
        detail: 'Fixed offline evidence importer only; no model executor is installed or invoked.' },
      registered_at: at,
    };
    const taskDocument = buildTask({ version, taskId, workspaceId,
      evidenceDigest: evidence.artifactManifestDigest, imageId, ownerPrincipalId, producerPrincipalId,
      adapterId, at, fixtureOnly });
    await command('adapters.register', { registration }, 'human', 'register-adapter');
    await command('tasks.create', { task: taskDocument }, 'human', 'create-task');
    await command('budget.grant', { grant: {
      grant_id: 'grt-' + taskId.slice(4), workspace_id: workspaceId, task_id: taskId,
      currency: 'USD', task_limit: 0.01, campaign_limit: 0.01, day_limit: 0.01, timeout_ms: 120000,
      granted_by: ownerPrincipalId, expires_at: null, revoked_at: null,
    } }, 'human', 'grant-offline-execution-only');
    const task = await findTask();
    await command('tasks.transition', { task_id: taskId, to_state: 'READY', expected_revision: task.revision,
      reason: 'Authenticated owner authorized the fixed offline evidence-import task; no model execution is permitted.',
      brief_digest: task.brief_digest, policy_digest: task.policy_digest, manifest_digest: task.manifest_digest }, 'human', 'ready');
    const started = await command('execution.start', { task_id: taskId, adapter_id: adapterId }, 'worker', 'execution-start');
    const run = started.run;
    if (!run?.run_id) fail('RUN_NOT_CREATED');
    let observed = null;
    const transport = {
      async dispatch(request) {
        if (canonicalDigest(request) !== clean(run.request_digest)) fail('EXECUTION_REQUEST_MISMATCH');
        const launched = launchImporter(staged, imageId);
        const manifest = {
          kind: 's2-008-paid-review-execution/1', task_id: taskId, workspace_id: workspaceId,
          fixture_only: fixtureOnly, evidence_manifest_digest: evidence.artifactManifestDigest,
          evidence_records: staged.records, bundle_sha256: sha(staged.bundleBytes),
          importer_sha256: sha(staged.importerBytes), image_ref: BASE_IMAGE, image_id: imageId,
          importer_report: {
            sha256: sha(launched.reportBytes), bytes: launched.reportBytes.length,
            status: launched.report.status, verified_records: launched.report.verified_records,
            verified_files: launched.report.verified_files, verified_missing: launched.report.verified_missing,
            fixture_only: launched.report.fixture_only, network: launched.report.network,
            model_calls: launched.report.model_calls, tokens: launched.report.tokens,
          },
          process: launched.process,
        };
        const manifestBytes = Buffer.from(JSON.stringify(manifest) + '\n');
        saveImmutable(paths.manifest, manifestBytes);
        observed = { manifest, manifestBytes, manifestSha256: sha(manifestBytes), durationMs: launched.process.duration_ms,
          reportSha256: sha(launched.reportBytes), stdoutSha256: launched.process.stdout_sha256 };
        return { observed_process_exit: launched.process.exit_status, output_sha256: launched.process.stdout_sha256 };
      },
    };
    await command('outbox.dispatch', { workspace_id: workspaceId, limit: 1 }, 'worker', 'dispatch-importer', transport);
    if (!observed) fail('IMPORTER_NOT_OBSERVED');
    await command('execution.collect_result', { run_id: run.run_id, result: {
      contract_version: 'veritas.execution/1.0.0', run_id: run.run_id, task_id: taskId,
      workspace_id: workspaceId, lease_id: run.lease_id, fencing_token: run.fencing_token, sequence: 1,
      outcome: 'SUCCEEDED', checkpoints: [],
      artifact_hashes: [{ artifact_id: 'art-' + taskId.slice(4), digest: 'sha256:' + observed.manifestSha256,
        media_type: 'application/vnd.veritas.paid-review-import+json' }],
      measurements: { duration_ms: observed.durationMs, spend: 0, currency: 'USD',
        model_id: 'NO_MODEL_OFFLINE_IMPORT', tool_calls: 1 },
      error: null, reconciliation_required: false, completed_at: iso(),
    } }, 'worker', 'collect-import-result');
    return status({ principalId, taskId });
  }
  async function decide({ principalId, taskId: requestedTaskId, decision, reason, observed: snapshot }) {
    if (principalId !== ownerPrincipalId || requestedTaskId !== taskId) fail('ACTOR_TASK_MISMATCH');
    if (!['approve', 'request_changes'].includes(decision) || typeof reason !== 'string' || reason.trim().length < 3) fail('DECISION_ARGUMENTS_INVALID');
    if (fixtureOnly && decision === 'approve') fail('PAID_REVIEW_FIXTURE_APPROVAL_FORBIDDEN');
    const current = await status({ principalId, taskId: requestedTaskId });
    if (!current.ready || current.state !== 'IN_REVIEW' || current.revision !== snapshot?.taskRevision
        || current.artifactManifestDigest !== snapshot?.artifactManifestDigest
        || current.expectedArtifactManifestDigest !== snapshot?.artifactManifestDigest
        || current.currentArtifactManifestDigest !== snapshot?.artifactManifestDigest) fail('REVIEW_VERSION_CHANGED');
    const paths = recordPaths();
    if (fs.existsSync(paths.decisionReceipt)) return status({ principalId, taskId: requestedTaskId });
    if (fs.existsSync(paths.decisionIntent)) fail('RECONCILIATION_REQUIRED');
    saveImmutable(paths.decisionIntent, Buffer.from(JSON.stringify({
      kind: 's2-008-paid-review-decision-intent/1', task_id: taskId, decision,
      snapshot_digest: snapshot.artifactManifestDigest, task_revision: snapshot.taskRevision,
      actor_principal_id: principalId, fixture_only: fixtureOnly, created_at: iso(),
    }) + '\n'));
    const task = await findTask();
    if (!task || task.state !== 'IN_REVIEW' || task.revision !== snapshot.taskRevision) fail('REVIEW_VERSION_CHANGED');
    await command('tasks.transition', {
      task_id: taskId, to_state: decision === 'approve' ? 'DONE' : 'BLOCKED',
      expected_revision: snapshot.taskRevision,
      reason: ('artifact sha256:' + snapshot.artifactManifestDigest + '; ' + reason.trim()).slice(0, 500),
      brief_digest: task.brief_digest, policy_digest: task.policy_digest, manifest_digest: task.manifest_digest,
    }, 'human', 'decision-' + decision);
    const result = await status({ principalId, taskId: requestedTaskId });
    const audit = await command('audit.list', { workspace_id: workspaceId, task_id: taskId, limit: 200 }, 'human', 'decision-audit');
    const receipt = {
      kind: 's2-008-paid-review-human-decision/1', task_id: taskId,
      fixture_only: fixtureOnly, actor_principal_id: principalId, producer_principal_id: producerPrincipalId,
      decision, state: result.state, prior_task_revision: snapshot.taskRevision, final_task_revision: result.revision,
      artifact_manifest_digest: snapshot.artifactManifestDigest,
      audit_digest: canonicalDigest(audit), audit,
      authority: 'Authenticated owner HTTP action bound to the exact artifact snapshot and AgentBoard revision',
      decided_at: iso(),
    };
    saveImmutable(paths.decisionReceipt, Buffer.from(JSON.stringify(receipt) + '\n'));
    return { ...result, decisionReceipt: receipt };
  }
  const workflow = Object.freeze({ status, start, decide, store, taskId, workspaceId, adapterId, version, fixtureOnly });
  TRUSTED_WORKFLOWS.add(workflow);
  return workflow;
}
