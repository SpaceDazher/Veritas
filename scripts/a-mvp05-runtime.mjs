// Additive local wrapper cycle. Historical pilot/campaign statuses are never edited.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { constants as F } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { pathToFileURL, fileURLToPath } from 'node:url';
import pg from 'pg';
import { PostgresAgentBoardStore } from '../src/lib/agentboard/store.mjs';
import { assertBoardContract } from '../src/lib/agentboard/contracts.mjs';
import { execute } from '../src/lib/agentboard/commands.mjs';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { PODMAN_HOST } from '../src/lib/isolation/launch.mjs';
import { BASE_IMAGE } from '../src/lib/isolation/image.mjs';
import { POSTGRES_IMAGE } from './verify-postgres-smoke.mjs';
import { applyMigrations } from './apply-migrations.mjs';
import { createA05ReviewServer, hashA05ReviewToken } from './a-mvp05-review.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const STATE = path.join(os.homedir(), '.local/state/veritas/a-mvp05');
const PROFILE = 'sbx-podman-local-restricted-v1';
const FILES = ['README.md', 'sum.mjs', 'sum.test.mjs', 'tests.log', 'run.json', 'diff.patch'];
const ADDITION = '\nReview cycle: local wrapper, no provider calls.\n';
const wire = (value) => 'sha256:' + canonicalDigest(value);
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const cleanDigest = (s) => String(s).replace(/^sha256:/, '');
const fail = (code) => { const error = new Error(code); error.code = code; throw error; };
function save(file, value, immutable = false) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: immutable ? 'wx' : 'w' });
  if (immutable) fs.chmodSync(file, 0o400);
}
function privateRead(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) || stat.uid !== process.getuid()) fail('PRIVATE_FILE_INVALID');
  return fs.readFileSync(file, 'utf8');
}
function podman(args, options = {}) {
  const result = spawnSync('/usr/bin/podman', [...PODMAN_HOST.argvPrefix, ...args], {
    encoding: 'utf8', timeout: 60_000, maxBuffer: 256 * 1024,
    env: { ...process.env, XDG_RUNTIME_DIR: path.join(STATE, 'xdg') }, ...options,
  });
  if (result.error || result.status !== 0) {
    const error = new Error('PODMAN_OPERATION_FAILED'); error.code = 'PODMAN_OPERATION_FAILED';
    error.diagnostic = { status: result.status, error: result.error?.code, stderr: result.stderr };
    throw error;
  }
  return result;
}
export function snapshotA05Artifacts(root, names) {
  if (!Array.isArray(names) || !names.length || new Set(names).size !== names.length) fail('ARTIFACT_PATH_INVALID');
  const realRoot = fs.realpathSync(root);
  return [...names].sort().map((name) => {
    if (typeof name !== 'string' || !/^[a-zA-Z0-9_.-]+$/.test(name) || ['.', '..'].includes(name)) fail('ARTIFACT_PATH_INVALID');
    const file = path.join(realRoot, name);
    let fd;
    try { fd = fs.openSync(file, F.O_RDONLY | F.O_NOFOLLOW); }
    catch { fail('ARTIFACT_FILE_INVALID'); }
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1) fail('ARTIFACT_FILE_INVALID');
      const bytes = fs.readFileSync(fd);
      return { name, bytes: bytes.length, sha256: sha(bytes) };
    } finally { fs.closeSync(fd); }
  });
}
export function replayA05Journal(task, rows) {
  let state = 'BACKLOG'; let revision = 1;
  const ids = [];
  for (const row of rows) {
    if (row.from_state !== state || Number(row.revision) !== revision + 1
        || ids.includes(row.transition_id)
        || canonicalDigest(row.payload) !== row.payload_digest) fail('JOURNAL_REPLAY_INVALID');
    for (const key of ['brief_digest', 'policy_digest', 'manifest_digest']) {
      if (cleanDigest(row[key]) !== cleanDigest(task[key])) fail('JOURNAL_BINDING_INVALID');
    }
    state = row.to_state; revision += 1; ids.push(row.transition_id);
  }
  if (state !== task.state || revision !== task.revision
      || canonicalDigest(ids) !== cleanDigest(task.history_digest)) fail('JOURNAL_HEAD_INVALID');
  return { ok: true, state, revision, transitions: rows.length, history_digest: task.history_digest };
}
async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve)); return port;
}
async function setupDatabase() {
  fs.mkdirSync(STATE, { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(STATE, 'xdg'), { recursive: true, mode: 0o700 });
  const configFile = path.join(STATE, 'database.private.json');
  let config;
  if (fs.existsSync(configFile)) config = JSON.parse(privateRead(configFile));
  else {
    const port = await freePort();
    const password = randomBytes(32).toString('hex');
    const url = new URL('postgresql://127.0.0.1:' + port + '/a_mvp05');
    url.username = 'a_mvp05'; url.password = password;
    config = { connectionString: url.toString(), port, container: 'veritas-a-mvp05-db' };
    save(configFile, config);
    fs.writeFileSync(path.join(STATE, 'postgres.private.env'),
      'POSTGRES_USER=a_mvp05\nPOSTGRES_DB=a_mvp05\nPOSTGRES_PASSWORD=' + password + '\nPGDATA=/var/lib/postgresql/data/pgdata\n',
      { mode: 0o600, flag: 'wx' });
  }
  const exists = spawnSync('/usr/bin/podman', [...PODMAN_HOST.argvPrefix, 'container', 'exists', config.container],
    { env: { ...process.env, XDG_RUNTIME_DIR: path.join(STATE, 'xdg') } }).status === 0;
  if (exists) {
    const running = podman(['inspect', config.container, '--format', '{{.State.Running}}']).stdout.trim();
    if (running !== 'true') podman(['start', config.container]);
  } else {
    const data = path.join(STATE, 'pgdata');
    fs.mkdirSync(data, { recursive: true, mode: 0o700 });
    podman(['unshare', 'chown', '70:70', data]);
    podman(['run', '--detach', '--name', config.container, '--pull=never',
      '--publish', '127.0.0.1:' + config.port + ':5432', '--read-only', '--user=70:70',
      '--cap-drop=all', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=256m',
      '--memory-swap=256m', '--cpus=1',
      '--volume', data + ':/var/lib/postgresql/data:rw',
      '--tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=4m,mode=1777',
      '--env-file', path.join(STATE, 'postgres.private.env'), POSTGRES_IMAGE]);
  }
  const pool = new pg.Pool({ connectionString: config.connectionString, max: 4, connectionTimeoutMillis: 2000 });
  let ready = false;
  for (let i = 0; i < 30; i++) {
    try { await pool.query('SELECT 1'); ready = true; break; }
    catch { await new Promise((resolve) => setTimeout(resolve, 500)); }
  }
  if (!ready) { await pool.end(); fail('POSTGRES_NOT_READY'); }
  await applyMigrations({ connectionString: config.connectionString, root: ROOT });
  return { pool, config };
}
const RUNNER = [
  "import fs from 'node:fs';", "import {spawnSync} from 'node:child_process';",
  "const before = '# A-MVP-05 isolated repository\\n\\nExisting sum tests protect the fixture.\\n';",
  "if(fs.readFileSync('README.md','utf8')!==before) throw new Error('INITIAL_ARTIFACT_CHANGED');",
  "fs.writeFileSync('README.md', before+" + JSON.stringify(ADDITION) + ");",
  "const test=spawnSync(process.execPath,['--test','sum.test.mjs'],{encoding:'utf8',timeout:10000,maxBuffer:65536});",
  "fs.writeFileSync('tests.log', String(test.stdout||'')+String(test.stderr||''));",
  "const result={node:process.version,pid:process.pid,test_exit:test.status,test_error:test.error?.code||null,model_calls:0,tokens:0};",
  "fs.writeFileSync('run.json', JSON.stringify(result,null,2)+'\\n');",
  "console.log(JSON.stringify(result)); if(test.error||test.status!==0) process.exit(1);",
].join('\n');
function prepareTicket(label, principalId) {
  const dir = path.join(STATE, label);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const ticketFile = path.join(dir, 'ticket.json');
  if (fs.existsSync(ticketFile)) return JSON.parse(privateRead(ticketFile));
  const project = path.join(dir, 'project');
  fs.mkdirSync(project, { mode: 0o700 });
  fs.writeFileSync(path.join(project, 'README.md'), '# A-MVP-05 isolated repository\n\nExisting sum tests protect the fixture.\n', { mode: 0o600 });
  fs.writeFileSync(path.join(project, 'sum.mjs'), 'export const sum = values => values.reduce((a,b)=>a+b,0);\n', { mode: 0o600 });
  fs.writeFileSync(path.join(project, 'sum.test.mjs'), [
    "import test from 'node:test'; import assert from 'node:assert/strict'; import {sum} from './sum.mjs';",
    "test('empty input has zero sum',()=>assert.equal(sum([]),0));",
    "test('mixed signs cancel correctly',()=>assert.equal(sum([4,-6,2]),0));",
    "test('fractional values sum correctly',()=>assert.equal(sum([0.5,1.5]),2));",
  ].join('\n') + '\n', { mode: 0o600 });
  for (const args of [['init', '--quiet'], ['add', 'README.md', 'sum.mjs', 'sum.test.mjs'],
    ['-c','user.name=Veritas local fixture','-c','user.email=fixture@example.invalid','commit','--quiet','-m','Isolated fixture baseline']]) {
    const p = spawnSync('git', args, { cwd: project, encoding: 'utf8' });
    if (p.status !== 0) fail('FIXTURE_GIT_FAILED');
  }
  const runner = path.join(dir, 'runner.mjs');
  fs.writeFileSync(runner, RUNNER, { mode: 0o400, flag: 'wx' });
  const image = JSON.parse(podman(['image','inspect', BASE_IMAGE]).stdout)[0];
  const suffix = randomBytes(6).toString('hex');
  const ticket = {
    label, principalId, producerId: 'prn-a05-producer-' + suffix, taskId: 'abt-a05-' + suffix,
    workspaceId: 'ws-a05-' + suffix, adapterId: 'adr-a05-' + suffix, dir, project, runner,
    imageId: image.Id, imageRef: BASE_IMAGE, runner_sha256: sha(fs.readFileSync(runner)),
    baseline: snapshotA05Artifacts(project, ['README.md', 'sum.mjs', 'sum.test.mjs']),
    createdAt: new Date().toISOString(),
    brief: { title: 'Add a review-cycle note to the isolated README', addition: ADDITION,
      acceptance: 'Only README changes; its added line matches the brief; all three existing sum tests pass.',
      runner: 'deterministic Node wrapper in Podman, not an LLM adapter',
      timeout_ms: 120000, currency: 'USD', cap: 0.01, cost_scope: 'Provider fees only; local electricity and opportunity cost NOT_MEASURED', planned_model_calls: 0, planned_tokens: 0 },
  };
  save(ticketFile, ticket, true); return ticket;
}
function principal(ticket, who) {
  return {
    principal_id: who === 'human' ? ticket.principalId : ticket.producerId,
    workspace_ids: [ticket.workspaceId],
    capabilities: who === 'human'
      ? ['board.task.read','board.task.create','board.task.transition','board.adapter.register','board.budget.grant','board.review.approve']
      : ['board.task.read','board.task.transition','board.execution.start','board.result.collect','board.evidence.submit'],
  };
}
export function buildA05Task(ticket, registration, at) {
  const task = {
    contractVersion: '1.0.0', task_id: ticket.taskId, workspace_id: ticket.workspaceId,
    title: ticket.brief.title, goal: 'Observe one human-created and human-reviewed bounded local change.',
    description: ticket.brief.runner, acceptance_criteria: [ticket.brief.acceptance],
    state: 'BACKLOG', revision: 1, priority: 'HIGH', dependencies: [],
    required_capabilities: registration.declared_capabilities, allowed_tools: registration.declared_tools,
    workspace_ref: { workspace_id: ticket.workspaceId, root_ref: 'project',
      isolation_profile_id: PROFILE, sandbox_profile_digest: wire({ profile: PROFILE, image: ticket.imageId }), read_only_paths: [] },
    time_limits: { timeout_ms: 120000, max_runtime_ms: 120000, deadline: null },
    cost_limits: { currency: 'USD', max_task_cost: 0.01, max_campaign_cost: 0.01, max_day_cost: 0.01 },
    acl: { visibility: 'personal', allowed_principal_ids: [ticket.principalId, ticket.producerId] },
    brief_digest: wire(ticket.brief), policy_digest: wire({ isolation: PROFILE, network: 'none', capabilities: registration.declared_capabilities }),
    manifest_digest: wire({ baseline: ticket.baseline, runner: ticket.runner_sha256, image: ticket.imageId }),
    assigned_adapter_id: null, active_lease_id: null, fencing_token: null, attempts: 0,
    artifacts: [], evidence_refs: [], block_reason: null, created_at: at, updated_at: at, history_digest: wire([]),
  };
  return assertBoardContract('board-task', task);
}

export function createA05Workflow({ pool, ticket }) {
  const clock = { now: () => new Date() };
  const store = new PostgresAgentBoardStore({ pool, clock, ids: () => randomBytes(16).toString('hex') });
  let inFlight = null;
  async function command(name, args, who, step, transport) {
    const value = await execute({
      command: name, args: { ...args, idempotency_key: canonicalDigest({ task: ticket.taskId, step, args }) },
      principal: principal(ticket, who), actorKind: who === 'human' ? 'human_owner' : 'adapter',
      store, clock, now: new Date().toISOString(), workspaceRoots: [ticket.dir],
      transport,
    });
    return value.data;
  }
  async function findTask() {
    const rows = await store.listTasks({ workspaceId: ticket.workspaceId, principalId: ticket.principalId, limit: 10 });
    return rows.find((row) => row.task_id === ticket.taskId) ?? null;
  }
  async function journal(task) {
    const rows = (await pool.query('SELECT * FROM agentboard_transition WHERE task_id=$1 ORDER BY revision', [ticket.taskId])).rows;
    return { ...replayA05Journal(task, rows), rows: rows.map((r) => ({ ...r, occurred_at: r.occurred_at.toISOString() })) };
  }
  async function status() {
    const task = await findTask();
    if (!task) return { state: 'PENDING', brief: ticket.brief, reviewer: 'Daniil', case_status: 'NOT_RUN', scope: 'local-wrapper-cycle-only' };
    const runs = await store.listRuns({ workspaceId: ticket.workspaceId, taskId: ticket.taskId, principalId: ticket.principalId });
    const run = runs.at(-1);
    const manifestFile = path.join(ticket.dir, 'artifact-manifest.json');
    let manifest = null; let current = null;
    if (fs.existsSync(manifestFile)) {
      manifest = JSON.parse(privateRead(manifestFile));
      current = canonicalDigest({ ...manifest, files: snapshotA05Artifacts(ticket.project, FILES) });
    }
    const expected = run?.result?.artifact_hashes?.[0]?.digest;
    return {
      state: task.state, revision: task.revision, brief: ticket.brief, taskId: ticket.taskId,
      producerPrincipalId: ticket.producerId,
      artifactManifestDigest: expected ? cleanDigest(expected) : null,
      expectedArtifactManifestDigest: expected ? cleanDigest(expected) : null,
      currentArtifactManifestDigest: current,
      diff: manifest ? fs.readFileSync(path.join(ticket.project,'diff.patch'),'utf8') : null,
      testLog: manifest ? fs.readFileSync(path.join(ticket.project,'tests.log'),'utf8') : null,
      runtime: manifest?.runtime ?? null, journal: await journal(task),
      case_status: 'NOT_CLAIMED_PENDING_INDEPENDENT_VERIFICATION', scope: 'local-wrapper-cycle-only',
    };
  }
  async function start({ principalId, taskId }) {
    if (principalId !== ticket.principalId || taskId !== ticket.taskId) fail('ACTOR_TASK_MISMATCH');
    if (inFlight) return inFlight;
    if (await findTask()) return status(); // No retry of an interrupted/unknown effect.
    inFlight = (async () => {
      if (sha(fs.readFileSync(ticket.runner)) !== ticket.runner_sha256
          || canonicalDigest(snapshotA05Artifacts(ticket.project, ['README.md','sum.mjs','sum.test.mjs'])) !== canonicalDigest(ticket.baseline)) fail('INITIAL_ARTIFACT_CHANGED');
      const at = new Date().toISOString();
      const registration = {
        contractVersion: '1.0.0', adapter_id: ticket.adapterId, adapter_interface: 'veritas.adapter/1.0.0',
        provider: 'generic_cli', display_name: 'Bounded local Node wrapper', adapter_kind: 'wrapper',
        health: 'healthy', workspace_id: ticket.workspaceId, principal_id: ticket.producerId,
        declared_capabilities: ['task.read','artifact.write'], declared_tools: ['tool:fs.read','tool:fs.write','tool:process.exec'],
        sandbox_profile_id: PROFILE, max_concurrency: 1,
        real_adapter_provenance: { status: 'NOT_RUN_REAL_ADAPTER', detail: 'Actual deterministic Node process under Podman; no installed model agent or model-quality claim.' },
        registered_at: at,
      };
      const task = buildA05Task(ticket, registration, at);
      await command('adapters.register', { registration }, 'human', 'register');
      await command('tasks.create', { task }, 'human', 'create');
      await command('budget.grant', { grant: {
        grant_id: 'grt-' + ticket.taskId.slice(4), workspace_id: ticket.workspaceId, task_id: ticket.taskId,
        currency: 'USD', task_limit: 0.01, campaign_limit: 0.01, day_limit: 0.01, timeout_ms: 120000,
        granted_by: ticket.principalId, expires_at: null, revoked_at: null,
      } }, 'human', 'grant');
      const bound = await findTask();
      await command('tasks.transition', { task_id: ticket.taskId, to_state: 'READY', expected_revision: bound.revision,
        reason: 'Authenticated user created the displayed fixed local task and resource limit.',
        brief_digest: bound.brief_digest, policy_digest: bound.policy_digest, manifest_digest: bound.manifest_digest }, 'human', 'ready');
      const started = await command('execution.start', { task_id: ticket.taskId, adapter_id: ticket.adapterId }, 'worker', 'execute');
      const run = started.run;
      if (!run?.run_id) fail('RUN_NOT_CREATED');
      let observed = null;
      const transport = {
        async dispatch(request) {
          if (canonicalDigest(request) !== cleanDigest(run.request_digest)) fail('EXECUTION_REQUEST_MISMATCH');
          const began = performance.now();
          const argv = ['run','--rm','--pull=never','--network=none','--read-only','--cap-drop=all',
            '--security-opt=no-new-privileges','--pids-limit=32','--memory=256m','--memory-swap=256m',
            '--cpus=1','--userns=keep-id','--user=' + process.getuid() + ':' + process.getgid(),
            '--tmpfs=/tmp:rw,nosuid,nodev,size=8m,mode=1777','--workdir=/workspace',
            '--volume', ticket.project + ':/workspace:rw','--volume', ticket.runner + ':/runner.mjs:ro',
            ticket.imageId,'node','/runner.mjs'];
          const result = podman(argv, { timeout: 120000 });
          const own = JSON.parse(fs.readFileSync(path.join(ticket.project,'run.json'),'utf8'));
          if (own.test_exit !== 0 || own.model_calls !== 0 || own.tokens !== 0) fail('RUNNER_RESULT_FAILED');
          for (const before of ticket.baseline.filter((row) => row.name !== 'README.md')) {
            if (sha(fs.readFileSync(path.join(ticket.project,before.name))) !== before.sha256) fail('UNEXPECTED_CODE_CHANGE');
          }
          const expectedReadme = '# A-MVP-05 isolated repository\n\nExisting sum tests protect the fixture.\n' + ADDITION;
          if (fs.readFileSync(path.join(ticket.project,'README.md'),'utf8') !== expectedReadme) fail('README_RESULT_FAILED');
          const diff = spawnSync('git',['diff','--','README.md'],{cwd:ticket.project,encoding:'utf8'});
          if (diff.status !== 0) fail('DIFF_FAILED');
          fs.writeFileSync(path.join(ticket.project,'diff.patch'), diff.stdout, { mode: 0o600, flag: 'wx' });
          observed = { ...own, podman_pid: result.pid, duration_ms: Math.ceil(performance.now()-began),
            image_id: ticket.imageId, image_ref: ticket.imageRef, runner_sha256: ticket.runner_sha256,
            isolation_profile: PROFILE, network: 'none', podman_argv: [...PODMAN_HOST.argvPrefix, ...argv] };
          const manifest = { kind: 'a-mvp05-artifacts/1', files: snapshotA05Artifacts(ticket.project, FILES), runtime: observed };
          save(path.join(ticket.dir,'artifact-manifest.json'), manifest, true);
          for (const name of FILES) fs.chmodSync(path.join(ticket.project,name), 0o400);
          return { observed_process_exit: result.status, output_sha256: sha(result.stdout) };
        },
      };
      await command('outbox.dispatch', { workspace_id: ticket.workspaceId, limit: 1 }, 'worker', 'dispatch', transport);
      if (!observed) fail('RUNNER_NOT_OBSERVED');
      const artifact = JSON.parse(privateRead(path.join(ticket.dir,'artifact-manifest.json')));
      await command('execution.collect_result', { run_id: run.run_id, result: {
        contract_version: 'veritas.execution/1.0.0', run_id: run.run_id, task_id: ticket.taskId,
        workspace_id: ticket.workspaceId, lease_id: run.lease_id, fencing_token: run.fencing_token, sequence: 1,
        outcome: 'SUCCEEDED', checkpoints: [],
        artifact_hashes: [{ artifact_id: 'art-' + ticket.taskId.slice(4), digest: wire(artifact), media_type: 'application/json' }],
        measurements: { duration_ms: observed.duration_ms, spend: 0, currency: 'USD',
          model_id: 'NO_MODEL_LOCAL_NODE', tool_calls: 3 },
        error: null, reconciliation_required: false, completed_at: new Date().toISOString(),
      } }, 'worker', 'collect');
      return status();
    })();
    try { return await inFlight; } finally { inFlight = null; }
  }
  async function decide({ principalId, taskId, decision, reason, observed }) {
    if (principalId !== ticket.principalId || taskId !== ticket.taskId) fail('ACTOR_TASK_MISMATCH');
    const current = await status();
    if (current.state !== 'IN_REVIEW' || current.revision !== observed.taskRevision
        || current.artifactManifestDigest !== observed.artifactManifestDigest
        || current.currentArtifactManifestDigest !== observed.artifactManifestDigest) fail('REVIEW_VERSION_CHANGED');
    const task = await findTask();
    await command('tasks.transition', {
      task_id: ticket.taskId, to_state: decision === 'approve' ? 'DONE' : 'BLOCKED',
      expected_revision: observed.taskRevision,
      reason: ('artifact sha256:' + observed.artifactManifestDigest + '; ' + reason).slice(0,500),
      brief_digest: task.brief_digest, policy_digest: task.policy_digest, manifest_digest: task.manifest_digest,
    }, 'human', 'decision-' + decision);
    const result = await status();
    const audit = await store.listAudit({ workspaceId: ticket.workspaceId, taskId: ticket.taskId, limit: 200 });
    save(path.join(ticket.dir,'decision-receipt.json'), { ...result, audit,
      authority: 'server-resolved scoped local bearer credential; explicit user HTTP action',
      reviewer_principal_id: ticket.principalId, producer_principal_id: ticket.producerId,
      fixture_test_only: ticket.label.startsWith('preflight') }, true);
    return result;
  }
  return { status, start, decide, store };
}
async function main() {
  const mode = process.argv[2];
  if (!['--init','--serve','--preflight','--inspect'].includes(mode) || process.argv.length !== 3) fail('USAGE_A05');
  const { pool } = await setupDatabase();
  try {
    const ticket = prepareTicket(mode === '--preflight' ? 'preflight-v2' : 'live',
      mode === '--preflight' ? 'prn-a05-test-reviewer' : 'prn-a05-daniil-reviewer');
    const workflow = createA05Workflow({ pool, ticket });
    if (mode === '--init') {
      const tokenFile = path.join(STATE,'reviewer.private.token');
      const authFile = path.join(STATE,'reviewer.private.json');
      if (!fs.existsSync(authFile)) {
        const token = randomBytes(32).toString('base64url');
        fs.writeFileSync(tokenFile, token, { mode: 0o600, flag: 'wx' });
        save(authFile,{ tokenHash: hashA05ReviewToken(token), principalId: ticket.principalId, taskId: ticket.taskId,
          expiresAt: new Date(Date.now()+24*60*60*1000).toISOString(), actions: ['start','approve','request_changes'] });
      }
      console.log(JSON.stringify({ state: 'PENDING', taskId: ticket.taskId, token_file: tokenFile }));
    } else if (mode === '--serve') {
      const auth = JSON.parse(privateRead(path.join(STATE,'reviewer.private.json')));
      const server = createA05ReviewServer({ credential: auth, workflow });
      await new Promise((resolve,reject) => { server.once('error',reject); server.listen(0,'127.0.0.1',resolve); });
      const metadata = { url: 'http://127.0.0.1:' + server.address().port, pid: process.pid,
        taskId: ticket.taskId, credential_expiry: auth.expiresAt, state: (await workflow.status()).state };
      save(path.join(STATE,'service.json'), metadata);
      console.log(JSON.stringify(metadata));
      await new Promise((resolve) => {
        process.once('SIGTERM', () => server.close(resolve));
        process.once('SIGINT', () => server.close(resolve));
      });
    } else if (mode === '--preflight') {
      const result = await workflow.start({ principalId: ticket.principalId, taskId: ticket.taskId });
      save(path.join(ticket.dir,'preflight-evidence.json'), { ...result, fixture_test_only: true,
        human_cycle_not_observed: true, case_status: 'NOT_RUN' });
      if (result.state !== 'IN_REVIEW') fail('PREFLIGHT_NOT_IN_REVIEW');
      console.log(JSON.stringify({ state: result.state, replay: result.journal.ok,
        node: result.runtime.node, test_exit: result.runtime.test_exit, fixture_test_only: true }));
    } else {
      const status = await workflow.status();
      console.log(JSON.stringify(status, null, 2));
    }
  } finally { await pool.end(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    fs.mkdirSync(path.join(STATE,'checks'),{recursive:true,mode:0o700});
    save(path.join(STATE,'checks/runtime-error.private.json'), { code: error.code ?? 'A05_RUNTIME_FAILED', message: error.message, diagnostic: error.diagnostic ?? null });
    console.error(JSON.stringify({ code: error.code ?? 'A05_RUNTIME_FAILED' })); process.exitCode = 1;
  });
}
