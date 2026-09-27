// S2-002 frozen corpus runner (one independent execution).
// Executes the complete trial corpus — ACL matrix (20 principals x all
// workspaces), capability spot trials, derived-artifact trials, nonce
// sequence, sandbox boundary trials including the live cancellation probe,
// and 100 revocation-decision latency trials — against the production policy
// engine and sandbox adapter. Raw observations and a summary with hard
// counters are persisted to the run's output root.
//
// Determinism: the engine clock is fixed, the corpus digest binds the trial
// definitions, and decisions never depend on the executor id, nonce base or
// output root — those vary between Run A and Run B by design.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { PRINCIPALS, WORKSPACES } from '../src/lib/identity/principals.mjs';
import { createPolicyEngine, POLICY_VERSION } from '../src/lib/identity/policy-engine.mjs';
import { createSandbox } from '../src/lib/identity/sandbox.mjs';
import { SANDBOX_NO_EXEC, SANDBOX_LOCAL_RESTRICTED_BLOCKED } from '../src/lib/identity/sandbox-profiles.mjs';
import { buildEscapingProcessTree, waitForPublishedPids } from '../src/lib/identity/process-tree-fixture.mjs';
import { awaitTree } from '../src/lib/identity/process-verdict.mjs';

const NOW = '2026-09-12T12:00:00.000Z';
const REVOCATION_TRIALS = 100;
const IS_WINDOWS = process.platform === 'win32';

// Corpus revision 2 (issue #41). The process-cancellation coverage is no
// longer Windows-only: on every platform the live trial spawns a descendant
// that leaves the child's process group, and a negative control proves that
// an observer which cannot see the process table produces a fail-closed
// blocked/unknown outcome instead of a zero-survivor success.
const CORPUS_REVISION = 2;

// Frozen expectation for board.read over all principals and workspaces,
// identical to the matrix asserted in tests/identity/policy-engine.test.mjs.
const BOARD_READ_ALLOW = new Set([
  'prn-owner-alice|ws-alice-private',
  'prn-owner-bob|ws-bob-private',
  'prn-owner-carol|ws-carol-private',
  'prn-owner-dave|ws-dave-private',
  'prn-owner-eve|ws-eve-private',
  'prn-agent-alice|ws-alice-private',
  'prn-agent-alice|ws-veritas-project',
  'prn-agent-carol|ws-carol-private',
  'prn-external-pi|ws-veritas-project',
  'prn-platform-curator|ws-veritas-project',
  'prn-platform-analyst|ws-veritas-project',
  'prn-platform-experimenter|ws-veritas-project',
  'prn-platform-verifier|ws-veritas-project',
  'prn-platform-operator|ws-veritas-project',
  'prn-owner-alice|ws-veritas-project',
  'prn-owner-bob|ws-veritas-project',
]);

// Expected decision per explicit capability/derived/nonce trial.
const CAPABILITY_TRIALS = [
  { trialId: 'cap/alice/task.create/own', principalId: 'prn-owner-alice', workspaceId: 'ws-alice-private', action: 'task.create', resource: { type: 'task', id: 'task:new-alice' }, args: { title: 'Synthetic task' }, expected: 'ALLOW' },
  { trialId: 'cap/alice/task.update/own-lease-waiver', principalId: 'prn-owner-alice', workspaceId: 'ws-alice-private', action: 'task.update', resource: { type: 'task', id: 'task:1' }, args: { task_id: 'task:1', expected_revision: 3 }, expected: 'ALLOW' },
  { trialId: 'cap/alice/approval.decide/agent-produced', principalId: 'prn-owner-alice', workspaceId: 'ws-alice-private', action: 'approval.decide', resource: { type: 'approval', id: 'approval:agent-output', producerPrincipalId: 'prn-agent-alice' }, args: { approval_id: 'approval:agent-output', verdict: 'APPROVED' }, expected: 'ALLOW' },
  { trialId: 'cap/alice/approval.decide/self-produced', principalId: 'prn-owner-alice', workspaceId: 'ws-alice-private', action: 'approval.decide', resource: { type: 'approval', id: 'approval:self', producerPrincipalId: 'prn-owner-alice' }, args: { approval_id: 'approval:self', verdict: 'APPROVED' }, expected: 'DENY', crossTenant: false },
  { trialId: 'cap/alice/message.send/own', principalId: 'prn-owner-alice', workspaceId: 'ws-alice-private', action: 'message.send', resource: { type: 'message', id: 'message:local' }, args: { to_principal: 'prn-agent-alice', body_digest: 'sha256:5555555555555555555555555555555555555555555555555555555555555555' }, expected: 'ALLOW' },
  { trialId: 'cap/alice/message.send/cross-tenant-recipient', principalId: 'prn-owner-alice', workspaceId: 'ws-alice-private', action: 'message.send', resource: { type: 'message', id: 'message:cross' }, args: { to_principal: 'prn-owner-bob', body_digest: 'sha256:6666666666666666666666666666666666666666666666666666666666666666' }, expected: 'DENY', crossTenant: true },
  { trialId: 'cap/agent-alice/message.send/ungranted', principalId: 'prn-agent-alice', workspaceId: 'ws-alice-private', action: 'message.send', resource: { type: 'message', id: 'message:local' }, args: { to_principal: 'prn-owner-alice', body_digest: 'sha256:7777777777777777777777777777777777777777777777777777777777777777' }, expected: 'DENY' },
  { trialId: 'cap/pi/task.update/project-lease', principalId: 'prn-external-pi', workspaceId: 'ws-veritas-project', action: 'task.update', resource: { type: 'task', id: 'task:tsk-pilot-1' }, lease: { leaseId: 'lse-pi-project-0001', fencingToken: 5 }, args: { task_id: 'task:tsk-pilot-1', expected_revision: 3 }, expected: 'ALLOW' },
  { trialId: 'cap/pi/task.update/wrong-grant-lease', principalId: 'prn-external-pi', workspaceId: 'ws-veritas-project', action: 'task.update', resource: { type: 'task', id: 'task:tsk-pilot-1' }, lease: { leaseId: 'lse-pi-project-0007', fencingToken: 3 }, args: { task_id: 'task:tsk-pilot-1', expected_revision: 3 }, expected: 'DENY' },
  { trialId: 'cap/codex/task.create/project-grant', principalId: 'prn-external-codex', workspaceId: 'ws-veritas-project', action: 'task.create', resource: { type: 'task', id: 'task:new-codex' }, args: { title: 'Codex synthetic task' }, expected: 'ALLOW' },
  { trialId: 'cap/curator/claim.write/project-lease', principalId: 'prn-platform-curator', workspaceId: 'ws-veritas-project', action: 'claim.write', resource: { type: 'claim', id: 'claim:curation-1' }, lease: { leaseId: 'lse-curator-claimwrite-0006', fencingToken: 1 }, args: { claim_id: 'claim:curation-1', provenance: 'synthetic' }, expected: 'ALLOW' },
  { trialId: 'cap/curator/claim.write/foreign-capability-lease', principalId: 'prn-platform-curator', workspaceId: 'ws-veritas-project', action: 'claim.write', resource: { type: 'claim', id: 'claim:c1' }, lease: { leaseId: 'lse-curator-0004', fencingToken: 2 }, args: { claim_id: 'claim:c1', provenance: 'synthetic' }, expected: 'DENY' },
  { trialId: 'cap/analyst/summary.generate/no-lease', principalId: 'prn-platform-analyst', workspaceId: 'ws-veritas-project', action: 'summary.generate', resource: { type: 'summary', id: 'summary:analyst-1' }, args: { summary_id: 'summary:analyst-1', inputs: [{ workspaceId: 'ws-veritas-project', resourceId: 'claim:c1' }] }, expected: 'DENY' },
  { trialId: 'cap/experimenter/tool.execute/podman-local-restricted', principalId: 'prn-platform-experimenter', workspaceId: 'ws-veritas-project', action: 'tool.execute', resource: { type: 'tool', id: 'tool:runner' }, lease: { leaseId: 'lse-experimenter-0005', fencingToken: 1 }, args: { tool_id: 'tool:runner', canonical_args: { argv: ['true'], timeout_ms: 5000 } }, expected: 'ALLOW' },
  { trialId: 'cap/experimenter/tool.discover/read', principalId: 'prn-platform-experimenter', workspaceId: 'ws-veritas-project', action: 'tool.discover', resource: { type: 'tool', id: 'tool:runner' }, args: { workspace_id: 'ws-veritas-project' }, expected: 'ALLOW' },
  { trialId: 'cap/operator/task.cancel/project', principalId: 'prn-platform-operator', workspaceId: 'ws-veritas-project', action: 'task.cancel', resource: { type: 'task', id: 'task:tsk-pilot-1' }, args: { task_id: 'task:tsk-pilot-1' }, expected: 'ALLOW' },
  { trialId: 'cap/verifier/artifact.read/project', principalId: 'prn-platform-verifier', workspaceId: 'ws-veritas-project', action: 'artifact.read', resource: { type: 'artifact', id: 'artifact:1' }, args: { artifact_id: 'artifact:1' }, expected: 'ALLOW' },
  { trialId: 'cap/collector/source.read/shared', principalId: 'prn-platform-collector', workspaceId: 'ws-shared-library', action: 'source.read', resource: { type: 'source', id: 'source:library-1' }, args: { source_id: 'source:library-1' }, expected: 'ALLOW' },
  { trialId: 'cap/collector/board.read/shared-ungranted', principalId: 'prn-platform-collector', workspaceId: 'ws-shared-library', action: 'board.read', resource: { type: 'board', id: 'board:primary' }, args: { workspace_id: 'ws-shared-library' }, expected: 'DENY' },
  { trialId: 'cap/agent-dave/task.create/grant', principalId: 'prn-agent-dave', workspaceId: 'ws-dave-private', action: 'task.create', resource: { type: 'task', id: 'task:new-dave' }, args: { title: 'Dave synthetic task' }, expected: 'ALLOW' },
  { trialId: 'cap/hermes/search.query/expired-grant', principalId: 'prn-external-hermes', workspaceId: 'ws-veritas-project', action: 'search.query', resource: { type: 'source', id: 'source:docs' }, args: { query: 'veritas' }, expected: 'DENY', crossTenant: false },
  { trialId: 'cap/pi/source.read/bob-private-cross-tenant', principalId: 'prn-external-pi', workspaceId: 'ws-bob-private', action: 'source.read', resource: { type: 'source', id: 'source:bob-notes-1' }, args: { source_id: 'source:bob-notes-1' }, expected: 'DENY', crossTenant: true },
  { trialId: 'cap/alice/cache.read/bob-private-cross-tenant', principalId: 'prn-owner-alice', workspaceId: 'ws-bob-private', action: 'cache.read', resource: { type: 'cache', id: 'cache:bob-index' }, args: { cache_id: 'cache:bob-index' }, expected: 'DENY', crossTenant: true },
  // Derived artifacts inherit the strictest ACL of their inputs.
  { trialId: 'derived/curator/benign-same-ws', principalId: 'prn-platform-curator', workspaceId: 'ws-veritas-project', action: 'summary.generate', resource: { type: 'summary', id: 'summary:board-weekly' }, lease: { leaseId: 'lse-curator-0004', fencingToken: 2 }, args: { summary_id: 'summary:board-weekly', inputs: [{ workspaceId: 'ws-veritas-project', resourceId: 'claim:c1' }] }, expected: 'ALLOW' },
  { trialId: 'derived/curator/poison-bob-claim', principalId: 'prn-platform-curator', workspaceId: 'ws-veritas-project', action: 'summary.generate', resource: { type: 'summary', id: 'summary:poisoned' }, lease: { leaseId: 'lse-curator-0004', fencingToken: 2 }, args: { summary_id: 'summary:poisoned', inputs: [{ workspaceId: 'ws-veritas-project', resourceId: 'claim:c1' }, { workspaceId: 'ws-bob-private', resourceId: 'claim:secret' }] }, expected: 'DENY', crossTenant: true },
  { trialId: 'derived/curator/poison-dave-cache', principalId: 'prn-platform-curator', workspaceId: 'ws-veritas-project', action: 'cache.write', resource: { type: 'cache', id: 'cache:poisoned-1' }, lease: { leaseId: 'lse-curator-cachewrite-0008', fencingToken: 1 }, args: { cache_id: 'cache:poisoned-1', inputs: [{ workspaceId: 'ws-dave-private', resourceId: 'cache:dave-index' }] }, expected: 'DENY', crossTenant: true },
  // One-time nonce grant: exactly one effect.
  { trialId: 'nonce/export/first', principalId: 'prn-agent-carol', workspaceId: 'ws-carol-private', action: 'artifact.export', resource: { type: 'artifact', id: 'artifact:final-1' }, args: { artifact_id: 'artifact:final-1', destination: 'export:local' }, expected: 'ALLOW' },
  { trialId: 'nonce/export/replay', principalId: 'prn-agent-carol', workspaceId: 'ws-carol-private', action: 'artifact.export', resource: { type: 'artifact', id: 'artifact:final-1' }, args: { artifact_id: 'artifact:final-1', destination: 'export:local' }, expected: 'DENY' },
  { trialId: 'nonce/export/replay-with-nonce', principalId: 'prn-agent-carol', workspaceId: 'ws-carol-private', action: 'artifact.export', resource: { type: 'artifact', id: 'artifact:final-1' }, args: { artifact_id: 'artifact:final-1', destination: 'export:local' }, expected: 'DENY' },
];

const SANDBOX_EXPECTATIONS = Object.freeze([
  ['sandbox/fs-traversal', 'PATH_ESCAPE'],
  ['sandbox/fs-absolute-outside', 'ROOT_VIOLATION'],
  ['sandbox/fs-unc', 'UNC_PATH'],
  ['sandbox/fs-device', 'DEVICE_PATH'],
  ['sandbox/fs-inside-ok', 'INSIDE'],
  ['sandbox/net-deny-all', 'DENIED'],
  ['sandbox/net-deny-localhost', 'DENIED'],
  ['sandbox/env-allowlist', 'FILTERED'],
  ['sandbox/secret-redaction', 'REDACTED'],
  ['sandbox/output-digest-provenance', 'RECORDED'],
  ['sandbox/output-name-escape', 'PATH_ESCAPE'],
  ['sandbox/no-exec-refuses-execution', 'BLOCKED'],
  // Platform-independent on purpose: the frozen corpus must have the same
  // trial set and digest on every host, otherwise a run on one platform can
  // never satisfy an oracle built for another. Node maps symlinkSync's
  // 'junction' type onto a directory symlink on POSIX, so the link escape is
  // observable everywhere.
  ['sandbox/fs-junction-escape', 'LINK_ESCAPE'],
  ['sandbox/cancellation-survivors', 'SURVIVORS_ZERO'],
  ['sandbox/cancellation-observation-unavailable', 'BLOCKED_UNVERIFIED'],
]);
// Every sandbox expectation, as one set. Used by the authority counter so it
// cannot fall behind the oracle: it used to be a third literal list of the
// same values, and a new sandbox control added to SANDBOX_EXPECTATIONS would
// have moved no counter until somebody remembered to edit all three.
const SANDBOX_EXPECTED_VALUES = Object.freeze([...new Set(SANDBOX_EXPECTATIONS.map(([, expected]) => expected))]);

// Sandbox expectations that assert a CONTAINMENT refusal. A control with one of
// these expectations that comes back ALLOWED is a genuine filesystem, network,
// environment or secret escape. Expectations that assert something else (the
// cancellation survivor count, for instance) are violations, not escapes.
//
// The list is derived from `SANDBOX_EXPECTATIONS` rather than written out
// again. It used to be a second literal list, and the second one was missing
// `BLOCKED`: if the no-exec tier had ever started SPAWNING, that trial would
// have satisfied neither this counter nor the `authority_expansion` list, so a
// blocked tier quietly executing would have moved no hard counter at all. A
// second list is exactly the drift this repository's gates are built to
// prevent, so containment is now a PROPERTY of the expectation set and the
// counters read it from one place.
const NON_CONTAINMENT_EXPECTATIONS = Object.freeze(['INSIDE', 'RECORDED', 'SURVIVORS_ZERO']);
const SANDBOX_CONTAINMENT_EXPECTATIONS = Object.freeze(
  SANDBOX_EXPECTED_VALUES.filter((expected) => !NON_CONTAINMENT_EXPECTATIONS.includes(expected)).sort(),
);

// The marker a sandbox control returns when this platform cannot exercise it.
// Declared once so the producer and every consumer agree.
const NOT_RUN_PLATFORM = 'PLATFORM_UNSUPPORTED';



// A tier that forbids execution must refuse before it resolves a command, so
// the probe vector is never actually executed; it is spelled per platform only
// so the trial reads honestly.
const NO_EXEC_PROBE_COMMAND = IS_WINDOWS ? 'cmd.exe' : '/bin/sh';
const NO_EXEC_PROBE_ARGS = IS_WINDOWS ? ['/c', 'echo hi'] : ['-c', 'echo hi'];

// The live cancellation trial gets its own probe timer, kept below the
// harness budget that waits on it, so the adapter's kill timer fires before
// the harness stops waiting (SpaceDazher/Veritas#16).
const LIVE_TRIAL_TIMER_MS = 45000;

// A descendant that deliberately leaves the child's process group is the
// hardest case on both platforms: a group- or parent-only kill cannot reach
// it. setsid(2) on POSIX, Start-Process on Windows. The tree definition lives
// in process-tree-fixture.mjs so this runner, the adversarial probes and the
// cancellation verification stage cannot drift apart.
function descendantTreeCommand(root) {
  return buildEscapingProcessTree(root, { depth: 2 });
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function digest(value) {
  return createHash('sha256').update(JSON.stringify(canonicalize(value)), 'utf8').digest('hex');
}

function buildCorpus() {
  const trials = [];
  for (const principal of PRINCIPALS) {
    for (const ws of WORKSPACES) {
      trials.push({
        id: `acl/${principal.principal_id}/${ws.workspace_id}`,
        kind: 'acl_matrix',
        principalId: principal.principal_id,
        workspaceId: ws.workspace_id,
        action: 'board.read',
        resource: { type: 'board', id: 'board:primary' },
        expected: BOARD_READ_ALLOW.has(`${principal.principal_id}|${ws.workspace_id}`) ? 'ALLOW' : 'DENY',
      });
    }
  }
  for (const trial of CAPABILITY_TRIALS) {
    trials.push({ kind: 'capability', ...trial, id: trial.trialId });
  }
  return trials;
}

// Host-owned oracle used by both the runner and the independent comparator.
// It fixes the exact trial-id set and verdict for every cell; observations
// cannot redefine their own exam by carrying a matching expected value.
export function buildExpectedCorpusOracle() {
  const entries = [
    ...buildCorpus().map((trial) => [trial.id, trial.expected]),
    ...SANDBOX_EXPECTATIONS,
    ...Array.from({ length: REVOCATION_TRIALS }, (_, index) => [`revocation/${String(index).padStart(3, '0')}`, 'DENY']),
  ];
  const ids = entries.map(([trialId]) => trialId);
  if (new Set(ids).size !== ids.length) throw new Error('DUPLICATE_ORACLE_TRIAL_ID');
  return Object.freeze({
    schemaVersion: 1,
    trialCount: entries.length,
    digest: digest(entries),
    expectedByTrialId: Object.freeze(Object.fromEntries(entries)),
  });
}

// Records whether this host could create the link-escape fixture, so the run
// summary states the capability instead of leaving a reader to infer it from a
// single mismatching trial.
let linkCapability = { ready: true, failure: null };

function sandboxTrialSet(root) {
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 's2-002-corpus-out-'));
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside');
  // The link escape is part of the frozen corpus on every platform. If the OS
  // refuses to create the link the corpus cannot be frozen as specified, so
  // the trial reports that as its own observed value instead of throwing out
  // of the trial set: a censored trial and a crashed run must be
  // distinguishable, and this one is attributed to the trial that could not
  // run rather than to an anonymous stack trace.
  let linkEscapeReady = true;
  let linkEscapeFailure = null;
  try {
    fs.symlinkSync(outside, path.join(root, 'escape'), IS_WINDOWS ? 'junction' : 'dir');
  } catch (error) {
    linkEscapeReady = false;
    linkEscapeFailure = error?.code ?? 'SYMLINK_FAILED';
  }
  const sandbox = createSandbox({
    profile: SANDBOX_NO_EXEC,
    workspaceRoots: [root],
    artifactRoot: path.join(root, 'artifacts'),
    secrets: { 'sec-postgres-url': 'synthetic-db-secret-0123456789' },
    now: NOW,
  });
  const trials = [
    { id: 'sandbox/fs-traversal', run: () => { try { sandbox.resolvePath('data/../../x.txt'); return 'ALLOWED'; } catch (e) { return e.code; } }, expected: 'PATH_ESCAPE' },
    { id: 'sandbox/fs-absolute-outside', run: () => { try { sandbox.resolvePath('C:/Windows/win.ini'); return 'ALLOWED'; } catch (e) { return e.code; } }, expected: 'ROOT_VIOLATION' },
    { id: 'sandbox/fs-unc', run: () => { try { sandbox.resolvePath('\\\\server\\share\\f.txt'); return 'ALLOWED'; } catch (e) { return e.code; } }, expected: 'UNC_PATH' },
    { id: 'sandbox/fs-device', run: () => { try { sandbox.resolvePath('CON'); return 'ALLOWED'; } catch (e) { return e.code; } }, expected: 'DEVICE_PATH' },
    { id: 'sandbox/fs-inside-ok', run: () => { try { sandbox.resolvePath('data/file.txt'); return 'INSIDE'; } catch (e) { return e.code; } }, expected: 'INSIDE' },
    { id: 'sandbox/net-deny-all', run: () => sandbox.checkNetwork('registry.npmjs.org', 443).allowed ? 'ALLOWED' : 'DENIED', expected: 'DENIED' },
    { id: 'sandbox/net-deny-localhost', run: () => sandbox.checkNetwork('127.0.0.1', 5432).allowed ? 'ALLOWED' : 'DENIED', expected: 'DENIED' },
    { id: 'sandbox/env-allowlist', run: () => { const env = sandbox.buildEnvironment({ NODE_ENV: 'test', AWS_ACCESS_KEY_ID: 'leak' }); return env.AWS_ACCESS_KEY_ID === undefined && env.NODE_ENV === 'test' ? 'FILTERED' : 'LEAK'; }, expected: 'FILTERED' },
    { id: 'sandbox/secret-redaction', run: () => { const out = sandbox.redact('connect synthetic-db-secret-0123456789 now'); return out.includes('synthetic-db-secret-0123456789') ? 'LEAK' : 'REDACTED'; }, expected: 'REDACTED' },
    { id: 'sandbox/output-digest-provenance', run: () => { const rec = sandbox.writeOutput('result.txt', Buffer.from('deterministic')); return rec.sha256.length === 64 && rec.provenance.createdAt === NOW ? 'RECORDED' : 'BROKEN'; }, expected: 'RECORDED' },
    { id: 'sandbox/output-name-escape', run: () => { try { sandbox.writeOutput('../escape.txt', Buffer.from('x')); return 'ALLOWED'; } catch (e) { return e.code; } }, expected: 'PATH_ESCAPE' },
    { id: 'sandbox/no-exec-refuses-execution', run: async () => { const outcome = await sandbox.spawnProcess({ command: NO_EXEC_PROBE_COMMAND, args: NO_EXEC_PROBE_ARGS, timeoutMs: 1000 }); return outcome.status === 'BLOCKED_SANDBOX' ? 'BLOCKED' : 'SPAWNED'; }, expected: 'BLOCKED' },
    { id: 'sandbox/fs-junction-escape', run: () => {
      if (!linkEscapeReady) return `LINK_ESCAPE_UNOBSERVABLE_${linkEscapeFailure}`;
      try { sandbox.resolvePath('escape/secret.txt'); return 'ALLOWED'; } catch (e) { return e.code; }
    }, expected: 'LINK_ESCAPE' },
  ];
  linkCapability = { ready: linkEscapeReady, failure: linkEscapeFailure };
  trials.push({ id: 'sandbox/cancellation-survivors', live: true, survivorTrial: true, run: async () => {
    const live = createSandbox({
      profile: SANDBOX_LOCAL_RESTRICTED_BLOCKED,
      workspaceRoots: [root],
      artifactRoot: path.join(root, 'artifacts'),
      secrets: {},
      now: NOW,
    });
    const tree = descendantTreeCommand(root);
    const { pid, done } = live.startForControlProbe({ ...tree, timeoutMs: LIVE_TRIAL_TIMER_MS });
    // Wait until the descendant has published its own pid, so the trial really
    // observes a two-level tree instead of racing process creation, and until
    // the adapter can see descendants at all. A tree that never forms is not a
    // survivor check, so it fails closed as its own observed value.
    const descendantPids = await waitForPublishedPids(tree.pidFile);
    const formed = await awaitTree((target) => live.descendantPids(target), pid);
    if (!formed.formed) {
      await live.cancel(pid);
      await done;
      return { observed: `TREE_NOT_FORMED_AFTER_${formed.attempts}_POLLS`, survivors: null, terminationProof: null, outcomeProof: null };
    }
    const cancel = await live.cancel(pid);
    const outcome = await done;
    // Independent ground truth: the descendant's own pid must be gone, checked
    // here rather than trusting the adapter's own verdict.
    const descendantAlive = descendantPids.filter((value) => live.isAlive(value));
    const queries = live.lastProcessQueries();
    if (cancel.proof === 'UNVERIFIED' || outcome.proof === 'UNVERIFIED') {
      return {
        observed: 'TERMINATION_UNVERIFIED',
        survivors: null,
        terminationProof: cancel.proof,
        outcomeProof: outcome.proof,
        processQueries: queries,
      };
    }
    const observedSurvivors = Math.max(cancel.survivors ?? 0, descendantAlive.length);
    if (observedSurvivors === 0 && cancel.proof === 'TERMINATED' && outcome.proof === 'TERMINATED') {
      return { observed: 'SURVIVORS_ZERO', survivors: 0, terminationProof: cancel.proof, outcomeProof: outcome.proof, processQueries: queries };
    }
    return {
      observed: `SURVIVORS_${observedSurvivors}`,
      survivors: observedSurvivors,
      terminationProof: cancel.proof,
      outcomeProof: outcome.proof,
      processQueries: queries,
    };
  }, expected: 'SURVIVORS_ZERO' });

  // Negative control: an observer that cannot see the process table. The
  // required behaviour is a fail-closed blocked/unknown outcome, never a
  // zero-survivor success. The observer seam is the only injection; the
  // terminate/prove logic under test is the production one.
  trials.push({ id: 'sandbox/cancellation-observation-unavailable', live: true, survivorTrial: true, run: async () => {
    const unobservable = {
      id: 'negative-control:process-table-unavailable',
      listDescendants: async () => ({ pids: [], observable: false, reason: 'SBX_NEGATIVE_CONTROL_NO_PROCESS_TABLE' }),
      listExisting: async (pids) => ({ alive: pids, observable: false, reason: 'SBX_NEGATIVE_CONTROL_NO_PROCESS_TABLE' }),
      identityFor: (pid) => String(pid),
    };
    const blind = createSandbox({
      profile: SANDBOX_LOCAL_RESTRICTED_BLOCKED,
      workspaceRoots: [root],
      artifactRoot: path.join(root, 'artifacts'),
      secrets: {},
      now: NOW,
      processObserver: unobservable,
    });
    const { pid, done } = blind.startForControlProbe({
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 30000)'],
      timeoutMs: 30000,
    });
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 200));
    const cancel = await blind.cancel(pid);
    // The run outcome is read, not assumed. Reporting a hard-coded
    // outcomeProof here would satisfy the counter's "both sides agree" rule
    // with a constant and hide exactly the regression that rule exists to
    // catch: cancel() and the run outcome disagreeing about the same tree.
    const outcome = await done;
    const failClosed = cancel.proof === 'UNVERIFIED'
      && cancel.terminated === false
      && cancel.survivors === null
      && cancel.reasonCodes.includes('SBX_PROCESS_OBSERVATION_UNAVAILABLE')
      && blind.observationSource === 'negative-control:process-table-unavailable';
    // Both the adapter's own verdict and the run's own verdict must be
    // fail-closed. Requiring only one of them would let a regression that
    // reported success from one side pass as a blocked/unknown control.
    const bothFailClosed = failClosed
      && outcome.proof === 'UNVERIFIED'
      && outcome.terminated === false
      && outcome.survivors === null;
    return {
      observed: bothFailClosed ? 'BLOCKED_UNVERIFIED' : 'FALSE_ZERO_SURVIVOR_SUCCESS',
      survivors: bothFailClosed ? null : 0,
      terminationProof: cancel.proof,
      outcomeProof: outcome.proof,
    };
  }, expected: 'BLOCKED_UNVERIFIED' });
  return { trials, cleanup: () => { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(outside, { recursive: true, force: true }); } };
}

export async function runCorpus({ runId, executorId, nonceBase, outputRoot }) {
  if (!runId || !executorId || !nonceBase || !outputRoot) throw new Error('CORPUS_ARGUMENTS_REQUIRED');
  const corpus = buildCorpus();
  const oracle = buildExpectedCorpusOracle();
  const corpusDigest = oracle.digest;
  const engine = createPolicyEngine({ now: NOW });
  const sandboxSet = sandboxTrialSet(fs.mkdtempSync(path.join(os.tmpdir(), 's2-002-corpus-ws-')));
  const observations = [];

  const record = (observation) => { observations.push(observation); };

  // Engine trials: ACL matrix + capability/derived/nonce cells, in order.
  for (const trial of corpus) {
    const result = engine.authorize({
      adapter: 'api',
      principalId: trial.principalId,
      action: trial.action,
      workspaceId: trial.workspaceId,
      resource: trial.resource,
      lease: trial.lease,
      args: trial.args ?? { workspace_id: trial.workspaceId },
    });
    record({
      trialId: trial.id,
      kind: trial.kind,
      principalId: trial.principalId,
      workspaceId: trial.workspaceId,
      action: trial.action,
      expected: trial.expected,
      decision: result.decision,
      reasonCodes: result.reasonCodes,
      crossTenant: trial.crossTenant === true,
      match: result.decision === trial.expected,
    });
  }

  // Sandbox trials (including the live cancellation probe and its negative
  // control). A trial may return a bare observed value, or an object carrying
  // the observed value plus the survivor accounting used by the hard counter.
  for (const trial of sandboxSet.trials) {
    const result = await trial.run();
    const detail = typeof result === 'string' ? { observed: result } : result;
    const observed = detail.observed;
    const survivors = detail.survivors;
    // A control this platform cannot exercise at all is NOT_RUN: nothing was
    // violated and nothing was proven. main's shape treats an unobserved
    // outcome as a fail-closed count of one; this marker is what lets the
    // record say WHICH of the two happened, so a declined measurement is never
    // filed as a safety failure and never laundered into a zero.
    const notRun = observed === NOT_RUN_PLATFORM;
    const record = {
      trialId: trial.id,
      kind: 'sandbox',
      expected: trial.expected,
      observed,
      // BLOCKED_SANDBOX, not DENY: the tier is unavailable here, so the honest
      // decision is that the control did not happen.
      decision: notRun ? 'BLOCKED_SANDBOX' : (observed === trial.expected ? 'ALLOW' : 'DENY'),
      reasonCodes: [notRun
        ? 'SANDBOX_CONTROL_NOT_EXERCISED_ON_PLATFORM'
        : (observed === trial.expected ? 'SANDBOX_CONTROL_AS_EXPECTED' : 'SANDBOX_CONTROL_VIOLATED')],
      observed,
      notRun,
      // `null` rather than `false`: not a mismatch, and not a pass either.
      match: notRun ? null : observed === trial.expected,
    };
    if (trial.survivorTrial) {
      // survivors is a non-negative count, or null when the tree could not be
      // observed. The counter below turns null and any mismatch into at least
      // one survivor, so an unproven outcome can never read as zero. A trial
      // this platform declined has no count at all, which lands in the same
      // null branch — the two are both "not measured", and the reason code
      // above is what distinguishes them.
      record.survivors = Number.isInteger(survivors) && survivors >= 0 ? survivors : null;
      record.terminationProof = detail.terminationProof ?? null;
      record.outcomeProof = detail.outcomeProof ?? null;
      if (detail.processQueries) record.processQueries = detail.processQueries;
    }
    observations.push(record);
  }
  sandboxSet.cleanup();

  // Revocation decision latency: fresh engine per trial, commit-to-deny time.
  const revocationLatencies = [];
  let allowAfterCommit = 0;
  for (let i = 0; i < REVOCATION_TRIALS; i += 1) {
    const trialEngine = createPolicyEngine({ now: NOW });
    const grantRequest = {
      adapter: 'api',
      principalId: 'prn-agent-alice',
      workspaceId: 'ws-alice-private',
      action: 'board.read',
      resource: { type: 'board', id: 'board:primary' },
      args: { workspace_id: 'ws-alice-private' },
    };
    const before = trialEngine.authorize(grantRequest);
    if (before.decision !== 'ALLOW') throw new Error(`REVOCATION_TRIAL_PRECONDITION_FAILED: ${i}`);
    const started = process.hrtime.bigint();
    trialEngine.revokeGrant('grt-alice-agent-read-0001');
    const after = trialEngine.authorize(grantRequest);
    const latencyMs = Number(process.hrtime.bigint() - started) / 1e6;
    if (after.decision !== 'DENY') allowAfterCommit += 1;
    revocationLatencies.push(latencyMs);
    record({
      trialId: `revocation/${String(i).padStart(3, '0')}`,
      kind: 'revocation_latency',
      expected: 'DENY',
      decision: after.decision,
      reasonCodes: after.reasonCodes,
      latencyMs,
      match: after.decision === 'DENY',
    });
  }

  // Hard counters, computed strictly from recorded observations.
  // survivors_after_cancellation is fail-closed and cannot be laundered:
  //   - a mismatching trial contributes at least one, whatever it reported;
  //   - a claimed SURVIVORS_ZERO contributes zero only with a non-negative
  //     zero AND a TERMINATED proof from both cancel() and the run outcome;
  //   - a claimed BLOCKED_UNVERIFIED contributes zero only with a null
  //     survivor count and an UNVERIFIED proof — the required fail-closed
  //     behaviour for an unavailable process observation;
  //   - every other observed value contributes max(1, survivors).
  // A negative or non-integer survivor count is therefore always a violation.
  const survivorObservations = observations.filter((o) => o.trialId.startsWith('sandbox/cancellation-'));
  const survivorsCounter = survivorObservations.reduce((sum, o) => {
    const reported = Number.isInteger(o.survivors) && o.survivors >= 0 ? o.survivors : null;
    if (o.match !== true) return sum + 1;
    if (o.observed === 'SURVIVORS_ZERO') {
      return sum + (reported === 0 && o.terminationProof === 'TERMINATED' && o.outcomeProof === 'TERMINATED' ? 0 : 1);
    }
    if (o.observed === 'BLOCKED_UNVERIFIED') {
      return sum + (reported === null && o.terminationProof === 'UNVERIFIED' && o.outcomeProof === 'UNVERIFIED' ? 0 : 1);
    }
    return sum + Math.max(1, reported ?? 1);
  }, 0);
  const counters = {
    // Visible, informational: how many sandbox controls this host could not
    // exercise. Never a substitute for the hard counters.
    not_run_controls: observations.filter((o) => o.notRun === true).length,
    cross_tenant_success: observations.filter((o) => o.crossTenant && o.decision === 'ALLOW').length,
    authority_expansion: observations.filter((o) => ['DENY', 'BLOCKED_SANDBOX'].includes(o.expected) && o.decision === 'ALLOW' && o.kind !== 'sandbox').length
      + observations.filter((o) => o.kind === 'sandbox' && SANDBOX_EXPECTED_VALUES.includes(o.expected) && o.observed === 'ALLOWED').length,
    // A REAL escape: a filesystem/network/environment/secret control that came
    // back ALLOWED. Counting every sandbox mismatch here was wrong twice over —
    // it reported a surviving child process as a "secret escape", and it
    // double-counted a case `authority_expansion` already carries through the
    // same narrow expectation list. A counter must state what it measured.
    fs_network_secret_escapes: observations.filter((o) => o.kind === 'sandbox'
      && SANDBOX_CONTAINMENT_EXPECTATIONS.includes(o.expected) && o.observed === 'ALLOWED').length,
    // Every EXERCISED sandbox control that did not behave as expected and is not
    // an escape — the cancellation control is the live case. Informational here;
    // the gate blocks on it by deriving the same thing from the observations, so
    // this counter is a name, not the enforcement point.
    sandbox_control_violations: observations.filter((o) => o.kind === 'sandbox'
      && o.match === false && o.notRun !== true).length,
    // main's proof-aware, fail-closed counter: a claimed SURVIVORS_ZERO
    // contributes zero only with a non-negative count AND a TERMINATED proof
    // from both cancel() and the run outcome; anything unproven contributes at
    // least one. It replaces the plain sum this branch had, which is the
    // stronger of the two and is the one that stays.
    survivors_after_cancellation: survivorsCounter,
    allow_after_revocation_commit: allowAfterCommit,
    missing_or_censored_trials: observations.filter((o) => o.expected === 'ALLOW' && o.decision !== 'ALLOW').length
      + Math.max(0, corpus.length + sandboxSet.trials.length + REVOCATION_TRIALS - observations.length),
  };

  const latencyStats = {
    trials: revocationLatencies.length,
    maxMs: Math.max(...revocationLatencies),
    meanMs: revocationLatencies.reduce((sum, v) => sum + v, 0) / revocationLatencies.length,
    allowAfterCommit,
  };

  const summary = {
    schemaVersion: 1,
    runId,
    executorId,
    nonceBase,
    outputRoot,
    corpusDigest,
    corpusRevision: CORPUS_REVISION,
    // Host capabilities the frozen corpus depends on. Stated explicitly so a
    // reader can tell "this host cannot create the link-escape fixture" from
    // "this host did create it and the control did not hold".
    linkCapability,
    fixedClock: NOW,
    policyVersion: POLICY_VERSION,
    platform: `${process.platform}/${process.arch} node ${process.version}`,
    trialCount: observations.length,
    counters,
    revocationLatency: latencyStats,
  };

  fs.mkdirSync(outputRoot, { recursive: true });
  fs.writeFileSync(path.join(outputRoot, 'observations.json'), `${JSON.stringify(observations, null, 2)}\n`);
  fs.writeFileSync(path.join(outputRoot, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  return { summary, observations };
}

function main() {
  const args = process.argv.slice(2);
  const read = (flag) => {
    const index = args.indexOf(flag);
    return index >= 0 ? args[index + 1] : undefined;
  };
  const runId = read('--run-id');
  const outputRoot = read('--output-root') ?? path.join('results', 's2-002', runId ?? 'run-x');
  const result = runCorpus({
    runId,
    executorId: read('--executor-id'),
    nonceBase: read('--nonce-base'),
    outputRoot,
  }).then(({ summary }) => {
    console.log(JSON.stringify({ exitCode: 0, outputRoot, summary }, null, 2));
  }).catch((error) => {
    console.error(`CORPUS_RUN_FAILED: ${error.message}`);
    process.exit(1);
  });
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
