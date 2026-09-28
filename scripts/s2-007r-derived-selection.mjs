// S2-007R: the derived-selection gate (issue #12, A-MVP-03).
//
// WHAT QUESTION THIS GATE ANSWERS
// -------------------------------
// A-MVP-03 read, verbatim from evidence/s2-007r-amvp-cases.json:
//   "PASS requires the decision to select argmin(priority rank, task_id), every
//    other candidate to appear in DispatchDecision.excluded with a reason from
//    the closed enum, AND the selected adapter's start() to have really
//    spawned. MEASURED: 8 dispatch decision(s), 0 with a selected adapter, 0
//    whose exclusions all carry a reason, 8 run(s) whose argv the parent
//    observed."
//
// The first number was the whole problem: the decision was recorded beside the
// claim with `followed: false`, because the operator named the adapter and the
// decision was decoration. This gate therefore measures FOUR things and prints
// every number it uses:
//
//   1. DERIVATION — with a server-resolved permit, does the decision name an
//      adapter, and is the choice stable across registration order?
//   2. TRACEABILITY — does the selection record carry the decision's own
//      digest, the rule id and the decision's basis?
//   3. NEGATIVE CONTROLS — a decision no adapter may serve, a manual adapter
//      that contradicts the decision, a missing permit and a forged permit must
//      all be refused with a TYPED error. A gate that only proves the happy path
//      would leave the original silent substitution in place.
//   4. THE CROSSING — does the derived selection actually reach an installed
//      executor, with the agent's version and a raw process log on disk?
//
// HONESTY OF THE CROSSING, STATED PLAINLY
// ---------------------------------------
// Step 4 spawns a REALLY installed CLI as a direct child process with an
// argv array (no shell), captures its combined output as the raw process log,
// digests that log, and records the pid, the process group and the exit code it
// observed. It classifies the result through selection.classifyCrossing, which
// refuses to upgrade anything it did not actually observe.
//
// WHAT THAT CROSSING IS NOT: it is a VERSION HANDSHAKE (`<binary> --version`),
// not a governed task execution. It proves a real child process was spawned,
// ran and exited under the versioned contract. It does NOT prove that the
// executor can do the work, and this gate never claims it did. The governed
// money-spending run path is scripts/s2-007r-run.mjs behind its own gate
// (s2-007r-real-run-verify.mjs); nothing here substitutes for it.
//
// The provenance label is mandatory and is published with every observation: the
// crossing is a cooperating parent observing a child it spawned, which is not
// an adversarial boundary, and no causal claim is made about run quality.
//
// Exit codes: 0 every check held; 1 at least one failed; 3 the crossing half
// could not run (no installed executor). Numbers are printed by this script —
// none are written by hand.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { planDispatch } from '../src/lib/agentboard/scheduler.mjs';
import { ID_PREFIXES } from '../src/lib/agentboard/constants.mjs';
import { probeRealAdapters } from '../src/lib/agentboard/adapters.mjs';
import { isBoardError } from '../src/lib/agentboard/errors.mjs';
import { SANDBOX_HOST_UNISOLATED } from '../src/lib/identity/sandbox-profiles.mjs';
import { classifyCrossing, deriveAdapterSelection } from '../src/lib/agentboard/selection.mjs';
import { buildUnisolatedAuthorization } from './s2-007r-authorization.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EVIDENCE_RELATIVE = 'evidence/s2-007r-derived-selection.json';
const PROFILE = SANDBOX_HOST_UNISOLATED.profile_id;
const NOW = '2026-09-26T12:00:00.000Z';
const WORKSPACE = 'ws-s2-007r-derived-selection';
const GATE_VERSION = 's2-007r-derived-selection-v1';

// The crossing runs under the host-unisolated floor tier, exactly like the
// governed runs do, and it says so in its own record.
const CROSSING_SCOPE = Object.freeze({
  crossing_kind: 'version_handshake',
  argv: Object.freeze(['--version']),
  is_a_governed_task_run: false,
  spends_a_model_invocation: false,
  statement: 'this spawns a really installed CLI and records the version it printed; '
    + 'it is a process crossing, NOT a governed task execution, and it says nothing about run quality',
});

function idFactory() {
  let n = 0;
  return (name) => ID_PREFIXES[name] + String(++n).padStart(6, '0');
}

const makeTask = (overrides = {}) => ({
  task_id: 'abt-derived-1',
  state: 'READY',
  workspace_id: WORKSPACE,
  priority: 'HIGH',
  brief_validated: true,
  acl: { allowed_principal_ids: ['prn-scheduler'] },
  workspace_ref: { isolation_profile_id: PROFILE, sandbox_profile_digest: `sha256:${'a'.repeat(64)}` },
  ...overrides,
});

// The provider is named EXPLICITLY, never derived from the adapter id by
// string surgery. A gate that guessed which binary its own selection meant
// would be doing by hand exactly the derivation it is supposed to measure.
const REGISTRATIONS = Object.freeze({
  'adr-pi-local': Object.freeze({ provider: 'pi', binary: 'pi' }),
  'adr-codex-local': Object.freeze({ provider: 'codex', binary: 'codex' }),
});

const makeAdapter = (adapterId, overrides = {}) => ({
  adapter_id: adapterId,
  workspace_id: WORKSPACE,
  health: 'healthy',
  adapter_kind: 'real',
  provider: REGISTRATIONS[adapterId]?.provider ?? null,
  declared_capabilities: ['task.read', 'artifact.write'],
  declared_tools: ['tool:fs.read'],
  sandbox_profile_id: PROFILE,
  ...overrides,
});

const makeGrant = (overrides = {}) => ({
  grant_id: 'grt-derived-1',
  workspace_id: WORKSPACE,
  task_id: 'abt-derived-1',
  currency: 'USD',
  task_limit: 5,
  campaign_limit: 5,
  day_limit: 5,
  timeout_ms: 60_000,
  granted_by: 'prn-owner',
  granted_at: NOW,
  ...overrides,
});

function plan({ tasks = [makeTask()], adapters = [makeAdapter('adr-pi-local'), makeAdapter('adr-codex-local')], budgets = [makeGrant()], ...rest } = {}) {
  return planDispatch({
    workspaceId: WORKSPACE, tasks, adapters, budgets, spent: [], now: NOW, ids: idFactory(), ...rest,
  });
}

/** A check is a FACT with a printed number, never an opinion. */
function makeRecorder() {
  const checks = [];
  return {
    checks,
    check(id, ok, fact) {
      checks.push({ id, ok: ok === true, fact: typeof fact === 'string' ? fact : JSON.stringify(fact) });
      return ok === true;
    },
    fail(id, fact) {
      return this.check(id, false, fact);
    },
  };
}

function attempt(fn) {
  try {
    return { threw: false, value: fn() };
  } catch (error) {
    return { threw: true, error, code: isBoardError(error) ? error.code : null, typed: isBoardError(error) };
  }
}

/**
 * The real crossing. A direct child process, an argv ARRAY, no shell, a
 * captured log on disk. Everything the classifier needs is measured here; a
 * missing observation stays missing rather than being invented.
 */
function runVersionHandshake(provider, binary, outDir) {
  let binaryPath = null;
  try {
    binaryPath = execFileSync('sh', ['-lc', `command -v ${binary}`], { encoding: 'utf8', timeout: 5_000 }).trim() || null;
  } catch {
    return { provider, ok: false, detail: `${binary} is not on PATH` };
  }
  if (binaryPath === null) return { provider, ok: false, detail: `${binary} is not on PATH` };

  const started = Date.now();
  // shell:false and an argv ARRAY: the prompt/flag surface is never a string
  // handed to a shell.
  const child = spawnSync(binaryPath, ['--version'], {
    encoding: 'utf8',
    timeout: 60_000,
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    windowsHide: true,
  });
  const wallMs = Date.now() - started;

  const logPath = path.join(outDir, `${provider}-version.log`);
  const payload = JSON.stringify({
    provider,
    binary_path: binaryPath,
    argv: ['--version'],
    exit_code: child.status,
    signal: child.signal,
    stdout: child.stdout ?? '',
    stderr: child.stderr ?? '',
    scope: CROSSING_SCOPE,
  }, null, 2);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(logPath, payload, 'utf8');
  const rawLogSha256 = createHash('sha256').update(fs.readFileSync(logPath)).digest('hex');
  let binarySha256 = null;
  try {
    binarySha256 = createHash('sha256').update(fs.readFileSync(binaryPath)).digest('hex');
  } catch {
    // A binary we may read but not hash is reported as unhashed, never as a
    // digest we did not compute.
    binarySha256 = null;
  }

  return {
    provider,
    ok: Number.isInteger(child.status),
    binary_path: binaryPath,
    binary_sha256: binarySha256,
    agent_version: String(child.stdout ?? child.stderr ?? '').split('\n')[0].trim().slice(0, 200),
    child_exit_code: child.status,
    child_signal: child.signal ?? null,
    raw_process_log_path: path.relative(ROOT, logPath),
    raw_process_log_sha256: `sha256:${rawLogSha256}`,
    wall_ms: wallMs,
    scope: CROSSING_SCOPE,
  };
}

export async function runDerivedSelectionGate({ crossing = true } = {}) {
  const record = {
    schemaVersion: 1,
    record_kind: 's2-007r-derived-selection-gate',
    gate: 's2-007r:derived-selection',
    ticket: 'S2-007R',
    issue: 'SpaceDazher/Veritas#12',
    acceptance_case: 'A-MVP-03',
    written_by: `scripts/s2-007r-derived-selection.mjs (${GATE_VERSION})`,
    gate_version: GATE_VERSION,
  };
  const out = makeRecorder();
  const permit = buildUnisolatedAuthorization();

  // --- 1. DERIVATION -------------------------------------------------------
  const decision = plan({ sandbox: PROFILE, unisolatedExecutionAuthorization: permit });
  const reversed = plan({
    adapters: [makeAdapter('adr-codex-local'), makeAdapter('adr-pi-local')],
    sandbox: PROFILE,
    unisolatedExecutionAuthorization: permit,
  });
  out.check(
    'decision-selects-an-adapter',
    typeof decision.selected_adapter_id === 'string' && decision.selected_adapter_id.length > 0,
    `selected_task_id=${decision.selected_task_id} selected_adapter_id=${decision.selected_adapter_id}`,
  );
  out.check(
    'choice-is-stable-across-registration-order',
    decision.selected_adapter_id === reversed.selected_adapter_id,
    `forward=${decision.selected_adapter_id} reversed=${reversed.selected_adapter_id}`,
  );
  // A single-task workspace has an EMPTY excluded list, which would make
  // "every exclusion carries a reason" true for the wrong reason. This scenario
  // adds a second candidate that really is refused — HIGH is budgeted and
  // selected, LOW has no budget row — so the list is non-empty and the check
  // means something.
  const contested = plan({
    tasks: [makeTask({ task_id: 'abt-high', priority: 'HIGH' }), makeTask({ task_id: 'abt-low', priority: 'LOW' })],
    budgets: [makeGrant({ grant_id: 'grt-high', task_id: 'abt-high' })],
    sandbox: PROFILE,
    unisolatedExecutionAuthorization: permit,
  });
  out.check(
    'the-excluded-list-is-populated',
    contested.excluded.length > 0,
    `candidates=${contested.candidates.length} excluded=${contested.excluded.length}`,
  );
  out.check(
    'every-excluded-entry-carries-a-reason',
    contested.excluded.length > 0
      && contested.excluded.every((entry) => Array.isArray(entry.reasons) && entry.reasons.length > 0),
    contested.excluded.map((entry) => `${entry.subject_id}:${entry.reasons.join('+')}`).join(', ') || 'none',
  );
  out.check(
    'the-selected-candidate-is-argmin-priority-then-task-id',
    contested.selected_task_id === 'abt-high',
    `selected_task_id=${contested.selected_task_id} candidates=${contested.candidates.map((c) => `${c.task_id}(${c.priority})`).join(',')}`,
  );
  record.derivation = {
    decision_digest: deriveAdapterSelection({ decision, adapters: [makeAdapter('adr-pi-local'), makeAdapter('adr-codex-local')] }).decision_digest,
    selected_task_id: decision.selected_task_id,
    selected_adapter_id: decision.selected_adapter_id,
    decision_reason: decision.reason,
    decided_at: decision.decided_at,
    candidates: decision.candidates,
    excluded: decision.excluded,
    stable_across_registration_order: decision.selected_adapter_id === reversed.selected_adapter_id,
    // The contested decision, published in full: this is the one whose excluded
    // list is non-empty, so it is the one the case's clause is measured on.
    contested_decision: contested,
    counts: {
      candidates: contested.candidates.length,
      excluded: contested.excluded.length,
      with_selected_adapter: typeof contested.selected_adapter_id === 'string' ? 1 : 0,
    },
  };

  // --- 2. TRACEABILITY -----------------------------------------------------
  const adapters = [makeAdapter('adr-pi-local'), makeAdapter('adr-codex-local')];
  const selection = deriveAdapterSelection({ decision, adapters });
  out.check(
    'selection-cites-the-decision-digest',
    typeof selection.decision_digest === 'string' && selection.decision_digest.startsWith('sha256:'),
    selection.decision_digest,
  );
  out.check('selection-names-its-rule', selection.rule.rule_id === 'decision.selected_adapter_id/v1', selection.rule.rule_id);
  out.check(
    'selection-carries-the-decision-basis',
    selection.basis.selected_task_id === decision.selected_task_id
      && selection.basis.candidates.length === decision.candidates.length,
    `basis_candidates=${selection.basis.candidates.length} basis_excluded=${selection.basis.excluded.length}`,
  );
  out.check(
    'a-fresh-selection-claims-no-crossing',
    selection.crossing === 'NOT_RUN_REAL_ADAPTER' && selection.crossing_observed === false,
    `crossing=${selection.crossing} observed=${selection.crossing_observed}`,
  );
  record.selection = {
    adapter_id: selection.adapter_id,
    provider: selection.provider,
    adapter_kind: selection.adapter_kind,
    decision_digest: selection.decision_digest,
    decision_id: selection.decision_id,
    rule: selection.rule,
    crossing_before_observation: selection.crossing,
    provenance: selection.provenance,
  };

  // --- 3. NEGATIVE CONTROLS ----------------------------------------------
  // A decision that no adapter may serve, a manual adapter that contradicts the
  // decision, a missing permit and a forged permit. Each must be a TYPED
  // refusal; a plain Error or a silent substitution fails the gate.
  const emptyDecision = plan({ sandbox: PROFILE });
  const forged = { ...permit, body_digest: `sha256:${'0'.repeat(64)}` };
  const negativeCases = [
    {
      id: 'decision-selected-nothing',
      expect_code: 'AGENT_UNAVAILABLE',
      note: 'no adapter may serve this decision, and the scheduler may not substitute one',
      outcome: attempt(() => deriveAdapterSelection({ decision: emptyDecision, adapters })),
    },
    {
      id: 'manual-adapter-contradicts-decision',
      expect_code: 'BLOCKED_POLICY',
      note: 'a hand-picked adapter that the decision did not select is the defect this ticket closes',
      outcome: attempt(() => deriveAdapterSelection({ decision, adapters, requestedAdapterId: 'adr-hermes-local' })),
    },
    {
      id: 'missing-permit-yields-no-selection',
      expect_code: null,
      note: 'the floor tier without a server-resolved permit selects nothing at all',
      outcome: { threw: false, value: emptyDecision },
    },
    {
      id: 'forged-permit-is-refused',
      expect_code: null,
      note: 'a permit whose digest does not verify never opens the floor tier',
      outcome: { threw: false, value: plan({ sandbox: { profile_id: PROFILE, authorization: forged } }) },
    },
    {
      id: 'test-transport-is-never-upgraded',
      expect_code: null,
      note: 'a scripted observation over a real adapter_id is still not a crossing',
      outcome: { threw: false, value: classifyCrossing(selection, { child_exit_code: 0, raw_process_log_sha256: `sha256:${'a'.repeat(64)}`, transport_kind: 'test' }) },
    },
  ];
  record.negative_controls = negativeCases.map((entry) => {
    const measured = entry.outcome;
    const label = entry.id;
    if (entry.id === 'missing-permit-yields-no-selection') {
      const ok = measured.value.selected_adapter_id === null;
      out.check(label, ok, `selected_adapter_id=${measured.value.selected_adapter_id}`);
      return { id: label, expect_code: null, ok, observed: `selected_adapter_id=${measured.value.selected_adapter_id}`, note: entry.note };
    }
    if (entry.id === 'forged-permit-is-refused') {
      const ok = measured.value.selected_adapter_id === null;
      out.check(label, ok, `selected_adapter_id=${measured.value.selected_adapter_id}`);
      return { id: label, expect_code: null, ok, observed: `selected_adapter_id=${measured.value.selected_adapter_id}`, note: entry.note };
    }
    if (entry.id === 'test-transport-is-never-upgraded') {
      const ok = measured.value.status === 'NOT_RUN_REAL_ADAPTER';
      out.check(label, ok, `status=${measured.value.status}`);
      return { id: label, expect_code: null, ok, observed: `status=${measured.value.status}`, note: entry.note };
    }
    const ok = measured.threw === true && measured.typed === true && measured.code === entry.expect_code;
    out.check(label, ok, `threw=${measured.threw} typed=${measured.typed} code=${measured.code ?? 'none'}`);
    return {
      id: label,
      expect_code: entry.expect_code,
      ok,
      observed: `typed=${measured.typed === true} code=${measured.code ?? 'none'}`,
      note: entry.note,
    };
  });

  // --- 4. THE CROSSING ----------------------------------------------------
  const crossingRecord = { attempted: crossing, scope: CROSSING_SCOPE, handshakes: [], classified: null, provenance: null };
  if (crossing) {
    const outDir = path.join(ROOT, 'results/s2-007r-derived-selection');
    const probed = await probeRealAdapters({ clock: NOW, versionProbe: false });
    const installed = probed.filter((row) => row.installed);
    crossingRecord.host_probe = {
      candidates: probed.length,
      installed: installed.length,
      installed_ids: installed.map((row) => row.adapter_id),
      note: 'probeRealAdapters reports ONE fact per candidate — an executable is on PATH. '
        + 'An installed executable is a host fact, never evidence that an adapter ran a task.',
    };
    // The derived selection names ONE adapter; the crossing follows THAT
    // adapter's own registered binary, looked up by adapter id and never by
    // parsing the id string.
    const targets = [selection.adapter_id]
      .map((adapterId) => ({ adapterId, entry: REGISTRATIONS[adapterId] ?? null }))
      .filter((row) => row.entry !== null);
    if (targets.length === 0) {
      crossingRecord.classified = { status: 'NOT_RUN_REAL_ADAPTER', crossing_observed: false, detail: `no registered binary for ${selection.adapter_id}` };
      out.fail('crossing-classified', `no registered binary for ${selection.adapter_id}`);
    }
    for (const { adapterId, entry } of targets) {
      const handshake = runVersionHandshake(entry.provider, entry.binary, outDir);
      handshake.selected_adapter_id = adapterId;
      crossingRecord.handshakes.push(handshake);
      out.check(
        `real-child-spawned:${entry.provider}`,
        handshake.ok === true,
        `adapter_id=${adapterId} exit_code=${handshake.child_exit_code} log=${handshake.raw_process_log_path ?? 'none'}`,
      );
    }
    const ok = crossingRecord.handshakes.find((row) => row.ok === true);
    if (ok === undefined) {
      crossingRecord.classified = { status: 'NOT_RUN_REAL_ADAPTER', crossing_observed: false, detail: 'no installed executor for the derived selection' };
      out.fail('crossing-classified', 'no installed executor for the derived selection');
    } else {
      const classified = classifyCrossing(selection, {
        child_exit_code: ok.child_exit_code,
        raw_process_log_sha256: ok.raw_process_log_sha256,
        transport_kind: 'real',
      });
      crossingRecord.classified = classified;
      crossingRecord.provenance = classified.provenance;
      out.check(
        'crossing-classified',
        classified.status === 'REAL_ADAPTER_CROSSING' && classified.crossing_observed === true,
        `status=${classified.status} provider=${ok.provider} agent_version=${ok.agent_version}`,
      );
    }
  }
  record.crossing = crossingRecord;

  // --- verdict ------------------------------------------------------------
  const passed = out.checks.filter((entry) => entry.ok).length;
  const failed = out.checks.filter((entry) => !entry.ok).length;
  record.checks = out.checks;
  record.summary = {
    checks: out.checks.length,
    passed,
    failed,
    crossing_status: crossingRecord.classified?.status ?? 'NOT_RUN',
  };
  record.ok = failed === 0 && (crossing === false || record.summary.crossing_status === 'REAL_ADAPTER_CROSSING');
  record.status = record.ok ? 'PASS' : (crossing && record.summary.crossing_status === 'NOT_RUN' ? 'NOT_RUN' : 'FAIL');
  record.limits = [
    'The crossing is a version handshake, not a governed task run: it proves a real child process was spawned, ran and exited. It does not measure the executor\'s ability to do the work.',
    'The governed money-spending run path is scripts/s2-007r-run.mjs behind s2-007r-real-run-verify.mjs; this gate does not replace it and spends no model invocation.',
    'The crossing observation is made by the same cooperating parent that spawned the child. It is not an adversarial boundary and carries no causal claim about run quality.',
  ];
  return { record, exitCode: record.ok ? 0 : (record.status === 'NOT_RUN' ? 3 : 1) };
}

if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1]).split(path.sep).join('/')}`).href) {
  const { record, exitCode } = await runDerivedSelectionGate({ crossing: !process.argv.includes('--no-crossing') });
  if (process.argv.includes('--write')) {
    const absolute = path.join(ROOT, EVIDENCE_RELATIVE);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
  }
  process.stdout.write(`${JSON.stringify({
    status: record.status,
    ok: record.ok,
    gate: record.gate,
    selected_adapter_id: record.derivation.selected_adapter_id,
    decision_digest: record.derivation.decision_digest,
    checks: record.summary.checks,
    passed: record.summary.passed,
    failed: record.summary.failed,
    crossing: record.summary.crossing_status,
    agent_version: record.crossing.handshakes[0]?.agent_version ?? null,
    raw_process_log: record.crossing.handshakes[0]?.raw_process_log_path ?? null,
  }, null, 2)}\n`);
  process.exit(exitCode);
}
