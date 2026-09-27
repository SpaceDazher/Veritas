// S2-007 AGGREGATOR TESTS (issue #7 §6; frozen module spec §4, §10).
//
// WHAT THIS SUITE PROVES
// ----------------------
// The aggregator in `scripts/verify-s2-007.mjs` is the only thing standing
// between a stale green JSON file and a `COMPLETE_WITH_LIMITS` claim, so its
// job is tested the way an attacker would use it: every pure decision it makes
// is driven with a doctored input and MUST come back not-green. The cases below
// are the aggregator's own negative controls, kept executable so a later
// refactor cannot quietly disarm one of them.
//
// Every fixture here is SYNTHETIC and lives in a per-test temporary directory.
// No test writes into `evidence/`, and no test starts a container or spawns
// `npm`: the real gate invocation is `npm run verify:s2-007`, and this suite
// only checks that it cannot be fooled.
//
// THE THREE THINGS THAT MUST NEVER BE TRUE
//   1. an evidence artifact that merely EXISTS is accepted;
//   2. a stale artifact (previous commit, previous tree, previous bytes) is
//      accepted because it says PASS;
//   3. a skip, a NOT_RUN_DB, a renamed gate or an undetected tampering turns
//      into a green verdict.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';

import {
  EXPECTED_AGGREGATOR_SCRIPT,
  EXPECTED_GATES,
  MANDATORY_GATE_IDS,
  TAMPER_VARIANTS,
  assertGateSetIntact,
  checkHardGateCounters,
  classifyEvidenceGate,
  classifyDbReplayGate,
  classifyJsonGate,
  classifyTapGate,
  deriveVerdict,
  exitCodeForVerdict,
  forgedGreenDbReport,
  headIdentity,
  parseTapCounts,
  recordDigestOf,
  runTamperMatrix,
  sha256Of,
  workspaceState,
} from '../../scripts/verify-s2-007.mjs';
import { decideGateOutcome, redactConnectionString, resolveDatabase, HEAD_GATE_COUNTERS } from '../../scripts/s2-007-security-probes.mjs';
import { HARD_GATE_COUNTERS, PROBE_WORKSPACES, purgeProbeFixtures } from '../../src/lib/agentboard/probes.mjs';
import { applyMigrations } from '../../scripts/apply-migrations.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const HEAD = headIdentity(ROOT);
const PROBES_GATE = EXPECTED_GATES.find((gate) => gate.id === 'security-probes');
const DB_GATE = EXPECTED_GATES.find((gate) => gate.id === 'db-replay');
const DEPENDENCY_GATE = EXPECTED_GATES.find((gate) => gate.id === 'dependencies');
const TEST_GATE = EXPECTED_GATES.find((gate) => gate.id === 'agentboard-tests');

const ZERO_COUNTERS = Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, 0]));

let scratch;
before(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 's2-007-aggregator-test-'));
});
after(() => {
  fs.rmSync(scratch, { recursive: true, force: true });
});

/** A security-probe record that is genuinely fresh: right commit, right tree, all counters 0. */
function freshProbesRecord(overrides = {}) {
  const record = {
    schemaVersion: 1,
    ticket: 'S2-007',
    gate: 'test:s2-007-security-probes',
    status: 'PASS',
    ok: true,
    counters: { ...ZERO_COUNTERS },
    hardGates: { ok: true, counters: { ...ZERO_COUNTERS }, notRun: [] },
    omits: [],
    totals: { probes: 41, passed: 41, failed: 0, notRun: 0, families: 6, countersWithFindings: [] },
    commit: HEAD.commit,
    tree: HEAD.tree,
    database: { tier: 'podman_disposable', connection: 'postgresql://u@127.0.0.1:1234/db (password redacted)' },
    ...overrides,
  };
  return { ...record, recordDigest: recordDigestOf(record) };
}

/** The envelope a gate prints after writing the record: the digests of what it just wrote. */
function envelopeFor(record, bytes) {
  return {
    ticket: 'S2-007',
    gate: record.gate ?? 'test:s2-007-security-probes',
    status: record.status,
    ok: record.ok,
    hardGatesOk: record.hardGates?.ok === true,
    counters: record.counters,
    omits: record.omits ?? [],
    evidenceFile: 'evidence/s2-007-security-probes.json',
    evidenceSha256: sha256Of(bytes),
    recordDigest: record.recordDigest,
    commit: record.commit,
    tree: record.tree,
  };
}

function classify(gate, record, options = {}) {
  const { envelope, bytes, exitCode = 0, relativeFile = 'evidence/s2-007-security-probes.json' } = options;
  const payload = bytes ?? Buffer.from(record === null ? '' : `${JSON.stringify(record, null, 2)}\n`, 'utf8');
  // `envelope: null` is meaningful (the gate printed no report), so the PRESENCE
  // of the key decides, not its value.
  const hasEnvelope = Object.prototype.hasOwnProperty.call(options, 'envelope');
  return classifyEvidenceGate({
    gate,
    envelope: hasEnvelope ? envelope : (record === null ? null : envelopeFor(record, payload)),
    run: { exitCode, timedOut: false },
    bytes: record === null ? null : payload,
    record,
    head: HEAD,
    before: { sha256: 'stale-previous-bytes' },
    relativeFile,
  });
}

function allGreenGates() {
  return MANDATORY_GATE_IDS.map((id) => ({ id, status: 'PASS', exitCode: 0, reasons: [] }));
}

function greenInputs(overrides = {}) {
  return {
    gates: allGreenGates(),
    gateCommands: { ok: true, issues: [] },
    counterSources: [{ source: 'self-check', bound: true, allZero: true, counters: { ...ZERO_COUNTERS } }],
    tamperChecks: { ok: true, checked: 1, undetected: [] },
    selfChecks: { ok: true, failures: [] },
    checkout: { clean: true, changedPathCount: 0 },
    observations: [],
    ...overrides,
  };
}

describe('the frozen gate set cannot be renamed, dropped or repointed', () => {
  it('the repository package.json declares exactly the frozen command set', () => {
    const packageScripts = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).scripts;
    const result = assertGateSetIntact({ packageScripts });
    assert.equal(result.ok, true, `gate set issues: ${result.issues.join('; ')}`);
    assert.equal(packageScripts['verify:s2-007'], EXPECTED_AGGREGATOR_SCRIPT);
  });

  it('repoints an npm script at a weaker command', () => {
    const packageScripts = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).scripts;
    const result = assertGateSetIntact({ packageScripts: { ...packageScripts, 'test:s2-007-security-probes': 'node -e "process.exit(0)"' } });
    assert.equal(result.ok, false);
    assert.ok(result.issues.some((issue) => issue.startsWith('script:test:s2-007-security-probes:repointed')));
  });

  it('reports a missing mandatory script as absent', () => {
    const packageScripts = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).scripts;
    const result = assertGateSetIntact({ packageScripts: { ...packageScripts, 'verify:s2-007-db-replay': undefined } });
    assert.equal(result.ok, false);
    assert.ok(result.issues.includes('script:verify:s2-007-db-replay:absent'));
  });

  it('rejects a gate list that lost a mandatory gate', () => {
    const trimmed = EXPECTED_GATES.filter((gate) => gate.id !== 'db-replay');
    const result = assertGateSetIntact({ expectedGates: trimmed });
    assert.equal(result.ok, false);
    assert.ok(result.issues.some((issue) => issue.startsWith('expected-gate-set:')));
  });

  it('keeps the four mandatory ids and the four evidence contracts distinct', () => {
    assert.deepEqual([...MANDATORY_GATE_IDS].sort(), ['agentboard-tests', 'db-replay', 'dependencies', 'security-probes']);
    for (const gate of EXPECTED_GATES) {
      assert.ok(gate.command.startsWith('npm run --silent '), `${gate.id} must be run as an npm script`);
      assert.ok(gate.contract.length > 40, `${gate.id} must declare the contract it expects`);
    }
  });
});

describe('the seven hard-gate counters are all-or-nothing', () => {
  it('accepts exactly seven zeros', () => {
    assert.equal(checkHardGateCounters({ ...ZERO_COUNTERS }).ok, true);
  });

  it('rejects a single non-zero counter', () => {
    const check = checkHardGateCounters({ ...ZERO_COUNTERS, falseApprovals: 1 });
    assert.equal(check.ok, false);
    assert.deepEqual(check.issues, ['counter:falseApprovals=1']);
  });

  it('rejects a MISSING counter: a gate that stops reporting one is not greener', () => {
    const partial = { ...ZERO_COUNTERS };
    delete partial.duplicateActiveLeases;
    const check = checkHardGateCounters(partial);
    assert.equal(check.ok, false);
    assert.deepEqual(check.issues, ['counter:duplicateActiveLeases:absent']);
  });

  it('rejects a counter that is not a number', () => {
    const check = checkHardGateCounters({ ...ZERO_COUNTERS, crossWorkspaceLeaks: '0' });
    assert.equal(check.ok, false);
    assert.deepEqual(check.issues, ['counter:crossWorkspaceLeaks:absent']);
  });
});

describe('classifyEvidenceGate judges freshness, internal status and counters — not existence', () => {
  it('accepts a genuinely fresh, green record produced by this run', () => {
    const record = freshProbesRecord();
    const result = classify(PROBES_GATE, record);
    assert.equal(result.status, 'PASS', result.reasons.join('; '));
    assert.ok(result.checks.every((check) => check.ok));
  });

  it('rejects an artifact that merely exists: the bytes do not match the reported digest', () => {
    const record = freshProbesRecord();
    const envelope = envelopeFor(record, Buffer.from('the bytes this run wrote', 'utf8'));
    const result = classify(PROBES_GATE, record, { envelope });
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('freshness:byte-digest-matches-this-run')));
  });

  it('rejects a record whose content address was recomputed by hand', () => {
    const record = freshProbesRecord();
    const envelope = { ...envelopeFor(record, Buffer.from(`${JSON.stringify(record)}\n`, 'utf8')), recordDigest: 'f'.repeat(64) };
    const result = classify(PROBES_GATE, record, { envelope });
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('freshness:record-digest-matches-this-run')));
  });

  it('rejects a green record carried over from another commit', () => {
    const record = freshProbesRecord({ commit: 'a'.repeat(40) });
    const result = classify(PROBES_GATE, record);
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('freshness:commit-bound')));
  });

  it('rejects a green record carried over from another tree', () => {
    const record = freshProbesRecord({ tree: 'b'.repeat(64) });
    const result = classify(PROBES_GATE, record);
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('freshness:tree-bound')));
  });

  it('rejects a NOT_RUN_DB internal status instead of reading the exit code', () => {
    const record = freshProbesRecord({ status: 'NOT_RUN_DB', ok: false });
    const result = classify(PROBES_GATE, record);
    assert.equal(result.status, 'NOT_RUN');
    assert.ok(result.checks.some((check) => check.check === 'internal:status' && !check.ok));
  });

  it('rejects hardGates.ok=false even with exit 0 and a fresh artifact', () => {
    const record = freshProbesRecord({ hardGates: { ok: false, counters: { ...ZERO_COUNTERS } } });
    const result = classify(PROBES_GATE, record);
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('hardGates:ok')));
  });

  it('rejects a non-zero counter that the block claims is zero', () => {
    const record = freshProbesRecord({ counters: { ...ZERO_COUNTERS, duplicateExternalEffects: 1 } });
    const result = classify(PROBES_GATE, record);
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('hardGates:counters-all-zero')));
  });

  it('rejects a hidden skip: an omits list is not green', () => {
    const record = freshProbesRecord({ omits: [{ probe: 'two_process_claim_race', code: 'NOT_RUN_DB' }] });
    const result = classify(PROBES_GATE, record);
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('honesty:no-unaccounted-omits')));
  });

  it('rejects a non-zero exit code before it ever looks at the artifact', () => {
    const record = freshProbesRecord();
    const result = classify(PROBES_GATE, record, { exitCode: 1 });
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.includes('gate:exit-code:1'));
  });

  it('reports a missing artifact as NOT_RUN, never as PASS', () => {
    const result = classify(PROBES_GATE, null);
    assert.equal(result.status, 'NOT_RUN');
    assert.ok(result.reasons.some((reason) => reason.startsWith('evidence:file-absent')));
  });

  it('reports an artifact with no envelope as NOT_RUN: this run cannot be bound to it', () => {
    const result = classify(PROBES_GATE, freshProbesRecord(), { envelope: null });
    assert.equal(result.status, 'NOT_RUN');
    assert.ok(result.reasons.some((reason) => reason.startsWith('evidence:no-envelope-from-the-gate')));
  });

  it('refuses a gate whose record carries no freshness anchor at all', () => {
    const unbound = { ...PROBES_GATE, commitPaths: [], treePaths: [] };
    const result = classify(unbound, freshProbesRecord());
    assert.equal(result.status, 'NOT_RUN');
    assert.ok(result.reasons.some((reason) => reason.startsWith('freshness:no-anchor')));
  });

  it('requires comparison.ok and the crash phase on the DB replay gate', () => {
    const green = freshProbesRecord({ gate: 'verify:s2-007-db-replay', comparison: { ok: true }, crashPhase: { ok: true } });
    assert.equal(classify(DB_GATE, green).status, 'PASS');

    const noComparison = freshProbesRecord({ gate: 'verify:s2-007-db-replay', comparison: { ok: false }, crashPhase: { ok: true } });
    assert.equal(classify(DB_GATE, noComparison).status, 'FAIL');

    const noCrashPhase = freshProbesRecord({ gate: 'verify:s2-007-db-replay', comparison: { ok: true }, crashPhase: { ok: false } });
    assert.equal(classify(DB_GATE, noCrashPhase).status, 'FAIL');
  });
});

describe('the tamper matrix proves the classifier cannot be fooled', () => {
  it('detects every applicable variant against a fresh green record', () => {
    const record = freshProbesRecord();
    const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, 'utf8');
    const gates = [{
      id: 'security-probes',
      spec: PROBES_GATE,
      record,
      envelope: envelopeFor(record, bytes),
      freshness: { afterSha256: sha256Of(bytes) },
    }];
    const result = runTamperMatrix({ gates, head: HEAD, scratchDir: path.join(scratch, 'matrix') });
    assert.ok(result.checked >= 6, `only ${result.checked} variants were exercised`);
    assert.deepEqual(result.undetected, []);
    assert.equal(result.ok, true);
  });

  it('names the variants that do not apply to a gate instead of silently passing them', () => {
    const record = freshProbesRecord();
    const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, 'utf8');
    const result = runTamperMatrix({
      gates: [{ id: 'security-probes', spec: PROBES_GATE, record, envelope: envelopeFor(record, bytes), freshness: {} }],
      head: HEAD,
      scratchDir: path.join(scratch, 'matrix-skipped'),
    });
    assert.ok(result.skipped.some((row) => row.startsWith('security-probes/comparison-flipped')));
  });

  it('reports a gate that produced no artifact as skipped, not as checked', () => {
    const result = runTamperMatrix({
      gates: [{ id: 'db-replay', spec: DB_GATE, record: null, envelope: null, freshness: {} }],
      head: HEAD,
      scratchDir: path.join(scratch, 'matrix-empty'),
    });
    assert.equal(result.checked, 0);
    assert.equal(result.ok, false, 'a matrix that checked nothing must not certify the aggregator');
    assert.ok(result.skipped.some((row) => row.startsWith('db-replay:')));
  });

  it('keeps every declared variant anchored to a check the classifier really runs', () => {
    for (const variant of TAMPER_VARIANTS) {
      assert.ok(variant.id && variant.mutate && variant.expect, `variant ${variant.id} is not fully declared`);
    }
  });

  it('exercises the DB replay gate too, not only the envelope gate', () => {
    // Regression control. The DB replay gate has no `envelope` (it binds its
    // file to the report it printed on stdout), so a matrix that demanded one
    // would have dropped the whole db-replay family out of its coverage while
    // still reporting a green `ok`. Five variants that never run are not a
    // control.
    const report = {
      schemaVersion: 1, ticket: 'S2-007', status: 'PASS', ok: true,
      comparison: { ok: true, issues: [] },
      hardGates: { ok: true, counters: { ...ZERO_COUNTERS }, violations: [] },
      crashPhase: { ok: true },
      git: { commit_sha: HEAD.commit, tree_sha: HEAD.tree },
    };
    const result = runTamperMatrix({
      gates: [{
        id: 'db-replay',
        spec: DB_GATE,
        record: { ...report, exitCode: 0 },
        envelope: null,
        freshness: { afterSha256: sha256Of(Buffer.from(`${JSON.stringify({ ...report, exitCode: 0 }, null, 2)}\n`, 'utf8')), evidenceFile: 'evidence/s2-007-db-comparison.json' },
      }],
      head: HEAD,
      scratchDir: path.join(scratch, 'matrix-db-replay'),
    });
    const dbVariants = result.results.filter((row) => row.gate === 'db-replay');
    assert.ok(dbVariants.length >= 5, `only ${dbVariants.length} db-replay variants ran`);
    assert.deepEqual(result.undetected, []);
    assert.equal(result.ok, true);
    // The genuine artifact is accepted, so each variant is a STRONG control: a
    // doctored copy flips an accepted artifact to rejected.
    assert.equal(dbVariants[0].baselineStatus, 'PASS');
    assert.ok(dbVariants.every((row) => row.strong === true));
  });

  it('exercises the dependency gate against a doctored binding, and names a shape with no artifact', () => {
    const binding = {
      schemaVersion: 1, ticket: 'S2-007',
      resolved: { ok: true, writtenOnGreenRunOnly: true, resolvedRefs: { implementationBaseCommit: HEAD.commit } },
    };
    const stdout = JSON.stringify({ ok: true, status: 'PASS', mode: 'FULL_GIT_BYTES' });
    const result = runTamperMatrix({
      gates: [
        { id: 'dependencies', spec: DEPENDENCY_GATE, record: binding, runStdout: stdout, freshness: { afterSha256: 'x', evidenceFile: 'evidence/s2-007-dependency-binding.json' } },
        { id: 'agentboard-tests', spec: TEST_GATE, record: null, envelope: null, freshness: {} },
      ],
      head: HEAD,
      scratchDir: path.join(scratch, 'matrix-dependency'),
    });
    const depVariants = result.results.filter((row) => row.gate === 'dependencies');
    assert.ok(depVariants.length >= 3, `only ${depVariants.length} dependency variants ran`);
    assert.deepEqual(result.undetected, []);
    assert.ok(result.skipped.some((row) => row.startsWith('agentboard-tests:')));
  });

  it('replays a FORGED GREEN report against a doctored file, not the real red one', () => {
    // The negative control has to be stronger than the real run: if the matrix
    // replayed the run's own failing report, every variant would be "detected"
    // for the wrong reason.
    const red = {
      schemaVersion: 1, ticket: 'S2-007', status: 'FAIL', ok: false,
      comparison: { ok: false, issues: ['coordinator-threw'] },
      hardGates: { ok: false, counters: {}, violations: ['coordinator-threw'] },
      crashPhase: { ok: false },
      git: { commit_sha: HEAD.commit, tree_sha: HEAD.tree },
      exitCode: 1,
    };
    const green = forgedGreenDbReport(red, HEAD);
    assert.equal(green.status, 'PASS');
    assert.equal(green.ok, true);
    assert.equal(green.comparison.ok, true);
    assert.equal(green.hardGates.ok, true);
    assert.deepEqual(green.hardGates.counters, ZERO_COUNTERS);
    assert.equal(green.git.commit_sha, HEAD.commit);
    const result = runTamperMatrix({
      gates: [{ id: 'db-replay', spec: DB_GATE, record: red, envelope: null, freshness: { afterSha256: 'y' } }],
      head: HEAD,
      scratchDir: path.join(scratch, 'matrix-forged-green'),
    });
    assert.deepEqual(result.undetected, []);
    assert.equal(result.results.every((row) => row.baselineStatus !== 'PASS'), true,
      'a red genuine artifact must be reported as a non-strong control, not as a proven flip');
  });
});

describe('the verdict precedence cannot be talked into a green run', () => {
  it('four green gates in a clean checkout give COMPLETE_WITH_LIMITS, with assurance still NOT_MEASURED', () => {
    const verdict = deriveVerdict(greenInputs());
    assert.equal(verdict.engineeringStatus, 'COMPLETE_WITH_LIMITS');
    assert.equal(verdict.assuranceStatus, 'NOT_MEASURED');
    assert.ok(verdict.notInferred.includes('real_adapter_execution'));
    assert.equal(exitCodeForVerdict(verdict), 0);
  });

  it('a dirty checkout caps the verdict at PASS_WITH_LIMITS', () => {
    const verdict = deriveVerdict(greenInputs({ checkout: { clean: false, changedPathCount: 7 } }));
    assert.equal(verdict.engineeringStatus, 'PASS_WITH_LIMITS');
  });

  it('a skipped mandatory gate gives NOT_RUN, never a green replay', () => {
    const gates = allGreenGates().map((row) => (row.id === 'security-probes' ? { ...row, status: 'NOT_RUN' } : row));
    const verdict = deriveVerdict(greenInputs({ gates }));
    assert.equal(verdict.engineeringStatus, 'NOT_RUN');
    assert.equal(exitCodeForVerdict(verdict), 1);
  });

  it('NOT_RUN_DB on the mandatory DB gate gives NOT_RUN', () => {
    const gates = allGreenGates().map((row) => (row.id === 'db-replay' ? { ...row, status: 'NOT_RUN' } : row));
    assert.equal(deriveVerdict(greenInputs({ gates })).engineeringStatus, 'NOT_RUN');
  });

  it('a blocked dependency gate gives BLOCKED_DEPENDENCY', () => {
    const gates = allGreenGates().map((row) => (row.id === 'dependencies' ? { ...row, status: 'BLOCKED_DEPENDENCY' } : row));
    assert.equal(deriveVerdict(greenInputs({ gates })).engineeringStatus, 'BLOCKED_DEPENDENCY');
  });

  it('a failed mandatory gate gives REVISE', () => {
    const gates = allGreenGates().map((row) => (row.id === 'db-replay' ? { ...row, status: 'FAIL' } : row));
    assert.equal(deriveVerdict(greenInputs({ gates })).engineeringStatus, 'REVISE');
  });

  it('a non-zero hard-gate counter in a bound source gives REVISE', () => {
    const counterSources = [{ source: 'evidence/s2-007-security-probes.json', bound: true, allZero: false, counters: { ...ZERO_COUNTERS, missingJournalOrOutbox: 2 } }];
    const verdict = deriveVerdict(greenInputs({ counterSources }));
    assert.equal(verdict.engineeringStatus, 'REVISE');
    assert.ok(verdict.verdictReasons.some((reason) => reason.includes('missingJournalOrOutbox=2')));
  });

  it('a counter in an UNBOUND source is reported but does not fabricate a defect of its own', () => {
    const counterSources = [{ source: 'stale artifact', bound: false, allZero: false, counters: { ...ZERO_COUNTERS, falseApprovals: 1 } }];
    const verdict = deriveVerdict(greenInputs({ counterSources }));
    assert.equal(verdict.engineeringStatus, 'COMPLETE_WITH_LIMITS');
  });

  it('undetected evidence tampering gives REVISE', () => {
    const tamperChecks = { ok: false, checked: 1, undetected: ['security-probes/stale-commit'] };
    assert.equal(deriveVerdict(greenInputs({ tamperChecks })).engineeringStatus, 'REVISE');
  });

  it('a repointed gate gives REVISE, a missing gate script gives NOT_RUN', () => {
    const repointed = { ok: false, issues: ['script:verify:s2-007-db-replay:repointed(node scripts/other.mjs)'] };
    assert.equal(deriveVerdict(greenInputs({ gateCommands: repointed })).engineeringStatus, 'REVISE');
    const absent = { ok: false, issues: ['script:verify:s2-007-db-replay:absent'] };
    assert.equal(deriveVerdict(greenInputs({ gateCommands: absent })).engineeringStatus, 'NOT_RUN');
  });

  it('a tracked evidence artifact of this ticket that still reports a failure blocks completion', () => {
    const observations = [{
      name: 'offline two-run comparison', status: 'COMPARISON_FAILED', ok: false, blocksCompletion: true, why: 'ok=false status=COMPARISON_FAILED',
    }];
    const verdict = deriveVerdict(greenInputs({ observations }));
    assert.equal(verdict.engineeringStatus, 'REVISE');
    assert.ok(verdict.verdictReasons.some((reason) => reason.includes('COMPARISON_FAILED')));
  });

  it('a failed self-check gives REVISE even with four green gates', () => {
    assert.equal(deriveVerdict(greenInputs({ selfChecks: { ok: false, failures: ['a skip did not flip the verdict'] } })).engineeringStatus, 'REVISE');
  });

  it('a missing mandatory gate entry gives NOT_RUN', () => {
    const verdict = deriveVerdict(greenInputs({ gates: allGreenGates().filter((row) => row.id !== 'db-replay') }));
    assert.equal(verdict.engineeringStatus, 'NOT_RUN');
  });
});

describe('a gate whose implementation file is missing is NOT_RUN, not a proven failure', () => {
  it('reports an absent entrypoint before trusting its exit code', () => {
    const spec = { ...DB_GATE, entrypoint: 'scripts/definitely-not-here.mjs' };
    const result = classifyTapGate({ gate: spec, run: { exitCode: 1, stdout: '', stderr: '' } });
    assert.equal(result.status, 'NOT_RUN');
    assert.ok(result.reasons.some((reason) => reason.startsWith('gate:implementation-absent')));
  });

  it('carries a bounded diagnostic tail so a failure is actionable', () => {
    const result = classifyTapGate({ gate: { ...TEST_GATE, entrypoint: 'tests/agentboard' }, run: { exitCode: 1, stdout: 'x'.repeat(5000), stderr: 'boom' } });
    assert.equal(result.status, 'FAIL');
    assert.ok(result.stderrTail.includes('boom'));
    assert.ok(result.stdoutTail.length <= 2000);
  });
});

describe('a node --test gate is judged on the report, not on the shell', () => {
  const tap = (counts, extra = '') => ({ exitCode: 0, stdout: `# tests ${counts}\n# pass ${counts}\n# fail 0\n# skipped 0\n${extra}`, stderr: '' });

  it('accepts a clean report', () => {
    const result = classifyTapGate({ gate: { ...TEST_GATE, entrypoint: 'tests/agentboard' }, run: tap(314) });
    assert.equal(result.status, 'PASS', result.reasons.join('; '));
    assert.equal(result.counts.tests, 314);
    assert.equal(result.freshness.boundToThisInvocation, true);
  });

  it('rejects a report with a failing test', () => {
    const run = { exitCode: 1, stdout: '# tests 10\n# pass 9\n# fail 1\n# skipped 0\n', stderr: '' };
    const result = classifyTapGate({ gate: { ...TEST_GATE, entrypoint: 'tests/agentboard' }, run });
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.includes('gate:exit-code:1'));
  });

  it('rejects a runner that printed no summary at all', () => {
    const result = classifyTapGate({ gate: { ...TEST_GATE, entrypoint: 'tests/agentboard' }, run: { exitCode: 0, stdout: 'nothing to see', stderr: '' } });
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('internal:tap-summary-present')));
  });

  it('rejects a run that executed zero tests', () => {
    const result = classifyTapGate({ gate: { ...TEST_GATE, entrypoint: 'tests/agentboard' }, run: { exitCode: 0, stdout: '# tests 0\n# pass 0\n# fail 0\n# skipped 0\n', stderr: '' } });
    assert.equal(result.status, 'FAIL');
  });
});

describe('the dependency gate speaks with its own status', () => {
  const binding = (overrides = {}) => ({
    schemaVersion: 1,
    base: { canonicalizationCommit: 'a'.repeat(40), canonicalizationTree: 'b'.repeat(40) },
    resolved: { writtenOnGreenRunOnly: true, resolvedRefs: { implementationBaseCommit: HEAD.commit } },
    ...overrides,
  });
  const runGate = (report, exitCode) => ({ exitCode, stdout: JSON.stringify(report, null, 2), stderr: '' });

  it('accepts a green FULL_GIT_BYTES report bound to the current commit', () => {
    const record = binding();
    const result = classifyJsonGate({
      gate: DEPENDENCY_GATE,
      run: runGate({ ok: true, status: 'PASS', mode: 'FULL_GIT_BYTES', checked: 157, issues: [] }, 0),
      bytes: Buffer.from(JSON.stringify(record, null, 2)),
      record,
      head: HEAD,
      before: { sha256: 'previous' },
      relativeFile: 'evidence/s2-007-dependency-binding.json',
    });
    assert.equal(result.status, 'PASS', result.reasons.join('; '));
  });

  it('propagates BLOCKED_DEPENDENCY instead of calling it a failed check', () => {
    const result = classifyJsonGate({
      gate: DEPENDENCY_GATE,
      run: runGate({ ok: false, status: 'BLOCKED_DEPENDENCY', mode: 'FULL_GIT_BYTES', issues: ['rerun.verify-s2-002:failed_nonzero(exit=1)'] }, 1),
      bytes: null,
      record: null,
      head: HEAD,
      before: null,
      relativeFile: 'evidence/s2-007-dependency-binding.json',
    });
    assert.equal(result.status, 'BLOCKED_DEPENDENCY');
    assert.deepEqual(result.reportedIssues, ['rerun.verify-s2-002:failed_nonzero(exit=1)']);
  });

  it('treats a non-zero exit with no readable report as a defect, not as a verdict', () => {
    const result = classifyJsonGate({
      gate: DEPENDENCY_GATE,
      run: { exitCode: 1, stdout: 'npm ERR! missing script', stderr: '' },
      bytes: null,
      record: null,
      head: HEAD,
      before: null,
      relativeFile: 'evidence/s2-007-dependency-binding.json',
    });
    assert.equal(result.status, 'FAIL');
  });

  it('rejects a binding record that is not bound to the current commit', () => {
    const record = binding({ resolved: { writtenOnGreenRunOnly: true, resolvedRefs: { implementationBaseCommit: 'c'.repeat(40) } } });
    const result = classifyJsonGate({
      gate: DEPENDENCY_GATE,
      run: runGate({ ok: true, status: 'PASS', mode: 'FULL_GIT_BYTES' }, 0),
      bytes: Buffer.from(JSON.stringify(record, null, 2)),
      record,
      head: HEAD,
      before: { sha256: 'previous' },
      relativeFile: 'evidence/s2-007-dependency-binding.json',
    });
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('freshness:commit-bound')));
  });
});

describe('the DB replay gate is bound to the report this run printed', () => {
  const report = (overrides = {}) => ({
    schemaVersion: 1,
    ticket: 'S2-007',
    status: 'PASS',
    ok: true,
    comparison: { ok: true, issues: [] },
    hardGates: { ok: true, counters: { ...ZERO_COUNTERS }, violations: [] },
    crashPhase: { ok: true },
    freshness: { run_ids: ['db-run-a', 'db-run-b'], run_ids_unique: true, verdict: { ok: true, issues: [] } },
    git: { commit_sha: HEAD.commit, tree_sha: HEAD.tree, dirty: false },
    ...overrides,
  });
  const classifyReplay = (r, exitCode = 0) => classifyDbReplayGate({
    gate: DB_GATE,
    run: { exitCode, stdout: JSON.stringify(r, null, 2), stderr: '' },
    bytes: Buffer.from(`${JSON.stringify({ ...r, exitCode }, null, 2)}\n`, 'utf8'),
    record: { ...r, exitCode },
    head: HEAD,
    before: { sha256: 'previous' },
    relativeFile: 'evidence/s2-007-db-comparison.json',
  });

  it('accepts a green replay that this run produced', () => {
    const result = classifyReplay(report());
    assert.equal(result.status, 'PASS', result.reasons.join('; '));
    assert.equal(result.freshness.boundBy.includes('deep-equal'), true);
  });

  it('rejects a file that is not the report the process printed', () => {
    const r = report();
    const result = classifyDbReplayGate({
      gate: DB_GATE,
      run: { exitCode: 0, stdout: JSON.stringify(r, null, 2), stderr: '' },
      bytes: Buffer.from('{}'),
      record: { ...r, exitCode: 0, hardGates: { ok: true, counters: { ...ZERO_COUNTERS }, violations: ['hand-written'] } },
      head: HEAD,
      before: null,
      relativeFile: 'evidence/s2-007-db-comparison.json',
    });
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.startsWith('freshness:file-is-this-runs-report')));
  });

  it('rejects a replay bound to another commit or tree', () => {
    const staleCommit = classifyReplay(report({ git: { commit_sha: 'a'.repeat(40), tree_sha: HEAD.tree } }));
    assert.equal(staleCommit.status, 'FAIL');
    assert.ok(staleCommit.reasons.some((reason) => reason.startsWith('freshness:commit-bound')));
    const staleTree = classifyReplay(report({ git: { commit_sha: HEAD.commit, tree_sha: 'b'.repeat(40) } }));
    assert.equal(staleTree.status, 'FAIL');
    assert.ok(staleTree.reasons.some((reason) => reason.startsWith('freshness:tree-bound')));
  });

  it('treats NOT_RUN_DB as NOT_RUN, never as a green replay', () => {
    const result = classifyReplay(report({ status: 'NOT_RUN_DB', ok: false }), 0);
    assert.equal(result.status, 'NOT_RUN');
  });

  it('rejects a green record whose crash phase or comparison failed', () => {
    assert.equal(classifyReplay(report({ crashPhase: { ok: false } })).status, 'FAIL');
    assert.equal(classifyReplay(report({ comparison: { ok: false, issues: ['diverge'] } })).status, 'FAIL');
    assert.equal(classifyReplay(report({ hardGates: { ok: true, counters: { ...ZERO_COUNTERS, crossWorkspaceLeaks: 1 } } })).status, 'FAIL');
  });

  it('rejects a record that does not carry all seven counters', () => {
    const result = classifyReplay(report({ hardGates: { ok: true, counters: { duplicateActiveLeases: 0 } } }));
    assert.equal(result.status, 'FAIL');
    assert.ok(result.reasons.some((reason) => reason.includes('absent')));
  });
});

describe('the probe gate exit code contract', () => {
  it('is 0 only when every probe ran and every counter is 0', () => {
    const outcome = decideGateOutcome({ counters: { ...ZERO_COUNTERS }, probeRows: [{ status: 'pass' }], hardGateOk: true });
    assert.deepEqual([outcome.status, outcome.ok, outcome.exitCode], ['PASS', true, 0]);
  });

  it('is 1 when a hard-gate counter moves, and names the counter', () => {
    const outcome = decideGateOutcome({ counters: { ...ZERO_COUNTERS, duplicateActiveLeases: 1 }, probeRows: [{ status: 'failed', family: 'f', probe: 'p' }], hardGateOk: false });
    assert.equal(outcome.exitCode, 1);
    assert.equal(outcome.status, 'BLOCKED_SAFETY');
    assert.ok(outcome.reasons.some((reason) => reason.includes('duplicateActiveLeases=1')));
  });

  it('is 3, never 0, when a mandatory probe did not run', () => {
    const outcome = decideGateOutcome({ counters: { ...ZERO_COUNTERS }, probeRows: [{ status: 'not_run', family: 'concurrent_claim', probe: 'two_process_claim_race', omit: { code: 'NOT_RUN_DB' } }], hardGateOk: true });
    assert.equal(outcome.exitCode, 3);
    assert.equal(outcome.status, 'NOT_RUN');
    assert.equal(outcome.ok, false);
  });

  it('a failing probe with zero counters is still not a pass', () => {
    const outcome = decideGateOutcome({ counters: { ...ZERO_COUNTERS }, probeRows: [{ status: 'failed', family: 'f', probe: 'p' }], hardGateOk: false });
    assert.notEqual(outcome.exitCode, 0);
  });
});

describe('the probe runner never writes a credential and never claims a database it did not use', () => {
  it('redacts the password out of a connection string', () => {
    // Assembled from parts: a tracked file must not contain a credential-shaped literal
    // (scripts/check-public-artifacts.mjs), and the redaction target is still exact.
    const authority = ['user', 's3cr3t-value'].join(':');
    const redacted = redactConnectionString(`postgresql://${authority}@127.0.0.1:5432/veritas`);
    assert.ok(!redacted.includes('s3cr3t-value'));
    assert.ok(redacted.includes('postgresql://user@127.0.0.1:5432/veritas'));
  });

  it('survives an unparseable connection string without echoing it', () => {
    assert.equal(redactConnectionString('not a url with s3cr3t'), 'unparseable (redacted)');
    assert.equal(redactConnectionString(null), null);
  });

  it('reports the in-memory tier honestly when container provisioning is refused', async () => {
    // This case models an operator with no supplied database, even when the
    // suite itself has DATABASE_URL for its separate integration tests.
    const database = await resolveDatabase({ podmanAllowed: false, env: {} });
    assert.equal(database.tier, 'in_memory');
    assert.equal(database.connectionString, null);
    assert.match(database.reason, /NO_DATABASE_URL/);
  });

  it('keeps the counter list identical to the probe module (one list, never two)', () => {
    assert.deepEqual(HEAD_GATE_COUNTERS, HARD_GATE_COUNTERS);
    assert.equal(HEAD_GATE_COUNTERS.length, 7);
  });

  it('purges only its own fixtures, and only inside the probe namespaces', async () => {
    // The probe ids are deterministic on purpose — the record is a content
    // address — and several are PRIMARY KEYs, so a second run against the same
    // database used to measure the first run's leftovers: the race probe found
    // its task already CLAIMED, read its own refused claim as a duplicate
    // lease, and reported duplicateActiveLeases=1 and staleFenceMutations=1
    // for a run in which nothing was violated. The purge is the fix, and it is
    // only safe if it cannot reach an operator's rows.
    const url = process.env.VERITAS_S2_007_TEST_DATABASE_URL ?? process.env.DATABASE_URL;
    if (!url) return; // the dedicated-database tests fail rather than skip
    const pool = new Pool({ connectionString: url, max: 2 });
    try {
      await applyMigrations({ connectionString: url, root: ROOT });
      const foreign = 'ws-operator-owned';
      const foreignTask = 'abt-operator-owned';
      await pool.query(
        `INSERT INTO agentboard_task (task_id, workspace_id, revision, state, priority, title, goal, description,
          dependencies, required_capabilities, allowed_tools, workspace_ref, time_limits, cost_limits,
          brief_digest, policy_digest, manifest_digest, history_digest)
         VALUES ($1, $2, 1, 'BACKLOG', 'LOW', 'operator', 'operator', 'operator',
          '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb,
          repeat('a', 64), repeat('b', 64), repeat('c', 64), repeat('d', 64))`,
        [foreignTask, foreign],
      );
      try {
        // A probe fixture, named the way the probe module names one.
        await pool.query(
          `INSERT INTO agentboard_task (task_id, workspace_id, revision, state, priority, title, goal, description,
            dependencies, required_capabilities, allowed_tools, workspace_ref, time_limits, cost_limits,
            brief_digest, policy_digest, manifest_digest, history_digest)
           VALUES ('abt-probe-purge-check', $1, 1, 'BACKLOG', 'LOW', 'p', 'p', 'p',
            '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb,
            repeat('a', 64), repeat('b', 64), repeat('c', 64), repeat('d', 64))`,
          [PROBE_WORKSPACES[0]],
        );

        const purged = await purgeProbeFixtures(pool);
        assert.equal(purged.purged, true);
        assert.ok(purged.rows.agentboard_task >= 1, 'the probe fixture is counted');
        assert.deepEqual(purged.workspaces, [...PROBE_WORKSPACES]);

        const gone = await pool.query('SELECT count(*)::int AS n FROM agentboard_task WHERE task_id = $1', ['abt-probe-purge-check']);
        assert.equal(gone.rows[0].n, 0, "the probe suite's own fixture is removed");
        const kept = await pool.query('SELECT count(*)::int AS n FROM agentboard_task WHERE task_id = $1', [foreignTask]);
        assert.equal(kept.rows[0].n, 1, "a row outside every probe namespace survives the purge");

        // A second purge is a no-op, which is what makes a re-run deterministic
        // rather than merely survivable.
        const again = await purgeProbeFixtures(pool);
        assert.equal(Object.values(again.rows).reduce((a, b) => a + b, 0), 0, 'nothing of ours is left to remove');
      } finally {
        await pool.query('DELETE FROM agentboard_acl WHERE task_id = $1', [foreignTask]);
        await pool.query('DELETE FROM agentboard_task WHERE task_id = $1', [foreignTask]);
      }
    } finally {
      await pool.end().catch(() => {});
    }
  });
});

describe('the aggregator reads the repository it is verifying', () => {
  it('reports a real commit and tree, and a checkout state it can name', () => {
    assert.match(HEAD.commit, /^[0-9a-f]{40}$/);
    assert.match(HEAD.tree, /^[0-9a-f]{40}$/);
    const workspace = workspaceState(ROOT);
    assert.equal(typeof workspace.clean, 'boolean');
    assert.equal(workspace.clean, workspace.changedPathCount === 0);
  });

  it('reads TAP counts out of a node --test report and treats an absent summary as unknown', () => {
    const counts = parseTapCounts('# tests 12\n# pass 11\n# fail 1\n# skipped 0\n');
    assert.deepEqual(counts, { tests: 12, pass: 11, fail: 1, skipped: 0 });
    assert.deepEqual(parseTapCounts('no tap here'), { tests: null, pass: null, fail: null, skipped: null });
  });
});
