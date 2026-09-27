// S2-008 — the two PROCESS-SEPARATED runs, executed (issue
// SpaceDazher/Veritas#8).
//
// A3  the criterion is the FROZEN EXPECTED-VALUE TABLE, not `A === B`
// A2  an interrupted trial and an infra trial are first-class outcomes
// A5  every artefact is bound to a resolved base and survives a repeat run
//
// WHY THIS FILE SPAWNS PROCESSES AT ALL
// The other suites in this track call the comparator IN-PROCESS, which is what
// makes the pure controls cheap: the same corruption can be injected into two
// run records and compared without a scheduler in the way. That is a real
// strength and it is also a limit, because nothing in an in-process test can
// show that two records were produced by two DIFFERENT executions. `A === B`
// over two objects built by the same module in the same process is a statement
// about function purity, not about reproducibility. So this file builds no run
// record in the test process at all: every run below is produced by a REAL
// child `node` process, with its own argv, its own environment, its own pid and
// its own per-process nonce, writing its artefact to disk; the test process
// only READS those artefacts back, verifies their binding and judges them. The
// judge is deliberately a different process from the run, because a run that
// scores itself proves nothing about the run.
//
// WHAT THE CHILDREN ARE, AND WHAT THEY ARE NOT
// Each child executes the track's own deterministic machinery: the run record
// comes from `tests/research/fixtures/fixture-measurement-set.mjs`
// (`buildCleanRun`), the binding comes from `src/lib/research/runner.mjs`
// (`freezeProvenance`, `deriveProcessNonce`, `bindArtefact`, `writeArtefact`,
// `assertArtefactBound`) and the classification of an interrupted trial comes
// from the same file (`classifyTrialObservation`, `reconciliationRow`). Nothing
// in this file invents a run, a verdict or a reconciliation: every assertion is
// made against a record the frozen code produced, and the table it is scored
// against is `src/lib/research/expected-values.mjs`, declared before any run
// happened. `scripts/s2-008-run.mjs --print-record` would be the fuller
// end-to-end subject, but the committed campaign currently refuses with
// NEEDS_INPUT/TRIAL_TIMEOUT_NOT_PREREGISTERED before it can produce a record, so
// scoring its NOT_RUN output would test the refusal and not the property. That
// is reported, not worked around by loosening an assertion.
//
// WHY THE CLEAN PAIR'S CAMPAIGN VERDICT IS `FAIL`, AND WHY THAT IS NOT SOFT
// The frozen table's fourth row is an INFRA trial, and a row that says VIOLATION
// is a VIOLATION: the campaign verdict for this design is FAIL, and the pooled
// interval is UNRESOLVED as well. So no test below asserts "the campaign
// passed" — that would be asserting a result the frozen table does not pin. A3's
// criterion is asserted instead, in the comparator's own words: `findingsA` and
// `findingsB` are EMPTY (both runs agree with the table) and the six controls
// are reported flipped. `digestsEqual` is asserted too, and always labelled as
// the ADDITIONAL condition it is.
//
// WHERE THE CHILDREN WORK
// Under the OS temp directory, one `mkdtemp` tree per test, removed by that
// test's own `t.after`. Nothing is written into the repository: no `evidence/`,
// no `results/`, no `.bb/`. The base is resolved once, with READ-ONLY git
// (`git rev-parse`), because A5's binding is only evidence when it names a
// commit that exists; the fixture's all-zero placeholder SHAs are exactly what
// must not reach a comparison, and `compareParallelTrack` is given the resolved
// pair so it can say `base_mismatch` if a child ever stamps anything else.
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { diffPaths } from '../../scripts/s2-008-run.mjs';
import { compareParallelTrack, resolveCampaignVerdict, resolveTrialVerdict } from '../../src/lib/research/comparator.mjs';
import {
  EXPECTED_CONTROLS, EXPECTED_COUNTERS, EXPECTED_METRIC, EXPECTED_TRIAL_DECISIONS,
  expectedTableDigest, expectedValueIssues,
} from '../../src/lib/research/expected-values.mjs';
import { assertArtefactBound, deriveProcessNonce } from '../../src/lib/research/runner.mjs';
import { decisionContentDigest, corruptedTableDigest } from './fixtures/fixture-corrupted-variants.mjs';
import { ALLOWED_PROCESS_DIFFERENCES, assertRunIdentitiesSeparated, fixtureRunIdentity } from './fixtures/fixture-run-identity.mjs';
import { PREREGISTRATION } from './fixtures/fixture-measurement-set.mjs';
import { TEMP_BASE_MARKER_NAME, purgeTempBase } from './fixtures/fixture-temp-base.mjs';

const REPO = path.resolve(new URL('../../', import.meta.url).pathname);

/** The one line every child prints its evidence on. Prefixed, so a child that
 * also logs cannot make the parent parse a log line as a record. */
const EVIDENCE_PREFIX = '@@S2-008-REPLAY@@';

/** The frozen table, exactly as `scripts/s2-008-harness.mjs` and
 * `tests/research/comparator.test.mjs` hand it to `compareParallelTrack`. */
const EXPECTED_TABLE = Object.freeze({
  EXPECTED_TRIAL_DECISIONS,
  EXPECTED_COUNTERS,
  EXPECTED_METRIC,
  EXPECTED_CONTROLS,
  digest: expectedTableDigest(),
});

/** The preregistration in force, with the table digest it was sealed against. */
const CONFIGURED_PREREG = Object.freeze({ ...PREREGISTRATION, expected_table_digest: expectedTableDigest() });

/** The frozen baseline the pooled agreement rate must equal, read from the
 * preregistration rather than written here: a second copy of the number is a
 * second thing to edit, and this file owns neither. */
const FROZEN_BASELINE = PREREGISTRATION.frozen_baseline.value;

/** Read-only git. Never a mutating call: the delivery worker owns git, and a
 * test that wrote to the repository could decide the base it then proves. */
function readOnlyGit(revision) {
  return execFileSync('git', ['rev-parse', revision], { cwd: REPO, encoding: 'utf8' }).trim();
}

/** The base every artefact below is bound to: a commit and a tree that exist. */
const RESOLVED_BASE = Object.freeze({
  commit_sha: readOnlyGit('HEAD^{commit}'),
  tree_sha: readOnlyGit('HEAD^{tree}'),
});

// --- the child ---------------------------------------------------------------

/**
 * The child program. Written to the test's own temp tree and executed by a real
 * `node` process; it is the only code this file runs outside the test process.
 *
 * Three modes, one per property under test:
 *   `run`         build the run for a label, bind it to the resolved base, write
 *                 the artefact, report what it wrote and what it purged.
 *   `interrupted` announce a trial it is about to execute, write that intent,
 *                 and then WAIT — so the parent can kill it for real, at a
 *                 point where the trial is genuinely undecided.
 *   `reconcile`   start WITHOUT purging, read the leftovers of the killed
 *                 child, classify the interrupted trial and write the open
 *                 reconciliation row.
 *
 * No clock, no randomness, no network, no credentials. The only host-dependent
 * values are the pid and the paths handed in argv/env, and both are reported
 * rather than baked in. Deliberately no template literals in the child: the
 * source is a template literal in this file, and `${` in the child would be read
 * as interpolation here.
 */
const DRIVER = `// S2-008 replay-two-run child. Generated by tests/research/replay-two-run.test.mjs.
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const REPO = process.env.S2_008_REPLAY_REPO;
const EVIDENCE_PREFIX = ${JSON.stringify(EVIDENCE_PREFIX)};
const load = (relative) => import(pathToFileURL(path.join(REPO, relative)).href);

const argv = process.argv.slice(2);
const options = {};
for (let index = 0; index < argv.length; index += 2) {
  const key = argv[index];
  if (typeof key !== 'string' || !key.startsWith('--')) throw new Error('REPLAY_ARGV_INVALID: ' + String(key));
  options[key.slice(2)] = argv[index + 1];
}

// ARGV AND ENV MUST AGREE. The two children are given separate argv AND a
// separate environment, so a disagreement between the two spellings is a real
// defect in the way this suite addresses a process — and it is cheaper to catch
// it in the child than to explain it later.
for (const name of ['mode', 'label', 'attempt']) {
  const fromEnv = process.env['S2_008_REPLAY_' + name.toUpperCase()];
  if (fromEnv !== options[name]) {
    throw new Error('REPLAY_ARGV_ENV_DISAGREE: ' + name + ' is ' + String(options[name]) + ' in argv and ' + String(fromEnv) + ' in env');
  }
}

const mode = options.mode;
const label = options.label;
const attempt = Number(options.attempt);
const step = options.step;
const parent = options.parent;
const commit = options.commit;
const tree = options.tree;

const { CLEAN_RUNS, PREREGISTRATION, PREREGISTRATION_DIGEST, buildCleanRun, buildRunBoundToTable } = await load('tests/research/fixtures/fixture-measurement-set.mjs');
const { buildVariant, decisionContentDigest } = await load('tests/research/fixtures/fixture-corrupted-variants.mjs');
const { assertStrictlyInside, createTempBase, listTempBase, readTempFile } = await load('tests/research/fixtures/fixture-temp-base.mjs');
const { fixtureRunIdentity } = await load('tests/research/fixtures/fixture-run-identity.mjs');
const { FIXED_INSTANT_ISO } = await load('tests/research/fixtures/fixture-fixed-clock.mjs');
const { bindArtefact, classifyTrialObservation, deriveProcessNonce, freezeProvenance, reconciliationRow, writeArtefact } = await load('src/lib/research/runner.mjs');
const { expectedTableDigest } = await load('src/lib/research/expected-values.mjs');
const researchConstants = await load('src/lib/research/constants.mjs');

const deps = { constants: researchConstants };
const report = (payload) => { process.stdout.write(EVIDENCE_PREFIX + JSON.stringify(payload) + '\\n'); };
const identity = fixtureRunIdentity(label);

// The provenance of THIS process: the resolved base, the label's own raw run
// id, and a nonce derived from the real pid. Two children therefore differ in
// their nonce because they are different processes, not because a constant was
// edited. The clock is the fixed instant, so nothing here reads a wall clock.
const provenanceFor = (runId) => freezeProvenance({
  commit,
  tree,
  runId,
  label,
  executorId: 'exec-s2-008-' + label,
  nonce: deriveProcessNonce({ label, runId, attempt, pid: process.pid }),
  attempt,
  pid: process.pid,
  clock: FIXED_INSTANT_ISO,
});

// An infra outcome laundered into "no effect": the trial is rewritten as a
// RESOLVED zero and folded into the pooled counts, which is precisely what the
// table must never accept.
const launderInfraIntoZero = (run) => {
  const trials = run.trials.map((trial) => (trial.not_measured === true ? {
    ...trial,
    status: 'RESOLVED',
    outcome: 'NEGATIVE',
    measured: true,
    not_measured: false,
    samples: [0, 0, 0, 0, 0, 0, 0, 0],
    numerator: 0,
    denominator: 8,
    observed: 0,
    interval: { lower: 0, upper: 0.9, method: 'wilson_score', confidence: 0.95 },
    reason_codes: [],
    infra: null,
    reconciliation: null,
    numeric_value: 0,
  } : trial));
  return {
    ...run,
    trials,
    metrics: { ...run.metrics, denominator: run.metrics.denominator + 8, notMeasured: 0 },
  };
};

// A5: the run is stamped with the execution that produced it, and every trial
// in it names the SAME execution. A per-trial block that named another run is
// the forged_provenance control, so the clean state has to be the agreeing one.
const stampProvenance = (run, provenance) => ({
  ...run,
  commit_sha: provenance.commit,
  tree_sha: provenance.tree,
  raw_run_id: provenance.run_id,
  nonce: provenance.nonce,
  executor_id: provenance.executor_id,
  provenance_is_placeholder: false,
  trials: run.trials.map((trial) => ({
    ...trial,
    provenance: { raw_run_id: provenance.run_id, commit_sha: provenance.commit, tree_sha: provenance.tree },
  })),
});

const writeIntoBase = (base, name, document) => {
  const target = path.join(base, name);
  assertStrictlyInside(target, base);
  return writeArtefact(target, document);
};

if (mode === 'run') {
  // purgeProbeFixtures discipline: the base is purged BEFORE the run that uses
  // it, so a repeat run fails on the property and not on its own leftovers.
  const base = createTempBase({ parent, label, step });
  const provenance = provenanceFor(identity.raw_run_id);
  let run = buildCleanRun(label);
  if (options.variant) run = buildVariant(options.variant, { label }).run;
  if (options.table) run = buildRunBoundToTable(label, options.table);
  if (options.launder_infra === 'true') run = launderInfraIntoZero(run);
  const bound = bindArtefact(stampProvenance(run, provenance), provenance);
  const written = writeIntoBase(base.base, 'run.json', bound);
  report({
    mode,
    label,
    attempt,
    pid: process.pid,
    argv_tail: process.argv.slice(2),
    env_echo: {
      mode: process.env.S2_008_REPLAY_MODE,
      label: process.env.S2_008_REPLAY_LABEL,
      attempt: process.env.S2_008_REPLAY_ATTEMPT,
    },
    base: base.base,
    purged: base.purged,
    entries: listTempBase(base.base),
    provenance: bound.provenance,
    artefact: written,
    decision_digest: decisionContentDigest(bound),
    table_digest: bound.expected_table_digest,
    table_digest_in_code: expectedTableDigest(),
    variant: options.variant || null,
    laundered_infra: options.launder_infra === 'true',
  });
} else if (mode === 'interrupted') {
  const base = createTempBase({ parent, label, step });
  const provenance = provenanceFor(identity.raw_run_id);
  const intent = {
    record_kind: 'TRIAL_INTENT',
    index: 1,
    trial: 'trl-s2-008-02',
    status: 'STARTED',
    started_at: FIXED_INSTANT_ISO,
    raw_run_id: provenance.run_id,
    nonce: provenance.nonce,
    pid: process.pid,
  };
  const target = path.join(base.base, 'trial-intent.json');
  assertStrictlyInside(target, base.base);
  writeFileSync(target, JSON.stringify(intent, null, 2) + '\\n', 'utf8');
  report({ mode, label, attempt, pid: process.pid, base: base.base, purged: base.purged, entries: listTempBase(base.base), intent_path: target, intent });
  // Stay alive so the parent can kill a real, mid-trial process. The interval is
  // what keeps the event loop alive; a bare never-resolving await would exit.
  const keepAlive = setInterval(() => {}, 200);
  process.on('SIGTERM', () => { clearInterval(keepAlive); process.exit(0); });
  await new Promise(() => {});
} else if (mode === 'reconcile') {
  // NO purge: a restart that cleaned up first would be hiding the very state it
  // has to reconcile. The base is addressed exactly as the killed child left it.
  const base = path.join(path.resolve(parent), label, step);
  const entriesBefore = listTempBase(base);
  const intent = JSON.parse(readTempFile(base, 'trial-intent.json'));
  const provenance = provenanceFor(identity.raw_run_id);
  const classified = classifyTrialObservation({
    interrupted: true,
    interrupted_at: intent.started_at,
    code: 'UNKNOWN_OUTCOME',
    detail: 'the executing process (pid ' + String(intent.pid) + ') was killed before it reported an outcome',
  }, {
    deps,
    index: intent.index,
    trial: intent.trial,
    noiseBand: PREREGISTRATION.noise_rule.band,
    rule: PREREGISTRATION.multiplicity_rule,
  });
  const row = reconciliationRow({
    run: { provenance: { run_id: provenance.run_id, nonce: provenance.nonce }, preregistration: { digest: PREREGISTRATION_DIGEST } },
    index: intent.index,
    trial: intent.trial,
    reasonCode: classified.reason_codes[0],
    detail: classified.reconciliation.detail,
    deps,
    clockIso: FIXED_INSTANT_ISO,
  });
  // The trial as the restart leaves it. The fixture's DECLARED verdict is
  // dropped on purpose: the test process asks the comparator for the verdict, so
  // an expectation cannot be read back as its own proof.
  const { verdict: declared, ...pristine } = CLEAN_RUNS[label].trials[intent.index];
  const trial = {
    ...pristine,
    status: classified.status,
    outcome: classified.outcome,
    measured: false,
    not_measured: true,
    samples: null,
    numerator: null,
    denominator: null,
    observed: null,
    interval: null,
    decision: null,
    derived_outcome: null,
    reason_codes: classified.reason_codes,
    infra: null,
    reconciliation: row,
    reconciliation_id: row.reconciliation_id,
    numeric_value: null,
  };
  const bound = bindArtefact(row, provenance);
  const written = writeIntoBase(base, 'reconciliation.json', bound);
  report({
    mode,
    label,
    attempt,
    pid: process.pid,
    base,
    entries_before: entriesBefore,
    restart_purged: false,
    intent,
    classified,
    reconciliation: bound,
    trial,
    artefact: written,
    attempts_recorded: entriesBefore.filter((name) => name.startsWith('trial-intent')).length,
    blind_retry: false,
    wrote_second_intent: listTempBase(base).filter((name) => name.startsWith('trial-intent')).length,
  });
} else {
  throw new Error('REPLAY_MODE_UNKNOWN: ' + String(mode));
}
`;

// --- the parent's harness for its children -----------------------------------

/** One temp tree per test: the driver, the child bases, and nothing else. */
function makeTree(t) {
  const parent = mkdtempSync(path.join(tmpdir(), 's2-008-replay-'));
  const driver = path.join(parent, 'driver.mjs');
  writeFileSync(driver, DRIVER, 'utf8');
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  return { parent, driver };
}

/** The argv every child is given. Separate per child, and separate from env. */
function childArgv(driver, { mode, label, attempt, step, parent, extra = [] }) {
  return [
    driver,
    '--mode', mode,
    '--label', label,
    '--attempt', String(attempt),
    '--step', step,
    '--parent', parent,
    '--commit', RESOLVED_BASE.commit_sha,
    '--tree', RESOLVED_BASE.tree_sha,
    ...extra,
  ];
}

/** The environment every child is given. Separate per child, and separate from
 * argv: the child refuses to run if the two spellings disagree. */
function childEnv({ mode, label, attempt }) {
  return {
    ...process.env,
    S2_008_REPLAY_REPO: REPO,
    S2_008_REPLAY_MODE: mode,
    S2_008_REPLAY_LABEL: label,
    S2_008_REPLAY_ATTEMPT: String(attempt),
    TZ: 'UTC',
  };
}

function parseEnvelope(stdout, stderr) {
  const line = stdout.split('\n').filter((entry) => entry.startsWith(EVIDENCE_PREFIX)).pop();
  assert.ok(line, `the child printed no evidence line.\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`);
  return JSON.parse(line.slice(EVIDENCE_PREFIX.length));
}

/** Run a child to completion and return its envelope plus the raw streams. */
function runChild({ driver, parent, mode, label, attempt = 0, step = 'run', extra = [] }) {
  const argv = childArgv(driver, { mode, label, attempt, step, parent, extra });
  const result = spawnSync(process.execPath, argv, { cwd: parent, env: childEnv({ mode, label, attempt }), encoding: 'utf8', timeout: 120000 });
  assert.equal(result.error, undefined, `the child could not be executed: ${String(result.error && result.error.message)}`);
  assert.equal(result.status, 0, `the child exited ${String(result.status)}.\n--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`);
  return { envelope: parseEnvelope(result.stdout, result.stderr), stdout: result.stdout, stderr: result.stderr, argv, pid: result.pid };
}

/**
 * Read an artefact back from disk and verify it with the runner's own guard.
 *
 * The judge does not take the run's word for it: the bytes are re-read from the
 * file the child wrote, and `assertArtefactBound` re-digests them and throws on
 * a mismatch. A run whose own summary was correct while its file was not is
 * exactly the failure this re-read exists to catch.
 */
function readArtefact(base, name) {
  const document = JSON.parse(readFileSync(path.join(base, name), 'utf8'));
  assertArtefactBound(document);
  return document;
}

/** The run artefact of one child's envelope, cross-checked against the digest
 * that child REPORTED — the report and the bytes must be the same document. */
function readRun(envelope) {
  const document = readArtefact(envelope.base, 'run.json');
  assert.equal(document.artefact_digest, envelope.artefact.artefact_digest, `${envelope.label}: the artefact on disk is not the artefact the child reported`);
  return document;
}

// --- A3: two runs, the frozen table, and `A === B` as the extra condition ---

test('A3 two real child processes on one resolved base both match the frozen table, and A === B holds additionally', (t) => {
  const tree = makeTree(t);
  // The identities must be separated BEFORE anything runs, or "the two runs
  // differ" is a property of the assertion rather than of the processes.
  assert.equal(assertRunIdentitiesSeparated(), true);

  const runA = runChild({ ...tree, mode: 'run', label: 'a' });
  const runB = runChild({ ...tree, mode: 'run', label: 'b' });

  // 1. PROCESS SEPARATION, observed rather than declared: different pids,
  //    different argv, different environments, different raw run ids and
  //    different nonces. The nonce of each run is RE-DERIVABLE from its own pid
  //    by the runner's own function, so it cannot be a constant that was edited.
  assert.notEqual(runA.pid, runB.pid, 'the two children shared one pid, so they were not two processes');
  assert.notDeepEqual(runA.argv, runB.argv, 'the two children were given the same argv');
  assert.notEqual(runA.envelope.env_echo.label, runB.envelope.env_echo.label);
  assert.notEqual(runA.envelope.label, runB.envelope.label);
  assert.equal(runA.envelope.label, 'a', 'the child reported a label it was not given');
  assert.equal(runB.envelope.label, 'b', 'the child reported a label it was not given');
  assert.notEqual(runA.envelope.provenance.run_id, runB.envelope.provenance.run_id, 'the two runs report one raw run id');
  assert.equal(runA.envelope.provenance.run_id, fixtureRunIdentity('a').raw_run_id);
  assert.equal(runB.envelope.provenance.run_id, fixtureRunIdentity('b').raw_run_id);
  assert.notEqual(runA.envelope.provenance.nonce, runB.envelope.provenance.nonce, 'the two runs share a nonce');
  for (const run of [runA, runB]) {
    assert.equal(
      run.envelope.provenance.nonce,
      deriveProcessNonce({ label: run.envelope.label, runId: run.envelope.provenance.run_id, attempt: 0, pid: run.envelope.pid }),
      `${run.envelope.label}: the nonce is not re-derivable from the reported pid`,
    );
  }

  // 2. A5: both artefacts are bound to the RESOLVED base, and the binding
  //    verifies from the bytes on disk.
  for (const run of [runA, runB]) {
    assert.equal(run.envelope.provenance.commit, RESOLVED_BASE.commit_sha, `${run.envelope.label} is bound to another commit`);
    assert.equal(run.envelope.provenance.tree, RESOLVED_BASE.tree_sha, `${run.envelope.label} is bound to another tree`);
    assert.equal(run.envelope.provenance_is_placeholder, undefined, 'the placeholder flag was never cleared');
    const artefact = readRun(run.envelope);
    assert.equal(artefact.provenance_is_placeholder, false, `${run.envelope.label} still declares a placeholder provenance`);
  }

  // 3. A3, the criterion: BOTH runs agree with the frozen table. The table was
  //    declared in code before either child ran, and each run carries the digest
  //    it was scored against.
  const artefactA = readRun(runA.envelope);
  const artefactB = readRun(runB.envelope);
  assert.equal(runA.envelope.table_digest, expectedTableDigest(), 'run A was scored against another table');
  assert.equal(runB.envelope.table_digest, expectedTableDigest(), 'run B was scored against another table');
  assert.deepEqual(expectedValueIssues(artefactA, 'a'), [], 'run A disagrees with the frozen table');
  assert.deepEqual(expectedValueIssues(artefactB, 'b'), [], 'run B disagrees with the frozen table');

  // 4. `A === B` — reported as the ADDITIONAL condition, never as the criterion.
  assert.equal(decisionContentDigest(artefactA), decisionContentDigest(artefactB), 'the two runs reached different decisions');
  assert.notEqual(artefactA.artefact_digest, artefactB.artefact_digest, 'the two artefacts are byte-identical, so nothing distinguished them');

  // 5. The track's own comparator, over the two records the children wrote,
  //    against the base the parent resolved. Every separation and table proof
  //    must hold, and the ONLY failures left are the ones the frozen table
  //    designs: the INFRA row is a VIOLATION and the pooled interval is
  //    UNRESOLVED. Asserting "no failures at all" here would assert a result the
  //    table does not pin.
  const comparison = compareParallelTrack({ runA: artefactA, runB: artefactB, prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: RESOLVED_BASE });
  assert.deepEqual(comparison.findingsA, []);
  assert.deepEqual(comparison.findingsB, []);
  assert.equal(comparison.digestsEqual, true, 'A === B does not hold, so the additional condition is not met');
  for (const code of ['run_manifest_collision', 'raw_run_id_collision', 'run_nonce_unbound', 'base_unverified', 'base_mismatch', 'expected_table_digest_mismatch', 'table_disagreement', 'preregistration_unbound', 'preregistration_digest_mismatch']) {
    assert.ok(!comparison.failures.some((entry) => entry.code === code), `${code} was reported: ${JSON.stringify(comparison.failures.filter((entry) => entry.code === code))}`);
  }
  const proof = Object.fromEntries(comparison.proofStatus.map((entry) => [entry.id, entry.status]));
  assert.equal(proof.base_binding, 'SATISFIED', 'the base binding is not satisfied');
  assert.equal(proof.process_separation, 'SATISFIED', 'the two runs are not process-separated');
  assert.equal(proof.table_agreement, 'SATISFIED', 'the runs do not agree with the table');
  assert.equal(proof.preregistration_bound, 'SATISFIED');
  assert.equal(proof.negative_controls, 'SATISFIED');
  // The designed failures, named so a reader can see they are not softened away.
  assert.equal(comparison.runs.a.raw_run_id, fixtureRunIdentity('a').raw_run_id);
  assert.equal(comparison.runs.b.raw_run_id, fixtureRunIdentity('b').raw_run_id);
  assert.equal(
    resolveCampaignVerdict(comparison),
    'FAIL',
    "this design's campaign verdict is FAIL: the INFRA row is a VIOLATION and the pooled interval is UNRESOLVED",
  );
  assert.equal(comparison.runs.a.trials, EXPECTED_TRIAL_DECISIONS.length, 'a run must answer every preregistered trial, the INFRA one included');
});

test('A3 a deliberately wrong expected table makes the comparison FAIL even though the two runs still agree', (t) => {
  const tree = makeTree(t);
  // The corruption is the TABLE, not the data: both runs are otherwise the
  // clean runs, so agreement between them is preserved exactly. If `A === B`
  // were the criterion, this pair would pass — and it must not.
  const wrong = corruptedTableDigest();
  assert.notEqual(wrong, expectedTableDigest(), 'the corrupted table is not a different table');
  const runA = runChild({ ...tree, mode: 'run', label: 'a', extra: ['--table', wrong] });
  const runB = runChild({ ...tree, mode: 'run', label: 'b', extra: ['--table', wrong] });

  const artefactA = readRun(runA.envelope);
  const artefactB = readRun(runB.envelope);
  assert.equal(artefactA.expected_table_digest, wrong, 'run A was not scored against the wrong table');
  assert.equal(artefactB.expected_table_digest, wrong, 'run B was not scored against the wrong table');
  // The two runs still agree with EACH OTHER: the criterion cannot be agreement.
  assert.equal(decisionContentDigest(artefactA), decisionContentDigest(artefactB), 'the corruption was supposed to leave the runs in agreement with each other');
  // And each one is found by the frozen table anyway.
  const findingsA = expectedValueIssues(artefactA, 'a');
  const findingsB = expectedValueIssues(artefactB, 'b');
  assert.ok(findingsA.length > 0, 'a run scored against a different table produced no finding');
  assert.ok(findingsB.length > 0, 'a run scored against a different table produced no finding');
  for (const finding of [...findingsA, ...findingsB]) {
    assert.equal(finding.code, 'TABLE_DIGEST_MISMATCH', `unexpected finding ${finding.code}`);
  }

  const comparison = compareParallelTrack({ runA: artefactA, runB: artefactB, prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: RESOLVED_BASE });
  assert.equal(comparison.digestsEqual, true, 'the two runs stopped agreeing, so this no longer tests the table');
  assert.equal(comparison.findingsA.length, 1, 'the comparison lost the table finding');
  assert.equal(comparison.findingsB.length, 1, 'the comparison lost the table finding');
  assert.ok(comparison.failures.some((entry) => entry.code === 'expected_table_digest_mismatch'), 'the comparator did not name the table mismatch');
  assert.equal(comparison.proofStatus.find((entry) => entry.id === 'table_agreement').status, 'UNMET', 'the table proof is SATISFIED for runs scored against the wrong table');
  assert.equal(resolveCampaignVerdict(comparison), 'FAIL');
});

test('A3 two identically wrong runs, in two processes, still produce findings: agreement alone is not a pass', (t) => {
  const tree = makeTree(t);
  // The same corruption in BOTH runs. Their decision digests must stay equal —
  // otherwise this test would prove nothing about agreement — and the table must
  // still find both. That pair of claims is what "A === B is an extra condition"
  // means, executed rather than asserted.
  const runA = runChild({ ...tree, mode: 'run', label: 'a', extra: ['--variant', 'nudged_counter'] });
  const runB = runChild({ ...tree, mode: 'run', label: 'b', extra: ['--variant', 'nudged_counter'] });
  assert.equal(runA.envelope.variant, 'nudged_counter');
  assert.equal(runB.envelope.variant, 'nudged_counter');

  const artefactA = readRun(runA.envelope);
  const artefactB = readRun(runB.envelope);
  assert.notEqual(runA.pid, runB.pid, 'the identical-wrong control compared one process with itself');
  assert.equal(decisionContentDigest(artefactA), decisionContentDigest(artefactB), 'the two corrupted runs disagree, so the agreement claim is untested');
  assert.notEqual(artefactA.artefact_digest, artefactB.artefact_digest, 'the two corrupted runs are the same artefact');

  const comparison = compareParallelTrack({ runA: artefactA, runB: artefactB, prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: RESOLVED_BASE });
  assert.equal(comparison.identicalWrongFindings.digests_still_equal, true);
  assert.equal(comparison.identicalWrongFindings.both_non_empty, true, 'the frozen table did not catch the identical corruption');
  assert.ok(comparison.identicalWrongFindings.findings_a.length > 0 && comparison.identicalWrongFindings.findings_b.length > 0);
  assert.equal(comparison.identicalWrongFindings.findings_a[0].field, 'counters.seedSubstitution');
  assert.ok(comparison.failures.some((entry) => entry.code === 'hard_gate_violated'), 'the moved counter was not named as a hard gate');
  assert.equal(comparison.proofStatus.find((entry) => entry.id === 'table_agreement').status, 'UNMET');
  assert.equal(resolveCampaignVerdict(comparison), 'FAIL', 'two runs that agree on a wrong answer produced a pass');
});

// --- A2: an infra or interrupted outcome is never "no effect" ---------------

test('A2 an infra outcome is a first-class outcome: never "no effect", never a pass', (t) => {
  const tree = makeTree(t);
  const runA = runChild({ ...tree, mode: 'run', label: 'a' });
  const runB = runChild({ ...tree, mode: 'run', label: 'b' });
  const artefactA = readRun(runA.envelope);
  const artefactB = readRun(runB.envelope);

  // The frozen table's fourth row, as the run recorded it and as the comparator
  // judges it. The declared verdict is never read: `resolveTrialVerdict` is
  // asked for it in the test process.
  const infraRow = EXPECTED_TRIAL_DECISIONS[3];
  const infra = artefactA.trials[3];
  assert.equal(infraRow.expectedStatus, 'INFRA_ERROR');
  assert.equal(infra.trial, infraRow.trial);
  assert.equal(infra.status, 'INFRA_ERROR');
  assert.equal(infra.outcome, 'INFRA');
  assert.equal(infra.measured, false);
  assert.equal(infra.not_measured, true);
  assert.equal(infra.numerator, null, 'an unmeasured trial reported a number');
  assert.equal(infra.denominator, null, 'an unmeasured trial reported a denominator');
  assert.equal(infra.numeric_value, null, 'an unmeasured trial is readable as a value');
  assert.equal(infra.reason_codes.includes('INFRA_ERROR'), true);
  // The DECLARED verdict is dropped rather than overwritten, so nothing in this
  // assertion can read an expectation back as its own proof.
  const { verdict: declaredInfraVerdict, ...infraForVerdict } = infra;
  assert.equal(declaredInfraVerdict, infraRow.expectedVerdict, "the run's declared verdict no longer matches the table's row");
  const verdict = resolveTrialVerdict(infraForVerdict);
  assert.equal(verdict.verdict, 'VIOLATION', 'an infra trial was allowed');
  assert.ok(verdict.reasons.includes('TRIAL_NOT_RESOLVED:INFRA_ERROR'), JSON.stringify(verdict.reasons));
  // A skipped or unresolved trial is a VIOLATION too, which is the A2 rule the
  // infra row is one instance of.
  for (const status of ['SKIPPED', 'UNRESOLVED', 'NOT_MEASURED']) {
    const { verdict: _dropped, ...rest } = infraForVerdict;
    const skipped = resolveTrialVerdict({ ...rest, status, outcome: status === 'SKIPPED' ? 'NEGATIVE' : 'UNRESOLVED' });
    assert.equal(skipped.verdict, 'VIOLATION', `a ${status} trial was allowed`);
  }

  // The pooled metric counts the MEASURED trials only. An infra trial folded in
  // as a zero would change 18/24 into 18/32 and would report nothing unmeasured.
  //
  // The outcome tally is DERIVED from the frozen table's rows, member for
  // member, because the second spelling of it is exactly what this repair
  // removed: the literal `{POSITIVE:1, NULL:1, NEGATIVE:1, INFRA:1}` described
  // the DESIGN each trial was authored for, and after R-B re-derived the three
  // measured rows from the frozen measurements the rule derives UNRESOLVED for
  // all of them. The tally a run records is the comparator's own
  // `metricsSummary` over the outcomes the run recorded, so a hand-written
  // tally here is a claim about the corpus rather than a check of it — and
  // "none of them is merged into another and none is a zero" is the property,
  // spelled as "every declared outcome appears with its own count".
  const declaredTally = EXPECTED_TRIAL_DECISIONS.reduce(
    (tally, row) => ({ ...tally, [row.expectedOutcome]: (tally[row.expectedOutcome] ?? 0) + 1 }),
    {},
  );
  for (const artefact of [artefactA, artefactB]) {
    assert.equal(artefact.metrics.numerator, 18);
    assert.equal(artefact.metrics.denominator, 24, 'the infra trial was folded into the denominator');
    assert.equal(artefact.metrics.notMeasured, 1, 'the unmeasured trial is not reported as unmeasured');
    assert.equal(artefact.metrics.basis, 'POOLED_TRIAL_COUNTS');
    assert.deepEqual(artefact.metrics.outcome_counts, declaredTally, 'the outcomes are not counted as themselves');
    assert.deepEqual(
      Object.keys(artefact.metrics.outcome_counts).sort(),
      Object.keys(declaredTally).sort(),
      'the run invented an outcome the table does not declare, or dropped one it does',
    );
  }
  // The DELIVERED tally, pinned: three measured rows the frozen rule could not
  // resolve on eight cases, and one INFRA row that is counted as itself rather
  // than as a zero. A different shape here means the table moved, and the
  // report has to be re-read before the assertion is touched.
  assert.deepEqual(declaredTally, { UNRESOLVED: 3, INFRA: 1 }, 'the frozen table is not the re-derived one; re-read docs/stages/S2-008.md before changing this');
  assert.equal(artefactA.metrics.numerator / artefactA.metrics.denominator, FROZEN_BASELINE);

  // THE NEGATIVE CONTROL, IN A PROCESS: the same run with the infra trial
  // laundered into a zero must be FOUND. A control whose "before" already
  // failed would prove nothing, so the clean pair above is the "before".
  const launderedA = runChild({ ...tree, mode: 'run', label: 'a', extra: ['--launder_infra', 'true'] });
  const launderedB = runChild({ ...tree, mode: 'run', label: 'b', extra: ['--launder_infra', 'true'] });
  assert.equal(launderedA.envelope.laundered_infra, true, 'the negative control ran without its corruption');
  const washedA = readRun(launderedA.envelope);
  const washedB = readRun(launderedB.envelope);
  const washedFindings = [...expectedValueIssues(washedA, 'a'), ...expectedValueIssues(washedB, 'b')];
  assert.ok(washedFindings.length >= 4, 'the laundering produced too few findings to be a real control');
  for (const code of ['TRIAL_FIELD_DIVERGES_FROM_TABLE', 'METRIC_DENOMINATOR_DIVERGES_FROM_TABLE', 'NOT_MEASURED_DIVERGES_FROM_TABLE']) {
    assert.ok(washedFindings.some((finding) => finding.code === code), `${code} was not reported for a laundered infra trial`);
  }
  const washed = compareParallelTrack({ runA: washedA, runB: washedB, prereg: CONFIGURED_PREREG, expected: EXPECTED_TABLE, base: RESOLVED_BASE });
  assert.equal(washed.proofStatus.find((entry) => entry.id === 'table_agreement').status, 'UNMET');
  assert.equal(resolveCampaignVerdict(washed), 'FAIL');
});

test('A5 a killed child leaves an interrupted trial that a later process classifies as a reconciliation, not a success', async (t) => {
  const tree = makeTree(t);

  // PHASE 1: a real process starts a trial, writes the intent, and waits. The
  // parent kills it with SIGKILL — not SIGTERM, not a clean exit — so the trial
  // is interrupted with no chance to report anything.
  const argv = childArgv(tree.driver, { mode: 'interrupted', label: 'a', attempt: 0, step: 'interrupted' });
  argv[argv.indexOf('--parent') + 1] = tree.parent;
  const child = spawn(process.execPath, argv, { cwd: tree.parent, env: childEnv({ mode: 'interrupted', label: 'a', attempt: 0 }), stdio: ['ignore', 'pipe', 'pipe'] });
  const started = await new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => reject(new Error(`the interrupted child never reported itself.\n${stdout}\n${stderr}`)), 60000);
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (!stdout.includes(EVIDENCE_PREFIX)) return;
      clearTimeout(timer);
      resolve(parseEnvelope(stdout, stderr));
    });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => { clearTimeout(timer); reject(error); });
    child.on('exit', (code, signal) => { clearTimeout(timer); reject(new Error(`the interrupted child exited (${String(code)}/${String(signal)}) before it could be killed`)); });
  });
  assert.equal(started.mode, 'interrupted');
  assert.equal(started.intent.status, 'STARTED', 'the trial was not in flight when the process was killed');
  assert.equal(started.intent.trial, 'trl-s2-008-02', 'the interrupted trial is not a preregistered one');
  assert.equal(started.entries.includes('trial-intent.json'), true, 'the intent was not on disk before the kill');

  assert.equal(child.exitCode, null, 'the child had already exited, so nothing was interrupted');
  assert.equal(child.signalCode, null, 'the child was already signalled, so nothing was interrupted');
  child.kill('SIGKILL');
  const [, signal] = await once(child, 'close');
  assert.equal(signal, 'SIGKILL', `the child died of ${String(signal)}, not of the kill this test issued`);

  // PHASE 2: a DIFFERENT process restarts over the same base, WITHOUT purging.
  // A restart that cleaned up first would be reconciling a state it had deleted.
  const restart = runChild({ ...tree, mode: 'reconcile', label: 'a', attempt: 1, step: 'interrupted' });
  assert.equal(restart.envelope.restart_purged, false, 'the restart purged the state it was supposed to reconcile');
  assert.notEqual(restart.pid, started.pid, 'the reconciliation was produced by the process that was killed');
  assert.equal(restart.envelope.entries_before.includes('trial-intent.json'), true, 'the restart did not see the interrupted state');
  assert.equal(restart.envelope.attempts_recorded, 1, 'more than one attempt was recorded for the interrupted trial');
  assert.equal(restart.envelope.wrote_second_intent, 1, 'the restart started a second attempt: a blind retry is not a reconciliation');
  assert.equal(restart.envelope.blind_retry, false);

  // The classification is the runner's own, from the frozen vocabulary.
  const classified = restart.envelope.classified;
  assert.equal(classified.status, 'UNRESOLVED', 'an interrupted trial was resolved');
  assert.equal(classified.outcome, 'UNRESOLVED', 'an interrupted trial was given an outcome');
  assert.equal(classified.observed, null, 'an interrupted trial reported an observation');
  assert.equal(classified.decision, null, 'an interrupted trial reported a decision');
  assert.equal(classified.infra, null, 'an interruption is not an infrastructure failure: its effect is unknown, not absent');
  assert.deepEqual(classified.reason_codes, ['UNKNOWN_OUTCOME']);
  assert.equal(classified.reconciliation.reasonCode, 'UNKNOWN_OUTCOME');
  assert.match(classified.reconciliation.detail, /was killed before it reported an outcome/);

  // The reconciliation row is OPEN, and it is itself a bound artefact (A5).
  const row = restart.envelope.reconciliation;
  assert.equal(row.record_kind, 'RECONCILIATION');
  assert.equal(row.decided, false, 'the reconciliation was decided by the run that was supposed to await a human');
  assert.equal(row.resolution, 'EFFECT_UNDETERMINED');
  assert.equal(row.decider_kind, 'human_owner');
  assert.equal(row.trial, 'trl-s2-008-02');
  assert.equal(row.trial_index, 1);
  assert.equal(row.reason_code, 'UNKNOWN_OUTCOME');
  assert.match(row.reconciliation_id, /^rec-[0-9a-f]{16}$/);
  assert.deepEqual(row.allowed_resolutions, ['OBSERVED_NO_EFFECT', 'OBSERVED_EFFECT_COMPLETED', 'OBSERVED_EFFECT_UNDONE', 'EFFECT_UNDETERMINED']);
  const rowOnDisk = JSON.parse(readFileSync(path.join(restart.envelope.base, 'reconciliation.json'), 'utf8'));
  assert.equal(rowOnDisk.reconciliation_id, row.reconciliation_id, 'the row on disk is not the row that was reported');
  assert.equal(rowOnDisk.artefact_digest, restart.envelope.artefact.artefact_digest);
  assert.equal(rowOnDisk.provenance.run_id, fixtureRunIdentity('a').raw_run_id, 'the reconciliation is not bound to the run it reconciles');
  assert.equal(rowOnDisk.provenance.commit, RESOLVED_BASE.commit_sha);

  // The trial as the restart left it: not a success, not a zero, and a VIOLATION
  // when the comparator is asked for the verdict in THIS process.
  const trial = restart.envelope.trial;
  assert.equal('verdict' in trial, false, 'the trial record carried a declared verdict into the assertion');
  assert.equal(trial.status, 'UNRESOLVED');
  assert.equal(trial.numerator, null, 'the interrupted trial reported a numerator');
  assert.equal(trial.denominator, null, 'the interrupted trial reported a denominator');
  assert.equal(trial.numeric_value, null, 'the interrupted trial is readable as a value');
  assert.equal(trial.reconciliation_id, row.reconciliation_id, 'the trial does not point at its reconciliation');
  const interruptedVerdict = resolveTrialVerdict(trial);
  assert.equal(interruptedVerdict.verdict, 'VIOLATION', 'an interrupted trial was allowed');
  assert.ok(interruptedVerdict.reasons.includes('TRIAL_NOT_RESOLVED:UNRESOLVED'), JSON.stringify(interruptedVerdict.reasons));
});

// --- A5: the repeat run ----------------------------------------------------

test('A5 a repeat run on the same base reproduces the decision, purges its own leftovers, and refuses a base it does not own', (t) => {
  const tree = makeTree(t);

  // FIRST RUN, then SECOND RUN over the SAME label and the SAME base, in two
  // different processes. The second must start from a known state, or the whole
  // claim would be "the base was clean because nothing had run there".
  const first = runChild({ ...tree, mode: 'run', label: 'a', attempt: 0 });
  assert.equal(first.envelope.purged.changed, false, 'the first run found leftovers in a fresh tree');
  assert.deepEqual(first.envelope.purged.removed, [], 'the first run removed something from a fresh tree');
  assert.equal(first.envelope.entries.includes(TEMP_BASE_MARKER_NAME), true);
  assert.equal(first.envelope.entries.includes('run.json'), true);
  // Read the first artefact NOW, before the second run overwrites the same path:
  // a repeat run writes to the SAME file, and reading it afterwards would
  // compare the second run with itself and prove nothing.
  const artefactFirst = readRun(first.envelope);

  const second = runChild({ ...tree, mode: 'run', label: 'a', attempt: 1 });
  assert.notEqual(second.pid, first.pid, 'the repeat run was not a second process');
  assert.equal(second.envelope.base, first.envelope.base, 'the repeat run did not run on the same base');
  // The leftovers were REAL and were removed, by name, and the base's own marker
  // survived: the purge removed one run's fixtures, not the base.
  assert.equal(second.envelope.purged.changed, true, 'the repeat run found no leftovers to purge');
  assert.deepEqual(second.envelope.purged.removed, ['run.json'], "the purge did not remove exactly the previous run's artefacts");
  assert.equal(second.envelope.purged.reason, null, 'the purge reported that the base was already clean');
  assert.equal(second.envelope.entries.includes(TEMP_BASE_MARKER_NAME), true, 'the purge removed the base marker');
  assert.equal(second.envelope.entries.filter((name) => name === 'run.json').length, 1, 'the repeat run left a second artefact beside the first');

  // REPEATABILITY: the decision is reproduced, and the difference between the
  // two artefacts is confined to the fields a per-process difference may move.
  const artefactSecond = readRun(second.envelope);
  assert.deepEqual(expectedValueIssues(artefactFirst, 'a'), [], 'the first run disagrees with the table');
  assert.deepEqual(expectedValueIssues(artefactSecond, 'a'), [], 'the repeat run disagrees with the table');
  assert.equal(decisionContentDigest(artefactFirst), decisionContentDigest(artefactSecond), 'the repeat run reached a different decision');
  assert.notEqual(artefactFirst.artefact_digest, artefactSecond.artefact_digest, 'the two artefacts are byte-identical, so nothing distinguishes them');
  const differing = diffPaths(artefactFirst, artefactSecond);
  assert.ok(differing.includes('artefact_digest'), 'the two records do not differ in their own digest, so the comparison is vacuous');
  for (const where of differing) {
    const member = where.split('.').pop();
    assert.ok(
      ALLOWED_PROCESS_DIFFERENCES.includes(member) || member === 'artefact_digest',
      `the repeat run differs at ${where}, which is not one of the allowed process differences (${ALLOWED_PROCESS_DIFFERENCES.join(', ')})`,
    );
  }
  assert.equal(artefactFirst.provenance.nonce, deriveProcessNonce({ label: 'a', runId: artefactFirst.provenance.run_id, attempt: 0, pid: first.envelope.pid }));
  assert.equal(artefactSecond.provenance.nonce, deriveProcessNonce({ label: 'a', runId: artefactSecond.provenance.run_id, attempt: 1, pid: second.envelope.pid }));
  assert.notEqual(artefactFirst.provenance.nonce, artefactSecond.provenance.nonce);

  // AND THE PURGE IS BOUNDED. A repeat run that could rescue itself by deleting
  // whatever was in the way would delete an operator's data instead, so a base
  // this suite cannot prove it created is refused — that is what makes the
  // successful repeat run above a statement rather than a deletion.
  const foreign = path.join(tree.parent, 'foreign', 'step');
  mkdirSync(foreign, { recursive: true });
  writeFileSync(path.join(foreign, 'operator-notes.json'), '{"keep":"me"}\n', 'utf8');
  assert.throws(
    () => purgeTempBase(foreign, { parent: tree.parent }),
    /FIXTURE_BASE_NOT_OWNED/,
    "a base without this suite's marker was purged anyway",
  );
  assert.equal(existsSync(path.join(foreign, 'operator-notes.json')), true, 'the refused purge deleted the data it could not identify');
  assert.throws(
    () => purgeTempBase(tree.parent, { parent: tree.parent }),
    /FIXTURE_PATH_ESCAPE/,
    'the parent directory itself was accepted as a purge target',
  );
  // An absent base is a no-op that says so, and a second purge changes nothing.
  const absentPath = path.join(tree.parent, 'absent', 'step');
  const absent = purgeTempBase(absentPath, { parent: tree.parent });
  assert.deepEqual(absent, { purged: true, changed: false, removed: [], base: absentPath, reason: 'ABSENT_ALREADY_CLEAN' });
  const secondPurge = purgeTempBase(first.envelope.base, { parent: tree.parent });
  assert.equal(secondPurge.removed.includes(TEMP_BASE_MARKER_NAME), false, 'a purge removed the base marker');
});
