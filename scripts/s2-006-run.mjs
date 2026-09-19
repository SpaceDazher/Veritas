// S2-006 offline evidence run (spec §3, §8, §9, §13).
//
// Architecture (blinding by construction):
//   * PARENT (this process, comparator/evaluator side) never executes the
//     candidate. It spawns TWO process-separated candidate children (distinct
//     executor id, PID, nonce, clock and output root) that run the SAME frozen
//     rubric implementation over the SAME frozen 45-case corpus.
//   * CHILD (--candidate) reads ONLY the frozen corpus manifest and case
//     files. The label sets, adjudications and thresholds are NEVER opened by
//     the child — the sealed prediction set is written before unseal.
//   * Only after BOTH prediction sets are sealed does the parent unseal the
//     labels/adjudication and run the preregistered exact comparator
//     (src/lib/verifier/comparator.mjs — never re-runs the candidate).
//   * Calibration metrics (fixture stratum), the lexicographic decision rule
//     and the A–S security probes are then computed and bound to evidence/.
//
// Honesty rules: no wall clock or randomness in decision-affecting output;
// no fabricated external metrics — the fixture stratum is labeled as such,
// the independence tier stays NOT_MEASURED (evaluator_not_independent) and
// every owner-owned threshold stays NEEDS_INPUT.
//
//   node scripts/s2-006-run.mjs                 # full offline evidence run
//   node scripts/s2-006-run.mjs --candidate …   # internal child mode
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { evaluateScenario, RUBRIC_ID, RUBRIC_VERSION } from '../src/lib/verifier/rubric.mjs';
import { compareRuns } from '../src/lib/verifier/comparator.mjs';
import { computeMetrics, decideLexicographic } from '../src/lib/verifier/calibration.mjs';
import { runAllSecurityProbes } from '../src/lib/verifier/probes.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CORPUS_DIR = path.join(ROOT, 'corpus/s2-006');
const EVIDENCE_DIR = path.join(ROOT, 'evidence');
const EXPECTED_CASE_COUNT = 45;
const THRESHOLDS_PATH = path.join(ROOT, 'contracts/s2-006-thresholds.json');
// Fixture-only HMAC key (tests/verifier/fixtures convention). Real annotator
// key custody with the label_custodian role is NOT_RUN — the fixture key
// proves the signature verification path, never real independence.
export const FIXTURE_ANNOTATION_HMAC_KEY = 's2-006-fixture-hmac-key';

// Candidate implementation identity: the exact modules the sealed predictions
// depend on. Any change to these bytes changes the implementation digest.
const CANDIDATE_MODULES = [
  'src/lib/verifier/rubric.mjs',
  'src/lib/verifier/canonical-json.mjs',
];

const RUN_A = {
  runId: 's2-006-run-a',
  executorId: 'exec-s2-006-a',
  nonce: 'n-a-7c1e4d90a2b8f3e6',
  clock: '2026-01-15T08:00:00.000Z',
  outputRoot: 'results/s2-006/run-a',
};
const RUN_B = {
  runId: 's2-006-run-b',
  executorId: 'exec-s2-006-b',
  nonce: 'n-b-3f9a62d1c5e80b74',
  clock: '2026-03-21T23:59:59.999Z',
  outputRoot: 'results/s2-006/run-b',
};

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

const sha256Bytes = (buf) => createHash('sha256').update(buf).digest('hex');

function getHeadCommit() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unavailable';
  }
}

// ---- frozen corpus load (shared by child and parent) ------------------------

function loadFrozenCorpus() {
  const manifestBytes = fs.readFileSync(path.join(CORPUS_DIR, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const issues = [];
  if (manifest.contractVersion !== '1.0.0') issues.push('manifest:contract-version-unknown');
  if (!Array.isArray(manifest.cases) || manifest.cases.length !== EXPECTED_CASE_COUNT) {
    issues.push(`manifest:case-count-not-${EXPECTED_CASE_COUNT}`);
  }
  const rubricBytes = fs.readFileSync(path.join(CORPUS_DIR, 'rubric-v1.json'));
  if (sha256Bytes(rubricBytes) !== manifest.rubricDigest) issues.push('manifest:rubric-digest-drift');
  const splitByCase = new Map(manifest.splitAssignments.map((a) => [a.caseId, a.split]));
  if (splitByCase.size !== manifest.cases.length) issues.push('manifest:split-assignment-incomplete');
  const cases = [];
  for (const entry of manifest.cases) {
    let bytes;
    try {
      bytes = fs.readFileSync(path.join(CORPUS_DIR, 'cases', `${entry.caseId}.json`));
    } catch {
      issues.push(`${entry.caseId}:missing`);
      continue;
    }
    if (sha256Bytes(bytes) !== entry.caseSha256) issues.push(`${entry.caseId}:case-digest-drift`);
    const file = JSON.parse(bytes.toString('utf8'));
    if (file.case?.caseId !== entry.caseId) issues.push(`${entry.caseId}:record-id-mismatch`);
    if (canonicalDigest(file.scenario) !== file.case?.textDigest) issues.push(`${entry.caseId}:scenario-digest-drift`);
    cases.push({
      caseId: entry.caseId,
      bytes,
      record: file.case,
      scenario: file.scenario,
      split: splitByCase.get(entry.caseId) ?? null,
    });
  }
  for (const file of fs.readdirSync(path.join(CORPUS_DIR, 'cases'))) {
    if (file.endsWith('.json') && !manifest.cases.some((c) => c.caseId === file.replace(/\.json$/, ''))) {
      issues.push(`${file}:unmanifested`);
    }
  }
  if (manifest.externalStratum?.status !== 'NEEDS_INPUT') issues.push('manifest:external-stratum-must-be-needs-input');
  return { ok: issues.length === 0, issues, manifest, manifestBytes, rubricBytes, rubricDigest: manifest.rubricDigest, cases };
}

// ---- child mode: the candidate (labels never read) ---------------------------

export function runCandidate({ runId, executorId, nonce, clock, outputRoot, corpus }) {
  const predictions = {};
  const hardCounters = {
    unauthorizedLeakageEvents: 0,
    lockedLabelAccessEvents: 0, // the child never opens label/adjudication files
    producerSelfReviewEvents: 0,
    upstreamArtifactMutationEvents: 0,
    unauthorizedSideEffectEvents: 0,
  };
  const LEAK_VERDICTS = new Set(['SUPPORTED', 'CONTRADICTED', 'PARTIALLY_SUPPORTED']);
  const perCase = [];
  for (const c of corpus.cases) {
    const r = evaluateScenario(c.scenario);
    predictions[c.caseId] = {
      verdict: r.verdict,
      reasonCodes: [...r.reasonCodes],
      missingnessKind: r.missingness.kind,
    };
    // A content-asserting verdict on a private-category case could only be
    // produced by reading the private span: a hard leak, counted here.
    if (c.scenario.category === 'private' && LEAK_VERDICTS.has(r.verdict)) {
      hardCounters.unauthorizedLeakageEvents += 1;
    }
    perCase.push({ caseId: c.caseId, verdict: r.verdict });
  }
  const implementationModules = Object.fromEntries(CANDIDATE_MODULES.map((rel) => [
    rel,
    sha256Bytes(fs.readFileSync(path.join(ROOT, rel))),
  ]));
  const implementationDigest = canonicalDigest({
    modules: implementationModules,
    rubricId: RUBRIC_ID,
    rubricVersion: RUBRIC_VERSION,
  });
  const runManifestDigest = canonicalDigest({
    runId, executorId, pid: process.pid, nonce, outputRoot, implementationDigest,
  });
  return {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'candidate sealed prediction set (labels, adjudications and thresholds never read before unseal)',
    runId,
    executorId,
    pid: process.pid,
    nonce,
    clock,
    outputRoot,
    testedImplementationCommit: getHeadCommit(),
    corpus: {
      manifestId: corpus.manifest.manifestId,
      corpusVersion: corpus.manifest.corpusVersion,
      manifestSha256: sha256Bytes(corpus.manifestBytes),
      rubricDigest: corpus.rubricDigest,
      caseCount: corpus.cases.length,
      stratum: 'fixture',
    },
    implementationDigest,
    implementationModules,
    predictions,
    predictionSetDigest: canonicalDigest(predictions),
    runManifestDigest,
    hardCounters,
    perCase,
    sealedBeforeUnseal: true,
    status: 'COMPLETED',
  };
}

// ---- unseal: gold consensus from labels + adjudications ----------------------

function loadGold(corpusCases) {
  const annotators = { a: {}, b: {} };
  const labelSets = {};
  for (const annotator of ['a', 'b']) {
    const bytes = fs.readFileSync(path.join(CORPUS_DIR, 'labels', `annotator-${annotator}.json`));
    for (const set of JSON.parse(bytes.toString('utf8'))) {
      labelSets[set.annotationSetId] = set;
      for (const l of set.labels) annotators[annotator][l.caseId] = l.label;
    }
  }
  const adjudications = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'adjudication.json'), 'utf8'));
  const gold = {};
  for (const c of corpusCases) {
    const disagreement = adjudications.find((r) => r.caseId === c.caseId);
    gold[c.caseId] = disagreement ? disagreement.decision : annotators.a[c.caseId];
  }
  return { annotators, labelSets, adjudications, gold };
}

// ---- evidence writers ---------------------------------------------------------

function writeEvidence(name, value) {
  const target = path.join(EVIDENCE_DIR, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
  return `evidence/${name}`;
}

function buildCalibrationRecord({ corpus, metrics, goldState, thresholds, thresholdsDigest, decision }) {
  const metricRecords = metrics.metricRecords;
  const allMetricNames = [...new Set(metricRecords.map((r) => r.name))];
  const splitComposition = {};
  for (const c of corpus.cases) splitComposition[c.split] = (splitComposition[c.split] ?? 0) + 1;
  return {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'calibration metrics over the frozen fixture stratum (45 cases, dev/calibration/locked_test splits)',
    corpus: {
      manifestId: corpus.manifest.manifestId,
      corpusVersion: corpus.manifest.corpusVersion,
      manifestSha256: sha256Bytes(corpus.manifestBytes),
      rubricDigest: corpus.rubricDigest,
      caseCount: corpus.cases.length,
      stratum: 'fixture',
      splitComposition,
    },
    inputs: {
      thresholdsDigest,
      predictionSource: 'evidence/s2-006-run-a.json (verified identical to run B by the comparator)',
      goldSource: 'raw blind labels of prn-annotator-a/prn-annotator-b + adjudication records (corpus/s2-006)',
    },
    metricRecords,
    confusionMatrices: metrics.confusionMatrices,
    coverage: metrics.coverage,
    selectiveRisk: metrics.selectiveRisk,
    hardViolations: metrics.hardViolations,
    rawAnnotatorAgreement: metrics.rawAnnotatorAgreement,
    slices: [
      { name: 'fixture-all', stratum: 'fixture', caseCount: corpus.cases.length, metricNames: allMetricNames },
    ],
    thresholdDecision: {
      thresholdsDigest,
      status: 'NEEDS_INPUT',
      ownerDecisionRef: null,
      appliedAt: null,
    },
    independence: {
      tier: 'NOT_INDEPENDENT',
      status: 'NOT_MEASURED',
      reason: 'evaluator_not_independent',
      details: {
        annotatorsAreFixturePrincipals: true,
        producerAndVerifierShareProject: true,
        noRealIndependentAnnotatorsOrAdjudicator: true,
        noMethodOwnerHumanDecision: true,
        note: 'Synthetic principals prove policy mechanics only; they never create independence (spec §3).',
      },
    },
    decision,
    externalStratum: { status: 'NEEDS_INPUT', reason: 'evaluator_not_independent' },
    limitations: [
      'Fixture stratum only: no externally authored, independently labelled cases exist.',
      'Inter-annotator agreement is NOT_MEASURED on this stratum (evaluator_not_independent); raw agreement is kept for transparency.',
      'Every owner-owned threshold numeric is null: no method-owner HumanDecision exists.',
      'No EvidenceMap/HypothesisCard inputs in this offline harness: evidence_map_completeness is NOT_APPLICABLE here.',
      'No probabilities emitted: Brier/ECE stay NOT_APPLICABLE.',
    ],
  };
}

// ---- parent orchestration ------------------------------------------------------

async function parentMode() {
  const written = [];
  const violations = [];

  // 1. frozen corpus (parent-side check; children re-verify independently)
  const corpus = loadFrozenCorpus();
  if (!corpus.ok) {
    console.error(JSON.stringify({ ok: false, status: 'QUARANTINED', issues: corpus.issues }, null, 2));
    process.exit(1);
  }

  // 2. process-separated candidate runs BEFORE unseal
  const sealed = {};
  for (const [key, params] of [['a', RUN_A], ['b', RUN_B]]) {
    const out = path.join(EVIDENCE_DIR, `s2-006-run-${key}.json`);
    const child = spawnSync(process.execPath, [
      path.join(ROOT, 'scripts/s2-006-run.mjs'),
      '--candidate',
      '--run-id', params.runId,
      '--executor-id', params.executorId,
      '--nonce', params.nonce,
      '--clock', params.clock,
      '--output-root', params.outputRoot,
      '--out', out,
    ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    if (child.status !== 0) {
      console.error(`candidate run ${params.runId} exited ${child.status}: ${String(child.stderr ?? '').slice(-800)}`);
      process.exit(1);
    }
    sealed[key] = JSON.parse(fs.readFileSync(out, 'utf8'));
    written.push(`evidence/s2-006-run-${key}.json`);
  }

  // 3. UNSEAL: labels/adjudications/thresholds are opened only here
  const goldState = loadGold(corpus.cases);
  const thresholdsBytes = fs.readFileSync(THRESHOLDS_PATH);
  const thresholds = JSON.parse(thresholdsBytes.toString('utf8'));
  const thresholdsDigest = canonicalDigest(thresholds);

  // 4. preregistered exact comparator over the two sealed sets
  const comparison = compareRuns({
    manifest: corpus.manifest,
    manifestBytes: corpus.manifestBytes,
    rubricBytes: corpus.rubricBytes,
    cases: corpus.cases,
    labelSets: goldState.labelSets,
    adjudications: goldState.adjudications,
    thresholdsDigest,
    annotationHmacKey: FIXTURE_ANNOTATION_HMAC_KEY,
    runA: {
      runId: sealed.a.runId,
      executorId: sealed.a.executorId,
      pid: sealed.a.pid,
      nonce: sealed.a.nonce,
      outputRoot: sealed.a.outputRoot,
      implementationDigest: sealed.a.implementationDigest,
      predictions: sealed.a.predictions,
      hardCounters: sealed.a.hardCounters,
    },
    runB: {
      runId: sealed.b.runId,
      executorId: sealed.b.executorId,
      pid: sealed.b.pid,
      nonce: sealed.b.nonce,
      outputRoot: sealed.b.outputRoot,
      implementationDigest: sealed.b.implementationDigest,
      predictions: sealed.b.predictions,
      hardCounters: sealed.b.hardCounters,
    },
  });
  if (!comparison.ok) {
    for (const f of comparison.failures) violations.push(`COMPARATOR_${f.code}`);
  }
  const comparisonRecord = {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'fail-closed comparator over two pre-sealed process-separated prediction sets (spec §9); the candidate is never re-run after unseal',
    testedImplementationCommit: sealed.a.testedImplementationCommit,
    corpus: {
      manifestId: corpus.manifest.manifestId,
      manifestSha256: sha256Bytes(corpus.manifestBytes),
      rubricDigest: corpus.rubricDigest,
      caseCount: corpus.cases.length,
      stratum: 'fixture',
    },
    runParameters: {
      run_a: { executor: sealed.a.executorId, pid: sealed.a.pid, clock: sealed.a.clock, nonce: sealed.a.nonce, output_root: sealed.a.outputRoot },
      run_b: { executor: sealed.b.executorId, pid: sealed.b.pid, clock: sealed.b.clock, nonce: sealed.b.nonce, output_root: sealed.b.outputRoot },
    },
    predictionSetDigests: { run_a: sealed.a.predictionSetDigest, run_b: sealed.b.predictionSetDigest },
    runManifestDigests: { run_a: sealed.a.runManifestDigest, run_b: sealed.b.runManifestDigest },
    hardCounters: { run_a: sealed.a.hardCounters, run_b: sealed.b.hardCounters },
    comparison,
    hardGates: { ok: comparison.ok, violations },
    // no wall clock: the run identity is (executor, pid, nonce, output root)
    blinding: {
      candidateNeverReadLabels: true,
      comparatorNeverReRunsCandidate: true,
      annotationHmacKey: 'fixture-key (real label_custodian custody NOT_RUN)',
    },
  };
  written.push(writeEvidence('s2-006-comparison.json', comparisonRecord));

  // 5. calibration metrics on the fixture stratum (MEASURED counts, honest NOT_MEASURED independence)
  const cases = corpus.cases.map((c) => ({ caseId: c.caseId, category: c.scenario.category, stratum: 'fixture' }));
  const goldReasons = Object.fromEntries(corpus.cases.map((c) => [c.caseId, c.scenario.expected?.reasonCodes ?? []]));
  const metrics = computeMetrics({
    cases,
    gold: goldState.gold,
    goldReasons,
    predictions: sealed.a.predictions,
    annotators: goldState.annotators,
    independence: { independent: false, reason: 'evaluator_not_independent' },
  });
  const finalDecision = decideLexicographic({
    systems: [{ systemId: 'rubric-candidate', metrics, isCandidate: true, cost: null, latency: null }],
    thresholds,
  });
  const calibrationRecord = buildCalibrationRecord({
    corpus,
    metrics,
    goldState,
    thresholds,
    thresholdsDigest,
    decision: finalDecision,
  });
  if (metrics.hardViolations.total !== 0) {
    violations.push(`CALIBRATION_HARD_VIOLATIONS_${metrics.hardViolations.total}`);
  }
  written.push(writeEvidence('s2-006-calibration.json', calibrationRecord));

  // 6. adversarial probes A–S (offline; probe S is honestly NOT_RUN_DB here)
  // Review P2-6: every probe carries an honest status pass|failed|not_run and
  // NOT_RUN among the mandatory A–S set is NOT green. Probe S turns green
  // only through the PostgreSQL crash/restart phase of verify:s2-006-db-replay
  // (combined by the verify-s2-006 aggregator). A FAILED probe still violates
  // the run; a NOT_RUN probe leaves the run green but the probes gate
  // honestly incomplete.
  const probeSuite = await runAllSecurityProbes();
  const probeFailures = probeSuite.probes.filter((p) => p.status === 'failed');
  const probesGreen = probeFailures.length === 0 && probeSuite.hardCounters.total === 0 && probeSuite.totals.not_run === 0;
  if (probeFailures.length > 0 || probeSuite.hardCounters.total > 0) violations.push('PROBES_A_TO_S');
  const probesRecord = {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'adversarial probes A–S over the verifier rubric/policy/signature/command surfaces (spec §12)',
    ok: probesGreen,
    status: probesGreen ? 'PASS' : (probeFailures.length > 0 ? 'FAIL' : 'INCOMPLETE_NOT_RUN_DB'),
    statusSemantics: 'each probe carries status pass|failed|not_run; not_run among the mandatory set is never green (review P2-6)',
    combine: 'probe S resolves to green ONLY via evidence/s2-006-db-comparison.json crashPhase (verify:s2-006-db-replay crash/restart phase)',
    totals: probeSuite.totals,
    hardCounters: probeSuite.hardCounters,
    notRun: probeSuite.notRun,
    probes: probeSuite.probes,
    testedImplementationCommit: sealed.a.testedImplementationCommit,
    executedAt: 'bound on the S2-006 branch',
  };
  written.push(writeEvidence('s2-006-security-probes.json', probesRecord));

  const ok = violations.length === 0;
  console.log(JSON.stringify({
    ok,
    violations,
    written,
    caseCount: corpus.cases.length,
    comparison: { ok: comparison.ok, failures: comparison.failures.length },
    predictionSetDigests: comparisonRecord.predictionSetDigests,
    calibration: {
      coverage: metrics.coverage,
      hardViolations: metrics.hardViolations.total,
      decision: finalDecision.status,
      independence: calibrationRecord.independence.status,
    },
    probes: {
      green: probesGreen,
      total: probeSuite.totals.probes,
      pass: probeSuite.totals.pass,
      failed: probeSuite.totals.failed,
      not_run: probeSuite.totals.not_run,
      probeS: probeSuite.probes.find((p) => p.id === 'S')?.status ?? null,
      combine: 'probe S green ONLY via verify:s2-006-db-replay crash phase',
    },
  }, null, 2));
  process.exit(ok ? 0 : 1);
}

// ---- entry ----------------------------------------------------------------------

const args = parseArgs(process.argv);
if (args.candidate === 'true') {
  const corpus = loadFrozenCorpus();
  if (!corpus.ok) {
    console.error(JSON.stringify({ status: 'QUARANTINED', issues: corpus.issues }, null, 2));
    process.exit(2);
  }
  const sealed = runCandidate({
    runId: args['run-id'] ?? 'run-x',
    executorId: args['executor-id'] ?? 'exec-x',
    nonce: args.nonce ?? 'n-default',
    clock: args.clock ?? '1970-01-01T00:00:00.000Z',
    outputRoot: args['output-root'] ?? 'results/s2-006/run-x',
    corpus,
  });
  const outPath = path.isAbsolute(args.out ?? '') ? args.out : path.join(ROOT, args.out ?? 'results/s2-006/sealed.json');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(sealed, null, 2)}\n`);
  console.log(JSON.stringify({
    run_id: sealed.runId,
    status: sealed.status,
    caseCount: corpus.cases.length,
    predictionSetDigest: sealed.predictionSetDigest,
    runManifestDigest: sealed.runManifestDigest,
    hardCounters: sealed.hardCounters,
  }, null, 2));
  process.exit(sealed.status === 'COMPLETED' ? 0 : 1);
} else if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await parentMode();
}
