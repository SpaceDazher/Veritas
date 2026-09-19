// S2-006 fail-closed comparator (spec §9). Runs after unseal, in a separate
// evaluation process: it compares two pre-sealed prediction sets (Run A /
// Run B) of the SAME frozen candidate over the SAME frozen inputs against
// the frozen labels, adjudications and manifests — and it never re-runs the
// candidate (probe Q).
//
// Fail-closed contract — ok:false unless every check passes:
//   * complete case composition on both runs (no missing, no extra);
//   * split membership matches the frozen manifest;
//   * every case/rubric/label byte digest recomputed and equal to the
//     manifest;
//   * annotation-set signatures verified over the exact binding digest;
//   * disagreements covered by adjudication records bound to this manifest;
//   * Run A and Run B predictions identical per case (preregistered exact
//     rule) with DISTINCT run-manifest digests (executor, pid, nonce, output
//     root);
//   * no degenerate prediction distribution (a single verdict across the
//     whole run is the S2-005 ERROR:55 regression signature — two identically
//     broken runs are never a match);
//   * zero hard counters in both run manifests.
//
// Node stdlib only; no producer-semantics imports (spec §3).
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { canonicalDigest } from './canonical-json.mjs';

export const COMPARATOR_RULE = 'exact';

const sha256Bytes = (buf) => createHash('sha256').update(buf).digest('hex');

function fail(failures, code, detail) {
  failures.push({ code, detail });
}

function verifySetSignature(set, hmacKey, failures) {
  if (!set?.signature || set.signature.scheme !== 'hmac-sha256') {
    fail(failures, 'signature_unverifiable', `${set?.annotationSetId}: only verified hmac-sha256 signatures are accepted offline`);
    return;
  }
  if (typeof hmacKey !== 'string' || hmacKey.length === 0) {
    fail(failures, 'signature_key_unavailable', `${set.annotationSetId}: no HMAC key in custody — failing closed, not trusting the attestation`);
    return;
  }
  const binding = canonicalDigest({
    annotationSetId: set.annotationSetId,
    split: set.split,
    corpusVersion: set.corpusVersion,
    sourceDigest: set.sourceDigest,
    rubricDigest: set.rubricDigest,
    labels: [...set.labels].sort((a, b) => a.caseId.localeCompare(b.caseId)),
  });
  const expected = createHmac('sha256', hmacKey).update(binding, 'utf8').digest('hex');
  const got = set.signature.digest;
  const equal = got.length === expected.length && timingSafeEqual(Buffer.from(got), Buffer.from(expected));
  if (!equal) fail(failures, 'signature_invalid', `${set.annotationSetId}: signature does not verify over the exact binding digest`);
}

// input: {
//   manifest, manifestBytes,
//   rubricBytes,
//   cases: [{caseId, bytes, record, scenario, split}],
//   labelSets: {annotationSetId: set},
//   adjudications: [record],
//   thresholdsDigest,
//   annotationHmacKey,
//   runA, runB: {runId, executorId, pid, nonce, outputRoot, implementationDigest,
//                predictions: {caseId: {verdict, reasonCodes}}, hardCounters?}
// }
export function compareRuns(input) {
  const failures = [];
  const {
    manifest, manifestBytes, rubricBytes, cases = [], labelSets = {}, adjudications = [],
    thresholdsDigest = null, annotationHmacKey = null, runA, runB,
  } = input ?? {};

  // ---- frozen bytes
  if (!manifest || !manifestBytes || !rubricBytes) {
    fail(failures, 'digest_mismatch', 'manifest bytes, manifest object and rubric bytes are all required');
    return { ok: false, failures, checks: {}, rule: COMPARATOR_RULE };
  }
  const manifestSha = sha256Bytes(manifestBytes);
  const rubricSha = sha256Bytes(rubricBytes);
  if (rubricSha !== manifest.rubricDigest) {
    fail(failures, 'digest_mismatch', 'rubric bytes digest != manifest.rubricDigest');
  }

  // ---- case composition
  const caseById = new Map(cases.map((c) => [c.caseId, c]));
  const manifestCases = new Map(manifest.cases.map((c) => [c.caseId, c]));
  for (const c of cases) {
    const entry = manifestCases.get(c.caseId);
    if (!entry) {
      fail(failures, 'incomplete_case_set', `${c.caseId}: present in corpus, absent from manifest`);
      continue;
    }
    const fileSha = sha256Bytes(c.bytes);
    if (fileSha !== entry.caseSha256) {
      fail(failures, 'digest_mismatch', `${c.caseId}: case file bytes != manifest.caseSha256`);
    }
    if (c.record?.textDigest !== canonicalDigest(c.scenario)) {
      fail(failures, 'digest_mismatch', `${c.caseId}: scenario digest != case.textDigest`);
    }
    if (c.record?.caseId !== c.caseId) {
      fail(failures, 'incomplete_case_set', `${c.caseId}: record id mismatch`);
    }
  }
  for (const id of manifestCases.keys()) {
    if (!caseById.has(id)) fail(failures, 'incomplete_case_set', `${id}: manifest case missing from corpus composition`);
  }

  // ---- split membership
  const splitByCase = new Map(manifest.splitAssignments.map((a) => [a.caseId, a.split]));
  for (const c of cases) {
    const expected = splitByCase.get(c.caseId);
    if (!expected) {
      fail(failures, 'split_membership_mismatch', `${c.caseId}: no split assignment`);
    } else if (c.split !== expected) {
      fail(failures, 'split_membership_mismatch', `${c.caseId}: corpus split ${c.split} != manifest split ${expected}`);
    }
  }

  // ---- labels: per-case digest binding, signatures, blinding
  for (const set of Object.values(labelSets)) {
    if (set.blindAssignment && !Object.values(set.blindAssignment).every(Boolean)) {
      fail(failures, 'signature_invalid', `${set.annotationSetId}: annotation set is not fully blind`);
    }
    if (set.rubricDigest !== manifest.rubricDigest) {
      fail(failures, 'digest_mismatch', `${set.annotationSetId}: rubric digest != manifest rubricDigest`);
    }
    verifySetSignature(set, annotationHmacKey, failures);
  }
  const labelEntry = (caseId, annotatorId) => {
    for (const set of Object.values(labelSets)) {
      const entry = set.labels.find((l) => l.caseId === caseId && l.annotatorId === annotatorId);
      if (entry) return { set, entry };
    }
    return null;
  };
  for (const c of cases) {
    const a = labelEntry(c.caseId, 'prn-annotator-a');
    const b = labelEntry(c.caseId, 'prn-annotator-b');
    if (!a || !b) {
      fail(failures, 'incomplete_case_set', `${c.caseId}: missing one of the two independent raw labels`);
      continue;
    }
    for (const { set, entry } of [a, b]) {
      const digest = canonicalDigest({
        annotationSetId: set.annotationSetId, annotatorId: entry.annotatorId,
        caseId: entry.caseId, label: entry.label, labeledAt: entry.labeledAt,
      });
      if (digest !== entry.labelDigest) {
        fail(failures, 'digest_mismatch', `${c.caseId}: label digest binding broken (${set.annotationSetId})`);
      }
    }
    const entry = manifestCases.get(c.caseId);
    const labelsSha = canonicalDigest({
      caseId: c.caseId,
      labels: [a.entry, b.entry].map((e) => ({
        caseId: e.caseId, label: e.label, labelDigest: e.labelDigest, annotatorId: e.annotatorId, labeledAt: e.labeledAt,
      })),
    });
    if (entry && labelsSha !== entry.labelsSha256) {
      fail(failures, 'digest_mismatch', `${c.caseId}: combined label bytes != manifest.labelsSha256`);
    }
  }

  // ---- adjudication coverage of raw disagreements, bound to this manifest
  const consensus = {};
  for (const c of cases) {
    const a = labelEntry(c.caseId, 'prn-annotator-a');
    const b = labelEntry(c.caseId, 'prn-annotator-b');
    if (!a || !b) continue;
    if (a.entry.label === b.entry.label) {
      consensus[c.caseId] = a.entry.label;
      continue;
    }
    const rec = adjudications.find((r) => r.caseId === c.caseId);
    if (!rec) {
      fail(failures, 'adjudication_missing', `${c.caseId}: raw labels disagree with no adjudication record`);
      continue;
    }
    if (rec.decision !== a.entry.label && rec.decision !== b.entry.label) {
      fail(failures, 'adjudication_invalid', `${c.caseId}: adjudicated decision matches neither raw vote`);
    }
    if (rec.versions?.annotationManifestDigest !== manifestSha) {
      fail(failures, 'digest_mismatch', `${c.caseId}: adjudication bound to a different annotation manifest`);
    }
    if (rec.versions?.rubricDigest !== manifest.rubricDigest) {
      fail(failures, 'digest_mismatch', `${c.caseId}: adjudication bound to a different rubric`);
    }
    if (thresholdsDigest && rec.versions?.thresholdsDigest !== thresholdsDigest) {
      fail(failures, 'digest_mismatch', `${c.caseId}: adjudication bound to different thresholds`);
    }
    consensus[c.caseId] = rec.decision;
  }

  // ---- runs: completeness, divergence, degeneracy, hard counters
  const runs = [
    ['runA', runA],
    ['runB', runB],
  ];
  const predictionDigests = {};
  const runManifestDigests = {};
  const perRun = {};
  for (const [name, run] of runs) {
    if (!run || typeof run.predictions !== 'object' || run.predictions === null) {
      fail(failures, 'incomplete_case_set', `${name}: missing prediction set`);
      continue;
    }
    const predIds = Object.keys(run.predictions).sort();
    for (const id of predIds) {
      if (!manifestCases.has(id)) fail(failures, 'incomplete_case_set', `${name}: extra prediction for unknown case ${id}`);
    }
    for (const id of manifestCases.keys()) {
      if (!run.predictions[id]) fail(failures, 'incomplete_case_set', `${name}: missing sealed prediction for ${id}`);
    }
    const verdicts = new Set(predIds.filter((id) => manifestCases.has(id)).map((id) => run.predictions[id].verdict));
    if (verdicts.size <= 1 && predIds.length > 1) {
      fail(failures, 'degenerate_run', `${name}: prediction distribution is degenerate (${[...verdicts].join(',')}) — regression signature of a broken run`);
    }
    const counters = run.hardCounters ?? {};
    const hardTotal = (counters.unauthorizedLeakageEvents ?? 0) + (counters.lockedLabelAccessEvents ?? 0)
      + (counters.producerSelfReviewEvents ?? 0) + (counters.upstreamArtifactMutationEvents ?? 0)
      + (counters.unauthorizedSideEffectEvents ?? 0);
    if (hardTotal > 0) fail(failures, 'hard_violations', `${name}: run manifest reports ${hardTotal} hard violation events`);
    predictionDigests[name] = canonicalDigest(run.predictions);
    runManifestDigests[name] = canonicalDigest({
      runId: run.runId, executorId: run.executorId, pid: run.pid,
      nonce: run.nonce, outputRoot: run.outputRoot, implementationDigest: run.implementationDigest,
    });
    perRun[name] = { runId: run.runId, verdictDistribution: Object.fromEntries([...verdicts].map((v) => [v, true])) };
  }
  if (predictionDigests.runA && predictionDigests.runB && runA && runB) {
    // preregistered exact rule: a deterministic candidate must reproduce the
    // same predictions in a process-separated second run
    if (predictionDigests.runA !== predictionDigests.runB) {
      fail(failures, 'run_divergence', 'Run A and Run B prediction sets differ under the exact comparison rule');
    }
    // distinct run-manifest digests are mandatory even for identical
    // predictions (executor ID, PID, nonce, output root — spec §3)
    if (runManifestDigests.runA === runManifestDigests.runB) {
      fail(failures, 'run_manifest_collision', 'Run A and Run B share one run-manifest digest; two independent executions are required');
    }
  }

  return {
    ok: failures.length === 0,
    failures,
    rule: COMPARATOR_RULE,
    checks: {
      caseCount: cases.length,
      manifestSha256: manifestSha,
      rubricDigest: manifest.rubricDigest,
      predictionDigests,
      runManifestDigests,
      consensusGold: consensus,
      perRun,
    },
  };
}
