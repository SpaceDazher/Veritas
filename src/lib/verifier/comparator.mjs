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
//   * annotation-set signatures AND adjudicator-identity attestations are
//     verified over the exact binding digests by the ONE custody-aware core
//     signature.verifyDetailed (contracts/annotation-set.schema.json
//     envelope: scheme hmac-sha256, keyRef, digest=MAC, verified,
//     attestedBy; contracts/adjudication-record.schema.json
//     adjudicatorIdentity): the keyRef must exist in the caller-provided
//     custody registry and be held by exactly the annotator/adjudicator
//     principal of record (review fix2-E: a valid MAC under a foreign or
//     shared key is rejected — the comparator never recomputes HMACs);
//   * annotator principals come from the annotation-set data itself
//     (annotatorId fields) or the expectedAnnotators argument — never from
//     hardcoded ids (review P1-4b);
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
import { createHash } from 'node:crypto';
import { canonicalDigest } from './canonical-json.mjs';
import { verifyDetailed as verifySignatureDetailed } from './signature.mjs';

export const COMPARATOR_RULE = 'exact';

// Frozen contract envelope shapes (contracts/*.schema.json):
const SIGNATURE_KEYS = ['scheme', 'keyRef', 'digest', 'verified', 'attestedBy'];
const ADJUDICATOR_IDENTITY_KEYS = ['principalId', 'role', 'authenticated', 'attestationDigest'];

const sha256Bytes = (buf) => createHash('sha256').update(buf).digest('hex');

function fail(failures, code, detail) {
  failures.push({ code, detail });
}

// Exact per-label binding digest (canonical-json-v1 over the raw label as
// signed). Single source for comparator verification and corpus tooling.
export function labelEntryDigest(entry) {
  const { annotationSetId, annotatorId, caseId, label, labeledAt } = entry ?? {};
  return canonicalDigest({ annotationSetId, annotatorId, caseId, label, labeledAt });
}

// Exact set-level binding digest: corpus+split+case+rubric+label bytes the
// annotation-set signature is taken over (spec §3). Single source for the
// comparator verification and corpus signing.
export function annotationSetBindingDigest(set) {
  return canonicalDigest({
    annotationSetId: set.annotationSetId,
    split: set.split,
    corpusVersion: set.corpusVersion,
    sourceDigest: set.sourceDigest,
    rubricDigest: set.rubricDigest,
    labels: [...set.labels].sort((a, b) => a.caseId.localeCompare(b.caseId)),
  });
}

// Exact combined per-case label digest bound by the annotation manifest
// (labelsSha256): the raw label entries of all independent annotators in
// ascending annotatorId order.
export function caseLabelsDigest(caseId, entries) {
  return canonicalDigest({
    caseId,
    labels: entries.map((e) => ({
      caseId: e.caseId, label: e.label, labelDigest: e.labelDigest, annotatorId: e.annotatorId, labeledAt: e.labeledAt,
    })),
  });
}

// Exact attestation binding of an adjudication record: the canonical digest
// of every field EXCEPT the adjudicatorIdentity envelope itself (which
// carries the MAC as attestationDigest). The identity attests exactly the
// decision content and its manifest/rubric/thresholds bindings.
export function adjudicationAttestationDigest(rec) {
  const { adjudicatorIdentity, ...attestedContent } = rec ?? {};
  return canonicalDigest(attestedContent);
}

// ONE custody-aware verifying core for every annotation-set envelope:
// signature.verifyDetailed enforces the exact contract shape, the scheme,
// the verified gate, keyRef existence in the registry, custody
// (key.custodian === attestedBy === annotator of record) and the MAC over
// the exact binding digest, constant-time. The comparator itself never
// recomputes an HMAC (review fix2-E).
function verifySetSignature(set, sigCtx, failures) {
  const sig = set?.signature;
  const id = set?.annotationSetId ?? '<unknown-set>';
  const shapeOk = typeof sig === 'object' && sig !== null && !Array.isArray(sig)
    && SIGNATURE_KEYS.every((k) => Object.prototype.hasOwnProperty.call(sig, k))
    && Object.keys(sig).length === SIGNATURE_KEYS.length
    && ['keyRef', 'digest', 'attestedBy'].every((k) => typeof sig[k] === 'string' && sig[k].length > 0);
  if (!shapeOk) {
    fail(failures, 'signature_unverifiable', `${id}: only a verified contract-shaped hmac-sha256 signature block (annotation-set contract) is accepted offline`);
    return;
  }
  if (!sigCtx) {
    fail(failures, 'signature_key_unavailable', `${id}: no signature key registry in custody — failing closed, not trusting the attestation`);
    return;
  }
  if (sigCtx.sharedKeyRefs.has(sig.keyRef)) {
    fail(failures, 'signature_rejected', `${id}: keyRef ${sig.keyRef} is observed under more than one annotator — one custody key can never serve two principals`);
    return;
  }
  const verdict = verifySignatureDetailed(sig, set.annotatorId, annotationSetBindingDigest(set), { registry: sigCtx.registry });
  if (!verdict.ok) fail(failures, 'signature_rejected', `${id}: custody-aware signature verification rejected (${verdict.reason})`);
}

// Adjudicator identities go through the SAME core. Structural contract
// checks run first; on the registry path the attestationDigest is verified
// as a MAC over adjudicationAttestationDigest(rec) with the adjudicator's
// custody key (resolved by verifyDetailed from the registry). In deprecated
// fixture mode there is no adjudicator custody key: structural checks only,
// the opaque fixture attestationDigest is NOT trusted as a MAC.
function verifyAdjudicationIdentity(rec, annotators, sigCtx, failures) {
  const identity = rec?.adjudicatorIdentity;
  const id = rec?.adjudicationId ?? '<unknown-adjudication>';
  const shapeOk = typeof identity === 'object' && identity !== null && !Array.isArray(identity)
    && ADJUDICATOR_IDENTITY_KEYS.every((k) => Object.prototype.hasOwnProperty.call(identity, k))
    && Object.keys(identity).length === ADJUDICATOR_IDENTITY_KEYS.length
    && identity.role === 'adjudicator'
    && identity.authenticated === true
    && typeof identity.principalId === 'string' && identity.principalId.length > 0
    && typeof identity.attestationDigest === 'string' && identity.attestationDigest.length > 0;
  if (!shapeOk) {
    fail(failures, 'signature_unverifiable', `${id}: only a fully authenticated adjudicator-identity block (adjudication-record contract) is accepted offline`);
    return;
  }
  if (annotators.includes(identity.principalId)) {
    fail(failures, 'annotator_set_mismatch', `${id}: adjudicator ${identity.principalId} is one of the annotators of record — self-review is refused`);
  }
  if (!sigCtx) {
    fail(failures, 'signature_key_unavailable', `${id}: no adjudicator custody registry supplied`);
    return;
  }
  const verdict = verifySignatureDetailed(identity, identity.principalId, adjudicationAttestationDigest(rec), { registry: sigCtx.registry });
  if (!verdict.ok) fail(failures, 'signature_rejected', `${id}: custody-aware adjudicator attestation rejected (${verdict.reason})`);
}

// input: {
//   manifest, manifestBytes,
//   rubricBytes,
//   cases: [{caseId, bytes, record, scenario, split}],
//   labelSets: {annotationSetId: set},
//   adjudications: [record],
//   thresholdsDigest,
//   signatureKeyRegistry: Map<keyRef, {secret, custodian, role}>
//     // REQUIRED for real (production) use: the custody registry of every
//     // signing principal, built with signature.registerKey (see
//     // tests/verifier/fixtures/keys.json). Every annotation-set signature
//     // and every adjudicator attestation is verified through the ONE
//     // custody-aware core signature.verifyDetailed against it.
//   annotationHmacKey, // retired: accepted only to produce a fail-closed
//                      // signature_key_unavailable result for old callers
//   expectedAnnotators?: [principalId, ...]  // pins the required annotator pair;
//                                            // defaults to the annotators in the data
//   runA, runB: {runId, executorId, pid, nonce, outputRoot, implementationDigest,
//                predictions: {caseId: {verdict, reasonCodes}}, hardCounters?}
// }
export function compareRuns(input) {
  const failures = [];
  const {
    manifest, manifestBytes, rubricBytes, cases = [], labelSets = {}, adjudications = [],
    thresholdsDigest = null, signatureKeyRegistry = null,
    expectedAnnotators = null, runA, runB,
  } = input ?? {};

  // ---- signature verification context (fix2-E: one custody-aware core)
  let sigCtx = null;
  if (signatureKeyRegistry !== null && signatureKeyRegistry !== undefined) {
    if (!(signatureKeyRegistry instanceof Map)) {
      throw new TypeError('signatureKeyRegistry must be a Map (keyRef -> {secret, custodian, role}) built with signature.registerKey');
    }
    sigCtx = { registry: signatureKeyRegistry, sharedKeyRefs: new Set(), fixture: false };
  }

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
  // (every signature runs through the single custody-aware core)
  for (const set of Object.values(labelSets)) {
    if (set.blindAssignment && !Object.values(set.blindAssignment).every(Boolean)) {
      fail(failures, 'signature_invalid', `${set.annotationSetId}: annotation set is not fully blind`);
    }
    if (set.rubricDigest !== manifest.rubricDigest) {
      fail(failures, 'digest_mismatch', `${set.annotationSetId}: rubric digest != manifest rubricDigest`);
    }
    verifySetSignature(set, sigCtx, failures);
  }
  const labelEntry = (caseId, annotatorId) => {
    for (const set of Object.values(labelSets)) {
      const entry = set.labels.find((l) => l.caseId === caseId && l.annotatorId === annotatorId);
      if (entry) return { set, entry };
    }
    return null;
  };
  // Independent annotator principals are DATA (review P1-4b): taken from
  // the annotation sets' annotatorId fields, or pinned via expectedAnnotators.
  // No literal principal ids live in this code.
  const dataAnnotators = [...new Set(Object.values(labelSets)
    .map((s) => (typeof s?.annotatorId === 'string' && s.annotatorId.length > 0 ? s.annotatorId : null))
    .filter(Boolean))].sort();
  let annotators = dataAnnotators;
  if (Array.isArray(expectedAnnotators)) {
    annotators = [...new Set(expectedAnnotators)].sort();
    if (annotators.length !== dataAnnotators.length || annotators.some((a, i) => a !== dataAnnotators[i])) {
      fail(failures, 'annotator_set_mismatch', `annotation-set annotators [${dataAnnotators.join(',')}] != expectedAnnotators [${annotators.join(',')}]`);
    }
  }
  if (annotators.length < 2) {
    fail(failures, 'incomplete_case_set', `independent labeling requires at least two distinct annotators, found ${annotators.length}`);
  }

  // ---- adjudicator identities: contract shape, no self-review, and on the
  // registry path a custody-checked MAC over the attested record content
  for (const rec of adjudications) {
    verifyAdjudicationIdentity(rec, annotators, sigCtx, failures);
  }

  for (const c of cases) {
    const found = [];
    let missing = false;
    for (const annotatorId of annotators) {
      const hit = labelEntry(c.caseId, annotatorId);
      if (!hit) {
        fail(failures, 'incomplete_case_set', `${c.caseId}: missing raw label from ${annotatorId}`);
        missing = true;
        continue;
      }
      found.push(hit);
    }
    if (missing || found.length < 2) continue;
    for (const { set, entry } of found) {
      if (entry.labelDigest !== labelEntryDigest({ annotationSetId: set.annotationSetId, annotatorId: entry.annotatorId, caseId: entry.caseId, label: entry.label, labeledAt: entry.labeledAt })) {
        fail(failures, 'digest_mismatch', `${c.caseId}: label digest binding broken (${set.annotationSetId})`);
      }
    }
    const entry = manifestCases.get(c.caseId);
    const labelsSha = caseLabelsDigest(c.caseId, found.map((f) => f.entry));
    if (entry && labelsSha !== entry.labelsSha256) {
      fail(failures, 'digest_mismatch', `${c.caseId}: combined label bytes != manifest.labelsSha256`);
    }
  }

  // ---- adjudication coverage of raw disagreements, bound to this manifest
  const consensus = {};
  for (const c of cases) {
    const found = annotators
      .map((annotatorId) => labelEntry(c.caseId, annotatorId))
      .filter(Boolean);
    if (found.length < 2) continue;
    const votes = found.map((f) => f.entry.label);
    if (votes.every((v) => v === votes[0])) {
      consensus[c.caseId] = votes[0];
      continue;
    }
    const rec = adjudications.find((r) => r.caseId === c.caseId);
    if (!rec) {
      fail(failures, 'adjudication_missing', `${c.caseId}: raw labels disagree with no adjudication record`);
      continue;
    }
    if (!votes.includes(rec.decision)) {
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
