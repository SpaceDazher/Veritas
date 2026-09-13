// S2-003 staged deduplication and lineage decisions.
// Strictly staged, deterministic, wall-clock-free:
//   stage 1 — exact raw-byte digest equality;
//   stage 2 — exact normalized-content digest equality;
//   stage 3 — exact canonical provider identity equality;
//   stage 4 — near-duplicate candidate relation (classifier, advisory only).
// Only stages 1–3 may create automated, confirmed lineage. Stage 4 output is
// always a non-automated candidate with evidence and confidence; it never
// deletes, merges or supersedes snapshots.
import { createHash } from 'node:crypto';
import { lineageId } from './time-model.mjs';

export const DEDUP_VERDICTS = Object.freeze({
  EXACT_DUPLICATE_RAW: 'EXACT_DUPLICATE_RAW',
  EXACT_DUPLICATE_NORMALIZED: 'EXACT_DUPLICATE_NORMALIZED',
  SAME_IDENTITY_SAME_VERSION: 'SAME_IDENTITY_SAME_VERSION',
  NEW_VERSION: 'NEW_VERSION',
  UNIQUE: 'UNIQUE',
  CANDIDATE_NEAR_DUPLICATE: 'CANDIDATE_NEAR_DUPLICATE',
});

const EXACT_METHODS = Object.freeze({
  EXACT_DUPLICATE_RAW: 'exact_raw_digest',
  EXACT_DUPLICATE_NORMALIZED: 'exact_normalized_digest',
  SAME_IDENTITY_SAME_VERSION: 'canonical_identity',
});

// Normalization is deterministic: NFC unicode, unified newlines, no trailing
// whitespace drift. It never uses time or host state.
export function normalizeContent(bytes) {
  const text = Buffer.from(bytes).toString('utf8');
  return text.normalize('NFC').replace(/\r\n?/g, '\n').replace(/[\t ]+\n/g, '\n').trimEnd();
}

export function sha256Hex(bytesOrText) {
  return createHash('sha256').update(bytesOrText).digest('hex');
}

// Staged decision for a candidate against all known snapshots of the store.
// Comparison order matters and is stable: exact raw, then exact normalized,
// then canonical identity, then the advisory classifier.
export function decideDedup({ store, candidate, classifier }) {
  const all = [...store.snapshots.values()].filter((s) => s.snapshot_kind === 'content');

  for (const existing of all) {
    if (existing.raw_sha256 === candidate.raw_sha256) {
      return verdict(existing, DEDUP_VERDICTS.EXACT_DUPLICATE_RAW, null);
    }
  }
  for (const existing of all) {
    if (existing.normalized_sha256 === candidate.normalized_sha256) {
      return verdict(existing, DEDUP_VERDICTS.EXACT_DUPLICATE_NORMALIZED, null);
    }
  }
  for (const existing of all) {
    if (existing.canonical_locator === candidate.canonical_locator) {
      if (existing.version === candidate.version) {
        return verdict(existing, DEDUP_VERDICTS.SAME_IDENTITY_SAME_VERSION, null);
      }
      return verdict(existing, DEDUP_VERDICTS.NEW_VERSION, null);
    }
  }
  if (classifier) {
    let best = null;
    for (const existing of all) {
      const similarity = classifier(candidate, existing);
      if (similarity !== null && (best === null || similarity.score > best.score)) {
        best = { existing, score: similarity.score };
      }
    }
    if (best && best.score >= classifier.threshold) {
      return {
        verdict: DEDUP_VERDICTS.CANDIDATE_NEAR_DUPLICATE,
        upstream: best.existing,
        confidence: Number(best.score.toFixed(6)),
        automated: false,
      };
    }
  }
  return { verdict: DEDUP_VERDICTS.UNIQUE, upstream: null, confidence: null, automated: false };

  function verdict(existing, name, confidence) {
    return {
      verdict: name,
      upstream: existing,
      confidence,
      automated: name !== DEDUP_VERDICTS.CANDIDATE_NEAR_DUPLICATE && name !== DEDUP_VERDICTS.NEW_VERSION && name !== DEDUP_VERDICTS.UNIQUE,
    };
  }
}

// Build the lineage record implied by a dedup verdict. NEW_VERSION and UNIQUE
// produce no lineage: an edit is a version chain, not a relation, and a
// unique document has nothing to relate to.
export function lineageFromVerdict({ result, upstreamSnapshot, downstreamSnapshot, createdAt }) {
  if (result.verdict === DEDUP_VERDICTS.CANDIDATE_NEAR_DUPLICATE) {
    return {
      contractVersion: '1.0.0',
      lineage_id: lineageId({ relation: 'mirror', upstream_snapshot_id: upstreamSnapshot.snapshot_id, downstream_snapshot_id: downstreamSnapshot.snapshot_id }),
      relation: 'mirror',
      upstream_snapshot_id: upstreamSnapshot.snapshot_id,
      downstream_snapshot_id: downstreamSnapshot.snapshot_id,
      evidence: {
        method: 'near_duplicate_classifier',
        digest_sha256: null,
        detail: `classifier score ${result.confidence} (NOT_CALIBRATED, advisory only)`,
      },
      confidence: result.confidence,
      automated: false,
      status: 'candidate',
      confirmed_by: null,
      created_at: createdAt,
    };
  }
  const method = EXACT_METHODS[result.verdict];
  if (!method) return null;
  const relation = result.verdict === DEDUP_VERDICTS.SAME_IDENTITY_SAME_VERSION ? 'mirror' : 'exact_duplicate';
  return {
    contractVersion: '1.0.0',
    lineage_id: lineageId({ relation, upstream_snapshot_id: upstreamSnapshot.snapshot_id, downstream_snapshot_id: downstreamSnapshot.snapshot_id }),
    relation,
    upstream_snapshot_id: upstreamSnapshot.snapshot_id,
    downstream_snapshot_id: downstreamSnapshot.snapshot_id,
    evidence: {
      method,
      digest_sha256: method === 'exact_raw_digest' ? downstreamSnapshot.raw_sha256 : method === 'exact_normalized_digest' ? downstreamSnapshot.normalized_sha256 : null,
      detail: null,
    },
    confidence: 1,
    automated: true,
    status: 'confirmed',
    confirmed_by: null,
    created_at: createdAt,
  };
}

// Advisory classifier: 5-word shingle Jaccard. Explicitly NOT_CALIBRATED —
// no precision/recall claims are made without an independent gold set.
export function makeShingleClassifier({ threshold = 0.8, shingleSize = 5 } = {}) {
  const fn = (candidate, existing) => {
    const a = shingles(candidate.segment_text ?? '', shingleSize);
    const b = shingles(existing.segment_text ?? '', shingleSize);
    if (a.size === 0 || b.size === 0) return null;
    let intersection = 0;
    for (const shingle of a) if (b.has(shingle)) intersection += 1;
    const union = a.size + b.size - intersection;
    if (union === 0) return null;
    return { score: intersection / union };
  };
  fn.threshold = threshold;
  return fn;
}

function shingles(text, size) {
  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  const set = new Set();
  for (let i = 0; i + size <= words.length; i += 1) {
    set.add(words.slice(i, i + size).join(' '));
  }
  if (set.size === 0 && words.length > 0) set.add(words.join(' '));
  return set;
}
