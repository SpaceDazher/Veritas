// A content-only preregistration supersession: both signed bodies differ while
// the frozen table and decision confidence remain identical.
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import { assertPreregistration, preregistrationDigest } from './preregistration.mjs';

const KEYS = Object.freeze([
  'kind', 'supersession_id', 'supersedes', 'replaced_by_preregistration_digest',
  'expected_table_digest', 'confidence', 'reason', 'supersession_digest',
]);
const DIGEST = /^[0-9a-f]{64}$/;

function pair(before, after) {
  assertPreregistration(before);
  assertPreregistration(after);
  const oldDigest = preregistrationDigest(before);
  const newDigest = preregistrationDigest(after);
  if (oldDigest === newDigest) throw new Error('CONTENT_SUPERSESSION_REPLACES_NOTHING');
  const frozen = [
    'card', 'metric', 'frozen_baseline', 'noise_rule', 'multiplicity_rule',
    'seed_rule', 'seeds_digest', 'seed_count', 'stopping_rule',
    'sequential_rule', 'holdout_access', 'inference_mode', 'trial_list',
    'expected_table_digest', 'bootstrap_process',
  ];
  for (const member of frozen) {
    if (canonicalDigest(before[member] ?? null) !== canonicalDigest(after[member] ?? null)) {
      throw new Error(`CONTENT_SUPERSESSION_RULE_MOVED:${member}`);
    }
  }
  return { oldDigest, newDigest };
}

export function createContentSupersession({ superseded, replacedBy, reason } = {}) {
  const { oldDigest, newDigest } = pair(superseded, replacedBy);
  if (typeof reason !== 'string' || reason.trim() !== reason || reason.length === 0 ||
      reason.length > 500 || /[\r\n]/.test(reason)) throw new Error('CONTENT_SUPERSESSION_REASON_INVALID');
  const body = {
    kind: 'SUPERSESSION',
    supersedes: oldDigest,
    replaced_by_preregistration_digest: newDigest,
    expected_table_digest: superseded.expected_table_digest,
    confidence: superseded.multiplicity_rule.confidence,
    reason,
  };
  const supersession_id = `spr-${canonicalDigest(body).slice(0, 24)}`;
  return Object.freeze({ ...body, supersession_id, supersession_digest: canonicalDigest({ ...body, supersession_id }) });
}

export function assertContentSupersession(record, superseded, replacedBy) {
  if (!record || typeof record !== 'object' || Array.isArray(record) ||
      Object.keys(record).sort().join('|') !== [...KEYS].sort().join('|') ||
      record.kind !== 'SUPERSESSION') throw new Error('CONTENT_SUPERSESSION_SCHEMA_INVALID');
  const { oldDigest, newDigest } = pair(superseded, replacedBy);
  if (record.supersedes !== oldDigest || record.replaced_by_preregistration_digest !== newDigest ||
      record.expected_table_digest !== superseded.expected_table_digest ||
      record.confidence !== superseded.multiplicity_rule.confidence) {
    throw new Error('CONTENT_SUPERSESSION_BINDING_MISMATCH');
  }
  if (!DIGEST.test(record.supersedes) || !DIGEST.test(record.replaced_by_preregistration_digest) ||
      !DIGEST.test(record.expected_table_digest) || typeof record.reason !== 'string' ||
      record.reason.length === 0 || record.reason.length > 500 || /[\r\n]/.test(record.reason)) {
    throw new Error('CONTENT_SUPERSESSION_CONTENT_INVALID');
  }
  const { supersession_id, supersession_digest, ...body } = record;
  if (supersession_id !== `spr-${canonicalDigest(body).slice(0, 24)}` ||
      supersession_digest !== canonicalDigest({ ...body, supersession_id })) {
    throw new Error('CONTENT_SUPERSESSION_DIGEST_MISMATCH');
  }
  return record;
}
