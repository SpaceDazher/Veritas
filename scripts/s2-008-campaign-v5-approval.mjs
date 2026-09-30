import { createHash } from 'node:crypto';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { FROZEN_MEMBERS, preregistrationDigest, scientificBody, scopeDrift } from './s2-008-campaign-approve.mjs';

const id = 'xpr-s2-008c-05';
const rule = 's2-008-prereg-v5';
const finalPinFile = 'evidence/s2-008-campaign/model-image-pin-v5.json';
const digestBytes = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function assertV5PresealPin({ pin, baseBytes, commitment = null }) {
  const first = pin?.first;
  const second = pin?.second;
  if (pin?.schema !== 's2-008-model-image-pin/5' ||
      pin.identical !== true || pin.context_digest_stable !== true ||
      pin.content_commitment_stable !== true ||
      pin.commitment_excludes_preregistration !== true ||
      !first?.sources || !second?.sources ||
      first.sources.prereg !== digestBytes(baseBytes)) throw new Error('V5_PIN_NOT_USABLE');
  const covers = Object.keys(first.sources).filter((name) => name !== 'prereg').sort();
  const expected = canonicalDigest(Object.fromEntries(covers.map((name) => [name, first.sources[name]])));
  if (first.content_commitment !== expected || second.content_commitment !== expected ||
      first.source_digest !== canonicalDigest(first.sources) ||
      second.source_digest !== canonicalDigest(second.sources) ||
      first.imageId !== second.imageId || first.digest !== second.digest ||
      canonicalDigest(first.sources) !== canonicalDigest(second.sources) ||
      canonicalDigest(first.content_commitment_covers) !== canonicalDigest(covers) ||
      canonicalDigest(pin.commitment?.covers) !== canonicalDigest(covers) ||
      canonicalDigest(pin.commitment?.excludes) !== canonicalDigest(['prereg']) ||
      (commitment !== null && commitment !== expected)) throw new Error('V5_PIN_MISMATCH');
  return { commitment: expected, covers };
}

export function createV5Draft({ base, baseBytes, pin }) {
  if (base?.rule !== 's2-008-prereg-v4' || base.preregistration_id !== 'xpr-s2-008c-04' ||
      base.approval?.in_force !== true || base.preregistration_digest !== preregistrationDigest(base)) {
    throw new Error('V5_BASE_NOT_IN_FORCE');
  }
  const { commitment, covers } = assertV5PresealPin({ pin, baseBytes });
  const draft = {
    ...base,
    rule,
    preregistration_id: id,
    executor: {
      ...base.executor,
      model_image: {
        ...base.executor.model_image,
        content_commitment: commitment,
        covers,
        excludes: ['prereg'],
        built_image_pin: finalPinFile,
        field_why: 'content commitment covers the cap-aware arm, bridge, corpus, base, pi and recipe; the signed document is excluded to avoid a digest cycle',
      },
    },
    budget_reservation: {
      ...base.budget_reservation,
      ceiling_scope: 'PER_RUN_A_OR_B',
      aggregate_spend_disclosure: 'A and B each have an independent 5,000,000-token ceiling; report their total spend separately',
    },
    supersession: {
      supersedes: base.preregistration_id,
      superseded_digest: base.preregistration_digest,
      reason: 'v5 replaces the model image with a shared remaining-token cap across seeds; the scientific rule and the 5,000,000-token ceiling per run are unchanged',
      unchanged: [...FROZEN_MEMBERS],
    },
    recorded_before_first_trial: {
      first_trial: 'NOT_STARTED',
      proof: 'no paid trial has run under v5 and v4 paid launches are blocked',
    },
    status: 'DRAFT',
    approval: {
      status: null, authority: 'HUMAN_OWNER', principal_id: null, label: null,
      issued_at: null,
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: false,
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v5 records this digest and supersession in the corpus manifest',
    },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift !== null) throw new Error(`APPROVAL_SCOPE_DRIFT:${drift.member}`);
  return draft;
}

export function approveV5({ draft, base, baseBytes, table, pin, principal, label, issuedAt = null }) {
  if (typeof principal !== 'string' || principal.length === 0 ||
      typeof label !== 'string' || label.length === 0) throw new Error('V5_APPROVAL_IDENTITY_MISSING');
  if (draft?.rule !== rule || draft.preregistration_id !== id ||
      base?.rule !== 's2-008-prereg-v4' || base.preregistration_id !== 'xpr-s2-008c-04' ||
      base.approval?.in_force !== true) throw new Error('V5_VERSION_MISMATCH');
  if (draft.approval?.status !== null || draft.status !== 'DRAFT') throw new Error('V5_ALREADY_SIGNED');
  if (draft.preregistration_digest !== preregistrationDigest(draft) ||
      base.preregistration_digest !== preregistrationDigest(base)) throw new Error('V5_DIGEST_MISMATCH');
  const drift = scopeDrift(base, draft);
  if (drift !== null) throw new Error(`APPROVAL_SCOPE_DRIFT:${drift.member}`);
  if (draft.expected_table_digest !== canonicalDigest(table) ||
      draft.expected_table_digest !== base.expected_table_digest) throw new Error('V5_TABLE_MISMATCH');
  const { commitment, covers } = assertV5PresealPin({ pin, baseBytes, commitment: draft.executor?.model_image?.content_commitment });
  if (draft.executor.model_image.built_image_pin !== finalPinFile ||
      canonicalDigest(draft.executor.model_image.covers) !== canonicalDigest(covers) ||
      canonicalDigest(draft.executor.model_image.excludes) !== canonicalDigest(['prereg']) ||
      draft.supersession?.supersedes !== base.preregistration_id ||
      draft.supersession?.superseded_digest !== base.preregistration_digest ||
      canonicalDigest(draft.supersession?.unchanged) !== canonicalDigest(FROZEN_MEMBERS)) {
    throw new Error('V5_PIN_MISMATCH');
  }
  const expected = createV5Draft({ base, baseBytes, pin });
  if (canonicalDigest(scientificBody(draft)) !== canonicalDigest(scientificBody(expected)) ||
      commitment !== expected.executor.model_image.content_commitment) throw new Error('V5_SCOPE_MISMATCH');
  const signed = {
    ...scientificBody(draft),
    status: 'APPROVED',
    approval: {
      status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: principal, label,
      issued_at: issuedAt,
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: false,
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v5 records this digest and supersession in the corpus manifest',
    },
  };
  return Object.freeze({ ...signed, preregistration_digest: preregistrationDigest(signed) });
}
