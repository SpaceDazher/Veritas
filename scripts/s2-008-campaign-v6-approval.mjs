import { createHash } from 'node:crypto';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { FROZEN_MEMBERS, preregistrationDigest, scientificBody, scopeDrift } from './s2-008-campaign-approve.mjs';
import { assertV6ModelTimeoutPolicy, createV6ModelTimeoutPolicy } from './s2-008-campaign-v6-timeout.mjs';

const ID = 'xpr-s2-008c-06';
const RULE = 's2-008-prereg-v6';
const FINAL_PIN = 'evidence/s2-008-campaign/model-image-pin-v6.json';
const HEX64 = /^[0-9a-f]{64}$/;
const digestBytes = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function approvalIdentityFromArgv(argv) {
  const principalIndex = argv.indexOf('--principal');
  const labelIndex = argv.indexOf('--label');
  if (principalIndex < 0 || labelIndex < 0 ||
      argv.lastIndexOf('--principal') !== principalIndex ||
      argv.lastIndexOf('--label') !== labelIndex) {
    throw new Error('V6_APPROVAL_IDENTITY_MISSING');
  }
  const principal = argv[principalIndex + 1];
  const label = argv[labelIndex + 1];
  if (typeof principal !== 'string' || principal.startsWith('--') || principal.trim() === '' ||
      typeof label !== 'string' || label.startsWith('--') || label.trim() === '') {
    throw new Error('V6_APPROVAL_IDENTITY_MISSING');
  }
  return Object.freeze({ principal, label });
}


export function assertV6PresealPin({ pin, baseBytes, commitment = null }) {
  const first = pin?.first;
  const second = pin?.second;
  if (pin?.schema !== 's2-008-model-image-pin/6' ||
      pin.identical !== true || pin.context_digest_stable !== true ||
      pin.content_commitment_stable !== true || pin.commitment_excludes_preregistration !== true ||
      !first?.sources || !second?.sources ||
      first.sources.prereg !== digestBytes(baseBytes) ||
      !HEX64.test(first.sources.pi_runtime_tree ?? '') ||
      !HEX64.test(first.sources.timeout_policy ?? '')) {
    throw new Error('V6_PRESEAL_PIN_INVALID');
  }
  const sourceNames = Object.keys(first.sources).sort();
  if (sourceNames.some((name) => !HEX64.test(first.sources[name] ?? ''))) {
    throw new Error('V6_PRESEAL_PIN_INVALID');
  }
  const covers = sourceNames.filter((name) => name !== 'prereg');
  const expected = canonicalDigest(Object.fromEntries(covers.map((name) => [name, first.sources[name]])));
  const sameSources = canonicalDigest(first.sources) === canonicalDigest(second.sources);
  if (first.content_commitment !== expected || second.content_commitment !== expected ||
      first.source_digest !== canonicalDigest(first.sources) ||
      second.source_digest !== canonicalDigest(second.sources) ||
      first.imageId !== second.imageId || first.digest !== second.digest ||
      !sameSources ||
      canonicalDigest(first.content_commitment_covers) !== canonicalDigest(covers) ||
      canonicalDigest(pin.commitment?.covers) !== canonicalDigest(covers) ||
      canonicalDigest(pin.commitment?.excludes) !== canonicalDigest(['prereg']) ||
      (commitment !== null && commitment !== expected)) {
    throw new Error('V6_PRESEAL_PIN_INVALID');
  }
  return { ok: true, commitment: expected, covers };
}

export function createV6Draft({ base, baseBytes, pin }) {
  if (base?.rule !== 's2-008-prereg-v5' || base.preregistration_id !== 'xpr-s2-008c-05' ||
      base.approval?.in_force !== true || base.preregistration_digest !== preregistrationDigest(base)) {
    throw new Error('V6_BASE_NOT_IN_FORCE');
  }
  const { commitment, covers } = assertV6PresealPin({ pin, baseBytes });
  const timeoutPolicy = createV6ModelTimeoutPolicy();
  const oldUsdReference = base.budget_reservation?.usd_reference ?? {};
  const budgetReservation = {
    ...base.budget_reservation,
    unit_definition: 'Tokens are the sum of usage.totalTokens across every billed assistant message in pi 0.99.1 final agent_end.messages for each call, reported by the executor; intermediate message and turn events are not independently counted. The pi runtime cost field is an estimate, not an independently verified provider invoice.',
    usd_reference: {
      ...oldUsdReference,
      measured: 'pi 0.99.1 final agent_end.messages[*].usage.cost.total, summed for billed assistant messages; pi runtime reported estimate, provider invoice not independently verified',
      caveat: 'The 5,000,000-token ceiling is binding independently for each A and B run, and aggregate A+B spend is reported separately. The retained 3,865,734-token / $0.530999 plan and $0.00140476 one-call observation were measured before v6 disabled tools, extensions, and skills; they are historical references, not a v6 cost projection. Stop before the next call when actual recorded token usage reaches the signed per-run ceiling.',
      per_call_observed: {
        ...oldUsdReference.per_call_observed,
        note: 'historical pre-v6 invocation; one trivial call, with system prompt about 9058 input tokens; not a v6 cost projection',
      },
      plan: {
        ...oldUsdReference.plan,
        note: 'historical pre-v6 estimate for 378 model case calls; v6 actual usage is measured during each run',
      },
    },
  };
  const draft = {
    ...base,
    rule: RULE,
    preregistration_id: ID,
    budget_reservation: budgetReservation,
    executor: {
      ...base.executor,
      model_launch_timeout: timeoutPolicy,
      model_image: {
        ...base.executor.model_image,
        content_commitment: commitment,
        covers,
        excludes: ['prereg'],
        built_image_pin: FINAL_PIN,
        built_image_pin_reason: 'v6 pin binds the full staged pi runtime tree, timeout policy, arm, bridge, corpus, base and recipe; the signed document is excluded to avoid a digest cycle',
        field_why: 'the runtime tree digest covers every staged pi file, nested bundle chunk, mode and symbolic link target; model calls have disabled tools, extensions and skills and usage comes from final assistant messages',
      },
    },
    supersession: {
      supersedes: base.preregistration_id,
      superseded_digest: base.preregistration_digest,
      scope: 'model execution and runtime binding; frozen scientific members and 5M per-run ceiling unchanged',
      reason: 'v6 records a finite per-model-call timeout and total model-container timeout, disables tool/extension/skill access for the one-word classification, measures final pi assistant-message usage, and commits the complete staged pi runtime tree while preserving the frozen scientific members and 5,000,000-token ceiling per A/B run',
      unchanged: [...FROZEN_MEMBERS],
    },
    recorded_before_first_trial: {
      first_trial: 'NOT_STARTED',
      proof: 'no paid trial has run under v6; v4 and v5 paid launches are refused',
    },
    status: 'DRAFT',
    approval: {
      status: null, authority: 'HUMAN_OWNER', principal_id: null, label: null,
      issued_at: null,
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: false,
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v6 records this digest and supersession in the corpus manifest',
    },
  };
  draft.preregistration_digest = preregistrationDigest(draft);
  const drift = scopeDrift(base, draft);
  if (drift !== null) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  return draft;
}

export function approveV6({ draft, base, baseBytes, table, pin, principal, label, issuedAt = null }) {
  if (typeof principal !== 'string' || principal.length === 0 ||
      typeof label !== 'string' || label.length === 0) throw new Error('V6_APPROVAL_IDENTITY_MISSING');
  if (draft?.rule !== RULE || draft.preregistration_id !== ID ||
      base?.rule !== 's2-008-prereg-v5' || base.preregistration_id !== 'xpr-s2-008c-05' ||
      base.approval?.in_force !== true) throw new Error('V6_VERSION_MISMATCH');
  if (draft.approval?.status !== null || draft.status !== 'DRAFT') throw new Error('V6_ALREADY_SIGNED');
  if (draft.preregistration_digest !== preregistrationDigest(draft) ||
      base.preregistration_digest !== preregistrationDigest(base)) throw new Error('V6_DIGEST_MISMATCH');
  const drift = scopeDrift(base, draft);
  if (drift !== null) throw new Error('APPROVAL_SCOPE_DRIFT:' + drift.member);
  if (draft.expected_table_digest !== canonicalDigest(table) ||
      draft.expected_table_digest !== base.expected_table_digest) throw new Error('V6_TABLE_MISMATCH');
  const { commitment, covers } = assertV6PresealPin({ pin, baseBytes, commitment: draft.executor?.model_image?.content_commitment });
  try { assertV6ModelTimeoutPolicy(draft.executor?.model_launch_timeout); }
  catch { throw new Error('V6_MODEL_TIMEOUT_POLICY_INVALID'); }
  if (draft.executor.model_image.built_image_pin !== FINAL_PIN ||
      canonicalDigest(draft.executor.model_image.covers) !== canonicalDigest(covers) ||
      canonicalDigest(draft.executor.model_image.excludes) !== canonicalDigest(['prereg']) ||
      draft.supersession?.supersedes !== base.preregistration_id ||
      draft.supersession?.superseded_digest !== base.preregistration_digest ||
      draft.supersession?.scope !== 'model execution and runtime binding; frozen scientific members and 5M per-run ceiling unchanged' ||
      canonicalDigest(draft.supersession?.unchanged) !== canonicalDigest(FROZEN_MEMBERS)) {
    throw new Error('V6_PIN_MISMATCH');
  }
  const expected = createV6Draft({ base, baseBytes, pin });
  if (canonicalDigest(scientificBody(draft)) !== canonicalDigest(scientificBody(expected)) ||
      commitment !== expected.executor.model_image.content_commitment) throw new Error('V6_SCOPE_MISMATCH');
  const signed = {
    ...scientificBody(draft),
    status: 'APPROVED',
    approval: {
      status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: principal, label,
      issued_at: issuedAt,
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: false,
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v6 records this digest and supersession in the corpus manifest',
    },
  };
  return Object.freeze({ ...signed, preregistration_digest: preregistrationDigest(signed) });
}
