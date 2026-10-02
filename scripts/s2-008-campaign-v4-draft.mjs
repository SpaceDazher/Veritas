#!/usr/bin/env node
// S2-008 раздел D — the v4 DRAFT. Science byte-for-byte as v3; one new member.
//
// WHAT THIS SCRIPT IS ALLOWED TO CHANGE, and why it is written as a generator
// rather than as a file edit.
//
// The owner's decision was that the signed body carries a CONTENT COMMITMENT, not
// the built image digest: the recipe COPYs the preregistration into the image, so
// a body carrying that image's own digest would be a document whose bytes depend
// on a field inside itself. The commitment therefore covers the build with the
// preregistration excluded, and the built Id/Digest stay in the evidence pin.
//
// Three things move and nothing else:
//   preregistration_id  xpr-s2-008c-03 -> xpr-s2-008c-04   (a new document is a new id)
//   rule                s2-008-prereg-v3 -> s2-008-prereg-v4
//   executor.model_image                                          (the new member)
//
// The commitment is READ from evidence/s2-008-campaign/model-image-pin-v4.json,
// which only the build can write. Typing the digest here would make the number
// and its own verification independent, which is the one arrangement this whole
// track exists to refuse.
//
// The ceiling is NOT moved. The plan enumerates 3,865,734 tokens against a
// 5,000,000 ceiling, and the single end-to-end call section B's acceptance needs
// (~10,233) fits inside what is left. A ceiling that is not re-examined is not
// re-issued: pretending it moved would be a change nobody made.
//
// The draft is left UNSIGNED. `approval.status` stays null and the script refuses
// to write anything else, because filling that field in on the owner's behalf is
// the one act in this document that no agent may perform.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { preregistrationDigest, scopeDrift, FROZEN_MEMBERS } from './s2-008-campaign-approve.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const V3 = path.join(ROOT, 'corpus/s2-008-campaign/preregistration.v3.in-force.json');
const PIN = path.join(ROOT, 'evidence/s2-008-campaign/model-image-pin-v4.json');
const OUT = path.join(ROOT, 'corpus/s2-008-campaign/preregistration.v4.draft.json');

const base = JSON.parse(fs.readFileSync(V3, 'utf8'));
const pin = JSON.parse(fs.readFileSync(PIN, 'utf8'));

// A pin that did not come from two agreeing builds is not a pin, and a draft
// built on one would carry a commitment to nothing.
if (pin.identical !== true || pin.content_commitment_stable !== true || pin.commitment_excludes_preregistration !== true) {
  process.stderr.write(`V4_PIN_NOT_USABLE:${JSON.stringify({
    identical: pin.identical,
    content_commitment_stable: pin.content_commitment_stable,
    commitment_excludes_preregistration: pin.commitment_excludes_preregistration,
  })}\n`);
  process.exit(1);
}

const draft = {
  ...base,
  rule: 's2-008-prereg-v4',
  preregistration_id: 'xpr-s2-008c-04',
  executor: {
    ...base.executor,
    model_image: {
      // The commitment, read from the build's own pin file.
      content_commitment: pin.first.content_commitment,
      covers: [...pin.commitment.covers],
      excludes: [...pin.commitment.excludes],
      field_why: 'this is a commitment to the CONTENT the run executes (arm, bridge, canonical-json, corpus, base, pi, recipe), not to the built image digest',
      cycle_why: 'the signed body is COPYed into this image, so a body carrying the image digest would contain a digest of itself; the direction is preregistration -> image only',
      // The built image is pinned in evidence, and the pin is re-checked on every
      // launch. It is deliberately NOT in the signed body, and this says so where
      // a reader of the signature will look for it.
      built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v4.json',
      built_image_pin_reason: 'the built image includes this signed document, so its digest is recorded in evidence and re-verified per launch; the signed body contains only the acyclic content commitment',
    },
  },
  supersession: {
    supersedes: 'xpr-s2-008c-03',
    superseded_digest: base.preregistration_digest,
    reason: 'the model image gained the egress bridge, so its content commitment changed. The question, card, metric, baseline, band, seeds, family, stopping, holdout access, trial list and ceiling are unchanged.',
    unchanged: ['metric', 'frozen_baseline', 'noise_rule', 'multiplicity_rule', 'seed_rule', 'seeds_digest', 'seed_count', 'stopping_rule', 'sequential_rule', 'holdout_access', 'card', 'trial_list', 'expected_table_digest', 'bootstrap_process', 'inference_mode'],
  },
  recorded_before_first_trial: {
    first_trial: 'NOT_STARTED',
    proof: 'no trial has run under this document, and the arm refuses an unapproved preregistration',
  },
  // The ceiling is unchanged. The explanatory enumeration corrects v3's
  // mistaken claim that all three trial arms call the model: only trial 01 does.
  budget_reservation: {
    ...base.budget_reservation,
    enumerated_work: '1 model trial x 3 frozen seeds = 3 model runs x 126 holdout cases = 378 case calls; 2 regex control trials make no model calls',
  },
  status: 'DRAFT',
  approval: {
    status: null,
    authority: 'HUMAN_OWNER',
    principal_id: null,
    label: null,
    issued_at: null,
    signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
    in_force: false,
    becomes_in_force_when: 'the owner signs this draft and scripts/s2-008-campaign-prepare.mjs seals the resulting digest into the corpus manifest',
  },
};
draft.preregistration_digest = preregistrationDigest(draft);

// The gate, run before anything is written. A draft that moved the science is not
// a draft of this experiment, and finding that out after it is on disk is a
// signature waiting to be given to the wrong document.
const drift = scopeDrift(base, draft);
if (drift !== null) {
  process.stderr.write(`V4_SCOPE_DRIFT:${drift.member}\n`);
  process.exit(1);
}
if (draft.approval.status !== null) {
  process.stderr.write('V4_DRAFT_WOULD_CLAIM_APPROVAL\n');
  process.exit(1);
}

fs.writeFileSync(OUT, `${JSON.stringify(draft, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({
  written: path.relative(ROOT, OUT),
  preregistration_id: draft.preregistration_id,
  preregistration_digest: draft.preregistration_digest,
  content_commitment: draft.executor.model_image.content_commitment,
  ceiling_unchanged: draft.budget_reservation.granted_units === base.budget_reservation.granted_units,
  frozen_members_checked: FROZEN_MEMBERS.length,
  scope_drift: drift,
  approval_status: draft.approval.status,
}, null, 2)}\n`);
