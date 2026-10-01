// S2-008 #12 — the OWNER'S SIGNATURE on preregistration v2.
//
//   node scripts/s2-008-campaign-approve.mjs --principal <id> --label "<text>" [--out <path>]
//
// WHY THIS IS A SCRIPT AND NOT A FIELD IN THE DRAFT
// A signature you can type into a JSON file is not a signature. The draft ships
// with `approval.status: null` on purpose, and this script is the only thing that
// can turn it into an approved document — and it REFUSES to issue one unless the
// document it is signing still says the thing the owner is approving. That is the
// difference this repository has now paid for twice in this track: a record that
// asserts itself, and an A-MVP gate that trusted the record it was judging.
//
// THREE THINGS HAPPEN HERE, IN THIS ORDER, and the order is the point:
//
//   1. THE SCIENCE IS CHECKED AGAINST v1 BEFORE ANY SIGNATURE. A supersession may
//      change the predictor, the currency and the spend. It may NOT change the
//      rule, the metric, the frozen baseline, the noise band, the seeds, the
//      multiplicity rule, the stopping rule, the holdout access or the hypothesis
//      card. Any movement in those is `SCOPE_DRIFT` and nothing is issued — so a
//      "signature" can never be a quiet rewrite of the experiment. The comparison
//      is by value, member by member, and it prints the first field that moved.
//
//   2. THE DOCUMENT IS FROZEN WITH A DIGEST OVER EVERYTHING EXCEPT THE APPROVAL
//      BLOCK. `preregistration_digest` is a hash of the scientific body. Editing
//      any field after signing changes the recomputed digest, and the arm — which
//      recomputes it from the bytes it was handed — refuses. The approval cannot
//      travel away from the document it approves.
//
//   3. THE APPROVAL RECORDS WHO, AND IT IS NOT A SECRET. A principal id and a
//      label, like scripts/s2-007r-authorization.mjs records the owner of the
//      HOST_UNISOLATED permit. `issued_at` is the wall clock, which decides nothing
//      here: it is a fact about when the permit was written, and the digest over
//      the body deliberately excludes it so a re-run does not change the document.
//
// The issued document is NOT yet in force. It becomes in force when
// `scripts/s2-008-campaign-prepare.mjs --seal-v2` records its digest in the corpus
// manifest and carries a SUPERSESSION from v1, exactly as the previous
// supersession did. Until then the arm's own `PREREG_NOT_APPROVED` check is not
// even reached, because a run is pointed at the draft.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';

export const APPROVE_ERRORS = Object.freeze({
  ARGS: 'APPROVAL_ARGUMENTS_INCOMPLETE',
  DRAFT_ABSENT: 'APPROVAL_DRAFT_ABSENT',
  DRAFT_ALREADY_APPROVED: 'APPROVAL_DRAFT_ALREADY_APPROVED',
  DRAFT_CORRUPT: 'APPROVAL_DRAFT_UNREADABLE',
  BASE_ABSENT: 'APPROVAL_BASE_PREREGISTRATION_ABSENT',
  SCOPE_DRIFT: 'APPROVAL_SCOPE_DRIFT',
  ALREADY_SIGNED: 'APPROVAL_ALREADY_SIGNED',
});

/** The members a supersession may not touch. Value-compared, in this order. */
export const FROZEN_MEMBERS = Object.freeze([
  'card',
  'metric',
  'frozen_baseline',
  'noise_rule',
  'multiplicity_rule',
  'seed_rule',
  'seeds_digest',
  'seed_count',
  'stopping_rule',
  'sequential_rule',
  'holdout_access',
  'inference_mode',
  'trial_list',
  'expected_table_digest',
  'bootstrap_process',
]);

/** The members that MAY move, and are named so the record says what it bought. */
export const MOVABLE_MEMBERS = Object.freeze(['arms', 'budget_reservation', 'executor', 'description', 'title', 'rule', 'preregistration_id']);

/** The body a digest is taken over: everything except the approval and the digest itself. */
export function scientificBody(document) {
  const { approval, preregistration_digest, status, ...body } = document ?? {};
  return body;
}

/** The digest of the scientific body. Recomputed by the verifier, not trusted. */
export function preregistrationDigest(document) {
  return canonicalDigest(scientificBody(document));
}

/**
 * The comparison that decides whether this document may be signed at all.
 * Returns the first member that moved, with the two values, or null when the
 * science is byte-for-byte the frozen one.
 */
export function scopeDrift(base, candidate, members = FROZEN_MEMBERS) {
  for (const member of members) {
    const a = canonicalDigest(base?.[member] ?? null);
    const b = canonicalDigest(candidate?.[member] ?? null);
    if (a !== b) {
      return { member, base_digest: a, candidate_digest: b, base_present: member in (base ?? {}), candidate_present: member in (candidate ?? {}) };
    }
  }
  return null;
}

export function parseArgs(argv) {
  const out = { principal: null, label: null, out: null, version: 'v2' };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    const take = () => {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) throw new Error(`${APPROVE_ERRORS.ARGS}:${token}`);
      i += 1;
      return value;
    };
    if (token === '--principal') out.principal = take();
    else if (token === '--label') out.label = take();
    else if (token === '--out') out.out = take();
    else if (token === '--version') out.version = take();
    else if (token === '--help' || token === '-h') out.help = true;
    else throw new Error(`${APPROVE_ERRORS.ARGS}:unknown-argument:${token}`);
  }
  return out;
}

/**
 * Issue the signed document. Refuses on a moved scientific member, on a draft
 * that already claims approval, and on anything it cannot read.
 */
export function approve({ draft, base, principal, label, issuedAt = null }) {
  if (typeof principal !== 'string' || principal.length === 0) throw new Error(`${APPROVE_ERRORS.ARGS}:--principal`);
  if (typeof label !== 'string' || label.length === 0) throw new Error(`${APPROVE_ERRORS.ARGS}:--label`);
  if (!isPlainObject(draft)) throw new Error(`${APPROVE_ERRORS.DRAFT_CORRUPT}`);
  if (!isPlainObject(base)) throw new Error(`${APPROVE_ERRORS.BASE_ABSENT}`);
  if (draft.approval?.status !== null && draft.approval?.status !== undefined) {
    // Signing a document that already claims to be signed is how a second,
    // different signature gets to coexist with the first one.
    throw new Error(`${APPROVE_ERRORS.ALREADY_SIGNED}:${String(draft.approval?.status)}`);
  }
  const drift = scopeDrift(base, draft);
  if (drift !== null) {
    throw new Error(`${APPROVE_ERRORS.SCOPE_DRIFT}:${drift.member}:${drift.base_digest.slice(0, 16)}!=${drift.candidate_digest.slice(0, 16)}`);
  }
  const body = {
    ...scientificBody(draft),
    status: 'APPROVED',
    approval: {
      status: 'APPROVED',
      authority: 'HUMAN_OWNER',
      principal_id: principal,
      label,
      // The wall clock decides nothing and is outside the digest, so re-running
      // this script does not produce a different document.
      issued_at: issuedAt,
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: false,
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v2 records this digest in the corpus manifest and carries a SUPERSESSION from xpr-s2-008c-01',
    },
  };
  return Object.freeze({ ...body, preregistration_digest: preregistrationDigest(body) });
}

export function approveV3({ draft, base, table, principal, label, issuedAt = null }) {
  if (typeof principal !== 'string' || principal.length === 0) throw new Error(`${APPROVE_ERRORS.ARGS}:--principal`);
  if (typeof label !== 'string' || label.length === 0) throw new Error(`${APPROVE_ERRORS.ARGS}:--label`);
  if (!isPlainObject(draft) || !isPlainObject(base) || !isPlainObject(table)) throw new Error('V3_DOCUMENT_ABSENT');
  if (draft.approval?.status !== null) throw new Error(`${APPROVE_ERRORS.ALREADY_SIGNED}:v3`);
  if (draft.rule !== 's2-008-prereg-v3' || draft.preregistration_id !== 'xpr-s2-008c-03') throw new Error('V3_VERSION_MISMATCH');
  const drift = scopeDrift(base, draft, FROZEN_MEMBERS.filter((member) => member !== 'trial_list' && member !== 'expected_table_digest'));
  if (drift !== null) throw new Error(`${APPROVE_ERRORS.SCOPE_DRIFT}:${drift.member}`);
  if (!Array.isArray(base.trial_list) || !Array.isArray(draft.trial_list) || draft.trial_list.length !== base.trial_list.length ||
      draft.trial_list[0]?.arm_id !== 'arm-model-zai-glm53flash') throw new Error('V3_SCOPE_DRIFT:trial_list');
  const expectedTrials = structuredClone(base.trial_list);
  expectedTrials[0].arm_id = draft.trial_list[0].arm_id;
  expectedTrials[0].predictor = draft.trial_list[0].predictor;
  if (canonicalDigest(expectedTrials) !== canonicalDigest(draft.trial_list)) throw new Error('V3_SCOPE_DRIFT:trial_list');
  if (!Array.isArray(draft.arms) || canonicalDigest(draft.arms.slice(1)) !== canonicalDigest(base.arms.slice(1)) ||
      draft.arms[0]?.arm_id !== draft.trial_list[0].arm_id) throw new Error('V3_SCOPE_DRIFT:arms');
  if (draft.expected_table_digest !== canonicalDigest(table) ||
      table.trial_list_digest !== canonicalDigest(draft.trial_list) ||
      table.budget_currency !== draft.budget_reservation.currency ||
      table.budget_ceiling !== draft.budget_reservation.granted_units ||
      table.supersession?.superseded_preregistration_digest !== base.preregistration_digest) {
    throw new Error('V3_SCOPE_DRIFT:expected_table_digest');
  }
  const body = {
    ...scientificBody(draft),
    status: 'APPROVED',
    approval: {
      status: 'APPROVED',
      authority: 'HUMAN_OWNER',
      principal_id: principal,
      label,
      issued_at: issuedAt,
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: false,
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v3 records this digest in the corpus manifest and carries a SUPERSESSION from xpr-s2-008c-01',
    },
  };
  return Object.freeze({ ...body, preregistration_digest: preregistrationDigest(body) });
}



export function assertV4Pin(draft, pin) {
  if (pin?.schema !== 's2-008-model-image-pin/4' || pin.identical !== true ||
      pin.context_digest_stable !== true || pin.content_commitment_stable !== true ||
      pin.commitment_excludes_preregistration !== true ||
      !isPlainObject(pin.first) || !isPlainObject(pin.second) ||
      !isPlainObject(pin.first.sources) || !isPlainObject(pin.second.sources)) {
    throw new Error('V4_PIN_NOT_USABLE');
  }
  const covers = Object.keys(pin.first.sources).filter((name) => name !== 'prereg').sort();
  const commitment = canonicalDigest(Object.fromEntries(covers.map((name) => [name, pin.first.sources[name]])));
  if (pin.first.content_commitment !== commitment ||
      pin.second.content_commitment !== commitment ||
      pin.first.source_digest !== canonicalDigest(pin.first.sources) ||
      pin.second.source_digest !== canonicalDigest(pin.second.sources) ||
      pin.first.source_digest !== pin.second.source_digest ||
      pin.first.imageId !== pin.second.imageId || pin.first.digest !== pin.second.digest ||
      canonicalDigest(pin.first.content_commitment_covers) !== canonicalDigest(covers) ||
      canonicalDigest(pin.second.content_commitment_covers) !== canonicalDigest(covers) ||
      canonicalDigest(pin.commitment?.covers) !== canonicalDigest(covers) ||
      canonicalDigest(pin.commitment?.excludes) !== canonicalDigest(['prereg']) ||
      pin.commitment?.field !== 'executor.model_image.content_commitment' ||
      draft.executor?.model_image?.content_commitment !== commitment ||
      canonicalDigest(draft.executor.model_image.covers) !== canonicalDigest(covers) ||
      canonicalDigest(draft.executor.model_image.excludes) !== canonicalDigest(['prereg']) ||
      draft.executor.model_image.built_image_pin !== 'evidence/s2-008-campaign/model-image-pin-v4.json') {
    throw new Error('V4_PIN_MISMATCH');
  }
  return commitment;
}

export function approveV4({ draft, base, table, principal, label, issuedAt = null, pin }) {
  if (typeof principal !== 'string' || principal.length === 0) throw new Error(`${APPROVE_ERRORS.ARGS}:--principal`);
  if (typeof label !== 'string' || label.length === 0) throw new Error(`${APPROVE_ERRORS.ARGS}:--label`);
  if (!isPlainObject(draft) || !isPlainObject(base) || !isPlainObject(table)) throw new Error('V4_DOCUMENT_ABSENT');
  if (draft.approval?.status !== null) throw new Error(`${APPROVE_ERRORS.ALREADY_SIGNED}:v4`);
  if (draft.rule !== 's2-008-prereg-v4' || draft.preregistration_id !== 'xpr-s2-008c-04' ||
      base.rule !== 's2-008-prereg-v3' || base.preregistration_id !== 'xpr-s2-008c-03') throw new Error('V4_VERSION_MISMATCH');
  if (base.preregistration_digest !== preregistrationDigest(base)) throw new Error('V4_BASE_MISMATCH');
  assertV4Pin(draft, pin);
  const drift = scopeDrift(base, draft);
  if (drift !== null) throw new Error(`${APPROVE_ERRORS.SCOPE_DRIFT}:${drift.member}`);
  if (draft.expected_table_digest !== canonicalDigest(table) ||
      draft.expected_table_digest !== base.expected_table_digest) throw new Error('V4_TABLE_MISMATCH');
  const expectedSupersessionKeys = ['supersedes', 'superseded_digest', 'reason', 'unchanged'];
  if (!isPlainObject(draft.supersession) ||
      canonicalDigest(Object.keys(draft.supersession).sort()) !== canonicalDigest(expectedSupersessionKeys.sort()) ||
      canonicalDigest(Array.isArray(draft.supersession.unchanged) ? [...draft.supersession.unchanged].sort() : null) !== canonicalDigest([...FROZEN_MEMBERS].sort()) ||
      typeof draft.supersession.reason !== 'string' || draft.supersession.reason.trim() !== draft.supersession.reason ||
      draft.supersession.reason.length === 0 || draft.supersession.reason.length > 500 ||
      /[\r\n]/.test(draft.supersession.reason)) throw new Error('V4_SUPERSESSION_SCOPE_MISMATCH');
  if (draft.supersession.supersedes !== base.preregistration_id ||
      draft.supersession.superseded_digest !== base.preregistration_digest) throw new Error('V4_BASE_MISMATCH:supersession');
  const beforeExecutor = structuredClone(base.executor ?? {});
  const afterExecutor = structuredClone(draft.executor ?? {});
  delete beforeExecutor.model_image;
  delete afterExecutor.model_image;
  if (canonicalDigest(beforeExecutor) !== canonicalDigest(afterExecutor) ||
      canonicalDigest(base.executor?.model_image ?? null) === canonicalDigest(draft.executor?.model_image ?? null)) {
    throw new Error('V4_SCOPE_DRIFT:executor');
  }
  const beforeBudget = structuredClone(base.budget_reservation ?? {});
  const afterBudget = structuredClone(draft.budget_reservation ?? {});
  delete beforeBudget.enumerated_work;
  delete afterBudget.enumerated_work;
  if (canonicalDigest(beforeBudget) !== canonicalDigest(afterBudget)) throw new Error('V4_SCOPE_DRIFT:budget_reservation');
  const allowed = new Set(['rule', 'preregistration_id', 'executor', 'budget_reservation', 'supersession', 'status', 'approval', 'preregistration_digest']);
  for (const member of new Set([...Object.keys(base), ...Object.keys(draft)])) {
    if (!allowed.has(member) && canonicalDigest(base[member] ?? null) !== canonicalDigest(draft[member] ?? null)) {
      throw new Error(`V4_SCOPE_DRIFT:${member}`);
    }
  }
  const body = {
    ...scientificBody(draft),
    status: 'APPROVED',
    approval: {
      status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: principal, label,
      issued_at: issuedAt,
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: false,
      becomes_in_force_when: 'scripts/s2-008-campaign-prepare.mjs --seal-v4 records this digest in the corpus manifest and carries a content-only SUPERSESSION from xpr-s2-008c-03',
    },
  };
  return Object.freeze({ ...body, preregistration_digest: preregistrationDigest(body) });
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const CORPUS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../corpus/s2-008-campaign');
const DRAFT = path.join(CORPUS_DIR, 'preregistration.v2.draft.json');
// The IN-FORCE v1, not preregistration-superseded.json: that file is the document the
// PREVIOUS supersession replaced, and its digest differs. v2 supersedes what is in force.
const BASE = path.join(CORPUS_DIR, 'preregistration.json');
const OUT = path.join(CORPUS_DIR, 'preregistration.v2.approved.json');
const V3_DRAFT = path.join(CORPUS_DIR, 'preregistration.v3.draft.json');
const V3_TABLE = path.join(CORPUS_DIR, 'frozen-table.v3.json');
const V3_OUT = path.join(CORPUS_DIR, 'preregistration.v3.approved.json');
const V4_DRAFT = path.join(CORPUS_DIR, 'preregistration.v4.draft.json');
const V4_OUT = path.join(CORPUS_DIR, 'preregistration.v4.approved.json');
const V4_BASE = path.join(CORPUS_DIR, 'preregistration.v3.in-force.json');
const V4_PIN = path.resolve(CORPUS_DIR, '../../evidence/s2-008-campaign/model-image-pin-v4.json');

const USAGE = `s2-008-campaign-approve — the owner's signature on a campaign preregistration

  --version v2|v3|v4|v8|v9  document to sign (default v2)
  --principal <id>     the owner's principal id, recorded like every permit here
  --label "<text>"     who is signing, in words
  --out <path>         where to write the signed document

Refuses to issue anything if a frozen scientific member moved against
xpr-s2-008c-01: the card, the metric, the frozen baseline, the noise band, the
seeds, the multiplicity rule, the stopping rule, the holdout access, the inference
mode, the trial list and the frozen table digest. A supersession may change the
predictor, the currency and the spend; it may not change the experiment.

Issuing does not put the document in force. That is --seal-v2's job, and until it
runs the campaign runs v1.
`;

async function main() {
  const argv = process.argv.slice(2);
  const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
  if (!isMain) return null;
  let args;
  try {
    args = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${String(error.message)}\n\n${USAGE}`);
    process.exitCode = 2;
    return null;
  }
  if (args.help || argv.length === 0) {
    process.stdout.write(USAGE);
    process.exitCode = args.help ? 0 : 2;
    return null;
  }
  try {
    if (args.version === 'v9') {
      const { approveV9, readV9MeasurementOnDisk, readV9ReconciliationInputs } = await import('./s2-008-campaign-v9-approval.mjs');
      const baseBytes = readFileSync(path.join(CORPUS_DIR, 'preregistration.v8.in-force.json'));
      const signed = approveV9({
        draft: JSON.parse(readFileSync(path.join(CORPUS_DIR, 'preregistration.v9.draft.json'), 'utf8')),
        base: JSON.parse(baseBytes), baseBytes,
        table: JSON.parse(readFileSync(V3_TABLE, 'utf8')),
        pin: JSON.parse(readFileSync(path.resolve(CORPUS_DIR, '../../evidence/s2-008-campaign/model-image-pin-v9-preseal.json'), 'utf8')),
        measurement: readV9MeasurementOnDisk(), ...readV9ReconciliationInputs(),
        principal: args.principal, label: args.label, issuedAt: new Date().toISOString(),
      });
      const out = args.out ?? path.join(CORPUS_DIR, 'preregistration.v9.approved.json');
      writeFileSync(out, JSON.stringify(signed, null, 2) + String.fromCharCode(10), { flag: 'wx', mode: 0o644 });
      process.stdout.write(JSON.stringify({written:out,preregistration_id:signed.preregistration_id,
        preregistration_digest:signed.preregistration_digest,approved_by:signed.approval.principal_id,in_force:false}) + String.fromCharCode(10));
      return signed;
    }
    if (args.version === 'v8') {
      const { approveV8, readV8MeasurementOnDisk } = await import('./s2-008-campaign-v8-approval.mjs');
      const baseBytes = readFileSync(path.join(CORPUS_DIR, 'preregistration.v7.in-force.json'));
      const signed = approveV8({
        draft: JSON.parse(readFileSync(path.join(CORPUS_DIR, 'preregistration.v8.draft.json'), 'utf8')),
        base: JSON.parse(baseBytes), baseBytes,
        table: JSON.parse(readFileSync(V3_TABLE, 'utf8')),
        pin: JSON.parse(readFileSync(path.resolve(CORPUS_DIR, '../../evidence/s2-008-campaign/model-image-pin-v8-preseal.json'), 'utf8')),
        measurement: readV8MeasurementOnDisk(),
        principal: args.principal, label: args.label, issuedAt: new Date().toISOString(),
      });
      const out = args.out ?? path.join(CORPUS_DIR, 'preregistration.v8.approved.json');
      writeFileSync(out, JSON.stringify(signed, null, 2) + String.fromCharCode(10), { flag: 'wx', mode: 0o644 });
      process.stdout.write(JSON.stringify({written:out,preregistration_id:signed.preregistration_id,
        preregistration_digest:signed.preregistration_digest,approved_by:signed.approval.principal_id,in_force:false}) + String.fromCharCode(10));
      return signed;
    }
    if (!['v2', 'v3', 'v4'].includes(args.version)) throw new Error('APPROVAL_VERSION_UNKNOWN');
    const draftPath = args.version === 'v4' ? V4_DRAFT : args.version === 'v3' ? V3_DRAFT : DRAFT;
    if (!existsSync(draftPath)) throw new Error(`${APPROVE_ERRORS.DRAFT_ABSENT}:${draftPath}`);
    const basePath = args.version === 'v4' ? V4_BASE : BASE;
    if (!existsSync(basePath)) throw new Error(`${APPROVE_ERRORS.BASE_ABSENT}:${basePath}`);
    const draft = JSON.parse(readFileSync(draftPath, 'utf8'));
    const base = JSON.parse(readFileSync(basePath, 'utf8'));
    const signed = (args.version === 'v4' ? approveV4 : args.version === 'v3' ? approveV3 : approve)({
      draft,
      base,
      ...(args.version === 'v3' || args.version === 'v4' ? { table: JSON.parse(readFileSync(V3_TABLE, 'utf8')) } : {}),
      ...(args.version === 'v4' ? { pin: JSON.parse(readFileSync(V4_PIN, 'utf8')) } : {}),
      principal: args.principal,
      label: args.label,
      issuedAt: new Date().toISOString(),
    });
    const out = args.out ?? (args.version === 'v4' ? V4_OUT : args.version === 'v3' ? V3_OUT : OUT);
    writeFileSync(out, `${JSON.stringify(signed, null, 2)}\n`, 'utf8');
    process.stdout.write(`${JSON.stringify({
      written: out,
      preregistration_id: signed.preregistration_id,
      status: signed.status,
      preregistration_digest: signed.preregistration_digest,
      approved_by: `${signed.approval.principal_id} (${signed.approval.authority})`,
      in_force: signed.approval.in_force,
      next: `node scripts/s2-008-campaign-prepare.mjs --seal-${args.version}`,
    }, null, 2)}\n`);
    process.exitCode = 0;
    return signed;
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      status: 'REFUSED',
      ok: false,
      code: String(error?.message ?? 'APPROVAL_FAILED').split(':')[0],
      detail: String(error?.message ?? error).slice(0, 400),
    }, null, 2)}\n`);
    process.exitCode = 3;
    return null;
  }
}

main();
