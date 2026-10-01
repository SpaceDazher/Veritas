#!/usr/bin/env node
// S2-008 раздел D, продолжающий — the v8 DRAFT: the executor moves to the same
// model this session uses. Science byte-for-byte as v7; one new member.
//
// The measurement that justifies the move is a single host-side call, and two
// limits of it are carried INTO the document rather than left in a report:
//
//   * tools were ON in the measurement and OFF in the container, so the container
//     figure is expected to be lower. The plan is therefore recorded as a
//     PROJECTION with its basis, not as a measured budget;
//   * pi reports `cost.total = 0` for this provider. That is what the client
//     says, not a price. The confirmed USD cost is `null` / NOT_VERIFIED, because
//     MISSING IS NOT ZERO and USD is a unit like any other.
//
// The ceiling is NOT moved. 378 x 11 139 = 4 210 542 against 5 000 000 still fits,
// and a ceiling nobody re-examined is not re-issued. If the container measurement
// comes in above that, the ceiling becomes an amendment taken BEFORE the run, not
// an edit after it.
//
// UNSIGNED. `approval.status` stays null and the generator refuses to emit
// anything else: filling that field in on the owner's behalf is the one act in
// this document no agent may perform.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { preregistrationDigest, scopeDrift, FROZEN_MEMBERS } from './s2-008-campaign-approve.mjs';
import { V8_CREDENTIAL_ENV_NAME, V8_EXECUTOR_POLICY, V7_PI_SETTINGS } from './s2-008-campaign-credential-env.mjs';
import { MODEL_EGRESS_TARGETS } from '../src/lib/isolation/profile.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const V7 = path.join(ROOT, 'corpus/s2-008-campaign/preregistration.v7.in-force.json');
const TRACE = path.join(ROOT, 'Stage 2/.bb/chats/thr_hj2st7xwcz/artifacts/pi-measurement-space-bunny-alpha.jsonl');
const OUT = path.join(ROOT, 'corpus/s2-008-campaign/preregistration.v8.draft.json');

const base = JSON.parse(fs.readFileSync(V7, 'utf8'));

// The token figure is READ from the measured trace, not typed. A draft whose
// number could be edited without touching the evidence is a draft that will be.
let usage = null;
for (const raw of fs.readFileSync(TRACE, 'utf8').split('\n')) {
  const trimmed = raw.trim();
  if (!trimmed.startsWith('{')) continue;
  let event;
  try { event = JSON.parse(trimmed); } catch { continue; }
  if (event.type !== 'agent_end' || !Array.isArray(event.messages)) continue;
  for (const message of event.messages) {
    const u = message?.usage;
    if (message?.role === 'assistant' && typeof u?.totalTokens === 'number' && (usage === null || u.totalTokens > usage.totalTokens)) usage = u;
  }
}
if (usage === null) {
  process.stderr.write('V8_MEASUREMENT_ABSENT:no assistant usage in the recorded trace\n');
  process.exit(1);
}

const cases = 126;
const seeds = 3;
const calls = cases * seeds;
const projected = calls * usage.totalTokens;
const ceiling = Number(base.budget_reservation.granted_units);

const draft = {
  ...base,
  rule: 's2-008-prereg-v8',
  preregistration_id: 'xpr-s2-008c-08',
  executor: {
    ...base.executor,
    ...V8_EXECUTOR_POLICY,
    package: '@earendil-works/pi-coding-agent',
    credential_delivery: 'podman --env-file — a path on the host argv; neither the value nor the variable name is in any argv',
    inside_isolation: `LOCAL_RESTRICTED, digest-pinned, egress allowlist ${MODEL_EGRESS_TARGETS.openrouter[0].host}:443 only`,
    pi_settings: V7_PI_SETTINGS,
    determinism: false,
    determinism_note: 'a model is not a function of its input. The arm records the digest of every raw answer so a repeat can be COMPARED against the committed one. No claim is made that the model is reproducible; the run statement is about the frozen inputs and the recorded outputs.',
    unparseable_policy: 'an answer that is not exactly one of MAJOR/MINOR is UNPARSED and counts as a disagreement, never as a guess',
  },
  budget_reservation: {
    ...base.budget_reservation,
    // Same reservation id family, same ceiling, same currency. Nothing moved.
    reservation_id: 'rsv-s2-008c-08',
    usd_reference: {
      confirmed_usd: null,
      confirmed_usd_status: 'NOT_VERIFIED',
      why_null: 'the executor client reports cost.total = 0 for this provider. That is what the client reports, not a price, and a 0 carried into a signed document would read as "free".',
      measured_input_tokens: usage.input,
      measured_output_tokens: usage.output,
      measured_cache_read_tokens: usage.cacheRead ?? 0,
      measured_total_tokens_per_call: usage.totalTokens,
      measured_answer: 'MINOR',
      measurement_basis: 'one host-side call with tools ENABLED; the container runs with tools OFF, so the container figure is expected to be LOWER',
      measurement_trace: 'Stage 2/.bb/chats/thr_hj2st7xwcz/artifacts/pi-measurement-space-bunny-alpha.jsonl',
      measurement_trace_sha256: '0946e3ffbc079bfda2e7de12a46dae82bc4175426728961322317ef507dd49df',
      measured_answer_correctness: 'NOT_CHECKED — the answer was parsed, its agreement with the sealed holdout was not opened',
      projection: {
        calls,
        cases_per_seed: cases,
        seeds,
        tokens_per_call: usage.totalTokens,
        tokens_estimate: projected,
        status: 'PROJECTION_NOT_MEASUREMENT',
        caveat: 'recompute from a container measurement (tools OFF) before any run relies on it; a lower container figure gives more headroom, a higher one makes this ceiling an amendment to be taken BEFORE the run',
      },
      ceiling_unchanged: true,
      ceiling_note: `${projected} projected against ${ceiling}; headroom ${ceiling - projected} tokens. The ceiling is not re-issued by a document that did not re-examine it.`,
    },
    enumerated_work: `1 model trial x ${seeds} frozen seeds = ${seeds} model runs x ${cases} holdout cases = ${calls} case calls; 2 regex control trials make no model calls`,
  },
  supersession: {
    supersedes: 'xpr-s2-008c-04',
    superseded_digest: base.preregistration_digest,
    reason: 'the executor provider and model change; the question, card, metric, baseline, band, seeds, family, stopping, holdout access, trial list and ceiling do not. The egress allowlist follows the provider, so the reachable host changes from open.bigmodel.cn:443 to openrouter.ai:443 and nothing else is admitted.',
    unchanged: ['metric', 'frozen_baseline', 'noise_rule', 'multiplicity_rule', 'seed_rule', 'seeds_digest', 'seed_count', 'stopping_rule', 'sequential_rule', 'holdout_access', 'card', 'trial_list', 'expected_table_digest', 'bootstrap_process', 'inference_mode', 'budget_reservation'],
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

const drift = scopeDrift(base, draft);
if (drift !== null) {
  process.stderr.write(`V8_SCOPE_DRIFT:${drift.member}\n`);
  process.exit(1);
}
if (draft.approval.status !== null) {
  process.stderr.write('V8_DRAFT_WOULD_CLAIM_APPROVAL\n');
  process.exit(1);
}
if (draft.budget_reservation.granted_units !== base.budget_reservation.granted_units) {
  process.stderr.write('V8_CEILING_MOVED:the ceiling is not re-issued by this document\n');
  process.exit(1);
}
if (projected > ceiling) {
  process.stderr.write(`V8_PROJECTION_EXCEEDS_CEILING:${projected}>${ceiling}\n`);
  process.exit(1);
}

fs.writeFileSync(OUT, `${JSON.stringify(draft, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({
  written: path.relative(ROOT, OUT),
  preregistration_id: draft.preregistration_id,
  preregistration_digest: draft.preregistration_digest,
  executor: { provider: draft.executor.provider, model: draft.executor.model, credential_env_name: draft.executor.credential_env_name },
  egress_host: MODEL_EGRESS_TARGETS.openrouter[0].host,
  measured_tokens_per_call: usage.totalTokens,
  projected_tokens: projected,
  ceiling,
  confirmed_usd: draft.budget_reservation.usd_reference.confirmed_usd,
  frozen_members_checked: FROZEN_MEMBERS.length,
  scope_drift: drift,
  approval_status: draft.approval.status,
}, null, 2)}\n`);
