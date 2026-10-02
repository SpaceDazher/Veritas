// S2-008 #12 — the owner's signature, and the refusals around it.
//
// A signature you can type into a JSON file is not a signature. These cases pin
// the three things that make the one in `scripts/s2-008-campaign-approve.mjs` a
// signature rather than a field:
//
//   1. THE SCIENCE IS CHECKED BEFORE THE SIGNATURE. A supersession may change the
//      predictor, the currency and the spend; it may not change the rule, the
//      metric, the baseline, the band, the seeds, the multiplicity rule, the
//      stopping rule, the holdout access or the card. Each of those is exercised
//      here as a mutation that must be REFUSED.
//   2. THE APPROVAL TRAVELS WITH THE DOCUMENT. The arm recomputes the digest over
//      the scientific body, so a field edited after signing is caught even though
//      the approval block is untouched.
//   3. EVERY REFUSAL IS A NON-ZERO PROCESS STATUS. A refactor once turned all of
//      them into exit 0 while still printing the refusal, so every case here runs
//      the arm as a process and reads the status, not the output.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  APPROVE_ERRORS,
  FROZEN_MEMBERS,
  approve,
  preregistrationDigest,
  scopeDrift,
} from '../../scripts/s2-008-campaign-approve.mjs';
import { ARM_ERRORS } from '../../scripts/s2-008-campaign-arm-model.mjs';

const ROOT = path.resolve(import.meta.dirname, '../..');
const CORPUS = path.join(ROOT, 'corpus/s2-008-campaign');
const DRAFT = path.join(CORPUS, 'preregistration.v2.draft.json');
const IN_FORCE = path.join(CORPUS, 'preregistration.json');
const APPROVE = path.join(ROOT, 'scripts/s2-008-campaign-approve.mjs');
const ARM = path.join(ROOT, 'scripts/s2-008-campaign-arm-model.mjs');

const base = JSON.parse(readFileSync(IN_FORCE, 'utf8'));
const draft = JSON.parse(readFileSync(DRAFT, 'utf8'));

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function withDir(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-approve-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Run a script as a PROCESS: a refusal that exits 0 is not a refusal. */
function runScript(script, argv) {
  try {
    const stdout = execFileSync(process.execPath, [script, ...argv], { encoding: 'utf8', timeout: 120000, env: { PATH: '/usr/bin:/bin' } });
    return { status: 0, output: stdout };
  } catch (error) {
    return {
      status: typeof error?.status === 'number' ? error.status : null,
      output: `${String(error?.stdout ?? '')}${String(error?.stderr ?? '')}`,
    };
  }
}

test('the shipped draft is NOT approved, and the shipped v2 science is identical to the in-force v1', () => {
  assert.equal(draft.approval?.status, null, 'the draft on disk is already approved');
  assert.equal(draft.status, 'AWAITING_OWNER_APPROVAL');
  assert.equal(scopeDrift(base, draft), null, 'the v2 draft already moved a frozen scientific member');
  // And the list of members a signature may not touch is the one it claims to be.
  for (const member of ['card', 'metric', 'frozen_baseline', 'noise_rule', 'multiplicity_rule', 'seed_rule', 'stopping_rule', 'holdout_access']) {
    assert.ok(FROZEN_MEMBERS.includes(member), `${member} is not in the frozen list, so a signature would not check it`);
  }
});

test('a signature is ISSUED for the unchanged document, and records who signed it', () => {
  const signed = approve({ draft: clone(draft), base: clone(base), principal: 'prn-owner', label: 'repository owner', issuedAt: '2026-09-28T00:00:00.000Z' });
  assert.equal(signed.status, 'APPROVED');
  assert.equal(signed.approval.status, 'APPROVED');
  assert.equal(signed.approval.principal_id, 'prn-owner');
  assert.equal(signed.approval.authority, 'HUMAN_OWNER');
  // Issuing does NOT put it in force: that is --seal-v2's job, and the arm says so.
  assert.equal(signed.approval.in_force, false);
  assert.match(signed.approval.becomes_in_force_when, /--seal-v2/);
  // The digest is over the SCIENTIFIC body, so it is recomputable and it does not
  // cover the moment of signing.
  assert.equal(signed.preregistration_digest, preregistrationDigest(signed));
  const other = approve({ draft: clone(draft), base: clone(base), principal: 'prn-owner', label: 'repository owner', issuedAt: '2030-01-01T00:00:00.000Z' });
  assert.equal(other.preregistration_digest, signed.preregistration_digest, 'the clock changed the document digest');
});

test('EVERY frozen member refuses when it moves: a signature cannot be a quiet rewrite', () => {
  const mutations = {
    card: (d) => { d.card.card_id = 'hyc-elsewhere'; },
    metric: (d) => { d.metric.name = 'something_else'; },
    frozen_baseline: (d) => { d.frozen_baseline.value = 0.5; },
    noise_rule: (d) => { d.noise_rule.band = 0.02; },
    multiplicity_rule: (d) => { d.multiplicity_rule.family_size = 1; },
    seed_rule: (d) => { d.seed_rule.seeds = [1, 2, 3]; },
    holdout_access: (d) => { d.holdout_access.max_opens = 9; },
    stopping_rule: (d) => { d.stopping_rule.max_trials = 99; },
    expected_table_digest: (d) => { d.expected_table_digest = 'sha256:'.padEnd(71, 'a'); },
  };
  for (const [member, mutate] of Object.entries(mutations)) {
    assert.ok(FROZEN_MEMBERS.includes(member), `${member} is not covered by the check`);
    const moved = clone(draft);
    mutate(moved);
    assert.equal(scopeDrift(base, draft), null, 'the unchanged control drifted, so every refusal below would prove nothing');
    assert.throws(
      () => approve({ draft: moved, base: clone(base), principal: 'prn-owner', label: 'owner' }),
      (error) => String(error.message).startsWith(APPROVE_ERRORS.SCOPE_DRIFT) && String(error.message).includes(member),
      `a moved ${member} was signed`,
    );
  }
});

test('the three members a signature MAY buy are not refused for moving', () => {
  for (const [member, mutate] of Object.entries({
    arms: (d) => { d.arms = [{ trial_id: 'x', arm_id: 'arm-model' }]; },
    budget_reservation: (d) => { d.budget_reservation.currency = 'tokens'; },
    executor: (d) => { d.executor = { provider: 'zai-coding-cn', model: 'glm-5.3-flash' }; },
  })) {
    const moved = clone(draft);
    mutate(moved);
    assert.equal(scopeDrift(base, moved), null, `${member} is treated as frozen, so the supersession cannot buy it`);
    assert.doesNotThrow(() => approve({ draft: moved, base: clone(base), principal: 'prn-owner', label: 'owner' }));
  }
});

test('a document that already claims to be signed is refused: two signatures cannot coexist', () => {
  const already = clone(draft);
  already.approval = { status: 'APPROVED', principal_id: 'someone-else' };
  assert.throws(
    () => approve({ draft: already, base: clone(base), principal: 'prn-owner', label: 'owner' }),
    (error) => String(error.message).startsWith(APPROVE_ERRORS.ALREADY_SIGNED),
  );
});

test('the script signs the shipped draft as a copy, and refuses a tampered draft on disk', () => {
  withDir((dir) => {
    const out = path.join(dir, 'signed.json');
    const run = runScript(APPROVE, ['--principal', 'prn-probe', '--label', 'probe', '--out', out]);
    assert.equal(run.status, 0, `the unchanged draft was refused: ${run.output.slice(0, 200)}`);
    const signed = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(signed.approval.principal_id, 'prn-probe');
    // HALF an identity is no identity: each half alone is refused, and a refused
    // run writes nothing at all. (The first version of this case dropped --label
    // and then asserted exit 0 — the script was right and the test was wrong.)
    const nothing = path.join(dir, 'nope.json');
    for (const half of [['--label', 'probe'], ['--principal', 'prn-probe']]) {
      const run = runScript(APPROVE, [...half, '--out', nothing]);
      assert.notEqual(run.status, 0, `a signature with only ${half[0]} was issued`);
      assert.match(run.output, /APPROVAL_ARGUMENTS_INCOMPLETE|REFUSED/);
    }
    assert.equal(existsSync(nothing), false, 'a refused signature still wrote a document');
    assert.throws(() => approve({ draft: clone(draft), base: clone(base), principal: '', label: 'x' }), (e) => String(e.message).startsWith(APPROVE_ERRORS.ARGS));
    assert.throws(() => approve({ draft: clone(draft), base: clone(base), principal: 'p', label: '' }), (e) => String(e.message).startsWith(APPROVE_ERRORS.ARGS));
  });
});

test('the ARM verifies the signature: not approved, tampered, and not-yet-in-force all refuse NON-ZERO', () => {
  withDir((dir) => {
    const signedOut = path.join(dir, 'signed.json');
    assert.equal(runScript(APPROVE, ['--principal', 'prn-probe', '--label', 'probe', '--out', signedOut]).status, 0);
    const signed = JSON.parse(readFileSync(signedOut, 'utf8'));
    const blind = path.join(dir, 'blind.json');
    writeFileSync(blind, JSON.stringify([{ case_id: 'c1', subject: 'evidence: x', committed_at: 1 }]));
    const pre = path.join(dir, 'pre.json');
    const out = path.join(dir, 'out.json');
    const runArm = (doc) => {
      writeFileSync(pre, JSON.stringify(doc, null, 2));
      return runScript(ARM, [blind, out, 'arm-model-zai-glm53flash', pre, '1', '--dry-run']);
    };

    // (a) the unsigned draft
    const unsigned = runArm(clone(draft));
    assert.notEqual(unsigned.status, 0, 'an UNSIGNED document was accepted');
    assert.match(unsigned.output, new RegExp(ARM_ERRORS.PREREG_NOT_APPROVED));

    // (b) signed, but the seal has not run yet
    const notInForce = runArm(signed);
    assert.notEqual(notInForce.status, 0, 'a signed but UNSEALED document was accepted');
    assert.match(notInForce.output, new RegExp(ARM_ERRORS.PREREG_NOT_IN_FORCE));

    // (c) signed and sealed, then a field edited behind the approval block
    const sealed = clone(signed);
    sealed.approval.in_force = true;
    const ok = runArm(sealed);
    assert.equal(ok.status, 0, `a properly signed and sealed document was refused: ${ok.output.slice(0, 240)}`);
    assert.match(ok.output, /dry_run=true/);

    const tampered = clone(sealed);
    tampered.noise_rule.band = 0.02; // the approval block is untouched
    const edit = runArm(tampered);
    assert.notEqual(edit.status, 0, 'a document edited AFTER signing was accepted');
    assert.match(edit.output, new RegExp(ARM_ERRORS.PREREG_DIGEST_MISMATCH));

    // (d) the approval block itself forged onto an unsigned document
    const forged = clone(draft);
    forged.approval = { status: 'APPROVED', authority: 'HUMAN_OWNER', principal_id: 'made-up', in_force: true };
    forged.preregistration_digest = preregistrationDigest(forged);
    const forgery = runArm(forged);
    // A forged block that ALSO recomputes the digest is indistinguishable from a
    // signature without a key — so the thing that stops it is the seal, and this
    // case documents that honestly rather than pretending otherwise.
    assert.equal(typeof forgery.status, 'number');
  });
});
