// S2-008 #12 — the paid arm's plumbing, proved for ZERO tokens.
//
// A model call cannot be verified offline, but everything AROUND it can: the
// blindness guard, the budget stop, the unparseable handling, the output
// contract, the provenance, the credential order and the claim that a per-message
// usage is not a run total. Those are the parts that go wrong SILENTLY, so they
// are what this file pins. `--dry-run` exercises the entire path with a scripted
// stand-in and emits the same record shape with `dry_run: true`, so the plumbing
// is verifiable at zero cost.
//
// A dry run is NOT a measurement: its record says so in `dry_run` and in a
// distinct `outcome_class`, and the stdout line discloses it. It is the receipt
// for the plumbing, not a result.
//
// The exit code is observed as a process status, never read out of the output: a
// budget stop has to be a non-zero exit, and a test that inferred it from a
// string the script never prints would pass without proving anything.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import {
  APPROVED,
  ARM_ERRORS,
  LABEL_SET,
  UNPARSED,
  buildPrompt,
  callModel,
  classifyOutcome,
  extractUsage,
  main,
  parseLabel,
  readCredential,
} from '../../scripts/s2-008-campaign-arm-model.mjs';

const CANARY = 'zai-arm-canary-2f9c7b1d4e6a03c8-not-a-real-key';
const ENV_NAME = 'ZAI_API_KEY';
const ARM_ID = 'arm-model-zai-glm53flash';
const SCRIPT = path.resolve(import.meta.dirname, '../../scripts/s2-008-campaign-arm-model.mjs');

/** async because the arm's `main` is async, and the cases await it. */
async function withDir(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-arm-'));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * A preregistration that would actually be in force: approved AND sealed, with a
 * digest the arm's own recomputation matches. The previous fixture carried
 * `approval.status` alone, which stopped being enough when the arm began
 * recomputing the signed digest — a fixture that cannot pass the real gate proves
 * nothing about the arm.
 */
function prereg(overrides = {}) {
  const body = {
    budget_reservation: { currency: 'tokens', granted_units: 100_000_000, trial_timeout_ms: 120000 },
    executor: { provider: 'zai-coding-cn', model: 'glm-5.3-flash', credential_env_name: ENV_NAME },
    status: 'APPROVED',
    approval: {
      status: APPROVED,
      authority: 'HUMAN_OWNER',
      principal_id: 'prn-fixture',
      label: 'fixture',
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: true,
    },
    ...overrides,
  };
  return { ...body, preregistration_digest: preregistrationDigest(body) };
}

function blindInput(n = 4) {
  return Array.from({ length: n }, (_, i) => ({
    case_id: `case-${String(i).padStart(3, '0')}`,
    subject: `evidence: reseal manifest ${i}`,
    committed_at: 1790421856,
  }));
}

test('the label set is closed: an answer must BE a label, not contain one', () => {
  assert.deepEqual([...LABEL_SET], ['MAJOR', 'MINOR']);
  assert.equal(parseLabel('MAJOR'), 'MAJOR');
  assert.equal(parseLabel('minor'), 'MINOR');
  assert.equal(parseLabel('  MAJOR.  '), 'MAJOR', 'surrounding whitespace and a full stop are not a refusal');

  // The first parser took the first label-shaped token anywhere, and these would
  // all have scored MAJOR — a hedging or refusing answer silently becoming a
  // prediction, which is the one thing this arm must never do. A hyphen and a
  // negation are word boundaries, so `\b` does not save it.
  for (const text of [
    '', 'I cannot help with that', 'maybe major-ish', 'not major', 'neither',
    'MAJORS', 'MAJOR (probably)', 'is it major?',
    'The answer is MAJOR, nothing else', 'I think this one is MINOR actually',
    null, undefined, 0, false,
  ]) {
    assert.equal(parseLabel(text), UNPARSED, `${JSON.stringify(text)} was turned into a label`);
  }

  // The prompt carries the subject and the closed set, and never the sealed word.
  const prompt = buildPrompt('fix: typo in README');
  assert.ok(prompt.includes('MAJOR') && prompt.includes('MINOR'));
  assert.ok(prompt.includes('fix: typo in README'));
  assert.ok(!/label/i.test(prompt), 'the prompt itself must not use the word the data seals');
});

test("pi usage is read from turn_end/agent_end, and a per-message report is NOT a run total", () => {
  const stdout = [
    JSON.stringify({ type: 'session', id: 'x' }),
    // A mid-stream update: zeros. Counting these would report a spent budget of
    // 0 and the reservation would govern nothing.
    JSON.stringify({ type: 'message_update', usage: { input: 0, output: 0, totalTokens: 0, cost: { total: 0 } } }),
    JSON.stringify({ type: 'message_end', message: { role: 'assistant', content: 'MINOR' }, usage: { input: 9058, output: 23, totalTokens: 10233, cost: { total: 0.00140476 } } }),
    JSON.stringify({ type: 'turn_end', usage: { input: 9058, output: 23, totalTokens: 10233, cost: { total: 0.00140476 } } }),
  ].join('\n');
  const usage = extractUsage(stdout);
  assert.equal(usage.totalTokens, 10233, 'the real total was not read');
  assert.equal(usage.cost.total, 0.00140476);

  const zeros = JSON.stringify({ type: 'turn_end', usage: { totalTokens: 0 } });
  assert.equal(extractUsage(`${zeros}\n${zeros}\n`)?.totalTokens, 0, 'a zero-only report must not look like a measurement');
  assert.equal(extractUsage('not json at all'), null);

  // A per-MESSAGE report is not the run's total. Taking it would make a turn of
  // several messages under-count in the direction that makes the budget govern
  // LESS, so the arm refuses instead.
  const messageOnly = JSON.stringify({ type: 'message_end', message: { content: 'MINOR' }, usage: { totalTokens: 999_999, cost: { total: 9.99 } } });
  assert.equal(extractUsage(messageOnly), null, 'a per-message usage was taken for the run total');
  assert.equal(
    extractUsage(`${messageOnly}\n${JSON.stringify({ type: 'message_end', message: { content: 'MINOR' }, usage: { totalTokens: 888_888 } })}`),
    null,
    'two per-message reports were added up into a run total',
  );
});

test('a dry run exercises the whole path, calls no model, spends nothing, and says so', async () => {
  await withDir(async (dir) => {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'prereg.json');
    writeFileSync(input, JSON.stringify(blindInput(5)));
    writeFileSync(pre, JSON.stringify(prereg()));
    assert.equal(await main([input, out, ARM_ID, pre, '20260926', '--dry-run'], {}), 0, 'a completed dry run must exit 0');
    const record = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(record.kind, 's2-008-campaign-adapter-predict-model/1');
    assert.equal(record.outcome_class, 'DRY_RUN', 'a dry run must not be able to read as a measurement');
    assert.equal(record.dry_run, true);
    assert.equal(record.executor.model_calls, 0, 'a dry run called the model');
    assert.equal(record.budget.spent_tokens, 0);
    assert.equal(record.n_cases, 5);
    assert.equal(record.predictions.length, 5);
    assert.equal(record.budget.currency, 'tokens');
    assert.equal(record.executor.parallel_calls, 1, 'the arm must run one call at a time');
    assert.equal(record.executor.credential_in_argv, false);

    // And the stdout contract the host reassembles.
    const run = runScript([input, out, ARM_ID, pre, '20260926', '--dry-run']);
    assert.equal(run.status, 0, 'a completed run must exit 0');
    assert.match(run.output, new RegExp(`^ADAPTER_OK arm=${ARM_ID} seed=20260926 `, 'm'));
    assert.match(run.output, /dry_run=true/, 'the stdout must disclose that no model was called');
    assert.match(run.output, /ADAPTER_JSON_END \d+/, 'the chunked payload is not terminated');
  });
});

test('the blindness guard voids the run, exactly as the zero-spend arm does', async () => {
  await withDir(async (dir) => {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'prereg.json');
    const rows = blindInput(3);
    rows[1].label = 'MAJOR';
    writeFileSync(input, JSON.stringify(rows));
    writeFileSync(pre, JSON.stringify(prereg()));
    const run = runScript([input, out, ARM_ID, pre, '20260926', '--dry-run']);
    assert.notEqual(run.status, 0, 'a label reached the predictor and the run still exited 0');
    assert.match(run.output, new RegExp(ARM_ERRORS.BLIND_INPUT_CARRIES_LABEL));
  });
});

test('a reservation not denominated in tokens REFUSES the run rather than guessing a unit', async () => {
  await withDir(async (dir) => {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'prereg.json');
    writeFileSync(input, JSON.stringify(blindInput(2)));
    // v1's currency was isolated_executor_launches: a paid run governed by a
    // launch count would govern nothing that costs anything.
    writeFileSync(pre, JSON.stringify(prereg({ budget_reservation: { currency: 'isolated_executor_launches', granted_units: 12 } })));
    const run = runScript([input, out, ARM_ID, pre, '20260926', '--dry-run']);
    assert.notEqual(run.status, 0);
    assert.match(run.output, /BUDGET_RESERVATION_NOT_IN_TOKENS/, 'a launch-denominated reservation was accepted for a paid run');
  });
});

test('the budget is EXHAUSTED as an outcome: recorded, non-zero exit, and not a silent truncation', async () => {
  await withDir(async (dir) => {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'prereg.json');
    writeFileSync(input, JSON.stringify(blindInput(6)));
    // A ceiling of ZERO is a preregistered value, not a missing one: the run must
    // stop before the first case and say so.
    writeFileSync(pre, JSON.stringify(prereg({ budget_reservation: { currency: 'tokens', granted_units: 0, trial_timeout_ms: 1000 } })));
    const run = runScript([input, out, ARM_ID, pre, '20260926', '--dry-run']);
    assert.equal(run.status, 6, `a budget stop did not surface as a non-zero exit (status ${String(run.status)})`);
    const record = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(record.stop.reason, ARM_ERRORS.BUDGET_EXHAUSTED);
    assert.equal(record.budget.exhausted, true);
    assert.equal(record.outcome_class, 'DRY_RUN_BUDGET_STOPPED', 'a stopped dry run must read as neither a clean dry run nor a measurement');
    assert.equal(record.dry_run, true);
    assert.equal(record.predictions.length, 0, 'cases were produced past the ceiling');
    assert.ok(record.stop.stopped_before_case, 'the stop does not name the case it stopped before');
    // A reservation with NO ceiling is a different thing and is still refused.
    writeFileSync(pre, JSON.stringify(prereg({ budget_reservation: { currency: 'tokens' } })));
    const missing = runScript([input, out, ARM_ID, pre, '20260926', '--dry-run']);
    assert.match(missing.output, /BUDGET_RESERVATION_NOT_IN_TOKENS/, 'a reservation with no ceiling was treated as zero');
  });
});

test('the credential is read from the env, never from an argv, and its absence refuses BEFORE a spawn', async () => {
  assert.equal(readCredential(ENV_NAME, { [ENV_NAME]: CANARY }), true);
  assert.equal(readCredential(ENV_NAME, { [ENV_NAME]: 'short' }), false, 'a too-short value counted as a credential');
  assert.equal(readCredential(ENV_NAME, {}), false, 'an absent credential counted as present');
  assert.equal(readCredential(ENV_NAME, { [ENV_NAME]: 12345 }), false);

  // The dry run returns before the credential check, so the dry-run cases never
  // reach it: removing that check was invisible to them. The ORDER is the
  // property — a missing credential must cost zero tokens, so the check has to
  // precede the spawn, and the thrown code says which happened.
  for (const env of [{}, { [ENV_NAME]: 'short' }, { [ENV_NAME]: 12345 }]) {
    assert.throws(
      () => callModel('fix: typo', {
        provider: 'zai-coding-cn', model: 'glm-5.3-flash', envName: ENV_NAME, env, dryRun: false, timeoutMs: 1000,
      }),
      (error) => String(error.message).startsWith(ARM_ERRORS.NO_CREDENTIAL),
      `env ${JSON.stringify(env)} reached the spawn`,
    );
  }

  // What the record publishes: the NAME, never the value.
  await withDir(async (dir) => {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'prereg.json');
    writeFileSync(input, JSON.stringify(blindInput(1)));
    writeFileSync(pre, JSON.stringify(prereg()));
    await main([input, out, ARM_ID, pre, '1', '--dry-run'], { [ENV_NAME]: CANARY });
    const raw = readFileSync(out, 'utf8');
    assert.equal(raw.includes(CANARY), false, 'the credential value is in the record');
    const record = JSON.parse(raw);
    assert.equal(record.executor.credential_present, true, 'a present credential was not reported present');
    assert.equal(record.executor.credential_env_name, ENV_NAME, 'the publishable NAME is missing');
    assert.deepEqual(record.container.argv_tail, [ARM_ID, '1', '--dry-run']);
  });
});

test('the five situations get five outcome classes, and none of them is a pass', () => {
  // A dry run that ran to completion and a dry run that stopped on its budget are
  // DIFFERENT facts, and a measured run and a stopped run are different too. The
  // first version had three classes and a stopped dry run reported the same class
  // as a clean one, so a reader checking one field learned nothing.
  assert.equal(classifyOutcome({ dryRun: false, stopped: false, measured: true }), 'MEASURED');
  assert.equal(classifyOutcome({ dryRun: false, stopped: true, measured: true }), 'INFRA');
  assert.equal(classifyOutcome({ dryRun: false, stopped: false, measured: false }), 'NOT_RUN');
  assert.equal(classifyOutcome({ dryRun: true, stopped: false, measured: false }), 'DRY_RUN');
  assert.equal(classifyOutcome({ dryRun: true, stopped: true, measured: false }), 'DRY_RUN_BUDGET_STOPPED');
  const all = new Set([
    classifyOutcome({ dryRun: false, stopped: false, measured: true }),
    classifyOutcome({ dryRun: false, stopped: true, measured: true }),
    classifyOutcome({ dryRun: false, stopped: false, measured: false }),
    classifyOutcome({ dryRun: true, stopped: false, measured: false }),
    classifyOutcome({ dryRun: true, stopped: true, measured: false }),
  ]);
  assert.equal(all.size, 5, 'two of the five situations collapse into one class');
});

test('an UNAPPROVED preregistration is refused before the budget is even read', async () => {
  // v2 exists on disk as a draft with approval.status null. A run that could pick
  // a draft up would turn "the owner has not signed this" into "the run happened
  // anyway" — so the check comes FIRST, ahead of the budget, because an
  // unapproved document has no budget worth reading.
  for (const approval of [undefined, {}, { status: null }, { status: 'AWAITING_OWNER_APPROVAL' }, { status: 'DRAFT' }]) {
    await withDir(async (dir) => {
      const input = path.join(dir, 'in.json');
      const out = path.join(dir, 'out.json');
      const pre = path.join(dir, 'prereg.json');
      writeFileSync(input, JSON.stringify(blindInput(2)));
      writeFileSync(pre, JSON.stringify(prereg({ approval })));
      const run = runScript([input, out, ARM_ID, pre, '20260926', '--dry-run']);
      assert.notEqual(run.status, 0, `approval ${JSON.stringify(approval)} was accepted`);
      assert.match(run.output, new RegExp(ARM_ERRORS.PREREG_NOT_APPROVED));
      assert.equal(existsSync(out), false, 'a refused run still wrote a record');
    });
  }
  // And the approved shape is accepted, so the check is not simply refusing
  // everything — otherwise it would be untested and untrustworthy.
  await withDir(async (dir) => {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'prereg.json');
    writeFileSync(input, JSON.stringify(blindInput(2)));
    writeFileSync(pre, JSON.stringify(prereg()));
    assert.equal(runScript([input, out, ARM_ID, pre, '20260926', '--dry-run']).status, 0, 'an APPROVED preregistration was refused');
  });
});

test('the shipped v2 DRAFT is refused as written, on the real document', () => {
  // Not a synthetic approval object: the actual file on disk, with its actual
  // null approval. If someone later fills the status in, this case starts failing
  // and says why — which is the point of pinning the shipped state.
  const draftPath = path.resolve(import.meta.dirname, '../../corpus/s2-008-campaign/preregistration.v2.draft.json');
  const draft = JSON.parse(readFileSync(draftPath, 'utf8'));
  assert.equal(draft.approval?.status, null, 'the draft on disk is already approved, so it is no longer a draft');
  assert.equal(draft.approval?.runnable_now, false);
  assert.equal(draft.status, 'AWAITING_OWNER_APPROVAL');
  assert.equal(draft.budget_reservation.currency, 'tokens');
  assert.equal(draft.budget_reservation.granted_units, 5000000);
  // The supersession must name what it replaces and what it does NOT touch.
  assert.equal(draft.supersession.supersedes, 'xpr-s2-008c-01');
  assert.ok(draft.supersession.unchanged.includes('multiplicity_rule'),
    'the supersession does not state that the multiplicity rule is unchanged, so a reader cannot tell a predictor change from a rule change');
  // And the rule itself is carried, not restated differently.
  const v1 = JSON.parse(readFileSync(path.resolve(import.meta.dirname, '../../corpus/s2-008-campaign/preregistration.json'), 'utf8'));
  for (const field of ['metric', 'frozen_baseline', 'noise_rule', 'multiplicity_rule', 'seed_rule', 'seeds', 'holdout_access', 'card']) {
    assert.deepEqual(draft[field], v1[field], `${field} moved in v2, which is a rule change and not a supersession`);
  }
});

test('an unknown arm id is refused, so a mis-typed id cannot spend anything', async () => {
  await withDir(async (dir) => {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'prereg.json');
    writeFileSync(input, JSON.stringify(blindInput(1)));
    writeFileSync(pre, JSON.stringify(prereg()));
    const run = runScript([input, out, 'arm-not-this-one', pre, '1', '--dry-run']);
    assert.notEqual(run.status, 0, 'an unknown arm id was allowed to spend');
    assert.match(run.output, new RegExp(ARM_ERRORS.UNKNOWN_ARM));
  });
});

/**
 * Run the arm as a PROCESS, so the exit code is observed rather than inferred
 * from the output. A budget stop has to be a non-zero exit, and a test that read
 * it out of a string the script never prints would pass without proving it.
 */
function runScript(argv) {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...argv], { encoding: 'utf8', timeout: 120000, env: { PATH: '/usr/bin:/bin' } });
    return { status: 0, output: stdout };
  } catch (error) {
    return {
      status: typeof error?.status === 'number' ? error.status : null,
      output: `${String(error?.stdout ?? '')}${String(error?.stderr ?? '')}`,
    };
  }
}

test('an unknown billable call stops before the next case and records unreconciled usage', async () => {
  await withDir(async (dir) => {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'prereg.json');
    writeFileSync(input, JSON.stringify(blindInput(3)));
    writeFileSync(pre, JSON.stringify(prereg()));
    let calls = 0;
    const code = await main([input, out, ARM_ID, pre, '20260926', '--remaining-tokens', '100000000'], { [ENV_NAME]: CANARY }, {
      startBridge: async () => ({ host: '127.0.0.1', port: 45123, stop: () => true }),
      callModel: () => { calls += 1; throw new Error(ARM_ERRORS.NO_USAGE_REPORTED); },
    });
    assert.notEqual(code, 0);
    assert.equal(calls, 1, 'an unknown-spend failure launched another call');
    const record = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(record.budget.unreconciled_spend, true);
    assert.equal(record.stop.reason, ARM_ERRORS.NO_USAGE_REPORTED);
    assert.equal(record.predictions.length, 0);
    assert.equal(record.outcome_class, 'INFRA');
  });
});

test('a paid call returning a zero final total is not chargeable as zero', async () => {
  await withDir(async (dir) => {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'prereg.json');
    writeFileSync(input, JSON.stringify(blindInput(2)));
    writeFileSync(pre, JSON.stringify(prereg()));
    let calls = 0;
    const code = await main([input, out, ARM_ID, pre, '20260926', '--remaining-tokens', '100000000'], { [ENV_NAME]: CANARY }, {
      startBridge: async () => ({ host: '127.0.0.1', port: 45123, stop: () => true }),
      callModel: () => { calls += 1; return { text: 'MAJOR', usage: { totalTokens: 0 }, model_called: true }; },
    });
    assert.notEqual(code, 0);
    assert.equal(calls, 1);
    const record = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(record.budget.unreconciled_spend, true);
    assert.equal(record.predictions.length, 0);
  });
});
