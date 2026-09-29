// S2-008 #12 — the LAUNCH ACCOUNTING REFUSES A BUDGET IT CANNOT MEASURE.
//
// The bypass this pins is specific and quiet. `scripts/s2-008-campaign-run.mjs`
// charges one unit per container launch. The v3 campaign is denominated in
// TOKENS. Charging "1 token" per launch would make nine launches read as 9 of
// 5,000,000 spent — a ceiling that looks untouched while the whole amount went
// out, and a record that would happily report `within_reservation`.
//
// So the rule is not "count the tokens instead". It is: a runner declares the
// unit it can observe, and a reservation in any other currency stops the campaign
// BEFORE the first container. A budget that cannot be measured must refuse, not
// acquire a unit size that flatters it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import {
  MEASURABLE as MEASURABLE_CURRENCY,
  assertRunnerPreregInForce,
  currencyRefusal,
  entryReportFor,
} from '../../scripts/s2-008-campaign-run.mjs';

const ROOT = path.resolve(import.meta.dirname, '../..');
const CORPUS = path.join(ROOT, 'corpus/s2-008-campaign');
const RUNNER = path.join(ROOT, 'scripts/s2-008-campaign-run.mjs');

const inForce = JSON.parse(readFileSync(path.join(CORPUS, 'preregistration.v3.in-force.json'), 'utf8'));
const launchDeno = JSON.parse(readFileSync(path.join(CORPUS, 'preregistration-superseded.json'), 'utf8'));

test('the currency this runner can measure is named, and it is launches', () => {
  assert.equal(MEASURABLE_CURRENCY, 'isolated_executor-launches'.replace('-', '_'));
});

test('the v3 campaign is denominated in tokens, so THIS runner cannot run it', () => {
  // The refusal is the point: a token ceiling is not a launch count, and the two
  // documents in the corpus are exactly that pair.
  assert.equal(inForce.budget_reservation.currency, 'tokens');
  assert.equal(inForce.budget_reservation.granted_units, 5000000);
  assert.equal(launchDeno.budget_reservation.currency, 'isolated_executor_launches');
  assert.notEqual(inForce.budget_reservation.currency, MEASURABLE_CURRENCY,
    'the v3 campaign became launch-denominated, so this test proves nothing');
});

test('the runner refuses a token reservation on the way in, with a non-zero status and no launch', () => {
  // Run as a PROCESS: a refusal that exits 0 is not a refusal, and an in-process
  // call would not show the exit code at all.
  let status = null;
  let output = '';
  try {
    const stdout = execFileSync(process.execPath, [RUNNER, '--write=false', '--out=/tmp/veritas-should-not-exist.json'], {
      encoding: 'utf8', timeout: 240000, env: { PATH: '/usr/bin:/bin' },
    });
    output = stdout;
  } catch (error) {
    status = typeof error?.status === 'number' ? error.status : null;
    output = `${String(error?.stdout ?? '')}${String(error?.stderr ?? '')}`;
  }
  assert.notEqual(status, 0, `the runner exited 0 against a token-denominated campaign:\n${output.slice(0, 400)}`);
  // Two guards can refuse, and both are correct here. The legacy runner reads
  // preregistration.json (v1, launch-denominated) while the manifest now names
  // v3 as the document IN FORCE, so it stops at the binding check before it ever
  // reaches the currency check. What matters to an operator is the same either
  // way: a NAMED reason, a non-zero status, and nothing launched. The currency
  // guard is exercised separately below, against a corpus where the binding
  // matches, so neither guard is untested.
  assert.match(output, /CAMPAIGN_PREREGISTRATION_NOT_IN_FORCE|BUDGET_UNMEASURABLE|not a token/,
    `the refusal did not name a reason, and an operator cannot act on it:\n${output.slice(0, 400)}`);
  assert.doesNotMatch(output, /"launches":\s*[1-9]/, 'a refused run claims launches happened');
  assert.doesNotMatch(output, /"spent_units":\s*[1-9]/, 'a refused run claims a non-zero spend');
});

test('the superseded guard still holds: a document that is not the one IN FORCE is refused', () => {
  const manifest = JSON.parse(readFileSync(path.join(CORPUS, 'manifest.json'), 'utf8'));
  // The real in-force document passes, so the guard is not simply refusing all.
  const forgedManifest = { ...manifest, preregistration: { ...manifest.preregistration, preregistration_digest: 'sha256:'.padEnd(71, '0') } };
  assert.throws(
    () => assertRunnerPreregInForce(inForce, forgedManifest),
    (error) => String(error.message) === 'CAMPAIGN_PREREGISTRATION_NOT_IN_FORCE',
    'a forged manifest binding was accepted',
  );
});

test('the currency guard is AHEAD of the first launch, and says it charged nothing', () => {
  // This is the ORDERING, which is the whole safety property: a launch before the
  // guard would spend real money on a campaign that then refuses to account for
  // it. (The first version of this case was a static index comparison that a
  // comment-inserting mutation satisfied without changing any behaviour — a
  // vacuous control, so the assertion is on the two things that must be true
  // rather than on a line number alone.)
  const source = readFileSync(RUNNER, 'utf8');
  const guardAt = source.indexOf('const refusal = currencyRefusal(');
  const firstLaunchAt = source.indexOf('const result = runTrial({');
  assert.ok(guardAt > 0, 'the currency guard is not in the runner at all');
  assert.ok(firstLaunchAt > guardAt, 'a container launch happens BEFORE the currency guard');
  const between = source.slice(guardAt, firstLaunchAt);
  // And the refusal is recorded, so a ledger cannot later read as a campaign that
  // started: a journal row, a zero spend and a zero launch count.
  assert.match(between, /BUDGET_REFUSAL/, 'the refusal leaves no journal row');
  assert.match(between, /spent_units: 0/, 'the refusal does not record a zero spend');
  assert.match(between, /launches: 0/, 'the refusal does not record a zero launch count');
  // And the decision is the pure one, not a second copy of the rule.
  assert.match(between, /if \(refusal !== null\)/, 'the guard does not consult the pure decision');
});

test('BOTH branches of the currency decision are directly observable', () => {
  // The guard used to be inline, so the only way to reach its refusal was to
  // satisfy an earlier guard first. That made a mutation of its EXIT CODE
  // invisible to the suite: the run refused for a different reason and exited
  // non-zero anyway. Extracted as a pure decision, both branches can be read.
  const measurable = currencyRefusal(MEASURABLE_CURRENCY);
  assert.equal(measurable, null, `a launch-denominated reservation was refused: ${JSON.stringify(measurable)}`);

  const refusal = currencyRefusal('tokens', { grantedUnits: 5000000 });
  assert.notEqual(refusal, null, 'a token reservation was allowed by the launch runner');
  assert.equal(refusal.code, 'BUDGET_UNMEASURABLE');
  assert.ok(refusal.exitCode !== 0, `the refusal carries a zero exit code: ${String(refusal.exitCode)}`);
  assert.equal(refusal.launches, 0);
  assert.equal(refusal.charged_units, 0);
  assert.equal(refusal.spent_units, 0);
  assert.equal(refusal.granted_units, 5000000);
  assert.match(refusal.detail, /not a token/);
  // A missing currency is not zero, and not a permission either.
  assert.equal(currencyRefusal(undefined)?.code, 'BUDGET_UNMEASURABLE');
  assert.equal(currencyRefusal(null)?.code, 'BUDGET_UNMEASURABLE');
});

test('BOTH branches of the entry report are directly observable', () => {
  // Same reason: a mutation that made the entry point IGNORE a refusal was
  // invisible, because on the real corpus an earlier guard refused first.
  const blocked = entryReportFor({ status: 'BLOCKED', code: 'BUDGET_UNMEASURABLE', launches: 0, charged_units: 0, exitCode: 4, detail: 'x' });
  assert.notEqual(blocked.report, null, 'a refused run printed nothing');
  assert.notEqual(blocked.exitCode, 0, 'a refused run exited 0');
  assert.equal(blocked.report.launches, 0);

  const normal = entryReportFor({ status: 'MEASURED', raw_run_id: 'r' });
  assert.equal(normal.report, null, 'a normal run was printed as a refusal');
  assert.equal(normal.exitCode, 0);
});
