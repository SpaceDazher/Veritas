import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyCurrentDbReplay } from '../../scripts/verify-s2-006.mjs';

const greenReport = () => ({
  schemaVersion: 1,
  ticket: 'S2-006',
  status: 'PASS',
  ok: true,
  comparison: { ok: true, issues: [] },
  hardGates: { ok: true, violations: [] },
  crashPhase: { ok: true, issues: [] },
});

const executed = (report, exitCode = 0) => ({ exitCode, stdout: JSON.stringify(report), stderr: '' });
const written = (report, exitCode = 0) => ({ ...report, exitCode });

describe('S2-006 DB replay freshness gate', () => {
  test('accepts only a green report matching this invocation and the written evidence', () => {
    const report = greenReport();
    const result = classifyCurrentDbReplay(executed(report), written(report));
    assert.equal(result.gate.status, 'PASS');
    assert.equal(result.gate.crashPhaseOk, true);
    assert.deepEqual(result.evidence, written(report));
  });

  test('a previously green evidence file cannot turn a current NOT_RUN_DB into PASS', () => {
    const oldGreen = written(greenReport());
    const current = { schemaVersion: 1, ticket: 'S2-006', status: 'NOT_RUN_DB', ok: false, reason: 'WSL unavailable' };
    const result = classifyCurrentDbReplay(executed(current), oldGreen);
    assert.notEqual(result.gate.status, 'PASS');
    assert.equal(result.evidence, null);
  });

  test('exit zero with a failed hard gate or crash phase is never PASS', () => {
    for (const patch of [
      { hardGates: { ok: false, violations: ['duplicate-ledger'] } },
      { crashPhase: { ok: false, issues: ['blind-retry'] } },
    ]) {
      const report = { ...greenReport(), ...patch };
      const result = classifyCurrentDbReplay(executed(report), written(report));
      assert.equal(result.gate.status, 'FAIL');
    }
  });

  test('a process error or malformed output cannot reuse stored PASS evidence', () => {
    const oldGreen = written(greenReport());
    for (const replay of [
      { exitCode: 1, stdout: '', stderr: 'process failed' },
      { exitCode: 0, stdout: 'not json', stderr: '' },
    ]) {
      const result = classifyCurrentDbReplay(replay, oldGreen);
      assert.equal(result.gate.status, 'FAIL');
      assert.equal(result.evidence, null);
    }
  });
});
