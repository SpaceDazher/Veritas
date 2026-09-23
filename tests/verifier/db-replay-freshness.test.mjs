import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { classifyCurrentDbReplay, engineeringGateExitCode } from '../../scripts/s2-006-db-gate.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

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

  test('a matching unavailable or failed DB report is classified by its observed status', () => {
    const unavailable = { schemaVersion: 1, ticket: 'S2-006', status: 'NOT_RUN_DB', ok: false, reason: 'no database' };
    assert.equal(classifyCurrentDbReplay(executed(unavailable), written(unavailable)).gate.status, 'NOT_RUN_DB');
    const failed = { schemaVersion: 1, ticket: 'S2-006', status: 'FAIL', ok: false };
    assert.equal(classifyCurrentDbReplay(executed(failed, 1), written(failed, 1)).gate.status, 'FAIL');
  });

  test('missing or failed mandatory DB replay makes the command fail even with NEEDS_INPUT verdict', () => {
    for (const status of ['NOT_RUN_DB', 'FAIL']) {
      assert.equal(engineeringGateExitCode('NEEDS_INPUT', { dbReplay: { status } }), 1);
    }
    assert.equal(engineeringGateExitCode('NEEDS_INPUT', { dbReplay: { status: 'PASS' } }), 0);
  });

  test('the fresh replay gate is included in the frozen manifest with exact bytes', () => {
    const relativePath = 'scripts/s2-006-db-gate.mjs';
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'evidence/frozen-manifest.json'), 'utf8'));
    const digest = createHash('sha256').update(fs.readFileSync(path.join(root, relativePath))).digest('hex');
    assert.equal(manifest.files[relativePath], digest);
  });
});
