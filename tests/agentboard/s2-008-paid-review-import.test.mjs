import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';

const IMPORTER = path.resolve('scripts/s2-008-paid-review-import.mjs');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

test('fixture-only offline importer verifies exact staged bytes without model accounting', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-paid-review-import-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const evidenceRoot = path.join(root, 'evidence');
  const outputRoot = path.join(root, 'output');
  fs.mkdirSync(evidenceRoot);
  fs.mkdirSync(outputRoot);
  const bytes = Buffer.from(JSON.stringify({ kind: 'fixture-only', status: 'NOT_ACCEPTANCE_EVIDENCE' }) + '\n');
  fs.writeFileSync(path.join(evidenceRoot, 'sample.json'), bytes, { mode: 0o400 });
  const records = [{ path: 'sample.json', bytes: bytes.length, sha256: sha256(bytes) }];
  const bundle = {
    kind: 's2-008-paid-review-import-bundle/1',
    fixture_only: true,
    artifact_manifest_digest: canonicalDigest(records),
    files: records,
  };
  const bundlePath = path.join(evidenceRoot, 'bundle.json');
  const outputPath = path.join(outputRoot, 'import.json');
  fs.writeFileSync(bundlePath, JSON.stringify(bundle) + '\n', { mode: 0o400 });
  const result = spawnSync(process.execPath, [IMPORTER, '--bundle', bundlePath, '--output', outputPath],
    { encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, String(result.stderr));
  const report = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
  assert.equal(report.kind, 's2-008-paid-review-import/1');
  assert.equal(report.artifact_manifest_digest, bundle.artifact_manifest_digest);
  assert.equal(report.verified_files, 1);
  assert.equal(report.model_calls, 0);
  assert.equal(report.tokens, 0);
  assert.equal(report.network, 'none');
  assert.equal(report.fixture_only, true);
  assert.equal(result.stdout.includes('sample.json'), false);
});

test('fixture-only offline importer blocks any byte change after the manifest is staged', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-paid-review-import-tamper-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const evidenceRoot = path.join(root, 'evidence');
  const outputRoot = path.join(root, 'output');
  fs.mkdirSync(evidenceRoot);
  fs.mkdirSync(outputRoot);
  const original = Buffer.from('original fixture bytes\n');
  fs.writeFileSync(path.join(evidenceRoot, 'sample.json'), original, { mode: 0o400 });
  const records = [{ path: 'sample.json', bytes: original.length, sha256: sha256(original) }];
  const bundlePath = path.join(evidenceRoot, 'bundle.json');
  fs.writeFileSync(bundlePath, JSON.stringify({
    kind: 's2-008-paid-review-import-bundle/1',
    fixture_only: true,
    artifact_manifest_digest: canonicalDigest(records),
    files: records,
  }) + '\n', { mode: 0o400 });
  fs.chmodSync(path.join(evidenceRoot, 'sample.json'), 0o600);
  fs.writeFileSync(path.join(evidenceRoot, 'sample.json'), 'mutated fixture bytes\n');
  const outputPath = path.join(outputRoot, 'import.json');
  const result = spawnSync(process.execPath, [IMPORTER, '--bundle', bundlePath, '--output', outputPath],
    { encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.equal(fs.existsSync(outputPath), false);
  assert.doesNotMatch(String(result.stdout) + String(result.stderr), /original fixture bytes|mutated fixture bytes/);
});
