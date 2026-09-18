import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('the frozen manifest covers S2-005 contracts, implementation, corpus, checks and probes', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'evidence/frozen-manifest.json'), 'utf8'));
  const required = [
    'contracts/retrieval-request.schema.json',
    'contracts/retrieval-hit.schema.json',
    'contracts/retrieval-run.schema.json',
    'contracts/evidence-map.schema.json',
    'contracts/hypothesis-card.schema.json',
    'contracts/synthesis-result.schema.json',
    'src/lib/synthesis/retrieval.mjs',
    'src/lib/synthesis/synthesis.mjs',
    'corpus/s2-005/manifest.json',
    'scripts/s2-005-run.mjs',
    'scripts/s2-005-db-replay.mjs',
    'scripts/s2-005-security-probes.mjs',
    'scripts/verify-s2-005.mjs',
    'scripts/verify-s2-005-dependencies.mjs',
    'evidence/s2-005-dependency-binding.json',
    'evidence/s2-005-security-probes.json',
  ];
  for (const file of required) {
    assert.match(manifest.files[file] ?? '', /^[0-9a-f]{64}$/, `${file} is not frozen`);
  }
});
