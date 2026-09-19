// S2-005 generated contract types drift check: src/lib/synthesis/contracts.d.ts
// must be exactly what scripts/generate-synthesis-types.mjs produces from the
// canonical JSON Schemas — the schemas are the single source of truth.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateTypes } from '../../scripts/generate-synthesis-types.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUT_FILE = path.join(ROOT, 'src/lib/synthesis/contracts.d.ts');

describe('S2-005 contract types', () => {
  test('contracts.d.ts is in sync with contracts/*.schema.json', () => {
    const current = fs.readFileSync(OUT_FILE, 'utf8');
    const generated = generateTypes();
    assert.equal(current.trimEnd(), generated.trimEnd(), 'drift detected: regenerate with npm run synthesis:types');
  });

  test('the declaration file exports all six contracts', () => {
    const source = fs.readFileSync(OUT_FILE, 'utf8');
    for (const name of ['RetrievalRequest', 'RetrievalHit', 'RetrievalRun', 'EvidenceMap', 'HypothesisCard', 'SynthesisResult']) {
      assert.match(source, new RegExp(`export interface ${name}\\b`), `${name} interface missing`);
    }
  });
});
