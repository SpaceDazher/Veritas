// S2-004 generated contract types drift check: src/lib/claims/contracts.d.ts
// must be exactly what scripts/generate-claim-types.mjs produces from the
// canonical JSON Schemas — the schemas are the single source of truth.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateTypes } from '../../scripts/generate-claim-types.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUT_FILE = path.join(ROOT, 'src/lib/claims/contracts.d.ts');

describe('S2-004 contract types', () => {
  test('contracts.d.ts is in sync with contracts/*.schema.json', () => {
    const current = fs.readFileSync(OUT_FILE, 'utf8');
    const generated = generateTypes();
    assert.equal(current.trimEnd(), generated.trimEnd(), 'drift detected: regenerate with npm run claims:types');
  });

  test('every canonical contract has a generated interface', () => {
    const current = fs.readFileSync(OUT_FILE, 'utf8');
    for (const name of ['Claim', 'EvidenceEdge', 'ClaimEdge', 'ExpertProfile', 'ExpertLens', 'CalibrationRecord', 'ClaimExtractionRequest', 'ClaimExtractionResult', 'ClaimReviewDecision', 'GraphInvalidationEvent']) {
      assert.match(current, new RegExp(`export interface ${name} \\{`), name);
    }
  });
});
