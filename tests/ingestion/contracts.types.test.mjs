// S2-003 TypeScript types derivation test.
// The committed src/lib/ingestion/contracts.d.ts must be byte-identical to
// what the schemas generate: hand-written copies of contract formats are
// forbidden (§2), so any schema edit must go through the generator.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { generateTypes, INGESTION_CONTRACTS } from '../../scripts/generate-ingestion-types.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUT_FILE = path.join(ROOT, 'src/lib/ingestion/contracts.d.ts');

describe('S2-003 generated TypeScript contract types', () => {
  test('the committed declarations match the schemas byte-for-byte', () => {
    const expected = `${generateTypes().replace(/\s+$/, '\n')}`;
    const actual = fs.readFileSync(OUT_FILE, 'utf8');
    assert.equal(actual, expected, 'contracts.d.ts drifted from contracts/*.schema.json; run npm run ingestion:types');
  });

  test('every ingestion contract contributes a top-level interface', () => {
    const source = fs.readFileSync(OUT_FILE, 'utf8');
    for (const name of INGESTION_CONTRACTS) {
      const typeName = name.split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('');
      assert.match(source, new RegExp(`export interface ${typeName} \\{`), typeName);
    }
  });

  test('the generator is deterministic across invocations', () => {
    assert.equal(generateTypes(), generateTypes());
  });

  test('the generator covers every enum value of the closed terminal states', () => {
    const source = fs.readFileSync(OUT_FILE, 'utf8');
    for (const terminal of ['COMMITTED', 'BLOCKED_CONNECTOR', 'ACCESS_DENIED', 'TOMBSTONED', 'QUARANTINED', 'FAILED', 'CANCELLED', 'RECONCILIATION_REQUIRED']) {
      assert.ok(source.includes(`"${terminal}"`), terminal);
    }
  });

  test('tsc accepts the generated declarations', () => {
    const result = execFileSync(process.execPath, [
      path.join(ROOT, 'node_modules/typescript/bin/tsc'),
      '--noEmit', '--skipLibCheck', OUT_FILE,
    ], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
    assert.equal(result, '');
  });
});
