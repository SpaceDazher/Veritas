import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verify } from '../../scripts/verify-s2-005.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const probeEvidence = path.join(root, 'evidence/s2-005-security-probes.json');

test('read-only S2-005 verification does not rewrite tracked probe evidence', async () => {
  const before = fs.readFileSync(probeEvidence);
  const outcome = await verify({ write: false });
  assert.equal(outcome.verdict, 'PASS_WITH_LIMITS');
  assert.deepEqual(fs.readFileSync(probeEvidence), before);
});
