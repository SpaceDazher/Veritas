import assert from 'node:assert/strict';
import { test } from 'node:test';

import { runSubprocessGate } from '../../scripts/verify-s2-007-dependencies.mjs';

test('dependency rerun launches npm and records a real exit code on this host', () => {
  const observed = runSubprocessGate({
    id: 'verify-s2-002-dependencies',
    npmScript: 'verify:s2-002-dependencies',
    command: 'npm run verify:s2-002-dependencies',
  });

  assert.equal(observed.timedOut, false);
  assert.equal(observed.signal, null);
  assert.equal(observed.exitCode, 0, observed.stderr);
  assert.match(observed.stdout, /"ok"\s*:\s*true/);
});
