// S2-002 phase 4 — adversarial corpus A–J.
// Every probe drives the production-facing policy path (policy engine +
// sandbox adapter) exactly as a hostile request would hit it. Guards are
// never re-implemented inside this suite: a probe passes only when the
// production modules themselves detect and reject the attack.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { runSecurityProbes } from '../../scripts/security-probes.mjs';

const EXPECTED = Object.freeze({
  A: 'cross-tenant source/search retrieval',
  B: 'private claim into shared summary or cache',
  C: 'payload/env forging role, principal or approval',
  D: 'junction/symlink/traversal filesystem escape',
  E: 'source prompt injection requesting authority or secrets',
  F: 'inter-agent message with foreign scope/tenant',
  G: 'child process surviving cancellation/timeout',
  H: 'stale grant/lease/fencing token after revocation',
  I: 'nonce/idempotency replay changing effect',
  J: 'corrupted/missing policy evidence failing open',
});

const PROBE_RESULTS = await runSecurityProbes({ writeReport: false });

describe('S2-002 adversarial corpus (production-facing path)', () => {
  const results = PROBE_RESULTS;

  test('covers exactly probes A through J', () => {
    assert.deepEqual(results.map((r) => r.id), Object.keys(EXPECTED));
  });

  for (const [id, title] of Object.entries(EXPECTED)) {
    test(`probe ${id} (${title}) is detected, never escaped`, () => {
      const probe = results.find((r) => r.id === id);
      assert.ok(probe, `probe ${id} missing`);
      assert.equal(
        probe.verdict,
        'DETECTED',
        `${id} must be DETECTED by the production path: ${JSON.stringify(probe.detail)}`,
      );
      assert.ok(probe.detail && String(probe.detail).length > 0, 'probe must record observation detail');
    });
  }

  test('no probe is silently skipped on this platform', () => {
    for (const probe of results) {
      assert.notEqual(probe.verdict, 'SKIPPED', `probe ${probe.id} must run on this platform`);
    }
  });
});
