// The HOST_UNISOLATED authorisation gate (issue #45).
//
// This test file is the regression net for one decision: a run on the host
// process space is possible only with a named human authorisation, the
// authorisation is server-resolved and never a payload, an isolated profile
// needs none and refuses one, and every single-field mutation of the permit is
// refused. If any of that stops holding, the ticket's central honesty property
// is gone, so the negatives are enumerated rather than sampled.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  assertLiveExecutionAuthorized,
  assertSandboxExecutable,
  assertUnisolatedExecutionAuthorized,
  hostUnisolatedAuthorizationDigest,
} from '../../src/lib/agentboard/policy.mjs';
import {
  SANDBOX_HOST_UNISOLATED,
  SANDBOX_LOCAL_RESTRICTED_PODMAN,
} from '../../src/lib/identity/sandbox-profiles.mjs';
import { isBoardError } from '../../src/lib/agentboard/errors.mjs';
import {
  UNISOLATED_AUTHORISATION,
  buildUnisolatedAuthorization,
} from '../../scripts/s2-007r-authorization.mjs';

const HOST = SANDBOX_HOST_UNISOLATED.profile_id;
const ISOLATED = SANDBOX_LOCAL_RESTRICTED_PODMAN.profile_id;
const NOW = '2026-09-26T12:00:00.000Z';
const permit = () => buildUnisolatedAuthorization();

const refuses = (fn, matcher, expectedCode = 'BLOCKED_SANDBOX') => {
  let thrown = null;
  try {
    fn();
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown, 'the call must refuse');
  assert.equal(isBoardError(thrown), true, 'the refusal must be a typed BoardError');
  assert.equal(thrown.code, expectedCode);
  // The neighbouring gate in policy.mjs puts the code in `message` and the
  // sentence in `detail`; both travel in the board-error document, so a matcher
  // is allowed to look at either.
  const text = `${thrown.message} ${thrown.detail ?? ''}`;
  if (matcher) assert.match(text, matcher);
};

describe('HOST_UNISOLATED authorisation (issue #45)', () => {
  test('the shipped permit passes the live gate for its own profile', () => {
    const decision = assertLiveExecutionAuthorized(HOST, { authorization: permit(), now: NOW });
    assert.equal(decision.tier, 'HOST_UNISOLATED');
    assert.equal(decision.profile_id, HOST);
    assert.equal(decision.authorization.authorization_id, UNISOLATED_AUTHORISATION.authorization_id);
  });

  test('the permit is refused without any authorisation at all', () => {
    refuses(() => assertLiveExecutionAuthorized(HOST, { now: NOW }), /authorisation document/);
    refuses(() => assertLiveExecutionAuthorized(HOST, { authorization: null, now: NOW }), /authorisation document/);
    refuses(() => assertLiveExecutionAuthorized(HOST, { authorization: 'yes', now: NOW }), /authorisation document/);
  });

  test('an isolated profile needs no permit and refuses one', () => {
    const decision = assertLiveExecutionAuthorized(ISOLATED, { now: NOW });
    assert.equal(decision.tier, 'ISOLATED');
    assert.equal(decision.authorization, null);
    refuses(() => assertLiveExecutionAuthorized(ISOLATED, { authorization: permit(), now: NOW }), /needs no unisolated-execution authorisation/);
  });

  // The interesting boundary: the floor tier must not become a back door into
  // the tiers that actually claim OS controls, and it must not become a way to
  // run under a name that says "proven".
  test('the floor tier is not an executable sandbox profile', () => {
    refuses(() => assertSandboxExecutable(HOST), /no proven OS controls/);
    assert.equal(assertSandboxExecutable(ISOLATED), true);
  });

  test('every single-field mutation of the permit is refused', () => {
    const mutations = {
      authorization_id: 'aut-hu-someone-elses-permit',
      authorised_by_principal_id: 'not-a-principal',
      authorised_by_label: 'x'.repeat(200),
      authority: 'AUTOMATED_GATE',
      scope: 'WHOLE_CAMPAIGN',
      profile_id: ISOLATED,
      issued_at: 'yesterday',
      expires_at: '2026-09-26T00:00:00.000Z',
      body_digest: `sha256:${'0'.repeat(64)}`,
    };
    for (const [field, value] of Object.entries(mutations)) {
      refuses(() => assertUnisolatedExecutionAuthorized({ ...permit(), [field]: value }, { profileId: HOST, now: NOW }));
    }
    for (const field of Object.keys(mutations)) {
      const body = { ...permit() };
      delete body[field];
      refuses(() => assertUnisolatedExecutionAuthorized(body, { profileId: HOST, now: NOW }), new RegExp(field));
    }
  });

  test('an expiry in the past and a window that has not opened are both refused', () => {
    refuses(() => assertLiveExecutionAuthorized(HOST, { authorization: permit(), now: '2026-09-25T12:00:00.000Z' }), /outside its window/);
    refuses(() => assertLiveExecutionAuthorized(HOST, { authorization: permit(), now: '2026-09-27T00:00:00.001Z' }), /outside its window/);
    // The last instant of the window is still inside it: the window is closed,
    // not open-ended at the boundary.
    assert.equal(assertLiveExecutionAuthorized(HOST, { authorization: permit(), now: '2026-09-27T00:00:00.000Z' }).tier, 'HOST_UNISOLATED');
  });

  // The window must be judged against the INJECTED clock. A guard that read the
  // process clock would make a replay depend on when it was replayed.
  test('the window is judged against the injected clock, never the process clock', () => {
    const inside = assertLiveExecutionAuthorized(HOST, { authorization: permit(), now: () => NOW });
    assert.equal(inside.tier, 'HOST_UNISOLATED');
    const asDate = assertLiveExecutionAuthorized(HOST, { authorization: permit(), now: new Date(NOW) });
    assert.equal(asDate.tier, 'HOST_UNISOLATED');
    // A missing clock is a policy refusal, not a sandbox verdict: the permit is
    // well formed, the evaluation simply cannot be trusted without a time.
    refuses(() => assertLiveExecutionAuthorized(HOST, { authorization: permit(), now: null }), /INJECTED_CLOCK/, 'BLOCKED_POLICY');
  });

  test('the body digest is an integrity control over the body, not a signature', () => {
    const authorization = permit();
    assert.equal(hostUnisolatedAuthorizationDigest(authorization), authorization.body_digest);
    const moved = { ...authorization, scope: 'SINGLE_PILOT_RUN' };
    assert.equal(hostUnisolatedAuthorizationDigest(moved), moved.body_digest);
    // Changing the body without recomputing breaks it; the digest proves the
    // document, never the author.
    const edited = { ...authorization, authorised_by_label: 'someone else' };
    assert.notEqual(hostUnisolatedAuthorizationDigest(edited), edited.body_digest);
  });

  test('a profile the board does not know is refused before anything else', () => {
    refuses(() => assertLiveExecutionAuthorized('sbx-invented-v9', { authorization: permit(), now: NOW }), /not a registered S2-002 profile/);
    refuses(() => assertLiveExecutionAuthorized('', { authorization: permit(), now: NOW }), /no sandbox profile is bound/);
  });
});
