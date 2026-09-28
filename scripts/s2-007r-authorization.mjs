// The named human authorisation for a run bound to the HOST_UNISOLATED floor
// tier (issue #45, decision D3-b).
//
// WHY THIS IS A SCRIPT AND NOT A CHECKED-IN JSON FILE
// The permit is a document whose body digest must match its own body, and the
// body names the profile, the authorising principal, the scope and the window.
// Emitting it here means the digest is computed by the same code that checks it
// (policy.hostUnisolatedAuthorizationDigest), so a hand-edited file can never
// carry a stale digest, and a tampered body can never keep a valid one.
//
// WHO AUTHORISED IT
// The repository owner, in the BB thread that runs issue #45, chose explicitly
// to add the HOST_UNISOLATED floor tier rather than (a) leaving the proven set
// untouched and accepting a BLOCKED ticket, or (b) naming a proven profile for a
// process that never entered its container. The owner is recorded BY LABEL and
// BY PRINCIPAL ID; no credential, no token and no account detail appears here.
//
// WHAT IT DOES AND DOES NOT ALLOW
// It allows a pilot run of a model-calling executor as an ordinary host process,
// with the network and environment controls the tier declares it does not have.
// It does not assert that the run is isolated, it does not approve any spend on
// its own (the board's budget grant does that, separately), and it can never be
// scored against an A-MVP isolation clause.
//
// The window is a fixed pair of injected instants, never the wall clock: the
// same script run on another day produces the same document.
import { hostUnisolatedAuthorizationDigest } from '../src/lib/agentboard/policy.mjs';
import { SANDBOX_HOST_UNISOLATED } from '../src/lib/identity/sandbox-profiles.mjs';

export const UNISOLATED_AUTHORISATION = Object.freeze({
  authorization_id: 'aut-hu-s2-007r-01',
  authorised_by_principal_id: 'prn-s2007r-owner',
  authorised_by_label: 'SpaceDazher (repository owner, BB thread thr_mgkk7cb5t6)',
  authority: 'HUMAN_OWNER',
  scope: 'SINGLE_PILOT_RUN',
  profile_id: SANDBOX_HOST_UNISOLATED.profile_id,
  issued_at: '2026-09-26T00:00:00.000Z',
  expires_at: '2026-09-27T00:00:00.000Z',
});

/** The permit with its own body digest, ready to hand to execute(). */
export function buildUnisolatedAuthorization(body = UNISOLATED_AUTHORISATION) {
  return Object.freeze({ ...body, body_digest: hostUnisolatedAuthorizationDigest(body) });
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const authorization = buildUnisolatedAuthorization();
  console.log(JSON.stringify({
    ...authorization,
    verification: 'node --test tests/agentboard/unisolated-authorization.test.mjs',
    note: 'This document authorises ONE pilot run of a model-calling executor on the host process space. It is not an isolation claim, not a spend approval and not an A-MVP acceptance.',
  }, null, 2));
}
