// S2-007 LIVE AGENT BOARD — HTTP adapter (App Router), mount point.
//
// THIS IS NOT THE PUBLIC SYNTHETIC DEMO.
// `/api/board` (src/app/api/board/route.ts), `src/lib/board.ts` and
// `scripts/veritas-cli.mjs` are the PUBLIC_SYNTHETIC_DEMO surface: a public
// planning fixture with no authentication, no tenancy, no leases, no scheduler
// and no execution. They keep their labelling and gain nothing. THIS route is
// the live board's transport: every request is authenticated server-side, every
// read is ACL-checked in `commands.execute`, every mutation is idempotency-keyed
// and re-checks actor, grant and arguments immediately before the side effect.
// The two surfaces are disjoint: nothing here reads the demo fixture and nothing
// there can reach the live board.
//
// WHAT THIS FILE IS, AND WHAT IT IS NOT
// A TRANSPORT SHIM. It converts a NextRequest into the call shape
// `handleRequest` expects, and converts the `{ status, body }` it returns into
// a NextResponse. That is all. It holds no state machine, no ACL rule, no
// transition, no budget rule and no error mapping of its own, because a rule
// enforced only here is a rule the CLI, the scheduler and the negative probes
// do not have. Every refusal is produced by the library and travels as a
// contract-valid `board-error` document (contracts/board-error.schema.json).
//
// WHY THE RUNTIME IS INJECTED AND NOT BUILT HERE
// Two dependencies of this surface cannot live in this repository:
//   * a CREDENTIAL STORE — S2-002 rule 7 forbids secrets in Git, so there is
//     no token file, no fixture principal and no development bypass here;
//   * a configured STORE — `PostgresAgentBoardStore` needs a connection
//     string, and `src/db/index.ts` throws at import time when `DATABASE_URL`
//     is missing, which would take the whole route module down.
// The host that serves the live board therefore registers a runtime object on
// the server process under `globalThis[LIVE_BOARD_RUNTIME_KEY]` before the
// first request (a custom server, an instrumentation hook or a bootstrap
// module):
//
//   globalThis[LIVE_BOARD_RUNTIME_KEY] = {
//     store: new PostgresAgentBoardStore({ connectionString: process.env.DATABASE_URL }),
//     principalResolver: async ({ token }) => resolveCredentialOnTheServer(token),
//     actorKinds: { 'prn-owner-alice': 'human_owner' },
//   };
//
// Until that registration exists the route is FAIL-CLOSED, not silently
// permissive: discovery (`GET /`) still answers with the library's own
// contract-valid description of the live board, and every other route answers
// a typed 401 (no credential store) or 500 (no store). It never falls back to
// the demo fixture, to an anonymous principal or to a permissive default.
// `scripts/veritas-board-cli.mjs` is the matching client.
//
// THE CATCH-ALL MOUNT
// This file answers the mount point itself (`/api/agent-board`). The routes
// declared in `HTTP_ROUTES` live BELOW it (`/capabilities`, `/tasks`,
// `/tasks/:task_id/transition`, ...), and an App Router `route.ts` matches only
// its exact path, so those seventeen routes would 404 in the framework before
// the library ever saw them. `[...path]/route.ts` mounts them. Both files
// delegate to the SAME `src/lib/agentboard/next-transport.ts` core, so the two
// mounts cannot drift into two different transports with two different rules.
import type { NextRequest } from 'next/server';
import { readBodyAndRespond as readBody, respond } from '@/lib/agentboard/next-transport';

// Force per-request evaluation: authorization is decided per request, and a
// cached board page would be a cross-principal leak.
export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET(request: NextRequest): Promise<Response> {
  return respond(request, null);
}

export async function POST(request: NextRequest): Promise<Response> {
  return readBody(request);
}
