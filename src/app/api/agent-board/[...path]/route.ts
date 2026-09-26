// S2-007 LIVE AGENT BOARD — the declared routes below the mount point.
//
// `route.ts` matches only `/api/agent-board`; this catch-all matches one or more
// segments below it (`/api/agent-board/capabilities`, `/api/agent-board/tasks/
// abt-x/transition`, ...), which is what makes the library's eighteen declared
// HTTP routes actually reachable over HTTP instead of only through the CLI and
// the negative probes.
//
// There is no logic here. Both mounts delegate to the same
// `src/lib/agentboard/next-transport.ts` core, so they cannot become two
// transports with two rule sets. See `../route.ts` for the full boundary
// description.
import type { NextRequest } from 'next/server';
import { readBodyAndRespond as readBody, respond } from '@/lib/agentboard/next-transport';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET(request: NextRequest): Promise<Response> {
  return respond(request, null);
}

export async function POST(request: NextRequest): Promise<Response> {
  return readBody(request);
}
