// S2-007 LIVE AGENT BOARD — shared Next.js transport core.
//
// ONE implementation, TWO mount points. The library's `HTTP_ROUTES` table
// declares eighteen routes (discovery, ACL-checked reads and idempotency-keyed
// mutations). A single App Router `route.ts` matches ONLY its exact path, so
// without a catch-all mount seventeen of those routes would 404 in the
// framework before `handleRequest` ever saw them — the route table would be
// unreachable over HTTP and only the CLI and the negative probes would exercise
// it. `route.ts` (the mount point itself) and `[...path]/route.ts` (one or more
// segments below it) therefore both delegate here, so the two mounts can never
// become two different transports with two different rules.
//
// The full boundary description — what this surface is, why it is not the
// public synthetic demo, and why the credential store and the configured store
// are injected by the host instead of being built here — lives in
// `src/app/api/agent-board/route.ts`, which is the canonical description of the
// live board. This module is transport only: it converts a NextRequest into
// `handleRequest`'s call shape and converts the result back. It holds no state
// machine, no ACL rule, no transition, no budget rule and no error mapping of
// its own; a rule enforced only in a transport is a rule the CLI, the scheduler
// and the negative probes do not have.
import { NextRequest, NextResponse } from 'next/server';
import { handleRequest, type BoardClock, type BoardPrincipalResolver } from '@/lib/agentboard/http.mjs';

export const LIVE_BOARD_RUNTIME_KEY = '__veritasLiveAgentBoardRuntime';
export const MOUNT_PATH = '/api/agent-board';


export interface LiveBoardRuntime {
  store?: unknown;
  principalResolver?: unknown;
  actorKinds?: Record<string, string>;
  adapters?: unknown;
  transport?: unknown;
  clock?: unknown;
}

export type LiveBoardGlobal = typeof globalThis & {
  [LIVE_BOARD_RUNTIME_KEY]?: LiveBoardRuntime;
};

/** Headers as a plain lowercased object; the library does its own lookup. */
export function headersOf(request: NextRequest): Record<string, string> {
  const out: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

export function liveBoardRuntime(): LiveBoardRuntime {
  const registered = (globalThis as LiveBoardGlobal)[LIVE_BOARD_RUNTIME_KEY];
  return registered && typeof registered === 'object' ? registered : {};
}

export async function respond(request: NextRequest, rawBody: string | null): Promise<Response> {
  const live = liveBoardRuntime();
  const { status, body } = await handleRequest({
    method: request.method,
    // The client-visible path is stripped of this route's mount point and of
    // the origin; the library re-derives the segments.
    path: request.nextUrl.pathname.startsWith(MOUNT_PATH)
      ? request.nextUrl.pathname.slice(MOUNT_PATH.length) || '/'
      : request.nextUrl.pathname,
    headers: headersOf(request),
    // A GET carries no body; a POST body is handed over RAW so that the
    // library — not this adapter — decides what a valid body is.
    body: rawBody,
    // The server-computed origin of THIS request. The library compares it with
    // the `Origin` header and refuses a cross-origin mutation; it never
    // trusts a client-supplied origin value.
    requestOrigin: request.nextUrl.origin,
    principalResolver: live.principalResolver as BoardPrincipalResolver | undefined,
    actorKinds: live.actorKinds,
    store: live.store,
    adapters: live.adapters,
    transport: live.transport,
    clock: live.clock as BoardClock | undefined,
  });
  return NextResponse.json(body, {
    status,
    headers: {
      // Distinguishes this surface from the public synthetic demo in a
      // response header as well as in the path.
      'x-veritas-board': 'live-agent-board',
      'cache-control': 'no-store',
    },
  });
}

export async function readBodyAndRespond(request: NextRequest): Promise<Response> {
  // A body that cannot even be read is a transport failure, not a board
  // result. It is reported as a bare 500 with no body so that a truncated
  // request can never be mistaken for a committed command.
  let raw: string;
  try {
    raw = await request.text();
  } catch {
    return NextResponse.json({ error: 'the request body could not be read' }, { status: 500 });
  }
  return respond(request, raw);
}
