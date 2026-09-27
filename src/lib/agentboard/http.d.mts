// Type declarations for src/lib/agentboard/http.mjs.
//
// WHY THIS FILE EXISTS
// `tsconfig.json` sets `allowJs: false`, so TypeScript cannot resolve a
// relative `.mjs` import (it answers TS2307 "cannot find module ... or its
// corresponding type declarations") and the Next.js adapter for the live
// Agent Board would not compile. The implementation stays plain ESM — the
// domain layer must not become TypeScript — so the boundary gets a hand
// written declaration instead. Only `http.d.mts` is found for an `http.mjs`
// specifier (`http.d.ts` is ignored), so the `.d.mts` extension is required.
// The ambient `declare const` form below is deliberate: it is the same
// declaration a `.d.ts` means, and it also parses when the repo's ESLint flat
// config treats `**/*.d.mts` as a plain module rather than as a declaration
// file (an initializer-less `export const` is a parse error there).
//
// This declares the TRANSPORT surface only. It intentionally re-declares no
// state, no transition, no error code and no payload shape: the wire types
// live in `src/lib/agentboard/contracts.d.ts` (generated from
// `contracts/*.schema.json`) and the semantic machine lives in
// `src/lib/agentboard/constants.mjs`. The store, the adapters, the transport
// and the principal record are opaque here on purpose — the HTTP boundary
// forwards them to `commands.execute` and never inspects them.
//
// Keep it in step with the `.mjs` exports: `toHttpStatus`, `handleRequest`,
// `HTTP_ROUTES`, `HTTP_STATUS_BY_CODE`.

/** An injected clock: a function, or `{ now(): Date | string }`. */
export type BoardClock = (() => Date | string) | { now: () => Date | string };

/** Anything with a header lookup: the library accepts a plain object, a Map or Headers. */
export type BoardHeaders =
  | Record<string, string | string[] | undefined>
  | Map<string, string>
  | Headers;

/** A server-resolved principal. `principal_id` is the only required field. */
export interface BoardPrincipal {
  principal_id: string;
  capabilities?: string[];
  workspace_ids?: string[];
  actor_kind?: string;
  [field: string]: unknown;
}

/** A server-side resolver: it receives the bearer token and returns a principal or nothing. */
export type BoardPrincipalResolver =
  | ((request: {
    method: string;
    path: string;
    headers: BoardHeaders | null;
    authorization: string | null;
    token: string | null;
  }) => BoardPrincipal | null | undefined | Promise<BoardPrincipal | null | undefined>)
  | Map<string, BoardPrincipal>
  | Record<string, BoardPrincipal>;

/** One entry of the routable surface. `segments` uses `:name` for a path parameter. */
export interface BoardHttpRoute {
  readonly method: string;
  readonly segments: readonly string[];
  readonly command: string;
  readonly mutating: boolean;
  readonly queryKeys: readonly string[];
}

/** The request `handleRequest` accepts. Every field is optional; a missing one is a typed refusal. */
export interface BoardHttpRequest {
  method?: string;
  path?: string;
  headers?: BoardHeaders | null;
  body?: unknown;
  principalResolver?: BoardPrincipalResolver;
  actorKinds?: Record<string, string>;
  store?: unknown;
  adapters?: unknown;
  clock?: BoardClock;
  transport?: unknown;
  requestOrigin?: string;
  basePath?: string;
  now?: string;
}

/** A committed command result, or a contract-valid `board-error` document on a refusal. */
export interface BoardHttpResponse {
  status: number;
  body: unknown;
}

/** Map a typed board error onto its HTTP status. Never 200, except for CANCELLED. */
export function toHttpStatus(error: unknown): number;

/** Authenticate server-side, translate `method + path` to one command, delegate to `commands.execute`. */
export function handleRequest(request?: BoardHttpRequest): Promise<BoardHttpResponse>;

/** The closed route table of the live board's HTTP surface. */
export declare const HTTP_ROUTES: readonly BoardHttpRoute[];

/** The exhaustive `BoardError.code` -> HTTP status table. */
export declare const HTTP_STATUS_BY_CODE: Readonly<Record<string, number>>;
