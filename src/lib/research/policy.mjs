// S2-008 research track — THE POLICY MODULE. RESERVED FILE, NO EXPORTS YET.
//
// Issue SpaceDazher/Veritas#8. Serves acceptance items A1, A2, A4 and A5 as
// the single home of the transition guards the research ledger is allowed to
// record, and of the negative-probe refusal table.
//
// OWNER: W4 (policy, probes, harness). Budget: part of W4's <= 1,100 lines.
// Status: RESERVED. This file intentionally exports nothing.
//
// WHY IT HAS NO EXPORTS
// The judged plan is explicit in two directions that collide here, and this
// file resolves the collision by NOT choosing:
//   * §1 "Frozen module interface list (authoritative — do not invent or
//     rename)" freezes ELEVEN module interfaces. This file is not one of them.
//   * §2 assigns `src/lib/research/policy.mjs` to W4, and the R1 graft calls it
//     "one policy module".
// The skeleton's rule is that a name is either frozen by the plan or it is not
// written down. Adding a `POLICY_VERSION`-style placeholder here would
// manufacture a public name the plan never froze, and the first thing that
// name would do is appear in `index.mjs` and in the evidence records — i.e. it
// would become de facto frozen by accident, which is exactly the kind of
// silent divergence this track exists to prevent. The file therefore exists
// (so ownership is unambiguous and W4 is not blocked by a missing path) with a
// header that states the gap, and nothing else.
//
// The body a stub would normally carry — `throw new Error('NOT_IMPLEMENTED:
// <name>')` — is also absent, because a module-level throw on import would
// break any consumer that imports this path before W4 fills it, and because
// there is no frozen `<name>` to hang it on. Every other skeleton file in
// `src/lib/research/` DOES carry its NOT_IMPLEMENTED bodies; this one is the
// single documented exception, recorded here rather than silently.
//
// WHAT W4 OWNS, AND WHERE THE NAMES MUST COME FROM
// The guard names are NOT free. They are the `guardName` values of
// `RESEARCH_TRANSITIONS` in `src/lib/research/constants.mjs` (W1's file),
// which mirrors the frozen board table at
// src/lib/agentboard/constants.mjs:40-74. W4 implements exactly those names,
// one exported function per edge, with this shape — the shape of
// `src/lib/agentboard/policy.mjs`, which is the sibling this track mirrors:
//   guardName(fromState, toState, context) -> void
//   throws the closed `BoardError` from src/lib/agentboard/errors.mjs (via
//   `refusalClass`) when the edge is not authorized in `context`.
// Rationale for a guard PER EDGE rather than a table of booleans: a boolean
// table is a second copy of `RESEARCH_TRANSITIONS`, and a second copy of a
// transition table is a second, independently editable authorization path —
// the "an in-memory store that roughly implements the same rules" failure the
// board explicitly refuses at src/lib/agentboard/store.mjs.
//
// WHAT MUST NOT BE ADDED HERE
//   * No verdict logic. Campaign verdicts are named only by `resolveVerdict`
//     (src/lib/sloqual/comparator.mjs:237) via comparator.mjs; trial verdicts
//     only by `resolveTrialVerdict`. A verdict function in policy.mjs would be
//     a second, silently divergent verdict layer.
//   * No statistics. `src/lib/sloqual/**` is imported, never forked, never
//     edited by this track.
//   * No clock reading. No `Date.now()`, no `Math.random()`, no argument-less
//     `new Date()`; the clock is injected and lives in preregistration.mjs.
//   * No persistence. The ledger's write disciplines live in registry.mjs and
//     nowhere else.
//   * No new id prefixes. The frozen `ID_PREFIXES`
//     (src/lib/agentboard/constants.mjs:201) is read-only; the research
//     vocabulary is `RESEARCH_ID_PREFIXES` in constants.mjs.
//
// IF W4 NEEDS A NAME THE PLAN DID NOT FREEZE
// Report it rather than inventing one: **BLOCKED:** to D, with the reason. A
// name that the plan did not freeze but the code needs is a plan defect, and
// it gets fixed in the plan or reviewed as a re-freeze — not quietly settled
// in a file nobody reads twice.
