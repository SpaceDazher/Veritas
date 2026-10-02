# Veritas — launch copy (take 2)

Angle: **the history is the audit trail**. Every number below is in
`brag-output/2026-09-27-081119/facts.json`; the SLOQUAL-001 figures are quoted from
`README.md` and marked as such.

---

## X / Twitter — the video post

> 56 commits in one day. Most of them paperwork.

> Veritas is an agent board where a verdict is not a permission: versioned
> sources, atomic claims, cross-domain synthesis, independent verification.
>
> 330 commits in 18 days. The log reads like a notary's diary.
>
> Sources → claims → synthesis → verdict.
>
> <video> · github.com/SpaceDazher/Veritas

## X — the thread variant

1. **56 commits in one day.** That is the busiest day of Veritas (2026-09-13).
   Almost none of them are features. They are `evidence: reseal…`, `chore:
   refreeze the integrity manifest…`, `rebind the closure record`.
2. **That is the point.** Veritas treats its own integrity — tracked-file
   inventory, manifest hashes, closure records — as a tested artefact. The
   commit log *is* the audit trail.
3. **The mechanism.** Versioned sources with provenance → atomic claims →
   synthesis across domains → an independent verifier that scores the result
   against a rubric it did not write.
4. **The honesty.** The public board runs on a synthetic demo fixture
   (`PUBLIC_SYNTHETIC_DEMO`): real adapters, auth and private data deliberately
   off. 330 commits, 80 test files, 56,285 lines — and the README still refuses
   to call it production.
5. **The ask.** S2-007…S2-012 are open: SolutionPack harness, real web/API,
   persistence, pilot acceptance. If you have seen a bounded-autonomy contract
   survive production, I want that story.

## LinkedIn — the post

> My repo has 330 commits in 18 days, and most of them are paperwork.

> I built Veritas because agent platforms turn "the agent finished" into "the
> agent may now act" — and that handoff is where the unverified claim becomes a
> production permission.

> What it does:
> — turns sources into versioned records with provenance, not free text
> — makes every claim atomic, so it can be cited, challenged and closed
> — synthesises across domains, then has an independent verifier score it
> — keeps execution, approval and private data off until a human says so

> Where it stands: 330 commits, 2 authors, 80 test files, 59 contract files,
> 7 ordered migrations. S2-001…S2-006 closed; S2-007…S2-012 open. Public board
> is a synthetic demo by design.

> github.com/SpaceDazher/Veritas

## Hacker News

**Title** — `Show HN: Veritas – 330 commits in 18 days, most of them paperwork`

**First comment** — The paperwork is the product, or half of it. Veritas is an
agent board where a research verdict is explicitly not a production permission,
and the repo holds itself to the same standard: most of its 330 commits are
`evidence: …` and `chore: reseal the integrity manifest …`, with closure
records binding each finished piece of work to its implementation commit.

Technically: one canonical task state shared by the web workspace, the HTTP API
and the CLI; versioned sources → atomic claim graph → cross-domain synthesis →
an independent semantic verifier. `SLOQUAL-001` is a frozen SLO contract
verified across 17 scenarios × 5 seeds and 105 revocation trials in two
independent runs (`README.md`), hard counters at zero — and the README still
says the production SLO is *not* authorised by that.

Missing: S2-007…S2-012 (SolutionPack harness, real web/API, persistence, pilot
acceptance). The demo video is 18.8 s; the screenshot is the live Agent Board
with 13 synthetic tasks across Backlog / Ready / In progress / In review.

Feedback I would use: who has run a bounded-autonomy contract under real load,
and which failure mode surprised you first?

## README release blurb

```markdown
## What's new

- Second cut of the launch film: `brag-output/2026-09-27-081119/promo.mp4`
  (18.8 s) — the "history is the audit trail" angle, ember palette, drift score.
- Same receipts, fresh numbers: 330 commits, 80 test files, 56,285 lines,
  7 ordered migrations, live board screenshot baked in as the poster.
```

Migration step: none. `npm ci && npm run db:migrate && npm run dev`.

## Short captions

- 15: `Veritas — receipts first`
- 30: `Veritas: audit trail as commit log`
- 60: `Agent board with 330 commits of paperwork, verdict still not permission`

## Per-channel checklist

- [x] first line stands alone in a muted autoplay square
- [x] every number appears in `facts.json` (or `README.md`, marked)
- [x] no claim about users, funding, speed or coverage
- [x] link is the canonical repository
- [x] the caption does not repeat the film's on-screen text word for word
