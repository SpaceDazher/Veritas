# Veritas — launch copy

Angle: **evidence before claims**. Every number below is in
`brag-output/2026-09-27-024608/facts.json`; the SLOQUAL-001 figures are quoted from
`README.md` and marked as such.

---

## X / Twitter — the video post

> Every claim needs a receipt.

> Veritas is a research and engineering platform where a claim is a record, not a
> sentence: versioned sources, atomic claims, cross-domain synthesis, independent
> verification. A research verdict is explicitly *not* a production permission.
>
> 330 commits in 18 days. 80 test files. 54,690 lines. 7 ordered migrations.
>
> Sources → claims → synthesis → verdict.
>
> <video> · github.com/SpaceDazher/Veritas

*(243 characters before the link.)*

## X — the thread variant

1. **A verdict is not a permission.** Most agent platforms let a "done" task become a
   granted capability. Veritas refuses to: research output stays research until
   something independent signs off.
2. **The mechanism.** Versioned sources with provenance → atomic claims → synthesis
   across domains → an independent verifier that scores the result against a rubric
   it did not write.
3. **The proof is in the history, not the README.** 330 commits in 18 days. The
   subjects are `evidence: reseal…`, `chore: refreeze the integrity manifest…`,
   `rebind the closure record`. The audit trail *is* the commit log.
4. **The limits are printed before you ask.** `node scripts/veritas-cli.mjs
   discovery` answers with `"mode": "PUBLIC_SYNTHETIC_DEMO"`,
   `"executionEnabled": false`, `"adapters": []`, `"privateDataAllowed": false`.
   No pretending to be production.
5. **What I want.** S2-007…S2-012 are open: SolutionPack harness, web/API, R&D,
   persistence, pilot acceptance. If you have opinions on bounded autonomy
   contracts, I would like to hear them.

## LinkedIn — the post

> The interesting part of Veritas is the part it refuses to do.

> I built it because the usual agent platform turns "the agent finished" into "the
> agent may now act" — and that handoff is exactly where the unverified claim
> becomes a production permission.

> What it does:
> — turns sources into versioned records with provenance, not free text
> — makes every claim atomic, so it can be cited, challenged and closed
> — synthesises across domains, then has an independent verifier score the result
> — keeps execution, approval and private data switched off until a human says so

> Where it stands: 18 days old, 330 commits, 80 test files, 54,690 lines, one
> maintainer. S2-001…S2-006 closed; S2-007…S2-012 open. The public board runs on a
> synthetic demo fixture — real adapters and auth are deliberately not wired yet.

> github.com/SpaceDazher/Veritas

## Hacker News

**Title** — `Show HN: Veritas – an agent board where a research verdict is not a production permission`

**First comment** — The board, the CLI and the HTTP API all run on the same canonical
task state; the CLI tells you which mode you are in before it does anything
(`"mode": "PUBLIC_SYNTHETIC_DEMO"`, `"executionEnabled": false`), because the failure
mode I kept hitting in earlier attempts was an agent platform that quietly assumed
production.

The part I did not expect to spend the time on: the commit history. Most of the 330
commits are `evidence: …` and `chore: reseal the integrity manifest …` — the repo
treats its own integrity (tracked-file inventory, manifest hashes, closure records)
as a tested artefact rather than a chore. `SLOQUAL-001` is a frozen SLO contract
verified across 17 scenarios × 5 seeds and 105 revocation trials in two independent
runs (`README.md`), with hard counters at zero — but the README is explicit that the
production SLO is *not* authorised by that.

What is missing: S2-007…S2-012 — the SolutionPack harness, real web/API surface,
R&D loop, persistence and pilot acceptance. The public board is a synthetic demo;
real adapters, authentication and private data are off on purpose.

Feedback I would actually use: does anyone have a real example of a bounded-autonomy
contract that survived contact with production? Mine is built from a paper workspace
and may be missing the failure modes that only show up under load.

<video> · one screenshot: the Agent Board with 13 synthetic tasks across
Backlog / Ready / In progress / In review.

## README release blurb

```markdown
## What's new

- Public launch of the Veritas Agent Board: one canonical task state shared by the
  web workspace, the HTTP API and the CLI, with execution, approval and private data
  off by default (`"mode": "PUBLIC_SYNTHETIC_DEMO"`).
- 330 commits across S2-001…S2-006: versioned sources, atomic claims, cross-domain
  synthesis, an independent verifier and 7 ordered SQL migrations, covered by 80
  test files.
- SLOQUAL-001 is frozen and verified — 17 scenarios × 5 seeds, 105 revocation
  trials, hard counters at zero. The production SLO is not authorised by this.
- Demo: the 20-second film in `brag-output/2026-09-27-024608/promo.mp4`.
```

Migration step: none. `npm ci && npm run db:migrate && npm run dev`.

## Short captions

- 15: `Veritas — evidence first`
- 30: `Veritas: an agent board with hard limits`
- 60: `Agent board that refuses to fake production, 330 commits in 18 days`

## Per-channel checklist

- [x] first line stands alone in a muted autoplay square
- [x] every number appears in `facts.json` (or `README.md`, marked)
- [x] no claim about users, funding, speed or coverage
- [x] link is the canonical repository
- [x] the caption does not repeat the film's on-screen text word for word
