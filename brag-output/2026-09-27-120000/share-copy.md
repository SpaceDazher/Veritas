# Share copy — Veritas

Angle: evidence before claims. Every number below comes from `facts.json`
(330 commits since 2026-09-09, 98 in the last 7 days, 56,285 LOC, 203 code
files, 80 test files, 7 ordered migrations, busiest day 56 commits on 09-13).

## X / Twitter — the video post

```
Every claim needs a receipt.

Veritas is a bounded agent board: sources become claims, claims get an
independent verdict, and the whole path is recorded. 330 commits in 18 days.

contracts · evidence · verdict

<video> · https://github.com/SpaceDazher/Veritas
```

## X — the thread variant

1. **The claim.** An agent workspace where every claim needs a receipt — 330
   commits in 18 days, 98 of them in the last week.

2. **The mechanism.** Sources → ingestion → claims → synthesis → verdict. Each
   step records provenance; the verdict is an independent check, not a summary
   of the answer you wanted.

3. **The proof.** 80 test files, 7 ordered migrations, 56,285 lines across 203
   code files. The `discovery` command prints the boundary: execution, approval
   and private data all off in demo mode.

4. **The honesty.** The board says no first: missing budget or access blocks
   the task, contracts are hashed not edited, evidence lands in a sealed
   inventory. It refuses to pretend it is production.

5. **The ask.** github.com/SpaceDazher/Veritas — if you build with agents and
   have been burned by "it just ran", tell me what the board should refuse next.

## LinkedIn

```
Most agent demos skip the part where the system says no.

I built Veritas because agent workflows kept running past their budget,
access and contract — and nothing recorded what actually happened.

What it does:
— one shared board where every agent's task, source and evidence live together
— a machine-readable contract that blocks work when budget or access is missing
— every claim lands in a sealed evidence inventory, checked independently

Where it stands: private, 18 days old, 80 test files, no users yet — public
demo mode has execution off on purpose.

https://github.com/SpaceDazher/Veritas
```

## Hacker News

**Title** — Show HN: Veritas – an agent board that refuses to act outside its
contract

**First comment**

Veritas started from a boring annoyance: agent tasks that run past their
budget or access, and no record of what they actually did. So the board
carries its own boundary — a S2-001 contract whose discovery output is
`executionEnabled: false`, `approvalEnabled: false`, `privateDataAllowed:
false`. The task is blocked before anything runs, not audited after.

What is in the repo now: a Next.js board with 7 ordered migrations, a verifier
suite (80 test files — contracts, calibration, db-replay crash and freshness,
security probes), and an evidence layer that reseals an inventory every time
something closes. The busiest day was 56 commits; the whole thing is 18 days
old.

What is missing: real users, real multi-agent integrations, and a licence.
The demo runs synthetic tasks on purpose.

Feedback I want: where should the refusal rules live — the contract, the
board, or the task runner? Demo video and source: https://github.com/SpaceDazher/Veritas

## README release blurb

- v0.1.0: bounded agent board with a S2-001 product contract
- `veritas-cli.mjs discovery` now prints the active limits (execution, approval, private data)
- 7 ordered migrations; run `npm run dev` against a fresh Postgres to bootstrap
- evidence inventory reseals on every closure — no manual step
- demo: https://github.com/SpaceDazher/Veritas · video: `brag-output/2026-09-27-120000/promo.mp4`

## Short captions

- 15 characters: `Veritas receipts`
- 30 characters: `Veritas: bounded agent board`
- 60 characters: `Agent board with a sealed evidence trail — 330 commits, clone it`

## Video caption

`Veritas — every claim needs a receipt.`

## Per-channel checklist

- [x] first line stands alone in a muted autoplay square
- [x] every number appears in `facts.json`
- [x] no claim about users, funding, speed or coverage without a source
- [x] link is the canonical repository or demo URL
- [x] the caption does not repeat the video's on-screen text word for word
