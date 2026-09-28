# Veritas — promo plan

**Angle:** a research verdict is not a production permission — Veritas makes every
claim carry its receipt.
**Hook:** `EVIDENCE BEFORE CLAIMS` + one line: **"Every claim needs a receipt."** No
context needed, reads as a thumbnail, and the board's own UI says the same thing in
its own words ("One shared board. Every agent. One source of truth.").
**Why this project:** the honest tension *is* the product. The commit history is not
feature work, it is `evidence: reseal…`, `chore: refreeze the integrity manifest…`,
`rebind the closure record`. A platform whose history is the audit trail, whose CLI
prints `"mode": "PUBLIC_SYNTHETIC_DEMO"` before you ask a question, and whose README
refuses to call itself production-ready.
**Tone:** dead-serious-founder · **Palette:** `paper` (the app's own cream + deep green
+ brick — `accent` brick, `accent2` green) · **Music:** `minimal` — sub bass and bells,
no drums @ 96 bpm, root 40
**Length:** 20.0 s + 0.8 s brand card · **Format:** landscape 1080p30 · **Loop:** yes

Every number below is from `facts.json` (`git.*`, `code.*`) or from the repo itself
(`migrations/`, `contracts/`, live CLI). Nothing invented.

| # | Scene | Kind | On screen | Source | Dur | Transition | SFX |
|---|-------|------|-----------|--------|-----|-----------|-----|
| 1 | Hook | `title` | `EVIDENCE BEFORE CLAIMS` / **Every claim needs a receipt.** / versioned sources · atomic claims · independent verification / badge `S2-001 → S2-006` | README headline | 2.4 | — | impact |
| 2 | Proof | `stat` | **330** commits · label `in 18 days` · items: 80 test files · 54,690 LOC · 7 ordered migrations | `git.totalCommits`, `git.firstCommit`, `code.testFiles`, `code.loc`, `migrations/*.sql` | 2.4 | dissolve | pop |
| 3 | The thing | `image` | live Agent Board, 1920×1080, caption `One shared board. Every agent. One source of truth.` | `board.png` (live app on :3100, captured this run) | 2.8 | push | whoosh |
| 4 | Pipeline | `flow` | Sources → Ingestion → Claims → Synthesis → **Verdict** | README architecture block | 2.6 | wipe | sweep |
| 5 | It says no | `code` | verbatim CLI output: `"mode": "PUBLIC_SYNTHETIC_DEMO"`, `"executionEnabled": false`, `"approvalEnabled": false` | `VERITAS_URL=… node scripts/veritas-cli.mjs discovery` (run this session) | 2.6 | dissolve | type |
| 6 | Method | `features` | Fail closed · Frozen contracts · Tracked evidence | README + git subjects | 2.6 | push | card |
| 7 | Momentum | `commits` | 26-week grid, `98 commits in the last 7 days` | `heatmap.levels`, `git.commits7d` | 2.2 | dissolve | tick |
| 8 | CTA | `outro` | **Veritas** / evidence before claims / `github.com/SpaceDazher/Veritas` / `clone · read the evidence` | `git.remote` | 2.4 | zoom | impact |

**Ending:** brand card that cuts back to the title frame, so the film loops.

**Not using in the film (goes in the copy):** 2 authors · 56 commits on the busiest
day (2026-09-13) · 200 code files · 59 contract files · 74 evidence files · 749 tracked
files. The SLOQUAL-001 numbers (17 scenarios × 5 seeds, 105 revocation trials) live in
`README.md`, not in `facts.json`, so they stay out of the rendered frames and go into
`share-copy.md` with a README trace.
