# S2-006M-P1 — OpenRouter diagnostic pilot (partial)

This is **not** independent calibration, a gold corpus, or an S2-006 verdict.
The owner expressly permitted short YouTube podcast excerpts to be sent to
`poolside/laguna-s-2.1:free` despite the provider's notice that free inputs and
outputs may be used for training. The canonical S2-006 provider-grant and
no-training rules were not weakened; this standalone pilot never calls its
verifier or `deriveVerdict`. Raw transcripts and model answers stay outside Git.

## Boundary and actual run

- Model: `poolside/laguna-s-2.1:free`, no fallback; one request per case.
- Input: one preselected ACCEPT case per episode/template, short claim and
  supporting quote only. Archive SHA-256 is checked before extraction. Quoted
  material is marked untrusted in the prompt. The model judges quote-to-claim
  attribution only, not world truth.
- Output: strict local JSON parser; no model answer becomes a gold label.
  Reports contain result metadata and model concerns, not input quotes or key.
- The synthetic connectivity request returned HTTP 200 and `OK.` from the
  pinned model. The two-case smoke run completed with two structurally valid
  `SUPPORTED` diagnostics. The 21-case attempt received HTTP 429 on its first
  request and stopped without retry or fallback. These are observed facts, not
  a claim that the model is well calibrated or that the account's daily quota
  was the cause of 429.
- Official S2-006 remains `NEEDS_INPUT`; independence and semantic performance
  statistics remain `NOT_MEASURED`.

The local reports are at
`D:/Project/AgentOS/.tmp/s2-006m-pilot-smoke.json` and
`D:/Project/AgentOS/.tmp/s2-006m-pilot-full.json`. Their SHA-256 digests and
metadata-only counts are recorded in `evidence/s2-006m-provider-pilot.json`.
The full-run file predates the runner's explicit `runStatus` field; its
`requestedCases=21`, `completedCases=1`, and HTTP 429 establish partial status.
The runner now returns a nonzero exit code for partial runs.

## Reproduction and limits

Run `node --env-file=.env.local scripts/s2-006m-pilot.mjs` with
`--allow-training`, `--v05`, `--ah6`, `--xuo`, and `--output` pointing to a new
file **outside** the Veritas Git tree. `--max-cases` defaults to 21. The runner
refuses to overwrite an existing report. A key in `.env.local` is ignored by
Git; it must not be copied into commands, logs, Git, or owner-inputs. Do not
repeat the full attempt blindly after HTTP 429. Check OpenRouter's account
limits first; a later run must use a new output path and its own evidence.

## TDD and checks

| Guarantee | RED | GREEN |
| --- | --- | --- |
| Pinned free model, consent gate, bounded quote, validated output, archive binding, no secret in report | `node --test tests/verifier/model-pilot.test.mjs` failed: runner module missing | 8/8 tests passed |
| Partial rate-limited run is explicit, not success | Same test failed: expected `PARTIAL_RATE_LIMITED`, got undefined | Same test 8/8 passed; CLI sets exit code 2 |

Focused coverage: `node --test --experimental-test-coverage
tests/verifier/model-pilot.test.mjs` — runner lines 91.07%, functions 82.61%,
branches 82.61%. The live-success CLI path and several malformed archive
variants are not unit-covered; live smoke and offline archive loading were
exercised separately. No claim of production readiness follows from these
tests.

Provider source: <https://openrouter.ai/poolside/laguna-s-2.1:free>.
