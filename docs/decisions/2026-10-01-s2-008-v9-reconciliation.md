# S2-008 v9: stopped A spend reconciled

Daniil confirmed the complete unfiltered wslPI activity list for 2026-10-01 13:41:00–13:44:59 UTC, including errors and cancellations. All eleven locally recorded generations were verified through the provider generation API. The owner supplied the twelfth Generation ID; its metadata was independently retrieved through the same API.

## Observed accounting

- Eleven local successful usage records: 6,735 native tokens.
- External generation gen-1790862092-qxgqw1Rrl8DGvxXX6i2A: 574 native prompt tokens including 128 cached, plus 3 completion tokens, total 577; provider-reported cost USD 0.
- Total for the twelve correlated v9 A requests: 7,312 tokens, provider-reported USD 0.
- Separate diagnostic: 578 tokens, provider-reported USD 0. Scoped campaign plus diagnostic total: 7,890 tokens. This is not the account-wide usage total.
- The last request started at 13:41:32.379 UTC and took 180,784 ms at the provider. Provider completion was 856 ms after the local run stopped. The signed client timeout remains 180,000 ms.

## Evidence and limits

evidence/s2-008-campaign/reconciliation-v9-a.json is the new immutable spend reconciliation. It binds the original run SHA-256 5958cdead994c3474a0496cf3bd41b2e9a4de31b02cf82075ff67339ac135b20 and sidecar SHA-256 69910f08dbb5d60f1373b58400df8e62c49faf3799e8d0c435ffd2f3a830be63. The original run and partial reconciliation are retained unchanged, including the original erroneous top-level zero. The new record records actual known spend separately.

The generation API confirms the selected generation metadata. Completeness relies on the explicit authenticated owner confirmation. The last ID did not survive in the local arm output; its attribution uses the complete owner log, eleven preceding exact token-pair matches, timing, and the fresh text-only request shape. No exact prompt comparison is claimed. Provider usage metadata does not supply a missing scientific prediction.

## Campaign state and continuation

Spend is RECONCILED; scientific A remains INFRA with eleven recorded predictions out of 378 required model calls. B, independent scientific evaluation, and paid A-MVP-05 human review remain NOT_RUN. No agent acceptance has been entered.

A fresh v10 successor may bind this reconciliation and the tested host accounting fix, then use two clean copies of one tested commit. Frozen science, provider/model, egress allowlist, disabled tools/retries, 180-second per-call timeout, and 5,000,000-token ceiling independently per A/B are preserved. The stopped v9 identity must not be retried or overwritten. A new unknown outcome stops execution and requires its own reconciliation.
