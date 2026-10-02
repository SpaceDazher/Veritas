# Stopped v10 A: financial reconciliation

Daniil confirmed that the ten wslPI records for 2026-10-02 02:00:00–02:00:59 America/Chicago are complete and unfiltered, including errors and cancellations. Nine are campaign generations already recorded locally. All 25 known campaign generations were independently retrieved through OpenRouter's generation API and match native prompt/completion accounting: **15,856 tokens, provider-reported USD 0**.

The tenth record (gen-1790924425-AX7ftss7HWmZpRnpRnSV) starts at 07:00:25.518Z, before the preceding synchronous campaign generation's first response can arrive according to its reported latency (07:00:28.148Z). Its tool_calls finish and 525,306-token prompt also differ from the campaign's no-tools case calls. No additional provider generation is attributable to attempt 26 in the owner-confirmed complete interval.

This closes financial reconciliation under the owner-confirmed ledger contract. Completeness was attested by Daniil, not verified by a listing API. Provider-reported USD 0 is not an independently audited invoice. The failed attempt's raw CLI transcript was not retained; its runtime failure cause remains unknown.

The original run and sidecar are unchanged. A stays **INFRA**, with 25 of 378 expected predictions, 26 local attempts and UNPARSED 0. No prediction or usage event is invented for attempt 26. B, independent scientific evaluation and paid human acceptance remain **NOT_RUN**.

A further campaign needs a separately signed successor and new clean A/B copies. It must retain the stopped v10 identity. The scoped v9 + v10 campaign total is 23,168 tokens; including the separate diagnostic it is 23,746. Earlier v7 and unrelated coding spend remain outside this reconciliation.

Evidence: evidence/s2-008-campaign/reconciliation-v10-a.json; the two bound provider receipt files; the bound original run and prediction sidecar.
