# Canonical verifier fixtures (S2-006 fix wave A1, review P1-1)

These four documents are CANONICAL, schema-valid producer artifacts. Every
test that uses them first compiles the frozen schemas with Ajv (draft
2020-12) and validates the fixture bytes against
`contracts/<kind>.schema.json` BEFORE any verifier call — the verifier must
accept producer-canonical form with no second internal format.

- `claim.json` — S2-004 claim (frozen `contracts/claim.schema.json`).
  `canonical_digest` is the REAL `canonicalDigestOfClaim` value
  (`src/lib/claims/validation.mjs`) over this exact record, computed at
  fixture-authoring time. No placeholder digests.
- `evidence-map.json` — S2-005 EvidenceMap: ONE checkable statement at map
  level; `entries[]` cite claims via snake_case `claim_id`/`claim_revision`
  plus `segment_id`/`span`/`quote_digest`. Quote digests are real SHA-256
  values over the exact quoted segment texts.
- `hypothesis-card.json` — S2-005 HypothesisCard: the checkable proposition
  is the `proposed_relation` triple (CORRELATION_EVIDENCE,
  `causal_assertion: null`); `nodes[]`/`counterevidence[]` are citations.
- `synthesis-result.json` — S2-005 SynthesisResult embedding the same map
  and card by `$ref`; `request_digest` is the real canonical-json digest of
  the synthesis request echo `{ requested, result_id }`.

The JSON files deliberately carry NO extra fields: the frozen schemas are
`additionalProperties: false`, so provenance notes live here, not inline.
