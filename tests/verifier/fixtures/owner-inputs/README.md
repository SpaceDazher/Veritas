# Owner-inputs fixture package (SYNTHETIC — path-conductivity proof only)

**This package is a test-only, synthetic proof that the validated owner-inputs
path of `scripts/s2-006-run.mjs` (`--owner-inputs <dir>`) is programmatically
passable end to end. It is NOT a production corpus, NOT real independent
labeling, and NOT a real method-owner decision.**

Every principal in this package (`prn-owner-annotator-a`, `prn-owner-annotator-b`,
`prn-owner-adjudicator-1`, `prn-owner-method-owner-1`,
`prn-owner-verifier-owner-1`) is synthetic. Every HMAC secret used for the
annotation-set signatures, the adjudicator attestation and the threshold-authority
grant is the public in-repo fixture material (`s2-006-fixture-hmac-key`
convention, see `tests/verifier/fixtures/keys.json`). The `MEASURED` external
stratum status and the all-true independence axes exist to exercise the loader's
white-list and tier resolution — they must never be read as a production claim
of real-world independence (spec §3: synthetic principals prove policy
mechanics only; one process playing several roles creates no independence).

## Contents

| file | validated against |
| --- | --- |
| `external-manifest.json` | frozen `contracts/annotation-manifest.schema.json` (loader white-lists `externalStratum.status` ∈ {`READY`,`MEASURED`} without touching the schema); every other field must pass the frozen schema as-is |
| `cases/case-owner-ext-*.json` | frozen `contracts/corpus-case.schema.json` (`case` sub-object) + byte digests + `textDigest` binding |
| `annotation-sets/*.json` | frozen `contracts/annotation-set.schema.json` + signature MAC over `annotationSetBindingDigest` |
| `adjudication.json` | frozen `contracts/adjudication-record.schema.json` + adjudicator attestation MAC over the record attestation digest + manifest/rubric/thresholds version bindings |
| `thresholds.json` | canonical thresholds layout (optional file: an owner-authored preregistration version; without it the run binds to the in-repo `contracts/s2-006-thresholds.json`) |
| `threshold-decision.json` | frozen `contracts/human-decision.schema.json` via `calibration.resolveThresholdDecision`: owner=user, APPROVED, bound to the exact canonical digest of `thresholds.json`, grant resolvable from the operator-side registry |
| `independence.json` | frozen `evaluator_independence` subschema of `contracts/calibration-record-v2.schema.json` + cross-checks against the annotation-set/adjudication principals |

Conventions this package is generated against (enforced fail-closed by the
loader in `scripts/s2-006-run.mjs`):

- `sourceDigest` of every annotation set = SHA-256 of the
  `external-manifest.json` bytes (the frozen corpus-source bytes the labels
  refer to).
- The adjudicator attestation (`attestationDigest`) = HMAC-SHA256 by the
  adjudicator principal over
  `adjudicationAttestationDigest(record)` = the canonical-json digest of the
  decision-bearing record fields (identity block and audit reference
  excluded), with the custody keyRef
  `kms://fixture/s2-006/owner-inputs/adjudicator/<principalId>`.
- `implementation_digest` in `independence.json` is declared structural data
  and is intentionally not cross-checked against live implementation bytes;
  run-identity digests are enforced separately by the comparator (Run A/B
  manifest digests).

## Expected pipeline outcome

The two sealed candidate runs agree; the comparator passes; calibration over
the 6 synthetic external cases measures `citation_entailment_f1 = 0.8`
(ext-06 is adjudicated to `INSUFFICIENT_EVIDENCE`), which fails the authored
`>= 0.9` soft threshold, so `decideLexicographic` resolves to `HUMAN_REVIEW`
(inconclusive) — a verdict other than `NEEDS_INPUT`, proving the path exits
the honest `NEEDS_INPUT` state without any code edit.

Tampered copies of this package (bad signature, invalid manifest, decision not
binding to the thresholds digest, missing file) must fail closed at
`loadOwnerInputs()` and never fall back to fixture-only behavior.
