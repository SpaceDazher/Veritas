# Owner-inputs fixture package (SYNTHETIC — negative fixture only)

**This package is deliberately insufficient.** It is a test-only fixture for
fail-closed parsing and tamper tests. It has six cases, uses public in-repo
fixture material and does not carry operator trust anchors. It MUST NOT advance
the aggregate verdict beyond `NEEDS_INPUT`.

Every principal in this package (`prn-owner-annotator-a`, `prn-owner-annotator-b`,
`prn-owner-adjudicator-1`, `prn-owner-method-owner-1`,
`prn-owner-verifier-owner-1`) is synthetic. Every HMAC secret used for the
annotation-set signatures and the adjudicator attestation is public in-repo
fixture material. The `MEASURED` external-stratum claim and the all-true
independence axes are hostile assertions: the loader must still reject the
package because a claim inside an untrusted package cannot establish authority,
key custody, independence or sample sufficiency.

## Contents

| file | validated against |
| --- | --- |
| `external-manifest.json` | `contracts/annotation-manifest.schema.json`; the original object is validated without status rewriting |
| `cases/case-owner-ext-*.json` | frozen `contracts/corpus-case.schema.json` (`case` sub-object) + byte digests + `textDigest` binding |
| `annotation-sets/*.json` | frozen `contracts/annotation-set.schema.json` + signature MAC over `annotationSetBindingDigest` |
| `adjudication.json` | frozen `contracts/adjudication-record.schema.json` + adjudicator attestation MAC over the record attestation digest + manifest/rubric/thresholds version bindings |
| `thresholds.json` | canonical thresholds layout (optional file: an owner-authored preregistration version; without it the run binds to the in-repo `contracts/s2-006-thresholds.json`) |
| `threshold-decision.json` | `contracts/human-decision.schema.json`; its grant reference is intentionally not trusted merely because the package names it |
| `independence.json` | frozen `evaluator_independence` subschema of `contracts/calibration-record-v2.schema.json` + cross-checks against the annotation-set/adjudication principals |

Conventions checked fail-closed by `scripts/s2-006-run.mjs`:

- `sourceDigest` of every annotation set = SHA-256 of the
  `external-manifest.json` bytes (the frozen corpus-source bytes the labels
  refer to).
- The adjudicator attestation (`attestationDigest`) = HMAC-SHA256 by the
  adjudicator principal over
  `adjudicationAttestationDigest(record)` = the canonical-json digest of the
  decision-bearing record fields, including the audit reference, with the custody keyRef
  `kms://fixture/s2-006/owner-inputs/adjudicator/<principalId>`.
- `implementation_digest` in `independence.json` is declared structural data
  and is intentionally not cross-checked against live implementation bytes;
  run-identity digests are enforced separately by the comparator (Run A/B
  manifest digests).

## Expected pipeline outcome

`loadOwnerInputs()` rejects this package for both missing independent trust
context and fewer than 20 eligible locked-test cases after family/template
deduplication. Supplying a trust file from inside this directory is also
rejected. A positive owner run requires both `--owner-inputs <dir>` and a
separate, local-only `--owner-trust <file>` validated by
`contracts/owner-trust-bundle.schema.json`; fixture-grade trust is refused.

Tampered copies (bad signature, invalid manifest, split-family leakage,
decision/digest mismatch or missing file) must fail closed and never fall back
to fixture-only behavior.
