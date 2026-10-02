# S2-008 campaign v6 execution

V6 is a historical operational supersession of signed v5. Its first A seed
stopped with INFRA because pi requires ZAI_CODING_CN_API_KEY while v6 supplied
ZAI_API_KEY. The original failure is immutable; a separate deny-all replay and
pinned-runtime auth guard reconcile its model spend as zero. V7 corrects delivery.
Frozen scientific members and
the frozen v3 table remain unchanged. Daniil authorized preparation and signature.

## Signed execution policy

- 5,000,000 recorded tokens per complete run A or B; disclose the aggregate separately.
- 180,000 ms per model call; 126 blind cases per model container.
- 300,000 ms for bridge startup and report completion.
- 22,980,000 ms per seed container: 126 * 180,000 + 300,000.
- Disable pi tools, extensions and skills.
- Bind the complete staged pi runtime tree and timeout-policy source in the image commitment.
- Token accounting sums assistant usage from the final agent_end messages.
  The reported USD cost is a pi price-table estimate, not a provider invoice.
- Reject paid launches on an unknown or dirty source base, missing/invalid expiry,
  an invalid authorization clock, or an expired reservation.
- Stop before the next call when recorded spend reaches the ceiling. An in-flight
  request may cross the ceiling; retain its actual usage and stop with a nonzero code.

## Reproducible host and image procedure

Use scripts/setup-podman-tmp.sh to select the repository Podman store and restore
its digest-pinned bases. This setup must preserve existing images and secrets.

The preseal generator and final pin writer each require two matching builds.
The preregistration is excluded from the content commitment to avoid a circular
digest, but its exact bytes are copied into the final image and recorded by the pin.

Public preregistration JSON must be readable by the image's unprivileged uid.
Credential env files remain 0600 and are delivered by path; never put a key in argv.

## Execution and evidence

Run the actual-image dry-run first:
node scripts/s2-008-campaign-run.mjs --v6 --arm arm-model-zai-glm53flash --dry-run

It must report three DRY_RUN outcomes, zero model calls and zero tokens.
A proposed separate paid connectivity call was NOT_RUN: automatic approval
review rejected the additional external holdout payload. The authorized A/B
campaign itself must provide the real credential/proxy-route evidence.

Run A and B from the same clean commit/tree. Temporarily stage A's generated
evidence outside the repository while B starts, then restore its exact bytes.
Keep all outcomes and UNPARSED predictions. Never replace unknown usage with zero
or silently retry an execution whose spend is unresolved.

Generate the seven campaign probes with an explicit active preregistration path.
The evaluator requires their matching preregistration digest and commit/tree, plus
fresh security probes and negative controls from the same base. Missing, duplicate,
foreign, failed or inconsistent records block evaluation.

Labels are opened once, after both blind runs are complete and evidence preflight
passes. Preserve a scientific refusal, including seed-rate movement, as a result.
A/B equality is additional evidence; independent table agreement remains required.
A-MVP-05 remains a human review and cannot be closed by an agent.
