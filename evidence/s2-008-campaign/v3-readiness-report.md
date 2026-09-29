# S2-008 v3 readiness, 2026-09-29

## Request and changes

The owner asked to perform the S2-008 steps and record the approval as Daniil.
The Linux checkout is `/home/daniil/Veritas`.

- Restored the disposable rootless Podman wrapper, added `scripts/setup-podman-tmp.sh` and documented how to source it after a reboot.
- Tightened the draft token cap from 100,000,000 to 5,000,000. The measured plan is 3,865,734 tokens, so the cap allows about 29% headroom.
- Issued the v2 approval as `prn-s2007r-owner`, label `Daniil (repository owner)`. It is signed but never entered into force: its frozen trial list names three old arms while its declared arms name one model arm. The model arm refused it with exit 9, `PREREGISTRATION_NOT_IN_FORCE`.
- With the owner's explicit approval for a new scientific version, created v3. Trial 01 uses the model; trials 02 and 03 retain the old control predictors. The metric, baseline, band, multiplicity rule, stopping rule, seeds, and holdout policy are unchanged. The changed trial list and token budget are named in a new frozen table and SUPERSESSION.
- Issued v3 approval as `prn-s2007r-owner`, label `Daniil (repository owner)`, then sealed it through `prepare.mjs --seal-v3`. The manifest points to digest `39d0b37a1aa3585f1aead90820b0d0b858b726ef875561cfe3b4934e5d2c3103`. The v1 document and original ledger remain on disk. The new ledger has three entries.
- Prevented the legacy v1 runner and default v1 prepare path from silently running or replacing the v3 manifest.
- Fixed the default `spawnSync` adapter in credential provisioning. The z.ai key was passed from local auth storage via stdin into Podman secret store under `sec-veritas-executor-credential`; no value was placed in argv or this report.
- Built the model image twice with `--timestamp 0`. Both builds produced Id `sha256:88229bc4d654b7198bc975c2fe699a6118fa8c55ab725b9e088a81786e6cc52b` and Digest `sha256:f85902b737b9148426f3ed354fc0ca21c5881359fb2af58535d6a1546dd0125b`. Full source and pin evidence is in `model-image-pin-v3.json`.
- Ran the model arm inside that image with the isolation launcher in dry-run mode: 126 predictions, `DRY_RUN`, zero model calls, zero tokens, exit 0.

## Verification

- `node scripts/s2-008-campaign-prepare.mjs --check`: `ok: true`.
- `node --test tests/research/*.test.mjs`: 281 passed, 0 failed.
- Focused credential and v3 guard tests: 11 passed, 0 failed.
- `npm run lint`: exit 0.
- `git diff --check`: exit 0.
- A default v1 prepare attempt returned `V3_IN_FORCE_REFUSES_V1_REBUILD` and left the manifest SHA-256 unchanged.
- The model image container dry-run returned `network: deny_all`; this is evidence that no paid call occurred.

## Open work and stop condition

The paid campaign, independent model-outcome evaluation, and A-MVP-05 human review were not performed. The current isolation profile says `network.policy: deny_all` and launches with `--network=none`; no working allowlisted egress proxy is present. The existing campaign runner charges container launches rather than measured tokens and invokes the old regex adapter. The existing evaluator also recomputes only regex arms. Sending a paid call through that path would bypass the signed token budget and mislabel the measurement. A model-aware runner, a controlled egress path, credential delivery into that runtime, and an evaluator over recorded model predictions must be implemented and verified before any paid call. The new image pin is recorded in evidence, not inside the already signed v3 body. If a contract requires the image digest inside preregistration, issue a new signed version before execution.
