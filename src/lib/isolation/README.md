# `src/lib/isolation/` — the S2-002 A-MVP-04 isolation tree

Issue `SpaceDazher/Veritas#12`, clause **A-MVP-04**, "изоляция — образ, allowlist,
secret handles". This tree is the part of that clause which the S2-007R record
left open: a genuinely installed executor, running inside an isolation profile,
with all four allowlist axes enforced and its credential arriving as a descriptor.

## Why this tree exists rather than a change to `src/lib/identity/`

`scripts/validate-contracts.mjs:118-134` lists `src/lib/identity`,
`tests/identity` and `src/lib/agentboard` as `frozenTargets`. Every byte in them
is hashed into `evidence/frozen-manifest.json`, so changing one requires an
explicit reviewed freeze — the operation the S2-007R line owns, and the one that
must not be disturbed while it is sealing.

The repository has already met this problem once and recorded the answer.
`src/lib/executors/README.md`, decision **D1**: "places the real executors in a
new tree precisely so the frozen unit is not re-opened". This tree is that answer
for the image.

`contracts/sandbox-profile.schema.json` is **not read, parsed or written** here.
The four-axis shape is mirrored as executable predicates in `profile.mjs`, so a
change to the contract and a change to this tree are two diffs a reader compares,
rather than one change that arrives through an import. Nothing in this tree is a
frozen target, so this work needs no re-freeze and cannot break an in-flight seal.

## The four axes, and where each one is actually enforced

| axis | declared in | enforced by | measured on this host |
| --- | --- | --- | --- |
| network | `network.policy` + `allowlist` | the kernel (`--network=none`) plus, for `allowlist`, one mounted forwarder socket | `/proc/net/route` inside the container has **0 rows**; `connect(443, open.bigmodel.cn)` answers `EAI_AGAIN`, exit 7 |
| filesystem | `filesystem.roots`, `writable_tmpfs`, `root_fs_read_only` | the kernel (`--read-only` + `--tmpfs`) | a write to `/etc` returns `EROFS`; a write to `/tmp` succeeds |
| environment | `environment.allowlist` + `fixed` | **this code** — the child env is built from the profile and no `process.env` is read on that path | operator `HOME=/home/daniil` → container `HOME=/tmp` (the profile's literal); a planted variable is `absent` |
| process | `process.max_processes`, `memory_mb`, `nano_cpus` | cgroup v2 and the pids controller | the flags are in the argv the kernel received. **A breach was not provoked** — the record says so in `axes.process.not_independently_measured` |

`deny` is the default on all four. A wildcard (`'*'`) is not a value any
executable profile may carry, and `network.policy: 'unrestricted'` is refused as
a policy, even though the contract permits it for `HOST_UNISOLATED`.

## `HOST_UNISOLATED` is not one of these

`EXECUTABLE_TIERS` is `['LOCAL_RESTRICTED', 'UNTRUSTED_CODE']`.
`NON_EXECUTABLE_TIERS` is `['NO_EXEC', 'HOST_UNISOLATED']`, and
`assertExecutableProfile` refuses both before anything is spawned.

`HOST_UNISOLATED` exists, per the S2-007R record, so a host that cannot execute a
model-calling agent inside an isolation profile can still be **recorded**
truthfully: it declares `unrestricted` network and an all-environment allowlist
precisely as the controls it lacks. That is a statement about a host, not a
launch authorisation. Treating it as an isolation tier is the one substitution
this tree exists to make impossible, so it is refused by name in
`assertExecutableProfile`, refused again in `assertNoWildcard` as a policy value,
and asserted by the `NON_EXECUTABLE_TIER_REFUSED` control on every run.

## The two image pins, and why there are two

`BASE_IMAGE` is a **registry digest** (`docker.io/library/node@sha256:25330af3…`,
the `linux/amd64` manifest). It is portable; every host pulls that exact digest.

`EXECUTOR_IMAGE` is a **derived image digest** — the base plus the host's real
installed executor, built by `scripts/s2-002-isolation-image.mjs` with
`--timestamp 0`. Buildah stamps layers with the wall clock by default, so two
builds of identical content get different digests; zeroing the timestamp makes the
digest a function of content, and two independent runs were measured to produce
the identical `Id` and `Digest`. That is what makes it a pin.

It is still the narrower of the two: it is only as good as the executor tree it was
built from, and that tree (14 014 files) is **not committed**. It is digested where
it is installed and recorded as `executor_tree_sha256`, and a host whose
installation hashes differently is **refused** rather than measured against
someone else's pin. The pin and its provenance are two constants next to each
other so they move together or not at all.

An earlier derived image here was built with a throwaway `Containerfile` and no
`--timestamp 0`. It was gone from the podman store an hour later, because a locally
built image nobody pulls is what a maintenance pass collects. The run script
refused to launch anything once that happened, which is the behaviour a pin is for.

## Secrets are handles

```
podman secret create sec-veritas-executor-credential <path>
podman run --secret sec-veritas-executor-credential …
```

The launch argv carries a **name**; the value is in podman's secret store and is
reachable inside the container only at `/run/secrets/<handle>`. Measured from
inside the container: the descriptor resolves (`VERITAS_SECRET_PRESENT=true`), the
container reports the credential's **length** and never its value, and the value
appears in no environment variable, no argument, no stream and no record.

Podman 4.9.3 caveat, recorded rather than discovered later: the newer inline form
is refused (`--secret=id=…,src=…` → `Error: option id=… invalid: parsing secret`,
exit 125) and a bare `src=…` is parsed as a secret *name*. Only the store-backed
name works, and `SECRET_ERRORS.PODMAN_SECRET_FORM` names the form so a podman
upgrade does not change the semantics silently.

The run does not merely avoid leaking — it **looks**.
`assertNoSecretLeak` is handed every surface the value could have reached and
fails the run if it is in any of them, including the record bytes. A detector that
has never fired is indistinguishable from one that cannot fire, so the run plants
the value in a throwaway surface and requires the detector to report it
(`detectorSelfCheckPassed`).

The value delivered to the container is a **synthetic canary literal in
`scripts/s2-002-isolation-run.mjs`**. No dotenv file, no environment variable and
no credential store is read anywhere in that script. That is what makes it safe to
commit and safe to print: there is nothing there to leak. What is measured is the
descriptor mechanism, not a real key.

## Why the network allowlist needs a forwarder

Rootless podman cannot express `network.policy: 'allowlist'`. Measured:
`--network=slirp4netns` installs a default route to `10.0.2.2` for **every**
destination, and a `connect()` to an arbitrary host succeeds. A profile naming one
host would be naming something the runtime does not enforce.

The pairing that makes it real:

* `--network=none` → the container has no route at all (measured: 0 rows);
* one bind-mounted unix socket the launcher chose;
* a `CONNECT` forwarder that admits exactly the profile's `{host, ports}` and
  refuses everything else with a machine-readable code.

The kernel denies everything; the forwarder grants the named destinations. The
container cannot reach the forwarder by any other route, which is what makes the
grant the *only* exit rather than one of two. TLS stays end-to-end, so the
forwarder never holds a credential — it reads destination host and port, which is
exactly what a network axis is about and not enough for anything else.

## Negative controls, and the falsification harness

Six controls run on every live run, each planting a real attempt and requiring a
refusal that names itself:

| control | plants | requires |
| --- | --- | --- |
| `NON_EXECUTABLE_TIER_REFUSED` | `NO_EXEC` and `HOST_UNISOLATED` | `ISOLATION_TIER_NOT_EXECUTABLE`, before any process |
| `WILDCARD_ALLOWLIST_REFUSED` | `'*'` on four shapes + `policy: unrestricted` | `ISOLATION_WILDCARD_ALLOWLIST_NOT_PERMITTED` |
| `ALLOWLIST_ESCAPE_REFUSED` | an off-list host, an off-list port, and the on-list pair | two `EGRESS_NOT_ALLOWLISTED` refusals **and one `HTTP/1.1 200` admission** |
| `DENY_BY_DEFAULT_RESOLUTION` | the same destinations through the policy layer | `deny_all` refuses the allowlisted host; `allowlist` admits only the named pair |
| `NO_ROUTE_INSIDE_CONTAINER` | `connect()` to the API host from inside the container | `ERR=EAI_AGAIN`, exit 7 |
| `HOST_ENVIRONMENT_NOT_INHERITED` | the operator's real `process.env` plus one planted variable | the variable is `absent` and the container's `HOME` is the profile's literal, not the operator's |

`ALLOWLIST_ESCAPE_REFUSED` is paired on purpose. A forwarder that refused
**everything** would pass a refusal test alone; the admitted pair is the inversion
that shows the control filters rather than blocks. (A first version of the
forwarder parsed the whole header block with an end-anchored regex and refused
every well-formed `CONNECT`, including the allowlisted one — so the negative
control was passing for the wrong reason. That is the failure the inversion
exists to catch, and `parseConnectRequest` now pins it.)

`scripts/verify-s2-002-isolation-falsification.sh` removes each control, one at a
time, in a throwaway copy of the tree under `/tmp`, and requires the suite to go
red. Fifteen mutations, fifteen caught. A control that keeps passing when its
mechanism is deleted is decoration, and this is the check that says which.

## What this tree does not claim

* **No model call is made.** A-MVP-04 is about isolation. Whether a model answers
  is a different clause, and paying for a call would not evidence a `--network=none`
  flag.
* **A-MVP-04 is not upgraded.** `aMvpStatus` is `NOT_CLAIMED`, the same marker the
  S2-007R records carry. The record measures the clause; upgrading the case is a
  reviewer's act.
* **The pids and memory ceilings are recorded from the argv the kernel received**,
  not from a provoked breach. `axes.process.not_independently_measured` says so.
* **`WINDIR`/`SystemRoot`-style host variables are not in play**: this is a WSL
  host and the launcher is `podman` directly, not `wsl.exe -d Ubuntu-24.04`. The
  measured invocation is in `PODMAN_HOST` and in every record, because podman
  4.9.3 rejects its own defaults here.

## Files

| file | role |
| --- | --- |
| `image.mjs` | the two pins, digest normalisation, `assertDigestPinned`, `assertImageMatchesPin`, `assertRealStart` |
| `profile.mjs` | the four axes, the executable/floor tier split, `assertNoWildcard`, `resolveEgress`, `buildEnvironment` |
| `egress.mjs` | the allowlist-enforcing `CONNECT` forwarder and its request-line parser |
| `secrets.mjs` | `sec-*` handles, the podman secret-store lifecycle, the fingerprint, `assertNoSecretLeak` |
| `launch.mjs` | the profile → podman argv translation, the spawn, the pin re-check |
| `Containerfile.executor` | the read-only build recipe: pinned `FROM`, one `COPY`, no `RUN` |

## Verification

```
npm run s2-002:isolation:image            # build + pin; exit 0
npm run s2-002:isolation:run             # the live run + 6 negative controls; exit 0
npm run verify:s2-002-isolation          # re-derive every claim from the records; exit 0
npm run test:s2-002-isolation            # 97 tests
npm run verify:s2-002-isolation-falsification   # 15 mutations, all caught
```

`verify:s2-002-isolation` starts no container and makes no network call. If the
records are absent it answers `NOT_RUN` with the command that produces them, and
exits non-zero — it does not reconstruct a pass out of the constants in the source.
