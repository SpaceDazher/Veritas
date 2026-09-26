# S2-007 Windows acceptance follow-up — 2026-09-26

This follow-up covers the Windows portability defects found while re-running
the pushed S2-007 branch at `8f6254db1be3eb9a3c886ef41465314bf8e797c8`.
It does not replace the original S2-007 evaluation report or authorize a live
adapter run.

## Corrections

- The dependency gate launches npm's JavaScript CLI under the current Node on
  Windows, without a shell. Its child exit codes are now measured rather than
  reported as `null` after `spawnSync('npm')` failed with `ENOENT`.
- The cross-process claim-race child is a tracked test fixture, not an ignored
  `.bb` chat artifact. Two independent processes still contend against real
  PostgreSQL; the test does not substitute an in-memory result.
- Tests convert `file:` URLs with `fileURLToPath`, avoiding `D:\D:\...` paths.
- Workspace containment compares host realpath segments on both Windows and
  POSIX. The positive inner-path control passes while symlink escape remains
  denied. The offline probe unit case explicitly uses an empty environment so
  an integration-test `DATABASE_URL` cannot change its premise.
- `*.mts` now has an explicit LF checkout rule: the clean Git archive and
  `git show HEAD:file` produce identical bytes for the Agent Board declaration.
- SLOQUAL provenance checks for an actual `.git` before using `git log` or
  `merge-base`; a commit-ID fallback in an archive is not object provenance.

## Observed verification

| Check | Result |
| --- | --- |
| `verify:s2-007-dependencies` on Windows with CIM | exit 0, `PASS`, 157 checks, no issues; embedded S2-002 dependency and replay both exit 0 |
| S2-002 replay within that gate | two 283-case runs, hard counters zero; protected evidence restored |
| Cross-process PostgreSQL concurrency test | 8/8 pass against a fresh dedicated database |
| `npm test` with Windows CIM and a fresh dedicated PostgreSQL database in WSL | exit 0; 1193 pass, 0 fail, 0 cancelled, 0 skipped |
| `npm run typecheck`, `npm run lint` | exit 0 each |
| `npm run build` with a fresh dedicated PostgreSQL database | exit 0 |
| `inventory:check`, `manifest:check`, `validate-contracts`, public-artifact scan | exit 0 each after the reviewed freeze |
| `test:sloqual` after the archive-provenance fix | 71 pass, 0 fail |

The test databases were created under the existing WSL PostgreSQL instance,
were separate from its pre-existing databases, and were dropped after each
run. No credential or connection string was committed.

The independent `verify:clean-checkout` is **not green**: the latest complete
Windows run recorded 36 command PASS and 8 FAIL. Installation, archive
manifest, contracts, typecheck, lint, build, and both npm audits passed.
The failures were WSL/Podman startup timeouts in the sandbox and PostgreSQL
replays, a dependent S2-006 `NOT_RUN_DB`, and an archive-only SLOQUAL
provenance error. The latter has a targeted regression fix (71 SLOQUAL tests
pass), but the full clean-checkout was not repeated after that change.
The remaining WSL timeouts are **not** downgraded to PASS; this host takes
about 19 seconds merely to enter WSL and around 30 seconds for `podman info`,
at or beyond the existing 30-second sandbox timeouts. The clean-checkout
evidence records the actual failed run. A faster or appropriately configured
Windows/WSL host is still required for a full green archive acceptance.

## Limits

`assuranceStatus=NOT_MEASURED`, `realAdapterStatus=NOT_RUN_REAL_ADAPTER`, and
`A-MVP-01..07=NOT_RUN` remain unchanged. Passing engineering gates is not an
issue #7 closure or `A-MVP PASS`. The parent-based process-tree limitation in
issue #41 also remains open. This follow-up does not claim production
readiness. The work is local until the owner separately authorizes a push/PR.
