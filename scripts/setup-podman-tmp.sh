#!/usr/bin/env bash
# Source this after a reboot to restore the isolated rootless Podman runtime.
#
# WHY THE PULL BELOW IS PART OF RESTORING THE RUNTIME, NOT A CONVENIENCE.
#
# `PODMAN_HOST.argvPrefix` in src/lib/isolation/launch.mjs sends every repository
# build and run to a SEPARATE store: `--root /tmp/podman-root --runroot
# /tmp/podman-runroot`. /tmp does not survive a WSL reboot, so after a reboot
# that store is empty while the pinned base is still sitting in the rootless
# store under $HOME. Every build runs with `--pull=never`, so the empty store
# cannot re-acquire the base and the build dies with
#
#   Error: creating build container: <digest>: image not known      (exit 125)
#
# Measured 2026-09-29, the same Containerfile / env / --pull=never in both
# stores: exit 125 in the /tmp store, exit 0 in the rootless store. The
# environment variables change nothing and `--pull=never` is not the cause — it
# is the only thing standing between you and a silent network pull. Log:
# Stage 2/.bb/chats/thr_hj2st7xwcz/artifacts/c1-store-probe.txt
#
# The same trap has a second door. `podman system reset -f` deletes the pinned
# base from whatever store the wrapper points at, and every later build fails
# with that same 125 until the digest is pulled back. So re-source this file
# after a reset; it is the same repair.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf 'Source this file: source scripts/setup-podman-tmp.sh\n' >&2
  exit 2
fi
mkdir -p /tmp/bin /tmp/xdg-rt
chmod 700 /tmp/xdg-rt
cat > /tmp/bin/podman <<'PODMAN'
#!/bin/sh
exec /usr/bin/podman --root /tmp/podman-root --runroot /tmp/podman-runroot --runtime /usr/bin/crun "$@"
PODMAN
chmod 700 /tmp/bin/podman
export PATH="/tmp/bin:$PATH" XDG_RUNTIME_DIR=/tmp/xdg-rt TMPDIR=/tmp

# One source of truth for the pin. Read it from the module rather than copying
# the digest here: a second copy of a pin is a pin that can drift silently.
veritas_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v node >/dev/null 2>&1; then
  printf 'podman: NOT_RUN — node не найден, пин базового образа не прочитан.\n' >&2
  printf 'podman: сборки упадут с exit 125 image not known, пока база не подтянута:\n' >&2
  return 0 2>/dev/null || exit 0
fi
base_image="$(VERITAS_ROOT="$veritas_root" node --input-type=module -e '
  import { pathToFileURL } from "node:url";
  const { BASE_IMAGE } = await import(pathToFileURL(process.env.VERITAS_ROOT + "/src/lib/isolation/image.mjs").href);
  process.stdout.write(BASE_IMAGE);
')"

# Presence is checked with `inspect <digest>`, NEVER with `podman images`. A
# build tagged `-t some/name` moves the base image's NAME onto its result, so a
# name-based listing reports a present image as missing — measured, and it
# points the diagnosis at the pin instead of at the store.
if podman inspect --format '{{.Id}}' "$base_image" >/dev/null 2>&1; then
  printf 'podman: базовый образ уже в /tmp/podman-root, проверено inspect по digest.\n'
else
  printf 'podman: базового образа нет в /tmp/podman-root, подтягиваю %s\n' "$base_image"
  if podman pull "$base_image" >/dev/null 2>&1; then
    printf 'podman: базовый образ подтянут, сборки с --pull=never снова работают.\n'
  else
    printf 'podman: НЕ УДАЛОСЬ подтянуть %s\n' "$base_image" >&2
    printf 'podman: сборки упадут с exit 125 image not known. Это NOT_RUN, не успех.\n' >&2
  fi
fi
# The full npm test suite also starts a pinned PostgreSQL image. Keep its
# digest in the frozen concurrency test and restore it into this same /tmp
# store. Read that literal without modifying the frozen test (G7 pins its bytes).
postgres_image="$(VERITAS_ROOT="$veritas_root" node --input-type=module -e '
  import fs from "node:fs";
  const source = fs.readFileSync(process.env.VERITAS_ROOT + "/tests/agentboard/concurrency.test.mjs", "utf8");
  const match = source.match(/const PINNED_POSTGRES = .(docker\.io\/library\/postgres@sha256:[0-9a-f]{64}).;/);
  if (!match) process.exit(2);
  process.stdout.write(match[1]);
')"
if podman inspect --format '{{.Id}}' "$postgres_image" >/dev/null 2>&1; then
  printf 'podman: закреплённый PostgreSQL для npm test уже в /tmp/podman-root.\n'
elif podman pull "$postgres_image" >/dev/null 2>&1; then
  printf 'podman: закреплённый PostgreSQL для npm test подтянут.\n'
else
  printf 'podman: NOT_RUN — PostgreSQL image не подтянут; concurrency suite даст exit 1.\n' >&2
fi
printf 'podman: после `podman system reset -f` закреплённая база удаляется —\n'
printf 'podman: снова выполните source scripts/setup-podman-tmp.sh.\n'
