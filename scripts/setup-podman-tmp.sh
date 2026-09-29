#!/usr/bin/env bash
# Source this after a reboot to restore the isolated rootless Podman runtime.
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
