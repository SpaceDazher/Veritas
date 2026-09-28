#!/usr/bin/env bash
# S2-002 A-MVP-04 — the falsification harness.
#
# A negative control is only worth its cost if it FAILS when the control is
# removed. This script removes each control, one at a time, in a throwaway copy of
# the tree, and requires the corresponding test to go red. A control that keeps
# passing when its mechanism is deleted is decoration.
#
# Nothing here touches the working tree: each mutation is applied to a copy under
# /tmp, the tests are run there, and the copy is discarded. The gates that need a
# container (`s2-002-isolation-run.mjs`) are NOT re-run, because a live re-run per
# mutation would cost more than the whole ticket; the falsification runs against
# the PURE layer, which is where every rule lives, plus a re-read of the live
# record for the controls whose evidence is on disk.
#
# Usage: scripts/verify-s2-002-isolation-falsification.sh
# Exit:  0 when every mutation was caught, 1 when any mutation survived.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d /tmp/s2-002-falsify.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

PASSED=0
FAILED=0
declare -a RESULTS=()

# mutation <name> <file> <python-replace-old> <python-replace-new> <test-glob>
run_mutation() {
  local name="$1" file="$2" old="$3" new="$4" glob="$5"
  local dir="$WORK/$name"
  mkdir -p "$dir"
  cp -a "$ROOT/src" "$ROOT/tests" "$ROOT/evidence" "$ROOT/results" "$ROOT/package.json" "$dir/" 2>/dev/null

  if ! python3 - "$dir/$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding='utf-8') as fh:
    source = fh.read()
if old not in source:
    sys.stderr.write('MUTATION TARGET NOT FOUND\n')
    sys.exit(2)
with open(path, 'w', encoding='utf-8') as fh:
    fh.write(source.replace(old, new, 1))
PY
  then
    RESULTS+=("SURVIVED  $name (the mutation target was not found, so nothing was removed)")
    FAILED=$((FAILED + 1))
    return
  fi

  local out rc
  out="$(cd "$dir" && node --test "$glob" 2>&1)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    local failing
    failing="$(printf '%s' "$out" | grep -cE '^ *not ok' || true)"
    RESULTS+=("CAUGHT    $name -> $failing failing test(s)")
    PASSED=$((PASSED + 1))
  else
    RESULTS+=("SURVIVED  $name -> the suite stayed GREEN with the control removed")
    FAILED=$((FAILED + 1))
  fi
}

# --- the reference run, unmutated: if this is red, the harness proves nothing ---
(cd "$ROOT" && node --test "tests/isolation/*.test.mjs" >/dev/null 2>&1)
if [ $? -ne 0 ]; then
  echo "FALSIFICATION ABORTED: the unmutated suite is already red, so a surviving mutation would mean nothing"
  (cd "$ROOT" && node --test "tests/isolation/*.test.mjs" 2>&1 | grep -A8 -E '^ *not ok' | head -40)
  exit 1
fi

echo "=== S2-002 A-MVP-04 falsification: each control removed, each must be caught ==="
echo

# 1. The tier gate. Delete the refusal of a non-executable tier.
run_mutation "01-tier-gate-removed" \
  "src/lib/isolation/profile.mjs" \
  "export const EXECUTABLE_TIERS = Object.freeze(['LOCAL_RESTRICTED', 'UNTRUSTED_CODE']);" \
  "export const EXECUTABLE_TIERS = Object.freeze(['LOCAL_RESTRICTED', 'UNTRUSTED_CODE', 'NO_EXEC', 'HOST_UNISOLATED']);" \
  "tests/isolation/*.test.mjs"

# 2. The wildcard scan. Make it look only at the top level again.
run_mutation "02-wildcard-scan-blind" \
  "src/lib/isolation/profile.mjs" \
  "    if (value && typeof value === 'object') {
      for (const [key, inner] of Object.entries(value)) scan(inner, \`\${where}.\${key}\`);
    }" \
  "    if (false) { /* objects are not walked */ }" \
  "tests/isolation/*.test.mjs"

# 3. The real-start proof. Accept any exit status at all.
#    NOTE: the first version of this mutation removed only the `Number.isInteger`
#    branch, and the suite stayed GREEN — because the very next line
#    (`else if (exitCode !== 0)`) still caught null. A mutation that does not
#    actually remove the control proves nothing about whether the suite would
#    notice, and a harness that reports such a thing as SURVIVED is reporting on
#    its own aim. Both branches go.
run_mutation "03-real-start-accepts-null" \
  "src/lib/isolation/image.mjs" \
  "  if (!Number.isInteger(exitCode)) issues.push(\`exitCode:\${String(exitCode)}\`);
  else if (exitCode !== 0) issues.push(\`exitCode:\${exitCode}\`);" \
  "  if (false) issues.push(\`exitCode:\${String(exitCode)}\`);
  if (false) issues.push(\`exitCode:\${exitCode}\`);" \
  "tests/isolation/*.test.mjs"

# 4. The real-start proof. Stop requiring the executor's own version output.
run_mutation "04-real-start-ignores-stdout" \
  "src/lib/isolation/image.mjs" \
  "  if (!match) issues.push('stdout:no-version-shape');" \
  "  if (false) issues.push('stdout:no-version-shape');" \
  "tests/isolation/*.test.mjs"

# 5. The image pin. Accept any image reference.
run_mutation "05-digest-pin-removed" \
  "src/lib/isolation/image.mjs" \
  "  const isPinned = DIGEST_REFERENCE.test(reference) || BARE_DIGEST.test(reference);" \
  "  const isPinned = true;" \
  "tests/isolation/*.test.mjs"

# 6. The digest comparison. Compare the raw strings, prefix and all.
run_mutation "06-digest-compare-unnormalised" \
  "src/lib/isolation/image.mjs" \
  "  if (normalizeDigest(id) !== wantId) throw new Error(\`\${IMAGE_ERRORS.DIGEST_MISMATCH}:id:\${id}\`);" \
  "  if (String(id) !== String(expected.imageId ?? EXECUTOR_IMAGE_ID)) { /* unnormalised: a bare id never matches a prefixed pin */ }" \
  "tests/isolation/*.test.mjs"

# 7. The egress forwarder. Parse the whole header block with an end-anchored regex
#    again, which refuses every well-formed CONNECT including the allowlisted one.
run_mutation "07-egress-request-line-regression" \
  "src/lib/isolation/egress.mjs" \
  "  const requestLine = String(block).split('\\r\\n')[0];" \
  "  const requestLine = String(block);" \
  "tests/isolation/*.test.mjs"

# 8. The leak detector. Skip the surfaces that were not supplied, so a caller can
#    omit the one surface it was worried about and get a clean report.
run_mutation "08-leak-detector-ignores-missing-surfaces" \
  "src/lib/isolation/secrets.mjs" \
  "    if (!(name in surfaces)) leaks.push(\`\${name}:surface-not-supplied\`);" \
  "    if (false) leaks.push(\`\${name}:surface-not-supplied\`);" \
  "tests/isolation/*.test.mjs"

# 9. The leak detector. Stop searching the surfaces it was given.
run_mutation "09-leak-detector-blind" \
  "src/lib/isolation/secrets.mjs" \
  "    if (haystack.includes(value)) leaks.push(name);" \
  "    if (false) leaks.push(name);" \
  "tests/isolation/*.test.mjs"

# 10. The environment axis. Read the host environment on the path that builds the
#     child's, which is what "the host environment is not inherited" forbids.
#     This lives in profile.mjs, not launch.mjs: `buildEnvironment` is the
#     function that produces the pairs, and a mutation aimed at the wrong file
#     silently removes nothing.
run_mutation "10-environment-axis-reads-process-env" \
  "src/lib/isolation/profile.mjs" \
  "  for (const name of profile.environment.allowlist) {" \
  "  for (const name of [...profile.environment.allowlist, ...Object.keys(process.env)]) {" \
  "tests/isolation/*.test.mjs"

# 11. The network axis. Let a deny_all profile mount the egress socket anyway, so
#     the allowlist exists without being the only exit.
run_mutation "11-deny-all-mounts-egress-socket" \
  "src/lib/isolation/launch.mjs" \
  "  const egressSocketPath = networkPolicy === 'allowlist' ? request.egressSocketPath : null;" \
  "  const egressSocketPath = request.egressSocketPath ?? null;" \
  "tests/isolation/*.test.mjs"

# 12. The undeclared secret handle. Stop refusing a credential the profile never
#     declared.
run_mutation "12-undeclared-handle-allowed" \
  "src/lib/isolation/launch.mjs" \
  "    if (!declared.has(handle)) {" \
  "    if (false) {" \
  "tests/isolation/*.test.mjs"

# 13. The forwarder's own wildcard refusal. Build it into a pass-through.
run_mutation "13-forwarder-wildcard-allowed" \
  "src/lib/isolation/egress.mjs" \
  "    if (!entry || entry.host === '*' || entry.ports?.includes(0)) {" \
  "    if (!entry) {" \
  "tests/isolation/*.test.mjs"

# 14. The pin. Stop re-checking the executor tree provenance, so a host with a
#     DIFFERENT installed executor is measured against someone else's pin.
run_mutation "14-executor-tree-provenance-ignored" \
  "src/lib/isolation/image.mjs" \
  "export const EXECUTOR_TREE_SHA256 = 'sha256:201209e7c5e783e847f6cb2d259530772210164b79053bac8e1ea8001abf5965';" \
  "export const EXECUTOR_TREE_SHA256 = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';" \
  "tests/isolation/*.test.mjs"

# 15. The read-only root filesystem. Let a profile declare a writable root.
run_mutation "15-writable-root-fs-allowed" \
  "src/lib/isolation/profile.mjs" \
  "  if (profile.filesystem.root_fs_read_only !== true) {" \
  "  if (false) {" \
  "tests/isolation/*.test.mjs"

# 16. THE RECORD ASKS FOR A NETWORK IT NEVER GOT. The fifteen mutations above all
#     remove a CONTROL from the code. This one mutates the EVIDENCE instead: the
#     published record claims `declared: allowlist` while the raw log it points at
#     still shows `--network=none`. It passed all seventeen checks with exit 0
#     before the gate learned to compare the declared policy with the argv, so
#     without this case the fix would be free to rot.
run_mutation "16-record-claims-a-network-it-never-had" \
  "evidence/s2-002-isolation-live.json" \
  '"declared": "deny_all"' \
  '"declared": "allowlist"' \
  "scripts/verify-s2-002-isolation.mjs"

# 17. Same shape, one axis further: the record keeps its numbers and its declared
#     policy but stops naming what it denies, which is prose without a measurement.
run_mutation "17-record-names-nothing-it-denies" \
  "evidence/s2-002-isolation-live.json" \
  '"any destination at all"' \
  '"nothing in particular"' \
  "scripts/verify-s2-002-isolation.mjs"

echo
for line in "${RESULTS[@]}"; do echo "$line"; done
echo
echo "mutations_caught=$PASSED mutations_survived=$FAILED"
if [ "$FAILED" -ne 0 ]; then
  echo "VERDICT: FAIL — a control survived its own removal"
  exit 1
fi
echo "VERDICT: PASS — every removed control was caught by the suite"
exit 0
