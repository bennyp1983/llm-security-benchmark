#!/usr/bin/env bash
# Suite 3 is excluded from the main battery because it measures timing, so the two mutants that can
# only show up in timing (M11 digest compare, M12 latency floor) are re-checked here against suite 3,
# one at a time, with nothing else loaded.
set -u
SEC="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
LOG="${LOG:-/tmp/mut-timing.log}"
: > "$LOG"

run_case() {
  local id="$1" file="$2" from="$3" to="$4" note="$5"
  local work; work=$(mktemp -d /tmp/mut-time-$id.XXXXXX)
  # Same layout as the main battery: <tree>/src/main/java/... The suites resolve shipped sources
  # through -Dauth.source.dir and now raise rather than falling back to the checkout, so a flat copy
  # would make every source-text guard in a suite fail for the wrong reason.
  local tree="$work/tree"
  mkdir -p "$tree/src"
  cp -r "$SEC/src/main" "$tree/src/main"
  cp -r "$SEC/src/test" "$tree/src/test"
  python3 - "$tree/src/main/$file" "$from" "$to" <<'PY'
import sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
if s.count(a) != 1:
    sys.exit(3)
open(p, "w").write(s.replace(a, b))
PY
  if [ $? -eq 3 ]; then echo "MUT $id ANCHOR-DRIFT ($note)" >>"$LOG"; rm -rf "$work"; return; fi
  if ! "${JAVAC:-javac}" -nowarn -d "$work/main" $(find "$tree/src/main" -name '*.java') >>"$LOG" 2>&1; then
    echo "MUT $id KILLED-BUILD ($note)" >>"$LOG"; rm -rf "$work"; return; fi
  if ! "${JAVAC:-javac}" -nowarn -d "$work/test" -cp "$work/main" $(find "$SEC/src/test/java" -name '*.java') >>"$LOG" 2>&1; then
    echo "MUT $id KILLED-BUILD-TEST ($note)" >>"$LOG"; rm -rf "$work"; return; fi
  local kills=0 errors=0 details=""
  out=$(cd "$SEC" && timeout 900 "${JAVA:-java}" "-Dauth.source.dir=$tree" \
        -cp "$work/main:$work/test" com.example.auth.Suite3Latency 2>&1)
  if echo "$out" | grep -q '^FAIL'; then
    kills=1; details=" $(echo "$out" | grep -m1 '^FAIL')"
  elif ! echo "$out" | grep -q '^SUMMARY'; then
    errors=1; details=" CRASH"
  else
    details=" $(echo "$out" | grep '^SUMMARY')"
  fi
  if [ $kills -gt 0 ]; then echo "MUT $id KILLED ($note) errors=$errors${details}" >>"$LOG"
  elif [ $errors -gt 0 ]; then echo "MUT $id ERROR ($note)${details}" >>"$LOG"
  else echo "MUT $id SURVIVED ($note)${details}" >>"$LOG"; fi
  rm -rf "$work"
}

run_case M11 java/com/example/auth/PasswordHasher.java \
  'MessageDigest.isEqual(candidate, storedDigest);' \
  'java.util.Arrays.equals(candidate, storedDigest);' \
  'digest compare not constant time'

run_case M12 java/com/example/auth/AuthenticationService.java \
  'budget.padUntil(startedNanos);' '// budget.padUntil(startedNanos);' \
  'latency floor removed'

echo "=== timing recheck done ===" >>"$LOG"
