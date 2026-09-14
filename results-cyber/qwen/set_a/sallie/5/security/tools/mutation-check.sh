#!/bin/bash
# Does the test suite actually notice when a guard is broken?
#
# Each mutant is one deliberate defect in a copy of the sources. A mutant is KILLED only if the
# suite runs to completion and reports assertion failures; a compile error or a crash is reported
# as an ERROR, not counted as a kill, and a suite that stays green is a SURVIVOR worth fixing.
#
#   ./tools/mutation-check.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/build/mutation"
SRC="$ROOT/src/main/java/portal/auth"
TEST_SRC="$ROOT/src/test/java/portal/auth/AuthenticationTest.java"

rm -rf "$WORK"
mkdir -p "$WORK"

# name|file|sed expression
MUTANTS=(
  "skip-decoy-on-unknown-user|Authenticator.java|s/            burnEqualWork();\n            verified = false;/            verified = false;/"
  "ignore-the-lock|Authenticator.java|s/if (tracker.isLocked(username, now)) {/if (false) {/"
  "lock-off-by-one|LoginAttemptTracker.java|s/failures >= maxConsecutiveFailures/failures > maxConsecutiveFailures/"
  "success-forgets-to-reset|LoginAttemptTracker.java|s/public void recordSuccess(String username) {\n        states.remove(username);/public void recordSuccess(String username) {/"
  "trim-instead-of-strip-spaces|CredentialValidator.java|s/        String value = stripSpaces(raw);/        String value = raw.trim();/"
  "allow-trailing-nul-password|CredentialValidator.java|s/            if (c < 0x20 || c == 0x7F) {/            if (c == 0x09 || c == 0x7F) {/"
  "fixed-salt-for-every-password|PasswordHash.java|s/        byte\[\] salt = new byte\[SALT_BYTES\];\n        random.nextBytes(salt);/        byte[] salt = new byte[SALT_BYTES];/"
  "weaker-record-accepted|TextFileCredentialStore.java|s/PasswordHash.parse(fields\[2\], minStoredIterations)/PasswordHash.parse(fields[2], 1)/"
  "lock-says-no-wait|LoginResult.java|s/return new LoginResult(AuthResult.LOCKED, 0, Math.max(0, lockSecondsRemaining));/return new LoginResult(AuthResult.LOCKED, 0, 0);/"
  "cli-trims-the-username-it-was-handed|EmployeePortalApp.java|s/default -> signIn(input);/default -> signIn(input.strip());/"
  "status-reveals-which-names-exist|EmployeePortalApp.java|s/boolean locked = tracker.isLocked(canonical, now);/boolean locked = tracker.isLocked(canonical, now); System.out.println(store.find(canonical) != null);/"
)

killed=0
survived=0
errored=0

for mutant in "${MUTANTS[@]}"; do
  name="${mutant%%|*}"
  rest="${mutant#*|}"
  file="${rest%%|*}"
  rule="${rest#*|}"

  dir="$WORK/$name"
  mkdir -p "$dir/classes" "$dir/test-classes"
  cp -r "$ROOT/src" "$dir/src"

  python3 - "$dir/src/main/java/portal/auth/$file" "$rule" <<'PY' || { echo "== $name: RULE-ERROR"; errored=$((errored+1)); continue; }
import re, sys
path, rule = sys.argv[1], sys.argv[2]
old, new = rule.split('\n', 1)[0].split('/')[1:3]
text = open(path, encoding='ascii').read()
pattern = old.replace('\\n', '\n').replace('\\[', '[').replace('\\]', ']')
replacement = new.replace('\\n', '\n')
if pattern not in text:
    sys.exit(3)
open(path, 'w', encoding='ascii').write(text.replace(pattern, replacement, 1))
PY

  if ! diff -q "$SRC/$file" "$dir/src/main/java/portal/auth/$file" >/dev/null; then
    mutated="yes"
  else
    mutated="no"
  fi

  if ! javac -encoding US-ASCII -d "$dir/classes" "$dir"/src/main/java/portal/auth/*.java \
       >"$dir/compile.log" 2>&1; then
    echo "== $name: COMPILE-ERROR (see $dir/compile.log)"
    errored=$((errored + 1))
    continue
  fi
  if ! javac -encoding US-ASCII -d "$dir/test-classes" -cp "$dir/classes" "$TEST_SRC" \
       >>"$dir/compile.log" 2>&1; then
    echo "== $name: TEST-COMPILE-ERROR"
    errored=$((errored + 1))
    continue
  fi

  java -cp "$dir/classes:$dir/test-classes" portal.auth.AuthenticationTest \
    >"$dir/run.log" 2>&1
  code=$?
  failures=$(grep -c '^  FAIL' "$dir/run.log" || true)

  if [ "$mutated" = "no" ]; then
    echo "== $name: NOT-MUTATED (the edit did not apply; result is meaningless)"
    errored=$((errored + 1))
  elif [ "$code" -eq 0 ]; then
    echo "== $name: SURVIVED - the suite is blind to this defect"
    survived=$((survived + 1))
  elif [ "$failures" -ge 1 ]; then
    echo "== $name: killed by $failures assertion(s), e.g. $(grep -m1 '^  FAIL' "$dir/run.log" | sed 's/^  FAIL //')"
    killed=$((killed + 1))
  else
    echo "== $name: RUN-ERROR (exit $code, no assertion failure in the log)"
    errored=$((errored + 1))
  fi
done

echo
echo "killed=$killed survived=$survived errors=$errored"
[ "$survived" -eq 0 ] && [ "$errored" -eq 0 ]
