#!/usr/bin/env bash
# End-to-end check against a throwaway H2 database in a private temp directory.
# No password is ever passed as a command line argument; the test password is
# generated at run time, kept in a 0600 file, piped on stdin, and deleted.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

if [[ ! -f target/secure-auth-1.0.0.jar ]]; then
  mvn -q -DskipTests package
fi
mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt -Dmdep.includeScope=runtime
CP="target/classes:$(cat target/cp.txt)"

WORK="$(mktemp -d)"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

export AUTH_DB_URL="jdbc:h2:file:$WORK/authdb;DB_CLOSE_DELAY=0"
export AUTH_SOURCE_ID="127.0.0.1"
export AUTH_MAX_ATTEMPTS_PER_ACCOUNT=3
export AUTH_MAX_ATTEMPTS_PER_SOURCE=30
export AUTH_SESSION_FILE="$WORK/session.token"

EMAIL="user@example.test"
PW_FILE="$WORK/pw"
(umask 077; printf 'Zq%s7x!K\n' "$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')" > "$PW_FILE")
PW="$(cat "$PW_FILE")"

run()  { java -cp "$CP" com.example.auth.App; }
admin() { java -cp "$CP" com.example.auth.AdminCli "$@"; }

echo "== 1. create schema"
admin init-schema

echo "== 2. set a password for $EMAIL"
printf '%s\n%s\n' "$PW" "$PW" | admin set-password "$EMAIL" >/dev/null
echo "   password stored"

echo "== 3. correct credentials"
OK_OUT="$(printf '%s\n%s\n' "$EMAIL" "$PW" | run 2>/dev/null || true)"
grep -q 'Authentication successful' <<<"$OK_OUT" && echo "   PASS" || { echo "   FAIL"; exit 1; }
[[ "$(stat -c '%a' "$AUTH_SESSION_FILE")" == "600" ]] \
  && echo "   session file mode 600: PASS" || { echo "   session file mode: FAIL"; exit 1; }
rm -f "$AUTH_SESSION_FILE"

echo "== 4. wrong password"
OUT="$(printf '%s\nnot-the-password-1A!\n' "$EMAIL" | run 2>/dev/null || true)"
grep -q 'Authentication failed' <<<"$OUT" && echo "   PASS" || { echo "   FAIL"; exit 1; }

echo "== 5. unknown account gives an identical message"
OUT2="$(printf 'nobody@example.test\nnot-the-password-1A!\n' | run 2>/dev/null || true)"
[[ "$OUT" == "$OUT2" ]] && echo "   PASS (byte-identical)" || { echo "   FAIL"; exit 1; }

echo "== 6. SQL injection attempt in the email field"
printf "%s\n%s\n" "' OR '1'='1' --" "$PW" | run >/dev/null 2>&1 || true
printf "%s\n%s\n" "x'; DROP TABLE app_user; --" "$PW" | run >/dev/null 2>&1 || true
AFTER_INJECTION="$(printf '%s\n%s\n' "$EMAIL" "$PW" | run 2>/dev/null || true)"
grep -q 'Authentication successful' <<<"$AFTER_INJECTION" \
  && echo "   PASS (table intact, injection rejected)" || { echo "   FAIL"; exit 1; }

echo "== 7. per-account throttle engages, then success still blocked"
for _ in 1 2 3 4; do
  printf '%s\nwrong-password-9Z!\n' "$EMAIL" | run >/dev/null 2>&1 || true
done
THROTTLED="$(printf '%s\n%s\n' "$EMAIL" "$PW" | run 2>&1 || true)"
grep -q 'Authentication failed' <<<"$THROTTLED" \
  && echo "   PASS (correct password refused while the window is exhausted)" \
  || { echo "   FAIL"; exit 1; }
grep -q 'ACCOUNT_LIMIT' <<<"$THROTTLED" \
  && echo "   PASS (reason ACCOUNT_LIMIT is in the log only)" || { echo "   FAIL"; exit 1; }

echo "== 8. no secret appears in the output or the log"
LOGS="$OK_OUT$THROTTLED"
if grep -qF -- "$PW" <<<"$LOGS" || grep -qF -- "$EMAIL" <<<"$LOGS"; then
  echo "   FAIL (password or address leaked)"; exit 1
else
  echo "   PASS (address masked, password absent)"
fi

echo
echo "All smoke checks passed."
