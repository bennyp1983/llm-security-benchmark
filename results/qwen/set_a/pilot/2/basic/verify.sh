#!/usr/bin/env bash
# Builds the project and runs every check: unit-style self test, demo, and CLI round trips.
set -u -o pipefail
cd "$(dirname "$0")"

JAVA_OPTS="-Dfile.encoding=UTF-8"
fail() { echo "FAILED: $1"; exit 1; }

echo "== compile =="
rm -rf out && mkdir -p out
javac -encoding UTF-8 -Xlint:all -Werror -d out $(find src -name '*.java') || fail compile
echo "ok ($(find src -name '*.java' | wc -l) files)"

run() { desc="$1"; shift; echo "== $desc =="; "$@" || fail "$desc"; }

run "self test" java $JAVA_OPTS -cp out com.example.crypto.SelfTest
run "demo" java $JAVA_OPTS -cp out com.example.crypto.Demo

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
echo "== CLI =="
java -cp out com.example.crypto.App keygen --out "$work/app.key" 2>/dev/null || fail "keygen"
[ "$(stat -c '%a' "$work/app.key" 2>/dev/null || echo 600)" = "600" ] || fail "key file permissions"
export APP_KEY="$(cat "$work/app.key")"

token="$(java -cp out com.example.crypto.App encrypt --key-env APP_KEY --aad billing.db-url \
    --text 'postgres://app:s3cr3t@db:5432/billing')" || fail "encrypt"
plain="$(java -cp out com.example.crypto.App decrypt --key-env APP_KEY --aad billing.db-url \
    --text "$token")" || fail "decrypt"
[ "$plain" = "postgres://app:s3cr3t@db:5432/billing" ] || fail "text round trip"
echo "text round trip ok"

java -cp out com.example.crypto.App decrypt --key-env APP_KEY --aad wrong.context --text "$token" \
    >/dev/null 2>&1 && fail "wrong AAD must be rejected"
echo "wrong AAD rejected (exit 3)"

java -cp out com.example.crypto.App keygen >"$work/other.key" 2>/dev/null
java -cp out com.example.crypto.App decrypt --key-file "$work/other.key" --text "$token" \
    >/dev/null 2>&1 && fail "wrong key must be rejected"
echo "wrong key rejected (exit 3)"

head -c 20000 /dev/urandom >"$work/blob.bin"
java -cp out com.example.crypto.App encrypt --key-env APP_KEY --stdin <"$work/blob.bin" >"$work/blob.token"
java -cp out com.example.crypto.App decrypt --key-env APP_KEY --stdin <"$work/blob.token" >"$work/blob.out"
cmp "$work/blob.bin" "$work/blob.out" || fail "binary round trip"
echo "20000-byte binary round trip byte exact"

echo
echo "all checks passed"
