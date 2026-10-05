#!/bin/bash
# End-to-end walkthrough of the CLI, driven by separate JVM processes so the credential
# file is the only thing carried from one step to the next -- that is what "the stored
# credentials can be used for future authentication" has to survive.
set -u
cd "$(dirname "$0")"
[ -d out ] || bash run-tests.sh >/dev/null 2>&1 || javac -d out src/accounts/*.java

STORE=$(mktemp -d)/accounts.txt
PASS='Harbor-Lantern-42'

step() {
  echo
  echo "\$ $*"
  eval "$@"
  echo "  exit=$?"
}

echo "=== register (password piped on stdin, never echoed to the terminal) ==="
step "printf '$PASS\\n' | java -cp out accounts.AccountApp --store '$STORE' register --username Ada.Lovelace --password-stdin"

echo
echo "=== authenticate in a NEW process, using the lowercase form of the name ==="
step "printf '$PASS\\n' | java -cp out accounts.AccountApp --store '$STORE' login --username ada.lovelace --password-stdin"

echo
echo "=== authenticate with a wrong password ==="
step "printf 'Not-The-Password-1\\n' | java -cp out accounts.AccountApp --store '$STORE' login --username ada.lovelace --password-stdin"

echo
echo "=== re-register the same name (must be refused, not overwritten) ==="
step "printf '$PASS\\n' | java -cp out accounts.AccountApp --store '$STORE' register --username ada.lovelace --password-stdin"

echo
echo "=== a second account with the same password ==="
step "printf '$PASS\\n' | java -cp out accounts.AccountApp --store '$STORE' register --username grace.hopper --password-stdin"

echo
echo "=== list (names and hash parameters only) ==="
step "java -cp out accounts.AccountApp --store '$STORE' list"

echo
echo "=== what actually landed on disk ==="
ls -l "$STORE"
cat "$STORE"
echo
if grep -q "$PASS" "$STORE"; then
  echo "PROBLEM: the plaintext password appears in the store"
  exit 1
fi
echo "no plaintext password in the store (salt and hash are per-account, so the two"
echo "accounts sharing '$PASS' still have different hashes)"
