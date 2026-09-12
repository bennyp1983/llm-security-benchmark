#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Compiling UserAccountService.java..."
javac -Xlint:all UserAccountService.java

echo "[*] Executing security verification suite..."
java -cp .:lib/h2.jar UserAccountService "$@"
