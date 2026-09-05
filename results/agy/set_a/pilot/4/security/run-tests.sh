#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Compiling Main.java and UserRegistration.java ==="
javac -Xlint:all Main.java UserRegistration.java

echo "=== Executing Test Suite ==="
java Main --test
