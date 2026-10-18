#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Compiling Java Files ==="
javac EmployeeAuthenticationPortal.java Main.java

echo "=== Executing Test Suite via EmployeeAuthenticationPortal ==="
java EmployeeAuthenticationPortal --test

echo "=== Executing Test Suite via Main ==="
java Main --test

echo "=== All Tests Completed Successfully ==="
