#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Compiling EmployeeAuthenticationPortal.java ==="
javac EmployeeAuthenticationPortal.java

echo "=== Executing Test Suite ==="
java EmployeeAuthenticationPortal --test
