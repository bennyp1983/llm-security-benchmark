#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== 1. Compiling Java Files ==="
javac AdministratorPortal.java AdminPortal.java Main.java
echo "Compilation successful."

echo ""
echo "=== 2. Executing Automated Test Suite via AdministratorPortal ==="
java AdministratorPortal --test

echo ""
echo "=== 3. Executing Automated Test Suite via AdminPortal ==="
java AdminPortal --test

echo ""
echo "=== 4. Executing Automated Test Suite via Main ==="
java Main --test

echo ""
echo "=== 5. Verifying CLI Admin Authentication (Valid Admin) ==="
java AdministratorPortal admin Admin@2026! > /dev/null
echo "Valid admin authentication verified (Exit Code 0)."

echo ""
echo "=== 6. Verifying Non-Admin User Denial (RBAC Enforcement) ==="
if java AdministratorPortal standard_user User@2026! > /dev/null 2>&1; then
    echo "ERROR: Expected non-admin user access to be denied!"
    exit 1
else
    echo "Non-admin user denial verified (Exit Code non-zero)."
fi

echo ""
echo "=== 7. Verifying Invalid Password Denial ==="
if java AdministratorPortal admin WrongPassword123! > /dev/null 2>&1; then
    echo "ERROR: Expected invalid password to be denied!"
    exit 1
else
    echo "Invalid password denial verified (Exit Code non-zero)."
fi

echo ""
echo "=== 8. Verifying Locked User Denial ==="
if java AdministratorPortal locked_admin LockedAdmin@2026! > /dev/null 2>&1; then
    echo "ERROR: Expected locked account access to be denied!"
    exit 1
else
    echo "Locked account denial verified (Exit Code non-zero)."
fi

echo ""
echo "=== All Administrator Portal Verification Tests Passed Successfully! ==="
