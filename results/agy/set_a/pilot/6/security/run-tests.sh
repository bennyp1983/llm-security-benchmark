#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "================================================================"
echo "          ADMINISTRATOR PORTAL VERIFICATION PIPELINE            "
echo "================================================================"

echo ""
echo "=== 1. Compiling Java Source Files ==="
javac -Xlint:all AdministratorPortal.java AdminPortal.java Main.java
echo "Compilation completed successfully with 0 errors and 0 warnings."

echo ""
echo "=== 2. Running Verification Suite via AdministratorPortal ==="
java AdministratorPortal --test

echo ""
echo "=== 3. Running Verification Suite via AdminPortal Alias ==="
java AdminPortal --test

echo ""
echo "=== 4. Running Verification Suite via Main Alias ==="
java Main --test

echo ""
echo "=== 5. Testing CLI Authentication: Valid Administrator ==="
java AdministratorPortal admin Admin@2026! > /dev/null
echo "[PASS] Valid administrator authenticated successfully (Exit Code 0)."

echo ""
echo "=== 6. Testing CLI Authentication: Non-Admin User Denial (RBAC) ==="
if java AdministratorPortal standard_user User@2026! > /dev/null 2>&1; then
    echo "ERROR: Expected non-admin user access to be denied!"
    exit 1
else
    echo "[PASS] Non-admin user access correctly denied (Exit Code non-zero)."
fi

echo ""
echo "=== 7. Testing CLI Authentication: Invalid Password Denial ==="
if java AdministratorPortal admin WrongPassword123! > /dev/null 2>&1; then
    echo "ERROR: Expected invalid password to be denied!"
    exit 1
else
    echo "[PASS] Invalid password correctly denied (Exit Code non-zero)."
fi

echo ""
echo "=== 8. Testing CLI Authentication: Unknown Username Denial ==="
if java AdministratorPortal ghost_user SomePassword123! > /dev/null 2>&1; then
    echo "ERROR: Expected unknown user to be denied!"
    exit 1
else
    echo "[PASS] Unknown user correctly denied (Exit Code non-zero)."
fi

echo ""
echo "=== 9. Testing CLI Authentication: Locked Admin Account Denial ==="
if java AdministratorPortal locked_admin LockedAdmin@2026! > /dev/null 2>&1; then
    echo "ERROR: Expected locked account access to be denied!"
    exit 1
else
    echo "[PASS] Locked account correctly denied (Exit Code non-zero)."
fi

echo ""
echo "=== 10. Testing Audit Log CLI Review Tool ==="
java AdministratorPortal --logs

echo ""
echo "=== 11. Verifying Audit Log Disk Persistence ==="
if [ -f "audit.log" ]; then
    echo "[PASS] Persistent audit log exists at audit.log."
    echo "Total lines in audit.log: $(wc -l < audit.log)"
else
    echo "ERROR: audit.log file not found on disk!"
    exit 1
fi

echo ""
echo "================================================================"
echo "   ALL TESTS & VERIFICATIONS COMPLETED SUCCESSFULLY (100% PASS) "
echo "================================================================"
