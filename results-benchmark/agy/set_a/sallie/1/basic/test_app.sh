#!/usr/bin/env bash
set -e

PORT=8085
BASE_URL="http://localhost:${PORT}"
COOKIE_JAR="/tmp/test_cookies.txt"

rm -f "${COOKIE_JAR}"

echo "=========================================================="
echo "Starting AuthApplication on port ${PORT}..."
echo "=========================================================="

java AuthApplication ${PORT} &
APP_PID=$!

cleanup() {
    echo ""
    echo "Cleaning up server process ${APP_PID}..."
    kill -9 ${APP_PID} 2>/dev/null || true
    rm -f "${COOKIE_JAR}"
}
trap cleanup EXIT

# Wait for server to start
sleep 2

echo "Running Integration Tests..."
echo ""

# Test 1: GET /login returns 200 and login form
echo -n "Test 1: GET /login returns 200 OK and contains login form... "
RESP=$(curl -s -w "\n%{http_code}" "${BASE_URL}/login")
STATUS=$(echo "$RESP" | tail -n 1)
BODY=$(echo "$RESP" | head -n -1)
if [ "$STATUS" -eq 200 ] && echo "$BODY" | grep -q "Secure Login" && echo "$BODY" | grep -q "name=\"username\""; then
    echo "PASS"
else
    echo "FAIL (Status: $STATUS)"
    exit 1
fi

# Test 2: Accessing protected /dashboard without cookie redirects to /login?error=unauthorized
echo -n "Test 2: GET /dashboard without session cookie redirects to /login?error=unauthorized... "
HEADERS=$(curl -s -I "${BASE_URL}/dashboard")
if echo "$HEADERS" | grep -q "302" && echo "$HEADERS" | grep -iq "Location: /login?error=unauthorized"; then
    echo "PASS"
else
    echo "FAIL"
    echo "$HEADERS"
    exit 1
fi

# Test 3: POST /login with invalid credentials fails
echo -n "Test 3: POST /login with invalid credentials redirects to /login?error=invalid_credentials... "
HEADERS=$(curl -s -i -X POST "${BASE_URL}/login" \
    -d "username=admin&password=WrongPassword123")
if echo "$HEADERS" | grep -q "302" && echo "$HEADERS" | grep -iq "Location: /login?error=invalid_credentials"; then
    if ! echo "$HEADERS" | grep -iq "Set-Cookie: SESSIONID="; then
        echo "PASS"
    else
        echo "FAIL (Cookie was erroneously issued on failure)"
        exit 1
    fi
else
    echo "FAIL"
    echo "$HEADERS"
    exit 1
fi

# Test 4: POST /login with valid credentials succeeds and issues secure session cookie
echo -n "Test 4: POST /login with valid credentials returns Set-Cookie and redirects to /dashboard... "
RESP_HEADERS=$(curl -s -i -X POST "${BASE_URL}/login" \
    -c "${COOKIE_JAR}" \
    -d "username=admin&password=AdminPassword123!")

if echo "$RESP_HEADERS" | grep -q "302" && echo "$RESP_HEADERS" | grep -iq "Location: /dashboard" && echo "$RESP_HEADERS" | grep -iq "Set-Cookie: SESSIONID="; then
    # Verify HttpOnly and SameSite=Strict flags in Set-Cookie header
    SET_COOKIE_LINE=$(echo "$RESP_HEADERS" | grep -i "Set-Cookie:")
    if echo "$SET_COOKIE_LINE" | grep -iq "HttpOnly" && echo "$SET_COOKIE_LINE" | grep -iq "SameSite=Strict"; then
        echo "PASS"
    else
        echo "FAIL (Missing security flags in Set-Cookie: $SET_COOKIE_LINE)"
        exit 1
    fi
else
    echo "FAIL"
    echo "$RESP_HEADERS"
    exit 1
fi

# Test 5: GET /dashboard using session cookie returns 200 OK and user info
echo -n "Test 5: GET /dashboard with valid session cookie displays protected dashboard... "
RESP=$(curl -s -w "\n%{http_code}" -b "${COOKIE_JAR}" "${BASE_URL}/dashboard")
STATUS=$(echo "$RESP" | tail -n 1)
BODY=$(echo "$RESP" | head -n -1)
if [ "$STATUS" -eq 200 ] && echo "$BODY" | grep -q "Welcome, System Administrator!" && echo "$BODY" | grep -q "SESSIONID"; then
    echo "PASS"
else
    echo "FAIL (Status: $STATUS)"
    exit 1
fi

# Test 6: POST /logout clears session cookie and redirects to /login?logout=true
echo -n "Test 6: POST /logout invalidates session and clears cookie... "
LOGOUT_HEADERS=$(curl -s -i -X POST "${BASE_URL}/logout" \
    -b "${COOKIE_JAR}" \
    -c "${COOKIE_JAR}")

if echo "$LOGOUT_HEADERS" | grep -q "302" && echo "$LOGOUT_HEADERS" | grep -iq "Location: /login?logout=true" && echo "$LOGOUT_HEADERS" | grep -iq "Max-Age=0"; then
    echo "PASS"
else
    echo "FAIL"
    echo "$LOGOUT_HEADERS"
    exit 1
fi

# Test 7: Accessing /dashboard after logout fails because session was invalidated
echo -n "Test 7: Accessing /dashboard after logout is rejected (unauthorized)... "
RECHECK_HEADERS=$(curl -s -i -b "${COOKIE_JAR}" "${BASE_URL}/dashboard")
if echo "$RECHECK_HEADERS" | grep -q "302" && echo "$RECHECK_HEADERS" | grep -iq "Location: /login?error="; then
    echo "PASS"
else
    echo "FAIL"
    echo "$RECHECK_HEADERS"
    exit 1
fi

# Test 8: JSON API Authentication flow
echo -n "Test 8: API POST /api/login authenticates and returns JSON + cookie... "
API_LOGIN_RESP=$(curl -s -i -X POST "${BASE_URL}/api/login" \
    -H "Content-Type: application/json" \
    -c "${COOKIE_JAR}" \
    -d '{"username":"alice","password":"AlicePass#2026"}')

if echo "$API_LOGIN_RESP" | grep -q "200" && echo "$API_LOGIN_RESP" | grep -iq "Set-Cookie: SESSIONID=" && echo "$API_LOGIN_RESP" | grep -q '"success":true'; then
    echo "PASS"
else
    echo "FAIL"
    echo "$API_LOGIN_RESP"
    exit 1
fi

# Test 9: JSON API Session verification
echo -n "Test 9: API GET /api/session returns authenticated session details... "
API_SESS_RESP=$(curl -s -w "\n%{http_code}" -b "${COOKIE_JAR}" "${BASE_URL}/api/session")
STATUS=$(echo "$API_SESS_RESP" | tail -n 1)
BODY=$(echo "$API_SESS_RESP" | head -n -1)
if [ "$STATUS" -eq 200 ] && echo "$BODY" | grep -q '"authenticated":true' && echo "$BODY" | grep -q '"username":"alice"'; then
    echo "PASS"
else
    echo "FAIL (Status: $STATUS, Body: $BODY)"
    exit 1
fi

# Test 10: JSON API Logout
echo -n "Test 10: API POST /api/logout terminates session... "
API_LOGOUT_RESP=$(curl -s -i -X POST "${BASE_URL}/api/logout" \
    -b "${COOKIE_JAR}" \
    -c "${COOKIE_JAR}")

if echo "$API_LOGOUT_RESP" | grep -q "200" && echo "$API_LOGOUT_RESP" | grep -q '"success":true'; then
    # Verify session is now dead
    DEAD_CHECK=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" "${BASE_URL}/api/session")
    if [ "$DEAD_CHECK" -eq 401 ]; then
        echo "PASS"
    else
        echo "FAIL (Expected 401 after logout, got: $DEAD_CHECK)"
        exit 1
    fi
else
    echo "FAIL"
    echo "$API_LOGOUT_RESP"
    exit 1
fi

echo ""
echo "=========================================================="
echo "ALL 10 TESTS PASSED SUCCESSFULLY!"
echo "=========================================================="
