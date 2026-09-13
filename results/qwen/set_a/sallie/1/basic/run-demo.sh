#!/bin/bash
#
# Builds the war, deploys it into a throwaway Tomcat under build/tomcat, and drives one full sign-in
# with curl so the cookie exchange is visible on screen: the cookie the server sets, the cookie the
# browser sends back, what the protected page says, and what happens after signing out.
#
#   ./run-demo.sh              build (if needed), start, demo, shut down
#   ./run-demo.sh --keep-open  leave the server listening afterwards (default port 8181)
#
# Port and Tomcat install come from the environment: HTTP_PORT, SHUTDOWN_PORT, TOMCAT_HOME.
#
set -u

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=tools/tomcat-env.sh
. "$PROJECT_DIR/tools/tomcat-env.sh"

KEEP_OPEN=""
[ "${1:-}" = "--keep-open" ] && KEEP_OPEN=1

step() { printf '\n\033[1m-- %s\033[0m\n' "$1"; }
show() { printf '%s\n' "$1" | sed 's/^/     /'; }

JAR="$BUILD_DIR/demo-cookies.txt"
rm -f "$JAR"

step "building"
if [ ! -f "$WAR" ] || [ -n "$(find "$PROJECT_DIR/src" "$PROJECT_DIR/build.sh" -newer "$WAR" 2>/dev/null | head -n 1)" ]; then
  "$PROJECT_DIR/build.sh"
else
  show "$WAR is up to date (./build.sh clean to force)"
fi

step "starting Tomcat on port $HTTP_PORT"
start_tomcat || exit 1
show "$BASE_URL"
if [ -z "$KEEP_OPEN" ]; then
  trap 'printf "\n"; step "shutting down"; stop_tomcat; show "stopped"' EXIT
fi

step "1. GET /status - no cookie needed, shows what the app is configured to do"
STATUS_JSON=$(curl -sS "$BASE_URL/status")
show "$STATUS_JSON"

step "2. GET /account - no cookie yet, so the app refuses and points at the sign-in page"
show "$(curl -sS -o /dev/null -D - "$BASE_URL/account" | tr -d '\r' | grep -E '^HTTP/|^Location:|^Cache-Control:')"

step "3. GET /account as an API call (Accept: application/json) - a 401 body, not a redirect"
show "$(curl -sS -H 'Accept: application/json' -o - -w '\n     (status %{http_code})' "$BASE_URL/account")"

step "4. GET /login - the server sets a session cookie and hands out a single-use form token"
curl -sS -o "$BUILD_DIR/demo-login.html" -D "$BUILD_DIR/demo-login.hdr" -c "$JAR" "$BASE_URL/login"
show "$(grep -i '^set-cookie:' "$BUILD_DIR/demo-login.hdr" | tr -d '\r')"
TOKEN=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$BUILD_DIR/demo-login.html" | head -n 1)
show "form token: ${TOKEN:0:16}... (${#TOKEN} chars, single-use)"
# curl marks HttpOnly entries by prefixing the host with "#HttpOnly_", so strip it before reading
# the columns - skipping those lines as comments makes the jar look empty.
show "cookie jar now holds: $(sed 's/^#HttpOnly_//' "$JAR" | awk '!/^#/ && NF >= 7 {print $6 "=" substr($7,1,12) "..."}')"

step "5. POST /login with the wrong password - 401, same message whichever username it was"
show "$(curl -sS -o "$BUILD_DIR/demo-bad.html" -D "$BUILD_DIR/demo-bad.hdr" -w '(status %{http_code})\n' \
    -c "$JAR" -b "$JAR" -X POST "$BASE_URL/login" -d 'username=alice' \
    --data-urlencode 'password=fingered-into-the-wrong-window' \
    --data-urlencode "csrf_token=$TOKEN" \
    && grep -o 'class="error"[^<]*<' "$BUILD_DIR/demo-bad.html" | sed 's/<$//')"

step "6. GET /login again, then POST the real credentials for alice"
rm -f "$JAR"
TOKEN=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' \
    <(curl -sS -c "$JAR" "$BASE_URL/login") | head -n 1)
show "response headers:"
show "$(curl -sS -o /dev/null -D - -c "$JAR" -b "$JAR" -X POST "$BASE_URL/login" \
    -d 'username=alice' --data-urlencode 'password=Alice!2345' \
    --data-urlencode "csrf_token=$TOKEN" | tr -d '\r' | grep -E '^HTTP/|^Location:|^Set-Cookie:')"
show "the session id in that Set-Cookie is new: it is not the id the sign-in page was given."

step "7. GET /account - the browser now sends the cookie, and the page renders"
# Print the body text only: stripping tags from the whole document leaves the stylesheet behind.
show "$(curl -sS -b "$JAR" "$BASE_URL/account" | sed -n '/<body>/,/<\/body>/p' \
    | sed -e 's/<[^>]*>//g' -e '/^[[:space:]]*$/d')"

step "8. POST /logout - the record is deleted and the cookie is cleared"
show "$(curl -sS -o /dev/null -D - -b "$JAR" -c "$JAR" -X POST "$BASE_URL/logout" | tr -d '\r' \
    | grep -E '^HTTP/|^Set-Cookie:')"

step "9. GET /account again - the same cookie value is dead server-side"
show "$(curl -sS -o /dev/null -D - -b "$JAR" "$BASE_URL/account" | tr -d '\r' | grep -E '^HTTP/|^Location:')"

if [ -n "$KEEP_OPEN" ]; then
  printf '\nServer left running at %s\n' "$BASE_URL"
  printf 'Sign in as alice / Alice!2345, then stop it with:\n'
  printf '  CATALINA_HOME=%s CATALINA_BASE=%s %s/bin/catalina.sh stop\n\n' \
      "$TOMCAT_HOME" "$CATALINA_BASE" "$TOMCAT_HOME"
fi
