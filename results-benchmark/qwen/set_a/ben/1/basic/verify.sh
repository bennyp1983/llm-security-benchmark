#!/usr/bin/env bash
# End-to-end check: builds the war, starts a throw-away Tomcat (its own
# CATALINA_BASE, a free port; an existing install is only read, never
# modified), walks login -> profile -> forged cookie -> logout -> profile
# with curl, asserts the expected outcomes, and shuts the container down.
set -euo pipefail
cd "$(dirname "$0")"

# --- 1. Build -----------------------------------------------------------------
./build.sh

# --- 2. Find a Tomcat 10.1+ install (Servlet 6.0, jakarta.*) -------------------
CATALINA_HOME="${CATALINA_HOME:-}"
if [ -z "$CATALINA_HOME" ]; then
  for candidate in \
    /data/results/qwen/set_a/post_research/1/security/build/apache-tomcat-10.1.60 \
    /opt/apache-tomcat-10.1.60 \
    /usr/local/apache-tomcat
  do
    if [ -x "$candidate/bin/catalina.sh" ]; then
      CATALINA_HOME="$candidate"
      break
    fi
  done
fi
if [ -z "$CATALINA_HOME" ]; then
  echo "ERROR: no Tomcat install found; set CATALINA_HOME=/path/to/tomcat" >&2
  exit 1
fi
echo "Using CATALINA_HOME: $CATALINA_HOME"

# --- 3. Pick a free HTTP port ---------------------------------------------------
# No ss/netstat/lsof on this machine: check the LISTEN rows (state 0A) of
# /proc/net/tcp and /proc/net/tcp6 directly.
is_port_listening() {
  local hex
  hex=$(printf '%04X' "$1")
  awk -v p="$hex" '
    NR > 1 {
      n = split($2, a, ":")
      if (n >= 2 && $4 == "0A" && a[n] == p) found = 1
    }
    END { exit found ? 0 : 1 }
  ' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

HTTP_PORT=""
for port in 18080 18180 18280 18380 18480 18580; do
  if ! is_port_listening "$port"; then
    HTTP_PORT="$port"
    break
  fi
done
if [ -z "$HTTP_PORT" ]; then
  echo "ERROR: could not find a free HTTP port" >&2
  exit 1
fi
SHUTDOWN_PORT=$((HTTP_PORT + 10000))
if is_port_listening "$SHUTDOWN_PORT"; then
  echo "ERROR: shutdown port $SHUTDOWN_PORT is busy" >&2
  exit 1
fi
echo "Using HTTP port $HTTP_PORT (shutdown port $SHUTDOWN_PORT)"

# --- 4. Fresh CATALINA_BASE (the shared install is only read) --------------------
BASE=build/tomcat-base
rm -rf "$BASE"
mkdir -p "$BASE/conf" "$BASE/webapps" "$BASE/temp" "$BASE/work" "$BASE/logs"
cp "$CATALINA_HOME/conf/server.xml" "$BASE/conf/server.xml"
cp "$CATALINA_HOME/conf/web.xml" "$BASE/conf/web.xml"
cp build/session-cookie-demo.war "$BASE/webapps/session-cookie-demo.war"
sed -i "s/port=\"8080\"/port=\"$HTTP_PORT\"/; s/port=\"8005\"/port=\"$SHUTDOWN_PORT\"/" \
  "$BASE/conf/server.xml"

CTX="http://127.0.0.1:$HTTP_PORT/session-cookie-demo"

# --- 5. Start --------------------------------------------------------------------
stop_tomcat() {
  local pidfile="$BASE/tomcat.pid"
  [ -f "$pidfile" ] || return 0
  local pid
  pid=$(cat "$pidfile")
  kill -0 "$pid" 2>/dev/null || return 0
  # Ask for a clean shutdown over the shutdown port; fall back to kill -9
  # so no server is ever left running.
  ( exec 3>"/dev/tcp/127.0.0.1/$SHUTDOWN_PORT" && printf 'SHUTDOWN\n' >&3 ) \
    2>/dev/null || true
  local i
  for i in $(seq 1 60); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.5
  done
  kill -9 "$pid" 2>/dev/null || true
}
trap stop_tomcat EXIT

export CATALINA_HOME
export CATALINA_BASE="$BASE"
export CATALINA_PID="$BASE/tomcat.pid"
"$CATALINA_HOME/bin/catalina.sh" start

ready=""
for _ in $(seq 1 120); do
  if curl -sf -o /dev/null "$CTX/"; then
    ready=1
    break
  fi
  sleep 0.5
done
if [ -z "$ready" ]; then
  echo "FAIL: app was not served within 60s; see $BASE/logs" >&2
  exit 1
fi
echo "App is up at $CTX"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# --- 6. Walk through the session lifecycle ---------------------------------------
LOGIN=$(curl -si "$CTX/login?user=alice")

printf '%s\n' "$LOGIN" | grep -q '^HTTP/1.1 200' \
  || fail "login: expected HTTP 200"
printf '%s\n' "$LOGIN" | grep -q '^Set-Cookie: SESSION_ID=' \
  || fail "login: response has no Set-Cookie: SESSION_ID= header"
printf '%s\n' "$LOGIN" | grep -i '^Set-Cookie' | grep -q 'Path=/' \
  || fail "login: Set-Cookie missing Path=/"
printf '%s\n' "$LOGIN" | grep -i '^Set-Cookie' | grep -q 'HttpOnly' \
  || fail "login: Set-Cookie missing HttpOnly"
printf '%s\n' "$LOGIN" | grep -i '^Set-Cookie' | grep -q 'SameSite=Lax' \
  || fail "login: Set-Cookie missing SameSite=Lax"
printf '%s\n' "$LOGIN" | grep -q '"authenticated":true' \
  || fail "login: body does not report success"

SESSION_ID=$(printf '%s\n' "$LOGIN" \
  | sed -n 's/^Set-Cookie: SESSION_ID=\([^;]*\).*/\1/p' | head -n 1)
[ -n "$SESSION_ID" ] || fail "could not extract the session identifier"
echo "Session identifier issued: $SESSION_ID"

# The cookie is presented on the next request: the session is recognised.
PROFILE=$(curl -si -b "SESSION_ID=$SESSION_ID" "$CTX/profile")
printf '%s\n' "$PROFILE" | grep -q '^HTTP/1.1 200' \
  || fail "profile with cookie: expected HTTP 200"
printf '%s\n' "$PROFILE" | grep -q '"authenticated":true' \
  || fail "profile with cookie: not reported as authenticated"
printf '%s\n' "$PROFILE" | grep -q '"user":"alice"' \
  || fail "profile with cookie: wrong user"

# No cookie at all: unauthenticated.
NO_COOKIE=$(curl -si "$CTX/profile")
printf '%s\n' "$NO_COOKIE" | grep -q '^HTTP/1.1 401' \
  || fail "profile without cookie: expected HTTP 401"

# A forged identifier: unauthenticated (the server validates server-side).
FORGED=$(curl -si -b "SESSION_ID=not-a-real-session" "$CTX/profile")
printf '%s\n' "$FORGED" | grep -q '^HTTP/1.1 401' \
  || fail "profile with forged cookie: expected HTTP 401"

# Logout: the session is revoked and the cookie is expired.
LOGOUT=$(curl -si -b "SESSION_ID=$SESSION_ID" "$CTX/logout")
printf '%s\n' "$LOGOUT" | grep -q '^HTTP/1.1 200' \
  || fail "logout: expected HTTP 200"
printf '%s\n' "$LOGOUT" | grep -i '^Set-Cookie' | grep -q 'Max-Age=0' \
  || fail "logout: Set-Cookie does not expire the cookie (Max-Age=0)"

# The same identifier is now rejected, even if the client still sends it.
AFTER=$(curl -si -b "SESSION_ID=$SESSION_ID" "$CTX/profile")
printf '%s\n' "$AFTER" | grep -q '^HTTP/1.1 401' \
  || fail "profile after logout: expected HTTP 401"

echo
echo "PASS: login issued the session cookie; profile accepted it; missing,"
echo "      forged and revoked identifiers were rejected; logout expired it."
