#!/bin/bash
#
# End-to-end checks against the packaged war, deployed into a throwaway Tomcat and driven with curl.
# Nothing here reasons about what the container "should" do: every check asserts on bytes that came
# off the wire -- status line, Set-Cookie attributes, Location header, page body, elapsed time.
#
#   ./tests/end-to-end.sh             build, deploy, test, shut down
#   KEEP_UP=1 ./tests/end-to-end.sh   leave Tomcat running afterwards to poke at by hand
#
set -u

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=../tools/tomcat-env.sh
. "$PROJECT_DIR/tools/tomcat-env.sh"

PASS=0
FAIL=0
# Scratch lives outside build/: build.sh deletes that tree, and it runs after this line.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/auth-e2e.XXXXXX")
CHECK=""
JAR=""
STATUS=""
HDRS="$WORK/hdr.txt"
BODY="$WORK/body.txt"

# assert <what it proves> <shell condition, evaluated> [extra detail on failure]
assert() {
  local what="$1" condition="$2" detail="${3:-}"
  if eval "$condition"; then
    PASS=$((PASS + 1))
    printf 'ok    %s\n' "$what"
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL  %s\n      %s\n' "$what" "${detail:-condition failed: $condition}"
  fi
}

cleanup() { [ -n "${KEEP_UP:-}" ] || stop_tomcat; rm -rf "$WORK"; }
trap cleanup EXIT

# --- helpers ---------------------------------------------------------------

hdr() { tr -d '\r' < "$HDRS" | grep -i "^$1:"; }

# req <method> <path> [curl extras] -- sends with $JAR as the cookie store when it is set.
req() {
  local method="$1" path="$2"
  shift 2
  : > "$HDRS"; : > "$BODY"
  local -a cookies=()
  [ -n "$JAR" ] && cookies=(-c "$JAR" -b "$JAR")
  STATUS=$(curl -sS -o "$BODY" -D "$HDRS" -w '%{http_code}' -X "$method" "${cookies[@]}" \
      "$@" "$BASE_URL$path" 2>/dev/null)
}

cookie_value() { printf '%s' "$1" | sed 's/^[Ss]et-[Cc]ookie: [^=]*=//' | cut -d';' -f1; }

set_cookie_line() { tr -d '\r' < "$1" | grep -i "^set-cookie: app_session=" | head -n 1; }

# jar_value <cookie-jar> -> the app_session value a browser would send from this jar
jar_value() { awk '$6 == "app_session" { print $7; exit }' "$1"; }

# Serve a sign-in page into a clean jar and echo its form token. The base URL is a parameter so the
# TLS checks can fetch their form over HTTPS rather than borrowing an HTTP page.
page_token() { # page_token <jar> <where-to-save-html> [base-url]
  local base="${3:-$BASE_URL}" extra=""
  [ "$base" = "${base#https://}" ] || extra="-k"
  # shellcheck disable=SC2086
  curl -sS $extra -o "$2" -c "$1" "$base/login" >/dev/null
  sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$2" | head -n 1
}

# Full browser-like sign-in: a fresh page, then the post carrying that page's cookie and token.
attempt_login() { # attempt_login <jar> <username> <password> [remember]
  local jar="$1" user="$2" pass="$3" remember="${4:-}"
  rm -f "$jar"
  local token
  token=$(page_token "$jar" "$WORK/form.html")
  : > "$HDRS"; : > "$BODY"
  local -a form=(-d "username=$user" --data-urlencode "password=$pass"
                 --data-urlencode "csrf_token=$token")
  [ "$remember" = "remember" ] && form+=(-d "remember=on")
  STATUS=$(curl -sS -o "$BODY" -D "$HDRS" -w '%{http_code}' -c "$jar" -b "$jar" \
      -X POST "$BASE_URL/login" "${form[@]}")
}

# Wall-clock seconds for one full sign-in attempt, as reported by curl.
timed_login() { # timed_login <jar> <username> <password>
  local jar="$1" user="$2" pass="$3" token
  rm -f "$jar"
  token=$(page_token "$jar" "$WORK/timed.html")
  curl -sS -o /dev/null -w '%{time_total}' -c "$jar" -b "$jar" -X POST "$BASE_URL/login" \
      -d "username=$user" --data-urlencode "password=$pass" --data-urlencode "csrf_token=$token"
}

echo "== building =="
"$PROJECT_DIR/build.sh" >/dev/null || { echo "build failed"; exit 1; }

echo "== starting =="
start_tomcat || exit 1
echo "   $BASE_URL via $TOMCAT_HOME"
echo

# --- the status endpoint needs no session ----------------------------------
CHECK="GET /status answers without any cookie"
JAR=""
req GET /status
assert "$CHECK" "[ '$STATUS' = 200 ]" "got $STATUS"
assert "and it reports the settings web.xml actually asked for" \
  "grep -q '\"passwordIterations\":240000' '$BODY'" "$(cat "$BODY")"
assert "the password algorithm is named" \
  "grep -q '\"passwordAlgorithm\":\"pbkdf2-sha256\"' '$BODY'" "$(cat "$BODY")"
assert "the idle timeout is 30 minutes" \
  "grep -q '\"sessionIdleTimeoutSeconds\":1800' '$BODY'" "$(cat "$BODY")"
assert "the absolute timeout is 8 hours" \
  "grep -q '\"sessionAbsoluteTimeoutSeconds\":28800' '$BODY'" "$(cat "$BODY")"
assert "the cookie it will issue is named" \
  "grep -q '\"cookieName\":\"app_session\"' '$BODY'" "$(cat "$BODY")"
assert "and flagged HttpOnly / SameSite=Lax" \
  "grep -q '\"cookieHttpOnly\":true' '$BODY' && grep -q '\"cookieSameSite\":\"Lax\"' '$BODY'" "$(cat "$BODY")"
assert "it says this visitor is not signed in" \
  "grep -q '\"signedIn\":false' '$BODY'" "$(cat "$BODY")"
assert "the status endpoint mints no cookie of its own" \
  "! grep -qi 'set-cookie' '$HDRS'" "$(tr -d '\r' < "$HDRS" | grep -i set-cookie)"

CHECK="the public status answer names no account and no secret"
assert "$CHECK" "! grep -qiE 'alice|bob|salt|digest' '$BODY'" "leakage: $(cat "$BODY")"

# --- the gate --------------------------------------------------------------
CHECK="GET /account with no cookie is redirected to the sign-in page"
JAR=""
req GET /account
assert "$CHECK" "[ '$STATUS' = 302 ]" "got $STATUS"
assert "pointing at the sign-in page of this application" \
  "hdr location | grep -q '^Location: /app/login\$'" "Location: $(hdr location)"
assert "and marked uncacheable, so a proxy cannot serve the refusal later" \
  "hdr cache-control | grep -qi 'no-store'" "Cache-Control: $(hdr cache-control)"

CHECK="POST /account with no cookie gets 401 JSON, not a redirect that would drop the method"
JAR=""
req POST /account -d 'note=hello'
assert "$CHECK" "[ '$STATUS' = 401 ]" "got $STATUS"
assert "carrying a machine-readable refusal" \
  "grep -q '\"error\":\"not_signed_in\"' '$BODY'" "$(cat "$BODY")"

CHECK="a path nobody mapped is protected too, so denying is the default"
JAR=""
req GET /some-page-that-does-not-exist
assert "$CHECK" "[ '$STATUS' = 302 ]" "got $STATUS"

# --- the sign-in page ------------------------------------------------------
CHECK="GET /login sets a session cookie carrying the attributes this app promises"
JAR="$WORK/browser1.txt"
rm -f "$JAR"
curl -sS -o "$WORK/login.html" -D "$WORK/login.hdr" -c "$JAR" "$BASE_URL/login" >/dev/null
FORM_LINE=$(set_cookie_line "$WORK/login.hdr")
assert "$CHECK" "[ -n '$FORM_LINE' ]" "no app_session cookie in $(tr -d '\r' < "$WORK/login.hdr" | grep -i set-cookie)"
assert "HttpOnly, so page script cannot read the session id" \
  "printf '%s' '$FORM_LINE' | grep -qi 'HttpOnly'" "$FORM_LINE"
assert "SameSite=Lax, so a cross-site form post never carries it" \
  "printf '%s' '$FORM_LINE' | grep -qi 'SameSite=Lax'" "$FORM_LINE"
assert "Path=/app, so it is sent only to this application" \
  "printf '%s' '$FORM_LINE' | grep -qi 'Path=/app'" "$FORM_LINE"

CHECK="a sign-in cookie is a browser-session cookie: no Max-Age, no Expires"
assert "$CHECK" "! printf '%s' '$FORM_LINE' | grep -qiE 'Max-Age|Expires'" "$FORM_LINE"

CHECK="the session id is 43 Base64url characters (256 bits of randomness)"
SID=$(cookie_value "$FORM_LINE")
assert "$CHECK" "printf '%s' '$SID' | grep -qE '^[A-Za-z0-9_-]{43}\$'" "id is '$SID'"
assert "and it never travels as a JSESSIONID or in a URL" \
  "! grep -qi 'jsessionid' '$WORK/login.hdr'" "jsessionid present"

CHECK="the form carries a single-use token, and the page never prints the session id"
TOKEN=$(page_token "$JAR" "$WORK/login.html")
assert "$CHECK" "[ ${#TOKEN} -ge 40 ]" "token too short: '$TOKEN'"
assert "the session id appears nowhere in the page" \
  "! grep -q -e '$SID' '$WORK/login.html'" "session id echoed into the page"

# --- wrong credentials -----------------------------------------------------
CHECK="a wrong password is refused with a message that gives nothing away"
JAR="$WORK/badpassword.txt"
attempt_login "$JAR" alice 'WrongPassword99'
assert "$CHECK" "[ '$STATUS' = 401 ]" "got $STATUS"
assert "the generic message, not 'no such user' or 'wrong password'" \
  "grep -q 'Invalid username or password.' '$BODY'" "$(sed -n 's/.*class=\"error\"[^>]*>\([^<]*\).*/\1/p' "$BODY" | head -n 1)"
assert "and the protected page is definitely not rendered" \
  "! grep -q '<h1>Signed in</h1>' '$BODY'" "the refusal also signed them in"

CHECK="a refused attempt grants no identity and persists nothing"
assert "$CHECK" "! printf '%s' \"$(set_cookie_line "$HDRS")\" | grep -qiE 'Max-Age|Expires'" \
  "the refusal persisted a cookie: $(set_cookie_line "$HDRS")"
req GET /account
assert "the cookie this browser holds still cannot reach the protected page" \
  "[ '$STATUS' = 302 ]" "the refused visitor reached /account ($STATUS)"

CHECK="an unknown username gets the same status and the same message"
attempt_login "$JAR" nosuchuseratall 'WrongPassword99'
assert "$CHECK" "[ '$STATUS' = 401 ]" "got $STATUS"
assert "so the endpoint cannot be used to enumerate accounts" \
  "grep -q 'Invalid username or password.' '$BODY'" "different answer for an unknown user"

CHECK="which usernames exist is not answerable by stopwatch either"
BAD_MS=$(timed_login "$WORK/t1.txt" alice 'WrongPassword99')
UNKNOWN_MS=$(timed_login "$WORK/t2.txt" nosuchuseratall 'WrongPassword99')
assert "a rejected attempt really does pay the password-stretching cost" \
  "awk -v a='$BAD_MS' 'BEGIN{ exit !(a > 0.05) }'" "only ${BAD_MS}s - nothing was stretched"
assert "and the unknown-username answer arrives just as slowly" \
  "awk -v a='$BAD_MS' -v b='$UNKNOWN_MS' 'BEGIN{ exit !(b >= a*0.4 && b <= a*2.5) }'" \
  "wrong-password ${BAD_MS}s vs unknown-user ${UNKNOWN_MS}s"

# --- correct credentials ---------------------------------------------------
CHECK="a correct password redirects to the protected page"
JAR="$WORK/alice.txt"
attempt_login "$JAR" alice 'Alice!2345'
assert "$CHECK" "[ '$STATUS' = 302 ]" "got $STATUS, body: $(head -c 160 "$BODY")"
assert "the Location header names the protected page" \
  "hdr location | grep -q '^Location: /app/account\$'" "Location: $(hdr location)"
LOGIN_LINE=$(set_cookie_line "$HDRS")
NEW_SID=$(cookie_value "$LOGIN_LINE")

CHECK="the cookie that survives the login is a brand-new id, never the pre-login one"
assert "$CHECK" "[ -n '$NEW_SID' ] && [ '$NEW_SID' != '$SID' ]" \
  "pre-login $SID, post-login $NEW_SID"
assert "it is HttpOnly" "printf '%s' '$LOGIN_LINE' | grep -qi 'HttpOnly'" "$LOGIN_LINE"
assert "and SameSite=Lax" "printf '%s' '$LOGIN_LINE' | grep -qi 'SameSite=Lax'" "$LOGIN_LINE"

CHECK="the protected page renders for that cookie and says who is signed in"
req GET /account
assert "$CHECK" "[ '$STATUS' = 200 ]" "got $STATUS"
assert "the page rendered" "grep -q '<h1>Signed in</h1>' '$BODY'" "no page"
assert "the username is shown" "grep -q 'alice' '$BODY'" "username missing"
assert "the roles from the account are shown" "grep -q 'admin, user' '$BODY'" "roles missing"
assert "the session id itself is not printed anywhere" \
  "! grep -q -e '$NEW_SID' '$BODY'" "session id leaked into the page"

CHECK="the status endpoint now reports this visitor as signed in"
req GET /status
assert "$CHECK" "grep -q '\"signedIn\":true' '$BODY'" "$(cat "$BODY")"

CHECK="a session id of the right shape that this server never issued is refused"
FORGED="${NEW_SID%?}Z"
[ "$FORGED" = "$NEW_SID" ] && FORGED="${NEW_SID%?}Y"
JAR="$WORK/forged.txt"
printf '# Netscape HTTP Cookie File\n127.0.0.1\tFALSE\t/\tFALSE\t0\tapp_session\t%s\n' "$FORGED" > "$JAR"
req GET /account
assert "$CHECK" "[ '$STATUS' = 302 ]" "forged id $FORGED accepted ($STATUS)"

# --- the form token gates the post -----------------------------------------
CHECK="a login POST without the form token cannot sign anyone in"
JAR="$WORK/notoken.txt"
rm -f "$JAR"
curl -sS -o /dev/null -c "$JAR" "$BASE_URL/login" >/dev/null
STATUS=$(curl -sS -o "$WORK/no.html" -D "$HDRS" -w '%{http_code}' -c "$JAR" -b "$JAR" -X POST \
    "$BASE_URL/login" -d 'username=alice' --data-urlencode 'password=Alice!2345')
assert "$CHECK" "[ '$STATUS' = 401 ]" "got $STATUS"
assert "even with a perfect password" \
  "! hdr location | grep -qi 'account'" "the token-less post signed them in"

CHECK="a form token posted twice is only honoured once"
JAR="$WORK/replay.txt"
rm -f "$JAR"
TOKEN=$(page_token "$JAR" "$WORK/replay-form.html")
replay() { curl -sS -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" -X POST "$BASE_URL/login" \
    -d 'username=alice' --data-urlencode 'password=Alice!2345' --data-urlencode "csrf_token=$TOKEN"; }
FIRST=$(replay)
SECOND=$(replay)
assert "$CHECK" "[ '$FIRST' = 302 ] && [ '$SECOND' = 401 ]" "first=$FIRST second=$SECOND"

CHECK="signing out by GET is refused, so a link or an img tag cannot do it"
JAR="$WORK/alice.txt"
req GET /logout
assert "$CHECK" "[ '$STATUS' = 405 ]" "got $STATUS"
assert "with an Allow header naming the real method" "hdr allow | grep -qi 'POST'" "no Allow header"

# --- remember me -----------------------------------------------------------
CHECK="'keep me signed in' sets a Max-Age the server decided, inside the absolute timeout"
JAR="$WORK/remember.txt"
attempt_login "$JAR" alice 'Alice!2345' remember
REMEMBER_LINE=$(set_cookie_line "$HDRS")
assert "$CHECK" "printf '%s' '$REMEMBER_LINE' | grep -qiE 'Max-Age=[0-9]+'" "no Max-Age: $REMEMBER_LINE"
MAX_AGE=$(printf '%s' "$REMEMBER_LINE" | sed 's/.*[Mm]ax-[Aa]ge=\([0-9]*\).*/\1/')
assert "the lifetime is bounded by the 8 hour ceiling" \
  "[ '$MAX_AGE' -gt 28000 ] && [ '$MAX_AGE' -le 28800 ]" "Max-Age=$MAX_AGE"
assert "with a matching Expires attribute" \
  "printf '%s' '$REMEMBER_LINE' | grep -qi 'Expires='" "$REMEMBER_LINE"

# --- logout ----------------------------------------------------------------
CHECK="signing out tells the browser to drop the cookie"
JAR="$WORK/alice.txt"
SAVED_SID=$(jar_value "$JAR")
req POST /logout
assert "$CHECK" "[ '$STATUS' = 200 ]" "got $STATUS"
CLEARED=$(set_cookie_line "$HDRS")
assert "by re-issuing it with Max-Age=0" \
  "printf '%s' '$CLEARED' | grep -qiE 'Max-Age=0|Expires=Thu, 01 Jan 1970'" "cookie: $CLEARED"

CHECK="the signed-out id is dead server-side, even replayed by hand"
JAR="$WORK/replay-old-cookie.txt"
printf '# Netscape HTTP Cookie File\n127.0.0.1\tFALSE\t/\tFALSE\t0\tapp_session\t%s\n' "$SAVED_SID" > "$JAR"
req GET /account
assert "$CHECK" "[ '$STATUS' = 302 ]" "the old id $SAVED_SID still works ($STATUS)"

CHECK="two sign-ins never share a session id"
attempt_login "$WORK/s1.txt" alice 'Alice!2345' >/dev/null
A_SID=$(cookie_value "$(set_cookie_line "$HDRS")")
attempt_login "$WORK/s2.txt" alice 'Alice!2345' >/dev/null
B_SID=$(cookie_value "$(set_cookie_line "$HDRS")")
assert "$CHECK" "[ -n '$A_SID' ] && [ '$A_SID' != '$B_SID' ]" "both got $A_SID"

CHECK="each sign-in is its own session: signing one out leaves the other alone"
JAR="$WORK/s1.txt"
req POST /logout >/dev/null
JAR="$WORK/s2.txt"
req GET /account
assert "$CHECK" "[ '$STATUS' = 200 ]" "the sibling session was lost ($STATUS)"

CHECK="a session keeps working while it is being used"
JAR="$WORK/s2.txt"
req GET /account; A=$STATUS
req GET /account; B=$STATUS
assert "$CHECK" "[ '$A' = 200 ] && [ '$B' = 200 ]" "$A then $B"

# --- over TLS --------------------------------------------------------------
# The Secure attribute can only be observed on a TLS connection, so the throwaway Tomcat also
# listens for HTTPS with a throwaway certificate. Without this the flag would silently never appear.
CHECK="over HTTPS the cookie is marked Secure as well"
JAR="$WORK/tls.txt"
rm -f "$JAR"
curl -skS -o "$WORK/tls.html" -D "$WORK/tls.hdr" -c "$JAR" "$SECURE_URL/login" >/dev/null
TLS_LINE=$(set_cookie_line "$WORK/tls.hdr")
if [ -z "$TLS_LINE" ]; then
  assert "$CHECK" "false" "TLS did not come up - no cookie from $SECURE_URL/login"
else
  assert "$CHECK" "printf '%s' '$TLS_LINE' | grep -qi 'Secure'" "$TLS_LINE"
  TLS_TOKEN=$(page_token "$JAR" "$WORK/tls-form.html" "$SECURE_URL")
  : > "$HDRS"
  STATUS=$(curl -skS -o "$WORK/tls-body.txt" -D "$HDRS" -w '%{http_code}' -c "$JAR" -b "$JAR" \
      -X POST "$SECURE_URL/login" -d 'username=alice' --data-urlencode 'password=Alice!2345' \
      --data-urlencode "csrf_token=$TLS_TOKEN")
  assert "and a sign-in over TLS still works" "[ '$STATUS' = 302 ]" "got $STATUS"
  assert "the session cookie it issues is Secure too" \
    "printf '%s' '$(set_cookie_line "$HDRS")' | grep -qi 'Secure'" "$(set_cookie_line "$HDRS")"
  curl -skS -o "$WORK/tls-status.txt" -b "$JAR" "$SECURE_URL/status" >/dev/null
  assert "the status endpoint reports the connection as secure" \
    "grep -q '\"cookieSecure\":true' '$WORK/tls-status.txt'" "$(cat "$WORK/tls-status.txt")"
fi

CHECK="over plain HTTP the cookie is deliberately not marked Secure"
JAR="$WORK/plain-http.txt"
attempt_login "$JAR" alice 'Alice!2345'
assert "$CHECK" "! printf '%s' '$(set_cookie_line "$HDRS")' | grep -qiE 'Secure'" \
  "Secure appeared on an insecure connection: $(set_cookie_line "$HDRS")"

# --- lockout ---------------------------------------------------------------
CHECK="five failures for one account name, and the next attempt is refused"
JAR="$WORK/locked.txt"
refused_early=""
for n in 1 2 3 4 5; do
  attempt_login "$JAR" bob 'not-the-password'
  if [ "$STATUS" != 401 ]; then
    refused_early="attempt $n returned $STATUS, expected 401"
    break
  fi
done
assert "$CHECK" "[ -z '$refused_early' ] && [ '$STATUS' = 401 ]" \
  "${refused_early:-the fifth attempt was already refused with $STATUS}"
attempt_login "$JAR" bob 'not-the-password'
assert "the sixth attempt gets 429 with a Retry-After" \
  "[ '$STATUS' = 429 ] && hdr retry-after | grep -qiE 'Retry-After: [0-9]+'" \
  "got $STATUS, Retry-After: $(hdr retry-after)"
attempt_login "$JAR" bob 'B0b-the-Builder'
assert "and during the lockout even the correct password is refused" \
  "[ '$STATUS' = 429 ]" "the lockout let the right password through ($STATUS)"

CHECK="the lockout follows the account name, so alice is untouched by bob's lockout"
attempt_login "$WORK/alice-after.txt" alice 'Alice!2345'
assert "$CHECK" "[ '$STATUS' = 302 ]" "got $STATUS"

echo
echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ] || exit 1
