#!/bin/bash
# Builds, deploys to a throwaway Tomcat and drives real HTTP assertions.
# Usage: ./build.sh            build + in-process harness + end-to-end (all three modes)
#        ./build.sh --unit     build + in-process harness only
set -u -o pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

SERVLET_API="${SERVLET_API_JAR:-tools/jakarta.servlet-api-6.0.0.jar}"
TOMCAT_HOME="build/apache-tomcat-10.1.60"
JAVA_HOME_DIR="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
JAVAC="$JAVA_HOME_DIR/bin/javac"
JAVA="$JAVA_HOME_DIR/bin/java"
JAR="$JAVA_HOME_DIR/bin/jar"
LOG_DIR="build/logs"
RC=0

if [ ! -f "$SERVLET_API" ]; then
  echo "ERROR servlet API jar not found at $SERVLET_API (see README for the pinned download)" >&2
  exit 2
fi
if [ ! -x "$JAVAC" ]; then
  echo "ERROR JDK not found at JAVA_HOME=$JAVA_HOME_DIR" >&2
  exit 2
fi
mkdir -p "$LOG_DIR"

# --- Third-party integrity gate (rule 8). Both files are used to compile and to run, so neither is
# --- trusted because it happens to be on disk. The jar is checked against the SHA-1 published next to
# --- it on Maven Central and against a locally pinned SHA-512 (the .pinned- prefix says the expected
# --- hash came from this project, not from the publisher -- Maven publishes only .sha1 here).
verify_publisher_sha1() {
  # The published .sha1 holds a bare digest with no file name, which `sha1sum -c` refuses to parse,
  # so the digests are compared directly. The 40-character check keeps an empty or truncated
  # signature file from matching nothing at all.
  [ -f "$2" ] || return 1
  local expected actual
  expected=$(tr -cd '0-9a-fA-F' < "$2" | tr 'A-F' 'a-f')
  actual=$(sha1sum "$1" | cut -d' ' -f1)
  [ "${#expected}" -eq 40 ] && [ "$expected" = "$actual" ]
}

verify_publisher_sha1 "$SERVLET_API" "$SERVLET_API.sha1" \
  || { echo "ERROR $SERVLET_API does not match the SHA-1 published with it" >&2; exit 2; }
( cd "$(dirname "$SERVLET_API")" && sha512sum -c "$(basename "$SERVLET_API").pinned-sha512" >/dev/null ) \
  || { echo "ERROR $SERVLET_API does not match the pinned SHA-512" >&2; exit 2; }
echo "NOTE  verified $SERVLET_API against the published SHA-1 and the pinned SHA-512"

# --- Stray-byte gate. A raw control character inside a string literal is invisible in a editor and
# --- in grep output, still compiles, and silently changes behaviour. Fail before anything else.
python3 - <<'PY' || exit 2
import glob, sys
bad = 0
for f in sorted(glob.glob('src/**/*.java', recursive=True)):
    b = open(f, 'rb').read()
    hits = [(i, c) for i, c in enumerate(b)
            if c < 0x09 or (0x0b <= c <= 0x0c) or (0x0e <= c < 0x20) or c == 0x7f or c > 0x7e]
    if hits:
        bad += 1
        print("ERROR %s contains %d stray/non-ASCII byte(s), first at offset %d (0x%02x)"
              % (f, len(hits), hits[0][0], hits[0][1]), file=sys.stderr)
sys.exit(1 if bad else 0)
PY
echo "NOTE  source byte scan clean (ASCII only, no stray control characters)"

# --- Descriptor gate. A malformed web.xml deploys as nothing at all: the container logs one SEVERE
# --- line and then answers 404 for every path, which reads like a broken component. Parse it here.
python3 - <<'PY' || exit 2
import sys, xml.etree.ElementTree as ET
try:
    ET.parse('deploy/web.xml')
except Exception as problem:
    print("ERROR deploy/web.xml is not well-formed: %s" % problem, file=sys.stderr)
    sys.exit(1)
PY
echo "NOTE  deploy/web.xml parses"

echo "NOTE  compiling main sources (-Xlint:all -Werror)"
rm -rf build/classes build/test-classes
mkdir -p build/classes build/test-classes
"$JAVAC" -Xlint:all -Werror -encoding US-ASCII -cp "$SERVLET_API" \
    -d build/classes $(find src/main/java -name '*.java') || exit 2
echo "NOTE  compiling test scaffolding"
"$JAVAC" -Xlint:all -encoding US-ASCII -cp "$SERVLET_API:build/classes" \
    -d build/test-classes $(find src/test/java -name '*.java') || exit 2

echo "NOTE  running the in-process harness"
timeout 600 "$JAVA" -cp "$SERVLET_API:build/classes:build/test-classes" \
    com.acme.portal.session.Harness > "$LOG_DIR/harness.log" 2>&1
HARNESS_RC=$?
# The harness deliberately feeds control characters through the component, so its console output
# legitimately contains them; strip only for display.
tr -d '\000-\010\013\014\016-\037\177' < "$LOG_DIR/harness.log" > "$LOG_DIR/harness.display.log"
grep -E '^(==|      |SUMMARY|FAILED)' "$LOG_DIR/harness.display.log" || true
if [ "$HARNESS_RC" -ne 0 ]; then
  echo "FAIL  in-process harness exited $HARNESS_RC (full log: $LOG_DIR/harness.log)" >&2
  RC=1
fi

if [ "${1:-}" = "--unit" ]; then
  exit "$RC"
fi

# --------------------------------------------------------------------------- war assembly

build_war() {
  # $1 = output war path, $2 = "with"|"without" the session-verifier service registration
  local war="$1" services="$2"
  local stage="build/stage-$(basename "$war" .war)"
  rm -rf "$stage"
  mkdir -p "$stage/WEB-INF/classes" "$stage/WEB-INF/static"
  cp -r build/classes/. "$stage/WEB-INF/classes/"
  # Only the stand-in authenticator, stand-in store and expiry switch belong in a deployed archive.
  # The harness and the HTTP client are compiled for the test classpath and must not ride along: a
  # deployed class is attack surface, and the harness in particular drives the component's internals.
  mkdir -p "$stage/WEB-INF/classes/com/acme/portal/testapp"
  cp build/test-classes/com/acme/portal/testapp/Stub*.class \
     "$stage/WEB-INF/classes/com/acme/portal/testapp/" || return 2
  cp deploy/WEB-INF/static/error.html "$stage/WEB-INF/static/error.html"
  # The shipped descriptor declares a marker instead of the test-only elements; inject the fragment so
  # the descriptor under test is the shipped one plus exactly those elements.
  python3 - "$stage/WEB-INF/web.xml" <<'PY' || return 2
import sys
marker = '<!-- test-only-elements -->'
shipped = open('deploy/web.xml', encoding='utf-8').read()
fragment = open('deploy/web.test-only.xml', encoding='utf-8').read()
if shipped.count(marker) != 1:
    sys.exit("ERROR deploy/web.xml must contain the marker %r exactly once" % marker)
open(sys.argv[1], 'w', encoding='utf-8').write(shipped.replace(marker, fragment, 1))
PY
  python3 - "$stage/WEB-INF/web.xml" <<'PY' || return 2
import sys, xml.etree.ElementTree as ET
try:
    ET.parse(sys.argv[1])
except Exception as problem:
    print("ERROR assembled %s is not well-formed: %s" % (sys.argv[1], problem), file=sys.stderr)
    sys.exit(1)
PY
  if [ "$services" = "with" ]; then
    mkdir -p "$stage/WEB-INF/classes/META-INF/services"
    cp 'src/test/resources/META-INF/services/com.acme.portal.session.SessionHandoffService$SessionStateVerifier' \
       "$stage/WEB-INF/classes/META-INF/services/"
  fi
  rm -f "$war"
  # Deterministic order, classes under WEB-INF/classes (a war with classes at the archive root
  # deploys "successfully" and answers 404 for every path).
  (cd "$stage" && "$JAR" --create --file "$ROOT/$war" -C . WEB-INF) || return 2
}

if [ ! -d "$TOMCAT_HOME" ]; then
  [ -f tools/apache-tomcat-10.1.60.tar.gz ] || { echo "ERROR Tomcat archive missing" >&2; exit 2; }
  # Verified before extraction, not asserted about afterwards: this archive becomes the servlet
  # container that runs the component, so an unverified copy is code execution as root's web server.
  ( cd tools && sha512sum -c apache-tomcat-10.1.60.tar.gz.sha512 >/dev/null ) \
    || { echo "ERROR the Tomcat archive does not match the pinned SHA-512" >&2; exit 2; }
  echo "NOTE  extracting the checksum-verified Tomcat archive"
  mkdir -p build
  tar -xzf tools/apache-tomcat-10.1.60.tar.gz -C build || exit 2
fi

# --------------------------------------------------------------------------- port selection

free_port() {
  # No ss/netstat/lsof on this box: read the LISTEN rows (state 0A) out of /proc/net/tcp. Only
  # LISTEN means a server owns the port; TIME_WAIT rows from the previous run's client connections
  # share the server's local port and would otherwise make every candidate look busy.
  local candidate
  for candidate in $(seq "$1" "$2"); do
    local hex
    hex=$(printf '%04X' "$candidate")
    if ! awk '$4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null \
         | grep -qiE ":${hex}$"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

# --------------------------------------------------------------------------- tomcat lifecycle

start_tomcat() {
  # $1 = CATALINA_BASE, $2 = http port, $3 = shutdown port, $4.. = extra env assignments
  # The caller owns wiping $base and installing the war -- this function must not delete a webapps
  # directory that already holds the war under test.
  local base="$1" http="$2" shutdown="$3"
  shift 3
  mkdir -p "$base/conf" "$base/logs" "$base/temp" "$base/webapps" "$base/work"
  cp -r "$TOMCAT_HOME/conf/." "$base/conf/"
  # Single HTTP connector on a free port, a real shutdown port (shutdownPort="-1" makes
  # catalina.sh stop a silent no-op and a leaked server will then fake the next run's results),
  # and an appBase holding exactly the war under test.
  python3 - "$base/conf/server.xml" "$http" "$shutdown" <<'PY'
import re, sys
path, http, shutdown = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding='utf-8').read()
text = re.sub(r'<Server port="\d+"', '<Server port="%s"' % shutdown, text, count=1)
text = re.sub(r'(<Connector[^>]*port=")\d+(")', r'\g<1>%s\g<2>' % http, text, count=1)
# Drop the AJP connector: it binds a fixed 8009 and would make a concurrent run fail spuriously.
text = re.sub(r'\s*<!--\s*<Connector[^>]*AJP[^>]*/>\s*-->', '', text)
text = re.sub(r'<Connector[^>]*protocol="AJP/1\.3"[^>]*/>\s*', '', text)
open(path, 'w', encoding='utf-8').write(text)
PY
  export JAVA_HOME="$JAVA_HOME_DIR"
  export CATALINA_HOME="$ROOT/$TOMCAT_HOME"
  export CATALINA_BASE="$ROOT/$base"
  export CATALINA_PID="$ROOT/$base/tomcat.pid"
  export CATALINA_OPTS="-Djava.awt.headless=true"
  env "$@" sh -c "CATALINA_HOME=\"\$CATALINA_HOME\" CATALINA_BASE=\"\$CATALINA_BASE\" \
      CATALINA_PID=\"\$CATALINA_PID\" exec \"$TOMCAT_HOME/bin/catalina.sh\" start" \
      > "$base/logs/startup.log" 2>&1 &
  local deadline=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$deadline" ]; do
    # -o /dev/null, never -o /dev: /dev is a directory, so curl reports a write error (exit 23)
    # against a server that is answering every probe correctly.
    if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$http/" ; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR Tomcat did not answer on port $http within 60 s" >&2
  tail -30 "$base/logs/catalina.out" 2>/dev/null >&2 || true
  return 1
}

stop_tomcat() {
  local base="$1"
  export CATALINA_HOME="$ROOT/$TOMCAT_HOME"
  export CATALINA_BASE="$ROOT/$base"
  export CATALINA_PID="$ROOT/$base/tomcat.pid"
  sh -c "\"$TOMCAT_HOME/bin/catalina.sh\" stop 30" >/dev/null 2>&1 || true
  # Confirm it actually released the port before the next run claims it. Only LISTEN rows (state
  # 0A) count: client connections this server served linger in TIME_WAIT on the same local port
  # for minutes, and treating those as "still held" makes every clean run look broken.
  local port="$2" deadline=$((SECONDS + 30)) hex
  hex=$(printf '%04X' "$port")
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! awk '$4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null \
         | grep -qiE ":${hex}$"; then
      return 0
    fi
    sleep 1
  done
  echo "WARN  port $port still held after shutdown; later runs may be affected" >&2
  return 1
}

MODE_SLOT=0

run_mode() {
  # $1 = mode label, $2 = war name, $3 = services with|without, $4.. = env assignments
  local mode="$1" war="$2" services="$3"
  shift 3
  local http shutdown base slot pbase sbase
  # Disjoint port ranges per mode: if one mode's server lingers (crash, slow stop), a later mode
  # must never be able to allocate the same port and drive assertions against the wrong server.
  slot=$((MODE_SLOT++))
  pbase=$((8391 + slot * 30))
  sbase=$((8701 + slot * 30))
  http=$(free_port "$pbase" $((pbase + 29))) || { echo "ERROR no free HTTP port" >&2; RC=1; return 1; }
  shutdown=$(free_port "$sbase" $((sbase + 29))) || { echo "ERROR no free shutdown port" >&2; RC=1; return 1; }
  base="build/catalina-$mode"
  build_war "build/$war" "$services" || { echo "ERROR war assembly failed" >&2; RC=1; return 1; }
  # Assert what is actually in the archive instead of trusting the copy above: a deployed class is
  # attack surface, and the harness in particular drives the component's internals. `jar --list`
  # because there is no unzip on this machine. Refusing before the container starts keeps a bad
  # archive from being diagnosed as a servlet bug.
  local listed harness_count client_count probe_count stub_count
  listed=$("$JAR" --list --file "build/$war") || { echo "ERROR war unreadable" >&2; RC=1; return 1; }
  harness_count=$(printf '%s\n' "$listed" | grep -c 'Harness.*\.class$')
  client_count=$(printf '%s\n' "$listed" | grep -c 'E2EClient.*\.class$')
  probe_count=$(printf '%s\n' "$listed" | grep -c 'ProbeVerifier.*\.class$')
  stub_count=$(printf '%s\n' "$listed" | grep -c 'testapp/Stub.*\.class$')
  echo "NOTE  mode=$mode war contents: harness=$harness_count e2eclient=$client_count" \
    "probe=$probe_count stubs=$stub_count"
  if [ "$harness_count" != 0 ] || [ "$client_count" != 0 ] || [ "$probe_count" != 0 ] \
     || [ "$stub_count" -lt 4 ]; then
    echo "ERROR $war carries the wrong set of classes" >&2
    RC=1
    return 1
  fi
  echo "NOTE  mode=$mode http=127.0.0.1:$http shutdown=$shutdown"
  # Install the war before the container starts. Tomcat's Host starts before its connector, so a war
  # that is already in appBase is deployed by the time the port answers; a war copied in afterwards
  # waits for the 10 s background deployer and every early request 404s.
  rm -rf "$base"
  mkdir -p "$base/webapps"
  cp "build/$war" "$base/webapps/handoff.war" || { echo "ERROR war install failed" >&2; RC=1; return 1; }
  if ! start_tomcat "$base" "$http" "$shutdown" "$@"; then
    RC=1
    return 1
  fi
  # Confirm the application, not just the connector: the host answers 404 for an undeployed context
  # and the servlet answers 403 (no assertion) once it is live. curl exits 0 on a 404, so the status
  # code has to be read, not the exit status.
  local deadline=$((SECONDS + 60)) code=000
  while [ "$SECONDS" -lt "$deadline" ]; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
        "http://127.0.0.1:$http/handoff/session/handoff" || echo 000)
    if [ "$code" != "000" ] && [ "$code" != "404" ]; then
      break
    fi
    sleep 1
  done
  if [ "$code" = "000" ] || [ "$code" = "404" ]; then
    echo "ERROR mode=$mode context never came up (last HTTP $code); see $base/logs/catalina.out" >&2
    grep -iE 'SEVERE|SAXParse|Deploy' "$base/logs/catalina.out" 2>/dev/null | tail -10 >&2 || true
    cp "$base/logs/catalina.out" "$LOG_DIR/catalina-$mode.log" 2>/dev/null || true
    stop_tomcat "$base" "$http" || true
    RC=1
    return 1
  fi
  echo "NOTE  mode=$mode context live (HTTP $code)"
  # The same assignments go to the container and to the assertion client: the client reads the E2E_*
  # copies so its expectations are stated in one place next to the container's configuration.
  env "$@" E2E_BASE="http://127.0.0.1:$http/handoff" E2E_MODE="$mode" \
    "$JAVA" -cp "build/classes:build/test-classes" com.acme.portal.testapp.E2EClient \
      > "$LOG_DIR/e2e-$mode.log" 2>&1
  local rc=$?
  grep -E '^(NOTE|  PASS|  FAIL|SUMMARY|FAILED|ERROR)' "$LOG_DIR/e2e-$mode.log" \
    | tr -d '\000-\010\013\014\016-\037\177' || true
  if [ "$rc" -ne 0 ]; then
    echo "FAIL  end-to-end mode=$mode exited $rc (log: $LOG_DIR/e2e-$mode.log)" >&2
    RC=1
  fi
  # Keep the container log for inspection, then shut it down cleanly.
  cp "$base/logs/catalina.out" "$LOG_DIR/catalina-$mode.log" 2>/dev/null || true
  stop_tomcat "$base" "$http" || true
  return 0
}

echo "NOTE  running end-to-end assertions against a deployed container"
run_mode default handoff.war with || true
# A 3 s window so the "allowance comes back" assertion is observable without a long sleep.
run_mode limited handoff-limited.war with PORTAL_HANDOFF_WINDOW_SECONDS=3 \
    PORTAL_HANDOFF_MAX_PER_WINDOW=3 E2E_WINDOW_SECONDS=3 E2E_PER_SOURCE=3 || true
run_mode noverifier handoff-nofv.war without || true

echo
if [ "$RC" -eq 0 ]; then
  echo "RESULT all suites green"
else
  echo "RESULT failures recorded (see build/logs)" >&2
fi
exit "$RC"
