#!/bin/sh
#
# Shared Tomcat plumbing for run-demo.sh and tests/end-to-end.sh.
#
# Builds a throwaway CATALINA_BASE under build/tomcat, pointed at the freshly packaged war, so the
# demo never touches the Tomcat installation it runs from. Everything is driven from the environment:
#
#   TOMCAT_HOME   Tomcat install to run from   (default: newest /tmp/apache-tomcat-* on disk)
#   HTTP_PORT     where to listen              (default: 8181)
#   SHUTDOWN_PORT where `stop` is accepted     (default: 8109)
#
# Nothing here hardcodes a machine: the Tomcat install is discovered, and the Servlet API jar used
# for compiling is discovered by build.sh.
#
# shellcheck shell=sh

# Callers set PROJECT_DIR before sourcing (its own location is not reliably reachable from /bin/sh
# once a file has been sourced rather than executed); the fallback covers a direct `. ./tools/...`.
PROJECT_DIR="${PROJECT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
BUILD_DIR="$PROJECT_DIR/build"
CATALINA_BASE="$BUILD_DIR/tomcat"
WAR="$BUILD_DIR/session-cookie-auth-demo.war"
APP_CONTEXT="app"
HTTP_PORT="${HTTP_PORT:-8181}"
HTTPS_PORT="${HTTPS_PORT:-8643}"
SHUTDOWN_PORT="${SHUTDOWN_PORT:-8109}"
BASE_URL="http://127.0.0.1:$HTTP_PORT/$APP_CONTEXT"
SECURE_URL="https://127.0.0.1:$HTTPS_PORT/$APP_CONTEXT"

find_tomcat_home() {
  if [ -n "${TOMCAT_HOME:-}" ]; then
    echo "$TOMCAT_HOME"
    return
  fi
  for candidate in /tmp/apache-tomcat-* /opt/tomcat /usr/local/tomcat; do
    if [ -x "$candidate/bin/catalina.sh" ] \
        && jar --list --file "$candidate/lib/servlet-api.jar" 2>/dev/null \
             | grep -q '^jakarta/servlet/http/Cookie.class$'; then
      echo "$candidate"
      return
    fi
  done
  echo ""
}

# A JVM on this box resolves user.home from the passwd entry, not from $HOME, so nothing in this
# demo is isolated by overriding HOME. Everything it can write goes under CATALINA_BASE instead.
scaffold_catalina_base() {
  rm -rf "$CATALINA_BASE"
  mkdir -p "$CATALINA_BASE/conf/Catalina/localhost" "$CATALINA_BASE/logs" \
           "$CATALINA_BASE/webapps" "$CATALINA_BASE/work" "$CATALINA_BASE/temp"
  cp "$TOMCAT_HOME/conf/web.xml" "$CATALINA_BASE/conf/web.xml"
  cp "$TOMCAT_HOME/conf/logging.properties" "$CATALINA_BASE/conf/logging.properties"
  # A throwaway self-signed certificate, generated fresh each time, so the HTTPS path can be driven
  # and checked rather than argued about: the cookie's Secure attribute is only observable over TLS.
  # Without this connector the application would always answer "not secure" and the Secure flag would
  # silently never appear.
  local keystore="$CATALINA_BASE/demo.jks"
  keytool -genkeypair -alias demo -keyalg RSA -keysize 2048 \
          -dname "CN=localhost, O=throwaway demo, C=US" \
          -validity 2 -storepass changeit -keypass changeit \
          -keystore "$keystore" -storetype PKCS12 >/dev/null 2>&1
  if [ ! -f "$keystore" ]; then
    echo "warning: could not generate a throwaway keystore; the HTTPS checks will not run" >&2
  fi

  # A real shutdown port, not -1: with -1, `catalina.sh stop` is a silent no-op and the leaked server
  # then holds HTTP_PORT for the next run and reports its answers as this one's.
  cat > "$CATALINA_BASE/conf/server.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<Server port="$SHUTDOWN_PORT" shutdown="SHUTDOWN">
  <Listener className="org.apache.catalina.startup.VersionLoggerListener"/>
  <Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>
  <Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener"/>
  <GlobalNamingResources/>
  <Service name="demo">
    <Executor name="demo" maxThreads="32" minSpareThreads="4"/>
    <Connector port="$HTTP_PORT" protocol="HTTP/1.1" executor="demo"
               connectionTimeout="20000" redirectPort="$HTTPS_PORT"/>
    <Connector port="$HTTPS_PORT" protocol="org.apache.coyote.http11.Http11NioProtocol"
               executor="demo" SSLEnabled="true" scheme="https" secure="true">
      <SSLHostConfig>
        <Certificate certificateKeystoreFile="$keystore" certificateKeystorePassword="changeit"
                     type="RSA"/>
      </SSLHostConfig>
    </Connector>
    <Engine name="demo" defaultHost="localhost">
      <Host name="localhost" appBase="$CATALINA_BASE/webapps" unpackWARs="true" autoDeploy="true">
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="access" suffix=".log" pattern="%h %l %u %t &quot;%r&quot; %s %b"/>
      </Host>
    </Engine>
  </Service>
</Server>
XML
  # The war is deployed as /app by being named app.war: the context path is then non-empty, which is
  # what exercises the contextPath handling in the redirects and cookie Path attribute.
  cp "$WAR" "$CATALINA_BASE/webapps/$APP_CONTEXT.war"
}

port_in_use() {
  # Only rows in LISTEN state (st == 0A) and only their LOCAL address count. Matching the whole line
  # instead also matches the remote-address column of yesterday's closed connections to the same
  # port, which reports every port as busy for minutes after a run.
  local hex
  hex=$(printf '%04X' "$1")
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -q ":$1 "
    return
  fi
  awk -v want="$hex" 'NR > 1 && $4 == "0A" { split($2, parts, ":"); if (parts[2] == want) found = 1 }
                      END { exit !found }' /proc/net/tcp 2>/dev/null
}

start_tomcat() {
  TOMCAT_HOME=$(find_tomcat_home)
  if [ -z "$TOMCAT_HOME" ]; then
    echo "error: no Tomcat 10+ with the jakarta.* Servlet API found." >&2
    echo "       set TOMCAT_HOME=/path/to/tomcat (Tomcat 10.1 or newer) and re-run." >&2
    return 1
  fi
  [ -f "$WAR" ] || { echo "error: $WAR missing - run ./build.sh first" >&2; return 1; }

  for port in "$HTTP_PORT" "$HTTPS_PORT" "$SHUTDOWN_PORT"; do
    if port_in_use "$port"; then
      echo "error: port $port is already in use." >&2
      echo "       another demo is running, or a previous one did not shut down. Pass" >&2
      echo "       HTTP_PORT/SHUTDOWN_PORT to pick different ports, or stop the other server." >&2
      return 1
    fi
  done

  scaffold_catalina_base

  if [ -z "${JAVA_HOME:-}" ]; then
    java_binary=$(command -v java)
    [ -n "$java_binary" ] || { echo "error: no java on PATH and JAVA_HOME unset" >&2; return 1; }
    JAVA_HOME=$(CDPATH= cd -- "$(dirname -- "$(readlink -f "$java_binary")")/.." && pwd)
  fi
  export JAVA_HOME CATALINA_HOME="$TOMCAT_HOME" CATALINA_BASE CATALINA_OUT="$CATALINA_BASE/logs/catalina.out"
  export CATALINA_PID="$CATALINA_BASE/tomcat.pid"
  export JAVA_OPTS="-Djava.awt.headless=true -Xmx256m"

  "$TOMCAT_HOME/bin/catalina.sh" start >/dev/null 2>&1 || {
    echo "error: catalina.sh start failed - see $CATALINA_OUT" >&2; return 1; }
  wait_for_app || return 1
}

wait_for_app() {
  attempt=0
  while [ "$attempt" -lt 120 ]; do
    # Any HTTP answer from /status means the web application is mapped and its context initialised.
    if curl -fsS -o /dev/null "$BASE_URL/status" 2>/dev/null; then
      return 0
    fi
    if [ -f "$CATALINA_PID" ] && ! kill -0 "$(cat "$CATALINA_PID")" 2>/dev/null; then
      echo "error: Tomcat exited during startup. Last log lines:" >&2
      tail -n 25 "$CATALINA_OUT" >&2 2>/dev/null
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "error: $BASE_URL/status never answered. Last log lines:" >&2
  tail -n 25 "$CATALINA_OUT" >&2 2>/dev/null
  return 1
}

stop_tomcat() {
  [ -n "${CATALINA_HOME:-}" ] || return 0
  "$CATALINA_HOME/bin/catalina.sh" stop 2>/dev/null >/dev/null || true
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    port_in_use "$SHUTDOWN_PORT" || break
    attempt=$((attempt + 1))
    sleep 1
  done
  if port_in_use "$SHUTDOWN_PORT" && [ -f "$CATALINA_BASE/tomcat.pid" ]; then
    # Only this demo's own pid, never a pattern match that could hit an unrelated JVM.
    kill "$(cat "$CATALINA_BASE/tomcat.pid")" 2>/dev/null || true
  fi
  return 0
}
