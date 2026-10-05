#!/usr/bin/env bash
# Compiles the sources and packages build/session-cookie.war.
#
#   ./build.sh              compile + war
#   ./build.sh /path/to/jakarta.servlet-api-6.0.0.jar
#
# The Servlet API is provided by the container at runtime, so it is needed only to compile. Point
# SERVLET_API_JAR at any Jakarta Servlet 6.0 jar (the one that ships with Tomcat 10.1 / Jetty 11+,
# or jakarta.servlet-api-6.0.0.jar from Maven Central).
set -euo pipefail

cd "$(dirname "$0")"
OUT=build
CLASSES="$OUT/classes"
WAR="$OUT/session-cookie.war"

find_servlet_api() {
  local candidates=()
  [ -n "${SERVLET_API_JAR:-}" ] && candidates+=("$SERVLET_API_JAR")
  [ -n "${1:-}" ] && candidates+=("$1")
  candidates+=("lib/jakarta.servlet-api-6.0.0.jar")
  local found
  found=$(find / -maxdepth 6 \( -name 'jakarta.servlet-api-*.jar' -o -name 'servlet-api.jar' \) \
      -not -path '*/\.git/*' 2>/dev/null | sort)
  while IFS= read -r jar; do [ -n "$jar" ] && candidates+=("$jar"); done <<<"$found"

  local jar
  for jar in "${candidates[@]}"; do
    # A javax.* namespace jar compiles nothing useful here; check for the jakarta package.
    if [ -f "$jar" ] && jar --list --file "$jar" 2>/dev/null | grep -q 'jakarta/servlet/http/Cookie.class'; then
      printf '%s\n' "$jar"
      return 0
    fi
  done
  return 1
}

SERVLET_API=$(find_servlet_api "${1:-}") || {
  cat >&2 <<'MSG'
No Jakarta Servlet 6.0 API jar found.

Set it explicitly:
  SERVLET_API_JAR=/path/to/jakarta.servlet-api-6.0.0.jar ./build.sh
or download it into ./lib:
  mkdir -p lib && curl -fLso lib/jakarta.servlet-api-6.0.0.jar \
    https://repo1.maven.org/maven2/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar
MSG
  exit 1
}

echo "servlet API: $SERVLET_API"

rm -rf "$OUT"
mkdir -p "$CLASSES"

# -Werror with -Xlint:all keeps the tree warning-free; encoding is explicit because the platform
# default on a machine without LANG/LC_ALL set is US-ASCII, not UTF-8.
javac -Xlint:all -Werror -encoding UTF-8 \
  -cp "$SERVLET_API" -d "$CLASSES" $(find src/main/java -name '*.java')
echo "compiled $(find "$CLASSES" -name '*.class' | wc -l) classes"

# WEB-INF/classes, not the top level: anything under WEB-INF is unreachable over HTTP, so the
# application cannot be read back or, worse, served as a static resource.
STAGE="$OUT/war"
mkdir -p "$STAGE/WEB-INF/classes"
cp -r "$CLASSES/." "$STAGE/WEB-INF/classes/"
cp -r src/main/webapp/. "$STAGE/"
( cd "$STAGE" && jar --create --file "../session-cookie.war" . )

echo "packaged $WAR ($(du -h "$WAR" | cut -f1))"
