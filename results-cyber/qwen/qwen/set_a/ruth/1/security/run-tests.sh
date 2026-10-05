#!/usr/bin/env bash
# Runs the assertion harness in src/test/java and exits non-zero on any failure.
#
#   ./run-tests.sh              compile + run
#   ./run-tests.sh --verbose    print every check, not just the summary
#
# The harness drives the servlets through Proxy doubles of the Servlet API, so it needs the same
# compile-time jar as build.sh and no container.
set -euo pipefail

cd "$(dirname "$0")"
OUT=build
VERBOSE="${1:-}"

find_servlet_api() {
  local candidates=()
  [ -n "${SERVLET_API_JAR:-}" ] && candidates+=("$SERVLET_API_JAR")
  candidates+=("lib/jakarta.servlet-api-6.0.0.jar")
  local found
  found=$(find / -maxdepth 6 \( -name 'jakarta.servlet-api-*.jar' -o -name 'servlet-api.jar' \) \
      -not -path '*/\.git/*' 2>/dev/null | sort)
  while IFS= read -r jar; do [ -n "$jar" ] && candidates+=("$jar"); done <<<"$found"
  local jar
  for jar in "${candidates[@]}"; do
    if [ -f "$jar" ] && jar --list --file "$jar" 2>/dev/null | grep -q 'jakarta/servlet/http/Cookie.class'; then
      printf '%s\n' "$jar"
      return 0
    fi
  done
  return 1
}

SERVLET_API=$(find_servlet_api) || {
  echo "No Jakarta Servlet 6.0 API jar found; see build.sh for how to supply one." >&2
  exit 1
}

mkdir -p "$OUT/classes" "$OUT/test-classes"
javac -Xlint:all -Werror -encoding UTF-8 \
  -cp "$SERVLET_API" -d "$OUT/classes" $(find src/main/java -name '*.java')
javac -Xlint:all -Werror -encoding UTF-8 \
  -cp "$SERVLET_API:$OUT/classes" -d "$OUT/test-classes" $(find src/test/java -name '*.java')

if [ "$VERBOSE" = "--verbose" ]; then
  java -cp "$SERVLET_API:$OUT/classes:$OUT/test-classes" com.example.auth.TestHarness
else
  java -cp "$SERVLET_API:$OUT/classes:$OUT/test-classes" com.example.auth.TestHarness \
    | grep -E '^==|^  FAIL|^OK|^FAILED'
fi
