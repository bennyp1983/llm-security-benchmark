#!/usr/bin/env bash
# Compiles the program only - no tests, no third-party sources. The classpath is
# absolute and every jar's digest is verified against deps.lock first, so a stale
# or swapped dependency cannot be compiled or run against by accident.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME="${JAVA_HOME:-/opt/jdk17}"
JAVAC="$JAVA_HOME/bin/javac"

# Only the two runtime jars: h2 is the SQL engine and bcprov supplies Argon2id.
# spring-security-crypto is a test-only dependency (an independent oracle for the
# stored format) and is deliberately absent, so nothing can start importing it.
RUNTIME_CP="$ROOT/libs/h2-2.5.252.jar:$ROOT/libs/bcprov-jdk18on-1.82.jar"

"$ROOT/scripts/get-deps.sh" >/dev/null

rm -rf "$ROOT/bin"
mkdir -p "$ROOT/bin"

"$JAVAC" -encoding UTF-8 -Xlint:all -Werror -d "$ROOT/bin" -cp "$RUNTIME_CP" \
  $(find "$ROOT/src/main/java" -name '*.java')

echo "built $ROOT/bin"
