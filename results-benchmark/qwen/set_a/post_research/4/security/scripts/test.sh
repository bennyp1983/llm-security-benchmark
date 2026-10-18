#!/usr/bin/env bash
# Compiles main and test sources and runs every *Test class. Scratch directories
# are per-process and removed by a shutdown hook inside the harness.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME="${JAVA_HOME:-/opt/jdk17}"
JAVA="$JAVA_HOME/bin/java"
JAVAC="$JAVA_HOME/bin/javac"

MAIN_CP="$ROOT/libs/h2-2.5.252.jar:$ROOT/libs/spring-security-crypto-6.5.11.jar:$ROOT/libs/bcprov-jdk18on-1.82.jar"
TEST_CP="$MAIN_CP:$ROOT/libs/test/commons-logging-1.3.5.jar"

"$ROOT/scripts/get-deps.sh" >/dev/null

rm -rf "$ROOT/bin" "$ROOT/build/test-classes"
mkdir -p "$ROOT/bin" "$ROOT/build/test-classes"

"$JAVAC" -encoding UTF-8 -Xlint:all -Werror -d "$ROOT/bin" -cp "$MAIN_CP" \
  $(find "$ROOT/src/main/java" -name '*.java')

"$JAVAC" -encoding UTF-8 -Xlint:all -d "$ROOT/build/test-classes" -cp "$ROOT/bin:$TEST_CP" \
  $(find "$ROOT/src/test/java" -name '*.java')

echo "compiled"

if [ "${1:-}" = "--compile-only" ]; then
  exit 0
fi

status=0
for class_file in $(find "$ROOT/src/test/java" -name '*Test.java' | sort); do
  class="$(basename "$class_file" .java)"
  echo "== $class"
  if ! "$JAVA" -cp "$ROOT/build/test-classes:$ROOT/bin:$TEST_CP" "app.$class"; then
    status=1
  fi
done
echo "OVERALL: $([ "$status" = 0 ] && echo PASS || echo FAIL)"
exit "$status"
