#!/usr/bin/env bash
# Runs the account CLI. The classpath is absolute and the jar digests are
# checked against deps.lock before anything starts, so a stale or swapped jar
# cannot be used by accident.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME="${JAVA_HOME:-/opt/jdk17}"
# Runtime classpath only: spring-security-crypto is a test-only oracle and is kept
# off the runtime path so nothing can accidentally start depending on it.
CP="$ROOT/bin:$ROOT/libs/h2-2.5.252.jar:$ROOT/libs/bcprov-jdk18on-1.82.jar"

# Build when there is nothing to run, or when a source file is newer than what was compiled.
# The second test matters: shipping classes that no longer match the sources would run a
# different program than the one that was reviewed, and the stale build has actually happened
# here during development. The jars need no such test - get-deps.sh below compares each digest
# against deps.lock, which is stronger than any timestamp.
needs_build() {
  [ -d "$ROOT/bin" ] || return 0
  [ -f "$ROOT/bin/app/Main.class" ] || return 0
  [ -n "$(find "$ROOT/src/main/java" -name '*.java' -newer "$ROOT/bin/app/Main.class" -print -quit)" ]
}

if needs_build; then
  "$ROOT/scripts/build.sh" >&2
fi
"$ROOT/scripts/get-deps.sh" >/dev/null

exec "$JAVA_HOME/bin/java" -cp "$CP" app.Main "$@"
