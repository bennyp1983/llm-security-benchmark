#!/usr/bin/env bash
# Compile and run the adversarial test suites. The suites use the same hand-rolled
# harness as the program's own build (no third-party test framework), so there is still
# nothing to download here.
#
#   ./test.sh              run every suite
#   ./test.sh Core         run suites whose name contains "Core"
#
# Each suite is a main() so it can be run, timed and mutated independently.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "${JAVAC:-}" ]; then :
elif [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then JAVAC="$JAVA_HOME/bin/javac"
else JAVAC="javac"
fi
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then JAVA="$JAVA_HOME/bin/java"
else JAVA="java"
fi

FILTER="${1:-}"

"$ROOT/build.sh"

OUT_MAIN="$ROOT/out/main"
OUT_TEST="$ROOT/out/test"
rm -rf "$OUT_TEST"
mkdir -p "$OUT_TEST"

"$JAVAC" -encoding US-ASCII -Xlint:all -Werror -parameters \
  -cp "$OUT_MAIN" -d "$OUT_TEST" \
  $(find "$ROOT/src/test/java" -name '*.java')

rc=0
for f in $(find "$ROOT/src/test/java" -name '*Suite.java' | sort); do
  suite="$(basename "$f" .java)"
  if [ -n "$FILTER" ] && [[ "$suite" != *"$FILTER"* ]]; then
    continue
  fi
  echo "=== $suite"
  # portal.src.main lets the suites assert on the shape of the production sources
  # (e.g. "no branch trims a credential"), which is the only way to falsify the
  # absence of a code path.
  if ! "$JAVA" -cp "$OUT_TEST:$OUT_MAIN" -Dportal.src.main="$ROOT/src/main/java" \
      -Djava.awt.headless=true "com.portal.auth.$suite"; then
    rc=1
  fi
done
exit "$rc"
