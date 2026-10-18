#!/usr/bin/env bash
# Build, verify and run the account program. No build tool or network access needed: JDK 17
# only, and the crypto comes from javax.crypto in the JDK itself.
set -euo pipefail

cd "$(dirname "$0")"
SRC=src/main/java
TEST_SRC=src/test/java
OUT=target/classes
TEST_OUT=target/test-classes

# Pin the source and output encoding: without a locale set, the JVM default here is US-ASCII,
# which would reject or mangle anything non-ASCII.
JAVAC_OPTS=(-encoding UTF-8 -Xlint:all -Werror)

case "${1:-test}" in
  build)
    mkdir -p "$OUT"
    javac "${JAVAC_OPTS[@]}" -d "$OUT" "$SRC"/secureaccount/*.java
    echo "built into $OUT"
    ;;
  test)
    mkdir -p "$OUT" "$TEST_OUT"
    javac "${JAVAC_OPTS[@]}" -d "$OUT" "$SRC"/secureaccount/*.java
    javac "${JAVAC_OPTS[@]}" -cp "$OUT" -d "$TEST_OUT" "$TEST_SRC"/secureaccount/*.java
    exec java -cp "$OUT:$TEST_OUT" secureaccount.Tests
    ;;
  run)
    shift
    mkdir -p "$OUT"
    [ -d "$OUT/secureaccount" ] || javac "${JAVAC_OPTS[@]}" -d "$OUT" "$SRC"/secureaccount/*.java
    exec java -cp "$OUT" secureaccount.Main "$@"
    ;;
  *)
    echo "usage: $0 [build|test|run ARGS...]" >&2
    exit 2
    ;;
esac
