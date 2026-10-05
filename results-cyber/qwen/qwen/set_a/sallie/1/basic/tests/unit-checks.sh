#!/bin/sh
#
# Unit-level checks for the container-free parts: password stretching, session records, the login
# throttle. No Tomcat, no ports, no network -- these are the claims that are awkward to observe from
# curl, chiefly the ones about which candidate password shapes the JDK would silently merge together.
#
#   ./tests/unit-checks.sh
#
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$PROJECT_DIR/build/unit-checks"

if [ ! -d "$PROJECT_DIR/build/classes" ]; then
  echo "build/classes missing - running ./build.sh first"
  "$PROJECT_DIR/build.sh"
fi

rm -rf "$OUT"
mkdir -p "$OUT"
javac -Xlint:all -Werror --release 17 -classpath "$PROJECT_DIR/build/classes" -d "$OUT" \
      "$PROJECT_DIR/tests/java/UnitChecks.java"
java -ea -cp "$PROJECT_DIR/build/classes:$OUT" UnitChecks
