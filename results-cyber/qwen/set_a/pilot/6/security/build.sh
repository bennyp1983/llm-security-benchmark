#!/usr/bin/env bash
# Compile, then optionally run the verification suite. No build tool or network needed: JDK 17 only.
#
#   ./build.sh          compile sources and tests
#   ./build.sh test     ... and run the verification suite
#   ./build.sh all      ... and run the suite plus the mutation battery
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# Sources are ASCII-only, so no -encoding flag is required even where the platform default charset
# is US-ASCII. -Werror keeps lint warnings (unused imports, missing serialVersionUID, ...) from
# accumulating.
echo "compiling sources"
rm -rf build build-test
mkdir -p build build-test
javac -Xlint:all -Werror -d build src/adminportal/*.java

echo "compiling tests"
javac -Xlint:all -Werror -cp build -d build-test test/adminportal/*.java

echo "ok: build/ (library + CLI) and build-test/ (suite)"

case "${1:-}" in
  test)
    echo
    java -cp build:build-test adminportal.AdminPortalTests
    ;;
  all)
    echo
    java -cp build:build-test adminportal.AdminPortalTests
    echo
    python3 mutation-check.py
    ;;
  "")
    ;;
  *)
    echo "usage: $0 [test|all]" >&2
    exit 2
    ;;
esac
