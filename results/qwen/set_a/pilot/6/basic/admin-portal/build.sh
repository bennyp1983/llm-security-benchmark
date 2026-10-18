#!/bin/sh
# Build and verification entry point. There is no Maven or Gradle on this machine, and no
# dependency is needed: the portal uses only the JDK.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

mkdir -p out test-out

# This host has no LANG/LC_ALL set, so javac's default charset is US-ASCII. Every source is
# ASCII-only, which keeps compilation independent of the ambient locale.
echo "compiling main sources"
javac -encoding US-ASCII -Xlint:all -d out $(find src/main/java -name '*.java')

if [ "${1:-}" = "test" ] || [ "${1:-}" = "all" ]; then
    echo "compiling verification suite"
    javac -encoding US-ASCII -Xlint:all -cp out -d test-out $(find src/test/java -name '*.java')
    echo "running verification suite"
    java -ea -cp out:test-out portal.VerificationSuite
fi

if [ "${1:-}" = "mutate" ]; then
    echo "running the mutation battery (each mutation gets its own copy of the tree)"
    python3 mutation-battery.py
fi

if [ "${1:-}" = "" ] || [ "${1:-}" = "all" ] || [ "${1:-}" = "jar" ]; then
    jar --create --file admin-portal.jar --main-class portal.cli.Main -C out .
    echo "built admin-portal.jar"
fi

echo "usage: java -cp out portal.cli.Main [--help]"
