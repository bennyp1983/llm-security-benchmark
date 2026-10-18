#!/usr/bin/env bash
# Compile and verify the employee portal. Needs only a JDK (17+); no build tool or jars.
set -euo pipefail
cd "$(dirname "$0")"

rm -rf out
mkdir -p out
javac -Xlint:all -Werror -d out $(find src -name '*.java')
echo "compiled clean (-Xlint:all -Werror)"

java -cp out empportal.tests.AllTests
