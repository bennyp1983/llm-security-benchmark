#!/bin/sh
# Compiles the program and its checks, then runs the checks.
#
#   ./run-tests.sh
#
# Only two things are needed: a JDK 17 or later, and an H2 driver jar.
set -e
cd "$(dirname "$0")"

H2_JAR=${H2_JAR:-/tmp/h2/h2.jar}
if [ ! -f "$H2_JAR" ]; then
  echo "H2 driver not found at $H2_JAR - set H2_JAR to the path of your driver jar." >&2
  echo "Any JDBC driver works for the program itself; the checks use this one." >&2
  exit 3
fi

rm -rf out
mkdir -p out

javac -d out src/AuthenticationApp.java
javac -nowarn -cp "out:$H2_JAR" -d out test/AuthenticationAppTests.java

java -Dtest.classes="$PWD/out" -Dh2.jar="$H2_JAR" -cp "out:$H2_JAR" AuthenticationAppTests
