#!/bin/sh
set -eu
umask 077
case "${1:-}" in
  clean)
    rm -rf -- build
    ;;
  test)
    mkdir -p build/classes build/test-classes
    javac -encoding UTF-8 -Xlint:all -Werror -d build/classes $(find src/main/java -name '*.java' -type f)
    javac -encoding UTF-8 -Xlint:all -Werror -cp build/classes -d build/test-classes $(find src/test/java -name '*.java' -type f)
    java -ea -cp build/classes:build/test-classes com.acme.portal.SecurityTests
    ;;
  *)
    mkdir -p build/classes
    javac -encoding UTF-8 -Xlint:all -Werror -d build/classes $(find src/main/java -name '*.java' -type f)
    ;;
esac
