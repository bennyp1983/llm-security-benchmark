#!/usr/bin/env bash
# Build and exercise the employee portal authentication module.
#
#   ./run.sh          compile, run the 130-check verification, run the scripted demo
#   ./run.sh verify   compile and run the verification only (exit code is the verdict)
#   ./run.sh app      compile and start the interactive sign-in prompt
#   ./run.sh mutants  re-run the verification against seven deliberately broken copies of the module
#
# Plain javac/java rather than Maven or Gradle: neither is installed on this machine, and the module
# deliberately depends on nothing outside the JDK.
set -euo pipefail

cd "$(dirname "$0")"
MAIN_SRC=$(find src/main/java -name '*.java')
TEST_SRC=$(find src/test/java -name '*.java')

# -Werror with -Xlint:all so a warning fails the build instead of scrolling past.
compile() {
  rm -rf build
  mkdir -p build/classes build/test-classes
  javac -Xlint:all -Werror -d build/classes $MAIN_SRC
  javac -Xlint:all -Werror -cp build/classes -d build/test-classes $TEST_SRC
  echo "compiled: $(echo "$MAIN_SRC" | wc -l) main, $(echo "$TEST_SRC" | wc -l) test source files"
}

verify() {
  echo "--- verification ---"
  java -cp build/classes:build/test-classes com.portal.auth.AuthVerification
}

demo() {
  echo "--- scripted sign-in: 6 wrong passwords for 'demo', then the correct one ---"
  printf '%s\n' \
    demo wrong-1 demo wrong-2 demo wrong-3 demo wrong-4 demo wrong-5 \
    demo Correct-Horse-9 ghost.user whatever quit \
    | java -cp build/classes com.portal.auth.PortalAuthApp
}

case "${1:-all}" in
  verify) compile; verify ;;
  app)    compile; exec java -cp build/classes com.portal.auth.PortalAuthApp ;;
  mutants) python3 tools/mutation-check.py ;;
  all)    compile; verify; demo ;;
  *)      echo "usage: $0 [all|verify|app|mutants]" >&2; exit 2 ;;
esac
