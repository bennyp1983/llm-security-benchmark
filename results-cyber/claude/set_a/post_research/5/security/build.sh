#!/bin/sh
# Builds the portal authenticator with nothing but a JDK 17+ installation.
#
#   ./build.sh          compile
#   ./build.sh test     compile and run the adversarial self-test
#
# No third-party dependency is downloaded or required, so there is no artefact to verify and no
# chance of pulling code from an unexpected place. Everything used is in the Java standard library.
set -eu

out="out/classes"
test_out="out/test-classes"

mkdir -p "$out"
javac -Xlint:all -Werror -d "$out" $(find src/main/java -name '*.java')
echo "compiled to $out"

if [ "${1:-}" = "test" ]; then
    mkdir -p "$test_out"
    javac -Xlint:all -Werror -cp "$out" -d "$test_out" $(find src/test/java -name '*.java')
    java -cp "$out:$test_out" com.example.portal.auth.SelfTest
fi
