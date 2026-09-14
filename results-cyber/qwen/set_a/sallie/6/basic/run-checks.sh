#!/bin/sh
# Compiles everything under src and runs the checks.
# Exit status is non-zero if anything fails.
set -e
cd "$(dirname "$0")"

rm -rf out
mkdir -p out
javac -Xlint:all -Werror -d out $(find src -name '*.java')

# The checks read one source file to pin a property that has no observable
# behaviour, so they need to run from this directory.
java -cp out -Dportal.source.root="$PWD" portal.PortalChecks
