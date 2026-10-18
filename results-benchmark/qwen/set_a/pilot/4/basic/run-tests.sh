#!/bin/bash
# Compile everything with warnings treated as errors, then run the test suite.
# There is no build tool on this machine, so this is the whole build: javac + java.
set -e
cd "$(dirname "$0")"
rm -rf out
mkdir -p out
javac -Xlint:all -Werror -d out $(find src tests -name '*.java')
echo "compiled clean with -Xlint:all -Werror"
java -cp out accounts.TestRunner
