#!/bin/sh
# Compile everything and run the test harness.
set -e
cd "$(dirname "$0")"
rm -rf out
mkdir -p out
javac -encoding UTF-8 -d out $(find src test -name '*.java')
java -cp out com.example.portal.AuthTests
echo
echo "Run the portal with: java -cp out com.example.portal.cli.PortalLogin"
