#!/bin/sh
# Compiles the portal and runs the self test.
set -e
cd "$(dirname "$0")"
rm -rf out test-out
javac -d out $(find src -name '*.java')
javac -cp out -d test-out $(find test -name '*.java')
java -cp out:test-out com.example.adminportal.PortalSelfTest
echo
echo "Run the portal with: java -cp out com.example.adminportal.AdminPortal"
