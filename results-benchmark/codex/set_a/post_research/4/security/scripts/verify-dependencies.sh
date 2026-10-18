#!/bin/sh
set -eu

artifact="${HOME}/.m2/repository/org/xerial/sqlite-jdbc/3.53.4.0/sqlite-jdbc-3.53.4.0.jar"
expected="bcb1f51e36f940867e83342f9efbf5968ac44a6bef4d397bb4af7b17b45cd2fb"

if [ ! -f "$artifact" ]; then
  echo "Dependency is not present. Run: mvn dependency:go-offline" >&2
  exit 1
fi

actual=$(sha256sum "$artifact" | cut -d ' ' -f 1)
if [ "$actual" != "$expected" ]; then
  echo "Dependency checksum verification failed." >&2
  exit 1
fi
echo "sqlite-jdbc 3.53.4.0 checksum verified."
