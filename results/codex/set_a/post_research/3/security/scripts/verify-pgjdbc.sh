#!/bin/sh
set -eu

version=42.7.13
expected_sha512=9c1c4abd2febc8bfb0cedc02b8ec073f0b5ab1fce25956024e2bf81353b0a67e424fbc4cbf8e804e8d92a11f2c6440538ec962de52938516aa5251efff9ab187
jar_path="${MAVEN_REPOSITORY:-${HOME}/.m2/repository}/org/postgresql/postgresql/${version}/postgresql-${version}.jar"

if [ ! -f "$jar_path" ]; then
    echo "pgJDBC ${version} is not present in the Maven repository." >&2
    exit 1
fi

actual_sha512=$(sha512sum "$jar_path" | awk '{print $1}')
if [ "$actual_sha512" != "$expected_sha512" ]; then
    echo "pgJDBC checksum verification failed." >&2
    exit 1
fi
echo "pgJDBC ${version} checksum verified."
