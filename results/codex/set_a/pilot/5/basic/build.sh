#!/usr/bin/env bash
set -euo pipefail

mkdir -p out/main out/test
javac -d out/main $(find src/main/java -name '*.java' -print)
javac -cp out/main -d out/test $(find src/test/java -name '*.java' -print)
