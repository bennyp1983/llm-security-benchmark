#!/usr/bin/env bash
# Compile all sources into ./out (requires a JDK, e.g. openjdk-17-jdk-headless)
set -euo pipefail
cd "$(dirname "$0")"
rm -rf out
javac -d out $(find src -name '*.java')
echo "Build OK -> $(pwd)/out"
