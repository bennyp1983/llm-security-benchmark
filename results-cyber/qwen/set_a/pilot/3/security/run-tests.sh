#!/usr/bin/env bash
# Compiles with strict lints and runs the executable checks. Needs JDK 17+, nothing else.
set -euo pipefail
cd "$(dirname "$0")"

rm -rf build/classes
mkdir -p build/classes

# -encoding US-ASCII is deliberate: the sources are 7-bit ASCII, so this fails loudly if anyone
# adds a non-ASCII byte instead of letting compilation depend on the platform default encoding.
javac -encoding US-ASCII -Xlint:all -Werror -d build/classes $(find src -name '*.java')

java -cp build/classes com.example.users.UserAccountRepositoryTest
