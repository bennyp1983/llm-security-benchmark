#!/usr/bin/env bash
# Compile with the platform compiler. No third-party dependencies exist at runtime, so
# there is nothing to download, resolve or verify here -- see tools/get-jdk.sh for the one
# network fetch in the whole build (the JDK itself, verified against Adoptium's digest).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Resolution order: $JAVAC, $JAVA_HOME/bin/javac, then whatever is on PATH.
if [ -n "${JAVAC:-}" ]; then :
elif [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then JAVAC="$JAVA_HOME/bin/javac"
else JAVAC="javac"
fi
OUT="$ROOT/out/main"

if ! command -v "$JAVAC" >/dev/null 2>&1 && [ ! -x "$JAVAC" ]; then
  echo "javac not found. Run tools/get-jdk.sh and set JAVAC, or install JDK 21+." >&2
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"

# -encoding US-ASCII is a compile-time guarantee, not cosmetics: the sources declare an
# ASCII-only charset contract, and a stray non-ASCII byte in a source file is exactly the
# kind of invisible character this program refuses to accept from a user.
"$JAVAC" -encoding US-ASCII -Xlint:all -Werror -parameters -d "$OUT" \
  $(find "$ROOT/src/main/java" -name '*.java')

echo "built -> $OUT"
