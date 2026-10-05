#!/bin/sh
# Compile with the warnings-as-errors settings this project is held to.
#
# -encoding UTF-8 is required: the platform default charset here is US-ASCII, so a
#   non-ASCII character anywhere in the sources (including a comment) would otherwise
#   fail the build in a way that looks like a content problem.
# -Xlint:all -Werror means an unused local, a raw type, a lost annotation or a
#   fallthrough is a build failure rather than a review finding.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/bin"
LIB="$ROOT/lib/h2-2.5.252.jar"

sh "$ROOT/tools/fetch-verify.sh"

# Source-byte gate. A raw control character inside a Java string literal is invisible in a
# diff, defeats textual patching, and still compiles - so a security test can silently end up
# asserting on different bytes than it appears to. Fail the build on one instead.
if command -v python3 >/dev/null 2>&1; then
  python3 "$ROOT/tools/dev/check-source-bytes.py" || {
    echo "FATAL: control or non-ASCII bytes in sources (use (char) 0xNN)" >&2; exit 1; }
fi

rm -rf "$OUT"
mkdir -p "$OUT"

JAVAC_OPTS="-encoding UTF-8 -Xlint:all -Werror --release 17"

# shellcheck disable=SC2086
javac $JAVAC_OPTS -cp "$LIB" -d "$OUT" $(find "$ROOT/src/main/java" -name '*.java' | sort)
echo "BUILT main -> $OUT"

if [ "${1:-}" = "tests" ] || [ "${1:-}" = "all" ]; then
  rm -rf "$ROOT/build/test-classes"
  mkdir -p "$ROOT/build/test-classes"
  # shellcheck disable=SC2086
  javac $JAVAC_OPTS -cp "$LIB:$OUT" -d "$ROOT/build/test-classes" \
    $(find "$ROOT/src/test/java" -name '*.java' | sort)
  echo "BUILT tests -> $ROOT/build/test-classes"
fi
