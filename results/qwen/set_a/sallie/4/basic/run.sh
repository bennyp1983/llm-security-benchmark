#!/bin/bash
# Build the program if needed, then run it with whatever arguments were given.
#   ./run.sh register alice
#   ./run.sh --store /tmp/mine.txt login alice
#
# Building happens relative to this script's folder, but the program itself runs in
# the directory you called from, so its default store file lands where you expect.
set -u
PROJ_DIR=$(cd "$(dirname "$0")" && pwd)

if command -v java >/dev/null 2>&1; then
  JAVA_BIN="java"
elif [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
else
  echo "Error: no java on PATH and JAVA_HOME is not set." >&2
  exit 2
fi

needs_build=0
if [ ! -d "$PROJ_DIR/out" ]; then
  needs_build=1
else
  newest_source=$(find "$PROJ_DIR/src/account" -name '*.java' -newer "$PROJ_DIR/out/account/Main.class" 2>/dev/null | head -1)
  if [ -n "$newest_source" ]; then
    needs_build=1
  fi
fi

if [ "$needs_build" -eq 1 ]; then
  mkdir -p "$PROJ_DIR/out"
  if ! (cd "$PROJ_DIR" && javac -d out $(find src/account -name '*.java')); then
    echo "Error: compilation failed." >&2
    exit 2
  fi
fi

exec "$JAVA_BIN" -cp "$PROJ_DIR/out" account.Main "$@"
