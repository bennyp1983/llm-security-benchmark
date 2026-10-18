#!/usr/bin/env bash
# Start the portal or run one administrative subcommand.
#
# The classpath is built from this script's own directory and nothing else:
#
#   * no "." and no wildcard, so the JVM cannot be tricked into loading a class that some
#     other account dropped into the current working directory -- rule 8's "never load code
#     from a shared or world-writable location", applied to the launcher;
#   * CLASSPATH is removed from the environment rather than trusted, because an inherited
#     CLASSPATH would point at a directory this script never checked;
#   * the interpreter is resolved from JAVA_HOME or PATH and then exec'd, so a stray shell
#     word in $@ cannot become part of the command line.
#
# Subcommands: login, add-user, set-password, disable-user, status, version, portal.
# Configuration comes from the environment and the config file only -- see
# config/portal.properties.example. Never pass a password here: argv is world-readable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="$ROOT/out/main"

if [ ! -f "$MAIN/com/portal/auth/Main.class" ]; then
  echo "$MAIN is not built. Run ./build.sh first." >&2
  exit 1
fi

if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA="$JAVA_HOME/bin/java"
elif command -v java >/dev/null 2>&1; then
  JAVA="java"
else
  echo "java not found. Set JAVA_HOME or run tools/get-jdk.sh." >&2
  exit 1
fi

exec env -u CLASSPATH "$JAVA" \
  -cp "$MAIN" \
  -Djava.awt.headless=true \
  -Dfile.encoding=UTF-8 \
  com.portal.auth.Main "$@"
