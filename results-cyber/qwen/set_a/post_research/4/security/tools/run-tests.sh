#!/bin/sh
# Run the security test suite.
#
# Why a script rather than "just run java": the suite needs a passphrase in the environment
# (Config refuses to start without one, by design), the pinned driver on the classpath, an explicit
# source root for the structural guards, and UTF-8 output. Getting any of those wrong produces a
# failure that looks like a code bug, so the invocation is spelled once here.
#
#   sh tools/run-tests.sh              # whole suite
#   sh tools/run-tests.sh password     # one suite by short name
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/bin"
TEST_OUT="$ROOT/build/test-classes"
LIB="$ROOT/lib/h2-2.5.252.jar"

[ -d "$TEST_OUT" ] || sh "$ROOT/tools/build.sh" tests

# No passphrase is exported here, on purpose.
#
# Every fixture supplies its own (Harness.PASSPHRASE) and every CLI child is launched with an
# explicit pb.environment().put(...), so nothing in the suite ever reads IDENTITY_DB_PASSWORD from
# the parent environment. Exporting one here would put a live-shaped database passphrase in a
# world-readable file and in this JVM's /proc/<pid>/environ, `ps e` output and any crash dump, for
# no benefit at all - which is exactly the exposure Config's own javadoc warns about. If you want
# the suite to run with your own value in the environment, export it yourself before calling this.

exec java -Xmx512m \
  -Dfile.encoding=UTF-8 \
  -Dportal.repo="$ROOT" \
  -Dportal.src="$ROOT/src/main/java/com/example/identity" \
  -cp "$LIB:$OUT:$TEST_OUT" \
  com.example.identity.MainSuite "${1:-}"
