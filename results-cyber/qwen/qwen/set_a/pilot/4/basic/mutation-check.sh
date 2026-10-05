#!/bin/bash
# Mutation check: inject a known bug into a throwaway copy of the tree and confirm the
# test suite FAILS. A mutation that leaves the suite green means the tests do not
# actually cover the property they claim to assert.
set -u
SRC=/data/results/qwen/set_a/pilot/4/basic
ROOT=$(mktemp -d /tmp/mutation-XXXXXX)
CAUGHT=0; MISSED=0; SKIPPED=0

mutate() {
  local name="$1"; shift
  local dir="$ROOT/$name"
  mkdir -p "$dir" && cp -r "$SRC/src" "$SRC/tests" "$dir/"
  ( cd "$dir" && "$@" ) >/dev/null 2>&1
  mkdir -p "$dir/out"
  if ! javac -nowarn -d "$dir/out" $(find "$dir/src" "$dir/tests" -name '*.java') >"$dir/compile.log" 2>&1; then
    echo "SKIPPED  $name (mutation did not compile)"; sed -n '1,3p' "$dir/compile.log" | sed 's/^/           /'
    SKIPPED=$((SKIPPED+1)); return
  fi
  if java -cp "$dir/out" accounts.TestRunner >"$dir/run.log" 2>&1; then
    echo "MISSED   $name  <-- suite stayed green, real coverage gap"
    MISSED=$((MISSED+1))
  else
    local n; n=$(grep -c '^  - ' "$dir/run.log")
    echo "CAUGHT   $name  ($n failing assertions)"
    grep '^  - ' "$dir/run.log" | head -2 | sed 's/^/           /'
    CAUGHT=$((CAUGHT+1))
  fi
}

# Replaces the whole file content with a patched copy read from a heredoc-free perl edit.
mutate "always-accept-password" \
  perl -0pi -e 's/boolean matched = hasher\.verify\(password, stored\);/boolean matched = true;/' src/accounts/UserRegistry.java

mutate "skip-hash-for-unknown-user" \
  perl -0pi -e 's/\n +hasher\.verify\(password, timingEqualizerCredential\(\)\);//' src/accounts/UserRegistry.java

mutate "username-not-in-derivation" \
  perl -0pi -e 's/(byte\[\] name = )username\.getBytes\(StandardCharsets\.UTF_8\);/$1new byte[0];/' src/accounts/PasswordHasher.java

mutate "fixed-salt-reused" \
  perl -0pi -e 's/\n +random\.nextBytes\(salt\);//' src/accounts/PasswordHasher.java

mutate "case-sensitive-lookup" \
  perl -0pi -e 's/return username\.toLowerCase\(Locale\.ROOT\);/return username;/' src/accounts/UserRegistry.java

mutate "registration-not-persisted" \
  perl -0pi -e 's/\n +store\.replaceAll\(updated\.values\(\)\);//' src/accounts/UserRegistry.java

mutate "store-password-as-hash" \
  perl -0pi -e 's/(byte\[\] hash = )derive\(password, salt, username, iterations\);/$1new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8);/' src/accounts/PasswordHasher.java

mutate "username-stored-verbatim" \
  perl -0pi -e 's/\Q + ENCODER.encodeToString(username.getBytes(StandardCharsets.UTF_8))\E/ + username/' src/accounts/CredentialRecord.java

mutate "world-readable-store" \
  perl -0pi -e 's/\QPosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        try {
            Files.setPosixFilePermissions\E/PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE);
        try {
            Files.setPosixFilePermissions/' src/accounts/UserStore.java

mutate "accept-any-username" \
  perl -0pi -e 's/\QPattern.compile("[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?", Pattern.CASE_INSENSITIVE);\E/Pattern.compile(".+", Pattern.DOTALL);/' src/accounts/UserRegistry.java

mutate "minimum-password-length-one" \
  perl -0pi -e 's/\Qstatic final int PASSWORD_MIN_LENGTH = 10;\E/static final int PASSWORD_MIN_LENGTH = 1;/' src/accounts/UserRegistry.java

mutate "duplicate-overwrites-account" \
  perl -0pi -e 's/\Q        if (byUsername.containsKey(key)) {
            return new Result(Status.USERNAME_TAKEN\E/        if (false) {\n            return new Result(Status.USERNAME_TAKEN/' src/accounts/UserRegistry.java

mutate "record-version-unchecked" \
  perl -0pi -e 's/\Q        if (!FILE_VERSION.equals(fields[0])) {\E/        if (false) {/' src/accounts/CredentialRecord.java

mutate "iterations-unbounded" \
  perl -0pi -e 's/\Q        if (iterations < ITERATIONS_MIN || iterations > ITERATIONS_MAX) {
            throw new IllegalArgumentException("iterations out of range: " + iterations);
        }
\E//s' src/accounts/CredentialRecord.java

echo
echo "caught: $CAUGHT   missed: $MISSED   skipped: $SKIPPED"
echo "artifacts under $ROOT"
[ "$MISSED" -eq 0 ]
