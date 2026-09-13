#!/bin/bash
# Mutation harness: break one guard at a time, rebuild, and require SelfTest to fail.
# A mutation that survives is reported, not hidden.
set -u
BASE=/data/results/qwen/set_a/sallie/4/security
WORK=$(mktemp -d)
SNAP="$WORK/snapshot"
# Freeze the sources once: editing src/ while the battery runs produces bogus
# compile failures that look like harness bugs.
mkdir -p "$SNAP" || exit 1
cp "$BASE"/src/*.java "$SNAP"/ || exit 1
mutants_total=$(grep -c '^run_mutation ' "$BASE/mutation-battery.sh")
cd "$WORK" || exit 1

run_mutation() {
  local name="$1" file="$2" from="$3" to="$4"
  rm -rf src out; mkdir -p src out
  cp "$SNAP"/*.java src/ || { echo "HARNESS-ERROR copy $name"; return; }
  if ! grep -qF -- "$from" "src/$file"; then
    echo "HARNESS-ERROR pattern-absent :: $name"
    return
  fi
  python3 - "src/$file" "$from" "$to" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
if text.count(old) != 1:
    sys.exit(3)
open(path, "w", encoding="utf-8").write(text.replace(old, new))
PY
  case $? in
    3) echo "HARNESS-ERROR ambiguous :: $name"; return;;
    *) ;;
  esac
  if ! javac -nowarn -d out src/*.java >compile.log 2>&1; then
    echo "HARNESS-ERROR compile :: $name"
    return
  fi
  local t0=$(date +%s%N)
  timeout 300 java -cp out SelfTest >run.log 2>&1
  local code=$?
  local ms=$(( ($(date +%s%N) - t0) / 1000000 ))
  applied=$((applied + 1))
  if [ "$code" -eq 0 ]; then
    survived=$((survived + 1))
    echo "SURVIVED    :: $name"
  elif grep -q '^  FAIL ' run.log; then
    killed=$((killed + 1))
    local failed=$(grep -c '^  FAIL ' run.log)
    local first=$(grep '^  FAIL ' run.log | head -2 | sed 's/^  FAIL /|/' | tr '\n' ' ')
    echo "KILLED      :: $name  (fails=$failed ${ms}ms) $first"
  elif [ "$code" -eq 124 ]; then
    killed=$((killed + 1))
    echo "KILLED(tmo) :: $name"
  else
    broken=$((broken + 1))
    echo "HARNESS-ERROR suite died without asserting :: $name (exit=$code)"
  fi
}

applied=0
killed=0
survived=0
broken=0

echo "=== mutation battery ==="
run_mutation "verify uses == instead of constant-time compare" PasswordHasher.java \
  'return MessageDigest.isEqual(actual, record.digest());' \
  'return actual == record.digest();'
run_mutation "verify uses early-exit Arrays.equals" PasswordHasher.java \
  'return MessageDigest.isEqual(actual, record.digest());' \
  'return java.util.Arrays.equals(actual, record.digest());'
run_mutation "unknown account skips the equalising derivation" UserAccountService.java \
  '        if (stored.isEmpty()) {
            hasher.burnWork();' \
  '        if (stored.isEmpty()) {'
run_mutation "malformed stored record short-circuits with no work" PasswordHasher.java \
  '        if (candidate == null || record == null) {
            burnWork();
            return false;
        }' \
  '        if (candidate == null || record == null) {
            return false;
        }'
run_mutation "digest is a reversible encoding of the password" PasswordHasher.java \
  '        byte[] digest = derive(password, salt, iterations);' \
  '        byte[] digest = java.util.Arrays.copyOf(java.util.Base64.getEncoder().encode(new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8)), HASH_BYTES);'
run_mutation "salt is a fixed constant instead of random" PasswordHasher.java \
  '        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);' \
  '        byte[] salt = new byte[SALT_BYTES];'
run_mutation "trailing-NUL guard removed" Passwords.java \
  '            if (c == 0) {
                return false;
            }' \
  '            if (false) {
                return false;
            }'
run_mutation "lone-surrogate guard removed" Passwords.java \
  '            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    return false;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }' \
  '            if (Character.isHighSurrogate(c)) {
                i++;
            }'
run_mutation "username trimming uses trim() (deletes control chars)" Usernames.java \
  '        String trimmed = raw.substring(start, end);' \
  '        String trimmed = raw.trim();'
run_mutation "duplicate account check removed" AccountStore.java \
  '        if (records.containsKey(username)) {
            return false;
        }' \
  '        if (false) {
            return false;
        }'
run_mutation "stored verifier format not checked before writing" AccountStore.java \
  '        if (PasswordHasher.tryParse(verifier) == null) {
            throw new IllegalArgumentException("refusing to store a malformed verifier");
        }' \
  '        if (false) {
            throw new IllegalArgumentException("refusing to store a malformed verifier");
        }'
run_mutation "stored-record length checks removed" PasswordHasher.java \
  '        if (salt.length != SALT_BYTES || digest.length != HASH_BYTES) {
            return null;
        }' \
  '        if (false) {
            return null;
        }'
run_mutation "duplicate username check removed from service" UserAccountService.java \
  '        if (store.contains(username)) {
            return new Outcome(Status.ACCOUNT_EXISTS);
        }' \
  '        if (false) {
            return new Outcome(Status.ACCOUNT_EXISTS);
        }'
run_mutation "empty store file accepted" AccountStore.java \
  '            if (line.isEmpty()) {
                continue;
            }' \
  '            if (line.isEmpty()) {
                records.put("", "");
                continue;
            }'
run_mutation "iteration-count bound removed" PasswordHasher.java \
  '        if (rounds < MIN_ITERATIONS || rounds > MAX_ITERATIONS) {
            return null;
        }' \
  '        if (false) {
            return null;
        }'
run_mutation "password length maximum removed" Passwords.java \
  'return password != null && password.length >= MIN_LENGTH && password.length <= MAX_LENGTH;' \
  'return password != null && password.length >= MIN_LENGTH;'
run_mutation "weak-password variety check removed" Passwords.java \
  '        return classes >= 2;' \
  '        return true;'
run_mutation "store reload ignores on-disk shape validation" AccountStore.java \
  '            if (Usernames.normalize(user) == null || PasswordHasher.tryParse(verifier) == null) {
                throw new IllegalStateException("Malformed account store " + file + " at line " + (i + 1));
            }' \
  '            if (false) {
                throw new IllegalStateException("Malformed account store " + file + " at line " + (i + 1));
            }'
echo "=== done ==="
echo "total mutants: $mutants_total   applied: $applied   killed: $killed   survived: $survived   harness problems: $((broken + mutants_total - applied))"
rm -rf "$WORK"
