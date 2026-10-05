#!/bin/bash
# Mutation battery for the load-bearing guards.
#
# Each mutant is one textual edit to src/main. A mutant is KILLED only when a suite reports a FAIL
# line. A mutant that passes every suite it was given is a SURVIVOR and is reported as one --
# survivors are information, not something to argue away. A suite that crashes without printing a
# SUMMARY is recorded as ERROR, never as a kill.
#
# Suite 3 (timing) is never used: its verdicts depend on machine load, which a text mutation
# perturbs for reasons unrelated to the guard under test.
set -u
ROOT="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
JAVAC="${JAVAC:-javac}"
JAVA="${JAVA:-java}"
WORK=/tmp/mut-$$.d
# The mutant tree is laid out as <TREE>/src/main/java/... because the suites read shipped sources
# through -Dauth.source.dir. Pointing that at a flat copy instead would have those assertions open
# the pristine tree and pronounce every mutant intact.
TREE="$WORK/tree"
SRC="$TREE/src/main"
MAIN="$WORK/main"
TEST="$WORK/test"
LOG="${LOG:-/tmp/mut-battery.log}"
: > "$LOG"
mkdir -p "$SRC" "$TREE/src/test" "$MAIN" "$TEST"
trap 'rm -rf "$WORK"' EXIT

suite_class() {
  case $1 in
    1) echo Suite1Validation;;
    2) echo Suite2LoginBehavior;;
    4) echo Suite4AuditDurability;;
    5) echo Suite5Concurrency;;
  esac
}

run_case() {
  local id="$1" file="$2" from="$3" to="$4" suites="$5" note="$6"
  rm -rf "$MAIN" "$TEST"; mkdir -p "$MAIN" "$TEST"
  rm -rf "$TREE"; mkdir -p "$SRC" "$TREE/src/test"
  cp -r "$ROOT/src/main/." "$SRC/"
  # The shipped-tree layout check also asks where the test classes live, so the scratch tree has to
  # carry them too, or that assertion fails for every mutant and manufactures a kill.
  cp -r "$ROOT/src/test/." "$TREE/src/test/"
  python3 - "$SRC/$file" "$from" "$to" <<'PY'
import sys
path, frm, to = sys.argv[1], sys.argv[2], sys.argv[3]
data = open(path, encoding='utf-8').read()
n = data.count(frm)
if n != 1:
    print("ANCHOR=%d" % n)
    sys.exit(3)
open(path, 'w', encoding='utf-8').write(data.replace(frm, to))
PY
  local applied=$?
  if [ "$applied" -eq 3 ]; then
    echo "MUT $id ANCHOR-DRIFT ($note)" | tee -a "$LOG"; return
  elif [ "$applied" -ne 0 ]; then
    echo "MUT $id APPLY-ERROR ($note)" | tee -a "$LOG"; return
  fi
  if ! "$JAVAC" -nowarn -d "$MAIN" $(find "$SRC" -name '*.java') >"$WORK/c.log" 2>&1; then
    echo "MUT $id KILLED-BUILD ($note): mutant does not compile" | tee -a "$LOG"; return
  fi
  if ! "$JAVAC" -nowarn -d "$TEST" -cp "$MAIN" $(find "$ROOT/src/test/java" -name '*.java') >"$WORK/t.log" 2>&1; then
    echo "MUT $id KILLED-BUILD ($note): tests no longer compile" | tee -a "$LOG"; return
  fi
  local kills=0 errors=0 detail=""
  for n in $suites; do
    local cls; cls=$(suite_class "$n")
    timeout 900 "$JAVA" -Dauth.source.dir="$TREE" -cp "$MAIN:$TEST" "com.example.auth.$cls" >"$WORK/s$n.log" 2>&1
    local st=$?
    local fails; fails=$(grep -c '^FAIL' "$WORK/s$n.log")
    local done_; done_=$(grep -c '^SUMMARY' "$WORK/s$n.log")
    if [ "$fails" -gt 0 ]; then
      kills=$((kills+1))
      detail="$detail suite$n:$(grep -m1 '^FAIL' "$WORK/s$n.log" | cut -c1-90)"
    elif [ "$st" -ne 0 ] || [ "$done_" -eq 0 ]; then
      errors=$((errors+1))
      detail="$detail suite$n:CRASH-exit$st"
    fi
  done
  if [ "$kills" -gt 0 ]; then
    echo "MUT $id KILLED ($note) kills=$kills errors=$errors$detail" | tee -a "$LOG"
  elif [ "$errors" -gt 0 ]; then
    echo "MUT $id ERROR ($note): suite crashed without a FAIL line$detail" | tee -a "$LOG"
  else
    echo "MUT $id SURVIVED ($note) suites=$suites" | tee -a "$LOG"
  fi
}

cd "$ROOT" || exit 1
echo "=== mutation battery start ===" | tee -a "$LOG"

# Self-check before any mutant: an edit that changes nothing must leave every suite green. If this
# reports FAIL the harness is broken (wrong source tree, stale classpath, a fixture that collides)
# and every result below would be meaningless, so stop here rather than report kills we did not earn.
run_case BASELINE java/com/example/auth/AuthConfig.java 'int minAcceptedIterations() {' 'int minAcceptedIterations() {' '1 2 4 5' 'harness self-check, no mutation'
if grep -qE 'MUT BASELINE (KILLED|ERROR|ANCHOR|APPLY)' "$LOG"; then
  echo "BASELINE FAILED - harness is not sound, aborting before any mutant" | tee -a "$LOG"
  exit 1
fi
echo "baseline clean" | tee -a "$LOG"

run_case M01 java/com/example/auth/InputValidator.java 'if (raw.length == 0) {' 'if (false) {' '2' 'empty password buffer bypasses the control scan'
run_case M02 java/com/example/auth/InputValidator.java 'if (c < 0x21 || c == 0x7f) {' 'if (c < 0x20 || c == 0x7f) {' '1 2' 'control scan admits a space'
run_case M03 java/com/example/auth/InputValidator.java 'return octetsSeen == 4;' 'return octetsSeen >= 3;' '1' 'dotted-quad octet count relaxed'
run_case M04a java/com/example/auth/AuditLogger.java 'if (!attrs.isRegularFile()) {' 'if (false) {' '4 5' 'inode identity guard removed'
# The isRegularFile branch above is subsumed by the fileKey() comparison, so it is only falsifiable
# by removing that one; M04a is a documented redundant layer, M04b is the guard that carries it.
run_case M04b java/com/example/auth/AuditLogger.java \
  'if (now != null && openedFileKey != null && !now.equals(openedFileKey)) {' 'if (false) {' \
  '4' 'inode identity comparison removed'
run_case M05 java/com/example/auth/AuditLogger.java \
  'if (PosixMode.notExactlyOwnerOnly(file)) {
            closeChannelQuietly();
            return false;' 'if (false) {
            closeChannelQuietly();
            return false;' '4' 'per-write log permission read-back removed'
run_case M06 java/com/example/auth/SessionTokenStore.java 'if (expiresAtMillis.size() >= maxActiveSessions) {' 'if (false) {' '1 5' 'session capacity cap removed'
run_case M07 java/com/example/auth/AttemptThrottle.java 'if (sources.size() >= MAX_SOURCE_KEYS && !evictIdleSources(horizon)) {' 'if (false) {' '5' 'source table cap removed'
run_case M08 java/com/example/auth/AttemptThrottle.java 'if (accounts.size() >= MAX_ACCOUNT_KEYS && !evictIdleAccounts(nowMillis - lockSeconds * 2000L)) {' 'if (false) {' '5' 'account table cap removed'
run_case M09 java/com/example/auth/AttemptThrottle.java 'long idleHorizon = nowMillis - SWEEP_INTERVAL_IDLE_MILLIS;' 'long idleHorizon = System.currentTimeMillis() - SWEEP_INTERVAL_IDLE_MILLIS;' '5' 'sweep uses the wall clock'
run_case M10 java/com/example/auth/AuthEvent.java 'if (sessionSuffixRejected) {' 'if (false) {' '1 4' 'unusable session id silently dropped'
run_case M11 java/com/example/auth/PasswordHasher.java 'MessageDigest.isEqual(candidate, storedDigest);' 'java.util.Arrays.equals(candidate, storedDigest);' '1 2' 'digest compare not constant time'
run_case M12 java/com/example/auth/AuthenticationService.java 'budget.padUntil(startedNanos);' '// budget.padUntil(startedNanos);' '2' 'latency floor removed'
run_case M13 java/com/example/auth/FileCredentialStore.java 'if (lines.size() > MAX_RECORDS) {' 'if (false) {' '1' 'record-count bound removed'
run_case M14 java/com/example/auth/AuthConfig.java 'config.validateFilesystem();' '// config.validateFilesystem();' '1' 'filesystem checks skipped on the env path'
run_case M15 java/com/example/auth/AuthenticationService.java 'if (issuedSessionId != null && !granted) {' 'if (false) {' '2' 'orphaned session identifier never revoked'
run_case M16 java/com/example/auth/FileCredentialStore.java "if (field.length() > 1 && field.charAt(0) == '0') {" 'if (false) {' '1' 'leading-zero iteration spelling admitted'
run_case M17 java/com/example/auth/PasswordHasher.java 'if (!Base64.getEncoder().encodeToString(decoded).equals(value)) {' 'if (false) {' '1' 'non-canonical Base64 admitted'
run_case M18 java/com/example/auth/AuditLogger.java '.accountFieldOf(original == null ? null : original.accountField())' '.accountFieldOf(AccountField.render(null, false))' '4' 'alert loses account attribution'

# --- guards added after the second adversarial review pass -------------------------------
# Each of these is a control that only exists because a reviewer asked for it, so each is paired
# with a suite that fails when it is removed. Suite 1's source-text checks are included on purpose
# for the two controls whose observable behaviour is a bound on work rather than an outcome.
run_case M19 java/com/example/auth/AuditLogger.java 'long boundary = offsetAfterLastNewline(probe, size);' 'long boundary = size;' '1 4' 'torn trailing record is not repaired'
run_case M20 java/com/example/auth/AuditLogger.java 'pendingTornAlertBytes += discarded;' '// pendingTornAlertBytes += discarded;' '4' 'discarded bytes on reopen are never reported'
run_case M21 java/com/example/auth/AuditLogger.java 'if (size >= maxLogBytes) {' 'if (false) {' '4' 'event log size ceiling removed'
run_case M22 java/com/example/auth/AuthenticationService.java \
  'alertAround(e);
            return AuthResult.denied();' \
  'throttle.recordAccountFailure(canonicalName == null ? AttemptThrottle.canonicalize(submitted) : canonicalName,
                    time.nowMillis(), config.accountLockAfter(), config.accountLockSeconds());
            alertAround(e);
            return AuthResult.denied();' '2' 'audit outage charged to the account'
run_case M23 java/com/example/auth/AuthenticationService.java 'logLockEngaged(submitted, present, canonicalSource,' 'logLockEngaged(submitted, false, canonicalSource,' '4' 'lock event contradicts the failure it follows'
run_case M24 java/com/example/auth/AuthConfig.java 'AuthConfig config = b.build();' 'AuthConfig config = new AuthConfig(b);' '1' 'environment path skips the cross-field sizing rules'
run_case M25 java/com/example/auth/PasswordHasher.java 'if (saltIterations < 1 || saltIterations > maxSaltIterations) {' 'if (saltIterations < 1 || saltIterations > MAX_ITERATIONS) {' '1 2' 'stored work factor uncapped per attempt'
run_case M26 java/com/example/auth/FileCredentialStore.java 'if (iterations < config.minAcceptedIterations() || iterations > config.pbkdf2Iterations()) {' 'if (iterations < config.minAcceptedIterations()) {' '1' 'store admits a record above the configured work factor'
run_case M27 java/com/example/auth/SessionTokenStore.java 'if (candidate == null || candidate.length() != TOKEN_HEX_LENGTH || !isHex(candidate)) {' 'if (candidate == null) {' '1' 'session shape check moved behind the table sweep'
# The mode gate fails closed when a file system reports no POSIX bits. This machine has no such mount,
# so the null branch is reached with a path that cannot be stat'ed and the third variant
# (writableByGroupOrOther) only by the shipped-source assertion; these two mutants prove both halves
# of that assertion are live rather than one needle satisfying three claims.
run_case M28 java/com/example/auth/PosixMode.java 'static boolean notExactlyOwnerOnly(Path path) {
        Set<PosixFilePermission> permissions = permissionsOf(path);
        if (permissions == null) {
            return true;' 'static boolean notExactlyOwnerOnly(Path path) {
        Set<PosixFilePermission> permissions = permissionsOf(path);
        if (permissions == null) {
            return false;' '1 4' 'an unreadable mode accepted as owner-only'
run_case M29 java/com/example/auth/PosixMode.java 'static boolean exposedToGroupOrOther(Path path) {
        Set<PosixFilePermission> permissions = permissionsOf(path);
        if (permissions == null) {
            return true;' 'static boolean exposedToGroupOrOther(Path path) {
        Set<PosixFilePermission> permissions = permissionsOf(path);
        if (permissions == null) {
            return false;' '1' 'an unreadable mode accepted as not exposed'

echo "=== summary ===" | tee -a "$LOG"
# The baseline row is the harness self-check, not a mutant: keep it out of both tallies.
echo "mutants=$(grep -c '^MUT M' "$LOG")" | tee -a "$LOG"
echo "killed=$(grep '^MUT M' "$LOG" | grep -c 'KILLED')" | tee -a "$LOG"
echo "survived=$(grep '^MUT M' "$LOG" | grep -c 'SURVIVED')" | tee -a "$LOG"
echo "errors=$(grep '^MUT M' "$LOG" | grep -cE '(ERROR|ANCHOR-DRIFT|APPLY-ERROR)')" | tee -a "$LOG"
grep -E '^MUT M.*(SURVIVED|ERROR|ANCHOR|DRIFT)' "$LOG" > "$LOG.problems.txt" || true
cat "$LOG.problems.txt" | tee -a "$LOG"
