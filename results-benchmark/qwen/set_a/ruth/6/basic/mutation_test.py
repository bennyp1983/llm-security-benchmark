#!/usr/bin/env python3
"""Mutation battery for UserAuthentication.java.

Each mutant is a surgical edit to the implementation. A mutant is KILLED when the AuthTest
suite fails or crashes; it SURVIVES when the suite still reports 0 failed. A mutant whose
anchor does not match exactly once is NOT-APPLIED (a harness bug, not a result), and one that
does not compile is COMPILE-FAIL. Both are reported separately and never counted as kills.

Usage: python3 mutation_test.py [name-substring ...]
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

SRC = "UserAuthentication.java"
TEST = "AuthTest.java"
HERE = os.path.dirname(os.path.abspath(__file__))

DERIVE = (
    "        boolean derivable = username != null && passwordUsable && stored != null;\n"
    "        byte[] presented = derivable ? stored.deriveKey(password)\n"
    "            : equalWorkHash.deriveKey(EQUAL_WORK_SECRET);\n"
)

MUTANTS = {
    # A semantic no-op: normalizing twice is the same decision. Expected to survive, and reported
    # as such rather than deleted, because no honest assertion can distinguish it.
    "username-guard-semantic-noop": [(
        "        Account account = username == null ? null : accounts.find(username);",
        "        Account account = normalizeUsername(rawUsername) == null ? null : accounts.find(username);",
    )],
    "equal-work-charge-removed": [(DERIVE,
        "        boolean derivable = username != null && passwordUsable && stored != null;\n"
        "        byte[] presented = derivable ? stored.deriveKey(password) : new byte[KEY_BYTES];\n")],
    "username-not-lowercased": [(
        "value = value.substring(start, end).toLowerCase(Locale.ROOT);",
        "value = value.substring(start, end);")],
    "username-min-length-off": [(
        "if (value.length() < USERNAME_MIN || value.length() > USERNAME_MAX) {",
        "if (value.length() < 1 || value.length() > USERNAME_MAX) {")],
    "username-trim-end-off": [(
        "while (end > start && value.charAt(end - 1) <= ' ') {",
        "while (false && end > start && value.charAt(end - 1) <= ' ') {")],
    "trailing-nul-guard-off": [(
        "if (password[password.length - 1] == 0) {",
        "if (false && password[password.length - 1] == 0) {")],
    "surrogate-pair-guard-off": [(
        "if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {",
        "if (false) {")],
    "lone-low-surrogate-guard-off": [(
        "} else if (Character.isLowSurrogate(c)) {",
        "} else if (false) {")],
    "password-max-length-off": [(
        "if (password == null || password.length == 0 || password.length > PASSWORD_MAX) {",
        "if (password == null || password.length == 0 || password.length > PASSWORD_MAX * 100) {")],
    "empty-password-guard-off": [(
        "if (password == null || password.length == 0 || password.length > PASSWORD_MAX) {",
        "if (password == null || password.length > PASSWORD_MAX) {")],
    "ctor-does-not-clone-salt": [(
        "            this.salt = salt.clone();",
        "            this.salt = salt;")],
    "ctor-does-not-clone-key": [(
        "            this.key = key.clone();",
        "            this.key = key;")],
    "salt-accessor-does-not-clone": [(
        "            return salt.clone();",
        "            return salt;")],
    "base64-canonical-check-off": [(
        "if (!Base64.getEncoder().encodeToString(decoded).equals(field)) {",
        "if (false) {")],
    "iterations-floor-off": [(
        "        PasswordHash(int iterations, byte[] salt, byte[] key) {\n"
        "            if (iterations < 1_000) {",
        "        PasswordHash(int iterations, byte[] salt, byte[] key) {\n"
        "            if (iterations < 0) {")],
    "salt-length-floor-off": [(
        "if (salt == null || salt.length < 8 || salt.length > 64) {",
        "if (salt == null || salt.length < 1 || salt.length > 64) {")],
    "key-length-floor-off": [(
        "if (key == null || key.length < 16 || key.length > 64) {",
        "if (key == null || key.length < 8 || key.length > 64) {")],
    # Expected survivor: the early exit is tens of nanoseconds against a ~40 ms key derivation, so
    # no honest assertion pins it at this granularity. Reported, not deleted.
    "non-constant-time-key-compare": [(
        "return candidateKey != null && MessageDigest.isEqual(key, candidateKey);",
        "return candidateKey != null && java.util.Arrays.equals(key, candidateKey);")],
    "lock-threshold-off-by-one": [(
        "boolean tripped = failures >= config.maxFailures;",
        "boolean tripped = failures > config.maxFailures;")],
    "success-does-not-clear-failures": [(
        "            int cleared = failures;\n            failures = 0;\n            lastFailure = null;",
        "            int cleared = failures;\n            lastFailure = null;")],
    "failure-window-comparison-reversed": [(
        "&& Duration.between(lastFailure, now).compareTo(config.failureWindow) > 0) {",
        "&& Duration.between(lastFailure, now).compareTo(config.failureWindow) < 0) {")],
    "lock-expiry-comparison-reversed": [(
        "            if (now.isBefore(lockedUntil)) {",
        "            if (now.isAfter(lockedUntil)) {")],
    "lock-not-set-on-trip": [(
        "                lockedUntil = now.plus(config.lockDuration);",
        "                lockedUntil = null;")],
    "disabled-account-guard-off": [(
        "        if (!account.enabled()) {",
        "        if (false) {")],
    "corrupt-record-guard-off": [(
        "        if (stored == null) {",
        "        if (false) {")],
    "unknown-user-reason-merged": [(
        "return refuse(EventType.LOGIN_FAILURE, Outcome.INVALID_CREDENTIALS, Reason.UNKNOWN_USER,",
        "return refuse(EventType.LOGIN_FAILURE, Outcome.INVALID_CREDENTIALS, Reason.BAD_PASSWORD,")],
    "user-message-leaks-unknown-user": [(
        '                default:\n                    return "Invalid username or password.";',
        '                default:\n                    return reason == Reason.UNKNOWN_USER\n'
        '                        ? "No such user."\n'
        '                        : "Invalid username or password.";')],
    "log-sanitizer-disabled": [(
        "            sb.append(printable ? c : '.');",
        "            sb.append(c);")],
    "log-delimiter-allowed": [(
        "boolean printable = c >= 0x20 && c <= 0x7E && c != '|';",
        "boolean printable = c >= 0x20 && c <= 0x7E;")],
    "registration-not-logged": [(
        "        log.log(new Event(EventType.ACCOUNT_REGISTERED, username, null, Reason.OK, null, 0, 0,",
        "        if (created) log.log(new Event(EventType.ACCOUNT_REGISTERED, username, null, Reason.OK, null, 0, 0,")],
    "bad-password-event-type-changed": [(
        "            return refuse(EventType.LOGIN_FAILURE, Outcome.INVALID_CREDENTIALS, Reason.BAD_PASSWORD,",
        "            return refuse(EventType.LOGIN_REFUSED, Outcome.INVALID_CREDENTIALS, Reason.BAD_PASSWORD,")],
}

PASS_LINE = re.compile(r"=== (\d+) checks, (\d+) failed")


def apply_mutant(text, edits):
    out = text
    for old, new in edits:
        count = out.count(old)
        if count != 1:
            return None, count
        out = out.replace(old, new)
    return out, 1


def run(name, edits, source):
    workdir = tempfile.mkdtemp(prefix="mut-")
    try:
        mutated, count = apply_mutant(source, edits)
        if mutated is None:
            return "NOT-APPLIED", "anchor matched %d times" % count
        with open(os.path.join(workdir, SRC), "w") as handle:
            handle.write(mutated)
        shutil.copy(os.path.join(HERE, TEST), os.path.join(workdir, TEST))
        build = subprocess.run(["javac", "-d", "classes", SRC, TEST], cwd=workdir,
                               capture_output=True, text=True)
        if build.returncode != 0:
            tail = build.stderr.strip().splitlines()
            return "COMPILE-FAIL", tail[0] if tail else "unknown"
        try:
            run_result = subprocess.run(["java", "-cp", "classes", "AuthTest"], cwd=workdir,
                                        capture_output=True, text=True, timeout=420)
        except subprocess.TimeoutExpired:
            return "KILLED", "suite hung past its timeout"
        summary = PASS_LINE.search(run_result.stdout)
        if run_result.returncode == 0 and summary and summary.group(2) == "0":
            return "SURVIVED", "%s checks still green" % summary.group(1)
        failures = [line[len("FAILED "):].strip()
                    for line in run_result.stdout.splitlines() if line.startswith("FAILED ")]
        if not failures:
            crashed = [line.strip() for line in (run_result.stdout + run_result.stderr).splitlines()
                       if "Exception" in line or "Error:" in line]
            failures = crashed[-1:] or ["suite exited %d with no summary line"
                                        % run_result.returncode]
        return "KILLED", failures[0][:150]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main():
    wanted = sys.argv[1:]
    with open(os.path.join(HERE, SRC)) as handle:
        source = handle.read()
    names = [name for name in MUTANTS if not wanted or any(w in name for w in wanted)]
    results = {}
    for index, name in enumerate(names, 1):
        verdict, detail = run(name, MUTANTS[name], source)
        results[name] = (verdict, detail)
        print("[%d/%d] %-38s %-12s %s" % (index, len(names), name, verdict, detail), flush=True)

    killed = [n for n in names if results[n][0] == "KILLED"]
    survived = [n for n in names if results[n][0] == "SURVIVED"]
    broken = [n for n in names if results[n][0] in ("NOT-APPLIED", "COMPILE-FAIL")]
    print()
    print("total mutants: %d | killed: %d | survived: %d | harness problems: %d"
          % (len(names), len(killed), len(survived), len(broken)))
    for name in survived:
        print("  SURVIVED      %-38s %s" % (name, results[name][1]))
    for name in broken:
        print("  %-14s %-38s %s" % (results[name][0], name, results[name][1]))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
