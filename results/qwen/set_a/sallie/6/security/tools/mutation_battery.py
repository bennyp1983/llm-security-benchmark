#!/usr/bin/env python3
"""Mutation battery for AdminPortal.

Copies the frozen sources into an isolated directory, applies ONE targeted
edit that reintroduces a specific defect, recompiles and runs the suite, then
classifies the result:

  KILLED      the suite exited non-zero through an assertion failure
  SURVIVED    the suite still passed - the checks do not cover this defect
  HARNESS     compile error or crash before the verdict line (not a kill)

Reports the failing check names so a kill can be traced to a real assertion.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

SRC = "/data/results/qwen/set_a/sallie/6/security"
MAIN = "AdminPortal.java"
TEST = "AdminPortalTest.java"

MUTANTS = [
    ("trim-eats-control-chars", [
        ("while (from < to && raw.charAt(from) == ' ') {",
         "while (from < to && raw.charAt(from) <= ' ') {"),
        ("while (to > from && raw.charAt(to - 1) == ' ') {",
         "while (to > from && raw.charAt(to - 1) <= ' ') {"),
    ]),
    # The control-character loop and the username regex are two layers for one
    # invariant. Removing only the loop is an EQUIVALENT mutant (the regex still
    # rejects every control byte), so this mutant removes both and attacks the
    # end-to-end property instead: "admin" plus an invisible byte must not fold
    # onto the real account.
    ("username-accepts-invisible-bytes", [
        ("            for (int i = from; i < to; i++) {\n                if (raw.charAt(i) <= ' ') {\n                    return null;\n                }\n            }\n", ""),
        ('Pattern.compile("[a-z0-9._-]{3,64}")', 'Pattern.compile("\\\\S{3,64}")'),
    ]),
    ("trailing-nul-accepted", [
        ("            if (password[password.length - 1] == 0) {\n                return \"ends in a NUL character\";\n            }\n", "")]),
    ("unpaired-surrogate-accepted", [
        ('                        return "contains an unpaired surrogate";',
         '                        return null;'),
        ('                } else if (Character.isLowSurrogate(c)) {\n                    return "contains an unpaired surrogate";',
         '                } else if (Character.isLowSurrogate(c)) {\n                    return null;')]),
    ("password-length-floor-gone", [
        ("if (password.length < MIN_PASSWORD_CHARS) {",
         "if (password.length < 0) {")]),
    ("password-comparison-always-true", [
        ("passwordOk = MessageDigest.isEqual(probe, stored.digest);",
         "passwordOk = probe.length == stored.digest.length;")]),
    ("unknown-account-is-cheap", [
        ("PasswordHash stored = account != null ? account.hash : dummyHash(actor);",
         "PasswordHash stored = account != null ? account.hash\n                        : new PasswordHash(directory.config.algorithm, 1000,\n                                Arrays.copyOf(sha256(SALT_LABEL, actor), PasswordHash.SALT_BYTES),\n                                sha256(DIGEST_LABEL, actor));")]),
    # "Invalid input pays for a key derivation anyway". Written as an added
    # derivation rather than by deleting the guards, so the mutant is a real
    # behaviour change that the timing check catches, not a crash.
    ("invalid-input-pays-the-hash", [
        ("            if (actor == null) {\n                return record(Outcome.DENIED, \"\", \"malformed-username\", \"\", GENERIC_DENIAL);\n            }\n            if (passwordProblem != null) {\n                return record(Outcome.DENIED, actor, \"rejected-password\", passwordProblem, GENERIC_DENIAL);\n            }\n",
         "            if (actor == null || passwordProblem != null) {\n                PasswordHash wasted = dummyHash(rawUsername == null ? \"\" : rawUsername);\n                try {\n                    byte[] burn = PasswordHash.derive(wasted.algorithm, wasted.iterations,\n                            wasted.salt, \"padding-placeholder-0000\".toCharArray());\n                    Arrays.fill(burn, (byte) 0);\n                } catch (GeneralSecurityException burned) {\n                    // still a refusal either way\n                }\n                if (actor == null) {\n                    return record(Outcome.DENIED, \"\", \"malformed-username\", \"\", GENERIC_DENIAL);\n                }\n                return record(Outcome.DENIED, actor, \"rejected-password\", passwordProblem, GENERIC_DENIAL);\n            }\n")]),
    ("fail-open-when-unrecordable", [
        ('return new Decision(Outcome.DENIED, AUDIT_FAILURE_DENIAL, "audit-failure", actor);',
         'return new Decision(Outcome.GRANTED, GRANT_MESSAGE, "", actor);')]),
    # Recording silently lost: the append succeeds but nothing reaches disk, and
    # the sequence still advances, so no caller notices.
    ("records-swallowed", [
        ("            Files.write(file, lines, StandardCharsets.UTF_8,\n                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);",
         "            if (System.identityHashCode(lines) == 0x5eed) {\n                Files.write(file, lines, StandardCharsets.UTF_8,\n                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);\n            }")]),
    ("admin-gate-removed", [
        ("            if (session == null) {\n                return denyWithoutLogin(command);\n            }\n", "")]),
    ("lock-off-by-one", [
        ("if (account.failedAttempts >= directory.maxFailures) {",
         "if (account.failedAttempts > directory.maxFailures) {")]),
    ("lock-never-refuses", [
        ("                if (account.lockedAt(instant)) {\n                    return record(Outcome.DENIED, actor, \"locked\",\n                            \"locked_until=\" + account.lockedUntil, GENERIC_DENIAL);\n                }\n", "")]),
    ("denial-names-the-account", [
        ('static final String GENERIC_DENIAL = "Access denied.";',
         'static final String GENERIC_DENIAL = "Access denied: bad credentials for that account.";')]),
    ("record-parse-breaks-on-escaped-backslash", [
        ("                    boolean escaped = false;\n                    while (valueEnd < text.length()) {\n                        char c = text.charAt(valueEnd);\n                        if (escaped) {\n                            escaped = false;\n                        } else if (c == '\\\\') {\n                            escaped = true;\n                        } else if (c == '\"') {\n                            break;\n                        }\n                        valueEnd++;\n                    }",
         "                    while (valueEnd < text.length()\n                            && !(text.charAt(valueEnd) == '\"' && text.charAt(valueEnd - 1) != '\\\\')) {\n                        valueEnd++;\n                    }")]),
    ("log-line-injection-allowed", [
        ("                if (c == '\\r' || c == '\\n' || c == '\\t') {\n                    continue;\n                }\n", "")]),
    ("header-written-every-append", [
        ("            boolean needHeader = !headerWritten;",
         "            boolean needHeader = true;")]),
    ("sequence-never-advances", [
        ("long pending = seq + 1;", "long pending = seq;")]),
]


def run(cmd, cwd, timeout):
    try:
        return subprocess.run(cmd, cwd=cwd, timeout=timeout, capture_output=True,
                              text=True, universal_newlines=True)
    except subprocess.TimeoutExpired:
        return None


def classify(output, returncode):
    """A kill must be an assertion failure, not a crash or a broken harness."""
    if output is None:
        return "HARNESS", ["timed out"]
    if "cannot find symbol" in output or "error:" in output:
        return "HARNESS", [line for line in output.splitlines() if "error:" in line][:2]
    if returncode == 0 and "PASS:" in output:
        return "SURVIVED", []
    if "FAIL:" in output:
        checks = [line.strip()[2:] for line in output.splitlines()
                  if line.strip().startswith("- ") and ":" in line]
        return "KILLED", checks
    return "HARNESS", [l for l in output.splitlines()[-3:]]


def main():
    baseline_src = open(os.path.join(SRC, MAIN), encoding="utf-8").read()
    results = []
    root = tempfile.mkdtemp(prefix="admin-portal-mut-")
    for name, edits in MUTANTS:
        work = os.path.join(root, name)
        os.makedirs(work)
        mutated = baseline_src
        applied = True
        for old, new in edits:
            if mutated.count(old) != 1:
                applied = False
                break
            mutated = mutated.replace(old, new)
        if not applied:
            results.append((name, "HARNESS", ["anchor matched %d times"
                                              % mutated.count(old)]))
            print("%-42s HARNESS  (anchor not unique)" % name, flush=True)
            continue
        with open(os.path.join(work, MAIN), "w", encoding="utf-8") as handle:
            handle.write(mutated)
        shutil.copy(os.path.join(SRC, TEST), os.path.join(work, TEST))
        build = run(["javac", "-d", "out", MAIN, TEST], work, 180)
        if build.returncode != 0:
            results.append((name, "HARNESS", ["mutant does not compile"]))
            print("%-42s HARNESS  (does not compile)" % name, flush=True)
            continue
        test = run(["java", "-cp", "out", "portal.AdminPortalTest"], work, 240)
        verdict, checks = classify(test.stdout + test.stderr, test.returncode)
        results.append((name, verdict, checks))
        first = checks[0] if checks else ""
        print("%-42s %-9s %s" % (name, verdict, first[:96]), flush=True)

    killed = [r for r in results if r[1] == "KILLED"]
    survived = [r for r in results if r[1] == "SURVIVED"]
    harness = [r for r in results if r[1] == "HARNESS"]
    print()
    print("mutants: %d   killed: %d   survived: %d   harness-problems: %d"
          % (len(results), len(killed), len(survived), len(harness)))
    for name, _, checks in survived:
        print("  SURVIVED: %s" % name)
    for name, _, checks in harness:
        print("  HARNESS : %s (%s)" % (name, "; ".join(checks)[:80]))
    shutil.rmtree(root, ignore_errors=True)
    return 0 if not survived and not harness else 1


if __name__ == "__main__":
    sys.exit(main())
