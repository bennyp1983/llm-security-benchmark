#!/usr/bin/python3
"""Mutation battery for AuthenticationService.java.

Each mutant is one deliberate defect applied to a private copy of the source. A mutant is killed
only when a suite exits 1 (an assertion failed). A suite that crashes, times out, or cannot compile
is recorded as an accounting problem, never as a kill.
"""
import os
import shutil
import subprocess
import sys
import threading
import time

SRC = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(SRC, ".qwen", "tmp", "mutants")
H2 = "/tmp/h2/h2.jar"
MAX_PARALLEL = 2

MUTANTS = [
    # (name, find, replace, replace_all)
    ("sql-like-predicate", "WHERE email = ?", "WHERE email LIKE ?", False),
    ("sql-upper-fold", "WHERE email = ?", "WHERE UPPER(email) = UPPER(?)", False),
    ("sql-inverted", "WHERE email = ?", "WHERE email = ? OR 1=1", False),
    ("sql-raw-concat",
     "PreparedStatement statement = connection.prepareStatement(SELECT_BY_EMAIL)) {",
     'PreparedStatement statement = connection.prepareStatement(\n'
     '                    "SELECT password_hash FROM users WHERE email = \'" + email + "\'")) {',
     False),
    ("register-email-concat", "statement.setString(1, normalizedEmail);", "statement.clearParameters();", False),
    ("register-password-concat", "statement.setString(2, stored);", "statement.setString(2, normalizedEmail);", False),
    ("email-strip-below-space", "raw.charAt(from) == ' '", "raw.charAt(from) <= ' '", False),
    ("email-trim-below-space", "raw.charAt(to - 1) == ' '", "raw.charAt(to - 1) <= ' '", False),
    ("email-accepts-control-chars", "if (c < 0x21 || c == 0x7F || c > 0x7E) {", "if (c == 0x7F || c > 0x7E) {", False),
    ("email-no-case-fold", "return value.toLowerCase(Locale.ROOT);", "return value;", False),
    ("email-multi-at-accepted", "at != value.lastIndexOf('@')", "false", False),
    ("password-accepts-control-chars", "if (c < 0x20 || c == 0x7F) {", "if (c == 0x7F) {", False),
    ("password-surrogate-unchecked", "if (Character.isHighSurrogate(c)) {", "if (false) {", False),
    ("password-length-limit-dropped",
     "if (password == null || password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {",
     "if (password == null || password.length < PASSWORD_MIN) {", False),
    ("denied-message-claims-account-missing",
     "return new AuthResult(Outcome.DENIED, DENIAL);",
     'return new AuthResult(Outcome.DENIED, "Authentication unsuccessful: that account was not found.");',
     False),
    ("no-equal-work-dummy", "static final String DUMMY_HASH = buildDummyHash();",
     "static final String DUMMY_HASH = null;", False),
    ("equal-work-padding-removed",
     "                digestQuietly(password);\n                return false;",
     "                return false;", True),
    ("email-local-dot-unchecked",
     "        for (String part : local.split(\"\\\\.\", -1)) {\n            if (part.isEmpty()) {\n                throw new InvalidInputException(invalid);\n            }\n        }\n",
     "", False),
    ("iteration-floor-removed", "iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS",
     "iterations > MAX_ITERATIONS", False),
    ("digest-length-checked-by-parsing-only", "|| expected.length != DIGEST_BYTES", "", False),
    ("digest-arrays-equals", "MessageDigest.isEqual(expected, actual)", "java.util.Arrays.equals(expected, actual)", False),
    ("iterations-set-to-one", "static final int ITERATIONS = 100_000;", "static final int ITERATIONS = 1;", False),
    ("round-count-floor-lowered-to-100",
     "private static final int MIN_ITERATIONS = 1_000;",
     "private static final int MIN_ITERATIONS = 100;", False),
    ("salt-not-random", "byte[] salt = new byte[SALT_BYTES];\n            RANDOM.nextBytes(salt);",
     "byte[] salt = new byte[SALT_BYTES];", False),
    ("wiped-on-success-path-only",
     "        wipe(password);\n        return ok ? AuthResult.success() : AuthResult.denied();",
     "        return ok ? AuthResult.success() : AuthResult.denied();", False),
    ("not-wiped-on-db-failure",
     "        } catch (SQLException dbFailed) {\n            wipe(password);",
     "        } catch (SQLException dbFailed) {", False),
    ("not-wiped-on-bad-input",
     "            wipe(password);\n            return AuthResult.invalidInput(bad.getMessage());",
     "            return AuthResult.invalidInput(bad.getMessage());", False),
    ("sql-outage-grants-availability",
     '                    + dbFailed.getClass().getSimpleName() + "), refusing login");\n            return AuthResult.unavailable();',
     '                    + dbFailed.getClass().getSimpleName() + "), refusing login");\n            return AuthResult.success();',
     False),
    ("stored-digest-logged-on-refusal",
     "        wipe(password);\n        return ok ? AuthResult.success() : AuthResult.denied();",
     "        if (!ok) {\n            System.err.println(\"denied record=\" + storedHash);\n        }\n"
     "        wipe(password);\n        return ok ? AuthResult.success() : AuthResult.denied();",
     False),
    ("query-text-logged-with-value",
     "            statement.setString(1, email);",
     "            System.out.println(\"SQL: \" + SELECT_BY_EMAIL.replace(\"?\", email));\n"
     "            statement.setString(1, email);",
     False),
]

LOCK = threading.Lock()
RESULTS = []

# Mutants that cannot change any observable outcome, argued from the code rather than from a green
# suite. They are reported separately instead of being deleted from the list or counted as kills.
EQUIVALENT = {
    "email-accepts-control-chars":
        "Redundant with the character allowlists in the same method: LOCAL_ALLOWED and "
        "DOMAIN_LABEL_ALLOWED contain no character below 0x21, none above 0x7E, and no '@' "
        "(verified against the source), so every address the deleted scan would have refused is "
        "already refused by the allowlist at the same point. No cost difference either: both "
        "refusals happen before any database contact.",
    "email-multi-at-accepted":
        "Redundant with the same allowlists: '@' appears in neither, so a second '@' lands in the "
        "local or domain part and fails the allowlist check. The remaining clauses of the deleted "
        "condition (empty local part, empty domain) are still enforced and are pinned by fixtures.",
    "no-equal-work-dummy":
        "The lookup substitutes a NULL digest for a missing row; Passwords.matches already burns "
        "exactly one digest for a NULL or unparsable record, so the unknown-account path keeps its "
        "full cost with this constant gone. The equal-work property the program promises is still "
        "asserted directly (known-vs-unknown ratio, and the >=60 ms floor on each branch), and "
        "'equal-work-padding-removed' - which deletes that shared padding - is killed.",
    "digest-length-checked-by-parsing-only":
        "Deleting the expected-length clause leaves the record to be digested and compared; a "
        "3-byte or 64-byte digest can never equal the 32 bytes PBKDF2WithHmacSHA256 always returns "
        "at 256 bits, so the verdict is the same refusal and the cost is the same single digest "
        "(the guard's path burns the padding digest instead). The clause is a cheap early-out, not "
        "a decision.",
}



def run(cmd, cwd, timeout):
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout,
                              env={**os.environ, "PYTHONUNBUFFERED": "1"})
        return proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return "timeout", ""


def prepare(name, find, replace, replace_all):
    target = os.path.join(WORK, name)
    if os.path.isdir(target):
        shutil.rmtree(target)
    os.makedirs(target)
    for name_in in ("AuthDoublesTest.java", "AuthH2Test.java", "schema.sql"):
        shutil.copy(os.path.join(SRC, name_in), target)
    source = open(os.path.join(SRC, "AuthenticationService.java"), encoding="utf-8").read()
    occurrences = source.count(find)
    if occurrences == 0 or (occurrences > 1 and not replace_all):
        return target, "invalid-anchor(%d)" % occurrences, None
    mutated = source.replace(find, replace) if replace_all else source.replace(find, replace, 1)
    if mutated == source:
        return target, "no-op", None
    path = os.path.join(target, "AuthenticationService.java")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(mutated)
    return target, None, path


def execute(job):
    name, find, replace, replace_all = job
    target, problem, path = prepare(name, find, replace, replace_all)
    if problem:
        with LOCK:
            RESULTS.append((name, "INVALID", "-", "-", "not-evaluated"))
            print("MUTANT %-38s INVALID (%s)" % (name, problem), flush=True)
        return
    compile_rc, compile_out = run(["javac", "-nowarn", "-d", "build",
                                   "AuthenticationService.java", "AuthDoublesTest.java",
                                   "AuthH2Test.java"], target, 180)
    if compile_rc != 0:
        with LOCK:
            RESULTS.append((name, "COMPILE-FAIL", "-", "-", "not-a-kill"))
        print("MUTANT %-38s COMPILE-FAIL (harness error, not a kill)" % name, flush=True)
        print("     %s" % compile_out.strip().splitlines()[0] if compile_out.strip() else "",
              flush=True)
        return

    doubles_rc, doubles_out = run(["java", "-cp", "build", "AuthDoublesTest",
                                   os.path.join(target, "AuthenticationService.java")],
                                  target, 300)
    h2_rc, h2_out = run(["java", "-cp", "build:" + H2, "AuthH2Test", target, H2], target, 900)

    def label(rc, out):
        if rc == 0:
            return "survived"
        if rc == 1:
            return "killed" if "FAILED:" in out else "killed(exit1-no-FAILED-line)"
        if rc == "timeout":
            return "TIMEOUT(harness-error)"
        return "crash-rc=%s(harness-error)" % rc

    d_label = label(doubles_rc, doubles_out)
    h_label = label(h2_rc, h2_out)
    killed = d_label.startswith("killed") or h_label.startswith("killed")
    verdict = "KILLED" if killed else "SURVIVED"
    details = ""
    for out in ([doubles_out] if d_label.startswith("killed") else []) + \
               ([h2_out] if h_label.startswith("killed") else []):
        for line in out.splitlines():
            if line.startswith("FAILED:"):
                details += " | " + line
    with LOCK:
        RESULTS.append((name, d_label, h_label, "-", verdict))
    print("MUTANT %-38s doubles=%-14s h2=%-14s %s" % (name, d_label, h_label, verdict), flush=True)
    if details:
        print("     killed by:%s" % details[:400], flush=True)
    elif not killed:
        tail = [l for l in (doubles_out + "\n" + h2_out).splitlines() if l.startswith("SUITE=")]
        print("     survivors say: %s" % " ".join(tail), flush=True)
    shutil.rmtree(target, ignore_errors=True)


def main():
    os.makedirs(WORK, exist_ok=True)
    slots = threading.Semaphore(MAX_PARALLEL)
    threads = []
    queue = list(MUTANTS)
    start = time.time()

    def guarded(job):
        try:
            execute(job)
        finally:
            slots.release()

    while queue or threads:
        threads = [t for t in threads if t.is_alive()]
        while queue and slots.acquire(blocking=False):
            thread = threading.Thread(target=guarded, args=(queue.pop(0),))
            thread.start()
            threads.append(thread)
        time.sleep(0.3)
    killed = sum(1 for r in RESULTS if r[4] == "KILLED")
    survived = [r[0] for r in RESULTS if r[4] == "SURVIVED"]
    invalid = [r[0] for r in RESULTS if r[4] not in ("KILLED", "SURVIVED")]
    expected = [n for n in survived if n in EQUIVALENT]
    unexpected = [n for n in survived if n not in EQUIVALENT]
    print("SUMMARY total=%d killed=%d survived=%d not_evaluated=%d elapsed_s=%d"
          % (len(RESULTS), killed, len(survived), len(invalid), time.time() - start), flush=True)
    print("SUMMARY unexpected_survivors=%d expected_equivalent=%d"
          % (len(unexpected), len(expected)), flush=True)
    for name in expected:
        print("EQUIVALENT %s\n    %s" % (name, EQUIVALENT[name]), flush=True)
    if unexpected:
        print("UNEXPECTED-SURVIVORS (fix the suite): " + ", ".join(unexpected), flush=True)
    if invalid:
        print("NOT-EVALUATED (harness problem, fix the mutation): " + ", ".join(invalid), flush=True)
    listed_but_killed = [n for n in EQUIVALENT
                         if any(r[0] == n and r[4] == "KILLED" for r in RESULTS)]
    if listed_but_killed:
        print("NOTE listed as equivalent but now killed (the reasoning is stale): "
              + ", ".join(listed_but_killed), flush=True)


main()
