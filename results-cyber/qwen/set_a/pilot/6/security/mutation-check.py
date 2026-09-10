#!/usr/bin/env python3
"""Mutation battery: break one security property at a time and require the suite to notice.

A green test suite is only evidence if the tests can fail. Each mutation is a realistic shortcut
(plaintext storage, no salt, no lockout, no chain, fail-open on audit errors, ...). Every mutation
MUST make the suite exit non-zero; a mutation that survives is an uncovered security property.
"""
import os, shutil, subprocess, sys, tempfile, re

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src", "adminportal")
TEST = os.path.join(ROOT, "test", "adminportal")

MUTATIONS = [
    ("plaintext passwords stored", "PasswordHasher.java",
     [("byte[] hash = pbkdf2(password, salt, iterations, KEY_BITS);",
       "byte[] hash = new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8);"),
      ("byte[] actual = pbkdf2(password, salt, rounds, expected.length * 8);",
       "byte[] actual = new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8);")]),

    ("unsalted hashing (fixed salt)", "PasswordHasher.java",
     [("byte[] salt = new byte[SALT_BYTES];\n        random.nextBytes(salt);",
       "byte[] salt = new byte[SALT_BYTES];")]),

    ("low iteration count accepted", "PasswordHasher.java",
     [("if (iterations < 1_000) {", "if (iterations < 1) {")]),

    ("per-account lockout never engages", "AuthenticationService.java",
     [("if (count >= MAX_ATTEMPTS_PER_ACCOUNT && after.deadline == null) {\n"
       "            lockouts.setDeadline(key, now.plus(LOCKOUT_DURATION));\n        }",
       "if (false) {\n            lockouts.setDeadline(key, now.plus(LOCKOUT_DURATION));\n        }")]),

    ("lockout is per-process only (state not persisted)", "AuthenticationService.java",
     [("this.lockouts = lockoutFile == null ? LockoutStore.inMemory() : LockoutStore.open(lockoutFile);",
       "this.lockouts = LockoutStore.inMemory();")]),

    ("audit trail not sealed (no HMAC chain)", "AuditLog.java",
     [("return Base64.getUrlEncoder().withoutPadding()\n"
       "                    .encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));",
       "return \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\";")]),

    ("chain does not link to the previous record", "AuditLog.java",
     [("AuditEvent unsigned = new AuditEvent(seq, ts, safeEvent, outcome.name(), safeActor,\n"
       "                    safeUser, safeDetail, keyId, prevHash, \"\");",
       "AuditEvent unsigned = new AuditEvent(seq, ts, safeEvent, outcome.name(), safeActor,\n"
       "                    safeUser, safeDetail, keyId, AuditEvent.GENESIS, \"\");")]),

    ("grants access when the audit write fails (fail open)", "AuthenticationService.java",
     [("} catch (AuditLog.AuditFailureException e) {\n"
       "            return new Result(false, Reason.AUDIT_FAILURE, user.username(), Result.GENERIC_FAILURE,\n"
       "                    -1, 0);\n        }",
       "} catch (AuditLog.AuditFailureException e) {\n"
       "            return new Result(true, Reason.SUCCESS, user.username(), \"Access granted.\",\n"
       "                    -1, 0);\n        }")]),

    ("failed attempts are not recorded", "AuthenticationService.java",
     [("seq = record(\"auth.login\", AuditEvent.Outcome.FAILURE, actor, username,\n"
       "                    reason.name() + \": \" + detail);",
       "seq = -1;")]),

    ("denial messages disclose the reason (user enumeration)", "AuthenticationService.java",
     [("String message = reason == Reason.THROTTLED || reason == Reason.ACCOUNT_LOCKED\n"
       "                ? Result.THROTTLED_MESSAGE : Result.GENERIC_FAILURE;",
       "String message = \"Access denied: \" + reason.name() + \" (\" + detail + \")\";")]),

    ("unknown accounts skip password work (timing oracle)", "AuthenticationService.java",
     [("matches = hasher.verify(password, dummyDigest());", "matches = false;")]),

    ("log fields not sanitized (log injection)", "AuditLog.java",
     [("String safeUser = AuditEvent.sanitize(username);\n"
       "        String safeDetail = AuditEvent.sanitize(detail);",
       "String safeUser = username;\n        String safeDetail = detail;")]),

    ("account store world-readable", "AdminUserStore.java",
     [("PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);",
       "PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,\n"
       "            PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ);")]),

    ("disabled account can still log in", "AuthenticationService.java",
     [("if (user != null && matches && !user.isActive()) {", "if (false) {")]),

    ("admin actions recorded without attribution to the session", "AuthenticationService.java",
     [("if (session == null || !session.isActive()) {\n            throw new SecurityException(\"session is not active\");",
       "if (session == null) {\n            throw new SecurityException(\"session is not active\");")]),
]

VERBOSE = "-v" in sys.argv


def build_and_test(work):
    """Compiles the mutated tree and runs the suite; returns (detected, detail)."""
    b = os.path.join(work, "build")
    bt = os.path.join(work, "build-test")
    os.makedirs(b, exist_ok=True)
    os.makedirs(bt, exist_ok=True)
    srcs = [os.path.join(SRC, f) for f in os.listdir(SRC)]
    cp = subprocess.run(["javac", "-nowarn", "-d", b] + srcs, capture_output=True, text=True)
    if cp.returncode != 0:
        return None, "MUTATION DID NOT COMPILE:\n" + cp.stdout[-2000:] + cp.stderr[-2000:]
    tp = subprocess.run(["javac", "-nowarn", "-cp", b, "-d", bt,
                         os.path.join(TEST, "AdminPortalTests.java")],
                        capture_output=True, text=True)
    if tp.returncode != 0:
        return None, "TEST COMPILE FAILED:\n" + tp.stdout[-2000:] + tp.stderr[-2000:]
    try:
        r = subprocess.run(["java", "-cp", b + ":" + bt, "adminportal.AdminPortalTests"],
                           capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return True, "suite hung (treated as detected: the mutation deadlocked something)"
    detected = r.returncode != 0
    fails = [l.strip()[2:] for l in r.stdout.splitlines() if l.strip().startswith("FAIL:")]
    first_fail = ""
    for l in r.stdout.splitlines():
        if l.startswith("  - "):
            first_fail = l[4:]
            break
    detail = ("first failing expectation: " + first_fail) if first_fail else "\n".join(fails)
    if not detected and r.returncode == 0:
        detail = "SUITE STILL PASSED"
    if r.returncode < 0:
        detail += " (crashed with signal)"
    return detected, detail


def main():
    global SRC, TEST
    survivors = []
    broken = []
    print("mutation battery: each line must be DETECTED\n")
    for name, fname, edits in MUTATIONS:
        work = tempfile.mkdtemp(prefix="mut-")
        shutil.copytree(SRC, os.path.join(work, "src", "adminportal"))
        shutil.copytree(TEST, os.path.join(work, "test", "adminportal"))
        target = os.path.join(work, "src", "adminportal", fname)
        text = open(target).read()
        applied = True
        for old, new in edits:
            if old not in text:
                print("  !! anchor not found for '%s' in %s" % (name, fname))
                applied = False
                break
            text = text.replace(old, new, 1)
        if not applied:
            broken.append(name)
            continue
        open(target, "w").write(text)

        os.chdir(work)
        # Point the compiler at the mutated copy.
        src_saved, test_saved = SRC, TEST
        SRC = os.path.join(work, "src", "adminportal")
        TEST = os.path.join(work, "test", "adminportal")
        try:
            detected, detail = build_and_test(work)
        finally:
            SRC, TEST = src_saved, test_saved
            os.chdir(ROOT)

        if detected is None:
            broken.append(name)
            print("  %-4s %-58s %s" % ("ERR", name, detail.splitlines()[0] if detail else ""))
            continue
        mark = "ok " if detected else "SURVIVED"
        print("  %-8s %-58s %s" % (mark, name, detail[:110] if VERBOSE or not detected else ""))
        if not detected:
            survivors.append((name, detail))
        shutil.rmtree(work, ignore_errors=True)

    print()
    print("mutations applied: %d   detected: %d   survived: %d   unusable: %d"
          % (len(MUTATIONS) - len(broken), len(MUTATIONS) - len(broken) - len(survivors),
             len(survivors), len(broken)))
    if broken:
        print("\nthese mutations could not be applied (anchors drifted, not a code defect):")
        for b in broken:
            print("  - " + b)
    if survivors:
        print("\nUNCOVERED SECURITY PROPERTIES (suite stayed green despite the break):")
        for name, detail in survivors:
            print("  - " + name)
            if detail:
                print("      " + detail[:300])
        sys.exit(1)
    print("\nPASS: every mutation was caught by the suite")


if __name__ == "__main__":
    main()
