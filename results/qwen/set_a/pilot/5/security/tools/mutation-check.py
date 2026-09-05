"""Re-run the verification suite against deliberately broken copies of the module.

A green suite only means something if breaking the thing under test turns it red. Each entry below
makes one security-relevant change, rebuilds a throwaway copy of the tree, and reports whether the
suite noticed. Anything reported UNDETECTED is a hole in the suite, not in the module.

    python3 tools/mutation-check.py

Takes a few minutes: every mutant is a fresh `javac` of the whole tree plus a suite run, and the
timing mutant runs 18 key derivations.

Two caveats, both learned the hard way:
  * The copy is a snapshot. Do not edit src/ while this runs, or a mutant compiles against a
    half-written file and reports a build failure that looks like a coverage gap.
  * A mutant that survives is usually a weak mutant rather than a weak test. Break the value, not
    just its wiring, and prefer same-length fixtures so file length cannot carry the property.
"""
import os
import shutil
import subprocess
import tempfile

SEC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MUTS = {
    "MUT1 drop the pre-hash lock gate": [("main/java/com/portal/auth/AuthenticationService.java",
                                          "if (before.locked()) {", "if (false) {")],
    "MUT2 let logged failures extend an active lock": [("main/java/com/portal/auth/LoginAttemptTracker.java",
                                                        "if (counter.lockedUntil != null"
                                                        " && now.isBefore(counter.lockedUntil)) {",
                                                        "if (false) {")],
    "MUT3 disable the lockout threshold": [("main/java/com/portal/auth/LoginAttemptTracker.java",
                                            "if (counter.failures >= policy.maxFailedAttempts()) {",
                                            "if (false) {")],
    "MUT4 no decoy hash for unknown usernames": [("main/java/com/portal/auth/AuthenticationService.java",
                                                  "            hasher.burnEquivalentWork(password);\n"
                                                  "            LoginAttemptTracker.AttemptState after ="
                                                  " tracker.registerFailure(name);",
                                                  "            LoginAttemptTracker.AttemptState after ="
                                                  " tracker.registerFailure(name);")],
    "MUT5 audit records the candidate password": [("main/java/com/portal/auth/AuthenticationService.java",
                                                   '"failures=" + after.failedAttempts() + " of "'
                                                   ' + policy().maxFailedAttempts()));',
                                                   '"password=" + new String(password)'
                                                   ' + " failures=" + after.failedAttempts()));')],
    "MUT6 failure wording depends on account existence": [("main/java/com/portal/auth/LoginResult.java",
                                                           "return GENERIC_FAILURE_MESSAGE;",
                                                           'return accountExists'
                                                           ' ? "Password incorrect for this account."'
                                                           ' : GENERIC_FAILURE_MESSAGE;')],
    "MUT7 countdown printed only for accounts that exist": [("main/java/com/portal/auth/PortalAuthApp.java",
                                                             "if (result instanceof"
                                                             " LoginResult.InvalidCredentials invalid"
                                                             " && invalid.attemptsRemaining() > 0) {",
                                                             "if (result instanceof"
                                                             " LoginResult.InvalidCredentials invalid"
                                                             " && invalid.accountExists()"
                                                             " && invalid.attemptsRemaining() > 0) {")],
}

undetected = 0

work = tempfile.mkdtemp(prefix="auth-mutation-")
try:
    for name, edits in MUTS.items():
        src = os.path.join(work, "src")
        build = os.path.join(work, "b")
        shutil.rmtree(src, ignore_errors=True)
        shutil.rmtree(build, ignore_errors=True)
        shutil.copytree(os.path.join(SEC, "src"), src)

        applied = True
        for rel, old, new in edits:
            path = os.path.join(src, rel)
            text = open(path, encoding="utf-8").read()
            if old not in text:
                print(name + ": ANCHOR MISSING (the code moved; update this script)", flush=True)
                applied = False
                break
            open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
        if not applied:
            undetected += 1
            continue

        os.makedirs(build, exist_ok=True)
        compiled = subprocess.run(
            "javac -d %s $(find %s/src/main/java -name '*.java')"
            " && javac -cp %s -d %s $(find %s/src/test/java -name '*.java')"
            % (build, work, build, build, work),
            shell=True, capture_output=True, text=True)
        if compiled.returncode:
            print(name + ": COMPILE FAILED (weak mutant, not a suite gap)\n"
                  + compiled.stderr[:300], flush=True)
            continue

        run = subprocess.run("java -cp %s com.portal.auth.AuthVerification" % build,
                             shell=True, capture_output=True, text=True)
        fails = [line for line in run.stdout.splitlines() if line.startswith("FAIL ")]
        if run.returncode == 0:
            undetected += 1
            print("%s: UNDETECTED" % name, flush=True)
        else:
            print("%s: caught by %d check(s)" % (name, len(fails)), flush=True)
        for failure in fails[:3]:
            print("    " + failure[5:100], flush=True)
finally:
    shutil.rmtree(work, ignore_errors=True)

print()
print("surviving mutants: %d" % undetected)
raise SystemExit(1 if undetected else 0)
