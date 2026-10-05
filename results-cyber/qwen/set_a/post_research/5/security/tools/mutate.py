#!/usr/bin/env python3
"""Mutation battery for the security guards.

One mutant = one semantic weakening of one guard in src/main (the test tree is copied,
frozen, and verified byte-identical at the end, so a mutant can never be killed by its own
edited tests). Accounting rules, stated up front because they are the point:

  KILLED         a suite printed a FAIL line (or exited non-zero). The only real verdict.
  SURVIVED       every suite ran to its summary and was green. This is a finding, not a
                 script failure -- it names an assertion the suite is missing.
  COMPILE-FAIL   the mutant does not build. Reported, never counted as a kill.
  ANCHOR-ERROR   the anchor text does not occur exactly once. Reported, never skipped.
  HARNESS-ERROR  a suite died or timed out without printing its SUMMARY. Reported as a
                 harness problem and re-run alone, because blaming a timeout on the tests
                 would invent a kill.

Suites run in cost order (three fast ones, then the subprocess matrix and the real-KDF
timing suite) and the battery stops at the first kill for that mutant.

    ./tools/mutate.py                  run everything
    ./tools/mutate.py M04 M18          run the named mutants
    ./tools/mutate.py --dry-run        apply every edit + compile, run nothing
    ./tools/mutate.py --preflight      check anchors only (seconds)
    JOBS=1 MUT_TIMEOUT=1800 ./tools/mutate.py
"""
import concurrent.futures as cf
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / "src" / "main" / "java" / "com" / "portal" / "auth"
WORK = Path(os.environ.get("MUT_WORK", "/tmp/qmut"))
JDK = Path(os.environ.get("JAVA_HOME", "/root/tools/jdk-21.0.12.1+1"))
JAVAC, JAVA = str(JDK / "bin" / "javac"), str(JDK / "bin" / "java")
FAST = ["SourceRefSuite", "CoreSecuritySuite", "HttpSuite"]
SLOW = ["ConfigCliSuite", "AuthFlowSuite"]
JOBS = int(os.environ.get("JOBS", "2"))
SUITE_TIMEOUT = int(os.environ.get("MUT_TIMEOUT", "1800"))

# id, file, exact old text, replacement, what it weakens.
# "\n" below are real newlines (these are Python string literals, not a TSV).
MUTANTS = [
    ("M01", "Authenticator.java",
     "            hasher.burnOneDigest(password, INVALID_REF);\n"
     "            throttle.consumeSourceBudget(sourceHex);",
     "            hasher.burnOneDigest(password, INVALID_REF);\n"
     "            // mut: malformed username no longer charges the source",
     "a malformed username no longer charges the per-source budget"),
    ("M02", "Authenticator.java",
     "            hasher.verifyAgainstDecoy(password, accountRef);\n"
     "            // Counted exactly like a wrong password, so neither the counter behaviour nor",
     "            // mut: decoy work and the failure record removed\n"
     "            // Counted exactly like a wrong password, so neither the counter behaviour nor",
     "an unknown username is free and no longer costs the account a failure"),
    ("M03", "Authenticator.java",
     "out[i] = (char) (out[i] + 32);", "out[i] = (char) (out[i] - 32);",
     "the ASCII case fold runs the wrong way"),
    ("M04", "PasswordHasher.java",
     "return Crypto.equal(key, p.key);", "return key.length == p.key.length;",
     "verification ignores the derived key's content"),
    ("M05", "Crypto.java",
     "return MessageDigest.isEqual(a, b);", "return a.length == b.length;",
     "the constant-time comparison ignores content"),
    ("M06", "InputPolicy.java",
     "if (!isAlnum(c[0]) || !isAlnum(c[c.length - 1])) {", "if (!isAlnum(c[0])) {",
     "a username may end in '-' '.' '_'"),
    ("M07", "InputPolicy.java",
     "return !s.contains(\"..\");", "return true;",
     "the '..' username shape is accepted"),
    ("M08", "InputPolicy.java",
     "if (secret == null || secret.length < PASSWORD_MIN || secret.length > PASSWORD_MAX) {",
     "if (secret == null || secret.length < PASSWORD_MIN || secret.length >= PASSWORD_MAX) {",
     "a legal 128-character secret is refused (off-by-one at the ceiling)"),
    ("M09", "InputPolicy.java",
     "if (c < 0x21 || c > 0x7E) {", "if (c < 0x20 || c > 0x7E) {",
     "an interior space/tab/NUL becomes a legal password character"),
    ("M10", "ThrottleManager.java",
     "|| a.failures >= ACCOUNT_MAX_FAILURES", "|| a.failures > ACCOUNT_MAX_FAILURES",
     "the account budget is one too generous"),
    ("M11", "ThrottleManager.java",
     "            State a = live(accounts, requireRef(accountRef));\n"
     "            a.failures = 0;\n"
     "            a.blockedUntil = 0;\n            a.strikes = 0;",
     "            State a = live(accounts, requireRef(accountRef));\n"
     "            a.blockedUntil = 0;\n            a.strikes = 0;",
     "a correct password stops clearing the account's failure count"),
    ("M12", "Ledger.java",
     "Counter current = a.generation > b.generation ? a : b;",
     "Counter current = a.count > b.count ? a : b;",
     "the count merge goes monotonic again (the sixth correct login is denied)"),
    ("M13", "PortalConfig.java",
     "if (segment.toString().equals(\"..\")) {",
     "if (p.normalize().toString().contains(\"..\")) {",
     "the parent-reference guard becomes the vacuous pre-fix version"),
    ("M14", "PortalConfig.java",
     "        for (int i = 0; i < raw.length(); i++) {\n"
     "            if (raw.charAt(i) < '0' || raw.charAt(i) > '9') {\n"
     "                throw new IllegalStateException(\"config-value-invalid: \" + key);\n"
     "            }\n        }",
     "        // mut: grammar check removed, parseInt decides",
     "a config number may carry a '+' sign"),
    ("M15", "SourceRef.java",
     "        for (int i = 0; i < mask.length(); i++) {\n"
     "            if (mask.charAt(i) < '0' || mask.charAt(i) > '9') {\n"
     "                throw new IllegalArgumentException(\"cidr-prefix-form\");\n"
     "            }\n        }",
     "        // mut: grammar check removed, parseInt decides",
     "a trusted-proxy range may be written '/+8'"),
    ("M16", "PrivateFiles.java",
     'PosixFilePermissions.fromString("rw-------");',
     'PosixFilePermissions.fromString("rw-r-----");',
     "the roster, audit log and ledger become group-readable"),
    ("M17", "EmployeeStore.java",
     "wasDisabled[0] = PasswordHasher.DISABLED_RECORD.equals(onDisk.get(username));",
     "wasDisabled[0] = false;",
     "a password reset silently lifts a disable"),
    ("M18", "PortalCli.java",
     "            if (c == '\\r') {\n"
     "                int after = in.read();\n"
     "                if (after >= 0 && after != '\\n') {\n"
     "                    in.unread(after);\n                }\n                break;\n            }",
     "            if (c == '\\r') {\n                continue;\n            }",
     "CR is deleted instead of terminating the line (the identity-folding auth bypass)"),
    ("M19", "SessionManager.java",
     "Long until = pendingCsrf.remove(key);", "Long until = pendingCsrf.get(key);",
     "a CSRF token can be replayed"),
    ("M20", "PortalConfig.java",
     "if (!SourceRef.isLiteralIpv4(raw) && !SourceRef.isLiteralIpv6(raw)) {",
     "if (false) {",
     "the listen host may be a hostname (DNS at startup)"),
    ("M21", "Authenticator.java",
     "audit.event(\"login\", subjectRef, sourceHex, \"denied\", auditDetail(reason));\n"
     "        throttle.padToFloor(startedAt);",
     "audit.event(\"login\", subjectRef, sourceHex, \"denied\", auditDetail(reason));\n"
     "        // mut: refusal no longer padded",
     "refusals skip the latency floor, so timing separates the branches"),
    ("M22", "PortalServer.java",
     'h.add("Strict-Transport-Security: max-age=" + config.hstsMaxAgeSeconds());',
     "// mut: HSTS not sent",
     "the HSTS header is not sent"),
    ("M23", "Authenticator.java",
     "            // the cost distinguishes an unknown name from a known one.\n"
     "            throttle.recordFailure(accountRef, sourceHex);",
     "            // the cost distinguishes an unknown name from a known one.",
     "an unknown username stops spending the account budget (enumeration-by-counter)"),
    ("M24", "EmployeeStore.java",
     "        for (int attempt = 0; attempt < 400; attempt++) {",
     "        for (int attempt = 0; attempt < 1; attempt++) {",
     "a contended roster lock is refused instead of waited for (concurrent enrolment fails)"),
    ("M25", "EmployeeStore.java",
     "        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {\n"
     "            return Map.of();\n"
     "        }\n"
     "        return parse(PrivateFiles.readPrivateBounded(file, MAX_FILE_BYTES));",
     "        return records;",
     "the mutator edits its own stale copy again (the cross-process lost update)"),
    ("M26", "Authenticator.java",
     "        store.refreshIfChanged();\n\n"
     "        String sourceHex = SourceRef.normalizeForLedger(sourceLabel);",
     "        String sourceHex = SourceRef.normalizeForLedger(sourceLabel);",
     "a decision never adopts another process's roster change (stale revocation)"),
    ("M27", "EmployeeStore.java",
     "                records = Map.of();\n"
     "                audit.systemFailure(\"roster-refresh\", \"-\", \"-\", unusable);",
     "                audit.systemFailure(\"roster-refresh\", \"-\", \"-\", unusable);",
     "a roster that no longer parses keeps answering from the last known-good copy"),
    ("M28", "EmployeeStore.java",
     "            fingerprint = now;\n"
     "            try {\n"
     "                Map<String, String> reloaded = currentRosterOnDisk();",
     "            try {\n"
     "                Map<String, String> reloaded = currentRosterOnDisk();",
     "an unusable roster is re-parsed and re-logged on every login instead of once"),
    ("M29", "Crypto.java",
     "        if (!isAscii(a) || !isAscii(b)) {\n"
     "            return false;\n"
     "        }",
     "        // mut: non-ascii operands reach the encoder",
     "two different non-ascii tokens can compare equal once the charset folds them"),
    ("M30", "Crypto.java",
     "        return idRef(ascii.toCharArray());",
     "        return sha256Hex(ascii.getBytes(StandardCharsets.US_ASCII)).substring(0, 16);",
     "a name is folded onto another name's throttle bucket by a lossy charset"),
    # Deliberately no mutant for "HSTS omitted on some replies only". That was the real
    # defect here, and it was reachable because securityHeaders took a withHsts flag. The
    # flag is gone -- the builder takes no argument -- so the only one-line weakenings left
    # are "never send it" (M22) and "send a different max-age", both already covered. The
    # asymmetry cannot be reintroduced without editing every call site, which is the point.
]

print_lock = threading.Lock()


def log(msg):
    with print_lock:
        print(msg, flush=True)


def shell(cmd, cwd=None, env=None, timeout=None):
    return subprocess.run(cmd, shell=isinstance(cmd, str), cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout)


def sources(path):
    java = [str(p) for p in sorted(Path(path).rglob("*.java"))]
    return java


def compile_dir(javac_args, timeout=600):
    return shell(javac_args, timeout=timeout)


def apply_mutant(wd, mid, rel, old, new):
    """Return (ok, detail). Copies the tree, then edits only src/main."""
    src = WORK / "main-freeze" / rel
    if not src.is_file():
        return False, "no such file " + rel
    text = src.read_text(encoding="utf-8")
    n = text.count(old)
    if n != 1:
        return False, "anchor matched %d times" % n
    target = wd / "src" / "main" / "java" / "com" / "portal" / "auth" / rel
    patched = text.replace(old, new)
    if patched == text:
        return False, "replacement is identical to the anchor"
    target.write_text(patched, encoding="utf-8")
    return True, "applied"


def prepare(mid, rel, old, new):
    wd = WORK / ("wd-" + mid)
    if wd.exists():
        shutil.rmtree(wd)
    # main-freeze mirrors the package directory, so it lands on the package path, not on
    # src/main. Copying it onto src/main silently produces a tree javac would reject.
    pkg = wd / "src" / "main" / "java" / "com" / "portal" / "auth"
    pkg.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(WORK / "main-freeze", pkg)
    shutil.copytree(WORK / "test-freeze", wd / "src" / "test")
    ok, detail = apply_mutant(wd, mid, rel, old, new)
    return wd, ok, detail


def build(wd):
    out_main, out_test = wd / "out" / "main", wd / "out" / "test"
    r = shell([JAVAC, "-encoding", "US-ASCII", "-Xlint:all", "-Werror", "-parameters",
               "-d", str(out_main)] + sources(wd / "src" / "main" / "java"), timeout=900)
    if r.returncode != 0:
        return False, "main: " + r.stdout.decode("utf-8", "replace")[-900:]
    r = shell([JAVAC, "-encoding", "US-ASCII", "-Xlint:all", "-Werror", "-parameters",
               "-cp", str(out_main), "-d", str(out_test)]
              + sources(wd / "src" / "test" / "java"), timeout=900)
    if r.returncode != 0:
        return False, "test: " + r.stdout.decode("utf-8", "replace")[-900:]
    return True, ""


def run_suite(wd, suite):
    env = dict(os.environ)
    env["JAVA_HOME"] = str(JDK)
    env["TMPDIR"] = str(wd / "tmp")
    (wd / "tmp").mkdir(exist_ok=True)
    # portal.src.main must point at THIS mutant's sources: several guards assert on the
    # shape of the production source text ("no branch trims a credential"), and pointing
    # them at the pristine tree would let a source-visible mutant survive on a technicality.
    try:
        r = shell([JAVA, "-cp", "out/test:out/main",
                   "-Dportal.src.main=" + str(wd / "src" / "main" / "java"),
                   "-Djava.awt.headless=true", "-Djava.io.tmpdir=" + str(wd / "tmp"),
                   "com.portal.auth." + suite],
                  cwd=str(wd), env=env, timeout=SUITE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return suite, "timeout", ""
    out = r.stdout.decode("utf-8", "replace")
    if "SUMMARY" not in out:
        return suite, "no-summary", out[-600:]
    fails = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
    if fails or r.returncode != 0:
        return suite, "killed", "\n".join(fails[:4]) or ("exit=%d" % r.returncode)
    return suite, "green", ""


def tidy(mid):
    """Remove scratch a mutant leaves in a SYSTEM path.

    M13 restores the vacuous '..' guard, which really does let PORTAL_DATA_DIR=/tmp/../etc/
    portal-x through, so running that mutant creates a root-owned /etc/portal-x. The tests no
    longer care (they diff the directory's own contents), but leaving it behind makes the
    machine differ depending on whether the battery was run. rmdir only ever removes an empty
    directory, so this can never delete anything a user put there.
    """
    if mid != "M13":
        return
    try:
        os.rmdir("/etc/portal-x")
        log("M13    removed the empty /etc/portal-x the mutant created")
    except OSError as stillPopulated:
        pass


def one(m):
    try:
        return run_mutant(m)
    finally:
        tidy(m[0])


def run_mutant(m):
    mid, rel, old, new, note = m
    res = WORK / "results"
    res.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    wd, ok, detail = prepare(mid, rel, old, new)
    if not ok:
        log("%-5s ANCHOR-ERROR %s" % (mid, detail))
        write(res, mid, "ANCHOR-ERROR", detail, note)
        return mid, "ANCHOR-ERROR"
    if DRY:
        good, err = build(wd)
        verdict = "DRY-OK" if good else "COMPILE-FAIL"
        log("%-5s %-12s %s" % (mid, verdict, "" if good else err[:200]))
        write(res, mid, verdict, err[:400], note)
        shutil.rmtree(wd, ignore_errors=True)
        return mid, verdict
    good, err = build(wd)
    if not good:
        log("%-5s COMPILE-FAIL %s" % (mid, err[:160]))
        write(res, mid, "COMPILE-FAIL", err[:600], note)
        shutil.rmtree(wd, ignore_errors=True)
        return mid, "COMPILE-FAIL"
    for suite in FAST + SLOW:
        name, state, blob = run_suite(wd, suite)
        if state == "killed":
            secs = int(time.time() - t0)
            log("%-5s KILLED by %-16s %3ds  %s" % (mid, name, secs, blob.replace("\n", " | ")[:150]))
            write(res, mid, "KILLED", "by %s: %s" % (name, blob.replace("\n", " | ")), note)
            shutil.rmtree(wd, ignore_errors=True)
            return mid, "KILLED"
        if state in ("timeout", "no-summary"):
            secs = int(time.time() - t0)
            log("%-5s HARNESS-ERROR at %-16s %3ds (%s)" % (mid, name, secs, state))
            write(res, mid, "HARNESS-ERROR", "%s: %s" % (name, blob[-300:]), note)
            shutil.rmtree(wd, ignore_errors=True)
            return mid, "HARNESS-ERROR"
    secs = int(time.time() - t0)
    log("%-5s SURVIVED (%3ds) -- %s" % (mid, secs, note))
    write(res, mid, "SURVIVED", "all suites green", note)
    shutil.rmtree(wd, ignore_errors=True)
    return mid, "SURVIVED"


def write(res, mid, verdict, detail, note):
    (res / (mid + ".txt")).write_text(
        "%s %s\nnote: %s\ndetail: %s\n" % (mid, verdict, note, detail), encoding="utf-8")


def baseline(work):
    """Run the fast tier against the UNMUTATED tree and refuse to continue if it is red.

    Every verdict in this battery is "a suite printed FAIL". If the suites are already red
    before any mutant is applied, every mutant is reported KILLED by whatever was already
    broken, and 25/25 looks like a strong result while proving nothing. That happened: the
    roster grew a lock file, two litter-count checks in CoreSecuritySuite went red, and the
    whole battery died on those two lines. So the honest prerequisite for a kill is a green
    baseline, checked here rather than assumed.
    """
    out = work / "out"
    if out.exists():
        shutil.rmtree(out)
    (out / "main").parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(WORK / "main-freeze", out / "main-src")
    shutil.copytree(WORK / "test-freeze", out / "test-src")
    r = shell([JAVAC, "-encoding", "US-ASCII", "-Xlint:all", "-Werror", "-parameters",
               "-d", str(out / "main")] + sources(out / "main-src"), timeout=900)
    if r.returncode != 0:
        return False, "pristine main does not build:\n" + r.stdout.decode("utf-8", "replace")[-900:]
    r = shell([JAVAC, "-encoding", "US-ASCII", "-Xlint:all", "-Werror", "-parameters",
               "-cp", str(out / "main"), "-d", str(out / "test")]
              + sources(out / "test-src" / "java"), timeout=900)
    if r.returncode != 0:
        return False, "pristine test tree does not build:\n" + r.stdout.decode("utf-8", "replace")[-900:]
    shutil.rmtree(out / "main-src")
    shutil.rmtree(out / "test-src")
    fake = work / "baseline"
    fake.mkdir(exist_ok=True)
    (fake / "src").symlink_to(ROOT / "src")
    (fake / "out").symlink_to(out)
    for suite in FAST:
        name, state, blob = run_suite(fake, suite)
        if state != "green":
            detail = "pristine %s is not green (%s)" % (suite, state)
            return False, detail + ("\n" + blob if blob else "")
    return True, ""


def main():
    global DRY
    args = [a for a in sys.argv[1:]]
    DRY = "--dry-run" in args
    preflight = "--preflight" in args
    args = [a for a in args if not a.startswith("--")]
    selected = [m for m in MUTANTS if not args or m[0] in args]
    if not selected:
        print("no mutant matched", args)
        return 1

    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    # Both trees are snapshotted once, here, and every mutant -- and the baseline -- is built
    # from the snapshot. Building src/main per mutant from the working tree while the tests
    # were frozen at launch desynchronises them: several guards assert on the text of the
    # production source, so editing a source after launch gives later mutants the new source
    # against the old guard and reports a false kill. (Measured: rewriting the response header
    # builder mid-run made four unrelated mutants "KILLED" by a stale count of its call sites.)
    shutil.copytree(ROOT / "src" / "test", WORK / "test-freeze")
    shutil.copytree(ROOT / "src" / "main" / "java" / "com" / "portal" / "auth",
                    WORK / "main-freeze")

    if preflight:
        bad = 0
        for m in selected:
            src = WORK / "main-freeze" / m[1]
            n = src.read_text(encoding="utf-8").count(m[2]) if src.is_file() else -1
            flag = "ok" if n == 1 else "BAD"
            bad += 0 if n == 1 else 1
            print("%-5s anchor-count=%-3d %s  %s" % (m[0], n, flag, m[4]))
        print("preflight: %d/%d anchors unique" % (len(selected) - bad, len(selected)))
        return 1 if bad else 0

    okb, why = baseline(WORK)
    if not okb:
        print("BASELINE-FAIL -- refusing to run, because every KILLED below would be "
              "attributed to whatever is already broken:\n" + why)
        return 2
    print("baseline: pristine fast tier is green")
    shutil.rmtree(WORK / "baseline", ignore_errors=True)

    print("mutants=%d jobs=%d fast=%ds-tier slow=%ds-tier" % (
        len(selected), JOBS, 15, 220))
    with cf.ThreadPoolExecutor(max_workers=JOBS) as pool:
        results = list(pool.map(one, selected))

    tally = {}
    for _, v in results:
        tally[v] = tally.get(v, 0) + 1
    print("\n=== verdicts ===")
    for mid, v in sorted(results):
        print("  %-5s %s" % (mid, v))
    print("=== totals ===")
    for k in sorted(tally, key=lambda x: -tally[x]):
        print("  %-14s %d" % (k, tally[k]))
    print("=== trees ===")
    for label, live, frozen in (("src/test", ROOT / "src" / "test", WORK / "test-freeze"),
                                ("src/main", ROOT / "src" / "main" / "java" / "com" / "portal"
                                 / "auth", WORK / "main-freeze")):
        diff = subprocess.run(["diff", "-r", str(live), str(frozen)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print("  %s identical to the frozen copy" % label if diff.returncode == 0 else
              "  WARNING %s changed while the battery ran -- the verdicts above mixed two "
              "revisions:\n%s" % (label, diff.stdout.decode("utf-8", "replace")[:800]))
    survivors = [m for m in results if m[1] == "SURVIVED"]
    if survivors:
        print("\nSurviving mutants (each is a missing assertion):")
        for mid, _ in survivors:
            print("  " + (WORK / "results" / (mid + ".txt")).read_text(encoding="utf-8").strip())
    return 0


DRY = False
if __name__ == "__main__":
    sys.exit(main())
