#!/usr/bin/env python3
"""Mutation battery: prove each security guard is actually load-bearing for a test.

A mutant is one small, semantically meaningful edit to a guard (drop a bound, invert a comparison,
delete a chmod, widen a pattern). For each one we compile a private copy of src/main, run the whole
security suite against it, and classify:

  KILL_ASSERT   the suite printed SUMMARY with failures > 0. This is the only kind of kill that
                means the test would have caught the regression.
  KILL_CRASH    the suite died before printing SUMMARY (exception escaped, JVM crashed). A crash
                shows something broke, but NOT that an assertion noticed - it is reported
                separately and is never counted as a kill.
  COMPILE_FAIL  the patch did not apply or the mutant did not compile. Almost always a stale
                  anchor string after a refactor, so it is reported loudly rather than skipped.
  SURVIVED      the suite went green with the guard weakened. This is a real finding: either the
                  guard is redundant (delete it) or untested (write the test).
  TIMEOUT       the mutant did not finish inside its budget.

Each mutant runs in its own JVM with its own scratch root, so a fixture left behind by one cannot
be mistaken for a failure of the next (the suite's own scratch dirs are pid-scoped, but the JVM
pid is reused across mutants otherwise and a leaked H2 file lock misattributes failures).

Usage:
  python3 tools/dev/mutate.py --dry-run          # anchors resolve, nothing executed
  python3 tools/dev/mutate.py --only 3,7,11      # subset by id
  python3 tools/dev/mutate.py                    # everything, serial
"""
import argparse
import concurrent.futures
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# tools/dev/mutate.py -> the repository root is two directories above tools/dev.
ROOT = Path(__file__).resolve().parents[2]
# Mutants are spelled by bare file name, so the source roots name the package directory itself.
PKG = "com/example/identity"
MAIN = ROOT / "src" / "main" / "java" / PKG
TESTS = ROOT / "src" / "test" / "java" / PKG
LIB = ROOT / "lib" / "h2-2.5.252.jar"
PASSPHRASE = "Test-only-database-passphrase-9f3c1a7e"

# (id, file, description, old, new, suite_expected_to_kill)
# Every `old` string must be unique in its file; --dry-run enforces that before anything is run,
# because an anchor that silently stops matching turns the whole battery into a green no-op.
MUTANTS = [
    ("M01", "Password.java", "drop the unpaired-surrogate rule (accept any unpaired surrogate)",
     "} else if (Character.isLowSurrogate(c)) {\n                return null; // unpaired low surrogate",
     "} else if (Character.isLowSurrogate(c)) {\n                cp++; i += 1; continue; // MUTANT",
     "password"),
    ("M02", "Password.java", "accept any NUL (drop the whole-buffer NUL scan)",
     "for (char c : chars) {\n            if (c == 0) {\n                return null;\n            }\n        }",
     "for (char c : chars) {\n            if (c == 1) {\n                return null;\n            }\n        }",
     "password"),
    ("M03", "Password.java", "raise the length ceiling so oversized input gets scanned",
     "if (chars.length > HARD_CAP_CP) {",
     "if (chars.length > HARD_CAP_CP * 1000) {",
     "password"),
    ("M04", "PasswordHasher.java", "compare digests with Arrays.equals instead of MessageDigest.isEqual",
     "MessageDigest.isEqual(",
     "java.util.Arrays.equals(",
     "password"),
    ("M05", "PasswordHasher.java", "ignore the stored iteration floor (a tampered row makes the KDF free)",
     "if (value > Integer.MAX_VALUE || (int) value < MIN_ACCEPTED_ITERATIONS) {",
     "if (value > Integer.MAX_VALUE) {",
     "password"),
    ("M06", "PasswordHasher.java", "skip the equal-work dummy on an undecodable stored credential",
     "            chargeDummy();\n            throw corruptOrAbsent;",
     "            /* MUTANT: the equal-work charge is skipped */\n            throw corruptOrAbsent;",
     "equalwork"),
    ("M07", "AuthApi.java", "never act on an active penalty (verify anyway)",
     "            if (sourceBlocked || accountBlocked) {",
     "            if (false && (sourceBlocked || accountBlocked)) {",
     "throttle"),
    ("M08", "AuthApi.java", "clear the source bucket on success too (one real credential empties it)",
     "            // thousand guesses.\n"
     "            store.clearBucket(SqlIdentityStore.bucketKindAccount(), identifier.canonical());",
     "            // thousand guesses.\n"
     "            store.clearBucket(SqlIdentityStore.bucketKindAccount(), identifier.canonical());\n"
     "            store.clearBucket(SqlIdentityStore.bucketKindSource(), source.canonical()); // MUTANT",
     "throttle"),
    ("M09", "SqlIdentityStore.java", "register without the serialisation row (allow a check-then-act race)",
     "SELECT k FROM meta WHERE k = ? FOR UPDATE",
     "SELECT k FROM meta WHERE k = ?",
     "storage"),
    ("M10", "SqlIdentityStore.java", "never count the live accounts (the cap stops being a cap)",
     "int liveAccounts = countAll(\"account\");",
     "int liveAccounts = 0;",
     "storage"),
    ("M11", "SqlIdentityStore.java", "register without charging either registration budget",
     "                chargeBudget(BUCKET_ID_GLOBAL_REGISTER, now, config.registerWindowSeconds());\n"
     "                chargeBudget(sourceBucket, now, config.registerWindowSeconds());",
     "                // MUTANT: neither registration budget is charged",
     "throttle"),
    ("M12", "SqlIdentityStore.java", "treat every SQLState as a duplicate key (mask storage failures)",
     "return state != null && state.startsWith(\"23\");",
     "return state != null;",
     "storage"),
    ("M13", "SqlIdentityStore.java", "let a stored row whose canonical email is not an address through",
     "        Identity email = Identity.fromStoredEmail(rs.getString(\"email_canon\"));\n"
     "        if (email == null) {",
     "        Identity email = Identity.fromStoredEmail(rs.getString(\"email_canon\"));\n"
     "        if (false && email == null) {",
     "storage"),
    ("M14", "SqlIdentityStore.java", "never enforce the per-account session cap",
     "                prune.executeUpdate();",
     "                // MUTANT: the per-account session cap is never applied",
     "storage"),
    ("M15", "AuditLog.java", "scrub only word-bounded key names (miss AUTH_DB_PASSWORD)",
     "[a-z0-9_-]*(?:password|passwd|passphrase|secret|token|apikey|api-key|api_key|authorization|cookie|credential)",
     "[a-z0-9]*(?:password|passwd|passphrase|secret|token|apikey|api-key|api_key|authorization|cookie|credential)",
     "audit"),
    ("M16", "AuditLog.java", "take an unquoted secret value only up to the next space",
     "(?:[^\\\\s,;{}\\\\r\\\\n][^\\\\r\\\\n]*)",
     "(?:[^\\\\s,;{}\\\\r\\\\n]+)",
     "audit"),
    ("M17", "AuditLog.java", "drop the 43-character token-shape rule",
     "Pattern.compile(\"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])\")",
     "Pattern.compile(\"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{44}(?![A-Za-z0-9_-])\")",
     "audit"),
    ("M18", "AuditLog.java", "swallow an unwritable audit log instead of failing closed",
     "        } catch (IOException e) {\n"
     "            throw new IdentityStoreException(Reason.AUDIT_FAILURE, \"cannot append to the audit log\", e);\n"
     "        }",
     "        } catch (IOException e) {\n"
     "            return; // MUTANT: the audit failure is swallowed\n"
     "        }",
     "audit"),
    ("M19", "AuditLog.java", "keep appending past the size cap (disk-exhaustion DoS)",
     "if (current + bytes.length > maxBytes) {",
     "if (false) {",
     "audit"),
    ("M20", "PosixFiles.java", "never compare the mode read back against the mode it claims to set",
     "        Set<PosixFilePermission> actual = actualPermissions(file);\n"
     "        if (!actual.equals(expected)) {",
     "        Set<PosixFilePermission> actual = actualPermissions(file);\n"
     "        if (false) {",
     "perms"),
    ("M21", "PosixFiles.java", "treat unreadable permission bits as proof the file is private",
     "static final boolean UNREADABLE_ATTRIBUTES_ARE_EXPOSED = true;",
     "static final boolean UNREADABLE_ATTRIBUTES_ARE_EXPOSED = false;",
     "perms"),
    ("M22", "Config.java", "accept a configured iteration count below the floor",
     "int minIterations = requiredInt(file, K_MIN_ITERATIONS, MIN_ITERATIONS_FLOOR, 20_000_000);",
     "int minIterations = requiredInt(file, K_MIN_ITERATIONS, 1, 20_000_000);",
     "config"),
    ("M23", "Config.java", "allow a passphrase shorter than 24 characters",
     "if (secret.length() < 24 || secret.length() > 512) {",
     "if (secret.length() < 1 || secret.length() > 512) {",
     "config"),
    ("M24", "Config.java", "never check the configuration file's own permissions",
     "PosixFiles.assertNoGroupOrOtherAccess(file, \"configuration file\");",
     "// MUTANT: whoever can read or write this file now picks the security parameters",
     "config"),
    ("M25", "SourceId.java", "strip control characters instead of refusing them",
     "        if (Identity.containsControlOrDel(s)) {\n            return null;\n        }",
     "        s = s.replaceAll(\"[\\\\x00-\\\\x20\\\\x7F]\", \"\"); // MUTANT\n"
     "        if (s.isEmpty()) {\n            return null;\n        }",
     "sourceid"),
    ("M26", "SessionToken.java", "derive tokens from a seeded java.util.Random",
     "        byte[] raw = new byte[TOKEN_BYTES];\n        random.nextBytes(raw);",
     "        byte[] raw = new byte[TOKEN_BYTES];\n"
     "        new java.util.Random(1700000000L).nextBytes(raw); // MUTANT",
     "session"),
    ("M27", "Identity.java", "print the value in toString (the audit log's only identifier channel)",
     "return kind + \"[len=\" + canonical.length() + \"]\";",
     "return kind + \"[len=\" + canonical.length() + \"]=\" + canonical;",
     "audit"),
    ("M28", "AuthApi.java", "return a distinct message for an unknown account",
     "                audit.append(Reason.ABSENT_ACCOUNT, identifier);\n"
     "                return AuthResult.of(Reason.BAD_CREDENTIAL);",
     "                audit.append(Reason.ABSENT_ACCOUNT, identifier);\n"
     "                return AuthResult.of(Reason.ABSENT_ACCOUNT); // MUTANT",
     "outcome"),
    # The floor on the *writing* key (security.pbkdf2Iterations) is deliberately not mutated: because
    # pbkdf2MinIterations is itself floored at the same constant, `iterations < FLOOR` always implies
    # `iterations < minIterations`, so no configuration can distinguish the two guards and no test
    # could ever be written for the redundant one. M22 probes the guard that is load-bearing.
    ("M29", "Config.java", "accept an inverted cost ordering (iterations below the accepted minimum)",
     "        if (iterations < minIterations) {",
     "        if (false) {",
     "config"),
    ("M30", "PosixFiles.java", "chmod through a symlink at a path we are securing",
     "        assertNotSymbolicLink(file, \"file\");\n        try {\n"
     "            Files.setPosixFilePermissions(file, PRIVATE_FILE);",
     "        try {\n            Files.setPosixFilePermissions(file, PRIVATE_FILE);",
     "perms"),
]


def log_tail(text: str, n: int = 12) -> str:
    lines = [l for l in text.splitlines() if l.strip()]
    return "\n".join(lines[-n:])


class Runner:
    def __init__(self, scratch: Path, timeout: int):
        self.scratch = scratch
        self.timeout = timeout
        self.lock = threading.Lock()

    def build(self, work: Path) -> tuple[bool, str]:
        srcs = [str(p) for p in sorted((work / "src").rglob("*.java"))]
        tsrcs = [str(p) for p in sorted((work / "tests").rglob("*.java"))]
        out = work / "out"
        tout = work / "test-out"
        out.mkdir()
        tout.mkdir()
        cp = str(LIB)
        r = subprocess.run(["javac", "-nowarn", "-encoding", "UTF-8", "--release", "17",
                            "-cp", cp, "-d", str(out)] + srcs,
                           capture_output=True, text=True, cwd=str(work))
        if r.returncode != 0:
            return False, "main compile failed:\n" + log_tail(r.stderr, 8)
        r = subprocess.run(["javac", "-nowarn", "-encoding", "UTF-8", "--release", "17",
                            "-cp", cp + ":" + str(out), "-d", str(tout)] + tsrcs,
                           capture_output=True, text=True, cwd=str(work))
        if r.returncode != 0:
            return False, "test compile failed:\n" + log_tail(r.stderr, 8)
        return True, ""

    def run_suite(self, work: Path, suite: str) -> tuple[str, str]:
        env = dict(os.environ)
        env["IDENTITY_DB_PASSWORD"] = PASSPHRASE
        envFile = self.scratch / ("mut-" + hashlib.md5(str(work).encode()).hexdigest()[:8])
        envFile.mkdir(parents=True, exist_ok=True)
        cmd = ["java", "-Xmx512m", "-Dfile.encoding=UTF-8",
               "-Dportal.repo=" + str(work),
               "-Dportal.src=" + str(work / "src"),
               "-Dportal.test.scratch=" + str(envFile),
               "-cp", str(LIB) + ":" + str(work / "out") + ":" + str(work / "test-out"),
               "com.example.identity.MainSuite", suite]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, env=env,
                               cwd=str(work), timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return "TIMEOUT", "timed out after %ss" % self.timeout
        out = r.stdout + r.stderr
        m = re.search(r"SUMMARY checks=(\d+) failures=(\d+)", out)
        if m is None:
            return "KILL_CRASH", log_tail(out, 10)
        if int(m.group(2)) > 0:
            fails = [l for l in out.splitlines() if l.strip().startswith("FAILED")]
            return "KILL_ASSERT", "; ".join(f.split("::", 1)[-1].strip() for f in fails[:4])
        return "SURVIVED", "checks=%s" % m.group(1)


def materialise(mid: str, mutant) -> tuple[Path, str]:
    """Copy the tree with the patch applied. Returns (workdir, error)."""
    _, rel, _, old, new, suite = mutant
    target = MAIN / rel
    text = target.read_text(encoding="utf-8")
    hits = text.count(old)
    if hits != 1:
        return None, ("anchor matched %d times (want exactly 1): %r in %s" % (hits, old[:60], rel))
    work = _sandbox(mid)
    (work / "src" / rel).write_text(text.replace(old, new), encoding="utf-8")
    return work, ""


def _sandbox(mid: str) -> Path:
    """
    A private copy of the tree that still looks like the repository to the suite.

    ``Harness`` locates production sources through ``-Dportal.src`` and repository artifacts through
    ``-Dportal.repo``, so the copy must carry the anchor files too - ``deps.lock`` (the root anchor)
    and ``identity.properties.example`` (whose mode and keys are asserted by two suites). Without
    them those checks silently degrade to "the file is missing" for every mutant.
    """
    work = Path(tempfile.mkdtemp(prefix="mut-" + mid + "-", dir=str(ROOT / ".mutation-work")))
    shutil.copytree(MAIN, work / "src")
    shutil.copytree(TESTS, work / "tests")
    for anchor in ("deps.lock", "identity.properties.example"):
        src = ROOT / anchor
        if src.is_file():
            shutil.copy2(src, work / anchor)
    return work


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--full-suite", action="store_true",
                    help="run every suite for each mutant instead of the expected one")
    args = ap.parse_args()

    (ROOT / ".mutation-work").mkdir(exist_ok=True)
    wanted = {s.strip() for s in args.only.split(",") if s.strip()}
    selected = [m for m in MUTANTS if not wanted or m[0] in wanted]

    print("mutation battery: %d mutant(s), jobs=%d" % (len(selected), args.jobs))
    bad = []
    for m in selected:
        _, rel, desc, old, _, suite = m
        text = (MAIN / rel).read_text(encoding="utf-8")
        hits = text.count(old)
        mark = "ok  " if hits == 1 else "BAD "
        if hits != 1:
            bad.append(m[0])
        print("  %s %s %-20s %-58s [%s]" % (mark, m[0], rel, desc[:58], suite))
    if args.dry_run:
        print("dry run: %d/%d anchors resolve" % (len(selected) - len(bad), len(selected)))
        return 1 if bad else 0
    if bad:
        print("refusing to run: %d anchor(s) do not resolve: %s" % (len(bad), ",".join(bad)))
        return 2

    scratch = Path(tempfile.mkdtemp(prefix="mut-scratch-", dir=str(ROOT / ".mutation-work")))
    runner = Runner(scratch, args.timeout)
    tally = {}
    started = time.time()

    def one(mutant):
        mid, rel, desc, old, new, suite = mutant
        text = (MAIN / rel).read_text(encoding="utf-8")
        work = _sandbox(mid)
        try:
            (work / "src" / rel).write_text(text.replace(old, new), encoding="utf-8")
            ok, why = runner.build(work)
            if not ok:
                return mid, desc, "COMPILE_FAIL", why
            target_suite = "" if args.full_suite else suite
            kind, detail = runner.run_suite(work, target_suite)
            return mid, desc, kind, detail
        finally:
            shutil.rmtree(work, ignore_errors=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futs = {pool.submit(one, m): m[0] for m in selected}
        for fut in concurrent.futures.as_completed(futs):
            mid, desc, kind, detail = fut.result()
            tally[kind] = tally.get(kind, 0) + 1
            print("[%3ds] %-5s %-58s %s" % (time.time() - started, mid + " " + kind, desc, detail))

    print("=" * 72)
    order = ["KILL_ASSERT", "SURVIVED", "KILL_CRASH", "COMPILE_FAIL", "TIMEOUT"]
    for k in order:
        if k in tally:
            print("%-12s %d" % (k, tally[k]))
    killed = tally.get("KILL_ASSERT", 0)
    scored = killed + tally.get("SURVIVED", 0)
    print("score (assertion kills / scored) = %d/%d" % (killed, scored))
    print("note: KILL_CRASH is NOT counted as a kill - a crash proves breakage, not a test.")
    shutil.rmtree(scratch, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
