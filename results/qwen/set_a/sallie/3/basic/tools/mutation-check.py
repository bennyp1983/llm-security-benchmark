#!/usr/bin/env python3
"""
Mutation check for the sign-in program.

Each entry below is a deliberate defect injected into src/AuthenticationApp.java. A defect is
"killed" when the test suite in test/AuthenticationAppTests.java fails because of it. A defect that
the suite does not notice (status SURVIVED) means the suite is not really checking that behaviour,
even if every one of its 179 checks passes.

    ./tools/mutation-check.py            # needs a JDK and H2_JAR (default /tmp/h2/h2.jar)

Statuses that are not KILLED are all actionable:
  SURVIVED      the suite is blind here - add a check
  NOT-APPLIED   the anchor text no longer matches the source - fix the entry
  COMPILE-FAIL  the injected defect does not compile - fix the entry
"""
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "AuthenticationApp.java")
TEST = os.path.join(ROOT, "test", "AuthenticationAppTests.java")
H2 = os.environ.get("H2_JAR", "/tmp/h2/h2.jar")

MUTANTS = [
    ("M01-sql-upper-case",
     "compare with UPPER(email) = UPPER(?)",
     "WHERE email = ?",
     "WHERE UPPER(email) = UPPER(?)"),
    ("M02-sql-like",
     "compare with LIKE instead of =",
     "WHERE email = ?",
     "WHERE email LIKE ?"),
    ("M03-sql-concatenated",
     "paste the address into the SELECT text instead of binding it",
     'String sql = "SELECT password_hash FROM " + TABLE + " WHERE email = ?";',
     'String sql = "SELECT password_hash FROM " + TABLE + " WHERE email = \''
     + '" + normalizedEmail + "\'";'),
    ("M04-insert-concatenated",
     "paste the stored hash into the INSERT text instead of binding it",
     'String sql = "INSERT INTO " + TABLE + " (email, password_hash) VALUES (?, ?)";',
     'String sql = "INSERT INTO " + TABLE + " (email, password_hash) VALUES (?, \''
     + '" + hash + "\')";'),
    ("M05-no-duplicate-guard",
     "silently use the first row when the table holds two for one address",
     'throw new SQLException("the table holds more than one row for one email address");',
     'return hash;'),
    ("M06-no-lower-casing",
     "stop folding the address to lower case",
     "String lowered = trimmed.toLowerCase(Locale.ROOT);",
     "String lowered = trimmed;"),
    ("M07-no-trim",
     "stop removing surrounding spaces",
     "String trimmed = email.trim();",
     "String trimmed = email;"),
    ("M08-no-equal-work",
     "answer immediately when no account matches the address",
     "params = EqualWork.PARAMS;",
     "return false;"),
    ("M09-length-only-compare",
     "compare only the length of the derived hash",
     "return MessageDigest.isEqual(candidate, params.expectedHash);",
     "return candidate.length == params.expectedHash.length;"),
    ("M10-ignore-scheme-name",
     "accept a stored value whatever its named algorithm",
     "if (parts.length != 4 || !SCHEME.equals(parts[0])) {",
     "if (parts.length != 4) {"),
    ("M11-cost-floor-off",
     "drop the floor on the stored cost",
     "private static final int MIN_ITERATIONS = 1_000;",
     "private static final int MIN_ITERATIONS = 1;"),
    ("M12-hash-length-unchecked",
     "accept a stored hash of any length",
     "if (salt.length < 8 || salt.length > 64 || expectedHash.length != HASH_BYTES) {",
     "if (salt.length < 8 || salt.length > 64) {"),
    ("M13-no-input-validation",
     "accept any password without checking it",
     "        if (password == null || password.length == 0 || password.length > MAX_PASSWORD_CHARS) {\n"
     "            return false;\n"
     "        }\n"
     "        for (int i = 0; i < password.length; i++) {\n"
     "            char c = password[i];\n"
     "            if (c == 0) {\n"
     "                return false;\n"
     "            }\n"
     "            if (Character.isHighSurrogate(c)) {\n"
     "                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {\n"
     "                    return false;\n"
     "                }\n"
     "                // Consume the tail of the pair so it is not read as an unpaired surrogate.\n"
     "                i++;\n"
     "            } else if (Character.isLowSurrogate(c)) {\n"
     "                return false;\n"
     "            }\n"
     "        }\n"
     "        return true;",
     "        return true;"),
    ("M14-lone-low-surrogate-accepted",
     "forget the lone low surrogate guard",
     "            } else if (Character.isLowSurrogate(c)) {\n"
     "                return false;\n"
     "            }",
     "            }"),
    ("M15-database-error-is-success",
     "report a broken database as a signed-in session",
     'System.err.println("[auth] the account could not be looked up in the database");\n'
     "            return AuthResult.FAILURE;",
     'System.err.println("[auth] the account could not be looked up in the database");\n'
     "            return AuthResult.SUCCESS;"),
    ("M16-always-success",
     "let every password through",
     "return passwordMatches ? AuthResult.SUCCESS : AuthResult.FAILURE;",
     "return AuthResult.SUCCESS;"),
    ("M17-swapped-messages",
     "print the success line for a refusal",
     'case SUCCESS:\n                System.out.println("Authentication successful.");\n                return 0;',
     'case SUCCESS:\n                System.out.println("Authentication unsuccessful.");\n                return 0;'),
    ("M18-refusal-exits-zero",
     "exit 0 for a refused sign-in",
     '            default:\n                System.out.println("Authentication unsuccessful.");\n'
     "                return 1;",
     '            default:\n                System.out.println("Authentication unsuccessful.");\n'
     "                return 0;"),
    ("M19-stores-the-password",
     "store the password as text instead of a hash",
     "String hash = PasswordHasher.hash(password);",
     'String hash = "plain:" + new String(password);'),
    ("M20-fixed-salt",
     "reuse one salt for every stored password",
     "byte[] salt = new byte[SALT_BYTES];\n        RANDOM.nextBytes(salt);",
     "byte[] salt = new byte[SALT_BYTES];"),
    ("M21-cheap-cost",
     "drop the cost to 10 rounds",
     "private static final int ITERATIONS = 120_000;",
     "private static final int ITERATIONS = 10;"),
    ("M22-no-local-part-limit",
     "accept an over-long local part",
     "        if (lowered.indexOf('@') > MAX_LOCAL_PART_CHARS) {\n"
     "            return null;\n"
     "        }\n",
     ""),
]


def run(mutant):
    name, description, old, new = mutant
    work = tempfile.mkdtemp(prefix="mut-")
    try:
        with open(SRC, encoding="utf-8") as handle:
            source = handle.read()
        count = source.count(old)
        if count != 1:
            return (name, description, "NOT-APPLIED", ["anchor found %d times" % count])
        mutated = source.replace(old, new, 1)
        src_dir = os.path.join(work, "src")
        test_dir = os.path.join(work, "test")
        out_dir = os.path.join(work, "out")
        for directory in (src_dir, test_dir, out_dir):
            os.makedirs(directory)
        with open(os.path.join(src_dir, "AuthenticationApp.java"), "w", encoding="utf-8") as handle:
            handle.write(mutated)
        shutil.copy(TEST, os.path.join(test_dir, "AuthenticationAppTests.java"))

        compile_app = subprocess.run(["javac", "-nowarn", "-d", out_dir,
                                      os.path.join(src_dir, "AuthenticationApp.java")],
                                     capture_output=True, text=True)
        if compile_app.returncode != 0:
            return (name, description, "COMPILE-FAIL",
                    [line for line in compile_app.stderr.splitlines() if "error" in line][:3])
        compile_tests = subprocess.run(["javac", "-nowarn", "-cp", out_dir + ":" + H2, "-d", out_dir,
                                        os.path.join(test_dir, "AuthenticationAppTests.java")],
                                       capture_output=True, text=True)
        if compile_tests.returncode != 0:
            return (name, description, "COMPILE-FAIL",
                    [line for line in compile_tests.stderr.splitlines() if "error" in line][:3])

        suite = subprocess.run(["java", "-Dtest.classes=" + out_dir, "-Dh2.jar=" + H2,
                                "-cp", out_dir + ":" + H2, "AuthenticationAppTests"],
                               capture_output=True, text=True, cwd=work)
        failures = [line.strip() for line in suite.stdout.splitlines() if line.startswith("  FAIL:")]
        if not failures and suite.returncode != 0:
            tail = [line for line in suite.stderr.splitlines() if line.strip()][-1:]
            failures = ["suite died instead of asserting: " + (tail[0] if tail else "no stderr")]
        if suite.returncode == 0:
            return (name, description, "SURVIVED", [])
        return (name, description, "KILLED", failures[:4])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    if not os.path.isfile(H2):
        print("H2 driver not found at %s - set H2_JAR." % H2, file=sys.stderr)
        return 3
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for result in pool.map(run, MUTANTS):
            results.append(result)
            print("%-32s %-13s %s" % (result[0], result[2], result[1]), flush=True)
            for reason in result[3]:
                print("      %s" % reason, flush=True)

    killed = [r for r in results if r[2] == "KILLED"]
    problems = [r for r in results if r[2] != "KILLED"]
    print()
    print("mutants: %d, killed: %d, problems: %d" % (len(results), len(killed), len(problems)))
    for name, description, status, reasons in problems:
        print("  %s %s: %s" % (status, name, description))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
