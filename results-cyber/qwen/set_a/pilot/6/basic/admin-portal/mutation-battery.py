#!/usr/bin/env python3
"""Mutation battery for the administrator portal.

A green test suite only means something if it goes red when the control it claims to test
is removed. This script copies the source tree, weakens one control at a time, rebuilds,
and requires the verification suite to FAIL. A mutation that the suite does not catch is
reported as a survivor and exits non-zero.

Run:  python3 mutation-battery.py
"""

import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")

# (id, human description, list of (relative source file, locator, replacement kind, payload))
MUTATIONS = [
    (
        "verify-prefix-compare",
        "password check compares only the first 4 digest bytes",
        [("portal/security/PasswordHasher.java", "replace",
          ("return MessageDigest.isEqual(stored.digest, digest);",
           "return java.util.Arrays.equals(java.util.Arrays.copyOf(stored.digest, 4),\n"
           "                        java.util.Arrays.copyOf(digest, 4));"))],
    ),
    (
        "no-burn-on-unknown-user",
        "unknown usernames skip the key derivation (timing reveals which names exist)",
        [("portal/security/PasswordHasher.java", "noop", None)],
    ),
    (
        "lock-message-leak",
        "a locked account tells the caller the account is locked",
        [("portal/admin/AuthenticationService.java", "replace",
          ("AuthResult.retryLater(AuthResult.Status.LOCKED, AuthResult.GENERIC_FAILURE, wait)",
           "AuthResult.retryLater(AuthResult.Status.LOCKED,\n"
           "                        \"Account \" + name + \" is temporarily locked.\", wait)"))],
    ),
    (
        "disabled-bypass",
        "the disabled-account check is skipped",
        [("portal/admin/AuthenticationService.java", "replace",
          ("if (account.state() == AccountState.DISABLED) {", "if (false) {"))],
    ),
    (
        "no-throttle",
        "the global failure window never throttles",
        [("portal/admin/AuthenticationService.java", "replace",
          ("return recentFailures.size() >= config.globalThrottleThreshold();", "return false;"))],
    ),
    (
        "fail-open-empty-store",
        "an unprovisioned store hands out a SUPER_ADMIN session",
        # Replaces the refusal itself (not the line before it), so the mutant compiles and
        # the assertion is what catches it.
        [("portal/admin/AuthenticationService.java", "replace",
          ('return AuthResult.of(AuthResult.Status.NOT_CONFIGURED,\n'
           '                    "No administrator accounts are configured yet. Run with --bootstrap-first-admin to create one.");',
           'return AuthResult.success(new AdminPrincipal(username.trim(), AdminRole.SUPER_ADMIN));'))],
    ),
    (
        "no-lockout",
        "failed attempts never lock an account",
        [("portal/admin/AuthenticationService.java", "replace",
          ("if (failures >= config.maxFailedAttempts()) {", "if (failures >= Integer.MAX_VALUE) {"))],
    ),
    (
        "audit-records-password",
        "the audit trail records the typed password",
        [("portal/admin/AuthenticationService.java", "replace",
          ('"bad credentials (" + failures + "/" + config.maxFailedAttempts() + ")");',
           '"bad credentials (" + failures + "/" + config.maxFailedAttempts() + ") typed=" + new String(password));',))],
    ),
    (
        "world-readable-store",
        "the credential file is written world-readable",
        # Files.createTempFile already yields 0600, so skipping the restrict call is
        # invisible. Relax the destination instead, which is the failure the code exists to
        # prevent (an operator making the store group-readable, say).
        [("portal/admin/CredentialStore.java", "replace",
          ("        restrictToOwner(file);",
           "        try { java.nio.file.Files.setPosixFilePermissions(file, java.util.EnumSet.allOf("
           "                java.nio.file.attribute.PosixFilePermission.class)); }"
           " catch (Exception ignored) { }"))],
    ),
    (
        "username-not-encoded",
        "usernames are stored raw, so record separators can be injected",
        [("portal/admin/CredentialStore.java", "replace",
          ("enc(account.username()),", "account.username(),"))],
    ),
    (
        "lenient-base64",
        "non-canonical base64 digests are accepted (digest malleability)",
        [("portal/security/PasswordHasher.java", "replace",
          ("if (!encoder.encodeToString(salt).equals(parts[2]) || !encoder.encodeToString(digest).equals(parts[3])) {",
           "if (false) {"))],
    ),
    (
        "gate-skips-rbac",
        "the gate no longer checks the role's permissions",
        [("portal/admin/AdminGate.java", "replace",
          ("if (!principal.get().can(permission)) {", "if (false) {"))],
    ),
    (
        "revoke-is-a-noop",
        "sign-out reports success but leaves the bearer token usable",
        [("portal/admin/SessionManager.java", "replace",
          ("AdminSession session = byTokenHash.remove(hashToken(presentedToken));",
           "AdminSession session = byTokenHash.get(hashToken(presentedToken));")),
         ("portal/admin/SessionManager.java", "replace",
          ('        session.revoke("signed out");', "        // revocation dropped"))],
    ),
    (
        "no-idle-expiry",
        "validate() ignores the idle deadline",
        [("portal/admin/SessionManager.java", "replace",
          ("if (session.expiresAtMillis() <= now) {", "if (false) {"))],
    ),
    (
        "no-absolute-expiry",
        "activity can extend a session past its absolute lifetime",
        [("portal/admin/SessionManager.java", "replace",
          ("if (session.absoluteDeadlineMillis() <= now) {", "if (false) {")),
         ("portal/admin/AdminSession.java", "replace",
          ("this.expiresAtMillis = Math.min(newExpiryMillis, this.absoluteDeadlineMillis);",
           "this.expiresAtMillis = newExpiryMillis;"))],
    ),
    (
        "no-session-cap",
        "live sessions are no longer capped per administrator",
        [("portal/admin/SessionManager.java", "replace",
          ("int excess = existing.size() - config.maxSessionsPerUser() + 1;", "int excess = 0;"))],
    ),
    (
        "deterministic-token",
        "session tokens are derived from the username instead of the CSPRNG",
        [("portal/admin/SessionManager.java", "replace",
          ("String tokenId = tokens.base64Url(32);",
           "String tokenId = AdminSession.sha256(principal.username());"))],
    ),
    (
        "role-change-keeps-sessions",
        "changing a role leaves sessions carrying the old role alive",
        [("portal/admin/AdminOperations.java", "replace",
          ('int revoked = sessions.revokeAllForUser(account.username(), "role changed to " + newRole);',
           "int revoked = 0;"))],
    ),
    (
        "no-last-superadmin-guard",
        "the last active SUPER_ADMIN can be disabled",
        [("portal/admin/AdminOperations.java", "replace",
          ("if (isLastActiveSuperAdmin(account)) {", "if (false) {"))],
    ),
    (
        "leaky-account-tostring",
        "Account#toString prints the stored digest",
        [("portal/admin/AdminAccount.java", "replace",
          ('+ ", digest=[masked]}";', '+ ", digest=" + passwordDigest + "}";'))],
    ),
    (
        "bootstrap-when-populated",
        "bootstrap can mint another super-administrator at any time",
        [("portal/cli/Main.java", "replace",
          ("if (!store.isEmpty()) {", "if (false) {"))],
    ),
    (
        "audit-no-crlf-filter",
        "audit fields are written without stripping newlines",
        [("portal/admin/AuditEvent.java", "replace",
          ("if (c == '\\n' || c == '\\r') {\n                out.append(' ');",
           "if (c == '\\n' || c == '\\r') {\n                out.append(c);"))],
    ),
    (
        "weak-password-floor",
        "the administrator password floor drops to 6 characters",
        [("portal/security/PasswordPolicy.java", "replace",
          ("public static final int MIN_LENGTH = 12;", "public static final int MIN_LENGTH = 6;"))],
    ),
    (
        "no-password-policy-on-reset",
        "password resets skip the policy check",
        [("portal/admin/AdminOperations.java", "replace",
          ("List<String> problems = checkPassword(newPassword, passwordConfirmation, account.username());\n"
           "        if (!problems.isEmpty()) {\n"
           "            return OperationOutcome.rejected(String.join(\"; \", problems));\n"
           "        }",
           "List<String> problems = new ArrayList<>();\n        if (!problems.isEmpty()) {\n"
           "            return OperationOutcome.rejected(String.join(\"; \", problems));\n        }"))],
    ),
]

def apply_mutation(tree, mutation):
    """Returns a list of errors; empty means every edit landed."""
    errors = []
    for rel, kind, payload in mutation[2]:
        path = os.path.join(tree, "main", "java", rel)
        if not os.path.exists(path):
            errors.append("missing file " + rel)
            continue
        with open(path, encoding="ascii") as handle:
            text = handle.read()

        if kind == "noop":
            # Neutralise spendSameWork so an unknown username costs nothing.
            old = "public void spendSameWork(char[] password) {"
            if old not in text:
                errors.append("anchor for " + mutation[0] + " not found in " + rel)
                continue
            text = text.replace(old, old + "\n        if (true) return;", 1)
        else:
            old, new = payload
            if text.count(old) != 1:
                errors.append("anchor for %s appears %d times in %s" % (mutation[0], text.count(old), rel))
                continue
            text = text.replace(old, new, 1)

        with open(path, "w", encoding="ascii") as handle:
            handle.write(text)
    return errors


def run_in(tree):
    """Compiles and runs the suite inside a copy. Returns (caught, detail)."""
    out = os.path.join(tree, "out")
    test_out = os.path.join(tree, "test-out")
    sources = []
    for root, _dirs, files in os.walk(os.path.join(tree, "main")):
        sources += [os.path.join(root, f) for f in files if f.endswith(".java")]
    compile_main = subprocess.run(
        ["javac", "-nowarn", "-encoding", "US-ASCII", "-d", out] + sources,
        capture_output=True, text=True)
    if compile_main.returncode != 0:
        return True, "mutation does not compile: " + compile_main.stderr.strip().splitlines()[0]

    compile_test = subprocess.run(
        ["javac", "-nowarn", "-encoding", "US-ASCII", "-cp", out, "-d", test_out,
         os.path.join(tree, "test", "java", "portal", "VerificationSuite.java")],
        capture_output=True, text=True)
    if compile_test.returncode != 0:
        return False, "suite did not compile against the mutant:\n" + compile_test.stderr[:800]

    run = subprocess.run(["java", "-ea", "-cp", out + ":" + test_out, "portal.VerificationSuite"],
                         capture_output=True, text=True, timeout=600)
    summary = [line for line in run.stdout.splitlines()
               if line.startswith("FAIL:") or line.startswith("  - ")]
    if run.returncode != 0:
        return True, "; ".join(summary[:4])[:400]
    return False, "suite stayed green: " + (summary[0] if summary else run.stdout[-200:])


def execute(mutation):
    identifier, description, _edits = mutation
    workspace = tempfile.mkdtemp(prefix="mutate-")
    tree = os.path.join(workspace, "src")
    try:
        shutil.copytree(SRC, tree)
        os.makedirs(os.path.join(workspace, "out"))
        os.makedirs(os.path.join(workspace, "test-out"))
        errors = apply_mutation(tree, mutation)
        if errors:
            return identifier, description, "ERROR", " | ".join(errors)
        caught, detail = run_in(tree)
        return identifier, description, ("CAUGHT" if caught else "SURVIVED"), detail
    except Exception as exc:  # noqa: BLE001 - report rather than abort the battery
        return identifier, description, "ERROR", repr(exc)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def main():
    wanted = os.environ.get("MUTATIONS")
    mutations = MUTATIONS
    if wanted:
        keep = {name.strip() for name in wanted.split(",") if name.strip()}
        mutations = [m for m in MUTATIONS if m[0] in keep]
        unknown = keep - {m[0] for m in mutations}
        if unknown:
            print("unknown mutation ids: " + ", ".join(sorted(unknown)))
            return 2
    print("applying %d mutations, each in its own copy of the tree" % len(mutations))
    survivors = []
    errored = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for identifier, description, verdict, detail in pool.map(execute, mutations):
            if verdict == "CAUGHT":
                print("  caught    %-28s %s" % (identifier, first_failure(detail)))
            elif verdict == "SURVIVED":
                print("  SURVIVED  %-28s %s" % (identifier, detail))
                survivors.append(identifier)
            else:
                print("  ERROR     %-28s %s" % (identifier, detail))
                errored.append(identifier)

    print()
    print("%d/%d mutations caught" % (len(mutations) - len(survivors) - len(errored), len(mutations)))
    if survivors:
        print("the verification suite does not cover: " + ", ".join(survivors))
    if errored:
        print("mutations that could not be applied: " + ", ".join(errored))
    return 1 if (survivors or errored) else 0


def first_failure(detail):
    for part in detail.split("; "):
        if part.strip().startswith("- "):
            return part.strip()[2:][:110]
    return detail[:110]


if __name__ == "__main__":
    sys.exit(main())
