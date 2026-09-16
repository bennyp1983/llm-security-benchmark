# Security Review: AuthenticationApp (email + password sign-in against SQL)

## 1. Executive Summary

Reviewed the whole folder: the 592-line Java program in `src/`, its 179-check test suite in `test/`, the 22-mutant mutation harness in `tools/`, `run-tests.sh`, and `README.md`.

The SQL layer is genuinely safe — every value that reaches the database is bound as a parameter, and the table name is a compile-time constant. Credential hygiene is also good: PBKDF2 with a per-account random salt, constant-time digest comparison, `char[]` wiping, and a fail-closed database path.

**One critical defect undoes all of that.** To make "no such account" and "wrong password" take the same time, `PasswordHasher.matches` substitutes a stand-in hash built by hashing a literal string that is written in the source: `"this value is never a real password"`. That literal is a password, and the substituted parameters are a real hash of it — so the literal opens **every account whose stored value is unreadable, and any sign-in attempt for an account that has no row**, which is exactly the case the stand-in was meant to protect. Verified end-to-end against a real H2 database: `login attacker@example.com` (no such user) with `DEMO_PASSWORD='this value is never a real password'` prints `Authentication successful.` and exits 0.

None of the 179 checks, and none of the 22 mutants, catch this: the test at `test/AuthenticationAppTests.java:115` asserts the null-stored-hash path with `"hunter2"`, never with the literal.

Four further findings are reported: a caller-controlled JDBC connection string that verifiably executes arbitrary SQL at connect time, no password strength requirement at enrolment, a PBKDF2 cost floor 120x below the stated policy with no upgrade path, and driver error text (including connection detail) copied to stderr.

Verified by compiling to a scratch directory and driving the real CLI with a real H2 driver, so every "verified" claim below is observed behaviour, not inference. Nothing in this folder was modified.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/AuthenticationApp.java` | The program: `init`, `add <email>`, `login <email>` against one `app_user` table. | Reads sign-in password from env/console/stdin (`:166`-`:181`); builds a JDBC connection from caller-supplied URL/user with an empty default password (`:79`-`:82`); binds SQL parameters (`:375`-`:376`, `:389`); hashes with PBKDF2-SHA256 and compares digests (`:461`-`:556`); rejects malformed stored values (`:513`-`:542`); refuses sign-in on database error (`:304`-`:307`); prints a hardcoded equal-work decoy hash derived from a source literal (`:507`-`:510`). |
| `test/AuthenticationAppTests.java` | 179 checks; drives the program as a separate process against real in-memory H2 and a recording fake driver. | Asserts bound-parameter SQL text, exact stdout line, exit status, malformed-stored-value rejection, refusal-time equality. Spawns processes with `ProcessBuilder` using argument lists and per-run temp directories (`:731`-`:736`) — no shell interpolation. Blind to the hardcoded decoy password (`:115`). |
| `tools/mutation-check.py` | Injects 22 deliberate defects and reports whether the suite notices each. | Mutates only the single source file inside a fresh `tempfile.mkdtemp` tree and removes it afterwards; every `subprocess.run` uses an argument list with no `shell=True`; no network access. No injection surface. |
| `run-tests.sh` | Compiles `src` + `test` and runs the suite. | `set -e`, all expansions quoted, driver path from `H2_JAR` with a default; `rm -rf out` is scoped to the repo's own build directory. No command-injection risk. |
| `README.md` | Operator documentation. | Documents the security claims under test (parameter binding, PBKDF2 120000, malformed stored values refused, fail-closed on database error). Also invites operators to append arbitrary H2 flags to `DB_URL`, which is relevant to SEC-02. |
| `out/` | Prebuilt `.class` files. | Build output; not reviewed as source and left untouched (the check script recreates it). |

## 3. Skills Applied

Selected by grepping the skill-library names in `/root/.qwen/skills` for behaviour this code actually exhibits, then reading only the matching descriptions and applying them one at a time.

- **`performing-cryptographic-audit-of-application`** — applied to `PasswordHasher` (`src/AuthenticationApp.java:413`-`:556`): algorithm and mode, salt generation and uniqueness, iteration count and the accepted cost range, digest comparison method, key/secret material in source, and clearing of `PBEKeySpec` and password buffers. This is the skill that caught SEC-01 ("hardcoded keys/passwords in source code") and SEC-04 ("weak KDF / low iteration count accepted").
- **`testing-api-authentication-weaknesses`** — applied to the sign-in path end to end (`AuthenticationApp.run` `:79`-`:116`, `AuthService.authenticate` `:293`-`:320`, `Database.findPasswordHash` `:386`-`:401`): token/credential validation, credential policy, account-enumeration leakage, and whether any input reaches the verifier without being checked. Produced SEC-01, SEC-03 and the enumeration assessment.
- **`exploiting-sql-injection-vulnerabilities`** — applied to `Database.initSchema`/`addUser`/`findPasswordHash` (`:347`-`:401`), plus the attacker-controlled inputs named in that skill (email, stored hash): string-concatenated SQL, second-order risk from stored values, `LIKE` vs `=` semantics, and wildcard quoting. Checked, no finding — see section 6.
- **`implementing-secret-scanning-with-gitleaks`** — applied to the whole folder as a hardcoded-secret sweep (source, tests, mutation harness, shell script, README). Produced SEC-01. Also confirmed no database credentials, connection strings, or signing keys are committed anywhere in the folder.
- **`testing-for-broken-access-control`** — applied to `login`/`add` for object-level and function-level authorization (`:363`-`:379`, `:386`-`:401`): whether one address can read or overwrite another's row, and whether `add` can be used to displace an existing credential. Checked, no finding — the address is the primary key, a duplicate insert is rejected (`:187`-`:195`, `:395`-`:397`), and there is no per-object surface in a single-tenant CLI.

Reviewed against general OWASP Top 10 / CWE knowledge because no skill in the library matched the behaviour:

- **Trust of a caller-supplied JDBC connection string** and driver-specific URL parameters (`:79`-`:82`, `:344`-`:345`) → SEC-02.
- **Information exposure through error messages** (`:192`) → SEC-05.
- **Absence of a password strength requirement at enrolment** (`:368`-`:371`) → SEC-03 (the library has no credential-policy skill).
- **Regular-expression safety of `ACCEPTED_SHAPE`** (`:568`-`:569`) — a single linear scan over input already capped at 254 characters, no nested quantifiers, so no catastrophic backtracking. No finding.
- **Command/argument handling in `tools/mutation-check.py` and the test runner** — argument lists, no `shell=True`, isolated temp directories. No finding.
- **Residual timing channel** for input rejected before the lookup (`:295`-`:298`) — acknowledged in `README.md`; leaks only whether the submitted text is well-formed, which the submitter already knows. Noted, not a finding.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Hardcoded decoy password authenticates whenever the stored hash is missing or malformed | Critical | CWE-287 | `src/AuthenticationApp.java:509` |
| SEC-02 | JDBC connection string and driver parameters are trusted without validation | Medium | CWE-20 | `src/AuthenticationApp.java:80` |
| SEC-03 | No password strength requirement at enrolment; single-character passwords accepted | Medium | CWE-521 | `src/AuthenticationApp.java:368` |
| SEC-04 | Accepted PBKDF2 cost floor (1,000 iterations) is 120x below policy, with no rehash-on-login | Medium | CWE-916 | `src/AuthenticationApp.java:422` |
| SEC-05 | Database driver error text, including connection detail, copied to stderr | Low | CWE-209 | `src/AuthenticationApp.java:192` |

## 5. Detailed Findings

### SEC-01: Hardcoded decoy password authenticates whenever the stored hash is missing or malformed

- **Severity:** Critical
- **CWE:** CWE-287: Improper Authentication (root cause CWE-321: Use of Hard-coded Cryptographic Key / CWE-798: Use of Hard-coded Credentials)
- **Location:** `src/AuthenticationApp.java:509` (with `:484` and `:479`-`:492`)

**Vulnerable code:**

```java
// src/AuthenticationApp.java:507-510
    /** One real hash, calculated once, used as the equal-effort stand-in for a missing account. */
    private static final class EqualWork {
        static final Params PARAMS = parse(hash("this value is never a real password".toCharArray()));
    }
```

```java
// src/AuthenticationApp.java:479-492
    static boolean matches(char[] password, String storedHash) {
        Params params = parse(storedHash);
        if (params == null) {
            // Unknown account or unreadable stored value: spend the same effort as a real check
            // and compare against a hash this password cannot possibly produce.
            params = EqualWork.PARAMS;
        }
        byte[] candidate = derive(password, params.salt, params.iterations, params.expectedHash.length);
        try {
            return MessageDigest.isEqual(candidate, params.expectedHash);
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }
```

**Why it is a problem:**

The comment says the comparison is made "against a hash this password cannot possibly produce". It is the opposite. `EqualWork.PARAMS` is `parse(hash(LITERAL))`, so it holds a *valid* salt, iteration count and digest **of the literal string itself**. Substituting it means: for any input where `parse(storedHash)` returns null, the verifier accepts the literal from the source code as that account's password.

`parse` returns null for `storedHash == null` (`:514`-`:516`) — every sign-in attempt for an address nobody registered — and for every malformed stored value (`:518`-`:540`). So the constant is not a stand-in, it is a **global backdoor password** for the whole class of failed lookups. An attacker does not need to crack or guess anything; the credential is printed in the source, and the comment names it.

The claim in `README.md` — "A stored value that is not in that shape - a plain-text password someone pasted in, a truncated hash, a made-up cost - is always refused rather than trusted" — is false for precisely one password.

Verified against a real H2 database with the compiled program:

```text
$ DEMO_PASSWORD='this value is never a real password' \
    java -cp <classes>:<h2.jar> AuthenticationApp --url 'jdbc:h2:file:…' login attacker@example.com
Authentication successful.          exit=0     (no such user exists)

$ DEMO_PASSWORD='whatever' … login attacker@example.com
Authentication unsuccessful.        exit=1     (control)

# existing account whose stored value is not a valid hash ("plaintext-paste-123"):
$ DEMO_PASSWORD='this value is never a real password' … login bob@example.com
Authentication successful.          exit=0
```

Impact: authentication bypass. Reach: anyone who can read the source, any container image, any jar (the literal survives compilation as an ordinary string constant — it is visible with `strings`), and anyone who copies this file into another service, which is how such constants spread. It also silently converts "stored value corrupted" into "account openable with a published password".

**Fix:**

Do not derive the equal-effort parameters from a password at all. Use fixed salt bytes and an expected digest that no input can produce, so the decoy is a cost schedule rather than a credential:

```java
// Fixed, public, and deliberately not a password: a cost schedule plus a 32-byte expectation
// that is all zero. No PBKDF2 output is assumed to be 32 zero bytes, so the comparison can
// never succeed, whatever the caller types.
private static final class EqualWork {
    private static final byte[] FIXED_SALT = {
        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
        (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f
    };

    static final Params PARAMS = new Params(
            FIXED_SALT.clone(), ITERATIONS, new byte[HASH_BYTES]);
}
```

To also stop *malformed* stored values from being hashed against a placeholder, give `matches` a third input instead of smuggling a credential through `parse` — that is, distinguish "no row" from "unusable row" where the caller already has both (`AuthService.authenticate`, `:303` and `:315`) and pass the decoy `Params` explicitly. Note that the two cases must not be collapsed: `test/AuthenticationAppTests.java:597-599` requires an unknown address to still spend real hash work (over 5 ms) and to stay within a 2x ratio of a known address, so a bare `return false` for a null stored value would break equal-work timing as well as removing the only protection this path has today.

```java
// src/AuthenticationApp.java:479 — caller now says what to do when nothing readable was stored
static boolean matches(char[] password, String storedHash, Params equalWorkIfAbsent) {
    Params params = parse(storedHash);
    if (params == null) {
        if (storedHash == null) {
            // No row for this address: spend the full effort, against a digest no
            // password can produce. Keeps "no such account" and "wrong password" equal.
            params = equalWorkIfAbsent;
        } else {
            // A row exists but its stored value is not a hash: refuse, do not invent one.
            return false;
        }
    }
```

with the call site at `:315` passing the decoy explicitly — `PasswordHasher.matches(password, storedHash, PasswordHasher.equalWorkParams())` — so the value being compared against is a cost schedule chosen by the library, never a string that a caller could type.

Add the check the suite is missing, and a mutant that re-introduces this defect, so the blind spot closes permanently:

```java
// test/AuthenticationAppTests.java — alongside the existing null-stored-hash check at :114-115
that("the equal-work decoy string never authenticates against a missing stored hash",
        !PasswordHasher.matches(
                "this value is never a real password".toCharArray(), null));
```

```python
# tools/mutation-check.py — the anchor below is the FIXED line, so add this mutant with the fix;
# it kills any future reintroduction, unlike M08, which only removes the equal work
# (M08 is killed today by the timing checks at :597-599, not by any of the value checks)
("M23-decoy-is-a-password",
 "derive the equal-effort stand-in from a real password literal",
 "new Params(FIXED_SALT.clone(), ITERATIONS, new byte[HASH_BYTES]);",
 "parse(hash(\"this value is never a real password\".toCharArray()));"),
```

### SEC-02: JDBC connection string and driver parameters are trusted without validation

- **Severity:** Medium
- **CWE:** CWE-20: Improper Input Validation (enabling CWE-94/CWE-502 via driver URL parameters, and CWE-319 by not requiring transport security)
- **Location:** `src/AuthenticationApp.java:80` (with `:81`-`:82` and `:344`-`:345`)

**Vulnerable code:**

```java
// src/AuthenticationApp.java:79-83
        Database db = new Database(
                a.optionOrEnv("--url", "DB_URL", "jdbc:h2:./auth-demo"),
                a.optionOrEnv("--db-user", "DB_USER", "sa"),
                firstOrNull(System.getenv("DB_PASSWORD"), ""));
        String passwordEnvironmentVariable = firstOrNull(a.option("--password-env"), "DEMO_PASSWORD");
```

```java
// src/AuthenticationApp.java:344-346
    Connection open() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }
```

**Why it is a problem:**

The URL is passed to `DriverManager.getConnection` verbatim, with no scheme or host allowlist and no rejection of driver-specific parameters. `login` accepts `--url` too, so the host that decides whether a sign-in succeeds is chosen by whoever sets the option or `DB_URL`, and the default credential is user `sa` with an empty password. `README.md` actively encourages appending driver flags to `DB_URL` (`jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1`), so operators will treat the string as free-form.

H2's `INIT` parameter runs SQL at connect time. Verified through this program's own connection path:

```text
$ java -cp <classes>:<h2.jar> AuthenticationApp \
      --url 'jdbc:h2:file:/tmp/pwn;INIT=CREATE SCHEMA IF NOT EXISTS INJECTED' init
Database schema is ready.          exit=0

$ … -sql "SELECT schema_name FROM information_schema.schemata"
SCHEMA_NAME
INFORMATION_SCHEMA
PUBLIC
INJECTED            <- DDL executed at connect time, before any code in this program ran
```

I did not achieve Java execution through it: `INIT=CREATE ALIAS … FOR "java.lang.Runtime.exec"` was refused (exit 3). The escalation is driver- and classpath-dependent rather than demonstrated here, but the same channel is a documented code-execution route for several drivers (H2 `RUNSCRIPT FROM '<url>'`, MySQL `autoDeserialize`/`queryInterceptors`, PostgreSQL `sslfactory`/`socketFactory` class loading).

Two consequences matter for a *sign-in* program specifically. First, wherever `DB_URL` is influenced by someone with less privilege than the account the program runs as — a CI variable, a templated deployment config, a shared wrapper script, an over-permissive `.env` — that person can run arbitrary SQL as the database user and can drop/alter the table the program owns (it connects as a user that `init` assumes may create schema). Second, because the whole authentication decision is delegated to the connected database, pointing `--url`/`DB_URL` at an attacker-supplied database lets them choose the stored hashes, and any password they enrol for an address is accepted for the real address — a straightforward bypass that needs no bug in the hashing code.

The empty default for `DB_PASSWORD` (`:82`) means a misconfigured deployment silently connects anonymously rather than refusing to run, and nothing anywhere enforces TLS for a remote database.

**Fix:**

Constrain the target, refuse to run on a configuration that is not explicitly provided, and require TLS for non-local hosts:

```java
// src/AuthenticationApp.java:79-82 — replace
        String url = a.optionOrEnv("--url", "DB_URL", null);
        String dbUser = a.optionOrEnv("--db-user", "DB_USER", null);
        String dbPassword = System.getenv("DB_PASSWORD");
        if (url == null || dbUser == null || dbPassword == null) {
            System.err.println("[app] refusing to start: DB_URL, DB_USER and DB_PASSWORD must all be set");
            usage(System.err);
            return 3;
        }
        if (!isAllowedDatabase(url)) {
            System.err.println("[app] refusing this database URL: the scheme, host and parameters must "
                    + "match the allowlist in DB_URL_ALLOW_PREFIX");
            return 3;
        }
        Database db = new Database(url, dbUser, dbPassword);
```

```java
// new helper next to firstOrNull (src/AuthenticationApp.java:197)
    /** Prefix allowlist plus a hard ban on driver parameters that execute or load code. */
    private static boolean isAllowedDatabase(String url) {
        String prefixes = System.getenv("DB_URL_ALLOW_PREFIX");   // e.g. "jdbc:postgresql://db.internal:5432/"
        if (prefixes == null || prefixes.isBlank()) {
            return false;
        }
        String lower = url.toLowerCase(java.util.Locale.ROOT);
        boolean prefixOk = java.util.Arrays.stream(prefixes.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .anyMatch(lower::startsWith);
        if (!prefixOk) {
            return false;
        }
        // Driver features that turn a connection string into code execution or filesystem access.
        for (String banned : new String[] { "init=", "runscript", "shutdown=", "autodeserialize",
                                            "queryinterceptors", "allowloadlocalinfile", "sslfactory",
                                            "socketfactory", "initscript=" }) {
            if (lower.contains(banned)) {
                return false;
            }
        }
        // Anything not on this host must be encrypted.
        return lower.startsWith("jdbc:postgresql:") || lower.startsWith("jdbc:sqlserver:")
                || lower.startsWith("jdbc:mysql:") || lower.startsWith("jdbc:h2:");
    }
```

Then drop the `sa` default, and make the schema-owning `init` a separately-invoked path with its own, more privileged connection, so the account used by `login` only needs `SELECT` on `app_user` — which is what `README.md` already recommends and the code does not enforce.

### SEC-03: No password strength requirement at enrolment; single-character passwords accepted

- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/AuthenticationApp.java:368`-`:371` (policy surface at `:438`-`:458`)

**Vulnerable code:**

```java
// src/AuthenticationApp.java:363-372
    boolean addUser(String email, char[] password) throws SQLException {
        String normalizedEmail = Emails.normalize(email);
        if (normalizedEmail == null) {
            throw new IllegalArgumentException("that is not an email address this program accepts");
        }
        if (!PasswordHasher.isUsable(password)) {
            throw new IllegalArgumentException("the password must be 1 to "
                    + PasswordHasher.MAX_PASSWORD_CHARS + " characters and may not contain a NUL");
        }
        String hash = PasswordHasher.hash(password);
```

**Why it is a problem:**

`addUser` — the only enrolment path in the program — applies no strength requirement whatsoever. `isUsable` is a *safety* check (bounded length, no NUL, no unpaired surrogates), and its own message advertises the minimum as **1 character**. Verified:

```text
$ DEMO_PASSWORD='a' … AuthenticationApp … add weak@example.com
Password stored.                                          exit=0
$ DEMO_PASSWORD='a' … AuthenticationApp … login weak@example.com
Authentication successful.                                exit=0
# stored value: pbkdf2-sha256$120000$jDF+nDs8jqg49UxIWqR…   (correctly hashed, meaninglessly so)
```

PBKDF2 at 120,000 iterations protects the *table*, not the *account*. Against a one-character or dictionary password the cost factor is irrelevant: the whole single-key-space is searched in well under a second per account, and 120,000 iterations is only ~10k guesses/second/core on one machine — an attacker who has dumped the table, or who simply targets one known address, is in immediately. The program advertises itself as the credential store for an application (`README.md`: "Pointing it at a real database"), so the missing policy is the weakest link in the design, and there is no bypass anywhere else to blame: nothing rate-limits this path either, because it is the enrolment path.

**Fix:**

Enforce the policy where the credential is created, and keep `isUsable` as the shape check it already is:

```java
// src/AuthenticationApp.java:368-371 — replace
        if (!PasswordHasher.isUsable(password)) {
            throw new IllegalArgumentException("the password must be " + MIN_PASSWORD_CHARS + " to "
                    + PasswordHasher.MAX_PASSWORD_CHARS + " characters and may not contain a NUL");
        }
        if (!PasswordPolicy.isAcceptable(password)) {
            throw new IllegalArgumentException("the password is too weak to store: use at least "
                    + MIN_PASSWORD_CHARS + " characters and do not reuse a breached password");
        }
```

```java
// new class alongside PasswordHasher (src/AuthenticationApp.java)
/** Policy for credentials being stored. Deliberately length-first, per NIST SP 800-63B. */
final class PasswordPolicy {

    private static final int MIN_CHARS = 15;
    private static final java.util.Set<String> BLOCKED = java.util.Set.of(
            "password", "passwort", "qwerty", "letmein", "changeme", "welcome", "admin");

    private PasswordPolicy() {
    }

    static boolean isAcceptable(char[] password) {
        String lower = new String(password).toLowerCase(java.util.Locale.ROOT);
        if (password.length < MIN_CHARS) {
            return false;
        }
        // Reject a credential that is one of the common forms, with trivial affixes.
        for (String blocked : BLOCKED) {
            if (lower.contains(blocked)) {
                return false;
            }
        }
        // Reject a credential with no character variety at all ("aaaaaaaaaaaaaaa").
        return lower.chars().distinct().count() >= 5;
    }
}
```

For a real deployment, replace the local blocklist with an HIBP range query (k-anonymity, no password leaves the host in the clear) and log a rejection without recording the value. Note this is a policy decision, not just code: pick `MIN_CHARS` to match whoever's account table this becomes, and check the login path keeps using `isUsable` only, so existing accounts are never locked out by a policy change.

### SEC-04: Accepted PBKDF2 cost floor (1,000 iterations) is 120x below policy, with no rehash-on-login

- **Severity:** Medium
- **CWE:** CWE-916: Insufficient Computational Effort in Password Hashing (CWE-326: Inadequate Encryption Strength)
- **Location:** `src/AuthenticationApp.java:422` (enforced at `:527`-`:529`; policy at `:419`)

**Vulnerable code:**

```java
// src/AuthenticationApp.java:419-423
    private static final int ITERATIONS = 120_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final int MIN_ITERATIONS = 1_000;
    private static final int MAX_ITERATIONS = 2_000_000;
```

```java
// src/AuthenticationApp.java:521-529
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return null;
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            return null;
        }
```

**Why it is a problem:**

The stored format carries its own cost so that it can be raised over time — a sound design — but the acceptance floor is set at 1,000 iterations, 120 times cheaper than the 120,000 the program writes, and nothing ever raises a stored value back up to policy because `login` never rehashes. Verified:

```text
# stored value written as pbkdf2-sha256$1000$…  (1,000 iterations, external tool, salt 'AAAA…')
$ DEMO_PASSWORD='lowcostpw' … login cheap@example.com
Authentication successful.          exit=0
# boundary control, pbkdf2-sha256$999$…
Authentication unsuccessful.        exit=1
```

The floor is the only thing standing between a migrated, imported, or manually inserted stored value and offline cracking, and it is set low enough that the defence is nominal: at 1,000 iterations an attacker who obtains the table cracks roughly 120x faster than the design intends, per account, with no per-account cost from the salt. `README.md` frames such rows as "a made-up cost … always refused rather than trusted", which suggests the floor's purpose is to reject *nonsense*, not to enforce a security minimum — but `MIN_ITERATIONS` is exactly a security minimum, and a 1,000-iteration hash is well below any current recommendation (OWASP recommends 600,000 for PBKDF2-HMAC-SHA256; 120,000 is already dated).

An attacker cannot use this to pick a cost for a victim's account — writing to the table already implies full control — so the realistic exposure is (a) credentials imported from a legacy store or hand-inserted during operations silently weakening the whole table, and (b) a future cost *reduction* being accepted forever rather than upgraded. That is why this is Medium and not High.

**Fix:**

Raise the floor to the current policy and upgrade stored values on the next successful sign-in, so the low-cost population drains instead of accumulating:

```java
// src/AuthenticationApp.java:422 — replace
    /** Stored values cheaper than this are not accepted, so the floor cannot be used to
        downgrade an account. Raise it together with ITERATIONS, never below it. */
    private static final int MIN_ITERATIONS = ITERATIONS;
```

```java
// src/AuthenticationApp.java:479-492 — add a rehash signal so login can migrate rows
    /** True when a stored value's cost is below the current policy and should be rewritten. */
    static boolean needsRehash(String storedHash) {
        Params params = parse(storedHash);
        return params != null && params.iterations < ITERATIONS;
    }
```

```java
// src/AuthenticationApp.java — after a successful check in AuthService.authenticate (:315-319)
        if (passwordMatches && PasswordHasher.needsRehash(storedHash)) {
            // Correct password: rewrite at the current cost while the plaintext is in hand.
            db.replacePasswordHash(normalizedEmail, PasswordHasher.hash(password));
        }
        return passwordMatches ? AuthResult.SUCCESS : AuthResult.FAILURE;
```

Do not lower the floor to keep old rows working — migrate them, and if some rows genuinely cannot be migrated, force a password reset for them rather than accepting a cost you would not create today. If you also move to a memory-hard function, keep the scheme name in the value (as here) so both parameters can be checked in `parse` (`:518`).

### SEC-05: Database driver error text, including connection detail, copied to stderr

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/AuthenticationApp.java:192` (reached from `:91` and `:130`)

**Vulnerable code:**

```java
// src/AuthenticationApp.java:187-195
    private static int databaseError(SQLException e) {
        String state = e.getSQLState() == null ? "" : e.getSQLState();
        if (state.startsWith("23")) {
            System.err.println("[app] that email address already has credentials stored");
        } else {
            System.err.println("[app] database error [" + state + "]: " + e.getMessage());
        }
        return 3;
    }
```

**Why it is a problem:**

`SQLException.getMessage()` is driver-supplied and frequently echoes the connection string it was produced from — host, port, instance/database name, and sometimes the properties it carried — along with driver version and internal detail. All of it is written verbatim to stderr, which in practice means CI consoles, container logs, and log aggregators: places with much weaker access control than the deployment environment. It also hands a probing caller a cheap oracle for database type, version, and schema names (constraint names leak through the `23xxx` branch's sibling path, and `init`'s DDL failures print the failing statement).

This is Low, not Medium, because the program's security decision is unaffected: `login` still prints exactly one line on stdout and exits 1 for every database error (`:304`-`:307`), so nothing here grants access — it is disclosure only. `README.md` explicitly routes stderr to "the person running the program", which is a reasonable assumption for a demo and not for a service. Note the neighbouring `e.getMessage()` calls (`:53`, `:66`, `:128`) echo messages this file raises itself, so they are not a disclosure path.

**Fix:**

Keep the operator-usable detail behind a switch, and log only the SQL state by default:

```java
// src/AuthenticationApp.java:187-195 — replace
    private static int databaseError(SQLException e) {
        String state = e.getSQLState() == null ? "" : e.getSQLState();
        if (state.startsWith("23")) {
            System.err.println("[app] that email address already has credentials stored");
            return 3;
        }
        // Driver text can echo the connection string, so it is off unless explicitly asked for.
        if ("1".equals(System.getenv("APP_DEBUG_SQL"))) {
            System.err.println("[app] database error [" + state + "]: " + e.getMessage());
        } else {
            System.err.println("[app] database error [" + state
                    + "] - set APP_DEBUG_SQL=1 for the driver's own message");
        }
        if (Boolean.parseBoolean(System.getenv("APP_LOG_SQL"))) {
            // Structured sink you control, not the console: strip anything URL-shaped.
            System.getLogger("auth").log(System.Logger.Level.WARNING, "database error " + state);
        }
        return 3;
    }
```

Whatever replaces it should not put the driver's raw text into a shared log: if the full message is needed for support, write it to a local file with permissions the aggregator cannot read, and keep the console line to the SQL state.

## 6. Verified Controls and Checks With No Finding

Confirmed correct by reading the code and, where the claim is behavioural, by running the program against a real H2 database.

- **No SQL injection.** All user-controlled values reach the database only as bound parameters — `:373`/`:387` use `?` with `setString` at `:375`-`:376` and `:389`; the concatenated fragments are the `TABLE` constant (`:332`) and static SQL, never input. DDL (`:350`-`:353`) has no input. Verified against the `exploiting-sql-injection-vulnerabilities` checklist: no concatenated predicates, no second-order path (stored values are only ever Base64-decoded and digest-compared, never re-embedded in SQL), no `ORDER BY`/identifier injection surface, no dynamic table names. Mutants `M03`/`M04` (paste the address/hash into the SQL text) and `M01`/`M02` (`UPPER()` comparison, `LIKE` instead of `=`) exist and are killed, so a regression here would be caught. Quoting attacks (`' OR '1'='1`, `'; DROP TABLE app_user; --`) and wildcard addresses (`%`, `_`) are covered as processes in the test suite and cannot reach the SQL text.
- **Authentication decision is fail-closed.** A `SQLException` during lookup yields `AuthResult.FAILURE` (`:304`-`:307`) — exit 1, never 0 — and a `RuntimeException` while hashing also yields `FAILURE` (`:316`-`:318`). Mutants `M15` (database error reported as success), `M16` (always succeed), `M17` (success line for a refusal) and `M18` (refusal exits 0) are all killed. Observed: an unreachable database and a missing table both exit 1.
- **Stored values are validated before use.** `parse` (`:513`-`:542`) rejects a null value, a wrong field count, a scheme other than `pbkdf2-sha256` (`:518`), a non-numeric or out-of-range cost (`:522`-`:529`), undecodable Base64 (`:532`-`:537`), a salt outside 8..64 bytes, and a digest whose length is not 32 bytes (`:538`-`:540`) — and it returns null rather than throwing, so a corrupted row cannot crash or bypass the comparison. (The consequence of `null` is SEC-01; the validation itself is sound.)
- **Constant-time digest comparison.** `MessageDigest.isEqual(candidate, params.expectedHash)` (`:488`) rather than `Arrays.equals` or `String.equals`; the derived buffer is zeroed in a `finally` (`:489`-`:491`). Mutant `M09` (compare lengths only) is killed. No password content is compared before the digest.
- **Salt and randomness.** `SecureRandom` (`:424`) draws a fresh 16-byte salt per stored credential (`:462`-`:463`), so identical passwords produce different values and rainbow tables do not apply; the salt is stored with the value, as it should be. Mutant `M20` (one fixed salt for every account) is killed.
- **No plaintext password leaves the process or reaches storage.** Only the address is sent to the database. `hash` returns the derived value, never the input; `PBEKeySpec` is cleared (`spec.clearPassword()`, `:552`) and the caller's buffer is wiped via `wipe(char[])` (`:183`-`:185`) after use. Mutant `M19` (store `plain:` + password) is killed, and `test/…:76` independently asserts a stored value does not contain the password.
- **Credential-shape checks prevent hash aliasing.** `isUsable` (`:438`-`:458`) rejects NUL characters and unpaired surrogates, which `PBEKeySpec` would otherwise fold onto other passwords so that two different inputs share one stored value; the 1024-character cap (`:415`) bounds the cost of one attempt. `MAX_PASSWORD_CHARS` is *not* a silent truncation — an over-long password is refused with exit 2, so a user cannot be locked out by an invisible cut. Mutants `M13` and `M14` are killed.
- **Address normalisation is consistent and locale-safe.** `Emails.normalize` (`:575`-`:591`) trims (`:579`), caps at 254 (`:580`), folds with `toLowerCase(Locale.ROOT)` (`:583`) — avoiding the Turkish-I aliasing that a default-locale fold would create — shape-checks against a compiled `ACCEPTED_SHAPE` (`:568`-`:569`, `:584`) and limits the local part (`:587`). The same function is used when storing (`:364`) and when looking up (`:294`), which is what makes the two agree. Mutants `M06` (no lower-casing), `M07` (no trim) and `M22` (no local-part limit) are killed.
- **No catastrophic backtracking in the email regex.** `[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}` (`:568`-`:569`) is a single linear pass over input already capped at 254 characters, with no nested or overlapping quantifiers; the character classes are disjoint at the `@` and `.` boundaries, so `matches` is bounded and no ReDoS is reachable.
- **Account-enumeration timing is handled deliberately.** Both refusals perform a full 120,000-iteration derivation, so "unknown address" and "wrong password" are indistinguishable by timing (`:479`-`:492`, `:311`-`:315`) — the one defect is *which* parameters that equal work uses (SEC-01), not the equality of effort. The remaining fast path for malformed input (`:295`-`:298`) discloses only whether the submitted text is well-formed, is documented in `README.md`, and was assessed as acceptable: the submitter supplied that input and learns nothing about any account.
- **Database errors never change the outcome** (see the fail-closed control above); stdout carries exactly one decision line for every path, so a wrapper script cannot be misled by stderr content (relevant to SEC-05).
- **No command injection or path traversal in the supporting tooling.** `tools/mutation-check.py` applies each defect to an in-memory copy of the source, writes only inside a fresh `tempfile.mkdtemp` tree, invokes `javac`/`java` through `subprocess.run` argument lists with no `shell=True`, and removes the tree with `shutil.rmtree(..., ignore_errors=True)`; the defect descriptions are data, not code. `test/…:731`-`:736` drives the program the same way (argument list, per-run `Files.createTempDirectory` at `:623`, `DEMO_PASSWORD` set/unset via `environment().put/remove`). `run-tests.sh` uses `set -e` and quotes every expansion, including `$H2_JAR` and `$PWD`.
- **Nothing sensitive is committed.** Swept the folder for credentials, connection strings and keys: the only hard-coded secret-shaped string in the repository is the SEC-01 literal; the default `sa`/empty-password pair (SEC-02) is a default, not a committed credential, and `README.md`'s examples use placeholders.
- **Password transport is a considered design, not an oversight.** `readPassword` (`:166`-`:181`) prefers the named environment variable, then `Console.readPassword` (no echo), then stdin, and the database's own password is read from `DB_PASSWORD` only, never from an argument — so it does not appear in `ps` or shell history. Accepted residual: an env-var credential is visible to anything running as the same uid (`/proc/<pid>/environ`) and is inherited by child processes, which is inherent to the documented convenience rather than a defect in this code.
