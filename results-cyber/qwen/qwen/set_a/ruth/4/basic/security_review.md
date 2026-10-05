# Security Review: UserAccountService (Java/JDBC PBKDF2 account store)

## 1. Executive Summary

The library under review is a single-class, dependency-free credential store: `UserAccountService`
registers accounts into one JDBC table and verifies logins with PBKDF2, over a `Connection` the
caller owns. The SQL layer is genuinely clean — all four statements are compile-time constants and
every piece of user data reaches the database through a bound placeholder, so there is no injection
surface at all, and the login path deliberately equalises its cost against unknown usernames so
response time does not leak which accounts exist.

The weaknesses are concentrated in two places. First, **the trust boundary is misplaced in the
key-derivation parameters**: `authenticate` takes the algorithm name, iteration count, salt and key
length from the database row and accepts any algorithm whose name merely *starts with* the seven
characters `PBKDF2`, with a floor of 1 000 iterations. The shipped default
(`PBKDF2WithHmacSHA256`, 310 000 rounds, 16-byte salt, 32-byte key) is therefore a policy that is
not enforced where it matters — the class happily verifies a row reading
`PBKDF2WithHmacSHA1` @ 1 000 rounds with an 8-byte salt and a 20-byte key, roughly 310× less work
than the default, and the project's own test suite proves this combination is accepted and works end
to end. Any row-level downgrade, or any deployment that "tunes" the instance for speed, persists
silently because the one upgrade hook that exists (`credentialsNeedUpgrade`) is detection-only and
has no write path. Second, several **resource- and memory-handling edges** were confirmed: the
password length ceiling is counted in UTF-16 code units while `PBEKeySpec` consumes the password's
UTF-8 encoding (up to ~4× the intended per-login CPU from astral-plane characters), no code path
ever wipes the caller's `char[]` (and a `SecureRandom`-generated secret is retained for the JVM's
whole lifetime to make the timing equaliser work), and `authenticate` never asserts that its
single-row lookup returned a single row — a guarantee the README advertises that exists only inside
a test double.

Seven findings are reported: one High, two Medium, four Low. None of them is a credential-leak or an
injection bug; all of them are strength, assurance and hygiene defects, and all are fixable without
changing the class's public contract. The `DuplicateUsernameException` message and `Demo.java`'s
plaintext stdout are the two items most likely to reach a real log or screen by accident; the rest
need a design decision (where does KDF policy live, and who is allowed to drop the table).

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `UserAccountService.java` | Production library: register, authenticate, delete accounts over a caller-supplied `Connection`. | PBKDF2 KDF choice and parameters (`:35-48`, `:115-133`); trust in KDF parameters read back from a DB row (`:261-262`, `:306-324`); four constant SQL statements (`:58-81`) with bound parameters (`:196-202`, `:243-244`, `:274-279`); `SecureRandom` salt generation (`:88`, `:185-186`); username/password policy (`:83`, `:337-357`); password-destroy semantics (`:359-372`); timing equaliser holding a derived key and a random password as long-lived fields (`:96-102`, `:374-405`); savepoint-only transaction handling (`:192-211`); duplicate-key classification (`:326-335`); destructive `dropSchema` and cost-triggering `deriveMillis` on the public API (`:161-166`, `:292-299`); exception text (`:463-482`). |
| `Demo.java` | Runnable demonstration against in-memory H2 (or a URL argument). | Hardcoded passphrases (`:32-34`, `:49`, `:52-53`, `:103`, `:109`); prints the candidate password in clear (`:75-77`); prints hex prefixes of stored salts/hashes (`:112-127`); prints the JDBC URL (`:24`); triggers a full key derivation at startup (`:25-26`). |
| `UserAccountServiceTest.java` | Real-engine (H2) behaviour suite, 622 lines. | Documents which KDF parameters the constructor accepts (`:507-516`) and proves that a weak tuned instance round-trips (`:516`, `:519-527`); asserts `Account.toString()` carries no secret (`:88`); asserts corrupt rows are refused within a time budget rather than derived; asserts unknown-user cost equals known-user cost. |
| `UserAccountServiceJdbcContractTest.java` | Contract suite over `java.lang.reflect.Proxy` JDBC doubles, 735 lines. | Asserts exact prepared-statement text, five placeholders, absence of user input in statement text, absence of `TRIM(`/`COLLATE` (`:93-94`); never calls `commit`/`rollback`/`close`/`setAutoCommit`; **implements the multi-row refusal inside the fake rather than in production code** (`:603-610`, driven by `:161-175`); uses `PBKDF2WithHmacSHA1` as its fixture algorithm (`:37`). |
| `README.md` | Design rationale, schema, guarantees, admitted trade-offs. | Invites bring-your-own DDL with no uniqueness requirement (`:67-70`); claims a two-row result is refused (`:206-213`); states passwords are never stored or logged (`:72-73`); admits no breach-list check (`:131-135`); admits both failure modes disclose account existence and that rate-limiting belongs elsewhere (`:289-296`). |
| `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Task/authoring context, not source. | No executable behaviour; included in the secret sweep only. Reviewed as non-code and excluded from findings. |

## 3. Skills Applied

- **`performing-cryptographic-audit-of-application`** — applied to `UserAccountService.java`
  `:35-48` (algorithm name, iteration count, salt length, key length), `:88` and `:185-186`
  (`SecureRandom` used for both salt and the dummy password — correct primitive, verified fresh
  entropy per registration), `:264` and `:401-403` (`MessageDigest.isEqual` over fixed-size keys on
  both comparison paths), `:306-324` (bounds on the stored parameters, which is where the audit's
  "check key derivation function parameters" and "detect usage of deprecated algorithms (MD5, SHA-1)"
  checks fire), and `:96-102` / `:369-371` / `:391` (how long derived key material and the
  derivation input survive in memory). Also applied to `Demo.java:32-34` and `:49` for the
  weakness table's "Hardcoded Secrets" row. This skill's own weakness table is what rates
  "Weak KDF | Low iteration PBKDF2" as High, and "Weak Hashing | …SHA-1…" as High.
- **`exploiting-sql-injection-vulnerabilities`** — applied to all four statement constants
  (`:58-67`, `:69-71`, `:73-77`, `:79`, `:81`) and every setter call site (`:197-201`, `:244`,
  `:276`). Its Step 1 "Injection Point Discovery" found no concatenation of external data into any
  statement; the second-order sink was also checked (stored values are never re-used to build SQL —
  only `algorithm` flows from a row into `SecretKeyFactory`, not into a query), and the stacked-query
  question was checked against the single-statement `Statement.execute` calls in `ensureSchema` /
  `dropSchema`, which receive constant text only.
- **`testing-for-sensitive-data-exposure`** — applied to the stored column set (`:58-67`), to
  `Account.toString()` (`:416-444`, `:442`) and the private `StoredCredential` (`:447-460`), which
  together keep salt/hash out of anything the caller can print, and to the transmission/output step:
  `Demo.java:75-77` (candidate password on stdout), `Demo.java:112-127` (hex prefixes of stored
  salt and hash), `Demo.java:24` (JDBC URL, which in a real deployment carries host and sometimes
  credentials), and `README.md`'s sample output. Its Step 1 secrets-in-code check drove the manual
  credential sweep described in the next bullet.
- **`testing-api-authentication-weaknesses`** — applied to its Step 6 "Password Policy and
  Credential Testing": `validatePassword` (`:344-357`) enforces length and control characters only,
  which `README.md:131-135` openly admits is not a breach-list check; and to "Test account
  enumeration via login response differences": the login path *is* protected against timing
  enumeration (`:238-241`, `:246-251`, `:255-260`, `:374-405`) but the signup path is not
  (`:207-209`), which `README.md:289-296` also admits.
- **`implementing-secret-scanning-with-gitleaks`** — `gitleaks` is not installed on this machine, so
  its Step 1 detection patterns were applied manually across `*.java`, `*.md` and `*.txt`
  (`api[_-]?key`, `secret`, `token`, `passwd`, `password`, `BEGIN [A-Z]+ PRIVATE KEY`, `AKIA…`,
  `ghp_`, `xox[baprs]-`, `jdbc:` with an embedded user/password). The only hits were the demo
  passphrases in `Demo.java` (reported as SEC-06); no API keys, private keys, bearer tokens or
  credential-bearing connection strings exist anywhere in the folder. Its Step 6 "rotate the exposed
  credential" does not apply — these are demonstration strings, not live secrets — so the remediation
  is removal from source rather than rotation.

**Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched:** the
memory-zeroisation semantics of `char[]` passwords, `String.toCharArray()` copies and
`PBEKeySpec.clearPassword()` (nothing in this skill library covers JVM key-material lifetime —
A02 / CWE-226, SEC-03); the secure-by-default API design of exposing destructive and expensive
diagnostics on a production service class (A05 / CWE-489 + CWE-284, SEC-05); output hygiene in
example code (SEC-06); the mismatch between a README assurance claim and the code that actually
implements it (SEC-07, where the guarantee lives in a `Proxy` double); and the concrete KDF
benchmarks used as the yardstick in SEC-01/SEC-02 — OWASP's 2023 password-storage guidance of
≈310 000 iterations for PBKDF2-HMAC-SHA256 and ≈600 000 for HMAC-SHA1, and a 128-bit minimum salt —
are cited here as general knowledge because
`performing-cryptographic-audit-of-application/references/standards.md` contains no PBKDF2, salt or
iteration guidance at all (a grep for `pbkdf2|argon|bcrypt|iteration|salt|random|entropy|sha-?1|hmac`
returns nothing). No Python helper script from any of these skills was executed: the target is Java,
and the skills supply analysis knowledge, not tooling for this language.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Stored row dictates its own KDF: `startsWith("PBKDF2")` accepts SHA-1 and a 1 000-round work factor | High | CWE-326, CWE-327 | `UserAccountService.java:311` |
| SEC-02 | Password ceiling counted in UTF-16 code units, charged in UTF-8 bytes | Medium | CWE-1284, CWE-400 | `UserAccountService.java:348` |
| SEC-03 | Passwords and the internal dummy secret are never zeroised | Medium | CWE-226, CWE-117 | `UserAccountService.java:369` |
| SEC-04 | Signup confirms account existence and echoes caller input into a user-facing message | Low | CWE-204, CWE-209 | `UserAccountService.java:480` |
| SEC-05 | Destructive `dropSchema` and cost-triggering `deriveMillis` are public on the production class | Low | CWE-489, CWE-284 | `UserAccountService.java:162` |
| SEC-06 | Demo hardcodes passphrases and prints the candidate password in clear | Low | CWE-798, CWE-532 | `Demo.java:75` |
| SEC-07 | Single-row lookup never asserts single-row, so a non-unique schema trusts the first row | Low | CWE-754 | `UserAccountService.java:246` |

## 5. Detailed Findings

### SEC-01: Stored row dictates its own KDF — `startsWith("PBKDF2")` accepts SHA-1 at 1 000 rounds

- **Severity:** High
- **CWE:** CWE-326: Inadequate Encryption Strength (also CWE-327: Use of a Broken or Risky Cryptographic Algorithm)
- **Location:** `UserAccountService.java:311`

**Vulnerable code:**

```java
        if (storedAlgorithm == null || !storedAlgorithm.startsWith("PBKDF2")) {
            return null;
        }
        if (storedIterations < MIN_STORED_ITERATIONS || storedIterations > MAX_STORED_ITERATIONS) {
            return null;
        }
```

**Why it is a problem:**

`authenticate` builds its verification key entirely from attacker-/storage-controlled row columns —
`derive(password, stored.salt, stored.iterations, stored.algorithm, stored.hash.length)`
(`UserAccountService.java:261-262`) — and `readCredential` screens those columns with a *prefix*
test plus a very low floor (`MIN_STORED_ITERATIONS = 1_000`, `UserAccountService.java:54`). The
prefix test admits `PBKDF2WithHmacSHA1`, `PBKDF2WithHmacMD5` and any other
`PBKDF2WithHmac<Anything>` the JVM happens to ship; the iteration floor permits a ~310× reduction
from the shipped default of 310 000 rounds. The `salt`/`hash` length floors (8 and 16 bytes,
`:317-320`) are likewise below the 128-bit salt that password hashing needs, and the *constructor*
applies the identical prefix rule (`:116-128`), so a whole deployment can be configured below policy
rather than only a single row.

This is not hypothetical: the project's own suite pins the weak-but-accepted configuration and
requires that it work end to end —

```java
        ok("a tuned instance works end to end", tuneAndCheck());
    }

    private static boolean tuneAndCheck() throws Exception {
        UserAccountService cheap = new UserAccountService("PBKDF2WithHmacSHA1", 1_000, 8, 20);
```

(`UserAccountServiceTest.java:516`, `:519-520`) — HMAC-SHA1, 1 000 rounds, 8-byte salt, 20-byte
output, registered and authenticated successfully. The contract suite uses SHA-1 as its normal
fixture too (`UserAccountServiceJdbcContractTest.java:37`).

The consequence is silent, permanent strength loss. Anyone able to write the `algorithm`/`iterations`
columns (a SQL-injection bug elsewhere, a restored backup, a mis-applied migration, an insider) can
move an account to a KDF an order of hundreds cheaper and it keeps logging in normally; offline
cracking of that row is correspondingly cheaper. The one hook that could catch this,
`credentialsNeedUpgrade(int)` (`:288-290`), compares only against the instance's own setting and is
documented as "detection only: the class has no write path for an existing row" (`:285-286`) — and
nothing in the class ever calls it. A row that is far below policy therefore *authenticates
successfully* rather than being flagged.

**Fix:**

Replace the prefix test with an exact allowlist of algorithms this build is willing to verify, and
raise the floors to policy values so a below-policy row is refused (and must be re-hashed on next
successful login through the caller's own update statement) rather than silently accepted. Add
`import java.util.Set;`.

```java
    /** Algorithms this build will verify against. Anything else — including other PBKDF2 variants —
     *  is refused, so a row cannot select a cheaper primitive by naming it. */
    private static final Set<String> ACCEPTED_ALGORITHMS =
            Set.of("PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA512");

    /** Below this a row is refused outright: it must be re-hashed, never merely verified. */
    private static final int MIN_STORED_ITERATIONS = 100_000;

    /** A per-user salt shorter than this is too small to defeat precomputed tables. */
    private static final int MIN_ACCEPTED_SALT_BYTES = 16;

    private StoredCredential readCredential(ResultSet rs) throws SQLException {
        String storedAlgorithm = rs.getString(1);
        int storedIterations = rs.getInt(2);
        byte[] salt = rs.getBytes(3);
        byte[] hash = rs.getBytes(4);
        if (storedAlgorithm == null || !ACCEPTED_ALGORITHMS.contains(storedAlgorithm)) {
            return null;
        }
        if (storedIterations < MIN_STORED_ITERATIONS || storedIterations > MAX_STORED_ITERATIONS) {
            return null;
        }
        if (salt == null || salt.length < MIN_ACCEPTED_SALT_BYTES || salt.length > 128) {
            return null;
        }
        if (hash == null || hash.length < 32 || hash.length > 128) {
            return null;
        }
        return new StoredCredential(storedAlgorithm, storedIterations, salt, hash);
    }
```

Apply the same exact-name check in the constructor (`UserAccountService.java:116`) so a tuned
instance cannot be constructed below policy either, and keep the refusal path going through
`burnKeyDerivation()` (`:255-260`) so refusing a weak row stays timing-indistinguishable from a wrong
password. `UserAccountServiceTest.java:519-527` and `:507-516` then need updating to assert the new
floor rather than the old permissiveness.

### SEC-02: The password ceiling is counted in UTF-16 code units but charged in UTF-8 bytes

- **Severity:** Medium
- **CWE:** CWE-1284: Improper Validation of Specified Quantity in Input (also CWE-400: Uncontrolled Resource Consumption)
- **Location:** `UserAccountService.java:348`

**Vulnerable code:**

```java
    private static void validatePassword(char[] password) {
        if (password == null) {
            throw new InvalidValueException("password must not be null");
        }
        if (password.length < MIN_PASSWORD_CHARS || password.length > MAX_PASSWORD_CHARS) {
            throw new InvalidValueException("password must be " + MIN_PASSWORD_CHARS + "-"
                    + MAX_PASSWORD_CHARS + " characters long");
        }
```

**Why it is a problem:**

`MAX_PASSWORD_CHARS = 1024` (`:86`) bounds `char[]` length, i.e. UTF-16 code units. But PBKDF2 does
not hash the `char[]`; `new PBEKeySpec(password, ...)` (`:361`) converts the password to its UTF-8
bytes and iterates over *those*. A code point outside the Basic Multilingual Plane (emoji, many CJK
extensions, most historic scripts) costs one `char[]` slot as a surrogate pair and four UTF-8 bytes.
1 024 surrogate pairs therefore pass validation as "1 024 characters" while the KDF does the work of
4 096 bytes — up to roughly four times the CPU per derivation that the limit was written to
guarantee, on the *unauthenticated* login path. `UserAccountServiceTest.java`'s hostile-input test
deliberately stores and re-derives an astral-plane password, confirming the path is exercised rather
than theoretical.

PBKDF2 is deliberately expensive, so the per-call cost is the DoS currency here, and this class sits
behind no rate limiter by design — `README.md` states that limiting belongs in front of the service.
A 4× amplification multiplied by login volume is what a cheap botnet aims at, and the same limit is
measured in the wrong unit in both directions: `MIN_PASSWORD_CHARS = 10` also lets a
10-code-point astral password in as nominally 40 bytes. The unit error is a validation defect
(CWE-1284) whose impact is resource consumption (CWE-400); note the existing `MAX_STORED_ITERATIONS`
guard (`:50-54`) shows the author was already defending against derivation-cost abuse, so this is a
gap in an intended control rather than an unconsidered one.

**Fix:**

Bound the quantity that actually drives the cost — the UTF-8 byte length — in addition to the
character bounds, and keep the exception text input-free. Add
`import java.nio.charset.StandardCharsets;`.

```java
    /** PBEKeySpec iterates the UTF-8 encoding, so bytes — not code units — are the real ceiling. */
    private static final int MAX_PASSWORD_BYTES = 128;

    private static void validatePassword(char[] password) {
        if (password == null) {
            throw new InvalidValueException("password must not be null");
        }
        if (password.length < MIN_PASSWORD_CHARS || password.length > MAX_PASSWORD_CHARS) {
            throw new InvalidValueException("password must be " + MIN_PASSWORD_CHARS + "-"
                    + MAX_PASSWORD_CHARS + " characters long");
        }
        if (new String(password).getBytes(StandardCharsets.UTF_8).length > MAX_PASSWORD_BYTES) {
            throw new InvalidValueException("password must not exceed " + MAX_PASSWORD_BYTES
                    + " bytes when UTF-8 encoded");
        }
        for (char c : password) {
            if (c < 0x20 || c == 0x7F) {
                throw new InvalidValueException("password must not contain control characters");
            }
        }
    }
```

If rejecting multi-byte passphrases outright is unacceptable for your user base, drop the byte check
and cap `MAX_PASSWORD_CHARS` at 256 instead — the point is that the bound must be expressed in the
unit the KDF consumes. Whichever you choose, publish it: the current error message promises 1 024
characters and the class then charges for up to 4 096 bytes.

### SEC-03: Passwords and the internal dummy secret are never zeroised

- **Severity:** Medium
- **CWE:** CWE-226: Sensitive Information in Resource Not Removed Before Reuse (also CWE-117: Improper Output Neutralization for Logs — the plaintext-password lifetime that ends up in memory and heap dumps)
- **Location:** `UserAccountService.java:369`

**Vulnerable code:**

```java
    private static byte[] derive(char[] password, byte[] salt, int iterations, String algorithm,
            int hashBytes) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, hashBytes * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            // Only reachable if the row names a KDF this JVM does not ship, which readCredential
            // already screens for; a wrong answer here must not look like "wrong password".
            throw new IllegalStateException("cannot derive key with " + algorithm, e);
        } finally {
            spec.clearPassword();
        }
    }
```

**Why it is a problem:**

`spec.clearPassword()` wipes the copy held inside the `PBEKeySpec`; it does nothing to the caller's
`char[]`, which is the buffer the whole API is designed around precisely so that it *can* be wiped.
The class knows this and declines responsibility: `@param password validated but not cleared; wipe
the caller's array if it matters to you` (`:175`). The result is that a plaintext password stays
readable in the heap — and in any heap dump, swap file or core dump taken later — for as long as the
collector happens to leave that array alive, which for a login handled on a pooled request thread can
be a long time. The `String` overloads make it strictly worse, because `password.toCharArray()`
(`:225`, `:270`) creates a second copy that no one can wipe either and the original `String` is
unwipeable by construction.

The same defect is worse in one specific place the author did not intend as a user secret: the timing
equaliser keeps a 32-character `SecureRandom` password in a long-lived field —
`dummyPassword = probe;` (`:391`, field declared at `:102`) — and reuses it for every
`burnKeyDerivation()` call (`:401`). It is a value no account can ever hold, so it cannot
authenticate anything, but it is still 32 bytes of high-entropy secret material resident for the
lifetime of the JVM and re-fed into the KDF on every unknown-username login, which is the highest-
volume path in the class. It buys nothing: the derivation cost depends on `iterations`, `algorithm`
and the salt length, none of which requires the password to be remembered between calls.

**Fix:**

Wipe the caller's array at the two entry points (this is a documented behaviour change — make it the
documented contract, or rename the parameter to say so), stop retaining the dummy password, and wipe
the internally generated one. Add `import java.util.Arrays;`.

```java
    public boolean authenticate(Connection connection, String username, char[] password)
            throws SQLException {
        try {
            // ... existing body of authenticate unchanged ...
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private void burnKeyDerivation() {
        byte[] key = dummyKey;
        if (key == null) {
            synchronized (this) {
                if (dummyKey == null) {
                    char[] probe = randomPassword();
                    try {
                        byte[] probeSalt = new byte[saltBytes];
                        RANDOM.nextBytes(probeSalt);
                        dummyKey = derive(probe, probeSalt, iterations, algorithm, hashBytes);
                    } finally {
                        Arrays.fill(probe, '\0');
                    }
                }
                key = dummyKey;
            }
        }
        // A fresh password and a salt that belongs to no stored account: same cost, but nothing here
        // is retained and the derivation can never be the basis of a successful login.
        char[] probePassword = randomPassword();
        try {
            byte[] throwawaySalt = new byte[saltBytes];
            RANDOM.nextBytes(throwawaySalt);
            byte[] probe = derive(probePassword, throwawaySalt, iterations, algorithm, hashBytes);
            if (MessageDigest.isEqual(probe, key)) {
                throw new IllegalStateException("internal error: dummy credential collision");
            }
        } finally {
            Arrays.fill(probePassword, '\0');
        }
    }
```

Delete the `dummyPassword` field (`:101-102` keeps `dummyKey`, which is a derived key and is fine to
hold), and do the same `finally`-wipe in `registerUser`. For the `String` overloads (`:220-226`,
`:268-271`), either deprecate them in favour of the `char[]` forms or keep them and state plainly in
the README that they forfeit zeroisation — the current javadoc at `:215-219` hints at this but the
code never enforces or documents it at the point of harm.

### SEC-04: Signup confirms account existence and echoes caller input into a user-facing message

- **Severity:** Low
- **CWE:** CWE-204: Observable Response Discrepancy (also CWE-209: Generation of Error Message Containing Sensitive Information)
- **Location:** `UserAccountService.java:480`

**Vulnerable code:**

```java
        DuplicateUsernameException(String username) {
            // Deliberately does not say whether the account exists for anyone other than the
            // registered owner; the username is echoed back to the requester, who supplied it.
            super("username is already registered: " + username);
        }
```

**Why it is a problem:**

The login path is defended against enumeration by equalising cost (`:238-241`, `:246-251`,
`:255-260`), but signup answers the same question instantly and unambiguously: a distinct exception
type plus a message that states the account is taken. That comment's reasoning — the requester
supplied the username, so echoing it reveals nothing new — is true of the *string*, but not of the
*status*: the whole point of the message is to disclose "this username is registered", to anyone who
tries it. `README.md:289-295` acknowledges this trade-off openly ("both reveal account existence to
whoever triggered them. Return a generic failure to end users, and rate-limit"), so the finding is
that the unsafe rendering is the *default and the path of least resistance*: a caller who renders
`e.getMessage()` — which is what an exception message is for, and what the README's own snippet at
`:280-282` warns against only in passing — leaks both the disclosure and the raw input.

Echoing unvalidated-by-this-class caller text into a rendered message is the second half of the
problem. Here the damage is limited because `validateUsername` (`:337-342`) anchors a conservative
`[A-Za-z0-9._-]` pattern via `Matcher.matches()`, so SQL metacharacters, control characters and HTML
cannot reach this string today — but the message's safety depends on a regex 350 lines away, and
nothing at the throw site records that dependency. The constructor does the same with
`"... got: " + algorithm` (`:117`), which is developer-supplied configuration and lower risk, but
still puts caller-controlled text into an exception message.

**Fix:**

Keep the exception distinguishable by type (callers need that) and carry the username in a field for
server-side audit, but remove user input from the message so the default rendering is safe:

```java
    /** Raised when an account with the requested username already exists. */
    public static final class DuplicateUsernameException extends Exception {

        private static final long serialVersionUID = 1L;

        private final String username;

        DuplicateUsernameException(String username) {
            // No user input in the message: callers render getMessage() directly, and the fact that
            // the name is taken is itself the account-exexistence disclosure. Rate-limit signup.
            super("username is not available");
            this.username = username;
        }

        /** For server-side logging and audit only. Never render this to a client. */
        public String usernameForAudit() {
            return username;
        }
    }
```

Then make the README's advice structural rather than advisory: put the rate-limit requirement next to
`registerUser`'s javadoc, not only in "Notes for production", and use a stable machine-readable
reason code if the front end must distinguish "taken" from a form error. Do the same at `:117` — name
the rejected value in a log line at the call site, keep the thrown message generic.

### SEC-05: Destructive `dropSchema` and cost-triggering `deriveMillis` are public on the production class

- **Severity:** Low
- **CWE:** CWE-489: Active Debug Code (also CWE-284: Improper Access Control — destructive and expensive operations left on the production API surface)
- **Location:** `UserAccountService.java:162`

**Vulnerable code:**

```java
    /** Removes the account table. Intended for tests and demos. */
    public void dropSchema(Connection connection) throws SQLException {
        try (Statement st = connection.createStatement()) {
            st.execute(DROP_TABLE);
        }
    }
```

**Why it is a problem:**

`DROP_TABLE` is `"DROP TABLE IF EXISTS " + TABLE` (`:81`) — the entire credential store — and the
only thing standing between a caller and that statement is a Javadoc sentence reading "Intended for
tests and demos". The method is `public`, on the same class the application wires up as a
long-lived singleton, reachable from any code that can see the `Connection` it already uses for
logins: a refactor, an admin endpoint that takes a connection from the pool, a copy-pasted teardown
line into a startup path, or a dependency-injection framework invoking a public no-argument-ish
method. There is no environment gate, no confirmation argument, and `IF EXISTS` makes a mistaken
call silent and idempotent rather than noisy.

`deriveMillis()` (`:292-299`) is the same category of mistake at lower stakes: it performs one real
key derivation with the instance's full iteration count — ~580 ms on the author's machine per
`README.md:291-292` — synchronously, on demand, from any caller, with nothing cached and no throttle.
Exposing it publicly turns a one-off tuning measurement into an unauthenticated-cost primitive;
`Demo.java:25-26` shows the pattern of calling it at startup, and a health check or metrics scrape
that copies it pays half a second of CPU per hit. It also bakes in a fixed probe passphrase
(`:294`), which is harmless but is exactly the shape of debug residue that CWE-489 covers.

**Fix:**

Remove both from the production API surface: move teardown into a nested maintenance type that
requires an explicit confirmation token, and make the timing measurement cached and non-public.

```java
    /** Destructive schema teardown. Not reachable without an explicit opt-in token. */
    public static final class SchemaMaintenance {

        public static final String CONFIRM_DROP = "DROP-APP-USER-TABLE";

        private final UserAccountService service;

        SchemaMaintenance() {
        }

        public void ensure(Connection connection) throws SQLException {
            try (Statement st = connection.createStatement()) {
                st.execute(CREATE_TABLE);
            }
        }

        public void drop(Connection connection, String confirmationToken) throws SQLException {
            if (!CONFIRM_DROP.equals(confirmationToken)) {
                throw new IllegalStateException(
                        "drop requires the explicit confirmation token; this deletes every account");
            }
            try (Statement st = connection.createStatement()) {
                st.execute(DROP_TABLE);
            }
        }
    }

    /** Schema lifecycle is a deployment concern, not an application-runtime one. */
    public SchemaMaintenance schemaMaintenance() {
        return new SchemaMaintenance();
    }

    private volatile long measuredMillis = -1L;

    /** One derivation cost, measured once per instance and cached; safe to call from a probe. */
    public long deriveMillis() {
        long cached = measuredMillis;
        if (cached >= 0L) {
            return cached;
        }
        synchronized (this) {
            if (measuredMillis < 0L) {
                char[] probe = new char[32];
                Arrays.fill(probe, 'x');
                byte[] salt = new byte[saltBytes];
                long start = System.nanoTime();
                derive(probe, salt, iterations, algorithm, hashBytes);
                measuredMillis = (System.nanoTime() - start) / 1_000_000L;
            }
            return measuredMillis;
        }
    }
```

`ensureSchema` may stay public if your deployment model wants it — it is idempotent and additive
(`CREATE TABLE IF NOT EXISTS`) — but `dropSchema` should not be reachable without intent, and
`UserAccountServiceTest.java` / `Demo.java` should call `schemaMaintenance().drop(c, CONFIRM_DROP)`
so a test typo cannot delete a real table.

### SEC-06: Demo hardcodes passphrases and prints the candidate password in clear

- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials (also CWE-532: Insertion of Sensitive Information into Log File)
- **Location:** `Demo.java:75`

**Vulnerable code:**

```java
    private static void authenticate(UserAccountService service, Connection connection,
            String username, String password) {
        try {
            boolean accepted = service.authenticate(connection, username, password);
            System.out.println((accepted ? "ACCEPTED     " : "REJECTED     ") + "'" + username
                    + "' with '" + password + "'");
```

**Why it is a problem:**

Every demonstration credential is a source literal — `"correct horse battery staple"` (`:32`),
`"trap' or 1=1 --oracle quote"` (`:33`), `"hunter2 hunter2 hunter2"` (`:34`),
`"a different passphrase here"` (`:49`), `"a long enough passphrase"` (`:52`, `:103`, `:109`) — and
line 76 interpolates the candidate password into the printed line. The severity is Low because this
is a demonstration program, not the library, and none of these values is a live credential; the risk
is in what readers copy. `Demo.java` is the file the README tells people to run, so its shape becomes
their shape: the same `println` reached a real log line becomes a credential sink that collects to a
log shipper, retains indefinitely, and is readable by operators, and `Demo.java` is exactly the file
whose output the README reproduces as expected behaviour. The manual secret sweep described in §3
returned *only* these literals, which is why they matter — they are the sole credentials in the
repository and the sole ones that can leak.

Three adjacent output issues in the same file reinforce the pattern rather than add findings:
`System.out.println("JDBC url : " + url)` (`:24`) prints the connection string, which in real use
carries host, port, database and frequently a `user=`/`password=` pair; `showStoredRows` prints hex
prefixes of stored salts and hashes (`:112-127`), which is a first-strength reduction if that output
is ever retained; and the passwords reach the KDF as `String`s (`:39-46`), forfeiting the zeroisation
the library went to the trouble of supporting.

**Fix:**

Print identity only, never the secret, and stop keeping passphrases as literals:

```java
    private static void authenticate(UserAccountService service, Connection connection,
            String username, char[] password) {
        try {
            boolean accepted = service.authenticate(connection, username, password);
            // Username and verdict only: the candidate password must never reach stdout or a log.
            System.out.println((accepted ? "ACCEPTED     " : "REJECTED     ") + "'" + username + "'");
        } catch (SQLException e) {
            throw new IllegalStateException("authentication failed", e);
        } finally {
            Arrays.fill(password, '\0');
        }
    }
```

Supply the demo passphrases from `System.console().readPassword()` or a clearly-labelled environment
variable instead of `:32-34`/`:49`/`:52-53`, use the `char[]` overloads throughout so the demo models
the safe call shape, and drop the stored-salt/hash hex (`:112-127`) down to a length-and-algorithm
summary. If the README's expected-output block (`:171`) changes as a result, update it — that block
is what a copy-pasting reader actually imitates.

### SEC-07: The single-row lookup never asserts that it got one row

- **Severity:** Low
- **CWE:** CWE-754: Improper Check for Unusual or Exceptional Conditions
- **Location:** `UserAccountService.java:246`

**Vulnerable code:**

```java
            try (ResultSet rs = select.executeQuery()) {
                if (!rs.next()) {
                    // Same cost as a real verification: an attacker timing logins cannot tell an
                    // existing account from a missing one.
                    burnKeyDerivation();
                    return false;
                }
                stored = readCredential(rs);
            }
```

**Why it is a problem:**

`SELECT_USER` is `"... WHERE username = ?"` (`:75-77`), and the safety of taking exactly one row from
it rests entirely on `username` being unique in whatever table the deployment created. Under
`ensureSchema` that holds, via `CONSTRAINT pk_app_user PRIMARY KEY (username)` (`:66`). But
`README.md:67-70` explicitly invites a different schema — "Skip `ensureSchema` and bring your own DDL
if you prefer -- the service only needs a table shaped like the one above" — and "shaped like"
describes the *columns*, not the constraint. On a BYO table without a unique index (or on an engine
where the column was made `VARCHAR(64)` with a case-insensitive collation, so `Alice` and `alice`
both land), one username can match two rows carrying *different* algorithms, iteration counts and
salts. The code consumes the first `rs.next()` and ignores the rest, so `authenticate` verifies the
password against whichever row the engine happened to return first — an identity decision made by
result ordering. Combined with SEC-01's permissive `readCredential`, the row selected could be the
cheapest one present.

The aggravating factor is assurance, not just probability: `README.md:206-213` advertises as a tested
guarantee "that a query returning two rows is refused instead of the first row being trusted", and
`UserAccountServiceJdbcContractTest.java:161-175` appears to prove it. It does not — the refusal is
implemented inside the test's own `Proxy` handler, which throws when its scripted row count exceeds
one:

```java
                            case "executeQuery":
                                script.selectExecutions++;
                                if (script.selectRowCount > 1) {
                                    throw new SQLException(
                                            "the single-row lookup received " + script.selectRowCount
                                            + " rows, so its predicate is not unique");
                                }
```

(`UserAccountServiceJdbcContractTest.java:603-609`.) Production never asks the question, so the test
passes against a fake's assertion instead of the library's behaviour — the same failure mode as
asserting that a mock validates input the code under test never validates.

**Fix:**

Assert single-rowness in production, and keep the refusal indistinguishable from a wrong password:

```java
            try (ResultSet rs = select.executeQuery()) {
                if (!rs.next()) {
                    burnKeyDerivation();
                    return false;
                }
                StoredCredential candidate = readCredential(rs);
                if (rs.next()) {
                    // More than one row matched, so `username = ?` is not unique in this schema and
                    // no single row is a safe identity. Refuse rather than trust result ordering.
                    burnKeyDerivation();
                    return false;
                }
                stored = candidate;
            }
```

Note the ordering above: read the candidate *before* consuming the second row so the refusal spends
the same KDF work as the normal path (`burnKeyDerivation()` alone would not restore parity if the
weak row were derived first). Then fix the assurance claim in both directions — correct
`README.md:206-213` to say the service *rejects* a multi-row result rather than implying the fake
tests it, move the multi-row assertion into `UserAccountServiceTest.java` against real H2 with a
non-unique DDL, and state the uniqueness requirement explicitly at `README.md:67-70` so BYO DDL
cannot silently drop the `PRIMARY KEY`.

## 6. Verified Controls and Checks With No Finding

- **No SQL injection surface.** All four statements plus DDL are `private static final` compile-time
  constants (`UserAccountService.java:58-81`); the only interpolated value in any of them is the
  hard-coded `TABLE` literal (`:56`). Every piece of external data reaches the database through a
  bound placeholder — `setString`/`setInt`/`setBytes` at `:197-201`, `setString` at `:244` and
  `:276` — and never as concatenated statement text. `UserAccountServiceJdbcContractTest.java:93-94`
  independently asserts no `TRIM(` or `COLLATE`, and the wider suite asserts no statement text ever
  contains user input.
- **No widened-match or second-order sink.** The lookup predicate is an exact equality on a bound
  parameter — no `LIKE`, no case folding, no `UPPER`/`LOWER` (`:73-77`) — so `alic_` cannot match
  `alice` and `Alice` cannot match `alice`; `Demo.java:44-46` and the real-engine suite exercise
  both. Stored values never flow back into SQL: the only column read back and *used* beyond
  comparison is `algorithm`, and it flows into `SecretKeyFactory.getInstance` under the bounds in
  `readCredential`, which is SEC-01 rather than an injection issue. `ensureSchema`/`dropSchema` use a
  plain `Statement` (not a `PreparedStatement`) but receive constant text with zero external input,
  so there is no stacked-query sink there either.
- **Correct cryptographic primitives where they are chosen.** `SecureRandom` (`:88`) seeds both the
  per-registration salt (`:185-186`) and the dummy password (`:407-413`); the salt is freshly drawn
  for every `registerUser` rather than reused, and the suite asserts fresh entropy per registration.
  Comparison of fixed-size derived keys uses `MessageDigest.isEqual` on both paths (`:264`, `:402`),
  which is length-independent and not an early-exit `Arrays.equals`/`==`. The shipped defaults
  (`:35`, `:42`, `:45`, `:48` — HMAC-SHA256, 310 000 rounds, 16-byte salt, 32-byte key) match
  current OWASP guidance; SEC-01 is about enforcing them, not about them being wrong.
- **Derivation-cost DoS closed on the stored-parameter axis.** `MAX_STORED_ITERATIONS = 20_000_000`
  (`:51`) rejects a corrupt row that would otherwise spin for minutes, the salt and hash length
  windows are bounded (`:317-320`), the algorithm must exist in the JVM before it is ever used, and
  a row naming an unavailable KDF routes to `burnKeyDerivation()` (`:255-260`) rather than throwing —
  `UserAccountServiceTest.java`'s malformed-row test confirms nine tampers are refused inside a
  seconds-scale budget rather than derived. SEC-01 is specifically that the *lower* end of the same
  screen is too permissive.
- **Credential disclosure from the object model is minimal.** The hash and salt are held in a
  `private` `StoredCredential` (`:447-460`) that is never handed to callers, and `Account` carries
  only username/algorithm/iterations with a `toString` (`:442`) that the suite pins as containing no
  secret material (`UserAccountServiceTest.java:88`). No method returns a stored hash, and neither
  password ever enters a bound parameter or statement text.
- **The caller's transaction stays the caller's.** The insert runs inside a savepoint created only
  when auto-commit is off (`:192-195`) and rolled back to that savepoint on failure (`:203-206`), so
  a taken username leaves the surrounding transaction usable on engines like PostgreSQL. The service
  never calls `commit`, `rollback`, `close` or `setAutoCommit` on the supplied connection — asserted
  by the contract suite — and unrelated `SQLException`s are rethrown unchanged rather than laundered
  into `DuplicateUsernameException` (`:207-210`), with the duplicate test split on the SQLState class
  23 check plus `SQLIntegrityConstraintViolationException` (`:326-335`) instead of message matching.
- **Username input is conservative and fully anchored.** `[A-Za-z0-9][A-Za-z0-9._-]{2,63}` (`:83`)
  applied through `Matcher.matches()` (`:337-342`) means a SQL metacharacter, wildcard, quote,
  separator or control character cannot reach an exception message, `Account.toString`, or (given
  constant SQL) any statement. Control characters are separately rejected in passwords (`:352-355`),
  and the null/empty-username path is forced through the constant-work branch (`:238-241`) instead of
  short-circuiting to a cheaper response.
- **Timing-equaliser design is sound (its hygiene is not).** The dummy credential is produced by
  running the real KDF rather than a hand-written constant (`:374-405`), so an unknown username, a
  corrupt row, an unsupported KDF and a wrong password all cost one genuine derivation and are not
  distinguishable by response time; a collision guard makes the dummy path fail loudly instead of
  authenticating. The two defects found there are reported as SEC-03 (retained secret) and are not
  correctness problems in the equalisation itself.
- **No live secrets in the repository.** The manual equivalent of the `gitleaks` Step 1 sweep across
  `*.java`, `*.md` and `*.txt` found no API keys, private keys, bearer tokens, connection strings
  with embedded credentials, or vendor key prefixes — the only credential-shaped literals are the
  demo passphrases reported as SEC-06.
- **Admitted trade-offs verified as such, not as bugs.** `README.md:131-135` (no breach-list check;
  `SecureRandom` can block on a starved entropy source), `:289-296` (account-existence disclosure on
  both failure paths, rate limiting belongs in front, one `Connection` per thread because `Connection`
  is not thread-safe while this class is) are documented, deliberate, and consistent with the code.
  `README.md:72-73` ("the password itself is never stored, never logged and never appears in any
  bound parameter or statement text") checks out for the library itself; the exceptions are in
  demo/README output (SEC-06) and in-memory lifetime (SEC-03), which is where the two findings sit.
