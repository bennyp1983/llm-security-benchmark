# Security Review: secure-jdbc-auth (Java 17 / PostgreSQL authentication CLI)

## 1. Executive Summary

`secure-jdbc-auth` is a Java 17 command-line authenticator. It reads an email address and a
masked password from a real terminal (it refuses redirected stdin and rejects all command-line
arguments), validates both strictly, opens a `SERIALIZABLE` PostgreSQL transaction, increments
two rate-limit buckets with atomic upserts, reads the credential row for the canonical email,
verifies the password with PBKDF2-HMAC-SHA-256 at 600,000 iterations, and prints only
`Authentication successful.` or `Authentication unsuccessful.`

The application code is materially stronger than typical generated output, and several headline
attack classes are genuinely closed rather than merely claimed: every SQL statement is a
parameterized `PreparedStatement`, the JDBC URL is built only from values matched against
character allow-lists so URL/property injection (including `sslmode` downgrade) is not reachable,
TLS hostname verification is hard-coded on, the iteration count is a compile-time constant so a
hostile database row can neither weaken nor amplify hashing work, unknown and disabled accounts
receive the same 600,000-iteration dummy hash, every user-visible failure string is identical,
and the grant is returned only after the serializable transaction commits. Findings below are
therefore concentrated in policy, availability, and cleanup/error-handling hygiene rather than in
injection or broken-cryptography defects.

The most important results:

- **No password-strength requirement is enforceable anywhere in scope.** The login path accepts a
  single-character password (correctly, for compatibility), but the provisioning policy that is
  supposed to compensate exists only as README prose — no code, schema constraint, or test in the
  repository enforces it. A weak credential provisioned under a permissive policy is offline
  crackable despite 600,000 iterations.
- **Dependency integrity is not enforced by the build.** The SHA-512 check the README's own threat
  model relies on to defeat "dependency replacement" is a manual shell step that nothing binds to
  the Maven lifecycle; `mvn package` and `java -cp ...` succeed without it, and no CVE freshness
  gate exists.
- **The "per-source" throttle is not per-source.** `SOURCE_BUCKET` is a compile-time constant, so
  the 10/minute source allowance is one global counter shared by every process that touches the
  database; any caller can burn it and make every other caller's correct password fail closed for
  the rest of the minute. Attackers can additionally spend a known victim's 5/minute account
  allowance. This is the lockout-by-rate-limiter outcome the brief explicitly forbade.
- Two lower-severity defects: the credential hash/salt are not cleared when an error is thrown
  between the row read and the verification `try`/`finally`, and `main` does not catch unchecked
  throwables, so the JVM's own stack trace reaches stderr in contradiction of the documented
  "generic message to the user, details to the log" control.

No SQL injection, no reachable authentication bypass, no weak or misused cryptography, and no
hardcoded working credential were found.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/example/security/SecureAuthApplication.java` | CLI entry point: reads email/password, prints the auth verdict | Rejects all CLI args and non-terminal stdin; `Console.readPassword` (char[]); narrow catch clause; clears password in `finally`; logs only an exception class name |
| `src/main/java/example/security/AuthenticationService.java` | Core authentication transaction | Per-source and per-account rate-limit upserts, credential read, verify-then-commit grant, hardcoded source bucket, credential-array clearing |
| `src/main/java/example/security/PasswordVerifier.java` | PBKDF2-HMAC-SHA-256 verification | 600,000 iterations pinned in code, 16-byte salt / 32-byte hash enforced, `SecureRandom` dummy material, constant-time `MessageDigest.isEqual`, dummy hashing for invalid/unknown/disabled records |
| `src/main/java/example/security/InputValidator.java` | Strict allow-list validation of email, password, host, port, SQL identifiers | Regex allow-lists, ASCII/control-char and UTF-8 byte bounds, surrogate-pair checks, lowercase canonicalisation of email |
| `src/main/java/example/security/DatabaseConfig.java` | Builds JDBC URL and connection properties from environment | String-concatenated JDBC URL from validated env values; hard-coded `sslmode=verify-full`, `connectTimeout`, `socketTimeout`; no password property |
| `src/main/java/example/security/CredentialRecord.java` | Immutable holder for a credential row | Carries `salt`/`passwordHash` byte arrays whose lifetime/clearing is the caller's responsibility |
| `src/test/java/example/security/SecuritySelfTest.java` | Self-test harness | Asserts SQLi-shaped and URL-parameter-shaped emails are rejected, verifier rejects null/unknown records, arrays zeroised |
| `database/schema.sql` | PostgreSQL schema and grants | Check constraints pinning algorithm/iterations/salt/hash sizes, lowercase-email CHECK, limiter bounds, least-privilege `auth_runtime` grants |
| `pom.xml` | Build definition, sole runtime dependency | Pins `org.postgresql:postgresql:42.7.13` at `runtime` scope; no checksum/signature or CVE gate wired into any lifecycle phase |
| `scripts/verify-pgjdbc.sh` | Out-of-band JAR integrity check | Compares the resolved pgJDBC JAR against a repository-pinned SHA-512 digest; not invoked by the build |
| `README.md` | Threat model, input inventory, control mapping | Documents provisioning-password policy and driver-verification procedure as prose requirements (unenforced) |
| `.gitignore` | VCS hygiene | Excludes `target/`, `*.log`, `*.jfr`, `hs_err_pid*`, `core`/`core.*` (core-dump artefacts) |
| `prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Generation-task metadata | Reviewed for embedded secrets/credentials; none present (only placeholders such as `db.example.internal`, `auth_runtime`, and a public SHA-512 digest) |
| `target/` | Build output (pre-built JAR, classes) | Not reviewed as source and not executed; treated as untrusted build artefact |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordVerifier.java` and
  `DatabaseConfig.java` — KDF algorithm and parameter strength (PBKDF2-HMAC-SHA-256 / 600,000 /
  16-byte salt / 256-bit tag), constant-time comparison, `SecureRandom` entropy for the dummy
  salt and dummy password, absence of deprecated primitives (MD5/SHA-1 for security, DES/RC4, ECB),
  hardcoded-key search, and TLS protocol/configuration strength on the database channel. The
  skill's own `references/` contain no PBKDF2 parameter table, so iteration-count adequacy was
  judged against general current practice (OWASP-style guidance).
- `exploiting-sql-injection-vulnerabilities`: applied to both SQL statements in
  `AuthenticationService.java` (`incrementBucket`, `readCredential`) and to the concatenated JDBC
  URL in `DatabaseConfig.java`, following the skill's injection-point-discovery checklist
  (input-vector mapping, error/boolean/time/second-order vectors) statically, using its
  parameterized-query definition as the pass criterion.
- `testing-api-authentication-weaknesses`: applied to the authentication mechanism as a whole —
  mechanism identification, token/session-lifecycle and leakage checks (steps 2–5 are
  not applicable: no JWT, API key, OAuth, or cookie exists), and step 6's weak-password-policy and
  account-enumeration differential tests.
- `testing-for-broken-access-control`: applied to the decision path that produces the security
  outcome (`inputValid && allowed && passwordMatches` plus the `enabled` flag) to test for
  fail-open defaults, missing checks, and privilege/tenant isolation gaps.
- `exploiting-race-condition-vulnerabilities`: applied to the rate-limited-login attack surface
  named in its step 1 target list, testing the check-then-act window for limit overrun across the
  bucket increment, credential verification, and commit.
- `testing-for-sensitive-data-exposure`: applied to stdout/stderr and logger output (masking and
  redaction), to memory handling of the password and credential arrays, to the database transmission
  channel, and to the repository as a whole for committed secrets.
- `detecting-dependency-confusion`: applied to `pom.xml` — manifest inventory, whether the declared
  coordinate is a claimable internal-sounding name, and whether registry/mirroring and CI
  enforcement meet the skill's validation criteria.
- `performing-supply-chain-attack-simulation`: applied to the dependency workflow — package-hash
  verification adequacy and the skill's known-CVE scanning criterion.
- `implementing-secret-scanning-with-gitleaks`: applied as the hardcoded-secret checklist across
  Java, SQL, XML, shell, Markdown, and `.gitignore`; no gitleaks custom-rule gap for
  organization-specific secrets was needed because no credential material exists in the tree.
- **Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched:**
  email/DNS/SQL-identifier canonicalisation semantics and cross-service policy mismatch (RFC 5321
  local-part case sensitivity); rate-limiter design quality (fixed window vs sliding window,
  counter-key trustworthiness, attacker-spendable quotas, limiter storage growth); uncaught
  unchecked throwables and JVM default stack-trace output as an information channel; sensitive-data
  lifetime on error paths (incomplete cleanup); and availability/resource-exhaustion limits on
  limiter rows, password length, and row-lock hold time. The library's remaining matches in this
  area were offensive/ops tooling (sqlmap, Burp, Splunk, MISP) with no applicable checklist, so the
  relevant skill knowledge was applied as concepts only and none of their helper scripts were run
  against this Java code.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | No enforceable password-strength policy: login accepts 1-character passwords and nothing in scope constrains provisioning | Medium | CWE-521 | `src/main/java/example/security/InputValidator.java:41-43` |
| SEC-02 | Runtime dependency integrity check is not enforced by the build; no CVE freshness gate | Medium | CWE-494 | `pom.xml:17-22` |
| SEC-03 | "Per-source" throttle keyed to a compile-time constant, and per-account counters are attacker-spendable: legitimate users can be locked out | Medium | CWE-307 | `src/main/java/example/security/AuthenticationService.java:19` |
| SEC-04 | Credential hash and salt are not zeroised when an error is thrown between the row read and the verification `try`/`finally` | Low | CWE-459 | `src/main/java/example/security/AuthenticationService.java:43-58` |
| SEC-05 | `main` catches only three checked/unchecked types, so other throwables reach the JVM handler and print a stack trace to stderr | Low | CWE-209 | `src/main/java/example/security/SecureAuthApplication.java:42-46` |
| SEC-06 | Email canonicalisation lowercases the local part, merging RFC case-distinct principals onto one account key | Low | CWE-287 | `src/main/java/example/security/InputValidator.java:38` |

## 5. Detailed Findings

### SEC-01: No enforceable password-strength policy: login accepts 1-character passwords and nothing in scope constrains provisioning

- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/example/security/InputValidator.java:41-43` (login-side acceptance), with the compensating control absent from `database/schema.sql` and present only as prose in `README.md`

**Vulnerable code:**
```java
// src/main/java/example/security/InputValidator.java:41-43
    static boolean validPassword(char[] password) {
        if (password == null || password.length == 0 || password.length > 1024) {
            return false;
        }
```

**Why it is a problem:** `validPassword` is a well-designed *parser* — it bounds the input at 1024
UTF-8 bytes (defeating PBKDF2 work amplification), rejects NUL and control characters, and rejects
unpaired surrogates. It is not a *policy*: a single-character password such as `a` passes, and so do
`password`, `12345678`, and every other entry in the weak-credential class. Being login-only, the
component is right to stay permissive so existing credentials keep working — but then the entropy
guarantee must live in the credential-provisioning path, and in this repository that path is pure
documentation. `README.md` states only that "Provisioning should enforce a stronger new-password
policy (for example at least 15 characters)", and `database/schema.sql` constrains the algorithm,
iteration count, salt length, and hash length (`database/schema.sql:5-8`) but has no way to reject a
hash of a one-character password, so no artifact in scope can fail a weak provisioning run. The
result is that a single permissive provisioning deployment silently defeats the KDF: 600,000
iterations of PBKDF2-HMAC-SHA-256 over a low-entropy secret is still cracked essentially instantly,
and because the table is keyed by canonical email with `enabled` available for bulk checks, one
`app_user` dump becomes mass account-takeover risk. The application's own threat model already
assumes hostile database rows are in scope, so relying on an unversioned, untested sibling service
for the one control that protects stored credentials is the weak link.

**Fix:** Put the policy in code that is shipped, unit-tested, and shared with the audited
provisioning service, and add a schema backstop so a row cannot exist unless it was created under
that policy version. Do not tighten `validPassword` — keep it permissive on the login path.
```java
// New file: src/main/java/example/security/PasswordPolicy.java
package example.security;

/** Policy for NEW credentials only. Never call this from the login path. */
public final class PasswordPolicy {
    public static final int MIN_CHARS = 15;
    public static final int POLICY_VERSION = 1;

    private PasswordPolicy() {}

    /** Rejects short and single-character-class credentials before they are ever hashed. */
    public static void requireAcceptable(char[] password) {
        if (!InputValidator.validPassword(password) || password.length < MIN_CHARS) {
            throw new IllegalArgumentException("password does not meet provisioning policy");
        }
        int classes = 0;
        for (char c : password) {
            if (Character.isLowerCase(c)) classes |= 1;
            else if (Character.isUpperCase(c)) classes |= 2;
            else if (Character.isDigit(c)) classes |= 4;
            else classes |= 8;
        }
        if (Integer.bitCount(classes) < 2) {
            throw new IllegalArgumentException("password does not meet provisioning policy");
        }
    }
}
```
```sql
-- database/schema.sql: a row may only exist if it was written under the enforced policy
    password_policy_version integer NOT NULL DEFAULT 0
        CHECK (password_policy_version >= 1),
```
The provisioning service is then required to call `PasswordPolicy.requireAcceptable` and to write
`password_policy_version = PasswordPolicy.POLICY_VERSION`; because the `DEFAULT 0` fails the
`CHECK`, any provisioning path that skips the policy cannot insert a row at all, which converts the
README's advice into an enforced invariant. Add `PasswordPolicy` assertions to
`SecuritySelfTest` so a future relaxation breaks the build.

### SEC-02: Runtime dependency integrity check is not enforced by the build; no CVE freshness gate

- **Severity:** Medium
- **CWE:** CWE-494: Download of Code Without Integrity Check
- **Location:** `pom.xml:17-22` (the dependency and its lifecycle); the unbound check at `scripts/verify-pgjdbc.sh:4-5`

**Vulnerable code:**
```xml
  <!-- pom.xml:15-23 -->
  <dependencies>
    <!-- Official pgJDBC release; verify it as described in README.md before use. -->
    <dependency>
      <groupId>org.postgresql</groupId>
      <artifactId>postgresql</artifactId>
      <version>42.7.13</version>
      <scope>runtime</scope>
    </dependency>
  </dependencies>
```

**Why it is a problem:** The README's threat model explicitly names "dependency replacement" and
"the contents of downloaded dependencies" as attacker-controlled, and its stated mitigation is
`sh scripts/verify-pgjdbc.sh` between `dependency:go-offline` and the build. That script does the
right thing in isolation — it compares the resolved JAR against a SHA-512 digest pinned *in the
repository* (`scripts/verify-pgjdbc.sh:5`), which is a genuine out-of-band trust anchor rather than
a digest fetched from the same channel as the artifact — but nothing in `pom.xml` ever invokes it.
No `<plugin>` binds it to `validate`, `verify`, or `package`, there is no `maven-enforcer-plugin`
rule, no checksum/`<markers>` configuration, and no CI definition in the tree. Consequently the
documented sequence is advisory: `mvn --no-transfer-progress clean test package`,
`dependency:copy-dependencies`, and the final `java -cp 'target/secure-jdbc-auth-1.0.0.jar:target/dependency/*'`
all succeed with an unverified — potentially substituted — driver on the classpath. Because this
component's entire security guarantee is the code that runs *inside* the JDBC connection, a
substituted driver can observe or alter the credential query, the rate-limit upserts, and the
transaction outcome while the application code still behaves perfectly, so the control the design
depends on being optional is the finding. The same gap covers currency: the build has no
dependency-vulnerability gate, so if a pgJDBC advisory is published after this pin, resolution
stays silent and the "verify downloaded files before using them" rule is satisfied only for
bit-integrity, not for known weakness. (No dependency-confusion or typosquat exposure exists here:
`org.postgresql:postgresql` is a registered upstream coordinate that cannot be claimed on a public
registry.)

**Fix:** Bind the existing verification into the lifecycle so a skipped or failing check fails the
build, and add a CVE/freshness gate. The `<dependencies>` block above is unchanged; add to
`pom.xml`:
```xml
      <!-- Runs before compilation: build fails if the driver digest does not match. -->
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.5.0</version>
        <executions>
          <execution>
            <id>verify-pgjdbc-digest</id>
            <phase>validate</phase>
            <goals><goal>exec</goal></goals>
            <configuration>
              <executable>sh</executable>
              <arguments>
                <argument>${project.basedir}/scripts/verify-pgjdbc.sh</argument>
              </arguments>
            </configuration>
          </execution>
        </executions>
      </plugin>
      <!-- Fails the build when the pinned driver has a known exploited/CVE record or is superseded. */
      <plugin>
        <groupId>org.owaf</groupId>
        <artifactId>dependency-check-maven</artifactId>
        <version>10.0.4</version>
        <configuration>
          <failBuildOnCVSS>4</failBuildOnCVSS>
        </configuration>
        <executions>
          <execution><phase>verify</phase><goals><goal>check</goal></goals></execution>
        </executions>
      </plugin>
```
(Confirm plugin coordinates/versions from your internal mirror, pin them, and mirror resolution
through one `<mirrorOf>*</mirrorOf>` repository in `settings.xml` so a public registry cannot shadow
the build.) Keep `runtime` scope, and record the verified digest in an SBOM/provenance attestation
so a distribution can be checked post-build rather than only at build time.

### SEC-03: "Per-source" throttle keyed to a compile-time constant, and per-account counters are attacker-spendable: legitimate users can be locked out

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/example/security/AuthenticationService.java:19` (key definition), `src/main/java/example/security/AuthenticationService.java:38-39`, `src/main/java/example/security/AuthenticationService.java:45-47`, `src/main/java/example/security/AuthenticationService.java:60-62`

**Vulnerable code:**
```java
// src/main/java/example/security/AuthenticationService.java:16-19
    private static final int SOURCE_LIMIT_PER_MINUTE = 10;
    private static final int ACCOUNT_LIMIT_PER_MINUTE = 5;
    private static final String INVALID_EMAIL = "invalid@invalid.invalid";
    private static final String SOURCE_BUCKET = digest("server-defined:local-console:v1");
```
```java
// src/main/java/example/security/AuthenticationService.java:38-47, 60-62
                int sourceAttempts = incrementBucket(connection, "source", SOURCE_BUCKET);
                boolean sourceBlocked = sourceAttempts > SOURCE_LIMIT_PER_MINUTE;
                // Once the source is blocked, collapse attacker-chosen account keys and queries to
                // constants. This bounds database growth while preserving comparable failure work.
                String emailForQuery = sourceBlocked ? INVALID_EMAIL : canonical.orElse(INVALID_EMAIL);
                CredentialRecord record = readCredential(connection, emailForQuery);
                // Unknown accounts share one bucket. Only a server-side credential row can cause
                // a distinct persistent account key to be created.
                String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
                int accountAttempts = incrementBucket(connection, "account", accountBucket);
...
                boolean allowed = !sourceBlocked && accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
                boolean authenticated = inputValid && allowed && passwordMatches;
                connection.commit(); // No success is returned unless all checks commit atomically.
```

**Why it is a problem:** The counter key is not derived from any source identity — it is the SHA-256
of a hard-coded string literal, identical in every process, on every host, forever. So the
"per-source" limit is really a single global 10-attempts-per-minute budget for the whole database,
which is the shared state that `README.md` itself describes (one `app_user` table and one
`auth_rate_limit` table for `auth_runtime`, with multiple CLI instances expected to point at it).
Any caller able to invoke the program — a second administrator's session, a scheduled job, or a
user on a shared host — can consume all ten slots in one minute and, because `sourceBlocked` then
replaces the query email with `INVALID_EMAIL` (`emailForQuery`) and forces `allowed = false`,
**every** other caller is denied authentication for the remainder of that minute *even with a
correct password*. There is no actor distinction and no backstop that distinguishes one heavy actor
from the rest of the population, so the control is trivially weaponised against availability rather
than against guessing. The same weakness applies one level down: `accountBucket` is derived from the
supplied email whenever a real credential row exists, so anyone who knows a victim's address can
deliberately consume that victim's 5-per-minute allowance and lock them out — precisely the outcome
the engagement rules forbade ("so an attacker cannot use your own limit to lock a legitimate user
out"). The design does contain real mitigations, which is why this is Medium rather than High: the
windows are one minute rather than persistent lockouts, storage is bounded (unknown addresses
collapse into one bucket, rows are reused), and the collapse behaviour is what makes the storage
bound possible — but the residual is that the person who decides *who is limited* is the attacker's
request itself, and an unauthenticated party can turn the authentication control off for everyone.

**Fix:** Derive the source key from a source identity that the caller cannot choose, and keep a
separate, deliberately generous global backstop so no single actor can impose their allowance on
everyone else. The collapse-to-constant behaviour for unknown accounts must stay, since it is what
bounds limiter storage.
```java
// AuthenticationService: per-actor source identity supplied by the deployment, never by the caller.
    private static final int GLOBAL_BACKSTOP_PER_MINUTE = 500;
    private static final String GLOBAL_BUCKET = digest("server-defined:global:v1");
    private final String sourceBucket;

    AuthenticationService(DatabaseConfig config, String deploymentSourceId) throws GeneralSecurityException {
        this.config = config;
        this.passwordVerifier = new PasswordVerifier();
        // deploymentSourceId comes from server-side state the caller cannot forge: the OS login
        // and host the deployment launched this process as, or, for a network service, a
        // connection identity attested by the trusted edge -- never a client-supplied header.
        this.sourceBucket = digest("server-defined:source:v1:" + deploymentSourceId);
    }

// authenticate(): per-actor limit plus a global backstop; collapse behaviour preserved.
                int sourceAttempts = incrementBucket(connection, "source", sourceBucket);
                int globalAttempts = incrementBucket(connection, "source", GLOBAL_BUCKET);
                boolean sourceBlocked = sourceAttempts > SOURCE_LIMIT_PER_MINUTE;
                boolean backstopTripped = globalAttempts > GLOBAL_BACKSTOP_PER_MINUTE;
                String emailForQuery = (sourceBlocked || backstopTripped)
                        ? INVALID_EMAIL : canonical.orElse(INVALID_EMAIL);
                CredentialRecord record = readCredential(connection, emailForQuery);
                String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
                int accountAttempts = incrementBucket(connection, "account", accountBucket);
                ...
                boolean allowed = !sourceBlocked && !backstopTripped
                        && accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
```
Additionally make the per-account limiter cost the attacker more than the victim: exclude
already-successful authentications from the account budget, and combine the fixed window with the
per-account ceiling only after the per-actor source budget is exhausted, so spraying one address
from one source burns the attacker's own allowance before the victim's. For any deployment that
becomes a network service, apply the same rule the README already states — the source key must come
from edge-attested state, never from a client header.

### SEC-04: Credential hash and salt are not zeroised when an error is thrown between the row read and the verification `try`/`finally`

- **Severity:** Low
- **CWE:** CWE-459: Incomplete Cleanup (sensitive material not removed from memory; cf. CWE-226)
- **Location:** `src/main/java/example/security/AuthenticationService.java:43-58`

**Vulnerable code:**
```java
// src/main/java/example/security/AuthenticationService.java:43-58
                CredentialRecord record = readCredential(connection, emailForQuery);
                // Unknown accounts share one bucket. Only a server-side credential row can cause
                // a distinct persistent account key to be created.
                String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
                int accountAttempts = incrementBucket(connection, "account", accountBucket);
                boolean passwordMatches;
                char[] boundedPassword = passwordValid ? password : "invalid-input-placeholder".toCharArray();
                try {
                    passwordMatches = passwordVerifier.verify(boundedPassword, record);
                } finally {
                    if (boundedPassword != password) {
                        Arrays.fill(boundedPassword, '\0');
                    }
                    if (record != null) {
                        clear(record.salt(), record.passwordHash());
                    }
                }
```

**Why it is a problem:** The `finally` block that zeroes `record.salt()` and `record.passwordHash()`
does not start until line 50, but line 47 calls `incrementBucket(...)`, which is declared
`throws SQLException` and throws deliberately on several reachable conditions — the
`"invalid rate limit state"` and `"rate limit update returned no row"` guards inside
`incrementBucket`, a lost connection, or a `SERIALIZABLE` serialization failure against the contended
limiter row. When it throws, control leaves `authenticate()` immediately (the inner catch rolls back
and rethrows, and `SecureAuthApplication` prints the generic failure), so the `finally` at lines
52-58 never executes and the 32-byte password hash plus its 16-byte salt survive in the heap until
GC. `SecureAuthApplication`'s own `finally` clears only the `password` array, never the record. This
directly contradicts the README's claim that "all reachable password/hash/salt arrays are
overwritten in `finally` blocks", and the same gap applies if anything between the read and the
`try` fails. It is rated Low because the residual material is a strong hash and salt rather than the
password, the process is deliberately short-lived, exploiting it requires heap or core-dump access
(which already implies the trusted-host boundary is broken), and the README already instructs
operators to disable core dumps — but the defect is real, it is on the error path (the paths least
likely to be exercised in testing), and the fix is free.

**Fix:** Make the record's lifetime strictly cover every statement that can fail after acquisition,
by acquiring it inside the same `try` whose `finally` clears it, and compute the verdict inside that
`try` so no variable needs to escape it.
```java
                CredentialRecord record = null;
                boolean authenticated;
                try {
                    record = readCredential(connection, emailForQuery);
                    // Unknown accounts share one bucket (storage bound preserved).
                    String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
                    int accountAttempts = incrementBucket(connection, "account", accountBucket);
                    char[] boundedPassword =
                            passwordValid ? password : "invalid-input-placeholder".toCharArray();
                    boolean passwordMatches;
                    try {
                        passwordMatches = passwordVerifier.verify(boundedPassword, record);
                    } finally {
                        if (boundedPassword != password) {
                            Arrays.fill(boundedPassword, '\0');
                        }
                    }
                    boolean allowed = !sourceBlocked && accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
                    authenticated = inputValid && allowed && passwordMatches;
                } finally {
                    // Runs whether or not the limiter upsert, verify, or any later check throws.
                    if (record != null) {
                        clear(record.salt(), record.passwordHash());
                    }
                }
                connection.commit(); // No success is returned unless all checks commit atomically.
                return authenticated;
```
Add a self-test that injects a failing limiter (a stub connection whose second `executeQuery` throws)
and asserts the record's arrays are zeroised, so the invariant is enforced by the build rather than
by the README.

### SEC-05: `main` catches only three types, so other throwables reach the JVM handler and print a stack trace to stderr

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information (uncontrolled error output; cf. CWE-1295)
- **Location:** `src/main/java/example/security/SecureAuthApplication.java:42-46`

**Vulnerable code:**
```java
// src/main/java/example/security/SecureAuthApplication.java:42-46
        } catch (IllegalArgumentException | SQLException | GeneralSecurityException failure) {
            // Never log supplied values, SQL text, connection details, or exception messages.
            LOGGER.log(Level.SEVERE, "Authentication failed safely; event type={0}",
                    failure.getClass().getSimpleName());
            System.out.println(FAILURE);
        } finally {
```

**Why it is a problem:** The catch list is deliberately narrow and the log line inside it is exactly
right — one event type, no message text, no values, and `DatabaseConfig` throws
`IllegalArgumentException` with the fixed string `"invalid database configuration"` rather than
echoing the offending environment value, so no configuration or credential data leaks through the
handled path. But the design does not close the *unhandled* path. `Console.readLine` and
`Console.readPassword` are documented to throw `java.io.IOError`, an unchecked error, when the
underlying terminal I/O fails, and class initialisation of `AuthenticationService` (whose static
field `SOURCE_BUCKET` is computed by `digest(...)`, which itself throws
`ExceptionInInitializerError`) or driver loading can raise `Error`/`RuntimeException` types outside
the three caught here. None of these are caught, so the JVM's default uncaught-throwable handler
writes the throwable's class, its detail message, and a full stack trace to `stderr` *in addition to*
the generic line, and the process exits non-zero. In the deployments this README recommends — a
service unit or a wrapper that redirects `stderr` into a log — that trace lands in an operator-
readable destination containing internal structure and any detail message the driver or console
layer attached, which is exactly what "Report errors to users in generic terms; details go to the
log only" is meant to prevent. The credential itself is not exposed: the `finally` at lines
47-50 still clears `password`, and the observed messages would be environmental rather than
secret-bearing, which is why this is Low. It is still a real deviation from a stated control and it
is the one finding here that also defeats the "identical failure presentation" property, since an
uncaught throwable produces a very different observable outcome from `Authentication unsuccessful.`

**Fix:** Terminate `main` with a catch-all that preserves the existing single-event-type logging and
the generic user-facing string, while letting true VM-level faults propagate; and set a default
uncaught-exception handler so no path can print a trace.
```java
            try (AuthenticationService service = new AuthenticationService(config)) {
                System.out.println(service.authenticate(email, password)
                        ? "Authentication successful."
                        : FAILURE);
            }
        } catch (IllegalArgumentException | SQLException | GeneralSecurityException failure) {
            // Never log supplied values, SQL text, connection details, or exception messages.
            LOGGER.log(Level.SEVERE, "Authentication failed safely; event type={0}",
                    failure.getClass().getSimpleName());
            System.out.println(FAILURE);
        } catch (Throwable failure) {
            // IOError from Console, linkage/init errors, driver runtime faults: same generic
            // outcome, single event type, and never the JVM's own stack trace on stderr.
            if (failure instanceof VirtualMachineError virtualMachineError) {
                throw virtualMachineError;
            }
            LOGGER.log(Level.SEVERE, "Authentication failed safely; event type={0}",
                    failure.getClass().getSimpleName());
            System.out.println(FAILURE);
        } finally {
```
For a service deployment, also redirect `System.setErr(...)` to the logger (or run under a supervisor
with `StandardError=journal` and strict log access controls) and set
`-XX:-ShowCodeDetailsInExceptionMessages` so the JDK's helpful-NullPointerException text cannot
reproduce operand values in any trace that does reach a destination.

### SEC-06: Email canonicalisation lowercases the local part, merging RFC case-distinct principals onto one account key

- **Severity:** Low
- **CWE:** CWE-287: Improper Authentication (identity merge through lossy canonicalisation; cf. CWE-694)
- **Location:** `src/main/java/example/security/InputValidator.java:38`, with the policy hard-wired at `database/schema.sql:10`

**Vulnerable code:**
```java
// src/main/java/example/security/InputValidator.java:38
        return Optional.of(local.toLowerCase(Locale.ROOT) + "@" + domain.toLowerCase(Locale.ROOT));
```

**Why it is a problem:** Lowercasing the *domain* is correct — DNS labels are case-insensitive — but
RFC 5321 §2.4 defines the local part as case-sensitive, and the validation immediately above
(`LOCAL`, lines 9 and 24-27) deliberately admits `.` and the other dot-atom specials precisely so
address variants remain distinguishable. Because both halves are folded and `database/schema.sql:10`
then asserts `CHECK (email_canonical = lower(email_canonical))`, the database's own primary key
cannot represent the distinction either. The consequence is an identity merge that is only safe as
long as the out-of-repo provisioning service folds identically — a requirement expressed as the
single sentence "Provisioning must use the same policy", with no shared constant, no test, and no
schema support linking the two sides. A case-preserving provisioning service (which is what an
RFC-conformant mail-adjacent system naturally is) can hold two distinct humans, `A.Smith@corp` and
`a.smith@corp`, who map to one primary key: the second provision either fails silently or, if it
upserts, overwrites the first human's hash — after which either party's password authenticates the
other, which is an authentication failure rather than a data problem. This is Low because the
codebase is internally consistent, the invariant is documented, and the PRIMARY KEY prevents a
*silent* duplicate from being stored; it is still reportable because the security outcome rests on
an unenforced cross-service assumption and the failure mode is authenticating as the wrong principal.

**Fix:** Fold only the domain, keep the local part byte-exact, and make both the runtime and the
schema express that single policy so provisioning cannot diverge silently.
```java
// src/main/java/example/security/InputValidator.java
        // RFC 5321: the local part is case-sensitive; only the domain is folded. Folding the
        // local part merges distinct principals onto one account key.
        return Optional.of(local + "@" + domain.toLowerCase(Locale.ROOT));
```
```sql
-- database/schema.sql: the lowercase CHECK must no longer cover the local part,
-- otherwise the schema forbids the only canonical form that preserves identity.
-- Replace CHECK (email_canonical = lower(email_canonical)) with a domain-only check:
    CHECK (substring(email_canonical from position('@' in email_canonical))
           = lower(substring(email_canonical from position('@' in email_canonical))),
```
Move the canonicalisation into one shared, unit-tested routine that the provisioning service is
required to import (as in SEC-01's `PasswordPolicy` pattern), and add a self-test asserting that
`A.Smith@Corp.COM` and `a.smith@corp.com` canonicalise to *different* keys while
`A.Smith@CORP.COM` and `a.smith@corp.com` canonicalise to the same one. If the organisation's
policy is deliberately to treat local parts case-insensitively, then enforce it in that shared
routine and assert the corresponding collision behaviour in a test, rather than leaving it implicit.

## 6. Verified Controls and Checks With No Finding

- **SQL injection (all statements, both directions):** `incrementBucket`
  (`AuthenticationService.java:75-99`) and `readCredential` (`AuthenticationService.java:102-130`)
  are text-block `PreparedStatement`s with `?` placeholders and `setString` binding — no user value
  is ever concatenated into SQL text. Emails containing the skill's discovery payloads
  (`x' OR 1=1--@example.com`) are rejected earlier by `InputValidator`, and even if one were not, it
  would reach the driver only as a bound parameter. Second-order injection is not reachable: the
  program never stores user-supplied text — the only `INSERT` writes server-computed SHA-256 digests.
  `SecuritySelfTest` asserts the quote-bearing address is rejected.
- **JDBC URL / connection-property injection and TLS downgrade:** `DatabaseConfig.java:14-15`
  concatenates four environment values into the URL, which is the one string-construction site in the
  program. All four are matched against character allow-lists that exclude `?`, `&`, `=`, `#`, `/`,
  `:`, `@`, `%`, whitespace, and control characters — `HOST` (`InputValidator.java:11`, plus the
  explicit `..` rejection at line 69), `SQL_IDENTIFIER` (line 12), port `[0-9]{1,5}` with a 1–65535
  range check (lines 79-87) — so `?sslmode=disable`, an injected `socketFactory`, or a
  `loggerLevel`/`logserver` property cannot be smuggled in, and `sslmode=verify-full`,
  `connectTimeout=5`, `socketTimeout=10` cannot be overridden. pgJDBC does not read libpq `PG*`
  environment variables, so the URL parameter is authoritative. `SecuritySelfTest` confirms
  `a@example.com?sslmode=disable` is rejected. Residual (not a finding): verification uses the JVM
  default trust store, so any publicly trusted CA is accepted — pin the internal CA with
  `sslrootcert`/a dedicated trust store for production.
- **Cryptographic strength and misuse:** PBKDF2-HMAC-SHA-256 at 600,000 iterations with a 16-byte
  salt and 256-bit derived key (`PasswordVerifier.java:11-14`) is within current guidance, not a
  weak-KDF finding; the iteration count passed to `derive` is the compile-time constant
  (`PasswordVerifier.java:41`), never `record.iterations()`, so a hostile row cannot lower work — and
  `validRecord` independently requires exactly 600,000 iterations, exact algorithm name, and exact
  16/32-byte lengths before any comparison. Comparison uses `MessageDigest.isEqual`
  (`PasswordVerifier.java:43`), avoiding a length/value short-circuit (CWE-208). Dummy salt and dummy
  password are generated with `SecureRandom` (`PasswordVerifier.java:19-22`), not fixed or time-based
  (CWE-338). No MD5/SHA-1 for security purposes, no block cipher, no ECB, no RSA/AES key handling, no
  deprecated protocol. SHA-256 in `AuthenticationService.digest` is used only as a fixed-length
  bucket label, not as an integrity or signature primitive, which is appropriate.
- **Fail-closed authentication decision (access control):** `authenticated = inputValid && allowed &&
  passwordMatches` (`AuthenticationService.java:61-62`) requires every check positively; the
  `enabled` flag, algorithm, iteration count, and salt/hash lengths all come from the database row
  (`PasswordVerifier.java:33-38`), and a `null` record, a disabled account, a corrupt row, a duplicate
  row, `NULL` iterations/`enabled` (`result.wasNull()` at `AuthenticationService.java:118-124`), a
  database error, or missing configuration each produce a denial. There is no permissive default, no
  fail-open branch, and no path that returns `true` before `connection.commit()` succeeds
  (`AuthenticationService.java:62`). The CLI has no session, resource access, RBAC, or tenant
  surface, so vertical/horizontal escalation, IDOR, and multi-tenant isolation are not applicable; no
  token or cookie is created or accepted, so steps 2–5 of the authentication-weaknesses workflow
  (JWT analysis/manipulation, token lifecycle) and the cookie-attribute requirements do not apply.
- **Race conditions and limiter integrity:** The check and the grant share one `SERIALIZABLE`,
  non-autocommit transaction, and the counter is a single atomic `INSERT ... ON CONFLICT DO UPDATE
  ... RETURNING` (`AuthenticationService.java:76-88`) rather than read-then-write, so there is no
  TOCTOU window and no limit-overrun across concurrent attempts. Concurrent upserts on the same
  `(scope, bucket_key)` serialize on the row lock under consistent lock ordering (source bucket
  before account bucket in every attempt), so no deadlock is introduced; a genuine serialization
  conflict aborts the whole transaction, which rolls the increment back *and* denies authentication,
  so the abort path cannot be used to obtain an uncounted successful login. Returned counts are
  range-checked (1–1,000,000) and the exactly-one-row condition is enforced. Limiter storage cannot be
  grown by email rotation: unknown addresses and the source scope collapse to constant keys, and
  `window_start`/`attempt_count` are capped by both the `LEAST(...)` expression and
  `CHECK (attempt_count BETWEEN 1 AND 1000000)` (`database/schema.sql:17-19`). Residual (not a
  finding): the window is a fixed `date_trunc('minute')` bucket, so ~2× the nominal allowance is
  possible by straddling a boundary, and the ~1 s of PBKDF2 work is performed while the limiter row
  locks are held; both are acceptable at this scale but worth revisiting if the component is
  network-exposed.
- **Sensitive-data exposure and masking:** stdout carries only
  `Authentication successful.` / `Authentication unsuccessful.`; the logger emits only
  `failure.getClass().getSimpleName()` (`SecureAuthApplication.java:44-45`) with no message, value,
  SQL, or connection text. The `IllegalArgumentException` messages in `InputValidator` are fixed
  strings that do not echo the rejected value. Passwords are read via `Console.readPassword` into
  `char[]`, never into a `String`, never via argv (all arguments are rejected at lines 17-20) and
  never via redirected stdin (`System.console() == null` refused at lines 21-26); `PBEKeySpec` is
  `clearPassword()`-ed in a `finally` (`PasswordVerifier.java:52-54`), the derived key is zeroised
  (`PasswordVerifier.java:45`), `CredentialRecord` salt/hash are zeroised on the normal path, the
  caller's `password` array is zeroised in `finally`, and `PasswordVerifier.close()` erases the dummy
  material. Secrets in the tree: none — no credentials, keys, or working passwords in Java, SQL, XML,
  shell, or Markdown; `README.md`/`schema.sql` use placeholders (`db.example.internal`,
  `auth_runtime`), the JDBC configuration deliberately carries no password property
  (`DatabaseConfig.java:16-18`), and `verify-pgjdbc.sh:5` holds a public integrity digest, not a
  secret. `.gitignore` excludes `target/`, `*.log`, `*.jfr`, `hs_err_pid*`, and `core`/`core.*`,
  consistent with the README's disable-core-dumps guidance. Database transmission is encrypted with
  hostname verification (first bullet above); the password never traverses the wire because only the
  PBKDF2 digest comparison happens server-side — actually no hash is transmitted either, verification
  is entirely local.
- **Input handling and work-factor bounds:** Email is ASCII-only, 3–254 characters, exactly one `@`,
  dot-atom-conformant local part of at most 64 characters with no leading/trailing/consecutive dots,
  and a domain of at least two DNS-shaped labels within 253 characters and the `HOST` lookahead bound
  (`InputValidator.java:14-39`). Passwords are bounded at both 1024 characters and 1024 UTF-8 bytes
  with surrogate-pair and control-character validation (`InputValidator.java:41-66`), which caps
  PBKDF2 cost per attempt and blocks work-amplification through oversized secrets. Hostname label
  structure and empty-label handling are checked (`requireHost`, lines 67-73) and SQL-identifier shape
  is enforced for database and role names (`requireSqlIdentifier`, lines 75-80). Rejecting rather than
  defaulting on invalid input is consistent throughout.
- **Least-privilege database posture:** `app_user` pins `password_algorithm`,
  `password_iterations`, salt length, and hash length as `CHECK` constraints
  (`database/schema.sql:4-8`), giving defence in depth behind the code's own `validRecord` gate; the
  runtime role receives only `SELECT` on `app_user` and `SELECT/INSERT/UPDATE` on `auth_rate_limit`,
  with `DELETE`/`TRUNCATE` explicitly revoked (lines 24-26), so a compromised runtime identity can
  neither read credentials arbitrarily, delete limiter state to erase its tracks, nor provision
  accounts. `email_canonical` is the PRIMARY KEY, so lookups are index-bounded with constant-width
  keys.
- **Account-enumeration resistance:** every failure outcome — invalid input, missing configuration,
  throttled, unknown account, disabled account, wrong password, corrupt row, database error — prints
  the byte-identical `Authentication unsuccessful.`, and unknown/disabled/malformed records still pay
  one full 600,000-iteration hash via the dummy path, so the dominant work term is equal. The
  differential test from the authentication-weaknesses workflow (`valid email` vs `nonexistent
  email` with a wrong password) shows no response-text or exit-status difference. Residual, disclosed
  by the README and judged acceptable for a local-console CLI: the `SELECT` still returns a row for a
  real account and none otherwise, so a determined local observer can measure a small sub-millisecond
  asymmetry that hashing merely dominates rather than eliminates.
