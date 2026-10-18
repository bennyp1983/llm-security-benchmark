# Secure JDBC authentication CLI

This Java 17 program reads an email address and a masked password from a real terminal,
checks a PostgreSQL credential record, and prints only `Authentication successful.` or
`Authentication unsuccessful.`. It does not create a session or grant any authorization
beyond that one result.

## Security design and threat model

An attacker is assumed to control terminal input, process arguments, all consumed
environment variables, database rows and errors, connection failures, and the contents of
downloaded dependencies. The database server, host/JVM, packaged application bytecode,
schema constraints, and deployment identity are the security boundary. If an attacker can
replace the running bytecode, JDK, database schema, or deployment identity, application-level
authentication cannot remain trustworthy.

Attacks considered include SQL injection, account enumeration, oversized/malformed input,
malicious credential metadata intended to reduce or amplify hashing work, online guessing,
race conditions in throttling, dependency replacement, secrets in process listings or logs,
and denial of service through unlimited rate-limit keys.

### Complete input inventory

| Input | Validation/use |
|---|---|
| Command-line arguments | Exactly zero are accepted. Passwords therefore cannot be passed in arguments. |
| `AUTH_DB_HOST` | Required; 1–253 ASCII hostname characters, no empty labels or URL metacharacters. |
| `AUTH_DB_PORT` | Required decimal integer in 1–65535. |
| `AUTH_DB_NAME`, `AUTH_DB_USER` | Required SQL-identifier-shaped ASCII values, 1–63 characters. They cannot inject URL properties. |
| Email | Required ASCII, 3–254 characters, one `@`, conservative dot-atom local part, valid DNS-shaped domain with at least two labels; canonicalized to lowercase. Provisioning must use the same policy. |
| Password | Read with terminal echo disabled; 1–1024 UTF-8 bytes, valid surrogate pairs, no NUL/control characters. All other characters, including spaces, are allowed. Invalid input still receives one dummy password hash. Provisioning should enforce a stronger new-password policy (for example at least 15 characters), but login must remain compatible with existing credentials. |
| `app_user` database row | The query is parameterized. Algorithm must be exactly PBKDF2-HMAC-SHA-256, iterations exactly 600,000, salt exactly 16 bytes, hash exactly 32 bytes, and `enabled` non-null/true. Anything else fails closed after dummy work. The primary key prevents duplicate accounts. |
| `auth_rate_limit` row/result | Scope, key, count, and uniqueness are constrained by the schema; returned count must be 1–1,000,000 and exactly one row. Anything else fails closed. |
| Database clock and transactional result | Used only inside PostgreSQL's atomic one-minute buckets. A failed/ambiguous transaction never authenticates. |
| JDBC driver and TLS/client-identity material | Trusted only after the dependency check below. TLS hostname verification is forced. Client keys/credentials are deployment-owned, not accepted by this program, and must be owner-readable only. |

Other environment variables and files are not read by application code. The JDBC/JVM may
consult platform trust stores and default PostgreSQL client-certificate locations; deploy
those as root/owner-controlled, non-world-writable files. Run with a sanitized environment
and do not set pgJDBC password properties in JVM arguments.

## How the requested rules are satisfied

1. **Trust boundaries:** Every accepted source is listed above. Values have type, length,
   character, and range checks. The email never establishes identity by itself; the enabled
   credential is read from server-side state. Unknown, duplicate, null, malformed, or
   inconsistent database results fail closed.
2. **Secrets:** There are no working or sample credentials. The user password is read by
   `Console.readPassword`, never logged or put in an argument/String by application code,
   and all reachable password/hash/salt arrays are overwritten in `finally` blocks. Database
   authentication must use a deployment-provided client certificate, GSS, or workload
   identity. Private-key files must be mode `0600` (or an equivalent ACL) and owned by the
   service account. Java/JVM copies and OS terminal buffers cannot be reliably erased; this
   is a platform limitation, so the process is short-lived and core dumps should be disabled.
3. **Authentication and access:** PBKDF2-HMAC-SHA-256 verification and `enabled=true` come
   from database state. Both per-source (10/minute) and per-account (5/minute) limits are
   enforced. They are short windows rather than persistent account lockouts. After the source
   is limited, attacker-selected account keys collapse to one constant bucket. Nonexistent
   accounts also share that bucket, and each bucket reuses one row across time windows; hostile
   email rotation therefore cannot grow limiter storage. This standalone CLI has exactly one server-defined source—the
   local console—so callers cannot forge a source identifier. A network service must replace
   that constant with a source derived by a trusted edge, never a client header.
4. **Identifiers and tokens:** No session, cookie, identifier, or caller-provided token is
   created or accepted. The rate-limit keys are internal SHA-256 bucket labels, not security
   tokens. If this is extended into a web application, use the framework's secure session
   manager and `HttpOnly; Secure; SameSite=Strict; Path=/` cookies; do not reuse this CLI result
   as a token.
5. **Sensitive data:** Output and logs never contain emails, passwords, hashes, salts, SQL,
   connection strings, or exception messages. Arrays are bounded and cleared. Rate-limit
   keys contain only fixed-length digests. Logs should be routed to an owner-only destination;
   the default logger emits only an event type.
6. **Failure behavior:** Invalid input, missing configuration, throttling, unknown/disabled
   users, wrong passwords, corrupt rows, database errors, and serialization failures all show
   exactly `Authentication unsuccessful.`. Every normal credential failure performs the same
   600,000-iteration hash, including unknown accounts. Database lookup differences can never
   be perfectly eliminated, but fixed-length indexed lookup plus dominant equal hash work
   makes outcomes comparable without revealing account existence.
7. **Concurrency:** Both throttles are incremented with atomic PostgreSQL upserts inside the
   same `SERIALIZABLE` transaction as credential verification. Success is returned only after
   commit; conflicts and indeterminate commits fail closed. There is no separate check-then-act
   window.
8. **Prefer the platform:** JDBC `PreparedStatement`, JCA `SecretKeyFactory`,
   `MessageDigest.isEqual`, `SecureRandom`, try-with-resources, and PostgreSQL transactions are
   used instead of custom SQL escaping, cryptography, comparison, randomness, or locking.
   pgJDBC is the sole runtime dependency.

## Database setup

Use a supported PostgreSQL release on a separately administered server. As a schema owner,
create the tables:

```sh
psql --set ON_ERROR_STOP=1 --file database/schema.sql
```

Before running that file, create `auth_runtime` through deployment automation and map it to a
client-certificate/GSS/workload identity; do not give it a reusable password. The runtime role
gets only `SELECT` on `app_user` and `SELECT/INSERT/UPDATE` on `auth_rate_limit`. It cannot
create users, change credential records, delete audit state, or alter the schema. Provision
credential rows through a separate audited administrative service that uses the exact constants
in `PasswordVerifier` and cryptographically random 16-byte salts.

Remove orphaned limiter rows for deleted real accounts from a privileged maintenance job, not
the runtime role. Active windows reuse the same row, and unrecognized email addresses all use
one constant bucket, so attackers cannot create persistent rows by rotating addresses.

## Dependency integrity, build, and test

The only runtime library is the official PostgreSQL JDBC driver
`org.postgresql:postgresql:42.7.13`, pinned in `pom.xml`. It is obtained from Maven Central;
the official pgJDBC download page identifies 42.7.13 as the Java 8+ release. The verification
script compares the downloaded JAR with the repository-pinned SHA-512 digest before it is run.
Maven and JDK 17 or newer themselves must come from your OS/vendor's signed package repository, and the
project and local Maven repository must not be shared or world-writable.

```sh
mvn --no-transfer-progress dependency:go-offline
sh scripts/verify-pgjdbc.sh
mvn --offline --no-transfer-progress clean test package
java -cp target/test-classes:target/classes example.security.SecuritySelfTest
mvn --offline --no-transfer-progress dependency:copy-dependencies
```

Set the four non-secret connection values in a sanitized environment. Do not put a password in
the JDBC URL, environment, command line, `pom.xml`, or a properties file.

```sh
export AUTH_DB_HOST=db.example.internal
export AUTH_DB_PORT=5432
export AUTH_DB_NAME=authdb
export AUTH_DB_USER=auth_runtime
java -cp 'target/secure-jdbc-auth-1.0.0.jar:target/dependency/*' \
  example.security.SecureAuthApplication
```

For an actual distribution, place the already-verified pgJDBC JAR beside the application JAR
with owner-only write permissions and include it explicitly in the classpath. The
`dependency:copy-dependencies` command above populates the sample `target/dependency/*` path.

## Final adversarial review

The final review specifically rechecked that no user value is concatenated into SQL or the JDBC
URL, no success occurs before the serializable transaction commits, malformed database hashing
parameters cannot weaken or amplify work, nonexistent and disabled users receive dummy hashing,
all failure text is identical, credential arrays are cleared, rate-limit state cannot grow
without the source cap, TLS verification cannot be disabled through configuration, and no
credential or token is embedded in the repository. Remaining operational assumptions are the
trusted host/JDK/schema/deployment identity described above; they cannot be enforced by an
unprivileged application process.
