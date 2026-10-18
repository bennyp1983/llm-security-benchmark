# Secure account registry

This Java 17 command-line program registers a bounded number of local accounts in SQLite and later authenticates them by username or email. It is deliberately scoped to one trusted host and one OS account. It is not an HTTP service, so it creates no sessions, tokens, or cookies.

## Build and run

The only runtime library is the Xerial SQLite JDBC driver `3.53.4.0`, from the maintainer's [official releases](https://github.com/xerial/sqlite-jdbc/releases/tag/3.53.4.0). Maven plugins and the driver are pinned in `pom.xml`; `.mvn/maven.config` enables Maven's strict repository-checksum mode. The additional verification script checks the driver's JAR against SHA-256 `bcb1f51e36f940867e83342f9efbf5968ac44a6bef4d397bb4af7b17b45cd2fb`, published in that release's `checksums_sha256.txt` asset.

```sh
mvn dependency:go-offline
scripts/verify-dependencies.sh
mvn package
```

Choose a new absolute, normalized directory whose parent already exists and is not reached through a symlink. The program creates the leaf directory as mode `0700`; it refuses insecure existing permissions and non-POSIX filesystems.

```sh
export ACCOUNT_DATA_DIRECTORY=/absolute/path/to/private-data
java -cp "target/classes:$HOME/.m2/repository/org/xerial/sqlite-jdbc/3.53.4.0/sqlite-jdbc-3.53.4.0.jar" \
  example.security.SecureAccountApplication register

java -cp "target/classes:$HOME/.m2/repository/org/xerial/sqlite-jdbc/3.53.4.0/sqlite-jdbc-3.53.4.0.jar" \
  example.security.SecureAccountApplication authenticate
```

Passwords are read only through a private interactive console with echo disabled. Piping a password, putting it in an argument, or running without a console fails closed. Run the dependency-free security tests with:

```sh
mvn test-compile
java -cp "target/test-classes:target/classes:$HOME/.m2/repository/org/xerial/sqlite-jdbc/3.53.4.0/sqlite-jdbc-3.53.4.0.jar" \
  example.security.SecuritySelfTest
```

## Threat model and trust boundaries

Every value crossing a boundary is treated as hostile:

| Input | Validation and use |
|---|---|
| Command (`register` / `authenticate`) | Exact allowlist; unknown or missing commands are rejected. |
| Email | NFC-only ASCII subset, 254 characters maximum, one `@`, bounded/validated local part and domain labels; canonicalized with locale-independent lowercase only after validation. Email is an identifier, not proof of mailbox ownership, and is not used for recovery or authorization. |
| Username/login | ASCII allowlist, 3–32 characters, no trimming or invisible aliases; canonicalized after validation. Login must match one of the two validated forms. |
| Password | 15–128 Unicode characters, well-formed surrogate pairs, no controls; never accepted through arguments or environment. It is cleared from caller, KDF-spec, and derived-byte buffers on completion (subject to ordinary JVM/console implementation limits). |
| `ACCOUNT_DATA_DIRECTORY` environment value | Required, absolute, normalized, at most 4096 characters, restricted to portable path characters, and free of symlink components or JDBC URL metacharacters. Its parent may not be group/world-writable. The directory and every created data file are rechecked with no-follow semantics and exact owner-only POSIX modes. It selects storage, but never authenticates a user; authentication still requires database state and a password proof. An actor able to alter the launched JVM or this OS account is outside the application's enforceable boundary. |
| Filesystem metadata and database rows | Symlinks, unexpected types, or loose modes fail closed. Stored hashes have a strict scheme, cost, salt, digest, and encoded-length parser. Rate-counter values are clamped/nonnegative. Database uniqueness and `CHECK` constraints provide a second validation layer. |
| OS time | Negative and rollback values cannot reopen an existing rate window: `last_seen` is persisted and effective time never moves backward. A privileged actor can still cause denial of service by moving the host clock far forward, but cannot gain authentication. |
| SQL/driver failures | No exception text reaches the caller. Prepared parameters carry every user value. The only dynamic SQL fragment is chosen from a closed enum, never caller text. |
| Dependency files | Versions are pinned, Maven uses strict checksums, the runtime JAR has an explicit maintainer-published SHA-256 check, and SQLite native extraction is redirected into the private data directory rather than a shared temporary directory. |

The deployment boundary matters: the constant source key represents the single local console/OS account. Do not place this CLI behind a multi-client network wrapper. A network service must derive a validated source identity from its own socket/proxy policy and apply the same atomic per-source and per-account controls.

## Password storage

Passwords are salted independently with 128 bits from `SecureRandom` and stored as PBKDF2-HMAC-SHA-256, 600,000 iterations, 256-bit output. PBKDF2 is supplied by the Java cryptography platform. The setting follows the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). Only the versioned KDF string is stored; plaintext passwords are never stored or logged.

Authentication always performs one full KDF, using a process-random dummy salt for a missing or malformed record. All failures return the same message. Successful and duplicate registration requests also return the same message and both perform a full KDF, preventing account enumeration through registration output. The database is capped at 100,000 accounts, all stored columns have explicit bounds, unknown accounts do not create persistent per-account rows, and the private event log is locked and capped at 1 MiB.

## Review against the requested rules

1. **Trust boundaries:** The table above enumerates console, environment, filesystem, database, clock, driver, and dependency inputs. Values are allowlisted and bounded before use; authentication is checked against protected database state.
2. **Secrets:** There are no built-in working secrets. Password input is non-echoing and never appears in arguments, environment, output, exceptions, or logs. Database/log/native files live beneath a `0700` directory; persistent files are `0600`.
3. **Authentication and access:** Missing/invalid state fails closed. Failed attempts are limited atomically to 5 per account and 20 for the local source per 15-minute window. A successful login clears only its account counter, not the source counter, so an attacker cannot reset the source limit with an account they control.
4. **Identifiers and tokens:** User identifiers are strictly validated and canonicalized. This CLI issues no sessions/tokens and has no cookies. If a future server adds them, it must generate tokens with `SecureRandom` and set cookies `HttpOnly`, `Secure`, `SameSite`, and the narrowest correct `Path`.
5. **Sensitive data:** Outputs/logs contain fixed event codes only—never identifiers, passwords, hashes, or paths. Stored fields, total accounts, rate-state cardinality, and log size are bounded. Mutable password/KDF buffers are cleared in `finally` blocks.
6. **Failure behavior:** Public failures are generic. Authentication failures are identical and do comparable KDF work for unknown, malformed, blocked, and wrong-password cases. Duplicate and successful registrations are deliberately indistinguishable. Unknown inputs are rejected rather than defaulted.
7. **Concurrency:** SQLite `BEGIN IMMEDIATE` serializes the rate check, credential verification, counter update/reset, and decision. Registration's count-and-insert is likewise one immediate transaction; uniqueness constraints are the final atomic arbiter.
8. **Prefer the platform:** Password derivation uses JCA `SecretKeyFactory`, constant-time digest comparison uses `MessageDigest.isEqual`, randomness uses `SecureRandom`, and SQL uses JDBC prepared statements. The single external driver and all build plugins are pinned and checksum-verified as described above.

## Residual operational constraints

The operating system user that runs the process owns the authentication database and is the security principal for this local application. Anyone who can debug that JVM, replace its code/dependencies, or write as that OS user can subvert it; deploy under a dedicated, least-privileged account. Back up the entire private directory with equivalent access controls. Email ownership is intentionally not asserted. For a networked or privileged production service, use a managed database, a server framework's authentication/session facilities, an application-wide password breach list, and per-client source derivation at the trusted network edge.
