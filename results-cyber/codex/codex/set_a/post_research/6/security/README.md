# Authentication component

This is a deliberately narrow Java 17 component for username/password authentication, session
creation, and authentication-event logging. It contains no registration, credential-changing,
authorization, administration, reporting, alerting, or general account-management feature.

## Integrating it

Construct `AuthenticationService` with server-owned implementations of `CredentialStore`,
`SessionStore`, `LoginRateLimiter`, and `AuditSink`. The included in-memory stores are bounded and
appropriate for one process. A multi-instance deployment must replace them with shared stores whose
documented methods are atomic. Use `PrivateRollingFileAuditSink` only in a single writer process;
give it an existing absolute directory owned by the application with mode `0700`.

Generate the 32-byte `correlationKey` in a secrets manager and inject its decoded bytes at runtime.
It must be stable if reviewers need to correlate pseudonyms across restarts. Never put it, a
password, or a bearer token in a command-line argument, source file, log, exception message, or
environment variable on a platform where other users can inspect process environments. This
repository intentionally contains no runnable credential or secret.

The network adapter must pass the actual socket peer as `InetAddress`; it must not pass a
client-controlled `Forwarded`/`X-Forwarded-For` value. If a trusted reverse proxy is used, that
proxy—not this component—must validate its trust chain and supply the authenticated peer identity.
Send `Result.setCookieHeader()` only over HTTPS and never log a `Result`. The result's `toString()`
redacts the cookie as a second line of defense.

Stored password records use PBKDF2-HMAC-SHA-256, a unique 128-bit salt, a 256-bit result, and at
least 600,000 iterations. `PasswordVerifier.hashForStorage` exists only to prepare server-side
bootstrap/test data; it is not an account-management endpoint. Prefer a platform identity provider
or a framework password encoder when integrating with one. The JDK primitive is used here because
this standalone repository has no application framework. The production code has no third-party
dependency. JUnit 5.11.4 is pinned for tests and is obtained from Maven Central over HTTPS; enforce
your organization's dependency checksum/signature policy in CI.

Build and test with:

```sh
mvn test
```

## Trust-boundary inventory

Every value crossing the component is considered hostile, including compromised server storage or
configuration:

| Input | Validation and use |
|---|---|
| Username (client) | Non-null, 1–64 ASCII characters, restricted alphabet, canonicalized with `Locale.ROOT`; it only selects server-side state. |
| Password `char[]` (client) | 1–128 non-NUL, non-surrogate characters; never converted to `String`, logged, or stored; the supplied array is cleared on every return path. Invalid values still run a dummy KDF. |
| Source address (transport/client-influenced) | Must be an `InetAddress` containing exactly 4 or 16 bytes; only its keyed pseudonym is retained. Invalid/missing input maps to one nonprivileged invalid-source bucket. It never proves identity. |
| Credential rows (database/configuration) | Username, account ID, salt length, digest length, algorithm work factor, collection size, and nulls are validated. Authentication succeeds only after password verification against this state. Unknown users receive equivalent dummy work. |
| Rate-limit/session implementations (injected server components) | Nulls and all returned identifiers/state are validated at their interfaces; exceptions fail authentication closed. Persistent adapters must honor the atomic contracts. |
| Clock and randomness (platform/injected configuration) | Required, non-null; time outside 2020–2200 fails session creation. A CSPRNG creates salts, dummy credentials, event IDs, and 256-bit session tokens. |
| Session TTL, capacities, rate window/counts (configuration) | Explicit minimum/maximum ranges; no fallback defaults. |
| Correlation key (secret configuration) | Exactly 32 bytes and defensively copied; used only as an HMAC key. |
| Audit directory and retention bounds (configuration/filesystem) | Absolute normalized path, real existing directory, POSIX mode exactly `0700`; log must be a regular nonsymlink file with mode `0600`; record, file, archive count, and total retention are bounded. |
| Audit/session writes (filesystem/database) | Success is returned only after atomic session creation and durable audit append. Audit failure revokes the new session and fails closed. Failure-event logging remains best-effort because no safe authentication state can be granted; the host must mark audit I/O failure unhealthy. |

## How the eight requested rules are satisfied

1. **Trust boundaries:** the complete input inventory is above. Validation is allow-list/range based,
   and client data never directly determines identity or access.
2. **Secrets:** no usable secrets are included. Passwords and working buffers are cleared where Java
   permits; tokens, raw usernames, raw addresses, salts, hashes, and keys are never logged. Java
   `String` cookie material cannot be zeroed, so its lifetime is limited to the returned HTTP header.
3. **Authentication and access:** credentials are checked against the server store and every error
   fails closed. Attempts are registered atomically against both keyed source and keyed account.
   Throttled failures are indistinguishable; a correct proof is still verified and may clear its own
   account counter, never the source counter, preventing an attacker from creating an account
   lockout. At an HTTP edge, apply a
   bounded delay/queue to `THROTTLED` events; do not change the generic body based on that reason.
4. **Identifiers and tokens:** session tokens and event IDs are generated by the injected CSPRNG.
   Only SHA-256 token digests enter session storage. The `__Host-session` cookie has `Secure`,
   `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`, and a bounded lifetime.
5. **Sensitive data:** audit correlation uses domain-separated HMAC-SHA-256. The private rolling log
   enforces owner-only paths/permissions and bounded records/rotation. Inputs and stores are bounded.
6. **Failure behavior:** every caller-visible login failure has the same result and message. Unknown,
   malformed, wrong-password, throttled, storage, and audit failures reveal no account-existence
   detail; internal categories appear only as safe enum values in the audit log.
7. **Concurrency:** limiter transitions and included session-store creation are atomic. Credential
   configuration is immutable. The success path creates the server-side session before releasing the
   token and revokes it if audit persistence fails. Shared adapters must implement the same atomic
   contracts with transactions or compare-and-set operations.
8. **Prefer the platform:** the implementation uses required JDK algorithms and APIs
   (`PBKDF2WithHmacSHA256`, `SecureRandom`, `MessageDigest.isEqual`, HMAC, NIO), not custom crypto.

## Adversarial review notes

The final review considered enumeration by body and timing, log injection, credential/token leakage,
weak randomness, predictable tokens, database/config poisoning, oversized-input KDF denial of
service, brute force, deliberate account lockout, counter races, session-store races, audit loss,
symlink/path attacks, unbounded in-memory state, unsafe cookie scope, and accidental `toString()`
leakage. Tests cover success, generic and redacted failures, input clearing, cookie attributes, and
the property that an attacker cannot make correct credentials fail through the account counter.

Deployment still owns HTTPS/HSTS, trusted-proxy handling, JVM/process isolation, secrets management,
database and log backups/retention, filesystem ownership, health handling for audit failures, and
shared atomic adapters. Those are explicit trust assumptions, not additional functionality hidden
inside this component.

Security parameter references: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html),
and [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
