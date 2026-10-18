# Authentication component

A self-contained username/password authentication component for Java SE 17, with
authentication-event logging. It authenticates, issues a session, and records every
attempt. It deliberately contains no registration, password-change, account-lockout
administration, user-listing, reporting or monitoring surface.

```
src/main/java/com/example/auth/
  AuthenticationService.java   entry point: authenticate / resumeSession / signOut
  AuthenticationResult.java    one generic failure state, success carries a session id
  InputPolicy.java             validation of everything crossing the trust boundary
  PasswordHasher.java          PBKDF2-HMAC-SHA512 verification (JDK SecretKeyFactory)
  CredentialRecord.java        salt + derived key + iterations, validated on construction
  CredentialStore.java         read-only server-side credential state (interface)
  InMemoryCredentialStore.java in-memory store, seeded at runtime, empty by default
  LoginThrottle.java           per-source and per-account attempt budgets
  SessionRegistry.java         SecureRandom session ids, digests held server-side
  Session.java                 server-side session state
  SessionCookie.java           Set-Cookie rendering with fixed hardened attributes
  AuthEventLog.java            audit sink (interface)
  FileAuthEventLog.java        owner-only, size-bounded, append-only event log
  AuthEvent.java               one record; has no field able to hold a secret
  LogSanitizer.java            escaping and masking for log fields
src/test/java/com/example/auth/
  AuthenticationSelfCheck.java 44 executable checks, bare JDK, no dependencies
```

## Build and run the checks

```sh
javac -d target/classes $(find src/main/java -name '*.java')
javac -cp target/classes -d target/test-classes src/test/java/com/example/auth/AuthenticationSelfCheck.java
java -cp target/classes:target/test-classes com.example.auth.AuthenticationSelfCheck
```

`mvn -q test-compile` also works; `pom.xml` declares no dependencies at all.

## Usage

```java
CredentialStore store = loadVerifiersFromYourStore();          // server-side state
PasswordHasher hasher = new PasswordHasher(PasswordHasher.DEFAULT_ITERATIONS);
LoginThrottle throttle = LoginThrottle.withDefaults();          // 10/source, 50/account, 15 min
SessionRegistry sessions = SessionRegistry.withDefaults();      // 30 min idle, 8 h absolute
AuthEventLog log = new FileAuthEventLog(Path.of("/var/log/app/auth-events.log"),
        8L * 1024 * 1024, correlationKeyFromYourSecretManager());

var service = new AuthenticationService(store, hasher, throttle, sessions, log, Instant::now);

char[] password = readPasswordIntoCharArray(request);           // never a String
AuthenticationResult result = service.authenticate(
        request.parameter("username"), password, request.remoteAddress());

if (result.isAuthenticated()) {
    response.addHeader("Set-Cookie",
            SessionCookie.setCookieHeader(result.sessionId().orElseThrow(), 8 * 3600));
} else {
    // Identical status and body for every failure cause.
    response.status(401).body(result.message());
}
```

`authenticate` takes ownership of the `char[]` and zeroes it before returning, on
every path including exceptions.

## Trust boundary

Every value below is treated as attacker-controlled.

| Input | Origin | Validation |
| --- | --- | --- |
| username | client | `InputPolicy.canonicalUsername`: 1–64 chars, ASCII alphanumerics plus `. _ - @ +`, must start and end alphanumeric, lower-cased with `Locale.ROOT` |
| password | client | `InputPolicy.isAcceptablePassword`: 12–256 chars; the upper bound caps key-derivation cost |
| source address | transport layer (or a trusted proxy) | `InputPolicy.canonicalSource`: must parse as an IPv4 or IPv6 literal, ≤45 chars |
| session identifier | client cookie | `InputPolicy.isWellFormedSessionId` for shape, then matched against `SessionRegistry`'s server-side table — shape alone grants nothing |
| credential record | credential store / database | `CredentialRecord` constructor: exact salt and key lengths, iteration count within `[100 000, 10 000 000]`, defensive copies |
| iteration count, budgets, windows, timeouts, log ceiling | configuration | range-checked in each constructor via `InputPolicy.requireInRange` / explicit bounds; out-of-range config throws rather than being clamped |
| correlation key | configuration / secret manager | minimum 16 bytes; never logged or echoed |
| log file and its directory | filesystem | must be a regular file / directory with `NOFOLLOW_LINKS`, owner-only permissions, else the log refuses to open |
| existing log size | filesystem | read at open, bounded by rotation |

## How each rule is satisfied

**1. Trust boundaries.** The table above lists every input and where it is
validated. Nothing is used before validation: an invalid username never reaches the
store lookup, the throttle key space or the log. No client-supplied value decides a
security outcome — the only inputs that can lead to success are the password (checked
against the stored verifier) and the session identifier (checked against the
registry's server-side table). Rejected input gets the same generic failure as any
other failure.

**2. Secrets.** No credential, key or password appears in this repository.
`InMemoryCredentialStore` ships empty, so running the code grants nobody access. The
self-check generates its password from `SecureRandom` at runtime. Verifier material,
session identifiers and the correlation key are never logged, never put in an
exception message (`CredentialRecord.toString`, `Session.toString` and
`AuthenticationResult.toString` all redact), never passed on a command line, and the
log file is created `0600` in a `0700` directory.

**3. Authentication and access.** Verification is always against server-side state:
`CredentialStore` for passwords, `SessionRegistry` for sessions. Every failure path
fails closed — a store exception, a key-derivation provider failure, a full session
registry, a saturated throttle table, an unexpected `RuntimeException`, or an
inability to retain the success event all deny the attempt. Passwords are verified
with the JDK's PBKDF2-HMAC-SHA512 at 210 000 iterations and compared with
`MessageDigest.isEqual` (constant time). Attempts are limited **per source** (10
failures / 15 min, blocks that address) *and* **per account** (50 failures / 15 min,
imposing a 5-minute cool-off). The account measure is a bounded, self-expiring
cool-off rather than a lockout, and there is no unlock step, so an attacker failing
on purpose can only delay a legitimate user, never deny them the account — and the
user remains able to sign in from a source that has budget left. A successful login
clears the account counter but not the source counter, so an attacker holding one
valid account cannot reset the per-source budget and keep guessing.

**4. Identifiers and tokens.** Session identifiers are generated here, from
`SecureRandom`, 256 bits, rendered base64url; none is ever accepted, derived or
influenced from caller input. A fresh identifier is minted on every successful
authentication, so session fixation is impossible. The registry stores only the
SHA-256 digest of the identifier, so reading server-side state yields no usable
session. The cookie is `__Host-session=<id>; Max-Age=…; Path=/; Secure; HttpOnly;
SameSite=Strict` with the attributes fixed in code so no deployment can weaken them;
`setCookieHeader` refuses any value that is not a well-formed identifier, so no
header injection is possible. No externally provided identifier is used, so there is
no residual risk to document on that point.

**5. Sensitive data.** The log holds no password material and no session identifier —
`AuthEvent` has no field that could carry one. Usernames are masked (`a*****e`) and
accompanied by a keyed HMAC-SHA256 correlation value so attempts on one account can
be grouped without the log naming it; source addresses are masked to an IPv4 /24 or
IPv6 /48. The log file is created `0600` with `NOFOLLOW_LINKS` inside a `0700`
directory and refuses to open if either is reachable by other users or is not a
regular file. Sizes are bounded everywhere: 64 characters per log field, a configured
byte ceiling with single-generation rotation (total footprint < 2 × ceiling), 50 000
throttle keys per dimension, 100 000 sessions. `authenticate` zeroes the caller's
password array, `PasswordHasher` zeroes derived keys and calls
`PBEKeySpec.clearPassword()`.

**6. Failure behaviour.** `AuthenticationResult` has exactly one failure state and
one message, `GENERIC_FAILURE_MESSAGE`, returned identically for malformed input, an
unknown account, a wrong password, a throttled attempt and an internal error; the
cause survives only in the log. Work is comparable too: an unknown username is run
against a process-local decoy record with the same PBKDF2 parameters, so response
time does not disclose which accounts exist. Nothing invalid is substituted with a
permissive default — unparseable configuration, a tampered record and a malformed
username all throw or reject.

**7. Concurrency.** Each check-then-act sequence is one atomic
`ConcurrentHashMap.compute`: the throttle's expiry-check-and-read, its
count-and-block update, and the registry's lookup-expire-refresh. So a burst of
parallel attempts cannot slip past a budget, and an expired session cannot be revived
by a racing request. Log writes are serialised on a dedicated lock and flushed, so
records never interleave. The service itself is stateless and safe for concurrent use.

**8. Prefer the platform.** Everything security-relevant is a JDK primitive:
`SecretKeyFactory` PBKDF2-HMAC-SHA512 for password verification, `SecureRandom` for
identifiers, `MessageDigest.isEqual` for comparison, `Mac`/HmacSHA256 for the
correlation value, `MessageDigest` SHA-256 for session digests, `java.nio.file` POSIX
attributes for file privacy, `ConcurrentHashMap` for atomic counters. No cryptography
is hand-rolled. There are **no third-party dependencies** and nothing is downloaded at
runtime; `pom.xml` pins `maven-compiler-plugin` 3.13.0 from Maven Central (whose
checksums Maven verifies) and nothing else, and no code is loaded from a shared or
world-writable location.

## Residual risks and deployment requirements

- **Source identifier provenance.** The component validates the shape of `source`,
  but it cannot tell whether the caller took it from the socket peer or from a
  client-settable header. Behind a proxy, terminate the header at a trusted hop and
  strip client-supplied copies; otherwise the per-source budget can be evaded.
- **Distributed guessing.** Per-source budgets limit one address. A botnet spreading
  guesses still faces the per-account cool-off and 210 000-iteration PBKDF2 cost, but
  defence in depth at the network edge remains worthwhile.
- **Saturation.** If the throttle tables or session registry fill, attempts are denied
  (fail closed). That is a deliberate availability-for-security trade: filling them
  requires tens of thousands of distinct keys, which the per-source budget makes
  expensive.
- **Iteration-count timing.** The decoy record uses the service's configured
  iteration count. If stored records carry a materially different count, verification
  time could distinguish them; re-derive records on the current parameters.
- **Audit availability.** A successful authentication whose event cannot be written is
  refused and its session dropped. Size the log volume accordingly.
- **Transport.** The cookie is `Secure` and `__Host-`-prefixed, so the application
  must be served over HTTPS; the identifier will not be sent or stored otherwise.
