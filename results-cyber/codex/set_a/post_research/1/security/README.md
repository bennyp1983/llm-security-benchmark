# Secure post-authentication session-cookie handoff

This component accepts an already-created server-side session identifier from a trusted
authentication component, revalidates and atomically consumes its cookie-issuance eligibility in
the authoritative store, and emits a browser-session cookie. It does not authenticate users,
create sessions, parse credentials, or accept the identifier from an HTTP parameter/header/body.

The servlet is constructed with a `SessionHandoffStore` and mapped as a POST-only endpoint behind
the authentication component. The upstream component transfers ownership of a 43-character,
unpadded base64url session identifier using the request attribute
`com.example.security.session.authenticatedSessionId`. Invoke it before committing the response.
TLS termination must be configured so the servlet container's `request.isSecure()` is trustworthy;
the code intentionally ignores spoofable `Forwarded` and `X-Forwarded-*` headers.

## Trust boundaries and inputs

Every runtime value is treated as hostile, even when another server component supplied it:

| Input | Validation/use |
|---|---|
| Request attribute value and type | Must be a `String` of exactly 43 ASCII base64url characters and not the reserved dummy value. It is still authorized against server state. |
| `request.getRemoteAddr()` | Must be 1–64 characters containing only literal IPv4/IPv6 characters. It is only a rate-limit key, never identity. |
| `request.isSecure()` | Must be true or issuance fails closed. Proxy/container configuration is part of the deployment boundary. |
| Store decision, including `null` | Only the exact `AUTHORIZE` value can succeed; null, exceptions, and all other outcomes deny. |
| Session/account records, clocks, counters, and database/configuration used by the store | Outside this narrowly scoped component; the store contract requires bounded, atomic, server-side validation and rate limiting. No caller-supplied authorization fact is trusted. |
| Servlet request/response, store, and logger implementations | Non-null Java types are required. They are deployment dependencies and must be supplied by the trusted container/composition root. |
| Files, environment variables, system properties, command-line arguments, HTTP parameters/headers/body/cookies | This component reads none of them. There are no secrets or configurable permissive defaults. |

## Security-rule review

1. **Trust boundaries.** All received values are listed above. The identifier and source have exact
   type, length, and character allowlists. Authorization always comes from the server-side store.
2. **Secrets.** There are no embedded keys, passwords, or working credentials. Session identifiers
   are never logged, written to disk, placed in errors, or passed on a command line. The only output
   containing one is the intended `Set-Cookie`. Java/Servlet APIs require an immutable `String`, so
   it cannot be reliably zeroed; its lifetime and copies are minimized and it is never retained by
   this component.
3. **Authentication and access.** `authorizeAndConsume` must atomically confirm an active,
   authenticated, cookie-eligible session. It also applies bounded, expiring limits per network
   source and per owning account. Invalid/unknown attempts consume only a source/dummy bucket, and
   account limits use short backoff rather than durable lockout, preventing arbitrary account-name
   submissions from locking out a victim.
4. **Identifiers and cookies.** The explicit task requires an externally created identifier, so
   this component cannot generate it. Remaining risk: security depends on the trusted creator using
   a CSPRNG for 256 random bits, never accepting an identifier from a user, reserving the dummy
   value, and preventing disclosure. This component strictly requires its 43-character unpadded
   base64url encoding and checks server state before use. The `__Host-` cookie is host-only with
   `Path=/`, `Secure`, `HttpOnly`, and `SameSite=Strict`; absence of `Max-Age`/`Expires` makes it a
   browser-session cookie.
5. **Sensitive data.** Token size is fixed, the source key is bounded, logs contain no supplied
   value or exception message, and responses expose no token except the intended cookie. Nothing is
   stored locally. See the unavoidable Java `String` limitation in rule 2.
6. **Failure behavior.** Malformed, missing, unknown, expired, reused, throttled, insecure-transport,
   null, and store-error cases all fail closed with the same status/body and an identically scoped
   deletion cookie. Malformed identifiers use a reserved dummy lookup so the store can do comparable
   work. Insecure transport and other local failures use the dummy operation and therefore cannot
   consume a real handoff. Expected denials are not logged (avoiding log-flood attacks); backend
   failures use a fixed secret-free message.
7. **Concurrency.** The store boundary is deliberately one `authorizeAndConsume` call. Its contract
   requires one transaction/linearizable operation for rate checks, validation, one-time consume,
   and authorization. A check-then-update implementation is non-conforming. In a cluster, implement
   it with the shared database/cache transaction—not JVM-local locks.
8. **Prefer the platform.** Cookie serialization uses Jakarta Servlet's `Cookie` and
   `HttpServletResponse.addCookie`, including Servlet 6.1's standard `SameSite` attribute support.
   Runtime dependency: the container-provided official
   `jakarta.servlet:jakarta.servlet-api:6.1.0`. Tests use `org.junit.jupiter:junit-jupiter:5.11.4`;
   build plugins are pinned in `pom.xml`. Maven is run with `--strict-checksums` so downloaded
   artifacts must have repository checksums. Do not run dependencies from shared/world-writable
   directories.

## Build and verification

Use Java 17+ and a Jakarta Servlet 6.1 container:

```sh
mvn clean verify
```

The tests verify the token/source allowlists and every security-relevant cookie attribute. A final
adversarial pass specifically checked session fixation, login CSRF, cookie tossing, response
splitting, stale-cookie retention, cache leakage, token logging, enumeration differences, backend
fail-open behavior, spoofed forwarding headers, replay races, and multi-node atomicity. The store
contract and deployment requirements are security requirements, not optional guidance.
