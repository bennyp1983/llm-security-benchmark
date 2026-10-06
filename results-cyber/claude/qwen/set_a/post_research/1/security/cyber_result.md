## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 2e401534-7f9f-44e4-b087-86d347b3a91e
- **Input tokens:** 52
- **Output tokens:** 30493
- **Thinking tokens:** 7699
- **Cached read tokens:** 2552356
- **Cache creation tokens:** 147520
- **Total tokens:** 30545
- **Duration:** 6m 47.397s
- **Turns:** 38

---

Review complete. `security_review.md` is written to `/data/results-cyber/claude/qwen/set_a/post_research/1/security/` (nothing in the read-only source tree was touched).

**What the code is:** a Jakarta Servlet 6.0 session-handoff component (16 main classes, ~2 725 lines) that re-verifies an upstream-asserted session identifier against the authoritative store and returns it in one hardened `Set-Cookie`, plus a descriptor, test scaffolding, build script and mutation tool.

**Six findings**, none critical — the component is genuinely well hardened (base64url reject-only validation makes cookie/header injection structurally impossible, `Secure`/`HttpOnly`/host-only/session-lifetime are class invariants, constant refusal body, fail-closed verifier loading, atomic bounded rate limiting, no `X-Forwarded-For` trust, no secrets/SQL/deserialization/exec):

| ID | Finding | Sev | CWE |
|---|---|---|---|
| SEC-01 | No HTTPS requirement anywhere: no `isSecure()` check, no `transport-guarantee`, no HSTS → the identifier is emitted in cleartext on a plaintext hop (the `Secure` flag only stops the browser replaying it, not the leak) | Medium | 319 |
| SEC-02 | `build.sh` packages the unauthenticated `StubControlServlet` and the `X-Stub-Assert`/`X-Stub-Login` header-driven assertion filter into deployable WARs — an auth bypass if one is mistaken for the shipping artifact | Medium | 489 |
| SEC-03 | `DeploymentHygiene.worldWritable` checks only `OTHERS_WRITE`, so a group-writable (0775/0770) classpath entry passes the gate whose entire purpose is stopping another local account from supplying the session verifier | Medium | 732 |
| SEC-04 | Session identifiers are logged as an **unkeyed** truncated SHA-256 digest — an offline guessing oracle if the upstream issues low-entropy ids (fix: HMAC with a per-process key) | Low | 532 |
| SEC-05 | No CSP / `X-Frame-Options` / `Referrer-Policy` on the HTML responses | Low | 1021 |
| SEC-06 | Per-source throttle collapses to one shared bucket behind a reverse proxy; 30 requests/min then deny issuance for everyone, undetectably | Low | 307 |

Skills applied: `performing-security-headers-audit`, `testing-for-sensitive-data-exposure`, `performing-cryptographic-audit-of-application`, `implementing-api-rate-limiting-and-throttling`, `testing-for-broken-access-control`, `testing-for-xss-vulnerabilities`; concurrency/visibility, `ServiceLoader` + filesystem permissions, timing channels, supply-chain integrity and active debug code were reviewed against general OWASP/CWE knowledge. Section 6 lists 24 verified controls, including the `tools/mutants.py` `shell=isinstance(cmd, str)` hazard, which I confirmed has no string call sites (no finding).
