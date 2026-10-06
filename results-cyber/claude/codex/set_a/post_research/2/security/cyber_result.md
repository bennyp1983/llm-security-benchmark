## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 88b6cbf6-dc18-459d-b151-5abf166e3eb6
- **Input tokens:** 20
- **Output tokens:** 21506
- **Thinking tokens:** 6949
- **Cached read tokens:** 468458
- **Cache creation tokens:** 68603
- **Total tokens:** 21526
- **Duration:** 4m 28.791s
- **Turns:** 13

---

Report written to `security_review.md` in the working folder; the source tree was read only and is unchanged.

**What the code is:** a dependency-free Java 17 AES-256-GCM data-protection component (`AesGcmDataProtector` + `DataProtectionException`) with a key ring, random 96-bit nonces, 128-bit tags, and a self-describing envelope whose header, `purpose` and caller `context` are bound in as length-delimited AAD.

**Skills applied** (per the router workflow): `performing-cryptographic-audit-of-application`, `implementing-aes-encryption-for-data-at-rest`, `exploiting-insecure-deserialization`, `testing-for-sensitive-data-exposure`, plus `configuring-hsm-for-key-storage` as a reference point; envelope parsing, AAD canonicalisation, error-oracle and concurrency behaviour were reviewed against general OWASP/CWE knowledge since no library skill covered them.

**Findings — no Critical or High:**

| ID | Title | Severity | CWE |
|---|---|---|---|
| SEC-01 | GCM nonce-reuse limit scoped per object instance — resets on every restart/second instance, so the 2^32 budget is never actually enforced | Medium | CWE-323 |
| SEC-02 | `DestroyableAesKey.equals` zeroes the array returned by the *other* key and throws on a destroyed key | Low | CWE-404 |
| SEC-03 | `hashCode` publishes `Arrays.hashCode` of the raw key bytes — a stable key fingerprint that escapes into dumps/collections | Low | CWE-200 |
| SEC-04 | Serialization blocked (`writeObject`) but deserialization is not — no `readObject`/`readObjectNoData` guard on a `Serializable` key class | Low | CWE-502 |

The cryptographic core held up: correct mode/key/tag/nonce sizes, canonical length-prefixed AAD (no cross-context substitution), uniform `DataProtectionException` on every attacker-reachable path, a dummy decryption for unknown key IDs so there's no cheap oracle, bounds checked before allocation, defensive key copying with zeroization, and read/write-lock atomicity for close-versus-use. Section 6 lists ~20 verified controls with file:line evidence.
