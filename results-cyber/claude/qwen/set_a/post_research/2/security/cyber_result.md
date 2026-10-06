## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 4631696f-591a-472c-8cf5-b73c853ea90d
- **Input tokens:** 42
- **Output tokens:** 38742
- **Thinking tokens:** 15046
- **Cached read tokens:** 1916033
- **Cache creation tokens:** 142862
- **Total tokens:** 38784
- **Duration:** 8m 22.837s
- **Turns:** 30

---

Structure validates: one H1, the six required H2 sections, 20 opening fences all tagged `java`, 20 closing. Nothing in the source folder was touched (read-only, reviewed statically — no build, no execution).

**Report:** `/data/results-cyber/claude/qwen/set_a/post_research/2/security/security_review.md`

## What the code is
A 14-class Java library (`com.example.crypto`, ~3,350 lines of main source) that encrypts application data with AES-256-GCM and manages the keys: a record format with an authenticated header, a versioned key vault with rotation, four key sources (env var, raw key file, PKCS#12 store, PBKDF2-wrapped container), POSIX filesystem privacy guards, and a two-message exception type.

## Findings (8)

| ID | Severity | Issue |
|---|---|---|
| SEC-01 | High | `KeyVault.sourceFor` returns a throwaway random "decoy" key whenever the version table is full — including for the **active** version on the **encrypt** path, so the vault reports a successful encryption of real data under a key that is zeroed immediately and can never be recovered (CWE-636, `KeyVault.java:385`) |
| SEC-02 | Medium | PBKDF2 floor is 310,000 iterations, ~half current guidance for HMAC-SHA256, and a container file may legitimately declare it (CWE-916, `Limits.java:35`) |
| SEC-03 | Medium | Env/base64 key path builds a non-erasable `String` of the key and leaves buffers unwiped — contradicting the wiping discipline the rest of the component enforces (CWE-316, `KeyEncoding.java:70`) |
| SEC-04 | Low | `releaseIfUnreferenced` can zero a passphrase mid-derivation in another thread; good data then reports `AUTHENTICATION_FAILED` (CWE-362) |
| SEC-05 | Low | No attempt throttling on passphrase unwrap (CWE-307) |
| SEC-06 | Low | All-zero / single-repeated-byte key material accepted as a valid AES key (CWE-331) |
| SEC-07 | Low | Decrypted plaintext never wiped by the `String` overloads (CWE-316) |
| SEC-08 | Low | Active version read outside the rotation lock, so a concurrent `rotate()` makes encryption fail spuriously (CWE-362) |

SEC-01 is the one worth acting on first: it is silent, irreversible, and the configuration that triggers it (a high initial version plus 64 registered readable keys) needs no attacker.

## Notably clean
The cipher core held up under the two crypto skills' checklists — fixed AES-256-GCM/128-bit tag with no attacker-selectable path, per-record `SecureRandom` nonce, full header binding as AAD, canonical-only blob encoding, uniform single-failure decrypt, no hardcoded secrets, create-with-`0600` plus inode re-validation on key-file reads, and `char[]`-only passwords. There is no SQL, command, deserialization, XML, or network surface in the component at all. Section 6 lists ~20 verified controls with line references.
