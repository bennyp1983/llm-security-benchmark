# Security Review — `SecureData.java`

**Scope:** `/data/results-cyber/claude/set_a/pilot/2/basic`
**Date:** 2026-09-09
**Method:** `review-code-for-security-vulnerabilities` router skill — understand the code, select matching specialised skills from the library, apply them against the source with `file:line` evidence.

---

## 1. What the code does (Step 1)

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SecureData.java` (310 lines) | Self-contained AES-256-GCM encrypt/decrypt utility with a CLI. Two modes: raw key and password-derived key. | Symmetric crypto (cipher/mode/tag), IV/nonce generation, PBKDF2 key derivation, key generation/export/import, CSPRNG use, secret handling in memory, untrusted message parsing, secrets passed via argv, secrets printed to stdout, error handling. |
| `SecureData.class` | Compiled artifact of the above (class major version 61 = Java 17). Strings confirm it matches the source (`AES/GCM/NoPadding`, `PBKDF2WithHmacSHA256`, demo constants). | Pre-built binary shipped next to source. |
| `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt` | Harness metadata: the generation prompt, this review's prompt, a hash, the generating run's transcript/telemetry. Not application code. | `result.md` / `return.txt` reproduce the model output; no credentials beyond the demo values already in the source. |

**Keywords derived:** cryptography, AES-GCM, nonce/IV management, key derivation (PBKDF2), key management, hardcoded secret, sensitive data exposure, secrets in memory, input validation, error handling.

**What is done correctly** (verified, no finding):
- `AES/GCM/NoPadding` with a 128-bit tag — AEAD, not ECB, not unauthenticated CBC (`SecureData.java:37,43`).
- 256-bit keys (`SecureData.java:41`), `KeyGenerator` seeded from `SecureRandom` (`SecureData.java:59-61`).
- Fresh random 96-bit IV per message from a CSPRNG, never derived or fixed (`SecureData.java:42,122,160,201-205`).
- Per-message random 16-byte salt for password mode (`SecureData.java:159`).
- Version byte bound as AAD on both encrypt and decrypt (`SecureData.java:125,150,165,195`), so the mode selector is tag-protected.
- No MD5/SHA-1/DES/3DES/RC4 anywhere; no `Random`/time-seeded entropy; no network or TLS code; no SQL, deserialization, file, or OS-command paths — so those OWASP categories are not reachable here.
- `SecretKeySpec` copies its input, so the `Arrays.fill` wipes at `SecureData.java:79,91` are correct and not a use-after-wipe bug.

---

## 2. Findings

Severity reflects impact in the intended use ("encrypt sensitive application data"). No finding breaks the confidentiality of a correctly used key — the core construction is sound. The issues are in key/secret *handling* around the crypto.

### F-01 — Keys and passwords passed as command-line arguments (High)
**CWE-214: Invocation of Process Using Visible Sensitive Information** (also CWE-522)
**Evidence:** `SecureData.java:228-241` (`String secret = args[2]`, used as `--key` at `:233` and `--password` at `:237`); documented as the intended interface at `SecureData.java:29-32,302-307`.

Process arguments are world-readable on Linux via `/proc/<pid>/cmdline` and `ps` for the lifetime of the process, and are persisted to shell history. Any local user, and any log/monitoring agent capturing command lines, recovers the AES key or password — which defeats the entire encryption scheme. The generating run's own notes call this out as an "operational note"; it is a code-level defect in the CLI contract, because the tool offers no other input path.

**Fix:** read the key/password from `System.console().readPassword()`, an environment variable, or a file path argument (`--key-file`). Keep argv acceptance only behind an explicit `--insecure-arg-secret` flag, if at all.

### F-02 — Secret key and sensitive plaintext printed to stdout (High)
**CWE-532: Insertion of Sensitive Information into Log File** (also CWE-497)
**Evidence:** `SecureData.java:220` (`keygen` prints the base64 AES key), `SecureData.java:267-270` (demo prints the plaintext, **the key**, the ciphertext and the roundtrip), `SecureData.java:273,276-278`.

The generated key is written to stdout, where it lands in terminal scrollback, CI job logs, redirected files, and container log collectors — the ciphertext and the key it protects are frequently captured by the same log sink, collapsing the security of the scheme to zero. The demo additionally prints a plaintext PAN and SSN (`SecureData.java:263`) alongside them, which is a PCI-DSS/PII logging violation if the demo is ever run in a shared environment.

**Fix:** write `keygen` output to a file with `0600` permissions (or emit to a fd the caller designates) and warn when stdout is a TTY-less pipe; in `demo()`, never print the key or the plaintext — print only lengths/fingerprints and the pass/fail of the tamper and wrong-key checks.

### F-03 — Hardcoded credential and hardcoded sensitive test data in source (Medium)
**CWE-798: Use of Hard-coded Credentials** (test PII: CWE-532/CWE-1188)
**Evidence:** `SecureData.java:275` and `SecureData.java:278` — the literal password `"correct horse battery staple"`; `SecureData.java:263` — `"card=4111111111111111; ssn=123-45-6789"`.

These are demo-only and not used to protect real data, so impact is limited. But they are compiled into the shipped artifact (both strings are recoverable from `SecureData.class`), they will fire on every secret scanner (gitleaks/trufflehog) creating triage noise, and a hardcoded password in a sample is the pattern most often copy-pasted into production callers.

**Fix:** generate the demo password randomly at runtime, or read it from an env var with a documented default of "none"; replace the card/SSN literal with obviously fake, non-PII-shaped text.

### F-04 — PBKDF2 iteration count below current guidance, and no password strength floor (Medium)
**CWE-916: Use of Password Hash With Insufficient Computational Effort** (also CWE-521)
**Evidence:** `SecureData.java:45` (`PBKDF2_ITERATIONS = 310_000`), used at `SecureData.java:85`; `deriveKey` accepts any `char[]` with no length/entropy check (`SecureData.java:84-96`), reached from the CLI at `SecureData.java:237`.

310,000 matches OWASP's older PBKDF2-HMAC-SHA256 figure but is below the ≥600,000 minimum the library's `implementing-aes-encryption-for-data-at-rest` skill mandates for 2024+. Combined with an unbounded-weakness password, an attacker holding a captured message (salt and IV are in the clear by design, `SecureData.java:168-173`) can mount an offline GPU dictionary attack against the derived key. The cost factor is also frozen as a compile-time constant with no per-message iteration field, so it cannot be raised for existing ciphertexts — the format has a version byte but no KDF-parameter field.

**Fix:** raise to ≥600,000 for PBKDF2-HMAC-SHA256, or switch to a memory-hard KDF (Argon2id / scrypt); embed the iteration count (and KDF id) in the message so it can be increased without breaking old ciphertexts; reject passwords below a documented minimum length in `encryptWithPassword`.

### F-05 — Key material held in immutable `String` objects that cannot be wiped (Medium)
**CWE-316: Cleartext Storage of Sensitive Information in Memory**
**Evidence:** `SecureData.java:65-67` (`exportKey` returns the base64 key as a `String`), `SecureData.java:70-71` (`importKey` takes a `String`), `SecureData.java:228` (`String secret = args[2]` holds the raw key or password), `SecureData.java:196` (decrypted plaintext returned as a `String`), `SecureData.java:101` / `SecureData.java:157` (plaintext accepted as a `String`).

The code is careful to zero `byte[]`/`char[]` buffers (`SecureData.java:79,91,94,106,116,243`), but every one of those wipes is undone by the surrounding `String`s, which are immutable and stay in the heap until GC — recoverable from a heap dump, a core file, or swap. `args[2]` in particular is never cleared: the `toCharArray()` at `SecureData.java:237` is wiped at `:243`, but the original `String` is not. Neither `SecretKey` (`SecureData.java:61,233,265`) is ever `destroy()`ed.

**Fix:** offer `char[]`/`byte[]` overloads for `importKey`, `encrypt`, and `decryptWithPassword`; return the exported key as a `char[]`; call `SecretKey.destroy()` where the provider supports it; treat `String`-based entry points as convenience APIs and document the limitation.

### F-06 — Insufficient minimum-length validation on attacker-controlled messages (Low)
**CWE-1284: Improper Validation of Specified Quantity in Input** (also CWE-20)
**Evidence:** `SecureData.java:138` (`require(buffer.remaining() > 1 + GCM_IV_BYTES, ...)`) and `SecureData.java:181` (`require(buffer.remaining() > 1 + SALT_BYTES + GCM_IV_BYTES, ...)`).

A well-formed message must also carry the 16-byte GCM tag, so the true minimums are 29 and 45 bytes; the checks accept 14 and 30. A message in the gap yields a `sealed` array shorter than the tag, which is then handed to `doFinal` (`SecureData.java:151,196`). SunJCE rejects this with `AEADBadTagException`, so there is no memory-safety or authentication bypass here — but the validation does not enforce the invariant the comment at `SecureData.java:21-22` claims, and the behaviour becomes provider-dependent.

**Fix:** `require(buffer.remaining() >= 1 + GCM_IV_BYTES + GCM_TAG_BITS / 8, ...)` and the equivalent for password mode.

### F-07 — Unchecked exceptions escape the documented `GeneralSecurityException` contract (Low)
**CWE-755: Improper Handling of Exceptional Conditions** (also CWE-248, CWE-209)
**Evidence:** `Base64.getDecoder().decode(...)` on untrusted input at `SecureData.java:112` and `SecureData.java:180` throws `IllegalArgumentException`; `require(...)` throws `IllegalArgumentException` at `SecureData.java:207-211`, reached from `SecureData.java:138,140,181,183`; `main` declares `throws Exception` (`SecureData.java:213`) so any of these prints a stack trace.

Callers following the Javadoc (`SecureData.java:110,135,177`) will catch only `GeneralSecurityException`, so malformed base64 or a truncated message crashes the caller rather than being reported as a decryption failure — an availability issue for any service that decrypts attacker-supplied data. The distinct exception types and messages (`SecureData.java:140-141,183-184`) also make "wrong format" externally distinguishable from "wrong key/tampered", a small information leak.

**Fix:** wrap parsing and base64 decoding so all decryption failures surface as a single `GeneralSecurityException` with a uniform message; catch and summarise exceptions in `main` instead of letting them propagate.

### F-08 — Random 96-bit IVs bound the safe message count per key, with no enforcement (Low / by design)
**CWE-323: Reusing a Nonce, Key Pair in Encryption**
**Evidence:** `SecureData.java:122,160` (random IV per message) with `SecureData.java:42` (12-byte IV); no counter, no message-count tracking, no rotation hook anywhere in the file.

Random 96-bit nonces are the correct choice for a stateless format, but the birthday bound means IV collision probability becomes non-negligible past roughly 2³² messages under one key — and GCM nonce reuse leaks the XOR of plaintexts and enables tag forgery. Nothing in the code or Javadoc caps this; the only mention is in the generating run's prose (`result.md`), not in the source.

**Fix:** document the per-key message limit in the class Javadoc, and either expose a message counter for callers to drive rotation or adopt an extended-nonce construction (XChaCha20-Poly1305, or AES-GCM-SIV) if a key must survive high volumes.

### F-09 — Whole-message in-memory processing with no size bound (Informational)
**CWE-789: Memory Allocation with Excessive Size Value**
**Evidence:** `SecureData.java:145` and `SecureData.java:190` allocate `new byte[buffer.remaining()]`; `SecureData.java:126,166` call `doFinal` on the entire payload; there is no streaming API.

If this class is put behind a service that decrypts caller-supplied blobs, a large input causes several full-size copies (base64 array, `sealed`, plaintext) and can exhaust the heap. Not exploitable in the shipped CLI, where inputs come from argv.

**Fix:** add a configurable maximum message size, and a `CipherInputStream`-based streaming path for large payloads.

---

## 3. Observations (not vulnerabilities)

- `SecureData.class` is a pre-built binary committed alongside the source. Its strings match `SecureData.java` and the class version (61 / Java 17) is consistent, so there is no evidence of divergence — but shipping a binary that consumers cannot trivially verify is a supply-chain hygiene issue (build from source in CI instead).
- The salt is not passed as AAD (`SecureData.java:165,195`), which is fine: altering the salt derives a different key and the GCM tag then fails. No finding.
- `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, and `return.txt` are harness metadata, not executable code; they were read and contain no credentials beyond the demo literals already reported in F-03.

---

## 4. Skills applied

| Skill | How it was used |
|---|---|
| `review-code-for-security-vulnerabilities` | Router: drove the four-step workflow (understand → select → apply → report). |
| `performing-cryptographic-audit-of-application` | Applied its weakness table and validation criteria: deprecated algorithms (none), ECB mode (none), key size (256-bit, OK), hardcoded secrets (→ F-03), weak KDF parameters (→ F-04), entropy/RNG (`SecureRandom`, OK), key storage and rotation practices (→ F-01, F-02, F-05, F-08). |
| `implementing-aes-encryption-for-data-at-rest` | Applied its AES-256-GCM checklist: AEAD mode (OK), 96-bit never-reused nonce from a CSPRNG (OK → F-08 for the birthday bound), salt/nonce/ciphertext/tag message format (OK, → F-06 for the length check), "PBKDF2 minimum 600,000 iterations as of 2024" (→ F-04), "securely wipe keys from memory after use" (→ F-05), streaming for large files (→ F-09). |
| `testing-for-sensitive-data-exposure` | Applied its insecure-storage/leakage checks, adapted from web responses to CLI surfaces: secrets in process arguments and history (→ F-01), secrets and PII written to logs/stdout (→ F-02), PAN/SSN handling (→ F-02, F-03), error responses distinguishable to an attacker (→ F-07). |

Skills considered and **not** applied, with reasons: `implementing-secret-scanning-with-gitleaks` and `implementing-secrets-scanning-in-ci-cd` (tooling/CI process guidance, not source-level rules — the hardcoded-secret finding F-03 is reported directly); `configuring-hsm-for-key-storage`, `implementing-secrets-management-with-vault`, `implementing-envelope-encryption-with-aws-kms` (key-custody architecture; relevant as remediation direction for F-01/F-02 but the code has no key store to audit); `exploiting-sql-injection-*`, `exploiting-insecure-deserialization`, `testing-for-xss-vulnerabilities`, the JWT/OAuth/API skills (no SQL, deserialization, rendering, network, or authentication surface exists in this code).

**Behaviours reviewed against general OWASP Top 10 / CWE knowledge** (no matching library skill): untrusted `ByteBuffer` message parsing and bounds checking (→ F-06, CWE-1284); exception-handling contract and error-message differentiation (→ F-07, CWE-755/CWE-209); unbounded allocation from untrusted length (→ F-09, CWE-789); Java-specific `String` immutability versus secret zeroization (→ F-05, CWE-316); command-line argument exposure on Linux (→ F-01, CWE-214).

---

## 5. Summary

| ID | Severity | CWE | Location |
|---|---|---|---|
| F-01 | High | CWE-214 | `SecureData.java:228-241` |
| F-02 | High | CWE-532 | `SecureData.java:220,267-270` |
| F-03 | Medium | CWE-798 | `SecureData.java:263,275,278` |
| F-04 | Medium | CWE-916 | `SecureData.java:45,84-96` |
| F-05 | Medium | CWE-316 | `SecureData.java:65-67,196,228` |
| F-06 | Low | CWE-1284 | `SecureData.java:138,181` |
| F-07 | Low | CWE-755 | `SecureData.java:112,180,207-211` |
| F-08 | Low | CWE-323 | `SecureData.java:122,160` |
| F-09 | Info | CWE-789 | `SecureData.java:145,190` |

The cryptographic core — AES-256-GCM, 128-bit tag, random per-message 96-bit IV, PBKDF2-HMAC-SHA256 with a per-message salt, AAD-bound version byte — is correctly constructed, and there is no algorithm, mode, or IV-reuse flaw. Every High and Medium finding is about how key material and secrets are *moved and stored* around that core: through argv (F-01), through stdout (F-02), through hardcoded literals (F-03), and through unwipeable `String`s (F-05), plus a KDF cost factor that is both below current guidance and not upgradable in the message format (F-04). Fixing F-01 and F-02 is the highest-value change.
