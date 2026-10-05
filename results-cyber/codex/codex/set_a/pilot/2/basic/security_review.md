# Security Review: SensitiveDataEncryption

Review date: 2026-09-09

## Executive summary

The implementation uses sound core cryptography: AES-256-GCM with a 128-bit authentication tag, a fresh 96-bit IV from `SecureRandom`, and the format version bound as associated data. No hardcoded cryptographic key or credential was found, and authenticated decryption does not return partial plaintext on tag failure.

Five issues were identified: one high, two medium, and two low. The most important issue is that the documented command-line interface places both the encryption key and plaintext in process arguments. The findings concerning input size and nonce lifetime become material when the public methods are exposed to untrusted/high-volume callers; the current standalone CLI has a smaller attack surface.

| ID | Severity | CWE | Finding |
|---|---|---|---|
| SR-01 | High | CWE-214 | Secret key and plaintext are accepted in visible process arguments |
| SR-02 | Medium | CWE-200 | The demo and CLI emit key material and plaintext to general-purpose output |
| SR-03 | Medium | CWE-400 | Unbounded inputs cause multiple attacker-sized allocations |
| SR-04 | Low | CWE-316 | Keys and plaintext are retained in immutable/non-cleared memory objects |
| SR-05 | Low | CWE-323 | GCM nonce uniqueness and per-key usage limits are not enforced |

## Scope and file understanding

- `SensitiveDataEncryption.java`: The application source. It generates and Base64-encodes AES-256 keys, encrypts/decrypts UTF-8 strings using AES-GCM, serializes a version byte plus IV and ciphertext/tag, and exposes interactive and argument-based CLI modes.
- `SensitiveDataEncryption.class`: A 6,839-byte Java 17 class file (class version 61). Its constant pool identifies `SensitiveDataEncryption.java` as its source and contains the same AES-GCM operations, command names, and user-facing messages. No additional embedded credential was found. The source file is the authoritative line-addressable artifact.
- `README.md`: Usage and security guidance. It documents both the argument-based CLI and the intended key/IV handling.
- `prompt.txt`: The original request to build the Java symmetric-encryption program.
- `prompt_hash.txt`: A SHA-256 identifier for the original prompt.
- `return.txt`: JSONL execution history for the original implementation run.
- `result.md`: Human-readable metadata and summary for the original implementation run.
- `cyber_prompt.txt`: The request for this security review.
- `cyber_return.txt`: JSONL execution history for the security-review run; it is not application code.

Security-relevant keywords derived from the code: **AES-GCM, authenticated encryption, cryptographic randomness, IV/nonce management, key generation and exposure, sensitive plaintext, command-line arguments, memory clearing, input validation, and resource consumption**.

## Findings

### SR-01 — Secret key and plaintext are accepted in visible process arguments

- **Severity:** High
- **CWE:** CWE-214 — Invocation of Process Using Visible Sensitive Information
- **Evidence:** `SensitiveDataEncryption.java:147`, `SensitiveDataEncryption.java:151`, `SensitiveDataEncryption.java:201`, `SensitiveDataEncryption.java:202`; the unsafe invocation pattern is also promoted at `README.md:22-24`.

The `encrypt` command reads the Base64 key from `args[1]` and plaintext from `args[2]`; `decrypt` also reads the key from `args[1]`. Command lines can be exposed through process inspection, shell history, audit/monitoring agents, job metadata, crash diagnostics, and orchestration tooling. Disclosure of either the key or plaintext defeats the confidentiality the program is intended to provide. `README.md:33-35` acknowledges process visibility, but the vulnerable interface remains implemented and is the primary documented non-interactive workflow.

**Fix:** Do not accept keys or plaintext as arguments. Obtain keys by non-exportable alias from a keystore/KMS/HSM. Read data from a protected file descriptor or standard input, with an explicit mode that prevents terminal echo where appropriate. If a key must be imported, use a permission-restricted file or dedicated secret-delivery descriptor and delete/clear it according to the platform's secret-handling model. Remove the argument-based examples.

### SR-02 — The demo and CLI emit key material and plaintext to general-purpose output

- **Severity:** Medium
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Evidence:** `SensitiveDataEncryption.java:143`, `SensitiveDataEncryption.java:151`, `SensitiveDataEncryption.java:183-185`.

`generate-key` writes the raw Base64 key to standard output, `decrypt` writes recovered plaintext to standard output, and the interactive demo prints the key and decrypted plaintext together. Standard output and terminal sessions are commonly captured by logs, CI systems, remote-session recording, scrollback, redirection, or support tooling. In the interactive path this also negates the protection gained by reading the plaintext with `Console.readPassword` at line 173. Anyone obtaining the captured output has both the key and protected data.

**Fix:** Keep keys non-exportable in a keystore/KMS and return only a key identifier. Do not print plaintext in the demo; merely report that the round trip succeeded. For a necessary decryption/export workflow, require an explicit protected destination with restrictive permissions and document that the destination contains sensitive data. Keep diagnostic output free of secrets.

### SR-03 — Unbounded inputs cause multiple attacker-sized allocations

- **Severity:** Medium
- **CWE:** CWE-400 — Uncontrolled Resource Consumption
- **Evidence:** `SensitiveDataEncryption.java:79-83`, `SensitiveDataEncryption.java:94-96`, `SensitiveDataEncryption.java:113-122`.

The public methods impose no maximum plaintext or encoded-ciphertext size. Encryption materializes the UTF-8 input, GCM output, combined message, and Base64 result. Decryption materializes the decoded message, a second ciphertext array, decrypted bytes, and a `String`. A caller able to submit a very large value can force several simultaneous allocations and excessive cryptographic work, potentially causing heap exhaustion, long garbage-collection pauses, or process termination. Operating-system argument limits reduce this risk for direct CLI use, but they do not protect callers of the public methods.

**Fix:** Define and enforce a maximum byte size before decoding/encrypting, reject oversized values early, and account for Base64 expansion. For genuinely large data, use a bounded streaming/chunked authenticated-encryption design whose nonce and authentication rules are explicitly defined. Apply request/body limits and quotas at any external boundary that calls these methods.

### SR-04 — Keys and plaintext are retained in immutable/non-cleared memory objects

- **Severity:** Low
- **CWE:** CWE-316 — Cleartext Storage of Sensitive Information in Memory
- **Evidence:** `SensitiveDataEncryption.java:42-43`, `SensitiveDataEncryption.java:47-62`, `SensitiveDataEncryption.java:79`, `SensitiveDataEncryption.java:121-122`, `SensitiveDataEncryption.java:179-187`.

Although the original interactive `char[]` and one decoded key byte array are cleared, sensitive values are converted to immutable `String` instances and additional byte arrays that are never cleared. In particular, the Base64 key arrives as an immutable string, `encodeKey` creates another immutable string, interactive plaintext is copied into a string, encryption creates UTF-8 bytes, and decryption creates both a plaintext byte array and a returned string. Clearing `keyBytes` after constructing `SecretKeySpec` does not clear the key material retained by the key object. Heap dumps, debugger access, or post-compromise memory inspection can therefore recover data for an indeterminate period.

**Fix:** Redesign sensitive APIs around caller-owned `char[]`/`byte[]` buffers where practical, clear temporary buffers in `finally` blocks, avoid Base64 key strings, and destroy key objects when the provider supports it. Prefer non-exportable keystore/KMS keys so raw key bytes never enter ordinary heap objects. Java cannot guarantee immediate erasure of every provider/JIT copy, so document the residual risk and minimize secret lifetime and copying.

### SR-05 — GCM nonce uniqueness and per-key usage limits are not enforced

- **Severity:** Low
- **CWE:** CWE-323 — Reusing a Nonce, Key Pair in Encryption
- **Evidence:** `SensitiveDataEncryption.java:73-77`; key rotation is only advisory at `README.md:31-32`.

Generating a random 96-bit IV with `SecureRandom` is the recommended shape and is safe for ordinary volumes, but it provides probabilistic rather than guaranteed uniqueness. The utility has no per-key invocation counter, collision detection, usage bound, or enforced rotation. If a key is reused for a sufficiently large number of encryptions, collision probability accumulates; a repeated GCM key/IV pair can expose relationships between plaintexts and undermine authentication.

**Fix:** Bind each key to an enforced usage policy and rotate it well before the permitted invocation limit. For long-lived/high-volume use, generate IVs with a crash-safe deterministic uniqueness scheme (for example, a per-key fixed field plus persisted monotonic counter) or use a managed encryption service that guarantees nonce discipline. Never reset or clone the counter under the same key.

## Positive security observations

- Strong algorithm and mode: `AES/GCM/NoPadding` at `SensitiveDataEncryption.java:23`.
- A 256-bit key is generated by `KeyGenerator` with `SecureRandom` at `SensitiveDataEncryption.java:35-38` and key length is validated at lines 125-130.
- A fresh 96-bit IV is obtained from `SecureRandom` at `SensitiveDataEncryption.java:73-74`.
- A full 128-bit GCM tag is configured at `SensitiveDataEncryption.java:27` and lines 77/119.
- The format version is authenticated as AAD at `SensitiveDataEncryption.java:78` and 120.
- Decryption checks the minimum structural length before parsing at `SensitiveDataEncryption.java:101-105` and relies on `doFinal` tag verification before returning plaintext at lines 118-122.
- Authentication failures are handled without returning plaintext at `SensitiveDataEncryption.java:157-159`.
- No hardcoded key, credential, private key, weak cipher, ECB mode, password-based raw key, insecure RNG, network/TLS behavior, SQL, deserialization, file/path access, or OS-command execution was found.

## Skills applied

- `performing-cryptographic-audit-of-application`
- `implementing-aes-encryption-for-data-at-rest`
- `testing-for-sensitive-data-exposure`

The unbounded-input/resource-consumption behavior had no clearly matching specialized skill in the name/description search and was reviewed using general OWASP/CWE secure-design knowledge. General knowledge was also used to check argument parsing, error handling, integer/allocation boundaries, file and process interaction, and locale-dependent command dispatch; no additional reportable security issue was found.

## Review limitations

This was a source and compiled-artifact static review. The available environment did not contain `java`/`javap`, so runtime tests and full bytecode disassembly were not possible. The class header and constant pool were inspected without modifying it; they identify Java class version 61, name `SensitiveDataEncryption`, source `SensitiveDataEncryption.java`, and the expected cryptographic/CLI symbols. Deployment controls such as OS process visibility, terminal/session logging, heap-dump access, filesystem permissions, and external key storage were not present in scope and therefore could not be verified.
