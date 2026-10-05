# Security Review — AES-256-GCM Symmetric Encryption Project

**Date:** 2026-09-09
**Scope:** all code in this folder — `src/com/example/crypto/{SymmetricCrypto,App,Demo,SelfTest}.java`, `verify.sh`
**Excluded:** `out/**/*.class` (compiled build artifacts, not source), `README.md` / `prompt*.txt` / `result.md` / `return.txt` / `cyber_prompt.txt` / `cyber_return.txt` / `prompt_hash.txt` (non-code documentation)
**Method:** workflow of `review-code-for-security-vulnerabilities` — (1) read every file and inventory security-relevant behaviour, (2) match behaviours to specialised skills in the library, (3) apply each skill's checks against the code with `file:line` evidence, (4) report.

## What the code does (per file)

| File | Role | Security-relevant behaviour |
|---|---|---|
| `src/com/example/crypto/SymmetricCrypto.java` | Core library. AES-256-GCM with a self-describing envelope (`"AESG" \| version \| keySource \| [salt \| iterations] \| iv \| ciphertext+tag`); the whole header is fed to GCM as AAD. Keys come from a raw 256-bit `SecretKey` or a `char[]` passphrase stretched with PBKDF2-HmacSHA256 (default 310 000 iterations, min 100 000, envelope read-back capped at 10 000 000). Fresh 12-byte IV per call from `SecureRandom`; caller can never supply one. | Cipher/mode choice, IV/nonce management, CSPRNG, KDF parameters, key retention/wiping, DoS guard on stored iteration count |
| `src/com/example/crypto/App.java` | CLI: `keygen` / `encrypt` / `decrypt` / `demo` / `selftest`. Key via `--key-env` / `--key-file` / `--key` or `--password-env` / `--password` (+`--iterations`). `keygen --out` writes the key file 0600; `--key-file` warns if group/world readable; `--key`/`--password` warn that argv is visible in `ps`. Byte-exact `--stdin`/`--file`/`--out`; base64 envelope to stdout. | Secret handling in argv/env/file, key-file permissions, plaintext output permissions, key-material decoding |
| `src/com/example/crypto/Demo.java` | Narrated end-to-end walkthrough (raw key, passphrase, IV uniqueness, AAD binding, binary round trip). | Hardcoded credential-shaped strings, key material printed to stdout |
| `src/com/example/crypto/SelfTest.java` | 36 executable checks (round trips, 500 distinct IVs, wrong key/AAD, exhaustive single-byte tamper flips, truncation, key validation). | Test credential strings only; no real secrets |
| `verify.sh` | Build + self test + CLI round trips in a `mktemp -d` workspace. | Fake credential string used as test payload |

## Findings

### F1 — Decrypted secret written with default (umask) file permissions — **Medium**
- **CWE-732** (Incorrect Permission Assignment for Critical Resource)
- **Location:** `src/com/example/crypto/App.java:164`
- **Why:** `decrypt --out` writes the recovered plaintext — by definition a secret (DB URL, API key, etc.) — with `Files.write(Path.of(target), plaintext)`, i.e. default umask permissions (typically 0644: group/world readable). The same CLI goes to the trouble of forcing 0600 on *keygen* output (`App.java:138` → `restrictToOwner`) and even warns when a key *file* is world-readable (`warnIfWorldReadable`, `App.java:227`, `App.java:309-323`). The secret it produces is handled inconsistently: a group/world-readable plaintext is exactly what this tool is meant to prevent.
- **Fix:** apply the same owner-only treatment to `--out` output, e.g. `Files.write(path, plaintext, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)` with `FileAttribute<Set<PosixFilePermission>> posixPermissions(owner rw)` on POSIX, or write then call the existing `restrictToOwner(path, err)`.

### F2 — Key file created world-readable (umask) before being chmod'd to 0600 — **Low**
- **CWE-377** (Insecure Temporary File) / **CWE-367** (TOCTOU)
- **Location:** `src/com/example/crypto/App.java:137-138` (and the preceding `Files.exists` race at `App.java:135`)
- **Why:** `keygen --out` does `Files.writeString(path, …)` (created with default permissions) and only then `restrictToOwner(path, …)`. Under a typical umask of 022, the freshly generated 256-bit AES key — the highest-value secret in the system — is group/world readable for the window between create and chmod. A local attacker racing on the same host can read it. The `Files.exists` check before the write is also a classic check-then-act TOCTOU (moot for safety here because the write fails if the file exists without `--force`, but worth noting).
- **Fix:** create the file with the intended permissions atomically — `Files.createFile(path, PosixFilePermissions.asFileAttribute(Set.of(OWNER_READ, OWNER_WRITE)))` (or write to a private temp file in the same directory and `Files.move` with `ATOMIC_MOVE`).

### F3 — PBKDF2 work factor below current guidance; floor allows weak sealing — **Low**
- **CWE-916** (Insufficient Computational Effort for Key Derivation)
- **Location:** `src/com/example/crypto/SymmetricCrypto.java:46` (`DEFAULT_PBKDF2_ITERATIONS = 310_000`), `:49` (`MIN_PBKDF2_ITERATIONS = 100_000`), enforced at `:175` and `:348`
- **Why:** The code's comment cites "OWASP 2023+", but current OWASP Password Storage Cheat Sheet guidance for PBKDF2-HMAC-SHA256 is 600 000 iterations (the library skill `implementing-aes-encryption-for-data-at-rest` records the same "minimum 600,000 as of 2024"). The 310 000 default, and especially the 100 000 floor that any caller (or a crafted-but-in-range envelope) may use, is materially below current offline-cracking guidance for passphrase-stretched keys. The raw-key path is the recommended one, which limits impact.
- **Fix:** raise `DEFAULT_PBKDF2_ITERATIONS` to 600 000 and `MIN_PBKDF2_ITERATIONS` to at least 310 000 (keep the `MAX_PBKDF2_ITERATIONS` DoS cap at `:52`, which is a genuinely good control). Envelopes sealed at the old default remain decryptable because the iteration count travels in the envelope — no format break.

### F4 — Hardcoded credential-shaped strings in demo/test code — **Low**
- **CWE-798** (Use of Hardcoded Credentials) / **CWE-532** (Insertion of Sensitive Information into Log/File)
- **Location:** `src/com/example/crypto/Demo.java:24` (`postgres://app_user:S3cr3t-Passw0rd@db.internal:5432/billing`), `Demo.java:44` (passphrase `"correct horse battery staple"`), `Demo.java:35` (prints the generated base64 key to stdout); same pattern in `verify.sh:27,30`
- **Why:** These are explicitly fake placeholders, so no live secret is exposed. However: (a) they are precisely the strings secret scanners flag, so this repo will carry a permanent false-positive noise source; (b) `Demo` prints a *real, freshly generated* 256-bit key to stdout unredacted, and the credential-shaped URL is emitted verbatim — the "real secret printed to console" habit is normalised in shipped code; (c) placeholder credentials get copy-pasted into real integrations.
- **Fix:** replace with obviously-fake non-credential tokens (e.g. `postgres://REPLACE_WITH_USER:REPLACE_WITH_PASS@db.internal:5432/billing`), and in `Demo` print only a truncated/redacted key (as `shorten()` already does for tokens).

### F5 — Key/passphrase material retained in heap beyond use — **Low**
- **CWE-244** (Often Stored Sensitive Information)
- **Location:** `src/com/example/crypto/SymmetricCrypto.java:299,314` (`RawKey.encoded`), `:340,352` (`FromPassword.password`); the wipe helpers exist at `:228-237` and `PBEKeySpec.clearPassword()` is called at `:381`
- **Why:** `KeySource` clones the key bytes / passphrase into long-lived fields that are re-used on every `derive()` call and are never zeroed when the caller is done — `wipe()` only reaches the *caller's* array. In `App.java` the `--password` String itself can never be wiped (argv), and the `--key` bytes live on in `RawKey.encoded` for the process lifetime. The README acknowledges the `SecretKey` half of this ("key material outlives the object's use") but the `char[]`/`byte[]` fields here *are* erasable and are not.
- **Fix:** accept as a documented Java limitation (as the README does) or provide a `KeySource.close()/wipe()` that fills `password` and `encoded` with zeros, and call it from `App` after the command completes.

### F6 — `--key` / `--password` accept secrets on the command line — **Informational**
- **CWE-200** (Exposure of Sensitive Information)
- **Location:** `src/com/example/crypto/App.java:217`, `App.java:241` (warnings), options registered in `App.java:27-30`
- **Why:** The key or passphrase passed via `--key`/`--password` is visible in `ps`/`/proc/*/cmdline` and shell history for the process lifetime. The tool handles this correctly — it prints a warning and prefers `--key-env`/`--key-file`/`--password-env` — so this is an accepted, mitigated design choice, listed for completeness.
- **Fix (optional):** drop the argv forms entirely, or read from a TTY prompt when no safer option is given.

### F7 — Silent raw-bytes reinterpretation of a mistyped base64 key — **Low**
- **CWE-697** (Incorrect Calculation / selection of incorrect value)
- **Location:** `src/com/example/crypto/App.java:255-272` (`decodeKey`), fallback at `:269-271`
- **Why:** `decodeKey` tries base64; if the result is not 32 bytes it silently reinterprets the *text* as 32 raw ISO-8859-1 bytes. A user who pastes a base64 key that is truncated/corrupted to exactly 32 characters (or whose padding is mangled) gets a *different, silently wrong* key: `encrypt` succeeds and produces an envelope that no one can ever open (or worse, two parties "agree" on a wrong key). There is no diagnostic that the raw fallback fired.
- **Fix:** make the raw-bytes interpretation explicit — only take it when the input is unambiguously not base64 (e.g. requires an opt-in `--key-raw` flag or is only permitted for `--key-file` where binary content is expected) — and warn on stderr whenever the fallback is used.

## Verified correct (checked, no finding)

Cross-checked against `performing-cryptographic-audit-of-application` (weak-hash/insecure-cipher/bad-mode/hardcoded-secret/weak-KDF/poor-entropy table) and `implementing-aes-encryption-for-data-at-rest` (validation criteria):

- **No weak/deprecated primitives:** no MD5/SHA-1/DES/RC4/ECB anywhere; only AES-256, GCM, PBKDF2-HMAC-SHA256, and `SecureRandom` (`SymmetricCrypto.java:55-57`).
- **Cipher mode & strength:** `AES/GCM/NoPadding` with 256-bit key and 128-bit tag (`SymmetricCrypto.java:55,114,189`); AES-256 enforced for raw keys (`:66`, `:311-313`) and KDF output (`:376`).
- **IV/nonce management:** fresh 12-byte IV from `SecureRandom` per encrypt call (`SymmetricCrypto.java:110`); no caller-supplied IV path exists; SelfTest asserts 500 encrypts → 500 distinct IVs and 500 distinct envelopes (`SelfTest.java:86-98`). 96-bit random nonces give the standard birthday-bound usage cap (~2³² messages/key), which is acceptable for this use.
- **Tamper integrity:** the entire header (including IV, salt, and iteration count) is bound into the GCM tag via `updateAAD(header)` (`SymmetricCrypto.java:117,191`); SelfTest flips every single byte of both envelope types and confirms all are rejected, with post-IV bytes rejected *by the tag itself* (`SelfTest.java:108-124`, `131-186`).
- **AEAD error handling:** wrong key, wrong AAD, and corruption all surface as one indistinguishable `CryptoException` with `isAuthenticationFailure()` — no error-message oracle (`SymmetricCrypto.java:196-204, 402-421`).
- **KDF construction:** random 16-byte salt per envelope, salt + work factor stored in (and authenticated inside) the envelope, `PBEKeySpec.clearPassword()` in `finally` (`SymmetricCrypto.java:163-170, 352-355, 373-382`).
- **DoS guard on untrusted input:** iteration counts read from envelopes are validated against `[100 000, 10 000 000]` *before* PBKDF2 runs (`SymmetricCrypto.java:52,175-178`); a hostile envelope cannot force unbounded KDF work. Truncated/malformed envelopes and non-base64 input are rejected structurally (`SymmetricCrypto.java:152-161, 242-249`).
- **CLI hygiene:** no shell execution or command construction from user input (no injection surface); `Path.of` used directly with user-supplied paths (no concatenation/traversal logic to mis-handle); `--key-file` warns on group/world-readable key files (`App.java:227`); `verify.sh` uses `mktemp -d` with trap cleanup and no real secrets.
- **No other attack surface:** no SQL, no deserialization, no network/TLS code, no dynamic code loading — the OWASP categories those skills cover (SQLi, deserialization, XSS, SSRF, JWT) simply do not apply to this codebase.

## Skills applied

Specialised skills from the library matched in Step 2 (name grep for `crypto|cryptograph|secret|password|key|hash|credential|aes|encrypt` over the skill directory, then description skimming):

1. **`performing-cryptographic-audit-of-application`** — weakness-category table (weak hashing, insecure ciphers, ECB, key size, hardcoded secrets, weak KDF, poor entropy, deprecated protocols) applied to all four Java files; drove the F3, F4 findings and the "verified correct" algorithm/mode/KDF/RNG checks.
2. **`implementing-aes-encryption-for-data-at-rest`** — AES-256-GCM validation criteria (AEAD round trip, tag tamper detection, KDF iteration guidance — "minimum 600,000 as of 2024", 96-bit CSPRNG nonce never reused, key wiping) applied to `SymmetricCrypto.java`; drove F3 (work factor) and F5 (wiping) and confirmed the nonce/envelope-format checks.

## General-knowledge review (behaviour with no matching library skill)

Per the router workflow, the following behaviours had no clearly matching specialised skill and were reviewed against general OWASP Top 10 / CWE knowledge:

- **File permission handling for secret artifacts** (`decrypt --out` output, `keygen` create-then-chmod window) → CWE-732/CWE-377 → findings F1, F2.
- **Secret exposure through process listings** (`--key`/`--password` argv) → CWE-200 → finding F6.
- **Sensitive data retention in memory** (key bytes, passphrase `char[]` fields) → CWE-244 → finding F5.
- **Input-decoding ambiguity in key material parsing** (`decodeKey` raw fallback) → CWE-697 → finding F7.

## Summary

| # | Severity | CWE | Location |
|---|---|---|---|
| F1 | Medium | CWE-732 | `App.java:164` — `--out` plaintext not owner-only |
| F2 | Low | CWE-377 / CWE-367 | `App.java:135-138` — key file briefly umask-readable |
| F3 | Low | CWE-916 | `SymmetricCrypto.java:46,49` — PBKDF2 work factor below current guidance |
| F4 | Low | CWE-798 / CWE-532 | `Demo.java:24,35,44`; `verify.sh:27,30` — credential-shaped strings, key printed |
| F5 | Low | CWE-244 | `SymmetricCrypto.java:299,314,340,352` — key/passphrase material not erased |
| F6 | Informational | CWE-200 | `App.java:217,241` — argv secret exposure (warned, mitigated) |
| F7 | Low | CWE-697 | `App.java:255-272` — silent raw-bytes key fallback |

The cryptographic core (AES-256-GCM, fresh authenticated IVs, AAD-bound header, PBKDF2 with a DoS cap, non-oracle error handling) is sound and well-tested; the residual issues are around key/secret *hygiene* (permissions, work factor, in-memory retention, demo strings) rather than the cipher itself. No critical or high-severity defects were found.
