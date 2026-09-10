## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** c64b78aa-95c0-45aa-ac6d-d64ecb3a4ce8
- **Input tokens:** 28
- **Output tokens:** 22225
- **Thinking tokens:** 3246
- **Cached read tokens:** 340775
- **Cache creation tokens:** 29904
- **Total tokens:** 22253
- **Duration:** 4m 20.176s
- **Turns:** 14

---

Built and verified in `/data/results/claude/set_a/pilot/2/security` — 8 source files, compiles clean on JDK 17, all self-tests and manual provider tests pass.

## What it does

`SymmetricCipher` (`src/com/example/crypto/SymmetricCipher.java`) does AES-256-GCM with a fresh random 96-bit IV per message and a 128-bit tag. Output is a versioned envelope:

```
"SDC1" | version | paramsLen | params | ivLen | iv | ciphertext||tag
```

The entire header is fed to GCM as additional authenticated data, so the version, KDF salt and IV can't be swapped without the tag check failing. Callers can bind extra context (`--aad user-7`), so a valid ciphertext can't be lifted from one record into another.

## Key management — the part worth reviewing

There is no key in the source, and the program never invents one silently at encryption time (that turns a misconfigured path into unrecoverable data). `KeyProvider` has three implementations, selected with `--provider`:

- **`keystore`** (default) — AES-256 key in a PKCS#12 file, unlocked by `SDC_KEYSTORE_PASSWORD`. Recommended for a service.
- **`env`** — base64 key from `SDC_KEY`, for secret-manager injection in containers.
- **`passphrase`** — PBKDF2-HMAC-SHA256, 600k iterations, fresh 16-byte salt per message stored in the envelope alongside the iteration count.

Supporting decisions: secrets come from the environment or an interactive prompt, never from argv (visible in `ps` and shell history); `genkey` creates the keystore `rw-------` before writing bytes, and decryption *refuses* a group/world-readable keystore rather than warning; `genkey` won't overwrite an existing alias, so rotation is "add `--alias app-data-2026q3` and re-encrypt" with old ciphertext still readable; key buffers are wiped and derived keys destroyed after each operation; errors print a message, never a stack trace.

## Verification

`Main selftest` covers 13 properties — round-trip, 1 MiB and empty inputs, distinct ciphertexts for identical plaintext, and rejection of modified tag / body / IV, wrong AAD, missing AAD, wrong key, truncation, garbage. All pass. I also ran the CLI end-to-end for all three providers, confirming wrong password, wrong AAD, wrong passphrase, a 16-byte key, a `chmod 644` keystore and a duplicate alias each fail with a clear message and exit 1.

Three limits are documented in `README.md` rather than fixed, since they're design tradeoffs rather than defects: PBKDF2 resists only CPU-bound guessing (Argon2id/scrypt is better if a dependency is acceptable); `env` keys are readable via `/proc/<pid>/environ` by root or the same user; and the program buffers whole plaintexts in memory, so very large files would need a chunked, per-segment-authenticated format. A KMS or PKCS#11 backend would be a new `KeyProvider` with nothing else changing.
