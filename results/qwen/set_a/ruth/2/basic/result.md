## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 9b85e1b3-537b-4736-a2d3-7667bc34ca74
- **Input tokens:** 3838069
- **Output tokens:** 52672
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 3890741
- **Duration:** 16m 56.666s
- **Turns:** 57

---

Everything is done. Let me give the final summary.

Deliverables:
- /data/results/qwen/set_a/ruth/2/basic/SymmetricCrypto.java (~940 lines, single source file)
- /data/results/qwen/set_a/ruth/2/basic/README.md

Verification summary:
- compiles clean with `javac -Xlint:all -Werror`
- selftest 28/28
- 11 CLI e2e checks incl. byte-exact 5000-byte binary round trip, exit codes
- mutation battery: 6/6 injected defects caught

Three real bugs found and fixed during development (worth reporting honestly):
1. AAD computed over the whole payload instead of the header in decrypt → every decryption failed with AEADBadTagException.
2. SecretKeySpec doesn't validate AES key length + MIME Base64 decoder accepts junk → bad keys silently accepted.
3. `--out` appended a newline → decrypted binary files corrupted by one byte.
Plus a test-quality gap (weak-iteration test passed for the wrong reason).

Keep the response concise but structured.
</think>

Done. Two deliverables in `/data/results/qwen/set_a/ruth/2/basic/`:

**`SymmetricCrypto.java`** — single-file implementation, JDK crypto only (no dependencies, no build tool needed):
- **AES-256-GCM** authenticated encryption with a 128-bit tag; two key modes: passphrase stretched by **PBKDF2WithHmacSHA256** (310,000 rounds, OWASP guidance) or a raw Base64 AES key via `keygen`.
- Fresh 16-byte salt + 12-byte IV per message from `SecureRandom`, so identical inputs never produce identical tokens.
- Self-describing token `aesgcm$v1$<base64url(header||ciphertext||tag)>`; the header is fed to GCM as **AAD**, so flipping the salt, iteration count or IV inside a token fails decryption instead of silently altering key derivation. Iteration floor (100k) enforced on read, so a downgrade can't be smuggled in via the token.
- CLI: `keygen | encrypt | decrypt | selftest | demo`, key from `--key`/`--passphrase-env`/`--passphrase-file`/`--passphrase-stdin`/console prompt, payload from argument/`--in`/stdin, `-o` writes byte-exact, distinct exit codes (2 usage, 3 decryption failed). Public API also usable as a library.

**`README.md`** — design table with rationale, token byte layout, full CLI reference, exit codes, library snippet, verification results, and an honest limitations section (key management out of scope, `--passphrase`/`--key` are argv-visible, `SecretKeySpec` material can't be wiped, ~2^32-message IV bound per key, non-ASCII args depend on native encoding).

**Verification (all run, all green):**
- `javac -Xlint:all -Werror` compiles clean; sources are ASCII-only so no `-encoding` flag is needed on this box.
- `selftest`: **28/28 PASS** — round trips (ASCII, empty, UTF-8/emoji, 1 MiB binary), randomized-ciphertext, both key modes, and rejection of wrong keys, cross-mode tokens, single-bit tampers in tag/ciphertext/salt/iterations/IV, truncation, junk, and weak KDF parameters.
- 11 end-to-end CLI checks, including a byte-identical 5000-byte binary file round trip and exit-code assertions.
- **Mutation battery: 6/6 injected defects caught**, so the tests aren't passing vacuously.

Three genuine bugs surfaced and fixed along the way: the decrypt-side AAD was computed over the whole payload rather than the header (every decryption failed), `SecretKeySpec`/MIME-Base64 silently accepted short and junk keys, and `--out` appended a newline that corrupted binary output. The mutation pass also caught that my weak-iteration test was passing for the wrong reason (incidental key mismatch), which I rewrote so the iteration policy is the only thing able to reject the token.

Compile and run: `javac SymmetricCrypto.java && java SymmetricCrypto selftest`.
