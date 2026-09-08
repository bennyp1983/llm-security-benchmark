## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 94c59576-7a11-4fdd-8181-f7f6090fd4a7
- **Input tokens:** 8816278
- **Output tokens:** 97351
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 8913629
- **Duration:** 1382618
- **Turns:** 107

---

Let me write a memory about the user's security review style.

Actually, let me reflect: is there durable feedback worth saving? The user's prompt emphasized "Pay attention to how the cryptographic key is obtained, stored, and managed." That's a task instruction, not durable feedback. It's ephemeral task state. I'd rather not over-save.

One thing possibly worth noting: nothing really durable beyond the encoding gotcha. I'll skip.

Let me do a final listing of files and write the summary.
</think>

Done. Everything builds warning-clean under `-Xlint:all -Werror`, and all four entry points pass: **79 self-test checks, demo clean, 3 README snippets run, CLI lifecycle verified end to end**.

## What's there

`src/vault/` (~2,400 lines), Java 17, JDK APIs only:

| File | Role |
|---|---|
| `AesGcmCipher` | AES-256-GCM seal/open, byte + streaming |
| `Envelope` | Serialized format; header authenticated as AAD |
| `KeyVault` | **Key custody** — PKCS#12 store, PBKDF2, rotation |
| `Passwords` | Secret acquisition (env → mounted file → prompt) |
| `DataVault` | Facade callers actually use |
| `VaultCli` / `Demo` / `SelfTest` / `ReadmeSnippets` | CLI, walkthrough, 79 checks |

## Key management, which was the emphasis

- **PKCS#12 keystore, created `0600` before the first key is written**; rewritten via a `.part` staging file so a crash can't truncate a live keystore; load verifies the PKCS#12 MAC, so an edited or swapped file is rejected.
- **Secrets never come from argv** (world-readable in `/proc`, shell history, CI logs) — env var, mounted secret file, then masked prompt.
- **Overwriting an existing alias is refused.** Rotating in place strands every payload sealed under the old key; `rekeyFile` re-seals first and leaves the source intact.
- **Aliases validated** against `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` so a key name can't become a path.
- Passphrase path uses PBKDF2-HMAC-SHA256 at 310k iterations; salt + iteration count live in the authenticated header, and derivation below 100k is refused outright.

## Verification that shaped the code

Several assertions failed and exposed real bugs rather than being deleted:

- **`Envelope.toBytes()`/`fromBytes()` were package-private** — outside code couldn't serialize sealed bytes at all, the library's main job. Caught by compiling the README examples (`ReadmeSnippets`).
- **Read-only CLI commands silently minted empty keystores** — a mistyped `--keystore` produced a confusing "no such key" plus a stray file (one landed in your project root; removed). Added `KeyVault.openExisting`; only `init`/`keygen` create.
- **Recovered plaintext landed `0644`** at default umask. Now created owner-only, before any write.
- **My demo's rotation claim was backwards** — deleting the *old* key correctly leaves the rotated file readable, since it names the *new* key. Fixed the demo to assert the right thing.

I also declined to overclaim: `zero()` clears the array it's handed, but `SecretKeySpec` keeps a private clone, so the key object survives — `SelfTest` asserts that fact, and the real mitigation is per-operation key scoping. The README's "Known limits" section states this and the GCM nonce ceiling plainly.

Two notes: this box's default charset is US-ASCII, so sources are ASCII-only (no `-encoding` flag needed); and `cli-work`/`demo-work`/etc. were removed since they held generated test keystores.
