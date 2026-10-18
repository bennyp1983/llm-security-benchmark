# AES-256-GCM symmetric encryption for application secrets

A complete, dependency-free Java 17 program that encrypts and decrypts sensitive application data
using the standard `javax.crypto` APIs. It is shipped as a library (`SymmetricCrypto`), a command
line tool (`App`), a narrated walk-through (`Demo`), and an executable check suite (`SelfTest`).

## Quick start

```bash
./verify.sh                      # compile + self test + demo + CLI round trips

java -cp out com.example.crypto.App keygen --out app.key      # 0600 key file
export APP_KEY="$(cat app.key)"

java -cp out com.example.crypto.App encrypt --key-env APP_KEY \
    --aad billing.db-url --text 'postgres://app:s3cr3t@db:5432/billing'
# QUVTRwEA... (base64 envelope)

java -cp out com.example.crypto.App decrypt --key-env APP_KEY \
    --aad billing.db-url --text 'QUVTRwEA...'
# postgres://app:s3cr3t@db:5432/billing
```

Or as a library:

```java
SymmetricCrypto crypto = new SymmetricCrypto();
SymmetricCrypto.KeySource key = SymmetricCrypto.KeySource.of(SymmetricCrypto.newKey());

String token = crypto.encryptToBase64(key, secret, "billing.db-url");
String back  = crypto.decryptBase64(key, token, "billing.db-url");
```

## How it works

AES-256 in **GCM** mode — an AEAD, so the ciphertext is both encrypted *and* authenticated. Each
call writes a self-describing envelope:

```
"AESG" | version(1) | keySource(1) | [salt(16) | iterations(4)] | iv(12) | ciphertext + tag(16)
```

The header is fed to GCM as additional authenticated data, so rewriting the IV, the salt, or the
iteration count breaks the tag exactly like rewriting the ciphertext would. Overhead is 34 bytes.

Design decisions worth knowing about:

- **Fresh 12-byte IV per call, from `SecureRandom`.** GCM's security proof collapses if a key ever
  encrypts two messages under the same IV, so the class draws one internally and never accepts a
  caller-supplied IV — reuse is impossible by construction. The cost is a 34-byte envelope, not a
  deterministic (searchable) one.
- **Two key sources.** A raw 256-bit key (`KeySource.of(SecretKey)`) for machine-held secrets, or a
  passphrase stretched with **PBKDF2-HmacSHA256 at 310,000 iterations** (`KeySource.of(char[])`, the
  OWASP 2023+ figure). The salt and work factor travel inside the envelope, so decryption needs the
  passphrase and nothing else.
- **AAD binds a ciphertext to its purpose.** Seal a value for `billing.db-url` and a token copied to
  a different config key fails the tag check instead of quietly decrypting.
- **`AEADBadTagException` is not distinguished by cause.** Wrong key, wrong AAD, and corruption all
  surface as `CryptoException` with `isAuthenticationFailure() == true`; the caller is not told which.
- **Iteration-count DoS guard.** A stored count outside `[100_000, 10_000_000]` is refused before
  PBKDF2 runs, so a hostile envelope cannot make the decryptor burn arbitrary CPU.
- **Passphrases are `char[]`,** wiped after derivation; `SecretKeySpec` copies are handed to the
  provider and `PBEKeySpec.clearPassword()` is called in a `finally`.

## CLI

```
java com.example.crypto.App keygen   [--out <file>] [--force]
java com.example.crypto.App encrypt  <key option> [--aad <ctx>] (--text <s> | --file <p> | --stdin)
java com.example.crypto.App decrypt  <key option> [--aad <ctx>] (--text <t> | --file <p> | --stdin) [--out <p>]
java com.example.crypto.App demo
java com.example.crypto.App selftest
```

Key options: `--key-env VAR` (preferred), `--key-file <path>`, `--key <b64>`, `--password-env VAR`,
`--password <pw>`, `--iterations <n>`. The argv forms print a warning because they are visible in
`ps`; the env and file forms do not. `keygen --out` writes the file `0600`, and `--key-file` warns if
the file is group- or world-readable.

Input is byte-exact through `--file` and `--stdin`, and `decrypt` writes plaintext to stdout with no
trailing newline (same convention as `openssl enc`), so binary payloads survive redirection.

Exit status: `0` ok, `1` usage, `2` bad input or key, `3` authentication failure, `4` I/O.

## Layout

```
src/com/example/crypto/
  SymmetricCrypto.java   library: envelope format, key sources, AES-GCM, CryptoException
  App.java               CLI: keygen / encrypt / decrypt / demo / selftest
  Demo.java              narrated end-to-end walk-through
  SelfTest.java          36 executable checks, no test framework needed
verify.sh                compile + all checks in one command
```

## Verification

`./verify.sh` compiles under `javac -encoding UTF-8 -Xlint:all -Werror` (clean, no warnings — the
`-encoding` flag is needed because this machine's default charset is US-ASCII) and then runs the
self-test suite, the demo, and CLI round trips. The 36 checks cover:

- text and binary round trips: empty input, 100 000 characters, non-ASCII (`pässwörd-€-日本-😀`),
  CR/LF/TAB, and 70 000 pseudo-random bytes, plus base64 that arrived line-wrapped;
- 500 encryptions of the same plaintext producing 500 distinct IVs *and* 500 distinct envelopes;
- rejection of a wrong key, a wrong passphrase, and a wrong or omitted AAD;
- **an exhaustive single-byte flip of every byte** in both a raw-key envelope (62 bytes) and a
  passphrase envelope (59 bytes) — all rejected, and every flip from the IV onwards specifically
  refused by the AEAD tag (the salt too; the version and source-id bytes are structural checks);
- truncation, a foreign blob, invalid base64, and an absurd stored work factor;
- key validation: short key, non-AES key, empty passphrase, work factor below the floor, and
  key-source mismatch in both directions.

## Notes and limits

- Not a keystore. The key lives wherever you put it (env var, file, secret manager) — this code
  never persists one, and `keygen` only prints or writes one at your explicit request.
- No key rotation or re-wrap support; envelope `version` is 1 and unknown versions are refused, so
  there is a place to grow.
- Java's `SecretKey` cannot be zeroed, so key material outlives the object's use within the process.
- Requires unlimited-strength crypto for AES-256, which is the default since JDK 8u161. Verified here
  on OpenJDK 17.0.20.1.
