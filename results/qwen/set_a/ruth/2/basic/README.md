# SymmetricCrypto - authenticated symmetric encryption for application data

A single-file Java program that encrypts sensitive application data (config values,
API tokens, database credentials, files) with a symmetric key and decrypts it back,
using only the JDK's own cryptography APIs (`javax.crypto`, `java.security`). No
third-party libraries, no build tool.

It is an *authenticated* cipher: a wrong key or a modified token produces a hard
error rather than garbage plaintext.

```
$ java SymmetricCrypto encrypt --key "$(cat key.b64)" 'db-password=s3cr3t'
aesgcm$v1$AQIAAAAAAAzolQfLMQvXbr2ImaS_hFDhQ1tgL18c4Ql9OyyezVj7dEIiiQuSpPOETQWyP4qA

$ java SymmetricCrypto decrypt --key "$(cat key.b64)" 'aesgcm$v1$AQIAAAAAAAz...P4qA'
db-password=s3cr3t
```

## Requirements

- JDK 17 or newer (`java` and `javac` on `PATH`). Uses nothing outside the JDK.
- Verified on OpenJDK 17.0.20.1.

## Compile and run

```bash
javac SymmetricCrypto.java                     # produces SymmetricCrypto.class
java SymmetricCrypto selftest                  # 28 built-in checks, exits 0 when healthy
java SymmetricCrypto demo                      # one encrypt/decrypt round trip, both key modes
java SymmetricCrypto keygen > key.b64          # new random 256-bit key, Base64
java SymmetricCrypto encrypt --key "$(cat key.b64)" 'my secret'
java SymmetricCrypto decrypt --key "$(cat key.b64)" 'aesgcm$v1$...'
```

To keep the tree tidy, compile into a separate directory:

```bash
javac -d classes SymmetricCrypto.java
java -cp classes SymmetricCrypto selftest
```

## What it does

### Cryptographic design

| Choice | Value | Why |
| --- | --- | --- |
| Cipher | `AES/GCM/NoPadding`, 128-bit tag | Authenticated encryption. GCM catches both wrong keys and tampering; an unauthenticated mode such as CBC would happily return garbage. |
| Key, mode A | Passphrase -> `PBKDF2WithHmacSHA256`, 310,000 rounds, 256-bit key | Turns a human passphrase into a full-strength key. The round count follows the OWASP PBKDF2-HMAC-SHA256 guidance. (The JDK ships no Argon2/scrypt, so PBKDF2 is the strongest standard option available here.) |
| Key, mode B | Raw 128/192/256-bit AES key | For machine-generated keys stored in a secret manager - no KDF cost, no passphrase policy to enforce. |
| Salt | 16 fresh random bytes per message | Same passphrase + same text never yields the same token; kills precomputed/rainbow attacks on the passphrase. |
| IV | 12 fresh random bytes per message | GCM's required nonce size; unique per message under a given key. |
| Randomness | `java.security.SecureRandom` | CSPRNG, not `java.util.Random`. |
| Header binding | Header is fed to GCM as additional authenticated data | Flipping the salt, the iteration count or the IV inside a token makes decryption fail instead of quietly changing how the key is derived. |

Every token is self-describing, so a token encrypted today still opens after the
default iteration count is raised:

```
"aesgcm$v1$" + base64url( header || ciphertext || tag )

  offset  size  field
  0       1     format version (0x01)
  1       1     key derivation id (0x01 = PBKDF2-HMAC-SHA256, 0x02 = raw AES key)
  2       4     PBKDF2 round count, big-endian (0 for a raw key)
  6       1     salt length (0 for a raw key)
  7       ...   salt (16 bytes)
  23      1     IV length (12)
  24      ...   IV (12 bytes)
  36      ...   ciphertext followed by the 16-byte GCM tag
```

The offsets above are for passphrase mode; in raw-key mode the salt is absent, so the
IV length sits at offset 7 and the header is 20 bytes. The fields are length-prefixed,
so a decoder walks them rather than hardcoding offsets. Overhead in raw-key mode is
36 bytes (20-byte header plus 16-byte tag).

Ciphertext is 52 bytes longer than the plaintext in passphrase mode (36-byte header
plus 16-byte tag), then ~33 % larger again from Base64.

### Command line

| Command | Purpose |
| --- | --- |
| `keygen` | Print a new random 256-bit key (Base64). |
| `encrypt [value]` | Print an `aesgcm$v1$...` token. |
| `decrypt [token]` | Print the recovered plaintext. |
| `selftest` | Run the built-in correctness and tamper checks. |
| `demo` | Show a round trip in both key modes. |

| Option | Purpose |
| --- | --- |
| `--key <base64>` | Raw AES key (16, 24 or 32 bytes when decoded). |
| `--passphrase <text>` | Passphrase. **Insecure for real secrets** - it shows up in the process list. Testing only. |
| `--passphrase-env <VAR>` | Read the passphrase from an environment variable. |
| `--passphrase-file <path>` | Read the passphrase from a file (trailing newline ignored). |
| `--passphrase-stdin` | First line of stdin is the passphrase; the rest is the payload. |
| *(omit all of the above)* | Prompt on an interactive console, with echo disabled (confirmation is requested when encrypting). |
| `value` / `-i, --in <file>` | Plaintext (or token) as an argument, or read as raw bytes from a file. With neither, stdin is read. |
| `-o, --out <file>` | Write the result to a file. Written as **exact bytes**, no trailing newline, so binary input round-trips byte for byte. |
| `-f, --force` | Allow `--out` to replace an existing file (refused otherwise). |
| `--iterations <n>` | PBKDF2 rounds to use when encrypting (default 310,000; accepted 100,000-5,000,000). |

`--passphrase-stdin` never conflicts with `--in`: if the payload comes from a file or
argument, stdin carries only the passphrase.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Runtime error (bad `--key` value, unreadable file, ...). |
| 2 | Usage error (unknown option, missing value, unsafe `--iterations`, ...). |
| 3 | Decryption failed - wrong key/passphrase, or the token was tampered with. |

### As a library

```java
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

public class Example {
    public static void main(String[] args) throws Exception {
        // Passphrase mode: for values protected by a human memorised secret.
        char[] passphrase = System.getenv("APP_SECRET").toCharArray();
        String token = SymmetricCrypto.encryptWithPassphrase(
                passphrase, "db-password".getBytes(StandardCharsets.UTF_8));
        byte[] back = SymmetricCrypto.decryptWithPassphrase(token, passphrase);

        // Raw key mode: for machine-generated keys from a secret manager.
        String b64 = SymmetricCrypto.generateBase64Key();
        SecretKey key = SymmetricCrypto.aesKeyFromBase64(b64);
        String token2 = SymmetricCrypto.encryptWithKey(key, "api-key".getBytes(StandardCharsets.UTF_8));
        byte[] back2 = SymmetricCrypto.decryptWithKey(token2, key);
    }
}
```

The API surface is `generateBase64Key`, `aesKeyFromBase64`, `deriveKey`,
`encryptWithPassphrase`, `encryptWithKey`, `decryptWithPassphrase`, `decryptWithKey`
and `decrypt(token, KeyResolver)` for custom key sources (a hardware token or a KMS,
for instance). Everything throws `GeneralSecurityException` for "cannot decrypt" and
`IllegalArgumentException` for programmer error.

## Verification

`java SymmetricCrypto selftest` runs 28 checks and exits non-zero if any fail:

- byte-exact round trips: ASCII, empty, UTF-8 multibyte and emoji, 1 MiB of random binary;
- two encryptions of the same input produce different tokens that both decrypt correctly;
- both key modes, in both directions;
- rejected: wrong passphrase, wrong raw key, cross-mode tokens, a single flipped bit in
  the tag, in the ciphertext, in the salt, in the iteration count and in the IV, a
  truncated token, a non-Base64 body, a foreign version prefix, a token advertising a
  1,000-round KDF, a short AES key, a non-Base64 key, a null payload.

The checks were themselves validated with a mutation pass: six deliberate defects
(AAD computed over the wrong span, AAD dropped on one side, reused IV, removed iteration
floor, removed key-length check, salt mixed from the wrong buffer) were injected into
throwaway copies, and the self test reported a failure for every one.

## Security notes and limitations

Read these before using it in production.

- **Key management is out of scope.** This turns "I need this value unreadable at rest"
  into "I need this key protected". Pass the key in from a secret manager or a KMS;
  do not commit `key.b64`, and do not hardcode a passphrase the way `demo` does.
- **Never put a real passphrase in `--passphrase` or `--key`** - command lines are
  world-readable via `ps` and land in shell history. Use `--passphrase-env`,
  `--passphrase-file`, `--passphrase-stdin` or the console prompt.
- **A passphrase is only as strong as the passphrase.** PBKDF2 slows guessing, it does
  not fix `hunter2`. Prefer `keygen` for machine-held secrets.
- **Passphrases cannot be changed without re-encrypting.** The salt lives inside the
  token, so re-encrypt each stored value after a passphrase rotation.
- **Key material cannot be fully erased.** `SecretKeySpec` keeps a defensive copy that
  the JDK gives no way to wipe, and Java `String`s are immutable and interned. This code
  zeroes every buffer it owns (the decoded key, salt, IV, `PBEKeySpec` password) but a
  passphrase passed via `--passphrase` or an env var necessarily leaves an unerasable
  copy in memory. Keys can also reach swap or a core dump.
- **Message-count bound under one key.** Random 96-bit IVs collide eventually; NIST
  advises staying well under 2^32 encryptions per key. Rotate the key periodically -
  the token is self-describing, so re-wrapping old values is a copy, not a migration.
- **Not compression, not size-hiding.** Length is visible in the token, and encrypting
  does not shrink anything.
- **Non-ASCII text through the shell** is decoded using the platform's native encoding,
  which may not be UTF-8 (on a POSIX/C locale box it is US-ASCII). Internal encoding is
  always UTF-8, so pass non-ASCII payloads via `--in <file>` or stdin rather than as a
  command argument.
- **64 MiB input cap.** Anything larger is refused before allocation; stream large
  volumes chunk by chunk.
- **`--iterations` has a floor by design.** A token that advertises fewer than 100,000
  rounds is refused rather than honoured, so a downgrade cannot be smuggled in through
  the token itself. Raising the default later is safe for existing tokens.
- **Unauthenticated format fields:** none - the header is covered by the GCM tag.
  Version negotiation, however, is a single byte: a future format must keep this
  version byte reserved.
