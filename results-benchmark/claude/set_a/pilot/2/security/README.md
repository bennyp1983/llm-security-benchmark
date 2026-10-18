# Symmetric encryption of application data (AES-256-GCM)

A complete, dependency-free Java 17 program that encrypts and decrypts sensitive application
data with the JDK's own cryptography APIs (JCA/JCE).

## Build and verify

    javac -d out $(find src -name '*.java')
    java -cp out com.example.crypto.Main selftest

## Use

    export SDC_KEYSTORE_PASSWORD='...'          # from your secret manager, not a shell profile
    java -cp out com.example.crypto.Main genkey --keystore sdc-keystore.p12 --alias app-data

    CT=$(java -cp out com.example.crypto.Main encrypt --text 'ssn=123-45-6789' --aad user-7)
    echo "$CT" | java -cp out com.example.crypto.Main decrypt --aad user-7

`--in FILE` / stdin and stdout work too; ciphertext is base64 so it survives config files, text
columns and pipes. `java -cp out com.example.crypto.Main help` lists everything.

As a library:

    var cipher = new SymmetricCipher(new KeyStoreKeyProvider(Path.of("sdc-keystore.p12"), "app-data"));
    byte[] envelope  = cipher.encrypt(plaintext, "user-7".getBytes(UTF_8));
    byte[] recovered = cipher.decrypt(envelope,  "user-7".getBytes(UTF_8));

## Cryptographic choices

- **AES-256-GCM.** Authenticated encryption: tampered ciphertext fails to decrypt instead of
  producing attacker-influenced plaintext. Unauthenticated modes (`AES/CBC/PKCS5Padding`,
  `AES/ECB`) are not used; ECB in particular leaks plaintext structure.
- **Fresh random 96-bit IV per message**, from `SecureRandom`. IV reuse under one key breaks
  GCM outright, so the IV is never fixed, derived from the data, or taken from mutable state.
- **128-bit tag**, and the whole header (version, key parameters, IV) is passed as additional
  authenticated data, so those fields cannot be swapped without the tag check failing.
- **Optional caller AAD** (`--aad`) binds a ciphertext to its context -- a record id, a tenant --
  so a valid ciphertext cannot be moved from one row to another.
- Envelope: `"SDC1" | version | paramsLen | params | ivLen | iv | ciphertext||tag`. The version
  byte allows the format to change without stranding existing data.

## Key management

The key never appears in source, and the program never invents one silently at encryption time.
`KeyProvider` has three implementations; pick one with `--provider`:

| Provider | Key comes from | Use when |
| --- | --- | --- |
| `keystore` (default) | AES-256 key in a PKCS#12 file, unlocked by `SDC_KEYSTORE_PASSWORD` | a deployed service |
| `env` | base64 key in `SDC_KEY`, injected by a secret manager | containers / Kubernetes secrets |
| `passphrase` | PBKDF2-HMAC-SHA256, 600k iterations, fresh 16-byte salt per message | files a person encrypts by hand |

Supporting decisions:

- Passwords and passphrases are read from the environment or an interactive prompt, **never from
  command-line arguments**, which are visible in `ps` output and shell history.
- `genkey` creates the keystore with `rw-------` before writing any bytes, and decryption
  *refuses* to use a keystore that is group- or world-readable rather than merely warning.
- `genkey` will not overwrite an existing alias: rotation means adding a new alias
  (`--alias app-data-2026q3`) and re-encrypting, so ciphertext under the old key stays readable.
- Key material is wiped from `char[]`/`byte[]` buffers after use and derived keys are destroyed
  after each operation. This shortens exposure in heap dumps; it is not a guarantee, since the
  JVM may have copied values during GC.
- Errors print a message only, never a stack trace that might carry plaintext or key bytes.

## Known limits

- **PBKDF2 resists only CPU-bound guessing.** If a dependency is acceptable, prefer a memory-hard
  KDF (Argon2id, scrypt) for passphrase-derived keys.
- **`env` keys are visible to root and to anyone who can read `/proc/<pid>/environ` as the same
  user**, and tend to leak into crash dumps and child processes. Prefer the keystore where
  practical, or a KMS/HSM where available -- swapping in an AWS KMS or PKCS#11 backend is a new
  `KeyProvider`, and nothing else changes.
- **One key encrypts everything.** GCM's safety margin with random IVs is large but finite
  (stay well under ~2^32 messages per key); rotate by alias on a schedule.
- The program holds plaintext in memory as a whole array, so it is unsuited to files larger than
  the heap; streaming would need chunked, individually authenticated segments.

## Files

    src/com/example/crypto/SymmetricCipher.java        AES-GCM encrypt/decrypt and the envelope format
    src/com/example/crypto/KeyProvider.java            key-source abstraction
    src/com/example/crypto/KeyStoreKeyProvider.java    PKCS#12 keystore, key generation, rotation
    src/com/example/crypto/EnvironmentKeyProvider.java base64 key from the environment
    src/com/example/crypto/PassphraseKeyProvider.java  PBKDF2-HMAC-SHA256 key derivation
    src/com/example/crypto/Secrets.java                secret reading, wiping, file permissions
    src/com/example/crypto/Main.java                   command-line interface
    src/com/example/crypto/SelfTest.java               round-trip and tamper-detection checks
