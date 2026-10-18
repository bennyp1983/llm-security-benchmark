# SecureDataCrypto

A self-contained Java program that encrypts and decrypts sensitive application
data (credentials, tokens, personal data, config secrets, files) using
**AES-256-GCM**. It uses only the Java standard library (JCA/JCE) and pays
particular attention to how the encryption key is **generated, stored,
unlocked, rotated, and retired**.

Everything is in one source file: `SecureDataCrypto.java`.

## What it does

| Command | Purpose |
|---|---|
| `generate-key [--alias NAME]` | Generates a random AES-256 key and stores it in a password-protected PKCS#12 keystore, creating the keystore if needed. The newest key becomes the **active** key. |
| `list-keys` | Lists keys (oldest first) with creation time; `*` marks the active key. |
| `encrypt [--alias NAME] [--in FILE] [--out FILE]` | Encrypts bytes from stdin or a file and writes Base64 ciphertext. |
| `decrypt [--in FILE] [--out FILE]` | Decrypts Base64 ciphertext and writes the original bytes. |
| `delete-key --alias NAME --yes` | Permanently removes a key (crypto-shredding: data encrypted with it can never be recovered). |
| `self-test` | Runs built-in checks: round trips, IV randomness, detection of tampered and truncated data, wrong key, keystore rotation and reload, wrong password. |

Common options: `--keystore FILE` and `--password-file FILE`.

Exit codes: `0` ok, `1` usage error, `2` crypto/integrity failure, `3` key or
keystore error, `4` I/O error.

## Requirements

- JDK 17 or newer (`javac` and `java` on `PATH`). No third-party libraries.
- Tested with OpenJDK 17.0.20 on Linux.

## Compile and run

```bash
# Compile
javac -d out SecureDataCrypto.java

# Check that everything works (uses a throwaway in-memory key and temp keystore)
java -cp out SecureDataCrypto self-test
```

You can also skip compiling and use the single-file launcher:
`java SecureDataCrypto.java self-test`.

### End-to-end example

```bash
# 1. Create a strong keystore password and store it in an owner-only file
umask 077
openssl rand -base64 32 > keystore.pass
export APP_CRYPTO_KEYSTORE_PASSWORD_FILE="$PWD/keystore.pass"

# 2. Create the keystore and the first key (data-key-1)
java -cp out SecureDataCrypto generate-key

# 3. Encrypt. Plaintext goes in on stdin or --in, never as an argument.
printf 'db_password=hunter2' | java -cp out SecureDataCrypto encrypt > secret.enc
cat secret.enc          # e.g. AQpkYXRhLWtleS0x...  (safe to store in a DB or config)

# 4. Decrypt
java -cp out SecureDataCrypto decrypt < secret.enc

# Files work too. Output files are created with mode 600.
java -cp out SecureDataCrypto encrypt --in customers.csv --out customers.csv.enc
java -cp out SecureDataCrypto decrypt --in customers.csv.enc --out customers.csv
```

### Key rotation

```bash
java -cp out SecureDataCrypto generate-key          # adds data-key-2, now the active key
java -cp out SecureDataCrypto list-keys
#    data-key-1   created 2026-09-11T07:36:43Z
# *  data-key-2   created 2026-09-11T08:02:10Z

# New encryptions use data-key-2. Old ciphertexts still decrypt, because
# each one records which key it was made with.
java -cp out SecureDataCrypto decrypt < secret.enc

# To retire data-key-1: decrypt and re-encrypt its data under the new key,
# then delete the old key (irreversible):
java -cp out SecureDataCrypto delete-key --alias data-key-1 --yes
```

## Key management design

### How the key is created
- `KeyGenerator.getInstance("AES")` with a 256-bit key size, seeded by
  `SecureRandom` (the OS CSPRNG).
- Keys are never derived from a human-chosen password and never hardcoded.
- Existing aliases are never overwritten, so a key can't be replaced by
  accident while data still depends on it.

### How the key is stored
- Keys live in a **PKCS#12 keystore** (`./app-keys.p12` by default; override
  with `--keystore` or `APP_CRYPTO_KEYSTORE`).
- On JDK 17, each secret-key entry is encrypted with
  `PBEWithHmacSHA256AndAES_256` and the whole file is integrity-protected
  with an HMAC-SHA256 MAC. A wrong password or a modified keystore is
  rejected when the file loads.
- The keystore is written to a temp file with owner-only permissions
  (`rw-------`) and then atomically renamed into place. An interrupted write
  can't leave a half-written keystore that loses keys.
- If the keystore or password file can be read by group or other users, the
  program prints a warning.
- **Store the keystore apart from the encrypted data**, and back it up
  securely. If you lose it, the data is unrecoverable.

### How the key is unlocked
The keystore password is looked up in this order:
1. `--password-file FILE`
2. `APP_CRYPTO_KEYSTORE_PASSWORD_FILE`: path to a file holding the password.
   **Recommended.** This works well with Docker/Kubernetes secrets,
   systemd `LoadCredential`, or Vault Agent templates.
3. `APP_CRYPTO_KEYSTORE_PASSWORD`: the password itself. This is convenient,
   but environment variables can show up in `/proc/<pid>/environ`, crash
   dumps, and CI logs.
4. An interactive prompt (`Console.readPassword`, no echo). This only works
   when both stdin and stdout are terminals.

The password is **never accepted as a command-line argument**, because
arguments are visible in `ps` output and shell history. Passwords are read into
`char[]` and wiped after use. A new keystore needs a password of at least 16
characters. Use a random one (`openssl rand -base64 32`), which also makes the
keystore's PBKDF2 iteration count irrelevant to its security.

### Rotation and retirement
- Each ciphertext header contains the key ID (alias). Decryption picks the
  right key automatically, so rotating keys never breaks existing data.
- The most recently created key is used for new encryptions. `--alias`
  overrides this for a single operation.
- `delete-key` requires `--yes`, because deleting a key destroys all data
  encrypted with it.

## Cryptographic design

- **Algorithm:** `AES/GCM/NoPadding`, a 256-bit key, a 96-bit random IV
  generated fresh for every message, and a 128-bit authentication tag. GCM
  gives confidentiality *and* integrity: any change to the ciphertext, IV, or
  header makes decryption fail instead of returning corrupted plaintext.
- **Ciphertext format** (Base64-encoded on output):

  ```
  [1 byte version=1][1 byte key-ID length N][N bytes key ID][12 bytes IV][ciphertext + 16-byte tag]
  ```

  The version and key ID are passed to GCM as additional authenticated data
  (AAD). An attacker can't swap in a different key ID or format version
  without detection. The version byte leaves room to change algorithms later.
- Decryption errors are deliberately generic, so they don't reveal which part
  of the ciphertext failed.
- Encrypting the same plaintext twice gives different ciphertexts, so
  repeated values can't be spotted.

## Using it from application code

The core classes can be called directly:

```java
try (var keys = SecureDataCrypto.KeyStoreManager.open(Path.of("app-keys.p12"), password)) {
    String keyId = keys.activeAlias();
    byte[] envelope = SecureDataCrypto.DataCipher.encrypt(keys.getKey(keyId), keyId, plaintext);
    byte[] original = SecureDataCrypto.DataCipher.decrypt(keys::getKey, envelope);
}
```

(The nested classes are package-private. Put the calling code in the same
package, or make them `public` when you move them into your codebase.)

## Limitations and production notes

- **Better options in production:** a password-protected file keystore is a
  reasonable choice for self-hosted apps. When you can, keep the root key in a
  **KMS or HSM** (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault Transit,
  or PKCS#11). Use envelope encryption there: the KMS wraps the data keys, so
  the root key never enters application memory. This program's `KeyResolver`
  interface is the place to plug that in.
- Input is processed in memory and limited to 64 MiB per operation. For very
  large files, use a streaming `CipherInputStream`/`CipherOutputStream`
  variant.
- In Java, wiping secrets from memory is best effort. The JVM, the GC, and
  intermediate buffers may keep copies, and `SecretKeySpec` can't be
  destroyed.
- Concurrent `generate-key` or `delete-key` runs against the same keystore
  aren't coordinated. Run key-management operations from one place at a time.
- Keys are 256-bit AES, which is supported by all current JDKs without
  extra policy files.
