# Sensitive data encryption example

This is a dependency-free Java CLI that encrypts arbitrary standard-input data
using AES-256-GCM. GCM authenticates the ciphertext as well as encrypting it, so
decryption fails if the data is changed or the wrong key is supplied. Each
encryption generates a fresh 96-bit random nonce and stores it alongside the
ciphertext in a versioned Base64 envelope.

## Requirements and usage

Java 11 or newer is required.

```sh
javac SensitiveDataCrypto.java

# Generate 32 random key bytes. The program refuses to overwrite an existing key.
java SensitiveDataCrypto generate-key application.key

# Encrypt and decrypt. Sensitive plaintext is read from stdin rather than argv.
printf '%s' 'database password' | java SensitiveDataCrypto encrypt application.key > secret.enc
java SensitiveDataCrypto decrypt application.key < secret.enc
```

The key can instead be supplied as Base64 through `APP_ENCRYPTION_KEY`:

```sh
APP_ENCRYPTION_KEY="$(tr -d '\r\n' < application.key)" \
  java SensitiveDataCrypto encrypt < private-data.txt > private-data.enc
```

## Key management

- Keep `application.key` out of source control, application packages, logs, and
  backups that do not have equivalent access controls. The generator requests
  owner-only (`0600`) permissions on POSIX filesystems.
- In production, inject the key at runtime from a secrets manager or KMS-backed
  secret store. An environment variable is supported for container platforms,
  but a mounted secret file is generally less likely to leak through diagnostics.
- Back up the key in a protected location: losing it makes existing ciphertext
  unrecoverable. Rotate keys by retaining the old key for decryption, encrypting
  new records with a new key, and re-encrypting old records. A larger application
  should store a non-secret key identifier with each ciphertext.
- Never reuse this raw key for another purpose. Do not replace the random key with
  a human password; password-based keys require a dedicated KDF and stored salt.
- Avoid converting secrets to Java `String` values in application code. This CLI
  processes plaintext as byte arrays and clears its working arrays where practical,
  though the JVM and operating system can still make transient copies.

The ciphertext format is `SDC` + version byte `01` + 12-byte nonce + GCM output
(ciphertext and 16-byte authentication tag). The four-byte format marker is also
authenticated as additional data.
