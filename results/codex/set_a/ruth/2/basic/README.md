# Sensitive Data Crypto

`SensitiveDataCrypto.java` is a complete command-line Java program for encrypting
and decrypting UTF-8 application data with a symmetric key. It uses only Java's
standard cryptography APIs.

The program uses AES-256 in Galois/Counter Mode (`AES/GCM/NoPadding`). AES-GCM
provides both confidentiality and authentication: a changed ciphertext or an
incorrect key causes decryption to fail. Every encryption generates a fresh
cryptographically random 96-bit IV. Output is a URL-safe Base64 token containing
a format/version marker, the IV, and the encrypted data plus its authentication
tag. The IV is not secret and the format marker is authenticated.

## Requirements

- JDK 11 or newer

## Compile

From this directory, run:

```sh
javac SensitiveDataCrypto.java
```

## Run

First generate a random AES-256 key. The program will not overwrite an existing
key file. On POSIX systems it creates the file with owner-only permissions
(`0600`).

```sh
java SensitiveDataCrypto generate-key application.key
```

Encrypt text and capture the resulting Base64 ciphertext:

```sh
ciphertext=$(java SensitiveDataCrypto encrypt application.key "Sensitive value")
printf '%s\n' "$ciphertext"
```

Decrypt it:

```sh
java SensitiveDataCrypto decrypt application.key "$ciphertext"
printf '\n'
```

For secrets, standard input is preferable because command-line arguments can be
visible in shell history and process listings:

```sh
printf '%s' 'Sensitive value' | java SensitiveDataCrypto encrypt application.key > ciphertext.txt
java SensitiveDataCrypto decrypt application.key < ciphertext.txt
printf '\n'
```

The decrypted bytes are written exactly as stored, without an added newline.

## Commands

```text
java SensitiveDataCrypto generate-key <key-file>
java SensitiveDataCrypto encrypt <key-file> [plaintext]
java SensitiveDataCrypto decrypt <key-file> [ciphertext]
```

When `plaintext` or `ciphertext` is omitted, it is read from standard input.

## Key and operational security

- Keep the key file separate from ciphertext, backups, logs, and source control.
- Restrict key-file access. On non-POSIX systems, configure equivalent file ACLs.
- Do not reuse or copy the generated key across unrelated applications.
- Rotate keys according to your application's policy. Old keys are required to
  decrypt old data unless that data is re-encrypted.
- This example stores a raw key in a local file for portability. Production
  systems should generally load keys from a managed KMS, HSM, or secret manager.
- Losing the key makes the ciphertext unrecoverable.

The public `encrypt` and `decrypt` methods can also be called directly from other
Java code with a `javax.crypto.SecretKey`.
