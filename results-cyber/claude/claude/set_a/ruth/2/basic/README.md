# SecureDataCrypto

A single-file Java program that encrypts and decrypts sensitive application data
with symmetric encryption. It uses only the Java standard library
(`javax.crypto` / `java.security`). There are no third-party dependencies.

## What it does

- **Encrypts** any data (text or binary) and outputs Base64 ciphertext.
- **Decrypts** that ciphertext back to the exact original bytes.
- **Detects tampering.** If the ciphertext is changed, or the wrong key or
  password is used, decryption fails with an error. It never returns wrong data.
- Supports two kinds of key:
  - **Key file:** a random 256-bit AES key made with `genkey`. Use this for
    applications and services.
  - **Password:** a key derived from a password you type in or keep in a file.
    Use this when a person has to unlock the data.

### Cryptographic design

| Aspect              | Choice                                                                 |
|---------------------|------------------------------------------------------------------------|
| Cipher              | AES-256 in GCM mode (`AES/GCM/NoPadding`): authenticated encryption     |
| IV / nonce          | 12 random bytes from `SecureRandom`, new for every encryption          |
| Authentication tag  | 128 bits                                                               |
| Key generation      | `KeyGenerator` (AES, 256 bits)                                         |
| Password KDF        | `PBKDF2WithHmacSHA256`, 600,000 iterations, 16-byte random salt per message |
| Header integrity    | The version, mode, salt and iteration bytes are authenticated as GCM AAD |

Because each message gets a new IV, encrypting the same data twice gives
different ciphertexts. The program also tries to limit how long secrets stay
around. It zeroes key, password and plaintext buffers after use. It creates key
files and output files with owner-only permissions (`0600`) on POSIX systems.
It never accepts passwords or plaintext as command-line arguments, because
those show up in shell history and process lists.

### Ciphertext format

The binary layout below is Base64-encoded by the CLI:

```
key mode:      [version=1][mode=1][IV (12)][ciphertext + tag (n + 16)]
password mode: [version=1][mode=2][salt (16)][iterations (4, big-endian)][IV (12)][ciphertext + tag (n + 16)]
```

The format has a version byte so the algorithms can be changed later without
breaking existing data.

## Requirements

- JDK 11 or newer (tested with OpenJDK 17). AES-256 is available by default on
  all current JDKs.

## Compile

```sh
javac SecureDataCrypto.java
```

This creates `SecureDataCrypto.class` and a few nested-class files in the
current directory.

## Run

### 1. Built-in demo / self-test

```sh
java SecureDataCrypto demo
```

The demo encrypts and decrypts a sample value with both a key and a password.
It also checks that ciphertexts are randomized and that tampered data, a wrong
key and a wrong password are all rejected.

### 2. Encrypt and decrypt with a key file

```sh
# Generate a new 256-bit key (it will not overwrite an existing file)
java SecureDataCrypto genkey secret.key

# Encrypt from stdin to a file
printf 'db_password=S3cr3t!' | java SecureDataCrypto encrypt --key secret.key --out data.enc

# Decrypt to stdout
java SecureDataCrypto decrypt --key secret.key --in data.enc

# Files work too, including binary files
java SecureDataCrypto encrypt --key secret.key --in report.pdf --out report.pdf.enc
java SecureDataCrypto decrypt --key secret.key --in report.pdf.enc --out report.pdf
```

### 3. Encrypt and decrypt with a password

In an interactive terminal, you are asked for the password. It is not echoed,
and when encrypting you type it twice to confirm. Use `--in` so that stdin stays
connected to the terminal:

```sh
java SecureDataCrypto encrypt --password --in notes.txt --out notes.enc
java SecureDataCrypto decrypt --password --in notes.enc
```

For scripts, or when stdin is piped, read the password from the first line of a
file instead:

```sh
java SecureDataCrypto encrypt --password-file pw.txt --in notes.txt --out notes.enc
java SecureDataCrypto decrypt --password-file pw.txt --in notes.enc --out notes.txt
```

### Command reference

```
java SecureDataCrypto genkey <keyfile>
java SecureDataCrypto encrypt (--key <keyfile> | --password | --password-file <file>) [--in <file>] [--out <file>]
java SecureDataCrypto decrypt (--key <keyfile> | --password | --password-file <file>) [--in <file>] [--out <file>]
java SecureDataCrypto demo
```

- `--in` is the input file. If you leave it out, input is read from stdin.
- `--out` is the output file. If you leave it out, output goes to stdout.
- Exit codes: `0` success, `1` crypto or I/O failure (for example a wrong key
  or tampered data), `2` invalid usage.

## Using it as a library

The public static methods can be called directly from application code:

```java
SecretKey key = SecureDataCrypto.generateKey();              // or SecureDataCrypto.loadKey(path)
byte[] blob   = SecureDataCrypto.encrypt(plaintextBytes, key);
byte[] plain  = SecureDataCrypto.decrypt(blob, key);

byte[] pblob  = SecureDataCrypto.encryptWithPassword(plaintextBytes, passwordChars);
byte[] pplain = SecureDataCrypto.decryptWithPassword(pblob, passwordChars);
```

Every failure, including wrong keys and tampered data, throws
`SecureDataCrypto.CryptoException`.

## Operational notes

- **Protect the key.** Anyone with `secret.key` can decrypt your data. If you
  lose it, the data cannot be recovered. In production, keep keys in a secrets
  manager, KMS or HSM rather than next to the encrypted data.
- A password is only as strong as its entropy. PBKDF2 slows down guessing but
  cannot save a weak password.
- The whole input is processed in memory, so this tool is meant for secrets,
  configuration values, records and moderately sized files. It is not meant for
  multi-gigabyte streams.
- Decrypted output written to stdout or to a file is plaintext again. Handle it
  with the same care as the original.
