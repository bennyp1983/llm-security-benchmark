# Sensitive Data Encryption (Java)

`SensitiveDataCrypto` is a dependency-free Java 17 command-line program and
reusable class for authenticated symmetric encryption. It reads data from
standard input, encrypts it to Base64, and can restore the exact original bytes.

The implementation uses only Java's standard cryptography APIs:

- AES-256 in GCM mode (`AES/GCM/NoPadding`) provides confidentiality and detects
  a changed ciphertext, header, or incorrect password.
- PBKDF2-HMAC-SHA-256 derives the AES key from the supplied password using a
  fresh 16-byte random salt and 600,000 iterations.
- `SecureRandom` generates a new 12-byte GCM IV for every encryption. IV reuse
  with the same key would be unsafe, so callers should use `encrypt` rather than
  constructing payloads themselves.
- A full 128-bit GCM authentication tag is used.

The Base64-decoded payload has a version byte, salt, IV, then the ciphertext and
authentication tag. The salt and IV are intentionally stored with the
ciphertext: neither is secret. The version, salt, and IV are authenticated as
additional data.

## Requirements and compilation

Install JDK 17 or newer, then run from this directory:

```sh
javac SensitiveDataCrypto.java
```

No third-party libraries or unrestricted cryptography policy files are needed
on modern JDK releases.

## Command-line use

The program reads the data from standard input. Keeping data out of command-line
arguments avoids exposing it in process listings and shell history.

In a terminal, encryption prompts twice for a password without echoing it:

```sh
printf '%s' 'sensitive application data' | java SensitiveDataCrypto encrypt > encrypted.txt
```

Decryption prompts once and writes the original bytes to standard output:

```sh
java SensitiveDataCrypto decrypt < encrypted.txt > decrypted.txt
```

To confirm a round trip:

```sh
printf '%s' 'sensitive application data' > original.txt
java SensitiveDataCrypto encrypt < original.txt > encrypted.txt
java SensitiveDataCrypto decrypt < encrypted.txt > decrypted.txt
cmp original.txt decrypted.txt
```

For a non-interactive process, set `DATA_ENCRYPTION_PASSWORD` in the process
environment:

```sh
DATA_ENCRYPTION_PASSWORD='use-a-long-random-secret' \
  java SensitiveDataCrypto encrypt < original.txt > encrypted.txt

DATA_ENCRYPTION_PASSWORD='use-a-long-random-secret' \
  java SensitiveDataCrypto decrypt < encrypted.txt > decrypted.txt
```

An incorrect password or altered ciphertext produces a generic failure and no
plaintext. Encryption output includes a trailing newline because it is Base64
text; decrypted data does not gain a newline.

## Key handling and operational guidance

The password and derived AES key are never written to disk by this program.
The password is normally obtained through `Console.readPassword`, which does not
echo it. Password and key byte arrays are cleared on a best-effort basis as soon
as they are no longer needed. Java and cryptographic providers can retain
internal copies until garbage collection, so this is not a guarantee of memory
erasure.

The environment-variable option is intended for automation, but environment
variables can be exposed by process-inspection tools, diagnostics, or accidental
logging. In production, obtain a high-entropy secret from a dedicated secret
manager at runtime and restrict access to the account running this program. Do
not hard-code the password in source, commit it, store it beside the ciphertext,
or reuse a human password from another system. Back up the secret securely:
there is deliberately no recovery route if it is lost.

PBKDF2 slows password guessing but cannot make a short or predictable password
safe. Prefer a long, randomly generated secret. Changing the password does not
automatically re-encrypt old data; decrypt it with the old password and encrypt
it again with the new one. For a larger application, consider storing a random
AES key in a platform KMS/HSM or protected Java KeyStore instead of using a
password, and include a key identifier in a versioned envelope to support key
rotation.

File permissions and backups are outside the program's control. Restrict access
to plaintext files, shell output, crash dumps, and backups as well as to the key.

The relevant platform and mode references are Oracle's
[Java Cryptography Architecture guide](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
and [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) for GCM.

## Using it as a Java class

The public methods support both text and arbitrary bytes:

```java
char[] password = obtainPasswordSecurely();
try {
    String ciphertext = SensitiveDataCrypto.encrypt("secret", password);
    String plaintext = SensitiveDataCrypto.decrypt(ciphertext, password);
} finally {
    java.util.Arrays.fill(password, '\0');
}
```

There are also `encrypt(byte[], char[])` and `decrypt(byte[], char[])` methods.
The caller owns the password and input/output arrays and should clear sensitive
ones when finished. The `String` convenience methods are easier to use, but Java
strings cannot be erased; use the byte-array methods when memory lifetime is
important.
