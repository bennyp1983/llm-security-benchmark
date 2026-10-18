# Symmetric data encryption example

This standalone Java program uses AES-256-GCM. GCM encrypts the data and also
authenticates it, so decryption fails if either the ciphertext or its associated
metadata has been modified.

Compile it with a modern JDK:

```sh
javac SensitiveDataEncryption.java
```

Run an interactive encryption/decryption demonstration:

```sh
java SensitiveDataEncryption
```

Or use the individual operations:

```sh
KEY=$(java SensitiveDataEncryption generate-key)
CIPHERTEXT=$(java SensitiveDataEncryption encrypt "$KEY" "sensitive value")
java SensitiveDataEncryption decrypt "$KEY" "$CIPHERTEXT"
```

The encrypted value contains a format version, a fresh random 96-bit IV, and the
ciphertext with its 128-bit authentication tag. The IV is not secret. A new IV is
generated for every encryption operation.

For a real application, store the key in a secret manager or keystore, restrict
access to it, and plan key rotation. Do not hard-code it or store it beside the
ciphertext. Command-line arguments may be visible to other local processes, so
integrate the `encrypt` and `decrypt` methods directly into applications that
handle genuinely sensitive values.
