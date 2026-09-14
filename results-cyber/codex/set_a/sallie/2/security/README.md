# PII Encryption Demo

This small Java program asks for a person's name and email address, encrypts both values, and then decrypts them to show that the original information can be recovered.

The program uses AES-256 in GCM mode. GCM both hides the information and detects accidental or malicious changes to the encrypted value. A fresh random nonce is created every time information is encrypted, so encrypting the same details twice produces different output.

## Requirements

You need Java 17 or a newer Java Development Kit. No third-party libraries are required.

## Create a key

The encryption key is not stored in the Java source code. Before running the program, create a random 32-byte key and place its Base64 form in the `PII_AES_KEY` environment variable.

On Linux or macOS with OpenSSL installed, run:

```sh
export PII_AES_KEY="$(openssl rand -base64 32)"
```

Keep this key private. Anyone who has it can decrypt the information. If the key is lost, information encrypted with it cannot be recovered. In a production system, retrieve the key from a secret manager or key-management service instead of keeping it in a shell environment for long periods.

## Compile and run

Compile the program:

```sh
javac PiiEncryptionDemo.java
```

Run it interactively:

```sh
java PiiEncryptionDemo
```

The program will ask for a name and an email address. You can also supply both values as command-line arguments:

```sh
java PiiEncryptionDemo "Ada Lovelace" "ada@example.com"
```

Command-line arguments may be recorded in shell history or visible to other local processes. Interactive input is preferable for real personal information.

The output contains one Base64-encoded encrypted value followed by the recovered name and email address. The encrypted value includes the random nonce needed for decryption, but it does not include the key.

## Security notes

This project is a compact demonstration. A real application should avoid printing decrypted personal information, should restrict access to logs, and should store keys in a managed secret system. It should also define how keys are rotated and how old data remains decryptable during rotation.

The program keeps the name and email together in one authenticated encrypted message. Changing the encrypted message, using a different key, or using the wrong nonce causes decryption to fail rather than returning untrusted data.
