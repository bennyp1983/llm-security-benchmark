# Authenticated data protection component

This is a small Java 17 library for encrypting application data. It has no CLI,
UI, administration endpoints, persistence layer, logging framework, or external
dependencies. It uses the JDK's `AES/GCM/NoPadding` implementation with a
256-bit key, a new 96-bit `SecureRandom` nonce for every encryption, and a full
128-bit authentication tag. These choices follow [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
and the [Java Cryptography Architecture guidance](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html).

## Use

Keys must come from a server-side secret manager, KMS export, or equivalent
protected runtime configuration—not source control, command-line arguments, or
client input. The example generates a runtime key only to show the API:

```java
byte[] key = AesGcmDataProtector.generateKey();
byte[] plaintext = loadSensitiveBytes();
byte[] context = "tenant/123/customer/456".getBytes(StandardCharsets.UTF_8);

try (AesGcmDataProtector protector = AesGcmDataProtector.create(
        Map.of("key-2026-10", key),
        "key-2026-10",
        "customer-profile",
        64 * 1024)) {
    Arrays.fill(key, (byte) 0); // the component already holds its private copy
    byte[] envelope = protector.encrypt(plaintext, context);
    Arrays.fill(plaintext, (byte) 0);

    byte[] recovered = protector.decrypt(envelope, context);
    try {
        consume(recovered);
    } finally {
        Arrays.fill(recovered, (byte) 0);
    }
}
```

The non-secret `purpose` is a stable domain separator. `context` should identify
the intended tenant, record, and field so a valid ciphertext cannot be moved to
another location. Exactly the same bytes are required to decrypt. The caller
must authorize access to that tenant/record before invoking this component.

For rotation, configure the old and new keys together and make the new key ID
active. Encryption always uses the server-configured active key. Decryption may
use an authenticated envelope key ID only after matching it against the trusted
key ring. Retire an old key only after all of its ciphertext has been migrated.
Never reuse the same key bytes under multiple IDs. Track total encryptions across
all processes and deployments and rotate before 2^32 invocations under one key;
the component also enforces that limit atomically within each instance.

Compile and run the dependency-free tests:

```text
mkdir -p out
javac -d out $(rg --files src/main/java src/test/java -g '*.java')
java -cp out com.example.security.crypto.AesGcmDataProtectorTest
```

`out` is build output and must not be deployed as writable shared code.

## Trust boundaries and adversarial review

Every input is treated as hostile:

| Input | Source | Validation/use |
|---|---|---|
| Raw keys | secret manager, KMS export, configuration, database, or runtime caller | Non-null, exactly 32 bytes, at most 32 distinct keys; defensively copied; duplicate material is rejected. Never parsed from strings by this library. |
| Key IDs and active ID | configuration; envelope ID is client-controlled | Strict 1–64 character ASCII allowlist. The active ID must exist in trusted server-side state. An envelope ID only selects a configured key and is covered by the GCM tag. |
| Purpose | configuration | Strict 1–64 character ASCII allowlist and authenticated as a domain separator. |
| Plaintext | database, file, service, or client | Non-null and bounded by the validated configured limit (1 byte–16 MiB). Empty plaintext is allowed. |
| Context | database, configuration, service, or client | Non-null, 0–64 KiB, length-delimited, and authenticated but not encrypted. It never grants authorization. |
| Ciphertext envelope | database, file, service, or client | Bounded before parsing; exact magic, version, algorithm, ID length/characters, nonce, and minimum tag length are checked. Header, context, and purpose are authenticated before plaintext is returned. Unknown keys perform a dummy authenticated-decryption attempt and fail generically. |
| Size limit | configuration | Integer restricted to 1 byte–16 MiB. Invalid values are rejected; no permissive default exists. |

Adversarial cases considered include tampering, truncation, algorithm/version
downgrade, unknown-key probing, cross-purpose and cross-record substitution,
nonce reuse, oversized-input denial of service, mutable caller arrays, key
rotation mistakes, concurrent close/use, serialization, and exception leakage.

## How the requested security rules apply

1. **Trust boundaries.** The table above enumerates every input. All are type,
   length, range, and/or allowlist checked. Ciphertext-controlled metadata is
   authenticated and can only reference trusted server-side keys.
2. **Secrets.** There are no embedded keys or credentials. Keys enter as runtime
   byte arrays, are never included in messages or `toString`, cannot be
   serialized by the operation-scoped key class, and are never logged or written
   to disk. Do not put keys in environment strings or command-line arguments;
   use a secret manager with least-privilege file/socket permissions if needed.
3. **Authentication and access.** This component neither authenticates users nor
   makes authorization decisions. Its caller must check server-side access before
   use. Account/source rate limiting is therefore not applicable; cryptographic
   failures are not login attempts and rate limiting here could enable lockout.
4. **Identifiers and tokens.** No session IDs, cookies, or authentication tokens
   exist. Nonces are generated internally with `SecureRandom` and cannot be
   supplied by a caller. Externally stored record identifiers belong in
   authenticated `context`; remaining authorization risk stays with the caller.
5. **Sensitive data.** Inputs and outputs are bounded. Internal raw-key copies
   are erased on close and operation copies are erased immediately. Callers must
   erase their own key/plaintext arrays and, if persisting envelopes, create files
   with owner-only permissions. The JVM/provider may retain unavoidable internal
   copies until garbage collection, so use a KMS/HSM design when that threat is
   in scope.
6. **Failure behavior.** Runtime operations expose only
   `DataProtectionException` with one fixed message, no cause, and no stack trace.
   Invalid input is rejected with no fallback. The library deliberately emits no
   logs; applications may record a generic failure metric but must not log keys,
   plaintext, context, envelopes, exception inputs, or existence-sensitive data.
7. **Concurrency.** The component is thread-safe. Per-key usage reservation is
   atomic. A read/write lifecycle lock makes use-versus-close atomic, so key
   erasure waits for active operations and new operations fail closed.
8. **Prefer the platform.** Cryptography and randomness use only Java 17 JCA/JCE
   primitives. No cipher, tag, random generator, or encoding is hand-rolled, and
   no third-party or remotely downloaded code is required.

Java cannot guarantee erasure of provider/JIT/GC-managed copies. Closing the
component and clearing caller-owned arrays is defense in depth, not a substitute
for process isolation, heap-dump controls, least privilege, and a managed KMS or
HSM for environments requiring non-exportable keys.
