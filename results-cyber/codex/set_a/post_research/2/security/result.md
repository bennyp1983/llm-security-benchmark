## Run Metadata

- **CLI:** ChatGPT Codex
- **Set:** a
- **Status:** SUCCESS
- **Output format:** jsonl
- **Conversation ID:** 01a0f4e7-e4ff-7da2-b4a3-2a2593e64a76
- **Input tokens:** 404936
- **Output tokens:** 18672
- **Thinking tokens:** 7795
- **Cached read tokens:** 366336
- **Cache creation tokens:** 0
- **Total tokens:** 423608
- **Duration:** 
- **Turns:** 1

---

Implemented a dependency-free Java 17 encryption component:

- [AesGcmDataProtector.java](/data/results/codex/set_a/post_research/2/security/src/main/java/com/example/security/crypto/AesGcmDataProtector.java)
- [DataProtectionException.java](/data/results/codex/set_a/post_research/2/security/src/main/java/com/example/security/crypto/DataProtectionException.java)
- [Security documentation and usage](/data/results/codex/set_a/post_research/2/security/README.md)
- [Dependency-free tests](/data/results/codex/set_a/post_research/2/security/src/test/java/com/example/security/crypto/AesGcmDataProtectorTest.java)

Key properties:

- AES-256-GCM with 96-bit secure-random nonces and 128-bit tags, following [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) and [Java JCA guidance](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html).
- Authenticated, versioned ciphertext envelope.
- Immutable server-side key ring with rotation support.
- Strict input validation and resource bounds.
- Purpose and record context binding.
- Generic, cause-free cryptographic failures.
- Comparable cryptographic work for unknown key IDs.
- Atomic per-key encryption limits and safe concurrent closure.
- Defensive key copies, memory clearing, and blocked key serialization.
- No CLI, external dependencies, logging, persistence, or unrelated functionality.

The README enumerates every input and maps all eight requested security rules to the implementation.

Verification passed with:

```text
javac -Xlint:all -Werror
AesGcmDataProtectorTest
```
