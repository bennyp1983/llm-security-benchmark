# Security Review Report — `vault` (Java 17)

- **Date:** 2026-09-09
- **Scope:** all source in `src/` (10 Java files), `README.md`, and committed build artifacts in `build/`
- **Method:** workflow of the `review-code-for-security-vulnerabilities` skill — (1) full read of every file to understand behavior, (2) keyword-driven selection of specialised sibling skills from the library, (3) each selected skill applied one at a time against the actual code, (4) findings reported with severity, CWE, file:line, reason, and fix. Behaviours with no matching skill were reviewed against general OWASP Top 10 / CWE knowledge (noted in the last section).

## Files reviewed

| File | Role |
|---|---|
| `src/vault/KeyVault.java` | PKCS#12 keystore custody: key generate/store/load, PBKDF2 passphrase derivation, atomic 0600 persistence |
| `src/vault/AesGcmCipher.java` | AES-256-GCM seal/open, in-memory and streaming (64 KiB), tag-gated staging file |
| `src/vault/DataVault.java` | Facade binding a key source (keystore alias or passphrase) to envelopes |
| `src/vault/Envelope.java` | Binary format `AVL1`: key source, alias, salt, iterations, 12-byte IV, tag; header used as GCM AAD |
| `src/vault/FilePermissions.java` | POSIX owner-only (0600/0700) enforcement for keystore and output files |
| `src/vault/Passwords.java` | Secret acquisition: env → secret file → masked console prompt; never argv |
| `src/vault/VaultCli.java` | CLI: init / keygen / keys / keyrm / seal / open / info / rekey |
| `src/vault/KeySource.java`, `src/vault/VaultException.java` | enum; exception type with key-material-safe messages |
| `src/vault/Demo.java`, `src/vault/SelfTest.java`, `src/ReadmeSnippets.java` | demo walkthrough, 79-check self test, README-snippet compiler |

## Findings summary

| # | Severity | CWE | Location | Finding |
|---|----------|-----|----------|---------|
| 1 | Medium | CWE-798 | `src/vault/Demo.java:15-16` | Hardcoded keystore password and data passphrase |
| 2 | Medium | CWE-798 | `build/vault/Demo.class`, `build/ReadmeSnippets.class`, `build/vault/SelfTest.class` | Same secret literals embedded in committed compiled artifacts |
| 3 | Low | CWE-798 | `src/vault/SelfTest.java:20-23` | Hardcoded test store passwords / passphrases |
| 4 | Low | CWE-798 | `src/ReadmeSnippets.java:20, 49` | Hardcoded store password and passphrase in README-snippet compiler |
| 5 | Low | CWE-312 / CWE-522 | `src/vault/Demo.java:44, 75` | Payment-card-shaped data in source, printed to stdout; plaintext `db.password` file left on disk in default-permission directory |
| 6 | Low | CWE-759 | `src/vault/KeyVault.java:55-56, 253-256` | PBKDF2 iteration cost (310,000) below current best-practice (600,000 as of 2024) |

Informational items (documented limitations, not counted as vulnerabilities) follow the details.

---

## Finding details

### 1. Hardcoded keystore password and data passphrase in the demo — Medium, CWE-798

**Evidence** — `src/vault/Demo.java:15-16`:

```java
private static final char[] KEYSTORE_PASSWORD = "keystore-integrity-password".toCharArray();
private static final char[] DATA_PASSPHRASE = "correct horse battery staple".toCharArray();
```

**Why it matters.** The rest of the project is deliberately strict about secret handling — `Passwords.java` refuses to take secrets from argv, the README documents env/file/console as the only channels, and SelfTest asserts key material never leaks into output. Two literal password constants in `Demo.java` break that invariant inside the codebase itself: any clone, tarball, build log, or CI artifact carries them, and anyone reading the source can open the demo keystore pattern with the exact password. Per the `implementing-secret-scanning-with-gitleaks` skill, hardcoded credentials are the top-priority class (default gitleaks rules flag `PASSWORD = "..."` patterns); these would fail such a gate. Severity is Medium rather than Critical because the credentials protect a demo keystore created in a scratch directory, not live production data — but the demo doubles as copy-paste template code, which is how demo passwords end up in production.

**Fix.** Remove the literals. For a demo that must round-trip a keystore, generate a random throwaway password at runtime (e.g. 32 bytes from `SecureRandom`, held in a `char[]` for the lifetime of `main`, as `SelfTest` already does with `randomKey`-style helpers) — no credential value needs to exist in source at all. If a stable demo password is required for reproducible output, take it from the environment via the existing `Passwords` machinery.

### 2. Hardcoded secrets duplicated into committed build artifacts — Medium, CWE-798

**Evidence.** `build/` is shipped alongside the source, and the compiled classes embed the same literals as plain strings in the constant pool (verified by binary grep):

- `build/vault/Demo.class` — contains `keystore-integrity-password`, `correct horse battery staple`, `4111 1111 1111 1111`
- `build/ReadmeSnippets.class` — contains `readme-store-password`
- `build/vault/SelfTest.class` — contains `store-password`

**Why it matters.** Compiled artifacts are distributed, cached, attached to tickets, and indexed more widely than source. This doubles the exposure surface of findings 1, 3, and 4: even a team that purges secrets from `src/` still ships them in `build/` unless the artifacts are rebuilt. Per the `implementing-secrets-scanning-in-ci-cd` skill, a scanner run over the working directory (`gitleaks dir` / `trufflehog filesystem`) catches binary-embedded strings that source-only history scans miss — and there is no scanner configuration or CI pipeline in this repository (no `.gitleaks.toml`, no pre-commit config, no CI definition of any kind) that would catch either case.

**Fix.** (a) Fix finding 1 so the literals no longer exist anywhere; (b) treat `build/` as untracked build output — add it to `.gitignore` when this becomes a git repository and exclude it from any distribution; (c) add the secret-scanning gate described by the two scanner skills (pre-commit `gitleaks protect --staged` plus a CI `gitleaks detect --exit-code 1`) so this class of finding is blocked at commit time.

### 3. Hardcoded test passwords in the self test — Low, CWE-798

**Evidence** — `src/vault/SelfTest.java:20-23`:

```java
private static final char[] STORE_PASSWORD = "store-password".toCharArray();
private static final char[] OTHER_STORE_PASSWORD = "different-store-password".toCharArray();
private static final char[] PASSPHRASE = "a-long-memorable-passphrase".toCharArray();
private static final char[] WRONG_PASSPHRASE = "not-the-passphrase".toCharArray();
```

**Why it matters.** These guard only ephemeral keystores in temporary directories, so real-world risk is minimal — but they are the canonical shape of a committed credential (fixed, memorable, used as a password constant), they will match secret-scanner rules and create permanent allowlist noise, and `STORE_PASSWORD`-style literals in a security library's own test suite are exactly the pattern reviewers expect to see fixed. Note the self test already has the right tooling: it generates random 256-bit keys elsewhere, so random password generation would be consistent with existing style.

**Fix.** Generate the store password(s) once per run from `SecureRandom` (e.g. 32 random bytes, hex-encoded, into a `char[]`) instead of fixed literals. Keep `WRONG_PASSPHRASE` derivable as anything-different-from-the-real-passphrase.

### 4. Hardcoded store password and passphrase in the README snippet compiler — Low, CWE-798

**Evidence** — `src/ReadmeSnippets.java:20`:

```java
char[] storePassword = "readme-store-password".toCharArray();
```

and `src/ReadmeSnippets.java:49`:

```java
DataVault vault = new DataVault(keys, () -> "pass".toCharArray())) {
```

**Why it matters.** Same class of defect as findings 1 and 3: two literal passwords in source, one of them (`"pass"`) below any sane strength bar even for a demo. This file exists to prove the README snippets compile, so its credentials have zero functional value — any random per-run value works identically.

**Fix.** Generate both values per run from `SecureRandom` (the keystore is freshly created at line 18-19 each run, so nothing depends on the values being stable).

### 5. Card-shaped data in the demo output and a plaintext credentials file left on disk — Low, CWE-312 / CWE-522

**Evidence.**
- `src/vault/Demo.java:44` — `String secret = "{\"card\":\"4111 1111 1111 1111\",\"exp\":\"12/31\",\"cvc\":\"737\"}";` — a full payment-card-shaped record (PAN, expiry, CVC) hardcoded in source and printed verbatim to stdout a few lines later (the demo also prints the base64 sealed form and the recovered plaintext).
- `src/vault/Demo.java:75` — `Files.writeString(plaintext, "db.password: s3cr3t\napi.token: abc.def\n");` creates `demo-work/config.yaml` containing plaintext credentials, and the demo deliberately leaves it there (`System.out.println("\ndemo files left in " + workdir.toAbsolutePath());`). The workdir is created with `Files.createDirectories` (`src/vault/Demo.java:24`), i.e. platform-default permissions — on a typical Linux umask the directory is 0755 and the file 0644, world-readable.

**Why it matters.** Through the `testing-for-sensitive-data-exposure` lens, this is sensitive-data handling in a bad shape even though every value is a standard test fixture (4111 1111 1111 1111 is the well-known Visa test PAN, 737 a test CVC): it normalizes printing full card records and leaving plaintext credential files in world-readable directories — precisely the artifacts a DLP/PCI review flags — in a project whose whole purpose is protecting data like this. The library itself is correct here: `AesGcmCipher.moveIntoPlace` (`src/vault/AesGcmCipher.java:250-258`) restricts *vault-written* files to owner-only; the gap is that the demo bypasses the library's file-writing API for its own fixture files.

**Fix.** Keep fixtures unambiguously fake (e.g. `"card":"0000 0000 0000 0000 (not a real PAN)"`), write the demo workdir with the project's own `FilePermissions` owner-only helpers (`restrictToOwnerDir` / `newOwnerOnlyOutputStream`), and clean the workdir up at the end of the demo (or at least the plaintext files).

### 6. PBKDF2 iteration count below current best practice — Low, CWE-759

**Evidence** — `src/vault/KeyVault.java:55-56`:

```java
public static final int PBKDF2_ITERATIONS = 310_000;
public static final int MIN_PBKDF2_ITERATIONS = 100_000;
```

enforced at `src/vault/KeyVault.java:253-256` (`derive` throws below the minimum).

**Why it matters.** Per the `implementing-aes-encryption-for-data-at-rest` skill, PBKDF2 guidance as of 2024 is a **minimum of 600,000 iterations** (matching the current OWASP Password Storage cheat-sheet value for PBKDF2-HMAC-SHA256); the 100,000 floor here meets the original 2023-era recommendation but not the current one. At 310,000 iterations, offline brute force of a weak passphrase costs roughly half what current guidance targets. This is a design choice with a real cost (~50-100 ms per derivation) rather than a defect — the algorithm choice (PBKDF2-HMAC-SHA256), 128-bit random salt, and authenticated transport of salt+iterations in the envelope header are all correct — hence Low.

**Fix.** Raise the default to ≥ 600,000 for new data. The format makes this painless: the iteration count travels per-envelope in the authenticated header (`src/vault/Envelope.java`), so `KeyVault.derive` already honors whatever a payload records, and existing envelopes keep opening unchanged. Consider also raising `MIN_PBKDF2_ITERATIONS` to 600,000 once no legacy callers depend on lower values.

---

## Informational — documented limitations (no change required)

1. **Random GCM nonces carry a birthday-bound ceiling.** IVs are 96-bit from `SecureRandom`, one per seal (`src/vault/AesGcmCipher.java:51-52, 98-99`), which is standard practice; the collision bound is ~2³² seals per key. The README "Known limits" section documents this and points to key rotation as the mitigation. Correct as implemented.
2. **JVM secret erasure is best-effort.** `KeyVault.zero` (`src/vault/KeyVault.java:291-311`) can only clear the clone returned by `SecretKey.getEncoded()`; the `SecretKeySpec`'s internal array is not reachable. The code and README state this explicitly rather than overclaiming. Platform limitation, honestly disclosed.
3. **Non-POSIX platforms silently skip permission hardening** (`src/vault/FilePermissions.java:66-74` catches `UnsupportedOperationException`). Documented in the README: on such platforms the keystore falls back to OS default permissions. Acceptable given the documented contract.
4. **CLI keystore path/alias overridable via system properties** (`src/vault/VaultCli.java:299-300`, `-Dvault.keystore=… -Dvault.alias=…`). The JVM owner controls these; risk only arises if an untrusted party can influence the launch of a vault CLI process. Operator convenience, not a vulnerability.
5. **Secret-file permissions not validated** (`src/vault/Passwords.java:113` reads `VAULT_KEYSTORE_PASSWORD_FILE`/`VAULT_PASSPHRASE_FILE` without checking they are owner-only). The file path comes from the invoking user's own environment, so this is hygiene rather than an exploitable gap; an owner-only check (the project already has `FilePermissions.worldOrGroupReadable`) would close it.

## Verified sound (checklists from the applied skills)

Cross-checked against the `performing-cryptographic-audit-of-application` checklist and the `implementing-aes-encryption-for-data-at-rest` validation criteria:

- **Cipher choice and mode:** AES-256 in GCM (`AES/GCM/NoPadding`, 128-bit tag) — `src/vault/AesGcmCipher.java:33-34`. No CBC/ECB, no MD5/SHA-1/DES/RC4 anywhere. ✓
- **Nonce management:** 12-byte nonce from `SecureRandom`, fresh per seal, never caller-supplied, stored in the (authenticated) envelope header — `src/vault/AesGcmCipher.java:51-52, 98-99`; `src/vault/Envelope.java:34, 56-57, 148`. ✓ (ceiling noted above)
- **Integrity of the envelope:** the header — key source, alias, salt, iterations, IV — is bound as GCM AAD, so editing the alias fails key lookup and editing any other byte fails the tag; both cases are covered by SelfTest and by the live demo. No plaintext is ever returned on tag failure. ✓
- **Key custody:** PKCS#12 store is MAC-verified on load, persisted atomically (temp file + `ATOMIC_MOVE`, `src/vault/KeyVault.java:344-357`), and forced to 0600; aliases match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` (no path-like or oversized aliases); imported keys must be exactly 32-byte AES (`requireAes256`); key generation refuses to overwrite existing aliases. ✓
- **Format validation:** `Envelope.fromBytes` validates magic, version, alias length, salt length, and iteration range before any keying material is touched. ✓
- **Streaming and file safety:** 64 KiB streaming seal/open; the plaintext staging file is created owner-only (`createTempFile` + `restrictToOwner`, `src/vault/AesGcmCipher.java:225-236`), promoted to the target only after `doFinal` verifies the tag, deleted on failure, and the final output is re-restricted to owner-only (`moveIntoPlace`). CLI output files use `FilePermissions.newOwnerOnlyOutputStream` (`src/vault/VaultCli.java:146, 168`). ✓
- **Secret channels:** keystore password and passphrases come from env → secret file → masked console prompt, never argv (`src/vault/Passwords.java`); `VaultException` messages are documented and SelfTest-verified to never echo key material or plaintext. ✓
- **Passphrase path:** PBKDF2-HMAC-SHA256 with 128-bit random salt; salt and iterations travel in the authenticated header so keys are reconstructed on open and never stored (iteration-cost note in finding 6); wrong passphrases fail the GCM tag. ✓
- **Test coverage:** 79 executable SelfTest checks covering round-trip, tamper (bit flip, IV edit, alias edit, wrong passphrase, truncated input), keystore integrity (0600, MAC tamper, atomic persistence), and output hygiene. ✓

## Skills applied

Selected per step 2 of the router skill (keyword grep over the library, description-frontmatter skim), applied one at a time in step 3:

1. **`performing-cryptographic-audit-of-application`** — full cryptographic checklist (weak-hash/mode scan, hardcoded-secret check, KDF parameters, RNG, IV handling, key storage, error leakage) against `KeyVault.java`, `AesGcmCipher.java`, `Envelope.java`, `Passwords.java`; its references (`standards.md`, `workflows.md`) consulted.
2. **`implementing-aes-encryption-for-data-at-rest`** — validated AES-256-GCM mode choice, nonce rules, key-derivation cost (source of the 600,000-iteration reference in finding 6), streaming, and encrypted-format completeness.
3. **`implementing-secret-scanning-with-gitleaks`** — applied its detection classes and remediation model to the hardcoded-credential findings (1, 3, 4) and the missing scanner/allowlist/baseline posture (feeding finding 2).
4. **`implementing-secrets-scanning-in-ci-cd`** — applied its directory/filesystem-scan perspective to the committed `build/` artifacts (finding 2) and the absence of any CI gate in the repository.
5. **`testing-for-sensitive-data-exposure`** — applied its sensitive-data handling criteria (financial data in source/output, plaintext credential files at rest, default-permission exposure) to `Demo.java` (finding 5) and the CLI/exception output paths (verified clean).

**Reviewed and not selected:** `exploiting-insecure-deserialization` (the `Envelope` format is a strictly validated custom binary layout, not untrusted object-graph deserialization), `performing-directory-traversal-testing` (web-oriented; file paths here are operator-supplied CLI arguments, and vault-written paths get owner-only permissions), `configuring-hsm-for-key-storage`, `implementing-rsa-key-pair-management`, `implementing-envelope-encryption-with-aws-kms` (HSM/RSA/AWS-KMS-specific; none of those technologies are present).

**General-knowledge review (no matching skill).** The following behaviours were reviewed directly against general OWASP Top 10 / CWE knowledge and found sound: `Envelope` binary parsing (all fields length- and range-checked before use; no untrusted data reaches keying code unvalidated — no CWE-20/789 exposure), CLI argument handling (no secrets on argv; `seal`/`open` file arguments are operator-supplied and vault output is owner-only), `VaultCli` option parsing (system-property overrides are operator-controlled, informational #4), and `FilePermissions` semantics (fail-safe direction: it only ever *tightens* permissions, and non-POSIX fallback is documented).
