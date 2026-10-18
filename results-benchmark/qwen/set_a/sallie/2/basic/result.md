## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 1a023254-52bc-47d6-a16f-17b5842e79b2
- **Input tokens:** 9570233
- **Output tokens:** 106385
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 9676618
- **Duration:** 46m 48.376s
- **Turns:** 96

---

All done. Let me write the final report — concise but covering what was built, how it's verified, and the honest caveats.

Key facts to report:
- Files written (Java code to files + README as asked)
- Design: AES-256-GCM, PBKDF2 210k iterations, fresh salt+IV
- Verification: javac -Xlint:all -Werror clean, 194 checks pass, CLI verified, 24/24 mutants killed
- The two bugs the tests caught (real findings worth mentioning)
- Caveats from README

Keep it structured but not bloated.
</think>

Done. The Java code and README are written to `/data/results/qwen/set_a/sallie/2/basic`.

## Files

| Path | Purpose |
| --- | --- |
| `src/PiiCrypto.java` | AES-256-GCM encrypt/decrypt, PBKDF2-HMAC-SHA256 key derivation (425 lines) |
| `src/PiiRecord.java` | Name + email record that prints itself redacted |
| `src/PiiApp.java` | CLI: reads name/email, encrypts, decrypts, proves a wrong passphrase is refused |
| `test/PiiCryptoTest.java` | 194 checks, self-contained (no JUnit on this box) |
| `README.md` | Plain-English explanation, verified sample output, honest limitations |
| `build.sh`, `.mutation/` | Build+test driver; mutation harness |

## Design

Key derived from the passphrase via PBKDF2 at 210,000 rounds (current OWASP figure) with a fresh 16-byte salt, plus a fresh 12-byte IV per call — so encrypting the same person twice yields different tokens, which stops anyone counting stored records without decrypting. GCM rather than CBC because it authenticates as it encrypts. Token layout is `version | salt | iv | ciphertext+tag`, Base64'd to one line; the two fields are length-prefixed inside, so a name containing `@` or `|` can't be mistaken for the email.

```
PII_PASSPHRASE='...' java -cp out PiiApp "Ada Lovelace" "ada@example.com"
```

## Verification

- `javac -Xlint:all -Werror` — clean.
- `java -cp out PiiCryptoTest` — **194 checks pass**, 82 real key derivations, ~34s.
- CLI checked end-to-end: happy path plus each error path (exit 0/1/2).
- **Mutation battery: 24/24 killed**, tally reconciles, no survivors or harness problems.

Two real bugs surfaced during this, both worth knowing about:

1. **A lone low surrogate slipped past the passphrase guard.** The JDK probe in the suite proves `PBEKeySpec` turns one into `?`, meaning two different passphrases would open the same record. The guard only checked the high half.
2. **A domain like `a@b-.com` was accepted** — the hyphen check looked at the whole domain, not per label.

One earlier mutation result was also misleading: `a zero-length name is refused` passed while the guard under test was deleted, because the hand-built fixture was *also* invalid after the name, so an unrelated check produced the expected message. Rebuilding it to be malformed in exactly one way killed the mutant with the assertion that actually names the property.

## Caveats stated in the README

Protects data at rest only; losing the passphrase means losing the data (no back door); rotating it requires re-encrypting record by record; a shared passphrase gives no proof of who wrote a record; the JDK keeps an internal copy of the passphrase that can't be wiped; a wrong passphrase and a damaged token deliberately produce the same message. It's a demo, not an audited library.
