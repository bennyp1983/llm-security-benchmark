## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** TEXT_FALLBACK
- **Output format:** text_fallback
- **Conversation ID:** 
- **Input tokens:** 
- **Output tokens:** 
- **Thinking tokens:** 
- **Cached read tokens:** 
- **Cache creation tokens:** 
- **Total tokens:** 
- **Duration:** 
- **Turns:** 

---

Developed and verified a complete, dependency-free Java 17 symmetric-encryption program in
/data/results/qwen/set_a/pilot/2/basic using only the standard javax.crypto APIs.

WHAT WAS BUILT
  src/com/example/crypto/SymmetricCrypto.java  library: AES-256-GCM encrypt/decrypt, self-describing
      envelope, two key sources (raw 256-bit key, or passphrase via PBKDF2-HmacSHA256 @310k iters),
      CryptoException with isAuthenticationFailure()
  src/com/example/crypto/App.java              CLI: keygen / encrypt / decrypt / demo / selftest
  src/com/example/crypto/Demo.java             narrated end-to-end walk-through
  src/com/example/crypto/SelfTest.java         36 executable checks, no test framework required
  verify.sh                                    compile + selftest + demo + CLI round trips
  README.md                                    design rationale, CLI reference, verification results

HOW IT WORKS
  AES-256 in GCM (AEAD: confidentiality + integrity in one primitive). Per-call envelope:
      "AESG" | version(1) | keySource(1) | [salt(16) | iterations(4)] | iv(12) | ciphertext+tag(16)
  The header is fed to GCM as additional authenticated data, so rewriting the IV, salt, or iteration
  count breaks the tag exactly like rewriting the ciphertext. Overhead: 34 bytes.
  A fresh 12-byte IV is drawn from SecureRandom inside encrypt and the API never accepts a
  caller-supplied IV, so GCM IV reuse — the classic way to break this cipher — is impossible by
  construction. An optional --aad/--aad context binds a ciphertext to the record it belongs to, so a
  token copied between config keys fails verification. Stored PBKDF2 work factors outside
  [100000, 10000000] are refused before derivation runs, so a hostile envelope cannot make the
  decryptor burn arbitrary CPU. Passphrases are char[] and wiped after derivation.

HOW TO RUN
  ./verify.sh
  java -cp out com.example.crypto.App keygen --out app.key            # written 0600
  export APP_KEY="$(cat app.key)"
  java -cp out com.example.crypto.App encrypt --key-env APP_KEY --aad billing.db-url \
      --text 'postgres://app:s3cr3t@db:5432/billing'                  # -> QUVTRwEA... (base64)
  java -cp out com.example.crypto.App decrypt --key-env APP_KEY --aad billing.db-url \
      --text 'QUVTRwEA...'                                            # -> original data
  Library form: KeySource key = SymmetricCrypto.KeySource.of(SymmetricCrypto.newKey());
                String token = crypto.encryptToBase64(key, secret, "billing.db-url");
                String back  = crypto.decryptBase64(key, token, "billing.db-url");

VERIFICATION (all run, all green)
  Compiles clean under: javac -encoding UTF-8 -Xlint:all -Werror   (the -encoding flag is required
    here because this machine's default charset is US-ASCII)
  ./verify.sh -> "all checks passed": selftest 36/36 PASS, demo OK, CLI keygen/encrypt/decrypt OK.
  36 checks include: round trips for empty input, 100000-char, non-ASCII, CR/LF/TAB and 70000 random
    bytes; 500 encryptions yielding 500 distinct IVs AND 500 distinct envelopes; wrong key / wrong
    passphrase / wrong AAD / omitted AAD all rejected; an exhaustive single-byte flip of EVERY byte of
    a raw-key envelope (62) and a passphrase envelope (59), all rejected and all from the IV onward
    specifically by the AEAD tag; truncation, foreign blob, invalid base64, absurd work factor;
    short/non-AES key, empty passphrase, weak work factor, key-source mismatch.
  CLI exit codes exercised: 1 usage, 2 bad input/key, 3 authentication failure. Binary payloads
    round-trip byte-exact through --file and --stdin (verified with cmp on 5000- and 20000-byte
    random files).

BUGS FOUND AND FIXED DURING VERIFICATION (caught by actually running the CLI)
  1. CLI encrypt lossily round-tripped bytes through a UTF-8 String, corrupting binary --file input;
     now it uses the byte[] API end to end.
  2. Standalone switches (--stdin/--force/--help) were stored without their "--" prefix but looked up
     with it, so --stdin never registered.
  3. The stdin newline-chomp was applied on encrypt but not decrypt, inflating binary output by a
     byte; stdin is now byte-exact both ways and decrypt prints no trailing newline (openssl-style).

