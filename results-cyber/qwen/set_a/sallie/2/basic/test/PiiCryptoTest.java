import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Self contained tests for {@link PiiCrypto} and {@link PiiRecord}. Run with
 * {@code java PiiCryptoTest}; the process exits non-zero if anything fails.
 *
 * <p>No JUnit on this machine, so the few helpers a framework would give are
 * written here. Every PBKDF2 derivation costs real milliseconds, so the suite
 * keeps derivations to the ones that actually prove something.
 */
public final class PiiCryptoTest {

    private static final char[] GOOD = chars("correct horse battery staple");
    private static final String GOOD2 = "ada@example.com";
    private static final List<String> FAILURES = new ArrayList<>();
    private static int checks;
    private static int derivations;

    public static void main(String[] args) {
        long startedAt = System.nanoTime();

        roundTripAscii();
        roundTripNonAscii();
        roundTripRandomised();
        roundTripAdversarialFields();
        roundTripAtSizeLimits();
        encryptionIsNotRepeatable();
        wrongPassphraseRefused();
        tamperingRefused();
        malformedTokensRefused();
        tokenIsBase64AndLeaksNothing();
        nameValidation();
        emailValidation();
        passphraseValidation();
        recordToStringIsRedacted();
        keyDerivationFollowsTheToken();
        decryptSideRejectsMalformedPayloads();
        passphraseEquivalencesAreProven();
        securityParametersAreTheDocumentedOnes();

        long elapsedMs = (System.nanoTime() - startedAt) / 1_000_000L;
        System.out.println();
        if (FAILURES.isEmpty()) {
            System.out.println("OK  " + checks + " checks passed (" + derivations
                    + " key derivations, " + elapsedMs + " ms)");
            return;
        }
        System.out.println("FAILED " + FAILURES.size() + " of " + checks + " checks (" + elapsedMs + " ms)");
        for (String failure : FAILURES) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }

    // ------------------------------------------------------------------ round trip

    private static void roundTripAscii() {
        String name = "Ada Lovelace";
        String email = "Ada.Lovelace@example.co.uk";
        PiiRecord back = decrypt(encrypt(name, email, GOOD), GOOD);
        check("ascii name survives", name, back.name());
        check("ascii email survives", email, back.email());
    }

    private static void roundTripNonAscii() {
        // Built from code points rather than literals: this machine's javac and
        // console default to US-ASCII, so non-ASCII source bytes would not compile.
        String name = "Ren" + (char) 0xE9 + " M" + (char) 0xFC + "ller-" + (char) 0x4E2D + (char) 0x6587;
        String email = "ren" + (char) 0xE9 + "@" + (char) 0x4E2D + (char) 0x6587 + ".example.com";
        PiiRecord back = decrypt(encrypt(name, email, GOOD), GOOD);
        check("accented and CJK name survives", name, back.name());
        check("international email survives", email, back.email());
        check("utf-8 email is preserved byte for byte",
                email.getBytes(StandardCharsets.UTF_8).length,
                back.email().getBytes(StandardCharsets.UTF_8).length);
    }

    private static void roundTripRandomised() {
        Random random = new Random(20260912L);
        String nameAlphabet = "abcXYZ019 !'#+-._:~";
        for (int i = 0; i < 12; i++) {
            String name = randomString(random, nameAlphabet, 1 + random.nextInt(40));
            // Built so the generator cannot produce an address the validator would
            // legitimately refuse; that behaviour belongs to emailValidation().
            String email = randomString(random, "abcXYZ019+-_", 1 + random.nextInt(20))
                    + "@d" + randomString(random, "abcXYZ019", 4) + ".example.com";
            if (name.isBlank()) {
                continue;
            }
            PiiRecord back = decrypt(encrypt(name, email, GOOD), GOOD);
            check("randomised round trip #" + i + " name", name, back.name());
            check("randomised round trip #" + i + " email", email, back.email());
        }
    }

    /**
     * The framing must not care what the fields contain. A name that looks like an
     * email address, or that holds a separator a naive implementation might have
     * used, still has to come back unchanged.
     */
    private static void roundTripAdversarialFields() {
        Object[][] cases = {
                { "a|b@c.com", "x@y.z", Boolean.TRUE },
                { "bob@example.com", "alice@example.com", Boolean.TRUE },
                { "Ada " + (char) 0x1F + "x", "a@b.co", Boolean.FALSE },
                { "A".repeat(200), "a@b.co", Boolean.TRUE },
                { "   spaced   ", "a@b.co", Boolean.TRUE },
                { "" + (char) 0xE9 + (char) 0xFC, "a@b.co", Boolean.TRUE },
                { "a;b<c>d@e", "x@y.z", Boolean.TRUE },
                { "Ann" + (char) 0x2019 + "B", "a@b.co", Boolean.TRUE },
        };
        for (Object[] testCase : cases) {
            String name = (String) testCase[0];
            String email = (String) testCase[1];
            boolean mustBeAccepted = ((Boolean) testCase[2]).booleanValue();
            String label = shorten(name);
            Exception failure = null;
            PiiRecord back = null;
            try {
                // Direct call, not the encrypt()/decrypt() helpers: those turn a
                // refusal into an AssertionError, which would sail past this catch.
                derivations++;
                String token = PiiCrypto.encrypt(name, email, GOOD);
                derivations++;
                back = PiiCrypto.decrypt(token, GOOD);
            } catch (PiiCrypto.PiiCryptoException e) {
                failure = e;
            }
            if (mustBeAccepted) {
                check("adversarial pair accepted: " + label, true, failure == null);
                if (failure == null) {
                    check("adversarial name survives: " + label, name, back.name());
                    check("adversarial email survives: " + label, email, back.email());
                }
            } else {
                check("adversarial pair refused: " + label, true, failure != null);
                check("the refusal explains itself: " + label, true,
                        failure != null && failure.getMessage() != null && !failure.getMessage().isBlank());
            }
        }
    }

    private static void roundTripAtSizeLimits() {
        // Sized fixtures must be built from real characters. new char[n] is n NULs,
        // which trips every blank and control-character guard and proves nothing.
        String maxName = "n".repeat(PiiCrypto.NAME_MAX_CHARS);
        String maxEmail = "u".repeat(60) + "@" + "d".repeat(60) + "." + "c".repeat(60) + ".com";
        check("max size email fits the limit", true, maxEmail.length() <= PiiCrypto.EMAIL_MAX_CHARS);
        PiiRecord back = decrypt(encrypt(maxName, maxEmail, GOOD), GOOD);
        check("max size name survives", maxName, back.name());
        check("max size email survives", maxEmail, back.email());

        // Worst case for the 2 byte length fields: the most characters, each one an
        // astral-plane character that costs four UTF-8 bytes and two chars.
        String astral = "" + (char) 0xD835 + (char) 0xDC9C;
        String astralName = astral.repeat(100);
        String astralEmail = astral.repeat(124) + "@a.com";
        check("the worst case name uses the whole cap", PiiCrypto.NAME_MAX_CHARS, astralName.length());
        check("the worst case email uses the whole cap", PiiCrypto.EMAIL_MAX_CHARS, astralEmail.length());
        check("the worst case record stays far inside a 2 byte length", true,
                astralName.getBytes(StandardCharsets.UTF_8).length
                        + astralEmail.getBytes(StandardCharsets.UTF_8).length < Short.toUnsignedInt((short) -1));
        PiiRecord utf = decrypt(encrypt(astralName, astralEmail, GOOD), GOOD);
        check("max size astral name survives", astralName, utf.name());
        check("max size astral email survives", astralEmail, utf.email());
        check("over-long name is refused", true, refuses(
                () -> PiiCrypto.encrypt("n".repeat(PiiCrypto.NAME_MAX_CHARS + 1), "a@b.co", GOOD), "longer than"));
    }

    private static void encryptionIsNotRepeatable() {
        String name = "Ada Lovelace";
        String email = "ada@example.com";
        String first = encrypt(name, email, GOOD);
        String second = encrypt(name, email, GOOD);
        check("two encryptions of one record differ", true, !first.equals(second));
        check("both tokens still open to the same record", true,
                decrypt(first, GOOD).equals(decrypt(second, GOOD)));
        check("the salt is different", true, !saltOf(first).equals(saltOf(second)));
        check("the iv is different", true, !ivOf(first).equals(ivOf(second)));
    }

    // --------------------------------------------------------------------- refusal

    private static void wrongPassphraseRefused() {
        String token = encrypt("Ada Lovelace", "ada@example.com", GOOD);
        String message = refusalMessage(() -> PiiCrypto.decrypt(token, chars("wrong horse battery staple")));
        check("wrong passphrase is refused", true, message != null);
        check("wrong passphrase mentions the passphrase", true, message != null && message.contains("passphrase"));
        check("the wrong passphrase is not echoed back", false,
                message != null && message.contains("horse battery staple"));
    }

    private static void tamperingRefused() {
        String token = encrypt("Ada Lovelace", "ada@example.com", GOOD);
        byte[] container = Base64.getDecoder().decode(token);
        int ciphertextStart = 1 + PiiCrypto.SALT_LENGTH_BYTES + PiiCrypto.IV_LENGTH_BYTES;

        byte[] flippedCiphertext = container.clone();
        flippedCiphertext[ciphertextStart] ^= 0x01;
        check("a flipped ciphertext bit is refused", true,
                refuses(() -> PiiCrypto.decrypt(encode(flippedCiphertext), GOOD)));

        byte[] flippedTag = container.clone();
        flippedTag[flippedTag.length - 1] ^= 0x08;
        check("a flipped tag bit is refused", true,
                refuses(() -> PiiCrypto.decrypt(encode(flippedTag), GOOD)));

        byte[] flippedSalt = container.clone();
        flippedSalt[3] ^= 0x20;
        check("a flipped salt byte is refused", true,
                refuses(() -> PiiCrypto.decrypt(encode(flippedSalt), GOOD)));

        byte[] flippedIv = container.clone();
        flippedIv[1 + PiiCrypto.SALT_LENGTH_BYTES] ^= 0x40;
        check("a flipped iv byte is refused", true,
                refuses(() -> PiiCrypto.decrypt(encode(flippedIv), GOOD)));

        byte[] truncated = new byte[ciphertextStart + 4];
        System.arraycopy(container, 0, truncated, 0, truncated.length);
        check("a truncated token is refused", true,
                refuses(() -> PiiCrypto.decrypt(encode(truncated), GOOD)));

        byte[] extended = new byte[container.length + 1];
        System.arraycopy(container, 0, extended, 0, container.length);
        check("an extra trailing byte is refused", true,
                refuses(() -> PiiCrypto.decrypt(encode(extended), GOOD)));

        byte[] wrongVersion = container.clone();
        wrongVersion[0] = 7;
        String message = refusalMessage(() -> PiiCrypto.decrypt(encode(wrongVersion), GOOD));
        check("an unknown format version is refused", true, message != null);
        check("an unknown format version says so", true,
                message != null && message.toLowerCase().contains("version"));
    }

    private static void malformedTokensRefused() {
        check("null token is refused", true, refuses(() -> PiiCrypto.decrypt(null, GOOD)));
        check("empty token is refused", true, refuses(() -> PiiCrypto.decrypt("", GOOD), "empty"));
        check("whitespace token is refused", true, refuses(() -> PiiCrypto.decrypt("   \t ", GOOD), "empty"));
        check("non-Base64 token is refused", true,
                refuses(() -> PiiCrypto.decrypt("notavalidtoken!!", GOOD), "Base64"));
        // The MIME decoder would throw the '-' and '_' away and decode this to
        // bytes, so the strict decoder's refusal is the thing to assert on.
        check("Base64url alphabet is refused", true, refuses(() -> PiiCrypto.decrypt("YWJj-_ZA", GOOD), "Base64"));
        check("too-short decoded token is refused", true,
                refuses(() -> PiiCrypto.decrypt(encode(new byte[10]), GOOD), "too short"));
        check("two-line token is refused", true,
                refuses(() -> PiiCrypto.decrypt("YWJj\nZA==", GOOD), "single unbroken line"));
        check("null passphrase is refused", true, refuses(() -> PiiCrypto.decrypt("YWJjZA==", null), "passphrase"));

        // Padding is not produced by encrypt() but must still be readable, so that a
        // token copied out of a tool which re-pads it keeps working.
        String token = encrypt("Ada Lovelace", "ada@example.com", GOOD);
        String repadded = Base64.getEncoder().encodeToString(Base64.getDecoder().decode(token));
        check("a re-padded token still decrypts", "ada@example.com", decrypt(repadded, GOOD).email());
        check("a token with surrounding blanks still decrypts", "Ada Lovelace",
                decrypt("  " + token + "  ", GOOD).name());
    }

    private static void tokenIsBase64AndLeaksNothing() {
        String name = "Ada Lovelace";
        String email = "ada@example.com";
        String token = encrypt(name, email, GOOD);

        // Sanity first, so the absence checks below cannot pass vacuously: the
        // plaintext really does carry both fields once you can open the token.
        PiiRecord back = decrypt(token, GOOD);
        check("the decrypted payload really contains the name", true, back.name().contains("Ada Lovelace"));
        check("the decrypted payload really contains the email", true, back.email().contains(email));
        check("token is not empty", true, !token.isEmpty());
        check("token is a single line", false, token.contains("\n") || token.contains("\r"));
        check("token has no padding characters", false, token.contains("="));
        check("token is valid Base64", true, Base64.getDecoder().decode(token).length > 0);
        check("token does not contain the email", false, token.contains(email));
        check("token does not contain Lovelace", false, token.toLowerCase().contains("lovelace"));
        String decoded = new String(Base64.getDecoder().decode(token), StandardCharsets.ISO_8859_1);
        check("decoded token does not contain the email", false, decoded.contains(email));
        check("decoded token does not contain the name", false, decoded.contains("Lovelace"));
        check("token length matches the documented framing",
                1 + PiiCrypto.SALT_LENGTH_BYTES + PiiCrypto.IV_LENGTH_BYTES + 5 + email.length() + name.length() + 16,
                Base64.getDecoder().decode(token).length);
    }

    // ------------------------------------------------------------------ validation

    private static void nameValidation() {
        check("null name refused", true, refuses(() -> PiiCrypto.encrypt(null, "a@b.co", GOOD), "name"));
        check("empty name refused", true, refuses(() -> PiiCrypto.encrypt("", "a@b.co", GOOD), "name"));
        check("blank name refused", true, refuses(() -> PiiCrypto.encrypt("   ", "a@b.co", GOOD), "empty"));
        check("newline in name refused", true,
                refuses(() -> PiiCrypto.encrypt("Ada\nLovelace", "a@b.co", GOOD), "control character"));
        check("tab in name refused", true,
                refuses(() -> PiiCrypto.encrypt("Ada\tLovelace", "a@b.co", GOOD), "control character"));
        check("NUL in name refused", true,
                refuses(() -> PiiCrypto.encrypt("Ada" + (char) 0 + "x", "a@b.co", GOOD), "control character"));
        check("delete char in name refused", true,
                refuses(() -> PiiCrypto.encrypt("Ada" + (char) 0x7F, "a@b.co", GOOD), "control character"));
        check("name with an @ is fine", true, accepts(() -> PiiCrypto.encrypt("a@b", "c@d.co", GOOD)));
        check("lone high surrogate in name refused", true,
                refuses(() -> PiiCrypto.encrypt("Ada" + (char) 0xD835, "a@b.co", GOOD), "multi-plane"));
        check("lone low surrogate in name refused", true,
                refuses(() -> PiiCrypto.encrypt("Ada" + (char) 0xDC9C, "a@b.co", GOOD), "multi-plane"));
        check("paired surrogate in name survives the round trip", true,
                roundTrips("Ada " + (char) 0xD835 + (char) 0xDC9C, "a@b.co"));
    }

    /** Encrypts and decrypts in one go and reports whether the value came back unchanged. */
    private static boolean roundTrips(String name, String email) {
        try {
            derivations += 2;
            PiiRecord back = PiiCrypto.decrypt(PiiCrypto.encrypt(name, email, GOOD), GOOD);
            return name.equals(back.name()) && email.equals(back.email());
        } catch (PiiCrypto.PiiCryptoException e) {
            return false;
        }
    }

    private static void emailValidation() {
        String[] accepted = {
                "a@b.co",
                "ada@example.com",
                "ADA@EXAMPLE.COM",
                "first.last+tag@sub.example.co.uk",
                "u!#$%&'*-/=?^_`{|}~z@example.com",
                "digits123@ex-ample.com",
                "" + (char) 0xE9 + "@example.com",
                "a@" + (char) 0xE9 + "xample.com",
                "x" + (char) 0xD835 + (char) 0xDC9C + "@b.co",
        };
        for (String email : accepted) {
            check("accepted email: " + shorten(email), true, accepts(() -> PiiCrypto.encrypt("N", email, GOOD)));
        }

        Object[][] rejected = {
                { null, "missing" },
                { "", "must contain an '@'" },
                { "plainaddress", "must contain an '@'" },
                { "a@b@c.com", "exactly one '@'" },
                { "@example.com", "before the '@'" },
                { "a@", "after the '@'" },
                { ".a@b.co", "badly placed" },
                { "a.@b.co", "badly placed" },
                { "a..b@b.co", "badly placed" },
                { "a b@c.com", "plain addresses" },
                { "a(b)@c.com", "plain addresses" },
                { "a\"b\"@c.com", "plain addresses" },
                { "a@b_c.com", "host names" },
                { "a@b..c.com", "host name" },
                { "a@b.", "host name" },
                { "a@.b.com", "host name" },
                { "a@-b.com", "host name" },
                { "a@b-.com", "host name" },
                { "a@bcom", "host name" },
                { "a@b,c.com", "host names" },
                { "a@b c.com", "host names" },
                { "a@b.co\n", "control character" },
                { "a@b.co" + (char) 0x7F, "control character" },
                { "u@" + "d".repeat(251) + ".com", "longer than" },
                { "a@" + (char) 0xD835 + "x.com", "multi-plane" },
                { "" + (char) 0xDC9C + "@b.co", "multi-plane" },
        };
        for (Object[] pair : rejected) {
            String email = (String) pair[0];
            String needle = (String) pair[1];
            if (email == null) {
                check("rejected email (null): " + needle, true,
                        refuses(() -> PiiCrypto.encrypt("N", null, GOOD), needle));
            } else {
                check("rejected email (" + needle + "): " + shorten(email), true,
                        refuses(() -> PiiCrypto.encrypt("N", email, GOOD), needle));
            }
        }
    }

    private static void passphraseValidation() {
        String token = encrypt("N", "a@b.co", GOOD);

        check("null passphrase refused on encrypt", true,
                refuses(() -> PiiCrypto.encrypt("N", "a@b.co", null), "passphrase"));
        check("empty passphrase refused on encrypt", true,
                refuses(() -> PiiCrypto.encrypt("N", "a@b.co", new char[0]), "passphrase"));
        check("empty passphrase refused on decrypt", true,
                refuses(() -> PiiCrypto.decrypt(token, new char[0]), "passphrase"));
        check("whitespace-only passphrase refused", true,
                refuses(() -> PiiCrypto.encrypt("N", "a@b.co", chars("     \t ")), "whitespace"));
        check("trailing NUL in passphrase refused", true,
                refuses(() -> PiiCrypto.encrypt("N", "a@b.co", chars("abcdefghijkl" + (char) 0)), "NUL"));
        check("leading NUL in passphrase refused", true,
                refuses(() -> PiiCrypto.decrypt(token, chars((char) 0 + "abcdefghijkl")), "NUL"));
        check("unpaired high surrogate refused", true,
                refuses(() -> PiiCrypto.encrypt("N", "a@b.co", chars("abcdefghijk" + (char) 0xD800)),
                        "supplementary"));
        check("unpaired low surrogate refused", true,
                refuses(() -> PiiCrypto.encrypt("N", "a@b.co", chars("abcdefghijk" + (char) 0xDE00)),
                        "supplementary"));
        check("paired surrogate passphrase is accepted", true,
                accepts(() -> PiiCrypto.encrypt("N", "a@b.co",
                        chars("abcdefghijk" + (char) 0xD835 + (char) 0xDC9C))));
        check("over-long passphrase refused", true,
                refuses(() -> PiiCrypto.encrypt("N", "a@b.co",
                        chars("p".repeat(PiiCrypto.PASSPHRASE_MAX_CHARS + 1))), "longer than"));
        check("short passphrase is accepted", true, accepts(() -> PiiCrypto.encrypt("N", "a@b.co", chars("p"))));

        // PBEKeySpec stops at a NUL and maps an unpaired surrogate to '?', so a
        // passphrase carrying either would silently share a key with a shorter one.
        check("NUL-bearing passphrase can never open a token made from its trimmed twin", true,
                refuses(() -> PiiCrypto.decrypt(token, chars("abcdefghijk" + (char) 0)), "NUL"));
        check("the trimmed twin still works on its own", true,
                accepts(() -> PiiCrypto.encrypt("N", "a@b.co", chars("abcdefghijk"))));
    }

    private static void recordToStringIsRedacted() {
        PiiRecord record = new PiiRecord("Ada Lovelace", "ada@example.com");
        String printed = record.toString();
        check("toString is not empty", true, !printed.isEmpty());
        check("toString hides the name", false, printed.contains("Lovelace"));
        check("toString hides the email", false, printed.contains("ada@example.com"));
        check("toString still identifies the type", true, printed.contains("PiiRecord"));
        check("equality works by value", true, record.equals(new PiiRecord("Ada Lovelace", "ada@example.com")));
        check("inequality works", false, record.equals(new PiiRecord("Ada Lovelace", "other@example.com")));
        boolean nullNameRejected;
        try {
            new PiiRecord(null, "a@b.co");
            nullNameRejected = false;
        } catch (NullPointerException expected) {
            nullNameRejected = true;
        }
        check("a null name is refused by the record", true, nullNameRejected);
    }

    /**
     * The key must come from (passphrase, salt) and nothing else. A token re-opened
     * twice must agree, and the same token must not open under a different
     * passphrase -- including one that differs by a single last character.
     */
    private static void keyDerivationFollowsTheToken() {
        String token = encrypt("Ada Lovelace", "ada@example.com", GOOD);
        byte[] container = Base64.getDecoder().decode(token);
        byte[] salt = Arrays.copyOfRange(container, 1, 1 + PiiCrypto.SALT_LENGTH_BYTES);
        check("the token carries a full salt", PiiCrypto.SALT_LENGTH_BYTES, salt.length);
        check("a token re-opened twice gives the same answer", true,
                decrypt(token, GOOD).equals(decrypt(token, GOOD)));
        check("a token does not open under a one-character-different passphrase", true,
                refuses(() -> PiiCrypto.decrypt(token, chars("correct horse battery staplb"))));
        check("a token does not open under a longer passphrase", true,
                refuses(() -> PiiCrypto.decrypt(token, chars("correct horse battery staple!"))));
        check("a token does not open under a shorter passphrase", true,
                refuses(() -> PiiCrypto.decrypt(token, chars("correct horse battery stap"))));
    }

    /**
     * Proves, straight from the JDK and with the guards switched off, that
     * PBEKeySpec is not a one-to-one map from characters to keys. The NUL and
     * surrogate refusals in {@link PiiCrypto} exist because of what this finds;
     * if the JDK ever stops behaving this way the assertions here say so.
     */
    private static void passphraseEquivalencesAreProven() {
        byte[] salt = new byte[PiiCrypto.SALT_LENGTH_BYTES];
        new Random(7L).nextBytes(salt);
        byte[] plain = rawKey("abcdefghijk", salt);
        byte[] withTrailingNul = rawKey("abcdefghijk" + (char) 0, salt);
        byte[] withQuestionMark = rawKey("abcdefghijk?", salt);
        byte[] withUnpairedHighSurrogate = rawKey("abcdefghijk" + (char) 0xD800, salt);
        byte[] withUnpairedLowSurrogate = rawKey("abcdefghijk" + (char) 0xDE00, salt);
        byte[] different = rawKey("abcdefghil", salt);

        check("a trailing NUL is dropped by the JDK key factory", true, Arrays.equals(plain, withTrailingNul));
        check("a plain passphrase differs from one ending in '?'", false, Arrays.equals(plain, withQuestionMark));
        check("an unpaired high surrogate collapses to '?' in the JDK key factory", true,
                Arrays.equals(withQuestionMark, withUnpairedHighSurrogate));
        check("an unpaired low surrogate collapses to '?' in the JDK key factory", true,
                Arrays.equals(withQuestionMark, withUnpairedLowSurrogate));
        check("two genuinely different passphrases get different keys", false, Arrays.equals(plain, different));

        // Same finding for the payload: half a supplementary character does not
        // survive UTF-8, which is why the name and email guards refuse it.
        byte[] halfEncoded = ("" + (char) 0xD835 + "x").getBytes(StandardCharsets.UTF_8);
        check("a lone high surrogate becomes '?' under utf-8", true,
                new String(halfEncoded, StandardCharsets.UTF_8).startsWith("?"));
        byte[] wholeEncoded = ("" + (char) 0xD835 + (char) 0xDC9C).getBytes(StandardCharsets.UTF_8);
        check("a paired surrogate survives utf-8 as four bytes", 4, wholeEncoded.length);
    }

    private static byte[] rawKey(String passphrase, byte[] salt) {
        try {
            derivations++;
            PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt,
                    PiiCrypto.PBKDF2_ITERATIONS, PiiCrypto.KEY_LENGTH_BITS);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new AssertionError("the JDK refused to derive a key: " + e, e);
        }
    }

    /**
     * Builds a token around an arbitrary payload, using the framing the class
     * documents. This is the only way to reach the checks on the decrypt side,
     * which exist for tokens written by something other than {@code encrypt}, and
     * it doubles as a direct assertion that the published framing is the real one.
     */
    private static String tokenForPayload(byte[] payload) {
        try {
            derivations++;
            byte[] salt = new byte[PiiCrypto.SALT_LENGTH_BYTES];
            new Random(3L).nextBytes(salt);
            byte[] iv = new byte[PiiCrypto.IV_LENGTH_BYTES];
            new Random(4L).nextBytes(iv);
            PBEKeySpec spec = new PBEKeySpec(GOOD, salt, PiiCrypto.PBKDF2_ITERATIONS, PiiCrypto.KEY_LENGTH_BITS);
            byte[] keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(PiiCrypto.TAG_LENGTH_BITS, iv));
            byte[] ciphertext = cipher.doFinal(payload);
            ByteBuffer container = ByteBuffer.allocate(1 + salt.length + iv.length + ciphertext.length);
            container.put(PiiCrypto.TOKEN_VERSION);
            container.put(salt);
            container.put(iv);
            container.put(ciphertext);
            return encode(container.array());
        } catch (Exception e) {
            throw new AssertionError("could not build a token: " + e, e);
        }
    }

    private static byte[] payloadWith(String name, String email) {
        return rawPayload(name.getBytes(StandardCharsets.UTF_8), email.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Raw bytes rather than a String, because {@code getBytes(UTF_8)} replaces an
     * unpaired surrogate with '?' and the case would never reach the decoder.
     */
    private static byte[] rawPayload(byte[] nameBytes, byte[] emailBytes) {
        ByteBuffer buffer = ByteBuffer.allocate(1 + 2 + nameBytes.length + 2 + emailBytes.length);
        buffer.put(PiiCrypto.PAYLOAD_VERSION);
        buffer.putShort((short) nameBytes.length);
        buffer.put(nameBytes);
        buffer.putShort((short) emailBytes.length);
        buffer.put(emailBytes);
        return buffer.array();
    }

    /** The guards on the decrypt side must fire on bad payloads and stay quiet on a good one. */
    private static void decryptSideRejectsMalformedPayloads() {
        PiiRecord handBuilt = decrypt(tokenForPayload(payloadWith("Ada Lovelace", "ada@example.com")), GOOD);
        check("a hand-built payload opens correctly", "Ada Lovelace", handBuilt.name());
        check("the published framing is the real one", true, handBuilt.email().equals("ada@example.com"));

        check("a NUL byte in the decrypted name is refused", true,
                refuses(() -> PiiCrypto.decrypt(tokenForPayload(payloadWith("Ada" + (char) 0, GOOD2)), GOOD), "NUL"));
        check("trailing bytes after the email are refused", true, refuses(() -> PiiCrypto.decrypt(
                tokenForPayload(concat(payloadWith("Ada", GOOD2), new byte[] { 9 })), GOOD), "trailing bytes"));
        // A truncated multi-byte sequence. new String(bytes, UTF_8) would turn this
        // into '?' silently; the strict decoder used by decrypt must refuse it.
        check("bytes that are not valid utf-8 are refused", true,
                refuses(() -> PiiCrypto.decrypt(
                        tokenForPayload(rawPayload(new byte[] { (byte) 0xC3 },
                                GOOD2.getBytes(StandardCharsets.UTF_8))), GOOD), "not valid text"));
        check("a lenient decoder really does hide those bytes", true,
                new String(new byte[] { (byte) 0xC3 }, StandardCharsets.UTF_8).length() == 1);

        // The UTF-8 decoder turns a lone surrogate into the replacement character,
        // so that is what has to be put in the payload to reach the guard.
        String loneSurrogateAfterDecoding = new String(new byte[] { (byte) 0xEF, (byte) 0xBF, (byte) 0xBD },
                StandardCharsets.UTF_8);
        check("the utf-8 decoder hands back a replacement character for a lone surrogate", true,
                loneSurrogateAfterDecoding.length() == 1 && loneSurrogateAfterDecoding.charAt(0) == (char) 0xFFFD);
        check("a name already mangled to a replacement character is refused", true,
                refuses(() -> PiiCrypto.decrypt(
                        tokenForPayload(rawPayload(new byte[] { (byte) 0xEF, (byte) 0xBF, (byte) 0xBD },
                                GOOD2.getBytes(StandardCharsets.UTF_8))), GOOD), "not valid text"));

        byte[] wrongLayout = payloadWith("Ada", GOOD2);
        wrongLayout[0] = 2;
        check("an unsupported payload layout is refused", true,
                refuses(() -> PiiCrypto.decrypt(tokenForPayload(wrongLayout), GOOD), "unsupported layout"));

        // Valid in every other respect, with only the name left empty. An earlier
        // version of this fixture was malformed after the name too, so a missing
        // empty-name guard still failed the email length check and the test passed
        // for the wrong reason. Everything after the length must be sound.
        ByteBuffer emptyName = ByteBuffer.allocate(7);
        emptyName.put(PiiCrypto.PAYLOAD_VERSION).putShort((short) 0).putShort((short) 2)
                .put(new byte[] { 'a', 'b' });
        check("a zero-length name is refused", true,
                refuses(() -> PiiCrypto.decrypt(tokenForPayload(emptyName.array()), GOOD), "corrupt length"));

        // A name length that runs past the end of the payload, padded past the
        // shortest legal payload so the length guard is what fires.
        ByteBuffer shortName = ByteBuffer.allocate(7);
        shortName.put(PiiCrypto.PAYLOAD_VERSION).putShort((short) 99).put(new byte[] { 1, 2, 3, 4 });
        check("a name length past the end is refused", true,
                refuses(() -> PiiCrypto.decrypt(tokenForPayload(shortName.array()), GOOD), "corrupt length"));
        check("an empty payload is refused", true,
                refuses(() -> PiiCrypto.decrypt(tokenForPayload(new byte[0]), GOOD), "too short"));
        check("a payload cut short of the two lengths is refused", true,
                refuses(() -> PiiCrypto.decrypt(tokenForPayload(new byte[] { PiiCrypto.PAYLOAD_VERSION, 0, 1 }), GOOD),
                        "too short"));
    }

    private static byte[] concat(byte[] head, byte[] tail) {
        byte[] joined = new byte[head.length + tail.length];
        System.arraycopy(head, 0, joined, 0, head.length);
        System.arraycopy(tail, 0, joined, head.length, tail.length);
        return joined;
    }

    /**
     * The security of the whole thing rests on a handful of numbers. They are stated
     * in README.md, so they are asserted here rather than left as comments: an AES
     * key is only 256 bits, a GCM tag is only 128 bits, and the key-stretching cost
     * is only there if the iteration count really is paid.
     */
    private static void securityParametersAreTheDocumentedOnes() {
        check("AES key length is 256 bits", 256, PiiCrypto.KEY_LENGTH_BITS);
        check("GCM tag length is 128 bits", 128, PiiCrypto.TAG_LENGTH_BITS);
        check("the salt is 16 bytes", 16, PiiCrypto.SALT_LENGTH_BYTES);
        check("the iv is 12 bytes, which GCM needs", 12, PiiCrypto.IV_LENGTH_BYTES);
        check("PBKDF2 runs at least 200000 rounds", true, PiiCrypto.PBKDF2_ITERATIONS >= 200_000);

        // And the cost is measured, not just declared: deleting the work is the
        // easiest way to quietly make an offline crack of a stored token feasible.
        long startedAt = System.nanoTime();
        encrypt("Ada Lovelace", GOOD2, GOOD);
        long elapsedMs = (System.nanoTime() - startedAt) / 1_000_000L;
        check("one key derivation takes at least 50 ms of real stretching", true, elapsedMs >= 50);
    }

    // --------------------------------------------------------------------- helpers

    private interface Action {
        void run() throws Exception;
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }

    private static String randomString(Random random, String alphabet, int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return builder.toString();
    }

    private static String saltOf(String token) {
        byte[] container = Base64.getDecoder().decode(token);
        return Base64.getEncoder().encodeToString(
                Arrays.copyOfRange(container, 1, 1 + PiiCrypto.SALT_LENGTH_BYTES));
    }

    private static String ivOf(String token) {
        byte[] container = Base64.getDecoder().decode(token);
        return Base64.getEncoder().encodeToString(Arrays.copyOfRange(container,
                1 + PiiCrypto.SALT_LENGTH_BYTES, 1 + PiiCrypto.SALT_LENGTH_BYTES + PiiCrypto.IV_LENGTH_BYTES));
    }

    private static String encode(byte[] container) {
        return Base64.getEncoder().withoutPadding().encodeToString(container);
    }

    private static String encrypt(String name, String email, char[] passphrase) {
        try {
            derivations++;
            return PiiCrypto.encrypt(name, email, passphrase);
        } catch (PiiCrypto.PiiCryptoException e) {
            throw new AssertionError("encrypt(" + shorten(name) + ", " + email + ") was refused: " + e.getMessage(),
                    e);
        }
    }

    private static PiiRecord decrypt(String token, char[] passphrase) {
        try {
            derivations++;
            return PiiCrypto.decrypt(token, passphrase);
        } catch (PiiCrypto.PiiCryptoException e) {
            throw new AssertionError("decrypt() was refused: " + e.getMessage(), e);
        }
    }

    private static boolean accepts(Action action) {
        try {
            action.run();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean refuses(Action action) {
        return refusalMessage(action) != null;
    }

    /** Refusal is not enough: the message has to name the reason, or a wrong guard passes. */
    private static boolean refuses(Action action, String needleInMessage) {
        String message = refusalMessage(action);
        if (message == null) {
            return false;
        }
        if (!message.contains(needleInMessage)) {
            record("the refusal should say '" + needleInMessage + "', it said: " + message);
            return false;
        }
        return true;
    }

    /** {@code null} means the action succeeded, which is a failure for the caller. */
    private static String refusalMessage(Action action) {
        try {
            action.run();
            record("expected a refusal but the call succeeded");
            return null;
        } catch (PiiCrypto.PiiCryptoException e) {
            String message = e.getMessage();
            if (message == null || message.isBlank()) {
                record("a refusal had no message: " + e.getClass().getSimpleName());
                return " ";
            }
            return message;
        } catch (Exception e) {
            record("expected a PiiCryptoException but got " + e.getClass().getName() + ": " + e.getMessage());
            return null;
        }
    }

    private static void record(String what) {
        FAILURES.add(what);
    }

    private static void check(String what, Object expected, Object actual) {
        checks++;
        boolean same = expected == null ? actual == null : expected.equals(actual);
        if (!same) {
            record(what + ": expected " + expected + " but was " + actual);
        }
    }

    private static String shorten(String value) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length() && builder.length() < 36; i++) {
            char c = value.charAt(i);
            builder.append(c < 0x20 || c == 0x7F ? '?' : c);
        }
        return value.length() > 36 ? builder + "..." : builder.toString();
    }

    private PiiCryptoTest() {
    }
}
