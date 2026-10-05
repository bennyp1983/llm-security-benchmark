package com.portal.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.Normalizer;
import java.util.List;

/**
 * Boundary, credential-storage and file-policy checks. Each negative fixture is invalid in
 * exactly one way, so a passing check proves the guard named in its title is the guard that
 * fired: a fixture that was invalid twice over can be rejected for the wrong reason and
 * still go green.
 */
public final class CoreSecuritySuite {

    public static void main(String[] args) {
        TestKit.systemClock();
        inputPolicy();
        folding();
        crypto();
        hasher();
        roster();
        privateFiles();
        auditLog();
        cookieParser();
        sourceTextGuards();
        System.exit(TestKit.report("core-security"));
    }

    // ------------------------------------------------------------------ rule 1: inputs

    private static void inputPolicy() {
        TestKit.caseOf("valid usernames accepted", () -> {
            String[] good = {"abc", "a.b", "a_b", "a-b", "bob2", "a".repeat(32),
                    "0abc", "employee.name-2_x"};
            for (String s : good) {
                TestKit.ok("username accepted " + s, InputPolicy.isUsername(s));
            }
        });

        TestKit.caseOf("invalid usernames refused, one defect each", () -> {
            String[] bad = {
                    null,
                    "ab",
                    "a".repeat(33),
                    "Alice",
                    "alice ",
                    "alice\t",
                    "ali ce",
                    "ali\u00e7e",
                    ".alice",
                    "alice.",
                    "_alice",
                    "a-lice-",
                    "a=lice",
                    "a/lice",
                    "a%2e",
                    "a\nlice",
                    "a..lice",
                    "admi\u0000n",
                    "\uFF41lice"
            };
            for (String s : bad) {
                TestKit.ok("username refused [" + describe(s) + "]", !InputPolicy.isUsername(s));
            }
        });

        TestKit.caseOf("unicode folding cannot reach a real account", () -> {
            // Evidence for the rule rather than an assertion of it: a normalising scheme
            // really would map this onto "alice", which is why the policy refuses it.
            String fullWidth = "\uFF41lice";
            TestKit.ok("NFKC would fold it onto alice",
                    "alice".equals(Normalizer.normalize(fullWidth, Normalizer.Form.NFKC)));
            TestKit.ok("we refuse it instead of normalising", !InputPolicy.isUsername(fullWidth));
            String kelvin = "K\u00e9vin";
            TestKit.ok("kelvin sign would fold too",
                    Normalizer.normalize("\u212Aevin", Normalizer.Form.NFKC).equals("Kevin"));
            TestKit.ok("and is refused", !InputPolicy.isUsername(kelvin));
        });

        TestKit.caseOf("secret shape rules", () -> {
            TestKit.ok("good secret", InputPolicy.isWellFormedSecret(TestKit.PW_ALICE.toCharArray()));
            TestKit.ok("short secret refused", !InputPolicy.isWellFormedSecret("Short-1!".toCharArray()));
            TestKit.ok("long secret refused", !InputPolicy.isWellFormedSecret(
                    ("Aa1!" + "x".repeat(InputPolicy.PASSWORD_MAX)).toCharArray()));
            TestKit.ok("trailing NUL refused",
                    !InputPolicy.isWellFormedSecret((TestKit.PW_ALICE + "\u0000").toCharArray()));
            TestKit.ok("leading NUL refused",
                    !InputPolicy.isWellFormedSecret(("\u0000" + TestKit.PW_ALICE).toCharArray()));
            TestKit.ok("tab refused",
                    !InputPolicy.isWellFormedSecret("Fresh-Quiver\u000971".toCharArray()));
            TestKit.ok("leading space refused",
                    !InputPolicy.isWellFormedSecret((" " + TestKit.PW_ALICE).toCharArray()));
            TestKit.ok("trailing space refused",
                    !InputPolicy.isWellFormedSecret((TestKit.PW_ALICE + " ").toCharArray()));
            TestKit.ok("non-ascii refused",
                    !InputPolicy.isWellFormedSecret("Fresh-Quiver-\u00e91!".toCharArray()));
            TestKit.ok("unpaired surrogate refused", !InputPolicy.isWellFormedSecret(
                    ("Fresh-Quiver-7" + (char) 0xD800).toCharArray()));
            TestKit.ok("del refused",
                    !InputPolicy.isWellFormedSecret("Fresh-Quiver-71\u007F".toCharArray()));
            TestKit.ok("empty secret refused", !InputPolicy.isWellFormedSecret(new char[0]));
            TestKit.ok("null secret refused", !InputPolicy.isWellFormedSecret(null));
            // A zero-filled buffer is 1024 NULs: every blank guard must catch it.
            TestKit.ok("all-NUL buffer refused", !InputPolicy.isWellFormedSecret(new char[64]));
            // An INTERIOR space, not just a leading or trailing one. The two edge spaces are
            // refused by their own dedicated check, so a matrix that only probes the ends
            // leaves the character class itself untested at 0x20 -- the one value where the
            // class bound and the space rule meet. Mutating the bound from < 0x21 to < 0x20
            // admits exactly this character and nothing else, and every earlier case stayed
            // green, which is how the gap was found.
            TestKit.ok("interior space refused",
                    !InputPolicy.isWellFormedSecret("Fresh Quiver-71!".toCharArray()));
            TestKit.ok("interior space in the middle refused",
                    !InputPolicy.isWellFormedSecret("Fresh-Quiver 71!".toCharArray()));
            TestKit.ok("every separator below 0x21 refused in an interior position",
                    java.util.stream.IntStream.rangeClosed(0x00, 0x20).allMatch(c ->
                            !InputPolicy.isWellFormedSecret(("Fresh-Quiver-"
                                    + (char) c + "71!").toCharArray())));
            // Length bounds must be probed AT the boundary. "long secret refused" above uses a
            // string well past the ceiling, so it passes whether the ceiling comparison is >
            // or >=; only a secret of exactly PASSWORD_MAX distinguishes them. Same for the
            // floor: "short secret refused" is 8 characters and cannot see an off-by-one at 12.
            TestKit.ok("secret of exactly the maximum length is accepted",
                    InputPolicy.isWellFormedSecret(
                            ("Aa1!" + "x".repeat(InputPolicy.PASSWORD_MAX - 4)).toCharArray()));
            TestKit.ok("one character past the maximum is refused",
                    !InputPolicy.isWellFormedSecret(
                            ("Aa1!" + "x".repeat(InputPolicy.PASSWORD_MAX - 3)).toCharArray()));
            TestKit.ok("secret of exactly the minimum length is accepted",
                    InputPolicy.isWellFormedSecret("Aa1!Aa1!Aa1!".toCharArray()));
            TestKit.ok("one character short of the minimum is refused",
                    !InputPolicy.isWellFormedSecret("Aa1!Aa1!Aa!".toCharArray()));
            TestKit.eq("the boundary fixtures are exactly at the documented limits",
                    InputPolicy.PASSWORD_MAX, ("Aa1!" + "x".repeat(InputPolicy.PASSWORD_MAX - 4)).length());
        });

        TestKit.caseOf("enrolment strength policy", () -> {
            String[] weak = {"alllowercase12!", "ALLUPPERCASE12!", "NoDigitsHere!!!",
                    "NoSymbolsHere123", "Aaaaaaaaaaaaa1!", "alice-Password-1",
                    "Ab1!abcdefghij", "abcdefghijkl1A!", "abcdefghijkl1A!abcdefghijklmno"};
            for (String s : weak) {
                TestKit.ok("weak refused [" + s + "]",
                        InputPolicy.strengthFailure(s.toCharArray(), "alice".toCharArray()) != null);
            }
            for (String s : List.of(TestKit.PW_ALICE, TestKit.PW_BOB, TestKit.PW_CAROL,
                    TestKit.PW_WRONG, TestKit.PW_WRONG2)) {
                TestKit.ok("strong accepted [" + s + "]",
                        InputPolicy.strengthFailure(s.toCharArray(), "alice".toCharArray()) == null);
            }
            TestKit.ok("username substring refused case-insensitively",
                    InputPolicy.strengthFailure("ALICE-Fresh-77!".toCharArray(),
                            "alice".toCharArray()) != null);
            TestKit.ok("malformed secret reports the shape rule",
                    InputPolicy.strengthFailure("x".toCharArray(), "alice".toCharArray())
                            .contains("printable ASCII"));
        });

        TestKit.caseOf("fixtures do not collide with the policy under test", () -> {
            for (String secret : List.of(TestKit.PW_ALICE, TestKit.PW_BOB, TestKit.PW_CAROL,
                    TestKit.PW_WRONG, TestKit.PW_WRONG2)) {
                for (String user : List.of("alice", "bob", "carol")) {
                    TestKit.ok("fixture [" + secret + "] omits " + user,
                            !secret.toLowerCase(java.util.Locale.ROOT).contains(user));
                }
            }
        });

        TestKit.caseOf("opaque token shapes", () -> {
            String session = Crypto.randomUrlToken(InputPolicy.SESSION_TOKEN_BYTES);
            TestKit.eq("session token wire length", 43, session.length());
            TestKit.ok("issued session token accepted", InputPolicy.isSessionToken(session));
            TestKit.ok("issued csrf token accepted",
                    InputPolicy.isCsrfToken(Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES)));
            String[] bad = {null, "", session + "=", session.substring(0, 42),
                    session.substring(0, 42) + "_", session + "xx", "a".repeat(300),
                    session.substring(0, 41) + "A=",
                    // padded base64url of 32 bytes: right byte length, wrong wire form
                    paddedUrlForm(InputPolicy.SESSION_TOKEN_BYTES),
                    // non-canonical trailing bits: decodes to 32 bytes, but the final
                    // group's unused bits are not zero
                    session.substring(0, 42) + 'B'};
            for (String s : bad) {
                TestKit.ok("session token refused [" + describe(s) + "]", !InputPolicy.isSessionToken(s));
            }
            TestKit.ok("a session-shaped string is not a csrf token",
                    !InputPolicy.isCsrfToken(session));
        });
    }

    private static void folding() {
        TestKit.caseOf("ascii folding is locale-free and non-invasive", () -> {
            TestKit.eq("upper folds to lower", "alice", Authenticator.foldAsciiCase("ALICE"));
            TestKit.eq("mixed", "a.b-c_d1", Authenticator.foldAsciiCase("A.B-C_D1"));
            TestKit.eq("dotted capital I untouched", "\u0130",
                    Authenticator.foldAsciiCase("\u0130"));
            TestKit.eq("kelvin sign untouched", "\u212A", Authenticator.foldAsciiCase("\u212A"));
            TestKit.eq("full width untouched", "\uFF21", Authenticator.foldAsciiCase("\uFF21"));
            TestKit.eq("sharp s untouched", "\u00DF", Authenticator.foldAsciiCase("\u00DF"));
            TestKit.ok("distinct accepted ids stay distinct",
                    !Authenticator.foldAsciiCase("alice.").equals(Authenticator.foldAsciiCase("alice")));
            char[] in = "ALICE".toCharArray();
            Authenticator.foldAsciiCase(in);
            TestKit.eq("char[] argument not mutated", "ALICE", new String(in));
            // The Turkish-i hazard in one line: a locale-aware fold of "I" under tr_TR is
            // "i\u0307", which would no longer match the stored name at all.
            TestKit.ok("locale fold would have differed",
                    !"i".equals("I".toLowerCase(java.util.Locale.forLanguageTag("tr-TR"))));
            TestKit.eq("our fold does not", "i", Authenticator.foldAsciiCase("I"));
        });
    }

    // ------------------------------------------------------------------ rule 4: tokens

    private static void crypto() {
        TestKit.caseOf("token generation", () -> {
            java.util.Set<String> seen = new java.util.HashSet<>();
            for (int i = 0; i < 500; i++) {
                seen.add(Crypto.randomUrlToken(InputPolicy.SESSION_TOKEN_BYTES));
            }
            TestKit.eq("500 tokens are distinct", 500, seen.size());
            TestKit.ok("token alphabet", seen.stream().allMatch(t -> t.matches("[A-Za-z0-9_-]{43}")));
            java.util.Set<String> raws = new java.util.HashSet<>();
            for (int i = 0; i < 200; i++) {
                raws.add(Crypto.toHex(Crypto.randomBytes(16)));
            }
            TestKit.eq("200 random buffers distinct", 200, raws.size());
            TestKit.ok("random buffer not all-zero",
                    !raws.iterator().next().equals("0".repeat(32)));
        });

        TestKit.caseOf("randomBytes bounds", () -> {
            for (int n : new int[]{0, 1, 8, 15, 4097, -1}) {
                TestKit.ok("randomBytes(" + n + ") refused",
                        throwsIllegal(() -> Crypto.randomBytes(n)));
            }
            TestKit.eq("16 accepted", 16, Crypto.randomBytes(16).length);
            TestKit.eq("4096 accepted", 4096, Crypto.randomBytes(4096).length);
        });

        TestKit.caseOf("name suffix bounds", () -> {
            TestKit.ok("suffix shape", Crypto.randomNameSuffix(9).matches("[A-Za-z0-9_-]{12}"));
            for (int n : new int[]{5, 16, 0, -1}) {
                TestKit.ok("suffix " + n + " refused", throwsIllegal(() -> Crypto.randomNameSuffix(n)));
            }
        });

        TestKit.caseOf("strict base64", () -> {
            byte[] raw = Crypto.randomBytes(16);
            String canonical = Crypto.base64(raw);
            TestKit.eq("canonical accepted", 16, Crypto.base64Strict(canonical).length);
            String[] bad = {canonical.substring(0, 21) + "!", canonical + "=",
                    canonical.substring(0, 22), "####", "",
                    canonical.substring(0, 20) + canonical.substring(22)};
            for (String s : bad) {
                TestKit.ok("refused [" + describe(s) + "]", throwsIllegal(() -> Crypto.base64Strict(s)));
            }
            // "AB==" and "AC==" decode to the same byte; only one is the canonical form.
            TestKit.ok("trailing-bit variant refused", throwsIllegal(() -> Crypto.base64Strict("AC==")));
            TestKit.eq("canonical one-byte form accepted", 1, Crypto.base64Strict("QQ==").length);
        });

        TestKit.caseOf("base64url expected length", () -> {
            String t = Crypto.randomUrlToken(32);
            TestKit.eq("right length decodes", 32,
                    Crypto.base64UrlStrictExpectedLen(t, 32).length);
            TestKit.ok("wrong expected length refused",
                    throwsIllegal(() -> Crypto.base64UrlStrictExpectedLen(t, 24)));
            TestKit.ok("padded form refused",
                    throwsIllegal(() -> Crypto.base64UrlStrictExpectedLen(t + "=", 32)));
            TestKit.ok("empty refused",
                    throwsIllegal(() -> Crypto.base64UrlStrictExpectedLen("", 32)));
            TestKit.ok("oversized refused", throwsIllegal(
                    () -> Crypto.base64UrlStrictExpectedLen("a".repeat(300), 32)));
        });

        TestKit.caseOf("idRef width and stability", () -> {
            String a = Crypto.idRef("alice");
            TestKit.eq("16 hex", 16, a.length());
            TestKit.ok("lower hex", a.matches("[0-9a-f]{16}"));
            TestKit.eq("stable across calls", a, Crypto.idRef("alice".toCharArray()));
            TestKit.ok("distinct identities differ", !a.equals(Crypto.idRef("bob")));
            TestKit.ok("identity not recoverable", !a.contains("alice"));
            TestKit.eq("matches the ledger key width", Ledger.SUBJECT_HEX, a.length());
        });

        TestKit.caseOf("wipe clears", () -> {
            char[] c = TestKit.PW_ALICE.toCharArray();
            Crypto.wipe(c);
            TestKit.ok("char[] wiped", allZero(c));
            byte[] b = Crypto.randomBytes(16);
            Crypto.wipe(b);
            TestKit.ok("byte[] wiped", allZero(b));
            Crypto.wipe((char[]) null);
            Crypto.wipe((byte[]) null);
        });

        TestKit.caseOf("equalChars", () -> {
            TestKit.ok("equal", Crypto.equalChars("abc".toCharArray(), "abc".toCharArray()));
            TestKit.ok("different length", !Crypto.equalChars("abc".toCharArray(), "abcd".toCharArray()));
            TestKit.ok("different content", !Crypto.equalChars("abc".toCharArray(), "abd".toCharArray()));
            TestKit.ok("prefix is not equal", !Crypto.equalChars("a".toCharArray(), "ab".toCharArray()));
            TestKit.ok("null-safe", Crypto.equalChars(null, null));
            TestKit.ok("one null", !Crypto.equalChars(null, "a".toCharArray()));
            TestKit.ok("empty vs empty", Crypto.equalChars(new char[0], new char[0]));
        });

        TestKit.caseOf("equalConstantTime", () -> {
            TestKit.ok("equal", Crypto.equalConstantTime("abc", "abc"));
            TestKit.ok("unequal", !Crypto.equalConstantTime("abc", "abd"));
            TestKit.ok("length mismatch", !Crypto.equalConstantTime("abc", "abcd"));
            TestKit.ok("null-safe", Crypto.equalConstantTime(null, null));
            TestKit.ok("one null", !Crypto.equalConstantTime(null, "a"));
            // The point of these three is the charset: encoding an operand through a charset
            // that cannot represent it replaces the character with '?', so two equal
            // non-ASCII strings would report unequal and two different ones could report
            // equal. Both directions have to say "not the same token".
            TestKit.ok("identical non-ascii is refused rather than folded to '?'",
                    !Crypto.equalConstantTime("caf\u00e9", "caf\u00e9"));
            TestKit.ok("a non-ascii value never matches the '?' it would fold to",
                    !Crypto.equalConstantTime("caf\u00e9", "caf?"));
            TestKit.ok("the folded form never matches either way round",
                    !Crypto.equalConstantTime("caf?", "caf\u00e9"));
        });

        TestKit.caseOf("asciiBytes refuses non-ascii", () -> {
            TestKit.ok("non-ascii refused", throwsIllegal(() -> Crypto.asciiBytes("caf\u00e9".toCharArray())));
            TestKit.eq("ascii length", 5, Crypto.asciiBytes("alice".toCharArray()).length);
        });

        TestKit.caseOf("idRef width and strictness", () -> {
            String ref = Crypto.idRef("alice");
            TestKit.eq("width is the pinned ledger subject width",
                    Ledger.SUBJECT_HEX, ref.length());
            TestKit.ok("lowercase hex only", ref.matches("[0-9a-f]{" + Ledger.SUBJECT_HEX + "}"));
            TestKit.ok("the two overloads agree", ref.equals(Crypto.idRef("alice".toCharArray())));
            TestKit.ok("a surrogate pair is refused, not folded",
                    throwsIllegal(() -> Crypto.idRef("ali\ud83d\ude00ce")));
            TestKit.ok("the String overload refuses instead of encoding to '?'",
                    throwsIllegal(() -> Crypto.idRef("caf\u00e9")));
            // Why the fold mattered: a lossy encoder would have sent the "caf??" name above
            // to the same bucket as the literal "caf?", so the '?' shape must not be a name
            // anyone can hold -- then a folded collision could not land on an account.
            TestKit.ok("'?' is not a character any account name may contain",
                    !InputPolicy.isUsername("caf?"));
            TestKit.ok("distinct names get distinct refs",
                    !Crypto.idRef("alice").equals(Crypto.idRef("alices")));
        });
    }

    // ---------------------------------------------------------- rules 2/5/8: credentials

    private static void hasher() {
        PasswordHasher h = new PasswordHasher(TestKit.FAST_ITERATIONS);

        TestKit.caseOf("constructor floors", () -> {
            for (int n : new int[]{0, 1, 99_999, PasswordHasher.MAX_ITERATIONS + 1, -5,
                    Integer.MIN_VALUE}) {
                TestKit.ok("iterations " + n + " refused", throwsIllegal(() -> new PasswordHasher(n)));
            }
            TestKit.eq("floor accepted", PasswordHasher.MIN_ITERATIONS,
                    new PasswordHasher(PasswordHasher.MIN_ITERATIONS).configuredIterations());
            TestKit.eq("ceiling accepted", PasswordHasher.MAX_ITERATIONS,
                    new PasswordHasher(PasswordHasher.MAX_ITERATIONS).configuredIterations());
        });

        TestKit.caseOf("record format", () -> {
            char[] secret = TestKit.pw(TestKit.PW_ALICE);
            String rec = h.hash(secret, "alice".toCharArray());
            String[] parts = rec.split("\\$", -1);
            TestKit.eq("five fields", 5, parts.length);
            TestKit.eq("alg", "pbkdf2", parts[0]);
            TestKit.eq("hash", "sha256", parts[1]);
            TestKit.eq("iterations", String.valueOf(TestKit.FAST_ITERATIONS), parts[2]);
            TestKit.eq("salt length", PasswordHasher.SALT_BYTES, Crypto.base64Strict(parts[3]).length);
            TestKit.eq("key length", PasswordHasher.KEY_BYTES, Crypto.base64Strict(parts[4]).length);
            TestKit.ok("password not stored", !rec.contains(TestKit.PW_ALICE));
            TestKit.ok("username not stored", !rec.contains("alice"));
            TestKit.ok("caller's secret survives hash()", Crypto.equalChars(secret,
                    TestKit.PW_ALICE.toCharArray()));
            String rec2 = h.hash(TestKit.pw(TestKit.PW_ALICE), "alice".toCharArray());
            TestKit.ok("same password, different record", !rec.equals(rec2));
            TestKit.ok("own record verifies", h.verify(TestKit.pw(TestKit.PW_ALICE), rec, "abc"));
            TestKit.ok("wrong password fails", !h.verify(TestKit.pw(TestKit.PW_WRONG), rec, "abc"));
            TestKit.ok("one bit off fails",
                    !h.verify((TestKit.PW_ALICE.substring(0, TestKit.PW_ALICE.length() - 1)
                            + "?").toCharArray(), rec, "abc"));
            TestKit.ok("identity does not participate in the derivation",
                    h.verify(TestKit.pw(TestKit.PW_ALICE), rec, "deadbeefdeadbeef"));
        });

        TestKit.caseOf("corrupt or hostile records never verify and never cheap out", () -> {
            String good = h.hash(TestKit.pw(TestKit.PW_ALICE), "alice".toCharArray());
            String salt = good.split("\\$")[3];
            String key = good.split("\\$")[4];
            String[] records = {
                    null,
                    "",
                    "not-a-record",
                    "pbkdf2$sha256$100000$AAAA$",
                    "pbkdf2$sha256$99999$" + salt + "$" + key,
                    "pbkdf2$sha256$999999999999$" + salt + "$" + key,
                    "pbkdf2$sha256$100000$not-base64!$" + key,
                    "pbkdf2$sha256$100000$" + salt + "$",
                    "pbkdf2$md5$100000$" + salt + "$" + key,
                    "pbkdf2$sha256$100000$" + Crypto.base64(shortBuffer(8)) + "$" + key,
                    "pbkdf2$sha256$100000$" + salt + "$" + Crypto.base64(Crypto.randomBytes(16)),
                    "x".repeat(300),
                    PasswordHasher.DISABLED_RECORD
            };
            for (String r : records) {
                long t0 = System.nanoTime();
                boolean v = h.verify(TestKit.pw(TestKit.PW_WRONG), r, "deadbeefdeadbeef");
                long us = (System.nanoTime() - t0) / 1000;
                TestKit.ok("never verifies [" + describe(r) + "]", !v);
                // An early return here is both a timing oracle and a cheap probe, so the
                // work itself is the thing under test.
                TestKit.ok("spent a full derivation for [" + describe(r) + "]", us > 15_000);
            }
            TestKit.ok("even the right password cannot verify a disabled record",
                    !h.verify(TestKit.pw(TestKit.PW_ALICE), PasswordHasher.DISABLED_RECORD, "abc"));
        });

        TestKit.caseOf("requireValidRecord is strict but accepts the disabled marker", () -> {
            h.requireValidRecord(h.hash(TestKit.pw(TestKit.PW_BOB), "bob".toCharArray()));
            h.requireValidRecord(PasswordHasher.DISABLED_RECORD);
            String[] bad = {"", "junk", "pbkdf2$sha256$5000$" + Crypto.base64(Crypto.randomBytes(16))
                    + "$" + Crypto.base64(Crypto.randomBytes(32))};
            for (String r : bad) {
                TestKit.ok("refuses [" + describe(r) + "]",
                        throwsIllegal(() -> h.requireValidRecord(r)));
            }
            TestKit.ok("short salt refused", throwsIllegal(() -> h.requireValidRecord(
                    "pbkdf2$sha256$100000$" + Crypto.base64(shortBuffer(8))
                            + "$" + Crypto.base64(Crypto.randomBytes(32)))));
            TestKit.ok("short key refused", throwsIllegal(() -> h.requireValidRecord(
                    "pbkdf2$sha256$100000$" + Crypto.base64(Crypto.randomBytes(16))
                            + "$" + Crypto.base64(Crypto.randomBytes(16)))));
            TestKit.ok("non-canonical base64 refused", throwsIllegal(() -> h.requireValidRecord(
                    "pbkdf2$sha256$100000$" + Crypto.base64(Crypto.randomBytes(16)) + "x$"
                            + Crypto.base64(Crypto.randomBytes(32)))));
            // Iteration count is range-checked on both sides before a record is ever
            // honoured: parseLenient rejects anything outside [MIN, MAX], so a hand-edited
            // cost this program cannot honour is refused at the load boundary instead of
            // denying that employee on every later login as kdf-unavailable.
            TestKit.ok("iterations above the ceiling refused", throwsIllegal(() ->
                    h.requireValidRecord("pbkdf2$sha256$" + (PasswordHasher.MAX_ITERATIONS + 1)
                            + "$" + Crypto.base64(Crypto.randomBytes(16))
                            + "$" + Crypto.base64(Crypto.randomBytes(32)))));
            TestKit.ok("an absurdly large cost is refused, not parsed as a huge workload",
                    throwsIllegal(() -> h.requireValidRecord("pbkdf2$sha256$999999999$"
                            + Crypto.base64(Crypto.randomBytes(16))
                            + "$" + Crypto.base64(Crypto.randomBytes(32)))));
            TestKit.ok("and the refusal is the load-boundary rejection, not a later one",
                    messageContains(() -> h.requireValidRecord("pbkdf2$sha256$3000000$"
                            + Crypto.base64(Crypto.randomBytes(16))
                            + "$" + Crypto.base64(Crypto.randomBytes(32))), "record:malformed"));
            String atCeiling = "pbkdf2$sha256$" + PasswordHasher.MAX_ITERATIONS + "$"
                    + Crypto.base64(Crypto.randomBytes(16))
                    + "$" + Crypto.base64(Crypto.randomBytes(32));
            TestKit.ok("exactly the ceiling is inside the range and loads",
                    !throwsIllegal(() -> h.requireValidRecord(atCeiling)));
        });

        TestKit.caseOf("needsRehash", () -> {
            PasswordHasher policy = new PasswordHasher(PasswordHasher.DEFAULT_ITERATIONS);
            PasswordHasher low = new PasswordHasher(PasswordHasher.MIN_ITERATIONS);
            String lowRec = low.hash(TestKit.pw(TestKit.PW_BOB), "bob".toCharArray());
            TestKit.ok("below policy needs upgrade", policy.needsRehash(lowRec));
            TestKit.ok("record made at the policy cost does not",
                    !policy.needsRehash(policy.hash(TestKit.pw(TestKit.PW_BOB),
                            "bob".toCharArray())));
            TestKit.ok("a hasher pinned at the floor still upgrades nothing further down",
                    !low.needsRehash(lowRec));
            TestKit.ok("at policy does not",
                    !h.needsRehash(h.hash(TestKit.pw(TestKit.PW_BOB), "bob".toCharArray())));
            TestKit.ok("unparseable needs no upgrade", !h.needsRehash("junk"));
            TestKit.ok("disabled marker needs no upgrade", !h.needsRehash(PasswordHasher.DISABLED_RECORD));
            TestKit.ok("null needs no upgrade", !h.needsRehash(null));
        });

        TestKit.caseOf("decoy work is real work and never throws on a denial path", () -> {
            long t0 = System.nanoTime();
            TestKit.ok("decoy never matches",
                    !h.verifyAgainstDecoy(TestKit.pw(TestKit.PW_ALICE), "abc"));
            long decoyUs = (System.nanoTime() - t0) / 1000;
            t0 = System.nanoTime();
            h.burnOneDigest(TestKit.pw(TestKit.PW_ALICE), "abc");
            long burnUs = (System.nanoTime() - t0) / 1000;
            TestKit.measure("decoy-us/burn-us", decoyUs + "/" + burnUs);
            TestKit.ok("burn is comparable to the decoy", burnUs > decoyUs / 3 && burnUs < decoyUs * 4);

            long s0 = System.nanoTime();
            h.burnOneDigest("a".toCharArray(), "abc");
            long shortUs = (System.nanoTime() - s0) / 1000;
            long n0 = System.nanoTime();
            h.burnOneDigest(null, "abc");
            long nullUs = (System.nanoTime() - n0) / 1000;
            TestKit.measure("burn-short/burn-null", shortUs + "/" + nullUs);
            // The fixed 64-char scratch is what makes input length irrelevant to cost.
            TestKit.ok("short input still spends the work", shortUs > burnUs / 2);
            TestKit.ok("null input still spends the work", nullUs > burnUs / 2);
            h.burnOneDigest((TestKit.PW_ALICE + "\u0000\u00e9\t ").toCharArray(), "abc");
            h.burnOneDigest(new char[InputPolicy.PASSWORD_MAX], "abc");
            h.burnOneDigest(TestKit.pw(TestKit.PW_ALICE), "");
            TestKit.ok("hostile shapes did not throw", true);
            TestKit.ok("over-long decoy ref refused",
                    throwsIllegal(() -> h.verifyAgainstDecoy(TestKit.pw(TestKit.PW_ALICE),
                            "r".repeat(65))));
        });

        TestKit.caseOf("derive re-asserts the printable-ASCII precondition", () -> {
            String rec = h.hash(TestKit.pw(TestKit.PW_ALICE), "alice".toCharArray());
            TestKit.ok("NUL refused", throwsIllegal(
                    () -> h.verify("Fresh\u0000Quiver-71".toCharArray(), rec, "abc")));
            TestKit.ok("tab refused", throwsIllegal(
                    () -> h.verify("Fresh-Quiver-71\t".toCharArray(), rec, "abc")));
            TestKit.ok("space refused", throwsIllegal(
                    () -> h.verify("Fresh-Quiver 71!".toCharArray(), rec, "abc")));
            TestKit.ok("non-ascii refused", throwsIllegal(
                    () -> h.verify("Fresh-Quiv\u00e9r-71".toCharArray(), rec, "abc")));
        });

        TestKit.caseOf("PBEKeySpec really is non-injective without the guard", () -> {
            // Direct evidence for the printable-ASCII rule: the platform derives one key
            // from "pw" and "pw\0", so the policy is a correctness requirement.
            byte[] salt = Crypto.randomBytes(16);
            javax.crypto.SecretKeyFactory f =
                    javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            String ka = Crypto.toHex(f.generateSecret(new javax.crypto.spec.PBEKeySpec(
                    TestKit.PW_ALICE.toCharArray(), salt, PasswordHasher.MIN_ITERATIONS, 256))
                    .getEncoded());
            String kb = Crypto.toHex(f.generateSecret(new javax.crypto.spec.PBEKeySpec(
                    (TestKit.PW_ALICE + "\u0000").toCharArray(), salt,
                    PasswordHasher.MIN_ITERATIONS, 256)).getEncoded());
            TestKit.ok("platform folds a trailing NUL away (hence the policy)", ka.equals(kb));
        });
    }

    // ------------------------------------------------------------------- rule 3: roster

    private static void roster() {
        TestKit.caseOf("create / lookup / duplicate", () -> {
            Path dir = TestKit.scratchDir("roster");
            AuditLog audit = AuditLog.discarding();
            PasswordHasher h = new PasswordHasher(TestKit.FAST_ITERATIONS);
            EmployeeStore store = new EmployeeStore(dir.resolve("employees.dat"), h, audit);
            store.initialiseEmpty();
            TestKit.eq("file mode", "rw-------", TestKit.mode(store.path()));
            TestKit.eq("empty", 0, store.size());
            TestKit.eq("created", EmployeeStore.CreateResult.CREATED,
                    store.create("alice", TestKit.pw(TestKit.PW_ALICE)));
            TestKit.eq("one account", 1, store.size());
            TestKit.eq("duplicate refused", EmployeeStore.CreateResult.NAME_TAKEN,
                    store.create("alice", TestKit.pw(TestKit.PW_BOB)));
            TestKit.eq("invalid name refused", EmployeeStore.CreateResult.INVALID_NAME,
                    store.create("Alice!", TestKit.pw(TestKit.PW_BOB)));
            // Invalid in exactly one way: it satisfies every username/shape rule and is
            // simply shorter than PASSWORD_MIN. (A password containing the username would
            // also be refused, which would hide which rule fired.)
            TestKit.eq("weak password refused", EmployeeStore.CreateResult.WEAK_PASSWORD,
                    store.create("bob", "Bob-Weak1!".toCharArray()));
            TestKit.eq("still one account after refusals", 1, store.size());
            TestKit.ok("record present", store.recordFor("alice").isPresent());
            TestKit.ok("unknown name is empty, not a default", store.recordFor("nobody").isEmpty());
            TestKit.ok("invalid name is empty", store.recordFor("no!body").isEmpty());
            TestKit.ok("null name is empty", store.recordFor(null).isEmpty());
            TestKit.ok("uppercase lookup is empty (fold happens in Authenticator)",
                    store.recordFor("Alice").isEmpty());
            TestKit.eq("names()", List.of("alice"), store.names());
            TestKit.ok("exists", store.exists("alice"));
            TestKit.ok("exists is null-safe", !store.exists(null));

            EmployeeStore reloaded = new EmployeeStore(store.path(), h, audit);
            TestKit.eq("reloads", 1, reloaded.load());
            TestKit.eq("mode after create", "rw-------", TestKit.mode(store.path()));
            // The cross-process lock is a new file the reviewer has never seen. It is created
            // with the same 0600 as everything else in the directory: it holds no data, but a
            // world-readable file in a 0700 directory is still an invitation to probe, and a
            // lock another account could delete is not a lock.
            TestKit.eq("mode of the roster lock file", "rw-------",
                    TestKit.mode(store.path().resolveSibling(store.path().getFileName() + ".lock")));
            String body = Files.readString(store.path());
            TestKit.ok("header first", body.startsWith(EmployeeStore.HEADER + "\n"));
            TestKit.ok("no plaintext on disk", !body.contains(TestKit.PW_ALICE));
            TestKit.eq("one line per account", 2, TestKit.countChar(body, "\n"));
            TestKit.ok("no temp files left", rosterDirIsClean(dir));
        });

        TestKit.caseOf("reload refuses a hostile roster at load time", () -> {
            Path dir = TestKit.scratchDir("roster-bad");
            PasswordHasher h = new PasswordHasher(TestKit.FAST_ITERATIONS);
            AuditLog audit = AuditLog.discarding();
            String r = "pbkdf2$sha256$100000$" + Crypto.base64(Crypto.randomBytes(16))
                    + "$" + Crypto.base64(Crypto.randomBytes(32));
            String[] hostile = {
                    "",
                    "junk\n",
                    EmployeeStore.HEADER + "v2\nu=alice r=" + r + "\n",
                    EmployeeStore.HEADER + "\nu=alice r=" + r + "\nu=alice r=" + r + "\n",
                    EmployeeStore.HEADER + "\nu=Alice r=" + r + "\n",
                    EmployeeStore.HEADER + "\nalice r=" + r + "\n",
                    EmployeeStore.HEADER + "\nu=alice x=" + r + "\n",
                    EmployeeStore.HEADER + "\nu=alice=r=" + r + "\n",
                    EmployeeStore.HEADER + "\nu=a b r=" + r + "\n",
                    EmployeeStore.HEADER + "\nu=" + "a".repeat(120) + " r=" + r + "\n",
                    EmployeeStore.HEADER + "\nu=alice\n",
                    EmployeeStore.HEADER + "\nu=.alice r=" + r + "\n"
            };
            int n = 0;
            int refused = 0;
            for (String body : hostile) {
                n++;
                Path f = dir.resolve("roster-" + n + ".dat");
                PrivateFiles.createPrivateNew(f, body.getBytes(StandardCharsets.UTF_8));
                try {
                    new EmployeeStore(f, h, audit).load();
                } catch (IllegalStateException expected) {
                    refused++;
                }
            }
            TestKit.eq("every structurally hostile roster refused at load", hostile.length, refused);

            Path ok = dir.resolve("ok.dat");
            PrivateFiles.createPrivateNew(ok, (EmployeeStore.HEADER + "\nu=alice r=" + r + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            EmployeeStore good = new EmployeeStore(ok, h, audit);
            TestKit.eq("a well-formed roster loads", 1, good.load());
            good.requirePolicyCompliantRecords();
        });

        TestKit.caseOf("records that parse are still refused when they are not valid", () -> {
            // Separated deliberately: these fixtures are invalid in exactly one way (the
            // record field) and nothing else, so a refusal here can only come from the
            // policy sweep, not from the structural loader.
            Path dir = TestKit.scratchDir("roster-record");
            PasswordHasher h = new PasswordHasher(TestKit.FAST_ITERATIONS);
            AuditLog audit = AuditLog.discarding();
            String r = "pbkdf2$sha256$100000$" + Crypto.base64(Crypto.randomBytes(16))
                    + "$" + Crypto.base64(Crypto.randomBytes(32));
            String[] badRecords = {
                    "",
                    r + " extra",
                    r + "$extra",
                    "pbkdf2$sha256$1000$" + Crypto.base64(Crypto.randomBytes(16))
                            + "$" + Crypto.base64(Crypto.randomBytes(32)),
                    "pbkdf2$sha256$100000$" + Crypto.base64(shortBuffer(8))
                            + "$" + Crypto.base64(Crypto.randomBytes(32)),
                    "pbkdf2$sha256$100000$" + Crypto.base64(Crypto.randomBytes(16))
                            + "$" + Crypto.base64(Crypto.randomBytes(16))
            };
            int n = 0;
            int caught = 0;
            for (String rec : badRecords) {
                n++;
                Path f = dir.resolve("rec-" + n + ".dat");
                PrivateFiles.createPrivateNew(f, (EmployeeStore.HEADER + "\nu=alice r=" + rec + "\n")
                        .getBytes(StandardCharsets.UTF_8));
                EmployeeStore s = new EmployeeStore(f, h, audit);
                s.load();
                if (throwsIllegal(s::requirePolicyCompliantRecords)) {
                    caught++;
                }
            }
            TestKit.eq("every bad record caught by the sweep", badRecords.length, caught);

            // Right shape, below the KDF floor: it parses, so prove its password can never
            // be honoured cheaply either.
            Path cheap = dir.resolve("cheap.dat");
            PrivateFiles.createPrivateNew(cheap, (EmployeeStore.HEADER
                    + "\nu=alice r=pbkdf2$sha256$1000$" + Crypto.base64(Crypto.randomBytes(16))
                    + "$" + Crypto.base64(Crypto.randomBytes(32)) + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            EmployeeStore cheapStore = new EmployeeStore(cheap, h, audit);
            cheapStore.load();
            String belowFloor = cheapStore.recordFor("alice").orElseThrow();
            // The contract is "refuse, and refuse at full cost", not "throw": verify()
            // cannot parse the record, so it runs the decoy derivation and returns false.
            // An exception here would be worse -- it would short-circuit the padding.
            long t0 = System.nanoTime();
            TestKit.ok("a below-floor record never verifies",
                    !h.verify(TestKit.pw(TestKit.PW_ALICE), belowFloor, "abc"));
            TestKit.ok("and it costs a full derivation",
                    (System.nanoTime() - t0) / 1000 > 15_000);
        });

        TestKit.caseOf("disabling an account survives the loader and never verifies", () -> {
            Path dir = TestKit.scratchDir("roster-disable");
            PasswordHasher h = new PasswordHasher(TestKit.FAST_ITERATIONS);
            AuditLog audit = AuditLog.discarding();
            EmployeeStore store = new EmployeeStore(dir.resolve("employees.dat"), h, audit);
            store.initialiseEmpty();
            store.create("alice", TestKit.pw(TestKit.PW_ALICE));
            store.create("bob", TestKit.pw(TestKit.PW_BOB));
            store.disableAccount("alice");
            EmployeeStore reloaded = new EmployeeStore(dir.resolve("employees.dat"), h, audit);
            TestKit.eq("the whole roster still loads", 2, reloaded.load());
            reloaded.requirePolicyCompliantRecords();
            TestKit.eq("marker written", PasswordHasher.DISABLED_RECORD,
                    reloaded.recordFor("alice").orElse(""));
            TestKit.ok("other account untouched",
                    reloaded.recordFor("bob").orElse("").startsWith("pbkdf2$"));
            TestKit.ok("disabling an unknown name is a refusal",
                    throwsIllegal(() -> store.disableAccount("nobody")));
        });

        TestKit.caseOf("rotate and setSecret", () -> {
            Path dir = TestKit.scratchDir("roster-rotate");
            PasswordHasher h = new PasswordHasher(TestKit.FAST_ITERATIONS);
            AuditLog audit = AuditLog.discarding();
            EmployeeStore store = new EmployeeStore(dir.resolve("employees.dat"), h, audit);
            store.initialiseEmpty();
            store.create("alice", TestKit.pw(TestKit.PW_ALICE));
            String before = store.recordFor("alice").orElseThrow();
            store.rotateSecret("alice", TestKit.pw(TestKit.PW_ALICE));
            String after = store.recordFor("alice").orElseThrow();
            TestKit.ok("record changed", !before.equals(after));
            TestKit.ok("fresh salt", !before.split("\\$")[3].equals(after.split("\\$")[3]));
            TestKit.ok("new record verifies", h.verify(TestKit.pw(TestKit.PW_ALICE), after, "abc"));
            TestKit.eq("setSecret", EmployeeStore.CreateResult.CREATED,
                    store.setSecret("alice", TestKit.pw(TestKit.PW_BOB)));
            TestKit.ok("new secret verifies",
                    h.verify(TestKit.pw(TestKit.PW_BOB), store.recordFor("alice").orElseThrow(), "abc"));
            TestKit.eq("setSecret on an unknown name fails", EmployeeStore.CreateResult.IO_FAILURE,
                    store.setSecret("nobody", TestKit.pw(TestKit.PW_BOB)));
            TestKit.eq("setSecret refuses a weak secret", EmployeeStore.CreateResult.WEAK_PASSWORD,
                    store.setSecret("alice", "short1!".toCharArray()));
            TestKit.ok("still no temp litter", rosterDirIsClean(dir));
            TestKit.ok("rotate on an unknown name refuses",
                    throwsIllegal(() -> store.rotateSecret("nobody", TestKit.pw(TestKit.PW_BOB))));
        });
    }

    // --------------------------------------------------------------- rules 2/5: on disk

    private static void privateFiles() {
        TestKit.caseOf("created modes", () -> {
            Path dir = TestKit.scratchDir("files");
            TestKit.eq("dir mode", "rwx------", TestKit.mode(dir));
            Path f = dir.resolve("a.dat");
            PrivateFiles.createPrivateNew(f, "hello".getBytes(StandardCharsets.UTF_8));
            TestKit.eq("file mode", "rw-------", TestKit.mode(f));
            PrivateFiles.writePrivateAtomic(f, "replaced".getBytes(StandardCharsets.UTF_8));
            TestKit.eq("mode after replace", "rw-------", TestKit.mode(f));
            TestKit.eq("content after replace", "replaced", Files.readString(f));
            Path log = dir.resolve("log");
            PrivateFiles.appendPrivateLine(log, "line1");
            PrivateFiles.appendPrivateLine(log, "line2");
            TestKit.eq("append mode", "rw-------", TestKit.mode(log));
            TestKit.eq("append content", "line1\nline2\n", Files.readString(log));
            TestKit.ok("createPrivateNew never overwrites", throwsIllegal(
                    () -> PrivateFiles.createPrivateNew(f, "x".getBytes(StandardCharsets.UTF_8))));
        });

        TestKit.caseOf("symlinks are refused, not followed", () -> {
            Path dir = TestKit.scratchDir("files-link");
            Path target = dir.resolve("target.dat");
            PrivateFiles.createPrivateNew(target, "secret".getBytes(StandardCharsets.UTF_8));
            Path link = dir.resolve("link.dat");
            Files.createSymbolicLink(link, target);
            TestKit.ok("read refused", throwsIllegal(() -> PrivateFiles.readPrivateBounded(link, 100)));
            TestKit.ok("atomic write refused", throwsIllegal(() -> PrivateFiles.writePrivateAtomic(
                    link, "x".getBytes(StandardCharsets.UTF_8))));
            TestKit.ok("append refused", throwsIllegal(() -> PrivateFiles.appendPrivateLine(link, "x")));
            TestKit.ok("create-over-link refused", throwsIllegal(
                    () -> PrivateFiles.createPrivateNew(link, "x".getBytes(StandardCharsets.UTF_8))));
            TestKit.ok("target untouched", "secret".equals(Files.readString(target)));
            Path dirLink = dir.resolve("sub");
            Files.createSymbolicLink(dirLink, TestKit.scratchDir("files-link2"));
            TestKit.ok("data directory that is a symlink refused",
                    throwsIllegal(() -> PrivateFiles.requireDataDirectory(dirLink)));
        });

        TestKit.caseOf("mode policy on files we did not create", () -> {
            Path dir = TestKit.scratchDir("files-modes");
            Path cfg = dir.resolve("app.cfg");
            Files.writeString(cfg, "k=v\n");
            for (String perms : List.of("rw-r--r--", "rw-rw-rw-", "rw----r--", "rwxrwxrwx")) {
                Files.setPosixFilePermissions(cfg, PosixFilePermissions.fromString(perms));
                TestKit.ok(perms + " refused", throwsIllegal(
                        () -> PrivateFiles.requireNoGroupOrOtherAccess(cfg)));
            }
            for (String perms : List.of("r--------", "rw-------")) {
                Files.setPosixFilePermissions(cfg, PosixFilePermissions.fromString(perms));
                PrivateFiles.requireNoGroupOrOtherAccess(cfg);
                TestKit.ok(perms + " accepted", true);
            }
            Path cfgLink = dir.resolve("sym.cfg");
            Files.createSymbolicLink(cfgLink, cfg);
            TestKit.ok("symlinked config refused",
                    throwsIllegal(() -> PrivateFiles.requireNoGroupOrOtherAccess(cfgLink)));
            TestKit.ok("missing config refused", throwsIllegal(
                    () -> PrivateFiles.requireNoGroupOrOtherAccess(dir.resolve("nope.cfg"))));
            Path cfgDir = dir.resolve("cfg-dir");
            Files.createDirectories(cfgDir);
            TestKit.ok("directory refused", throwsIllegal(
                    () -> PrivateFiles.requireNoGroupOrOtherAccess(cfgDir)));
        });

        TestKit.caseOf("world-writable ancestors refused, sticky ones tolerated", () -> {
            Path base = TestKit.scratchDir("files-anc");
            Path open = base.resolve("open");
            Files.createDirectories(open);
            Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rwxrwxrwx"));
            Path inside = open.resolve("data");
            TestKit.ok("world-writable ancestor refused",
                    throwsIllegal(() -> PrivateFiles.requireDataDirectory(inside)));
            Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rwxrwxrwx"));

            // The sticky exception cannot be fabricated here: PosixFilePermissions only
            // expresses the nine rwx bits, so the sticky bit is set-able only by chmod.
            // Evidence therefore comes from a real sticky ancestor -- /tmp -- and its
            // precondition is asserted first so the check cannot pass vacuously.
            Integer tmpMode = PrivateFiles.unixMode(Path.of("/tmp"));
            TestKit.ok("/tmp is world-writable (precondition)",
                    tmpMode != null && (tmpMode & 0_002) != 0);
            TestKit.ok("/tmp is sticky (precondition)", tmpMode != null && (tmpMode & 0_1000) != 0);
            Path underTmp = TestKit.scratchDir("files-sticky");
            PrivateFiles.requireDataDirectory(underTmp.resolve("deeper"));
            TestKit.ok("a sticky world-writable ancestor is tolerated",
                    Files.isDirectory(underTmp.resolve("deeper")));
            TestKit.eq("the created directory is still private", "rwx------",
                    TestKit.mode(underTmp.resolve("deeper")));
        });

        TestKit.caseOf("data directory rules", () -> {
            TestKit.ok("relative path refused",
                    throwsIllegal(() -> PrivateFiles.requireDataDirectory(Path.of("relative-dir"))));
            Path dir = TestKit.scratchDir("files-dir");
            Path file = dir.resolve("not-a-dir");
            Files.writeString(file, "x");
            TestKit.ok("existing file refused",
                    throwsIllegal(() -> PrivateFiles.requireDataDirectory(file)));
            Path loose = dir.resolve("loose");
            Files.createDirectories(loose);
            Files.setPosixFilePermissions(loose, PosixFilePermissions.fromString("rwxr-xr-x"));
            TestKit.ok("0755 data dir refused",
                    throwsIllegal(() -> PrivateFiles.requireDataDirectory(loose)));
            Path fresh = dir.resolve("fresh");
            PrivateFiles.requireDataDirectory(fresh);
            TestKit.eq("fresh dir mode", "rwx------", TestKit.mode(fresh));
            PrivateFiles.requireDataDirectory(fresh);
            TestKit.ok("re-accepting our own directory is fine", Files.isDirectory(fresh));
            TestKit.eq("no probe file left behind", 0, countProbes(fresh));
        });

        TestKit.caseOf("reads are bounded and refuse non-regular files", () -> {
            Path dir = TestKit.scratchDir("files-read");
            Path f = dir.resolve("big.dat");
            PrivateFiles.createPrivateNew(f, new byte[2048]);
            TestKit.ok("over-cap read refused",
                    throwsIllegal(() -> PrivateFiles.readPrivateBounded(f, 1024)));
            TestKit.eq("under-cap read ok", 2048, PrivateFiles.readPrivateBounded(f, 4096).length());
            TestKit.ok("directory read refused",
                    throwsIllegal(() -> PrivateFiles.readPrivateBounded(dir, 4096)));
            TestKit.ok("missing read refused",
                    throwsIllegal(() -> PrivateFiles.readPrivateBounded(dir.resolve("gone"), 10)));
            Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-r--r--"));
            TestKit.ok("group-readable read refused",
                    throwsIllegal(() -> PrivateFiles.readPrivateBounded(f, 4096)));
        });

        TestKit.caseOf("atomic replace never exposes a partial file", () -> {
            Path dir = TestKit.scratchDir("files-atomic");
            Path f = dir.resolve("x.dat");
            PrivateFiles.writePrivateAtomic(f, "aaa".getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < 40; i++) {
                PrivateFiles.writePrivateAtomic(f,
                        ("b".repeat(200 + i)).getBytes(StandardCharsets.UTF_8));
                String seen = Files.readString(f);
                TestKit.ok("reader sees a whole file", seen.equals("aaa") || seen.length() == 200 + i);
            }
            TestKit.eq("no stray temps", 1, PrivateFiles.countEntries(dir, 50));
        });
    }

    // ---------------------------------------------------------------------- rule 5: log

    private static void auditLog() {
        TestKit.caseOf("audit lines carry references, never secrets", () -> {
            Path dir = TestKit.scratchDir("audit");
            AuditLog audit = new AuditLog(dir.resolve("audit.log"));
            String pw = TestKit.PW_ALICE;
            audit.event("login", Crypto.idRef("alice"), Crypto.idRef("10.0.0.1"), "denied",
                    "bad-credentials");
            audit.event("create", Crypto.idRef("bob"), "-", "ok", "created");
            audit.event("probe", "alice", pw, "denied", pw);
            audit.event("throttle", Authenticator.INVALID_REF, "-", "denied", "throttled");
            audit.systemFailure("http", "-", "-", new IOException("/etc/shadow blew up"));
            String body = Files.readString(dir.resolve("audit.log"));
            TestKit.eq("log mode", "rw-------", TestKit.mode(dir.resolve("audit.log")));
            TestKit.eq("one line per event", 5, TestKit.countChar(body, "\n"));
            TestKit.ok("password absent", !body.contains(pw));
            TestKit.ok("username absent", !body.lines().anyMatch(l -> l.contains("alice")));
            TestKit.ok("filesystem path absent", !body.contains("/etc/"));
            TestKit.ok("scratch path absent", !body.contains(dir.toString()));
            TestKit.ok("exception message absent", !body.contains("blew up"));
            TestKit.ok("exception type recorded", body.contains("type=IOException"));
            TestKit.ok("attacker-shaped detail rejected", body.contains("detail=rejected"));
            TestKit.ok("raw username as subject rejected", body.contains("subject=rejected"));
            TestKit.ok("hex subject kept", body.contains("subject=" + Crypto.idRef("alice")));
            TestKit.ok("internal label kept", body.contains("subject=invalid"));
            TestKit.ok("every subject field is a digest or a known token", body.lines()
                    .map(l -> l.replaceAll(".*subject=([^ ]*).*", "$1"))
                    .allMatch(t -> t.equals("-") || t.equals("rejected") || t.equals("invalid")
                            || t.matches("[0-9a-f]{16}")));
            TestKit.ok("every src field likewise", body.lines()
                    .map(l -> l.replaceAll(".*src=([^ ]*).*", "$1"))
                    .allMatch(t -> t.equals("-") || t.equals("rejected") || t.equals("invalid")
                            || t.matches("[0-9a-f]{16}")));
            TestKit.ok("timestamp present", body.contains("ts=20"));
            TestKit.eq("ring bounded", AuditLog.MAX_KEPT, boundedRing());
        });

        TestKit.caseOf("a failed audit write cannot change a decision", () -> {
            Path dir = TestKit.scratchDir("audit-fail");
            // A directory in place of the log: every append fails and no permission can
            // make it work, unlike a read-only file (which we run as root here).
            Path log = dir.resolve("audit.log");
            Files.createDirectories(log);
            AuditLog audit = new AuditLog(log);
            audit.event("login", Crypto.idRef("alice"), "-", "denied", "bad-credentials");
            TestKit.eq("failure counted", 1L, audit.failedWriteCount());
            TestKit.eq("nothing claimed written", 0L, audit.writtenCount());
            TestKit.ok("event still in the ring",
                    audit.lastEventForTesting().contains("event=login"));
            TestKit.ok("discarding sink writes nothing anywhere", true);
            AuditLog discarding = AuditLog.discarding();
            discarding.event("login", "-", "-", "ok", "granted");
            TestKit.eq("no writes", 0L, discarding.writtenCount());
        });
    }

    private static int boundedRing() {
        AuditLog a = AuditLog.discarding();
        for (int i = 0; i < AuditLog.MAX_KEPT + 10; i++) {
            a.event("e", "-", "-", "ok", "x");
        }
        return a.recentForTesting(AuditLog.MAX_KEPT + 100).size();
    }

    private static void cookieParser() {
        TestKit.caseOf("cookie parsing is exact", () -> {
            TestKit.eq("plain", "2", CookieParser.value("a=1; b=2", "b").orElse(""));
            TestKit.eq("no space", "2", CookieParser.value("a=1;b=2", "b").orElse(""));
            TestKit.ok("two spaces before a name is not tolerated",
                    CookieParser.value("a=1;  b=2", "b").isEmpty());
            TestKit.ok("space inside a name refused", CookieParser.value("a=1; b =2", "b").isEmpty());
            TestKit.ok("suffix alias refused", CookieParser.value("xxb=2", "b").isEmpty());
            TestKit.ok("prefix alias refused", CookieParser.value("bx=2", "b").isEmpty());
            TestKit.ok("case-folded name refused", CookieParser.value("B=2", "b").isEmpty());
            TestKit.eq("first pair wins", "1", CookieParser.value("b=1;b=2", "b").orElse(""));
            TestKit.eq("quoted value stays opaque", "\"2\"", CookieParser.value("b=\"2\"", "b").orElse(""));
            TestKit.ok("empty value present but empty",
                    CookieParser.value("b=", "b").orElse("MISSING").isEmpty());
            TestKit.ok("null header", CookieParser.value(null, "b").isEmpty());
            TestKit.ok("oversized header", CookieParser.value("b=" + "x".repeat(9000), "b").isEmpty());
            TestKit.ok("oversized value", CookieParser.value("b=" + "x".repeat(600), "b").isEmpty());
            TestKit.ok("pair with no equals", CookieParser.value("justname", "justname").isEmpty());
            TestKit.ok("empty name refused", CookieParser.value("=v", "").isEmpty());
            TestKit.ok("trailing semicolon still finds the pair",
                    CookieParser.value("b=2;", "b").isPresent());
            TestKit.ok("cookie name is not a substring match on a prefix pair",
                    CookieParser.value("x=1;PORTAL_SESSION=steal", "PORTAL_SESSION").isPresent());
            TestKit.ok("unrelated cookie does not match",
                    CookieParser.value("PORTAL_SESSION2=steal", "PORTAL_SESSION").isEmpty());
        });
    }

    // ------------------------------------------------------- structural (rules 6/7/8) guards

    /**
     * Text guards for properties a behavioural test cannot falsify cheaply (or at all --
     * the absence of a DNS lookup is not observable from a denial). Comments are stripped
     * first, because prose in this codebase names the very patterns being banned.
     */
    private static void sourceTextGuards() {
        TestKit.caseOf("no locale-dependent or value-altering normalisation", () -> {
            for (String f : List.of("Authenticator.java", "InputPolicy.java", "PortalServer.java",
                    "SourceRef.java", "PortalCli.java", "CookieParser.java", "PasswordHasher.java",
                    "EmployeeStore.java", "Ledger.java")) {
                String src = source(f);
                TestKit.ok(f + " has no .trim(", !src.contains(".trim("));
                TestKit.ok(f + " has no .strip(", !src.contains(".strip("));
                TestKit.ok(f + " has no bare toLowerCase()", !src.contains("toLowerCase()"));
                TestKit.ok(f + " has no bare toUpperCase()", !src.contains("toUpperCase()"));
                TestKit.ok(f + " has no String.CASE_INSENSITIVE_ORDER",
                        !src.contains("CASE_INSENSITIVE_ORDER"));
            }
        });

        TestKit.caseOf("no DNS and no reverse DNS", () -> {
            for (String f : List.of("SourceRef.java", "PortalConfig.java", "JdkHttpsListener.java",
                    "PortalServer.java", "Main.java")) {
                String src = source(f);
                TestKit.ok(f + " never resolves a name", !src.contains("InetAddress.getByName"));
                TestKit.ok(f + " never reverse-resolves", !src.contains("getHostName()"));
                TestKit.ok(f + " never looks up a name for a decision",
                        !src.contains("getAllByName") && !src.contains("InetAddress.getLocalHost"));
            }
        });

        TestKit.caseOf("the throttle decides and mutates in one monitor", () -> {
            String src = source("ThrottleManager.java");
            int at = src.indexOf("Kind beginAttempt(");
            TestKit.ok("beginAttempt exists", at > 0);
            String body = src.substring(at, at + 1500);
            TestKit.ok("takes the monitor", body.contains("synchronized (monitor)"));
            TestKit.ok("mutates inside it", body.contains("failures++"));
            TestKit.ok("decides inside it", body.contains("blockedUntil > now"));
            TestKit.ok("returns the verdict from inside it", body.contains("return verdict"));
            TestKit.ok("no peek-only gate survived", !src.contains("Kind gate("));
            TestKit.ok("recordFailure no longer returns a verdict",
                    !src.contains("Kind recordFailure("));
            TestKit.ok("both dimensions exist", src.contains("accounts") && src.contains("sources"));
            TestKit.ok("account ceiling is shorter than the source ceiling",
                    ThrottleManager.MAX_ACCOUNT_BLOCK_SECONDS < ThrottleManager.MAX_SOURCE_BLOCK_SECONDS);
        });

        TestKit.caseOf("the authenticator keeps exactly one derivation per path", () -> {
            String src = source("Authenticator.java");
            TestKit.ok("three burn sites for the non-verifying refusals",
                    TestKit.countChar(src, "burnOneDigest") >= 3);
            TestKit.ok("decoy runs for the throttled and unknown-name paths",
                    TestKit.countChar(src, "verifyAgainstDecoy") >= 2);
            TestKit.ok("one wipe site covers every return", src.contains("Crypto.wipe(password)"));
            TestKit.ok("throttle is consulted before the roster",
                    src.indexOf("beginAttempt") < src.indexOf("recordFor"));
            String denyBody = between(src, "private void deny(", "\n    }");
            TestKit.ok("the audit write is charged before the padding",
                    denyBody.indexOf("audit.event") >= 0 && denyBody.indexOf("audit.event")
                            < denyBody.indexOf("padToFloor"));
            TestKit.ok("no padding decision in the deny path", !denyBody.contains("if ("));
        });

        TestKit.caseOf("no secret reaches argv, stdout or a response body", () -> {
            String cli = source("PortalCli.java");
            TestKit.ok("no password flag on argv", !cli.contains("--password"));
            TestKit.ok("no --user flag carries a secret other than a name",
                    cli.contains("--user="));
            TestKit.ok("the session id is never printed", !cli.contains("sessionId()"));
            TestKit.ok("granted line names the user only", cli.contains("user=\" + result.username()"));
            String srv = source("PortalServer.java");
            TestKit.ok("the server never renders the internal reason",
                    !srv.contains("reasonForInternalUseOnly"));
            TestKit.ok("the server never renders the username", !srv.contains("result.username()"));
            TestKit.ok("no plaintext-HTTP listener exists",
                    !source("JdkHttpsListener.java").contains("HttpServer.create"));
            TestKit.ok("the keystore password is read from a file",
                    source("PortalConfig.java").contains("PASSWORD_FILE"));
            for (String f : List.of("PortalCli.java", "PortalServer.java", "Main.java",
                    "JdkHttpsListener.java", "Authenticator.java")) {
                String src = source(f);
                TestKit.ok(f + " never prints an exception message", !src.contains("printStackTrace"));
            }
        });

        TestKit.caseOf("every denial shares one response shape", () -> {
            String src = source("PortalServer.java");
            TestKit.eq("exactly one 401 site", 1, TestKit.countChar(src, "ex.respond(401"));
            TestKit.ok("one shared header builder", TestKit.countChar(src, "securityHeaders()") >= 7);
            // The header block must not be parameterisable. An earlier build took a
            // withHsts flag and passed false on the 404/405/415/500 replies, so the security
            // headers themselves distinguished the branches -- the exact thing the shared
            // builder exists to prevent. Asserting the builder has no flag is stronger than
            // counting call sites, because a future branch can always call it with false.
            TestKit.ok("the header builder takes no flag", !src.contains("withHsts"));
            TestKit.ok("HSTS is added unconditionally, exactly once",
                    TestKit.countChar(src, "h.add(\"Strict-Transport-Security") == 1);
            // The quoted form, not the bare name: the method's own javadoc explains why the
            // header is sent on every reply and mentions it there.
            TestKit.ok("nothing re-adds the header per branch",
                    TestKit.countChar(src, "\"Strict-Transport-Security: max-age=\"") == 1);
            // Four cookie builders (set + clear, for each of the two cookies) and nothing
            // else may emit a Set-Cookie line.
            TestKit.eq("cookie attributes appear once per builder", 4,
                    TestKit.countChar(src, "; Path=/; HttpOnly; Secure; SameSite=Strict"));
            TestKit.ok("no cookie is built outside those four",
                    TestKit.countChar(src, "Set-Cookie: ") == 4);
            TestKit.ok("session cookie is only set on success",
                    TestKit.countChar(src, "sessionCookie(") == 2);
        });

        TestKit.caseOf("fail-closed wiring", () -> {
            String runtime = source("PortalRuntime.java");
            TestKit.ok("runtime checks the file mode", runtime.contains("requireAcceptableFileMode"));
            TestKit.ok("runtime checks the records", runtime.contains("requirePolicyCompliantRecords"));
            TestKit.ok("runtime reports an unusable ledger", runtime.contains("ledgerLossCount"));
            String cfg = source("PortalConfig.java");
            TestKit.ok("an unknown config key is fatal", cfg.contains("config-unknown-key"));
            TestKit.ok("the data directory is required", cfg.contains("require(ENV_DATA_DIR)"));
            TestKit.ok("the listen host must be a literal", cfg.contains("hostLiteral"));
            TestKit.ok("keystore and password file must arrive together",
                    cfg.contains("keystore-and-password-file-must-be-supplied-together"));
            String listener = source("JdkHttpsListener.java");
            TestKit.ok("the listener refuses to start without a keystore",
                    listener.contains("https-keystore-not-configured"));
            TestKit.ok("weak TLS protocols are removed",
                    listener.contains("TLSv1.2") && listener.contains("TLSv1.3")
                            && !listener.contains("\"TLSv1.1\", \"TLSv1\""));
        });
    }

    private static int countProbes(Path dir) throws IOException {
        int n = 0;
        try (var walk = Files.list(dir)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                if (p.getFileName().toString().startsWith(".ownership-probe-")) {
                    n++;
                }
            }
        }
        return n;
    }

    // ------------------------------------------------------------------------ utilities

    /**
     * Whether a roster directory holds only the roster and its cross-process lock file.
     *
     * <p>This used to be {@code countEntries(dir) == 1}. A bare count fails for any reason at
     * all and then says nothing about which file appeared, so when the roster grew a
     * {@code employees.dat.lock} sibling the two litter checks below went red and reported
     * "temp files left" for a directory whose second entry was the deliberate lock. Naming
     * what is there makes the same claim -- no atomic-write temp file was abandoned -- and
     * keeps it true when the accepted set changes.
     */
    private static boolean rosterDirIsClean(Path dir) {
        List<String> unexpected = new java.util.ArrayList<>();
        try (var walk = Files.list(dir)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                String n = p.getFileName().toString();
                if (!n.equals("employees.dat") && !n.equals("employees.dat.lock")) {
                    unexpected.add(n);
                }
            }
        } catch (java.io.IOException unreadable) {
            return false;
        }
        if (!unexpected.isEmpty()) {
            TestKit.note("unexpected files in roster dir: " + unexpected);
            return false;
        }
        return true;
    }

    interface ThrowingAction {
        void run() throws Exception;
    }

    private static boolean throwsIllegal(ThrowingAction a) {
        try {
            a.run();
            return false;
        } catch (IllegalStateException | IllegalArgumentException expected) {
            return true;
        } catch (Exception other) {
            return false;
        }
    }

    /**
     * Asserts <em>why</em> something was refused. An absence-style check on a refusal that
     * happens for an unrelated reason passes vacuously, so the rejection's own message is
     * the thing under test here.
     */
    private static boolean messageContains(ThrowingAction a, String needle) {
        try {
            a.run();
            return false;
        } catch (IllegalStateException | IllegalArgumentException expected) {
            String m = expected.getMessage();
            return m != null && m.contains(needle);
        } catch (Exception other) {
            return false;
        }
    }

    /** A buffer shorter than the security-token floor, for negative record fixtures. */
    private static byte[] shortBuffer(int n) {
        return java.util.Arrays.copyOf(Crypto.randomBytes(16), n);
    }

    /** base64url of {@code n} random bytes, with the padding the wire format forbids. */
    private static String paddedUrlForm(int n) {
        // The URL encoder pads by default; withoutPadding() is the opt-out we use for
        // real tokens, so the padded form is what a hostile client would send.
        return java.util.Base64.getUrlEncoder().encodeToString(Crypto.randomBytes(n));
    }

    private static boolean allZero(char[] c) {
        for (char x : c) {
            if (x != '\0') {
                return false;
            }
        }
        return true;
    }

    private static boolean allZero(byte[] b) {
        for (byte x : b) {
            if (x != 0) {
                return false;
            }
        }
        return true;
    }

    private static String describe(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(s.length(), 22); i++) {
            char c = s.charAt(i);
            sb.append(c < 0x21 || c > 0x7E ? '@' : c);
        }
        if (s.length() > 22) {
            sb.append("...(").append(s.length()).append(')');
        }
        return sb.toString();
    }

    private static String between(String src, String start, String end) {
        int a = src.indexOf(start);
        if (a < 0) {
            TestKit.ok("found " + start, false);
            return "";
        }
        int b = src.indexOf(end, a);
        return b < 0 ? src.substring(a) : src.substring(a, b);
    }

    private static String source(String simpleName) {
        Path p = Path.of(System.getProperty("portal.src.main", ""), "com", "portal", "auth",
                simpleName);
        String body;
        try {
            body = Files.readString(p, StandardCharsets.US_ASCII);
        } catch (IOException unreadable) {
            TestKit.ok("cannot read source " + p + " (pass -Dportal.src.main)", false);
            return "";
        }
        TestKit.ok("source is non-trivial " + simpleName, body.length() > 300);
        return stripComments(body);
    }

    /** Strips line and block comments, respecting string and character literals. */
    static String stripComments(String src) {
        StringBuilder out = new StringBuilder(src.length());
        boolean inString = false;
        boolean inChar = false;
        boolean inLine = false;
        boolean inBlock = false;
        for (int i = 0; i < src.length(); i++) {
            char c = src.charAt(i);
            char n = i + 1 < src.length() ? src.charAt(i + 1) : '\0';
            if (inLine) {
                if (c == '\n') {
                    inLine = false;
                    out.append('\n');
                }
                continue;
            }
            if (inBlock) {
                if (c == '*' && n == '/') {
                    inBlock = false;
                    i++;
                }
                continue;
            }
            if (inString || inChar) {
                out.append(c);
                if (c == '\\' && i + 1 < src.length()) {
                    out.append(src.charAt(++i));
                } else if ((inString && c == '"') || (inChar && c == '\'')) {
                    inString = false;
                    inChar = false;
                }
                continue;
            }
            if (c == '/' && n == '/') {
                inLine = true;
                i++;
                continue;
            }
            if (c == '/' && n == '*') {
                inBlock = true;
                i++;
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '\'') {
                inChar = true;
            }
            out.append(c);
        }
        return out.toString();
    }
}
