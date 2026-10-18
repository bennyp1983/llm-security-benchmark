package com.example.auth;

import static com.example.auth.T.eq;
import static com.example.auth.T.inRange;
import static com.example.auth.T.no;
import static com.example.auth.T.section;
import static com.example.auth.T.yes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Rule 1 (trust boundaries), rule 2 (secrets), rule 5 (masking), rule 6 (reject, never default).
 *
 * <p>Every rejection below is asserted positively as well as negatively: a fixture that is invalid in
 * two unrelated ways would prove nothing about the guard under test, so accepted and rejected
 * fixtures differ from their neighbours in exactly one property.
 */
public final class AllTests {

    private AllTests() {
    }

    public static void main(String[] args) throws Exception {
        emails();
        passwords();
        tokens();
        identifiers();
        sourceIds();
        integers();
        dbPaths();
        crypto();
        masking();
        logSanitisation();
        logFilePermissions();
        configuration();
        sourceTextAudits();
        System.exit(T.summary("AllTests"));
    }

    // ---------------------------------------------------------------- rule 1: email

    private static void emails() {
        T.section("email validation");
        String[] ok = {
            "a@example.com",
            "alice+tag@example.com",
            "first.last@sub.example.co.uk",
            "UPPER@EXAMPLE.COM",
            "u_s-me%d+1@mail.example.io",
            "digits123@ex4mple.dev",
            "a@" + "l".repeat(63) + ".com",
            "x@ex" + "a".repeat(50) + "mple.com",
        };
        for (String e : ok) {
            yes("accepts " + e, accepted(e));
        }
        T.eq("normalises case", "alice@example.com", normalise("Alice@Example.COM"));
        T.eq("local part preserved", "alice+tag@example.com", normalise("Alice+Tag@Example.COM"));

        Map<String, String> bad = new LinkedHashMap<>();
        bad.put("", "empty");
        bad.put("a", "no at sign");
        bad.put("@example.com", "empty local part");
        bad.put("alice@", "empty domain");
        bad.put("a@@example.com", "two at signs");
        bad.put("al ice@example.com", "space in local part");
        bad.put("alice @example.com", "trailing space before at");
        bad.put(" alice@example.com", "leading space");
        bad.put("alice@ example.com", "space after at");
        bad.put("ali\nce@example.com", "embedded newline");
        bad.put("alice@example.com\r\nX-Evil: 1", "CRLF injection");
        bad.put("alice\t@example.com", "tab");
        bad.put("alice@example.com\0", "trailing NUL");
        bad.put("alice@exam\tple.com", "tab in domain");
        bad.put("alice@example.com.", "trailing root dot");
        bad.put("alice@sub..example.com", "double dot in domain");
        bad.put(".alice@example.com", "leading dot in local part");
        bad.put("alice.@example.com", "trailing dot in local part");
        bad.put("al..ice@example.com", "double dot in local part");
        bad.put("alice@-example.com", "domain label starts with hyphen");
        bad.put("alice@example-.com", "domain label ends with hyphen");
        bad.put("alice@exa mple.com", "space in domain");
        bad.put("alice@ex\u00e4mple.com", "non-ASCII local (homoglyph)");
        bad.put("alice@xn--exmple-cua.com", "punycode label (IDN homograph)");
        bad.put("ali\u00e7e@example.com", "accented character");
        bad.put("alice@192.168.1.1", "IPv4 literal domain");
        bad.put("alice@12345", "numeric top label");
        bad.put("alice@exa_mple.com", "underscore in domain");
        bad.put("ali\"ce@example.com", "double quote");
        bad.put("ali'ce@example.com", "single quote (SQL fragment)");
        bad.put("alice@example;INIT=RUNSCRIPT.com", "semicolon");
        bad.put("alice@example.com'--", "SQL comment");
        bad.put("a".repeat(65) + "@example.com", "local part 65 chars");
        bad.put("x@ex" + "a".repeat(250) + "mple.com", "domain over 253 chars");
        bad.put("a".repeat(255) + "@example.com", "total over 254");
        // One defect at a time: a 253-char domain is the longest legal one.
        no("accepts a 253-char domain", accepted("x@ex" + "a".repeat(238) + "mple.com"));
        bad.put("alice@example.c", "single-letter top label");
        bad.put("\u2028alice@example.com", "unicode line separator");
        bad.put("alice@exam\u0001ple.com", "control character in domain");
        bad.put("null", "literal word null is not an address");
        for (Map.Entry<String, String> e : bad.entrySet()) {
            no("refuses " + e.getValue(), accepted(e.getKey()));
        }
        // Rejection codes must never contain the offending value.
        String leaked = rejectionCode("alice'@ex\u00e4mple.com' OR 1=1");
        T.eq("rejection code carries no input", "email_charset", leaked);
    }

    private static boolean accepted(String raw) {
        try {
            InputValidator.requireEmail(raw);
            return true;
        } catch (InputValidator.ValidationException e) {
            return false;
        }
    }

    private static String normalise(String raw) {
        try {
            return InputValidator.requireEmail(raw);
        } catch (InputValidator.ValidationException e) {
            return "!rejected:" + e.getMessage();
        }
    }

    private static String rejectionCode(String raw) {
        try {
            InputValidator.requireEmail(raw);
            return "!accepted";
        } catch (InputValidator.ValidationException e) {
            return e.getMessage();
        }
    }

    // ---------------------------------------------------------------- rule 1: password

    private static void passwords() {
        T.section("password validation");
        String[] ok = {
            "Winters-Vector-44", "harbor delta nineteen", "Tr\u00a1me-Password-7",
            "a".repeat(12), "a".repeat(1024), "P\u00e4ssw\u00f6rd-Unicode-9",
        };
        for (String p : ok) {
            no("accepts a " + p.length() + "-char password", rejected(p, 12));
        }
        String[] bad = {
            "shorty",                       // below minimum
            "exactly-11",                   // one under the default minimum
            "",                             // empty
            " leading-space-1234",          // leading space
            "trailing-space-1234 ",         // trailing space
            "tab\there-12345678",           // tab
            "newline\nhere-12345678",       // newline
            "nul\0here-12345678",           // NUL: would make "pw" and "pw\0" agree
            "esc\u0001ape-12345678",        // control character
            "c1\u0085control-12345678",     // C1 control
        };
        for (String p : bad) {
            yes("refuses a " + describe(p) + " password", rejected(p, 12));
        }
        yes("refuses 1025 characters", rejected("a".repeat(1025), 12));
        yes("refuses unpaired high surrogate", rejected("Surrogate-x-123456\uD800", 12));
        yes("refuses a high surrogate in the middle", rejected("Sur\uD800rogate-12345", 12));
        yes("refuses unpaired low surrogate", rejected("Surrogate-\uDC00-x-12345", 12));
        yes("accepts a paired surrogate (emoji)", !rejected("Emoji-\uD83D\uDE00-Pass-99", 12));
        // A 400-char all-CJK password is 1200 UTF-8 bytes: refused on encoded length, not char count.
        yes("refuses >1024 UTF-8 bytes at 400 chars", rejected("\u4e2d".repeat(400), 12));
        yes("accepts 341 CJK chars (1023 bytes)", !rejected("\u4e2d".repeat(341), 12));

        // The all-zero buffer is a separate negative case: it is NUL-filled, not "long".
        yes("refuses an all-NUL buffer", thrown(new char[64], 12));
        yes("refuses a null buffer", thrown(null, 12));
        // The minimum is enforced exactly, not approximately.
        no("accepts exactly the minimum length", rejected("a".repeat(12), 12));
        yes("refuses one below the minimum", rejected("a".repeat(11), 12));
        yes("refuses below a raised minimum", rejected("a".repeat(14), 15));
        no("accepts a password at the raised minimum", rejected("a".repeat(15), 15));
    }

    private static boolean rejected(String p, int min) {
        return thrown(T.chars(p), min);
    }

    private static boolean thrown(char[] p, int min) {
        try {
            InputValidator.requirePassword(p, min);
            return false;
        } catch (InputValidator.ValidationException e) {
            return true;
        }
    }

    private static String describe(String p) {
        if (p.isEmpty()) {
            return "zero-length";
        }
        if (p.length() < 12) {
            return "too-short";
        }
        if (p.startsWith(" ")) {
            return "leading-space";
        }
        if (p.endsWith(" ")) {
            return "trailing-space";
        }
        if (p.indexOf('\t') >= 0) {
            return "tab-containing";
        }
        if (p.indexOf('\n') >= 0) {
            return "newline-containing";
        }
        if (p.indexOf('\0') >= 0) {
            return "NUL-containing";
        }
        return "control-character";
    }

    // ---------------------------------------------------------------- rule 4: tokens

    private static void tokens() {
        T.section("session token shape");
        String good = "a".repeat(64);
        T.eq("accepts 64 lowercase hex", good, tokenOrThrow(good));
        yes("refuses uppercase hex", tokenRejected("A".repeat(64)));
        yes("refuses 63 hex", tokenRejected("a".repeat(63)));
        yes("refuses 65 hex", tokenRejected("a".repeat(65)));
        yes("refuses non-hex", tokenRejected("g".repeat(64)));
        yes("refuses empty", tokenRejected(""));
        yes("refuses null", tokenRejected(null));
        yes("refuses embedded newline", tokenRejected("a".repeat(32) + "\n" + "a".repeat(31)));
        yes("refuses a uuid-shaped token",
                tokenRejected("550e8400-e29b-41d4-a716-446655440000"));

        // Rule 4: tokens come from this code, are 256-bit, and show no exploitable structure.
        java.util.Set<String> seen = new java.util.HashSet<>();
        int distinctFirstBytes = 0;
        java.util.Set<Byte> firstBytes = new java.util.HashSet<>();
        for (int i = 0; i < 200; i++) {
            byte[] raw = CryptoUtils.randomBytes(32);
            String hex = CryptoUtils.toHex(raw);
            seen.add(hex);
            firstBytes.add(raw[0]);
            T.eq("token is 256 bits", 64, hex.length());
        }
        T.eq("200 tokens are all distinct", 200, seen.size());
        T.inRange("first byte varies across draws", firstBytes.size(), 20, 256);
        System.out.println("NOTE distinct-first-bytes=" + firstBytes.size() + " of 200 draws");
    }

    private static String tokenOrThrow(String raw) {
        try {
            return InputValidator.requireSessionToken(raw);
        } catch (InputValidator.ValidationException e) {
            return "!rejected:" + e.getMessage();
        }
    }

    private static boolean tokenRejected(String raw) {
        try {
            InputValidator.requireSessionToken(raw);
            return false;
        } catch (InputValidator.ValidationException e) {
            return true;
        }
    }

    // ---------------------------------------------------------------- rule 1: identifiers

    private static void identifiers() {
        T.section("SQL identifier allowlist");
        String[] ok = {"auth_accounts", "app_auth_store", "_legacy2", "Auth_Accounts"};
        for (String s : ok) {
            no("accepts " + s, identRejected(s));
        }
        String[] bad = {
            "", "a".repeat(31), "1leading", "has space", "has-dash", "has;semicolon",
            "quote\"inside", "back`tick", "select", "TABLE", "user", "IN", "or", "null",
            "information_schema", "sa", "dba", "exec", "runscript", "shutdown",
            "a\u0001b", "x\0y",
        };
        for (String s : bad) {
            yes("refuses [" + s.replace('\0', 'N').replace('\u0001', 'C') + "]", identRejected(s));
        }
    }

    private static boolean identRejected(String s) {
        try {
            InputValidator.requireSqlIdentifier(s);
            return false;
        } catch (InputValidator.ValidationException e) {
            return true;
        }
    }

    private static void sourceIds() {
        T.section("source label allowlist");
        no("accepts local-cli", sourceRejected("local-cli"));
        no("accepts tenant_7", sourceRejected("tenant_7"));
        yes("refuses leading dash", sourceRejected("-leading"));
        yes("refuses space", sourceRejected("two words"));
        yes("refuses path separator", sourceRejected("../etc"));
        yes("refuses quote", sourceRejected("a'b"));
        yes("refuses newline", sourceRejected("a\nb"));
        yes("refuses empty", sourceRejected(""));
        yes("refuses over 48", sourceRejected("s".repeat(49)));
    }

    private static boolean sourceRejected(String s) {
        try {
            InputValidator.requireSourceId(s);
            return false;
        } catch (InputValidator.ValidationException e) {
            return true;
        }
    }

    // ---------------------------------------------------------------- rule 6: ranges

    private static void integers() {
        T.section("numeric configuration");
        T.eq("plain decimal accepted", 210000, parseInt("210000", 1, 999999));
        T.eq("leading zeros parse then range-check", 210000, parseInt("0210000", 1, 999999));
        T.eq("leading zeros cannot escape the range", -1, parseInt("0900", 100, 500));
        T.eq("plus sign refused", -1, parseInt("+5", 1, 9));
        T.eq("minus refused", -1, parseInt("-5", 1, 9));
        T.eq("hex refused", -1, parseInt("0x10", 1, 99));
        T.eq("empty refused", -1, parseInt("", 1, 9));
        T.eq("null refused", -1, parseInt(null, 1, 9));
        T.eq("space refused", -1, parseInt(" 5", 1, 9));
        T.eq("word refused", -1, parseInt("five", 1, 9));
        T.eq("float refused", -1, parseInt("5.0", 1, 9));
        T.eq("below range refused (never clamped upward)", -1, parseInt("1", 100, 200));
        T.eq("above range refused (never clamped downward)", -1, parseInt("300", 100, 200));
        T.eq("in range accepted", 150, parseInt("150", 100, 200));
        T.eq("10 digits refused", -1, parseInt("10000000000", 1, 999999999));
    }

    private static int parseInt(String raw, int min, int max) {
        try {
            return InputValidator.requireInt(raw, "cfg", min, max);
        } catch (InputValidator.ValidationException e) {
            return -1;
        }
    }

    // ---------------------------------------------------------------- rule 1: paths

    private static void dbPaths() {
        T.section("database path validation");
        no("accepts a plain absolute path", pathRejected("/var/lib/authdb/store"));
        String[] bad = {
            null, "", "relative/store", "/var/lib/authdb/", "/var/lib/a/../b/store",
            "/var/lib/store;INIT=RUNSCRIPT FROM 'file:///tmp/x.sql'",
            "/var/lib/store=1", "/var/lib/store\n/etc/passwd", "/var/lib/st\u0001ore",
            "/var/lib/store\u00e9", "/var/lib/" + "d".repeat(600) + "/store",
            "/var/lib/store\t", "/var/ lib/store",
        };
        for (String s : bad) {
            yes("refuses " + (s == null ? "null" : "[" + s.replace('\n', 'N').replace('\t', 'T')
                    .replace('\u0001', 'C') + "]"), pathRejected(s));
        }
    }

    private static boolean pathRejected(String s) {
        try {
            InputValidator.requireDbPath(s);
            return false;
        } catch (InputValidator.ValidationException e) {
            return true;
        }
    }

    // ---------------------------------------------------------------- crypto

    private static void crypto() {
        T.section("crypto helpers");
        byte[] b = CryptoUtils.randomBytes(32);
        String hex = CryptoUtils.toHex(b);
        T.eq("hex round-trips", true, CryptoUtils.constantTimeEquals(b, CryptoUtils.fromHex(hex)));
        T.eq("hex is lowercase", hex, hex.toLowerCase(java.util.Locale.ROOT));
        T.eq("32 bytes is 64 hex chars", 64, hex.length());
        yes("odd-length hex refused", hexRejected("abc"));
        yes("empty hex is zero bytes", CryptoUtils.fromHex("").length == 0);
        yes("non-hex character refused", hexRejected("zz"));
        yes("null hex refused", hexRejected(null));
        // Regression guard: an inverted parity check here silently rejects every valid digest, which
        // makes a correctly stored credential unreadable (observed as db_row_rejected).
        no("32-byte digest hex accepted", hexRejected("0".repeat(64)));

        byte[] x = CryptoUtils.sha256("abc");
        T.eq("sha256 length", 32, x.length);
        T.eq("sha256 known vector",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                CryptoUtils.toHex(x));
        T.eq("sha256 of utf-8 is byte-exact",
                CryptoUtils.toHex(CryptoUtils.sha256("caf\u00e9".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8))),
                CryptoUtils.toHex(CryptoUtils.sha256("caf\u00e9")));

        yes("equal arrays compare equal",
                CryptoUtils.constantTimeEquals(new byte[]{1, 2, 3}, new byte[]{1, 2, 3}));
        no("differing content is unequal",
                CryptoUtils.constantTimeEquals(new byte[]{1, 2, 3}, new byte[]{1, 2, 4}));
        no("prefix is unequal even though shorter is a prefix",
                CryptoUtils.constantTimeEquals(new byte[]{1, 2}, new byte[]{1, 2, 0}));
        no("empty vs non-empty unequal",
                CryptoUtils.constantTimeEquals(new byte[0], new byte[]{0}));
        yes("null handled safely", !CryptoUtils.constantTimeEquals(null, new byte[]{0}));
        yes("null vs null not equal (no accidental grant)",
                !CryptoUtils.constantTimeEquals(null, null));

        // Wipe actually clears the caller's buffer.
        byte[] secret = CryptoUtils.randomBytes(16);
        CryptoUtils.wipe(secret);
        T.eq("wipe zeroes a byte buffer", true, allZero(secret));
        char[] chars = "secret-value".toCharArray();
        CryptoUtils.wipe(chars);
        T.eq("wipe zeroes a char buffer", true, allZeroChars(chars));
    }

    private static boolean hexRejected(String s) {
        try {
            CryptoUtils.fromHex(s);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private static boolean allZero(byte[] a) {
        for (byte v : a) {
            if (v != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean allZeroChars(char[] a) {
        for (char c : a) {
            if (c != 0) {
                return false;
            }
        }
        return true;
    }

    // ---------------------------------------------------------------- rule 5: masking

    private static void masking() {
        T.section("log masking");
        T.eq("masks the mailbox name", "a***@example.com",
                LogWriter.maskEmail("alice@example.com"));
        T.eq("masks a long local part", "a***@example.com",
                LogWriter.maskEmail("alice.bob.carol.dave@example.com"));
        T.eq("keeps a digit start", "1***@example.com", LogWriter.maskEmail("12345@example.com"));
        T.eq("null collapses", "*", LogWriter.maskEmail(null));
        T.eq("no at sign collapses", "*", LogWriter.maskEmail("alice.example.com"));
        T.eq("two at signs collapse", "*", LogWriter.maskEmail("a@b@example.com"));
        T.eq("empty local collapses", "*", LogWriter.maskEmail("@example.com"));
        T.eq("empty domain collapses", "*", LogWriter.maskEmail("alice@"));
        T.eq("uppercase collapses (never echoes unvalidated input)", "*",
                LogWriter.maskEmail("Alice@Example.com"));
        T.eq("symbol-leading local collapses", "*", LogWriter.maskEmail("+evil@example.com"));
        T.eq("over-long local collapses", "*",
                LogWriter.maskEmail("a".repeat(65) + "@example.com"));
        T.eq("domain with control char collapses", "*",
                LogWriter.maskEmail("alice@example\u0001.com"));
        yes("masked output never contains the local part",
                !LogWriter.maskEmail("supersecretnname@example.com").contains("supersecretnname"));
        yes("masked output never contains a password",
                !LogWriter.maskEmail("Winters-Vector-44@example.com")
                        .contains("Winters-Vector-44"));
    }

    private static void logSanitisation() {
        T.section("log line sanitisation");
        T.eq("plain line passes", "ev=login_denied acct=a***@example.com n=0",
                LogWriter.sanitize("ev=login_denied acct=a***@example.com n=0"));
        T.eq("newline dropped", "log_line_rejected",
                LogWriter.sanitize("ev=ok\nINJECTED=1"));
        T.eq("carriage return dropped", "log_line_rejected",
                LogWriter.sanitize("ev=ok\r\nINJECTED=1"));
        T.eq("null dropped", "log_line_rejected", LogWriter.sanitize("ev=ok\0"));
        T.eq("tab dropped", "log_line_rejected", LogWriter.sanitize("ev=ok\tx"));
        T.eq("backslash dropped", "log_line_rejected", LogWriter.sanitize("ev=ok\\x"));
        T.eq("non-ASCII dropped", "log_line_rejected", LogWriter.sanitize("ev=caf\u00e9"));
        T.eq("empty dropped", "log_line_rejected", LogWriter.sanitize(""));
        T.eq("null dropped as line", "log_line_rejected", LogWriter.sanitize(null));
        T.eq("over-long dropped", "log_line_rejected", LogWriter.sanitize("a".repeat(400)));
        T.eq("ansi escape dropped", "log_line_rejected", LogWriter.sanitize("ev=\u001b[2J"));
        // The reason-code parameter is restricted to this program's own tokens.
        Path dir;
        try {
            dir = T.scratch("logcode");
        } catch (IOException e) {
            T.yes("scratch dir creatable", false);
            return;
        }
        try (LogWriter w = LogWriter.open(dir.resolve("a.log"))) {
            w.log(LogWriter.Event.LOGIN_DENIED, "a***@example.com", "credential_match");
            w.log(LogWriter.Event.LOGIN_DENIED, "a***@example.com",
                    "credential_match\nINJECTED=1");
            w.log(LogWriter.Event.LOGIN_DENIED, "a***@example.com", "VALUE=secret");
            w.log(LogWriter.Event.LOGIN_DENIED, "a***@example.com", null);
        } catch (IOException e) {
            T.yes("log opens", false);
            return;
        }
        String content;
        try {
            content = T.read(dir.resolve("a.log"));
        } catch (IOException e) {
            T.yes("log readable", false);
            return;
        }
        int lines = content.split("\n", -1).length - (content.endsWith("\n") ? 1 : 0);
        T.eq("one physical line per event (no injection)", 4, lines);
        yes("injected newline never reached the file", !content.contains("INJECTED"));
        yes("uppercase reason replaced", content.contains("reason=code_unavailable"));
        yes("legitimate reason kept", content.contains("reason=credential_match"));
        System.out.println("NOTE log lines written=" + lines);
    }

    private static void logFilePermissions() throws IOException {
        T.section("audit file permissions (rule 2/5)");
        Path dir = T.scratch("logfile");
        Path file = dir.resolve("store.audit.log");
        try (LogWriter w = LogWriter.open(file)) {
            w.log(LogWriter.Event.BOOT_OK, "*", 0);
        }
        T.eq("audit file is 0600", "rw-------", T.mode(file));
        T.eq("scratch dir is 0700", "rwx------", T.mode(dir));

        // A pre-existing group-readable log is refused rather than silently tightened.
        Path dir2 = T.scratch("logfile2");
        Path loose = dir2.resolve("loose.log");
        Files.writeString(loose, "x");
        Files.setPosixFilePermissions(loose,
                java.util.EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.GROUP_READ));
        yes("refuses a group-readable audit log", logOpenRejected(loose));

        Path dir3 = T.scratch("logfile3");
        Path other = dir3.resolve("o.log");
        Files.writeString(other, "x");
        Files.setPosixFilePermissions(other,
                java.util.EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OTHERS_READ));
        yes("refuses a world-readable audit log", logOpenRejected(other));

        // Re-opening an existing 0600 log appends rather than truncating: the audit trail survives.
        try (LogWriter w = LogWriter.open(file)) {
            w.log(LogWriter.Event.LOGIN_DENIED, "b***@example.com", 0);
        }
        String content = T.read(file);
        yes("existing log line survives a re-open", content.contains("ev=boot_ok"));
        yes("new line appended", content.contains("ev=login_denied"));
        T.eq("still 0600 after re-open", "rw-------", T.mode(file));

        // A world-writable or group-writable directory is refused even if the file would be private.
        Path dir4 = T.scratch("logfile4");
        Path sub = dir4.resolve("open");
        Files.createDirectory(sub);
        Files.setPosixFilePermissions(sub,
                java.util.EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.OTHERS_WRITE));
        yes("refuses a world-writable log directory", logOpenRejected(sub.resolve("x.log")));

        // Byte cap: a flood cannot grow the file without bound.
        Path dir5 = T.scratch("logfile5");
        Path capped = dir5.resolve("cap.log");
        long before = System.currentTimeMillis();
        try (LogWriter w = LogWriter.open(capped)) {
            for (int i = 0; i < 200_000; i++) {
                w.log(LogWriter.Event.LOGIN_DENIED, "a***@example.com", i);
            }
            T.inRange("cap reached (writes bounded)", w.bytesWritten(), 1, 4 * 1024 * 1024 + 64);
            System.out.println("NOTE audit bytes after 200000 events=" + w.bytesWritten()
                    + " in " + (System.currentTimeMillis() - before) + " ms");
        }
        T.inRange("audit file size bounded on disk", Files.size(capped), 1, 4 * 1024 * 1024 + 64);
    }

    private static boolean logOpenRejected(Path p) {
        try (LogWriter w = LogWriter.open(p)) {
            w.log(LogWriter.Event.BOOT_OK, "*", 0);
            return false;
        } catch (IOException | RuntimeException e) {
            return true;
        }
    }

    // ---------------------------------------------------------------- rule 2/6: configuration

    private static void configuration() throws Exception {
        T.section("configuration refuses instead of defaulting");
        Path dir = T.scratch("cfg");
        String db = dir.resolve("store").toString();

        yes("missing db path refused", configRejected(Map.of("AUTH_DB_USER", "authsvc")));
        yes("missing db user refused", configRejected(Map.of("AUTH_DB_PATH", db)));
        yes("empty db path refused",
                configRejected(Map.of("AUTH_DB_PATH", "", "AUTH_DB_USER", "authsvc")));
        yes("relative db path refused",
                configRejected(Map.of("AUTH_DB_PATH", "store", "AUTH_DB_USER", "authsvc")));
        yes("db path with semicolon refused", configRejected(
                Map.of("AUTH_DB_PATH", db + ";INIT=RUNSCRIPT FROM 'x'", "AUTH_DB_USER", "authsvc")));
        yes("db user as keyword refused",
                configRejected(Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "user")));
        yes("db user with injection refused",
                configRejected(Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "a\"; DROP TABLE t;--")));
        yes("iterations below floor refused", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_ITERATIONS", "100")));
        yes("iterations above ceiling refused", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_ITERATIONS",
                        "1500001")));
        yes("iterations non-numeric refused", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_ITERATIONS", "auto")));
        yes("out-of-range window refused, not clamped", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_IDENTITY_WINDOW_SEC",
                        "5")));
        yes("session ttl out of range refused", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_SESSION_TTL_SEC", "1")));
        yes("emit_session non-boolean refused", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_EMIT_SESSION", "yes")));
        yes("duplicate table names refused", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_THROTTLE_TABLE",
                        "auth_accounts")));
        yes("source budget smaller than account budget refused", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_IDENTITY_MAX_FAILURES",
                        "50", "AUTH_SOURCE_MAX_ATTEMPTS", "10")));
        yes("password minimum below policy floor refused", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_PASSWORD_MIN_LENGTH",
                        "4")));
        yes("anti-timing floor switchable off refused", configRejected(
                Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc", "AUTH_MIN_LOGIN_MS", "0")));

        // Valid configuration loads, and the credential is retrievable exactly once.
        Config c = Config.load(Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc",
                "AUTH_DB_PASSWORD", "storage-cred-for-local-testing-only"));
        T.eq("db path kept verbatim", db, c.dbPath());
        T.eq("default iterations", 210_000, c.iterations());
        T.eq("default account budget", 8, c.identityMaxFailures());
        T.eq("default source budget", 120, c.sourceMaxAttempts());
        T.eq("default session ttl", 900, c.sessionTtlSec());
        T.eq("default minimum floor", 1000, c.minLoginMs());
        T.eq("session emission defaults off", false, c.emitSession());
        char[] first = c.takeDbPassword();
        T.eq("credential delivered", 35, first.length);
        T.eq("credential delivered once", 0, c.takeDbPassword().length);
        T.eq("credential no longer reported", false, c.hasConfiguredDbPassword());

        // No configured credential is an acceptable state: Main must refuse (asserted in E2ETests).
        Config bare = Config.load(Map.of("AUTH_DB_PATH", db, "AUTH_DB_USER", "authsvc"));
        T.eq("absent credential is empty, not a default", 0, bare.takeDbPassword().length);

        // Nothing in a config exception or in Config's own text carries a configured value.
        String code = configCode(Map.of("AUTH_DB_PATH", "/tmp/writable-secret-value",
                "AUTH_DB_USER", "authsvc", "AUTH_ITERATIONS", "7"));
        yes("config error names the setting, not the value",
                code.contains("iterations") && !code.contains("writable-secret-value")
                        && !code.contains("7"));
    }

    private static boolean configRejected(Map<String, String> env) {
        try {
            Config.load(env);
            return false;
        } catch (Config.ConfigException e) {
            return true;
        }
    }

    private static String configCode(Map<String, String> env) {
        try {
            Config.load(env);
            return "!accepted";
        } catch (Config.ConfigException e) {
            return e.getMessage();
        }
    }

    // ------------------------------------------------ source text audits (invariant guards)

    private static void sourceTextAudits() throws Exception {
        T.section("source text invariants");
        Map<String, String> sources = mainSources();
        T.inRange("every main class found", sources.size(), 9, 40);

        int sqlish = 0;
        for (Map.Entry<String, String> e : sources.entrySet()) {
            String body = stripComments(e.getValue());
            // Every SQL string literal must contain at most the fixed literals plus quoted
            // identifiers. A value must reach the statement only through a bind parameter.
            for (String lit : stringLiterals(body)) {
                String up = lit.toUpperCase(java.util.Locale.ROOT);
                if (!(up.contains("SELECT") || up.contains("INSERT") || up.contains("UPDATE")
                        || up.contains("DELETE") || up.contains("CREATE TABLE")
                        || up.contains("ALTER TABLE"))) {
                    continue;
                }
                sqlish++;
                // A '+' inside the literal, or a %s, would mean a value is being concatenated in.
                T.no(e.getKey() + ": sql literal has no embedded placeholder ["
                        + abbrev(lit) + "]", lit.contains("%s") || lit.contains("%d"));
                // Only validated identifiers may be concatenated; assert no concatenation happens
                // inside the literal itself and that no statement ends in a stray quote char.
                T.no(e.getKey() + ": sql literal has no raw quote char [" + abbrev(lit) + "]",
                        lit.contains("'"));
            }
        }
        T.inRange("sql literals inspected", sqlish, 12, 200);
        System.out.println("NOTE sql literals inspected=" + sqlish + " over "
                + sources.size() + " files");

        // No dynamic SQL built by concatenating a method parameter that is not a table name.
        for (Map.Entry<String, String> e : sources.entrySet()) {
            String body = stripComments(e.getValue());
            for (String line : body.split("\n", -1)) {
                String l = line.trim();
                if (!l.contains("+")) {
                    continue;
                }
                boolean sqly = l.toUpperCase(java.util.Locale.ROOT).contains("SELECT ")
                        || l.toUpperCase(java.util.Locale.ROOT).contains("INSERT ")
                        || l.toUpperCase(java.util.Locale.ROOT).contains("UPDATE ")
                        || l.toUpperCase(java.util.Locale.ROOT).contains("DELETE ")
                        || l.toUpperCase(java.util.Locale.ROOT).contains("WHERE ");
                if (!sqly) {
                    continue;
                }
                // Allowed operands are the quoted table-name fields and the literal text itself.
                String stripped = l.replaceAll("\"[^\"]*\"", "");
                for (String operand : stripped.split("[+=;,()]")) {
                    String id = operand.trim();
                    if (id.isEmpty() || !id.matches("[A-Za-z_][A-Za-z0-9_.]*")) {
                        continue;
                    }
                    String leaf = id.contains(".") ? id.substring(id.lastIndexOf('.') + 1) : id;
                    T.no("sql concatenation uses only table-name fields (found " + leaf + ")",
                            leaf.contains("email") || leaf.contains("password")
                                    || leaf.contains("salt") || leaf.contains("digest")
                                    || leaf.contains("token") || leaf.contains("source")
                                    || leaf.contains("hash") || leaf.contains("key"));
                }
            }
        }

        // The credential must never become a String. PasswordHasher does build Strings (hex digests
        // and salts), so the invariant is asserted per line: no line may turn a password-shaped
        // expression into a String, and no method may take the credential as a String.
        int stringLines = 0;
        for (Map.Entry<String, String> e : sources.entrySet()) {
            for (String line : stripComments(e.getValue()).split("\n", -1)) {
                String l = line.trim();
                if (l.contains("new String(")) {
                    stringLines++;
                    T.no(e.getKey() + ": no String built from the login credential ["
                            + abbrev(l) + "]",
                            l.contains("(password") || l.contains("(pw") || l.contains("(first")
                                    || l.contains("(again") || l.contains("(currentPassword"));
                }
                // Per-line so a (?s) match cannot span from an unrelated "String" to a later
                // "password" word in a different declaration.
                T.no(e.getKey() + ": no String-typed credential declaration [" + abbrev(l) + "]",
                        l.matches(".*(String|CharSequence)\\s+(password|passwd|pw|secret)\\b.*")
                                && !l.contains("dbPassword"));
                T.no(e.getKey() + ": no printf of a credential [" + abbrev(l) + "]",
                        l.matches(".*(printf|format)\\(.*password.*") && !l.contains("//"));
            }
        }
        T.inRange("String constructions all inspected", stringLines, 1, 40);
        System.out.println("NOTE new String( occurrences audited=" + stringLines);
        // Database.java holds exactly one String password: the JDBC handoff, immediately consumed.
        String dbBody = stripComments(sources.get("Database.java"));
        T.eq("Database has one String password handoff", 1, count(dbBody, "new String(dbPassword"));
        yes("that String is handed to the driver property",
                dbBody.contains("props.setProperty(\"password\", jdbcPassword)"));

        // No secret is printed. Per line: a (?s) match across the file would flag any file that
        // merely contains both a println and the word "salt" somewhere.
        for (Map.Entry<String, String> e : sources.entrySet()) {
            for (String line : stripComments(e.getValue()).split("\n", -1)) {
                String l = line.toLowerCase(java.util.Locale.ROOT);
                boolean prints = l.contains("system.out.print") || l.contains("system.err.print")
                        || l.contains("err.print") || l.contains("out.print");
                if (!prints) {
                    continue;
                }
                T.no(e.getKey() + ": printed line carries no credential value [" + abbrev(l) + "]",
                        l.matches(".*(password|dbpassword|salt|digest|secret|first|again)"
                                + "(\\b|\\().*"));
            }
        }

        // Rule 7: the reservation must take a row lock and must be inside a transaction.
        String throttle = stripComments(sources.get("ThrottleStore.java"));
        yes("reservation locks the budget row", throttle.contains("FOR UPDATE"));
        yes("reservation commits explicitly", throttle.contains("connection.commit()"));
        yes("reservation rolls back on refusal", throttle.contains("rollback()"));
        yes("reservation sorts lock order", throttle.contains("sort(Comparator.comparing"));
        yes("reservation serialises on the shared connection",
                throttle.contains("synchronized (connection)"));
        yes("throttle turns auto-commit off for the reservation",
                throttle.contains("setAutoCommit(false)"));
        yes("throttle restores auto-commit afterwards", throttle.contains("setAutoCommit(true)"));
        yes("refund is one conditional statement",
                throttle.contains("used = used - 1") && throttle.contains("AND used > 0"));

        // Rule 4: no session token may be generated from anything but SecureRandom.
        String sessions = stripComments(sources.get("SessionStore.java"));
        yes("token drawn through CryptoUtils.randomBytes",
                sessions.contains("CryptoUtils.randomBytes(32)"));
        yes("token not built from time or uuid",
                !sessions.contains("nanoTime") && !sessions.contains("UUID"));
        yes("only the token hash is bound to the statement",
                sessions.contains("CryptoUtils.sha256(token)"));
        int tokenBinds = 0;
        for (String line : sessions.split("\n", -1)) {
            if (line.contains("setString")) {
                tokenBinds++;
                yes("a bound value is the hash, never the raw token",
                        line.contains("sha256(token)") || line.contains("identityId")
                                || line.contains("sourceId"));
            }
        }
        System.out.println("NOTE session store bind sites=" + tokenBinds);

        // Rule 8: the only non-JDK thing on the classpath is the pinned database engine, and no
        // source file imports it - it is reached solely through java.sql.
        int importLines = 0;
        for (Map.Entry<String, String> e : sources.entrySet()) {
            for (String line : e.getValue().split("\n", -1)) {
                String l = line.trim();
                if (!l.startsWith("import ")) {
                    continue;
                }
                importLines++;
                String target = l.substring("import ".length()).replace("static ", "").trim();
                int dot = target.indexOf('.');
                String top = dot < 0 ? target : target.substring(0, dot);
                yes(e.getKey() + ": import from an expected namespace (" + top + ")",
                        "java".equals(top) || "javax".equals(top) || "com".equals(top));
                no(e.getKey() + ": no third-party crypto import",
                        l.contains("bcrypt") || l.contains("argon") || l.contains("scrypt")
                                || l.contains("bouncycastle") || l.contains("commons"));
            }
        }
        T.inRange("import statements audited", importLines, 30, 400);
        System.out.println("NOTE import lines audited=" + importLines);
        // The engine is referenced only by URL string and through java.sql interfaces.
        // Exactly one place prints a bearer token, and only inside the operator's emit flag.
        String mainBody = stripComments(sources.get("Main.java"));
        String[] mainLines = mainBody.split("\n", -1);
        int guardLine = -1;
        int printLines = 0;
        for (int i = 0; i < mainLines.length; i++) {
            String l = mainLines[i];
            if (l.contains("config.emitSession()") && l.contains("sessionToken")) {
                guardLine = i;
            }
            if (l.contains("result.sessionToken") && !l.contains("emitSession")) {
                printLines++;
                yes("the bearer-token print sits inside the emit guard (line " + i + ")",
                        guardLine >= 0 && i > guardLine && i - guardLine <= 6);
            }
        }
        T.eq("there is an emit guard for the token", true, guardLine >= 0);
        T.eq("exactly one bearer-token print site", 1, printLines);
        yes("the token is never written to the audit log",
                !stripComments(sources.get("LogWriter.java")).contains("sessionToken"));
        yes("no log event text mentions a token value",
                !stripComments(sources.get("LogWriter.java")).contains("token_hash"));
        yes("database reached through java.sql only",
                !stripComments(sources.get("Database.java")).contains("import org.h2"));
    }

    private static Map<String, String> mainSources() throws IOException {
        Path root = Path.of(System.getProperty("auth.src.root", "src/main/java"));
        Map<String, String> out = new LinkedHashMap<>();
        if (!Files.isDirectory(root)) {
            T.yes("main sources found at " + root.toAbsolutePath(), false);
            return out;
        }
        List<Path> files = new ArrayList<>();
        Files.walk(root).filter(p -> p.toString().endsWith(".java")).forEach(files::add);
        for (Path p : files) {
            String name = p.getFileName().toString();
            String body = Files.readString(p);
            T.yes("read " + name + " (" + body.length() + " bytes)", body.length() > 200);
            out.put(name, body);
        }
        return out;
    }

    /** Removes comments so prose in them cannot trip a banned-pattern check. */
    static String stripComments(String body) {
        StringBuilder sb = new StringBuilder(body.length());
        int i = 0;
        int n = body.length();
        while (i < n) {
            char c = body.charAt(i);
            if (c == '"') {
                sb.append(c);
                i++;
                while (i < n) {
                    char d = body.charAt(i);
                    sb.append(d);
                    i++;
                    if (d == '\\') {
                        if (i < n) {
                            sb.append(body.charAt(i));
                            i++;
                        }
                    } else if (d == '"') {
                        break;
                    }
                }
                continue;
            }
            if (c == '\'' && i + 2 < n && body.charAt(i + 1) == '\\') {
                sb.append(body, i, Math.min(i + 4, n));
                i += 4;
                continue;
            }
            if (c == '/' && i + 1 < n && body.charAt(i + 1) == '/') {
                while (i < n && body.charAt(i) != '\n') {
                    i++;
                }
                continue;
            }
            if (c == '/' && i + 1 < n && body.charAt(i + 1) == '*') {
                i += 2;
                while (i + 1 < n && !(body.charAt(i) == '*' && body.charAt(i + 1) == '/')) {
                    i++;
                }
                i += 2;
                continue;
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    /** Extracts double-quoted string literals, concatenation-blind. */
    static List<String> stringLiterals(String body) {
        List<String> out = new ArrayList<>();
        int i = 0;
        while (i < body.length()) {
            char c = body.charAt(i);
            if (c != '"') {
                i++;
                continue;
            }
            StringBuilder sb = new StringBuilder();
            i++;
            while (i < body.length()) {
                char d = body.charAt(i);
                if (d == '\\') {
                    i += 2;
                    continue;
                }
                if (d == '"') {
                    i++;
                    break;
                }
                sb.append(d);
                i++;
            }
            out.add(sb.toString());
        }
        return out;
    }

    private static String abbrev(String s) {
        return s.length() <= 48 ? s : s.substring(0, 48) + "...";
    }

    private static int count(String haystack, String needle) {
        int n = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + 1)) {
            n++;
        }
        return n;
    }
}
