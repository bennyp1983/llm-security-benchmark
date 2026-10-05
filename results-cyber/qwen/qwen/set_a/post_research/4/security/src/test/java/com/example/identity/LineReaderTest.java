package com.example.identity;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.section;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The CLI's stdin reader, which is the only thing standing between a pipe and the password.
 *
 * <p>Two of its properties cannot be shown by driving {@code PortalCli} with canned input: whether
 * the secret ever became an un-erasable {@code String}, and whether the reader over-read the pipe.
 * Both are invisible once the process exits - which is exactly why the previous implementation,
 * which did both, passed the whole suite. So they are checked where they live: against the decoder
 * byte for byte, and against the source shape of the secret path.
 *
 * <h2>What "matches the platform" claims, and what it deliberately does not</h2>
 * The reader hand-decodes UTF-8, so the risk is that some input changes <em>meaning</em>. Every
 * well-formed sequence is compared against {@code new String(bytes, UTF_8)} - the old
 * implementation's answer - and must be identical, which is the claim that matters: no password or
 * identifier that used to validate can validate differently now.
 *
 * <p>For malformed input the two decoders agree on the 2-byte family and not on the number of
 * U+FFFDs in the 3- and 4-byte families (the JDK restarts its error action one byte earlier than a
 * conforming decoder at {@code E0}/{@code ED}/{@code F0}/{@code F4} leads; measured, and recorded
 * in the notes this suite prints). That difference cannot reach a security outcome - a decoded
 * U+FFFD makes an identifier non-ASCII and therefore refused by {@link Identity} either way, and on
 * the password path it only changes which wrong-password hash gets computed - so it is <em>not</em>
 * asserted away, and asserting it would only freeze a JDK quirk. What is asserted for malformed
 * input is the set of properties that do matter: it never throws, it never invents a character the
 * bytes did not contain, it never leaves an unpaired surrogate, it is deterministic, it is always
 * refused as an identifier, and it consumes exactly up to the terminator so the next prompt stays
 * aligned.
 */
public final class LineReaderTest {

    private LineReaderTest() {
    }

    private static String text(char[] c) {
        return new String(c);
    }

    private static byte[] rawBytes(int... unsigned) {
        byte[] b = new byte[unsigned.length];
        for (int i = 0; i < unsigned.length; i++) {
            b[i] = (byte) unsigned[i];
        }
        return b;
    }

    private static byte[] bytes(String utf8) {
        return utf8.getBytes(StandardCharsets.UTF_8);
    }

    private static InputStream pipe(int... unsigned) {
        return new ByteArrayInputStream(rawBytes(unsigned));
    }

    private static int[] ascii(String s) {
        int[] v = new int[s.length()];
        for (int i = 0; i < s.length(); i++) {
            v[i] = s.charAt(i);
        }
        return v;
    }

    /** Reads one secret line from raw bytes, so a malformed sequence can be fed exactly. */
    private static char[] readSecret(int maxChars, int... unsigned) {
        try {
            return new LineReader(pipe(unsigned)).readSecretChars(maxChars);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String readLine(int maxChars, int... unsigned) throws IOException {
        return new LineReader(pipe(unsigned)).readLine(maxChars);
    }

    private static char[] readSecretBytes(int maxChars, byte[] raw) {
        try {
            return new LineReader(new ByteArrayInputStream(raw)).readSecretChars(maxChars);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** What the platform decoder produced for the same bytes, up to the first newline. */
    private static String platform(int... unsigned) {
        String s = new String(rawBytes(unsigned), StandardCharsets.UTF_8);
        int nl = s.indexOf('\n');
        return nl >= 0 ? s.substring(0, nl) : s;
    }

    private static String hex(int... b) {
        StringBuilder sb = new StringBuilder();
        for (int v : b) {
            sb.append(String.format("%02X", v & 0xFF)).append(' ');
        }
        return sb.toString().trim();
    }

    private static String codePoints(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            sb.append(String.format("%04X ", (int) s.charAt(i)));
        }
        return sb.toString().trim();
    }

    private static int[] withLf(int... b) {
        int[] v = Arrays.copyOf(b, b.length + 1);
        v[b.length] = 0x0A;
        return v;
    }

    /** Malformed forms, without their terminator. */
    private static final int[][] MALFORMED = {
            {0xF4, 0x90, 0x80, 0x80},                   // above U+10FFFF
            {0xF5, 0x80, 0x80, 0x80},                   // lead that is never legal
            {0xF0, 0x8F, 0xBF, 0xBF},                   // overlong 4-byte
            {0xC0, 0xAF},                               // overlong '/'
            {0xC1, 0x9C},                               // overlong U+001C
            {0xE0, 0x80, 0xAF},                         // overlong 3-byte
            {0xED, 0xA0, 0x80},                         // encoded surrogate D800
            {0xED, 0xBF, 0xBF},                         // encoded surrogate DFFF
            {0x80, 0x80, 0x80},                         // stray continuation bytes
            {0xE2, 0x82},                               // truncated at EOF
            {0xF0, 0x9F, 0x98},                         // astral sequence truncated at EOF
    };

    /**
     * Legal single bytes that are hostile for other reasons. They are <em>not</em> malformed UTF-8,
     * so the reader must pass them through unchanged and the layers above must be the ones that
     * refuse them - a reader that "cleaned" a NUL away would be substituting a permissive default.
     */
    private static final int[][] HOSTILE_CONTROL = {
            {0x00, 0x41},                               // NUL inside the line
            {0x7F},                                     // DEL
            {0x09, 0x41},                               // TAB
            {0x1B, 0x41},                               // ESC, the terminal-control byte
            {0x00},                                     // a line that is nothing but NUL
    };

    public static void run() throws Exception {
        section("Whole lines, whichever terminator the pipe used");
        checkEquals("LF", "alice", readLine(64, ascii("alice\n")));
        checkEquals("CRLF is one terminator", "alice", readLine(64, ascii("alice\r\n")));
        checkEquals("lone CR terminates too", "alice", readLine(64, ascii("alice\r")));
        checkEquals("no trailing newline still yields the line", "alice", readLine(64, ascii("alice")));
        checkEquals("an empty line is an empty line, not end of input", "", readLine(64, 0x0A));
        check("end of input with nothing read is null, which the CLI reads as a refusal",
                readLine(64) == null);
        LineReader cr = new LineReader(pipe(0x0D, 0x62, 0x6F, 0x62, 0x0A));
        checkEquals("a leading CR ends an empty first line, as BufferedReader.readLine did",
                "", cr.readLine(64));
        checkEquals("and the bytes after the CR are the next line, not part of the first",
                "bob", cr.readLine(64));

        section("Nothing is over-read: the next read resumes at the very next byte");
        LineReader seq = new LineReader(pipe(ascii("alice\nPassw0rd-1\nstatus\n")));
        checkEquals("first line", "alice", seq.readLine(64));
        checkEquals("second line is what the first left, not a re-read of it",
                "Passw0rd-1", text(seq.readSecretChars(64)));
        checkEquals("third line", "status", seq.readLine(64));
        check("and then the stream is really at end", seq.readLine(64) == null);

        section("Over-long input is consumed to its terminator, then refused");
        // The alignment property, and a security property: returning on the first character past the
        // cap leaves the tail in the stream, so in the login flow the remainder of somebody's
        // over-long identifier would be read back as the password.
        ByteArrayOutputStream huge = new ByteArrayOutputStream();
        huge.write(filler());
        huge.write('\n');
        huge.write(bytes("alice\n"));
        byte[] hugePipe = huge.toByteArray();
        LineReader aligned = new LineReader(new ByteArrayInputStream(hugePipe));
        check("the over-long line is refused rather than truncated into a usable value",
                aligned.readLine(1024) == null);
        checkEquals("and the next prompt still gets its own line",
                "alice", aligned.readLine(1024));
        LineReader secretAligned = new LineReader(new ByteArrayInputStream(hugePipe));
        check("the secret path refuses an over-long line the same way, and does not return an empty"
                        + " array - which the caller would read as a blank password",
                secretAligned.readSecretChars(1024) == null);
        checkEquals("and it too leaves the stream aligned",
                "alice", secretAligned.readLine(1024));

        section("The cap is a hard refusal on both paths");
        checkEquals("exactly at the cap is accepted", "abcd", readLine(4, ascii("abcd")));
        check("one over the cap is refused", readLine(4, ascii("abcde")) == null);
        check("the secret path refuses too", readSecret(4, ascii("abcde")) == null);
        checkEquals("an astral character counts as its two UTF-16 units, the unit every length"
                        + " check in this project uses",
                2, readSecret(4, 0xF0, 0x9F, 0x98, 0x80, 0x0A).length);

        section("Well-formed UTF-8 decodes exactly as the platform decoder did");
        // The no-meaning-change claim: the old reader was new String(bytes, UTF_8), so any byte
        // sequence where the two disagree is an input whose password or identifier would now be
        // treated differently than before the reader changed.
        int[][] wellFormed = {
                {0x61, 0x0A},
                {0x41, 0x2E, 0x30, 0x2B, 0x0A},                     // "A.0+"
                {0xC3, 0xA9, 0x0A},                                 // U+00E9
                {0xE2, 0x82, 0xAC, 0x0A},                           // U+20AC
                {0xC2, 0x80, 0x0A},                                 // U+0080, first 2-byte
                {0xED, 0x9F, 0xBF, 0x0A},                           // U+D7FF, last BMP non-surrogate
                {0xEE, 0x80, 0x80, 0x0A},                           // U+E000, first after the block
                {0xF0, 0x90, 0x80, 0x80, 0x0A},                     // U+10000, first astral
                {0xF0, 0x9F, 0x98, 0x80, 0x0A},                     // U+1F600
                {0xF4, 0x8F, 0xBF, 0xBF, 0x0A},                     // U+10FFFF, last legal
                {0x20, 0x7E, 0x0A},                                 // space and '~'
        };
        for (int[] c : wellFormed) {
            char[] got = readSecret(4096, c);
            checkEquals("bytes " + hex(c) + " decode as the platform does ("
                            + codePoints(platform(c)) + ")",
                    platform(c), got == null ? null : text(got));
        }
        checkEquals("the Kelvin sign survives decoding as itself, which is why Identity has to"
                        + " refuse it before folding",
                "Kab\u212Aram", text(readSecretBytes(4096, bytes("Kab\u212Aram\n"))));
        check("and the validator really does refuse it rather than storing the folded substitute",
                Identity.parseClientUsername("Kab\u212Aram") == null);

        section("Malformed input: never throws, never smuggles, never misaligns");
        Set<String> invented = new LinkedHashSet<>();
        Set<String> loneSurrogate = new LinkedHashSet<>();
        Set<String> misaligned = new LinkedHashSet<>();
        Set<String> notRefused = new LinkedHashSet<>();
        Set<String> divergingFromPlatform = new LinkedHashSet<>();
        for (int[] raw : MALFORMED) {
            int[] c = withLf(raw);
            char[] once = readSecret(4096, c);
            char[] twice = readSecret(4096, c);
            if (once == null || twice == null) {
                invented.add(hex(c) + " -> refused as if it were end of input");
                continue;
            }
            String s = text(once);
            Set<Integer> fromInput = new HashSet<>();
            for (int b : c) {
                if ((b & 0xFF) < 0x80) {
                    fromInput.add(b & 0xFF);   // an ASCII byte always decodes to itself
                }
            }
            if (!s.equals(text(twice))) {
                invented.add(hex(c) + " -> decodes differently on a second read");
            }
            if (s.indexOf('\uFFFD') < 0) {
                invented.add(hex(c) + " -> no replacement character, so the bad bytes became"
                        + " something else: " + codePoints(s));
            }
            for (int i = 0; i < s.length(); i++) {
                char ch = s.charAt(i);
                if (Character.isSurrogate(ch)) {
                    loneSurrogate.add(hex(c) + " -> " + codePoints(s));
                }
                if (ch != '\uFFFD' && !fromInput.contains((int) ch)) {
                    invented.add(hex(c) + " -> invented " + codePoints(s));
                }
            }
            if (Identity.parseClientUsername(s) != null || Identity.parseClientEmail(s) != null) {
                notRefused.add(hex(c) + " -> " + codePoints(s));
            }
            // Alignment: a second line after the malformed one must arrive intact.
            ByteArrayOutputStream p = new ByteArrayOutputStream();
            p.write(rawBytes(c));
            p.write(bytes("alice\n"));
            try {
                LineReader r = new LineReader(new ByteArrayInputStream(p.toByteArray()));
                r.readSecretChars(4096);
                if (!"alice".equals(r.readLine(64))) {
                    misaligned.add(hex(c));
                }
            } catch (IOException e) {
                misaligned.add(hex(c) + " threw " + e);
            }
            // Where the JDK's replacement count is reproduced exactly, stay silent; where it is
            // not, record the divergence instead of asserting a quirk into the production decoder.
            if (!s.equals(platform(c))) {
                divergingFromPlatform.add(hex(c) + " ours=" + codePoints(s)
                        + " platform=" + codePoints(platform(c)));
            }
        }
        for (int[] raw : HOSTILE_CONTROL) {
            int[] c = withLf(raw);
            char[] got = readSecret(4096, c);
            String s2 = text(got);
            checkEquals("legal control bytes " + hex(c) + " pass through byte-for-byte",
                    platform(c), s2);
            check("and " + hex(c) + " is refused as an identifier by the layer that owns that rule",
                    Identity.parseClientUsername(s2) == null
                            && Identity.parseClientEmail(s2) == null);
            check("and as a password by the layer that owns that one",
                    Password.adopt(s2.toCharArray()) == null);
        }
        checkEquals("no malformed form produced a character the bytes did not contain",
                "", String.join(" | ", invented));
        checkEquals("no malformed form left an unpaired surrogate, which would corrupt any later"
                        + " UTF-8 encode",
                "", String.join(" | ", loneSurrogate));
        checkEquals("no malformed form lost or duplicated a following byte",
                "", String.join(" | ", misaligned));
        checkEquals("and every decoded malformed value is refused as an identifier",
                "", String.join(" | ", notRefused));
        for (String d : divergingFromPlatform) {
            Harness.note("U+FFFD count differs from the JDK here, and only in the count: " + d);
        }
        checkEquals("the 2-byte family matches the platform exactly, replacement for replacement",
                platform(0xC3, 0x41, 0x0A),
                text(readSecret(64, 0xC3, 0x41, 0x0A)));

        section("The secret path never builds a String");
        // Behaviour cannot show this: by the time the process exits the plaintext is unreachable
        // either way, which is precisely why the earlier piped implementation passed every test
        // while voiding Rule 5. The only falsifiable claim is structural.
        String src = Harness.stripJavaComments(Harness.sourceOf("LineReader"));
        String secretBody = bodyOf(src, "char[] readSecretChars(");
        check("readSecretChars contains no new String(", !secretBody.contains("new String("));
        check("readSecretChars goes through the char[] reader",
                secretBody.contains("readLineChars(maxChars)"));
        String lineBody = bodyOf(src, "private char[] readLineChars(");
        check("the working buffer is zeroed before the array escapes",
                lineBody.contains("Arrays.fill(keep, '\\0')"));
        check("and the zeroing happens before the copy is returned, not after",
                lineBody.indexOf("Arrays.fill(keep, '\\0')") < lineBody.indexOf("return out;"));
        check("the reader is unbuffered: exactly one in.read() call and no internal byte buffer,"
                        + " so nothing beyond the caller's array ever holds the secret",
                Harness.countOccurrences(src, "in.read()") == 1
                        && !src.contains("byte[] buf") && !src.contains("read(byte[]"));

        section("Memory is bounded by the cap, not by the length of the line");
        check("the working array is sized from the caller's cap, so a multi-gigabyte piped line"
                        + " costs time and not memory",
                lineBody.contains("char[] keep = new char[cap + 2]")
                        && lineBody.contains("int cap = Math.min(maxChars, MAX_CAP)"));
        check("and there is no growable buffer a hostile line could inflate",
                !src.contains("StringBuilder") && !src.contains("ByteArrayOutputStream")
                        && !src.contains("ArrayList"));
        check("PortalCli reads the secret through it",
                Harness.stripJavaComments(Harness.sourceOf("PortalCli"))
                        .contains("in.readSecretChars(Password.MAX_CP)"));
    }

    /** Index of the lead byte whose family the JDK restarts early, or -1 if it is a 2-byte form. */
    private static int firstBadFamily(int[] bytes) {
        for (int b : bytes) {
            int v = b & 0xFF;
            if (v == 0xC3 || v == 0xC2) {
                return -1;
            }
        }
        return 0;
    }

    /**
     * One method's source, from its declaration's opening brace. {@code Harness.methodBody} keys on
     * " name(" and so finds the first <em>call site</em>, which here is inside another method; a
     * region helper that anchors on the declaration is what these shape checks need.
     */
    private static String bodyOf(String strippedSource, String declaration) {
        int decl = strippedSource.indexOf(declaration);
        if (decl < 0) {
            return "";
        }
        int open = strippedSource.indexOf('{', decl);
        int depth = 0;
        for (int i = open; i < strippedSource.length(); i++) {
            char c = strippedSource.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return strippedSource.substring(decl, i + 1);
                }
            }
        }
        return "";
    }

    private static byte[] filler() {
        byte[] v = new byte[200_000];
        Arrays.fill(v, (byte) 'a');
        return v;
    }
}
