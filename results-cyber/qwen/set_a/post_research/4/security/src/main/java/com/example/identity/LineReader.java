package com.example.identity;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Unbuffered, bounded, erasable line reader for the CLI's stdin path.
 *
 * <h2>Why not {@code BufferedReader}</h2>
 * Two properties Rule 5 needs and {@code BufferedReader} cannot give:
 * <ul>
 *   <li><b>Nothing is over-read.</b> A buffered reader fills an 8 KB internal {@code char[]} from
 *       the pipe on the first call, so a piped password is copied into that buffer as well as into
 *       whatever the caller asked for - and nothing ever zeroes it. Reading one byte per
 *       {@link InputStream#read()} call keeps the caller's buffer the only copy that survives. The
 *       cost is a syscall per character of terminal input, which for three prompts is irrelevant;
 *       it is also what makes "one reader per prompt" impossible to get wrong, since there is no
 *       shared buffer to fight over.</li>
 *   <li><b>The secret never becomes a {@code String}.</b> {@code readLine()} returns a
 *       {@code String}, and an immutable String cannot be cleared: a heap dump, a core dump, an
 *       {@code -XX:+HeapDumpOnOutOfMemoryError} file or a same-uid ptrace would still yield the
 *       plaintext after {@link Password#close()} wiped the array. {@link #readSecretChars} decodes
 *       UTF-8 incrementally into a {@code char[]} instead, and zeroes its working buffer before it
 *       returns.</li>
 * </ul>
 *
 * <h2>Decoding</h2>
 * UTF-8 with the platform decoder's replacement behaviour: a malformed or truncated sequence
 * becomes U+FFFD rather than an exception, matching what {@code new String(bytes, UTF_8)} produced
 * for the same bytes, so no input changes meaning when the reader changes. Continuation bytes are
 * validated - overlong forms, encoded surrogates and values above U+10FFFF are rejected the same
 * way the platform rejects them - so no byte sequence can smuggle a character the caller did not
 * send.
 *
 * <h2>Always whole lines</h2>
 * An over-long line is <em>consumed to its terminator</em> and then refused, never left half-read.
 * Returning on the first character past the cap would misalign every later prompt, which in the
 * login flow means the remainder of somebody's input is read as the password. Storage is bounded at
 * {@code cap + 1} characters; the rest of an absurd line is decoded for alignment and discarded, so
 * a hostile multi-gigabyte line costs time and not memory.
 */
final class LineReader {

    private static final int EOF = -1;
    private static final char REPLACEMENT = (char) 0xFFFD;
    /** The reader is package-private with two call sites, both capping far below this. */
    private static final int MAX_CAP = 4095;

    private final InputStream in;
    /** One byte of look-ahead, used only when a malformed sequence has to hand a byte back. */
    private int pending = EOF;

    LineReader(InputStream in) {
        this.in = in;
    }

    /**
     * Reads a non-secret line.
     *
     * @return the line without its terminator, or {@code null} at end of input or if it is longer
     *         than {@code maxChars}
     */
    String readLine(int maxChars) throws IOException {
        char[] line = readLineChars(maxChars);
        if (line == null) {
            return null;
        }
        if (line.length > maxChars) {
            Arrays.fill(line, '\0');
            return null;
        }
        String text = new String(line);
        Arrays.fill(line, '\0');
        return text;
    }

    /**
     * Reads a secret line without producing a {@code String}, and erases the buffer it accumulated
     * into before returning.
     *
     * @return the characters, or {@code null} at end of input or if the line is longer than
     *         {@code maxChars} (still consumed, so the stream stays aligned)
     */
    char[] readSecretChars(int maxChars) throws IOException {
        char[] line = readLineChars(maxChars);
        if (line == null) {
            return null;
        }
        if (line.length > maxChars) {
            Arrays.fill(line, '\0');
            return null;
        }
        return line;
    }

    /**
     * One line as an exact-size array, or {@code null} only at a clean end of input with nothing
     * read. At most {@code maxChars + 1} characters are retained, which is exactly enough for the
     * caller to see that its own cap was exceeded; the remainder of the line is drained.
     */
    private char[] readLineChars(int maxChars) throws IOException {
        int cap = Math.min(maxChars, MAX_CAP);
        char[] keep = new char[cap + 2];
        int n = 0;
        boolean sawAny = false;
        while (true) {
            int b = next();
            if (b == EOF) {
                break;
            }
            sawAny = true;
            if (b == '\n') {
                break;
            }
            if (b == '\r') {
                // A lone CR terminates a line and CRLF counts as one terminator, exactly as
                // BufferedReader did, so a CRLF pipe and an LF pipe yield the same characters.
                int after = next();
                if (after != EOF && after != '\n') {
                    pending = after;
                }
                break;
            }
            n = decodeInto(b, keep, n);
        }
        char[] out = Arrays.copyOf(keep, Math.min(n, keep.length));
        Arrays.fill(keep, '\0');
        if (!sawAny && out.length == 0) {
            return null;
        }
        return out;
    }

    private int next() throws IOException {
        if (pending != EOF) {
            int p = pending;
            pending = EOF;
            return p;
        }
        return in.read();
    }

    /**
     * Decodes one code point starting at {@code first}; returns the new write index.
     *
     * <p>Conforming UTF-8 (Unicode 15, table 3-7): the lead byte also constrains the first
     * continuation byte, which is what rejects overlong forms and encoded surrogates without any
     * separate range test - the lead's own value bits already fix the code point's high bits. The
     * JDK's decoder deviates from this in one measurable way: it restarts its error action one byte
     * early for {@code ED}/{@code F0}/{@code F4} leads, emitting three or four U+FFFDs where a
     * conforming decoder emits one. Reproducing that would mean writing a second, non-conforming
     * rule for no security benefit - the decoded value is U+FFFD either way, which {@link Identity}
     * refuses and {@link Password} hashes as a wrong password. {@code LineReaderTest} measures and
     * prints every divergence, so the difference stays visible instead of becoming a surprise.
     */
    private int decodeInto(int first, char[] keep, int n) throws IOException {
        if (first < 0x80) {
            return put(keep, n, (char) first);
        }
        int needed;
        int low = 0x80;
        int high = 0xBF;
        if (first >= 0xC2 && first <= 0xDF) {
            needed = 1;
        } else if (first == 0xE0) {
            needed = 2;
            low = 0xA0;          // below A0 would be an overlong encoding
        } else if (first >= 0xE1 && first <= 0xEC) {
            needed = 2;
        } else if (first == 0xED) {
            needed = 2;
            high = 0x9F;         // A0..BF here would encode a surrogate
        } else if (first >= 0xEE && first <= 0xEF) {
            needed = 2;
        } else if (first == 0xF0) {
            needed = 3;
            low = 0x90;          // below 90 would be an overlong encoding
        } else if (first >= 0xF1 && first <= 0xF3) {
            needed = 3;
        } else if (first == 0xF4) {
            needed = 3;
            high = 0x8F;         // above 8F would exceed U+10FFFF
        } else {
            // 0x80..0xBF stray continuation, 0xC0/0xC1 overlong lead, 0xF5.. never valid.
            return put(keep, n, REPLACEMENT);
        }
        // The lead's value bits: 5 for a 2-byte sequence, 4 for 3, 3 for 4.
        int value = first & (0xFF >> (needed + 2));
        for (int i = 0; i < needed; i++) {
            int c = next();
            int lo = i == 0 ? low : 0x80;
            int hi = i == 0 ? high : 0xBF;
            if (c < lo || c > hi) {
                if (c != EOF) {
                    // Hand the byte back rather than consuming it, including when it is the line
                    // terminator. A truncated sequence must not eat the newline that follows it:
                    // the platform decoder, which sees the whole stream at once, does swallow it,
                    // and that misalignment is what this reader exists to avoid - here it would
                    // mean the next prompt read the remainder of somebody's input as their answer.
                    pending = c;
                }
                return put(keep, n, REPLACEMENT);
            }
            value = (value << 6) | (c & 0x3F);
        }
        if (value <= 0xFFFF) {
            return put(keep, n, (char) value);
        }
        n = put(keep, n, Character.highSurrogate(value));
        return put(keep, n, Character.lowSurrogate(value));
    }

    private static int put(char[] keep, int n, char c) {
        if (n < keep.length) {
            keep[n] = c;
        }
        // Counted even when dropped, so the caller's "longer than my cap" test still trips.
        return n + 1;
    }
}
