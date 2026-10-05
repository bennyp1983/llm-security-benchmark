package com.example.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads shipped production sources so a guard can be checked against the code itself.
 *
 * <p>Some properties have no observable behaviour to assert, which makes the source the only honest
 * place to test them: "no copy of the password ever becomes an immutable {@code String}" leaves no
 * trace in an API response, and "this class exposes no way to write a credential record" is exactly
 * as true or false whether or not anything calls it. Asserting those at runtime would mean asserting
 * nothing, and a mutation that reintroduces either would survive every functional suite.
 *
 * <p>Comments are stripped before any text is matched, so prose in a javadoc that <em>mentions</em>
 * a forbidden call can neither satisfy nor defeat the check - and the read itself is asserted,
 * because a guard that silently inspected an empty string passes forever.
 */
final class ProductionSource {

    private ProductionSource() {
    }

    /**
     * Reads {@code simpleFileName} from {@code src/main/java/com/example/auth}, comments removed.
     *
     * @throws IOException when the file cannot be read; the caller's suite fails loudly rather than
     *     inspecting nothing
     */
    static String of(String simpleFileName, String assertedName) throws IOException {
        Path candidate = pathOf(simpleFileName);
        String text = stripComments(new String(Files.readAllBytes(candidate), StandardCharsets.UTF_8));
        // A source file that read as empty would make every "does not contain" check below pass for
        // the wrong reason.
        if (text.isBlank()) {
            throw new IOException("cannot inspect " + assertedName + ": " + simpleFileName + " read as empty");
        }
        return text;
    }

    /**
     * The body of {@code signatureMarker}, from that marker to the first line indented at the method
     * level. Inner blocks are indented deeper, so this stops at the method's own closing brace.
     */
    static String methodBody(String source, String signatureMarker, String assertedName) throws IOException {
        int start = source.indexOf(signatureMarker);
        if (start < 0) {
            throw new IOException("cannot inspect " + assertedName + ": no " + signatureMarker + " in the source");
        }
        int end = source.indexOf("\n    }\n", start);
        if (end <= start) {
            throw new IOException("cannot inspect " + assertedName + ": " + signatureMarker + " has no method end");
        }
        return source.substring(start, end);
    }

    /**
     * The same file verbatim, comments included. Used where the check is about text a comment could
     * otherwise hide, such as "this class never calls that method".
     */
    static String verbatim(String simpleFileName) throws IOException {
        return new String(Files.readAllBytes(pathOf(simpleFileName)), StandardCharsets.UTF_8);
    }

    /**
     * Location of a shipped source file.
     *
     * <p>{@code -Dauth.source.dir} wins over the working directory, and a file that is absent under it
     * is an error rather than a fall-through to the pristine tree. A mutation harness compiles a
     * mutated copy in a scratch directory and runs the suites from the project root; silently falling
     * back would have those assertions read the unmutated file and report a guard as intact for every
     * mutant, which is the exact failure mode a source-text check is supposed to avoid.
     */
    static Path pathOf(String simpleFileName) throws IOException {
        Path candidate = rootRelative("src/main/java/com/example/auth", simpleFileName);
        if (!Files.isRegularFile(candidate)) {
            throw new IOException(simpleFileName + " is not readable at " + candidate.toAbsolutePath());
        }
        return candidate;
    }

    /** Where a class lives, so "this belongs in the test tree" is a checked fact and not a comment. */
    static boolean isInMainTree(String simpleFileName) {
        return Files.isRegularFile(rootRelative("src/main/java/com/example/auth", simpleFileName));
    }

    /** As {@link #isInMainTree}, for the test tree. */
    static boolean isInTestTree(String simpleFileName) {
        return Files.isRegularFile(rootRelative("src/test/java/com/example/auth", simpleFileName));
    }

    /** {@code -Dauth.source.dir} when given, otherwise the working directory. */
    private static Path rootRelative(String packageDir, String simpleFileName) {
        return Path.of(System.getProperty("auth.source.dir", "."), packageDir, simpleFileName);
    }

    /**
     * Removes every character at or below a space, so a check can match code shape without depending
     * on line breaks or indentation. Wrapping and re-indentation are the normal ways a source-text
     * guard starts failing for the wrong reason; this removes that failure mode.
     */
    static String compact(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c > ' ') {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** Removes line and block comments while respecting character and string literals. */
    static String stripComments(String text) {
        StringBuilder out = new StringBuilder(text.length());
        boolean inString = false;
        boolean inChar = false;
        boolean escaped = false;
        boolean inLine = false;
        boolean inBlock = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            char next = i + 1 < text.length() ? text.charAt(i + 1) : '\0';
            if (inLine) {
                if (c == '\n') {
                    inLine = false;
                    out.append('\n');
                }
                continue;
            }
            if (inBlock) {
                if (c == '*' && next == '/') {
                    inBlock = false;
                    i++;
                }
                continue;
            }
            if (inString) {
                out.append(c);
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (inChar) {
                out.append(c);
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '\'') {
                    inChar = false;
                }
                continue;
            }
            if (c == '/' && next == '/') {
                inLine = true;
                i++;
                continue;
            }
            if (c == '/' && next == '*') {
                inBlock = true;
                i++;
                continue;
            }
            out.append(c);
            if (c == '"') {
                inString = true;
            } else if (c == '\'') {
                inChar = true;
            }
        }
        return out.toString();
    }
}
