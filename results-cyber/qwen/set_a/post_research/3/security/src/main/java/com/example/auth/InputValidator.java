package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;

/**
 * The single place where attacker-controlled text is turned into something the rest of the
 * program may use. Every method either returns a validated value or throws
 * {@link ValidationException} whose message is a fixed code token that never contains the
 * offending input.
 *
 * <p>Nothing here is permissive: an absent, empty, oversized, or out-of-charset value is refused,
 * never defaulted and never silently normalised (the single exception is ASCII case folding of the
 * email address, which is a documented normalisation performed before comparison and storage).
 */
final class InputValidator {

    static final int EMAIL_MAX_CHARS = 254;
    static final int EMAIL_LOCAL_MAX = 64;
    static final int EMAIL_DOMAIN_MAX = 253;
    static final int PASSWORD_MIN_DEFAULT = 12;
    static final int PASSWORD_MAX_CHARS = 1024;
    static final int PASSWORD_MAX_UTF8_BYTES = 1024;
    static final int TOKEN_HEX_LEN = 64;

    private static final String LOCAL_ALLOWED =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-";
    private static final String DOMAIN_ALLOWED =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-";

    /** SQL words that must never be used as a configured table/user identifier. */
    private static final Set<String> RESERVED_SQL = Set.of(
            "select", "insert", "update", "delete", "drop", "alter", "create", "table", "user",
            "values", "where", "from", "into", "set", "grant", "revoke", "exec", "call", "init",
            "runscript", "shutdown", "in", "and", "or", "not", "null", "primary", "key", "index",
            "order", "group", "by", "as", "on", "join", "left", "right", "inner", "outer", "union",
            "all", "distinct", "count", "sum", "merge", "using", "when", "matched", "then",
            "inserted", "default", "current", "session", "user_id", "public", "information_schema",
            "h2", "sa", "dba", "admin", "true", "false");

    private InputValidator() {
    }

    /** Raised for invalid input. Carries a code token only, never the offending value. */
    static final class ValidationException extends Exception {
        private static final long serialVersionUID = 1L;

        ValidationException(String code) {
            super(code);
        }
    }

    /**
     * Validates and normalises an email address.
     *
     * <p>Accepted: printable ASCII only, exactly one {@code @}, local part 1-64 chars from
     * {@code [A-Za-z0-9._%+-]}, domain of 1-127 dot-separated labels from {@code [A-Za-z0-9.-]},
     * each label 1-63 chars, not starting or ending with a hyphen, no consecutive dots, TLD of at
     * least two ASCII letters (so a dotted-quad IP address is refused), and no trailing root dot.
     * The whole address is at most 254 chars. Output is ASCII-lowercase: this is the only form ever
     * compared against the database.
     *
     * <p>Deliberately refused: Unicode look-alikes and any non-ASCII byte (so no homoglyph account
     * confusion and no IDN homograph), whitespace, control characters including CR/LF (log
     * forging), quotes and backslashes, and anything above the length caps (never truncated).
     */
    static String requireEmail(String raw) throws ValidationException {
        if (raw == null) {
            throw new ValidationException("email_missing");
        }
        if (raw.length() > EMAIL_MAX_CHARS) {
            throw new ValidationException("email_too_long");
        }
        // Printable ASCII only. Rejects NUL, tab, CR/LF (log forging), DEL, C1 controls, every
        // non-ASCII code point (homoglyphs, IMAP-mUTF-7 tricks, overlong UTF-8), and space.
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c < 0x21 || c > 0x7E) {
                throw new ValidationException("email_charset");
            }
        }
        int at = raw.indexOf('@');
        if (at < 0 || raw.indexOf('@', at + 1) >= 0) {
            throw new ValidationException("email_at_count");
        }
        String local = raw.substring(0, at);
        String domain = raw.substring(at + 1);
        if (local.isEmpty() || local.length() > EMAIL_LOCAL_MAX) {
            throw new ValidationException("email_local_length");
        }
        if (local.charAt(0) == '.' || local.charAt(local.length() - 1) == '.') {
            throw new ValidationException("email_local_dot");
        }
        if (local.indexOf("..") >= 0) {
            throw new ValidationException("email_local_dotdot");
        }
        for (int i = 0; i < local.length(); i++) {
            if (LOCAL_ALLOWED.indexOf(local.charAt(i)) < 0) {
                throw new ValidationException("email_local_charset");
            }
        }
        String normalised = requireDomain(domain).toLowerCase(Locale.ROOT);
        String folded = local.toLowerCase(Locale.ROOT);
        String out = folded + "@" + normalised;
        if (out.length() > EMAIL_MAX_CHARS) {
            throw new ValidationException("email_too_long");
        }
        return out;
    }

    private static String requireDomain(String domain) throws ValidationException {
        if (domain.isEmpty() || domain.length() > EMAIL_DOMAIN_MAX) {
            throw new ValidationException("email_domain_length");
        }
        if (domain.charAt(domain.length() - 1) == '.') {
            throw new ValidationException("email_domain_trailing_dot");
        }
        if (domain.indexOf("..") >= 0 || domain.charAt(0) == '.' || domain.charAt(0) == '-') {
            throw new ValidationException("email_domain_shape");
        }
        String[] labels = domain.split("\\.", -1);
        if (labels.length < 2) {
            throw new ValidationException("email_domain_needs_dot");
        }
        if (labels.length > 127) {
            throw new ValidationException("email_domain_labels");
        }
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) {
                throw new ValidationException("email_domain_label_length");
            }
            if (label.charAt(0) == '-' || label.charAt(label.length() - 1) == '-') {
                throw new ValidationException("email_domain_label_hyphen");
            }
            // Punycode labels are refused outright. This program accepts printable ASCII only, so a
            // "xn--" label is how an internationalised homoglyph of a real domain would arrive
            // (paypa1 vs paypal); refusing it closes visual account confusion at the boundary
            // instead of relying on anything downstream to render it safely.
            if (label.regionMatches(true, 0, "xn--", 0, 4)) {
                throw new ValidationException("email_domain_punycode");
            }
            for (int i = 0; i < label.length(); i++) {
                if (DOMAIN_ALLOWED.indexOf(label.charAt(i)) < 0) {
                    throw new ValidationException("email_domain_charset");
                }
            }
        }
        String tld = labels[labels.length - 1];
        boolean allLetters = true;
        for (int i = 0; i < tld.length(); i++) {
            char c = tld.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) {
                allLetters = false;
                break;
            }
        }
        if (!allLetters || tld.length() < 2) {
            // Refuses a dotted-quad IPv4 literal and any all-numeric top label.
            throw new ValidationException("email_domain_tld");
        }
        return domain;
    }

    /**
     * Validates a password held as {@code char[]} so the caller can wipe it.
     *
     * <p>Refused: length outside [{@code min}, {@value #PASSWORD_MAX_CHARS}], UTF-8 encoding above
     * {@value #PASSWORD_MAX_UTF8_BYTES} bytes, any control character (including NUL and tab, which
     * would let {@code "pw"} and {@code "pw\0"} hash identically), leading or trailing space, and
     * unpaired surrogates. Unpaired surrogates matter because {@link javax.crypto.spec.PBEKeySpec}
     * silently maps them to {@code '?'} when converting chars to bytes, which would make two
     * different passwords verify identically.
     *
     * <p>Interior spaces are allowed; nothing is trimmed or otherwise altered.
     */
    static void requirePassword(char[] pw, int min) throws ValidationException {
        if (pw == null) {
            throw new ValidationException("password_missing");
        }
        if (pw.length < min || pw.length > PASSWORD_MAX_CHARS) {
            throw new ValidationException("password_length");
        }
        boolean highOpen = false;
        for (int i = 0; i < pw.length; i++) {
            char c = pw[i];
            if (c <= 0x1F || c == 0x7F || (c >= 0x80 && c <= 0x9F)) {
                throw new ValidationException("password_control_char");
            }
            if ((i == 0 || i == pw.length - 1) && c == ' ') {
                throw new ValidationException("password_edge_space");
            }
            if (Character.isHighSurrogate(c)) {
                if (highOpen) {
                    throw new ValidationException("password_surrogate");
                }
                highOpen = true;
            } else if (Character.isLowSurrogate(c)) {
                if (!highOpen) {
                    throw new ValidationException("password_surrogate");
                }
                highOpen = false;
            } else if (highOpen) {
                throw new ValidationException("password_surrogate");
            }
        }
        if (highOpen) {
            throw new ValidationException("password_surrogate");
        }
        if (utf8Length(pw) > PASSWORD_MAX_UTF8_BYTES) {
            throw new ValidationException("password_utf8_length");
        }
    }

    static int utf8Length(char[] pw) {
        int n = 0;
        for (int i = 0; i < pw.length; i++) {
            char c = pw[i];
            if (c < 0x80) {
                n += 1;
            } else if (c < 0x800) {
                n += 2;
            } else if (Character.isHighSurrogate(c)) {
                n += 4;
                i++;
            } else {
                n += 3;
            }
        }
        return n;
    }

    /** A session token as presented by a caller: exactly 64 lowercase hex characters. */
    static String requireSessionToken(String token) throws ValidationException {
        if (token == null || token.length() != TOKEN_HEX_LEN) {
            throw new ValidationException("token_shape");
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!ok) {
                throw new ValidationException("token_charset");
            }
        }
        return token;
    }

    /**
     * Validates a SQL identifier used in DDL and metadata lookups ({@code ^[A-Za-z_][A-Za-z0-9_]{0,29}$}).
     * Values are additionally double-quoted at their use site and checked against a reserved-word
     * deny list, so a configured name can never terminate a statement or change its grammar.
     */
    static String requireSqlIdentifier(String value) throws ValidationException {
        if (value == null || value.isEmpty() || value.length() > 30) {
            throw new ValidationException("identifier_length");
        }
        char first = value.charAt(0);
        if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_')) {
            throw new ValidationException("identifier_first_char");
        }
        for (int i = 1; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '_')) {
                throw new ValidationException("identifier_charset");
            }
        }
        if (RESERVED_SQL.contains(value.toLowerCase(Locale.ROOT))) {
            throw new ValidationException("identifier_reserved");
        }
        return value;
    }

    /**
     * Validates the per-source label. It is treated as attacker-influenceable: it may name a
     * budget but it never grants access. See the residual-risk note in THREAT-MODEL.md (R6).
     */
    static String requireSourceId(String value) throws ValidationException {
        if (value == null || value.isEmpty() || value.length() > 48) {
            throw new ValidationException("source_length");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || (i > 0 && (c == '.' || c == '_' || c == '-'));
            if (!ok) {
                throw new ValidationException("source_charset");
            }
        }
        return value;
    }

    /** A strictly positive integer written in plain ASCII decimal, bounded to a sane range. */
    static int requireInt(String raw, String code, int min, int max) throws ValidationException {
        if (raw == null) {
            raw = "";
        }
        if (!raw.matches("[0-9]{1,9}")) {
            throw new ValidationException(code + "_shape");
        }
        long v;
        try {
            v = Long.parseLong(raw);
        } catch (NumberFormatException e) {
            throw new ValidationException(code + "_shape");
        }
        if (v < min || v > max) {
            throw new ValidationException(code + "_range");
        }
        return (int) v;
    }

    static boolean requireBoolean(String raw, String code) throws ValidationException {
        if ("true".equals(raw)) {
            return true;
        }
        if ("false".equals(raw)) {
            return false;
        }
        throw new ValidationException(code + "_shape");
    }

    /**
     * A canonical absolute filesystem path with no JDBC-URL metacharacters.
     *
     * <p>{@code ;} and {@code =} are refused because an H2 URL is {@code jdbc:h2:<path>[;opt=v]};
     * a path containing them would let a configured value append engine options such as
     * {@code INIT=RUNSCRIPT FROM ...}. Control characters and NUL are refused for the same reason
     * plus file-system portability. The result must already be absolute and must contain no
     * {@code ..} segment after canonicalisation.
     */
    static String requireDbPath(String raw) throws ValidationException {
        if (raw == null || raw.isEmpty() || raw.length() > 512) {
            throw new ValidationException("dbpath_length");
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == ';' || c == '=' || c < 0x21 || c > 0x7E) {
                throw new ValidationException("dbpath_charset");
            }
        }
        if (!raw.startsWith("/")) {
            throw new ValidationException("dbpath_not_absolute");
        }
        if (raw.indexOf("..") >= 0 || raw.endsWith("/")) {
            throw new ValidationException("dbpath_shape");
        }
        java.nio.file.Path p = java.nio.file.Path.of(raw).normalize();
        if (!p.isAbsolute() || !p.toString().equals(raw)) {
            throw new ValidationException("dbpath_not_canonical");
        }
        if (raw.getBytes(StandardCharsets.UTF_8).length != raw.length()) {
            throw new ValidationException("dbpath_charset");
        }
        return raw;
    }
}
