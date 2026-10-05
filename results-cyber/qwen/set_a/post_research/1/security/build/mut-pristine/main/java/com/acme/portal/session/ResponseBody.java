package com.acme.portal.session;

/**
 * The only two bodies this component ever writes.
 *
 * <p>Both are constant. The refusal body in particular is a compile-time constant shared by every
 * refusal path, so a response can never disclose <i>why</i> it refused: not which check failed, not
 * whether an identifier exists, not whether the component is misconfigured. That is rule 6's
 * "identical messages" requirement, made structural rather than a convention a maintainer has to
 * remember.
 *
 * <p>Neither body contains the session identifier, a client address, a stack trace, a class name or a
 * value read from the environment. Both are pure ASCII, built without any control character appearing
 * in a source literal.
 */
final class ResponseBody {

    /** Byte-identical for every refusal, whatever the reason. */
    static final String REFUSAL = "<!DOCTYPE html>"
            + "<html lang=\"en\"><head><meta charset=\"utf-8\">"
            + "<title>Sign-in</title></head><body>"
            + "<h1>Sign-in</h1>"
            + "<p>We could not complete sign-in. Please start again.</p>"
            + "</body></html>";

    /**
     * Bound on the escaped <b>output</b>, so a long configured value cannot inflate a page.
     *
     * <p>The distinction matters, and this constant used to get it wrong by bounding the input
     * instead: escaping only ever grows, so 256 characters of {@code "} are 1 536 bytes of
     * {@code &quot;} -- six times the limit, on a page whose guard had just reported itself satisfied.
     * The loop therefore checks the room a character <i>needs</i> before emitting it, which keeps the
     * result inside the bound and also guarantees it never cuts an entity in half: {@code &am} or
     * {@code &quo} left in a document is broken markup, worse than a page that stops one entity early.
     */
    private static final int MAX_ESCAPED_LENGTH = 256;

    /** Widest replacement this escaper can emit for a single input character ({@code &quot;}). */
    private static final int WIDEST_ENTITY = 6;

    /** Substitute for a control character; a space, never an NUL. */
    private static final char SUBSTITUTE = (char) 0x20;

    private ResponseBody() {
    }

    /**
     * Success page. Says only that sign-in completed and which cookie now exists. It deliberately
     * does not echo the session identifier: the cookie already carries it, and repeating it in the
     * document would put a bearer credential into the DOM, page history and any HTML-rewriting proxy.
     */
    static String granted(SessionCookiePolicy policy) {
        return "<!DOCTYPE html>"
                + "<html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<title>Signed in</title></head><body>"
                + "<h1>Signed in</h1>"
                + "<p>You are signed in. Your session is held in the cookie <code>"
                + escapeHtml(policy.name()) + "</code>.</p>"
                + "</body></html>";
    }

    /**
     * Contextual escaping for HTML text. Both inputs come from validated configuration rather than
     * from a client, and are escaped anyway: output encoding is cheap and the alternative is
     * depending on a validator never regressing.
     */
    static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(Math.min(MAX_ESCAPED_LENGTH, value.length() + 16));
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            String replacement;
            switch (c) {
                case '&':
                    replacement = "&amp;";
                    break;
                case '<':
                    replacement = "&lt;";
                    break;
                case '>':
                    replacement = "&gt;";
                    break;
                case '"':
                    replacement = "&quot;";
                    break;
                case '\'':
                    replacement = "&#39;";
                    break;
                default:
                    if (c < 0x20 || c == 0x7F) {
                        // Never emitted, even as an entity: a control byte in a page is a bug worth
                        // seeing as a marker, not a character worth rendering.
                        replacement = String.valueOf(SUBSTITUTE);
                    } else {
                        replacement = String.valueOf(c);
                    }
            }
            // Charged against the widest replacement this escaper can emit, so the emitted length can
            // never pass the bound however the characters fall -- and an entity is always whole or
            // absent. Sizing the cut on the input length is what let a quote-heavy value exceed the
            // bound sixfold, and cutting on the output length is what would leave "&quo" in a page.
            if (out.length() + WIDEST_ENTITY > MAX_ESCAPED_LENGTH) {
                break;
            }
            out.append(replacement);
        }
        return out.toString();
    }
}
