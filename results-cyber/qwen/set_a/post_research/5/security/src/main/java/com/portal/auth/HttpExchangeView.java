package com.portal.auth;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * The slice of HTTP this program needs, expressed as an interface so the security
 * behaviour of {@link PortalServer} (routing, refusals, cookie shape, header equality) can
 * be exercised against a double instead of only against a live socket.
 *
 * <p>Implementations must be strict: an absent or malformed thing stays absent, because
 * {@link PortalServer} treats every absent/invalid thing as a refusal.
 */
public interface HttpExchangeView {

    /** Uppercase HTTP method token as received. */
    String method();

    /** Path component only, no query, already percent-decoded nowhere. */
    String rawPath();

    /** First value of a header, or null. Header names are matched case-insensitively. */
    String header(String name);

    List<String> headers(String name);

    /**
     * Read at most {@code maxBytes + 1} of the request body, so the caller can tell "exactly
     * at the cap" from "over the cap". Never returns more than {@code maxBytes + 1} bytes
     * no matter what the client sends.
     */
    byte[] readBodyBounded(int maxBytes) throws IOException;

    /** Literal peer address of the TCP connection; never a resolved hostname. */
    String peerAddress();

    /** Send the response. Implementations must not add or remove caller headers. */
    void respond(int status, byte[] body, List<String> setCookieHeaders) throws IOException;

    /** Sentinel for "no body". */
    byte[] EMPTY = new byte[0];

    default Optional<String> cookieValue(String cookieHeader, String name) {
        return CookieParser.value(cookieHeader, name);
    }
}
