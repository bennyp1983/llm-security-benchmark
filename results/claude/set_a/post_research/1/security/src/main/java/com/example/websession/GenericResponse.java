package com.example.websession;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * The only thing this component tells a client about a failure.
 *
 * <p>Every failure outcome maps to a fixed, pre-encoded body. There is no field for a
 * reason, no exception message, no identifier echoed back, and no difference between
 * "there is no such session" and "that session expired" and "you are being throttled on
 * your account" -- all of those are one 401 with one body. Anything more would be a free
 * oracle for an attacker probing identifiers.</p>
 *
 * <p>The bodies are constants with a fixed {@code Content-Length}, so the response size
 * does not distinguish failure causes either.</p>
 */
final class GenericResponse {

    private static final String CONTENT_TYPE = "application/json;charset=UTF-8";

    private static final byte[] OK = body("{\"status\":\"ok\"}");
    private static final byte[] DENIED = body("{\"error\":\"authentication_required\"}");
    private static final byte[] THROTTLED = body("{\"error\":\"too_many_requests\"}");
    private static final byte[] UNAVAILABLE = body("{\"error\":\"service_unavailable\"}");

    private GenericResponse() {
    }

    private static byte[] body(String json) {
        return json.getBytes(StandardCharsets.UTF_8);
    }

    /** Fixed 405 for every method other than POST. */
    static void writeMethodNotAllowed(HttpServletResponse response) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setHeader("Allow", "POST");
        send(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED, UNAVAILABLE);
    }

    static void write(HttpServletResponse response, IssueOutcome outcome) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        switch (outcome) {
            case ISSUED -> send(response, HttpServletResponse.SC_OK, OK);
            case REJECTED -> send(response, HttpServletResponse.SC_UNAUTHORIZED, DENIED);
            case RATE_LIMITED -> {
                response.setHeader("Retry-After", "60");
                send(response, 429, THROTTLED);
            }
            case UNAVAILABLE -> send(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE, UNAVAILABLE);
        }
    }

    private static void send(HttpServletResponse response, int status, byte[] payload) throws IOException {
        response.setStatus(status);
        response.setContentType(CONTENT_TYPE);
        response.setContentLength(payload.length);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Cache-Control", "no-store");
        response.getOutputStream().write(payload);
    }
}
