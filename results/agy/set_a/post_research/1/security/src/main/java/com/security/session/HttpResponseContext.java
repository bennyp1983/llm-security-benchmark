package com.security.session;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * Abstraction over outgoing HTTP response manipulation, supporting header addition,
 * status setting, and sanitized body writing.
 */
public interface HttpResponseContext {

    /**
     * Sets a response header, replacing any previous value.
     */
    void setHeader(String name, String value);

    /**
     * Adds a response header value (e.g. for Set-Cookie).
     */
    void addHeader(String name, String value);

    /**
     * Sets the HTTP response status code.
     */
    void setStatus(int statusCode);

    /**
     * Writes JSON response content.
     */
    void writeJsonBody(String body) throws IOException;

    /**
     * Creates an HttpResponseContext adapter wrapping a Jakarta HttpServletResponse.
     */
    static HttpResponseContext fromServlet(HttpServletResponse response) {
        Objects.requireNonNull(response, "HttpServletResponse cannot be null");

        return new HttpResponseContext() {
            @Override
            public void setHeader(String name, String value) {
                response.setHeader(name, value);
            }

            @Override
            public void addHeader(String name, String value) {
                response.addHeader(name, value);
            }

            @Override
            public void setStatus(int statusCode) {
                response.setStatus(statusCode);
            }

            @Override
            public void writeJsonBody(String body) throws IOException {
                response.setContentType("application/json; charset=UTF-8");
                response.getWriter().write(body);
                response.getWriter().flush();
            }
        };
    }
}
