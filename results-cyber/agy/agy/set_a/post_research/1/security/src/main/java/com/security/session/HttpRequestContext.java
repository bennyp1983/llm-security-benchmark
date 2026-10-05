package com.security.session;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Objects;

/**
 * Abstraction over incoming HTTP request attributes, decoupling the security component
 * from specific container implementations while providing strict input handling.
 */
public interface HttpRequestContext {

    /**
     * Returns the verified or sanitized remote client IP address.
     */
    String getRemoteAddr();

    /**
     * Returns true if the request was made over TLS / HTTPS.
     */
    boolean isSecure();

    /**
     * Returns the value of the specified request header, or null if absent.
     */
    String getHeader(String name);

    /**
     * Returns the HTTP request method (e.g. POST, GET).
     */
    String getMethod();

    /**
     * Creates an HttpRequestContext adapter wrapping a Jakarta HttpServletRequest.
     */
    static HttpRequestContext fromServlet(HttpServletRequest request, SessionCookieConfig config) {
        Objects.requireNonNull(request, "HttpServletRequest cannot be null");
        Objects.requireNonNull(config, "SessionCookieConfig cannot be null");

        return new HttpRequestContext() {
            @Override
            public String getRemoteAddr() {
                if (config.isTrustForwardedHeaders()) {
                    String forwarded = request.getHeader(config.getTrustedProxyIpHeader());
                    if (forwarded != null && !forwarded.isBlank()) {
                        // Take the leftmost IP from forwarded header and sanitize
                        String firstIp = forwarded.split(",")[0].trim();
                        if (isValidIp(firstIp)) {
                            return firstIp;
                        }
                    }
                }
                String remoteAddr = request.getRemoteAddr();
                return (remoteAddr != null && !remoteAddr.isBlank()) ? remoteAddr : "0.0.0.0";
            }

            @Override
            public boolean isSecure() {
                if (request.isSecure()) {
                    return true;
                }
                if (config.isTrustForwardedHeaders()) {
                    String proto = request.getHeader("X-Forwarded-Proto");
                    if ("https".equalsIgnoreCase(proto)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            public String getHeader(String name) {
                return request.getHeader(name);
            }

            @Override
            public String getMethod() {
                return request.getMethod();
            }
        };
    }

    /**
     * Basic check for IPv4 or IPv6 format to avoid header injection via remote address.
     */
    static boolean isValidIp(String ip) {
        if (ip == null || ip.isBlank() || ip.length() > 45) {
            return false;
        }
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':')) {
                return false;
            }
        }
        return true;
    }
}
