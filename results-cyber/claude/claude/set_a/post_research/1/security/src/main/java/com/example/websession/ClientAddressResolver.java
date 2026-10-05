package com.example.websession;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Determines the per-source key used for rate limiting.
 *
 * <p>{@code X-Forwarded-For} is client-controlled: any client can send it, and any client
 * can send a hundred different values to get a hundred fresh rate-limit buckets. It is
 * therefore ignored unless the operator has declared how many trusted proxies sit in front
 * of the application, and even then only the entry those proxies are known to have written
 * is read -- entries further left are attacker-supplied and skipped.</p>
 *
 * <p>Whatever is selected is validated as an IP literal before use. A hostile value never
 * becomes a map key, and no name resolution is performed, so the header cannot be used to
 * make the server issue DNS queries.</p>
 */
final class ClientAddressResolver {

    private static final String FORWARDED_FOR = "X-Forwarded-For";
    private static final int MAX_HEADER_LENGTH = 1024;
    private static final int MAX_ADDRESS_LENGTH = 45; // longest IPv6 textual form
    private static final String UNKNOWN = "unknown";

    private final int trustedProxyCount;

    ClientAddressResolver(int trustedProxyCount) {
        if (trustedProxyCount < 0) {
            throw new IllegalArgumentException("trustedProxyCount must not be negative");
        }
        this.trustedProxyCount = trustedProxyCount;
    }

    /** @return a validated address literal, or {@code "unknown"} -- never a client-supplied string. */
    String resolve(HttpServletRequest request) {
        String direct = sanitize(request.getRemoteAddr());
        if (trustedProxyCount == 0) {
            return direct;
        }
        String header = request.getHeader(FORWARDED_FOR);
        if (header == null || header.length() > MAX_HEADER_LENGTH) {
            return direct;
        }
        String[] hops = header.split(",", -1);
        int index = hops.length - trustedProxyCount;
        if (index < 0 || index >= hops.length) {
            // Fewer hops than the deployment promises: the chain is not what we were told
            // it would be, so fall back to the only address we observed ourselves.
            return direct;
        }
        String candidate = sanitize(hops[index].trim());
        return candidate.equals(UNKNOWN) ? direct : candidate;
    }

    private static String sanitize(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > MAX_ADDRESS_LENGTH) {
            return UNKNOWN;
        }
        String value = raw;
        // Some proxies emit "[2001:db8::1]:443" or "203.0.113.5:1234"; keep the address only.
        if (value.startsWith("[")) {
            int end = value.indexOf(']');
            if (end < 0) {
                return UNKNOWN;
            }
            value = value.substring(1, end);
        } else {
            int colon = value.indexOf(':');
            if (colon >= 0 && value.indexOf(':', colon + 1) < 0) {
                value = value.substring(0, colon);
            }
        }
        return isIpLiteral(value) ? value : UNKNOWN;
    }

    private static boolean isIpLiteral(String value) {
        if (value.isEmpty() || value.length() > MAX_ADDRESS_LENGTH) {
            return false;
        }
        boolean sawColon = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ':') {
                sawColon = true;
                continue;
            }
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex && c != '.') {
                // Rejects '%' zone ids, wildcards, hostnames, and anything else.
                return false;
            }
        }
        return sawColon ? value.length() >= 2 : isDottedQuad(value);
    }

    private static boolean isDottedQuad(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            int octet = 0;
            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
                octet = octet * 10 + (c - '0');
            }
            if (octet > 255) {
                return false;
            }
        }
        return true;
    }
}
