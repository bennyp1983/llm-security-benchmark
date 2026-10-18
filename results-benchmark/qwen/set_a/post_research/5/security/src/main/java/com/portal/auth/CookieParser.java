package com.portal.auth;

import java.util.Optional;

/**
 * Parses one {@code Cookie} header.
 *
 * <p>Written by hand because the JDK has no cookie parser that is not bound to a servlet
 * container, and all it needs to do is two things: split on {@code ';'} and match
 * {@code name=value} exactly -- no trimming, no unquoting, no case-folding. A pair that
 * does not match exactly is simply not found, and the caller then refuses, which is the
 * safe direction: a lenient parser here would let {@code name =value} or {@code nxname=value}
 * alias onto a name we did not intend to honour.
 *
 * <p>The whole header is size-bounded by the caller before it reaches here.
 */
final class CookieParser {

    private static final int MAX_HEADER_BYTES = 8 * 1024;
    private static final int MAX_VALUE_BYTES = 512;

    private CookieParser() {
    }

    static Optional<String> value(String cookieHeader, String name) {
        if (cookieHeader == null || name == null || name.isEmpty()
                || cookieHeader.length() > MAX_HEADER_BYTES) {
            return Optional.empty();
        }
        int searchFrom = 0;
        while (searchFrom <= cookieHeader.length()) {
            int next = cookieHeader.indexOf(';', searchFrom);
            int end = next < 0 ? cookieHeader.length() : next;
            String pair = cookieHeader.substring(searchFrom, end);
            int eq = pair.indexOf('=');
            // RFC 6265 permits one optional leading space before a cookie-pair, so exactly
            // that much is tolerated; anything further is a pair we do not recognise.
            if (eq > 0) {
                String key = pair.charAt(0) == ' ' ? pair.substring(1, eq) : pair.substring(0, eq);
                if (key.equals(name)) {
                    String v = pair.substring(eq + 1);
                    if (v.length() > MAX_VALUE_BYTES || v.length() > name.length() + 512) {
                        return Optional.empty();
                    }
                    return Optional.of(v);
                }
            }
            if (next < 0) {
                break;
            }
            searchFrom = next + 1;
        }
        return Optional.empty();
    }
}
