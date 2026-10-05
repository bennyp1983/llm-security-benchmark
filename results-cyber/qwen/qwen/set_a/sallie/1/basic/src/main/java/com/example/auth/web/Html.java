package com.example.auth.web;

/**
 * Minimal HTML writing for the demo pages. Every value that came from a request or from a stored
 * account is escaped before it is placed between tags, so a username or an error message can never
 * become markup.
 */
final class Html {

    private Html() {
    }

    static String escape(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder(raw.length() + 16);
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '&' -> escaped.append("&amp;");
                case '<' -> escaped.append("&lt;");
                case '>' -> escaped.append("&gt;");
                case '"' -> escaped.append("&quot;");
                case '\'' -> escaped.append("&#39;");
                default -> escaped.append(c);
            }
        }
        return escaped.toString();
    }

    /**
     * Turns text into something safe to drop inside an HTML attribute value that is delimited by a
     * given quote character.
     */
    static String attribute(String raw) {
        return escape(raw);
    }
}
