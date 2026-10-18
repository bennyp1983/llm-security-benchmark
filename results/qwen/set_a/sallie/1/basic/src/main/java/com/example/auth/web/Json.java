package com.example.auth.web;

/**
 * Just enough JSON writing for the status endpoint. Values are escaped by hand rather than pulled in
 * from a library, because the only thing ever serialised here is a fixed set of settings and
 * identifiers this application produced itself.
 */
final class Json {

    private Json() {
    }

    static String quote(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x7F) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    static String field(String name, String value) {
        return "\"" + quote(name) + "\":\"" + quote(value) + "\"";
    }

    static String field(String name, Object value) {
        return "\"" + quote(name) + "\":" + value;
    }

    static String object(String... fields) {
        return "{" + String.join(",", fields) + "}";
    }

    static String array(String... values) {
        return "[" + String.join(",", values) + "]";
    }
}
