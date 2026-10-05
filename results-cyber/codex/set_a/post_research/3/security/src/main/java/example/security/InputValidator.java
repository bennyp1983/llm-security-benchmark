package example.security;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

final class InputValidator {
    private static final Pattern LOCAL = Pattern.compile("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}");
    private static final Pattern LABEL = Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?");
    private static final Pattern HOST = Pattern.compile("(?=.{1,253}\\z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?");
    private static final Pattern SQL_IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");

    private InputValidator() {}

    static Optional<String> canonicalEmail(String input) {
        if (input == null || input.length() < 3 || input.length() > 254 || !isAscii(input)) {
            return Optional.empty();
        }
        int at = input.indexOf('@');
        if (at <= 0 || at != input.lastIndexOf('@')) {
            return Optional.empty();
        }
        String local = input.substring(0, at);
        String domain = input.substring(at + 1);
        if (!LOCAL.matcher(local).matches() || local.startsWith(".") || local.endsWith(".")
                || local.contains("..") || domain.length() > 253) {
            return Optional.empty();
        }
        String[] labels = domain.split("\\.", -1);
        if (labels.length < 2) {
            return Optional.empty();
        }
        for (String label : labels) {
            if (!LABEL.matcher(label).matches()) {
                return Optional.empty();
            }
        }
        return Optional.of(local.toLowerCase(Locale.ROOT) + "@" + domain.toLowerCase(Locale.ROOT));
    }

    static boolean validPassword(char[] password) {
        if (password == null || password.length == 0 || password.length > 1024) {
            return false;
        }
        int utf8Bytes = 0;
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (c == 0 || Character.isISOControl(c)) {
                return false;
            }
            if (Character.isHighSurrogate(c)) {
                if (++i >= password.length || !Character.isLowSurrogate(password[i])) {
                    return false;
                }
                utf8Bytes += 4;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            } else {
                utf8Bytes += c <= 0x7f ? 1 : c <= 0x7ff ? 2 : 3;
            }
            if (utf8Bytes > 1024) {
                return false;
            }
        }
        return true;
    }

    static String requireHost(String value) {
        if (value == null || !HOST.matcher(value).matches() || value.contains("..")) {
            throw new IllegalArgumentException("invalid database configuration");
        }
        return value.toLowerCase(Locale.ROOT);
    }

    static String requireSqlIdentifier(String value) {
        if (value == null || !SQL_IDENTIFIER.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid database configuration");
        }
        return value;
    }

    static int requirePort(String value) {
        if (value == null || !value.matches("[0-9]{1,5}")) {
            throw new IllegalArgumentException("invalid database configuration");
        }
        int port = Integer.parseInt(value);
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("invalid database configuration");
        }
        return port;
    }

    private static boolean isAscii(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) > 0x7f || Character.isISOControl(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
