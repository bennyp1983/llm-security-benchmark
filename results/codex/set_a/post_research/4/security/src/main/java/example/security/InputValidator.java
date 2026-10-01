package example.security;

import java.text.Normalizer;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

final class InputValidator {
    static final int MAX_PASSWORD_CHARS = 128;
    private static final int MIN_PASSWORD_CHARS = 15;
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{2,31}");
    private static final Pattern LOCAL_PART = Pattern.compile("[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}");
    private static final Pattern DOMAIN_LABEL = Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?");

    private InputValidator() { }

    static Optional<String> username(String value) {
        if (value == null || !isStableText(value) || !USERNAME.matcher(value).matches()) {
            return Optional.empty();
        }
        return Optional.of(value.toLowerCase(Locale.ROOT));
    }

    static Optional<String> email(String value) {
        if (value == null || value.length() > 254 || !isStableText(value)) {
            return Optional.empty();
        }
        int at = value.indexOf('@');
        if (at <= 0 || at != value.lastIndexOf('@')) {
            return Optional.empty();
        }
        String local = value.substring(0, at);
        String domain = value.substring(at + 1);
        if (!LOCAL_PART.matcher(local).matches() || local.startsWith(".") || local.endsWith(".")
                || local.contains("..") || domain.length() > 253) {
            return Optional.empty();
        }
        String[] labels = domain.split("\\.", -1);
        if (labels.length < 2) {
            return Optional.empty();
        }
        for (String label : labels) {
            if (!DOMAIN_LABEL.matcher(label).matches()) {
                return Optional.empty();
            }
        }
        return Optional.of(value.toLowerCase(Locale.ROOT));
    }

    static boolean password(char[] value) {
        if (value == null || value.length < MIN_PASSWORD_CHARS || value.length > MAX_PASSWORD_CHARS) {
            return false;
        }
        for (int i = 0; i < value.length; i++) {
            char c = value[i];
            if (Character.isISOControl(c) || (Character.isSurrogate(c)
                    && (i + 1 >= value.length || !Character.isSurrogatePair(c, value[++i])))) {
                return false;
            }
        }
        return true;
    }

    static Optional<Login> login(String value) {
        Optional<String> user = username(value);
        if (user.isPresent()) {
            return Optional.of(new Login(LoginKind.USERNAME, user.get()));
        }
        return email(value).map(v -> new Login(LoginKind.EMAIL, v));
    }

    private static boolean isStableText(String value) {
        return value.equals(value.strip()) && Normalizer.isNormalized(value, Normalizer.Form.NFC)
                && value.chars().noneMatch(Character::isISOControl);
    }

    enum LoginKind { USERNAME, EMAIL }
    record Login(LoginKind kind, String canonicalValue) { }
}
