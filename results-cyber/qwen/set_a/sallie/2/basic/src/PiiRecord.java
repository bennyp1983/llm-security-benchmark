import java.util.Objects;

/**
 * A decrypted person record: the two PII fields this program protects.
 *
 * <p>{@link #toString()} is deliberately redacted. Records print their components
 * by default, and a decrypted email landing in a log line, a stack trace or a
 * debugger dump would defeat the point of encrypting it.
 */
public record PiiRecord(String name, String email) {

    public PiiRecord {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(email, "email");
    }

    @Override
    public String toString() {
        return "PiiRecord[redacted]";
    }
}
