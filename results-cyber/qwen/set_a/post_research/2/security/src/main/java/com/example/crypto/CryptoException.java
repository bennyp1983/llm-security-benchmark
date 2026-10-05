package com.example.crypto;

/**
 * The only failure type this component throws.
 *
 * <p>It carries two messages and the distinction is the whole point:
 *
 * <ul>
 *   <li>{@link #getUserMessage()} is a short, generic, fixed-vocabulary string. It is safe to show
 *       to an end user or return over an API, and {@link #getMessage()} returns exactly it, so a
 *       caller who blindly renders {@code e.getMessage()} leaks nothing.</li>
 *   <li>{@link #getTechnicalDetail()} is a one-line, secret-free diagnostic intended for the log.
 *       It is never reachable from {@link #getMessage()} or {@link #toString()}.</li>
 * </ul>
 *
 * <p>Stack traces are disabled: this component has a fixed, small set of failure modes and their
 * causes are already named by {@link Crypto FailureCode}, so a stack trace would add nothing while
 * inviting callers to log internal package layout alongside it.
 *
 * <p>Cryptographic failures in particular never carry the underlying {@code
 * javax.crypto.AEADBadTagException} as a {@code cause} that survives into {@link #getMessage()};
 * the code records it, the detail string describes it, and the key material never does.
 */
public final class CryptoException extends Exception {

    private static final long serialVersionUID = 1L;

    /** Machine-readable failure category. Safe to expose; it names no secret. */
    public enum CryptoFailureCode {
        /** A required input was absent. */
        MISSING_INPUT("No data was supplied"),
        /** An input was the wrong type, size, encoding or range. */
        INVALID_INPUT("The supplied data is not in a supported format"),
        /** The bytes are not a blob this component produced (unknown or unsupported version). */
        UNSUPPORTED_FORMAT("The supplied data is not in a supported format"),
        /** The record's version is known but the caller has no key authorised to read it. */
        KEY_UNAVAILABLE("The data could not be decrypted"),
        /** The key that would be needed is present but not yet usable (not yet valid / destroyed). */
        KEY_NOT_ACTIVE("The data could not be decrypted"),
        /** AES-GCM tag verification failed. Covers a wrong key, a tampered blob and a wrong context. */
        AUTHENTICATION_FAILED("The data could not be decrypted"),
        /** Key material was supplied in a form this component refuses to accept. */
        INVALID_KEY("The data could not be decrypted"),
        /** A key or password source is absent or unusable. Never contains the secret. */
        KEY_SOURCE_UNAVAILABLE("The data could not be decrypted"),
        /** A key store or key file failed its ownership or permission requirements. */
        INSECURE_KEY_STORAGE("The data could not be decrypted"),
        /** A ciphertext exceeded {@link Limits#MAX_CIPHERTEXT_BYTES} before anything was allocated. */
        TOO_LARGE("The supplied data is not in a supported format"),
        /** The underlying platform refused the primitive. Fails closed; nothing is substituted. */
        PROVIDER_FAILURE("The data could not be processed");

        private final String userMessage;

        CryptoFailureCode(String userMessage) {
            this.userMessage = userMessage;
        }

        /** Generic text for this code. Contains no record, key, path or existence information. */
        public String userMessage() {
            return userMessage;
        }
    }

    /*
     * Not transient. `getMessage()` returns `code.userMessage()`, so a code that did not survive
     * deserialization would make the generic message throw a NullPointerException - on the error path,
     * where the caller's own handler replaces the safe fixed vocabulary with an unrelated failure. The
     * enum names only a category, so serializing it discloses nothing. `technicalDetail` stays
     * transient: it can name a path or a component, and it is meant for the log of the JVM that made it.
     */
    private final CryptoFailureCode code;
    private final transient String technicalDetail;

    CryptoException(String detail) {
        this(CryptoFailureCode.INVALID_INPUT, detail, null);
    }

    CryptoException(CryptoFailureCode code, String detail) {
        this(code, detail, null);
    }

    CryptoException(CryptoFailureCode code, String detail, Throwable cause) {
        super(code.userMessage(), cause, /*enableSuppression*/ false, /*writableStackTrace*/ false);
        this.code = code;
        this.technicalDetail = detail;
    }

    /** Failure category. */
    public CryptoFailureCode code() {
        return code;
    }

    /**
     * Generic, renderable message. Deliberately identical for every failure that concerns a secret,
     * so a response cannot be used to distinguish a wrong key from a tampered blob.
     */
    @Override
    public String getMessage() {
        return code.userMessage();
    }

    /**
     * One-line diagnostic for logging. Never contains key bytes, passwords, plaintext, file
     * contents, or a cause's message that might itself contain any of those.
     */
    public String getTechnicalDetail() {
        return technicalDetail;
    }

    /**
     * Writes the generic message only. The technical detail and the cause are intentionally
     * omitted so that {@code log.error("...", e)} cannot leak them through this exception's own
     * rendering; log {@link #getTechnicalDetail()} explicitly if it is wanted.
     */
    @Override
    public void printStackTrace(java.io.PrintStream ps) {
        ps.println(getClass().getName() + ": " + getMessage());
    }

    @Override
    public void printStackTrace(java.io.PrintWriter pw) {
        pw.println(getClass().getName() + ": " + getMessage());
    }

    /**
     * Returns a cause with its message stripped, so that generic logging of {@code getCause()}
     * cannot surface a provider message. Callers that genuinely need the original exception should
     * use {@link #getUnderlyingCause()} from trusted internal code.
     */
    @Override
    public synchronized Throwable getCause() {
        Throwable t = super.getCause();
        if (t == null) {
            return null;
        }
        return new ProviderFailure(t.getClass().getName());
    }

    /** Real cause, for internal diagnostics only. Never render this to an untrusted audience. */
    public synchronized Throwable getUnderlyingCause() {
        return super.getCause();
    }

    /**
     * {@link #getMessage()} is final-by-override above, so this type only ever carries its own
     * message. {@code ProviderFailure} exists to replace the wrapped cause's message with its class
     * name; provider messages can quote key lengths, algorithm parameters and file paths.
     */
    private static final class ProviderFailure extends Exception {
        private static final long serialVersionUID = 1L;

        ProviderFailure(String causeClassName) {
            super("provider failure: " + causeClassName, null, false, false);
        }
    }
}
