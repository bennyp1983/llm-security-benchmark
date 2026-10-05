package com.example.identity;

/**
 * Machine-readable outcomes.
 *
 * <p>Split in two on purpose: {@link #genericUserMessage()} is the only text that may reach the
 * person at the keyboard, and it is deliberately identical for every outcome that would otherwise
 * disclose whether an account, row or session exists. The specific {@link Reason} goes to the audit
 * log only, where an operator needs it.
 *
 * <p>The "which outcomes share a message" table is a security control, so it is asserted in the
 * test suite ({@code OutcomeMessageTest}) rather than left to convention.
 */
public enum Reason {

    // --- accepted -------------------------------------------------------------
    ACCOUNT_CREATED("Account created."),
    AUTHENTICATED("Signed in."),
    /**
     * Session id was live and is now gone. Message is shared with {@link #ALREADY_REVOKED} on
     * purpose: if the two differed, presenting a random token would tell an attacker whether some
     * session id had ever existed.
     */
    SESSION_REVOKED("Session revoked."),
    /**
     * Nothing was deleted. Distinct from {@link #SESSION_REVOKED} in the audit log only; the user
     * message is identical so revocation is not a token-existence oracle.
     */
    ALREADY_REVOKED("Session revoked."),

    // --- refused: indistinguishable from each other on purpose ----------------
    /** Identifier not in the database. Message identical to a wrong password. */
    ABSENT_ACCOUNT("Sign-in failed."),
    /** Password did not match. */
    BAD_CREDENTIAL("Sign-in failed."),
    /** Row present but failing strict re-validation; treated as nonexistent. */
    CORRUPT_RECORD("Sign-in failed."),
    /**
     * Correct password, administratively disabled account. Same message as a wrong password, so
     * "is this account disabled" is not answerable by an unauthenticated caller. The cost is that
     * the owner cannot tell their account is disabled from a typo - see README "Limitations".
     */
    ACCOUNT_DISABLED("Sign-in failed."),
    /** Session id unknown, expired, or erased. Never says which. */
    INVALID_SESSION("Session is not active."),
    /** Throttle window not yet elapsed. Same wording as a wrong password. */
    THROTTLED("Sign-in failed."),
    /** Registration rate limited, per source or globally. */
    REGISTRATION_THROTTLED("Registration is temporarily unavailable."),
    /** Same message as a duplicate username, so registration cannot enumerate accounts. */
    EMAIL_TAKEN("That account could not be registered."),
    /** Same message as an email collision. */
    USERNAME_TAKEN("That account could not be registered."),
    /** Same message as a taken name, and deliberately similar to a sign-in failure. */
    ACCOUNT_CAP_REACHED("That account could not be registered."),

    /**
     * What a caller gets back for either collision. The store still classifies the collision as
     * {@link #USERNAME_TAKEN} or {@link #EMAIL_TAKEN} and the audit log records which, because an
     * operator investigating a ticket needs the fact. The <em>returned</em> reason is collapsed:
     * both facts disclose that an account exists, so any distinction carried by the value a front
     * end receives - not only in the text it prints - is the enumeration oracle Rule 6 forbids.
     */
    REGISTRATION_DUPLICATE("That account could not be registered."),

    // --- refused: input is the caller's own, so it may be specific -----------
    /** Validation feedback. Never leaks whether any account exists. */
    INVALID_EMAIL("The e-mail address is not valid."),
    INVALID_USERNAME("The username is not valid."),
    INVALID_PASSWORD("The password is not acceptable."),
    /** Unknown or unusable command line. */
    INVALID_REQUEST("The request could not be understood."),
    /** Session id was not a well-formed token; no database access happened. */
    MALFORMED_TOKEN("The session token is not valid."),

    // --- operational failures: fail closed, generic to the user --------------
    STORAGE_UNAVAILABLE("The service is unavailable."),
    CONFIG_INVALID("The service is not configured correctly."),
    CRYPTO_FAILURE("The service is unavailable."),
    AUDIT_FAILURE("The service is unavailable.");

    private final String genericUserMessage;

    Reason(String genericUserMessage) {
        this.genericUserMessage = genericUserMessage;
    }

    /** The only string about this outcome that may be shown to a caller. */
    public String genericUserMessage() {
        return genericUserMessage;
    }

    /**
     * The reason that may be <em>returned</em> to a caller, as opposed to logged.
     *
     * <p>Currently only the two collisions need collapsing. A username collision and an email
     * collision are different facts for the operator investigating a ticket and identical secrets for
     * an attacker - each one answers "does this account exist?" - so both are returned as
     * {@link #REGISTRATION_DUPLICATE}. Collapsing only the printed text would be no protection: a
     * front end can branch on the enum, serialise it, or put it in a header, and the oracle is back.
     * Call sites that write the audit log deliberately pass the uncollapsed reason.
     */
    public Reason forCaller() {
        return switch (this) {
            case USERNAME_TAKEN, EMAIL_TAKEN -> REGISTRATION_DUPLICATE;
            default -> this;
        };
    }

    /** True when the message is about the caller's own input, not about server state. */
    public boolean describesCallerInput() {
        return switch (this) {
            case INVALID_EMAIL, INVALID_USERNAME, INVALID_PASSWORD, INVALID_REQUEST, MALFORMED_TOKEN -> true;
            default -> false;
        };
    }

    public boolean isSuccess() {
        return switch (this) {
            case ACCOUNT_CREATED, AUTHENTICATED, SESSION_REVOKED, ALREADY_REVOKED -> true;
            default -> false;
        };
    }

    /**
     * Outcomes where a full derivation worth of work must still be spent, so that response time
     * does not identify which branch was taken.
     *
     * <p>{@link #THROTTLED} is deliberately <em>not</em> in this list, and is not an existence
     * oracle either: throttle rows are created for identifiers that do not exist (the upsert
     * happens before any lookup), so a cheap refusal is equally available when guessing an existing
     * account and when guessing a nonexistent one. Charging the derivation on the throttled branch
     * would defeat the limiter whose entire purpose is to bound that cost.
     */
    public boolean mustMatchVerificationCost() {
        return switch (this) {
            case ABSENT_ACCOUNT, CORRUPT_RECORD, BAD_CREDENTIAL, INVALID_PASSWORD -> true;
            default -> false;
        };
    }
}
