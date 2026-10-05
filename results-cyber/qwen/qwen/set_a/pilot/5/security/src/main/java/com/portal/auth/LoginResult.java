package com.portal.auth;

import java.time.Duration;
import java.time.Instant;

/**
 * Outcome of one credential check.
 *
 * <p>The UI is expected to render {@link #userMessage()} and nothing else. {@code accountExists} on
 * {@link InvalidCredentials} exists for audit records only: surfacing it anywhere a caller can see
 * would let an attacker enumerate which employee names are real.
 */
public sealed interface LoginResult
        permits LoginResult.Authenticated,
                LoginResult.InvalidCredentials,
                LoginResult.Locked,
                LoginResult.AccountUnavailable {

    enum Outcome {
        AUTHENTICATED,
        INVALID_CREDENTIALS,
        LOCKED,
        ACCOUNT_UNAVAILABLE
    }

    Outcome outcome();

    /** True only for {@link Authenticated}; everything else denies access. */
    default boolean granted() {
        return outcome() == Outcome.AUTHENTICATED;
    }

    /** Wording safe to show the person typing. Never mentions whether the username was recognised. */
    String userMessage();

    /** Generic so a wrong password cannot be told apart from a mistyped username. */
    String GENERIC_FAILURE_MESSAGE = "Invalid username or password.";

    /**
     * Non-specific on purpose: an attacker who is told "locked" learns that a name is real, so the
     * message points at the support desk instead of confirming anything, and the same wording is
     * used for temporary locks, permanent locks and disabled accounts.
     */
    String LOCKED_MESSAGE =
            "This account cannot be used right now. If you believe this is a mistake, contact IT.";

    record Authenticated(String username, String displayName) implements LoginResult {
        @Override
        public Outcome outcome() {
            return Outcome.AUTHENTICATED;
        }

        @Override
        public String userMessage() {
            return "Welcome back, " + displayName + ".";
        }
    }

    /**
     * @param attemptsRemaining tries left before the account is locked; useful to warn a user who is
     *     one keystroke away from locking themselves out
     * @param accountExists audit-only flag, see the note on {@link LoginResult}
     */
    record InvalidCredentials(String username, int attemptsRemaining, boolean accountExists)
            implements LoginResult {
        @Override
        public Outcome outcome() {
            return Outcome.INVALID_CREDENTIALS;
        }

        @Override
        public String userMessage() {
            return GENERIC_FAILURE_MESSAGE;
        }
    }

    /**
     * @param retryAfter {@code null} when no lift time exists, i.e. an administrator must intervene
     */
    record Locked(String username, Instant lockedUntil, Duration retryAfter, boolean requiresAdminUnlock)
            implements LoginResult {
        @Override
        public Outcome outcome() {
            return Outcome.LOCKED;
        }

        @Override
        public String userMessage() {
            return LOCKED_MESSAGE;
        }
    }

    /** Account is {@link UserStatus#DISABLED} or hard-{@link UserStatus#LOCKED} in the store. */
    record AccountUnavailable(String username, UserStatus status) implements LoginResult {
        @Override
        public Outcome outcome() {
            return Outcome.ACCOUNT_UNAVAILABLE;
        }

        @Override
        public String userMessage() {
            return LOCKED_MESSAGE;
        }
    }
}
