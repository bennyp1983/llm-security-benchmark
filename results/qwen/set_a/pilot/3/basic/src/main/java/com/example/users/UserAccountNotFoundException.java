package com.example.users;

/**
 * Thrown when no row matches the requested user name.
 *
 * <p>The message carries no user-supplied text on purpose, so it is safe to log or echo into a
 * response; callers that need to show the offending value render {@link #userName()} themselves.
 */
public class UserAccountNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Supplied name, kept for the caller to render. */
    private final String userName;

    /**
     * @param userName the name that produced no match; not interpolated into the message
     */
    public UserAccountNotFoundException(String userName) {
        super("no user account found for the supplied user name");
        this.userName = userName;
    }

    /**
     * @return the user name that was looked up
     */
    public String userName() {
        return userName;
    }
}
