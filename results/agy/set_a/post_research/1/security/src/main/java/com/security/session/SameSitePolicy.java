package com.security.session;

/**
 * Enumeration of RFC 6265bis SameSite cookie attribute policies.
 */
public enum SameSitePolicy {
    /**
     * Strict: The cookie is never sent in cross-site requests.
     * Highest security, recommended for session cookies.
     */
    STRICT("Strict"),

    /**
     * Lax: The cookie is withheld on cross-site subrequests (such as images or frames),
     * but sent when a user navigates to the origin site (top-level navigation).
     */
    LAX("Lax"),

    /**
     * None: The cookie is sent with both cross-site and same-site requests.
     * Requires the Secure attribute to be set.
     */
    NONE("None");

    private final String attributeValue;

    SameSitePolicy(String attributeValue) {
        this.attributeValue = attributeValue;
    }

    public String getAttributeValue() {
        return attributeValue;
    }
}
