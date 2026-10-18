package com.acme.portal.session;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Default assertion source: the authenticator, running in the same JVM behind this servlet, stashes
 * the session identifier it just created under a namespaced request attribute.
 *
 * <p>A request attribute is set by server-side code and cannot be written by a client, which is why
 * this is a safe default. The attribute key comes from validated configuration
 * ({@link SessionHandoffSettings#assertionAttribute()}) so an integrator can match whatever their
 * filter uses without editing code.
 *
 * <p>Only a {@link String} value is accepted. Any other object type is treated as "no assertion", so
 * a mis-pointed attribute name cannot make this component call {@code toString()} on an unrelated
 * object and treat the result as a session identifier.
 */
public final class RequestAttributeAssertionSource implements TrustedSessionAssertionSource {

    private final String attributeName;

    public RequestAttributeAssertionSource(String attributeName) {
        if (attributeName == null || attributeName.isEmpty()) {
            throw new IllegalArgumentException("assertion attribute name is required");
        }
        this.attributeName = attributeName;
    }

    @Override
    public String assertedSessionId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object asserted;
        try {
            asserted = request.getAttribute(attributeName);
        } catch (RuntimeException attributeUnavailable) {
            // A container that cannot hand us an attribute has asserted nothing. Refuse, and do not
            // include the failure text: attribute names are configuration, not diagnostics.
            return null;
        }
        if (!(asserted instanceof String)) {
            return null;
        }
        return (String) asserted;
    }
}
