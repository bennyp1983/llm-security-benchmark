/**
 * Post-authentication session-cookie component.
 *
 * <p>Scope: this package does <em>not</em> authenticate users and does not create or
 * validate server-side sessions. A separate, trusted component does that. This package
 * only takes an already-created server-side session identifier and returns it to the
 * browser in a hardened cookie, then hardens the response that carries it.</p>
 *
 * <p>Trust model: every value reaching this package -- request attributes, headers,
 * configuration, and the records returned by {@link com.example.websession.TrustedSessionService}
 * -- is treated as attacker-controlled and validated before use.</p>
 */
package com.example.websession;
