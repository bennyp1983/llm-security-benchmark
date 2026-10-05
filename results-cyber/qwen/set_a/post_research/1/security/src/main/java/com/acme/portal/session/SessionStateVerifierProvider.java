package com.acme.portal.session;

import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Discovers the application's {@link SessionHandoffService.SessionStateVerifier} from the classpath.
 *
 * <p>Why a service loader and not a hard dependency: this component must not know where sessions
 * live. It needs one boolean from whoever owns that state, and a compile-time dependency on a
 * datastore would either drag a driver in or force a second HTTP hop with its own timeout, retry and
 * failure semantics to get right.
 *
 * <p>The two risks a loader introduces are both closed here:
 * <ul>
 *   <li><b>Ambiguity.</b> More than one provider is a configuration error with an obvious
 *       security consequence -- which store wins? -- so it is refused rather than resolved by
 *       classpath order.</li>
 *   <li><b>Foreign code.</b> Whatever is loaded is the authority on "is this session valid", so its
 *       code location is handed to {@link DeploymentHygiene} and a writable location stops the
 *       component from serving at all. The discovery below is deliberately shaped so that check
 *       happens <i>before</i> the candidate is instantiated: a hygiene verdict reached after the
 *       class has run its static initialiser and constructor reports a compromise, it does not
 *       prevent one.</li>
 * </ul>
 *
 * <p>The interface is declared in this package and implemented by the application; {@code
 * META-INF/services} names the implementation. A provider that throws in its constructor, or cannot
 * be instantiated, yields {@code null} and the servlet refuses every request.
 */
public final class SessionStateVerifierProvider {

    private static final Logger LOG = Logger.getLogger(SessionStateVerifierProvider.class.getName());

    private SessionStateVerifierProvider() {
    }

    /**
     * @return the single deployed verifier, or {@code null} if there is none, more than one, or the
     *         deployed one cannot be constructed. Never returns a substitute that guesses.
     */
    public static SessionHandoffService.SessionStateVerifier load() {
        return load(SessionStateVerifierProvider.class.getClassLoader());
    }

    /**
     * Same contract, over an explicit loader. Package private on purpose: no caller outside this
     * package has any business choosing where the verifier is looked for. The seam exists because the
     * ordering below is invisible in the return value -- a candidate in a writable location yields
     * {@code null} whether it was refused or merely refused after it had already run -- so the only way
     * to test that the gate precedes the code is to point the loader at a directory whose mode the test
     * controls and ask whether the candidate's class initialiser ran.
     */
    static SessionHandoffService.SessionStateVerifier load(ClassLoader where) {
        ServiceLoader<SessionHandoffService.SessionStateVerifier> loader =
                ServiceLoader.load(SessionHandoffService.SessionStateVerifier.class, where);
        java.util.List<ServiceLoader.Provider<SessionHandoffService.SessionStateVerifier>> providers =
                new java.util.ArrayList<ServiceLoader.Provider<SessionHandoffService.SessionStateVerifier>>();
        try {
            // stream() rather than iterator(), and it matters: a Provider element hands over its
            // Class without constructing anything, and the loader defines a candidate class without
            // initialising it. So the static initialiser and the constructor of a candidate have not
            // run at the point the hygiene verdict is reached below. With iterator() the old code
            // called next(), which built the object -- meaning that by the time the servlet asked
            // where the verifier came from, the code from that location had already executed. The
            // check belonged to the post-mortem department, and a verifier planted in a writable
            // directory had already had its turn.
            loader.stream().forEach(providers::add);
        } catch (ServiceConfigurationError discoveryFailed) {
            LOG.log(Level.SEVERE, "the session verifier could not be discovered, exceptionType={0}",
                    discoveryFailed.getClass().getName());
            return null;
        }
        if (providers.isEmpty()) {
            return null;
        }
        if (providers.size() > 1) {
            // Counted without instantiating any of them, so an ambiguous deployment -- which store
            // wins? -- refuses without executing any candidate's code either.
            LOG.log(Level.SEVERE, "more than one session verifier is deployed; refusing to"
                    + " guess which session store is authoritative");
            return null;
        }
        ServiceLoader.Provider<SessionHandoffService.SessionStateVerifier> only = providers.get(0);
        Class<?> candidate;
        try {
            candidate = only.type();
        } catch (ServiceConfigurationError unloadable) {
            LOG.log(Level.SEVERE, "the deployed session verifier could not be loaded,"
                    + " exceptionType={0}", unloadable.getClass().getName());
            return null;
        }
        // The gate that the ordering above exists to make meaningful: this class is about to run
        // code this component does not own, and it is the authority on whether a session exists, so
        // its code location is proven read-only first. Names no path to the caller, and the reason it
        // returns names a path and nothing else.
        String hygieneProblem;
        try {
            hygieneProblem = DeploymentHygiene.describeProblem(candidate);
        } catch (RuntimeException hygieneCheckFailed) {
            hygieneProblem = "the deployment hygiene check failed: "
                    + hygieneCheckFailed.getClass().getName();
        }
        if (hygieneProblem != null) {
            LOG.log(Level.SEVERE, "a deployed session verifier was refused before it was"
                    + " instantiated: {0}", hygieneProblem);
            return null;
        }
        final SessionHandoffService.SessionStateVerifier verifier;
        try {
            verifier = only.get();
        } catch (ServiceConfigurationError brokenProvider) {
            LOG.log(Level.SEVERE, "a deployed session verifier could not be instantiated,"
                    + " exceptionType={0}", brokenProvider.getClass().getName());
            return null;
        }
        if (verifier == null) {
            LOG.log(Level.SEVERE, "a deployed session verifier factory returned null");
            return null;
        }
        // Log the loaded class name only. It is a class, not a credential, and an operator needs it to
        // diagnose "why is everything refused".
        LOG.log(Level.INFO, "session verifier loaded from {0}", candidate.getName());
        return verifier;
    }
}
