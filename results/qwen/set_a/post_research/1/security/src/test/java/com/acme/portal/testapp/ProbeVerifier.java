package com.acme.portal.testapp;

import com.acme.portal.session.SessionHandoffService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Discovery probe for the harness, never deployed.
 *
 * <p>Its reason for existing is the static initialiser: writing a marker file is a side effect a test
 * can look for afterwards, which is the only way to tell whether {@code SessionStateVerifierProvider}
 * reached its hygiene verdict about the directory this class was loaded from <i>before</i> that class
 * ran any code of its own. The refusal looks identical either way -- {@code null} in both cases -- so a
 * return value cannot carry the answer.
 *
 * <p>The marker path comes from a system property the harness sets, because a class loaded from a copy
 * in a temporary directory cannot be handed a constructor argument: {@code ServiceLoader} requires a
 * public no-argument constructor, which is itself part of what the loader must refuse to run blindly.
 */
public final class ProbeVerifier implements SessionHandoffService.SessionStateVerifier {

    static {
        String marker = System.getProperty("portal.probe.marker");
        if (marker == null) {
            throw new IllegalStateException("portal.probe.marker is not set; this class exists only"
                    + " for the harness, which sets it before loading a copy of this file");
        }
        try {
            Files.write(Path.of(marker), "initialised".getBytes(StandardCharsets.US_ASCII),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException couldNotMark) {
            // A test looks for the absence of the marker, so a marker that could not be written must
            // not be mistaken for evidence that the initialiser never ran.
            throw new IllegalStateException("the probe initialiser ran but could not write its marker",
                    couldNotMark);
        }
    }

    /** Required by {@code ServiceLoader}; also the moment the mutant version would reach. */
    public ProbeVerifier() {
    }

    @Override
    public boolean isSessionValid(String sessionId) {
        return false;
    }
}
