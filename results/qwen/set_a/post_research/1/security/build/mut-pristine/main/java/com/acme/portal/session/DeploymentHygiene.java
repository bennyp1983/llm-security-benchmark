package com.acme.portal.session;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Startup check for the one class of deployment mistake that turns a correct component into remote
 * code execution: loading classes from somewhere another local account can write.
 *
 * <p>The component reads no files itself, so file permissions would be moot if it stayed alone. But
 * it does one thing that pulls the environment in: it discovers the application's session verifier
 * through a service loader, and a loader follows the classpath. If any location on that path is
 * writable by another account, that account can supply the code that answers "is this session
 * valid", and every guard in this package becomes decoration. Rule 8 asks for exactly this check, so
 * it is performed and enforced rather than assumed.
 *
 * <p>What is inspected: every JVM classpath entry, plus the code-source location (and its parent
 * directory, because a writable directory lets a file be replaced even when the file is not) of this
 * class and of the resolved verifier -- the two code bases that actually decide the outcome.
 *
 * <p>Descriptions name a path and nothing else. Paths are configuration, not secrets, and the text
 * stays terse because it reaches a log line.
 */
final class DeploymentHygiene {

    private static final int MAX_ENTRIES = 512;
    private static final int MAX_PATH_LENGTH = 4096;

    private DeploymentHygiene() {
    }

    /**
     * @param codeOwners classes whose own code location must be trustworthy; typically this class and
     *                   the resolved session verifier
     * @return {@code null} when the deployment looks safe, otherwise a one-line reason to refuse
     *         service. An unreadable location is reported as a problem: "unknown" is not "safe".
     */
    static String describeProblem(Class<?>... codeOwners) {
        Set<Path> locations = new LinkedHashSet<Path>();
        String classpath = System.getProperty("java.class.path", "");
        if (!classpath.isEmpty()) {
            String[] entries = classpath.split(File.pathSeparator);
            if (entries.length > MAX_ENTRIES) {
                return "the JVM classpath has more than " + MAX_ENTRIES + " entries";
            }
            for (String entry : entries) {
                Path path = toPath(entry);
                if (path != null) {
                    locations.add(path);
                }
            }
        }
        for (Class<?> codeOwner : codeOwners) {
            if (codeOwner == null) {
                return "a required code owner was not supplied";
            }
            Path fromCodeSource = codeSourceLocation(codeOwner);
            if (fromCodeSource == null) {
                // Cannot establish where this class was loaded from, so cannot prove it is not
                // somebody else's to write. Unknown is not safe.
                return "the code location of " + codeOwner.getName() + " could not be established";
            }
            locations.add(fromCodeSource);
        }
        for (Path location : locations) {
            if (!Files.exists(location)) {
                // A classpath entry with nothing there is not evidence of safety: the verdict was
                // reached without seeing a single permission bit, and an entry that was removed (or
                // was never extracted) between the packaging step and this check is precisely the
                // window in which a location changes hands. Reported, not skipped.
                return "a code location named by the deployment is not present to be inspected: "
                        + logSafe(location);
            }
            if (worldWritable(location)) {
                return "code is loadable from a location other users can write: " + logSafe(location);
            }
            Path parent = location.getParent();
            if (parent != null && Files.isDirectory(parent) && worldWritable(parent)) {
                return "code is loadable from a directory other users can write: " + logSafe(parent);
            }
        }
        return null;
    }

    /**
     * Text for a refusal reason, which ends up on the console.
     *
     * <p>A path is configuration, not a secret -- but it is also the one string here that a packaging
     * step, and therefore anything that can write a build, influences. Control characters stripped
     * rather than escaped, because a filename carrying CR or LF is the only way this component could
     * ever be made to write a log line it did not author. Everything else, including every other byte
     * of the path, is passed through so the operator still recognises it.
     */
    private static String logSafe(Path location) {
        String text = String.valueOf(location);
        StringBuilder safe = new StringBuilder(Math.min(text.length(), MAX_PATH_LENGTH));
        for (int i = 0; i < text.length() && safe.length() < MAX_PATH_LENGTH; i++) {
            char c = text.charAt(i);
            if (c >= 0x20 && c != 0x7F) {
                safe.append(c);
            }
        }
        return safe.length() == 0 ? "(unnamed location)" : safe.toString();
    }

    private static Path toPath(String entry) {
        if (entry == null || entry.isEmpty() || entry.length() > MAX_PATH_LENGTH) {
            return null;
        }
        try {
            return Paths.get(entry);
        } catch (RuntimeException | Error unparseable) {
            return null;
        }
    }

    private static Path codeSourceLocation(Class<?> owner) {
        try {
            ProtectionDomain domain = owner.getProtectionDomain();
            CodeSource source = domain == null ? null : domain.getCodeSource();
            if (source == null || source.getLocation() == null) {
                return null;
            }
            java.net.URL location = source.getLocation();
            if (!"file".equalsIgnoreCase(location.getProtocol())) {
                // A jar over http or a nested module location cannot be judged by POSIX bits, and
                // neither is a directory an attacker could have written in place.
                return null;
            }
            return toPath(java.net.URLDecoder.decode(location.getPath(),
                    java.nio.charset.StandardCharsets.UTF_8));
        } catch (RuntimeException | Error unavailable) {
            return null;
        }
    }

    private static boolean worldWritable(Path path) {
        try {
            Set<java.nio.file.attribute.PosixFilePermission> permissions =
                    Files.getPosixFilePermissions(path);
            return permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
        } catch (UnsupportedOperationException notPosix) {
            // A filesystem without POSIX bits cannot be judged here. Fail closed: the integrator has
            // to run this component where the check can actually be made.
            return true;
        } catch (IOException unreadable) {
            return true;
        }
    }
}
