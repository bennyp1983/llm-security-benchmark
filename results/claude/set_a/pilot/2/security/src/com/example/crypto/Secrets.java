package com.example.crypto;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Set;

/** Helpers for reading secrets from the deployment environment and for locking down files. */
public final class Secrets {

    private Secrets() {}

    /**
     * Reads a secret from an environment variable, or prompts on the console when the variable
     * is unset and a console is attached.
     *
     * <p>Environment variables and interactive prompts are used rather than command-line
     * arguments because arguments are visible to every user on the host through the process
     * table and are routinely captured in shell history.
     */
    public static char[] read(String envVar, String prompt) {
        String fromEnv = System.getenv(envVar);
        if (fromEnv != null && !fromEnv.isEmpty()) {
            return fromEnv.toCharArray();
        }
        Console console = System.console();
        if (console != null) {
            char[] entered = console.readPassword("%s: ", prompt);
            if (entered != null && entered.length > 0) {
                return entered;
            }
        }
        throw new IllegalStateException(
                "no value for " + envVar + " and no console available to prompt for " + prompt);
    }

    /** Overwrites a secret held in memory once it is no longer needed. */
    public static void wipe(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, '\0');
        }
    }

    /** Overwrites a secret held in memory once it is no longer needed. */
    public static void wipe(byte[] secret) {
        if (secret != null) {
            Arrays.fill(secret, (byte) 0);
        }
    }

    /**
     * Restricts a file holding key material to its owner. On filesystems without POSIX
     * permissions this is a no-op, so it is a hardening step rather than a guarantee.
     */
    public static void restrictToOwner(Path path) throws IOException {
        PosixFileAttributeView view =
                Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view != null) {
            view.setPermissions(PosixFilePermissions.fromString("rw-------"));
        }
    }

    /** True when the file is readable by anyone other than its owner. */
    public static boolean isWorldOrGroupReadable(Path path) throws IOException {
        PosixFileAttributeView view =
                Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            return false;
        }
        Set<PosixFilePermission> perms = view.readAttributes().permissions();
        return perms.contains(PosixFilePermission.GROUP_READ)
                || perms.contains(PosixFilePermission.OTHERS_READ);
    }

    /** Decodes UTF-8 text into a byte array without interning it in the string pool. */
    public static byte[] toUtf8(char[] chars) {
        java.nio.ByteBuffer buf = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(chars));
        byte[] out = new byte[buf.remaining()];
        buf.get(out);
        Arrays.fill(buf.array(), (byte) 0);
        return out;
    }
}
