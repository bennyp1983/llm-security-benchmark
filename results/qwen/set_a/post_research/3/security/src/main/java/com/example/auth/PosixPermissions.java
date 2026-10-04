package com.example.auth;

import java.io.IOException;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/** The one place POSIX permission sets are spelled out. */
final class PosixPermissions {

    /** {@code rw-------} : readable and writable by the owner only. */
    static final Set<PosixFilePermission> OWNER_ONLY =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    /** {@code rwx------} : a directory no other account can list, traverse, or add to. */
    static final Set<PosixFilePermission> OWNER_ONLY_DIR = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE);

    private PosixPermissions() {
    }
}
