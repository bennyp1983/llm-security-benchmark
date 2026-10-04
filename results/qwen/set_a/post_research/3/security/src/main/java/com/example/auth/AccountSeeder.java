package com.example.auth;

/**
 * Creates accounts. This is the only place a credential is written, and it is the reason the program
 * contains no credential at all: the store starts empty and accounts appear only through a password
 * the operator types at runtime (or pipes in for a scripted setup).
 *
 * <p>Each account gets a fresh 16-byte {@link java.security.SecureRandom} salt and the configured
 * iteration count. An existing address is refused rather than overwritten - silently replacing a
 * credential is how a seeding script becomes a takeover path - and there is deliberately no
 * "change password" or "delete account" path in this program, so the only way to alter a stored
 * credential is to replace the file, which {@link Database#findAccount} then re-validates row by row.
 */
final class AccountSeeder {

    enum SeedResult {
        CREATED,
        ALREADY_EXISTS,
        REJECTED
    }

    private final Config config;
    private final Database database;
    private final PasswordHasher hasher;
    private final LogWriter log;

    AccountSeeder(Config config, Database database, LogWriter log) {
        this.config = config;
        this.database = database;
        this.log = log;
        this.hasher = new PasswordHasher(config.iterations());
    }

    /**
     * Validates, hashes and stores one credential pair. {@code password} is owned by the caller and is
     * not wiped here; nothing about it is returned or logged.
     *
     * @throws Database.StorageException on a storage failure, which the caller reports generically
     */
    SeedResult seed(String rawEmail, char[] password) throws Database.StorageException {
        String normalised;
        try {
            normalised = InputValidator.requireEmail(rawEmail);
            InputValidator.requirePassword(password, config.passwordMinLength());
        } catch (InputValidator.ValidationException e) {
            log.log(LogWriter.Event.SEED_REJECTED, "*", 0);
            return SeedResult.REJECTED;
        }
        byte[] salt = hasher.newSalt();
        byte[] digest;
        try {
            digest = hasher.derive(password, salt, config.iterations());
        } catch (PasswordHasher.AuthFailure e) {
            CryptoUtils.wipe(salt);
            log.log(LogWriter.Event.LOGIN_INTERNAL, "*", 0);
            return SeedResult.REJECTED;
        }
        try {
            database.insertAccount(AuthService.identityHash(normalised), PasswordHasher.ALGORITHM,
                    config.iterations(), salt, digest, System.currentTimeMillis() / 1000L);
        } catch (Database.StorageException e) {
            CryptoUtils.wipe(salt);
            CryptoUtils.wipe(digest);
            // The unique index on email_hash is the only expected failure, and it means the address
            // is already provisioned. Nothing is overwritten; the engine detail is logged as a code.
            if (isUniqueViolation(e)) {
                log.log(LogWriter.Event.SEED_EXISTS, LogWriter.maskEmail(normalised), 0);
                return SeedResult.ALREADY_EXISTS;
            }
            throw e;
        }
        CryptoUtils.wipe(salt);
        CryptoUtils.wipe(digest);
        log.log(LogWriter.Event.SEED_OK, LogWriter.maskEmail(normalised), 0);
        return SeedResult.CREATED;
    }

    /**
     * Recognises the unique-constraint failure from the SQL state rather than the engine's message,
     * which can name the table and the conflicting value.
     */
    private static boolean isUniqueViolation(Database.StorageException e) {
        Throwable cause = e.getCause();
        if (!(cause instanceof java.sql.SQLException)) {
            return false;
        }
        String state = ((java.sql.SQLException) cause).getSQLState();
        // 23505 is H2's unique violation; 23 is the standard integrity-constraint class.
        return state != null && state.startsWith("23");
    }
}
