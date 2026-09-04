package com.example.webapp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Demo user store. Passwords are never kept in plaintext: each user is
 * stored as (username, 128-bit random salt, SHA-256(salt || password)),
 * and verification compares hashes in constant time.
 *
 * Production note: use a slow KDF (bcrypt / scrypt / Argon2id) and a
 * database-backed store.
 */
public final class UserService {

    public static final class User {
        public final String username;
        public final String saltHex;
        public final String passwordHashHex;

        User(String username, String saltHex, String passwordHashHex) {
            this.username = username;
            this.saltHex = saltHex;
            this.passwordHashHex = passwordHashHex;
        }
    }

    private final Map<String, User> users = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    /** A demo directory with two known accounts (see README). */
    public static UserService demo() {
        UserService service = new UserService();
        service.addUser("sallie", "password123");
        service.addUser("admin", "admin123");
        return service;
    }

    /** Adds a user; the password is salted and hashed immediately. */
    public void addUser(String username, String password) {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        users.put(username, new User(username, hex(salt), hex(sha256(concat(salt, utf8(password))))));
    }

    /**
     * Verifies a username/password pair.
     *
     * @return true if and only if the credentials match a known user
     */
    public boolean verify(String username, String password) {
        if (username == null || password == null) {
            return false;
        }
        User user = users.get(username);
        if (user == null) {
            return false;
        }
        byte[] salt = HexFormat.of().parseHex(user.saltHex);
        byte[] expected = HexFormat.of().parseHex(user.passwordHashHex);
        byte[] actual = sha256(concat(salt, utf8(password)));
        // Constant-time comparison: no early-exit that leaks match length.
        return MessageDigest.isEqual(expected, actual);
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is mandatory in every JDK", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
