-- Table used by UserAuthenticator.java.
-- The program creates this table automatically if it does not exist;
-- this file is provided for database administrators who prefer to create it by hand.
--
-- Passwords are NOT stored here. Each row holds a random salt and a
-- PBKDF2-HMAC-SHA256 hash of the password (both Base64-encoded).
-- Use "java UserAuthenticator add-user" to add users, so hashes are generated correctly.

CREATE TABLE IF NOT EXISTS users (
    email         VARCHAR(255) PRIMARY KEY,  -- stored in lower case
    password_hash VARCHAR(255) NOT NULL,
    salt          VARCHAR(255) NOT NULL,
    iterations    INTEGER      NOT NULL
);
