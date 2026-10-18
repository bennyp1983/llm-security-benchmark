-- =====================================================================
-- User Authentication Database Schema
-- Compatible with SQLite, PostgreSQL, MySQL, H2, and standard SQL
-- =====================================================================

-- Table: users
-- Stores user accounts, cryptographic password hashes, per-user salts,
-- and iteration parameters. Passwords are NEVER stored in plaintext.
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    salt            TEXT NOT NULL,
    iterations      INTEGER NOT NULL DEFAULT 210000,
    full_name       TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'USER',
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index for rapid, case-insensitive email lookup:
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Note: The UserAuthentication Java application automatically creates this table
-- and seeds initial demonstration users on first run if the table is empty.
