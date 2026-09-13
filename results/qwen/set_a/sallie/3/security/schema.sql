-- Schema for the email/password login example.
--
-- The password column holds only a salted digest in the form
--   pbkdf2-sha256$<iterations>$<base64 salt>$<base64 digest>
-- never the password itself. 300 characters leaves room for a larger iteration count or
-- digest, so a valid credential is never silently truncated by the column.

CREATE TABLE IF NOT EXISTS users (
    email         VARCHAR(254)  NOT NULL,
    password_hash VARCHAR(1024) NOT NULL,
    CONSTRAINT users_email_unique UNIQUE (email)
);
