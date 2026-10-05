-- Run as a schema owner. Do not grant that role to the application.
CREATE TABLE app_user (
    email_canonical varchar(254) PRIMARY KEY,
    password_algorithm varchar(32) NOT NULL
        CHECK (password_algorithm = 'PBKDF2WithHmacSHA256'),
    password_iterations integer NOT NULL CHECK (password_iterations = 600000),
    password_salt bytea NOT NULL CHECK (octet_length(password_salt) = 16),
    password_hash bytea NOT NULL CHECK (octet_length(password_hash) = 32),
    enabled boolean NOT NULL DEFAULT true,
    CHECK (email_canonical = lower(email_canonical)),
    CHECK (length(email_canonical) BETWEEN 3 AND 254)
);

CREATE TABLE auth_rate_limit (
    scope varchar(8) NOT NULL CHECK (scope IN ('source', 'account')),
    bucket_key char(64) NOT NULL CHECK (bucket_key ~ '^[0-9a-f]{64}$'),
    window_start timestamptz NOT NULL,
    attempt_count integer NOT NULL CHECK (attempt_count BETWEEN 1 AND 1000000),
    PRIMARY KEY (scope, bucket_key)
);

-- Create a NOLOGIN owner and a separate LOGIN role in deployment automation.
-- Replace auth_runtime with that least-privileged runtime role.
GRANT SELECT ON app_user TO auth_runtime;
GRANT SELECT, INSERT, UPDATE ON auth_rate_limit TO auth_runtime;
REVOKE DELETE, TRUNCATE ON app_user, auth_rate_limit FROM auth_runtime;
