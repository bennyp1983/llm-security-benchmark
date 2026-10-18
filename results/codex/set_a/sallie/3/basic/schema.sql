CREATE TABLE users (
    email VARCHAR(254) PRIMARY KEY,
    password_hash VARCHAR(100) NOT NULL,
    password_salt VARCHAR(100) NOT NULL,
    password_iterations INTEGER NOT NULL CHECK (password_iterations > 0)
);
