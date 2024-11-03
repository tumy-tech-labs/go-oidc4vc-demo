-- init.sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert a test user (password should be hashed outside of SQL for security)
INSERT INTO users (username, email, password_hash, salt)
VALUES ('testuser', 'testuser@example.com', crypt('plaintextpassword' || gen_salt('bf'), gen_salt('bf')), gen_salt('bf'));
