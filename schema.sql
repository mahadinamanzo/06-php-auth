CREATE DATABASE IF NOT EXISTS swd_auth
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE swd_auth;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

ALTER TABLE users
    MODIFY COLUMN email VARCHAR(254) NOT NULL,
    ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user' AFTER password_hash,
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP NULL DEFAULT NULL AFTER created_at;

CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email VARCHAR(254) NOT NULL,
    ip VARCHAR(45) NULL,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_login_attempts_email_time (email, attempted_at),
    KEY idx_login_attempts_ip_time (ip, attempted_at),
    KEY idx_login_attempts_time (attempted_at)
) ENGINE=InnoDB;

ALTER TABLE login_attempts
    ADD COLUMN IF NOT EXISTS ip VARCHAR(45) NULL AFTER email,
    MODIFY COLUMN email VARCHAR(254) NOT NULL;
