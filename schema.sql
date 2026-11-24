-- BIT3360 Advanced Databases - Database Schema
-- Database: chatroom_db (InnoDB, utf8mb4, integrity constraints)

CREATE DATABASE IF NOT EXISTS chatroom_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE chatroom_db;

-- 1. Users table: username + bcrypt hash + brute-force lockout state (no PII)
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(30) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until DATETIME NULL DEFAULT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_users_username UNIQUE (username),
  CONSTRAINT chk_users_username_len CHECK (CHAR_LENGTH(username) BETWEEN 3 AND 30),
  CONSTRAINT chk_users_username_chars CHECK (REGEXP_LIKE(username, '^[A-Za-z0-9_]+$')),
  CONSTRAINT chk_users_failed_attempts CHECK (failed_attempts >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 2. Messages table: user-owned messages with cascade delete and non-empty check
CREATE TABLE IF NOT EXISTS messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  content VARCHAR(500) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_messages_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT chk_messages_content_not_empty CHECK (CHAR_LENGTH(TRIM(content)) > 0),
  CONSTRAINT chk_messages_content_len CHECK (CHAR_LENGTH(content) <= 500)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 3. Audit log table: append-only security event log (chat_app has INSERT only)
CREATE TABLE IF NOT EXISTS audit_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  username_attempted VARCHAR(100) NULL,
  action VARCHAR(50) NOT NULL,
  target_id INT NULL,
  success BOOLEAN NOT NULL,
  ip_address VARCHAR(45) NULL,
  user_agent VARCHAR(255) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT chk_audit_action_not_empty CHECK (CHAR_LENGTH(TRIM(action)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
