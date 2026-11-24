-- BIT3360 Advanced Databases - One-Step Database Setup
-- Safe to re-run any number of times:
--   sudo mysql < setup.sql   (or: mysql -u root -p < setup.sql)

DROP DATABASE IF EXISTS chatroom_db;
CREATE DATABASE chatroom_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE chatroom_db;

-- 1. Users table (no PII; username uniqueness is case-insensitive via utf8mb4_unicode_ci)
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(30) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until DATETIME NULL DEFAULT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_users_username UNIQUE (username),
  CONSTRAINT chk_users_username_len CHECK (CHAR_LENGTH(username) BETWEEN 3 AND 30),
  CONSTRAINT chk_users_failed_attempts CHECK (failed_attempts >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Messages table (cascade delete on user removal; rejects empty/blank messages)
CREATE TABLE messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  content VARCHAR(500) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_messages_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT chk_messages_content_not_empty CHECK (CHAR_LENGTH(TRIM(content)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Audit log table (append-only for chat_app: INSERT only)
CREATE TABLE audit_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  username_attempted VARCHAR(100) NULL,
  action VARCHAR(50) NOT NULL,
  target_id INT NULL,
  success BOOLEAN NOT NULL,
  ip_address VARCHAR(45) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Least-privilege MySQL users (created for both 'localhost' and '127.0.0.1')
-- Fixed sample passwords match config.js for easy local assignment setup.
DROP USER IF EXISTS 'chat_admin'@'localhost', 'chat_admin'@'127.0.0.1';
DROP USER IF EXISTS 'chat_app'@'localhost', 'chat_app'@'127.0.0.1';
DROP USER IF EXISTS 'chat_readonly'@'localhost', 'chat_readonly'@'127.0.0.1';

CREATE USER 'chat_admin'@'localhost' IDENTIFIED BY 'AdminPass123!';
CREATE USER 'chat_admin'@'127.0.0.1' IDENTIFIED BY 'AdminPass123!';

CREATE USER 'chat_app'@'localhost' IDENTIFIED BY 'AppPass123!';
CREATE USER 'chat_app'@'127.0.0.1' IDENTIFIED BY 'AppPass123!';

CREATE USER 'chat_readonly'@'localhost' IDENTIFIED BY 'ReadOnlyPass123!';
CREATE USER 'chat_readonly'@'127.0.0.1' IDENTIFIED BY 'ReadOnlyPass123!';

-- chat_admin: full privileges on chatroom_db only (never used by the running server)
GRANT ALL PRIVILEGES ON chatroom_db.* TO 'chat_admin'@'localhost';
GRANT ALL PRIVILEGES ON chatroom_db.* TO 'chat_admin'@'127.0.0.1';

-- chat_app: least-privilege account used by server.js
GRANT SELECT, INSERT, UPDATE ON chatroom_db.users TO 'chat_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON chatroom_db.users TO 'chat_app'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE, DELETE ON chatroom_db.messages TO 'chat_app'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON chatroom_db.messages TO 'chat_app'@'127.0.0.1';
GRANT INSERT ON chatroom_db.audit_log TO 'chat_app'@'localhost';
GRANT INSERT ON chatroom_db.audit_log TO 'chat_app'@'127.0.0.1';

-- chat_readonly: SELECT on messages only
GRANT SELECT ON chatroom_db.messages TO 'chat_readonly'@'localhost';
GRANT SELECT ON chatroom_db.messages TO 'chat_readonly'@'127.0.0.1';

FLUSH PRIVILEGES;

-- 5. Sample data (pre-computed bcryptjs cost-10 hashes for AlicePass123!, BobPass123!, CharliePass123!)
INSERT INTO users (username, password_hash) VALUES
  ('alice', '$2a$10$WuSgr93Yb0lMcFCwcoLwauBF5BXN1oEFGGSWGsONs7IBPCIwnJx3e'),
  ('bob', '$2a$10$QfCnPGDmrrbE6Ls1pCNPcebqjcEad/keLyqpzB5k4aLm4aV1DG.Lq'),
  ('charlie', '$2a$10$h5SB1conw7dnJCaf3FciUOPPnICHlgOShxZk4dEifqR8zsVqO43sS');

INSERT INTO messages (user_id, content) VALUES
  (1, 'Hello everyone! Welcome to the BIT3360 security demo.'),
  (2, 'Hi Alice! Testing parameterised queries and least privilege.'),
  (3, 'Remember: never log passwords or raw SQL errors!'),
  (1, 'Only I can edit or delete my own messages.');
