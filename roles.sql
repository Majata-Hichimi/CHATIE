-- BIT3360 Advanced Databases - Least-Privilege Database Roles
-- Replace the CHANGE_ME_* placeholder passwords before applying in your environment.

CREATE USER IF NOT EXISTS 'chat_admin'@'localhost' IDENTIFIED BY 'CHANGE_ME_admin';
CREATE USER IF NOT EXISTS 'chat_app'@'localhost' IDENTIFIED BY 'CHANGE_ME_app';
CREATE USER IF NOT EXISTS 'chat_readonly'@'localhost' IDENTIFIED BY 'CHANGE_ME_readonly';

-- Clear any existing privileges so re-running this script enforces exact permissions
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'chat_admin'@'localhost';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'chat_app'@'localhost';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'chat_readonly'@'localhost';

-- 1. chat_admin: full privileges on chatroom_db only (setup & maintenance, never used by the running app)
GRANT ALL PRIVILEGES ON chatroom_db.* TO 'chat_admin'@'localhost';

-- 2. chat_app: least-privilege account used by the running Express application
--    - users: SELECT, INSERT, UPDATE (no DELETE)
--    - messages: SELECT, INSERT, UPDATE, DELETE
--    - audit_log: INSERT only (cannot read, modify, or delete audit history)
GRANT SELECT, INSERT, UPDATE ON chatroom_db.users TO 'chat_app'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON chatroom_db.messages TO 'chat_app'@'localhost';
GRANT INSERT ON chatroom_db.audit_log TO 'chat_app'@'localhost';

-- 3. chat_readonly: SELECT on messages only (nothing else)
GRANT SELECT ON chatroom_db.messages TO 'chat_readonly'@'localhost';

FLUSH PRIVILEGES;
