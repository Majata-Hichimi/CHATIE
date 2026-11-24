/**
 * src/db.js
 * Creates and exports the MySQL connection pool used by the running application.
 * Security controls:
 *  - Connects strictly as the least-privilege `chat_app` MySQL user.
 *  - Sets `multipleStatements: false` to block stacked SQL injection queries.
 *  - Supports optional TLS/SSL encryption to MySQL via DB_SSL env vars.
 */

const fs = require('fs');
const mysql = require('mysql2/promise');

function buildSslConfig() {
  if (process.env.DB_SSL !== 'true') {
    return undefined;
  }

  const sslConfig = {
    rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false',
  };

  if (process.env.DB_SSL_CA) {
    sslConfig.ca = fs.readFileSync(process.env.DB_SSL_CA, 'utf8');
  }

  return sslConfig;
}

const dbUser = process.env.DB_USER || 'chat_app';

// Enforce least privilege: never let the running API start as chat_admin or root
if (dbUser !== 'chat_app') {
  throw new Error(
    `Unsafe DB_USER "${dbUser}". The application must connect ONLY as "chat_app".`
  );
}

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 3306,
  user: dbUser,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'chatroom_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // CRITICAL: prevent stacked queries (e.g., '; DROP TABLE users; --)
  multipleStatements: false,
  ssl: buildSslConfig(),
});

module.exports = pool;
