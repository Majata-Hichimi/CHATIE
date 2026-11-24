/**
 * db.js
 * MySQL 8 connection pool and helper functions.
 *
 * Security notes:
 *  - The running API uses `pool`, which connects ONLY as `chat_app` (least privilege).
 *  - `multipleStatements` is explicitly set to `false` to block stacked SQL queries.
 */

const mysql = require('mysql2/promise');
const config = require('./config');

// Guardrail: prevent the application pool from accidentally running as chat_admin or root
if (config.db.app.user !== 'chat_app') {
  throw new Error(
    `Unsafe DB user "${config.db.app.user}". The server must connect ONLY as "chat_app".`
  );
}

// Shared connection pool for all API endpoints (uses least-privilege chat_app)
const pool = mysql.createPool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.app.user,
  password: config.db.app.password,
  database: config.db.database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  multipleStatements: false, // Prevents stacked queries such as '; DROP TABLE users; --
});

// Helper used ONLY by demo.js and `npm run check` to test specific MySQL roles
async function createRoleConnection(roleName, { withDatabase = true } = {}) {
  const role = config.db[roleName];
  if (!role) {
    throw new Error(`Unknown database role: ${roleName}`);
  }

  return mysql.createConnection({
    host: config.db.host,
    port: config.db.port,
    user: role.user,
    password: role.password,
    database: withDatabase ? config.db.database : undefined,
    multipleStatements: false,
  });
}

// Translates low-level MySQL errors into plain-English troubleshooting hints
function explainDbError(err) {
  if (!err) return 'Unknown database error.';

  if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT') {
    return (
      `Cannot connect to MySQL at ${config.db.host}:${config.db.port}. ` +
      'Make sure the MySQL 8 service is running (e.g. `sudo service mysql start`).'
    );
  }
  if (err.code === 'ER_ACCESS_DENIED_ERROR' || err.errno === 1045) {
    return (
      'MySQL rejected the username or password. ' +
      'Run `sudo mysql < setup.sql` (or `mysql -u root -p < setup.sql`) so the users and passwords match config.js.'
    );
  }
  if (err.code === 'ER_BAD_DB_ERROR' || err.errno === 1049) {
    return (
      `Database "${config.db.database}" does not exist yet. ` +
      'Run `sudo mysql < setup.sql` (or `mysql -u root -p < setup.sql`) first.'
    );
  }
  if (err.code === 'ER_NO_SUCH_TABLE' || err.errno === 1146) {
    return (
      'Required tables are missing in chatroom_db. ' +
      'Re-run `sudo mysql < setup.sql` (or `mysql -u root -p < setup.sql`).'
    );
  }
  return err.message || 'Database check failed.';
}

module.exports = {
  pool,
  createRoleConnection,
  explainDbError,
};
