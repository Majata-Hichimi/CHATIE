/**
 * scripts/setup-db.js
 * Runs schema.sql and roles.sql to initialize chatroom_db and its 3 MySQL roles.
 *
 * Usage:
 *   DB_SETUP_USER=root DB_SETUP_PASSWORD=... npm run setup-db
 * Defaults to DB_ADMIN_USER / DB_ADMIN_PASSWORD from .env if DB_SETUP_* is unset.
 */

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

async function main() {
  const rootDir = path.resolve(__dirname, '..');
  const schemaSql = fs.readFileSync(path.join(rootDir, 'schema.sql'), 'utf8');
  let rolesSql = fs.readFileSync(path.join(rootDir, 'roles.sql'), 'utf8');

  // If real passwords are set in .env, substitute the CHANGE_ME_* placeholders in memory
  const adminPass = process.env.DB_ADMIN_PASSWORD;
  const appPass = process.env.DB_PASSWORD;
  const readonlyPass = process.env.DB_READONLY_PASSWORD;

  if (adminPass && !adminPass.startsWith('CHANGE_ME_')) {
    rolesSql = rolesSql.replace("'CHANGE_ME_admin'", mysql.escape(adminPass));
  }
  if (appPass && !appPass.startsWith('CHANGE_ME_')) {
    rolesSql = rolesSql.replace("'CHANGE_ME_app'", mysql.escape(appPass));
  }
  if (readonlyPass && !readonlyPass.startsWith('CHANGE_ME_')) {
    rolesSql = rolesSql.replace("'CHANGE_ME_readonly'", mysql.escape(readonlyPass));
  }

  const user = process.env.DB_SETUP_USER || process.env.DB_ADMIN_USER || 'root';
  const password =
    process.env.DB_SETUP_PASSWORD !== undefined
      ? process.env.DB_SETUP_PASSWORD
      : process.env.DB_ADMIN_PASSWORD || '';

  const connConfig = {
    user,
    password,
    multipleStatements: true,
  };

  // Support Ubuntu auth_socket root login via Unix socket when running `sudo npm run setup-db`
  const defaultSocket = '/var/run/mysqld/mysqld.sock';
  if (process.env.DB_SOCKET_PATH) {
    connConfig.socketPath = process.env.DB_SOCKET_PATH;
  } else if (user === 'root' && !password && fs.existsSync(defaultSocket)) {
    connConfig.socketPath = defaultSocket;
  } else {
    connConfig.host = process.env.DB_HOST || 'localhost';
    connConfig.port = Number(process.env.DB_PORT) || 3306;
  }

  const conn = await mysql.createConnection(connConfig);

  try {
    console.log(`Connected as "${user}". Running schema.sql...`);
    await conn.query(schemaSql);
    console.log('schema.sql applied successfully.');

    console.log('Running roles.sql...');
    await conn.query(rolesSql);
    console.log('roles.sql applied successfully.');
  } finally {
    await conn.end();
  }
}

main().catch((err) => {
  console.error('Database setup failed:', err.message);
  console.error(
    'Tip: On Ubuntu with auth_socket root, run `sudo mysql < schema.sql && sudo mysql < roles.sql` or set DB_SETUP_USER/DB_SETUP_PASSWORD.'
  );
  process.exit(1);
});
