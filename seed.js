/**
 * seed.js
 * Inserts sample users and sample messages using parameterised queries and bcrypt.
 * Connects as `chat_admin` (setup/maintenance role), never used by the running app.
 */

require('dotenv').config();

const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

const BCRYPT_COST = 12;

const SAMPLE_USERS = [
  { username: 'alice', password: 'AlicePassword1!' },
  { username: 'bob', password: 'BobPassword1!' },
  { username: 'charlie', password: 'CharliePassword1!' },
];

const SAMPLE_MESSAGES = [
  { username: 'alice', content: 'Hello everyone! Welcome to the BIT3360 security demo.' },
  { username: 'bob', content: 'Hi Alice! Testing parameterised queries and session auth.' },
  { username: 'charlie', content: 'Remember: never log passwords or raw SQL errors!' },
  { username: 'alice', content: 'Only I should be able to edit or delete my own messages.' },
];

async function main() {
  const adminUser = process.env.DB_ADMIN_USER || 'chat_admin';
  const adminPassword = process.env.DB_ADMIN_PASSWORD;

  if (!adminPassword) {
    throw new Error('DB_ADMIN_PASSWORD must be set in .env to run seed.js');
  }

  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    user: adminUser,
    password: adminPassword,
    database: process.env.DB_NAME || 'chatroom_db',
    multipleStatements: false,
  });

  try {
    console.log(`Connected to ${process.env.DB_NAME || 'chatroom_db'} as ${adminUser}...`);

    // Reset sample tables cleanly so demos start from predictable IDs
    await conn.execute('DELETE FROM audit_log');
    await conn.execute('DELETE FROM messages');
    await conn.execute('DELETE FROM users');
    await conn.query('ALTER TABLE audit_log AUTO_INCREMENT = 1');
    await conn.query('ALTER TABLE messages AUTO_INCREMENT = 1');
    await conn.query('ALTER TABLE users AUTO_INCREMENT = 1');

    const userIds = {};

    for (const sample of SAMPLE_USERS) {
      const hash = await bcrypt.hash(sample.password, BCRYPT_COST);
      const [res] = await conn.execute(
        'INSERT INTO users (username, password_hash) VALUES (?, ?)',
        [sample.username, hash]
      );
      userIds[sample.username] = res.insertId;
      console.log(`Seeded user "${sample.username}" (id=${res.insertId})`);
    }

    for (const msg of SAMPLE_MESSAGES) {
      const [res] = await conn.execute(
        'INSERT INTO messages (user_id, content) VALUES (?, ?)',
        [userIds[msg.username], msg.content]
      );
      console.log(`Seeded message id=${res.insertId} for "${msg.username}"`);
    }

    console.log('Seed completed successfully.');
  } finally {
    await conn.end();
  }
}

main().catch((err) => {
  console.error('Seed failed:', err.message);
  process.exit(1);
});
