/**
 * demo/01-permissions.js
 * Demonstrates MySQL least-privilege enforcement across chat_admin, chat_app,
 * and chat_readonly. Prints ALLOWED vs DENIED (with MySQL error code) in a table.
 */

require('dotenv').config();

const mysql = require('mysql2/promise');
const { printTable } = require('./_helpers');

async function connectAs(user, password) {
  return mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    user,
    password,
    database: process.env.DB_NAME || 'chatroom_db',
    multipleStatements: false,
  });
}

async function testOp(conn, fn) {
  try {
    await fn(conn);
    return { status: 'ALLOWED', detail: '-' };
  } catch (err) {
    return {
      status: 'DENIED',
      detail: `${err.code || 'ERR'} (${err.errno || '?'})`,
    };
  }
}

async function main() {
  const adminUser = process.env.DB_ADMIN_USER || 'chat_admin';
  const adminPass = process.env.DB_ADMIN_PASSWORD;
  const appUser = process.env.DB_USER || 'chat_app';
  const appPass = process.env.DB_PASSWORD;
  const roUser = process.env.DB_READONLY_USER || 'chat_readonly';
  const roPass = process.env.DB_READONLY_PASSWORD;

  if (!adminPass || !appPass || !roPass) {
    throw new Error(
      'DB_ADMIN_PASSWORD, DB_PASSWORD, and DB_READONLY_PASSWORD must be set in .env'
    );
  }

  const adminSetup = await connectAs(adminUser, adminPass);
  let sampleUserId = 1;
  let tempUserCreated = false;

  try {
    const [uRows] = await adminSetup.execute('SELECT id FROM users ORDER BY id ASC LIMIT 1');
    if (uRows.length > 0) {
      sampleUserId = uRows[0].id;
    } else {
      const [ins] = await adminSetup.execute(
        'INSERT INTO users (username, password_hash) VALUES (?, ?)',
        ['demo_perm_user', '$2b$12$placeholderplaceholderplaceholderplaceholderplacehold']
      );
      sampleUserId = ins.insertId;
      tempUserCreated = true;
    }

    const roles = [
      { name: adminUser, password: adminPass },
      { name: appUser, password: appPass },
      { name: roUser, password: roPass },
    ];

    const operations = [
      {
        label: 'SELECT messages',
        run: (c) => c.execute('SELECT id FROM messages LIMIT 1'),
      },
      {
        label: 'INSERT message',
        run: (c) =>
          c.execute('INSERT INTO messages (user_id, content) VALUES (?, ?)', [
            sampleUserId,
            'permission test message',
          ]),
      },
      {
        label: 'UPDATE message',
        run: (c) =>
          c.execute('UPDATE messages SET content = ? WHERE id = 1', ['updated test']),
      },
      {
        label: 'DELETE message',
        run: (c) => c.execute('DELETE FROM messages WHERE id = -1'),
      },
      {
        label: 'SELECT audit_log',
        run: (c) => c.execute('SELECT id FROM audit_log LIMIT 1'),
      },
      {
        label: 'UPDATE audit_log',
        run: (c) =>
          c.execute('UPDATE audit_log SET action = ? WHERE id = -1', ['TAMPER']),
      },
      {
        label: 'DELETE audit_log',
        run: (c) => c.execute('DELETE FROM audit_log WHERE id = -1'),
      },
    ];

    const tableRows = [];

    for (const role of roles) {
      const conn = await connectAs(role.name, role.password);
      try {
        // Run DML operations inside a transaction and roll back so no data changes
        await conn.beginTransaction();
        for (const op of operations) {
          const res = await testOp(conn, op.run);
          tableRows.push([role.name, op.label, res.status, res.detail]);
        }
        await conn.rollback();

        // Prepare throwaway table demo_scratch before testing DROP TABLE
        await adminSetup.execute(
          'CREATE TABLE IF NOT EXISTS demo_scratch (id INT PRIMARY KEY)'
        );
        const dropRes = await testOp(conn, (c) =>
          c.execute('DROP TABLE demo_scratch')
        );
        tableRows.push([role.name, 'DROP TABLE (demo_scratch)', dropRes.status, dropRes.detail]);

        // Test CREATE TABLE using a throwaway table name
        await adminSetup.execute('DROP TABLE IF EXISTS demo_create_check');
        const createRes = await testOp(conn, (c) =>
          c.execute('CREATE TABLE demo_create_check (id INT PRIMARY KEY)')
        );
        tableRows.push([role.name, 'CREATE TABLE', createRes.status, createRes.detail]);
      } finally {
        await conn.end();
      }
    }

    // Clean up throwaway tables/temp user
    await adminSetup.execute('DROP TABLE IF EXISTS demo_scratch');
    await adminSetup.execute('DROP TABLE IF EXISTS demo_create_check');
    if (tempUserCreated) {
      await adminSetup.execute('DELETE FROM users WHERE id = ?', [sampleUserId]);
    }

    printTable(
      'DEMO 01: MySQL Least-Privilege Permissions Matrix',
      ['MySQL User', 'Operation', 'Result', 'MySQL Error Code'],
      tableRows
    );
  } finally {
    await adminSetup.end();
  }
}

main().catch((err) => {
  console.error('Demo 01 failed:', err.message);
  process.exit(1);
});
