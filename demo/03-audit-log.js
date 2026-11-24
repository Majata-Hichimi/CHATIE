/**
 * demo/03-audit-log.js
 * Performs real API actions (failed login, successful login, create/edit/delete
 * message, unauthorized edit attempt, logout), then connects as `chat_admin`
 * (since `chat_app` cannot SELECT audit_log) to print the resulting audit rows.
 */

require('dotenv').config();

const mysql = require('mysql2/promise');
const { printTable, ApiClient, getBaseUrl } = require('./_helpers');

async function main() {
  const baseUrl = getBaseUrl();
  const bob = new ApiClient(baseUrl);

  // 1. Failed login for bob
  const failRes = await bob.request('POST', '/api/login', {
    username: 'bob',
    password: 'WrongPassword123!',
  });

  // 2. Successful login for bob
  const okRes = await bob.request('POST', '/api/login', {
    username: 'bob',
    password: 'BobPassword1!',
  });
  if (okRes.status !== 200) {
    throw new Error(`Bob login failed: HTTP ${okRes.status} ${JSON.stringify(okRes.data)}`);
  }

  // 3. Create a message as bob
  const createRes = await bob.request('POST', '/api/messages', {
    content: 'Audit demo message from Bob',
  });
  if (createRes.status !== 201) {
    throw new Error(`Message create failed: HTTP ${createRes.status}`);
  }
  const bobMsgId = createRes.data.message.id;

  // 4. Edit bob's own message
  await bob.request('PUT', `/api/messages/${bobMsgId}`, {
    content: 'Audit demo message edited by Bob',
  });

  // 5. Attempt to edit alice's message (id=1) -> triggers 403 ACCESS_DENIED
  await bob.request('PUT', '/api/messages/1', {
    content: 'Bob trying to tamper with Alice message',
  });

  // 6. Delete bob's own message
  await bob.request('DELETE', `/api/messages/${bobMsgId}`);

  // 7. Logout bob
  await bob.request('POST', '/api/logout');

  const actionSummary = [
    ['Failed login (bob)', `HTTP ${failRes.status}`],
    ['Successful login (bob)', `HTTP ${okRes.status}`],
    [`Create message #${bobMsgId}`, `HTTP ${createRes.status}`],
    [`Edit own message #${bobMsgId}`, 'HTTP 200'],
    ['Edit alice message #1', 'HTTP 403 (ACCESS_DENIED)'],
    [`Delete own message #${bobMsgId}`, 'HTTP 200'],
    ['Logout (bob)', 'HTTP 200'],
  ];

  printTable(
    'DEMO 03 (Part A): API Actions Triggered',
    ['Action Performed', 'API Response'],
    actionSummary
  );

  // Connect as chat_admin to read audit_log (chat_app only has INSERT privilege)
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_ADMIN_USER || 'chat_admin',
    password: process.env.DB_ADMIN_PASSWORD,
    database: process.env.DB_NAME || 'chatroom_db',
  });

  try {
    const [auditRows] = await conn.execute(
      `SELECT id, user_id, username_attempted, action, target_id, success, ip_address
       FROM audit_log
       ORDER BY id DESC
       LIMIT 10`
    );

    const formatted = auditRows
      .reverse()
      .map((r) => [
        r.id,
        r.user_id ?? 'NULL',
        r.username_attempted ?? 'NULL',
        r.action,
        r.target_id ?? 'NULL',
        r.success ? 'TRUE' : 'FALSE',
        r.ip_address || '-',
      ]);

    printTable(
      'DEMO 03 (Part B): Resulting audit_log Rows (Queried as chat_admin)',
      ['ID', 'User ID', 'Username', 'Action', 'Target ID', 'Success', 'IP Address'],
      formatted
    );
  } finally {
    await conn.end();
  }
}

main().catch((err) => {
  console.error('Demo 03 failed:', err.message);
  process.exit(1);
});
