/**
 * demo.js
 * Self-contained, repeatable security demonstration runner (`npm run demo`).
 * - Resets sample data as chat_admin (including lockout counters and audit_log)
 * - Starts the API server in-process with demoMode=true on an ephemeral localhost port
 * - Prints 4 titled tables + a final pass/fail summary line
 */

const bcrypt = require('bcryptjs');
const config = require('./config');
const { pool, createRoleConnection, explainDbError } = require('./db');
const { startServer, verifyDatabaseReady } = require('./server');

function printTable(title, headers, rows) {
  console.log(`\n=== ${title} ===`);
  const widths = headers.map((h, i) =>
    Math.max(String(h).length, ...rows.map((r) => String(r[i] ?? '').length))
  );
  const border = '+' + widths.map((w) => '-'.repeat(w + 2)).join('+') + '+';
  const line = (cols) =>
    '| ' + cols.map((c, i) => String(c ?? '').padEnd(widths[i])).join(' | ') + ' |';

  console.log(border);
  console.log(line(headers));
  console.log(border);
  for (const row of rows) {
    console.log(line(row));
  }
  console.log(border);
}

class ApiClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookie = '';
  }

  async request(method, path, body = undefined) {
    const headers = {};
    if (this.cookie) headers.Cookie = this.cookie;
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      this.cookie = setCookie.split(';')[0];
    }

    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }
}

async function resetSampleData() {
  const admin = await createRoleConnection('admin');
  try {
    await admin.execute('DELETE FROM audit_log');
    await admin.execute('DELETE FROM messages');
    await admin.execute('DELETE FROM users');
    await admin.query('ALTER TABLE audit_log AUTO_INCREMENT = 1');
    await admin.query('ALTER TABLE messages AUTO_INCREMENT = 1');
    await admin.query('ALTER TABLE users AUTO_INCREMENT = 1');

    const sampleUsers = [
      ['alice', 'AlicePass123!'],
      ['bob', 'BobPass123!'],
      ['charlie', 'CharliePass123!'],
    ];

    const ids = {};
    for (const [username, password] of sampleUsers) {
      const hash = await bcrypt.hash(password, 10);
      const [res] = await admin.execute(
        'INSERT INTO users (username, password_hash, failed_attempts, locked_until) VALUES (?, ?, 0, NULL)',
        [username, hash]
      );
      ids[username] = res.insertId;
    }

    const sampleMessages = [
      [ids.alice, 'Hello everyone! Welcome to the BIT3360 security demo.'],
      [ids.bob, 'Hi Alice! Testing parameterised queries and least privilege.'],
      [ids.charlie, 'Remember: never log passwords or raw SQL errors!'],
      [ids.alice, 'Only I can edit or delete my own messages.'],
    ];

    for (const [userId, content] of sampleMessages) {
      await admin.execute('INSERT INTO messages (user_id, content) VALUES (?, ?)', [
        userId,
        content,
      ]);
    }
  } finally {
    await admin.end();
  }
}

async function trySql(conn, fn) {
  try {
    await fn(conn);
    return { status: 'ALLOWED', code: '-' };
  } catch (err) {
    return { status: 'DENIED', code: `${err.code || 'ERR'} (${err.errno || '?'})` };
  }
}

async function runPermissionsDemo(recordCheck) {
  const admin = await createRoleConnection('admin');
  const expected = {
    [config.db.admin.user]: {
      'SELECT messages': 'ALLOWED',
      'INSERT message': 'ALLOWED',
      'UPDATE message': 'ALLOWED',
      'DELETE message': 'ALLOWED',
      'SELECT audit_log': 'ALLOWED',
      'UPDATE audit_log': 'ALLOWED',
      'DELETE audit_log': 'ALLOWED',
      'DROP TABLE': 'ALLOWED',
      'CREATE TABLE': 'ALLOWED',
    },
    [config.db.app.user]: {
      'SELECT messages': 'ALLOWED',
      'INSERT message': 'ALLOWED',
      'UPDATE message': 'ALLOWED',
      'DELETE message': 'ALLOWED',
      'SELECT audit_log': 'DENIED',
      'UPDATE audit_log': 'DENIED',
      'DELETE audit_log': 'DENIED',
      'DROP TABLE': 'DENIED',
      'CREATE TABLE': 'DENIED',
    },
    [config.db.readonly.user]: {
      'SELECT messages': 'ALLOWED',
      'INSERT message': 'DENIED',
      'UPDATE message': 'DENIED',
      'DELETE message': 'DENIED',
      'SELECT audit_log': 'DENIED',
      'UPDATE audit_log': 'DENIED',
      'DELETE audit_log': 'DENIED',
      'DROP TABLE': 'DENIED',
      'CREATE TABLE': 'DENIED',
    },
  };

  const dmlOps = [
    ['SELECT messages', (c) => c.execute('SELECT id FROM messages LIMIT 1')],
    [
      'INSERT message',
      (c) =>
        c.execute('INSERT INTO messages (user_id, content) VALUES (?, ?)', [
          1,
          'permission test row',
        ]),
    ],
    [
      'UPDATE message',
      (c) => c.execute('UPDATE messages SET content = ? WHERE id = 1', ['temp update']),
    ],
    ['DELETE message', (c) => c.execute('DELETE FROM messages WHERE id = -1')],
    ['SELECT audit_log', (c) => c.execute('SELECT id FROM audit_log LIMIT 1')],
    [
      'UPDATE audit_log',
      (c) => c.execute('UPDATE audit_log SET action = ? WHERE id = -1', ['TAMPER']),
    ],
    ['DELETE audit_log', (c) => c.execute('DELETE FROM audit_log WHERE id = -1')],
  ];

  const rows = [];

  try {
    for (const roleKey of ['admin', 'app', 'readonly']) {
      const userName = config.db[roleKey].user;
      const conn = await createRoleConnection(roleKey);
      try {
        // Wrap DML tests in a transaction and roll back so no sample data changes
        await conn.beginTransaction();
        for (const [label, opFn] of dmlOps) {
          const res = await trySql(conn, opFn);
          recordCheck(res.status === expected[userName][label]);
          rows.push([userName, label, res.status, res.code]);
        }
        await conn.rollback();

        // Test DROP TABLE on a throwaway table so real tables are never touched
        await admin.execute('CREATE TABLE IF NOT EXISTS demo_scratch (id INT PRIMARY KEY)');
        const dropRes = await trySql(conn, (c) => c.execute('DROP TABLE demo_scratch'));
        recordCheck(dropRes.status === expected[userName]['DROP TABLE']);
        rows.push([userName, 'DROP TABLE (demo_scratch)', dropRes.status, dropRes.code]);

        // Test CREATE TABLE on a throwaway table
        await admin.execute('DROP TABLE IF EXISTS demo_create_check');
        const createRes = await trySql(conn, (c) =>
          c.execute('CREATE TABLE demo_create_check (id INT PRIMARY KEY)')
        );
        recordCheck(createRes.status === expected[userName]['CREATE TABLE']);
        rows.push([userName, 'CREATE TABLE', createRes.status, createRes.code]);
      } finally {
        await conn.end();
      }
    }

    await admin.execute('DROP TABLE IF EXISTS demo_scratch');
    await admin.execute('DROP TABLE IF EXISTS demo_create_check');
  } finally {
    await admin.end();
  }

  printTable(
    '1. Permissions Matrix (MySQL Least-Privilege Roles)',
    ['MySQL User', 'Operation', 'Result', 'MySQL Error Code'],
    rows
  );
}

async function runSqlInjectionDemo(baseUrl, recordCheck) {
  const client = new ApiClient(baseUrl);
  const payloads = [
    ['Tautology bypass', "' OR '1'='1"],
    ['Comment truncation', "alice'-- "],
    ['UNION injection', "' UNION SELECT 1, 'attacker'-- "],
  ];

  const rows = [];
  for (const [label, payload] of payloads) {
    const unsafeRes = await client.request('POST', '/api/demo/login-unsafe', {
      username: payload,
      password: 'wrong-password',
    });
    const safeRes = await client.request('POST', '/api/login', {
      username: payload,
      password: 'WrongPassword1!',
    });

    const unsafeBypassed = unsafeRes.status === 200 && unsafeRes.data.queryReturnedRows === true;
    const safeBlocked = safeRes.status === 400 || safeRes.status === 401;

    recordCheck(unsafeBypassed && safeBlocked);
    rows.push([
      label,
      payload,
      unsafeBypassed ? 'BYPASSED (rows returned)' : `HTTP ${unsafeRes.status}`,
      safeBlocked ? `BLOCKED (HTTP ${safeRes.status})` : `HTTP ${safeRes.status}`,
    ]);
  }

  printTable(
    '2. SQL Injection (/api/demo/login-unsafe vs /api/login)',
    ['Attack Type', 'Payload', 'Unsafe Route', 'Safe /api/login'],
    rows
  );
}

async function runAuditLogDemo(baseUrl, recordCheck) {
  const bob = new ApiClient(baseUrl);

  const failRes = await bob.request('POST', '/api/login', {
    username: 'bob',
    password: 'WrongPassword1!',
  });
  const okRes = await bob.request('POST', '/api/login', {
    username: 'bob',
    password: 'BobPass123!',
  });
  const createRes = await bob.request('POST', '/api/messages', {
    content: 'Audit demo message from Bob',
  });
  const msgId = createRes.data?.message?.id;
  const editRes = await bob.request('PUT', `/api/messages/${msgId}`, {
    content: 'Audit demo message edited by Bob',
  });
  const deniedRes = await bob.request('PUT', '/api/messages/1', {
    content: 'Bob trying to edit Alice message',
  });
  const delRes = await bob.request('DELETE', `/api/messages/${msgId}`);
  const logoutRes = await bob.request('POST', '/api/logout');

  recordCheck(failRes.status === 401);
  recordCheck(okRes.status === 200);
  recordCheck(createRes.status === 201 && Boolean(msgId));
  recordCheck(editRes.status === 200);
  recordCheck(deniedRes.status === 403);
  recordCheck(delRes.status === 200);
  recordCheck(logoutRes.status === 200);

  // Connect as chat_admin to read audit_log (chat_app only has INSERT)
  const admin = await createRoleConnection('admin');
  let auditRows = [];
  try {
    const [rows] = await admin.execute(
      `SELECT id, user_id, username_attempted, action, target_id, success, ip_address
       FROM audit_log
       ORDER BY id ASC`
    );
    auditRows = rows;
  } finally {
    await admin.end();
  }

  const actionsFound = new Set(auditRows.map((r) => r.action));
  const expectedActions = [
    'LOGIN_FAILED',
    'LOGIN_SUCCESS',
    'MESSAGE_CREATE',
    'MESSAGE_EDIT',
    'ACCESS_DENIED',
    'MESSAGE_DELETE',
    'LOGOUT',
  ];
  for (const act of expectedActions) {
    recordCheck(actionsFound.has(act));
  }

  const formatted = auditRows.map((r) => [
    r.id,
    r.user_id ?? 'NULL',
    r.username_attempted ?? 'NULL',
    r.action,
    r.target_id ?? 'NULL',
    r.success ? 'TRUE' : 'FALSE',
    r.ip_address || '-',
  ]);

  printTable(
    '3. Audit Log (Queried as chat_admin after API Actions)',
    ['ID', 'User ID', 'Username', 'Action', 'Target ID', 'Success', 'IP Address'],
    formatted
  );
}

async function runAccessControlAndLockoutDemo(baseUrl, recordCheck) {
  const anon = new ApiClient(baseUrl);
  const bob = new ApiClient(baseUrl);
  const alice = new ApiClient(baseUrl);
  const charlie = new ApiClient(baseUrl);

  const rows = [];

  // 1. 401 Unauthenticated edit attempt
  const r401 = await anon.request('PUT', '/api/messages/1', { content: 'Anon edit' });
  const ok401 = r401.status === 401;
  recordCheck(ok401);
  rows.push(['Anonymous', 'PUT /api/messages/1', `HTTP ${r401.status}`, ok401 ? 'PASS' : 'FAIL']);

  // 2. 403 Non-owner (bob) editing alice's message #1
  await bob.request('POST', '/api/login', { username: 'bob', password: 'BobPass123!' });
  const r403 = await bob.request('PUT', '/api/messages/1', { content: 'Bob edit' });
  const ok403 = r403.status === 403;
  recordCheck(ok403);
  rows.push(['bob (non-owner)', 'PUT /api/messages/1', `HTTP ${r403.status}`, ok403 ? 'PASS' : 'FAIL']);

  // 3. 200 Owner (alice) editing her own message #1
  await alice.request('POST', '/api/login', { username: 'alice', password: 'AlicePass123!' });
  const r200 = await alice.request('PUT', '/api/messages/1', {
    content: 'Updated by Alice during access control demo.',
  });
  const ok200 = r200.status === 200;
  recordCheck(ok200);
  rows.push(['alice (owner)', 'PUT /api/messages/1', `HTTP ${r200.status}`, ok200 ? 'PASS' : 'FAIL']);

  // 4. 404 Non-existent message
  const r404 = await alice.request('PUT', '/api/messages/99999', { content: 'Missing' });
  const ok404 = r404.status === 404;
  recordCheck(ok404);
  rows.push(['alice', 'PUT /api/messages/99999', `HTTP ${r404.status}`, ok404 ? 'PASS' : 'FAIL']);

  // 5. Account lockout: 5 failed attempts on charlie -> HTTP 423 on 5th attempt
  let lockoutStatus = 0;
  for (let i = 1; i <= 5; i += 1) {
    const res = await charlie.request('POST', '/api/login', {
      username: 'charlie',
      password: `WrongPassAttempt${i}!`,
    });
    lockoutStatus = res.status;
    if (i < 5) recordCheck(res.status === 401);
  }
  const ok423 = lockoutStatus === 423;
  recordCheck(ok423);
  rows.push([
    'charlie (5 wrong)',
    'POST /api/login (5th fail)',
    `HTTP ${lockoutStatus}`,
    ok423 ? 'PASS' : 'FAIL',
  ]);

  // Verify charlie stays locked even with the correct password
  const lockedCorrect = await charlie.request('POST', '/api/login', {
    username: 'charlie',
    password: 'CharliePass123!',
  });
  const okLockedStill = lockedCorrect.status === 423;
  recordCheck(okLockedStill);
  rows.push([
    'charlie (locked)',
    'POST /api/login (right pw)',
    `HTTP ${lockedCorrect.status}`,
    okLockedStill ? 'PASS' : 'FAIL',
  ]);

  printTable(
    '4. Access Control & Account Lockout (401 / 403 / 200 / 404 / 423)',
    ['Actor', 'Request', 'Response', 'Check'],
    rows
  );
}

async function main() {
  let passed = 0;
  let total = 0;
  const recordCheck = (ok) => {
    total += 1;
    if (ok) passed += 1;
  };

  let server;
  try {
    await verifyDatabaseReady();
    await resetSampleData();

    // Start on ephemeral port (0) with demoMode=true so it works even if `npm start` is running on 3000
    server = await startServer({ port: 0, host: '127.0.0.1', demoMode: true });
    const addr = server.address();
    const baseUrl = `http://${addr.address}:${addr.port}`;

    await runPermissionsDemo(recordCheck);
    await runSqlInjectionDemo(baseUrl, recordCheck);
    await runAuditLogDemo(baseUrl, recordCheck);
    await runAccessControlAndLockoutDemo(baseUrl, recordCheck);

    console.log(`\nSummary: ${passed} / ${total} checks passed.`);
    process.exitCode = passed === total ? 0 : 1;
  } catch (err) {
    console.error(`Demo failed: ${explainDbError(err)}`);
    process.exitCode = 1;
  } finally {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await pool.end().catch(() => {});
  }
}

main();
