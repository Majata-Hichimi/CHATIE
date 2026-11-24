/**
 * server.js
 * Secure Chatroom JSON REST API (BIT3360 Advanced Databases).
 * Also supports `npm run check` (`node server.js --check`) for environment verification.
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const config = require('./config');
const { pool, createRoleConnection, explainDbError } = require('./db');

const BCRYPT_COST = 10;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;
const USERNAME_REGEX = /^[A-Za-z0-9_]{3,30}$/;

// Constant-time timing defense: precomputed cost-10 hash used when a username does not exist
const DUMMY_HASH = bcrypt.hashSync('dummy_timing_defense_password', BCRYPT_COST);

// --- Audit logging helper (runs as chat_app, which only has INSERT on audit_log) ---
async function writeAuditLog({
  userId = null,
  usernameAttempted = null,
  action,
  targetId = null,
  success,
  req = null,
}) {
  // Never store passwords or message content in audit_log
  const ipAddress = req
    ? String(req.ip || req.socket?.remoteAddress || '').slice(0, 45) || null
    : null;
  const safeUsername =
    usernameAttempted !== null && usernameAttempted !== undefined
      ? String(usernameAttempted).slice(0, 100)
      : null;

  try {
    await pool.execute(
      `INSERT INTO audit_log (user_id, username_attempted, action, target_id, success, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, safeUsername, action, targetId, Boolean(success), ipAddress]
    );
  } catch (err) {
    // Log server-side only; an audit insert failure must not crash the user's request
    console.error('[AUDIT_ERROR]', err.message);
  }
}

// --- Input validation helpers (executed before any SQL query) ---
function validateUsername(username) {
  if (typeof username !== 'string' || !USERNAME_REGEX.test(username)) {
    return 'Username must be 3-30 characters using letters, digits, and underscores only';
  }
  return null;
}

function validatePassword(password) {
  if (typeof password !== 'string') {
    return 'Password must be a string';
  }
  if (password.trim().length === 0) {
    return 'Password cannot be empty or whitespace only';
  }
  if (password.length < 8 || password.length > 72) {
    return 'Password must be between 8 and 72 characters';
  }
  return null;
}

function validateMessageContent(content) {
  if (typeof content !== 'string') {
    return 'Message content must be a string';
  }
  if (content.trim().length === 0) {
    return 'Message content cannot be empty or whitespace only';
  }
  if (content.length > 500) {
    return 'Message content must not exceed 500 characters';
  }
  return null;
}

function parsePositiveInt(raw) {
  if (typeof raw !== 'string' || !/^[1-9]\d*$/.test(raw)) return null;
  const num = Number(raw);
  return Number.isSafeInteger(num) ? num : null;
}

function parsePagination(limitRaw, offsetRaw) {
  let limit = 20;
  let offset = 0;

  if (limitRaw !== undefined) {
    if (typeof limitRaw !== 'string' || !/^[1-9]\d*$/.test(limitRaw)) {
      return { error: 'Query parameter "limit" must be an integer between 1 and 50' };
    }
    limit = Number(limitRaw);
    if (limit < 1 || limit > 50) {
      return { error: 'Query parameter "limit" must be an integer between 1 and 50' };
    }
  }

  if (offsetRaw !== undefined) {
    if (typeof offsetRaw !== 'string' || !/^\d+$/.test(offsetRaw)) {
      return { error: 'Query parameter "offset" must be a non-negative integer' };
    }
    offset = Number(offsetRaw);
    if (!Number.isSafeInteger(offset)) {
      return { error: 'Query parameter "offset" must be a non-negative integer' };
    }
  }

  return { limit, offset };
}

// --- Authentication middleware ---
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user || !req.session.user.id) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  return next();
}

// --- Express application factory ---
function createApp({ demoMode = config.demoMode } = {}) {
  const app = express();

  // Hide Express server fingerprint
  app.disable('x-powered-by');

  // Limit JSON request body size to 10kb
  app.use(express.json({ limit: '10kb' }));

  // Hardened session cookies: httpOnly (blocks JS access), sameSite strict (CSRF defense), 30m expiry
  app.use(
    session({
      name: 'chatroom.sid',
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      rolling: true,
      cookie: {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 30 * 60 * 1000, // 30 minutes
      },
    })
  );

  // Friendly health/welcome route so opening http://127.0.0.1:3000 in a browser works cleanly
  app.get('/', (req, res) => {
    res.json({
      status: 'ok',
      message: 'Secure Chatroom API is running. Use /api/* endpoints.',
    });
  });

  // POST /api/register - creates a user with username + password only (no PII)
  app.post('/api/register', async (req, res, next) => {
    try {
      const { username, password } = req.body || {};
      const usernameErr = validateUsername(username);
      if (usernameErr) return res.status(400).json({ error: usernameErr });

      const passwordErr = validatePassword(password);
      if (passwordErr) return res.status(400).json({ error: passwordErr });

      // Hash password with bcryptjs cost 10 (salt is generated automatically)
      const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

      try {
        const [result] = await pool.execute(
          'INSERT INTO users (username, password_hash) VALUES (?, ?)',
          [username, passwordHash]
        );

        await writeAuditLog({
          userId: result.insertId,
          usernameAttempted: username,
          action: 'REGISTER',
          targetId: result.insertId,
          success: true,
          req,
        });

        return res.status(201).json({
          message: 'User registered successfully',
          user: { id: result.insertId, username },
        });
      } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          await writeAuditLog({
            userId: null,
            usernameAttempted: username,
            action: 'REGISTER',
            success: false,
            req,
          });
          return res.status(409).json({ error: 'Username is already taken' });
        }
        throw err;
      }
    } catch (err) {
      return next(err);
    }
  });

  // POST /api/login - authenticates user, enforces 5-attempt lockout, regenerates session ID
  app.post('/api/login', async (req, res, next) => {
    try {
      const { username, password } = req.body || {};
      const usernameErr = validateUsername(username);
      if (usernameErr) return res.status(400).json({ error: usernameErr });

      const passwordErr = validatePassword(password);
      if (passwordErr) return res.status(400).json({ error: passwordErr });

      // Parameterised query prevents SQL injection
      const [rows] = await pool.execute(
        `SELECT id, username, password_hash, failed_attempts, locked_until
         FROM users
         WHERE username = ?`,
        [username]
      );

      if (rows.length === 0) {
        // Still run bcrypt.compare against dummy hash so response timing does not leak usernames
        await bcrypt.compare(password, DUMMY_HASH);
        await writeAuditLog({
          userId: null,
          usernameAttempted: username,
          action: 'LOGIN_FAILED',
          success: false,
          req,
        });
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      const user = rows[0];
      const isLocked = user.locked_until !== null && new Date(user.locked_until) > new Date();

      if (isLocked) {
        await bcrypt.compare(password, DUMMY_HASH);
        await writeAuditLog({
          userId: user.id,
          usernameAttempted: user.username,
          action: 'LOGIN_FAILED',
          success: false,
          req,
        });
        return res.status(423).json({
          error: 'Account is temporarily locked due to too many failed login attempts.',
        });
      }

      const passwordMatches = await bcrypt.compare(password, user.password_hash);

      if (!passwordMatches) {
        // If an old lock has already expired, restart the counter from 1
        const previousAttempts = user.locked_until ? 0 : user.failed_attempts;
        const nextAttempts = previousAttempts + 1;

        if (nextAttempts >= MAX_FAILED_ATTEMPTS) {
          await pool.execute(
            `UPDATE users
             SET failed_attempts = ?, locked_until = DATE_ADD(NOW(), INTERVAL ? MINUTE)
             WHERE id = ?`,
            [nextAttempts, LOCKOUT_MINUTES, user.id]
          );

          await writeAuditLog({
            userId: user.id,
            usernameAttempted: user.username,
            action: 'LOGIN_FAILED',
            success: false,
            req,
          });
          await writeAuditLog({
            userId: user.id,
            usernameAttempted: user.username,
            action: 'ACCOUNT_LOCKED',
            targetId: user.id,
            success: false,
            req,
          });

          return res.status(423).json({
            error: 'Account is temporarily locked due to too many failed login attempts.',
          });
        }

        await pool.execute(
          'UPDATE users SET failed_attempts = ?, locked_until = NULL WHERE id = ?',
          [nextAttempts, user.id]
        );
        await writeAuditLog({
          userId: user.id,
          usernameAttempted: user.username,
          action: 'LOGIN_FAILED',
          success: false,
          req,
        });
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Successful login: reset lockout counters in the database
      await pool.execute(
        'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?',
        [user.id]
      );

      // Regenerate session ID to prevent session fixation attacks
      await new Promise((resolve, reject) => {
        req.session.regenerate((err) => (err ? reject(err) : resolve()));
      });

      req.session.user = { id: user.id, username: user.username };

      await writeAuditLog({
        userId: user.id,
        usernameAttempted: user.username,
        action: 'LOGIN_SUCCESS',
        targetId: user.id,
        success: true,
        req,
      });

      return res.status(200).json({
        message: 'Login successful',
        user: { id: user.id, username: user.username },
      });
    } catch (err) {
      return next(err);
    }
  });

  // POST /api/logout - destroys session and clears cookie
  app.post('/api/logout', requireAuth, async (req, res, next) => {
    try {
      const user = req.session.user;

      await new Promise((resolve, reject) => {
        req.session.destroy((err) => (err ? reject(err) : resolve()));
      });

      res.clearCookie('chatroom.sid', { httpOnly: true, sameSite: 'strict' });

      await writeAuditLog({
        userId: user.id,
        usernameAttempted: user.username,
        action: 'LOGOUT',
        targetId: user.id,
        success: true,
        req,
      });

      return res.status(200).json({ message: 'Logged out successfully' });
    } catch (err) {
      return next(err);
    }
  });

  // GET /api/me - returns safe profile fields for the logged-in user (never password_hash)
  app.get('/api/me', requireAuth, async (req, res, next) => {
    try {
      const [rows] = await pool.execute(
        'SELECT id, username, created_at FROM users WHERE id = ?',
        [req.session.user.id]
      );
      if (rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(200).json({ user: rows[0] });
    } catch (err) {
      return next(err);
    }
  });

  // GET /api/messages - lists messages with validated pagination (max limit 50)
  app.get('/api/messages', requireAuth, async (req, res, next) => {
    try {
      const page = parsePagination(req.query.limit, req.query.offset);
      if (page.error) return res.status(400).json({ error: page.error });

      const [rows] = await pool.query(
        `SELECT m.id, m.user_id, u.username, m.content, m.created_at, m.updated_at
         FROM messages m
         INNER JOIN users u ON m.user_id = u.id
         ORDER BY m.created_at DESC, m.id DESC
         LIMIT ? OFFSET ?`,
        [page.limit, page.offset]
      );

      return res.status(200).json({
        messages: rows,
        pagination: { limit: page.limit, offset: page.offset, count: rows.length },
      });
    } catch (err) {
      return next(err);
    }
  });

  // POST /api/messages - creates a new chat message owned by the logged-in user
  app.post('/api/messages', requireAuth, async (req, res, next) => {
    try {
      const { content } = req.body || {};
      const contentErr = validateMessageContent(content);
      if (contentErr) return res.status(400).json({ error: contentErr });

      const { id: userId, username } = req.session.user;

      const [result] = await pool.execute(
        'INSERT INTO messages (user_id, content) VALUES (?, ?)',
        [userId, content]
      );

      await writeAuditLog({
        userId,
        usernameAttempted: username,
        action: 'MESSAGE_CREATE',
        targetId: result.insertId,
        success: true,
        req,
      });

      const [rows] = await pool.execute(
        `SELECT m.id, m.user_id, u.username, m.content, m.created_at, m.updated_at
         FROM messages m
         INNER JOIN users u ON m.user_id = u.id
         WHERE m.id = ?`,
        [result.insertId]
      );

      return res.status(201).json({ message: rows[0] });
    } catch (err) {
      return next(err);
    }
  });

  // PUT /api/messages/:id - edits a message ONLY if the caller owns it
  app.put('/api/messages/:id', requireAuth, async (req, res, next) => {
    try {
      const messageId = parsePositiveInt(req.params.id);
      if (!messageId) return res.status(400).json({ error: 'Invalid message ID' });

      const { content } = req.body || {};
      const contentErr = validateMessageContent(content);
      if (contentErr) return res.status(400).json({ error: contentErr });

      const { id: userId, username } = req.session.user;

      // Ownership is enforced inside the SQL statement itself (WHERE id = ? AND user_id = ?)
      const [result] = await pool.execute(
        'UPDATE messages SET content = ? WHERE id = ? AND user_id = ?',
        [content, messageId, userId]
      );

      if (result.affectedRows === 0) {
        const [existing] = await pool.execute(
          'SELECT id FROM messages WHERE id = ?',
          [messageId]
        );
        if (existing.length === 0) {
          return res.status(404).json({ error: 'Message not found' });
        }

        await writeAuditLog({
          userId,
          usernameAttempted: username,
          action: 'ACCESS_DENIED',
          targetId: messageId,
          success: false,
          req,
        });
        return res.status(403).json({ error: 'Forbidden: you can only edit your own messages' });
      }

      await writeAuditLog({
        userId,
        usernameAttempted: username,
        action: 'MESSAGE_EDIT',
        targetId: messageId,
        success: true,
        req,
      });

      const [rows] = await pool.execute(
        `SELECT m.id, m.user_id, u.username, m.content, m.created_at, m.updated_at
         FROM messages m
         INNER JOIN users u ON m.user_id = u.id
         WHERE m.id = ?`,
        [messageId]
      );

      return res.status(200).json({ message: rows[0] });
    } catch (err) {
      return next(err);
    }
  });

  // DELETE /api/messages/:id - deletes a message ONLY if the caller owns it
  app.delete('/api/messages/:id', requireAuth, async (req, res, next) => {
    try {
      const messageId = parsePositiveInt(req.params.id);
      if (!messageId) return res.status(400).json({ error: 'Invalid message ID' });

      const { id: userId, username } = req.session.user;

      // Ownership is enforced inside the SQL statement itself (WHERE id = ? AND user_id = ?)
      const [result] = await pool.execute(
        'DELETE FROM messages WHERE id = ? AND user_id = ?',
        [messageId, userId]
      );

      if (result.affectedRows === 0) {
        const [existing] = await pool.execute(
          'SELECT id FROM messages WHERE id = ?',
          [messageId]
        );
        if (existing.length === 0) {
          return res.status(404).json({ error: 'Message not found' });
        }

        await writeAuditLog({
          userId,
          usernameAttempted: username,
          action: 'ACCESS_DENIED',
          targetId: messageId,
          success: false,
          req,
        });
        return res.status(403).json({ error: 'Forbidden: you can only delete your own messages' });
      }

      await writeAuditLog({
        userId,
        usernameAttempted: username,
        action: 'MESSAGE_DELETE',
        targetId: messageId,
        success: true,
        req,
      });

      return res.status(200).json({ message: 'Message deleted' });
    } catch (err) {
      return next(err);
    }
  });

  // Mount intentionally vulnerable route ONLY when demoMode is enabled (npm run demo or DEMO_MODE=true)
  if (demoMode) {
    const localhostIps = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

    // INTENTIONALLY VULNERABLE - DEMO ONLY - NEVER DEPLOY
    app.post('/api/demo/login-unsafe', async (req, res) => {
      const remoteIp = req.socket?.remoteAddress || req.ip || '';
      if (!localhostIps.has(remoteIp)) {
        return res.status(403).json({ error: 'Demo endpoint is restricted to localhost' });
      }

      const username = typeof req.body?.username === 'string' ? req.body.username : '';
      // Unsafe string concatenation: vulnerable to SQL injection payloads
      const sql = "SELECT id, username FROM users WHERE username = '" + username + "'";

      try {
        const [rows] = await pool.query(sql);
        // Never create a session or return user data
        return res.status(200).json({
          queryReturnedRows: rows.length > 0,
          queryExecuted: sql,
        });
      } catch (err) {
        return res.status(200).json({
          queryReturnedRows: false,
          queryExecuted: sql,
        });
      }
    });
  }

  // 404 fallback
  app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
  });

  // Central error handler: logs details server-side, never leaks SQL errors or stack traces
  app.use((err, req, res, _next) => {
    if (err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'Invalid JSON request body' });
    }
    if (err.type === 'entity.too.large') {
      return res.status(413).json({ error: 'Request payload too large' });
    }

    console.error('[SERVER_ERROR]', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

// --- Startup database verification ---
async function verifyDatabaseReady() {
  const [versionRows] = await pool.execute('SELECT VERSION() AS version');
  const versionStr = String(versionRows[0]?.version || '');
  const major = parseInt(versionStr.split('.')[0], 10);

  if (Number.isNaN(major) || major < 8) {
    throw Object.assign(
      new Error(`MySQL ${versionStr} is too old. MySQL 8.0+ is required.`),
      { isPlainMessage: true }
    );
  }

  // chat_app has privileges on users, messages, and audit_log, so SHOW TABLES lists all three
  const [tables] = await pool.query('SHOW TABLES');
  const tableNames = new Set(tables.map((row) => Object.values(row)[0]));
  const missing = ['users', 'messages', 'audit_log'].filter((t) => !tableNames.has(t));

  if (missing.length > 0) {
    throw Object.assign(
      new Error(
        `Missing table(s): ${missing.join(', ')}. Run \`sudo mysql < setup.sql\` (or \`mysql -u root -p < setup.sql\`) first.`
      ),
      { isPlainMessage: true }
    );
  }

  return versionStr;
}

// --- `npm run check` diagnostic mode ---
async function runCheck() {
  let allPassed = true;
  const report = (ok, label, detail) => {
    const tag = ok ? '[PASS]' : '[FAIL]';
    console.log(`${tag} ${label}${detail ? ` - ${detail}` : ''}`);
    if (!ok) allPassed = false;
  };

  // 1. Node version check
  const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
  if (nodeMajor >= 18) {
    report(true, 'Node.js version', `v${process.versions.node}`);
  } else {
    report(false, 'Node.js version', `v${process.versions.node} found. Please install Node.js 18 LTS or newer.`);
  }

  // 2. MySQL reachable & version >= 8.0 (check via chat_app first; fallback error explains connection)
  let appConn;
  try {
    appConn = await createRoleConnection('app', { withDatabase: false });
    const [vRows] = await appConn.execute('SELECT VERSION() AS version');
    const ver = String(vRows[0]?.version || '');
    const mysqlMajor = parseInt(ver.split('.')[0], 10);
    if (mysqlMajor >= 8) {
      report(true, 'MySQL reachable & version >= 8.0', `MySQL ${ver}`);
    } else {
      report(false, 'MySQL version', `Found ${ver}. Upgrade to MySQL 8.0+.`);
    }
  } catch (err) {
    report(false, 'MySQL connection (chat_app)', explainDbError(err));
  } finally {
    if (appConn) await appConn.end().catch(() => {});
  }

  // 3. setup.sql applied (database & tables exist)
  let adminConn;
  try {
    adminConn = await createRoleConnection('admin', { withDatabase: true });
    const [tables] = await adminConn.query('SHOW TABLES');
    const names = new Set(tables.map((r) => Object.values(r)[0]));
    const missing = ['users', 'messages', 'audit_log'].filter((t) => !names.has(t));
    if (missing.length === 0) {
      report(true, 'Database schema (setup.sql)', 'chatroom_db and all 3 tables exist');
    } else {
      report(false, 'Database schema (setup.sql)', `Missing tables: ${missing.join(', ')}. Run \`sudo mysql < setup.sql\`.`);
    }
  } catch (err) {
    report(false, 'Database schema (setup.sql)', explainDbError(err));
  } finally {
    if (adminConn) await adminConn.end().catch(() => {});
  }

  // 4. All three MySQL roles can log in
  for (const role of ['admin', 'app', 'readonly']) {
    const roleLabel = `MySQL login (${config.db[role].user})`;
    let conn;
    try {
      conn = await createRoleConnection(role, { withDatabase: true });
      await conn.execute('SELECT 1');
      report(true, roleLabel, 'Login OK');
    } catch (err) {
      report(false, roleLabel, explainDbError(err));
    } finally {
      if (conn) await conn.end().catch(() => {});
    }
  }

  await pool.end().catch(() => {});
  process.exit(allPassed ? 0 : 1);
}

async function startServer({ port = config.port, host = config.host, demoMode = config.demoMode } = {}) {
  const app = createApp({ demoMode });

  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => {
      resolve(server);
    });
    server.on('error', (err) => reject(err));
  });
}

async function main() {
  if (process.argv.includes('--check')) {
    await runCheck();
    return;
  }

  try {
    await verifyDatabaseReady();
  } catch (err) {
    const msg = err.isPlainMessage ? err.message : explainDbError(err);
    console.error(`Startup failed: ${msg}`);
    await pool.end().catch(() => {});
    process.exit(1);
  }

  try {
    const server = await startServer();
    const addr = server.address();
    console.log(`Secure Chatroom API listening on http://${addr.address}:${addr.port}`);
    if (config.demoMode) {
      console.warn('[DEMO MODE] /api/demo/login-unsafe is active on localhost only.');
    }
  } catch (err) {
    if (err.code === 'EADDRINUSE') {
      console.error(`Startup failed: Port ${config.port} is already in use. Stop the other process or set PORT=3001.`);
    } else {
      console.error(`Startup failed: ${err.message}`);
    }
    await pool.end().catch(() => {});
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { createApp, startServer, verifyDatabaseReady };
