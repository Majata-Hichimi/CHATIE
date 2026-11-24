/**
 * src/routes/demo.js
 * Contains the intentionally vulnerable SQL injection demonstration route.
 * Only active when DEMO_MODE=true AND NODE_ENV !== 'production', and only
 * responds to requests originating from localhost.
 */

const express = require('express');
const pool = require('../db');

const router = express.Router();

const LOCALHOST_IPS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

// Guard middleware: double-check demo mode and restrict strictly to localhost clients
router.use((req, res, next) => {
  if (process.env.DEMO_MODE !== 'true' || process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Not found' });
  }

  const remoteIp = req.socket?.remoteAddress || req.ip || '';
  if (!LOCALHOST_IPS.has(remoteIp)) {
    return res.status(403).json({ error: 'Demo endpoint is restricted to localhost' });
  }

  return next();
});

// INTENTIONALLY VULNERABLE - DEMO ONLY - NEVER DEPLOY
router.post('/login-unsafe', async (req, res) => {
  const username = typeof req.body?.username === 'string' ? req.body.username : '';

  // Deliberately unsafe string concatenation to demonstrate SQL injection
  const sql = "SELECT id, username FROM users WHERE username = '" + username + "'";

  try {
    const [rows] = await pool.query(sql);
    // Do NOT create a session or return any user rows/data
    return res.status(200).json({
      queryReturnedRows: rows.length > 0,
      queryExecuted: sql,
    });
  } catch (err) {
    return res.status(200).json({
      queryReturnedRows: false,
      queryExecuted: sql,
      sqlError: err.code || 'SQL_ERROR',
    });
  }
});

module.exports = router;
