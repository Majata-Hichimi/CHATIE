/**
 * src/routes/auth.js
 * Authentication routes: register, login, logout, and current-user profile.
 *
 * Security controls implemented here:
 *  - Strict input validation (username format & password length/non-empty)
 *  - bcrypt password hashing with cost 12
 *  - Dummy bcrypt comparison when username does not exist (timing attack defense)
 *  - Account lockout after 5 consecutive failed logins for 15 minutes
 *  - Rate limiting on /register and /login (10 requests per 15 minutes per IP)
 *  - Session regeneration on login (prevents session fixation)
 *  - Audit logging without ever storing plaintext passwords or hashes
 */

const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../db');
const { writeAuditLog } = require('../audit');
const { requireAuth } = require('../middleware/auth');
const { createAuthRateLimiter } = require('../middleware/rateLimit');
const { validateUsername, validatePassword } = require('../middleware/validate');

const router = express.Router();

const BCRYPT_COST = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

// Computed once at startup so non-existent username lookups still pay cost-12 bcrypt time
const DUMMY_HASH = bcrypt.hashSync('dummy_timing_protection_value', BCRYPT_COST);

const registerLimiter = createAuthRateLimiter();
const loginLimiter = createAuthRateLimiter();

// POST /api/register
router.post('/register', registerLimiter, async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    const usernameError = validateUsername(username);
    if (usernameError) {
      return res.status(400).json({ error: usernameError });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

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

// POST /api/login
router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    const usernameError = validateUsername(username);
    if (usernameError) {
      return res.status(400).json({ error: usernameError });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    const [rows] = await pool.execute(
      `SELECT id, username, password_hash, failed_attempts, locked_until
       FROM users
       WHERE username = ?`,
      [username]
    );

    if (rows.length === 0) {
      // Constant-time mitigation: always perform a bcrypt compare even when user is missing
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
    const now = new Date();
    const isCurrentlyLocked =
      user.locked_until !== null && new Date(user.locked_until) > now;

    if (isCurrentlyLocked) {
      // Run bcrypt compare so response timing does not trivially leak lock state
      await bcrypt.compare(password, DUMMY_HASH);

      await writeAuditLog({
        userId: user.id,
        usernameAttempted: user.username,
        action: 'LOGIN_FAILED',
        success: false,
        req,
      });

      return res.status(423).json({
        error: 'Account is temporarily locked due to too many failed login attempts. Try again later.',
      });
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatches) {
      // If a previous lock expired, restart the counter from 1
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
          error: 'Account is temporarily locked due to too many failed login attempts. Try again later.',
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

    // Successful login: reset failed_attempts and locked_until
    await pool.execute(
      'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?',
      [user.id]
    );

    // Regenerate session ID to prevent session fixation attacks
    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => (err ? reject(err) : resolve()));
    });

    req.session.user = {
      id: user.id,
      username: user.username,
    };

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

// POST /api/logout
router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    const user = req.session.user;

    await new Promise((resolve, reject) => {
      req.session.destroy((err) => (err ? reject(err) : resolve()));
    });

    res.clearCookie('chatroom.sid', {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
    });

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

// GET /api/me
router.get('/me', requireAuth, async (req, res, next) => {
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

module.exports = router;
