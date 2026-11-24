/**
 * src/routes/messages.js
 * Protected chatroom message endpoints (list, create, edit, delete).
 *
 * Access control:
 *  - Every route requires an authenticated session (401 otherwise).
 *  - PUT and DELETE enforce ownership BOTH in the SQL WHERE clause
 *    (WHERE id = ? AND user_id = ?) and in application logic (403 + ACCESS_DENIED
 *    audit log when another user owns the message, 404 when it does not exist).
 */

const express = require('express');
const pool = require('../db');
const { writeAuditLog } = require('../audit');
const { requireAuth } = require('../middleware/auth');
const {
  validateMessageContent,
  parsePositiveInt,
  parsePagination,
} = require('../middleware/validate');

const router = express.Router();

// All message endpoints require authentication
router.use(requireAuth);

// GET /api/messages?limit=20&offset=0
router.get('/', async (req, res, next) => {
  try {
    const pagination = parsePagination(req.query.limit, req.query.offset);
    if (pagination.error) {
      return res.status(400).json({ error: pagination.error });
    }

    const { limit, offset } = pagination;

    // Using pool.query with integer placeholders (or String for execute); values are validated integers
    const [rows] = await pool.query(
      `SELECT m.id, m.user_id, u.username, m.content, m.created_at, m.updated_at
       FROM messages m
       INNER JOIN users u ON m.user_id = u.id
       ORDER BY m.created_at DESC, m.id DESC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );

    return res.status(200).json({
      messages: rows,
      pagination: { limit, offset, count: rows.length },
    });
  } catch (err) {
    return next(err);
  }
});

// POST /api/messages
router.post('/', async (req, res, next) => {
  try {
    const { content } = req.body || {};
    const contentError = validateMessageContent(content);
    if (contentError) {
      return res.status(400).json({ error: contentError });
    }

    const userId = req.session.user.id;
    const username = req.session.user.username;

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

// PUT /api/messages/:id
router.put('/:id', async (req, res, next) => {
  try {
    const messageId = parsePositiveInt(req.params.id);
    if (!messageId) {
      return res.status(400).json({ error: 'Invalid message ID' });
    }

    const { content } = req.body || {};
    const contentError = validateMessageContent(content);
    if (contentError) {
      return res.status(400).json({ error: contentError });
    }

    const userId = req.session.user.id;
    const username = req.session.user.username;

    // Ownership enforced directly inside the SQL UPDATE statement
    const [result] = await pool.execute(
      'UPDATE messages SET content = ? WHERE id = ? AND user_id = ?',
      [content, messageId, userId]
    );

    if (result.affectedRows === 0) {
      // Distinguish between "not found" (404) and "owned by someone else" (403)
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

      return res.status(403).json({
        error: 'Forbidden: you can only edit your own messages',
      });
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

// DELETE /api/messages/:id
router.delete('/:id', async (req, res, next) => {
  try {
    const messageId = parsePositiveInt(req.params.id);
    if (!messageId) {
      return res.status(400).json({ error: 'Invalid message ID' });
    }

    const userId = req.session.user.id;
    const username = req.session.user.username;

    // Ownership enforced directly inside the SQL DELETE statement
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

      return res.status(403).json({
        error: 'Forbidden: you can only delete your own messages',
      });
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

module.exports = router;
