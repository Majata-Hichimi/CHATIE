/**
 * src/audit.js
 * Writes security events to the append-only `audit_log` table as `chat_app`.
 * `chat_app` has INSERT-only permission on `audit_log`, so it cannot alter or
 * delete past audit records even if the app layer is compromised.
 */

const pool = require('./db');

/**
 * Valid audit action names:
 *  REGISTER, LOGIN_SUCCESS, LOGIN_FAILED, ACCOUNT_LOCKED, LOGOUT,
 *  MESSAGE_CREATE, MESSAGE_EDIT, MESSAGE_DELETE, ACCESS_DENIED
 */
async function writeAuditLog({
  userId = null,
  usernameAttempted = null,
  action,
  targetId = null,
  success,
  req = null,
}) {
  // Never store passwords or message content in the audit log.
  const ipAddress = req
    ? String(req.ip || req.socket?.remoteAddress || '').slice(0, 45) || null
    : null;
  const userAgent = req
    ? String(req.get('user-agent') || '').slice(0, 255) || null
    : null;
  const safeUsername =
    usernameAttempted !== null && usernameAttempted !== undefined
      ? String(usernameAttempted).slice(0, 100)
      : null;

  try {
    await pool.execute(
      `INSERT INTO audit_log
        (user_id, username_attempted, action, target_id, success, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        safeUsername,
        action,
        targetId,
        Boolean(success),
        ipAddress,
        userAgent,
      ]
    );
  } catch (err) {
    // Log server-side only; an audit failure must not crash the user request
    console.error('[AUDIT_LOG_ERROR]', err.message);
  }
}

module.exports = { writeAuditLog };
