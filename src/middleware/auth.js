/**
 * src/middleware/auth.js
 * Session authentication guard for protected API routes.
 */

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user || !req.session.user.id) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  return next();
}

module.exports = { requireAuth };
