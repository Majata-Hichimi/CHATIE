/**
 * src/middleware/errorHandler.js
 * Central Express error handler.
 * Prevents information leakage by never returning stack traces or raw SQL errors.
 */

function errorHandler(err, req, res, _next) {
  // Handle malformed JSON or oversized body cleanly
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON request body' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request payload too large' });
  }

  // Log full diagnostic details server-side only
  console.error('[SERVER_ERROR]', {
    method: req.method,
    path: req.originalUrl,
    code: err.code || undefined,
    message: err.message,
    stack: err.stack,
  });

  return res.status(500).json({ error: 'Internal server error' });
}

module.exports = { errorHandler };
