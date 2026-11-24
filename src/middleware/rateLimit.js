/**
 * src/middleware/rateLimit.js
 * IP-based rate limiters for authentication endpoints to mitigate brute-force
 * and credential-stuffing attacks.
 */

const rateLimit = require('express-rate-limit');

function createAuthRateLimiter() {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 requests per 15 minutes per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: 'Too many requests from this IP. Please try again after 15 minutes.',
    },
  });
}

module.exports = { createAuthRateLimiter };
