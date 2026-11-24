/**
 * src/middleware/validate.js
 * Input validation helpers enforcing strict types, lengths, and character sets.
 * Rejects invalid input early with HTTP 400 and clear, non-revealing messages.
 */

const USERNAME_REGEX = /^[A-Za-z0-9_]{3,30}$/;
const POSITIVE_INT_REGEX = /^[1-9]\d*$/;
const NON_NEGATIVE_INT_REGEX = /^\d+$/;

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
  if (Buffer.byteLength(password, 'utf8') > 72) {
    return 'Password exceeds the 72-byte bcrypt maximum';
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

function parsePositiveInt(rawValue) {
  if (typeof rawValue !== 'string' || !POSITIVE_INT_REGEX.test(rawValue)) {
    return null;
  }
  const num = Number(rawValue);
  if (!Number.isSafeInteger(num) || num <= 0) {
    return null;
  }
  return num;
}

function parsePagination(limitRaw, offsetRaw) {
  let limit = 20;
  let offset = 0;

  if (limitRaw !== undefined) {
    if (typeof limitRaw !== 'string' || !POSITIVE_INT_REGEX.test(limitRaw)) {
      return { error: 'Query parameter "limit" must be an integer between 1 and 50' };
    }
    limit = Number(limitRaw);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50) {
      return { error: 'Query parameter "limit" must be an integer between 1 and 50' };
    }
  }

  if (offsetRaw !== undefined) {
    if (typeof offsetRaw !== 'string' || !NON_NEGATIVE_INT_REGEX.test(offsetRaw)) {
      return { error: 'Query parameter "offset" must be a non-negative integer' };
    }
    offset = Number(offsetRaw);
    if (!Number.isSafeInteger(offset) || offset < 0) {
      return { error: 'Query parameter "offset" must be a non-negative integer' };
    }
  }

  return { limit, offset };
}

module.exports = {
  validateUsername,
  validatePassword,
  validateMessageContent,
  parsePositiveInt,
  parsePagination,
};
