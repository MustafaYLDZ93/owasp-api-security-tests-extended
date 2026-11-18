'use strict';

const crypto = require('crypto');

/**
 * Minimal password hashing (scrypt, fixed-cost, random salt).
 * Not production-grade KDF tuning — this app's focus is the OWASP API Top 10
 * surface, not password storage benchmarking, but we still avoid plaintext.
 */
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(plain, salt, 32).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(plain, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, expected] = stored.split(':');
  const derived = crypto.scryptSync(plain, salt, 32).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(derived, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword };
