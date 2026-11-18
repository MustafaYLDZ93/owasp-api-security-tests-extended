'use strict';

/**
 * A tiny Mongo-like matcher used only by POST /api/auth/login-legacy to
 * demonstrate CWE-943 (operator/NoSQL injection) against an in-memory
 * array of users — the main /api/auth/login endpoint is SQL/JWT-backed
 * (see §2.1 of DESIGN.md) and is a separate, unrelated code path.
 */

function matchesSecure(record, query) {
  // Every query value must be a primitive. An object value (e.g. the
  // classic `{"password": {"$ne": null}}` payload) is rejected outright
  // instead of being interpreted as a query operator.
  return Object.entries(query).every(([key, value]) => {
    if (value !== null && typeof value === 'object') return false;
    return record[key] === value;
  });
}

function matchesVulnerable(record, query) {
  return Object.entries(query).every(([key, value]) => {
    if (value !== null && typeof value === 'object') {
      return Object.entries(value).every(([op, opVal]) => {
        switch (op) {
          case '$ne': return record[key] !== opVal;
          case '$eq': return record[key] === opVal;
          case '$gt': return record[key] > opVal;
          case '$gte': return record[key] >= opVal;
          case '$lt': return record[key] < opVal;
          case '$lte': return record[key] <= opVal;
          case '$regex': return new RegExp(opVal).test(String(record[key]));
          default: return false;
        }
      });
    }
    return record[key] === value;
  });
}

module.exports = { matchesSecure, matchesVulnerable };
