'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

class OAuthError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

function getClient(db, clientId) {
  const row = db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(clientId);
  if (!row) return null;
  return { ...row, redirect_uris: JSON.parse(row.redirect_uris), scopes: JSON.parse(row.scopes) };
}

/**
 * Validates a `redirect_uri` against the client's registered list.
 * Secure mode (`strictMatch: true`): exact string match only (RFC 6749 §3.1.2.3).
 * Vulnerable mode (`strictMatch: false`): accepts any URI whose host merely
 * matches the registered redirect's host (classic open-redirect-via-OAuth /
 * CWE-601 flavoured misconfiguration — a common real-world OAuth bug).
 */
function isRedirectUriAllowed(client, redirectUri, strictMatch) {
  if (strictMatch) return client.redirect_uris.includes(redirectUri);
  try {
    const requestedHost = new URL(redirectUri).host;
    return client.redirect_uris.some(u => new URL(u).host === requestedHost);
  } catch {
    return false;
  }
}

/**
 * GET /oauth/authorize — issues a short-lived authorization code.
 * Expects the caller to already be authenticated (userId passed in).
 */
function authorize(db, { clientId, redirectUri, scope, userId }, policy) {
  const client = getClient(db, clientId);
  if (!client) throw new OAuthError('invalid_client', 'Unknown client_id');
  if (!isRedirectUriAllowed(client, redirectUri, policy.strictRedirectMatch)) {
    throw new OAuthError('invalid_redirect_uri', 'redirect_uri is not registered for this client');
  }

  const requested = (scope ?? '').split(' ').filter(Boolean);
  // Secure: grant only the intersection of requested & client-registered scopes.
  // Vulnerable: grant whatever was requested, even scopes the client was never registered for.
  const granted = policy.enforceScopeAllowlist
    ? requested.filter(s => client.scopes.includes(s))
    : requested;

  const code = crypto.randomBytes(16).toString('hex');
  db.prepare(`
    INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, expires_at, used)
    VALUES (?, ?, ?, ?, ?, ?, 0)
  `).run(code, clientId, userId, redirectUri, granted.join(' '), Date.now() + 60_000);

  return code;
}

/**
 * POST /oauth/token — exchanges an authorization code for an access token.
 */
function exchangeToken(db, { code, clientId, clientSecret, redirectUri, requestedScope }, policy, jwtSecret) {
  const client = getClient(db, clientId);
  if (!client || client.client_secret !== clientSecret) {
    throw new OAuthError('invalid_client', 'Unknown client or bad client_secret', 401);
  }

  const row = db.prepare('SELECT * FROM oauth_codes WHERE code = ?').get(code);
  if (!row || row.client_id !== clientId) {
    throw new OAuthError('invalid_grant', 'Unknown authorization code');
  }
  if (row.used) throw new OAuthError('invalid_grant', 'Authorization code already used');
  if (row.expires_at < Date.now()) throw new OAuthError('invalid_grant', 'Authorization code expired');

  // Secure: the redirect_uri presented at token exchange MUST match the one
  // used at the /authorize step (RFC 6749 §4.1.3) — prevents code interception attacks.
  if (policy.verifyRedirectUriOnExchange && row.redirect_uri !== redirectUri) {
    throw new OAuthError('invalid_grant', 'redirect_uri does not match the authorization request');
  }

  db.prepare('UPDATE oauth_codes SET used = 1 WHERE code = ?').run(code);

  // Secure: the token is scoped to exactly what was granted at /authorize.
  // Vulnerable: a caller-supplied `scope` in the token request silently
  // overrides the granted scope (CWE-285 scope escalation, TC-A17).
  const finalScope = (!policy.lockScopeToAuthorization && requestedScope)
    ? requestedScope
    : row.scope;

  const accessToken = jwt.sign(
    { userId: row.user_id, clientId, scope: finalScope, tokenType: 'oauth_access' },
    jwtSecret,
    { algorithm: 'HS256', expiresIn: '1h' },
  );

  return { access_token: accessToken, token_type: 'Bearer', expires_in: 3600, scope: finalScope };
}

module.exports = { authorize, exchangeToken, OAuthError, getClient };
