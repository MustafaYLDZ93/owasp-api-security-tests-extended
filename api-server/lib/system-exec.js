'use strict';

const { execFile, exec } = require('child_process');

/**
 * POST /api/system/echo backing functions — a deliberately tiny, portable
 * OS Command Injection (CWE-78/77) sink. Uses `echo`/`sleep` (always present,
 * no raw sockets or network capability needed, unlike `ping`) so the
 * time-based oracle (`message; sleep 2` → ~2s extra latency) works in any
 * sandboxed CI container.
 */

const SAFE_MESSAGE_RE = /^[a-zA-Z0-9 ,.!_-]{0,200}$/;

function echoSecure(message) {
  return new Promise((resolve, reject) => {
    if (!SAFE_MESSAGE_RE.test(message ?? '')) {
      return reject(Object.assign(new Error('Message contains disallowed characters'), { code: 'INVALID_MESSAGE' }));
    }
    // execFile never spawns a shell — there is no metacharacter to inject into.
    execFile('echo', [message], (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
}

function echoVulnerable(message) {
  return new Promise((resolve, reject) => {
    // Vulnerable: string concatenation into a real shell (`/bin/sh -c ...`).
    exec(`echo ${message}`, { timeout: 8000 }, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
}

module.exports = { echoSecure, echoVulnerable };
