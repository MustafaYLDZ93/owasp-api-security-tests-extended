'use strict';

const INTERNAL_PATTERNS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^::1$/,
  /^0\.0\.0\.0$/,
  /^localhost$/i,
  /^metadata\.google\.internal$/i,
];

function isInternalHost(host) {
  const bare = host.toLowerCase().replace(/^\[|\]$/g, '');
  return INTERNAL_PATTERNS.some(p => p.test(bare));
}

/**
 * Decodes a decimal/hex/octal-obfuscated IPv4 host back to dotted-decimal.
 * Classic SSRF-filter-bypass technique: `http://2130706433/` and
 * `http://0x7f000001/` both resolve (via the OS resolver / Node's `http`
 * client) to 127.0.0.1, but a naive regex over the literal hostname string
 * never recognises them as "internal".
 * Returns null if `host` isn't one of these numeral forms.
 */
function decodeObfuscatedIPv4(host) {
  if (/^\d+$/.test(host)) {
    const num = Number(host);
    if (Number.isInteger(num) && num >= 0 && num <= 0xFFFFFFFF) return toDotted(num);
  }
  if (/^0x[0-9a-f]+$/i.test(host)) {
    const num = parseInt(host, 16);
    if (num >= 0 && num <= 0xFFFFFFFF) return toDotted(num);
  }
  if (host.includes('.')) {
    const parts = host.split('.');
    if (parts.length === 4 && parts.every(p => /^(0x[0-9a-f]+|0\d+|\d+)$/i.test(p))) {
      const octets = parts.map(p => {
        if (/^0x/i.test(p)) return parseInt(p, 16);
        if (/^0\d/.test(p)) return parseInt(p, 8);
        return parseInt(p, 10);
      });
      if (octets.every(o => o >= 0 && o <= 255)) return octets.join('.');
    }
  }
  return null;
}

function toDotted(num) {
  return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');
}

/**
 * @param {string} rawUrl
 * @param {{normalizeObfuscation: boolean}} opts  secure=true, vulnerable=false
 */
function isInternalUrl(rawUrl, opts = { normalizeObfuscation: true }) {
  if (!rawUrl) return true;
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return true; // Unparseable URL → reject
  }
  if (!['http:', 'https:'].includes(url.protocol)) return true; // file:, gopher:, etc.

  const host = url.hostname;
  if (isInternalHost(host)) return true;

  if (opts.normalizeObfuscation) {
    const decoded = decodeObfuscatedIPv4(host);
    if (decoded && isInternalHost(decoded)) return true;
  }
  return false;
}

module.exports = { isInternalUrl, isInternalHost, decodeObfuscatedIPv4 };
