'use strict';

/**
 * A tiny `{{expr}}` template renderer used by POST /api/templates/render.
 *
 * - renderSecure: only resolves whitelisted dotted variable paths (`{{user.name}}`);
 *   never evaluates arbitrary expressions. CWE-94/SSTI is structurally impossible.
 * - renderVulnerable: evaluates the raw expression with `new Function(...)`,
 *   exactly the class of bug WSTG-INJT-11/18 (Server-Side Template Injection)
 *   targets (`{{7*7}}` → 49 is the canonical probe).
 */

function renderSecure(template, context) {
  return template.replace(/\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}/g, (_match, varPath) => {
    const value = varPath.split('.').reduce(
      (acc, key) => (acc && Object.prototype.hasOwnProperty.call(acc, key) ? acc[key] : undefined),
      context,
    );
    return value === undefined ? '' : String(value);
  });
}

function renderVulnerable(template, context) {
  return template.replace(/\{\{([\s\S]*?)\}\}/g, (_match, expr) => {
    try {
      // eslint-disable-next-line no-new-func
      const fn = new Function(...Object.keys(context), `return (${expr});`);
      return String(fn(...Object.values(context)));
    } catch (e) {
      return `[template error: ${e.message}]`;
    }
  });
}

module.exports = { renderSecure, renderVulnerable };
